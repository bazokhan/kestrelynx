package remediation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// --- package.json: which specifiers are edited, and how ---

func TestNpmSpecifierEditsKeepTheOperator(t *testing.T) {
	for spec, want := range map[string]string{
		"1.2.5": "1.2.6", "=1.2.5": "=1.2.6", "^1.2.5": "^1.2.6", "~1.2.5": "~1.2.6",
		"^0.5.0": "^1.2.6", "~1.0.0": "~1.2.6", "0.0.1": "1.2.6",
	} {
		got, ok := npmEditedSpec(spec, "1.2.6")
		if !ok || got != want {
			t.Errorf("%s: %q, %v, want %q", spec, got, ok, want)
		}
	}
	// Forms that are not edited.
	for _, spec := range []string{
		"1.2.5-beta.1", "1.2.5+build", "1.x", "1.2", "1", "*", "", ">=1.2.5", ">1.2.5", "<2", "<=1.2.5", "1.2.5 - 1.3.0",
		"~1.2.5 || ^2.0.0", "^1.2.5 ^1", "latest", "next", "file:../a", "git+https://x/y.git", "https://x/y.tgz",
		"npm:other@1.2.5", "workspace:^1.2.5", "link:../a", "v1.2.5", "^v1.2.5", "^ 1.2.5", " 1.2.5", "01.2.5", "^1.2.5.1",
	} {
		if got, ok := npmEditedSpec(spec, "1.2.6"); ok {
			t.Errorf("%q was edited to %q", spec, got)
		}
	}
	// A target that is not a plain version is not written in.
	for _, target := range []string{"1.2.6-rc.1", "1.2.6+b", "1.2", "x", ""} {
		if got, ok := npmEditedSpec("^1.2.5", target); ok {
			t.Errorf("target %q written as %q", target, got)
		}
	}
}

func TestPackageJSONEditChangesOnlyTheVersion(t *testing.T) {
	docs := map[string]string{
		"two spaces":  "{\n  \"name\": \"a\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"zed\": \"^1.0.0\",\n    \"minimist\": \"1.2.5\",\n    \"alpha\": \"2.0.0\"\n  },\n  \"devDependencies\": {\n    \"minimist\": \"~1.1.0\"\n  }\n}\n",
		"tabs":        "{\n\t\"dependencies\": {\n\t\t\"minimist\": \"1.2.5\"\n\t},\n\t\"devDependencies\": {\"minimist\": \"~1.1.0\"}\n}\n",
		"one line":    `{"dependencies":{"minimist":"1.2.5"},"devDependencies":{"minimist":"~1.1.0"}}`,
		"crlf":        "{\r\n  \"dependencies\": {\r\n    \"minimist\": \"1.2.5\"\r\n  },\r\n  \"devDependencies\": {\r\n    \"minimist\": \"~1.1.0\"\r\n  }\r\n}\r\n",
		"odd spacing": "{ \"dependencies\" :\n { \"x\" : \"1\" ,\"minimist\":\t\"1.2.5\" } ,\n\"devDependencies\":{ \"minimist\" : \"~1.1.0\" } , \"z\": [1, {\"a\": null}, \"minimist\"]}",
	}
	for name, doc := range docs {
		edits := []ManifestEdit{
			{Section: "dependencies", Name: "minimist", From: "1.2.5", To: "1.2.6"},
			{Section: "devDependencies", Name: "minimist", From: "~1.1.0", To: "~1.2.6"},
		}
		got, err := editPackageJSON(bg, []byte(doc), edits)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := strings.Replace(strings.Replace(doc, `"1.2.5"`, `"1.2.6"`, 1), `"~1.1.0"`, `"~1.2.6"`, 1)
		if string(got) != want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want)
		}
	}
	// The same name in another section or another object is not touched.
	doc := `{"dependencies":{"minimist":"1.2.5"},"overrides":{"minimist":"1.2.5"},"x":{"dependencies":{"minimist":"1.2.5"}}}`
	got, err := editPackageJSON(bg, []byte(doc), []ManifestEdit{{Section: "dependencies", Name: "minimist", From: "1.2.5", To: "1.2.6"}})
	if err != nil || string(got) != `{"dependencies":{"minimist":"1.2.6"},"overrides":{"minimist":"1.2.5"},"x":{"dependencies":{"minimist":"1.2.5"}}}` {
		t.Errorf("got %s, %v", got, err)
	}
}

func TestPackageJSONEditRefusesWhatItCannotFollow(t *testing.T) {
	edit := []ManifestEdit{{Section: "dependencies", Name: "minimist", From: "1.2.5", To: "1.2.6"}}
	for name, doc := range map[string]string{
		"the text differs from what was read": `{"dependencies":{"minimist":"1.2.4"}}`,
		"an escaped spelling":                 `{"dependencies":{"minimist":"1.2.\u0035"}}`,
		"the dependency is absent":            `{"dependencies":{"other":"1.2.5"}}`,
		"the section is absent":               `{"devDependencies":{"minimist":"1.2.5"}}`,
		"not an object":                       `["dependencies"]`,
		"the value is not a string":           `{"dependencies":{"minimist":125}}`,
		"broken":                              `{"dependencies":{"minimist":"1.2.5"`,
	} {
		if _, err := editPackageJSON(bg, []byte(doc), edit); err == nil {
			t.Errorf("%s: edited", name)
		}
	}
	var deep strings.Builder
	deep.WriteString(`{"a":`)
	deep.WriteString(strings.Repeat("[", maxManifestDepth+5))
	deep.WriteString(strings.Repeat("]", maxManifestDepth+5))
	deep.WriteString(`,"dependencies":{"minimist":"1.2.5"}}`)
	if _, err := editPackageJSON(bg, []byte(deep.String()), edit); err == nil {
		t.Error("a document nested far too deep was edited")
	}
}

func TestMajorChangeIsTheLeavingOfTheMajorLine(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{"1.2.5", "1.2.6", false}, {"^1.2.5", "^1.4.0", false}, {"~1.1.0", "~1.2.6", false},
		{"^1.2.5", "^2.0.1", true}, {"1.9.9", "2.0.0", true},
		{"^0.2.1", "^0.2.9", false}, {"^0.2.1", "^0.3.0", true}, {"0.2.1", "1.0.0", true},
		{"0.0.1", "0.0.2", true}, {"0.0.1", "0.0.1", false},
	} {
		if got := releaseLine(semverRelease(c.from)) != releaseLine(semverRelease(c.to)); got != c.want {
			t.Errorf("%s -> %s: %v", c.from, c.to, got)
		}
	}
}

// --- pyproject.toml ---

func TestUvRequirementEditsKeepExtrasAndMarkers(t *testing.T) {
	for s, want := range map[string]string{
		"urllib3==1.26.4":                            "urllib3==1.26.17",
		"urllib3 == 1.26.4":                          "urllib3 == 1.26.17",
		"urllib3==1.26.4 ":                           "urllib3==1.26.17 ",
		"urllib3[socks]==1.26.4":                     "urllib3[socks]==1.26.17",
		"urllib3[socks, brotli] == 1.26.4":           "urllib3[socks, brotli] == 1.26.17",
		`urllib3==1.26.4; python_version>="3.8"`:     `urllib3==1.26.17; python_version>="3.8"`,
		`urllib3 ==1.26.4 ; sys_platform == 'linux'`: `urllib3 ==1.26.17 ; sys_platform == 'linux'`,
		"urllib3~=1.26.4":                            "urllib3~=1.26.17",
		"urllib3~=1.25":                              "urllib3~=1.26",
		"urllib3~=1.26.0":                            "urllib3~=1.26.17",
		"My_Pkg.x==1.0":                              "My_Pkg.x==1.26.17",
	} {
		got, ok := uvEditedRequirement(s, "1.26.17")
		if !ok || got != want {
			t.Errorf("%q: %q, %v, want %q", s, got, ok, want)
		}
	}
	for _, s := range []string{
		"urllib3>=1.26,<2", "urllib3>=1.26", "urllib3<2", "urllib3!=1.26.5", "urllib3===1.26.4", "urllib3==1.26.*",
		"urllib3~=1", "urllib3==1.26.4,<2", "urllib3==1.26.4.post1", "urllib3==1.26.4rc1", "urllib3==1!1.26.4", "urllib3==1.26.4+local",
		"urllib3", "urllib3 @ https://x/y.whl", "urllib3==", "==1.26.4", "urllib3~=1.26.4,>=1.26.5",
	} {
		if got, ok := uvEditedRequirement(s, "1.26.17"); ok {
			t.Errorf("%q was edited to %q", s, got)
		}
	}
	// A target that is not a plain release is not written in.
	for _, target := range []string{"1.26.17rc1", "1.26.17.post1", "2!1.0", "1.26.17+x", ""} {
		if got, ok := uvEditedRequirement("urllib3==1.26.4", target); ok {
			t.Errorf("target %q written as %q", target, got)
		}
	}
	// ~= keeps its precision and still allows the target.
	if got, _ := uvEditedRequirement("urllib3~=1.25", "2.0.3"); got != "urllib3~=2.0" {
		t.Errorf("got %q", got)
	}
}

func TestPyprojectEditChangesOnlyTheRequirement(t *testing.T) {
	docs := map[string]string{
		"plain":                    "[project]\nname = \"p\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"urllib3==1.26.4\"]\n\n[tool.uv]\npackage = false\n",
		"multi-line with comments": "# top\n[project]\nname = \"p\"\ndependencies = [\n    # the http part\n    \"requests>=2\",  # why\n    'urllib3==1.26.4',\n    \"six\",\n]\noptional-dependencies = { x = [\"urllib3==1.26.4\"] }\n\n[dependency-groups]\ndev = [\"urllib3==1.26.4\"]\n",
		"crlf":                     "[project]\r\nname = \"p\"\r\ndependencies = [\r\n  \"urllib3[socks]==1.26.4; python_version >= '3.8'\",\r\n]\r\n",
		"other tables first":       "[tool.x]\nlist = [\"urllib3==1.26.4\", { a = \"urllib3==1.26.4\" }]\ntext = \"\"\"\n[project]\ndependencies = [\"urllib3==1.26.4\"]\n\"\"\"\n\n[ project ]\nname = \"p\"\ndependencies = [\"x\", \"urllib3==1.26.4\"]\n",
	}
	for name, doc := range docs {
		py, err := parseTOML([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		list := py["project"].(map[string]any)["dependencies"].([]any)
		idx := -1
		for i, e := range list {
			if strings.HasPrefix(e.(string), "urllib3") {
				idx = i
			}
		}
		from := list[idx].(string)
		to := strings.Replace(from, "1.26.4", "1.26.17", 1)
		got, err := editPyproject(bg, []byte(doc), []int{idx}, []ManifestEdit{{Section: "project.dependencies", Name: "urllib3", From: from, To: to}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Only the text of that one requirement differs.
		if len(got) != len(doc)+len(to)-len(from) {
			t.Errorf("%s: length %d", name, len(got))
		}
		var diffs int
		for i := 0; i < len(doc) && i < len(got); i++ {
			if doc[i] != got[i] {
				diffs++
			}
		}
		if diffs == 0 || !strings.Contains(string(got), to) {
			t.Errorf("%s: not edited: %q", name, got)
		}
		if strings.Count(string(got), "1.26.4") != strings.Count(doc, "1.26.4")-1 {
			t.Errorf("%s: another occurrence changed: %q", name, got)
		}
	}
}

func TestPyprojectEditRefusesWhatItCannotFollow(t *testing.T) {
	edit := func(idx int) []ManifestEdit {
		return []ManifestEdit{{Section: "project.dependencies", Name: "urllib3", From: "urllib3==1.26.4", To: "urllib3==1.26.17"}}
	}
	for name, doc := range map[string]string{
		"an escaped spelling":     "[project]\ndependencies = [\"urllib3==1.26.\\u0034\"]\n",
		"the text differs":        "[project]\ndependencies = [\"urllib3==1.26.5\"]\n",
		"a multi-line string":     "[project]\ndependencies = [\"\"\"urllib3==1.26.4\"\"\"]\n",
		"dotted keys at the root": "project.dependencies = [\"urllib3==1.26.4\"]\nproject.name = \"p\"\n",
		"an inline project table": "project = { name = \"p\", dependencies = [\"urllib3==1.26.4\"] }\n",
		"no dependencies array":   "[project]\nname = \"p\"\n",
		"dependencies not a list": "[project]\ndependencies = \"urllib3==1.26.4\"\n",
		"a list of tables":        "[project]\ndependencies = [{ a = \"urllib3==1.26.4\" }]\n",
		"broken":                  "[project\ndependencies = [\"urllib3==1.26.4\"]\n",
	} {
		if _, err := editPyproject(bg, []byte(doc), []int{0}, edit(0)); err == nil {
			t.Errorf("%s: edited", name)
		}
	}
}

// --- the update with edited manifests, through the fake work container ---

// editedNpm is an npm project whose package.json asks for minimist as spec,
// with the lockfile the update leaves: the edited specifier at the root and
// minimist resolved to resolved.
func editedNpm(t *testing.T, spec, edited, resolved string) *harness {
	t.Helper()
	manifest := "{\n  \"name\": \"a\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"" + spec + "\"\n  }\n}\n"
	lock := func(ver, specifier, integrity string) string {
		return `{"name":"a","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"a","version":"1.0.0","dependencies":{"minimist":"` + specifier + `"}},
"node_modules/minimist":{"version":"` + ver + `","resolved":"https://registry.npmjs.org/minimist/-/minimist-` + ver + `.tgz","integrity":"` + integrity + `"}}}`
	}
	files := map[string]string{"package.json": manifest, "package-lock.json": lock("1.2.5", spec, "sha512-x")}
	item := itemFor(t, ManagerNpm, files, minimistGroup())
	if item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not an update candidate: %s %s", item.Category, item.Detail)
	}
	h := newHarness(t, "npm")
	h.files, h.item = files, item
	h.gh = ghFor(files)
	h.cfg.GitHub = h.gh
	h.npm.dists["minimist@"+resolved] = NpmDist{Tarball: "https://registry.npmjs.org/minimist/-/minimist-" + resolved + ".tgz", Integrity: "sha512-y"}
	h.after = []byte(lock(resolved, edited, "sha512-y"))
	h.fx.beforePkgs = [][2]string{{"minimist", "1.2.5"}}
	h.fx.afterPkgs = [][2]string{{"minimist", resolved}}
	return h
}

func TestNpmDirectDependencyOutOfRangeIsEditedAndUpdated(t *testing.T) {
	for _, c := range []struct {
		spec, edited, resolved string
		major                  bool
	}{
		{"1.2.5", "1.2.6", "1.2.6", false},
		{"=1.2.5", "=1.2.6", "1.2.6", false},
		{"~1.1.5", "~1.2.6", "1.2.8", false},
		{"^0.5.0", "^1.2.6", "1.2.8", true},
	} {
		t.Run(c.spec, func(t *testing.T) {
			h := editedNpm(t, c.spec, c.edited, c.resolved)
			got, _ := h.run()
			wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
			if len(h.work.jobs) != 2 {
				t.Fatalf("jobs = %d", len(h.work.jobs))
			}
			edited := strings.Replace(h.files["package.json"], `"`+c.spec+`"`, `"`+c.edited+`"`, 1)
			// The original input is checked as it is, in a job of its own.
			if s := h.work.jobs[0].Steps; len(s) != 1 || s[0].Op != worker.OpNpmRelock || !s[0].Scratch {
				t.Errorf("first job steps = %+v", s)
			}
			if string(h.work.srcs[0]["package.json"]) != h.files["package.json"] {
				t.Error("the baseline job was not given the original manifest")
			}
			// The update runs on the edited manifest and the original lockfile.
			if s := h.work.jobs[1].Steps; len(s) != 1 || s[0].ID != stepUpdate || s[0].Op != worker.OpNpmRelock || s[0].Scratch {
				t.Errorf("second job steps = %+v", s)
			}
			if string(h.work.srcs[1]["package.json"]) != edited || string(h.work.srcs[1]["package-lock.json"]) != h.files["package-lock.json"] {
				t.Errorf("second job input = %q", h.work.srcs[1]["package.json"])
			}
			want := []ManifestEdit{{File: "package.json", Section: "dependencies", Name: "minimist", From: c.spec, To: c.edited, MajorChange: c.major}}
			if fmt.Sprint(got.Update.ManifestEdits) != fmt.Sprint(want) {
				t.Errorf("edits = %+v", got.Update.ManifestEdits)
			}
			if len(got.Artifacts) != 2 || got.Artifacts[1].Path != "package.json" || string(got.Artifacts[1].Content) != edited ||
				got.Artifacts[1].SHA256 != sha256Hex([]byte(edited)) || got.Artifacts[1].Size != int64(len(edited)) {
				t.Errorf("artifacts = %+v", got.Artifacts)
			}
			sc := got.SourceCheck
			if sc == nil || !sc.Passed {
				t.Fatalf("source check = %+v", sc)
			}
			for i := range sc.Before {
				if (sc.Before[i].SHA256 == sc.After[i].SHA256) != false {
					t.Errorf("%s did not change between the scans", sc.Before[i].Path)
				}
			}
		})
	}
}

func TestEditedNpmManifestMustComeBackAsEdited(t *testing.T) {
	t.Run("the container changes the manifest again", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{}
			}
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"package-lock.json": h.after, "package.json": []byte(strings.Replace(string(src["package.json"]), `"1.2.6"`, `"^1.2.6"`, 1))}}}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonManifestChanged)
	})
	t.Run("the container leaves the original manifest in place", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{}
			}
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"package-lock.json": h.after, "package.json": []byte(h.files["package.json"])}}}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonManifestChanged)
	})
	t.Run("the lockfile does not record the edited specifier", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.after = []byte(strings.Replace(string(h.after), `"dependencies":{"minimist":"1.2.6"}`, `"dependencies":{"minimist":"1.2.5"}`, 1))
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonLockfileInconsistent)
	})
	t.Run("the lockfile records another specifier", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.after = []byte(strings.Replace(string(h.after), `"dependencies":{"minimist":"1.2.6"}`, `"dependencies":{"minimist":"^1.0.0"}`, 1))
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonLockfileInconsistent)
	})
	t.Run("the lockfile changes the specifier of a package that was not edited", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.after = []byte(strings.Replace(string(h.after), `"dependencies":{"minimist":"1.2.6"}`, `"dependencies":{"minimist":"1.2.6","extra":"1.0.0"}`, 1))
		got, _ := h.run()
		if got.Category != CategoryManual {
			t.Fatalf("%s/%s", got.Category, got.Reason)
		}
	})
	t.Run("the lockfile resolves outside the edited range", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.8")
		got, _ := h.run()
		if got.Category != CategoryManual {
			t.Fatalf("%s/%s", got.Category, got.Reason)
		}
	})
	t.Run("the original input fails its own check", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{failStep: stepBaseline}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonLockfileInconsistent)
		if len(h.work.jobs) != 1 {
			t.Errorf("jobs = %d", len(h.work.jobs))
		}
	})
	t.Run("the relock step fails", func(t *testing.T) {
		h := editedNpm(t, "1.2.5", "1.2.6", "1.2.6")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{}
			}
			return fakeOutcome{failStep: stepUpdate}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonUpdateStepFailed)
	})
}

func TestManifestFormsThatAreNotEditedStayManual(t *testing.T) {
	for _, spec := range []string{"<=1.2.5", "1.2.5 - 1.2.5", "<1.2.6"} {
		t.Run(spec, func(t *testing.T) {
			h := editedNpm(t, spec, spec, "1.2.8")
			if h.item.Category != CategoryDependencyUpdateCandidate {
				t.Skip("not a candidate")
			}
			got, _ := h.run()
			wantCategory(t, got, CategoryManual, ReasonManifestEditRequired)
			if h.work.calls != 0 {
				t.Error("a job ran")
			}
			if got.Update != nil && len(got.Update.ManifestEdits) != 0 {
				t.Errorf("edits recorded: %+v", got.Update.ManifestEdits)
			}
		})
	}
}

func TestEditedPnpmManifestIsRelockedAndChecked(t *testing.T) {
	lockOf := func(spec, ver, integrity string) string {
		return `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      minimist:
        specifier: ` + spec + `
        version: ` + ver + `

packages:

  minimist@` + ver + `:
    resolution: {integrity: ` + integrity + `}

snapshots:

  minimist@` + ver + `: {}
`
	}
	manifest := "{\n  \"name\": \"a\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"~1.1.5\"\n  }\n}\n"
	manifest = strings.ReplaceAll(manifest, `\n`, "\n")
	files := map[string]string{"package.json": manifest, "pnpm-lock.yaml": lockOf("~1.1.5", "1.2.5", "sha512-aaa")}
	setup := func(t *testing.T) *harness {
		item := itemFor(t, ManagerPnpm, files, minimistGroup())
		if item.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("not a candidate: %s %s", item.Category, item.Detail)
		}
		h := newHarness(t, "pnpm")
		h.files, h.item = files, item
		h.gh = ghFor(files)
		h.cfg.GitHub = h.gh
		h.after = []byte(lockOf("~1.2.6", "1.2.8", "sha512-bbb"))
		h.npm.dists["minimist@1.2.8"] = NpmDist{Tarball: minimist128.Tarball, Integrity: "sha512-bbb"}
		return h
	}
	t.Run("an edited specifier", func(t *testing.T) {
		h := setup(t)
		got, _ := h.run()
		wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
		if len(h.work.jobs) != 2 {
			t.Fatalf("jobs = %d", len(h.work.jobs))
		}
		if s := h.work.jobs[0].Steps; len(s) != 1 || s[0].Op != worker.OpPnpmFrozen || !s[0].Scratch {
			t.Errorf("first job steps = %+v", s)
		}
		s := h.work.jobs[1].Steps
		if len(s) != 2 || s[0].Op != worker.OpPnpmRelock || s[0].Scratch || s[1].Op != worker.OpPnpmFrozen || !s[1].Scratch {
			t.Errorf("second job steps = %+v", s)
		}
		if !strings.Contains(string(h.work.srcs[1]["package.json"]), `"~1.2.6"`) || string(h.work.srcs[1]["pnpm-lock.yaml"]) != files["pnpm-lock.yaml"] {
			t.Errorf("second job input = %q", h.work.srcs[1]["package.json"])
		}
		e := got.Update.ManifestEdits
		if len(e) != 1 || e[0].From != "~1.1.5" || e[0].To != "~1.2.6" || e[0].MajorChange || e[0].Section != "dependencies" {
			t.Errorf("edits = %+v", e)
		}
		if len(got.Artifacts) != 2 {
			t.Errorf("artifacts = %+v", got.Artifacts)
		}
	})
	t.Run("the importer does not record the edited specifier", func(t *testing.T) {
		h := setup(t)
		h.after = []byte(lockOf("~1.1.5", "1.2.8", "sha512-bbb"))
		got, _ := h.run()
		if got.Category != CategoryManual {
			t.Fatalf("%s/%s", got.Category, got.Reason)
		}
	})
	t.Run("the check changes the lockfile", func(t *testing.T) {
		h := setup(t)
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{}
			}
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": h.after}, stepCheck: {"pnpm-lock.yaml": []byte(strings.Replace(string(h.after), "sha512-bbb", "sha512-ccc", -1))}}}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonPostUpdateLockUnstable)
	})
	t.Run("the baseline changes the lockfile", func(t *testing.T) {
		h := setup(t)
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {"pnpm-lock.yaml": h.after}}}
			}
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": h.after}}}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonLockfileInconsistent)
	})
}

func TestEditedUvRequirementIsLockedAndChecked(t *testing.T) {
	setup := func(t *testing.T, from, to, specBefore, specAfter string) *harness {
		h := newHarness(t, "uv")
		re := func(s, spec string) string {
			return strings.Replace(s, `requires-dist = [{ name = "urllib3", specifier = ">=1.26,<2" }]`, `requires-dist = [{ name = "urllib3"`+spec+` }]`, 1)
		}
		h.files["pyproject.toml"] = strings.Replace(h.files["pyproject.toml"], `"urllib3>=1.26,<2"`, `"`+from+`"`, 1)
		h.files["uv.lock"] = re(h.files["uv.lock"], specBefore)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
		if h.item.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("not a candidate: %s %s", h.item.Category, h.item.Detail)
		}
		h.editLock(re(string(h.after), specAfter))
		return h
	}
	t.Run("an exact pin", func(t *testing.T) {
		h := setup(t, "urllib3==1.26.4", "", `, specifier = "==1.26.4"`, `, specifier = "==1.26.17"`)
		got, _ := h.run()
		wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
		if len(h.work.jobs) != 2 {
			t.Fatalf("jobs = %d", len(h.work.jobs))
		}
		if s := h.work.jobs[0].Steps; len(s) != 1 || s[0].Op != worker.OpUvCheck || !s[0].Scratch {
			t.Errorf("first job steps = %+v", s)
		}
		s := h.work.jobs[1].Steps
		if len(s) != 2 || s[0].Op != worker.OpUvUpgrade || s[0].Packages[0] != (worker.Package{Name: "urllib3", Version: "1.26.17"}) || s[1].Op != worker.OpUvCheck || !s[1].Scratch {
			t.Errorf("second job steps = %+v", s)
		}
		if !strings.Contains(string(h.work.srcs[1]["pyproject.toml"]), `"urllib3==1.26.17"`) || !strings.Contains(string(h.work.srcs[0]["pyproject.toml"]), `"urllib3==1.26.4"`) {
			t.Errorf("inputs: %q / %q", h.work.srcs[0]["pyproject.toml"], h.work.srcs[1]["pyproject.toml"])
		}
		e := got.Update.ManifestEdits
		if len(e) != 1 || e[0].File != "pyproject.toml" || e[0].Section != "project.dependencies" || e[0].Name != "urllib3" ||
			e[0].From != "urllib3==1.26.4" || e[0].To != "urllib3==1.26.17" || e[0].MajorChange {
			t.Errorf("edits = %+v", e)
		}
		if len(got.Artifacts) != 2 || got.Artifacts[1].Path != "pyproject.toml" {
			t.Errorf("artifacts = %+v", got.Artifacts)
		}
	})
	t.Run("extras and a marker are kept", func(t *testing.T) {
		h := setup(t, `urllib3[socks]==1.26.4; python_version >= '3.8'`, "", `, extras = ["socks"], marker = "python_full_version >= '3.8'", specifier = "==1.26.4"`, `, extras = ["socks"], marker = "python_full_version >= '3.8'", specifier = "==1.26.17"`)
		got, _ := h.run()
		if got.Category != CategoryPRCandidate {
			t.Skipf("the extras fixture is not accepted by the other checks: %s %s", got.Reason, got.Detail)
		}
		if !strings.Contains(string(h.work.srcs[1]["pyproject.toml"]), `"urllib3[socks]==1.26.17; python_version >= '3.8'"`) {
			t.Errorf("input = %q", h.work.srcs[1]["pyproject.toml"])
		}
	})
	t.Run("the lockfile does not record the edited specifier", func(t *testing.T) {
		h := setup(t, "urllib3==1.26.4", "", `, specifier = "==1.26.4"`, `, specifier = "==1.26.4"`)
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonLockfileInconsistent)
	})
	t.Run("the container changes the manifest again", func(t *testing.T) {
		h := setup(t, "urllib3==1.26.4", "", `, specifier = "==1.26.4"`, `, specifier = "==1.26.17"`)
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{}
			}
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": h.after, "pyproject.toml": []byte(strings.Replace(string(src["pyproject.toml"]), "1.26.17", "1.26.18", 1))}}}
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonManifestChanged)
	})
	t.Run("a form that is not edited", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.files["pyproject.toml"] = strings.Replace(h.files["pyproject.toml"], `"urllib3>=1.26,<2"`, `"urllib3<=1.26.4"`, 1)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonManifestEditRequired)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
	})
	t.Run("a requirement outside [project] dependencies is not edited", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.files["pyproject.toml"] = strings.Replace(h.files["pyproject.toml"], `dependencies = ["urllib3>=1.26,<2"]`, `dependencies = ["urllib3>=1.26,<2"]
optional-dependencies = { extra = ["urllib3==1.26.4"] }`, 1)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
		if h.item.Category != CategoryDependencyUpdateCandidate {
			t.Skip("not a candidate")
		}
		got, _ := h.run()
		wantCategory(t, got, CategoryManual, ReasonManifestEditRequired)
	})
}
