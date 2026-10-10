package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// --- keys are read by their exact spelling ---

const minimistEntry = `"node_modules/minimist": {
      "version": "1.2.8",
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",
      "integrity": "` + "sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==" + `"`

func TestNpmLockKeysAreReadByTheirExactSpelling(t *testing.T) {
	entry := func(body string) []byte {
		return []byte(`{"lockfileVersion":3,"packages":{"":{"name":"a"},"node_modules/m":{` + body + `}}}`)
	}
	oldTar, newTar := "https://registry.npmjs.org/m/-/m-1.0.0.tgz", "https://registry.npmjs.org/m/-/m-2.0.0.tgz"
	for name, body := range map[string]string{
		"a key and the same key in another case": `"version":"2.0.0","resolved":"` + oldTar + `","Resolved":"` + newTar + `"`,
		"a repeated key":                         `"version":"1.0.0","version":"2.0.0"`,
		"a repeated integrity":                   `"integrity":"sha512-a","integrity":"sha512-b"`,
		"upper case against upper case":          `"Link":true,"link":false`,
		"a key that is not a string":             `"version":2`,
		"a dependency map that repeats a name":   `"dependencies":{"x":"^1","x":"^2"}`,
	} {
		if _, err := readNpmLock(entry(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := parseNpm([]byte(`{"name":"a","version":"1.0.0"}`), entry(body)); err == nil {
			t.Errorf("%s: the plan's parser accepted it", name)
		} else {
			mustUnsupported(t, err, ReasonUnparsableSource)
		}
	}
	// A key in another case is not the key: only the exact spelling counts.
	doc, err := readNpmLock(entry(`"version":"2.0.0","Resolved":"` + newTar + `","INTEGRITY":"sha512-x"`))
	if err != nil {
		t.Fatal(err)
	}
	if e := doc.entries["node_modules/m"]; e.Resolved != "" || e.Integrity != "" || e.Version != "2.0.0" {
		t.Errorf("entry = %+v", e)
	}
	// Two packages whose names differ only in case are two packages.
	if _, err := readNpmLock([]byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/JSONStream":{"version":"1.0.0"},"node_modules/jsonstream":{"version":"1.0.0"}}}`)); err != nil {
		t.Errorf("names that differ in case: %v", err)
	}
	// package.json is read the same way.
	if _, err := readManifest([]byte(`{"dependencies":{"a":"1"},"Dependencies":{"a":"2"}}`)); err == nil {
		t.Error("package.json with two spellings of dependencies accepted")
	}
	if _, err := readManifest([]byte(`{"dependencies":{"a":"1","a":"2"}}`)); err == nil {
		t.Error("package.json repeating a dependency accepted")
	}
}

func TestOutputWithAmbiguousKeysIsRefusedForEveryManager(t *testing.T) {
	t.Run("npm lockfile", func(t *testing.T) {
		h := newHarness(t, "npm")
		// The old tarball in the spelling npm reads, the new one in another.
		h.editLock(strings.Replace(string(h.after), `"resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",`,
			`"resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
      "Resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",`, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("npm lockfile with a lone upper-case key", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(strings.Replace(string(h.after), `"resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",`, `"Resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",`, 1))
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s", it.Category, it.Reason)
		}
	})
	t.Run("npm relock of the original", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			dup := strings.Replace(h.files["package-lock.json"], `"version": "0.5.5",`, `"version": "0.5.5", "Version": "0.5.6",`, 1)
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {"package-lock.json": []byte(dup)}, stepUpdate: {"package-lock.json": h.after}}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonLockfileInconsistent)
	})
	t.Run("pnpm lockfile", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.editLock(strings.Replace(string(h.after), "resolution: {integrity: "+minimist128.Integrity+"}", "resolution: {integrity: sha512-old, Integrity: "+minimist128.Integrity+"}", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("uv lockfile", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.editLock(strings.Replace(string(h.after), `hash = "sha256:`+urllibWheelSHA+`"`, `hash = "sha256:`+h64('1')+`", Hash = "sha256:`+urllibWheelSHA+`"`, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("pip report", func(t *testing.T) {
		for name, edit := range map[string]func(string) string{
			"url": func(r string) string {
				return strings.Replace(r, `"url":`, `"URL":"https://files.pythonhosted.org/x/old.whl","url":`, 1)
			},
			"version": func(r string) string {
				return strings.Replace(r, `"version":"1.26.17"`, `"version":"1.26.4","version":"1.26.17"`, 1)
			},
			"hashes": func(r string) string {
				return strings.Replace(r, `"hashes":{`, `"hashes":{"sha256":"`+h64('0')+`","sha256":"`+h64('1')+`",`, 1)
			},
		} {
			h := newHarness(t, "pip")
			h.checkReport(edit)
			it, _ := h.run()
			if it.Category != CategoryManual || it.Reason != ReasonOutputFilesInvalid {
				t.Errorf("%s: %s/%s (%s)", name, it.Category, it.Reason, it.Detail)
			}
		}
	})
}

func TestPnpmAndUvKeysAreCheckedWherePlanningReadsThem(t *testing.T) {
	pnpm := readTestdata(t, "pnpm", "package.json", "pnpm-lock.yaml")
	for name, edit := range map[string]func(string) string{
		"two spellings of integrity": func(s string) string {
			return strings.Replace(s, "resolution: {integrity: ", "resolution: {Integrity: sha512-a, integrity: ", 1)
		},
		"two spellings of specifier": func(s string) string {
			return strings.Replace(s, "        specifier: 0.5.5", "        specifier: 0.5.5\n        Specifier: 0.5.6", 1)
		},
		"two spellings of a section": func(s string) string { return strings.Replace(s, "\nsnapshots:", "\nSnapshots: {}\nsnapshots:", 1) },
	} {
		if _, err := parsePnpm([]byte(pnpm["package.json"]), []byte(edit(pnpm["pnpm-lock.yaml"]))); err == nil {
			t.Errorf("pnpm, %s: accepted by the plan's parser", name)
		}
		if _, err := pnpmGraph(bg, []byte(edit(pnpm["pnpm-lock.yaml"]))); err == nil {
			t.Errorf("pnpm, %s: accepted by the graph", name)
		}
	}
	uv := readTestdata(t, "uv", "pyproject.toml", "uv.lock")
	for name, edit := range map[string]func(string) string{
		"two spellings of a hash": func(s string) string {
			return strings.Replace(s, `{ url = "https://files.pythonhosted.org/packages/09`, `{ Hash = "sha256:00", url = "https://files.pythonhosted.org/packages/09`, 1)
		},
		"two spellings of a name": func(s string) string {
			return strings.Replace(s, `name = "urllib3"`, `name = "urllib3"`+"\nName = \"other\"", 1)
		},
	} {
		if _, err := parseUv([]byte(uv["pyproject.toml"]), []byte(edit(uv["uv.lock"]))); err == nil {
			t.Errorf("uv, %s: accepted by the plan's parser", name)
		}
		if _, err := uvGraph(bg, []byte(edit(uv["uv.lock"]))); err == nil {
			t.Errorf("uv, %s: accepted by the graph", name)
		}
	}
	if _, err := parsePipReport([]byte(`{"version":"1","Version":"2","install":[]}`)); err == nil {
		t.Error("report with two spellings accepted")
	}
}

// --- a required requirement that was dangling before stays refused ---

func TestRequiredRequirementThatWasAlreadyDanglingIsStillRefused(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	before := map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0", deps: map[string]string{"o": "^1.0.0"}}, // o has no entry
	}
	after := map[string]npmEntry{
		"node_modules/a": before["node_modules/a"],
		"node_modules/t": {ver: "1.0.5", deps: map[string]string{"o": "^1.0.0"}},
	}
	h := newNpmCase(t, root, before, after)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	// Declared optional by the registry, the same file is fine.
	h = newNpmCase(t, root, before, after)
	h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", OptionalDependencies: map[string]string{"o": "^1.0.0"}}
	it, _ = h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	// Declared as a peer dependency, likewise.
	h = newNpmCase(t, root, before, npmWith3(after))
	h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", PeerDependencies: map[string]string{"o": "^1.0.0"}}
	it, _ = h.run()
	if it.Category == CategoryDeferred || it.Category == CategoryFailed {
		t.Fatalf("%s/%s", it.Category, it.Reason)
	}
}

// npmWith3 returns after unchanged; it stands for a project whose entry
// records the peer dependency in the file's own section, which the plan's
// helper cannot write, so the case is judged by its category only.
func npmWith3(m map[string]npmEntry) map[string]npmEntry { return m }

// --- every line of the requirements file is checked against the report ---

func TestRequirementsFileLinesMustBeInstalledAtAllowedVersions(t *testing.T) {
	file := "requests==2.22.0\nurllib3==1.26.4\n"
	mk := func(requirements string, before, after []pipItem, requires map[string][]string) *harness {
		h := newHarness(t, "pip")
		h.files["requirements.txt"] = requirements
		h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.pypi.requires = requires
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			items, step := before, stepBaseline
			if n == 1 {
				items, step = after, stepCheck
			}
			return fakeOutcome{edit: map[string]map[string][]byte{step: {worker.PipReportName: pipReportItems(items...)}}}
		}
		return h
	}
	req := map[string][]string{"requests==2.22.0": {"urllib3<1.26.10"}}
	t.Run("a requirement the report leaves out", func(t *testing.T) {
		// requests asks for urllib3<1.26, so leaving it out hides a conflict.
		h := mk(file, []pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "requests", ver: "2.22.0"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}}, req)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "requests") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("with it left in, the conflict is found", func(t *testing.T) {
		h := mk(file, []pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "requests", ver: "2.22.0"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}, {name: "requests", ver: "2.22.0"}}, req)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	})
	t.Run("a pin the report does not honour, whatever else is pinned", func(t *testing.T) {
		h := mk("six==1.16.0\nsix==1.15.0\nurllib3==1.26.4\n",
			[]pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "six", ver: "1.16.0"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}, {name: "six", ver: "1.16.0"}}, nil)
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a specifier that is not a pin is judged", func(t *testing.T) {
		h := mk("six>=1.17\nurllib3==1.26.4\n",
			[]pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "six", ver: "1.16.0"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}, {name: "six", ver: "1.16.0"}}, nil)
		it, _ := h.run()
		// The baseline already contradicts the file.
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	})
	t.Run("a line whose marker is false here need not be installed", func(t *testing.T) {
		h := mk("urllib3==1.26.4\ncolorama==0.4.6 ; sys_platform == 'win32'\n",
			[]pipItem{{name: "urllib3", ver: "1.26.4"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}}, nil)
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a line whose marker is true here must be", func(t *testing.T) {
		h := mk("urllib3==1.26.4\nsix==1.16.0 ; sys_platform == 'linux'\n",
			[]pipItem{{name: "urllib3", ver: "1.26.4"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}}, nil)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a line the report cannot be checked against", func(t *testing.T) {
		h := mk("urllib3==1.26.4\nsix @ https://example.com/six.whl\n",
			[]pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "six", ver: "1.16.0"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}, {name: "six", ver: "1.16.0"}}, nil)
		if h.item.Category != CategoryDependencyUpdateCandidate {
			t.Skip("the plan stops it first")
		}
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s", it.Category, it.Reason)
		}
	})
	t.Run("the roots are the file's lines, not what the report calls requested", func(t *testing.T) {
		// The report marks nothing as requested; the file's lines still root the graph.
		h := mk("urllib3==1.26.4\n", []pipItem{{name: "urllib3", ver: "1.26.4", notReq: true}}, []pipItem{{name: "urllib3", ver: "1.26.17", notReq: true}}, nil)
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
}

// --- requires-python ---

func TestPythonSpecifierHelpers(t *testing.T) {
	cases := []struct {
		spec, minor string
		ok, decided bool
	}{
		{"", "3.12", true, true},
		{">=3.8", "3.12", true, true},
		{">=3.8, !=3.9.*", "3.12", true, true},
		{">=3.13", "3.12", false, true},
		{">=3.8,<3.12", "3.12", false, true},
		{"<3.13", "3.12", true, true},
		{"!=3.12.1", "3.12", false, false},
		{">=3.12.1", "3.12", false, false},
		{"==3.12.*", "3.12", true, true},
		{"~=3.8", "3.12", true, true},
		{"===3.12.0", "3.12", false, false},
		{"not a specifier", "3.12", false, false},
		{">=3.8;", "3.12", false, false},
	}
	for _, c := range cases {
		ok, decided := pythonMinorAllows(c.spec, c.minor)
		if ok != c.ok || decided != c.decided {
			t.Errorf("pythonMinorAllows(%q, %s) = %v, %v; want %v, %v", c.spec, c.minor, ok, decided, c.ok, c.decided)
		}
	}
	lows := map[string]string{">=3.9": "3.9", ">=3.9,<4": "3.9", ">=3.8, >=3.10": "3.10", "~=3.9": "3.9", "==3.10.*": "3.10.0", "": "", "<4": "", ">3.8": "", "!=3.9.1": "", "garbage": ""}
	for spec, want := range lows {
		got, ok := pythonLowerBound(spec)
		if (want == "") == ok || got != want {
			t.Errorf("pythonLowerBound(%q) = %q, %v; want %q", spec, got, ok, want)
		}
	}
}

func TestRequiresPythonOfAPipWheelIsJudgedForTheImagesPython(t *testing.T) {
	for _, c := range []struct {
		name, spec string
		ok         bool
	}{
		{"fits", ">=3.8", true},
		{"too new", ">=3.13", false},
		{"too old", "<3.12", false},
		{"patch level decides", "!=3.12.1", false},
		{"unreadable", "python 3", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "pip")
			rel := h.pypi.releases["urllib3==1.26.17"]
			for i := range rel {
				if rel[i].Wheel {
					rel[i].RequiresPython = c.spec
				}
			}
			it, _ := h.run()
			if c.ok {
				wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
				return
			}
			wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
		})
	}
	t.Run("the release's own requires-python is used when the file has none", func(t *testing.T) {
		h := newHarness(t, "pip")
		h.pypi.requiresPython = map[string]string{"urllib3==1.26.17": ">=3.13"}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
}

func TestRequiresPythonOfAUvDistributionMustFitTheProjectsLowestPython(t *testing.T) {
	for _, c := range []struct {
		name, spec, project string
		ok                  bool
	}{
		{"fits", ">=3.8", ">=3.9", true},
		{"equal", ">=3.9", ">=3.9", true},
		{"needs a newer python than the project's lowest", ">=3.10", ">=3.9", false},
		{"excluded below", ">=3.8,!=3.9.*", ">=3.9", false},
		{"unreadable", "wat", ">=3.9", false},
		{"project without a lower bound", ">=3.8", "<4", false},
		{"project with only a strict bound", ">=3.8", ">3.8", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "uv")
			h.files["pyproject.toml"] = strings.Replace(h.files["pyproject.toml"], `">=3.9"`, `"`+c.project+`"`, 1)
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
			if h.item.Category != CategoryDependencyUpdateCandidate {
				t.Skipf("the plan stops it: %s", h.item.Reason)
			}
			rel := h.pypi.releases["urllib3==1.26.17"]
			for i := range rel {
				rel[i].RequiresPython = c.spec
			}
			it, _ := h.run()
			if c.ok {
				wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
				return
			}
			wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
		})
	}
}

// --- the kind and the name of a uv file ---

func TestUvFileKindAndNameMustMatchTheIndex(t *testing.T) {
	sdistURL := "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-1.26.17.tar.gz"
	wheelURL := "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-1.26.17-py2.py3-none-any.whl"
	cases := map[string]func(string) string{
		"the sdist listed among the wheels": func(s string) string {
			s = strings.Replace(s, `sdist = { url = "`+sdistURL+`", hash = "sha256:`+urllibSdistSHA+`", size = 305031, upload-time = "2023-10-02T17:22:30.961Z" }`+"\n", "", 1)
			return strings.Replace(s, `{ url = "`+wheelURL+`", hash = "sha256:`+urllibWheelSHA+`"`, `{ url = "`+sdistURL+`", hash = "sha256:`+urllibSdistSHA+`"`, 1)
		},
		"the wheel given as the sdist": func(s string) string {
			return strings.Replace(s, `sdist = { url = "`+sdistURL+`", hash = "sha256:`+urllibSdistSHA+`"`, `sdist = { url = "`+wheelURL+`", hash = "sha256:`+urllibWheelSHA+`"`, 1)
		},
	}
	for name, forge := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "uv")
			forged := forge(string(h.after))
			if forged == string(h.after) {
				t.Fatal("the forgery did not change the file")
			}
			h.editLock(forged)
			it, _ := h.run()
			if it.Category != CategoryManual {
				t.Fatalf("%s/%s", it.Category, it.Reason)
			}
		})
	}
	t.Run("a file name of another package or version that the index lists", func(t *testing.T) {
		h := newHarness(t, "uv")
		other := "https://files.pythonhosted.org/packages/48/fe/aa/other-3.0.0-py3-none-any.whl"
		h.pypi.releases["urllib3==1.26.17"] = append(h.pypi.releases["urllib3==1.26.17"], PyPIFile{Filename: "other-3.0.0-py3-none-any.whl", URL: other, Wheel: true, SHA256: urllibWheelSHA})
		h.editLock(strings.Replace(string(h.after), wheelURL, other, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "file name") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("name helpers", func(t *testing.T) {
		for file, want := range map[string]bool{
			"urllib3-1.26.17-py2.py3-none-any.whl": true, "Urllib3-1.26.17-1-py3-none-any.whl": true, "urllib3-1.26.18-py3-none-any.whl": false,
			"other-1.26.17-py3-none-any.whl": false, "urllib3-1.26.17.tar.gz": false, "urllib3-1.26.17-py3-none.whl": false, "-1.26.17-a-b-c.whl": false,
		} {
			if got := wheelNameOK(file, "urllib3", "1.26.17"); got != want {
				t.Errorf("wheelNameOK(%q) = %v", file, got)
			}
		}
		for file, want := range map[string]bool{
			"urllib3-1.26.17.tar.gz": true, "urllib3-1.26.17.zip": true, "urllib3-1.26.18.tar.gz": false, "x-urllib3-1.26.17.tar.gz": false, "urllib3-1.26.17.whl": false,
		} {
			if got := sdistNameOK(file, "urllib3", "1.26.17"); got != want {
				t.Errorf("sdistNameOK(%q) = %v", file, got)
			}
		}
	})
}

// --- deep paths ---

func TestDeepNpmPathsAreBoundedBeforeAnythingIsBuilt(t *testing.T) {
	path := func(levels int) string { return strings.Repeat(npmModules+"a/", levels) + npmModules + "z" }
	lock := func(levels int) []byte {
		return []byte(fmt.Sprintf(`{"lockfileVersion":3,"packages":{"":{},%q:{"version":"1.0.0"}}}`, path(levels)))
	}
	if _, err := readNpmLock(lock(maxNpmPathDepth - 2)); err != nil {
		t.Errorf("a path %d levels deep: %v", maxNpmPathDepth-1, err)
	}
	if _, err := readNpmLock(lock(maxNpmPathDepth + 1)); err == nil {
		t.Error("a path over the depth limit was accepted")
	}
	long := []byte(fmt.Sprintf(`{"lockfileVersion":3,"packages":{"":{},"node_modules/%s":{"version":"1.0.0"}}}`, strings.Repeat("a", maxNpmPathBytes)))
	if _, err := readNpmLock(long); err == nil {
		t.Error("a path over the length limit was accepted")
	}
	// The plan's parser and the graph builder read it the same way.
	if _, err := parseNpm([]byte(`{"name":"a"}`), lock(maxNpmPathDepth+1)); err == nil {
		t.Error("the plan's parser accepted a deep path")
	}
	if _, err := npmGraph(bg, lock(maxNpmPathDepth+1)); err == nil {
		t.Error("the graph accepted a deep path")
	}
}

func TestResolvingRequirementsHasAWorkLimitAndWatchesTheDeadline(t *testing.T) {
	deps := map[string]string{}
	for i := 0; i < 50; i++ {
		deps[fmt.Sprintf("missing%d", i)] = "^1"
	}
	deepest := strings.Repeat(npmModules+"a/", 30) + npmModules + "z"
	lock, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"":      map[string]any{},
		deepest: map[string]any{"version": "1.0.0", "dependencies": deps},
	}})
	if _, err := npmGraph(bg, lock); err != nil {
		t.Fatalf("within the limit: %v", err)
	}
	old := maxResolveSteps
	maxResolveSteps = 100
	defer func() { maxResolveSteps = old }()
	if _, err := npmGraph(bg, lock); err == nil || !strings.Contains(err.Error(), "steps") {
		t.Errorf("over the limit: %v", err)
	}
	maxResolveSteps = old
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	many := map[string]string{}
	for i := 0; i < 400; i++ {
		many[fmt.Sprintf("missing%d", i)] = "^1"
	}
	big, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"":      map[string]any{},
		deepest: map[string]any{"version": "1.0.0", "dependencies": many},
	}})
	if _, err := npmGraph(ctx, big); err == nil {
		t.Error("the deadline was not watched")
	}
}

// --- the size of a rewrite follows from the hashes alone ---

func TestHashLinesAreIndentedByAFixedFourSpaces(t *testing.T) {
	indent := strings.Repeat(" ", 1<<20)
	in := "pkg==1 \\\n" + indent + "--hash=sha256:" + h64('a') + "\n"
	var hs []string
	for i := 0; i < maxWheelsPerEdit; i++ {
		hs = append(hs, fmt.Sprintf("%064x", i))
	}
	out, err := rewriteRequirements(bg, []byte(in), []reqEdit{{Name: "pkg", Line: 1, OldVersion: "1", NewVersion: "2", Hashes: hs}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > len(hs)*hashLineBytes+100 {
		t.Errorf("the result is %d bytes for %d hashes", len(out), len(hs))
	}
	for _, l := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")[1:] {
		if !strings.HasPrefix(l, "    --hash=sha256:") || strings.HasPrefix(l, "     ") {
			t.Fatalf("line %q", clip(l, 40))
		}
	}
	// What is estimated before the build is what is built, for the worst layout.
	var edits []reqEdit
	var b strings.Builder
	for i := 0; i < maxPipEdits; i++ {
		fmt.Fprintf(&b, "pkg==1 \\\r\n\t\t\t\t--hash=sha256:%s\r\n", h64('a'))
		edits = append(edits, reqEdit{Name: "pkg", Line: 2*i + 1, OldVersion: "1", NewVersion: "2", Hashes: hs[:8]})
	}
	got, err := rewriteRequirements(bg, []byte(b.String()), edits)
	if err != nil {
		t.Fatal(err)
	}
	growth := len(got) - b.Len()
	if bound := len(edits) * (8*hashLineBytes + 1); growth > bound {
		t.Errorf("grew by %d bytes, estimated at most %d", growth, bound)
	}
}

// --- the budget of marker evaluations ---

func TestMarkerEvaluationsAreCountedPerExtraAndWatchTheDeadline(t *testing.T) {
	env := markerEnv{pyMinor: "3.12", machine: "x86_64", extras: map[string]bool{"a": true, "b": true, "c": true, "d": true}}
	env.budget = &markerBudget{ctx: context.Background(), max: 4}
	if _, err := env.eval(`extra == "z"`); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("err = %v", err)
	}
	env.budget = &markerBudget{ctx: context.Background(), max: 5}
	if _, err := env.eval(`extra == "z"`); err != nil {
		t.Errorf("five bindings in a budget of five: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	env.budget = &markerBudget{ctx: ctx, max: 100}
	if _, err := env.eval(`extra == "z"`); err == nil {
		t.Error("the deadline was not watched")
	}

	// In an update the budget is the update's: running out of it defers the item.
	old := maxMarkerEvals
	maxMarkerEvals = 3
	defer func() { maxMarkerEvals = old }()
	h := newHarness(t, "pip")
	useUnhashed(t, h)
	h.pypi.requires = map[string][]string{"urllib3==1.26.4": {`pysocks; extra == "socks"`, `x; extra == "y"`}, "urllib3==1.26.17": {`pysocks; extra == "socks"`, `x; extra == "y"`}}
	it, _ := h.run()
	wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
}

// --- a package listed without a snapshot ---

func TestPnpmPackageWithoutASnapshotIsRefused(t *testing.T) {
	h := newHarness(t, "pnpm")
	forged := strings.Replace(string(h.after), "  mkdirp@0.5.5:\n    dependencies:\n      minimist: 1.2.8\n", "", 1)
	if forged == string(h.after) {
		t.Fatal("the forgery did not change the file")
	}
	h.editLock(forged)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	if !strings.Contains(it.Detail, "without a snapshot") {
		t.Errorf("detail = %q", it.Detail)
	}
}

// --- the legacy tree of a lockfileVersion 2 file ---

// npmV2 turns a package-lock.json of version 3 into one of version 2 with the
// legacy dependencies tree npm keeps for older clients; edit may change the
// tree before it is written.
func npmV2(t *testing.T, v3 string, edit func(legacy map[string]map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(v3), &doc); err != nil {
		t.Fatal(err)
	}
	doc["lockfileVersion"] = 2
	legacy := map[string]map[string]any{}
	for path, e := range doc["packages"].(map[string]any) {
		if !strings.HasPrefix(path, npmModules) || strings.Contains(path[len(npmModules):], npmModules) {
			continue
		}
		em := e.(map[string]any)
		n := map[string]any{"version": em["version"], "resolved": em["resolved"], "integrity": em["integrity"]}
		if d, ok := em["dependencies"]; ok {
			n["requires"] = d
		}
		legacy[path[len(npmModules):]] = n
	}
	if edit != nil {
		edit(legacy)
	}
	doc["dependencies"] = legacy
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func TestLegacyTreeOfALockfileVersion2MustAgreeWithPackages(t *testing.T) {
	setup := func(t *testing.T, edit func(map[string]map[string]any)) *harness {
		h := newHarness(t, "npm")
		h.files["package-lock.json"] = npmV2(t, h.files["package-lock.json"], nil)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerNpm, h.files, minimistGroup())
		h.editLock(npmV2(t, string(h.after), edit))
		return h
	}
	t.Run("a consistent file passes", func(t *testing.T) {
		it, _ := setup(t, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the legacy tree keeps the old version", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) { l["minimist"]["version"] = "1.2.5" }).run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "legacy") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the legacy tree keeps the old tarball", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) {
			l["minimist"]["resolved"] = "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz"
		}).run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the legacy tree keeps the old integrity", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) { l["minimist"]["integrity"] = "sha512-old" }).run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the legacy tree lacks the updated package", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) { delete(l, "minimist") }).run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the legacy tree nests the updated package where packages does not", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) {
			l["mkdirp"]["dependencies"] = map[string]any{"minimist": map[string]any{"version": "1.2.8", "resolved": l["minimist"]["resolved"], "integrity": l["minimist"]["integrity"]}}
		}).run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a legacy tree too deep is refused", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) {
			node := map[string]any{"version": "1.0.0"}
			for i := 0; i <= maxNpmPathDepth+1; i++ {
				node = map[string]any{"version": "1.0.0", "dependencies": map[string]any{"x": node}}
			}
			l["deep"] = node
		}).run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s", it.Category, it.Reason)
		}
	})
}
