package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

const (
	backendWorkspace  = "allowBuilds:\n  '@nestjs/core': true\n  '@scarf/scarf': true\n  unrs-resolver: true\n"
	frontendWorkspace = "allowBuilds:\n  msw: true\n  sharp: true\n  unrs-resolver: true\nsupportedArchitectures:\n  os: [linux]\n  cpu: [x64, arm64]\n  libc: [glibc, musl]\n"
)

func TestPnpmWorkspaceFileOfSettingsOnly(t *testing.T) {
	for name, doc := range map[string]string{
		"the backend's":                   backendWorkspace,
		"the frontend's":                  frontendWorkspace,
		"an empty file":                   "",
		"comments only":                   "# nothing here\n",
		"an explicit null":                "~\n",
		"the older lists":                 "onlyBuiltDependencies:\n  - esbuild\nignoredBuiltDependencies: [core-js]\nneverBuiltDependencies: []\n",
		"false and a placeholder":         "allowBuilds:\n  esbuild: false\n  core-js: set this to true or false\n",
		"a matcher with a version":        "allowBuilds:\n  nx@21.6.4 || 21.6.5: true\n",
		"the current platform":            "supportedArchitectures:\n  os: [current, win32]\n  cpu: [x64]\n",
		"an empty supportedArchitectures": "supportedArchitectures: {}\n",
		"block lists":                     "supportedArchitectures:\n  os:\n    - linux\n    - darwin\n",
	} {
		if reason, why := pnpmWorkspaceProblem([]byte(doc)); reason != "" {
			t.Errorf("%s: %s (%s)", name, reason, why)
		}
	}
}

func TestPnpmWorkspaceFileThatIsNotSettingsOnly(t *testing.T) {
	cases := []struct {
		name, doc string
		reason    Reason
		detail    string
	}{
		{"packages", "packages:\n  - 'packages/*'\n", ReasonWorkspaceUnsupported, "packages"},
		{"packages with settings", backendWorkspace + "packages: []\n", ReasonWorkspaceUnsupported, "packages"},
		{"catalog", "catalog:\n  react: ^18\n", ReasonWorkspaceSettingsUnsupported, "catalog"},
		{"catalogs", "catalogs:\n  a: {x: 1}\n", ReasonWorkspaceSettingsUnsupported, "catalogs"},
		{"overrides", "overrides:\n  lodash: 4.17.21\n", ReasonWorkspaceSettingsUnsupported, "overrides"},
		{"packageExtensions", "packageExtensions: {}\n", ReasonWorkspaceSettingsUnsupported, "packageExtensions"},
		{"patchedDependencies", "patchedDependencies:\n  a@1: p.patch\n", ReasonWorkspaceSettingsUnsupported, "patchedDependencies"},
		{"minimumReleaseAge", "minimumReleaseAge: 0\n", ReasonWorkspaceSettingsUnsupported, "minimumReleaseAge"},
		{"registries", "registries:\n  default: https://x\n", ReasonWorkspaceSettingsUnsupported, "registries"},
		{"a key nobody knows", backendWorkspace + "frobnicate: true\n", ReasonWorkspaceSettingsUnsupported, "frobnicate"},
		{"several keys", "overrides: {}\ncatalog: {}\nzzz: 1\n", ReasonWorkspaceSettingsUnsupported, "catalog, overrides, zzz"},
		{"a key spelled in another case", "AllowBuilds:\n  a: true\n", ReasonWorkspaceSettingsUnsupported, "AllowBuilds"},
		{"allowBuilds as a list", "allowBuilds: [a]\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with a mapping value", "allowBuilds:\n  a: {b: c}\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with a list value", "allowBuilds:\n  a: [true]\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with an empty value", "allowBuilds:\n  a:\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds as a scalar", "allowBuilds: true\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"a built list as a mapping", "onlyBuiltDependencies: {a: true}\n", ReasonWorkspaceSettingsUnsupported, "onlyBuiltDependencies"},
		{"a built list of lists", "ignoredBuiltDependencies: [[a]]\n", ReasonWorkspaceSettingsUnsupported, "ignoredBuiltDependencies"},
		{"a built list as a string", "neverBuiltDependencies: esbuild\n", ReasonWorkspaceSettingsUnsupported, "neverBuiltDependencies"},
		{"supportedArchitectures as a list", "supportedArchitectures: [linux]\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"supportedArchitectures with another member", "supportedArchitectures:\n  os: [linux]\n  abi: [x]\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"supportedArchitectures os as a string", "supportedArchitectures:\n  os: linux\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"supportedArchitectures with a mapping inside", "supportedArchitectures:\n  os: [{a: b}]\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"supportedArchitectures with an odd name", "supportedArchitectures:\n  cpu: ['x64; rm -rf']\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"supportedArchitectures with an empty name", "supportedArchitectures:\n  cpu: ['']\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"allowBuilds with a number", "allowBuilds:\n  x: 123\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with a float", "allowBuilds:\n  x: 1.5\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with a tagged number", "allowBuilds:\n  x: !!int 7\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with a number as a matcher", "allowBuilds:\n  123: true\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"allowBuilds with a boolean as a matcher", "allowBuilds:\n  true: true\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		{"a built list of booleans", "onlyBuiltDependencies: [true]\n", ReasonWorkspaceSettingsUnsupported, "onlyBuiltDependencies"},
		{"a built list of numbers", "ignoredBuiltDependencies: [1, 2]\n", ReasonWorkspaceSettingsUnsupported, "ignoredBuiltDependencies"},
		{"a built list of nulls", "neverBuiltDependencies: [~]\n", ReasonWorkspaceSettingsUnsupported, "neverBuiltDependencies"},
		{"supportedArchitectures cpu numbers", "supportedArchitectures:\n  cpu: [123]\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"supportedArchitectures booleans", "supportedArchitectures:\n  os: [true]\n", ReasonWorkspaceSettingsUnsupported, "supportedArchitectures"},
		{"a list at the top", "- allowBuilds\n", ReasonUnparsableSource, ""},
		{"a scalar at the top", "allowBuilds\n", ReasonUnparsableSource, ""},
		{"broken YAML", "allowBuilds: [\n", ReasonUnparsableSource, ""},
		{"two documents", "allowBuilds: {a: true}\n---\nallowBuilds: {b: true}\n", ReasonUnparsableSource, ""},
		{"a repeated key", "allowBuilds: {a: true}\nallowBuilds: {b: true}\n", ReasonUnparsableSource, ""},
		{"a repeated key inside", "allowBuilds:\n  a: true\n  a: false\n", ReasonUnparsableSource, ""},
		{"an anchor", "allowBuilds: &x {a: true}\nonlyBuiltDependencies: *x\n", ReasonUnparsableSource, ""},
		{"a merge key", "allowBuilds:\n  <<: {a: true}\n", ReasonUnparsableSource, ""},
		{"a custom tag", "allowBuilds: !evil {a: true}\n", ReasonUnparsableSource, ""},
	}
	for _, c := range cases {
		reason, why := pnpmWorkspaceProblem([]byte(c.doc))
		if reason != c.reason || !strings.Contains(why, c.detail) {
			t.Errorf("%s: %s / %q", c.name, reason, why)
		}
	}
	// A file over the size limit is not read.
	if reason, _ := pnpmWorkspaceProblem([]byte("allowBuilds:\n" + strings.Repeat("  a: true # "+strings.Repeat("x", 100)+"\n", maxYAMLBytes/100))); reason == "" {
		t.Error("an oversized file was accepted")
	}
	// The lists are bounded.
	var many strings.Builder
	many.WriteString("onlyBuiltDependencies:\n")
	for i := 0; i <= maxWorkspaceEntries; i++ {
		many.WriteString("  - p\n")
	}
	if reason, _ := pnpmWorkspaceProblem([]byte(many.String())); reason != ReasonWorkspaceSettingsUnsupported {
		t.Errorf("a list over the limit: %s", reason)
	}
}

func TestLanguagePlan_PnpmWorkspaceFileOfSettings(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	plan := func(setup func(f *fakeGitHub)) LanguageItem {
		gh := newFakeGitHub()
		gh.put("ex/app", ".", "package.json", pnpmManifest)
		gh.put("ex/app", ".", "pnpm-lock.yaml", pnpmLock)
		setup(gh)
		return langPlan(t, gh, deps, nil, in).LanguageItems[0]
	}
	for name, doc := range map[string]string{"backend": backendWorkspace, "frontend": frontendWorkspace, "comments only": "# settings\n"} {
		t.Run(name, func(t *testing.T) {
			it := plan(func(f *fakeGitHub) { f.put("ex/app", ".", "pnpm-workspace.yaml", doc) })
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
			}
			var blob string
			for _, f := range it.Source.Files {
				if f.Path == "pnpm-workspace.yaml" {
					blob = f.BlobSHA
				}
			}
			if blob != blobOf(doc) {
				t.Errorf("the settings file is not recorded with its blob: %+v", it.Source.Files)
			}
		})
	}
	t.Run("the file is part of what an update is made from", func(t *testing.T) {
		a := plan(func(f *fakeGitHub) { f.put("ex/app", ".", "pnpm-workspace.yaml", backendWorkspace) })
		b := plan(func(f *fakeGitHub) { f.put("ex/app", ".", "pnpm-workspace.yaml", frontendWorkspace) })
		c := plan(func(f *fakeGitHub) {})
		if LanguageInputFingerprint(a) == LanguageInputFingerprint(b) || LanguageInputFingerprint(a) == LanguageInputFingerprint(c) {
			t.Error("the fingerprint does not depend on the settings file")
		}
	})
	for name, c := range map[string]struct {
		doc    string
		reason Reason
		detail string
	}{
		"packages":     {"packages:\n  - 'packages/*'\n", ReasonWorkspaceUnsupported, "packages"},
		"overrides":    {backendWorkspace + "overrides:\n  lodash: 4.17.21\n", ReasonWorkspaceSettingsUnsupported, "overrides"},
		"a wrong type": {"allowBuilds: [a]\n", ReasonWorkspaceSettingsUnsupported, "allowBuilds"},
		"broken":       {"allowBuilds: [\n", ReasonUnparsableSource, "pnpm-workspace.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			it := plan(func(f *fakeGitHub) { f.put("ex/app", ".", "pnpm-workspace.yaml", c.doc) })
			if it.Category != CategoryManual || it.Reason != c.reason || !strings.Contains(it.Detail, c.detail) {
				t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
			}
			for _, p := range it.Packages {
				if p.Reason != c.reason {
					t.Errorf("package reason = %s", p.Reason)
				}
			}
		})
	}
	t.Run("the file is a symbolic link", func(t *testing.T) {
		it := plan(func(f *fakeGitHub) {
			f.putEntry("ex/app", ".", github.Entry{Name: "pnpm-workspace.yaml", Type: github.EntrySymlink})
		})
		if it.Reason != ReasonDependencyFileUnusable {
			t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
}

// --- the update stage hands the file to the work container ---

// pnpmWithSettings is the pnpm harness with a pnpm-workspace.yaml in the
// project.
func pnpmWithSettings(t *testing.T, settings string) *harness {
	t.Helper()
	h := newHarness(t, "pnpm")
	if settings != "" {
		h.files["pnpm-workspace.yaml"] = settings
	}
	h.item = itemFor(t, ManagerPnpm, h.files, h.fx.group())
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	return h
}

func TestPnpmUpdateGivesTheSettingsFileToTheWorkContainer(t *testing.T) {
	h := pnpmWithSettings(t, frontendWorkspace)
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if len(h.work.jobs) != 1 {
		t.Fatalf("jobs = %d", len(h.work.jobs))
	}
	job := h.work.jobs[0]
	if err := job.Validate(); err != nil {
		t.Fatal(err)
	}
	var declared *worker.Input
	for i := range job.Inputs {
		if job.Inputs[i].Path == "pnpm-workspace.yaml" {
			declared = &job.Inputs[i]
		}
	}
	if declared == nil || declared.SHA256 != sha256Hex([]byte(frontendWorkspace)) || declared.Size != int64(len(frontendWorkspace)) {
		t.Fatalf("inputs = %+v", job.Inputs)
	}
	if string(h.work.srcs[0]["pnpm-workspace.yaml"]) != frontendWorkspace {
		t.Error("the content was not given")
	}
	// It is not an output, and it is not part of the pull request.
	for _, o := range job.Outputs {
		if o == "pnpm-workspace.yaml" {
			t.Error("the settings file is an output")
		}
	}
	for _, a := range it.Artifacts {
		if strings.HasSuffix(a.Path, "pnpm-workspace.yaml") {
			t.Errorf("artifact %s", a.Path)
		}
	}
}

func TestPnpmUpdateWithoutSettingsGivesNoSuchInput(t *testing.T) {
	h := pnpmWithSettings(t, "")
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	for _, in := range h.work.jobs[0].Inputs {
		if in.Path == "pnpm-workspace.yaml" {
			t.Error("an input for a file the project does not have")
		}
	}
	if _, ok := h.work.srcs[0]["pnpm-workspace.yaml"]; ok {
		t.Error("a file the project does not have was given")
	}
}

func TestEveryJobOfAnEditedPnpmUpdateGetsTheSettingsFile(t *testing.T) {
	h := editedPnpmWithSettings(t)
	got, _ := h.run()
	wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
	if len(h.work.jobs) != 2 {
		t.Fatalf("jobs = %d", len(h.work.jobs))
	}
	for i, src := range h.work.srcs {
		if string(src["pnpm-workspace.yaml"]) != frontendWorkspace {
			t.Errorf("job %d lacks the settings file", i)
		}
	}
}

func TestSettingsFileChangedByAStepRefusesTheUpdate(t *testing.T) {
	h := pnpmWithSettings(t, backendWorkspace)
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{failStep: stepUpdate, failReason: worker.ReasonInputModified}
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonWorkInputModified)
}

func TestSettingsFileOfTheUpdateIsTheBlobOfThePlan(t *testing.T) {
	h := pnpmWithSettings(t, backendWorkspace)
	h.gh.files["pnpm-workspace.yaml"] = []byte(backendWorkspace + "# edited later\n")
	it, _ := h.run()
	wantCategory(t, it, CategoryFailed, ReasonSourceChanged)
	if h.work.calls != 0 {
		t.Error("a job ran")
	}
}

func TestSettingsFileThePlanLeftOutIsNotGuessedAtTheUpdate(t *testing.T) {
	// A file that is in the plan's record but that the update stage no longer
	// accepts is refused before any job.
	h := pnpmWithSettings(t, backendWorkspace)
	bad := "overrides:\n  lodash: 1.0.0\n"
	h.gh.files["pnpm-workspace.yaml"] = []byte(bad)
	for i := range h.item.Source.Files {
		if h.item.Source.Files[i].Path == "pnpm-workspace.yaml" {
			h.item.Source.Files[i].BlobSHA = gitBlobSHA([]byte(bad))
		}
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonWorkspaceSettingsUnsupported)
	if h.work.calls != 0 {
		t.Error("a job ran")
	}
}

// editedPnpmWithSettings is a pnpm project whose package.json asks for
// minimist as 1.2.5 (edited to 1.2.6 by the update), with a settings file.
func editedPnpmWithSettings(t *testing.T) *harness {
	t.Helper()
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
	files := map[string]string{
		"package.json":        "{\n  \"name\": \"a\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"1.2.5\"\n  }\n}\n",
		"pnpm-lock.yaml":      lockOf("1.2.5", "1.2.5", "sha512-aaa"),
		"pnpm-workspace.yaml": frontendWorkspace,
	}
	item := itemFor(t, ManagerPnpm, files, minimistGroup())
	if item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not a candidate: %s %s", item.Category, item.Detail)
	}
	h := newHarness(t, "pnpm")
	h.files, h.item = files, item
	h.gh = ghFor(files)
	h.cfg.GitHub = h.gh
	h.after = []byte(lockOf("1.2.6", "1.2.6", "sha512-bbb"))
	h.npm.dists["minimist@1.2.6"] = NpmDist{Tarball: "https://registry.npmjs.org/minimist/-/minimist-1.2.6.tgz", Integrity: "sha512-bbb"}
	h.fx.beforePkgs = [][2]string{{"minimist", "1.2.5"}}
	h.fx.afterPkgs = [][2]string{{"minimist", "1.2.6"}}
	return h
}

func TestPnpmRecordsAnOptionalPeerThatOnlyTheMetaListsAsAnyRange(t *testing.T) {
	node := &depNode{name: "sharp", version: "0.35.5", install: map[string]string{"peerDependenciesMeta": "@types/node"},
		peerRanges: map[string]string{"@types/node": "*"}}
	reg := NpmDist{Install: map[string]string{"peerDependenciesMeta": "@types/node"}}
	if why := installProblem(ManagerPnpm, node, reg); why != "" {
		t.Errorf("pnpm's own form was refused: %s", why)
	}
	// A listed range is the range, and the meta adds nothing to it.
	node.peerRanges = map[string]string{"@types/node": ">= 14"}
	reg.PeerDependencies = map[string]string{"@types/node": ">= 14"}
	if why := installProblem(ManagerPnpm, node, reg); why != "" {
		t.Errorf("a listed peer: %s", why)
	}
	// Other forms are still refused.
	for name, ranges := range map[string]map[string]string{
		"another range":                     {"@types/node": "^1"},
		"a peer the registry does not have": {"@types/node": ">= 14", "x": "*"},
		"no peer":                           {},
	} {
		node.peerRanges = ranges
		if why := installProblem(ManagerPnpm, node, reg); why == "" {
			t.Errorf("%s was accepted", name)
		}
	}
	// npm does not add the optional peer.
	npmNode := &depNode{name: "sharp", version: "0.35.5", install: map[string]string{"peerDependenciesMeta": "@types/node"}, peerRanges: map[string]string{"@types/node": "*"}}
	if why := installProblem(ManagerNpm, npmNode, NpmDist{Install: map[string]string{"peerDependenciesMeta": "@types/node"}}); why == "" {
		t.Error("npm: a peer the registry does not list was accepted")
	}
}
