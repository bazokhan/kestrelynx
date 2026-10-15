package remediation

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// TestIntegrationLangUpdate runs the update stage over the R4 fixtures with
// the official images the build pins (see itSetup for the settings).
func TestIntegrationLangUpdate(t *testing.T) {
	e := itSetup(t)
	ctx, env := e.ctx, e.image
	nodeOrigin := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/minimist/package.json"}
	pyOrigin := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "usr/local/lib/python3.12/site-packages/urllib3-1.26.4.dist-info/METADATA", Target: "Python"}
	minimist := func() *findingGroup {
		return group(typeNodePkg, "minimist", "1.2.5", nodeOrigin, CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
	}
	urllib3 := func() *findingGroup {
		return group(typePythonPkg, "urllib3", "1.26.4", pyOrigin,
			CVERef{VulnID: "CVE-2021-33503", FixedVers: []string{"1.26.5"}},
			CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17", "2.0.6"}})
	}

	// declare adds members to the top level of the package.json of a fixture.
	declare := func(members string) func(map[string]string) {
		return func(f map[string]string) {
			f["package.json"] = strings.Replace(f["package.json"], "{", "{\n  "+members+",", 1)
		}
	}
	// requires changes requires-python in the pyproject.toml and the uv.lock of
	// the uv fixture alike, so that the lockfile still matches the project.
	requires := func(spec string) func(map[string]string) {
		return func(f map[string]string) {
			f["pyproject.toml"] = strings.Replace(f["pyproject.toml"], `requires-python = ">=3.9"`, `requires-python = "`+spec+`"`, 1)
			f["uv.lock"] = strings.Replace(f["uv.lock"], `requires-python = ">=3.9"`, `requires-python = "`+spec+`"`, 1)
		}
	}
	withFile := func(name, content string, rest func(map[string]string)) func(map[string]string) {
		return func(f map[string]string) {
			f[name] = content
			if rest != nil {
				rest(f)
			}
		}
	}
	// urllib3OnPython315 is the same finding in an image whose Python is 3.15,
	// which makes pip target Python 3.15.
	urllib3OnPython315 := func() *findingGroup {
		o := pyOrigin
		o.PkgPath = strings.Replace(o.PkgPath, "python3.12", "python3.15", 1)
		return group(typePythonPkg, "urllib3", "1.26.4", o,
			CVERef{VulnID: "CVE-2021-33503", FixedVers: []string{"1.26.5"}},
			CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17", "2.0.6"}})
	}
	// onNode26 makes the project name Node.js 26 and the manager release.
	onNode26 := func(manager string) func(map[string]string) {
		return func(f map[string]string) {
			f[".nvmrc"] = "26\n"
			declare(`"packageManager": "` + manager + `"`)(f)
		}
	}
	cases := []struct {
		name    string
		manager DependencyManager
		dir     string
		files   []string
		group   func() *findingGroup
		pkg     string
		// mutate changes the fixture files before the item is planned, and
		// wantNote is a text one note of the run must contain.
		mutate   func(map[string]string)
		wantNote string
		// wantEdit is "from>to" of the one manifest edit the run must make.
		wantEdit string
		// wantTool and wantSource are the release of the manager the run must
		// use and why; empty means the default release.
		wantTool, wantSource string
	}{
		{"npm", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist", nil, "", "", "", ""},
		{"pnpm", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist", nil, "", "", "", ""},
		{"uv", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3", nil, "", "", "", ""},
		{"pip", ManagerPip, "pip", []string{"requirements.txt"}, urllib3, "urllib3", nil, "", "", "", ""},
		{"npm_direct_pinned_out_of_range", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"mkdirp": "0.5.5"`, `"minimist": "1.2.5",
    "mkdirp": "0.5.5"`, 1)
				f["package-lock.json"] = strings.Replace(f["package-lock.json"], `"dependencies": {
        "mkdirp": "0.5.5"`, `"dependencies": {
        "minimist": "1.2.5",
        "mkdirp": "0.5.5"`, 1)
			}, "", "1.2.5>1.2.6", "", ""},
		{"pnpm_direct_pinned_out_of_range", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"mkdirp": "0.5.5"`, `"minimist": "1.2.5",
    "mkdirp": "0.5.5"`, 1)
				f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], `    dependencies:
      mkdirp:`, `    dependencies:
      minimist:
        specifier: 1.2.5
        version: 1.2.5
      mkdirp:`, 1)
			}, "", "1.2.5>1.2.6", "", ""},
		{"uv_direct_pinned_out_of_range", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			func(f map[string]string) {
				f["pyproject.toml"] = strings.Replace(f["pyproject.toml"], `"urllib3>=1.26,<2"`, `"urllib3==1.26.4"`, 1)
				f["uv.lock"] = strings.Replace(f["uv.lock"], `specifier = ">=1.26,<2"`, `specifier = "==1.26.4"`, 1)
			}, "", "urllib3==1.26.4>urllib3==1.26.17", "", ""},
		{"pnpm_workspace_allow_builds", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) { f["pnpm-workspace.yaml"] = backendWorkspace }, "", "", "", ""},
		{"pnpm_workspace_supported_architectures", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) { f["pnpm-workspace.yaml"] = frontendWorkspace }, "", "", "", ""},
		// A lockfile of version 2 keeps its packages in a second tree as well; the
		// target is taken out of both.
		{"npm_lockfile_v2", ManagerNpm, "npm_v2", []string{"package.json", "package-lock.json"}, minimist, "minimist", nil, "", "", "", ""},
		// A direct dependency whose range allows the fixed version is taken out of
		// the lockfile and resolved again within its range, with no edit.
		{"npm_direct_in_range", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"mkdirp": "0.5.5"`, `"minimist": "^1.2.0",
    "mkdirp": "0.5.5"`, 1)
				f["package-lock.json"] = strings.Replace(f["package-lock.json"], `"dependencies": {
        "mkdirp": "0.5.5"`, `"dependencies": {
        "minimist": "^1.2.0",
        "mkdirp": "0.5.5"`, 1)
			}, "", "", "", ""},
		{"pnpm_direct_in_range", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"mkdirp": "0.5.5"`, `"minimist": "^1.2.0",
    "mkdirp": "0.5.5"`, 1)
				f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], `    dependencies:
      mkdirp:`, `    dependencies:
      minimist:
        specifier: ^1.2.0
        version: 1.2.5
      mkdirp:`, 1)
			}, "", "", "", ""},
		// The release of the manager the project declares is the one that runs,
		// and nothing of the image's own npm, corepack or yarn is used.
		{"pnpm_declared_9", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			declare(`"packageManager": "pnpm@9.15.9"`), "", "", "9.15.9", "declared"},
		{"pnpm_declared_10", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			declare(`"packageManager": "pnpm@10.34.4"`), "", "", "10.34.4", "declared"},
		{"pnpm_declared_12", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			declare(`"packageManager": "pnpm@12.11.2"`), "", "", "12.11.2", "declared"},
		{"pnpm_range_default", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			declare(`"engines": {"pnpm": ">=10"}`), "", "", itDefaultToolVersions[ManagerPnpm], "default_in_range"},
		{"npm_declared_9", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			declare(`"packageManager": "npm@9.9.4"`), "", "", "9.9.4", "declared"},
		{"npm_declared_10", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			declare(`"packageManager": "npm@10.9.9"`), "", "", "10.9.9", "declared"},
		{"npm_declared_10_with_devEngines", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			declare(`"packageManager": "npm@10.9.9", "devEngines": {"packageManager": {"name": "npm", "version": "^10", "onFail": "error"}}`), "", "", "10.9.9", "declared"},
		{"npm_declared_12", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			declare(`"packageManager": "npm@12.2.0"`), "", "", "12.2.0", "declared"},
		{"npm_devEngines_range_default", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			declare(`"devEngines": {"packageManager": {"name": "npm", "version": "^11", "onFail": "error"}}`), "", "", itDefaultToolVersions[ManagerNpm], "default_in_range"},
		// A Node.js version the project declares chooses the image the update
		// runs in.
		{"npm_node24_from_nvmrc", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			func(f map[string]string) { f[".nvmrc"] = "24\n" }, "", "", "", ""},
		{"npm_node22_from_nvmrc", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			func(f map[string]string) { f[".nvmrc"] = "22\n" }, "", "", "", ""},
		{"pnpm_node22_from_nvmrc", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) { f[".nvmrc"] = "22\n" }, "", "", "", ""},
		{"pnpm_node22_from_engine_ranges", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			declare(`"engines": {"node": ">=20", "pnpm": ">=11"}`), "", "", itDefaultToolVersions[ManagerPnpm], "default_in_range"},
		// Node.js 26 with every manager release the build fetches: the frozen
		// check and the lock made again run on it.
		{"npm_node26_from_nvmrc", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			func(f map[string]string) { f[".nvmrc"] = "26\n" }, "", "", "", ""},
		{"pnpm_node26_from_nvmrc", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) { f[".nvmrc"] = "26\n" }, "", "", "", ""},
		{"npm_node26_declared_9", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			onNode26("npm@9.9.4"), "", "", "9.9.4", "declared"},
		{"npm_node26_declared_10", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			onNode26("npm@10.9.9"), "", "", "10.9.9", "declared"},
		{"npm_node26_declared_11", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			onNode26("npm@11.21.0"), "", "", "11.21.0", "declared"},
		{"npm_node26_declared_12", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			onNode26("npm@12.2.0"), "", "", "12.2.0", "declared"},
		{"pnpm_node26_declared_9", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			onNode26("pnpm@9.15.9"), "", "", "9.15.9", "declared"},
		{"pnpm_node26_declared_10", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			onNode26("pnpm@10.34.4"), "", "", "10.34.4", "declared"},
		{"pnpm_node26_declared_11", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			onNode26("pnpm@11.28.5"), "", "", "11.28.5", "declared"},
		{"pnpm_node26_declared_12", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			onNode26("pnpm@12.11.2"), "", "", "12.11.2", "declared"},
		// The Python the project declares chooses the image uv locks in; the
		// fixture's own requires-python (">=3.9") runs in the lowest series in
		// support.
		{"uv_python312_from_file", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			withFile(".python-version", "3.12\n", nil), "", "", "", ""},
		{"uv_python313_from_file", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			withFile(".python-version", "3.13.5\n", nil), "", "", "", ""},
		{"uv_python314_from_file", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			withFile(".python-version", "cpython-3.14\n", nil), "", "", "", ""},
		{"uv_python312_from_range", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			requires(">=3.12"), "", "", "", ""},
		{"uv_python314_from_range", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			requires(">=3.14"), "", "", "", ""},
		{"uv_python315_from_file", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			withFile(".python-version", "3.15\n", nil), "", "", "", ""},
		{"uv_python315_from_range", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			requires(">=3.15"), "", "", "", ""},
		// The lowest uv the build supports, on Python 3.15.
		{"uv_python315_declared_0_12_22", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			func(f map[string]string) {
				f[".python-version"] = "3.15\n"
				f["pyproject.toml"] = strings.Replace(f["pyproject.toml"], "[tool.uv]", "[tool.uv]\nrequired-version = \"==0.12.22\"", 1)
			}, "", "", "0.12.22", "declared"},
		// pip runs in the default image and targets the Python of the scanned one.
		{"pip_target_315", ManagerPip, "pip", []string{"requirements.txt"}, urllib3OnPython315, "urllib3", nil, "", "", "", ""},
		{"uv_declared", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			func(f map[string]string) {
				f["pyproject.toml"] = strings.Replace(f["pyproject.toml"], "[tool.uv]", "[tool.uv]\nrequired-version = \"==0.12.24\"", 1)
			}, "", "", "0.12.24", "declared"},
	}
	// One case per runtime of the table that is in support and has an image,
	// made from the table: each is chosen by a declaration (.nvmrc for npm and
	// pnpm, .python-version for uv) and runs the update and the check after it.
	// A series the table gains is covered without a case being written.
	tableRuntime := map[string]string{}
	now := time.Now()
	for _, r := range worker.Runtimes() {
		if !r.HasImage() || r.EndOfLife(now) {
			continue
		}
		add := func(name string, manager DependencyManager, dir string, files []string, g func() *findingGroup, pkg string, mutate func(map[string]string)) {
			c := cases[0]
			c.name, c.manager, c.dir, c.files, c.group, c.pkg, c.mutate = name, manager, dir, files, g, pkg, mutate
			c.wantNote, c.wantEdit, c.wantTool, c.wantSource = "", "", "", ""
			cases = append(cases, c)
			tableRuntime[name] = r.ID
		}
		switch r.Kind {
		case worker.KindNode:
			nvmrc := func(f map[string]string) { f[".nvmrc"] = r.Series + "\n" }
			add("table_npm_"+r.ID, ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist", nvmrc)
			add("table_pnpm_"+r.ID, ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist", nvmrc)
		case worker.KindPython:
			add("table_uv_"+r.ID, ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
				withFile(".python-version", r.Series+"\n", nil))
		}
	}
	// ran holds the runtimes a case ran in and passed.
	ran := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := readTestdata(t, c.dir, c.files...)
			if c.mutate != nil {
				c.mutate(files)
			}
			it := itemFor(t, c.manager, files, c.group())
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("the fixture is not an update candidate: %s %s", it.Category, it.Detail)
			}
			plan := &Plan{LanguageItems: []LanguageItem{it}}
			up, err := NewLangUpdater(e.config(LangUpdateConfig{
				GitHub: ghFor(files), Images: map[string]ImageEnv{"img": env},
				MaxJobs: 4, JobIDPrefix: "it",
			}))
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			use := up.Run(ctx, plan)
			got := plan.LanguageItems[0]
			t.Logf("%s: category=%s reason=%s detail=%q jobs=%d took=%s", c.name, got.Category, got.Reason, got.Detail, use.Jobs, time.Since(start).Round(time.Millisecond))
			if got.Update != nil {
				t.Logf("steps=%+v notes=%v diff=%+v", got.Update.Steps, got.Update.Notes, got.Update.Diff)
			}
			if got.Category != CategoryPRCandidate {
				for _, p := range got.Packages {
					t.Logf("package %s: %s %s %s", p.Name, p.Action, p.Reason, p.Detail)
				}
				t.Fatalf("category = %s (%s), want pr_candidate", got.Category, got.Reason)
			}
			if !got.UpdateExecuted || !got.PostUpdateCheckExecuted {
				t.Errorf("executed flags = %v %v", got.UpdateExecuted, got.PostUpdateCheckExecuted)
			}
			// What the update ran in and with is on record.
			wantRuntime := map[DependencyManager]string{ManagerNpm: defaultNodeRuntime(time.Now()), ManagerPnpm: defaultNodeRuntime(time.Now()), ManagerUv: "python3.13", ManagerPip: "python3.13"}[c.manager]
			if c.manager == ManagerUv {
				wantRuntime = "python3.11"
			}
			if id, ok := tableRuntime[c.name]; ok {
				wantRuntime = id
			}
			for _, series := range []string{"22", "24", "26"} {
				if strings.Contains(c.name, "node"+series) {
					wantRuntime = "node" + series
				}
			}
			for _, minor := range []string{"12", "13", "14", "15"} {
				if strings.Contains(c.name, "python3"+minor) {
					wantRuntime = "python3." + minor
				}
			}
			if rt := got.Update.Runtime; rt == nil || rt.ID != wantRuntime || rt.Version == "" || rt.Digest == "" {
				t.Errorf("runtime record = %+v, want %s", rt, wantRuntime)
			}
			if tl := got.Update.Tool; c.manager == ManagerPip && tl != nil {
				t.Errorf("pip has a tool record: %+v", tl)
			} else if c.manager != ManagerPip {
				wantTool, wantSource := c.wantTool, c.wantSource
				if wantTool == "" {
					wantTool, wantSource = itDefaultToolVersions[c.manager], "default"
				}
				if tl == nil || tl.Version != wantTool || tl.Source != wantSource || tl.SHA256 == "" {
					t.Errorf("tool record = %+v, want %s (%s)", tl, wantTool, wantSource)
				}
			}
			if c.wantEdit != "" {
				edits := got.Update.ManifestEdits
				if len(edits) != 1 || edits[0].From+">"+edits[0].To != c.wantEdit {
					t.Errorf("manifest edits = %+v, want %s", edits, c.wantEdit)
				}
				t.Logf("edit %+v", edits[0])
			}
			if c.wantNote != "" {
				found := false
				for _, n := range got.Update.Notes {
					found = found || strings.Contains(n, c.wantNote)
				}
				if !found {
					t.Errorf("notes %v lack %q", got.Update.Notes, c.wantNote)
				}
			}
			p := got.Packages[0]
			t.Logf("%s %s -> adopted %s (lower bound %s)", p.Name, p.Installed, p.AdoptedVersion, p.SelectionLowerBound)
			if got.SourceCheck == nil || !got.SourceCheck.Passed {
				t.Fatalf("source check = %+v", got.SourceCheck)
			}
			sc := got.SourceCheck
			t.Logf("fs check: before=%v after=%v resolved=%v remaining=%v introduced=%v", sc.Before, sc.After, sc.Resolved, sc.Remaining, sc.Introduced)
			wantArtifacts := 1
			if c.wantEdit != "" {
				wantArtifacts = 2
			}
			if len(got.Artifacts) != wantArtifacts || len(got.Artifacts[0].Content) == 0 {
				t.Fatalf("artifacts = %+v", got.Artifacts)
			}
			for _, cv := range p.CVEs {
				found := false
				for _, r := range sc.Resolved {
					found = found || r.VulnID == cv.VulnID
				}
				if !found {
					t.Errorf("%s is not among the resolved findings", cv.VulnID)
				}
			}
			if !t.Failed() {
				ran[got.Update.Runtime.ID] = true
			}
		})
	}
	// Every runtime of the table that is in support and has an image has to
	// have run and passed here; one that did not fails the test (and so the
	// table update), whatever the reason.
	for _, r := range worker.Runtimes() {
		if r.HasImage() && !r.EndOfLife(now) && !ran[r.ID] {
			t.Errorf("the runtime %s is in the table and in support, and no case ran in it and passed", r.ID)
		}
	}
	// The table update records the runtimes that were run and passed, and no
	// others, as tested.
	if path := os.Getenv("KESTRELYNX_IT_TESTED_RUNTIMES"); path != "" && !t.Failed() {
		var ids []string
		for id := range ran {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if err := os.WriteFile(path, []byte(strings.Join(ids, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIntegrationLangUpdateRealisticProjects runs the update stage over
// lockfiles of mid-size projects (express and axios, vite, fastapi and httpx,
// requests with hashes), each built with the same tools and an old
// release date so that the transitive packages are old, and checks that
// output that is honest is accepted. The projects are not part of the
// repository: KESTRELYNX_REALISTIC_DIR names a directory with the
// subdirectories npm, pnpm, uv and pip, each holding the project's files.
// KESTRELYNX_WORKER_IT and the settings of TestIntegrationLangUpdate apply.
func TestIntegrationLangUpdateRealisticProjects(t *testing.T) {
	dir := os.Getenv("KESTRELYNX_REALISTIC_DIR")
	if dir == "" {
		t.Skip("set KESTRELYNX_REALISTIC_DIR to run this test")
	}
	e := itSetup(t)
	ctx, env := e.ctx, e.image
	node := func(name, ver string, cves ...CVERef) func() *findingGroup {
		o := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/" + name + "/package.json"}
		return func() *findingGroup { return group(typeNodePkg, name, ver, o, cves...) }
	}
	py := func(name, ver string, cves ...CVERef) func() *findingGroup {
		o := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "usr/local/lib/python3.12/site-packages/" + name + "-" + ver + ".dist-info/METADATA", Target: "Python"}
		return func() *findingGroup { return group(typePythonPkg, name, ver, o, cves...) }
	}
	cases := []struct {
		name    string
		manager DependencyManager
		dir     string
		files   []string
		group   func() *findingGroup
		// wantFailure is the reason an update the tool itself cannot do ends
		// with (the project pins a package that holds the target back); empty
		// means pr_candidate is required.
		wantFailure Reason
	}{
		{"npm_follow_redirects_under_axios_and_express", ManagerNpm, "npm", []string{"package.json", "package-lock.json"},
			node("follow-redirects", "1.13.0", CVERef{VulnID: "CVE-2022-0155", FixedVers: []string{"1.14.7"}}), ""},
		{"npm_proxy_addr_under_express", ManagerNpm, "npm", []string{"package.json", "package-lock.json"},
			node("proxy-addr", "2.0.6", CVERef{VulnID: "CVE-2026-90711", FixedVers: []string{"2.0.8"}}), ""},
		{"pnpm_nanoid_under_vite", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"},
			node("nanoid", "3.3.6", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18"}}), ""},
		{"pnpm_rollup_under_vite", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"},
			node("rollup", "3.29.3", CVERef{VulnID: "CVE-2024-47068", FixedVers: []string{"3.29.5"}}), ""},
		{"pnpm_frontend_nanoid_with_supported_architectures", ManagerPnpm, "pnpm_frontend", []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
			node("nanoid", "3.3.7", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18"}}), ""},
		{"pnpm_frontend_sharp_direct_pinned", ManagerPnpm, "pnpm_frontend", []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
			node("sharp", "0.33.0", CVERef{VulnID: "GHSA-wq5f-xc86-pv6w", FixedVers: []string{"0.35.5"}}), ""},
		{"pnpm_backend_allow_builds", ManagerPnpm, "pnpm_backend", []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
			node("nanoid", "3.3.6", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18"}}), ""},
		{"uv_certifi_under_httpx", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"},
			py("certifi", "2022.12.7", CVERef{VulnID: "CVE-2023-37920", FixedVers: []string{"2023.7.22"}}), ""},
		{"uv_anyio_under_httpx_and_starlette", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"},
			py("anyio", "3.6.2", CVERef{VulnID: "CVE-2026-63374", FixedVers: []string{"4.14.2"}}), ReasonUpdateStepFailed},
		{"pip_urllib3_under_requests", ManagerPip, "pip", []string{"requirements.txt"},
			py("urllib3", "1.26.9", CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17"}}), ""},
		{"pip_certifi_under_requests", ManagerPip, "pip", []string{"requirements.txt"},
			py("certifi", "2022.5.18.1", CVERef{VulnID: "CVE-2023-37920", FixedVers: []string{"2023.7.22"}}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			for _, f := range c.files {
				b, err := os.ReadFile(filepath.Join(dir, c.dir, f))
				if err != nil {
					t.Fatal(err)
				}
				files[f] = string(b)
			}
			it := itemFor(t, c.manager, files, c.group())
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("the project is not an update candidate: %s %s %s", it.Category, it.Reason, it.Detail)
			}
			plan := &Plan{LanguageItems: []LanguageItem{it}}
			up, err := NewLangUpdater(e.config(LangUpdateConfig{
				GitHub: ghFor(files), Images: map[string]ImageEnv{"img": env},
				MaxJobs: 4, JobIDPrefix: "it",
			}))
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			use := up.Run(ctx, plan)
			got := plan.LanguageItems[0]
			t.Logf("%s: category=%s reason=%s detail=%q jobs=%d took=%s", c.name, got.Category, got.Reason, got.Detail, use.Jobs, time.Since(start).Round(time.Millisecond))
			if got.Update != nil {
				t.Logf("notes=%v diff=%+v", got.Update.Notes, got.Update.Diff)
			}
			for _, p := range got.Packages {
				t.Logf("package %s %s: %s %s %s adopted=%s", p.Name, p.Installed, p.Action, p.Reason, p.Detail, p.AdoptedVersion)
			}
			if c.wantFailure != "" {
				if got.Reason != c.wantFailure {
					t.Fatalf("reason = %s, want %s", got.Reason, c.wantFailure)
				}
				return
			}
			if got.Category != CategoryPRCandidate {
				t.Fatalf("category = %s (%s: %s), want pr_candidate", got.Category, got.Reason, got.Detail)
			}
		})
	}
}
