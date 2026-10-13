package remediation

import (
	"encoding/json"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func defaultTool(m DependencyManager) string {
	return toolfetch.DefaultVersion(toolfetch.Manager(m), "node24")
}

// plannedItem plans one unit made of the manifest and lockfile of the manager
// plus the extra files, which are given by their path under the repository.
func plannedItem(t *testing.T, dir string, files map[string]string) LanguageItem {
	t.Helper()
	gh := newFakeGitHub()
	for p, c := range files {
		d, name := ".", p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			d, name = p[:i], p[i+1:]
		}
		gh.put("ex/app", d, name, c)
	}
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", dir)}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	if _, ok := files[pathIn(dir, "uv.lock")]; ok {
		in = langInput("shop", "api", pyFinding("CVE-1", "certifi", "2024.2.2", "2024.7.4"))
	}
	return langPlan(t, gh, deps, nil, in).LanguageItems[0]
}

func nodeFiles(manager, dir string, extra map[string]string) map[string]string {
	files := map[string]string{}
	switch manager {
	case "npm":
		files[pathIn(dir, "package.json")] = npmManifest
		files[pathIn(dir, "package-lock.json")] = npmLockV3
	case "pnpm":
		files[pathIn(dir, "package.json")] = pnpmManifest
		files[pathIn(dir, "pnpm-lock.yaml")] = pnpmLock
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func withField(manifest, field string) string {
	return strings.Replace(manifest, `{"name":`, `{`+field+`,"name":`, 1)
}

func TestToolSpec_NodeDeclarationsBeforeAnyRun(t *testing.T) {
	pm := defaultTool(ManagerPnpm)
	nm := defaultTool(ManagerNpm)
	cases := []struct {
		name     string
		manager  string
		manifest string // replaces the default manifest when set
		extra    map[string]string
		reason   Reason // "" for a unit that is planned as usual
	}{
		{"nothing declared", "npm", "", nil, ""},
		{".nvmrc 24", "npm", "", map[string]string{".nvmrc": "24\n"}, ""},
		{".nvmrc v24.15.0 differs in the patch only", "npm", "", map[string]string{".nvmrc": "v24.15.0\n"}, ""},
		{".nvmrc lts/krypton", "npm", "", map[string]string{".nvmrc": "lts/krypton\n"}, ""},
		{".node-version 26", "npm", "", map[string]string{".node-version": "26\n"}, ""},
		{".nvmrc 26 for pnpm", "pnpm", "", map[string]string{".nvmrc": "v26.11.1\n"}, ""},
		{"engines.node >=26", "npm", withField(npmManifest, `"engines":{"node":">=26"}`), nil, ""},
		{".node-version 24.21.0", "pnpm", "", map[string]string{".node-version": "24.21.0\n"}, ""},
		{"engines.node >=24", "npm", withField(npmManifest, `"engines":{"node":">=24"}`), nil, ""},
		{"devEngines.runtime range", "npm", withField(npmManifest, `"devEngines":{"runtime":{"name":"node","version":">=22"}}`), nil, ""},

		{".nvmrc 20", "npm", "", map[string]string{".nvmrc": "20\n"}, ReasonRuntimeEndOfLife},
		{".nvmrc lts/iron", "npm", "", map[string]string{".nvmrc": "lts/iron\n"}, ReasonRuntimeEndOfLife},
		{".nvmrc node", "npm", "", map[string]string{".nvmrc": "node\n"}, ReasonNodeSpecUnsupported},
		{".nvmrc latest", "npm", "", map[string]string{".nvmrc": "latest\n"}, ReasonNodeSpecUnsupported},
		{".node-version of a series not in the table yet", "npm", "", map[string]string{".node-version": nextNodeSeries() + "\n"}, ReasonNodeSpecUnsupported},
		{".nvmrc 25 is not in the table", "npm", "", map[string]string{".nvmrc": "25\n"}, ReasonNodeSpecUnsupported},
		{"engines.node above the table", "npm", withField(npmManifest, `"engines":{"node":">=`+nextNodeSeries()+`"}`), nil, ReasonNodeSpecUnsupported},
		{"engines.node <20.12", "npm", withField(npmManifest, `"engines":{"node":"<20.12"}`), nil, ReasonRuntimeEndOfLife},
		{"engines.node 18 and below", "npm", withField(npmManifest, `"engines":{"node":"<=18"}`), nil, ReasonNodeSpecUnsupported},
		{"devEngines.runtime 20", "npm", withField(npmManifest, `"devEngines":{"runtime":{"name":"node","version":"20.x"}}`), nil, ReasonRuntimeEndOfLife},
		{"engines.runtime 22", "npm", withField(npmManifest, `"engines":{"runtime":{"name":"node","version":"^22"}}`), nil, ""},
		{".nvmrc 22 for pnpm", "pnpm", "", map[string]string{".nvmrc": "22\n"}, ""},
		{"engines.node >=20 with engines.pnpm >=11", "pnpm", withField(pnpmManifest, `"engines":{"node":">=20","pnpm":">=11"}`), nil, ""},
		{".nvmrc 20 with npm 12 is a runtime past its support", "npm", withField(npmManifest, `"packageManager":"npm@12.2.0"`), map[string]string{".nvmrc": "20\n"}, ReasonRuntimeEndOfLife},
		{".nvmrc 18", "pnpm", "", map[string]string{".nvmrc": "18\n"}, ReasonNodeSpecUnsupported},
		{"engines.node of odd series only", "npm", withField(npmManifest, `"engines":{"node":"^23"}`), nil, ReasonNodeSpecUnsupported},
		{"engines.node ^20 || ^22", "pnpm", withField(pnpmManifest, `"engines":{"node":"^20 || ^22"}`), nil, ""},
		{"devEngines.runtime for bun", "npm", withField(npmManifest, `"devEngines":{"runtime":{"name":"bun","version":"1"}}`), nil, ReasonNodeSpecUnsupported},
		{".node-version 20.11.1 with engines <20.12 agree, and name a runtime past its support", "npm", withField(npmManifest, `"engines":{"node":"<20.12"}`), map[string]string{".node-version": "20.11.1\n"}, ReasonRuntimeEndOfLife},

		{".node-version and .nvmrc disagree on the patch", "npm", "", map[string]string{".node-version": "20.11.1\n", ".nvmrc": "20.11.0\n"}, ReasonNodeSpecConflict},
		{".nvmrc 22 against engines.node >=24", "npm", withField(npmManifest, `"engines":{"node":">=24"}`), map[string]string{".nvmrc": "22\n"}, ReasonNodeSpecConflict},
		{".nvmrc 24.15.0 against engines.node >=24.20", "pnpm", withField(pnpmManifest, `"engines":{"node":">=24.20"}`), map[string]string{".nvmrc": "24.15.0\n"}, ReasonNodeSpecConflict},
		{"two ranges that share nothing", "npm", withField(npmManifest, `"engines":{"node":">=24"},"devEngines":{"runtime":{"name":"node","version":"<22"}}`), nil, ReasonNodeSpecConflict},

		{".nvmrc is not a version", "npm", "", map[string]string{".nvmrc": "twenty\n"}, ReasonNodeSpecInvalid},
		{".node-version 24.x", "npm", "", map[string]string{".node-version": "24.x\n"}, ReasonNodeSpecInvalid},
		{".nvmrc is empty", "npm", "", map[string]string{".nvmrc": "\n\n"}, ReasonNodeSpecInvalid},
		{".nvmrc lts/unknown", "npm", "", map[string]string{".nvmrc": "lts/nowhere\n"}, ReasonNodeSpecInvalid},
		{"engines.node is a tag", "npm", withField(npmManifest, `"engines":{"node":"latest"}`), nil, ReasonNodeSpecInvalid},
		{"engines.node is a number", "npm", withField(npmManifest, `"engines":{"node":24}`), nil, ReasonNodeSpecInvalid},
		{"engines.node has a pre-release bound", "npm", withField(npmManifest, `"engines":{"node":">=24.0.0-rc.1"}`), nil, ReasonNodeSpecInvalid},
		{"two node runtimes", "npm", withField(npmManifest, `"devEngines":{"runtime":[{"name":"node","version":">=22"},{"name":"node","version":">=24"}]}`), nil, ReasonNodeSpecInvalid},
		{"runtime without a name", "npm", withField(npmManifest, `"devEngines":{"runtime":{"version":">=22"}}`), nil, ReasonNodeSpecInvalid},

		{"runtime onFail download", "npm", withField(npmManifest, `"devEngines":{"runtime":{"name":"node","version":">=24","onFail":"download"}}`), nil, ReasonToolFetchConfigUnsupported},
		{"engines.runtime onFail download", "pnpm", withField(pnpmManifest, `"engines":{"runtime":{"name":"node","version":">=24","onFail":"download"}}`), nil, ReasonToolFetchConfigUnsupported},
		{"runtime onFail error is fine", "npm", withField(npmManifest, `"devEngines":{"runtime":{"name":"node","version":">=24","onFail":"error"}}`), nil, ""},

		{"pnpm.configDependencies", "pnpm", withField(pnpmManifest, `"pnpm":{"configDependencies":{"x":"1.0.0"}}`), nil, ReasonToolFetchConfigUnsupported},
		{"pnpm.executionEnv", "pnpm", withField(pnpmManifest, `"pnpm":{"executionEnv":{"nodeVersion":"20"}}`), nil, ReasonToolFetchConfigUnsupported},
		{"pnpm.overrides", "pnpm", withField(pnpmManifest, `"pnpm":{"overrides":{"a":"1"}}`), nil, ReasonToolFetchConfigUnsupported},
		{"pnpm field is not an object", "pnpm", withField(pnpmManifest, `"pnpm":"x"`), nil, ReasonToolFetchConfigUnsupported},
		{"pnpm.onlyBuiltDependencies is allowed", "pnpm", withField(pnpmManifest, `"pnpm":{"onlyBuiltDependencies":["esbuild"]}`), nil, ""},
		{"resolutions", "pnpm", withField(pnpmManifest, `"resolutions":{"lodash":"4.17.21"}`), nil, ReasonToolFetchConfigUnsupported},
		{"resolutions mean nothing to npm", "npm", withField(npmManifest, `"resolutions":{"lodash":"4.17.21"}`), nil, ""},
		{"pnpm-workspace.yaml configDependencies", "pnpm", "", map[string]string{"pnpm-workspace.yaml": "configDependencies:\n  x: 1.0.0\n"}, ReasonWorkspaceSettingsUnsupported},

		{"packageManager is the default pnpm", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@`+pm+`"`), nil, ""},
		{"packageManager is the default npm", "npm", withField(npmManifest, `"packageManager":"npm@`+nm+`"`), nil, ""},
		{"packageManager pnpm@10.34.4", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@10.34.4"`), nil, ""},
		{"packageManager npm@10.9.9", "npm", withField(npmManifest, `"packageManager":"npm@10.9.9"`), nil, ""},
		{"packageManager pnpm@9.15.9", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@9.15.9"`), nil, ""},
		{"packageManager pnpm@12.11.2", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@12.11.2"`), nil, ""},
		{"packageManager npm@9.9.4", "npm", withField(npmManifest, `"packageManager":"npm@9.9.4"`), nil, ""},
		{"packageManager npm@12.2.0", "npm", withField(npmManifest, `"packageManager":"npm@12.2.0"`), nil, ""},
		{"packageManager pnpm older than 9", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@8.15.9"`), nil, ReasonManagerSpecUnsupported},
		{"packageManager pnpm newer than 12", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@13.0.0"`), nil, ReasonManagerSpecUnsupported},
		{"packageManager npm older than 9", "npm", withField(npmManifest, `"packageManager":"npm@8.19.4"`), nil, ReasonManagerSpecUnsupported},
		{"packageManager npm newer than 12", "npm", withField(npmManifest, `"packageManager":"npm@13.0.0"`), nil, ReasonManagerSpecUnsupported},
		{"packageManager with a v prefix", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@v10.34.4"`), nil, ReasonManagerSpecInvalid},
		{"engines.pnpm names the release", "pnpm", withField(pnpmManifest, `"engines":{"pnpm":"10.34.4"}`), nil, ""},
		{"devEngines.packageManager names the release", "pnpm", withField(pnpmManifest, `"devEngines":{"packageManager":{"name":"pnpm","version":"10.34.4","onFail":"error"}}`), nil, ""},
		{"devEngines.packageManager with a range around the release", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@10.34.4","devEngines":{"packageManager":{"name":"pnpm","version":"^10"}}`), nil, ""},
		{"devEngines.packageManager range excludes the packageManager release", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@10.34.4","devEngines":{"packageManager":{"name":"pnpm","version":"^11"}}`), nil, ReasonManagerSpecConflict},
		{"packageManager pre-release", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@12.0.0-rc.1"`), nil, ReasonManagerSpecUnsupported},
		{"packageManager names another manager", "npm", withField(npmManifest, `"packageManager":"pnpm@`+pm+`"`), nil, ReasonManagerSpecConflict},
		{"packageManager yarn for pnpm", "pnpm", withField(pnpmManifest, `"packageManager":"yarn@4.0.0"`), nil, ReasonManagerSpecConflict},
		{"packageManager is a range", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@^11"`), nil, ReasonManagerSpecInvalid},
		{"packageManager has no version", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm"`), nil, ReasonManagerSpecInvalid},
		{"packageManager hash is short", "pnpm", withField(pnpmManifest, `"packageManager":"pnpm@`+pm+`+sha512.abcd"`), nil, ReasonManagerSpecInvalid},
		{"packageManager is not a string", "pnpm", withField(pnpmManifest, `"packageManager":11`), nil, ReasonManagerSpecInvalid},
		{"engines.pnpm allows the default", "pnpm", withField(pnpmManifest, `"engines":{"pnpm":">=11"}`), nil, ""},
		{"engines.pnpm <11", "pnpm", withField(pnpmManifest, `"engines":{"pnpm":"<11"}`), nil, ReasonManagerSpecUnsupported},
		{"engines.pnpm and packageManager disagree", "pnpm", withField(pnpmManifest, `"engines":{"pnpm":"10.34.4"},"packageManager":"pnpm@`+pm+`"`), nil, ReasonManagerSpecConflict},
		{"engines.npm is not a string", "npm", withField(npmManifest, `"engines":{"npm":11}`), nil, ReasonManagerSpecInvalid},
		{"devEngines.packageManager is the default", "pnpm", withField(pnpmManifest, `"devEngines":{"packageManager":{"name":"pnpm","version":">=11","onFail":"error"}}`), nil, ""},
		{"devEngines.packageManager 10", "pnpm", withField(pnpmManifest, `"devEngines":{"packageManager":{"name":"pnpm","version":"^10"}}`), nil, ReasonManagerSpecUnsupported},
		{"devEngines.packageManager names npm for pnpm", "pnpm", withField(pnpmManifest, `"devEngines":{"packageManager":{"name":"npm","version":"11"}}`), nil, ReasonManagerSpecConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := nodeFiles(c.manager, "web", c.extra)
			// The files of the extra map are in the project's directory.
			for k, v := range c.extra {
				delete(files, k)
				files[pathIn("web", k)] = v
			}
			if c.manifest != "" {
				files["web/package.json"] = c.manifest
			}
			it := plannedItem(t, "web", files)
			if c.reason == "" {
				if it.Category != CategoryDependencyUpdateCandidate {
					t.Fatalf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
				}
				return
			}
			if it.Category != CategoryManual || it.Reason != c.reason {
				t.Fatalf("item = %s / %s (%s), want manual / %s", it.Category, it.Reason, it.Detail, c.reason)
			}
			if len(it.Packages) == 0 {
				t.Error("a manual unit keeps its packages listed")
			}
			if (c.reason == ReasonRuntimeEndOfLife) != (it.RuntimeEOL != nil) {
				t.Errorf("RuntimeEOL = %+v for the reason %s", it.RuntimeEOL, it.Reason)
			}
			for _, p := range it.Packages {
				if p.Action != ActionManual || p.Reason != c.reason {
					t.Errorf("package = %+v", p)
				}
			}
		})
	}
}

func TestToolSpec_ReadFilesAreInputs(t *testing.T) {
	base := nodeFiles("npm", "web", nil)
	with := func(content string) LanguageItem {
		files := map[string]string{}
		for k, v := range base {
			files[k] = v
		}
		files["web/.nvmrc"] = content
		return plannedItem(t, "web", files)
	}
	a, b := with("24\n"), with("24.15\n")
	if a.Category != CategoryDependencyUpdateCandidate || b.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("items = %s, %s", a.Category, b.Category)
	}
	found := false
	for _, f := range a.Source.Files {
		if f.Path == "web/.nvmrc" && f.BlobSHA != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("the .nvmrc that was read is not recorded: %+v", a.Source.Files)
	}
	for _, p := range a.Source.Absent {
		if strings.HasSuffix(p, ".nvmrc") {
			t.Errorf("the .nvmrc that exists is recorded as absent: %v", a.Source.Absent)
		}
	}
	if !containsString(a.Source.Absent, "web/.node-version") {
		t.Errorf("the absent .node-version is not recorded: %v", a.Source.Absent)
	}
	if LanguageInputFingerprint(a) == LanguageInputFingerprint(b) {
		t.Error("the fingerprint does not depend on the .nvmrc")
	}
	none := plannedItem(t, "web", base)
	if LanguageInputFingerprint(none) == LanguageInputFingerprint(a) {
		t.Error("the fingerprint does not tell a project without .nvmrc from one with it")
	}
}

func uvFiles(dir string, pyproject string, extra map[string]string) map[string]string {
	files := map[string]string{pathIn(dir, "pyproject.toml"): pyproject, pathIn(dir, "uv.lock"): uvLock}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func TestToolSpec_PythonAndUvDeclarationsBeforeAnyRun(t *testing.T) {
	req := func(spec string) string {
		return strings.Replace(uvPyproject, `requires-python = ">=3.12"`, `requires-python = "`+spec+`"`, 1)
	}
	toolSection := func(body string) string { return uvPyproject + "\n[tool.uv]\n" + body + "\n" }
	cases := []struct {
		name      string
		pyproject string
		extra     map[string]string
		reason    Reason
	}{
		{"nothing declared", uvPyproject, nil, ""},
		{".python-version 3.13", uvPyproject, map[string]string{"svc/.python-version": "3.13\n"}, ""},
		{".python-version cpython@3.13.2", uvPyproject, map[string]string{"svc/.python-version": "cpython@3.13.2\n"}, ""},
		{".python-version cpython-3.13", uvPyproject, map[string]string{"svc/.python-version": "cpython-3.13\n"}, ""},
		{"requires-python admits 3.13.16", req(">=3.9,<3.15"), nil, ""},
		{"required-version allows 0.13.0", toolSection(`required-version = ">=0.12.22,<0.14"`), nil, ""},
		{"required-version fixes 0.13.0", toolSection(`required-version = "==0.13.0"`), nil, ""},
		{"allowed [tool.uv] keys", toolSection("dev-dependencies = [\"pytest\"]\npackage = false\n[tool.uv.sources]\nrequests = { url = \"https://example.com/r.whl\" }"), nil, ReasonUnsupportedSource},

		{".python-version 3.9", req(">=3.9"), map[string]string{"svc/.python-version": "3.9\n"}, ReasonRuntimeEndOfLife},
		{"requires-python allows only 3.9 and 3.10", req(">=3.9,<3.11"), nil, ReasonRuntimeEndOfLife},
		{"requires-python allows 3.10 and 3.11", req(">=3.10,<3.12"), nil, ""},
		{".python-version 3.12", uvPyproject, map[string]string{"svc/.python-version": "3.12\n"}, ""},
		{".python-version 3.14.0", uvPyproject, map[string]string{"svc/.python-version": "3.14.0\n"}, ""},
		{".python-version 3.12.99 differs from the image in the patch", uvPyproject, map[string]string{"svc/.python-version": "3.12.99\n"}, ""},
		{".python-version 3.15", uvPyproject, map[string]string{"svc/.python-version": "3.15\n"}, ""},
		{".python-version of a series not in the table yet", uvPyproject, map[string]string{"svc/.python-version": nextPythonSeries() + "\n"}, ReasonPythonSpecUnsupported},
		{".python-version 3.8", req(">=3.8"), map[string]string{"svc/.python-version": "3.8\n"}, ReasonPythonSpecUnsupported},
		{"requires-python below 3.9", req("<3.9"), nil, ReasonPythonSpecUnsupported},
		{"requires-python needs a newer patch than the image has", req(">=3.12.99,<3.13"), nil, ReasonPythonSpecUnsupported},
		{".python-version pypy", uvPyproject, map[string]string{"svc/.python-version": "pypy3.10\n"}, ReasonPythonSpecUnsupported},
		{".python-version free-threaded", uvPyproject, map[string]string{"svc/.python-version": "3.13t\n"}, ReasonPythonSpecUnsupported},
		{".python-versions", uvPyproject, map[string]string{"svc/.python-versions": "3.13\n3.12\n"}, ReasonPythonSpecUnsupported},
		{"requires-python excludes 3.13", req(">=3.9,<3.13"), nil, ""},
		{"requires-python from 3.14", req(">=3.14"), nil, ""},
		{"requires-python from 3.15", req(">=3.15"), nil, ""},
		{"requires-python above the table", req(">=" + nextPythonSeries()), nil, ReasonPythonSpecUnsupported},
		{"required-version fixes 0.12.30", toolSection(`required-version = "==0.12.30"`), nil, ""},
		{"required-version fixes 0.12.21", toolSection(`required-version = "==0.12.21"`), nil, ReasonManagerSpecUnsupported},
		{"required-version fixes the default", toolSection(`required-version = "==0.13.0"`), nil, ""},
		{"required-version below 0.13", toolSection(`required-version = "<0.13"`), nil, ReasonManagerSpecUnsupported},

		{".python-version 3.12.3 against requires-python >=3.12.5", req(">=3.12.5"), map[string]string{"svc/.python-version": "3.12.3\n"}, ReasonPythonSpecConflict},
		{".python-version 3.11 against requires-python >=3.12", uvPyproject, map[string]string{"svc/.python-version": "3.11\n"}, ReasonPythonSpecConflict},

		{".python-version is not a version", uvPyproject, map[string]string{"svc/.python-version": "snake\n"}, ReasonPythonSpecInvalid},
		{".python-version is empty", uvPyproject, map[string]string{"svc/.python-version": "\n"}, ReasonPythonSpecInvalid},
		{"requires-python is not a specifier", req("python 3"), nil, ReasonPythonSpecInvalid},
		{"required-version is not a specifier", toolSection(`required-version = "latest"`), nil, ReasonManagerSpecInvalid},
		{"required-version is a number", toolSection(`required-version = 13`), nil, ReasonManagerSpecInvalid},

		{"uv.toml in the project directory", uvPyproject, map[string]string{"svc/uv.toml": "index-url = \"https://example.com\"\n"}, ReasonToolFetchConfigUnsupported},
		{"uv.toml in the parent", uvPyproject, map[string]string{"uv.toml": "python-preference = \"only-managed\"\n"}, ReasonToolFetchConfigUnsupported},
		{"uv.toml at the root of a deeper project", uvPyproject, map[string]string{"a/uv.toml": "x = 1\n"}, ""},
		{"[tool.uv] index", toolSection(`index-url = "https://example.com/simple"`), nil, ReasonToolFetchConfigUnsupported},
		{"[tool.uv] python-preference", toolSection(`python-preference = "only-managed"`), nil, ReasonToolFetchConfigUnsupported},
		{"[tool.uv] override-dependencies", toolSection(`override-dependencies = ["requests>=2"]`), nil, ReasonToolFetchConfigUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			it := plannedItem(t, "svc", uvFiles("svc", c.pyproject, c.extra))
			switch {
			case c.reason == "":
				if it.Category != CategoryDependencyUpdateCandidate {
					t.Fatalf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
				}
			case c.name == "allowed [tool.uv] keys":
				// The keys are read; what is wrong is the source the package comes from.
				if it.Reason == ReasonToolFetchConfigUnsupported {
					t.Fatalf("an allowed key was refused: %s", it.Detail)
				}
			default:
				if it.Category != CategoryManual || it.Reason != c.reason {
					t.Fatalf("item = %s / %s (%s), want manual / %s", it.Category, it.Reason, it.Detail, c.reason)
				}
			}
		})
	}
}

func TestToolSpec_UvLooksForUvTomlUpToTheRoot(t *testing.T) {
	files := uvFiles("a/b/svc", uvPyproject, nil)
	gh := newFakeGitHub()
	for p, c := range files {
		i := strings.LastIndex(p, "/")
		gh.put("ex/app", p[:i], p[i+1:], c)
	}
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "a/b/svc")}
	it := langPlan(t, gh, deps, nil, langInput("shop", "api", pyFinding("CVE-1", "certifi", "2024.2.2", "2024.7.4"))).LanguageItems[0]
	if it.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
	}
	for _, want := range []string{"a/b/svc/uv.toml", "a/b/uv.toml", "a/uv.toml", "uv.toml", "a/b/svc/.python-version", "a/b/svc/.python-versions"} {
		if !containsString(it.Source.Absent, want) {
			t.Errorf("%s is not recorded as absent: %v", want, it.Source.Absent)
		}
	}
	// pip reads none of these.
	gh = newFakeGitHub()
	gh.put("ex/app", "svc", "requirements.txt", "requests==2.31.0\n")
	deps = []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}
	pip := langPlan(t, gh, deps, nil, langInput("shop", "api", pyFinding("CVE-1", "requests", "2.31.0", "2.32.0"))).LanguageItems[0]
	if len(pip.Source.Absent) != 0 {
		t.Errorf("pip absent = %v", pip.Source.Absent)
	}
}

func TestToolSpec_ResolvedChoices(t *testing.T) {
	pm := defaultTool(ManagerPnpm)
	hash := strings.Repeat("ab", 64)
	spec, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(withField(pnpmManifest, `"packageManager":"pnpm@`+pm+`+sha512.`+strings.ToUpper(hash)+`"`))})
	if uerr != nil {
		t.Fatal(uerr)
	}
	if spec.ToolVersion != pm || spec.ToolSource != "declared" || spec.SpecHash != "sha512."+hash || spec.Runtime != "node24" {
		t.Errorf("spec = %+v", spec)
	}
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(npmManifest)})
	if uerr != nil || spec.ToolVersion != defaultTool(ManagerNpm) || spec.ToolSource != "default" || spec.SpecHash != "" {
		t.Errorf("npm: %+v %v", spec, uerr)
	}
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerUv, Manifest: []byte(uvPyproject)})
	if uerr != nil || spec.ToolVersion != "0.13.0" || spec.ToolSource != "default" || spec.Runtime != "python3.12" {
		t.Errorf("uv: %+v %v", spec, uerr)
	}
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerPip})
	if uerr != nil || spec.Runtime != "python3.13" || spec.ToolVersion != "" {
		t.Errorf("pip: %+v %v", spec, uerr)
	}
	// A version other than the default that the project names exactly is the
	// one to run, with the hash it was declared with.
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(withField(pnpmManifest, `"packageManager":"pnpm@10.34.4+sha512.`+hash+`"`))})
	if uerr != nil || spec.ToolVersion != "10.34.4" || spec.ToolSource != "declared" || spec.SpecHash != "sha512."+hash || spec.Runtime != "node24" {
		t.Errorf("pnpm 10 with a hash: %+v %v", spec, uerr)
	}
	// Ranges alone leave the default when it is inside all of them.
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(withField(npmManifest, `"engines":{"npm":">=10"},"devEngines":{"packageManager":{"name":"npm","version":"^11"}}`))})
	if uerr != nil || spec.ToolVersion != defaultTool(ManagerNpm) || spec.ToolSource != "default_in_range" {
		t.Errorf("npm ranges: %+v %v", spec, uerr)
	}
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(withField(npmManifest, `"engines":{"npm":">=10"},"devEngines":{"packageManager":{"name":"npm","version":"10.9.9"}}`))})
	if uerr != nil || spec.ToolVersion != "10.9.9" || spec.ToolSource != "declared" {
		t.Errorf("npm exact beside a range: %+v %v", spec, uerr)
	}
	if _, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(withField(npmManifest, `"engines":{"npm":"<11"}`))}); uerr == nil || uerr.Reason != ReasonManagerSpecUnsupported {
		t.Errorf("npm range without the default: %v", uerr)
	}
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerUv, Manifest: []byte(strings.Replace(uvPyproject, "[project]", "[tool.uv]\nrequired-version = \"==0.12.30\"\n\n[project]", 1))})
	if uerr != nil || spec.ToolVersion != "0.12.30" || spec.ToolSource != "declared" {
		t.Errorf("uv exact: %+v %v", spec, uerr)
	}
	spec, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerUv, Manifest: []byte(strings.Replace(uvPyproject, "[project]", "[tool.uv]\nrequired-version = \">=0.12\"\n\n[project]", 1))})
	if uerr != nil || spec.ToolVersion != "0.13.0" || spec.ToolSource != "default_in_range" {
		t.Errorf("uv range: %+v %v", spec, uerr)
	}
	if _, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(pnpmManifest), Lock: []byte(pnpmLock)}); uerr != nil {
		t.Errorf("the plain lock: %v", uerr)
	}
}

func TestToolSpec_RequestedRuntimes(t *testing.T) {
	node := func(manifest string, files map[string]string) ([]string, *UnsupportedError) {
		return RequestedRuntimes(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(manifest), Files: fileBytes(files)})
	}
	cases := []struct {
		name     string
		manifest string
		files    map[string]string
		want     []string
		reason   Reason
	}{
		{".nvmrc 20", npmManifest, map[string]string{".nvmrc": "20"}, []string{"node20"}, ""},
		{".nvmrc lts/jod", npmManifest, map[string]string{".nvmrc": "lts/jod"}, []string{"node22"}, ""},
		{"engines.node <20.12", withField(npmManifest, `"engines":{"node":"<20.12"}`), nil, []string{"node20"}, ""},
		{"engines.node >=20", withField(npmManifest, `"engines":{"node":">=20"}`), nil, tableNodeIDs(), ""},
		{"engines.node ^20 || ^24 with .node-version 24.1", withField(npmManifest, `"engines":{"node":"^20 || ^24"}`), map[string]string{".node-version": "24.1"}, []string{"node24"}, ""},
		{"no declaration names every series", npmManifest, nil, tableNodeIDs(), ""},
		{"engines.node 18", withField(npmManifest, `"engines":{"node":"<19"}`), nil, nil, ""},
		{"conflict", npmManifest, map[string]string{".node-version": "20.11.1", ".nvmrc": "20.11.0"}, nil, ReasonNodeSpecConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, uerr := node(c.manifest, c.files)
			if c.reason != "" {
				if uerr == nil || uerr.Reason != c.reason {
					t.Fatalf("error = %v", uerr)
				}
				return
			}
			if uerr != nil || !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v (%v), want %v", got, uerr, c.want)
			}
		})
	}
	py := func(pyproject string, files map[string]string) ([]string, *UnsupportedError) {
		return RequestedRuntimes(ToolSpecInput{Manager: ManagerUv, Manifest: []byte(pyproject), Files: fileBytes(files)})
	}
	got, uerr := py(uvPyproject, map[string]string{".python-version": "3.12"})
	if uerr != nil || !reflect.DeepEqual(got, []string{"python3.12"}) {
		t.Errorf(".python-version 3.12: %v %v", got, uerr)
	}
	got, uerr = py(strings.Replace(uvPyproject, ">=3.12", ">=3.12,<3.14", 1), nil)
	if uerr != nil || !reflect.DeepEqual(got, []string{"python3.12", "python3.13"}) {
		t.Errorf("requires-python >=3.12,<3.14: %v %v", got, uerr)
	}
	got, uerr = py(strings.Replace(uvPyproject, ">=3.12", ">=3.9", 1), map[string]string{".python-version": "3.9.18"})
	if uerr != nil || !reflect.DeepEqual(got, []string{"python3.9"}) {
		t.Errorf(".python-version 3.9.18: %v %v", got, uerr)
	}
	if _, uerr = py(strings.Replace(uvPyproject, ">=3.12", ">=3.12.5", 1), map[string]string{".python-version": "3.12.3"}); uerr == nil || uerr.Reason != ReasonPythonSpecConflict {
		t.Errorf("conflict: %v", uerr)
	}
	if got, uerr = RequestedRuntimes(ToolSpecInput{Manager: ManagerPip}); got != nil || uerr != nil {
		t.Errorf("pip: %v %v", got, uerr)
	}
}

func fileBytes(files map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range files {
		out[k] = []byte(v)
	}
	return out
}

func TestToolSpec_PlannedEndOfLifeCarriesTheRuntime(t *testing.T) {
	it := plannedItem(t, "web", nodeFiles("npm", "web", map[string]string{"web/.nvmrc": "20\n"}))
	if it.Category != CategoryManual || it.Reason != ReasonRuntimeEndOfLife {
		t.Fatalf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
	}
	if want := (RuntimeEOLInfo{ID: "node20", Name: "Node.js 20", EOL: "2026-04-30"}); it.RuntimeEOL == nil || *it.RuntimeEOL != want {
		t.Fatalf("RuntimeEOL = %+v", it.RuntimeEOL)
	}
	spec, _ := worker.LookupRuntime("node20")
	if it.Detail != RuntimeEndOfLifeText(spec) {
		t.Errorf("detail = %q", it.Detail)
	}
	raw, err := json.Marshal(it)
	if err != nil || !strings.Contains(string(raw), `"runtime_eol":{"id":"node20","name":"Node.js 20","eol":"2026-04-30"}`) {
		t.Errorf("json = %s %v", raw, err)
	}
}

func TestToolSpec_HugeRangesAreRefusedQuickly(t *testing.T) {
	huge := strings.TrimSuffix(strings.Repeat("* || ", 13000), " || ")
	if len(huge) < 60000 {
		t.Fatalf("input is %d bytes", len(huge))
	}
	manifest := withField(npmManifest, `"engines":{"node":"`+huge+`"},"devEngines":{"runtime":{"name":"node","version":"`+huge+`"}}`)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(manifest)})
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if uerr == nil || uerr.Reason != ReasonNodeSpecInvalid {
		t.Fatalf("error = %v", uerr)
	}
	if elapsed > 2*time.Second || after.TotalAlloc-before.TotalAlloc > 64<<20 {
		t.Errorf("took %s and %d bytes", elapsed, after.TotalAlloc-before.TotalAlloc)
	}
	// The same through the planner.
	files := nodeFiles("npm", "web", nil)
	files["web/package.json"] = manifest
	if it := plannedItem(t, "web", files); it.Category != CategoryManual || it.Reason != ReasonNodeSpecInvalid {
		t.Errorf("item = %s / %s", it.Category, it.Reason)
	}
	// Many alternatives that stay within the limits are merged, not multiplied.
	many := strings.TrimSuffix(strings.Repeat("^1 || ^2 || ", 15), " || ")
	start = time.Now()
	for i := 0; i < 50; i++ {
		_, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(withField(npmManifest, `"engines":{"node":"`+many+` || >=24"},"devEngines":{"runtime":{"name":"node","version":"`+many+` || ^24"}}`))})
		if uerr != nil {
			t.Fatal(uerr)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("merging took %s", time.Since(start))
	}
}

func TestToolSpec_VersionSetNormalization(t *testing.T) {
	a, _ := rangeSet("^1 || ^1.5 || >=1.2 <3 || 2.x || >=5")
	if len(a) != 2 {
		t.Fatalf("merged to %d intervals: %+v", len(a), a)
	}
	b, _ := rangeSet("<2.5 || >=2.5")
	if len(b) != 1 || b[0].lo.set || b[0].hi.set {
		t.Fatalf("touching intervals did not merge: %+v", b)
	}
	c, _ := rangeSet("<2.5 || >2.5")
	if len(c) != 2 {
		t.Fatalf("a gap of one version was merged: %+v", c)
	}
	d := a.intersect(b)
	if len(d) != len(a) {
		t.Errorf("intersection with everything changed the set: %+v", d)
	}
	if !a.intersect(pointSet(triple{"4", "0", "0"})).isEmpty() {
		t.Error("4.0.0 is outside the set")
	}
}

func TestToolSpec_LockRuntimeInAnyYAMLSpelling(t *testing.T) {
	cases := map[string]string{
		"quoted key":      "lockfileVersion: '9.0'\npackages:\n  \"node@runtime:24.0.0\":\n    resolution: {type: variations}\n",
		"escaped key":     "lockfileVersion: '9.0'\npackages:\n  \"node\\x40runtime:24.0.0\":\n    resolution: {type: variations}\n",
		"flow dependency": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      node: {specifier: 'runtime:24.0.0', version: 'runtime:24.0.0'}\n",
		"flow version":    "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      node: {specifier: \"^24\", version: \"runtime:24.0.0\"}\n",
		"snapshots":       "lockfileVersion: '9.0'\nsnapshots:\n  'node@runtime:24.0.0': {}\n",
		"deep in a list":  "lockfileVersion: '9.0'\nx:\n  - - 'runtime:1.0.0'\n",
	}
	for name, lock := range cases {
		t.Run(name, func(t *testing.T) {
			_, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(pnpmManifest), Lock: []byte(lock)})
			if uerr == nil || uerr.Reason != ReasonToolFetchConfigUnsupported {
				t.Fatalf("error = %v", uerr)
			}
		})
	}
	// A lockfile that cannot be read is not passed over.
	_, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(pnpmManifest), Lock: []byte("a: [\n")})
	if uerr == nil || uerr.Reason != ReasonUnparsableSource {
		t.Errorf("unreadable lock: %v", uerr)
	}
	// Text that only mentions the word is not a runtime.
	_, uerr = ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(pnpmManifest), Lock: []byte("lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-xx}\n    note: not a runtime\n")})
	if uerr != nil {
		t.Errorf("plain lock: %v", uerr)
	}
}

func TestToolSpec_VersionSetLowestSkipsIntervalsWithoutAnyRelease(t *testing.T) {
	set, ok := rangeSet(">22.0.0 <22.0.1 || >=24")
	if !ok {
		t.Fatal("range not read")
	}
	if low, ok := set.lowest(); !ok || low != (triple{"24", "0", "0"}) {
		t.Errorf("lowest = %v %v", low, ok)
	}
	if set, _ := rangeSet(">22.0.0 <22.0.2"); !set.contains(triple{"22", "0", "1"}) || set.contains(triple{"22", "0", "2"}) {
		t.Errorf("set = %v", set)
	}
	if low, _ := (versionSet{{lo: bound{set: true, v: triple{"1", "2", "3"}, open: true}}}).lowest(); low != (triple{"1", "2", "4"}) {
		t.Errorf("open lower bound: %v", low)
	}
}

func TestToolSpec_LowestIsAlwaysInTheSet(t *testing.T) {
	set, _ := rangeSet("<0.0.0 || >=22")
	if low, ok := set.lowest(); !ok || low != (triple{"22", "0", "0"}) {
		t.Errorf("<0.0.0 || >=22: lowest = %v %v", low, ok)
	}
	if set, _ := rangeSet("<0.0.0"); !set.isEmpty() {
		t.Errorf("<0.0.0 holds %v", set)
	}
	for _, text := range []string{
		">=22", ">22.0.0", "<22", "<=0.0.0", "<0.0.1", ">1.2.3 <1.2.4 || ^24", ">22.0.0 <22.0.1 || >=24", "<0.0.0 || >=22",
		"<0.0.0 || >0.0.0 <0.0.2", "^20 || ^22.5", "~22.1.0 || >24.3.7", "20.x || <0.0.0", ">=1 <1", "",
	} {
		set, ok := rangeSet(text)
		if !ok {
			t.Fatalf("%q not read", text)
		}
		low, has := set.lowest()
		if has != !set.isEmpty() {
			t.Errorf("%q: lowest ok = %v for a set %v", text, has, set)
			continue
		}
		if has && !set.contains(low) {
			t.Errorf("%q: lowest %v is not in the set %v", text, low, set)
		}
	}
}

// tableNodeIDs are the ids of the Node.js rows of the runtime table, lowest
// series first.
func tableNodeIDs() []string {
	var ids []string
	for _, r := range worker.Runtimes() {
		if r.Kind == worker.KindNode {
			ids = append(ids, r.ID)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool { return seriesNumber(ids[i]) < seriesNumber(ids[j]) })
	return ids
}
