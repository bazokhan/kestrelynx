package remediation

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// TestIntegrationNpmChain runs the update stage with the chain update over npm
// projects whose lockfiles hold minimist below the fix because a package
// requires it exactly, in the official image the build pins, with the real npm
// and registry and a real Trivy (see itSetup for the settings). The projects
// declare ranges that stay inside releases that no longer change.
func TestIntegrationNpmChain(t *testing.T) {
	e := itSetup(t)
	minimist := func() *findingGroup {
		return group(typeNodePkg, "minimist", "0.0.8", FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/minimist/package.json"},
			CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
	}
	versions := func(t *testing.T, lock []byte) map[string][]string {
		t.Helper()
		out := map[string][]string{}
		for _, p := range npmPackagesOf(lock) {
			out[p[0]] = append(out[p[0]], p[1])
		}
		for _, v := range out {
			sort.Strings(v)
		}
		return out
	}
	entry := func(t *testing.T, lock []byte, path string) string {
		t.Helper()
		var doc struct {
			Packages map[string]json.RawMessage `json:"packages"`
		}
		if err := json.Unmarshal(lock, &doc); err != nil {
			t.Fatal(err)
		}
		return string(doc.Packages[path])
	}
	run := func(t *testing.T, dir string) (LanguageItem, map[string]string) {
		t.Helper()
		files := readTestdata(t, dir, "package.json", "package-lock.json")
		it := itemFor(t, ManagerNpm, files, minimist())
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("the fixture is not an update candidate: %s %s", it.Category, it.Detail)
		}
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		up, err := NewLangUpdater(e.config(LangUpdateConfig{
			GitHub: ghFor(files), Images: map[string]ImageEnv{"img": e.image}, MaxJobs: 4, JobIDPrefix: "itc",
		}))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		up.Run(e.ctx, plan)
		got := plan.LanguageItems[0]
		t.Logf("%s: category=%s reason=%s detail=%q took=%s", dir, got.Category, got.Reason, got.Detail, time.Since(start).Round(time.Second))
		if got.Update != nil {
			t.Logf("chain=%+v notes=%v", got.Update.Chain, got.Update.Notes)
		}
		return got, files
	}

	t.Run("npm_chain_exact_pin", func(t *testing.T) {
		got, files := run(t, "npm_chain_exact_pin")
		if got.Category != CategoryPRCandidate || got.Reason != ReasonUpdateVerified {
			t.Fatalf("category = %s/%s (%s)", got.Category, got.Reason, got.Detail)
		}
		c := got.Update.Chain
		if c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0].Name != "mkdirp" || c.Tops[0].From != "0.5.1" ||
			len(c.Blocked) != 1 || c.Blocked[0].Package != "minimist" || c.Blocked[0].Parent != "mkdirp" || c.Blocked[0].Range != "0.0.8" || c.Blocked[0].Proof != "exact" {
			t.Fatalf("chain = %+v", c)
		}
		if c.Usage.Containers != 2 {
			t.Errorf("containers = %d: the first update and the chain update", c.Usage.Containers)
		}
		min := packageOf(t, got, "minimist")
		if min.Action != ActionUpdate || min.Reason != ReasonUpdateVerified || strings.Join(min.Through, ",") != "mkdirp" {
			t.Errorf("minimist = %+v", min)
		}
		if cmp, _ := compareVersions(schemeSemver, min.AdoptedVersion, "1.2.6"); cmp < 0 {
			t.Errorf("adopted = %s", min.AdoptedVersion)
		}
		if len(got.Artifacts) != 1 || got.Artifacts[0].Path != "package-lock.json" {
			t.Fatalf("artifacts = %+v: the manifest is not changed", got.Artifacts)
		}
		after := versions(t, got.Artifacts[0].Content)
		if len(after["minimist"]) != 1 || len(after["mkdirp"]) != 1 || after["mkdirp"][0] == "0.5.1" {
			t.Errorf("versions after = %v", after)
		}
		if got.SourceCheck == nil || !got.SourceCheck.Passed || got.SourceCheck.Basis != "package_version_vuln_edges" {
			t.Errorf("source check = %+v", got.SourceCheck)
		}
		if files["package.json"] == "" || len(got.Update.ManifestEdits) != 0 {
			t.Errorf("manifest edits = %+v", got.Update.ManifestEdits)
		}
	})
	t.Run("npm_chain_fixed_and_unfixed_paths", func(t *testing.T) {
		got, files := run(t, "npm_chain_fixed_and_unfixed")
		if got.Category != CategoryPRCandidate || got.Reason != ReasonUpdateVerified {
			t.Fatalf("category = %s/%s (%s)", got.Category, got.Reason, got.Detail)
		}
		c := got.Update.Chain
		if c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0].Name != "mkdirp" {
			t.Fatalf("chain = %+v: mkdirp is the only top", c)
		}
		after := got.Artifacts[0].Content
		if before := []byte(files["package-lock.json"]); entry(t, before, "node_modules/rc") != entry(t, after, "node_modules/rc") {
			t.Errorf("rc changed:\n%s\n%s", entry(t, before, "node_modules/rc"), entry(t, after, "node_modules/rc"))
		}
		for _, v := range versions(t, after)["minimist"] {
			if cmp, _ := compareVersions(schemeSemver, v, "1.2.6"); cmp < 0 {
				t.Errorf("minimist %s is left", v)
			}
		}
		if packageOf(t, got, "minimist").Through[0] != "mkdirp" {
			t.Errorf("through = %v", packageOf(t, got, "minimist").Through)
		}
	})
	t.Run("npm_chain_two_tops_one_stuck", func(t *testing.T) {
		got, _ := run(t, "npm_chain_two_tops")
		if got.Category == CategoryPRCandidate {
			t.Fatalf("a result was proposed: %s", got.Detail)
		}
		wantCategory(t, got, CategoryManual, ReasonTargetNotUpdated)
		if min := packageOf(t, got, "minimist"); min.Reason != ReasonDependentsNotFixed {
			t.Errorf("minimist = %+v", min)
		}
		c := got.Update.Chain
		if c == nil || c.Outcome != ChainNotFixed || len(c.Blocked) < 2 {
			t.Errorf("chain = %+v: both mkdirp and optimist pin it", c)
		}
		if len(got.Artifacts) != 0 {
			t.Errorf("artifacts = %+v", got.Artifacts)
		}
	})
	t.Run("npm_chain_mixed_direct", func(t *testing.T) {
		got, _ := run(t, "npm_chain_mixed_direct")
		wantCategory(t, got, CategoryManual, ReasonTargetNotUpdated)
		if got.Update != nil && got.Update.Chain != nil {
			t.Errorf("chain = %+v: a package the project declares is left to the ordinary update", got.Update.Chain)
		}
		if min := packageOf(t, got, "minimist"); min.Reason != ReasonTargetNotUpdated || len(min.Through) != 0 {
			t.Errorf("minimist = %+v", min)
		}
	})
}

// TestIntegrationPnpmChain is TestIntegrationNpmChain for pnpm projects, run
// with the releases of pnpm 9, 10 and 12 (the first 12 release that resolves
// the lockfile with entries taken out), each declared in package.json.
func TestIntegrationPnpmChain(t *testing.T) {
	e := itSetup(t)
	minimist := func() *findingGroup {
		return group(typeNodePkg, "minimist", "0.0.8", FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/minimist/package.json"},
			CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
	}
	run := func(t *testing.T, dir, release string) (LanguageItem, map[string]string) {
		t.Helper()
		files := readTestdata(t, dir, "package.json", "pnpm-lock.yaml")
		files["package.json"] = strings.Replace(files["package.json"], "{", "{\n  \"packageManager\": \"pnpm@"+release+"\",", 1)
		it := itemFor(t, ManagerPnpm, files, minimist())
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("the fixture is not an update candidate: %s %s", it.Category, it.Detail)
		}
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		up, err := NewLangUpdater(e.config(LangUpdateConfig{
			GitHub: ghFor(files), Images: map[string]ImageEnv{"img": e.image}, MaxJobs: 4, JobIDPrefix: "itp",
		}))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		up.Run(e.ctx, plan)
		got := plan.LanguageItems[0]
		t.Logf("%s pnpm %s: category=%s reason=%s detail=%q took=%s", dir, release, got.Category, got.Reason, got.Detail, time.Since(start).Round(time.Second))
		if got.Update != nil {
			t.Logf("chain=%+v notes=%v tool=%+v", got.Update.Chain, got.Update.Notes, got.Update.Tool)
		}
		return got, files
	}
	for _, release := range []string{"9.15.9", "10.34.4", "12.11.2"} {
		t.Run("pnpm_chain_exact_pin_"+release, func(t *testing.T) {
			got, _ := run(t, "pnpm_chain_exact_pin", release)
			if got.Category != CategoryPRCandidate || got.Reason != ReasonUpdateVerified {
				t.Fatalf("category = %s/%s (%s)", got.Category, got.Reason, got.Detail)
			}
			c := got.Update.Chain
			if c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0].Name != "mkdirp" || c.Tops[0].From != "0.5.1" ||
				len(c.Blocked) != 1 || c.Blocked[0].Parent != "mkdirp" || c.Blocked[0].Proof != "exact" || c.Usage.Containers != 2 {
				t.Fatalf("chain = %+v", c)
			}
			if tl := got.Update.Tool; tl == nil || tl.Version != release {
				t.Errorf("tool = %+v", tl)
			}
			frozen := false
			for _, s := range got.Update.Steps {
				frozen = frozen || (s.Op == string(worker.OpPnpmFrozen) && s.Scratch && s.ExitCode == 0)
			}
			if !frozen {
				t.Errorf("steps = %+v: the chain's result was not checked by a frozen install", got.Update.Steps)
			}
			min := packageOf(t, got, "minimist")
			if strings.Join(min.Through, ",") != "mkdirp" {
				t.Errorf("minimist = %+v", min)
			}
			if cmp, _ := compareVersions(schemeSemver, min.AdoptedVersion, "1.2.6"); cmp < 0 {
				t.Errorf("adopted = %s", min.AdoptedVersion)
			}
			if len(got.Artifacts) != 1 || got.Artifacts[0].Path != "pnpm-lock.yaml" {
				t.Errorf("artifacts = %+v", got.Artifacts)
			}
			if got.SourceCheck == nil || !got.SourceCheck.Passed || got.SourceCheck.Basis != "package_version_vuln_edges" {
				t.Errorf("source check = %+v", got.SourceCheck)
			}
		})
		t.Run("pnpm_chain_fixed_and_unfixed_paths_"+release, func(t *testing.T) {
			got, files := run(t, "pnpm_chain_fixed_and_unfixed", release)
			if got.Category != CategoryPRCandidate || got.Reason != ReasonUpdateVerified {
				t.Fatalf("category = %s/%s (%s)", got.Category, got.Reason, got.Detail)
			}
			c := got.Update.Chain
			if c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0].Name != "mkdirp" {
				t.Fatalf("chain = %+v: mkdirp is the only top", c)
			}
			after := string(got.Artifacts[0].Content)
			// rc keeps its record and its place in the importer; only the version
			// of minimist it points to moved.
			recordOf := func(lock, section, key string) string {
				i := strings.Index(lock, "\n"+section+":\n")
				j := strings.Index(lock[i:], "\n  "+key+":")
				if i < 0 || j < 0 {
					return ""
				}
				rest := lock[i+j+1:]
				if k := strings.Index(rest, "\n\n"); k >= 0 {
					rest = rest[:k]
				}
				return rest
			}
			if recordOf(files["pnpm-lock.yaml"], "packages", "rc@1.2.8") != recordOf(after, "packages", "rc@1.2.8") || recordOf(after, "packages", "rc@1.2.8") == "" {
				t.Errorf("the package record of rc changed:\n%s", after)
			}
			if strings.Contains(after, "minimist@0.0.8") || strings.Contains(after, "minimist@1.2.0") {
				t.Errorf("a vulnerable minimist is left:\n%s", after)
			}
			if !strings.Contains(after, "  rc@1.2.8:\n    dependencies:") || !strings.Contains(after, "mkdirp@0.5.6") {
				t.Errorf("lockfile:\n%s", after)
			}
		})
	}
}
