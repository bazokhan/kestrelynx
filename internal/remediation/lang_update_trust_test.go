package remediation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Tests for the trust boundary: the registries' metadata is believed, the work
// container's output is believed only where the metadata or a computation of
// this program backs it.

// --- every occurrence is compared on its own ---

func TestEachOccurrenceOfTheSameVersionIsComparedOnItsOwn(t *testing.T) {
	root := map[string]string{"a": "^1.0.0", "t": "^1.0.0"}
	before := map[string]npmEntry{
		"node_modules/a":                {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/a/node_modules/t": {ver: "1.0.0"},
		"node_modules/t":                {ver: "1.0.0"},
	}
	good := map[string]npmEntry{
		"node_modules/a":                {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/a/node_modules/t": {ver: "1.0.5"},
		"node_modules/t":                {ver: "1.0.5"},
	}
	h := newNpmCase(t, root, before, good)
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)

	// The nested copy claims 1.0.5 and records the tarball of 1.0.0.
	forged := map[string]npmEntry{
		"node_modules/a":                {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/a/node_modules/t": {ver: "1.0.5", url: npmURL("t", "1.0.0")},
		"node_modules/t":                {ver: "1.0.5"},
	}
	h = newNpmCase(t, root, before, forged)
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	if !strings.Contains(it.Detail, "node_modules/a/node_modules/t") {
		t.Errorf("detail = %q", it.Detail)
	}
	// The registry was asked once for the version, not once per occurrence.
	n := 0
	for _, l := range h.npm.lookups {
		if l == "t@1.0.5" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("t@1.0.5 was looked up %d times", n)
	}
}

// --- directness and ranges ---

func TestManifestAndLockfileRootMustAgreeAboutAnUpdatedPackage(t *testing.T) {
	before := map[string]npmEntry{"node_modules/t": {ver: "1.0.0"}}
	after := map[string]npmEntry{"node_modules/t": {ver: "2.0.0"}}
	// package.json asks for ^1.0.0; the lockfile's root (before and after) records a range that allows 2.0.0.
	h := newNpmCaseM(t, map[string]string{"t": "^1.0.0"}, map[string]string{"t": "^1.0.0 || ^2.0.0"}, before, after)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonLockfileInconsistent)
	if it.Packages[0].Reason != ReasonLockfileInconsistent {
		t.Errorf("package = %+v", it.Packages[0])
	}
	// The package.json range is the one that counts, also when they agree.
	h = newNpmCaseM(t, map[string]string{"t": "^1.0.0"}, map[string]string{"t": "^1.0.0"}, before, after)
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
}

func TestManifestRequirementTheLockfileRootLacksIsRefused(t *testing.T) {
	before := map[string]npmEntry{"node_modules/t": {ver: "1.0.0"}, "node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}}}
	after := map[string]npmEntry{"node_modules/t": {ver: "1.0.5"}, "node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}}}
	h := newNpmCaseM(t, map[string]string{"a": "^1.0.0", "t": "^1.0.0"}, map[string]string{"a": "^1.0.0"}, before, after)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonLockfileInconsistent)
}

func TestUvManifestAndLockMetadataMustAgree(t *testing.T) {
	h := newHarness(t, "uv")
	widened := func(s string) string {
		return strings.Replace(s, `specifier = ">=1.26,<2"`, `specifier = ">=1.26,<3"`, 1)
	}
	h.files["uv.lock"] = widened(h.files["uv.lock"])
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
	forged := widened(strings.ReplaceAll(string(h.after), "1.26.17", "2.0.7"))
	h.pypi.releases["urllib3==2.0.7"] = []PyPIFile{
		{Filename: "urllib3-2.0.7-py2.py3-none-any.whl", URL: "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-2.0.7-py2.py3-none-any.whl", Wheel: true, SHA256: urllibWheelSHA},
		{Filename: "urllib3-2.0.7.tar.gz", URL: "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-2.0.7.tar.gz", Sdist: true, SHA256: urllibSdistSHA},
	}
	h.editLock(forged)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonLockfileInconsistent)
}

func TestTransitiveRangeIsTheRegistrysNotTheLockfiles(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	// The lockfile records that a accepts t ^1.0.0 || ^2.0.0; the registry says ^1.0.0.
	lax := map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0 || ^2.0.0"}}}
	before := map[string]npmEntry{"node_modules/a": lax["node_modules/a"], "node_modules/t": {ver: "1.0.0"}}
	after := map[string]npmEntry{"node_modules/a": lax["node_modules/a"], "node_modules/t": {ver: "2.0.0"}}
	h := newNpmCase(t, root, before, after)
	h.npm.dists["a@1.0.0"] = NpmDist{Tarball: npmURL("a", "1.0.0"), Integrity: "sha512-a1.0.0", Dependencies: map[string]string{"t": "^1.0.0 || ^2.0.0"}}
	it, _ := h.run()
	if it.Category != CategoryManual {
		// The registry agrees with the lockfile here, so 2.0.0 is allowed;
		// the next case is the one that matters.
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	}
	h = newNpmCase(t, root, before, after)
	h.npm.dists["a@1.0.0"] = NpmDist{Tarball: npmURL("a", "1.0.0"), Integrity: "sha512-a1.0.0", Dependencies: map[string]string{"t": "^1.0.0"}}
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
}

func TestParentTheRegistryDoesNotKnowOrDoesNotListTheChild(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	before := map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}}, "node_modules/t": {ver: "1.0.0"}}
	after := map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}}, "node_modules/t": {ver: "1.0.5"}}
	h := newNpmCase(t, root, before, after)
	delete(h.npm.dists, "a@1.0.0")
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)

	h = newNpmCase(t, root, before, after)
	h.npm.dists["a@1.0.0"] = NpmDist{Tarball: npmURL("a", "1.0.0"), Integrity: "sha512-a1.0.0"}
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}

func TestPnpmParentRange(t *testing.T) {
	h := newHarness(t, "pnpm")
	forged := strings.NewReplacer("minimist@1.2.8", "minimist@2.0.0", "minimist: 1.2.8", "minimist: 2.0.0", minimist128.Integrity, "sha512-two").Replace(string(h.after))
	h.npm.dists["minimist@2.0.0"] = NpmDist{Tarball: "https://registry.npmjs.org/minimist/-/minimist-2.0.0.tgz", Integrity: "sha512-two"}
	h.editLock(forged)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	if !strings.Contains(it.Detail, "mkdirp 0.5.5") {
		t.Errorf("detail = %q", it.Detail)
	}
}

// uvTransitive makes a uv project whose only requirement is app-lib, which
// requires urllib3, locked at urllib3 1.26.4; after has urllib3 at ver.
func uvTransitive(t *testing.T, ver string) *harness {
	t.Helper()
	pkg := func(name, v, deps string) string {
		return fmt.Sprintf(`
[[package]]
name = %q
version = %q
source = { registry = "https://pypi.org/simple" }
%swheels = [
    { url = "https://files.pythonhosted.org/packages/x/%s-%s-py3-none-any.whl", hash = "sha256:%s" },
]
`, name, v, deps, name, v, fakeWheelSHA(name, v))
	}
	lock := func(uv string) string {
		return `version = 1
revision = 5
requires-python = ">=3.9"

[[package]]
name = "app"
version = "1.0.0"
source = { virtual = "." }
dependencies = [
    { name = "app-lib" },
]

[package.metadata]
requires-dist = [{ name = "app-lib", specifier = ">=1" }]
` + pkg("app-lib", "1.0.0", "dependencies = [\n    { name = \"urllib3\" },\n]\n") + pkg("urllib3", uv, "")
	}
	h := newHarness(t, "uv")
	h.files = map[string]string{
		"pyproject.toml": "[project]\nname = \"app\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"app-lib>=1\"]\n\n[tool.uv]\npackage = false\n",
		"uv.lock":        lock("1.26.4"),
	}
	h.after = []byte(lock(ver))
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.item = itemFor(t, ManagerUv, h.files, group(typePythonPkg, "urllib3", "1.26.4", pyOrigin(), CVERef{VulnID: "CVE-2021-33503", FixedVers: []string{"1.26.5"}}))
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not a candidate: %s %s", h.item.Reason, h.item.Detail)
	}
	h.fx.beforePkgs = [][2]string{{"urllib3", "1.26.4"}}
	h.fx.afterPkgs = [][2]string{{"urllib3", ver}}
	h.pypi.releases = map[string][]PyPIFile{}
	h.pypi.requires = map[string][]string{"app-lib==1.0.0": {"urllib3<1.26.10"}}
	return h
}

func TestUvParentRangeComesFromTheIndex(t *testing.T) {
	good := uvTransitive(t, "1.26.8")
	it, _ := good.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)

	// 1.26.17 is above what app-lib accepts.
	h := uvTransitive(t, "1.26.17")
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)

	// The index does not list the requirement the lockfile claims.
	h = uvTransitive(t, "1.26.8")
	h.pypi.requires = map[string][]string{"app-lib==1.0.0": {"idna>=2"}}
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}

func TestPipParentRange(t *testing.T) {
	h := newHarness(t, "pip")
	useUnhashed(t, h)
	h.pypi.requires = map[string][]string{"parent==1.0": {"urllib3<1.26.10"}}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: pipReportItems(pipItem{name: "urllib3", ver: "1.26.4"}, pipItem{name: "parent", ver: "1.0"})}}}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: pipReportItems(pipItem{name: "urllib3", ver: "1.26.17"}, pipItem{name: "parent", ver: "1.0"})}}}
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
}

// --- dependencies an entry records are the ones the registry declares ---

func TestDeclarationRemovedTogetherWithItsEntryIsRefused(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	before := map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}},
		"node_modules/c": {ver: "1.0.0"},
	}
	// root -> a -> t -> c. The output drops t's requirement of c and c's entry.
	after := map[string]npmEntry{
		"node_modules/a": before["node_modules/a"],
		"node_modules/t": {ver: "1.0.5"},
	}
	h := newNpmCase(t, root, before, after)
	// The registry says t 1.0.5 still depends on c.
	h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", Dependencies: map[string]string{"c": "^1.0.0"}}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	if !strings.Contains(it.Detail, "t 1.0.5") {
		t.Errorf("detail = %q", it.Detail)
	}
	// With the registry's own declaration the same output is fine.
	h = newNpmCase(t, root, before, after)
	it, _ = h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}

func TestNpmDependencySetsAndPeersMatchTheRegistry(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	before := map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}}, "node_modules/t": {ver: "1.0.0"}}
	after := map[string]npmEntry{"node_modules/a": before["node_modules/a"], "node_modules/t": {ver: "1.0.5"}}
	t.Run("an undeclared dependency is added", func(t *testing.T) {
		h := newNpmCase(t, root, before, npmWith2(after, "node_modules/t", npmEntry{ver: "1.0.5", deps: map[string]string{"x": "^1.0.0"}}, "node_modules/x"))
		h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5"}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a declared peer is missing from the entry", func(t *testing.T) {
		h := newNpmCase(t, root, before, after)
		h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", PeerDependencies: map[string]string{"react": "^18"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("an optional dependency counts with the dependencies", func(t *testing.T) {
		h := newNpmCase(t, root, before, after)
		h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", OptionalDependencies: map[string]string{"fsevents": "^2"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

// npmWith2 returns m with the entry at key replaced and the extra entry added.
func npmWith2(m map[string]npmEntry, key string, e npmEntry, extra string) map[string]npmEntry {
	out := map[string]npmEntry{}
	for k, v := range m {
		out[k] = v
	}
	out[key] = e
	out[extra] = npmEntry{ver: "1.0.0"}
	return out
}

func TestPnpmSnapshotMatchesTheRegistry(t *testing.T) {
	t.Run("a dependency the registry does not declare", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		forged := strings.Replace(string(h.after), "  minimist@1.2.8: {}", "  minimist@1.2.8:\n    dependencies:\n      foo: 1.0.0\n\n  foo@1.0.0: {}", 1)
		forged = strings.Replace(forged, "  mkdirp@0.5.5:\n    resolution", "  foo@1.0.0:\n    resolution: {integrity: sha512-foo}\n\n  mkdirp@0.5.5:\n    resolution", 1)
		h.editLock(forged)
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a declared dependency the snapshot lacks", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.npm.dists["minimist@1.2.8"] = NpmDist{Tarball: minimist128.Tarball, Integrity: minimist128.Integrity, Dependencies: map[string]string{"foo": "^1"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "lacks the dependency foo") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("a peer the snapshot installed is allowed", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		forged := strings.Replace(string(h.after), "  minimist@1.2.8: {}", "  minimist@1.2.8:\n    dependencies:\n      foo: 1.0.0\n\n  foo@1.0.0: {}", 1)
		forged = strings.Replace(forged, "  mkdirp@0.5.5:\n    resolution", "  foo@1.0.0:\n    resolution: {integrity: sha512-foo}\n\n  mkdirp@0.5.5:\n    resolution", 1)
		forged = strings.Replace(forged, "  minimist@1.2.8:\n    resolution: {integrity: "+minimist128.Integrity+"}", "  minimist@1.2.8:\n    resolution: {integrity: "+minimist128.Integrity+"}\n    peerDependencies:\n      foo: ^1", 1)
		h.editLock(forged)
		h.npm.dists["minimist@1.2.8"] = NpmDist{Tarball: minimist128.Tarball, Integrity: minimist128.Integrity, PeerDependencies: map[string]string{"foo": "^1"}}
		h.npm.dists["foo@1.0.0"] = NpmDist{Tarball: npmURL("foo", "1.0.0"), Integrity: "sha512-foo"}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
}

func TestUvRequirementsOfTheIndexMustBeInTheEntry(t *testing.T) {
	t.Run("a requirement without an extra is missing", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"idna>=2; python_version >= '3'"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "idna") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("requirements of extras need not be there", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {`brotli>=1.0.9; extra == "brotli"`, `pysocks!=1.5.7,<2.0,>=1.5.6; extra == 'socks'`}}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
}

func TestPipRequirementsInForceMustBeInstalled(t *testing.T) {
	cases := []struct {
		name     string
		requires []string
		file     string
		cat      Category
		reason   Reason
	}{
		{"in force and missing", []string{"idna>=2; python_version >= '3.8'"}, "urllib3==1.26.4\n", CategoryManual, ReasonUnexplainedDiff},
		{"unconditional and missing", []string{"idna>=2"}, "urllib3==1.26.4\n", CategoryManual, ReasonUnexplainedDiff},
		{"marker false for this python", []string{"idna>=2; python_version < '3.9'"}, "urllib3==1.26.4\n", CategoryPRCandidate, ReasonUpdateVerified},
		{"marker false for this platform", []string{"colorama; sys_platform == 'win32'"}, "urllib3==1.26.4\n", CategoryPRCandidate, ReasonUpdateVerified},
		{"marker false for this os", []string{"colorama; os_name == 'nt' or platform_system == 'Windows'"}, "urllib3==1.26.4\n", CategoryPRCandidate, ReasonUpdateVerified},
		{"extra not asked for", []string{"pysocks; extra == 'socks'"}, "urllib3==1.26.4\n", CategoryPRCandidate, ReasonUpdateVerified},
		{"extra asked for", []string{"pysocks; extra == 'socks'"}, "urllib3[socks]==1.26.4\n", CategoryManual, ReasonUnexplainedDiff},
		{"undecidable marker", []string{"idna; platform_release >= '5'"}, "urllib3==1.26.4\n", CategoryManual, ReasonMarkerNotEvaluated},
		{"unreadable marker", []string{"idna; python_version >>> '3'"}, "urllib3==1.26.4\n", CategoryManual, ReasonMarkerNotEvaluated},
		{"patch level matters", []string{"idna; python_full_version == '3.12.1'"}, "urllib3==1.26.4\n", CategoryManual, ReasonMarkerNotEvaluated},
		{"patch level does not matter", []string{"colorama; python_full_version < '3.10'"}, "urllib3==1.26.4\n", CategoryPRCandidate, ReasonUpdateVerified},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "pip")
			h.files["requirements.txt"] = c.file
			h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.pypi.requires = map[string][]string{"urllib3==1.26.4": c.requires, "urllib3==1.26.17": c.requires}
			it, _ := h.run()
			wantCategory(t, it, c.cat, c.reason)
		})
	}
}

// --- unresolved requirements and markers ---

func TestUnresolvedRequirementsArePositional(t *testing.T) {
	root := map[string]string{"a": "^1.0.0", "e": "^1.0.0"}
	before := map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0"},
		// e left an optional requirement of the same name unresolved before.
		"node_modules/e": {ver: "1.0.0"},
	}
	t.Run("a required requirement of the updated package stays unresolved", func(t *testing.T) {
		after := map[string]npmEntry{
			"node_modules/a": before["node_modules/a"],
			"node_modules/t": {ver: "1.0.5", deps: map[string]string{"o": "^1.0.0"}},
			"node_modules/e": {ver: "1.0.0"},
		}
		h := newNpmCase(t, root, before, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("an exception elsewhere does not cover it", func(t *testing.T) {
		// e records "o" as an optional dependency that no entry satisfies,
		// before and after. t gains a required requirement of the same name.
		eBefore := npmEntry{ver: "1.0.0", deps: map[string]string{"o": "^1.0.0"}}
		b := map[string]npmEntry{"node_modules/a": before["node_modules/a"], "node_modules/t": before["node_modules/t"], "node_modules/e": eBefore}
		after := map[string]npmEntry{
			"node_modules/a": before["node_modules/a"],
			"node_modules/t": {ver: "1.0.5", deps: map[string]string{"o": "^1.0.0"}},
			"node_modules/e": eBefore,
		}
		h := newNpmCase(t, root, b, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("a requirement resolved before and not after", func(t *testing.T) {
		b := map[string]npmEntry{"node_modules/a": before["node_modules/a"], "node_modules/t": before["node_modules/t"], "node_modules/e": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}}, "node_modules/c": {ver: "1.0.0"}}
		after := map[string]npmEntry{"node_modules/a": before["node_modules/a"], "node_modules/t": {ver: "1.0.5"}, "node_modules/e": b["node_modules/e"]}
		h := newNpmCase(t, root, b, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
}

func TestUnresolvedGraphRules(t *testing.T) {
	mk := func(optional bool, owner string) *depGraph {
		g := &depGraph{nodes: map[string]*depNode{}}
		g.nodes[owner] = &depNode{name: "p", version: "1", deps: []depEdge{{name: "o", optional: optional}}}
		return g
	}
	// The same entry, the same requirement: tolerated, required or optional.
	for _, opt := range []bool{true, false} {
		if got := newUnresolved(mk(opt, "node_modules/p"), mk(opt, "node_modules/p")); len(got) != 0 {
			t.Errorf("optional=%v: %v", opt, got)
		}
	}
	// A new key for the same package: an optional requirement may move with it, a required one may not.
	if got := newUnresolved(mk(true, "node_modules/p"), mk(true, "node_modules/x/node_modules/p")); len(got) != 0 {
		t.Errorf("optional moved: %v", got)
	}
	if got := newUnresolved(mk(false, "p@1"), mk(false, "p@2")); len(got) != 1 {
		t.Errorf("required moved: %v", got)
	}
	// Another package's exception does not cover this one.
	other := mk(true, "node_modules/p")
	other.nodes["node_modules/q"] = &depNode{name: "q", version: "1"}
	after := mk(true, "node_modules/p")
	after.nodes["node_modules/q"] = &depNode{name: "q", version: "1", deps: []depEdge{{name: "o", optional: true}}}
	if got := newUnresolved(other, after); len(got) != 1 || got[0].ownerName != "q" {
		t.Errorf("another package: %v", got)
	}
}

func TestMarkerEvaluation(t *testing.T) {
	env := markerEnv{pyMinor: "3.12", machine: "x86_64", extras: map[string]bool{"socks": true}}
	cases := []struct {
		marker string
		want   bool
		err    bool
	}{
		{`python_version >= "3.8"`, true, false},
		{`python_version < "3.9"`, false, false},
		{`python_version == "3.12"`, true, false},
		{`python_version == "3.*"`, true, false},
		{`python_version != "3.12"`, false, false},
		{`"3.8" <= python_version`, true, false},
		{`python_version >= "3.10" and python_version < "3.13"`, true, false},
		{`python_version < "3.8" or python_version > "3.11"`, true, false},
		{`(python_version < "3.8" or sys_platform == "win32") and os_name == "posix"`, false, false},
		{`sys_platform == "linux"`, true, false},
		{`sys_platform == 'darwin'`, false, false},
		{`sys_platform != "win32"`, true, false},
		{`platform_system == "Linux"`, true, false},
		{`platform_system == "Windows"`, false, false},
		{`os_name == "nt"`, false, false},
		{`platform_machine == "x86_64"`, true, false},
		{`platform_machine == "aarch64"`, false, false},
		{`platform_machine in "x86_64 amd64 AMD64"`, true, false},
		{`"linux" in sys_platform`, true, false},
		{`sys_platform not in "win32 cygwin"`, true, false},
		{`implementation_name == "cpython"`, true, false},
		{`implementation_name == "pypy"`, false, false},
		{`platform_python_implementation == "CPython"`, true, false},
		{`platform_python_implementation != "CPython"`, false, false},
		{`python_full_version >= "3.8.1"`, true, false},
		{`python_full_version < "3.12"`, false, false},
		{`python_full_version >= "3.12.1"`, false, true},
		{`python_full_version == "3.12.1"`, false, true},
		{`python_full_version < "3.13"`, true, false},
		{`implementation_version >= "3.8"`, true, false},
		{`extra == "socks"`, true, false},
		{`extra == "brotli"`, false, false},
		{`extra != "brotli"`, true, false},
		{`extra == 'SOCKS'`, true, false},
		{`platform_release >= "5"`, false, true},
		{`platform_version == "x"`, false, true},
		{`unknown_variable == "x"`, false, true},
		{`sys_platform == "win32" and platform_release >= "5"`, false, false},
		{`sys_platform == "linux" or platform_release >= "5"`, true, false},
		{`sys_platform == "linux" and platform_release >= "5"`, false, true},
		{`python_version >>> "3"`, false, true},
		{`python_version >= `, false, true},
		{`python_version >= "3.8`, false, true},
		{`(python_version >= "3.8"`, false, true},
		{`python_version >= "3.8" )`, false, true},
		{`"a" == "b"`, false, true},
		{`python_version`, false, true},
		{`python_version === "3.12"`, true, false},
	}
	for _, c := range cases {
		got, err := env.eval(c.marker)
		if (err != nil) != c.err || (err == nil && got != c.want) {
			t.Errorf("eval(%s) = %v, %v; want %v, error %v", c.marker, got, err, c.want, c.err)
		}
	}
	if _, err := env.eval(strings.Repeat("(", 40) + `python_version >= "3"` + strings.Repeat(")", 40)); err == nil {
		t.Error("a marker nested 40 deep was evaluated")
	}
	// The tags decide the machine.
	if m := pipMachine(&worker.Target{Platforms: []string{"manylinux_2_36_aarch64"}}); m != "aarch64" {
		t.Errorf("machine = %q", m)
	}
	if m := pipMachine(&worker.Target{Platforms: []string{"musllinux_1_2_x86_64"}}); m != "x86_64" {
		t.Errorf("machine = %q", m)
	}
}

// --- rewriting is bounded and linear ---

func TestRewriteIsBounded(t *testing.T) {
	ed := func(line int, hashes ...string) reqEdit {
		return reqEdit{Name: "pkg", Line: line, OldVersion: "1", NewVersion: "2", Hashes: hashes}
	}
	t.Run("too many lines", func(t *testing.T) {
		var edits []reqEdit
		var b strings.Builder
		for i := 0; i <= maxPipEdits; i++ {
			b.WriteString("pkg==1\n")
			edits = append(edits, ed(i+1))
		}
		if _, err := rewriteRequirements(bg, []byte(b.String()), edits); !errors.Is(err, errRewriteLimit) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("too many hashes for one requirement", func(t *testing.T) {
		var hs []string
		for i := 0; i <= maxWheelsPerEdit; i++ {
			hs = append(hs, fmt.Sprintf("%064x", i))
		}
		in := "pkg==1 \\\n  --hash=sha256:" + h64('a') + "\n"
		if _, err := rewriteRequirements(bg, []byte(in), []reqEdit{ed(1, hs...)}); !errors.Is(err, errRewriteLimit) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the result would be too large", func(t *testing.T) {
		var edits []reqEdit
		var b strings.Builder
		var hs []string
		for i := 0; i < maxWheelsPerEdit; i++ {
			hs = append(hs, fmt.Sprintf("%064x", i))
		}
		for i := 0; i < maxPipEdits; i++ {
			fmt.Fprintf(&b, "pkg==1 \\\n  --hash=sha256:%s\n", h64('a'))
			edits = append(edits, ed(2*i+1, hs...))
		}
		if _, err := rewriteRequirements(bg, []byte(b.String()), edits); !errors.Is(err, errRewriteLimit) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the deadline is watched", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := rewriteRequirements(ctx, []byte("pkg==1\n"), []reqEdit{ed(1)}); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a big file with many edits is rewritten in one pass", func(t *testing.T) {
		var b strings.Builder
		var edits []reqEdit
		for i := 0; i < 200000; i++ {
			if i%1000 == 0 && len(edits) < maxPipEdits {
				b.WriteString("pkg==1\n")
				edits = append(edits, ed(i+1))
			} else {
				b.WriteString("# a comment line that stays\n")
			}
		}
		start := time.Now()
		out, err := rewriteRequirements(bg, []byte(b.String()), edits)
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("took %s", d)
		}
		if len(out) != b.Len() {
			t.Errorf("length = %d", len(out))
		}
	})
	t.Run("the line must name the expected package", func(t *testing.T) {
		if _, err := rewriteRequirements(bg, []byte("other==1\n"), []reqEdit{ed(1)}); err == nil {
			t.Error("rewrote a line of another package")
		}
		if out, err := rewriteRequirements(bg, []byte("Pkg_Name[x]==1\n"), []reqEdit{{Name: "pkg-name", Line: 1, OldVersion: "1", NewVersion: "2"}}); err != nil || string(out) != "Pkg_Name[x]==2\n" {
			t.Errorf("%q %v", out, err)
		}
	})
	t.Run("overlapping edits", func(t *testing.T) {
		in := "pkg==1 \\\n  --hash=sha256:" + h64('a') + "\n"
		if _, err := rewriteRequirements(bg, []byte(in), []reqEdit{ed(1, h64('b')), ed(2)}); err == nil {
			t.Error("accepted an edit inside another")
		}
	})
}

func TestPipLimitsDefer(t *testing.T) {
	t.Run("a release with too many wheels", func(t *testing.T) {
		h := newHarness(t, "pip")
		var files []PyPIFile
		for i := 0; i <= maxWheelsPerEdit; i++ {
			files = append(files, PyPIFile{Filename: fmt.Sprintf("u-%d.whl", i), URL: fmt.Sprintf("https://files.pythonhosted.org/%d.whl", i), Wheel: true, SHA256: fmt.Sprintf("%064x", i+1)})
		}
		h.pypi.releases["urllib3==1.26.17"] = files
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
	})
	t.Run("too many packages", func(t *testing.T) {
		h := newHarness(t, "pip")
		for i := 0; i < worker.MaxPackages+1; i++ {
			h.item.Packages = append(h.item.Packages, LanguagePackage{
				Name: fmt.Sprintf("p%d", i), Ecosystem: typePythonPkg, Installed: "1.0.0", SelectionLowerBound: "1.0.1", Action: ActionUpdate,
				Occurrences: []SourceOccurrence{{Path: fmt.Sprintf("requirements.txt:%d", i+1), Version: "1.0.0", Matched: true}},
			})
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdatePackageLimit)
		if h.work.calls != 0 || h.pypi.lookups != nil {
			t.Error("work was done")
		}
	})
	t.Run("the deadline during the rewrite defers", func(t *testing.T) {
		h := newHarness(t, "pip")
		ctx, cancel := context.WithCancel(context.Background())
		h.cfg.PyPI = pypiFunc(func(c context.Context, name, version string) (PyPIRelease, error) {
			cancel()
			return PyPIRelease{Files: []PyPIFile{fakeWheel(name, version)}}, nil
		})
		it, _ := h.runCtx(ctx)
		wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
	})
}

// --- the classification of limits ---

func TestLimitsAreClassifiedByWhoseBudgetTheyAre(t *testing.T) {
	t.Run("an output that is too large to read is manual", func(t *testing.T) {
		h := newHarness(t, "npm")
		lowerGraphLimits(t, 3, 1000)
		// The original has three entries; the output has a fourth.
		h.editLock(strings.Replace(string(h.after), `"node_modules/mkdirp"`, `"node_modules/extra": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz", "integrity": "sha512-x"},
    "node_modules/mkdirp"`, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("this program's registry budget defers", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.npm.err = errRegistryBudget
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonRegistryCheckLimit)
	})
}
