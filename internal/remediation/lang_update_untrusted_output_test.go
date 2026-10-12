package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// These tests give the update stage the output of a compromised package
// manager: a result it should refuse. Each starts from an update that passes.

func npmURL(name, ver string) string {
	return "https://registry.npmjs.org/" + name + "/-/" + name[strings.LastIndex(name, "/")+1:] + "-" + ver + ".tgz"
}

// newNpmCase makes an npm harness over a synthetic project: root requires
// the given ranges, before and after are the lockfile entries before and
// after the update of the package "t" (1.0.0 to 1.0.5). The registry
// publishes every entry of the after file as the file records it.
func newNpmCase(t *testing.T, root map[string]string, before, after map[string]npmEntry) *harness {
	t.Helper()
	return newNpmCaseM(t, root, root, before, after)
}

// newNpmCaseM is newNpmCase with a package.json that asks for manifestRoot
// where the lockfile's root entry records lockRoot.
func newNpmCaseM(t *testing.T, manifestRoot, root map[string]string, before, after map[string]npmEntry) *harness {
	t.Helper()
	h := newHarness(t, "npm")
	manifest, _ := json.Marshal(map[string]any{"name": "app", "version": "1.0.0", "dependencies": manifestRoot})
	files := map[string]string{"package.json": string(manifest), "package-lock.json": string(npmLock(root, before))}
	h.files = files
	h.after = npmLock(root, after)
	h.gh = ghFor(files)
	h.cfg.GitHub = h.gh
	origin := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/t/package.json"}
	h.item = itemFor(t, ManagerNpm, files, group(typeNodePkg, "t", "1.0.0", origin, CVERef{VulnID: "CVE-T", FixedVers: []string{"1.0.5"}}))
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not a candidate: %s %s", h.item.Reason, h.item.Detail)
	}
	pkgsOf := func(m map[string]npmEntry) (out [][2]string) {
		for p, e := range m {
			out = append(out, [2]string{p[strings.LastIndex(p, "node_modules/")+len("node_modules/"):], e.ver})
		}
		return out
	}
	h.fx.beforePkgs, h.fx.afterPkgs = pkgsOf(before), pkgsOf(after)
	h.fx.vulns = [][3]string{{"t", "1.0.0", "CVE-T"}}
	h.npm.dists = map[string]NpmDist{}
	for p, e := range after {
		name := p[strings.LastIndex(p, "node_modules/")+len("node_modules/"):]
		h.npm.dists[name+"@"+e.ver] = NpmDist{Tarball: npmURL(name, e.ver), Integrity: "sha512-" + name + e.ver, Dependencies: e.deps}
	}
	return h
}

func baseNpm() map[string]npmEntry {
	return map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}},
		"node_modules/c": {ver: "1.0.0"},
		"node_modules/e": {ver: "1.0.0"},
	}
}

func npmWith(mut func(map[string]npmEntry)) map[string]npmEntry {
	m := baseNpm()
	mut(m)
	return m
}

var npmRoot = map[string]string{"a": "^1.0.0", "e": "^1.0.0"}

func TestNpmCaseUpdatePasses(t *testing.T) {
	after := npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"d": "^1.0.0"}}
		delete(m, "node_modules/c")
		m["node_modules/d"] = npmEntry{ver: "1.0.0"}
	})
	h := newNpmCase(t, npmRoot, baseNpm(), after)
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	// The target and the dependency it pulled in were both looked up.
	// The two entries the update added or changed, then the parent of the target.
	if got := strings.Join(h.npm.lookups, " "); got != "d@1.0.0 t@1.0.5 a@1.0.0" {
		t.Errorf("lookups = %q", got)
	}
}

// --- the files a version is installed from must be the registry's ---

func TestNpmVersionWithTheDistributionOfAnOlderOneIsRefused(t *testing.T) {
	h := newHarness(t, "npm")
	// minimist 1.2.8 as the version, with the tarball and integrity of 1.2.5.
	forged := strings.NewReplacer(
		"minimist-1.2.8.tgz", "minimist-1.2.5.tgz",
		minimist128.Integrity, "sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==",
	).Replace(string(h.after))
	h.editLock(forged)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	if it.Packages[0].Reason != ReasonDistributionMismatch {
		t.Errorf("package = %+v", it.Packages[0])
	}
}

func TestNpmIntegrityOfAnotherFileIsRefused(t *testing.T) {
	h := newHarness(t, "npm")
	h.editLock(strings.Replace(string(h.after), minimist128.Integrity, "sha512-"+strings.Repeat("A", 86)+"==", 1))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}

func TestNpmTarballOfAnotherVersionIsRefused(t *testing.T) {
	h := newHarness(t, "npm")
	h.editLock(strings.Replace(string(h.after), "minimist-1.2.8.tgz", "minimist-9.9.9.tgz", 1))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}

func TestPnpmIntegrityOfAnotherFileIsRefused(t *testing.T) {
	h := newHarness(t, "pnpm")
	h.editLock(strings.Replace(string(h.after), strings.TrimPrefix(minimist128.Integrity, ""), "sha512-"+strings.Repeat("B", 86)+"==", 1))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}

func TestUvFilesOfAnotherReleaseAreRefused(t *testing.T) {
	for name, forge := range map[string]func(string) string{
		"hash": func(s string) string { return strings.Replace(s, "sha256:"+urllibWheelSHA, "sha256:"+h64('7'), 1) },
		"url": func(s string) string {
			return strings.Replace(s, "urllib3-1.26.17-py2.py3-none-any.whl", "urllib3-1.26.18-py2.py3-none-any.whl", 1)
		},
		"sdist hash": func(s string) string { return strings.Replace(s, "sha256:"+urllibSdistSHA, "sha256:"+h64('8'), 1) },
		"no files":   func(s string) string { return cutUvDistributions(s) },
		"other sdist": func(s string) string {
			return strings.Replace(s, "urllib3-1.26.17.tar.gz", "urllib3-1.26.18.tar.gz", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "uv")
			h.editLock(forge(string(h.after)))
			it, _ := h.run()
			if it.Category != CategoryManual || (it.Reason != ReasonDistributionMismatch && it.Reason != ReasonUnparsableSource && it.Reason != ReasonOutputFilesInvalid && it.Reason != ReasonSdistOnly && it.Reason != ReasonTargetNotUpdated && it.Reason != ReasonResolvedSourceChanged) {
				t.Fatalf("%s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			if name != "no files" {
				wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
			}
		})
	}
}

func cutUvDistributions(s string) string {
	var out []string
	skip := false
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(l, "sdist = "):
		case strings.HasPrefix(l, "wheels = ["):
			skip = true
		case skip && l == "]":
			skip = false
		case skip:
		default:
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestAddedDependenciesAreComparedWithTheRegistry(t *testing.T) {
	after := npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"d": "^1.0.0"}}
		delete(m, "node_modules/c")
		m["node_modules/d"] = npmEntry{ver: "1.0.0"}
	})
	t.Run("another file", func(t *testing.T) {
		h := newNpmCase(t, npmRoot, baseNpm(), after)
		h.npm.dists["d@1.0.0"] = NpmDist{Tarball: npmURL("d", "1.0.0"), Integrity: "sha512-other"}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("unknown to the registry", func(t *testing.T) {
		h := newNpmCase(t, npmRoot, baseNpm(), after)
		delete(h.npm.dists, "d@1.0.0")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

func TestRegistryLookupsAreBoundedAndFailuresAreClassified(t *testing.T) {
	t.Run("registry unreachable", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.npm.err = errors.New("dial tcp: i/o timeout")
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonDistributionLookup)
	})
	t.Run("index unreachable", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.pypi.err = errors.New("dial tcp: i/o timeout")
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonDistributionLookup)
	})
	t.Run("deadline during a lookup", func(t *testing.T) {
		h := newHarness(t, "npm")
		ctx, cancel := context.WithCancel(context.Background())
		h.cfg.Npm = npmFunc(func(ctx context.Context, name, version string) (NpmDist, error) {
			cancel()
			return NpmDist{}, ctx.Err()
		})
		it, _ := h.runCtx(ctx)
		wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
	})
	t.Run("too many versions to look up", func(t *testing.T) {
		deps := map[string]string{}
		after := npmWith(func(m map[string]npmEntry) { delete(m, "node_modules/c") })
		for i := 0; i < maxRegistryChecks+1; i++ {
			n := fmt.Sprintf("d%d", i)
			deps[n] = "^1.0.0"
			after["node_modules/"+n] = npmEntry{ver: "1.0.0"}
		}
		after["node_modules/t"] = npmEntry{ver: "1.0.5", deps: deps}
		h := newNpmCase(t, npmRoot, baseNpm(), after)
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonRegistryCheckLimit)
		if len(h.npm.lookups) > maxRegistryChecks {
			t.Errorf("%d lookups, over the budget", len(h.npm.lookups))
		}
	})
}

type npmFunc func(ctx context.Context, name, version string) (NpmDist, error)

func (f npmFunc) VersionDist(ctx context.Context, name, version string) (NpmDist, error) {
	return f(ctx, name, version)
}

// --- the final version is judged by the ranges that bind it ---

func TestDirectDependencyOutsideItsManifestRangeIsRefused(t *testing.T) {
	root := map[string]string{"t": "^1.0.0"}
	before := map[string]npmEntry{"node_modules/t": {ver: "1.0.0"}}
	t.Run("npm", func(t *testing.T) {
		after := map[string]npmEntry{"node_modules/t": {ver: "2.0.0"}}
		h := newNpmCase(t, root, before, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
		if it.Packages[0].Reason != ReasonRangeExcludesFix {
			t.Errorf("package = %+v", it.Packages[0])
		}
	})
	t.Run("inside it passes", func(t *testing.T) {
		after := map[string]npmEntry{"node_modules/t": {ver: "1.9.0"}}
		h := newNpmCase(t, root, before, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a range that cannot be judged", func(t *testing.T) {
		h := newNpmCase(t, map[string]string{"t": "^1.0.0 || latest"}, before, map[string]npmEntry{"node_modules/t": {ver: "1.9.0"}})
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s", it.Category, it.Reason)
		}
	})
}

func TestTransitiveDependencyOutsideItsParentsRangeIsRefused(t *testing.T) {
	t.Run("npm parent range", func(t *testing.T) {
		h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "2.0.0", deps: map[string]string{"c": "^1.0.0"}}
		}))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
		if !strings.Contains(it.Detail, "a 1.0.0 asks for t") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("a parent range that cannot be judged", func(t *testing.T) {
		bad := baseNpm()
		bad["node_modules/a"] = npmEntry{ver: "1.0.0", deps: map[string]string{"t": "github:x/t"}}
		h := newNpmCase(t, npmRoot, bad, npmWith(func(m map[string]npmEntry) {
			m["node_modules/a"] = bad["node_modules/a"]
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
		}))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeNotEvaluable)
	})
	t.Run("fixture: mkdirp asks for minimist ^1.2.5", func(t *testing.T) {
		h := newHarness(t, "npm")
		forged := strings.NewReplacer(`"version": "1.2.8"`, `"version": "2.0.0"`, "minimist-1.2.8.tgz", "minimist-2.0.0.tgz", minimist128.Integrity, "sha512-two").Replace(string(h.after))
		h.npm.dists["minimist@2.0.0"] = NpmDist{Tarball: "https://registry.npmjs.org/minimist/-/minimist-2.0.0.tgz", Integrity: "sha512-two"}
		h.editLock(forged)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	})
}

func TestPnpmAndUvDirectDependenciesAreJudgedByTheManifest(t *testing.T) {
	t.Run("pnpm importer", func(t *testing.T) {
		files := map[string]string{
			"package.json": `{"name":"a","version":"1.0.0","dependencies":{"minimist":"^1.2.5"}}`,
			"pnpm-lock.yaml": `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      minimist:
        specifier: ^1.2.5
        version: 1.2.5

packages:

  minimist@1.2.5:
    resolution: {integrity: sha512-aaa}

snapshots:

  minimist@1.2.5: {}
`,
		}
		after := strings.NewReplacer("1.2.5\n", "2.0.0\n", "minimist@1.2.5", "minimist@2.0.0", "sha512-aaa", "sha512-bbb").Replace(files["pnpm-lock.yaml"])
		after = strings.Replace(after, "specifier: ^2.0.0", "specifier: ^1.2.5", 1)
		h := newHarness(t, "pnpm")
		h.files, h.after = files, []byte(after)
		h.item = itemFor(t, ManagerPnpm, files, minimistGroup())
		h.gh = ghFor(files)
		h.cfg.GitHub = h.gh
		h.npm.dists["minimist@2.0.0"] = NpmDist{Tarball: "https://registry.npmjs.org/minimist/-/minimist-2.0.0.tgz", Integrity: "sha512-bbb"}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	})
	t.Run("uv pyproject", func(t *testing.T) {
		h := newHarness(t, "uv")
		forged := strings.ReplaceAll(string(h.after), "1.26.17", "2.0.7")
		h.pypi.releases["urllib3==2.0.7"] = []PyPIFile{
			{Filename: "urllib3-2.0.7-py2.py3-none-any.whl", URL: "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-2.0.7-py2.py3-none-any.whl", Wheel: true, SHA256: urllibWheelSHA},
			{Filename: "urllib3-2.0.7.tar.gz", URL: "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-2.0.7.tar.gz", Sdist: true, SHA256: urllibSdistSHA},
		}
		h.editLock(forged)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	})
}

// --- a requirement may not lose its entry ---

func TestRequiredEntryDeletedWhileItsRequirerStaysIsRefused(t *testing.T) {
	h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
		// root -> a -> t -> c, with c's entry gone and t still requiring c.
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
		delete(m, "node_modules/c")
	}))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if !strings.Contains(it.Detail, "t requires c") {
		t.Errorf("detail = %q", it.Detail)
	}
}

func TestNewUnresolvedRequirementOfAnUnrelatedPackageIsRefused(t *testing.T) {
	h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
		m["node_modules/e"] = npmEntry{ver: "1.0.0", deps: map[string]string{"x": "^1.0.0"}}
	}))
	// e gains a requirement with no entry: new unresolved edge.
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
}

func TestPipReportThatDropsAnInstalledRequirementIsRefused(t *testing.T) {
	h := newHarness(t, "pip")
	useUnhashed(t, h)
	h.pypi.requires = map[string][]string{"urllib3==1.26.4": {"c"}, "urllib3==1.26.17": {"c"}}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			rep := pipReportItems(pipItem{name: "urllib3", ver: "1.26.4", requires: []string{"c"}}, pipItem{name: "c", ver: "1.0", notReq: true})
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: rep}}}
		}
		// urllib3 still requires c, and c is not installed.
		rep := pipReportItems(pipItem{name: "urllib3", ver: "1.26.17", requires: []string{"c"}})
		return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: rep}}}
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
}

func TestUnresolvedRequirementsOfTheOriginalAreTolerated(t *testing.T) {
	// An optional requirement the original file could not resolve either is
	// not new.
	before := baseNpm()
	before["node_modules/e"] = npmEntry{ver: "1.0.0", deps: map[string]string{"optional-missing": "^1.0.0"}}
	h := newNpmCase(t, npmRoot, before, npmWith(func(m map[string]npmEntry) {
		m["node_modules/e"] = before["node_modules/e"]
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
	}))
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}

// --- an edge added by the output does not make an entry changeable ---

func TestEdgeFromTheUpdatedPackageToAnUnrelatedPackageDoesNotLetItChange(t *testing.T) {
	// e is required by the root, not through t. The output adds t -> e and
	// changes e.
	h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0", "e": "^1.0.0"}}
		m["node_modules/e"] = npmEntry{ver: "1.0.9"}
	}))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if !strings.Contains(it.Detail, "node_modules/e") {
		t.Errorf("detail = %q", it.Detail)
	}
}

func TestEdgeFromTheUpdatedPackageToItsAncestorDoesNotLetItChange(t *testing.T) {
	// a requires t; the output makes t require a and changes a.
	h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0", "a": "^1.0.0"}}
		m["node_modules/a"] = npmEntry{ver: "1.0.7", deps: map[string]string{"t": "^1.0.0"}}
	}))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
}

func TestAncestorOfTheUpdatedPackageMustNotChange(t *testing.T) {
	h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
		m["node_modules/a"] = npmEntry{ver: "1.0.1", deps: map[string]string{"t": "^1.0.0"}}
	}))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
}

func TestEntryBelowOnlyTheUpdatedPackageMayChange(t *testing.T) {
	h := newNpmCase(t, npmRoot, baseNpm(), npmWith(func(m map[string]npmEntry) {
		m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
		m["node_modules/c"] = npmEntry{ver: "1.0.3"}
	}))
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}

// --- the job's overall status must agree with its steps ---

func TestCompletedStatusWithAFailedStepIsRefused(t *testing.T) {
	cases := map[string]func(r *worker.Result){
		"non-zero exit code": func(r *worker.Result) { r.Steps[1].ExitCode = 1 },
		"timed out":          func(r *worker.Result) { r.Steps[1].TimedOut = true },
		"step error":         func(r *worker.Result) { r.Steps[0].Error = "signal: killed" },
		"unexpected files": func(r *worker.Result) {
			r.Steps[1].Reason, r.Steps[1].UnexpectedPaths, r.Steps[1].UnexpectedCount = worker.ReasonUnexpectedFiles, []string{"x"}, 1
		},
		"release age":             func(r *worker.Result) { r.Steps[0].Reason = worker.ReasonReleaseAgeViolation },
		"job error":               func(r *worker.Result) { r.Error = "something failed" },
		"a step lacks its files":  func(r *worker.Result) { r.Steps[1].Outputs = r.Steps[1].Outputs[:1] },
		"no final files":          func(r *worker.Result) { r.Final = nil },
		"final lacks the lock":    func(r *worker.Result) { r.Final = r.Final[:1] },
		"a step is missing":       func(r *worker.Result) { r.Steps = r.Steps[:1] },
		"a step is repeated":      func(r *worker.Result) { r.Steps = append(r.Steps, r.Steps[1]) },
		"steps in another order":  func(r *worker.Result) { r.Steps[0], r.Steps[1] = r.Steps[1], r.Steps[0] },
		"another op":              func(r *worker.Result) { r.Steps[1].Op = worker.OpPnpmFrozen },
		"another id":              func(r *worker.Result) { r.Steps[1].ID = "other" },
		"another scratch flag":    func(r *worker.Result) { r.Steps[0].Scratch = false },
		"a failed step has files": func(r *worker.Result) { r.Status = worker.StatusStepFailed; r.Steps[1].ExitCode = 1 },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "npm")
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				o := h.okScript(n, job, src)
				o.mangleResult = mangle
				return o
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
			if len(it.Artifacts) != 0 {
				t.Error("artifacts kept")
			}
		})
	}
}

func TestStatusesThatContradictTheirStepsAreRefused(t *testing.T) {
	cases := map[string]func(r *worker.Result){
		"step_failed with every step clean": func(r *worker.Result) { r.Status = worker.StatusStepFailed },
		"timed_out with no step timed out":  func(r *worker.Result) { r.Status = worker.StatusTimedOut },
		"step_failed where the last step timed out": func(r *worker.Result) {
			r.Status = worker.StatusStepFailed
			r.Steps[1].TimedOut, r.Steps[1].ExitCode, r.Steps[1].Outputs = true, -1, nil
			r.Final = nil
		},
		"input_rejected with steps": func(r *worker.Result) { r.Status = worker.StatusInputRejected; r.Final = nil },
		"failure with final files": func(r *worker.Result) {
			r.Status = worker.StatusStepFailed
			r.Steps[1].ExitCode, r.Steps[1].Outputs = 1, nil
		},
		"an earlier step failed but the last ran": func(r *worker.Result) {
			r.Status = worker.StatusStepFailed
			r.Steps[0].ExitCode, r.Steps[0].Outputs = 1, nil
			r.Final = nil
		},
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "npm")
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				o := h.okScript(n, job, src)
				o.mangleResult = mangle
				return o
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
		})
	}
}

// --- pip's report is checked against the file and the index ---

func TestPipReportDistributionsAreCheckedAgainstTheFileAndTheIndex(t *testing.T) {
	wheel := fakeWheelURL("urllib3", "1.26.17")
	cases := []struct {
		name  string
		edit  func(string) string
		setup func(*harness)
		cat   Category
		why   Reason
	}{
		{"a source distribution", func(r string) string {
			return strings.Replace(r, wheel, "https://files.pythonhosted.org/packages/x/urllib3-1.26.17.tar.gz", 1)
		}, nil, CategoryManual, ReasonDistributionMismatch},
		{"a yanked file", func(r string) string { return strings.Replace(r, `"is_yanked":false`, `"is_yanked":true`, 1) }, nil, CategoryManual, ReasonDistributionMismatch},
		{"another host", func(r string) string {
			return strings.Replace(r, "files.pythonhosted.org", "files.pythonhosted.org.evil.example", 1)
		}, nil, CategoryManual, ReasonDistributionMismatch},
		{"a hash the file does not give", func(r string) string { return strings.Replace(r, urllibWheelSHA, h64('c'), 1) }, nil, CategoryManual, ReasonDistributionMismatch},
		{"no hash", func(r string) string { return strings.Replace(r, urllibWheelSHA, "", 1) }, nil, CategoryManual, ReasonDistributionMismatch},
		{"a version the file does not pin", func(r string) string { return strings.ReplaceAll(r, "1.26.17", "1.26.18") }, nil, CategoryManual, ReasonDistributionMismatch},
		{"a wheel for another interpreter", func(r string) string {
			return strings.Replace(r, "py3-none-any", "cp311-cp311-manylinux_2_17_x86_64", 1)
		}, nil, CategoryManual, ReasonDistributionMismatch},
		{"a wheel for another platform", func(r string) string { return strings.Replace(r, "py3-none-any", "cp312-cp312-win_amd64", 1) }, nil, CategoryManual, ReasonDistributionMismatch},
		{"a file the index does not publish", func(r string) string { return strings.Replace(r, "/packages/x/", "/packages/y/", 1) }, nil, CategoryManual, ReasonDistributionMismatch},
		{"a release the index does not know", func(r string) string { return r }, func(h *harness) { h.pypi.missing = map[string]bool{"urllib3==1.26.17": true, "urllib3==1.26.4": true} }, CategoryManual, ReasonNoWheelForVersion},
		{"a file the index lists as yanked", func(r string) string { return r }, func(h *harness) {
			h.pypi.releases["urllib3==1.26.17"][0].Yanked = true
		}, CategoryManual, ReasonReleaseYanked},
		{"an index that cannot be asked", func(r string) string { return r }, func(h *harness) {
			h.pypi.releases["urllib3==1.26.17"] = h.pypi.releases["urllib3==1.26.17"][:1]
			h.pypi.err = errors.New("timeout")
		}, CategoryFailed, ReasonDistributionLookup},
	}
	for _, c := range cases {
		for _, hashed := range []bool{true, false} {
			if !hashed && (strings.Contains(c.name, "hash the file") || c.why == ReasonNoWheelForVersion || c.why == ReasonReleaseYanked) {
				continue // those concern the hashes or the rewrite, which an unhashed file has none of
			}
			t.Run(fmt.Sprintf("%s/hashed=%v", c.name, hashed), func(t *testing.T) {
				h := newHarness(t, "pip")
				if !hashed {
					useUnhashed(t, h)
				}
				if c.setup != nil {
					c.setup(h)
				}
				h.checkReport(c.edit)
				it, _ := h.run()
				wantCategory(t, it, c.cat, c.why)
			})
		}
	}
}

func TestPipBaselineReportIsCheckedToo(t *testing.T) {
	h := newHarness(t, "pip")
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		o := h.okScript(n, job, src)
		if n == 0 {
			rep := strings.Replace(string(pipReportJSON(h.fx.beforePkgs...)), fakeWheelSHA("urllib3", "1.26.4"), h64('d'), 1)
			o.edit = map[string]map[string][]byte{stepBaseline: {worker.PipReportName: []byte(rep)}}
		}
		return o
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}

func TestPipReportSizeIsBounded(t *testing.T) {
	h := newHarness(t, "pip")
	useUnhashed(t, h)
	var items []pipItem
	items = append(items, pipItem{name: "urllib3", ver: "1.26.17"})
	for i := 0; i < maxRegistryChecks+1; i++ {
		items = append(items, pipItem{name: fmt.Sprintf("p%d", i), ver: "1.0", notReq: true})
	}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			return h.okScript(n, job, src)
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: pipReportItems(items...)}}}
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryDeferred, ReasonRegistryCheckLimit)
}

func TestWheelFitsTarget(t *testing.T) {
	tg := &worker.Target{PythonVersion: "3.12", Implementation: "cp", ABIs: []string{"cp312"},
		Platforms: []string{"manylinux_2_36_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64", "manylinux_2_5_x86_64"}}
	cases := map[string]bool{
		"urllib3-1.26.17-py2.py3-none-any.whl":                             true,
		"x-1.0-py3-none-any.whl":                                           true,
		"x-1.0-py312-none-any.whl":                                         true,
		"x-1.0-py311-none-any.whl":                                         false,
		"x-1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": true,
		"x-1.0-cp312-cp312-manylinux1_x86_64.whl":                          true,
		"x-1.0-cp312-cp312-manylinux2010_x86_64.whl":                       true,
		"x-1.0-cp311-cp311-manylinux_2_17_x86_64.whl":                      false,
		"x-1.0-cp39-abi3-manylinux_2_17_x86_64.whl":                        true,
		"x-1.0-cp313-abi3-manylinux_2_17_x86_64.whl":                       false,
		"x-1.0-cp312-cp312-musllinux_1_2_x86_64.whl":                       false,
		"x-1.0-cp312-cp312-manylinux_2_17_aarch64.whl":                     false,
		"x-1.0-cp312-cp312-win_amd64.whl":                                  false,
		"x-1.0-1-cp312-cp312-manylinux_2_17_x86_64.whl":                    true,
		"x-1.0.tar.gz":    false,
		"x-1.0-cp312.whl": false,
		"x-1.0-cp312-none-manylinux_2_28_x86_64.whl": false,
		"x-1.0-cp312-none-any.whl":                   true,
	}
	for name, want := range cases {
		if got := wheelFitsTarget(name, tg); got != want {
			t.Errorf("wheelFitsTarget(%q) = %v, want %v", name, got, want)
		}
	}
}

// --- graphs are bounded ---

func lowerGraphLimits(t *testing.T, nodes, edges int) {
	t.Helper()
	n, e := maxGraphNodes, maxGraphEdges
	maxGraphNodes, maxGraphEdges = nodes, edges
	t.Cleanup(func() { maxGraphNodes, maxGraphEdges = n, e })
}

func uvLockWithPackages(n int, deps func(i int) string) string {
	var b strings.Builder
	b.WriteString("version = 1\nrevision = 5\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"root\"\nversion = \"1.0.0\"\nsource = { virtual = \".\" }\ndependencies = [\n    { name = \"p0\" },\n]\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\n[[package]]\nname = \"p%d\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n", i)
		b.WriteString(deps(i))
	}
	return b.String()
}

func TestUvAmbiguousReferenceIsNotFannedOut(t *testing.T) {
	lock := uvLockWithPackages(2, func(i int) string { return "" })
	lock += "\n[[package]]\nname = \"p0\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	if _, err := uvGraph(bg, []byte(lock)); err == nil || !strings.Contains(err.Error(), "without a version") {
		t.Fatalf("err = %v", err)
	}
	// With a version the reference is exact.
	ok := strings.Replace(lock, "    { name = \"p0\" },", "    { name = \"p0\", version = \"1.0.0\" },", 1)
	if g, err := uvGraph(bg, []byte(ok)); err != nil || g.roots[0].key != "p0==1.0.0" {
		t.Fatalf("%v %+v", err, g)
	}
}

func TestGraphSizeIsBoundedBeforeItIsBuilt(t *testing.T) {
	lowerGraphLimits(t, 50, 200)
	t.Run("uv nodes", func(t *testing.T) {
		if _, err := uvGraph(bg, []byte(uvLockWithPackages(60, func(int) string { return "" }))); err == nil || !strings.Contains(err.Error(), "more than 50 entries") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("uv edges", func(t *testing.T) {
		many := func(int) string {
			var b strings.Builder
			b.WriteString("dependencies = [\n")
			for j := 0; j < 10; j++ {
				b.WriteString("    { name = \"p0\" },\n")
			}
			b.WriteString("]\n")
			return b.String()
		}
		if _, err := uvGraph(bg, []byte(uvLockWithPackages(30, many))); err == nil || !strings.Contains(err.Error(), "dependency edges") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("npm nodes", func(t *testing.T) {
		pk := map[string]npmEntry{}
		for i := 0; i < 60; i++ {
			pk[fmt.Sprintf("node_modules/p%d", i)] = npmEntry{ver: "1.0.0"}
		}
		if _, err := npmGraph(bg, npmLock(map[string]string{}, pk)); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("npm edges", func(t *testing.T) {
		deps := map[string]string{}
		for i := 0; i < 250; i++ {
			deps[fmt.Sprintf("d%d", i)] = "^1"
		}
		if _, err := npmGraph(bg, npmLock(map[string]string{}, map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: deps}})); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("pnpm nodes", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages:\n")
		for i := 0; i < 60; i++ {
			fmt.Fprintf(&b, "  p%d@1.0.0:\n    resolution: {integrity: sha512-x}\n", i)
		}
		b.WriteString("snapshots:\n")
		if _, err := pnpmGraph(bg, []byte(b.String())); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("pip report", func(t *testing.T) {
		var items []pipItem
		for i := 0; i < 60; i++ {
			items = append(items, pipItem{name: fmt.Sprintf("p%d", i), ver: "1.0"})
		}
		if _, err := pipGraph(bg, pipReportItems(items...), nil, nil); err == nil {
			t.Error("accepted")
		}
	})
}

func TestGraphBuildWatchesTheDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := map[string]string{}
	for i := 0; i < 1000; i++ {
		deps[fmt.Sprintf("d%d", i)] = "^1"
	}
	lock := npmLock(map[string]string{}, map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: deps}})
	if _, err := npmGraph(ctx, lock); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	// The diff watches it as well.
	g, _ := npmGraph(bg, lock)
	if _, reason, _ := diffGraphs(ctx, g, g, map[string]bool{"a": true}); reason == "" {
		t.Error("a diff ran on after the deadline")
	}
}

func TestUvAmbiguousOutputIsRefused(t *testing.T) {
	h := newHarness(t, "uv")
	// The output adds two versions of a package and a reference to it
	// without a version.
	forged := string(h.after) +
		"\n[[package]]\nname = \"six\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n" +
		"\n[[package]]\nname = \"six\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n" +
		"\n[[package]]\nname = \"user\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"six\" },\n]\n"
	h.editLock(forged)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
}

// --- the limits of a job are deferrals ---

func TestLimitsOfAJobDefer(t *testing.T) {
	t.Run("too many packages", func(t *testing.T) {
		h := newHarness(t, "npm")
		for i := 0; i < worker.MaxPackages+1; i++ {
			h.item.Packages = append(h.item.Packages, LanguagePackage{
				Name: fmt.Sprintf("p%d", i), Ecosystem: typeNodePkg, Installed: "1.0.0", SelectionLowerBound: "1.0.1", Action: ActionUpdate,
				Occurrences: []SourceOccurrence{{Path: fmt.Sprintf("node_modules/p%d", i), Version: "1.0.0", Matched: true}},
			})
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdatePackageLimit)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
		if it.Packages[0].Action != ActionUpdate {
			t.Error("a deferred item's packages changed")
		}
	})
	t.Run("input too large", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.gh.files["package-lock.json"] = make([]byte, worker.MaxInputFileBytes+1)
		for i := range h.item.Source.Files {
			if h.item.Source.Files[i].Path == "package-lock.json" {
				h.item.Source.Files[i].BlobSHA = gitBlobSHA(h.gh.files["package-lock.json"])
			}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
	})
}

func TestClientsAlwaysHaveATimeout(t *testing.T) {
	if hc := boundedClient(nil); hc.Timeout <= 0 {
		t.Error("nil")
	}
	custom := boundedClient(&scannerlessClient)
	if custom.Timeout <= 0 {
		t.Error("a client without a timeout was used as it was")
	}
	if scannerlessClient.Timeout != 0 {
		t.Error("the caller's client was changed")
	}
}

var scannerlessClient = http.Client{}
