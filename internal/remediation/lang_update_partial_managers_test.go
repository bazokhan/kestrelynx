package remediation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// partialProject describes the project of the partial update tests for one
// manager: a package that can be taken to its target (fast) and a package a
// direct requirement or its holder keeps below it (slow). lock makes the
// lockfile with the packages at the given versions; direct is the version the
// manifest asks for slow, "" when it does not ask for it.
type partialProject struct {
	name                   string
	mgr                    DependencyManager
	lockName, manifestName string
	typ, ecosystem         string
	fast, slow             string
	fastFrom, fastTo       string
	slowFrom, slowMid      string
	slowTo                 string
	manifest               func(direct string) string
	lock                   func(fastVer, slowVer, direct string) string
	// edited is what the manifest holds once the specifier of slow was edited.
	edited string
	listed *regexp.Regexp
}

func (p partialProject) groups(packages []string) []*findingGroup {
	var out []*findingGroup
	for _, n := range packages {
		switch n {
		case p.fast:
			out = append(out, group(p.ecosystem, p.fast, p.fastFrom, p.origin(p.fast, p.fastFrom), CVERef{VulnID: "CVE-A", FixedVers: []string{p.fastTo}}))
		case p.slow:
			out = append(out, group(p.ecosystem, p.slow, p.slowFrom, p.origin(p.slow, p.slowFrom), CVERef{VulnID: "CVE-B", FixedVers: []string{p.slowTo}}))
		}
	}
	return out
}

func (p partialProject) origin(name, ver string) FindingOrigin {
	if p.ecosystem == typePythonPkg {
		return FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "Python",
			PkgPath: "usr/local/lib/python3.12/site-packages/" + name + "-" + ver + ".dist-info/METADATA"}
	}
	return FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/" + name + "/package.json"}
}

// scan is the filesystem scan of the lockfile it is given: its packages, and
// the vulnerability of each of the two at the version the original has.
func (p partialProject) scan(in map[string][]byte) scanner.FSScan {
	var pkgs [][2]string
	var vulns [][3]string
	for _, m := range p.listed.FindAllStringSubmatch(string(in[p.lockName]), -1) {
		pkgs = append(pkgs, [2]string{m[1], m[2]})
		switch {
		case m[1] == p.fast && m[2] == p.fastFrom:
			vulns = append(vulns, [3]string{m[1], m[2], "CVE-A"})
		case m[1] == p.slow && m[2] == p.slowFrom:
			vulns = append(vulns, [3]string{m[1], m[2], "CVE-B"})
		}
	}
	return fsReport(p.typ, pkgs, vulns)
}

func npmPartialProject() partialProject {
	return partialProject{
		name: "npm", mgr: ManagerNpm, lockName: "package-lock.json", manifestName: "package.json", typ: "npm", ecosystem: typeNodePkg,
		fast: "minimist", slow: "pinned", fastFrom: "1.2.5", fastTo: "1.2.8", slowFrom: "2.0.0", slowMid: "2.0.1", slowTo: "2.0.2",
		edited: `"pinned": "2.0.2"`,
		listed: regexp.MustCompile(`"node_modules/([^"]+)": \{\s*"version": "([^"]+)"`),
		manifest: func(direct string) string {
			extra := ""
			if direct != "" {
				extra = fmt.Sprintf(",\n    \"pinned\": %q", direct)
			}
			return "{\n  \"name\": \"fixture-npm\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"holder\": \"1.0.0\",\n    \"mkdirp\": \"0.5.5\"" + extra + "\n  }\n}\n"
		},
		lock: func(fastVer, slowVer, direct string) string {
			fastInt := "sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw=="
			if fastVer == "1.2.8" {
				fastInt = minimist128.Integrity
			} else if fastVer != "1.2.5" {
				fastInt = partialIntegrity("minimist", fastVer)
			}
			extra := ""
			if direct != "" {
				extra = fmt.Sprintf(",\n        \"pinned\": %q", direct)
			}
			return fmt.Sprintf(`{
  "name": "fixture-npm",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "fixture-npm",
      "version": "1.0.0",
      "dependencies": {
        "holder": "1.0.0",
        "mkdirp": "0.5.5"%s
      }
    },
    "node_modules/holder": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/holder/-/holder-1.0.0.tgz",
      "integrity": %q,
      "dependencies": {
        "pinned": "^2.0.0"
      }
    },
    "node_modules/minimist": {
      "version": %q,
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-%s.tgz",
      "integrity": %q,
      "license": "MIT"
    },
    "node_modules/mkdirp": {
      "version": "0.5.5",
      "resolved": "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.5.tgz",
      "integrity": "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==",
      "license": "MIT",
      "dependencies": {
        "minimist": "^1.2.5"
      },
      "bin": {
        "mkdirp": "bin/cmd.js"
      }
    },
    "node_modules/pinned": {
      "version": %q,
      "resolved": "https://registry.npmjs.org/pinned/-/pinned-%s.tgz",
      "integrity": %q
    }
  }
}
`, extra, partialIntegrity("holder", "1.0.0"), fastVer, fastVer, fastInt, slowVer, slowVer, partialIntegrity("pinned", slowVer))
		},
	}
}

func pnpmPartialProject() partialProject {
	return partialProject{
		name: "pnpm", mgr: ManagerPnpm, lockName: "pnpm-lock.yaml", manifestName: "package.json", typ: "pnpm", ecosystem: typeNodePkg,
		fast: "minimist", slow: "pinned", fastFrom: "1.2.5", fastTo: "1.2.8", slowFrom: "2.0.0", slowMid: "2.0.1", slowTo: "2.0.2",
		edited:   `"pinned": "2.0.2"`,
		listed:   regexp.MustCompile(`(?m)^  ([a-z0-9-]+)@([0-9.]+):\n    resolution`),
		manifest: partialPackageJSON,
		lock:     func(fastVer, slowVer, direct string) string { return partialLock(fastVer, slowVer, direct) },
	}
}

func uvPartialProject() partialProject {
	wheel := func(name, ver string) string {
		return fmt.Sprintf("wheels = [\n    { url = %q, hash = \"sha256:%s\" },\n]\n", fakeWheelURL(name, ver), fakeWheelSHA(name, ver))
	}
	return partialProject{
		name: "uv", mgr: ManagerUv, lockName: "uv.lock", manifestName: "pyproject.toml", typ: "uv", ecosystem: typePythonPkg,
		fast: "urllib3", slow: "pinned", fastFrom: "1.26.4", fastTo: "1.26.17", slowFrom: "2.0.0", slowMid: "2.0.1", slowTo: "2.0.2",
		edited: `pinned==2.0.2`,
		listed: regexp.MustCompile(`\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"`),
		manifest: func(direct string) string {
			extra := ""
			if direct != "" {
				extra = fmt.Sprintf(", \"pinned==%s\"", direct)
			}
			return "[project]\nname = \"fixture-uv\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"urllib3>=1.26,<2\", \"holder==1.0.0\"" + extra + "]\n\n[tool.uv]\npackage = false\n"
		},
		lock: func(fastVer, slowVer, direct string) string {
			dep, meta := "", ""
			if direct != "" {
				dep = "    { name = \"pinned\" },\n"
				meta = fmt.Sprintf("    { name = \"pinned\", specifier = \"==%s\" },\n", direct)
			}
			fast := `sdist = { url = "https://files.pythonhosted.org/packages/cb/cf/871177f1fc795c6c10787bc0e1f27bb6cf7b81dbde399fd35860472cecbc/urllib3-1.26.4.tar.gz", hash = "sha256:e7b021f7241115872f92f43c6508082facffbd1c048e3c6e2bb9c2a157e28937", size = 293008, upload-time = "2021-03-15T15:04:37.697Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/09/c6/d3e3abe5b4f4f16cf0dfc9240ab7ce10c2baa0e268989a4e3ec19e90c84e/urllib3-1.26.4-py2.py3-none-any.whl", hash = "sha256:2f4da4594db7e1e110a944bb1b551fdf4e6c136ad42e4234131391e21eb5b0df", size = 153320, upload-time = "2021-03-15T15:04:35.709Z" },
]
`
			if fastVer == "1.26.17" {
				fast = `sdist = { url = "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-1.26.17.tar.gz", hash = "sha256:24d6a242c28d29af46c3fae832c36db3bbebcc533dd1bb549172cd739c82df21", size = 305031, upload-time = "2023-10-02T17:22:30.961Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-1.26.17-py2.py3-none-any.whl", hash = "sha256:94a757d178c9be92ef5539b8840d48dc9cf1b2709c9d6b588232a055c524458b", size = 143431, upload-time = "2023-10-02T17:22:28.101Z" },
]
`
			}
			return fmt.Sprintf(`version = 1
revision = 5
requires-python = ">=3.9"

[[package]]
name = "fixture-uv"
version = "1.0.0"
source = { virtual = "." }
dependencies = [
    { name = "holder" },
%s    { name = "urllib3" },
]

[package.metadata]
requires-dist = [
    { name = "holder", specifier = "==1.0.0" },
%s    { name = "urllib3", specifier = ">=1.26,<2" },
]

[[package]]
name = "holder"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pinned" },
]
%s
[[package]]
name = "pinned"
version = %q
source = { registry = "https://pypi.org/simple" }
%s
[[package]]
name = "urllib3"
version = %q
source = { registry = "https://pypi.org/simple" }
%s`, dep, meta, wheel("holder", "1.0.0"), slowVer, wheel("pinned", slowVer), fastVer, fast)
		},
	}
}

func (p partialProject) filesFor(direct string) map[string]string {
	return map[string]string{p.manifestName: p.manifest(direct), p.lockName: p.lock(p.fastFrom, p.slowFrom, direct)}
}

// newHarness is a harness over the project: the work container returns the
// lockfile that lockFor gives for the job and the scans list the packages of
// the lockfile they are given.
func (p partialProject) newHarness(t *testing.T, direct string, lockFor func(job worker.Job, src map[string][]byte) string) *harness {
	t.Helper()
	files := p.filesFor(direct)
	h := &harness{t: t, fx: fixtureFor(p.name), files: files}
	h.item = itemFor(t, p.mgr, files, p.groups([]string{p.fast, p.slow})...)
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the project is not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	h.npm = &fakeNpm{dists: map[string]NpmDist{
		"minimist@1.2.8": minimist128,
		"mkdirp@0.5.5": {Tarball: "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.5.tgz", Dependencies: map[string]string{"minimist": "^1.2.5"},
			Integrity: "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ=="},
	}}
	h.pypi = &fakePyPI{auto: true, releases: map[string][]PyPIFile{
		"urllib3==1.26.17": {
			fakeWheel("urllib3", "1.26.17"),
			{Filename: "urllib3-1.26.17-py2.py3-none-any.whl", URL: "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-1.26.17-py2.py3-none-any.whl", Wheel: true, SHA256: urllibWheelSHA},
			{Filename: "urllib3-1.26.17.tar.gz", URL: "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-1.26.17.tar.gz", Sdist: true, SHA256: urllibSdistSHA},
		},
	}}
	h.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {p.lockName: []byte(lockFor(job, src))}}}
	}}
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) { return p.scan(in), nil }}
	h.cfg = LangUpdateConfig{
		Scanner: h.fs, Work: h.work, PyPI: h.pypi, Npm: h.npm, GitHub: h.gh,
		Prepared: fsConds, Images: map[string]ImageEnv{"img": debianAmd64}, MaxJobs: 5,
	}
	h.cfg = withTestTools(h.t, h.cfg)
	return h
}

func partialProjects() []partialProject {
	return []partialProject{npmPartialProject(), pnpmPartialProject(), uvPartialProject()}
}

// namesSlow reports whether the job's update names the slow package.
func (p partialProject) namesSlow(job worker.Job) bool { return hasName(namesInUpdate(job), p.slow) }

func TestLangUpdatePartialEveryManagerUsesTheResultAsItIs(t *testing.T) {
	for _, p := range partialProjects() {
		t.Run(p.name, func(t *testing.T) {
			h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowFrom, "") })
			before := LanguageInputFingerprint(h.item)
			it, use := h.run()
			wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
			if use.Jobs != 1 || h.work.calls != 1 {
				t.Errorf("jobs = %d, containers = %d, want 1 and 1", use.Jobs, h.work.calls)
			}
			fast, slow := packageOf(t, it, p.fast), packageOf(t, it, p.slow)
			if fast.Action != ActionUpdate || fast.AdoptedVersion != p.fastTo || fast.LeftOut {
				t.Errorf("%s = %+v", p.fast, fast)
			}
			if slow.Action != ActionManual || slow.Reason != ReasonTargetNotUpdated || !slow.LeftOut || slow.AdoptedVersion != "" {
				t.Errorf("%s = %+v", p.slow, slow)
			}
			if after := LanguageInputFingerprint(it); after != before {
				t.Errorf("fingerprint changed from %s to %s", before, after)
			}
			u := buildLanguageUnit(&it, 0)
			if u.manual {
				t.Fatalf("unit is manual: %s %s", u.manualReason, u.manualDetail)
			}
			rec := u.lang.record
			if len(rec.Packages) != 1 || rec.Packages[0].Name != p.fast || len(rec.Remaining) != 1 || rec.Remaining[0].Name != p.slow {
				t.Errorf("record = %+v", rec)
			}
		})
	}
}

func TestLangUpdatePartialEveryManagerRunsAgainWithoutTheManifestEditOfAPackageLeftOut(t *testing.T) {
	for _, p := range partialProjects() {
		t.Run(p.name, func(t *testing.T) {
			// The manifest asks for the slow package at a version below its target,
			// so the specifier is edited for the first run, which does not take the
			// package there. The edit is not kept for a package that is left out.
			h := p.newHarness(t, p.slowFrom, func(job worker.Job, src map[string][]byte) string {
				if strings.Contains(string(src[p.manifestName]), p.edited) {
					return p.lock(p.fastTo, p.slowFrom, p.slowTo)
				}
				return p.lock(p.fastTo, p.slowFrom, p.slowFrom)
			})
			it, use := h.run()
			wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
			if use.Jobs != 1 {
				t.Errorf("jobs = %d", use.Jobs)
			}
			if !packageOf(t, it, p.slow).LeftOut || packageOf(t, it, p.fast).Action != ActionUpdate {
				t.Errorf("packages = %+v", it.Packages)
			}
			if len(it.Update.ManifestEdits) != 0 {
				t.Errorf("manifest edits = %+v, want none", it.Update.ManifestEdits)
			}
			if h.work.calls < 2 {
				t.Fatalf("containers = %d, want the edited run and the run without the edit", h.work.calls)
			}
			edited := func(n int) bool { return strings.Contains(string(h.work.srcs[n][p.manifestName]), p.edited) }
			sawEdit := false
			for n := 0; n < h.work.calls-1; n++ {
				sawEdit = sawEdit || edited(n)
			}
			if !sawEdit || edited(h.work.calls-1) {
				t.Errorf("an earlier run had the edited manifest %v, the last run %v", sawEdit, edited(h.work.calls-1))
			}
			for _, a := range it.Artifacts {
				if a.Path == p.manifestName {
					t.Errorf("artifacts = %+v, want the lockfile only", it.Artifacts)
				}
			}
		})
	}
}

func TestLangUpdatePartialEveryManagerFailsAsAWholeWhenTheResultWithoutAPackageIsRefused(t *testing.T) {
	for _, p := range partialProjects() {
		t.Run(p.name, func(t *testing.T) {
			// Both runs move the slow package to a version below its target; the
			// second run did not name it, so the move has no explanation.
			h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowMid, "") })
			it, use := h.run()
			wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
			if use.Jobs != 1 || h.work.calls != 2 {
				t.Errorf("jobs = %d, containers = %d, want 1 and 2", use.Jobs, h.work.calls)
			}
			// The reason the package was left out stays in the detail.
			if !strings.Contains(it.Detail, "after leaving out "+p.slow) || !strings.Contains(it.Detail, "below the target "+p.slowTo) {
				t.Errorf("detail = %q", it.Detail)
			}
			if slow := packageOf(t, it, p.slow); slow.Reason != ReasonTargetNotUpdated || slow.LeftOut || slow.Action != ActionManual {
				t.Errorf("%s = %+v", p.slow, slow)
			}
			if fast := packageOf(t, it, p.fast); fast.Action != ActionManual || fast.Reason == ReasonUpdateVerified || fast.AdoptedVersion != "" {
				t.Errorf("%s = %+v", p.fast, fast)
			}
			if len(it.Artifacts) != 0 {
				t.Errorf("artifacts = %+v", it.Artifacts)
			}
		})
	}
}

func TestLangUpdatePartialEveryManagerKeepsATransientFailureOfTheSecondRunRetryable(t *testing.T) {
	for _, p := range partialProjects() {
		t.Run(p.name, func(t *testing.T) {
			// The first run moves the slow package to a version still below its
			// target, so the update is run again; the container fails in that
			// second run. That says nothing about the result, so the item is not
			// made manual: it is failed and is tried again in the next cycle.
			h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowMid, "") })
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				if !p.namesSlow(job) {
					return fakeOutcome{err: errors.New("the container could not be started")}
				}
				return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {p.lockName: []byte(p.lock(p.fastTo, p.slowMid, ""))}}}
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryFailed, ReasonUpdateJobFailed)
			if h.work.calls != 2 {
				t.Errorf("containers = %d, want 2", h.work.calls)
			}
			if !strings.Contains(it.Detail, "after leaving out "+p.slow) {
				t.Errorf("detail = %q", it.Detail)
			}
			if len(it.Artifacts) != 0 {
				t.Errorf("artifacts = %+v", it.Artifacts)
			}
		})
	}
}

func TestLangUpdatePartialEveryManagerRefusesAContradictoryResultOfTheSecondRun(t *testing.T) {
	// A result of the second run that contradicts itself (a declared output with
	// the wrong hash, or output that is not a result at all) is a problem of the
	// result: the item is manual and keeps why the package was left out. The same
	// result in the first run stays a failed run.
	cases := map[string]func(*fakeOutcome){
		"hash": func(o *fakeOutcome) {
			o.mangleResult = func(r *worker.Result) {
				for i := range r.Final {
					r.Final[i].SHA256 = strings.Repeat("0", 64)
				}
			}
		},
		"garbage": func(o *fakeOutcome) { o.raw = []byte("hello\n") },
	}
	for _, p := range partialProjects() {
		for name, spoil := range cases {
			t.Run(p.name+"/"+name, func(t *testing.T) {
				h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowMid, "") })
				h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
					o := fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {p.lockName: []byte(p.lock(p.fastTo, p.slowMid, ""))}}}
					if !p.namesSlow(job) {
						spoil(&o)
					}
					return o
				}
				it, _ := h.run()
				wantCategory(t, it, CategoryManual, ReasonUpdateResultInvalid)
				if !strings.Contains(it.Detail, "after leaving out "+p.slow) || !strings.Contains(it.Detail, "below the target "+p.slowTo) {
					t.Errorf("detail = %q", it.Detail)
				}
				if len(it.Artifacts) != 0 || packageOf(t, it, p.fast).Action != ActionManual {
					t.Errorf("artifacts = %+v, packages = %+v", it.Artifacts, it.Packages)
				}
			})
		}
	}
}

func TestLangUpdatePartialEveryManagerKeepsThePlanWhenTheSecondRunRunsOutOfTime(t *testing.T) {
	for _, p := range partialProjects() {
		t.Run(p.name, func(t *testing.T) {
			h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowMid, "") })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				if !p.namesSlow(job) {
					cancel() // the cycle's time is over while the second run is made
					return fakeOutcome{err: context.Canceled}
				}
				return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {p.lockName: []byte(p.lock(p.fastTo, p.slowMid, ""))}}}
			}
			planned := h.item
			it, _ := h.runCtx(ctx)
			wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
			if !strings.Contains(it.Detail, "after leaving out "+p.slow) || !strings.Contains(it.Detail, "below the target "+p.slowTo) {
				t.Errorf("detail = %q", it.Detail)
			}
			// The packages are as the plan had them.
			for i, want := range planned.Packages {
				got := it.Packages[i]
				if got.Action != want.Action || got.Reason != want.Reason || got.LeftOut || got.AdoptedVersion != "" || got.SelectionLowerBound != want.SelectionLowerBound || got.Installed != want.Installed {
					t.Errorf("%s = %+v, planned %+v", got.Name, got, want)
				}
			}
			if len(it.Artifacts) != 0 {
				t.Errorf("artifacts = %+v", it.Artifacts)
			}
			// What the first run found stays on the record.
			if it.Update == nil || len(it.Update.Steps) == 0 {
				t.Fatalf("update = %+v", it.Update)
			}
			noted := false
			for _, n := range it.Update.Notes {
				noted = noted || strings.Contains(n, "run again without it")
			}
			if !noted {
				t.Errorf("notes = %v", it.Update.Notes)
			}
		})
	}
}
