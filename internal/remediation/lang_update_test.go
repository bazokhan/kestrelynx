package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

const (
	urllibWheelSHA = "94a757d178c9be92ef5539b8840d48dc9cf1b2709c9d6b588232a055c524458b"
	urllibSdistSHA = "24d6a242c28d29af46c3fae832c36db3bbebcc533dd1bb549172cd739c82df21"
)

var debianAmd64 = ImageEnv{Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, OSFamily: "debian", OSName: "12.5"}

// fixture is one manager's input and what a correct update of it produces.
type fixture struct {
	mgr   DependencyManager
	dir   string
	files []string
	// lock is the file the update rewrites; after is its updated content.
	lock  string
	after string
	group func() *findingGroup
	typ   string // scanner result type
	// pkgs before and after, and the findings of the original files.
	beforePkgs, afterPkgs [][2]string
	vulns                 [][3]string
}

func pyOrigin() FindingOrigin {
	return FindingOrigin{Entity: "img", Workload: "compose/p/web",
		PkgPath: "usr/local/lib/python3.12/site-packages/urllib3-1.26.4.dist-info/METADATA", Target: "Python"}
}

func urllibGroup() *findingGroup {
	return group(typePythonPkg, "urllib3", "1.26.4", pyOrigin(),
		CVERef{VulnID: "CVE-2021-33503", FixedVers: []string{"1.26.5"}},
		CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17", "2.0.6"}})
}

func minimistGroup() *findingGroup {
	return group(typeNodePkg, "minimist", "1.2.5", FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/minimist/package.json"},
		CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
}

func fixtureFor(name string) fixture {
	switch name {
	case "npm":
		return fixture{mgr: ManagerNpm, dir: "npm", files: []string{"package.json", "package-lock.json"}, lock: "package-lock.json",
			group: minimistGroup, typ: "npm",
			beforePkgs: [][2]string{{"mkdirp", "0.5.5"}, {"minimist", "1.2.5"}}, afterPkgs: [][2]string{{"mkdirp", "0.5.5"}, {"minimist", "1.2.8"}},
			vulns: [][3]string{{"minimist", "1.2.5", "CVE-2021-44906"}}}
	case "pnpm":
		return fixture{mgr: ManagerPnpm, dir: "pnpm", files: []string{"package.json", "pnpm-lock.yaml"}, lock: "pnpm-lock.yaml",
			group: minimistGroup, typ: "pnpm",
			beforePkgs: [][2]string{{"mkdirp", "0.5.5"}, {"minimist", "1.2.5"}}, afterPkgs: [][2]string{{"mkdirp", "0.5.5"}, {"minimist", "1.2.8"}},
			vulns: [][3]string{{"minimist", "1.2.5", "CVE-2021-44906"}}}
	case "uv":
		return fixture{mgr: ManagerUv, dir: "uv", files: []string{"pyproject.toml", "uv.lock"}, lock: "uv.lock",
			group: urllibGroup, typ: "uv",
			beforePkgs: [][2]string{{"fixture-uv", "1.0.0"}, {"urllib3", "1.26.4"}}, afterPkgs: [][2]string{{"fixture-uv", "1.0.0"}, {"urllib3", "1.26.17"}},
			vulns: [][3]string{{"urllib3", "1.26.4", "CVE-2021-33503"}, {"urllib3", "1.26.4", "CVE-2023-43804"}}}
	}
	return fixture{mgr: ManagerPip, dir: "pip", files: []string{"requirements.txt"}, lock: "requirements.txt",
		group: urllibGroup, typ: "pip",
		beforePkgs: [][2]string{{"urllib3", "1.26.4"}}, afterPkgs: [][2]string{{"urllib3", "1.26.17"}},
		vulns: [][3]string{{"urllib3", "1.26.4", "CVE-2021-33503"}, {"urllib3", "1.26.4", "CVE-2023-43804"}}}
}

// pipAfter is requirements.txt of the pip fixture after a correct update.
const pipAfter = "# pinned for the fixture\nurllib3==1.26.17 \\\n    --hash=sha256:" + urllibWheelSHA + "\n"

func (f fixture) load(t *testing.T) (files map[string]string, after []byte) {
	t.Helper()
	files = readTestdata(t, f.dir, f.files...)
	if f.mgr == ManagerPip {
		return files, []byte(pipAfter)
	}
	b, err := os.ReadFile(filepath.Join("testdata", "update", f.dir, "after", f.lock))
	if err != nil {
		t.Fatal(err)
	}
	return files, b
}

// pipItem is one package of a fake pip install report.
type pipItem struct {
	name, ver string
	requires  []string
	notReq    bool
}

// pipReportItems is the report of pip install --dry-run for the items, as
// wheels the fake index publishes.
func pipReportItems(items ...pipItem) []byte {
	var inst []map[string]any
	for _, it := range items {
		md := map[string]any{"name": it.name, "version": it.ver}
		if len(it.requires) > 0 {
			md["requires_dist"] = it.requires
		}
		inst = append(inst, map[string]any{
			"download_info": map[string]any{
				"url":          fakeWheelURL(it.name, it.ver),
				"archive_info": map[string]any{"hashes": map[string]string{"sha256": fakeWheelSHA(it.name, it.ver)}},
			},
			"requested": !it.notReq,
			"is_yanked": false,
			"metadata":  md,
		})
	}
	b, _ := json.Marshal(map[string]any{"version": "1", "pip_version": "26.2.1", "install": inst, "environment": map[string]any{"python_version": "3.12"}})
	return b
}

// pipReportJSON is pipReportItems for name, version pairs that are all requested.
func pipReportJSON(pkgs ...[2]string) []byte {
	var items []pipItem
	for _, p := range pkgs {
		items = append(items, pipItem{name: p[0], ver: p[1]})
	}
	return pipReportItems(items...)
}

// harness wires an updater to fakes.
type harness struct {
	t     *testing.T
	fx    fixture
	files map[string]string
	after []byte
	item  LanguageItem
	work  *fakeWork
	fs    *fakeFS
	pypi  *fakePyPI
	npm   *fakeNpm
	gh    *fakeGH
	cfg   LangUpdateConfig
}

func newHarness(t *testing.T, name string) *harness {
	t.Helper()
	fx := fixtureFor(name)
	files, after := fx.load(t)
	h := &harness{t: t, fx: fx, files: files, after: after}
	h.item = itemFor(t, fx.mgr, files, fx.group())
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("fixture %s is not an update candidate: %s %s", name, h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	// The release of the target is published under the URLs of the uv
	// lockfile and the fake pip report alike.
	h.pypi = &fakePyPI{auto: true, releases: map[string][]PyPIFile{
		"urllib3==1.26.17": {
			fakeWheel("urllib3", "1.26.17"),
			{Filename: "urllib3-1.26.17-py2.py3-none-any.whl", URL: "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-1.26.17-py2.py3-none-any.whl", Wheel: true, SHA256: urllibWheelSHA},
			{Filename: "urllib3-1.26.17.tar.gz", URL: "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-1.26.17.tar.gz", Sdist: true, SHA256: urllibSdistSHA},
		},
	}}
	h.npm = &fakeNpm{dists: map[string]NpmDist{
		"minimist@1.2.8": minimist128,
		"mkdirp@0.5.5": {Tarball: "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.5.tgz", Dependencies: map[string]string{"minimist": "^1.2.5"},
			Integrity: "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ=="},
	}}
	h.work = &fakeWork{script: h.okScript}
	h.fs = &fakeFS{fn: h.okFS}
	h.cfg = LangUpdateConfig{
		Scanner: h.fs, Work: h.work, PyPI: h.pypi, Npm: h.npm, GitHub: h.gh,
		Prepared: fsConds, Images: map[string]ImageEnv{"img": debianAmd64}, MaxJobs: 5,
	}
	h.cfg = withTestTools(h.t, h.cfg)
	return h
}

// okScript is a work container whose update does what the real tools did.
func (h *harness) okScript(n int, job worker.Job, src map[string][]byte) fakeOutcome {
	if h.fx.mgr == ManagerPip {
		if n == 0 {
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: pipReportJSON(h.fx.beforePkgs...)}}}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: pipReportJSON(h.fx.afterPkgs...)}}}
	}
	return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {h.fx.lock: h.after}}}
}

func (h *harness) okFS(n int, files map[string][]byte) (scanner.FSScan, error) {
	if n == 0 {
		return fsReport(h.fx.typ, h.fx.beforePkgs, h.fx.vulns), nil
	}
	return fsReport(h.fx.typ, h.fx.afterPkgs, nil), nil
}

// run runs the updater over the harness's item and returns the item after.
func (h *harness) run() (LanguageItem, LangUpdateUsage) {
	h.t.Helper()
	return h.runCtx(context.Background())
}

func (h *harness) runCtx(ctx context.Context) (LanguageItem, LangUpdateUsage) {
	h.t.Helper()
	up, err := NewLangUpdater(h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	item := h.item
	item.Packages = append([]LanguagePackage(nil), h.item.Packages...)
	plan := &Plan{LanguageItems: []LanguageItem{item}}
	use := up.Run(ctx, plan)
	return plan.LanguageItems[0], use
}

func wantCategory(t *testing.T, it LanguageItem, c Category, r Reason) {
	t.Helper()
	if it.Category != c || it.Reason != r {
		t.Fatalf("category/reason = %s/%s (%s), want %s/%s", it.Category, it.Reason, it.Detail, c, r)
	}
}

func TestLangUpdateSucceedsForEveryManager(t *testing.T) {
	for _, name := range []string{"npm", "pnpm", "uv", "pip"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, name)
			it, use := h.run()
			wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
			if use.Jobs != 1 {
				t.Errorf("jobs = %d", use.Jobs)
			}
			if !it.UpdateExecuted || !it.PostUpdateCheckExecuted {
				t.Errorf("executed flags = %v %v", it.UpdateExecuted, it.PostUpdateCheckExecuted)
			}
			p := it.Packages[0]
			wantVer := h.fx.afterPkgs[len(h.fx.afterPkgs)-1][1]
			if p.AdoptedVersion != wantVer || p.Action != ActionUpdate {
				t.Errorf("package = %+v", p)
			}
			if len(it.Artifacts) != 1 || it.Artifacts[0].Path != h.fx.lock || string(it.Artifacts[0].Content) != string(h.after) ||
				it.Artifacts[0].SHA256 != sha256Hex(h.after) || it.Artifacts[0].Size != int64(len(h.after)) || it.Artifacts[0].Mode != "100644" {
				t.Errorf("artifacts = %+v", it.Artifacts)
			}
			sc := it.SourceCheck
			if sc == nil || !sc.Passed || sc.CommitSHA != testCommit || len(sc.Resolved) == 0 || len(sc.Introduced) != 0 {
				t.Fatalf("source check = %+v", sc)
			}
			if len(sc.Before) != len(h.fx.files) || len(sc.After) != len(h.fx.files) {
				t.Errorf("source check hashes = %+v %+v", sc.Before, sc.After)
			}
			for i := range sc.Before {
				same := sc.Before[i].SHA256 == sc.After[i].SHA256
				if (sc.Before[i].Path == h.fx.lock) == same || sc.Before[i].Path != sc.After[i].Path {
					t.Errorf("source check hash of %s: before %s, after %s", sc.Before[i].Path, sc.Before[i].SHA256, sc.After[i].SHA256)
				}
			}
			if it.Update == nil || len(it.Update.Steps) == 0 || it.Update.Diff == nil {
				t.Errorf("update record = %+v", it.Update)
			}
			// The plan keeps the path, size and hash of an artifact, not its content.
			raw, err := json.Marshal(it)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "Content") || strings.Contains(string(raw), `"content"`) || strings.Contains(string(raw), "[[package]]") || strings.Contains(string(raw), "lockfileVersion") || strings.Contains(string(raw), "--hash") {
				t.Errorf("the item JSON holds file content: %s", raw)
			}
			if !strings.Contains(string(raw), `"sha256":"`+sha256Hex(h.after)+`"`) {
				t.Errorf("the item JSON lacks the artifact hash")
			}
		})
	}
}

// jobsOf returns the worker jobs the fake received.
func (h *harness) jobsOf() []worker.Job { return h.work.jobs }

func TestLangUpdateJobs(t *testing.T) {
	t.Run("npm", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.run()
		jobs := h.jobsOf()
		if len(jobs) != 1 || jobs[0].Manager != worker.ManagerNpm {
			t.Fatalf("jobs = %+v", jobs)
		}
		s := jobs[0].Steps
		if len(s) != 2 || s[0].Op != worker.OpNpmRelock || !s[0].Scratch || s[1].Op != worker.OpNpmUpdate || s[1].Scratch ||
			len(s[1].Packages) != 1 || s[1].Packages[0] != (worker.Package{Name: "minimist"}) {
			t.Errorf("steps = %+v", s)
		}
		if err := jobs[0].Validate(); err != nil {
			t.Error(err)
		}
		if got := h.work.srcs[0]["package.json"]; string(got) != h.files["package.json"] {
			t.Errorf("package.json input = %q", got)
		}
		if id := h.work.ids[0]; !strings.HasPrefix(id, "lang-") {
			t.Errorf("job id = %q", id)
		}
	})
	t.Run("pnpm transitive has no version", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.run()
		s := h.jobsOf()[0].Steps
		if len(s) != 3 || s[0].Op != worker.OpPnpmFrozen || !s[0].Scratch || s[1].Op != worker.OpPnpmUpdate || s[2].Op != worker.OpPnpmFrozen || !s[2].Scratch {
			t.Fatalf("steps = %+v", s)
		}
		if s[1].Packages[0] != (worker.Package{Name: "minimist"}) {
			t.Errorf("packages = %+v", s[1].Packages)
		}
	})
	t.Run("uv pins the target", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.run()
		s := h.jobsOf()[0].Steps
		if len(s) != 3 || s[0].Op != worker.OpUvCheck || s[1].Op != worker.OpUvUpgrade || s[2].Op != worker.OpUvCheck {
			t.Fatalf("steps = %+v", s)
		}
		if s[1].Packages[0] != (worker.Package{Name: "urllib3", Version: "1.26.17"}) {
			t.Errorf("packages = %+v", s[1].Packages)
		}
	})
	t.Run("pip runs the original and the rewritten file", func(t *testing.T) {
		h := newHarness(t, "pip")
		h.run()
		jobs := h.jobsOf()
		if len(jobs) != 2 {
			t.Fatalf("%d jobs", len(jobs))
		}
		for i, j := range jobs {
			if len(j.Steps) != 1 || j.Steps[0].Op != worker.OpPipDryRun || !j.Steps[0].RequireHashes {
				t.Errorf("job %d steps = %+v", i, j.Steps)
			}
			tg := j.Steps[0].Target
			if tg == nil || tg.PythonVersion != "3.12" || tg.Implementation != "cp" || len(tg.ABIs) != 1 || tg.ABIs[0] != "cp312" ||
				tg.Platforms[0] != "manylinux_2_36_x86_64" || tg.Platforms[len(tg.Platforms)-1] != "manylinux_2_5_x86_64" {
				t.Errorf("job %d target = %+v", i, tg)
			}
		}
		if string(h.work.srcs[0]["requirements.txt"]) != h.files["requirements.txt"] || string(h.work.srcs[1]["requirements.txt"]) != pipAfter {
			t.Errorf("inputs = %q %q", h.work.srcs[0]["requirements.txt"], h.work.srcs[1]["requirements.txt"])
		}
		// The wheel hashes of the target, and the packages of the two pip reports.
		if strings.Join(h.pypi.lookups, " ") != "urllib3==1.26.17 urllib3==1.26.4" {
			t.Errorf("lookups = %v", h.pypi.lookups)
		}
	})
}

func TestLangUpdateLimitsAndDeadline(t *testing.T) {
	t.Run("job limit defers the rest", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.cfg.MaxJobs = 1
		up, err := NewLangUpdater(h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		second := h.item
		second.Key += "-2"
		plan := &Plan{LanguageItems: []LanguageItem{h.item, second}}
		use := up.Run(context.Background(), plan)
		if use.Jobs != 1 {
			t.Errorf("jobs = %d", use.Jobs)
		}
		wantCategory(t, plan.LanguageItems[0], CategoryPRCandidate, ReasonUpdateVerified)
		wantCategory(t, plan.LanguageItems[1], CategoryDeferred, ReasonUpdateJobLimit)
		if plan.LanguageItems[1].Packages[0].Action != ActionUpdate || plan.LanguageItems[1].UpdateExecuted {
			t.Errorf("a deferred item changed: %+v", plan.LanguageItems[1])
		}
		if h.work.calls != 1 {
			t.Errorf("work calls = %d", h.work.calls)
		}
	})
	t.Run("zero allows none", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.cfg.MaxJobs = 0
		it, use := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdateJobLimit)
		if use.Jobs != 0 || h.work.calls != 0 {
			t.Errorf("work ran: %d %d", use.Jobs, h.work.calls)
		}
	})
	t.Run("cancelled context defers", func(t *testing.T) {
		h := newHarness(t, "npm")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		it, _ := h.runCtx(ctx)
		wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
	})
	t.Run("only update candidates are touched", func(t *testing.T) {
		h := newHarness(t, "npm")
		for _, c := range []Category{CategoryManual, CategoryRebuildExpected, CategoryDeferred, CategoryFailed, CategoryNotComparable} {
			h.item.Category, h.item.Reason = c, "x"
			it, use := h.run()
			if it.Category != c || it.Reason != "x" || use.Jobs != 0 {
				t.Errorf("%s item changed to %s/%s", c, it.Category, it.Reason)
			}
		}
	})
	t.Run("constructor validates", func(t *testing.T) {
		h := newHarness(t, "npm")
		for name, mut := range map[string]func(*LangUpdateConfig){
			"no work":     func(c *LangUpdateConfig) { c.Work = nil },
			"no scanner":  func(c *LangUpdateConfig) { c.Scanner = nil },
			"no pypi":     func(c *LangUpdateConfig) { c.PyPI = nil },
			"no github":   func(c *LangUpdateConfig) { c.GitHub = nil },
			"neg limit":   func(c *LangUpdateConfig) { c.MaxJobs = -1 },
			"neg timeout": func(c *LangUpdateConfig) { c.JobTimeout = -1 },
			"short":       func(c *LangUpdateConfig) { c.JobTimeout = 10 },
		} {
			c := h.cfg
			mut(&c)
			if _, err := NewLangUpdater(c); err == nil {
				t.Errorf("%s: no error", name)
			}
		}
	})
}

func TestLangUpdateSourceReads(t *testing.T) {
	t.Run("blob mismatch", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.gh.files["package-lock.json"] = []byte(h.files["package-lock.json"] + " ")
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonSourceChanged)
		if h.work.calls != 0 {
			t.Error("a job ran on files that do not match the plan")
		}
	})
	t.Run("read error", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.gh.err = errors.New("boom")
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonSourceReadFailed)
	})
	t.Run("missing record", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.item.Source.Files = h.item.Source.Files[:1]
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateInputInvalid)
	})
	t.Run("no commit", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.item.Source.CommitSHA = ""
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateInputInvalid)
	})
	t.Run("no package to update", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.item.Packages[0].Action = ActionManual
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateInputInvalid)
	})
}

func TestLangUpdateJobOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		mgr    string
		script func(h *harness) func(n int, job worker.Job, src map[string][]byte) fakeOutcome
		cat    Category
		reason Reason
	}{
		{"client error", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome {
				return fakeOutcome{err: errors.New("daemon down")}
			}
		}, CategoryFailed, ReasonUpdateJobFailed},
		{"client timeout", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome {
				return fakeOutcome{err: fmt.Errorf("%w: x", docker.ErrJobTimeout)}
			}
		}, CategoryFailed, ReasonUpdateJobTimedOut},
		{"program exit code", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{exit: 3} }
		}, CategoryFailed, ReasonUpdateJobFailed},
		{"garbage output", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{raw: []byte("hello\n")} }
		}, CategoryFailed, ReasonUpdateResultInvalid},
		{"empty output", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{raw: []byte{}} }
		}, CategoryFailed, ReasonUpdateResultInvalid},
		{"status timed out", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome {
				return fakeOutcome{status: worker.StatusTimedOut, failStep: stepUpdate}
			}
		}, CategoryFailed, ReasonUpdateJobTimedOut},
		{"input rejected", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome {
				return fakeOutcome{status: worker.StatusInputRejected, mangleResult: func(r *worker.Result) { r.Steps = []worker.StepResult{}; r.Error = "bad input" }}
			}
		}, CategoryFailed, ReasonUpdateJobInputRefused},
		{"baseline step fails", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{failStep: stepBaseline} }
		}, CategoryManual, ReasonLockfileInconsistent},
		{"update step fails", "npm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{failStep: stepUpdate} }
		}, CategoryManual, ReasonUpdateStepFailed},
		{"check step fails", "pnpm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{failStep: stepCheck} }
		}, CategoryManual, ReasonPostUpdateCheckFailed},
		{"unexpected files", "pnpm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome {
				return fakeOutcome{failStep: stepUpdate, failReason: worker.ReasonUnexpectedFiles, unexpected: []string{"pnpm-workspace.yaml"}}
			}
		}, CategoryManual, ReasonUnexpectedFiles},
		{"release age", "pnpm", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome {
				return fakeOutcome{failStep: stepBaseline, failReason: worker.ReasonReleaseAgeViolation}
			}
		}, CategoryManual, ReasonReleaseAgeViolation},
		{"uv check fails", "uv", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{failStep: stepBaseline} }
		}, CategoryManual, ReasonLockfileInconsistent},
		{"pip baseline dry run fails", "pip", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{failStep: stepBaseline} }
		}, CategoryManual, ReasonLockfileInconsistent},
		{"pip check dry run fails", "pip", func(h *harness) func(int, worker.Job, map[string][]byte) fakeOutcome {
			return func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				if n == 0 {
					return h.okScript(n, job, src)
				}
				return fakeOutcome{failStep: stepCheck}
			}
		}, CategoryManual, ReasonPostUpdateCheckFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.mgr)
			h.work.script = c.script(h)
			it, _ := h.run()
			wantCategory(t, it, c.cat, c.reason)
			if len(it.Artifacts) != 0 {
				t.Error("a failed item keeps artifacts")
			}
			for _, p := range it.Packages {
				if p.Action != ActionManual && it.Category != CategoryDeferred || p.Reason != c.reason {
					t.Errorf("package = %+v", p)
				}
			}
			if h.fs.calls != 0 {
				t.Errorf("the dependency files were scanned after a failed job (%d)", h.fs.calls)
			}
		})
	}
}

func TestLangUpdateKeepsAResultWhenTheContainerCannotBeDeleted(t *testing.T) {
	h := newHarness(t, "npm")
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		o := h.okScript(n, job, src)
		o.cleanupErr = fmt.Errorf("%w: busy", docker.ErrCleanup)
		return o
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if len(it.Update.Notes) != 1 || !strings.Contains(it.Update.Notes[0], "could not be deleted") {
		t.Errorf("notes = %v", it.Update.Notes)
	}
}

func TestClipCleansTextFromTools(t *testing.T) {
	if got := clip("a\x1b[31mred\x00\nb", 100); got != "a [31mred  b" {
		t.Errorf("clip = %q", got)
	}
	if got := clip(strings.Repeat("é", 100), 11); len(got) > 14 || !strings.HasSuffix(got, "...") {
		t.Errorf("clip = %q", got)
	}
}

func TestLangUpdateRefusesTamperedResults(t *testing.T) {
	cases := map[string]func(files map[string][]byte){
		"undeclared file": func(f map[string][]byte) { f["steps/update/evil.sh"] = []byte("x") },
		"altered content": func(f map[string][]byte) { f["final/package-lock.json"] = []byte("{}") },
		"missing declared file": func(f map[string][]byte) {
			delete(f, "final/package.json")
		},
		"no result.json": func(f map[string][]byte) { delete(f, "result.json") },
		"extra final":    func(f map[string][]byte) { f["final/notes.txt"] = []byte("x") },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "npm")
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				o := h.okScript(n, job, src)
				o.mangle = mangle
				return o
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
		})
	}
	t.Run("wrong steps", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			o := h.okScript(n, job, src)
			o.mangleResult = func(r *worker.Result) { r.Steps[1].Argv = []string{"sh", "-c", "evil"} }
			return o
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
	})
	t.Run("completed with fewer steps", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			o := h.okScript(n, job, src)
			o.mangleResult = func(r *worker.Result) { r.Steps = r.Steps[:1] }
			return o
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
	})
	t.Run("declared output with the wrong hash", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			o := h.okScript(n, job, src)
			o.mangleResult = func(r *worker.Result) { r.Final[1].SHA256 = strings.Repeat("0", 64) }
			return o
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
	})
	t.Run("protocol", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			o := h.okScript(n, job, src)
			o.mangleResult = func(r *worker.Result) { r.Protocol = 9 }
			return o
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
	})
}

// edit makes the update step write content to the lockfile.
func (h *harness) editLock(content string) {
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {h.fx.lock: []byte(content)}}}
	}
}

func TestLangUpdateInspectsTheResult(t *testing.T) {
	t.Run("manifest changed", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {
				"package-lock.json": h.after, "package.json": []byte(h.files["package.json"] + "\n"),
			}}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonManifestChanged)
	})
	t.Run("lockfile unchanged", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(int, worker.Job, map[string][]byte) fakeOutcome { return fakeOutcome{} }
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	})
	t.Run("relocking the original changes it", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{edit: map[string]map[string][]byte{
				stepBaseline: {"package-lock.json": []byte(strings.Replace(h.files["package-lock.json"], "mkdirp-0.5.5", "mkdirp-0.5.6", 1))},
				stepUpdate:   {"package-lock.json": h.after},
			}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonLockfileInconsistent)
	})
	t.Run("format changed", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(strings.Replace(string(h.after), `"lockfileVersion": 3`, `"lockfileVersion": 2`, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonLockfileFormatChanged)
	})
	t.Run("uv revision migrated", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.editLock(strings.Replace(string(h.after), "revision = 5", "revision = 3", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonLockfileFormatChanged)
	})
	t.Run("target below its lower bound", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(strings.NewReplacer("1.2.8", "1.2.5").Replace(string(h.after)))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
		if it.Packages[0].Reason != ReasonTargetNotUpdated {
			t.Errorf("package = %+v", it.Packages[0])
		}
	})
	t.Run("version does not meet the fix", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.item.Packages[0].CVEs[0].FixedVers = []string{"9.9.9"}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonFixConditionNotMet)
	})
	t.Run("target dropped", func(t *testing.T) {
		h := newHarness(t, "npm")
		var doc map[string]any
		_ = json.Unmarshal(h.after, &doc)
		delete(doc["packages"].(map[string]any), "node_modules/minimist")
		b, _ := json.MarshalIndent(doc, "", "  ")
		h.editLock(string(b))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonTargetRemoved)
	})
	t.Run("not from the public registry", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(strings.Replace(string(h.after), "https://registry.npmjs.org/minimist", "https://evil.example/minimist", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonResolvedSourceChanged)
	})
	t.Run("an unrelated package changed", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(strings.Replace(string(h.after), "mkdirp-0.5.5.tgz", "mkdirp-0.5.6.tgz", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("a new package nothing explains", func(t *testing.T) {
		h := newHarness(t, "npm")
		var doc map[string]any
		_ = json.Unmarshal(h.after, &doc)
		doc["packages"].(map[string]any)["node_modules/extra"] = map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz", "integrity": "sha512-x"}
		b, _ := json.MarshalIndent(doc, "", "  ")
		h.editLock(string(b))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("the project's own entry changed", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(strings.Replace(string(h.after), `"name": "fixture-npm",`, `"name": "other",`, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("pnpm check changes the lockfile", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{edit: map[string]map[string][]byte{
				stepUpdate: {"pnpm-lock.yaml": h.after},
				stepCheck:  {"pnpm-lock.yaml": append(append([]byte(nil), h.after...), '\n')},
			}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonPostUpdateLockUnstable)
	})
	t.Run("pnpm baseline check changes the lockfile", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{edit: map[string]map[string][]byte{
				stepBaseline: {"pnpm-lock.yaml": []byte(h.files["pnpm-lock.yaml"] + "\n")},
				stepUpdate:   {"pnpm-lock.yaml": h.after},
			}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonLockfileInconsistent)
	})
	t.Run("pnpm picks up a tarball source", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.editLock(strings.Replace(string(h.after), "minimist@1.2.8:\n    resolution: {integrity:", "minimist@1.2.8:\n    resolution: {tarball: https://evil.example/m.tgz, integrity:", 1))
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("category = %s %s", it.Category, it.Reason)
		}
	})
	t.Run("uv index changed", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.editLock(strings.Replace(string(h.after), `source = { registry = "https://pypi.org/simple" }`, `source = { registry = "https://pypi.example/simple" }`, 1))
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("category = %s %s", it.Category, it.Reason)
		}
	})
	t.Run("uv root requirement changed", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.editLock(strings.Replace(string(h.after), `specifier = ">=1.26,<2"`, `specifier = ">=1.26"`, 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("the failing package is named, the others are not applied", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.item.Packages = append(h.item.Packages, LanguagePackage{
			Name: "ms", Ecosystem: typeNodePkg, Installed: "2.0.0", SelectionLowerBound: "2.1.0", Action: ActionUpdate, Reason: ReasonUpdateCandidateInSource,
			Occurrences: []SourceOccurrence{{Path: "node_modules/ms", Version: "2.0.0", Matched: true}},
		})
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonTargetRemoved)
		// ms is not in the lockfile at all (the fixture has no such package),
		// so it is the one that fails; minimist is left as part of the set.
		if it.Packages[1].Reason != ReasonTargetRemoved {
			t.Errorf("package ms = %+v", it.Packages[1])
		}
		if it.Packages[0].Reason != ReasonUpdateSetNotApplied || it.Packages[0].Action != ActionManual {
			t.Errorf("package minimist = %+v", it.Packages[0])
		}
	})
}

func TestLangUpdateManifestRanges(t *testing.T) {
	directNpm := func(spec string) (map[string]string, LanguageItem) {
		files := map[string]string{
			"package.json": `{"name":"a","version":"1.0.0","dependencies":{"minimist":"` + spec + `"}}`,
			"package-lock.json": `{"name":"a","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"a","version":"1.0.0","dependencies":{"minimist":"` + spec + `"}},
"node_modules/minimist":{"version":"1.2.5","resolved":"https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz","integrity":"sha512-x"}}}`,
		}
		return files, itemFor(t, ManagerNpm, files, minimistGroup())
	}
	cases := []struct {
		spec string
		ok   bool
	}{
		{"^1.2.5", true}, {"~1.2.5", true}, {">=1.2.0 <2", true}, {"1.x", true}, {"*", true}, {"~1.2.5 || ^2.0.0", true},
		{"<1.2.6", false}, {"latest", false}, {"file:../m", false}, {"npm:other@1", false}, {"1.2.5 - 1.2.5", false},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			files, item := directNpm(c.spec)
			if item.Category != CategoryDependencyUpdateCandidate {
				// A spec the planner cannot use never reaches the update stage.
				t.Skipf("not a candidate: %s %s", item.Category, item.Reason)
			}
			h := newHarness(t, "npm")
			h.files, h.item = files, item
			h.gh = ghFor(files)
			h.cfg.GitHub = h.gh
			h.npm.dists["minimist@1.2.8"] = NpmDist{Tarball: minimist128.Tarball, Integrity: "sha512-y"}
			h.editLock(strings.NewReplacer(`"version":"1.2.5"`, `"version":"1.2.8"`, "minimist-1.2.5.tgz", "minimist-1.2.8.tgz", `"sha512-x"`, `"sha512-y"`).Replace(files["package-lock.json"]))
			got, _ := h.run()
			if c.ok {
				wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
				if h.work.jobs[0].Steps[1].Packages[0].Version != "" {
					t.Error("npm update takes no version")
				}
				return
			}
			wantCategory(t, got, CategoryManual, ReasonManifestEditRequired)
			if got.Packages[0].Reason != ReasonManifestEditRequired || h.work.calls != 0 {
				t.Errorf("package = %+v, work calls = %d", got.Packages[0], h.work.calls)
			}
		})
	}
}

func TestLangUpdatePnpmDirectDependencyIsPinned(t *testing.T) {
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
	after := strings.NewReplacer("1.2.5\n", "1.2.8\n", "minimist@1.2.5", "minimist@1.2.8", "sha512-aaa", "sha512-bbb").Replace(files["pnpm-lock.yaml"])
	after = strings.Replace(after, "specifier: ^1.2.8", "specifier: ^1.2.5", 1)
	h := newHarness(t, "pnpm")
	h.files = files
	h.item = itemFor(t, ManagerPnpm, files, minimistGroup())
	h.gh = ghFor(files)
	h.cfg.GitHub = h.gh
	h.after = []byte(after)
	h.npm.dists["minimist@1.2.8"] = NpmDist{Tarball: minimist128.Tarball, Integrity: "sha512-bbb"}
	got, _ := h.run()
	wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
	if p := h.work.jobs[0].Steps[1].Packages[0]; p != (worker.Package{Name: "minimist", Version: "1.2.6"}) {
		t.Errorf("update package = %+v", p)
	}
	if got.Packages[0].AdoptedVersion != "1.2.8" {
		t.Errorf("adopted = %q", got.Packages[0].AdoptedVersion)
	}
}

func TestLangUpdateUvProjectChecks(t *testing.T) {
	pyproject := func(h *harness, from, to string) {
		h.files["pyproject.toml"] = strings.Replace(h.files["pyproject.toml"], from, to, 1)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
	}
	for _, c := range []struct {
		name, from, to string
		cat            Category
		reason         Reason
	}{
		{"requires-python excludes 3.13", `">=3.9"`, `">=3.9,<3.13"`, CategoryManual, "python_spec_unsupported"},
		{"requires-python above", `">=3.9"`, `">=3.14"`, CategoryManual, "python_spec_unsupported"},
		{"requires-python unreadable", `">=3.9"`, `"~3"`, CategoryManual, "python_spec_invalid"},
		{"specifier excludes the target", `"urllib3>=1.26,<2"`, `"urllib3>=1.26,<1.26.10"`, CategoryManual, ReasonManifestEditRequired},
		{"upper bound excludes the target", `"urllib3>=1.26,<2"`, `"urllib3<=1.26.4"`, CategoryManual, ReasonManifestEditRequired},
		{"arbitrary equality is not judged", `"urllib3>=1.26,<2"`, `"urllib3===1.26.4"`, CategoryManual, ReasonManifestEditRequired},
		{"extras and markers are fine", `"urllib3>=1.26,<2"`, `"urllib3[socks]>=1.26,<2; python_version >= '3.8'"`, CategoryPRCandidate, ReasonUpdateVerified},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "uv")
			pyproject(h, c.from, c.to)
			if h.item.Category != CategoryDependencyUpdateCandidate {
				t.Skipf("not a candidate: %s", h.item.Reason)
			}
			it, _ := h.run()
			wantCategory(t, it, c.cat, c.reason)
			if c.cat == CategoryManual && h.work.calls != 0 {
				t.Error("a job ran")
			}
		})
	}
	t.Run("no requires-python", func(t *testing.T) {
		h := newHarness(t, "uv")
		pyproject(h, "requires-python = \">=3.9\"\n", "")
		if h.item.Category != CategoryDependencyUpdateCandidate {
			t.Skip("the planner stops this one")
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
}
