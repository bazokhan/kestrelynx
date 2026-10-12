package remediation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// fakeGitHub serves branches, directories and files; every call is recorded.
type fakeGitHub struct {
	branchErr map[string]error // by repo
	listErr   map[string]error // by repo/dir
	readErr   map[string]error // by repo/path
	dirs      map[string][]github.Entry
	files     map[string]string // by repo/path
	calls     []string
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{branchErr: map[string]error{}, listErr: map[string]error{}, readErr: map[string]error{},
		dirs: map[string][]github.Entry{}, files: map[string]string{}}
}

// put adds a regular file to the directory of repo and its content.
func (f *fakeGitHub) put(repo, dir, name, content string) {
	k := repo + "/" + dir
	f.dirs[k] = append(f.dirs[k], github.Entry{Name: name, Path: pathIn(dir, name), Type: github.EntryFile, SHA: blobOf(content)})
	f.files[repo+"/"+pathIn(dir, name)] = content
}

func (f *fakeGitHub) putEntry(repo, dir string, e github.Entry) {
	e.Path = pathIn(dir, e.Name)
	f.dirs[repo+"/"+dir] = append(f.dirs[repo+"/"+dir], e)
}

// blobOf is a stand-in blob SHA, stable for a content.
func blobOf(content string) string {
	return fmt.Sprintf("%040x", len(content)*7919+int(content[0]))
}

func (f *fakeGitHub) ResolveBranch(_ context.Context, repo, branch string) (string, error) {
	f.calls = append(f.calls, "branch:"+repo+"@"+branch)
	if err := f.branchErr[repo]; err != nil {
		return "", err
	}
	return testCommit, nil
}

func (f *fakeGitHub) ListDirectory(_ context.Context, repo, sha, dir string) ([]github.Entry, error) {
	f.calls = append(f.calls, "list:"+repo+"/"+dir+"@"+sha)
	if err := f.listErr[repo+"/"+dir]; err != nil {
		return nil, err
	}
	return f.dirs[repo+"/"+dir], nil
}

func (f *fakeGitHub) ReadFile(_ context.Context, repo, sha, p string) (github.File, error) {
	f.calls = append(f.calls, "read:"+repo+"/"+p+"@"+sha)
	if err := f.readErr[repo+"/"+p]; err != nil {
		return github.File{}, err
	}
	c, ok := f.files[repo+"/"+p]
	if !ok {
		return github.File{}, github.ErrNotFound
	}
	return github.File{Path: p, SHA: blobOf(c), Content: []byte(c)}, nil
}

func (f *fakeGitHub) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func depMapping(workload, repo, dir string) DependencyMapping {
	parts := strings.Split(workload, "/")
	return DependencyMapping{Workload: workload, Project: parts[1], Service: parts[2], Repository: repo, BaseBranch: "main", Directory: dir}
}

// langInput is a scanned image of a Compose service with the findings.
func langInput(project, service string, fs ...scanner.Finding) ImageInput {
	ref := project + "-" + service + ":1"
	return ImageInput{
		Scan:     configScan(ref, 'a', fs, nil),
		Services: []ServiceRef{{Project: project, Service: service, Container: project + "-" + service + "-1"}},
	}
}

func langPlan(t *testing.T, gh GitHubReader, deps []DependencyMapping, intel IntelFunc, inputs ...ImageInput) Plan {
	t.Helper()
	return langPlanCtx(t, context.Background(), gh, deps, intel, inputs...)
}

func langPlanCtx(t *testing.T, ctx context.Context, gh GitHubReader, deps []DependencyMapping, intel IntelFunc, inputs ...ImageInput) Plan {
	t.Helper()
	p, err := NewPlanner(Config{
		Registry: newFakeRegistry(), Scanner: newFakeScanner(), Limits: Limits{MaxCandidateScans: 1, MaxBaselineRescans: 1, MaxTagPages: 1},
		GitHub: gh, Dependencies: deps, Intel: intel,
		Now: func() time.Time { return time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.Plan(ctx, inputs)
}

func npmRepo(f *fakeGitHub, repo, dir string) {
	f.put(repo, dir, "package.json", npmManifest)
	f.put(repo, dir, "package-lock.json", npmLockV3)
}

func TestLanguagePlan_NpmCandidate(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "backend")
	intel := func(id string) (VulnIntel, bool) {
		if id == "CVE-2" {
			return VulnIntel{Priority: PriorityActNow, KEV: true}, true
		}
		return VulnIntel{}, false
	}
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "backend")}, intel,
		langInput("shop", "api",
			nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
			nodeFinding("CVE-2", "express", "4.18.2", "4.19.2"),
			nodeFinding("CVE-3", "ghost", "1.0.0", "1.0.1"),
		))
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("language items = %d", len(plan.LanguageItems))
	}
	it := plan.LanguageItems[0]
	if it.Category != CategoryDependencyUpdateCandidate || it.Reason != ReasonUpdateCandidateInSource || it.Manager != ManagerNpm {
		t.Errorf("item = %s / %s / %s (%s)", it.Category, it.Reason, it.Manager, it.Detail)
	}
	if it.UpdateExecuted || it.PostUpdateCheckExecuted {
		t.Error("a plan must say the update and its check were not run")
	}
	if it.Key != "deps:ex/app@main:backend#npm" || len(it.Workloads) != 1 || it.Workloads[0] != "compose/shop/api" || it.Priority != PriorityActNow {
		t.Errorf("identity = %q %v %q", it.Key, it.Workloads, it.Priority)
	}
	s := it.Source
	if s.CommitSHA != testCommit || s.Repository != "ex/app" || s.BaseBranch != "main" || s.Directory != "backend" ||
		s.Origin != OriginConfig || s.Confidence != ConfidenceAsserted {
		t.Errorf("source = %+v", s)
	}
	if len(s.Files) != 2 || s.Files[0].Path != "backend/package.json" || s.Files[1].Path != "backend/package-lock.json" ||
		s.Files[0].BlobSHA != blobOf(npmManifest) || s.Files[1].BlobSHA != blobOf(npmLockV3) {
		t.Errorf("files = %+v", s.Files)
	}
	if len(it.Packages) != 3 {
		t.Fatalf("packages = %+v", it.Packages)
	}
	if it.Packages[0].Name != "express" || it.Packages[0].KEVCount() != 1 {
		t.Errorf("the KEV package comes first: %+v", it.Packages[0])
	}
	if it.Count(ActionUpdate) != 2 || it.Count(ActionManual) != 1 {
		t.Errorf("actions: update=%d manual=%d", it.Count(ActionUpdate), it.Count(ActionManual))
	}
	if gh.count("branch:") != 1 || gh.count("list:") != 1 || gh.count("read:") != 2 {
		t.Errorf("calls = %v", gh.calls)
	}
	for _, c := range gh.calls[1:] {
		if !strings.HasSuffix(c, "@"+testCommit) {
			t.Errorf("%s is not read at the resolved commit", c)
		}
	}
	if plan.Count(CategoryDependencyUpdateCandidate) != 0 || plan.CountLanguage(CategoryDependencyUpdateCandidate) != 1 || plan.CountAll(CategoryDependencyUpdateCandidate) != 1 {
		t.Error("counts do not separate image and language items")
	}
}

func TestLanguagePlan_SharedRootIsOneUnit(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	deps := []DependencyMapping{
		depMapping("compose/shop/api", "ex/app", "."),
		depMapping("compose/shop/worker", "EX/App", "."), // GitHub names are case-insensitive
	}
	plan := langPlan(t, gh, deps, nil,
		langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")),
		langInput("shop", "worker", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"), nodeFinding("CVE-2", "express", "4.18.2", "4.19.2")),
	)
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("units = %d, want 1", len(plan.LanguageItems))
	}
	it := plan.LanguageItems[0]
	if len(it.Workloads) != 2 || it.Workloads[0] != "compose/shop/api" || it.Workloads[1] != "compose/shop/worker" {
		t.Errorf("workloads = %v", it.Workloads)
	}
	if len(it.Packages) != 2 {
		t.Errorf("the same package from two workloads is one entry: %+v", it.Packages)
	}
	if gh.count("branch:") != 1 || gh.count("read:") != 2 {
		t.Errorf("the source is read once per unit: %v", gh.calls)
	}
	if it.Source.Directory != "." || it.Source.Files[0].Path != "package.json" {
		t.Errorf("root directory paths = %+v", it.Source)
	}
}

func TestLanguagePlan_FindingsStayWithTheirOwnWorkloads(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "backend")
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "backend")}
	plan := langPlan(t, gh, deps, nil,
		langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")),
		langInput("shop", "web", nodeFinding("CVE-2", "express", "4.18.2", "4.19.2")), // not mapped
	)
	if len(plan.LanguageItems) != 1 || len(plan.LanguageItems[0].Packages) != 1 || plan.LanguageItems[0].Packages[0].Name != "lodash" {
		t.Errorf("plan = %+v", plan.LanguageItems)
	}
	// With nothing to fix for any mapped workload, nothing is read.
	gh2 := newFakeGitHub()
	npmRepo(gh2, "ex/app", "backend")
	plan = langPlan(t, gh2, deps, nil, langInput("shop", "web", nodeFinding("CVE-2", "express", "4.18.2", "4.19.2")))
	if len(plan.LanguageItems) != 0 || len(gh2.calls) != 0 {
		t.Errorf("items = %d, calls = %v", len(plan.LanguageItems), gh2.calls)
	}
	// An affected package without a fix is not a target.
	affected := nodeFinding("CVE-3", "lodash", "4.17.20", "")
	affected.Status = scanner.StatusAffected
	plan = langPlan(t, gh2, deps, nil, langInput("shop", "api", affected))
	if len(plan.LanguageItems) != 0 || len(gh2.calls) != 0 {
		t.Errorf("an unfixed finding started source reading: %v", gh2.calls)
	}
}

func TestLanguagePlan_NoMappingsOrReaderChangesNothing(t *testing.T) {
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	if plan := langPlan(t, newFakeGitHub(), nil, nil, in); plan.LanguageItems != nil {
		t.Errorf("language items without mappings: %+v", plan.LanguageItems)
	}
	if plan := langPlan(t, nil, []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}, nil, in); plan.LanguageItems != nil {
		t.Errorf("language items without a reader: %+v", plan.LanguageItems)
	}
}

func TestLanguagePlan_FileDetection(t *testing.T) {
	nodeIn := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"), nodeFinding("CVE-3", "react", "18.2.0", "18.3.0"))
	pyIn := langInput("shop", "api", pyFinding("CVE-2", "requests", "2.31.0", "2.32.0"))
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}
	cases := []struct {
		name   string
		setup  func(f *fakeGitHub)
		reason Reason
		mgr    DependencyManager
		cat    Category
	}{
		{"nothing", func(f *fakeGitHub) { f.put("ex/app", "svc", "README.md", "x") }, ReasonDependencyFilesNotFound, "", CategoryManual},
		{"manifest without lockfile", func(f *fakeGitHub) { f.put("ex/app", "svc", "package.json", npmManifest) }, ReasonDependencyFilesNotFound, "", CategoryManual},
		{"yarn only", func(f *fakeGitHub) {
			f.put("ex/app", "svc", "package.json", npmManifest)
			f.put("ex/app", "svc", "yarn.lock", "x")
		}, ReasonDependencyFilesNotFound, "", CategoryManual},
		{"npm and pnpm", func(f *fakeGitHub) {
			npmRepo(f, "ex/app", "svc")
			f.put("ex/app", "svc", "pnpm-lock.yaml", pnpmLock)
		}, ReasonAmbiguousDependencyFile, "", CategoryManual},
		{"uv and requirements", func(f *fakeGitHub) {
			f.put("ex/app", "svc", "pyproject.toml", uvPyproject)
			f.put("ex/app", "svc", "uv.lock", uvLock)
			f.put("ex/app", "svc", "requirements.txt", "requests==2.31.0\n")
		}, ReasonAmbiguousDependencyFile, "", CategoryManual},
		{"lockfile is a symlink", func(f *fakeGitHub) {
			f.put("ex/app", "svc", "package.json", npmManifest)
			f.putEntry("ex/app", "svc", github.Entry{Name: "package-lock.json", Type: github.EntrySymlink})
		}, ReasonDependencyFileUnusable, "", CategoryManual},
		{"pip only", func(f *fakeGitHub) { f.put("ex/app", "svc", "requirements.txt", "requests==2.31.0\n") }, ReasonUpdateCandidateInSource, ManagerPip, CategoryDependencyUpdateCandidate},
		{"uv", func(f *fakeGitHub) {
			f.put("ex/app", "svc", "pyproject.toml", uvPyproject)
			f.put("ex/app", "svc", "uv.lock", uvLock)
		}, ReasonUpdateCandidateInSource, ManagerUv, CategoryDependencyUpdateCandidate},
		{"pnpm", func(f *fakeGitHub) {
			f.put("ex/app", "svc", "package.json", pnpmManifest)
			f.put("ex/app", "svc", "pnpm-lock.yaml", pnpmLock)
		}, ReasonUpdateCandidateInSource, ManagerPnpm, CategoryDependencyUpdateCandidate},
		{"unsupported lockfile version", func(f *fakeGitHub) {
			f.put("ex/app", "svc", "package.json", npmManifest)
			f.put("ex/app", "svc", "package-lock.json", `{"lockfileVersion":1}`)
		}, ReasonUnsupportedLockfile, ManagerNpm, CategoryManual},
		{"requirements with an include", func(f *fakeGitHub) { f.put("ex/app", "svc", "requirements.txt", "-r base.txt\n") }, ReasonUnsupportedRequirements, ManagerPip, CategoryManual},
	}
	pythonCases := map[string]bool{"uv and requirements": true, "pip only": true, "uv": true, "requirements with an include": true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gh := newFakeGitHub()
			c.setup(gh)
			in := nodeIn
			if pythonCases[c.name] {
				in = pyIn
			}
			plan := langPlan(t, gh, deps, nil, in)
			if len(plan.LanguageItems) != 1 {
				t.Fatalf("units = %d", len(plan.LanguageItems))
			}
			it := plan.LanguageItems[0]
			if it.Category != c.cat || it.Reason != c.reason || it.Manager != c.mgr {
				t.Errorf("item = %s / %s / %s (%s)", it.Category, it.Reason, it.Manager, it.Detail)
			}
			if it.Category == CategoryManual {
				if len(it.Packages) == 0 {
					t.Error("a manual unit keeps its packages listed")
				}
				for _, p := range it.Packages {
					if p.Action != ActionManual || p.Reason != it.Reason {
						t.Errorf("package = %+v", p)
					}
				}
			}
			// No other directory is looked at, except that for pnpm, which looks
			// for pnpm-workspace.yaml above the project, and for uv, which looks
			// for uv.toml there, the directories above it.
			for _, call := range gh.calls {
				if strings.HasPrefix(call, "list:") && !strings.HasPrefix(call, "list:ex/app/svc@") && !((c.mgr == ManagerPnpm || c.mgr == ManagerUv) && strings.HasPrefix(call, "list:ex/app/.@")) {
					t.Errorf("unexpected listing %s", call)
				}
			}
		})
	}
}

func TestLanguagePlan_RebuildAndMixedUnits(t *testing.T) {
	gh := newFakeGitHub()
	gh.put("ex/app", ".", "requirements.txt", requirements)
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}

	plan := langPlan(t, gh, deps, nil, langInput("shop", "api", pyFinding("CVE-1", "urllib3", "1.26.18", "2.2.2"), pyFinding("CVE-2", "Django", "4.2.0", "4.2.14")))
	it := plan.LanguageItems[0]
	if it.Category != CategoryRebuildExpected || it.Reason != ReasonRangeAllowsFix || it.Count(ActionRebuildExpected) != 2 {
		t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
	}

	// One pinned package makes the unit a candidate; the range line is kept
	// in the same unit with its own action.
	plan = langPlan(t, gh, deps, nil, langInput("shop", "api", pyFinding("CVE-1", "urllib3", "1.26.18", "2.2.2"), pyFinding("CVE-3", "requests", "2.31.0", "2.32.0")))
	it = plan.LanguageItems[0]
	if it.Category != CategoryDependencyUpdateCandidate || it.Count(ActionUpdate) != 1 || it.Count(ActionRebuildExpected) != 1 {
		t.Errorf("item = %s: %+v", it.Category, it.Packages)
	}

	// Nothing proposable: the shared reason is kept.
	plan = langPlan(t, gh, deps, nil, langInput("shop", "api", pyFinding("CVE-1", "idna", "3.4", "3.7")))
	it = plan.LanguageItems[0]
	if it.Category != CategoryManual || it.Reason != ReasonNotFoundInSource {
		t.Errorf("item = %s / %s", it.Category, it.Reason)
	}
}

func TestLanguagePlan_GitHubErrors(t *testing.T) {
	in := func() []ImageInput {
		return []ImageInput{
			langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")),
			langInput("shop", "web", nodeFinding("CVE-2", "express", "4.18.2", "4.19.2")),
		}
	}
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/one", "."), depMapping("compose/shop/web", "ex/two", ".")}
	reset := time.Date(2026, 10, 9, 4, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		err       error
		cat       Category
		reason    Reason
		haltsRest bool
	}{
		{"not found", github.ErrNotFound, CategoryFailed, ReasonSourceNotFound, false},
		{"auth required", github.ErrAuthRequired, CategoryFailed, ReasonSourceAccessDenied, false},
		{"forbidden", github.ErrForbidden, CategoryFailed, ReasonSourceAccessDenied, false},
		{"too large", github.ErrTooLarge, CategoryFailed, ReasonSourceTooLarge, false},
		{"server error", &github.StatusError{Status: 502}, CategoryFailed, ReasonSourceError, false},
		{"rate limited", &github.RateLimitedError{Reset: reset}, CategoryDeferred, ReasonRateLimited, true},
		{"budget", github.ErrBudgetExhausted, CategoryDeferred, ReasonGitHubBudget, true},
		{"deadline", context.DeadlineExceeded, CategoryDeferred, ReasonCycleDeadline, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gh := newFakeGitHub()
			npmRepo(gh, "ex/one", ".")
			npmRepo(gh, "ex/two", ".")
			gh.branchErr["ex/one"] = c.err
			plan := langPlan(t, gh, deps, nil, in()...)
			if len(plan.LanguageItems) != 2 {
				t.Fatalf("units = %d", len(plan.LanguageItems))
			}
			first := plan.LanguageItems[0]
			if first.Category != c.cat || first.Reason != c.reason {
				t.Errorf("first = %s / %s (%s)", first.Category, first.Reason, first.Detail)
			}
			if len(first.Packages) != 1 || first.Packages[0].Action != "" {
				t.Errorf("an unread unit lists its packages without a verdict: %+v", first.Packages)
			}
			second := plan.LanguageItems[1]
			if c.haltsRest {
				if second.Category != CategoryDeferred || second.Reason != c.reason {
					t.Errorf("second = %s / %s; the rest of the pass must be deferred", second.Category, second.Reason)
				}
				if gh.count("branch:ex/two") != 0 {
					t.Error("GitHub was asked again after it stopped the pass")
				}
			} else if second.Category != CategoryDependencyUpdateCandidate {
				t.Errorf("second = %s / %s; one unit's failure must not stop the others", second.Category, second.Reason)
			}
			if first.Detail == "" {
				t.Error("no detail")
			}
		})
	}
}

func TestLanguagePlan_ReadFailuresAndCancelledCycle(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/one", ".")}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))

	gh := newFakeGitHub()
	npmRepo(gh, "ex/one", ".")
	gh.readErr["ex/one/package-lock.json"] = github.ErrLFSPointer
	it := langPlan(t, gh, deps, nil, in).LanguageItems[0]
	if it.Category != CategoryManual || it.Reason != ReasonDependencyFileUnusable {
		t.Errorf("an LFS pointer = %s / %s", it.Category, it.Reason)
	}
	if len(it.Source.Files) != 1 || it.Source.Files[0].Path != "package.json" {
		t.Errorf("only the files actually read are recorded: %+v", it.Source.Files)
	}

	gh = newFakeGitHub()
	npmRepo(gh, "ex/one", ".")
	gh.readErr["ex/one/package.json"] = &github.RateLimitedError{}
	it = langPlan(t, gh, deps, nil, in).LanguageItems[0]
	if it.Category != CategoryDeferred || it.Reason != ReasonRateLimited || it.Source.CommitSHA != testCommit {
		t.Errorf("a rate limit while reading = %s / %s", it.Category, it.Reason)
	}

	gh = newFakeGitHub()
	npmRepo(gh, "ex/one", ".")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	it = langPlanCtx(t, ctx, gh, deps, nil, in).LanguageItems[0]
	if it.Category != CategoryDeferred || it.Reason != ReasonCycleDeadline || len(gh.calls) != 0 {
		t.Errorf("a finished cycle = %s / %s, calls %v", it.Category, it.Reason, gh.calls)
	}
}

func TestLanguagePlan_UnitsFollowPriority(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/low", ".")
	npmRepo(gh, "ex/high", ".")
	intel := func(id string) (VulnIntel, bool) {
		if id == "CVE-2" {
			return VulnIntel{Priority: PriorityActNow}, true
		}
		return VulnIntel{Priority: PriorityLow}, true
	}
	deps := []DependencyMapping{depMapping("compose/shop/a", "ex/low", "."), depMapping("compose/shop/b", "ex/high", ".")}
	plan := langPlan(t, gh, deps, intel,
		langInput("shop", "a", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")),
		langInput("shop", "b", nodeFinding("CVE-2", "express", "4.18.2", "4.19.2")))
	if len(plan.LanguageItems) != 2 || !strings.Contains(plan.LanguageItems[0].Key, "ex/high") {
		t.Errorf("order = %v", []string{plan.LanguageItems[0].Key, plan.LanguageItems[1].Key})
	}
}

func TestLanguagePlan_PlanSurvivesTheStore(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}, nil,
		langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")))
	store := PlanStore{Path: t.TempDir() + "/plan.json"}
	if err := store.Save(plan); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.Load()
	if err != nil || !found {
		t.Fatalf("load: %v %v", found, err)
	}
	if len(got.LanguageItems) != 1 || got.LanguageItems[0].Packages[0].SelectionLowerBound != "4.17.21" ||
		got.LanguageItems[0].Source.CommitSHA != testCommit || got.LanguageItems[0].UpdateExecuted {
		t.Errorf("stored language items = %+v", got.LanguageItems)
	}
}

func TestFingerprint_Language(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	mk := func() Plan {
		return langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}, nil,
			langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")))
	}
	a := mk()
	if Fingerprint(a) == "" {
		t.Fatal("a plan with only a language item has the empty fingerprint")
	}
	b := mk()
	b.GeneratedAt = b.GeneratedAt.Add(time.Hour)
	b.LanguageItems[0].Source.CommitSHA = strings.Repeat("f", 40)
	b.LanguageItems[0].Source.Files[0].BlobSHA = strings.Repeat("e", 40)
	b.LanguageItems[0].Detail = "other wording"
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("commit, blobs, time or wording changed the fingerprint")
	}
	for name, mut := range map[string]func(*Plan){
		"target":   func(p *Plan) { p.LanguageItems[0].Packages[0].SelectionLowerBound = "4.17.22" },
		"category": func(p *Plan) { p.LanguageItems[0].Category = CategoryManual },
		"package":  func(p *Plan) { p.LanguageItems[0].Packages[0].Name = "express" },
		"action":   func(p *Plan) { p.LanguageItems[0].Packages[0].Action = ActionManual },
		"workload": func(p *Plan) { p.LanguageItems[0].Workloads = append(p.LanguageItems[0].Workloads, "compose/shop/x") },
	} {
		c := mk()
		mut(&c)
		if Fingerprint(a) == Fingerprint(c) {
			t.Errorf("a changed %s did not change the fingerprint", name)
		}
	}
	// Plans without language items keep their fingerprint.
	if Fingerprint(Plan{}) != "" {
		t.Error("an empty plan must have the empty fingerprint")
	}
}

func TestLanguagePlan_MixedEcosystemDirectoryIsTwoUnits(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "svc")
	gh.put("ex/app", "svc", "requirements.txt", requirements)
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}
	plan := langPlan(t, gh, deps, nil, langInput("shop", "api",
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
		pyFinding("CVE-2", "requests", "2.31.0", "2.32.0")))
	if len(plan.LanguageItems) != 2 {
		t.Fatalf("units = %d, want one per ecosystem", len(plan.LanguageItems))
	}
	byManager := map[DependencyManager]LanguageItem{}
	for _, it := range plan.LanguageItems {
		byManager[it.Manager] = it
	}
	npm, pip := byManager[ManagerNpm], byManager[ManagerPip]
	if npm.Category != CategoryDependencyUpdateCandidate || len(npm.Packages) != 1 || npm.Packages[0].Name != "lodash" || npm.Key != "deps:ex/app@main:svc#npm" {
		t.Errorf("npm unit = %s %q %+v", npm.Category, npm.Key, npm.Packages)
	}
	if pip.Category != CategoryDependencyUpdateCandidate || len(pip.Packages) != 1 || pip.Packages[0].Name != "requests" || pip.Key != "deps:ex/app@main:svc#pip" {
		t.Errorf("pip unit = %s %q %+v", pip.Category, pip.Key, pip.Packages)
	}
	if len(npm.Source.Files) != 2 || len(pip.Source.Files) != 1 || npm.Source.CommitSHA != testCommit || pip.Source.CommitSHA != testCommit {
		t.Errorf("sources: %+v / %+v", npm.Source, pip.Source)
	}
	if gh.count("branch:") != 1 || gh.count("list:") != 1 {
		t.Errorf("the branch and directory are read once for both: %v", gh.calls)
	}
}
