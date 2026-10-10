package remediation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	testRepo   = "example/app"
	testRepoID = 101
	composeYML = `services:
  web:
    image: nginx:1.25.3
  worker:
    image: nginx:1.25.3
  db:
    image: postgres:16.1.0
`
)

func topDigest(c byte) string { return "sha256:" + hex64(c) }

func testContainers() []inventory.Container {
	d := configKey('a').Digest
	mk := func(name, project, service string) inventory.Container {
		return inventory.Container{Name: name, Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: project, Name: service},
			Image: inventory.RunningImage{Ref: "nginx:1.25.3", Config: d}}
	}
	return []inventory.Container{mk("app-web-1", "app", "web"), mk("app-worker-1", "app", "worker"), mk("other-extra-1", "other", "extra")}
}

func testMappings() []ComposeMapping {
	mk := func(service string) ComposeMapping {
		return ComposeMapping{Workload: "compose/app/" + service, Project: "app", Service: service, Repository: testRepo,
			BaseBranch: "main", Path: "compose.yml", ComposeService: service}
	}
	return []ComposeMapping{mk("web"), mk("worker")}
}

func pkgCoord(name string) PackageCoord {
	return PackageCoord{Ecosystem: inventory.Ecosystem("debian"), Class: inventory.ClassOS, Name: name}
}

// nginxItem is an adopted candidate for the running nginx:1.25.3: every
// vulnerability in resolved is resolved, every one in remaining remains.
func nginxItem(tag string, top byte, resolved, remaining []string) Item {
	it := Item{
		Key:      "nginx:1.25.3|" + entityString(configKey('a')),
		Services: []ServiceRef{{Project: "app", Service: "web", Container: "app-web-1"}, {Project: "app", Service: "worker", Container: "app-worker-1"}, {Project: "other", Service: "extra", Container: "other-extra-1"}},
		Kind:     TagPinned, Category: CategoryPRCandidate, Reason: ReasonAdopted,
		Current:      ImageState{Ref: "nginx:1.25.3", Tag: "1.25.3", Entity: entityString(configKey('a')), ConfigDigest: "sha256:" + hex64('a'), Platform: "linux/amd64", DigestKindUnverified: true},
		Candidate:    &ImageState{Ref: "nginx:" + tag, Tag: tag, TopDigest: topDigest(top), ManifestDigest: "sha256:" + hex64('m'), ConfigDigest: "sha256:" + hex64('c'), Platform: "linux/amd64"},
		BaselineScan: "s1", CandidateScan: "s2",
		Comparison: &VerificationResult{Comparable: true, Severities: []string{"CRITICAL", "HIGH"}, Scope: "only findings of severity CRITICAL, HIGH were evaluated"},
	}
	for _, id := range resolved {
		it.Targets = append(it.Targets, Target{VulnID: id, Package: pkgCoord("pkg-" + id), Severity: scanner.Severity("HIGH")})
		it.Comparison.Verdicts = append(it.Comparison.Verdicts, VulnVerdict{VulnID: id, Package: pkgCoord("pkg-" + id), Outcome: OutcomeResolved})
	}
	for _, id := range remaining {
		it.Targets = append(it.Targets, Target{VulnID: id, Package: pkgCoord("pkg-" + id)})
		it.Comparison.Verdicts = append(it.Comparison.Verdicts, VulnVerdict{VulnID: id, Package: pkgCoord("pkg-" + id), Outcome: OutcomeRemaining})
	}
	return it
}

func testPlan(items ...Item) Plan {
	return Plan{Version: PlanVersion, GeneratedAt: time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC), Conditions: testConds("db1"), Items: items}
}

type prHarness struct {
	t          *testing.T
	gh         *fakePRGitHub
	store      PRStorage
	dir        string
	limits     PRLimits
	containers []inventory.Container
	mappings   []ComposeMapping
	clock      time.Time
}

func newPRHarness(t *testing.T) *prHarness {
	t.Helper()
	gh := newFakePRGitHub()
	gh.addRepo(testRepo, testRepoID, map[string]string{"compose.yml": composeYML})
	gh.tops["nginx:1.25.4"] = topDigest('1')
	gh.tops["nginx:1.25.5"] = topDigest('2')
	dir := filepath.Join(t.TempDir(), "state")
	return &prHarness{t: t, gh: gh, store: PRStore{Dir: dir}, dir: dir, limits: PRLimits{NewPRsPerCycle: 3, OpenPRs: 10},
		containers: testContainers(), mappings: testMappings(), clock: time.Date(2026, 10, 9, 4, 0, 0, 0, time.UTC)}
}

func (h *prHarness) run(plan Plan) PRStageResult {
	h.t.Helper()
	h.clock = h.clock.Add(24 * time.Hour)
	now := h.clock
	stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: h.gh, Store: h.store, Limits: h.limits, Now: func() time.Time { return now }})
	if err != nil {
		h.t.Fatal(err)
	}
	res := stage.Run(context.Background(), PRStageInput{Plan: plan, Containers: h.containers, Mappings: h.mappings})
	h.gh.checkInvariants(h.t)
	return res
}

func (h *prHarness) load() PRStoreFile {
	h.t.Helper()
	f, found, err := PRStore{Dir: h.dir}.Load()
	if err != nil || !found {
		h.t.Fatalf("load records: found=%v err=%v", found, err)
	}
	return f
}

func onlyUnit(t *testing.T, res PRStageResult) PRUnit {
	t.Helper()
	if len(res.Units) != 1 {
		t.Fatalf("units = %+v, want one", res.Units)
	}
	return res.Units[0]
}

func wantStatus(t *testing.T, u PRUnit, status PRUnitStatus, reason Reason) {
	t.Helper()
	if u.Status != status || u.Reason != reason {
		t.Fatalf("unit status %s/%s (%s), want %s/%s", u.Status, u.Reason, u.Detail, status, reason)
	}
}

func countCalls(gh *fakePRGitHub, method string) int {
	gh.mu.Lock()
	defer gh.mu.Unlock()
	n := 0
	for _, c := range gh.calls {
		if strings.HasPrefix(c, method+" ") {
			n++
		}
	}
	return n
}

func TestPRStageHappyPath(t *testing.T) {
	h := newPRHarness(t)
	res := h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if u.Number != 1 || u.State != PRStateOpen || len(u.Services) != 2 || u.UpdateKey == "" || u.AttemptKey == "" {
		t.Errorf("unit = %+v", u)
	}
	if len(u.AlsoRunning) != 1 || u.AlsoRunning[0].Service != "extra" {
		t.Errorf("also running = %+v", u.AlsoRunning)
	}
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 1 {
		t.Fatalf("pulls = %d", len(pulls))
	}
	pr := pulls[0]
	if pr.Title != "Update nginx to 1.25.4 in compose.yml" || !strings.HasPrefix(pr.HeadRef, "kestrelynx/compose/web-and-1-1.25.4-") {
		t.Errorf("title %q head %q", pr.Title, pr.HeadRef)
	}
	lines := strings.Split(strings.TrimRight(pr.Body, "\n"), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], markerPrefix) {
		t.Errorf("the marker is not the last line: %q", lines[len(lines)-1])
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.verify(testRepoID) != nil || m.HeadSHA != pr.HeadSHA || m.UpdateKey != u.UpdateKey {
		t.Fatalf("marker %+v err %v", m, err)
	}
	// The edited file holds the new tag for both services and nothing else.
	f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "compose.yml")
	if err != nil || string(f.Content) != strings.ReplaceAll(composeYML, "nginx:1.25.3", "nginx:1.25.4") || f.Mode != "100644" {
		t.Errorf("edited file %q mode %q err %v", f.Content, f.Mode, err)
	}
	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].State != PRStateOpen || len(rec.Attempts) != 1 || rec.Attempts[0].Status != AttemptPRCreated {
		t.Errorf("records = %+v", rec)
	}
	if rec.PRs[0].Evidence == nil || len(rec.PRs[0].FixTargets) != 2 {
		t.Errorf("fix targets %+v evidence %v", rec.PRs[0].FixTargets, rec.PRs[0].Evidence != nil)
	}
	// Five writes, each an intent and a result event.
	if len(res.Operations) != 10 || res.LastSeq != res.Operations[9].Seq {
		t.Fatalf("operations = %d, last %d", len(res.Operations), res.LastSeq)
	}
	kinds := []OperationKind{OpCreateBlob, OpCreateTree, OpCreateCommit, OpCreateRef, OpCreatePull}
	for i, k := range kinds {
		in, out := res.Operations[2*i], res.Operations[2*i+1]
		if in.Kind != k || in.Phase != PhaseIntent || out.Phase != PhaseResult || out.Result != ResultOK || out.ID != in.ID {
			t.Errorf("operation %d = %+v / %+v", i, in, out)
		}
	}

	// The next cycle sees the open pull request and writes nothing.
	writes := h.gh.writeCount()
	if err := MarkPROperationsDelivered(h.store, res.LastSeq); err != nil {
		t.Fatal(err)
	}
	res2 := h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	wantStatus(t, onlyUnit(t, res2), PRStatusOpen, "")
	if h.gh.writeCount() != writes || len(res2.Operations) != 0 || len(res2.Problems) != 0 {
		t.Errorf("second cycle wrote %d, operations %d, problems %+v", h.gh.writeCount()-writes, len(res2.Operations), res2.Problems)
	}
	if Fingerprint(planWith(res)) == Fingerprint(planWith(res2)) {
		t.Error("a created and an open pull request fingerprint the same")
	}
}

func planWith(res PRStageResult) Plan {
	p := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	res.Attach(&p)
	return p
}

func TestPRStageOpenWithDifferentAttemptKey(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.run(plan)
	// The base moves (another file changes): the attempt key would differ,
	// the update key does not.
	h.gh.commitFiles(testRepo, "main", map[string]string{"README": "x"})
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusOpen, "")
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageClosedAndMerged(t *testing.T) {
	for _, merged := range []bool{false, true} {
		h := newPRHarness(t)
		plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		h.run(plan)
		h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State, p.Merged = "closed", merged })
		u := onlyUnit(t, h.run(plan))
		if merged {
			wantStatus(t, u, PRStatusMerged, "")
		} else {
			wantStatus(t, u, PRStatusSuppressed, "")
		}
		// Never recreated, even with a new base.
		h.gh.commitFiles(testRepo, "main", map[string]string{"README": "y"})
		h.run(plan)
		if n := len(h.gh.pulls(testRepo)); n != 1 {
			t.Errorf("merged=%v: pulls = %d", merged, n)
		}
	}
}

// twoUnitHarness has a second Compose file with its own unit.
func twoUnitHarness(t *testing.T) (*prHarness, Plan) {
	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"db.yml": "services:\n  db:\n    image: postgres:16.1.0\n"})
	h.gh.humanMoved = map[string]bool{}
	h.gh.tops["postgres:16.1.1"] = topDigest('3')
	d := configKey('b').Digest
	h.containers = append(h.containers, inventory.Container{Name: "app-db-1", Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "app", Name: "db"},
		Image: inventory.RunningImage{Ref: "postgres:16.1.0", Config: d}})
	h.mappings = append(h.mappings, ComposeMapping{Workload: "compose/app/db", Project: "app", Service: "db", Repository: testRepo, BaseBranch: "main", Path: "db.yml", ComposeService: "db"})
	pg := nginxItem("1.25.4", '1', []string{"CVE-9"}, nil)
	pg.Key = "postgres:16.1.0|" + entityString(configKey('b'))
	pg.Services = []ServiceRef{{Project: "app", Service: "db", Container: "app-db-1"}}
	pg.Current = ImageState{Ref: "postgres:16.1.0", Tag: "16.1.0", Entity: entityString(configKey('b')), Platform: "linux/amd64"}
	pg.Candidate = &ImageState{Ref: "postgres:16.1.1", Tag: "16.1.1", TopDigest: topDigest('3'), Platform: "linux/amd64"}
	return h, testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil), pg)
}

func TestPRStageLimits(t *testing.T) {
	h, plan := twoUnitHarness(t)
	h.limits = PRLimits{NewPRsPerCycle: 1, OpenPRs: 10}
	res := h.run(plan)
	if len(res.Units) != 2 {
		t.Fatalf("units = %+v", res.Units)
	}
	wantStatus(t, res.Units[0], PRStatusCreated, "")
	wantStatus(t, res.Units[1], PRStatusDeferred, ReasonPRLimit)

	// Open limit: one is open and the limit is one.
	h.limits = PRLimits{NewPRsPerCycle: 5, OpenPRs: 1}
	res = h.run(plan)
	wantStatus(t, res.Units[0], PRStatusOpen, "")
	wantStatus(t, res.Units[1], PRStatusDeferred, ReasonPRLimit)
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
	h.limits = PRLimits{NewPRsPerCycle: 5, OpenPRs: 2}
	res = h.run(plan)
	wantStatus(t, res.Units[1], PRStatusCreated, "")
}

func TestPRStageCandidateChanged(t *testing.T) {
	h := newPRHarness(t)
	h.gh.tops["nginx:1.25.4"] = topDigest('9')
	res := h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	wantStatus(t, onlyUnit(t, res), PRStatusDeferred, ReasonCandidateChanged)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

func TestPRStageCandidateChangedRightBeforeCreatePull(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.afterWrite["CreateRef"] = func() { h.gh.tops["nginx:1.25.4"] = topDigest('9') }
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonCandidateChanged)
	if countCalls(h.gh, "CreatePull") != 0 {
		t.Error("CreatePull was sent")
	}
	// The branch stays; once the tag is back, the attempt resumes from it.
	h.gh.tops["nginx:1.25.4"] = topDigest('1')
	refs := countCalls(h.gh, "CreateRef")
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusCreated, "")
	if countCalls(h.gh, "CreateRef") != refs {
		t.Error("the branch was created again instead of resumed")
	}
}

func TestPRStageEditProblemIsManual(t *testing.T) {
	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"compose.yml": strings.Replace(composeYML, "  worker:\n", "  worker:\n    build: .\n", 1)})
	u := onlyUnit(t, h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))))
	wantStatus(t, u, PRStatusManual, ReasonComposeBuild)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

func TestPRStageRefExists(t *testing.T) {
	t.Run("ours", func(t *testing.T) {
		h := newPRHarness(t)
		h.gh.failNext("CreateRef", refExistsOurs)
		wantStatus(t, onlyUnit(t, h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))), PRStatusCreated, "")
	})
	t.Run("not ours", func(t *testing.T) {
		h := newPRHarness(t)
		h.gh.failNext("CreateRef", refExistsOther)
		plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusWriteBlocked, ReasonBranchNotOurs)
		if len(h.gh.pulls(testRepo)) != 0 {
			t.Error("a pull request was opened from a foreign branch")
		}
		// The branch is never touched and the target stays blocked.
		res := h.run(plan)
		wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonAttemptUnsettled)
		if countCalls(h.gh, "CreateRef") != 1 {
			t.Errorf("CreateRef calls = %d", countCalls(h.gh, "CreateRef"))
		}
	})
}

func TestPRStageBaseMovedBeforePull(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.afterWrite["CreateRef"] = func() { h.gh.commitFiles(testRepo, "main", map[string]string{"README": "moved"}) }
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonBaseMoved)
	first := h.load().Attempts[0]

	// Next cycle: the old branch is kept without a pull request and a new
	// attempt on the new base opens the pull request.
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	rec := h.load()
	if len(rec.Attempts) != 2 {
		t.Fatalf("attempts = %+v", rec.Attempts)
	}
	old := rec.Attempts[0]
	if old.AttemptKey != first.AttemptKey || old.Status != AttemptAbandonedWithoutPR || old.UpdateKey != rec.Attempts[1].UpdateKey {
		t.Errorf("old attempt = %+v", old)
	}
	if sha, ok, _ := h.gh.Ref(context.Background(), testRepo, old.Branch); !ok || sha != old.CommitSHA {
		t.Error("the old branch was not kept")
	}
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageAbandonedWhenRefAbsent(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.failNext("CreateCommit", failLost)
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonWriteOutcomeUnknown)
	if countCalls(h.gh, "CreateRef") != 0 {
		t.Fatal("writes continued after an unknown outcome")
	}
	// No branch exists: the attempt is abandoned and started again.
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	if countCalls(h.gh, "CreateCommit") != 2 {
		t.Errorf("CreateCommit calls = %d", countCalls(h.gh, "CreateCommit"))
	}
	settled := false
	for _, op := range res.Operations {
		if op.Phase == PhaseSettled && op.Kind == OpCreateCommit && op.Result == ResultUnknown {
			settled = true
		}
	}
	if !settled {
		t.Errorf("no settlement of the unknown commit: %+v", res.Operations)
	}
}

func TestPRStageResponseLossAfterCreatePull(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.failNext("CreatePull", failLost)
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusDeferred, ReasonWriteOutcomeUnknown)
	last := res.Operations[len(res.Operations)-1]
	if last.Kind != OpCreatePull || last.Result != ResultUnknown {
		t.Fatalf("last operation = %+v", last)
	}
	if err := MarkPROperationsDelivered(h.store, res.LastSeq); err != nil {
		t.Fatal(err)
	}
	// The next cycle adopts the pull request instead of opening another,
	// and delivers the settled outcome again under the same operation ID.
	res2 := h.run(plan)
	wantStatus(t, onlyUnit(t, res2), PRStatusOpen, "")
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Fatalf("pulls = %d", n)
	}
	if len(res2.Operations) != 1 || res2.Operations[0].Phase != PhaseSettled || res2.Operations[0].ID != last.ID || res2.Operations[0].Result != ResultOK {
		t.Errorf("operations = %+v", res2.Operations)
	}
	if res2.Operations[0].Seq <= res.LastSeq {
		t.Error("the settled event reuses a delivered sequence number")
	}
}

func TestPRStageAdoptsMergedPullWithDeletedBranch(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.failNext("CreatePull", failLost)
	h.run(plan)
	pr := h.gh.pulls(testRepo)[0]
	h.gh.editPull(testRepo, pr.Number, func(p *github.PullRequest) { p.State, p.Merged = "closed", true })
	h.gh.deleteBranch(testRepo, pr.HeadRef)
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusMerged, "")
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageSaveFailureStopsWrites(t *testing.T) {
	for _, okSaves := range []int{0, 1, 3, 6, 9} {
		h := newPRHarness(t)
		plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		real := h.store
		fs := &faultyStore{PRStorage: real, okSaves: okSaves, gh: h.gh}
		h.store = fs
		res := h.run(plan)
		var problem bool
		for _, p := range res.Problems {
			problem = problem || p.Code == PRProblemStorageFailed
		}
		if !problem {
			t.Errorf("okSaves=%d: no storage_failed problem: %+v", okSaves, res.Problems)
		}
		writesAtFailure := h.gh.writeCount()
		if !fs.failedSet || writesAtFailure != fs.failedAt {
			t.Errorf("okSaves=%d: %d writes after the failed save", okSaves, writesAtFailure-fs.failedAt)
		}
		// With a working store the next cycles finish with one pull request.
		h.store = real
		h.run(plan)
		h.run(plan)
		if n := len(h.gh.pulls(testRepo)); n != 1 {
			t.Errorf("okSaves=%d: pulls = %d (writes at failure %d)", okSaves, n, writesAtFailure)
		}
	}
}

// faultyStore fails every save after okSaves successful ones and notes how
// many writes the fake had seen when the first save failed.
type faultyStore struct {
	PRStorage
	okSaves   int
	saves     int
	gh        *fakePRGitHub
	failedAt  int
	failedSet bool
}

func (s *faultyStore) Save(f PRStoreFile) error {
	s.saves++
	if s.saves > s.okSaves {
		if !s.failedSet {
			s.failedSet, s.failedAt = true, s.gh.writeCount()
		}
		return errors.New("disk full (test)")
	}
	return s.PRStorage.Save(f)
}

func TestPRStageLockHeld(t *testing.T) {
	h := newPRHarness(t)
	unlock, err := h.store.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	res := h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonStoreLocked)
	if len(res.Problems) != 1 || res.Problems[0].Code != PRProblemWriteBlocked || len(h.gh.calls) != 0 {
		t.Errorf("problems %+v calls %v", res.Problems, h.gh.calls)
	}
}

func TestPRStageZeroCandidatesStillReconciles(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State, p.Merged = "closed", true })
	res := h.run(testPlan())
	if len(res.Units) != 0 {
		t.Errorf("units = %+v", res.Units)
	}
	if st := h.load().PRs[0].State; st != PRStateMerged {
		t.Errorf("record state = %s", st)
	}
	// An open pull request on a kestrelynx/ branch without a marker blocks
	// writes even with nothing to propose.
	h.gh.addForeignPull(testRepo, github.PullRequest{HeadRef: "kestrelynx/compose/x-1.0.0-000000000000", HeadSHA: hex40('e'), HeadRepoFullName: testRepo, BaseRef: "main", User: "someone", Body: "no marker"})
	res = h.run(testPlan())
	if len(res.Problems) != 1 || res.Problems[0].Code != PRProblemRecordsUnverified || res.Problems[0].Repo != testRepo {
		t.Errorf("problems = %+v", res.Problems)
	}
}

func hex40(c byte) string { return strings.Repeat(string(c), 40) }

func TestPRStageRecoveryFromMarkers(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.run(plan)
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusOpen, "")
	rec := h.load()
	if len(rec.PRs) != 1 || !rec.PRs[0].Recovered || rec.InitializedAt.IsZero() || len(rec.Repos) != 1 || rec.Repos[0].RepoID != testRepoID {
		t.Errorf("recovered records = %+v", rec)
	}
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageRecoveryIsStrict(t *testing.T) {
	cases := map[string]string{
		"no marker":  "a description without a marker",
		"bad json":   markerPrefix + `{"v":1,` + markerSuffix,
		"unknown v":  markerPrefix + `{"v":2}` + markerSuffix,
		"bad fields": "", // filled below: keys that do not recompute
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h := newPRHarness(t)
			if name == "bad fields" {
				m := PRMarker{V: 1, RepoID: testRepoID, BaseBranch: "main", Path: "compose.yml", Locations: []string{"services.web.image"},
					CurrentRef: "nginx:1.25.3", CandidateTag: "1.25.4", CandidateDigest: topDigest('1'), BaseSHA: hex40('1'), HeadSHA: hex40('2'),
					InputBlobSHA: hex40('3'), Changes: []FileChange{{Path: "compose.yml", Mode: "100644", BlobSHA: hex40('4')}},
					TargetKey: "t", UpdateKey: "u", AttemptKey: "aaaaaaaaaaaaaaaa"}
				body = encodeMarker(m)
			}
			h.gh.addForeignPull(testRepo, github.PullRequest{State: "closed", HeadRef: "kestrelynx/compose/web-1.25.4-aaaaaaaaaaaa", HeadSHA: hex40('2'), HeadRepoFullName: testRepo, BaseRef: "main", User: "bot2", Body: body})
			res := h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
			wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonRecordsUnverified)
			if h.gh.writeCount() != 0 {
				t.Errorf("writes = %d", h.gh.writeCount())
			}
			if _, err := os.Stat(filepath.Join(h.dir, "prs.json")); !os.IsNotExist(err) {
				t.Errorf("the record file was written: %v", err)
			}
		})
	}
}

func TestPRStageMultiRepoRecoveryFailureBlocksAll(t *testing.T) {
	h, plan := twoUnitHarness(t)
	h.gh.addRepo("example/other", 202, map[string]string{"compose.yml": composeYML})
	h.mappings = append(h.mappings, ComposeMapping{Workload: "compose/other/svc", Project: "other", Service: "svc", Repository: "example/other", BaseBranch: "main", Path: "compose.yml", ComposeService: "web"})
	h.gh.failNext("ListPulls example/other", failError)
	res := h.run(plan)
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusWriteBlocked, ReasonRecordsUnverified)
	}
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
	if len(res.Problems) != 1 || res.Problems[0].Code != PRProblemRecordsUnverified {
		t.Errorf("problems = %+v", res.Problems)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "prs.json")); !os.IsNotExist(err) {
		t.Error("records were initialized although a repository failed")
	}
	// Once every repository can be examined, the writes go ahead.
	res = h.run(plan)
	wantStatus(t, res.Units[0], PRStatusCreated, "")
}

func TestPRStageForkPullsAreIgnored(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.run(plan)
	ours := h.gh.pulls(testRepo)[0]
	// A fork copies the branch name and the marker of our pull request.
	h.gh.addForeignPull(testRepo, github.PullRequest{HeadRef: ours.HeadRef, HeadSHA: ours.HeadSHA, HeadRepoFullName: "mallory/app", BaseRef: "main", User: "mallory", Body: ours.Body})
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusOpen, "")
	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].Number != ours.Number {
		t.Errorf("records = %+v", rec.PRs)
	}
	if len(res.Problems) != 0 {
		t.Errorf("problems = %+v", res.Problems)
	}
}

func TestPRStageUserModifiedIsProtected(t *testing.T) {
	for _, change := range []string{"head", "base"} {
		t.Run(change, func(t *testing.T) {
			h := newPRHarness(t)
			h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
			if change == "head" {
				h.gh.pushToPull(testRepo, 1)
			} else {
				h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.BaseRef = "release" })
			}
			// A newer candidate resolving everything would replace #1, but
			// a pull request someone changed is never replaced.
			res := h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1", "CVE-2"}, nil)))
			wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
			rec := h.load()
			old := rec.PRs[0]
			if !old.UserModified || old.State != PRStateOpen {
				t.Errorf("old record = %+v", old)
			}
			if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
				t.Errorf("old pull request touched: %+v", p)
			}
			// Its update stays suppressed as open.
			wantStatus(t, onlyUnit(t, h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))), PRStatusOpen, "")
		})
	}
}

func TestPRStageReplacement(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	res := h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1", "CVE-2"}, nil)))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Replaced) != 1 || u.Replaced[0] != 1 {
		t.Errorf("replaced = %v (%+v)", u.Replaced, u.Replacing)
	}
	old := h.gh.pulls(testRepo)[0]
	if old.State != "closed" {
		t.Errorf("old pull request state = %s", old.State)
	}
	cs := h.gh.comments(testRepo, 1)
	if len(cs) != 1 || !hasSupersedeMarker(cs[0].Body, 2, u.UpdateKey) || !strings.HasPrefix(cs[0].Body, "Superseded by #2 (https://github.com/example/app/pull/2)") {
		t.Errorf("comments = %+v", cs)
	}
	rec := h.load()
	if rec.PRs[0].State != PRStateReplaced || rec.PRs[0].ReplacedBy != 2 {
		t.Errorf("old record = %+v", rec.PRs[0])
	}
	// The comment came before the close.
	var order []string
	for _, c := range h.gh.calls {
		if strings.HasPrefix(c, "CreateIssueComment") || strings.HasPrefix(c, "ClosePull") {
			order = append(order, strings.Fields(c)[0])
		}
	}
	if strings.Join(order, ",") != "CreateIssueComment,ClosePull" {
		t.Errorf("order = %v", order)
	}
}

func TestPRStagePartialCoverageKeepsOldPull(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1", "CVE-3"}, nil)))
	res := h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, []string{"CVE-3"})))
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	if p := h.gh.pulls(testRepo)[0]; p.State != "open" {
		t.Error("the old pull request was closed although the new one does not resolve all its targets")
	}
	if len(h.load().PRs[1].Replacing) != 0 {
		t.Error("a replacement was decided")
	}
}

func TestPRStageReplacementOnlyAfterNewPull(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	h.gh.failNext("CreatePull", failRefused)
	res := h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil)))
	wantStatus(t, onlyUnit(t, res), PRStatusFailed, ReasonGitHubRefused)
	if countCalls(h.gh, "CreateIssueComment")+countCalls(h.gh, "ClosePull") != 0 {
		t.Error("the old pull request was touched before the new one existed")
	}
}

func TestPRStageCommentFoundByMarkerIsNotReposted(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	plan2 := testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))
	h.gh.failNext("CreateIssueComment", failLost)
	h.run(plan2)
	if countCalls(h.gh, "ClosePull") != 0 {
		t.Fatal("closed after an unknown comment outcome")
	}
	h.run(plan2)
	if cs := h.gh.comments(testRepo, 1); len(cs) != 1 {
		t.Errorf("comments = %d", len(cs))
	}
	if p := h.gh.pulls(testRepo)[0]; p.State != "closed" {
		t.Error("the old pull request was not closed")
	}
	if rec := h.load(); rec.PRs[0].State != PRStateReplaced {
		t.Errorf("old record = %+v", rec.PRs[0])
	}
}

func TestPRStageUnknownCloseSettledLater(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	plan2 := testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))
	h.gh.failNext("ClosePull", failLost)
	h.run(plan2)
	if rec := h.load(); rec.PRs[1].Replacing[0].State != ReplacementClosed || rec.PRs[0].State != PRStateOpen {
		t.Fatalf("after unknown close: %+v", rec.PRs)
	}
	h.run(plan2)
	rec := h.load()
	if rec.PRs[0].State != PRStateReplaced || rec.PRs[0].ReplacedBy != 2 || rec.PRs[1].Replacing[0].State != ReplacementDone {
		t.Errorf("settled: %+v", rec.PRs)
	}
	if countCalls(h.gh, "ClosePull") != 1 {
		t.Errorf("ClosePull calls = %d", countCalls(h.gh, "ClosePull"))
	}
}

func TestPRStageMergedWinsAfterUnknownClose(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	plan2 := testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))
	h.gh.failNext("ClosePull", failLostNotApplied)
	h.run(plan2)
	h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State, p.Merged = "closed", true })
	h.run(plan2)
	rec := h.load()
	if rec.PRs[0].State != PRStateMerged || rec.PRs[0].ReplacedBy != 0 {
		t.Errorf("old record = %+v", rec.PRs[0])
	}
}

func TestPRStageOperationCapStorageFull(t *testing.T) {
	h := newPRHarness(t)
	// A record file whose log is nearly full of undelivered events.
	f := PRStoreFile{Version: PRStoreVersion, NextSeq: 1, InitializedAt: h.clock,
		Repos: []RepoInit{{Repo: testRepo, RepoID: testRepoID, InitializedAt: h.clock}}}
	for i := 0; i < maxOperationEvents-5; i++ {
		f.Operations = append(f.Operations, OperationEvent{Seq: f.NextSeq, ID: "old", Phase: PhaseResult, Kind: OpCreateBlob, Repo: testRepo, Result: ResultOK})
		f.NextSeq++
	}
	if err := h.store.Save(f); err != nil {
		t.Fatal(err)
	}
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonStorageFull)
	if h.gh.writeCount() != 0 || len(res.Problems) != 1 || res.Problems[0].Code != PRProblemStorageFull {
		t.Errorf("writes %d problems %+v", h.gh.writeCount(), res.Problems)
	}
	if len(res.Operations) != maxOperationEvents-5 {
		t.Errorf("undelivered events = %d", len(res.Operations))
	}
	// Once delivered, old events make room.
	if err := MarkPROperationsDelivered(h.store, res.LastSeq); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusCreated, "")
	if n := len(h.load().Operations); n > maxOperationEvents {
		t.Errorf("log holds %d events", n)
	}
}

func TestPRStageManualUnitsNeedNoGitHub(t *testing.T) {
	h := newPRHarness(t)
	it := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
	// The worker runs another entity that has no plan item.
	h.containers[1].Image.Config = configKey('z').Digest
	res := h.run(testPlan(it))
	wantStatus(t, onlyUnit(t, res), PRStatusManual, ReasonComposeSetNotAdopted)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

func TestPRStageRateLimitDefers(t *testing.T) {
	h, plan := twoUnitHarness(t)
	h.gh.failNext("CreateBlob", failRate)
	res := h.run(plan)
	wantStatus(t, res.Units[0], PRStatusDeferred, ReasonGitHubRateLimited)
	wantStatus(t, res.Units[1], PRStatusDeferred, ReasonGitHubRateLimited)
	res = h.run(plan)
	wantStatus(t, res.Units[0], PRStatusCreated, "")
	wantStatus(t, res.Units[1], PRStatusCreated, "")
}

func TestPRStageRenamedRepositoryIsBlocked(t *testing.T) {
	h := newPRHarness(t)
	h.gh.repos[testRepo].info.FullName = "example/renamed"
	res := h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonRepositoryMismatch)
	if len(res.Problems) != 2 || res.Problems[0].Code != PRProblemRecordsUnverified || res.Problems[1].Code != PRProblemWriteBlocked {
		t.Errorf("problems = %+v", res.Problems)
	}
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

// lostRecordsAfterBranch runs a cycle that creates the branch but stops
// before the pull request, then deletes the record file. It returns the
// branch and the commit it points at.
func lostRecordsAfterBranch(t *testing.T, h *prHarness, plan Plan) (string, string) {
	t.Helper()
	h.gh.afterWrite["CreateRef"] = func() { h.gh.tops["nginx:1.25.4"] = topDigest('9') }
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonCandidateChanged)
	h.gh.tops["nginx:1.25.4"] = topDigest('1')
	a := h.load().Attempts[0]
	if a.Status != AttemptRefCreated || h.gh.branch(testRepo, a.Branch) != a.CommitSHA {
		t.Fatalf("attempt = %+v", a)
	}
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	return a.Branch, a.CommitSHA
}

func TestPRStageAdoptsSameChangeBranchAfterRecordsLost(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	branch, commit := lostRecordsAfterBranch(t, h, plan)

	// Recovery finds no pull request; the new attempt has the same key, its
	// branch exists at a commit of the same change, which is adopted.
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 1 || pulls[0].HeadRef != branch || pulls[0].HeadSHA != commit {
		t.Fatalf("pulls = %+v", pulls)
	}
	if h.gh.branch(testRepo, branch) != commit {
		t.Error("the branch moved")
	}
	m, err := parsePRMarker(pulls[0].Body)
	if err != nil || m.HeadSHA != commit {
		t.Errorf("marker head %s err %v", m.HeadSHA, err)
	}
	rec := h.load()
	if len(rec.Attempts) != 1 || rec.Attempts[0].CommitSHA != commit || rec.Attempts[0].Status != AttemptPRCreated || rec.PRs[0].HeadSHA != commit {
		t.Errorf("records = %+v", rec)
	}
	adopted := false
	for _, op := range res.Operations {
		if op.Kind == OpCreateRef && op.Phase == PhaseSettled && op.Result == ResultOK && op.Ref == commit {
			adopted = true
		}
	}
	if !adopted {
		t.Errorf("no operation event records the adoption: %+v", res.Operations)
	}
	// The pull request is not replaced or duplicated later.
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusOpen, "")
}

func TestPRStageLostRecordsBranchWithOtherTreeIsBlocked(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	branch, _ := lostRecordsAfterBranch(t, h, plan)
	// Same parent (the base), different tree.
	h.gh.pointBranchAtBase(testRepo, branch)
	moved := h.gh.branch(testRepo, branch)
	res := h.run(plan)
	wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonBranchNotOurs)
	if len(h.gh.pulls(testRepo)) != 0 || h.gh.branch(testRepo, branch) != moved {
		t.Error("a pull request was opened or the branch was touched")
	}
}

func TestPRStageSameChangeBranch(t *testing.T) {
	t.Run("no record: adopted", func(t *testing.T) {
		h := newPRHarness(t)
		h.gh.failNext("CreateRef", refExistsSameContent)
		wantStatus(t, onlyUnit(t, h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))), PRStatusCreated, "")
	})
	t.Run("record exists: strict", func(t *testing.T) {
		h := newPRHarness(t)
		plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		// The first branch creation is refused, leaving an attempt record that
		// the next cycle abandons (no branch) and starts again.
		h.gh.failNext("CreateRef", failRefused)
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusFailed, ReasonGitHubRefused)
		h.gh.failNext("CreateRef", refExistsSameContent)
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusWriteBlocked, ReasonBranchNotOurs)
		if len(h.gh.pulls(testRepo)) != 0 {
			t.Error("a pull request was opened from a branch that is not the recorded commit")
		}
	})
}

func findProblem(res PRStageResult, code PRProblemCode, reason Reason) *PRStageProblem {
	for i := range res.Problems {
		if res.Problems[i].Code == code && (reason == "" || res.Problems[i].Reason == reason) {
			return &res.Problems[i]
		}
	}
	return nil
}

func TestPRStageAdoptionUsesTheStoredAttempt(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.failNext("CreatePull", failLost)
	h.run(plan)
	// Someone pushes to the branch and rewrites the marker's head to match:
	// the marker's keys still recompute, but the stored attempt's commit
	// does not match.
	pr := h.gh.pulls(testRepo)[0]
	h.gh.pushToPull(testRepo, pr.Number)
	newHead := h.gh.pulls(testRepo)[0].HeadSHA
	h.gh.editPull(testRepo, pr.Number, func(p *github.PullRequest) { p.Body = strings.ReplaceAll(p.Body, pr.HeadSHA, newHead) })
	if m, err := parsePRMarker(h.gh.pulls(testRepo)[0].Body); err != nil || m.verify(testRepoID) != nil {
		t.Fatalf("the rewritten marker should still verify: %v", err)
	}
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusOpen, "")
	rec := h.load()
	if len(rec.PRs) != 1 || !rec.PRs[0].UserModified || rec.PRs[0].HeadSHA != rec.Attempts[0].CommitSHA || rec.Attempts[0].Status != AttemptPRCreated {
		t.Fatalf("records = %+v / %+v", rec.PRs, rec.Attempts)
	}
	// It is never closed in favour of a newer pull request.
	wantStatus(t, onlyUnit(t, h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil)))), PRStatusCreated, "")
	if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, p.Number)) != 0 {
		t.Error("the changed pull request was touched")
	}
}

func TestPRStageMarkerOnlyPullsAreSuppressionOnly(t *testing.T) {
	h := newPRHarness(t)
	plan1 := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	plan2 := testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))
	h.run(plan1)
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, onlyUnit(t, h.run(plan1)), PRStatusOpen, "")
	if rec := h.load(); !rec.PRs[0].MarkerOnly {
		t.Fatalf("recovered record = %+v", rec.PRs[0])
	}
	// It counts toward the open limit.
	h.limits = PRLimits{NewPRsPerCycle: 3, OpenPRs: 1}
	wantStatus(t, onlyUnit(t, h.run(plan2)), PRStatusDeferred, ReasonPRLimit)
	// It is never replaced.
	h.limits = PRLimits{NewPRsPerCycle: 3, OpenPRs: 10}
	u := onlyUnit(t, h.run(plan2))
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Replacing) != 0 || len(u.Replaced) != 0 {
		t.Errorf("replacing %+v replaced %v", u.Replacing, u.Replaced)
	}
	if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
		t.Error("a marker-only pull request was commented on or closed")
	}
	// And it still suppresses its own update.
	wantStatus(t, onlyUnit(t, h.run(plan1)), PRStatusOpen, "")
}

func TestPRStageAdoptedThroughAttemptIsReplaceable(t *testing.T) {
	h := newPRHarness(t)
	plan1 := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	h.gh.failNext("CreatePull", failLost)
	h.run(plan1)
	wantStatus(t, onlyUnit(t, h.run(plan1)), PRStatusOpen, "")
	if rec := h.load(); rec.PRs[0].MarkerOnly || rec.PRs[0].UserModified {
		t.Fatalf("adopted record = %+v", rec.PRs[0])
	}
	u := onlyUnit(t, h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))))
	if len(u.Replaced) != 1 || u.Replaced[0] != 1 {
		t.Errorf("replaced = %v (%+v)", u.Replaced, u.Replacing)
	}
}

func TestPRStageBaseRepositoryID(t *testing.T) {
	t.Run("recovery", func(t *testing.T) {
		h := newPRHarness(t)
		plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		h.run(plan)
		h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.BaseRepoID = 999 })
		if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
			t.Fatal(err)
		}
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusWriteBlocked, ReasonRecordsUnverified)
	})
	t.Run("after CreatePull", func(t *testing.T) {
		h := newPRHarness(t)
		h.gh.createBaseRepoID = 999
		u := onlyUnit(t, h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))))
		wantStatus(t, u, PRStatusCreated, "")
		if !u.UserModified || !strings.Contains(u.Detail, "repository ID 999") {
			t.Errorf("unit = %+v", u)
		}
		h.gh.createBaseRepoID = 0
		h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil)))
		if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
			t.Error("a pull request into another repository was replaced")
		}
	})
	t.Run("re-read before replacing", func(t *testing.T) {
		h := newPRHarness(t)
		h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
		h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.BaseRepoID = 999 })
		h.run(testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil)))
		if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
			t.Error("the old pull request was replaced")
		}
		if rec := h.load(); !rec.PRs[0].UserModified {
			t.Errorf("old record = %+v", rec.PRs[0])
		}
	})
}

func TestPRStageReplacementChecksPersistedModification(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	plan2 := testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))
	h.gh.failNext("CreateIssueComment", failRate)
	h.run(plan2)
	if rp := h.load().PRs[1].Replacing; len(rp) != 1 || rp[0].State != ReplacementPending {
		t.Fatalf("replacing = %+v", rp)
	}
	// The new pull request's head changes and the change is recorded, while
	// the replacement cannot proceed; then the head is put back.
	orig := h.gh.pulls(testRepo)[1].HeadSHA
	h.gh.pushToPull(testRepo, 2)
	h.gh.resolveErr = errors.New("registry unavailable (test)")
	h.run(plan2)
	if !h.load().PRs[1].UserModified {
		t.Fatal("the change was not recorded")
	}
	h.gh.editPull(testRepo, 2, func(p *github.PullRequest) { p.HeadSHA = orig })
	h.gh.resolveErr = nil
	h.run(plan2)
	if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
		t.Error("the old pull request was replaced by one that was changed")
	}
	if rp := h.load().PRs[1].Replacing[0]; rp.State != ReplacementAbandoned {
		t.Errorf("replacement = %+v", rp)
	}
}

func TestPRStageInitSaveFailureWithAddedRepos(t *testing.T) {
	h, plan := twoUnitHarness(t)
	h.gh.addRepo("example/other", 202, map[string]string{"compose.yml": composeYML})
	h.mappings = append(h.mappings, ComposeMapping{Workload: "compose/other/svc", Project: "other", Service: "svc", Repository: "example/other", BaseBranch: "main", Path: "compose.yml", ComposeService: "web"})
	// A record file exists, but neither repository was initialized yet.
	if err := h.store.Save(PRStoreFile{Version: PRStoreVersion, NextSeq: 1}); err != nil {
		t.Fatal(err)
	}
	h.store = &faultyStore{PRStorage: h.store, okSaves: 0, gh: h.gh}
	res := h.run(plan)
	if findProblem(res, PRProblemStorageFailed, "") == nil {
		t.Errorf("problems = %+v", res.Problems)
	}
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
	for _, u := range res.Units {
		if u.Status == PRStatusCreated {
			t.Errorf("unit = %+v", u)
		}
	}
}

func TestPRStageBlockedTargetIsReportedEveryCycle(t *testing.T) {
	h := newPRHarness(t)
	h.gh.failNext("CreateRef", refExistsOther)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	for cycle := 1; cycle <= 3; cycle++ {
		res := h.run(plan)
		p := findProblem(res, PRProblemWriteBlocked, ReasonBranchNotOurs)
		if p == nil || p.Repo != testRepo || p.Target != "compose.yml (services.web.image, services.worker.image)" || !strings.Contains(p.Detail, "compose.yml") {
			t.Fatalf("cycle %d: problems = %+v", cycle, res.Problems)
		}
	}
	// The same block fingerprints the same, cycle after cycle.
	a, b := h.run(plan), h.run(plan)
	pa, pb := testPlan(), testPlan()
	a.Attach(&pa)
	b.Attach(&pb)
	if Fingerprint(pa) != Fingerprint(pb) || Fingerprint(pa) == "" {
		t.Error("a persisting block does not fingerprint stably")
	}
}

func TestPRStageSeveralPullsOnTheBranchAreAllProtected(t *testing.T) {
	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))
	plan2 := testPlan(nginxItem("1.25.5", '2', []string{"CVE-1"}, nil))
	// The answer to the newer pull request is lost; it is closed, and someone
	// else opens another one from the same branch with the same marker.
	h.gh.failNext("CreatePull", failLost)
	h.run(plan2)
	lostPR := h.gh.pulls(testRepo)[1]
	h.gh.editPull(testRepo, lostPR.Number, func(p *github.PullRequest) { p.State = "closed" })
	copied := h.gh.addForeignPull(testRepo, github.PullRequest{HeadRef: lostPR.HeadRef, HeadSHA: lostPR.HeadSHA, HeadRepoFullName: testRepo,
		BaseRef: "main", User: "mallory", Body: lostPR.Body})

	for cycle := 0; cycle < 2; cycle++ {
		res := h.run(plan2)
		if findProblem(res, PRProblemWriteBlocked, ReasonAttemptUnsettled) == nil {
			t.Errorf("cycle %d: problems = %+v", cycle, res.Problems)
		}
	}
	rec := h.load()
	for _, n := range []int{lostPR.Number, copied} {
		r := (&prRun{file: rec}).recordByNumber(testRepoID, n)
		if r == nil || !r.UserModified {
			t.Errorf("pull request #%d record = %+v", n, r)
		}
	}
	if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
		t.Error("the older pull request was commented on or closed")
	}
	if countCalls(h.gh, "CreateIssueComment")+countCalls(h.gh, "ClosePull") != 0 {
		t.Error("a replacement write was sent")
	}
}
