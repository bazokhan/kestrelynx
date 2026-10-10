package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// fakePRStage returns a fixed result and records what it was given.
type fakePRStage struct {
	result remediation.PRStageResult
	runs   int
	in     remediation.PRStageInput
	hadDL  bool
}

func (f *fakePRStage) Run(ctx context.Context, in remediation.PRStageInput) remediation.PRStageResult {
	_, f.hadDL = ctx.Deadline()
	f.runs++
	f.in = in
	return f.result
}

// memPRStore is an in-memory record file.
type memPRStore struct {
	file  remediation.PRStoreFile
	found bool
	locks int
}

func (m *memPRStore) Lock() (func() error, error) { m.locks++; return func() error { return nil }, nil }
func (m *memPRStore) Load() (remediation.PRStoreFile, bool, error) {
	return m.file, m.found, nil
}
func (m *memPRStore) Save(f remediation.PRStoreFile) error { m.file, m.found = f, true; return nil }

type prHarness struct {
	*planHarness
	stage    *fakePRStage
	prs      *memPRStore
	stages   int
	resolver remediation.CandidateResolver
	newErr   error
}

var prMappings = []remediation.ComposeMapping{
	{Workload: "compose/shop/web", Project: "shop", Service: "web", Repository: "ex/deploy", BaseBranch: "main", Path: "compose.yml", ComposeService: "web"},
}

func newPRHarness(findings ...scanner.Finding) *prHarness {
	h := &prHarness{planHarness: newPlanHarness(findings...), stage: &fakePRStage{}, prs: &memPRStore{}}
	h.prs.file = remediation.PRStoreFile{Version: remediation.PRStoreVersion, NextSeq: 10, DeliveredSeq: 2}
	h.prs.found = true
	h.r.Plan.PullRequests = &PullRequestConfig{
		NewStage: func(res remediation.CandidateResolver) (PRStage, error) {
			h.stages++
			h.resolver = res
			if h.newErr != nil {
				return nil, h.newErr
			}
			return h.stage, nil
		},
		Mappings: prMappings,
		Store:    h.prs,
	}
	return h
}

func createdUnit() remediation.PRUnit {
	return remediation.PRUnit{
		Key: "ex/deploy@main:compose.yml|web:1.25.3", Repo: "ex/deploy", BaseBranch: "main", Path: "compose.yml",
		Services: []string{"web"}, Locations: []string{"services.web.image"}, Current: "web:1.25.3", CandidateTag: "1.25.4",
		Status: remediation.PRStatusCreated, Number: 4, URL: "https://github.com/ex/deploy/pull/4", State: remediation.PRStateOpen,
	}
}

func createdResult() remediation.PRStageResult {
	return remediation.PRStageResult{
		Units:      []remediation.PRUnit{createdUnit()},
		Operations: []remediation.OperationEvent{{Seq: 7, ID: "op-7", Phase: remediation.PhaseResult, Kind: remediation.OpCreatePull, Repo: "ex/deploy", Number: 4, Result: remediation.ResultOK}},
		LastSeq:    7,
	}
}

func TestPullRequests_StageRunsAfterTheSavedPlanAndIsAttached(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.stage.result = createdResult()
	h.run(t)

	if h.stage.runs != 1 || h.stages != 1 {
		t.Fatalf("stage runs = %d, built = %d", h.stage.runs, h.stages)
	}
	if h.resolver != remediation.CandidateResolver(h.reg) {
		t.Errorf("resolver = %v, want the cycle's registry client", h.resolver)
	}
	in := h.stage.in
	if len(in.Plan.Items) != 1 || len(in.Containers) != 1 || len(in.Mappings) != 1 || in.Mappings[0].Path != "compose.yml" {
		t.Errorf("stage input = %d items, %d containers, %d mappings", len(in.Plan.Items), len(in.Containers), len(in.Mappings))
	}
	// The stored plan is the plan as built; the stage result rides along in
	// the notification only.
	if len(h.plans.saved) != 1 || len(h.plans.saved[0].PullRequests) != 0 {
		t.Errorf("saved plan = %+v", h.plans.saved)
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.PullRequests) != 1 || p.Plan.PullRequests[0].Number != 4 || len(p.Plan.PROperations) != 1 {
		t.Fatalf("notified plan = %+v", p)
	}
	if want := remediation.Fingerprint(*p.Plan); len(h.delivered.saves) != 1 || h.delivered.saves[0] != want {
		t.Errorf("delivered = %v, want the fingerprint with the pull request", h.delivered.saves)
	}
	if h.prs.file.DeliveredSeq != 7 {
		t.Errorf("delivered sequence = %d, want 7", h.prs.file.DeliveredSeq)
	}
}

func TestPullRequests_OperationsNotMarkedDeliveredAfterAFailedSend(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.stage.result = createdResult()
	h.notif.err = errors.New("slack down")
	if err := h.r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected the send error")
	}
	if h.prs.file.DeliveredSeq != 2 || len(h.delivered.saves) != 0 {
		t.Errorf("delivered seq = %d, plan saves = %v after a failed send", h.prs.file.DeliveredSeq, h.delivered.saves)
	}
}

func TestPullRequests_UndeliveredOperationsAndProblemsForceASend(t *testing.T) {
	for _, mode := range []string{"diff", "full"} {
		t.Run(mode, func(t *testing.T) {
			// A clean cycle whose plan matches the delivered one: only the
			// stage has something to say.
			h := newPRHarness()
			if mode == "full" {
				h.r.Store = nil
			}
			h.run(t)
			if h.notif.called {
				t.Fatal("a quiet cycle notified")
			}

			h.stage.result = remediation.PRStageResult{
				Operations: []remediation.OperationEvent{{Seq: 8, ID: "op-8", Phase: remediation.PhaseResult, Kind: remediation.OpCreateRef, Repo: "ex/deploy", Result: remediation.ResultUnknown}},
				LastSeq:    8,
			}
			h.run(t)
			if !h.notif.called {
				t.Fatal("undelivered operation events did not send")
			}
			if h.prs.file.DeliveredSeq != 8 {
				t.Errorf("delivered sequence = %d, want 8", h.prs.file.DeliveredSeq)
			}

			// Delivered: quiet again.
			h.notif.called = false
			h.stage.result = remediation.PRStageResult{}
			h.run(t)
			if h.notif.called {
				t.Error("nothing new, yet a notification was sent")
			}

			// A problem is sent every cycle while it lasts, though its
			// fingerprint is delivered after the first time.
			h.stage.result = remediation.PRStageResult{Problems: []remediation.PRStageProblem{{
				Code: remediation.PRProblemRecordsUnverified, Repo: "ex/deploy", Reason: remediation.ReasonRecordsUnverified}}}
			for i := 0; i < 3; i++ {
				h.notif.called = false
				h.run(t)
				if !h.notif.called {
					t.Fatalf("cycle %d with a persisting problem was not sent", i+1)
				}
				if got := h.notif.msg.Plan.Plan.PRProblems; len(got) != 1 {
					t.Errorf("problems = %+v", got)
				}
			}
		})
	}
}

func TestPullRequests_UnsavedPlanIsNotActedOn(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.stage.result = createdResult()
	h.plans.err = errors.New("disk full")
	h.run(t)
	if h.stages != 0 || h.stage.runs != 0 {
		t.Errorf("the stage ran on a plan that was not saved (built %d, runs %d)", h.stages, h.stage.runs)
	}
	p := h.notif.msg.Plan
	if p == nil || !p.NotSaved || p.Plan == nil || len(p.Plan.PullRequests) != 0 {
		t.Fatalf("plan = %+v", p)
	}
	if len(p.Plan.PRProblems) != 1 || p.Plan.PRProblems[0].Code != remediation.PRProblemStorageFailed || p.Plan.PRProblems[0].Reason != remediation.ReasonStorageFailed {
		t.Errorf("problems = %+v, want storage_failed", p.Plan.PRProblems)
	}
}

func TestPullRequests_StageSetupFailureNeverStopsTheCycle(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.newErr = errors.New("bad limits")
	h.run(t)
	if !h.notif.called || h.store.saved == nil {
		t.Fatal("the cycle did not complete")
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.PRProblems) != 1 || p.Plan.PRProblems[0].Code != remediation.PRProblemWriteBlocked || len(p.Plan.Items) != 1 {
		t.Fatalf("plan = %+v", p)
	}
}

func TestPullRequests_DisabledLeavesThePlanAsToday(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.run(t)
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || p.Plan.PullRequests != nil || p.Plan.PROperations != nil || p.Plan.PRProblems != nil {
		t.Fatalf("plan = %+v", p)
	}
	if h.r.Plan.PullRequests != nil {
		t.Error("pull requests are on by default")
	}
}

func TestPullRequests_NoPlanNoStage(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.scn.prepareErr = errors.New("db down")
	h.run(t)
	if h.stages != 0 || h.stage.runs != 0 {
		t.Errorf("the stage ran without a plan (built %d, runs %d)", h.stages, h.stage.runs)
	}
}

func TestPullRequests_StageSharesThePlanDeadline(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.r.Plan.CycleTimeout = time.Minute
	h.run(t)
	if h.stage.runs != 1 || !h.stage.hadDL {
		t.Errorf("runs = %d, deadline = %v; the stage runs inside the plan stage deadline", h.stage.runs, h.stage.hadDL)
	}
}
