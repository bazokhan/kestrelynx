package remediation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var prepared = testConds("db1")

// env wires a planner to fakes. Candidate scans return candFindings for any
// remote target unless a scan is registered for its ref.
type env struct {
	reg *fakeRegistry
	scn *fakeScanner
}

func newEnv() *env { return &env{reg: newFakeRegistry(), scn: newFakeScanner()} }

func (e *env) planner(t *testing.T, lim Limits, budget *registry.Budget) *Planner {
	t.Helper()
	p, err := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: lim, Budget: budget,
		Intel: func(id string) (VulnIntel, bool) {
			if id == "KEV-NEW" {
				return VulnIntel{Priority: PriorityActNow, KEV: true}, true
			}
			if id == "CVE-A" {
				return VulnIntel{Priority: PriorityWatch}, true
			}
			return VulnIntel{}, false
		},
		Now: func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var bigLimits = Limits{MaxCandidateScans: 10, MaxBaselineRescans: 10, MaxTagPages: 10}

// candidateScan registers the scan returned for a candidate ref.
func (e *env) candidateScan(ref string, fs []scanner.Finding, pk []scanner.ResultPackages) {
	e.scn.scans[ref] = func(t scanner.ScanTarget) scanner.ImageScan { return remoteScan(t, fs, pk) }
}

func input(ref string, h byte, conds scanner.ScanConditions, fs ...scanner.Finding) ImageInput {
	scan := configScan(ref, h, fs, pkgs("libc", "1"))
	return ImageInput{
		Scan: scan, Conditions: conds,
		Target:   scanner.ScanTarget{Subject: scan.Subject, Source: scanner.SourceLocal},
		Services: []ServiceRef{{Project: "p", Service: "svc-" + ref}},
	}
}

func fixedA() scanner.Finding { return finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh) }

func item(t *testing.T, p Plan, i int) Item {
	t.Helper()
	if len(p.Items) <= i {
		t.Fatalf("plan has %d items, want index %d", len(p.Items), i)
	}
	return p.Items[i]
}

func TestPlanPinnedAdopted(t *testing.T) {
	e := newEnv()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4", "1.25.5", "1.26.0", "1.25.6-rc1"}, Pages: 2}
	e.reg.res["nginx:1.25.5"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.5", nil, pkgs("libc", "2"))
	budget := registry.NewBudget(100)

	plan := e.planner(t, bigLimits, budget).Plan(context.Background(), []ImageInput{input("nginx:1.25.3", 'a', prepared, fixedA())})
	it := item(t, plan, 0)
	if it.Category != CategoryPRCandidate || it.Reason != ReasonAdopted || it.Kind != TagPinned {
		t.Fatalf("item = %+v", it)
	}
	if it.Candidate == nil || it.Candidate.Tag != "1.25.5" || it.Candidate.ConfigDigest != "sha256:"+hex64('c') {
		t.Errorf("candidate = %+v", it.Candidate)
	}
	if it.Current.ConfigDigest != "sha256:"+hex64('a') || it.Current.Platform != "linux/amd64" {
		t.Errorf("current = %+v", it.Current)
	}
	if it.Decision == nil || !it.Decision.Propose || it.Comparison == nil || !it.Comparison.Comparable {
		t.Errorf("decision/comparison = %+v / %+v", it.Decision, it.Comparison)
	}
	if plan.Usage.CandidateScans != 1 || plan.Usage.BaselineRescans != 0 || plan.Usage.TagPages != 2 {
		t.Errorf("usage = %+v", plan.Usage)
	}
	if plan.Version != PlanVersion || !plan.Conditions.Equal(prepared) {
		t.Errorf("plan header = %+v", plan)
	}
}

func TestPlanFloatingPullAgainAndSameContent(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
	// The running config digest equals the tag's current config digest.
	e.reg.res["redis:7"] = resolution('d', 'a')

	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{
		input("postgres:16", 'a', prepared, fixedA()),
		input("redis:7", 'a', prepared, fixedA()),
	})
	byRef := map[string]Item{}
	for _, it := range plan.Items {
		byRef[it.Current.Ref] = it
	}
	if it := byRef["postgres:16"]; it.Category != CategoryPullAgain || it.Kind != TagFloating {
		t.Errorf("postgres = %+v", it)
	}
	if it := byRef["redis:7"]; it.Category != CategoryNoCandidate || it.Reason != ReasonSameContent || it.Candidate != nil {
		t.Errorf("redis = %+v", it)
	}
	if e.reg.listCalls != 0 {
		t.Error("a floating tag must not list tags")
	}
}

func TestPlanImplicitLatestIsFloating(t *testing.T) {
	e := newEnv()
	e.reg.res["busybox:latest"] = resolution('b', 'c')
	e.candidateScan("busybox:latest", nil, pkgs("libc", "2"))
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("busybox", 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryPullAgain || it.Candidate.Tag != "latest" {
		t.Errorf("item = %+v", it)
	}
}

func TestPlanNoEntryPoint(t *testing.T) {
	e := newEnv()
	affected := finding("CVE-X", "libc", "1", "", scanner.SeverityHigh)
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("nginx:1.25.3", 'a', prepared, affected)})
	if len(plan.Items) != 0 {
		t.Errorf("items = %+v", plan.Items)
	}
}

func TestPlanExcludedAndBaselineProblems(t *testing.T) {
	e := newEnv()
	digest := "sha256:" + hex64('e')
	failed := input("nginx:1.25.3", 'a', prepared, fixedA())
	failed.Scan.Err = errors.New("pull failed")
	unpinned := input("alpine:3.19.1", 'a', prepared, fixedA())
	unpinned.Scan.Pinned = false
	noPlatform := input("alpine:3.18.1", 'a', prepared, fixedA())
	noPlatform.Scan.Platform = inventory.Platform{}
	variant := input("alpine:3.17.1", 'a', prepared, fixedA())
	variant.Scan.Platform.Variant = "v7"

	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{
		input("nginx@"+digest, 'a', prepared, fixedA()),
		input("nginx:1.25.3-rc1", 'a', prepared, fixedA()),
		input(digest, 'a', prepared, fixedA()),
		failed, unpinned, noPlatform, variant,
	})
	want := map[string][2]string{
		"nginx@" + digest:  {string(CategoryExcluded), string(ExcludeDigestOnly)},
		"nginx:1.25.3-rc1": {string(CategoryExcluded), string(ExcludePrerelease)},
		digest:             {string(CategoryExcluded), string(ExcludeBareDigest)},
		"nginx:1.25.3":     {string(CategoryFailed), string(ReasonScanFailed)},
		"alpine:3.19.1":    {string(CategoryNotComparable), string(ReasonEntityUnverified)},
		"alpine:3.18.1":    {string(CategoryNotComparable), string(ReasonPlatformUnknown)},
		"alpine:3.17.1":    {string(CategoryNotComparable), string(ReasonVariantUnsupported)},
	}
	if len(plan.Items) != len(want) {
		t.Fatalf("items = %d", len(plan.Items))
	}
	for _, it := range plan.Items {
		w := want[it.Current.Ref]
		if string(it.Category) != w[0] || string(it.Reason) != w[1] {
			t.Errorf("%s: %s/%s, want %v", it.Current.Ref, it.Category, it.Reason, w)
		}
	}
	if e.reg.listCalls != 0 || len(e.reg.resolveCnt) != 0 || len(e.scn.calls) != 0 {
		t.Error("no registry or scan work is spent on ineligible baselines")
	}
}

func TestPlanRegistryOutcomes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		cat  Category
		why  Reason
	}{
		{"variant", &registry.VariantError{Observed: "v7"}, CategoryNotComparable, ReasonVariantUnsupported},
		{"platform missing", fmt.Errorf("x: %w", registry.ErrPlatformNotFound), CategoryNotComparable, ReasonPlatformNotFound},
		{"platform ambiguous", registry.ErrPlatformAmbiguous, CategoryNotComparable, ReasonPlatformAmbiguous},
		{"platform mismatch", registry.ErrPlatformMismatch, CategoryNotComparable, ReasonPlatformMismatch},
		{"auth", registry.ErrAuthRequired, CategoryNotComparable, ReasonAuthRequired},
		{"rate limited", &registry.RateLimitedError{Host: "h", RetryAfter: time.Second}, CategoryDeferred, ReasonRateLimited},
		{"budget", registry.ErrBudgetExhausted, CategoryDeferred, ReasonRegistryBudget},
		{"deadline", context.DeadlineExceeded, CategoryDeferred, ReasonCycleDeadline},
		{"digest mismatch", registry.ErrDigestMismatch, CategoryFailed, ReasonRegistryError},
		{"not found", registry.ErrNotFound, CategoryFailed, ReasonRegistryError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv()
			e.reg.resErr["postgres:16"] = c.err
			plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
			if it := item(t, plan, 0); it.Category != c.cat || it.Reason != c.why {
				t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
		})
	}
}

func TestPlanRateLimitStopsFurtherRegistryWork(t *testing.T) {
	e := newEnv()
	e.reg.resErr["postgres:16"] = &registry.RateLimitedError{Host: "h"}
	e.reg.res["redis:7"] = resolution('b', 'c')
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{
		input("postgres:16", 'a', prepared, fixedA()),
		input("redis:7", 'b', prepared, fixedA()),
	})
	for _, it := range plan.Items {
		if it.Category != CategoryDeferred || it.Reason != ReasonRateLimited {
			t.Errorf("%s = %s/%s", it.Current.Ref, it.Category, it.Reason)
		}
	}
	if e.reg.resolveCnt["redis:7"] != 0 {
		t.Error("a request was sent after the registry rate limited")
	}
}

func TestPlanTruncatedListingIsDeferredNotNoCandidate(t *testing.T) {
	e := newEnv()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3"}, Truncated: true, Pages: 5}
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("nginx:1.25.3", 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryDeferred || it.Reason != ReasonTagListIncomplete {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestPlanNoNewerTag(t *testing.T) {
	e := newEnv()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.26.0"}, Pages: 1}
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("nginx:1.25.3", 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryNoCandidate || it.Reason != ReasonNoNewerTag {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestPlanTagListSharedAndPageLimit(t *testing.T) {
	e := newEnv()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4"}, Pages: 3}
	e.reg.tags["redis"] = registry.TagList{Tags: []string{"7.2.1"}, Pages: 1}
	e.reg.res["nginx:1.25.4"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	p := e.planner(t, Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 3}, nil)
	plan := p.Plan(context.Background(), []ImageInput{
		input("nginx:1.25.3", 'a', prepared, fixedA()),
		input("nginx:1.25.3-alpine", 'b', prepared, fixedA()),
		input("redis:7.2.0", 'd', prepared, fixedA()),
	})
	byRef := map[string]Item{}
	for _, it := range plan.Items {
		byRef[it.Current.Ref] = it
	}
	if it := byRef["nginx:1.25.3"]; it.Category != CategoryPRCandidate {
		t.Errorf("nginx = %s/%s", it.Category, it.Reason)
	}
	if it := byRef["nginx:1.25.3-alpine"]; it.Category != CategoryNoCandidate {
		t.Errorf("alpine = %s/%s (same listing, different suffix)", it.Category, it.Reason)
	}
	if it := byRef["redis:7.2.0"]; it.Category != CategoryDeferred || it.Reason != ReasonTagPageLimit {
		t.Errorf("redis = %s/%s", it.Category, it.Reason)
	}
	if e.reg.listCalls != 1 {
		t.Errorf("list calls = %d, want 1 (shared)", e.reg.listCalls)
	}
}

func TestPlanCandidateScanLimitAndSharing(t *testing.T) {
	e := newEnv()
	for _, ref := range []string{"postgres:16", "redis:7", "mysql:8"} {
		e.reg.res[ref] = resolution('b', 'c')
		e.candidateScan(ref, nil, pkgs("libc", "2"))
	}
	// Two images with the same tag share the candidate scan.
	plan := e.planner(t, Limits{MaxCandidateScans: 2, MaxBaselineRescans: 5, MaxTagPages: 5}, nil).Plan(context.Background(), []ImageInput{
		input("postgres:16", 'a', prepared, fixedA()),
		input("postgres:16", '9', prepared, fixedA()),
		input("redis:7", 'd', prepared, fixedA()),
		input("mysql:8", 'e', prepared, fixedA()),
	})
	var deferred, ok int
	for _, it := range plan.Items {
		switch it.Category {
		case CategoryPullAgain:
			ok++
		case CategoryDeferred:
			deferred++
			if it.Reason != ReasonCandidateScanLimit {
				t.Errorf("reason = %s", it.Reason)
			}
		}
	}
	if ok != 3 || deferred != 1 {
		t.Errorf("ok=%d deferred=%d", ok, deferred)
	}
	if plan.Usage.CandidateScans != 2 {
		t.Errorf("candidate scans = %d", plan.Usage.CandidateScans)
	}
}

func TestPlanOrderAndUrgency(t *testing.T) {
	e := newEnv()
	e.reg.res["a:1"] = resolution('b', 'c')
	e.reg.res["b:1"] = resolution('b', 'c')
	e.reg.res["c:1"] = resolution('b', 'c')
	for _, r := range []string{"a:1", "b:1", "c:1"} {
		e.candidateScan(r, nil, pkgs("libc", "2"))
	}
	low := finding("CVE-LOW", "libc", "1", "2", scanner.SeverityHigh)
	kev := finding("KEV-NEW", "libc", "1", "2", scanner.SeverityHigh)
	// Only one candidate scan is allowed: it must go to the act_now image.
	plan := e.planner(t, Limits{MaxCandidateScans: 1, MaxBaselineRescans: 1, MaxTagPages: 1}, nil).Plan(context.Background(), []ImageInput{
		input("a:1", 'a', prepared, low),
		input("b:1", '8', prepared, fixedA()),
		input("c:1", 'f', prepared, kev),
	})
	refs := []string{plan.Items[0].Current.Ref, plan.Items[1].Current.Ref, plan.Items[2].Current.Ref}
	if refs[0] != "c:1" || refs[1] != "b:1" || refs[2] != "a:1" {
		t.Errorf("order = %v", refs)
	}
	if plan.Items[0].Category != CategoryPullAgain || plan.Items[1].Category != CategoryDeferred || plan.Items[2].Category != CategoryDeferred {
		t.Errorf("categories = %s %s %s", plan.Items[0].Category, plan.Items[1].Category, plan.Items[2].Category)
	}
}

func TestPlanBaselineRescan(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
	rescan := func(t scanner.ScanTarget) scanner.ImageScan {
		return configScan(t.Subject.Ref, 'a', []scanner.Finding{fixedA()}, pkgs("libc", "1"))
	}
	e.scn.scans["postgres:16-local"] = rescan
	mk := func() ImageInput {
		in := input("postgres:16", 'a', testConds("older-db"), fixedA()) // taken under other conditions
		in.Target.Subject.Ref = "postgres:16-local"
		return in
	}

	t.Run("rescanned", func(t *testing.T) {
		e.scn.calls = nil
		plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{mk()})
		if it := item(t, plan, 0); it.Category != CategoryPullAgain {
			t.Errorf("item = %s/%s %s", it.Category, it.Reason, it.Detail)
		}
		if plan.Usage.BaselineRescans != 1 || len(e.scn.calls) != 2 {
			t.Errorf("usage=%+v calls=%v", plan.Usage, e.scn.calls)
		}
	})
	t.Run("unknown conditions are rescanned too", func(t *testing.T) {
		in := mk()
		in.Conditions = scanner.ScanConditions{}
		plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
		if it := item(t, plan, 0); it.Category != CategoryPullAgain || plan.Usage.BaselineRescans != 1 {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("rescan limit", func(t *testing.T) {
		plan := e.planner(t, Limits{MaxCandidateScans: 5, MaxBaselineRescans: 0, MaxTagPages: 5}, nil).Plan(context.Background(), []ImageInput{mk()})
		if it := item(t, plan, 0); it.Category != CategoryDeferred || it.Reason != ReasonBaselineRescanLimit {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		if plan.Usage.CandidateScans != 0 {
			t.Error("a candidate scan was spent although the pair cannot be completed")
		}
	})
	t.Run("rescan failure", func(t *testing.T) {
		in := mk()
		in.Target.Subject.Ref = "missing"
		plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
		if it := item(t, plan, 0); it.Category != CategoryFailed || it.Reason != ReasonScanFailed {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
}

func TestPlanConditionsNotComparable(t *testing.T) {
	t.Run("database changed during scans", func(t *testing.T) {
		e := newEnv()
		e.reg.res["postgres:16"] = resolution('b', 'c')
		e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
		e.scn.verifyOK = false
		plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
		if it := item(t, plan, 0); it.Category != CategoryNotComparable || it.Reason != ReasonConditionsUnknown {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		var changed bool
		for _, s := range plan.Scans {
			if s.Role == RoleCandidate && s.DB == DBChanged && s.DBCheckAt != nil {
				changed = true
			}
		}
		if !changed {
			t.Errorf("the failed database check is not recorded: %+v", plan.Scans)
		}
	})
	t.Run("verification error", func(t *testing.T) {
		e := newEnv()
		e.reg.res["postgres:16"] = resolution('b', 'c')
		e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
		e.scn.verifyEr = errors.New("cannot hash")
		plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
		if it := item(t, plan, 0); it.Category != CategoryNotComparable {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		if got := plan.Scans[len(plan.Scans)-1]; got.DB != DBCheckFailed || got.DBError == "" {
			t.Errorf("record = %+v", got)
		}
	})
	t.Run("cycle has no prepared conditions", func(t *testing.T) {
		e := newEnv()
		e.reg.res["postgres:16"] = resolution('b', 'c')
		p, _ := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Limits: bigLimits})
		plan := p.Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
		if it := item(t, plan, 0); it.Category != CategoryNotComparable || it.Reason != ReasonConditionsUnknown {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		if len(e.scn.calls) != 0 {
			t.Error("scans ran without conditions")
		}
	})
}

func TestPlanAdoptionDecisions(t *testing.T) {
	two := []scanner.Finding{fixedA(), finding("CVE-B", "libc", "1", "2", scanner.SeverityHigh)}
	cases := []struct {
		name  string
		cand  []scanner.Finding
		cat   Category
		why   Reason
		trace string
	}{
		{"all resolved", nil, CategoryPullAgain, ReasonAdopted, ""},
		{"partial", []scanner.Finding{two[1]}, CategoryPullAgain, ReasonAdopted, ""},
		{"partial with introduced", []scanner.Finding{two[1], finding("CVE-N", "newlib", "1", "", scanner.SeverityHigh)}, CategoryManual, ReasonIntroducedFindings, ""},
		{"nothing resolved", two, CategoryNoCandidate, ReasonCandidateNotFixing, ""},
		{"introduced", []scanner.Finding{finding("CVE-N", "newlib", "1", "", scanner.SeverityHigh)}, CategoryManual, ReasonIntroducedFindings, ""},
		{"introduced KEV", []scanner.Finding{finding("KEV-NEW", "newlib", "1", "", scanner.SeverityCritical)}, CategoryManual, ReasonIntroducedKEV, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv()
			e.reg.res["postgres:16"] = resolution('b', 'c')
			e.candidateScan("postgres:16", c.cand, pkgs("libc", "2"))
			plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, two...)})
			it := item(t, plan, 0)
			if it.Category != c.cat || it.Reason != c.why {
				t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			if it.Comparison == nil || it.Decision == nil || it.Candidate == nil {
				t.Error("comparison, decision and candidate are recorded whether or not proposed")
			}
		})
	}
}

func TestPlanPartialAdoptionKeepsCountsAndKind(t *testing.T) {
	two := []scanner.Finding{fixedA(), finding("CVE-B", "libc", "1", "2", scanner.SeverityHigh)}
	for _, tc := range []struct {
		name string
		ref  string
		cand []scanner.Finding
		cat  Category
		kind DecisionKind
		res  int
	}{
		{"floating partial", "postgres:16", []scanner.Finding{two[1]}, CategoryPullAgain, DecisionAdoptPartial, 1},
		{"floating full", "postgres:16", nil, CategoryPullAgain, DecisionAdopt, 2},
		{"pinned partial", "nginx:1.25.3", []scanner.Finding{two[1]}, CategoryPRCandidate, DecisionAdoptPartial, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv()
			e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.5"}, Pages: 1}
			cand := tc.ref
			if tc.ref == "nginx:1.25.3" {
				cand = "nginx:1.25.5"
			}
			e.reg.res[cand] = resolution('b', 'c')
			e.candidateScan(cand, tc.cand, pkgs("libc", "2"))
			plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input(tc.ref, 'a', prepared, two...)})
			it := item(t, plan, 0)
			if it.Category != tc.cat || it.Reason != ReasonAdopted {
				t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			d := it.Decision
			if d.Kind != tc.kind || !d.Propose || d.Targets != 2 || d.Resolved != tc.res || d.Remaining != 2-tc.res || d.Introduced != 0 {
				t.Errorf("decision = %+v", d)
			}
			resolved, remaining, _ := it.Comparison.Counts()
			if resolved != tc.res || remaining != 2-tc.res {
				t.Errorf("comparison counts = %d resolved, %d remaining", resolved, remaining)
			}
		})
	}
}

func TestPlanCandidateScanFailureAndPlatform(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	// No scan registered: the fake fails it.
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryFailed || it.Reason != ReasonScanFailed {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}

	// A candidate scan on another platform than the baseline is refused.
	e2 := newEnv()
	e2.reg.res["postgres:16"] = resolution('b', 'c')
	e2.scn.scans["postgres:16"] = func(t scanner.ScanTarget) scanner.ImageScan {
		s := remoteScan(t, nil, pkgs("libc", "2"))
		s.Platform.Architecture = "arm64"
		return s
	}
	plan = e2.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryNotComparable || it.Reason != ReasonPlatformDiffer {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestPlanCandidateTargetIsPinnedByManifest(t *testing.T) {
	e := newEnv()
	e.reg.res["ghcr.io/o/app:2.0"] = resolution('b', 'c')
	var got scanner.ScanTarget
	e.scn.scans["ghcr.io/o/app:2.0"] = func(t scanner.ScanTarget) scanner.ImageScan {
		got = t
		return remoteScan(t, nil, pkgs("libc", "2"))
	}
	e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("ghcr.io/o/app:2.0", 'a', prepared, fixedA())})
	if got.Source != scanner.SourceRemote || !got.Subject.Resolved ||
		got.Registry.Repository != "ghcr.io/o/app" || got.Registry.Digest.String() != "sha256:"+hex64('b') ||
		got.Subject.Key.Digest != got.Registry.Digest || got.Subject.Key.Platform != linuxAmd64 {
		t.Errorf("target = %+v", got)
	}
}

func TestPlanCancelledContextDefersEverything(t *testing.T) {
	e := newEnv()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := e.planner(t, bigLimits, nil).Plan(ctx, []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryDeferred || it.Reason != ReasonCycleDeadline {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestNewPlannerValidates(t *testing.T) {
	if _, err := NewPlanner(Config{}); err == nil {
		t.Error("missing dependencies accepted")
	}
	e := newEnv()
	if _, err := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Limits: Limits{MaxTagPages: -1}}); err == nil {
		t.Error("negative limit accepted")
	}
}

func TestPlanTagPageAllowanceIsPassedAndEnforced(t *testing.T) {
	e := newEnv()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4"}, Pages: 5}
	e.reg.tags["redis"] = registry.TagList{Tags: []string{"7.2.0"}, Pages: 1}
	p := e.planner(t, Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 4}, nil)
	plan := p.Plan(context.Background(), []ImageInput{
		input("nginx:1.25.3", 'a', prepared, fixedA()),
		input("redis:7.2.0", 'd', prepared, fixedA()),
	})
	if len(e.reg.allowances) == 0 || e.reg.allowances[0] != 4 {
		t.Fatalf("allowances = %v, want the first listing to get 4", e.reg.allowances)
	}
	nginx := item(t, plan, 0)
	if nginx.Category != CategoryDeferred || nginx.Reason != ReasonTagPageLimit {
		t.Errorf("a listing stopped by the cap must be deferred: %s/%s", nginx.Category, nginx.Reason)
	}
	if plan.Usage.TagPages != 4 {
		t.Errorf("tag pages = %d, want 4", plan.Usage.TagPages)
	}
	if redis := item(t, plan, 1); redis.Category != CategoryDeferred || redis.Reason != ReasonTagPageLimit {
		t.Errorf("no allowance left: %s/%s", redis.Category, redis.Reason)
	}
	if e.reg.listCalls != 1 {
		t.Errorf("list calls = %d, want 1", e.reg.listCalls)
	}
}

func TestPlanTagListingErrorStillCountsPages(t *testing.T) {
	e := newEnv()
	e.reg.tagErr["nginx"] = &registry.StatusError{Host: "h", Status: 500}
	e.reg.errPages["nginx"] = 2
	e.reg.tags["redis"] = registry.TagList{Tags: []string{"7.2.0", "7.2.1"}, Pages: 1}
	e.reg.res["redis:7.2.1"] = resolution('b', 'c')
	e.candidateScan("redis:7.2.1", nil, pkgs("libc", "2"))
	p := e.planner(t, Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 3}, nil)
	plan := p.Plan(context.Background(), []ImageInput{
		input("nginx:1.25.3", 'a', prepared, fixedA()),
		input("redis:7.2.0", 'd', prepared, fixedA()),
	})
	if it := item(t, plan, 0); it.Category != CategoryFailed || it.Reason != ReasonRegistryError {
		t.Errorf("nginx = %s/%s", it.Category, it.Reason)
	}
	if plan.Usage.TagPages != 3 {
		t.Errorf("tag pages = %d, want 2 from the failed listing plus 1", plan.Usage.TagPages)
	}
	if e.reg.allowances[1] != 1 {
		t.Errorf("second listing allowance = %d, want 1 (3 minus the 2 consumed)", e.reg.allowances[1])
	}
	if it := item(t, plan, 1); it.Category != CategoryPRCandidate {
		t.Errorf("redis = %s/%s", it.Category, it.Reason)
	}
}

func TestPlanSharesCandidateScanAcrossRepositorySpellings(t *testing.T) {
	e := newEnv()
	for _, r := range []string{"nginx:1.25", "docker.io/library/nginx:1.25"} {
		e.reg.res[r] = resolution('b', 'c')
		e.candidateScan(r, nil, pkgs("libc", "2"))
	}
	plan := e.planner(t, Limits{MaxCandidateScans: 1, MaxBaselineRescans: 1, MaxTagPages: 1}, nil).Plan(context.Background(), []ImageInput{
		input("nginx:1.25", 'a', prepared, fixedA()),
		input("docker.io/library/nginx:1.25", 'd', prepared, fixedA()),
	})
	for _, it := range plan.Items {
		if it.Category != CategoryPullAgain {
			t.Errorf("%s = %s/%s", it.Current.Ref, it.Category, it.Reason)
		}
	}
	if plan.Usage.CandidateScans != 1 {
		t.Errorf("candidate scans = %d, want 1", plan.Usage.CandidateScans)
	}
	if plan.Items[0].CandidateScan == "" || plan.Items[0].CandidateScan != plan.Items[1].CandidateScan {
		t.Errorf("items should share one candidate scan record: %q %q", plan.Items[0].CandidateScan, plan.Items[1].CandidateScan)
	}
}

func TestPlanKeepsInputOrderWithinPriority(t *testing.T) {
	e := newEnv()
	var inputs []ImageInput
	for _, ref := range []string{"zed:1", "alpha:1", "mid:1"} {
		inputs = append(inputs, input(ref, 'a', prepared, fixedA()))
	}
	plan := e.planner(t, Limits{}, nil).Plan(context.Background(), inputs)
	got := []string{plan.Items[0].Current.Ref, plan.Items[1].Current.Ref, plan.Items[2].Current.Ref}
	if got[0] != "zed:1" || got[1] != "alpha:1" || got[2] != "mid:1" {
		t.Errorf("order = %v", got)
	}
}

func TestPlanRegistryKindEntityIsComparedNotShortcut(t *testing.T) {
	e := newEnv()
	e.reg.res["app:2"] = resolution('b', 'c')
	e.candidateScan("app:2", nil, pkgs("libc", "2"))
	reg, _ := inventory.ParseDigest(inventory.DigestRegistry, "sha256:"+hex64('9'))
	in := input("app:2", 'a', prepared, fixedA())
	key := inventory.EntityKey{Digest: reg, Platform: linuxAmd64}
	in.Scan.Subject.Key, in.Scan.ScannedKey = key, key
	in.Target.Subject = in.Scan.Subject
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	if it := item(t, plan, 0); it.Category != CategoryPullAgain {
		t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
	}

	// The same registry digest as the candidate's manifest is the same content.
	same := input("app:2", 'a', prepared, fixedA())
	rk, _ := inventory.ParseDigest(inventory.DigestRegistry, "sha256:"+hex64('b'))
	k2 := inventory.EntityKey{Digest: rk, Platform: linuxAmd64}
	same.Scan.Subject.Key, same.Scan.ScannedKey = k2, k2
	plan = e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{same})
	if it := item(t, plan, 0); it.Reason != ReasonSameContent {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestPlanRecordsScanExecutions(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
	e.reg.res["mysql:8"] = resolution('d', 'e')
	// mysql's candidate scan fails (nothing registered).

	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{
		input("postgres:16", 'a', prepared, fixedA()),
		input("mysql:8", '1', prepared, fixedA()),
	})
	byID := map[string]ScanExecution{}
	for _, s := range plan.Scans {
		byID[s.ID] = s
	}
	pg := item(t, plan, 0)
	b, c := byID[pg.BaselineScan], byID[pg.CandidateScan]
	if b.Role != RoleBaseline || b.DB != DBSupplied || b.Source != scanner.SourceLocal || b.Requested != b.Confirmed || b.Requested == Unconfirmed {
		t.Errorf("baseline record = %+v", b)
	}
	if c.Role != RoleCandidate || c.Source != scanner.SourceRemote || c.DB != DBVerified || c.ScannedAt == nil || c.DBCheckAt == nil || c.Failure != "" {
		t.Errorf("candidate record = %+v", c)
	}
	my := item(t, plan, 1)
	if my.Category != CategoryFailed {
		t.Fatalf("mysql = %s/%s", my.Category, my.Reason)
	}
	f := byID[my.CandidateScan]
	if f.Failure == "" || f.Confirmed != Unconfirmed || f.DB != DBNotChecked || f.Requested == Unconfirmed {
		t.Errorf("failed scan record = %+v", f)
	}
}

func TestPlanUnanalysedTypeIsNotComparableNotNoCandidate(t *testing.T) {
	e := newEnv()
	e.reg.res["app:2"] = resolution('b', 'c')
	node := langFinding("CVE-NODE", "node-pkg", "left-pad")
	// The candidate scan has no node-pkg result at all.
	e.candidateScan("app:2", nil, pkgs("libc", "2"))
	in := input("app:2", 'a', prepared, node)
	in.Scan.Packages = append(in.Scan.Packages, langPkgs("node-pkg", "left-pad", "1")...)
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	it := item(t, plan, 0)
	if it.Category != CategoryNotComparable || it.Reason != ReasonAnalysisIncomplete {
		t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
	}
	if it.Decision == nil || it.Decision.Propose || it.Decision.Unknown != 1 {
		t.Errorf("decision = %+v", it.Decision)
	}
}

func TestPlanBaselineRescanNoLongerShowsTargets(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
	// The rescan under the prepared conditions reports no findings.
	e.scn.scans["postgres:16-local"] = func(t scanner.ScanTarget) scanner.ImageScan {
		return configScan(t.Subject.Ref, 'a', nil, pkgs("libc", "1"))
	}
	in := input("postgres:16", 'a', testConds("older-db"), fixedA())
	in.Target.Subject.Ref = "postgres:16-local"
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	it := item(t, plan, 0)
	if it.Category != CategoryNotComparable || it.Reason != ReasonTargetsNotDetected {
		t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
	}
	if it.Decision == nil || it.Decision.Propose || it.Decision.Undetected != 1 || plan.Usage.BaselineRescans != 1 {
		t.Errorf("decision = %+v usage = %+v", it.Decision, plan.Usage)
	}
}
