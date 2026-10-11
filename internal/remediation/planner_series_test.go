package remediation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// seriesPlanner is a planner whose registry can page, so pinned tags are read
// by series.
func (e *env) seriesPlanner(t *testing.T, pager *sortedPager, lim Limits) *Planner {
	t.Helper()
	p, err := NewPlanner(Config{
		Registry: seriesRegistry{e.reg, pager}, Scanner: e.scn, Prepared: prepared, Limits: lim, Budget: registry.NewBudget(1000),
		Intel: func(id string) (VulnIntel, bool) { return VulnIntel{Priority: PriorityWatch}, id == "CVE-A" },
		Now:   func() time.Time { return time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanSeriesWalkFindsNewestPatch(t *testing.T) {
	e := newEnv()
	pager := newSortedPager([]string{"1.24.9", "1.25.3", "1.25.3-alpine", "1.25.4", "1.25.4-alpine", "1.25.5", "1.25.5-rc1", "1.26.0", "latest"})
	e.reg.res["nginx:1.25.5"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.5", nil, pkgs("libc", "2"))
	plan := e.seriesPlanner(t, pager, bigLimits).Plan(context.Background(), []ImageInput{input("nginx:1.25.3", 'a', prepared, fixedA())})
	it := item(t, plan, 0)
	if it.Category != CategoryPRCandidate || it.Candidate == nil || it.Candidate.Tag != "1.25.5" {
		t.Fatalf("item = %+v", it)
	}
	if plan.Usage.TagPages != pager.requests() || plan.Usage.TagPages == 0 {
		t.Errorf("tag pages = %d, requests = %d", plan.Usage.TagPages, pager.requests())
	}
	if e.reg.listCalls != 0 {
		t.Error("the full listing must not be read when the series walk completes")
	}
}

func TestPlanSeriesWalkNoNewerFormalRelease(t *testing.T) {
	e := newEnv()
	pager := newSortedPager(elasticLike())
	const ref = "docker.elastic.co/elasticsearch/elasticsearch:8.19.16"
	plan := e.seriesPlanner(t, pager, Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 20}).
		Plan(context.Background(), []ImageInput{input(ref, 'a', prepared, fixedA())})
	it := item(t, plan, 0)
	if it.Category != CategoryNoCandidate || it.Reason != ReasonNoNewerTag {
		t.Fatalf("item = %s/%s %s", it.Category, it.Reason, it.Detail)
	}
	if plan.Usage.TagPages > 20 {
		t.Errorf("tag pages = %d", plan.Usage.TagPages)
	}
}

func TestPlanSeriesWalkStoppedByPageLimitIsDeferred(t *testing.T) {
	e := newEnv()
	plan := e.seriesPlanner(t, newSortedPager(elasticLike()), Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 2}).
		Plan(context.Background(), []ImageInput{input("docker.elastic.co/elasticsearch/elasticsearch:8.19.16", 'a', prepared, fixedA())})
	it := item(t, plan, 0)
	if it.Category != CategoryDeferred || it.Reason != ReasonTagPageLimit {
		t.Fatalf("item = %s/%s %s", it.Category, it.Reason, it.Detail)
	}
	if plan.Usage.TagPages != 2 {
		t.Errorf("tag pages = %d, want 2", plan.Usage.TagPages)
	}
}

func TestPlanSeriesDifferentSeriesOfOneRepositoryAreListedSeparately(t *testing.T) {
	e := newEnv()
	pager := newSortedPager([]string{"1.24.1", "1.24.2", "1.25.3", "1.25.4"})
	e.reg.res["nginx:1.24.2"] = resolution('b', 'c')
	e.reg.res["nginx:1.25.4"] = resolution('d', 'e')
	e.candidateScan("nginx:1.24.2", nil, pkgs("libc", "2"))
	e.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	plan := e.seriesPlanner(t, pager, bigLimits).Plan(context.Background(), []ImageInput{
		input("nginx:1.24.1", 'a', prepared, fixedA()), input("nginx:1.25.3", 'a', prepared, fixedA()),
	})
	got := map[string]string{}
	for _, it := range plan.Items {
		got[it.Current.Ref] = it.Candidate.Tag
	}
	if got["nginx:1.24.1"] != "1.24.2" || got["nginx:1.25.3"] != "1.25.4" {
		t.Errorf("candidates = %v", got)
	}
}

func TestRegistryFailureSeparatesRequestTimeoutFromCycleDeadline(t *testing.T) {
	timeout := fmt.Errorf("%w: GET https://x/v2/a/tags/list", registry.ErrTimeout)
	live := &run{ctx: context.Background()}
	var it Item
	live.registryFailure(&it, timeout)
	if it.Category != CategoryDeferred || it.Reason != ReasonRegistryTimeout || live.halted != nil {
		t.Errorf("request timeout: %s/%s halted=%v; want deferred/registry_timeout without halting the pass", it.Category, it.Reason, live.halted)
	}

	dead, cancel := context.WithCancel(context.Background())
	cancel()
	for name, err := range map[string]error{
		"timeout while the cycle is over": timeout,
		"cycle context error":             fmt.Errorf("registry: GET x: %w", context.DeadlineExceeded),
		"canceled":                        context.Canceled,
	} {
		r := &run{ctx: dead}
		it = Item{}
		r.registryFailure(&it, err)
		if it.Category != CategoryDeferred || it.Reason != ReasonCycleDeadline || r.halted == nil {
			t.Errorf("%s: %s/%s halted=%v; want deferred/cycle_deadline and a halt", name, it.Category, it.Reason, r.halted)
		}
	}
}

func TestPlanRequestTimeoutDefersOnlyThatRepository(t *testing.T) {
	e := newEnv()
	e.reg.tagErr["redis"] = fmt.Errorf("%w: GET https://registry-1.docker.io/...", registry.ErrTimeout)
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4"}, Pages: 1}
	e.reg.res["nginx:1.25.4"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	plan := e.planner(t, bigLimits, registry.NewBudget(100)).Plan(context.Background(), []ImageInput{
		input("redis:7.2.0", 'a', prepared, fixedA()), input("nginx:1.25.3", 'a', prepared, fixedA()),
	})
	byRef := map[string]Item{}
	for _, it := range plan.Items {
		byRef[it.Current.Ref] = it
	}
	if r := byRef["redis:7.2.0"]; r.Category != CategoryDeferred || r.Reason != ReasonRegistryTimeout {
		t.Errorf("redis = %s/%s", r.Category, r.Reason)
	}
	if n := byRef["nginx:1.25.3"]; n.Category != CategoryPRCandidate {
		t.Errorf("nginx = %s/%s %s; a slow repository must not stop the others", n.Category, n.Reason, n.Detail)
	}
}

func TestPlanSkipsLocallyBuiltImages(t *testing.T) {
	cases := []struct {
		ref     string
		digests []string
		local   bool
	}{
		{"regfis-infra-elasticsearch", nil, true},
		{"regfis-infra-elasticsearch:latest", nil, true},
		{"myteam/app:3", nil, true},
		{"nginx:1.25.3", pulledDigests, false}, // pulled from Docker Hub
		{"nginx", pulledDigests, false},        // pulled from Docker Hub, implicit latest
		{"ghcr.io/org/app:latest", nil, false}, // names a registry
		{"localhost:5000/app:1", nil, false},   // names a registry
		{"registry.example.com/a", nil, false}, // names a registry
		{"ghcr.io/org/app:latest", pulledDigests, false},
	}
	for _, c := range cases {
		e := newEnv()
		in := input(c.ref, 'a', prepared, fixedA())
		in.Scan.RegistryDigests = c.digests
		plan := e.planner(t, bigLimits, registry.NewBudget(100)).Plan(context.Background(), []ImageInput{in})
		it := item(t, plan, 0)
		gotLocal := it.Reason == ReasonLocallyBuilt
		if gotLocal != c.local {
			t.Errorf("%s with digests %v: %s/%s, locally built = %v, want %v", c.ref, c.digests, it.Category, it.Reason, gotLocal, c.local)
		}
		if c.local {
			if it.Category != CategoryExcluded {
				t.Errorf("%s: category %s, want excluded", c.ref, it.Category)
			}
			if e.reg.listCalls != 0 || len(e.reg.resolveCnt) != 0 || plan.Usage.RegistryRequests != 0 {
				t.Errorf("%s: the registry was contacted (list %d, resolve %v)", c.ref, e.reg.listCalls, e.reg.resolveCnt)
			}
		}
	}
}

func TestPlanLocallyBuiltRequiresAScanFirst(t *testing.T) {
	// A failed scan is reported as a failed scan, not as a local build: the
	// missing registry digest means nothing without a scan.
	in := input("regfis-infra-elasticsearch", 'a', prepared, fixedA())
	in.Scan.RegistryDigests = nil
	in.Scan.Err = errors.New("trivy failed")
	plan := newEnv().planner(t, bigLimits, registry.NewBudget(10)).Plan(context.Background(), []ImageInput{in})
	if it := item(t, plan, 0); it.Reason == ReasonLocallyBuilt {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

// The page limit is the repository's, however many series are read from it.
func TestPlanPageLimitIsPerRepositoryAcrossSeries(t *testing.T) {
	e := newEnv()
	pager := newSortedPager([]string{"1.25.3", "1.25.4", "1.30.1", "1.30.2"})
	e.reg.res["nginx:1.25.4"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	// The first walk needs five requests here (nothing sits in front of the
	// series), the second four.
	lim := Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 7}
	plan := e.seriesPlanner(t, pager, lim).Plan(context.Background(), []ImageInput{
		input("nginx:1.25.3", 'a', prepared, fixedA()), input("nginx:1.30.1", 'a', prepared, fixedA()),
	})
	got := map[string]Item{}
	for _, it := range plan.Items {
		got[it.Current.Ref] = it
	}
	if it := got["nginx:1.25.3"]; it.Category != CategoryPRCandidate {
		t.Errorf("first series = %s/%s %s", it.Category, it.Reason, it.Detail)
	}
	if it := got["nginx:1.30.1"]; it.Category != CategoryDeferred || it.Reason != ReasonTagPageLimit {
		t.Errorf("second series = %s/%s %s; want deferred by the repository's page limit", it.Category, it.Reason, it.Detail)
	}
	if plan.Usage.TagPages > 7 || pager.requests() > 7 {
		t.Errorf("tag pages = %d, requests = %d; the repository's limit is 7", plan.Usage.TagPages, pager.requests())
	}
}

func TestPlanSeriesListingIsSharedAcrossPatches(t *testing.T) {
	e := newEnv()
	pager := newSortedPager([]string{"1.24.0", "1.25.1", "1.25.3", "1.25.4"})
	e.reg.res["nginx:1.25.4"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	plan := e.seriesPlanner(t, pager, bigLimits).Plan(context.Background(), []ImageInput{input("nginx:1.25.3", 'a', prepared, fixedA())})
	one := pager.requests()
	e2 := newEnv()
	e2.reg.res["nginx:1.25.4"] = resolution('b', 'c')
	e2.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	pager2 := newSortedPager([]string{"1.24.0", "1.25.1", "1.25.3", "1.25.4"})
	plan2 := e2.seriesPlanner(t, pager2, bigLimits).Plan(context.Background(), []ImageInput{
		input("nginx:1.25.3", 'a', prepared, fixedA()), input("nginx:1.25.1", 'a', prepared, fixedA()),
	})
	if pager2.requests() != one || len(plan2.Items) != 2 {
		t.Errorf("two patches of one series took %d requests, one took %d", pager2.requests(), one)
	}
	for _, it := range plan2.Items {
		if it.Candidate == nil || it.Candidate.Tag != "1.25.4" {
			t.Errorf("%s: %s/%s", it.Current.Ref, it.Category, it.Reason)
		}
	}
	_ = plan
}
