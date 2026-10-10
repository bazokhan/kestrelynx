package runner

import (
	"context"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const dfFile = "FROM python:3.12.3-slim\nCOPY . /app\n"

// baseRegistry serves a python base image whose layers are the first two of
// the running image's, and the ordinary tags of the harness for the rest.
type baseRegistry struct{ planRegistry }

func (r *baseRegistry) ListTagsUpTo(ctx context.Context, repo string, n int) (registry.TagList, error) {
	if repo == "python" {
		return registry.TagList{Tags: []string{"3.12.3-slim", "3.12.5-slim"}, Pages: 1}, nil
	}
	return r.planRegistry.ListTagsUpTo(ctx, repo, n)
}

func (r *baseRegistry) Resolve(ctx context.Context, repo, ref string, p inventory.Platform) (registry.Resolution, error) {
	res, err := r.planRegistry.Resolve(ctx, repo, ref, p)
	if repo != "python" || err != nil {
		return res, err
	}
	res.RootFSType, res.DiffIDs = "layers", []string{"sha256:" + hex64('1'), "sha256:" + hex64('2')}
	if ref == "3.12.5-slim" {
		res.ManifestDigest, res.ConfigDigest = "sha256:"+hex64('d'), "sha256:"+hex64('e')
	}
	return res, nil
}

// withDockerfile gives the harness's running image three layers, a finding
// in the second, a Dockerfile mapping for its service and a source that
// serves the Dockerfile.
func (h *planHarness) withDockerfile(src *fakeSource) {
	layered := osFinding("CVE-1")
	layered.LayerDiffID = "sha256:" + hex64('2')
	for _, m := range []map[string]scanner.ImageScan{h.scn.local, h.normal.byImage} {
		s := m["web:1.25.3"]
		s.Findings = []scanner.Finding{layered}
		s.DiffIDs = []string{"sha256:" + hex64('1'), "sha256:" + hex64('2'), "sha256:" + hex64('3')}
		m["web:1.25.3"] = s
	}
	// The current base has the finding, the candidate base does not.
	h.scn.byRef = map[string][]scanner.Finding{"python:3.12.3-slim": {osFinding("CVE-1")}, "python:3.12.5-slim": nil}
	h.r.Plan.NewRegistry = func(b *registry.Budget) remediation.Registry {
		h.reg.budget = b
		return &baseRegistry{planRegistry: *h.reg}
	}
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "compose/shop/web", Project: "shop", Service: "web", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.r.Plan.NewGitHub = func() remediation.GitHubReader { return src }
}

func TestPlan_DockerfileItemsIncludedAndStored(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile}}
	h.withDockerfile(src)
	h.run(t)

	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.DockerfileItems) != 1 {
		t.Fatalf("Message.Plan = %+v", p)
	}
	it := p.Plan.DockerfileItems[0]
	if it.Category != remediation.CategoryPRCandidate || it.BaseRef != "python:3.12.3-slim" || it.Candidate == nil || it.Candidate.Tag != "3.12.5-slim" ||
		it.Counts.Targets != 1 || it.Counts.Resolved != 1 || it.Source.CommitSHA != langCommit {
		t.Errorf("Dockerfile item = %+v", it)
	}
	if len(it.Entities) != 1 || it.Entities[0].Layers.Status != "confirmed" || it.Entities[0].Layers.BaseLayers != 2 {
		t.Errorf("entities = %+v", it.Entities)
	}
	if len(h.plans.saved) != 1 || len(h.plans.saved[0].DockerfileItems) != 1 {
		t.Errorf("the saved plan lacks the Dockerfile items: %+v", h.plans.saved)
	}
	if want := remediation.Fingerprint(*p.Plan); len(h.delivered.saves) != 1 || h.delivered.saves[0] != want {
		t.Errorf("delivered = %v, want %q", h.delivered.saves, want)
	}
	if h.scn.local["web:1.25.3"].Image == "" {
		t.Fatal("harness")
	}
	// The running image is not scanned again; both bases are.
	scans := 0
	for _, e := range h.scn.events {
		if e == "scan:python:3.12.3-slim" || e == "scan:python:3.12.5-slim" {
			scans++
		}
	}
	if scans != 2 {
		t.Errorf("base scans = %d, events %v", scans, h.scn.events)
	}
}

func TestPlan_NoDockerfileMappingsChangesNothing(t *testing.T) {
	with := newPlanHarness(osFinding("CVE-1"))
	with.run(t)
	if p := with.notif.msg.Plan; p == nil || p.Plan == nil || p.Plan.DockerfileItems != nil {
		t.Errorf("plan = %+v", p)
	}

	// Mappings for other workloads read nothing.
	h := newPlanHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile}}
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "compose/shop/other", Project: "shop", Service: "other", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.r.Plan.NewGitHub = func() remediation.GitHubReader { return src }
	h.run(t)
	if len(src.calls) != 0 {
		t.Errorf("GitHub was read for a workload without a route: %v", src.calls)
	}
	if p := h.notif.msg.Plan; p == nil || p.Plan == nil || p.Plan.DockerfileItems != nil {
		t.Errorf("plan = %+v", p)
	}
}

func TestPlan_DockerfileRepositoriesReachThePullRequestStage(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile}}
	h.withDockerfile(src)
	h.r.Plan.PullRequests.Repositories = []string{"ex/web"}
	h.run(t)
	if h.stage.runs != 1 || len(h.stage.in.Repositories) != 1 || h.stage.in.Repositories[0] != "ex/web" {
		t.Errorf("stage input = %+v (runs %d)", h.stage.in.Repositories, h.stage.runs)
	}
	if len(h.stage.in.Plan.DockerfileItems) != 1 {
		t.Errorf("the stage's plan has %d Dockerfile items", len(h.stage.in.Plan.DockerfileItems))
	}
}
