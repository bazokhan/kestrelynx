package runner

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	// A Compose file whose service builds from the Dockerfile at the root.
	composeBuildFile = "services:\n  web:\n    build: .\n"
	pipReqFile       = "urllib3==1.26.4\n"
)

func pythonFinding(vuln, pkg, ver, fixed string) scanner.Finding {
	return scanner.Finding{
		Class: scanner.ClassLang, Type: "python-pkg", Target: "Python", Package: pkg, InstalledVer: ver, FixedVer: fixed,
		Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

// standalone makes the harness's only container one that docker run started:
// it has the given name and no workload.
func (h *planHarness) standalone(name string) {
	cs := h.r.Lister.(fakeLister).containers
	cs[0].Name, cs[0].Workload = name, inventory.Workload{}
	h.r.Lister = fakeLister{containers: cs}
}

func TestPlanContainer_DockerfileItem(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile}}
	h.withDockerfile(src)
	h.standalone("shop-api")
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "container/shop-api", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.run(t)

	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.DockerfileItems) != 1 {
		t.Fatalf("Message.Plan = %+v", p)
	}
	it := p.Plan.DockerfileItems[0]
	if it.Category != remediation.CategoryPRCandidate || it.Candidate == nil || it.Candidate.Tag != "3.12.5-slim" ||
		it.Source.Origin != remediation.DockerfileFromMapping {
		t.Errorf("Dockerfile item = %+v", it)
	}
	if len(it.Workloads) != 1 || it.Workloads[0] != "container/shop-api" {
		t.Errorf("workloads = %v", it.Workloads)
	}
}

func TestPlanContainer_SharedWithComposeBuildIsOneUnit(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile, "compose.yml": composeBuildFile}}
	h.withDockerfile(src)
	// Two containers run the same image: a Compose service built from the
	// Dockerfile and a container started with docker run.
	cs := h.r.Lister.(fakeLister).containers
	second := cs[0]
	second.ID, second.Name, second.Workload = "c2", "shop-api", inventory.Workload{}
	h.r.Lister = fakeLister{containers: append(cs, second)}
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "container/shop-api", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.r.Plan.Composes = []remediation.ComposeMapping{
		{Workload: "compose/shop/web", Project: "shop", Service: "web", Repository: "ex/web", BaseBranch: "main", Path: "compose.yml", ComposeService: "web"},
	}
	h.run(t)

	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.DockerfileItems) != 1 {
		t.Fatalf("Message.Plan = %+v", p)
	}
	it := p.Plan.DockerfileItems[0]
	if it.Source.Origin != remediation.DockerfileFromBoth || it.Category != remediation.CategoryPRCandidate {
		t.Errorf("origin = %s, category = %s (%s)", it.Source.Origin, it.Category, it.Reason)
	}
	if len(it.Workloads) != 2 || it.Workloads[0] != "compose/shop/web" || it.Workloads[1] != "container/shop-api" {
		t.Errorf("workloads = %v", it.Workloads)
	}
}

func TestPlanContainer_ComposeContainerNameIsNotMatched(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile}}
	h.withDockerfile(src)
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "container/shop-web-1", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.run(t)

	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.DockerfileItems) != 0 {
		t.Fatalf("Message.Plan = %+v, want no Dockerfile item", p)
	}
	if len(src.calls) != 0 {
		t.Errorf("GitHub was read for a mapping that matches no container: %v", src.calls)
	}
}

func TestPlanContainer_LanguageItems(t *testing.T) {
	cases := []struct {
		name    string
		finding scanner.Finding
		files   map[string]string
		manager remediation.DependencyManager
	}{
		{"npm", nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.21"), map[string]string{"package.json": langManifest, "package-lock.json": langLock}, remediation.ManagerNpm},
		{"pip", pythonFinding("CVE-3", "urllib3", "1.26.4", "1.26.5"), map[string]string{"requirements.txt": pipReqFile}, remediation.ManagerPip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newPlanHarness(osFinding("CVE-1"), c.finding)
			h.standalone("shop-api")
			h.r.Plan.Dependencies = []remediation.DependencyMapping{
				{Workload: "container/shop-api", Repository: "ex/web", BaseBranch: "main", Directory: "."},
			}
			h.r.Plan.NewGitHub = func() remediation.GitHubReader { return &fakeSource{repo: "ex/web", files: c.files} }
			h.run(t)

			p := h.notif.msg.Plan
			if p == nil || p.Plan == nil || len(p.Plan.LanguageItems) != 1 {
				t.Fatalf("Message.Plan = %+v", p)
			}
			it := p.Plan.LanguageItems[0]
			if it.Category != remediation.CategoryDependencyUpdateCandidate || it.Manager != c.manager {
				t.Errorf("language item = %s / %s (%s)", it.Category, it.Manager, it.Reason)
			}
			if len(it.Workloads) != 1 || it.Workloads[0] != "container/shop-api" {
				t.Errorf("workloads = %v", it.Workloads)
			}
		})
	}
}

// A mapping that names a container by another name than its own matches
// nothing, and Compose and Kubernetes mappings are untouched by the change.
func TestPlanContainer_OtherNameMatchesNothing(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	src := &fakeSource{repo: "ex/web", files: map[string]string{"Dockerfile": dfFile}}
	h.withDockerfile(src)
	h.standalone("shop-api")
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "container/other", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.run(t)
	if len(src.calls) != 0 {
		t.Errorf("GitHub was read: %v", src.calls)
	}
}

func TestPlanContainer_ComposeNameWarning(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h := newPlanHarness(osFinding("CVE-1"))
	h.r.Log = log
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "container/shop-web-1", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	warnings := func() int { return strings.Count(buf.String(), "names a container of a Compose service") }
	setCompose := func(group, name string) {
		cs := h.r.Lister.(fakeLister).containers
		cs[0].Name = "shop-web-1"
		cs[0].Workload = inventory.Workload{Kind: inventory.WorkloadCompose, Group: group, Name: name}
		h.r.Lister = fakeLister{containers: cs}
	}

	h.run(t)
	if warnings() != 1 || !strings.Contains(buf.String(), "compose/shop/web") || !strings.Contains(buf.String(), "container/shop-web-1") {
		t.Fatalf("first cycle: log = %q", buf.String())
	}
	h.run(t)
	if warnings() != 1 {
		t.Errorf("the same state warned again: %q", buf.String())
	}

	// The Compose key it points to changes.
	setCompose("shop", "api")
	h.run(t)
	if warnings() != 2 || !strings.Contains(buf.String(), "compose/shop/api") {
		t.Errorf("a changed Compose key did not warn: %q", buf.String())
	}

	// The mapping stops matching a Compose container, then matches one again.
	cs := h.r.Lister.(fakeLister).containers
	cs[0].Name, cs[0].Workload = "unrelated", inventory.Workload{}
	h.r.Lister = fakeLister{containers: cs}
	h.run(t)
	if warnings() != 2 {
		t.Errorf("warned while not matching: %q", buf.String())
	}
	setCompose("shop", "api")
	h.run(t)
	if warnings() != 3 {
		t.Errorf("did not warn after matching again: %q", buf.String())
	}
}

func TestPlanContainer_NoWarningWithoutContainerMappings(t *testing.T) {
	var buf bytes.Buffer
	h := newPlanHarness(osFinding("CVE-1"))
	h.r.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h.r.Plan.Dockerfiles = []remediation.DockerfileMapping{
		{Workload: "compose/shop/web", Project: "shop", Service: "web", Repository: "ex/web", BaseBranch: "main", Path: "Dockerfile"},
	}
	h.run(t)
	if strings.Contains(buf.String(), "Compose service") {
		t.Errorf("log = %q", buf.String())
	}
}
