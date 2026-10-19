package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestBuildPlanConfig(t *testing.T) {
	cfg := config.Config{
		State: config.StateConfig{Path: "/var/lib/kestrelynx/state.json"},
		Remediation: config.RemediationConfig{
			Enabled:    true,
			StorageDir: "/data/remediation",
			Limits: config.RemediationLimits{
				CandidateScansPerCycle: 3, BaselineRescansPerCycle: 4, RegistryRequestsPerCycle: 50,
				TagPagesPerRepository: 5, CycleTimeout: 7 * time.Minute,
			},
		},
	}
	pc := buildPlanConfig(cfg)
	if pc.Limits.MaxCandidateScans != 3 || pc.Limits.MaxBaselineRescans != 4 || pc.Limits.MaxTagPages != 5 ||
		pc.MaxRegistryRequests != 50 || pc.CycleTimeout != 7*time.Minute {
		t.Errorf("plan config = %+v", pc)
	}
	ps, ok := pc.Plans.(remediation.PlanStore)
	ds, ok2 := pc.Delivered.(remediation.DeliveredStore)
	if !ok || !ok2 || ps.Path != "/data/remediation/plan.json" || ds.Path != "/data/remediation/delivered.json" {
		t.Errorf("stores = %+v / %+v, want them under storage_dir", pc.Plans, pc.Delivered)
	}
	if pc.NewGitHub != nil {
		t.Error("a GitHub client is built without a dependencies mapping")
	}

	cfg.Remediation.Mappings = []config.RemediationMapping{
		{Workload: "compose/p/web", Repository: "ex/deploy", BaseBranch: "main", Compose: &config.RemediationComposeSource{Path: "c.yml", Service: "web"}},
	}
	// A Compose mapping is read too: the build section of its service may name
	// a Dockerfile.
	if pc := buildPlanConfig(cfg); pc.NewGitHub == nil || len(pc.Composes) != 1 || len(pc.Dockerfiles) != 0 {
		t.Errorf("a compose-only mapping gives no GitHub client or no compose mapping: %+v", pc)
	}
	cfg.Remediation.Mappings = append(cfg.Remediation.Mappings,
		config.RemediationMapping{Workload: "compose/p/api", Repository: "ex/app", BaseBranch: "main", Dependencies: &config.RemediationDependenciesSource{Directory: "."}})
	pc = buildPlanConfig(cfg)
	if pc.NewGitHub == nil || pc.NewGitHub() == nil {
		t.Fatal("no GitHub client factory with a dependencies mapping")
	}
	if pc.NewGitHub() == pc.NewGitHub() {
		t.Error("the GitHub client must be new for each cycle")
	}
}

func TestDependencyMappings(t *testing.T) {
	got := dependencyMappings([]config.RemediationMapping{
		{Workload: "compose/shop/web", Repository: "ex/deploy", BaseBranch: "main", Compose: &config.RemediationComposeSource{Path: "c.yml", Service: "web"}},
		{Workload: "compose/shop/api", Repository: "ex/app", BaseBranch: "release", Dependencies: &config.RemediationDependenciesSource{Directory: "backend"}},
		{Workload: "not-a-key", Repository: "ex/app", BaseBranch: "main", Dependencies: &config.RemediationDependenciesSource{Directory: "."}},
	})
	if len(got) != 1 {
		t.Fatalf("mappings = %+v, want only the valid dependencies mapping", got)
	}
	want := remediation.DependencyMapping{Workload: "compose/shop/api", Project: "shop", Service: "api", Repository: "ex/app", BaseBranch: "release", Directory: "backend"}
	if got[0] != want {
		t.Errorf("mapping = %+v, want %+v", got[0], want)
	}
	cfg := config.Config{
		State: config.StateConfig{Path: "/var/lib/kestrelynx/state.json"},
		Remediation: config.RemediationConfig{
			Enabled: true, StorageDir: "/data/remediation",
			Mappings: []config.RemediationMapping{{Workload: "compose/shop/api", Repository: "ex/app", BaseBranch: "main", Dependencies: &config.RemediationDependenciesSource{Directory: "."}}},
		},
	}
	if pc := buildPlanConfig(cfg); len(pc.Dependencies) != 1 || pc.NewGitHub == nil {
		t.Errorf("plan config = %+v", pc)
	}
}

func TestBuildPlanConfig_PullRequests(t *testing.T) {
	cfg := config.Config{
		State: config.StateConfig{Path: "/var/lib/kestrelynx/state.json"},
		Remediation: config.RemediationConfig{
			Enabled: true, StorageDir: "/data/remediation",
			GitHub: config.RemediationGitHubConfig{Token: "ghp_exampletoken"},
			Limits: config.RemediationLimits{NewPRsPerCycle: 2, OpenPRs: 5},
			Mappings: []config.RemediationMapping{
				{Workload: "compose/shop/web", Repository: "ex/deploy", BaseBranch: "main", Compose: &config.RemediationComposeSource{Path: "deploy/compose.yml", Service: "web"}},
				{Workload: "compose/shop/api", Repository: "ex/app", BaseBranch: "main", Dependencies: &config.RemediationDependenciesSource{Directory: "."}},
			},
		},
	}
	if pc := buildPlanConfig(cfg); pc.PullRequests != nil {
		t.Fatal("a pull request stage is built with pull requests off")
	}

	cfg.Remediation.PullRequests.Enabled = true
	pc := buildPlanConfig(cfg)
	if pc.PullRequests == nil || pc.PullRequests.NewStage == nil {
		t.Fatalf("no pull request stage with pull requests on: %+v", pc.PullRequests)
	}
	want := []remediation.ComposeMapping{{
		Workload: "compose/shop/web", Project: "shop", Service: "web", Repository: "ex/deploy", BaseBranch: "main",
		Path: "deploy/compose.yml", ComposeService: "web",
	}}
	if got := pc.PullRequests.Mappings; len(got) != 1 || got[0] != want[0] {
		t.Errorf("mappings = %+v, want only the compose mapping %+v", got, want)
	}
	if st, ok := pc.PullRequests.Store.(remediation.PRStore); !ok || st.Dir != "/data/remediation" {
		t.Errorf("store = %+v, want the records under storage_dir", pc.PullRequests.Store)
	}
	a, err := pc.PullRequests.NewStage(nil)
	if err == nil || a != nil {
		t.Errorf("a stage without a resolver was built: %v, %v", a, err)
	}
	reg := fakeResolver{}
	s1, err := pc.PullRequests.NewStage(reg)
	if err != nil || s1 == nil {
		t.Fatalf("NewStage: %v", err)
	}
	if s2, _ := pc.PullRequests.NewStage(reg); s1 == s2 {
		t.Error("the stage (and its clients and budgets) must be new for each cycle")
	}

	cfg.Remediation.Limits = config.RemediationLimits{}
	if _, err := buildPlanConfig(cfg).PullRequests.NewStage(reg); err == nil {
		t.Error("a stage with no limits was built")
	}
}

type fakeResolver struct{}

func (fakeResolver) Resolve(context.Context, string, string, inventory.Platform) (registry.Resolution, error) {
	return registry.Resolution{}, nil
}

func TestDockerfileMappings(t *testing.T) {
	ms := []config.RemediationMapping{
		{Workload: "compose/shop/web", Repository: "ex/deploy", BaseBranch: "main", Compose: &config.RemediationComposeSource{Path: "c.yml", Service: "web"}},
		{Workload: "compose/shop/api", Repository: "ex/app", BaseBranch: "release", Dockerfile: &config.RemediationDockerfileSource{Path: "api/Dockerfile", Target: "runtime"}},
		{Workload: "compose/shop/worker", Repository: "EX/App", BaseBranch: "release", Dockerfile: &config.RemediationDockerfileSource{Path: "api/Dockerfile"}},
		{Workload: "not-a-key", Repository: "ex/app", BaseBranch: "main", Dockerfile: &config.RemediationDockerfileSource{Path: "Dockerfile"}},
	}
	got := dockerfileMappings(ms)
	if len(got) != 2 {
		t.Fatalf("mappings = %+v, want the two valid Dockerfile mappings", got)
	}
	want := remediation.DockerfileMapping{Workload: "compose/shop/api", Project: "shop", Service: "api", Repository: "ex/app", BaseBranch: "release", Path: "api/Dockerfile", Target: "runtime"}
	if got[0] != want {
		t.Errorf("mapping = %+v, want %+v", got[0], want)
	}
	if repos := dockerfileRepositories(got); len(repos) != 1 || repos[0] != "ex/app" {
		t.Errorf("repositories = %v, want the repository once", repos)
	}

	cfg := config.Config{
		State: config.StateConfig{Path: "/var/lib/kestrelynx/state.json"},
		Remediation: config.RemediationConfig{
			Enabled: true, StorageDir: "/data/remediation",
			GitHub:   config.RemediationGitHubConfig{Token: "ghp_exampletoken"},
			Limits:   config.RemediationLimits{NewPRsPerCycle: 2, OpenPRs: 5},
			Mappings: ms[:3],
		},
	}
	pc := buildPlanConfig(cfg)
	if len(pc.Dockerfiles) != 2 || pc.NewGitHub == nil {
		t.Errorf("plan config = %+v, want the Dockerfile mappings and a GitHub client", pc)
	}
	cfg.Remediation.PullRequests.Enabled = true
	pc = buildPlanConfig(cfg)
	if pc.PullRequests == nil || len(pc.PullRequests.Repositories) != 1 || pc.PullRequests.Repositories[0] != "ex/app" {
		t.Errorf("pull request config = %+v, want the Dockerfile repository", pc.PullRequests)
	}
}

func TestBuildPlanConfigPassesRegistryLoginsToScannerAndClient(t *testing.T) {
	cfg := config.Config{Remediation: config.RemediationConfig{
		Enabled: true, StorageDir: "/data/remediation",
		Limits:     config.RemediationLimits{TagPagesPerRepository: 5},
		Registries: []config.RemediationRegistry{{Host: "ghcr.io", Username: "me", Password: "pw-value", TokenHosts: []string{"auth.example.com"}}},
	}}
	pc := buildPlanConfig(cfg)
	tr, ok := pc.Scanner.(scanner.Trivy)
	if !ok {
		t.Fatalf("scanner is %T", pc.Scanner)
	}
	cred, ok := tr.Auth.For("ghcr.io")
	if !ok || cred.Username != "me" || cred.Password() != "pw-value" || !cred.AllowsTokenHost("auth.example.com") {
		t.Errorf("the scanner's credential = %v, %v", cred, ok)
	}
	if _, ok := tr.Auth.For("docker.io"); ok {
		t.Error("a login appeared for a host that was not configured")
	}
	if c, ok := pc.NewRegistry(registry.NewBudget(1)).(*registry.Client); !ok || c == nil {
		t.Errorf("registry client = %T", c)
	}

	cfg.Remediation.Registries = nil
	if tr := buildPlanConfig(cfg).Scanner.(scanner.Trivy); len(tr.Auth.Hosts()) != 0 {
		t.Error("logins appeared without configuration")
	}
}

// The scanner's authentication checks use the cycle's registry client, so
// they spend the cycle's request budget.
func TestBuildPlanConfigChallengesShareTheCycleBudget(t *testing.T) {
	cfg := config.Config{Remediation: config.RemediationConfig{
		Enabled: true, StorageDir: "/data/remediation",
		Limits:     config.RemediationLimits{TagPagesPerRepository: 5},
		Registries: []config.RemediationRegistry{{Host: "ghcr.io", Username: "me", Password: "pw-value"}},
	}}
	pc := buildPlanConfig(cfg)
	ch := pc.Scanner.(scanner.Trivy).Challenger
	if _, err := ch.Challenges(context.Background(), "ghcr.io/org/app"); err == nil {
		t.Error("a check before any cycle has a client must fail, not run unaccounted")
	}
	b := registry.NewBudget(0)
	pc.NewRegistry(b)
	if _, err := ch.Challenges(context.Background(), "ghcr.io/org/app"); !errors.Is(err, registry.ErrBudgetExhausted) {
		t.Errorf("err = %v; the check should have been refused by the cycle's budget", err)
	}
	// A new cycle's budget replaces the old one.
	b2 := registry.NewBudget(5)
	pc.NewRegistry(b2)
	_, _ = ch.Challenges(context.Background(), "127.0.0.1:1/org/app")
	if b2.Used() == 0 {
		t.Error("the new cycle's budget was not used")
	}
}

func TestTrivyDockerHost(t *testing.T) {
	cfg := config.Config{Docker: config.DockerConfig{Socket: "/run/user/1000/docker.sock"}}
	if got := trivyDockerHost(cfg); got != "/run/user/1000/docker.sock" {
		t.Errorf("docker host = %q, want the configured socket", got)
	}
	if tr, ok := buildPlanConfig(cfg).Scanner.(scanner.Trivy); !ok || tr.DockerHost != "/run/user/1000/docker.sock" {
		t.Errorf("plan scanner = %#v, want the configured socket", buildPlanConfig(cfg).Scanner)
	}
	cfg.Kubernetes.Enabled = true
	if got := trivyDockerHost(cfg); got != "" {
		t.Errorf("docker host on Kubernetes = %q, want none", got)
	}
}
