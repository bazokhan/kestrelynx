package main

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
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
	if buildPlanConfig(cfg).NewGitHub != nil {
		t.Error("a GitHub client is built for a compose-only mapping")
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
