package main

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// With Kubernetes the plan is built from dependency mappings keyed by the
// Kubernetes workload key, reads GitHub, and has no pull request stage, no
// language updater and no Docker host to scan from.
func TestBuildPlanConfig_Kubernetes(t *testing.T) {
	cfg := config.Config{
		Kubernetes: config.KubernetesConfig{Enabled: true},
		Docker:     config.DockerConfig{Socket: "/var/run/docker.sock"},
		State:      config.StateConfig{Path: "/var/lib/kestrelynx/state.json"},
		Remediation: config.RemediationConfig{
			Enabled: true, StorageDir: "/data/remediation",
			Mappings: []config.RemediationMapping{{
				Workload: "deployment/shop/api/app", Repository: "ex/app", BaseBranch: "main",
				Dependencies: &config.RemediationDependenciesSource{Directory: "backend"},
			}},
		},
	}
	pc := buildPlanConfig(cfg)
	want := remediation.DependencyMapping{Workload: "deployment/shop/api/app", Repository: "ex/app", BaseBranch: "main", Directory: "backend"}
	if len(pc.Dependencies) != 1 || pc.Dependencies[0] != want {
		t.Errorf("dependencies = %+v, want %+v", pc.Dependencies, want)
	}
	if pc.NewGitHub == nil || pc.PullRequests != nil || pc.Language != nil {
		t.Errorf("GitHub reader %v, pull requests %v, language %v; want a reader only", pc.NewGitHub != nil, pc.PullRequests != nil, pc.Language != nil)
	}
	if trivy, ok := pc.Scanner.(scanner.Trivy); !ok || trivy.DockerHost != "" {
		t.Errorf("scanner = %+v, want no Docker host with Kubernetes", pc.Scanner)
	}
}

func TestWorkloadParts(t *testing.T) {
	for key, want := range map[string]struct {
		project, service string
		ok               bool
	}{
		"compose/shop/web":        {"shop", "web", true},
		"deployment/shop/web/app": {"", "", true},
		"cronjob/shop/report/job": {"", "", true},
		"deployment/shop/web":     {"", "", false},
		"container/shop-api":      {"", "", true},
		"container/a":             {"", "", false},
		"container/a/b":           {"", "", false},
		"not-a-key":               {"", "", false},
	} {
		p, s, ok := workloadParts(key)
		if p != want.project || s != want.service || ok != want.ok {
			t.Errorf("workloadParts(%q) = %q, %q, %v; want %q, %q, %v", key, p, s, ok, want.project, want.service, want.ok)
		}
	}
}

// With pull requests on, Kubernetes gets the pull request stage with the
// manifest mappings, whose repositories the stage examines, and a language
// stage that builds no updater.
func TestBuildPlanConfig_KubernetesPullRequests(t *testing.T) {
	cfg := config.Config{
		Kubernetes: config.KubernetesConfig{Enabled: true},
		State:      config.StateConfig{Path: "/var/lib/kestrelynx/state.json"},
		Remediation: config.RemediationConfig{
			Enabled: true, StorageDir: "/data/remediation",
			GitHub:       config.RemediationGitHubConfig{Token: "ghp_exampletoken"},
			PullRequests: config.RemediationPullRequestsConfig{Enabled: true},
			Limits:       config.RemediationLimits{NewPRsPerCycle: 2, OpenPRs: 5},
			Mappings: []config.RemediationMapping{
				{Workload: "deployment/shop/web/app", Repository: "ex/deploy", BaseBranch: "main", Manifest: &config.RemediationManifestSource{Path: "apps/web.yaml", ObjectName: "prod-web"}},
				{Workload: "deployment/shop/web/app", Repository: "ex/app", BaseBranch: "main", Dockerfile: &config.RemediationDockerfileSource{Path: "Dockerfile"}},
			},
		},
	}
	pc := buildPlanConfig(cfg)
	if pc.PullRequests == nil || pc.PullRequests.NewStage == nil {
		t.Fatal("no pull request stage")
	}
	want := remediation.KubernetesMapping{Workload: "deployment/shop/web/app", Repository: "ex/deploy", BaseBranch: "main", Path: "apps/web.yaml", ObjectName: "prod-web"}
	if got := pc.PullRequests.Kubernetes; len(got) != 1 || got[0] != want {
		t.Errorf("Kubernetes mappings = %+v, want %+v", got, want)
	}
	if got := pc.PullRequests.Repositories; len(got) != 2 {
		t.Errorf("repositories = %v, want both the Dockerfile's and the manifest's", got)
	}
	if len(pc.Dockerfiles) != 1 || pc.Dockerfiles[0].Workload != "deployment/shop/web/app" {
		t.Errorf("Dockerfile mappings = %+v", pc.Dockerfiles)
	}
	lc := kubernetesLanguageConfig(config.Config{}, quietLog())
	if lc.NewUpdater != nil || lc.Unavailable == nil || !lc.Unavailable.Manual || lc.Unavailable.Reason != remediation.ReasonWorkNamespaceNotConfigured {
		t.Errorf("language config = %+v", lc)
	}
}
