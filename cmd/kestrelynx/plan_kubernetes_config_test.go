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
		"not-a-key":               {"", "", false},
	} {
		p, s, ok := workloadParts(key)
		if p != want.project || s != want.service || ok != want.ok {
			t.Errorf("workloadParts(%q) = %q, %q, %v; want %q, %q, %v", key, p, s, ok, want.project, want.service, want.ok)
		}
	}
}
