package config

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func TestParse_WorkerDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Remediation
	if r.Worker.Registry != "" || r.Worker.ProgramDir != "" {
		t.Errorf("Worker = %+v, want no registry or program dir", r.Worker)
	}
	if r.Worker.ToolVersions.MinReleaseAge != 72*time.Hour || r.Worker.ToolVersions.CacheMaxSize != 1<<30 {
		t.Errorf("ToolVersions = %+v, want 72h and 1GiB", r.Worker.ToolVersions)
	}
	if r.Limits.DependencyJobsPerCycle != 3 {
		t.Errorf("DependencyJobsPerCycle = %d, want 3", r.Limits.DependencyJobsPerCycle)
	}
	if r.Limits.JobTimeout != remediation.DefaultUpdateJobTimeout {
		t.Errorf("JobTimeout = %s, want the update stage's default %s", r.Limits.JobTimeout, remediation.DefaultUpdateJobTimeout)
	}
}

func TestParse_WorkerExplicit(t *testing.T) {
	c, err := Parse([]byte(minimal + `
remediation:
  worker:
    registry: registry.example.com:5000/dockerhub
    program_dir: /opt/worker
    tool_versions:
      min_release_age: 96h
      cache_max_size: 512MiB
  limits:
    dependency_jobs_per_cycle: 7
    job_timeout: 90s
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := c.Remediation
	w := r.Worker
	if w.Registry != "registry.example.com:5000/dockerhub" || w.ProgramDir != "/opt/worker" ||
		w.ToolVersions.MinReleaseAge != 96*time.Hour || w.ToolVersions.CacheMaxSize != 512<<20 {
		t.Errorf("worker = %+v", w)
	}
	if r.Limits.DependencyJobsPerCycle != 7 || r.Limits.JobTimeout != 90*time.Second {
		t.Errorf("limits = %+v", r.Limits)
	}
}

func TestParse_JobTimeoutBounds(t *testing.T) {
	for _, v := range []string{"1m", "1h", "1h30s"} {
		c, err := Parse([]byte(minimal + "\nremediation:\n  limits:\n    job_timeout: " + v + "\n"))
		if err != nil {
			t.Errorf("%s: %v", v, err)
			continue
		}
		// The job deadline the update stage derives must fit the work program.
		if d := int(c.Remediation.Limits.JobTimeout.Seconds()) - 30; d < 1 || d > worker.MaxDeadlineSeconds {
			t.Errorf("%s gives a job deadline of %ds", v, d)
		}
	}
}

func TestParse_WorkerInvalid(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"registry with a scheme":          {"worker:\n    registry: https://registry.example.com", "worker.registry"},
		"registry with a tag":             {"worker:\n    registry: registry.example.com/dockerhub:latest", "worker.registry"},
		"registry with a digest":          {"worker:\n    registry: registry.example.com/x@sha256:abc", "worker.registry"},
		"registry with upper case":        {"worker:\n    registry: Registry.example.com", "worker.registry"},
		"registry with a double slash":    {"worker:\n    registry: registry.example.com//x", "worker.registry"},
		"registry with a parent segment":  {"worker:\n    registry: registry.example.com/../x", "worker.registry"},
		"registry with a trailing slash":  {"worker:\n    registry: registry.example.com/x/", "worker.registry"},
		"program dir not absolute":        {"worker:\n    program_dir: bin", "worker.program_dir"},
		"zero release age":                {"worker:\n    tool_versions:\n      min_release_age: 0s", "min_release_age"},
		"negative release age":            {"worker:\n    tool_versions:\n      min_release_age: -1h", "min_release_age"},
		"cache not a size":                {"worker:\n    tool_versions:\n      cache_max_size: lots", "cache_max_size"},
		"cache too small":                 {"worker:\n    tool_versions:\n      cache_max_size: 64MiB", "cache_max_size"},
		"cache negative":                  {"worker:\n    tool_versions:\n      cache_max_size: -5", "cache_max_size"},
		"zero jobs":                       {"limits:\n    dependency_jobs_per_cycle: 0", "dependency_jobs_per_cycle"},
		"negative jobs":                   {"limits:\n    dependency_jobs_per_cycle: -1", "dependency_jobs_per_cycle"},
		"zero job timeout":                {"limits:\n    job_timeout: 0s", "job_timeout"},
		"negative job timeout":            {"limits:\n    job_timeout: -5m", "job_timeout"},
		"job timeout too short":           {"limits:\n    job_timeout: 30s", "job_timeout"},
		"job timeout over the work limit": {"limits:\n    job_timeout: 2h", "job_timeout"},
		"job timeout just over":           {"limits:\n    job_timeout: 1h31s", "job_timeout"},
		"job timeout not a time":          {"limits:\n    job_timeout: soon", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(minimal + "\nremediation:\n  " + c.yaml + "\n"))
			if err == nil {
				t.Fatal("Parse accepted it")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// The work-image mirror setting is not tied to the adapter; with Kubernetes it
// is accepted like any other setting of a plan that runs no work containers.
func TestParse_WorkerRegistryWithKubernetesAccepted(t *testing.T) {
	_, err := Parse([]byte(minimal + `
kubernetes:
  enabled: true
remediation:
  enabled: true
  worker:
    registry: registry.example.com
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestParse_WorkerRegistryForms(t *testing.T) {
	for _, v := range []string{"registry.example.com", "registry.example.com:5000", "localhost:5000/dockerhub", "harbor.example.com/proxy-cache/dockerhub"} {
		if _, err := Parse([]byte(minimal + "\nremediation:\n  worker:\n    registry: " + v + "\n")); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
}

func TestParseByteSize(t *testing.T) {
	for in, want := range map[string]int64{"1GiB": 1 << 30, "512MiB": 512 << 20, "128 MiB": 128 << 20, "2048": 2048, "4KiB": 4096} {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GiB", "-1MiB", "1.5GiB", "9999999999999GiB"} {
		if _, err := parseByteSize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
