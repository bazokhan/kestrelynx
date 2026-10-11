package config

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

const goodWorkImage = "registry.example.com:5000/kestrelynx-worker@sha256:0d18f19513e094d4b1a1f0e9b7332992d2eeb481657e609d6ceeb1f6af20040c"

func TestParse_WorkerDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Remediation
	if r.Worker.Image != "" {
		t.Errorf("Worker.Image = %q, want the build's own image (empty)", r.Worker.Image)
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
    image: ` + goodWorkImage + `
  limits:
    dependency_jobs_per_cycle: 7
    job_timeout: 90s
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := c.Remediation
	if r.Worker.Image != goodWorkImage || r.Limits.DependencyJobsPerCycle != 7 || r.Limits.JobTimeout != 90*time.Second {
		t.Errorf("remediation = %+v", r)
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
	digest := "sha256:0d18f19513e094d4b1a1f0e9b7332992d2eeb481657e609d6ceeb1f6af20040c"
	cases := map[string]struct{ yaml, want string }{
		"tag instead of digest":           {"worker:\n    image: ghcr.io/example/worker:latest", "worker.image"},
		"short digest":                    {"worker:\n    image: ghcr.io/example/worker@sha256:abc", "worker.image"},
		"upper case repository":           {"worker:\n    image: GHCR.io/example/worker@" + digest, "worker.image"},
		"tag and digest":                  {"worker:\n    image: ghcr.io/example/worker:1@" + digest, "worker.image"},
		"double slash":                    {"worker:\n    image: ghcr.io//worker@" + digest, "worker.image"},
		"parent segment":                  {"worker:\n    image: ghcr.io/../worker@" + digest, "worker.image"},
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

// Pull requests with a work image set still need Docker mode, as before.
func TestParse_WorkerImageWithKubernetesStillRejected(t *testing.T) {
	_, err := Parse([]byte(minimal + `
kubernetes:
  enabled: true
remediation:
  enabled: true
  worker:
    image: ` + goodWorkImage + `
`))
	if err == nil || !strings.Contains(err.Error(), "kubernetes") {
		t.Fatalf("err = %v, want the kubernetes rejection", err)
	}
}
