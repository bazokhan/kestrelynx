package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

const testWorkImage = "127.0.0.1:5000/kestrelynx-worker@sha256:0d18f19513e094d4b1a1f0e9b7332992d2eeb481657e609d6ceeb1f6af20040c"

func workTestConfig(t *testing.T, image string) config.Config {
	t.Helper()
	return config.Config{
		Docker: config.DockerConfig{Socket: filepath.Join(t.TempDir(), "no-docker.sock")},
		Remediation: config.RemediationConfig{
			Enabled: true, PullRequests: config.RemediationPullRequestsConfig{Enabled: true},
			StorageDir: filepath.Join(t.TempDir(), "remediation"),
			Worker:     config.RemediationWorkerConfig{Image: image},
			Limits:     config.RemediationLimits{DependencyJobsPerCycle: 2, JobTimeout: 3 * time.Minute},
		},
	}
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The log of a work container must hold the largest result the work program
// can print: its tar in base64 with the block's line breaks and lines.
func TestWorkTransferLimitsHoldTheLargestResult(t *testing.T) {
	l := workTransferLimits()
	tar := worker.DefaultResultLimits().MaxTarBytes
	block := (tar+2)/3*4 + (tar+2)/3*4/76 + 1 + 200 // the base64 text, its newlines, the header and end lines
	if l.LogMaxBytes < block || l.MaxStdoutBytes < l.LogMaxBytes {
		t.Errorf("log max %d, stdout max %d, the largest block %d", l.LogMaxBytes, l.MaxStdoutBytes, block)
	}
	if l.MaxInputBytes < worker.MaxInputTotalBytes || l.MaxInputTarBytes <= l.MaxInputBytes || l.MaxInputFiles < worker.MaxInputs+1 {
		t.Errorf("input limits = %+v", l)
	}
}

func TestBuildLanguageConfigWithoutAWorkImage(t *testing.T) {
	saved := worker.DefaultImage
	worker.DefaultImage = ""
	t.Cleanup(func() { worker.DefaultImage = saved })
	lc := buildLanguageConfig(workTestConfig(t, ""), quietLog())
	if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageNotConfigured || lc.Unavailable.Detail == "" || lc.NewUpdater != nil {
		t.Errorf("config = %+v", lc)
	}
}

func TestBuildLanguageConfigUsesTheBuildsImageUnlessOverridden(t *testing.T) {
	saved := worker.DefaultImage
	worker.DefaultImage = testWorkImage
	t.Cleanup(func() { worker.DefaultImage = saved })
	cfg := workTestConfig(t, "")
	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable != nil || lc.NewUpdater == nil {
		t.Fatalf("config = %+v", lc)
	}
	// The instance id was created under storage_dir.
	if matches, _ := filepath.Glob(filepath.Join(cfg.Remediation.StorageDir, "work-instance-id")); len(matches) != 1 {
		t.Errorf("instance id files = %v", matches)
	}
	// Making the image ready needs the Docker daemon, which is not there: the
	// stage reports it and never builds an updater.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if u, err := lc.NewUpdater(ctx, runner.LanguageUpdateInput{}); err == nil || u != nil {
		t.Errorf("NewUpdater = %v, %v; want an error without a daemon", u, err)
	}
}

func TestBuildLanguageConfigStorageProblemDisablesUpdates(t *testing.T) {
	cfg := workTestConfig(t, testWorkImage)
	cfg.Remediation.StorageDir = "/proc/kestrelynx-no-such-dir/x"
	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageUnavailable {
		t.Errorf("config = %+v", lc)
	}
}

func TestPullRequestRepositoriesListsEachOnce(t *testing.T) {
	got := pullRequestRepositories([]config.RemediationMapping{
		{Workload: "compose/p/a", Repository: "Ex/App", BaseBranch: "main", Dockerfile: &config.RemediationDockerfileSource{Path: "Dockerfile"}},
		{Workload: "compose/p/b", Repository: "ex/app", BaseBranch: "main", Dependencies: &config.RemediationDependenciesSource{Directory: "."}},
		{Workload: "compose/p/c", Repository: "ex/libs", BaseBranch: "main", Dependencies: &config.RemediationDependenciesSource{Directory: "."}},
		{Workload: "compose/p/d", Repository: "ex/deploy", BaseBranch: "main", Compose: &config.RemediationComposeSource{Path: "c.yml", Service: "d"}},
	})
	if len(got) != 2 || got[0] != "Ex/App" || got[1] != "ex/libs" {
		t.Errorf("repositories = %v, want the Dockerfile and dependency repositories once each", got)
	}
}
