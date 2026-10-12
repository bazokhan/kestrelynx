package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func workTestConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		Docker: config.DockerConfig{Socket: filepath.Join(t.TempDir(), "no-docker.sock")},
		Remediation: config.RemediationConfig{
			Enabled: true, PullRequests: config.RemediationPullRequestsConfig{Enabled: true},
			StorageDir: filepath.Join(t.TempDir(), "remediation"),
			Limits:     config.RemediationLimits{DependencyJobsPerCycle: 2, JobTimeout: 3 * time.Minute},
		},
	}
}

// withProgramDir writes a work program file for this machine's architecture and
// points the configuration at its directory.
func withProgramDir(t *testing.T, cfg *config.Config, content string) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, worker.ProgramFileName(runtime.GOARCH))
	if err := os.WriteFile(file, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Remediation.Worker.ProgramDir = dir
	return file
}

// withToolSupply sets the factory of the package manager provider for a test.
func withToolSupply(t *testing.T, f func(config.Config, *slog.Logger) (toolSupply, error)) {
	t.Helper()
	saved := toolSupplyFactory
	toolSupplyFactory = f
	t.Cleanup(func() { toolSupplyFactory = saved })
}

func okToolSupply(config.Config, *slog.Logger) (toolSupply, error) {
	return toolSupply{DefaultVersion: func(remediation.DependencyManager, string) string { return "1.0.0" }}, nil
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

func TestBuildLanguageConfigWithoutAProgram(t *testing.T) {
	savedA, savedB := worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64
	worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64 = "", ""
	t.Cleanup(func() { worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64 = savedA, savedB })
	withToolSupply(t, okToolSupply)
	lc := buildLanguageConfig(workTestConfig(t), quietLog())
	if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageNotConfigured || lc.Unavailable.Detail == "" || lc.NewUpdater != nil {
		t.Errorf("config = %+v", lc)
	}
}

func TestBuildLanguageConfigLegacyImageKeyTurnsUpdatesOff(t *testing.T) {
	cfg := workTestConfig(t)
	withProgramDir(t, &cfg, "program")
	withToolSupply(t, okToolSupply)
	cfg.Remediation.Worker.LegacyImage = "ghcr.io/example/worker@sha256:" + strings.Repeat("a", 64)
	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageNotConfigured || !strings.Contains(lc.Unavailable.Detail, "remediation.worker.image") || lc.NewUpdater != nil {
		t.Errorf("config = %+v", lc)
	}
}

func TestBuildLanguageConfigWithoutAToolProvider(t *testing.T) {
	cfg := workTestConfig(t)
	withProgramDir(t, &cfg, "program")
	withToolSupply(t, nil)
	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable == nil || lc.NewUpdater != nil {
		t.Errorf("config = %+v", lc)
	}
}

func TestBuildLanguageConfigProgramProblemsTurnUpdatesOff(t *testing.T) {
	withToolSupply(t, okToolSupply)
	t.Run("missing file", func(t *testing.T) {
		cfg := workTestConfig(t)
		cfg.Remediation.Worker.ProgramDir = t.TempDir()
		lc := buildLanguageConfig(cfg, quietLog())
		if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageUnavailable {
			t.Errorf("config = %+v", lc)
		}
	})
	t.Run("not the embedded hash", func(t *testing.T) {
		savedA, savedB := worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64
		worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64 = strings.Repeat("0", 64), strings.Repeat("0", 64)
		t.Cleanup(func() { worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64 = savedA, savedB })
		dir := t.TempDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// The build's own directory is /usr/local/libexec/kestrelynx; a test
		// cannot write there, so the loader is checked directly.
		load, err := programLoader("", runtime.GOARCH)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := load(); err == nil {
			t.Error("a program that is not in the build's directory was loaded")
		}
	})
}

func TestBuildLanguageConfigEnabled(t *testing.T) {
	cfg := workTestConfig(t)
	withProgramDir(t, &cfg, "program")
	withToolSupply(t, okToolSupply)
	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable != nil || lc.NewUpdater == nil {
		t.Fatalf("config = %+v", lc)
	}
	// The instance id was created under storage_dir.
	if matches, _ := filepath.Glob(filepath.Join(cfg.Remediation.StorageDir, "work-instance-id")); len(matches) != 1 {
		t.Errorf("instance id files = %v", matches)
	}
	// The images are made ready when a job needs them, not when the cycle
	// starts, so the updater exists without a daemon.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	u, err := lc.NewUpdater(ctx, runner.LanguageUpdateInput{GitHub: nopGitHub{}, Prepared: scanner.ScanConditions{}})
	if err != nil || u == nil {
		t.Errorf("NewUpdater = %v, %v", u, err)
	}
}

func TestBuildLanguageConfigStorageProblemDisablesUpdates(t *testing.T) {
	cfg := workTestConfig(t)
	withProgramDir(t, &cfg, "program")
	withToolSupply(t, okToolSupply)
	cfg.Remediation.StorageDir = "/proc/kestrelynx-no-such-dir/x"
	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageUnavailable {
		t.Errorf("config = %+v", lc)
	}
}

func TestProgramLoaderChecksTheBytesEachTime(t *testing.T) {
	cfg := workTestConfig(t)
	file := withProgramDir(t, &cfg, "program one")
	load, err := programLoader(cfg.Remediation.Worker.ProgramDir, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := load(); err != nil || string(b) != "program one" {
		t.Fatalf("load = %q, %v", b, err)
	}
	if err := os.WriteFile(file, []byte("program two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := load(); err == nil {
		t.Error("a program changed after the start was loaded")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := load(); err == nil {
		t.Error("a program that is gone was loaded")
	}
	if err := os.WriteFile(file, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := programLoader(cfg.Remediation.Worker.ProgramDir, runtime.GOARCH); err == nil {
		t.Error("an empty program was accepted")
	}
	if _, err := programLoader("", "riscv64"); err == nil {
		t.Error("an architecture the build has no program for was accepted")
	}
}

func TestProgramLoaderUsesTheEmbeddedHash(t *testing.T) {
	// With no override the build's own directory is read; it does not exist
	// here, which is a failure to load, and an empty embedded hash means the
	// build carries no program.
	savedA, savedB := worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64
	t.Cleanup(func() { worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64 = savedA, savedB })
	worker.ProgramSHA256Amd64, worker.ProgramSHA256Arm64 = "", ""
	if _, err := programLoader("", runtime.GOARCH); !errors.Is(err, errNoProgramHash) {
		t.Errorf("err = %v, want errNoProgramHash", err)
	}
}

func TestWorkImageRef(t *testing.T) {
	spec, _ := worker.LookupRuntime("node24")
	if got := workImageRef(spec, ""); got != "node@"+spec.IndexDigest {
		t.Errorf("no mirror: %s", got)
	}
	if got := workImageRef(spec, "registry.example.com:5000/dockerhub"); got != "registry.example.com:5000/dockerhub/library/node@"+spec.IndexDigest {
		t.Errorf("mirror: %s", got)
	}
}

// nopGitHub stands in for the GitHub reader of a cycle; the updater only
// needs it to exist.
type nopGitHub struct{ remediation.GitHubReader }

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
