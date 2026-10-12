package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The program the work container runs, and the environment its container gets.
// The container inherits nothing from this process. The program is not part of
// the image: it is placed into the container from this process's own files
// before the container starts.
var (
	workEntrypoint = []string{worker.ProgramPath, "run", worker.JobFile}
	workEnv        = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir}
	workEnvKeys    = []string{"PATH", "HOME"}
)

// maxProgramBytes bounds the work program file this process reads and places
// into a container.
const maxProgramBytes = 16 << 20

// workCleanupTimeout bounds the removal of containers an earlier run left.
const workCleanupTimeout = time.Minute

// workTransferLimits are the sizes a job may send and return. The log limit
// holds the largest result the work program can print: its tar, in base64
// with line breaks, and a margin for the block's header and end lines. The
// package manager archive and the program have limits of their own.
func workTransferLimits() docker.TransferLimits {
	tar := worker.DefaultResultLimits().MaxTarBytes
	enc := (tar + 2) / 3 * 4
	enc += enc/76 + 1
	logMax := enc + 1<<20
	return docker.TransferLimits{
		MaxInputBytes:     worker.MaxInputTotalBytes,
		MaxInputTarBytes:  worker.MaxInputTotalBytes + worker.MaxToolArchiveBytes + maxProgramBytes + 1<<20,
		MaxInputFiles:     worker.MaxInputs + 4,
		MaxInputPathBytes: 256,
		MaxToolBytes:      worker.MaxToolArchiveBytes,
		MaxProgramBytes:   maxProgramBytes,
		LogMaxBytes:       logMax,
		MaxStdoutBytes:    logMax,
	}
}

// toolSupply is where the package manager releases come from: the provider
// that fetches, checks and caches them, and the version of each manager to run
// when a project declares none.
type toolSupply struct {
	Provider       remediation.ToolProvider
	DefaultVersion func(m remediation.DependencyManager, runtimeID string) string
	// NewCycle renews the provider's budget of fetches; the update stage of a
	// cycle calls it once at its start.
	NewCycle func()
}

// toolSupplyFactory builds the toolSupply for a configuration: the provider
// that fetches, checks and caches the package manager releases under
// storage_dir. A test replaces it.
var toolSupplyFactory = func(cfg config.Config, log *slog.Logger) (toolSupply, error) {
	tv := cfg.Remediation.Worker.ToolVersions
	p, err := toolfetch.New(toolfetch.Config{
		StorageDir: cfg.Remediation.StorageDir, MinReleaseAge: tv.MinReleaseAge, CacheMaxSize: tv.CacheMaxSize,
	})
	if err != nil {
		return toolSupply{}, err
	}
	return toolSupply{
		Provider: remediation.NewToolProvider(p),
		DefaultVersion: func(m remediation.DependencyManager, runtimeID string) string {
			return toolfetch.DefaultVersion(toolfetch.Manager(m), runtimeID)
		},
		NewCycle: p.NewCycle,
	}, nil
}

// workImageRef is the pinned reference of a runtime's official image: the
// familiar Docker Hub form, or the mirror's host and path in place of Docker
// Hub's with the same repository below it.
func workImageRef(spec worker.RuntimeSpec, mirror string) string {
	if mirror == "" {
		return spec.ImageRef()
	}
	return mirror + "/library/" + spec.ImageRef()
}

// programLoader returns a function that reads the work program for goarch and
// checks it against the hash this build embeds. A program directory set in the
// configuration replaces the build's own files for development; the hash is
// then that of the file at start. The function is called each time a program
// is placed into a container, so the bytes sent are the bytes checked.
func programLoader(dir, goarch string) (func() ([]byte, error), error) {
	want, err := worker.ProgramSHA256(goarch)
	if err != nil {
		return nil, err
	}
	override := dir != ""
	if !override {
		dir = worker.ProgramDir
		if want == "" {
			return nil, errNoProgramHash
		}
	}
	file := filepath.Join(dir, worker.ProgramFileName(goarch))
	read := func() ([]byte, error) {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open the work program: %w", err)
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxProgramBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read the work program: %w", err)
		}
		if len(b) == 0 || len(b) > maxProgramBytes {
			return nil, fmt.Errorf("the work program %s is empty or over %d bytes", file, maxProgramBytes)
		}
		return b, nil
	}
	check := func(b []byte) error {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("the work program %s is not the one this build was released with", file)
		}
		return nil
	}
	if override {
		first, err := read()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(first)
		want = hex.EncodeToString(sum[:])
	}
	return func() ([]byte, error) {
		b, err := read()
		if err != nil {
			return nil, err
		}
		if err := check(b); err != nil {
			return nil, err
		}
		return b, nil
	}, nil
}

// errNoProgramHash says this build carries no work program.
var errNoProgramHash = errors.New("this build carries no work program")

// buildLanguageConfig assembles the dependency update stage. The work clients
// exist only here, so with pull requests off nothing in the process can start a
// work container. A problem that stops every update (the program is missing or
// altered, the clients cannot be set up, the removed worker.image key is still
// set) is returned as the reason the cycle's update candidates are deferred
// with; nothing is run in this process instead.
func buildLanguageConfig(cfg config.Config, log *slog.Logger) *runner.LanguageUpdateConfig {
	rc := cfg.Remediation
	unavailable := func(reason remediation.Reason, detail string, err error) *runner.LanguageUpdateConfig {
		log.Warn("language package updates are disabled", "reason", reason, "detail", detail, "err", err)
		return &runner.LanguageUpdateConfig{Unavailable: &runner.LanguageUnavailable{Reason: reason, Detail: detail}}
	}
	if rc.Worker.LegacyImage != "" {
		return unavailable(remediation.ReasonWorkImageNotConfigured,
			"remediation.worker.image was removed: the update containers now use the official Node.js and Python images pinned by this build; remove the key (use remediation.worker.registry for a mirror)", nil)
	}
	goarch := runtime.GOARCH
	program, err := programLoader(rc.Worker.ProgramDir, goarch)
	switch {
	case errors.Is(err, errNoProgramHash):
		return unavailable(remediation.ReasonWorkImageNotConfigured, "this build carries no work program and remediation.worker.program_dir is not set", nil)
	case err != nil:
		return unavailable(remediation.ReasonWorkImageUnavailable, "the work program is missing or is not the one this build was released with", err)
	}
	if _, err := program(); err != nil {
		return unavailable(remediation.ReasonWorkImageUnavailable, "the work program is missing or is not the one this build was released with", err)
	}
	if toolSupplyFactory == nil {
		return unavailable(remediation.ReasonWorkImageNotConfigured, "this build has no package manager provider", nil)
	}
	tools, err := toolSupplyFactory(cfg, log)
	if err != nil {
		return unavailable(remediation.ReasonWorkImageUnavailable, "the package manager provider could not be set up", err)
	}
	id, err := docker.LoadOrCreateInstanceID(rc.StorageDir)
	if err != nil {
		return unavailable(remediation.ReasonWorkImageUnavailable, "the instance id of the work containers could not be read or created", err)
	}
	platform := "linux/" + goarch
	set := docker.NewWorkSet()
	for _, rid := range remediation.DefaultRuntimeIDs() {
		spec, ok := worker.LookupRuntime(rid)
		if !ok || !spec.HasImage() {
			return unavailable(remediation.ReasonWorkImageUnavailable, "the runtime "+rid+" is not in the table of this build", nil)
		}
		wc, err := docker.NewWork(cfg.Docker.Socket, docker.WorkConfig{
			Image: workImageRef(spec, rc.Worker.Registry), Platform: platform,
			ExpectEnv:  map[string]string{spec.VersionEnv(): spec.Version},
			Entrypoint: workEntrypoint, Env: workEnv, AllowedEnvKeys: workEnvKeys,
			InstanceID: id, Limits: workTransferLimits(), Log: log,
		})
		if err == nil {
			err = set.Add(rid, wc)
		}
		if err != nil {
			return unavailable(remediation.ReasonWorkImageUnavailable, "the work container client for "+rid+" could not be set up", err)
		}
	}
	// Containers an earlier run left are removed once, before any client runs
	// a job.
	cctx, cancel := context.WithTimeout(context.Background(), workCleanupTimeout)
	if n, err := set.CleanupStale(cctx); err != nil {
		log.Warn("work containers left by an earlier run could not all be removed", "removed", n, "err", err)
	} else if n > 0 {
		log.Info("removed work containers left by an earlier run", "removed", n)
	}
	cancel()

	l := rc.Limits
	log.Info("language package updates enabled", "runtimes", set.Keys(), "platform", platform, "registry", rc.Worker.Registry,
		"dependency_jobs_per_cycle", l.DependencyJobsPerCycle, "job_timeout", l.JobTimeout)
	return &runner.LanguageUpdateConfig{
		NewUpdater: func(ctx context.Context, in runner.LanguageUpdateInput) (runner.LanguageUpdater, error) {
			if tools.NewCycle != nil {
				tools.NewCycle()
			}
			return remediation.NewLangUpdater(remediation.LangUpdateConfig{
				Work:     set,
				Scanner:  scanner.Trivy{Severity: cfg.Scan.Severity, SkipDBUpdate: true},
				PyPI:     &remediation.PyPIClient{},
				Npm:      &remediation.NpmClient{},
				GitHub:   in.GitHub,
				Prepared: in.Prepared,
				Images:   in.Images,
				Intel:    in.Intel,
				MaxJobs:  l.DependencyJobsPerCycle, JobTimeout: l.JobTimeout,
				Tools: tools.Provider, DefaultToolVersion: tools.DefaultVersion,
				Platform: platform, Program: program,
			})
		},
	}
}
