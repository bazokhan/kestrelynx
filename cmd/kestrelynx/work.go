package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The program the work image runs, and the environment its container gets.
// The container inherits nothing from this process.
var (
	workEntrypoint = []string{"/usr/local/libexec/kestrelynx-worker", "run", worker.JobFile}
	workEnv        = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/worker"}
	workEnvKeys    = []string{"PATH", "HOME"}
)

// workCleanupTimeout bounds the removal of containers an earlier run left.
const workCleanupTimeout = time.Minute

// workTransferLimits are the sizes a job may send and return. The log limit
// holds the largest result the work program can print: its tar, in base64
// with line breaks, and a margin for the block's header and end lines.
func workTransferLimits() docker.TransferLimits {
	tar := worker.DefaultResultLimits().MaxTarBytes
	enc := (tar + 2) / 3 * 4
	enc += enc/76 + 1
	logMax := enc + 1<<20
	return docker.TransferLimits{
		MaxInputBytes:     worker.MaxInputTotalBytes,
		MaxInputTarBytes:  worker.MaxInputTotalBytes + 1<<20,
		MaxInputFiles:     worker.MaxInputs + 4,
		MaxInputPathBytes: 256,
		LogMaxBytes:       logMax,
		MaxStdoutBytes:    logMax,
	}
}

// buildLanguageConfig assembles the dependency update stage. The work client
// exists only here, so with pull requests off nothing in the process can start
// a work container. A problem that stops every update (no work image, the
// client cannot be set up) is returned as the reason the cycle's update
// candidates are deferred with; nothing is run in this process instead.
func buildLanguageConfig(cfg config.Config, log *slog.Logger) *runner.LanguageUpdateConfig {
	rc := cfg.Remediation
	image := rc.Worker.Image
	if image == "" {
		image = worker.DefaultImage
	}
	unavailable := func(reason remediation.Reason, detail string, err error) *runner.LanguageUpdateConfig {
		log.Warn("language package updates are disabled", "reason", reason, "detail", detail, "err", err)
		return &runner.LanguageUpdateConfig{Unavailable: &runner.LanguageUnavailable{Reason: reason, Detail: detail}}
	}
	if image == "" {
		return unavailable(remediation.ReasonWorkImageNotConfigured,
			"this build carries no work image and remediation.worker.image is not set", nil)
	}
	id, err := docker.LoadOrCreateInstanceID(rc.StorageDir)
	if err != nil {
		return unavailable(remediation.ReasonWorkImageUnavailable, "the instance id of the work containers could not be read or created", err)
	}
	wc, err := docker.NewWork(cfg.Docker.Socket, docker.WorkConfig{
		Image: image, Entrypoint: workEntrypoint, Env: workEnv, AllowedEnvKeys: workEnvKeys,
		InstanceID: id, Limits: workTransferLimits(), Log: log,
	})
	if err != nil {
		return unavailable(remediation.ReasonWorkImageUnavailable, "the work container client could not be set up", err)
	}
	cctx, cancel := context.WithTimeout(context.Background(), workCleanupTimeout)
	if n, err := wc.CleanupStale(cctx); err != nil {
		log.Warn("work containers left by an earlier run could not all be removed", "removed", n, "err", err)
	} else if n > 0 {
		log.Info("removed work containers left by an earlier run", "removed", n)
	}
	cancel()

	l := rc.Limits
	// The image is pulled when a cycle first needs it, and again in a later
	// cycle after a failed pull; once it is ready it is not checked again.
	var (
		mu    sync.Mutex
		ready bool
	)
	ensure := func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if ready {
			return nil
		}
		if err := wc.EnsureImage(ctx); err != nil {
			return err
		}
		ready = true
		return nil
	}
	log.Info("language package updates enabled", "work_image", image, "dependency_jobs_per_cycle", l.DependencyJobsPerCycle, "job_timeout", l.JobTimeout)
	return &runner.LanguageUpdateConfig{
		NewUpdater: func(ctx context.Context, in runner.LanguageUpdateInput) (runner.LanguageUpdater, error) {
			if err := ensure(ctx); err != nil {
				return nil, fmt.Errorf("work image: %w", err)
			}
			return remediation.NewLangUpdater(remediation.LangUpdateConfig{
				Work:     wc,
				Scanner:  scanner.Trivy{Severity: cfg.Scan.Severity, SkipDBUpdate: true},
				PyPI:     &remediation.PyPIClient{},
				Npm:      &remediation.NpmClient{},
				GitHub:   in.GitHub,
				Prepared: in.Prepared,
				Images:   in.Images,
				Intel:    in.Intel,
				MaxJobs:  l.DependencyJobsPerCycle, JobTimeout: l.JobTimeout,
			})
		},
	}
}
