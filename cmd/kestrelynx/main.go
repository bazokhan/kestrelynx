// Command kestrelynx scans the host's running container images for HIGH/CRITICAL
// vulnerabilities and notifies Slack/webhook on a schedule. See docs/ for
// more detail.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/kubernetes"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func main() {
	// `kestrelynx sensor ...` is a distinct subcommand (the Sensor's
	// observer/probe entry point, see sensor.go), dispatched before the
	// default flag set below ever parses os.Args: it never reaches
	// flag.Parse() with "-config", so this leaves every other invocation
	// (no args, "-config ...", "--help", ...) exactly as it behaved before
	// this subcommand existed.
	if len(os.Args) > 1 && os.Args[1] == "sensor" {
		runSensorCommand(os.Args[2:])
		return
	}

	configPath := flag.String("config", "/etc/kestrelynx/config.yml", "path to config file")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	notifier := buildNotifier(cfg.Notify)
	if notifier == nil {
		log.Error("no notify target configured")
		os.Exit(1)
	}

	lister, envKind, scanSource, err := buildLister(cfg, log)
	if err != nil {
		log.Error("configure runtime adapter", "err", err)
		os.Exit(1)
	}

	// Kind identifies the Runtime Adapter this composition root wired up; it
	// is never config-driven (only Name is) — buildLister derives it
	// mechanically from whichever adapter cfg.Kubernetes.Enabled selected.
	env := inventory.Environment{Name: cfg.Environment.Name, Kind: envKind}

	r := runner.Runner{
		Lister:                   lister,
		Scanner:                  scanner.Trivy{Severity: cfg.Scan.Severity},
		Notifier:                 notifier,
		NotifyOnClean:            cfg.Notify.NotifyOnClean,
		FullReportDay:            runner.NoFullReport,
		Environment:              env,
		Source:                   scanSource,
		Now:                      time.Now,
		Log:                      log,
		GenericWebhookConfigured: cfg.Notify.GenericWebhookURL != "",
	}
	if cfg.Notify.Mode == "diff" {
		r.Store = state.FileStore{Path: cfg.State.Path, Env: env}
		if day, ok := cfg.Notify.FullReportWeekday(); ok {
			r.FullReportDay = day
		}
	}
	if cfg.Triage.Enabled {
		// The intel cache lives next to the diff state so one volume mount
		// covers both.
		r.Intel = &intel.Source{
			CacheDir: filepath.Join(filepath.Dir(cfg.State.Path), "intel"),
			KEVURL:   cfg.Triage.KEVURL,
			EPSSURL:  cfg.Triage.EPSSURL,
			Log:      log,
		}
		r.ActNowEPSS = cfg.Triage.ActNowEPSS
		r.WatchEPSS = cfg.Triage.WatchEPSS
		r.DiscussionLinks = cfg.Triage.DiscussionLinks
	}
	if cfg.Runtime.Enabled {
		r.Evidence = evidence.NewFileProvider(cfg.Runtime.EvidenceDir)
		r.MuteUnfixableNotInUse = cfg.Runtime.MuteUnfixableNotInUse
		// Config validation already rejects runtime.enabled alongside
		// kubernetes.enabled, so lister is always the Docker adapter here;
		// the type assertion just avoids widening ContainerLister itself
		// with an Inspect method every other adapter would also need to
		// implement.
		if dc, ok := lister.(*docker.Client); ok {
			r.Inspector = dc
		} else {
			log.Warn("runtime.enabled is set but the current runtime adapter cannot inspect containers; runtime usage will show as unavailable")
		}
	}

	if cfg.Remediation.Enabled {
		r.Plan = buildPlanConfig(cfg)
		l := cfg.Remediation.Limits
		log.Info("fix plan enabled",
			"candidate_scans_per_cycle", l.CandidateScansPerCycle,
			"baseline_rescans_per_cycle", l.BaselineRescansPerCycle,
			"registry_requests_per_cycle", l.RegistryRequestsPerCycle,
			"tag_pages_per_repository", l.TagPagesPerRepository,
			"cycle_timeout", l.CycleTimeout,
			"storage_dir", cfg.Remediation.StorageDir,
			"mappings", len(cfg.Remediation.Mappings),
			"github_token_set", cfg.Remediation.GitHub.Token != "",
			"pull_requests", cfg.Remediation.PullRequests.Enabled,
			"new_prs_per_cycle", l.NewPRsPerCycle,
			"open_prs", l.OpenPRs)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("kestrelynx started",
		"daily_at", cfg.Schedule.DailyAt,
		"run_on_start", cfg.Schedule.RunOnStart,
		"severity", cfg.Scan.Severity,
		"mode", cfg.Notify.Mode,
		"full_report_day", cfg.Notify.FullReportDay,
		"triage", cfg.Triage.Enabled)

	if err := r.Loop(ctx, cfg.Schedule); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("runner loop", "err", err)
		os.Exit(1)
	}
	log.Info("kestrelynx stopped")
}

// gitHubRequestsPerCycle is the provisional request budget of a
// cycle's GitHub client; like the other plan limits it is to be revisited once
// real runs show what a cycle costs.
const gitHubRequestsPerCycle = 200

// dependencyMappings picks the mappings that read a dependency root. Config
// validation has already checked the workload keys.
func dependencyMappings(ms []config.RemediationMapping) []remediation.DependencyMapping {
	var out []remediation.DependencyMapping
	for _, m := range ms {
		if m.Dependencies == nil {
			continue
		}
		project, service, err := config.ParseWorkloadKey(m.Workload)
		if err != nil {
			continue
		}
		out = append(out, remediation.DependencyMapping{
			Workload: m.Workload, Project: project, Service: service,
			Repository: m.Repository, BaseBranch: m.BaseBranch, Directory: m.Dependencies.Directory,
		})
	}
	return out
}

// composeMappings picks the mappings that edit a Compose file. Config
// validation has already checked the workload keys.
func composeMappings(ms []config.RemediationMapping) []remediation.ComposeMapping {
	var out []remediation.ComposeMapping
	for _, m := range ms {
		if m.Compose == nil {
			continue
		}
		project, service, err := config.ParseWorkloadKey(m.Workload)
		if err != nil {
			continue
		}
		out = append(out, remediation.ComposeMapping{
			Workload: m.Workload, Project: project, Service: service,
			Repository: m.Repository, BaseBranch: m.BaseBranch, Path: m.Compose.Path, ComposeService: m.Compose.Service,
		})
	}
	return out
}

// buildPullRequestConfig assembles the pull request stage. The write client
// exists only here, so with pull requests off nothing in the process can
// write to GitHub. Each cycle gets its own write and read clients, each with
// its own request budget; the token goes to those clients alone.
func buildPullRequestConfig(rc config.RemediationConfig) *runner.PullRequestConfig {
	token := rc.GitHub.Token.Value()
	store := remediation.PRStore{Dir: rc.StorageDir}
	limits := remediation.PRLimits{NewPRsPerCycle: rc.Limits.NewPRsPerCycle, OpenPRs: rc.Limits.OpenPRs}
	return &runner.PullRequestConfig{
		NewStage: func(resolver remediation.CandidateResolver) (runner.PRStage, error) {
			stage, err := remediation.NewPRStage(remediation.PRStageConfig{
				GitHub:   github.NewWriter(github.Options{Token: github.Token(token), Budget: github.NewBudget(gitHubRequestsPerCycle)}),
				Source:   github.New(github.Options{Token: github.Token(token), Budget: github.NewBudget(gitHubRequestsPerCycle)}),
				Resolver: resolver,
				Store:    store,
				Limits:   limits,
			})
			if err != nil {
				return nil, err
			}
			return stage, nil
		},
		Mappings: composeMappings(rc.Mappings),
		Store:    store,
	}
}

// buildPlanConfig assembles the read-only fix plan; config validation already
// restricts it to the Docker adapter.
func buildPlanConfig(cfg config.Config) *runner.PlanConfig {
	rc := cfg.Remediation
	l := rc.Limits
	pc := &runner.PlanConfig{
		// Comparison mode: the databases PrepareDB fixes are the only ones
		// any scan of the cycle uses.
		Scanner: scanner.Trivy{Severity: cfg.Scan.Severity, SkipDBUpdate: true},
		NewRegistry: func(b *registry.Budget) remediation.Registry {
			return registry.New(registry.Options{Budget: b, MaxTagPages: l.TagPagesPerRepository})
		},
		Limits: remediation.Limits{
			MaxCandidateScans:  l.CandidateScansPerCycle,
			MaxBaselineRescans: l.BaselineRescansPerCycle,
			MaxTagPages:        l.TagPagesPerRepository,
		},
		MaxRegistryRequests: l.RegistryRequestsPerCycle,
		CycleTimeout:        l.CycleTimeout,
		Plans:               remediation.PlanStore{Path: remediation.DefaultPlanPath(rc.StorageDir)},
		Delivered:           remediation.DeliveredStore{Path: remediation.DefaultDeliveredPath(rc.StorageDir)},
	}
	if rc.PullRequests.Enabled {
		pc.PullRequests = buildPullRequestConfig(rc)
	}
	pc.Dependencies = dependencyMappings(rc.Mappings)
	if len(pc.Dependencies) > 0 {
		// One client per cycle: its request budget and file byte total are
		// per-cycle counters. The token goes to this client alone.
		token := rc.GitHub.Token.Value()
		pc.NewGitHub = func() remediation.GitHubReader {
			return github.New(github.Options{Token: github.Token(token), Budget: github.NewBudget(gitHubRequestsPerCycle)})
		}
	}
	return pc
}

// buildLister constructs the Runtime Adapter cfg.Kubernetes.Enabled selects
// and reports which inventory.EnvironmentKind it wired up, along with the
// scanner.ScanSource that adapter's images must be scanned as (a registry
// digest reached over the network for Kubernetes, the runtime's own image
// store for Docker). Docker is the default path and behaves exactly as it
// did before this adapter existed; config validation already guarantees the
// two are mutually exclusive.
func buildLister(cfg config.Config, log *slog.Logger) (runner.ContainerLister, inventory.EnvironmentKind, scanner.ScanSource, error) {
	if cfg.Kubernetes.Enabled {
		client, err := kubernetes.New(kubernetes.Options{
			APIServer:     cfg.Kubernetes.APIServer,
			TokenFile:     cfg.Kubernetes.TokenFile,
			CAFile:        cfg.Kubernetes.CAFile,
			TLSServerName: cfg.Kubernetes.TLSServerName,
			Namespaces:    cfg.Kubernetes.Namespaces,
			Log:           log,
		})
		if err != nil {
			return nil, "", "", fmt.Errorf("kubernetes: %w", err)
		}
		return client, inventory.KindKubernetes, scanner.SourceRemote, nil
	}

	dockerClient := docker.New(cfg.Docker.Socket)
	dockerClient.Log = log
	return dockerClient, inventory.KindDocker, scanner.SourceLocal, nil
}

// buildNotifier assembles the configured notify targets into one Notifier.
func buildNotifier(c config.NotifyConfig) runner.Notifier {
	var notifiers []notify.Notifier
	lang := notify.Language(c.Language)
	// Config validation guarantees the token and webhook are mutually
	// exclusive; the API path adds the thread report the webhook can't do.
	if c.SlackBotToken != "" {
		notifiers = append(notifiers, notify.SlackAPINotifier{Token: c.SlackBotToken, Channel: c.SlackChannel, Language: lang})
	}
	if c.SlackWebhookURL != "" {
		notifiers = append(notifiers, notify.SlackNotifier{WebhookURL: c.SlackWebhookURL, Language: lang})
	}
	if c.GenericWebhookURL != "" {
		notifiers = append(notifiers, notify.WebhookNotifier{URL: c.GenericWebhookURL})
	}
	if len(notifiers) == 0 {
		return nil
	}
	return notify.Multi(notifiers...)
}
