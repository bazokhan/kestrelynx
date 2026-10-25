// Command kestrelynx regularly scans images used by running Docker and Kubernetes
// containers with Trivy and sends changes since the last scan and priorities
// based on severity, CISA KEV, and EPSS to Slack or a webhook.
// For Docker and Compose, remediation plans and pull requests (experimental)
// support remediation from comparing update candidates to creating GitHub pull
// requests, with both features disabled by default. Users handle merging,
// rebuilding, and deployment. See docs/ for more detail.
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/kubernetes"
	"github.com/kitsunetrail/kestrelynx/internal/nodecore"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/pycore"
	"github.com/kitsunetrail/kestrelynx/internal/regauth"
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

	// `kestrelynx receive` is the init container of a work Pod (see receive.go);
	// like sensor it is dispatched before the flag set parses os.Args.
	if len(os.Args) > 1 && os.Args[1] == "receive" {
		os.Exit(runReceiveCommand())
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
		Scanner:                  scanner.Trivy{Severity: cfg.Scan.Severity, DockerHost: trivyDockerHost(cfg)},
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
	// One advisor per language runtime serves every image scan of the cycle
	// (the normal scanner and, below, the fix plan's comparison scanner), so
	// they all match the runtimes against the same data. Fs scans in work.go
	// never get them.
	runtimeAdvisors, runtimeRefreshers := buildRuntimes(cfg, log)
	r.RuntimeRefreshers = runtimeRefreshers
	r.Scanner = withRuntimes(r.Scanner.(scanner.Trivy), runtimeAdvisors)
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
		for _, w := range cfg.MappingsOutsideScope() {
			log.Warn("a remediation mapping names a workload outside kubernetes.namespaces and has no effect", "workload", w)
		}
		r.Plan = buildPlanConfig(cfg)
		r.Plan.Scanner = withRuntimes(r.Plan.Scanner.(scanner.Trivy), runtimeAdvisors)
		r.Plan.Runtimes = runtimeAdvisors
		if cfg.Remediation.PullRequests.Enabled && len(r.Plan.Dependencies) > 0 {
			if cfg.Kubernetes.Enabled {
				r.Plan.Language = kubernetesLanguageConfig(cfg, log)
			} else {
				r.Plan.Language = buildLanguageConfig(cfg, log)
			}
		}
		l := cfg.Remediation.Limits
		log.Info("fix plan enabled",
			"candidate_scans_per_cycle", l.CandidateScansPerCycle,
			"baseline_rescans_per_cycle", l.BaselineRescansPerCycle,
			"registry_requests_per_cycle", l.RegistryRequestsPerCycle,
			"tag_pages_per_repository", l.TagPagesPerRepository,
			"cycle_timeout", l.CycleTimeout,
			"storage_dir", cfg.Remediation.StorageDir,
			"mappings", len(cfg.Remediation.Mappings),
			"registry_logins", len(cfg.Remediation.Registries),
			"github_token_set", cfg.Remediation.GitHub.Token != "",
			"pull_requests", cfg.Remediation.PullRequests.Enabled,
			"new_prs_per_cycle", l.NewPRsPerCycle,
			"open_prs", l.OpenPRs,
			"dependency_jobs_per_cycle", l.DependencyJobsPerCycle,
			"job_timeout", l.JobTimeout)
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

// workloadParts splits a mapping's workload key: the project and service of a
// Compose key, nothing for a Kubernetes key, which is used whole. ok is false
// for a key of neither form, which config validation has already refused.
func workloadParts(key string) (project, service string, ok bool) {
	if p, s, err := config.ParseWorkloadKey(key); err == nil {
		return p, s, true
	}
	if _, err := config.ParseKubernetesWorkloadKey(key); err == nil {
		return "", "", true
	}
	return "", "", false
}

// dependencyMappings picks the mappings that read a dependency root. Config
// validation has already checked the workload keys.
func dependencyMappings(ms []config.RemediationMapping) []remediation.DependencyMapping {
	var out []remediation.DependencyMapping
	for _, m := range ms {
		if m.Dependencies == nil {
			continue
		}
		project, service, ok := workloadParts(m.Workload)
		if !ok {
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
		project, service, ok := workloadParts(m.Workload)
		if !ok {
			continue
		}
		out = append(out, remediation.ComposeMapping{
			Workload: m.Workload, Project: project, Service: service,
			Repository: m.Repository, BaseBranch: m.BaseBranch, Path: m.Compose.Path, ComposeService: m.Compose.Service,
		})
	}
	return out
}

// dockerfileMappings picks the mappings that name a Dockerfile. Config
// validation has already checked the workload keys.
func dockerfileMappings(ms []config.RemediationMapping) []remediation.DockerfileMapping {
	var out []remediation.DockerfileMapping
	for _, m := range ms {
		if m.Dockerfile == nil {
			continue
		}
		project, service, ok := workloadParts(m.Workload)
		if !ok {
			continue
		}
		out = append(out, remediation.DockerfileMapping{
			Workload: m.Workload, Project: project, Service: service,
			Repository: m.Repository, BaseBranch: m.BaseBranch, Path: m.Dockerfile.Path, Target: m.Dockerfile.Target,
		})
	}
	return out
}

// kubernetesMappings picks the mappings that edit a Kubernetes manifest.
// Config validation has already checked the workload keys.
func kubernetesMappings(ms []config.RemediationMapping) []remediation.KubernetesMapping {
	var out []remediation.KubernetesMapping
	for _, m := range ms {
		if m.Manifest == nil {
			continue
		}
		out = append(out, remediation.KubernetesMapping{
			Workload: m.Workload, Repository: m.Repository, BaseBranch: m.BaseBranch,
			Path: m.Manifest.Path, ObjectKind: m.Manifest.ObjectKind, ObjectName: m.Manifest.ObjectName,
		})
	}
	return out
}

// kustomizeMappings picks the mappings that edit a Kustomize images entry.
func kustomizeMappings(ms []config.RemediationMapping) []remediation.KustomizeMapping {
	var out []remediation.KustomizeMapping
	for _, m := range ms {
		if m.Kustomize == nil {
			continue
		}
		out = append(out, remediation.KustomizeMapping{
			Workload: m.Workload, Repository: m.Repository, BaseBranch: m.BaseBranch,
			Path: m.Kustomize.Path, Image: m.Kustomize.Image, Affects: append([]string(nil), m.Kustomize.Affects...),
		})
	}
	return out
}

// helmValuesMappings picks the mappings that edit a Helm values key.
func helmValuesMappings(ms []config.RemediationMapping) []remediation.HelmValuesMapping {
	var out []remediation.HelmValuesMapping
	for _, m := range ms {
		if m.HelmValues == nil {
			continue
		}
		out = append(out, remediation.HelmValuesMapping{
			Workload: m.Workload, Repository: m.Repository, BaseBranch: m.BaseBranch,
			Path: m.HelmValues.Path, Key: m.HelmValues.Key, Affects: append([]string(nil), m.HelmValues.Affects...),
		})
	}
	return out
}

// dockerfileRepositories lists the repositories of the Dockerfile mappings,
// each once.
func dockerfileRepositories(ms []remediation.DockerfileMapping) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range ms {
		if k := strings.ToLower(m.Repository); !seen[k] {
			seen[k] = true
			out = append(out, m.Repository)
		}
	}
	return out
}

// pullRequestRepositories lists the repositories the pull request stage
// examines besides those of the Compose mappings: those of the Dockerfile and
// dependency mappings, each once. A repository with an open pull request of
// this tool is reconciled even in a cycle that has nothing new to propose.
func pullRequestRepositories(ms []config.RemediationMapping) []string {
	var out []string
	seen := map[string]bool{}
	add := func(repo string) {
		if k := strings.ToLower(repo); !seen[k] {
			seen[k] = true
			out = append(out, repo)
		}
	}
	for _, repo := range dockerfileRepositories(dockerfileMappings(ms)) {
		add(repo)
	}
	for _, m := range dependencyMappings(ms) {
		add(m.Repository)
	}
	for _, m := range kubernetesMappings(ms) {
		add(m.Repository)
	}
	for _, m := range kustomizeMappings(ms) {
		add(m.Repository)
	}
	for _, m := range helmValuesMappings(ms) {
		add(m.Repository)
	}
	return out
}

// buildPullRequestConfig assembles the pull request stage. The write client
// exists only here, so with pull requests off nothing in the process can
// write to GitHub. Each cycle gets its own write and read clients, each with
// its own request budget; the token goes to those clients alone.
func buildPullRequestConfig(rc config.RemediationConfig, language string) *runner.PullRequestConfig {
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
				Language: remediation.BodyLanguage(language),
			})
			if err != nil {
				return nil, err
			}
			return stage, nil
		},
		Mappings:     composeMappings(rc.Mappings),
		Kubernetes:   kubernetesMappings(rc.Mappings),
		Kustomize:    kustomizeMappings(rc.Mappings),
		HelmValues:   helmValuesMappings(rc.Mappings),
		Repositories: pullRequestRepositories(rc.Mappings),
		Store:        store,
	}
}

// buildRuntimes builds the advisor and the refresher of every language
// runtime the config enables, in the order the refreshers are called (Node.js,
// then CPython). Both slices are empty when none is enabled.
func buildRuntimes(cfg config.Config, log *slog.Logger) ([]scanner.RuntimeAdvisor, []runner.RuntimeRefresher) {
	var advisors []scanner.RuntimeAdvisor
	var refreshers []runner.RuntimeRefresher
	if cfg.Scan.NodeRuntime.Enabled {
		advisor, refresher := buildNodeRuntime(cfg, log)
		advisors = append(advisors, advisor)
		refreshers = append(refreshers, refresher)
	}
	if cfg.Scan.PythonRuntime.Enabled {
		advisor, refresher := buildPythonRuntime(cfg, log)
		advisors = append(advisors, advisor)
		refreshers = append(refreshers, refresher)
	}
	return advisors, refreshers
}

// withRuntimes returns tr with the advisors appended to its runtime checks.
func withRuntimes(tr scanner.Trivy, advisors []scanner.RuntimeAdvisor) scanner.Trivy {
	tr.Runtimes = append(tr.Runtimes, advisors...)
	return tr
}

// buildNodeRuntime builds the Node.js advisory data source and the advisor the
// image scanners share. The data is cached in a nodejs directory next to the
// diff state, like the intel cache, whether or not triage is enabled, so one
// volume mount covers all of it.
func buildNodeRuntime(cfg config.Config, log *slog.Logger) (*nodecore.Advisor, nodecore.Refresher) {
	nr := cfg.Scan.NodeRuntime
	advisor := &nodecore.Advisor{}
	return advisor, nodecore.Refresher{
		Source: &nodecore.Source{
			CacheDir:        filepath.Join(filepath.Dir(cfg.State.Path), "nodejs"),
			SecurityWGURL:   nr.SecurityWGURL,
			BlogFeedURL:     nr.BlogFeedURL,
			BlogPostBaseURL: nr.BlogPostBaseURL,
			ReleasesURL:     nr.ReleasesURL,
			ScheduleURL:     nr.ScheduleURL,
			Log:             log,
		},
		Advisor: advisor,
	}
}

// buildPythonRuntime builds the CPython advisory data source and the advisor
// the image scanners share. The data is cached in a python directory next to
// the diff state, like the Node.js data.
func buildPythonRuntime(cfg config.Config, log *slog.Logger) (*pycore.Advisor, pycore.Refresher) {
	pr := cfg.Scan.PythonRuntime
	advisor := &pycore.Advisor{}
	return advisor, pycore.Refresher{
		Source: &pycore.Source{
			CacheDir:         filepath.Join(filepath.Dir(cfg.State.Path), "python"),
			AdvisoryDBURL:    pr.AdvisoryDBURL,
			CVERecordBaseURL: pr.CVERecordBaseURL,
			ReleasesURL:      pr.ReleasesURL,
			ReleaseCycleURL:  pr.ReleaseCycleURL,
			Log:              log,
		},
		Advisor: advisor,
	}
}

// buildPlanConfig assembles the fix plan and, with pull requests enabled, the
// pull request stage. With Kubernetes, config validation allows manifest,
// Dockerfile and dependency mappings.
func buildPlanConfig(cfg config.Config) *runner.PlanConfig {
	rc := cfg.Remediation
	l := rc.Limits
	// Config validation has rejected a host listed twice, the only way the
	// store can fail to build; without logins the store is nil and every
	// registry is reached anonymously.
	auth, _ := rc.RegistryCredentials()
	challenger := &cycleChallenger{}
	pc := &runner.PlanConfig{
		// Comparison mode: the databases PrepareDB fixes are the only ones
		// any scan of the cycle uses. The registry logins reach Trivy only for
		// a scan that fetches from the login's own host.
		Scanner: scanner.Trivy{Severity: cfg.Scan.Severity, SkipDBUpdate: true, Auth: auth, Challenger: challenger, DockerHost: trivyDockerHost(cfg)},
		NewRegistry: func(b *registry.Budget) remediation.Registry {
			c := registry.New(registry.Options{Budget: b, MaxTagPages: l.TagPagesPerRepository, Auth: auth})
			challenger.use(c)
			return c
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
		pc.PullRequests = buildPullRequestConfig(rc, cfg.Notify.Language)
	}
	pc.Dependencies = dependencyMappings(rc.Mappings)
	pc.Dockerfiles = dockerfileMappings(rc.Mappings)
	pc.Composes = composeMappings(rc.Mappings)
	if len(pc.Dependencies) > 0 || len(pc.Dockerfiles) > 0 || len(pc.Composes) > 0 {
		// One client per cycle: its request budget and file byte total are
		// per-cycle counters. The token goes to this client alone.
		token := rc.GitHub.Token.Value()
		pc.NewGitHub = func() remediation.GitHubReader {
			return github.New(github.Options{Token: github.Token(token), Budget: github.NewBudget(gitHubRequestsPerCycle)})
		}
	}
	return pc
}

// trivyDockerHost is the Docker socket image scans read local images from:
// the one the container list comes from, or none on Kubernetes, where no
// Docker socket is configured.
func trivyDockerHost(cfg config.Config) string {
	if cfg.Kubernetes.Enabled {
		return ""
	}
	return cfg.Docker.Socket
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

// cycleChallenger answers the scanner's authentication checks with the
// registry client of the cycle being planned, so that those requests count
// against the cycle's registry request budget like all the others. The plan
// builds the client when a cycle starts (use) and scans only after that, one
// cycle at a time.
type cycleChallenger struct {
	mu     sync.Mutex
	client *registry.Client
}

func (c *cycleChallenger) use(cl *registry.Client) {
	c.mu.Lock()
	c.client = cl
	c.mu.Unlock()
}

func (c *cycleChallenger) Challenges(ctx context.Context, repo string) ([]regauth.Challenge, error) {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()
	if cl == nil {
		return nil, errors.New("no registry client for this cycle")
	}
	return cl.Challenges(ctx, repo)
}
