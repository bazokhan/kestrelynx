package runner

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// PlanScanner is the comparison-mode scanner of the fix plan (implemented by
// scanner.Trivy with SkipDBUpdate set). PrepareDB fixes the vulnerability
// databases for the cycle; every scan then runs against them without
// updating, and VerifyDB tells whether they are still the prepared ones.
type PlanScanner interface {
	ImageScanner
	PrepareDB(ctx context.Context) (scanner.ScanConditions, error)
	VerifyDB(ctx context.Context, base scanner.ScanConditions) (bool, error)
}

// PlanStore keeps the latest plan (implemented by remediation.PlanStore).
type PlanStore interface {
	Save(remediation.Plan) error
}

// DeliveredStore keeps the fingerprint of the last plan that was delivered in
// a notification (implemented by remediation.DeliveredStore).
type DeliveredStore interface {
	Load() (string, error)
	Save(fingerprint string) error
}

// SlackDeliveredStore is the part of a DeliveredStore that keeps the
// fingerprint of the last Slack fix plan message. A store without it sends
// that message whenever the plan as a whole changed.
type SlackDeliveredStore interface {
	LoadSlack() (string, error)
	SaveSlack(fingerprint string) error
}

// PRStage runs the pull request stage once (implemented by
// *remediation.PRStage).
type PRStage interface {
	Run(ctx context.Context, in remediation.PRStageInput) remediation.PRStageResult
}

// LanguageUpdater runs the dependency update stage over a plan, in place
// (implemented by *remediation.LangUpdater).
type LanguageUpdater interface {
	Run(ctx context.Context, plan *remediation.Plan) remediation.LangUpdateUsage
}

// LanguageUpdateInput is what the update stage of one cycle is built from.
type LanguageUpdateInput struct {
	// Prepared are the cycle's scan conditions; the stage's scans of the
	// dependency files are valid only under them.
	Prepared scanner.ScanConditions
	// Images are the environments of the cycle's scanned images by entity key.
	Images map[string]remediation.ImageEnv
	// GitHub rereads the files a dependency unit was planned from.
	GitHub remediation.GitHubReader
	Intel  remediation.IntelFunc
}

// LanguageUpdateConfig turns on the dependency update stage that runs
// between the plan and the pull request stage. It exists only with pull
// requests enabled: the stage starts work containers.
type LanguageUpdateConfig struct {
	// Unavailable, when set, says why no update can run in this process (no
	// work image is configured, the Docker client could not be set up). Every
	// update candidate is then deferred with it; nothing is run instead.
	Unavailable *LanguageUnavailable
	// NewUpdater returns the stage for one cycle. An error (the work image
	// cannot be made ready) defers the cycle's update candidates.
	NewUpdater func(ctx context.Context, in LanguageUpdateInput) (LanguageUpdater, error)
}

// LanguageUnavailable is the reason dependency updates cannot run.
type LanguageUnavailable struct {
	Reason remediation.Reason
	Detail string
	// Manual says that no update can ever run in this process, so the update
	// candidates become manual items instead of being put off.
	Manual bool
}

// PullRequestConfig turns on the pull request stage of the plan. A PlanConfig
// without it never writes to GitHub.
type PullRequestConfig struct {
	// NewStage returns the stage for one cycle, built with the cycle's
	// registry client to re-resolve candidates and with GitHub clients that
	// carry the cycle's request budget.
	NewStage func(resolver remediation.CandidateResolver) (PRStage, error)
	// Mappings are the Compose mappings of the configuration, Kubernetes the
	// Kubernetes manifest mappings.
	Mappings   []remediation.ComposeMapping
	Kubernetes []remediation.KubernetesMapping
	// Kustomize are the Kustomize images entry mappings.
	Kustomize []remediation.KustomizeMapping
	// HelmValues are the Helm values key mappings.
	HelmValues []remediation.HelmValuesMapping
	// Repositories are the repositories the Dockerfile mappings name, which
	// the stage examines and writes to besides those of Mappings.
	Repositories []string
	// Store keeps the pull request records; the runner marks the operation
	// events delivered in it after a notification was sent.
	Store remediation.PRStorage
}

// PlanConfig holds what a Runner needs to build the read-only fix plan. A
// Runner with a nil Plan never prepares databases, never switches the scans
// to comparison mode and never touches the registry.
type PlanConfig struct {
	// Scanner scans the cycle's images (when the databases were prepared)
	// and the candidates.
	Scanner PlanScanner
	// NewRegistry returns the registry client for one cycle, built with the
	// budget the runner creates.
	NewRegistry func(*registry.Budget) remediation.Registry
	Limits      remediation.Limits
	// MaxRegistryRequests is the cycle's registry request budget.
	MaxRegistryRequests int
	// CycleTimeout is the deadline of the plan stage: the planner's registry
	// and candidate work, not the cycle's ordinary scans. Work the deadline
	// cuts off is deferred. Zero or less sets no deadline.
	CycleTimeout time.Duration
	// NewGitHub returns the read-only GitHub client for one cycle, used to
	// read the sources of the configured dependency, Dockerfile and Compose
	// mappings; nil when no such mapping exists.
	NewGitHub func() remediation.GitHubReader
	// Dependencies are the dependency mappings whose source files the plan
	// reads through the GitHub client.
	Dependencies []remediation.DependencyMapping
	// Dockerfiles are the Dockerfile mappings, and Composes the Compose
	// mappings whose services' build sections can name a Dockerfile; the plan
	// reads both through the GitHub client.
	Dockerfiles []remediation.DockerfileMapping
	Composes    []remediation.ComposeMapping
	Plans       PlanStore
	Delivered   DeliveredStore
	// PullRequests, when set, opens and tracks pull requests for the
	// update candidates of the plan; nil leaves the plan read-only.
	PullRequests *PullRequestConfig
	// Language, when set, updates the dependency units that are update
	// candidates in work containers and checks the result, so that they can
	// become pull requests; nil leaves them as candidates that were not run.
	Language *LanguageUpdateConfig
}

// planCycle is the plan state of one cycle.
type planCycle struct {
	prepared scanner.ScanConditions
	ok       bool // the databases were prepared; scans run in comparison mode
	// scanConds are the conditions the cycle's scans carry: the prepared
	// ones if the databases were verified unchanged after the scans, none
	// otherwise.
	scanConds scanner.ScanConditions
	// budget and reg are the cycle's registry request budget and registry
	// client. They are made before the cycle's scans, so that anything the
	// scanners ask the registry (which logins a scan may carry) spends the
	// same budget as the plan does, and the plan uses the same client.
	budget *registry.Budget
	reg    remediation.Registry
}

// planOutcome is what the plan contributes to the cycle's notification. The
// zero value is a cycle without a plan.
type planOutcome struct {
	info *notify.PlanInfo // nil when the plan is not enabled
	// fingerprint and changed are set only when a plan was produced. changed
	// means its content differs from the last delivered plan.
	fingerprint string
	changed     bool
	// slackFingerprint and slackChanged are the same for what the Slack fix
	// plan message shows (notify.PlanInfo.SlackFingerprint).
	slackFingerprint string
	slackChanged     bool
	// prLastSeq is the highest sequence number among the pull request
	// operation events the notification carries (0 when there are none).
	// prPending says the pull request stage has something to deliver whatever
	// the fingerprint says: operation events not yet delivered, or a problem
	// that stops its writes, which is reported every cycle while it lasts.
	prLastSeq int64
	prPending bool
}

// mustSend says the plan gives a reason to send a notification.
func (o planOutcome) mustSend() bool { return o.changed || o.prPending }

// message copies the plan into m, with whether it is the weekly day.
func (o planOutcome) message(m notify.Message) notify.Message {
	if o.info != nil {
		o.info.Weekly = m.FullReport
	}
	m.Plan = o.info
	return m
}

// preparePlan fixes the cycle's scan databases. A failure is logged and
// leaves the cycle without a plan; the normal scans then run as they do with
// the plan disabled.
func (r Runner) preparePlan(ctx context.Context) planCycle {
	conds, err := r.Plan.Scanner.PrepareDB(ctx)
	if err != nil {
		r.log().Warn("fix plan unavailable: scan databases could not be prepared", "err", err)
		return planCycle{}
	}
	cyc := planCycle{prepared: conds, ok: true}
	if r.Plan.NewRegistry != nil {
		cyc.budget = registry.NewBudget(r.Plan.MaxRegistryRequests)
		cyc.reg = r.Plan.NewRegistry(cyc.budget)
	}
	return cyc
}

// verifyScans checks, after the cycle's scans, that the databases are still
// the prepared ones; only then do the scans carry the prepared conditions.
// Otherwise the plan rescans the baselines it needs.
func (r Runner) verifyScans(ctx context.Context, cyc planCycle) planCycle {
	ok, err := r.Plan.Scanner.VerifyDB(ctx, cyc.prepared)
	switch {
	case err != nil:
		r.log().Warn("fix plan: scan databases could not be verified after the scans; baselines will be rescanned", "err", err)
	case !ok:
		r.log().Warn("fix plan: scan databases changed during the scans; baselines will be rescanned")
	default:
		cyc.scanConds = cyc.prepared
	}
	return cyc
}

// planUnavailable is the outcome of a cycle whose plan could not be built.
func (r Runner) planUnavailable(reason notify.PlanUnavailable) planOutcome {
	return r.finishPlan(&notify.PlanInfo{Unavailable: reason}, "")
}

// finishPlan fingerprints what the cycle delivers about the plan — the plan
// itself and any problem with it — and compares it with the last delivered
// one. A new problem, or the end of one, therefore counts as a change (and is
// sent even in a cycle with nothing else to say), while the same problem
// repeating does not.
func (r Runner) finishPlan(info *notify.PlanInfo, planFingerprint string) planOutcome {
	out := planOutcome{
		info:        info,
		fingerprint: remediation.StatusFingerprint(planFingerprint, string(info.Unavailable), info.NotSaved),
	}
	delivered := ""
	if r.Plan.Delivered != nil {
		var err error
		if delivered, err = r.Plan.Delivered.Load(); err != nil {
			// An unreadable record counts as nothing delivered: the plan is
			// announced again rather than lost.
			r.log().Warn("delivered fix plan record unreadable; treating the plan as undelivered", "err", err)
			delivered = ""
		}
	}
	out.changed = out.fingerprint != delivered
	info.Changed = out.changed

	// What the Slack message shows is compared on its own: it is the plan as a
	// reader sees it, so a change the message does not show does not send it.
	out.slackFingerprint = info.SlackFingerprint()
	out.slackChanged = out.changed
	if store, ok := r.Plan.Delivered.(SlackDeliveredStore); ok {
		last, err := store.LoadSlack()
		if err != nil {
			r.log().Warn("delivered Slack fix plan record unreadable; treating the plan as undelivered", "err", err)
			last = ""
		}
		out.slackChanged = out.slackFingerprint != last
	}
	info.SlackChanged = out.slackChanged
	return out
}

// buildPlan runs the planner over this cycle's scans and stores the result.
// Nothing here fails the cycle: a planner or store failure shows up in the
// outcome only.
func (r Runner) buildPlan(ctx context.Context, cyc planCycle, report analyze.Report, containers []inventory.Container, bindings []remediation.DeployBinding, scans []scanner.ImageScan, targets []scanner.ScanTarget) planOutcome {
	log := r.log()
	if !cyc.ok {
		return r.planUnavailable(notify.PlanDatabasesNotPrepared)
	}
	pc := r.Plan
	if pc.NewRegistry == nil {
		log.Warn("fix plan unavailable: no registry client configured")
		return r.planUnavailable(notify.PlanNotBuilt)
	}

	if pc.CycleTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, pc.CycleTimeout)
		defer cancel()
	}
	budget, reg := cyc.budget, cyc.reg
	var gh remediation.GitHubReader
	if pc.NewGitHub != nil && (len(pc.Dependencies) > 0 || len(pc.Dockerfiles) > 0 || len(pc.Composes) > 0) {
		// One client per cycle: its request budget and file byte total are
		// per-cycle counters. A nil client leaves the language and Dockerfile
		// parts off.
		if c := pc.NewGitHub(); c != nil {
			gh = c
		}
	}
	planner, err := remediation.NewPlanner(remediation.Config{
		Registry:     reg,
		Scanner:      pc.Scanner,
		Prepared:     cyc.prepared,
		Limits:       pc.Limits,
		Budget:       budget,
		Intel:        r.planIntel(ctx, report),
		GitHub:       gh,
		Dependencies: pc.Dependencies,
		Dockerfiles:  pc.Dockerfiles,
		Composes:     pc.Composes,
		Now:          r.now,
	})
	if err != nil {
		log.Warn("fix plan unavailable: planner could not be built", "err", err)
		return r.planUnavailable(notify.PlanNotBuilt)
	}

	inputs := planInputsWith(report, containers, bindings, scans, targets, cyc.scanConds)
	plan := planner.Plan(ctx, inputs)
	log.Info("fix plan built",
		"items", len(plan.Items),
		"pull_again", plan.Count(remediation.CategoryPullAgain),
		"update_candidate", plan.Count(remediation.CategoryPRCandidate),
		"dependency_units", len(plan.LanguageItems),
		"dependency_update_candidates", plan.CountLanguage(remediation.CategoryDependencyUpdateCandidate),
		"dockerfile_items", len(plan.DockerfileItems),
		"dockerfile_update_candidates", plan.CountDockerfile(remediation.CategoryPRCandidate),
		"candidate_scans", plan.Usage.CandidateScans,
		"baseline_rescans", plan.Usage.BaselineRescans,
		"registry_requests", plan.Usage.RegistryRequests)

	// The dependency update stage follows the plan and comes before it is
	// saved; the counts above are those of the plan alone.
	if pc.Language != nil {
		var store remediation.PRStorage
		if pc.PullRequests != nil {
			store = pc.PullRequests.Store
		}
		r.runLanguageUpdates(ctx, pc.Language, &plan, store, LanguageUpdateInput{
			Prepared: cyc.prepared, Images: remediation.ImageEnvs(inputs), GitHub: gh, Intel: r.planIntel(ctx, report),
		})
	}

	info := &notify.PlanInfo{Plan: &plan}
	if pc.Plans != nil {
		if err := pc.Plans.Save(plan); err != nil {
			log.Warn("fix plan could not be saved", "err", err)
			info.NotSaved = true
		}
	}

	if pc.PullRequests != nil {
		r.runPullRequests(ctx, pc.PullRequests, reg, &plan, containers, bindings, !info.NotSaved)
	}

	out := r.finishPlan(info, remediation.Fingerprint(plan))
	out.prLastSeq = lastOperationSeq(plan.PROperations)
	out.prPending = len(plan.PROperations) > 0 || len(plan.PRProblems) > 0
	return out
}

// runLanguageUpdates runs the dependency update stage over the plan, in
// place. Nothing here fails the cycle: when the stage cannot be set up, the
// update candidates are deferred with the reason and the rest of the plan is
// untouched.
func (r Runner) runLanguageUpdates(ctx context.Context, cfg *LanguageUpdateConfig, plan *remediation.Plan, store remediation.PRStorage, in LanguageUpdateInput) {
	log := r.log()
	if plan.CountLanguage(remediation.CategoryDependencyUpdateCandidate) == 0 {
		return
	}
	// Candidates whose inputs a pull request was already made from are tied to
	// it first, whatever the state of the work image: only what is left needs
	// the stage.
	order, bound := remediation.BindProposedLanguageUpdatesAt(plan, store, r.now())
	// What the pass found out about waiting is kept on every way out from
	// here, the ones that run nothing included: an item tied to a pull request
	// ends its wait, and an item that is still waiting has been seen.
	defer r.recordLanguageWaits(ctx, plan, store)
	if len(order) == 0 {
		log.Info("dependency update stage finished", "jobs", 0, "tied_to_existing_pull_requests", bound,
			"pr_candidates", plan.CountLanguage(remediation.CategoryPRCandidate))
		return
	}
	if cfg.Unavailable != nil && cfg.Unavailable.Manual {
		n := remediation.MarkLanguageManual(plan, cfg.Unavailable.Reason, cfg.Unavailable.Detail)
		log.Warn("dependency updates are not run", "reason", cfg.Unavailable.Reason, "manual", n, "tied_to_existing_pull_requests", bound)
		return
	}
	if cfg.Unavailable != nil {
		n := remediation.DeferLanguageUpdates(plan, cfg.Unavailable.Reason, cfg.Unavailable.Detail)
		log.Warn("dependency updates are not run", "reason", cfg.Unavailable.Reason, "deferred", n, "tied_to_existing_pull_requests", bound)
		return
	}
	if in.GitHub == nil || cfg.NewUpdater == nil {
		n := remediation.DeferLanguageUpdates(plan, remediation.ReasonWorkImageUnavailable, "the dependency update stage could not be set up")
		log.Warn("dependency updates are not run: the stage could not be set up", "deferred", n, "tied_to_existing_pull_requests", bound)
		return
	}
	updater, err := cfg.NewUpdater(ctx, in)
	var un *workexec.Unavailable
	if errors.As(err, &un) {
		// The executor says itself why nothing can run now (work Pods are at
		// their limit, the admission policy is not in force, ...).
		if un.Manual {
			n := remediation.MarkLanguageManual(plan, remediation.Reason(un.Reason), un.Detail)
			log.Warn("dependency updates are not run", "reason", un.Reason, "manual", n, "tied_to_existing_pull_requests", bound)
		} else {
			n := remediation.DeferLanguageUpdates(plan, remediation.Reason(un.Reason), un.Detail)
			log.Warn("dependency updates are not run", "reason", un.Reason, "deferred", n, "tied_to_existing_pull_requests", bound)
		}
		return
	}
	if err != nil {
		n := remediation.DeferLanguageUpdates(plan, remediation.ReasonWorkImageUnavailable, "the work image could not be made ready: "+clipText(err.Error(), 300))
		log.Warn("dependency updates are not run: the work image could not be made ready", "err", err, "deferred", n, "tied_to_existing_pull_requests", bound)
		return
	}
	use := remediation.RunLanguageUpdatesInOrder(ctx, updater.Run, plan, order)
	log.Info("dependency update stage finished",
		"jobs", use.Jobs,
		"tied_to_existing_pull_requests", bound,
		"pr_candidates", plan.CountLanguage(remediation.CategoryPRCandidate),
		"manual", plan.CountLanguage(remediation.CategoryManual),
		"deferred", plan.CountLanguage(remediation.CategoryDeferred),
		"failed", plan.CountLanguage(remediation.CategoryFailed))
}

// recordLanguageWaits saves the waits of the dependency update items in the
// pull request records. It runs on a context cut loose from the cycle's
// deadline and from the time an item was given to work in, so that an item
// that stopped for running out of either can still be counted, and for a short
// time of its own. When the waits cannot be saved, the items that were put off
// for them are settled without waiting.
func (r Runner) recordLanguageWaits(ctx context.Context, plan *remediation.Plan, store remediation.PRStorage) {
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := remediation.RecordLanguageWaits(saveCtx, store, plan, r.now()); err != nil {
		r.log().Warn("the waits of dependency updates could not be recorded; the items that were put off are settled instead", "err", err)
		remediation.ApplyWaitSaveFailure(plan, err)
	}
}

// clipText shortens s to at most n runes.
func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// runPullRequests runs the pull request stage on the saved plan and attaches
// its result to it, within the deadline of ctx. A plan that could not be
// saved is not acted on: nothing is written and the problem is reported.
func (r Runner) runPullRequests(ctx context.Context, cfg *PullRequestConfig, resolver remediation.CandidateResolver, plan *remediation.Plan, containers []inventory.Container, bindings []remediation.DeployBinding, saved bool) {
	log := r.log()
	if !saved {
		plan.PRProblems = []remediation.PRStageProblem{{
			Code: remediation.PRProblemStorageFailed, Reason: remediation.ReasonStorageFailed,
			Detail: "the fix plan could not be saved, so no pull request was processed",
		}}
		return
	}
	stage, err := cfg.NewStage(resolver)
	if err != nil {
		log.Warn("pull request stage could not be set up", "err", err)
		plan.PRProblems = []remediation.PRStageProblem{{
			Code: remediation.PRProblemWriteBlocked, Reason: remediation.ReasonGitHubError,
			Detail: "the pull request stage could not be set up",
		}}
		return
	}
	res := stage.Run(ctx, remediation.PRStageInput{Plan: *plan, Containers: containers, Mappings: cfg.Mappings, Kubernetes: cfg.Kubernetes, Kustomize: cfg.Kustomize, HelmValues: cfg.HelmValues, Management: observedManagement(containers, bindings), Repositories: cfg.Repositories})
	res.Attach(plan)
	created := 0
	for _, u := range res.Units {
		if u.Status == remediation.PRStatusCreated {
			created++
		}
	}
	log.Info("pull request stage finished",
		"units", len(res.Units), "created", created, "problems", len(res.Problems), "undelivered_operations", len(res.Operations))
}

// lastOperationSeq is the highest sequence number among events.
func lastOperationSeq(events []remediation.OperationEvent) int64 {
	var last int64
	for _, ev := range events {
		if ev.Seq > last {
			last = ev.Seq
		}
	}
	return last
}

// markDelivered records the plan's fingerprint after a notification carrying
// it was sent. A failure only means the plan may be announced again.
func (r Runner) markDelivered(o planOutcome) {
	if o.info == nil {
		return
	}
	if o.changed && r.Plan.Delivered != nil {
		if err := r.Plan.Delivered.Save(o.fingerprint); err != nil {
			r.log().Warn("delivered fix plan could not be recorded; the plan may be announced again", "err", err)
		}
	}
	r.saveSlackPlan(o)
	if o.prLastSeq > 0 && r.Plan.PullRequests != nil && r.Plan.PullRequests.Store != nil {
		if err := remediation.MarkPROperationsDelivered(r.Plan.PullRequests.Store, o.prLastSeq); err != nil {
			r.log().Warn("delivered pull request operations could not be recorded; they may be announced again", "err", err)
		}
	}
}

// saveSlackPlan records what the Slack fix plan message showed.
func (r Runner) saveSlackPlan(o planOutcome) {
	if r.Plan == nil || !o.slackChanged {
		return
	}
	if store, ok := r.Plan.Delivered.(SlackDeliveredStore); ok {
		if err := store.SaveSlack(o.slackFingerprint); err != nil {
			r.log().Warn("delivered Slack fix plan could not be recorded; the plan may be announced again", "err", err)
		}
	}
}

// markSlackPlanDelivered records the Slack fix plan message after a send that
// failed as a whole, when the plan itself was posted: the next cycle then does
// not post it again. The rest stays unrecorded and is sent again.
func (r Runner) markSlackPlanDelivered(o planOutcome, d *notify.PlanDelivery) {
	if o.info == nil || d == nil || !d.Posted || d.Failed {
		return
	}
	r.saveSlackPlan(o)
}

// KEVSource lists the CISA KEV catalog (implemented by intel.Source). It is
// optional: an IntelSource without it simply cannot say whether an unseen
// vulnerability is KEV-listed.
type KEVSource interface {
	KEVSet(ctx context.Context) (map[string]bool, error)
}

// planIntel looks up the triage verdict of a vulnerability: first in the
// report's package groups (the vulnerabilities this cycle's scans found, with
// their priorities), then in the KEV catalog, which is loaded once, on the
// first vulnerability the report does not know. That second step is what
// recognises a KEV-listed vulnerability a candidate introduces. With neither
// triage nor a KEV source it knows nothing.
func (r Runner) planIntel(ctx context.Context, report analyze.Report) remediation.IntelFunc {
	kevSource, _ := r.Intel.(KEVSource)
	if !report.Triage && kevSource == nil {
		return nil
	}
	known := map[string]remediation.VulnIntel{}
	if report.Triage {
		for _, section := range [][]analyze.ImageFindings{report.Actionable, report.Watch, report.WontFix, report.EOLPackages} {
			for _, img := range section {
				for _, g := range img.Packages {
					for _, v := range g.Vulns {
						in := known[v.ID]
						if p := remediation.Priority(v.Priority); p.Rank() > in.Priority.Rank() {
							in.Priority = p
						}
						in.KEV = in.KEV || v.KEV
						known[v.ID] = in
					}
				}
			}
		}
	}
	var (
		kev    map[string]bool
		loaded bool
	)
	return func(id string) (remediation.VulnIntel, bool) {
		if in, ok := known[id]; ok {
			return in, true
		}
		if kevSource == nil {
			return remediation.VulnIntel{}, false
		}
		if !loaded {
			loaded = true
			var err error
			if kev, err = kevSource.KEVSet(ctx); err != nil {
				r.log().Warn("fix plan: KEV catalog unavailable; vulnerabilities a candidate introduces are not checked against it", "err", err)
			}
		}
		if kev[id] {
			return remediation.VulnIntel{Priority: remediation.PriorityActNow, KEV: true}, true
		}
		return remediation.VulnIntel{}, false
	}
}

// entityRef identifies one running entity of a reference.
type entityRef struct {
	ref string
	key inventory.EntityKey
}

// planInputs pairs every scan with how to rescan it and which services run
// it, in the order the plan should consider them: by the report's priority
// buckets with the runtime usage order they already carry, then the rest.
// The planner keeps this order within one priority.
func planInputs(report analyze.Report, containers []inventory.Container, scans []scanner.ImageScan, targets []scanner.ScanTarget, conds scanner.ScanConditions) []remediation.ImageInput {
	return planInputsWith(report, containers, nil, scans, targets, conds)
}

// planInputsWith is planInputs with the management chains of the containers.
// A Kubernetes container is named by its workload key, the same for all the
// replicas of the workload, and carries what its Pod spec declares; Docker
// containers are named as before.
func planInputsWith(report analyze.Report, containers []inventory.Container, bindings []remediation.DeployBinding, scans []scanner.ImageScan, targets []scanner.ScanTarget, conds scanner.ScanConditions) []remediation.ImageInput {
	chainsOf := map[string][]remediation.OwnerChain{}
	for _, b := range bindings {
		chainsOf[b.Container] = b.Chains
	}
	services := map[entityRef][]remediation.ServiceRef{}
	declared := map[entityRef][]remediation.DeclaredInstance{}
	// byRef collects the declarations of every container of a running
	// reference, whatever entity it reports: a reference whose declaration
	// disagrees or is missing in any one of them is not compared in any.
	byRef := map[string][]remediation.DeclaredInstance{}
	management := map[entityRef][]remediation.WorkloadChains{}
	for _, c := range containers {
		if c.Image.Ref == "" {
			continue
		}
		key, _ := inventory.EntityKeyOf(c.Image)
		k := entityRef{c.Image.Ref, key}
		ref := remediation.ServiceRef{Container: c.Name}
		switch {
		case c.Workload.Kind == inventory.WorkloadCompose:
			ref.Project, ref.Service = c.Workload.Group, c.Workload.Name
		case c.Declared != nil:
			// A Kubernetes container. A Pod whose owner cannot be traced
			// still gets a key (container/<namespace>/<pod>/<container>),
			// which no mapping can name.
			if wk := state.WorkloadKey(c); wk != "" {
				ref = remediation.ServiceRef{Workload: wk}
			}
		}
		dup := false
		for _, have := range services[k] {
			dup = dup || have == ref
		}
		if !dup {
			services[k] = append(services[k], ref)
		}
		if ref.Workload == "" {
			continue
		}
		d := remediation.DeclaredInstance{Workload: ref.Workload, Ref: c.Declared.Ref, PullPolicy: c.Declared.PullPolicy}
		if !slices.Contains(declared[k], d) {
			declared[k] = append(declared[k], d)
		}
		if !slices.Contains(byRef[c.Image.Ref], d) {
			byRef[c.Image.Ref] = append(byRef[c.Image.Ref], d)
		}
		if chains, ok := chainsOf[c.Name]; ok && len(chains) > 0 {
			wc := remediation.NewWorkloadChains(ref.Workload, chains)
			if !slices.ContainsFunc(management[k], func(have remediation.WorkloadChains) bool { return have.Key() == wc.Key() }) {
				management[k] = append(management[k], wc)
			}
		}
	}

	for k := range declared {
		for _, p := range remediation.DeclaredProblems(byRef[k.ref], k.ref) {
			if !slices.Contains(declared[k], p) {
				declared[k] = append(declared[k], p)
			}
		}
	}

	rank := map[entityRef]int{}
	note := func(imgs []analyze.ImageFindings) {
		for _, img := range imgs {
			k := entityRef{img.Image, img.Subject.Key}
			if _, seen := rank[k]; !seen {
				rank[k] = len(rank)
			}
		}
	}
	pv := report.ByPriority()
	note(pv.ActNow)
	note(pv.Watch)
	note(pv.Low)
	note(report.Actionable)

	idx := make([]int, len(scans))
	for i := range idx {
		idx[i] = i
	}
	rankOf := func(i int) int {
		if n, ok := rank[entityRef{scans[i].Subject.Ref, scans[i].Subject.Key}]; ok {
			return n
		}
		return len(rank)
	}
	sort.SliceStable(idx, func(a, b int) bool { return rankOf(idx[a]) < rankOf(idx[b]) })

	inputs := make([]remediation.ImageInput, 0, len(scans))
	for _, i := range idx {
		s := scans[i]
		inputs = append(inputs, remediation.ImageInput{
			Scan:       s,
			Conditions: conds,
			Target:     targets[i],
			Services:   services[entityRef{s.Subject.Ref, s.Subject.Key}],
			Declared:   declared[entityRef{s.Subject.Ref, s.Subject.Key}],
			Management: management[entityRef{s.Subject.Ref, s.Subject.Key}],
		})
	}
	return inputs
}

// observedManagement returns the management chains of every Kubernetes
// container of the cycle's observation, by workload key, whether or not the
// plan has an item for it.
func observedManagement(containers []inventory.Container, bindings []remediation.DeployBinding) []remediation.WorkloadChains {
	chainsOf := map[string][]remediation.OwnerChain{}
	for _, b := range bindings {
		chainsOf[b.Container] = b.Chains
	}
	var out []remediation.WorkloadChains
	for _, c := range containers {
		if c.Declared == nil {
			continue
		}
		wk := state.WorkloadKey(c)
		chains := chainsOf[c.Name]
		if wk == "" || len(chains) == 0 {
			continue
		}
		wc := remediation.NewWorkloadChains(wk, chains)
		if !slices.ContainsFunc(out, func(have remediation.WorkloadChains) bool { return have.Key() == wc.Key() }) {
			out = append(out, wc)
		}
	}
	return out
}
