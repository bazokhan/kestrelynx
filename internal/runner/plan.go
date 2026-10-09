package runner

import (
	"context"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
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
	// read the sources of the configured dependency mappings; nil when no
	// such mapping exists.
	NewGitHub func() remediation.GitHubReader
	// Dependencies are the dependency mappings whose source files the plan
	// reads through the GitHub client.
	Dependencies []remediation.DependencyMapping
	Plans        PlanStore
	Delivered    DeliveredStore
}

// planCycle is the plan state of one cycle.
type planCycle struct {
	prepared scanner.ScanConditions
	ok       bool // the databases were prepared; scans run in comparison mode
	// scanConds are the conditions the cycle's scans carry: the prepared
	// ones if the databases were verified unchanged after the scans, none
	// otherwise.
	scanConds scanner.ScanConditions
}

// planOutcome is what the plan contributes to the cycle's notification. The
// zero value is a cycle without a plan.
type planOutcome struct {
	info *notify.PlanInfo // nil when the plan is not enabled
	// fingerprint and changed are set only when a plan was produced. changed
	// means its content differs from the last delivered plan.
	fingerprint string
	changed     bool
}

// message copies the plan into m.
func (o planOutcome) message(m notify.Message) notify.Message {
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
	return planCycle{prepared: conds, ok: true}
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
	return out
}

// buildPlan runs the planner over this cycle's scans and stores the result.
// Nothing here fails the cycle: a planner or store failure shows up in the
// outcome only.
func (r Runner) buildPlan(ctx context.Context, cyc planCycle, report analyze.Report, containers []inventory.Container, scans []scanner.ImageScan, targets []scanner.ScanTarget) planOutcome {
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
	budget := registry.NewBudget(pc.MaxRegistryRequests)
	var gh remediation.GitHubReader
	if pc.NewGitHub != nil && len(pc.Dependencies) > 0 {
		// One client per cycle: its request budget and file byte total are
		// per-cycle counters. A nil client leaves the language part off.
		if c := pc.NewGitHub(); c != nil {
			gh = c
		}
	}
	planner, err := remediation.NewPlanner(remediation.Config{
		Registry:     pc.NewRegistry(budget),
		Scanner:      pc.Scanner,
		Prepared:     cyc.prepared,
		Limits:       pc.Limits,
		Budget:       budget,
		Intel:        r.planIntel(ctx, report),
		GitHub:       gh,
		Dependencies: pc.Dependencies,
		Now:          r.now,
	})
	if err != nil {
		log.Warn("fix plan unavailable: planner could not be built", "err", err)
		return r.planUnavailable(notify.PlanNotBuilt)
	}

	plan := planner.Plan(ctx, planInputs(report, containers, scans, targets, cyc.scanConds))
	log.Info("fix plan built",
		"items", len(plan.Items),
		"pull_again", plan.Count(remediation.CategoryPullAgain),
		"update_candidate", plan.Count(remediation.CategoryPRCandidate),
		"dependency_units", len(plan.LanguageItems),
		"dependency_update_candidates", plan.CountLanguage(remediation.CategoryDependencyUpdateCandidate),
		"candidate_scans", plan.Usage.CandidateScans,
		"baseline_rescans", plan.Usage.BaselineRescans,
		"registry_requests", plan.Usage.RegistryRequests)

	info := &notify.PlanInfo{Plan: &plan}
	if pc.Plans != nil {
		if err := pc.Plans.Save(plan); err != nil {
			log.Warn("fix plan could not be saved", "err", err)
			info.NotSaved = true
		}
	}

	return r.finishPlan(info, remediation.Fingerprint(plan))
}

// markDelivered records the plan's fingerprint after a notification carrying
// it was sent. A failure only means the plan may be announced again.
func (r Runner) markDelivered(o planOutcome) {
	if o.info == nil || !o.changed || r.Plan.Delivered == nil {
		return
	}
	if err := r.Plan.Delivered.Save(o.fingerprint); err != nil {
		r.log().Warn("delivered fix plan could not be recorded; the plan may be announced again", "err", err)
	}
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
	services := map[entityRef][]remediation.ServiceRef{}
	for _, c := range containers {
		if c.Image.Ref == "" {
			continue
		}
		key, _ := inventory.EntityKeyOf(c.Image)
		k := entityRef{c.Image.Ref, key}
		ref := remediation.ServiceRef{Container: c.Name}
		if c.Workload.Kind == inventory.WorkloadCompose {
			ref.Project, ref.Service = c.Workload.Group, c.Workload.Name
		}
		dup := false
		for _, have := range services[k] {
			dup = dup || have == ref
		}
		if !dup {
			services[k] = append(services[k], ref)
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
		})
	}
	return inputs
}
