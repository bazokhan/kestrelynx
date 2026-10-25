// Package runner wires the pipeline together: list running images, scan each,
// triage, and notify. It owns the once-per-cycle orchestration and the
// in-process scheduler (docs/ARCHITECTURE.md §2, ADR-003).
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// ContainerLister enumerates running containers (implemented by docker.Client).
type ContainerLister interface {
	RunningContainers(ctx context.Context) ([]inventory.Container, error)
}

// ContainerObserver is a ContainerLister that can also report the management
// chains of the same containers from the same listing (implemented by
// kubernetes.Client). It is used only when the fix plan is on: the chains are
// shown in the plan, and reading them costs more LIST calls.
type ContainerObserver interface {
	Observe(ctx context.Context) ([]inventory.Container, []remediation.DeployBinding, error)
}

// ImageScanner scans one image target (implemented by scanner.Trivy).
type ImageScanner interface {
	Scan(ctx context.Context, target scanner.ScanTarget) scanner.ImageScan
}

// Inspector reads one container's current identity and exposure by ID
// (implemented by docker.Client.Inspect). Only ever consulted when Evidence
// is set (runtime.enabled) — it is what lets AttachRuntime confirm a Sensor
// evidence generation is still the generation actually running (analyze/
// runtime.go's matchGeneration) and judge its exposure.
type Inspector interface {
	Inspect(ctx context.Context, id string) (docker.InspectResult, error)
}

// Notifier delivers a message (implemented by notify.Notifier).
type Notifier interface {
	Send(ctx context.Context, m notify.Message) error
}

// StateStore persists scan state between cycles (implemented by state.FileStore).
type StateStore interface {
	Load() (state.State, error)
	Save(state.State) error
}

// IntelSource supplies exploitation intel for the triage layer (implemented by
// intel.Source). Discussions is only consulted for act-now CVEs and only when
// discussion links are enabled.
type IntelSource interface {
	Lookup(ctx context.Context, ids []string) (map[string]intel.Enrichment, intel.Freshness, error)
	Discussions(ctx context.Context, ids []string) map[string]intel.Discussion
}

// RuntimeRefresher loads the advisory data the image scanners use to check
// one language runtime of an image (implemented by nodecore.Refresher and
// pycore.Refresher).
type RuntimeRefresher interface {
	Refresh(ctx context.Context) error
}

// Runner holds the collaborators for one scan cycle.
type Runner struct {
	Lister          ContainerLister
	Scanner         ImageScanner
	Notifier        Notifier
	NotifyOnClean   bool
	Store           StateStore   // nil = full mode (re-send everything each cycle)
	FullReportDay   time.Weekday // diff mode: weekday of the full digest; NoFullReport disables
	Intel           IntelSource  // nil = triage off (Phase 1 severity-only output)
	ActNowEPSS      float64      // triage thresholds (config.Triage)
	WatchEPSS       float64
	DiscussionLinks bool // look up HN discussions for act-now CVEs
	// Environment identifies the runtime instance this Runner scans. It is
	// stamped onto every Report (RunOnce) and, via cmd/kestrelynx wiring,
	// shares its Name with the StateStore so state and notifications agree
	// on which environment they describe. The zero value is the unnamed
	// default environment.
	Environment inventory.Environment
	// Source is the ScanSource this Runner's ContainerLister observes
	// images from, stamped onto every ScanTarget scanAll builds. The zero
	// value is treated as scanner.SourceLocal (see source()) so existing
	// Docker callers that never set this field keep their exact prior
	// behavior; cmd/kestrelynx wiring sets it explicitly per adapter.
	Source scanner.ScanSource
	Now    func() time.Time
	Log    *slog.Logger

	// Evidence supplies the current runtime-usage snapshot from an optional
	// Sensor companion process. nil (the default) means runtime.enabled is
	// false: no evidence is ever read, Inspect is never called, and
	// analyze.AttachRuntime is never called either — Report.Runtime and
	// every PackageGroup.Runtime stay at their zero value, which is what
	// keeps a disabled deployment's notifications byte-identical.
	Evidence evidence.Provider
	// Inspector reads a container's current identity/exposure by ID. Only
	// consulted when Evidence is set; nil with Evidence set means no
	// container can be corroborated (every group judges
	// container_not_observed), which is a safe, inert degradation rather
	// than a panic.
	Inspector Inspector
	// BootTime returns the host's boot time, used to convert a Sensor
	// evidence generation's boot-relative InitProcess.Starttime into a
	// wall-clock instant comparable with Docker's own StartedAt (analyze.
	// GenerationInspect.BootTime). nil uses hostBootTime (reads
	// /proc/stat's "btime" line); only ever called when Evidence is set.
	BootTime func() (time.Time, error)
	// MuteUnfixableNotInUse enables runtime.mute_unfixable_not_in_use:
	// once true, analyze.ApplyMuting runs right after AttachRuntime every
	// cycle (only reached at all when Evidence is set), so a group's
	// Muted always reflects this cycle's own status/priority/runtime
	// verdict, never a value carried over from before.
	MuteUnfixableNotInUse bool
	// GenericWebhookConfigured mirrors config.NotifyConfig.GenericWebhookURL
	// != "", stamped onto every Report (RunOnce) the same way Environment is:
	// notify has no other way to know whether the generic webhook guidance
	// it shows in place of a hidden low-priority/muted row is actually
	// true for this deployment.
	GenericWebhookConfigured bool

	// RuntimeRefreshers load, once per cycle before any image is scanned and
	// in this order, the data the scanners use to check the language
	// runtimes (Node.js, CPython). A failure is logged and the cycle goes
	// on, with that runtime left unchecked. Empty (the default) means the
	// feature is off and the cycle is unchanged.
	RuntimeRefreshers []RuntimeRefresher

	// Plan enables the read-only fix plan. nil (the default) means the plan
	// is off: no database preparation, no comparison-mode scans, no registry
	// access, no plan or delivery records, and every scan, state change and
	// notification is exactly what it is without this field.
	Plan *PlanConfig
}

// NoFullReport disables the weekly full report in diff mode.
const NoFullReport time.Weekday = -1

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// source normalizes r.Source: the zero value (an unset field) is
// scanner.SourceLocal, so a Runner built without a Source behaves exactly
// as it did before this field existed.
func (r Runner) source() scanner.ScanSource {
	if r.Source == "" {
		return scanner.SourceLocal
	}
	return r.Source
}

// RunOnce executes a single scan cycle. A failure to list images aborts the
// cycle; a failure to scan an individual image is captured in the report (so
// one bad image never sinks the run) and surfaced to the user.
func (r Runner) RunOnce(ctx context.Context) error {
	log := r.log()
	containers, bindings, err := r.listContainers(ctx)
	if err != nil {
		return fmt.Errorf("list running containers: %w", err)
	}
	images := inventory.DistinctImages(containers)
	log.Info("scanning images", "count", len(images))

	for _, rf := range r.RuntimeRefreshers {
		if err := rf.Refresh(ctx); err != nil {
			log.Warn("language runtime advisory data unavailable; that runtime of images is not checked this cycle", "refresher", fmt.Sprintf("%T", rf), "err", err)
		}
	}

	// With the plan on, prepared databases put every scan of the cycle, and
	// the plan's candidate scans, on the same database content. Without them
	// the scans run as usual and the cycle has no plan.
	sc := r.Scanner
	var cyc planCycle
	if r.Plan != nil {
		if cyc = r.preparePlan(ctx); cyc.ok {
			sc = r.Plan.Scanner
		}
	}
	scans, targets := r.scanImages(ctx, sc, images)
	if cyc.ok {
		cyc = r.verifyScans(ctx, cyc)
	}

	report := analyze.Build(scans, containers, r.triage(ctx, scans), r.now())
	report.Environment = r.Environment
	report.GenericWebhookConfigured = r.GenericWebhookConfigured
	if r.Evidence != nil {
		r.attachRuntime(ctx, &report, containers)
		if r.MuteUnfixableNotInUse {
			analyze.ApplyMuting(&report, r.now())
		}
	}
	var plan planOutcome
	if r.Plan != nil {
		plan = r.buildPlan(ctx, cyc, report, containers, bindings, scans, targets)
	}
	if r.Store == nil {
		return r.sendFull(ctx, report, plan)
	}
	return r.sendDiff(ctx, report, plan)
}

// listContainers lists the running containers. With the fix plan on and an
// adapter that can report them, the management chains of the containers come
// from the same listing; without either, only the containers are listed, as
// they always were.
func (r Runner) listContainers(ctx context.Context) ([]inventory.Container, []remediation.DeployBinding, error) {
	if o, ok := r.Lister.(ContainerObserver); ok && r.Plan != nil {
		return o.Observe(ctx)
	}
	containers, err := r.Lister.RunningContainers(ctx)
	return containers, nil, err
}

// scanAll scans every running image, de-duplicating on the resolved
// EntityKey: the same entity running under several references is scanned
// once and the result is replicated to each alias reference. A cached result
// is only stored, and only reused, when it came back Pinned — an unpinned
// (unconfirmed or failed) result describes a scan that never actually
// confirmed it saw the requested entity, so nothing about it is safe to
// share with a sibling reference; each alias re-scans until one succeeds.
// Images whose identity did not resolve are scanned individually by
// reference and never join the EntityKey de-duplication (they already can't
// collide there, since inventory.DistinctImages itself de-duplicates on
// (Ref, EntityKey)).
func (r Runner) scanAll(ctx context.Context, images []inventory.RunningImage) []scanner.ImageScan {
	scans, _ := r.scanImages(ctx, r.Scanner, images)
	return scans
}

// scanImages is scanAll with the scanner chosen by the caller. It also
// returns, per scan, the target that scans the same image again.
func (r Runner) scanImages(ctx context.Context, sc ImageScanner, images []inventory.RunningImage) ([]scanner.ImageScan, []scanner.ScanTarget) {
	log := r.log()
	source := r.source()
	scans := make([]scanner.ImageScan, 0, len(images))
	targets := make([]scanner.ScanTarget, 0, len(images))
	byKey := map[inventory.EntityKey]scanner.ImageScan{}

	for _, img := range images {
		key, resolved := inventory.EntityKeyOf(img)
		subject := inventory.ImageSubject{Ref: img.Ref, Key: key, Resolved: resolved}
		target := scanner.ScanTarget{Subject: subject, Registry: img.Registry, Source: source}

		if !resolved {
			result := sc.Scan(ctx, target)
			if result.Err != nil {
				log.Warn("image scan failed", "image", img.Ref, "resolved", false, "err", result.Err)
			}
			log.Info("scanned image", "ref", img.Ref, "resolved", false)
			scans = append(scans, result)
			targets = append(targets, target)
			continue
		}

		result, ok := byKey[key]
		if !ok || !result.Pinned {
			result = sc.Scan(ctx, target)
			if result.Err != nil {
				log.Warn("image scan failed", "image", img.Ref, "content_id", key.Digest.String(), "resolved", true, "err", result.Err)
			}
			if result.Pinned {
				byKey[key] = result
			}
		}
		log.Info("scanned image", "ref", img.Ref, "content_id", key.Digest.String(), "resolved", true)
		scans = append(scans, retarget(result, img.Ref))
		targets = append(targets, target)
	}
	return scans, targets
}

// retarget deep-copies scan and relabels it for ref. A de-duplicated scan
// result is shared across every alias reference running the same entity, so
// each alias must get its own Findings slice — mutating one ref's copy must
// never reach another's.
func retarget(scan scanner.ImageScan, ref string) scanner.ImageScan {
	out := scan
	out.Image = ref
	out.Subject.Ref = ref
	if scan.Findings != nil {
		out.Findings = make([]scanner.Finding, len(scan.Findings))
		for i, f := range scan.Findings {
			f.Image = ref
			out.Findings[i] = f
		}
	}
	if scan.RegistryDigests != nil {
		out.RegistryDigests = append([]string(nil), scan.RegistryDigests...)
	}
	return out
}

// triage looks up exploitation intel for every vulnerability the scans found
// and assembles the triage input for analyze.Build. Intel failures never fail
// the cycle: the triage degrades (and says so in the notification) while the
// scan and delivery proceed (docs/TRIAGE_SPEC.md §3).
func (r Runner) triage(ctx context.Context, scans []scanner.ImageScan) analyze.Triage {
	if r.Intel == nil {
		return analyze.Triage{}
	}
	log := r.log()

	seen := map[string]bool{}
	ids := []string{}
	for _, s := range scans {
		for _, f := range s.Findings {
			if !seen[f.VulnID] {
				seen[f.VulnID] = true
				ids = append(ids, f.VulnID)
			}
		}
	}

	enrich, fresh, err := r.Intel.Lookup(ctx, ids)
	if err != nil {
		log.Warn("intel lookup incomplete", "err", err)
	}
	if fresh.Degraded() {
		log.Warn("vulnerability intel unavailable; falling back to severity-only triage")
	}

	converted := make(map[string]analyze.Enrichment, len(enrich))
	for id, e := range enrich {
		converted[id] = analyze.Enrichment(e)
	}
	tr := analyze.Triage{
		Enabled:    true,
		ActNowEPSS: r.ActNowEPSS,
		WatchEPSS:  r.WatchEPSS,
		Enrich:     converted,
		Intel:      analyze.IntelStatus{KEVOK: fresh.KEVOK, EPSSOK: fresh.EPSSOK, StaleDays: fresh.StaleDays},
	}
	tr.Refs = r.discussionRefs(ctx, tr)
	return tr
}

// discussionRefs collects HN discussion links for the CVEs whose intel already
// signals act_now. Only those IDs are ever sent as search queries (the
// documented exception to "nothing leaves the host" — a handful of world-famous
// CVEs, and only with DiscussionLinks on). Degraded intel means no act-now
// signals to trust, so nothing is queried.
func (r Runner) discussionRefs(ctx context.Context, tr analyze.Triage) map[string][]analyze.Ref {
	if !r.DiscussionLinks || tr.Intel.Degraded() {
		return nil
	}
	var ids []string
	for id, e := range tr.Enrich {
		if tr.SignalsActNow(e) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids) // deterministic query order

	refs := map[string][]analyze.Ref{}
	for id, d := range r.Intel.Discussions(ctx, ids) {
		refs[id] = []analyze.Ref{{
			Kind:  "discussion",
			Label: fmt.Sprintf("HN (%d pts)", d.Points),
			URL:   d.URL,
		}}
	}
	return refs
}

// attachRuntime reads this cycle's runtime evidence and inspects every
// running container once (one GET /containers/{id}/json per scanned
// container), then folds both into report via analyze.AttachRuntime.
// A failure to read evidence or to inspect a specific container never fails
// the cycle — it degrades to the corresponding "unavailable" reason
// (RuntimeInfo.LoadFailed/NotReporting, or a container simply missing from
// GenerationInspect.ByContainer, which analyze/runtime.go's matchGeneration
// treats as container_not_observed) and the scan/notify pipeline continues
// exactly as it does for any other partial failure this Runner already
// tolerates.
func (r Runner) attachRuntime(ctx context.Context, report *analyze.Report, containers []inventory.Container) {
	log := r.log()

	snap, err := r.Evidence.Load(ctx)
	rt := analyze.RuntimeInfo{Sensor: snap.Sensor}
	if err != nil {
		rt.LoadFailed = true
		rt.NotReporting = errors.Is(err, evidence.ErrNotReporting)
		log.Warn("runtime evidence unavailable", "err", err)
	}

	insp := analyze.GenerationInspect{ByContainer: map[string]docker.InspectResult{}}
	if bt, btErr := r.bootTime(); btErr == nil {
		insp.BootTime = bt
	} else {
		log.Warn("runtime: host boot time unavailable; evidence generations cannot be matched", "err", btErr)
	}
	if r.Inspector != nil {
		seen := map[string]bool{}
		for _, c := range containers {
			if c.ID == "" || seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			result, iErr := r.Inspector.Inspect(ctx, c.ID)
			if iErr != nil {
				log.Warn("runtime: inspect container failed", "id", c.ID, "err", iErr)
				continue
			}
			insp.ByContainer[c.ID] = result
		}
	}

	analyze.AttachRuntime(report, rt, snap, insp, r.now())
}

// bootTime resolves r.BootTime, defaulting to hostBootTime.
func (r Runner) bootTime() (time.Time, error) {
	if r.BootTime != nil {
		return r.BootTime()
	}
	return hostBootTime()
}

// sendFull is the stateless full mode: re-send everything whenever there is
// anything to say.
func (r Runner) sendFull(ctx context.Context, report analyze.Report, plan planOutcome) error {
	log := r.log()
	// The vulnerability message and the fix plan message are due on their own
	// terms; the generic webhook gets both together whenever either is sent.
	reportDue := report.HasIssues() || r.NotifyOnClean || len(report.RuntimeUnchecked) > 0
	m := plan.message(notify.Message{Report: report, SkipReport: !reportDue})
	if !reportDue && !plan.mustSend() && !m.Plan.SlackDue() {
		log.Info("no issues found; skipping notification")
		return nil
	}
	m.PlanDelivery = &notify.PlanDelivery{}
	if err := r.Notifier.Send(ctx, m); err != nil {
		r.markSlackPlanDelivered(plan, m.PlanDelivery)
		return fmt.Errorf("send notification: %w", err)
	}
	r.markDelivered(plan)
	log.Info("notification sent",
		"affected", report.AffectedImageCount(),
		"eosl", len(report.EOSLImages),
		"scan_errors", len(report.ScanErrors))
	return nil
}

// sendDiff is diff mode: notify what changed since the previous scan, send a
// one-line heartbeat while findings stay open (so silence always means "all
// clear", never "the scanner died"), and stay quiet on clean-and-unchanged
// unless NotifyOnClean. State is saved only after a successful (or skipped)
// delivery, so a failed send is re-reported as new next cycle instead of lost.
func (r Runner) sendDiff(ctx context.Context, report analyze.Report, plan planOutcome) error {
	log := r.log()
	prev, err := r.Store.Load()
	if err != nil {
		// Corrupt state: fall back to re-reporting everything as new rather
		// than failing the cycle or silently dropping history.
		log.Warn("load state failed; treating all findings as new", "err", err)
	}
	diff, next := state.Compute(prev, report)
	// The last-full-report ref carries over verbatim unless this cycle posts a
	// fresh thread: a failed (or skipped) post must keep the old link alive.
	next.LastFullReport = prev.LastFullReport

	fullToday := r.FullReportDay != NoFullReport && r.now().Weekday() == r.FullReportDay
	// holding is true when a reference this cycle failed to pin still has a
	// finding on record from before: state's conservative carry-over means
	// the cycle isn't really silent even if this report alone looks clean,
	// so a quiet cycle must not skip the notification just because nothing
	// newly changed.
	holding := holdingUnconfirmed(prev, report)
	// The vulnerability message and the fix plan message are due on their own
	// terms; the generic webhook gets both together whenever either is sent.
	// An unchecked Node.js runtime also makes the cycle due: its findings
	// are held, so a quiet report would otherwise hide that they were not
	// re-checked.
	reportDue := report.HasIssues() || diff.HasChanges() || r.NotifyOnClean || holding || len(report.RuntimeUnchecked) > 0

	res := &notify.ThreadResult{}
	m := plan.message(notify.Message{
		Report:     report,
		Diff:       &diff,
		FullReport: fullToday,
		Holding:    holding,
		SkipReport: !reportDue,
		// The thread mirrors the channel: post the full state when something
		// changed (or on the weekly digest day); on quiet days the summary
		// links to the previous thread instead.
		Thread:       diff.HasChanges() || fullToday,
		FirstSeen:    next.FirstSeen,
		EOLFirstSeen: next.EOLFirstSeen,
		LastReport:   prev.LastFullReport,
		Result:       res,
	})
	if !reportDue && !plan.mustSend() && !m.Plan.SlackDue() {
		log.Info("no issues and no changes; skipping notification")
		return r.saveState(next)
	}
	m.PlanDelivery = &notify.PlanDelivery{}
	if err := r.Notifier.Send(ctx, m); err != nil {
		r.markSlackPlanDelivered(plan, m.PlanDelivery)
		return fmt.Errorf("send notification: %w", err)
	}
	r.markDelivered(plan)
	if res.Ref.TS != "" {
		ref := res.Ref
		next.LastFullReport = &ref
	}
	attrs := []any{
		"new", len(diff.Changes),
		"resolved", len(diff.Resolved),
		"open_critical", diff.OpenCritical,
		"open_high", diff.OpenHigh,
	}
	// The levels below HIGH appear only when scan.severity selects them, so
	// the line is unchanged for the default configuration.
	for _, x := range []struct {
		key string
		n   int
	}{{"open_medium", diff.OpenSevMedium}, {"open_low", diff.OpenSevLow}, {"open_unknown", diff.OpenSevUnknown}} {
		if x.n > 0 {
			attrs = append(attrs, x.key, x.n)
		}
	}
	attrs = append(attrs,
		"full_report", fullToday,
		"thread_report", res.Ref.TS != "",
		"scan_errors", len(report.ScanErrors))
	log.Info("notification sent", attrs...)
	return r.saveState(next)
}

// holdingUnconfirmed reports whether any reference this cycle could not pin
// (report.UnconfirmedRefs) still has a finding on record from prev: state's
// conservative carry-over (analyze's unconfirmed accounting feeding
// PartialFailure) keeps such findings rather than marking them resolved, so
// a notification must not stay quiet — or claim "all clear" — just because
// this cycle's own report looks empty for that reference.
func holdingUnconfirmed(prev state.State, report analyze.Report) bool {
	for _, ref := range report.UnconfirmedRefs {
		if prev.HasFindingsFor(ref) {
			return true
		}
	}
	return false
}

// saveState persists the next state. Failure is surfaced (some changes may be
// re-announced next cycle) but has already been preceded by a successful send.
func (r Runner) saveState(next state.State) error {
	if err := r.Store.Save(next); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}

// Loop runs RunOnce on the schedule until ctx is cancelled. A cycle error is
// logged but does not stop the loop, so a transient failure (e.g. Slack down)
// doesn't kill the agent.
func (r Runner) Loop(ctx context.Context, sched config.ScheduleConfig) error {
	log := r.log()
	if sched.RunOnStart {
		if err := r.RunOnce(ctx); err != nil {
			log.Error("initial scan cycle failed", "err", err)
		}
	}
	for {
		wait := untilNext(sched, r.now())
		log.Info("next scan scheduled", "in", wait.Round(time.Second).String())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			if err := r.RunOnce(ctx); err != nil {
				log.Error("scan cycle failed", "err", err)
			}
		}
	}
}

// untilNext computes the wait until the next run: to the daily wall-clock time
// if configured, otherwise a fixed 24h interval.
func untilNext(sched config.ScheduleConfig, now time.Time) time.Duration {
	if hour, min, ok := sched.DailyTime(); ok {
		return nextDaily(now, hour, min).Sub(now)
	}
	return 24 * time.Hour
}

// nextDaily returns the next occurrence of hour:min strictly after now.
func nextDaily(now time.Time, hour, min int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, min, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}
