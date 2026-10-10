package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Registry is the part of the registry client the planner uses.
type Registry interface {
	// ListTagsUpTo follows at most maxPages pages. Even on an error the
	// returned list's Pages says how many page requests were made.
	ListTagsUpTo(ctx context.Context, repo string, maxPages int) (registry.TagList, error)
	Resolve(ctx context.Context, repo, tagOrDigest string, platform inventory.Platform) (registry.Resolution, error)
}

// Scanner scans images and can tell whether the databases of the cycle's
// prepared conditions are still intact. The planner expects Scan to run in
// comparison mode (databases fixed, no updates, a clean environment).
type Scanner interface {
	Scan(ctx context.Context, target scanner.ScanTarget) scanner.ImageScan
	VerifyDB(ctx context.Context, base scanner.ScanConditions) (bool, error)
}

var (
	_ Registry = (*registry.Client)(nil)
	_ Scanner  = scanner.Trivy{}
)

// ImageInput is one scanned running image of the cycle.
type ImageInput struct {
	// Scan is the cycle's scan of the running image. Its findings are the
	// source of the targets and its package list the baseline's.
	Scan scanner.ImageScan
	// Conditions are the conditions Scan was taken under; zero when they are
	// not known (a scan that did not run in comparison mode).
	Conditions scanner.ScanConditions
	// Target is how to scan the same image again, used when the baseline has
	// to be rescanned under the prepared conditions.
	Target   scanner.ScanTarget
	Services []ServiceRef
}

// Config holds what a Planner needs.
type Config struct {
	Registry Registry
	Scanner  Scanner
	// Prepared are the cycle's scan conditions, from the database
	// preparation. Candidate scans are taken under them, and a baseline taken
	// under anything else is rescanned.
	Prepared scanner.ScanConditions
	Limits   Limits
	// Budget is the registry.Budget the Registry was built with; the planner
	// only reads it, to report usage. Nil is allowed.
	Budget *registry.Budget
	Intel  IntelFunc
	// GitHub reads the dependency files of the Dependencies mappings; the
	// language-package part is skipped when it is nil.
	GitHub GitHubReader
	// Dependencies are the configured dependency mappings.
	Dependencies []DependencyMapping
	// Dockerfiles are the configured Dockerfile mappings and Composes the
	// Compose mappings whose services' build sections can name a Dockerfile;
	// the Dockerfile part is skipped when GitHub is nil or both are empty.
	Dockerfiles []DockerfileMapping
	Composes    []ComposeMapping
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Planner builds read-only remediation plans.
//
// Scans run strictly one after another in one process, and comparison mode
// never updates the databases, so the check after one scan also covers the
// start of the next, and the first scan follows the database preparation that
// produced the prepared conditions. Running scans concurrently would need a
// check before each scan as well.
type Planner struct {
	cfg Config
}

// NewPlanner validates cfg and returns a Planner.
func NewPlanner(cfg Config) (*Planner, error) {
	if cfg.Registry == nil || cfg.Scanner == nil {
		return nil, errors.New("remediation: planner needs a registry and a scanner")
	}
	if cfg.Limits.MaxCandidateScans < 0 || cfg.Limits.MaxBaselineRescans < 0 || cfg.Limits.MaxTagPages < 0 {
		return nil, errors.New("remediation: limits must not be negative")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Planner{cfg: cfg}, nil
}

type tagEntry struct {
	list      registry.TagList
	err       error
	allowance int // the page allowance the listing was fetched with
}

type resolveEntry struct {
	res registry.Resolution
	err error
}

// scanned is a scan record with the ID of its entry in Plan.Scans.
type scanned struct {
	rec ScanRecord
	id  string
}

// halt records a condition that stops all further registry work in a pass.
type halt struct {
	reason Reason
	detail string
}

type run struct {
	p    *Planner
	ctx  context.Context
	plan Plan

	tags     map[string]tagEntry
	resolved map[string]resolveEntry
	cands    map[string]scanned
	bases    map[string]scanned
	halted   *halt
	// srcHalt stops all further GitHub reads of the language-package part and
	// the Dockerfile part.
	srcHalt *halt

	// The Dockerfile part's per-cycle caches: commits by branch, files by
	// commit and path, and the scans of base images by role and content.
	dfSHA   map[string]dfShaEntry
	dfFiles map[string]*dfFileEntry
	dfScans map[string]scanned
}

// Plan builds the plan for the cycle's images. Images without a target
// (no fixed finding) get no item. Images are handled in the order of their
// most urgent target (act_now, watch, then the rest); within one priority the
// order of inputs is kept, so callers pass images in the order they prefer
// (for example those in use at runtime first). Work past a limit is recorded
// as deferred, never dropped or counted as "no candidate".
func (p *Planner) Plan(ctx context.Context, inputs []ImageInput) Plan {
	r := &run{
		p:        p,
		ctx:      ctx,
		tags:     map[string]tagEntry{},
		resolved: map[string]resolveEntry{},
		cands:    map[string]scanned{},
		bases:    map[string]scanned{},
		plan: Plan{
			Version:     PlanVersion,
			GeneratedAt: p.cfg.Now(),
			Conditions:  p.cfg.Prepared,
			Limits:      p.cfg.Limits,
			Items:       []Item{},
		},
	}
	startUsed := p.cfg.Budget.Used()

	type entry struct {
		in      ImageInput
		targets []Target
		ref     string
	}
	var entries []entry
	for _, in := range inputs {
		ts := SelectTargets(in.Scan.Findings, p.cfg.Intel)
		if len(ts) == 0 {
			continue
		}
		ref := in.Scan.Subject.Ref
		if ref == "" {
			ref = in.Scan.Image
		}
		entries = append(entries, entry{in, ts, ref})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		return maxTargetPriority(a.targets).Rank() > maxTargetPriority(b.targets).Rank()
	})

	for _, e := range entries {
		it := baseItem(e.in, e.ref, e.targets)
		if err := ctx.Err(); err != nil {
			defer0(&it, ReasonCycleDeadline, err.Error())
		} else {
			r.process(e.in, &it)
		}
		r.plan.Items = append(r.plan.Items, it)
	}
	r.languagePart(inputs)
	r.dockerfilePart(inputs)
	r.plan.Usage.RegistryRequests = p.cfg.Budget.Used() - startUsed
	return r.plan
}

func defer0(it *Item, reason Reason, detail string) {
	it.Category, it.Reason, it.Detail = CategoryDeferred, reason, detail
}

func set(it *Item, c Category, reason Reason, detail string) {
	it.Category, it.Reason, it.Detail = c, reason, detail
}

func baseItem(in ImageInput, ref string, targets []Target) Item {
	s := in.Scan
	it := Item{
		Key:      ref + "|" + entityString(s.Subject.Key),
		Services: in.Services,
		Priority: maxTargetPriority(targets),
		Targets:  targets,
		Current:  ImageState{Ref: ref, Entity: entityString(s.Subject.Key)},
	}
	if s.Subject.Key.Digest.Kind == inventory.DigestConfig {
		it.Current.ConfigDigest = s.Subject.Key.Digest.String()
		// Docker's image ID is typed as a config digest, but with the
		// containerd image store it is the index digest; nothing here
		// confirms which, so the plan says so.
		it.Current.DigestKindUnverified = s.Source == scanner.SourceLocal
	}
	if s.Platform.Known() {
		it.Current.Platform = s.Platform.OS + "/" + s.Platform.Architecture
	}
	return it
}

// baselineReady checks the scan the plan starts from before any request is
// spent on it.
func baselineReady(s scanner.ImageScan) (Reason, string, bool) {
	switch {
	case s.Err != nil:
		return ReasonScanFailed, "baseline scan failed: " + s.Err.Error(), false
	case !s.Subject.Resolved || !s.Pinned:
		return ReasonEntityUnverified, "baseline scan did not confirm the running image", false
	case !s.Platform.Known():
		return ReasonPlatformUnknown, "the platform of the baseline scan is not known", false
	case s.Platform.Variant != "":
		return ReasonVariantUnsupported, "the baseline platform has a variant: " + s.Platform.Variant, false
	}
	return "", "", true
}

// sameContent reports whether the running entity is the resolved candidate.
// The running digest is treated as a digest of unknown kind: Docker reports
// the image config digest with the classic image store but the multi-platform
// index digest with the containerd store, so the candidate is the same
// content when the digest equals its config digest, its platform manifest
// digest or its top-level (index) digest. A digest that differs from all
// three is not evidence of a difference by itself; the caller compares the
// scans. matched names which of the candidate's digests was equal. known is
// false when the entity has no digest to compare.
func sameContent(key inventory.EntityKey, res registry.Resolution) (same, known bool, matched string) {
	if !key.Digest.Valid() {
		return false, false, ""
	}
	d := key.Digest.String()
	switch d {
	case "":
		return false, false, ""
	case res.ConfigDigest:
		return true, true, "config"
	case res.ManifestDigest:
		return true, true, "manifest"
	case res.TopDigest:
		return true, true, "index"
	}
	return false, true, ""
}

func (r *run) process(in ImageInput, it *Item) {
	ref := ParseImageRef(it.Current.Ref)
	it.Kind = ref.Kind
	it.Current.Tag = ref.Tag
	if ref.Kind == TagExcluded {
		set(it, CategoryExcluded, Reason(ref.Exclude), "reference is not eligible for update lookup: "+string(ref.Exclude))
		return
	}
	if reason, detail, ok := baselineReady(in.Scan); !ok {
		cat := CategoryNotComparable
		if reason == ReasonScanFailed {
			cat = CategoryFailed
		}
		set(it, cat, reason, detail)
		return
	}
	platform := inventory.Platform{OS: in.Scan.Platform.OS, Architecture: in.Scan.Platform.Architecture}

	candTag := ref.Tag
	if ref.Kind == TagPinned {
		if !r.pinnedCandidate(ref, it, &candTag) {
			return
		}
	}
	res, ok := r.resolve(ref.Repository, candTag, platform, it)
	if !ok {
		return
	}
	cand := &ImageState{
		Ref:            ref.Repository + ":" + candTag,
		Tag:            candTag,
		ConfigDigest:   res.ConfigDigest,
		ManifestDigest: res.ManifestDigest,
		TopDigest:      res.TopDigest,
		Platform:       platform.OS + "/" + platform.Architecture,
	}
	same, known, matched := sameContent(in.Scan.Subject.Key, res)
	if !known {
		set(it, CategoryNotComparable, ReasonEntityUnverified, "the running entity cannot be compared with registry content")
		return
	}
	if same {
		set(it, CategoryNoCandidate, ReasonSameContent, "the candidate resolves to the content already running (the running digest equals the candidate's "+matched+" digest)")
		return
	}
	it.Candidate = cand
	r.compare(in, ref, platform, res, it)
}

// pinnedCandidate lists the tags and selects the newest patch. It returns
// false after recording the item's outcome when there is no candidate to
// continue with.
func (r *run) pinnedCandidate(ref ImageRef, it *Item, candTag *string) bool {
	key, ok := inventory.RepositoryKey(ref.Repository)
	if !ok {
		set(it, CategoryExcluded, Reason(ExcludeUnparsable), "repository cannot be normalized")
		return false
	}
	e, cached := r.tags[key]
	if !cached {
		if r.halted != nil {
			defer0(it, r.halted.reason, r.halted.detail)
			return false
		}
		allowance := r.p.cfg.Limits.MaxTagPages
		if allowance <= 0 {
			defer0(it, ReasonTagPageLimit, fmt.Sprintf("tag page limit of %d reached", r.p.cfg.Limits.MaxTagPages))
			return false
		}
		list, err := r.p.cfg.Registry.ListTagsUpTo(r.ctx, ref.Repository, allowance)
		e = tagEntry{list: list, err: err, allowance: allowance}
		r.tags[key] = e
		r.plan.Usage.TagPages += list.Pages
	}
	if e.err != nil {
		r.registryFailure(it, e.err)
		return false
	}
	sel := SelectPinned(ref.Version, e.list)
	switch sel.Outcome {
	case SelectionIncomplete:
		reason := ReasonTagListIncomplete
		if e.list.Pages >= e.allowance {
			reason = ReasonTagPageLimit // stopped by the repository's page allowance
		}
		defer0(it, reason, fmt.Sprintf("tag listing stopped after %d pages; newer patches cannot be ruled out", e.list.Pages))
		return false
	case SelectionNone:
		set(it, CategoryNoCandidate, ReasonNoNewerTag, "the complete tag listing has no newer patch of this series")
		return false
	}
	*candTag = sel.Tag
	return true
}

// resolve resolves a candidate tag to the platform's manifest and config,
// sharing the result between images. ok is false after the item's outcome
// has been recorded.
func (r *run) resolve(repo, tag string, platform inventory.Platform, it *Item) (registry.Resolution, bool) {
	rk, _ := inventory.RepositoryKey(repo)
	key := rk + ":" + tag + "|" + platform.OS + "/" + platform.Architecture
	e, cached := r.resolved[key]
	if !cached {
		if r.halted != nil {
			defer0(it, r.halted.reason, r.halted.detail)
			return registry.Resolution{}, false
		}
		res, err := r.p.cfg.Registry.Resolve(r.ctx, repo, tag, platform)
		e = resolveEntry{res: res, err: err}
		r.resolved[key] = e
	}
	if e.err != nil {
		r.registryFailure(it, e.err)
		return registry.Resolution{}, false
	}
	return e.res, true
}

// registryFailure maps a registry error to a plan outcome. Rate limiting,
// an exhausted budget and a dead context stop further registry work in the
// pass.
func (r *run) registryFailure(it *Item, err error) {
	var variant *registry.VariantError
	var limited *registry.RateLimitedError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		r.halted = &halt{ReasonCycleDeadline, err.Error()}
		defer0(it, r.halted.reason, r.halted.detail)
	case errors.Is(err, registry.ErrBudgetExhausted):
		r.halted = &halt{ReasonRegistryBudget, "registry request budget exhausted"}
		defer0(it, r.halted.reason, r.halted.detail)
	case errors.As(err, &limited):
		detail := err.Error()
		r.halted = &halt{ReasonRateLimited, detail}
		defer0(it, r.halted.reason, r.halted.detail)
	case errors.As(err, &variant):
		set(it, CategoryNotComparable, ReasonVariantUnsupported, err.Error())
	case errors.Is(err, registry.ErrAuthRequired):
		set(it, CategoryNotComparable, ReasonAuthRequired, err.Error())
	case errors.Is(err, registry.ErrPlatformNotFound):
		set(it, CategoryNotComparable, ReasonPlatformNotFound, err.Error())
	case errors.Is(err, registry.ErrPlatformAmbiguous):
		set(it, CategoryNotComparable, ReasonPlatformAmbiguous, err.Error())
	case errors.Is(err, registry.ErrPlatformMismatch):
		set(it, CategoryNotComparable, ReasonPlatformMismatch, err.Error())
	default:
		set(it, CategoryFailed, ReasonRegistryError, err.Error())
	}
}

// compare scans the baseline (when needed) and the candidate under the
// prepared conditions, compares them and records the decision.
func (r *run) compare(in ImageInput, ref ImageRef, platform inventory.Platform, res registry.Resolution, it *Item) {
	prep := r.p.cfg.Prepared
	if !prep.Known() {
		set(it, CategoryNotComparable, ReasonConditionsUnknown, "the cycle has no prepared scan conditions")
		return
	}
	regDigest, ok := inventory.ParseDigest(inventory.DigestRegistry, res.ManifestDigest)
	if !ok {
		set(it, CategoryFailed, ReasonRegistryError, "the registry resolution has no usable manifest digest")
		return
	}
	repoKey, _ := inventory.RepositoryKey(ref.Repository)
	candKey := repoKey + "|" + entityString(inventory.EntityKey{Digest: regDigest, Platform: platform})

	baseKey := entityString(in.Scan.Subject.Key) + "|" + string(in.Target.Source)
	base, baseCached := r.bases[baseKey]
	needRescan := !baseCached && !(in.Conditions.Known() && in.Conditions.Equal(prep))
	cand, candCached := r.cands[candKey]

	// Check both limits before spending either, so a deferral wastes nothing.
	if needRescan && r.plan.Usage.BaselineRescans >= r.p.cfg.Limits.MaxBaselineRescans {
		defer0(it, ReasonBaselineRescanLimit, fmt.Sprintf("baseline rescan limit of %d reached", r.p.cfg.Limits.MaxBaselineRescans))
		return
	}
	if !candCached && r.plan.Usage.CandidateScans >= r.p.cfg.Limits.MaxCandidateScans {
		defer0(it, ReasonCandidateScanLimit, fmt.Sprintf("candidate scan limit of %d reached", r.p.cfg.Limits.MaxCandidateScans))
		return
	}

	switch {
	case needRescan:
		r.plan.Usage.BaselineRescans++
		base = r.scanUnder(RoleBaseline, in.Target)
		r.bases[baseKey] = base
	case !baseCached:
		rec := ScanRecord{Scan: in.Scan, Conditions: in.Conditions}
		base = scanned{rec: rec, id: r.addExecution(RoleBaseline, rec, entityString(in.Scan.Subject.Key), DBSupplied, nil, "", nil)}
		r.bases[baseKey] = base
	}
	if !candCached {
		r.plan.Usage.CandidateScans++
		target := scanner.ScanTarget{
			Subject: inventory.ImageSubject{
				Ref:      ref.Repository + ":" + it.Candidate.Tag,
				Key:      inventory.EntityKey{Digest: regDigest, Platform: platform},
				Resolved: true,
			},
			Registry: inventory.RegistryRef{Repository: ref.Repository, Digest: regDigest},
			Source:   scanner.SourceRemote,
		}
		cand = r.scanUnder(RoleCandidate, target)
		r.cands[candKey] = cand
	}
	it.BaselineScan, it.CandidateScan = base.id, cand.id
	if err := r.ctx.Err(); err != nil {
		defer0(it, ReasonCycleDeadline, err.Error())
		it.Candidate = nil
		return
	}

	vr := Compare(base.rec, cand.rec).ApplyCoverage(it.Targets, base.rec, cand.rec)
	dec := Decide(it.Targets, vr, r.p.cfg.Intel)
	it.Comparison, it.Decision = &vr, &dec
	switch dec.Kind {
	case DecisionAdopt, DecisionAdoptPartial:
		if ref.Kind == TagPinned {
			it.Category = CategoryPRCandidate
		} else {
			it.Category = CategoryPullAgain
		}
		it.Reason = ReasonAdopted
		if dec.Kind == DecisionAdopt {
			it.Detail = fmt.Sprintf("all %d targets resolved, nothing introduced", dec.Targets)
		} else {
			it.Detail = fmt.Sprintf("%d of %d targets resolved, %d remain, %d not detected on the running image, nothing introduced", dec.Resolved, dec.Targets, dec.Remaining, dec.Undetected)
		}
	case DecisionIntroduced:
		set(it, CategoryManual, ReasonIntroducedFindings, fmt.Sprintf("%d findings are introduced by the candidate", dec.Introduced))
	case DecisionNewKEV:
		set(it, CategoryManual, ReasonIntroducedKEV, fmt.Sprintf("the candidate introduces KEV-listed vulnerabilities: %v", dec.IntroducedKEV))
	case DecisionAnalysisIncomplete:
		set(it, CategoryNotComparable, ReasonAnalysisIncomplete, fmt.Sprintf("%d of %d targets could not be judged: the candidate scan did not cover their package type", dec.Unknown, dec.Targets))
	case DecisionTargetsNotDetected:
		set(it, CategoryNotComparable, ReasonTargetsNotDetected, fmt.Sprintf("none of the %d targets is shown by the baseline comparison scan", dec.Targets))
	case DecisionNotResolving:
		set(it, CategoryNoCandidate, ReasonCandidateNotFixing, fmt.Sprintf("none of %d targets is resolved by the candidate", dec.Targets))
	default:
		cat := CategoryNotComparable
		if vr.Reason == ReasonScanFailed {
			cat = CategoryFailed
		}
		set(it, cat, vr.Reason, vr.Detail)
	}
}

// scanUnder scans target and records the scan. The prepared conditions are
// attached only if the databases are verified unchanged afterwards;
// otherwise the record carries no conditions and cannot be compared.
func (r *run) scanUnder(role ScanRole, target scanner.ScanTarget) scanned {
	scan := r.p.cfg.Scanner.Scan(r.ctx, target)
	at := r.p.cfg.Now()
	rec := ScanRecord{Scan: scan}
	requested := Unconfirmed
	if target.Subject.Resolved {
		requested = entityString(target.Subject.Key)
	}
	if scan.Err != nil {
		return scanned{rec: rec, id: r.addExecution(role, rec, requested, DBNotChecked, nil, "", &at)}
	}
	ok, err := r.p.cfg.Scanner.VerifyDB(r.ctx, r.p.cfg.Prepared)
	checked := r.p.cfg.Now()
	check, dbErr := DBVerified, ""
	switch {
	case err != nil:
		check, dbErr = DBCheckFailed, err.Error()
	case !ok:
		check = DBChanged
	default:
		rec.Conditions = r.p.cfg.Prepared
	}
	return scanned{rec: rec, id: r.addExecution(role, rec, requested, check, &checked, dbErr, &at)}
}

// addExecution appends a scan record to the plan and returns its ID.
func (r *run) addExecution(role ScanRole, rec ScanRecord, requested string, db DBCheck, checkedAt *time.Time, dbErr string, scannedAt *time.Time) string {
	s := rec.Scan
	ex := ScanExecution{
		ID:        fmt.Sprintf("s%d", len(r.plan.Scans)+1),
		Role:      role,
		Source:    s.Source,
		Ref:       s.Subject.Ref,
		Requested: requested,
		Confirmed: Unconfirmed,
		ScannedAt: scannedAt,
		DB:        db,
		DBCheckAt: checkedAt,
		DBError:   dbErr,
	}
	if ex.Ref == "" {
		ex.Ref = s.Image
	}
	if s.Pinned {
		ex.Confirmed = entityString(s.ScannedKey)
	}
	if s.Err != nil {
		ex.Failure = s.Err.Error()
	}
	r.plan.Scans = append(r.plan.Scans, ex)
	return ex.ID
}
