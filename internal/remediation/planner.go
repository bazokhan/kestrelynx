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
	// returned list's Pages says how many page requests were made. A
	// registry that also implements TagPager is read by series instead (see
	// walkSeries) and ListTagsUpTo is only the fallback.
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
	// Declared are what the definitions of the running containers declare
	// for the image, one entry per workload, reference and pull policy; empty
	// where the runtime has no such notion (Docker).
	Declared []DeclaredInstance
	// Management are the management chains of the workloads that run the
	// image, where they are known.
	Management []WorkloadChains
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
	// Runtimes are the advisors of the language runtimes the scanner checks
	// itself; the planner reads the runtimes of a base image from its config
	// with them. The same advisors as the scanner's, so both see the same
	// advisory data.
	Runtimes []scanner.RuntimeAdvisor
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

	// composeBuild records, by workload key, what is known of the mapped
	// Compose service's build section; a workload without a mapping, or
	// when no GitHub reader is configured, has no entry.
	composeBuild map[string]composeState
	// tagUsed counts the tag listing requests made for each repository, over
	// all the series read from it.
	tagUsed map[string]int
}

// composeState is what is known of a mapped workload's Compose service.
type composeState struct {
	build ComposeBuild
	// out, set when the build section could not be determined, is the plan
	// outcome of the images the workload runs.
	out *dfOutcome
}

// initDF creates the caches the GitHub reads of the Dockerfile and Compose
// parts share, once per pass.
func (r *run) initDF() {
	if r.dfSHA == nil {
		r.dfSHA = map[string]dfShaEntry{}
		r.dfFiles = map[string]*dfFileEntry{}
		r.dfScans = map[string]scanned{}
	}
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
		tagUsed:  map[string]int{},
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

	var withTargets []ImageInput
	for _, e := range entries {
		withTargets = append(withTargets, e.in)
	}
	r.readComposeBuilds(withTargets)

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

		Declared:   in.Declared,
		Management: in.Management,
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
	// A declaration that disagrees with the running reference or is missing
	// comes first, whatever the reference is: no other outcome rests on it.
	if reason, detail, ok := declaredCheck(in.Declared, it.Current.Ref); !ok {
		set(it, CategoryNotComparable, reason, detail)
		return
	}
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
	verdict, why, unknown := r.locallyBuilt(ref, in)
	switch verdict {
	case builtLocally:
		set(it, CategoryExcluded, ReasonLocallyBuilt, why)
		return
	case localUnknown:
		set(it, unknown.cat, unknown.reason, unknown.detail)
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

// readComposeBuilds reads, for each mapped Compose workload of the inputs,
// whether its service has a build section. The reads are the ones the
// Dockerfile part makes again later and are cached with them; a file that
// cannot be read or understood leaves the workload without an answer.
func (r *run) readComposeBuilds(inputs []ImageInput) {
	r.composeBuild = map[string]composeState{}
	cfg := r.p.cfg
	if cfg.GitHub == nil || len(cfg.Composes) == 0 {
		return
	}
	r.initDF()
	composes := map[string]*ComposeMapping{}
	for i := range cfg.Composes {
		if m := &cfg.Composes[i]; composes[m.Workload] == nil {
			composes[m.Workload] = m
		}
	}
	for _, in := range inputs {
		for _, s := range in.Services {
			k := workloadKey(s)
			cm := composes[k]
			if _, done := r.composeBuild[k]; cm == nil || done {
				continue
			}
			sha, out := r.dfBranch(cm.Repository, cm.BaseBranch)
			if out != nil {
				r.composeBuild[k] = composeState{out: out}
				continue
			}
			e := r.dfRead(cm.Repository, sha, cm.Path)
			if e.out != nil {
				r.composeBuild[k] = composeState{out: e.out}
				continue
			}
			build, why := ComposeServiceBuilds(e.file.Content, cm.Path, cm.ComposeService)
			st := composeState{build: build}
			if build == ComposeBuildUndetermined {
				st.out = &dfOutcome{CategoryManual, ReasonComposeBuildUndetermined,
					"the mapped Compose service cannot be read with confidence (" + why + "), so it is not known whether the running image was built on this host"}
			}
			r.composeBuild[k] = st
		}
	}
}

// localVerdict is the outcome of asking whether a running image was built on
// its host.
type localVerdict int

const (
	// notLocal: nothing says it was built on the host.
	notLocal localVerdict = iota
	// builtLocally: it was.
	builtLocally
	// localUnknown: the workload is mapped to a Compose file that cannot say;
	// the outcome is in the returned dfOutcome.
	localUnknown
)

// locallyBuilt decides whether the running image was built on its host, so
// that no registry holds a copy to compare with and a lookup would only send
// its name to Docker Hub. detail says why. Only evidence counts; an image
// with none is looked up as usual, and whether a registry knows the name, or
// refuses it, is never taken as evidence. In order of confidence:
//
//  1. The workload is mapped to a Compose file whose service has a build
//     section. A service with both image: and build: is built too: Compose
//     builds it and tags the result with the image: name, which is how an
//     image meant to be pushed is named, but what runs here is the local
//     build. Looking its tag up would propose a different image than the one
//     built, so such a service is not looked up either.
//  2. The image's own configuration carries the labels Docker Compose puts on
//     an image it builds, com.docker.compose.project and
//     com.docker.compose.service, they name the project and service of the
//     container that runs it, and the reference is the name Compose gives
//     an image it builds (see below). An image pulled from a registry has the
//     labels only if its publisher built it with Compose; that is told apart
//     by the name, and by a mapped Compose service that is known to have no
//     build section, which settles it first. What remains is an image that
//     CI built and published under exactly <project>-<service>:latest, which
//     is read as built here.
//  3. The reference names no registry and the scan found no registry digest
//     (the classic image store).
//  4. The workload is mapped but its Compose service cannot be read with
//     confidence (or the file cannot be read): the image is neither looked up
//     nor called built, since either would be a guess; the outcome is
//     deferred or manual.
func (r *run) locallyBuilt(ref ImageRef, in ImageInput) (localVerdict, string, *dfOutcome) {
	var unknown *dfOutcome
	noBuild := false
	for _, s := range in.Services {
		st, ok := r.composeBuild[workloadKey(s)]
		switch {
		case !ok:
		case st.out != nil:
			if unknown == nil {
				unknown = st.out
			}
		case st.build == ComposeBuildYes:
			return builtLocally, "its Compose service has a build section, so the running image was built on this host and is not looked up in a registry", nil
		default:
			noBuild = true
		}
	}
	// The labels count only where nothing better is known: a mapped Compose
	// service confirmed to have no build section pulls its image, whatever
	// the image's labels say. And the reference must be the name Compose gives
	// an image it builds when the service names none (image: unset),
	// <project>-<service> or the older <project>_<service>, tagged latest,
	// with no registry host and no namespace: an image published under any
	// other name, by CI that built it with Compose under the same project and
	// service names, is a pulled image and is looked up as usual. A pulled
	// image could carry such a name only as a Docker Official Image (a name
	// with no host and no namespace resolves to docker.io/library/), and
	// those are not published from a Compose project.
	if p, sv := in.Scan.ComposeProject, in.Scan.ComposeService; p != "" && sv != "" && !noBuild && ref.Tag == "latest" {
		for _, s := range in.Services {
			if s.Project != p || s.Service != sv {
				continue
			}
			for _, sep := range []string{"-", "_"} {
				if ref.Repository == p+sep+sv {
					return builtLocally, "the image carries the Docker Compose labels of project " + p + " and service " + sv + ", the ones of the container that runs it, and is named as Compose names an image it builds, so Compose built it on this host", nil
				}
			}
		}
	}
	if !inventory.HasRegistryHost(ref.Repository) && len(in.Scan.RegistryDigests) == 0 {
		return builtLocally, "the image has no registry digest and its reference names no registry, so it was built on this host and no registry holds a copy to compare with", nil
	}
	if unknown != nil {
		return localUnknown, "", unknown
	}
	return notLocal, "", nil
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
	repoKey := key
	if _, ok := r.p.cfg.Registry.(TagPager); ok {
		// The tags read are those of the image's series, so images of other
		// series of one repository do not share a listing (patches of one
		// series do).
		key += "|" + seriesKey(ref.Version)
	}
	e, cached := r.tags[key]
	if !cached {
		if r.halted != nil {
			defer0(it, r.halted.reason, r.halted.detail)
			return false
		}
		// The limit is the repository's, whatever the number of series read
		// from it: each listing gets what the earlier ones left.
		allowance := r.p.cfg.Limits.MaxTagPages - r.tagUsed[repoKey]
		if allowance <= 0 {
			defer0(it, ReasonTagPageLimit, fmt.Sprintf("tag page limit of %d reached", r.p.cfg.Limits.MaxTagPages))
			return false
		}
		list, err := listPinnedSeries(r.ctx, r.p.cfg.Registry, ref.Repository, ref.Version, allowance)
		e = tagEntry{list: list, err: err, allowance: allowance}
		r.tags[key] = e
		r.tagUsed[repoKey] += list.Pages
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
// pass. A request that merely ran out of its own time, while the cycle's
// context is live, defers only the image it was for: the cycle deadline and
// one slow registry are different conditions.
func (r *run) registryFailure(it *Item, err error) {
	var variant *registry.VariantError
	var limited *registry.RateLimitedError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, registry.ErrTimeout) && r.ctx.Err() != nil:
		r.halted = &halt{ReasonCycleDeadline, err.Error()}
		defer0(it, r.halted.reason, r.halted.detail)
	case errors.Is(err, registry.ErrTimeout):
		defer0(it, ReasonRegistryTimeout, err.Error())
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
			it.Pull = pullAdvice(in.Declared, ref)
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
