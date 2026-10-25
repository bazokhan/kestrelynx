// Package analyze turns raw scanner findings into a triaged, aggregated Report:
// it sorts vulnerabilities into sections by Trivy Status (sectionOf), groups
// them per image+package,
// judges update risk (semver for language packages only), and surfaces
// end-of-life base images. This is the differentiation core (docs/PROJECT_CONTEXT.md):
// the post-processing that makes raw scanner output actionable.
package analyze

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Risk is the update-risk hint attached to a fixable package.
type Risk string

const (
	RiskNone         Risk = ""              // not applicable (no fix available)
	RiskDistroUpdate Risk = "distro_update" // OS package: distro security revision, not semver
	RiskSafe         Risk = "safe"          // lang package: patch/minor bump
	RiskCaution      Risk = "caution"       // lang package: major bump (possible breaking change)
	RiskUnknown      Risk = "unknown"       // lang package: version not parseable
)

// PackageGroup aggregates all selected vulnerabilities of one package within
// one image (a single package often carries many CVEs). The aggregation key
// is PackageRef, not just Package's name: an image can run an OS package and
// a language package that happen to share a name (distro openssl and a Rust
// openssl crate), and they must never be merged into one row.
type PackageGroup struct {
	Package      string
	Class        scanner.PkgClass
	InstalledVer string
	FixedVer     string
	Status       scanner.Status // the section's status (sectionOf), never a raw status that sectionOf folds into another
	Risk         Risk
	Critical     int       // count of distinct CRITICAL CVEs
	High         int       // count of distinct HIGH CVEs
	Medium       int       // count of distinct MEDIUM CVEs (scan.severity may include it)
	Low          int       // count of distinct LOW CVEs
	Unknown      int       // count of distinct CVEs whose severity is UNKNOWN or not a recognized level
	Vulns        []VulnRef // deduplicated, strongest verdict first (sortVulns)
	Priority     Priority  // max of Vulns' priorities; PriorityNone when triage is off
	URL          string    // representative reference

	// Ecosystem is the one identity field Package/Class/InstalledVer didn't
	// already cover. It is not folded into a stored PackageRef alongside
	// them — that would keep the same four values in two places — so
	// PackageRef() (below) is how callers get the combined identity.
	Ecosystem inventory.Ecosystem
	// Instances is every distinct place this exact (ecosystem, class, name,
	// version) was found in the image: which raw Trivy Result it came from
	// (Type/Target) and, for a language package, which file reported it
	// (PkgPath). More than one Instance means the same package shows up more
	// than once — e.g. the same vendored Go module embedded in two
	// separately built binaries under /app/api and /app/tool — and each
	// place can end up with its own runtime usage verdict later. Sorted for
	// determinism; never rendered directly in Slack or the webhook.
	Instances []Instance
	// LayerDiffIDs are the distinct filesystem layers (diff IDs, sorted) the
	// group's findings were attributed to; it holds "" when a finding carried
	// no layer. Empty only for a group built without findings.
	LayerDiffIDs []string

	// Runtime is this package's projected runtime-usage verdict: its
	// Instances judged against the current evidence.Snapshot's matched
	// container generations, then folded by evidence.ProjectGroup — see
	// AttachRuntime (runtime.go). The zero value (Usage == "") means runtime
	// evidence was never attached, which is either runtime.enabled being
	// false or AttachRuntime simply never having been called. Every notify
	// rendering that shows runtime information gates on this being non-zero
	// first, so a disabled deployment's output is byte-identical to a build
	// that never linked this field at all.
	Runtime Runtime

	// Muted and MutedReason are set by ApplyMuting
	// (runtime.mute_unfixable_not_in_use): notify hides this group's row
	// from its Slack rendering and shows it only in a count instead, because
	// no fix is coming and nothing has used the package for the whole
	// observation window. Both stay at their zero value (false, "") whenever
	// the setting is off or the group was never eligible, and neither one
	// ever changes Priority or a VulnRef's own Priority — muting changes
	// what notify shows, never the triage verdict underneath it.
	Muted       bool
	MutedReason MutedReason
}

// MutedReason names why ApplyMuting judged a PackageGroup muted.
// Kept as its own type rather than a bare string literal so a future second
// muting rule has an established place to add its own value without
// disturbing this one's wire representation.
type MutedReason string

// MutedNoFixNotInUse7d is ApplyMuting's one current judgment: the
// canonical Status has no fix coming, and nothing has used the package
// during at least 7 days of Sensor observation.
const MutedNoFixNotInUse7d MutedReason = "no_fix_not_in_use_7d"

// Instance is one raw Trivy Result a PackageGroup's Instances collects,
// deduplicated by (Type, Target, PkgPath): the same triple reported twice
// (once per CVE on the package, say) counts once.
type Instance struct {
	PackageRef inventory.PackageRef
	Type       string
	Target     string
	PkgPath    string
}

// sortInstances orders a group's Instances deterministically: Type, then
// Target, then PkgPath (PackageRef is constant across one group's Instances,
// so it never needs to break a tie).
func sortInstances(instances []Instance) {
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Type != instances[j].Type {
			return instances[i].Type < instances[j].Type
		}
		if instances[i].Target != instances[j].Target {
			return instances[i].Target < instances[j].Target
		}
		return instances[i].PkgPath < instances[j].PkgPath
	})
}

// PackageRef is g's identity, assembled from Package/Class/InstalledVer/
// Ecosystem on demand — the same pattern as scanner.Finding.PackageRef():
// one derivation, so nothing can independently drift from Package, Class,
// InstalledVer or Ecosystem by being set to a different value.
func (g PackageGroup) PackageRef() inventory.PackageRef {
	return inventory.PackageRef{Ecosystem: g.Ecosystem, Class: g.Class, Name: g.Package, Version: g.InstalledVer}
}

// Total is the number of distinct vulnerabilities in the group.
func (g PackageGroup) Total() int { return g.Counts().Total() }

// Counts returns the group's per-severity counts.
func (g PackageGroup) Counts() SeverityCounts {
	return SeverityCounts{Critical: g.Critical, High: g.High, Medium: g.Medium, Low: g.Low, Unknown: g.Unknown}
}

// SeverityCounts is a distinct-CVE count per severity level. Every level
// is counted exactly: HIGH counts only HIGH, and a level scan.severity does
// not select simply stays zero.
type SeverityCounts struct {
	Critical, High, Medium, Low, Unknown int
}

// Add returns c plus o, level by level.
func (c SeverityCounts) Add(o SeverityCounts) SeverityCounts {
	return SeverityCounts{
		Critical: c.Critical + o.Critical,
		High:     c.High + o.High,
		Medium:   c.Medium + o.Medium,
		Low:      c.Low + o.Low,
		Unknown:  c.Unknown + o.Unknown,
	}
}

// Total is the sum over every level.
func (c SeverityCounts) Total() int { return c.Critical + c.High + c.Medium + c.Low + c.Unknown }

// VulnIDs returns the group's vulnerability IDs, sorted.
func (g PackageGroup) VulnIDs() []string {
	ids := make([]string, 0, len(g.Vulns))
	for _, v := range g.Vulns {
		ids = append(ids, v.ID)
	}
	sort.Strings(ids)
	return ids
}

// TopVuln is the vulnerability whose verdict headlines the group (the evidence
// shown for an act_now item). Zero value when the group is empty.
func (g PackageGroup) TopVuln() VulnRef {
	if len(g.Vulns) == 0 {
		return VulnRef{}
	}
	return g.Vulns[0]
}

// ImageFindings is one running entity's package groups within a single status
// section. The aggregation unit is (Image, EntityKey) rather than Image
// alone: when the same reference runs more than one distinct entity at once,
// each entity gets its own section entry instead of being merged silently.
// Subject carries that entity's identity (and Ref, mirroring Image), and
// Pinned records whether this cycle's scan actually confirmed it. The
// ordinary, single-resolved-entity case renders exactly as before; it is
// only when a reference is genuinely ambiguous that more than one entry
// shares the same Image.
type ImageFindings struct {
	Image    string
	Subject  inventory.ImageSubject // this entity's identity; zero value (Resolved == false) when unresolved
	Pinned   bool                   // true when this cycle's scan confirmed Subject.Key was what actually ran
	Packages []PackageGroup
	// Containers is the entity-level observation backing this section entry:
	// every container whose (Ref, EntityKey) matches (Image, Subject.Key)
	// exactly, in the order containers was passed to Build. Nil when Build
	// received no containers, or none matched this entity.
	Containers []inventory.Container
}

// ContentID projects Subject onto the boundary-validated OCI image config
// digest string (the pre-generalization "ContentID") when this entity
// resolved to a config-kind identity; "" otherwise (unresolved, or resolved
// to a non-config identity kind). Renderers that only ever dealt with
// Docker's config digests keep working against this exact same string.
func (f ImageFindings) ContentID() string {
	if f.Subject.Resolved && f.Subject.Key.Digest.Kind == inventory.DigestConfig {
		return f.Subject.Key.Digest.String()
	}
	return ""
}

// CriticalCount sums CRITICAL CVEs across the image's packages.
func (f ImageFindings) CriticalCount() int {
	n := 0
	for _, g := range f.Packages {
		n += g.Critical
	}
	return n
}

// Counts sums the per-severity counts across the image's packages.
func (f ImageFindings) Counts() SeverityCounts {
	var c SeverityCounts
	for _, g := range f.Packages {
		c = c.Add(g.Counts())
	}
	return c
}

// TotalCount sums all CVEs across the image's packages.
func (f ImageFindings) TotalCount() int {
	n := 0
	for _, g := range f.Packages {
		n += g.Total()
	}
	return n
}

// RuntimeUncheckedRef names a language runtime (Package, e.g. "Node.js") of an
// image that was detected but not checked.
type RuntimeUncheckedRef struct {
	Image   string
	Package string
}

// ScanError records an image whose scan failed, so it is surfaced rather than
// silently dropped.
type ScanError struct {
	Image string
	Err   string
}

// ImageObservation is the identity inventory for one scanned reference,
// covering every scan target this cycle — clean or not, resolved or not,
// failed or not. It is the single source state.Compute reads to update
// State.Images and to detect partial-failure references; unlike the status
// sections it does not depend on there being any findings.
//
// State persists a *sorted set* of content IDs per reference, not a single
// value, because an Ambiguous reference can run more than one verified
// entity at once. To give state.Compute that set without re-deriving it from
// the status sections, this inventory carries the set directly as
// ContentIDs; a single-entity reference simply has len(ContentIDs) <= 1.
type ImageObservation struct {
	Ref string

	// ContentIDs is the sorted set of boundary-validated, config-kind
	// ContentIDs (a projection of Subject) observed running under Ref this
	// cycle. This is identity data reported by the caller, independent of
	// whether the Trivy scan itself succeeded (scanner/exec.go: Subject
	// survives a scan failure unchanged) — a failed scan whose entity was
	// still resolved still contributes to this set. What never contributes
	// is a reference-fallback scan's ScannedKey: that describes whatever
	// Trivy happened to resolve on its own, not a specific running entity
	// the caller told us about.
	ContentIDs []string
	// RegistryDigests is the sorted union of RegistryDigests across every
	// entity that both resolved a ContentID and scanned successfully under
	// Ref (Trivy's Metadata.RepoDigests isn't available otherwise).
	RegistryDigests []string
	// Ambiguous is true when more than one distinct resolved entity (any
	// identity kind) is running under Ref at once — the cardinality of the
	// set of EntityKeys observed, not just the config-digest subset ContentIDs
	// projects.
	Ambiguous bool
	// IdentityResolved is true when every entity running under Ref had a
	// Docker-observed ContentID this cycle (false if any entity used the
	// reference-fallback path, or resolved to a non-config-digest identity).
	// This is independent of scan success: it reflects what was reported,
	// not what Trivy managed to scan.
	IdentityResolved bool
	// ScanFailed is true when every entity running under Ref failed to scan
	// this cycle (the existing full-failure case: state carries findings over
	// untouched).
	ScanFailed bool
	// PartialFailure is true when at least one entity running under Ref is
	// missing trustworthy evidence this cycle: either it failed to scan while
	// a sibling succeeded, or it scanned successfully but could not be
	// pinned (Unconfirmed). Either way state must not silently drop or
	// resolve findings just because some other entity under the same Ref
	// looked fine.
	PartialFailure bool
	// Unconfirmed is true when at least one entity running under Ref scanned
	// without error but could not be confirmed as the entity actually
	// requested (Pinned == false, Source == remote). Always false for
	// Docker, which never falls back this way.
	Unconfirmed bool
	// Containers is the union of every container observed running Ref this
	// cycle, across all of its entities (ContentIDs). Nil when Build received
	// no containers, or none matched this reference.
	Containers []inventory.Container
}

// Report is the triaged output, ready for the notify layer. Sections are
// ordered by priority via their position (docs/NOTIFICATION_SPEC.md §2):
// EOSL first, then actionable (fixed), watch (affected), wont-fix, and the
// packages the vendor reports as end-of-life for this release.
type Report struct {
	ImagesTotal int             // unique images scanned this run (incl. failures)
	EOSLImages  []string        // base OS end-of-life: highest priority
	Actionable  []ImageFindings // Status == fixed
	Watch       []ImageFindings // Status == affected, plus the statuses sectionOf folds into it (upstream not yet fixed)
	WontFix     []ImageFindings // Status == will_not_fix
	// EOLPackages holds every end_of_life package group, including those of
	// images whose base OS is itself end-of-life: renderers decide what to
	// fold (EOLPackageAlerts, FoldedEOLCount), the report and the webhook
	// keep everything.
	EOLPackages []ImageFindings // Status == end_of_life
	ScanErrors  []ScanError
	// Images is the per-reference identity inventory, covering every scanned
	// reference regardless of findings. Sorted by Ref.
	Images []ImageObservation
	// UnconfirmedRefs is the sorted set of references with at least one
	// Unconfirmed entity this cycle (a projection of Images, kept as its own
	// field so notify doesn't have to re-derive it). Always nil for Docker.
	UnconfirmedRefs []string
	// RuntimeUnchecked is the set of (reference, runtime package) pairs whose
	// language runtime (Node.js, Python runtime) was detected but not checked
	// because its advisory data was unavailable, de-duplicated and sorted by
	// reference, then package. Scans that failed are not included.
	RuntimeUnchecked []RuntimeUncheckedRef
	Triage           bool        // priorities were assigned (renderers use ByPriority)
	Intel            IntelStatus // freshness of the intel behind the priorities
	GeneratedAt      time.Time
	// Environment identifies the runtime instance this cycle observed. Build
	// never sets it (it has no scan-derived meaning to interpret); the caller
	// copies it in from config/composition-root state.
	Environment inventory.Environment
	// Runtime is this cycle's Sensor-wide runtime status: set only by
	// AttachRuntime (runtime.go), nil whenever runtime.enabled is false. See
	// RuntimeInfo's own doc comment for why this carries the Sensor's raw
	// self-report rather than a display-ready status string.
	Runtime *RuntimeInfo
	// GenericWebhookConfigured mirrors whether notify.generic_webhook_url is
	// set. Build never sets it (it has no scan-derived meaning to interpret,
	// same as Environment above) — the caller copies it in from
	// config/composition-root state. It exists only so notify's guidance
	// text can point at the one destination that actually carries full
	// per-package detail (the generic webhook) without ever naming it to a
	// deployment that never configured one.
	GenericWebhookConfigured bool
}

// AffectedImageCount is the number of distinct images with any issue (findings
// or EOLL). Scan failures are not counted as "affected".
func (r Report) AffectedImageCount() int {
	seen := map[string]bool{}
	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			seen[img.Image] = true
		}
	}
	for _, im := range r.EOSLImages {
		seen[im] = true
	}
	return len(seen)
}

// HasFindings reports whether any vulnerability or EOSL image is present.
func (r Report) HasFindings() bool {
	return len(r.Actionable) > 0 || len(r.Watch) > 0 || len(r.WontFix) > 0 || len(r.EOLPackages) > 0 || len(r.EOSLImages) > 0
}

// IsEOL reports whether g is an end_of_life package group: the vendor
// reports its CVEs as out of support for the installed release.
func IsEOL(g PackageGroup) bool { return g.Status == scanner.StatusEndOfLife }

// EOLPackageAlerts is the part of EOLPackages shown as individual rows: every
// entry except those of images whose base OS is end-of-life (r.EOSLImages),
// which the base-OS line summarizes instead. It does not filter by priority,
// and it keeps each entry whole (Subject, Pinned, Containers) without merging
// entries that share an image.
func (r Report) EOLPackageAlerts() []ImageFindings {
	folded := stringSet(r.EOSLImages)
	var out []ImageFindings
	for _, img := range r.EOLPackages {
		if !folded[img.Image] {
			out = append(out, img)
		}
	}
	return out
}

// FoldedEOLCount is the number of end_of_life package groups the base-OS
// line of ref summarizes, act_now groups included. It is 0 when ref's base
// OS is not end-of-life.
func (r Report) FoldedEOLCount(ref string) int {
	if !stringSet(r.EOSLImages)[ref] {
		return 0
	}
	n := 0
	for _, img := range r.EOLPackages {
		if img.Image == ref {
			n += len(img.Packages)
		}
	}
	return n
}

func stringSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}

// sectionOf maps a raw Trivy status to the report section it belongs to.
// ok is false for not_affected, the one status that is dropped: it states
// the package is not vulnerable. fix_deferred, under_investigation,
// unknown (including a missing status), and any value Trivy may add later
// are all unfixed findings, so they join affected rather than disappearing;
// the raw value survives on VulnRef.Status.
func sectionOf(s scanner.Status) (scanner.Status, bool) {
	switch s {
	case scanner.StatusFixed, scanner.StatusWontFix, scanner.StatusEndOfLife:
		return s, true
	case scanner.StatusNotAffected:
		return "", false
	default:
		return scanner.StatusAffected, true
	}
}

// mergeRawStatus picks one raw status for a CVE ID seen more than once in the
// same package group with different raw statuses. The result must not depend
// on the order Trivy listed the lines in: the section's own status wins when
// either side carries it, otherwise the lexically smaller value.
func mergeRawStatus(section, a, b scanner.Status) scanner.Status {
	if a == section || b == section {
		return section
	}
	if a < b {
		return a
	}
	return b
}

// HasIssues reports whether anything worth a notification exists, including
// scan failures.
func (r Report) HasIssues() bool {
	return r.HasFindings() || len(r.ScanErrors) > 0
}

// vulnInfo is the per-CVE data captured from the scanner during accumulation.
type vulnInfo struct {
	sev    scanner.Severity
	url    string
	title  string
	status scanner.Status // raw Trivy status (see mergeRawStatus)
}

// pkgAcc accumulates a package group while deduplicating CVEs by ID and
// Instances by (Type, Target, PkgPath).
type pkgAcc struct {
	group     PackageGroup
	vulns     map[string]vulnInfo
	instances map[Instance]bool
	layers    map[string]bool
}

// imgKey is the aggregation unit for findings: a running entity, identified
// by its display reference plus the EntityKey the scan's Subject carried.
// Subject.Key is used rather than the scanned entity: for an unresolved scan
// Subject.Key is the zero value, which is exactly "unresolved" and must not
// be confused with a resolved entity's key.
type imgKey struct {
	ref string
	key inventory.EntityKey
}

// entityMeta carries the per-entity identity fields (Subject, Pinned) that
// ImageFindings needs but that a package-group accumulator has no natural
// home for: they describe the scan, not any one finding within it.
type entityMeta struct {
	subject inventory.ImageSubject
	pinned  bool
}

// obsAcc accumulates one reference's identity inventory across every scan
// target observed under it this cycle: possibly several distinct entities
// when the reference is ambiguous, possibly a mix of successes, failures,
// and unconfirmed results.
type obsAcc struct {
	total, failed, unconfirmed int
	// contentIDs projects only the config-kind subset of resolved entities
	// (the pre-generalization "ContentIDs" set): the persisted state format
	// and the diff rules built on it are config-digest-specific and frozen.
	contentIDs map[string]bool
	// entityKeys is every resolved entity (any identity kind) observed under
	// this ref, used for Ambiguous: a cardinality question that must not be
	// narrowed to the config-digest subset contentIDs tracks. For Docker,
	// every resolved entity is config-kind, so the two sets are in bijection
	// and Ambiguous is unchanged.
	entityKeys      map[inventory.EntityKey]bool
	registryDigests map[string]bool
	anyUnresolved   bool // some scan target under this ref did not resolve a config-kind entity (tallied regardless of scan success/failure)
	seenEOSL        bool
}

// Build triages and aggregates scan results into a Report. tr supplies the
// exploitation intel and thresholds for priority assignment (zero value =
// triage off, Phase 1 behavior). now is injected for deterministic output.
func Build(scans []scanner.ImageScan, containers []inventory.Container, tr Triage, now time.Time) Report {
	r := Report{GeneratedAt: now, ImagesTotal: len(scans), Triage: tr.Enabled, Intel: tr.Intel}

	// section status -> (ref, entity key) -> package identity -> accumulator
	byStatus := map[scanner.Status]map[imgKey]map[inventory.PackageRef]*pkgAcc{}
	obs := map[string]*obsAcc{}     // by ref, the inventory backing Report.Images
	meta := map[imgKey]entityMeta{} // per-entity Subject/Pinned, for buildSection
	uncheckedSeen := map[RuntimeUncheckedRef]bool{}

	for _, s := range scans {
		a := obs[s.Image]
		if a == nil {
			a = &obsAcc{contentIDs: map[string]bool{}, entityKeys: map[inventory.EntityKey]bool{}, registryDigests: map[string]bool{}}
			obs[s.Image] = a
		}
		a.total++

		// Identity (Subject) is Docker-observed data that survives a Trivy
		// scan failure unchanged (scanner/exec.go): every error path still
		// returns the Subject the caller asked Trivy to pin to. So this must
		// be recorded regardless of s.Err — only the scan-derived
		// RegistryDigests genuinely require a successful, pinned scan.
		if s.Subject.Resolved {
			a.entityKeys[s.Subject.Key] = true
			if s.Subject.Key.Digest.Kind == inventory.DigestConfig {
				a.contentIDs[s.Subject.Key.Digest.String()] = true
			} else {
				// A resolved-but-non-config-digest entity is not the
				// pre-generalization "ContentID" set's business.
				a.anyUnresolved = true
			}
		} else {
			// Reference-fallback identity data describes whatever Trivy
			// happened to resolve, not a specific running entity, so it never
			// joins the verified set.
			a.anyUnresolved = true
		}

		if s.Err != nil {
			a.failed++
			r.ScanErrors = append(r.ScanErrors, ScanError{Image: s.Image, Err: s.Err.Error()})
			continue
		}
		if !s.Pinned && s.Source == scanner.SourceRemote {
			a.unconfirmed++
		}
		if s.Pinned {
			for _, d := range s.RegistryDigests {
				a.registryDigests[d] = true
			}
		}
		if s.OSEOSL && !a.seenEOSL {
			a.seenEOSL = true
			r.EOSLImages = append(r.EOSLImages, s.Image)
		}

		for _, pkg := range s.RuntimeUnchecked {
			ref := RuntimeUncheckedRef{Image: s.Image, Package: pkg}
			if !uncheckedSeen[ref] {
				uncheckedSeen[ref] = true
				r.RuntimeUnchecked = append(r.RuntimeUnchecked, ref)
			}
		}

		k := imgKey{ref: s.Image, key: s.Subject.Key}
		meta[k] = entityMeta{subject: s.Subject, pinned: s.Pinned}
		for _, find := range s.Findings {
			section, ok := sectionOf(find.Status)
			if !ok {
				continue
			}
			images := byStatus[section]
			if images == nil {
				images = map[imgKey]map[inventory.PackageRef]*pkgAcc{}
				byStatus[section] = images
			}
			pkgs := images[k]
			if pkgs == nil {
				pkgs = map[inventory.PackageRef]*pkgAcc{}
				images[k] = pkgs
			}
			ref := find.PackageRef()
			acc := pkgs[ref]
			if acc == nil {
				acc = &pkgAcc{
					group: PackageGroup{
						Package:      find.Package,
						Class:        find.Class,
						InstalledVer: find.InstalledVer,
						FixedVer:     find.FixedVer,
						Status:       section,
						URL:          find.URL,
						Ecosystem:    ref.Ecosystem,
					},
					vulns:     map[string]vulnInfo{},
					instances: map[Instance]bool{},
					layers:    map[string]bool{},
				}
				pkgs[ref] = acc
			}
			acc.instances[Instance{PackageRef: ref, Type: find.Type, Target: find.Target, PkgPath: find.PkgPath}] = true
			acc.layers[find.LayerDiffID] = true
			// The same CVE ID can appear on more than one Trivy result line (e.g.
			// matched via more than one data source); prefer whichever line carries
			// a non-empty Title rather than letting a later, title-less line blank it.
			prev, seen := acc.vulns[find.VulnID]
			title := find.Title
			if title == "" {
				title = prev.title
			}
			status := find.Status
			if seen {
				status = mergeRawStatus(section, prev.status, find.Status)
			}
			acc.vulns[find.VulnID] = vulnInfo{sev: find.Severity, url: find.URL, title: title, status: status}
		}
	}

	sort.Strings(r.EOSLImages)
	sort.Slice(r.RuntimeUnchecked, func(i, j int) bool {
		a, b := r.RuntimeUnchecked[i], r.RuntimeUnchecked[j]
		if a.Image != b.Image {
			return a.Image < b.Image
		}
		return a.Package < b.Package
	})
	byKey, byRef := indexContainers(containers)
	r.Actionable = buildSection(byStatus[scanner.StatusFixed], tr, byKey, meta)
	r.Watch = buildSection(byStatus[scanner.StatusAffected], tr, byKey, meta)
	r.WontFix = buildSection(byStatus[scanner.StatusWontFix], tr, byKey, meta)
	r.EOLPackages = buildSection(byStatus[scanner.StatusEndOfLife], tr, byKey, meta)
	r.Images = buildInventory(obs, byRef)
	for _, o := range r.Images {
		if o.Unconfirmed {
			r.UnconfirmedRefs = append(r.UnconfirmedRefs, o.Ref)
		}
	}
	return r
}

// indexContainers groups containers for attachment to the report: byKey for
// the entity-level join (an ImageFindings entry's exact (Image, EntityKey)),
// byRef for the reference-level union (every ImageObservation entity under
// Ref). imgKey doubles as the entity join key here because a container whose
// identity did not resolve gets the zero-value EntityKey, which collapses
// the join to ref-only for exactly those containers — matching the
// unresolved ImageFindings entries (Subject.Resolved == false) they
// correspond to, and no others. A container with an empty Ref is never
// scanned (DistinctImages excludes it) and so never joins anything here
// either. Containers is nil when the caller passed none, and lookups on a
// nil map simply return nil, so every attached field stays nil and existing
// output is unaffected.
func indexContainers(containers []inventory.Container) (byKey map[imgKey][]inventory.Container, byRef map[string][]inventory.Container) {
	if len(containers) == 0 {
		return nil, nil
	}
	byKey = map[imgKey][]inventory.Container{}
	byRef = map[string][]inventory.Container{}
	for _, c := range containers {
		if c.Image.Ref == "" {
			continue
		}
		key, _ := inventory.EntityKeyOf(c.Image)
		k := imgKey{ref: c.Image.Ref, key: key}
		byKey[k] = append(byKey[k], c)
		byRef[c.Image.Ref] = append(byRef[c.Image.Ref], c)
	}
	return byKey, byRef
}

// buildInventory finalizes the per-reference identity inventory that backs
// State.Images and the partial-failure rule: every scanned reference appears
// exactly once, independent of whether it produced any findings.
func buildInventory(obs map[string]*obsAcc, byRef map[string][]inventory.Container) []ImageObservation {
	if len(obs) == 0 {
		return nil
	}
	out := make([]ImageObservation, 0, len(obs))
	for ref, a := range obs {
		var contentIDs []string
		for id := range a.contentIDs {
			contentIDs = append(contentIDs, id)
		}
		sort.Strings(contentIDs)
		var registryDigests []string
		for d := range a.registryDigests {
			registryDigests = append(registryDigests, d)
		}
		sort.Strings(registryDigests)

		out = append(out, ImageObservation{
			Ref:             ref,
			ContentIDs:      contentIDs,
			RegistryDigests: registryDigests,
			Ambiguous:       len(a.entityKeys) > 1,
			// Docker-observed, independent of scan success (see the
			// accumulation loop above) — a scan failure never demotes this.
			IdentityResolved: a.total > 0 && !a.anyUnresolved,
			ScanFailed:       a.total > 0 && a.failed == a.total,
			PartialFailure:   (a.failed > 0 && a.failed < a.total) || a.unconfirmed > 0,
			Unconfirmed:      a.unconfirmed > 0,
			Containers:       byRef[ref],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// buildSection finalizes one status bucket into sorted ImageFindings.
func buildSection(images map[imgKey]map[inventory.PackageRef]*pkgAcc, tr Triage, byKey map[imgKey][]inventory.Container, meta map[imgKey]entityMeta) []ImageFindings {
	if len(images) == 0 {
		return nil
	}
	out := make([]ImageFindings, 0, len(images))
	for k, pkgs := range images {
		groups := make([]PackageGroup, 0, len(pkgs))
		for _, acc := range pkgs {
			groups = append(groups, finalize(acc, tr))
		}
		sortPackages(groups)
		m := meta[k]
		out = append(out, ImageFindings{Image: k.ref, Subject: m.subject, Pinned: m.pinned, Packages: groups, Containers: byKey[k]})
	}
	sortImages(out)
	return out
}

// finalize computes counts, per-vulnerability triage verdicts, the group's
// aggregate priority (max over its CVEs), and the risk label.
func finalize(acc *pkgAcc, tr Triage) PackageGroup {
	g := acc.group
	for id, info := range acc.vulns {
		switch strings.ToUpper(string(info.sev)) {
		case string(scanner.SeverityCritical):
			g.Critical++
		case string(scanner.SeverityHigh):
			g.High++
		case string(scanner.SeverityMedium):
			g.Medium++
		case string(scanner.SeverityLow):
			g.Low++
		default:
			g.Unknown++
		}
		e := tr.Enrich[id]
		v := VulnRef{
			ID:         id,
			Severity:   info.sev,
			URL:        info.url,
			Title:      info.title,
			Status:     info.status,
			KEV:        e.KEV,
			Ransomware: e.Ransomware,
			EPSS:       e.EPSS,
			EPSSKnown:  e.EPSSKnown,
			Priority:   tr.priorityOf(info.sev, e, g.Status),
			Refs:       buildRefs(e, tr.Refs[id]),
		}
		g.Vulns = append(g.Vulns, v)
		if v.Priority.Rank() > g.Priority.Rank() {
			g.Priority = v.Priority
		}
	}
	sortVulns(g.Vulns)
	g.Risk = riskOf(g)
	for inst := range acc.instances {
		g.Instances = append(g.Instances, inst)
	}
	sortInstances(g.Instances)
	for l := range acc.layers {
		g.LayerDiffIDs = append(g.LayerDiffIDs, l)
	}
	sort.Strings(g.LayerDiffIDs)
	return g
}

// riskOf judges update risk. Semver is applied only to language packages;
// OS package versions are distro-format and not semver (docs/ARCHITECTURE.md ADR-005).
func riskOf(g PackageGroup) Risk {
	if g.Status != scanner.StatusFixed {
		return RiskNone
	}
	if g.Class == scanner.ClassOS {
		return RiskDistroUpdate
	}
	return langRisk(g.InstalledVer, g.FixedVer)
}

// langRisk compares major versions of a language package. A higher fixed major
// means a possible breaking change (caution); same-or-lower major is treated as
// safe (patch/minor). Unparseable versions yield unknown rather than a guess.
func langRisk(installed, fixed string) Risk {
	im, ok1 := majorVersion(installed)
	fm, ok2 := majorVersion(fixed)
	if !ok1 || !ok2 {
		return RiskUnknown
	}
	if fm > im {
		return RiskCaution
	}
	return RiskSafe
}

// majorVersion extracts the leading integer (the semver major) from a version
// string, tolerating an optional leading "v". Returns false if absent.
func majorVersion(v string) (int, bool) {
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(v[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

// severityTier ranks a group by its worst level: 0 with a CRITICAL, 1 with a
// HIGH, 2 otherwise.
func severityTier(g PackageGroup) int {
	switch {
	case g.Critical > 0:
		return 0
	case g.High > 0:
		return 1
	}
	return 2
}

// sortPackages orders packages within an image: CRITICAL-bearing first, then
// HIGH-bearing, then the rest, then by total count desc, then package name. Two groups can now share a name
// (the aggregation key is PackageRef, not the name alone — the OS openssl
// and a Rust openssl crate, or two installed versions of the same package),
// so Ecosystem, then Version, then Class break the tie and make the order
// unique: a same-named, same-version OS/language pair with an unrecognized
// (empty) Type on both sides shares Ecosystem and Version too, and only
// Class still tells them apart.
func sortPackages(g []PackageGroup) {
	sort.Slice(g, func(i, j int) bool {
		if ti, tj := severityTier(g[i]), severityTier(g[j]); ti != tj {
			return ti < tj
		}
		if g[i].Total() != g[j].Total() {
			return g[i].Total() > g[j].Total()
		}
		if g[i].Package != g[j].Package {
			return g[i].Package < g[j].Package
		}
		if g[i].Ecosystem != g[j].Ecosystem {
			return g[i].Ecosystem < g[j].Ecosystem
		}
		if g[i].InstalledVer != g[j].InstalledVer {
			return g[i].InstalledVer < g[j].InstalledVer
		}
		return g[i].Class < g[j].Class
	})
}

// sortImages orders images within a section by CRITICAL count, then by
// whether they carry any HIGH, then total count, then image name, then EntityKey for stability (an Ambiguous
// reference can contribute more than one entry with the same Image). For
// Docker (config-kind digests only, Platform always zero) comparing EntityKey
// reduces to comparing digest hex, the same order comparing the old
// ContentID wire string produced (both share the constant "sha256:" prefix).
func sortImages(f []ImageFindings) {
	sort.Slice(f, func(i, j int) bool {
		ci, cj := f[i].CriticalCount(), f[j].CriticalCount()
		if ci != cj {
			return ci > cj
		}
		if hi, hj := f[i].Counts().High > 0, f[j].Counts().High > 0; hi != hj {
			return hi
		}
		ti, tj := f[i].TotalCount(), f[j].TotalCount()
		if ti != tj {
			return ti > tj
		}
		if f[i].Image != f[j].Image {
			return f[i].Image < f[j].Image
		}
		return lessEntityKey(f[i].Subject.Key, f[j].Subject.Key)
	})
}

// lessEntityKey orders two EntityKeys deterministically: Digest.Kind first
// (the zero value "" for an unresolved entity sorts before either resolved
// kind), then Hex, then Platform field by field.
func lessEntityKey(a, b inventory.EntityKey) bool {
	if a.Digest.Kind != b.Digest.Kind {
		return a.Digest.Kind < b.Digest.Kind
	}
	if a.Digest.Hex != b.Digest.Hex {
		return a.Digest.Hex < b.Digest.Hex
	}
	if a.Platform.OS != b.Platform.OS {
		return a.Platform.OS < b.Platform.OS
	}
	if a.Platform.Architecture != b.Platform.Architecture {
		return a.Platform.Architecture < b.Platform.Architecture
	}
	return a.Platform.Variant < b.Platform.Variant
}
