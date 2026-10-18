// Package state persists per-finding first-seen timestamps between scan cycles
// and computes the cycle-over-cycle diff that drives diff-mode notifications.
// Repeating an identical report every day trains the reader to ignore it; the
// diff surfaces what changed and ages what didn't.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// version guards the on-disk format. A mismatch is treated as no prior state
// (everything re-reported as new) rather than an error.
const version = 1

// Entry is the persisted memory of one finding (one package within one image,
// across all Trivy statuses).
//
// Priority was added later, for triage, without a version bump: state
// written before that addition simply decodes with an empty Priority, which
// suppresses escalation detection for one cycle instead of re-announcing
// every known finding as new.
//
// ContentID was added later, for a content-digest identity model, without a
// version bump, for the same reason: it is the single verified entity confirmed
// running under the entry's reference as of this cycle. It is left empty
// whenever that isn't a safe claim to make this cycle — the reference is
// Ambiguous (more than one distinct entity) or partially failed to scan (a
// sibling entity's success this cycle makes the stored identity stale) —
// rather than showing a possibly-stale identity as if it were current. A
// *full* scan failure is the
// existing untouched-carryover case (see Compute): the entry, ContentID
// included, is left exactly as it was, since no other entity's success this
// cycle could have made it misleading.
type Entry struct {
	FirstSeen time.Time `json:"first_seen"`
	Fixable   bool      `json:"fixable"` // any of the package's CVEs has a fix
	Priority  string    `json:"priority,omitempty"`
	VulnIDs   []string  `json:"vuln_ids"`
	ContentID string    `json:"content_id,omitempty"`
}

// EOLEntry is the persisted memory of one package's end-of-life findings
// (one package within one image), kept apart from Entry so that its changes,
// its age and its carry-over rules never mix with the package's ordinary
// findings. FirstSeen is when the package was first seen end-of-life, not
// when any of its CVEs first appeared.
type EOLEntry struct {
	FirstSeen time.Time `json:"first_seen"`
	Priority  string    `json:"priority,omitempty"` // strongest priority among the end-of-life CVEs
	VulnIDs   []string  `json:"vuln_ids"`           // the end-of-life CVE IDs, sorted
}

// ImageMeta is the persisted identity record for one reference. ContentIDs/
// Ambiguous are Docker-observed data (analyze.ImageObservation.ContentIDs
// survives a Trivy scan failure unchanged, chunk1), so Compute refreshes
// them every cycle regardless of scan outcome. LastSeen alone follows a
// stricter rule: only updated on a cycle where every entity under the
// reference scanned successfully; otherwise the last confirmed value carries
// over.
type ImageMeta struct {
	ContentIDs      []string  `json:"content_ids,omitempty"`
	RegistryDigests []string  `json:"registry_digests,omitempty"`
	Ambiguous       bool      `json:"ambiguous,omitempty"`
	LastSeen        time.Time `json:"last_seen"`
	// Workloads is the sorted set of workload keys (see WorkloadKey) that
	// ran this reference as of the last cycle. Added without a version bump:
	// older state decodes it empty, which only means no reference change can
	// be recognised for that reference.
	Workloads []string `json:"workloads,omitempty"`
}

// EnvironmentRecord is the persisted self-description of which environment a
// state file belongs to. It is purely descriptive: Compute and the diff
// rules never read it, so a rename never changes a key or an Entry value
// (docs/development/environment-workload-model.md).
type EnvironmentRecord struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// State is everything remembered between scan cycles.
//
// LastFullReport was added for the Slack thread report without a version
// bump: older state decodes with a nil ref, which simply forces one fresh
// full-report post.
//
// Images was added later, for a content-digest identity model, without a
// version bump: older state decodes with a nil map, and the first cycle on
// the new binary simply records the current identity information as a fresh
// baseline.
//
// Environment was added for the Environment/Workload model without a
// version bump, for the same reason as Images: older state decodes with a
// nil pointer, and Save simply starts recording the current value.
//
// EOLPackages was added for end-of-life package findings without a version
// bump: older state decodes with a nil map, the first cycle on the new
// binary announces every end-of-life package once, and a state with none is
// written byte-for-byte as before (omitempty drops the empty map).
type State struct {
	Version        int                  `json:"version"`
	Findings       map[string]Entry     `json:"findings"`               // keyed by image \t package
	EOSL           map[string]time.Time `json:"eosl"`                   // image -> first seen as EOL
	EOLPackages    map[string]EOLEntry  `json:"eol_packages,omitempty"` // keyed by image \t package, like Findings
	Images         map[string]ImageMeta `json:"images,omitempty"`       // keyed by reference
	LastFullReport *ReportRef           `json:"last_full_report,omitempty"`
	// Muted is the set of (image, package) keys currently muted under
	// runtime.mute_unfixable_not_in_use, added without a version bump the
	// same way EOLPackages was: older state decodes with a nil map, and the
	// first cycle on a binary with the setting on simply starts recording it
	// fresh. The unit is the whole key, never a single PackageGroup within
	// it: analyze.ApplyMuting only ever marks every group of a key
	// Muted when every one of them qualifies (a fixed or end-of-life
	// sibling, or any other disqualified group under the same key, blocks
	// the whole key), so "was this key muted last cycle" is a single,
	// unambiguous fact. Muting itself is judged fresh every cycle from
	// the current groups' own Runtime/Status/Priority — this map exists only
	// so Compute can notice a key that was muted last cycle no longer
	// being muted this cycle, the transition KindUnmuted reports.
	Muted map[string]bool `json:"muted,omitempty"`
	// Environment records which environment this file belongs to, for
	// self-description and diagnostics only. It is nil for the unnamed
	// default environment (FileStore.Env.Name == "") so that an unconfigured
	// user's state file stays byte-for-byte identical to the pre-Environment
	// format; a named environment gets it set on every Save.
	Environment *EnvironmentRecord `json:"environment,omitempty"`
}

// ReportRef locates the Slack message whose thread carries the most recent
// full open-findings report. Channel records the configured destination at
// post time: if notifications later move elsewhere, the permalink points at a
// thread the new channel's readers may not see, so the ref is treated as
// absent and the next cycle posts a fresh full report.
type ReportRef struct {
	Channel   string `json:"channel_id"`
	TS        string `json:"ts"`
	Permalink string `json:"permalink"`
}

// ValidFor reports whether the ref can serve as the "last full report" link
// for the given destination channel. Safe to call on a nil ref.
func (r *ReportRef) ValidFor(channel string) bool {
	return r != nil && r.TS != "" && r.Permalink != "" && r.Channel == channel
}

// empty returns a fresh, usable state.
func empty() State {
	return State{
		Version:     version,
		Findings:    map[string]Entry{},
		EOSL:        map[string]time.Time{},
		EOLPackages: map[string]EOLEntry{},
		Images:      map[string]ImageMeta{},
		Muted:       map[string]bool{},
	}
}

// key identifies a finding. Tab is not a valid character in image references or
// package names, so the compound key is unambiguous.
func key(image, pkg string) string { return image + "\t" + pkg }

func keyImage(k string) string {
	if i := strings.IndexByte(k, '\t'); i >= 0 {
		return k[:i]
	}
	return k
}

func keyPackage(k string) string {
	if i := strings.IndexByte(k, '\t'); i >= 0 {
		return k[i+1:]
	}
	return ""
}

// FirstSeen returns when the finding (image, pkg) was first observed. ok is
// false for findings this state has never recorded.
func (s State) FirstSeen(image, pkg string) (time.Time, bool) {
	e, ok := s.Findings[key(image, pkg)]
	return e.FirstSeen, ok
}

// EOLFirstSeen returns when the package (image, pkg) was first seen
// end-of-life. ok is false when this state has no end-of-life record for it.
func (s State) EOLFirstSeen(image, pkg string) (time.Time, bool) {
	e, ok := s.EOLPackages[key(image, pkg)]
	return e.FirstSeen, ok
}

// HasFindingsFor reports whether s has at least one recorded finding for
// ref, ordinary or end-of-life package. Read-only: it does not touch
// Compute, the key space, or the persisted format — a lookup helper for
// callers (the diff-mode send decision) that need to ask "did we have
// anything on record for this reference" without hand-rolling the key
// format themselves. A base-OS end-of-life record alone does not count.
func (s State) HasFindingsFor(ref string) bool {
	for k := range s.Findings {
		if keyImage(k) == ref {
			return true
		}
	}
	for k := range s.EOLPackages {
		if keyImage(k) == ref {
			return true
		}
	}
	return false
}

// FileStore persists State as a single JSON file, written atomically.
type FileStore struct {
	Path string
	// Env is the environment this store's state file belongs to. It is
	// stamped onto State.Environment on every Save (see Save) but never read
	// back by Load/Compute — the key space and diff rules do not depend on
	// it (docs/development/environment-workload-model.md).
	Env inventory.Environment
}

// Load reads the state file. A missing file or a version mismatch yields empty
// state and no error (first run / format change); only unreadable or corrupt
// data is an error, so the caller can decide to fall back rather than
// re-notify everything silently.
func (s FileStore) Load() (State, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return empty(), nil
	}
	if err != nil {
		return empty(), fmt.Errorf("read state %s: %w", s.Path, err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return empty(), fmt.Errorf("parse state %s: %w", s.Path, err)
	}
	if st.Version != version {
		return empty(), nil
	}
	if st.Findings == nil {
		st.Findings = map[string]Entry{}
	}
	if st.EOSL == nil {
		st.EOSL = map[string]time.Time{}
	}
	if st.EOLPackages == nil {
		st.EOLPackages = map[string]EOLEntry{}
	}
	if st.Images == nil {
		st.Images = map[string]ImageMeta{}
	}
	if st.Muted == nil {
		st.Muted = map[string]bool{}
	}
	return st, nil
}

// Save writes the state atomically (temp file + rename) so a crash mid-write
// never leaves a truncated file behind. The unnamed default environment
// (s.Env.Name == "") leaves st.Environment nil, so an unconfigured user's
// state file is written byte-for-byte identical to the pre-Environment
// format — omitempty then drops the field entirely rather than emitting it
// with an empty name.
func (s FileStore) Save(st State) error {
	if s.Env.Name != "" {
		st.Environment = &EnvironmentRecord{Name: s.Env.Name, Kind: string(s.Env.Kind)}
	} else {
		st.Environment = nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// ChangeKind classifies why a finding appears in the "new" section.
type ChangeKind string

const (
	KindNew        ChangeKind = "new"         // package not seen before
	KindEscalated  ChangeKind = "escalated"   // known package's priority rose (e.g. a CVE entered KEV)
	KindNewCVEs    ChangeKind = "new_cves"    // known package gained CVEs
	KindNowFixable ChangeKind = "now_fixable" // known package's fix became available
	// KindUnmuted marks a package that was muted under
	// runtime.mute_unfixable_not_in_use last cycle and no longer is this
	// cycle, for a reason no other Kind above already covers (it became
	// in use, or its observation window reset) — Compute only ever assigns
	// this when none of the other four Kinds fired, so a fallout that also
	// happens to be, say, now_fixable is reported as now_fixable instead of
	// duplicating the story.
	KindUnmuted ChangeKind = "unmuted"
)

// Change is one finding that is new or changed since the previous scan. Groups
// carries the package's current per-status groups (usually one; a package can
// have both fixed and unfixed CVEs).
type Change struct {
	Image   string
	Package string
	Kind    ChangeKind
	NewCVEs int      // for KindNewCVEs: how many CVE IDs are new (len(NewIDs); kept for webhook compatibility)
	NewIDs  []string // for KindNewCVEs: the new CVE IDs themselves, sorted (same order as analyze.PackageGroup.VulnIDs)
	Groups  []analyze.PackageGroup
	// EOLGroups is this key's end-of-life groups this cycle (Report.
	// EOLPackages), kept apart from Groups because end-of-life lives in its
	// own Report section and its own mergeSections pass, never merged into
	// the three ordinary ones. It exists so a KindUnmuted transition
	// caused by the package additionally becoming end-of-life — Fixable,
	// VulnIDs and Priority on the ordinary side can all stay exactly the
	// same — has somewhere to point notify's reason text at; nil whenever
	// the key has no end-of-life groups this cycle.
	EOLGroups []analyze.PackageGroup
}

// Resolved is a finding present in the previous scan but gone now: fixed,
// image updated, or the container no longer running.
type Resolved struct {
	Image   string
	Package string
}

// EOLChangeKind classifies a change to a package's end-of-life findings. It
// is a type of its own, not a ChangeKind: end-of-life changes are judged
// and reported independently of the package's ordinary changes.
type EOLChangeKind string

const (
	EOLKindNew       EOLChangeKind = "eol_new"       // package newly end-of-life (never recorded, or recorded again after it cleared)
	EOLKindNewCVEs   EOLChangeKind = "eol_new_cves"  // an end-of-life package gained end-of-life CVEs
	EOLKindEscalated EOLChangeKind = "eol_escalated" // an end-of-life package's priority rose to act_now
)

// EOLChange is one package whose end-of-life findings are new or changed
// since the previous scan. Groups holds only the package's end_of_life
// groups.
type EOLChange struct {
	Image   string
	Package string
	Kind    EOLChangeKind
	NewIDs  []string // for EOLKindNewCVEs: the new end-of-life CVE IDs, sorted
	Groups  []analyze.PackageGroup
}

// ResolvedEOL is a package that was end-of-life in the previous scan and no
// longer is. StillOpen is true when the package still has ordinary findings
// this scan (its CVEs left end-of-life but not the report).
type ResolvedEOL struct {
	Image     string
	Package   string
	StillOpen bool
}

// ImageReplacement is one reference whose running content changed between
// scans. It fires only when both the previous and current verified
// ContentID sets are non-empty and differ as sets — never on first
// observation (an empty-to-non-empty transition is the identity model
// recording data for the first time, not a replacement). Detection does not
// depend on scan success: ContentIDs is
// Docker-observed and survives a Trivy scan failure unchanged (see
// replacedImages), so a genuine replacement is still reported even if the new
// content's own scan failed.
type ImageReplacement struct {
	Ref            string
	PrevContentIDs []string
	ContentIDs     []string
}

// Diff is what changed between the previous scan and the current report, plus
// the ambient "still open" summary used for the heartbeat line.
type Diff struct {
	NewEOSL      []string
	ResolvedEOSL []string
	Changes      []Change
	Resolved     []Resolved
	Replaced     []ImageReplacement
	// RefChanges lists the references whose history was carried over to a
	// new reference of the same repository (see RefChange).
	RefChanges []RefChange

	OpenCritical int
	OpenHigh     int
	// OpenSevMedium, OpenSevLow and OpenSevUnknown count CVEs by severity
	// level (unlike OpenLow, the triage "low" package count) and are
	// non-zero only when scan.severity selects those levels.
	OpenSevMedium  int
	OpenSevLow     int
	OpenSevUnknown int
	OpenImages     int
	OldestOpen     time.Time // zero when nothing is open

	// Triage breakdown (zero when triage is off). Counts are package groups,
	// the unit shown to the user. OldestUrgent ages only act_now/watch (and
	// EOSL) findings: an old "low" is the triage working as designed, not debt.
	OpenActNow   int
	OpenWatch    int
	OpenLow      int
	OldestUrgent time.Time

	// End-of-life packages, judged apart from Changes/Resolved.
	NewEOLPackages      []EOLChange
	ResolvedEOLPackages []ResolvedEOL
	// OpenEOSL is every reference whose base OS is recorded end-of-life after
	// this cycle, held records included (the keys of the next State.EOSL,
	// sorted). State-derived views fold end-of-life packages into the base-OS
	// line by this set, so the base-OS count and the fold always agree.
	OpenEOSL []string
	// OpenEOLPackages counts the end-of-life package records not folded into
	// a base-OS line (OpenEOSL), whatever their priority.
	OpenEOLPackages int
	// AnyOpen is true when the next state still holds anything — ordinary
	// findings, end-of-life packages or base-OS records, held ones included.
	AnyOpen bool
}

// HasChanges reports whether anything is new or resolved since the last scan.
func (d Diff) HasChanges() bool {
	return len(d.Changes) > 0 || len(d.Resolved) > 0 || len(d.NewEOSL) > 0 || len(d.ResolvedEOSL) > 0 || len(d.Replaced) > 0 || len(d.RefChanges) > 0 ||
		len(d.NewEOLPackages) > 0 || len(d.ResolvedEOLPackages) > 0
}

// OldestOpenDays is the age in whole days of the oldest open finding at now,
// 0 when nothing is open or everything was first seen today.
func (d Diff) OldestOpenDays(now time.Time) int { return wholeDays(d.OldestOpen, now) }

// OldestUrgentDays is the age in whole days of the oldest open act_now/watch
// (or EOSL) finding at now.
func (d Diff) OldestUrgentDays(now time.Time) int { return wholeDays(d.OldestUrgent, now) }

func wholeDays(t, now time.Time) int {
	if t.IsZero() {
		return 0
	}
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// current is the merged view of one finding across the report's sections.
type current struct {
	groups  []analyze.PackageGroup
	ids     map[string]bool
	fixable bool
}

// Compute diffs the report against the previous state and returns the diff and
// the next state to persist. Findings of images whose scan failed this cycle
// are carried over untouched — a transient pull failure must not report every
// known finding as resolved and re-announce it tomorrow.
//
// Report.Images (the identity inventory) is the sole source for two things:
// updating State.Images, and classifying each reference as fully failed
// (every entity failed to scan; existing behavior, carry findings over
// untouched and suppress Resolved), partially failed (some but not all
// entities failed; carry over the findings only the failed entity
// contributed, and conservatively merge the findings both contributed, so a
// sibling entity's temporary scan failure can never look like "fixed" or
// "gone" and then reappear as new/escalated once it recovers), or fully
// resolved (ordinary diffing, unaffected).
//
// End-of-life package findings (Report.EOLPackages) live in their own map,
// State.EOLPackages, and produce their own changes (NewEOLPackages,
// ResolvedEOLPackages) under the same carry-over rules. The two sides touch
// in three places only: an ordinary judgement counts the package's previous
// end-of-life record as history, a package whose ordinary findings all moved
// to end-of-life is not reported resolved, and the heartbeat counts each
// package once.
func Compute(prev State, r analyze.Report) (Diff, State) {
	// A workload that moved to another reference of the same repository keeps
	// its history: prev is rewritten before anything else reads it, so the
	// rest of Compute sees an ordinary unchanged reference.
	prev, refChanges := carryOverRefChanges(prev, r.Images)
	next := empty()
	now := r.GeneratedAt

	// refContentID holds, for each reference, the single verified ContentID
	// safe to publish as "the" entity running there this cycle: every entity
	// under the reference had a Docker-observed ContentID this cycle
	// (IdentityResolved — independent of scan success), there is exactly one
	// distinct value among them (not Ambiguous), and the reference did not
	// (partially) fail to scan. Every other case — Ambiguous, a mix of
	// resolved and reference-fallback entities, or a (partial) scan failure —
	// is deliberately left absent.
	refContentID := map[string]string{}
	fullyFailedRef := map[string]bool{}
	partiallyFailedRef := map[string]bool{}
	for _, o := range r.Images {
		if o.ScanFailed {
			fullyFailedRef[o.Ref] = true
		}
		if o.PartialFailure {
			partiallyFailedRef[o.Ref] = true
		}
		if o.IdentityResolved && !o.Ambiguous && !o.ScanFailed && !o.PartialFailure && len(o.ContentIDs) == 1 {
			refContentID[o.Ref] = o.ContentIDs[0]
		}
	}
	next.Images = nextImages(prev.Images, r.Images, now)
	d := Diff{Replaced: replacedImages(prev.Images, r.Images), RefChanges: refChanges}

	// Report order: sections are already priority-sorted.
	cur, order := mergeSections(r.Actionable, r.Watch, r.WontFix)
	curEOL, eolOrder := mergeSections(r.EOLPackages)
	// heldKey marks every key whose stored Findings entry this cycle carries
	// (fully or partially) a held contribution rather than a fresh judgment
	// — set both by the main loop below (partial failure with a live
	// sibling) and by the full/partial carry-over loop further down (no
	// live sibling at all). The "open now" heartbeat and OldestUrgent must
	// never exclude a held key's contribution just because its Muted flag
	// happens to still read true from before: that flag was carried over
	// unchanged, not re-judged, so a held act_now can never quietly
	// disappear from the count.
	heldKey := map[string]bool{}

	for _, k := range order {
		ref := keyImage(k)
		c := cur[k]
		ids := sortedIDs(c.ids)

		// The package's previous end-of-life record counts as history for
		// the ordinary judgement: a CVE that leaves end-of-life for the
		// ordinary sections is not new, and the package is not new either.
		prevE, knownE := prev.Findings[k]
		prevEOL, knownEOL := prev.EOLPackages[k]
		known := knownE || knownEOL
		firstSeen := now
		switch {
		case knownE:
			firstSeen = prevE.FirstSeen
		case knownEOL:
			firstSeen = prevEOL.FirstSeen
		}
		baseIDs := prevE.VulnIDs
		if knownEOL {
			baseIDs = mergeSorted(prevE.VulnIDs, prevEOL.VulnIDs)
		}
		basePrio := analyze.Priority(prevE.Priority)
		if p := analyze.Priority(prevEOL.Priority); p.Rank() > basePrio.Rank() {
			basePrio = p
		}
		prio := analyze.MaxPriority(c.groups)

		// Conservative merge: a partially-failed reference's cur view only
		// reflects the entities that scanned successfully this cycle, so what
		// gets persisted must not regress below what a sibling entity
		// contributed last time it succeeded: VulnIDs is the union of prev and
		// cur, Fixable is prev||cur, and Priority is whichever is higher.
		storeIDs, storeFixable, storePrio := ids, c.fixable, prio
		if partiallyFailedRef[ref] && knownE {
			storeIDs = mergeSorted(ids, prevE.VulnIDs)
			storeFixable = storeFixable || prevE.Fixable
			if prevPrio := analyze.Priority(prevE.Priority); prevPrio.Rank() > storePrio.Rank() {
				storePrio = prevPrio
			}
		}
		next.Findings[k] = Entry{
			FirstSeen: firstSeen, Fixable: storeFixable, Priority: string(storePrio),
			VulnIDs: storeIDs, ContentID: refContentID[ref],
		}

		change := Change{Image: ref, Package: keyPackage(k), Groups: c.groups}
		if eolC := curEOL[k]; eolC != nil {
			change.EOLGroups = eolC.groups
		}
		added := newIDs(ids, baseIDs)

		var kind ChangeKind
		switch {
		case !known:
			kind = KindNew
		// Escalation outranks the other kinds: "this got urgent" is the news,
		// whatever caused it. An empty stored priority (state written before
		// the triage upgrade, or triage previously off) never escalates —
		// there is no baseline to have risen from. Degraded intel suppresses
		// escalations too: severity-only fallback inflates every priority, and
		// announcing that en masse would turn a feed outage into a false alarm
		// storm (the header warning carries the news instead).
		case !r.Intel.Degraded() && basePrio != analyze.PriorityNone && prio.Rank() > basePrio.Rank():
			kind = KindEscalated
		case len(added) > 0:
			kind = KindNewCVEs
		case c.fixable && !prevE.Fixable:
			kind = KindNowFixable
		}

		// Muting never removes a Change from the diff — the generic
		// webhook needs the full record, and even a muted key's row is
		// only ever hidden by notify's rendering, not by Compute. What
		// muting does affect: whether this key is recorded into
		// State.Muted, and whether it just lost that status.
		//
		// held is true exactly when this key's stored Priority/Fixable/
		// VulnIDs above were merged with (rather than freshly replacing)
		// last cycle's record — a scan failure is never evidence that a
		// finding stopped being muted, so the key's muted flag is
		// carried over unchanged in that case, the same as every other held
		// field on this Entry, and no unmuted notice can fire from
		// data this cycle never actually re-judged.
		held := partiallyFailedRef[ref] && knownE
		if held {
			heldKey[k] = true
		}
		wasMuted := prev.Muted[k]
		mutedNow := wasMuted
		if !held {
			mutedNow = allMuted(c.groups)
		}
		if mutedNow {
			next.Muted[k] = true
		}
		becameUnmuted := wasMuted && !held && !mutedNow

		switch {
		case kind != "":
			change.Kind = kind
		case becameUnmuted:
			// No ordinary Kind fired (same CVEs, same fix status, same
			// priority), so this is the only news: the key no longer
			// qualifies for muting — some group under it is now in use,
			// act_now, fixed, or otherwise no longer eligible. A fallout
			// that also happens to be, say, now_fixable took the case above
			// instead, reusing that more specific label rather than
			// duplicating it.
			change.Kind = KindUnmuted
		default:
			continue // unchanged
		}
		if change.Kind == KindNewCVEs {
			change.NewIDs = added
			change.NewCVEs = len(added)
		}
		d.Changes = append(d.Changes, change)
	}

	for k, e := range prev.Findings {
		if _, ok := cur[k]; ok {
			continue
		}
		ref := keyImage(k)
		switch {
		case fullyFailedRef[ref]:
			// Existing full-failure behavior: carry the entry over exactly as
			// it was, ContentID included — there is no sibling entity whose
			// success could make a stale ContentID misleading here.
			next.Findings[k] = e
			carryMuted(next.Muted, prev.Muted, k)
			heldKey[k] = true
			continue
		case partiallyFailedRef[ref]:
			// This finding belonged to the one entity that failed to scan
			// this cycle while a sibling under the same ref succeeded. Carry
			// it over unknown-but-not-resolved, and blank ContentID — unlike
			// the full-failure case, a sibling's success this cycle makes it
			// misleading to keep asserting an old identity as current.
			// This holds even when a sibling now shows the same package as
			// end-of-life: that says nothing about the failed entity's own
			// findings.
			e.ContentID = ""
			next.Findings[k] = e
			carryMuted(next.Muted, prev.Muted, k)
			heldKey[k] = true
			continue
		case curEOL[k] != nil:
			// Every CVE left for end-of-life: the package is not resolved,
			// its end-of-life change announces it instead.
			continue
		}
		d.Resolved = append(d.Resolved, Resolved{Image: ref, Package: keyPackage(k)})
	}
	sort.Slice(d.Resolved, func(i, j int) bool {
		if d.Resolved[i].Image != d.Resolved[j].Image {
			return d.Resolved[i].Image < d.Resolved[j].Image
		}
		return d.Resolved[i].Package < d.Resolved[j].Package
	})

	d.NewEOLPackages = computeEOL(prev, next, curEOL, eolOrder, partiallyFailedRef, r.Intel.Degraded(), now)
	for k, e := range prev.EOLPackages {
		if _, ok := curEOL[k]; ok {
			continue
		}
		ref := keyImage(k)
		// Same carry-over as ordinary findings and EOSL: a reference that
		// (partially) failed to scan this cycle is no evidence the package
		// stopped being end-of-life.
		if fullyFailedRef[ref] || partiallyFailedRef[ref] {
			next.EOLPackages[k] = e
			continue
		}
		d.ResolvedEOLPackages = append(d.ResolvedEOLPackages, ResolvedEOL{Image: ref, Package: keyPackage(k), StillOpen: cur[k] != nil})
	}
	sort.Slice(d.ResolvedEOLPackages, func(i, j int) bool {
		if d.ResolvedEOLPackages[i].Image != d.ResolvedEOLPackages[j].Image {
			return d.ResolvedEOLPackages[i].Image < d.ResolvedEOLPackages[j].Image
		}
		return d.ResolvedEOLPackages[i].Package < d.ResolvedEOLPackages[j].Package
	})

	for _, img := range r.EOSLImages {
		firstSeen, known := prev.EOSL[img]
		if !known {
			firstSeen = now
			d.NewEOSL = append(d.NewEOSL, img)
		}
		next.EOSL[img] = firstSeen
	}
	for img := range prev.EOSL {
		if _, ok := next.EOSL[img]; ok {
			continue
		}
		// Same conservative carryover as findings: a reference that lost its
		// only EOSL-reporting entity to a (partial) scan failure this cycle
		// must not look like the base image got un-EOL'd.
		if fullyFailedRef[img] || partiallyFailedRef[img] {
			next.EOSL[img] = prev.EOSL[img]
			continue
		}
		d.ResolvedEOSL = append(d.ResolvedEOSL, img)
	}
	sort.Strings(d.ResolvedEOSL)

	d.OpenImages = r.AffectedImageCount()
	for img := range next.EOSL {
		d.OpenEOSL = append(d.OpenEOSL, img)
	}
	sort.Strings(d.OpenEOSL)
	folded := map[string]bool{}
	for _, img := range d.OpenEOSL {
		folded[img] = true
	}
	older := func(cur *time.Time, t time.Time) {
		if cur.IsZero() || t.Before(*cur) {
			*cur = t
		}
	}

	// Priority buckets count each (image, package) once: act_now on either
	// side wins; otherwise the ordinary side's priority counts. An
	// end-of-life record's watch/low is represented by the end-of-life
	// segment (OpenEOLPackages) alone, so it never adds a second bucket. A
	// key excluded here (next.Muted[k] true and not heldKey) never
	// contributes its own bucket or ages the "oldest urgent" heartbeat —
	// that heartbeat exists to nag about work still needing a decision, and
	// a muted key is exactly the opposite of that by construction (never
	// act_now, so eolActNow alone can still count it here, unaffected). A
	// heldKey key is never excluded even if its Muted flag still reads
	// true, since that flag was carried over unchanged rather than
	// re-judged this cycle — a held act_now can never disappear from this
	// count just because its muted flag happens to predate the failure.
	// OldestOpen is deliberately left unfiltered: it also backs the generic
	// webhook's oldest_open_days, which stays a raw, unabridged figure.
	for k, e := range next.Findings {
		muted := next.Muted[k] && !heldKey[k]
		older(&d.OldestOpen, e.FirstSeen)
		if urgent(e.Priority) && !muted {
			older(&d.OldestUrgent, e.FirstSeen)
		}
		eolActNow := analyze.Priority(next.EOLPackages[k].Priority) == analyze.PriorityActNow
		switch {
		case (analyze.Priority(e.Priority) == analyze.PriorityActNow && !muted) || eolActNow:
			d.OpenActNow++
		case analyze.Priority(e.Priority) == analyze.PriorityWatch && !muted:
			d.OpenWatch++
		case analyze.Priority(e.Priority) == analyze.PriorityLow && !muted:
			d.OpenLow++
		}
	}
	for k, e := range next.EOLPackages {
		actNow := analyze.Priority(e.Priority) == analyze.PriorityActNow
		if !folded[keyImage(k)] {
			d.OpenEOLPackages++
		}
		if _, ok := next.Findings[k]; !ok && actNow {
			d.OpenActNow++
		}
		// A folded record ages through its base-OS record instead, unless
		// it is act_now and so shown on its own.
		if !folded[keyImage(k)] || actNow {
			older(&d.OldestOpen, e.FirstSeen)
			older(&d.OldestUrgent, e.FirstSeen)
		}
	}
	for _, t := range next.EOSL {
		older(&d.OldestOpen, t)
		older(&d.OldestUrgent, t)
	}
	d.AnyOpen = len(next.Findings) > 0 || len(next.EOLPackages) > 0 || len(next.EOSL) > 0
	// Summed per group rather than via img.CriticalCount()/TotalCount() so a
	// muted group's CVEs can be left out — otherwise the triage-off
	// heartbeat's CRITICAL/HIGH total would count vulnerabilities from rows
	// the body never shows. Mathematically identical to the whole-image sum
	// whenever nothing is muted.
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				if g.Muted {
					continue
				}
				d.OpenCritical += g.Critical
				d.OpenHigh += g.High
				d.OpenSevMedium += g.Medium
				d.OpenSevLow += g.Low
				d.OpenSevUnknown += g.Unknown
			}
		}
	}
	return d, next
}

// mergeSections merges report section entries into one view per
// (image, package), in report order.
func mergeSections(sections ...[]analyze.ImageFindings) (map[string]*current, []string) {
	cur := map[string]*current{}
	var order []string
	for _, section := range sections {
		for _, img := range section {
			for _, g := range img.Packages {
				k := key(img.Image, g.Package)
				c := cur[k]
				if c == nil {
					c = &current{ids: map[string]bool{}}
					cur[k] = c
					order = append(order, k)
				}
				c.groups = append(c.groups, g)
				for _, id := range g.VulnIDs() {
					c.ids[id] = true
				}
				if g.Status == scanner.StatusFixed {
					c.fixable = true
				}
			}
		}
	}
	return cur, order
}

// computeEOL records this cycle's end-of-life packages in next and returns
// their changes. The previous ordinary entry is deliberately not consulted:
// a CVE moving from the ordinary sections into end-of-life is news for the
// end-of-life view even when the package itself is long known.
func computeEOL(prev, next State, curEOL map[string]*current, order []string, partiallyFailedRef map[string]bool, degraded bool, now time.Time) []EOLChange {
	var changes []EOLChange
	for _, k := range order {
		ref := keyImage(k)
		c := curEOL[k]
		ids := sortedIDs(c.ids)
		prio := analyze.MaxPriority(c.groups)

		prevL, known := prev.EOLPackages[k]
		firstSeen := now
		if known {
			firstSeen = prevL.FirstSeen
		}
		// Same conservative merge as ordinary entries: a partially-failed
		// reference keeps what the failed entity contributed last time.
		storeIDs, storePrio := ids, prio
		if partiallyFailedRef[ref] && known {
			storeIDs = mergeSorted(ids, prevL.VulnIDs)
			if p := analyze.Priority(prevL.Priority); p.Rank() > storePrio.Rank() {
				storePrio = p
			}
		}
		next.EOLPackages[k] = EOLEntry{FirstSeen: firstSeen, Priority: string(storePrio), VulnIDs: storeIDs}

		change := EOLChange{Image: ref, Package: keyPackage(k), Groups: c.groups}
		added := newIDs(ids, prevL.VulnIDs)
		prevPrio := analyze.Priority(prevL.Priority)
		switch {
		case !known:
			change.Kind = EOLKindNew
		// Only a rise to act_now is announced, under the same conditions as
		// an ordinary escalation (a baseline exists, intel is not degraded).
		case !degraded && prevPrio != analyze.PriorityNone && prio == analyze.PriorityActNow && prio.Rank() > prevPrio.Rank():
			change.Kind = EOLKindEscalated
		case len(added) > 0:
			change.Kind = EOLKindNewCVEs
			change.NewIDs = added
		default:
			continue
		}
		changes = append(changes, change)
	}
	return changes
}

// carryMuted preserves a key's muted flag across a cycle where no
// entity contributing to it was observed at all (full or partial reference
// failure with no successful sibling for this specific package): a scan
// failure is never evidence that a finding stopped being muted, so the
// same holding rule already applied to Findings/EOSL/EOLPackages applies
// here too.
func carryMuted(next, prev map[string]bool, k string) {
	if prev[k] {
		next[k] = true
	}
}

// allMuted reports whether every one of groups is Muted (analyze.
// PackageGroup.Muted). analyze.ApplyMuting only ever sets Muted on
// every group of a key when every one of them individually qualifies (a
// fixed or end-of-life sibling, or any other disqualified group under the
// same key, blocks the whole key — see its own doc comment), so this is
// equivalent to asking whether the key itself, as observed this cycle, is
// muted. Always false when groups is empty, or when
// runtime.mute_unfixable_not_in_use is off (Muted is then always false
// on every group).
func allMuted(groups []analyze.PackageGroup) bool {
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !g.Muted {
			return false
		}
	}
	return true
}

// sortedIDs returns the members of an ID set, sorted.
func sortedIDs(set map[string]bool) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// nextImages builds State.Images for the next cycle from this cycle's
// identity inventory. ContentIDs/Ambiguous are Docker-observed data
// (analyze.ImageObservation.ContentIDs survives a Trivy scan failure
// unchanged, chunk1) and so are refreshed every cycle regardless of scan
// outcome. RegistryDigests only ever comes from a successful, resolved scan's
// Trivy Metadata (analyze.Build already only populates it from those), so a
// cycle with no such scan for a reference correctly records none rather than
// keeping a possibly-stale digest from a different entity. LastSeen alone
// follows a stricter rule: updated only when every entity under the
// reference scanned successfully this cycle; otherwise the last confirmed
// value carries over.
func nextImages(prevImages map[string]ImageMeta, obs []analyze.ImageObservation, now time.Time) map[string]ImageMeta {
	next := map[string]ImageMeta{}
	for _, o := range obs {
		meta := ImageMeta{ContentIDs: o.ContentIDs, RegistryDigests: o.RegistryDigests, Ambiguous: o.Ambiguous, Workloads: workloadKeys(o.Containers)}
		if !o.ScanFailed && !o.PartialFailure {
			meta.LastSeen = now
		} else if prevMeta, ok := prevImages[o.Ref]; ok {
			meta.LastSeen = prevMeta.LastSeen
		}
		next[o.Ref] = meta
	}
	return next
}

// replacedImages detects image-replacement events: a reference whose
// verified ContentID set is non-empty both last cycle and this cycle, and
// differs between the two. ContentIDs is Docker-observed and independent of
// scan success (see nextImages), so this comparison is not gated on
// ScanFailed/PartialFailure — the set is accurate either way.
func replacedImages(prevImages map[string]ImageMeta, obs []analyze.ImageObservation) []ImageReplacement {
	var out []ImageReplacement
	for _, o := range obs {
		prevMeta, known := prevImages[o.Ref]
		if !known || len(prevMeta.ContentIDs) == 0 || len(o.ContentIDs) == 0 {
			continue // migration-initial (or never-resolved) on either side: never fires
		}
		if !equalStrings(prevMeta.ContentIDs, o.ContentIDs) {
			out = append(out, ImageReplacement{Ref: o.Ref, PrevContentIDs: prevMeta.ContentIDs, ContentIDs: o.ContentIDs})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// equalStrings reports whether two already-sorted string slices hold the same
// set of values.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mergeSorted returns the sorted union of two ID sets.
func mergeSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, id := range a {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range b {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// urgent reports whether a stored priority counts toward the heartbeat's
// staleness escalation.
func urgent(p string) bool {
	pr := analyze.Priority(p)
	return pr == analyze.PriorityActNow || pr == analyze.PriorityWatch
}

// newIDs returns the ids not present in prev, in ids' own order (the caller
// passes ids already sorted, so the result comes back sorted too).
func newIDs(ids, prev []string) []string {
	seen := map[string]bool{}
	for _, id := range prev {
		seen[id] = true
	}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			out = append(out, id)
		}
	}
	return out
}
