// Package notify formats an analyze.Report and delivers it to Slack and/or a
// generic webhook. Formatting (pure) is kept separate from delivery (HTTP) so
// the message content is unit-testable without a network.
package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

const timeLayout = "2006-01-02 15:04"

// collapsePreview caps how many package names are listed when the lower-risk
// fixes are collapsed into a single summary line.
const collapsePreview = 5

// staleDays is the age at which the "still open" heartbeat escalates: after
// this many days an unresolved finding stops being news and starts being debt.
const staleDays = 14

// openNowEOLBaseWithoutTriage decides whether the triage-off "Open now"
// heartbeat leads with the "⛔ N EOL base" segment, as the triage heartbeat
// always has. The end-of-life package segment is shown in both modes
// regardless; this switch only covers the base-OS segment.
const openNowEOLBaseWithoutTriage = true

// joinShortDigests renders a ContentID set as short, comma-joined digests for
// display. The sets themselves (state.ImageReplacement's Prev/ContentIDs) are
// already sorted upstream, so this only shortens each value — it never
// reorders.
// refTagLabel is how a reference is named after its repository in a reference
// change line: the tag, else the short digest of a digest-pinned reference,
// else "latest" (a reference with neither names the default tag).
func refTagLabel(ref string) string {
	if tag := inventory.TagOf(ref); tag != "" {
		return tag
	}
	if d := inventory.DigestOf(ref); d != "" {
		return shortDigest(d)
	}
	return "latest"
}

func joinShortDigests(ids []string) string {
	short := make([]string, len(ids))
	for i, id := range ids {
		short[i] = shortDigest(id)
	}
	return strings.Join(short, ", ")
}

// shortDigest is the display form of a content digest across the notify
// layer: the "sha256:" prefix stripped, then the leading 12 hex characters
// — a single rule shared by the Replaced lines and the ambiguous-reference
// heading annotation below.
func shortDigest(contentID string) string {
	hex := strings.TrimPrefix(contentID, "sha256:")
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// imagesByRef indexes the report's identity inventory by reference, serving
// two different kinds of lookup that must not be confused:
//   - Per-entity renderers with an analyze.ImageFindings in hand (imageLabel,
//     imagePayloads) use it only for the reference's aggregate Ambiguous
//     status and RegistryDigests — never for IdentityResolved, since that
//     aggregate would misreport a pinned entity as unresolved whenever a
//     sibling under the same reference fell back to scanning by reference.
//     Per-entity resolution is ImageFindings.Pinned's own job.
//   - Reference-only renderers with nothing but a bare ref string (refLabel:
//     diff/EOSL/scan-error lines that are reference-keyed by design) have no
//     per-entity ContentID to fall back on, so the reference's aggregate
//     IdentityResolved — "did every entity under this ref resolve this
//     cycle" — is the coarsest signal available and the correct one to use
//     there.
//
// Ambiguous is also computed report-wide here rather than re-derived from the
// status sections, which — split across Actionable/Watch/WontFix — could miss
// a sibling entity landing in a different bucket.
func imagesByRef(r analyze.Report) map[string]analyze.ImageObservation {
	out := make(map[string]analyze.ImageObservation, len(r.Images))
	for _, o := range r.Images {
		out[o.Ref] = o
	}
	return out
}

// imageLabel is the display name for one ImageFindings entry, annotated per
// the identity model: not pinned this cycle (a reference-fallback scan, or a
// resolved entity this cycle failed to confirm) gets an explicit warning
// that the entity actually running there was never confirmed;
// pinned-but-ambiguous (more than one distinct entity currently running
// under the same reference) gets the short digest appended so the
// per-entity sections can be told apart — a registry-kind digest also
// carries its platform, since unlike a config digest it doesn't pin one on
// its own. The ordinary single-entity case (the vast majority) renders
// exactly as before.
func imageLabel(img analyze.ImageFindings, byRef map[string]analyze.ImageObservation, msg messages) string {
	switch {
	case !img.Pinned:
		return img.Image + " — " + msg.IdentityUnconfirmed
	case byRef[img.Image].Ambiguous:
		digest := shortDigest(img.Subject.Key.Digest.String())
		if img.Subject.Key.Digest.Kind == inventory.DigestRegistry {
			digest += " " + platformString(img.Subject.Key.Platform)
		}
		return img.Image + " (" + digest + ")"
	default:
		return img.Image
	}
}

// platformString renders an inventory.Platform for display, e.g.
// "linux/amd64" or "linux/arm/v7" when Variant is set.
func platformString(p inventory.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// refLabel is the reference-level counterpart of imageLabel, for renderers
// that only ever have a bare reference string — not an analyze.ImageFindings
// entry with its own ContentID — because they sit downstream of the
// reference-keyed diff history or the per-reference EOSL/scan-error lists
// (state.Change.Image, state.Resolved.Image, analyze.ScanError.Image, an EOSL
// image name: diff history stays reference-keyed on purpose, so per-entity
// ContentID is not available to restore here). It appends the same warning
// whenever the reference's identity inventory (analyze.Report.Images, looked
// up by ref) says at least one entity running under it was unresolved this
// cycle. Unlike imageLabel it never appends a short digest for an Ambiguous
// reference: a diff/EOSL/error line is already a union across every entity
// running under the reference, so there is no single content id to show. A
// reference absent from byRef — not scanned this cycle, e.g. a Resolved/gone
// image — is left unannotated: no data is not the same claim as
// "unconfirmed".
func refLabel(ref string, byRef map[string]analyze.ImageObservation, msg messages) string {
	if obs, ok := byRef[ref]; ok && !obs.IdentityResolved {
		return ref + " — " + msg.IdentityUnconfirmed
	}
	return ref
}

// unresolvedRefsLine is the cross-cutting summary of every reference with an
// unresolved entity this cycle, each reference escaped.
func unresolvedRefsLine(r analyze.Report, msg messages) string {
	var refs []string
	for _, o := range r.Images {
		if !o.IdentityResolved {
			refs = append(refs, o.Ref)
		}
	}
	if len(refs) == 0 {
		return ""
	}
	sort.Strings(refs)
	for i := range refs {
		refs[i] = escMrkdwn(refs[i])
	}
	return fmt.Sprintf(msg.UnresolvedRefsLine, msg.IdentityUnconfirmed, strings.Join(refs, ", "))
}

// unconfirmedRefsLine is the summary of every reference whose previous
// findings are being held, each reference escaped.
func unconfirmedRefsLine(r analyze.Report, msg messages) string {
	if len(r.UnconfirmedRefs) == 0 {
		return ""
	}
	refs := make([]string, len(r.UnconfirmedRefs))
	for i, ref := range r.UnconfirmedRefs {
		refs[i] = escMrkdwn(ref)
	}
	return fmt.Sprintf(msg.UnconfirmedRefsLine, strings.Join(refs, ", "))
}

// runtimeUncheckedLine is the note that a language runtime of some images was
// not checked ("" when every one was). It names the runtimes, sorted, and
// counts the distinct images.
func runtimeUncheckedLine(r analyze.Report, msg messages) string {
	if len(r.RuntimeUnchecked) == 0 {
		return ""
	}
	images := map[string]bool{}
	seen := map[string]bool{}
	var names []string
	for _, u := range r.RuntimeUnchecked {
		images[u.Image] = true
		if !seen[u.Package] {
			seen[u.Package] = true
			names = append(names, u.Package)
		}
	}
	sort.Strings(names)
	return fmt.Sprintf(msg.RuntimeUncheckedLine, strings.Join(names, msg.RuntimeNameSeparator), len(images))
}

// runtimeUncheckedPayload is one entry of the webhook's runtime_unchecked.
type runtimeUncheckedPayload struct {
	Image   string `json:"image"`
	Package string `json:"package"`
}

// runtimeUncheckedPayloads converts the report's pairs (nil when none, so the
// field is omitted).
func runtimeUncheckedPayloads(refs []analyze.RuntimeUncheckedRef) []runtimeUncheckedPayload {
	if len(refs) == 0 {
		return nil
	}
	out := make([]runtimeUncheckedPayload, len(refs))
	for i, u := range refs {
		out[i] = runtimeUncheckedPayload{Image: u.Image, Package: u.Package}
	}
	return out
}

// visibleChange pairs a state.Change with the subset of its Groups notify
// actually renders a row for.
type visibleChange struct {
	change state.Change
	groups []analyze.PackageGroup
}

// visibleChanges filters changes down to the ones with at least one
// non-Muted group, and each one's Groups down to that subset: Compute
// never drops a muted key's Change from the diff (the generic webhook
// needs the full record, and Kind/priority are never touched by
// muting), so notify is where the row itself is hidden instead — the
// same policy filterMuted already applies to the status-section views.
// analyze.ApplyMuting only ever marks every group of a key Muted
// together, so in practice a Change's Groups are either all Muted or
// none are; filtering per group here is just the defensive form of that. A
// Change left with no visible groups at all is dropped entirely: no image
// heading line, and no count in the header above it. Order is preserved.
func visibleChanges(changes []state.Change) []visibleChange {
	var out []visibleChange
	for _, c := range changes {
		var groups []analyze.PackageGroup
		for _, g := range c.Groups {
			if !g.Muted {
				groups = append(groups, g)
			}
		}
		if len(groups) > 0 {
			out = append(out, visibleChange{change: c, groups: groups})
		}
	}
	return out
}

// groupNewIDs narrows a change's new CVE ids to the ones this group carries.
// A package can render as two groups (fixed and unfixed CVEs), and a new id
// belongs to exactly one of them: listing it under the other would claim a
// fix version covers a CVE it does not.
func groupNewIDs(c state.Change, g analyze.PackageGroup) []string {
	if len(c.NewIDs) == 0 {
		return nil
	}
	in := make(map[string]bool, len(g.Vulns))
	for _, v := range g.Vulns {
		in[v.ID] = true
	}
	var ids []string
	for _, id := range c.NewIDs {
		if in[id] {
			ids = append(ids, id)
		}
	}
	return ids
}

// newIDsMax caps how many new CVE ids are listed in a new_cves change suffix
// before falling back to a "(+N more)" count (the full list is always in the
// webhook payload).
const newIDsMax = 3

// resolvedParts is writeResolved's content as values: the heading count and
// the list lines, without their trailing newlines. The count is 0 when
// nothing was resolved.
func resolvedParts(d state.Diff, byRef map[string]analyze.ImageObservation, msg messages) (int, []string) {
	type pkgKey struct{ image, pkg string }
	seen := map[pkgKey]bool{}
	var gone []pkgKey
	for _, res := range d.Resolved {
		k := pkgKey{res.Image, res.Package}
		if !seen[k] {
			seen[k] = true
			gone = append(gone, k)
		}
	}
	var leftEOL []state.ResolvedEOL
	for _, res := range d.ResolvedEOLPackages {
		k := pkgKey{res.Image, res.Package}
		switch {
		case res.StillOpen:
			leftEOL = append(leftEOL, res)
		case !seen[k]:
			seen[k] = true
			gone = append(gone, k)
		}
	}
	if len(gone) == 0 && len(leftEOL) == 0 && len(d.ResolvedEOSL) == 0 {
		return 0, nil
	}
	sort.SliceStable(gone, func(i, j int) bool {
		if gone[i].image != gone[j].image {
			return gone[i].image < gone[j].image
		}
		return gone[i].pkg < gone[j].pkg
	})
	var lines []string
	line := func(format string, args ...any) {
		lines = append(lines, strings.TrimSuffix(fmt.Sprintf(format, args...), "\n"))
	}
	for _, img := range d.ResolvedEOSL {
		line(msg.BaseOSNoLongerEOL, escMrkdwn(refLabel(img, byRef, msg)))
	}
	byImage := map[string][]string{}
	var imgOrder []string
	for _, k := range gone {
		if _, ok := byImage[k.image]; !ok {
			imgOrder = append(imgOrder, k.image)
		}
		byImage[k.image] = append(byImage[k.image], escMrkdwn(k.pkg))
	}
	for _, img := range imgOrder {
		line(msg.ResolvedImagePackages, escMrkdwn(refLabel(img, byRef, msg)), strings.Join(byImage[img], ", "))
	}
	for _, res := range leftEOL {
		line(msg.NoLongerEndOfLife, escMrkdwn(refLabel(res.Image, byRef, msg)), escMrkdwn(res.Package))
	}
	return len(gone) + len(leftEOL) + len(d.ResolvedEOSL), lines
}

// writeNothingOpenNow is the heartbeat for a cycle whose report has no
// findings. "All clear" is only claimed when state holds nothing either:
// findings held for an unpinned scan (holding) or for a failed scan
// (d.AnyOpen) are still open, just not re-scanned.
func writeNothingOpenNow(b *strings.Builder, d state.Diff, holding bool, msg messages) {
	switch {
	case holding:
		b.WriteString(msg.OpenNowUnconfirmedHolding)
	case d.AnyOpen:
		b.WriteString(msg.OpenNowNotRescanned)
	default:
		b.WriteString(msg.OpenNowAllClear)
	}
}

// openNowEOLSegments are the end-of-life segments leading the "Open now"
// heartbeat, counted from state so held records are included and the
// base-OS count agrees with the fold (d.OpenEOSL). The package segment is
// independent of triage; the base-OS one follows openNowEOLBaseWithoutTriage
// when triage is off.
func openNowEOLSegments(d state.Diff, triage bool, msg messages) []string {
	var seg []string
	if n := len(d.OpenEOSL); n > 0 && (triage || openNowEOLBaseWithoutTriage) {
		seg = append(seg, fmt.Sprintf(msg.SegEOLBase, n))
	}
	if d.OpenEOLPackages > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLPackage, d.OpenEOLPackages))
	}
	return seg
}

// priority holds the headline counts shown at the top of the message.
type priority struct {
	eol, eolPackages, critical, care, safe int
}

// summarize tallies the headline: EOL base images, end-of-life packages shown
// individually, total CRITICAL CVEs across all sections, fixable packages
// that need care (major bump), and fixable packages low-risk enough to be
// collapsed.
func summarize(r analyze.Report) priority {
	p := priority{eol: len(r.EOSLImages), eolPackages: analyze.GroupCount(r.EOLPackageAlerts())}
	// Summed per group, skipping Muted ones, so this total agrees with the
	// per-image counts the body actually shows (the status sections
	// already hide a muted group's card and, with it, its CVEs).
	// Mathematically identical to summing img.CriticalCount() whenever
	// nothing is muted.
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				if !g.Muted {
					p.critical += g.Critical
				}
			}
		}
	}
	for _, img := range r.Actionable {
		for _, g := range img.Packages {
			switch {
			case needsAttention(g):
				if g.Risk == analyze.RiskCaution {
					p.care++
				}
			default:
				p.safe++
			}
		}
	}
	return p
}

// headlineSegments are the segments of the triage-off priority line, zero
// counts omitted.
func headlineSegments(p priority, msg messages) []string {
	var seg []string
	if p.eol > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLBase, p.eol))
	}
	if p.eolPackages > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLPackage, p.eolPackages))
	}
	if p.critical > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegCritical, p.critical))
	}
	if p.care > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegNeedCare, p.care))
	}
	if p.safe > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegSafe, p.safe))
	}
	return seg
}

// needsAttention reports whether a fixable package warrants a human decision and
// should be shown in full: it carries a CRITICAL, or its fix is a major-version
// bump (possible breaking change).
func needsAttention(g analyze.PackageGroup) bool {
	return g.Critical > 0 || g.Risk == analyze.RiskCaution
}

// langTag is the bracketed tag a language package's card shows: the ecosystem name (e.g. "python-pkg", "gobinary") when Trivy's
// Result.Type parsed to a known one, or the generic "lang" it always showed
// before ecosystems were tracked, when it didn't.
func langTag(eco inventory.Ecosystem) string {
	if eco == inventory.EcosystemUnknown {
		return "lang"
	}
	return string(eco)
}

// collapsedSeverity is the severity summary of a collapsed lower-risk line.
func collapsedSeverity(c analyze.SeverityCounts) string {
	if c.Critical > 0 {
		return fmt.Sprintf("CRITICAL %d / HIGH %d", c.Critical, c.High) + lowerSeverityParts(c, " / %[1]s %[2]d")
	}
	return fmt.Sprintf("HIGH %d", c.High) + lowerSeverityParts(c, " / %[1]s %[2]d")
}

// lowerSeverityParts renders the levels below HIGH that have a non-zero
// count, in descending order (MEDIUM, LOW, UNKNOWN), each through part
// (level name %[1]s, count %[2]d). It is empty for the default
// scan.severity, which keeps every existing line unchanged.
func lowerSeverityParts(c analyze.SeverityCounts, part string) string {
	var b strings.Builder
	for _, l := range []struct {
		name string
		n    int
	}{{"MEDIUM", c.Medium}, {"LOW", c.Low}, {"UNKNOWN", c.Unknown}} {
		if l.n > 0 {
			fmt.Fprintf(&b, part, l.name, l.n)
		}
	}
	return b.String()
}

// countsLine renders the CRITICAL / HIGH counts through the language's
// CardCounts format, followed by the non-zero lower levels.
func countsLine(msg messages, c analyze.SeverityCounts) string {
	return fmt.Sprintf(msg.CardCounts, c.Critical, c.High) + lowerSeverityParts(c, " / %[1]s %[2]d")
}

// severityMap is the severity_counts object of the webhook: CRITICAL and
// HIGH always, the lower levels only when non-zero.
func severityMap(c analyze.SeverityCounts) map[string]int {
	m := map[string]int{"CRITICAL": c.Critical, "HIGH": c.High}
	if c.Medium > 0 {
		m["MEDIUM"] = c.Medium
	}
	if c.Low > 0 {
		m["LOW"] = c.Low
	}
	if c.Unknown > 0 {
		m["UNKNOWN"] = c.Unknown
	}
	return m
}

// collapsedNames lists up to collapsePreview package names, then a count of
// the rest.
func collapsedNames(names []string, msg messages) string {
	shown, extra := names, 0
	if len(names) > collapsePreview {
		shown, extra = names[:collapsePreview], len(names)-collapsePreview
	}
	s := strings.Join(shown, ", ")
	if extra > 0 {
		s += fmt.Sprintf(msg.MoreCount, extra)
	}
	return s
}

func imageEmoji(img analyze.ImageFindings) string {
	if img.CriticalCount() > 0 {
		return "🔴"
	}
	return "🟠"
}

// --- generic webhook payload ---

type webhookPayload struct {
	GeneratedAt string              `json:"generated_at"`
	Environment *environmentPayload `json:"environment,omitempty"`
	Summary     summary             `json:"summary"`
	EOSLImages  []string            `json:"eosl_images"`
	Actionable  []imagePayload      `json:"actionable"`
	Watch       []imagePayload      `json:"watch"`
	WontFix     []imagePayload      `json:"wont_fix"`
	EOLPackages []imagePayload      `json:"eol_packages"` // every end-of-life package group, folded and act_now ones included
	ScanErrors  []errorPayload      `json:"scan_errors"`
	// RuntimeUnchecked lists the language runtimes of images that were not
	// checked because their advisory data was unavailable; absent when none.
	RuntimeUnchecked []runtimeUncheckedPayload `json:"runtime_unchecked,omitempty"`
	Diff             *diffPayload              `json:"diff,omitempty"`
	// Runtime is the Sensor-wide runtime status, present only when
	// runtime.enabled is true (analyze.Report.Runtime != nil).
	Runtime *runtimePayload `json:"runtime,omitempty"`
	// Remediation is the read-only fix plan, present only when the plan is
	// enabled (Message.Plan != nil).
	Remediation *remediationPayload `json:"remediation,omitempty"`
}

// runtimePayload mirrors analyze.RuntimeInfo for the webhook's top-level
// "runtime" object. Rules is fixed prose describing how usage is judged —
// it never varies per-report — included so a receiver never has to
// hard-code the same wording this codebase decided on.
type runtimePayload struct {
	SensorStatus    string               `json:"sensor_status"`
	HeartbeatAt     string               `json:"heartbeat_at,omitempty"`
	IntervalSeconds int                  `json:"interval_seconds,omitempty"`
	Rules           runtimeRulesPayload  `json:"rules"`
	EventsStatus    string               `json:"events_status"`
	EventsReason    string               `json:"events_reason,omitempty"`
	Counts          runtimeCountsPayload `json:"counts"`
}

type runtimeRulesPayload struct {
	OSPackages          string `json:"os_packages"`
	LangPackagesBinary  string `json:"lang_packages_binary"`
	LangPackagesRuntime string `json:"lang_packages_runtime"`
}

type runtimeCountsPayload struct {
	InUse       int `json:"in_use"`
	NotObserved int `json:"not_observed"`
	Unavailable int `json:"unavailable"`
	// Muted overlaps NotObserved by construction (analyze.ApplyMuting
	// only ever mutes a not-observed group) rather than being mutually
	// exclusive with it. Always 0 when runtime.mute_unfixable_not_in_use
	// is off.
	Muted int `json:"muted"`
}

// environmentPayload mirrors inventory.Environment. Kind is always present —
// BuildWebhookPayload always populates the pointer, since even the unnamed
// default environment has a Kind — while Name is omitted for the unnamed
// default rather than sent as "".
type environmentPayload struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

// diffPayload mirrors state.Diff for webhook consumers. The full sections above
// are always present; the diff is additive so receivers can build their own
// "what changed" view without keeping state.
type diffPayload struct {
	New      []changePayload   `json:"new"`
	Resolved []resolvedPayload `json:"resolved"`
	Replaced []replacedPayload `json:"replaced"`
	// ReferenceChanges is omitted when empty so the payload of a cycle with
	// no reference change is unchanged.
	ReferenceChanges []referenceChangePayload `json:"reference_changes,omitempty"`
	NewEOSL          []string                 `json:"new_eosl"`
	ResolvedEOSL     []string                 `json:"resolved_eosl"`
	OldestOpenDay    int                      `json:"oldest_open_days"`

	// End-of-life package changes, independent of new/resolved above (the
	// same package can appear in both).
	NewEOLPackages      []eolChangePayload   `json:"new_eol_packages"`
	ResolvedEOLPackages []eolResolvedPayload `json:"resolved_eol_packages"`
}

// eolChangePayload mirrors state.EOLChange.
type eolChangePayload struct {
	Image    string   `json:"image"`
	Package  string   `json:"package"`
	Kind     string   `json:"kind"`                  // eol_new | eol_new_cves | eol_escalated
	NewIDs   []string `json:"new_cve_ids,omitempty"` // eol_new_cves: the end-of-life CVE ids added
	Critical int      `json:"critical"`
	High     int      `json:"high"`
	Medium   int      `json:"medium,omitempty"`
	Low      int      `json:"low,omitempty"`
	Unknown  int      `json:"unknown,omitempty"`
	Priority string   `json:"priority,omitempty"` // triage: act_now | watch | low
	Reason   string   `json:"reason,omitempty"`   // eol_escalated: evidence for the new verdict

	// Ecosystems mirrors changePayload.Ecosystems: the deduplicated, sorted
	// set across every merged analyze.PackageGroup.
	Ecosystems []string `json:"ecosystems"`

	// RuntimeUsage mirrors changePayload.RuntimeUsage: the projected usage
	// across every merged analyze.PackageGroup. "" (omitted) when
	// runtime.enabled is false.
	RuntimeUsage string `json:"runtime_usage,omitempty"`
}

// eolResolvedPayload mirrors state.ResolvedEOL.
type eolResolvedPayload struct {
	Image     string `json:"image"`
	Package   string `json:"package"`
	StillOpen bool   `json:"still_open"` // the package still has ordinary findings
}

// replacedPayload mirrors state.ImageReplacement: a reference whose verified
// running content changed since the previous scan. The ID sets are already
// sorted upstream.
type replacedPayload struct {
	Ref            string   `json:"ref"`
	PrevContentIDs []string `json:"prev_content_ids"`
	ContentIDs     []string `json:"content_ids"`
}

// referenceChangePayload mirrors state.RefChange: a workload that moved to
// another reference of the same repository and whose findings history was
// carried over.
type referenceChangePayload struct {
	Repository  string   `json:"repository"`
	PreviousRef string   `json:"previous_ref"`
	Ref         string   `json:"ref"`
	Workloads   []string `json:"workloads"`
}

type changePayload struct {
	Image    string   `json:"image"`
	Package  string   `json:"package"`
	Kind     string   `json:"kind"` // new | escalated | new_cves | now_fixable
	NewCVEs  int      `json:"new_cve_count,omitempty"`
	NewIDs   []string `json:"new_cve_ids,omitempty"` // plain CVE ids added, same set as new_cve_count
	Critical int      `json:"critical"`
	High     int      `json:"high"`
	Medium   int      `json:"medium,omitempty"`
	Low      int      `json:"low,omitempty"`
	Unknown  int      `json:"unknown,omitempty"`
	Priority string   `json:"priority,omitempty"` // triage: act_now | watch | low
	Reason   string   `json:"reason,omitempty"`   // escalated: evidence for the new verdict

	// Ecosystems is the deduplicated, sorted set of Ecosystem values across
	// every analyze.PackageGroup this (image, package) change merged
	// (state's key is (image, package name) only, so an OS package and a
	// same-named language package, or two installed versions, can land in
	// the same change). "" (unknown/OS-without-a-parsed-type) sorts first.
	Ecosystems []string `json:"ecosystems"`

	// RuntimeUsage is this (image, package) change's projected runtime
	// usage: in_use if any merged analyze.PackageGroup is, else unavailable
	// if any is, else not_observed — the same order
	// evidence.ProjectUsages/analyze.Runtime's own projection uses. ""
	// (omitted) when runtime.enabled is false, i.e. none of the merged
	// groups ever had AttachRuntime judge them.
	RuntimeUsage string `json:"runtime_usage,omitempty"`

	// Muted is true when every analyze.PackageGroup this change merged is
	// Muted under runtime.mute_unfixable_not_in_use — the webhook's
	// counterpart to notify hiding this change's row entirely in Slack.
	// analyze.ApplyMuting only ever marks every group of a key Muted
	// together (a fixed or otherwise-ineligible sibling group blocks the
	// whole key), so in practice this is never true for only some of a
	// change's groups.
	Muted bool `json:"muted,omitempty"`
}

type resolvedPayload struct {
	Image   string `json:"image"`
	Package string `json:"package"`
}

type summary struct {
	ImagesTotal    int            `json:"images_total"`
	ImagesAffected int            `json:"images_affected"`
	PriorityCounts map[string]int `json:"priority_counts,omitempty"` // triage: act_now / watch / low
	Intel          *intelPayload  `json:"intel,omitempty"`           // triage: data freshness
}

// intelPayload tells webhook consumers how much to trust the priorities in
// this payload.
type intelPayload struct {
	Degraded  bool `json:"degraded"`
	KEVOK     bool `json:"kev_ok"`
	EPSSOK    bool `json:"epss_ok"`
	StaleDays int  `json:"stale_days"`
}

type imagePayload struct {
	Image          string           `json:"image"`
	SeverityCounts map[string]int   `json:"severity_counts"`
	Findings       []findingPayload `json:"findings"`

	// Containers is the entity-level observation backing this section entry
	// (analyze.ImageFindings.Containers): every running container matching
	// this (Image, Subject.Key) exactly. Unlike RegistryDigests below this is
	// per-entity, not a Ref-level union — a reference running two distinct
	// verified entities lists each entity's own containers under its own
	// section entry, not a merged set.
	Containers []containerPayload `json:"containers"`

	// Identity fields. ContentID mirrors analyze.ImageFindings.ContentID():
	// non-empty only when this entity resolved to a config-digest identity
	// (single confirmed entity — the ordinary case, or one entry of an
	// Ambiguous reference); a registry-digest entity never populates it.
	// IdentityResolved mirrors this entity's own Pinned — never the
	// reference's aggregate IdentityResolved (analyze.Report.Images), so a
	// pinned entity is never reported as unresolved just because a sibling
	// under the same reference wasn't. ScanTargetKind names which identity
	// kind was pinned ("content_id" | "registry_digest"), or "reference" when
	// not pinned at all. RegistryDigests alone is the reference's identity
	// inventory, looked up by Image (ImageFindings carries no per-entity
	// RegistryDigests of its own).
	ContentID        string   `json:"content_id,omitempty"`
	RegistryDigests  []string `json:"registry_digests"`
	IdentityResolved bool     `json:"identity_resolved"`
	ScanTargetKind   string   `json:"scan_target_kind"` // content_id | registry_digest | reference
}

// containerPayload mirrors inventory.Container: the container's own display
// name, plus whatever Workload association was found for it.
type containerPayload struct {
	Name     string          `json:"name"`
	Workload workloadPayload `json:"workload"`
}

// workloadPayload mirrors inventory.Workload. Kind is always written,
// including "unknown" — inventory.WorkloadUnknown is the Go empty string so
// a zero-valued Workload reads as unknown by construction, but the webhook
// contract spells it out explicitly so a receiver can tell "no association
// found" apart from "this payload version doesn't carry workloads at all".
// Group/Name are omitted when unknown, since neither is meaningful then.
type workloadPayload struct {
	Kind  string `json:"kind"`
	Group string `json:"group,omitempty"`
	Name  string `json:"name,omitempty"`
}

type findingPayload struct {
	Package        string         `json:"package"`
	Installed      string         `json:"installed"`
	Fixed          string         `json:"fixed"`
	Status         string         `json:"status"`
	SeverityCounts map[string]int `json:"severity_counts"`
	UpgradeRisk    string         `json:"upgrade_risk"`
	Priority       string         `json:"priority,omitempty"` // triage verdict for the package
	VulnIDs        []string       `json:"vuln_ids"`
	Vulns          []vulnPayload  `json:"vulns"` // per-CVE detail (superset of vuln_ids)

	// Class is "os" or "lang" (analyze.PackageGroup.Class).
	// Ecosystem is Trivy's Result.Type as parsed against the allowlist
	// (analyze.PackageGroup.Ecosystem); "" when Trivy's value was empty or
	// unrecognized.
	Class     string `json:"class"`
	Ecosystem string `json:"ecosystem"`

	// Runtime is this package's runtime-usage verdict, present only when
	// runtime.enabled is true (analyze.PackageGroup.Runtime.Usage != "").
	Runtime *findingRuntimePayload `json:"runtime,omitempty"`
}

// findingRuntimePayload mirrors analyze.Runtime, plus the PackageGroup-level
// Muted verdict it travels alongside.
type findingRuntimePayload struct {
	Usage          string                           `json:"usage"`
	Reason         string                           `json:"reason,omitempty"`
	EvidenceKinds  []string                         `json:"evidence_kinds,omitempty"`
	EventsCoverage string                           `json:"events_coverage,omitempty"`
	Exposure       string                           `json:"exposure,omitempty"`
	HighPrivilege  bool                             `json:"high_privilege,omitempty"`
	Containers     []findingRuntimeContainerPayload `json:"containers,omitempty"`
	// Muted and MutedReason mirror analyze.PackageGroup.Muted/
	// MutedReason: true only under runtime.mute_unfixable_not_in_use.
	// The generic webhook always carries the finding either way — this is a
	// marker, never an omission.
	Muted       bool   `json:"muted,omitempty"`
	MutedReason string `json:"muted_reason,omitempty"`
}

// findingRuntimeContainerPayload mirrors analyze.ContainerRuntime.
type findingRuntimeContainerPayload struct {
	Name                string   `json:"name"`
	ContainerID         string   `json:"container_id"`
	GenerationStartedAt string   `json:"generation_started_at,omitempty"`
	Usage               string   `json:"usage"`
	Reason              string   `json:"reason,omitempty"`
	LastSeen            string   `json:"last_seen,omitempty"`
	Ports               []string `json:"ports,omitempty"`
	// KindsAmbiguous and ProcessExes mirror analyze.ContainerRuntime's own
	// fields: KindsAmbiguous true means evidence_kinds cannot be paired with
	// process.exe (an OS package record aggregated more than one kind
	// across more than one process), and ProcessExes then names every
	// process actually observed instead, unabridged.
	KindsAmbiguous bool                          `json:"kinds_ambiguous,omitempty"`
	ProcessExes    []string                      `json:"process_exes,omitempty"`
	Process        *findingRuntimeProcessPayload `json:"process,omitempty"`
	// Instances is this language package's per-Instance (per-Target)
	// verdict within this one container: a package embedded
	// in two binaries, e.g. /app/api and /app/tool, can be in use through
	// one and not the other. Nil for an OS package (analyze.ContainerRuntime.
	// Instances' own doc comment).
	Instances []findingRuntimeInstancePayload `json:"instances,omitempty"`
}

// findingRuntimeInstancePayload mirrors analyze.InstanceRuntime.
type findingRuntimeInstancePayload struct {
	Type    string `json:"type,omitempty"`
	Target  string `json:"target,omitempty"`
	PkgPath string `json:"pkg_path,omitempty"`
	Usage   string `json:"usage"`
	Reason  string `json:"reason,omitempty"`
}

// findingRuntimeProcessPayload mirrors analyze.ContainerProcess.
type findingRuntimeProcessPayload struct {
	Exe           string   `json:"exe,omitempty"`
	EffectiveUID  int      `json:"effective_uid"`
	Userns        bool     `json:"userns"`
	DangerousCaps []string `json:"dangerous_caps,omitempty"`
	Privileged    bool     `json:"privileged"`
}

// vulnPayload is the per-CVE record: id and severity always; the triage fields
// carry the enrichment when triage is on. EPSS is null when no score is known.
type vulnPayload struct {
	ID         string       `json:"id"`
	Severity   string       `json:"severity"`
	URL        string       `json:"url,omitempty"`    // scanner's primary advisory
	Title      string       `json:"title,omitempty"`  // short human-readable summary, if the scanner supplied one
	Status     string       `json:"status,omitempty"` // raw scanner status, only when it differs from the finding's status (e.g. fix_deferred in watch)
	KEV        bool         `json:"kev"`
	Ransomware bool         `json:"ransomware,omitempty"`
	EPSS       *float64     `json:"epss"`
	Priority   string       `json:"priority,omitempty"`
	Refs       []refPayload `json:"refs,omitempty"` // vendor advisory, discussions
}

type refPayload struct {
	Kind  string `json:"kind"` // vendor | discussion
	Label string `json:"label"`
	URL   string `json:"url"`
}

type errorPayload struct {
	Image string `json:"image"`
	Error string `json:"error"`
}

// BuildWebhookPayload produces the structured JSON payload for the generic
// webhook. It is returned as a value so callers (and tests) can marshal it.
// The payload always carries the full current data (the webhook's role is the
// unabridged record); d adds the diff section when diff mode is on.
func BuildWebhookPayload(r analyze.Report, d *state.Diff) any {
	return BuildWebhookPayloadWithPlan(r, d, nil)
}

// BuildWebhookPayloadWithPlan is BuildWebhookPayload plus the fix plan: a nil
// plan leaves the payload exactly as BuildWebhookPayload produces it.
func BuildWebhookPayloadWithPlan(r analyze.Report, d *state.Diff, plan *PlanInfo) any {
	byRef := imagesByRef(r)
	p := webhookPayload{
		GeneratedAt: r.GeneratedAt.Format(time.RFC3339),
		Environment: &environmentPayload{
			Kind: string(r.Environment.Kind),
			Name: r.Environment.Name,
		},
		Summary: summary{
			ImagesTotal:    r.ImagesTotal,
			ImagesAffected: r.AffectedImageCount(),
		},
		EOSLImages:  r.EOSLImages,
		Actionable:  imagePayloads(r.Actionable, byRef),
		Watch:       imagePayloads(r.Watch, byRef),
		WontFix:     imagePayloads(r.WontFix, byRef),
		EOLPackages: imagePayloads(r.EOLPackages, byRef),
		ScanErrors:  errorPayloads(r.ScanErrors),

		RuntimeUnchecked: runtimeUncheckedPayloads(r.RuntimeUnchecked),
	}
	if r.Triage {
		pv := r.ByPriority()
		p.Summary.PriorityCounts = map[string]int{
			"act_now": analyze.GroupCount(pv.ActNow),
			"watch":   analyze.GroupCount(pv.Watch),
			"low":     analyze.GroupCount(pv.Low),
		}
		p.Summary.Intel = &intelPayload{
			Degraded:  r.Intel.Degraded(),
			KEVOK:     r.Intel.KEVOK,
			EPSSOK:    r.Intel.EPSSOK,
			StaleDays: r.Intel.StaleDays,
		}
	}
	if r.Runtime != nil {
		p.Runtime = runtimePayloadOf(r)
	}
	if d != nil {
		p.Diff = buildDiffPayload(r, *d)
	}
	if plan != nil {
		p.Remediation = remediationPayloadOf(plan)
	}
	return p
}

// runtimePayloadOf builds the webhook's top-level "runtime" object from
// r.Runtime. Only called when r.Runtime != nil.
func runtimePayloadOf(r analyze.Report) *runtimePayload {
	rt := r.Runtime
	inUse, notObserved, unavailable, muted := runtimeCounts(r)
	return &runtimePayload{
		SensorStatus:    runtimeDisplayStatus(rt, r.GeneratedAt),
		HeartbeatAt:     formatTimeOrEmpty(rt.Sensor.HeartbeatAt),
		IntervalSeconds: rt.Sensor.IntervalSeconds,
		Rules: runtimeRulesPayload{
			OSPackages:          "executed_or_loaded_by_running_process",
			LangPackagesBinary:  "in_running_binary",
			LangPackagesRuntime: "runtime_process_running",
		},
		EventsStatus: string(rt.Sensor.Events.Status),
		EventsReason: string(rt.Sensor.Events.Reason),
		Counts:       runtimeCountsPayload{InUse: inUse, NotObserved: notObserved, Unavailable: unavailable, Muted: muted},
	}
}

// formatTimeOrEmpty formats t as RFC3339, or "" for the zero value — used
// for the runtime payload's optional timestamps, which are meaningless (and
// so omitted via omitempty) before a Sensor has ever reported.
func formatTimeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func buildDiffPayload(r analyze.Report, d state.Diff) *diffPayload {
	dp := &diffPayload{
		New:                 []changePayload{},
		Resolved:            []resolvedPayload{},
		Replaced:            []replacedPayload{},
		NewEOSL:             emptyIfNil(d.NewEOSL),
		ResolvedEOSL:        emptyIfNil(d.ResolvedEOSL),
		OldestOpenDay:       d.OldestOpenDays(r.GeneratedAt),
		NewEOLPackages:      []eolChangePayload{},
		ResolvedEOLPackages: []eolResolvedPayload{},
	}
	for _, c := range d.Changes {
		var cnt analyze.SeverityCounts
		for _, g := range c.Groups {
			cnt = cnt.Add(g.Counts())
		}
		cp := changePayload{
			Image:        c.Image,
			Package:      c.Package,
			Kind:         string(c.Kind),
			NewCVEs:      c.NewCVEs,
			NewIDs:       c.NewIDs,
			Critical:     cnt.Critical,
			High:         cnt.High,
			Medium:       cnt.Medium,
			Low:          cnt.Low,
			Unknown:      cnt.Unknown,
			Priority:     string(analyze.MaxPriority(c.Groups)),
			Ecosystems:   ecosystemsOf(c.Groups),
			RuntimeUsage: runtimeUsageOf(c.Groups),
			Muted:        allMuted(c.Groups),
		}
		switch c.Kind {
		case state.KindEscalated:
			// The generic webhook payload is never translated (it's
			// consumed programmatically, not read in Slack), so its reason
			// text always uses the English dictionary regardless of
			// notify.language.
			cp.Reason = changeEvidence(r, c, enMessages)
		case state.KindUnmuted:
			cp.Reason = unmutedReason(changeReasonGroups(c), enMessages)
		}
		dp.New = append(dp.New, cp)
	}
	for _, res := range d.Resolved {
		dp.Resolved = append(dp.Resolved, resolvedPayload{Image: res.Image, Package: res.Package})
	}
	for _, rep := range d.Replaced {
		dp.Replaced = append(dp.Replaced, replacedPayload{
			Ref:            rep.Ref,
			PrevContentIDs: emptyIfNil(rep.PrevContentIDs),
			ContentIDs:     emptyIfNil(rep.ContentIDs),
		})
	}
	for _, rc := range d.RefChanges {
		dp.ReferenceChanges = append(dp.ReferenceChanges, referenceChangePayload{
			Repository:  rc.Repository,
			PreviousRef: rc.PreviousRef,
			Ref:         rc.Ref,
			Workloads:   emptyIfNil(rc.Workloads),
		})
	}
	for _, c := range d.NewEOLPackages {
		var cnt analyze.SeverityCounts
		for _, g := range c.Groups {
			cnt = cnt.Add(g.Counts())
		}
		cp := eolChangePayload{
			Image:        c.Image,
			Package:      c.Package,
			Kind:         string(c.Kind),
			NewIDs:       c.NewIDs,
			Critical:     cnt.Critical,
			High:         cnt.High,
			Medium:       cnt.Medium,
			Low:          cnt.Low,
			Unknown:      cnt.Unknown,
			Priority:     string(analyze.MaxPriority(c.Groups)),
			Ecosystems:   ecosystemsOf(c.Groups),
			RuntimeUsage: runtimeUsageOf(c.Groups),
		}
		if c.Kind == state.EOLKindEscalated {
			// Same rule as above: the webhook payload always uses English.
			cp.Reason = changeEvidence(r, eolAsChange(c), enMessages)
		}
		dp.NewEOLPackages = append(dp.NewEOLPackages, cp)
	}
	for _, res := range d.ResolvedEOLPackages {
		dp.ResolvedEOLPackages = append(dp.ResolvedEOLPackages, eolResolvedPayload{Image: res.Image, Package: res.Package, StillOpen: res.StillOpen})
	}
	return dp
}

// ecosystemsOf is the deduplicated, sorted set of Ecosystem values across a
// diff change's merged package groups. "" (EcosystemUnknown — Trivy's
// Result.Type was empty, or outside the allowlist) sorts first like any
// other string, and is included: its presence in the set is itself
// informative (this (image, package) change includes at least one group
// without a recognized ecosystem), so it is not filtered out the way
// emptyIfNil clears an unset list.
func ecosystemsOf(groups []analyze.PackageGroup) []string {
	seen := map[string]bool{}
	for _, g := range groups {
		seen[string(g.Ecosystem)] = true
	}
	out := make([]string, 0, len(seen))
	for e := range seen {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func imagePayloads(imgs []analyze.ImageFindings, byRef map[string]analyze.ImageObservation) []imagePayload {
	out := make([]imagePayload, 0, len(imgs))
	for _, img := range imgs {
		findings := make([]findingPayload, 0, len(img.Packages))
		for _, g := range img.Packages {
			vulns := make([]vulnPayload, 0, len(g.Vulns))
			for _, v := range g.Vulns {
				vp := vulnPayload{
					ID:         v.ID,
					Severity:   string(v.Severity),
					URL:        v.URL,
					Title:      v.Title,
					KEV:        v.KEV,
					Ransomware: v.Ransomware,
					Priority:   string(v.Priority),
				}
				if v.Status != g.Status {
					vp.Status = string(v.Status)
				}
				if v.EPSSKnown {
					epss := v.EPSS
					vp.EPSS = &epss
				}
				for _, ref := range v.Refs {
					vp.Refs = append(vp.Refs, refPayload(ref))
				}
				vulns = append(vulns, vp)
			}
			findings = append(findings, findingPayload{
				Package:        g.Package,
				Installed:      g.InstalledVer,
				Fixed:          g.FixedVer,
				Status:         string(g.Status),
				SeverityCounts: severityMap(g.Counts()),
				UpgradeRisk:    string(g.Risk),
				Priority:       string(g.Priority),
				VulnIDs:        g.VulnIDs(),
				Vulns:          vulns,
				Class:          string(g.Class),
				Ecosystem:      string(g.Ecosystem),
				Runtime:        runtimeFindingPayload(g),
			})
		}
		// scan_target_kind and identity_resolved are both entity-level (this
		// ImageFindings' own Pinned/Subject), not the reference's aggregate
		// IdentityResolved: a mixed reference (one entity pinned, a sibling on
		// reference-fallback) must not report a resolved entity as
		// identity_resolved=false just because a sibling wasn't.
		// RegistryDigests alone stays a Ref-level lookup (analyze.ImageFindings
		// carries no per-entity RegistryDigests of its own).
		scanTargetKind := "reference"
		switch {
		case img.Pinned && img.Subject.Key.Digest.Kind == inventory.DigestConfig:
			scanTargetKind = "content_id"
		case img.Pinned && img.Subject.Key.Digest.Kind == inventory.DigestRegistry:
			scanTargetKind = "registry_digest"
		}
		out = append(out, imagePayload{
			Image:            img.Image,
			SeverityCounts:   severityMap(img.Counts()),
			Findings:         findings,
			Containers:       containerPayloads(img.Containers),
			ContentID:        img.ContentID(),
			RegistryDigests:  emptyIfNil(byRef[img.Image].RegistryDigests),
			IdentityResolved: img.Pinned,
			ScanTargetKind:   scanTargetKind,
		})
	}
	return out
}

// containerPayloads converts an entity's observed containers to their
// webhook form. Empty/nil input yields an empty slice, not null — matching
// the other list fields in imagePayload (e.g. RegistryDigests via
// emptyIfNil).
func containerPayloads(cs []inventory.Container) []containerPayload {
	out := make([]containerPayload, 0, len(cs))
	for _, c := range cs {
		out = append(out, containerPayload{
			Name: c.Name,
			Workload: workloadPayload{
				Kind:  workloadKindPayload(c.Workload.Kind),
				Group: c.Workload.Group,
				Name:  c.Workload.Name,
			},
		})
	}
	return out
}

// workloadKindPayload maps inventory.WorkloadKind to its webhook string,
// writing out "unknown" explicitly for inventory.WorkloadUnknown (the Go
// zero value, "") rather than letting it serialize as an empty string.
func workloadKindPayload(k inventory.WorkloadKind) string {
	if k == inventory.WorkloadUnknown {
		return "unknown"
	}
	return string(k)
}

func errorPayloads(errs []analyze.ScanError) []errorPayload {
	out := make([]errorPayload, 0, len(errs))
	for _, e := range errs {
		out = append(out, errorPayload{Image: e.Image, Error: e.Err})
	}
	return out
}
