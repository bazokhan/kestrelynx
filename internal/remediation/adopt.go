package remediation

import (
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Priority is the triage verdict of a vulnerability. The values are the same
// strings the triage layer uses; this package carries its own type so it
// does not depend on that layer.
type Priority string

const (
	PriorityNone   Priority = ""
	PriorityLow    Priority = "low"
	PriorityWatch  Priority = "watch"
	PriorityActNow Priority = "act_now"
)

// Rank orders priorities, higher meaning more urgent.
func (p Priority) Rank() int {
	switch p {
	case PriorityActNow:
		return 3
	case PriorityWatch:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// VulnIntel is what is known about one vulnerability beyond the scan.
type VulnIntel struct {
	Priority Priority
	KEV      bool
}

// IntelFunc looks up the intel for a vulnerability ID. The second result is
// false when nothing is known; a nil IntelFunc knows nothing.
type IntelFunc func(vulnID string) (VulnIntel, bool)

func (f IntelFunc) lookup(id string) (VulnIntel, bool) {
	if f == nil {
		return VulnIntel{}, false
	}
	return f(id)
}

// Target is one vulnerability in one package that an update is meant to fix.
// The set of targets is fixed before any candidate is looked up and is not
// narrowed afterwards.
type Target struct {
	VulnID    string           `json:"vuln_id"`
	Package   PackageCoord     `json:"package"`
	Severity  scanner.Severity `json:"severity,omitempty"`
	FixedVers []string         `json:"fixed_vers,omitempty"` // every fixed version reported, sorted
	Priority  Priority         `json:"priority,omitempty"`
	KEV       bool             `json:"kev,omitempty"`
	// Types are the scanner's raw result types the target was reported in,
	// sorted. A comparison can judge the target only if both scans listed
	// packages of these types.
	Types []string `json:"types,omitempty"`
}

// SelectTargets returns the entry points of a scan: the findings whose
// status is fixed and that name a fixed version, merged by (VulnID,
// coordinate), ordered act_now, watch, then the rest, and by ID within a
// priority. Each finding contributes its own fixed version; nothing is
// taken from a per-package aggregate.
func SelectTargets(findings []scanner.Finding, intel IntelFunc) []Target {
	idx := map[verdictKey]*Target{}
	var order []verdictKey
	for _, f := range findings {
		if f.Status != scanner.StatusFixed || f.FixedVer == "" {
			continue
		}
		k := verdictKey{f.VulnID, coordOf(f)}
		t := idx[k]
		if t == nil {
			t = &Target{VulnID: f.VulnID, Package: k.coord, Severity: f.Severity}
			if in, ok := intel.lookup(f.VulnID); ok {
				t.Priority, t.KEV = in.Priority, in.KEV
			}
			idx[k] = t
			order = append(order, k)
		}
		if !containsString(t.FixedVers, f.FixedVer) {
			t.FixedVers = append(t.FixedVers, f.FixedVer)
		}
		if f.Type != "" && !containsString(t.Types, f.Type) {
			t.Types = append(t.Types, f.Type)
		}
	}
	out := make([]Target, 0, len(order))
	for _, k := range order {
		t := *idx[k]
		sort.Strings(t.FixedVers)
		sort.Strings(t.Types)
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Priority.Rank() != b.Priority.Rank() {
			return a.Priority.Rank() > b.Priority.Rank()
		}
		if a.VulnID != b.VulnID {
			return a.VulnID < b.VulnID
		}
		return a.Package.Name < b.Package.Name
	})
	return out
}

func containsString(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// maxTargetPriority is the strongest priority among targets.
func maxTargetPriority(ts []Target) Priority {
	max := PriorityNone
	for _, t := range ts {
		if t.Priority.Rank() > max.Rank() {
			max = t.Priority
		}
	}
	return max
}

// DecisionKind is how a comparison bears on proposing the candidate.
type DecisionKind string

const (
	// DecisionAdopt: every target is resolved and nothing is introduced.
	DecisionAdopt DecisionKind = "adopt"
	// DecisionAdoptPartial: some targets are resolved, the rest remain or
	// were not reported, and nothing is introduced. The candidate is
	// proposed; the counts say how much of the target set it resolves.
	DecisionAdoptPartial DecisionKind = "adopt_partial"
	// DecisionNotResolving: no target is resolved.
	DecisionNotResolving DecisionKind = "not_resolving"
	// DecisionIntroduced: the candidate brings findings the baseline did not
	// have. They are never offset against resolved ones.
	DecisionIntroduced DecisionKind = "introduced"
	// DecisionNewKEV: as DecisionIntroduced, and at least one introduced
	// vulnerability is in the KEV catalog.
	DecisionNewKEV DecisionKind = "new_kev"
	// DecisionAnalysisIncomplete: the comparison is valid but some targets
	// could not be judged (the candidate scan did not cover their kind of
	// package) and none is positively known to remain.
	DecisionAnalysisIncomplete DecisionKind = "analysis_incomplete"
	// DecisionTargetsNotDetected: none of the targets appears in the
	// baseline comparison (for example a rescan no longer shows them) and
	// none is observed remaining, so the comparison cannot speak about them.
	DecisionTargetsNotDetected DecisionKind = "targets_not_detected"
	// DecisionNotComparable: the comparison could not be made.
	DecisionNotComparable DecisionKind = "not_comparable"
)

// Decision records whether a comparison justifies proposing the candidate.
// The comparison is recorded either way; Propose is true only for
// DecisionAdopt and DecisionAdoptPartial.
type Decision struct {
	Kind    DecisionKind `json:"kind"`
	Propose bool         `json:"propose"`

	Targets    int `json:"targets"`
	Resolved   int `json:"resolved"`
	Remaining  int `json:"remaining"`
	Unknown    int `json:"unknown"`    // targets whose verdict is unknown
	Undetected int `json:"undetected"` // targets the baseline comparison did not report (e.g. outside the severity range)
	Introduced int `json:"introduced"`

	// IntroducedKEV lists introduced vulnerabilities known to be in KEV.
	IntroducedKEV []string `json:"introduced_kev,omitempty"`
	// IntroducedTopPriority is the strongest known priority among the
	// introduced vulnerabilities.
	IntroducedTopPriority Priority `json:"introduced_top_priority,omitempty"`
	// IntroducedUnknownIntel counts introduced vulnerabilities with no intel.
	IntroducedUnknownIntel int `json:"introduced_unknown_intel,omitempty"`

	Note string `json:"note,omitempty"`
}

// Decide applies the adoption rule. The candidate is proposed when the
// comparison is valid, at least one target is resolved, nothing is introduced
// in the evaluated range, and no target is unknown (a target whose kind of
// package a scan did not analyse; any unknown target makes the analysis
// incomplete, whatever else was resolved or remains); targets that remain
// do not block it (DecisionAdoptPartial says so, DecisionAdopt means all were
// resolved). A candidate that fixes nothing, or any introduced finding, is
// recorded but not proposed; introduced findings are not offset against
// resolved ones, and a newly introduced KEV entry is called out for a person
// to judge. A target the comparison did not report (for example one outside
// the severity range) counts as undetected, never as resolved.
func Decide(targets []Target, vr VerificationResult, intel IntelFunc) Decision {
	d := Decision{Targets: len(targets)}
	if !vr.Comparable {
		d.Kind = DecisionNotComparable
		d.Note = string(vr.Reason)
		return d
	}
	outcomes := map[verdictKey]Outcome{}
	for _, v := range vr.Verdicts {
		outcomes[verdictKey{v.VulnID, v.Package}] = v.Outcome
	}
	for _, t := range targets {
		switch outcomes[verdictKey{t.VulnID, t.Package}] {
		case OutcomeResolved:
			d.Resolved++
		case OutcomeRemaining:
			d.Remaining++
		case OutcomeUnknown:
			d.Unknown++
		default:
			d.Undetected++
		}
	}
	d.Introduced = len(vr.Introduced)
	kev := map[string]bool{}
	for _, v := range vr.Introduced {
		in, ok := intel.lookup(v.VulnID)
		if !ok {
			d.IntroducedUnknownIntel++
			continue
		}
		if in.Priority.Rank() > d.IntroducedTopPriority.Rank() {
			d.IntroducedTopPriority = in.Priority
		}
		if in.KEV && !kev[v.VulnID] {
			kev[v.VulnID] = true
			d.IntroducedKEV = append(d.IntroducedKEV, v.VulnID)
		}
	}
	sort.Strings(d.IntroducedKEV)

	switch {
	case len(d.IntroducedKEV) > 0:
		d.Kind = DecisionNewKEV
	case d.Introduced > 0:
		d.Kind = DecisionIntroduced
	case d.Targets == 0:
		d.Kind = DecisionNotResolving
	case d.Unknown > 0:
		d.Kind = DecisionAnalysisIncomplete
	case d.Resolved == 0 && d.Remaining == 0:
		d.Kind = DecisionTargetsNotDetected
	case d.Resolved == 0:
		d.Kind = DecisionNotResolving
	case d.Resolved < d.Targets:
		d.Kind, d.Propose = DecisionAdoptPartial, true
	default:
		d.Kind = DecisionAdopt
		d.Propose = true
	}
	return d
}
