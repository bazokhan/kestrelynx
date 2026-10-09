package remediation

import (
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestSelectTargets(t *testing.T) {
	intel := func(id string) (VulnIntel, bool) {
		switch id {
		case "CVE-NOW":
			return VulnIntel{Priority: PriorityActNow, KEV: true}, true
		case "CVE-WATCH":
			return VulnIntel{Priority: PriorityWatch}, true
		case "CVE-LOW":
			return VulnIntel{Priority: PriorityLow}, true
		}
		return VulnIntel{}, false
	}
	fs := []scanner.Finding{
		finding("CVE-LOW", "a", "1", "2", scanner.SeverityHigh),
		finding("CVE-NOFIX", "b", "1", "", scanner.SeverityHigh),
		finding("CVE-WATCH", "c", "1", "2", scanner.SeverityHigh),
		finding("CVE-NOW", "d", "1", "2", scanner.SeverityCritical),
		finding("CVE-UNKNOWN", "e", "1", "2", scanner.SeverityHigh),
		finding("CVE-NOW", "d", "1", "3", scanner.SeverityCritical), // second fixed version, same pair
	}
	wontFix := finding("CVE-WF", "f", "1", "2", scanner.SeverityHigh)
	wontFix.Status = scanner.StatusWontFix
	noVer := finding("CVE-NV", "g", "1", "", scanner.SeverityHigh)
	noVer.Status = scanner.StatusFixed
	fs = append(fs, wontFix, noVer)

	got := SelectTargets(fs, intel)
	var ids []string
	for _, tg := range got {
		ids = append(ids, tg.VulnID)
	}
	if want := []string{"CVE-NOW", "CVE-WATCH", "CVE-LOW", "CVE-UNKNOWN"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("order = %v, want %v", ids, want)
	}
	if !reflect.DeepEqual(got[0].FixedVers, []string{"2", "3"}) || !got[0].KEV {
		t.Errorf("first target = %+v", got[0])
	}
}

func TestDecide(t *testing.T) {
	coord := func(n string) PackageCoord { return PackageCoord{Ecosystem: "debian", Class: "os", Name: n} }
	tg := func(id, pkg string) Target { return Target{VulnID: id, Package: coord(pkg)} }
	verdict := func(id, pkg string, o Outcome) VulnVerdict {
		return VulnVerdict{VulnID: id, Package: coord(pkg), Outcome: o}
	}
	intro := func(id string) VulnVerdict { return verdict(id, "new", OutcomeIntroduced) }
	intel := func(id string) (VulnIntel, bool) {
		switch id {
		case "KEV":
			return VulnIntel{Priority: PriorityActNow, KEV: true}, true
		case "WATCH":
			return VulnIntel{Priority: PriorityWatch}, true
		}
		return VulnIntel{}, false
	}
	two := []Target{tg("C1", "a"), tg("C2", "b")}
	cases := []struct {
		name    string
		targets []Target
		vr      VerificationResult
		kind    DecisionKind
		propose bool
	}{
		{"all resolved", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeResolved)}}, DecisionAdopt, true},
		{"extra non-target resolved/remaining ignored", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeResolved), verdict("C9", "z", OutcomeRemaining)}}, DecisionAdopt, true},
		{"partial", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeRemaining)}}, DecisionAdoptPartial, true},
		{"partial with introduced is not adopted", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeRemaining)}, Introduced: []VulnVerdict{intro("WATCH")}}, DecisionIntroduced, false},
		{"partial with introduced KEV is not adopted", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeRemaining)}, Introduced: []VulnVerdict{intro("KEV")}}, DecisionNewKEV, false},
		{"one target not reported", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved)}}, DecisionAdoptPartial, true},
		{"none resolved", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeRemaining), verdict("C2", "b", OutcomeRemaining)}}, DecisionNotResolving, false},
		{"no targets", nil, VerificationResult{Comparable: true}, DecisionNotResolving, false},
		{"resolved but introduced", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeResolved)}, Introduced: []VulnVerdict{intro("WATCH")}}, DecisionIntroduced, false},
		{"introduced with no intel", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeResolved)}, Introduced: []VulnVerdict{intro("???")}}, DecisionIntroduced, false},
		{"introduced KEV", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeResolved)}, Introduced: []VulnVerdict{intro("KEV")}}, DecisionNewKEV, false},
		{"no target reported by the comparison", two, VerificationResult{Comparable: true}, DecisionTargetsNotDetected, false},
		{"only unrelated verdicts", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C9", "z", OutcomeResolved)}}, DecisionTargetsNotDetected, false},
		{"all targets unknown", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeUnknown), verdict("C2", "b", OutcomeUnknown)}}, DecisionAnalysisIncomplete, false},
		{"resolved and unknown", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeUnknown)}}, DecisionAnalysisIncomplete, false},
		{"unknown and remaining is incomplete", two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeRemaining), verdict("C2", "b", OutcomeUnknown)}}, DecisionAnalysisIncomplete, false},
		{"resolved, remaining and unknown is not adopted", append(two, tg("C3", "c")), VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeRemaining), verdict("C3", "c", OutcomeUnknown)}}, DecisionAnalysisIncomplete, false},
		{"not comparable", two, VerificationResult{Reason: ReasonConditionsDiffer}, DecisionNotComparable, false},
		{"unknown verdicts are not resolved", two, VerificationResult{Reason: ReasonScanFailed, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeUnknown), verdict("C2", "b", OutcomeUnknown)}}, DecisionNotComparable, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(c.targets, c.vr, intel)
			if d.Kind != c.kind || d.Propose != c.propose {
				t.Fatalf("kind=%q propose=%v, want %q %v (%+v)", d.Kind, d.Propose, c.kind, c.propose, d)
			}
		})
	}

	d := Decide(two, VerificationResult{Comparable: true, Verdicts: []VulnVerdict{verdict("C1", "a", OutcomeResolved), verdict("C2", "b", OutcomeResolved)}, Introduced: []VulnVerdict{intro("WATCH"), intro("KEV"), intro("???")}}, intel)
	if d.IntroducedTopPriority != PriorityActNow || !reflect.DeepEqual(d.IntroducedKEV, []string{"KEV"}) || d.IntroducedUnknownIntel != 1 || d.Introduced != 3 {
		t.Errorf("introduced summary = %+v", d)
	}
}
