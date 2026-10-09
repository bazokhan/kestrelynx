package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Reason is a short machine-readable code explaining a plan outcome or why a
// comparison could not be made.
type Reason string

// Reasons a comparison is not possible.
const (
	ReasonScanFailed         Reason = "scan_failed"
	ReasonEntityUnverified   Reason = "entity_unverified"
	ReasonConditionsUnknown  Reason = "conditions_unknown"
	ReasonConditionsDiffer   Reason = "conditions_differ"
	ReasonPlatformUnknown    Reason = "platform_unknown"
	ReasonPlatformDiffer     Reason = "platform_differ"
	ReasonVariantUnsupported Reason = "variant_unsupported"
	ReasonPackagesMissing    Reason = "packages_missing"
	ReasonPackagesTruncated  Reason = "packages_truncated"
	// ReasonUnknownPackageType: a baseline finding names a package type this
	// build does not recognise, so what the candidate scan covered cannot be
	// judged.
	ReasonUnknownPackageType Reason = "unknown_package_type"
	// ReasonTypeNotAnalysed is the reason of an unknown verdict: the
	// candidate scan has no result for the kind of package the finding was in,
	// so the finding's absence proves nothing.
	ReasonTypeNotAnalysed Reason = "type_not_analysed"
)

// Outcome is what happened to one (vulnerability, package) pair between the
// baseline and the candidate.
type Outcome string

const (
	// OutcomeResolved: present on the baseline, absent on the candidate,
	// within the scanned severity range.
	OutcomeResolved Outcome = "resolved"
	// OutcomeRemaining: still present on the candidate, in any version or
	// location.
	OutcomeRemaining Outcome = "remaining"
	// OutcomeIntroduced: absent on the baseline, present on the candidate.
	OutcomeIntroduced Outcome = "introduced"
	// OutcomeUnknown: the scans could not be compared.
	OutcomeUnknown Outcome = "unknown"
)

// Disposition says, for a resolved pair, what happened to the package on the
// candidate, read from the candidate's package list.
type Disposition string

const (
	DispositionNone           Disposition = ""
	DispositionRemoved        Disposition = "package_removed" // the package is not in the candidate
	DispositionVersionChanged Disposition = "version_changed" // the candidate carries other versions only
	DispositionSameVersion    Disposition = "same_version"    // the package is there at a version the baseline had; the finding vanished anyway
)

// PackageCoord is a package without its version: the unit findings are
// compared by, so a package present in several versions is one coordinate.
type PackageCoord struct {
	Ecosystem inventory.Ecosystem `json:"ecosystem"`
	Class     inventory.PkgClass  `json:"class"`
	Name      string              `json:"name"`
}

// Occurrence is one place a vulnerability was reported for a package.
type Occurrence struct {
	Package  inventory.PackageRef `json:"package"`        // carries the version
	Type     string               `json:"type,omitempty"` // the scanner's raw result type
	Target   string               `json:"target,omitempty"`
	PkgPath  string               `json:"pkg_path,omitempty"` // "" when the scanner reported none; never invented
	Status   scanner.Status       `json:"status,omitempty"`
	FixedVer string               `json:"fixed_ver,omitempty"`
}

// VulnVerdict is the comparison result for one (VulnID, PackageCoord).
type VulnVerdict struct {
	VulnID      string           `json:"vuln_id"`
	Package     PackageCoord     `json:"package"`
	Severity    scanner.Severity `json:"severity,omitempty"`
	Before      []Occurrence     `json:"before,omitempty"`
	After       []Occurrence     `json:"after,omitempty"`
	Outcome     Outcome          `json:"outcome"`
	Disposition Disposition      `json:"disposition,omitempty"`
	// Reason explains an unknown outcome inside a comparable result.
	Reason Reason `json:"reason,omitempty"`
}

// Versions returns the sorted distinct package versions of occ.
func Versions(occ []Occurrence) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range occ {
		if !seen[o.Package.Version] {
			seen[o.Package.Version] = true
			out = append(out, o.Package.Version)
		}
	}
	sort.Strings(out)
	return out
}

// ScanRecord is a scan together with the conditions it was taken under. The
// conditions are the caller's statement of what the scan ran with; zero
// conditions mean they are not known.
type ScanRecord struct {
	Scan       scanner.ImageScan
	Conditions scanner.ScanConditions
}

// VerificationResult is the comparison of a baseline scan with a candidate
// scan. Verdicts holds the pairs the baseline reported, Introduced the pairs
// only the candidate reported. When Comparable is false no pair is claimed
// resolved or introduced: every verdict is OutcomeUnknown and Introduced is
// empty.
type VerificationResult struct {
	Comparable bool   `json:"comparable"`
	Reason     Reason `json:"reason,omitempty"` // why not comparable
	Detail     string `json:"detail,omitempty"`

	BaselineEntity  string `json:"baseline_entity,omitempty"`
	CandidateEntity string `json:"candidate_entity,omitempty"`
	// Severities is the range both scans covered. Findings of other
	// severities were not evaluated and say nothing about this comparison.
	Severities []string `json:"severities,omitempty"`
	// Scope states what the result covers.
	Scope string `json:"scope,omitempty"`

	Verdicts   []VulnVerdict `json:"verdicts,omitempty"`
	Introduced []VulnVerdict `json:"introduced,omitempty"`
}

// Counts tallies the verdicts by outcome.
func (r VerificationResult) Counts() (resolved, remaining, introduced int) {
	for _, v := range r.Verdicts {
		switch v.Outcome {
		case OutcomeResolved:
			resolved++
		case OutcomeRemaining:
			remaining++
		}
	}
	return resolved, remaining, len(r.Introduced)
}

// verdictKey identifies a pair across both scans.
type verdictKey struct {
	vuln  string
	coord PackageCoord
}

type pairAcc struct {
	severity scanner.Severity
	occ      []Occurrence
	seen     map[Occurrence]bool
}

func coordOf(f scanner.Finding) PackageCoord {
	r := f.PackageRef()
	return PackageCoord{Ecosystem: r.Ecosystem, Class: r.Class, Name: r.Name}
}

// collect groups the findings of scan whose severity is in the range by
// (VulnID, coordinate), de-duplicating identical occurrences.
func collect(scan scanner.ImageScan, rng map[string]bool) map[verdictKey]*pairAcc {
	out := map[verdictKey]*pairAcc{}
	for _, f := range scan.Findings {
		if !rng[strings.ToUpper(string(f.Severity))] {
			continue
		}
		k := verdictKey{f.VulnID, coordOf(f)}
		acc := out[k]
		if acc == nil {
			acc = &pairAcc{severity: f.Severity, seen: map[Occurrence]bool{}}
			out[k] = acc
		}
		o := Occurrence{Package: f.PackageRef(), Type: f.Type, Target: f.Target, PkgPath: f.PkgPath, Status: f.Status, FixedVer: f.FixedVer}
		if !acc.seen[o] {
			acc.seen[o] = true
			acc.occ = append(acc.occ, o)
		}
	}
	for _, acc := range out {
		sort.Slice(acc.occ, func(i, j int) bool {
			a, b := acc.occ[i], acc.occ[j]
			if a.Package.Version != b.Package.Version {
				return a.Package.Version < b.Package.Version
			}
			if a.Target != b.Target {
				return a.Target < b.Target
			}
			return a.PkgPath < b.PkgPath
		})
	}
	return out
}

func sortedKeys(m map[verdictKey]*pairAcc) []verdictKey {
	keys := make([]verdictKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.vuln != b.vuln {
			return a.vuln < b.vuln
		}
		if a.coord.Name != b.coord.Name {
			return a.coord.Name < b.coord.Name
		}
		if a.coord.Class != b.coord.Class {
			return a.coord.Class < b.coord.Class
		}
		return a.coord.Ecosystem < b.coord.Ecosystem
	})
	return keys
}

// Unconfirmed is recorded in place of an entity identity that was not
// established; a zero key is never rendered as if it were an identity.
const Unconfirmed = "unconfirmed"

// entityString renders an entity key for records.
func entityString(k inventory.EntityKey) string {
	if !k.Digest.Valid() {
		return Unconfirmed
	}
	s := string(k.Digest.Kind) + ":" + k.Digest.String()
	if k.Platform.Known() {
		s += "@" + k.Platform.OS + "/" + k.Platform.Architecture
	}
	return s
}

// notComparable builds the not-comparable result, with an unknown verdict for
// each pair the baseline reported when it has findings to list.
func notComparable(base ScanRecord, reason Reason, detail string, rng map[string]bool, sev []string) VerificationResult {
	r := VerificationResult{Reason: reason, Detail: detail, Severities: sev, Scope: comparisonScope(sev)}
	if base.Scan.Err == nil {
		r.BaselineEntity = entityString(base.Scan.Subject.Key)
		bm := collect(base.Scan, rng)
		for _, k := range sortedKeys(bm) {
			r.Verdicts = append(r.Verdicts, VulnVerdict{VulnID: k.vuln, Package: k.coord, Severity: bm[k].severity, Before: bm[k].occ, Outcome: OutcomeUnknown})
		}
	}
	return r
}

func comparisonScope(sev []string) string {
	if len(sev) == 0 {
		return "no severity range known: nothing was evaluated"
	}
	return "only findings of severity " + strings.Join(sev, ", ") + " were evaluated; other severities are not covered"
}

// Compare compares a baseline scan with a candidate scan.
//
// Both must have succeeded with a verified (resolved and pinned) entity,
// have been taken under known and equal conditions, report the same known
// platform without a variant, and carry a complete package list; otherwise
// the result is not comparable with the first reason that applies and nothing
// is claimed resolved. The severity range is the one in the conditions (the
// baseline's, else the candidate's); only findings in it are evaluated.
func Compare(baseline, candidate ScanRecord) VerificationResult {
	rng := map[string]bool{}
	sev := baseline.Conditions.Severities
	if len(sev) == 0 {
		sev = candidate.Conditions.Severities
	}
	for _, s := range sev {
		rng[strings.ToUpper(s)] = true
	}
	fail := func(reason Reason, detail string) VerificationResult {
		return notComparable(baseline, reason, detail, rng, sev)
	}

	for _, side := range []struct {
		name string
		rec  ScanRecord
	}{{"baseline", baseline}, {"candidate", candidate}} {
		if side.rec.Scan.Err != nil {
			return fail(ReasonScanFailed, side.name+" scan failed: "+side.rec.Scan.Err.Error())
		}
	}
	for _, side := range []struct {
		name string
		rec  ScanRecord
	}{{"baseline", baseline}, {"candidate", candidate}} {
		if !side.rec.Scan.Subject.Resolved || !side.rec.Scan.Pinned {
			return fail(ReasonEntityUnverified, side.name+" scan did not confirm the image it scanned")
		}
	}
	if !baseline.Conditions.Known() || !candidate.Conditions.Known() {
		return fail(ReasonConditionsUnknown, "scan conditions are not known for both scans")
	}
	if !baseline.Conditions.Equal(candidate.Conditions) {
		return fail(ReasonConditionsDiffer, "the scans ran under different conditions")
	}
	bp, cp := baseline.Scan.Platform, candidate.Scan.Platform
	switch {
	case !bp.Known() || !cp.Known():
		return fail(ReasonPlatformUnknown, "the platform of a scan is not known")
	case bp.Variant != "" || cp.Variant != "":
		return fail(ReasonVariantUnsupported, "a platform variant is involved")
	case bp.OS != cp.OS || bp.Architecture != cp.Architecture:
		return fail(ReasonPlatformDiffer, "the scans cover different platforms")
	}
	for _, side := range []struct {
		name string
		scan scanner.ImageScan
	}{{"baseline", baseline.Scan}, {"candidate", candidate.Scan}} {
		if len(side.scan.Packages) == 0 {
			return fail(ReasonPackagesMissing, side.name+" scan has no package list")
		}
		if side.scan.PackagesTruncated {
			return fail(ReasonPackagesTruncated, side.name+" package list is truncated")
		}
	}

	for _, f := range baseline.Scan.Findings {
		if rng[strings.ToUpper(string(f.Severity))] && inventory.ParseEcosystem(f.Type) == inventory.EcosystemUnknown {
			return fail(ReasonUnknownPackageType, fmt.Sprintf("baseline finding %s in %q has package type %q", f.VulnID, f.Package, f.Type))
		}
	}

	for _, rp := range candidate.Scan.Packages {
		if inventory.ParseEcosystem(rp.Type) == inventory.EcosystemUnknown {
			return fail(ReasonUnknownPackageType, fmt.Sprintf("candidate package list has result type %q", rp.Type))
		}
	}
	for _, f := range candidate.Scan.Findings {
		if rng[strings.ToUpper(string(f.Severity))] && inventory.ParseEcosystem(f.Type) == inventory.EcosystemUnknown {
			return fail(ReasonUnknownPackageType, fmt.Sprintf("candidate finding %s in %q has package type %q", f.VulnID, f.Package, f.Type))
		}
	}

	res := VerificationResult{
		Comparable:      true,
		BaselineEntity:  entityString(baseline.Scan.Subject.Key),
		CandidateEntity: entityString(candidate.Scan.Subject.Key),
		Severities:      sev,
		Scope:           comparisonScope(sev),
	}
	bm, cm := collect(baseline.Scan, rng), collect(candidate.Scan, rng)
	candPkgs := packageVersions(candidate.Scan)
	analysed := analysedKinds(candidate.Scan)
	for _, k := range sortedKeys(bm) {
		v := VulnVerdict{VulnID: k.vuln, Package: k.coord, Severity: bm[k].severity, Before: bm[k].occ}
		if c, ok := cm[k]; ok {
			v.After, v.Outcome = c.occ, OutcomeRemaining
		} else {
			if missing := unanalysed(bm[k].occ, analysed); missing != "" {
				v.Outcome, v.Reason = OutcomeUnknown, ReasonTypeNotAnalysed
			} else {
				v.Outcome = OutcomeResolved
				v.Disposition = dispositionOf(k.coord, Versions(bm[k].occ), candPkgs)
			}
		}
		res.Verdicts = append(res.Verdicts, v)
	}
	for _, k := range sortedKeys(cm) {
		if _, ok := bm[k]; ok {
			continue
		}
		res.Introduced = append(res.Introduced, VulnVerdict{VulnID: k.vuln, Package: k.coord, Severity: cm[k].severity, After: cm[k].occ, Outcome: OutcomeIntroduced})
	}
	return res
}

// packageVersions indexes a scan's package list by coordinate.
func packageVersions(scan scanner.ImageScan) map[PackageCoord]map[string]bool {
	out := map[PackageCoord]map[string]bool{}
	for _, rp := range scan.Packages {
		eco := inventory.ParseEcosystem(rp.Type)
		for _, p := range rp.Packages {
			c := PackageCoord{Ecosystem: eco, Class: rp.Class, Name: p.Name}
			if out[c] == nil {
				out[c] = map[string]bool{}
			}
			out[c][p.Version] = true
		}
	}
	return out
}

func dispositionOf(c PackageCoord, before []string, cand map[PackageCoord]map[string]bool) Disposition {
	have := cand[c]
	if len(have) == 0 {
		return DispositionRemoved
	}
	for _, v := range before {
		if have[v] {
			return DispositionSameVersion
		}
	}
	return DispositionVersionChanged
}

type kindKey struct {
	typ   string
	class inventory.PkgClass
}

// analysedKinds lists the (result type, class) pairs the scan produced a
// package list for. An OS result counts only when the scan also identified
// the OS family.
func analysedKinds(scan scanner.ImageScan) map[kindKey]bool {
	out := map[kindKey]bool{}
	for _, rp := range scan.Packages {
		if rp.Class == inventory.ClassOS && scan.OSFamily == "" {
			continue
		}
		out[kindKey{rp.Type, rp.Class}] = true
	}
	return out
}

// unanalysed returns the type of the first occurrence whose kind of package
// the candidate scan did not analyse, "" when all were.
func unanalysed(occ []Occurrence, analysed map[kindKey]bool) string {
	for _, o := range occ {
		if !analysed[kindKey{o.Type, o.Package.Class}] {
			return o.Type
		}
	}
	return ""
}

// ApplyCoverage checks the analysis coverage over the fixed target set. A
// target can be judged only if both the baseline and the candidate scan
// listed packages of every result type the target was reported in (and, for
// OS packages, identified the OS family). Compare checks coverage only for
// the pairs the baseline reported, so a target the baseline comparison did
// not show at all would otherwise look merely undetected; here it is
// unknown, as is a target whose verdict says resolved or remaining on the
// strength of a scan that did not cover its type. Targets without recorded
// types are left as they are. The receiver is not modified.
func (r VerificationResult) ApplyCoverage(targets []Target, baseline, candidate ScanRecord) VerificationResult {
	if !r.Comparable {
		return r
	}
	sides := []map[kindKey]bool{analysedKinds(baseline.Scan), analysedKinds(candidate.Scan)}
	var gaps []Target
	for _, t := range targets {
	types:
		for _, typ := range t.Types {
			for _, analysed := range sides {
				if !analysed[kindKey{typ, t.Package.Class}] {
					gaps = append(gaps, t)
					break types
				}
			}
		}
	}
	if len(gaps) == 0 {
		return r
	}
	out := r
	out.Verdicts = append([]VulnVerdict(nil), r.Verdicts...)
	for _, t := range gaps {
		set := false
		for i := range out.Verdicts {
			v := &out.Verdicts[i]
			if v.VulnID == t.VulnID && v.Package == t.Package {
				v.Outcome, v.Reason, v.Disposition = OutcomeUnknown, ReasonTypeNotAnalysed, DispositionNone
				set = true
			}
		}
		if !set {
			out.Verdicts = append(out.Verdicts, VulnVerdict{
				VulnID: t.VulnID, Package: t.Package, Severity: t.Severity,
				Outcome: OutcomeUnknown, Reason: ReasonTypeNotAnalysed,
			})
		}
	}
	return out
}
