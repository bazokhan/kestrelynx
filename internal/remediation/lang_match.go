package remediation

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Scanner result types the language-package part reads.
const (
	typeNodePkg   = "node-pkg"
	typePythonPkg = "python-pkg"
)

// findingGroup is one package version running in an image, with every fixed
// vulnerability reported for it.
type findingGroup struct {
	Type      string
	Name      string
	Installed string
	cves      []CVERef
	origins   []FindingOrigin
	priority  Priority
	rank      int // the best (lowest) input rank among the findings
}

// srcFinding is a finding of a scanned running image with where it came
// from.
type srcFinding struct {
	f         scanner.Finding
	entity    string   // the verified entity key of the scanned image
	workloads []string // the mapped workloads running that image
	rank      int      // the position of the image among the planner's inputs
}

// groupLanguageFindings groups the fixed findings of node and python
// packages by package and installed version. Each finding contributes its own
// fixed versions; the groups are ordered by priority, then name.
func groupLanguageFindings(fs []srcFinding, intel IntelFunc) []*findingGroup {
	type gk struct{ typ, name, ver string }
	idx := map[gk]*findingGroup{}
	vulns := map[gk]map[string]*CVERef{}
	var order []gk
	seen := map[string]bool{}
	for _, lf := range fs {
		f := lf.f
		if f.Status != scanner.StatusFixed || f.FixedVer == "" || f.Package == "" || f.InstalledVer == "" {
			continue
		}
		if f.Type != typeNodePkg && f.Type != typePythonPkg {
			continue
		}
		name := f.Package
		if f.Type == typePythonPkg {
			name = normalizePyName(name)
		}
		k := gk{f.Type, name, f.InstalledVer}
		g := idx[k]
		if g == nil {
			g = &findingGroup{Type: f.Type, Name: f.Package, Installed: f.InstalledVer, rank: lf.rank}
			idx[k] = g
			vulns[k] = map[string]*CVERef{}
			order = append(order, k)
		}
		if lf.rank < g.rank {
			g.rank = lf.rank
		}
		ref := f.PackageRef()
		for _, w := range lf.workloads {
			o := FindingOrigin{Entity: lf.entity, Ecosystem: string(ref.Ecosystem), Class: string(ref.Class), Name: f.Package,
				Version: f.InstalledVer, VulnID: f.VulnID, Target: f.Target, PkgPath: f.PkgPath, Workload: w}
			if ok := o.key(); !seen[ok] {
				seen[ok] = true
				g.origins = append(g.origins, o)
			}
		}
		c := vulns[k][f.VulnID]
		if c == nil {
			c = &CVERef{VulnID: f.VulnID, Severity: f.Severity}
			if in, ok := intel.lookup(f.VulnID); ok {
				c.Priority, c.KEV = in.Priority, in.KEV
			}
			vulns[k][f.VulnID] = c
		}
		for _, alt := range splitFixed(f.FixedVer) {
			if !containsString(c.FixedVers, alt) {
				c.FixedVers = append(c.FixedVers, alt)
			}
		}
	}
	out := make([]*findingGroup, 0, len(order))
	for _, k := range order {
		g := idx[k]
		for _, c := range vulns[k] {
			sort.Strings(c.FixedVers)
			g.cves = append(g.cves, *c)
			if c.Priority.Rank() > g.priority.Rank() {
				g.priority = c.Priority
			}
		}
		sort.Slice(g.cves, func(i, j int) bool { return g.cves[i].VulnID < g.cves[j].VulnID })
		sort.Slice(g.origins, func(i, j int) bool { return g.origins[i].key() < g.origins[j].key() })
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.priority.Rank() != b.priority.Rank() {
			return a.priority.Rank() > b.priority.Rank()
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Installed < b.Installed
	})
	return out
}

// splitFixed splits a reported fixed version, which may list alternatives
// separated by commas.
func splitFixed(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// chooseTarget picks the version selection starts from: for each
// vulnerability the lowest reported fix above the installed version, then the
// highest of those over the vulnerabilities. A version that does not parse
// anywhere on the way hands the package to a person.
func chooseTarget(sc scheme, installed string, cves []CVERef) (string, Reason, string) {
	inst, ok := parseVersion(sc, installed)
	if !ok {
		return "", ReasonUnparsableVersion, fmt.Sprintf("the installed version %q is not a version", installed)
	}
	var best version
	bestStr := ""
	for _, c := range cves {
		var low version
		lowStr := ""
		for _, alt := range c.FixedVers {
			for _, one := range splitFixed(alt) {
				v, ok := parseVersion(sc, one)
				if !ok {
					return "", ReasonUnparsableVersion, fmt.Sprintf("%s reports the fixed version %q, which is not a version", c.VulnID, one)
				}
				if v.compare(inst) <= 0 {
					continue
				}
				if low == nil || v.compare(low) < 0 {
					low, lowStr = v, one
				}
			}
		}
		if low == nil {
			return "", ReasonNoFixedVersion, fmt.Sprintf("%s reports no fixed version above %s", c.VulnID, installed)
		}
		if best == nil || low.compare(best) > 0 {
			best, bestStr = low, lowStr
		}
	}
	if best == nil {
		return "", ReasonNoFixedVersion, "no vulnerability to fix"
	}
	return bestStr, "", ""
}

// versionsEqual compares two versions of one scheme, falling back to the
// text when either does not parse.
func versionsEqual(sc scheme, a, b string) bool {
	if c, ok := compareVersions(sc, a, b); ok {
		return c == 0
	}
	return a == b
}

func versionParses(sc scheme, v string) bool {
	_, ok := parseVersion(sc, v)
	return ok
}

// pyClause is one parsed clause of a version specifier.
type pyClause struct {
	op       string
	version  pyVersion
	wildcard bool // "==1.2.*" and "!=1.2.*"
}

var pyReleaseOnlyRE = regexp.MustCompile(`^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*$`)

// parseSpecifierClause checks one clause against the PEP 440 specifier
// grammar, apart from the version syntax itself: ".*" only follows == and !=
// and only a release (with optional epoch), a local label only follows == and
// !=, "~=" names at least two release segments, and the operator is one of
// the known ones. Arbitrary equality (===) is a valid clause the plan does not
// judge; ok is false for it and for anything that breaks the grammar, and
// grammar says which.
func parseSpecifierClause(clause string) (c pyClause, grammar bool, ok bool) {
	var op string
	for _, o := range []string{"===", "==", "!=", "<=", ">=", "~=", "<", ">"} {
		if strings.HasPrefix(clause, o) {
			op = o
			break
		}
	}
	ver := strings.TrimSpace(strings.TrimPrefix(clause, op))
	if op == "" || ver == "" {
		return pyClause{}, false, false
	}
	if op == "===" {
		return pyClause{op: op}, true, false
	}
	c.op = op
	if strings.HasSuffix(ver, ".*") {
		if op != "==" && op != "!=" {
			return pyClause{}, false, false
		}
		ver = strings.TrimSuffix(ver, ".*")
		if !pyReleaseOnlyRE.MatchString(ver) {
			return pyClause{}, false, false
		}
		c.wildcard = true
	}
	v, parsed := parsePEP440(ver)
	if !parsed || strings.Contains(ver, "*") {
		return pyClause{}, false, false
	}
	if len(v.local) > 0 && op != "==" && op != "!=" {
		return pyClause{}, false, false
	}
	if op == "~=" && len(v.release) < 2 {
		return pyClause{}, false, false
	}
	c.version = v
	return c, true, true
}

// pySatisfies reports whether version v meets every clause of a specifier
// like ">=1.2,<2", under the PEP 440 rules: ">V" does not allow a post-release
// of V (unless V is one) and "<V" does not allow a pre-release of V (unless V
// is one), "~=" needs the same epoch and release prefix, and "==" / "!=" take
// a ".*" prefix match. evaluable is false for a clause the plan cannot judge
// (arbitrary equality, a clause that breaks the grammar).
func pySatisfies(v pyVersion, constraint string) (ok, evaluable bool) {
	if constraint == "" {
		return true, true
	}
	ok = true
	for _, clause := range strings.Split(constraint, ",") {
		cl, _, valid := parseSpecifierClause(clause)
		if !valid {
			return false, false
		}
		s, op, wild := cl.version, cl.op, cl.wildcard
		cand := v
		if len(s.local) == 0 {
			cand.local = nil // a specifier without a local label ignores the candidate's
		}
		c := cand.compare(s)
		var met bool
		switch op {
		case "==", "!=":
			if wild {
				met = cand.epoch == s.epoch && releasePrefixEqual(cand.release, s.release)
			} else {
				met = c == 0
			}
			if op == "!=" {
				met = !met
			}
		case ">=":
			met = c >= 0
		case "<=":
			met = c <= 0
		case ">":
			met = c > 0 && !(!s.hasPost && cand.hasPost && sameBase(cand, s))
		case "<":
			met = c < 0 && !(!s.isPrerelease() && cand.isPrerelease() && !cand.hasPost && cand.epoch == s.epoch && cmpRelease(cand.release, s.release) == 0)
		case "~=":
			met = c >= 0 && cand.epoch == s.epoch && releasePrefixEqual(cand.release, s.release[:len(s.release)-1])
		}
		if !met {
			ok = false
		}
	}
	return ok, true
}

// sameBase reports whether a and b are the same version apart from a
// post-release, dev and local part: the version a post-release belongs to.
func sameBase(a, b pyVersion) bool {
	return a.epoch == b.epoch && cmpRelease(a.release, b.release) == 0 &&
		a.hasPre == b.hasPre && (!a.hasPre || a.preKind == b.preKind && a.preNum == b.preNum)
}

// releasePrefixEqual compares the first len(prefix) release segments, a
// missing segment counting as zero.
func releasePrefixEqual(rel, prefix []string) bool {
	for i, p := range prefix {
		r := "0"
		if i < len(rel) {
			r = rel[i]
		}
		if r != p {
			return false
		}
	}
	return true
}

// relationOf says how the occurrences are required.
func relationOf(occs []SourceOccurrence) Relation {
	direct, transitive := false, false
	for _, o := range occs {
		if o.Direct {
			direct = true
		} else {
			transitive = true
		}
	}
	switch {
	case direct && transitive:
		return RelationMixed
	case direct:
		return RelationDirect
	case transitive:
		return RelationTransitive
	}
	return ""
}

func manualPackage(p *LanguagePackage, reason Reason, detail string) {
	p.Action, p.Reason, p.Detail = ActionManual, reason, detail
}

// matchPackage matches one running package against the unit's files and
// chooses its target version. Interactions between the groups of one name are
// settled afterwards by reconcileVersions.
func matchPackage(l *lockfile, g *findingGroup) LanguagePackage {
	sc := l.manager.scheme()
	p := LanguagePackage{Name: g.Name, Ecosystem: g.Type, Installed: g.Installed, CVEs: g.cves, Origins: g.origins}
	if sc == schemePEP440 {
		p.Normalized = normalizePyName(g.Name)
	}
	lp := l.lookup(g.Name)
	if lp == nil {
		manualPackage(&p, ReasonNotFoundInSource, "the dependency files do not list the package")
		return p
	}
	occs := append([]SourceOccurrence(nil), lp.occs...)
	matched := 0
	for i := range occs {
		if occs[i].Version != "" && versionsEqual(sc, occs[i].Version, g.Installed) {
			occs[i].Matched = true
			matched++
		}
	}
	p.Occurrences = occs

	if matched == 0 {
		return matchWithoutPin(l, g, p)
	}
	var ms []SourceOccurrence
	for _, o := range occs {
		if o.Matched {
			ms = append(ms, o)
		}
	}
	p.Relation = relationOf(ms)
	for _, o := range ms {
		if o.ManualReason != "" {
			manualPackage(&p, o.ManualReason, o.Detail)
			return p
		}
	}
	if why, forced := l.forced[l.key(g.Name)]; forced {
		manualPackage(&p, ReasonForcedByOverride, why)
		return p
	}
	target, reason, detail := chooseTarget(sc, g.Installed, g.cves)
	if reason != "" {
		manualPackage(&p, reason, detail)
		return p
	}
	p.SelectionLowerBound = target
	p.Action, p.Reason = ActionUpdate, ReasonUpdateCandidateInSource
	return p
}

// matchWithoutPin handles a package whose installed version is not listed:
// a requirements line that is not an exact pin, an entry from another source,
// or nothing.
func matchWithoutPin(l *lockfile, g *findingGroup, p LanguagePackage) LanguagePackage {
	sc := l.manager.scheme()
	var versions []string
	ranges, allRanges := 0, true
	for _, o := range p.Occurrences {
		if o.Unpinned && o.ManualReason == "" {
			ranges++
			continue
		}
		allRanges = false
		if o.ManualReason != "" && !versionParses(sc, o.Version) {
			p.Relation = relationOf(p.Occurrences)
			manualPackage(&p, o.ManualReason, o.Detail)
			return p
		}
		if o.Version != "" {
			versions = append(versions, o.Version)
		}
	}
	if l.manager != ManagerPip || ranges == 0 {
		manualPackage(&p, ReasonNotFoundInSource, fmt.Sprintf("the dependency files list the package at %s, not %s", strings.Join(versions, ", "), g.Installed))
		return p
	}
	p.Relation = relationOf(p.Occurrences)
	if !allRanges {
		manualPackage(&p, ReasonMultipleVersions, "the package is both pinned and given a version range")
		return p
	}
	if why, forced := l.forced[l.key(g.Name)]; forced {
		manualPackage(&p, ReasonForcedByOverride, why)
		return p
	}
	target, reason, detail := chooseTarget(sc, g.Installed, g.cves)
	if reason != "" {
		manualPackage(&p, reason, detail)
		return p
	}
	p.SelectionLowerBound = target
	tv, _ := parsePEP440(target)
	if tv.isPrerelease() {
		manualPackage(&p, ReasonRangeNotEvaluable, fmt.Sprintf("the fix %s is a pre-release, which pip does not select by default", target))
		return p
	}
	for _, o := range p.Occurrences {
		ok, evaluable := pySatisfies(tv, o.Constraint)
		switch {
		case !evaluable:
			manualPackage(&p, ReasonRangeNotEvaluable, fmt.Sprintf("the requirement %q cannot be judged", o.Constraint))
			return p
		case !ok:
			manualPackage(&p, ReasonRangeExcludesFix, fmt.Sprintf("the requirement %q does not allow %s", o.Constraint, target))
			return p
		}
	}
	p.Action, p.Reason = ActionRebuildExpected, ReasonRangeAllowsFix
	return p
}

// reconcileVersions settles packages that appear in the files more than
// once. The installed versions of one name can only be one update if every
// one of them will be updated to the same target version and every other
// occurrence is already at or above it. If any version or occurrence cannot
// be handled (a manual source, an unparsable fix, a version the files do not
// list), none of them is updated: all go to a person, with the occurrences
// kept.
func reconcileVersions(l *lockfile, pkgs []LanguagePackage) {
	sc := l.manager.scheme()
	byName := map[string][]int{}
	for i, p := range pkgs {
		byName[l.key(p.Name)] = append(byName[l.key(p.Name)], i)
	}
	for _, idxs := range byName {
		var updates []int
		why := ""
		covered := map[string]bool{} // versions that will be updated
		for _, i := range idxs {
			if pkgs[i].Action == ActionUpdate {
				updates = append(updates, i)
				covered[pkgs[i].Installed] = true
			} else if why == "" {
				why = fmt.Sprintf("the installed version %s of the package cannot be updated (%s)", pkgs[i].Installed, pkgs[i].Reason)
			}
		}
		if len(updates) == 0 {
			continue
		}
		var maxT version
		if why == "" {
			for _, i := range updates {
				tv, _ := parseVersion(sc, pkgs[i].SelectionLowerBound)
				if maxT == nil {
					maxT = tv
				} else if tv.compare(maxT) != 0 {
					why = fmt.Sprintf("the installed versions need different target versions (%s and %s)", pkgs[updates[0]].SelectionLowerBound, pkgs[i].SelectionLowerBound)
				}
			}
		}
		if why == "" {
			for _, o := range pkgs[updates[0]].Occurrences {
				if o.ManualReason != "" {
					why = fmt.Sprintf("the files list an occurrence at %s that cannot be updated (%s)", o.Path, o.ManualReason)
					break
				}
				if o.Version == "" {
					why = "the package is also given a version range"
					break
				}
				isCovered := false
				for v := range covered {
					if versionsEqual(sc, v, o.Version) {
						isCovered = true
					}
				}
				if isCovered {
					continue
				}
				if ov, ok := parseVersion(sc, o.Version); ok && ov.compare(maxT) >= 0 {
					continue
				}
				why = fmt.Sprintf("the files also list %s, which this update would not cover", o.Version)
				break
			}
		}
		if why == "" {
			continue
		}
		for _, i := range updates {
			pkgs[i].SelectionLowerBound = ""
			manualPackage(&pkgs[i], ReasonMultipleVersions, why)
		}
	}
}
