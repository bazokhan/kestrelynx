package remediation

import (
	"context"
	"fmt"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// chainScanBasis names what a chain update's findings are compared by when no
// position check ran, and chainScanPositionsBasis when it did.
const (
	chainScanBasis          = "package_version_vuln_edges"
	chainScanPositionsBasis = "package_version_vuln_edges_positions"
)

// chainTriple is a vulnerability of one version of a package.
type chainTriple struct{ name, version, vuln string }

// evaluateChainScan judges the scans of the dependency files before and after
// a chain update more strictly than evaluateSourceCheck, which compares a
// package's vulnerabilities apart from its version and its place. A chain
// update moves packages the project did not name, so it must not bring a
// vulnerability that was not there, nor more entries of a vulnerable version,
// nor more requirements on one:
//
//   - a (package, version, vulnerability) found only after is new, unless it is
//     carried (see below);
//   - for each found in both, the entries of that package at that version are
//     not more than before;
//   - for each (package, vulnerability) found after, the entries of the package
//     at the versions that have it, and the requirements, the project's
//     included, that point to them, are not more than before.
//
// With the graphs the two lockfiles are compared in (cmp), the requirements are
// also judged by place. A place is a requirement reached from the project
// parent by parent, with the same name, kind (peer or regular) and marker at
// every step. Every requirement into an entry that has a vulnerability after
// the update, except one the original had as it is, must stand at a place where
// the original had a requirement for exactly one entry of the same package, and
// the vulnerabilities of the new entry must be among that entry's; no entry of
// the original may become two vulnerable entries. A vulnerability found only
// after whose every requirement passes is carried: the package there only moved
// to another version that keeps the vulnerability. Carrying does not fix it.
//
// What it does not see: the number of paths from the project to a vulnerable
// entry; a vulnerability taken to be the same issue in every version that
// carries its ID; versions that swap between corresponding places; a
// vulnerability the scan does not know or reports outside the severities asked
// for; and the packages the scan does not analyse.
//
// g0 and g1 are the graphs of the two lockfiles as the format writes them (for
// pnpm the entries are the snapshots, for uv a package at a version is one
// entry however many forks it is in). The counts, the carried vulnerabilities,
// the refusals and the basis are recorded on sc.
func evaluateChainScan(sc *SourceCheck, before, after scanner.ImageScan, g0, g1 *depGraph, typ string, key func(string) string, kev func(vulnID string) bool) *updateFailure {
	return evaluateChainScanWith(context.Background(), sc, before, after, g0, g1, [2]*depGraph{}, ManagerNpm, typ, key, kev)
}

// evaluateChainScanWith is evaluateChainScan with the comparison graphs of the
// two lockfiles for the position check (both nil for the stricter comparison
// without it) and the manager they are of.
func evaluateChainScanWith(ctx context.Context, sc *SourceCheck, before, after scanner.ImageScan, g0, g1 *depGraph, cmp [2]*depGraph, m DependencyManager, typ string, key func(string) string, kev func(vulnID string) bool) *updateFailure {
	sc.Basis = chainScanBasis
	triples := func(s scanner.ImageScan) map[chainTriple]scanner.Finding {
		out := map[chainTriple]scanner.Finding{}
		for _, f := range s.Findings {
			if f.Type == typ {
				out[chainTriple{key(f.Package), f.InstalledVer, f.VulnID}] = f
			}
		}
		return out
	}
	t0, t1 := triples(before), triples(after)

	var newOnes []chainTriple
	for t := range t1 {
		if _, was := t0[t]; !was {
			newOnes = append(newOnes, t)
		}
	}
	sortTriples(newOnes)
	anyKEV := false

	entries := func(g *depGraph) map[chainTriple]int {
		out := map[chainTriple]int{}
		for _, n := range g.nodes {
			out[chainTriple{key(n.name), n.version, ""}]++
		}
		return out
	}
	e0, e1 := entries(g0), entries(g1)
	var remaining []chainTriple
	for t := range t1 {
		if _, was := t0[t]; was {
			remaining = append(remaining, t)
		}
	}
	sortTriples(remaining)
	var entryGrowth []chainTriple
	edgeGrowth := 0
	grew := map[[2]string]bool{}          // (package, vulnerability) whose counts grew
	grewByVersion := map[[2]string]bool{} // those whose entries of one version grew
	for _, t := range remaining {
		b, a := e0[chainTriple{t.name, t.version, ""}], e1[chainTriple{t.name, t.version, ""}]
		if a > b {
			entryGrowth = append(entryGrowth, t)
			grew[[2]string{t.name, t.vuln}] = true
			grewByVersion[[2]string{t.name, t.vuln}] = true
			sc.ChainEntryGrowth = append(sc.ChainEntryGrowth, ChainCount{Package: t1[t].Package, Version: t.version, VulnID: t.vuln, Before: b, After: a})
			anyKEV = anyKEV || kev(t.vuln)
		}
	}

	// The entries and the requirements that point to them, of a package at the
	// versions that have a vulnerability, by package and vulnerability.
	into0, into1 := edgeCounts(g0, key), edgeCounts(g1, key)
	versions := func(ts map[chainTriple]scanner.Finding) map[[2]string]map[string]bool {
		out := map[[2]string]map[string]bool{}
		for t := range ts {
			k := [2]string{t.name, t.vuln}
			if out[k] == nil {
				out[k] = map[string]bool{}
			}
			out[k][t.version] = true
		}
		return out
	}
	v0, v1 := versions(t0), versions(t1)
	pairs := make([][2]string, 0, len(v1))
	for k := range v1 {
		pairs = append(pairs, k)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	display := func(name string) string {
		for t, f := range t1 {
			if t.name == name {
				return f.Package
			}
		}
		return name
	}
	for _, k := range pairs {
		if b, a := sumEntries(e0, k[0], v0[k]), sumEntries(e1, k[0], v1[k]); a > b && !grewByVersion[k] {
			entryGrowth = append(entryGrowth, chainTriple{name: k[0], vuln: k[1]})
			grew[k] = true
			sc.ChainEntryGrowth = append(sc.ChainEntryGrowth, ChainCount{Package: display(k[0]), VulnID: k[1], Before: b, After: a})
			anyKEV = anyKEV || kev(k[1])
		}
		if b, a := sumEdges(into0, k[0], v0[k]), sumEdges(into1, k[0], v1[k]); a > b {
			edgeGrowth++
			grew[k] = true
			sc.ChainEdgeGrowth = append(sc.ChainEdgeGrowth, ChainCount{Package: display(k[0]), VulnID: k[1], Before: b, After: a})
			anyKEV = anyKEV || kev(k[1])
		}
	}

	// The position check.
	stillNew := newOnes
	var refusals []ChainPositionRefusal
	if cmp[0] != nil && cmp[1] != nil {
		sc.Basis = chainScanPositionsBasis
		corr, err := buildCorrespondence(ctx, cmp[0], cmp[1], m)
		if err != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
		}
		res := checkPositions(positionInput{
			m: m, cmp0: cmp[0], cmp1: cmp[1], corr: corr, key: key, kev: kev,
			vuln0: vulnsByVersion(t0), vuln1: vulnsByVersion(t1), newTriples: newOnes,
			display: func(t chainTriple) string { return t1[t].Package },
			// A vulnerability whose counts grew is not carried.
			grew: grew,
		})
		refusals, stillNew = res.refusals, res.stillNew
		sc.ChainCarried = res.carried
		anyKEV = anyKEV || res.anyKEV
	}
	for _, t := range stillNew {
		f := t1[t]
		v := SourceVuln{Package: f.Package, Version: f.InstalledVer, VulnID: t.vuln, Severity: f.Severity, FixedVer: f.FixedVer, KEV: kev(t.vuln)}
		anyKEV = anyKEV || v.KEV
		sc.ChainNewTriples = append(sc.ChainNewTriples, v)
	}
	sc.ChainPositionRefusals = refusals
	if len(sc.ChainNewTriples) > maxSourceVulns {
		sc.ChainNewTriples, sc.Truncated = sc.ChainNewTriples[:maxSourceVulns], true
	}
	if len(sc.ChainCarried) > maxSourceVulns {
		sc.ChainCarried, sc.Truncated = sc.ChainCarried[:maxSourceVulns], true
	}
	if len(sc.ChainPositionRefusals) > maxSourceVulns {
		sc.ChainPositionRefusals, sc.Truncated = sc.ChainPositionRefusals[:maxSourceVulns], true
	}
	for _, l := range []*[]ChainCount{&sc.ChainEntryGrowth, &sc.ChainEdgeGrowth} {
		if len(*l) > maxSourceVulns {
			*l, sc.Truncated = (*l)[:maxSourceVulns], true
		}
	}

	var what string
	switch {
	case len(refusals) > 0:
		what = refusals[0].describe(len(refusals))
	case len(stillNew) > 0:
		f := stillNew[0]
		what = fmt.Sprintf("the update introduces %d vulnerabilities of package versions that were not there, such as %s for %s %s", len(stillNew), f.vuln, t1[f].Package, f.version)
	case len(entryGrowth) > 0:
		g := sc.ChainEntryGrowth[0]
		what = fmt.Sprintf("the update adds entries of vulnerable versions, such as %s %s (%s), from %d to %d", g.Package, g.Version, g.VulnID, g.Before, g.After)
	case edgeGrowth > 0:
		g := sc.ChainEdgeGrowth[0]
		what = fmt.Sprintf("the update adds requirements on entries with a vulnerability, such as %s for %s, from %d to %d", g.VulnID, g.Package, g.Before, g.After)
	default:
		return nil
	}
	sc.Passed = false
	if anyKEV {
		return manualFailure(ReasonSourceIntroducedKEV, "%s (KEV-listed)", what)
	}
	return manualFailure(ReasonSourceIntroduced, "%s", what)
}

// vulnsByVersion are the vulnerability IDs the findings give a package at a
// version, by (package, version).
func vulnsByVersion(ts map[chainTriple]scanner.Finding) map[[2]string]map[string]bool {
	out := map[[2]string]map[string]bool{}
	for t := range ts {
		k := [2]string{t.name, t.version}
		if out[k] == nil {
			out[k] = map[string]bool{}
		}
		out[k][t.vuln] = true
	}
	return out
}

// sumEntries adds the counts of the entries of the package at the versions.
func sumEntries(counts map[chainTriple]int, name string, versions map[string]bool) int {
	total := 0
	for v := range versions {
		total += counts[chainTriple{name, v, ""}]
	}
	return total
}

func sortTriples(ts []chainTriple) {
	sort.Slice(ts, func(i, j int) bool {
		a, b := ts[i], ts[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.version != b.version {
			return a.version < b.version
		}
		return a.vuln < b.vuln
	})
}

// edgeCounts counts, for each entry, the requirements that point to it: the
// project's and every entry's, peer requirements included. Requirements of
// one parent for one name that point to the same entry with the same marker
// are counted once; requirements with other markers count apart.
func edgeCounts(g *depGraph, key func(string) string) map[string]map[string]int {
	g.link()
	type edge struct{ parent, name, target, marker string }
	seen := map[edge]bool{}
	byName := map[string]map[string]int{} // package -> entry key -> count
	count := func(parent string, es []depEdge) {
		for _, e := range es {
			n := g.target(e)
			if n == nil {
				continue
			}
			k := edge{parent, e.name, n.key, e.marker}
			if seen[k] {
				continue
			}
			seen[k] = true
			name := key(n.name)
			if byName[name] == nil {
				byName[name] = map[string]int{}
			}
			byName[name][n.key]++
		}
	}
	count("", g.roots)
	for _, n := range g.list {
		count(n.key, n.deps)
	}
	// The counts are given by version, which is what the findings name.
	out := map[string]map[string]int{}
	for name, byKey := range byName {
		out[name] = map[string]int{}
		for k, c := range byKey {
			out[name][g.nodes[k].version] += c
		}
	}
	return out
}

// sumEdges adds the counts of the requirements that point to the package at
// the versions.
func sumEdges(counts map[string]map[string]int, name string, versions map[string]bool) int {
	total := 0
	for v := range versions {
		total += counts[name][v]
	}
	return total
}

// chainSourceCheck is the comparison a chain update's scans get after the
// ordinary one passed: see evaluateChainScan.
func (r *updateRun) chainSourceCheck(ctx context.Context, sc *SourceCheck, before, after scanner.ImageScan, lockBefore, lockAfter []byte) *updateFailure {
	m := r.it.Manager
	g0, err0 := buildGraph(ctx, m, lockBefore)
	g1, err1 := buildGraph(ctx, m, lockAfter)
	if err0 != nil || err1 != nil {
		if ctx.Err() != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return manualFailure(ReasonOutputFilesInvalid, "the dependency graph cannot be read: %v", clip(fmt.Sprint(err0, err1), 200))
	}
	key := func(n string) string {
		if m.scheme() == schemePEP440 {
			return normalizePyName(n)
		}
		return n
	}
	kev := func(id string) bool {
		in, ok := r.u.cfg.Intel.lookup(id)
		return ok && in.KEV
	}
	return evaluateChainScanWith(ctx, sc, before, after, g0, g1, r.chainCmp, m, sourceScanTypes[m], key, kev)
}
