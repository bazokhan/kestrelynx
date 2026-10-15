package remediation

import (
	"context"
	"fmt"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// chainScanBasis names what a chain update's findings are compared by.
const chainScanBasis = "package_version_vuln_edges"

// chainTriple is a vulnerability of one version of a package.
type chainTriple struct{ name, version, vuln string }

// evaluateChainScan judges the scans of the dependency files before and after
// a chain update more strictly than evaluateSourceCheck, which compares a
// package's vulnerabilities apart from its version. A chain update moves
// packages the project did not name, so it must not bring a vulnerability of a
// version that was not there, nor more entries of a vulnerable version, nor
// more requirements on one:
//
//   - a (package, version, vulnerability) found only after is new;
//   - for each found in both, the entries of that package at that version are
//     not more than before;
//   - for each (package, vulnerability) found after, the requirements, the
//     project's included, that point to an entry of the package at a version
//     that has the vulnerability are not more than before.
//
// What it does not see is written in the design of the update: the number of
// paths from the project to a vulnerable entry, which requirements swapped
// places with the count unchanged, a vulnerability the scan does not know or
// reports outside the severities asked for.
//
// g0 and g1 are the graphs of the two lockfiles as the format writes them (for
// pnpm the entries are the snapshots, for uv a package at a version is one
// entry however many forks it is in). The counts and the basis are recorded on
// sc.
func evaluateChainScan(sc *SourceCheck, before, after scanner.ImageScan, g0, g1 *depGraph, typ string, key func(string) string, kev func(vulnID string) bool) *updateFailure {
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
	for _, t := range newOnes {
		f := t1[t]
		v := SourceVuln{Package: f.Package, Version: f.InstalledVer, VulnID: t.vuln, Severity: f.Severity, FixedVer: f.FixedVer, KEV: kev(t.vuln)}
		anyKEV = anyKEV || v.KEV
		sc.ChainNewTriples = append(sc.ChainNewTriples, v)
	}

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
	for _, t := range remaining {
		b, a := e0[chainTriple{t.name, t.version, ""}], e1[chainTriple{t.name, t.version, ""}]
		if a > b {
			entryGrowth = append(entryGrowth, t)
			sc.ChainEntryGrowth = append(sc.ChainEntryGrowth, ChainCount{Package: t1[t].Package, Version: t.version, VulnID: t.vuln, Before: b, After: a})
			anyKEV = anyKEV || kev(t.vuln)
		}
	}

	// The requirements that point to a vulnerable entry of a package, by
	// package and vulnerability.
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
	for _, k := range pairs {
		b, a := sumEdges(into0, k[0], v0[k]), sumEdges(into1, k[0], v1[k])
		if a > b {
			display := k[0]
			for t, f := range t1 {
				if t.name == k[0] {
					display = f.Package
					break
				}
			}
			edgeGrowth++
			sc.ChainEdgeGrowth = append(sc.ChainEdgeGrowth, ChainCount{Package: display, VulnID: k[1], Before: b, After: a})
			anyKEV = anyKEV || kev(k[1])
		}
	}
	if len(sc.ChainNewTriples) > maxSourceVulns {
		sc.ChainNewTriples, sc.Truncated = sc.ChainNewTriples[:maxSourceVulns], true
	}
	for _, l := range []*[]ChainCount{&sc.ChainEntryGrowth, &sc.ChainEdgeGrowth} {
		if len(*l) > maxSourceVulns {
			*l, sc.Truncated = (*l)[:maxSourceVulns], true
		}
	}

	var what string
	switch {
	case len(newOnes) > 0:
		f := newOnes[0]
		what = fmt.Sprintf("the update introduces %d vulnerabilities of package versions that were not there, such as %s for %s %s", len(newOnes), f.vuln, t1[f].Package, f.version)
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
	return evaluateChainScan(sc, before, after, g0, g1, sourceScanTypes[m], key, kev)
}
