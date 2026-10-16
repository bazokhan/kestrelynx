package remediation

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// The chain update: a package that the first update could not take to its
// fixed version because a package that requires it asks for an older one is
// taken there by updating the chain of packages between it and the project's
// own direct dependency, within the ranges the project declares. This file
// holds what decides whether and where to do that; it runs no container.

// Limits of the chain, checked before it is tried (the number of entries it
// may move is checked on its result, see diffGraphsChain).
const (
	maxChainTops      = 5
	maxChainAncestors = 32
	maxChainMoves     = 64
)

// edgeClass says what the range a parent declares for a package does to the
// package's fixed version.
type edgeClass int

const (
	// edgeUnclassified: not judged.
	edgeUnclassified edgeClass = iota
	// edgePinning: the range allows no version that fixes the package, which
	// holds it at the version it has.
	edgePinning
	// edgeAllowsFix: the range allows the lowest fixed version, so the parent
	// does not hold the package back.
	edgeAllowsFix
	// edgeUnevaluable: neither of the above can be shown.
	edgeUnevaluable
)

// Proofs a pinning edge is established by.
const (
	proofExact      = "exact"
	proofUpperBound = "upper_bound"
)

// chainTop is a direct dependency of the project from which the chain starts:
// the group of the manifest that declares it and its range there.
type chainTop struct {
	Name, Group, Spec, Key string
}

// chainScope is what a chain update is allowed to move, found in the original
// lockfile's graph.
type chainScope struct {
	// Names are the names of the chain: the ancestors' and the tops'.
	Names map[string]bool
	// Blocked are the pinning requirements, the evidence for the chain.
	Blocked []ChainBlock
	// Bn are the names of the packages held back, Be the keys of their
	// entries that a pinning requirement points to, and Anc the keys of the
	// entries that require them (directly or through others) by requirements
	// that are not peer-only, the parents of the pinning requirements
	// included.
	Bn  []string
	Be  map[string]bool
	Anc map[string]bool
	// Tops are the project's direct dependencies the ancestors hang from.
	Tops []chainTop
	// The entries the update takes out of the lockfile to make them again:
	// the ancestors, the entries of the packages being updated (by name, as
	// Targets) and, for npm, the entries nested below either.
	RAnc, RTgt, RNest map[string]bool
	// Targets are the names of the packages the attempt updates.
	Targets map[string]bool
	// Scheme orders the versions of the manager.
	Scheme scheme
	// peers are the names, by the key of the entry that requires them, that
	// the registry declares as peer dependencies only.
	peers map[string]map[string]bool
}

// markPeerOnly marks, in a graph of the original lockfile, the requirements
// the registry declares as peer-only, for the entries that have the keys the
// scope was built with.
func (s *chainScope) markPeerOnly(g *depGraph) {
	g.link()
	for k, names := range s.peers {
		n := g.nodes[k]
		if n == nil {
			continue
		}
		for i := range n.deps {
			if names[n.deps[i].name] {
				n.deps[i].peerOnly = true
			}
		}
	}
}

// topNames are the names of the tops.
func (s *chainScope) topNames() map[string]bool {
	out := make(map[string]bool, len(s.Tops))
	for _, t := range s.Tops {
		out[t.Name] = true
	}
	return out
}

// chainCandidates are the matching names of the packages the first update did
// not take to their target, f being its failure (nil when it passed with
// packages left out). Only an update whose lockfile is known to be consistent
// with its manifest can say so: for npm and pnpm the lockfile unchanged, every
// package short of its target, or some short with the result unusable as it
// is; for uv a failed update step or a refused difference after the baseline
// was found consistent.
func chainCandidates(r *updateRun, f *updateFailure) []string {
	var names []string
	switch r.it.Manager {
	case ManagerNpm, ManagerPnpm:
		switch {
		case f == nil:
			for n := range r.leftOut {
				names = append(names, n)
			}
		case len(f.retryWithout) > 0:
			for n := range f.retryWithout {
				names = append(names, n)
			}
		case f.lockUnchanged || f.allUnreached:
			names = append(names, r.set.names...)
		}
	case ManagerUv:
		if f != nil && f.baselineVerified {
			names = append(names, r.set.names...)
		}
	}
	sort.Strings(names)
	return names
}

// excludeDeclared drops, from the names, those the project declares itself:
// in a dependency field of the manifest, in the project's own requirements in
// the lockfile, or by a requirement of the project that points to any entry of
// the package. Such a package is updated by the ordinary update only, which
// edits the declaration. The set the ordinary update works on is not changed.
func excludeDeclared(m DependencyManager, manifest []byte, g0 *depGraph, names []string) []string {
	declared := map[string]bool{}
	switch m {
	case ManagerNpm, ManagerPnpm:
		pj, err := readManifest(manifest)
		if err != nil {
			return nil
		}
		for _, f := range manifestDepFields {
			for n := range pj.deps[f] {
				declared[n] = true
			}
		}
	case ManagerUv:
		py, err := parseTOML(manifest)
		if err != nil {
			return nil
		}
		for _, e := range pyprojectRequirementEntries(py) {
			if name, _, ok := pythonRequirement(e.text); ok {
				declared[name] = true
			} else if nm := pipNameRE.FindStringSubmatch(strings.TrimSpace(e.text)); nm != nil {
				declared[normalizePyName(nm[1])] = true
			}
		}
	default:
		return nil
	}
	g0.link()
	for _, e := range g0.roots {
		declared[normalizeIfPython(m, e.name)] = true
		if n := g0.target(e); n != nil {
			declared[n.name] = true
		}
	}
	var out []string
	for _, n := range names {
		if !declared[n] {
			out = append(out, n)
		}
	}
	return out
}

// normEdge is a parent's requirement for a name as the registry declares it.
type normEdge struct {
	spec     string
	optional bool
	peerOnly bool
}

// normalizeParentEdges reads what a version of a package requires from the
// registry's declaration of it, never from the lockfile's record, and
// reduces the declarations to one requirement per name. A name only in the
// peer dependencies is peer-only. A name in both the dependencies and the
// optional dependencies with the same range is one optional requirement. A
// name whose ranges differ between the dependencies and the optional
// dependencies, or that is a peer dependency and a dependency or an optional
// one, cannot be reduced; the names are returned as unsupported.
func normalizeParentEdges(m DependencyManager, parent *depNode, d NpmDist) (edges map[string]normEdge, unsupported []string) {
	edges = map[string]normEdge{}
	bad := map[string]bool{}
	peers := d.peersFor(m)
	for name, spec := range d.Dependencies {
		edges[name] = normEdge{spec: spec}
	}
	for name, spec := range d.OptionalDependencies {
		if old, both := edges[name]; both && old.spec != spec {
			bad[name] = true
		}
		edges[name] = normEdge{spec: spec, optional: true}
	}
	for name, spec := range peers {
		if _, regular := edges[name]; regular {
			bad[name] = true
			continue
		}
		edges[name] = normEdge{spec: spec, optional: true, peerOnly: true}
	}
	for name := range bad {
		unsupported = append(unsupported, name)
	}
	sort.Strings(unsupported)
	return edges, unsupported
}

// exactVersionOf returns the version a range names when it names one version
// and nothing else: 1.2.3, =1.2.3 or v1.2.3.
func exactVersionOf(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	s = strings.TrimSpace(strings.TrimPrefix(s, "="))
	s = strings.TrimPrefix(s, "v")
	if _, ok := parseSemver(s); !ok {
		return "", false
	}
	return s, true
}

// minFixed is the lowest of the versions a vulnerability is reported fixed in.
func minFixed(c CVERef) (string, bool) {
	best := ""
	for _, f := range c.FixedVers {
		for _, one := range splitFixed(f) {
			if _, ok := parseSemver(one); !ok {
				return "", false
			}
			if best == "" {
				best = one
			} else if cmp, _ := compareVersions(schemeSemver, one, best); cmp < 0 {
				best = one
			}
		}
	}
	return best, best != ""
}

// classifyEdge judges the range spec of a requirement for a package, whose
// lowest fixed version is lower and whose vulnerabilities are cves, for npm
// and pnpm (semver).
//
//   - Pinning: the range is one version that does not fix some vulnerability,
//     or one set of comparators (no ||) with an upper bound that is not above
//     the lowest version some vulnerability is fixed in, so it allows no fixed
//     version.
//   - Allows the fix: the range can be evaluated and allows a version that
//     fixes every vulnerability (the lowest fixed version, or the first fixed
//     version of a line of releases).
//   - Unevaluable: anything else, a range with || that is not the former, a
//     tag, a range that cannot be read, no lowest fixed version.
func classifyEdge(spec string, lower string, cves []CVERef) edgeClass {
	c, _ := classifyEdgeProof(spec, lower, cves)
	return c
}

// classifyEdgeProof is classifyEdge with the proof a pinning requirement is
// established by.
func classifyEdgeProof(spec, lower string, cves []CVERef) (edgeClass, string) {
	if v, ok := exactVersionOf(spec); ok {
		for _, c := range cves {
			if !meetsFix(schemeSemver, v, c.FixedVers) {
				return edgePinning, proofExact
			}
		}
	} else if !strings.Contains(spec, "||") {
		if preds, valid := rangePredicates(spec); valid {
			for _, p := range preds {
				if p.op != "<" && p.op != "<=" {
					continue
				}
				u := strings.Join(p.val[:], ".")
				for _, c := range cves {
					m, ok := minFixed(c)
					if !ok {
						continue
					}
					cmp, _ := compareVersions(schemeSemver, u, m)
					if (p.op == "<" && cmp <= 0) || (p.op == "<=" && cmp < 0) {
						return edgePinning, proofUpperBound
					}
				}
			}
		}
	}
	// The range can be shown to allow a fixed version: the lowest one chosen
	// for the package, or the first fixed version of a line of releases the
	// vulnerabilities report (the lowest one may be in an older line than the
	// range's).
	candidates := []string{lower}
	for _, c := range cves {
		for _, f := range c.FixedVers {
			candidates = append(candidates, splitFixed(f)...)
		}
	}
	for _, cand := range candidates {
		lv, ok := parseSemver(cand)
		if !ok || len(cves) == 0 || !fixedAt(schemeSemver, cand, cves) {
			continue
		}
		if allowed, evaluable := npmRangeAllows(spec, lv); evaluable && allowed {
			return edgeAllowsFix, ""
		}
	}
	return edgeUnevaluable, ""
}

// cloneEdges returns a copy of the linked graph whose entries and requirement
// lists can be marked without changing the original; the numbers of the
// entries are the original's.
func (g *depGraph) cloneEdges() *depGraph {
	g.link()
	c := &depGraph{nodes: make(map[string]*depNode, len(g.nodes)), roots: append([]depEdge(nil), g.roots...), meta: g.meta,
		list: make([]*depNode, len(g.list)), linked: true}
	for i, n := range g.list {
		cn := *n
		cn.deps = append([]depEdge(nil), n.deps...)
		c.list[i] = &cn
		c.nodes[n.key] = &cn
	}
	return c
}

// chainNorm is a parent's requirements, normalized, or why they could not be.
type chainNorm struct {
	edges       map[string]normEdge
	unsupported map[string]bool
	unknown     string // why the registry's declaration is not known
}

// chainScoper builds the scope of one chain attempt.
type chainScoper struct {
	ctx   context.Context
	r     *updateRun
	g     *depGraph // the working copy of the original graph
	norms map[int]*chainNorm
	// names are the packages the scope is built for, and lookups how many
	// registry documents it has read.
	names   []string
	lookups int
}

// maxScopeLookups bounds the registry documents read to decide whether and
// where to start a chain update, before the item's budget applies to it.
const maxScopeLookups = 2*(maxChainTops+maxChainAncestors) + 64

// normalize reads the registry's declaration of the entry and marks the
// peer-only requirements in the working copy. A failure is a deferral: the
// item's limits or time ran out.
func (s *chainScoper) normalize(p *depNode) (*chainNorm, *updateFailure) {
	if cn, ok := s.norms[p.id]; ok {
		return cn, nil
	}
	cn := &chainNorm{unsupported: map[string]bool{}}
	s.norms[p.id] = cn
	if p.problem != "" {
		cn.unknown = p.name + " " + p.version + " is not a registry package"
		return cn, nil
	}
	if s.lookups++; s.lookups > maxScopeLookups {
		return nil, unsupportedChain(s.names, ReasonDependentsLimit, "deciding where to start the update needs more than %d registry lookups", maxScopeLookups)
	}
	d, err := s.r.npmRelease(s.ctx, p.name, p.version)
	switch {
	case err == nil:
	case isItemBudget(err) != "" || s.ctx.Err() != nil:
		return nil, lookupFailure(s.ctx, err, p.name+" "+p.version+" in the npm registry")
	default:
		cn.unknown = fmt.Sprintf("the registry's declaration of %s %s is not known: %v", p.name, p.version, clip(err.Error(), 100))
		return cn, nil
	}
	var bad []string
	cn.edges, bad = normalizeParentEdges(s.r.it.Manager, p, d)
	for _, n := range bad {
		cn.unsupported[n] = true
	}
	for i := range p.deps {
		if ne, ok := cn.edges[p.deps[i].name]; ok {
			p.deps[i].peerOnly = ne.peerOnly
		}
	}
	return cn, nil
}

// unsupportedChain is the failure of an attempt that cannot be made with the
// inputs it has; every package held back gets the reason.
func unsupportedChain(names []string, reason Reason, format string, args ...any) *updateFailure {
	f := manualFailure(reason, format, args...)
	f.pkgs = map[string]updateFailureDetail{}
	for _, n := range names {
		f.pkgs[n] = updateFailureDetail{reason, f.detail}
	}
	return f
}

// buildChainScope finds, in the original graph g0, the packages of U that the
// project does not declare and that a requirement holds at a version below the
// fixed one, the entries that require them, and the direct dependencies the
// chain starts from. It returns no scope and no failure when there is nothing
// to try: no package is held back, or the first update's reason stands. It
// returns a failure when the attempt is refused (unsupported inputs or over a
// limit, with a reason for each package held back), or an item's limit or time
// ran out (a deferral).
func buildChainScope(ctx context.Context, r *updateRun, g0 *depGraph, U []string) (*chainScope, *updateFailure) {
	m := r.it.Manager
	if m != ManagerNpm && m != ManagerPnpm {
		return nil, nil
	}
	cand := excludeDeclared(m, r.src.manifest, g0, U)
	if len(cand) == 0 {
		return nil, nil
	}
	sc := m.scheme()
	g := g0.cloneEdges()
	rev := g.reverseIndex()
	// The lookups are the item's but not yet bound by its budget, and the
	// first update's own limit on them does not apply.
	sr := *r
	sr.chain = &chainScope{}
	s := &chainScoper{ctx: ctx, r: &sr, g: g, norms: map[int]*chainNorm{}, names: cand}

	scope := &chainScope{Names: map[string]bool{}, Be: map[string]bool{}, Anc: map[string]bool{},
		RAnc: map[string]bool{}, RTgt: map[string]bool{}, RNest: map[string]bool{}, Targets: map[string]bool{}, Scheme: sc}

	// Which occurrences of each package are held, and by what.
	var pinParents []int
	for _, n := range cand {
		lower := r.full.target[n]
		var cves []CVERef
		for _, i := range r.full.byName[n] {
			cves = append(cves, r.it.Packages[i].CVEs...)
		}
		type held struct {
			key    string
			blocks []ChainBlock
			parent []int
		}
		var occs []held
		ok := true
	occurrences:
		for _, node := range g.list {
			if node.name != n || fixedAt(sc, node.version, cves) {
				continue
			}
			if len(rev.roots[node.id]) > 0 {
				ok = false
				break
			}
			h := held{key: node.key}
			seen := map[int]bool{}
			for _, ref := range rev.from[node.id] {
				p := g.list[ref.node]
				if seen[p.id] {
					continue
				}
				seen[p.id] = true
				cn, fail := s.normalize(p)
				if fail != nil {
					return nil, fail
				}
				edge := p.deps[ref.edge]
				ne, found := cn.edges[edge.name]
				switch {
				case cn.unknown != "" || !found || edge.local:
					ok = false
					break occurrences
				case cn.unsupported[edge.name]:
					return nil, unsupportedChain(cand, ReasonDependentsUnsupported, "%s %s declares %s in a way that cannot be reduced to one requirement (a peer dependency that is also a dependency, or different ranges in dependencies and optionalDependencies)", p.name, p.version, edge.name)
				case ne.peerOnly:
					ok = false
					break occurrences
				}
				cls, proof := classifyEdgeProof(ne.spec, lower, cves)
				p.deps[ref.edge].class = cls
				switch cls {
				case edgeUnevaluable:
					ok = false
					break occurrences
				case edgePinning:
					h.blocks = append(h.blocks, ChainBlock{Package: n, Version: node.version, Parent: p.name, ParentVersion: p.version, Range: ne.spec, Proof: proof})
					h.parent = append(h.parent, p.id)
				}
			}
			occs = append(occs, h)
		}
		if !ok {
			continue
		}
		pinned := false
		for _, h := range occs {
			if len(h.blocks) > 0 {
				pinned = true
				scope.Be[h.key] = true
				scope.Blocked = append(scope.Blocked, h.blocks...)
				pinParents = append(pinParents, h.parent...)
			}
		}
		if pinned {
			scope.Bn = append(scope.Bn, n)
		}
	}
	if len(scope.Bn) == 0 {
		return nil, nil
	}
	sort.Strings(scope.Bn)
	bn := scope.Bn

	// The attempt updates what the first update reached and what it could not
	// reach because it was held, and not the packages left to the ordinary
	// update's reason.
	unreached := map[string]bool{}
	for _, n := range U {
		unreached[n] = true
	}
	for _, n := range r.full.names {
		if !unreached[n] {
			scope.Targets[n] = true
		}
	}
	for _, n := range bn {
		scope.Targets[n] = true
	}

	// The ancestors: walk the requirements backwards from the parents of the
	// pinning requirements, reading each parent's declaration as it is met so
	// that a peer-only requirement is not followed.
	var bases map[string][]int
	if m == ManagerPnpm {
		bases = map[string][]int{}
		for _, n := range g.list {
			b := pnpmBase(n.key)
			bases[b] = append(bases[b], n.id)
		}
	}
	visited := make([]bool, len(g.list))
	var queue []int
	push := func(id int) {
		if !visited[id] {
			visited[id] = true
			queue = append(queue, id)
		}
	}
	for _, id := range pinParents {
		push(id)
	}
	var rootEdges []int
	for steps := 0; len(queue) > 0; steps++ {
		if steps%1024 == 0 && ctx.Err() != nil {
			return nil, &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		x := g.list[id]
		scope.Anc[x.key] = true
		if len(scope.Anc) > maxChainAncestors {
			return nil, unsupportedChain(bn, ReasonDependentsLimit, "re-resolving would move more than %d packages that require the held back packages", maxChainAncestors)
		}
		if bases != nil {
			for _, sib := range bases[pnpmBase(x.key)] {
				push(sib)
			}
		}
		rootEdges = append(rootEdges, rev.roots[id]...)
		for _, ref := range rev.from[id] {
			p := g.list[ref.node]
			cn, fail := s.normalize(p)
			if fail != nil {
				return nil, fail
			}
			edge := p.deps[ref.edge]
			switch {
			case cn.unknown != "":
				return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s", cn.unknown)
			case cn.unsupported[edge.name]:
				return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s %s declares %s in a way that cannot be reduced to one requirement", p.name, p.version, edge.name)
			}
			if _, found := cn.edges[edge.name]; !found {
				return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "the registry does not list %s among the requirements of %s %s", edge.name, p.name, p.version)
			}
			if g.list[ref.node].deps[ref.edge].peerOnly {
				continue
			}
			push(p.id)
		}
	}

	// The tops: the project's requirements that point to an ancestor.
	if len(rootEdges) == 0 {
		return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "no direct dependency of the project leads to the held back packages")
	}
	pj, err := readManifest(r.src.manifest)
	if err != nil {
		return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%v", err)
	}
	seenTop := map[string]bool{}
	for _, i := range rootEdges {
		e := g.roots[i]
		if e.local {
			return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s is required by the project from a local or non-registry location", e.name)
		}
		if seenTop[e.name] {
			continue
		}
		seenTop[e.name] = true
		top := chainTop{Name: e.name, Key: e.key, Spec: e.ref}
		for _, f := range manifestDepFields {
			if spec, ok := pj.deps[f][e.name]; ok {
				top.Group, top.Spec = f, spec
				break
			}
		}
		scope.Tops = append(scope.Tops, top)
	}
	sort.Slice(scope.Tops, func(i, j int) bool { return scope.Tops[i].Name < scope.Tops[j].Name })
	if len(scope.Tops) > maxChainTops {
		return nil, unsupportedChain(bn, ReasonDependentsLimit, "re-resolving would start from %d direct dependencies, more than the %d allowed", len(scope.Tops), maxChainTops)
	}

	// The direct dependencies each pinning parent hangs below.
	for i := range scope.Blocked {
		seenNode := map[int]bool{pinParents[i]: true}
		queue := []int{pinParents[i]}
		via := map[string]bool{}
		for len(queue) > 0 {
			id := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			for _, ri := range rev.roots[id] {
				via[g.roots[ri].name] = true
			}
			for _, ref := range rev.from[id] {
				if !g.list[ref.node].deps[ref.edge].peerOnly && !seenNode[ref.node] {
					seenNode[ref.node] = true
					queue = append(queue, ref.node)
				}
			}
		}
		scope.Blocked[i].Via = sortedSet(via)
	}
	for k := range scope.Anc {
		scope.RAnc[k] = true
		scope.Names[g.nodes[k].name] = true
	}
	for _, t := range scope.Tops {
		scope.Names[t.Name] = true
	}

	// What cannot be updated by taking entries out: entries that are not
	// registry packages, packages fixed by overrides, packages the plan left
	// to a person for another reason.
	for k := range scope.Anc {
		if n := g.nodes[k]; n.problem != "" {
			return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s %s: %s", n.name, n.version, n.problem)
		}
	}
	for _, p := range g.list {
		if !scope.Anc[p.key] {
			continue
		}
		for _, ref := range rev.from[p.id] {
			if g.list[ref.node].deps[ref.edge].local && scope.Anc[g.list[ref.node].key] {
				return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s requires %s from a local or non-registry location", g.list[ref.node].name, p.name)
			}
		}
	}
	lf, err := parseLockfileFor(m, r.src.manifest, r.src.lock)
	if err != nil {
		return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "the original lockfile cannot be read: %v", err)
	}
	for n := range scope.Names {
		if why, forced := lf.forced[lf.key(n)]; forced {
			return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s: %s", n, why)
		}
	}
	for n := range scope.Targets {
		if why, forced := lf.forced[lf.key(n)]; forced {
			return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s: %s", n, why)
		}
	}
	for _, p := range r.it.Packages {
		if p.Action == ActionManual && !p.LeftOut && scope.Names[p.matchName()] {
			return nil, unsupportedChain(bn, ReasonDependentsUnsupported, "%s is left to a person for another reason: %s", p.Name, p.Detail)
		}
	}

	scope.peers = map[string]map[string]bool{}
	for id, cn := range s.norms {
		for name, ne := range cn.edges {
			if ne.peerOnly {
				k := g.list[id].key
				if scope.peers[k] == nil {
					scope.peers[k] = map[string]bool{}
				}
				scope.peers[k][name] = true
			}
		}
	}

	// The entries to take out.
	for _, n := range g.list {
		if scope.Targets[n.name] {
			scope.RTgt[n.key] = true
		}
	}
	if m == ManagerNpm {
		for _, n := range g.list {
			for _, a := range npmAncestors(n.key) {
				if scope.RAnc[a] || scope.RTgt[a] {
					if !scope.RAnc[n.key] && !scope.RTgt[n.key] {
						scope.RNest[n.key] = true
					}
					break
				}
			}
		}
	}
	return scope, nil
}

// fixedAt reports whether the version meets the fix of every vulnerability.
func fixedAt(sc scheme, v string, cves []CVERef) bool {
	for _, c := range cves {
		if !meetsFix(sc, v, c.FixedVers) {
			return false
		}
	}
	return true
}
