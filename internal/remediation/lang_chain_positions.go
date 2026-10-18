package remediation

import (
	"context"
	"fmt"
	"sort"
)

// posKey is a place in the dependency graph where a requirement stands: the
// entry that holds it (by key; "" is the project), the name it asks for and its
// marker.
type posKey struct{ parent, name, marker string }

// chainCorrespondence says, for the requirements of an updated lockfile, which
// requirements of the original stood at the same place: reached from the
// project parent by parent, with the same name, kind and marker at every step.
type chainCorrespondence struct {
	// old maps a place of the updated lockfile to the keys of the entries the
	// requirements at the corresponding places of the original pointed to.
	old map[posKey]map[string]bool
	// new maps the key of an entry of the original to the keys of the entries of
	// the updated lockfile that its places lead to, requirements that did not
	// change included.
	new map[string]map[string]bool
}

// Kinds of a requirement: a peer requirement is one the package records as a
// peer dependency, any other (optional ones included) is regular.
const (
	kindPeer    = "peer"
	kindRegular = "regular"
)

// edgeKind tells the kind of a requirement of parent (nil for the project) as
// the lockfile records it: npm marks the requirements that came from the
// peerDependencies of an entry, pnpm records the peer ranges of a package, and
// uv has no peer requirements.
func edgeKind(m DependencyManager, parent *depNode, e depEdge) string {
	switch m {
	case ManagerNpm:
		if e.lockPeer {
			return kindPeer
		}
	case ManagerPnpm:
		if parent != nil {
			if _, ok := parent.peerRanges[e.name]; ok {
				return kindPeer
			}
		}
	}
	return kindRegular
}

// posEdge is a requirement of one parent with its kind.
type posEdge struct {
	e    depEdge
	kind string
}

// positionEdges lists the requirements of one parent by name, the duplicates
// joined: requirements for one name that point to the same entry with the same
// range, marker and kind are one.
func positionEdges(m DependencyManager, parent *depNode, es []depEdge) map[string][]posEdge {
	out := map[string][]posEdge{}
	for _, e := range es {
		pe := posEdge{e, edgeKind(m, parent, e)}
		dup := false
		for _, x := range out[e.name] {
			if x.e.key == e.key && x.e.ref == e.ref && x.e.marker == e.marker && x.kind == pe.kind {
				dup = true
				break
			}
		}
		if !dup {
			out[e.name] = append(out[e.name], pe)
		}
	}
	return out
}

// requirementsOf are the requirements of the entry with the key, or of the
// project for "".
func requirementsOf(g *depGraph, key string) (*depNode, []depEdge) {
	if key == "" {
		return nil, g.roots
	}
	n := g.nodes[key]
	if n == nil {
		return nil, nil
	}
	return n, n.deps
}

// sameRecordAndEdges reports whether the entry with the key has the same
// record and the same resolved requirements (name, kind, marker and entry
// pointed to) in both lockfiles. The record alone is not enough: the attributes
// of a pnpm or uv entry leave out what it requires.
func sameRecordAndEdges(m DependencyManager, before, after *depGraph, key string) bool {
	n0, es0 := requirementsOf(before, key)
	n1, es1 := requirementsOf(after, key)
	if n0 == nil || n1 == nil || n0.attrs != n1.attrs {
		return false
	}
	set := func(n *depNode, es []depEdge) map[[4]string]bool {
		out := map[[4]string]bool{}
		for _, list := range positionEdges(m, n, es) {
			for _, pe := range list {
				out[[4]string{pe.e.name, pe.kind, pe.e.marker, pe.e.key}] = true
			}
		}
		return out
	}
	a, b := set(n0, es0), set(n1, es1)
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// unchangedEdge reports whether a requirement of the updated lockfile is one
// the original had as it is: the same parent and the same entry pointed to
// (each with the same record and the same requirements), and the same name,
// kind and marker.
func unchangedEdge(m DependencyManager, before, after *depGraph, parent string, e depEdge) bool {
	p1, _ := requirementsOf(after, parent)
	p0, es0 := requirementsOf(before, parent)
	if parent != "" && !sameRecordAndEdges(m, before, after, parent) {
		return false
	}
	t1 := after.target(e)
	if t1 == nil || !sameRecordAndEdges(m, before, after, t1.key) {
		return false
	}
	kind := edgeKind(m, p1, e)
	for _, x := range es0 {
		if x.name == e.name && x.key == e.key && x.marker == e.marker && edgeKind(m, p0, x) == kind {
			return true
		}
	}
	return false
}

// buildCorrespondence walks the two lockfiles from the project at once, parent
// by parent. A pair of entries is followed through the names for which each has
// one requirement of the same kind and marker; those two requirements stand at
// the same place, and the entries they point to correspond. Only regular
// requirements are followed further; a peer requirement is recorded and not
// followed. A pair whose requirements differ in kind or marker records nothing
// and is not followed. Requirements that did not change are entered in the map
// of the original's entries even where the walk does not reach them.
func buildCorrespondence(ctx context.Context, before, after *depGraph, m DependencyManager) (*chainCorrespondence, error) {
	before.link()
	after.link()
	c := &chainCorrespondence{old: map[posKey]map[string]bool{}, new: map[string]map[string]bool{}}
	add := func(m map[string]map[string]bool, k, v string) {
		if m[k] == nil {
			m[k] = map[string]bool{}
		}
		m[k][v] = true
	}
	type pair struct{ k0, k1 string }
	seen := map[pair]bool{{"", ""}: true}
	queue := []pair{{"", ""}}
	for steps := 0; len(queue) > 0; steps++ {
		if steps%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		p := queue[0]
		queue = queue[1:]
		n0, es0 := requirementsOf(before, p.k0)
		n1, es1 := requirementsOf(after, p.k1)
		l0, l1 := positionEdges(m, n0, es0), positionEdges(m, n1, es1)
		for name, a := range l0 {
			b := l1[name]
			if len(a) != 1 || len(b) != 1 || a[0].kind != b[0].kind || a[0].e.marker != b[0].e.marker {
				continue
			}
			c0, c1 := before.target(a[0].e), after.target(b[0].e)
			if c0 == nil || c1 == nil {
				continue
			}
			pos := posKey{p.k1, name, b[0].e.marker}
			if c.old[pos] == nil {
				c.old[pos] = map[string]bool{}
			}
			c.old[pos][c0.key] = true
			add(c.new, c0.key, c1.key)
			if a[0].kind == kindRegular {
				if next := (pair{c0.key, c1.key}); !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
	}
	// Requirements that did not change stand where they stood.
	walk := func(parent string, es []depEdge) {
		for _, e := range es {
			if t := after.target(e); t != nil && unchangedEdge(m, before, after, parent, e) {
				add(c.new, t.key, t.key)
			}
		}
	}
	walk("", after.roots)
	keys := make([]string, 0, len(after.nodes))
	for k := range after.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		walk(k, after.nodes[k].deps)
	}
	return c, nil
}

// positionInput is what the position check judges: the comparison graphs of the
// two lockfiles and their correspondence, the vulnerability IDs found for each
// (package, version) before and after, and the triples found only after.
type positionInput struct {
	m          DependencyManager
	cmp0, cmp1 *depGraph
	corr       *chainCorrespondence
	key        func(string) string
	kev        func(vulnID string) bool
	vuln0      map[[2]string]map[string]bool
	vuln1      map[[2]string]map[string]bool
	newTriples []chainTriple
	display    func(chainTriple) string
	// grew are the (package, vulnerability) pairs whose counts grew: such a
	// vulnerability is not carried.
	grew map[[2]string]bool
}

// positionResult is the outcome of the position check.
type positionResult struct {
	refusals []ChainPositionRefusal
	carried  []ChainCarried
	// stillNew are the triples found only after that are not carried.
	stillNew []chainTriple
	anyKEV   bool
}

// describe says why a refusal was made, for the failure's detail.
func (r ChainPositionRefusal) describe(total int) string {
	what := ""
	switch r.Check {
	case posNoPosition:
		what = "has no requirement at the same place in the original lockfile"
	case posMerged:
		what = "stands where requirements for more than one entry of the original were"
	case posName:
		what = "stands where the original had another package"
	case posNewVuln:
		what = "has " + r.VulnID + ", which the entry at the same place in the original lacked"
	case posSplit:
		what = "is an entry of the original that became more than one vulnerable entry"
		return "the position check refused the update: " + r.Package + " " + r.Version + " " + what + " (" + posSplit + ")"
	}
	by := ""
	if r.Parent != "" {
		by = " of " + r.Parent
	}
	out := "the position check refused the update: the requirement" + by + " for " + r.Package + " " + r.Version + " " + what + " (" + r.Check + ")"
	if total > 1 {
		out += " and " + itoa(total-1) + " more"
	}
	return out
}

func itoa(n int) string { return fmt.Sprint(n) }

// checkPositions applies the position check to the requirements of the updated
// lockfile that point to an entry with a vulnerability, and decides which of the
// triples found only after are carried.
//
//   - A requirement the original had as it is is not checked.
//   - Any other requirement into a vulnerable entry must stand at a place with
//     exactly one entry of the original (otherwise: no_position, or merged for
//     more than one), of the same package (name), whose vulnerabilities include
//     those of the new entry (new_vuln).
//   - No entry of the original may lead to more than one vulnerable entry of the
//     updated lockfile (split), whatever else was removed.
func checkPositions(in positionInput) positionResult {
	var res positionResult
	vulnsOf := func(v map[[2]string]map[string]bool, n *depNode) map[string]bool {
		return v[[2]string{in.key(n.name), n.version}]
	}
	vulnerable := func(n *depNode) bool { return len(vulnsOf(in.vuln1, n)) > 0 }
	type entryState struct {
		bad       bool
		positions int
		from      map[string]int
	}
	state := map[string]*entryState{}
	refuse := func(st *entryState, t *depNode, parent *depNode, check, vuln string) {
		st.bad = true
		r := ChainPositionRefusal{Package: t.name, Version: t.version, Check: check, VulnID: vuln}
		if parent != nil {
			r.Parent = parent.name
		}
		res.refusals = append(res.refusals, r)
		if vuln != "" {
			res.anyKEV = res.anyKEV || in.kev(vuln)
			return
		}
		for v := range vulnsOf(in.vuln1, t) {
			res.anyKEV = res.anyKEV || in.kev(v)
		}
	}
	parents := []string{""}
	keys := make([]string, 0, len(in.cmp1.nodes))
	for k := range in.cmp1.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parents = append(parents, keys...)
	for _, parent := range parents {
		p1, es := requirementsOf(in.cmp1, parent)
		by := positionEdges(in.m, p1, es)
		names := make([]string, 0, len(by))
		for n := range by {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, pe := range by[name] {
				t := in.cmp1.target(pe.e)
				if t == nil || !vulnerable(t) || unchangedEdge(in.m, in.cmp0, in.cmp1, parent, pe.e) {
					continue
				}
				st := state[t.key]
				if st == nil {
					st = &entryState{from: map[string]int{}}
					state[t.key] = st
				}
				olds := in.corr.old[posKey{parent, name, pe.e.marker}]
				switch {
				case len(olds) == 0:
					refuse(st, t, p1, posNoPosition, "")
				case len(olds) > 1:
					refuse(st, t, p1, posMerged, "")
				default:
					var e0 *depNode
					for k := range olds {
						e0 = in.cmp0.nodes[k]
					}
					switch {
					case e0 == nil || in.key(e0.name) != in.key(t.name):
						refuse(st, t, p1, posName, "")
					default:
						had := vulnsOf(in.vuln0, e0)
						missing := ""
						for v := range vulnsOf(in.vuln1, t) {
							if !had[v] && (missing == "" || v < missing) {
								missing = v
							}
						}
						if missing != "" {
							refuse(st, t, p1, posNewVuln, missing)
							for v := range vulnsOf(in.vuln1, t) {
								if !had[v] {
									res.anyKEV = res.anyKEV || in.kev(v)
								}
							}
						} else {
							st.positions++
							st.from[e0.version]++
						}
					}
				}
			}
		}
	}
	// An entry of the original that leads to more than one vulnerable entry.
	splitInto := map[string]bool{} // vulnerable entries an entry of the original was split into
	oldKeys := make([]string, 0, len(in.corr.new))
	for k := range in.corr.new {
		oldKeys = append(oldKeys, k)
	}
	sort.Strings(oldKeys)
	for _, k := range oldKeys {
		n := 0
		for k1 := range in.corr.new[k] {
			if t := in.cmp1.nodes[k1]; t != nil && vulnerable(t) {
				n++
			}
		}
		if n < 2 {
			continue
		}
		for k1 := range in.corr.new[k] {
			splitInto[k1] = true
		}
		if e0 := in.cmp0.nodes[k]; e0 != nil {
			res.refusals = append(res.refusals, ChainPositionRefusal{Package: e0.name, Version: e0.version, Check: posSplit})
			for v := range vulnsOf(in.vuln0, e0) {
				res.anyKEV = res.anyKEV || in.kev(v)
			}
		}
	}
	sort.SliceStable(res.refusals, func(i, j int) bool {
		a, b := res.refusals[i], res.refusals[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Parent != b.Parent {
			return a.Parent < b.Parent
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.VulnID < b.VulnID
	})

	// The triples found only after whose entries all passed are carried.
	type carryKey struct{ name, to, vuln string }
	carried := map[carryKey]*ChainCarried{}
	for _, t := range in.newTriples {
		var entries []*depNode
		for _, n := range in.cmp1.nodes {
			if in.key(n.name) == t.name && n.version == t.version {
				entries = append(entries, n)
			}
		}
		ok := !in.grew[[2]string{t.name, t.vuln}] && len(entries) > 0
		positions := 0
		from := ""
		for _, n := range entries {
			st := state[n.key]
			if st == nil || st.bad || st.positions == 0 || splitInto[n.key] {
				ok = false
				break
			}
			positions += st.positions
			for v := range st.from {
				if from == "" || v < from {
					from = v
				}
			}
		}
		if !ok {
			res.stillNew = append(res.stillNew, t)
			continue
		}
		ck := carryKey{t.name, t.version, t.vuln}
		if c := carried[ck]; c != nil {
			c.Positions += positions
			continue
		}
		carried[ck] = &ChainCarried{Package: in.display(t), From: from, To: t.version, VulnID: t.vuln, Positions: positions, KEV: in.kev(t.vuln)}
	}
	for _, c := range carried {
		res.carried = append(res.carried, *c)
	}
	sort.Slice(res.carried, func(i, j int) bool {
		a, b := res.carried[i], res.carried[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.VulnID < b.VulnID
	})
	return res
}
