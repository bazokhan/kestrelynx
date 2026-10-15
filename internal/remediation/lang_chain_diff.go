package remediation

import (
	"context"
	"fmt"
	"sort"
)

// diffGraphsChain judges the difference between a lockfile and the one a chain
// update made of it, as diffGraphs judges an ordinary update's. Where an
// ordinary update may change the updated packages and what hangs below them, a
// chain update may change the entries it took out and made again (the chain's
// ancestors, the packages being updated and, for npm, what is nested below
// either) and what hangs below them, and nothing else; no path to a package of
// the chain or to a package being updated may end at an older version than it
// did.
//
// Both graphs are the ones to be compared (for pnpm, with the peer contexts of
// the chain left out of the keys), the first marked with the requirements that
// are peer-only. The rules, which use only what the two files hold:
//
//   - The part of the file that is not entries is unchanged.
//   - The project's requirements other than those of the updated packages and
//     the tops point to the very same entry, with the same version, files and
//     record. The same key is not enough: an npm path can hold another version
//     after the update.
//   - No new requirement points to something other than a registry package.
//   - Every updated package is still in the file and needed, and every top still
//     resolves.
//   - Taking out the entries of the chain and of the updated packages can change
//     them, and what hung only below them. An entry outside them keeps its
//     content; a requirement of one that moved to another version of a package
//     the chain's own subtree reaches, not an older one, is followed.
//   - An entry that is new is reachable from a top or from an updated package.
//   - An entry that is gone was required only by those or by entries that
//     followed.
//   - Following every requirement that is not peer-only from the project, in
//     both files at once, no requirement that reaches an entry of the chain or
//     an updated package ends at a lower version (see mapChainPaths).
//   - The entries other than those of the updated packages that were added,
//     changed or removed are not more than maxChainMoves.
//
// The returned reason is empty when the changes are explained. The entries that
// are new or changed are returned in Touched (not truncated).
func diffGraphsChain(ctx context.Context, before, after *depGraph, scope *chainScope) (DependencyDiff, Reason, string) {
	var diff DependencyDiff
	before.link()
	after.link()
	targets := scope.Targets
	tops := scope.topNames()
	masked := make(map[string]bool, len(targets)+len(scope.Names))
	for n := range targets {
		masked[n] = true
	}
	for n := range scope.Names {
		masked[n] = true
	}
	if before.meta != after.meta {
		return diff, ReasonUnexplainedDiff, "the part of the file outside its package entries changed"
	}
	if why := rootsOutsideChain(before, after, func(name string) bool { return targets[name] || tops[name] }); why != "" {
		return diff, ReasonUnexplainedDiff, why
	}
	if why := newNonRegistryEdge(ctx, before, after); why != "" {
		return diff, ReasonResolvedSourceChanged, why
	}

	reachAfter := after.reach(ctx, rootKeys(after.roots), nil)
	byName := map[string][]string{}
	for k, n := range after.nodes {
		byName[n.name] = append(byName[n.name], k)
	}
	for _, name := range sortedSet(targets) {
		found, needed := len(byName[name]) > 0, false
		for _, k := range byName[name] {
			needed = needed || reachAfter[k]
		}
		switch {
		case !found:
			return diff, ReasonTargetRemoved, fmt.Sprintf("%s is no longer in the updated file", name)
		case !needed:
			return diff, ReasonTargetRemoved, fmt.Sprintf("%s is in the updated file but nothing requires it", name)
		}
	}
	var c1Starts []string
	for _, top := range scope.Tops {
		resolved := false
		for _, e := range after.roots {
			if e.name != top.Name {
				continue
			}
			n := after.target(e)
			if n == nil {
				return diff, ReasonUnexplainedDiff, fmt.Sprintf("the project's requirement for %s no longer resolves", top.Name)
			}
			resolved = true
			c1Starts = append(c1Starts, e.key)
		}
		if !resolved {
			return diff, ReasonUnexplainedDiff, fmt.Sprintf("the project no longer requires %s", top.Name)
		}
	}
	for k, n := range after.nodes {
		if targets[n.name] {
			c1Starts = append(c1Starts, k)
		}
	}

	// What may change: the entries taken out, the updated packages by name, and
	// what hung below them only.
	m0 := map[string]bool{}
	for _, set := range []map[string]bool{scope.RAnc, scope.RNest} {
		for k := range set {
			if _, ok := before.nodes[k]; ok {
				m0[k] = true
			}
		}
	}
	for k, n := range before.nodes {
		if targets[n.name] {
			m0[k] = true
		}
	}
	m0Keys := make([]string, 0, len(m0))
	for k := range m0 {
		m0Keys = append(m0Keys, k)
	}
	belowM0 := before.reach(ctx, m0Keys, nil)
	freeBefore := before.reach(ctx, rootKeys(before.roots), func(n *depNode) bool { return m0[n.key] })
	c1 := after.reach(ctx, c1Starts, nil)
	if err := ctx.Err(); err != nil {
		return diff, ReasonUnexplainedDiff, err.Error()
	}
	mayChange := func(k string, n *depNode) bool {
		return m0[k] || (belowM0[k] && !freeBefore[k])
	}

	movedAway := map[string]map[string]bool{}
	var followedTo []string
	keys := make([]string, 0, len(after.nodes))
	for k := range after.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n := after.nodes[k]
		old, existed := before.nodes[k]
		switch {
		case !existed:
			diff.Added = append(diff.Added, k)
			if !targets[n.name] && !c1[k] {
				return diff, ReasonUnexplainedDiff, fmt.Sprintf("%s is new but is neither required by a top or an updated package nor an updated package", k)
			}
		case old.full(before, masked) != n.full(after, masked):
			diff.Changed = append(diff.Changed, k)
			if !mayChange(k, old) {
				moves, fromKeys, toKeys, ok := followedMoves(before, after, old, n, c1)
				if !ok {
					return diff, ReasonUnexplainedDiff, fmt.Sprintf("%s changed but is neither taken out by the update nor only reachable through what is", k)
				}
				for _, mv := range moves {
					if cmp, ok := compareVersions(scope.Scheme, mv.To, mv.From); !ok || cmp < 0 {
						return diff, ReasonChainDowngrade, fmt.Sprintf("%s follows %s from %s to %s, an older version", k, mv.Name, mv.From, mv.To)
					}
				}
				diff.Followed = append(diff.Followed, FollowedEntry{Entry: n.name + "@" + n.version, Moves: moves})
				followedTo = append(followedTo, toKeys...)
				for _, from := range fromKeys {
					if movedAway[from] == nil {
						movedAway[from] = map[string]bool{}
					}
					movedAway[from][k] = true
				}
			}
		default:
			continue
		}
		if n.problem != "" {
			return diff, ReasonResolvedSourceChanged, fmt.Sprintf("%s: %s", k, n.problem)
		}
	}
	diff.touched = append(append([]string(nil), diff.Added...), diff.Changed...)
	have := make(map[string]bool, len(diff.touched))
	for _, k := range diff.touched {
		have[k] = true
	}
	for _, k := range followedTo {
		if !have[k] {
			have[k] = true
			diff.touched = append(diff.touched, k)
		}
	}

	keys = keys[:0]
	for k := range before.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, kept := after.nodes[k]; kept {
			continue
		}
		diff.Removed = append(diff.Removed, k)
		if n := before.nodes[k]; !targets[n.name] && !m0[k] && freeBefore[k] && !onlyFollowersRequired(before, k, targets, mayChange, movedAway[k]) {
			return diff, ReasonUnexplainedDiff, fmt.Sprintf("%s was removed but was required without the entries the update took out", k)
		}
	}

	if reason, why := mapChainPaths(ctx, before, after, scope); reason != "" {
		return diff, reason, why
	}

	moved := 0
	for _, k := range diff.Added {
		if !targets[after.nodes[k].name] {
			moved++
		}
	}
	for _, k := range diff.Changed {
		if !targets[after.nodes[k].name] {
			moved++
		}
	}
	for _, k := range diff.Removed {
		if !targets[before.nodes[k].name] {
			moved++
		}
	}
	if moved > maxChainMoves {
		return diff, ReasonChainMoveLimit, fmt.Sprintf("the update adds, changes or removes %d entries other than the updated packages, more than the %d allowed", moved, maxChainMoves)
	}
	diff.trim()
	return diff, "", ""
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// rootsOutsideChain returns what differs between the project's requirements of
// the two graphs for the names that skip does not name: they must be the same
// requirements pointing to the same entry, the same version, files and record.
func rootsOutsideChain(before, after *depGraph, skip func(name string) bool) string {
	group := func(g *depGraph) map[string][]depEdge {
		out := map[string][]depEdge{}
		for _, e := range g.roots {
			out[e.name] = append(out[e.name], e)
		}
		return out
	}
	gb, ga := group(before), group(after)
	names := map[string]bool{}
	for n := range gb {
		names[n] = true
	}
	for n := range ga {
		names[n] = true
	}
	for _, name := range sortedSet(names) {
		if skip(name) {
			continue
		}
		eb, ea := gb[name], ga[name]
		if len(eb) != len(ea) {
			return fmt.Sprintf("the project's requirements for %s changed", name)
		}
		for i := range eb {
			b, a := eb[i], ea[i]
			if b.optional != a.optional || b.dev != a.dev || b.soft != a.soft || b.ref != a.ref || b.local != a.local || b.marker != a.marker {
				return fmt.Sprintf("the project's requirement for %s changed", name)
			}
			nb, na := before.target(b), after.target(a)
			if (nb == nil) != (na == nil) {
				return fmt.Sprintf("the project's requirement for %s points to a different entry", name)
			}
			if nb != nil && (nb.key != na.key || nb.version != na.version || nb.attrs != na.attrs || !sameDistRefs(nb.dist, na.dist)) {
				return fmt.Sprintf("the project's requirement for %s points to %s, which changed", name, clip(na.key, 100))
			}
		}
	}
	return ""
}

func sameDistRefs(a, b []distRef) bool {
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

// chainEdge is a requirement after normalization: the first of the
// requirements of one parent for one name that point to the same entry with
// the same range and marker (the dependencies and optional dependencies that
// the registry declares with one range are recorded twice).
type chainEdge struct {
	e   depEdge
	idx int
}

// chainEdges lists the parent's requirements that are not peer-only, by name,
// the duplicates joined. The project's own requirements are es of the graph.
func chainEdges(es []depEdge) map[string][]chainEdge {
	out := map[string][]chainEdge{}
	for i, e := range es {
		if e.peerOnly {
			continue
		}
		dup := false
		for _, x := range out[e.name] {
			if x.e.key == e.key && x.e.ref == e.ref && x.e.marker == e.marker {
				dup = true
				break
			}
		}
		if !dup {
			out[e.name] = append(out[e.name], chainEdge{e, i})
		}
	}
	return out
}

// mapChainPaths follows the requirements of both files from the project at
// once. A pair of entries (one of each file) is followed through every
// requirement that is not peer-only, the entries that did not change included,
// and the entry each requirement of the original file reaches is matched with
// the one the same-named requirement of the pair's other half reaches. Where
// the first is an entry of the chain or of an updated package, the second must
// not be an older version. A requirement that is gone because the new version
// of its entry no longer asks for the package ends its path there, and is not
// an unmatched one. Every requirement of the original file that reaches such
// an entry and that the project reaches without passing a gone one must have
// been matched or have ended that way; one that was not, or that cannot be
// matched because a parent has more than one requirement for the name or the
// markers of the matched requirements differ, is refused.
func mapChainPaths(ctx context.Context, before, after *depGraph, scope *chainScope) (Reason, string) {
	before.link()
	after.link()
	targets := scope.Targets
	tracked := func(n *depNode) bool { return scope.RAnc[n.key] || targets[n.name] }
	relevant := func(name string) bool { return targets[name] || scope.Names[name] }
	type slot struct {
		parent string
		idx    int
	}
	type pair struct{ k0, k1 string }
	mapped := map[slot]bool{}
	ended := map[slot]bool{}
	seen := map[pair]bool{}
	var queue []pair

	downgrade := func(format string, args ...any) (Reason, string) {
		return ReasonChainDowngrade, fmt.Sprintf(format, args...)
	}
	step := func(parent0 string, es0, es1 []depEdge) (Reason, string) {
		e0, e1 := chainEdges(es0), chainEdges(es1)
		names := make([]string, 0, len(e0))
		for n := range e0 {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			l0, l1 := e0[name], e1[name]
			switch {
			case len(l0) > 1 || len(l1) > 1:
				if relevant(name) {
					return downgrade("%s has more than one requirement for %s, so its versions cannot be matched", clip(parent0, 100), name)
				}
				continue
			case len(l1) == 0:
				ended[slot{parent0, l0[0].idx}] = true
				continue
			}
			a, b := l0[0], l1[0]
			s := slot{parent0, a.idx}
			c0 := before.target(a.e)
			if c0 == nil {
				continue
			}
			mapped[s] = true
			c1 := after.target(b.e)
			if tracked(c0) {
				switch {
				case c1 == nil:
					return downgrade("the requirement of %s for %s no longer resolves", clip(parent0, 100), name)
				case a.e.marker != b.e.marker:
					return downgrade("the requirement of %s for %s has another marker after the update", clip(parent0, 100), name)
				}
				if cmp, ok := compareVersions(scope.Scheme, c1.version, c0.version); !ok || cmp < 0 {
					return downgrade("%s requires %s at %s after the update, older than the %s it required before", clip(parent0, 100), name, c1.version, c0.version)
				}
			}
			if c1 != nil {
				p := pair{c0.key, c1.key}
				if !seen[p] {
					seen[p] = true
					queue = append(queue, p)
				}
			}
		}
		return "", ""
	}
	if reason, why := step("", before.roots, after.roots); reason != "" {
		return reason, why
	}
	for steps := 0; len(queue) > 0; steps++ {
		if steps%1024 == 0 && ctx.Err() != nil {
			return ReasonUnexplainedDiff, ctx.Err().Error()
		}
		p := queue[0]
		queue = queue[1:]
		if reason, why := step(p.k0, before.nodes[p.k0].deps, after.nodes[p.k1].deps); reason != "" {
			return reason, why
		}
	}

	// Every requirement into the chain that the project reaches, without
	// passing a path that ended, was matched.
	visited := map[string]bool{}
	var walk []string
	cover := func(parent string, es []depEdge) (Reason, string) {
		names := make([]string, 0)
		by := chainEdges(es)
		for n := range by {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, ce := range by[name] {
				s := slot{parent, ce.idx}
				if ended[s] {
					continue
				}
				c0 := before.target(ce.e)
				if c0 == nil {
					continue
				}
				if tracked(c0) && !mapped[s] {
					return downgrade("the requirement of %s for %s at %s cannot be matched to one of the updated file", clip(parent, 100), name, c0.version)
				}
				if !visited[c0.key] {
					visited[c0.key] = true
					walk = append(walk, c0.key)
				}
			}
		}
		return "", ""
	}
	if reason, why := cover("", before.roots); reason != "" {
		return reason, why
	}
	for steps := 0; len(walk) > 0; steps++ {
		if steps%1024 == 0 && ctx.Err() != nil {
			return ReasonUnexplainedDiff, ctx.Err().Error()
		}
		k := walk[len(walk)-1]
		walk = walk[:len(walk)-1]
		if reason, why := cover(k, before.nodes[k].deps); reason != "" {
			return reason, why
		}
	}
	return "", ""
}
