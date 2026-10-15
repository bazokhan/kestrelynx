package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// The checks that belong to the way npm and pnpm updates are made (see
// lang_remove.go): the dependency that was taken out of the pnpm importer so
// that pnpm resolves again has to come back as it was, and the deprecation
// notes of the lockfile follow the registry's.

// buildGraphs reads the original lockfile and the updated one as dependency
// graphs, to be compared. For pnpm, they are the graphs of the files as they
// are written with the keys of the entries changed (see normalizedGraph); what
// refers to what is the written files' own, and the checks of the references as
// they are written are on checkReferences.
func (r *updateRun) buildGraphs(ctx context.Context, newLock []byte) (before, after *depGraph, errBefore, errAfter error) {
	m := r.it.Manager
	before, errBefore = buildGraph(ctx, m, r.src.lock)
	after, errAfter = buildGraph(ctx, m, newLock)
	if m != ManagerPnpm {
		return before, after, errBefore, errAfter
	}
	// The contexts of the chain's packages are left out like the updated
	// packages': they are what the update makes again.
	names := r.full.targets
	if r.chain != nil {
		names = map[string]bool{}
		for n := range r.full.targets {
			names[n] = true
		}
		for n := range r.chain.Names {
			names[n] = true
		}
	}
	if errBefore == nil {
		before, errBefore = normalizedGraph(ctx, before, names)
	}
	if errAfter == nil {
		after, errAfter = normalizedGraph(ctx, after, names)
	}
	return before, after, errBefore, errAfter
}

// checkReferences requires every requirement of the updated lockfile as it is
// written to be satisfied by an entry of it wherever the original's was, with
// the peer contexts as they are: an importer that asks for host@1.0.0(next@0.0.0)
// when the file has only host@1.0.0(next@15.2.0) is a broken file, whatever the
// comparison that leaves those contexts out makes of it.
func (r *updateRun) checkReferences(ctx context.Context, newLock []byte) *updateFailure {
	if r.it.Manager != ManagerPnpm {
		return nil
	}
	before, err1 := buildGraph(ctx, r.it.Manager, r.src.lock)
	after, err2 := buildGraph(ctx, r.it.Manager, newLock)
	if err1 != nil || err2 != nil {
		if ctx.Err() != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return manualFailure(ReasonOutputFilesInvalid, "the dependency graph cannot be read: %v", errors.Join(err1, err2))
	}
	if reason, detail := checkUnresolvedCtx(ctx, before, after); reason != "" {
		return manualFailure(reason, "%s", detail)
	}
	// A requirement that must be met has to be met by an entry the file has under
	// the very name it writes, unless the original had that requirement unmet in
	// the same place and the same way; and every updated package has to be
	// reached from the project through requirements met that way.
	before.link()
	after.link()
	// What the original left unmet, by owner and then by requirement, so that a
	// long key is held once and not once for each requirement.
	type need struct{ name, ref string }
	had := map[string]map[need]bool{}
	steps := 0
	tick := func() *updateFailure {
		if steps++; steps%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
			}
		}
		return nil
	}
	note := func(owner string, e depEdge) {
		if had[owner] == nil {
			had[owner] = map[need]bool{}
		}
		had[owner][need{e.name, e.ref}] = true
	}
	for _, e := range before.roots {
		if e.to < 0 {
			note("", e)
		}
	}
	for _, n := range before.list {
		for _, e := range n.deps {
			if f := tick(); f != nil {
				return f
			}
			if e.to < 0 {
				note(n.key, e)
			}
		}
	}
	unmet := func(owner, who string, e depEdge) *updateFailure {
		if e.to >= 0 || e.optional || had[owner][need{e.name, e.ref}] {
			return nil
		}
		return manualFailure(ReasonUnexplainedDiff, "the updated file has a requirement no entry satisfies as it is written: %s requires %s as %q", clip(who, 100), e.name, clip(e.ref, 100))
	}
	for _, e := range after.roots {
		if f := unmet("", "the project", e); f != nil {
			return f
		}
	}
	for _, n := range after.list {
		for _, e := range n.deps {
			if f := tick(); f != nil {
				return f
			}
			if f := unmet(n.key, n.key, e); f != nil {
				return f
			}
		}
	}
	reached := after.reach(ctx, rootKeys(after.roots), nil)
	if err := ctx.Err(); err != nil {
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
	}
	needed := map[string]bool{}
	for k := range reached {
		needed[after.nodes[k].name] = true
	}
	for name := range r.full.targets {
		if !needed[name] {
			return manualFailure(ReasonTargetRemoved, "%s is not reached from the project through the references of the updated file as they are written", name)
		}
	}
	return nil
}

// checkTriggerReturned requires the direct dependency that was taken out of
// the importer, when no target was one, to be there again as it was: with the
// same specifier, the same entry (version and resolution), the same record
// and the same requirements. What a dependency that was taken out and
// resolved again comes back as is not something to look into: a project whose
// dependency does not is left to a person, with the unit made as it was (the
// update is not made again with another dependency taken out).
func (r *updateRun) checkTriggerReturned(before, after *depGraph, oldLock, newLock []byte) *updateFailure {
	name := r.pnpmTrigger
	if name == "" {
		return nil
	}
	drop := func(format string, args ...any) *updateFailure {
		return manualFailure(ReasonDropSideEffect, "%s was taken out of pnpm-lock.yaml to make pnpm resolve again, and %s", name, fmt.Sprintf(format, args...))
	}
	was, err1 := pnpmImporterSpecs(oldLock)
	now, err2 := pnpmImporterSpecs(newLock)
	if err1 != nil || err2 != nil {
		return drop("the importer of the file cannot be read")
	}
	for _, grp := range pnpmImporterGroups {
		w, inWas := was[grp][name]
		n, inNow := now[grp][name]
		if inWas != inNow || w != n {
			return drop("it is not listed in %s as it was (%q)", grp, w)
		}
	}
	before.link()
	after.link()
	var be, ae *depEdge
	for i := range before.roots {
		if before.roots[i].name == name {
			be = &before.roots[i]
		}
	}
	for i := range after.roots {
		if after.roots[i].name == name {
			ae = &after.roots[i]
		}
	}
	if be == nil || ae == nil {
		return drop("it is not required by the project as it was")
	}
	bn, an := before.target(*be), after.target(*ae)
	if bn == nil || an == nil || be.key != ae.key {
		return drop("it does not resolve to the same entry")
	}
	if bn.full(before, r.full.targets) != an.full(after, r.full.targets) {
		return drop("its entry (version, resolution, record or requirements) is not what it was")
	}
	return nil
}

// checkDeprecated judges the deprecation notes of the updated lockfile. A
// note of a package version that was added, changed or taken away by the
// update (the package manager writes the registry's note when it resolves a
// package) is accepted only when it is the one the npm registry has for that
// version, and the number of versions it was found for is kept. Notes that the
// update left as they were are not looked into.
func (r *updateRun) checkDeprecated(ctx context.Context, before, after *depGraph) *updateFailure {
	type release struct{ name, version, note string }
	changed := map[release]bool{}
	// carried are releases that arrive with the note they are known to have: a
	// new version of an entry whose old version had the same text. They are
	// checked against the registry like the others, and stated in the pull
	// request, but are not counted among the notes that changed.
	carried := map[release]bool{}
	kinds := map[[2]string]string{}
	keys := make([]string, 0, len(after.nodes))
	for k := range after.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n := after.nodes[k]
		was := ""
		old := before.nodes[k]
		if old != nil {
			was = old.deprecated
		}
		sameRelease := old != nil && old.name == n.name && old.version == n.version
		if n.deprecated == was && (sameRelease || n.deprecated == "") {
			continue
		}
		if n.problem != "" {
			return manualFailure(ReasonDistributionMismatch, "%s %s: %s records a deprecation note and is not a package the registry publishes", n.name, n.version, k)
		}
		if n.deprecated == was {
			carried[release{n.name, n.version, n.deprecated}] = true
		} else {
			changed[release{n.name, n.version, n.deprecated}] = true
		}
		if _, ok := kinds[[2]string{n.name, n.version}]; !ok {
			kinds[[2]string{n.name, n.version}] = deprecationKind(before.nodes[k], n)
		}
	}
	// A deprecation note that went away with its entry is not looked at. A
	// version whose note changed in one entry and not in another is looked up
	// once.
	list := make([]release, 0, len(changed)+len(carried))
	for c := range changed {
		list = append(list, c)
	}
	for c := range carried {
		if !changed[c] {
			list = append(list, c)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.version != b.version {
			return a.version < b.version
		}
		return a.note < b.note
	})
	versions := map[[2]string]bool{}
	seen := map[[2]string]bool{}
	var notes []DeprecationChange
	for _, c := range list {
		d, err := r.npmRelease(ctx, c.name, c.version)
		if err != nil {
			return lookupFailure(ctx, err, c.name+" "+c.version+" in the npm registry")
		}
		if d.Deprecated != c.note {
			f := manualFailure(ReasonDistributionMismatch, "%s %s: the lockfile records the deprecation note %q, the registry has %q",
				c.name, c.version, clip(c.note, 100), clip(d.Deprecated, 100))
			if r.targetSet()[c.name] {
				f.pkgs = map[string]updateFailureDetail{c.name: {ReasonDistributionMismatch, f.detail}}
			}
			return f
		}
		key := [2]string{c.name, c.version}
		if kind := kinds[key]; !seen[key] && kind != "" {
			notes = append(notes, DeprecationChange{Name: c.name, Version: c.version, Kind: kind})
		}
		seen[key] = true
		if changed[c] {
			versions[key] = true
		}
	}
	r.upd.DeprecatedChanged = len(versions)
	r.upd.DeprecatedNotes = notes
	return nil
}

// deprecationKind says what the note of an entry of the updated file is, as
// far as it is known: a change of the note of the very same name and version
// (the registry has the new value, which is checked) is a change of the note
// itself; for an entry whose version differs from the one before, or a new
// entry, the old and new notes belong to different releases, so only the
// note the new version has is stated. "" is nothing to state.
func deprecationKind(old, n *depNode) string {
	if old != nil && old.name == n.name && old.version == n.version {
		switch {
		case old.deprecated == "":
			return DeprecationGained
		case n.deprecated == "":
			return DeprecationLost
		}
		return DeprecationChanged
	}
	if n.deprecated != "" {
		return DeprecationPresent
	}
	return ""
}
