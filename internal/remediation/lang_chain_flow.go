package remediation

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// chainRunner makes the chain update of one manager: it takes the lockfile
// with the entries of scope taken out, has the package manager resolve it again
// and checks the result, as the run of the first update does. The run it is
// given has the scope set (which makes the checks of the result the chain's)
// and shares the item's budget. It returns nil when the result passed every
// check, and the run holds the result.
type chainRunner func(ctx context.Context, r *updateRun, scope *chainScope) *updateFailure

// A pass that stops for the same reason this many times in a row stops trying
// the chain update for the inputs.
const chainWaitStops = 3

// chainBytesPerLookup is what the bytes an attempt sets aside are estimated
// from: the lookups it will make.
const chainBytesPerLookup = 128 << 10

// chainStage goes on from the first update's result to the chain update when
// the first update left packages short of their target that a requirement of
// another package holds back. It returns true when it settled the item, and
// false when the item is to be settled by the first update's own result as if
// the stage did not exist.
//
// first is the first update's run and firstFail its failure (nil when it passed
// with packages left out). Whatever is adopted has passed every check: the
// chain's result, the first update's own when it did, or the result of the
// first update run again without the packages it did not reach, inside the
// budget set aside for it. A result that was not checked in full is never
// adopted, so an item put off keeps its plan.
func (u *LangUpdater) chainStage(ctx context.Context, it *LanguageItem, n int, set updateSet, first *updateRun, firstFail *updateFailure, run chainRunner) bool {
	if first.src == nil {
		return false
	}
	unreached := chainCandidates(first, firstFail)
	if len(unreached) == 0 {
		return false
	}
	g0, err := buildGraph(ctx, it.Manager, first.src.lock)
	if err != nil {
		return false
	}
	scope, sfail := buildChainScope(ctx, first, g0, unreached)
	if sfail != nil {
		if sfail.category == CategoryDeferred && it.chainStopped != nil {
			// The chain update is not tried for these inputs; only the ordinary
			// reason of the first update is left to settle.
			return false
		}
		if sfail.category == CategoryDeferred {
			return u.chainDeferred(ctx, it, set, first, firstFail, nil, unreached, sfail)
		}
		chain := &ChainUpdate{Outcome: ChainNotTried, Reason: sfail.reason, Detail: sfail.detail, Source: chainSource(it, firstFail), Blocked: []ChainBlock{}, Tops: []ChainMove{}}
		u.finishFirst(ctx, ctx, it, n, set, first, firstFail, chain, sfail.pkgs)
		return true
	}
	if scope == nil {
		return false
	}
	held := func(reason Reason, detail string) map[string]updateFailureDetail {
		out := map[string]updateFailureDetail{}
		for _, name := range scope.Bn {
			out[name] = updateFailureDetail{reason, detail}
		}
		return out
	}
	if stop := it.chainStopped; stop != nil {
		reason, detail := stoppedReason(stop.StopReason)
		chain := &ChainUpdate{Outcome: ChainNotTried, Reason: stop.StopReason, Detail: detail, Source: chainSource(it, firstFail), Blocked: scope.Blocked, Tops: topMoves(scope, g0, nil)}
		if stop.StopReason == ReasonReleaseTooNew {
			chain.Outcome = ChainRejected
		}
		u.finishFirst(ctx, ctx, it, n, set, first, firstFail, chain, held(reason, detail))
		return true
	}

	// Set aside what the attempt and the run of the first update that may have
	// to follow it will use, so that neither stops half way.
	sh := first.shared
	entries := 0
	for _, node := range g0.nodes {
		if scope.Targets[node.name] {
			entries++
		}
	}
	recheck := it.Manager == ManagerUv && firstFail != nil && firstFail.rejectedLock != nil
	containers, lookups := 1, 2*(len(scope.Tops)+len(scope.Anc)+entries)+64
	if recheck {
		containers = 0 // the first update's lockfile is judged again; nothing is run
	}
	if firstFail != nil && len(firstFail.retryWithout) > 0 {
		containers++
		lookups += first.lookups
	}
	if !sh.budget.reserve(containers, lookups, int64(lookups)*chainBytesPerLookup) {
		kind := sh.budget.which(containers, lookups, int64(lookups)*chainBytesPerLookup)
		f := &updateFailure{category: CategoryDeferred, reason: ReasonChainItemBudget, detail: (&itemBudgetError{kind}).Error() + " for the update of the packages that hold " + strings.Join(scope.Bn, ", ") + " back", wait: &langWaitIntent{Kind: kind}}
		return u.chainDeferred(ctx, it, set, first, firstFail, scope, scope.Bn, f)
	}
	sh.budget.enforced = true
	workCtx, cancel := sh.budget.workCtx(ctx, u.cfg.JobTimeout)
	defer cancel()

	// The packages the attempt leaves to the first update's reasons.
	drop := map[string]updateFailureDetail{}
	for _, name := range set.names {
		if !scope.Targets[name] {
			drop[name] = firstReason(first, firstFail, name)
		}
	}
	cr := &updateRun{
		u: u, it: it, n: n, set: set.without(drop), full: set, upd: &LanguageUpdate{},
		noPartial: true, src: first.src, manifest: first.src.manifest, toolSpec: first.toolSpec,
		chain: scope, shared: sh, leftOut: drop, baseOK: first.baseOK,
	}
	var cfail *updateFailure
	// The direct dependencies among the packages updated get the same edits of
	// their declarations as in the first update.
	switch it.Manager {
	case ManagerNpm, ManagerPnpm:
		cfail = cr.planNodeManifest(workCtx)
	case ManagerUv:
		cfail = cr.planUvProject(workCtx)
	}
	source := chainSource(it, firstFail)
	if recheck {
		cr.recheck = firstFail.rejectedLock
		cr.upd.Steps, cr.upd.Runtime, cr.upd.Tool = first.upd.Steps, first.upd.Runtime, first.upd.Tool
	}
	if cfail == nil {
		cfail = run(workCtx, cr, scope)
	}
	cr.upd.Notes = uniqueSorted(cr.upd.Notes)
	chain := &ChainUpdate{Source: source, Blocked: scope.Blocked, Tops: topMoves(scope, g0, nil)}
	if cfail != nil {
		u.expired(ctx, workCtx, sh, cfail)
	}
	switch {
	case cfail == nil:
		u.adoptChain(ctx, it, cr, first, scope, g0, chain)
		return true
	case cfail.wait != nil:
		return u.chainDeferred(ctx, it, set, first, firstFail, scope, scope.Bn, cfail)
	case cfail.category == CategoryDeferred:
		cfail.apply(it, set.idx)
		it.Update = cr.upd
		return true
	}
	var heldBy map[string]updateFailureDetail
	switch {
	case cfail.reason == ReasonTargetNotUpdated:
		chain.Outcome, chain.Reason, chain.Detail = ChainNotFixed, "", cfail.detail
		heldBy = held(ReasonDependentsNotFixed, cfail.detail)
	case cfail.category == CategoryFailed || cfail.reason == ReasonUpdateStepFailed:
		chain.Outcome, chain.Reason, chain.Detail = ChainFailed, cfail.reason, cfail.detail
	default:
		chain.Outcome, chain.Reason, chain.Detail = ChainRejected, cfail.reason, cfail.detail
		heldBy = held(ReasonDependentsRejected, cfail.detail)
	}
	// What the update would have made, when there is a lockfile to read: the one
	// the checks refused, or the one that failed the comparison of findings.
	var g1 *depGraph
	lock := cr.newLock
	if lock == nil {
		lock = cr.recheck
	}
	if len(lock) > 0 {
		g1, _ = buildGraph(ctx, it.Manager, lock)
	}
	chain.Moves, chain.Truncated = chainMovesIn(ctx, it.Manager, cr.chainGraphNames(), scope, cr.upd.Diff, g0, g1)
	if firstFail != nil && cr.check != nil {
		// The item is handed to a person on the first update's failure; the scan
		// of the chain's lockfile is what it records of the findings.
		first.check = cr.check
	}
	u.finishFirst(workCtx, ctx, it, n, set, first, firstFail, chain, heldBy)
	return true
}

// firstReason is why the first update did not take the package to its target:
// the reason it gave for the package, or for the item as a whole.
func firstReason(first *updateRun, f *updateFailure, name string) updateFailureDetail {
	switch {
	case f == nil:
		if d, ok := first.leftOut[name]; ok {
			return d
		}
	case len(f.retryWithout) > 0:
		if d, ok := f.retryWithout[name]; ok {
			return d
		}
	}
	if f != nil {
		if d, ok := f.pkgs[name]; ok {
			return d
		}
		return updateFailureDetail{f.reason, f.detail}
	}
	return updateFailureDetail{ReasonTargetNotUpdated, name + " did not reach its target in the first update"}
}

// expired turns a failure into a wait when the time the item was given to work
// in (work) has ended and the cycle's own (parent) has not: whatever the work
// reported then, it was cut short and is neither a rejection nor a result. The
// end of the cycle's own time is left as it is.
func (u *LangUpdater) expired(parent, work context.Context, sh *itemShared, f *updateFailure) {
	if f.wait != nil || sh == nil || sh.budget.workDeadline.IsZero() || parent.Err() != nil || work.Err() == nil {
		return
	}
	f.category, f.reason, f.detail = CategoryDeferred, ReasonChainItemBudget, "the time the item may work for is over"
	f.wait = &langWaitIntent{Kind: budgetTimeWait}
}

// stoppedReason is the reason and the text of the packages held back by a
// stopped chain update.
func stoppedReason(stop Reason) (Reason, string) {
	if stop == ReasonReleaseTooNew {
		return ReasonDependentsRejected, "a version the update brings in was published less than the minimum age ago on each of the last passes, so it is no longer tried"
	}
	return ReasonDependentsLimit, "the update needed more than one item may use on each of the last passes, so it is no longer tried"
}

// chainDeferred settles an item whose chain update was put off. The item
// waits, and the wait is recorded, unless this was the third pass in a row to
// stop for the same reason: then the chain update is stopped for the inputs and
// the item is settled by what passed every check. Running out of the cycle's own
// time defers the item without a record. bn are the packages the update was
// meant for: those held back, or, when the scope could not be built, those the
// first update did not reach.
func (u *LangUpdater) chainDeferred(ctx context.Context, it *LanguageItem, set updateSet, first *updateRun, firstFail *updateFailure, scope *chainScope, bn []string, f *updateFailure) bool {
	if f.wait == nil {
		f.apply(it, set.idx)
		return true
	}
	var blocked []ChainBlock
	if scope != nil {
		blocked = scope.Blocked
	}
	chain := &ChainUpdate{Outcome: ChainDeferred, Reason: f.reason, Detail: f.detail, Source: chainSource(it, firstFail), Blocked: blocked, Tops: []ChainMove{}}
	if blocked == nil {
		chain.Blocked = []ChainBlock{}
	}
	if sh := first.shared; sh != nil {
		chain.Usage = sh.usage()
	}
	kind := f.wait.Kind
	p := it.priorWait
	third := p != nil && p.Kind == kind && p.Count+1 >= chainWaitStops
	if third || it.chainStopped != nil {
		stop := ReasonChainItemBudget
		reason := ReasonDependentsLimit
		if kind == releaseAgeWait {
			stop, reason = ReasonReleaseTooNew, ReasonDependentsRejected
		}
		_, detail := stoppedReason(stop)
		chain.Outcome, chain.Reason, chain.Detail = ChainNotTried, stop, detail
		if kind == releaseAgeWait {
			chain.Outcome = ChainRejected
		}
		heldBy := map[string]updateFailureDetail{}
		for _, name := range bn {
			heldBy[name] = updateFailureDetail{reason, detail}
		}
		if third {
			it.waitIntent = &langWaitIntent{Stop: true, StopReason: stop}
		}
		if firstFail != nil && (firstFail.wait != nil || len(firstFail.retryWithout) > 0) {
			// The result cannot be made without work the item no longer has: the
			// packages are handed to a person.
			firstFail = unsettled(bn, reason, detail)
		}
		u.finishFirst(ctx, ctx, it, first.n, set, first, firstFail, chain, heldBy)
		return true
	}
	fallback := u.waitFallbackFor(it, set, first, firstFail, bn, kind)
	deferReason := ReasonChainItemBudget
	if kind == releaseAgeWait {
		deferReason = ReasonReleaseTooNew
		retry := f.wait.RetryAfter
		it.RetryAfter = &retry
	}
	deferItem(it, deferReason, f.detail)
	it.Update = &LanguageUpdate{Chain: chain}
	it.waitIntent = &langWaitIntent{Kind: kind, RetryAfter: f.wait.RetryAfter}
	it.waitFallback = fallback
	return true
}

// waitFallbackFor is what the item becomes if its wait cannot be recorded: the
// first update's result when it passed every check, with the packages held
// back handed to a person, and otherwise the item handed to a person. It is
// made without running anything.
func (u *LangUpdater) waitFallbackFor(it *LanguageItem, set updateSet, first *updateRun, firstFail *updateFailure, bn []string, kind string) *LanguageItem {
	cp := *it
	cp.Packages = append([]LanguagePackage(nil), it.Packages...)
	cp.waitIntent, cp.waitFallback = nil, nil
	detail := waitNotRecordedDetail(kind)
	heldBy := map[string]updateFailureDetail{}
	for _, name := range bn {
		heldBy[name] = updateFailureDetail{ReasonDependentsLimit, detail}
	}
	if firstFail == nil {
		fr := *first
		fr.it = &cp
		fr.leftOut = map[string]updateFailureDetail{}
		for name, d := range first.leftOut {
			if h, ok := heldBy[name]; ok {
				d = h
			}
			fr.leftOut[name] = d
		}
		fr.upd = &LanguageUpdate{}
		*fr.upd = *first.upd
		fr.succeed()
		return &cp
	}
	f := manualFailure(ReasonDependentsLimit, "%s", detail)
	f.pkgs = heldBy
	f.apply(&cp, set.idx)
	return &cp
}

// finishFirst settles the item by the first update's result: what passed every
// check is adopted, a first update that asked to be run again without the
// packages it did not reach is run again with the budget set aside for it, and
// anything else is handed to a person. The packages the chain update was meant
// for get the reasons in held, and the chain record is kept on the item's
// update.
func (u *LangUpdater) finishFirst(ctx, parent context.Context, it *LanguageItem, n int, set updateSet, first *updateRun, fail *updateFailure, chain *ChainUpdate, held map[string]updateFailureDetail) {
	res := first
	if fail != nil && len(fail.retryWithout) > 0 {
		orig := fail
		if err := ctx.Err(); err != nil {
			res, fail = first, &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
		} else {
			res, fail = u.runWithout(ctx, it, n, set, fail.retryWithout, first.shared, first.baseOK)
		}
		if fail != nil {
			u.expired(parent, ctx, first.shared, fail)
		}
		if fail != nil && fail.wait != nil {
			names := make([]string, 0, len(held))
			for name := range held {
				names = append(names, name)
			}
			if len(names) == 0 {
				names = set.names
			}
			sort.Strings(names)
			if it.chainStopped != nil {
				// The chain update is stopped for these inputs; what cannot be
				// finished is handed to a person.
				_, detail := stoppedReason(ReasonChainItemBudget)
				fail = unsettled(names, ReasonDependentsLimit, detail)
				res = first
			} else {
				u.chainDeferred(parent, it, set, first, orig, nil, names, fail)
				return
			}
		}
		if fail != nil && fail.category == CategoryDeferred && fail.wait == nil {
			first.upd.Notes = uniqueSorted(append(first.upd.Notes, res.upd.Notes...))
			res = first
		}
	}
	if sh := res.shared; sh != nil && chain != nil {
		chain.Usage = sh.usage()
	}
	if chain != nil {
		res.upd.Chain = chain
	}
	if fail != nil {
		it.Update = res.upd
		it.SourceCheck = res.check
		fail.apply(it, set.idx)
		res.keepLeftOutReasons(fail)
		if fail.category != CategoryDeferred {
			for _, i := range set.idx {
				if d, ok := held[it.Packages[i].matchName()]; ok {
					manualPackage(&it.Packages[i], d.reason, d.detail)
				}
			}
		}
		if fail.category != CategoryDeferred && it.waitIntent == nil {
			it.waitIntent = &langWaitIntent{Clear: true}
		}
		return
	}
	for name, d := range held {
		if _, left := res.leftOut[name]; left {
			res.leftOut[name] = d
		}
	}
	res.succeed()
	if it.waitIntent == nil {
		it.waitIntent = &langWaitIntent{Clear: true}
	}
}

// unsettled is the failure of an item that cannot be finished within what it
// may use: the packages named are handed to a person with the reason.
func unsettled(names []string, reason Reason, detail string) *updateFailure {
	f := manualFailure(reason, "%s", detail)
	f.pkgs = map[string]updateFailureDetail{}
	for _, name := range names {
		f.pkgs[name] = updateFailureDetail{reason, detail}
	}
	return f
}

// adoptChain records a chain update that passed every check on the item.
func (u *LangUpdater) adoptChain(ctx context.Context, it *LanguageItem, cr, first *updateRun, scope *chainScope, g0 *depGraph, chain *ChainUpdate) {
	chain.Outcome = ChainAdopted
	g1, _ := buildGraph(ctx, it.Manager, cr.newLock)
	chain.Tops = topMoves(scope, g0, g1)
	chain.Moves, chain.Truncated = chainMovesIn(ctx, it.Manager, cr.chainGraphNames(), scope, cr.upd.Diff, g0, g1)
	if sh := cr.shared; sh != nil {
		chain.Usage = sh.usage()
	}
	cr.upd.Chain = chain
	through := throughOf(scope, g0, g1)
	cr.upd.Notes = uniqueSorted(append(cr.upd.Notes, fmt.Sprintf("%s could not be taken to the fixed version because the packages that require it ask for an older one, so %s was updated within the ranges the project declares", strings.Join(scope.Bn, ", "), strings.Join(through, ", "))))
	cr.succeed()
	for _, i := range cr.set.idx {
		p := &it.Packages[i]
		for _, name := range scope.Bn {
			if p.matchName() == name {
				p.Through = through
			}
		}
	}
	if it.waitIntent == nil {
		it.waitIntent = &langWaitIntent{Clear: true}
	}
}

// topMoves lists the tops with the versions they have in the original lockfile
// and in the updated one (nil before the update).
func topMoves(scope *chainScope, g0, g1 *depGraph) []ChainMove {
	out := []ChainMove{}
	for _, t := range scope.Tops {
		mv := ChainMove{Name: t.Name, Kind: "top"}
		if n := g0.nodes[t.Key]; n != nil {
			mv.From = n.version
		}
		if g1 != nil {
			g1.link()
			for _, e := range g1.roots {
				if n := g1.target(e); n != nil && e.name == t.Name {
					mv.To = n.version
				}
			}
		}
		out = append(out, mv)
	}
	return out
}

// chainMovesIn is chainMoves for the graphs and scope as the update's difference
// names the entries. For pnpm that is the keys with the peer contexts of the
// given packages left out, so the graphs and the scope are written that way
// first; when that cannot be done no entry is listed and the list is marked cut.
func chainMovesIn(ctx context.Context, m DependencyManager, names map[string]bool, scope *chainScope, diff *DependencyDiff, g0, g1 *depGraph) ([]ChainMove, bool) {
	if m == ManagerPnpm && diff != nil {
		sc, err := scope.inGraph(ctx, names)
		n0, e0 := normalizedGraph(ctx, g0, names)
		var n1 *depGraph
		var e1 error
		if g1 != nil {
			n1, e1 = normalizedGraph(ctx, g1, names)
		}
		if err != nil || e0 != nil || e1 != nil {
			// The entries of the difference cannot be matched to the graphs, so
			// none is listed; the list is marked as cut.
			return nil, true
		}
		scope, g0, g1 = sc, n0, n1
	}
	return chainMoves(scope, diff, g0, g1)
}

// chainMoves lists the entries the update added, changed or removed other than
// the direct dependencies it moved and the packages updated, with the names and
// versions the graphs give (g1 is nil when there is no result to read), cut at
// maxDiffEntries.
func chainMoves(scope *chainScope, diff *DependencyDiff, g0, g1 *depGraph) ([]ChainMove, bool) {
	if diff == nil {
		return nil, false
	}
	tops := scope.topNames()
	// The entries the project's requirements for the tops point to after the
	// update: a top is listed with the tops, not among the moves.
	topNow := map[string]bool{}
	if g1 != nil {
		g1.link()
		for _, e := range g1.roots {
			if tops[e.name] && e.key != "" {
				topNow[e.key] = true
			}
		}
	}
	var out []ChainMove
	add := func(k, kind string) {
		mv := ChainMove{Name: k, Kind: kind}
		var from, to *depNode
		if g0 != nil {
			from = g0.nodes[k]
		}
		if g1 != nil {
			to = g1.nodes[k]
		}
		name := ""
		switch {
		case from != nil:
			name = from.name
		case to != nil:
			name = to.name
		}
		if name != "" {
			if scope.Targets[name] || (tops[name] && (scope.Anc[k] || topNow[k])) {
				return
			}
			mv.Name = name
		}
		if from != nil {
			mv.From = from.version
		}
		if to != nil {
			mv.To = to.version
		}
		out = append(out, mv)
	}
	for _, k := range diff.Added {
		add(k, "added")
	}
	for _, k := range diff.Changed {
		kind := "followed"
		if scope.Anc[k] {
			kind = "ancestor"
		}
		add(k, kind)
	}
	for _, k := range diff.Removed {
		add(k, "removed")
	}
	if len(out) > maxDiffEntries {
		return out[:maxDiffEntries], true
	}
	return out, diff.Truncated
}

// throughOf names the direct dependencies the update moved. When none moved but
// an ancestor did, it names the ancestor nearest the project.
func throughOf(scope *chainScope, g0, g1 *depGraph) []string {
	var through []string
	for _, mv := range topMoves(scope, g0, g1) {
		if mv.From != mv.To {
			through = append(through, mv.Name)
		}
	}
	if len(through) > 0 || g1 == nil {
		sort.Strings(through)
		return through
	}
	depth := map[string]int{}
	var queue []string
	g0.link()
	for _, e := range g0.roots {
		if e.key != "" {
			if _, seen := depth[e.key]; !seen {
				depth[e.key] = 0
				queue = append(queue, e.key)
			}
		}
	}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		for _, e := range g0.nodes[k].deps {
			if _, seen := depth[e.key]; e.key != "" && !seen {
				depth[e.key] = depth[k] + 1
				queue = append(queue, e.key)
			}
		}
	}
	best, bestDepth := "", -1
	for k := range scope.Anc {
		n1 := g1.nodes[k]
		if n1 != nil && n1.version == g0.nodes[k].version {
			continue
		}
		d, ok := depth[k]
		name := g0.nodes[k].name
		if ok && (bestDepth < 0 || d < bestDepth || d == bestDepth && name < best) {
			best, bestDepth = name, d
		}
	}
	if best == "" {
		return nil
	}
	return []string{best}
}

// chainSource says what a chain attempt rests on: "first_run" when the first
// update's own lockfile is judged again by the chain's rules, "chain_job" when
// a job of its own is run.
func chainSource(it *LanguageItem, firstFail *updateFailure) string {
	if it.Manager == ManagerUv && firstFail != nil && firstFail.rejectedLock != nil {
		return "first_run"
	}
	return "chain_job"
}
