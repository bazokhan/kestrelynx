package remediation

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
)

// LanguageInputFingerprint names what a language update is made from: the
// item, the blobs of the files the plan read (not the commit they were read
// at) and the packages with their installed versions and target versions.
// The same fingerprint means the same update would be run, so a pull request
// made from it stands for it.
func LanguageInputFingerprint(it LanguageItem) string {
	type pkg struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Installed string `json:"installed"`
		Target    string `json:"target"`
	}
	var files []string
	for _, f := range it.Source.Files {
		if f.Repository == "" {
			files = append(files, f.Path+"\x00"+f.BlobSHA)
		}
	}
	sort.Strings(files)
	absent := append([]string{}, it.Source.Absent...)
	sort.Strings(absent)
	pkgs := []pkg{}
	for _, p := range it.Packages {
		// A package left out of the update was part of what the update was
		// made from, so it stays in the fingerprint: the unit has the same one
		// before and after the update stage.
		if p.Action == ActionUpdate || p.LeftOut {
			pkgs = append(pkgs, pkg{p.Ecosystem, p.matchName(), p.Installed, p.SelectionLowerBound})
		}
	}
	sort.Slice(pkgs, func(i, j int) bool { return fmt.Sprint(pkgs[i]) < fmt.Sprint(pkgs[j]) })
	return hashCanonical(struct {
		Key      string   `json:"key"`
		Files    []string `json:"files"`
		Absent   []string `json:"absent,omitempty"`
		Packages []pkg    `json:"packages"`
	}{it.Key, files, absent, pkgs})
}

// languageLockPath is the lockfile a language item updates, "" when the files
// the plan read do not name exactly one.
func languageLockPath(it LanguageItem) string {
	found := ""
	n := 0
	for _, f := range it.Source.Files {
		if f.Repository == "" && path.Base(f.Path) == it.Manager.LockfileName() {
			found = f.Path
			n++
		}
	}
	if n != 1 {
		return ""
	}
	return found
}

// proposalFor returns the record of a pull request of this tool made from the
// inputs of the item (its fingerprint): an open one first, then a merged one,
// then a closed one. A replaced one was closed in favour of another and does
// not stand for the inputs.
//
// The record has to be the item's own: the same repository (by ID when repoID
// is not 0), the same manager, and the target key the item's repository, base
// branch, dependency directory and lockfile give. A record rebuilt from a
// marker is never used: a marker can be written by anyone with push access, so
// the fingerprint in it proves nothing; only a record this tool made itself,
// after creating the pull request, or one whose inputs this program has
// checked by running the update again (InputVerified), stands for an update.
func (f PRStoreFile) proposalFor(it LanguageItem, fingerprint string, repoID int64) *PRRecord {
	lock := languageLockPath(it)
	root := it.Source.Directory
	if root == "" {
		root = "."
	}
	var best *PRRecord
	rank := func(s PRState) int {
		switch s {
		case PRStateOpen:
			return 3
		case PRStateMerged:
			return 2
		case PRStateClosed:
			return 1
		}
		return 0
	}
	for i := range f.PRs {
		rec := &f.PRs[i]
		if kindOf(rec.Kind) != prKindLanguage || rec.Lang == nil || rec.Lang.InputFingerprint != fingerprint ||
			((rec.MarkerOnly || rec.Recovered) && !rec.InputVerified) || rank(rec.State) == 0 ||
			!strings.EqualFold(rec.Repo, it.Source.Repository) || (repoID != 0 && rec.RepoID != repoID) ||
			rec.Lang.Manager != string(it.Manager) || lock == "" ||
			rec.TargetKey != TargetKeyOf(prKindLanguage, rec.RepoID, it.Source.BaseBranch, lock, []string{root}) {
			continue
		}
		if best == nil || rank(rec.State) > rank(best.State) {
			best = rec
		}
	}
	return best
}

// BindProposedLanguageUpdates is the step before the update stage. A
// dependency update candidate whose inputs have a fingerprint a pull request
// of the records was made from is not run again: it becomes a pr_candidate
// with ReasonUpdateAlreadyProposed, and the pull request stage ties it to that
// pull request. It returns the indexes of the items left to run, in the order
// to run them: items whose lockfile has no open pull request first, those that
// have one (made from other inputs) after, each group in plan order. Without
// readable records nothing is bound.
func BindProposedLanguageUpdates(plan *Plan, store PRStorage) (order []int, bound int) {
	var file PRStoreFile
	if store != nil {
		if f, found, err := store.Load(); err == nil && found {
			file = f
		}
	}
	openOn := func(it LanguageItem) bool {
		lock := languageLockPath(it)
		for _, rec := range file.PRs {
			if rec.State == PRStateOpen && kindOf(rec.Kind) == prKindLanguage && strings.EqualFold(rec.Repo, it.Source.Repository) &&
				rec.BaseBranch == it.Source.BaseBranch && lock != "" && rec.Path == lock {
				return true
			}
		}
		return false
	}
	var first, later []int
	for i := range plan.LanguageItems {
		it := &plan.LanguageItems[i]
		if it.Category != CategoryDependencyUpdateCandidate {
			continue
		}
		if rec := file.proposalFor(*it, LanguageInputFingerprint(*it), 0); rec != nil {
			it.Category, it.Reason = CategoryPRCandidate, ReasonUpdateAlreadyProposed
			it.Detail = fmt.Sprintf("the inputs are those of pull request #%d, so the update was not run again", rec.Number)
			bound++
			continue
		}
		if openOn(*it) {
			later = append(later, i)
		} else {
			first = append(first, i)
		}
	}
	return append(first, later...), bound
}

// RunLanguageUpdates binds the candidates to the pull requests already made
// from their inputs, then runs the update stage over the rest in the order
// BindProposedLanguageUpdates gives, so that a limit on the jobs of a pass
// defers the units that already have a pull request rather than those that
// have none. run is the stage's Run.
func RunLanguageUpdates(ctx context.Context, run func(context.Context, *Plan) LangUpdateUsage, plan *Plan, store PRStorage) (use LangUpdateUsage, bound int) {
	order, bound := BindProposedLanguageUpdates(plan, store)
	return RunLanguageUpdatesInOrder(ctx, run, plan, order), bound
}

// RunLanguageUpdatesInOrder runs the update stage over the items at the
// indexes, in that order, and puts their results back in the plan. It is the
// second half of RunLanguageUpdates, for a caller that needs to know whether
// anything is left to run before it sets the stage up.
func RunLanguageUpdatesInOrder(ctx context.Context, run func(context.Context, *Plan) LangUpdateUsage, plan *Plan, order []int) (use LangUpdateUsage) {
	if len(order) == 0 {
		return use
	}
	sub := &Plan{LanguageItems: make([]LanguageItem, len(order))}
	for k, i := range order {
		sub.LanguageItems[k] = plan.LanguageItems[i]
	}
	use = run(ctx, sub)
	for k, i := range order {
		plan.LanguageItems[i] = sub.LanguageItems[k]
	}
	return use
}
