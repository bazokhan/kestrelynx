package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// runPip updates the pinned lines of a requirements.txt. The file is not a
// lockfile, so there is no tool to run for the update: this stage rewrites the
// lines of the packages in the set (the version, and the hashes of a line that
// has them, taken from the release's wheels on PyPI) and has the work image
// resolve the original and the rewritten file with pip for the environment the
// image runs in.
func (r *updateRun) runPip(ctx context.Context) *updateFailure {
	it := r.it
	orig := r.src.lock

	if len(r.set.names) > worker.MaxPackages {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdatePackageLimit,
			detail: fmt.Sprintf("the update names %d packages, more than the %d one job takes", len(r.set.names), worker.MaxPackages)}
	}
	var pkgs []LanguagePackage
	for _, i := range r.set.idx {
		pkgs = append(pkgs, it.Packages[i])
	}
	target, undecided, mismatch, why := pipTargetOf(pkgs, r.u.cfg.Images)
	switch {
	case undecided:
		return manualFailure(ReasonPipTargetUndecidable, "the environment pip resolves for cannot be decided: %s", why)
	case mismatch:
		return manualFailure(ReasonPipTargetMismatch, "%s", why)
	}

	edits, fail := r.pipEdits()
	if fail != nil {
		return fail
	}
	lines := splitReqLines(orig)
	// Hashes of the wheels of each release, for the lines that carry hashes.
	fetched := map[string][]string{}
	for i := range edits {
		if !requirementHasHashes(lines, edits[i].Line) {
			continue
		}
		key := edits[i].Name + "==" + edits[i].NewVersion
		hs, ok := fetched[key]
		if !ok {
			var f *updateFailure
			if hs, f = r.wheelHashesOf(ctx, edits[i].Name, edits[i].NewVersion); f != nil {
				return f
			}
			fetched[key] = hs
		}
		edits[i].Hashes = hs
	}
	requireHashes := requirementsHaveHashes(orig)

	newLock, err := rewriteLines(ctx, orig, lines, edits)
	if err == nil {
		err = verifyRewrite(orig, newLock, edits)
	}
	switch {
	case errors.Is(err, errRewriteLimit):
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit, detail: err.Error()}
	case err != nil && ctx.Err() != nil:
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	case err != nil:
		return manualFailure(ReasonRequirementsRewrite, "%v", err)
	}
	if bytes.Equal(newLock, orig) {
		return manualFailure(ReasonTargetNotUpdated, "the rewrite left requirements.txt unchanged")
	}
	it.UpdateExecuted = true

	baseStep := worker.Step{ID: stepBaseline, Op: worker.OpPipDryRun, Scratch: true, RequireHashes: requireHashes, Target: target}
	baseOut, fail := r.exec(ctx, worker.ManagerPip, map[string][]byte{"requirements.txt": orig}, []worker.Step{baseStep}, "base")
	if fail != nil {
		if fail.reason == ReasonLockfileInconsistent {
			fail.detail = "the original requirements.txt does not resolve for the image's environment: " + fail.detail
		}
		return fail
	}
	reportBefore, ok := baseOut.stepFile(stepBaseline, worker.PipReportName)
	if !ok {
		return failedFailure(ReasonUpdateResultInvalid, "the baseline step returned no pip report")
	}

	checkStep := worker.Step{ID: stepCheck, Op: worker.OpPipDryRun, Scratch: true, RequireHashes: requireHashes, Target: target}
	out, fail := r.exec(ctx, worker.ManagerPip, map[string][]byte{"requirements.txt": newLock}, []worker.Step{checkStep}, "check")
	if fail != nil {
		return fail
	}
	it.PostUpdateCheckExecuted = true
	if final, ok := out.finalFile("requirements.txt"); !ok || !bytes.Equal(final, newLock) {
		return manualFailure(ReasonOutputFilesInvalid, "the check changed requirements.txt")
	}
	reportAfter, ok := out.stepFile(stepCheck, worker.PipReportName)
	if !ok {
		return failedFailure(ReasonUpdateResultInvalid, "the check step returned no pip report")
	}

	chkBefore, fail := r.checkPipReport(ctx, reportBefore, orig, target)
	if fail != nil {
		return fail
	}
	chkAfter, fail := r.checkPipReport(ctx, reportAfter, newLock, target)
	if fail != nil {
		return fail
	}
	gb, err1 := pipGraph(ctx, reportBefore, chkBefore.requires, chkBefore.roots)
	ga, err2 := pipGraph(ctx, reportAfter, chkAfter.requires, chkAfter.roots)
	if err1 != nil || err2 != nil {
		if ctx.Err() != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return manualFailure(ReasonOutputFilesInvalid, "the pip report cannot be read: %v", errors.Join(err1, err2))
	}
	diff, reason, detail := diffGraphs(ctx, gb, ga, r.targetSet())
	r.upd.Diff = &diff
	if ctx.Err() != nil {
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	if reason != "" {
		return manualFailure(reason, "%s", detail)
	}
	for _, n := range r.set.names {
		node := ga.nodes[n]
		if node == nil || !versionsEqual(schemePEP440, node.version, r.set.target[n]) {
			got := ""
			if node != nil {
				got = node.version
			}
			return manualFailure(ReasonTargetNotUpdated, "pip resolves %s to %q, not the pinned %s", n, got, r.set.target[n])
		}
	}
	return r.verifyAndScan(ctx, newLock)
}

// pipEdits lists the requirement lines to rewrite: every occurrence of an
// updated package at the version the image runs, with the name it must have.
func (r *updateRun) pipEdits() ([]reqEdit, *updateFailure) {
	var edits []reqEdit
	seen := map[int]bool{}
	for _, i := range r.set.idx {
		p := r.it.Packages[i]
		for _, o := range p.Occurrences {
			if !o.Matched {
				continue
			}
			line, err := occurrenceLine(o.Path)
			if err != nil {
				return nil, failedFailure(ReasonUpdateInputInvalid, "%s: %v", p.Name, err)
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			edits = append(edits, reqEdit{Name: p.matchName(), Line: line, OldVersion: o.Version, NewVersion: p.SelectionLowerBound})
		}
	}
	if len(edits) == 0 {
		return nil, failedFailure(ReasonUpdateInputInvalid, "no requirement line is to be updated")
	}
	return edits, nil
}

// occurrenceLine reads the line number of a "requirements.txt:N" occurrence.
func occurrenceLine(path string) (int, error) {
	i := strings.LastIndexByte(path, ':')
	if i < 0 {
		return 0, fmt.Errorf("the occurrence %q has no line number", path)
	}
	n, err := strconv.Atoi(path[i+1:])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("the occurrence %q has no line number", path)
	}
	return n, nil
}

// requirementsHaveHashes reports whether any requirement of the file carries
// a --hash option; pip then requires a hash for every requirement.
func requirementsHaveHashes(data []byte) bool {
	for _, l := range splitReqLines(data) {
		if reqHashTokRE.MatchString(pipCommentRE.ReplaceAllString(l.text, "")) {
			return true
		}
	}
	return false
}

// wheelHashesOf returns the sha256 of every wheel of a release. A release the
// index does not know, one with no wheel or one with a yanked file is left to a
// person: the hashes would be of files that cannot be installed as pinned.
func (r *updateRun) wheelHashesOf(ctx context.Context, name, ver string) ([]string, *updateFailure) {
	rel, err := r.pyRelease(ctx, name, ver)
	pkg := func(reason Reason, format string, args ...any) *updateFailure {
		return pkgFailure(name, reason, format, args...)
	}
	switch {
	case errors.Is(err, ErrReleaseNotFound):
		return nil, pkg(ReasonNoWheelForVersion, "%s %s is not on PyPI", name, ver)
	case err != nil:
		return nil, lookupFailure(ctx, err, name+" "+ver+" on PyPI")
	}
	hs, yanked := wheelHashes(rel.Files)
	switch {
	case yanked:
		return nil, pkg(ReasonReleaseYanked, "%s %s has a yanked file on PyPI", name, ver)
	case len(hs) == 0:
		return nil, pkg(ReasonNoWheelForVersion, "%s %s has no wheel on PyPI, so no hash of an installable file can be pinned", name, ver)
	case len(hs) > maxWheelsPerEdit:
		return nil, &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("%s %s has %d wheels, more than the %d hashes one requirement is given", name, ver, len(hs), maxWheelsPerEdit)}
	}
	return hs, nil
}
