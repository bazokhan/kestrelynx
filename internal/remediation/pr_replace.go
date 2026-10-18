package remediation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Replacement closes an older pull request of this tool when a newer one
// edits the same file and service locations to a newer patch of the same
// image repository and resolves every vulnerability the older one claimed.
// It is persisted on the new record and resumed every cycle: the supersede
// comment goes first (found again by its marker, so a lost answer does not
// post it twice), then the close. Both pull requests are read again before
// each write; any condition that fails leaves the old pull request open.

// resolvedFromEvidence is the set of pairs, per location, that every entity
// of the location resolves in the verified comparison, targets or not.
func resolvedFromEvidence(ev *VerificationSummary) map[string]bool {
	perLoc := map[string]map[string]bool{}
	for _, it := range ev.Items {
		pairs := map[string]bool{}
		for _, v := range append(append([]VulnSummary(nil), it.Resolved...), it.OtherResolved...) {
			pairs[v.VulnID+"\x00"+string(v.Package.Ecosystem)+"\x00"+string(v.Package.Class)+"\x00"+v.Package.Name] = true
		}
		for _, loc := range it.Locations {
			acc, seen := perLoc[loc]
			if !seen {
				cp := map[string]bool{}
				for k := range pairs {
					cp[k] = true
				}
				perLoc[loc] = cp
				continue
			}
			for k := range acc {
				if !pairs[k] {
					delete(acc, k)
				}
			}
		}
	}
	out := map[string]bool{}
	for loc, pairs := range perLoc {
		for k := range pairs {
			out[loc+"\x00"+k] = true
		}
	}
	return out
}

// newerPatch reports whether tag b is a newer patch than a of the same
// series.
func newerPatch(a, b string) bool {
	va, ok1 := ParseTagVersion(a)
	vb, ok2 := ParseTagVersion(b)
	return ok1 && ok2 && va.Prefix == vb.Prefix && va.Suffix == vb.Suffix && va.Major == vb.Major && va.Minor == vb.Minor && vb.Patch > va.Patch
}

// resolvedEntitiesFromEvidence is, for a Dockerfile update, the running
// images each target is resolved for. The key is a FixTarget's identity.
func resolvedEntitiesFromEvidence(ev *VerificationSummary) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, it := range ev.Items {
		for _, loc := range it.Locations {
			for _, v := range it.Resolved {
				k := FixTarget{Location: loc, VulnID: v.VulnID, Package: v.Package, Layers: v.Layers}.key()
				if out[k] == nil {
					out[k] = map[string]bool{}
				}
				out[k][it.ItemKey] = true
			}
		}
	}
	return out
}

// replaceable reports whether old may be replaced by rec. inherits says
// whether rec resolves a target old claimed.
func replaceable(rec, old *PRRecord, inherits func(FixTarget) bool) bool {
	if old == rec || old.RepoID != rec.RepoID || old.State != PRStateOpen || old.UserModified || old.MarkerOnly ||
		rec.UserModified || rec.MarkerOnly ||
		old.TargetKey != rec.TargetKey || old.UpdateKey == rec.UpdateKey ||
		old.BaseBranch != rec.BaseBranch || old.Path != rec.Path || strings.Join(old.Locations, "\x00") != strings.Join(rec.Locations, "\x00") {
		return false
	}
	if kindOf(rec.Kind) == prKindLanguage {
		// A language update replaces an older one of the same lockfile when it
		// fixes everything the older one fixes; there is no tag series.
		if kindOf(old.Kind) != prKindLanguage || len(old.FixTargets) == 0 {
			return false
		}
	} else {
		ok, _ := inventory.RepositoryKey(old.CurrentRef)
		nk, _ := inventory.RepositoryKey(rec.CurrentRef)
		if ok == "" || ok != nk || !newerPatch(old.CandidateTag, rec.CandidateTag) || len(old.FixTargets) == 0 {
			return false
		}
	}
	for _, f := range old.FixTargets {
		if !inherits(f) {
			return false
		}
	}
	return true
}

// decideReplacements adds every replaceable older pull request to the new
// record's replacements. Nothing is sent here.
func (r *prRun) decideReplacements(rec *PRRecord) {
	if rec == nil || rec.UserModified || rec.MarkerOnly || rec.State != PRStateOpen || (rec.Evidence == nil && rec.Lang == nil) ||
		r.targetBlocked(rec.RepoID, rec.TargetKey) {
		return
	}
	inherits := func(f FixTarget) bool { return false }
	switch {
	case kindOf(rec.Kind) == prKindLanguage:
		// Every target the old pull request fixed, at the same place in the
		// lockfile and for the same vulnerability, must be fixed by the new
		// one; the new one's update passed the check of its final files.
		have := map[string]bool{}
		for _, f := range rec.FixTargets {
			have[f.key()] = true
		}
		inherits = func(f FixTarget) bool { return have[f.key()] }
	case kindOf(rec.Kind) == prKindDockerfile:
		// Every target the old pull request resolved for an image must be
		// resolved for that image by the new one.
		resolved := resolvedEntitiesFromEvidence(rec.Evidence)
		inherits = func(f FixTarget) bool {
			have := resolved[f.key()]
			if len(f.Entities) == 0 {
				return len(have) > 0
			}
			for _, e := range f.Entities {
				if !have[e] {
					return false
				}
			}
			return true
		}
	default:
		resolved := resolvedFromEvidence(rec.Evidence)
		inherits = func(f FixTarget) bool { return resolved[f.key()] }
	}
	changed := false
	for i := range r.file.PRs {
		old := &r.file.PRs[i]
		if !replaceable(rec, old, inherits) || r.replacementOf(old) != nil {
			continue
		}
		rec.Replacing = append(rec.Replacing, Replacement{OldNumber: old.Number, State: ReplacementPending})
		changed = true
	}
	if changed {
		rec.UpdatedAt = r.now()
		r.save()
	}
}

// replacementOf returns the replacement in progress for old, if any.
func (r *prRun) replacementOf(old *PRRecord) *Replacement {
	for i := range r.file.PRs {
		rec := &r.file.PRs[i]
		if rec.RepoID != old.RepoID {
			continue
		}
		for j := range rec.Replacing {
			if rec.Replacing[j].OldNumber == old.Number && !rec.Replacing[j].terminal() {
				return &rec.Replacing[j]
			}
		}
	}
	return nil
}

// resumeReplacements continues every replacement in progress.
func (r *prRun) resumeReplacements() {
	for i := range r.file.PRs {
		for j := 0; j < len(r.file.PRs[i].Replacing); j++ {
			rec := &r.file.PRs[i]
			rp := &rec.Replacing[j]
			if rp.terminal() || rp.State == ReplacementClosed {
				continue
			}
			rs := r.repoByID(rec.RepoID)
			if rs == nil || !r.canWrite(rs) {
				continue
			}
			r.replace(rs, rec, rp)
		}
	}
}

func (r *prRun) repoByID(id int64) *repoState {
	for _, rs := range r.repos {
		if rs.ok && rs.info.ID == id {
			return rs
		}
	}
	return nil
}

// abandonReplacement leaves the old pull request as it is.
func (r *prRun) abandonReplacement(rec *PRRecord, rp *Replacement, detail string) {
	rp.State, rp.Detail = ReplacementAbandoned, detail
	rec.UpdatedAt = r.now()
	r.save()
}

// checkPair reads both pull requests again and reports whether the
// replacement may proceed: the new one open at its recorded head, the old
// one open at its recorded head and not changed by anyone. A pull request
// found merged or closed is recorded so.
func (r *prRun) checkPair(rs *repoState, rec, old *PRRecord, rp *Replacement) bool {
	if !r.eligiblePair(rec, old, rp) {
		return false
	}
	gh := r.s.cfg.GitHub
	npr, err := gh.Pull(r.ctx, rs.name, rec.Number)
	if err != nil {
		r.haltFor(err)
		return false
	}
	if st := pullState(npr); st != PRStateOpen || markModified(rec, npr) || rec.UserModified {
		rec.State = st
		r.abandonReplacement(rec, rp, fmt.Sprintf("pull request #%d is no longer open at the commit, base and repository this tool created it with", rec.Number))
		return false
	}
	opr, err := gh.Pull(r.ctx, rs.name, old.Number)
	if err != nil {
		r.haltFor(err)
		return false
	}
	switch st := pullState(opr); {
	case st == PRStateMerged:
		old.State, old.UpdatedAt = PRStateMerged, r.now()
		r.abandonReplacement(rec, rp, fmt.Sprintf("pull request #%d was merged", old.Number))
		return false
	case st == PRStateClosed:
		old.State, old.UpdatedAt = PRStateClosed, r.now()
		if rp.State == ReplacementCommented {
			old.SupersededBy = rec.Number
		}
		r.abandonReplacement(rec, rp, fmt.Sprintf("pull request #%d was closed by someone else", old.Number))
		return false
	}
	if markModified(old, opr) || old.UserModified {
		old.UpdatedAt = r.now()
		r.abandonReplacement(rec, rp, fmt.Sprintf("pull request #%d was changed by someone else", old.Number))
		return false
	}
	return true
}

// findSupersede looks for this replacement's comment on the old pull
// request.
func (r *prRun) findSupersede(rs *repoState, rec *PRRecord, oldNumber int) (bool, error) {
	cs, err := r.listComments(rs, oldNumber)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if hasSupersedeMarker(c.Body, rec.Number, rec.UpdateKey) {
			return true, nil
		}
	}
	return false, nil
}

// replace runs one replacement as far as it can go this cycle.
func (r *prRun) replace(rs *repoState, rec *PRRecord, rp *Replacement) {
	gh := r.s.cfg.GitHub
	old := r.recordByNumber(rec.RepoID, rp.OldNumber)
	if old == nil {
		r.abandonReplacement(rec, rp, "the old pull request is not in the records")
		return
	}
	if !r.eligiblePair(rec, old, rp) {
		return
	}
	if kindOf(rec.Kind) == prKindLanguage {
		// The new pull request carries the targets it fixes; there is no tag
		// to resolve again.
		if rec.Lang == nil || len(rec.FixTargets) == 0 {
			r.abandonReplacement(rec, rp, "the new pull request has no record of what it fixes")
			return
		}
	} else {
		if rec.Evidence == nil || len(rec.Evidence.Items) == 0 {
			r.abandonReplacement(rec, rp, "the new pull request has no verification record")
			return
		}
		cand := rec.Evidence.Items[0].Candidate
		platform, ok := parsePlatform(cand.Platform)
		if !ok {
			r.abandonReplacement(rec, rp, "the candidate's platform is not known")
			return
		}
		res, err := r.s.cfg.Resolver.Resolve(r.ctx, repoOfRef(rec.CurrentRef), rec.CandidateTag, platform)
		if err != nil {
			r.haltFor(err)
			return // tried again next cycle
		}
		if res.TopDigest != rec.CandidateDigest {
			r.abandonReplacement(rec, rp, fmt.Sprintf("tag %s now points at %s, not the verified %s", rec.CandidateTag, res.TopDigest, rec.CandidateDigest))
			return
		}
	}

	if rp.State == ReplacementPending {
		if !r.checkPair(rs, rec, old, rp) {
			return
		}
		found, err := r.findSupersede(rs, rec, old.Number)
		if err != nil {
			r.haltFor(err)
			return
		}
		if found {
			r.settle(rp.PendingOp, ResultOK, "the supersede comment exists")
		} else {
			if rp.PendingOp != "" {
				r.settle(rp.PendingOp, ResultFailed, "no supersede comment was found")
				rp.PendingOp = ""
			}
			if !r.reserve(4) {
				return
			}
			_, opID, err := r.write(OperationEvent{Kind: OpCreateComment, Repo: rs.name, AttemptKey: rec.AttemptKey, Number: old.Number,
				Intent: fmt.Sprintf("comment on #%d that #%d supersedes it", old.Number, rec.Number)}, func() (string, error) {
				return "", gh.CreateIssueComment(r.ctx, rs.name, old.Number, supersedeComment(rec.Number, rec.URL, rec.UpdateKey))
			})
			if err != nil {
				if isUnknown(err) {
					rp.PendingOp = opID
					r.save()
				} else if r.halt == nil && !isStopped(err) {
					r.abandonReplacement(rec, rp, "the supersede comment was refused: "+err.Error())
				}
				return
			}
		}
		rp.State, rp.PendingOp, rp.Detail = ReplacementCommented, "", ""
		rec.UpdatedAt = r.now()
		if !r.save() || !r.canWrite(rs) {
			return
		}
	}

	if rp.State == ReplacementCommented {
		if !r.checkPair(rs, rec, old, rp) {
			return
		}
		if !r.reserve(2) {
			return
		}
		_, opID, err := r.write(OperationEvent{Kind: OpClosePull, Repo: rs.name, AttemptKey: rec.AttemptKey, Number: old.Number,
			Intent: fmt.Sprintf("close #%d, superseded by #%d", old.Number, rec.Number)}, func() (string, error) {
			return "", gh.ClosePull(r.ctx, rs.name, old.Number)
		})
		switch {
		case err == nil:
			old.State, old.ReplacedBy, old.UpdatedAt = PRStateReplaced, rec.Number, r.now()
			rp.State, rp.Detail = ReplacementDone, ""
		case isUnknown(err):
			rp.State, rp.PendingOp = ReplacementClosed, opID
		case r.halt != nil || isStopped(err):
			return
		default:
			r.abandonReplacement(rec, rp, "the close was refused: "+err.Error())
			return
		}
		rec.UpdatedAt = r.now()
		r.save()
	}
}

// settleClose finds out the outcome of a close whose answer was lost. A merge
// wins; a pull request closed unmerged with the supersede comment on it is
// taken as replaced, since nothing shows a person closed it; without the
// comment it is recorded as closed with the newer pull request as related
// information. An open one was not closed, and the close is tried again
// after the usual checks. It returns false when GitHub could not be read.
func (r *prRun) settleClose(rs *repoState, rec *PRRecord, rp *Replacement) bool {
	old := r.recordByNumber(rec.RepoID, rp.OldNumber)
	if old == nil {
		rp.State, rp.Detail = ReplacementAbandoned, "the old pull request is not in the records"
		return true
	}
	pr, err := r.s.cfg.GitHub.Pull(r.ctx, rs.name, old.Number)
	if err != nil {
		r.haltFor(err)
		return false
	}
	switch pullState(pr) {
	case PRStateMerged:
		r.settle(rp.PendingOp, ResultFailed, fmt.Sprintf("#%d was merged", old.Number))
		old.State, old.UpdatedAt = PRStateMerged, r.now()
		rp.State, rp.PendingOp, rp.Detail = ReplacementAbandoned, "", "merged"
	case PRStateClosed:
		found, err := r.findSupersede(rs, rec, old.Number)
		if err != nil {
			r.haltFor(err)
			return false
		}
		r.settle(rp.PendingOp, ResultOK, fmt.Sprintf("#%d is closed", old.Number))
		if found {
			old.State, old.ReplacedBy = PRStateReplaced, rec.Number
		} else {
			old.State, old.SupersededBy = PRStateClosed, rec.Number
		}
		old.UpdatedAt = r.now()
		rp.State, rp.PendingOp, rp.Detail = ReplacementDone, "", ""
	default:
		r.settle(rp.PendingOp, ResultFailed, fmt.Sprintf("#%d is still open", old.Number))
		rp.State, rp.PendingOp = ReplacementCommented, ""
	}
	rec.UpdatedAt = r.now()
	return true
}

func isUnknown(err error) bool { return err != nil && errors.Is(err, github.ErrOutcomeUnknown) }
func isStopped(err error) bool { return errors.Is(err, errWritesStopped) }

// eligiblePair checks the persisted records before any step of a
// replacement: a pull request once seen changed by someone else, or known
// only by its marker, is never commented on, closed or used to replace,
// even if its head was later put back.
func (r *prRun) eligiblePair(rec, old *PRRecord, rp *Replacement) bool {
	switch {
	case r.targetBlocked(rec.RepoID, rec.TargetKey):
		r.abandonReplacement(rec, rp, "an attempt for this file and these services cannot be settled")
	case rec.UserModified || rec.MarkerOnly:
		r.abandonReplacement(rec, rp, fmt.Sprintf("pull request #%d was changed by someone else or is not known from this tool's records", rec.Number))
	case old.UserModified || old.MarkerOnly:
		r.abandonReplacement(rec, rp, fmt.Sprintf("pull request #%d was changed by someone else or is not known from this tool's records", old.Number))
	default:
		return true
	}
	return false
}

// targetBlocked reports whether an attempt of the target cannot be settled,
// in this cycle or as recorded. No replacement starts or continues for such
// a target: which pull request on its branch is this tool's is not known.
func (r *prRun) targetBlocked(repoID int64, targetKey string) bool {
	for _, rs := range r.repos {
		if rs.ok && rs.info.ID == repoID {
			if _, blocked := rs.blockedTargets[targetKey]; blocked {
				return true
			}
		}
	}
	for _, a := range r.file.Attempts {
		if a.RepoID == repoID && a.TargetKey == targetKey && a.Status == AttemptBlocked {
			return true
		}
	}
	return false
}
