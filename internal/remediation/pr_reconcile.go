package remediation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// loadRepos reads every configured repository. A repository that cannot be
// read, that GitHub now spells differently (renamed or transferred: writes
// are not redirected) or whose ID differs from the one recorded is not
// written to this cycle.
func (r *prRun) loadRepos() {
	for _, rs := range r.repos {
		if !r.active() {
			rs.blocked, rs.blockedDetail = r.inactiveDetail()
			continue
		}
		info, err := r.s.cfg.GitHub.Repository(r.ctx, rs.name)
		if err != nil {
			if r.haltFor(err) {
				rs.blocked, rs.blockedDetail = r.halt.reason, r.halt.detail
				continue
			}
			r.blockRepo(rs, PRProblemWriteBlocked, ReasonReconcileFailed, "the repository could not be read: "+err.Error())
			continue
		}
		rs.info = info
		if !strings.EqualFold(info.FullName, rs.name) {
			r.blockRepo(rs, PRProblemWriteBlocked, ReasonRepositoryMismatch,
				fmt.Sprintf("GitHub names the repository %s; update the configuration to that name", info.FullName))
			continue
		}
		for _, ri := range r.file.Repos {
			if strings.EqualFold(ri.Repo, rs.name) && ri.RepoID != info.ID {
				r.blockRepo(rs, PRProblemWriteBlocked, ReasonRepositoryMismatch,
					fmt.Sprintf("the repository's ID is %d, the records were made for ID %d", info.ID, ri.RepoID))
			}
		}
		if rs.blocked == "" {
			rs.ok = true
		}
	}
}

// recoverAll rebuilds the records of every configured repository when there
// is no record file. Every repository must be examined completely before
// anything is written; if one fails, nothing is initialized and no pull
// request is written anywhere this cycle.
func (r *prRun) recoverAll() {
	var all []PRRecord
	var inits []RepoInit
	fail := ""
	for _, rs := range r.repos {
		if !rs.ok {
			fail = fmt.Sprintf("%s: %s", rs.name, orDefault(rs.blockedDetail, "the repository could not be read"))
			break
		}
		recs, err := r.recoverRepo(rs)
		if err != nil {
			fail = fmt.Sprintf("%s: %v", rs.name, err)
			break
		}
		all = append(all, recs...)
		inits = append(inits, RepoInit{Repo: rs.name, RepoID: rs.info.ID, InitializedAt: r.now()})
	}
	if fail != "" {
		detail := "the pull request records are missing and could not be rebuilt from GitHub: " + fail
		for _, rs := range r.repos {
			if rs.blocked == "" {
				rs.blocked, rs.blockedDetail = ReasonRecordsUnverified, detail
			}
		}
		r.problem(PRStageProblem{Code: PRProblemRecordsUnverified, Reason: ReasonRecordsUnverified, Detail: detail})
		return
	}
	r.file.PRs = all
	r.file.Repos = inits
	r.file.InitializedAt = r.now()
	r.save()
}

// initAddedRepos examines a repository added to the configuration after the
// record file was made, once, before its first write.
func (r *prRun) initAddedRepos() {
	for _, rs := range r.repos {
		if !rs.ok {
			continue
		}
		known := false
		for _, ri := range r.file.Repos {
			known = known || strings.EqualFold(ri.Repo, rs.name)
		}
		if known {
			continue
		}
		recs, err := r.recoverRepo(rs)
		if err != nil {
			rs.ok = false
			r.blockRepo(rs, PRProblemRecordsUnverified, ReasonRecordsUnverified, "the repository's pull requests could not be verified: "+err.Error())
			continue
		}
		for _, rec := range recs {
			if r.recordByNumber(rec.RepoID, rec.Number) == nil {
				r.file.PRs = append(r.file.PRs, rec)
			}
		}
		r.file.Repos = append(r.file.Repos, RepoInit{Repo: rs.name, RepoID: rs.info.ID, InitializedAt: r.now()})
		if !r.save() {
			return
		}
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// recoverRepo lists every pull request of the repository and rebuilds a
// record from each of this tool's branches. Every one must carry a marker
// whose keys recompute and whose branch is the marker's attempt; anything
// else, or an incomplete listing, is an error.
func (r *prRun) recoverRepo(rs *repoState) ([]PRRecord, error) {
	if !r.active() {
		_, detail := r.inactiveDetail()
		return nil, errors.New(detail)
	}
	pulls, err := r.listPulls(rs, github.ListPullsOptions{State: "all"})
	if err != nil {
		r.haltFor(err)
		return nil, fmt.Errorf("listing pull requests: %v", err)
	}
	var out []PRRecord
	for _, pr := range pulls {
		if !rs.ours(pr) {
			continue
		}
		if pr.BaseRepoID != rs.info.ID {
			return nil, fmt.Errorf("pull request #%d merges into repository ID %d, not %d", pr.Number, pr.BaseRepoID, rs.info.ID)
		}
		m, err := r.verifiedMarker(rs, pr)
		if err != nil {
			return nil, fmt.Errorf("pull request #%d: %v", pr.Number, err)
		}
		rec := r.recordFromPull(rs, pr, m)
		if rec.State == PRStateClosed {
			// A supersede comment links the replacement; whether this tool or a
			// person closed it is not known, so it stays closed.
			if cs, err := r.listComments(rs, pr.Number); err == nil {
				for _, c := range cs {
					if n := supersededByIn(c.Body); n > 0 {
						rec.SupersededBy = n
					}
				}
			} else {
				r.haltFor(err)
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

// verifiedMarker parses and verifies the marker of a pull request on one of
// this tool's branches.
func (r *prRun) verifiedMarker(rs *repoState, pr github.PullRequest) (PRMarker, error) {
	m, err := parsePRMarker(pr.Body)
	if err != nil {
		return PRMarker{}, err
	}
	if err := m.verify(rs.info.ID); err != nil {
		return PRMarker{}, err
	}
	if !m.branchMatches(pr.HeadRef) {
		return PRMarker{}, fmt.Errorf("head branch %s is not the marker's attempt", pr.HeadRef)
	}
	return m, nil
}

// recordFromPull builds a record from a pull request and its verified
// marker. Only the marker vouches for it, so the record is marker-only:
// it suppresses its update but is never replaced or used to replace. A pull
// request whose head or base is not the marker's is recorded as changed by
// someone else.
func (r *prRun) recordFromPull(rs *repoState, pr github.PullRequest, m PRMarker) PRRecord {
	now := r.now()
	rec := PRRecord{
		Repo: rs.name, RepoID: rs.info.ID, Kind: kindOf(m.Kind), TargetKey: m.TargetKey, UpdateKey: m.UpdateKey, AttemptKey: m.AttemptKey,
		Branch: pr.HeadRef, Number: pr.Number, URL: pr.HTMLURL, BaseBranch: m.BaseBranch, BaseSHA: m.BaseSHA, HeadSHA: m.HeadSHA,
		Path: m.Path, Locations: sortedCopy(m.Locations), State: pullState(pr), FixTargets: m.FixTargets,
		CurrentRef: m.CurrentRef, CandidateTag: m.CandidateTag, CandidateDigest: m.CandidateDigest,
		Recovered: true, MarkerOnly: true, CreatedAt: now, UpdatedAt: now,
	}
	markModified(&rec, pr)
	return rec
}

// markModified flags a record whose pull request no longer has the head,
// base branch or base repository this tool created it with.
func markModified(rec *PRRecord, pr github.PullRequest) bool {
	if rec.UserModified {
		return false
	}
	switch {
	case pr.HeadSHA != rec.HeadSHA:
		rec.UserModified, rec.ModifiedReason = true, "the head is "+pr.HeadSHA+", not the commit this tool created"
	case pr.BaseRef != rec.BaseBranch:
		rec.UserModified, rec.ModifiedReason = true, "the base is "+pr.BaseRef+", not "+rec.BaseBranch
	case pr.BaseRepoID != rec.RepoID:
		rec.UserModified, rec.ModifiedReason = true, fmt.Sprintf("the pull request merges into repository ID %d, not %d", pr.BaseRepoID, rec.RepoID)
	default:
		return false
	}
	return true
}

// reconcileRepo checks the records of one repository against GitHub before
// any write: open pull requests of this tool not in the records are adopted
// when their marker verifies, every record open in the store is read again,
// and every unsettled attempt and replacement whose outcome is unknown is
// settled by reading. It runs even when there is nothing to propose. A
// failure stops writes to the repository this cycle.
func (r *prRun) reconcileRepo(rs *repoState) {
	if !rs.ok || rs.blocked != "" || !r.active() {
		return
	}
	fail := func(err error) {
		if r.haltFor(err) {
			rs.blocked, rs.blockedDetail = r.halt.reason, r.halt.detail
			return
		}
		r.blockRepo(rs, PRProblemWriteBlocked, ReasonReconcileFailed, err.Error())
	}

	open, err := r.listPulls(rs, github.ListPullsOptions{State: "open"})
	if err != nil {
		fail(fmt.Errorf("listing open pull requests: %w", err))
		return
	}
	seen := map[int]bool{}
	for _, pr := range open {
		if !rs.ours(pr) {
			continue
		}
		seen[pr.Number] = true
		if rec := r.recordByNumber(rs.info.ID, pr.Number); rec != nil {
			if rec.State != PRStateOpen {
				rec.State, rec.UpdatedAt = PRStateOpen, r.now()
			}
			if markModified(rec, pr) {
				rec.UpdatedAt = r.now()
			}
			continue
		}
		m, err := r.verifiedMarker(rs, pr)
		if err != nil {
			r.blockRepo(rs, PRProblemRecordsUnverified, ReasonRecordsUnverified, fmt.Sprintf("open pull request #%d on %s is not in the records and cannot be verified: %v", pr.Number, pr.HeadRef, err))
			return
		}
		if a := r.attempt(m.AttemptKey); a != nil && a.RepoID == rs.info.ID {
			// The stored attempt, not the marker, says what this tool
			// created. An unsettled attempt on this branch is settled below
			// from its own data, once every pull request of the branch is
			// seen; anything else on the attempt's branch was not opened by
			// this tool and is kept as changed by someone else.
			if !a.Status.settled() && pr.HeadRef == a.Branch {
				continue
			}
			rec := r.recordFromAttempt(a, pr)
			if !markModified(&rec, pr) {
				rec.UserModified, rec.ModifiedReason = true, "a pull request on the attempt's branch that this tool did not open"
			}
			r.file.PRs = append(r.file.PRs, rec)
			continue
		}
		r.file.PRs = append(r.file.PRs, r.recordFromPull(rs, pr, m))
	}
	for i := range r.file.PRs {
		rec := &r.file.PRs[i]
		if rec.RepoID != rs.info.ID || rec.State != PRStateOpen || seen[rec.Number] {
			continue
		}
		pr, err := r.s.cfg.GitHub.Pull(r.ctx, rs.name, rec.Number)
		if err != nil {
			fail(fmt.Errorf("reading pull request #%d: %w", rec.Number, err))
			r.save()
			return
		}
		if st := pullState(pr); st != rec.State {
			rec.State, rec.UpdatedAt = st, r.now()
		}
		if markModified(rec, pr) {
			rec.UpdatedAt = r.now()
		}
	}
	if !r.save() {
		return
	}

	for i := range r.file.Attempts {
		a := &r.file.Attempts[i]
		if a.RepoID != rs.info.ID || a.Status.settled() {
			continue
		}
		if !r.reconcileAttempt(rs, a) {
			if r.halt != nil {
				rs.blocked, rs.blockedDetail = r.halt.reason, r.halt.detail
			} else {
				r.blockRepo(rs, PRProblemWriteBlocked, ReasonReconcileFailed, fmt.Sprintf("attempt on branch %s could not be checked", a.Branch))
			}
			r.save()
			return
		}
		if !r.save() {
			return
		}
	}
	for i := range r.file.PRs {
		rec := &r.file.PRs[i]
		if rec.RepoID != rs.info.ID {
			continue
		}
		for j := range rec.Replacing {
			if rec.Replacing[j].State == ReplacementClosed {
				if !r.settleClose(rs, rec, &rec.Replacing[j]) {
					if r.halt != nil {
						rs.blocked, rs.blockedDetail = r.halt.reason, r.halt.detail
					} else {
						r.blockRepo(rs, PRProblemWriteBlocked, ReasonReconcileFailed, fmt.Sprintf("the close of pull request #%d could not be settled", rec.Replacing[j].OldNumber))
					}
					r.save()
					return
				}
			}
		}
	}
	if r.save() {
		rs.reconciled = true
	}
}

// branchPulls keeps the pull requests whose head is exactly the branch in the
// repository itself.
func (r *prRun) branchPulls(rs *repoState, pulls []github.PullRequest, branch string) []github.PullRequest {
	var out []github.PullRequest
	for _, pr := range pulls {
		if pr.HeadRef == branch && strings.EqualFold(pr.HeadRepoFullName, rs.info.FullName) {
			out = append(out, pr)
		}
	}
	return out
}

// reconcileAttempt finds out what exists of an unsettled attempt. It returns
// false when GitHub could not be read; the attempt's target is then blocked.
func (r *prRun) reconcileAttempt(rs *repoState, a *AttemptRecord) bool {
	gh := r.s.cfg.GitHub
	pulls, err := r.listPulls(rs, github.ListPullsOptions{State: "all", Head: rs.owner() + ":" + a.Branch})
	if err != nil {
		if !r.haltFor(err) {
			r.blockTarget(rs, a, ReasonReconcileFailed, "the pull requests of branch "+a.Branch+" could not be listed: "+err.Error())
		}
		return false
	}
	if pulls = r.branchPulls(rs, pulls, a.Branch); len(pulls) > 0 {
		r.settleAttemptPulls(rs, a, pulls)
		return true
	}
	sha, found, err := gh.Ref(r.ctx, rs.name, a.Branch)
	if err != nil {
		if !r.haltFor(err) {
			r.blockTarget(rs, a, ReasonReconcileFailed, "branch "+a.Branch+" could not be read: "+err.Error())
		}
		return false
	}
	switch {
	case !found:
		// Nothing but unreferenced objects can exist; the attempt may start
		// again. Whether a blob, tree or commit was stored cannot be told and
		// does not matter: such an object is never used.
		if k := r.opKind(a.PendingOp); k == OpCreateRef || k == OpCreatePull {
			r.settle(a.PendingOp, ResultFailed, "branch "+a.Branch+" does not exist and no pull request was opened from it")
		} else {
			r.settle(a.PendingOp, ResultUnknown, "not determinable; any object it stored is unused and the attempt starts again")
		}
		a.Status, a.Detail, a.PendingOp, a.UpdatedAt = AttemptAbandoned, "no branch and no pull request exist", "", r.now()
	case a.CommitSHA != "" && sha == a.CommitSHA:
		if a.Status == AttemptPRRequested {
			r.settle(a.PendingOp, ResultFailed, "no pull request exists for branch "+a.Branch)
		} else {
			r.settle(a.PendingOp, ResultOK, "branch "+a.Branch+" points at "+sha)
		}
		a.Status, a.Detail, a.PendingOp, a.UpdatedAt = AttemptRefCreated, "", "", r.now()
		rs.resumable[a.AttemptKey] = true
	default:
		a.Status, a.Detail, a.UpdatedAt = AttemptBlocked, "branch "+a.Branch+" points at "+sha+", not the attempt's commit", r.now()
		r.blockTarget(rs, a, ReasonBranchNotOurs, a.Detail)
	}
	return true
}

// settleAttemptPulls records the pull requests found for an attempt's
// branch, judged by the stored attempt: its commit, branch, base and keys.
// Exactly one whose head and marker match the attempt is adopted as this
// tool's. One whose head, marker head, base, base repository or keys differ
// is recorded as changed by someone else; it suppresses the update and
// settles the attempt. Several leave the attempt blocked. Every pull request
// of the branch is checked before the attempt is settled.
func (r *prRun) settleAttemptPulls(rs *repoState, a *AttemptRecord, pulls []github.PullRequest) {
	for _, pr := range pulls {
		if r.recordByNumber(rs.info.ID, pr.Number) != nil {
			continue
		}
		rec := r.recordFromAttempt(a, pr)
		rec.URL = pr.HTMLURL
		markModified(&rec, pr)
		m, err := parsePRMarker(pr.Body)
		if !rec.UserModified && (err != nil || m.UpdateKey != a.UpdateKey || m.AttemptKey != a.AttemptKey ||
			m.HeadSHA != a.CommitSHA || m.BaseSHA != a.BaseSHA || m.RepoID != a.RepoID) {
			rec.UserModified, rec.ModifiedReason = true, "the description no longer carries this attempt's marker"
		}
		if !rec.UserModified && a.CommitSHA == "" {
			rec.UserModified, rec.ModifiedReason = true, "the attempt recorded no commit"
		}
		r.file.PRs = append(r.file.PRs, rec)
	}
	if len(pulls) > 1 {
		// Which of them this tool opened cannot be told, so none is trusted:
		// every one, recorded before or not, only suppresses its update.
		for _, pr := range pulls {
			if rec := r.recordByNumber(rs.info.ID, pr.Number); rec != nil && !rec.UserModified {
				rec.UserModified, rec.ModifiedReason, rec.UpdatedAt = true, fmt.Sprintf("%d pull requests exist for branch %s", len(pulls), a.Branch), r.now()
			}
		}
		a.Status, a.Detail, a.UpdatedAt = AttemptBlocked, fmt.Sprintf("%d pull requests exist for branch %s", len(pulls), a.Branch), r.now()
		r.blockTarget(rs, a, ReasonAttemptUnsettled, a.Detail)
		return
	}
	pr := pulls[0]
	r.settle(a.PendingOp, ResultOK, fmt.Sprintf("pull request #%d exists for branch %s", pr.Number, a.Branch))
	a.Status, a.PRNumber, a.PendingOp, a.Detail, a.UpdatedAt = AttemptPRCreated, pr.Number, "", "", r.now()
	if rec := r.recordByNumber(rs.info.ID, pr.Number); rec != nil && rec.UserModified {
		a.Detail = rec.ModifiedReason
	}
}

// opKind is the kind of an operation in the log, "" when it is not there.
func (r *prRun) opKind(id string) OperationKind {
	for _, op := range r.file.Operations {
		if op.ID == id {
			return op.Kind
		}
	}
	return ""
}
