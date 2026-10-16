package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// PRGitHub is the part of the GitHub writer the pull request stage uses. It
// has no way to move or delete a ref or to merge.
type PRGitHub interface {
	Repository(ctx context.Context, repo string) (github.RepoInfo, error)
	Commit(ctx context.Context, repo, sha string) (github.CommitInfo, error)
	Ref(ctx context.Context, repo, branch string) (sha string, found bool, err error)
	ListPulls(ctx context.Context, repo string, o github.ListPullsOptions) ([]github.PullRequest, bool, error)
	Pull(ctx context.Context, repo string, number int) (github.PullRequest, error)
	ListIssueComments(ctx context.Context, repo string, number, page int) ([]github.IssueComment, bool, error)
	CreateBlob(ctx context.Context, repo string, content []byte) (string, error)
	CreateTree(ctx context.Context, repo, baseTree string, entries []github.TreeEntry) (string, error)
	CreateCommit(ctx context.Context, repo, message, tree string, parents []string) (string, error)
	CreateRef(ctx context.Context, repo, branch, sha string) error
	CreatePull(ctx context.Context, repo string, p github.NewPull) (github.PullRequest, error)
	ClosePull(ctx context.Context, repo string, number int) error
	CreateIssueComment(ctx context.Context, repo string, number int, body string) error
}

// PRSource reads the Compose file at the base branch.
type PRSource interface {
	ResolveBranch(ctx context.Context, repo, branch string) (string, error)
	ReadFile(ctx context.Context, repo, sha, path string) (github.File, error)
}

// CandidateResolver resolves a candidate tag again, without any cache, right
// before a pull request is opened or an older one is replaced.
type CandidateResolver interface {
	Resolve(ctx context.Context, repo, tagOrDigest string, platform inventory.Platform) (registry.Resolution, error)
}

var (
	_ PRGitHub          = (*github.Writer)(nil)
	_ PRSource          = (*github.Client)(nil)
	_ CandidateResolver = (*registry.Client)(nil)
)

// PRLimits caps the pull requests of the stage.
type PRLimits struct {
	// NewPRsPerCycle is how many pull requests one cycle may open.
	NewPRsPerCycle int
	// OpenPRs is how many of this tool's pull requests may be open at once in
	// the configured repositories. An old one is never closed to make room.
	OpenPRs int
}

// PRStageConfig holds what a PRStage needs.
type PRStageConfig struct {
	GitHub   PRGitHub
	Source   PRSource
	Resolver CandidateResolver
	Store    PRStorage
	Limits   PRLimits
	// MaxListPages caps the pages (of 100) of one pull request or comment
	// listing; a listing the cap stops is incomplete. Zero means 30.
	MaxListPages int
	// Language is the wording of the pull request bodies; the empty value
	// means English. A body's wording never changes how a pull request is
	// recognised, since only its marker is read back.
	Language BodyLanguage
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// PRStageInput is one cycle's input. The caller runs the stage only when
// pull requests are enabled and the plan was saved; the deadline is the
// context's.
type PRStageInput struct {
	Plan       Plan
	Containers []inventory.Container
	Mappings   []ComposeMapping
	// Repositories are further repositories to examine and, for their units,
	// to write to: those the Dockerfile mappings name, which a Compose mapping
	// need not share. A repository of a unit is always examined.
	Repositories []string
}

// PRStage opens and tracks pull requests that update the image tag of
// Compose services, and the base image tag of Dockerfiles, to an adopted
// candidate, and that write the lockfile (and manifest) a language package
// update produced. All kinds share the stage's records, limits and writes.
//
// Every external write is preceded by a saved intent and followed by a saved
// result, so a crash at any point leaves records from which the next cycle
// finds out, by reading GitHub, what happened. A write whose outcome is
// unknown is never sent again blindly: all writes stop for the rest of the
// cycle and the next cycle settles it by reading. A failure to save stops
// all writes too. Refs are only created, never moved or deleted.
type PRStage struct {
	cfg PRStageConfig
}

// NewPRStage validates cfg and returns a PRStage.
func NewPRStage(cfg PRStageConfig) (*PRStage, error) {
	if cfg.GitHub == nil || cfg.Source == nil || cfg.Resolver == nil || cfg.Store == nil {
		return nil, errors.New("remediation: the pull request stage needs a GitHub writer, a source reader, a candidate resolver and a store")
	}
	if cfg.Limits.NewPRsPerCycle <= 0 || cfg.Limits.OpenPRs <= 0 {
		return nil, errors.New("remediation: pull request limits must be positive")
	}
	if err := cfg.Language.validate(); err != nil {
		return nil, err
	}
	if cfg.MaxListPages < 0 {
		return nil, errors.New("remediation: the listing page cap must not be negative")
	}
	if cfg.MaxListPages == 0 {
		cfg.MaxListPages = 30
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &PRStage{cfg: cfg}, nil
}

// Language is the wording this stage writes pull request bodies in.
func (s *PRStage) Language() BodyLanguage {
	if s.cfg.Language == "" {
		return BodyEN
	}
	return s.cfg.Language
}

// repoState is one configured repository during a run.
type repoState struct {
	name string // as configured
	info github.RepoInfo
	ok   bool // info was read and matches the configuration
	// blocked, when set, stops writes to the repository this cycle.
	blocked       Reason
	blockedDetail string
	// blockedTargets are target keys with an attempt that cannot be settled.
	blockedTargets map[string]string
	// resumable are unsettled attempts whose branch was verified at the
	// recorded commit this cycle.
	resumable map[string]bool
	// reconciled is set once the repository's records were checked against
	// GitHub this cycle.
	reconciled bool
}

func (rs *repoState) owner() string {
	o, _, _ := strings.Cut(rs.info.FullName, "/")
	return o
}

// writable reports whether writes to the repository may proceed.
func (rs *repoState) writable() bool { return rs.ok && rs.blocked == "" && rs.reconciled }

// stopInfo is a condition that ends every further write in the run.
type stopInfo struct {
	status PRUnitStatus
	reason Reason
	detail string
}

type prRun struct {
	s   *PRStage
	ctx context.Context

	file  PRStoreFile
	repos []*repoState
	byKey map[string]*repoState // lower-case name

	stop     *stopInfo // writes ended (outcome unknown, storage)
	halt     *halt     // all GitHub work ended (rate limit, budget, deadline)
	problems []PRStageProblem
	newPRs   int
}

func (r *prRun) now() time.Time { return r.s.cfg.Now().UTC() }

// problem records a problem once per code, repository and target.
func (r *prRun) problem(p PRStageProblem) {
	for _, have := range r.problems {
		if have.Code == p.Code && have.Repo == p.Repo && have.Target == p.Target {
			return
		}
	}
	r.problems = append(r.problems, p)
}

// blockRepo stops writes to one repository and reports it.
func (r *prRun) blockRepo(rs *repoState, code PRProblemCode, reason Reason, detail string) {
	if rs.blocked == "" {
		rs.blocked, rs.blockedDetail = reason, detail
	}
	r.problem(PRStageProblem{Code: code, Repo: rs.name, Reason: reason, Detail: detail})
}

// blockTarget stops new attempts for the target of an attempt and reports
// it. Blocked attempts are examined again every cycle, so the problem is
// reported for as long as it lasts.
func (r *prRun) blockTarget(rs *repoState, a *AttemptRecord, reason Reason, detail string) {
	rs.blockedTargets[a.TargetKey] = detail
	r.problem(PRStageProblem{Code: PRProblemWriteBlocked, Repo: rs.name, Target: targetName(a.Path, a.Locations), Reason: reason,
		Detail: fmt.Sprintf("%s in %s: %s", strings.Join(a.Locations, ", "), a.Path, detail)})
}

// targetName names a target by file and image locations.
func targetName(path string, locations []string) string {
	return path + " (" + strings.Join(locations, ", ") + ")"
}

// inactiveDetail says why GitHub work has ended in the run.
func (r *prRun) inactiveDetail() (Reason, string) {
	switch {
	case r.halt != nil:
		return r.halt.reason, r.halt.detail
	case r.stop != nil:
		return r.stop.reason, r.stop.detail
	}
	return ReasonReconcileFailed, "GitHub work has ended in this cycle"
}

// storageFailed ends all writes after a failed save.
func (r *prRun) storageFailed(err error) {
	if r.stop == nil || r.stop.reason != ReasonStorageFailed {
		r.stop = &stopInfo{PRStatusWriteBlocked, ReasonStorageFailed, err.Error()}
	}
	r.problem(PRStageProblem{Code: PRProblemStorageFailed, Reason: ReasonStorageFailed, Detail: err.Error()})
}

// save writes the records. A failure ends all writes in the run.
func (r *prRun) save() bool {
	if r.stop != nil && r.stop.reason == ReasonStorageFailed {
		return false
	}
	r.file.trimOperations(0)
	if err := r.s.cfg.Store.Save(r.file); err != nil {
		r.storageFailed(err)
		return false
	}
	return true
}

// reserve makes room in the operation log for n more events, removing only
// delivered events of settled attempts. Without room no new external
// operation starts in this run.
func (r *prRun) reserve(n int) bool {
	if r.file.trimOperations(n) {
		return true
	}
	detail := fmt.Sprintf("the operation log is full (%d events kept) with events that are not yet delivered or belong to unsettled attempts", len(r.file.Operations))
	if r.stop == nil {
		r.stop = &stopInfo{PRStatusWriteBlocked, ReasonStorageFull, detail}
	}
	r.problem(PRStageProblem{Code: PRProblemStorageFull, Reason: ReasonStorageFull, Detail: detail})
	return false
}

// event appends one operation event and returns it.
func (r *prRun) event(ev OperationEvent) OperationEvent {
	if r.file.NextSeq < 1 {
		r.file.NextSeq = 1
	}
	ev.Seq = r.file.NextSeq
	r.file.NextSeq++
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("op-%d", ev.Seq)
	}
	ev.At = r.now()
	r.file.Operations = append(r.file.Operations, ev)
	return ev
}

// settle appends the found-out outcome of an operation whose result was
// unknown.
func (r *prRun) settle(opID string, result OperationResult, detail string) {
	if opID == "" {
		return
	}
	var orig *OperationEvent
	for i := range r.file.Operations {
		if r.file.Operations[i].ID == opID {
			orig = &r.file.Operations[i]
			break
		}
	}
	ev := OperationEvent{ID: opID, Phase: PhaseSettled, Result: result, Error: detail}
	if orig != nil {
		ev.Kind, ev.Repo, ev.AttemptKey, ev.Number = orig.Kind, orig.Repo, orig.AttemptKey, orig.Number
	}
	r.event(ev)
}

// errWritesStopped is returned by write when a save failed before the
// request could be sent.
var errWritesStopped = errors.New("writes are stopped")

// write runs one external write: it saves the intent, sends the request
// once, and saves the result. An unknown outcome ends all writes in the run;
// a rate limit or exhausted budget ends all GitHub work. It returns the
// operation ID with fn's result.
func (r *prRun) write(op OperationEvent, fn func() (string, error)) (string, string, error) {
	op.Phase = PhaseIntent
	ev := r.event(op)
	if !r.save() {
		return "", ev.ID, errWritesStopped
	}
	ref, err := fn()
	res := OperationEvent{ID: ev.ID, Phase: PhaseResult, Kind: op.Kind, Repo: op.Repo, AttemptKey: op.AttemptKey, Number: op.Number, Ref: ref}
	switch {
	case err == nil:
		res.Result = ResultOK
	case errors.Is(err, github.ErrOutcomeUnknown):
		res.Result, res.Error = ResultUnknown, err.Error()
		if r.stop == nil {
			r.stop = &stopInfo{PRStatusDeferred, ReasonWriteOutcomeUnknown, fmt.Sprintf("the outcome of %s on %s is unknown; the next cycle settles it by reading", op.Kind, op.Repo)}
		}
	default:
		res.Result, res.Error = ResultFailed, err.Error()
		r.haltFor(err)
	}
	r.event(res)
	r.save()
	return ref, ev.ID, err
}

// haltFor ends all GitHub work in the run when err is a rate limit, an
// exhausted budget or the deadline. It reports whether it did.
func (r *prRun) haltFor(err error) bool {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, registry.ErrTimeout) && r.ctx.Err() != nil:
		if r.halt == nil {
			r.halt = &halt{ReasonCycleDeadline, err.Error()}
		}
	case errors.Is(err, github.ErrRateLimited):
		if r.halt == nil {
			r.halt = &halt{ReasonGitHubRateLimited, err.Error()}
		}
	case errors.Is(err, github.ErrBudgetExhausted):
		if r.halt == nil {
			r.halt = &halt{ReasonGitHubBudget, err.Error()}
		}
	default:
		return false
	}
	return true
}

// active reports whether GitHub may still be read.
func (r *prRun) active() bool {
	if r.halt == nil {
		if err := r.ctx.Err(); err != nil {
			r.haltFor(err)
		}
	}
	return r.halt == nil && (r.stop == nil || r.stop.reason != ReasonStorageFailed)
}

// canWrite reports whether a new write may start.
func (r *prRun) canWrite(rs *repoState) bool {
	return r.active() && r.stop == nil && rs.writable()
}

// listAll reads every page of a listing up to the page cap; a listing the
// cap or an error stops is an error.
func listAll[T any](r *prRun, page func(int) ([]T, bool, error)) ([]T, error) {
	var out []T
	for p := 1; p <= r.s.cfg.MaxListPages; p++ {
		items, next, err := page(p)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if !next {
			return out, nil
		}
	}
	return nil, fmt.Errorf("the listing has more than %d pages", r.s.cfg.MaxListPages)
}

func (r *prRun) listPulls(rs *repoState, o github.ListPullsOptions) ([]github.PullRequest, error) {
	o.PerPage = 100
	return listAll(r, func(p int) ([]github.PullRequest, bool, error) {
		o.Page = p
		return r.s.cfg.GitHub.ListPulls(r.ctx, rs.name, o)
	})
}

func (r *prRun) listComments(rs *repoState, number int) ([]github.IssueComment, error) {
	return listAll(r, func(p int) ([]github.IssueComment, bool, error) {
		return r.s.cfg.GitHub.ListIssueComments(r.ctx, rs.name, number, p)
	})
}

// ours reports whether a pull request's head is a branch of this tool in the
// repository itself. A pull request from a fork (or from a deleted
// repository) is never one this tool opened and is ignored.
func (rs *repoState) ours(pr github.PullRequest) bool {
	return strings.HasPrefix(pr.HeadRef, branchPrefix) && strings.EqualFold(pr.HeadRepoFullName, rs.info.FullName)
}

// Run executes the stage for one cycle.
func (s *PRStage) Run(ctx context.Context, in PRStageInput) PRStageResult {
	r := &prRun{s: s, ctx: ctx, byKey: map[string]*repoState{}}
	units := buildComposeUnits(in.Plan, in.Containers, in.Mappings)
	units = append(units, buildDockerfileUnits(in.Plan)...)
	units = append(units, buildLanguageUnits(in.Plan)...)
	addRepo := func(name string) {
		k := strings.ToLower(name)
		if r.byKey[k] == nil {
			rs := &repoState{name: name, blockedTargets: map[string]string{}, resumable: map[string]bool{}}
			r.byKey[k] = rs
			r.repos = append(r.repos, rs)
		}
	}
	for _, m := range in.Mappings {
		addRepo(m.Repository)
	}
	for _, name := range in.Repositories {
		addRepo(name)
	}
	for _, u := range units {
		addRepo(u.repo)
	}

	unlock, err := s.cfg.Store.Lock()
	if err != nil {
		reason := ReasonStoreLocked
		if !errors.Is(err, ErrPRStoreLocked) {
			reason = ReasonStorageFailed
		}
		r.stop = &stopInfo{PRStatusWriteBlocked, reason, err.Error()}
		r.problem(PRStageProblem{Code: PRProblemWriteBlocked, Reason: reason, Detail: err.Error()})
		return r.result(units)
	}
	defer unlock()

	file, found, err := s.cfg.Store.Load()
	if err != nil {
		r.storageFailed(err)
		return r.result(units)
	}
	if !found {
		file = PRStoreFile{Version: PRStoreVersion, NextSeq: 1}
	}
	r.file = file

	r.loadRepos()
	if !found {
		r.recoverAll()
	} else {
		r.initAddedRepos()
	}
	for _, rs := range r.repos {
		r.reconcileRepo(rs)
	}

	views := make([]PRUnit, len(units))
	for i, u := range units {
		views[i] = r.processUnit(in.Plan, u)
	}
	r.resumeReplacements()
	return r.finish(units, views)
}

// result builds the outcome of a run that could not use the records.
func (r *prRun) result(units []*composeUnit) PRStageResult {
	out := PRStageResult{Problems: r.problems}
	for _, u := range units {
		v := unitView(u)
		if u.manual {
			v.Status, v.Reason, v.Detail = PRStatusManual, u.manualReason, u.manualDetail
		} else {
			v.Status, v.Reason, v.Detail = r.stop.status, r.stop.reason, r.stop.detail
		}
		out.Units = append(out.Units, v)
	}
	sortProblems(out.Problems)
	return out
}

// finish fills the unit views from the final records and reports the
// undelivered events.
func (r *prRun) finish(units []*composeUnit, views []PRUnit) PRStageResult {
	for i := range views {
		v := &views[i]
		if v.UpdateKey == "" {
			continue
		}
		switch v.Status {
		case PRStatusCreated, PRStatusOpen, PRStatusMerged, PRStatusSuppressed:
		default:
			continue
		}
		rec := r.recordByUpdateKey(v.UpdateKey)
		if rec == nil {
			continue
		}
		v.Number, v.URL, v.State, v.UserModified = rec.Number, rec.URL, rec.State, rec.UserModified
		v.AttemptKey = rec.AttemptKey
		v.FixTargets = rec.FixTargets
		v.ReplacedBy = rec.ReplacedBy
		v.Replacing = append([]Replacement(nil), rec.Replacing...)
		v.Replaced = nil
		for _, rp := range rec.Replacing {
			if rp.State == ReplacementDone {
				if old := r.recordByNumber(rec.RepoID, rp.OldNumber); old != nil && old.State == PRStateReplaced {
					v.Replaced = append(v.Replaced, rp.OldNumber)
				}
			}
		}
	}
	ops, last := r.file.undelivered()
	out := PRStageResult{Units: views, Operations: ops, LastSeq: last, Problems: r.problems}
	sortProblems(out.Problems)
	return out
}

func sortProblems(p []PRStageProblem) {
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].Code != p[j].Code {
			return p[i].Code < p[j].Code
		}
		if p[i].Repo != p[j].Repo {
			return p[i].Repo < p[j].Repo
		}
		return p[i].Target < p[j].Target
	})
}

// unitView is the part of a unit's outcome known before any GitHub work.
func unitView(u *composeUnit) PRUnit {
	v := PRUnit{
		Key: u.key, Repo: u.repo, BaseBranch: u.baseBranch, Path: u.path,
		Services: u.services, Locations: u.locations, Workloads: u.workloads, AlsoRunning: u.also,
		Current: u.current,
	}
	if u.df != nil {
		v.Kind = prKindDockerfile
	}
	if u.lang != nil {
		v.Kind, v.ItemKey, v.Language = prKindLanguage, u.lang.item.Key, u.lang.view
	}
	if u.candidate != nil {
		v.CandidateTag, v.CandidateDigest = u.candidate.Tag, u.candidate.TopDigest
	}
	return v
}

// recordByUpdateKey returns the record of an update: an open one first,
// then a merged one, then any.
func (r *prRun) recordByUpdateKey(key string) *PRRecord {
	var best *PRRecord
	rank := func(s PRState) int {
		switch s {
		case PRStateOpen:
			return 3
		case PRStateMerged:
			return 2
		}
		return 1
	}
	for i := range r.file.PRs {
		rec := &r.file.PRs[i]
		if rec.UpdateKey == key && (best == nil || rank(rec.State) > rank(best.State)) {
			best = rec
		}
	}
	return best
}

func (r *prRun) recordByNumber(repoID int64, number int) *PRRecord {
	for i := range r.file.PRs {
		if r.file.PRs[i].RepoID == repoID && r.file.PRs[i].Number == number {
			return &r.file.PRs[i]
		}
	}
	return nil
}

func (r *prRun) attempt(key string) *AttemptRecord {
	for i := range r.file.Attempts {
		if r.file.Attempts[i].AttemptKey == key {
			return &r.file.Attempts[i]
		}
	}
	return nil
}

// openCount is how many records of the configured repositories are open.
func (r *prRun) openCount() int {
	ids := map[int64]bool{}
	for _, rs := range r.repos {
		if rs.ok {
			ids[rs.info.ID] = true
		}
	}
	n := 0
	for _, rec := range r.file.PRs {
		if rec.State == PRStateOpen && (ids[rec.RepoID] || r.byKey[strings.ToLower(rec.Repo)] != nil) {
			n++
		}
	}
	return n
}

// unitCtx is the state of one unit being processed.
type unitCtx struct {
	plan      Plan
	u         *composeUnit
	rs        *repoState
	v         *PRUnit
	targetKey string
	updateKey string
}

func (c *unitCtx) set(status PRUnitStatus, reason Reason, detail string) {
	c.v.Status, c.v.Reason, c.v.Detail = status, reason, detail
}

// stopped sets the unit's status from the condition that prevents writes
// and reports whether there is one.
func (r *prRun) stopped(c *unitCtx) bool {
	switch {
	case r.halt != nil:
		c.set(PRStatusDeferred, r.halt.reason, r.halt.detail)
	case r.stop != nil:
		c.set(r.stop.status, r.stop.reason, r.stop.detail)
	case !c.rs.writable():
		reason, detail := c.rs.blocked, c.rs.blockedDetail
		if reason == "" {
			reason, detail = ReasonReconcileFailed, "the repository's records were not checked against GitHub this cycle"
		}
		c.set(PRStatusWriteBlocked, reason, detail)
	default:
		return false
	}
	return true
}

// readFailure records a failed read for the unit.
func (r *prRun) readFailure(c *unitCtx, what string, err error) {
	if r.haltFor(err) {
		c.set(PRStatusDeferred, r.halt.reason, r.halt.detail)
		return
	}
	if errors.Is(err, github.ErrByteBudgetExhausted) {
		c.set(PRStatusDeferred, ReasonByteBudget, err.Error())
		return
	}
	c.set(PRStatusFailed, ReasonGitHubError, what+": "+err.Error())
}

// recheckCandidate resolves the candidate tag again and compares its top
// digest with the verified one. ok is false after the unit's status was set.
func (r *prRun) recheckCandidate(c *unitCtx, repoRef string, cand ImageState) bool {
	platform, ok := parsePlatform(cand.Platform)
	if !ok {
		c.set(PRStatusDeferred, ReasonRegistryRecheck, "the candidate's platform is not known")
		return false
	}
	res, err := r.s.cfg.Resolver.Resolve(r.ctx, repoRef, cand.Tag, platform)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, registry.ErrTimeout) {
			r.haltFor(err)
		}
		c.set(PRStatusDeferred, ReasonRegistryRecheck, "the candidate tag could not be resolved again: "+err.Error())
		return false
	}
	if res.TopDigest != cand.TopDigest {
		c.set(PRStatusDeferred, ReasonCandidateChanged, fmt.Sprintf("tag %s now points at %s, not the verified %s", cand.Tag, res.TopDigest, cand.TopDigest))
		return false
	}
	return true
}

func parsePlatform(s string) (inventory.Platform, bool) {
	os, arch, ok := strings.Cut(s, "/")
	if !ok || os == "" || arch == "" || strings.Contains(arch, "/") {
		return inventory.Platform{}, false
	}
	return inventory.Platform{OS: os, Architecture: arch}, true
}

// processUnit decides and, when allowed, carries out the pull request of one
// unit.
func (r *prRun) processUnit(plan Plan, u *composeUnit) PRUnit {
	v := unitView(u)
	if u.manual {
		v.Status, v.Reason, v.Detail = PRStatusManual, u.manualReason, u.manualDetail
		return v
	}
	rs := r.byKey[strings.ToLower(u.repo)]
	c := &unitCtx{plan: plan, u: u, rs: rs, v: &v}
	if !rs.ok {
		r.stopped(c)
		if v.Status == "" {
			c.set(PRStatusWriteBlocked, rs.blocked, rs.blockedDetail)
		}
		return v
	}
	c.targetKey = TargetKeyOf(u.kind(), rs.info.ID, u.baseBranch, u.path, u.locations)
	if u.lang != nil && u.lang.proposedFP != "" {
		// The item was not updated again: it stands for the pull request made
		// from the same inputs, whose keys it takes.
		rec := r.fileProposal(rs, *u.lang.item, u.lang.proposedFP)
		if rec == nil {
			c.set(PRStatusDeferred, ReasonProposalNotFound, "the pull request this item was tied to is not in the records; the next cycle updates again")
			return v
		}
		// The record matched the item's own target key; its update key is the
		// update's.
		c.updateKey = rec.UpdateKey
		v.Language = languageViewOfTied(*u.lang.item, rec)
	} else if u.lang != nil {
		c.updateKey = LangUpdateKey(c.targetKey, u.lang.record.Packages, u.lang.record.ManifestEdits, u.lang.record.Chain...)
	} else {
		c.updateKey = UpdateKey(c.targetKey, u.current, u.candidate.Tag, u.candidate.TopDigest)
	}
	v.TargetKey, v.UpdateKey = c.targetKey, c.updateKey

	if rec := r.recordByUpdateKey(c.updateKey); rec != nil {
		r.addInputFingerprint(c, rec)
		switch rec.State {
		case PRStateOpen:
			c.set(PRStatusOpen, "", "")
			if !rec.UserModified && !r.targetBlocked(rec.RepoID, rec.TargetKey) {
				r.decideReplacements(rec)
			}
		case PRStateMerged:
			c.set(PRStatusMerged, "", "merged; deployment of the merge is not confirmed")
		default:
			c.set(PRStatusSuppressed, "", fmt.Sprintf("pull request #%d was %s; this update is not proposed again", rec.Number, rec.State))
		}
		return v
	}

	if r.stopped(c) {
		return v
	}
	if detail, blocked := rs.blockedTargets[c.targetKey]; blocked {
		c.set(PRStatusWriteBlocked, ReasonAttemptUnsettled, detail)
		return v
	}
	if u.lang != nil && u.lang.proposedFP != "" {
		// Its pull request is gone from the records without any trace of what
		// became of it; nothing is written for an item with no update.
		c.set(PRStatusDeferred, ReasonProposalNotFound, "the pull request this item was tied to is not open; the next cycle updates again")
		return v
	}
	if u.lang != nil && !r.languageNotInOpenPR(c) {
		return v
	}
	if r.newPRs >= r.s.cfg.Limits.NewPRsPerCycle {
		c.set(PRStatusDeferred, ReasonPRLimit, fmt.Sprintf("%d pull requests were opened this cycle (limit %d)", r.newPRs, r.s.cfg.Limits.NewPRsPerCycle))
		return v
	}
	if n := r.openCount(); n >= r.s.cfg.Limits.OpenPRs {
		c.set(PRStatusDeferred, ReasonPRLimit, fmt.Sprintf("%d pull requests are open (limit %d)", n, r.s.cfg.Limits.OpenPRs))
		return v
	}
	if u.lang != nil {
		r.createPull(c, "")
		return v
	}
	imageRepo, _ := inventory.RepositoryOf(u.current)
	if !r.recheckCandidate(c, imageRepo, *u.candidate) {
		return v
	}
	r.createPull(c, imageRepo)
	return v
}

// editedFile is one file of the commit an attempt builds.
type editedFile struct {
	Path    string
	Mode    string
	Content []byte
	BlobSHA string
}

// createPull builds the edit and runs the attempt for it, resuming an
// earlier attempt of the same content when its branch is verified.
func (r *prRun) createPull(c *unitCtx, imageRepo string) {
	u, rs, gh := c.u, c.rs, r.s.cfg.GitHub
	base, err := r.s.cfg.Source.ResolveBranch(r.ctx, rs.name, u.baseBranch)
	if err != nil {
		r.readFailure(c, "resolve the base branch", err)
		return
	}
	var (
		files    []editedFile
		inputSHA string
		change   prChange
	)
	if u.lang != nil {
		var ok bool
		if files, inputSHA, ok = r.languageFiles(c, base); !ok {
			return
		}
	} else {
		if u.df != nil && !r.dockerfileSourceUnchanged(c, base) {
			return
		}
		file, err := r.s.cfg.Source.ReadFile(r.ctx, rs.name, base, u.path)
		if err != nil {
			var nr *github.NotRegularFileError
			notFound, unusable, what := ReasonComposeFileNotFound, ReasonComposeFileUnusable, "read the Compose file"
			if u.df != nil {
				notFound, unusable, what = ReasonDockerfileFileNotFound, ReasonDockerfileFileUnusable, "read the Dockerfile"
			}
			switch {
			case errors.Is(err, github.ErrNotFound):
				c.set(PRStatusManual, notFound, err.Error())
			case errors.As(err, &nr), errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrTooLarge):
				c.set(PRStatusManual, unusable, err.Error())
			default:
				r.readFailure(c, what, err)
			}
			return
		}
		edited, ch, ok := r.editSource(c, file.Content)
		if !ok {
			return
		}
		mode := file.Mode
		if mode == "" {
			mode = "100644"
		}
		files = []editedFile{{Path: u.path, Mode: mode, Content: edited, BlobSHA: gitBlobSHA(edited)}}
		inputSHA, change = file.SHA, ch
	}
	contents := map[string][]byte{}
	changes := make([]FileChange, 0, len(files))
	for _, f := range files {
		contents[f.Path] = f.Content
		changes = append(changes, FileChange{Path: f.Path, Mode: f.Mode, BlobSHA: f.BlobSHA})
	}
	mode, newBlob := changes[0].Mode, changes[0].BlobSHA
	attemptKey := AttemptKey(c.updateKey, base, inputSHA, changes)
	var branch string
	switch {
	case u.lang != nil:
		branch, err = LanguageBranchName(u.services, string(u.lang.manager), attemptKey)
	case u.df != nil:
		branch, err = DockerfileBranchName(u.services, u.candidate.Tag, attemptKey)
	default:
		branch, err = BranchName(u.services, u.candidate.Tag, attemptKey)
	}
	if err != nil {
		c.set(PRStatusFailed, ReasonGitHubError, err.Error())
		return
	}
	c.v.AttemptKey = attemptKey

	// Earlier attempts of the same target: a verified branch of another
	// attempt is left without a pull request (the base moved); anything not
	// verified this cycle blocks a new attempt.
	resume := false
	for i := range r.file.Attempts {
		a := &r.file.Attempts[i]
		if a.TargetKey != c.targetKey || a.RepoID != rs.info.ID || a.Status.settled() {
			continue
		}
		switch {
		case a.AttemptKey == attemptKey && rs.resumable[a.AttemptKey]:
			resume = true
		case rs.resumable[a.AttemptKey]:
			a.Status, a.Detail, a.UpdatedAt = AttemptAbandonedWithoutPR, "the base branch moved; the branch is kept without a pull request", r.now()
			delete(rs.resumable, a.AttemptKey)
			if !r.save() {
				c.set(r.stop.status, r.stop.reason, r.stop.detail)
				return
			}
		default:
			c.set(PRStatusWriteBlocked, ReasonAttemptUnsettled, fmt.Sprintf("attempt %s (%s) is not settled", a.AttemptKey[:12], a.Status))
			return
		}
	}
	a := r.attempt(attemptKey)
	// Without any record of this attempt, a branch of its name may still be
	// ours from a run whose records were lost; see buildCommit.
	recorded := a != nil
	if a != nil && a.Status == AttemptAbandonedWithoutPR {
		// The base is back at the commit of a kept branch: reuse the branch
		// if it still points at the recorded commit.
		sha, found, err := gh.Ref(r.ctx, rs.name, a.Branch)
		if err != nil {
			r.readFailure(c, "read the branch", err)
			return
		}
		if found && sha == a.CommitSHA {
			a.Status, a.Detail = AttemptRefCreated, ""
			resume = true
		} else {
			a.Status = AttemptAbandoned
		}
	}
	if a != nil && a.Status == AttemptPRCreated {
		c.set(PRStatusWriteBlocked, ReasonAttemptUnsettled, "the attempt has a pull request that is not in the records")
		return
	}

	need := 2 // the pull request
	if !resume {
		need = 2 * (len(changes) + 4) // blobs, tree, commit, ref and pull request
	}
	if !r.reserve(need) {
		c.set(r.stop.status, r.stop.reason, r.stop.detail)
		return
	}
	now := r.now()
	if !resume {
		baseCommit, err := gh.Commit(r.ctx, rs.name, base)
		if err != nil {
			r.readFailure(c, "read the base commit", err)
			return
		}
		fresh := AttemptRecord{
			AttemptKey: attemptKey, UpdateKey: c.updateKey, TargetKey: c.targetKey,
			Repo: rs.name, RepoID: rs.info.ID, Branch: branch, BaseBranch: u.baseBranch, BaseSHA: base,
			Path: u.path, Mode: mode, InputSHA: inputSHA, NewBlobSHA: newBlob, Status: AttemptIntent,
			Services: u.services, Locations: u.locations, CurrentRef: u.current, Kind: recordedKind(u.kind()),
			FixTargets: u.fixTargets(), Evidence: u.evidence(c.plan), CreatedAt: now, UpdatedAt: now,
		}
		if u.candidate != nil {
			fresh.CandidateTag, fresh.CandidateDigest = u.candidate.Tag, u.candidate.TopDigest
		}
		if u.lang != nil {
			fresh.Changes, fresh.Lang, fresh.Language = changes, u.lang.record, u.lang.view
		}
		if a == nil {
			r.file.Attempts = append(r.file.Attempts, fresh)
		} else {
			*a = fresh
		}
		a = r.attempt(attemptKey)
		if !r.buildCommit(c, a, baseCommit.Tree, contents, recorded) {
			return
		}
	} else {
		a.Evidence, a.FixTargets = u.evidence(c.plan), u.fixTargets()
	}
	r.openPull(c, a, imageRepo, change)
}

// maxMarkerWithLayers is the encoded size up to which a marker carries the
// layers of its fix targets in full.
const maxMarkerWithLayers = 20000

// dockerfileSourceUnchanged checks, when the base branch is not at the commit
// the plan was made from, that every file the plan read (the Dockerfile and
// the Compose file its location was derived from or that showed the service has
// no build section) still has the blob it had there. If one differs or is gone, the build section, the stage or the
// platform may have changed since the comparison, so nothing is edited and the
// next cycle plans again. ok is false after the unit's status was set.
func (r *prRun) dockerfileSourceUnchanged(c *unitCtx, base string) bool {
	df := c.u.df
	moved := df.commit != "" && df.commit != base
	for _, f := range df.files {
		repo, sha := c.rs.name, base
		if f.Repository != "" {
			// A file of another repository has no commit of the plan to compare
			// with: its current blob is.
			var err error
			repo = f.Repository
			if sha, err = r.s.cfg.Source.ResolveBranch(r.ctx, repo, f.BaseBranch); err != nil {
				r.readFailure(c, "resolve the branch of "+f.Path, err)
				return false
			}
		} else if !moved {
			continue
		}
		cur, err := r.s.cfg.Source.ReadFile(r.ctx, repo, sha, f.Path)
		if err != nil {
			if errors.Is(err, github.ErrNotFound) {
				c.set(PRStatusDeferred, ReasonSourceChanged, fmt.Sprintf("%s is gone from %s, which moved from %s to %s since the plan", f.Path, c.u.baseBranch, df.commit, base))
			} else {
				r.readFailure(c, "read "+f.Path, err)
			}
			return false
		}
		if cur.SHA != f.BlobSHA {
			c.set(PRStatusDeferred, ReasonSourceChanged, fmt.Sprintf("%s changed since the plan: %s moved from %s to %s", f.Path, c.u.baseBranch, df.commit, base))
			return false
		}
	}
	return true
}

// prChange is the change an edit made, as the pull request body describes it.
type prChange struct {
	compose    []ComposeChange
	dockerfile DockerfileChange
}

// editSource edits the file the unit proposes a change to. ok is false after
// the unit's status was set.
func (r *prRun) editSource(c *unitCtx, content []byte) ([]byte, prChange, bool) {
	u := c.u
	if u.df == nil {
		edit, prob := EditComposeImageTag(ComposeEditRequest{Content: content, Services: u.services, Current: u.current, NewTag: u.candidate.Tag})
		if prob != nil {
			c.set(PRStatusManual, prob.Reason, prob.Error())
			return nil, prChange{}, false
		}
		return edit.Content, prChange{compose: edit.Changes}, true
	}

	// Every build stage the unit's workloads name must lead to the same FROM,
	// the one the plan found, and give the same file.
	targets := u.df.targets
	if len(targets) == 0 {
		targets = []string{""}
	}
	var first DockerfileEdit
	for i, target := range targets {
		edit, prob := EditDockerfileBaseTag(DockerfileEditRequest{Content: content, Target: target, Current: u.current, NewTag: u.candidate.Tag})
		if prob != nil {
			c.set(PRStatusManual, prob.Reason, prob.Error())
			return nil, prChange{}, false
		}
		// The stage and the platform are those the plan compared.
		if d, prob := ParseDockerfile(content); prob == nil {
			if b, prob := d.ResolveBase(target); prob == nil && (!strings.EqualFold(d.Stages[b.Stage].Name, u.df.stageName) || b.Platform != u.df.platform) {
				c.set(PRStatusManual, ReasonDockerfileSourceMismatch,
					fmt.Sprintf("the build stage %q now leads to stage %q with platform %q, not %q with %q the plan compared", target, d.Stages[b.Stage].Name, b.Platform, u.df.stageName, u.df.platform))
				return nil, prChange{}, false
			}
		}
		if edit.Change.Stage != u.df.stage {
			c.set(PRStatusManual, ReasonDockerfileSourceMismatch,
				fmt.Sprintf("the build stage %q now leads to the FROM of stage %d, not stage %d the plan was made for", target, edit.Change.Stage, u.df.stage))
			return nil, prChange{}, false
		}
		if i == 0 {
			first = edit
		} else if !bytes.Equal(edit.Content, first.Content) {
			c.set(PRStatusManual, ReasonDockerfileSourceMismatch, "the build stages of the workloads do not lead to one edit")
			return nil, prChange{}, false
		}
	}
	return first.Content, prChange{dockerfile: first.Change}, true
}

// buildCommit creates the blob, tree, commit and branch of an attempt. It
// reports whether the branch now points at the attempt's commit.
//
// A branch of the attempt's name that already exists is used only when it
// points at the commit just created, with one exception: when the records
// held nothing about this attempt (they were lost after the branch was
// created), a branch whose commit has the attempt's base as its only parent
// and exactly the tree just built holds the same change, so that commit is
// adopted as the attempt's commit. With a record, the recorded commit is the
// only one accepted.
func (r *prRun) buildCommit(c *unitCtx, a *AttemptRecord, baseTree string, contents map[string][]byte, recorded bool) bool {
	rs, gh := c.rs, r.s.cfg.GitHub
	step := func(kind OperationKind, intent string, fn func() (string, error)) (string, bool) {
		ref, opID, err := r.write(OperationEvent{Kind: kind, Repo: rs.name, AttemptKey: a.AttemptKey, Intent: intent}, fn)
		if err != nil {
			if errors.Is(err, github.ErrOutcomeUnknown) {
				a.PendingOp, a.UpdatedAt = opID, r.now()
				r.save()
			}
			r.writeFailure(c, kind, err)
			return "", false
		}
		return ref, true
	}
	advance := func(st AttemptStatus) bool {
		a.Status, a.UpdatedAt = st, r.now()
		if !r.save() {
			c.set(r.stop.status, r.stop.reason, r.stop.detail)
			return false
		}
		return true
	}
	if !advance(AttemptIntent) {
		return false
	}
	var entries []github.TreeEntry
	var paths []string
	for _, fc := range a.fileChanges() {
		fc := fc
		if _, ok := step(OpCreateBlob, "store the edited "+fc.Path+" as blob "+fc.BlobSHA, func() (string, error) {
			return gh.CreateBlob(r.ctx, rs.name, contents[fc.Path])
		}); !ok {
			return false
		}
		entries = append(entries, github.TreeEntry{Path: fc.Path, Mode: fc.Mode, BlobSHA: fc.BlobSHA})
		paths = append(paths, fc.Path)
	}
	if !advance(AttemptBlobCreated) {
		return false
	}
	tree, ok := step(OpCreateTree, "create a tree on base "+a.BaseSHA+" with "+strings.Join(paths, ", ")+" changed", func() (string, error) {
		return gh.CreateTree(r.ctx, rs.name, baseTree, entries)
	})
	if !ok {
		return false
	}
	a.TreeSHA = tree
	if !advance(AttemptTreeCreated) {
		return false
	}
	var title string
	switch {
	case c.u.lang != nil:
		title = c.u.lang.title
	case kindOf(a.Kind) == prKindDockerfile:
		title = dockerfileUnitTitle(repoOfRef(a.CurrentRef), a.CandidateTag, a.Path)
	default:
		title = composeUnitTitle(repoOfRef(a.CurrentRef), a.CandidateTag, a.Path)
	}
	commit, ok := step(OpCreateCommit, "create a commit of tree "+tree+" on "+a.BaseSHA, func() (string, error) {
		return gh.CreateCommit(r.ctx, rs.name, title, tree, []string{a.BaseSHA})
	})
	if !ok {
		return false
	}
	a.CommitSHA = commit
	if !advance(AttemptCommitCreated) {
		return false
	}
	_, opID, err := r.write(OperationEvent{Kind: OpCreateRef, Repo: rs.name, AttemptKey: a.AttemptKey, Ref: a.Branch, Intent: "create branch " + a.Branch + " at " + commit}, func() (string, error) {
		return a.Branch, gh.CreateRef(r.ctx, rs.name, a.Branch, commit)
	})
	switch {
	case err == nil:
	case errors.Is(err, github.ErrRefExists):
		// Only a branch that already points at this very commit is used.
		sha, found, rerr := gh.Ref(r.ctx, rs.name, a.Branch)
		if rerr != nil {
			r.readFailure(c, "read the existing branch", rerr)
			return false
		}
		if found && sha != commit && !recorded {
			bc, cerr := gh.Commit(r.ctx, rs.name, sha)
			if cerr != nil {
				r.readFailure(c, "read the existing branch's commit", cerr)
				return false
			}
			if len(bc.Parents) == 1 && bc.Parents[0] == a.BaseSHA && bc.Tree == a.TreeSHA {
				a.CommitSHA, commit = sha, sha
				r.settle(opID, ResultOK, "branch "+a.Branch+" already holds the same change at "+sha+"; that commit is adopted")
				r.file.Operations[len(r.file.Operations)-1].Ref = sha
			}
		}
		if !found || sha != commit {
			a.Status, a.Detail, a.UpdatedAt = AttemptBlocked, "branch "+a.Branch+" exists and does not point at the attempt's commit", r.now()
			r.blockTarget(rs, a, ReasonBranchNotOurs, a.Detail)
			r.save()
			c.set(PRStatusWriteBlocked, ReasonBranchNotOurs, a.Detail)
			return false
		}
	default:
		if errors.Is(err, github.ErrOutcomeUnknown) {
			a.PendingOp, a.UpdatedAt = opID, r.now()
			r.save()
		}
		r.writeFailure(c, OpCreateRef, err)
		return false
	}
	return advance(AttemptRefCreated)
}

// writeFailure sets the unit's status after a failed write.
func (r *prRun) writeFailure(c *unitCtx, kind OperationKind, err error) {
	var se *github.StatusError
	switch {
	case errors.Is(err, errWritesStopped), errors.Is(err, github.ErrOutcomeUnknown):
		c.set(r.stop.status, r.stop.reason, r.stop.detail)
	case r.halt != nil && (errors.Is(err, github.ErrRateLimited) || errors.Is(err, github.ErrBudgetExhausted) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		c.set(PRStatusDeferred, r.halt.reason, r.halt.detail)
	case errors.As(err, &se):
		c.set(PRStatusFailed, ReasonGitHubRefused, fmt.Sprintf("%s: %s", kind, err.Error()))
	default:
		c.set(PRStatusFailed, ReasonGitHubError, fmt.Sprintf("%s: %s", kind, err.Error()))
	}
}

// repoOfRef is the repository of an image reference as written.
func repoOfRef(ref string) string {
	if repo, ok := inventory.RepositoryOf(ref); ok {
		return repo
	}
	return ref
}

// openPull opens the pull request of an attempt whose branch points at its
// commit, after checking that the base has not moved, the branch is still
// ours, no pull request exists for it and the candidate is unchanged.
func (r *prRun) openPull(c *unitCtx, a *AttemptRecord, imageRepo string, change prChange) {
	rs, gh := c.rs, r.s.cfg.GitHub
	base, err := r.s.cfg.Source.ResolveBranch(r.ctx, rs.name, a.BaseBranch)
	if err != nil {
		r.readFailure(c, "resolve the base branch", err)
		return
	}
	if base != a.BaseSHA {
		c.set(PRStatusDeferred, ReasonBaseMoved, fmt.Sprintf("%s moved from %s to %s; the next cycle builds the change again", a.BaseBranch, a.BaseSHA, base))
		return
	}
	// The inputs of a Dockerfile update are checked again now that the branch
	// exists: one in another repository can change between the edit and the
	// pull request. Nothing is opened then; the branch stays and the attempt
	// is settled by the next cycle's reconciliation.
	if c.u.df != nil && !r.dockerfileSourceUnchanged(c, base) {
		return
	}
	sha, found, err := gh.Ref(r.ctx, rs.name, a.Branch)
	if err != nil {
		r.readFailure(c, "read the branch", err)
		return
	}
	if !found || sha != a.CommitSHA {
		a.Status, a.Detail, a.UpdatedAt = AttemptBlocked, "branch "+a.Branch+" no longer points at the attempt's commit", r.now()
		r.blockTarget(rs, a, ReasonBranchNotOurs, a.Detail)
		r.save()
		c.set(PRStatusWriteBlocked, ReasonBranchNotOurs, a.Detail)
		return
	}
	pulls, err := r.listPulls(rs, github.ListPullsOptions{State: "all", Head: rs.owner() + ":" + a.Branch})
	if err != nil {
		r.readFailure(c, "list pull requests of the branch", err)
		return
	}
	if pulls = r.branchPulls(rs, pulls, a.Branch); len(pulls) > 0 {
		r.settleAttemptPulls(rs, a, pulls)
		r.save()
		if rec := r.recordByUpdateKey(c.updateKey); rec != nil && a.Status == AttemptPRCreated {
			c.set(PRStatusOpen, "", "")
			if rec.State != PRStateOpen {
				c.set(PRStatusSuppressed, "", fmt.Sprintf("pull request #%d was %s", rec.Number, rec.State))
			}
			return
		}
		c.set(PRStatusWriteBlocked, ReasonAttemptUnsettled, a.Detail)
		return
	}
	if c.u.lang == nil && !r.recheckCandidate(c, imageRepo, ImageState{Tag: a.CandidateTag, TopDigest: a.CandidateDigest, Platform: c.u.candidate.Platform}) {
		return
	}

	marker := PRMarker{
		V: markerV, Kind: a.Kind, RepoID: a.RepoID, BaseBranch: a.BaseBranch, Path: a.Path, Locations: a.Locations,
		CurrentRef: a.CurrentRef, CandidateTag: a.CandidateTag, CandidateDigest: a.CandidateDigest,
		BaseSHA: a.BaseSHA, HeadSHA: a.CommitSHA, InputBlobSHA: a.InputSHA,
		Changes:   a.fileChanges(),
		TargetKey: a.TargetKey, UpdateKey: a.UpdateKey, AttemptKey: a.AttemptKey, FixTargets: a.FixTargets, Lang: a.Lang,
	}
	if marker.FixTargets == nil {
		marker.FixTargets = []FixTarget{}
	}
	// The images a target is claimed for stay in the record; a recovered record
	// is never replaced, so the marker does not carry them. The layers are part
	// of a target's identity and are carried in full while the marker stays
	// small, else as the digest of each target's layer set.
	marker.FixTargets = append([]FixTarget(nil), marker.FixTargets...)
	for i := range marker.FixTargets {
		marker.FixTargets[i].Entities = nil
	}
	if len(encodeMarker(marker)) > maxMarkerWithLayers {
		for i := range marker.FixTargets {
			ft := &marker.FixTargets[i]
			ft.LayersDigest, ft.Layers = ft.layerSetKey(), nil
		}
	}
	if marker.FixTargets == nil {
		marker.FixTargets = []FixTarget{}
	}
	var body, title string
	if c.u.lang != nil {
		body, err = buildLanguagePRBody(languageBodyInput{
			Repo: rs.name, BaseBranch: a.BaseBranch, BaseSHA: a.BaseSHA, LockPath: a.Path, Root: c.u.lang.root,
			Item: c.u.lang.item, Record: c.u.lang.record, Files: a.fileChanges(), Workloads: c.u.workloads,
			UpdateKey: a.UpdateKey, AttemptKey: a.AttemptKey, Marker: encodeMarker(marker), Language: r.s.cfg.Language,
		})
		title = c.u.lang.title
	} else if c.u.df != nil {
		body, err = buildDockerfilePRBody(dockerfileBodyInput{
			Repo: rs.name, BaseBranch: a.BaseBranch, BaseSHA: a.BaseSHA, Path: a.Path, Current: a.CurrentRef,
			Workloads: c.u.workloads, Stage: c.u.df.stage, Change: change.dockerfile, CandidateTag: a.CandidateTag, Evidence: a.Evidence,
			UpdateKey: a.UpdateKey, AttemptKey: a.AttemptKey, Marker: encodeMarker(marker), Language: r.s.cfg.Language,
		})
		title = dockerfileUnitTitle(imageRepo, a.CandidateTag, a.Path)
	} else {
		body, err = buildPRBody(prBodyInput{
			Repo: rs.name, BaseBranch: a.BaseBranch, BaseSHA: a.BaseSHA, Path: a.Path, Current: a.CurrentRef,
			Services: a.Services, Locations: a.Locations, Workloads: c.u.workloads, AlsoRunning: c.u.also,
			Changes: change.compose, CandidateTag: a.CandidateTag, Evidence: a.Evidence,
			UpdateKey: a.UpdateKey, AttemptKey: a.AttemptKey, Marker: encodeMarker(marker), Language: r.s.cfg.Language,
		})
		title = composeUnitTitle(imageRepo, a.CandidateTag, a.Path)
	}
	if err != nil {
		c.set(PRStatusFailed, ReasonGitHubError, err.Error())
		return
	}

	a.Status, a.UpdatedAt = AttemptPRRequested, r.now()
	pr, opID, err := r.writePull(rs, a, github.NewPull{Title: title, Body: body, Head: a.Branch, Base: a.BaseBranch})
	if err != nil {
		if errors.Is(err, github.ErrOutcomeUnknown) {
			a.PendingOp, a.UpdatedAt = opID, r.now()
		} else {
			// The request was refused, so no pull request exists; the
			// branch stays and the next cycle resumes from it.
			a.Status, a.UpdatedAt = AttemptRefCreated, r.now()
		}
		r.save()
		r.writeFailure(c, OpCreatePull, err)
		return
	}
	r.newPRs++
	rec := r.recordFromAttempt(a, pr)
	// The answer must show the pull request as requested; otherwise it is
	// kept as one changed by someone else and never used for replacement.
	switch {
	case pr.HeadSHA != a.CommitSHA:
		rec.UserModified, rec.ModifiedReason = true, "the new pull request's head is not the attempt's commit"
	case pr.BaseRef != a.BaseBranch:
		rec.UserModified, rec.ModifiedReason = true, "the new pull request's base is not "+a.BaseBranch
	case pr.HeadRef != a.Branch || !strings.EqualFold(pr.HeadRepoFullName, rs.info.FullName):
		rec.UserModified, rec.ModifiedReason = true, "the new pull request's head is not the attempt's branch"
	case pr.BaseRepoID != rs.info.ID:
		rec.UserModified, rec.ModifiedReason = true, fmt.Sprintf("the new pull request merges into repository ID %d, not %d", pr.BaseRepoID, rs.info.ID)
	}
	r.file.PRs = append(r.file.PRs, rec)
	a.Status, a.PRNumber, a.PendingOp, a.UpdatedAt = AttemptPRCreated, pr.Number, "", r.now()
	if !r.save() {
		c.set(PRStatusCreated, ReasonStorageFailed, fmt.Sprintf("pull request #%d was opened but could not be recorded; the next cycle adopts it", pr.Number))
		return
	}
	c.set(PRStatusCreated, "", "")
	if rec.UserModified {
		c.v.Detail = rec.ModifiedReason
		return
	}
	r.decideReplacements(r.recordByNumber(rec.RepoID, rec.Number))
}

// writePull sends CreatePull as one operation.
func (r *prRun) writePull(rs *repoState, a *AttemptRecord, np github.NewPull) (github.PullRequest, string, error) {
	var pr github.PullRequest
	_, opID, err := r.write(OperationEvent{Kind: OpCreatePull, Repo: rs.name, AttemptKey: a.AttemptKey, Intent: "open a pull request from " + a.Branch + " into " + a.BaseBranch}, func() (string, error) {
		var err error
		pr, err = r.s.cfg.GitHub.CreatePull(r.ctx, rs.name, np)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("#%d", pr.Number), nil
	})
	return pr, opID, err
}

// recordFromAttempt is the record of a pull request opened by an attempt.
func (r *prRun) recordFromAttempt(a *AttemptRecord, pr github.PullRequest) PRRecord {
	now := r.now()
	rec := PRRecord{
		Repo: a.Repo, RepoID: a.RepoID, Kind: kindOf(a.Kind), TargetKey: a.TargetKey, UpdateKey: a.UpdateKey, AttemptKey: a.AttemptKey,
		Branch: a.Branch, Number: pr.Number, URL: pr.HTMLURL, BaseBranch: a.BaseBranch, BaseSHA: a.BaseSHA, HeadSHA: a.CommitSHA,
		Path: a.Path, Locations: a.Locations, State: pullState(pr), FixTargets: a.FixTargets, Services: a.Services,
		CurrentRef: a.CurrentRef, CandidateTag: a.CandidateTag, CandidateDigest: a.CandidateDigest,
		Evidence: a.Evidence, Lang: a.Lang, Language: a.Language, CreatedAt: now, UpdatedAt: now,
	}
	return rec
}

func pullState(pr github.PullRequest) PRState {
	switch {
	case pr.Merged:
		return PRStateMerged
	case pr.State == "closed":
		return PRStateClosed
	}
	return PRStateOpen
}
