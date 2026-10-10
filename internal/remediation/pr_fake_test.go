package remediation

import (
	"context"
	"crypto/sha1" //nolint:gosec // fake object IDs
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// failMode is an injected failure of one call.
type failMode int

const (
	// failRefused: the write is refused (4xx) and not applied.
	failRefused failMode = iota + 1
	// failLost: the write is applied, then the answer is lost.
	failLost
	// failLostNotApplied: the answer is lost and the write was not applied.
	failLostNotApplied
	// failRate: rate limited, not applied.
	failRate
	// failError: a read fails with a server error.
	failError
	// refExistsOurs / refExistsOther: CreateRef answers "already exists"
	// with the branch at the requested commit / at another commit.
	refExistsOurs
	refExistsOther
	// refExistsSameContent: CreateRef answers "already exists" with the
	// branch at another commit of the same tree and parents.
	refExistsSameContent
)

type fakeEntry struct {
	blob, mode string
}

type fakeCommit struct {
	tree    string
	parents []string
}

type fakePull struct {
	pr       github.PullRequest
	comments []github.IssueComment
}

type fakeRepoState struct {
	info     github.RepoInfo
	branches map[string]string
	blobs    map[string][]byte
	trees    map[string]map[string]fakeEntry
	commits  map[string]fakeCommit
	pulls    []*fakePull
}

// fakePRGitHub is an in-memory GitHub with repositories, refs, pull requests and
// comments. It implements PRGitHub, PRSource and CandidateResolver.
type fakePRGitHub struct {
	mu      sync.Mutex
	repos   map[string]*fakeRepoState
	fail    map[string][]failMode // by method, or "method repo"
	calls   []string
	writes  int
	counter int
	nextNum int
	// created are the branches the writer created and the commit each was
	// created at; humanMoved are branches tests moved on purpose.
	created    map[string]string
	humanMoved map[string]bool
	// tops is what Resolve answers for "repo:tag".
	tops       map[string]string
	resolveErr error
	// afterWrite runs after a successful write of the named method.
	afterWrite map[string]func()
	// createBaseRepoID, when set, is the base repository ID of the pull
	// requests CreatePull opens.
	createBaseRepoID int64
}

func newFakePRGitHub() *fakePRGitHub {
	return &fakePRGitHub{
		repos: map[string]*fakeRepoState{}, fail: map[string][]failMode{}, created: map[string]string{},
		humanMoved: map[string]bool{}, tops: map[string]string{}, afterWrite: map[string]func(){}, nextNum: 1,
	}
}

func fakeSHA(parts ...string) string {
	h := sha1.New() //nolint:gosec // see import
	h.Write([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h.Sum(nil))
}

// addRepo creates a repository whose main branch holds files.
func (f *fakePRGitHub) addRepo(name string, id int64, files map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := &fakeRepoState{
		info:     github.RepoInfo{ID: id, FullName: name, DefaultBranch: "main"},
		branches: map[string]string{}, blobs: map[string][]byte{}, trees: map[string]map[string]fakeEntry{}, commits: map[string]fakeCommit{},
	}
	f.repos[strings.ToLower(name)] = rs
	f.commitFilesLocked(rs, "main", files)
}

// commitFiles moves a branch to a new commit holding files (a person
// pushing).
func (f *fakePRGitHub) commitFiles(repo, branch string, files map[string]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.repos[strings.ToLower(repo)]
	f.humanMoved[repo+"@"+branch] = true
	return f.commitFilesLocked(rs, branch, files)
}

func (f *fakePRGitHub) commitFilesLocked(rs *fakeRepoState, branch string, files map[string]string) string {
	tree := map[string]fakeEntry{}
	if parent, ok := rs.branches[branch]; ok {
		for p, e := range rs.trees[rs.commits[parent].tree] {
			tree[p] = e
		}
	}
	for p, c := range files {
		b := gitBlobSHA([]byte(c))
		rs.blobs[b] = []byte(c)
		tree[p] = fakeEntry{blob: b, mode: "100644"}
	}
	f.counter++
	tsha := f.treeSHA(tree)
	rs.trees[tsha] = tree
	var parents []string
	if p, ok := rs.branches[branch]; ok {
		parents = []string{p}
	}
	csha := fakeSHA("human", tsha, fmt.Sprint(f.counter))
	rs.commits[csha] = fakeCommit{tree: tsha, parents: parents}
	rs.branches[branch] = csha
	return csha
}

func (f *fakePRGitHub) treeSHA(tree map[string]fakeEntry) string {
	var keys []string
	for p, e := range tree {
		keys = append(keys, p+"="+e.blob+":"+e.mode)
	}
	sort.Strings(keys)
	return fakeSHA(append([]string{"tree"}, keys...)...)
}

func (f *fakePRGitHub) repo(name string) (*fakeRepoState, error) {
	rs := f.repos[strings.ToLower(name)]
	if rs == nil {
		return nil, github.ErrNotFound
	}
	return rs, nil
}

// failNext queues a failure for the next call of method (optionally for one
// repository: "Method owner/name").
func (f *fakePRGitHub) failNext(method string, modes ...failMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[method] = append(f.fail[method], modes...)
}

// take pops the failure for a call, if one is queued.
func (f *fakePRGitHub) take(method, repo string) failMode {
	for _, k := range []string{method + " " + repo, method} {
		if q := f.fail[k]; len(q) > 0 {
			f.fail[k] = q[1:]
			return q[0]
		}
	}
	return 0
}

// begin records a call and returns its injected failure.
func (f *fakePRGitHub) begin(method, repo string, write bool) failMode {
	f.calls = append(f.calls, method+" "+repo)
	if write {
		f.writes++
	}
	return f.take(method, repo)
}

func refused() error {
	return &github.StatusError{Status: http.StatusUnprocessableEntity, Message: "refused by test"}
}
func lost() error { return fmt.Errorf("%w: answer lost by test", github.ErrOutcomeUnknown) }

// readErr maps an injected failure of a read.
func readErr(m failMode) error {
	switch m {
	case failRate:
		return &github.RateLimitedError{}
	case failError, failRefused:
		return &github.StatusError{Status: http.StatusInternalServerError}
	}
	return nil
}

// writeErr is the error of a failed write before it is applied, nil when
// the write goes ahead.
func writeErr(m failMode) error {
	switch m {
	case failRefused:
		return refused()
	case failRate:
		return &github.RateLimitedError{}
	case failLostNotApplied:
		return lost()
	}
	return nil
}

func (f *fakePRGitHub) done(method string, m failMode) error {
	if fn := f.afterWrite[method]; fn != nil {
		delete(f.afterWrite, method)
		f.mu.Unlock()
		fn()
		f.mu.Lock()
	}
	if m == failLost {
		return lost()
	}
	return nil
}

// ---- PRGitHub ----

func (f *fakePRGitHub) Repository(_ context.Context, repo string) (github.RepoInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("Repository", repo, false)); err != nil {
		return github.RepoInfo{}, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return github.RepoInfo{}, err
	}
	return rs.info, nil
}

func (f *fakePRGitHub) Commit(_ context.Context, repo, sha string) (github.CommitInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("Commit", repo, false)); err != nil {
		return github.CommitInfo{}, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return github.CommitInfo{}, err
	}
	c, ok := rs.commits[sha]
	if !ok {
		return github.CommitInfo{}, github.ErrNotFound
	}
	return github.CommitInfo{SHA: sha, Tree: c.tree, Parents: c.parents}, nil
}

func (f *fakePRGitHub) Ref(_ context.Context, repo, branch string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("Ref", repo, false)); err != nil {
		return "", false, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return "", false, err
	}
	sha, ok := rs.branches[branch]
	return sha, ok, nil
}

func (f *fakePRGitHub) ResolveBranch(_ context.Context, repo, branch string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("ResolveBranch", repo, false)); err != nil {
		return "", err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	sha, ok := rs.branches[branch]
	if !ok {
		return "", github.ErrNotFound
	}
	return sha, nil
}

func (f *fakePRGitHub) ReadFile(_ context.Context, repo, sha, path string) (github.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("ReadFile", repo, false)); err != nil {
		return github.File{}, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return github.File{}, err
	}
	c, ok := rs.commits[sha]
	if !ok {
		return github.File{}, github.ErrNotFound
	}
	e, ok := rs.trees[c.tree][path]
	if !ok {
		return github.File{}, fmt.Errorf("%w: %s", github.ErrNotFound, path)
	}
	return github.File{Path: path, SHA: e.blob, Content: append([]byte(nil), rs.blobs[e.blob]...), Mode: e.mode}, nil
}

func (f *fakePRGitHub) ListPulls(_ context.Context, repo string, o github.ListPullsOptions) ([]github.PullRequest, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("ListPulls", repo, false)); err != nil {
		return nil, false, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return nil, false, err
	}
	var all []github.PullRequest
	for _, p := range rs.pulls {
		pr := p.pr
		switch o.State {
		case "", "open":
			if pr.State != "open" {
				continue
			}
		case "closed":
			if pr.State != "closed" {
				continue
			}
		}
		if o.Head != "" {
			owner, br, _ := strings.Cut(o.Head, ":")
			hOwner, _, _ := strings.Cut(pr.HeadRepoFullName, "/")
			if !strings.EqualFold(owner, hOwner) || pr.HeadRef != br {
				continue
			}
		}
		all = append(all, pr)
	}
	per := o.PerPage
	if per == 0 {
		per = 30
	}
	page := max(o.Page, 1)
	start := (page - 1) * per
	if start >= len(all) {
		return nil, false, nil
	}
	end := min(start+per, len(all))
	return all[start:end], end < len(all), nil
}

func (f *fakePRGitHub) pull(rs *fakeRepoState, n int) *fakePull {
	for _, p := range rs.pulls {
		if p.pr.Number == n {
			return p
		}
	}
	return nil
}

func (f *fakePRGitHub) Pull(_ context.Context, repo string, number int) (github.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("Pull", repo, false)); err != nil {
		return github.PullRequest{}, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return github.PullRequest{}, err
	}
	p := f.pull(rs, number)
	if p == nil {
		return github.PullRequest{}, github.ErrNotFound
	}
	return p.pr, nil
}

func (f *fakePRGitHub) ListIssueComments(_ context.Context, repo string, number, page int) ([]github.IssueComment, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := readErr(f.begin("ListIssueComments", repo, false)); err != nil {
		return nil, false, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return nil, false, err
	}
	p := f.pull(rs, number)
	if p == nil {
		return nil, false, github.ErrNotFound
	}
	if page > 1 {
		return nil, false, nil
	}
	return append([]github.IssueComment(nil), p.comments...), false, nil
}

func (f *fakePRGitHub) CreateBlob(_ context.Context, repo string, content []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("CreateBlob", repo, true)
	if err := writeErr(m); err != nil {
		return "", err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	sha := gitBlobSHA(content)
	rs.blobs[sha] = append([]byte(nil), content...)
	if err := f.done("CreateBlob", m); err != nil {
		return "", err
	}
	return sha, nil
}

func (f *fakePRGitHub) CreateTree(_ context.Context, repo, baseTree string, entries []github.TreeEntry) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("CreateTree", repo, true)
	if err := writeErr(m); err != nil {
		return "", err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	base, ok := rs.trees[baseTree]
	if !ok {
		return "", refused()
	}
	tree := map[string]fakeEntry{}
	for p, e := range base {
		tree[p] = e
	}
	for _, e := range entries {
		if _, ok := rs.blobs[e.BlobSHA]; !ok {
			return "", refused()
		}
		tree[e.Path] = fakeEntry{blob: e.BlobSHA, mode: e.Mode}
	}
	sha := f.treeSHA(tree)
	rs.trees[sha] = tree
	if err := f.done("CreateTree", m); err != nil {
		return "", err
	}
	return sha, nil
}

func (f *fakePRGitHub) CreateCommit(_ context.Context, repo, message, tree string, parents []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("CreateCommit", repo, true)
	if err := writeErr(m); err != nil {
		return "", err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	if _, ok := rs.trees[tree]; !ok {
		return "", refused()
	}
	// Like GitHub, the commit SHA depends on the time it was made.
	f.counter++
	sha := fakeSHA("commit", message, tree, strings.Join(parents, ","), fmt.Sprint(f.counter))
	rs.commits[sha] = fakeCommit{tree: tree, parents: append([]string(nil), parents...)}
	if err := f.done("CreateCommit", m); err != nil {
		return "", err
	}
	return sha, nil
}

func (f *fakePRGitHub) CreateRef(_ context.Context, repo, branch, sha string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("CreateRef", repo, true)
	rs, err := f.repo(repo)
	if err != nil {
		return err
	}
	switch m {
	case refExistsOurs:
		rs.branches[branch] = sha
		f.created[repo+"@"+branch] = sha
		return fmt.Errorf("%w: %s: %w", github.ErrRefExists, branch, refused())
	case refExistsSameContent:
		c := rs.commits[sha]
		f.counter++
		other := fakeSHA("same content", fmt.Sprint(f.counter))
		rs.commits[other] = fakeCommit{tree: c.tree, parents: append([]string(nil), c.parents...)}
		rs.branches[branch] = other
		f.created[repo+"@"+branch] = other
		return fmt.Errorf("%w: %s: %w", github.ErrRefExists, branch, refused())
	case refExistsOther:
		rs.branches[branch] = f.commitOtherLocked(rs)
		f.humanMoved[repo+"@"+branch] = true
		return fmt.Errorf("%w: %s: %w", github.ErrRefExists, branch, refused())
	}
	if err := writeErr(m); err != nil {
		return err
	}
	if _, ok := rs.branches[branch]; ok {
		return fmt.Errorf("%w: %s: %w", github.ErrRefExists, branch, refused())
	}
	if _, ok := rs.commits[sha]; !ok {
		return refused()
	}
	rs.branches[branch] = sha
	f.created[repo+"@"+branch] = sha
	return f.done("CreateRef", m)
}

func (f *fakePRGitHub) commitOtherLocked(rs *fakeRepoState) string {
	f.counter++
	sha := fakeSHA("other", fmt.Sprint(f.counter))
	rs.commits[sha] = fakeCommit{tree: rs.commits[rs.branches["main"]].tree, parents: []string{rs.branches["main"]}}
	return sha
}

func (f *fakePRGitHub) CreatePull(_ context.Context, repo string, np github.NewPull) (github.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("CreatePull", repo, true)
	if err := writeErr(m); err != nil {
		return github.PullRequest{}, err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return github.PullRequest{}, err
	}
	head, ok := rs.branches[np.Head]
	if !ok {
		return github.PullRequest{}, refused()
	}
	pr := github.PullRequest{
		Number: f.nextNum, State: "open", HTMLURL: fmt.Sprintf("https://github.com/%s/pull/%d", rs.info.FullName, f.nextNum),
		Title: np.Title, Body: np.Body, HeadRef: np.Head, HeadSHA: head, HeadRepoFullName: rs.info.FullName, BaseRef: np.Base, User: "bot",
		BaseRepoID: rs.info.ID,
	}
	if f.createBaseRepoID != 0 {
		pr.BaseRepoID = f.createBaseRepoID
	}
	f.nextNum++
	rs.pulls = append(rs.pulls, &fakePull{pr: pr})
	if err := f.done("CreatePull", m); err != nil {
		return github.PullRequest{}, err
	}
	return pr, nil
}

func (f *fakePRGitHub) ClosePull(_ context.Context, repo string, number int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("ClosePull", repo, true)
	if err := writeErr(m); err != nil {
		return err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return err
	}
	p := f.pull(rs, number)
	if p == nil {
		return github.ErrNotFound
	}
	p.pr.State = "closed"
	return f.done("ClosePull", m)
}

func (f *fakePRGitHub) CreateIssueComment(_ context.Context, repo string, number int, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.begin("CreateIssueComment", repo, true)
	if err := writeErr(m); err != nil {
		return err
	}
	rs, err := f.repo(repo)
	if err != nil {
		return err
	}
	p := f.pull(rs, number)
	if p == nil {
		return github.ErrNotFound
	}
	f.counter++
	p.comments = append(p.comments, github.IssueComment{ID: int64(f.counter), Body: body, User: "bot"})
	return f.done("CreateIssueComment", m)
}

// Resolve answers the configured top digest of a candidate tag.
func (f *fakePRGitHub) Resolve(_ context.Context, repo, tag string, _ inventory.Platform) (registry.Resolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Resolve "+repo+":"+tag)
	if f.resolveErr != nil {
		return registry.Resolution{}, f.resolveErr
	}
	top, ok := f.tops[repo+":"+tag]
	if !ok {
		return registry.Resolution{}, registry.ErrNotFound
	}
	return registry.Resolution{TopDigest: top, PlatformVerified: true}, nil
}

// ---- test helpers acting as people ----

func (f *fakePRGitHub) pulls(repo string) []github.PullRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []github.PullRequest
	for _, p := range f.repos[strings.ToLower(repo)].pulls {
		out = append(out, p.pr)
	}
	return out
}

func (f *fakePRGitHub) comments(repo string, number int) []github.IssueComment {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]github.IssueComment(nil), f.pull(f.repos[strings.ToLower(repo)], number).comments...)
}

func (f *fakePRGitHub) editPull(repo string, number int, fn func(*github.PullRequest)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.pull(f.repos[strings.ToLower(repo)], number).pr)
}

// pushToPull moves a pull request's branch to a new commit, as a person
// pushing to it.
func (f *fakePRGitHub) pushToPull(repo string, number int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.repos[strings.ToLower(repo)]
	p := f.pull(rs, number)
	sha := f.commitOtherLocked(rs)
	rs.branches[p.pr.HeadRef] = sha
	p.pr.HeadSHA = sha
	f.humanMoved[repo+"@"+p.pr.HeadRef] = true
}

func (f *fakePRGitHub) deleteBranch(repo, branch string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.repos[strings.ToLower(repo)].branches, branch)
	f.humanMoved[repo+"@"+branch] = true
}

// addForeignPull adds a pull request opened by someone else.
func (f *fakePRGitHub) addForeignPull(repo string, pr github.PullRequest) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.repos[strings.ToLower(repo)]
	pr.Number = f.nextNum
	f.nextNum++
	if pr.State == "" {
		pr.State = "open"
	}
	switch pr.BaseRepoID {
	case 0:
		pr.BaseRepoID = rs.info.ID
	case -1:
		pr.BaseRepoID = 0
	}
	pr.HTMLURL = fmt.Sprintf("https://github.com/%s/pull/%d", rs.info.FullName, pr.Number)
	rs.pulls = append(rs.pulls, &fakePull{pr: pr})
	return pr.Number
}

func (f *fakePRGitHub) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// checkInvariants asserts that the writer never opened two pull requests for
// one update and never moved or deleted a branch it created.
func (f *fakePRGitHub) checkInvariants(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, rs := range f.repos {
		seen := map[string]int{}
		for _, p := range rs.pulls {
			if p.pr.User != "bot" {
				continue
			}
			m, err := parsePRMarker(p.pr.Body)
			if err != nil {
				t.Errorf("%s: pull request #%d opened by the writer has no marker: %v", name, p.pr.Number, err)
				continue
			}
			if n, dup := seen[m.UpdateKey]; dup {
				t.Errorf("%s: pull requests #%d and #%d share update key %s", name, n, p.pr.Number, m.UpdateKey[:12])
			}
			seen[m.UpdateKey] = p.pr.Number
		}
	}
	for key, sha := range f.created {
		if f.humanMoved[key] {
			continue
		}
		repo, branch, _ := strings.Cut(key, "@")
		if got := f.repos[strings.ToLower(repo)].branches[branch]; got != sha {
			t.Errorf("branch %s moved from %s to %q without a person doing it", key, sha, got)
		}
	}
}

// pointBranchAtBase moves a branch to a new commit on top of main holding
// main's tree, as a person pushing an unrelated commit.
func (f *fakePRGitHub) pointBranchAtBase(repo, branch string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.repos[strings.ToLower(repo)]
	rs.branches[branch] = f.commitOtherLocked(rs)
	f.humanMoved[repo+"@"+branch] = true
}

func (f *fakePRGitHub) branch(repo, branch string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.repos[strings.ToLower(repo)].branches[branch]
}
