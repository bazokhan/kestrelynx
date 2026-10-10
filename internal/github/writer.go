package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// maxPullTitleChars and maxBodyChars are GitHub's limits for a pull
	// request title and for a pull request or comment body.
	maxPullTitleChars = 256
	maxBodyChars      = 65536
	// maxCommitMessageBytes bounds a commit message.
	maxCommitMessageBytes = 64 << 10
	// maxTreeEntries bounds the entries sent in one tree.
	maxTreeEntries = 1000
	// maxParents bounds the parents of a commit this writer creates.
	maxParents = 2
	// requestOverheadBytes is the allowance on top of the largest blob (as
	// base64) for the JSON around it.
	requestOverheadBytes = 1 << 20

	defaultPerPage = 30
	maxPerPage     = 100
	maxMessageLen  = 200
)

// Writer talks to the GitHub API to create the objects of a fix pull request:
// blobs, trees, commits, a new branch, the pull request and comments on it.
// It is a separate type from Client on purpose: nothing reachable from a
// Client can write, and a Writer is built only by NewWriter. It shares
// Client's guarded transport, request budget, caps and token handling.
//
// Writes are sent once. A POST or PATCH is never retried, and a failure after
// the request went out is reported as ErrOutcomeUnknown so the caller reads
// the state again instead of sending the request twice. Redirects are not
// followed for writes. Branches are only ever created: there is deliberately
// no method that moves or deletes a ref, and none that merges.
type Writer struct {
	c  *Client
	wh *http.Client // c.http without redirect following
}

// NewWriter returns a Writer for api.github.com. The options mean what they
// mean for New; the token needs permission to write to the repositories.
func NewWriter(o Options) *Writer {
	c := New(o)
	wh := *c.http
	wh.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Writer{c: c, wh: &wh}
}

// ---- repository ----

// RepoInfo describes a repository.
type RepoInfo struct {
	// ID is the numeric repository ID; it survives renames and transfers.
	ID int64
	// FullName is owner/name as GitHub currently spells it, which differs from
	// the requested name after a rename.
	FullName      string
	DefaultBranch string
	Private       bool
}

// Repository reads the repository repo (owner/name).
func (w *Writer) Repository(ctx context.Context, repo string) (RepoInfo, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return RepoInfo{}, err
	}
	r, err := w.get(ctx, w.c.repoURL(rp, ""), acceptJSON, w.c.opts.MaxListBytes)
	if err != nil {
		return RepoInfo{}, err
	}
	var v struct {
		ID            int64  `json:"id"`
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
	}
	if err := json.Unmarshal(r.body, &v); err != nil {
		return RepoInfo{}, fmt.Errorf("%w: repository response is not a JSON object", ErrBadResponse)
	}
	if _, err := ParseRepo(v.FullName); err != nil || v.ID <= 0 || !ValidBranch(v.DefaultBranch) {
		return RepoInfo{}, fmt.Errorf("%w: repository response is malformed", ErrBadResponse)
	}
	return RepoInfo{ID: v.ID, FullName: v.FullName, DefaultBranch: v.DefaultBranch, Private: v.Private}, nil
}

// ---- git data ----

// CreateBlob stores content as a blob and returns its SHA, which is checked
// against the hash computed locally. The content is at most MaxFileBytes.
func (w *Writer) CreateBlob(ctx context.Context, repo string, content []byte) (string, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return "", err
	}
	if int64(len(content)) > w.c.opts.MaxFileBytes {
		return "", fmt.Errorf("%w: blob is %d bytes (limit %d)", ErrInvalidInput, len(content), w.c.opts.MaxFileBytes)
	}
	want := blobSHA(content)
	body := map[string]string{"content": base64.StdEncoding.EncodeToString(content), "encoding": "base64"}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := w.write(ctx, http.MethodPost, w.c.repoURL(rp, "/git/blobs"), body, &out); err != nil {
		return "", err
	}
	if out.SHA != want {
		// The blob exists on GitHub's side now, so the caller must not assume
		// nothing happened.
		return "", unknown(fmt.Errorf("%w: GitHub stored a blob whose SHA differs from the content's", ErrHashMismatch))
	}
	return want, nil
}

// TreeEntry is one file of a tree to create.
type TreeEntry struct {
	Path string
	// Mode is "100644" or "100755".
	Mode    string
	BlobSHA string
}

// CreateTree creates a tree on top of baseTree holding entries, and returns
// its SHA. Entries are regular files only.
func (w *Writer) CreateTree(ctx context.Context, repo, baseTree string, entries []TreeEntry) (string, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return "", err
	}
	if !validSHA(baseTree) {
		return "", fmt.Errorf("%w: base tree %q is not a 40-hex SHA", ErrInvalidInput, baseTree)
	}
	if len(entries) == 0 || len(entries) > maxTreeEntries {
		return "", fmt.Errorf("%w: %d tree entries (want 1 to %d)", ErrInvalidInput, len(entries), maxTreeEntries)
	}
	type wireEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	wire := make([]wireEntry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !ValidPath(e.Path, false) {
			return "", fmt.Errorf("%w: tree path %q", ErrInvalidInput, e.Path)
		}
		if e.Mode != modeFile && e.Mode != modeExecutable {
			return "", fmt.Errorf("%w: tree mode %q for %s", ErrInvalidInput, e.Mode, e.Path)
		}
		if !validSHA(e.BlobSHA) {
			return "", fmt.Errorf("%w: blob %q for %s is not a 40-hex SHA", ErrInvalidInput, e.BlobSHA, e.Path)
		}
		if seen[e.Path] {
			return "", fmt.Errorf("%w: tree path %s appears twice", ErrInvalidInput, e.Path)
		}
		seen[e.Path] = true
		wire = append(wire, wireEntry{Path: e.Path, Mode: e.Mode, Type: "blob", SHA: e.BlobSHA})
	}
	body := map[string]any{"base_tree": baseTree, "tree": wire}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := w.write(ctx, http.MethodPost, w.c.repoURL(rp, "/git/trees"), body, &out); err != nil {
		return "", err
	}
	if !validSHA(out.SHA) {
		return "", unknown(fmt.Errorf("%w: tree response holds no SHA", ErrBadResponse))
	}
	return out.SHA, nil
}

// CreateCommit creates a commit of tree on top of one or two parents and
// returns its SHA. The commit takes the author and committer GitHub derives
// from the token.
func (w *Writer) CreateCommit(ctx context.Context, repo, message, tree string, parents []string) (string, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(message) == "" || len(message) > maxCommitMessageBytes || !utf8.ValidString(message) || strings.ContainsRune(message, 0) {
		return "", fmt.Errorf("%w: commit message", ErrInvalidInput)
	}
	if !validSHA(tree) {
		return "", fmt.Errorf("%w: tree %q is not a 40-hex SHA", ErrInvalidInput, tree)
	}
	if len(parents) < 1 || len(parents) > maxParents {
		return "", fmt.Errorf("%w: %d parents (want 1 to %d)", ErrInvalidInput, len(parents), maxParents)
	}
	for _, p := range parents {
		if !validSHA(p) {
			return "", fmt.Errorf("%w: parent %q is not a 40-hex SHA", ErrInvalidInput, p)
		}
	}
	body := map[string]any{"message": message, "tree": tree, "parents": parents}
	var out struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := w.write(ctx, http.MethodPost, w.c.repoURL(rp, "/git/commits"), body, &out); err != nil {
		return "", err
	}
	ok := validSHA(out.SHA) && out.Tree.SHA == tree && len(out.Parents) == len(parents)
	for i := 0; ok && i < len(parents); i++ {
		ok = out.Parents[i].SHA == parents[i]
	}
	if !ok {
		return "", unknown(fmt.Errorf("%w: commit response does not match the request", ErrBadResponse))
	}
	return out.SHA, nil
}

// CommitInfo is a commit as GitHub reports it.
type CommitInfo struct {
	SHA     string
	Tree    string
	Parents []string
	Message string
}

// Commit reads the commit sha.
func (w *Writer) Commit(ctx context.Context, repo, sha string) (CommitInfo, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return CommitInfo{}, err
	}
	if !validSHA(sha) {
		return CommitInfo{}, fmt.Errorf("%w: commit %q is not a 40-hex SHA", ErrInvalidInput, sha)
	}
	r, err := w.get(ctx, w.c.repoURL(rp, "/git/commits/"+sha), acceptJSON, w.c.opts.MaxListBytes)
	if err != nil {
		return CommitInfo{}, err
	}
	var v struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(r.body, &v); err != nil {
		return CommitInfo{}, fmt.Errorf("%w: commit response is not a JSON object", ErrBadResponse)
	}
	if v.SHA != sha || !validSHA(v.Tree.SHA) {
		return CommitInfo{}, fmt.Errorf("%w: commit response does not match the request", ErrBadResponse)
	}
	info := CommitInfo{SHA: v.SHA, Tree: v.Tree.SHA, Message: v.Message}
	for _, p := range v.Parents {
		if !validSHA(p.SHA) {
			return CommitInfo{}, fmt.Errorf("%w: commit response has a malformed parent", ErrBadResponse)
		}
		info.Parents = append(info.Parents, p.SHA)
	}
	return info, nil
}

// CreateRef creates the branch refs/heads/<branch> at the commit sha. A branch
// that already exists is ErrRefExists.
//
// Refs are never moved or deleted: Writer has no update or delete for them, so
// a branch it created is final.
func (w *Writer) CreateRef(ctx context.Context, repo, branch, sha string) error {
	rp, err := ParseRepo(repo)
	if err != nil {
		return err
	}
	if !ValidBranch(branch) {
		return fmt.Errorf("%w: branch %q", ErrInvalidInput, branch)
	}
	if !validSHA(sha) {
		return fmt.Errorf("%w: commit %q is not a 40-hex SHA", ErrInvalidInput, sha)
	}
	body := map[string]string{"ref": "refs/heads/" + branch, "sha": sha}
	var out struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	err = w.write(ctx, http.MethodPost, w.c.repoURL(rp, "/git/refs"), body, &out)
	var se *StatusError
	if errors.As(err, &se) && se.Status == http.StatusUnprocessableEntity && strings.Contains(strings.ToLower(se.Message), "already exists") {
		return fmt.Errorf("%w: %s: %w", ErrRefExists, branch, err)
	}
	if err != nil {
		return err
	}
	if out.Ref != "refs/heads/"+branch || out.Object.SHA != sha {
		return unknown(fmt.Errorf("%w: ref response does not match the request", ErrBadResponse))
	}
	return nil
}

// Ref returns the commit SHA the branch points to; found is false when the
// branch does not exist. Only an exact name matches: a response for another
// reference (GitHub answers with a list of prefix matches in some cases) never
// counts as the branch.
func (w *Writer) Ref(ctx context.Context, repo, branch string) (sha string, found bool, err error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return "", false, err
	}
	if !ValidBranch(branch) {
		return "", false, fmt.Errorf("%w: branch %q", ErrInvalidInput, branch)
	}
	r, err := w.get(ctx, w.c.repoURL(rp, "/git/ref/heads/"+escapePath(branch)), acceptJSON, w.c.opts.MaxListBytes)
	if errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	type refObj struct {
		Ref    string `json:"ref"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	var cands []refObj
	if t := bytes.TrimSpace(r.body); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(r.body, &cands); err != nil {
			return "", false, fmt.Errorf("%w: ref response is not JSON", ErrBadResponse)
		}
	} else {
		var one refObj
		if err := json.Unmarshal(r.body, &one); err != nil {
			return "", false, fmt.Errorf("%w: ref response is not JSON", ErrBadResponse)
		}
		if one.Ref != "refs/heads/"+branch {
			return "", false, fmt.Errorf("%w: ref response names another reference", ErrBadResponse)
		}
		cands = []refObj{one}
	}
	for _, c := range cands {
		if c.Ref != "refs/heads/"+branch {
			continue
		}
		if c.Object.Type != "commit" || !validSHA(c.Object.SHA) {
			return "", false, fmt.Errorf("%w: ref response holds no commit SHA", ErrBadResponse)
		}
		return c.Object.SHA, true, nil
	}
	return "", false, nil
}

// ---- pull requests ----

// PullRequest is a pull request as listed or read.
type PullRequest struct {
	Number int
	// State is "open" or "closed"; Merged tells a merged one from one closed
	// without merging.
	State  string
	Merged bool
	// HTMLURL is the https address of the pull request page.
	HTMLURL string
	Title   string
	Body    string
	HeadRef string
	HeadSHA string
	// HeadRepoFullName is empty when the head repository was deleted.
	HeadRepoFullName string
	BaseRef          string
	// BaseRepoID is the numeric ID of the repository the pull request
	// merges into; 0 when the response did not name it.
	BaseRepoID int64
	// User is the login of the author.
	User string
}

// ListPullsOptions selects pull requests. The zero value lists the first page
// of open pull requests.
type ListPullsOptions struct {
	// State is "open" (default), "closed" or "all".
	State string
	// Head filters by head as "owner:branch"; empty means any.
	Head string
	// Base filters by base branch; empty means any.
	Base string
	// Page is 1-based; 0 means 1.
	Page int
	// PerPage is at most 100; 0 means 30.
	PerPage int
}

type wirePull struct {
	Number   int     `json:"number"`
	State    string  `json:"state"`
	MergedAt *string `json:"merged_at"`
	HTMLURL  string  `json:"html_url"`
	Title    string  `json:"title"`
	Body     *string `json:"body"`
	Head     struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string `json:"ref"`
		Repo *struct {
			ID int64 `json:"id"`
		} `json:"repo"`
	} `json:"base"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
}

func (p wirePull) convert() (PullRequest, error) {
	u, err := url.Parse(p.HTMLURL)
	if p.Number <= 0 || (p.State != "open" && p.State != "closed") || err != nil || u.Scheme != "https" || u.Host == "" ||
		!validSHA(p.Head.SHA) || p.Head.Ref == "" || p.Base.Ref == "" {
		return PullRequest{}, fmt.Errorf("%w: malformed pull request", ErrBadResponse)
	}
	pr := PullRequest{
		Number: p.Number, State: p.State, Merged: p.MergedAt != nil, HTMLURL: p.HTMLURL, Title: p.Title,
		HeadRef: p.Head.Ref, HeadSHA: p.Head.SHA, BaseRef: p.Base.Ref, User: p.User.Login,
	}
	if p.Body != nil {
		pr.Body = *p.Body
	}
	if p.Head.Repo != nil {
		pr.HeadRepoFullName = p.Head.Repo.FullName
	}
	if p.Base.Repo != nil {
		if p.Base.Repo.ID < 0 {
			return PullRequest{}, fmt.Errorf("%w: malformed pull request base repository", ErrBadResponse)
		}
		pr.BaseRepoID = p.Base.Repo.ID
	}
	return pr, nil
}

// ListPulls lists one page of pull requests of repo and reports whether a
// further page exists (the Link header names a next one).
func (w *Writer) ListPulls(ctx context.Context, repo string, o ListPullsOptions) (pulls []PullRequest, hasNext bool, err error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return nil, false, err
	}
	q := url.Values{}
	switch o.State {
	case "":
		q.Set("state", "open")
	case "open", "closed", "all":
		q.Set("state", o.State)
	default:
		return nil, false, fmt.Errorf("%w: pull request state %q", ErrInvalidInput, o.State)
	}
	if o.Head != "" {
		owner, br, ok := strings.Cut(o.Head, ":")
		if !ok || !validOwner(owner) || !ValidBranch(br) {
			return nil, false, fmt.Errorf("%w: head filter %q is not owner:branch", ErrInvalidInput, o.Head)
		}
		q.Set("head", o.Head)
	}
	if o.Base != "" {
		if !ValidBranch(o.Base) {
			return nil, false, fmt.Errorf("%w: base %q", ErrInvalidInput, o.Base)
		}
		q.Set("base", o.Base)
	}
	if o.Page < 0 || o.PerPage < 0 || o.PerPage > maxPerPage {
		return nil, false, fmt.Errorf("%w: page %d, per page %d", ErrInvalidInput, o.Page, o.PerPage)
	}
	page, per := o.Page, o.PerPage
	if page == 0 {
		page = 1
	}
	if per == 0 {
		per = defaultPerPage
	}
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", strconv.Itoa(per))
	r, err := w.get(ctx, w.c.repoURL(rp, "/pulls?"+q.Encode()), acceptJSON, w.c.opts.MaxListBytes)
	if err != nil {
		return nil, false, err
	}
	var raw []wirePull
	if !isJSONArray(r.body) || json.Unmarshal(r.body, &raw) != nil {
		return nil, false, fmt.Errorf("%w: pull request list is not a JSON array", ErrBadResponse)
	}
	if len(raw) > per {
		return nil, false, fmt.Errorf("%w: pull request list is longer than the page size", ErrBadResponse)
	}
	for _, p := range raw {
		pr, err := p.convert()
		if err != nil {
			return nil, false, err
		}
		pulls = append(pulls, pr)
	}
	return pulls, linkHasNext(r.header.Values("Link")), nil
}

// isJSONArray reports whether body's top-level value is an array; "null" is
// not one, and must not pass for an empty list.
func isJSONArray(body []byte) bool {
	t := bytes.TrimSpace(body)
	return len(t) > 0 && t[0] == '['
}

// linkHasNext reports whether a Link header holds a rel="next" relation.
func linkHasNext(values []string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			segs := strings.Split(part, ";")
			if len(segs) < 2 {
				continue
			}
			for _, s := range segs[1:] {
				s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
				if s == `rel="next"` || s == `rel=next` {
					return true
				}
			}
		}
	}
	return false
}

// Pull reads pull request number.
func (w *Writer) Pull(ctx context.Context, repo string, number int) (PullRequest, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return PullRequest{}, err
	}
	if number <= 0 {
		return PullRequest{}, fmt.Errorf("%w: pull request number %d", ErrInvalidInput, number)
	}
	r, err := w.get(ctx, w.c.repoURL(rp, "/pulls/"+strconv.Itoa(number)), acceptJSON, w.c.opts.MaxListBytes)
	if err != nil {
		return PullRequest{}, err
	}
	var raw wirePull
	if err := json.Unmarshal(r.body, &raw); err != nil {
		return PullRequest{}, fmt.Errorf("%w: pull request response is not a JSON object", ErrBadResponse)
	}
	pr, err := raw.convert()
	if err != nil {
		return PullRequest{}, err
	}
	if pr.Number != number {
		return PullRequest{}, fmt.Errorf("%w: pull request response does not match the request", ErrBadResponse)
	}
	return pr, nil
}

// NewPull is a pull request to open.
type NewPull struct {
	Title string
	Body  string
	// Head is the branch with the changes: "branch", or "owner:branch" for a
	// branch of a fork.
	Head string
	// Base is the branch to merge into.
	Base                string
	MaintainerCanModify bool
}

// CreatePull opens a pull request and returns it. This package never merges it.
func (w *Writer) CreatePull(ctx context.Context, repo string, p NewPull) (PullRequest, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return PullRequest{}, err
	}
	if err := validTitle(p.Title); err != nil {
		return PullRequest{}, err
	}
	if err := validBody(p.Body, true); err != nil {
		return PullRequest{}, err
	}
	headBranch := p.Head
	if owner, br, ok := strings.Cut(p.Head, ":"); ok {
		if !validOwner(owner) {
			return PullRequest{}, fmt.Errorf("%w: head %q", ErrInvalidInput, p.Head)
		}
		headBranch = br
	}
	if !ValidBranch(headBranch) || !ValidBranch(p.Base) {
		return PullRequest{}, fmt.Errorf("%w: head %q or base %q", ErrInvalidInput, p.Head, p.Base)
	}
	body := map[string]any{
		"title": p.Title, "body": p.Body, "head": p.Head, "base": p.Base,
		"maintainer_can_modify": p.MaintainerCanModify,
	}
	var out wirePull
	if err := w.write(ctx, http.MethodPost, w.c.repoURL(rp, "/pulls"), body, &out); err != nil {
		return PullRequest{}, err
	}
	pr, err := out.convert()
	if err != nil {
		return PullRequest{}, unknown(err)
	}
	return pr, nil
}

// ClosePull closes pull request number without merging it.
func (w *Writer) ClosePull(ctx context.Context, repo string, number int) error {
	rp, err := ParseRepo(repo)
	if err != nil {
		return err
	}
	if number <= 0 {
		return fmt.Errorf("%w: pull request number %d", ErrInvalidInput, number)
	}
	var out struct {
		Number int    `json:"number"`
		State  string `json:"state"`
	}
	if err := w.write(ctx, http.MethodPatch, w.c.repoURL(rp, "/pulls/"+strconv.Itoa(number)), map[string]string{"state": "closed"}, &out); err != nil {
		return err
	}
	if out.Number != number || out.State != "closed" {
		return unknown(fmt.Errorf("%w: pull request response does not show it closed", ErrBadResponse))
	}
	return nil
}

// CreateIssueComment adds a comment to pull request (or issue) number.
func (w *Writer) CreateIssueComment(ctx context.Context, repo string, number int, body string) error {
	rp, err := ParseRepo(repo)
	if err != nil {
		return err
	}
	if number <= 0 {
		return fmt.Errorf("%w: pull request number %d", ErrInvalidInput, number)
	}
	if err := validBody(body, false); err != nil {
		return err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := w.write(ctx, http.MethodPost, w.c.repoURL(rp, "/issues/"+strconv.Itoa(number)+"/comments"), map[string]string{"body": body}, &out); err != nil {
		return err
	}
	if out.ID <= 0 {
		return unknown(fmt.Errorf("%w: comment response holds no ID", ErrBadResponse))
	}
	return nil
}

// IssueComment is a comment on a pull request (or issue) as listed.
type IssueComment struct {
	ID   int64
	Body string
	// User is the login of the author.
	User string
}

// ListIssueComments lists one page (1-based; 0 means 1) of up to 100 comments
// on pull request (or issue) number, oldest first, and reports whether a
// further page exists.
func (w *Writer) ListIssueComments(ctx context.Context, repo string, number, page int) (comments []IssueComment, hasNext bool, err error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return nil, false, err
	}
	if number <= 0 {
		return nil, false, fmt.Errorf("%w: pull request number %d", ErrInvalidInput, number)
	}
	if page < 0 {
		return nil, false, fmt.Errorf("%w: page %d", ErrInvalidInput, page)
	}
	if page == 0 {
		page = 1
	}
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", strconv.Itoa(maxPerPage))
	r, err := w.get(ctx, w.c.repoURL(rp, "/issues/"+strconv.Itoa(number)+"/comments?"+q.Encode()), acceptJSON, w.c.opts.MaxListBytes)
	if err != nil {
		return nil, false, err
	}
	var raw []struct {
		ID   int64   `json:"id"`
		Body *string `json:"body"`
		User *struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if !isJSONArray(r.body) || json.Unmarshal(r.body, &raw) != nil {
		return nil, false, fmt.Errorf("%w: comment list is not a JSON array", ErrBadResponse)
	}
	if len(raw) > maxPerPage {
		return nil, false, fmt.Errorf("%w: comment list is longer than the page size", ErrBadResponse)
	}
	for _, c := range raw {
		if c.ID <= 0 {
			return nil, false, fmt.Errorf("%w: malformed comment", ErrBadResponse)
		}
		ic := IssueComment{ID: c.ID}
		if c.Body != nil {
			ic.Body = *c.Body
		}
		if c.User != nil {
			ic.User = c.User.Login
		}
		comments = append(comments, ic)
	}
	return comments, linkHasNext(r.header.Values("Link")), nil
}

func validTitle(s string) error {
	if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > maxPullTitleChars || !utf8.ValidString(s) {
		return fmt.Errorf("%w: title", ErrInvalidInput)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: title has a control character", ErrInvalidInput)
		}
	}
	return nil
}

func validBody(s string, allowEmpty bool) error {
	if (!allowEmpty && strings.TrimSpace(s) == "") || utf8.RuneCountInString(s) > maxBodyChars || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return fmt.Errorf("%w: body", ErrInvalidInput)
	}
	return nil
}

// ---- sending ----

// unknown marks err as a failure after which the write may have been applied.
func unknown(err error) error {
	return fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
}

// write sends one JSON request (one budget unit), never retries and never
// follows a redirect, and decodes a success body into out. Once the request
// has gone out, every failure that does not prove the write was refused is
// ErrOutcomeUnknown.
func (w *Writer) write(ctx context.Context, method, rawURL string, payload, out any) error {
	return w.c.redact(w.send(ctx, method, rawURL, payload, out))
}

// get is Client.get with every returned error scrubbed of the token.
func (w *Writer) get(ctx context.Context, rawURL, accept string, limit int64) (*response, error) {
	r, err := w.c.get(ctx, rawURL, accept, limit)
	return r, w.c.redact(err)
}

func (w *Writer) send(ctx context.Context, method, rawURL string, payload, out any) error {
	c := w.c
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if limit := c.opts.MaxFileBytes*4/3 + requestOverheadBytes; int64(len(b)) > limit {
		return fmt.Errorf("%w: request body is %d bytes (limit %d)", ErrInvalidInput, len(b), limit)
	}
	if err := c.budget.take(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	var sent atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteHeaders: func() { sent.Store(true) },
		WroteRequest: func(httptrace.WroteRequestInfo) { sent.Store(true) },
	})
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	// bytes.NewReader makes NewRequest set GetBody, which lets the HTTP/2
	// transport replay a POST or PATCH after a refused stream. A write must
	// reach the server at most once, so the body cannot be rewound: with no
	// GetBody the transports give up instead of resending.
	req.GetBody = nil
	req.Header.Set("Accept", acceptJSON)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "kestrelynx")
	if a := c.auth(); a != "" {
		req.Header.Set("Authorization", a)
	}
	resp, err := w.wh.Do(req)
	if err != nil {
		// url.Error carries the URL, never a header.
		err = fmt.Errorf("github: %s %s: %w", method, req.URL.Redacted(), err)
		if sent.Load() {
			return unknown(err)
		}
		return err
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	max := c.opts.MaxListBytes
	if !ok {
		max = maxErrorBodyBytes
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if !ok {
		// A truncated error body still tells the status.
		if int64(len(body)) > max {
			body = body[:max]
		}
		return w.writeStatusErr(&response{status: resp.StatusCode, header: resp.Header, body: body}, time.Now())
	}
	if rerr != nil {
		return unknown(fmt.Errorf("github: read %s: %w", req.URL.Redacted(), rerr))
	}
	if int64(len(body)) > max {
		return unknown(fmt.Errorf("%w: response is over %d bytes", ErrTooLarge, max))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return unknown(fmt.Errorf("%w: response is not the expected JSON object", ErrBadResponse))
	}
	return nil
}

// writeStatusErr converts a non-success answer to a write. A 4xx proves the
// write was refused; a 5xx does not.
func (w *Writer) writeStatusErr(r *response, now time.Time) error {
	msg := w.c.message(r.body)
	switch {
	case r.status == http.StatusTooManyRequests:
		return rateLimited(r.header, now)
	case r.status == http.StatusForbidden && (r.header.Get("X-RateLimit-Remaining") == "0" || r.header.Get("Retry-After") != "" ||
		strings.Contains(strings.ToLower(msg), "rate limit")):
		return rateLimited(r.header, now)
	case r.status >= 300 && r.status < 400:
		return fmt.Errorf("%w: write answered with a redirect (HTTP %d); the repository may have moved", ErrBadResponse, r.status)
	case r.status >= 500:
		return unknown(&StatusError{Status: r.status, Message: msg})
	}
	return &StatusError{Status: r.status, Message: msg}
}

// message extracts GitHub's "message" from an error body: control characters
// become spaces, the token (should it ever be echoed) is masked, and the text
// is shortened.
func (c *Client) message(body []byte) string {
	var v struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &v) != nil || v.Message == "" {
		return ""
	}
	m := c.scrub(v.Message)
	m = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, m)
	if rs := []rune(m); len(rs) > maxMessageLen {
		m = string(rs[:maxMessageLen]) + "..."
	}
	return strings.TrimSpace(m)
}

// scrub masks the token wherever it appears in s.
func (c *Client) scrub(s string) string {
	if tok := strings.TrimPrefix(c.auth(), "Bearer "); tok != "" {
		return strings.ReplaceAll(s, tok, redacted)
	}
	return s
}

// redactedError is an error whose text had the token masked. It still
// unwraps to the original, so errors.Is and errors.As keep working.
type redactedError struct {
	err  error
	text string
}

func (e *redactedError) Error() string { return e.text }
func (e *redactedError) Unwrap() error { return e.err }

// redact returns err unchanged unless its text holds the token, in which case
// the text is masked. Transport errors can carry response-supplied strings (a
// malformed Location header, say), so every error from a request goes here.
func (c *Client) redact(err error) error {
	if err == nil {
		return nil
	}
	if t := err.Error(); c.scrub(t) != t {
		return &redactedError{err: err, text: c.scrub(t)}
	}
	return err
}
