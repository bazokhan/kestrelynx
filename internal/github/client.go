// Package github is a read-only client for the GitHub REST API (api.github.com
// only). It resolves a branch to a commit SHA, lists a directory and reads a
// file at that SHA. It has no write endpoints.
//
// The client is built to be a bounded guest: HTTPS only, a per-request
// timeout, capped response and file sizes, a caller-supplied request budget
// and a cap on the file bytes read in a cycle. It never sleeps or retries by
// itself; rate limiting and exhausted budgets are returned as typed errors so
// the caller decides what to do next. The token, when one is configured, is
// sent only to api.github.com and never appears in an error.
package github

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git object IDs are SHA-1; this verifies content against them, not for security
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

const (
	apiBase = "https://api.github.com"

	defaultTimeout       = 20 * time.Second
	defaultMaxFileBytes  = 8 << 20
	defaultMaxTotalBytes = 32 << 20
	defaultMaxListBytes  = 2 << 20
	maxErrorBodyBytes    = 64 << 10
	maxRedirects         = 3
	// lfsPointerMaxBytes bounds the size of a Git LFS pointer file.
	lfsPointerMaxBytes = 1024
	lfsPointerPrefix   = "version https://git-lfs.github.com/spec/v1\n"
)

// Options configures a Client. Zero values select the defaults.
type Options struct {
	// Token is a GitHub token sent as a Bearer credential. Empty means
	// anonymous access, which reaches public repositories only.
	Token Token
	// HTTPClient is the base client. It is copied, and the copy's timeout and
	// redirect policy are replaced; nil means a default client.
	HTTPClient *http.Client
	// Budget caps the requests this client may send. Nil is unlimited.
	Budget *Budget
	// Timeout bounds each HTTP request, body read included.
	Timeout time.Duration

	MaxFileBytes  int64 // one file's content
	MaxTotalBytes int64 // file content read by this client over its lifetime (one cycle)
	MaxListBytes  int64 // one directory listing or ref response

	// Resolver looks up the addresses of a host name at dial time; nil means
	// the system resolver. Every returned address is checked before dialing.
	Resolver func(ctx context.Context, host string) ([]net.IP, error)
	// AllowAddr is for tests only. When non-nil and it returns true for an
	// address and port, that address is permitted even though the default
	// policy (public addresses only) would refuse it. Production code leaves
	// it nil.
	AllowAddr func(ip net.IP, port string) bool
}

// Client talks to the GitHub API. It is safe for concurrent use.
type Client struct {
	http   *http.Client
	budget *Budget
	opts   Options
	auth   func() string
	base   string // apiBase; tests point it at a local server
	host   string

	mu         sync.Mutex
	totalBytes int64
	commits    map[string]string      // repo@commit -> tree SHA
	trees      map[string][]treeEntry // repo@tree SHA -> entries
}

// New returns a Client for api.github.com.
func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = defaultMaxFileBytes
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = defaultMaxTotalBytes
	}
	if o.MaxListBytes <= 0 {
		o.MaxListBytes = defaultMaxListBytes
	}
	var hc http.Client
	if o.HTTPClient != nil {
		hc = *o.HTTPClient
	}
	// The per-request deadline is a context, so Client.Timeout stays off.
	hc.Timeout = 0
	c := &Client{commits: map[string]string{}, trees: map[string][]treeEntry{}, budget: o.Budget, auth: bearer(o.Token)}
	// The copy kept in the client must not hold the token: fmt prints
	// unexported fields without calling their methods.
	o.Token = ""
	c.opts = o
	c.setBase(apiBase)
	hc.CheckRedirect = c.checkRedirect
	// Every connection goes through dialContext so addresses are validated
	// where they are resolved. A caller-supplied transport is cloned for its
	// TLS settings; anything that is not an *http.Transport is replaced. A
	// proxy would be dialed instead of GitHub, so none is used.
	var tr *http.Transport
	if t, ok := hc.Transport.(*http.Transport); ok {
		tr = t.Clone()
	} else {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	}
	tr.Proxy = nil
	tr.DialTLSContext = nil
	tr.DialContext = c.dialContext
	hc.Transport = tr
	c.http = &hc
	return c
}

func (c *Client) setBase(base string) {
	c.base = base
	if u, err := url.Parse(base); err == nil {
		c.host = u.Host
	}
}

// BytesRead returns the file content bytes counted against the cycle's cap.
func (c *Client) BytesRead() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalBytes
}

func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if c.opts.Resolver != nil {
		if ips, err = c.opts.Resolver(ctx, host); err != nil {
			return nil, fmt.Errorf("github: resolve %s: %w", host, err)
		}
	} else if ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host); err != nil {
		return nil, fmt.Errorf("github: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("github: %s resolved to no address", host)
	}
	for _, ip := range ips {
		if registry.ForbiddenAddr(ip) && (c.opts.AllowAddr == nil || !c.opts.AllowAddr(ip, port)) {
			return nil, fmt.Errorf("%w: %s is or resolves to %s", ErrForbiddenAddress, host, ip)
		}
	}
	var d net.Dialer
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// checkRedirect allows a few redirects within the API host, only over HTTPS,
// each costing one request. A redirect to another host is refused, so the
// token cannot leave api.github.com.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("%w: too many redirects", ErrBadResponse)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%w: redirect to a non-HTTPS URL", ErrBadResponse)
	}
	if req.URL.Host != c.host {
		return fmt.Errorf("%w: redirect to another host", ErrBadResponse)
	}
	return c.budget.take()
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// get sends one authenticated GET (one budget unit) and reads the body within
// limit. Successful responses over the limit are ErrTooLarge; error bodies
// are truncated instead. Non-success statuses become typed errors.
func (c *Client) get(ctx context.Context, rawURL, accept string, limit int64) (*response, error) {
	return c.fetch(ctx, rawURL, accept, limit, nil)
}

// fetch is get that also reports, in read, how many body bytes were read from
// the network, whatever the outcome.
func (c *Client) fetch(ctx context.Context, rawURL, accept string, limit int64, read *int64) (*response, error) {
	if err := c.budget.take(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "kestrelynx")
	if a := c.auth(); a != "" {
		req.Header.Set("Authorization", a)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error carries the URL, never a header.
		return nil, fmt.Errorf("github: GET %s: %w", req.URL.Redacted(), err)
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	max := limit
	if !ok {
		max = maxErrorBodyBytes
	}
	if ok && resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: response declares %d bytes (limit %d)", ErrTooLarge, resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if read != nil {
		*read = int64(len(body))
	}
	if err != nil {
		return nil, fmt.Errorf("github: read %s: %w", req.URL.Redacted(), err)
	}
	if int64(len(body)) > max {
		if ok {
			return nil, fmt.Errorf("%w: response is over %d bytes", ErrTooLarge, limit)
		}
		body = body[:max]
	}
	r := &response{status: resp.StatusCode, header: resp.Header, body: body}
	if !ok {
		return nil, statusErr(r, time.Now())
	}
	return r, nil
}

// statusErr converts a non-success status into its error.
func statusErr(r *response, now time.Time) error {
	switch r.status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return ErrAuthRequired
	case http.StatusTooManyRequests:
		return rateLimited(r.header, now)
	case http.StatusForbidden:
		if r.header.Get("X-RateLimit-Remaining") == "0" || r.header.Get("Retry-After") != "" {
			return rateLimited(r.header, now)
		}
		return ErrForbidden
	}
	return &StatusError{Status: r.status}
}

func rateLimited(h http.Header, now time.Time) *RateLimitedError {
	e := &RateLimitedError{}
	if n, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && n > 0 {
		e.Reset = time.Unix(n, 0)
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(h.Get("Retry-After")), 10, 64); err == nil && n > 0 {
		const maxDelay = int64(24 * time.Hour / time.Second)
		if n > maxDelay {
			n = maxDelay
		}
		e.RetryAfter = time.Duration(n) * time.Second
	}
	return e
}

func (c *Client) repoURL(repo Repo, suffix string) string {
	return c.base + "/repos/" + url.PathEscape(repo.Owner) + "/" + url.PathEscape(repo.Name) + suffix
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

const (
	acceptJSON = "application/vnd.github+json"
	acceptRaw  = "application/vnd.github.raw+json"
)

// Git tree entry modes. Entries are classified by mode, not by any type name
// the API derives from it.
const (
	modeFile       = "100644"
	modeExecutable = "100755"
	modeSymlink    = "120000"
	modeSubmodule  = "160000"
	modeTree       = "040000"
)

// EntryType is the kind of a directory entry.
type EntryType string

const (
	EntryFile      EntryType = "file"
	EntryDir       EntryType = "dir"
	EntrySymlink   EntryType = "symlink"
	EntrySubmodule EntryType = "submodule"
)

// Entry is one item of a directory listing. Only EntryFile entries may be
// read as files; a symlink or submodule is reported as such and never
// followed.
type Entry struct {
	Name string
	Path string
	Type EntryType
	// Size is the blob size of a file or symlink (the length of its target);
	// 0 for a directory or submodule.
	Size int64
	// SHA is the git object ID: the blob of a file, the tree of a directory,
	// the target commit of a submodule.
	SHA string
}

type treeEntry struct {
	name string
	typ  EntryType
	size int64
	sha  string
}

func entryTypeOfMode(mode, objType string) (EntryType, bool) {
	switch {
	case (mode == modeFile || mode == modeExecutable) && objType == "blob":
		return EntryFile, true
	case mode == modeSymlink && objType == "blob":
		return EntrySymlink, true
	case mode == modeSubmodule && objType == "commit":
		return EntrySubmodule, true
	case mode == modeTree && objType == "tree":
		return EntryDir, true
	}
	return "", false
}

// ResolveBranch returns the commit SHA the branch of repo (owner/name) points
// to.
func (c *Client) ResolveBranch(ctx context.Context, repo, branch string) (string, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return "", err
	}
	if !ValidBranch(branch) {
		return "", fmt.Errorf("%w: branch %q", ErrInvalidInput, branch)
	}
	r, err := c.get(ctx, c.repoURL(rp, "/git/ref/heads/"+escapePath(branch)), acceptJSON, c.opts.MaxListBytes)
	if err != nil {
		return "", err
	}
	var ref struct {
		Ref    string `json:"ref"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(r.body, &ref); err != nil {
		return "", fmt.Errorf("%w: ref response is not a JSON object", ErrBadResponse)
	}
	if ref.Ref != "refs/heads/"+branch {
		return "", fmt.Errorf("%w: ref response names another reference", ErrBadResponse)
	}
	if ref.Object.Type != "commit" || !validSHA(ref.Object.SHA) {
		return "", fmt.Errorf("%w: ref response holds no commit SHA", ErrBadResponse)
	}
	return ref.Object.SHA, nil
}

// rootTree returns the tree SHA of a commit.
func (c *Client) rootTree(ctx context.Context, rp Repo, commit string) (string, error) {
	key := rp.String() + "@" + commit
	c.mu.Lock()
	t, ok := c.commits[key]
	c.mu.Unlock()
	if ok {
		return t, nil
	}
	r, err := c.get(ctx, c.repoURL(rp, "/git/commits/"+commit), acceptJSON, c.opts.MaxListBytes)
	if err != nil {
		return "", err
	}
	var cm struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(r.body, &cm); err != nil {
		return "", fmt.Errorf("%w: commit response is not a JSON object", ErrBadResponse)
	}
	if cm.SHA != commit || !validSHA(cm.Tree.SHA) {
		return "", fmt.Errorf("%w: commit response does not match the request", ErrBadResponse)
	}
	c.mu.Lock()
	c.commits[key] = cm.Tree.SHA
	c.mu.Unlock()
	return cm.Tree.SHA, nil
}

// tree lists one tree, non-recursively. A truncated response is never taken
// for the complete listing.
func (c *Client) tree(ctx context.Context, rp Repo, treeSHA string) ([]treeEntry, error) {
	key := rp.String() + "@" + treeSHA
	c.mu.Lock()
	es, ok := c.trees[key]
	c.mu.Unlock()
	if ok {
		return es, nil
	}
	r, err := c.get(ctx, c.repoURL(rp, "/git/trees/"+treeSHA), acceptJSON, c.opts.MaxListBytes)
	if err != nil {
		return nil, err
	}
	var t struct {
		SHA       string `json:"sha"`
		Truncated bool   `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size int64  `json:"size"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(r.body, &t); err != nil {
		return nil, fmt.Errorf("%w: tree response is not a JSON object", ErrBadResponse)
	}
	if t.SHA != treeSHA {
		return nil, fmt.Errorf("%w: tree response does not match the request", ErrBadResponse)
	}
	if t.Truncated {
		return nil, fmt.Errorf("%w: the tree listing is truncated", ErrTooLarge)
	}
	seen := make(map[string]bool, len(t.Tree))
	out := make([]treeEntry, 0, len(t.Tree))
	for _, e := range t.Tree {
		typ, ok := entryTypeOfMode(e.Mode, e.Type)
		if !ok || e.Path == "" || strings.Contains(e.Path, "/") || e.Path == "." || e.Path == ".." ||
			!validSHA(e.SHA) || e.Size < 0 || seen[e.Path] {
			return nil, fmt.Errorf("%w: malformed tree entry", ErrBadResponse)
		}
		seen[e.Path] = true
		size := e.Size
		if typ == EntryDir || typ == EntrySubmodule {
			size = 0
		}
		out = append(out, treeEntry{name: e.Path, typ: typ, size: size, sha: e.SHA})
	}
	c.mu.Lock()
	c.trees[key] = out
	c.mu.Unlock()
	return out, nil
}

// dirTree walks from the commit's tree to the tree of dir ("." for the root),
// one non-recursive listing per path component. A component that is not a
// directory, a symlink included, ends the walk; links are never followed.
func (c *Client) dirTree(ctx context.Context, rp Repo, commit, dir string) (string, error) {
	cur, err := c.rootTree(ctx, rp, commit)
	if err != nil || dir == "." {
		return cur, err
	}
	for _, comp := range strings.Split(dir, "/") {
		es, err := c.tree(ctx, rp, cur)
		if err != nil {
			return "", err
		}
		next := ""
		for _, e := range es {
			if e.name != comp {
				continue
			}
			if e.typ != EntryDir {
				return "", fmt.Errorf("%w: %s is a %s", ErrNotDirectory, comp, e.typ)
			}
			next = e.sha
		}
		if next == "" {
			return "", fmt.Errorf("%w: %s", ErrNotFound, comp)
		}
		cur = next
	}
	return cur, nil
}

// ListDirectory lists the directory dir ("." for the root) of repo
// (owner/name) at the commit sha. Entries are classified by their git mode.
func (c *Client) ListDirectory(ctx context.Context, repo, sha, dir string) ([]Entry, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return nil, err
	}
	if !validSHA(sha) {
		return nil, fmt.Errorf("%w: commit %q is not a 40-hex SHA", ErrInvalidInput, sha)
	}
	if !ValidPath(dir, true) {
		return nil, fmt.Errorf("%w: directory %q", ErrInvalidInput, dir)
	}
	ts, err := c.dirTree(ctx, rp, sha, dir)
	if err != nil {
		return nil, err
	}
	es, err := c.tree(ctx, rp, ts)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(es))
	for _, e := range es {
		p := e.name
		if dir != "." {
			p = dir + "/" + e.name
		}
		out = append(out, Entry{Name: e.name, Path: p, Type: e.typ, Size: e.size, SHA: e.sha})
	}
	return out, nil
}

// File is a file read at a commit.
type File struct {
	Path string
	// SHA is the blob SHA of Content, verified by hashing it.
	SHA     string
	Content []byte
}

// ReadFile reads the regular file path of repo (owner/name) at the commit sha.
// A directory, symlink or submodule is *NotRegularFileError, a Git LFS pointer
// is ErrLFSPointer, a file over the per-file cap, or one that would take the
// cycle past its total cap, is ErrTooLarge; both caps are checked against the
// size in the tree before the blob is requested. The content is fetched raw,
// read up to the cap, and verified against its blob SHA.
func (c *Client) ReadFile(ctx context.Context, repo, sha, p string) (File, error) {
	rp, err := ParseRepo(repo)
	if err != nil {
		return File{}, err
	}
	if !validSHA(sha) {
		return File{}, fmt.Errorf("%w: commit %q is not a 40-hex SHA", ErrInvalidInput, sha)
	}
	if !ValidPath(p, false) {
		return File{}, fmt.Errorf("%w: path %q", ErrInvalidInput, p)
	}
	dir, name := ".", p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		dir, name = p[:i], p[i+1:]
	}
	ts, err := c.dirTree(ctx, rp, sha, dir)
	if err != nil {
		return File{}, err
	}
	es, err := c.tree(ctx, rp, ts)
	if err != nil {
		return File{}, err
	}
	var ent *treeEntry
	for i := range es {
		if es[i].name == name {
			ent = &es[i]
		}
	}
	if ent == nil {
		return File{}, fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	if ent.typ != EntryFile {
		return File{}, &NotRegularFileError{Path: p, Type: string(ent.typ)}
	}
	if ent.size > c.opts.MaxFileBytes {
		return File{}, fmt.Errorf("%w: %s is %d bytes (limit %d)", ErrTooLarge, p, ent.size, c.opts.MaxFileBytes)
	}
	if err := c.reserve(p, ent.size); err != nil {
		return File{}, err
	}
	// The body is read up to the size the tree declared (plus one byte to
	// notice an overrun). Whatever happens, the cycle is charged for the bytes
	// actually read and only the unused part of the reservation is released.
	var read int64
	r, err := c.fetch(ctx, c.repoURL(rp, "/git/blobs/"+ent.sha), acceptRaw, ent.size, &read)
	c.count(read - ent.size)
	if err != nil {
		return File{}, err
	}
	content := r.body
	if int64(len(content)) != ent.size || blobSHA(content) != ent.sha {
		return File{}, fmt.Errorf("%w: %s", ErrHashMismatch, p)
	}
	if isLFSPointer(content) {
		return File{}, fmt.Errorf("%w: %s", ErrLFSPointer, p)
	}
	return File{Path: p, SHA: ent.sha, Content: content}, nil
}

// reserve counts size bytes against the cycle's total, or refuses.
func (c *Client) reserve(p string, size int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.totalBytes+size > c.opts.MaxTotalBytes {
		return fmt.Errorf("%w: reading %s would pass the cycle's %d byte file limit", ErrByteBudgetExhausted, p, c.opts.MaxTotalBytes)
	}
	c.totalBytes += size
	return nil
}

// count corrects the reserved total when the content turned out to differ in
// size from the declared one.
func (c *Client) count(delta int64) {
	c.mu.Lock()
	c.totalBytes += delta
	c.mu.Unlock()
}

// blobSHA is the git object ID of a blob with the given content.
func blobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // see import
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

func isLFSPointer(content []byte) bool {
	return len(content) <= lfsPointerMaxBytes && bytes.HasPrefix(content, []byte(lfsPointerPrefix))
}
