package github

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	sha40 = "0123456789abcdef0123456789abcdef01234567"
	token = "ghp_secrettoken0123456789"
)

func gitBlobSHA(b []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// newTest starts a TLS server with handler and returns a client pointed at
// it, allowed to reach the loopback address.
func newTest(t *testing.T, h http.Handler, o Options) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	o.HTTPClient = srv.Client()
	o.AllowAddr = func(ip net.IP, port string) bool { return ip.IsLoopback() }
	c := New(o)
	c.setBase(srv.URL)
	return c, srv
}

func jsonResp(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func TestResolveBranch(t *testing.T) {
	var gotPath, gotAuth, gotUA string
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotUA = r.URL.EscapedPath(), r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		jsonResp(w, 200, `{"ref":"refs/heads/release/1.x","object":{"type":"commit","sha":"`+sha40+`"}}`)
	}), Options{Token: Token(token)})
	sha, err := c.ResolveBranch(context.Background(), "example/app", "release/1.x")
	if err != nil || sha != sha40 {
		t.Fatalf("ResolveBranch = %q, %v", sha, err)
	}
	if gotPath != "/repos/example/app/git/ref/heads/release/1.x" {
		t.Errorf("path = %s", gotPath)
	}
	if gotAuth != "Bearer "+token {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotUA == "" {
		t.Error("no User-Agent")
	}
}

func TestAnonymousSendsNoAuthorization(t *testing.T) {
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("Authorization header sent without a token")
		}
		jsonResp(w, 200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha40+`"}}`)
	}), Options{})
	if _, err := c.ResolveBranch(context.Background(), "example/app", "main"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveBranchRejectsBadResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":     `nope`,
		"other ref":    `{"ref":"refs/heads/other","object":{"type":"commit","sha":"` + sha40 + `"}}`,
		"tag object":   `{"ref":"refs/heads/main","object":{"type":"tag","sha":"` + sha40 + `"}}`,
		"short sha":    `{"ref":"refs/heads/main","object":{"type":"commit","sha":"abc"}}`,
		"uppercase":    `{"ref":"refs/heads/main","object":{"type":"commit","sha":"` + strings.ToUpper(sha40) + `"}}`,
		"missing sha":  `{"ref":"refs/heads/main","object":{"type":"commit"}}`,
		"prefix array": `[{"ref":"refs/heads/main"}]`,
	} {
		c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonResp(w, 200, body) }), Options{})
		if _, err := c.ResolveBranch(context.Background(), "example/app", "main"); !errors.Is(err, ErrBadResponse) {
			t.Errorf("%s: err = %v, want ErrBadResponse", name, err)
		}
	}
}

func TestInvalidInputNeverReachesTheNetwork(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }), Options{})
	ctx := context.Background()
	if _, err := c.ResolveBranch(ctx, "no-slash", "main"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("repo: %v", err)
	}
	if _, err := c.ResolveBranch(ctx, "a/b", "-x"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("branch: %v", err)
	}
	if _, err := c.ListDirectory(ctx, "a/b", "main", "."); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("sha: %v", err)
	}
	if _, err := c.ListDirectory(ctx, "a/b", sha40, "../x"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("dir: %v", err)
	}
	if _, err := c.ReadFile(ctx, "a/b", sha40, "."); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("file: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("server hit %d times", hits.Load())
	}
}

// node is a file, symlink, submodule or directory of a fake repository.
type node struct {
	mode     string
	data     []byte
	children map[string]*node
}

// fakeGH serves the Git Data API for one repository at one commit.
type fakeGH struct {
	root     *node
	commit   string
	treeSHA  map[*node]string
	trees    map[string]*node
	blobs    map[string][]byte // by blob SHA
	override map[string][]byte // served instead of the real content
	truncate map[string]bool   // tree SHAs reported truncated

	mu         sync.Mutex
	blobReqs   int
	treeReqs   int
	lastAccept string
	paths      []string
}

func newFakeGH() *fakeGH {
	return &fakeGH{
		root: &node{mode: "040000", children: map[string]*node{}}, commit: sha40,
		override: map[string][]byte{}, truncate: map[string]bool{},
	}
}

func (f *fakeGH) add(p, mode string, data []byte) {
	cur := f.root
	parts := strings.Split(p, "/")
	for _, d := range parts[:len(parts)-1] {
		next, ok := cur.children[d]
		if !ok {
			next = &node{mode: "040000", children: map[string]*node{}}
			cur.children[d] = next
		}
		cur = next
	}
	cur.children[parts[len(parts)-1]] = &node{mode: mode, data: data}
}

func (f *fakeGH) addFile(p string, data []byte) { f.add(p, "100644", data) }
func (f *fakeGH) addSymlink(p, target string)   { f.add(p, "120000", []byte(target)) }
func (f *fakeGH) addSubmodule(p string)         { f.add(p, "160000", nil) }
func (f *fakeGH) addDir(p string)               { f.add(p+"/.keep", "100644", nil) }

func (f *fakeGH) objType(n *node) string {
	switch n.mode {
	case "040000":
		return "tree"
	case "160000":
		return "commit"
	}
	return "blob"
}

func sortedNames(n *node) []string {
	var names []string
	for k := range n.children {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// seal computes object IDs; call after the last add.
func (f *fakeGH) seal() *fakeGH {
	f.treeSHA, f.trees, f.blobs = map[*node]string{}, map[string]*node{}, map[string][]byte{}
	var walk func(n *node) string
	walk = func(n *node) string {
		switch f.objType(n) {
		case "blob":
			sum := gitBlobSHA(n.data)
			f.blobs[sum] = n.data
			return sum
		case "commit":
			return "feedfacefeedfacefeedfacefeedfacefeedface"
		}
		h := sha1.New()
		for _, name := range sortedNames(n) {
			c := n.children[name]
			fmt.Fprintf(h, "%s %s %s\n", c.mode, name, walk(c))
		}
		sum := hex.EncodeToString(h.Sum(nil))
		f.treeSHA[n], f.trees[sum] = sum, n
		return sum
	}
	walk(f.root)
	return f
}

func (f *fakeGH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	const prefix = "/repos/example/app/git/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case strings.HasPrefix(rest, "commits/"):
		if strings.TrimPrefix(rest, "commits/") != f.commit {
			jsonResp(w, 404, `{}`)
			return
		}
		jsonResp(w, 200, fmt.Sprintf(`{"sha":%q,"tree":{"sha":%q}}`, f.commit, f.treeSHA[f.root]))
	case strings.HasPrefix(rest, "trees/"):
		f.mu.Lock()
		f.treeReqs++
		f.mu.Unlock()
		id := strings.TrimPrefix(rest, "trees/")
		n, ok := f.trees[id]
		if !ok {
			jsonResp(w, 404, `{}`)
			return
		}
		var ents []string
		for _, name := range sortedNames(n) {
			c := n.children[name]
			sum := f.treeSHA[c]
			if f.objType(c) == "blob" {
				sum = gitBlobSHA(c.data)
			} else if f.objType(c) == "commit" {
				sum = "feedfacefeedfacefeedfacefeedfacefeedface"
			}
			e := fmt.Sprintf(`{"path":%q,"mode":%q,"type":%q,"sha":%q`, name, c.mode, f.objType(c), sum)
			if f.objType(c) == "blob" {
				e += fmt.Sprintf(`,"size":%d`, len(c.data))
			}
			ents = append(ents, e+"}")
		}
		jsonResp(w, 200, fmt.Sprintf(`{"sha":%q,"tree":[%s],"truncated":%v}`, id, strings.Join(ents, ","), f.truncate[id]))
	case strings.HasPrefix(rest, "blobs/"):
		f.mu.Lock()
		f.blobReqs++
		f.lastAccept = r.Header.Get("Accept")
		f.mu.Unlock()
		id := strings.TrimPrefix(rest, "blobs/")
		data, ok := f.blobs[id]
		if o, has := f.override[id]; has {
			data, ok = o, true
		}
		if !ok {
			jsonResp(w, 404, `{}`)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	default:
		jsonResp(w, 404, `{}`)
	}
}

func newGH(t *testing.T, f *fakeGH, o Options) *Client {
	t.Helper()
	c, _ := newTest(t, f, o)
	return c
}

func TestListDirectoryClassifiesByMode(t *testing.T) {
	f := newFakeGH()
	f.addFile("web/app/package.json", []byte("{}"))
	f.add("web/app/run.sh", "100755", []byte("#!/bin/sh\n"))
	f.addDir("web/app/src")
	f.addSymlink("web/app/lock.json", "../shared/lock.json")
	f.addSubmodule("web/app/vendor")
	f.seal()
	c := newGH(t, f, Options{})
	got, err := c.ListDirectory(context.Background(), "example/app", sha40, "web/app")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]EntryType{
		"package.json": EntryFile, "run.sh": EntryFile, "src": EntryDir, "lock.json": EntrySymlink, "vendor": EntrySubmodule,
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %+v", got)
	}
	for _, e := range got {
		if e.Type != want[e.Name] || e.Path != "web/app/"+e.Name || !validSHA(e.SHA) {
			t.Errorf("entry = %+v, want type %s", e, want[e.Name])
		}
		if e.Name == "package.json" && e.Size != 2 {
			t.Errorf("size = %d", e.Size)
		}
		if e.Type == EntryDir && e.Size != 0 {
			t.Errorf("dir size = %d", e.Size)
		}
	}
	// commit + root + web + app, each listing fetched once.
	if f.treeReqs != 3 {
		t.Errorf("tree requests = %d, want 3 (root, web, app)", f.treeReqs)
	}
	for _, p := range f.paths {
		if strings.Contains(p, "/contents") {
			t.Errorf("the contents API was used: %s", p)
		}
	}
}

func TestListDirectoryRoot(t *testing.T) {
	f := newFakeGH()
	f.addFile("go.mod", []byte("module x\n"))
	f.seal()
	c := newGH(t, f, Options{})
	got, err := c.ListDirectory(context.Background(), "example/app", sha40, ".")
	if err != nil || len(got) != 1 || got[0].Path != "go.mod" || got[0].Type != EntryFile {
		t.Fatalf("entries = %+v, err = %v", got, err)
	}
}

func TestTreesAreCachedWithinTheClient(t *testing.T) {
	f := newFakeGH()
	f.addFile("a/b/x", []byte("1"))
	f.addFile("a/b/y", []byte("2"))
	f.seal()
	c := newGH(t, f, Options{})
	ctx := context.Background()
	for _, name := range []string{"a/b/x", "a/b/y"} {
		if _, err := c.ReadFile(ctx, "example/app", sha40, name); err != nil {
			t.Fatal(err)
		}
	}
	if f.treeReqs != 3 {
		t.Errorf("tree requests = %d, want 3 for two files in one directory", f.treeReqs)
	}
}

func TestPathThroughLinkOrFileIsNotADirectory(t *testing.T) {
	f := newFakeGH()
	f.addFile("plain", []byte("x"))
	f.addSymlink("link", "real")
	f.addSubmodule("sub")
	f.addFile("real/inner", []byte("y"))
	f.seal()
	c := newGH(t, f, Options{})
	ctx := context.Background()
	for _, dir := range []string{"plain", "link", "sub"} {
		if _, err := c.ListDirectory(ctx, "example/app", sha40, dir); !errors.Is(err, ErrNotDirectory) {
			t.Errorf("list %s: err = %v, want ErrNotDirectory", dir, err)
		}
	}
	// A file reached through a symlinked directory is never read.
	if _, err := c.ReadFile(ctx, "example/app", sha40, "link/inner"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("read through link: err = %v", err)
	}
	if _, err := c.ListDirectory(ctx, "example/app", sha40, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing dir: err = %v", err)
	}
	if _, err := c.ReadFile(ctx, "example/app", sha40, "real/none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing file: err = %v", err)
	}
	if f.blobReqs != 0 {
		t.Errorf("blob requests = %d", f.blobReqs)
	}
}

func TestTruncatedTreeIsRefused(t *testing.T) {
	f := newFakeGH()
	f.addFile("a", []byte("x"))
	f.seal()
	f.truncate[f.treeSHA[f.root]] = true
	c := newGH(t, f, Options{})
	if _, err := c.ListDirectory(context.Background(), "example/app", sha40, "."); !errors.Is(err, ErrTooLarge) {
		t.Errorf("list: err = %v, want ErrTooLarge", err)
	}
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "a"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("read: err = %v, want ErrTooLarge", err)
	}
	if f.blobReqs != 0 {
		t.Error("a blob was requested from a truncated tree")
	}
}

func TestMalformedTreeResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      `x`,
		"other tree":    `{"sha":"` + sha40 + `","tree":[],"truncated":false}`,
		"unknown mode":  `{"sha":"ROOT","tree":[{"path":"a","mode":"100664","type":"blob","sha":"` + sha40 + `","size":1}],"truncated":false}`,
		"mode and type": `{"sha":"ROOT","tree":[{"path":"a","mode":"120000","type":"tree","sha":"` + sha40 + `"}],"truncated":false}`,
		"slash in name": `{"sha":"ROOT","tree":[{"path":"a/b","mode":"100644","type":"blob","sha":"` + sha40 + `","size":1}],"truncated":false}`,
		"duplicate":     `{"sha":"ROOT","tree":[{"path":"a","mode":"100644","type":"blob","sha":"` + sha40 + `","size":1},{"path":"a","mode":"100644","type":"blob","sha":"` + sha40 + `","size":1}],"truncated":false}`,
		"bad sha":       `{"sha":"ROOT","tree":[{"path":"a","mode":"100644","type":"blob","sha":"zz","size":1}],"truncated":false}`,
	} {
		root := strings.Repeat("a", 40)
		c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/git/commits/") {
				jsonResp(w, 200, `{"sha":"`+sha40+`","tree":{"sha":"`+root+`"}}`)
				return
			}
			jsonResp(w, 200, strings.ReplaceAll(body, "ROOT", root))
		}), Options{})
		if _, err := c.ListDirectory(context.Background(), "example/app", sha40, "."); !errors.Is(err, ErrBadResponse) {
			t.Errorf("%s: err = %v, want ErrBadResponse", name, err)
		}
	}
}

func TestReadFile(t *testing.T) {
	content := []byte("{\n  \"name\": \"app\"\n}\n")
	f := newFakeGH()
	f.addFile("web/package.json", content)
	f.addFile("web/other", []byte("zzz"))
	f.seal()
	c := newGH(t, f, Options{})
	got, err := c.ReadFile(context.Background(), "example/app", sha40, "web/package.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Content) != string(content) || got.SHA != gitBlobSHA(content) || got.Path != "web/package.json" {
		t.Errorf("file = %+v", got)
	}
	if f.lastAccept != "application/vnd.github.raw+json" {
		t.Errorf("blob Accept = %q, want the raw media type", f.lastAccept)
	}
	if c.BytesRead() != int64(len(content)) {
		t.Errorf("BytesRead = %d", c.BytesRead())
	}
	if f.blobReqs != 1 {
		t.Errorf("blob requests = %d", f.blobReqs)
	}
}

func TestReadFileBinaryAndEmpty(t *testing.T) {
	bin := []byte{0, 1, 2, 0xff, '\n', '\r', '\n', 0xfe}
	f := newFakeGH()
	f.addFile("bin", bin)
	f.addFile("empty", nil)
	f.seal()
	c := newGH(t, f, Options{})
	for name, want := range map[string][]byte{"bin": bin, "empty": nil} {
		got, err := c.ReadFile(context.Background(), "example/app", sha40, name)
		if err != nil || string(got.Content) != string(want) {
			t.Errorf("%s: %v, %v", name, got.Content, err)
		}
	}
}

func TestReadFileHashMismatch(t *testing.T) {
	for name, served := range map[string][]byte{
		"same size other content": []byte("HELLO"),
		"shorter":                 []byte("hell"),
	} {
		f := newFakeGH()
		f.addFile("f", []byte("hello"))
		f.seal()
		f.override[gitBlobSHA([]byte("hello"))] = served
		c := newGH(t, f, Options{})
		if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); !errors.Is(err, ErrHashMismatch) {
			t.Errorf("%s: err = %v, want ErrHashMismatch", name, err)
		}
	}
}

func TestReadFileLongerThanDeclaredIsTooLarge(t *testing.T) {
	f := newFakeGH()
	f.addFile("f", []byte("hello"))
	f.seal()
	f.override[gitBlobSHA([]byte("hello"))] = []byte("hello!")
	c := newGH(t, f, Options{})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestReadFileNotRegular(t *testing.T) {
	f := newFakeGH()
	f.addSymlink("link", "target")
	f.addSubmodule("sub")
	f.addDir("dir")
	f.seal()
	c := newGH(t, f, Options{})
	for typ, p := range map[string]string{"symlink": "link", "submodule": "sub", "dir": "dir"} {
		_, err := c.ReadFile(context.Background(), "example/app", sha40, p)
		var nr *NotRegularFileError
		if !errors.Is(err, ErrNotRegularFile) || !errors.As(err, &nr) || nr.Type != typ {
			t.Errorf("%s: err = %v", typ, err)
		}
	}
	if f.blobReqs != 0 {
		t.Errorf("blob requests = %d, want none for non-regular entries", f.blobReqs)
	}
}

func TestReadFileLFSPointer(t *testing.T) {
	f := newFakeGH()
	f.addFile("lock", []byte("version https://git-lfs.github.com/spec/v1\noid sha256:"+strings.Repeat("a", 64)+"\nsize 12345\n"))
	f.seal()
	c := newGH(t, f, Options{})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "lock"); !errors.Is(err, ErrLFSPointer) {
		t.Errorf("err = %v, want ErrLFSPointer", err)
	}
}

func TestReadFileSizeCapsNearTheLimit(t *testing.T) {
	f := newFakeGH()
	f.addFile("exact", []byte(strings.Repeat("y", 100)))
	f.addFile("over", []byte(strings.Repeat("y", 101)))
	f.seal()
	c := newGH(t, f, Options{MaxFileBytes: 100})
	ctx := context.Background()
	if got, err := c.ReadFile(ctx, "example/app", sha40, "exact"); err != nil || len(got.Content) != 100 {
		t.Errorf("exact: %v", err)
	}
	blobsBefore := f.blobReqs
	if _, err := c.ReadFile(ctx, "example/app", sha40, "over"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over: err = %v", err)
	}
	if f.blobReqs != blobsBefore {
		t.Error("a blob over the cap was requested")
	}
	if c.BytesRead() != 100 {
		t.Errorf("BytesRead = %d, want only the file that was read", c.BytesRead())
	}
}

func TestReadFileBodyLargerThanTheTreeSaid(t *testing.T) {
	f := newFakeGH()
	f.addFile("f", []byte(strings.Repeat("y", 100)))
	f.seal()
	f.override[gitBlobSHA([]byte(strings.Repeat("y", 100)))] = []byte(strings.Repeat("y", 5000))
	c := newGH(t, f, Options{MaxFileBytes: 100})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge (body read stops at the cap)", err)
	}
	if c.BytesRead() != 101 {
		t.Errorf("BytesRead = %d, want the 101 bytes actually read", c.BytesRead())
	}
}

func TestTotalByteBudgetIsReservedBeforeFetching(t *testing.T) {
	f := newFakeGH()
	for i := 0; i < 3; i++ {
		f.addFile(fmt.Sprintf("f%d", i), []byte(strings.Repeat(fmt.Sprint(i), 100)))
	}
	f.seal()
	c := newGH(t, f, Options{MaxFileBytes: 100, MaxTotalBytes: 250})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.ReadFile(ctx, "example/app", sha40, fmt.Sprintf("f%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ReadFile(ctx, "example/app", sha40, "f2"); !errors.Is(err, ErrByteBudgetExhausted) || errors.Is(err, ErrTooLarge) {
		t.Errorf("third read: err = %v, want ErrByteBudgetExhausted and not ErrTooLarge", err)
	}
	if f.blobReqs != 2 {
		t.Errorf("blob requests = %d, want 2: none once the budget is spent", f.blobReqs)
	}
	if c.BytesRead() != 200 {
		t.Errorf("BytesRead = %d", c.BytesRead())
	}
}

func TestTotalByteBudgetUnderConcurrency(t *testing.T) {
	f := newFakeGH()
	for i := 0; i < 8; i++ {
		f.addFile(fmt.Sprintf("f%d", i), []byte(strings.Repeat(fmt.Sprint(i), 100)))
	}
	f.seal()
	c := newGH(t, f, Options{MaxFileBytes: 100, MaxTotalBytes: 350})
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.ReadFile(context.Background(), "example/app", sha40, fmt.Sprintf("f%d", i)); err == nil {
				ok.Add(1)
			} else if !errors.Is(err, ErrByteBudgetExhausted) {
				t.Errorf("err = %v", err)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 3 || c.BytesRead() != 300 || f.blobReqs != 3 {
		t.Errorf("ok=%d bytes=%d blobs=%d, want 3/300/3", ok.Load(), c.BytesRead(), f.blobReqs)
	}
}

func TestFailedFetchReleasesItsReservation(t *testing.T) {
	f := newFakeGH()
	f.addFile("a", []byte(strings.Repeat("a", 100)))
	f.seal()
	b := NewBudget(2) // the commit and the root tree, then none for the blob
	c := newGH(t, f, Options{Budget: b})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "a"); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v", err)
	}
	if c.BytesRead() != 0 {
		t.Errorf("BytesRead = %d after a fetch that never happened", c.BytesRead())
	}
}

func TestResponseBodyCap(t *testing.T) {
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(200)
		fmt.Fprint(w, `{`+strings.Repeat(" ", 5000)+`}`)
	}), Options{MaxListBytes: 1000})
	if _, err := c.ListDirectory(context.Background(), "a/b", sha40, "."); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestTokenIsNeverPrinted(t *testing.T) {
	const secret = "ghp_printedsecret0123"
	c := New(Options{Token: Token(secret)})
	o := Options{Token: Token(secret)}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "client", c, "opts", o, "token", o.Token)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "client", c, "opts", o, "token", o.Token)
	outs := []string{buf.String()}
	for _, v := range []any{c, o, &o, o.Token} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
	}
	if j, err := json.Marshal(o); err == nil {
		outs = append(outs, string(j))
	}
	for _, out := range outs {
		if strings.Contains(out, secret) || strings.Contains(out, hex.EncodeToString([]byte(secret))) {
			t.Errorf("token printed: %.200s", out)
		}
	}
	if o.Token.Value() != secret {
		t.Error("Value() must return the token")
	}
}

func TestOnlyGetRequests(t *testing.T) {
	var methods []string
	f := newFakeGH()
	f.addFile("f", []byte("x"))
	f.seal()
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if strings.Contains(r.URL.Path, "/git/ref/") {
			jsonResp(w, 200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha40+`"}}`)
			return
		}
		f.ServeHTTP(w, r)
	}), Options{})
	ctx := context.Background()
	c.ResolveBranch(ctx, "example/app", "main")
	c.ListDirectory(ctx, "example/app", sha40, ".")
	c.ReadFile(ctx, "example/app", sha40, "f")
	if len(methods) < 4 {
		t.Fatalf("methods = %v", methods)
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("method %s", m)
		}
	}
}

func TestStatusErrors(t *testing.T) {
	reset := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	cases := []struct {
		name    string
		status  int
		headers map[string]string
		want    error
	}{
		{"not found", 404, nil, ErrNotFound},
		{"unauthorized", 401, nil, ErrAuthRequired},
		{"forbidden", 403, map[string]string{"X-RateLimit-Remaining": "12"}, ErrForbidden},
		{"primary limit", 403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": fmt.Sprint(reset.Unix())}, ErrRateLimited},
		{"secondary limit", 403, map[string]string{"Retry-After": "60"}, ErrRateLimited},
		{"429", 429, map[string]string{"X-RateLimit-Reset": fmt.Sprint(reset.Unix())}, ErrRateLimited},
	}
	for _, tc := range cases {
		c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range tc.headers {
				w.Header().Set(k, v)
			}
			jsonResp(w, tc.status, `{"message":"nope"}`)
		}), Options{Token: Token(token)})
		_, err := c.ResolveBranch(context.Background(), "a/b", "main")
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("%s: error contains the token", tc.name)
		}
		var rl *RateLimitedError
		if errors.As(err, &rl) {
			if tc.name == "secondary limit" && rl.RetryAfter != time.Minute {
				t.Errorf("RetryAfter = %v", rl.RetryAfter)
			}
			if tc.headers["X-RateLimit-Reset"] != "" && !rl.Reset.Equal(reset) {
				t.Errorf("Reset = %v, want %v", rl.Reset, reset)
			}
		}
	}
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonResp(w, 500, `{}`) }), Options{})
	var se *StatusError
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); !errors.As(err, &se) || se.Status != 500 {
		t.Errorf("500: err = %v", err)
	}
}

func TestBudget(t *testing.T) {
	var hits atomic.Int32
	b := NewBudget(2)
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		jsonResp(w, 200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha40+`"}}`)
	}), Options{Budget: b})
	for i := 0; i < 2; i++ {
		if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("err = %v, want ErrBudgetExhausted", err)
	}
	if hits.Load() != 2 || b.Used() != 2 || b.Remaining() != 0 {
		t.Errorf("hits=%d used=%d remaining=%d", hits.Load(), b.Used(), b.Remaining())
	}
}

func TestRedirects(t *testing.T) {
	var other atomic.Int32
	otherSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("token reached another host")
		}
		jsonResp(w, 200, `{}`)
	}))
	t.Cleanup(otherSrv.Close)

	b := NewBudget(10)
	var sameHost func(w http.ResponseWriter, r *http.Request)
	c, srv := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sameHost(w, r) }), Options{Token: token, Budget: b})

	// Cross-host: refused, and the other host never sees a request.
	sameHost = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherSrv.URL+"/x", http.StatusFound)
	}
	_, err := c.ResolveBranch(context.Background(), "a/b", "main")
	if !errors.Is(err, ErrBadResponse) {
		t.Errorf("cross-host: err = %v, want ErrBadResponse", err)
	}
	if err != nil && strings.Contains(err.Error(), token) {
		t.Error("error contains the token")
	}
	if other.Load() != 0 {
		t.Errorf("other host got %d requests", other.Load())
	}

	// Same host: followed, each hop costs one budget unit.
	before := b.Used()
	sameHost = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			jsonResp(w, 200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha40+`"}}`)
			return
		}
		http.Redirect(w, r, srv.URL+"/moved", http.StatusMovedPermanently)
	}
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
	if got := b.Used() - before; got != 2 {
		t.Errorf("budget used for a redirect = %d, want 2", got)
	}

	// A redirect loop stops.
	sameHost = func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, srv.URL+"/again", http.StatusFound) }
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); !errors.Is(err, ErrBadResponse) {
		t.Errorf("loop: err = %v", err)
	}
}

func TestAddressPolicyRefusesLoopbackByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("reached the server") }))
	defer srv.Close()
	c := New(Options{HTTPClient: srv.Client()})
	c.setBase(srv.URL)
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
}

func TestResolverResultsAreChecked(t *testing.T) {
	c := New(Options{Resolver: func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}, nil
	}})
	c.setBase("https://api.github.com")
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
}

func TestTimeout(t *testing.T) {
	c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}), Options{Timeout: 100 * time.Millisecond})
	start := time.Now()
	if _, err := c.ResolveBranch(context.Background(), "a/b", "main"); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("timeout not applied")
	}
}

func TestDefaultBaseIsGitHubAPI(t *testing.T) {
	c := New(Options{})
	if c.base != "https://api.github.com" || c.host != "api.github.com" {
		t.Errorf("base = %q host = %q", c.base, c.host)
	}
}

// chunkedBlobServer serves every blob request with the given body, streamed
// without a Content-Length, optionally cutting the connection short.
func chunkedBlob(t *testing.T, f *fakeGH, body []byte, cut bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/git/blobs/") {
			f.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if cut {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)+10))
			w.Write(body)
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		w.(http.Flusher).Flush()
		w.Write(body)
	})
}

func TestOverrunReadStopsAtTheDeclaredSizePlusOne(t *testing.T) {
	f := newFakeGH()
	f.addFile("f", []byte("hello"))
	f.seal()
	c, _ := newTest(t, chunkedBlob(t, f, []byte(strings.Repeat("z", 50)), false), Options{MaxTotalBytes: 10})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if c.BytesRead() != 6 {
		t.Errorf("BytesRead = %d, want 6 (declared 5 plus the byte that showed the overrun)", c.BytesRead())
	}
}

func TestDeclaredOverrunIsRefusedWithoutReading(t *testing.T) {
	f := newFakeGH()
	f.addFile("f", []byte("hello"))
	f.seal()
	f.override[gitBlobSHA([]byte("hello"))] = []byte(strings.Repeat("z", 50))
	c := newGH(t, f, Options{MaxTotalBytes: 10})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if c.BytesRead() != 0 {
		t.Errorf("BytesRead = %d, want 0: no body was read", c.BytesRead())
	}
}

func TestTruncatedBodyChargesWhatWasRead(t *testing.T) {
	f := newFakeGH()
	f.addFile("f", []byte(strings.Repeat("a", 100)))
	f.seal()
	c, _ := newTest(t, chunkedBlob(t, f, []byte(strings.Repeat("a", 40)), true), Options{})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); err == nil {
		t.Fatal("a truncated body was accepted")
	}
	if c.BytesRead() != 40 {
		t.Errorf("BytesRead = %d, want the 40 bytes received", c.BytesRead())
	}
}

func TestHashMismatchChargesTheBytesRead(t *testing.T) {
	f := newFakeGH()
	f.addFile("f", []byte("hello"))
	f.seal()
	f.override[gitBlobSHA([]byte("hello"))] = []byte("HELLO")
	c := newGH(t, f, Options{})
	if _, err := c.ReadFile(context.Background(), "example/app", sha40, "f"); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v", err)
	}
	if c.BytesRead() != 5 {
		t.Errorf("BytesRead = %d, want 5", c.BytesRead())
	}
}
