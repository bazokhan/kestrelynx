package github

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const repoPath = "/repos/example/app"

// newWriterTest starts a TLS server with handler and returns a Writer pointed
// at it, allowed to reach the loopback address.
func newWriterTest(t *testing.T, h http.Handler, o Options) *Writer {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	o.HTTPClient = srv.Client()
	o.AllowAddr = func(ip net.IP, port string) bool { return ip.IsLoopback() }
	w := NewWriter(o)
	w.c.setBase(srv.URL)
	return w
}

// recorded is one request as the server saw it.
type recorded struct {
	method, path, query, accept, version, ctype, auth string
	body                                              []byte
}

// recorder answers every request with status and body and keeps what it saw.
func recorder(status int, body string, out *[]recorded) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*out = append(*out, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Accept"),
			r.Header.Get("X-GitHub-Api-Version"), r.Header.Get("Content-Type"), r.Header.Get("Authorization"), b})
		jsonResp(w, status, body)
	})
}

func jsonBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("request body is not a JSON object: %v: %s", err, r.body)
	}
	return m
}

func checkHeaders(t *testing.T, r recorded, method, path string) {
	t.Helper()
	if r.method != method || r.path != path {
		t.Errorf("request = %s %s, want %s %s", r.method, r.path, method, path)
	}
	if r.accept != "application/vnd.github+json" || r.version != "2022-11-28" {
		t.Errorf("headers: Accept %q, version %q", r.accept, r.version)
	}
	if r.auth != "Bearer "+token {
		t.Errorf("Authorization = %q", r.auth)
	}
	if method != http.MethodGet && r.ctype != "application/json" {
		t.Errorf("Content-Type = %q", r.ctype)
	}
}

var tok = Options{Token: Token(token)}

func TestWriterRepository(t *testing.T) {
	var rec []recorded
	w := newWriterTest(t, recorder(200, `{"id":42,"full_name":"example/app","default_branch":"main","private":true}`, &rec), tok)
	info, err := w.Repository(context.Background(), "example/app")
	if err != nil {
		t.Fatal(err)
	}
	if info != (RepoInfo{ID: 42, FullName: "example/app", DefaultBranch: "main", Private: true}) {
		t.Errorf("info = %+v", info)
	}
	checkHeaders(t, rec[0], "GET", repoPath)
	for name, body := range map[string]string{
		"no id":       `{"full_name":"example/app","default_branch":"main"}`,
		"bad name":    `{"id":1,"full_name":"nope","default_branch":"main"}`,
		"bad default": `{"id":1,"full_name":"example/app","default_branch":""}`,
		"not object":  `[]`,
	} {
		w := newWriterTest(t, recorder(200, body, new([]recorded)), Options{})
		if _, err := w.Repository(context.Background(), "example/app"); !errors.Is(err, ErrBadResponse) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestCreateBlob(t *testing.T) {
	content := []byte("hello\n\x00bin")
	want := blobSHA(content)
	var rec []recorded
	w := newWriterTest(t, recorder(201, `{"sha":"`+want+`","url":"x"}`, &rec), tok)
	sha, err := w.CreateBlob(context.Background(), "example/app", content)
	if err != nil || sha != want {
		t.Fatalf("CreateBlob = %q, %v", sha, err)
	}
	checkHeaders(t, rec[0], "POST", repoPath+"/git/blobs")
	m := jsonBody(t, rec[0])
	got, _ := base64.StdEncoding.DecodeString(m["content"].(string))
	if m["encoding"] != "base64" || string(got) != string(content) {
		t.Errorf("body = %v", m)
	}
}

func TestCreateBlobRejectsAMismatchedSHA(t *testing.T) {
	w := newWriterTest(t, recorder(201, `{"sha":"`+sha40+`"}`, new([]recorded)), Options{})
	if _, err := w.CreateBlob(context.Background(), "example/app", []byte("x")); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("err = %v, want ErrHashMismatch", err)
	}
}

func TestCreateBlobSizeCapIsEnforcedBeforeSending(t *testing.T) {
	var hits atomic.Int32
	w := newWriterTest(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), Options{MaxFileBytes: 16})
	if _, err := w.CreateBlob(context.Background(), "example/app", make([]byte, 17)); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Error("request sent")
	}
}

func TestCreateTree(t *testing.T) {
	const out = "1111111111111111111111111111111111111111"
	var rec []recorded
	w := newWriterTest(t, recorder(201, `{"sha":"`+out+`"}`, &rec), tok)
	sha, err := w.CreateTree(context.Background(), "example/app", sha40, []TreeEntry{
		{Path: "web/package.json", Mode: "100644", BlobSHA: sha40},
		{Path: "run.sh", Mode: "100755", BlobSHA: sha40},
	})
	if err != nil || sha != out {
		t.Fatalf("CreateTree = %q, %v", sha, err)
	}
	checkHeaders(t, rec[0], "POST", repoPath+"/git/trees")
	var body struct {
		BaseTree string `json:"base_tree"`
		Tree     []struct{ Path, Mode, Type, SHA string }
	}
	if err := json.Unmarshal(rec[0].body, &body); err != nil {
		t.Fatal(err)
	}
	if body.BaseTree != sha40 || len(body.Tree) != 2 || body.Tree[1].Mode != "100755" || body.Tree[0].Type != "blob" ||
		body.Tree[0].Path != "web/package.json" || body.Tree[0].SHA != sha40 {
		t.Errorf("body = %s", rec[0].body)
	}
}

func TestCreateTreeInvalidInput(t *testing.T) {
	var hits atomic.Int32
	w := newWriterTest(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), Options{})
	ok := TreeEntry{Path: "a", Mode: "100644", BlobSHA: sha40}
	many := make([]TreeEntry, maxTreeEntries+1)
	for i := range many {
		many[i] = TreeEntry{Path: fmt.Sprint("f", i), Mode: "100644", BlobSHA: sha40}
	}
	for name, tc := range map[string]struct {
		base string
		es   []TreeEntry
	}{
		"bad base":     {"main", []TreeEntry{ok}},
		"no entries":   {sha40, nil},
		"too many":     {sha40, many},
		"dotdot":       {sha40, []TreeEntry{{Path: "../x", Mode: "100644", BlobSHA: sha40}}},
		"absolute":     {sha40, []TreeEntry{{Path: "/x", Mode: "100644", BlobSHA: sha40}}},
		"symlink mode": {sha40, []TreeEntry{{Path: "x", Mode: "120000", BlobSHA: sha40}}},
		"tree mode":    {sha40, []TreeEntry{{Path: "x", Mode: "040000", BlobSHA: sha40}}},
		"bad blob":     {sha40, []TreeEntry{{Path: "x", Mode: "100644", BlobSHA: "abc"}}},
		"duplicate":    {sha40, []TreeEntry{ok, ok}},
	} {
		if _, err := w.CreateTree(context.Background(), "example/app", tc.base, tc.es); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if hits.Load() != 0 {
		t.Error("request sent")
	}
}

func TestCreateCommitAndCommit(t *testing.T) {
	const parent = "2222222222222222222222222222222222222222"
	const commit = "3333333333333333333333333333333333333333"
	var rec []recorded
	resp := `{"sha":"` + commit + `","tree":{"sha":"` + sha40 + `"},"parents":[{"sha":"` + parent + `"}],"message":"fix: bump\n"}`
	w := newWriterTest(t, recorder(201, resp, &rec), tok)
	sha, err := w.CreateCommit(context.Background(), "example/app", "fix: bump", sha40, []string{parent})
	if err != nil || sha != commit {
		t.Fatalf("CreateCommit = %q, %v", sha, err)
	}
	checkHeaders(t, rec[0], "POST", repoPath+"/git/commits")
	m := jsonBody(t, rec[0])
	if m["message"] != "fix: bump" || m["tree"] != sha40 || !reflect.DeepEqual(m["parents"], []any{parent}) {
		t.Errorf("body = %v", m)
	}

	rec = nil
	w = newWriterTest(t, recorder(200, resp, &rec), tok)
	info, err := w.Commit(context.Background(), "example/app", commit)
	if err != nil {
		t.Fatal(err)
	}
	if info.SHA != commit || info.Tree != sha40 || !reflect.DeepEqual(info.Parents, []string{parent}) || info.Message != "fix: bump\n" {
		t.Errorf("info = %+v", info)
	}
	checkHeaders(t, rec[0], "GET", repoPath+"/git/commits/"+commit)
	if _, err := w.Commit(context.Background(), "example/app", sha40); !errors.Is(err, ErrBadResponse) {
		t.Errorf("other sha: %v", err)
	}
}

func TestCreateCommitRejectsAnAnswerThatDoesNotMatch(t *testing.T) {
	const commit = "3333333333333333333333333333333333333333"
	w := newWriterTest(t, recorder(201, `{"sha":"`+commit+`","tree":{"sha":"`+commit+`"},"parents":[{"sha":"`+sha40+`"}]}`, new([]recorded)), Options{})
	_, err := w.CreateCommit(context.Background(), "example/app", "m", sha40, []string{sha40})
	if !errors.Is(err, ErrBadResponse) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("err = %v", err)
	}
}

func TestCreateCommitInvalidInput(t *testing.T) {
	var hits atomic.Int32
	w := newWriterTest(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), Options{})
	ctx := context.Background()
	for name, f := range map[string]func() error{
		"empty message": func() error { _, e := w.CreateCommit(ctx, "example/app", " \n", sha40, []string{sha40}); return e },
		"long message": func() error {
			_, e := w.CreateCommit(ctx, "example/app", strings.Repeat("x", maxCommitMessageBytes+1), sha40, []string{sha40})
			return e
		},
		"bad tree":   func() error { _, e := w.CreateCommit(ctx, "example/app", "m", "t", []string{sha40}); return e },
		"no parents": func() error { _, e := w.CreateCommit(ctx, "example/app", "m", sha40, nil); return e },
		"bad parent": func() error { _, e := w.CreateCommit(ctx, "example/app", "m", sha40, []string{"main"}); return e },
		"three": func() error {
			_, e := w.CreateCommit(ctx, "example/app", "m", sha40, []string{sha40, sha40, sha40})
			return e
		},
		"commit sha":   func() error { _, e := w.Commit(ctx, "example/app", "HEAD"); return e },
		"bad repo":     func() error { _, e := w.CreateCommit(ctx, "nope", "m", sha40, []string{sha40}); return e },
		"ref branch":   func() error { return w.CreateRef(ctx, "example/app", "a..b", sha40) },
		"ref sha":      func() error { return w.CreateRef(ctx, "example/app", "fix", "x") },
		"ref repo":     func() error { return w.CreateRef(ctx, "x", "fix", sha40) },
		"Ref branch":   func() error { _, _, e := w.Ref(ctx, "example/app", "-x"); return e },
		"pull zero":    func() error { _, e := w.Pull(ctx, "example/app", 0); return e },
		"close zero":   func() error { return w.ClosePull(ctx, "example/app", -1) },
		"comment zero": func() error { return w.CreateIssueComment(ctx, "example/app", 0, "x") },
		"comment body": func() error { return w.CreateIssueComment(ctx, "example/app", 1, " ") },
		"comment long": func() error { return w.CreateIssueComment(ctx, "example/app", 1, strings.Repeat("x", maxBodyChars+1)) },
		"pull title": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: "", Head: "a", Base: "main"})
			return e
		},
		"pull title nl": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: "a\nb", Head: "a", Base: "main"})
			return e
		},
		"pull title long": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: strings.Repeat("x", maxPullTitleChars+1), Head: "a", Base: "main"})
			return e
		},
		"pull body long": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: "t", Body: strings.Repeat("あ", maxBodyChars+1), Head: "a", Base: "main"})
			return e
		},
		"pull head": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: "t", Head: "a b", Base: "main"})
			return e
		},
		"pull head owner": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: "t", Head: "-o:b", Base: "main"})
			return e
		},
		"pull base": func() error {
			_, e := w.CreatePull(ctx, "example/app", NewPull{Title: "t", Head: "a", Base: ""})
			return e
		},
		"list state": func() error { _, _, e := w.ListPulls(ctx, "example/app", ListPullsOptions{State: "merged"}); return e },
		"list head":  func() error { _, _, e := w.ListPulls(ctx, "example/app", ListPullsOptions{Head: "branch"}); return e },
		"list base":  func() error { _, _, e := w.ListPulls(ctx, "example/app", ListPullsOptions{Base: "a..b"}); return e },
		"list per":   func() error { _, _, e := w.ListPulls(ctx, "example/app", ListPullsOptions{PerPage: 101}); return e },
		"list page":  func() error { _, _, e := w.ListPulls(ctx, "example/app", ListPullsOptions{Page: -1}); return e },
	} {
		if err := f(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("server hit %d times", hits.Load())
	}
}

func TestCreateRef(t *testing.T) {
	var rec []recorded
	w := newWriterTest(t, recorder(201, `{"ref":"refs/heads/kestrelynx/fix-1","object":{"type":"commit","sha":"`+sha40+`"}}`, &rec), tok)
	if err := w.CreateRef(context.Background(), "example/app", "kestrelynx/fix-1", sha40); err != nil {
		t.Fatal(err)
	}
	checkHeaders(t, rec[0], "POST", repoPath+"/git/refs")
	m := jsonBody(t, rec[0])
	if m["ref"] != "refs/heads/kestrelynx/fix-1" || m["sha"] != sha40 {
		t.Errorf("body = %v", m)
	}
}

func TestCreateRefExists(t *testing.T) {
	w := newWriterTest(t, recorder(422, `{"message":"Reference already exists","documentation_url":"x"}`, new([]recorded)), tok)
	err := w.CreateRef(context.Background(), "example/app", "fix", sha40)
	if !errors.Is(err, ErrRefExists) {
		t.Fatalf("err = %v, want ErrRefExists", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 422 {
		t.Errorf("StatusError = %v", se)
	}
	// Another 422 is not "exists".
	w = newWriterTest(t, recorder(422, `{"message":"Object does not exist"}`, new([]recorded)), tok)
	err = w.CreateRef(context.Background(), "example/app", "fix", sha40)
	if errors.Is(err, ErrRefExists) || !errors.As(err, &se) || se.Message != "Object does not exist" {
		t.Errorf("err = %v", err)
	}
}

func TestWriterHasNoRefMutation(t *testing.T) {
	// Refs are created only. The Writer must not grow a method that updates,
	// moves or deletes one, or merges a pull request.
	typ := reflect.TypeOf(&Writer{})
	for i := 0; i < typ.NumMethod(); i++ {
		n := strings.ToLower(typ.Method(i).Name)
		for _, bad := range []string{"delete", "update", "move", "force", "merge", "setref", "patch"} {
			if strings.Contains(n, bad) {
				t.Errorf("Writer has method %s", typ.Method(i).Name)
			}
		}
	}
}

func TestRefExactMatch(t *testing.T) {
	ref := func(name string) string {
		return `{"ref":"refs/heads/` + name + `","object":{"type":"commit","sha":"` + sha40 + `"}}`
	}
	cases := []struct {
		name      string
		status    int
		body      string
		wantFound bool
		wantErr   error
	}{
		{"exact", 200, ref("fix"), true, nil},
		{"not found", 404, `{"message":"Not Found"}`, false, nil},
		{"prefix list without it", 200, `[` + ref("fix-2") + `,` + ref("fix/x") + `]`, false, nil},
		{"prefix list with it", 200, `[` + ref("fix-2") + `,` + ref("fix") + `]`, true, nil},
		{"other object", 200, ref("fix-2"), false, ErrBadResponse},
		{"tag", 200, `{"ref":"refs/heads/fix","object":{"type":"tag","sha":"` + sha40 + `"}}`, false, ErrBadResponse},
		{"not json", 200, `x`, false, ErrBadResponse},
	}
	for _, tc := range cases {
		var rec []recorded
		w := newWriterTest(t, recorder(tc.status, tc.body, &rec), tok)
		sha, found, err := w.Ref(context.Background(), "example/app", "fix")
		if found != tc.wantFound || (tc.wantErr == nil) != (err == nil) || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
			t.Errorf("%s: sha %q found %v err %v", tc.name, sha, found, err)
		}
		if found && sha != sha40 {
			t.Errorf("%s: sha = %q", tc.name, sha)
		}
		if rec[0].method != "GET" || rec[0].path != repoPath+"/git/ref/heads/fix" {
			t.Errorf("%s: request %s %s", tc.name, rec[0].method, rec[0].path)
		}
	}
}

const pullJSON = `{"number":7,"state":"open","merged_at":null,"html_url":"https://github.com/example/app/pull/7","title":"Bump x","body":"b",
"head":{"ref":"kestrelynx/x","sha":"` + sha40 + `","repo":{"full_name":"example/app"}},"base":{"ref":"main","repo":{"id":42}},"user":{"login":"bot"}}`

func TestListPulls(t *testing.T) {
	merged := strings.Replace(pullJSON, `"merged_at":null`, `"merged_at":"2026-01-02T03:04:05Z"`, 1)
	merged = strings.Replace(merged, `"number":7`, `"number":8`, 1)
	merged = strings.Replace(merged, `"state":"open"`, `"state":"closed"`, 1)
	merged = strings.Replace(merged, `"repo":{"full_name":"example/app"}`, `"repo":null`, 1)
	merged = strings.Replace(merged, `"repo":{"id":42}`, `"repo":null`, 1)
	var rec []recorded
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec = append(rec, recorded{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization"),
			accept: r.Header.Get("Accept"), version: r.Header.Get("X-GitHub-Api-Version")})
		if r.URL.Query().Get("page") == "1" {
			w.Header().Add("Link", `<https://api.github.com/repositories/1/pulls?page=2>; rel="next", <https://api.github.com/repositories/1/pulls?page=3>; rel="last"`)
		} else {
			w.Header().Add("Link", `<https://api.github.com/repositories/1/pulls?page=1>; rel="prev", <https://api.github.com/repositories/1/pulls?page=1>; rel="first"`)
		}
		jsonResp(w, 200, `[`+pullJSON+`,`+merged+`]`)
	})
	w := newWriterTest(t, h, tok)
	pulls, next, err := w.ListPulls(context.Background(), "example/app", ListPullsOptions{State: "all", Head: "example:kestrelynx/x", Base: "main", Page: 1, PerPage: 50})
	if err != nil || !next || len(pulls) != 2 {
		t.Fatalf("pulls %d next %v err %v", len(pulls), next, err)
	}
	checkHeaders(t, rec[0], "GET", repoPath+"/pulls")
	if rec[0].query != "base=main&head=example%3Akestrelynx%2Fx&page=1&per_page=50&state=all" {
		t.Errorf("query = %s", rec[0].query)
	}
	want := PullRequest{Number: 7, State: "open", HTMLURL: "https://github.com/example/app/pull/7", Title: "Bump x", Body: "b",
		HeadRef: "kestrelynx/x", HeadSHA: sha40, HeadRepoFullName: "example/app", BaseRef: "main", BaseRepoID: 42, User: "bot"}
	if pulls[0] != want {
		t.Errorf("pull 0 = %+v", pulls[0])
	}
	if !pulls[1].Merged || pulls[1].State != "closed" || pulls[1].HeadRepoFullName != "" || pulls[1].BaseRepoID != 0 {
		t.Errorf("pull 1 = %+v", pulls[1])
	}
	_, next, err = w.ListPulls(context.Background(), "example/app", ListPullsOptions{Page: 2})
	if err != nil || next {
		t.Errorf("page 2: next %v err %v", next, err)
	}
	if rec[1].query != "page=2&per_page=30&state=open" {
		t.Errorf("default query = %s", rec[1].query)
	}
}

func TestLinkHasNext(t *testing.T) {
	for in, want := range map[string]bool{
		`<u>; rel="next"`:                  true,
		`<u>; rel="prev", <v>; rel="next"`: true,
		`<u>; rel="last"`:                  false,
		`<u>; rel="nextish"`:               false,
		``:                                 false,
		`garbage`:                          false,
	} {
		if got := linkHasNext([]string{in}); got != want {
			t.Errorf("%q = %v", in, got)
		}
	}
}

func TestListPullsRejectsMalformedPulls(t *testing.T) {
	for name, body := range map[string]string{
		"not array": `{}`,
		"zero":      `[` + strings.Replace(pullJSON, `"number":7`, `"number":0`, 1) + `]`,
		"state":     `[` + strings.Replace(pullJSON, `"state":"open"`, `"state":"weird"`, 1) + `]`,
		"http url":  `[` + strings.Replace(pullJSON, `https://github`, `http://github`, 1) + `]`,
		"head sha":  `[` + strings.Replace(pullJSON, sha40, "abc", 1) + `]`,
		"base repo": `[` + strings.Replace(pullJSON, `"repo":{"id":42}`, `"repo":{"id":-1}`, 1) + `]`,
	} {
		w := newWriterTest(t, recorder(200, body, new([]recorded)), Options{})
		if _, _, err := w.ListPulls(context.Background(), "example/app", ListPullsOptions{}); !errors.Is(err, ErrBadResponse) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPull(t *testing.T) {
	var rec []recorded
	w := newWriterTest(t, recorder(200, pullJSON, &rec), tok)
	pr, err := w.Pull(context.Background(), "example/app", 7)
	if err != nil || pr.Number != 7 || pr.HeadSHA != sha40 || pr.BaseRepoID != 42 || pr.HeadRepoFullName != "example/app" {
		t.Fatalf("Pull = %+v, %v", pr, err)
	}
	checkHeaders(t, rec[0], "GET", repoPath+"/pulls/7")
	if _, err := w.Pull(context.Background(), "example/app", 9); !errors.Is(err, ErrBadResponse) {
		t.Errorf("other number: %v", err)
	}
}

func TestCreatePull(t *testing.T) {
	var rec []recorded
	w := newWriterTest(t, recorder(201, pullJSON, &rec), tok)
	pr, err := w.CreatePull(context.Background(), "example/app", NewPull{Title: "Bump x", Body: "b", Head: "kestrelynx/x", Base: "main", MaintainerCanModify: true})
	if err != nil || pr.Number != 7 {
		t.Fatalf("CreatePull = %+v, %v", pr, err)
	}
	checkHeaders(t, rec[0], "POST", repoPath+"/pulls")
	m := jsonBody(t, rec[0])
	if m["title"] != "Bump x" || m["body"] != "b" || m["head"] != "kestrelynx/x" || m["base"] != "main" || m["maintainer_can_modify"] != true {
		t.Errorf("body = %v", m)
	}
	// A body of exactly 65536 characters is accepted.
	if _, err := w.CreatePull(context.Background(), "example/app", NewPull{Title: "t", Body: strings.Repeat("あ", maxBodyChars), Head: "fork:x", Base: "main"}); err != nil {
		t.Errorf("max body: %v", err)
	}
}

func TestClosePull(t *testing.T) {
	var rec []recorded
	w := newWriterTest(t, recorder(200, `{"number":7,"state":"closed"}`, &rec), tok)
	if err := w.ClosePull(context.Background(), "example/app", 7); err != nil {
		t.Fatal(err)
	}
	checkHeaders(t, rec[0], "PATCH", repoPath+"/pulls/7")
	if m := jsonBody(t, rec[0]); len(m) != 1 || m["state"] != "closed" {
		t.Errorf("body = %v", m)
	}
	w = newWriterTest(t, recorder(200, `{"number":7,"state":"open"}`, new([]recorded)), Options{})
	if err := w.ClosePull(context.Background(), "example/app", 7); !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("still open: %v", err)
	}
}

func TestCreateIssueComment(t *testing.T) {
	var rec []recorded
	w := newWriterTest(t, recorder(201, `{"id":99}`, &rec), tok)
	if err := w.CreateIssueComment(context.Background(), "example/app", 7, "hello"); err != nil {
		t.Fatal(err)
	}
	checkHeaders(t, rec[0], "POST", repoPath+"/issues/7/comments")
	if m := jsonBody(t, rec[0]); len(m) != 1 || m["body"] != "hello" {
		t.Errorf("body = %v", m)
	}
}

func TestListIssueComments(t *testing.T) {
	var rec []recorded
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec = append(rec, recorded{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization"),
			accept: r.Header.Get("Accept"), version: r.Header.Get("X-GitHub-Api-Version")})
		if r.URL.Query().Get("page") == "1" {
			w.Header().Add("Link", `<https://api.github.com/repositories/1/issues/7/comments?page=2>; rel="next"`)
		}
		jsonResp(w, 200, `[{"id":5,"body":"first","user":{"login":"bot"}},{"id":6,"body":null,"user":null}]`)
	})
	w := newWriterTest(t, h, tok)
	cs, next, err := w.ListIssueComments(context.Background(), "example/app", 7, 0)
	if err != nil || !next || len(cs) != 2 {
		t.Fatalf("comments %d next %v err %v", len(cs), next, err)
	}
	checkHeaders(t, rec[0], "GET", repoPath+"/issues/7/comments")
	if rec[0].query != "page=1&per_page=100" {
		t.Errorf("query = %s", rec[0].query)
	}
	if cs[0] != (IssueComment{ID: 5, Body: "first", User: "bot"}) || cs[1] != (IssueComment{ID: 6}) {
		t.Errorf("comments = %+v", cs)
	}
	if _, next, err := w.ListIssueComments(context.Background(), "example/app", 7, 2); err != nil || next {
		t.Errorf("page 2: next %v err %v", next, err)
	}
	if rec[1].query != "page=2&per_page=100" {
		t.Errorf("page 2 query = %s", rec[1].query)
	}
	for _, bad := range []struct {
		number, page int
	}{{0, 1}, {7, -1}} {
		if _, _, err := w.ListIssueComments(context.Background(), "example/app", bad.number, bad.page); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%+v: err = %v", bad, err)
		}
	}
	if len(rec) != 2 {
		t.Errorf("invalid input sent %d requests", len(rec)-2)
	}
}

func TestListIssueCommentsRejectsMalformedLists(t *testing.T) {
	for name, body := range map[string]string{
		"not array": `{}`,
		"zero id":   `[{"id":0,"body":"x"}]`,
	} {
		w := newWriterTest(t, recorder(200, body, new([]recorded)), Options{})
		if _, _, err := w.ListIssueComments(context.Background(), "example/app", 7, 1); !errors.Is(err, ErrBadResponse) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestWriteStatusErrors(t *testing.T) {
	reset := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	cases := []struct {
		name    string
		status  int
		headers map[string]string
		body    string
		want    error
		msg     string
	}{
		{"unauthorized", 401, nil, `{"message":"Bad credentials"}`, ErrAuthRequired, "Bad credentials"},
		{"forbidden", 403, nil, `{"message":"Resource not accessible by personal access token"}`, ErrForbidden, "Resource not accessible by personal access token"},
		{"not found", 404, nil, `{"message":"Not Found"}`, ErrNotFound, "Not Found"},
		{"validation", 422, nil, `{"message":"Validation Failed\nline"}`, nil, "Validation Failed line"},
		{"primary limit", 403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": fmt.Sprint(reset.Unix())}, `{}`, ErrRateLimited, ""},
		{"secondary limit", 403, nil, `{"message":"You have exceeded a secondary rate limit."}`, ErrRateLimited, ""},
		{"429", 429, map[string]string{"Retry-After": "60"}, `{}`, ErrRateLimited, ""},
		{"500", 500, nil, `{"message":"boom"}`, ErrOutcomeUnknown, "boom"},
		{"502 no body", 502, nil, `<html>`, ErrOutcomeUnknown, ""},
		{"echoed token", 422, nil, `{"message":"bad ` + token + `"}`, nil, "bad [redacted]"},
	}
	for _, tc := range cases {
		var hits atomic.Int32
		w := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			for k, v := range tc.headers {
				rw.Header().Set(k, v)
			}
			jsonResp(rw, tc.status, tc.body)
		}), tok)
		err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
			continue
		}
		if hits.Load() != 1 {
			t.Errorf("%s: %d requests", tc.name, hits.Load())
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("%s: error holds the token", tc.name)
		}
		var se *StatusError
		if tc.msg != "" {
			if !errors.As(err, &se) || se.Message != tc.msg || se.Status != tc.status {
				t.Errorf("%s: StatusError = %+v (err %v)", tc.name, se, err)
			}
		}
		if tc.want != ErrOutcomeUnknown && errors.Is(err, ErrOutcomeUnknown) {
			t.Errorf("%s: a refused write must not be outcome unknown", tc.name)
		}
		if tc.want == ErrRateLimited {
			var rl *RateLimitedError
			if !errors.As(err, &rl) {
				t.Errorf("%s: not a RateLimitedError", tc.name)
			}
		}
	}
}

func TestLongErrorMessageIsShortened(t *testing.T) {
	w := newWriterTest(t, recorder(422, `{"message":"`+strings.Repeat("x", 5000)+`"}`, new([]recorded)), Options{})
	err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	var se *StatusError
	if !errors.As(err, &se) || len(se.Message) > maxMessageLen+3 {
		t.Errorf("message length %d", len(se.Message))
	}
}

// dropper reads the request and closes the connection without answering.
func dropper(hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
}

func TestNoRetryOfAWriteThatFailsMidFlight(t *testing.T) {
	var hits atomic.Int32
	w := newWriterTest(t, dropper(&hits), tok)
	ctx := context.Background()
	calls := map[string]func() error{
		"POST":  func() error { return w.CreateIssueComment(ctx, "example/app", 1, "x") },
		"PATCH": func() error { return w.ClosePull(ctx, "example/app", 1) },
		"ref":   func() error { return w.CreateRef(ctx, "example/app", "fix", sha40) },
		"blob":  func() error { _, e := w.CreateBlob(ctx, "example/app", []byte("x")); return e },
	}
	n := int32(0)
	for name, f := range calls {
		err := f()
		n++
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Errorf("%s: err = %v, want ErrOutcomeUnknown", name, err)
		}
		if err != nil && strings.Contains(err.Error(), token) {
			t.Errorf("%s: error holds the token", name)
		}
		if hits.Load() != n {
			t.Fatalf("%s: server hits = %d, want %d", name, hits.Load(), n)
		}
	}
}

func TestWriteTimeoutAfterSendingIsOutcomeUnknown(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	w := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), Options{Timeout: 100 * time.Millisecond})
	err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d", hits.Load())
	}
}

func TestUnreadableSuccessIsOutcomeUnknown(t *testing.T) {
	w := newWriterTest(t, recorder(201, `not json`, new([]recorded)), Options{})
	err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}
	big := newWriterTest(t, recorder(201, `{"id":1,"pad":"`+strings.Repeat("x", 4096)+`"}`, new([]recorded)), Options{MaxListBytes: 1024})
	if err := big.CreateIssueComment(context.Background(), "example/app", 1, "x"); !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized: %v", err)
	}
}

func TestForbiddenAddressIsNotOutcomeUnknown(t *testing.T) {
	w := NewWriter(Options{Resolver: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.1")}, nil }})
	err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if !errors.Is(err, ErrForbiddenAddress) || errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("err = %v", err)
	}
}

func TestWritesDoNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	w := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(rw, r, "/elsewhere", http.StatusTemporaryRedirect)
	}), tok)
	err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if !errors.Is(err, ErrBadResponse) || errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d", hits.Load())
	}
}

func TestReadsOfTheWriterFollowTheClientRedirectPolicy(t *testing.T) {
	var paths []string
	w := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == repoPath {
			http.Redirect(rw, r, "/repositories/42", http.StatusMovedPermanently)
			return
		}
		jsonResp(rw, 200, `{"id":42,"full_name":"example/renamed","default_branch":"main"}`)
	}), Options{Budget: NewBudget(5)})
	info, err := w.Repository(context.Background(), "example/app")
	if err != nil || info.FullName != "example/renamed" || len(paths) != 2 {
		t.Errorf("info %+v err %v paths %v", info, err, paths)
	}
}

func TestWriterBudgetIsChargedPerRequest(t *testing.T) {
	var hits atomic.Int32
	b := NewBudget(3)
	w := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.Method {
		case "GET":
			jsonResp(rw, 200, pullJSON)
		case "PATCH":
			jsonResp(rw, 200, `{"number":7,"state":"closed"}`)
		default:
			jsonResp(rw, 201, `{"id":1}`)
		}
	}), Options{Budget: b})
	ctx := context.Background()
	if _, err := w.Pull(ctx, "example/app", 7); err != nil {
		t.Fatal(err)
	}
	if err := w.CreateIssueComment(ctx, "example/app", 7, "x"); err != nil {
		t.Fatal(err)
	}
	if err := w.ClosePull(ctx, "example/app", 7); err != nil {
		t.Fatal(err)
	}
	if b.Used() != 3 || b.Remaining() != 0 {
		t.Errorf("used %d remaining %d", b.Used(), b.Remaining())
	}
	if err := w.CreateIssueComment(ctx, "example/app", 7, "x"); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 3 {
		t.Errorf("hits = %d", hits.Load())
	}
}

func TestWriterTokenIsNeverPrinted(t *testing.T) {
	const secret = "ghp_writersecret0123456"
	w := NewWriter(Options{Token: Token(secret)})
	o := Options{Token: Token(secret)}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "writer", w, "opts", o)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "writer", w, "opts", o)
	outs := []string{buf.String()}
	for _, v := range []any{w, *w, o, &o} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
	}
	// Errors from a failing server never echo the token either.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jsonResp(rw, 422, `{"message":"bad `+secret+`"}`)
	}))
	defer srv.Close()
	w2 := NewWriter(Options{Token: Token(secret), HTTPClient: srv.Client(), AllowAddr: func(ip net.IP, _ string) bool { return ip.IsLoopback() }})
	w2.c.setBase(srv.URL)
	err := w2.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if err == nil {
		t.Fatal("want error")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		outs = append(outs, fmt.Sprintf(verb, err), fmt.Sprintf(verb, w2))
	}
	for _, out := range outs {
		if strings.Contains(out, secret) || strings.Contains(out, hex.EncodeToString([]byte(secret))) {
			t.Errorf("token printed: %.200s", out)
		}
	}
}

func TestWriterCannotBeMadeFromAClient(t *testing.T) {
	wt, ct := reflect.TypeOf(Writer{}), reflect.TypeOf(Client{})
	if ct.ConvertibleTo(wt) || wt.ConvertibleTo(ct) || ct.AssignableTo(wt) {
		t.Error("Client and Writer must be unrelated types")
	}
	// Client has no method that returns or exposes a Writer.
	pt := reflect.TypeOf(&Client{})
	for i := 0; i < pt.NumMethod(); i++ {
		m := pt.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			if o := m.Type.Out(j); o == reflect.TypeOf(&Writer{}) || o == wt {
				t.Errorf("Client.%s returns a Writer", m.Name)
			}
		}
	}
	// Writer fields are all unexported, so no other package can build one.
	for i := 0; i < wt.NumField(); i++ {
		if wt.Field(i).IsExported() {
			t.Errorf("Writer field %s is exported", wt.Field(i).Name)
		}
	}
}

func TestBlobOverTheFileCapIsNotSent(t *testing.T) {
	var hits atomic.Int32
	w := newWriterTest(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), Options{MaxFileBytes: 1})
	if _, err := w.CreateBlob(context.Background(), "example/app", []byte("ab")); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Error("request sent")
	}
}

// getBodySpy records whether any request reached the transport with a
// GetBody, which would let a transport replay the body.
type getBodySpy struct {
	next      http.RoundTripper
	requests  atomic.Int32
	withRetry atomic.Int32
}

func (s *getBodySpy) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		s.requests.Add(1)
		if r.GetBody != nil {
			s.withRetry.Add(1)
		}
	}
	return s.next.RoundTrip(r)
}

func TestWritesCarryNoGetBody(t *testing.T) {
	w := newWriterTest(t, recorder(201, `{"id":1}`, new([]recorded)), Options{})
	spy := &getBodySpy{next: w.wh.Transport}
	w.wh.Transport = spy
	if err := w.CreateIssueComment(context.Background(), "example/app", 1, "x"); err != nil {
		t.Fatal(err)
	}
	if spy.requests.Load() != 1 || spy.withRetry.Load() != 0 {
		t.Errorf("write requests %d, with GetBody %d", spy.requests.Load(), spy.withRetry.Load())
	}
}

// A real REFUSED_STREAM, which is what makes the HTTP/2 transport replay a
// request that has a GetBody, cannot be produced by the standard library
// server. This test aborts the stream after the body was read and checks the
// write is sent once and reported as unknown; TestWritesCarryNoGetBody covers
// the property that rules out the replay (net/http's HTTP/2 retry path gives
// up when Request.GetBody is nil and the body has been written).
func TestHTTP2ResetAfterTheBodyIsNotReplayed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		panic(http.ErrAbortHandler)
	}))
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	w := NewWriter(Options{HTTPClient: srv.Client(), AllowAddr: func(ip net.IP, _ string) bool { return ip.IsLoopback() }})
	w.c.setBase(srv.URL)
	err := w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("server saw %d requests", hits.Load())
	}
}

func allVerbs(v any) []string {
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out = append(out, fmt.Sprintf(verb, v))
	}
	return out
}

func TestResponseValuesNeverLeakTheToken(t *testing.T) {
	ctx := context.Background()
	check := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: want an error", name)
			return
		}
		for _, out := range allVerbs(err) {
			if strings.Contains(out, token) {
				t.Errorf("%s: token in %.200s", name, out)
			}
		}
	}
	// Returned SHAs that are the token.
	bad := func(body string) *Writer { return newWriterTest(t, recorder(201, body, new([]recorded)), tok) }
	_, err := bad(`{"sha":"`+token+`"}`).CreateBlob(ctx, "example/app", []byte("x"))
	check("blob", err)
	_, err = bad(`{"sha":"`+token+`"}`).CreateTree(ctx, "example/app", sha40, []TreeEntry{{Path: "a", Mode: "100644", BlobSHA: sha40}})
	check("tree", err)
	_, err = bad(`{"sha":"`+token+`","tree":{"sha":"`+token+`"},"parents":[]}`).CreateCommit(ctx, "example/app", "m", sha40, []string{sha40})
	check("commit", err)
	check("ref", bad(`{"ref":"`+token+`","object":{"sha":"`+token+`"}}`).CreateRef(ctx, "example/app", "fix", sha40))
	_, err = bad(strings.Replace(pullJSON, sha40, token, 1)).CreatePull(ctx, "example/app", NewPull{Title: "t", Head: "a", Base: "main"})
	check("pull", err)
	rd := newWriterTest(t, recorder(200, `{"sha":"`+token+`","tree":{"sha":"`+token+`"}}`, new([]recorded)), tok)
	_, err = rd.Commit(ctx, "example/app", sha40)
	check("commit read", err)
	_, _, err = newWriterTest(t, recorder(200, `{"ref":"refs/heads/`+token+`"}`, new([]recorded)), tok).Ref(ctx, "example/app", "fix")
	check("ref read", err)

	// A Location header holding the token breaks the redirect on a read
	// (which follows redirects) and is refused on a write.
	loc := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Location", "http://[::1 "+token)
		rw.WriteHeader(http.StatusFound)
	}), tok)
	_, err = loc.Repository(ctx, "example/app")
	check("location read", err)
	check("location write", loc.CreateIssueComment(ctx, "example/app", 1, "x"))
}

func TestRedactKeepsTheChain(t *testing.T) {
	c := New(Options{Token: Token(token)})
	inner := fmt.Errorf("%w: x %s", ErrBadResponse, token)
	err := c.redact(inner)
	if strings.Contains(err.Error(), token) || !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}
	if c.redact(ErrNotFound) != ErrNotFound || c.redact(nil) != nil {
		t.Error("clean errors must pass through unchanged")
	}
}

func TestResponseValidationFailuresAfterSuccessAreOutcomeUnknown(t *testing.T) {
	ctx := context.Background()
	w := func(body string) *Writer { return newWriterTest(t, recorder(201, body, new([]recorded)), Options{}) }
	cases := map[string]struct {
		err  error
		also error
	}{}
	_, e := w(`{"sha":"`+sha40+`"}`).CreateBlob(ctx, "example/app", []byte("x"))
	cases["blob mismatch"] = struct{ err, also error }{e, ErrHashMismatch}
	_, e = w(`{}`).CreateBlob(ctx, "example/app", []byte("x"))
	cases["blob missing"] = struct{ err, also error }{e, ErrHashMismatch}
	_, e = w(`{"sha":"x"}`).CreateTree(ctx, "example/app", sha40, []TreeEntry{{Path: "a", Mode: "100644", BlobSHA: sha40}})
	cases["tree"] = struct{ err, also error }{e, ErrBadResponse}
	_, e = w(`{"sha":"x"}`).CreateCommit(ctx, "example/app", "m", sha40, []string{sha40})
	cases["commit"] = struct{ err, also error }{e, ErrBadResponse}
	e = w(`{}`).CreateRef(ctx, "example/app", "fix", sha40)
	cases["ref"] = struct{ err, also error }{e, ErrBadResponse}
	_, e = w(`{}`).CreatePull(ctx, "example/app", NewPull{Title: "t", Head: "a", Base: "main"})
	cases["pull"] = struct{ err, also error }{e, ErrBadResponse}
	e = w(`{"number":1,"state":"open"}`).ClosePull(ctx, "example/app", 1)
	cases["close"] = struct{ err, also error }{e, ErrBadResponse}
	e = w(`{}`).CreateIssueComment(ctx, "example/app", 1, "x")
	cases["comment"] = struct{ err, also error }{e, ErrBadResponse}
	e = w(`null`).CreateIssueComment(ctx, "example/app", 1, "x")
	cases["comment null"] = struct{ err, also error }{e, ErrBadResponse}
	for name, c := range cases {
		if !errors.Is(c.err, ErrOutcomeUnknown) || !errors.Is(c.err, c.also) {
			t.Errorf("%s: err = %v", name, c.err)
		}
	}
}

func TestListsRequireAJSONArray(t *testing.T) {
	ctx := context.Background()
	for _, body := range []string{`null`, `{}`, `"x"`, `7`, ``} {
		w := newWriterTest(t, recorder(200, body, new([]recorded)), Options{})
		if _, _, err := w.ListPulls(ctx, "example/app", ListPullsOptions{}); !errors.Is(err, ErrBadResponse) {
			t.Errorf("pulls %q: err = %v", body, err)
		}
		if _, _, err := w.ListIssueComments(ctx, "example/app", 1, 1); !errors.Is(err, ErrBadResponse) {
			t.Errorf("comments %q: err = %v", body, err)
		}
	}
	w := newWriterTest(t, recorder(200, ` []`, new([]recorded)), Options{})
	if p, next, err := w.ListPulls(ctx, "example/app", ListPullsOptions{}); err != nil || next || len(p) != 0 {
		t.Errorf("empty array: %v %v %v", p, next, err)
	}
}
