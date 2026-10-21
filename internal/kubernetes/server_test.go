package kubernetes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// scriptedResponse is one canned HTTP response a fakeServer path can be
// programmed to return.
type scriptedResponse struct {
	status int
	header http.Header
	body   []byte
}

func ok(body []byte) scriptedResponse {
	return scriptedResponse{status: http.StatusOK, body: body}
}

// fakeServer is a minimal scriptable stand-in for kube-apiserver. Each path
// (matched on r.URL.Path, ignoring the query string) is given a queue of
// scriptedResponse values consumed one per request; once a path's queue is
// exhausted (or was never set), it falls back to an empty list envelope.
// onFunc paths take priority over scripted ones, for tests that need
// request-triggered side effects (token rotation).
type fakeServer struct {
	t *testing.T

	mu       sync.Mutex
	scripts  map[string][]scriptedResponse
	handlers map[string]http.HandlerFunc
	requests []string // r.URL.String() in request order, across every path
	methods  []string // r.Method of each request, in the same order
}

func newFakeServer(t *testing.T) *fakeServer {
	return &fakeServer{
		t:        t,
		scripts:  map[string][]scriptedResponse{},
		handlers: map[string]http.HandlerFunc{},
	}
}

// on scripts responses (consumed in order) for exact path.
func (f *fakeServer) on(path string, responses ...scriptedResponse) {
	f.scripts[path] = responses
}

// onFunc registers a custom handler for exact path, taking priority over on.
func (f *fakeServer) onFunc(path string, h http.HandlerFunc) {
	f.handlers[path] = h
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.String())
	f.methods = append(f.methods, r.Method)
	h := f.handlers[r.URL.Path]
	f.mu.Unlock()

	if h != nil {
		h(w, r)
		return
	}

	f.mu.Lock()
	var resp scriptedResponse
	if q := f.scripts[r.URL.Path]; len(q) > 0 {
		resp = q[0]
		f.scripts[r.URL.Path] = q[1:]
	} else {
		resp = ok(envelope(""))
	}
	f.mu.Unlock()

	for k, vs := range resp.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if resp.status == 0 {
		resp.status = http.StatusOK
	}
	w.WriteHeader(resp.status)
	w.Write(resp.body)
}

func (f *fakeServer) start() *httptest.Server {
	srv := httptest.NewServer(f)
	f.t.Cleanup(srv.Close)
	return srv
}

// requestedPathPrefix reports whether any recorded request's path+query
// starts with prefix.
func (f *fakeServer) requestedPathPrefix(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if len(r) >= len(prefix) && r[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// envelope builds a well-formed Kubernetes List response body: Kind and
// APIVersion are filled with placeholder-but-valid values (the production
// code only checks Kind ends in "List" and APIVersion is non-empty, never
// which resource they name) so every test gets a body that passes
// validateListEnvelope without each call site having to know which resource
// it's faking.
func envelope(continueToken string, items ...json.RawMessage) []byte {
	type meta struct {
		Continue string `json:"continue"`
	}
	type env struct {
		Kind       string            `json:"kind"`
		APIVersion string            `json:"apiVersion"`
		Metadata   meta              `json:"metadata"`
		Items      []json.RawMessage `json:"items"`
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	b, err := json.Marshal(env{
		Kind:       "FakeList",
		APIVersion: "v1",
		Metadata:   meta{Continue: continueToken},
		Items:      items,
	})
	if err != nil {
		panic(err) // test fixture construction only; a marshal failure here is a test bug.
	}
	return b
}

// loadFixture reads a hand-written JSON fixture from testdata/.
func loadFixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return json.RawMessage(b)
}

// repeatedServerErrors builds n identical 500 responses, enough to exhaust
// getWithRetry's retry budget regardless of maxRetries' exact value.
func repeatedServerErrors(n int) []scriptedResponse {
	rs := make([]scriptedResponse, n)
	for i := range rs {
		rs[i] = scriptedResponse{status: http.StatusInternalServerError, body: []byte("boom")}
	}
	return rs
}

// newTestClient builds a Client pointed at srv, with a real (temp-file)
// token so 401-retry tests can rewrite it mid-test.
func newTestClient(t *testing.T, srv *httptest.Server, namespaces []string) *Client {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return newClient(srv.URL, srv.Client(), tokenPath, namespaces)
}
