package toolfetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRegistry serves npm and PyPI documents and files over TLS.
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	// docs maps a request path (decoded) to a handler; hits counts requests.
	routes map[string]http.HandlerFunc
	hits   map[string]int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{t: t, routes: map[string]http.HandlerFunc{}, hits: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		h := f.routes[r.URL.Path]
		f.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeRegistry) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.hits {
		n += c
	}
	return n
}

func (f *fakeRegistry) handle(path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = h
}

func (f *fakeRegistry) serveBytes(path string, data []byte) {
	f.handle(path, func(w http.ResponseWriter, r *http.Request) { w.Write(data) })
}

func (f *fakeRegistry) serveJSON(path string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	f.handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
}

// npmPkg describes a fake npm package version.
type npmPkg struct {
	name, version string
	files         map[string]string // path inside the tarball without package/
	engines       string
	published     time.Time
	badIntegrity  bool
	noTime        bool
}

func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func sha512b64(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

func hexOf(algo string, b []byte) string {
	h := newHash(algo)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// addNpm registers the version document, the packument and the tarball and
// returns the tarball bytes.
func (f *fakeRegistry) addNpm(p npmPkg) []byte {
	f.t.Helper()
	files := map[string]string{}
	for k, v := range p.files {
		files["package/"+k] = v
	}
	body := tgz(f.t, files)
	return f.addNpmBytes(p, body)
}

func (f *fakeRegistry) addNpmBytes(p npmPkg, body []byte) []byte {
	f.t.Helper()
	tb := "/-/" + strings.ReplaceAll(p.name, "/", "_") + "-" + p.version + ".tgz"
	integ := sha512b64(body)
	if p.badIntegrity {
		integ = sha512b64([]byte("something else"))
	}
	doc := map[string]any{
		"name": p.name, "version": p.version,
		"dist": map[string]any{"tarball": f.srv.URL + tb, "integrity": integ},
	}
	if p.engines != "" {
		doc["engines"] = map[string]string{"node": p.engines}
	}
	f.serveJSON("/"+p.name+"/"+p.version, doc)
	f.addTime(p)
	f.serveBytes(tb, body)
	return body
}

// packTimes keeps the packument times per registry and package, so that
// several versions of one package share one packument.
var packTimes sync.Map

func (f *fakeRegistry) addTime(p npmPkg) {
	key := fmt.Sprintf("%p/%s", f, p.name)
	v, _ := packTimes.LoadOrStore(key, map[string]string{})
	m := v.(map[string]string)
	f.mu.Lock()
	if !p.noTime {
		m[p.version] = p.published.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	f.mu.Unlock()
	f.serveJSON("/"+p.name, map[string]any{"name": p.name, "time": m})
}

func wheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

// addUv registers uv's PyPI document with one wheel file per given name.
func (f *fakeRegistry) addUv(version string, published time.Time, wheels map[string][]byte) {
	f.t.Helper()
	var urls []map[string]any
	for name, body := range wheels {
		path := "/files/" + name
		sum := sha256.Sum256(body)
		urls = append(urls, map[string]any{
			"filename": name, "url": f.srv.URL + path, "size": len(body), "yanked": false,
			"packagetype": "bdist_wheel", "upload_time_iso_8601": published.UTC().Format("2006-01-02T15:04:05.000000Z"),
			"digests": map[string]string{"sha256": hex.EncodeToString(sum[:])},
		})
		f.serveBytes(path, body)
	}
	f.serveJSON("/pypi/uv/"+version+"/json", map[string]any{"info": map[string]any{"name": "uv", "version": version}, "urls": urls})
}

// provider returns a Provider that talks to the fake registry.
func (f *fakeRegistry) provider(t *testing.T, dir string, mod func(*Config)) *Provider {
	t.Helper()
	cfg := Config{StorageDir: dir, Transport: f.srv.Client().Transport, MinReleaseAge: 72 * time.Hour}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.srv.URL)
	p.net.policy = netPolicy{hosts: map[string]bool{u.Hostname(): true}, port: u.Port()}
	p.npmBase, p.pypi = f.srv.URL, f.srv.URL
	return p
}

var old = time.Now().Add(-30 * 24 * time.Hour)

func wantErr(t *testing.T, err error, class Class, code Code) *Error {
	t.Helper()
	var e *Error
	if err == nil {
		t.Fatalf("want %s/%s, got no error", class, code)
	}
	var ok bool
	if e, ok = err.(*Error); !ok {
		t.Fatalf("want *Error, got %T %v", err, err)
	}
	if e.Class != class || e.Code != code {
		t.Fatalf("want %s/%s, got %s/%s: %s", class, code, e.Class, e.Code, e.Detail)
	}
	return e
}

// tgzWithLink is a tarball that holds the entry and a symbolic link.
func tgzWithLink(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "package/bin/npm-cli.js", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	tw.WriteHeader(&tar.Header{Name: "package/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.Close()
	zw.Close()
	return buf.Bytes()
}
