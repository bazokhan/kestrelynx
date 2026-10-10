package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

const testToken = "tok-secret-123"

func sha(body string) string {
	s := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(s[:])
}

// fakeRegistry is a TLS registry that demands a Bearer token from its own
// /token endpoint and serves canned content at /v2/... paths.
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	tokenHits   int
	tokenQuery  []string
	requests    []string
	routes      map[string]func(w http.ResponseWriter, r *http.Request)
	rejectToken bool   // keep answering 401 even with a token
	tokenBody   string // override the token response
	noAuth      bool   // serve without demanding a token
	challenge   string // override WWW-Authenticate
	tokenTTL    int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{t: t, routes: map[string]func(http.ResponseWriter, *http.Request){}, tokenTTL: 300}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) host() string { return f.srv.Listener.Addr().String() }

func (f *fakeRegistry) repo(path string) string { return f.host() + "/" + path }

func (f *fakeRegistry) port() string {
	_, p, _ := net.SplitHostPort(f.host())
	return p
}

// client builds a client that may reach this fake registry's address (and
// nothing else on loopback) unless the options set their own policy.
func (f *fakeRegistry) client(o Options) *Client {
	o.HTTPClient = f.srv.Client()
	if o.AllowAddr == nil {
		o.AllowAddr = func(ip net.IP, port string) bool { return ip.IsLoopback() && port == f.port() }
	}
	return New(o)
}

func (f *fakeRegistry) hits() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.RequestURI())
	f.mu.Unlock()
	if r.URL.Path == "/token" {
		f.mu.Lock()
		f.tokenHits++
		f.tokenQuery = append(f.tokenQuery, r.URL.RawQuery)
		body := f.tokenBody
		ttl := f.tokenTTL
		f.mu.Unlock()
		if body == "" {
			body = fmt.Sprintf(`{"token":%q,"expires_in":%d}`, testToken, ttl)
		}
		fmt.Fprint(w, body)
		return
	}
	if !f.noAuth && (f.rejectToken || r.Header.Get("Authorization") != "Bearer "+testToken) {
		ch := f.challenge
		if ch == "" {
			ch = fmt.Sprintf(`Bearer realm="https://%s/token",service="test-registry"`, f.host())
		}
		w.Header().Set("WWW-Authenticate", ch)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	h := f.routes[r.URL.Path]
	f.mu.Unlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func (f *fakeRegistry) route(path string, h func(http.ResponseWriter, *http.Request)) {
	f.mu.Lock()
	f.routes[path] = h
	f.mu.Unlock()
}

// serveManifest registers body at /v2/<repo>/manifests/<ref> for each ref.
func (f *fakeRegistry) serveManifest(repo, mediaType, body string, refs ...string) {
	for _, ref := range refs {
		f.route("/v2/"+repo+"/manifests/"+ref, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", mediaType)
			w.Header().Set("Docker-Content-Digest", sha(body))
			fmt.Fprint(w, body)
		})
	}
}

// serveConfig registers an image config blob for the platform and returns
// its digest.
func (f *fakeRegistry) serveConfig(repo, os, arch, variant string) string {
	body := fmt.Sprintf(`{"os":%q,"architecture":%q,"variant":%q,"rootfs":{}}`, os, arch, variant)
	d := sha(body)
	f.route("/v2/"+repo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.config.v1+json")
		fmt.Fprint(w, body)
	})
	return d
}

var linuxAMD64 = inventory.Platform{OS: "linux", Architecture: "amd64"}

// imageFixture registers an index with the given platform entries and one
// image manifest per entry, returning the index body, per-platform manifest
// digests and config digests.
type fixture struct {
	indexBody   string
	indexDigest string
	manifest    map[string]string // platform key -> manifest digest
	config      map[string]string // platform key -> config digest
}

func (f *fakeRegistry) serveIndex(repo, indexMedia, manifestMedia string, platforms ...inventory.Platform) fixture {
	fx := fixture{manifest: map[string]string{}, config: map[string]string{}}
	var entries []string
	for _, p := range platforms {
		key := p.OS + "/" + p.Architecture + "/" + p.Variant
		cfg := f.serveConfig(repo, p.OS, p.Architecture, p.Variant)
		mbody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q,"size":10},"layers":[]}`, manifestMedia, cfg)
		md := sha(mbody)
		f.serveManifest(repo, manifestMedia, mbody, md)
		fx.manifest[key] = md
		fx.config[key] = cfg
		variant := ""
		if p.Variant != "" {
			variant = fmt.Sprintf(`,"variant":%q`, p.Variant)
		}
		entries = append(entries, fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":1,"platform":{"os":%q,"architecture":%q%s}}`, manifestMedia, md, p.OS, p.Architecture, variant))
	}
	// An attestation entry must never be picked.
	entries = append(entries, fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":1,"platform":{"os":"unknown","architecture":"unknown"}}`, manifestMedia, sha("att")))
	fx.indexBody = fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[%s]}`, indexMedia, strings.Join(entries, ","))
	fx.indexDigest = sha(fx.indexBody)
	f.serveManifest(repo, indexMedia, fx.indexBody, "latest", fx.indexDigest)
	return fx
}

func TestEndpoint(t *testing.T) {
	cases := []struct{ repo, host, path string }{
		{"nginx", "registry-1.docker.io", "library/nginx"},
		{"docker.io/nginx", "registry-1.docker.io", "library/nginx"},
		{"docker.io/library/nginx", "registry-1.docker.io", "library/nginx"},
		{"index.docker.io/bitnami/redis", "registry-1.docker.io", "bitnami/redis"},
		{"bitnami/redis", "registry-1.docker.io", "bitnami/redis"},
		{"ghcr.io/org/app", "ghcr.io", "org/app"},
		{"quay.io/a/b/c", "quay.io", "a/b/c"},
		{"registry.example.com:5000/x", "registry.example.com:5000", "x"},
	}
	for _, tc := range cases {
		host, path, err := Endpoint(tc.repo)
		if err != nil || host != tc.host || path != tc.path {
			t.Errorf("Endpoint(%q) = %q, %q, %v; want %q, %q", tc.repo, host, path, err, tc.host, tc.path)
		}
	}
	for _, bad := range []string{"", "sha256:" + strings.Repeat("a", 64), "UPPER/case", "a b"} {
		if _, _, err := Endpoint(bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Endpoint(%q) err = %v, want ErrInvalidInput", bad, err)
		}
	}
}

func TestTokenFlowAndCache(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"team/app","tags":["1.0","1.1"]}`)
	})
	c := f.client(Options{})
	for i := 0; i < 2; i++ {
		tl, err := c.ListTags(context.Background(), f.repo("team/app"))
		if err != nil {
			t.Fatal(err)
		}
		if len(tl.Tags) != 2 || tl.Truncated {
			t.Fatalf("tags = %+v", tl)
		}
	}
	if f.tokenHits != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (cached)", f.tokenHits)
	}
	q := f.tokenQuery[0]
	if !strings.Contains(q, "scope=repository%3Ateam%2Fapp%3Apull") || !strings.Contains(q, "service=test-registry") {
		t.Errorf("token query = %q", q)
	}
}

func TestTokenExpiryRefetches(t *testing.T) {
	f := newFakeRegistry(t)
	f.tokenTTL = 100
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":[]}`) })
	now := time.Unix(1_000_000, 0)
	c := f.client(Options{Now: func() time.Time { return now }})
	if _, err := c.ListTags(context.Background(), f.repo("team/app")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(60 * time.Second) // within ttl minus skew
	if _, err := c.ListTags(context.Background(), f.repo("team/app")); err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 1 {
		t.Fatalf("token hits = %d before expiry, want 1", f.tokenHits)
	}
	now = now.Add(60 * time.Second) // past ttl
	if _, err := c.ListTags(context.Background(), f.repo("team/app")); err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 2 {
		t.Errorf("token hits = %d after expiry, want 2", f.tokenHits)
	}
}

func TestTokenAccessTokenFieldAccepted(t *testing.T) {
	f := newFakeRegistry(t)
	f.tokenBody = fmt.Sprintf(`{"access_token":%q}`, testToken)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":["a"]}`) })
	if _, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app")); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRequiredAfterToken_NoTokenInError(t *testing.T) {
	f := newFakeRegistry(t)
	f.rejectToken = true
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/private"))
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("err = %v, want ErrAuthRequired", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the token: %v", err)
	}
	if f.tokenHits != 1 {
		t.Errorf("token hits = %d, want exactly one anonymous attempt", f.tokenHits)
	}
}

func TestAuthRequired_ForbiddenAndNonBearer(t *testing.T) {
	f := newFakeRegistry(t)
	f.noAuth = true
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	if _, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app")); !errors.Is(err, ErrAuthRequired) {
		t.Errorf("403: err = %v", err)
	}

	g := newFakeRegistry(t)
	g.challenge = `Basic realm="registry"`
	if _, err := g.client(Options{}).ListTags(context.Background(), g.repo("team/app")); !errors.Is(err, ErrAuthRequired) {
		t.Errorf("Basic challenge: err = %v", err)
	}
	if g.tokenHits != 0 {
		t.Error("a Basic challenge must not trigger a token request")
	}
}

func TestTokenRealmMustBeHTTPS(t *testing.T) {
	f := newFakeRegistry(t)
	f.challenge = `Bearer realm="http://127.0.0.1:1/token",service="x"`
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v, want ErrBadResponse", err)
	}
}

func TestNotFound(t *testing.T) {
	f := newFakeRegistry(t)
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/missing"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func tagPage(tags []string, next string, w http.ResponseWriter) {
	if next != "" {
		w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, next))
	}
	quoted := make([]string, len(tags))
	for i, t := range tags {
		quoted[i] = fmt.Sprintf("%q", t)
	}
	fmt.Fprintf(w, `{"name":"x","tags":[%s]}`, strings.Join(quoted, ","))
}

func TestListTags_PaginationAndTruncation(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("last") {
		case "":
			if r.URL.Query().Get("n") != "2" {
				t.Errorf("first page n = %q, want 2", r.URL.Query().Get("n"))
			}
			tagPage([]string{"1", "2"}, "/v2/team/app/tags/list?last=2&n=2", w)
		case "2":
			tagPage([]string{"3", "4"}, "/v2/team/app/tags/list?last=4&n=2", w)
		case "4":
			tagPage([]string{"5"}, "", w)
		}
	})
	full, err := f.client(Options{TagPageSize: 2}).ListTags(context.Background(), f.repo("team/app"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(full.Tags, ",") != "1,2,3,4,5" || full.Truncated || full.Pages != 3 {
		t.Errorf("full = %+v", full)
	}

	cut, err := f.client(Options{TagPageSize: 2, MaxTagPages: 2}).ListTags(context.Background(), f.repo("team/app"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cut.Tags, ",") != "1,2,3,4" || !cut.Truncated || cut.Pages != 2 {
		t.Errorf("cut = %+v", cut)
	}

	// Ending exactly at the page limit is complete, not truncated.
	exact, err := f.client(Options{TagPageSize: 2, MaxTagPages: 3}).ListTags(context.Background(), f.repo("team/app"))
	if err != nil || exact.Truncated || len(exact.Tags) != 5 {
		t.Errorf("exact = %+v, %v", exact, err)
	}
}

func TestListTags_LinkToOtherHostRejected(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		tagPage([]string{"1"}, "https://evil.example.com/v2/team/app/tags/list?last=1", w)
	})
	tl, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if !errors.Is(err, ErrBadResponse) || tl.Tags != nil {
		t.Errorf("tl=%+v err=%v; want ErrBadResponse and no partial list", tl, err)
	}
}

func TestListTags_ErrorMidwayDiscardsPartial(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("last") == "" {
			tagPage([]string{"1"}, "/v2/team/app/tags/list?last=1", w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	tl, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 500 || tl.Tags != nil {
		t.Errorf("tl=%+v err=%v", tl, err)
	}
	if tl.Pages != 2 {
		t.Errorf("pages = %d, want the 2 requests that were sent", tl.Pages)
	}
}

func TestListTagsUpTo_PerCallAllowance(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("last") {
		case "":
			tagPage([]string{"1", "2"}, "/v2/team/app/tags/list?last=2&n=2", w)
		case "2":
			tagPage([]string{"3", "4"}, "/v2/team/app/tags/list?last=4&n=2", w)
		case "4":
			tagPage([]string{"5"}, "", w)
		}
	})
	c := f.client(Options{TagPageSize: 2})
	cut, err := c.ListTagsUpTo(context.Background(), f.repo("team/app"), 1)
	if err != nil || !cut.Truncated || cut.Pages != 1 || len(cut.Tags) != 2 {
		t.Errorf("allowance of 1: %+v, %v", cut, err)
	}
	// An allowance above the client's own limit does not raise it.
	g := f.client(Options{TagPageSize: 2, MaxTagPages: 2})
	cut, err = g.ListTagsUpTo(context.Background(), f.repo("team/app"), 10)
	if err != nil || !cut.Truncated || cut.Pages != 2 {
		t.Errorf("allowance above limit: %+v, %v", cut, err)
	}
	full, err := c.ListTagsUpTo(context.Background(), f.repo("team/app"), 3)
	if err != nil || full.Truncated || full.Pages != 3 || len(full.Tags) != 5 {
		t.Errorf("allowance of 3: %+v, %v", full, err)
	}
}

func TestResolve_OCIIndex(t *testing.T) {
	f := newFakeRegistry(t)
	arm := inventory.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	fx := f.serveIndex("team/app", mediaOCIIndex, mediaOCIManifest, linuxAMD64, arm)
	c := f.client(Options{})

	got, err := c.Resolve(context.Background(), f.repo("team/app"), "latest", linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	want := Resolution{
		TopDigest: fx.indexDigest, TopMediaType: mediaOCIIndex,
		ManifestDigest: fx.manifest["linux/amd64/"], ConfigDigest: fx.config["linux/amd64/"],
		PlatformVerified: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}

	// A variant is never matched, whether requested or found on the entry.
	_, err = c.Resolve(context.Background(), f.repo("team/app"), "latest", arm)
	var ve *VariantError
	if !errors.Is(err, ErrVariantUnsupported) || !errors.As(err, &ve) || ve.Requested != "v8" {
		t.Errorf("requested variant: err = %v", err)
	}
	_, err = c.Resolve(context.Background(), f.repo("team/app"), "latest", inventory.Platform{OS: "linux", Architecture: "arm64"})
	if !errors.Is(err, ErrVariantUnsupported) || !errors.As(err, &ve) || ve.Observed != "v8" {
		t.Errorf("entry variant: err = %v", err)
	}
	// By digest works and is verified.
	got, err = c.Resolve(context.Background(), f.repo("team/app"), fx.indexDigest, linuxAMD64)
	if err != nil || got.TopDigest != fx.indexDigest {
		t.Errorf("by digest: %+v, %v", got, err)
	}
}

func TestResolve_DockerManifestListAndSchema2(t *testing.T) {
	f := newFakeRegistry(t)
	fx := f.serveIndex("team/app", mediaDockerList, mediaDockerV2, linuxAMD64)
	got, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "latest", linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if got.TopMediaType != mediaDockerList || got.ConfigDigest != fx.config["linux/amd64/"] {
		t.Errorf("got %+v", got)
	}
}

func TestResolve_SingleManifest(t *testing.T) {
	for _, media := range []string{mediaOCIManifest, mediaDockerV2} {
		f := newFakeRegistry(t)
		cfg := f.serveConfig("team/app", "linux", "amd64", "")
		body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q,"size":3},"layers":[]}`, media, cfg)
		f.serveManifest("team/app", media, body, "v1")
		got, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if err != nil {
			t.Fatal(err)
		}
		if got.TopDigest != sha(body) || got.ManifestDigest != got.TopDigest || got.ConfigDigest != cfg || !got.PlatformVerified {
			t.Errorf("%s: got %+v", media, got)
		}
	}
}

func TestResolve_PlatformErrors(t *testing.T) {
	f := newFakeRegistry(t)
	f.serveIndex("team/app", mediaOCIIndex, mediaOCIManifest, linuxAMD64,
		inventory.Platform{OS: "linux", Architecture: "arm", Variant: "v6"},
		inventory.Platform{OS: "linux", Architecture: "arm", Variant: "v7"})
	c := f.client(Options{})
	cases := []struct {
		name string
		p    inventory.Platform
		want error
	}{
		{"no such arch", inventory.Platform{OS: "linux", Architecture: "s390x"}, ErrPlatformNotFound},
		{"no such os", inventory.Platform{OS: "windows", Architecture: "amd64"}, ErrPlatformNotFound},
		{"requested variant", inventory.Platform{OS: "linux", Architecture: "amd64", Variant: "v2"}, ErrVariantUnsupported},
		{"entry variants are refused", inventory.Platform{OS: "linux", Architecture: "arm"}, ErrVariantUnsupported},
		{"unknown platform", inventory.Platform{}, ErrInvalidInput},
	}
	for _, tc := range cases {
		_, err := c.Resolve(context.Background(), f.repo("team/app"), "latest", tc.p)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestResolve_DigestVerification(t *testing.T) {
	f := newFakeRegistry(t)
	fx := f.serveIndex("team/app", mediaOCIIndex, mediaOCIManifest, linuxAMD64)
	md := fx.manifest["linux/amd64/"]

	// A child fetched by digest whose content is something else.
	f.route("/v2/team/app/manifests/"+md, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mediaOCIManifest)
		fmt.Fprint(w, `{"schemaVersion":2,"config":{"digest":"`+sha("evil")+`"}}`)
	})
	_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "latest", linuxAMD64)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("body not matching its digest: err = %v", err)
	}

	// A registry reporting a Docker-Content-Digest that disagrees with the body.
	g := newFakeRegistry(t)
	body := `{"schemaVersion":2,"mediaType":"` + mediaOCIManifest + `","config":{"digest":"` + sha("c") + `"}}`
	g.route("/v2/team/app/manifests/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mediaOCIManifest)
		w.Header().Set("Docker-Content-Digest", sha("other"))
		fmt.Fprint(w, body)
	})
	_, err = g.client(Options{}).Resolve(context.Background(), g.repo("team/app"), "v1", linuxAMD64)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("header digest mismatch: err = %v", err)
	}
}

func TestResolve_ComputedDigestWithoutHeader(t *testing.T) {
	f := newFakeRegistry(t)
	cfg := f.serveConfig("team/app", "linux", "amd64", "")
	body := `{"schemaVersion":2,"mediaType":"` + mediaOCIManifest + `","config":{"digest":"` + cfg + `"}}`
	f.route("/v2/team/app/manifests/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mediaOCIManifest)
		fmt.Fprint(w, body)
	})
	got, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
	if err != nil || got.TopDigest != sha(body) {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestResolve_SendsAcceptForAllManifestTypes(t *testing.T) {
	f := newFakeRegistry(t)
	var accept string
	f.route("/v2/team/app/manifests/v1", func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		http.NotFound(w, r)
	})
	_, _ = f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
	for _, mt := range []string{mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerV2} {
		if !strings.Contains(accept, mt) {
			t.Errorf("Accept %q lacks %s", accept, mt)
		}
	}
}

func TestResolve_UnsupportedAndInvalid(t *testing.T) {
	f := newFakeRegistry(t)
	f.serveManifest("team/app", "application/vnd.docker.distribution.manifest.v1+prettyjws", `{"schemaVersion":1}`, "old")
	if _, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "old", linuxAMD64); !errors.Is(err, ErrUnsupported) {
		t.Errorf("schema1: err = %v", err)
	}
	before := len(f.hits())
	for _, ref := range []string{"", "../x", "a/b", "sha256:short", "-bad"} {
		if _, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), ref, linuxAMD64); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ref %q: err = %v, want ErrInvalidInput", ref, err)
		}
	}
	if len(f.hits()) != before {
		t.Errorf("invalid references must not reach the network: %v", f.hits())
	}
}

func TestRateLimited_ReturnsRetryAfterWithoutRetrying(t *testing.T) {
	f := newFakeRegistry(t)
	var calls int32
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	start := time.Now()
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	var rl *RateLimitedError
	if !errors.Is(err, ErrRateLimited) || !errors.As(err, &rl) {
		t.Fatalf("err = %v", err)
	}
	if rl.RetryAfter != 42*time.Second {
		t.Errorf("RetryAfter = %v", rl.RetryAfter)
	}
	if atomic.LoadInt32(&calls) != 1 || time.Since(start) > 5*time.Second {
		t.Errorf("calls=%d elapsed=%v; the client must neither retry nor sleep", calls, time.Since(start))
	}
}

func TestRateLimited_TokenEndpoint(t *testing.T) {
	f := newFakeRegistry(t)
	f.challenge = fmt.Sprintf(`Bearer realm="https://%s/tokenlimited",service="s"`, f.host())
	// Serve 429 on the alternate realm path by wrapping the handler.
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokenlimited" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		f.serve(w, r)
	})
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                              0,
		"30":                            30 * time.Second,
		"-5":                            0,
		"junk":                          0,
		"99999999":                      24 * time.Hour,
		"Fri, 09 Oct 2026 12:01:00 GMT": time.Minute,
		"Fri, 09 Oct 2026 11:00:00 GMT": 0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBudget(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { tagPage([]string{"1"}, "", w) })

	// Challenge + token + retry = 3 requests.
	b := NewBudget(3)
	if _, err := f.client(Options{Budget: b}).ListTags(context.Background(), f.repo("team/app")); err != nil {
		t.Fatal(err)
	}
	if b.Used() != 3 || b.Remaining() != 0 {
		t.Errorf("used=%d remaining=%d", b.Used(), b.Remaining())
	}

	g := newFakeRegistry(t)
	g.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { tagPage([]string{"1"}, "", w) })
	b = NewBudget(2)
	tl, err := g.client(Options{Budget: b}).ListTags(context.Background(), g.repo("team/app"))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	// The tag request went out and was challenged; only the token request
	// after it was refused, so the page counts.
	if tl.Pages != 1 {
		t.Errorf("pages = %d, want 1 (the page request was sent)", tl.Pages)
	}
	if n := len(g.hits()); n != 2 {
		t.Errorf("server saw %d requests with a budget of 2", n)
	}

	zero := NewBudget(0)
	tl, err = g.client(Options{Budget: zero}).ListTags(context.Background(), g.repo("team/app"))
	if !errors.Is(err, ErrBudgetExhausted) || len(g.hits()) != 2 || tl.Pages != 0 {
		t.Errorf("zero budget must send nothing: err=%v hits=%d pages=%d", err, len(g.hits()), tl.Pages)
	}
}

func TestBudgetCountsResolveRequests(t *testing.T) {
	f := newFakeRegistry(t)
	f.serveIndex("team/app", mediaOCIIndex, mediaOCIManifest, linuxAMD64)
	b := NewBudget(100)
	if _, err := f.client(Options{Budget: b}).Resolve(context.Background(), f.repo("team/app"), "latest", linuxAMD64); err != nil {
		t.Fatal(err)
	}
	// Challenge, token, index, platform manifest, config blob.
	if b.Used() != 5 {
		t.Errorf("used = %d, want 5", b.Used())
	}
}

func TestOversizedResponses(t *testing.T) {
	big := strings.Repeat("x", 4096)

	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tags":["%s"]}`, big)
	})
	if _, err := f.client(Options{MaxTagPageBytes: 1024}).ListTags(context.Background(), f.repo("team/app")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("tag page: err = %v", err)
	}

	f.route("/v2/team/app/manifests/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mediaOCIManifest)
		w.Header().Set("Transfer-Encoding", "chunked") // no Content-Length
		fmt.Fprintf(w, `{"pad":"%s"}`, big)
	})
	if _, err := f.client(Options{MaxManifestBytes: 1024}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64); !errors.Is(err, ErrTooLarge) {
		t.Errorf("manifest: err = %v", err)
	}

	g := newFakeRegistry(t)
	g.tokenBody = fmt.Sprintf(`{"token":"%s"}`, big)
	if _, err := g.client(Options{MaxTokenBytes: 1024}).ListTags(context.Background(), g.repo("team/app")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("token: err = %v", err)
	}
}

func TestRedirectToHTTPRejected(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/plain", http.StatusFound)
	})
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v, want ErrBadResponse", err)
	}
}

func TestRedirectOverHTTPSFollowedWithoutTokenOnOtherHost(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("token forwarded to another host")
		}
		fmt.Fprint(w, `{"tags":["moved"]}`)
	}))
	defer other.Close()
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
	})
	// Trust both test servers' certificates.
	pool := f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	pool.AddCert(other.Certificate())
	tl, err := f.client(Options{AllowAddr: func(ip net.IP, port string) bool { return ip.IsLoopback() }}).ListTags(context.Background(), f.repo("team/app"))
	if err != nil || len(tl.Tags) != 1 || tl.Tags[0] != "moved" {
		t.Errorf("tl=%+v err=%v", tl, err)
	}
}

func TestRequestTimeout(t *testing.T) {
	f := newFakeRegistry(t)
	f.noAuth = true
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	start := time.Now()
	_, err := f.client(Options{Timeout: 100 * time.Millisecond}).ListTags(context.Background(), f.repo("team/app"))
	if err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("err=%v elapsed=%v; want a timeout error", err, time.Since(start))
	}
}

func TestParseChallenge(t *testing.T) {
	ch := parseChallenge([]string{`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`})
	if ch.scheme != "Bearer" || ch.params["realm"] != "https://auth.docker.io/token" || ch.params["service"] != "registry.docker.io" {
		t.Errorf("%+v", ch)
	}
	ch = parseChallenge([]string{`Basic realm="x"`, `Bearer realm="r",service=s`})
	if ch.scheme != "Bearer" || ch.params["realm"] != "r" || ch.params["service"] != "s" {
		t.Errorf("%+v", ch)
	}
	if ch = parseChallenge(nil); ch.scheme != "" {
		t.Errorf("%+v", ch)
	}
}

func singleManifest(f *fakeRegistry, repo, ref, cfg string) {
	body := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q,"size":3},"layers":[]}`, mediaOCIManifest, cfg)
	f.serveManifest(repo, mediaOCIManifest, body, ref)
}

func TestResolve_ConfigBlobProblems(t *testing.T) {
	t.Run("missing blob", func(t *testing.T) {
		f := newFakeRegistry(t)
		singleManifest(f, "team/app", "v1", sha("nowhere"))
		_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("digest mismatch", func(t *testing.T) {
		f := newFakeRegistry(t)
		cfg := sha("claimed")
		singleManifest(f, "team/app", "v1", cfg)
		f.route("/v2/team/app/blobs/"+cfg, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"os":"linux","architecture":"amd64"}`)
		})
		_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Errorf("err = %v, want ErrDigestMismatch", err)
		}
	})
	t.Run("different platform", func(t *testing.T) {
		f := newFakeRegistry(t)
		singleManifest(f, "team/app", "v1", f.serveConfig("team/app", "linux", "arm64", ""))
		_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if !errors.Is(err, ErrPlatformMismatch) {
			t.Errorf("err = %v, want ErrPlatformMismatch", err)
		}
	})
	t.Run("config variant", func(t *testing.T) {
		f := newFakeRegistry(t)
		singleManifest(f, "team/app", "v1", f.serveConfig("team/app", "linux", "arm64", "v8"))
		_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", inventory.Platform{OS: "linux", Architecture: "arm64"})
		var ve *VariantError
		if !errors.Is(err, ErrVariantUnsupported) || !errors.As(err, &ve) || ve.Observed != "v8" {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("index entry disagrees with config", func(t *testing.T) {
		f := newFakeRegistry(t)
		cfg := f.serveConfig("team/app", "linux", "arm64", "")
		mbody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q}}`, mediaOCIManifest, cfg)
		md := sha(mbody)
		f.serveManifest("team/app", mediaOCIManifest, mbody, md)
		ibody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, mediaOCIIndex, md)
		f.serveManifest("team/app", mediaOCIIndex, ibody, "latest")
		_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "latest", linuxAMD64)
		if !errors.Is(err, ErrPlatformMismatch) {
			t.Errorf("err = %v, want ErrPlatformMismatch", err)
		}
	})
	t.Run("oversized config", func(t *testing.T) {
		f := newFakeRegistry(t)
		cfg := f.serveConfig("team/app", "linux", "amd64", "")
		singleManifest(f, "team/app", "v1", cfg)
		_, err := f.client(Options{MaxConfigBytes: 8}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})
}

func TestForbiddenAddr(t *testing.T) {
	forbidden := []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "fc00::1", "fd12::1",
		"169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "100.64.0.1", "100.127.255.255",
		"::ffff:10.0.0.1", "255.255.255.255", "0.1.2.3"}
	for _, s := range forbidden {
		if !forbiddenAddr(net.ParseIP(s)) {
			t.Errorf("%s must be forbidden", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.32.0.1", "2606:4700::1111"} {
		if forbiddenAddr(net.ParseIP(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

// strictClient has no test opt-in, so the default policy applies.
func strictClient(f *fakeRegistry, o Options) *Client {
	o.HTTPClient = f.srv.Client()
	return New(o)
}

func TestAddressPolicy_InternalLiteralHost(t *testing.T) {
	f := newFakeRegistry(t)
	for _, repo := range []string{"10.0.0.1/team/app", "169.254.169.254/team/app", "[::1]:5000/team/app", "127.0.0.1:1/team/app"} {
		_, err := strictClient(f, Options{}).ListTags(context.Background(), repo)
		if !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: err = %v, want ErrForbiddenAddress", repo, err)
		}
	}
	// The fake registry itself, on loopback, is refused by default.
	if _, err := strictClient(f, Options{}).ListTags(context.Background(), f.repo("team/app")); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("loopback registry: err = %v", err)
	}
	if n := len(f.hits()); n != 0 {
		t.Errorf("server saw %d requests despite the refusals", n)
	}
}

func TestAddressPolicy_NameResolvingToInternalIP(t *testing.T) {
	var asked []string
	resolver := func(ctx context.Context, host string) ([]net.IP, error) {
		asked = append(asked, host)
		switch host {
		case "internal.example.com":
			return []net.IP{net.ParseIP("192.168.1.5")}, nil
		case "mixed.example.com":
			return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.9")}, nil
		}
		return nil, errors.New("no such host")
	}
	f := newFakeRegistry(t)
	for _, host := range []string{"internal.example.com", "mixed.example.com"} {
		_, err := strictClient(f, Options{Resolver: resolver}).ListTags(context.Background(), host+"/team/app")
		if !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: err = %v, want ErrForbiddenAddress", host, err)
		}
	}
	if len(asked) != 2 {
		t.Errorf("resolver calls = %v", asked)
	}
}

func TestAddressPolicy_ResolvedIPIsDialed(t *testing.T) {
	// A name resolving to the test server is dialed by IP once the opt-in
	// permits it; the name itself is never dialed.
	f := newFakeRegistry(t)
	f.noAuth = true
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { tagPage([]string{"ok"}, "", w) })
	host, port, _ := net.SplitHostPort(f.host())
	resolver := func(ctx context.Context, name string) ([]net.IP, error) {
		if name != "registry.test" {
			t.Errorf("unexpected lookup %q", name)
		}
		return []net.IP{net.ParseIP(host)}, nil
	}
	c := New(Options{HTTPClient: f.srv.Client(), Resolver: resolver,
		AllowAddr: func(ip net.IP, p string) bool { return p == port }})
	// The test certificate names 127.0.0.1, not registry.test, so the TLS
	// handshake fails after a successful dial; that is enough to show the
	// address check passed.
	_, err := c.ListTags(context.Background(), "registry.test:"+port+"/team/app")
	if errors.Is(err, ErrForbiddenAddress) || err == nil {
		t.Errorf("err = %v, want a TLS error after an allowed dial", err)
	}
}

func TestAddressPolicy_RealmToInternalAddress(t *testing.T) {
	realm := newFakeRegistry(t) // another loopback server, not allowed
	f := newFakeRegistry(t)
	f.challenge = fmt.Sprintf(`Bearer realm="https://%s/token",service="s"`, realm.host())
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
	if len(realm.hits()) != 0 {
		t.Error("the realm server must not be contacted")
	}
}

func TestAddressPolicy_RedirectToInternalAddress(t *testing.T) {
	target := newFakeRegistry(t)
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+"/v2/team/app/tags/list", http.StatusFound)
	})
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
	if len(target.hits()) != 0 {
		t.Error("the redirect target must not be contacted")
	}
}

func TestResolve_AmbiguousDistinctDigests(t *testing.T) {
	f := newFakeRegistry(t)
	ibody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[`+
		`{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}},`+
		`{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, mediaOCIIndex, sha("m1"), sha("m2"))
	f.serveManifest("team/app", mediaOCIIndex, ibody, "latest")
	_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "latest", linuxAMD64)
	if !errors.Is(err, ErrPlatformAmbiguous) {
		t.Errorf("err = %v, want ErrPlatformAmbiguous", err)
	}
}

func TestResolve_DuplicateDigestVariantInAnyOrder(t *testing.T) {
	for _, order := range [][2]string{{"", "v8"}, {"v8", ""}} {
		f := newFakeRegistry(t)
		cfg := f.serveConfig("team/app", "linux", "arm64", "")
		mbody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q}}`, mediaOCIManifest, cfg)
		md := sha(mbody)
		f.serveManifest("team/app", mediaOCIManifest, mbody, md)
		entry := func(v string) string {
			variant := ""
			if v != "" {
				variant = fmt.Sprintf(`,"variant":%q`, v)
			}
			return fmt.Sprintf(`{"digest":%q,"platform":{"os":"linux","architecture":"arm64"%s}}`, md, variant)
		}
		ibody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[%s,%s]}`, mediaOCIIndex, entry(order[0]), entry(order[1]))
		f.serveManifest("team/app", mediaOCIIndex, ibody, "latest")
		_, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "latest", inventory.Platform{OS: "linux", Architecture: "arm64"})
		var ve *VariantError
		if !errors.Is(err, ErrVariantUnsupported) || !errors.As(err, &ve) || ve.Observed != "v8" {
			t.Errorf("order %q: err = %v", order, err)
		}
	}
}
