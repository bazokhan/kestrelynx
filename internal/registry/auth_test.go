package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/regauth"
)

const (
	authUser = "puller"
	authPass = "p4ss-w0rd-secret"
)

var authBasic = "Basic " + base64.StdEncoding.EncodeToString([]byte(authUser+":"+authPass))

// recorder is a TLS server that records the Authorization header of each
// request by path.
type recorder struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []seenReq
	h    http.HandlerFunc
}

type seenReq struct{ path, query, authz string }

func newRecorder(t *testing.T, h http.HandlerFunc) *recorder {
	t.Helper()
	r := &recorder{h: h}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, seenReq{req.URL.Path, req.URL.RawQuery, req.Header.Get("Authorization")})
		r.mu.Unlock()
		r.h(w, req)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) host() string { return r.srv.Listener.Addr().String() }

func (r *recorder) requests(path string) []seenReq {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []seenReq
	for _, s := range r.seen {
		if s.path == path {
			out = append(out, s)
		}
	}
	return out
}

func loopbackOK(ip net.IP, _ string) bool { return ip.IsLoopback() }

func authClient(r *recorder, auth *regauth.Store, o Options) *Client {
	o.HTTPClient = r.srv.Client() // all httptest servers share one certificate
	o.AllowAddr = loopbackOK
	o.Auth = auth
	return New(o)
}

func store(t *testing.T, host string, tokenHosts ...string) *regauth.Store {
	t.Helper()
	s, err := regauth.NewStore([]regauth.Credential{regauth.New(host, authUser, authPass, tokenHosts)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tokenRegistry answers /v2 with a Bearer challenge for the token service at
// tokenHost and demands the token it issues.
func tokenRegistry(t *testing.T, tokenHost func() string, tokenHandler http.HandlerFunc) *recorder {
	return newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenHandler(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="reg"`, tokenHost()))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"name":"a/b","tags":["1","2"]}`)
	})
}

func tokenOK(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `{"token":"tok-1","expires_in":300}`)
}

func TestCredentialGoesToTokenServiceOnTheSameHost(t *testing.T) {
	var reg *recorder
	reg = tokenRegistry(t, func() string { return reg.host() }, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authBasic {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokenOK(w, r)
	})
	c := authClient(reg, store(t, reg.host()), Options{})
	got, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if err != nil || len(got.Tags) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if tr := reg.requests("/token"); len(tr) != 1 || tr[0].authz != authBasic {
		t.Errorf("token requests = %+v, want one carrying the credential", tr)
	}
	for _, r := range reg.requests("/v2/a/b/tags/list") {
		if strings.HasPrefix(r.authz, "Basic") {
			t.Errorf("the credential reached the registry endpoint itself: %+v", r)
		}
	}
	// The token is cached: the second listing needs no token request.
	if _, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "1", 10); err != nil {
		t.Fatal(err)
	}
	if n := len(reg.requests("/token")); n != 1 {
		t.Errorf("token requests = %d, want the cached token reused", n)
	}
}

func TestCredentialIsNotSentToAForeignTokenService(t *testing.T) {
	tokenSvc := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" { // would grant a token
			tokenOK(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized) // anonymous: refused
	})
	reg := tokenRegistry(t, tokenSvc.host, nil)
	c := authClient(reg, store(t, reg.host()), Options{})
	_, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("err = %v, want ErrAuthRequired", err)
	}
	if !strings.Contains(err.Error(), "token_hosts") {
		t.Errorf("the error should say how to allow the token service: %v", err)
	}
	for _, r := range tokenSvc.requests("/token") {
		if r.authz != "" {
			t.Errorf("the credential reached a token service that was not named: %+v", r)
		}
	}
	if strings.Contains(err.Error(), authPass) || strings.Contains(err.Error(), authUser) {
		t.Errorf("error shows the login: %v", err)
	}
}

func TestCredentialGoesToANamedForeignTokenService(t *testing.T) {
	tokenSvc := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authBasic {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokenOK(w, r)
	})
	reg := tokenRegistry(t, tokenSvc.host, nil)
	c := authClient(reg, store(t, reg.host(), tokenSvc.host()), Options{})
	if _, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10); err != nil {
		t.Fatal(err)
	}
	if tr := tokenSvc.requests("/token"); len(tr) != 1 || tr[0].authz != authBasic {
		t.Errorf("token requests = %+v", tr)
	}
}

func TestNoCredentialsMeansAnAnonymousTokenRequest(t *testing.T) {
	var reg *recorder
	reg = tokenRegistry(t, func() string { return reg.host() }, tokenOK)
	for _, st := range []*regauth.Store{nil, store(t, "other.example.com")} {
		c := authClient(reg, st, Options{})
		if _, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range reg.requests("/token") {
		if r.authz != "" {
			t.Errorf("anonymous access sent an Authorization header: %+v", r)
		}
	}
}

func TestTokenServiceRefusesCredentials(t *testing.T) {
	var reg *recorder
	reg = tokenRegistry(t, func() string { return reg.host() }, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	_, err := authClient(reg, store(t, reg.host()), Options{}).ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if !errors.Is(err, ErrAuthRequired) || !strings.Contains(err.Error(), "rejected the configured credentials") {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(err.Error(), authPass) {
		t.Errorf("error shows the password: %v", err)
	}
}

// basicRegistry demands a Basic login at the registry endpoint itself.
func basicRegistry(t *testing.T) *recorder {
	return newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="Registry Realm"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"name":"a/b","tags":["1"]}`)
	})
}

func TestBasicChallengeIsAnsweredAndRemembered(t *testing.T) {
	reg := basicRegistry(t)
	c := authClient(reg, store(t, reg.host()), Options{Budget: NewBudget(10)})
	for i := 0; i < 2; i++ {
		got, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
		if err != nil || len(got.Tags) != 1 {
			t.Fatalf("round %d: %+v, %v", i, got, err)
		}
	}
	reqs := reg.requests("/v2/a/b/tags/list")
	if len(reqs) != 3 || reqs[0].authz != "" || reqs[1].authz != authBasic || reqs[2].authz != authBasic {
		t.Errorf("requests = %+v, want one anonymous try, then the login at once", reqs)
	}
}

func TestBasicChallengeWithoutCredentials(t *testing.T) {
	reg := basicRegistry(t)
	_, err := authClient(reg, nil, Options{}).ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if !errors.Is(err, ErrAuthRequired) {
		t.Errorf("err = %v, want ErrAuthRequired", err)
	}
}

func TestBasicChallengeWithWrongCredentials(t *testing.T) {
	reg := basicRegistry(t)
	wrong, _ := regauth.NewStore([]regauth.Credential{regauth.New(reg.host(), authUser, "not-the-password", nil)})
	_, err := authClient(reg, wrong, Options{}).ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if !errors.Is(err, ErrAuthRequired) || !strings.Contains(err.Error(), "configured credentials") {
		t.Errorf("err = %v", err)
	}
	for _, leak := range []string{"not-the-password", authUser, authPass} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error shows %q: %v", leak, err)
		}
	}
	// One anonymous try, one with the login, then stop.
	if n := len(reg.requests("/v2/a/b/tags/list")); n != 2 {
		t.Errorf("requests = %d, want 2", n)
	}
}

func TestCredentialForAnotherHostIsNotSent(t *testing.T) {
	reg := basicRegistry(t)
	_, err := authClient(reg, store(t, "ghcr.io"), Options{}).ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("err = %v", err)
	}
	for _, r := range reg.requests("/v2/a/b/tags/list") {
		if r.authz != "" {
			t.Errorf("a credential for ghcr.io was sent to %s: %+v", reg.host(), r)
		}
	}
}

func TestCredentialIsDroppedAtRedirects(t *testing.T) {
	other := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"tags":["x"]}`) })
	var reg *recorder
	reg = newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/a/b/tags/list":
			if r.Header.Get("Authorization") != authBasic {
				w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			target := "https://" + other.host() + "/far"
			if r.URL.Query().Get("last") == "same" {
				target = "https://" + reg.host() + "/near"
			}
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		default:
			fmt.Fprint(w, `{"tags":["y"]}`)
		}
	})
	c := authClient(reg, store(t, reg.host()), Options{})
	for _, last := range []string{"far", "same"} {
		if _, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", last, 10); err != nil {
			t.Fatalf("%s: %v", last, err)
		}
	}
	if far := other.requests("/far"); len(far) != 1 || far[0].authz != "" {
		t.Errorf("the other host saw %+v", far)
	}
	if near := reg.requests("/near"); len(near) != 1 || near[0].authz != "" {
		t.Errorf("the same-host redirect carried %+v", near)
	}
}

func TestRequestTimeoutIsNotAContextError(t *testing.T) {
	reg := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	c := authClient(reg, nil, Options{Timeout: 50 * time.Millisecond})
	_, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if !errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want ErrTimeout and not a context deadline", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c = authClient(reg, nil, Options{Timeout: 10 * time.Second})
	_, err = c.ListTagsAfter(ctx, reg.host()+"/a/b", "", 10)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) {
		t.Errorf("err = %v, want the caller's deadline and not ErrTimeout", err)
	}
}

func TestListTagsAfterRequestAndMore(t *testing.T) {
	reg := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("last") {
		case "link":
			w.Header().Set("Link", `</v2/a/b/tags/list?last=z&n=5>; rel="next"`)
			fmt.Fprint(w, `{"tags":["a"]}`)
		case "full":
			fmt.Fprint(w, `{"tags":["a","b"]}`)
		case "null":
			fmt.Fprint(w, `{"name":"a/b","tags":null}`)
		default:
			fmt.Fprint(w, `{"tags":["a"]}`)
		}
	})
	c := authClient(reg, nil, Options{})
	repo := reg.host() + "/a/b"
	got, err := c.ListTagsAfter(context.Background(), repo, "8.19.16.~", 5)
	if err != nil || got.More || !got.Sent || len(got.Tags) != 1 {
		t.Errorf("short page = %+v, %v", got, err)
	}
	r := reg.requests("/v2/a/b/tags/list")[0]
	if !strings.Contains(r.query, "n=5") || !strings.Contains(r.query, "last=8.19.16.~") {
		t.Errorf("query = %q", r.query)
	}
	if got, _ = c.ListTagsAfter(context.Background(), repo, "link", 5); !got.More {
		t.Error("a Link header means more")
	}
	if got, _ = c.ListTagsAfter(context.Background(), repo, "full", 2); !got.More {
		t.Error("a full page means more")
	}
	if got, _ = c.ListTagsAfter(context.Background(), repo, "null", 2); got.More || len(got.Tags) != 0 {
		t.Errorf("null tags = %+v", got)
	}
	if _, err = c.ListTagsAfter(context.Background(), repo, "", 0); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("n=0: %v", err)
	}
	if _, err = c.ListTagsAfter(context.Background(), repo, strings.Repeat("x", 600), 5); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("long last: %v", err)
	}
	// An empty last sends no last parameter.
	if _, err = c.ListTagsAfter(context.Background(), repo, "", 5); err != nil {
		t.Fatal(err)
	}
	reqs := reg.requests("/v2/a/b/tags/list")
	if q := reqs[len(reqs)-1].query; strings.Contains(q, "last") {
		t.Errorf("query = %q", q)
	}
}

func TestListTagsAfterReportsUnsentRequests(t *testing.T) {
	reg := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"tags":[]}`) })
	c := authClient(reg, nil, Options{Budget: NewBudget(0)})
	got, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 5)
	if !errors.Is(err, ErrBudgetExhausted) || got.Sent {
		t.Errorf("got %+v, %v; want a budget error and nothing sent", got, err)
	}
}

func TestNoAuthorizationFollowsAnyRedirect(t *testing.T) {
	var reg *recorder
	reg = tokenRegistry(t, func() string { return reg.host() }, tokenOK)
	reg.h = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenOK(w, r)
		case "/v2/a/b/tags/list":
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="reg"`, reg.host()))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "https://"+reg.host()+"/elsewhere", http.StatusTemporaryRedirect)
		default:
			fmt.Fprint(w, `{"tags":["z"]}`)
		}
	}
	c := authClient(reg, store(t, reg.host()), Options{})
	if _, err := c.ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10); err != nil {
		t.Fatal(err)
	}
	if far := reg.requests("/elsewhere"); len(far) != 1 || far[0].authz != "" {
		t.Errorf("the same-host redirect target saw %+v; the token must not follow", far)
	}
}

func TestChallenges(t *testing.T) {
	var tokenHost string
	reg := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		repoPath := strings.HasPrefix(r.URL.Path, "/v2/") && r.URL.Path != "/v2/"
		switch {
		case r.URL.Path == "/v2/" && r.Header.Get("X-Case") == "":
			// the /v2/ endpoint says Bearer with the registry's own token service
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token"`, tokenHost))
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/open/x/tags/list":
			fmt.Fprint(w, `{"tags":[]}`)
		case r.URL.Path == "/v2/basic/x/tags/list":
			w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/bearer/x/tags/list":
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://evil.example.org:8443/token",service="s"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/digest/x/tags/list":
			w.Header().Set("WWW-Authenticate", `Digest realm="r"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/weird/x/tags/list":
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://plain.example.com/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/gone/x/tags/list":
			w.WriteHeader(http.StatusNotFound)
		case repoPath:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	tokenHost = reg.host()
	c := authClient(reg, store(t, reg.host()), Options{})
	selfBearer := regauth.Challenge{Scheme: "bearer", RealmHost: reg.host()}
	for repo, want := range map[string][]regauth.Challenge{
		"open/x":   {selfBearer, {Scheme: "none"}},
		"basic/x":  {selfBearer, {Scheme: "basic"}},
		"bearer/x": {selfBearer, {Scheme: "bearer", RealmHost: "evil.example.org:8443"}},
		"digest/x": {selfBearer, {Scheme: "other"}},
		"gone/x":   {selfBearer, {Scheme: "other"}},
	} {
		got, err := c.Challenges(context.Background(), reg.host()+"/"+repo)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v, %v; want %+v", repo, got, err, want)
		}
	}
	if _, err := c.Challenges(context.Background(), reg.host()+"/weird/x"); !errors.Is(err, ErrBadResponse) {
		t.Errorf("an http realm: %v", err)
	}
	if _, err := c.Challenges(context.Background(), reg.host()+"/boom/x"); err == nil {
		t.Error("a server error must be an error")
	}
	for _, r := range reg.seen {
		if r.authz != "" {
			t.Errorf("a challenge request carried %q", r.authz)
		}
	}
	// Both places are asked, and both cost a request of the budget.
	b := NewBudget(1)
	if _, err := authClient(reg, nil, Options{Budget: b}).Challenges(context.Background(), reg.host()+"/open/x"); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("one request of budget for two checks: %v", err)
	}
}

func TestClientErrorsNeverHoldTheLogin(t *testing.T) {
	// A token service that echoes the Authorization it was sent in a
	// server error; the client's own errors must not repeat anything of it.
	reg := tokenRegistry(t, nil, nil)
	reg.h = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			http.Error(w, "bad request: "+r.Header.Get("Authorization"), http.StatusUnauthorized)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token"`, reg.host()))
		w.WriteHeader(http.StatusUnauthorized)
	}
	_, err := authClient(reg, store(t, reg.host()), Options{}).ListTagsAfter(context.Background(), reg.host()+"/a/b", "", 10)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, leak := range []string{authPass, strings.TrimPrefix(authBasic, "Basic ")} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error shows the login: %v", err)
		}
	}
}
