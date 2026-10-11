// Package registry is a read-only client for the Docker Registry HTTP API v2.
// It lists tags and resolves a tag or digest to the manifest and image config
// digests of one platform.
//
// The client is built to be a polite, bounded guest: HTTPS only, pull access
// only, capped response sizes, a per-request timeout, and a caller-supplied
// request budget. It is anonymous unless the caller supplies credentials for
// a registry host; those are sent only to that host, or to a token service
// the configuration names, and are dropped at every redirect. It never sleeps
// or retries by itself; rate limiting and exhausted budgets are returned as
// typed errors so the caller decides what to do next.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/regauth"
)

const (
	defaultTimeout          = 30 * time.Second
	defaultMaxManifestBytes = 4 << 20
	defaultMaxTagPageBytes  = 2 << 20
	defaultMaxTokenBytes    = 64 << 10
	defaultMaxConfigBytes   = 4 << 20
	defaultMaxTagPages      = 20
	defaultTagPageSize      = 1000
	maxErrorBodyBytes       = 64 << 10
	maxRedirects            = 3
	// defaultTokenTTL applies when a token response gives no expires_in; the
	// token specification says clients assume 60 seconds then.
	defaultTokenTTL = 60 * time.Second
	// tokenSkew retires a cached token slightly before it expires.
	tokenSkew = 10 * time.Second
)

// Options configures a Client. Zero values select the defaults.
type Options struct {
	// HTTPClient is the base client. It is copied, and the copy's timeout and
	// redirect policy are replaced; nil means a default client.
	HTTPClient *http.Client
	// Budget caps the requests this client may send. Nil is unlimited.
	Budget *Budget
	// Timeout bounds each HTTP request, body read included.
	Timeout time.Duration
	// Auth holds credentials by registry host. A host without one is reached
	// anonymously. Nil means no credentials at all.
	Auth *regauth.Store

	MaxManifestBytes int64 // manifest and index bodies
	MaxTagPageBytes  int64 // one tag listing page
	MaxTokenBytes    int64 // token endpoint responses
	MaxConfigBytes   int64 // image config blobs
	MaxTagPages      int   // pages ListTags follows before reporting truncation
	TagPageSize      int   // the n parameter of tag listings

	// Resolver looks up the addresses of a host name at dial time; nil means
	// the system resolver. Every returned address is checked before dialing.
	Resolver func(ctx context.Context, host string) ([]net.IP, error)
	// AllowAddr is for tests only. When non-nil and it returns true for an
	// address and port, that address is permitted even though the default
	// policy (public addresses only) would refuse it. Production code leaves
	// it nil.
	AllowAddr func(ip net.IP, port string) bool

	// Now is the clock for token expiry; nil means time.Now.
	Now func() time.Time
}

// Client talks to registries. It is safe for concurrent use.
type Client struct {
	http   *http.Client
	budget *Budget
	opts   Options

	mu     sync.Mutex
	tokens map[string]cachedToken
	// basic holds the hosts that answered a Basic challenge, so later
	// requests carry the credential at once.
	basic map[string]bool
}

type cachedToken struct {
	value   string
	expires time.Time
}

// New returns a Client.
func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxManifestBytes <= 0 {
		o.MaxManifestBytes = defaultMaxManifestBytes
	}
	if o.MaxTagPageBytes <= 0 {
		o.MaxTagPageBytes = defaultMaxTagPageBytes
	}
	if o.MaxTokenBytes <= 0 {
		o.MaxTokenBytes = defaultMaxTokenBytes
	}
	if o.MaxConfigBytes <= 0 {
		o.MaxConfigBytes = defaultMaxConfigBytes
	}
	if o.MaxTagPages <= 0 {
		o.MaxTagPages = defaultMaxTagPages
	}
	if o.TagPageSize <= 0 {
		o.TagPageSize = defaultTagPageSize
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	var hc http.Client
	if o.HTTPClient != nil {
		hc = *o.HTTPClient
	}
	// The per-request deadline is a context, so Client.Timeout stays off.
	hc.Timeout = 0
	c := &Client{budget: o.Budget, opts: o, tokens: map[string]cachedToken{}, basic: map[string]bool{}}
	hc.CheckRedirect = c.checkRedirect
	// Every connection goes through dialContext so addresses are validated
	// where they are resolved. A caller-supplied transport is cloned for its
	// TLS settings; anything that is not an *http.Transport is replaced. A
	// proxy would be dialed instead of the registry, so none is used.
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

// forbiddenAddr reports whether ip is outside the public address space the
// client is willing to contact.
func forbiddenAddr(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		// 0.0.0.0/8, carrier-grade NAT 100.64.0.0/10 and the limited broadcast.
		if ip4[0] == 0 || (ip4[0] == 100 && ip4[1]&0xc0 == 64) || ip4.Equal(net.IPv4bcast) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast()
}

// ForbiddenAddr reports whether ip is outside the public address space that
// outbound read-only clients are willing to contact: loopback, private,
// link-local, unspecified, multicast, carrier-grade NAT and the like.
func ForbiddenAddr(ip net.IP) bool { return forbiddenAddr(ip) }

// dialContext resolves addr, refuses it if any resolved address is not
// allowed, and dials a validated IP directly so the name cannot resolve to
// something else between the check and the connection.
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
			return nil, fmt.Errorf("registry: resolve %s: %w", host, err)
		}
	} else if ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host); err != nil {
		return nil, fmt.Errorf("registry: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("registry: %s resolved to no address", host)
	}
	for _, ip := range ips {
		if forbiddenAddr(ip) && (c.opts.AllowAddr == nil || !c.opts.AllowAddr(ip, port)) {
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

// checkRedirect allows a few redirects, only to HTTPS, each costing one
// request. No Authorization header, credential or token, is carried to a
// redirect target, whichever host or path that is: the target is asked
// without one, and a registry that wants a token there answers with its own
// challenge.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("%w: too many redirects", ErrBadResponse)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%w: redirect to a non-HTTPS URL", ErrBadResponse)
	}
	req.Header.Del("Authorization")
	return c.budget.take()
}

// Endpoint maps a repository as written in an image reference to the registry
// host to contact and the repository path on it: docker.io (or no host) goes
// to registry-1.docker.io with a "library/" prefix for single-segment names;
// any other host is used as written.
func Endpoint(repo string) (host, path string, err error) {
	key, ok := inventory.RepositoryKey(repo)
	if !ok {
		return "", "", fmt.Errorf("%w: repository %q", ErrInvalidInput, repo)
	}
	host, path, _ = strings.Cut(key, "/")
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	if path == "" {
		return "", "", fmt.Errorf("%w: repository %q", ErrInvalidInput, repo)
	}
	return host, path, nil
}

type target struct {
	host, path string
}

func (t target) key() string { return t.host + "/" + t.path }

func (t target) base() string { return "https://" + t.host + "/v2/" + t.path }

func newTarget(repo string) (target, error) {
	host, path, err := Endpoint(repo)
	if err != nil {
		return target{}, err
	}
	return target{host: host, path: path}, nil
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// once sends one GET (one budget unit), reads the body within limit and
// returns the raw response. Successful responses over the limit are
// ErrTooLarge; error bodies are truncated instead. sent is false only when
// the budget refused the request, so nothing went out.
func (c *Client) once(ctx context.Context, rawURL, accept, authz string, limit int64) (r *response, sent bool, err error) {
	if err := c.budget.take(); err != nil {
		return nil, false, err
	}
	r, err = c.send(ctx, rawURL, accept, authz, limit)
	return r, true, err
}

// requestErr wraps a failed request. When only the request's own deadline
// passed, and the caller's context is still live, the error is ErrTimeout;
// when the caller's context ended, the error keeps that cause so the caller
// can tell a cycle deadline from a slow registry.
func requestErr(parent, req context.Context, what string, err error) error {
	if parent.Err() == nil && errors.Is(req.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s", ErrTimeout, what)
	}
	return fmt.Errorf("registry: %s: %w", what, err)
}

// send performs one GET. authz is the complete Authorization header value,
// "" for none.
func (c *Client) send(parent context.Context, rawURL, accept, authz string, limit int64) (*response, error) {
	ctx, cancel := context.WithTimeout(parent, c.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, requestErr(parent, ctx, "GET "+req.URL.Redacted(), err)
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	max := limit
	if !ok {
		max = maxErrorBodyBytes
	}
	if ok && resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: %s declares %d bytes (limit %d)", ErrTooLarge, req.URL.Host, resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, requestErr(parent, ctx, "read "+req.URL.Redacted(), err)
	}
	if int64(len(body)) > max {
		if ok {
			return nil, fmt.Errorf("%w: %s sent more than %d bytes", ErrTooLarge, req.URL.Host, limit)
		}
		body = body[:max]
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

// statusErr converts a non-success status that is not an authentication
// challenge into its error.
func statusErr(host string, r *response) error {
	switch r.status {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, host)
	case http.StatusTooManyRequests:
		return &RateLimitedError{Host: host, RetryAfter: parseRetryAfter(r.header.Get("Retry-After"), time.Now())}
	}
	return &StatusError{Host: host, Status: r.status}
}

// parseRetryAfter reads a Retry-After value (seconds or an HTTP date); 0 for
// anything else.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return 0
		}
		const maxDelay = int64(24 * time.Hour / time.Second)
		if n > maxDelay {
			n = maxDelay
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			if d > 24*time.Hour {
				d = 24 * time.Hour
			}
			return d
		}
	}
	return 0
}

// get fetches rawURL from the registry of t, answering an authentication
// challenge when there is one (see getSent).
func (c *Client) get(ctx context.Context, t target, rawURL, accept string, limit int64) (*response, error) {
	r, _, err := c.getSent(ctx, t, rawURL, accept, limit)
	return r, err
}

// getSent is get that also reports whether a request for rawURL itself was
// sent, whatever happened afterwards (for example the budget running out at
// the token request that follows a 401 for it).
//
// A cached token, or a Basic credential the host asked for before, is tried
// first. A Bearer challenge is answered with one token request; a Basic
// challenge is answered with the configured credential of t's host, if there
// is one. At most one challenge is answered per call.
func (c *Client) getSent(ctx context.Context, t target, rawURL, accept string, limit int64) (resp *response, sent bool, err error) {
	cred, hasCred := c.opts.Auth.For(t.host)
	if hasCred {
		// Whatever goes wrong, the text that is kept holds no part of the login.
		defer func() { err = cred.ScrubError(err) }()
	}
	authz := c.cachedAuthz(t, cred, hasCred)
	fresh := false
	for {
		r, s, err := c.once(ctx, rawURL, accept, authz, limit)
		sent = sent || s
		if err != nil {
			return nil, sent, err
		}
		switch {
		case r.status >= 200 && r.status < 300:
			return r, sent, nil
		case r.status == http.StatusUnauthorized && !fresh && !strings.HasPrefix(authz, "Basic "):
			ch := parseChallenge(r.header.Values("Www-Authenticate"))
			switch {
			case strings.EqualFold(ch.scheme, "bearer") && ch.params["realm"] != "":
				authz, err = c.fetchToken(ctx, t, ch)
				if err != nil {
					return nil, sent, err
				}
			case strings.EqualFold(ch.scheme, "basic") && hasCred:
				authz = cred.BasicAuthorization()
				c.mu.Lock()
				c.basic[t.host] = true
				c.mu.Unlock()
			case strings.EqualFold(ch.scheme, "basic"):
				return nil, sent, fmt.Errorf("%w: %s asks for a login and no credentials are configured for it", ErrAuthRequired, t.host)
			default:
				return nil, sent, fmt.Errorf("%w: %s sent no usable authentication challenge", ErrAuthRequired, t.host)
			}
			fresh = true
		case r.status == http.StatusUnauthorized, r.status == http.StatusForbidden:
			if hasCred {
				return nil, sent, fmt.Errorf("%w: %s refused access to %s with the configured credentials", ErrAuthRequired, t.host, t.path)
			}
			return nil, sent, fmt.Errorf("%w: %s refused anonymous access to %s and no credentials are configured for it", ErrAuthRequired, t.host, t.path)
		default:
			return nil, sent, statusErr(t.host, r)
		}
	}
}

// cachedAuthz is the Authorization value to try first for t: a live cached
// token, else the Basic credential of a host that asked for one, else none.
func (c *Client) cachedAuthz(t target, cred regauth.Credential, hasCred bool) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ct, ok := c.tokens[t.key()]; ok {
		if c.opts.Now().Before(ct.expires) {
			return "Bearer " + ct.value
		}
		delete(c.tokens, t.key())
	}
	if hasCred && c.basic[t.host] {
		return cred.BasicAuthorization()
	}
	return ""
}

// fetchToken gets a pull token for t from the challenge's realm, caches it
// and returns it as an Authorization value. When credentials are configured
// for t's host, they authenticate the request, but only if the realm is on
// that same host or on a host the credential names; any other realm is asked
// anonymously.
func (c *Client) fetchToken(ctx context.Context, t target, ch challenge) (string, error) {
	realm, err := url.Parse(ch.params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" || realm.User != nil {
		return "", fmt.Errorf("%w: unusable token realm from %s", ErrBadResponse, t.host)
	}
	q := realm.Query()
	if s := ch.params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+t.path+":pull")
	realm.RawQuery = q.Encode()

	var authz string
	withheld := false
	cred, hasCred := c.opts.Auth.For(t.host)
	if hasCred {
		if cred.AllowsTokenHost(realm.Host) {
			authz = cred.BasicAuthorization()
		} else {
			withheld = true
		}
	}
	r, _, err := c.once(ctx, realm.String(), "application/json", authz, c.opts.MaxTokenBytes)
	if err != nil {
		return "", err
	}
	switch {
	case r.status >= 200 && r.status < 300:
	case r.status == http.StatusUnauthorized, r.status == http.StatusForbidden:
		switch {
		case authz != "":
			return "", fmt.Errorf("%w: token service %s rejected the configured credentials for %s", ErrAuthRequired, realm.Host, t.path)
		case withheld:
			return "", fmt.Errorf("%w: token service %s refused an anonymous token for %s, and the credentials for %s are not sent to that host unless it is listed in token_hosts", ErrAuthRequired, realm.Host, t.path, t.host)
		}
		return "", fmt.Errorf("%w: token service %s refused an anonymous token for %s and no credentials are configured for %s", ErrAuthRequired, realm.Host, t.path, t.host)
	default:
		return "", statusErr(realm.Host, r)
	}
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(r.body, &tr); err != nil {
		return "", fmt.Errorf("%w: token response from %s is not JSON", ErrBadResponse, realm.Host)
	}
	token := tr.Token
	if token == "" {
		token = tr.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("%w: token response from %s holds no token", ErrBadResponse, realm.Host)
	}
	ttl := defaultTokenTTL
	if tr.ExpiresIn > 0 {
		ttl = time.Duration(tr.ExpiresIn) * time.Second
	}
	if ttl -= tokenSkew; ttl > 0 {
		c.mu.Lock()
		c.tokens[t.key()] = cachedToken{value: token, expires: c.opts.Now().Add(ttl)}
		c.mu.Unlock()
	}
	return "Bearer " + token, nil
}

type challenge struct {
	scheme string
	params map[string]string
}

// parseChallenge reads the first Bearer challenge from WWW-Authenticate
// header values; if there is none, it returns the first challenge's scheme
// with no parameters.
func parseChallenge(values []string) challenge {
	var first challenge
	for i, v := range values {
		v = strings.TrimSpace(v)
		scheme, rest, _ := strings.Cut(v, " ")
		ch := challenge{scheme: scheme, params: parseAuthParams(rest)}
		if i == 0 {
			first = challenge{scheme: scheme, params: map[string]string{}}
		}
		if strings.EqualFold(scheme, "bearer") {
			return ch
		}
	}
	return first
}

// parseAuthParams reads comma-separated key="value" or key=value pairs.
func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	for {
		s = strings.TrimLeft(s, " ,")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return out
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
			}
			val = b.String()
			if i < len(s) {
				i++
			}
			s = s[i:]
		} else {
			end := strings.IndexByte(s, ',')
			if end < 0 {
				end = len(s)
			}
			val = strings.TrimSpace(s[:end])
			s = s[end:]
		}
		out[key] = val
	}
}

// Challenges asks the registry of repo how it wants a request authenticated,
// without any credential, at the two places a client looks: the registry's
// /v2/ endpoint, which clients such as Trivy's registry library ping first and
// take their authentication scheme and token service from, and the
// repository's tag list. Each answer gives the scheme and, for Bearer, the
// host of the token service. It costs two requests. The answers describe the
// registry at this moment; a later request may be answered differently.
func (c *Client) Challenges(ctx context.Context, repo string) ([]regauth.Challenge, error) {
	t, err := newTarget(repo)
	if err != nil {
		return nil, err
	}
	var out []regauth.Challenge
	for _, u := range []string{"https://" + t.host + "/v2/", t.base() + "/tags/list?n=1"} {
		ch, err := c.challengeAt(ctx, t, u)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, nil
}

func (c *Client) challengeAt(ctx context.Context, t target, rawURL string) (regauth.Challenge, error) {
	r, _, err := c.once(ctx, rawURL, "application/json", "", c.opts.MaxTagPageBytes)
	if err != nil {
		return regauth.Challenge{}, err
	}
	switch {
	case r.status >= 200 && r.status < 300:
		return regauth.Challenge{Scheme: "none"}, nil
	case r.status == http.StatusUnauthorized:
		ch := parseChallenge(r.header.Values("Www-Authenticate"))
		switch {
		case strings.EqualFold(ch.scheme, "bearer") && ch.params["realm"] != "":
			realm, err := url.Parse(ch.params["realm"])
			if err != nil || realm.Scheme != "https" || realm.Host == "" || realm.User != nil {
				return regauth.Challenge{}, fmt.Errorf("%w: unusable token realm from %s", ErrBadResponse, t.host)
			}
			return regauth.Challenge{Scheme: "bearer", RealmHost: realm.Host}, nil
		case strings.EqualFold(ch.scheme, "basic"):
			return regauth.Challenge{Scheme: "basic"}, nil
		}
		return regauth.Challenge{Scheme: "other"}, nil
	case r.status == http.StatusNotFound:
		// Some registries answer an unknown repository before asking for a
		// login; nothing here says how a login would be answered.
		return regauth.Challenge{Scheme: "other"}, nil
	}
	return regauth.Challenge{}, statusErr(t.host, r)
}
