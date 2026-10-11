// Package regauth holds the credentials for private image registries and the
// rules for where they may be sent. It is shared by the registry client and
// the scanner so both look a host up the same way and neither can print a
// password by accident.
package regauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const placeholder = "[redacted]"

// hostRE is a registry host as it appears in an image reference: a host name
// or IPv4 address and an optional port, never a scheme, user information or
// path.
var hostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::([0-9]{1,5}))?$`)

// NormalizeHost lower-cases host and folds the host names Docker Hub is
// reached by into "docker.io", the form an image reference without a
// registry host is taken to have.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return host
}

// ValidateHost checks that host is a bare registry host, optionally with a
// port. It does not echo anything but the host, which is not a secret.
func ValidateHost(host string) error {
	if host == "" {
		return errors.New("must not be empty")
	}
	if strings.Contains(host, "://") {
		return fmt.Errorf("%q must be a host name without a scheme", host)
	}
	if strings.ContainsAny(host, "/@?# \t") {
		return fmt.Errorf("%q must be a host name (and an optional port) only, without a path or user information", host)
	}
	m := hostRE.FindStringSubmatch(strings.ToLower(host))
	if m == nil {
		return fmt.Errorf("%q is not a valid registry host", host)
	}
	if m[1] != "" {
		if n, _ := strconv.Atoi(m[1]); n < 1 || n > 65535 {
			return fmt.Errorf("%q has an invalid port", host)
		}
	}
	return nil
}

// ValidateUsername checks a user name: Basic authentication joins it to the
// password with a colon, so it cannot contain one.
func ValidateUsername(s string) error {
	if err := ValidateSecretText(s); err != nil {
		return err
	}
	if strings.Contains(s, ":") {
		return errors.New("must not contain a colon")
	}
	return nil
}

// ValidateSecretText checks a username or password for characters that cannot
// be sent in an HTTP Basic credential or written to a Docker config file. The
// value is never part of the error.
func ValidateSecretText(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return errors.New("must not contain whitespace or control characters")
	}
	return nil
}

// Credential is the login for one registry host.
type Credential struct {
	// Host is the registry host as written in image references, normalized.
	Host     string
	Username string
	// TokenHosts are token service hosts, besides Host itself, that may
	// receive the credential when Host's Bearer challenge names them.
	TokenHosts []string
	password   string
}

// New returns a Credential. The host and the token hosts are normalized; the
// caller validates them first.
func New(host, username, password string, tokenHosts []string) Credential {
	c := Credential{Host: NormalizeHost(host), Username: username, password: password}
	for _, h := range tokenHosts {
		c.TokenHosts = append(c.TokenHosts, NormalizeHost(h))
	}
	return c
}

// Password returns the password itself.
func (c Credential) Password() string { return c.password }

// BasicAuthorization is the value of an Authorization header carrying the
// credential.
func (c Credential) BasicAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.password))
}

// AllowsTokenHost reports whether the credential may be sent to a token
// service at realmHost: the registry's own host, or a host named in
// TokenHosts. Anything else gets an anonymous request.
func (c Credential) AllowsTokenHost(realmHost string) bool {
	h := NormalizeHost(realmHost)
	if h == c.Host {
		return true
	}
	for _, t := range c.TokenHosts {
		if t == h {
			return true
		}
	}
	return false
}

// authValueRE matches the credential of an Authorization header value, as it
// appears in an error body that echoes a request.
var authValueRE = regexp.MustCompile(`(?i)\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]+`)

// Scrub removes the credential from s, for text that came from outside and
// might quote it: the password, the user:password pair, that pair encoded in
// base64 (standard and URL alphabets, with or without padding), as it appears
// in an Authorization header or a Docker config file, and the value of any
// Basic or Bearer authorization.
func (c Credential) Scrub(s string) string {
	if c.password != "" {
		pair := c.Username + ":" + c.password
		reps := []string{pair}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			reps = append(reps, enc.EncodeToString([]byte(pair)))
		}
		reps = append(reps, url.QueryEscape(c.password), url.PathEscape(c.password), c.password)
		for _, r := range reps {
			if r != "" {
				s = strings.ReplaceAll(s, r, placeholder)
			}
		}
	}
	return authValueRE.ReplaceAllString(s, "$1 "+placeholder)
}

// scrubbedError is an error whose text has been cleaned; it still unwraps to
// the original, so errors.Is and errors.As keep working, but its own text is
// the only text anything stores.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// ScrubError returns err with its text cleaned by Scrub. An error whose text
// holds nothing to remove is returned as it is.
func (c Credential) ScrubError(err error) error {
	if err == nil {
		return nil
	}
	if msg := c.Scrub(err.Error()); msg != err.Error() {
		return &scrubbedError{msg: msg, err: err}
	}
	return err
}

// Challenge is what a registry answered to an anonymous request.
type Challenge struct {
	// Scheme is "basic", "bearer", "none" (the request was allowed without
	// a login) or "other".
	Scheme string
	// RealmHost is the host of a Bearer challenge's token service.
	RealmHost string
}

// Permits says whether the credential may be handed to a client that will
// answer ch with it, and if not, why not. A Basic challenge goes to the
// registry's own host. A Bearer challenge is answered at its token service,
// which must be the registry's host or one the credential names. A registry
// that needs no login is not given one.
func (c Credential) Permits(ch Challenge) (bool, string) {
	switch ch.Scheme {
	case "basic":
		return true, ""
	case "bearer":
		if c.AllowsTokenHost(ch.RealmHost) {
			return true, ""
		}
		return false, fmt.Sprintf("the token service %s of %s is not %s or listed in token_hosts", ch.RealmHost, c.Host, c.Host)
	case "none":
		return false, c.Host + " allowed the request without a login"
	}
	return false, c.Host + " asked for an authentication scheme that is not supported"
}

func (c Credential) redacted() string {
	return fmt.Sprintf("regauth.Credential{host=%s user=%s password=%s}", c.Host, c.Username, placeholder)
}

// Format implements fmt.Formatter, covering every verb.
func (c Credential) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.redacted()) }

func (c Credential) String() string               { return c.redacted() }
func (c Credential) GoString() string             { return c.redacted() }
func (c Credential) MarshalText() ([]byte, error) { return []byte(c.redacted()), nil }
func (c Credential) LogValue() slog.Value         { return slog.StringValue(c.redacted()) }

// Store looks credentials up by registry host. The nil Store holds none.
type Store struct {
	byHost map[string]Credential
}

// NewStore returns a Store of creds; two credentials for one host are an
// error.
func NewStore(creds []Credential) (*Store, error) {
	s := &Store{byHost: map[string]Credential{}}
	for _, c := range creds {
		h := NormalizeHost(c.Host)
		if _, dup := s.byHost[h]; dup {
			return nil, fmt.Errorf("regauth: two credentials for host %s", h)
		}
		c.Host = h
		s.byHost[h] = c
	}
	return s, nil
}

// For returns the credential for host.
func (s *Store) For(host string) (Credential, bool) {
	if s == nil {
		return Credential{}, false
	}
	c, ok := s.byHost[NormalizeHost(host)]
	return c, ok
}

// Hosts lists the hosts the store holds credentials for, sorted.
func (s *Store) Hosts() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.byHost))
	for h := range s.byHost {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (s *Store) redacted() string {
	return fmt.Sprintf("regauth.Store{hosts=%v}", s.Hosts())
}

// Format implements fmt.Formatter so a store prints its hosts only.
func (s *Store) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.redacted()) }

func (s *Store) String() string       { return s.redacted() }
func (s *Store) GoString() string     { return s.redacted() }
func (s *Store) LogValue() slog.Value { return slog.StringValue(s.redacted()) }
