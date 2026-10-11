package regauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
)

const secretPW = "pw-s3cret-value"

func TestValidateHost(t *testing.T) {
	good := []string{"ghcr.io", "GHCR.IO", "registry.example.com:5000", "127.0.0.1:5443", "localhost", "my-registry.internal", "docker.io"}
	bad := []string{"", "https://ghcr.io", "ghcr.io/org", "ghcr.io/", "user@ghcr.io", "ghcr.io:", "ghcr.io:99999", "ghcr.io:0",
		"-bad.io", "bad-.io", "a b.io", "ghcr.io?x=1", "ghcr.io#x", "[::1]:5000", "a..b"}
	for _, h := range good {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) = %v, want ok", h, err)
		}
	}
	for _, h := range bad {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) = nil, want an error", h)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"GHCR.io": "ghcr.io", "index.docker.io": "docker.io", "registry-1.docker.io": "docker.io", " docker.io ": "docker.io",
		"quay.io": "quay.io",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateSecretText(t *testing.T) {
	for _, s := range []string{"", "a b", "a\tb", "a\nb", "a\x00b"} {
		err := ValidateSecretText(s)
		if err == nil {
			t.Errorf("ValidateSecretText(%q) = nil", s)
		} else if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("error quotes the value: %v", err)
		}
	}
	if err := ValidateSecretText("ghp_abcDEF123"); err != nil {
		t.Error(err)
	}
}

func TestStoreLookupAndDuplicates(t *testing.T) {
	s, err := NewStore([]Credential{New("ghcr.io", "u", secretPW, nil), New("index.docker.io", "d", secretPW, []string{"auth.docker.io"})})
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := s.For("GHCR.io"); !ok || c.Username != "u" {
		t.Errorf("ghcr.io = %v, %v", c, ok)
	}
	for _, h := range []string{"docker.io", "registry-1.docker.io", "index.docker.io"} {
		if c, ok := s.For(h); !ok || c.Username != "d" {
			t.Errorf("%s = %v, %v", h, c, ok)
		}
	}
	if _, ok := s.For("quay.io"); ok {
		t.Error("quay.io has no credential")
	}
	var none *Store
	if _, ok := none.For("ghcr.io"); ok {
		t.Error("the nil store holds nothing")
	}
	if _, err := NewStore([]Credential{New("ghcr.io", "a", "p", nil), New("GHCR.io", "b", "q", nil)}); err == nil {
		t.Error("a host twice must be an error")
	}
	if _, err := NewStore([]Credential{New("docker.io", "a", "p", nil), New("registry-1.docker.io", "b", "q", nil)}); err == nil {
		t.Error("two spellings of Docker Hub must be an error")
	}
}

func TestAllowsTokenHost(t *testing.T) {
	c := New("ghcr.io", "u", "p", []string{"Auth.Example.com", "token.example.com:8443"})
	for host, want := range map[string]bool{
		"ghcr.io": true, "GHCR.io": true, "auth.example.com": true, "token.example.com:8443": true,
		"token.example.com": false, "evil.example.org": false, "ghcr.io:444": false, "": false,
	} {
		if got := c.AllowsTokenHost(host); got != want {
			t.Errorf("AllowsTokenHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestBasicAuthorization(t *testing.T) {
	if got := New("h.io", "user", "pass", nil).BasicAuthorization(); got != "Basic dXNlcjpwYXNz" {
		t.Errorf("got %q", got)
	}
}

func TestPasswordNeverPrinted(t *testing.T) {
	c := New("ghcr.io", "me", secretPW, []string{"t.example.com"})
	s, _ := NewStore([]Credential{c})
	var logbuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logbuf, nil)).Info("x", "cred", c, "store", s)
	slog.New(slog.NewJSONHandler(&logbuf, nil)).Info("x", "cred", c, "store", s)
	js, err := json.Marshal(map[string]any{"c": c, "cs": []Credential{c}})
	if err != nil {
		t.Fatal(err)
	}
	outs := []string{
		fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s %q %x", c, c, c, c, c, c), fmt.Sprint(&c), fmt.Sprintf("%+v", []Credential{c}),
		fmt.Sprintf("%+v", struct{ C Credential }{c}), fmt.Sprint(s), fmt.Sprintf("%+v %#v", s, s), fmt.Sprintf("%+v", struct{ S *Store }{s}),
		logbuf.String(), string(js), c.String(),
	}
	for i, o := range outs {
		if strings.Contains(o, secretPW) || strings.Contains(o, "czNjcmV0") /* base64 fragment */ {
			t.Errorf("output %d shows the password: %s", i, o)
		}
	}
	if !strings.Contains(fmt.Sprint(c), "ghcr.io") {
		t.Error("the host should still show")
	}
}

func TestScrub(t *testing.T) {
	c := New("h.io", "u", secretPW, nil)
	if got := c.Scrub("denied for " + secretPW + " twice " + secretPW); strings.Contains(got, secretPW) {
		t.Errorf("got %q", got)
	}
	if got := New("h.io", "u", "", nil).Scrub("text"); got != "text" {
		t.Errorf("got %q", got)
	}
}

func TestScrubRemovesEncodedLogins(t *testing.T) {
	c := New("h.io", "me", secretPW, nil)
	pair := "me:" + secretPW
	var forms []string
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		forms = append(forms, enc.EncodeToString([]byte(pair)))
	}
	forms = append(forms, pair, secretPW, url.QueryEscape(secretPW))
	for _, f := range forms {
		for _, text := range []string{"x " + f + " y", "Authorization: Basic " + f, `{"auth":"` + f + `"}`} {
			if got := c.Scrub(text); strings.Contains(got, f) {
				t.Errorf("Scrub(%q) = %q still holds the login", text, got)
			}
		}
	}
	for in, want := range map[string]string{
		"sent Basic dXNlcjpwYXNz.":       "sent Basic [redacted]",
		"header bearer abc.DEF-1_2~+/==": "header bearer [redacted]",
		"nothing to remove":              "nothing to remove",
	} {
		if got := c.Scrub(in); got != want {
			t.Errorf("Scrub(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubErrorKeepsTheCause(t *testing.T) {
	c := New("h.io", "me", secretPW, nil)
	cause := errors.New("token service said Basic " + base64.StdEncoding.EncodeToString([]byte("me:"+secretPW)))
	err := c.ScrubError(fmt.Errorf("registry: %w", cause))
	if strings.Contains(err.Error(), secretPW) || strings.Contains(err.Error(), "bWU6") || !errors.Is(err, cause) {
		t.Errorf("err = %v", err)
	}
	if c.ScrubError(nil) != nil {
		t.Error("nil stays nil")
	}
	plain := errors.New("nothing secret")
	if c.ScrubError(plain) != plain {
		t.Error("a clean error is returned as it is")
	}
}

func TestValidateUsername(t *testing.T) {
	for _, u := range []string{"me", "a.b@example.com", "user-1"} {
		if err := ValidateUsername(u); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"", "a:b", ":", "a b", "a\x00b", "a\nb"} {
		if err := ValidateUsername(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if err := ValidateSecretText("pa:ss"); err != nil {
		t.Errorf("a colon in a password is fine: %v", err)
	}
}

func TestPermits(t *testing.T) {
	c := New("ghcr.io", "u", "p", []string{"auth.example.com"})
	for name, tc := range map[string]struct {
		ch Challenge
		ok bool
	}{
		"basic":          {Challenge{Scheme: "basic"}, true},
		"bearer, same":   {Challenge{Scheme: "bearer", RealmHost: "ghcr.io"}, true},
		"bearer, listed": {Challenge{Scheme: "bearer", RealmHost: "AUTH.example.com"}, true},
		"bearer, other":  {Challenge{Scheme: "bearer", RealmHost: "evil.example.org"}, false},
		"none":           {Challenge{Scheme: "none"}, false},
		"other":          {Challenge{Scheme: "other"}, false},
		"empty":          {Challenge{}, false},
	} {
		ok, why := c.Permits(tc.ch)
		if ok != tc.ok || (!ok && why == "") {
			t.Errorf("%s: Permits = %v, %q", name, ok, why)
		}
	}
}
