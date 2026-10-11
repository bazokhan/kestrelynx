//go:build live

package remediation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/regauth"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// These tests need a registry that asks for a login (the registry image with
// htpasswd authentication, served over TLS on a loopback address with a
// certificate of its own) holding kx/app:1.2.3 and kx/app:1.2.4, and a Trivy
// with its databases already downloaded. They run only with the environment
// below set:
//
//	KX_LIVE_AUTH_ADDR   host:port of the registry, e.g. 127.0.0.1:5443
//	KX_LIVE_AUTH_USER   the login's user name
//	KX_LIVE_AUTH_PWFILE a file holding the login's password
//	KX_LIVE_AUTH_CA     the registry certificate, PEM
//
//	go test -tags live -run TestLiveAuth -v ./internal/remediation
type liveAuth struct {
	addr, user, password, ca string
}

func liveAuthEnv(t *testing.T) liveAuth {
	t.Helper()
	l := liveAuth{addr: os.Getenv("KX_LIVE_AUTH_ADDR"), user: os.Getenv("KX_LIVE_AUTH_USER"), ca: os.Getenv("KX_LIVE_AUTH_CA")}
	pw, _ := os.ReadFile(os.Getenv("KX_LIVE_AUTH_PWFILE"))
	l.password = strings.TrimSpace(string(pw))
	if l.addr == "" || l.user == "" || l.password == "" || l.ca == "" {
		t.Skip("KX_LIVE_AUTH_* is not set")
	}
	return l
}

func (l liveAuth) client(t *testing.T, withLogin bool, budget *registry.Budget) *registry.Client {
	t.Helper()
	pem, err := os.ReadFile(l.ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no certificate in KX_LIVE_AUTH_CA")
	}
	_, port, _ := net.SplitHostPort(l.addr)
	o := registry.Options{
		Budget:     budget,
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}},
		AllowAddr:  func(ip net.IP, p string) bool { return ip.IsLoopback() && p == port },
	}
	if withLogin {
		st, err := regauth.NewStore([]regauth.Credential{regauth.New(l.addr, l.user, l.password, nil)})
		if err != nil {
			t.Fatal(err)
		}
		o.Auth = st
	}
	return registry.New(o)
}

func TestLiveAuthRegistryClient(t *testing.T) {
	l := liveAuthEnv(t)
	repo := l.addr + "/kx/app"
	ctx := context.Background()

	_, err := l.client(t, false, nil).ListTagsAfter(ctx, repo, "", 100)
	if !errors.Is(err, registry.ErrAuthRequired) {
		t.Fatalf("without a login: err = %v, want ErrAuthRequired", err)
	}
	t.Logf("without a login: %v", err)
	if _, err := listPinnedSeries(ctx, l.client(t, false, nil), repo, tv(t, "1.2.3"), 20); !errors.Is(err, registry.ErrAuthRequired) {
		t.Fatalf("series walk without a login: err = %v", err)
	}

	budget := registry.NewBudget(50)
	c := l.client(t, true, budget)
	list, err := listPinnedSeries(ctx, c, repo, tv(t, "1.2.3"), 20)
	if err != nil {
		t.Fatalf("with the login: %v", err)
	}
	sel := SelectPinned(tv(t, "1.2.3"), list)
	t.Logf("with the login: tags = %v, selection = %+v, tag requests = %d, http requests = %d", list.Tags, sel, list.Pages, budget.Used())
	if sel.Outcome != SelectionFound || sel.Tag != "1.2.4" {
		t.Fatalf("selection = %+v, want 1.2.4", sel)
	}
	res, err := c.Resolve(ctx, repo, "1.2.4", inventory.Platform{OS: "linux", Architecture: "amd64"})
	if err != nil || !res.PlatformVerified {
		t.Fatalf("resolve with the login: %+v, %v", res, err)
	}
	t.Logf("resolved 1.2.4: manifest %s config %s", res.ManifestDigest, res.ConfigDigest)
}

// liveScanner scans remote targets with the real Trivy and everything else
// with the fake.
type liveScanner struct {
	*fakeScanner
	trivy scanner.Trivy
}

func (s liveScanner) Scan(ctx context.Context, t scanner.ScanTarget) scanner.ImageScan {
	if t.Source == scanner.SourceRemote {
		return s.trivy.Scan(ctx, t)
	}
	return s.fakeScanner.Scan(ctx, t)
}

func TestLiveAuthPlannerAndTrivy(t *testing.T) {
	l := liveAuthEnv(t)
	t.Setenv("SSL_CERT_FILE", l.ca) // Trivy trusts the test registry's certificate
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	trivyFor := func(withLogin bool) scanner.Trivy {
		tr := scanner.Trivy{Severity: []string{"HIGH", "CRITICAL"}, SkipDBUpdate: true, Challenger: l.client(t, false, nil)}
		if withLogin {
			st, _ := regauth.NewStore([]regauth.Credential{regauth.New(l.addr, l.user, l.password, nil)})
			tr.Auth = st
		}
		return tr
	}
	conds, err := trivyFor(false).PrepareDB(ctx)
	if err != nil {
		t.Fatalf("prepare databases: %v", err)
	}

	ref := l.addr + "/kx/app:1.2.3"
	for _, withLogin := range []bool{false, true} {
		fake := newFakeScanner()
		base := configScan(ref, 'a', []scanner.Finding{finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "1"))
		fake.scans[ref] = func(scanner.ScanTarget) scanner.ImageScan { return base }
		budget := registry.NewBudget(100)
		p, err := NewPlanner(Config{
			Registry: l.client(t, withLogin, budget), Scanner: liveScanner{fake, trivyFor(withLogin)}, Prepared: conds,
			Limits: Limits{MaxCandidateScans: 3, MaxBaselineRescans: 3, MaxTagPages: 20}, Budget: budget,
			Intel: func(string) (VulnIntel, bool) { return VulnIntel{Priority: PriorityWatch}, true },
		})
		if err != nil {
			t.Fatal(err)
		}
		in := ImageInput{Scan: base, Conditions: conds, Target: scanner.ScanTarget{Subject: base.Subject, Source: scanner.SourceLocal}}
		plan := p.Plan(ctx, []ImageInput{in})
		it := item(t, plan, 0)
		t.Logf("login=%v: %s/%s %s | candidate=%v | scans=%d requests=%d", withLogin, it.Category, it.Reason, it.Detail, it.Candidate != nil, len(plan.Scans), plan.Usage.RegistryRequests)
		if !withLogin {
			if it.Category != CategoryNotComparable || it.Reason != ReasonAuthRequired {
				t.Errorf("without a login: %s/%s, want not_comparable/auth_required", it.Category, it.Reason)
			}
			continue
		}
		if it.Candidate == nil || it.Candidate.Tag != "1.2.4" {
			t.Fatalf("with the login: candidate = %+v", it.Candidate)
		}
		var candScan *ScanExecution
		for i := range plan.Scans {
			if plan.Scans[i].Role == RoleCandidate {
				candScan = &plan.Scans[i]
			}
		}
		if candScan == nil || candScan.Failure != "" || candScan.Confirmed == Unconfirmed {
			t.Fatalf("candidate scan = %+v; the remote scan with the login did not go through", candScan)
		}
		t.Logf("candidate scan: %+v", *candScan)
	}

	// The same remote scan without the login must fail.
	res, err := l.client(t, true, nil).Resolve(ctx, l.addr+"/kx/app", "1.2.4", inventory.Platform{OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	dg, _ := inventory.ParseDigest(inventory.DigestRegistry, res.ManifestDigest)
	target := scanner.ScanTarget{
		Subject:  inventory.ImageSubject{Ref: l.addr + "/kx/app:1.2.4", Key: inventory.EntityKey{Digest: dg, Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}}, Resolved: true},
		Registry: inventory.RegistryRef{Repository: l.addr + "/kx/app", Digest: dg}, Source: scanner.SourceRemote,
	}
	anon := trivyFor(false).Scan(ctx, target)
	if anon.Err == nil {
		t.Fatal("an anonymous remote scan of the private image succeeded")
	}
	msg := anon.Err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	t.Logf("anonymous remote scan: %s", msg)
	if strings.Contains(anon.Err.Error(), l.password) {
		t.Error("the error shows the password")
	}
	authed := trivyFor(true).Scan(ctx, target)
	if authed.Err != nil || !authed.Pinned {
		t.Fatalf("remote scan with the login: pinned=%v err=%v", authed.Pinned, authed.Err)
	}
	t.Logf("remote scan with the login: pinned=%v repoDigests=%v", authed.Pinned, authed.RegistryDigests)
}
