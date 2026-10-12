package toolfetch

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingTransport counts the requests that reach the real registries.
type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

// TestLiveRegistries fetches the tools from the public registries. It needs
// the network, so it is skipped with -short.
func TestLiveRegistries(t *testing.T) {
	if testing.Short() {
		t.Skip("uses the public registries")
	}
	ct := &countingTransport{}
	dir := t.TempDir()
	// A short waiting period lets versions published a few days ago through;
	// the default period is checked separately below.
	p, err := New(Config{StorageDir: dir, Transport: ct, MinReleaseAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	type tc struct {
		name string
		req  Request
		spec func(t *testing.T, a Artifact) string // a declared hash to check, or nil
	}
	node := "24.21.0"
	cases := []tc{
		{name: "pnpm 10.34.4", req: Request{Manager: ManagerPnpm, Version: "10.34.4", Platform: PlatformAmd64, NodeVersion: node}},
		{name: "pnpm default node24", req: Request{Manager: ManagerPnpm, Version: DefaultVersion(ManagerPnpm, "node24"), Platform: PlatformAmd64, NodeVersion: node}},
		{name: "pnpm default node22", req: Request{Manager: ManagerPnpm, Version: DefaultVersion(ManagerPnpm, "node22"), Platform: PlatformAmd64, NodeVersion: "22.23.3"}},
		{name: "pnpm default node20", req: Request{Manager: ManagerPnpm, Version: DefaultVersion(ManagerPnpm, "node20"), Platform: PlatformAmd64, NodeVersion: "20.20.2"}},
		{name: "npm default node24", req: Request{Manager: ManagerNpm, Version: DefaultVersion(ManagerNpm, "node24"), Platform: PlatformAmd64, NodeVersion: node}},
		{name: "npm default node22", req: Request{Manager: ManagerNpm, Version: DefaultVersion(ManagerNpm, "node22"), Platform: PlatformAmd64, NodeVersion: "22.23.3"}},
		{name: "pnpm 12 amd64", req: Request{Manager: ManagerPnpm, Version: "12.11.2", Platform: PlatformAmd64, NodeVersion: node}},
		{name: "pnpm 12 arm64", req: Request{Manager: ManagerPnpm, Version: "12.11.2", Platform: PlatformArm64, NodeVersion: node}},
		{name: "uv amd64", req: Request{Manager: ManagerUv, Version: DefaultVersion(ManagerUv, "python3.13"), Platform: PlatformAmd64}},
		{name: "uv arm64", req: Request{Manager: ManagerUv, Version: DefaultVersion(ManagerUv, "python3.13"), Platform: PlatformArm64}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p.NewCycle()
			a, err := p.Provide(ctx, c.req)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(a.Path)
			if err != nil || info.Size() != a.Size || a.Size == 0 {
				t.Fatalf("file: %v %v", info, err)
			}
			t.Logf("%s %s: %s %d bytes entry=%s published=%s digest=%s", a.Manager, a.Version, a.Format, a.Size, a.Entry, a.PublishedAt.Format(time.RFC3339), a.RegistryDigest[:20])

			// The second request is answered from the cache, which hashes the
			// file again, without a request.
			n := ct.n.Load()
			b, err := p.Provide(ctx, c.req)
			if err != nil || b.Path != a.Path || b.SHA256 != a.SHA256 {
				t.Fatalf("hit: %+v %v", b, err)
			}
			if got := ct.n.Load(); got != n {
				t.Fatalf("the hit made %d requests", got-n)
			}
		})
	}

	t.Run("declared hash of pnpm 12 is the wrapper's", func(t *testing.T) {
		var doc struct {
			Dist struct {
				Integrity string `json:"integrity"`
			} `json:"dist"`
		}
		resp, err := http.Get("https://registry.npmjs.org/pnpm/12.11.2")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		sum, ok := decodeIntegrity(doc.Dist.Integrity)
		if !ok {
			t.Fatal("no integrity")
		}
		req := Request{Manager: ManagerPnpm, Version: "12.11.2", Platform: PlatformAmd64, NodeVersion: node, SpecHash: "sha512." + sum}
		p.NewCycle()
		a, err := p.Provide(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if a.SpecHashOf != "wrapper" || a.Wrapper == nil || a.Wrapper.SHA512 != sum || a.Entry != "pnpm" {
			t.Fatalf("artifact = %+v", a)
		}
		// The pnpm 12 executable is not the declared package.
		bad := req
		bad.SpecHash = "sha512." + a.SHA512
		p.NewCycle()
		wantErr(t, mustErr(p.Provide(ctx, bad)), ClassManual, CodeHashMismatch)
	})

	t.Run("tampered cache file is fetched again", func(t *testing.T) {
		req := Request{Manager: ManagerNpm, Version: DefaultVersion(ManagerNpm, "node24"), Platform: PlatformAmd64, NodeVersion: node}
		a, err := p.Provide(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(a.Path)
		data[len(data)/2] ^= 1
		if err := os.WriteFile(a.Path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		p.NewCycle()
		n := ct.n.Load()
		b, err := p.Provide(ctx, req)
		if err != nil || b.SHA256 != a.SHA256 || ct.n.Load() == n {
			t.Fatalf("after tampering: %+v %v (requests %d)", b, err, ct.n.Load()-n)
		}
		if h := hashFile(t, b.Path); h != a.SHA256 {
			t.Fatal("the file was not restored")
		}
	})

	t.Run("declared version is outside the policy", func(t *testing.T) {
		p.NewCycle()
		// npm 12.2.0 needs Node.js 22.22.2 or later; an older Node.js is refused.
		wantErr(t, mustErr(p.Provide(ctx, Request{Manager: ManagerNpm, Version: "12.2.0", Platform: PlatformAmd64, NodeVersion: "22.12.0"})), ClassManual, CodeVersionUnsupported)
		p.NewCycle()
		wantErr(t, mustErr(p.Provide(ctx, Request{Manager: ManagerNpm, Version: "11.999.0", Platform: PlatformAmd64, NodeVersion: node})), ClassManual, CodeVersionNotFound)
		p.NewCycle()
		wantErr(t, mustErr(p.Provide(ctx, Request{Manager: ManagerPnpm, Version: "11.28.0", Platform: PlatformAmd64, NodeVersion: "20.20.2"})), ClassManual, CodeVersionUnsupported)
	})

	t.Run("default waiting period", func(t *testing.T) {
		// The versions of the table, with the real waiting period: each is
		// either past it or, if published within three days, deferred.
		strict, err := New(Config{StorageDir: t.TempDir(), Transport: ct})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			strict.NewCycle()
			_, err := strict.Provide(ctx, c.req)
			if err == nil {
				continue
			}
			e, ok := err.(*Error)
			if !ok || e.Code != CodeTooNew || !strings.Contains(e.Detail, "can be used from") {
				t.Errorf("%s: %v", c.name, err)
			} else {
				t.Logf("%s: %s", c.name, e.Detail)
			}
		}
	})
}

func hashFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return hexOf("sha256", data)
}
