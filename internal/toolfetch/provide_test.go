package toolfetch

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func npmReq(version string) Request {
	return Request{Manager: ManagerNpm, Version: version, Platform: PlatformAmd64, NodeVersion: "24.21.0"}
}

func TestNpmFetchAndCacheHit(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x", "package.json": "{}"}, engines: "^20.17.0 || >=22.9.0", published: old})
	dir := t.TempDir()
	p := f.provider(t, dir, nil)

	a, err := p.Provide(context.Background(), npmReq("11.21.0"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != FormatNpmTgz || a.Entry != "bin/npm-cli.js" || !a.RunWithNode || a.Size != int64(len(body)) {
		t.Fatalf("artifact = %+v", a)
	}
	if a.SHA512 != hexOf("sha512", body) || a.SHA256 != hexOf("sha256", body) || a.RegistryDigest != "sha512-"+a.SHA512 {
		t.Fatalf("hashes = %+v", a)
	}
	if !filepath.IsAbs(a.Path) || !strings.HasPrefix(a.Path, filepath.Join(dir, "tools")) {
		t.Fatalf("path = %s", a.Path)
	}
	st, err := os.Stat(a.Path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("blob mode = %v %v", st, err)
	}
	for _, d := range []string{filepath.Join(dir, "tools"), filepath.Join(dir, "tools", "blobs")} {
		if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %v", d, st.Mode())
		}
	}
	if st, _ := os.Stat(filepath.Join(dir, "tools", "index.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("index mode = %v", st.Mode())
	}

	before := f.total()
	b, err := p.Provide(context.Background(), npmReq("11.21.0"))
	if err != nil || b.Path != a.Path {
		t.Fatalf("second = %+v %v", b, err)
	}
	if f.total() != before {
		t.Fatalf("a cache hit made %d requests", f.total()-before)
	}
	// A new Provider over the same directory finds the entry too.
	p2 := f.provider(t, dir, nil)
	if _, err := p2.Provide(context.Background(), npmReq("11.21.0")); err != nil || f.total() != before {
		t.Fatalf("reopened: %v, %d requests", err, f.total()-before)
	}
}

func TestVersionNotFound(t *testing.T) {
	f := newFakeRegistry(t)
	p := f.provider(t, t.TempDir(), nil)
	_, err := p.Provide(context.Background(), npmReq("11.99.0"))
	wantErr(t, err, ClassManual, CodeVersionNotFound)
}

func TestPolicyRefusals(t *testing.T) {
	f := newFakeRegistry(t)
	p := f.provider(t, t.TempDir(), nil)
	cases := []struct {
		name string
		req  Request
	}{
		{"pre-release", Request{Manager: ManagerNpm, Version: "11.0.0-rc.1", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"range", Request{Manager: ManagerNpm, Version: "^11.0.0", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"npm 8", Request{Manager: ManagerNpm, Version: "8.19.4", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"npm 13", Request{Manager: ManagerNpm, Version: "13.0.0", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"pnpm 8", Request{Manager: ManagerPnpm, Version: "8.15.9", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"pnpm 13", Request{Manager: ManagerPnpm, Version: "13.0.0", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"uv old", Request{Manager: ManagerUv, Version: "0.12.21", Platform: PlatformAmd64}},
		{"uv pre-release", Request{Manager: ManagerUv, Version: "0.13.0rc1", Platform: PlatformAmd64}},
		{"platform", Request{Manager: ManagerNpm, Version: "11.21.0", Platform: "linux/s390x", NodeVersion: "24.21.0"}},
		{"manager", Request{Manager: "yarn", Version: "4.0.0", Platform: PlatformAmd64, NodeVersion: "24.21.0"}},
		{"node version", Request{Manager: ManagerNpm, Version: "11.21.0", Platform: PlatformAmd64, NodeVersion: "24"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := p.Provide(context.Background(), c.req)
			wantErr(t, err, ClassManual, CodeVersionUnsupported)
		})
	}
	if f.total() != 0 {
		t.Fatalf("refusals made %d requests", f.total())
	}
	_, err := p.Provide(context.Background(), Request{Manager: ManagerUv, Version: "0.13.0", Platform: PlatformAmd64, SpecHash: "sha256." + strings.Repeat("a", 64)})
	wantErr(t, err, ClassManual, CodeHashUnsupported)
}

func TestEnginesMustAllowNode(t *testing.T) {
	f := newFakeRegistry(t)
	f.addNpm(npmPkg{name: "npm", version: "12.2.0", files: map[string]string{"bin/npm-cli.js": "x"}, engines: "^22.22.2 || ^24.15.0 || >=26.0.0", published: old})
	p := f.provider(t, t.TempDir(), nil)
	r := npmReq("12.2.0")
	r.NodeVersion = "22.12.0"
	e := wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassManual, CodeVersionUnsupported)
	if !strings.Contains(e.Detail, "22.12.0") {
		t.Fatalf("detail = %s", e.Detail)
	}
	r.NodeVersion = "24.21.0"
	if _, err := p.Provide(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// A hit applies the check again, for another job's Node.js.
	r.NodeVersion = "22.12.0"
	before := f.total()
	wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassManual, CodeVersionUnsupported)
	if f.total() != before {
		t.Fatal("the cache hit went to the network")
	}
}

func mustErr(_ Artifact, err error) error { return err }

func TestTooNewAndUnknownTime(t *testing.T) {
	f := newFakeRegistry(t)
	now := time.Now()
	f.addNpm(npmPkg{name: "npm", version: "11.30.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: now.Add(-71 * time.Hour)})
	f.addNpm(npmPkg{name: "npm", version: "11.31.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: now.Add(-73 * time.Hour)})
	f.addNpm(npmPkg{name: "npm", version: "11.32.0", files: map[string]string{"bin/npm-cli.js": "x"}, noTime: true})
	p := f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.30.0"))), ClassDeferred, CodeTooNew)
	if f.count("/-/npm-11.30.0.tgz") != 0 {
		t.Fatal("a version that is too new was downloaded")
	}
	if _, err := p.Provide(context.Background(), npmReq("11.31.0")); err != nil {
		t.Fatal(err)
	}
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.32.0"))), ClassDeferred, CodeTooNew)
}

func TestSpecHashDoesNotWaiveAge(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.30.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: time.Now().Add(-time.Hour)})
	p := f.provider(t, t.TempDir(), nil)
	r := npmReq("11.30.0")
	r.SpecHash = "sha512." + hexOf("sha512", body)
	wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassDeferred, CodeTooNew)
}

func TestRegistryHashMismatchLeavesNothing(t *testing.T) {
	f := newFakeRegistry(t)
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old, badIntegrity: true})
	dir := t.TempDir()
	p := f.provider(t, dir, nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassManual, CodeHashMismatch)
	for _, sub := range []string{"blobs", "tmp"} {
		ents, _ := os.ReadDir(filepath.Join(dir, "tools", sub))
		if len(ents) != 0 {
			t.Fatalf("%s holds %d files after a mismatch", sub, len(ents))
		}
	}
}

func TestSpecHash(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "pnpm", version: "10.34.4", files: map[string]string{"bin/pnpm.cjs": "x"}, published: old})
	p := f.provider(t, t.TempDir(), nil)
	r := Request{Manager: ManagerPnpm, Version: "10.34.4", Platform: PlatformAmd64, NodeVersion: "24.21.0"}

	r.SpecHash = "sha512." + strings.Repeat("0", 128)
	wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassManual, CodeHashMismatch)

	for _, algo := range []string{"sha1", "sha224", "sha256", "sha384", "sha512"} {
		r.SpecHash = algo + "." + hexOf(algo, body)
		a, err := p.Provide(context.Background(), r)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if a.SpecHashChecked != r.SpecHash || a.SpecHashOf != "artifact" || a.Entry != "bin/pnpm.cjs" {
			t.Fatalf("%s: %+v", algo, a)
		}
	}
	// A hit is checked against the declared hash too.
	r.SpecHash = "sha256." + strings.Repeat("0", 64)
	wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassManual, CodeHashMismatch)

	for _, bad := range []string{"sha512", "sha512.zz", "md5." + strings.Repeat("a", 32), "sha256." + strings.Repeat("g", 64), "sha256." + strings.Repeat("a", 63)} {
		r.SpecHash = bad
		wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassManual, CodeHashUnsupported)
	}
}

func TestPnpm12WrapperAndExe(t *testing.T) {
	f := newFakeRegistry(t)
	exe := f.addNpm(npmPkg{name: "@pnpm/exe.linux-arm64", version: "12.10.1", files: map[string]string{"pnpm": "ELF"}, published: old})
	wrapper := f.addNpm(npmPkg{name: "pnpm", version: "12.10.1", files: map[string]string{"pnpm": "wrapper", "bin/pnpm.mjs": "x"}, engines: ">=18.*", published: old})
	p := f.provider(t, t.TempDir(), nil)
	r := Request{Manager: ManagerPnpm, Version: "12.10.1", Platform: PlatformArm64, NodeVersion: "24.21.0"}

	a, err := p.Provide(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if a.Entry != "pnpm" || a.RunWithNode || a.SHA512 != hexOf("sha512", exe) || a.SpecHashOf != "" || a.Wrapper != nil {
		t.Fatalf("artifact = %+v", a)
	}
	if f.count("/-/pnpm-12.10.1.tgz") != 0 {
		t.Fatal("the wrapper was downloaded without a declared hash")
	}

	// A declared hash is the wrapper's. The wrapper is fetched alone.
	r.SpecHash = "sha512." + hexOf("sha512", wrapper)
	a, err = p.Provide(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if a.SpecHashOf != "wrapper" || a.Wrapper == nil || a.Wrapper.SHA512 != hexOf("sha512", wrapper) || a.SHA512 != hexOf("sha512", exe) {
		t.Fatalf("artifact = %+v", a)
	}
	if f.count("/-/@pnpm_exe.linux-arm64-12.10.1.tgz") != 1 {
		t.Fatalf("the exe was downloaded %d times", f.count("/-/@pnpm_exe.linux-arm64-12.10.1.tgz"))
	}
	before := f.total()
	if _, err := p.Provide(context.Background(), r); err != nil || f.total() != before {
		t.Fatalf("hit: %v, %d requests", err, f.total()-before)
	}
	// The exe's hash is not what a declaration is checked against.
	r.SpecHash = "sha512." + hexOf("sha512", exe)
	wantErr(t, mustErr(p.Provide(context.Background(), r)), ClassManual, CodeHashMismatch)
}

func TestAliasedDocumentRefused(t *testing.T) {
	f := newFakeRegistry(t)
	body := tgz(t, map[string]string{"package/bin/npm-cli.js": "x"})
	f.addNpmBytes(npmPkg{name: "npm", version: "11.21.0", published: old}, body)
	// The registry answers for npm@11.21.0 with another package's document.
	f.serveJSON("/npm/11.21.0", map[string]any{"name": "evil", "version": "11.21.0", "dist": map[string]any{"tarball": f.srv.URL + "/-/npm-11.21.0.tgz", "integrity": sha512b64(body)}})
	p := f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassManual, CodeMetadataInvalid)
}

func TestTarballAddressRefused(t *testing.T) {
	f := newFakeRegistry(t)
	body := tgz(t, map[string]string{"package/bin/npm-cli.js": "x"})
	for _, tb := range []string{"http://registry.npmjs.org/x.tgz", "https://user:pw@registry.npmjs.org/x.tgz", "https://evil.example/x.tgz", "https://registry.npmjs.org:8443/x.tgz"} {
		f.addNpmBytes(npmPkg{name: "npm", version: "11.21.0", published: old}, body)
		f.serveJSON("/npm/11.21.0", map[string]any{"name": "npm", "version": "11.21.0", "dist": map[string]any{"tarball": tb, "integrity": sha512b64(body)}})
		p := f.provider(t, t.TempDir(), nil)
		wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassManual, CodeMetadataInvalid)
	}
}

func TestRedirects(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	f.serveBytes("/real.tgz", body)

	// To a host that is not allowed.
	f.handle("/-/npm-11.21.0.tgz", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/x.tgz", http.StatusFound)
	})
	p := f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchFailed)

	// To plain HTTP, to a user-info address and to another port.
	for _, to := range []string{"http://" + strings.TrimPrefix(f.srv.URL, "https://") + "/real.tgz", "https://u:p@" + strings.TrimPrefix(f.srv.URL, "https://") + "/real.tgz", "https://127.0.0.1:1/real.tgz"} {
		f.handle("/-/npm-11.21.0.tgz", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, to, http.StatusFound) })
		p = f.provider(t, t.TempDir(), nil)
		wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchFailed)
	}

	// Within the allowed host, up to five hops.
	hop := func(n int) {
		for i := 0; i < n; i++ {
			next := "/hop" + string(rune('a'+i+1))
			if i == n-1 {
				next = "/real.tgz"
			}
			f.handle("/hop"+string(rune('a'+i)), func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, next, http.StatusFound) })
		}
		f.handle("/-/npm-11.21.0.tgz", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/hopa", http.StatusFound) })
	}
	hop(4) // the tarball address, then 5 redirects in all
	p = f.provider(t, t.TempDir(), nil)
	if _, err := p.Provide(context.Background(), npmReq("11.21.0")); err != nil {
		t.Fatalf("5 redirects: %v", err)
	}
	hop(5) // 6 redirects
	p = f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchFailed)
}

func TestServerErrorsAreDeferredAndRetriedOnce(t *testing.T) {
	f := newFakeRegistry(t)
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	var mu sync.Mutex
	n := 0
	f.handle("/npm/11.21.0", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		http.Error(w, "busy", http.StatusServiceUnavailable)
	})
	p := f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchFailed)
	if n != 2 {
		t.Fatalf("the document was requested %d times, want 2", n)
	}
	// 429 is deferred too, 403 as well.
	f.handle("/npm/11.21.0", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusForbidden) })
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchFailed)
}

func TestOversizedBodies(t *testing.T) {
	f := newFakeRegistry(t)
	big := func(n int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			chunk := make([]byte, 1<<20)
			for i := range chunk {
				chunk[i] = ' '
			}
			for i := 0; i < n; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}
	}
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})

	f.handle("/-/npm-11.21.0.tgz", big(65))
	p := f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassManual, CodeArtifactInvalid)

	f.handle("/npm/11.21.0", big(3))
	p = f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassManual, CodeMetadataInvalid)

	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	f.handle("/npm", big(33))
	p = f.provider(t, t.TempDir(), nil)
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassManual, CodeMetadataInvalid)
}

func TestArchiveShapes(t *testing.T) {
	f := newFakeRegistry(t)
	p := f.provider(t, t.TempDir(), nil)
	provide := func(v string) error { p.NewCycle(); return mustErr(p.Provide(context.Background(), npmReq(v))) }
	// No entry.
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"package.json": "{}"}, published: old})
	wantErr(t, provide("11.21.0"), ClassManual, CodeArtifactInvalid)
	// Outside package/.
	f.addNpmBytes(npmPkg{name: "npm", version: "11.22.0", published: old}, tgz(t, map[string]string{"package/bin/npm-cli.js": "x", "other/x": "y"}))
	wantErr(t, provide("11.22.0"), ClassManual, CodeArtifactInvalid)
	// A symbolic link.
	f.addNpmBytes(npmPkg{name: "npm", version: "11.23.0", published: old}, tgzWithLink(t))
	wantErr(t, provide("11.23.0"), ClassManual, CodeArtifactInvalid)
	// Too many files.
	many := map[string]string{"package/bin/npm-cli.js": "x"}
	for i := 0; i < maxArchiveFile; i++ {
		many["package/f/"+strings.Repeat("a", 3)+itoa(i)] = ""
	}
	f.addNpmBytes(npmPkg{name: "npm", version: "11.24.0", published: old}, tgz(t, many))
	wantErr(t, provide("11.24.0"), ClassManual, CodeArtifactInvalid)
	// Expands to too much: 170 MiB of zeros compresses to a few hundred kB.
	f.addNpmBytes(npmPkg{name: "npm", version: "11.25.0", published: old}, tgz(t, map[string]string{"package/bin/npm-cli.js": "x", "package/big": strings.Repeat("\x00", 170<<20)}))
	wantErr(t, provide("11.25.0"), ClassManual, CodeArtifactInvalid)
	// Not gzip.
	f.addNpmBytes(npmPkg{name: "npm", version: "11.26.0", published: old}, []byte("not an archive"))
	wantErr(t, provide("11.26.0"), ClassManual, CodeArtifactInvalid)
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}
	return string(b)
}

func TestCacheTamperIsRefetched(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	p := f.provider(t, t.TempDir(), nil)
	a, err := p.Provide(context.Background(), npmReq("11.21.0"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		t.Helper()
		p.NewCycle()
		b, err := p.Provide(context.Background(), npmReq("11.21.0"))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		got, _ := os.ReadFile(b.Path)
		if string(got) != string(body) {
			t.Fatalf("%s: the file was not restored", label)
		}
	}
	// Same size, different bytes.
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)/2] ^= 0xff
	if err := os.WriteFile(a.Path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	n := f.count("/-/npm-11.21.0.tgz")
	check("bit flip")
	if f.count("/-/npm-11.21.0.tgz") != n+1 {
		t.Fatal("the tampered file was not fetched again")
	}
	// Truncated.
	os.WriteFile(a.Path, body[:10], 0o600)
	check("truncated")
	// Removed.
	os.Remove(a.Path)
	check("removed")
	// Replaced by a link to a file with the right bytes.
	other := filepath.Join(t.TempDir(), "copy")
	os.WriteFile(other, body, 0o600)
	os.Remove(a.Path)
	os.Symlink(other, a.Path)
	check("symlink")
	if st, _ := os.Lstat(a.Path); st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the link was left in the cache")
	}
}

func TestIndexDamageIsEmptyIndex(t *testing.T) {
	f := newFakeRegistry(t)
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	dir := t.TempDir()
	p := f.provider(t, dir, nil)
	if _, err := p.Provide(context.Background(), npmReq("11.21.0")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "tools", "index.json"), []byte("{not json"), 0o600)
	p = f.provider(t, dir, nil)
	if _, err := p.Provide(context.Background(), npmReq("11.21.0")); err != nil {
		t.Fatal(err)
	}
}

func TestCacheFullAndEviction(t *testing.T) {
	f := newFakeRegistry(t)
	mk := func(v string) []byte {
		return f.addNpmBytes(npmPkg{name: "npm", version: v, published: old}, tgz(t, map[string]string{"package/bin/npm-cli.js": noise(v, 5000)}))
	}
	b1, b2, b3 := mk("11.21.0"), mk("11.22.0"), mk("11.23.0")
	dir := t.TempDir()
	p := f.provider(t, dir, nil)
	limit := int64(len(b1)+len(b2)) + 2048
	p.cache.max = limit
	p.reserve = int64(len(b3))

	a1, err := p.Provide(context.Background(), npmReq("11.21.0"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provide(context.Background(), npmReq("11.22.0")); err != nil {
		t.Fatal(err)
	}
	// Both are in use: the third finds no room and is deferred before any
	// download.
	p.Release(Artifact{SHA256: ""})
	n := f.count("/-/npm-11.23.0.tgz")
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.23.0"))), ClassDeferred, CodeCacheFull)
	if f.count("/-/npm-11.23.0.tgz") != n {
		t.Fatal("a full cache still downloaded")
	}
	// Releasing the older one lets it go; the newer stays.
	p.Release(a1)
	a3, err := p.Provide(context.Background(), npmReq("11.23.0"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a1.Path); !os.IsNotExist(err) {
		t.Fatal("the released, oldest file was not evicted")
	}
	if _, err := os.Stat(a3.Path); err != nil {
		t.Fatal(err)
	}
	if u := p.cache.usage(); u > limit {
		t.Fatalf("usage %d is over the capacity %d", u, limit)
	}
	_ = b3
}

func TestCacheCapacityCountsDebris(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	dir := t.TempDir()
	p := f.provider(t, dir, nil)
	p.reserve = int64(len(body))
	p.cache.max = int64(len(body)) + 2048
	// An orphaned blob and an old temporary file use the room.
	os.WriteFile(filepath.Join(dir, "tools", "blobs", strings.Repeat("ab", 32)), make([]byte, 1500), 0o600)
	old := filepath.Join(dir, "tools", "tmp", "dl-old")
	os.WriteFile(old, make([]byte, 1500), 0o600)
	os.Chtimes(old, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))
	if p.cache.usage() < 3000 {
		t.Fatal("debris is not counted")
	}
	if _, err := p.Provide(context.Background(), npmReq("11.21.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the stale temporary file stayed")
	}
	// A recent temporary file (a download in progress) is not removed.
	fresh := filepath.Join(dir, "tools", "tmp", "dl-fresh")
	os.WriteFile(fresh, make([]byte, 100), 0o600)
	p.cache.makeRoom(p.cache.max, nil)
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("a fresh temporary file was removed")
	}
}

func TestConcurrentSameKeyFetchesOnce(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	f.handle("/-/npm-11.21.0.tgz", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write(body)
	})
	p := f.provider(t, t.TempDir(), nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	paths := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := p.Provide(context.Background(), npmReq("11.21.0"))
			errs <- err
			paths <- a.Path
		}()
	}
	wg.Wait()
	close(errs)
	close(paths)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("/-/npm-11.21.0.tgz"); n != 1 {
		t.Fatalf("the tarball was downloaded %d times", n)
	}
}

func TestConcurrentOtherKeys(t *testing.T) {
	f := newFakeRegistry(t)
	for _, v := range []string{"11.21.0", "11.22.0", "11.23.0"} {
		f.addNpm(npmPkg{name: "npm", version: v, files: map[string]string{"bin/npm-cli.js": v}, published: old})
	}
	p := f.provider(t, t.TempDir(), nil)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		v := []string{"11.21.0", "11.22.0", "11.23.0"}[i%3]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Provide(context.Background(), npmReq(v)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// The index is whole and holds all three.
	p2 := f.provider(t, p.cache.dir[:len(p.cache.dir)-len("/tools")], nil)
	if len(p2.cache.idx.Entries) != 3 {
		t.Fatalf("index has %d entries", len(p2.cache.idx.Entries))
	}
}

func TestFetchBudget(t *testing.T) {
	f := newFakeRegistry(t)
	for i := 0; i < 5; i++ {
		f.addNpm(npmPkg{name: "npm", version: "11.2" + itoa(i) + ".0", files: map[string]string{"bin/npm-cli.js": "x" + itoa(i)}, published: old})
	}
	clock := time.Now()
	p := f.provider(t, t.TempDir(), func(c *Config) { c.Now = func() time.Time { return clock } })
	// Failures count: three versions the registry does not have.
	for i := 0; i < 3; i++ {
		wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.9"+itoa(i)+".0"))), ClassManual, CodeVersionNotFound)
	}
	if _, err := p.Provide(context.Background(), npmReq("11.20.0")); err != nil {
		t.Fatal(err)
	}
	// A cache hit costs nothing.
	if _, err := p.Provide(context.Background(), npmReq("11.20.0")); err != nil {
		t.Fatal(err)
	}
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchBudget)
	p.NewCycle()
	if _, err := p.Provide(context.Background(), npmReq("11.21.0")); err != nil {
		t.Fatal(err)
	}
	// Time passing does not renew the count; only a new cycle does.
	for i := 0; i < 3; i++ {
		p.Provide(context.Background(), npmReq("11.9"+itoa(i)+".0"))
	}
	clock = clock.Add(cycleTime + time.Minute)
	n := f.total()
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.22.0"))), ClassDeferred, CodeFetchBudget)
	if f.total() != n {
		t.Fatal("a spent budget still made requests")
	}
}

func TestFetchTimeBudget(t *testing.T) {
	f := newFakeRegistry(t)
	body := f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	f.addNpm(npmPkg{name: "npm", version: "11.22.0", files: map[string]string{"bin/npm-cli.js": "y"}, published: old})

	// A download that outlasts the cycle's time is cut off and deferred as a
	// spent budget, not as a failure of the registry.
	f.handle("/-/npm-11.21.0.tgz", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
			w.Write(body)
		case <-r.Context().Done():
		}
	})
	p := f.provider(t, t.TempDir(), nil)
	p.cycleTime = 300 * time.Millisecond
	start := time.Now()
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeFetchBudget)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the fetch ran %s past a 300ms budget", d)
	}
	// The time is the cycle's: what is left is all the next fetch gets, and
	// with none left it does not start.
	time.Sleep(350 * time.Millisecond)
	n := f.total()
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.22.0"))), ClassDeferred, CodeFetchBudget)
	if f.total() != n {
		t.Fatal("a fetch started with no time left")
	}
	// A new cycle gives the time again.
	p.NewCycle()
	p.cycleTime = time.Minute
	if _, err := p.Provide(context.Background(), npmReq("11.22.0")); err != nil {
		t.Fatal(err)
	}
	// A cache hit needs no time.
	p.cycleTime = time.Nanosecond
	time.Sleep(time.Millisecond)
	if _, err := p.Provide(context.Background(), npmReq("11.22.0")); err != nil {
		t.Fatal(err)
	}
	// The caller's own cancellation stays a failure of the request.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.NewCycle()
	p.cycleTime = time.Minute
	wantErr(t, mustErr(p.Provide(ctx, npmReq("11.23.0"))), ClassDeferred, CodeFetchFailed)
}

func TestUvWheels(t *testing.T) {
	f := newFakeRegistry(t)
	files := func(v string) map[string]string {
		return map[string]string{"uv-" + v + ".data/scripts/uv": "ELF", "uv-" + v + ".dist-info/METADATA": "x"}
	}
	amd := wheel(t, files("0.13.0"))
	arm := wheel(t, files("0.13.0"))
	arm = append(arm[:len(arm):len(arm)], 0) // not byte-identical to the amd64 wheel, still a zip
	_ = arm
	arm = wheel(t, map[string]string{"uv-0.13.0.data/scripts/uv": "ELF-arm", "uv-0.13.0.dist-info/METADATA": "x"})
	musl := wheel(t, map[string]string{"uv-0.13.0.data/scripts/uv": "ELF-musl"})
	f.addUv("0.13.0", old, map[string][]byte{
		"uv-0.13.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl":                         amd,
		"uv-0.13.0-py3-none-manylinux_2_28_aarch64.whl":                                             arm,
		"uv-0.13.0-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64.whl": musl,
		"uv-0.13.0-py3-none-musllinux_1_1_x86_64.whl":                                               musl,
		"uv-0.13.0-py3-none-win_amd64.whl":                                                          musl,
	})
	p := f.provider(t, t.TempDir(), nil)
	a, err := p.Provide(context.Background(), Request{Manager: ManagerUv, Version: "0.13.0", Platform: PlatformAmd64})
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != FormatWheel || a.Entry != "uv-0.13.0.data/scripts/uv" || a.RunWithNode || a.SHA256 != hexOf("sha256", amd) || a.RegistryDigest != "sha256-"+a.SHA256 {
		t.Fatalf("amd64 = %+v", a)
	}
	b, err := p.Provide(context.Background(), Request{Manager: ManagerUv, Version: "0.13.0", Platform: PlatformArm64})
	if err != nil {
		t.Fatal(err)
	}
	if b.SHA256 != hexOf("sha256", arm) || b.Path == a.Path {
		t.Fatalf("arm64 = %+v", b)
	}
}

func TestUvWheelProblems(t *testing.T) {
	f := newFakeRegistry(t)
	good := wheel(t, map[string]string{"uv-0.13.0.data/scripts/uv": "x"})
	name := "uv-0.13.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
	again := func(p *Provider, r Request) error { p.NewCycle(); return mustErr(p.Provide(context.Background(), r)) }
	req := Request{Manager: ManagerUv, Version: "0.13.0", Platform: PlatformAmd64}

	// Too new.
	f.addUv("0.13.0", time.Now().Add(-time.Hour), map[string][]byte{name: good})
	p := f.provider(t, t.TempDir(), nil)
	wantErr(t, again(p, req), ClassDeferred, CodeTooNew)

	// No wheel for the platform.
	f.addUv("0.13.0", old, map[string][]byte{"uv-0.13.0-py3-none-win_amd64.whl": good})
	wantErr(t, again(p, req), ClassManual, CodeVersionNotFound)

	// The wheel lacks the executable.
	f.addUv("0.13.0", old, map[string][]byte{name: wheel(t, map[string]string{"other": "x"})})
	wantErr(t, again(p, req), ClassManual, CodeArtifactInvalid)

	// The bytes differ from the listed sha256.
	f.addUv("0.13.0", old, map[string][]byte{name: good})
	f.serveBytes("/files/"+name, wheel(t, map[string]string{"uv-0.13.0.data/scripts/uv": "y"}))
	wantErr(t, again(p, req), ClassManual, CodeHashMismatch)

	// Yanked.
	f.addUv("0.13.0", old, map[string][]byte{name: good})
	f.handle("/pypi/uv/0.13.0/json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"info":{"version":"0.13.0"},"urls":[{"filename":"`+name+`","url":"`+f.srv.URL+`/files/`+name+`","size":1,"yanked":true,"packagetype":"bdist_wheel","upload_time_iso_8601":"2020-01-01T00:00:00Z","digests":{"sha256":"`+strings.Repeat("a", 64)+`"}}]}`)
	})
	wantErr(t, again(p, req), ClassManual, CodeVersionUnsupported)
}

func TestHitReappliesAge(t *testing.T) {
	f := newFakeRegistry(t)
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: time.Now().Add(-100 * time.Hour)})
	dir := t.TempDir()
	if _, err := f.provider(t, dir, nil).Provide(context.Background(), npmReq("11.21.0")); err != nil {
		t.Fatal(err)
	}
	p := f.provider(t, dir, func(c *Config) { c.MinReleaseAge = 200 * time.Hour })
	wantErr(t, mustErr(p.Provide(context.Background(), npmReq("11.21.0"))), ClassDeferred, CodeTooNew)
}

func TestCancelledContext(t *testing.T) {
	f := newFakeRegistry(t)
	f.addNpm(npmPkg{name: "npm", version: "11.21.0", files: map[string]string{"bin/npm-cli.js": "x"}, published: old})
	p := f.provider(t, t.TempDir(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantErr(t, mustErr(p.Provide(ctx, npmReq("11.21.0"))), ClassDeferred, CodeFetchFailed)
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("no storage dir accepted")
	}
	if _, err := New(Config{StorageDir: t.TempDir(), CacheMaxSize: -1}); err == nil {
		t.Fatal("negative size accepted")
	}
}

// noise is text that does not compress, the same for the same seed.
func noise(seed string, n int) string {
	h := sha512.Sum512([]byte(seed))
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(hex.EncodeToString(h[:]))
		h = sha512.Sum512(h[:])
	}
	return b.String()[:n]
}
