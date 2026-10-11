package inventory

import "testing"

func TestRepositoryOf(t *testing.T) {
	hex := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		ref, repo, tag, digest string
		ok                     bool
	}{
		{"ghcr.io/kitsunetrail/kestrelynx:sha-abc", "ghcr.io/kitsunetrail/kestrelynx", "sha-abc", "", true},
		{"registry.example:5000/team/app:1.2", "registry.example:5000/team/app", "1.2", "", true},
		{"registry.example:5000/team/app", "registry.example:5000/team/app", "", "", true},
		{"[::1]:5000/team/app:a", "[::1]:5000/team/app", "a", "", true},
		{"[2001:db8::1]/team/app", "[2001:db8::1]/team/app", "", "", true},
		{"[::1]:5000/app", "[::1]:5000/app", "", "", true},
		{"[::1/app", "", "", "", false},
		{"[]:5000/app", "", "", "", false},
		{"localhost:5000/app", "localhost:5000/app", "", "", true},
		{"app", "app", "", "", true},
		{"app:latest", "app", "latest", "", true},
		{"repo/app@" + hex, "repo/app", "", hex, true},
		{"repo/app:v1@" + hex, "repo/app", "v1", hex, true},
		{hex, "", "", "", false},
		{"", "", "", "", false},
		{"Repo/App:1", "", "", "", false},
		{"repo/app:", "", "", "", false},
		{"repo/app@sha256:short", "", "", "", false},
		{"repo//app:1", "", "", "", false},
		{" app", "", "", "", false},
	}
	for _, tc := range cases {
		repo, ok := RepositoryOf(tc.ref)
		if ok != tc.ok || repo != tc.repo {
			t.Errorf("RepositoryOf(%q) = %q,%v; want %q,%v", tc.ref, repo, ok, tc.repo, tc.ok)
		}
		if got := TagOf(tc.ref); got != tc.tag {
			t.Errorf("TagOf(%q) = %q; want %q", tc.ref, got, tc.tag)
		}
		if got := DigestOf(tc.ref); got != tc.digest {
			t.Errorf("DigestOf(%q) = %q; want %q", tc.ref, got, tc.digest)
		}
	}
}

func TestRepositoryKey(t *testing.T) {
	a, _ := RepositoryKey("app:1")
	b, _ := RepositoryKey("docker.io/library/app:2")
	c, _ := RepositoryKey("library/app")
	if a != b || b != c || a != "docker.io/library/app" {
		t.Errorf("got %q %q %q", a, b, c)
	}
	d, _ := RepositoryKey("team/app")
	e, _ := RepositoryKey("docker.io/team/app:1")
	if d != e || d == a {
		t.Errorf("got %q %q", d, e)
	}
	x, _ := RepositoryKey("registry.example:5000/app")
	y, _ := RepositoryKey("registry.example/app")
	if x == y {
		t.Errorf("port must be kept: %q %q", x, y)
	}
	if _, ok := RepositoryKey("sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); ok {
		t.Error("bare digest must not yield a key")
	}
}

func TestRepositoryKey_IPv6(t *testing.T) {
	a, ok1 := RepositoryKey("[::1]:5000/team/app:a")
	b, ok2 := RepositoryKey("[::1]:5000/team/app:b")
	c, _ := RepositoryKey("[::1]:5001/team/app:a")
	if !ok1 || !ok2 || a != b || a == c {
		t.Errorf("got %q %q %q", a, b, c)
	}
}

func TestHasRegistryHost(t *testing.T) {
	for ref, want := range map[string]bool{
		"nginx":                       false,
		"nginx:1.25.3":                false,
		"team/app:1":                  false,
		"regfis-infra-elasticsearch":  false,
		"ghcr.io/org/app:latest":      true,
		"docker.io/library/nginx":     true,
		"localhost/app":               true,
		"localhost:5000/app:1":        true,
		"registry.example.com:5000/a": true,
		"":                            false,
		"sha256:abc":                  false,
	} {
		if got := HasRegistryHost(ref); got != want {
			t.Errorf("HasRegistryHost(%q) = %v, want %v", ref, got, want)
		}
	}
}
