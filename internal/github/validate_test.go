package github

import (
	"strings"
	"testing"
)

func TestParseRepo(t *testing.T) {
	for _, s := range []string{"example/app", "a/b", "Ex-ample1/my.repo_x-y", "a/.github", "a/" + strings.Repeat("r", 100)} {
		if _, err := ParseRepo(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{
		"", "a", "a/", "/b", "a/b/c", "-a/b", "a-/b", "a--b/c", "a_b/c", "a b/c", "a/b c", "a/..", "a/.", "a/b.git",
		"a/b?x", "a/b#x", "a/b\x00", strings.Repeat("o", 40) + "/r", "a/" + strings.Repeat("r", 101), "ä/b", "a/%2e%2e",
	} {
		if _, err := ParseRepo(s); err == nil {
			t.Errorf("%q: accepted", s)
		}
	}
	r, _ := ParseRepo("Example/App")
	if r.Owner != "Example" || r.Name != "App" || r.String() != "Example/App" {
		t.Errorf("repo = %+v", r)
	}
}

func TestValidBranch(t *testing.T) {
	for _, s := range []string{"main", "release/1.x", "feature/a-b_c", "v1.0.0", "a@b", "x.y"} {
		if !ValidBranch(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{
		"", "-x", "/x", "x/", "a//b", "a..b", "a b", "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a\\b", "a\tb", "a\x7fb",
		"@", "a@{b", "x.", ".hidden", "a/.b", "a.lock", "a/b.lock", strings.Repeat("b", 256),
	} {
		if ValidBranch(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidPath(t *testing.T) {
	for _, s := range []string{"a", "a/b", "web/package.json", "dir with space/x", "ü/x", "a/.hidden/b"} {
		if !ValidPath(s, false) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{
		"", "/a", "../a", "a/..", "a/../b", "./a", "a/./b", "a//b", "a/", "a\\b", "a\x00b", "a\nb", "a\x7fb", ".", "..",
		strings.Repeat("p", 1025), "a/\xff",
	} {
		if ValidPath(s, false) {
			t.Errorf("%q accepted", s)
		}
	}
	if !ValidPath(".", true) || ValidPath(".", false) {
		t.Error("root handling wrong")
	}
	if ValidPath("", true) || ValidPath("./", true) || ValidPath("a/..", true) {
		t.Error("allowRoot must only accept \".\"")
	}
}
