package notify

import (
	"strings"
	"testing"
)

func TestBoldMrkdwn(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ghcr.io/org/app:latest", "`ghcr.io/org/app:latest`"},
		{"localhost:5000/app:1.0", "`localhost:5000/app:1.0`"},
		{"github.com/org/module", "`github.com/org/module`"},
		{"ghcr.io/org/app:latest (sha256:abcd linux/amd64)", "`ghcr.io/org/app:latest` (sha256:abcd linux/amd64)"},
		{"ghcr.io/org/app:latest — unconfirmed <x>", "`ghcr.io/org/app:latest` — unconfirmed &lt;x&gt;"},
		{"nginx:1.27", "nginx:1.27"},
		{"example-elasticsearch", "example-elasticsearch"},
		{"@babel/core", "@babel/core"},
		{"@scope.v1/pkg", "@scope.v1/pkg"},
		{"openssl", "openssl"},
		{"a&b", "a&amp;b"},
	}
	for _, c := range cases {
		if got := boldMrkdwn(c.in); got != c.want {
			t.Errorf("boldMrkdwn(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBoldMrkdwnCappedKeepsTheCodeSpanClosed(t *testing.T) {
	long := "ghcr.io/org/" + strings.Repeat("a", 300) + ":tag"
	got := boldMrkdwnCapped(long, 50)
	if !strings.HasPrefix(got, "`") || !strings.HasSuffix(got, "`") || strings.Count(got, "`") != 2 {
		t.Fatalf("boldMrkdwnCapped did not keep one closed code span: %q", got)
	}
	if utf16Len(got) > 52 {
		t.Fatalf("boldMrkdwnCapped(…, 50) is %d units long: %q", utf16Len(got), got)
	}
	if got := boldMrkdwnCapped("nginx:1.27", 50); got != "nginx:1.27" {
		t.Fatalf("a reference without a host changed: %q", got)
	}
}

func TestBoldLinesKeepRegistryNamesOutOfLinks(t *testing.T) {
	rd := renderer{msg: enMessages, lim: defaultRenderLimits}
	if got, want := rd.imageHeading("ghcr.io/org/app:latest"), "*Image: `ghcr.io/org/app:latest`*"; got != want {
		t.Errorf("imageHeading = %q, want %q", got, want)
	}
	if got, want := rd.imageHeading("nginx:1.27"), "*Image: nginx:1.27*"; got != want {
		t.Errorf("imageHeading = %q, want %q", got, want)
	}
	c := pkgCard{Name: "github.com/org/module", Ecosystem: "gobinary"}
	if got, want := c.titleLine(), "*◆ `github.com/org/module`* [gobinary]"; got != want {
		t.Errorf("titleLine = %q, want %q", got, want)
	}
}
