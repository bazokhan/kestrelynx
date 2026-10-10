package remediation

import (
	"testing"
)

func TestNpmRangeAllows(t *testing.T) {
	cases := []struct {
		spec, ver string
		ok, eval  bool
	}{
		{"1.2.6", "1.2.6", true, true},
		{"=1.2.6", "1.2.6", true, true},
		{"v1.2.6", "1.2.6", true, true},
		{"1.2.5", "1.2.6", false, true},
		{"^1.2.5", "1.2.6", true, true},
		{"^1.2.5", "1.3.0", true, true},
		{"^1.2.5", "2.0.0", false, true},
		{"^1.2.7", "1.2.6", false, true},
		{"^0.2.3", "0.2.9", true, true},
		{"^0.2.3", "0.3.0", false, true},
		{"^0.0.3", "0.0.3", true, true},
		{"^0.0.3", "0.0.4", false, true},
		{"^0.0", "0.0.9", true, true},
		{"^0", "0.9.9", true, true},
		{"^1", "1.9.0", true, true},
		{"^1.x", "1.9.0", true, true},
		{"~1.2.5", "1.2.9", true, true},
		{"~1.2.5", "1.3.0", false, true},
		{"~1.2", "1.2.9", true, true},
		{"~1", "1.9.9", true, true},
		{"~1", "2.0.0", false, true},
		{"~>1.2.3", "1.2.4", true, true},
		{">=1.2.6", "1.2.6", true, true},
		{">1.2.6", "1.2.6", false, true},
		{">1.2", "1.2.9", false, true},
		{">1.2", "1.3.0", true, true},
		{"<1.2.6", "1.2.6", false, true},
		{"<=1.2.6", "1.2.6", true, true},
		{"<=1.2", "1.2.9", true, true},
		{"<1.2", "1.2.0", false, true},
		{">=1.0.0 <2.0.0", "1.9.9", true, true},
		{">=1.0.0 <2.0.0", "2.0.0", false, true},
		{">= 1.0.0 < 2.0.0", "1.5.0", true, true},
		{">=1.0.0   <1.2.6", "1.2.6", false, true},
		{"1.x", "1.9.9", true, true},
		{"1.X.x", "1.9.9", true, true},
		{"1.2.x", "1.2.9", true, true},
		{"1.2.x", "1.3.0", false, true},
		{"1", "1.9.9", true, true},
		{"1.2", "1.2.7", true, true},
		{"*", "9.9.9", true, true},
		{"x", "9.9.9", true, true},
		{"", "9.9.9", true, true},
		{"1.0.0 - 2.0.0", "1.5.0", true, true},
		{"1.0.0 - 2.0.0", "2.0.1", false, true},
		{"1.0.0 - 2", "2.9.9", true, true},
		{"1.0.0 - 2", "3.0.0", false, true},
		{"1.2 - 1.3", "1.3.9", true, true},
		{"^1.0.0 || ^2.0.0", "2.5.0", true, true},
		{"^1.0.0 || ^2.0.0", "3.0.0", false, true},
		{"1.2.5 || 1.2.6", "1.2.6", true, true},
		{"10.0.0", "10.0.0", true, true},
		{"^9.0.0", "10.0.0", false, true},
		// Not judged.
		{"latest", "1.2.6", false, false},
		{"next", "1.2.6", false, false},
		{"npm:other@^1", "1.2.6", false, false},
		{"file:../x", "1.2.6", false, false},
		{"git+https://github.com/a/b", "1.2.6", false, false},
		{"github:a/b", "1.2.6", false, false},
		{"workspace:*", "1.2.6", false, false},
		{"catalog:", "1.2.6", false, false},
		{"https://x.example/a.tgz", "1.2.6", false, false},
		{"^1.2.3-beta.1", "1.2.6", false, false},
		{">=1.0.0-rc.1", "1.2.6", false, false},
		{"1.x.3", "1.2.6", false, false},
		{"^01.2.3", "1.2.6", false, false},
		{"1.2.3.4", "1.2.6", false, false},
		{">*", "1.2.6", false, false},
		{"^1.2.5", "1.2.6-beta.1", false, false},
		{"^1.2.5 ||", "1.2.6", true, true},
	}
	for _, c := range cases {
		t.Run(c.spec+" @ "+c.ver, func(t *testing.T) {
			v, ok := parseSemver(c.ver)
			if !ok {
				t.Fatalf("bad test version %q", c.ver)
			}
			ok, eval := npmRangeAllows(c.spec, v)
			if ok != c.ok || eval != c.eval {
				t.Errorf("allows(%q, %s) = %v, evaluable %v; want %v, %v", c.spec, c.ver, ok, eval, c.ok, c.eval)
			}
		})
	}
}

func TestPythonRequirement(t *testing.T) {
	cases := []struct {
		in, name, constraint string
		ok                   bool
	}{
		{"urllib3", "urllib3", "", true},
		{"URLLIB3>=1.26", "urllib3", ">=1.26", true},
		{"urllib3 >= 1.26 , < 2", "urllib3", ">=1.26,<2", true},
		{"urllib3[socks,brotli]~=1.26.0", "urllib3", "~=1.26.0", true},
		{"urllib3 (>=1.26)", "urllib3", ">=1.26", true},
		{"urllib3>=1.26; python_version >= '3.8'", "urllib3", ">=1.26", true},
		{"my_pkg.name==1.0", "my-pkg-name", "==1.0", true},
		{"urllib3 @ https://x.example/u.whl", "", "", false},
		{"urllib3>=1.26 foo", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, con, ok := pythonRequirement(c.in)
		if name != c.name || con != c.constraint || ok != c.ok {
			t.Errorf("pythonRequirement(%q) = %q %q %v; want %q %q %v", c.in, name, con, ok, c.name, c.constraint, c.ok)
		}
	}
}

func TestMeetsFix(t *testing.T) {
	cases := []struct {
		sc    scheme
		v     string
		fixed []string
		ok    bool
	}{
		{schemeSemver, "1.2.8", []string{"0.2.4", "1.2.6"}, true},
		{schemeSemver, "1.2.5", []string{"0.2.4", "1.2.6"}, false},
		{schemeSemver, "0.2.9", []string{"0.2.4", "1.2.6"}, true},
		{schemeSemver, "0.2.3", []string{"0.2.4", "1.2.6"}, false},
		{schemeSemver, "2.0.0", []string{"0.2.4", "1.2.6"}, true},
		{schemeSemver, "1.9.0", []string{"2.0.0", "1.2.6"}, false},
		{schemeSemver, "1.2.9", []string{"2.0.0", "1.2.6"}, true},
		{schemeSemver, "1.2.7", []string{"1.2.6", "1.2.9"}, false},
		{schemeSemver, "1.2.9", []string{"1.2.6", "1.2.9"}, true},
		{schemeSemver, "1.3.0", []string{"1.2.6", "1.2.9"}, true},
		{schemeSemver, "4.2.0", []string{"4.1.13", "4.2.16"}, false},
		{schemeSemver, "4.2.16", []string{"4.1.13", "4.2.16"}, true},
		{schemeSemver, "4.1.20", []string{"4.1.13", "4.2.16"}, true},
		{schemeSemver, "4.3.0", []string{"4.1.13", "4.2.16"}, true},
		{schemeSemver, "1.2.7-beta.1", []string{"1.2.6"}, false},
		{schemeSemver, "1.3.0-rc.1", []string{"1.3.0-rc.1"}, true},
		{schemeSemver, "2.0.0-rc.1", []string{"1.2.6"}, false},
		{schemePEP440, "1.26.18rc1", []string{"1.26.17"}, false},
		{schemePEP440, "2.1.0", []string{"2.0.6", "1.26.17"}, true},
		{schemePEP440, "2.0.5", []string{"2.0.6", "1.26.17"}, false},
		{schemeSemver, "1.2.5", []string{"2.0.0", "1.2.6"}, false},
		{schemeSemver, "3.0.0", []string{"2.0.6, 1.26.17"}, true},
		{schemeSemver, "1.2.8", []string{"9.9.9"}, false},
		{schemeSemver, "1.2.8", nil, false},
		{schemeSemver, "x", []string{"1.0.0"}, false},
		{schemePEP440, "1.26.17", []string{"1.26.17", "2.0.6"}, true},
		{schemePEP440, "1.26.16", []string{"1.26.17", "2.0.6"}, false},
		{schemePEP440, "2.0.5", []string{"1.26.17", "2.0.6"}, false},
		{schemePEP440, "2.8.0", []string{"1.26.17", "2.0.6"}, true},
	}
	for _, c := range cases {
		if got := meetsFix(c.sc, c.v, c.fixed); got != c.ok {
			t.Errorf("meetsFix(%s, %v) = %v, want %v", c.v, c.fixed, got, c.ok)
		}
	}
}
