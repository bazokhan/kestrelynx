package remediation

import "testing"

func TestSemverOrder(t *testing.T) {
	// Each version is below the next.
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "2.0.0", "10.0.0"}
	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			c, ok := compareVersions(schemeSemver, ordered[i], ordered[j])
			if !ok {
				t.Fatalf("%s or %s did not parse", ordered[i], ordered[j])
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if c != want {
				t.Errorf("compare(%s, %s) = %d, want %d", ordered[i], ordered[j], c, want)
			}
		}
	}
	if c, _ := compareVersions(schemeSemver, "1.0.0+build.5", "1.0.0"); c != 0 {
		t.Errorf("build metadata took part in the order: %d", c)
	}
}

func TestSemverRejects(t *testing.T) {
	for _, s := range []string{"", "1", "1.2", "v1.2.3", "01.2.3", "1.2.3-", "1.2.3-01", "1.2.3.4", "^1.2.3", ">=1.0.0", "1.2.x", "1.2.3.4-"} {
		if _, ok := parseVersion(schemeSemver, s); ok {
			t.Errorf("%q parsed as semver", s)
		}
	}
}

func TestPEP440Order(t *testing.T) {
	ordered := []string{
		"1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1", "1.0.1", "1.1", "2.0",
		"1!0.5",
	}
	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			c, ok := compareVersions(schemePEP440, ordered[i], ordered[j])
			if !ok {
				t.Fatalf("%s or %s did not parse", ordered[i], ordered[j])
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if c != want {
				t.Errorf("compare(%s, %s) = %d, want %d", ordered[i], ordered[j], c, want)
			}
		}
	}
}

func TestPEP440Equivalences(t *testing.T) {
	for _, p := range [][2]string{
		{"1.0", "1.0.0"}, {"1.0.0", "1"}, {"1.0a1", "1.0alpha1"}, {"1.0rc1", "1.0c1"}, {"1.0.post1", "1.0-1"},
		{"1.0.post1", "1.0rev1"}, {"V1.0", "1.0"}, {"1.0.RC.1", "1.0rc1"}, {"1.0+local", "1.0+LOCAL"},
	} {
		if c, ok := compareVersions(schemePEP440, p[0], p[1]); !ok || c != 0 {
			t.Errorf("compare(%s, %s) = %d, %v; want equal", p[0], p[1], c, ok)
		}
	}
	if c, _ := compareVersions(schemePEP440, "1.0", "1.0+local"); c >= 0 {
		t.Error("a local version should sort above the public one")
	}
}

func TestPEP440Rejects(t *testing.T) {
	for _, s := range []string{"", "abc", "1.0.*", ">=1.0", "1..0", "1.0-beta-1x", "1.0 beta"} {
		if _, ok := parseVersion(schemePEP440, s); ok {
			t.Errorf("%q parsed as a PEP 440 version", s)
		}
	}
}

func TestNormalizePyName(t *testing.T) {
	for in, want := range map[string]string{
		"Django": "django", "typing_extensions": "typing-extensions", "Typing.Extensions": "typing-extensions",
		"zope.interface": "zope-interface", "a--b__c..d": "a-b-c-d", "Foo-_.Bar": "foo-bar", "requests": "requests",
	} {
		if got := normalizePyName(in); got != want {
			t.Errorf("normalizePyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func cves(fixed ...[]string) []CVERef {
	var out []CVERef
	for i, f := range fixed {
		out = append(out, CVERef{VulnID: string(rune('A'+i)) + "-CVE", FixedVers: f})
	}
	return out
}

func TestChooseTarget(t *testing.T) {
	cases := []struct {
		name      string
		sc        scheme
		installed string
		cves      []CVERef
		want      string
		reason    Reason
	}{
		{"single", schemeSemver, "4.17.20", cves([]string{"4.17.21"}), "4.17.21", ""},
		{"alternatives take the lowest above installed", schemeSemver, "4.17.20", cves([]string{"3.0.1", "4.17.21", "5.0.0"}), "4.17.21", ""},
		{"max over CVEs of the per-CVE minimum", schemeSemver, "1.0.0", cves([]string{"1.0.5"}, []string{"1.2.0", "2.0.0"}), "1.2.0", ""},
		{"prerelease sorts below its release", schemeSemver, "1.0.0", cves([]string{"2.0.0-rc.1", "2.0.0"}), "2.0.0-rc.1", ""},
		{"installed prerelease is below the release", schemeSemver, "2.0.0-beta.1", cves([]string{"2.0.0"}), "2.0.0", ""},
		{"nothing above installed", schemeSemver, "2.0.0", cves([]string{"1.9.0"}), "", ReasonNoFixedVersion},
		{"one CVE without a higher fix", schemeSemver, "2.0.0", cves([]string{"2.0.1"}, []string{"1.0.0"}), "", ReasonNoFixedVersion},
		{"unparsable fix", schemeSemver, "1.0.0", cves([]string{">=1.2"}), "", ReasonUnparsableVersion},
		{"unparsable installed", schemeSemver, "latest", cves([]string{"1.0.0"}), "", ReasonUnparsableVersion},
		{"comma separated in one string", schemeSemver, "1.0.0", cves([]string{"1.5.0, 2.0.0"}), "1.5.0", ""},
		{"python", schemePEP440, "2.31.0", cves([]string{"2.32.0"}), "2.32.0", ""},
		{"python post release", schemePEP440, "1.0", cves([]string{"1.0.post1", "1.1"}), "1.0.post1", ""},
		{"python unparsable", schemePEP440, "1.0", cves([]string{"1.0.*"}), "", ReasonUnparsableVersion},
		{"python epoch", schemePEP440, "2.0", cves([]string{"1!1.0"}), "1!1.0", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason, _ := chooseTarget(c.sc, c.installed, c.cves)
			if got != c.want || reason != c.reason {
				t.Errorf("chooseTarget = %q, %q; want %q, %q", got, reason, c.want, c.reason)
			}
		})
	}
}

func TestPySatisfies(t *testing.T) {
	cases := []struct {
		v, spec   string
		ok, evalu bool
	}{
		{"2.32.0", ">=2.0", true, true},
		{"2.32.0", ">=2.0,<3", true, true},
		{"2.32.0", ">=2.0,<2.32", false, true},
		{"2.32.0", "~=2.31", true, true},
		{"3.0.0", "~=2.31", false, true},
		{"2.32.0", "~=2.31.0", false, true},
		{"2.32.0", "!=2.32.0", false, true},
		{"2.32.0", "==2.32.0", true, true},
		{"2.32.0", "==2.31.*", false, true},
		{"2.31.4", "==2.31.*", true, true},
		{"2.31.4", "!=2.31.*", false, true},
		{"2.31.4", ">=2.0.*", false, false},
		{"2.32.0", "===2.32.0", false, false},
		{"2.32.0", ">=junk", false, false},
		{"2.32.0", "~=2", false, false},
		{"1.0", "==1.0+abc", false, true},
	}
	for _, c := range cases {
		v, _ := parsePEP440(c.v)
		ok, ev := pySatisfies(v, c.spec)
		if ok != c.ok || ev != c.evalu {
			t.Errorf("pySatisfies(%s, %q) = %v, %v; want %v, %v", c.v, c.spec, ok, ev, c.ok, c.evalu)
		}
	}
}
