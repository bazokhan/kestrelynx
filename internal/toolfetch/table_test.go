package toolfetch

import "testing"

func TestRangeAllows(t *testing.T) {
	cases := []struct {
		spec, v string
		allowed bool
		valid   bool
	}{
		{"^20.17.0 || >=22.9.0", "24.21.0", true, true},
		{"^20.17.0 || >=22.9.0", "20.16.0", false, true},
		{"^22.22.2 || ^24.15.0 || >=26.0.0", "24.21.0", true, true},
		{"^22.22.2 || ^24.15.0 || >=26.0.0", "22.12.0", false, true},
		{"^22.22.2 || ^24.15.0 || >=26.0.0", "25.1.0", false, true},
		{">=18.*", "24.21.0", true, true},
		{">=18.12", "18.11.9", false, true},
		{">=22.13", "22.13.0", true, true},
		{"<20.12", "20.11.1", true, true},
		{"20 - 22", "22.5.0", true, true},
		{"~22.9.0", "22.10.0", false, true},
		{"*", "1.0.0", true, true},
		{"", "1.0.0", true, true},
		{"^1.0.0-beta.1", "1.0.0", false, false},
		{"latest", "1.0.0", false, false},
	}
	for _, c := range cases {
		v, _ := parseExact(c.v)
		got, valid := rangeAllows(c.spec, v)
		if got != c.allowed || valid != c.valid {
			t.Errorf("%q vs %s = %v,%v; want %v,%v", c.spec, c.v, got, valid, c.allowed, c.valid)
		}
	}
}

func TestParseExact(t *testing.T) {
	for _, s := range []string{"1.2.3", "0.13.0", "12.0.0"} {
		if _, ok := parseExact(s); !ok {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "1.2", "1.2.3.4", "01.2.3", "1.2.3-rc.1", "1.2.3+b", "v1.2.3", "1.2.x", "1.2.3rc1", "9999999999.0.0"} {
		if _, ok := parseExact(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestDefaultVersions(t *testing.T) {
	for _, c := range []struct {
		m       Manager
		runtime string
		set     bool
	}{
		{ManagerPnpm, "node24", true}, {ManagerNpm, "node24", true},
		{ManagerPnpm, "node22", true}, {ManagerNpm, "node22", true},
		{ManagerPnpm, "node20", true}, {ManagerNpm, "node20", false},
		{ManagerUv, "python3.13", true}, {ManagerUv, "node24", false}, {ManagerPnpm, "python3.13", false},
		{ManagerPnpm, "node18", false},
	} {
		v := DefaultVersion(c.m, c.runtime)
		if (v != "") != c.set {
			t.Errorf("DefaultVersion(%s, %s) = %q", c.m, c.runtime, v)
		}
		if v != "" {
			if _, ok := parseExact(v); !ok {
				t.Errorf("DefaultVersion(%s, %s) = %q is not an exact version", c.m, c.runtime, v)
			}
		}
	}
}

func TestResolveEntries(t *testing.T) {
	cases := []struct {
		m       Manager
		v       string
		entry   string
		node    bool
		wrapper bool
		name    string
	}{
		{ManagerNpm, "9.9.4", "bin/npm-cli.js", true, false, "npm"},
		{ManagerNpm, "12.2.0", "bin/npm-cli.js", true, false, "npm"},
		{ManagerPnpm, "9.15.9", "bin/pnpm.cjs", true, false, "pnpm"},
		{ManagerPnpm, "10.34.6", "bin/pnpm.cjs", true, false, "pnpm"},
		{ManagerPnpm, "11.28.5", "bin/pnpm.mjs", true, false, "pnpm"},
		{ManagerPnpm, "12.11.2", "pnpm", false, true, "@pnpm/exe.linux-arm64"},
		{ManagerUv, "0.13.0", "uv-0.13.0.data/scripts/uv", false, false, "uv"},
	}
	for _, c := range cases {
		tg, err := resolve(Request{Manager: c.m, Version: c.v, Platform: PlatformArm64})
		if err != nil {
			t.Fatalf("%s %s: %v", c.m, c.v, err)
		}
		if tg.entry != c.entry || tg.runNode != c.node || (tg.wrapper != nil) != c.wrapper || tg.main.name != c.name {
			t.Errorf("%s %s: %+v", c.m, c.v, tg)
		}
	}
	tg, _ := resolve(Request{Manager: ManagerPnpm, Version: "12.0.0", Platform: PlatformAmd64})
	if tg.main.name != "@pnpm/exe.linux-x64" {
		t.Errorf("amd64 exe = %s", tg.main.name)
	}
}
