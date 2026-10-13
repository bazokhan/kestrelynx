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
		{ManagerPnpm, "node27", true}, {ManagerUv, "python3.16", true},
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

func TestNodeEnginesOfTheManagers(t *testing.T) {
	cases := []struct {
		manager Manager
		version string
		want    string
		known   bool
	}{
		{ManagerPnpm, "9.15.9", ">=18.12.0", true},
		{ManagerPnpm, "10.34.6", ">=18.12.0", true},
		{ManagerPnpm, "11.28.5", ">=22.13.0", true},
		{ManagerPnpm, "12.11.2", ">=18.0.0", true},
		{ManagerNpm, "9.9.4", "^14.17.0 || ^16.13.0 || >=18.0.0", true},
		{ManagerNpm, "10.9.4", "^18.17.0 || >=20.5.0", true},
		{ManagerNpm, "11.21.0", "^20.17.0 || >=22.9.0", true},
		{ManagerNpm, "12.2.0", "^22.22.2 || ^24.15.0 || >=26.0.0", true},
		{ManagerNpm, "13.0.0", "", false},
		{ManagerPnpm, "8.15.9", "", false},
		{ManagerUv, "0.13.0", "", false},
		{ManagerNpm, "11", "", false},
	}
	for _, c := range cases {
		got, known := NodeEngines(c.manager, c.version)
		if got != c.want || known != c.known {
			t.Errorf("NodeEngines(%s, %s) = %q, %v; want %q, %v", c.manager, c.version, got, known, c.want, c.known)
		}
	}
	for _, m := range []Manager{ManagerNpm, ManagerPnpm} {
		for _, r := range []string{"node20", "node22", "node24", "node26", "node27"} {
			if d := DefaultVersion(m, r); d != "" {
				if _, known := NodeEngines(m, d); !known {
					t.Errorf("no engines.node for the default %s %s of %s", m, d, r)
				}
			}
		}
	}
}

func TestDefaultVersionIsPerLanguageWithRuntimeOverrides(t *testing.T) {
	for _, c := range []struct {
		manager Manager
		runtime string
		want    string
	}{
		{ManagerPnpm, "node24", "11.28.5"},
		{ManagerNpm, "node27", "11.21.0"}, // a runtime the table gains takes the language's
		{ManagerPnpm, "node30", "11.28.5"},
		{ManagerPnpm, "node20", "10.34.6"}, // overridden
		{ManagerNpm, "node20", ""},
		{ManagerUv, "python3.16", "0.13.0"},
		{ManagerUv, "python3.9", "0.13.0"},
		{ManagerUv, "node24", ""}, // a manager of the other language
		{ManagerPnpm, "python3.13", ""},
		{ManagerPnpm, "node", ""},
		{ManagerPnpm, "", ""},
		{ManagerPnpm, "ruby3", ""},
	} {
		if got := DefaultVersion(c.manager, c.runtime); got != c.want {
			t.Errorf("DefaultVersion(%s, %s) = %q, want %q", c.manager, c.runtime, got, c.want)
		}
	}
}
