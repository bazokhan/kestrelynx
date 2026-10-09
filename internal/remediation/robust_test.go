package remediation

import (
	"fmt"
	"strings"
	"testing"
)

// noPanic runs f and fails the test if it panics.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

func TestParseTOMLMalformedNumbersAndStructure(t *testing.T) {
	for name, doc := range map[string]string{
		"underscore only":        "x = _\n",
		"underscore number":      "x = 1__0\n",
		"leading underscore":     "x = _1\n",
		"trailing underscore":    "x = 1_\n",
		"leading zero":           "x = 01\n",
		"zero underscore":        "x = 0_1\n",
		"signed hex":             "x = +0x1\n",
		"empty hex":              "x = 0x\n",
		"bad octal":              "x = 0o8\n",
		"float without digits":   "x = 1.\n",
		"float leading dot":      "x = .5\n",
		"exponent without digit": "x = 1e\n",
		"integer overflow":       "x = 99999999999999999999\n",
		"plus only":              "x = +\n",
		"minus only":             "x = -\n",
		"dash date":              "x = 2026-13\n",
		"stray date text":        "x = 2026-10-09T\n",
		"redefined table":        "[a]\nx = 1\n[a]\ny = 2\n",
		"redefined subtable":     "[a.b]\nx = 1\n[a.b]\ny = 2\n",
		"header over dotted":     "a.b = 1\n[a]\nc = 2\n",
		"dotted over header":     "[a]\nx = 1\n[b]\n[a.c]\n[a]\n",
		"extend inline table":    "a = { x = 1 }\na.y = 2\n",
		"header into inline":     "a = { x = 1 }\n[a.b]\n",
		"header over inline":     "a = { x = 1 }\n[a]\n",
		"append to static array": "a = [1]\n[[a]]\nx = 1\n",
		"static array as table":  "a = [{ x = 1 }]\n[a.b]\n",
		"table array over table": "[a]\n[[a]]\n",
		"inline duplicate key":   "a = { x = 1, x = 2 }\n",
		"unterminated inline":    "a = { x = 1\n",
		"empty key":              " = 1\n",
		"lone bracket":           "[\n",
		"lone quote":             "\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			noPanic(t, name, func() {
				if _, err := parseTOML([]byte(doc)); err == nil {
					t.Errorf("parsed %q", doc)
				}
			})
		})
	}
}

func TestParseTOMLNumberGrammarAccepts(t *testing.T) {
	doc := "a = 0\nb = -17\nc = 1_000\nd = 0xDEAD_beef\ne = 0o755\nf = 0b1010\ng = 3.14\nh = 1e10\ni = -2.5E-3\nj = 6_0.1_5\nk = +1\nl = inf\nm = -inf\nn = 07:32:00\no = 1979-05-27\np = 1979-05-27 07:32:00Z\n"
	got, err := parseTOML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != int64(0) || got["b"] != int64(-17) || got["c"] != int64(1000) || got["d"] != int64(0xdeadbeef) ||
		got["e"] != int64(0o755) || got["f"] != int64(10) || got["g"] != 3.14 || got["h"] != 1e10 || got["j"] != 60.15 || got["k"] != int64(1) {
		t.Errorf("numbers = %v", got)
	}
}

func TestParseTOMLTablesStillWork(t *testing.T) {
	doc := "[a]\nx = 1\n[a.b]\ny = 2\n[c.d]\nz = 3\n[c]\nw = 4\n[[p]]\nn = 1\n[p.sub]\nk = 1\n[[p]]\nn = 2\n[p.sub]\nk = 2\n"
	got, err := parseTOML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	ps := got["p"].([]any)
	if len(ps) != 2 || ps[1].(map[string]any)["sub"].(map[string]any)["k"] != int64(2) {
		t.Errorf("array of tables with sub-tables = %v", got["p"])
	}
	if got["c"].(map[string]any)["w"] != int64(4) || got["c"].(map[string]any)["d"].(map[string]any)["z"] != int64(3) {
		t.Errorf("a table named after its implicit parents = %v", got["c"])
	}
}

// garbageInputs are inputs that must make a parser return an error or a
// value, never panic: every prefix of the fixtures, and mangled copies.
func garbageInputs() []string {
	var out []string
	for _, doc := range []string{npmLockV3, npmManifest, pnpmLock, pnpmManifest, uvLock, uvPyproject, requirements} {
		for i := 0; i <= len(doc); i += 3 {
			out = append(out, doc[:i], doc[i:])
		}
		out = append(out, strings.ReplaceAll(doc, "=", "_"), strings.ReplaceAll(doc, "\n", ""), strings.ReplaceAll(doc, "\"", ""),
			strings.ReplaceAll(doc, ":", ""), strings.ReplaceAll(doc, "{", "["), strings.ToUpper(doc))
	}
	out = append(out, "", "\x00", "\xff\xfe", "=", "[", "[[", "]]", "{", "}", "x = _", "x = [[[[[[[[[[", "a.b.c.d = ", "\"\"\"", "'''")
	return out
}

func TestParsersNeverPanicOnGarbage(t *testing.T) {
	for i, in := range garbageInputs() {
		b := []byte(in)
		noPanic(t, fmt.Sprintf("input %d", i), func() {
			parseTOML(b)
			parseNpm(b, b)
			parseNpm([]byte(npmManifest), b)
			parsePnpm(b, b)
			parsePnpm([]byte(pnpmManifest), b)
			parseUv(b, b)
			parseUv([]byte(uvPyproject), b)
			parseUv(b, []byte(uvLock))
			parseRequirements(b)
			parseVersion(schemeSemver, in)
			parseVersion(schemePEP440, in)
			pySatisfies(pyVersion{release: []string{"1"}}, in)
			npmrcProblem(b)
		})
	}
}

func FuzzParseTOML(f *testing.F) {
	for _, s := range []string{uvLock, uvPyproject, "x = _", "a = { b = 1 }\n[a.c]\n", "x = 0_1", "[[a]]\n[a.b]\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		parseTOML([]byte(s))
	})
}

func FuzzParseRequirements(f *testing.F) {
	f.Add(requirements)
	f.Add("a==1 ; (")
	f.Fuzz(func(t *testing.T, s string) {
		parseRequirements([]byte(s))
	})
}

func TestVersionsWithHugeNumbers(t *testing.T) {
	big := strings.Repeat("9", 40)
	bigger := "1" + strings.Repeat("0", 40)
	for _, c := range []struct {
		sc   scheme
		a, b string
		want int
	}{
		{schemeSemver, big + ".0.0", bigger + ".0.0", -1},
		{schemeSemver, "1." + bigger + ".0", "1." + big + ".0", 1},
		{schemeSemver, "1.0." + big, "1.0." + big, 0},
		{schemeSemver, "1.0.0-" + big, "1.0.0-" + bigger, -1},
		{schemePEP440, big, bigger, -1},
		{schemePEP440, "1." + bigger, "1." + big, 1},
		{schemePEP440, "1!0", "0!" + bigger, 1},
		{schemePEP440, "1.0a" + big, "1.0a" + bigger, -1},
		{schemePEP440, "1.0.post" + bigger, "1.0.post" + big, 1},
		{schemePEP440, "1.0.dev" + big, "1.0.dev" + big, 0},
		{schemePEP440, "1.0+" + big, "1.0+" + bigger, -1},
		{schemePEP440, "0001.00", "1", 0},
	} {
		got, ok := compareVersions(c.sc, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("compare(%.30s, %.30s) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
		if back, _ := compareVersions(c.sc, c.b, c.a); back != -c.want {
			t.Errorf("compare is not antisymmetric for %.30s and %.30s", c.a, c.b)
		}
	}
	if tgt, reason, _ := chooseTarget(schemeSemver, "1.0.0", cves([]string{bigger + ".0.0"})); tgt != bigger+".0.0" || reason != "" {
		t.Errorf("a huge target = %.30s, %q", tgt, reason)
	}
}

func TestPySatisfiesSpecExamples(t *testing.T) {
	cases := []struct {
		v, spec string
		ok      bool
	}{
		// ">V" does not allow a post-release of V unless V is one.
		{"1.7.1", ">1.7", true},
		{"1.7.0.post1", ">1.7", false},
		{"1.7.post2", ">1.7.post1", true},
		{"1.7+local", ">1.7", false},
		{"1.8.post1", ">1.7", true},
		// "<V" does not allow a pre-release of V unless V is one.
		{"1.6", "<1.7", true},
		{"1.7rc1", "<1.7", false},
		{"1.7.dev1", "<1.7", false},
		{"1.7a1", "<1.7b1", true},
		{"1.6rc1", "<1.7", true},
		// Compatible release: same epoch and prefix.
		{"2.2", "~=2.2", true},
		{"2.9", "~=2.2", true},
		{"3.0", "~=2.2", false},
		{"1.4.5", "~=1.4.5", true},
		{"1.4.9", "~=1.4.5", true},
		{"1.5.0", "~=1.4.5", false},
		{"1.4.4", "~=1.4.5", false},
		{"2.9", "~=2.2.post3", true},
		{"2.2.post4", "~=2.2.post3", true},
		{"2.2", "~=2.2.post3", false},
		{"1!2.5", "~=1!2.2", true},
		{"2.5", "~=1!2.2", false},
		{"1!2.5", "~=2.2", false},
		// Prefix matching.
		{"1.1.5", "==1.1.*", true},
		{"1.2.0", "==1.1.*", false},
		{"1.1.post1", "==1.1.*", true},
		{"1.2", "!=1.1.*", true},
		// Plain comparisons and combinations.
		{"2.0", ">=1.0,<3.0", true},
		{"3.0", ">=1.0,<3.0", false},
		{"1.0", "==1.0.0", true},
		{"1.0", "!=1.0", false},
	}
	for _, c := range cases {
		v, ok := parsePEP440(c.v)
		if !ok {
			t.Fatalf("%s did not parse", c.v)
		}
		got, evaluable := pySatisfies(v, c.spec)
		if !evaluable || got != c.ok {
			t.Errorf("%s satisfies %q = %v (evaluable %v), want %v", c.v, c.spec, got, evaluable, c.ok)
		}
	}
}
