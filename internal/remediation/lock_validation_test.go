package remediation

import (
	"strings"
	"testing"
)

func TestParseTOMLDepthLimit(t *testing.T) {
	arr := func(n int) string { return "x = " + strings.Repeat("[", n) + strings.Repeat("]", n) + "\n" }
	inl := func(n int) string { return "x = " + strings.Repeat("{a=", n) + "1" + strings.Repeat("}", n) + "\n" }
	mixed := func(n int) string {
		return "x = " + strings.Repeat("[{a=", n/2) + "1" + strings.Repeat("}]", n/2) + "\n"
	}
	dotted := func(n int) string { return strings.TrimSuffix(strings.Repeat("a.", n), ".") + " = 1\n" }
	header := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("a.", n), ".") + "]\nx = 1\n" }
	for name, f := range map[string]func(int) string{"array": arr, "inline table": inl, "mixed": mixed, "dotted key": dotted, "header": header} {
		t.Run(name, func(t *testing.T) {
			noPanic(t, name, func() {
				if _, err := parseTOML([]byte(f(maxTOMLDepth))); err != nil {
					t.Errorf("depth %d (the limit) was rejected: %v", maxTOMLDepth, err)
				}
				for _, n := range []int{maxTOMLDepth + 2, 1000, 200000} {
					if _, err := parseTOML([]byte(f(n))); err == nil {
						t.Errorf("depth %d was accepted", n)
					}
				}
			})
		})
	}
	// Unterminated deep input fails without recursing past the limit too.
	noPanic(t, "unterminated", func() {
		if _, err := parseTOML([]byte("x = " + strings.Repeat("[", 500000))); err == nil {
			t.Error("accepted")
		}
		if _, err := parseTOML([]byte("x = " + strings.Repeat("{a=", 500000))); err == nil {
			t.Error("accepted")
		}
	})
}

func TestParseTOMLArrayOfTablesIsNotRedefined(t *testing.T) {
	for name, doc := range map[string]string{
		"table after array":  "[[a]]\nx = 1\n[a]\ny = 2\n",
		"table after sub":    "[[a]]\n[a.child]\n[a]\n",
		"package then table": "[[package]]\nname = \"x\"\n[package]\nname = \"y\"\n",
		"array after table":  "[a]\nx = 1\n[[a]]\n",
		"nested then table":  "[[a.b]]\n[a.b]\n",
	} {
		if _, err := parseTOML([]byte(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	got, err := parseTOML([]byte("[[a]]\nx = 1\n[a.child]\ny = 2\n[[a]]\nx = 3\n[a.child]\ny = 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	as := got["a"].([]any)
	if len(as) != 2 || as[1].(map[string]any)["child"].(map[string]any)["y"] != int64(4) {
		t.Errorf("sub-tables of the last element = %v", got["a"])
	}
	// The same in a lockfile.
	_, err = parseUv([]byte(uvPyproject), []byte(uvLock+"\n[package]\nname = \"again\"\n"))
	mustUnsupported(t, err, ReasonUnparsableSource)
}

func TestNpmrcProblem(t *testing.T) {
	cases := []struct {
		name string
		rc   string
		bad  bool
	}{
		{"public", "registry=https://registry.npmjs.org/\n", false},
		{"public no slash", "registry=https://registry.npmjs.org", false},
		{"spaces around", "  registry  =  https://registry.npmjs.org/  \n", false},
		{"trailing semicolon comment", "registry=https://registry.npmjs.org/ ; the default\n", false},
		{"trailing hash comment", "registry=https://registry.npmjs.org/ # the default\n", false},
		{"comment without space", "registry=https://registry.npmjs.org/;x\n", false},
		{"comment lines and blanks", "; a\n# b\n\n  # c\nregistry=https://registry.npmjs.org/\n", false},
		{"quoted value", "registry=\"https://registry.npmjs.org/\"\n", false},
		{"single quoted value", "registry='https://registry.npmjs.org/' ; c\n", false},
		{"quoted key", "\"registry\"=https://registry.npmjs.org/\n", false},
		{"single quoted key", "'registry' = https://registry.npmjs.org/\n", false},
		{"CRLF", "registry=https://registry.npmjs.org/\r\nfoo=bar\r\n", false},
		{"other settings", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nsave-exact=true\nfund=false\nflag\n", false},
		{"private", "registry=https://npm.corp.example/\n", true},
		{"private after comment", "registry=https://npm.corp.example/ ; was npmjs\n", true},
		{"quoted private key", "\"registry\"=https://npm.corp.example/\n", true},
		{"single quoted private key", "'registry'=https://npm.corp.example/\n", true},
		{"scoped private", "@corp:registry=https://npm.corp.example/\n", true},
		{"quoted scoped key", "\"@corp:registry\"=https://npm.corp.example/\n", true},
		{"scoped public is fine", "@corp:registry=https://registry.npmjs.org/\n", false},
		{"registry without value", "registry\n", true},
		{"empty registry", "registry=\n", true},
		{"http", "registry=http://registry.npmjs.org/\n", true},
		{"environment", "registry=${REG}\n", true},
		{"hash inside value hides nothing", "registry=https://npm.corp.example/#https://registry.npmjs.org/\n", true},
		{"section", "[global]\nregistry=https://npm.corp.example/\n", true},
		{"unterminated quote", "registry=\"https://registry.npmjs.org/\n", true},
		{"junk after quoted value", "registry=\"https://registry.npmjs.org/\" extra\n", true},
		{"escape in unquoted value", "registry=https://registry.npmjs.org/\\n\n", true},
		{"quote in unquoted key", "reg\"istry=x\n", true},
		{"no key", "=value\n", true},
		{"quoted key then junk", "\"registry\" junk\n", true},
		{"garbage", "\x00\x01\n", false},
		{"lone CR breaks lines", "fund=false\rregistry=https://private.example/", true},
		{"CR then public", "fund=false\rregistry=https://registry.npmjs.org/\r", false},
		{"CR comment", "; note\rregistry=https://private.example/\n", true},
		{"quote inside quotes", "'\"registry\"'=https://private.example/\n", true},
		{"double quote inside quotes", "\"'registry'\"=https://private.example/\n", true},
		{"escaped quote in key", "\"reg\\\"istry\"=x\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			noPanic(t, c.name, func() {
				got := npmrcProblem([]byte(c.rc))
				if (got != "") != c.bad {
					t.Errorf("npmrcProblem(%q) = %q, want a problem: %v", c.rc, got, c.bad)
				}
			})
		})
	}
}

func TestPythonSpecifierGrammar(t *testing.T) {
	v, _ := parsePEP440("1.0")
	for _, spec := range []string{
		"==1.0rc1.*", "==1.0.post1.*", "==1.0.dev1.*", "==1.0+local.*", ">=1.0.*", "<1.*", "~=1.0.*", "!=1.0a1.*",
		">=1.0+local", "<=1.0+local", "~=1.0+local", ">1.0+abc", "<1.0+abc",
		"~=1", "~=1!1", "===1.0", "==", ">=", "=1.0", "~=1.0.*", "== 1.0 .*",
	} {
		if _, ev := pySatisfies(v, spec); ev {
			t.Errorf("%q was judged", spec)
		}
	}
	for _, spec := range []string{"==1.0", "==1.*", "==1!1.*", "!=1.0.*", "==1.0+local", "!=1.0+local", "~=1.0", "~=1!1.0", ">=1.0", ">1.0rc1", "<=1.0.post1"} {
		if _, ev := pySatisfies(v, spec); !ev {
			t.Errorf("%q was not judged", spec)
		}
	}
	// requirements.txt takes the grammar too: a clause that breaks it makes
	// the file unsupported, while arbitrary equality is kept for a person.
	for _, line := range []string{"foo==1.0rc1.*", "foo>=1.0+local", "foo~=1", "foo>=1.*"} {
		_, err := parseRequirements([]byte(line + "\n"))
		mustUnsupported(t, err, ReasonUnsupportedRequirements)
	}
	l, err := parseRequirements([]byte("foo===1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := match(t, l, pyFinding("CVE-1", "foo", "1.0", "1.1"))[0]
	if p.Action != ActionManual || p.Reason != ReasonRangeNotEvaluable {
		t.Errorf("arbitrary equality = %+v", p)
	}
}

func TestParseUvWheelsAreValidated(t *testing.T) {
	const good = `{ url = "https://files.pythonhosted.org/certifi.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", size = 2 }`
	orig := "wheels = [\n    " + good + ",\n]"
	if !strings.Contains(uvLock, orig) {
		t.Fatal("fixture changed")
	}
	with := func(block string) string { return strings.Replace(uvLock, orig, block, 1) }
	for name, block := range map[string]string{
		"false":           "wheels = [false]",
		"empty table":     "wheels = [{}]",
		"mixed":           "wheels = [" + good + ", {}]",
		"mixed with bool": "wheels = [true, " + good + "]",
		"string":          `wheels = ["certifi.whl"]`,
		"no hash":         `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", size = 2 }]`,
		"bad hash":        `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = "md5:aa" }]`,
		"hash not string": `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = 5 }]`,
		"http url":        `wheels = [{ url = "http://files.pythonhosted.org/certifi.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]`,
		"url not string":  `wheels = [{ url = 5, hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]`,
		"path only":       `wheels = [{ path = "certifi.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]`,
		"no location":     `wheels = [{ hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseUv([]byte(uvPyproject), []byte(with(block)))
			mustUnsupported(t, err, ReasonUnparsableSource)
		})
	}
	// The url must be an https location on the registry's host, and the hash
	// exactly 64 lower-case hex digits.
	h64 := strings.Repeat("a", 64)
	for name, block := range map[string]string{
		"empty host":      `wheels = [{ url = "https:///certifi.whl", hash = "sha256:` + h64 + `" }]`,
		"wrong host":      `wheels = [{ url = "https://evil.example/certifi.whl", hash = "sha256:` + h64 + `" }]`,
		"lookalike host":  `wheels = [{ url = "https://files.pythonhosted.org.evil.example/certifi.whl", hash = "sha256:` + h64 + `" }]`,
		"userinfo host":   `wheels = [{ url = "https://files.pythonhosted.org@evil.example/certifi.whl", hash = "sha256:` + h64 + `" }]`,
		"unparsable url":  `wheels = [{ url = "https://files.pythonhosted.org/%zz", hash = "sha256:` + h64 + `" }]`,
		"short hash":      `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = "sha256:aa" }]`,
		"long hash":       `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = "sha256:` + h64 + `a" }]`,
		"upper case hash": `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = "sha256:` + strings.ToUpper(h64) + `" }]`,
		"non hex hash":    `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = "sha256:` + strings.Repeat("g", 64) + `" }]`,
		"other algorithm": `wheels = [{ url = "https://files.pythonhosted.org/certifi.whl", hash = "sha512:` + h64 + `" }]`,
	} {
		t.Run("strict "+name, func(t *testing.T) {
			_, err := parseUv([]byte(uvPyproject), []byte(with(block)))
			mustUnsupported(t, err, ReasonUnparsableSource)
		})
	}
	if _, err := parseUv([]byte(uvPyproject), []byte(with(`wheels = [{ url = "https://files.pythonhosted.org/packages/ab/cd/certifi.whl", hash = "sha256:`+h64+`", size = 1 }]`))); err != nil {
		t.Errorf("a valid wheel: %v", err)
	}
	// A package from another registry has its wheels on that registry's host.
	priv := strings.Replace(uvLock, `url = "https://pypi.corp.example/privpkg.whl"`, `url = "https://files.pythonhosted.org/privpkg.whl"`, 1)
	if priv == uvLock {
		t.Fatal("fixture changed")
	}
	_, err := parseUv([]byte(uvPyproject), []byte(priv))
	mustUnsupported(t, err, ReasonUnparsableSource)

	// No wheels at all is sdist-only, not an error.
	for _, block := range []string{"wheels = []", ""} {
		l, err := parseUv([]byte(uvPyproject), []byte(with(block)))
		if err != nil {
			t.Fatalf("%q: %v", block, err)
		}
		if o := l.lookup("certifi").occs[0]; o.ManualReason != ReasonSdistOnly {
			t.Errorf("%q: certifi = %+v", block, o)
		}
	}
	if l, err := parseUv([]byte(uvPyproject), []byte(with("wheels = ["+good+", "+good+"]"))); err != nil || l.lookup("certifi").occs[0].ManualReason != "" {
		t.Errorf("valid wheels: %v", err)
	}
}

func TestManifestShapeIsValidated(t *testing.T) {
	validNpmLock := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`
	for name, m := range map[string]string{
		"null":               `null`,
		"array":              `[]`,
		"string":             `"x"`,
		"number":             `1`,
		"empty":              ``,
		"deps null":          `{"dependencies":null}`,
		"deps array":         `{"dependencies":[]}`,
		"deps string":        `{"dependencies":"x"}`,
		"dev deps number":    `{"devDependencies":{"a":1}}`,
		"optional deps null": `{"optionalDependencies":null}`,
		"peer deps list":     `{"peerDependencies":["a"]}`,
		"dep value object":   `{"dependencies":{"a":{"b":"c"}}}`,
		"dep value null":     `{"dependencies":{"lodash":null}}`,
		"dev value null":     `{"devDependencies":{"lodash":null}}`,
		"dep value number":   `{"dependencies":{"lodash":4}}`,
		"dep value bool":     `{"optionalDependencies":{"lodash":true}}`,
		"dep value array":    `{"peerDependencies":{"lodash":["4"]}}`,
	} {
		t.Run("npm "+name, func(t *testing.T) {
			_, err := parseNpm([]byte(m), []byte(validNpmLock))
			mustUnsupported(t, err, ReasonUnparsableSource)
		})
		t.Run("pnpm "+name, func(t *testing.T) {
			_, err := parsePnpm([]byte(m), []byte(pnpmLock))
			mustUnsupported(t, err, ReasonUnparsableSource)
		})
	}
	// Valid shapes still pass.
	if _, err := parseNpm([]byte(`{}`), []byte(`{"lockfileVersion":3,"packages":{"":{}}}`)); err != nil {
		t.Errorf("an empty manifest object: %v", err)
	}
	if _, err := parseNpm([]byte(npmManifest), []byte(validNpmLock)); err != nil {
		t.Error(err)
	}
}

func TestLanguagePlan_NullManifestIsManual(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	for _, lock := range []struct{ name, file, content string }{
		{"npm", "package-lock.json", npmLockV3},
		{"pnpm", "pnpm-lock.yaml", pnpmLock},
	} {
		gh := newFakeGitHub()
		gh.put("ex/app", ".", "package.json", "null")
		gh.put("ex/app", ".", lock.file, lock.content)
		it := langPlan(t, gh, deps, nil, in).LanguageItems[0]
		if it.Category != CategoryManual || it.Reason != ReasonUnparsableSource {
			t.Errorf("%s: %s / %s (%s)", lock.name, it.Category, it.Reason, it.Detail)
		}
	}
}
