package remediation

import (
	"errors"
	"strings"
	"testing"
)

const npmManifest = `{"name":"backend","version":"1.0.0","dependencies":{"express":"^4.18.2","lodash":"^4.17.20"},"devDependencies":{"jest":"^29.0.0"}}`

const npmLockV3 = `{
  "name": "backend",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "backend",
      "version": "1.0.0",
      "dependencies": {"express": "^4.18.2", "lodash": "^4.17.20", "mylib": "github:x/mylib", "shared": "file:../shared", "aliased": "npm:real-pkg@1"},
      "devDependencies": {"jest": "^29.0.0"}
    },
    "node_modules/aliased": {"name": "real-pkg", "version": "1.0.0", "resolved": "https://registry.npmjs.org/real-pkg/-/real-pkg-1.0.0.tgz", "integrity": "sha512-a"},
    "node_modules/express": {"version": "4.18.2", "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz", "integrity": "sha512-b"},
    "node_modules/express/node_modules/qs": {"version": "6.11.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz", "integrity": "sha512-c"},
    "node_modules/jest": {"version": "29.7.0", "dev": true, "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz", "integrity": "sha512-d"},
    "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "integrity": "sha512-e"},
    "node_modules/mylib": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/mylib.git#0123456789abcdef"},
    "node_modules/qs": {"version": "6.11.2", "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.2.tgz", "integrity": "sha512-f"},
    "node_modules/shared": {"resolved": "../shared", "link": true},
    "node_modules/@scope/pkg": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz", "integrity": "sha512-g"},
    "node_modules/mirrored": {"version": "1.0.0", "resolved": "https://npm.corp.example/mirrored/-/mirrored-1.0.0.tgz", "integrity": "sha512-h"}
  }
}`

func mustUnsupported(t *testing.T, err error, want Reason) {
	t.Helper()
	var ue *UnsupportedError
	if !errors.As(err, &ue) || ue.Reason != want {
		t.Fatalf("error = %v, want unsupported %s", err, want)
	}
}

func occOf(t *testing.T, l *lockfile, name, path string) SourceOccurrence {
	t.Helper()
	p := l.lookup(name)
	if p == nil {
		t.Fatalf("%s not in the lockfile", name)
	}
	for _, o := range p.occs {
		if o.Path == path {
			return o
		}
	}
	t.Fatalf("%s has no occurrence at %q: %+v", name, path, p.occs)
	return SourceOccurrence{}
}

func TestParseNpm(t *testing.T) {
	l, err := parseNpm([]byte(npmManifest), []byte(npmLockV3))
	if err != nil {
		t.Fatal(err)
	}
	if o := occOf(t, l, "lodash", "node_modules/lodash"); !o.Direct || o.Version != "4.17.20" || o.ManualReason != "" {
		t.Errorf("lodash = %+v", o)
	}
	if o := occOf(t, l, "jest", "node_modules/jest"); !o.Direct {
		t.Errorf("a devDependency of the root must be direct: %+v", o)
	}
	// qs is required by express (nested) and also installed at the top
	// level, where nothing in the root requires it: both are transitive.
	if len(l.lookup("qs").occs) != 2 {
		t.Fatalf("qs occurrences = %+v", l.lookup("qs").occs)
	}
	for _, o := range l.lookup("qs").occs {
		if o.Direct {
			t.Errorf("qs occurrence %s is direct", o.Path)
		}
	}
	if o := occOf(t, l, "@scope/pkg", "node_modules/@scope/pkg"); o.Version != "2.0.0" || o.ManualReason != "" || o.Direct {
		t.Errorf("scoped package = %+v", o)
	}
	for name, path := range map[string]string{
		"mylib":    "node_modules/mylib",
		"shared":   "node_modules/shared",
		"mirrored": "node_modules/mirrored",
		"real-pkg": "node_modules/aliased",
	} {
		if o := occOf(t, l, name, path); o.ManualReason != ReasonNonRegistrySource || o.Detail == "" {
			t.Errorf("%s = %+v, want a non-registry occurrence", name, o)
		}
	}
	if l.lookup("aliased") != nil {
		t.Error("an alias must be recorded under the real package name only")
	}
}

func TestParseNpmUnsupported(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		lock     string
		reason   Reason
	}{
		{"lockfile v1", npmManifest, `{"lockfileVersion":1,"dependencies":{}}`, ReasonUnsupportedLockfile},
		{"no version", npmManifest, `{"packages":{"":{}}}`, ReasonUnsupportedLockfile},
		{"no root entry", npmManifest, `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`, ReasonUnsupportedLockfile},
		{"workspaces in package.json", `{"name":"r","workspaces":["packages/*"]}`, `{"lockfileVersion":3,"packages":{"":{}}}`, ReasonWorkspaceUnsupported},
		{"workspace member entry", npmManifest, `{"lockfileVersion":3,"packages":{"":{},"packages/a":{"version":"1.0.0"}}}`, ReasonWorkspaceUnsupported},
		{"lock not JSON", npmManifest, `lockfileVersion: 3`, ReasonUnparsableSource},
		{"manifest not JSON", `{`, `{"lockfileVersion":3,"packages":{"":{}}}`, ReasonUnparsableSource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseNpm([]byte(c.manifest), []byte(c.lock))
			mustUnsupported(t, err, c.reason)
		})
	}
}

func TestParseNpmOverrides(t *testing.T) {
	manifest := `{"name":"b","overrides":{"lodash":"4.17.20","foo@^1":{"qs":"6.11.0"}}}`
	l, err := parseNpm([]byte(manifest), []byte(`{"lockfileVersion":2,"packages":{"":{"dependencies":{"lodash":"^4"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"lodash", "foo", "qs"} {
		if _, ok := l.forced[n]; !ok {
			t.Errorf("%s is not marked as overridden: %v", n, l.forced)
		}
	}
}

const pnpmManifest = `{"name":"web","dependencies":{"lodash":"^4.17.20","react-dom":"^18.2.0","react":"^18.2.0","local-lib":"link:../local-lib"},"devDependencies":{"@types/node":"^20.0.0"}}`

const pnpmLock = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
      react:
        specifier: ^18.2.0
        version: 18.2.0
      local-lib:
        specifier: link:../local-lib
        version: link:../local-lib
    devDependencies:
      '@types/node':
        specifier: ^20.0.0
        version: 20.11.0

packages:
  '@types/node@20.11.0':
    resolution: {integrity: sha512-aaa}
  lodash@4.17.20:
    resolution: {integrity: sha512-bbb}
  react@18.2.0:
    resolution: {integrity: sha512-ccc}
  react-dom@18.2.0:
    resolution: {integrity: sha512-ddd}
  scheduler@0.23.0:
    resolution: {integrity: sha512-eee}
  tarball-pkg@1.0.0:
    resolution: {tarball: 'https://example.com/tarball-pkg-1.0.0.tgz', integrity: sha512-fff}
  git-pkg@https://codeload.github.com/x/git-pkg/tar.gz/abc:
    resolution: {tarball: 'https://codeload.github.com/x/git-pkg/tar.gz/abc'}

snapshots:
  '@types/node@20.11.0': {}
  lodash@4.17.20: {}
  react@18.2.0: {}
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
      scheduler: 0.23.0
  scheduler@0.23.0: {}
  tarball-pkg@1.0.0: {}
  git-pkg@https://codeload.github.com/x/git-pkg/tar.gz/abc: {}
`

func TestParsePnpm(t *testing.T) {
	l, err := parsePnpm([]byte(pnpmManifest), []byte(pnpmLock))
	if err != nil {
		t.Fatal(err)
	}
	if o := occOf(t, l, "lodash", "lodash@4.17.20"); !o.Direct || o.Version != "4.17.20" || o.ManualReason != "" {
		t.Errorf("lodash = %+v", o)
	}
	if o := occOf(t, l, "react-dom", "react-dom@18.2.0(react@18.2.0)"); !o.Direct || o.Version != "18.2.0" {
		t.Errorf("react-dom = %+v (the peer suffix is not part of the version)", o)
	}
	if o := occOf(t, l, "scheduler", "scheduler@0.23.0"); o.Direct {
		t.Errorf("scheduler is transitive: %+v", o)
	}
	if o := occOf(t, l, "@types/node", "@types/node@20.11.0"); !o.Direct || o.Version != "20.11.0" {
		t.Errorf("scoped dev dependency = %+v", o)
	}
	if o := occOf(t, l, "tarball-pkg", "tarball-pkg@1.0.0"); o.ManualReason != ReasonNonRegistrySource {
		t.Errorf("tarball package = %+v", o)
	}
	if o := occOf(t, l, "git-pkg", "git-pkg@https://codeload.github.com/x/git-pkg/tar.gz/abc"); o.ManualReason != ReasonNonRegistrySource {
		t.Errorf("git package = %+v", o)
	}
	if o := occOf(t, l, "local-lib", "importers[.].local-lib"); o.ManualReason != ReasonNonRegistrySource || !o.Direct {
		t.Errorf("link dependency = %+v", o)
	}
}

func TestParsePnpmUnsupported(t *testing.T) {
	base := func(mut func(string) string) []byte { return []byte(mut(pnpmLock)) }
	cases := []struct {
		name   string
		lock   []byte
		reason Reason
	}{
		{"version 6", base(func(s string) string { return strings.Replace(s, "'9.0'", "'6.0'", 1) }), ReasonUnsupportedLockfile},
		{"unquoted 9.0 is read", nil, ""},
		{"two importers", base(func(s string) string {
			return strings.Replace(s, "packages:\n", "  packages/a:\n    dependencies: {}\n\npackages:\n", 1)
		}), ReasonWorkspaceUnsupported},
		{"catalogs", base(func(s string) string {
			return s + "\ncatalogs:\n  default:\n    react:\n      specifier: ^18\n      version: 18.2.0\n"
		}), ReasonUnsupportedLockfile},
		{"patched", base(func(s string) string {
			return s + "\npatchedDependencies:\n  lodash@4.17.20:\n    hash: abc\n    path: patches/x.patch\n"
		}), ReasonUnsupportedLockfile},
		{"snapshot without package", base(func(s string) string { return s + "  ghost@1.0.0: {}\n" }), ReasonUnparsableSource},
		{"not yaml", []byte("lockfileVersion: [\n"), ReasonUnparsableSource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.reason == "" {
				if _, err := parsePnpm([]byte(pnpmManifest), []byte(strings.Replace(pnpmLock, "'9.0'", "9.0", 1))); err != nil {
					t.Fatalf("unquoted version: %v", err)
				}
				return
			}
			_, err := parsePnpm([]byte(pnpmManifest), c.lock)
			mustUnsupported(t, err, c.reason)
		})
	}
}

const uvPyproject = `[project]
name = "api"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "requests>=2.31",
    "Flask-Cors",
]

[dependency-groups]
dev = ["pytest"]
`

const uvLock = `version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "api"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "flask-cors" },
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[package.metadata]
requires-dist = [
    { name = "flask-cors" },
    { name = "requests", specifier = ">=2.31" },
]

[[package]]
name = "certifi"
version = "2024.2.2"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/certifi.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/certifi.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", size = 2 },
]

[[package]]
name = "flask-cors"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/flask_cors.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", size = 3 },
]

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/pytest.whl", hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", size = 4 }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
]
wheels = [
    { url = "https://files.pythonhosted.org/requests.whl", hash = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", size = 5 },
]

[[package]]
name = "oldpkg"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/oldpkg.tar.gz", hash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", size = 6 }

[[package]]
name = "gitpkg"
version = "0.2.0"
source = { git = "https://github.com/x/gitpkg?rev=abc#abc" }

[[package]]
name = "privpkg"
version = "3.0.0"
source = { registry = "https://pypi.corp.example/simple" }
wheels = [{ url = "https://pypi.corp.example/privpkg.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 7 }]
`

func TestParseUv(t *testing.T) {
	l, err := parseUv([]byte(uvPyproject), []byte(uvLock))
	if err != nil {
		t.Fatal(err)
	}
	if o := occOf(t, l, "requests", "requests==2.31.0"); !o.Direct || o.ManualReason != "" {
		t.Errorf("requests = %+v", o)
	}
	if o := occOf(t, l, "Flask_Cors", "flask-cors==4.0.0"); !o.Direct {
		t.Errorf("name matching must be PEP 503 normalized: %+v", o)
	}
	if o := occOf(t, l, "pytest", "pytest==8.0.0"); !o.Direct {
		t.Errorf("a dev dependency of the root is direct: %+v", o)
	}
	if o := occOf(t, l, "certifi", "certifi==2024.2.2"); o.Direct || o.ManualReason != "" {
		t.Errorf("certifi = %+v", o)
	}
	for name, want := range map[string]Reason{
		"oldpkg":  ReasonSdistOnly,
		"gitpkg":  ReasonNonRegistrySource,
		"privpkg": ReasonNonRegistrySource,
		"api":     ReasonNonRegistrySource,
	} {
		p := l.lookup(name)
		if p == nil || p.occs[0].ManualReason != want {
			t.Errorf("%s = %+v, want %s", name, p, want)
		}
	}
}

func TestParseUvUnsupported(t *testing.T) {
	cases := []struct {
		name      string
		pyproject string
		lock      string
		reason    Reason
	}{
		{"lock version 2", uvPyproject, strings.Replace(uvLock, "version = 1\n", "version = 2\n", 1), ReasonUnsupportedLockfile},
		{"workspace in lock", uvPyproject, uvLock + "\n[manifest]\nmembers = [\"api\", \"lib\"]\n", ReasonWorkspaceUnsupported},
		{"workspace in pyproject", uvPyproject + "\n[tool.uv.workspace]\nmembers = [\"lib\"]\n", uvLock, ReasonWorkspaceUnsupported},
		{"dynamic dependencies", strings.Replace(uvPyproject, "version = \"0.1.0\"\n", "dynamic = [\"dependencies\"]\n", 1), uvLock, ReasonDynamicMetadata},
		{"no project table", "[tool.uv]\nmanaged = true\n", uvLock, ReasonDynamicMetadata},
		{"no root project", uvPyproject, strings.Replace(uvLock, `source = { virtual = "." }`, `source = { virtual = "sub" }`, 1), ReasonUnsupportedLockfile},
		{"lock not toml", uvPyproject, "version = ", ReasonUnparsableSource},
		{"pyproject not toml", "[project\n", uvLock, ReasonUnparsableSource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseUv([]byte(c.pyproject), []byte(c.lock))
			mustUnsupported(t, err, c.reason)
		})
	}
}

func TestParseUvForcedSources(t *testing.T) {
	py := uvPyproject + "\n[tool.uv.sources]\nrequests = { git = \"https://github.com/psf/requests\" }\n"
	l, err := parseUv([]byte(py), []byte(uvLock))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.forced["requests"]; !ok {
		t.Errorf("forced = %v", l.forced)
	}
}

const requirements = `# runtime
requests==2.31.0 \
    --hash=sha256:aaaa \
    --hash=sha256:bbbb
Flask_Cors == 4.0.0   # pinned
urllib3>=1.26,<3
Django
PyYAML~=6.0
numpy[extra]==1.26.4
direct @ https://example.com/direct-1.0.tgz
--require-hashes

`

func TestParseRequirements(t *testing.T) {
	l, err := parseRequirements([]byte(requirements))
	if err != nil {
		t.Fatal(err)
	}
	if o := occOf(t, l, "requests", "requirements.txt:2"); o.Version != "2.31.0" || !o.Direct || o.Constraint != "" {
		t.Errorf("requests (continuation lines with hashes) = %+v", o)
	}
	if o := occOf(t, l, "flask-cors", "requirements.txt:5"); o.Version != "4.0.0" || o.Marker != "" || o.ManualReason != "" {
		t.Errorf("flask-cors (spaces, comment) = %+v", o)
	}
	if o := occOf(t, l, "urllib3", "requirements.txt:6"); o.Version != "" || o.Constraint != ">=1.26,<3" {
		t.Errorf("urllib3 = %+v", o)
	}
	if o := occOf(t, l, "Django", "requirements.txt:7"); o.Version != "" || o.Constraint != "" || o.ManualReason != "" {
		t.Errorf("an unversioned requirement = %+v", o)
	}
	if o := occOf(t, l, "pyyaml", "requirements.txt:8"); o.Constraint != "~=6.0" {
		t.Errorf("pyyaml = %+v", o)
	}
	if o := occOf(t, l, "numpy", "requirements.txt:9"); o.Version != "1.26.4" {
		t.Errorf("a pin with extras = %+v", o)
	}
	if o := occOf(t, l, "direct", "requirements.txt:10"); o.ManualReason != ReasonNonRegistrySource {
		t.Errorf("a direct reference = %+v", o)
	}
}

func TestParseRequirementsUnsupported(t *testing.T) {
	cases := map[string]string{
		"include":         "-r base.txt\nrequests==2.31.0\n",
		"constraint":      "-c constraints.txt\nrequests==2.31.0\n",
		"editable":        "-e .\nrequests==2.31.0\n",
		"index url":       "--index-url https://pypi.corp.example/simple\nrequests==2.31.0\n",
		"extra index":     "requests==2.31.0\n--extra-index-url https://x.example/simple\n",
		"find links":      "-f ./wheels\nrequests==2.31.0\n",
		"bare URL":        "https://example.com/pkg-1.0.tgz\nrequests==2.31.0\n",
		"bare path":       "./local/pkg\n",
		"unknown option":  "requests==2.31.0 --global-option=--foo\n",
		"not a specifier": "requests=>2\n",
		"invalid UTF-8":   "requests==2.31.0 # \xff\n",
		"unparsable pin":  "requests==2.x.y\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseRequirements([]byte(doc))
			var ue *UnsupportedError
			if !errors.As(err, &ue) {
				t.Fatalf("error = %v, want an unsupported error", err)
			}
		})
	}
	_, err := parseRequirements([]byte("-r base.txt\n"))
	mustUnsupported(t, err, ReasonUnsupportedRequirements)
}

func TestParseRequirementsIgnoresHarmlessLines(t *testing.T) {
	l, err := parseRequirements([]byte("\xef\xbb\xbf# only comments\n\n--prefer-binary\nrequests==2.31.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.pkgs) != 1 || l.lookup("requests") == nil {
		t.Errorf("packages = %v", l.pkgs)
	}
}
