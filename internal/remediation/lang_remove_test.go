package remediation

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// pnpmChain is a lockfile of three direct dependencies: alpha, which requires
// beta, which requires gamma (a closure of three); zulu, which requires
// nothing (a closure of one); and mid, which requires gamma (a closure of two).
const pnpmChain = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      alpha:
        specifier: ^1.0.0
        version: 1.0.0
      mid:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      zulu:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  alpha@1.0.0:
    resolution: {integrity: sha512-a}

  beta@1.0.0:
    resolution: {integrity: sha512-b}

  gamma@1.0.0:
    resolution: {integrity: sha512-c}

  gamma@1.1.0:
    resolution: {integrity: sha512-c2}

  mid@1.0.0:
    resolution: {integrity: sha512-m}

  zulu@1.0.0:
    resolution: {integrity: sha512-z}

snapshots:

  alpha@1.0.0:
    dependencies:
      beta: 1.0.0

  beta@1.0.0:
    dependencies:
      gamma: 1.0.0

  gamma@1.0.0: {}

  gamma@1.1.0: {}

  mid@1.0.0:
    dependencies:
      gamma: 1.1.0

  zulu@1.0.0: {}
`

func targetsOf(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func pnpmKeys(t *testing.T, lock []byte, section string) []string {
	t.Helper()
	doc, err := readPnpmLock(lock)
	if err != nil {
		t.Fatalf("the lockfile cannot be read: %v\n%s", err, lock)
	}
	var keys []string
	for k := range gmap(doc.top[section]) {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func pnpmImporterNames(t *testing.T, lock []byte) []string {
	t.Helper()
	specs, err := pnpmImporterSpecs(lock)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range specs {
		for n := range g {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func TestRemovePnpmTargetsTakesADirectTargetOutOfTheImporter(t *testing.T) {
	got, problem := removePnpmTargets(context.Background(), []byte(pnpmChain), targetsOf("mid"))
	if problem != nil {
		t.Fatal(problem)
	}
	if !reflect.DeepEqual(got.direct, []string{"mid"}) || got.trigger != "" {
		t.Errorf("direct = %v, trigger = %q", got.direct, got.trigger)
	}
	if names := pnpmImporterNames(t, got.lock); !reflect.DeepEqual(names, []string{"alpha", "zulu"}) {
		t.Errorf("importer = %v", names)
	}
	want := []string{"alpha@1.0.0", "beta@1.0.0", "gamma@1.0.0", "gamma@1.1.0", "zulu@1.0.0"}
	if keys := pnpmKeys(t, got.lock, "packages"); !reflect.DeepEqual(keys, want) {
		t.Errorf("packages = %v", keys)
	}
	if keys := pnpmKeys(t, got.lock, "snapshots"); !reflect.DeepEqual(keys, want) {
		t.Errorf("snapshots = %v", keys)
	}
}

func TestRemovePnpmTargetsTakesEveryVersionOfATargetOut(t *testing.T) {
	got, problem := removePnpmTargets(context.Background(), []byte(pnpmChain), targetsOf("gamma"))
	if problem != nil {
		t.Fatal(problem)
	}
	for _, section := range []string{"packages", "snapshots"} {
		for _, k := range pnpmKeys(t, got.lock, section) {
			if strings.HasPrefix(k, "gamma@") {
				t.Errorf("%s still has %s", section, k)
			}
		}
	}
}

func TestRemovePnpmTargetsTakesOutTheDirectDependencyWithTheSmallestClosure(t *testing.T) {
	// alpha reaches three entries, mid two and zulu one: zulu is taken out,
	// though alpha is the first by name.
	got, problem := removePnpmTargets(context.Background(), []byte(pnpmChain), targetsOf("gamma"))
	if problem != nil {
		t.Fatal(problem)
	}
	if got.trigger != "zulu" || len(got.direct) != 0 {
		t.Errorf("trigger = %q, direct = %v", got.trigger, got.direct)
	}
	if names := pnpmImporterNames(t, got.lock); !reflect.DeepEqual(names, []string{"alpha", "mid"}) {
		t.Errorf("importer = %v", names)
	}
	// The entries of the dependency stay: only the importer is changed.
	if keys := pnpmKeys(t, got.lock, "snapshots"); !contains(keys, "zulu@1.0.0") {
		t.Errorf("snapshots = %v", keys)
	}
}

func TestRemovePnpmTargetsTakesTheFirstByNameAmongEquals(t *testing.T) {
	lock := strings.NewReplacer("      zulu:\n        specifier: ^1.0.0\n        version: 1.0.0\n", "      zulu:\n        specifier: ^1.0.0\n        version: 1.0.0\n      yankee:\n        specifier: ^1.0.0\n        version: 1.0.0\n",
		"  zulu@1.0.0:\n    resolution: {integrity: sha512-z}\n", "  yankee@1.0.0:\n    resolution: {integrity: sha512-y}\n\n  zulu@1.0.0:\n    resolution: {integrity: sha512-z}\n",
		"  zulu@1.0.0: {}\n", "  yankee@1.0.0: {}\n\n  zulu@1.0.0: {}\n").Replace(pnpmChain)
	got, problem := removePnpmTargets(context.Background(), []byte(lock), targetsOf("gamma"))
	if problem != nil {
		t.Fatal(problem)
	}
	if got.trigger != "yankee" {
		t.Errorf("trigger = %q, want the first by name of the two with a closure of one", got.trigger)
	}
}

func TestRemovePnpmTargetsRefusesWhatCannotBeMadeAgain(t *testing.T) {
	// The one direct dependency is itself what is reached by nothing else and
	// is not a target, but a project of only a target has nothing to take out.
	only := `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      local:
        specifier: link:../local
        version: link:../local

packages:

  gamma@1.0.0:
    resolution: {integrity: sha512-c}

snapshots:

  gamma@1.0.0: {}
`
	_, problem := removePnpmTargets(context.Background(), []byte(only), targetsOf("gamma"))
	if problem == nil || problem.reason != ReasonNoReresolveTrigger {
		t.Errorf("a project with nothing to take out: %v", problem)
	}
	_, problem = removePnpmTargets(context.Background(), []byte(pnpmChain), targetsOf("delta"))
	if problem == nil || problem.reason != ReasonTargetNotInLockfile || problem.name != "delta" {
		t.Errorf("a target the lockfile lacks: %v", problem)
	}
	_, problem = removePnpmTargets(context.Background(), []byte(pnpmChain), nil)
	if problem == nil {
		t.Error("no target accepted")
	}
	_, problem = removePnpmTargets(context.Background(), []byte("lockfileVersion: '9.0'\n---\nlockfileVersion: '9.0'\n"), targetsOf("gamma"))
	if problem == nil {
		t.Error("a lockfile of two documents accepted")
	}
}

func TestRemovePnpmTargetsLeavesTheRestOfTheFileAsItIs(t *testing.T) {
	got, problem := removePnpmTargets(context.Background(), []byte(pnpmChain), targetsOf("beta"))
	if problem != nil {
		t.Fatal(problem)
	}
	was, err := readPnpmLock([]byte(pnpmChain))
	if err != nil {
		t.Fatal(err)
	}
	now, err := readPnpmLock(got.lock)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"packages", "snapshots"} {
		w, n := gmap(was.top[section]), gmap(now.top[section])
		delete(w, "beta@1.0.0")
		if !reflect.DeepEqual(w, n) {
			t.Errorf("%s differ: %v / %v", section, w, n)
		}
	}
	for _, k := range []string{"lockfileVersion", "settings"} {
		if !reflect.DeepEqual(was.top[k], now.top[k]) {
			t.Errorf("%s changed: %v / %v", k, was.top[k], now.top[k])
		}
	}
	if now.versionText != "9.0" {
		t.Errorf("version = %q", now.versionText)
	}
}

func TestStripPeerSuffix(t *testing.T) {
	next := targetsOf("next")
	for _, c := range []struct{ in, want string }{
		{"1.0.0", "1.0.0"},
		{"1.0.0(next@15.1.0)", "1.0.0"},
		{"1.0.0(next@15.1.0(react@19.0.0))", "1.0.0"},
		{"1.0.0(react@19.0.0)(next@15.1.0(react@19.0.0))(react-dom@19.0.0)", "1.0.0(react@19.0.0)(react-dom@19.0.0)"},
		{"1.0.0(foo@1.0.0(next@15.1.0))", "1.0.0(foo@1.0.0)"},
		{"1.0.0(@scope/pkg@2.0.0)", "1.0.0(@scope/pkg@2.0.0)"},
		{"1.0.0(next-intl@3.0.0)", "1.0.0(next-intl@3.0.0)"},
		{"1.0.0(next@15.1.0", "1.0.0(next@15.1.0"},
		{"link:../x", "link:../x"},
	} {
		got, err := newTestStripper(next).text(c.in)
		if err != nil || got != c.want {
			t.Errorf("text(%q) = %q, %v, want %q", c.in, got, err, c.want)
		}
	}
	if got, _ := newTestStripper(targetsOf("@scope/pkg")).text("1.0.0(@scope/pkg@2.0.0)(react@19.0.0)"); got != "1.0.0(react@19.0.0)" {
		t.Errorf("scoped: %q", got)
	}
}

const peerLock = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      host:
        specifier: ^1.0.0
        version: 1.0.0(next@15.1.0)
      next:
        specifier: 15.1.0
        version: 15.1.0

packages:

  host@1.0.0:
    resolution: {integrity: sha512-h}

  next@15.1.0:
    resolution: {integrity: sha512-n}

snapshots:

  host@1.0.0(next@15.1.0):
    dependencies:
      next: 15.1.0

  next@15.1.0: {}
`

func TestNormalizedGraphCarriesTheResolvedReferencesOver(t *testing.T) {
	raw, err := buildGraph(context.Background(), ManagerPnpm, []byte(peerLock))
	if err != nil {
		t.Fatal(err)
	}
	g, err := normalizedGraph(context.Background(), raw, targetsOf("next"))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range g.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"host@1.0.0", "next@15.1.0"}) {
		t.Errorf("keys = %v", keys)
	}
	g.link()
	for _, e := range g.roots {
		if e.to < 0 {
			t.Errorf("the importer's requirement for %s is not resolved", e.name)
		}
	}
	// Two entries that are one once the contexts are left out are refused.
	twice := strings.Replace(peerLock, "  next@15.1.0: {}\n", "  host@1.0.0(next@15.2.0): {}\n\n  next@15.1.0: {}\n", 1)
	raw, err = buildGraph(context.Background(), ManagerPnpm, []byte(twice))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizedGraph(context.Background(), raw, targetsOf("next")); err == nil {
		t.Error("two entries of one accepted")
	}
}

// A requirement the written file does not resolve is not resolved by leaving
// the contexts out, in either direction.
func TestNormalizedGraphDoesNotResolveWhatTheFileDidNot(t *testing.T) {
	lock := func(ref, key string) string {
		return "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n      host:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n" +
			"  host@1.0.0:\n    resolution: {integrity: sha512-h}\n\n  shared@1.1.0:\n    resolution: {integrity: sha512-s}\n\nsnapshots:\n\n" +
			"  host@1.0.0:\n    optionalDependencies:\n      shared: " + ref + "\n\n  " + key + ": {}\n"
	}
	for name, l := range map[string]string{
		"the reference has a context, the snapshot has none": lock("1.1.0(app@0.0.0)", "shared@1.1.0"),
		"the reference has none, the snapshot has a context": lock("1.1.0", "shared@1.1.0(app@0.0.0)"),
	} {
		raw, err := buildGraph(context.Background(), ManagerPnpm, []byte(l))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		g, err := normalizedGraph(context.Background(), raw, targetsOf("app"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		g.link()
		host := g.nodes["host@1.0.0"]
		if host == nil || len(host.deps) != 1 || host.deps[0].to >= 0 {
			t.Errorf("%s: the requirement of host for shared is resolved: %+v", name, host)
		}
	}
}

// --- package-lock.json ---

const npmTree = `{
  "name": "a",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {"name": "a", "version": "1.0.0", "dependencies": {"app": "^1.0.0", "ms": "^2.0.0"}},
    "node_modules/app": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/app/-/app-1.0.0.tgz", "integrity": "sha512-app", "dependencies": {"ms": "^1.0.0"}},
    "node_modules/app/node_modules/ms": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz", "integrity": "sha512-ms1"},
    "node_modules/app/node_modules/ms/node_modules/inner": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/inner/-/inner-1.0.0.tgz", "integrity": "sha512-in"},
    "node_modules/ms": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz", "integrity": "sha512-ms2"},
    "node_modules/@scope/pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", "integrity": "sha512-sc"}
  },
  "dependencies": {
    "@scope/pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", "integrity": "sha512-sc"},
    "app": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/app/-/app-1.0.0.tgz", "integrity": "sha512-app", "requires": {"ms": "^1.0.0"}, "dependencies": {
      "ms": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz", "integrity": "sha512-ms1", "dependencies": {
        "inner": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/inner/-/inner-1.0.0.tgz", "integrity": "sha512-in"}}}}},
    "ms": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz", "integrity": "sha512-ms2"}
  }
}
`

func npmPaths(t *testing.T, lock []byte) []string {
	t.Helper()
	doc, err := readNpmLock(lock)
	if err != nil {
		t.Fatalf("the lockfile cannot be read: %v\n%s", err, lock)
	}
	var paths []string
	for p := range doc.entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func TestRemoveNpmTargetsTakesEveryPathAndWhatIsNestedBelowIt(t *testing.T) {
	got, problem := removeNpmTargets(context.Background(), []byte(npmTree), targetsOf("ms"))
	if problem != nil {
		t.Fatal(problem)
	}
	want := []string{"", "node_modules/@scope/pkg", "node_modules/app"}
	if paths := npmPaths(t, got.lock); !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if len(got.paths) != 3 {
		t.Errorf("taken out = %v", got.paths)
	}
	// The tree of lockfileVersion 2 loses the same nodes.
	top, err := nameMap(got.lock)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := nameMap(top["dependencies"])
	if err != nil {
		t.Fatal(err)
	}
	if _, has := legacy["ms"]; has || len(legacy) != 2 {
		t.Errorf("legacy top level = %v", legacy)
	}
	app, _ := nameMap(legacy["app"])
	if sub, has := app["dependencies"]; has {
		nested, _ := nameMap(sub)
		if len(nested) != 0 {
			t.Errorf("legacy app still has %v", nested)
		}
	}
	// The root entry is not touched: npm sees the dependency missing from the
	// tree and resolves it again.
	root, _ := nameMap(top["packages"])
	if !strings.Contains(string(root[""]), `"ms"`) {
		t.Errorf("root entry = %s", root[""])
	}
	if !strings.HasSuffix(string(got.lock), "\n") {
		t.Error("the final newline went missing")
	}
}

func TestRemoveNpmTargetsHandlesScopedNamesAndRefusesWhatIsMissing(t *testing.T) {
	got, problem := removeNpmTargets(context.Background(), []byte(npmTree), targetsOf("@scope/pkg"))
	if problem != nil {
		t.Fatal(problem)
	}
	for _, p := range npmPaths(t, got.lock) {
		if strings.Contains(p, "@scope/pkg") {
			t.Errorf("%s is still there", p)
		}
	}
	if _, problem := removeNpmTargets(context.Background(), []byte(npmTree), targetsOf("absent")); problem == nil || problem.reason != ReasonTargetNotInLockfile {
		t.Errorf("a target the lockfile lacks: %v", problem)
	}
	if _, problem := removeNpmTargets(context.Background(), []byte(`{"packages": {`), targetsOf("ms")); problem == nil {
		t.Error("a file that is not JSON accepted")
	}
	// A lockfileVersion 3 file has no tree to take it out of.
	v3 := strings.Replace(npmTree, `"lockfileVersion": 2`, `"lockfileVersion": 3`, 1)
	v3 = v3[:strings.Index(v3, `,
  "dependencies": {`)] + "\n}\n"
	got, problem = removeNpmTargets(context.Background(), []byte(v3), targetsOf("app"))
	if problem != nil {
		t.Fatal(problem)
	}
	if paths := npmPaths(t, got.lock); !reflect.DeepEqual(paths, []string{"", "node_modules/@scope/pkg", "node_modules/ms"}) {
		t.Errorf("paths = %v", paths)
	}
}

func newTestStripper(names map[string]bool) *peerStripper {
	return &peerStripper{ctx: context.Background(), names: names, budget: maxPeerStripBytes}
}

func TestPeerStripperIsBoundedAndLinear(t *testing.T) {
	deep := "1.0.0" + strings.Repeat("(x@1.0.0", 100000) + strings.Repeat(")", 100000)
	if _, err := newTestStripper(targetsOf("next")).text(deep); err == nil {
		t.Error("100000 levels of contexts accepted")
	}
	nest := func(n int) string { return "1.0.0" + strings.Repeat("(x@1.0.0", n) + strings.Repeat(")", n) }
	if got, err := newTestStripper(targetsOf("next")).text(nest(maxPeerSuffixDepth)); err != nil || got != nest(maxPeerSuffixDepth) {
		t.Errorf("the deepest accepted nesting: %v", err)
	}
	if _, err := newTestStripper(targetsOf("next")).text(nest(maxPeerSuffixDepth + 1)); err == nil {
		t.Error("one level too many accepted")
	}
	long := "1.0.0(" + strings.Repeat("a", maxPeerSuffixBytes) + "@1)"
	if _, err := newTestStripper(targetsOf("next")).text(long); err == nil {
		t.Error("a context over the length bound accepted")
	}
	// A file of many contexts runs out of the budget, and of time.
	p := newTestStripper(targetsOf("next"))
	p.budget = 100
	for i := 0; i < 10; i++ {
		if _, err := p.text("1.0.0(react@19.0.0)"); err != nil {
			return
		}
	}
	t.Error("the budget was not spent")
}

func TestPeerStripperWatchesTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &peerStripper{ctx: ctx, names: targetsOf("next"), budget: maxPeerStripBytes}
	long := "1.0.0(" + strings.Repeat("a", 8000) + "@1)"
	var err error
	for i := 0; i < 200 && err == nil; i++ {
		_, err = p.text(long)
	}
	if err == nil || ctx.Err() == nil {
		t.Error("a cancelled context was not noticed")
	}
}
