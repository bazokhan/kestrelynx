package remediation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestClassifyEdge(t *testing.T) {
	cves := []CVERef{{VulnID: "CVE-1", FixedVers: []string{"0.2.4", "1.2.6"}}}
	cases := []struct {
		spec string
		want edgeClass
		name string
	}{
		{"0.0.8", edgePinning, "an exact version below the fix"},
		{"=0.0.8", edgePinning, "= and an exact version"},
		{"v0.0.8", edgePinning, "v and an exact version"},
		{"1.2.5", edgePinning, "an exact version in a line the fix is above"},
		{"<0.2.4", edgePinning, "an upper bound at the lowest fixed version"},
		{"<0.1.0", edgePinning, "an upper bound below the lowest fixed version"},
		{"<=0.2.3", edgePinning, "an inclusive upper bound below the lowest fixed version"},
		{"~0.0.1", edgePinning, "a tilde range whose upper bound is below it"},
		{"^0.1.0", edgePinning, "a caret range of 0.x whose upper bound is below it"},
		{"0.0.x", edgePinning, "an x-range"},
		{">=0.0.1 <0.1.0", edgePinning, "one set of comparators with an upper bound"},
		{"0.0.1 - 0.1.0", edgePinning, "a hyphen range"},
		{"<=0.2.4", edgeAllowsFix, "an inclusive upper bound at the lowest fixed version allows it"},
		{"<0.2.5", edgeAllowsFix, "an upper bound above the lowest fixed version"},
		{"^1.2.0", edgeAllowsFix, "a range that allows the lowest fixed version"},
		{"*", edgeAllowsFix, "any version"},
		{">=1.0.0", edgeAllowsFix, "a lower bound only"},
		{"1.2.6", edgeAllowsFix, "the lowest fixed version itself"},
		{"1.3.0", edgeUnevaluable, "an exact version that is fixed but is not the lowest fixed one"},
		{"^0.0.8 || ^1.2.0", edgeAllowsFix, "an OR range that allows the fix"},
		{"0.0.8 || 0.0.9", edgeUnevaluable, "an OR range of versions below the fix"},
		{"<0.1.0 || <0.2.0", edgeUnevaluable, "an OR range of upper bounds"},
		{"latest", edgeUnevaluable, "a tag"},
		{"github:a/b", edgeUnevaluable, "a location"},
		{"not a range", edgeUnevaluable, "a range that cannot be read"},
		{"^1.2.0-beta.1", edgeUnevaluable, "a pre-release bound"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyEdge(c.spec, "1.2.6", cves); got != c.want {
				t.Errorf("classifyEdge(%q) = %v, want %v", c.spec, got, c.want)
			}
		})
	}
	t.Run("no fixed version to judge by", func(t *testing.T) {
		if got := classifyEdge("^1.2.0", "", []CVERef{{VulnID: "CVE-1"}}); got != edgeUnevaluable {
			t.Errorf("got %v", got)
		}
	})
	t.Run("a range of a later line allows the first fix of that line", func(t *testing.T) {
		// The lowest fixed version is in 0.x; ^1.2.0 allows 1.2.6, the first fix of 1.x.
		if got := classifyEdge("^1.2.0", "0.2.4", cves); got != edgeAllowsFix {
			t.Errorf("got %v", got)
		}
	})
	t.Run("the proof of a pinning edge", func(t *testing.T) {
		if _, p := classifyEdgeProof("0.0.8", "1.2.6", cves); p != proofExact {
			t.Errorf("proof = %q", p)
		}
		if _, p := classifyEdgeProof("~0.0.1", "1.2.6", cves); p != proofUpperBound {
			t.Errorf("proof = %q", p)
		}
	})
	t.Run("a vulnerability fixed in a later version pins what the first fix allows", func(t *testing.T) {
		two := []CVERef{{VulnID: "A", FixedVers: []string{"1.2.6"}}, {VulnID: "B", FixedVers: []string{"2.0.0"}}}
		if got := classifyEdge("^1.2.0", "2.0.0", two); got != edgePinning {
			t.Errorf("got %v", got)
		}
	})
}

func TestNormalizeParentEdges(t *testing.T) {
	d := NpmDist{
		Dependencies:         map[string]string{"a": "^1", "both": "^1", "differ": "^1", "mixed": "^1"},
		OptionalDependencies: map[string]string{"opt": "^1", "both": "^1", "differ": "^2"},
		PeerDependencies:     map[string]string{"peer": "^1", "mixed": "^1"},
	}
	edges, bad := normalizeParentEdges(ManagerNpm, &depNode{name: "p"}, d)
	if strings.Join(bad, ",") != "differ,mixed" {
		t.Errorf("unsupported = %v", bad)
	}
	if e := edges["peer"]; !e.peerOnly || !e.optional {
		t.Errorf("peer = %+v", e)
	}
	if e := edges["both"]; e.peerOnly || !e.optional || e.spec != "^1" {
		t.Errorf("both = %+v: one optional requirement", e)
	}
	if e := edges["a"]; e.peerOnly || e.optional {
		t.Errorf("a = %+v", e)
	}
	// pnpm lists a peer dependency that is only marked optional.
	d2 := NpmDist{Install: map[string]string{"peerDependenciesMeta": "marked"}}
	if e := func() normEdge { m, _ := normalizeParentEdges(ManagerPnpm, &depNode{}, d2); return m["marked"] }(); !e.peerOnly {
		t.Errorf("pnpm marked = %+v", e)
	}
	if m, _ := normalizeParentEdges(ManagerNpm, &depNode{}, d2); len(m) != 0 {
		t.Errorf("npm lists %v", m)
	}
}

// chainRun makes a run of an npm update of the packages in groups (name,
// installed, lowest fixed version, fixed versions) over the lockfile, with the
// registry declaring dists.
func chainRun(t *testing.T, manifest string, lock []byte, dists map[string]NpmDist, groups ...LanguagePackage) *updateRun {
	t.Helper()
	it := &LanguageItem{Manager: ManagerNpm, Packages: groups}
	set, fail := newUpdateSet(it)
	if fail != nil {
		t.Fatal(fail.detail)
	}
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: &fakeNpm{dists: dists}}}
	return &updateRun{
		u: u, it: it, set: set, full: set, upd: &LanguageUpdate{},
		src:      &sourceFiles{manifest: []byte(manifest), lock: lock, manifestName: "package.json", lockName: "package-lock.json"},
		manifest: []byte(manifest), shared: newItemShared(),
	}
}

func minimistPkg() LanguagePackage {
	return LanguagePackage{Name: "minimist", Installed: "0.0.8", SelectionLowerBound: "1.2.6", Action: ActionUpdate,
		CVEs: []CVERef{{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}}}}
}

const mkdirpManifest = `{"name":"app","version":"1.0.0","dependencies":{"mkdirp":"^0.5.1","rc":"^1.2.0"}}`

var mkdirpRoot = map[string]string{"mkdirp": "^0.5.1", "rc": "^1.2.0"}

func mkdirpLock() []byte {
	return npmLock(mkdirpRoot, map[string]npmEntry{
		"node_modules/mkdirp":                   {ver: "0.5.1", deps: map[string]string{"minimist": "0.0.8"}},
		"node_modules/minimist":                 {ver: "0.0.8"},
		"node_modules/rc":                       {ver: "1.2.8", deps: map[string]string{"minimist": "^1.2.0"}},
		"node_modules/rc/node_modules/minimist": {ver: "1.2.0"},
	})
}

var mkdirpDists = map[string]NpmDist{
	"mkdirp@0.5.1": {Dependencies: map[string]string{"minimist": "0.0.8"}},
	"rc@1.2.8":     {Dependencies: map[string]string{"minimist": "^1.2.0"}},
}

func TestBuildChainScope(t *testing.T) {
	t.Run("a pinned path and a path that allows the fix", func(t *testing.T) {
		r := chainRun(t, mkdirpManifest, mkdirpLock(), mkdirpDists, minimistPkg())
		g0, err := buildGraph(bg, ManagerNpm, r.src.lock)
		if err != nil {
			t.Fatal(err)
		}
		scope, fail := buildChainScope(bg, r, g0, []string{"minimist"})
		if fail != nil || scope == nil {
			t.Fatalf("scope = %v, failure = %+v", scope, fail)
		}
		if strings.Join(scope.Bn, ",") != "minimist" || len(scope.Tops) != 1 || scope.Tops[0].Name != "mkdirp" || scope.Tops[0].Group != "dependencies" || scope.Tops[0].Spec != "^0.5.1" {
			t.Errorf("Bn = %v, Tops = %+v", scope.Bn, scope.Tops)
		}
		if !scope.Anc["node_modules/mkdirp"] || scope.Anc["node_modules/rc"] || len(scope.Anc) != 1 {
			t.Errorf("Anc = %v: rc allows the fix and is not an ancestor", scope.Anc)
		}
		if !scope.Be["node_modules/minimist"] || scope.Be["node_modules/rc/node_modules/minimist"] {
			t.Errorf("Be = %v", scope.Be)
		}
		if len(scope.Blocked) != 1 || !reflect.DeepEqual(scope.Blocked[0], ChainBlock{Package: "minimist", Version: "0.0.8", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "0.0.8", Proof: "exact", Via: []string{"mkdirp"}}) {
			t.Errorf("Blocked = %+v", scope.Blocked)
		}
		if !scope.RTgt["node_modules/minimist"] || !scope.RTgt["node_modules/rc/node_modules/minimist"] || !scope.RAnc["node_modules/mkdirp"] {
			t.Errorf("RTgt = %v RAnc = %v", scope.RTgt, scope.RAnc)
		}
		if !scope.Targets["minimist"] || !scope.Names["mkdirp"] {
			t.Errorf("Targets = %v Names = %v", scope.Targets, scope.Names)
		}
	})
	t.Run("the lookups go through the item's cache and budget", func(t *testing.T) {
		r := chainRun(t, mkdirpManifest, mkdirpLock(), mkdirpDists, minimistPkg())
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		if _, fail := buildChainScope(bg, r, g0, []string{"minimist"}); fail != nil {
			t.Fatal(fail.detail)
		}
		npm := r.u.cfg.Npm.(*fakeNpm)
		if got := strings.Join(npm.lookups, " "); got != "mkdirp@0.5.1 rc@1.2.8" && got != "rc@1.2.8 mkdirp@0.5.1" {
			t.Errorf("lookups = %q", got)
		}
		if r.shared.budget.lookups != 2 {
			t.Errorf("counted %d lookups", r.shared.budget.lookups)
		}
	})
	t.Run("a package the project declares is not held back by a chain", func(t *testing.T) {
		manifest := `{"name":"app","version":"1.0.0","dependencies":{"mkdirp":"^0.5.1","rc":"^1.2.0","minimist":"^1.2.0"}}`
		r := chainRun(t, manifest, mkdirpLock(), mkdirpDists, minimistPkg())
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		scope, fail := buildChainScope(bg, r, g0, []string{"minimist"})
		if scope != nil || fail != nil {
			t.Fatalf("scope = %v, failure = %+v", scope, fail)
		}
		npm := r.u.cfg.Npm.(*fakeNpm)
		if len(npm.lookups) != 0 {
			t.Errorf("looked up %v for a package that is excluded", npm.lookups)
		}
	})
	t.Run("a range that cannot be judged", func(t *testing.T) {
		dists := map[string]NpmDist{
			"mkdirp@0.5.1": {Dependencies: map[string]string{"minimist": "latest"}},
			"rc@1.2.8":     {Dependencies: map[string]string{"minimist": "^1.2.0"}},
		}
		r := chainRun(t, mkdirpManifest, mkdirpLock(), dists, minimistPkg())
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		if scope, fail := buildChainScope(bg, r, g0, []string{"minimist"}); scope != nil || fail != nil {
			t.Fatalf("scope = %v, failure = %+v: the first update's reason stands", scope, fail)
		}
	})
	t.Run("a requirement that is peer-only", func(t *testing.T) {
		dists := map[string]NpmDist{
			"mkdirp@0.5.1": {PeerDependencies: map[string]string{"minimist": "0.0.8"}},
			"rc@1.2.8":     {Dependencies: map[string]string{"minimist": "^1.2.0"}},
		}
		r := chainRun(t, mkdirpManifest, mkdirpLock(), dists, minimistPkg())
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		if scope, fail := buildChainScope(bg, r, g0, []string{"minimist"}); scope != nil || fail != nil {
			t.Fatalf("scope = %v, failure = %+v", scope, fail)
		}
	})
	t.Run("declarations that cannot be reduced", func(t *testing.T) {
		for name, d := range map[string]NpmDist{
			"peer and regular":            {Dependencies: map[string]string{"minimist": "0.0.8"}, PeerDependencies: map[string]string{"minimist": "*"}},
			"different dependency ranges": {Dependencies: map[string]string{"minimist": "0.0.8"}, OptionalDependencies: map[string]string{"minimist": "0.0.9"}},
		} {
			t.Run(name, func(t *testing.T) {
				r := chainRun(t, mkdirpManifest, mkdirpLock(), map[string]NpmDist{"mkdirp@0.5.1": d, "rc@1.2.8": mkdirpDists["rc@1.2.8"]}, minimistPkg())
				g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
				_, fail := buildChainScope(bg, r, g0, []string{"minimist"})
				if fail == nil || fail.reason != ReasonDependentsUnsupported || fail.pkgs["minimist"].reason != ReasonDependentsUnsupported {
					t.Fatalf("failure = %+v", fail)
				}
			})
		}
		t.Run("the same range twice is one optional requirement", func(t *testing.T) {
			d := NpmDist{Dependencies: map[string]string{"minimist": "0.0.8"}, OptionalDependencies: map[string]string{"minimist": "0.0.8"}}
			r := chainRun(t, mkdirpManifest, mkdirpLock(), map[string]NpmDist{"mkdirp@0.5.1": d, "rc@1.2.8": mkdirpDists["rc@1.2.8"]}, minimistPkg())
			g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
			if scope, fail := buildChainScope(bg, r, g0, []string{"minimist"}); fail != nil || scope == nil {
				t.Fatalf("scope = %v, failure = %+v", scope, fail)
			}
		})
	})
	t.Run("an ancestor that is not a registry package", func(t *testing.T) {
		root := map[string]string{"top": "^1.0.0"}
		lock := npmLock(root, map[string]npmEntry{
			"node_modules/top":      {ver: "1.0.0", deps: map[string]string{"mkdirp": "^0.5.0"}, url: "https://example.com/top.tgz"},
			"node_modules/mkdirp":   {ver: "0.5.1", deps: map[string]string{"minimist": "0.0.8"}},
			"node_modules/minimist": {ver: "0.0.8"},
		})
		dists := map[string]NpmDist{"mkdirp@0.5.1": mkdirpDists["mkdirp@0.5.1"]}
		r := chainRun(t, manifestOf("top"), lock, dists, minimistPkg())
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		_, fail := buildChainScope(bg, r, g0, []string{"minimist"})
		if fail == nil || fail.reason != ReasonDependentsUnsupported {
			t.Fatalf("failure = %+v", fail)
		}
	})
	t.Run("a pinning parent that is not a registry package is not judged", func(t *testing.T) {
		lock := npmLock(mkdirpRoot, map[string]npmEntry{
			"node_modules/mkdirp":                   {ver: "0.5.1", deps: map[string]string{"minimist": "0.0.8"}, url: "https://example.com/mkdirp.tgz"},
			"node_modules/minimist":                 {ver: "0.0.8"},
			"node_modules/rc":                       {ver: "1.2.8", deps: map[string]string{"minimist": "^1.2.0"}},
			"node_modules/rc/node_modules/minimist": {ver: "1.2.0"},
		})
		r := chainRun(t, mkdirpManifest, lock, mkdirpDists, minimistPkg())
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		if scope, fail := buildChainScope(bg, r, g0, []string{"minimist"}); scope != nil || fail != nil {
			t.Fatalf("scope = %v, failure = %+v", scope, fail)
		}
	})
	t.Run("an ancestor left to a person for another reason", func(t *testing.T) {
		other := LanguagePackage{Name: "mkdirp", Installed: "0.5.1", Action: ActionManual, Reason: ReasonUpdateInputInvalid, Detail: "no fix"}
		r := chainRun(t, mkdirpManifest, mkdirpLock(), mkdirpDists, minimistPkg(), other)
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		_, fail := buildChainScope(bg, r, g0, []string{"minimist"})
		if fail == nil || fail.reason != ReasonDependentsUnsupported {
			t.Fatalf("failure = %+v", fail)
		}
	})
	t.Run("the item's lookups run out", func(t *testing.T) {
		r := chainRun(t, mkdirpManifest, mkdirpLock(), mkdirpDists, minimistPkg())
		r.shared.budget.maxLookups, r.shared.budget.enforced = 1, true
		g0, _ := buildGraph(bg, ManagerNpm, r.src.lock)
		_, fail := buildChainScope(bg, r, g0, []string{"minimist"})
		if fail == nil || fail.category != CategoryDeferred || fail.reason != ReasonChainItemBudget || fail.wait == nil || fail.wait.Kind != budgetLookupWait {
			t.Fatalf("failure = %+v", fail)
		}
	})
}

// chainPackages makes a lockfile in which each of the parents requires t
// exactly, with the registry declaring it.
func fanLock(parents []string, chain map[string][]string) ([]byte, map[string]NpmDist) {
	root := map[string]string{}
	pkgs := map[string]npmEntry{"node_modules/t": {ver: "0.5.0"}}
	dists := map[string]NpmDist{}
	for _, p := range parents {
		root[p] = "^1.0.0"
	}
	names := append([]string(nil), parents...)
	for k, l := range chain {
		names = append(names, k)
		_ = l
	}
	for _, name := range names {
		deps := map[string]string{}
		for _, d := range chain[name] {
			deps[d] = "^1.0.0"
		}
		if len(chain[name]) == 0 {
			deps["t"] = "0.5.0"
		}
		pkgs["node_modules/"+name] = npmEntry{ver: "1.0.0", deps: deps}
		dists[name+"@1.0.0"] = NpmDist{Dependencies: deps}
	}
	return npmLock(root, pkgs), dists
}

func tPkg() LanguagePackage {
	return LanguagePackage{Name: "t", Installed: "0.5.0", SelectionLowerBound: "1.2.6", Action: ActionUpdate,
		CVEs: []CVERef{{VulnID: "CVE-T", FixedVers: []string{"1.2.6"}}}}
}

func manifestOf(names ...string) string {
	var deps []string
	for _, n := range names {
		deps = append(deps, fmt.Sprintf("%q:\"^1.0.0\"", n))
	}
	return `{"name":"app","version":"1.0.0","dependencies":{` + strings.Join(deps, ",") + `}}`
}

func TestBuildChainScopeCapsAndCycles(t *testing.T) {
	t.Run("more tops than allowed", func(t *testing.T) {
		var parents []string
		for i := 0; i <= maxChainTops; i++ {
			parents = append(parents, fmt.Sprintf("top%d", i))
		}
		lock, dists := fanLock(parents, nil)
		r := chainRun(t, manifestOf(parents...), lock, dists, tPkg())
		g0, _ := buildGraph(bg, ManagerNpm, lock)
		_, fail := buildChainScope(bg, r, g0, []string{"t"})
		if fail == nil || fail.reason != ReasonDependentsLimit {
			t.Fatalf("failure = %+v", fail)
		}
		// At the limit it goes on.
		lock, dists = fanLock(parents[:maxChainTops], nil)
		r = chainRun(t, manifestOf(parents[:maxChainTops]...), lock, dists, tPkg())
		g0, _ = buildGraph(bg, ManagerNpm, lock)
		if scope, fail := buildChainScope(bg, r, g0, []string{"t"}); fail != nil || len(scope.Tops) != maxChainTops {
			t.Fatalf("scope = %+v, failure = %+v", scope, fail)
		}
	})
	t.Run("more ancestors than allowed", func(t *testing.T) {
		build := func(n int) (*updateRun, *depGraph) {
			chain := map[string][]string{}
			for i := 0; i < n-1; i++ {
				chain[fmt.Sprintf("a%02d", i)] = []string{fmt.Sprintf("a%02d", i+1)}
			}
			chain[fmt.Sprintf("a%02d", n-1)] = nil
			lock, dists := fanLock([]string{"a00"}, chain)
			r := chainRun(t, manifestOf("a00"), lock, dists, tPkg())
			g0, err := buildGraph(bg, ManagerNpm, lock)
			if err != nil {
				t.Fatal(err)
			}
			return r, g0
		}
		r, g0 := build(maxChainAncestors + 1)
		if _, fail := buildChainScope(bg, r, g0, []string{"t"}); fail == nil || fail.reason != ReasonDependentsLimit {
			t.Fatalf("failure = %+v", fail)
		}
		r, g0 = build(maxChainAncestors)
		if scope, fail := buildChainScope(bg, r, g0, []string{"t"}); fail != nil || len(scope.Anc) != maxChainAncestors {
			t.Fatalf("scope = %+v, failure = %+v", scope, fail)
		}
	})
	t.Run("a cycle between ancestors", func(t *testing.T) {
		lock, dists := fanLock([]string{"a"}, map[string][]string{"a": {"b"}, "b": {"a", "t"}})
		dists["b@1.0.0"] = NpmDist{Dependencies: map[string]string{"a": "^1.0.0", "t": "0.5.0"}}
		lock = npmLock(map[string]string{"a": "^1.0.0"}, map[string]npmEntry{
			"node_modules/a": {ver: "1.0.0", deps: map[string]string{"b": "^1.0.0"}},
			"node_modules/b": {ver: "1.0.0", deps: map[string]string{"a": "^1.0.0", "t": "0.5.0"}},
			"node_modules/t": {ver: "0.5.0"},
		})
		r := chainRun(t, manifestOf("a"), lock, dists, tPkg())
		g0, _ := buildGraph(bg, ManagerNpm, lock)
		scope, fail := buildChainScope(bg, r, g0, []string{"t"})
		if fail != nil || scope == nil || len(scope.Anc) != 2 || len(scope.Tops) != 1 || scope.Tops[0].Name != "a" {
			t.Fatalf("scope = %+v, failure = %+v", scope, fail)
		}
	})
}

// pnpmHostLock makes a pnpm lockfile in which host has the given peer
// contexts as separate snapshots; only the first requires t, which is pinned.
// top requires the first and other the second.
func pnpmHostLock(variants int) (manifest string, lock []byte) {
	var b strings.Builder
	ctx := func(i int) string { return fmt.Sprintf("host@1.0.0(peer@%d.0.0)", i+1) }
	b.WriteString("lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n")
	b.WriteString("      other:\n        specifier: ^1.0.0\n        version: 1.0.0\n")
	b.WriteString("      top:\n        specifier: ^1.0.0\n        version: 1.0.0\n")
	b.WriteString("\npackages:\n\n")
	for _, p := range [][2]string{{"host", "1.0.0"}, {"other", "1.0.0"}, {"peer", "1.0.0"}, {"t", "0.5.0"}, {"top", "1.0.0"}} {
		fmt.Fprintf(&b, "  %s@%s:\n    resolution: {integrity: %s}\n\n", p[0], p[1], partialIntegrity(p[0], p[1]))
	}
	b.WriteString("snapshots:\n\n")
	for i := 0; i < variants; i++ {
		fmt.Fprintf(&b, "  %s:\n", ctx(i))
		if i == 0 {
			b.WriteString("    dependencies:\n      t: 0.5.0\n")
		} else {
			b.WriteString("    {}\n")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "  other@1.0.0:\n    dependencies:\n      host: %s\n\n", strings.TrimPrefix(ctx(variants-1), "host@"))
	b.WriteString("  peer@1.0.0: {}\n\n  t@0.5.0: {}\n\n")
	fmt.Fprintf(&b, "  top@1.0.0:\n    dependencies:\n      host: %s\n", strings.TrimPrefix(ctx(0), "host@"))
	return manifestOf("other", "top"), []byte(b.String())
}

func TestBuildChainScopePnpmSnapshots(t *testing.T) {
	dists := map[string]NpmDist{
		"host@1.0.0":  {Dependencies: map[string]string{"t": "0.5.0"}},
		"top@1.0.0":   {Dependencies: map[string]string{"host": "^1.0.0"}},
		"other@1.0.0": {Dependencies: map[string]string{"host": "^1.0.0"}},
	}
	run := func(variants int) (*chainScope, *updateFailure) {
		manifest, lock := pnpmHostLock(variants)
		it := &LanguageItem{Manager: ManagerPnpm, Packages: []LanguagePackage{tPkg()}}
		set, _ := newUpdateSet(it)
		r := &updateRun{
			u:  &LangUpdater{cfg: LangUpdateConfig{Npm: &fakeNpm{dists: dists}}},
			it: it, set: set, full: set, upd: &LanguageUpdate{}, shared: newItemShared(),
			src:      &sourceFiles{manifest: []byte(manifest), lock: lock, manifestName: "package.json", lockName: "pnpm-lock.yaml"},
			manifest: []byte(manifest),
		}
		g0, err := buildGraph(bg, ManagerPnpm, lock)
		if err != nil {
			t.Fatal(err)
		}
		return buildChainScope(bg, r, g0, []string{"t"})
	}
	t.Run("every snapshot of a package that is an ancestor is one, with its ancestors", func(t *testing.T) {
		scope, fail := run(2)
		if fail != nil || scope == nil {
			t.Fatalf("scope = %v, failure = %+v", scope, fail)
		}
		var anc []string
		for k := range scope.Anc {
			anc = append(anc, k)
		}
		sort.Strings(anc)
		want := "host@1.0.0(peer@1.0.0),host@1.0.0(peer@2.0.0),other@1.0.0,top@1.0.0"
		if strings.Join(anc, ",") != want {
			t.Errorf("Anc = %v", anc)
		}
		if len(scope.Tops) != 2 || scope.Tops[0].Name != "other" || scope.Tops[1].Name != "top" {
			t.Errorf("Tops = %+v", scope.Tops)
		}
	})
	t.Run("the limit counts after the snapshots are added", func(t *testing.T) {
		// One snapshot is the parent of the pinning requirement; its 32 siblings
		// bring the ancestors over the limit, though 3 would not be.
		if _, fail := run(maxChainAncestors); fail == nil || fail.reason != ReasonDependentsLimit {
			t.Fatalf("failure = %+v", fail)
		}
		if scope, fail := run(maxChainAncestors - 3); fail != nil || len(scope.Anc) != maxChainAncestors-3+2 {
			t.Fatalf("scope = %+v, failure = %+v", scope, fail)
		}
	})
}

func TestChainRemovalLeavesOnlyAllowedReferences(t *testing.T) {
	// After the entries of the ancestors, the updated packages and what is
	// nested below either are taken out, a kept entry can still refer to one
	// of them only by a requirement on an updated package (a requirement that
	// allows the fix, or one on an entry that was already fixed) or a peer-only
	// requirement on an ancestor; the project's own requirements on the tops
	// stay in the root.
	root := map[string]string{"mkdirp": "^0.5.1", "rc": "^1.2.0", "host": "^1.0.0", "plug": "^1.0.0"}
	lock := npmLock(root, map[string]npmEntry{
		"node_modules/mkdirp":                     {ver: "0.5.1", deps: map[string]string{"minimist": "0.0.8", "nested": "^1.0.0"}},
		"node_modules/mkdirp/node_modules/nested": {ver: "1.0.0", deps: map[string]string{"minimist": "^1.0.0"}},
		"node_modules/minimist":                   {ver: "0.0.8"},
		"node_modules/rc":                         {ver: "1.2.8", deps: map[string]string{"minimist": "^1.2.0"}},
		"node_modules/rc/node_modules/minimist":   {ver: "1.2.0"},
		"node_modules/host":                       {ver: "1.0.0"},
		"node_modules/plug":                       {ver: "1.0.0", deps: map[string]string{"mkdirp": "^0.5.0"}},
	})
	dists := map[string]NpmDist{
		"mkdirp@0.5.1": {Dependencies: map[string]string{"minimist": "0.0.8", "nested": "^1.0.0"}},
		"rc@1.2.8":     {Dependencies: map[string]string{"minimist": "^1.2.0"}},
		"plug@1.0.0":   {PeerDependencies: map[string]string{"mkdirp": "^0.5.0"}},
		"nested@1.0.0": {Dependencies: map[string]string{"minimist": "^1.0.0"}},
	}
	manifest := manifestOf("mkdirp", "rc", "host", "plug")
	r := chainRun(t, manifest, lock, dists, minimistPkg())
	g0, err := buildGraph(bg, ManagerNpm, lock)
	if err != nil {
		t.Fatal(err)
	}
	scope, fail := buildChainScope(bg, r, g0, []string{"minimist"})
	if fail != nil || scope == nil {
		t.Fatalf("scope = %v, failure = %+v", scope, fail)
	}
	if scope.Anc["node_modules/plug"] {
		t.Fatalf("a peer-only requirement made plug an ancestor: %v", scope.Anc)
	}
	if !scope.RNest["node_modules/mkdirp/node_modules/nested"] {
		t.Fatalf("RNest = %v", scope.RNest)
	}
	scope.markPeerOnly(g0)
	removed := func(k string) bool { return scope.RAnc[k] || scope.RTgt[k] || scope.RNest[k] }
	for _, n := range g0.list {
		if removed(n.key) {
			continue
		}
		for _, e := range n.deps {
			if e.key == "" || !removed(e.key) {
				continue
			}
			target := g0.nodes[e.key]
			switch {
			case scope.Targets[target.name]:
				// A requirement on an updated package that allows the fix.
			case e.peerOnly && scope.RAnc[e.key]:
				// A peer requirement on an ancestor.
			default:
				t.Errorf("%s keeps a reference to %s that is none of the allowed kinds", n.key, e.key)
			}
		}
	}
	// The pinning requirements are all inside what is taken out.
	for k := range scope.Be {
		for _, p := range g0.list {
			for _, e := range p.deps {
				if e.key == k && !e.peerOnly && !removed(p.key) {
					t.Errorf("%s requires the pinned %s and is kept", p.key, k)
				}
			}
		}
	}
}

func TestExcludeDeclared(t *testing.T) {
	// minimist is a dependency of the project, its range allows the fix, and the
	// finding is on a nested old copy only: the ordinary update's set does not
	// see it as direct, and the chain update leaves it alone.
	manifest := `{"name":"app","version":"1.0.0","dependencies":{"mkdirp":"^0.5.1","minimist":"^1.2.0"}}`
	root := map[string]string{"mkdirp": "^0.5.1", "minimist": "^1.2.0"}
	lock := npmLock(root, map[string]npmEntry{
		"node_modules/mkdirp":                       {ver: "0.5.1", deps: map[string]string{"minimist": "0.0.8"}},
		"node_modules/mkdirp/node_modules/minimist": {ver: "0.0.8"},
		"node_modules/minimist":                     {ver: "1.2.8"},
	})
	g0 := graphOf(t, lock)
	pkg := minimistPkg()
	pkg.Occurrences = []SourceOccurrence{{Path: "node_modules/mkdirp/node_modules/minimist", Version: "0.0.8", Matched: true}}
	it := &LanguageItem{Manager: ManagerNpm, Packages: []LanguagePackage{pkg}}
	set, _ := newUpdateSet(it)
	if set.direct["minimist"] {
		t.Fatal("the ordinary set takes it as direct")
	}
	if got := excludeDeclared(ManagerNpm, []byte(manifest), g0, []string{"minimist", "other"}); strings.Join(got, ",") != "other" {
		t.Errorf("excluded = %v", got)
	}
	if set.direct["minimist"] {
		t.Error("the update set changed")
	}
	t.Run("not in the manifest but required by the project's lockfile record", func(t *testing.T) {
		g := graphOf(t, lock)
		got := excludeDeclared(ManagerNpm, []byte(`{"name":"app","version":"1.0.0"}`), g, []string{"minimist"})
		if len(got) != 0 {
			t.Errorf("excluded = %v", got)
		}
	})
	t.Run("declared in any field", func(t *testing.T) {
		for _, field := range manifestDepFields {
			m := fmt.Sprintf(`{"name":"app","version":"1.0.0","%s":{"minimist":"*"}}`, field)
			g := graphOf(t, npmLock(map[string]string{}, map[string]npmEntry{"node_modules/minimist": {ver: "0.0.8"}}))
			if got := excludeDeclared(ManagerNpm, []byte(m), g, []string{"minimist"}); len(got) != 0 {
				t.Errorf("%s: excluded = %v", field, got)
			}
		}
	})
	t.Run("a manifest that cannot be read judges nothing", func(t *testing.T) {
		if got := excludeDeclared(ManagerNpm, []byte(`[`), g0, []string{"x"}); got != nil {
			t.Errorf("got %v", got)
		}
	})
	t.Run("uv declarations", func(t *testing.T) {
		py := "[project]\nname = \"p\"\nversion = \"1\"\ndependencies = [\"Requests>=2\"]\n[dependency-groups]\ndev = [\"idna\"]\n"
		g := &depGraph{nodes: map[string]*depNode{}}
		got := excludeDeclared(ManagerUv, []byte(py), g, []string{"requests", "idna", "urllib3"})
		if strings.Join(got, ",") != "urllib3" {
			t.Errorf("excluded = %v", got)
		}
	})
}

func TestChainCandidates(t *testing.T) {
	run := func(m DependencyManager) *updateRun {
		it := &LanguageItem{Manager: m, Packages: []LanguagePackage{
			{Name: "b", Installed: "1.0.0", SelectionLowerBound: "2.0.0", Action: ActionUpdate},
			{Name: "a", Installed: "1.0.0", SelectionLowerBound: "2.0.0", Action: ActionUpdate},
		}}
		set, _ := newUpdateSet(it)
		return &updateRun{it: it, set: set, full: set}
	}
	names := func(l []string) string { return strings.Join(l, ",") }
	t.Run("the lockfile left as it was", func(t *testing.T) {
		if got := chainCandidates(run(ManagerNpm), &updateFailure{lockUnchanged: true}); names(got) != "a,b" {
			t.Errorf("got %v", got)
		}
	})
	t.Run("every package short of its target", func(t *testing.T) {
		if got := chainCandidates(run(ManagerPnpm), &updateFailure{allUnreached: true}); names(got) != "a,b" {
			t.Errorf("got %v", got)
		}
	})
	t.Run("a package left out of a passing result", func(t *testing.T) {
		r := run(ManagerNpm)
		r.leftOut = map[string]updateFailureDetail{"b": {}}
		if got := chainCandidates(r, nil); names(got) != "b" {
			t.Errorf("got %v", got)
		}
	})
	t.Run("a package that asks to be run again without", func(t *testing.T) {
		got := chainCandidates(run(ManagerNpm), &updateFailure{retryWithout: map[string]updateFailureDetail{"a": {}}})
		if names(got) != "a" {
			t.Errorf("got %v", got)
		}
	})
	t.Run("a package that is not pinned to a version is not one", func(t *testing.T) {
		f := pkgFailure("a", ReasonTargetNotUpdated, "a at x is not pinned to a version in the updated file")
		if got := chainCandidates(run(ManagerNpm), f); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("other failures", func(t *testing.T) {
		if got := chainCandidates(run(ManagerNpm), manualFailure(ReasonUnexplainedDiff, "x")); len(got) != 0 {
			t.Errorf("got %v", got)
		}
		if got := chainCandidates(run(ManagerPip), &updateFailure{lockUnchanged: true}); len(got) != 0 {
			t.Errorf("pip: got %v", got)
		}
	})
	t.Run("uv only after the baseline was consistent", func(t *testing.T) {
		if got := chainCandidates(run(ManagerUv), &updateFailure{reason: ReasonUpdateStepFailed}); len(got) != 0 {
			t.Errorf("got %v", got)
		}
		if got := chainCandidates(run(ManagerUv), &updateFailure{reason: ReasonUpdateStepFailed, baselineVerified: true}); names(got) != "a,b" {
			t.Errorf("got %v", got)
		}
		if got := chainCandidates(run(ManagerUv), &updateFailure{lockUnchanged: true}); len(got) != 0 {
			t.Errorf("a uv lockfile left alone is not a candidate: %v", got)
		}
	})
}

func TestBaselineVerified(t *testing.T) {
	src := []byte("lock")
	out := &jobOutput{files: map[string][]byte{"steps/baseline/uv.lock": src}}
	if !baselineVerified(out, src, "uv.lock") {
		t.Error("the baseline returned the original and was not taken as verified")
	}
	if baselineVerified(out, []byte("other"), "uv.lock") {
		t.Error("a baseline that returned something else was verified")
	}
	if baselineVerified(&jobOutput{files: map[string][]byte{}}, src, "uv.lock") || baselineVerified(nil, src, "uv.lock") {
		t.Error("a missing baseline was verified")
	}
}

func TestAncestorsOf(t *testing.T) {
	lock := npmLock(map[string]string{"a": "^1.0.0"}, map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"b": "^1.0.0"}},
		"node_modules/b": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0", "a": "^1.0.0"}},
		"node_modules/c": {ver: "1.0.0"},
		"node_modules/p": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}},
	})
	g := graphOf(t, lock)
	keys := func(m map[string]bool) string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := keys(ancestorsOf(bg, g, []string{"node_modules/c"})); got != "node_modules/a,node_modules/b,node_modules/c,node_modules/p" {
		t.Errorf("ancestors = %s", got)
	}
	for i := range g.nodes["node_modules/p"].deps {
		g.nodes["node_modules/p"].deps[i].peerOnly = true
	}
	if got := keys(ancestorsOf(bg, g, []string{"node_modules/c"})); got != "node_modules/a,node_modules/b,node_modules/c" {
		t.Errorf("a peer-only requirement was followed: %s", got)
	}
}

func TestBuildChainScopeNamesTheDirectDependencyAboveAPinningParent(t *testing.T) {
	// top requires middle, which requires t exactly: the evidence names middle
	// as the parent and top as the direct dependency it hangs below.
	lock, dists := fanLock([]string{"top"}, map[string][]string{"top": {"middle"}, "middle": nil})
	r := chainRun(t, manifestOf("top"), lock, dists, tPkg())
	g0, _ := buildGraph(bg, ManagerNpm, lock)
	scope, fail := buildChainScope(bg, r, g0, []string{"t"})
	if fail != nil || scope == nil {
		t.Fatalf("scope = %v, failure = %+v", scope, fail)
	}
	if len(scope.Blocked) != 1 || scope.Blocked[0].Parent != "middle" || strings.Join(scope.Blocked[0].Via, ",") != "top" || len(scope.Tops) != 1 || scope.Tops[0].Name != "top" {
		t.Errorf("Blocked = %+v, Tops = %+v", scope.Blocked, scope.Tops)
	}
	moves := chainMovesOf(&ChainUpdate{Blocked: scope.Blocked, Tops: []ChainMove{{Name: "top", From: "1.0.0", To: "1.1.0"}}})
	if len(moves) != 1 || moves[0].Held != "t" || moves[0].HeldRange != "0.5.0" || moves[0].HeldBy != "middle" {
		t.Errorf("moves = %+v", moves)
	}
}
