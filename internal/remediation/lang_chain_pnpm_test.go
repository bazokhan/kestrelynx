package remediation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The pnpm project of these tests is the mkdirp and rc project of the npm
// ones: mkdirp holds minimist at exactly 0.0.8 and rc, whose range allows the
// fix, has the vulnerable 1.2.0 of its own.
func mkdirpPnpm(mkdirp, minimist string, rcMinimist string) string {
	min := func(v string) map[string]string { return map[string]string{"minimist": v} }
	pkgs := []genPkg{
		{"mkdirp", mkdirp, min(minimist)}, {"minimist", minimist, nil},
		{"rc", "1.2.8", min(rcMinimist)},
	}
	if rcMinimist != minimist {
		pkgs = append(pkgs, genPkg{"minimist", rcMinimist, nil})
	}
	return genPnpmLock([]genImp{{"mkdirp", "^0.5.1", mkdirp}, {"rc", "^1.2.0", "1.2.8"}}, pkgs)
}

func mkdirpPnpmHarness(t *testing.T, afterChain func(n int) string) *harness {
	manifest := `{"name":"fixture-chain","version":"1.0.0","private":true,"dependencies":{"mkdirp":"^0.5.1","rc":"^1.2.0"}}`
	dists := map[string]NpmDist{
		"mkdirp@0.5.1":   genDist("mkdirp", "0.5.1", map[string]string{"minimist": "0.0.8"}),
		"mkdirp@0.5.6":   genDist("mkdirp", "0.5.6", map[string]string{"minimist": "^1.2.6"}),
		"minimist@1.2.8": genDist("minimist", "1.2.8", nil),
		"rc@1.2.8":       genDist("rc", "1.2.8", map[string]string{"minimist": "^1.2.0"}),
	}
	findings := map[string]string{"minimist@0.0.8": "CVE-2021-44906", "minimist@1.2.0": "CVE-2021-44906"}
	return newGenHarness(t, manifest, mkdirpPnpm("0.5.1", "0.0.8", "1.2.0"), []*findingGroup{minimistGroupAt("0.0.8")}, dists, findings, afterChain)
}

func TestPnpmChainTakesAPinnedPackageThroughItsDirectDependency(t *testing.T) {
	chainLock := mkdirpPnpm("0.5.6", "1.2.8", "1.2.8")
	h := mkdirpPnpmHarness(t, func(n int) string {
		if n == 0 {
			return ""
		}
		return chainLock
	})
	up, _ := NewLangUpdater(h.cfg)
	plan := &Plan{LanguageItems: []LanguageItem{h.item}}
	up.Run(bg, plan)
	it := plan.LanguageItems[0]
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 2 {
		t.Fatalf("containers = %d: the first update and the chain update", h.work.calls)
	}
	min := packageOf(t, it, "minimist")
	if min.AdoptedVersion != "1.2.8" || strings.Join(min.Through, ",") != "mkdirp" {
		t.Errorf("minimist = %+v", min)
	}
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0].Name != "mkdirp" || c.Tops[0].To != "0.5.6" {
		t.Errorf("chain = %+v", c)
	}
	if len(c.Moves) != 0 {
		t.Errorf("moves = %+v: the top and the updated package are not listed among them", c.Moves)
	}
	if string(it.Artifacts[0].Content) != chainLock {
		t.Error("the artifact is not the chain's lockfile")
	}
	// The lockfile the chain job was given lacks mkdirp (its snapshot, its
	// record and its place in the importer) and every minimist, and keeps rc.
	given := string(h.work.srcs[1]["pnpm-lock.yaml"])
	for _, gone := range []string{"mkdirp", "minimist@"} {
		if strings.Contains(given, gone) {
			t.Errorf("the chain job's lockfile still has %q:\n%s", gone, given)
		}
	}
	if !strings.Contains(given, "rc@1.2.8") {
		t.Errorf("rc was taken out:\n%s", given)
	}
	steps := h.work.jobs[1].Steps
	if len(steps) != 2 || steps[0].Op != worker.OpPnpmRelock || steps[1].Op != worker.OpPnpmFrozen || !steps[1].Scratch {
		t.Errorf("chain job steps = %+v: the update and the frozen check, and no check of the original", steps)
	}
}

func TestPnpmChainRefusesAResultThatIsNotStableUnderAFrozenInstall(t *testing.T) {
	chainLock := mkdirpPnpm("0.5.6", "1.2.8", "1.2.8")
	h := mkdirpPnpmHarness(t, nil)
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": src["pnpm-lock.yaml"]}}}
		}
		// The frozen install changes the file it was given.
		return fakeOutcome{edit: map[string]map[string][]byte{
			stepUpdate: {"pnpm-lock.yaml": []byte(chainLock)},
			stepCheck:  {"pnpm-lock.yaml": []byte(chainLock + "\n# changed\n")},
		}}
	}
	up, _ := NewLangUpdater(h.cfg)
	plan := &Plan{LanguageItems: []LanguageItem{h.item}}
	up.Run(bg, plan)
	it := plan.LanguageItems[0]
	if it.Category == CategoryPRCandidate {
		t.Fatalf("a result that a frozen install changes was proposed")
	}
	if c := it.Update.Chain; c == nil || c.Outcome != ChainRejected || c.Reason != ReasonPostUpdateLockUnstable {
		t.Errorf("chain = %+v", c)
	}
	if pk := packageOf(t, it, "minimist"); pk.Reason != ReasonDependentsRejected {
		t.Errorf("minimist = %+v", pk)
	}
}

func TestRemovePnpmEntries(t *testing.T) {
	_, lock := pnpmHostLock(2)
	got, problem := removePnpmEntries(bg, lock, map[string]bool{"t": true},
		map[string]bool{"host@1.0.0(peer@1.0.0)": true, "host@1.0.0(peer@2.0.0)": true, "top@1.0.0": true},
		map[string]bool{"top": true})
	if problem != nil {
		t.Fatal(problem.detail)
	}
	out := string(got.lock)
	for _, gone := range []string{"host@", "top@", "t@0.5.0", "      top:"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q is still in:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"other@1.0.0", "peer@1.0.0", "      other:"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q was taken out:\n%s", kept, out)
		}
	}
	if strings.Join(got.direct, ",") != "top" {
		t.Errorf("direct = %v", got.direct)
	}
	// A package record stays while one of its snapshots does.
	one, problem := removePnpmEntries(bg, lock, map[string]bool{"t": true}, map[string]bool{"host@1.0.0(peer@1.0.0)": true}, map[string]bool{"top": true})
	if problem != nil {
		t.Fatal(problem.detail)
	}
	if !strings.Contains(string(one.lock), "  host@1.0.0:\n    resolution") {
		t.Errorf("the record of host went with one of its two snapshots:\n%s", one.lock)
	}
	// A snapshot the lockfile does not have, and a removal with no top, are refused.
	if _, problem := removePnpmEntries(bg, lock, map[string]bool{"t": true}, map[string]bool{"zzz@1.0.0": true}, map[string]bool{"top": true}); problem == nil || problem.reason != ReasonTargetNotInLockfile {
		t.Errorf("a snapshot the lockfile lacks: %+v", problem)
	}
	if _, problem := removePnpmEntries(bg, lock, map[string]bool{"t": true}, nil, nil); problem == nil {
		t.Error("an update that takes nothing out of the importer was made")
	}
	// Without snapshots and tops it is the removal of the targets that removePnpmTargets makes.
	a, _ := removePnpmTargets(bg, lock, map[string]bool{"t": true})
	if a == nil || strings.Contains(string(a.lock), "t@0.5.0") || !strings.Contains(string(a.lock), "host@1.0.0(peer@1.0.0)") {
		t.Errorf("removePnpmTargets changed: %v", a)
	}
}

func TestChainScopeInTheKeysOfAPnpmComparisonGraph(t *testing.T) {
	scope := &chainScope{
		Be: map[string]bool{"t@0.5.0": true}, Anc: map[string]bool{"host@1.0.0(peer@1.0.0)": true, "top@1.0.0": true},
		RAnc: map[string]bool{"host@1.0.0(peer@1.0.0)": true}, RTgt: map[string]bool{"t@0.5.0": true}, RNest: map[string]bool{},
		Tops:  []chainTop{{Name: "top", Key: "top@1.0.0"}},
		peers: map[string]map[string]bool{"host@1.0.0(peer@1.0.0)": {"peer": true}},
	}
	got, err := scope.inGraph(bg, map[string]bool{"peer": true})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Anc["host@1.0.0"] || !got.RAnc["host@1.0.0"] || got.Anc["host@1.0.0(peer@1.0.0)"] || !got.Be["t@0.5.0"] || got.Tops[0].Key != "top@1.0.0" {
		t.Errorf("scope = %+v", got)
	}
	if !got.peers["host@1.0.0"]["peer"] {
		t.Errorf("peers = %v", got.peers)
	}
	if scope.Anc["host@1.0.0"] {
		t.Error("the scope it was made from changed")
	}
	// Peer-only requirements are recognised on a graph with the mapped keys, and
	// not when the mapping of their keys could not be made.
	build := func(sc *chainScope) *depGraph {
		g := &depGraph{nodes: map[string]*depNode{
			"host@1.0.0": {name: "host", version: "1.0.0", deps: []depEdge{{name: "peer", key: "peer@1.0.0"}, {name: "t", key: "t@0.5.0"}}},
			"peer@1.0.0": {name: "peer", version: "1.0.0"}, "t@0.5.0": {name: "t", version: "0.5.0"},
		}}
		g.link()
		sc.markPeerOnly(g)
		return g
	}
	if g := build(got); !g.nodes["host@1.0.0"].deps[0].peerOnly || g.nodes["host@1.0.0"].deps[1].peerOnly {
		t.Errorf("deps = %+v", g.nodes["host@1.0.0"].deps)
	}
	// A key over the bounds of a peer context cannot be mapped. For the entries
	// that is an error; for the peer-only requirements it leaves them unmarked.
	long := "x@1.0.0(" + strings.Repeat("a", maxPeerSuffixBytes) + ")"
	scope.peers[long] = map[string]bool{"peer": true}
	got, err = scope.inGraph(bg, map[string]bool{"peer": true})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.peers != nil {
		t.Errorf("peers = %v", got.peers)
	}
	if g := build(got); g.nodes["host@1.0.0"].deps[0].peerOnly {
		t.Error("a requirement was taken as peer-only without the mapping")
	}
	scope.Anc[long] = true
	if _, err := scope.inGraph(bg, map[string]bool{"peer": true}); err == nil {
		t.Error("an entry key that cannot be mapped was accepted")
	}
}

// peerChainLock is a pnpm project in which lib has top as a peer dependency, so that
// lib's snapshot key carries the version of top it was installed with.
func peerChainLock(top, t string) string {
	return fmt.Sprintf(`lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      lib:
        specifier: ^1.0.0
        version: 1.0.0(top@%[1]s)
      top:
        specifier: ^1.0.0
        version: %[1]s

packages:

  lib@1.0.0:
    resolution: {integrity: %[3]s}
    peerDependencies:
      top: ^1.0.0

  t@%[2]s:
    resolution: {integrity: %[4]s}

  top@%[1]s:
    resolution: {integrity: %[5]s}

snapshots:

  lib@1.0.0(top@%[1]s):
    dependencies:
      top: %[1]s

  t@%[2]s: {}

  top@%[1]s:
    dependencies:
      t: %[2]s
`, top, t, chainIntegrity("lib", "1.0.0"), chainIntegrity("t", t), chainIntegrity("top", top))
}

func TestPnpmChainWithAPeerContextOfAChainPackageInAKey(t *testing.T) {
	// lib's snapshot key names the version of top it was installed with, and the
	// chain update moves top: lib's key changes with it, and that is not a change
	// of lib. The requirement of lib on top is a peer and is not followed.
	manifest := `{"name":"fixture-peer","version":"1.0.0","private":true,"dependencies":{"lib":"^1.0.0","top":"^1.0.0"}}`
	dists := map[string]NpmDist{
		"top@1.0.0": genDist("top", "1.0.0", map[string]string{"t": "0.5.0"}),
		"top@1.1.0": genDist("top", "1.1.0", map[string]string{"t": "^1.2.6"}),
		"t@1.2.8":   genDist("t", "1.2.8", nil),
		"lib@1.0.0": {Tarball: "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz", Integrity: chainIntegrity("lib", "1.0.0"), PeerDependencies: map[string]string{"top": "^1.0.0"}},
	}
	h := newGenHarness(t, manifest, peerChainLock("1.0.0", "0.5.0"), []*findingGroup{genGroup("t", "0.5.0", "CVE-T", "1.2.6")}, dists,
		map[string]string{"t@0.5.0": "CVE-T"}, func(n int) string {
			if n == 0 {
				return ""
			}
			return peerChainLock("1.1.0", "1.2.8")
		})
	up, _ := NewLangUpdater(h.cfg)
	plan := &Plan{LanguageItems: []LanguageItem{h.item}}
	up.Run(bg, plan)
	it := plan.LanguageItems[0]
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if c := it.Update.Chain; c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0].Name != "top" {
		t.Fatalf("chain = %+v", c)
	}
	// lib is not an ancestor, and its snapshot was not taken out.
	if given := string(h.work.srcs[1]["pnpm-lock.yaml"]); !strings.Contains(given, "lib@1.0.0(top@1.0.0)") || strings.Contains(given, "top@1.0.0:") {
		t.Errorf("the chain job's lockfile:\n%s", given)
	}
}

func TestChainMovesNameTheEntriesOfAPnpmDifference(t *testing.T) {
	// The keys of the difference are written without the peer contexts of the
	// packages of the chain and of the updated ones, so the snapshot keys of the
	// target and of the top are rewritten: they are still not moves, and what is
	// listed has names and versions.
	node := func(name, ver string, deps ...depEdge) *depNode {
		return &depNode{name: name, version: ver, deps: deps}
	}
	g0 := &depGraph{
		nodes: map[string]*depNode{
			"top@1.0.0(t@0.5.0)": node("top", "1.0.0", depEdge{name: "mid", key: "mid@1.0.0"}),
			"mid@1.0.0":          node("mid", "1.0.0", depEdge{name: "t", key: "t@0.5.0(mid@1.0.0)"}, depEdge{name: "old", key: "old@1.0.0"}),
			"t@0.5.0(mid@1.0.0)": node("t", "0.5.0"),
			"old@1.0.0":          node("old", "1.0.0"),
		},
		roots: []depEdge{{name: "top", key: "top@1.0.0(t@0.5.0)"}},
	}
	g1 := &depGraph{
		nodes: map[string]*depNode{
			"top@1.1.0(t@1.2.8)": node("top", "1.1.0", depEdge{name: "mid", key: "mid@1.1.0"}),
			"mid@1.1.0":          node("mid", "1.1.0", depEdge{name: "t", key: "t@1.2.8(mid@1.1.0)"}, depEdge{name: "new", key: "new@1.0.0"}),
			"t@1.2.8(mid@1.1.0)": node("t", "1.2.8"),
			"new@1.0.0":          node("new", "1.0.0"),
		},
		roots: []depEdge{{name: "top", key: "top@1.1.0(t@1.2.8)"}},
	}
	g0.link()
	g1.link()
	scope := &chainScope{
		Names: map[string]bool{"top": true, "mid": true}, Targets: map[string]bool{"t": true},
		Anc:  map[string]bool{"top@1.0.0(t@0.5.0)": true, "mid@1.0.0": true},
		Tops: []chainTop{{Name: "top", Key: "top@1.0.0(t@0.5.0)"}},
	}
	names := map[string]bool{"t": true, "top": true, "mid": true}
	diff := &DependencyDiff{
		Added:   []string{"mid@1.1.0", "new@1.0.0", "t@1.2.8", "top@1.1.0"},
		Removed: []string{"mid@1.0.0", "old@1.0.0", "t@0.5.0", "top@1.0.0"},
	}
	got, _ := chainMovesIn(bg, ManagerPnpm, names, scope, diff, g0, g1)
	var text []string
	for _, m := range got {
		text = append(text, m.Kind+" "+m.Name+" "+m.From+">"+m.To)
	}
	want := []string{"added mid >1.1.0", "added new >1.0.0", "removed mid 1.0.0>", "removed old 1.0.0>"}
	if strings.Join(text, "|") != strings.Join(want, "|") {
		t.Errorf("moves = %q, want %q", text, want)
	}
}

func TestNormalizedGraphKeepsLocalReferencesAsWritten(t *testing.T) {
	// An untouched package has an optional requirement for a local directory
	// whose reference ends in a peer context of the updated package. The context
	// is left out of a registry reference and not of a local one: a change in the
	// local one is a change of source, and the ordinary update refuses it.
	graph := func(next, ref string) *depGraph {
		g := &depGraph{
			nodes: map[string]*depNode{
				"a@1.0.0":      {name: "a", version: "1.0.0", deps: []depEdge{{name: "x", ref: ref, local: true, optional: true}, {name: "next", key: "next@" + next + "", ref: next}}},
				"next@" + next: {name: "next", version: next},
			},
			roots: []depEdge{{name: "a", key: "a@1.0.0", ref: "1.0.0"}},
		}
		g.link()
		return g
	}
	names := map[string]bool{"next": true}
	before, err := normalizedGraph(bg, graph("1.0.0", "link:vendor/x(next@1.0.0)"), names)
	if err != nil {
		t.Fatal(err)
	}
	after, err := normalizedGraph(bg, graph("2.0.0", "link:vendor/x(next@2.0.0)"), names)
	if err != nil {
		t.Fatal(err)
	}
	if got := before.nodes["a@1.0.0"].deps[0].ref; got != "link:vendor/x(next@1.0.0)" {
		t.Errorf("local reference = %q", got)
	}
	reg := graph("1.0.0", "link:vendor/x(next@1.0.0)")
	reg.nodes["a@1.0.0"].deps[1].ref = "1.0.0(next@1.0.0)"
	if n, _ := normalizedGraph(bg, reg, names); n.nodes["a@1.0.0"].deps[1].ref != "1.0.0" {
		t.Errorf("registry reference = %q", n.nodes["a@1.0.0"].deps[1].ref)
	}
	_, reason, detail := diffGraphs(bg, before, after, names)
	if reason != ReasonResolvedSourceChanged {
		t.Fatalf("reason = %q (%s): a changed local reference of an untouched package was explained", reason, detail)
	}
}

func TestChainMovesAreNotListedWhenTheKeysCannotBeMatched(t *testing.T) {
	// A key whose peer contexts are over the bounds cannot be written without
	// the contexts of the chain's packages: the entries of the difference cannot
	// be matched to the graphs, so none is listed and the list is marked cut.
	long := "x@1.0.0(" + strings.Repeat("a", maxPeerSuffixBytes) + ")"
	g0 := &depGraph{nodes: map[string]*depNode{long: {name: "x", version: "1.0.0"}}}
	g0.link()
	scope := &chainScope{Names: map[string]bool{}, Targets: map[string]bool{"t": true}, Anc: map[string]bool{}}
	diff := &DependencyDiff{Removed: []string{"x@1.0.0"}}
	got, truncated := chainMovesIn(bg, ManagerPnpm, map[string]bool{"t": true}, scope, diff, g0, nil)
	if len(got) != 0 || !truncated {
		t.Errorf("moves = %+v, truncated = %v", got, truncated)
	}
}
