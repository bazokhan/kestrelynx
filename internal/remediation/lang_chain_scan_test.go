package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func scanOf(typ string, pkgs [][2]string, vulns [][3]string) scanner.ImageScan {
	return fsReport(typ, pkgs, vulns).Report
}

func plainKey(n string) string { return n }

func noKEV(string) bool { return false }

func graphOf(t *testing.T, lock []byte) *depGraph {
	t.Helper()
	g, err := npmGraph(bg, lock)
	if err != nil {
		t.Fatal(err)
	}
	g.link()
	return g
}

// checkRun is a run of an update of t from 0.5.0 to 1.2.8 that the ordinary
// comparison of findings can judge.
func checkRun() *updateRun {
	it := &LanguageItem{Manager: ManagerNpm, Packages: []LanguagePackage{{
		Name: "t", Installed: "0.5.0", SelectionLowerBound: "1.2.6", Action: ActionUpdate,
		CVEs: []CVERef{{VulnID: "CVE-T", FixedVers: []string{"1.2.6"}}},
	}}}
	set, _ := newUpdateSet(it)
	return &updateRun{u: &LangUpdater{}, it: it, set: set, full: set, afterVersions: map[string][]string{"t": {"1.2.8"}}}
}

func TestChainScanCounterExamples(t *testing.T) {
	root := map[string]string{"a": "^1.0.0", "b": "^1.0.0"}
	t.Run("a vulnerability of a version that was not there", func(t *testing.T) {
		before := scanOf("npm", [][2]string{{"t", "0.5.0"}, {"x", "1.0.0"}}, [][3]string{{"t", "0.5.0", "CVE-T"}, {"x", "1.0.0", "CVE-X"}})
		after := scanOf("npm", [][2]string{{"t", "1.2.8"}, {"x", "1.0.0"}, {"x", "3.0.0"}}, [][3]string{{"x", "1.0.0", "CVE-X"}, {"x", "3.0.0", "CVE-X"}})
		// The ordinary comparison names a package and a vulnerability apart from
		// the version, and passes: x has CVE-X before and after.
		r := checkRun()
		if f := r.evaluateSourceCheck(&SourceCheck{}, before, after); f != nil {
			t.Fatalf("the ordinary comparison: %s: %s", f.reason, f.detail)
		}
		g := graphOf(t, npmLock(root, map[string]npmEntry{"node_modules/a": {ver: "1.0.0"}, "node_modules/b": {ver: "1.0.0"}, "node_modules/x": {ver: "1.0.0"}}))
		sc := &SourceCheck{}
		f := evaluateChainScan(sc, before, after, g, g, "npm", plainKey, noKEV)
		if f == nil || f.reason != ReasonSourceIntroduced {
			t.Fatalf("failure = %+v", f)
		}
		if sc.Basis != "package_version_vuln_edges" || len(sc.ChainNewTriples) != 1 || sc.ChainNewTriples[0].Version != "3.0.0" || sc.Passed {
			t.Errorf("record = %+v", sc)
		}
	})
	t.Run("a new vulnerability that is KEV-listed", func(t *testing.T) {
		before := scanOf("npm", [][2]string{{"x", "1.0.0"}}, nil)
		after := scanOf("npm", [][2]string{{"x", "1.0.0"}}, [][3]string{{"x", "1.0.0", "CVE-K"}})
		g := graphOf(t, npmLock(root, map[string]npmEntry{"node_modules/x": {ver: "1.0.0"}}))
		f := evaluateChainScan(&SourceCheck{}, before, after, g, g, "npm", plainKey, func(id string) bool { return id == "CVE-K" })
		if f == nil || f.reason != ReasonSourceIntroducedKEV {
			t.Fatalf("failure = %+v", f)
		}
	})
	t.Run("more entries of a vulnerable version", func(t *testing.T) {
		// The update of t is judged too: t is found before and fixed after.
		before := scanOf("npm", [][2]string{{"t", "0.5.0"}, {"x", "1.0.0"}}, [][3]string{{"t", "0.5.0", "CVE-T"}, {"x", "1.0.0", "CVE-X"}})
		scan := scanOf("npm", [][2]string{{"t", "1.2.8"}, {"x", "1.0.0"}}, [][3]string{{"x", "1.0.0", "CVE-X"}})
		one := graphOf(t, npmLock(root, map[string]npmEntry{"node_modules/a": {ver: "1.0.0"}, "node_modules/x": {ver: "1.0.0"}}))
		two := graphOf(t, npmLock(root, map[string]npmEntry{"node_modules/a": {ver: "1.0.0"}, "node_modules/x": {ver: "1.0.0"}, "node_modules/a/node_modules/x": {ver: "1.0.0"}}))
		if f := r2(evaluateChainScan(&SourceCheck{}, before, scan, one, one, "npm", plainKey, noKEV)); f != "" {
			t.Fatalf("same entries: %s", f)
		}
		sc := &SourceCheck{}
		f := evaluateChainScan(sc, before, scan, one, two, "npm", plainKey, noKEV)
		if f == nil || f.reason != ReasonSourceIntroduced || len(sc.ChainEntryGrowth) != 1 || sc.ChainEntryGrowth[0].Before != 1 || sc.ChainEntryGrowth[0].After != 2 {
			t.Fatalf("failure = %+v, record = %+v", f, sc)
		}
		// The ordinary comparison does not see it.
		if f := checkRun().evaluateSourceCheck(&SourceCheck{}, before, scan); f != nil {
			t.Fatalf("the ordinary comparison: %s: %s", f.reason, f.detail)
		}
	})
	t.Run("a requirement on a vulnerable entry that a second parent now has", func(t *testing.T) {
		scan := scanOf("npm", [][2]string{{"x", "1.0.0"}}, [][3]string{{"x", "1.0.0", "CVE-X"}})
		onlyB := graphOf(t, npmLock(root, map[string]npmEntry{
			"node_modules/a": {ver: "1.0.0"}, "node_modules/b": {ver: "1.0.0", deps: map[string]string{"x": "1.0.0"}}, "node_modules/x": {ver: "1.0.0"},
		}))
		both := graphOf(t, npmLock(root, map[string]npmEntry{
			"node_modules/a": {ver: "1.0.0", deps: map[string]string{"x": "1.0.0"}}, "node_modules/b": {ver: "1.0.0", deps: map[string]string{"x": "1.0.0"}}, "node_modules/x": {ver: "1.0.0"},
		}))
		sc := &SourceCheck{}
		f := evaluateChainScan(sc, scan, scan, onlyB, both, "npm", plainKey, noKEV)
		if f == nil || f.reason != ReasonSourceIntroduced || len(sc.ChainEdgeGrowth) != 1 || sc.ChainEdgeGrowth[0].Before != 1 || sc.ChainEdgeGrowth[0].After != 2 {
			t.Fatalf("failure = %+v, record = %+v", f, sc)
		}
		if len(sc.ChainEntryGrowth) != 0 {
			t.Errorf("the entry count did not change: %+v", sc.ChainEntryGrowth)
		}
	})
	t.Run("a requirement moves between versions with the same vulnerability", func(t *testing.T) {
		// Documented limit: the number of requirements on entries with the
		// vulnerability is the same, so the move is accepted.
		before := scanOf("npm", [][2]string{{"x", "1.0.0"}, {"x", "2.0.0"}}, [][3]string{{"x", "1.0.0", "CVE-X"}, {"x", "2.0.0", "CVE-X"}})
		after := scanOf("npm", [][2]string{{"x", "1.0.0"}}, [][3]string{{"x", "1.0.0", "CVE-X"}})
		g0 := graphOf(t, npmLock(root, map[string]npmEntry{
			"node_modules/a": {ver: "1.0.0", deps: map[string]string{"x": "2.0.0"}}, "node_modules/a/node_modules/x": {ver: "2.0.0"},
			"node_modules/b": {ver: "1.0.0", deps: map[string]string{"x": "1.0.0"}}, "node_modules/x": {ver: "1.0.0"},
		}))
		g1 := graphOf(t, npmLock(root, map[string]npmEntry{
			"node_modules/a": {ver: "1.0.0", deps: map[string]string{"x": "1.0.0"}},
			"node_modules/b": {ver: "1.0.0", deps: map[string]string{"x": "1.0.0"}}, "node_modules/x": {ver: "1.0.0"},
		}))
		sc := &SourceCheck{}
		if f := evaluateChainScan(sc, before, after, g0, g1, "npm", plainKey, noKEV); f != nil {
			t.Fatalf("%s: %s", f.reason, f.detail)
		}
		if sc.Basis != "package_version_vuln_edges" {
			t.Errorf("basis = %q", sc.Basis)
		}
	})
}

// r2 is the reason of a failure, "" for none.
func r2(f *updateFailure) string {
	if f == nil {
		return ""
	}
	return string(f.reason) + ": " + f.detail
}

func TestChainScanUv(t *testing.T) {
	scan := scanOf("uv", [][2]string{{"x", "1.0"}}, [][3]string{{"x", "1.0", "CVE-X"}})
	build := func(forks int, markers ...string) *depGraph {
		x := &depNode{name: "x", version: "1.0"}
		for i := 0; i < forks; i++ {
			x.resMarkers = append(x.resMarkers, "fork"+string(rune('a'+i)))
		}
		p := &depNode{name: "p", version: "1"}
		for _, m := range markers {
			p.deps = append(p.deps, depEdge{name: "x", key: "x==1.0", marker: m})
		}
		g := &depGraph{nodes: map[string]*depNode{"x==1.0": x, "p==1": p}, roots: []depEdge{{name: "p", key: "p==1"}}}
		g.link()
		return g
	}
	t.Run("a package with two forks is one entry", func(t *testing.T) {
		if f := evaluateChainScan(&SourceCheck{}, scan, scan, build(1, ""), build(2, ""), "uv", plainKey, noKEV); f != nil {
			t.Fatalf("%s: %s", f.reason, f.detail)
		}
	})
	t.Run("records with other markers are other requirements", func(t *testing.T) {
		sc := &SourceCheck{}
		f := evaluateChainScan(sc, scan, scan, build(1, "python_version < '3.9'"), build(1, "python_version < '3.9'", "python_version >= '3.9'"), "uv", plainKey, noKEV)
		if f == nil || len(sc.ChainEdgeGrowth) != 1 || sc.ChainEdgeGrowth[0].After != 2 || !strings.Contains(f.detail, "requirements") {
			t.Fatalf("failure = %+v, record = %+v", f, sc)
		}
		// The same marker twice is one record counted once.
		if f := evaluateChainScan(&SourceCheck{}, scan, scan, build(1, "m"), build(1, "m", "m"), "uv", plainKey, noKEV); f != nil {
			t.Fatalf("%s: %s", f.reason, f.detail)
		}
	})
}
