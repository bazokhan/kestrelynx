package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// scanOfVersions makes a scan from "name version vuln,vuln" rows; a row with no
// vulnerability only lists the package.
func scanOfVersions(rows ...string) scanner.ImageScan {
	var pkgs [][2]string
	var vulns [][3]string
	for _, r := range rows {
		f := strings.Fields(r)
		pkgs = append(pkgs, [2]string{f[0], f[1]})
		if len(f) > 2 {
			for _, v := range strings.Split(f[2], ",") {
				vulns = append(vulns, [3]string{f[0], f[1], v})
			}
		}
	}
	return fsReport("npm", pkgs, vulns).Report
}

// positionCheck runs the chain comparison of findings over two graphs that are
// also the graphs the lockfiles are compared in.
func positionCheck(t *testing.T, m DependencyManager, g0, g1 *depGraph, before, after scanner.ImageScan, kev func(string) bool) (*SourceCheck, *updateFailure) {
	t.Helper()
	if kev == nil {
		kev = noKEV
	}
	sc := &SourceCheck{}
	f := evaluateChainScanWith(bg, sc, before, after, g0, g1, [2]*depGraph{g0, g1}, m, "npm", plainKey, kev)
	return sc, f
}

func wantPositionRefusal(t *testing.T, sc *SourceCheck, f *updateFailure, check, pkg string) {
	t.Helper()
	if f == nil || f.reason != ReasonSourceIntroduced || sc.Passed {
		t.Fatalf("failure = %+v, passed = %v", f, sc.Passed)
	}
	for _, r := range sc.ChainPositionRefusals {
		if r.Check == check && r.Package == pkg {
			if !strings.Contains(f.detail, check) && len(sc.ChainPositionRefusals) == 1 {
				t.Errorf("detail %q does not name the check", f.detail)
			}
			return
		}
	}
	t.Fatalf("refusals = %+v (%s), want %s of %s", sc.ChainPositionRefusals, f.detail, check, pkg)
}

func TestChainCarriesAVulnerabilityThatStaysAtItsPlace(t *testing.T) {
	t.Run("a package moves to a version with the same vulnerability", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1.0")}, tn{key: "A@1.0", name: "A", ver: "1.0"})
		g1 := tgraph([]depEdge{te("A", "A@1.5")}, tn{key: "A@1.5", name: "A", ver: "1.5"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("A 1.0 c"), scanOfVersions("A 1.5 c"), nil)
		if f != nil {
			t.Fatalf("%s: %s", f.reason, f.detail)
		}
		if len(sc.ChainCarried) != 1 || sc.ChainCarried[0] != (ChainCarried{Package: "A", From: "1.0", To: "1.5", VulnID: "c", Positions: 1}) {
			t.Errorf("carried = %+v", sc.ChainCarried)
		}
		if sc.Basis != "package_version_vuln_edges_positions" || len(sc.ChainNewTriples) != 0 {
			t.Errorf("basis = %q, new = %+v", sc.Basis, sc.ChainNewTriples)
		}
		// Without the comparison graphs the new triple is a new finding, as before.
		strict := &SourceCheck{}
		if f := evaluateChainScan(strict, scanOfVersions("A 1.0 c"), scanOfVersions("A 1.5 c"), g0, g1, "npm", plainKey, noKEV); f == nil || f.reason != ReasonSourceIntroduced || strict.Basis != "package_version_vuln_edges" {
			t.Errorf("without positions: %+v (%s)", f, strict.Basis)
		}
	})
	t.Run("at depth", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("T", "T@1")}, tn{key: "T@1", name: "T", ver: "1", deps: []depEdge{te("B", "B@2.0")}}, tn{key: "B@2.0", name: "B", ver: "2.0"})
		g1 := tgraph([]depEdge{te("T", "T@2")}, tn{key: "T@2", name: "T", ver: "2", deps: []depEdge{te("B", "B@2.1")}}, tn{key: "B@2.1", name: "B", ver: "2.1"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("T 1", "B 2.0 c"), scanOfVersions("T 2", "B 2.1 c"), nil)
		if f != nil {
			t.Fatalf("%s: %s", f.reason, f.detail)
		}
		if len(sc.ChainCarried) != 1 || sc.ChainCarried[0].Package != "B" || sc.ChainCarried[0].To != "2.1" {
			t.Errorf("carried = %+v", sc.ChainCarried)
		}
	})
	t.Run("two places move to one entry", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@2")}},
			tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@2", name: "X", ver: "2"})
		g1 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@3")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@3")}},
			tn{key: "X@3", name: "X", ver: "3"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("A 1", "B 1", "X 1 c", "X 2 c"), scanOfVersions("A 1", "B 1", "X 3 c"), nil)
		if f != nil {
			t.Fatalf("%s: %s", f.reason, f.detail)
		}
		if len(sc.ChainCarried) != 1 || sc.ChainCarried[0].Positions != 2 || sc.ChainCarried[0].To != "3" {
			t.Errorf("carried = %+v", sc.ChainCarried)
		}
	})
	t.Run("a carried vulnerability that is KEV-listed is recorded as such", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1.0")}, tn{key: "A@1.0", name: "A", ver: "1.0"})
		g1 := tgraph([]depEdge{te("A", "A@1.5")}, tn{key: "A@1.5", name: "A", ver: "1.5"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("A 1.0 c"), scanOfVersions("A 1.5 c"), func(id string) bool { return id == "c" })
		if f != nil || len(sc.ChainCarried) != 1 || !sc.ChainCarried[0].KEV {
			t.Errorf("failure = %+v, carried = %+v", f, sc.ChainCarried)
		}
	})
}

func TestChainPositionCheckRefuses(t *testing.T) {
	t.Run("a new package with a vulnerability", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("T", "T@1")}, tn{key: "T@1", name: "T", ver: "1"})
		g1 := tgraph([]depEdge{te("T", "T@2")}, tn{key: "T@2", name: "T", ver: "2", deps: []depEdge{te("N", "N@1")}}, tn{key: "N@1", name: "N", ver: "1"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("T 1"), scanOfVersions("T 2", "N 1 d"), nil)
		wantPositionRefusal(t, sc, f, "no_position", "N")
		if len(sc.ChainCarried) != 0 || len(sc.ChainNewTriples) != 1 {
			t.Errorf("carried = %+v, new = %+v", sc.ChainCarried, sc.ChainNewTriples)
		}
	})
	t.Run("a vulnerable package gains a dependent while another stops using it", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1"), te("C", "C@1")},
			tn{key: "A@1", name: "A", ver: "1"}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@1")}},
			tn{key: "C@1", name: "C", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "X@1", name: "X", ver: "1"})
		g1 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1"), te("C", "C@2")},
			tn{key: "A@1", name: "A", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@1")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@1")}},
			tn{key: "C@2", name: "C", ver: "2"}, tn{key: "X@1", name: "X", ver: "1"})
		scan := scanOfVersions("A 1", "B 1", "C 1", "X 1 c")
		// The counts alone do not see it: the edges into X@1 are two before and two after.
		strict := &SourceCheck{}
		if f := evaluateChainScan(strict, scan, scanOfVersions("A 1", "B 1", "C 2", "X 1 c"), g0, g1, "npm", plainKey, noKEV); f != nil {
			t.Fatalf("the counts alone refuse it: %s", f.detail)
		}
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scan, scanOfVersions("A 1", "B 1", "C 2", "X 1 c"), nil)
		wantPositionRefusal(t, sc, f, "no_position", "X")
	})
	t.Run("an existing triple that is new to its place", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@2")}},
			tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@2", name: "X", ver: "2"})
		g1 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@2")},
			tn{key: "A@1", name: "A", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@2")}}, tn{key: "B@2", name: "B", ver: "2"},
			tn{key: "X@2", name: "X", ver: "2"})
		before, after := scanOfVersions("A 1", "B 1", "X 1", "X 2 c"), scanOfVersions("A 1", "B 2", "X 2 c")
		strict := &SourceCheck{}
		if f := evaluateChainScan(strict, before, after, g0, g1, "npm", plainKey, noKEV); f != nil {
			t.Fatalf("the comparison without positions refuses it: %s", f.detail)
		}
		sc, f := positionCheck(t, ManagerNpm, g0, g1, before, after, nil)
		wantPositionRefusal(t, sc, f, "new_vuln", "X")
		if len(sc.ChainNewTriples) != 0 {
			t.Errorf("there is no new triple: %+v", sc.ChainNewTriples)
		}
	})
	t.Run("a new version brings a vulnerability the old one lacked", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("X", "X@1")}, tn{key: "X@1", name: "X", ver: "1"})
		g1 := tgraph([]depEdge{te("X", "X@2")}, tn{key: "X@2", name: "X", ver: "2"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("X 1 c"), scanOfVersions("X 2 c,e"), nil)
		wantPositionRefusal(t, sc, f, "new_vuln", "X")
		if sc.ChainPositionRefusals[0].VulnID != "e" || len(sc.ChainCarried) != 0 {
			t.Errorf("refusals = %+v, carried = %+v", sc.ChainPositionRefusals, sc.ChainCarried)
		}
	})
	t.Run("a split that a deletion elsewhere offsets", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1"), te("C", "C@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@1")}},
			tn{key: "C@1", name: "C", ver: "1", deps: []depEdge{te("X", "X@4")}}, tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@4", name: "X", ver: "4"})
		g1 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1"), te("C", "C@2")},
			tn{key: "A@1", name: "A", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@2")}}, tn{key: "B@1", name: "B", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@3")}},
			tn{key: "C@2", name: "C", ver: "2"}, tn{key: "X@2", name: "X", ver: "2"}, tn{key: "X@3", name: "X", ver: "3"})
		before, after := scanOfVersions("A 1", "B 1", "C 1", "X 1 c", "X 4 c"), scanOfVersions("A 1", "B 1", "C 2", "X 2 c", "X 3 c")
		sc, f := positionCheck(t, ManagerNpm, g0, g1, before, after, nil)
		wantPositionRefusal(t, sc, f, "split", "X")
		if len(sc.ChainCarried) != 0 {
			t.Errorf("carried = %+v: nothing is carried when an entry was split", sc.ChainCarried)
		}
	})
	t.Run("a split below a peer requirement the walk does not follow", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("T", "T@1"), te("C", "C@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@1")}},
			tn{key: "T@1", name: "T", ver: "1", deps: []depEdge{te("B", "B@1", asPeer())}},
			tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@1")}},
			tn{key: "C@1", name: "C", ver: "1", deps: []depEdge{te("X", "X@4")}},
			tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@4", name: "X", ver: "4"})
		g1 := tgraph([]depEdge{te("A", "A@2"), te("T", "T@1"), te("C", "C@2")},
			tn{key: "A@2", name: "A", ver: "2", deps: []depEdge{te("X", "X@2")}},
			tn{key: "T@1", name: "T", ver: "1", deps: []depEdge{te("B", "B@1", asPeer())}},
			tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@1")}},
			tn{key: "C@2", name: "C", ver: "2"},
			tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@2", name: "X", ver: "2"})
		before, after := scanOfVersions("A 1", "T 1", "B 1", "C 1", "X 1 c", "X 4 c"), scanOfVersions("A 2", "T 1", "B 1", "C 2", "X 1 c", "X 2 c")
		sc, f := positionCheck(t, ManagerNpm, g0, g1, before, after, nil)
		wantPositionRefusal(t, sc, f, "split", "X")
		if len(sc.ChainPositionRefusals) != 1 || sc.ChainPositionRefusals[0].Version != "1" {
			t.Errorf("refusals = %+v: the split is X@1 into X@1 and X@2", sc.ChainPositionRefusals)
		}
	})
	t.Run("the paths of old entries merge into one requirement", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("P", "P@1")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("P", "P@2")}},
			tn{key: "P@1", name: "P", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "P@2", name: "P", ver: "2", deps: []depEdge{te("X", "X@2")}},
			tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@2", name: "X", ver: "2"})
		g1 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", rev: "r2", deps: []depEdge{te("P", "P@3")}}, tn{key: "B@1", name: "B", ver: "1", rev: "r2", deps: []depEdge{te("P", "P@3")}},
			tn{key: "P@3", name: "P", ver: "3", deps: []depEdge{te("X", "X@3")}}, tn{key: "X@3", name: "X", ver: "3"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("A 1", "B 1", "P 1", "P 2", "X 1", "X 2 c"), scanOfVersions("A 1", "B 1", "P 3", "X 3 c"), nil)
		wantPositionRefusal(t, sc, f, "merged", "X")
	})
	t.Run("uv: the marker of a middle requirement changes and a vulnerable version follows", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("P", "P@1")}, tn{key: "P@1", name: "P", ver: "1", deps: []depEdge{te("X", "X@1", withMarker("sys_platform == 'linux'"))}}, tn{key: "X@1", name: "X", ver: "1"})
		g1 := tgraph([]depEdge{te("P", "P@1")}, tn{key: "P@1", name: "P", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@2", withMarker("sys_platform == 'win32'"))}}, tn{key: "X@2", name: "X", ver: "2"})
		sc, f := positionCheck(t, ManagerUv, g0, g1, scanOfVersions("P 1", "X 1"), scanOfVersions("P 1", "X 2 c"), nil)
		wantPositionRefusal(t, sc, f, "no_position", "X")
	})
	t.Run("a peer requirement becomes a regular one", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("P", "P@1")}, tn{key: "P@1", name: "P", ver: "1", deps: []depEdge{te("X", "X@1", asPeer())}}, tn{key: "X@1", name: "X", ver: "1"})
		g1 := tgraph([]depEdge{te("P", "P@1")}, tn{key: "P@1", name: "P", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@2")}}, tn{key: "X@2", name: "X", ver: "2"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("P 1", "X 1"), scanOfVersions("P 1", "X 2 c"), nil)
		wantPositionRefusal(t, sc, f, "no_position", "X")
	})
	t.Run("an entry that one place stood for becomes two peer-context entries of a package", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@1")}}, tn{key: "X@1", name: "X", ver: "1"})
		g1 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
			tn{key: "A@1", name: "A", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@2(p@1)")}}, tn{key: "B@1", name: "B", ver: "1", rev: "r2", deps: []depEdge{te("X", "X@2(p@2)")}},
			tn{key: "X@2(p@1)", name: "X", ver: "2"}, tn{key: "X@2(p@2)", name: "X", ver: "2"})
		sc, f := positionCheck(t, ManagerPnpm, g0, g1, scanOfVersions("A 1", "B 1", "X 1 c"), scanOfVersions("A 1", "B 1", "X 2 c"), nil)
		wantPositionRefusal(t, sc, f, "split", "X")
	})
	t.Run("a new triple that is KEV-listed is refused as such", func(t *testing.T) {
		g0 := tgraph([]depEdge{te("T", "T@1")}, tn{key: "T@1", name: "T", ver: "1"})
		g1 := tgraph([]depEdge{te("T", "T@2")}, tn{key: "T@2", name: "T", ver: "2", deps: []depEdge{te("N", "N@1")}}, tn{key: "N@1", name: "N", ver: "1"})
		sc, f := positionCheck(t, ManagerNpm, g0, g1, scanOfVersions("T 1"), scanOfVersions("T 2", "N 1 d"), func(id string) bool { return id == "d" })
		if f == nil || f.reason != ReasonSourceIntroducedKEV || len(sc.ChainPositionRefusals) == 0 {
			t.Fatalf("failure = %+v", f)
		}
	})
}

func TestChainDiagnosticsKeepTheOrdinaryFailure(t *testing.T) {
	// The target is still detected after the update, which the ordinary comparison
	// refuses; the chain's comparison is made for its record and changes nothing
	// of the failure.
	lock0 := npmLock(map[string]string{"a": "^1"}, map[string]npmEntry{"node_modules/a": {ver: "1.0.0"}, "node_modules/t": {ver: "0.5.0"}})
	lock1 := npmLock(map[string]string{"a": "^1"}, map[string]npmEntry{"node_modules/a": {ver: "1.5.0"}, "node_modules/t": {ver: "0.5.0"}})
	g0, g1 := graphOf(t, lock0), graphOf(t, lock1)
	before := fsReport("npm", [][2]string{{"a", "1.0.0"}, {"t", "0.5.0"}}, [][3]string{{"a", "1.0.0", "CVE-A"}, {"t", "0.5.0", "CVE-T"}})
	after := fsReport("npm", [][2]string{{"a", "1.5.0"}, {"t", "0.5.0"}}, [][3]string{{"a", "1.5.0", "CVE-A"}, {"t", "0.5.0", "CVE-T"}})
	run := func(chain bool) (*SourceCheck, *updateFailure) {
		it := &LanguageItem{Manager: ManagerNpm, Packages: []LanguagePackage{{
			Name: "t", Installed: "0.5.0", SelectionLowerBound: "1.2.6", Action: ActionUpdate, CVEs: []CVERef{{VulnID: "CVE-T", FixedVers: []string{"1.2.6"}}},
		}}}
		set, _ := newUpdateSet(it)
		fs := &fakeFS{fn: func(n int, files map[string][]byte) (scanner.FSScan, error) {
			if n == 0 {
				return before, nil
			}
			return after, nil
		}}
		r := &updateRun{
			u: &LangUpdater{cfg: LangUpdateConfig{Scanner: fs, Prepared: fsConds}}, it: it, set: set, full: set,
			afterVersions: map[string][]string{"t": {"0.5.0"}}, src: &sourceFiles{lockName: "package-lock.json", lock: lock0},
		}
		if chain {
			r.chain = &chainScope{}
			r.chainCmp = [2]*depGraph{g0, g1}
		}
		f := r.sourceCheck(bg, map[string][]byte{"package-lock.json": lock0}, map[string][]byte{"package-lock.json": lock1})
		return r.check, f
	}
	plainSC, plain := run(false)
	chainSC, got := run(true)
	if plain == nil || got == nil || got.reason != plain.reason || got.detail != plain.detail || got.category != plain.category {
		t.Fatalf("failure with diagnostics = %+v, without = %+v", got, plain)
	}
	if got.reason != ReasonSourceTargetStillDetected || chainSC.Passed || plainSC.Passed {
		t.Errorf("reason = %s, passed = %v / %v", got.reason, chainSC.Passed, plainSC.Passed)
	}
	if chainSC.Basis != "package_version_vuln_edges_positions" || len(chainSC.ChainCarried) != 1 || chainSC.ChainCarried[0].Package != "a" {
		t.Errorf("the chain fields are not filled: basis %q, carried %+v", chainSC.Basis, chainSC.ChainCarried)
	}
	if plainSC.Basis != "" || len(plainSC.ChainCarried) != 0 {
		t.Errorf("the ordinary run has chain fields: %+v", plainSC)
	}
}

func TestChainPositionCheckSeesAChangedRequirementOfAnEntryWithTheSameRecord(t *testing.T) {
	imps := []genImp{{"a", "1.0.0", "1.0.0"}, {"b", "1.0.0", "1.0.0"}}
	before := genPnpmLock(imps, []genPkg{
		{"a", "1.0.0", map[string]string{"p": "1.0.0"}},
		{"b", "1.0.0", map[string]string{"p": "2.0.0"}},
		{"p", "1.0.0", map[string]string{"x": "1.0.0"}},
		{"p", "2.0.0", map[string]string{"x": "2.0.0", "y": "1.0.0"}},
		{"x", "1.0.0", nil}, {"x", "2.0.0", nil},
		{"y", "1.0.0", nil},
	})
	after := genPnpmLock(imps, []genPkg{
		{"a", "1.0.0", map[string]string{"p": "2.0.0"}},
		{"b", "1.0.0", map[string]string{"p": "2.0.0"}},
		{"p", "2.0.0", map[string]string{"x": "2.0.0", "y": "2.0.0"}},
		{"x", "2.0.0", nil},
		{"y", "2.0.0", nil},
	})
	g0, err := buildGraph(bg, ManagerPnpm, []byte(before))
	if err != nil {
		t.Fatal(err)
	}
	g1, err := buildGraph(bg, ManagerPnpm, []byte(after))
	if err != nil {
		t.Fatal(err)
	}
	p0, p1 := g0.nodes["p@2.0.0"], g1.nodes["p@2.0.0"]
	if p0 == nil || p1 == nil || p0.attrs != p1.attrs {
		t.Fatalf("the entries should have the same record: %+v %+v", p0, p1)
	}
	if sameRecordAndEdges(ManagerPnpm, g0, g1, "p@2.0.0") {
		t.Fatal("the entry requires another version of y after, so it is not the same")
	}
	sc, f := positionCheck(t, ManagerPnpm, g0, g1,
		scanOfVersions("x 1.0.0", "x 2.0.0 c", "y 1.0.0"), scanOfVersions("x 2.0.0 c", "y 2.0.0"), nil)
	wantPositionRefusal(t, sc, f, posMerged, "x")
}

func TestChainPositionCheckAggregatesKEVOverEveryMissingVulnerability(t *testing.T) {
	g0 := tgraph([]depEdge{te("A", "A@1"), te("B", "B@1")},
		tn{key: "A@1", name: "A", ver: "1", deps: []depEdge{te("X", "X@1")}},
		tn{key: "B@1", name: "B", ver: "1", deps: []depEdge{te("X", "X@2")}},
		tn{key: "X@1", name: "X", ver: "1"}, tn{key: "X@2", name: "X", ver: "2"})
	g1 := tgraph([]depEdge{te("A", "A@1")},
		tn{key: "A@1", name: "A", ver: "1", rev: "n", deps: []depEdge{te("X", "X@2")}},
		tn{key: "X@2", name: "X", ver: "2"})
	kev := func(v string) bool { return v == "z" }
	sc, f := positionCheck(t, ManagerNpm, g0, g1,
		scanOfVersions("X 1", "X 2 c,z"), scanOfVersions("X 2 c,z"), kev)
	if f == nil || f.reason != ReasonSourceIntroducedKEV {
		t.Fatalf("failure = %+v, want the KEV reason; check = %+v", f, sc)
	}
}
