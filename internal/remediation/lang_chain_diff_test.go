package remediation

import (
	"fmt"
	"strings"
	"testing"
)

// chainTestScope makes the scope of a chain update by hand: anc are the keys
// of the ancestors in g0 and targets the names of the packages being updated.
func chainTestScope(t *testing.T, g0 *depGraph, anc []string, targets ...string) *chainScope {
	t.Helper()
	g0.link()
	s := &chainScope{
		Names: map[string]bool{}, Be: map[string]bool{}, Anc: map[string]bool{}, RAnc: map[string]bool{},
		RTgt: map[string]bool{}, RNest: map[string]bool{}, Targets: map[string]bool{}, Scheme: schemeSemver,
	}
	for _, k := range anc {
		n := g0.nodes[k]
		if n == nil {
			t.Fatalf("no entry %s", k)
		}
		s.Anc[k], s.RAnc[k], s.Names[n.name] = true, true, true
	}
	for _, n := range targets {
		s.Targets[n] = true
	}
	for k, n := range g0.nodes {
		if s.Targets[n.name] {
			s.RTgt[k] = true
		}
	}
	for _, e := range g0.roots {
		if s.Anc[e.key] {
			s.Tops = append(s.Tops, chainTop{Name: e.name, Key: e.key, Group: "dependencies"})
			s.Names[e.name] = true
		}
	}
	for k := range g0.nodes {
		for _, a := range npmAncestors(k) {
			if (s.RAnc[a] || s.RTgt[a]) && !s.RAnc[k] && !s.RTgt[k] {
				s.RNest[k] = true
				break
			}
		}
	}
	return s
}

// chainDiffNpm compares two package-lock.json files as a chain update would.
func chainDiffNpm(t *testing.T, before, after []byte, anc []string, targets ...string) (DependencyDiff, Reason, string) {
	t.Helper()
	gb, err := npmGraph(bg, before)
	if err != nil {
		t.Fatal(err)
	}
	ga, err := npmGraph(bg, after)
	if err != nil {
		t.Fatal(err)
	}
	return diffGraphsChain(bg, gb, ga, chainTestScope(t, gb, anc, targets...))
}

func lockWith(root map[string]string, base map[string]npmEntry, mut func(map[string]npmEntry)) []byte {
	m := map[string]npmEntry{}
	for k, v := range base {
		m[k] = v
	}
	if mut != nil {
		mut(m)
	}
	return npmLock(root, m)
}

// The chain update of these tests: top requires t at exactly 0.5.0, which is
// below the fixed version, and an update of top within its range takes t to
// 1.2.8.
var chainBase = map[string]npmEntry{
	"node_modules/top": {ver: "1.0.0", deps: map[string]string{"t": "0.5.0"}},
	"node_modules/t":   {ver: "0.5.0"},
	"node_modules/e":   {ver: "1.0.0"},
}

var chainRoot = map[string]string{"top": "^1.0.0", "e": "^1.0.0"}

func chainFixed(m map[string]npmEntry) {
	m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^1.2.6"}}
	m["node_modules/t"] = npmEntry{ver: "1.2.8"}
}

func TestDiffGraphsChainAccepted(t *testing.T) {
	before := npmLock(chainRoot, chainBase)
	t.Run("the top moves and takes the target with it", func(t *testing.T) {
		after := lockWith(chainRoot, chainBase, chainFixed)
		diff, reason, detail := chainDiffNpm(t, before, after, []string{"node_modules/top"}, "t")
		if reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
		if strings.Join(diff.Changed, ",") != "node_modules/t,node_modules/top" {
			t.Errorf("diff = %+v", diff)
		}
	})
	t.Run("the new version of the top drops a dependency", func(t *testing.T) {
		root := map[string]string{"top": "^1.0.0", "q": "^1.0.0"}
		base := map[string]npmEntry{
			"node_modules/top": {ver: "1.0.0", deps: map[string]string{"dep": "^1.0.0"}},
			"node_modules/dep": {ver: "1.0.0", deps: map[string]string{"t": "0.5.0"}},
			"node_modules/q":   {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
			"node_modules/t":   {ver: "0.5.0"},
		}
		b := npmLock(root, base)
		a := lockWith(root, base, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0"}
			delete(m, "node_modules/dep")
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
		})
		if _, reason, detail := chainDiffNpm(t, b, a, []string{"node_modules/dep", "node_modules/top"}, "t"); reason != "" {
			t.Fatalf("a path that ended by removal is not an unmatched one: %s: %s", reason, detail)
		}
	})
}

func TestDiffGraphsChainRejects(t *testing.T) {
	before := npmLock(chainRoot, chainBase)
	anc := []string{"node_modules/top"}

	t.Run("another direct dependency changes at the same path", func(t *testing.T) {
		// The key of e is the same; its version and files are not.
		after := lockWith(chainRoot, chainBase, func(m map[string]npmEntry) {
			chainFixed(m)
			m["node_modules/e"] = npmEntry{ver: "1.0.1"}
		})
		_, reason, detail := chainDiffNpm(t, before, after, anc, "t")
		if reason != ReasonUnexplainedDiff || !strings.Contains(detail, "e") {
			t.Fatalf("reason = %q (%s)", reason, detail)
		}
	})
	t.Run("another direct dependency changes only in its files", func(t *testing.T) {
		after := lockWith(chainRoot, chainBase, func(m map[string]npmEntry) {
			chainFixed(m)
			m["node_modules/e"] = npmEntry{ver: "1.0.0", url: "https://registry.npmjs.org/e/-/e-1.0.0-other.tgz"}
		})
		if _, reason, _ := chainDiffNpm(t, before, after, anc, "t"); reason != ReasonUnexplainedDiff {
			t.Fatalf("reason = %q", reason)
		}
	})
	t.Run("a requirement of the project other than the tops changes", func(t *testing.T) {
		after := lockWith(map[string]string{"top": "^1.0.0", "e": "^2.0.0"}, chainBase, chainFixed)
		if _, reason, _ := chainDiffNpm(t, before, after, anc, "t"); reason != ReasonUnexplainedDiff {
			t.Fatalf("reason = %q", reason)
		}
	})
	t.Run("a shared position is replaced outside what was taken out", func(t *testing.T) {
		root := map[string]string{"top": "^1.0.0", "e": "^1.0.0"}
		base := map[string]npmEntry{
			"node_modules/top": {ver: "1.0.0", deps: map[string]string{"t": "0.5.0", "y": "^1.0.0"}},
			"node_modules/t":   {ver: "0.5.0"},
			"node_modules/e":   {ver: "1.0.0", deps: map[string]string{"y": "^1.0.0"}},
			"node_modules/y":   {ver: "1.0.0"},
		}
		b := npmLock(root, base)
		a := lockWith(root, base, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^1.2.6", "y": "^1.1.0"}}
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
			m["node_modules/y"] = npmEntry{ver: "1.1.0"} // e shares it
		})
		_, reason, detail := chainDiffNpm(t, b, a, anc, "t")
		if reason != ReasonUnexplainedDiff || !strings.Contains(detail, "node_modules/y") {
			t.Fatalf("reason = %q (%s)", reason, detail)
		}
	})
	t.Run("an entry of a chain name that is not part of the chain changes", func(t *testing.T) {
		root := map[string]string{"top": "^1.0.0", "e": "^1.0.0"}
		base := map[string]npmEntry{
			"node_modules/top":                {ver: "1.0.0", deps: map[string]string{"t": "0.5.0"}},
			"node_modules/t":                  {ver: "0.5.0"},
			"node_modules/e":                  {ver: "1.0.0", deps: map[string]string{"top": "^2.0.0"}},
			"node_modules/e/node_modules/top": {ver: "2.0.0"},
		}
		b := npmLock(root, base)
		a := lockWith(root, base, func(m map[string]npmEntry) {
			chainFixed(m)
			m["node_modules/e/node_modules/top"] = npmEntry{ver: "2.0.1"}
		})
		if _, reason, _ := chainDiffNpm(t, b, a, anc, "t"); reason != ReasonUnexplainedDiff {
			t.Fatalf("reason = %q", reason)
		}
	})
	t.Run("an entry is added that no top or updated package requires", func(t *testing.T) {
		after := lockWith(chainRoot, chainBase, func(m map[string]npmEntry) {
			chainFixed(m)
			m["node_modules/stray"] = npmEntry{ver: "1.0.0"}
		})
		if _, reason, _ := chainDiffNpm(t, before, after, anc, "t"); reason != ReasonUnexplainedDiff {
			t.Fatalf("reason = %q", reason)
		}
	})
	t.Run("the target is no longer needed", func(t *testing.T) {
		after := lockWith(chainRoot, chainBase, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0"}
			delete(m, "node_modules/t")
		})
		if _, reason, _ := chainDiffNpm(t, before, after, anc, "t"); reason != ReasonTargetRemoved {
			t.Fatalf("reason = %q", reason)
		}
	})
}

func TestDiffGraphsChainDowngrades(t *testing.T) {
	t.Run("two versions of an ancestor and one path goes down", func(t *testing.T) {
		root := map[string]string{"top": "^1.0.0"}
		base := map[string]npmEntry{
			"node_modules/top":              {ver: "1.0.0", deps: map[string]string{"X": "1.0.0", "w": "^1.0.0"}},
			"node_modules/X":                {ver: "1.0.0", deps: map[string]string{"t": "0.5.0"}},
			"node_modules/w":                {ver: "1.0.0", deps: map[string]string{"X": "9.0.0"}},
			"node_modules/w/node_modules/X": {ver: "9.0.0", deps: map[string]string{"t": "0.5.0"}},
			"node_modules/t":                {ver: "0.5.0"},
		}
		b := npmLock(root, base)
		anc := []string{"node_modules/top", "node_modules/X", "node_modules/w", "node_modules/w/node_modules/X"}
		a := lockWith(root, base, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"X": "^1.0.0", "w": "^1.0.0"}}
			m["node_modules/X"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^1.2.6"}}
			m["node_modules/w/node_modules/X"] = npmEntry{ver: "2.0.0", deps: map[string]string{"t": "^1.2.6"}}
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
		})
		_, reason, detail := chainDiffNpm(t, b, a, anc, "t")
		if reason != ReasonChainDowngrade || !strings.Contains(detail, "9.0.0") {
			t.Fatalf("reason = %q (%s)", reason, detail)
		}
		// With the path kept at its version, the same change is accepted.
		ok := lockWith(root, base, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"X": "^1.0.0", "w": "^1.0.0"}}
			m["node_modules/X"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^1.2.6"}}
			m["node_modules/w/node_modules/X"] = npmEntry{ver: "9.0.1", deps: map[string]string{"t": "^1.2.6"}}
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
		})
		if _, reason, detail := chainDiffNpm(t, b, ok, anc, "t"); reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
	})
	t.Run("a path through an entry the update does not change", func(t *testing.T) {
		// top holds t at 0.5.0; b is not an ancestor and has its own t at 9.0.0,
		// which a fixed version of 2 allows. After the update b reaches t at
		// 2.1.0 through the hoisted entry: b's own copy is gone and the path
		// went down, though b itself is unchanged.
		root := map[string]string{"top": "^1.0.0", "b": "^1.0.0"}
		base := map[string]npmEntry{
			"node_modules/top":              {ver: "1.0.0", deps: map[string]string{"t": "1.0.0"}},
			"node_modules/t":                {ver: "1.0.0"},
			"node_modules/b":                {ver: "1.0.0", deps: map[string]string{"t": "*"}},
			"node_modules/b/node_modules/t": {ver: "9.0.0"},
		}
		b := npmLock(root, base)
		a := lockWith(root, base, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^2.0.0"}}
			m["node_modules/t"] = npmEntry{ver: "2.1.0"}
			delete(m, "node_modules/b/node_modules/t")
		})
		_, reason, detail := chainDiffNpm(t, b, a, []string{"node_modules/top"}, "t")
		if reason != ReasonChainDowngrade || !strings.Contains(detail, "node_modules/b") {
			t.Fatalf("reason = %q (%s)", reason, detail)
		}
	})
	t.Run("a parent has two requirements for a name after normalization", func(t *testing.T) {
		before := npmLock(chainRoot, chainBase)
		after := lockWith(chainRoot, chainBase, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^1.2.6"}, opt: map[string]string{"t": "^1.3.0"}}
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
		})
		_, reason, detail := chainDiffNpm(t, before, after, []string{"node_modules/top"}, "t")
		if reason != ReasonChainDowngrade || !strings.Contains(detail, "more than one requirement") {
			t.Fatalf("reason = %q (%s)", reason, detail)
		}
		// The same range in the dependencies and the optional dependencies is
		// one requirement.
		same := lockWith(chainRoot, chainBase, func(m map[string]npmEntry) {
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: map[string]string{"t": "^1.2.6"}, opt: map[string]string{"t": "^1.2.6"}}
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
		})
		if _, reason, detail := chainDiffNpm(t, before, same, []string{"node_modules/top"}, "t"); reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
	})
	t.Run("the marker of a matched requirement differs", func(t *testing.T) {
		gb, _ := npmGraph(bg, npmLock(chainRoot, chainBase))
		ga, _ := npmGraph(bg, lockWith(chainRoot, chainBase, chainFixed))
		ga.nodes["node_modules/top"].deps[0].marker = "sys_platform == 'linux'"
		reason, detail := mapChainPaths(bg, gb, ga, chainTestScope(t, gb, []string{"node_modules/top"}, "t"))
		if reason != ReasonChainDowngrade || !strings.Contains(detail, "marker") {
			t.Fatalf("reason = %q (%s)", reason, detail)
		}
	})
}

func TestDiffGraphsChainMoveLimit(t *testing.T) {
	root := map[string]string{"top": "^1.0.0"}
	base := map[string]npmEntry{
		"node_modules/top": {ver: "1.0.0", deps: map[string]string{"t": "0.5.0"}},
		"node_modules/t":   {ver: "0.5.0"},
	}
	before := npmLock(root, base)
	// The top changes, and the new version brings n new packages.
	after := func(n int) []byte {
		return lockWith(root, base, func(m map[string]npmEntry) {
			deps := map[string]string{"t": "^1.2.6"}
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("d%03d", i)
				deps[name] = "^1.0.0"
				m["node_modules/"+name] = npmEntry{ver: "1.0.0"}
			}
			m["node_modules/top"] = npmEntry{ver: "1.1.0", deps: deps}
			m["node_modules/t"] = npmEntry{ver: "1.2.8"}
		})
	}
	if _, reason, detail := chainDiffNpm(t, before, after(maxChainMoves-1), []string{"node_modules/top"}, "t"); reason != "" {
		t.Fatalf("%d entries moved: %s: %s", maxChainMoves, reason, detail)
	}
	if _, reason, _ := chainDiffNpm(t, before, after(maxChainMoves), []string{"node_modules/top"}, "t"); reason != ReasonChainMoveLimit {
		t.Fatalf("%d entries moved: reason = %q", maxChainMoves+1, reason)
	}
}

func TestDiffGraphsOrdinaryUpdateUnchanged(t *testing.T) {
	// An ordinary update's rules are not the chain's: the same files that a
	// chain update accepts are refused when the top is not among the updated
	// packages.
	before := npmLock(chainRoot, chainBase)
	after := lockWith(chainRoot, chainBase, chainFixed)
	if _, reason, _ := diffNpm(t, before, after, "t"); reason != ReasonUnexplainedDiff {
		t.Fatalf("reason = %q: an ancestor of an updated package may not change in an ordinary update", reason)
	}
}
