package remediation

import (
	"sort"
	"strings"
	"testing"
)

// tn is an entry of a graph made by hand: its key, package and version, and its
// requirements. Two entries with the same key and the same rev are the same
// record.
type tn struct {
	key, name, ver, rev string
	peerRanges          map[string]string
	deps                []depEdge
}

// te is a requirement for name that points to the entry with the key.
func te(name, key string, opts ...func(*depEdge)) depEdge {
	e := depEdge{name: name, key: key}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func withMarker(m string) func(*depEdge) { return func(e *depEdge) { e.marker = m } }
func asPeer() func(*depEdge)             { return func(e *depEdge) { e.lockPeer = true } }

// tgraph makes a linked graph from entries and the project's requirements.
func tgraph(roots []depEdge, nodes ...tn) *depGraph {
	g := &depGraph{nodes: map[string]*depNode{}, roots: roots}
	for _, n := range nodes {
		g.nodes[n.key] = &depNode{name: n.name, version: n.ver, attrs: n.key + "|" + n.rev, deps: n.deps, peerRanges: n.peerRanges}
	}
	g.link()
	return g
}

func setKeys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestEdgeKind(t *testing.T) {
	parent := &depNode{peerRanges: map[string]string{"p": "^1"}}
	if edgeKind(ManagerNpm, parent, depEdge{name: "p"}) != kindRegular || edgeKind(ManagerNpm, parent, depEdge{name: "p", lockPeer: true}) != kindPeer {
		t.Error("npm: the kind is the one the lockfile's peerDependencies give the requirement")
	}
	if edgeKind(ManagerNpm, nil, depEdge{name: "p", lockPeer: true}) != kindPeer {
		t.Error("npm: a peer requirement of the project is a peer")
	}
	if edgeKind(ManagerPnpm, parent, depEdge{name: "p"}) != kindPeer || edgeKind(ManagerPnpm, parent, depEdge{name: "q"}) != kindRegular || edgeKind(ManagerPnpm, nil, depEdge{name: "p"}) != kindRegular {
		t.Error("pnpm: the kind is the package's peer ranges")
	}
	if edgeKind(ManagerUv, parent, depEdge{name: "p", lockPeer: true}) != kindRegular {
		t.Error("uv has no peer requirements")
	}
}

func TestNpmGraphMarksTheRequirementsOfTheProjectAndOfEntriesThatCameFromPeerDependencies(t *testing.T) {
	lock := []byte(`{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"peerDependencies":{"p":"^1"}},
"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-a1","dependencies":{"q":"^1"},"peerDependencies":{"p":"^1"}},
"node_modules/p":{"version":"1.0.0","resolved":"https://registry.npmjs.org/p/-/p-1.0.0.tgz","integrity":"sha512-p1"},
"node_modules/q":{"version":"1.0.0","resolved":"https://registry.npmjs.org/q/-/q-1.0.0.tgz","integrity":"sha512-q1"}}}`)
	g, err := npmGraph(bg, lock)
	if err != nil {
		t.Fatal(err)
	}
	peers := map[string]bool{}
	for _, e := range g.roots {
		peers["root:"+e.name] = e.lockPeer
	}
	for _, e := range g.nodes["node_modules/a"].deps {
		peers["a:"+e.name] = e.lockPeer
	}
	want := map[string]bool{"root:a": false, "root:p": true, "a:q": false, "a:p": true}
	for k, v := range want {
		if peers[k] != v {
			t.Errorf("%s: peer = %v, want %v", k, peers[k], v)
		}
	}
}

func TestCorrespondenceFollowsPlacesParentByParent(t *testing.T) {
	// npm paths: root -> a -> (a/node_modules/x) before and after, with x at
	// another version.
	before := tgraph([]depEdge{te("a", "node_modules/a")},
		tn{key: "node_modules/a", name: "a", ver: "1", deps: []depEdge{te("x", "node_modules/a/node_modules/x")}},
		tn{key: "node_modules/a/node_modules/x", name: "x", ver: "1"})
	after := tgraph([]depEdge{te("a", "node_modules/a")},
		tn{key: "node_modules/a", name: "a", ver: "1", deps: []depEdge{te("x", "node_modules/a/node_modules/x")}},
		tn{key: "node_modules/a/node_modules/x", name: "x", ver: "2"})
	c, err := buildCorrespondence(bg, before, after, ManagerNpm)
	if err != nil {
		t.Fatal(err)
	}
	if got := setKeys(c.old[posKey{"node_modules/a", "x", ""}]); got != "node_modules/a/node_modules/x" {
		t.Errorf("old = %v", c.old)
	}
	if got := setKeys(c.new["node_modules/a/node_modules/x"]); got != "node_modules/a/node_modules/x" {
		t.Errorf("new = %v", c.new)
	}
	if got := setKeys(c.old[posKey{"", "a", ""}]); got != "node_modules/a" {
		t.Errorf("the project's requirement is a place too: %v", c.old)
	}
}

func TestCorrespondenceMergeAndSplit(t *testing.T) {
	merge0 := tgraph([]depEdge{te("a", "a@1"), te("b", "b@1")},
		tn{key: "a@1", name: "a", ver: "1", deps: []depEdge{te("p", "p@1")}}, tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("p", "p@2")}},
		tn{key: "p@1", name: "p", ver: "1", deps: []depEdge{te("x", "x@1")}}, tn{key: "p@2", name: "p", ver: "2", deps: []depEdge{te("x", "x@2")}},
		tn{key: "x@1", name: "x", ver: "1"}, tn{key: "x@2", name: "x", ver: "2"})
	merge1 := tgraph([]depEdge{te("a", "a@1"), te("b", "b@1")},
		tn{key: "a@1", name: "a", ver: "1", deps: []depEdge{te("p", "p@3")}}, tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("p", "p@3")}},
		tn{key: "p@3", name: "p", ver: "3", deps: []depEdge{te("x", "x@3")}}, tn{key: "x@3", name: "x", ver: "3"})
	c, err := buildCorrespondence(bg, merge0, merge1, ManagerNpm)
	if err != nil {
		t.Fatal(err)
	}
	if got := setKeys(c.old[posKey{"p@3", "x", ""}]); got != "x@1,x@2" {
		t.Errorf("merge: old = %q: two places of the original stand for one", got)
	}
	// One entry of the original leads to two entries of the updated one.
	split0 := tgraph([]depEdge{te("a", "a@1"), te("b", "b@1")},
		tn{key: "a@1", name: "a", ver: "1", deps: []depEdge{te("x", "x@1")}}, tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("x", "x@1")}},
		tn{key: "x@1", name: "x", ver: "1"})
	split1 := tgraph([]depEdge{te("a", "a@1"), te("b", "b@1")},
		tn{key: "a@1", name: "a", ver: "1", deps: []depEdge{te("x", "x@2")}}, tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("x", "x@3")}},
		tn{key: "x@2", name: "x", ver: "2"}, tn{key: "x@3", name: "x", ver: "3"})
	c, err = buildCorrespondence(bg, split0, split1, ManagerNpm)
	if err != nil {
		t.Fatal(err)
	}
	if got := setKeys(c.new["x@1"]); got != "x@2,x@3" {
		t.Errorf("split: new = %q", got)
	}
}

func TestCorrespondenceStopsAtAKindOrMarkerMismatch(t *testing.T) {
	mk := func(kind func(*depEdge), marker string, xver string) *depGraph {
		var opts []func(*depEdge)
		if kind != nil {
			opts = append(opts, kind)
		}
		if marker != "" {
			opts = append(opts, withMarker(marker))
		}
		return tgraph([]depEdge{te("p", "p@1")},
			tn{key: "p@1", name: "p", ver: "1", deps: []depEdge{te("m", "m@1", opts...)}},
			tn{key: "m@1", name: "m", ver: "1", deps: []depEdge{te("x", "x@"+xver)}},
			tn{key: "x@" + xver, name: "x", ver: xver})
	}
	t.Run("a peer requirement becomes regular", func(t *testing.T) {
		c, _ := buildCorrespondence(bg, mk(asPeer(), "", "1"), mk(nil, "", "2"), ManagerNpm)
		if len(c.old[posKey{"p@1", "m", ""}]) != 0 || len(c.old[posKey{"m@1", "x", ""}]) != 0 {
			t.Errorf("old = %v: nothing at or below a kind mismatch", c.old)
		}
	})
	t.Run("a peer requirement is recorded and not followed", func(t *testing.T) {
		c, _ := buildCorrespondence(bg, mk(asPeer(), "", "1"), mk(asPeer(), "", "2"), ManagerNpm)
		if got := setKeys(c.old[posKey{"p@1", "m", ""}]); got != "m@1" {
			t.Errorf("old = %v", c.old)
		}
		if len(c.old[posKey{"m@1", "x", ""}]) != 0 {
			t.Errorf("old = %v: the walk went below a peer requirement", c.old)
		}
	})
	t.Run("a marker of the middle requirement changes", func(t *testing.T) {
		before, after := mk(nil, "sys_platform == 'linux'", "1"), mk(nil, "sys_platform == 'win32'", "2")
		c, _ := buildCorrespondence(bg, before, after, ManagerUv)
		if len(c.old[posKey{"p@1", "m", "sys_platform == 'win32'"}]) != 0 || len(c.old[posKey{"m@1", "x", ""}]) != 0 {
			t.Errorf("old = %v: nothing at or below a marker mismatch", c.old)
		}
		// The matching of paths for the downgrade check goes on below it, as it
		// always has: only a requirement into an entry of the chain is compared.
		scope := &chainScope{Targets: map[string]bool{}, Names: map[string]bool{}, RAnc: map[string]bool{}, Scheme: schemePEP440}
		if reason, why := mapChainPaths(bg, before, after, scope); reason != "" {
			t.Errorf("mapChainPaths = %s (%s)", reason, why)
		}
	})
}

func TestCorrespondenceKeepsUnchangedRequirementsTheWalkDoesNotReach(t *testing.T) {
	// t requires b only as a peer, so the walk does not go below it, and b's
	// requirement for x stays as it was.
	before := tgraph([]depEdge{te("t", "t@1")},
		tn{key: "t@1", name: "t", ver: "1", deps: []depEdge{te("b", "b@1", asPeer())}},
		tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("x", "x@1")}}, tn{key: "x@1", name: "x", ver: "1"})
	after := tgraph([]depEdge{te("t", "t@1")},
		tn{key: "t@1", name: "t", ver: "1", deps: []depEdge{te("b", "b@1", asPeer())}},
		tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("x", "x@1")}}, tn{key: "x@1", name: "x", ver: "1"})
	c, _ := buildCorrespondence(bg, before, after, ManagerNpm)
	if len(c.old[posKey{"b@1", "x", ""}]) != 0 {
		t.Errorf("old = %v", c.old)
	}
	if got := setKeys(c.new["x@1"]); got != "x@1" {
		t.Errorf("new = %v: the unchanged requirement still leads x@1 to x@1", c.new)
	}
	edgeOf := func(g *depGraph) depEdge { return g.nodes["b@1"].deps[0] }
	if !unchangedEdge(ManagerNpm, before, after, "b@1", edgeOf(after)) {
		t.Error("the requirement did not change")
	}
	// A changed record of the parent, or of the entry pointed to, is a change.
	changed := tgraph([]depEdge{te("t", "t@1")},
		tn{key: "t@1", name: "t", ver: "1", deps: []depEdge{te("b", "b@1", asPeer())}},
		tn{key: "b@1", name: "b", ver: "1", rev: "other", deps: []depEdge{te("x", "x@1")}}, tn{key: "x@1", name: "x", ver: "1"})
	if unchangedEdge(ManagerNpm, before, changed, "b@1", edgeOf(changed)) {
		t.Error("the parent's record changed")
	}
	moved := tgraph([]depEdge{te("t", "t@1")},
		tn{key: "t@1", name: "t", ver: "1", deps: []depEdge{te("b", "b@1", asPeer())}},
		tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("x", "x@1")}}, tn{key: "x@1", name: "x", ver: "1", rev: "other"})
	if unchangedEdge(ManagerNpm, before, moved, "b@1", edgeOf(moved)) {
		t.Error("the entry's record changed")
	}
	marked := tgraph([]depEdge{te("t", "t@1")},
		tn{key: "t@1", name: "t", ver: "1", deps: []depEdge{te("b", "b@1", asPeer())}},
		tn{key: "b@1", name: "b", ver: "1", deps: []depEdge{te("x", "x@1", withMarker("m"))}}, tn{key: "x@1", name: "x", ver: "1"})
	if unchangedEdge(ManagerNpm, before, marked, "b@1", edgeOf(marked)) {
		t.Error("the marker changed")
	}
}
