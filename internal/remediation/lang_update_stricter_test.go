package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// --- the legacy tree: alias and link nodes, a missing tree, named entries ---

// withAlias adds to a package-lock.json an entry installed under another
// name than its path's, and returns the lock.
func withAlias(t *testing.T, lock string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(lock), &doc); err != nil {
		t.Fatal(err)
	}
	doc["packages"].(map[string]any)["node_modules/mk"] = map[string]any{
		"name": "mkdirp", "version": "0.5.5",
		"resolved":  "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.5.tgz",
		"integrity": "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==",
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func TestLegacyTreeKeepsAliasNodesAndDoesNotExemptNamedEntries(t *testing.T) {
	setup := func(t *testing.T, named bool, edit func(map[string]map[string]any)) *harness {
		h := newHarness(t, "npm")
		prep := func(lock string) string {
			lock = withAlias(t, lock)
			if named {
				lock = editNpmEntry(t, lock, "node_modules/mkdirp", func(e map[string]any) { e["name"] = "mkdirp" })
			}
			return lock
		}
		h.files["package-lock.json"] = npmV2(t, prep(h.files["package-lock.json"]), nil)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerNpm, h.files, minimistGroup())
		h.editLock(npmV2(t, prep(string(h.after)), edit))
		return h
	}
	t.Run("an alias node that is the original's passes", func(t *testing.T) {
		it, _ := setup(t, false, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("an entry with an explicit name equal to its path's passes", func(t *testing.T) {
		it, _ := setup(t, true, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	other := "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
	for name, edit := range map[string]func(map[string]map[string]any){
		"an alias node switched to another version":      func(l map[string]map[string]any) { l["mk"]["version"] = "0.5.6" },
		"an alias node switched to another distribution": func(l map[string]map[string]any) { l["mk"]["resolved"] = other },
		"an alias node with another integrity": func(l map[string]map[string]any) {
			l["mk"]["integrity"] = "sha512-" + strings.Repeat("A", 86) + "=="
		},
		"an alias node with a member the original lacks": func(l map[string]map[string]any) { l["mk"]["bundled"] = true },
		"an alias node missing":                          func(l map[string]map[string]any) { delete(l, "mk") },
	} {
		t.Run(name, func(t *testing.T) {
			it, _ := setup(t, false, edit).run()
			wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
			if !strings.Contains(it.Detail, "legacy") {
				t.Errorf("detail = %q", it.Detail)
			}
		})
	}
	for name, edit := range map[string]func(map[string]map[string]any){
		"a named entry whose node gives another tarball": func(l map[string]map[string]any) { l["mkdirp"]["resolved"] = other },
		"a named entry whose node gives another version": func(l map[string]map[string]any) { l["mkdirp"]["version"] = "0.5.6" },
		"a named entry missing from the tree":            func(l map[string]map[string]any) { delete(l, "mkdirp") },
	} {
		t.Run(name, func(t *testing.T) {
			it, _ := setup(t, true, edit).run()
			wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		})
	}
	t.Run("the whole tree missing where the original has one", func(t *testing.T) {
		h := setup(t, false, nil)
		var doc map[string]any
		if err := json.Unmarshal(h.after, &doc); err != nil {
			t.Fatal(err)
		}
		delete(doc, "dependencies")
		b, _ := json.MarshalIndent(doc, "", "  ")
		h.editLock(string(b))
		it, _ := h.run()
		if it.Category != CategoryManual || it.Reason == ReasonUpdateVerified {
			t.Fatalf("category/reason = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("no tree in either file passes", func(t *testing.T) {
		h := newHarness(t, "npm")
		strip := func(lock string) string {
			var doc map[string]any
			if err := json.Unmarshal([]byte(lock), &doc); err != nil {
				t.Fatal(err)
			}
			doc["lockfileVersion"] = 2
			b, _ := json.MarshalIndent(doc, "", "  ")
			return string(b)
		}
		h.files["package-lock.json"] = strip(h.files["package-lock.json"])
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerNpm, h.files, minimistGroup())
		h.editLock(strip(string(h.after)))
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
}

// --- uv.lock: every member is read as the type uv reads ---

func TestUvRecordMembersAreCheckedAsUvReadsThem(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{
			"name": "urllib3", "version": "1.26.17",
			"source": map[string]any{"registry": "https://pypi.org/simple"},
			"sdist": map[string]any{
				"url": "https://files.pythonhosted.org/packages/a/urllib3-1.26.17.tar.gz", "hash": "sha256:" + strings.Repeat("a", 64),
				"size": int64(10), "upload-time": "2023-10-02T17:22:30.961Z",
			},
			"wheels": []any{map[string]any{
				"url": "https://files.pythonhosted.org/packages/a/urllib3-1.26.17-py2.py3-none-any.whl", "hash": "sha256:" + strings.Repeat("b", 64),
				"size": int64(10), "upload-time": "2023-10-02T17:22:28Z",
			}},
			"resolution-markers": []any{"python_full_version >= '3.9'"},
			"metadata": map[string]any{
				"requires-dist":   []any{map[string]any{"name": "a", "specifier": ">=1", "extras": []any{"x"}, "marker": "sys_platform == 'linux'"}},
				"provides-extras": []any{"x"},
				"requires-dev":    map[string]any{"dev": []any{map[string]any{"name": "pytest"}}},
			},
			"default-groups":        []any{"dev"},
			"group-requires-python": map[string]any{"dev": ">=3.9"},
		}
	}
	if why := uvRecordProblem(good()); why != "" {
		t.Fatalf("a well-formed record: %s", why)
	}
	wheel := func(m map[string]any) map[string]any { return m["wheels"].([]any)[0].(map[string]any) }
	for name, edit := range map[string]func(m map[string]any){
		"a wheel upload time that is not a timestamp": func(m map[string]any) { wheel(m)["upload-time"] = "not-a-timestamp" },
		"a sdist upload time with no zone":            func(m map[string]any) { m["sdist"].(map[string]any)["upload-time"] = "2023-10-02T17:22:30" },
		"an upload time that is a number":             func(m map[string]any) { wheel(m)["upload-time"] = int64(5) },
		"a wheel file name that is no wheel name":     func(m map[string]any) { wheel(m)["filename"] = "readme.txt" },
		"a wheel file name of the wrong shape":        func(m map[string]any) { wheel(m)["filename"] = "a-1.whl" },
		"a wheel file name that is too long":          func(m map[string]any) { wheel(m)["filename"] = strings.Repeat("a", 300) + "-1-py3-none-any.whl" },
		"a wheel file name with a path in it":         func(m map[string]any) { wheel(m)["filename"] = "../a-1-py3-none-any.whl" },
		"metadata that is a number":                   func(m map[string]any) { m["metadata"] = int64(42) },
		"metadata with a member uv does not write":    func(m map[string]any) { m["metadata"].(map[string]any)["extra"] = "x" },
		"requires-dist that is a string":              func(m map[string]any) { m["metadata"].(map[string]any)["requires-dist"] = "a" },
		"a requirement without a name": func(m map[string]any) {
			m["metadata"].(map[string]any)["requires-dist"] = []any{map[string]any{"specifier": ">=1"}}
		},
		"a requirement with specifier that is a list": func(m map[string]any) {
			m["metadata"].(map[string]any)["requires-dist"] = []any{map[string]any{"name": "a", "specifier": []any{}}}
		},
		"a requirement with extras that are numbers": func(m map[string]any) {
			m["metadata"].(map[string]any)["requires-dist"] = []any{map[string]any{"name": "a", "extras": []any{int64(1)}}}
		},
		"provides-extras that is a table":         func(m map[string]any) { m["metadata"].(map[string]any)["provides-extras"] = map[string]any{} },
		"requires-dev that is a list":             func(m map[string]any) { m["metadata"].(map[string]any)["requires-dev"] = []any{} },
		"resolution-markers that is a number":     func(m map[string]any) { m["resolution-markers"] = int64(42) },
		"resolution-markers with a number in it":  func(m map[string]any) { m["resolution-markers"] = []any{int64(1)} },
		"default-groups that is a number":         func(m map[string]any) { m["default-groups"] = int64(1) },
		"group-requires-python that is a list":    func(m map[string]any) { m["group-requires-python"] = []any{} },
		"group-requires-python with a number":     func(m map[string]any) { m["group-requires-python"] = map[string]any{"dev": int64(3)} },
		"dependency-groups that is a string":      func(m map[string]any) { m["dependency-groups"] = "x" },
		"a source that is a string":               func(m map[string]any) { m["source"] = "pypi" },
		"a source with a value that is a table":   func(m map[string]any) { m["source"] = map[string]any{"registry": map[string]any{}} },
		"a name that is no project name":          func(m map[string]any) { m["name"] = "a b" },
		"a version that is not a version":         func(m map[string]any) { m["version"] = "latest" },
		"a size that is negative":                 func(m map[string]any) { wheel(m)["size"] = int64(-1) },
		"a wheel with a member uv does not write": func(m map[string]any) { wheel(m)["zstd"] = true },
		"a requirement with a member uv does not write": func(m map[string]any) {
			m["metadata"].(map[string]any)["requires-dist"] = []any{map[string]any{"name": "a", "evil": "x"}}
		},
	} {
		m := good()
		edit(m)
		if why := uvRecordProblem(m); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	// Forms uv writes are not refused.
	for name, edit := range map[string]func(m map[string]any){
		"default-groups all":         func(m map[string]any) { m["default-groups"] = "all" },
		"a timestamp with an offset": func(m map[string]any) { wheel(m)["upload-time"] = "2023-10-02T17:22:28+02:00" },
		"a wheel file name given":    func(m map[string]any) { wheel(m)["filename"] = "urllib3-1.26.17-py2.py3-none-any.whl" },
		"dependency-groups in metadata": func(m map[string]any) {
			m["metadata"].(map[string]any)["dependency-groups"] = map[string]any{"g": []any{}}
		},
	} {
		m := good()
		edit(m)
		if why := uvRecordProblem(m); why != "" {
			t.Errorf("%s: %s", name, why)
		}
	}
}

func TestUvOutputWithATypeUvDoesNotReadIsRefused(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"an upload time that is not a timestamp": func(s string) string {
			return strings.Replace(s, `upload-time = "2023-10-02T17:22:28.101Z"`, `upload-time = "not-a-timestamp"`, 1)
		},
		"metadata that is a number on a package": func(s string) string {
			return strings.Replace(s, "[[package]]\nname = \"urllib3\"", "[[package]]\nname = \"urllib3\"\nmetadata = 42", 1)
		},
		"resolution-markers that is a number": func(s string) string {
			return strings.Replace(s, "[[package]]\nname = \"urllib3\"", "[[package]]\nname = \"urllib3\"\nresolution-markers = 42", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "uv")
			edited := edit(string(h.after))
			if edited == string(h.after) {
				t.Fatal("the edit changed nothing")
			}
			h.editLock(edited)
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
		})
	}
}

// --- install fields: a value of another type is never "unspecified" ---

func TestInstallFieldsOfAnotherTypeAreNotUnspecified(t *testing.T) {
	rec := func(body string) map[string]string {
		m, err := nameMap([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		r, err := installRecord(m, "pkg", nil, "bundleDependencies")
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		return r
	}
	none := rec(`{}`)
	for _, body := range []string{
		`{"os":{}}`, `{"os":false}`, `{"os":""}`, `{"os":[]}`, `{"os":"linux"}`, `{"os":{"a":"b"}}`, `{"os":[1]}`,
		`{"cpu":{}}`, `{"libc":false}`,
		`{"engines":[]}`, `{"engines":false}`, `{"engines":""}`, `{"engines":{}}`, `{"engines":["node"]}`, `{"engines":{"node":1}}`,
		`{"bin":false}`, `{"bin":""}`, `{"bin":[]}`, `{"bin":{}}`, `{"bin":{"a":1}}`,
		`{"bundleDependencies":false}`, `{"bundleDependencies":{}}`, `{"bundleDependencies":""}`, `{"bundleDependencies":"a"}`,
		`{"peerDependenciesMeta":[]}`, `{"peerDependenciesMeta":"x"}`, `{"peerDependenciesMeta":{"a":1}}`, `{"peerDependenciesMeta":{"a":{"optional":"yes"}}}`,
	} {
		if _, same := sameRecordOK(rec(body), none); same {
			t.Errorf("%s compares equal to a member left out", body)
		}
	}
	// Different types never meet in a common empty.
	pairs := [][2]string{
		{`{"os":{}}`, `{"os":[]}`}, {`{"os":false}`, `{"os":[]}`}, {`{"engines":[]}`, `{"engines":{}}`},
		{`{"os":""}`, `{"os":{}}`}, {`{"bin":false}`, `{"bin":{}}`}, {`{"cpu":{}}`, `{"cpu":false}`},
	}
	for _, p := range pairs {
		if _, same := sameRecordOK(rec(p[0]), rec(p[1])); same {
			t.Errorf("%s equals %s", p[0], p[1])
		}
	}
	// Null is unspecified; spelling and order of the same value do not matter.
	if _, same := sameRecordOK(rec(`{"os":null,"engines":null}`), none); !same {
		t.Error("null differs from absent")
	}
	if _, same := sameRecordOK(rec(`{"os":["b","a","a"]}`), rec(`{"os":["a","b"]}`)); !same {
		t.Error("the same set differs")
	}
}

func sameRecordOK(a, b map[string]string) (string, bool) {
	k, _, _, same := sameRecord(a, b)
	return k, same
}

func TestRegistryValuesNpmDoesNotStoreAreNotRecorded(t *testing.T) {
	doc := func(extra string) []byte {
		return []byte(`{"name":"p","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/p/-/p-1.0.0.tgz","integrity":"sha512-x"}` + extra + `}`)
	}
	for name, extra := range map[string]string{
		"an empty os list":              `,"os":[]`,
		"an empty engines object":       `,"engines":{}`,
		"a false bundleDependencies":    `,"bundleDependencies":false`,
		"an empty bin object":           `,"bin":{}`,
		"an empty peerDependenciesMeta": `,"peerDependenciesMeta":{}`,
		"a null libc":                   `,"libc":null`,
	} {
		d, err := parseNpmVersion(doc(extra), "p", "1.0.0")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(d.Install) != 0 {
			t.Errorf("%s: install = %v", name, d.Install)
		}
	}
	d, err := parseNpmVersion(doc(`,"os":["linux"],"engines":{"node":">=8"}`), "p", "1.0.0")
	if err != nil || d.Install["os"] != `["linux"]` || d.Install["engines"] != `{"node":">=8"}` {
		t.Errorf("install = %v, %v", d.Install, err)
	}
}

func TestPnpmEnginesOfAnyVersionAreNotRecorded(t *testing.T) {
	node := &depNode{name: "p", version: "1.0.0", install: map[string]string{}}
	reg := NpmDist{Install: map[string]string{"engines": `{"node":"*"}`}}
	if why := installProblem(ManagerPnpm, node, reg); why != "" {
		t.Errorf("pnpm leaves engines of * out: %s", why)
	}
	reg = NpmDist{Install: map[string]string{"engines": `{"node":"*","npm":">=6"}`}}
	node.install = map[string]string{"engines": `{"npm":">=6"}`}
	if why := installProblem(ManagerPnpm, node, reg); why != "" {
		t.Errorf("pnpm keeps the engines that are not *: %s", why)
	}
	node.install = map[string]string{"engines": `{"node":"*","npm":">=6"}`}
	if why := installProblem(ManagerPnpm, node, reg); why == "" {
		t.Error("a record with a * engine pnpm would not write was accepted")
	}
	// npm stores engines of * as they are.
	node.install = map[string]string{}
	reg = NpmDist{Install: map[string]string{"engines": `{"node":"*"}`}}
	if why := installProblem(ManagerNpm, node, reg); why == "" {
		t.Error("npm: an engines record left out was accepted")
	}
}

// --- pnpm-lock.yaml: a repeated key anywhere ---

func TestPnpmLockRefusesARepeatedKeyInAnyMapping(t *testing.T) {
	base := "lockfileVersion: '9.0'\n\n"
	for name, doc := range map[string]string{
		"settings":                    base + "settings:\n  autoInstallPeers: true\n  autoInstallPeers: false\n\nimporters:\n  .: {}\n",
		"an unknown top-level map":    base + "extra:\n  a: 1\n  a: 2\n",
		"a nested unknown map":        base + "extra:\n  deep:\n    x:\n      k: 1\n      k: 2\n",
		"a flow mapping":              base + "extra: {a: 1, a: 2}\n",
		"the importer":                base + "importers:\n  .:\n    dependencies: {}\n    dependencies: {}\n",
		"a package record":            base + "packages:\n  a@1.0.0:\n    resolution: {integrity: x}\n    resolution: {integrity: y}\n",
		"a resolution":                base + "packages:\n  a@1.0.0:\n    resolution: {integrity: x, integrity: y}\n",
		"a mapping inside a sequence": base + "extra:\n  - k: 1\n    k: 2\n",
	} {
		if _, err := readPnpmLock([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := readPnpmLock([]byte(base + "settings:\n  a: true\n  b: false\nextra:\n  - k: 1\n  - k: 2\n")); err != nil {
		t.Errorf("distinct keys: %v", err)
	}
}

// --- pnpm graph: missing snapshots are unresolved edges, unknown members are not copied per snapshot ---

func TestPnpmEdgeToAPackageWithOnlyPeerSnapshotsIsUnresolved(t *testing.T) {
	lock := func(depVersion string) []byte {
		return []byte(`lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: ` + depVersion + `

packages:
  a@1.0.0:
    resolution: {integrity: sha512-aaa}
  b@2.0.0:
    resolution: {integrity: sha512-bbb}

snapshots:
  a@1.0.0(b@2.0.0):
    dependencies:
      b: 2.0.0
  b@2.0.0: {}
`)
	}
	g, err := buildGraph(context.Background(), ManagerPnpm, lock("1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.roots) != 1 || g.roots[0].key != "" {
		t.Fatalf("roots = %+v", g.roots)
	}
	other, err := buildGraph(context.Background(), ManagerPnpm, lock("1.0.0(b@2.0.0)"))
	if err != nil {
		t.Fatal(err)
	}
	if other.roots[0].key != "a@1.0.0(b@2.0.0)" {
		t.Fatalf("roots = %+v", other.roots)
	}
	// Neither comparison nor the walks over the graph meet a missing node.
	for _, pair := range [][2]*depGraph{{g, other}, {other, g}, {g, g}} {
		diffGraphs(context.Background(), pair[0], pair[1], map[string]bool{"a": true})
		checkUnresolved(pair[0], pair[1])
		pair[0].reach(context.Background(), []string{"a@1.0.0"}, nil)
		for _, n := range pair[0].nodes {
			edgeSig(pair[0], n.deps, map[string]bool{"a": true})
		}
	}
	// Edges handed to the graph code that point nowhere are dropped.
	dangling := &depGraph{nodes: map[string]*depNode{"x@1": {name: "x", version: "1", deps: []depEdge{{name: "y", key: "y@1"}}}}, roots: []depEdge{{name: "z", key: "z@1"}}}
	dangling.dropDangling()
	if dangling.roots[0].key != "" || dangling.nodes["x@1"].deps[0].key != "" {
		t.Errorf("dangling edges kept: %+v", dangling)
	}
	edgeSig(dangling, []depEdge{{name: "y", key: "y@1"}}, map[string]bool{"y": true})
}

func TestPnpmUnknownMembersAreListedOncePerPackage(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-aaa")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, ", k%d: x", i)
	}
	b.WriteString("}\n")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, "    m%d: x\n", i)
	}
	b.WriteString("\nsnapshots:\n  a@1.0.0:\n    dependencies:\n      p: 1.0.0\n")
	const snapshots = 4000
	for i := 0; i < snapshots; i++ {
		fmt.Fprintf(&b, "\n  a@1.0.0(p%d@1.0.0): {}\n", i)
	}
	b.WriteString("\n  p@1.0.0: {}\n")
	start := time.Now()
	g, err := pnpmGraph(context.Background(), []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	total := 0
	for _, n := range g.nodes {
		total += len(n.unknown)
		if len(n.unknown) > 2*maxUnknownNamed {
			t.Fatalf("%s lists %d unknown members", n.name, len(n.unknown))
		}
	}
	if g.nodes["a@1.0.0"] == nil || len(g.nodes["a@1.0.0"].unknown) == 0 {
		t.Error("the unknown members were not reported")
	}
	if total > (snapshots+2)*2*maxUnknownNamed {
		t.Errorf("total unknown names = %d", total)
	}
}

// --- pip report and uv: tags are judged as sets ---

func TestWheelTagsAreJudgedAsSetsAndBounded(t *testing.T) {
	tg := &worker.Target{PythonVersion: "3.12", Platforms: []string{"manylinux_2_17_x86_64", "manylinux2014_x86_64", "linux_x86_64"}}
	many := func(prefix string, n int) string {
		tags := make([]string, n)
		for i := range tags {
			tags[i] = fmt.Sprintf("%s%d", prefix, i)
		}
		return strings.Join(tags, ".")
	}
	long := "a-1-" + many("cp2", 10) + ".cp312-" + many("abi", 10) + ".abi3-manylinux_2_17_x86_64.whl"
	if !wheelFitsTarget(long, tg) {
		t.Errorf("a wheel with 11 python tags and 11 abi tags that fits was refused")
	}
	if wheelFitsTarget("a-1-"+many("cp2", 5000)+"-"+many("abi", 5000)+"-manylinux_2_17_x86_64.whl", tg) {
		t.Error("a wheel with thousands of tags was accepted")
	}
	if wheelFitsTarget("a-1-cp312-cp312-"+many("manylinux_2_5_", 5000)+".whl", tg) {
		t.Error("a wheel with thousands of platform tags was accepted")
	}
	if wheelFitsTarget("a-1-py3-none-"+strings.Repeat("x", 300)+".whl", tg) {
		t.Error("a wheel name over the length limit was accepted")
	}
	start := time.Now()
	for i := 0; i < 2000; i++ {
		wheelFitsTarget("a-1-"+many("cp2", 64)+"-"+many("abi", 64)+"-manylinux_2_17_x86_64.whl", tg)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("judging tags took %v", d)
	}
	for name, want := range map[string]bool{
		"a-1-py2.py3-none-any.whl":                     true,
		"a-1-cp312-abi3-manylinux2014_x86_64.whl":      true,
		"a-1-cp39.cp310-abi3-manylinux2014_x86_64.whl": true,
		"a-1-cp313-abi3-manylinux2014_x86_64.whl":      false,
		"a-1-cp311-cp311-manylinux2014_x86_64.whl":     false,
		"a-1-cp312-none-win_amd64.whl":                 false,
		"a-1-py3-cp312-any.whl":                        false,
	} {
		if got := wheelFitsTarget(name, tg); got != want {
			t.Errorf("wheelFitsTarget(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPipReportWheelTagsAreReadOnlyForAFilePyPIPublishes(t *testing.T) {
	h := newHarness(t, "pip")
	tags := strings.Repeat("cp39.", 20000) + "cp312"
	h.checkReport(func(s string) string {
		return strings.Replace(s, "-py3-none-any.whl", "-"+tags+"-"+tags+"-any.whl", -1)
	})
	start := time.Now()
	it, _ := h.run()
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	if !strings.Contains(it.Detail, "does not publish") {
		t.Errorf("detail = %q", it.Detail)
	}
}

// --- direct requirements: duplicates are compared once ---

func TestDuplicateDirectRequirementsAreComparedOnce(t *testing.T) {
	build := func(t *testing.T, specs []string) *harness {
		h := newHarness(t, "uv")
		quoted := make([]string, len(specs))
		reqs := make([]string, len(specs))
		for i, s := range specs {
			quoted[i] = `"urllib3` + s + `"`
			reqs[i] = `{ name = "urllib3", specifier = "` + s + `" }`
		}
		pyproject := strings.Replace(h.files["pyproject.toml"], `dependencies = ["urllib3>=1.26,<2"]`, "dependencies = ["+strings.Join(quoted, ", ")+"]", 1)
		h.files["pyproject.toml"] = pyproject
		relock := func(lock string) string {
			return strings.Replace(lock, `requires-dist = [{ name = "urllib3", specifier = ">=1.26,<2" }]`, "requires-dist = ["+strings.Join(reqs, ", ")+"]", 1)
		}
		h.files["uv.lock"] = relock(h.files["uv.lock"])
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerUv, h.files, h.fx.group())
		h.editLock(relock(string(h.after)))
		return h
	}
	dup := make([]string, 3000)
	for i := range dup {
		dup[i] = ">=1.26,<2"
	}
	old := maxRangeComparisons
	maxRangeComparisons = 10
	defer func() { maxRangeComparisons = old }()
	t.Run("the same requirement written thousands of times", func(t *testing.T) {
		start := time.Now()
		it, _ := build(t, dup).run()
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("took %v", d)
		}
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("many different requirements are over the comparison budget", func(t *testing.T) {
		var distinct []string
		for i := 0; i < 50; i++ {
			distinct = append(distinct, fmt.Sprintf(">=1.%d,<2", i%26))
		}
		for i := 0; i < 50; i++ {
			distinct = append(distinct, fmt.Sprintf(">=1.0.%d,<2", i))
		}
		it, _ := build(t, distinct).run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
	})
}

// --- overrides: one decoding, bounded depth and size ---

func TestOverridesAreWalkedOnceUnderBounds(t *testing.T) {
	names, err := overrideNames(json.RawMessage(`{"a":"1","b@^2":{".":"3","c":{"a":"2","d":"1"}},"e":{"f":{"g":"1"}}}`))
	if err != nil || strings.Join(names, ",") != "a,b,c,d,e,f,g" {
		t.Errorf("names = %v, %v", names, err)
	}
	deep := strings.Repeat(`{"x":`, maxOverrideDepth+5) + `"1"` + strings.Repeat(`}`, maxOverrideDepth+5)
	if _, err := overrideNames(json.RawMessage(deep)); err == nil {
		t.Error("overrides nested far too deep were accepted")
	}
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < maxOverrideNodes+10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"p%d":"1"`, i)
	}
	b.WriteString("}")
	if _, err := overrideNames(json.RawMessage(b.String())); err == nil {
		t.Error("overrides with far too many entries were accepted")
	}
	// A nesting at the limit takes linear time.
	level := strings.Repeat(`{"`+strings.Repeat("n", 200)+`":`, maxOverrideDepth-1) + `"1"` + strings.Repeat(`}`, maxOverrideDepth-1)
	start := time.Now()
	if _, err := overrideNames(json.RawMessage(level)); err != nil {
		t.Error(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}
	// The plan reads the manifest through the same path.
	manifest := `{"name":"b","overrides":` + deep + `}`
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"b"}}}`
	if _, err := parseNpm([]byte(manifest), []byte(lock)); err == nil {
		t.Error("the plan accepted overrides nested too deep")
	} else {
		mustUnsupported(t, err, ReasonUnparsableSource)
	}
}

// --- uv: the project's lowest Python is asked only of entries it reaches ---

func TestUvLowestPythonIsAskedOnlyOfEntriesItReaches(t *testing.T) {
	setup := func(t *testing.T, marker string) *harness {
		h := newHarness(t, "uv")
		rel := h.pypi.releases["urllib3==1.26.17"]
		for i := range rel {
			rel[i].RequiresPython = ">=3.10" // the image's Python 3.12 is fine, the project's 3.9 is not
		}
		if marker != "" {
			mark := func(lock string) string {
				return strings.Replace(lock, "[[package]]\nname = \"urllib3\"\n", "[[package]]\nname = \"urllib3\"\nresolution-markers = [\n    \""+marker+"\",\n]\n", 1)
			}
			h.files["uv.lock"] = mark(h.files["uv.lock"])
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.item = itemFor(t, ManagerUv, h.files, h.fx.group())
			h.editLock(mark(string(h.after)))
		}
		return h
	}
	t.Run("an entry every Python reaches is asked", func(t *testing.T) {
		it, _ := setup(t, "").run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
	t.Run("an entry only for Pythons above the lowest passes", func(t *testing.T) {
		it, _ := setup(t, "python_full_version >= '3.10'").run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("an entry for an environment the lowest Python is in is asked", func(t *testing.T) {
		it, _ := setup(t, "python_full_version < '3.10'").run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
	t.Run("an entry whose markers cannot be decided is left to the image's own check", func(t *testing.T) {
		it, _ := setup(t, "platform_release >= '5.0'").run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the image's own Python still decides", func(t *testing.T) {
		h := setup(t, "python_full_version >= '3.10'")
		rel := h.pypi.releases["urllib3==1.26.17"]
		for i := range rel {
			rel[i].RequiresPython = ">=3.13"
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
}

// --- uv: an entry the image's environment does not reach needs no wheel for it ---

func TestUvEntryForAnotherPlatformNeedsNoWheelForTheImage(t *testing.T) {
	winHash := strings.Repeat("c", 64)
	winURL := "https://files.pythonhosted.org/packages/x/winonly-1.0.0-py3-none-win_amd64.whl"
	setup := func(t *testing.T, marker string) *harness {
		h := newHarness(t, "uv")
		dep := `dependencies = [
    { name = "winonly"` + marker + ` },
]
`
		after := strings.Replace(string(h.after), "[[package]]\nname = \"urllib3\"\nversion = \"1.26.17\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
			"[[package]]\nname = \"urllib3\"\nversion = \"1.26.17\"\nsource = { registry = \"https://pypi.org/simple\" }\n"+dep, 1)
		after += "\n[[package]]\nname = \"winonly\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [\n    { url = \"" + winURL + "\", hash = \"sha256:" + winHash + "\" },\n]\n"
		if after == string(h.after) {
			t.Fatal("the edit changed nothing")
		}
		h.editLock(after)
		h.pypi.releases["winonly==1.0.0"] = []PyPIFile{{Filename: "winonly-1.0.0-py3-none-win_amd64.whl", URL: winURL, Wheel: true, SHA256: winHash}}
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"winonly; sys_platform == 'win32'"}}
		return h
	}
	t.Run("a Windows-only dependency behind a win32 marker passes", func(t *testing.T) {
		it, _ := setup(t, `, marker = "sys_platform == 'win32'"`).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a marker that cannot be decided still needs a wheel", func(t *testing.T) {
		h := setup(t, `, marker = "platform_release >= '5.0'"`)
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"winonly; platform_release >= '5.0'"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the same dependency without a marker still needs a wheel", func(t *testing.T) {
		h := setup(t, "")
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"winonly"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a marker true here still needs a wheel", func(t *testing.T) {
		h := setup(t, `, marker = "sys_platform == 'linux'"`)
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"winonly; sys_platform == 'linux'"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

// --- best-effort checks ---

func TestSpecifiersAreBounded(t *testing.T) {
	long := strings.Repeat(">=3.9,", maxSpecifierClauses+5) + ">=3.9"
	start := time.Now()
	if _, ok := pythonLowerBound(long); ok {
		t.Error("a specifier with far too many clauses was read")
	}
	if _, ok := normalizeSpecifier(">=" + strings.Repeat("1", maxSpecifierBytes)); ok {
		t.Error("a specifier over the length limit was read")
	}
	if ok, ev := pySatisfies(pyVersion{}, long); ok || ev {
		t.Error("a specifier with far too many clauses was evaluated")
	}
	var clauses []string
	for i := 0; i < maxSpecifierClauses-1; i++ {
		clauses = append(clauses, fmt.Sprintf(">=3.%d", i%12))
	}
	for i := 0; i < 2000; i++ {
		if got, ok := pythonLowerBound(strings.Join(clauses, ",")); !ok || got != "3.11" {
			t.Fatalf("lower bound = %q, %v", got, ok)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestListsKeepTheirElementBoundaries(t *testing.T) {
	rec := func(body string) map[string]string {
		m, err := nameMap([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		r, err := installRecord(m, "pkg", nil, "bundleDependencies")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	none := rec(`{}`)
	for _, body := range []string{`{"os":[""]}`, `{"os":["",""]}`, `{"cpu":["a,b"]}`, `{"bundleDependencies":[""]}`} {
		if _, same := sameRecordOK(rec(body), none); same {
			t.Errorf("%s equals a member left out", body)
		}
	}
	if _, same := sameRecordOK(rec(`{"os":["a,b"]}`), rec(`{"os":["a","b"]}`)); same {
		t.Error(`["a,b"] equals ["a","b"]`)
	}
}

func TestUvWheelFilenameMustBeTheEndOfItsURL(t *testing.T) {
	w := func(filename string) map[string]any {
		return map[string]any{
			"url": "https://files.pythonhosted.org/packages/a/urllib3-1.26.17-py2.py3-none-any.whl", "hash": "sha256:" + strings.Repeat("b", 64),
			"filename": filename,
		}
	}
	if why := wheelShapeProblem(w("urllib3-1.26.17-py2.py3-none-any.whl")); why != "" {
		t.Errorf("matching filename: %s", why)
	}
	for name, f := range map[string]string{
		"another file than the url's":     "urllib3-1.26.18-py2.py3-none-any.whl",
		"a build tag that is not numeric": "urllib3-1.26.17-abc-py2.py3-none-any.whl",
		"a name with no version":          "urllib3.whl",
	} {
		if why := wheelShapeProblem(w(f)); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if why := wheelShapeProblem(w("urllib3-1.26.17-1-py2.py3-none-any.whl")); why == "" {
		t.Error("a build tag that does not match the url was accepted")
	}
}

func TestPnpmLockRefusesTagsThatChangeWhatAValueIs(t *testing.T) {
	base := "lockfileVersion: '9.0'\n\n"
	for name, doc := range map[string]string{
		"a binary value":      base + "extra: !!binary aGVsbG8=\n",
		"a custom tag":        base + "extra: !evil x\n",
		"a tagged mapping":    base + "extra: !ruby/object {a: 1}\n",
		"a timestamp tag":     base + "extra: !!timestamp 2020-01-01\n",
		"a tag on a key":      base + "!!binary aGk=: 1\n",
		"a set":               base + "extra: !!set {a: null}\n",
		"a tag in a sequence": base + "extra:\n  - !!python/name:os.system x\n",
	} {
		if _, err := readPnpmLock([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := readPnpmLock([]byte(base + "extra: !!str 12\nother: !!int 5\nm: !!map {a: !!seq [x]}\nn: !!null ~\nb: !!bool true\nf: !!float 1.5\n")); err != nil {
		t.Errorf("standard tags: %v", err)
	}
}

func TestPipReportNeedsItsFixedMembers(t *testing.T) {
	good := `{"version":"1","pip_version":"26.2.1","install":[],"environment":{"python_version":"3.12"}}`
	if _, err := parsePipReport([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"no version":           `{"pip_version":"26.2.1","install":[],"environment":{}}`,
		"no pip_version":       `{"version":"1","install":[],"environment":{}}`,
		"no install":           `{"version":"1","pip_version":"26.2.1","environment":{}}`,
		"no environment":       `{"version":"1","pip_version":"26.2.1","install":[]}`,
		"a null install":       `{"version":"1","pip_version":"26.2.1","install":null,"environment":{}}`,
		"install as an object": `{"version":"1","pip_version":"26.2.1","install":{},"environment":{}}`,
		"version as a number":  `{"version":1,"pip_version":"26.2.1","install":[],"environment":{}}`,
		"pip_version a number": `{"version":"1","pip_version":26,"install":[],"environment":{}}`,
		"environment a list":   `{"version":"1","pip_version":"26.2.1","install":[],"environment":[]}`,
	} {
		if _, err := parsePipReport([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// --- bundled packages: membership is computed from the packages above ---

// nestMinimist moves the minimist entry of a package-lock.json under mkdirp.
func nestMinimist(t *testing.T, lock string, edit func(parent, child map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(lock), &doc); err != nil {
		t.Fatal(err)
	}
	pk := doc["packages"].(map[string]any)
	child := pk["node_modules/minimist"].(map[string]any)
	delete(pk, "node_modules/minimist")
	pk["node_modules/mkdirp/node_modules/minimist"] = child
	if edit != nil {
		edit(pk["node_modules/mkdirp"].(map[string]any), child)
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func nestedMinimistHarness(t *testing.T, edit func(parent, child map[string]any)) *harness {
	t.Helper()
	h := newHarness(t, "npm")
	h.files["package-lock.json"] = nestMinimist(t, h.files["package-lock.json"], nil)
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.item = itemFor(t, ManagerNpm, h.files, group(typeNodePkg, "minimist", "1.2.5",
		FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/mkdirp/node_modules/minimist/package.json"},
		CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}}))
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the nested fixture is not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.editLock(nestMinimist(t, string(h.after), edit))
	return h
}

func TestBundledEntriesAreFoundFromThePackagesAbove(t *testing.T) {
	t.Run("a nested entry nobody bundles passes", func(t *testing.T) {
		it, _ := nestedMinimistHarness(t, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the registry says the parent bundles it and the output dropped inBundle", func(t *testing.T) {
		h := nestedMinimistHarness(t, nil)
		d := h.npm.dists["mkdirp@0.5.5"]
		d.Install = map[string]string{"bundleDependencies": `["minimist"]`}
		h.npm.dists["mkdirp@0.5.5"] = d
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "bundles dependencies") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the output records the bundle in the parent", func(t *testing.T) {
		it, _ := nestedMinimistHarness(t, func(parent, child map[string]any) { parent["bundleDependencies"] = []any{"minimist"} }).run()
		if it.Category != CategoryManual {
			t.Fatalf("category/reason = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("the output marks the entry as bundled", func(t *testing.T) {
		it, _ := nestedMinimistHarness(t, func(parent, child map[string]any) { child["inBundle"] = true }).run()
		if it.Category != CategoryManual {
			t.Fatalf("category/reason = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("the parent of a nested entry is missing from the output", func(t *testing.T) {
		h := nestedMinimistHarness(t, nil)
		var doc map[string]any
		_ = json.Unmarshal(h.after, &doc)
		delete(doc["packages"].(map[string]any), "node_modules/mkdirp")
		b, _ := json.Marshal(doc)
		h.editLock(string(b))
		it, _ := h.run()
		if it.Category == CategoryPRCandidate {
			t.Fatal("accepted")
		}
	})
}

func TestPlanDoesNotOfferBundledOccurrences(t *testing.T) {
	for name, edit := range map[string]func(parent, child map[string]any){
		"the parent lists it as bundled": func(parent, child map[string]any) { parent["bundleDependencies"] = []any{"minimist"} },
		"the parent bundles everything":  func(parent, child map[string]any) { parent["bundleDependencies"] = true },
		"the entry says inBundle":        func(parent, child map[string]any) { child["inBundle"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "npm")
			files := map[string]string{"package.json": h.files["package.json"], "package-lock.json": nestMinimist(t, h.files["package-lock.json"], edit)}
			it := itemFor(t, ManagerNpm, files, group(typeNodePkg, "minimist", "1.2.5",
				FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/mkdirp/node_modules/minimist/package.json"},
				CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"1.2.6"}}))
			if it.Category == CategoryDependencyUpdateCandidate {
				t.Fatalf("offered as an update: %s", it.Detail)
			}
		})
	}
	if got := npmAncestors("node_modules/a/node_modules/@s/b/node_modules/c"); strings.Join(got, "|") != "node_modules/a|node_modules/a/node_modules/@s/b" {
		t.Errorf("ancestors = %v", got)
	}
	if got := npmAncestors("node_modules/a"); len(got) != 0 {
		t.Errorf("ancestors = %v", got)
	}
}

// --- reach by markers: every entry and marker is judged once ---

func TestUvReachJudgesEachMarkerAndEntryOnce(t *testing.T) {
	const parents = 3000
	g := &depGraph{nodes: map[string]*depNode{}}
	g.nodes["t==1"] = &depNode{name: "t", version: "1", resMarkers: []string{"python_version < '3.9'", "python_version < '3.8'"}}
	for i := 0; i < parents; i++ {
		k := fmt.Sprintf("p%d==1", i)
		g.nodes[k] = &depNode{name: fmt.Sprintf("p%d", i), version: "1", deps: []depEdge{{name: "t", key: "t==1", marker: "python_version >= '3.9'"}}}
		g.roots = append(g.roots, depEdge{name: fmt.Sprintf("p%d", i), key: k})
	}
	old := maxMarkerEvals
	maxMarkerEvals = 10
	defer func() { maxMarkerEvals = old }()
	start := time.Now()
	reached, f := uvReach(context.Background(), g, markerEnv{pyMinor: "3.12"}, true)
	if f != nil {
		t.Fatalf("%+v", f)
	}
	if reached["t==1"] {
		t.Error("an entry resolved only for Pythons below 3.9 was reached on 3.12")
	}
	if len(reached) != parents {
		t.Errorf("reached %d", len(reached))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestMarkersAreBoundedAndTokenizedOnce(t *testing.T) {
	env := markerEnv{pyMinor: "3.12", budget: &markerBudget{ctx: context.Background(), max: 100}}
	if _, err := env.eval("python_version >= '3.9'"); err != nil {
		t.Fatal(err)
	}
	if len(env.budget.toks) != 1 {
		t.Errorf("cache = %d", len(env.budget.toks))
	}
	env.eval("python_version >= '3.9'")
	if len(env.budget.toks) != 1 {
		t.Errorf("cache = %d", len(env.budget.toks))
	}
	long := "python_version >= '3.9'" + strings.Repeat(" and python_version >= '3.9'", 300)
	if _, err := env.eval(long); err == nil {
		t.Error("a marker over the byte limit was read")
	}
	many := strings.TrimSuffix(strings.Repeat("python_version and ", 100), " and ")
	if _, err := markerTokens(many); err != nil {
		t.Errorf("%v", err)
	}
	if _, err := markerTokens(strings.Repeat("a ", maxMarkerTokens+5)); err == nil {
		t.Error("a marker over the token limit was read")
	}
}

// --- uv: requirements that no admitted Python puts in force ---

func TestUvRequirementForPythonsTheProjectExcludesIsNotRequired(t *testing.T) {
	setup := func(t *testing.T, requiresPython, regMarker string) *harness {
		h := newHarness(t, "uv")
		re := func(s string) string {
			return strings.Replace(s, `requires-python = ">=3.9"`, `requires-python = "`+requiresPython+`"`, 1)
		}
		h.files["pyproject.toml"] = re(h.files["pyproject.toml"])
		h.files["uv.lock"] = re(h.files["uv.lock"])
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerUv, h.files, h.fx.group())
		h.editLock(re(string(h.after)))
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"six; " + regMarker}}
		return h
	}
	t.Run("a requirement for Pythons below the project's lowest is not required", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "python_version < '3.10'").run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a python_full_version condition below the lowest", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "python_full_version < '3.10.5'").run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a requirement some admitted Python puts in force is required", func(t *testing.T) {
		it, _ := setup(t, ">=3.9", "python_version < '3.10'").run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a requirement for newer Pythons is required", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "python_version >= '3.13'").run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a Python condition that is false throughout, with a platform condition", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "python_version < '3.10' and sys_platform == 'linux'").run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		it, _ = setup(t, ">=3.12", "sys_platform == 'win32' and python_version < '3.10'").run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a platform condition alternative keeps the requirement", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "python_version < '3.10' or sys_platform == 'linux'").run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		it, _ = setup(t, ">=3.12", "python_version < '3.10' or sys_platform == 'win32'").run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a platform condition alone keeps the requirement", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "sys_platform == 'win32'").run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a condition that depends on the patch level is required", func(t *testing.T) {
		it, _ := setup(t, ">=3.12", "python_full_version < '3.12.5'").run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

// deepMinimistHarness puts minimist two levels down: under a, which is under
// mkdirp. a is in the registry with the given install record.
func deepMinimistHarness(t *testing.T, edit func(mkdirp, a, child map[string]any)) *harness {
	t.Helper()
	deepen := func(lock string, e func(mkdirp, a, child map[string]any)) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(lock), &doc); err != nil {
			t.Fatal(err)
		}
		pk := doc["packages"].(map[string]any)
		child := pk["node_modules/minimist"].(map[string]any)
		delete(pk, "node_modules/minimist")
		pk["node_modules/mkdirp/node_modules/a/node_modules/minimist"] = child
		a := map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-" + strings.Repeat("A", 86) + "==",
			"dependencies": map[string]any{"minimist": "^1.2.5"}}
		pk["node_modules/mkdirp/node_modules/a"] = a
		pk["node_modules/mkdirp"].(map[string]any)["dependencies"] = map[string]any{"a": "^1.0.0"}
		if e != nil {
			e(pk["node_modules/mkdirp"].(map[string]any), a, child)
		}
		b, _ := json.MarshalIndent(doc, "", "  ")
		return string(b)
	}
	h := newHarness(t, "npm")
	h.files["package-lock.json"] = deepen(h.files["package-lock.json"], nil)
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.item = itemFor(t, ManagerNpm, h.files, group(typeNodePkg, "minimist", "1.2.5",
		FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/mkdirp/node_modules/a/node_modules/minimist/package.json"},
		CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"1.2.6"}}))
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.editLock(deepen(string(h.after), edit))
	mk := h.npm.dists["mkdirp@0.5.5"]
	mk.Dependencies = map[string]string{"a": "^1.0.0"}
	h.npm.dists["mkdirp@0.5.5"] = mk
	h.npm.dists["a@1.0.0"] = NpmDist{Tarball: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", Integrity: "sha512-" + strings.Repeat("A", 86) + "==",
		Dependencies: map[string]string{"minimist": "^1.2.5"}}
	return h
}

func TestEverythingBelowABundlingPackageIsTakenToBeBundled(t *testing.T) {
	t.Run("nothing bundles anything", func(t *testing.T) {
		it, _ := deepMinimistHarness(t, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the grandparent bundles the parent, which holds the entry", func(t *testing.T) {
		h := deepMinimistHarness(t, nil)
		d := h.npm.dists["mkdirp@0.5.5"]
		d.Install = map[string]string{"bundleDependencies": `["a"]`}
		h.npm.dists["mkdirp@0.5.5"] = d
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the parent bundles something else than the entry", func(t *testing.T) {
		h := deepMinimistHarness(t, nil)
		h.npm.dists["a@1.0.0"] = NpmDist{Tarball: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", Integrity: "sha512-" + strings.Repeat("A", 86) + "==",
			Dependencies: map[string]string{"minimist": "^1.2.5"}, Install: map[string]string{"bundleDependencies": `["other"]`}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the entry bundles something itself", func(t *testing.T) {
		h := deepMinimistHarness(t, nil)
		d := h.npm.dists["minimist@1.2.8"]
		d.Install = map[string]string{"bundleDependencies": `["x"]`}
		h.npm.dists["minimist@1.2.8"] = d
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("category/reason = %s/%s", it.Category, it.Reason)
		}
	})
}

func TestPlanLeavesEverythingBelowABundlingPackage(t *testing.T) {
	deep := func(t *testing.T, e func(mkdirp, a, child map[string]any)) LanguageItem {
		h := deepMinimistHarnessFiles(t, e)
		return h
	}
	for name, e := range map[string]func(mkdirp, a, child map[string]any){
		"the grandparent bundles the parent":     func(m, a, c map[string]any) { m["bundleDependencies"] = []any{"a"} },
		"the parent bundles something else":      func(m, a, c map[string]any) { a["bundleDependencies"] = []any{"other"} },
		"the parent bundles everything":          func(m, a, c map[string]any) { a["bundleDependencies"] = true },
		"the entry bundles something itself":     func(m, a, c map[string]any) { c["bundleDependencies"] = []any{"x"} },
		"the alternative spelling of the member": func(m, a, c map[string]any) { a["bundledDependencies"] = []any{"x"} },
	} {
		t.Run(name, func(t *testing.T) {
			if it := deep(t, e); it.Category == CategoryDependencyUpdateCandidate {
				t.Fatalf("offered as an update: %s", it.Detail)
			}
		})
	}
	for name, e := range map[string]func(mkdirp, a, child map[string]any){
		"nothing bundled":    nil,
		"empty bundle lists": func(m, a, c map[string]any) { a["bundleDependencies"] = []any{}; m["bundledDependencies"] = false },
	} {
		t.Run(name, func(t *testing.T) {
			if it := deep(t, e); it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("not offered: %s %s", it.Category, it.Detail)
			}
		})
	}
}

// deepMinimistHarnessFiles plans the item of deepMinimistHarness over a lock
// edited by edit, without running the update.
func deepMinimistHarnessFiles(t *testing.T, edit func(mkdirp, a, child map[string]any)) LanguageItem {
	t.Helper()
	h := newHarness(t, "npm")
	var doc map[string]any
	if err := json.Unmarshal([]byte(h.files["package-lock.json"]), &doc); err != nil {
		t.Fatal(err)
	}
	pk := doc["packages"].(map[string]any)
	child := pk["node_modules/minimist"].(map[string]any)
	delete(pk, "node_modules/minimist")
	pk["node_modules/mkdirp/node_modules/a/node_modules/minimist"] = child
	a := map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-" + strings.Repeat("A", 86) + "==",
		"dependencies": map[string]any{"minimist": "^1.2.5"}}
	pk["node_modules/mkdirp/node_modules/a"] = a
	pk["node_modules/mkdirp"].(map[string]any)["dependencies"] = map[string]any{"a": "^1.0.0"}
	if edit != nil {
		edit(pk["node_modules/mkdirp"].(map[string]any), a, child)
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	files := map[string]string{"package.json": h.files["package.json"], "package-lock.json": string(b)}
	return itemFor(t, ManagerNpm, files, group(typeNodePkg, "minimist", "1.2.5",
		FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/mkdirp/node_modules/a/node_modules/minimist/package.json"},
		CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"1.2.6"}}))
}

func TestBundleListsAreJudgedByTheirTextOnce(t *testing.T) {
	raw := func(s string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"bundleDependencies": json.RawMessage(s)}
	}
	for s, want := range map[string]bool{"null": false, "false": false, "[]": false, `""`: false, "{}": false, " [ ] ": false,
		"true": true, `["a"]`: true, `[""]`: true, `"a"`: true, "1": true} {
		if got := entryBundlesAnything(raw(s)); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
	if entryBundlesAnything(map[string]json.RawMessage{}) {
		t.Error("an absent member bundles something")
	}
	if !entryBundlesAnything(map[string]json.RawMessage{"bundledDependencies": json.RawMessage(`["x"]`)}) {
		t.Error("the alternative spelling was ignored")
	}
	// A list with a million elements is judged without being read.
	// The entry is built once: copying the list for every call would time
	// the copy, not the judgment.
	big := raw("[" + strings.Repeat(`"x",`, 1000000) + `"x"]`)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		entryBundlesAnything(big)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	if recordBundlesAnything("") || recordBundlesAnything("[]") || !recordBundlesAnything(`["a"]`) {
		t.Error("canonical text misjudged")
	}
}

// --- packages that carry their own shrinkwrap ---

func TestParsedRegistryVersionTellsWhetherItCarriesAShrinkwrap(t *testing.T) {
	doc := func(extra string) []byte {
		return []byte(`{"name":"p","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/p/-/p-1.0.0.tgz","integrity":"sha512-x"}` + extra + `}`)
	}
	for extra, want := range map[string]bool{"": false, `,"_hasShrinkwrap":false`: false, `,"_hasShrinkwrap":null`: false, `,"_hasShrinkwrap":true`: true} {
		d, err := parseNpmVersion(doc(extra), "p", "1.0.0")
		if err != nil || d.HasShrinkwrap != want {
			t.Errorf("%q: %v, %v", extra, d.HasShrinkwrap, err)
		}
	}
	if !entryHasShrinkwrap(map[string]json.RawMessage{"hasShrinkwrap": json.RawMessage("true")}) ||
		entryHasShrinkwrap(map[string]json.RawMessage{"hasShrinkwrap": json.RawMessage("false")}) ||
		entryHasShrinkwrap(map[string]json.RawMessage{}) {
		t.Error("entryHasShrinkwrap misjudged")
	}
}

func TestEverythingBelowAPackageWithAShrinkwrapIsLeftToAPerson(t *testing.T) {
	t.Run("the registry says the parent carries a shrinkwrap", func(t *testing.T) {
		h := nestedMinimistHarness(t, nil)
		d := h.npm.dists["mkdirp@0.5.5"]
		d.HasShrinkwrap = true
		h.npm.dists["mkdirp@0.5.5"] = d
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "shrinkwrap") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the registry says the entry itself carries one", func(t *testing.T) {
		h := nestedMinimistHarness(t, nil)
		d := h.npm.dists["minimist@1.2.8"]
		d.HasShrinkwrap = true
		h.npm.dists["minimist@1.2.8"] = d
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the grandparent carries one and the entry is two levels down", func(t *testing.T) {
		h := deepMinimistHarness(t, nil)
		d := h.npm.dists["mkdirp@0.5.5"]
		d.HasShrinkwrap = true
		h.npm.dists["mkdirp@0.5.5"] = d
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the output records the flag on the entry", func(t *testing.T) {
		it, _ := nestedMinimistHarness(t, func(parent, child map[string]any) { child["hasShrinkwrap"] = true }).run()
		if it.Category != CategoryManual {
			t.Fatalf("category/reason = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("a registry that does not say so passes", func(t *testing.T) {
		it, _ := nestedMinimistHarness(t, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
}

func TestPlanLeavesEverythingBelowAPackageWithAShrinkwrap(t *testing.T) {
	for name, e := range map[string]func(mkdirp, a, child map[string]any){
		"the grandparent carries a shrinkwrap": func(m, a, c map[string]any) { m["hasShrinkwrap"] = true },
		"the parent carries one":               func(m, a, c map[string]any) { a["hasShrinkwrap"] = true },
		"the entry carries one":                func(m, a, c map[string]any) { c["hasShrinkwrap"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			if it := deepMinimistHarnessFiles(t, e); it.Category == CategoryDependencyUpdateCandidate {
				t.Fatalf("offered as an update: %s", it.Detail)
			}
		})
	}
	if it := deepMinimistHarnessFiles(t, func(m, a, c map[string]any) { m["hasShrinkwrap"] = false }); it.Category != CategoryDependencyUpdateCandidate {
		t.Errorf("a false flag stopped the update: %s %s", it.Category, it.Detail)
	}
}

// --- the work of an edit is linear and bounded ---

func TestEditsAreMadeWithOneSortAndOneScan(t *testing.T) {
	// A hundred thousand replacements given in reverse order.
	b := []byte(strings.Repeat("abcdefghij", 100000))
	var reps []replacement
	for i := 99999; i >= 0; i-- {
		reps = append(reps, replacement{i * 10, i*10 + 1, "XY"})
	}
	start := time.Now()
	out, err := applyReplacements(b, reps)
	if err != nil || len(out) != len(b)+100000 || !strings.HasPrefix(string(out), "XYbcdefghijXYbc") {
		t.Fatalf("%v, %d", err, len(out))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	if _, err := applyReplacements([]byte("abcdef"), []replacement{{1, 4, "x"}, {3, 5, "y"}}); err == nil {
		t.Error("overlapping edits were applied")
	}
	if _, err := applyReplacements([]byte("abc"), []replacement{{2, 9, "x"}}); err == nil {
		t.Error("an edit past the end was applied")
	}

	// The same requirement written the most times one update edits.
	var doc strings.Builder
	doc.WriteString("[project]\nname = \"p\"\ndependencies = [\n")
	var idx []int
	var edits []ManifestEdit
	for i := 0; i < maxManifestEdits; i++ {
		doc.WriteString("  \"urllib3==1.26.4\",\n")
		idx = append(idx, i)
		edits = append(edits, ManifestEdit{Section: "project.dependencies", Name: "urllib3", From: "urllib3==1.26.4", To: "urllib3==1.26.17"})
	}
	doc.WriteString("]\n")
	start = time.Now()
	got, err := editPyproject(bg, []byte(doc.String()), idx, edits)
	if err != nil || strings.Count(string(got), "1.26.17") != maxManifestEdits || strings.Contains(string(got), "1.26.4") {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	// One more is over the limit, whatever the document.
	if _, err := editPyproject(bg, []byte(doc.String()), append(idx, 0), append(edits, edits[0])); !errors.Is(err, errManifestEditLimit) {
		t.Errorf("over the limit: %v", err)
	}

	// package.json: many edits in a document with many members.
	var pj strings.Builder
	pj.WriteString(`{"dependencies":{`)
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&pj, `"p%d":"1.0.0",`, i)
	}
	pj.WriteString(`"minimist":"1.2.5"},"devDependencies":{"minimist":"1.2.5"},"optionalDependencies":{"minimist":"1.2.5"}}`)
	var pedits []ManifestEdit
	for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		pedits = append(pedits, ManifestEdit{Section: sec, Name: "minimist", From: "1.2.5", To: "1.2.6"})
	}
	for i := 0; i < 200; i++ {
		pedits = append(pedits, ManifestEdit{Section: "dependencies", Name: fmt.Sprintf("p%d", i), From: "1.0.0", To: "1.0.1"})
	}
	start = time.Now()
	pgot, err := editPackageJSON(bg, []byte(pj.String()), pedits)
	if err != nil || strings.Count(string(pgot), `"1.2.6"`) != 3 {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if _, err := editPackageJSON(bg, []byte(pj.String()), append(pedits, pedits...)); err == nil {
		t.Error("more edits than the limit were made")
	}
	// A time that is over stops the edit.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := editPackageJSON(ctx, []byte(pj.String()), pedits[:1]); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	if _, err := editPyproject(ctx, []byte(doc.String()), idx[:1], edits[:1]); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestMaskingEditedSpecifiersWalksTheRequirementsOnce(t *testing.T) {
	var reqs []any
	for i := 0; i < 200000; i++ {
		reqs = append(reqs, map[string]any{"name": fmt.Sprintf("p%d", i), "specifier": ">=1"})
	}
	meta, _ := json.Marshal(map[string]any{"\x00root": map[string]any{"metadata": map[string]any{"requires-dist": reqs}}})
	g := &depGraph{meta: string(meta)}
	var edits []ManifestEdit
	for i := 0; i < maxManifestEdits; i++ {
		edits = append(edits, ManifestEdit{Section: "project.dependencies", Name: fmt.Sprintf("P%d", i*7)})
	}
	start := time.Now()
	if err := g.maskEditedSpecs(bg, ManagerUv, edits); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if n := strings.Count(g.meta, editedMask[1:]); n != maxManifestEdits {
		t.Errorf("masked %d", n)
	}
	if err := g.maskEditedSpecs(bg, ManagerUv, append(edits, edits[0])); err == nil {
		t.Error("more edits than the limit were masked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.maskEditedSpecs(ctx, ManagerUv, edits[:1]); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestMoreEditsThanOneUpdateMakesDefersTheItem(t *testing.T) {
	h := newHarness(t, "uv")
	n := maxManifestEdits + 1
	reqs := make([]string, n)
	quoted := make([]string, n)
	for i := range reqs {
		reqs[i] = `{ name = "urllib3", specifier = "==1.26.4" }`
		quoted[i] = `"urllib3==1.26.4"`
	}
	h.files["pyproject.toml"] = strings.Replace(h.files["pyproject.toml"], `dependencies = ["urllib3>=1.26,<2"]`, "dependencies = ["+strings.Join(quoted, ", ")+"]", 1)
	h.files["uv.lock"] = strings.Replace(h.files["uv.lock"], `requires-dist = [{ name = "urllib3", specifier = ">=1.26,<2" }]`, "requires-dist = ["+strings.Join(reqs, ", ")+"]", 1)
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.item = itemFor(t, ManagerUv, h.files, urllibGroup())
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not a candidate: %s %s", h.item.Category, h.item.Detail)
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
	if h.work.calls != 0 {
		t.Error("a job ran")
	}
}

// --- the job timeout the work program can be given ---

func TestJobTimeoutMustFitTheWorkProgramsDeadlineLimit(t *testing.T) {
	h := newHarness(t, "npm")
	limit := time.Duration(worker.MaxDeadlineSeconds+30) * time.Second
	for name, c := range map[string]struct {
		timeout time.Duration
		ok      bool
	}{
		"the default":             {0, true},
		"exactly the limit":       {limit, true},
		"a second over the limit": {limit + time.Second, false},
		"an hour and a half":      {90 * time.Minute, false},
		"a day":                   {24 * time.Hour, false},
		"just under a minute":     {59 * time.Second, false},
		"a minute":                {time.Minute, true},
	} {
		cfg := h.cfg
		cfg.JobTimeout = c.timeout
		u, err := NewLangUpdater(cfg)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err == nil {
			if d := u.newJob(worker.ManagerNpm, &jobEnvironment{}, map[string][]byte{}, []worker.Step{{ID: "a", Op: worker.OpNpmRelock}}).DeadlineSeconds; d < 1 || d > worker.MaxDeadlineSeconds {
				t.Errorf("%s: deadline %d", name, d)
			}
		}
	}
}

// --- the planning of the manifest is linear in targets plus requirements ---

// bigUvRun is an update of k packages of a project whose pyproject.toml lists
// m requirements, k of them the targets, each pinned below its target.
func bigUvRun(t *testing.T, k, m int) *updateRun {
	t.Helper()
	var doc strings.Builder
	doc.WriteString("[project]\nname = \"p\"\nversion = \"1\"\nrequires-python = \">=3.9\"\ndependencies = [\n")
	it := &LanguageItem{Manager: ManagerUv}
	for i := 0; i < m; i++ {
		name := fmt.Sprintf("pkg%d", i)
		if i < k {
			fmt.Fprintf(&doc, "  \"%s==1.0.0\",\n", name)
			it.Packages = append(it.Packages, LanguagePackage{
				Name: name, Normalized: name, Action: ActionUpdate, SelectionLowerBound: "1.0.1",
				Occurrences: []SourceOccurrence{{Matched: true, Direct: true}},
			})
			continue
		}
		fmt.Fprintf(&doc, "  \"%s>=1\",\n", name)
	}
	doc.WriteString("]\n")
	set, fail := newUpdateSet(it)
	if fail != nil {
		t.Fatal(fail.detail)
	}
	return &updateRun{it: it, set: set, upd: &LanguageUpdate{}, src: &sourceFiles{manifestName: "pyproject.toml", manifestPath: "pyproject.toml", manifest: []byte(doc.String())}}
}

func TestUvPlanningReadsEachRequirementOnce(t *testing.T) {
	r := bigUvRun(t, worker.MaxPackages, 150000)
	r.manifest = r.src.manifest
	start := time.Now()
	fail := r.planUvProject(bg)
	d := time.Since(start)
	if fail != nil {
		t.Fatalf("%s %s", fail.reason, fail.detail)
	}
	if len(r.upd.ManifestEdits) != worker.MaxPackages {
		t.Errorf("edits = %d", len(r.upd.ManifestEdits))
	}
	if d > 10*time.Second {
		t.Errorf("planning took %v", d)
	}
	// Over the bound on requirements the item is deferred, before any job.
	r = bigUvRun(t, 2, maxManifestRequirements+1)
	r.manifest = r.src.manifest
	fail = r.planUvProject(bg)
	if fail == nil || fail.category != CategoryDeferred || fail.reason != ReasonUpdateInputLimit {
		t.Errorf("over the requirement limit: %+v", fail)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = bigUvRun(t, 2, 5000)
	r.manifest = r.src.manifest
	if fail := r.planUvProject(ctx); fail == nil || fail.category != CategoryDeferred {
		t.Errorf("canceled: %+v", fail)
	}
}

func TestUpdateSetIsIndexedOnce(t *testing.T) {
	r := bigUvRun(t, worker.MaxPackages, worker.MaxPackages)
	start := time.Now()
	for i := 0; i < 200; i++ {
		for _, n := range r.set.names {
			if !r.isDirect(n) || r.nameOf(n) != n || !r.targetSet()[n] {
				t.Fatalf("%s", n)
			}
		}
		r.packageArgs(nil, func(string) bool { return true })
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if got := r.nameOf("unknown"); got != "unknown" {
		t.Errorf("nameOf = %q", got)
	}
	if len(r.set.byName["pkg3"]) != 1 {
		t.Errorf("byName = %v", r.set.byName["pkg3"])
	}
}

func TestLimitsAreCheckedBeforeTheManifestIsPlanned(t *testing.T) {
	t.Run("more packages than one job takes", func(t *testing.T) {
		h := newHarness(t, "npm")
		for i := 0; i < worker.MaxPackages+1; i++ {
			name := fmt.Sprintf("extra%d", i)
			h.item.Packages = append(h.item.Packages, LanguagePackage{Name: name, Action: ActionUpdate, SelectionLowerBound: "1.0.1", Installed: "1.0.0"})
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdatePackageLimit)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
	})
	t.Run("a manifest over the size limit", func(t *testing.T) {
		for _, mgr := range []string{"npm", "pnpm", "uv"} {
			h := newHarness(t, mgr)
			name := map[string]string{"npm": "package.json", "pnpm": "package.json", "uv": "pyproject.toml"}[mgr]
			h.files[name] += strings.Repeat(" ", maxManifestBytes)
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			src := h.item.Source
			src.Files = append([]SourceFile(nil), src.Files...)
			for i := range src.Files {
				if path.Base(src.Files[i].Path) == name {
					src.Files[i].BlobSHA = gitBlobSHA([]byte(h.files[name]))
				}
			}
			h.item.Source = src
			it, _ := h.run()
			wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
			if h.work.calls != 0 {
				t.Errorf("%s: a job ran", mgr)
			}
		}
	})
	t.Run("an edit of a manifest over the size limit is a limit, not a failure", func(t *testing.T) {
		big := []byte(strings.Repeat(" ", maxManifestBytes+1))
		if _, err := editPackageJSON(bg, big, nil); !errors.Is(err, errManifestEditLimit) {
			t.Errorf("package.json: %v", err)
		}
		if _, err := editPyproject(bg, big, nil, nil); !errors.Is(err, errManifestEditLimit) {
			t.Errorf("pyproject.toml: %v", err)
		}
		r := &updateRun{it: &LanguageItem{Manager: ManagerNpm}, upd: &LanguageUpdate{}, src: &sourceFiles{manifestName: "package.json"}}
		fail := r.applyManifestEdits(bg, []ManifestEdit{{Name: "a"}}, func() ([]byte, error) { return editPackageJSON(bg, big, nil) })
		if fail == nil || fail.category != CategoryDeferred || fail.reason != ReasonUpdateInputLimit {
			t.Errorf("fail = %+v", fail)
		}
	})
}
