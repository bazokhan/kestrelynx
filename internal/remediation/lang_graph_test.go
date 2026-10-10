package remediation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// npmEntry is a package entry for npmLock.
type npmEntry struct {
	ver  string
	deps map[string]string
	opt  map[string]string // optionalDependencies
	url  string            // resolved; the public registry when empty
}

// npmLock makes a package-lock.json (lockfileVersion 3) from the root's
// dependencies and package entries by path.
func npmLock(root map[string]string, pkgs map[string]npmEntry) []byte {
	packages := map[string]any{"": map[string]any{"name": "app", "version": "1.0.0", "dependencies": root}}
	for path, e := range pkgs {
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		url := e.url
		if url == "" {
			url = "https://registry.npmjs.org/" + name + "/-/" + name[strings.LastIndex(name, "/")+1:] + "-" + e.ver + ".tgz"
		}
		ent := map[string]any{"version": e.ver, "resolved": url, "integrity": "sha512-" + name + e.ver}
		if len(e.deps) > 0 {
			ent["dependencies"] = e.deps
		}
		if len(e.opt) > 0 {
			ent["optionalDependencies"] = e.opt
		}
		packages[path] = ent
	}
	b, _ := json.Marshal(map[string]any{"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": packages})
	return b
}

func diffNpm(t *testing.T, before, after []byte, targets ...string) (DependencyDiff, Reason, string) {
	t.Helper()
	gb, err := npmGraph(bg, before)
	if err != nil {
		t.Fatal(err)
	}
	ga, err := npmGraph(bg, after)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, n := range targets {
		m[n] = true
	}
	diff, reason, detail := diffGraphs(bg, gb, ga, m)
	if reason == "" {
		reason, detail = checkUnresolved(gb, ga)
	}
	return diff, reason, detail
}

func TestDiffGraphsNpm(t *testing.T) {
	root := map[string]string{"a": "^1.0.0", "e": "^1.0.0"}
	base := map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}},
		"node_modules/c": {ver: "1.0.0"},
		"node_modules/e": {ver: "1.0.0"},
	}
	with := func(mut func(map[string]npmEntry)) []byte {
		m := map[string]npmEntry{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		return npmLock(root, m)
	}
	before := npmLock(root, base)

	t.Run("the target moves and its dependency changes", func(t *testing.T) {
		after := with(func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"d": "^1.0.0"}}
			delete(m, "node_modules/c")
			m["node_modules/d"] = npmEntry{ver: "1.0.0"}
		})
		diff, reason, detail := diffNpm(t, before, after, "t")
		if reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
		if strings.Join(diff.Added, ",") != "node_modules/d" || strings.Join(diff.Changed, ",") != "node_modules/t" || strings.Join(diff.Removed, ",") != "node_modules/c" {
			t.Errorf("diff = %+v", diff)
		}
	})
	t.Run("only the target changes", func(t *testing.T) {
		after := with(func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
		})
		if _, reason, detail := diffNpm(t, before, after, "t"); reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
	})
	t.Run("a dependency of the target is updated too", func(t *testing.T) {
		after := with(func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
			m["node_modules/c"] = npmEntry{ver: "1.0.9"}
		})
		if _, reason, detail := diffNpm(t, before, after, "t"); reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
	})
	rejects := []struct {
		name   string
		mut    func(map[string]npmEntry)
		reason Reason
	}{
		{"an unrelated package changes", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
			m["node_modules/e"] = npmEntry{ver: "1.0.1"}
		}, ReasonUnexplainedDiff},
		{"the parent of the target changes", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
			m["node_modules/a"] = npmEntry{ver: "1.0.1", deps: map[string]string{"t": "^1.0.0"}}
		}, ReasonUnexplainedDiff},
		{"the parent's requirement is loosened", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
			m["node_modules/a"] = npmEntry{ver: "1.0.0", deps: map[string]string{"t": "^1.0.5"}}
		}, ReasonUnexplainedDiff},
		{"an unrelated package disappears", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
			delete(m, "node_modules/e")
		}, ReasonUnexplainedDiff},
		{"a new package nothing requires", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}}
			m["node_modules/x"] = npmEntry{ver: "1.0.0"}
		}, ReasonUnexplainedDiff},
		{"a package the target needs is removed while still required elsewhere", func(m map[string]npmEntry) {
			m["node_modules/e"] = npmEntry{ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}}
			m["node_modules/t"] = npmEntry{ver: "1.0.5"}
			delete(m, "node_modules/c")
		}, ReasonUnexplainedDiff},
		{"the target is gone", func(m map[string]npmEntry) {
			delete(m, "node_modules/t")
			delete(m, "node_modules/c")
		}, ReasonTargetRemoved},
		{"the target stays but nothing requires it", func(m map[string]npmEntry) {
			m["node_modules/a"] = npmEntry{ver: "1.0.0"}
			delete(m, "node_modules/c")
		}, ReasonTargetRemoved},
		{"a new package comes from elsewhere", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"d": "^1.0.0"}}
			delete(m, "node_modules/c")
			m["node_modules/d"] = npmEntry{ver: "1.0.0", url: "https://evil.example/d-1.0.0.tgz"}
		}, ReasonResolvedSourceChanged},
		{"the target comes from elsewhere", func(m map[string]npmEntry) {
			m["node_modules/t"] = npmEntry{ver: "1.0.5", deps: map[string]string{"c": "^1.0.0"}, url: "git+ssh://git@github.com/x/t.git#abc"}
		}, ReasonResolvedSourceChanged},
	}
	for _, c := range rejects {
		t.Run(c.name, func(t *testing.T) {
			_, reason, detail := diffNpm(t, before, with(c.mut), "t")
			if reason != c.reason {
				t.Errorf("reason = %q (%s), want %q", reason, detail, c.reason)
			}
		})
	}
	t.Run("the root requirements change", func(t *testing.T) {
		after := npmLock(map[string]string{"a": "^1.0.0", "e": "^1.0.0", "c": "^1.0.0"}, base)
		if _, reason, _ := diffNpm(t, before, after, "t"); reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %q", reason)
		}
	})
	t.Run("a nested target", func(t *testing.T) {
		nested := map[string]npmEntry{
			"node_modules/a":                {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
			"node_modules/a/node_modules/t": {ver: "1.0.0"},
			"node_modules/t":                {ver: "2.0.0"},
		}
		b := npmLock(map[string]string{"a": "^1.0.0", "t": "^2.0.0"}, nested)
		nested["node_modules/a/node_modules/t"] = npmEntry{ver: "1.0.5"}
		a := npmLock(map[string]string{"a": "^1.0.0", "t": "^2.0.0"}, nested)
		// Both copies of t are the target; the copy that did not change does not matter.
		if _, reason, detail := diffNpm(t, b, a, "t"); reason != "" {
			t.Fatalf("%s: %s", reason, detail)
		}
	})
	t.Run("scoped package names resolve", func(t *testing.T) {
		scoped := map[string]npmEntry{
			"node_modules/@s/a":                   {ver: "1.0.0", deps: map[string]string{"@s/b": "^1.0.0"}},
			"node_modules/@s/a/node_modules/@s/b": {ver: "1.0.0"},
		}
		g, err := npmGraph(bg, npmLock(map[string]string{"@s/a": "^1.0.0"}, scoped))
		if err != nil {
			t.Fatal(err)
		}
		if g.roots[0].key != "node_modules/@s/a" || g.nodes["node_modules/@s/a"].deps[0].key != "node_modules/@s/a/node_modules/@s/b" {
			t.Errorf("roots %+v nodes %+v", g.roots, g.nodes["node_modules/@s/a"].deps)
		}
	})
}

func TestGraphsOfTheFixtures(t *testing.T) {
	read := func(dir, name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "update", dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	keys := func(g *depGraph) string {
		var ks []string
		for k := range g.nodes {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	for _, c := range []struct {
		name  string
		g     func() (*depGraph, error)
		nodes string
		root  string
		child string
	}{
		{"npm", func() (*depGraph, error) { return npmGraph(bg, read("npm", "package-lock.json")) },
			"node_modules/minimist,node_modules/mkdirp", "node_modules/mkdirp", "node_modules/minimist"},
		{"pnpm", func() (*depGraph, error) { return pnpmGraph(bg, read("pnpm", "pnpm-lock.yaml")) },
			"minimist@1.2.5,mkdirp@0.5.5", "mkdirp@0.5.5", "minimist@1.2.5"},
		{"uv", func() (*depGraph, error) { return uvGraph(bg, read("uv", "uv.lock")) },
			"urllib3==1.26.4", "urllib3==1.26.4", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			g, err := c.g()
			if err != nil {
				t.Fatal(err)
			}
			if got := keys(g); got != c.nodes {
				t.Errorf("nodes = %s", got)
			}
			if len(g.roots) != 1 || g.roots[0].key != c.root {
				t.Errorf("roots = %+v", g.roots)
			}
			if c.child != "" {
				n := g.nodes[c.root]
				if len(n.deps) != 1 || n.deps[0].key != c.child {
					t.Errorf("deps = %+v", n.deps)
				}
			}
			for k, n := range g.nodes {
				if n.problem != "" {
					t.Errorf("%s: %s", k, n.problem)
				}
			}
		})
	}
	t.Run("the fixtures' updates are explained", func(t *testing.T) {
		for _, c := range []struct {
			dir, lock, target string
			g                 func(context.Context, []byte) (*depGraph, error)
		}{
			{"npm", "package-lock.json", "minimist", npmGraph},
			{"pnpm", "pnpm-lock.yaml", "minimist", pnpmGraph},
			{"uv", "uv.lock", "urllib3", uvGraph},
		} {
			b, err := c.g(bg, read(c.dir, c.lock))
			if err != nil {
				t.Fatal(err)
			}
			a, err := c.g(bg, readAfter(t, c.dir, c.lock))
			if err != nil {
				t.Fatal(err)
			}
			if _, reason, detail := diffGraphs(bg, b, a, map[string]bool{c.target: true}); reason != "" {
				t.Errorf("%s: %s: %s", c.dir, reason, detail)
			}
			// The same change is not explained for a package that was not updated.
			if _, reason, _ := diffGraphs(bg, b, a, map[string]bool{"other": true}); reason == "" {
				t.Errorf("%s: the update is explained by a package that is not in the file", c.dir)
			}
		}
	})
}

func readAfter(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "update", dir, "after", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDiffGraphsPnpmAndUv(t *testing.T) {
	read := func(dir, name string) string {
		b, err := os.ReadFile(filepath.Join("testdata", "update", dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	t.Run("pnpm: a changed unrelated entry", func(t *testing.T) {
		before := read("pnpm", "pnpm-lock.yaml")
		after := string(readAfter(t, "pnpm", "pnpm-lock.yaml"))
		after = strings.Replace(after, "mkdirp@0.5.5:\n    resolution: {integrity: sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==}", "mkdirp@0.5.5:\n    resolution: {integrity: sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ00==}", 1)
		gb, _ := pnpmGraph(bg, []byte(before))
		ga, err := pnpmGraph(bg, []byte(after))
		if err != nil {
			t.Fatal(err)
		}
		if _, reason, _ := diffGraphs(bg, gb, ga, map[string]bool{"minimist": true}); reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %q", reason)
		}
	})
	t.Run("pnpm: the importer's specifier changes", func(t *testing.T) {
		before := read("pnpm", "pnpm-lock.yaml")
		after := strings.Replace(string(readAfter(t, "pnpm", "pnpm-lock.yaml")), "specifier: 0.5.5", "specifier: ^0.5.5", 1)
		gb, _ := pnpmGraph(bg, []byte(before))
		ga, _ := pnpmGraph(bg, []byte(after))
		if _, reason, _ := diffGraphs(bg, gb, ga, map[string]bool{"minimist": true}); reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %q", reason)
		}
	})
	t.Run("uv: an extra package", func(t *testing.T) {
		before := read("uv", "uv.lock")
		after := string(readAfter(t, "uv", "uv.lock")) + `
[[package]]
name = "extra"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
`
		gb, _ := uvGraph(bg, []byte(before))
		ga, err := uvGraph(bg, []byte(after))
		if err != nil {
			t.Fatal(err)
		}
		if _, reason, _ := diffGraphs(bg, gb, ga, map[string]bool{"urllib3": true}); reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %q", reason)
		}
	})
	t.Run("uv: a wheel from another host", func(t *testing.T) {
		after := strings.Replace(string(readAfter(t, "uv", "uv.lock")), "https://files.pythonhosted.org/packages/48", "https://evil.example/packages/48", 1)
		ga, err := uvGraph(bg, []byte(after))
		if err != nil {
			t.Fatal(err)
		}
		gb, _ := uvGraph(bg, []byte(read("uv", "uv.lock")))
		if _, reason, _ := diffGraphs(bg, gb, ga, map[string]bool{"urllib3": true}); reason != ReasonResolvedSourceChanged {
			t.Errorf("reason = %q", reason)
		}
	})
	t.Run("uv: top-level settings change", func(t *testing.T) {
		after := strings.Replace(string(readAfter(t, "uv", "uv.lock")), `requires-python = ">=3.9"`, `requires-python = ">=3.8"`, 1)
		ga, _ := uvGraph(bg, []byte(after))
		gb, _ := uvGraph(bg, []byte(read("uv", "uv.lock")))
		if _, reason, _ := diffGraphs(bg, gb, ga, map[string]bool{"urllib3": true}); reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %q", reason)
		}
	})
}

var bg = context.Background()
