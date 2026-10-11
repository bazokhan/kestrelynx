package remediation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- a requirement that points to a local location is never taken for a
// requirement the registry can vouch for ---

func pnpmLockWith(aVersion, aDeps, extraPackages, extraSnapshots string) string {
	return `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: ` + aVersion + `

packages:

  a@` + aVersion + `:
    resolution: {integrity: sha512-aaa` + aVersion + `}
` + extraPackages + `
snapshots:

  a@` + aVersion + `:
` + aDeps + extraSnapshots
}

func diffOf(t *testing.T, m DependencyManager, before, after string, targets ...string) (Reason, string) {
	t.Helper()
	gb, err := buildGraph(bg, m, []byte(before))
	if err != nil {
		t.Fatalf("before: %v", err)
	}
	ga, err := buildGraph(bg, m, []byte(after))
	if err != nil {
		t.Fatalf("after: %v", err)
	}
	set := map[string]bool{}
	for _, n := range targets {
		set[n] = true
	}
	_, reason, detail := diffGraphs(bg, gb, ga, set)
	return reason, detail
}

func TestPnpmOptionalDependencyMovedToALocalDirectoryIsRefused(t *testing.T) {
	xPkg := "\n  x@1.0.0:\n    resolution: {integrity: sha512-xxx}\n"
	before := pnpmLockWith("1.0.0", "    optionalDependencies:\n      x: 1.0.0\n", xPkg, "\n  x@1.0.0: {}\n")
	t.Run("the registry version stays", func(t *testing.T) {
		after := pnpmLockWith("1.0.1", "    optionalDependencies:\n      x: 1.0.0\n", xPkg, "\n  x@1.0.0: {}\n")
		if reason, detail := diffOf(t, ManagerPnpm, before, after, "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	for name, ref := range map[string]string{
		"a link":           "link:vendor/x",
		"a file":           "file:vendor/x.tgz",
		"a workspace":      "workspace:*",
		"a git location":   "git+https://example.com/x.git#abc",
		"a tarball":        "https://example.com/x.tgz",
		"a link to a path": "link:../x",
	} {
		t.Run(name+" replaces it and the entries are gone", func(t *testing.T) {
			after := pnpmLockWith("1.0.1", "    optionalDependencies:\n      x: "+ref+"\n", "", "")
			reason, detail := diffOf(t, ManagerPnpm, before, after, "a")
			if reason != ReasonResolvedSourceChanged || !strings.Contains(detail, ref) {
				t.Errorf("%s: %s", reason, detail)
			}
		})
	}
	t.Run("a required dependency moved the same way", func(t *testing.T) {
		after := pnpmLockWith("1.0.1", "    dependencies:\n      x: link:vendor/x\n", "", "")
		reason, _ := diffOf(t, ManagerPnpm, before, after, "a")
		if reason != ReasonResolvedSourceChanged {
			t.Errorf("reason = %s", reason)
		}
	})
	t.Run("a project requirement moved the same way", func(t *testing.T) {
		after := strings.Replace(pnpmLockWith("1.0.1", "", "", ""), "version: 1.0.1", "version: link:vendor/a", 1)
		after = strings.Replace(after, "  a@1.0.1:\n    resolution: {integrity: sha512-aaa1.0.1}\n", "", 1)
		after = strings.Replace(after, "  a@1.0.1:\n", "", 1)
		reason, _ := diffOf(t, ManagerPnpm, before, after, "a")
		if reason != ReasonResolvedSourceChanged && reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %s", reason)
		}
	})
	t.Run("the same local reference the original had stays", func(t *testing.T) {
		withLink := pnpmLockWith("1.0.0", "    optionalDependencies:\n      x: link:vendor/x\n", "", "")
		after := pnpmLockWith("1.0.1", "    optionalDependencies:\n      x: link:vendor/x\n", "", "")
		if reason, detail := diffOf(t, ManagerPnpm, withLink, after, "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	t.Run("an optional dependency that is simply not in the file stays fine", func(t *testing.T) {
		after := pnpmLockWith("1.0.1", "    optionalDependencies:\n      x: 1.0.0\n", "", "")
		if reason, detail := diffOf(t, ManagerPnpm, before, after, "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
}

func npmLockOf(aVersion, aDeps, entries string) string {
	return `{"name":"p","lockfileVersion":3,"packages":{
"":{"name":"p","dependencies":{"a":"^1.0.0"}},
"node_modules/a":{"version":"` + aVersion + `","resolved":"https://registry.npmjs.org/a/-/a-` + aVersion + `.tgz","integrity":"sha512-a` + aVersion + `"` + aDeps + `}` + entries + `}}`
}

func TestNpmOptionalDependencyMovedToALocalLocationIsRefused(t *testing.T) {
	x := `,"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-x"}`
	before := npmLockOf("1.0.0", `,"optionalDependencies":{"x":"^1.0.0"}`, x)
	t.Run("the registry range stays", func(t *testing.T) {
		after := npmLockOf("1.0.1", `,"optionalDependencies":{"x":"^1.0.0"}`, x)
		if reason, detail := diffOf(t, ManagerNpm, before, after, "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	for name, spec := range map[string]string{
		"file":      "file:vendor/x",
		"link":      "link:vendor/x",
		"git":       "git+https://example.com/x.git",
		"tarball":   "https://example.com/x.tgz",
		"github":    "someone/x",
		"a path":    "../x",
		"an alias":  "npm:other@1",
		"workspace": "workspace:*",
	} {
		t.Run(spec+"/"+name+" with the entry removed", func(t *testing.T) {
			after := npmLockOf("1.0.1", `,"optionalDependencies":{"x":"`+spec+`"}`, "")
			reason, detail := diffOf(t, ManagerNpm, before, after, "a")
			if reason != ReasonResolvedSourceChanged || !strings.Contains(detail, spec) {
				t.Errorf("%s: %s", reason, detail)
			}
		})
	}
	t.Run("an existing local entry that the updated package now resolves to", func(t *testing.T) {
		local := `,"node_modules/loc":{"resolved":"vendor/loc","link":true}`
		b := npmLockOf("1.0.0", ``, local)
		after := npmLockOf("1.0.1", `,"optionalDependencies":{"loc":"^1.0.0"}`, local)
		reason, _ := diffOf(t, ManagerNpm, b, after, "a")
		if reason != ReasonResolvedSourceChanged {
			t.Errorf("reason = %s", reason)
		}
	})
	t.Run("a local entry the original already resolved to stays", func(t *testing.T) {
		local := `,"node_modules/loc":{"resolved":"vendor/loc","link":true}`
		b := npmLockOf("1.0.0", `,"optionalDependencies":{"loc":"^1.0.0"}`, local)
		after := npmLockOf("1.0.1", `,"optionalDependencies":{"loc":"^1.0.0"}`, local)
		if reason, detail := diffOf(t, ManagerNpm, b, after, "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	if npmSpecIsLocal("^1.2.3") || npmSpecIsLocal("1.x") || npmSpecIsLocal("latest") || npmSpecIsLocal(">=1 <2") || npmSpecIsLocal("~1.2.3 || ^2") || npmSpecIsLocal("*") || npmSpecIsLocal("") {
		t.Error("a registry specifier was taken for a local one")
	}
}

func uvLockOf(aVersion, aDeps, packages string) string {
	return `version = 1
revision = 5
requires-python = ">=3.9"

[[package]]
name = "p"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "a" },
]

[package.metadata]
requires-dist = [{ name = "a" }]

[[package]]
name = "a"
version = "` + aVersion + `"
source = { registry = "https://pypi.org/simple" }
` + aDeps + `sdist = { url = "https://files.pythonhosted.org/packages/aa/a-` + aVersion + `.tar.gz", hash = "sha256:` + strings.Repeat("a", 64) + `" }
` + packages
}

func TestUvDependencyOnALocalSourceIsRefused(t *testing.T) {
	b := `
[[package]]
name = "b"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/bb/b-1.0.0.tar.gz", hash = "sha256:` + strings.Repeat("b", 64) + `" }
`
	local := `
[[package]]
name = "b"
version = "1.0.0"
source = { directory = "../b" }
`
	before := uvLockOf("1.0.0", "dependencies = [\n    { name = \"b\" },\n]\n", b)
	t.Run("the registry source stays", func(t *testing.T) {
		after := uvLockOf("1.0.1", "dependencies = [\n    { name = \"b\" },\n]\n", b)
		if reason, detail := diffOf(t, ManagerUv, before, after, "a"); reason != "" && reason != ReasonUnexplainedDiff {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	for name, src := range map[string]string{
		"a directory": `{ directory = "../b" }`,
		"a path":      `{ path = "../b.whl" }`,
		"editable":    `{ editable = "../b" }`,
		"git":         `{ git = "https://example.com/b.git" }`,
		"url":         `{ url = "https://example.com/b.tgz" }`,
	} {
		t.Run(name, func(t *testing.T) {
			after := uvLockOf("1.0.1", "dependencies = [\n    { name = \"b\", source = "+src+" },\n]\n", local)
			reason, _ := diffOf(t, ManagerUv, before, after, "a")
			if reason != ReasonResolvedSourceChanged {
				t.Errorf("reason = %s", reason)
			}
		})
	}
	t.Run("the original already had it", func(t *testing.T) {
		dep := "dependencies = [\n    { name = \"b\", source = { directory = \"../b\" } },\n]\n"
		bb := uvLockOf("1.0.0", dep, local)
		after := uvLockOf("1.0.1", dep, local)
		if reason, _ := diffOf(t, ManagerUv, bb, after, "a"); reason == ReasonResolvedSourceChanged {
			t.Error("a reference the original had was refused")
		}
	})
}

// --- an optional peer that only peerDependenciesMeta lists ---

func TestPnpmOptionalPeerOnlyInTheMetaCountsEverywhere(t *testing.T) {
	lock := func(ver, integrity, extraPkg, snapDeps, extraSnap string) string {
		return `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      minimist:
        specifier: ^1.2.5
        version: ` + ver + `

packages:

  minimist@` + ver + `:
    resolution: {integrity: ` + integrity + `}
` + extraPkg + `
snapshots:

  minimist@` + ver + `:
` + snapDeps + extraSnap
	}
	files := map[string]string{
		"package.json":   `{"name":"a","version":"1.0.0","dependencies":{"minimist":"^1.2.5"}}`,
		"pnpm-lock.yaml": lock("1.2.5", "sha512-aaa", "", "    {}\n", ""),
	}
	files["pnpm-lock.yaml"] = strings.Replace(files["pnpm-lock.yaml"], "minimist@1.2.5:\n    {}\n", "minimist@1.2.5: {}\n", 1)
	item := itemFor(t, ManagerPnpm, files, minimistGroup())
	if item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not a candidate: %s %s", item.Category, item.Detail)
	}
	after := lock("1.2.8", "sha512-bbb", `    peerDependencies:
      opt: '*'
    peerDependenciesMeta:
      opt:
        optional: true

  opt@1.0.0:
    resolution: {integrity: sha512-ooo}
`, "    dependencies:\n      opt: 1.0.0\n", "\n  opt@1.0.0: {}\n")
	setup := func(t *testing.T, declare func(d *NpmDist)) *harness {
		h := newHarness(t, "pnpm")
		h.files, h.item = files, item
		h.gh = ghFor(files)
		h.cfg.GitHub = h.gh
		h.after = []byte(after)
		d := NpmDist{Tarball: minimist128.Tarball, Integrity: "sha512-bbb", Install: map[string]string{"peerDependenciesMeta": "opt"}}
		if declare != nil {
			declare(&d)
		}
		h.npm.dists["minimist@1.2.8"] = d
		h.npm.dists["opt@1.0.0"] = NpmDist{Tarball: "https://registry.npmjs.org/opt/-/opt-1.0.0.tgz", Integrity: "sha512-ooo"}
		return h
	}
	t.Run("pnpm's record of an optional peer is accepted", func(t *testing.T) {
		it, _ := setup(t, nil).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the range the parent states for it is any", func(t *testing.T) {
		d := NpmDist{Install: map[string]string{"peerDependenciesMeta": "opt"}}
		if got := d.peersFor(ManagerPnpm); got["opt"] != "*" || len(got) != 1 {
			t.Errorf("pnpm: %v", got)
		}
		if got := d.peersFor(ManagerNpm); len(got) != 0 {
			t.Errorf("npm: %v", got)
		}
		d.PeerDependencies = map[string]string{"opt": ">=2"}
		if got := d.peersFor(ManagerPnpm); got["opt"] != ">=2" {
			t.Errorf("a listed range: %v", got)
		}
		if len(d.PeerDependencies) != 1 {
			t.Error("the registry's map was changed")
		}
	})
	t.Run("a dependency the registry does not list at all is still refused", func(t *testing.T) {
		h := setup(t, func(d *NpmDist) { d.Install = map[string]string{} })
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

// --- the exception is for an occurrence that was installed before ---

func TestLocalReferenceOfAnUnreachedSnapshotDoesNotVouchForAReachedOne(t *testing.T) {
	// esbuild 0.25.0 is in the file but nothing requires it; it points its
	// platform package at a local directory. esbuild 0.24.0 is the installed one.
	lock := func(importerVersion, _ string, snapshots []string) string {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      esbuild:\n        specifier: '>=0.24.0'\n        version: " + importerVersion + "\n\npackages:\n")
		// Every snapshot has its package.
		for _, s := range snapshots {
			key := strings.TrimSpace(strings.SplitN(s, ":\n", 2)[0])
			key = strings.TrimSuffix(key, ": {}")
			b.WriteString("\n  " + key + ":\n    resolution: {integrity: sha512-" + strings.Map(func(r rune) rune {
				if r == '@' || r == '/' || r == '\'' {
					return -1
				}
				return r
			}, key) + "}\n")
		}
		b.WriteString("\nsnapshots:\n")
		for _, s := range snapshots {
			b.WriteString("\n" + s)
		}
		return b.String()
	}
	snap := func(name, platform string) string {
		return "  " + name + ":\n    optionalDependencies:\n      '@esbuild/linux-x64': " + platform + "\n"
	}
	plain240 := "  '@esbuild/linux-x64@0.24.0': {}\n"
	plain251 := "  '@esbuild/linux-x64@0.25.1': {}\n"
	before := lock("0.24.0", "", []string{snap("esbuild@0.24.0", "0.24.0"), plain240, snap("esbuild@0.25.0", "link:vendor/replacement")})
	t.Run("the original is well-formed", func(t *testing.T) {
		if _, err := buildGraph(bg, ManagerPnpm, []byte(before)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the link moves from the unreached snapshot to the reached update", func(t *testing.T) {
		after := lock("0.25.1", "", []string{snap("esbuild@0.25.1", "link:vendor/replacement"), snap("esbuild@0.25.0", "link:vendor/replacement")})
		reason, detail := diffOf(t, ManagerPnpm, before, after, "esbuild")
		if reason != ReasonResolvedSourceChanged || !strings.Contains(detail, "link:vendor/replacement") {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	t.Run("the update takes the registry package instead", func(t *testing.T) {
		after := lock("0.25.1", "", []string{snap("esbuild@0.25.1", "0.25.1"), plain251, snap("esbuild@0.25.0", "link:vendor/replacement")})
		if reason, detail := diffOf(t, ManagerPnpm, before, after, "esbuild"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	t.Run("the installed one had the link, so the update keeps it", func(t *testing.T) {
		withLink := lock("0.24.0", "", []string{snap("esbuild@0.24.0", "link:vendor/replacement")})
		after := lock("0.25.1", "", []string{snap("esbuild@0.25.1", "link:vendor/replacement")})
		if reason, detail := diffOf(t, ManagerPnpm, withLink, after, "esbuild"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	t.Run("another package's link does not vouch for it", func(t *testing.T) {
		other := lock("0.24.0", "", []string{snap("esbuild@0.24.0", "0.24.0"), plain240})
		other = strings.Replace(other, "snapshots:\n", "snapshots:\n\n  other@1.0.0:\n    optionalDependencies:\n      '@esbuild/linux-x64': link:vendor/replacement\n", 1)
		after := lock("0.25.1", "", []string{snap("esbuild@0.25.1", "link:vendor/replacement")})
		if reason, _ := diffOf(t, ManagerPnpm, other, after, "esbuild"); reason != ReasonResolvedSourceChanged {
			t.Errorf("reason = %s", reason)
		}
	})
}

func TestNpmLocalReferenceOfAnUnreachedEntryDoesNotVouchForAReachedOne(t *testing.T) {
	entry := func(path, ver, deps string) string {
		return `,"` + path + `":{"version":"` + ver + `","resolved":"https://registry.npmjs.org/x/-/x-` + ver + `.tgz","integrity":"sha512-` + ver + `"` + deps + `}`
	}
	// Nothing reaches node_modules/x/node_modules/old, which links its optional
	// dependency to a local directory.
	before := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"x":"^1.0.0"}}` +
		entry("node_modules/x", "1.0.0", `,"optionalDependencies":{"y":"^1.0.0"}`) +
		entry("node_modules/y", "1.0.0", "") +
		entry("node_modules/z", "1.0.0", `,"optionalDependencies":{"y":"file:vendor/y"}`) + `}}`
	after := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"x":"^1.0.0"}}` +
		entry("node_modules/x", "1.0.1", `,"optionalDependencies":{"y":"file:vendor/y"}`) +
		entry("node_modules/z", "1.0.0", `,"optionalDependencies":{"y":"file:vendor/y"}`) + `}}`
	reason, detail := diffOf(t, ManagerNpm, before, after, "x")
	if reason != ReasonResolvedSourceChanged || !strings.Contains(detail, "file:vendor/y") {
		t.Errorf("%s: %s", reason, detail)
	}
}

// --- the comparison of two graphs does not rehash long keys per requirement ---

func TestComparingGraphsWithLongKeysIsNotProportionalToTheirProduct(t *testing.T) {
	const owners, perOwner, keyLen = 100, 3000, 4000
	build := func(version string) *depGraph {
		g := &depGraph{nodes: map[string]*depNode{}}
		keys := make([]string, owners)
		for i := range keys {
			keys[i] = fmt.Sprintf("%0*d", keyLen, i)
		}
		for i, k := range keys {
			n := &depNode{name: fmt.Sprintf("p%d", i), version: version}
			for j := 0; j < perOwner; j++ {
				n.deps = append(n.deps, depEdge{name: fmt.Sprintf("d%d", j), key: keys[(i+j+1)%owners], ref: "^1.0.0"})
			}
			n.deps = append(n.deps, depEdge{name: "missing", optional: true, ref: "^1"})
			g.nodes[k] = n
			g.roots = append(g.roots, depEdge{name: n.name, key: k})
		}
		return g
	}
	before, after := build("1.0.0"), build("1.0.1")
	start := time.Now()
	un := newUnresolvedCtx(bg, before, after)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("unresolved took %v", d)
	}
	if len(un) != 0 {
		t.Errorf("unresolved = %d", len(un))
	}
	start = time.Now()
	if why := newNonRegistryEdge(bg, before, after); why != "" {
		t.Errorf("non-registry: %s", why)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("non-registry took %v", d)
	}
	start = time.Now()
	reach := after.reach(bg, rootKeys(after.roots), nil)
	if len(reach) != owners {
		t.Errorf("reach = %d", len(reach))
	}
	for _, n := range after.nodes {
		edgeSig(after, n.deps, map[string]bool{})
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("reach and signatures took %v", d)
	}
	// A time that is over stops the walks.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	newUnresolvedCtx(ctx, before, after)
	if why := newNonRegistryEdge(ctx, before, after); why != "" {
		t.Errorf("canceled: %s", why)
	}
	if r, _ := checkUnresolvedCtx(ctx, before, after); r != "" {
		t.Errorf("canceled: %s", r)
	}
}

func TestGraphNamesAreBoundedBeforeTheGraphIsBuilt(t *testing.T) {
	long := strings.Repeat("n", maxGraphNameBytes+1)
	if _, err := buildGraph(bg, ManagerNpm, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"`+long+`":"1"}}}}`)); err == nil {
		t.Error("npm: a dependency name over the bound")
	}
	if _, err := buildGraph(bg, ManagerNpm, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"p"},"node_modules/`+long+`":{"version":"1.0.0"}}}`)); err == nil {
		t.Error("npm: a package name over the bound")
	}
	if _, err := buildGraph(bg, ManagerNpm, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"p"},"node_modules/a":{"version":"`+strings.Repeat("1", maxGraphNameBytes+1)+`"}}}`)); err == nil {
		t.Error("npm: a version over the bound")
	}
	pn := "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-a}\n\nsnapshots:\n\n  a@1.0.0:\n    dependencies:\n      " + long + ": 1.0.0\n"
	if _, err := buildGraph(bg, ManagerPnpm, []byte(pn)); err == nil {
		t.Error("pnpm: a dependency name over the bound")
	}
	if _, err := buildGraph(bg, ManagerPnpm, []byte(strings.ReplaceAll(strings.ReplaceAll(pn, "      "+long+": 1.0.0\n", ""), "a@1.0.0", long+"@1.0.0"))); err == nil {
		t.Error("pnpm: a package name over the bound")
	}
	// Names at the bound are fine.
	ok := strings.Repeat("n", maxGraphNameBytes)
	if _, err := buildGraph(bg, ManagerNpm, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"p"},"node_modules/`+ok+`":{"version":"1.0.0"}}}`)); err != nil {
		t.Errorf("a name at the bound: %v", err)
	}
}

// --- the exception needs the very same non-registry occurrence ---

func TestRegistryRequirementDoesNotVouchForANonRegistryOne(t *testing.T) {
	entry := func(path, ver, resolved, deps string) string {
		return `,"` + path + `":{"version":"` + ver + `","resolved":"` + resolved + `","integrity":"sha512-` + ver + `"` + deps + `}`
	}
	reg := func(name, ver string) string {
		return "https://registry.npmjs.org/" + name + "/-/" + name + "-" + ver + ".tgz"
	}
	before := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"a":"^1.0.0"}}` +
		entry("node_modules/a", "1.0.0", reg("a", "1.0.0"), `,"dependencies":{"x":"^1"}`) +
		entry("node_modules/a/node_modules/x", "1.0.0", reg("x", "1.0.0"), "") + `}}`
	after := func(xResolved string) string {
		return `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"a":"^1.0.0"}}` +
			entry("node_modules/a", "1.0.1", reg("a", "1.0.1"), `,"dependencies":{"x":"^1"}`) +
			entry("node_modules/x", "1.0.0", xResolved, "") + `}}`
	}
	t.Run("the same version from the registry stays", func(t *testing.T) {
		if reason, detail := diffOf(t, ManagerNpm, before, after(reg("x", "1.0.0")), "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	for name, resolved := range map[string]string{
		"a tarball from another host": "https://evil.example/x/-/x-1.0.0.tgz",
		"a file":                      "file:../x",
		"plain http":                  "http://registry.npmjs.org/x/-/x-1.0.0.tgz",
	} {
		t.Run(name, func(t *testing.T) {
			reason, _ := diffOf(t, ManagerNpm, before, after(resolved), "a")
			if reason != ReasonResolvedSourceChanged && reason != ReasonUnexplainedDiff {
				t.Errorf("reason = %q", reason)
			}
		})
	}
	// An entry that was not a registry package before and is the same one now.
	evil := "https://evil.example/x/-/x-1.0.0.tgz"
	bad := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"a":"^1.0.0"}}` +
		entry("node_modules/a", "1.0.0", reg("a", "1.0.0"), `,"dependencies":{"x":"^1"}`) +
		entry("node_modules/x", "1.0.0", evil, "") + `}}`
	t.Run("the same non-registry entry stays", func(t *testing.T) {
		if reason, detail := diffOf(t, ManagerNpm, bad, after(evil), "a"); reason != "" {
			t.Errorf("%s: %s", reason, detail)
		}
	})
	t.Run("another non-registry location is not the same entry", func(t *testing.T) {
		reason, _ := diffOf(t, ManagerNpm, bad, after("https://evil.example/other/-/x-1.0.0.tgz"), "a")
		if reason != ReasonResolvedSourceChanged && reason != ReasonUnexplainedDiff {
			t.Errorf("reason = %q", reason)
		}
	})
}

// --- every name of a graph is within the bound, whatever way it was found ---

func TestEveryGraphBuilderBoundsTheNamesItAssigns(t *testing.T) {
	long := strings.Repeat("n", 1<<20)
	t.Run("npm: the name of an aliased entry", func(t *testing.T) {
		lock := `{"lockfileVersion":3,"packages":{"":{"name":"p"},"node_modules/a":{"name":"` + long + `","version":"1.0.0"}}}`
		if _, err := buildGraph(bg, ManagerNpm, []byte(lock)); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("npm: an alias name at the bound", func(t *testing.T) {
		lock := `{"lockfileVersion":3,"packages":{"":{"name":"p"},"node_modules/a":{"name":"` + strings.Repeat("n", maxGraphNameBytes) + `","version":"1.0.0"}}}`
		if _, err := buildGraph(bg, ManagerNpm, []byte(lock)); err != nil {
			t.Errorf("refused: %v", err)
		}
	})
	t.Run("the final check covers names however they got there", func(t *testing.T) {
		mk := func(edit func(g *depGraph)) error {
			g := &depGraph{nodes: map[string]*depNode{"k": {name: "a", version: "1", deps: []depEdge{{name: "b"}}}}, roots: []depEdge{{name: "a", key: "k"}}}
			edit(g)
			return g.checkBounds()
		}
		if err := mk(func(*depGraph) {}); err != nil {
			t.Fatal(err)
		}
		for name, edit := range map[string]func(g *depGraph){
			"a node name":    func(g *depGraph) { g.nodes["k"].name = long },
			"a node version": func(g *depGraph) { g.nodes["k"].version = long },
			"a dependency":   func(g *depGraph) { g.nodes["k"].deps[0].name = long },
			"a root":         func(g *depGraph) { g.roots[0].name = long },
		} {
			if err := mk(edit); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
	t.Run("pnpm: the package key and a dependency", func(t *testing.T) {
		lock := "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-a}\n\nsnapshots:\n\n  a@1.0.0:\n    dependencies:\n      " + long + ": 1.0.0\n"
		if _, err := buildGraph(bg, ManagerPnpm, []byte(lock)); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("uv: the name of a dependency", func(t *testing.T) {
		lock := uvLockOf("1.0.0", "dependencies = [\n    { name = \""+long+"\" },\n]\n", "")
		if _, err := buildGraph(bg, ManagerUv, []byte(lock)); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("pip: the name of an installed package", func(t *testing.T) {
		report := `{"version":"1","pip_version":"26.2.1","environment":{},"install":[{"download_info":{"url":"https://files.pythonhosted.org/packages/x/` + long[:300] + `-1.0-py3-none-any.whl","archive_info":{"hashes":{"sha256":"` + strings.Repeat("a", 64) + `"}}},"is_direct":false,"is_yanked":false,"requested":true,"metadata":{"name":"` + long[:300] + `","version":"1.0"}}]}`
		if _, err := pipGraph(bg, []byte(report), nil, nil); err == nil {
			t.Error("accepted")
		}
	})
}

// --- what snapshots share is hashed once ---

func TestSnapshotsOfOnePackageShareOneDigestOfItsDistribution(t *testing.T) {
	const snapshots = 20000
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0(p0@1.0.0)\n\npackages:\n\n  a@1.0.0:\n    resolution: {tarball: https://example.com/a.tgz, integrity: sha512-")
	b.WriteString(strings.Repeat("A", 1<<20))
	b.WriteString("}\n\nsnapshots:\n")
	for i := 0; i < snapshots; i++ {
		fmt.Fprintf(&b, "\n  a@1.0.0(p%d@1.0.0): {}\n", i)
	}
	lock := b.String()
	start := time.Now()
	g, err := buildGraph(bg, ManagerPnpm, []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("building the graph took %v", d)
	}
	var first *depNode
	for _, n := range g.nodes {
		if n.problem == "" {
			t.Fatal("the entry with a tarball resolution is taken for a registry package")
		}
		if first == nil {
			first = n
		}
		if n.distDigest == "" || n.distDigest != first.distDigest {
			t.Fatalf("the snapshots of one package do not share a digest: %q", n.distDigest)
		}
		if len(n.pid) != 16 {
			t.Fatalf("pid = %d bytes", len(n.pid))
		}
	}
	if len(g.nodes) != snapshots {
		t.Errorf("nodes = %d", len(g.nodes))
	}
	// Two different packages with the same name and version differ in their pid.
	other := strings.Replace(lock, "sha512-A", "sha512-B", 1)
	g2, err := buildGraph(bg, ManagerPnpm, []byte(other))
	if err != nil {
		t.Fatal(err)
	}
	var n2 *depNode
	for _, n := range g2.nodes {
		n2 = n
		break
	}
	if n2.distDigest == first.distDigest {
		t.Error("another distribution has the same digest")
	}
}

func TestLinkingWatchesTheDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lock := "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-a}\n\nsnapshots:\n\n  a@1.0.0: {}\n"
	if _, err := buildGraph(ctx, ManagerPnpm, []byte(lock)); err == nil {
		t.Error("a graph was built after the deadline")
	}
	g := &depGraph{nodes: map[string]*depNode{"k": {name: "a"}}}
	if err := g.linkCtx(ctx); err == nil || g.linked {
		t.Errorf("linked = %v, err = %v", g.linked, err)
	}
	if err := g.linkCtx(context.Background()); err != nil || !g.linked {
		t.Errorf("linked = %v, err = %v", g.linked, err)
	}
}

// --- the nested registry entry is removed and a fallback outside takes its place ---

func TestRemovingTheNestedRegistryEntryDoesNotSwitchToAFallbackThatWasThere(t *testing.T) {
	entry := func(path, ver, resolved, deps string) string {
		return `,"` + path + `":{"version":"` + ver + `","resolved":"` + resolved + `","integrity":"sha512-` + ver + `"` + deps + `}`
	}
	reg := func(name, ver string) string {
		return "https://registry.npmjs.org/" + name + "/-/" + name + "-" + ver + ".tgz"
	}
	evil := "https://evil.example/x/-/x-1.0.0.tgz"
	// The original file has two x: the registry one nested under a, which a
	// resolves to, and a non-registry one at the top that nothing requires.
	before := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"a":"^1.0.0"}}` +
		entry("node_modules/a", "1.0.0", reg("a", "1.0.0"), `,"dependencies":{"x":"^1"}`) +
		entry("node_modules/a/node_modules/x", "1.0.0", reg("x", "1.0.0"), "") +
		entry("node_modules/x", "1.0.0", evil, "") + `}}`
	// The update drops the nested entry; a's requirement now finds the other.
	after := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"a":"^1.0.0"}}` +
		entry("node_modules/a", "1.0.1", reg("a", "1.0.1"), `,"dependencies":{"x":"^1"}`) +
		entry("node_modules/x", "1.0.0", evil, "") + `}}`
	reason, detail := diffOf(t, ManagerNpm, before, after, "a")
	if reason != ReasonResolvedSourceChanged && reason != ReasonUnexplainedDiff {
		t.Fatalf("reason = %q (%s)", reason, detail)
	}
	if reason == ReasonResolvedSourceChanged && !strings.Contains(detail, "node_modules/a") {
		t.Errorf("detail = %q", detail)
	}
	// Control: the nested entry stays and the fallback stays unreached.
	same := `{"name":"p","lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"a":"^1.0.0"}}` +
		entry("node_modules/a", "1.0.1", reg("a", "1.0.1"), `,"dependencies":{"x":"^1"}`) +
		entry("node_modules/a/node_modules/x", "1.0.0", reg("x", "1.0.0"), "") +
		entry("node_modules/x", "1.0.0", evil, "") + `}}`
	if reason, detail := diffOf(t, ManagerNpm, before, same, "a"); reason != "" {
		t.Errorf("control: %s: %s", reason, detail)
	}
}
