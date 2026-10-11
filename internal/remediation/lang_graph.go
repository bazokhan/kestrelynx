package remediation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// depNode is one entry of a dependency file: a package version at a place in
// the file, with what the file says about it.
type depNode struct {
	name    string // the matching name: exact for npm and pnpm, PEP 503 for Python
	version string
	// attrs is everything the file records about the entry except which
	// entries it requires: version, source, hashes and its declared
	// requirements. Two entries with the same key and attrs are the same
	// entry.
	attrs string
	deps  []depEdge
	// problem is set when the entry is not fetched from the public registry.
	problem string
	// dist is what the file records about the distribution files of the
	// entry, to be compared with what the registry publishes for the version.
	dist []distRef
	// declared are the names of the dependencies the file records for the
	// entry (declPeers: its peer dependencies, for the formats that record
	// them), to be compared with what the registry says the version declares.
	declared, declPeers []string
	// extraDeps are, for a uv package, the dependency names it records per
	// extra (its optional-dependencies), and otherRecords is set when it has
	// a kind of dependency record a registry package does not have.
	extraDeps    map[string][]string
	otherRecords bool
	// install is the entry's record of the fields that decide whether and how
	// it is installed (see installRecord), installErr says why they could not
	// be read, and unknown lists the members of the entry this program does
	// not know the effect of.
	install    map[string]string
	installErr string
	unknown    []string
	// flags are the booleans the entry records about how it is reached (dev,
	// optional, devOptional, inBundle, extraneous), true ones only.
	flags map[string]bool
	// peerRanges are the peer dependency ranges a pnpm package records.
	peerRanges map[string]string
	// id, key and kid identify the entry once the graph is linked: its number
	// in depGraph.list, its key, and a fixed-size digest of the key to stand
	// for it where keys of different graphs are compared.
	id       int
	key, kid string
	// pid identifies an entry that is not a registry package (see link), and
	// distDigest, when a builder sets it, is a fixed-size digest of what the
	// entry shares with others about its distribution (pnpm: the package record
	// all of a package's snapshots share), so that it is hashed once.
	pid, distDigest string
	// resMarkers are the resolution-markers a uv.lock package carries: the
	// environments (forks) it was resolved for.
	resMarkers []string
}

// distRef is a distribution file as a lockfile records it: its URL (empty
// where the format has none) and its hash in the format's own spelling.
type distRef struct {
	url  string
	hash string
	// kind is "sdist" or "wheel" for a uv file, and empty where the format has
	// one file per entry.
	kind string
}

// maxGraphNameBytes bounds the name and the version of an entry and the name of
// a requirement. Entries are compared by these (and by a digest of their
// keys), so their length bounds the work of comparing two graphs.
const maxGraphNameBytes = 256

func checkGraphName(what, s string) error {
	if len(s) > maxGraphNameBytes {
		return fmt.Errorf("%s %q is over %d bytes", what, clip(s, 40), maxGraphNameBytes)
	}
	return nil
}

// checkBounds requires every entry's name and version and every requirement's
// name to be within maxGraphNameBytes, whichever way the name was found (from a
// path, a key, a member of the entry or a report). Each graph builder ends with
// it, so no graph reaches a comparison with a name over the bound.
func (g *depGraph) checkBounds() error {
	for _, e := range g.roots {
		if err := checkGraphName("a requirement name", e.name); err != nil {
			return err
		}
	}
	for _, n := range g.nodes {
		if err := errors.Join(checkGraphName("a package name", n.name), checkGraphName("a version", n.version)); err != nil {
			return err
		}
		for _, e := range n.deps {
			if err := checkGraphName("a requirement name", e.name); err != nil {
				return err
			}
		}
	}
	return nil
}

// maxUnknownNamed bounds the unrecognized member names kept per entry.
const maxUnknownNamed = 16

// Bounds on a graph. A lockfile or report is output of a tool that cannot be
// trusted, so what is built from it is bounded before it is allocated.
var (
	maxGraphNodes = 50000
	maxGraphEdges = 500000
)

// maxAttrBytes bounds the normalized attributes kept for the entries of a file.
var maxAttrBytes = 96 << 20

// graphBudget counts the edges of a graph under construction and watches the
// deadline.
type graphBudget struct {
	ctx   context.Context
	edges int
	steps int
	bytes int
}

// edges adds n edges, failing when the graph is over its bound or the
// deadline has passed.
func (b *graphBudget) add(n int) error {
	b.edges += n
	if b.edges > maxGraphEdges {
		return fmt.Errorf("the file describes more than %d dependency edges", maxGraphEdges)
	}
	return b.ctx.Err()
}

func checkNodeCount(n int) error {
	if n > maxGraphNodes {
		return fmt.Errorf("the file holds more than %d entries", maxGraphNodes)
	}
	return nil
}

// depEdge is a requirement of a package: the name it asks for and the entry
// of the file that satisfies it ("" when the file has none).
type depEdge struct {
	name string
	key  string
	// optional marks a requirement the format lets stay unresolved: an
	// optional or peer dependency.
	optional bool
	// confirmed is set when the kind (required or optional) is the one the
	// registry declares for the entry, not the one the lockfile's own section
	// says.
	confirmed bool
	// dev marks a requirement of the project that is a development
	// dependency, and soft one that makes what it requires optional (an
	// optional dependency, a peer dependency marked optional).
	dev, soft bool
	// marker is the marker a uv.lock requirement carries ("" for none).
	marker string
	// ref is what the file says the requirement points to (the version of a
	// pnpm dependency, the specifier of an npm one, the source table of a uv
	// one), and local is set when that is not a version from the registry: a
	// link, a file, a workspace, a git or tarball location. A local reference
	// is never resolved to a registry entry, whether or not it has an entry.
	ref   string
	local bool
	// to is the number of the entry the requirement points to (see
	// depGraph.link), -1 when it points to none.
	to int
}

// depGraph is the dependency graph a lockfile (or, for pip, the install
// report) describes.
type depGraph struct {
	nodes map[string]*depNode
	// roots are the requirements of the project itself.
	roots []depEdge
	// list holds the entries by number, and linked says the numbers and the
	// edges' targets are set (see link).
	list   []*depNode
	linked bool
	// meta is the rest of the file that no update may change: its format and
	// version, the project's own entry and its declared requirements.
	meta string
}

// canonicalJSON re-encodes a decoded value with sorted keys, so equal content
// gives equal text.
func canonicalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// decodeJSONValue decodes JSON keeping numbers exact.
func decodeJSONValue(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// --- npm ---

type npmGraphEntry struct {
	// m is the entry as a JSON object, read by exact key.
	m                    map[string]json.RawMessage
	Name                 string
	Version              string
	Resolved             string
	Integrity            string
	Link                 bool
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
}

// npmLockDoc is a package-lock.json read by the exact spelling of its keys.
type npmLockDoc struct {
	version int
	top     map[string]json.RawMessage
	entries map[string]npmGraphEntry
	raws    map[string]json.RawMessage
}

// Bounds on the paths of a package-lock.json, checked before anything is
// built from them.
const (
	maxNpmPathBytes = 4096
	maxNpmPathDepth = 64
)

// readNpmLock reads package-lock.json. Its fixed-word objects (the file, each
// entry) must not repeat a key or have two keys that differ only in case, the
// path of an entry is bounded in length and depth, and the number of entries
// is bounded.
func readNpmLock(data []byte) (*npmLockDoc, error) {
	top, err := strictObject(data)
	if err != nil {
		return nil, fmt.Errorf("package-lock.json cannot be read: %v", err)
	}
	doc := &npmLockDoc{top: top, entries: map[string]npmGraphEntry{}}
	if raw, ok := top["lockfileVersion"]; ok {
		if err := json.Unmarshal(raw, &doc.version); err != nil {
			return nil, fmt.Errorf("package-lock.json has a lockfileVersion that is not a number")
		}
	}
	rawPkgs, ok := top["packages"]
	if !ok {
		return doc, nil
	}
	pkgs, err := nameMap(rawPkgs)
	if err != nil {
		return nil, fmt.Errorf("package-lock.json packages: %v", err)
	}
	if err := checkNodeCount(len(pkgs)); err != nil {
		return nil, err
	}
	doc.raws = pkgs
	for k, raw := range pkgs {
		if len(k) > maxNpmPathBytes || strings.Count(k, npmModules) > maxNpmPathDepth {
			return nil, fmt.Errorf("package-lock.json has an entry path over %d bytes or %d levels", maxNpmPathBytes, maxNpmPathDepth)
		}
		e, err := readNpmEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("package-lock.json entry %q: %v", clip(k, 100), err)
		}
		doc.entries[k] = e
	}
	return doc, nil
}

func readNpmEntry(raw []byte) (npmGraphEntry, error) {
	var e npmGraphEntry
	m, err := strictObject(raw)
	if err != nil {
		return e, err
	}
	e.m = m
	if e.Name, err = optString(m, "name"); err != nil {
		return e, err
	}
	if e.Version, err = optString(m, "version"); err != nil {
		return e, err
	}
	if e.Resolved, err = optString(m, "resolved"); err != nil {
		return e, err
	}
	if e.Integrity, err = optString(m, "integrity"); err != nil {
		return e, err
	}
	if e.Link, err = optBool(m, "link"); err != nil {
		return e, err
	}
	for field, dst := range map[string]*map[string]string{
		"dependencies": &e.Dependencies, "devDependencies": &e.DevDependencies,
		"optionalDependencies": &e.OptionalDependencies, "peerDependencies": &e.PeerDependencies,
	} {
		if *dst, err = optStringMap(m, field); err != nil {
			return e, err
		}
	}
	return e, nil
}

// npmGraph reads a package-lock.json (lockfileVersion 2 or 3) of a single
// project as a graph whose entries are the keys of its packages map.
func npmGraph(ctx context.Context, lock []byte) (*depGraph, error) {
	budget := &graphBudget{ctx: ctx}
	doc, err := readNpmLock(lock)
	if err != nil {
		return nil, err
	}
	if doc.raws == nil {
		return nil, fmt.Errorf("package-lock.json has no packages map")
	}
	rootRaw, ok := doc.raws[""]
	if !ok {
		return nil, fmt.Errorf("package-lock.json has no root entry")
	}
	g := &depGraph{nodes: map[string]*depNode{}}

	rest := map[string]any{}
	for k, raw := range doc.top {
		// The legacy tree of a lockfileVersion 2 file repeats the entries of
		// packages; the updated packages' part of it is compared with them
		// separately.
		if k == "packages" || (k == "dependencies" && doc.version == 2) {
			continue
		}
		v, err := decodeJSONValue(raw)
		if err != nil {
			return nil, err
		}
		rest[k] = v
	}
	rootVal, err := decodeJSONValue(rootRaw)
	if err != nil {
		return nil, err
	}
	rest["\x00root"] = rootVal
	if g.meta, err = canonicalJSON(rest); err != nil {
		return nil, err
	}

	entries := doc.entries
	for k, raw := range doc.raws {
		if k == "" {
			continue
		}
		if err := budget.ctx.Err(); err != nil {
			return nil, err
		}
		e := entries[k]
		val, err := decodeJSONValue(raw)
		if err != nil {
			return nil, err
		}
		attrs, err := canonicalJSON(val)
		if err != nil {
			return nil, err
		}
		pathName := k[strings.LastIndex(k, npmModules)+len(npmModules):]
		if err := errors.Join(checkGraphName("a package name", pathName), checkGraphName("a version", e.Version)); err != nil {
			return nil, err
		}
		n := &depNode{name: pathName, version: e.Version, attrs: attrs, dist: []distRef{{url: e.Resolved, hash: e.Integrity}}}
		n.unknown = unknownKeys(e.m, npmEntryKeys)
		rec, rerr := installRecord(e.m, pathName, e.Dependencies, "bundleDependencies")
		n.install = rec
		n.flags = map[string]bool{}
		for _, f := range []string{"dev", "optional", "devOptional", "inBundle", "extraneous", "hasShrinkwrap"} {
			b, ferr := optBool(e.m, f)
			if ferr != nil && rerr == nil {
				rerr = ferr
			}
			if b {
				n.flags[f] = true
			}
		}
		if rerr != nil {
			n.installErr = rerr.Error()
		}
		optPeers := stringSet(strings.Split(rec["peerDependenciesMeta"], ","))
		switch {
		case e.Name != "" && e.Name != pathName:
			if err := checkGraphName("an alias target name", e.Name); err != nil {
				return nil, err
			}
			n.name = e.Name
			n.problem = "installed under an alias name"
		case e.Link:
			n.problem = "a link to a local directory"
		default:
			n.problem = npmSourceProblem(e.Resolved)
		}
		for i, m := range []map[string]string{e.Dependencies, e.OptionalDependencies, e.PeerDependencies} {
			if err := budget.add(len(m)); err != nil {
				return nil, err
			}
			for dep, spec := range m {
				if err := checkGraphName("a dependency name", dep); err != nil {
					return nil, err
				}
				key, err := budget.resolve(entries, k, dep)
				if err != nil {
					return nil, err
				}
				n.deps = append(n.deps, depEdge{name: dep, key: key, optional: i > 0, soft: i == 1 || (i == 2 && optPeers[dep]), ref: spec, local: npmSpecIsLocal(spec)})
			}
		}
		n.declared = depNames(e.Dependencies, e.OptionalDependencies)
		n.declPeers = depNames(e.PeerDependencies)
		n.peerRanges = e.PeerDependencies
		sortEdges(n.deps)
		g.nodes[k] = n
	}
	root := entries[""]
	rootPeers := map[string]bool{}
	if rrec, rerr := installRecord(root.m, "", root.Dependencies); rerr == nil {
		rootPeers = stringSet(strings.Split(rrec["peerDependenciesMeta"], ","))
	}
	for i, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
		if err := budget.add(len(m)); err != nil {
			return nil, err
		}
		for dep, spec := range m {
			if err := checkGraphName("a dependency name", dep); err != nil {
				return nil, err
			}
			key, err := budget.resolve(entries, "", dep)
			if err != nil {
				return nil, err
			}
			g.roots = append(g.roots, depEdge{name: dep, key: key, optional: i >= 2, dev: i == 1, soft: i == 2 || (i == 3 && rootPeers[dep]), ref: spec, local: npmSpecIsLocal(spec)})
		}
	}
	sortEdges(g.roots)
	if err := g.checkBounds(); err != nil {
		return nil, err
	}
	return g, nil
}

// npmEntriesOf reads the entries of package-lock.json by path ("" is the
// root).
func npmEntriesOf(lock []byte) (map[string]npmGraphEntry, error) {
	doc, err := readNpmLock(lock)
	if err != nil {
		return nil, err
	}
	if doc.raws == nil {
		return nil, fmt.Errorf("package-lock.json has no packages map")
	}
	return doc.entries, nil
}

// maxResolveSteps bounds the work of finding where requirements resolve in
// one file: each step is one lookup along the way up from a package.
var (
	maxResolveSteps = 4000000
	// maxResolveBytes bounds the length of all the candidate paths built while
	// resolving, the real cost of a step on a long path.
	maxResolveBytes = 256 << 20
)

// resolve finds the entry that satisfies a requirement of the package at path
// from the way node_modules is searched: the package's own node_modules, then
// those of each ancestor, up to the top. It counts its steps against the
// budget and watches the deadline.
func (b *graphBudget) resolve(entries map[string]npmGraphEntry, from, dep string) (string, error) {
	for p := from; ; {
		if b.steps++; b.steps > maxResolveSteps {
			return "", fmt.Errorf("resolving the requirements of the file takes more than %d steps", maxResolveSteps)
		}
		if b.steps%1024 == 0 {
			if err := b.ctx.Err(); err != nil {
				return "", err
			}
		}
		cand := npmModules + dep
		if p != "" {
			cand = p + "/" + npmModules + dep
		}
		if b.bytes += len(cand); b.bytes > maxResolveBytes {
			return "", fmt.Errorf("resolving the requirements of the file builds more than %d bytes of paths", maxResolveBytes)
		}
		if _, ok := entries[cand]; ok {
			return cand, nil
		}
		if p == "" {
			return "", nil
		}
		i := strings.LastIndex(p, npmModules)
		if i <= 0 {
			p = ""
		} else {
			p = p[:i-1]
		}
	}
}

// depNames returns the distinct keys of the maps, sorted.
func depNames(ms ...map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func sortEdges(es []depEdge) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].name != es[j].name {
			return es[i].name < es[j].name
		}
		return es[i].key < es[j].key
	})
}

// --- pnpm ---

// pnpmGraph reads a pnpm-lock.yaml (lockfileVersion '9.0') of a single
// project as a graph whose entries are its snapshots.
func pnpmGraph(ctx context.Context, lock []byte) (*depGraph, error) {
	budget := &graphBudget{ctx: ctx}
	ydoc, err := readPnpmLock(lock)
	if err != nil {
		return nil, fmt.Errorf("pnpm-lock.yaml cannot be read: %v", err)
	}
	top := ydoc.top
	packages, _ := top["packages"].(map[string]any)
	snapshots, _ := top["snapshots"].(map[string]any)
	importers, _ := top["importers"].(map[string]any)
	if err := checkNodeCount(len(packages) + len(snapshots)); err != nil {
		return nil, err
	}
	imp, _ := importers["."].(map[string]any)
	if imp == nil {
		return nil, fmt.Errorf("pnpm-lock.yaml has no importer \".\"")
	}
	g := &depGraph{nodes: map[string]*depNode{}}

	rest := map[string]any{}
	for k, v := range top {
		if k != "packages" && k != "snapshots" && k != "importers" {
			rest[k] = v
		}
	}
	// Of the importer only the declared specifiers count; the versions chosen
	// are compared as graph edges.
	impMeta := map[string]any{}
	groups := []string{"dependencies", "devDependencies", "optionalDependencies"}
	for k, v := range imp {
		if contains(groups, k) {
			continue
		}
		impMeta[k] = v
	}
	for _, grp := range groups {
		deps, _ := imp[grp].(map[string]any)
		if err := budget.add(len(deps)); err != nil {
			return nil, err
		}
		specs := map[string]any{}
		for name, d := range deps {
			if err := checkGraphName("a dependency name", name); err != nil {
				return nil, err
			}
			dm, _ := d.(map[string]any)
			specs[name] = dm["specifier"]
			ver, _ := dm["version"].(string)
			g.roots = append(g.roots, depEdge{name: name, key: pnpmEdgeKey(snapshots, packages, name, ver), optional: grp == "optionalDependencies", soft: grp == "optionalDependencies", dev: grp == "devDependencies", ref: ver, local: pnpmLocalRef(ver)})
		}
		if len(specs) > 0 {
			impMeta[grp] = specs
		}
	}
	sortEdges(g.roots)
	rest["\x00importer"] = impMeta
	if g.meta, err = canonicalJSON(rest); err != nil {
		return nil, fmt.Errorf("pnpm-lock.yaml has content that cannot be compared: %v", err)
	}

	pkHashes := map[string]string{}
	type installRec struct {
		rec, peers map[string]string
		err        string
	}
	installRecs := map[string]installRec{}
	pkUnknown := map[string][]string{}
	attrBytes := 0
	add := func(key string, snap map[string]any) error {
		base := pnpmBase(key)
		name, ver, ok := splitPnpmKey(base)
		if !ok {
			return fmt.Errorf("pnpm-lock.yaml has the key %q", clip(key, 100))
		}
		if err := errors.Join(checkGraphName("a package name", name), checkGraphName("a version", ver)); err != nil {
			return err
		}
		pk, _ := packages[base].(map[string]any)
		res, _ := pk["resolution"].(map[string]any)
		own := map[string]any{}
		for k, v := range snap {
			if k != "dependencies" && k != "optionalDependencies" {
				own[k] = v
			}
		}
		// The metadata of a package is shared by all its snapshots (one per
		// peer context): it is normalized once and the snapshots carry its hash.
		pkHash, seen := pkHashes[base]
		if !seen {
			canon, err := canonicalJSON(pk)
			if err != nil {
				return fmt.Errorf("pnpm-lock.yaml has content that cannot be compared: %v", err)
			}
			if attrBytes += len(canon); attrBytes > maxAttrBytes {
				return fmt.Errorf("the file holds more than %d bytes of package attributes", maxAttrBytes)
			}
			sum := sha256.Sum256([]byte(canon))
			pkHash = hex.EncodeToString(sum[:])
			pkHashes[base] = pkHash
		}
		ownCanon, err := canonicalJSON(own)
		if err != nil {
			return fmt.Errorf("pnpm-lock.yaml has content that cannot be compared: %v", err)
		}
		if attrBytes += len(ownCanon); attrBytes > maxAttrBytes {
			return fmt.Errorf("the file holds more than %d bytes of package attributes", maxAttrBytes)
		}
		attrs := pkHash + "|" + ownCanon
		integrity, _ := res["integrity"].(string)
		n := &depNode{name: name, version: ver, attrs: attrs, dist: []distRef{{hash: integrity}}, distDigest: pkHash}
		ir, seenIR := installRecs[base]
		if !seenIR {
			ir.rec, ir.peers, ir.err = pnpmInstallRecord(pk, name)
			installRecs[base] = ir
		}
		n.install, n.peerRanges, n.installErr = ir.rec, ir.peers, ir.err
		n.flags = map[string]bool{}
		if gstr(snap["optional"]) == "true" {
			n.flags["optional"] = true
		}
		// The members of a package outside the format are listed once per
		// package and shared by its snapshots; a list is capped so that a
		// package with many members cannot grow with the snapshot count.
		pu, seenPU := pkUnknown[base]
		if !seenPU {
			for k := range pk {
				if !pnpmPackageKeys[k] {
					pu = append(pu, k)
				}
			}
			for k := range res {
				if k != "integrity" {
					pu = append(pu, "resolution."+k)
				}
			}
			sort.Strings(pu)
			if len(pu) > maxUnknownNamed {
				pu = pu[:maxUnknownNamed]
			}
			pkUnknown[base] = pu
		}
		n.unknown = pu
		var su []string
		for k := range snap {
			if !pnpmSnapshotKeys[k] {
				su = append(su, "snapshot."+k)
			}
		}
		if len(su) > 0 {
			sort.Strings(su)
			if len(su) > maxUnknownNamed {
				su = su[:maxUnknownNamed]
			}
			n.unknown = append(append(make([]string, 0, len(pu)+len(su)), pu...), su...)
			sort.Strings(n.unknown)
		}
		switch {
		case pk["id"] != nil || pk["patched"] != nil || pk["name"] != nil || pk["version"] != nil || pk["prepare"] != nil:
			n.problem = "recorded as other than a plain registry package (id, patched, name, version or prepare)"
		case pnpmNonRegistryVersion(ver):
			n.problem = "required as " + pnpmBase(ver)
		case res["tarball"] != nil || res["directory"] != nil || res["type"] != nil:
			n.problem = "not resolved from the registry by integrity"
		case integrity == "":
			n.problem = "no integrity in its resolution"
		}
		for _, grp := range []string{"dependencies", "optionalDependencies"} {
			deps, _ := snap[grp].(map[string]any)
			if err := budget.add(len(deps)); err != nil {
				return err
			}
			for dn, dv := range deps {
				if err := checkGraphName("a dependency name", dn); err != nil {
					return err
				}
				v, _ := dv.(string)
				n.deps = append(n.deps, depEdge{name: dn, key: pnpmEdgeKey(snapshots, packages, dn, v), optional: grp == "optionalDependencies", soft: grp == "optionalDependencies", ref: v, local: pnpmLocalRef(v)})
				n.declared = append(n.declared, dn)
			}
		}
		sort.Strings(n.declared)
		sortEdges(n.deps)
		g.nodes[key] = n
		return nil
	}
	for key, v := range snapshots {
		snap, _ := v.(map[string]any)
		if err := add(key, snap); err != nil {
			return nil, err
		}
	}
	// lockfileVersion 9 lists every package in snapshots as well (once per peer
	// context, under a key that may carry a suffix); a package without one has
	// no recorded dependencies to compare.
	hasSnapshot := make(map[string]bool, len(snapshots))
	for key := range snapshots {
		hasSnapshot[pnpmBase(key)] = true
	}
	for key := range packages {
		if !hasSnapshot[key] {
			return nil, fmt.Errorf("pnpm-lock.yaml lists the package %q without a snapshot", clip(key, 100))
		}
	}
	if err := g.checkBounds(); err != nil {
		return nil, err
	}
	return g, nil
}

// pnpmLocalRef reports whether the value of a pnpm dependency is not a version
// from the registry: a link, file or workspace reference, a git or tarball
// location (anything with a scheme), or nothing at all.
func pnpmLocalRef(ver string) bool {
	return ver == "" || strings.Contains(pnpmBase(ver), ":")
}

var npmShorthandRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.#/-]+$`)

// npmSpecIsLocal reports whether an npm dependency specifier is not a range
// or tag of the registry: it has a scheme (file:, link:, git+..., https:,
// npm: aliases, workspace:), is a path, or is the user/repo shorthand of a
// GitHub repository.
func npmSpecIsLocal(spec string) bool {
	return strings.Contains(spec, ":") || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") ||
		strings.HasPrefix(spec, "~/") || npmShorthandRE.MatchString(spec)
}

// pnpmEdgeKey is the snapshot key a requirement of version value ver of name
// points to, "" if there is none.
func pnpmEdgeKey(snapshots, packages map[string]any, name, ver string) string {
	if ver == "" || strings.Contains(pnpmBase(ver), ":") {
		return ""
	}
	// Only a snapshot is a node: a package listed under the bare key whose
	// snapshots all carry a peer suffix has no node to point to.
	key := name + "@" + ver
	if _, ok := snapshots[key]; ok {
		return key
	}
	return ""
}

// --- uv ---

var uvDependencyTables = []string{"dependencies", "optional-dependencies", "dev-dependencies"}

// uvGraph reads a uv.lock of a project without a workspace as a graph whose
// entries are its registry packages, keyed name==version.
func uvGraph(ctx context.Context, lock []byte) (*depGraph, error) {
	budget := &graphBudget{ctx: ctx}
	doc, err := parseTOML(lock)
	if err != nil {
		return nil, fmt.Errorf("uv.lock cannot be read")
	}
	if err := checkTOMLKeys(doc); err != nil {
		return nil, fmt.Errorf("uv.lock cannot be read: %v", err)
	}
	list, _ := doc["package"].([]any)
	if err := checkNodeCount(len(list)); err != nil {
		return nil, err
	}
	g := &depGraph{nodes: map[string]*depNode{}}

	byName := map[string][]string{}
	type pending struct {
		key string
		tbl map[string]any
	}
	var todo []pending
	var root map[string]any
	for _, p := range list {
		m, ok := p.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("uv.lock has a package entry that is not a table")
		}
		src, _ := m["source"].(map[string]any)
		if d, _ := src["virtual"].(string); d == "." {
			root = m
			continue
		}
		if d, _ := src["editable"].(string); d == "." {
			root = m
			continue
		}
		name, _ := m["name"].(string)
		ver, _ := m["version"].(string)
		if why := uvRecordProblem(m); why != "" {
			return nil, fmt.Errorf("uv.lock, %s %s: %s", clip(name, 100), clip(ver, 40), why)
		}
		key := name + "==" + ver
		if _, dup := g.nodes[key]; dup {
			return nil, fmt.Errorf("uv.lock holds %s twice", key)
		}
		norm := normalizePyName(name)
		n := &depNode{name: norm, version: ver}
		if rm, ok := m["resolution-markers"].([]any); ok {
			for _, x := range rm {
				if t, ok := x.(string); ok {
					n.resMarkers = append(n.resMarkers, t)
				}
			}
		}
		for k := range m {
			if !uvPackageKeys[k] {
				n.unknown = append(n.unknown, k)
			}
		}
		if sk, _ := m["source"].(map[string]any); len(sk) != 1 {
			n.unknown = append(n.unknown, "source")
		} else if _, reg := sk["registry"]; !reg {
			n.unknown = append(n.unknown, "source.kind")
		}
		sort.Strings(n.unknown)
		attrs, err := canonicalJSON(stripUvVersions(m))
		if err != nil {
			return nil, fmt.Errorf("uv.lock has content that cannot be compared: %v", err)
		}
		n.attrs = attrs
		switch idx, isReg := src["registry"].(string); {
		case isReg && idx == publicPyPIIndex:
			if sd, ok := m["sdist"].(map[string]any); ok {
				u, _ := sd["url"].(string)
				h, _ := sd["hash"].(string)
				if !pypiFileURL(u) {
					n.problem = "its sdist is not on " + pypiWheelHost
				}
				n.dist = append(n.dist, distRef{url: u, hash: h, kind: "sdist"})
			}
			ws, _ := m["wheels"].([]any)
			for i, w := range ws {
				if why := wheelProblem(w, pypiWheelHost); why != "" {
					n.problem = fmt.Sprintf("wheel %d %s", i+1, why)
					break
				}
				wm := w.(map[string]any)
				u, _ := wm["url"].(string)
				h, _ := wm["hash"].(string)
				n.dist = append(n.dist, distRef{url: u, hash: h, kind: "wheel"})
			}
		case isReg:
			n.problem = "from the index " + idx
		default:
			n.problem = "from a " + uvSourceKind(src) + " source"
		}
		g.nodes[key] = n
		byName[norm] = append(byName[norm], key)
		todo = append(todo, pending{key, m})
	}
	if root == nil {
		return nil, fmt.Errorf("uv.lock has no root project")
	}
	if why := uvRecordProblem(root); why != "" {
		return nil, fmt.Errorf("uv.lock, the root project: %s", why)
	}
	resolve := func(m map[string]any) ([]depEdge, error) {
		var out []depEdge
		for _, tbl := range uvDependencyTables {
			var lists []any
			switch v := m[tbl].(type) {
			case []any:
				lists = append(lists, v)
			case map[string]any:
				for _, l := range v {
					lists = append(lists, l)
				}
			}
			for _, l := range lists {
				items, _ := l.([]any)
				if err := budget.add(len(items)); err != nil {
					return nil, err
				}
				for _, it := range items {
					d, _ := it.(map[string]any)
					dn, _ := d["name"].(string)
					if err := checkGraphName("a dependency name", dn); err != nil {
						return nil, err
					}
					norm := normalizePyName(dn)
					dv, _ := d["version"].(string)
					cands := byName[norm]
					// uv writes a version on a dependency only to tell apart
					// several versions of the package in the file. A reference
					// without one to a package that has several is not
					// something the format lets a reader resolve, so it is not
					// guessed (and not fanned out to every version).
					switch {
					case dv != "":
						cands = []string{dn + "==" + dv}
					case len(cands) > 1:
						return nil, fmt.Errorf("uv.lock requires %s without a version, and the file holds %d versions of it", norm, len(cands))
					}
					c := ""
					if len(cands) == 1 {
						if _, ok := g.nodes[cands[0]]; ok {
							c = cands[0]
						}
					}
					mk, _ := d["marker"].(string)
					edge := depEdge{name: norm, key: c, marker: mk}
					if src, ok := d["source"].(map[string]any); ok {
						ref, _ := canonicalJSON(src)
						_, registry := src["registry"]
						edge.ref, edge.local = ref, !registry
					}
					out = append(out, edge)
				}
			}
		}
		sortEdges(out)
		return out, nil
	}
	for _, p := range todo {
		deps, err := resolve(p.tbl)
		if err != nil {
			return nil, err
		}
		n := g.nodes[p.key]
		n.deps = deps
		// The dependencies of the package itself (not of its extras) are the
		// ones its metadata lists without an extra.
		items, _ := p.tbl["dependencies"].([]any)
		for _, it := range items {
			d, _ := it.(map[string]any)
			dn, _ := d["name"].(string)
			n.declared = append(n.declared, normalizePyName(dn))
		}
		sort.Strings(n.declared)
		if opt, ok := p.tbl["optional-dependencies"].(map[string]any); ok {
			n.extraDeps = map[string][]string{}
			for extra, l := range opt {
				items, _ := l.([]any)
				for _, it := range items {
					d, _ := it.(map[string]any)
					dn, _ := d["name"].(string)
					n.extraDeps[normalizePyName(extra)] = append(n.extraDeps[normalizePyName(extra)], normalizePyName(dn))
				}
			}
		} else if _, present := p.tbl["optional-dependencies"]; present {
			n.otherRecords = true
		}
		if _, present := p.tbl["dev-dependencies"]; present {
			n.otherRecords = true
		}
	}
	var rerr error
	if g.roots, rerr = resolve(root); rerr != nil {
		return nil, rerr
	}

	rest := map[string]any{}
	for k, v := range doc {
		if k != "package" {
			rest[k] = v
		}
	}
	rest["\x00root"] = stripUvVersions(root)
	if g.meta, err = canonicalJSON(rest); err != nil {
		return nil, fmt.Errorf("uv.lock has content that cannot be compared: %v", err)
	}
	if err := g.checkBounds(); err != nil {
		return nil, err
	}
	return g, nil
}

// stripUvVersions copies a package table without the "version" of the
// dependencies it lists: a version appears there only to tell apart several
// versions of one package, and which one is chosen is compared as an edge.
func stripUvVersions(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if !contains(uvDependencyTables, k) {
			out[k] = v
			continue
		}
		out[k] = stripDepVersions(v)
	}
	return out
}

func stripDepVersions(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = stripDepVersions(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if k == "version" {
				if _, isStr := e.(string); isStr {
					continue
				}
			}
			out[k] = stripDepVersions(e)
		}
		return out
	}
	return v
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// pypiFileURL reports whether u is an https URL on the host PyPI serves
// distribution files from.
func pypiFileURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Hostname() == pypiWheelHost
}

// --- pip ---

// pipReport is the part of the report of pip install --report that the
// update stage reads.
type pipReport struct {
	Version string
	Install []pipInstall
}

type pipInstall struct {
	URL       string
	Hashes    map[string]string
	Requested bool
	IsYanked  bool
	// IsDirect is set for a requirement given as a URL.
	IsDirect bool
	Name     string
	Version  string
	// RequiresDist is pip's own copy of the requirements; the update stage
	// does not use it (it uses the index's).
	RequiresDist []string
}

// parsePipReport reads the install report by the exact spelling of its keys
// (see strictObject): a repeated key, or two that differ only in case, in any
// of its fixed-word objects is refused.
func parsePipReport(data []byte) (*pipReport, error) {
	top, err := strictObject(data)
	if err != nil {
		return nil, err
	}
	if u := unknownKeys(top, pipReportKeys); len(u) > 0 {
		return nil, fmt.Errorf("the report has the member %q, which the installation report format does not have", u[0])
	}
	// Of the report's members, version, pip_version, install and environment
	// are always written; they must be there, with their types.
	for _, k := range []string{"version", "pip_version", "install", "environment"} {
		if raw, ok := top[k]; !ok || string(bytes.TrimSpace(raw)) == "null" {
			return nil, fmt.Errorf("the report lacks %q", k)
		}
	}
	var rep pipReport
	if rep.Version, err = optString(top, "version"); err != nil {
		return nil, err
	}
	if _, err = optString(top, "pip_version"); err != nil {
		return nil, err
	}
	if _, err = strictObject(top["environment"]); err != nil {
		return nil, fmt.Errorf("environment is not an object: %v", err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(top["install"], &items); err != nil || items == nil {
		return nil, errors.New("install is not a list")
	}
	if err := checkNodeCount(len(items)); err != nil {
		return nil, err
	}
	for _, raw := range items {
		im, err := strictObject(raw)
		if err != nil {
			return nil, err
		}
		if u := unknownKeys(im, pipItemKeys); len(u) > 0 {
			return nil, fmt.Errorf("an install entry has the member %q, which the installation report format does not have", u[0])
		}
		var it pipInstall
		if dl, ok := im["download_info"]; ok {
			dm, err := strictObject(dl)
			if err != nil {
				return nil, err
			}
			if u := unknownKeys(dm, keySet("url", "archive_info")); len(u) > 0 {
				return nil, fmt.Errorf("download_info has the member %q (a VCS or directory source, or something else that is not a file on an index)", u[0])
			}
			if it.URL, err = optString(dm, "url"); err != nil {
				return nil, err
			}
			if ai, ok := dm["archive_info"]; ok {
				am, err := strictObject(ai)
				if err != nil {
					return nil, err
				}
				if u := unknownKeys(am, keySet("hash", "hashes")); len(u) > 0 {
					return nil, fmt.Errorf("archive_info has the member %q", u[0])
				}
				if it.Hashes, err = optStringMap(am, "hashes"); err != nil {
					return nil, err
				}
			}
		}
		if it.Requested, err = optBool(im, "requested"); err != nil {
			return nil, err
		}
		if it.IsYanked, err = optBool(im, "is_yanked"); err != nil {
			return nil, err
		}
		if it.IsDirect, err = optBool(im, "is_direct"); err != nil {
			return nil, err
		}
		if md, ok := im["metadata"]; ok {
			mm, err := strictObject(md)
			if err != nil {
				return nil, err
			}
			if it.Name, err = optString(mm, "name"); err != nil {
				return nil, err
			}
			if it.Version, err = optString(mm, "version"); err != nil {
				return nil, err
			}
			if raw, ok := mm["requires_dist"]; ok && string(bytes.TrimSpace(raw)) != "null" {
				if err := json.Unmarshal(raw, &it.RequiresDist); err != nil {
					return nil, errors.New("requires_dist is not a list of strings")
				}
			}
		}
		rep.Install = append(rep.Install, it)
	}
	return &rep, nil
}

// pipGraph reads the install report of a pip dry run as a graph keyed by
// PEP 503 name. The requirements of a package are not taken from the report
// (pip's own output): requires maps each name to the names of the
// requirements that are in force for it in the environment pip resolved for,
// worked out by the caller from what the index declares. The project's own
// requirements are roots, given by name: they come from the requirements
// file, not from what the report marks as requested. A requirement whose
// package the report does not install is unresolved.
func pipGraph(ctx context.Context, report []byte, requires map[string][]string, roots []string) (*depGraph, error) {
	budget := &graphBudget{ctx: ctx}
	rp, err := parsePipReport(report)
	if err != nil || rp.Version != "1" {
		return nil, fmt.Errorf("pip report cannot be read")
	}
	r := *rp
	if err := checkNodeCount(len(r.Install)); err != nil {
		return nil, err
	}
	g := &depGraph{nodes: map[string]*depNode{}, meta: "pip-report-v1"}
	for _, it := range r.Install {
		name := normalizePyName(it.Name)
		if name == "" {
			return nil, fmt.Errorf("pip report has an entry without a name")
		}
		if _, dup := g.nodes[name]; dup {
			return nil, fmt.Errorf("pip report installs %s twice", name)
		}
		n := &depNode{name: name, version: it.Version}
		var hs []string
		for algo, h := range it.Hashes {
			hs = append(hs, algo+"="+h)
		}
		sort.Strings(hs)
		n.attrs = it.Version + "|" + it.URL + "|" + strings.Join(hs, ",")
		if !pypiFileURL(it.URL) {
			n.problem = "downloaded from " + it.URL
		}
		g.nodes[name] = n
	}
	for _, it := range r.Install {
		name := normalizePyName(it.Name)
		n := g.nodes[name]
		if err := budget.add(len(requires[name])); err != nil {
			return nil, err
		}
		for _, dep := range requires[name] {
			if _, ok := g.nodes[dep]; ok && dep != name {
				n.deps = append(n.deps, depEdge{name: dep, key: dep})
			} else if dep != name {
				n.deps = append(n.deps, depEdge{name: dep})
			}
		}
		sortEdges(n.deps)
	}
	for _, name := range roots {
		if _, ok := g.nodes[name]; ok {
			g.roots = append(g.roots, depEdge{name: name, key: name})
		} else {
			g.roots = append(g.roots, depEdge{name: name})
		}
	}
	sortEdges(g.roots)
	if err := g.checkBounds(); err != nil {
		return nil, err
	}
	return g, nil
}

// --- comparison ---

// link numbers the entries, gives each a digest of its key, and sets for every
// requirement the number of the entry it points to; a requirement whose key
// has no entry becomes an unresolved one. It is done once, so that walking the
// graph and comparing two graphs never hashes a long key per requirement: the
// work is the length of the keys once plus the number of requirements.
func (g *depGraph) link() { _ = g.linkCtx(context.Background()) }

// linkCtx is link that watches ctx; a graph whose linking was stopped is not
// linked.
func (g *depGraph) linkCtx(ctx context.Context) error {
	if g.linked {
		return nil
	}
	list := make([]*depNode, 0, len(g.nodes))
	index := make(map[string]int, len(g.nodes))
	for k, n := range g.nodes {
		if len(list)%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		n.id, n.key = len(list), k
		sum := sha256.Sum256([]byte(k))
		n.kid = string(sum[:16])
		if n.problem != "" {
			// What an entry that is not a registry package is, as one digest:
			// its name, version, the reason it is not, and where it is from.
			// What its snapshots share is already a digest.
			h := sha256.New()
			fmt.Fprintf(h, "%s\x00%s\x00%s", n.name, n.version, n.problem)
			if n.distDigest != "" {
				fmt.Fprintf(h, "\x00%s", n.distDigest)
			} else {
				for _, d := range n.dist {
					fmt.Fprintf(h, "\x00%s\x00%s", d.url, d.hash)
				}
			}
			n.pid = string(h.Sum(nil)[:16])
		}
		index[k] = n.id
		list = append(list, n)
	}
	steps := 0
	fix := func(es []depEdge) error {
		for i := range es {
			if steps++; steps%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			es[i].to = -1
			if es[i].key == "" {
				continue
			}
			if id, ok := index[es[i].key]; ok {
				es[i].to = id
			} else {
				es[i].key = ""
			}
		}
		return nil
	}
	if err := fix(g.roots); err != nil {
		return err
	}
	for _, n := range list {
		if err := fix(n.deps); err != nil {
			return err
		}
	}
	g.list, g.linked = list, true
	return nil
}

// dropDangling turns an edge to a key without a node into an unresolved one,
// so that no later lookup meets a missing node.
func (g *depGraph) dropDangling() { g.link() }

// target returns the entry a requirement points to, nil if it points to none.
func (g *depGraph) target(e depEdge) *depNode {
	g.link()
	if e.to < 0 || e.to >= len(g.list) {
		return nil
	}
	return g.list[e.to]
}

// reachBits marks, by number, the entries reachable from the project along the
// requirements. It stops, returning what it has, when ctx ends.
func (g *depGraph) reachBits(ctx context.Context) []bool {
	g.link()
	seen := make([]bool, len(g.list))
	var queue []int
	for _, e := range g.roots {
		if e.to >= 0 {
			queue = append(queue, e.to)
		}
	}
	for steps := 0; len(queue) > 0; steps++ {
		if steps%1024 == 0 && ctx.Err() != nil {
			return seen
		}
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		for _, e := range g.list[id].deps {
			if e.to >= 0 && !seen[e.to] {
				queue = append(queue, e.to)
			}
		}
	}
	return seen
}

// editedMask replaces a specifier this program edited when the part of a
// lockfile outside its entries is compared.
const editedMask = "\x00edited"

// maskEditedSpecs replaces, in the part of the file outside its entries, the
// recorded specifier of each edited dependency, so that the part compares
// equal to the original's where nothing else changed.
func (g *depGraph) maskEditedSpecs(ctx context.Context, m DependencyManager, edits []ManifestEdit) error {
	if len(edits) > maxManifestEdits {
		return errManifestEditLimit
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(g.meta), &meta); err != nil {
		return err
	}
	switch m {
	case ManagerNpm, ManagerPnpm:
		key := "\x00root"
		if m == ManagerPnpm {
			key = "\x00importer"
		}
		root, _ := meta[key].(map[string]any)
		for _, e := range edits {
			if sec, _ := root[e.Section].(map[string]any); sec != nil {
				if _, ok := sec[e.Name]; ok {
					sec[e.Name] = editedMask
				}
			}
		}
	case ManagerUv:
		// The edited names are put in a set and the requirements are walked once.
		names := make(map[string]bool, len(edits))
		for _, e := range edits {
			names[normalizePyName(e.Name)] = true
		}
		root, _ := meta["\x00root"].(map[string]any)
		md, _ := root["metadata"].(map[string]any)
		list, _ := md["requires-dist"].([]any)
		for i, x := range list {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if d, _ := x.(map[string]any); d != nil {
				if name, ok := d["name"].(string); ok && names[normalizePyName(name)] {
					d["specifier"] = editedMask
				}
			}
		}
	}
	out, err := canonicalJSON(meta)
	if err != nil {
		return err
	}
	g.meta = out
	return nil
}

// edgeSig describes the edges of a node for comparison: an edge to a package
// being updated is only named, since which version it points to is what the
// update changes; any other edge also names the entry it resolves to.
func edgeSig(g *depGraph, es []depEdge, targets map[string]bool) string {
	g.link()
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.name)
		b.WriteByte('=')
		switch n := g.target(e); {
		case n == nil:
			b.WriteByte('?')
		case targets[n.name]:
			b.WriteByte('T')
		default:
			b.WriteString(n.kid)
		}
		b.WriteByte(';')
	}
	return b.String()
}

func (n *depNode) full(g *depGraph, targets map[string]bool) string {
	return n.attrs + "\x00" + edgeSig(g, n.deps, targets)
}

// reach returns the entries reachable from the starts along the graph's
// edges. Entries for which stop returns true are included but not expanded.
// It gives up (returning what it has) when ctx ends; callers check ctx.
func (g *depGraph) reach(ctx context.Context, starts []string, stop func(*depNode) bool) map[string]bool {
	g.link()
	seen := make([]bool, len(g.list))
	var queue []int
	for _, k := range starts {
		if n := g.nodes[k]; k != "" && n != nil {
			queue = append(queue, n.id)
		}
	}
	out := map[string]bool{}
	for steps := 0; len(queue) > 0; steps++ {
		if steps%1024 == 0 && ctx.Err() != nil {
			return out
		}
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		n := g.list[id]
		out[n.key] = true
		if stop != nil && stop(n) {
			continue
		}
		for _, e := range n.deps {
			if e.to >= 0 && !seen[e.to] {
				queue = append(queue, e.to)
			}
		}
	}
	return out
}

func rootKeys(es []depEdge) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.key)
	}
	return out
}

// unresolvedEdge is a requirement of the entry at ownerKey (named
// ownerName; the empty key is the project) that no entry satisfies.
type unresolvedEdge struct {
	ownerKey, ownerName, dep string
	optional, confirmed      bool
}

func (g *depGraph) unresolvedEdges() []unresolvedEdge {
	var out []unresolvedEdge
	for _, e := range g.roots {
		if e.key == "" {
			out = append(out, unresolvedEdge{"", "", e.name, e.optional, e.confirmed})
		}
	}
	for k, n := range g.nodes {
		for _, e := range n.deps {
			if e.key == "" {
				out = append(out, unresolvedEdge{k, n.name, e.name, e.optional, e.confirmed})
			}
		}
	}
	return out
}

// newUnresolved returns the requirements of the updated graph that no entry
// satisfies and that the original graph did not leave unsatisfied in the same
// place. A requirement left unresolved at the same entry before is the same
// requirement. A package whose entry has a new key because its version moved
// may keep an optional requirement unresolved only if the original entry of
// that package left the same optional requirement unresolved. A required
// requirement that is unresolved, and was not so at the same entry, is never
// allowed, however the original graph looked elsewhere. The kind (required or
// optional) is part of what has to be the same: a requirement that was optional
// before is not the same as a required one. For the entries an update adds or
// changes the kind is the one the registry declares, which the caller sets on
// the edges before this is called.
func newUnresolved(before, after *depGraph) []unresolvedEdge {
	return newUnresolvedCtx(context.Background(), before, after)
}

// ownerEdges are the unresolved requirements of one entry (the empty key is
// the project).
type ownerEdges struct {
	key, name string
	edges     []unresolvedEdge
}

// unresolvedByOwner lists the unresolved requirements of a graph entry by
// entry, so that a long key is looked up once per entry and not once per
// requirement.
func (g *depGraph) unresolvedByOwner() []ownerEdges {
	g.link()
	var out []ownerEdges
	var roots []unresolvedEdge
	for _, e := range g.roots {
		if e.to < 0 {
			roots = append(roots, unresolvedEdge{"", "", e.name, e.optional, e.confirmed})
		}
	}
	if len(roots) > 0 {
		out = append(out, ownerEdges{"", "", roots})
	}
	for _, n := range g.list {
		var es []unresolvedEdge
		for _, e := range n.deps {
			if e.to < 0 {
				es = append(es, unresolvedEdge{n.key, n.name, e.name, e.optional, e.confirmed})
			}
		}
		if len(es) > 0 {
			out = append(out, ownerEdges{n.key, n.name, es})
		}
	}
	return out
}

func newUnresolvedCtx(ctx context.Context, before, after *depGraph) []unresolvedEdge {
	type kind struct {
		dep      string
		optional bool
	}
	type named struct{ owner, dep string }
	sameEntry := map[string]map[kind]bool{} // by the owner's key
	byName := map[named]bool{}              // optional requirements, by package name
	for _, o := range before.unresolvedByOwner() {
		set := make(map[kind]bool, len(o.edges))
		for _, u := range o.edges {
			set[kind{u.dep, u.optional}] = true
			if u.optional {
				byName[named{o.name, u.dep}] = true
			}
		}
		sameEntry[o.key] = set
	}
	var out []unresolvedEdge
	for i, o := range after.unresolvedByOwner() {
		if i%1024 == 0 && ctx.Err() != nil {
			break
		}
		// The owner is looked up once: whether the original has it, and what it
		// left unresolved.
		had := sameEntry[o.key]
		exists := o.key == "" || before.nodes[o.key] != nil
		for _, u := range o.edges {
			switch {
			case u.confirmed && u.optional:
				// The registry says it is an optional or peer dependency, which
				// may stay unresolved.
			case u.confirmed:
				// The registry says it is required: whatever the original looked
				// like, it must resolve.
				out = append(out, u)
			case had[kind{u.dep, u.optional}] && exists:
			case u.optional && byName[named{o.name, u.dep}]:
			default:
				out = append(out, u)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ownerKey != out[j].ownerKey {
			return out[i].ownerKey < out[j].ownerKey
		}
		return out[i].dep < out[j].dep
	})
	return out
}

// diffGraphs checks what an update changed in a dependency file against the
// packages it was meant to update (targets, by matching name) and returns the
// changes. The rules, which use only what the two files hold:
//
//   - The parts of the file that are not entries (format, version, settings,
//     the project's own entry and its declared requirements) are unchanged,
//     and so are the project's requirements apart from which version of an
//     updated package they take.
//   - Every updated package is still in the file after the update and is
//     still needed: some entry of it is reachable from the project's
//     requirements. Dropping the package is not a fix.
//   - An entry of the original file may change or go away only if it is an
//     updated package or was reachable before the update only through updated
//     packages (it hung below them). An entry that was an ancestor of an
//     updated package, or reachable without one, keeps its content whatever
//     edges the updated file gives it.
//   - An entry that is new is reachable from an updated package in the updated
//     graph: the new version may pull a different or new dependency, and
//     nothing else.
//   - A new or changed entry is fetched from the public registry.
//
// The returned reason is empty when the changes are explained. The entries
// that are new or changed are returned in Touched (not truncated).
func diffGraphs(ctx context.Context, before, after *depGraph, targets map[string]bool) (DependencyDiff, Reason, string) {
	var diff DependencyDiff
	if before.meta != after.meta {
		return diff, ReasonUnexplainedDiff, "the part of the file outside its package entries changed"
	}
	if edgeSig(before, before.roots, targets) != edgeSig(after, after.roots, targets) {
		return diff, ReasonUnexplainedDiff, "the requirements of the project itself point to different entries"
	}
	if why := newNonRegistryEdge(ctx, before, after); why != "" {
		return diff, ReasonResolvedSourceChanged, why
	}
	isTarget := func(n *depNode) bool { return targets[n.name] }
	reachAfter := after.reach(ctx, rootKeys(after.roots), nil)
	byName := map[string][]string{}
	for k, n := range after.nodes {
		byName[n.name] = append(byName[n.name], k)
	}
	for name := range targets {
		found, needed := len(byName[name]) > 0, false
		for _, k := range byName[name] {
			needed = needed || reachAfter[k]
		}
		switch {
		case !found:
			return diff, ReasonTargetRemoved, fmt.Sprintf("%s is no longer in the updated file", name)
		case !needed:
			return diff, ReasonTargetRemoved, fmt.Sprintf("%s is in the updated file but nothing requires it", name)
		}
	}

	var afterTargets, beforeTargets []string
	for k, n := range after.nodes {
		if isTarget(n) {
			afterTargets = append(afterTargets, k)
		}
	}
	for k, n := range before.nodes {
		if isTarget(n) {
			beforeTargets = append(beforeTargets, k)
		}
	}
	underTargetAfter := after.reach(ctx, afterTargets, nil)
	// Before the update: what is reachable from the project without passing
	// through an updated package, and what hangs below the updated packages.
	freeBefore := before.reach(ctx, rootKeys(before.roots), isTarget)
	belowBefore := before.reach(ctx, beforeTargets, nil)
	if err := ctx.Err(); err != nil {
		return diff, ReasonUnexplainedDiff, err.Error()
	}
	mayChange := func(k string, n *depNode) bool {
		return isTarget(n) || (belowBefore[k] && !freeBefore[k])
	}

	var keys []string
	for k := range after.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n := after.nodes[k]
		old, existed := before.nodes[k]
		switch {
		case !existed:
			diff.Added = append(diff.Added, k)
			if !isTarget(n) && !underTargetAfter[k] {
				return diff, ReasonUnexplainedDiff, fmt.Sprintf("%s is new but is neither an updated package nor required by one", k)
			}
		case old.full(before, targets) != n.full(after, targets):
			diff.Changed = append(diff.Changed, k)
			if !mayChange(k, old) {
				return diff, ReasonUnexplainedDiff, fmt.Sprintf("%s changed but is neither an updated package nor only reachable through one", k)
			}
		default:
			continue
		}
		if n.problem != "" {
			return diff, ReasonResolvedSourceChanged, fmt.Sprintf("%s: %s", k, n.problem)
		}
	}
	diff.touched = append(append([]string(nil), diff.Added...), diff.Changed...)

	keys = keys[:0]
	for k := range before.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, kept := after.nodes[k]; kept {
			continue
		}
		diff.Removed = append(diff.Removed, k)
		if n := before.nodes[k]; !isTarget(n) && freeBefore[k] {
			return diff, ReasonUnexplainedDiff, fmt.Sprintf("%s was removed but was required without the updated packages", k)
		}
	}
	diff.trim()
	return diff, "", ""
}

// trim cuts each list at maxDiffEntries.
func (d *DependencyDiff) trim() {
	for _, l := range []*[]string{&d.Added, &d.Changed, &d.Removed} {
		if len(*l) > maxDiffEntries {
			*l = (*l)[:maxDiffEntries]
			d.Truncated = true
		}
	}
}

// newNonRegistryEdge returns a description of the first requirement in after
// that points to something other than a registry package and has no
// counterpart in before, or "". A requirement points to one when its reference
// is local (a link, file, workspace, git or tarball location), whether or not
// an entry exists for it, or when the entry it points to is not a registry
// package. The exceptions for a requirement the registry declares optional do
// not apply: an optional dependency that is not in the lockfile is fine, one
// that points to a local directory is a package nothing here checks.
//
// The counterpart has to be an occurrence that was installed before, and one
// that was not a registry package either: an entry reachable from the project
// in before, of the same package name, with the same requirement (name and
// reference) pointing to nothing, or to the very entry (its name, version, why
// it is not a registry package and where it is from) that it points to now.
// A requirement that pointed to a registry package before is no counterpart. An entry the
// original file only carried, that nothing reached, does not vouch for one
// that is reached now, and neither does another package's. Only the entries
// reachable in after are judged.
func newNonRegistryEdge(ctx context.Context, before, after *depGraph) string {
	type sig struct{ owner, name, ref, target string }
	// The identity of what a requirement points to when it is not a registry
	// package: the entry (its digest, which covers where it is from), or
	// nothing for a local reference that has no entry.
	ident := func(g *depGraph, e depEdge) string {
		if t := g.target(e); t != nil && t.problem != "" {
			return t.pid
		}
		return ""
	}
	bad := func(g *depGraph, e depEdge) bool {
		if e.local {
			return true
		}
		t := g.target(e)
		return t != nil && t.problem != ""
	}
	reachBefore, reachAfter := before.reachBits(ctx), after.reachBits(ctx)
	// Only a requirement that was not a registry package before can vouch for
	// one that is not now: a registry requirement of the same name is no
	// reason to take a local one.
	had := map[sig]bool{}
	for _, e := range before.roots {
		if bad(before, e) {
			had[sig{"", e.name, e.ref, ident(before, e)}] = true
		}
	}
	for i, n := range before.list {
		if i%1024 == 0 && ctx.Err() != nil {
			return ""
		}
		if !reachBefore[n.id] {
			continue
		}
		for _, e := range n.deps {
			if bad(before, e) {
				had[sig{n.name, e.name, e.ref, ident(before, e)}] = true
			}
		}
	}
	for _, e := range after.roots {
		if bad(after, e) && !had[sig{"", e.name, e.ref, ident(after, e)}] {
			return fmt.Sprintf("the project now requires %s as %q, which is not a registry package", e.name, clip(e.ref, 100))
		}
	}
	// In a fixed order, so that the same input gives the same answer.
	order := make([]*depNode, 0, len(after.list))
	for _, n := range after.list {
		if reachAfter[n.id] {
			order = append(order, n)
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i].key < order[j].key })
	for i, n := range order {
		if i%1024 == 0 && ctx.Err() != nil {
			return ""
		}
		for _, e := range n.deps {
			if bad(after, e) && !had[sig{n.name, e.name, e.ref, ident(after, e)}] {
				return fmt.Sprintf("%s now requires %s as %q, which is not a registry package", n.key, e.name, clip(e.ref, 100))
			}
		}
	}
	return ""
}

// checkUnresolved refuses an updated graph that has a requirement no entry
// satisfies and that the original did not leave unsatisfied in the same place
// and of the same kind (see newUnresolved).
func checkUnresolved(before, after *depGraph) (Reason, string) {
	return checkUnresolvedCtx(context.Background(), before, after)
}

// checkUnresolvedCtx is checkUnresolved that watches ctx.
func checkUnresolvedCtx(ctx context.Context, before, after *depGraph) (Reason, string) {
	un := newUnresolvedCtx(ctx, before, after)
	if len(un) == 0 {
		return "", ""
	}
	owner := un[0].ownerName
	if un[0].ownerKey == "" {
		owner = "the project"
	}
	return ReasonUnexplainedDiff, fmt.Sprintf("the updated file has a requirement no entry satisfies: %s requires %s", owner, un[0].dep)
}

// pnpmPackageKeys and pnpmSnapshotKeys are the members of a package's record
// and of a snapshot in pnpm-lock.yaml (LockfilePackageInfo and
// LockfilePackageSnapshot of @pnpm/lockfile.types, with requiresBuild and
// prepare that lockfiles of version 9 can still carry).
var (
	pnpmPackageKeys = keySet("id", "patched", "hasBin", "name", "version", "resolution", "peerDependencies", "peerDependenciesMeta",
		"bundledDependencies", "engines", "os", "cpu", "libc", "deprecated", "requiresBuild", "prepare")
	pnpmSnapshotKeys = keySet("optional", "dependencies", "optionalDependencies", "transitivePeerDependencies")
)

// pnpmInstallRecord reads the install-relevant members of a package record
// of pnpm-lock.yaml in the form installRecord reduces them to. hasBin is a
// flag where the registry has a bin map, so a record only says "present".
func pnpmInstallRecord(pk map[string]any, name string) (rec map[string]string, peers map[string]string, errText string) {
	m := map[string]json.RawMessage{}
	for _, k := range []string{"os", "cpu", "libc", "engines"} {
		if v, ok := pk[k]; ok {
			b, _ := json.Marshal(v)
			m[k] = b
		}
	}
	if v, ok := pk["bundledDependencies"]; ok {
		if s, isStr := v.(string); isStr && s == "true" {
			m["bundledDependencies"] = json.RawMessage("true")
		} else {
			b, _ := json.Marshal(v)
			m["bundledDependencies"] = b
		}
	}
	if v, ok := pk["peerDependenciesMeta"]; ok {
		meta := map[string]any{}
		for n, e := range gmap(v) {
			meta[n] = map[string]any{"optional": gstr(gmap(e)["optional"]) == "true"}
		}
		b, _ := json.Marshal(meta)
		m["peerDependenciesMeta"] = b
	}
	rec, err := installRecord(m, name, nil, "bundledDependencies")
	if err != nil {
		return nil, nil, err.Error()
	}
	if gstr(pk["hasBin"]) == "true" {
		rec["bin"] = "present"
	}
	peers = map[string]string{}
	for k, v := range gmap(pk["peerDependencies"]) {
		peers[k] = gstr(v)
	}
	return rec, peers, ""
}

// pipReportKeys and pipItemKeys are the members of the installation report
// (https://packaging.python.org/en/latest/specifications/installation-report/)
// that this program accepts at the top and in an install entry.
var (
	pipReportKeys = keySet("version", "pip_version", "install", "environment")
	pipItemKeys   = keySet("download_info", "is_direct", "is_yanked", "requested", "requested_extras", "metadata")
)
