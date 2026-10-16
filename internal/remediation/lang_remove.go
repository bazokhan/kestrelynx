package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The lockfile of an npm or pnpm update is not updated by a command that
// names the packages. This program makes a copy of the lockfile with the
// entries of the packages being updated taken out, with its own strict reader,
// and the package manager makes the lockfile again from it (a relock): the
// packages that are missing are resolved afresh within the ranges of their
// dependents, and nothing else is asked to move. The result is checked like
// any other output of the work container.

// removalProblem says why a lockfile for an update could not be made.
type removalProblem struct {
	reason Reason
	detail string
	// name is the package the problem belongs to, "" for the unit.
	name string
}

func (p *removalProblem) Error() string { return p.detail }

// failure is the outcome of an update that could not be made for this reason:
// the end of the time allowed defers it, anything else is a manual unit.
func (p *removalProblem) failure() *updateFailure {
	switch {
	case p.reason == ReasonCycleDeadline:
		return &updateFailure{category: CategoryDeferred, reason: p.reason, detail: p.detail}
	case p.name != "":
		return pkgFailure(p.name, p.reason, "%s", p.detail)
	}
	return manualFailure(p.reason, "%s", p.detail)
}

func removalFailure(format string, args ...any) *removalProblem {
	return &removalProblem{reason: ReasonOutputFilesInvalid, detail: fmt.Sprintf(format, args...)}
}

// maxRemovalTargets bounds the work of a removal over the packages named.
const maxRemovalTargets = 4096

// --- pnpm-lock.yaml ---

// pnpmRemoval is a pnpm-lock.yaml with the update targets taken out.
type pnpmRemoval struct {
	lock []byte
	// direct are the targets the importer required itself, taken out of it.
	// trigger is the direct dependency taken out of the importer, when no
	// target was one, so that pnpm resolves again and fills in what was
	// taken out: without a change to the importer pnpm takes the lockfile to
	// be up to date and writes it with the entries missing.
	direct  []string
	trigger string
}

// yamlGet returns the value of a key of a mapping node, nil if there is none.
func yamlGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// yamlDelete removes the members of a mapping node whose key drop accepts and
// returns the keys it removed.
func yamlDelete(n *yaml.Node, drop func(key string) bool) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var gone []string
	kept := n.Content[:0:0]
	for i := 0; i+1 < len(n.Content); i += 2 {
		if drop(n.Content[i].Value) {
			gone = append(gone, n.Content[i].Value)
			continue
		}
		kept = append(kept, n.Content[i], n.Content[i+1])
	}
	n.Content = kept
	return gone
}

var pnpmImporterGroups = []string{"dependencies", "devDependencies", "optionalDependencies"}

// removePnpmTargets makes the pnpm-lock.yaml of the update: every package
// record and snapshot of a target, in every version, taken out, and the
// importer changed so that pnpm resolves again (see pnpmRemoval).
//
// A target that is a direct dependency is taken out of the importer. Otherwise
// the direct dependency whose closure (the entries reachable from it) is the
// smallest is taken out, the first by name if several are as small: taking out
// a dependency that reaches much of the graph lets pnpm settle versions
// elsewhere in it too. A project with nothing to take out has no such
// dependency, and the update is left to a person.
func removePnpmTargets(ctx context.Context, lock []byte, targets map[string]bool) (*pnpmRemoval, *removalProblem) {
	if len(targets) == 0 || len(targets) > maxRemovalTargets {
		return nil, removalFailure("%d packages are taken out of pnpm-lock.yaml", len(targets))
	}
	root, err := readYAMLRoot(lock)
	if err != nil {
		return nil, removalFailure("pnpm-lock.yaml cannot be read: %v", err)
	}
	imp := yamlGet(yamlGet(root, "importers"), ".")
	if imp == nil {
		return nil, removalFailure("pnpm-lock.yaml has no importer \".\"")
	}
	out := &pnpmRemoval{}
	isTarget := func(name string) bool { return targets[name] }
	for _, g := range pnpmImporterGroups {
		for _, name := range yamlDelete(yamlGet(imp, g), isTarget) {
			out.direct = append(out.direct, name)
		}
	}
	sort.Strings(out.direct)
	if len(out.direct) == 0 {
		trigger, problem := pnpmTrigger(ctx, lock, targets)
		if problem != nil {
			return nil, problem
		}
		for _, g := range pnpmImporterGroups {
			yamlDelete(yamlGet(imp, g), func(name string) bool { return name == trigger })
		}
		out.trigger = trigger
	}
	// A group the importer is left without is not written.
	for _, g := range pnpmImporterGroups {
		if m := yamlGet(imp, g); m != nil && len(m.Content) == 0 {
			yamlDelete(imp, func(key string) bool { return key == g })
		}
	}

	lock, problem := pnpmWriteWithout(root, targets, nil)
	if problem != nil {
		return nil, problem
	}
	out.lock = lock
	return out, nil
}

// removePnpmEntries is removePnpmTargets for an update that also resolves again
// the packages that require a held back package: the snapshots at the given
// keys are taken out with the package records they leave without a snapshot,
// and the tops (direct dependencies by name) are taken out of every group of
// the importer, which is what makes pnpm resolve them again from the ranges in
// package.json. Every snapshot has to be in the lockfile, and a package record
// is taken out only when every one of its snapshots is.
func removePnpmEntries(ctx context.Context, lock []byte, targets, snapshots, tops map[string]bool) (*pnpmRemoval, *removalProblem) {
	if len(targets) == 0 || len(targets) > maxRemovalTargets || len(snapshots) > maxChainAncestors || len(tops) == 0 || len(tops) > maxChainTops {
		return nil, removalFailure("%d packages and %d snapshots are taken out of pnpm-lock.yaml", len(targets), len(snapshots))
	}
	if err := ctx.Err(); err != nil {
		return nil, &removalProblem{reason: ReasonCycleDeadline, detail: err.Error()}
	}
	root, err := readYAMLRoot(lock)
	if err != nil {
		return nil, removalFailure("pnpm-lock.yaml cannot be read: %v", err)
	}
	imp := yamlGet(yamlGet(root, "importers"), ".")
	if imp == nil {
		return nil, removalFailure("pnpm-lock.yaml has no importer \".\"")
	}
	out := &pnpmRemoval{}
	drop := func(name string) bool { return targets[name] || tops[name] }
	for _, g := range pnpmImporterGroups {
		out.direct = append(out.direct, yamlDelete(yamlGet(imp, g), drop)...)
	}
	sort.Strings(out.direct)
	for _, g := range pnpmImporterGroups {
		if m := yamlGet(imp, g); m != nil && len(m.Content) == 0 {
			yamlDelete(imp, func(key string) bool { return key == g })
		}
	}
	data, problem := pnpmWriteWithout(root, targets, snapshots)
	if problem != nil {
		return nil, problem
	}
	out.lock = data
	return out, nil
}

// pnpmWriteWithout takes the records and snapshots of the targets (in every
// version) and the snapshots at the given keys out of the lockfile and writes
// it. A package record goes with the snapshots only when none of its snapshots
// is left.
func pnpmWriteWithout(root *yaml.Node, targets, snapshots map[string]bool) ([]byte, *removalProblem) {
	found := map[string]bool{}
	foundSnap := map[string]bool{}
	left := map[string]bool{} // package records (name@version) that keep a snapshot
	gone := map[string]bool{} // package records whose snapshots are all taken out
	for _, e := range snapshotKeys(yamlGet(root, "snapshots")) {
		name, _, ok := splitPnpmKey(pnpmBase(e))
		switch {
		case ok && targets[name]:
			gone[pnpmBase(e)] = true
		case snapshots[e]:
			gone[pnpmBase(e)] = true
		default:
			left[pnpmBase(e)] = true
		}
	}
	for base := range left {
		delete(gone, base)
	}
	yamlDelete(yamlGet(root, "snapshots"), func(key string) bool {
		name, _, ok := splitPnpmKey(pnpmBase(key))
		if snapshots[key] {
			foundSnap[key] = true
			return true
		}
		if !ok || !targets[name] {
			return false
		}
		found[name] = true
		return true
	})
	yamlDelete(yamlGet(root, "packages"), func(key string) bool {
		name, _, ok := splitPnpmKey(pnpmBase(key))
		if ok && targets[name] {
			found[name] = true
			return true
		}
		return gone[pnpmBase(key)]
	})
	for name := range targets {
		if !found[name] {
			return nil, &removalProblem{reason: ReasonTargetNotInLockfile, name: name,
				detail: fmt.Sprintf("%s has no entry in pnpm-lock.yaml", name)}
		}
	}
	for key := range snapshots {
		if !foundSnap[key] {
			return nil, &removalProblem{reason: ReasonTargetNotInLockfile, name: key,
				detail: fmt.Sprintf("%s has no snapshot in pnpm-lock.yaml", key)}
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, removalFailure("pnpm-lock.yaml cannot be written again: %v", err)
	}
	if err := enc.Close(); err != nil {
		return nil, removalFailure("pnpm-lock.yaml cannot be written again: %v", err)
	}
	if _, err := readPnpmLock(buf.Bytes()); err != nil {
		return nil, removalFailure("the pnpm-lock.yaml made for the update cannot be read: %v", err)
	}
	return buf.Bytes(), nil
}

// snapshotKeys lists the keys of a mapping node.
func snapshotKeys(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, n.Content[i].Value)
	}
	return out
}

// pnpmTrigger chooses the direct dependency to take out of the importer when
// no target is one: the one with the smallest closure, and the first by name
// among those as small.
func pnpmTrigger(ctx context.Context, lock []byte, targets map[string]bool) (string, *removalProblem) {
	g, err := buildGraph(ctx, ManagerPnpm, lock)
	if err != nil {
		return "", removalFailure("the dependency graph of pnpm-lock.yaml cannot be read: %v", err)
	}
	best, bestSize := "", -1
	roots := append([]depEdge(nil), g.roots...)
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].name < roots[j].name })
	for i, e := range roots {
		if i%256 == 0 && ctx.Err() != nil {
			return "", &removalProblem{reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		// A dependency that is not a registry package, or that the lockfile
		// does not resolve, is not one to take out and put back.
		if e.local || e.key == "" || targets[e.name] {
			continue
		}
		size := len(g.reach(ctx, []string{e.key}, nil))
		if bestSize < 0 || size < bestSize {
			best, bestSize = e.name, size
		}
	}
	if err := ctx.Err(); err != nil {
		return "", &removalProblem{reason: ReasonCycleDeadline, detail: err.Error()}
	}
	if best == "" {
		return "", &removalProblem{reason: ReasonNoReresolveTrigger,
			detail: "no direct dependency of the project other than the packages being updated can be taken out of pnpm-lock.yaml to make pnpm resolve again"}
	}
	return best, nil
}

// Bounds on the peer contexts of a snapshot key or a version: the text is
// written by a program that cannot be trusted, and a parenthesis in a scalar
// is not limited by the depth the YAML reader checks.
const (
	maxPeerSuffixBytes = 16 << 10
	maxPeerSuffixDepth = 64
	// maxPeerStripBytes is how much text one lockfile may have stripped.
	maxPeerStripBytes = 128 << 20
	peerStripCtxEvery = 1 << 20
)

// peerStripper takes the peer contexts of some packages out of the keys and
// versions of a pnpm lockfile, within a budget of work.
type peerStripper struct {
	ctx    context.Context
	names  map[string]bool
	budget int
	since  int
}

// text returns s without the parenthesized contexts whose package is in names, at any depth:
// foo@1.0.0(next@15.1.0)(react@19.0.0) becomes foo@1.0.0(react@19.0.0) for next.
// It reads s once. Text that is not made of a base and balanced groups is
// returned as it is; text over the bounds is an error.
func (p *peerStripper) text(s string) (string, error) {
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return s, nil
	}
	if len(s) > maxPeerSuffixBytes {
		return "", fmt.Errorf("a peer context of %d bytes is over the %d bytes read", len(s), maxPeerSuffixBytes)
	}
	if p.budget -= len(s); p.budget < 0 {
		return "", errors.New("the peer contexts of the file are over the amount of text read")
	}
	if p.since += len(s); p.since >= peerStripCtxEvery {
		p.since = 0
		if err := p.ctx.Err(); err != nil {
			return "", err
		}
	}
	type frame struct {
		start     int // where the group starts in out
		headStart int // where its first word starts in s
		headDone  bool
		drop      bool
	}
	out := make([]byte, 0, len(s))
	out = append(out, s[:i]...)
	var stack []frame
	for ; i < len(s); i++ {
		c := s[i]
		if c == '(' || c == ')' {
			if n := len(stack); n > 0 && !stack[n-1].headDone {
				f := &stack[n-1]
				f.headDone = true
				head := s[f.headStart:i]
				name := head
				if at := strings.LastIndexByte(head, '@'); at > 0 {
					name = head[:at]
				}
				f.drop = p.names[name]
			}
		}
		switch c {
		case '(':
			if len(stack) >= maxPeerSuffixDepth {
				return "", fmt.Errorf("peer contexts nest over %d levels", maxPeerSuffixDepth)
			}
			stack = append(stack, frame{start: len(out), headStart: i + 1})
			out = append(out, c)
		case ')':
			if len(stack) == 0 {
				return s, nil
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if f.drop {
				out = out[:f.start]
			} else {
				out = append(out, c)
			}
		default:
			if len(stack) == 0 {
				// text after the groups that is not a group
				return s, nil
			}
			out = append(out, c)
		}
	}
	if len(stack) != 0 {
		return s, nil
	}
	return string(out), nil
}

// normalizedGraph makes the graph the two lockfiles of an update are compared
// in from the graph of a lockfile as it is written. Updating a package changes
// the peer context in the keys of the entries that have it as a peer, and the
// comparison is about everything else in them, so the keys of the entries are
// written without the contexts of the updated packages. The graph keeps exactly
// the references the written file resolved: each is carried over to the
// entries' new keys, and a reference the written file did not resolve is not
// resolved again by the new keys. Two entries that become one are refused.
func normalizedGraph(ctx context.Context, raw *depGraph, names map[string]bool) (*depGraph, error) {
	if err := raw.linkCtx(ctx); err != nil {
		return nil, err
	}
	p := &peerStripper{ctx: ctx, names: names, budget: maxPeerStripBytes}
	mapped := make(map[string]string, len(raw.nodes))
	taken := make(map[string]string, len(raw.nodes))
	for k := range raw.nodes {
		nk, err := p.text(k)
		if err != nil {
			return nil, err
		}
		if other, dup := taken[nk]; dup {
			return nil, fmt.Errorf("two entries are the same once the contexts of the updated packages are left out: %s and %s", clip(other, 100), clip(k, 100))
		}
		taken[nk], mapped[k] = k, nk
	}
	var carryErr error
	carry := func(es []depEdge) []depEdge {
		out := append([]depEdge(nil), es...)
		for i := range out {
			// key is "" for a reference the written file did not resolve, and
			// stays so.
			if out[i].key != "" {
				out[i].key = mapped[out[i].key]
			}
			// What a requirement for a registry version says it points to carries
			// the same contexts. A reference to a link, a file, a repository or a
			// tarball is kept as it is written: a change in it is a change of
			// source.
			if !out[i].local {
				ref, err := p.text(out[i].ref)
				if err != nil && carryErr == nil {
					carryErr = err
				}
				out[i].ref = ref
			}
			out[i].to = -1
		}
		return out
	}
	g := &depGraph{nodes: make(map[string]*depNode, len(raw.nodes)), meta: raw.meta}
	for k, n := range raw.nodes {
		c := *n
		c.deps = carry(n.deps)
		g.nodes[mapped[k]] = &c
	}
	g.roots = carry(raw.roots)
	if carryErr != nil {
		return nil, carryErr
	}
	return g, nil
}

// --- package-lock.json ---

// npmRemoval is a package-lock.json with the update targets taken out.
type npmRemoval struct {
	lock []byte
	// paths are the entries taken out of "packages", in order.
	paths []string
}

// encodeObjectEntries writes the members of an object in the order given.
func encodeObjectEntries(es []kv) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range es {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(e.key)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(e.raw)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// npmPathName is the package name at the end of a path of package-lock.json.
func npmPathName(p string) string {
	i := strings.LastIndex(p, npmModules)
	if i < 0 {
		return ""
	}
	return p[i+len(npmModules):]
}

// removeNpmTargets makes the package-lock.json of the update: the entry of
// every target at every path, with the entries nested below it, taken out of
// "packages", and out of the tree "dependencies" of a lockfileVersion 2 file.
func removeNpmTargets(ctx context.Context, lock []byte, targets map[string]bool) (*npmRemoval, *removalProblem) {
	return removeNpmEntries(ctx, lock, targets, nil)
}

// removeNpmEntries is removeNpmTargets that also takes out the entries at the
// given paths, with what is nested below them: the entries of the packages
// that require a package held back, for an update that resolves those again.
// Every path has to be in the lockfile.
func removeNpmEntries(ctx context.Context, lock []byte, targets, paths map[string]bool) (*npmRemoval, *removalProblem) {
	if len(targets) == 0 || len(targets) > maxRemovalTargets {
		return nil, removalFailure("%d packages are taken out of package-lock.json", len(targets))
	}
	if len(paths) > maxChainAncestors {
		return nil, removalFailure("%d entries are taken out of package-lock.json by path", len(paths))
	}
	top, err := objectEntries(lock)
	if err != nil {
		return nil, removalFailure("package-lock.json cannot be read: %v", err)
	}
	removed := map[string]bool{}
	found := map[string]bool{}
	foundPaths := map[string]bool{}
	out := &npmRemoval{}
	for ti, e := range top {
		if e.key != "packages" {
			continue
		}
		pkgs, err := objectEntries(e.raw)
		if err != nil {
			return nil, removalFailure("package-lock.json packages cannot be read: %v", err)
		}
		for _, p := range pkgs {
			if p.key == "" || !strings.HasPrefix(p.key, npmModules) {
				continue
			}
			if targets[npmPathName(p.key)] {
				removed[p.key] = true
				found[npmPathName(p.key)] = true
			}
			if paths[p.key] {
				removed[p.key] = true
				foundPaths[p.key] = true
			}
		}
		kept := make([]kv, 0, len(pkgs))
		for i, p := range pkgs {
			if i%1024 == 0 && ctx.Err() != nil {
				return nil, &removalProblem{reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
			}
			gone := removed[p.key]
			for _, anc := range npmAncestors(p.key) {
				gone = gone || removed[anc]
			}
			if gone {
				out.paths = append(out.paths, p.key)
				continue
			}
			kept = append(kept, p)
		}
		raw, err := encodeObjectEntries(kept)
		if err != nil {
			return nil, removalFailure("package-lock.json cannot be written again: %v", err)
		}
		top[ti].raw = raw
	}
	for name := range targets {
		if !found[name] {
			return nil, &removalProblem{reason: ReasonTargetNotInLockfile, name: name,
				detail: fmt.Sprintf("%s has no entry in package-lock.json", name)}
		}
	}
	for p := range paths {
		if !foundPaths[p] {
			return nil, &removalProblem{reason: ReasonTargetNotInLockfile, name: p,
				detail: fmt.Sprintf("%s has no entry in package-lock.json", p)}
		}
	}
	gone := map[string]bool{}
	for _, p := range out.paths {
		gone[p] = true
	}
	for ti, e := range top {
		if e.key != "dependencies" || !bytes.HasPrefix(bytes.TrimSpace(e.raw), []byte("{")) {
			continue
		}
		raw, err := removeLegacyNodes(ctx, e.raw, "", gone, 0)
		if err != nil {
			return nil, removalFailure("the dependencies tree of package-lock.json: %v", err)
		}
		top[ti].raw = raw
	}
	raw, err := encodeObjectEntries(top)
	if err != nil {
		return nil, removalFailure("package-lock.json cannot be written again: %v", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "  "); err != nil {
		return nil, removalFailure("package-lock.json cannot be written again: %v", err)
	}
	if bytes.HasSuffix(lock, []byte("\n")) {
		indented.WriteByte('\n')
	}
	out.lock = indented.Bytes()
	if _, err := readNpmLock(out.lock); err != nil {
		return nil, removalFailure("the package-lock.json made for the update cannot be read: %v", err)
	}
	return out, nil
}

// removeLegacyNodes takes the nodes whose path is in gone out of the tree
// "dependencies" of a lockfileVersion 2 file, at any depth.
func removeLegacyNodes(ctx context.Context, raw []byte, parent string, gone map[string]bool, depth int) ([]byte, error) {
	if depth > maxNpmPathDepth {
		return nil, errors.New("it is nested too deeply")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nodes, err := objectEntries(raw)
	if err != nil {
		return nil, err
	}
	kept := make([]kv, 0, len(nodes))
	for _, n := range nodes {
		path := npmModules + n.key
		if parent != "" {
			path = parent + "/" + npmModules + n.key
		}
		if gone[path] {
			continue
		}
		members, err := objectEntries(n.raw)
		if err != nil {
			return nil, err
		}
		changed := false
		for mi, m := range members {
			if m.key == "dependencies" {
				sub, err := removeLegacyNodes(ctx, m.raw, path, gone, depth+1)
				if err != nil {
					return nil, err
				}
				members[mi].raw, changed = sub, true
			}
		}
		if changed {
			if n.raw, err = encodeObjectEntries(members); err != nil {
				return nil, err
			}
		}
		kept = append(kept, n)
	}
	return encodeObjectEntries(kept)
}
