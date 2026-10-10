package remediation

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const npmModules = "node_modules/"

// publicNpmHost is the only registry host whose tarballs count as the public
// registry.
const publicNpmHost = "registry.npmjs.org"

// parseNpm reads package-lock.json (lockfileVersion 2 or 3) of a single
// project. manifest is the project's package.json.
func parseNpm(manifest, lock []byte) (*lockfile, error) {
	pj, err := readManifest(manifest)
	if err != nil {
		return nil, err
	}
	if pj.workspaces {
		return nil, unsupported(ReasonWorkspaceUnsupported, "package.json declares workspaces")
	}

	doc, err := readNpmLock(lock)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "%v", err)
	}
	if doc.version != 2 && doc.version != 3 {
		return nil, unsupported(ReasonUnsupportedLockfile, "package-lock.json has lockfileVersion %d; only 2 and 3 are read", doc.version)
	}
	root, ok := doc.entries[""]
	if !ok {
		return nil, unsupported(ReasonUnsupportedLockfile, "package-lock.json has no root entry in its packages map")
	}

	direct := map[string]bool{}
	for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
		for n := range m {
			direct[n] = true
		}
	}

	keys := make([]string, 0, len(doc.entries))
	for k := range doc.entries {
		if k == "" {
			continue
		}
		if !strings.HasPrefix(k, npmModules) {
			// A workspace member or a package outside node_modules.
			return nil, unsupported(ReasonWorkspaceUnsupported, "package-lock.json has the entry %q outside node_modules", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	bundles := make(map[string]bool, len(keys))
	for _, k := range keys {
		bundles[k] = entryBundlesAnything(doc.entries[k].m)
	}

	l := newLockfile(ManagerNpm)
	for _, k := range keys {
		e := doc.entries[k]
		name := k[strings.LastIndex(k, npmModules)+len(npmModules):]
		if name == "" {
			return nil, unsupported(ReasonUnparsableSource, "package-lock.json has the entry %q without a package name", k)
		}
		o := SourceOccurrence{Path: k, Version: e.Version, Direct: k == npmModules+name && direct[name]}
		switch {
		case e.Name != "" && e.Name != name:
			// An alias: the installed package is e.Name under another name.
			name = e.Name
			o.ManualReason, o.Detail = ReasonNonRegistrySource, "installed under an alias name"
		case e.Link:
			o.ManualReason, o.Detail = ReasonNonRegistrySource, "a link to a local directory"
		default:
			if why := npmSourceProblem(e.Resolved); why != "" {
				o.ManualReason, o.Detail = ReasonNonRegistrySource, why
			}
		}
		if o.ManualReason == "" {
			// A package bundled in another one is taken from that package's
			// tarball, not fetched from the registry by itself.
			if why := npmBundledProblem(bundles, k, e); why != "" {
				o.ManualReason, o.Detail = ReasonNonRegistrySource, why
			}
		}
		l.add(name, o)
	}

	names, err := overrideNames(pj.overrides)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "%v", err)
	}
	for _, n := range names {
		l.force(n, "package.json overrides it")
	}
	return l.finish(), nil
}

// npmSourceProblem returns why a resolved URL is not the public registry, or
// "" when it is.
func npmSourceProblem(resolved string) string {
	if resolved == "" {
		return "no resolved URL"
	}
	u, err := url.Parse(resolved)
	if err != nil || u.Host == "" {
		return "resolved from a location that is not a registry URL"
	}
	if u.Scheme != "https" || u.Hostname() != publicNpmHost {
		return "resolved from " + u.Scheme + "://" + u.Host
	}
	return ""
}

// Bounds on a package.json "overrides" object; the planner call has no
// context, so depth and node count are the only limits.
const (
	maxOverrideDepth = 32
	maxOverrideNodes = 100000
)

// overrideNames lists the package names an npm "overrides" object touches,
// at any depth. A key may carry a range (name@range). The object is decoded
// once and walked once; a nesting or size over the limits is an error.
func overrideNames(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	nodes := 0
	type frame struct {
		v     any
		depth int
	}
	stack := []frame{{doc, 1}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		m, ok := f.v.(map[string]any)
		if !ok {
			continue
		}
		if f.depth > maxOverrideDepth {
			return nil, fmt.Errorf("package.json overrides nest over %d levels", maxOverrideDepth)
		}
		for k, v := range m {
			if nodes++; nodes > maxOverrideNodes {
				return nil, fmt.Errorf("package.json overrides hold over %d entries", maxOverrideNodes)
			}
			if k != "." {
				seen[nameWithoutRange(k)] = true
			}
			stack = append(stack, frame{v, f.depth + 1})
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// nameWithoutRange strips an "@range" suffix from a package name; a leading
// "@" is a scope.
func nameWithoutRange(s string) string {
	if i := strings.Index(s[min(1, len(s)):], "@"); i >= 0 {
		return s[:i+1]
	}
	return s
}

// manifest is the part of a package.json the plan reads.
type manifest struct {
	workspaces bool
	deps       map[string]map[string]string // dependencies, devDependencies, optionalDependencies, peerDependencies
	overrides  json.RawMessage
}

var manifestDepFields = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// readManifest reads a package.json. The top level must be a JSON object, not
// null or anything else, and each dependency field present must be an object
// of string versions; a manifest that is not shaped like that is not read.
func readManifest(data []byte) (*manifest, error) {
	top, err := strictObject(data)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "package.json cannot be read: %v", err)
	}
	if top == nil {
		return nil, unsupported(ReasonUnparsableSource, "package.json is not a JSON object")
	}
	m := &manifest{deps: map[string]map[string]string{}, overrides: top["overrides"]}
	_, m.workspaces = top["workspaces"]
	for _, f := range manifestDepFields {
		raw, ok := top[f]
		if !ok {
			continue
		}
		vals, err := nameMap(raw)
		if err != nil || vals == nil {
			return nil, unsupported(ReasonUnparsableSource, "package.json field %s is not an object of version strings", f)
		}
		deps := make(map[string]string, len(vals))
		for name, v := range vals {
			// A JSON null would decode into an empty string; every value
			// must really be a string.
			var s string
			if t := strings.TrimSpace(string(v)); !strings.HasPrefix(t, `"`) || json.Unmarshal(v, &s) != nil {
				return nil, unsupported(ReasonUnparsableSource, "package.json field %s gives %s a value that is not a string", f, name)
			}
			deps[name] = s
		}
		m.deps[f] = deps
	}
	return m, nil
}

// npmBundledProblem returns why the entry at path k is, or may be, installed
// from the tarball of a package, or "" when it is not: the entry says inBundle,
// it bundles something itself, or a package it is nested in bundles something
// (see entryBundlesAnything for why the names listed are not consulted).
// bundles holds, for the paths of the file, whether the entry bundles
// anything, and is filled once for the file.
func npmBundledProblem(bundles map[string]bool, k string, e npmGraphEntry) string {
	if b, err := optBool(e.m, "inBundle"); err != nil || b {
		return "bundled in another package"
	}
	if bundles[k] {
		return "bundles dependencies itself"
	}
	for _, anc := range npmAncestors(k) {
		if bundles[anc] {
			return "nested in " + clip(anc, 100) + ", which bundles dependencies"
		}
	}
	return ""
}
