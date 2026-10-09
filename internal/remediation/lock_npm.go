package remediation

import (
	"encoding/json"
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

	var doc struct {
		LockfileVersion int                `json:"lockfileVersion"`
		Packages        map[string]npmPack `json:"packages"`
	}
	if err := json.Unmarshal(lock, &doc); err != nil {
		return nil, unsupported(ReasonUnparsableSource, "package-lock.json cannot be read: %v", err)
	}
	if doc.LockfileVersion != 2 && doc.LockfileVersion != 3 {
		return nil, unsupported(ReasonUnsupportedLockfile, "package-lock.json has lockfileVersion %d; only 2 and 3 are read", doc.LockfileVersion)
	}
	root, ok := doc.Packages[""]
	if !ok {
		return nil, unsupported(ReasonUnsupportedLockfile, "package-lock.json has no root entry in its packages map")
	}

	direct := map[string]bool{}
	for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
		for n := range m {
			direct[n] = true
		}
	}

	keys := make([]string, 0, len(doc.Packages))
	for k := range doc.Packages {
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

	l := newLockfile(ManagerNpm)
	for _, k := range keys {
		e := doc.Packages[k]
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
		l.add(name, o)
	}

	for _, n := range overrideNames(pj.overrides) {
		l.force(n, "package.json overrides it")
	}
	return l.finish(), nil
}

type npmPack struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
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

// overrideNames lists the package names an npm "overrides" object touches,
// at any depth. A key may carry a range (name@range).
func overrideNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	var out []string
	for k, v := range m {
		if k != "." {
			out = append(out, nameWithoutRange(k))
		}
		out = append(out, overrideNames(v)...)
	}
	sort.Strings(out)
	return out
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
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
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
		var vals map[string]json.RawMessage
		if err := json.Unmarshal(raw, &vals); err != nil || vals == nil {
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
