package remediation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// plainJSON encodes v as compact JSON without the escaping of <, > and & that
// json.Marshal adds, so the text of a record is the text of its values.
func plainJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}

// The fields of a package's record that decide whether and how it is
// installed, and so must say what the registry says for that name and
// version: the platforms it is limited to (os, cpu, libc), the engines it
// asks for, the commands it links (bin), the dependencies it bundles, and
// which peer dependencies are optional. Each is reduced to a canonical text
// so the lockfile's and the registry's can be compared; a field that is
// absent, empty or null is the empty text.
//
// The registry and the lockfiles spell these fields the same way (they are
// fields of package.json), except that a lockfile of pnpm writes hasBin for
// bin and bundledDependencies for bundleDependencies.

// installKeys are the members read, by the name they have in the registry.
var installKeys = []string{"os", "cpu", "libc", "engines", "bin", "bundleDependencies", "peerDependenciesMeta"}

// isNull reports whether a member is absent or JSON null. Only these are
// "unspecified": an empty object, empty list, false or an empty string is a
// value of its own that a lockfile has to be compared on.
func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// rawForm is the text of a member whose type is not the one its field has:
// it carries the value as it is, so values of different types or contents
// never compare equal, and never equal an absent member.
func rawForm(raw json.RawMessage) string {
	v, err := decodeJSONValue(raw)
	if err != nil {
		return "raw:" + string(bytes.TrimSpace(raw))
	}
	return "raw:" + plainJSON(v)
}

// storedByNpm reports whether npm writes a member of a package.json into its
// lockfile: lib/shrinkwrap.js of @npmcli/arborist (metaFieldFromPkg) skips a
// value that is falsy and an object or list with no members. A registry
// value in that form is "not recorded" on the lockfile side.
func storedByNpm(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	switch string(t) {
	case "", "null", "false", `""`, "0", "[]", "{}":
		return false
	}
	return true
}

// normStringSet reduces a list of strings to its sorted distinct elements;
// the text is the JSON list, so the boundaries between elements are kept (a
// list holding one empty string is not an empty list). Any other kind of value is kept as it is.
func normStringSet(raw json.RawMessage) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	var l []string
	if err := json.Unmarshal(raw, &l); err != nil || l == nil {
		return rawForm(raw), nil
	}
	sort.Strings(l)
	out := []string{}
	for i, x := range l {
		if i == 0 || x != l[i-1] {
			out = append(out, x)
		}
	}
	return plainJSON(out), nil
}

// asStringMap reads an object of strings; ok is false for any other value.
func asStringMap(raw json.RawMessage) (map[string]string, bool) {
	m, err := nameMap(raw)
	if err != nil || m == nil {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		var s string
		if json.Unmarshal(v, &s) != nil {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}

// normStringMap reduces an object of strings to canonical JSON (an empty
// object is "{}"); any other kind of value is kept as it is.
func normStringMap(raw json.RawMessage) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	out, ok := asStringMap(raw)
	if !ok {
		return rawForm(raw), nil
	}
	return plainJSON(out), nil
}

// normBin reduces bin to canonical JSON of command name to the file it runs:
// a bare string is the command named like the package, and a "./" in front of
// a path does not matter. Any other kind of value is kept as it is.
func normBin(raw json.RawMessage, pkg string) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	cmds := map[string]string{}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return rawForm(raw), nil
		}
		cmds[pkg[strings.LastIndex(pkg, "/")+1:]] = s
	} else {
		m, ok := asStringMap(raw)
		if !ok {
			return rawForm(raw), nil
		}
		for k, v := range m {
			cmds[k] = v
		}
	}
	for k, v := range cmds {
		cmds[k] = path.Clean(strings.TrimPrefix(v, "./"))
	}
	return plainJSON(cmds), nil
}

// normBundle reduces the bundled dependencies to the sorted names; true means
// every dependency, which deps names. Any other kind of value is kept as it is.
func normBundle(raw json.RawMessage, deps map[string]string) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	if string(bytes.TrimSpace(raw)) == "true" {
		return plainJSON(depNames(deps)), nil
	}
	return normStringSet(raw)
}

// normPeerMeta reduces peerDependenciesMeta to the names marked optional.
// An entry that is not an object, or marks "optional" with a non-boolean, is
// kept as it is.
func normPeerMeta(raw json.RawMessage) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	m, err := nameMap(raw)
	if err != nil || m == nil {
		return rawForm(raw), nil
	}
	var opt []string
	for name, v := range m {
		var meta struct {
			Optional *bool `json:"optional"`
		}
		if json.Unmarshal(v, &meta) != nil {
			return rawForm(raw), nil
		}
		if meta.Optional != nil && *meta.Optional {
			opt = append(opt, name)
		}
	}
	sort.Strings(opt)
	return strings.Join(opt, ","), nil
}

// installRecord reads the install-relevant members of an object that has the
// registry's field names (a lockfile entry of npm, a version document of the
// registry). bundleKeys are the names bundled dependencies may be under;
// deps are the object's dependencies, for bundleDependencies: true.
func installRecord(m map[string]json.RawMessage, pkg string, deps map[string]string, bundleKeys ...string) (map[string]string, error) {
	out := map[string]string{}
	set := func(key string, v string, err error) error {
		if err != nil {
			return fmt.Errorf("%q %v", key, err)
		}
		if v != "" {
			out[key] = v
		}
		return nil
	}
	for _, key := range []string{"os", "cpu", "libc"} {
		v, err := normStringSet(m[key])
		if err := set(key, v, err); err != nil {
			return nil, err
		}
	}
	v, err := normStringMap(m["engines"])
	if err := set("engines", v, err); err != nil {
		return nil, err
	}
	v, err = normBin(m["bin"], pkg)
	if err := set("bin", v, err); err != nil {
		return nil, err
	}
	for _, key := range bundleKeys {
		if raw, ok := m[key]; ok {
			v, err := normBundle(raw, deps)
			if err := set("bundleDependencies", v, err); err != nil {
				return nil, err
			}
			break
		}
	}
	v, err = normPeerMeta(m["peerDependenciesMeta"])
	if err := set("peerDependenciesMeta", v, err); err != nil {
		return nil, err
	}
	return out, nil
}

// sameRecord reports the first member in which two install records differ.
func sameRecord(a, b map[string]string) (key, x, y string, same bool) {
	for _, k := range installKeys {
		if a[k] != b[k] {
			return k, a[k], b[k], false
		}
	}
	return "", "", "", true
}

// unknownKeys lists the keys of m that are not in known, sorted.
func unknownKeys(m map[string]json.RawMessage, known map[string]bool) []string {
	var out []string
	for k := range m {
		if !known[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func keySet(keys ...string) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// npmEntryKeys are the members arborist writes for an entry of
// package-lock.json (lib/shrinkwrap.js of @npmcli/arborist: pkgMetaKeys,
// nodeMetaKeys and the flags it adds), without the patch records (patched,
// packageExtensionsApplied, npmExtensionApplied) that say a package was
// changed after it was fetched. A member outside this set is not something this
// program knows the effect of.
var npmEntryKeys = keySet(
	"name", "version", "resolved", "integrity", "link",
	"dev", "optional", "devOptional", "peer", "extraneous", "inBundle",
	"hasInstallScript", "hasShrinkwrap", "license", "funding", "deprecated",
	"engines", "os", "cpu", "libc", "bin",
	"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta",
	"bundleDependencies", "acceptDependencies", "workspaces",
)

// npmAncestors lists the paths of the packages a lockfile path is nested in,
// outermost first: node_modules/a/node_modules/@s/b has node_modules/a.
func npmAncestors(p string) []string {
	var out []string
	for i := 0; i+len(npmModules) < len(p); {
		j := strings.Index(p[i+1:], "/"+npmModules)
		if j < 0 {
			break
		}
		i += 1 + j
		out = append(out, p[:i])
	}
	return out
}

// A package that bundles dependencies carries them in its tarball, and npm
// places what they need (their own dependencies, and what those bring) in the
// same bundle, so which entries below a bundling package belong to the bundle
// is not decided by the names it lists. The rule is therefore the cautious one:
// every entry nested below a package that bundles anything (a non-empty
// bundleDependencies, or true), and a package that bundles anything itself, is
// taken to be in a bundle, whatever its name. Whether a list is empty is read
// off its text, once per package, without reading the list.

// entryBundlesAnything reports whether the members of a lockfile entry of npm
// say that the package bundles something: bundleDependencies (or
// bundledDependencies) is present and is not null, false, an empty list or
// object, or an empty string.
func entryBundlesAnything(m map[string]json.RawMessage) bool {
	for _, key := range []string{"bundleDependencies", "bundledDependencies"} {
		raw, ok := m[key]
		if !ok {
			continue
		}
		t := bytes.TrimSpace(raw)
		switch string(t) {
		case "", "null", "false", `""`:
			continue
		}
		// An empty list or object, with whatever white space is inside.
		if len(t) >= 2 && (t[0] == '[' || t[0] == '{') && len(bytes.TrimSpace(t[1:len(t)-1])) == 0 {
			continue
		}
		return true
	}
	return false
}

// entryHasShrinkwrap reports whether the members of a lockfile entry of npm
// say that the package carries its own npm-shrinkwrap.json (hasShrinkwrap).
// npm reads that file again after it unpacks the package, so what is below the
// package is decided by it and not by the entries of the outer lockfile; a
// package with one is treated like a package that bundles dependencies.
func entryHasShrinkwrap(m map[string]json.RawMessage) bool {
	raw, ok := m["hasShrinkwrap"]
	return ok && storedByNpm(raw)
}

// recordBundlesAnything is entryBundlesAnything for the canonical
// bundled-dependencies text of an installRecord: absent or an empty list is
// nothing, anything else is something.
func recordBundlesAnything(text string) bool {
	return text != "" && text != "[]"
}
