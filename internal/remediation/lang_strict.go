package remediation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reading the files of an update's result exactly.
//
// encoding/json matches a key to a struct field without regard to case, and
// takes the last of two equal keys, while the package managers read keys by
// their exact spelling. A file with "resolved" and "Resolved" would be read
// one way here and another way by npm. So the keys that carry meaning are read
// by their exact spelling, and an object that has the same key twice, or two
// keys that differ only in case, is refused. Maps keyed by package names are
// the exception to the second rule (two packages can differ in case alone)
// but not to the first.

type kv struct {
	key string
	raw json.RawMessage
}

// objectEntries returns the members of a JSON object in order. It fails for
// anything that is not one object with nothing after it.
func objectEntries(data []byte) ([]kv, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var out []kv
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("a JSON object has a key that is not a string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out = append(out, kv{key, raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("text after a JSON object")
	}
	return out, nil
}

// nameMap reads an object whose keys are names (of packages): a repeated key
// is refused.
func nameMap(data []byte) (map[string]json.RawMessage, error) {
	es, err := objectEntries(data)
	if err != nil {
		return nil, err
	}
	m := make(map[string]json.RawMessage, len(es))
	for _, e := range es {
		if _, dup := m[e.key]; dup {
			return nil, fmt.Errorf("the key %q is repeated", clip(e.key, 100))
		}
		m[e.key] = e.raw
	}
	return m, nil
}

// strictObject reads an object whose keys are fixed words: a repeated key, or
// two keys that differ only in case, is refused.
func strictObject(data []byte) (map[string]json.RawMessage, error) {
	m, err := nameMap(data)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]string, len(m))
	for k := range m {
		l := strings.ToLower(k)
		if other, clash := seen[l]; clash {
			return nil, fmt.Errorf("the keys %q and %q differ only in case", clip(other, 100), clip(k, 100))
		}
		seen[l] = k
	}
	return m, nil
}

// optString reads a string member: absent is "", a member that is not a string
// is an error.
func optString(m map[string]json.RawMessage, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%q is not a string", key)
	}
	return s, nil
}

func optBool(m map[string]json.RawMessage, key string) (bool, error) {
	raw, ok := m[key]
	if !ok {
		return false, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, fmt.Errorf("%q is not a boolean", key)
	}
	return b, nil
}

// optStringMap reads an object of names to strings.
func optStringMap(m map[string]json.RawMessage, key string) (map[string]string, error) {
	raw, ok := m[key]
	if !ok {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	nm, err := nameMap(raw)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", key, err)
	}
	out := make(map[string]string, len(nm))
	for k, v := range nm {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, fmt.Errorf("%q: the value of %q is not a string", key, clip(k, 100))
		}
		out[k] = s
	}
	return out, nil
}

// --- YAML (pnpm-lock.yaml) ---

// Bounds on a pnpm-lock.yaml, checked before it is converted. The YAML
// decoder's own conversion into maps compares each new key with all the earlier
// ones (quadratic in the size of a mapping), so the file is parsed to a node
// tree first, its keys are checked with maps, and the values are converted by
// the code below.
const (
	maxYAMLBytes = 8 << 20
	maxYAMLNodes = 3000000
	maxYAMLDepth = 32
)

// pnpmLockDoc is a pnpm-lock.yaml read for its meaning: every scalar is the
// text it was written as (null is nil), mappings are maps and sequences slices.
type pnpmLockDoc struct {
	top map[string]any
	// versionText and versionIsScalar describe the lockfileVersion member.
	versionText     string
	versionIsScalar bool
}

// readYAMLRoot parses a YAML file that must be exactly one document (a second
// one, or a syntax error anywhere, is refused), without anchors, aliases or
// merge keys, with no repeated key in any mapping, and within the bounds
// above. It returns the root node of the document.
func readYAMLRoot(data []byte) (*yaml.Node, error) {
	if len(data) > maxYAMLBytes {
		return nil, fmt.Errorf("the file is over %d bytes", maxYAMLBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	var second yaml.Node
	if err := dec.Decode(&second); err != io.EOF {
		if err == nil {
			return nil, errors.New("the file holds more than one YAML document")
		}
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("not a YAML document")
	}
	root := doc.Content[0]
	count := 0
	if err := yamlWalk(root, 0, &count); err != nil {
		return nil, err
	}
	return root, nil
}

// readPnpmLock parses pnpm-lock.yaml. It must be exactly one YAML document
// (a second one, or a syntax error anywhere, is refused), without anchors,
// aliases or merge keys, with no repeated key in any mapping and no two keys
// that differ only in case in a mapping of fixed words (see yamlLevel), and
// within the bounds above.
func readPnpmLock(data []byte) (*pnpmLockDoc, error) {
	root, err := readYAMLRoot(data)
	if err != nil {
		return nil, err
	}
	if err := yamlLevel(root); err != nil {
		return nil, err
	}
	out := &pnpmLockDoc{}
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("the document is not a mapping")
	}
	v, err := yamlValue(root)
	if err != nil {
		return nil, err
	}
	out.top, _ = v.(map[string]any)
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "lockfileVersion" {
			out.versionText, out.versionIsScalar = root.Content[i+1].Value, root.Content[i+1].Kind == yaml.ScalarNode
		}
	}
	return out, nil
}

// yamlPlainTags are the tags a lockfile may spell out.
var yamlPlainTags = keySet("!!str", "!!int", "!!bool", "!!null", "!!map", "!!seq", "!!float")

// yamlWalk counts the nodes and refuses what the lockfile format does not
// use: anchors, aliases, merge keys, non-scalar keys, repeated keys in any
// mapping (unrecognized members included), deep nesting.
func yamlWalk(n *yaml.Node, depth int, count *int) error {
	if *count++; *count > maxYAMLNodes {
		return fmt.Errorf("the file holds more than %d YAML nodes", maxYAMLNodes)
	}
	if depth > maxYAMLDepth {
		return fmt.Errorf("the file nests more than %d levels", maxYAMLDepth)
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return errors.New("the file uses a YAML anchor or alias")
	}
	// A tag written in the file may change what a value is (a !!binary or a
	// custom tag); only the standard tags of the types the lockfile uses are
	// read.
	if n.Style&yaml.TaggedStyle != 0 && !yamlPlainTags[n.Tag] {
		return fmt.Errorf("the file uses the YAML tag %q", clip(n.Tag, 100))
	}
	if n.Kind == yaml.MappingNode {
		keys := make(map[string]struct{}, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return errors.New("the file has a mapping key that is not a scalar")
			}
			if _, dup := keys[k.Value]; dup {
				return fmt.Errorf("the key %q is repeated in a mapping", clip(k.Value, 100))
			}
			keys[k.Value] = struct{}{}
			if k.Tag == "!!merge" || k.Value == "<<" {
				return errors.New("the file uses a YAML merge key")
			}
		}
	}
	for _, c := range n.Content {
		if err := yamlWalk(c, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

// yamlValue converts a node: a mapping to map[string]any, a sequence to
// []any, a null to nil and any other scalar to its text.
func yamlValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			v, err := yamlValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[n.Content[i].Value] = v // repeated keys were refused by yamlWalk
		}
		return m, nil
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlValue(c)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		return s, nil
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return nil, nil
		}
		return n.Value, nil
	}
	return nil, errors.New("an unsupported YAML node")
}

// yamlMembers returns the members of a mapping, refusing a repeated key. A
// node that is not a mapping has none.
func yamlMembers(n *yaml.Node) (map[string]*yaml.Node, error) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	out := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("the key %q is repeated", clip(k, 100))
		}
		out[k] = n.Content[i+1]
	}
	return out, nil
}

// yamlFixed checks a mapping of fixed words for case clashes.
func yamlFixed(n *yaml.Node) (map[string]*yaml.Node, error) {
	m, err := yamlMembers(n)
	if err != nil || m == nil {
		return m, err
	}
	seen := make(map[string]string, len(m))
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		l := strings.ToLower(k)
		if other, clash := seen[l]; clash {
			return nil, fmt.Errorf("the keys %q and %q differ only in case", clip(other, 100), clip(k, 100))
		}
		seen[l] = k
	}
	return m, nil
}

// yamlLevel checks the keys of the file's mappings. The mappings keyed by
// package names (packages, snapshots, the dependency maps, overrides) are
// checked for repeated keys only; the others hold fixed words.
func yamlLevel(top *yaml.Node) error {
	t, err := yamlFixed(top)
	if err != nil {
		return err
	}
	for _, sect := range []string{"packages", "snapshots"} {
		sm, err := yamlMembers(t[sect])
		if err != nil {
			return err
		}
		for _, pk := range sm {
			f, err := yamlFixed(pk)
			if err != nil {
				return err
			}
			// A deprecation note is text, or nothing: a plain false or 1 is a
			// boolean or a number to pnpm, and becomes text only when the file is
			// converted for reading.
			if d := f["deprecated"]; d != nil && !(d.Kind == yaml.ScalarNode && (d.Tag == "!!str" || d.Tag == "!!null")) {
				return fmt.Errorf("the package %q has a deprecated member that is not text", clip(pkgKey(sm, pk), 100))
			}
			if res := f["resolution"]; res != nil {
				if _, err := yamlFixed(res); err != nil {
					return err
				}
			}
			for _, grp := range []string{"dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "engines"} {
				if _, err := yamlMembers(f[grp]); err != nil {
					return err
				}
			}
		}
	}
	if _, err := yamlMembers(t["overrides"]); err != nil {
		return err
	}
	imps, err := yamlMembers(t["importers"])
	if err != nil {
		return err
	}
	for _, imp := range imps {
		f, err := yamlFixed(imp)
		if err != nil {
			return err
		}
		for _, grp := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			deps, err := yamlMembers(f[grp])
			if err != nil {
				return err
			}
			for _, d := range deps {
				if _, err := yamlFixed(d); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// --- TOML (uv.lock) ---

// checkTOMLKeys refuses a uv.lock whose fixed-word tables hold two keys that
// differ only in case. (The TOML reader refuses a repeated key itself.)
func checkTOMLKeys(doc map[string]any) error {
	fixed := func(m map[string]any) error {
		seen := map[string]string{}
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			l := strings.ToLower(k)
			if other, clash := seen[l]; clash {
				return fmt.Errorf("the keys %q and %q differ only in case", clip(other, 100), clip(k, 100))
			}
			seen[l] = k
		}
		return nil
	}
	if err := fixed(doc); err != nil {
		return err
	}
	tables := func(v any) []map[string]any {
		var out []map[string]any
		switch t := v.(type) {
		case map[string]any:
			out = append(out, t)
		case []any:
			for _, e := range t {
				if m, ok := e.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
		return out
	}
	pkgs, _ := doc["package"].([]any)
	for _, p := range pkgs {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if err := fixed(pm); err != nil {
			return err
		}
		for _, key := range []string{"source", "sdist", "wheels", "dependencies", "metadata"} {
			for _, m := range tables(pm[key]) {
				if err := fixed(m); err != nil {
					return err
				}
			}
		}
		if md, ok := pm["metadata"].(map[string]any); ok {
			for _, m := range tables(md["requires-dist"]) {
				if err := fixed(m); err != nil {
					return err
				}
			}
		}
		for _, key := range []string{"optional-dependencies", "dev-dependencies"} {
			if groups, ok := pm[key].(map[string]any); ok {
				for _, l := range groups {
					for _, m := range tables(l) {
						if err := fixed(m); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

// pkgKey names a package record of a section by its value, for a message.
func pkgKey(section map[string]*yaml.Node, rec *yaml.Node) string {
	for k, v := range section {
		if v == rec {
			return k
		}
	}
	return ""
}
