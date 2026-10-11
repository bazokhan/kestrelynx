package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// This file edits the version specifier of a direct dependency in a manifest
// when the specifier does not allow the version a fix needs. Only the plainest
// specifiers are edited, and only the version inside them is replaced, byte
// for byte, so that the formatting, the order of the keys and everything else
// in the file stay as they were. After an edit the file is read again and
// must be the original with that one value changed.

// Bounds on an edit: the nesting the byte scanners follow, how many
// specifiers one update edits, and how large a manifest is edited.
const (
	maxManifestDepth = 64
	maxManifestEdits = 256
	maxManifestBytes = 8 << 20
	// maxManifestRequirements bounds the requirement strings of a
	// pyproject.toml one update reads.
	maxManifestRequirements = 200000
)

// checkEditable refuses an edit that is over the bounds, or after the update's
// time is over.
func checkEditable(ctx context.Context, data []byte, edits int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if edits > maxManifestEdits {
		return errManifestEditLimit
	}
	if len(data) > maxManifestBytes {
		return fmt.Errorf("%w (the manifest is over %d bytes)", errManifestEditLimit, maxManifestBytes)
	}
	return nil
}

// errManifestEditLimit: the update asks for more edits than one update makes.
var errManifestEditLimit = fmt.Errorf("the manifest or its edits are over the limits of one update: more than %d specifiers would be edited, or the manifest is over %d bytes", maxManifestEdits, maxManifestBytes)

// --- package.json ---

// npmEditableFields are the sections of package.json whose specifiers are
// edited. A peer dependency states what the project's own consumers must
// provide, which is not this program's to change.
var npmEditableFields = keySet("dependencies", "devDependencies", "optionalDependencies")

var npmSimpleSpecRE = regexp.MustCompile(`^(=|\^|~)?([0-9]+\.[0-9]+\.[0-9]+)$`)

// npmEditedSpec returns spec with its version replaced by target and its
// operator kept, for the specifiers X.Y.Z, =X.Y.Z, ^X.Y.Z and ~X.Y.Z with a
// plain version. ok is false for any other specifier, or a target that is not
// a plain version, or when the result would not allow the target.
func npmEditedSpec(spec, target string) (string, bool) {
	m := npmSimpleSpecRE.FindStringSubmatch(spec)
	if m == nil || !worker.ValidSemver(m[2]) || !worker.ValidSemver(target) || strings.ContainsAny(target, "-+") {
		return "", false
	}
	out := m[1] + target
	tv, ok := parseSemver(target)
	if !ok {
		return "", false
	}
	if allowed, evaluable := npmRangeAllows(out, tv); !evaluable || !allowed {
		return "", false
	}
	return out, true
}

// releaseLine is the part of a version a major change is judged on: the major
// version, and for 0.x the minor version as well (and the patch for 0.0.x).
func releaseLine(release []int) string {
	for len(release) < 3 {
		release = append(release, 0)
	}
	switch {
	case release[0] != 0:
		return strconv.Itoa(release[0])
	case release[1] != 0:
		return "0." + strconv.Itoa(release[1])
	}
	return "0.0." + strconv.Itoa(release[2])
}

func semverRelease(v string) []int {
	var out []int
	for _, p := range strings.SplitN(strings.TrimLeft(v, "=^~"), ".", 3) {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// jsonSkipSpace returns the offset of the first byte at or after i that is not
// JSON white space.
func jsonSkipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// jsonStringEnd returns the offset just after the string that starts at i.
func jsonStringEnd(b []byte, i int) (int, error) {
	if i >= len(b) || b[i] != '"' {
		return 0, errors.New("not a string")
	}
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, errors.New("unterminated string")
}

// jsonValueEnd returns the offset just after the value that starts at i.
func jsonValueEnd(b []byte, i, depth int) (int, error) {
	if depth > maxManifestDepth {
		return 0, errors.New("nested too deep")
	}
	i = jsonSkipSpace(b, i)
	if i >= len(b) {
		return 0, errors.New("unexpected end")
	}
	switch b[i] {
	case '"':
		return jsonStringEnd(b, i)
	case '{', '[':
		closer := byte('}')
		if b[i] == '[' {
			closer = ']'
		}
		j := jsonSkipSpace(b, i+1)
		if j < len(b) && b[j] == closer {
			return j + 1, nil
		}
		for {
			if closer == '}' {
				k, err := jsonStringEnd(b, jsonSkipSpace(b, j))
				if err != nil {
					return 0, err
				}
				j = jsonSkipSpace(b, k)
				if j >= len(b) || b[j] != ':' {
					return 0, errors.New("no colon")
				}
				j++
			}
			k, err := jsonValueEnd(b, j, depth+1)
			if err != nil {
				return 0, err
			}
			j = jsonSkipSpace(b, k)
			if j >= len(b) {
				return 0, errors.New("unexpected end")
			}
			if b[j] == ',' {
				j = jsonSkipSpace(b, j+1)
				continue
			}
			if b[j] == closer {
				return j + 1, nil
			}
			return 0, errors.New("unexpected byte")
		}
	}
	j := i
	for j < len(b) && !strings.ContainsRune(" \t\r\n,]}", rune(b[j])) {
		j++
	}
	if j == i {
		return 0, errors.New("unexpected byte")
	}
	return j, nil
}

// jsonMember is a member of an object: its decoded key and where its value is.
type jsonMember struct {
	key        string
	start, end int
}

// jsonMembers lists the members of the object that starts at i.
func jsonMembers(b []byte, i int) ([]jsonMember, error) {
	i = jsonSkipSpace(b, i)
	if i >= len(b) || b[i] != '{' {
		return nil, errors.New("not an object")
	}
	var out []jsonMember
	j := jsonSkipSpace(b, i+1)
	if j < len(b) && b[j] == '}' {
		return out, nil
	}
	for {
		j = jsonSkipSpace(b, j)
		ke, err := jsonStringEnd(b, j)
		if err != nil {
			return nil, err
		}
		var key string
		if err := json.Unmarshal(b[j:ke], &key); err != nil {
			return nil, err
		}
		j = jsonSkipSpace(b, ke)
		if j >= len(b) || b[j] != ':' {
			return nil, errors.New("no colon")
		}
		vs := jsonSkipSpace(b, j+1)
		ve, err := jsonValueEnd(b, vs, 1)
		if err != nil {
			return nil, err
		}
		out = append(out, jsonMember{key, vs, ve})
		j = jsonSkipSpace(b, ve)
		if j < len(b) && b[j] == ',' {
			j++
			continue
		}
		if j < len(b) && b[j] == '}' {
			return out, nil
		}
		return nil, errors.New("unexpected byte")
	}
}

// applyReplacements replaces the byte ranges of b with the given texts. The
// ranges are put in order once; ranges that overlap are an error.
func applyReplacements(b []byte, reps []replacement) ([]byte, error) {
	sorted := append([]replacement(nil), reps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].start < sorted[j].start })
	out := make([]byte, 0, len(b))
	pos := 0
	for _, r := range sorted {
		if r.start < pos || r.end < r.start || r.end > len(b) {
			return nil, errors.New("two edits are in the same place")
		}
		out = append(out, b[pos:r.start]...)
		out = append(out, r.text...)
		pos = r.end
	}
	return append(out, b[pos:]...), nil
}

type replacement struct {
	start, end int
	text       string
}

// editPackageJSON replaces the specifier of each edit in data. Each edit's
// current specifier must be the text there; the result is read again and must
// be the original document with those values changed and nothing else. The
// document is scanned once: the sections and their members are indexed, and
// each edit is looked up in the index.
func editPackageJSON(ctx context.Context, data []byte, edits []ManifestEdit) ([]byte, error) {
	if err := checkEditable(ctx, data, len(edits)); err != nil {
		return nil, err
	}
	top, err := jsonMembers(data, 0)
	if err != nil {
		return nil, err
	}
	sections := map[string]int{}
	for _, m := range top {
		sections[m.key] = m.start
	}
	index := map[string]map[string]jsonMember{}
	var reps []replacement
	for _, e := range edits {
		members, scanned := index[e.Section]
		if !scanned {
			start, ok := sections[e.Section]
			if !ok {
				return nil, fmt.Errorf("%s is not in the file", e.Section)
			}
			list, err := jsonMembers(data, start)
			if err != nil {
				return nil, err
			}
			members = make(map[string]jsonMember, len(list))
			for _, m := range list {
				members[m.key] = m
			}
			index[e.Section] = members
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		m, ok := members[e.Name]
		if !ok {
			return nil, fmt.Errorf("%s of %s is not in the file", e.Name, e.Section)
		}
		if data[m.start] != '"' {
			return nil, errors.New("the value is not a string")
		}
		s, t := m.start+1, m.end-1
		if string(data[s:t]) != e.From {
			return nil, fmt.Errorf("%s of %s is written in a form that is not the plain text %q", e.Name, e.Section, e.From)
		}
		reps = append(reps, replacement{s, t, e.To})
	}
	out, err := applyReplacements(data, reps)
	if err != nil {
		return nil, err
	}

	want, err := decodeJSONValue(data)
	if err != nil {
		return nil, err
	}
	for _, e := range edits {
		sec, _ := want.(map[string]any)[e.Section].(map[string]any)
		if sec == nil || sec[e.Name] != e.From {
			return nil, fmt.Errorf("%s of %s is not as expected", e.Name, e.Section)
		}
		sec[e.Name] = e.To
	}
	got, err := decodeJSONValue(out)
	if err != nil {
		return nil, fmt.Errorf("the edited file cannot be read: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		return nil, errors.New("the edited file differs from the original in more than the edited values")
	}
	if _, err := readManifest(out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- pyproject.toml ---

var uvEditRE = regexp.MustCompile(`^(\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]\n]*\])?\s*)(==|~=)(\s*)([0-9]+(?:\.[0-9]+)*)(\s*(?:;.*)?)$`)

var plainReleaseRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// uvEditedRequirement returns the requirement string s with its version
// replaced by target, for a requirement whose only version clause is name==X
// or name~=X.Y (the number of components of ~= is kept); extras and a marker
// stay as they are. ok is false for any other form, or a target that is not a
// plain release, or when the result would not allow the target.
func uvEditedRequirement(s, target string) (string, bool) {
	m := uvEditRE.FindStringSubmatch(s)
	if m == nil || !plainReleaseRE.MatchString(target) {
		return "", false
	}
	ver := target
	if m[2] == "~=" {
		n := len(strings.Split(m[4], "."))
		if n < 2 {
			return "", false
		}
		parts := strings.Split(target, ".")
		for len(parts) < n {
			parts = append(parts, "0")
		}
		ver = strings.Join(parts[:n], ".")
	}
	out := m[1] + m[2] + m[3] + ver + m[5]
	tv, ok := parsePEP440(target)
	if !ok {
		return "", false
	}
	_, constraint, ok := pythonRequirement(out)
	if !ok {
		return "", false
	}
	if allowed, evaluable := pySatisfies(tv, constraint); !evaluable || !allowed {
		return "", false
	}
	return out, true
}

// uvRequirementRelease is the numeric release of the version clause of a
// requirement string accepted by uvEditRE.
func uvRequirementRelease(s string) []int {
	m := uvEditRE.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	var out []int
	for _, p := range strings.Split(m[4], ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// tomlSkipSpace skips white space, newlines and comments.
func tomlSkipSpace(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
			i++
		case '#':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		default:
			return i
		}
	}
	return i
}

// tomlStringEnd returns the offset just after the string that starts at i.
func tomlStringEnd(b []byte, i int) (int, error) {
	if i >= len(b) {
		return 0, errors.New("unexpected end")
	}
	q := b[i]
	if q != '"' && q != '\'' {
		return 0, errors.New("not a string")
	}
	if bytes.HasPrefix(b[i:], bytes.Repeat([]byte{q}, 3)) {
		end := bytes.Index(b[i+3:], bytes.Repeat([]byte{q}, 3))
		if end < 0 {
			return 0, errors.New("unterminated string")
		}
		j := i + 3 + end + 3
		for j < len(b) && b[j] == q { // up to two more quotes belong to the text
			j++
		}
		return j, nil
	}
	for j := i + 1; j < len(b); j++ {
		switch {
		case b[j] == '\n':
			return 0, errors.New("unterminated string")
		case q == '"' && b[j] == '\\':
			j++
		case b[j] == q:
			return j + 1, nil
		}
	}
	return 0, errors.New("unterminated string")
}

// tomlValueEnd returns the offset just after the value that starts at i.
func tomlValueEnd(b []byte, i, depth int) (int, error) {
	if depth > maxManifestDepth {
		return 0, errors.New("nested too deep")
	}
	if i >= len(b) {
		return 0, errors.New("unexpected end")
	}
	switch b[i] {
	case '"', '\'':
		return tomlStringEnd(b, i)
	case '[', '{':
		closer := byte(']')
		if b[i] == '{' {
			closer = '}'
		}
		j := i + 1
		for {
			j = tomlSkipSpace(b, j)
			if j >= len(b) {
				return 0, errors.New("unexpected end")
			}
			if b[j] == closer {
				return j + 1, nil
			}
			if closer == '}' {
				k, err := tomlKeyEnd(b, j)
				if err != nil {
					return 0, err
				}
				j = tomlSkipSpace(b, k)
				if j >= len(b) || b[j] != '=' {
					return 0, errors.New("no equals sign")
				}
				j = tomlSkipSpace(b, j+1)
			}
			k, err := tomlValueEnd(b, j, depth+1)
			if err != nil {
				return 0, err
			}
			j = tomlSkipSpace(b, k)
			if j < len(b) && b[j] == ',' {
				j++
			}
		}
	}
	j := i
	for j < len(b) && !strings.ContainsRune(" \t\r\n#,]}", rune(b[j])) {
		j++
	}
	if j == i {
		return 0, errors.New("unexpected byte")
	}
	return j, nil
}

// tomlKeyEnd returns the offset just after the (possibly dotted) key that
// starts at i.
func tomlKeyEnd(b []byte, i int) (int, error) {
	j := i
	for j < len(b) {
		switch {
		case b[j] == '"' || b[j] == '\'':
			k, err := tomlStringEnd(b, j)
			if err != nil {
				return 0, err
			}
			j = k
		case b[j] == ' ' || b[j] == '\t' || b[j] == '.' || b[j] == '-' || b[j] == '_' || b[j] >= '0' && b[j] <= '9' || b[j] >= 'a' && b[j] <= 'z' || b[j] >= 'A' && b[j] <= 'Z':
			j++
		default:
			if j == i {
				return 0, errors.New("no key")
			}
			return j, nil
		}
	}
	return j, nil
}

// tomlStringSpan is a basic or literal single-line string of an array: the
// offsets of the text between the quotes.
type tomlStringSpan struct{ start, end int }

// tomlProjectDependencies finds the strings of the array "dependencies" in
// the [project] table of a pyproject.toml. A file that has the array in
// another form (dotted keys, an inline table, multi-line strings) is an
// error.
func tomlProjectDependencies(b []byte) ([]tomlStringSpan, error) {
	table := ""
	i := 0
	for {
		i = tomlSkipSpace(b, i)
		if i >= len(b) {
			return nil, errors.New("the [project] table has no dependencies array")
		}
		if b[i] == '[' {
			end := bytes.IndexByte(b[i:], ']')
			if end < 0 {
				return nil, errors.New("unterminated table header")
			}
			hdr := strings.TrimSpace(string(b[i+1 : i+end]))
			i += end + 1
			if i < len(b) && b[i] == ']' {
				i++
				hdr = "[" + hdr + "]"
			}
			table = strings.Join(strings.Fields(hdr), "")
			continue
		}
		k, err := tomlKeyEnd(b, i)
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(string(b[i:k]))
		j := tomlSkipSpace(b, k)
		if j >= len(b) || b[j] != '=' {
			return nil, errors.New("a line is not a key and a value")
		}
		j = tomlSkipSpace(b, j+1)
		if table == "project" && key == "dependencies" {
			if j >= len(b) || b[j] != '[' {
				return nil, errors.New("dependencies is not an array")
			}
			var out []tomlStringSpan
			j++
			for {
				j = tomlSkipSpace(b, j)
				if j >= len(b) {
					return nil, errors.New("unterminated array")
				}
				if b[j] == ']' {
					return out, nil
				}
				if b[j] != '"' && b[j] != '\'' {
					return nil, errors.New("an element of dependencies is not a string")
				}
				if bytes.HasPrefix(b[j:], bytes.Repeat([]byte{b[j]}, 3)) {
					return nil, errors.New("dependencies has a multi-line string")
				}
				e, err := tomlStringEnd(b, j)
				if err != nil {
					return nil, err
				}
				out = append(out, tomlStringSpan{j + 1, e - 1})
				j = tomlSkipSpace(b, e)
				if j < len(b) && b[j] == ',' {
					j++
				}
			}
		}
		i, err = tomlValueEnd(b, j, 1)
		if err != nil {
			return nil, err
		}
	}
}

// editPyproject replaces requirement strings in the [project] dependencies of
// data: edits give the index of each and its current and new text. The
// result is read again and must be the original with those strings changed.
func editPyproject(ctx context.Context, data []byte, idx []int, edits []ManifestEdit) ([]byte, error) {
	if err := checkEditable(ctx, data, len(edits)); err != nil {
		return nil, err
	}
	spans, err := tomlProjectDependencies(data)
	if err != nil {
		return nil, err
	}
	orig, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	project, _ := orig["project"].(map[string]any)
	list, _ := project["dependencies"].([]any)
	if len(list) != len(spans) {
		return nil, errors.New("the dependencies array is not read the same by the scanner and the parser")
	}
	for i, s := range spans {
		if v, _ := list[i].(string); v != string(data[s.start:s.end]) {
			return nil, errors.New("a dependency is written with escapes or in a form the scanner does not follow")
		}
	}
	var reps []replacement
	for n, e := range edits {
		i := idx[n]
		if i < 0 || i >= len(spans) || string(data[spans[i].start:spans[i].end]) != e.From {
			return nil, fmt.Errorf("%s is not where it was read", e.From)
		}
		reps = append(reps, replacement{spans[i].start, spans[i].end, e.To})
	}
	out, err := applyReplacements(data, reps)
	if err != nil {
		return nil, err
	}
	for n, e := range edits {
		list[idx[n]] = e.To
	}
	got, err := parseTOML(out)
	if err != nil {
		return nil, fmt.Errorf("the edited file cannot be read: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		return nil, errors.New("the edited file differs from the original in more than the edited values")
	}
	return out, nil
}
