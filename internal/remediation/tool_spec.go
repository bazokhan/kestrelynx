package remediation

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The files, besides the manifest and the lockfile, that declare which
// runtime or tool version a project wants. They are read from the directory
// of the lockfile.
const (
	nodeVersionFileName    = ".node-version"
	nvmrcFileName          = ".nvmrc"
	pythonVersionFileName  = ".python-version"
	pythonVersionsFileName = ".python-versions"
	uvTomlFileName         = "uv.toml"
)

// ToolSpecFileNames are the files, in the directory of the lockfile, that
// the manager's declarations are read from besides its manifest and lockfile.
// A file that exists is read and one that does not is recorded as absent.
// uv also reads uv.toml in the directories above (see ToolSpecInput.UvToml).
func ToolSpecFileNames(m DependencyManager) []string {
	switch m {
	case ManagerNpm, ManagerPnpm:
		return []string{nodeVersionFileName, nvmrcFileName}
	case ManagerUv:
		return []string{pythonVersionFileName, pythonVersionsFileName}
	}
	return nil
}

// ToolSpecInput is what a unit's declarations are read from.
type ToolSpecInput struct {
	Manager DependencyManager
	// Manifest is package.json (npm, pnpm) or pyproject.toml (uv), and Lock
	// the lockfile.
	Manifest []byte
	Lock     []byte
	// Files holds the content of the files of ToolSpecFileNames that exist,
	// by name; a file that does not exist has no key.
	Files map[string][]byte
	// UvToml lists the paths of the uv.toml files that exist in the
	// directory of the lockfile and above it, up to the root of the
	// repository.
	UvToml []string
}

// ToolDeclaration is one declaration that was read, for the record.
type ToolDeclaration struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}

// ToolSpec is what a unit's declarations come to: the runtime and the exact
// release of the package manager the update runs with.
type ToolSpec struct {
	Manager DependencyManager
	// Runtime is the id of the runtime the job runs in.
	Runtime string
	// ToolVersion is the exact version of the manager; ToolSource says
	// whether the project declared it or the build's default is used.
	ToolVersion string
	ToolSource  string
	// SpecHash is the hash the project declared with the version, written
	// "<algorithm>.<hex>", or "".
	SpecHash string
	// Requested are the ids of the runtimes of the table that every
	// declaration about the language allows, lowest first; with no such
	// declaration it is empty.
	Requested    []string
	Declarations []ToolDeclaration
}

const toolSourceDeclared = "declared"

// ResolveToolSpec reads the declarations of a unit and decides the runtime and
// the package manager release the update runs with. A problem is returned as
// an *UnsupportedError, which makes the unit a manual one before anything runs:
//   - a declaration that cannot be read, or that contradicts another;
//   - one the update cannot run with: the runtime is the default Node.js
//     with npm or pnpm and the default Python with uv (and pip), so a
//     declaration about the runtime that does not hold there, a manager
//     version outside the supported range or one that is a pre-release, and
//     version ranges the build's default manager version is outside of; a
//     project never gets another manager version than the one it declares;
//   - a setting that makes the manager fetch a tool or a runtime itself.
//
// Mistakes in the input itself (a lockfile that is not the manager's) are not
// checked here; the parsers of the files do.
func ResolveToolSpec(in ToolSpecInput) (ToolSpec, *UnsupportedError) {
	switch in.Manager {
	case ManagerNpm, ManagerPnpm:
		return resolveNodeSpec(in)
	case ManagerUv:
		return resolveUvSpec(in)
	case ManagerPip:
		// pip's version is the one the Python image carries and declares
		// nothing of its own.
		return ToolSpec{Manager: ManagerPip, Runtime: defaultPythonRuntime}, nil
	}
	return ToolSpec{}, unsupported(ReasonManagerSpecUnsupported, "%s has no tool declarations that are read", in.Manager)
}

// RequestedRuntimes returns the ids of the runtimes of the table that every
// declaration about the language of the unit allows, lowest first: Node.js
// series for npm and pnpm, Python series for uv. The declarations are read
// and checked for consistency only; whether the update can run in one of
// them, or whether it is past the end of its support, is for the caller to
// judge from the table. An empty list means the declarations name no series
// of the table. A declaration that cannot be read or that contradicts
// another is an error.
func RequestedRuntimes(in ToolSpecInput) ([]string, *UnsupportedError) {
	switch in.Manager {
	case ManagerNpm, ManagerPnpm:
		d, err := readNodeDeclarations(in)
		if err != nil {
			return nil, err
		}
		return nodeSeriesOf(d), nil
	case ManagerUv:
		d, err := readPythonDeclarations(in)
		if err != nil {
			return nil, err
		}
		return pythonSeriesOf(d), nil
	}
	return nil, nil
}

// declared is one declaration of a version: where it was read, what it says
// and the versions it allows.
type declared struct {
	source string
	value  string
	set    versionSet
}

// nodeDecl is one declaration about the Node.js version.
type nodeDecl struct {
	declared
	// major is the major version a file names, "" for a range: a file
	// matches the runtime when the major versions agree, a range when it
	// allows the runtime's exact version.
	major string
}

// nodeDeclarations are the declarations about Node.js of a unit.
type nodeDeclarations struct {
	decls []nodeDecl
	top   map[string]json.RawMessage
}

// readNodeDeclarations reads the declarations about Node.js and checks that
// they can all hold.
func readNodeDeclarations(in ToolSpecInput) (*nodeDeclarations, *UnsupportedError) {
	top, err := strictObject(in.Manifest)
	if err != nil || top == nil {
		return nil, unsupported(ReasonUnparsableSource, "package.json cannot be read")
	}
	d := &nodeDeclarations{top: top}
	for _, f := range []string{nodeVersionFileName, nvmrcFileName} {
		data, ok := in.Files[f]
		if !ok {
			continue
		}
		decl, uerr := parseNodeVersionFile(f, data)
		if uerr != nil {
			return nil, uerr
		}
		d.decls = append(d.decls, decl)
	}
	engines, uerr := objectField(top, "engines", ReasonNodeSpecInvalid)
	if uerr != nil {
		return nil, uerr
	}
	if raw, ok := engines["node"]; ok {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, unsupported(ReasonNodeSpecInvalid, "engines.node is not a string")
		}
		decl, uerr := rangeDecl("engines.node", s)
		if uerr != nil {
			return nil, uerr
		}
		d.decls = append(d.decls, decl)
	}
	runtimes, uerr := runtimeEntries(top, engines)
	if uerr != nil {
		return nil, uerr
	}
	var nodes []engineEntry
	for _, e := range runtimes {
		if e.name == "node" {
			nodes = append(nodes, e)
		}
	}
	switch {
	case len(runtimes) > 0 && len(nodes) == 0:
		return nil, unsupported(ReasonNodeSpecUnsupported, "%s declares a runtime other than node", runtimes[0].where)
	case len(nodes) > 1:
		return nil, unsupported(ReasonNodeSpecInvalid, "%s and %s both declare node", nodes[0].where, nodes[1].where)
	case len(nodes) == 1 && nodes[0].version != "":
		decl, uerr := rangeDecl(nodes[0].where+" node", nodes[0].version)
		if uerr != nil {
			return nil, uerr
		}
		d.decls = append(d.decls, decl)
	}
	if uerr := nodeConsistency(d.decls); uerr != nil {
		return nil, uerr
	}
	return d, nil
}

func rangeDecl(source, text string) (nodeDecl, *UnsupportedError) {
	set, ok := rangeSet(text)
	if !ok {
		return nodeDecl{}, unsupported(ReasonNodeSpecInvalid, "%s %q is not a version range that is read", source, clip(text, 80))
	}
	if full, ok := fullVersion(text); ok {
		set = pointSet(full)
	}
	return nodeDecl{declared: declared{source, text, set}}, nil
}

// nvmrcAliases are the names of release lines nvm accepts, with the major
// version each stands for.
var nvmrcAliases = map[string]string{
	"argon": "4", "boron": "6", "carbon": "8", "dubnium": "10", "erbium": "12", "fermium": "14",
	"gallium": "16", "hydrogen": "18", "iron": "20", "jod": "22", "krypton": "24",
}

// latestLTSSeries is the Node.js series that "lts/*" stands for: the newest
// one of the runtime table in long-term support.
func latestLTSSeries() (string, bool) {
	best, found := 0, false
	for _, r := range worker.Runtimes() {
		if r.Kind != worker.KindNode || r.Support != "lts" {
			continue
		}
		if n, err := strconv.Atoi(r.Series); err == nil && (!found || n > best) {
			best, found = n, true
		}
	}
	return strconv.Itoa(best), found
}

// parseNodeVersionFile reads .node-version or .nvmrc: the first line that is
// not empty, a version with its major version and optionally the minor and the
// patch, written with or without a leading "v". .nvmrc also takes the names
// of long-term support lines.
func parseNodeVersionFile(name string, data []byte) (nodeDecl, *UnsupportedError) {
	line := firstLine(data)
	if line == "" || len(line) > 100 {
		return nodeDecl{}, unsupported(ReasonNodeSpecInvalid, "%s has no version on its first line, or the line is too long", name)
	}
	text := strings.TrimPrefix(strings.ToLower(line), "v")
	if name == nvmrcFileName {
		switch {
		case line == "node" || line == "stable" || line == "latest" || line == "current" || line == "system" || line == "iojs":
			return nodeDecl{}, unsupported(ReasonNodeSpecUnsupported, "%s names %q, which is not a version", name, line)
		case strings.HasPrefix(strings.ToLower(line), "lts/"):
			alias := strings.ToLower(line[len("lts/"):])
			major := nvmrcAliases[alias]
			if alias == "*" {
				var ok bool
				if major, ok = latestLTSSeries(); !ok {
					return nodeDecl{}, unsupported(ReasonNodeSpecUnsupported, "%s names %q, and no Node.js series in the runtime table is in long-term support", name, line)
				}
			}
			if major == "" {
				return nodeDecl{}, unsupported(ReasonNodeSpecInvalid, "%s names %q, which is not a release line that is read", name, clip(line, 40))
			}
			return fileDecl(name, line, partial{parts: [3]string{major}, n: 1}), nil
		}
	}
	if strings.ContainsAny(text, "xX*") {
		return nodeDecl{}, unsupported(ReasonNodeSpecInvalid, "%s %q is not a version", name, clip(line, 40))
	}
	p, ok := parsePartial(text)
	if !ok || p.n == 0 {
		return nodeDecl{}, unsupported(ReasonNodeSpecInvalid, "%s %q is not a version", name, clip(line, 40))
	}
	return fileDecl(name, line, p), nil
}

func fileDecl(name, value string, p partial) nodeDecl {
	return nodeDecl{declared: declared{name, value, partialSet(p)}, major: p.parts[0]}
}

// firstLine is the first line of a file that is not empty, without
// surrounding spaces.
func firstLine(data []byte) string {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	for _, l := range strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' || r == '\r' }) {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// consistency requires one version to satisfy every declaration. The
// error names the first two declarations that exclude each other.
func consistency(decls []declared, reason Reason, what string) *UnsupportedError {
	all := allVersions()
	for _, d := range decls {
		all = all.intersect(d.set)
	}
	if !all.isEmpty() {
		return nil
	}
	for i := range decls {
		for j := i + 1; j < len(decls); j++ {
			if decls[i].set.intersect(decls[j].set).isEmpty() {
				return unsupported(reason, "%s (%s) and %s (%s) allow no %s version in common",
					decls[i].source, clip(decls[i].value, 60), decls[j].source, clip(decls[j].value, 60), what)
			}
		}
	}
	var parts []string
	for _, d := range decls {
		parts = append(parts, d.source+" ("+clip(d.value, 60)+")")
	}
	return unsupported(reason, "%s allow no %s version in common", strings.Join(parts, ", "), what)
}

func nodeConsistency(decls []nodeDecl) *UnsupportedError {
	ds := make([]declared, len(decls))
	for i, d := range decls {
		ds[i] = d.declared
	}
	return consistency(ds, ReasonNodeSpecConflict, "Node.js")
}

// nodeSeriesOf lists the Node.js runtimes of the table that the declarations
// allow some version of.
func nodeSeriesOf(d *nodeDeclarations) []string {
	var out []string
	for _, r := range worker.Runtimes() {
		if r.Kind != worker.KindNode {
			continue
		}
		major := triple{r.Series, "0", "0"}
		span := versionSet{{lo: bound{set: true, v: major}, hi: bound{set: true, v: triple{incDecimal(r.Series), "0", "0"}, open: true}}}
		ok := true
		for _, decl := range d.decls {
			if span = span.intersect(decl.set); span.isEmpty() {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, r.ID)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return seriesNumber(out[i]) < seriesNumber(out[j]) })
	return out
}

// seriesNumber orders runtime ids by their series ("node22" before "node24",
// "python3.9" before "python3.13").
func seriesNumber(id string) int {
	digits := strings.TrimLeft(id, "abcdefghijklmnopqrstuvwxyz")
	parts := strings.SplitN(digits, ".", 2)
	n := 0
	for _, p := range parts {
		v, _ := strconv.Atoi(p)
		n = n*1000 + v
	}
	return n
}

// resolveNodeSpec resolves the declarations of an npm or pnpm unit.
func resolveNodeSpec(in ToolSpecInput) (ToolSpec, *UnsupportedError) {
	spec := ToolSpec{Manager: in.Manager, Runtime: defaultNodeRuntime}
	if uerr := nodeFetchConfigProblem(in); uerr != nil {
		return spec, uerr
	}
	d, uerr := readNodeDeclarations(in)
	if uerr != nil {
		return spec, uerr
	}
	spec.Requested = nodeSeriesOf(d)
	for _, decl := range d.decls {
		spec.Declarations = append(spec.Declarations, ToolDeclaration{Source: decl.source, Value: clip(decl.value, 100)})
	}

	rt, ok := worker.LookupRuntime(defaultNodeRuntime)
	if !ok {
		return spec, unsupported(ReasonNodeSpecUnsupported, "the runtime %s is not in the runtime table", defaultNodeRuntime)
	}
	exact, ok := fullVersion(rt.Version)
	if !ok {
		return spec, unsupported(ReasonNodeSpecUnsupported, "the runtime %s has the version %q", rt.ID, rt.Version)
	}
	for _, decl := range d.decls {
		switch {
		case decl.major != "" && decl.major != rt.Series:
			return spec, unsupported(ReasonNodeSpecUnsupported, "%s asks for Node.js %s, and updates run on Node.js %s so far", decl.source, decl.value, rt.Version)
		case decl.major == "" && !decl.set.contains(exact):
			return spec, unsupported(ReasonNodeSpecUnsupported, "%s %s does not allow Node.js %s, which updates run on so far", decl.source, clip(decl.value, 80), rt.Version)
		}
	}

	mgr, uerr := resolveNodeManager(in, d.top)
	if uerr != nil {
		return spec, uerr
	}
	spec.ToolVersion, spec.ToolSource, spec.SpecHash = mgr.version, mgr.source, mgr.specHash
	spec.Declarations = append(spec.Declarations, mgr.declarations...)
	return spec, nil
}

// objectField reads a member of a JSON object that must itself be an object (or
// absent) as a map of its members.
func objectField(obj map[string]json.RawMessage, key string, invalid Reason) (map[string]json.RawMessage, *UnsupportedError) {
	raw, ok := obj[key]
	if !ok {
		return nil, nil
	}
	m, err := nameMap(raw)
	if err != nil || m == nil {
		return nil, unsupported(invalid, "package.json %s is not an object", key)
	}
	return m, nil
}

// engineEntry is one element of devEngines.runtime or engines.runtime.
type engineEntry struct {
	where   string
	name    string
	version string
	onFail  string
}

// entryList reads a declaration given as one object or as a list of objects.
func entryList(raw json.RawMessage, where string, invalid Reason) ([]engineEntry, *UnsupportedError) {
	raw = bytes.TrimSpace(raw)
	var items []json.RawMessage
	switch {
	case bytes.HasPrefix(raw, []byte("{")):
		items = []json.RawMessage{raw}
	case bytes.HasPrefix(raw, []byte("[")):
		if json.Unmarshal(raw, &items) != nil || len(items) > 64 {
			return nil, unsupported(invalid, "%s is not a list of at most 64 objects", where)
		}
	default:
		return nil, unsupported(invalid, "%s is neither an object nor a list of objects", where)
	}
	var out []engineEntry
	for _, item := range items {
		var m map[string]any
		if json.Unmarshal(item, &m) != nil || m == nil {
			return nil, unsupported(invalid, "%s has an element that is not an object", where)
		}
		e := engineEntry{where: where}
		for key, dst := range map[string]*string{"name": &e.name, "version": &e.version, "onFail": &e.onFail} {
			v, present := m[key]
			if !present {
				continue
			}
			s, isString := v.(string)
			if !isString {
				return nil, unsupported(invalid, "%s: %s is not a string", where, key)
			}
			*dst = s
		}
		if e.name == "" {
			return nil, unsupported(invalid, "%s has an element without a name", where)
		}
		out = append(out, e)
	}
	return out, nil
}

// runtimeEntries lists the runtimes devEngines.runtime and engines.runtime
// declare.
func runtimeEntries(top, engines map[string]json.RawMessage) ([]engineEntry, *UnsupportedError) {
	var out []engineEntry
	dev, uerr := objectField(top, "devEngines", ReasonNodeSpecInvalid)
	if uerr != nil {
		return nil, uerr
	}
	for where, raw := range map[string]json.RawMessage{"devEngines.runtime": dev["runtime"], "engines.runtime": engines["runtime"]} {
		if raw == nil {
			continue
		}
		es, uerr := entryList(raw, where, ReasonNodeSpecInvalid)
		if uerr != nil {
			return nil, uerr
		}
		out = append(out, es...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].where < out[j].where })
	return out, nil
}
