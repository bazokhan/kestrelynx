package remediation

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// publicPyPIIndex is the only index whose registry packages count as PyPI.
const publicPyPIIndex = "https://pypi.org/simple"

// uvLockRevisions are the uv.lock revisions this build reads: the one the work
// image's uv 0.13.0 writes and keeps when it locks. A lockfile of another
// revision (an older one is rewritten as revision 5 by that uv, which is a
// migration of the format) or with none goes to a person until a revision is
// added here after checking its format and that the work image keeps it.
var uvLockRevisions = map[int64]bool{5: true}

// parseUv reads uv.lock (version = 1) of a project with a static
// pyproject.toml and no workspace.
func parseUv(pyproject, lock []byte) (*lockfile, error) {
	py, err := parseTOML(pyproject)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "pyproject.toml cannot be read: %v", err)
	}
	project, ok := py["project"].(map[string]any)
	if !ok {
		return nil, unsupported(ReasonDynamicMetadata, "pyproject.toml has no [project] table")
	}
	// Any dynamic field means the project's metadata is computed by running
	// its build backend, which the plan does not do.
	if dyn, present := project["dynamic"]; present {
		list, isList := dyn.([]any)
		if !isList || len(list) > 0 {
			return nil, unsupported(ReasonDynamicMetadata, "pyproject.toml declares dynamic project fields")
		}
	}
	tool, err := tomlTable(py, "tool")
	if err != nil {
		return nil, err
	}
	uvTool, err := tomlTable(tool, "uv")
	if err != nil {
		return nil, err
	}
	if _, ok := uvTool["workspace"]; ok {
		return nil, unsupported(ReasonWorkspaceUnsupported, "pyproject.toml declares a uv workspace")
	}

	doc, err := parseTOML(lock)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "uv.lock cannot be read: %v", err)
	}
	if err := checkTOMLKeys(doc); err != nil {
		return nil, unsupported(ReasonUnparsableSource, "uv.lock cannot be read: %v", err)
	}
	if v, ok := doc["version"].(int64); !ok || v != 1 {
		return nil, unsupported(ReasonUnsupportedLockfile, "uv.lock has version %v; only version = 1 is read", doc["version"])
	}
	rev, ok := doc["revision"].(int64)
	if !ok || !uvLockRevisions[rev] {
		return nil, unsupported(ReasonUnsupportedLockfile, "uv.lock has revision %v; only the revisions this build knows are read", doc["revision"])
	}
	manifest, err := tomlTable(doc, "manifest")
	if err != nil {
		return nil, err
	}
	if members, present := manifest["members"]; present {
		if list, isList := members.([]any); !isList || len(list) > 0 {
			return nil, unsupported(ReasonWorkspaceUnsupported, "uv.lock lists workspace members")
		}
	}
	pkgs, _ := doc["package"].([]any)
	if len(pkgs) == 0 {
		return nil, unsupported(ReasonUnsupportedLockfile, "uv.lock has no packages")
	}

	// The root project is the package that is the project itself.
	var root map[string]any
	for _, p := range pkgs {
		m, ok := p.(map[string]any)
		if !ok {
			return nil, unsupported(ReasonUnparsableSource, "uv.lock has a package entry that is not a table")
		}
		src, err := tomlTable(m, "source")
		if err != nil {
			return nil, err
		}
		for _, kind := range []string{"virtual", "editable"} {
			if dir, _ := src[kind].(string); dir == "." {
				if root != nil {
					return nil, unsupported(ReasonWorkspaceUnsupported, "uv.lock has more than one root project")
				}
				root = m
			}
		}
	}
	if root == nil {
		return nil, unsupported(ReasonUnsupportedLockfile, "uv.lock has no root project")
	}

	l := newLockfile(ManagerUv)
	direct := map[string]bool{}
	names, err := uvDependencyNames(root)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		direct[normalizePyName(n)] = true
	}

	for _, p := range pkgs {
		m := p.(map[string]any)
		name, ok := m["name"].(string)
		if !ok || name == "" {
			return nil, unsupported(ReasonUnparsableSource, "uv.lock has a package without a name")
		}
		ver := ""
		if v, present := m["version"]; present {
			if ver, ok = v.(string); !ok {
				return nil, unsupported(ReasonUnparsableSource, "uv.lock gives %s a version that is not a string", name)
			}
		}
		if why := uvRecordProblem(m); why != "" {
			return nil, unsupported(ReasonUnparsableSource, "uv.lock, %s: %s", name, why)
		}
		src, _ := m["source"].(map[string]any) // checked above
		pypi := src["registry"] == publicPyPIIndex
		wheelHost := pypiWheelHost
		if idx, ok := src["registry"].(string); ok && !pypi {
			wheelHost = ""
			if u, err := url.Parse(idx); err == nil && u.Scheme == "https" {
				wheelHost = u.Hostname()
			}
		}
		wheels := 0
		if w, present := m["wheels"]; present {
			list, ok := w.([]any)
			if !ok {
				return nil, unsupported(ReasonUnparsableSource, "uv.lock gives %s wheels that are not a list", name)
			}
			for i, e := range list {
				if why := wheelProblem(e, wheelHost); why != "" {
					return nil, unsupported(ReasonUnparsableSource, "uv.lock wheel %d of %s %s", i+1, name, why)
				}
			}
			wheels = len(list)
		}
		o := SourceOccurrence{Path: name + "==" + ver, Version: ver, Direct: direct[normalizePyName(name)]}
		switch idx, isReg := src["registry"].(string); {
		case isReg && idx == publicPyPIIndex:
			if wheels == 0 {
				o.ManualReason, o.Detail = ReasonSdistOnly, "no wheel is listed, so installing it would build from source"
			}
		case isReg:
			o.ManualReason, o.Detail = ReasonNonRegistrySource, "from the index "+idx
		default:
			o.ManualReason, o.Detail = ReasonNonRegistrySource, "from a "+uvSourceKind(src)+" source"
		}
		l.add(name, o)
	}

	sources, err := tomlTable(uvTool, "sources")
	if err != nil {
		return nil, err
	}
	{
		for n := range sources {
			l.force(n, "[tool.uv.sources] sets its source")
		}
	}
	for _, key := range []string{"overrides", "constraints"} {
		list, _ := manifest[key].([]any)
		for _, e := range list {
			if m, ok := e.(map[string]any); ok {
				if n, _ := m["name"].(string); n != "" {
					l.force(n, "the lockfile records a "+key[:len(key)-1]+" for it")
				}
			}
		}
	}
	return l.finish(), nil
}

// uvSourceKind names the kind of a lock source table.
func uvSourceKind(src map[string]any) string {
	var ks []string
	for k := range src {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	if len(ks) == 0 {
		return "unknown"
	}
	return ks[0]
}

// uvDependencyNames lists the package names the root project requires:
// its dependencies, dependency groups and optional dependencies. A field of
// another type than the lockfile format defines is an error.
func uvDependencyNames(root map[string]any) ([]string, error) {
	var out []string
	collect := func(v any, where string) error {
		list, ok := v.([]any)
		if !ok {
			return unsupported(ReasonUnparsableSource, "uv.lock root project %s is not a list", where)
		}
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				return unsupported(ReasonUnparsableSource, "uv.lock root project %s has an entry that is not a table", where)
			}
			n, ok := m["name"].(string)
			if !ok || n == "" {
				return unsupported(ReasonUnparsableSource, "uv.lock root project %s has an entry without a name", where)
			}
			out = append(out, n)
		}
		return nil
	}
	if v, present := root["dependencies"]; present {
		if err := collect(v, "dependencies"); err != nil {
			return nil, err
		}
	}
	for _, key := range []string{"dev-dependencies", "optional-dependencies"} {
		v, present := root[key]
		if !present {
			continue
		}
		groups, ok := v.(map[string]any)
		if !ok {
			return nil, unsupported(ReasonUnparsableSource, "uv.lock root project %s is not a table", key)
		}
		for _, g := range groups {
			if err := collect(g, key); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// tomlTable returns the table at key of m: empty when absent, an error when
// the key holds something else.
func tomlTable(m map[string]any, key string) (map[string]any, error) {
	v, present := m[key]
	if !present {
		return nil, nil
	}
	t, ok := v.(map[string]any)
	if !ok {
		return nil, unsupported(ReasonUnparsableSource, "%s is not a table", key)
	}
	return t, nil
}

// pypiWheelHost is where PyPI wheels are served from.
const pypiWheelHost = "files.pythonhosted.org"

var wheelHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// wheelProblem returns why an element of a package's wheels list is not a
// wheel entry as uv writes it, or "" when it is: a table with a location and
// a sha256 hash of 64 lower-case hex digits. The location is an https url on
// the host the package's registry serves wheels from (host; empty when that
// is not known, which allows only a path, as a local index uses), or a path.
// An element that is not one is no evidence that a wheel exists.
func wheelProblem(e any, host string) string {
	w, ok := e.(map[string]any)
	if !ok {
		return "is not a table"
	}
	if why := uvFileFieldsProblem(w, uvWheelKeys); why != "" {
		return why
	}
	_, hasURL := w["url"]
	_, hasPath := w["path"]
	switch {
	case hasURL:
		s, ok := w["url"].(string)
		if !ok {
			return "has a url that is not a string"
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return "has a url that is not an https location"
		}
		if host == "" || u.Hostname() != host {
			return "has a url that is not on the registry's host"
		}
	case hasPath:
		if s, ok := w["path"].(string); !ok || s == "" {
			return "has a path that is not a string"
		}
		if host == pypiWheelHost {
			return "has a path, but the package comes from PyPI"
		}
	default:
		return "has neither a url nor a path"
	}
	if h, ok := w["hash"].(string); !ok || !wheelHashRE.MatchString(h) {
		return "has no sha256 hash of 64 hex digits"
	}
	return ""
}

// uvWheelKeys and uvSdistKeys are the members of a wheel and of a source
// distribution in uv.lock (WheelWire and SourceDist of
// crates/uv-lock/src/lock/mod.rs in uv).
var (
	uvWheelKeys = keySet("url", "path", "filename", "hash", "size", "upload-time")
	uvSdistKeys = keySet("url", "path", "hash", "size", "upload-time")
)

// uvFileFieldsProblem checks the members of a distribution file record other
// than its location and hash: only known members, a size that is a
// non-negative integer, an upload time that is an RFC 3339 timestamp, and a
// wheel's file name that has the form of a wheel name.
func uvFileFieldsProblem(w map[string]any, known map[string]bool) string {
	for k := range w {
		if !known[k] {
			return "has the member " + k + ", which is not one uv writes"
		}
	}
	if s, present := w["size"]; present {
		if n, ok := s.(int64); !ok || n < 0 {
			return "has a size that is not a non-negative integer"
		}
	}
	if v, present := w["upload-time"]; present {
		t, ok := v.(string)
		if !ok {
			return "has upload-time that is not a string"
		}
		if _, err := time.Parse(time.RFC3339Nano, t); err != nil {
			return "has upload-time that is not an RFC 3339 timestamp"
		}
	}
	if v, present := w["filename"]; present {
		f, ok := v.(string)
		if !ok {
			return "has filename that is not a string"
		}
		if !wheelFileShape(f) {
			return "has filename that is not the name of a wheel"
		}
		if u, ok := w["url"].(string); ok {
			if pu, err := url.Parse(u); err != nil || path.Base(pu.Path) != f {
				return "has filename that is not the last part of its url"
			}
		}
	}
	return ""
}

// maxWheelNameBytes bounds a wheel file name (a file name is at most 255 bytes).
const (
	maxWheelNameBytes = 255
	maxWheelTags      = 64 // tags of one kind in a wheel name
)

var wheelNameChars = regexp.MustCompile(`^[A-Za-z0-9_.+!]+$`)

// wheelFileShape reports whether file has the form of a wheel name,
// name-version[-build]-python-abi-platform.whl, of bounded length and made of
// the characters such a name has.
func wheelFileShape(file string) bool {
	base, ok := strings.CutSuffix(file, ".whl")
	if !ok || len(file) > maxWheelNameBytes {
		return false
	}
	parts := strings.Split(base, "-")
	if len(parts) != 5 && len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if !wheelNameChars.MatchString(p) {
			return false
		}
	}
	// A build tag, when there is one, starts with a digit.
	if len(parts) == 6 && (parts[2][0] < '0' || parts[2][0] > '9') {
		return false
	}
	return true
}

// sdistProblem returns why an sdist member of a package is not a source
// distribution record as uv writes it for a registry package: a table with an
// https url on the registry's file host, a sha256 hash, and a size and an
// upload time of the right types.
func sdistProblem(e any, host string) string {
	w, ok := e.(map[string]any)
	if !ok {
		return "is not a table"
	}
	if why := uvFileFieldsProblem(w, uvSdistKeys); why != "" {
		return why
	}
	s, ok := w["url"].(string)
	if !ok {
		return "has no url that is a string"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "has a url that is not an https location"
	}
	if host != "" && u.Hostname() != host {
		return "has a url that is not on the registry's host"
	}
	if h, ok := w["hash"].(string); !ok || !wheelHashRE.MatchString(h) {
		return "has no sha256 hash of 64 hex digits"
	}
	return ""
}

var uvDependencyKeys = keySet("name", "version", "source", "marker", "extra")

// uvDependencyProblem checks the dependency records of a package: a list of
// tables (or, for optional and development dependencies, a table of such
// lists) with a name, and a version, a marker and extras of the right types.
func uvDependencyProblem(v any, grouped bool) string {
	if grouped {
		groups, ok := v.(map[string]any)
		if !ok {
			return "is not a table of lists"
		}
		for g, l := range groups {
			if why := uvDependencyProblem(l, false); why != "" {
				return g + ": " + why
			}
		}
		return ""
	}
	list, ok := v.([]any)
	if !ok {
		return "is not a list"
	}
	for i, e := range list {
		d, ok := e.(map[string]any)
		if !ok {
			return fmt.Sprintf("entry %d is not a table", i+1)
		}
		for k := range d {
			if !uvDependencyKeys[k] {
				return fmt.Sprintf("entry %d has the member %s, which is not one uv writes", i+1, k)
			}
		}
		if n, ok := d["name"].(string); !ok || n == "" {
			return fmt.Sprintf("entry %d has no name", i+1)
		}
		for _, k := range []string{"version", "marker"} {
			if x, present := d[k]; present {
				if _, ok := x.(string); !ok {
					return fmt.Sprintf("entry %d has %s that is not a string", i+1, k)
				}
			}
		}
		if x, present := d["extra"]; present {
			l, ok := x.([]any)
			if !ok {
				return fmt.Sprintf("entry %d has extra that is not a list", i+1)
			}
			for _, s := range l {
				if _, ok := s.(string); !ok {
					return fmt.Sprintf("entry %d has an extra that is not a string", i+1)
				}
			}
		}
		if x, present := d["source"]; present {
			if _, ok := x.(map[string]any); !ok {
				return fmt.Sprintf("entry %d has source that is not a table", i+1)
			}
		}
	}
	return ""
}

// uvPackageKeys are the members of a package in uv.lock (PackageWire of
// crates/uv-lock/src/lock/mod.rs in uv).
var uvPackageKeys = keySet("name", "version", "source", "metadata", "sdist", "wheels", "resolution-markers",
	"dependencies", "optional-dependencies", "default-groups", "dev-dependencies", "dependency-groups", "group-requires-python")

// uvRecordProblem checks the types of the records of a package that decide
// what is fetched: its sdist, its wheels and its dependency records. A record
// of the wrong type is a problem, never a missing record.
func uvRecordProblem(m map[string]any) string {
	if n, ok := m["name"].(string); !ok || !worker.ValidPythonName(n) {
		return "name is not a project name"
	}
	if v, present := m["version"]; present {
		if s, ok := v.(string); !ok || !worker.ValidPythonVersion(s) {
			return "version is not a normalized version"
		}
	}
	if v, present := m["source"]; present {
		src, ok := v.(map[string]any)
		if !ok {
			return "source is not a table"
		}
		for k, x := range src {
			if _, ok := x.(string); !ok {
				return "source." + k + " is not a string"
			}
		}
	}
	for _, k := range []string{"resolution-markers"} {
		if v, present := m[k]; present {
			if why := stringListProblem(v); why != "" {
				return k + " " + why
			}
		}
	}
	if v, present := m["default-groups"]; present {
		if s, isStr := v.(string); !isStr || s != "all" {
			if why := stringListProblem(v); why != "" {
				return "default-groups " + why
			}
		}
	}
	if v, present := m["metadata"]; present {
		if why := uvMetadataProblem(v); why != "" {
			return "metadata " + why
		}
	}
	if v, present := m["group-requires-python"]; present {
		t, ok := v.(map[string]any)
		if !ok {
			return "group-requires-python is not a table"
		}
		for g, x := range t {
			if _, ok := x.(string); !ok {
				return "group-requires-python." + g + " is not a string"
			}
		}
	}
	if v, present := m["sdist"]; present {
		if why := sdistProblem(v, ""); why != "" {
			return "sdist " + why
		}
	}
	if v, present := m["wheels"]; present {
		list, ok := v.([]any)
		if !ok {
			return "wheels is not a list"
		}
		for i, e := range list {
			if why := wheelShapeProblem(e); why != "" {
				return fmt.Sprintf("wheel %d %s", i+1, why)
			}
		}
	}
	if v, present := m["dependencies"]; present {
		if why := uvDependencyProblem(v, false); why != "" {
			return "dependencies " + why
		}
	}
	for _, k := range []string{"optional-dependencies", "dev-dependencies", "dependency-groups"} {
		if v, present := m[k]; present {
			if why := uvDependencyProblem(v, true); why != "" {
				return k + " " + why
			}
		}
	}
	return ""
}

// wheelShapeProblem checks the types of a wheel record without judging where
// it points: a table of known members with a url or a path that is a string
// and a sha256 hash.
func wheelShapeProblem(e any) string {
	w, ok := e.(map[string]any)
	if !ok {
		return "is not a table"
	}
	if why := uvFileFieldsProblem(w, uvWheelKeys); why != "" {
		return why
	}
	for _, k := range []string{"url", "path"} {
		if v, present := w[k]; present {
			if s, ok := v.(string); !ok || s == "" {
				return "has " + k + " that is not a string"
			}
		}
	}
	if _, hasURL := w["url"]; !hasURL {
		if _, hasPath := w["path"]; !hasPath {
			return "has neither a url nor a path"
		}
	}
	if h, ok := w["hash"].(string); !ok || !wheelHashRE.MatchString(h) {
		return "has no sha256 hash of 64 hex digits"
	}
	return ""
}

// stringListProblem returns why v is not a list of strings, or "".
func stringListProblem(v any) string {
	list, ok := v.([]any)
	if !ok {
		return "is not a list"
	}
	for _, e := range list {
		if _, ok := e.(string); !ok {
			return "has an element that is not a string"
		}
	}
	return ""
}

// uvRequirementStrings are the members of a requirement record in a
// package's metadata that are strings, and uvRequirementKeys all its members
// (RequirementWire of crates/uv-lock/src/lock/mod.rs in uv).
var (
	uvRequirementStrings = keySet("name", "specifier", "marker", "url", "path", "directory", "git", "index", "subdirectory", "branch", "tag", "rev", "group")
	uvRequirementKeys    = keySet("name", "specifier", "marker", "url", "path", "directory", "git", "index", "subdirectory", "branch", "tag", "rev", "group",
		"extras", "editable", "virtual", "lfs", "conflict")
)

// uvMetadataProblem checks a package's metadata table: requires-dist and
// each of requires-dev / dependency-groups are lists of requirement records,
// provides-extras is a list of strings.
func uvMetadataProblem(v any) string {
	t, ok := v.(map[string]any)
	if !ok {
		return "is not a table"
	}
	for k, x := range t {
		switch k {
		case "requires-dist":
			if why := uvRequirementsProblem(x); why != "" {
				return k + " " + why
			}
		case "provides-extras":
			if why := stringListProblem(x); why != "" {
				return k + " " + why
			}
		case "requires-dev", "dependency-groups":
			groups, ok := x.(map[string]any)
			if !ok {
				return k + " is not a table"
			}
			for g, l := range groups {
				if why := uvRequirementsProblem(l); why != "" {
					return k + "." + g + " " + why
				}
			}
		default:
			return "has the member " + k + ", which is not one uv writes"
		}
	}
	return ""
}

func uvRequirementsProblem(v any) string {
	list, ok := v.([]any)
	if !ok {
		return "is not a list"
	}
	for i, e := range list {
		r, ok := e.(map[string]any)
		if !ok {
			return fmt.Sprintf("entry %d is not a table", i+1)
		}
		for k, x := range r {
			switch {
			case !uvRequirementKeys[k]:
				return fmt.Sprintf("entry %d has the member %s, which is not one uv writes", i+1, k)
			case uvRequirementStrings[k]:
				if _, ok := x.(string); !ok {
					return fmt.Sprintf("entry %d has %s that is not a string", i+1, k)
				}
			case k == "extras":
				if why := stringListProblem(x); why != "" {
					return fmt.Sprintf("entry %d has extras that %s", i+1, why)
				}
			case k == "conflict":
				if _, ok := x.(map[string]any); !ok {
					return fmt.Sprintf("entry %d has conflict that is not a table", i+1)
				}
			default: // editable, virtual, lfs
				if _, ok := x.(bool); !ok {
					return fmt.Sprintf("entry %d has %s that is not a boolean", i+1, k)
				}
			}
		}
		if n, _ := r["name"].(string); n == "" {
			return fmt.Sprintf("entry %d has no name", i+1)
		}
	}
	return ""
}
