package remediation

import (
	"net/url"
	"regexp"
	"sort"
)

// publicPyPIIndex is the only index whose registry packages count as PyPI.
const publicPyPIIndex = "https://pypi.org/simple"

// uvLockRevisions are the uv.lock revisions this build reads. Revision 3 is
// what uv 0.11.16 writes; a lockfile of any other revision (or with none) may
// differ in ways the parser does not know, so it goes to a person until the
// revision is added here after checking its format.
var uvLockRevisions = map[int64]bool{3: true}

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
