package remediation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// pythonDecls are the declarations about the Python version of a uv unit.
type pythonDecls struct {
	// file is .python-version: its minor series ("3.13") and its patch
	// ("" when only the series is written).
	hasFile    bool
	fileText   string
	fileMinor  string
	filePatch  string
	hasRequire bool
	require    string // requires-python, normalized
	requireRaw string
	// project is the parsed pyproject.toml.
	project map[string]any
	py      map[string]any
}

var pythonVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$`)

// parsePythonVersionFile reads .python-version: the first line that is not
// empty, "3.13" or "3.13.5", optionally with a "cpython-" or "cpython@"
// prefix.
func parsePythonVersionFile(data []byte) (minor, patch, text string, uerr *UnsupportedError) {
	line := firstLine(data)
	if line == "" || len(line) > 100 {
		return "", "", "", unsupported(ReasonPythonSpecInvalid, ".python-version has no version on its first line, or the line is too long")
	}
	low := strings.ToLower(line)
	for _, other := range []string{"pypy", "graalpy", "pyodide", "system"} {
		if strings.HasPrefix(low, other) {
			return "", "", "", unsupported(ReasonPythonSpecUnsupported, ".python-version asks for %q, and updates run with CPython", clip(line, 40))
		}
	}
	rest := low
	for _, p := range []string{"cpython-", "cpython@"} {
		rest = strings.TrimPrefix(rest, p)
	}
	m := pythonVersionRE.FindStringSubmatch(rest)
	if m == nil {
		if strings.HasSuffix(rest, "t") && pythonVersionRE.MatchString(strings.TrimSuffix(rest, "t")) {
			return "", "", "", unsupported(ReasonPythonSpecUnsupported, ".python-version asks for the free-threaded build %q", clip(line, 40))
		}
		return "", "", "", unsupported(ReasonPythonSpecInvalid, ".python-version %q is not a version", clip(line, 40))
	}
	return m[1] + "." + m[2], m[3], line, nil
}

// readPythonDeclarations reads the declarations about Python of a uv unit and
// checks that they can hold together.
func readPythonDeclarations(in ToolSpecInput) (*pythonDecls, *UnsupportedError) {
	d := &pythonDecls{}
	py, err := parseTOML(in.Manifest)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "pyproject.toml cannot be read: %v", err)
	}
	d.py = py
	d.project, _ = py["project"].(map[string]any)
	if _, ok := in.Files[pythonVersionsFileName]; ok {
		return nil, unsupported(ReasonPythonSpecUnsupported, ".python-versions lists several versions, which are not read")
	}
	if data, ok := in.Files[pythonVersionFileName]; ok {
		minor, patch, text, uerr := parsePythonVersionFile(data)
		if uerr != nil {
			return nil, uerr
		}
		d.hasFile, d.fileMinor, d.filePatch, d.fileText = true, minor, patch, text
	}
	if v, present := d.project["requires-python"]; present {
		s, isString := v.(string)
		if !isString {
			return nil, unsupported(ReasonPythonSpecInvalid, "pyproject.toml requires-python is not a string")
		}
		norm, ok := normalizeSpecifier(s)
		if !ok || norm == "" {
			return nil, unsupported(ReasonPythonSpecInvalid, "requires-python %q is not a version specifier that is read", clip(s, 80))
		}
		d.hasRequire, d.require, d.requireRaw = true, norm, s
	}
	if d.hasFile && d.hasRequire {
		admits, decided := requireAdmits(d.require, d.fileMinor, d.filePatch)
		switch {
		case !decided:
			return nil, unsupported(ReasonPythonSpecInvalid, "requires-python %q cannot be judged against .python-version %s", clip(d.requireRaw, 80), d.fileText)
		case !admits:
			return nil, unsupported(ReasonPythonSpecConflict, ".python-version %s and requires-python %s allow no Python version in common", d.fileText, clip(d.requireRaw, 80))
		}
	}
	return d, nil
}

// requireAdmits reports whether some Python version of the series (or the
// given patch release of it) satisfies the specifier. decided is false when
// the specifier cannot be judged.
func requireAdmits(spec, minor, patch string) (admits, decided bool) {
	var samples []string
	if patch != "" {
		samples = []string{minor + "." + patch}
	} else {
		samples = []string{minor + ".0", minor + ".9999"}
		// A clause that names a patch of the series is decided by that patch
		// and its neighbours.
		for _, c := range strings.Split(spec, ",") {
			cm := pipClauseRE.FindStringSubmatch(c)
			if cm == nil {
				continue
			}
			lit := strings.TrimSuffix(cm[2], ".*")
			if rest, ok := strings.CutPrefix(lit, minor+"."); ok {
				if n, err := strconv.Atoi(rest); err == nil {
					for _, k := range []int{n - 1, n, n + 1} {
						if k >= 0 {
							samples = append(samples, fmt.Sprintf("%s.%d", minor, k))
						}
					}
				}
			}
		}
	}
	for _, s := range samples {
		v, ok := parsePEP440(s)
		if !ok {
			return false, false
		}
		ok, evaluable := pySatisfies(v, spec)
		if !evaluable {
			return false, false
		}
		if ok {
			return true, true
		}
	}
	return false, true
}

// pythonSeriesOf lists the Python runtimes of the table that the declarations
// allow some version of.
func pythonSeriesOf(d *pythonDecls) []string {
	var out []string
	for _, r := range worker.Runtimes() {
		if r.Kind != worker.KindPython {
			continue
		}
		minor := r.Series
		if d.hasFile && d.fileMinor != minor {
			continue
		}
		if d.hasRequire {
			if admits, decided := requireAdmits(d.require, minor, ""); !decided || !admits {
				continue
			}
		}
		out = append(out, r.ID)
	}
	return out
}

// uvVersionRE matches a requirement that fixes one exact uv version.
var uvExactRE = regexp.MustCompile(`^==(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// resolveUvSpec resolves the declarations of a uv unit.
func resolveUvSpec(in ToolSpecInput) (ToolSpec, *UnsupportedError) {
	spec := ToolSpec{Manager: ManagerUv, Runtime: defaultPythonRuntime}
	if uerr := uvFetchConfigProblem(in); uerr != nil {
		return spec, uerr
	}
	d, uerr := readPythonDeclarations(in)
	if uerr != nil {
		return spec, uerr
	}
	spec.Requested = pythonSeriesOf(d)
	if d.hasFile {
		spec.Declarations = append(spec.Declarations, ToolDeclaration{Source: pythonVersionFileName, Value: clip(d.fileText, 100)})
	}
	if d.hasRequire {
		spec.Declarations = append(spec.Declarations, ToolDeclaration{Source: "requires-python", Value: clip(d.requireRaw, 100)})
	}

	rt, ok := worker.LookupRuntime(defaultPythonRuntime)
	if !ok {
		return spec, unsupported(ReasonPythonSpecUnsupported, "the runtime %s is not in the runtime table", defaultPythonRuntime)
	}
	if d.hasFile && d.fileMinor != rt.Series {
		return spec, unsupported(ReasonPythonSpecUnsupported, ".python-version asks for Python %s, and updates run on Python %s so far", d.fileText, rt.Version)
	}
	if d.hasRequire {
		pv, ok := parsePEP440(rt.Version)
		if !ok {
			return spec, unsupported(ReasonPythonSpecUnsupported, "the runtime %s has the version %q", rt.ID, rt.Version)
		}
		if admits, evaluable := pySatisfies(pv, d.require); !evaluable {
			return spec, unsupported(ReasonPythonSpecInvalid, "requires-python %q cannot be judged", clip(d.requireRaw, 80))
		} else if !admits {
			return spec, unsupported(ReasonPythonSpecUnsupported, "requires-python %s does not allow Python %s, which updates run on so far", clip(d.requireRaw, 80), rt.Version)
		}
	}

	def := toolfetch.DefaultVersion(toolfetch.ManagerUv, defaultPythonRuntime)
	spec.ToolVersion, spec.ToolSource = def, toolSourceDefault
	tool, _ := d.py["tool"].(map[string]any)
	uv, _ := tool["uv"].(map[string]any)
	v, present := uv["required-version"]
	if !present {
		return spec, nil
	}
	text, isString := v.(string)
	norm, ok := normalizeSpecifier(text)
	if !isString || !ok || norm == "" {
		return spec, unsupported(ReasonManagerSpecInvalid, "[tool.uv] required-version is not a version specifier that is read")
	}
	spec.Declarations = append(spec.Declarations, ToolDeclaration{Source: "tool.uv.required-version", Value: clip(text, 100)})
	dv, ok := parsePEP440(def)
	if !ok {
		return spec, unsupported(ReasonManagerSpecUnsupported, "no default version of uv is set for %s", defaultPythonRuntime)
	}
	if uvExactRE.MatchString(norm) {
		// The project names the release: it is the one to run, if the fetching
		// package takes it.
		exact := strings.TrimPrefix(norm, "==")
		if ok, why := toolfetch.CheckVersion(toolfetch.ManagerUv, exact); !ok {
			return spec, unsupported(ReasonManagerSpecUnsupported, "[tool.uv] required-version %s: %s", clip(text, 80), why)
		}
		spec.ToolVersion, spec.ToolSource = exact, toolSourceDeclared
		return spec, nil
	}
	admits, evaluable := pySatisfies(dv, norm)
	switch {
	case !evaluable:
		return spec, unsupported(ReasonManagerSpecInvalid, "[tool.uv] required-version %q cannot be judged", clip(text, 80))
	case !admits:
		return spec, unsupported(ReasonManagerSpecUnsupported, "[tool.uv] required-version %s does not allow uv %s, which updates run with when the project names no exact version", clip(text, 80), def)
	}
	spec.ToolSource = toolSourceDefaultInRange
	return spec, nil
}
