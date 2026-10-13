package remediation

import (
	"strconv"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// declaredRuntimeEOL reports whether the declarations of a unit allow only
// runtimes that are past the end of their support (an .nvmrc that says 20, a
// requires-python of 3.9 or 3.10), and returns the one to name: the lowest
// one they allow, which is the one the update would have run in (the default
// runtime when nothing is declared). Declarations that allow a runtime still in support, or that name
// none of the table, or that cannot be read, are left to ResolveToolSpec.
func declaredRuntimeEOL(in ToolSpecInput, now time.Time) (worker.RuntimeSpec, bool) {
	req, uerr := RequestedRuntimes(in)
	if uerr != nil || len(req) == 0 {
		return worker.RuntimeSpec{}, false
	}
	// req is lowest first, so the one named is the series the update would have
	// run in had it been in support.
	// With no declaration about the language the update runs in the default
	// runtime, which is the one to name.
	undeclared := declaresNothingAboutLanguage(in)
	var first worker.RuntimeSpec
	for _, id := range req {
		spec, ok := worker.LookupRuntime(id)
		if !ok || !spec.EndOfLife(now) {
			return worker.RuntimeSpec{}, false
		}
		if first.ID == "" || (undeclared && id == runtimeIDFor(worker.Manager(in.Manager), now)) {
			first = spec
		}
	}
	return first, true
}

// declaresNothingAboutLanguage reports whether a unit has no declaration of the
// Node.js or Python version.
func declaresNothingAboutLanguage(in ToolSpecInput) bool {
	switch in.Manager {
	case ManagerNpm, ManagerPnpm:
		d, uerr := readNodeDeclarations(in)
		return uerr == nil && len(d.decls) == 0
	case ManagerUv:
		d, uerr := readPythonDeclarations(in)
		return uerr == nil && !d.hasFile && !d.hasRequire
	}
	return false
}

// pythonPastSupport reports whether the Python series ("3.10") is past the end
// of its support: a series of the table whose end has passed, or one lower than
// every series of the table (the table has no date for it, so the spec returned
// has none).
func pythonPastSupport(minor string, now time.Time) (worker.RuntimeSpec, bool) {
	if spec, ok := worker.LookupRuntime("python" + minor); ok {
		return spec, spec.EndOfLife(now)
	}
	major, rest, ok := strings.Cut(minor, ".")
	n, err := strconv.Atoi(rest)
	if !ok || major != "3" || err != nil {
		return worker.RuntimeSpec{}, false
	}
	for _, r := range worker.Runtimes() {
		if r.Kind != worker.KindPython {
			continue
		}
		if low, err := strconv.Atoi(strings.TrimPrefix(r.Series, "3.")); err == nil && low <= n {
			return worker.RuntimeSpec{}, false
		}
	}
	return worker.RuntimeSpec{ID: "python" + minor, Kind: worker.KindPython, Series: minor}, true
}
