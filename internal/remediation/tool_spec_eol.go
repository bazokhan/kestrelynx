package remediation

import (
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// declaredRuntimeEOL reports whether the declarations of a unit allow only
// runtimes that are past the end of their support (an .nvmrc that says 20, a
// requires-python of 3.9 or 3.10), and returns the one to name: the runtime
// the unit would run in when the declarations allow it, else the lowest one
// they allow. Declarations that allow a runtime still in support, or that name
// none of the table, or that cannot be read, are left to ResolveToolSpec.
func declaredRuntimeEOL(in ToolSpecInput, now time.Time) (worker.RuntimeSpec, bool) {
	req, uerr := RequestedRuntimes(in)
	if uerr != nil || len(req) == 0 {
		return worker.RuntimeSpec{}, false
	}
	var first worker.RuntimeSpec
	for _, id := range req {
		spec, ok := worker.LookupRuntime(id)
		if !ok || !spec.EndOfLife(now) {
			return worker.RuntimeSpec{}, false
		}
		if first.ID == "" || id == runtimeIDFor(worker.Manager(in.Manager)) {
			first = spec
		}
	}
	return first, true
}
