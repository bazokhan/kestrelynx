package runner

import (
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// composeNameWarnings remembers, for this process only, which container/<name>
// mappings have been reported as naming a Compose container and which Compose
// key the warning pointed to.
type composeNameWarnings struct {
	shown map[string]string
}

// warnComposeNames logs a warning for every mapping whose container/<name> key
// names a container of a Compose service: such a container is matched by its
// compose/<project>/<service> key only, so the mapping does nothing. The same
// warning is not repeated while it stays the same; it is shown again when the
// Compose key it points to changes, or after the mapping stopped matching a
// Compose container and then matches one again.
func (r Runner) warnComposeNames(containers []inventory.Container) {
	pc := r.Plan
	if pc == nil {
		return
	}
	if pc.composeNames == nil {
		pc.composeNames = &composeNameWarnings{shown: map[string]string{}}
	}
	w := pc.composeNames

	byName := map[string]string{}
	for _, c := range containers {
		if c.Workload.Kind == inventory.WorkloadCompose && c.Name != "" {
			if k := c.WorkloadKey(); k != "" {
				byName[c.Name] = k
			}
		}
	}
	current := map[string]string{}
	note := func(workload string) {
		name, ok := strings.CutPrefix(workload, inventory.ContainerKeyPrefix)
		if !ok {
			return
		}
		if k, ok := byName[name]; ok {
			current[workload] = k
		}
	}
	for _, m := range pc.Dockerfiles {
		note(m.Workload)
	}
	for _, m := range pc.Dependencies {
		note(m.Workload)
	}

	for workload := range w.shown {
		if _, ok := current[workload]; !ok {
			delete(w.shown, workload)
		}
	}
	workloads := make([]string, 0, len(current))
	for workload := range current {
		workloads = append(workloads, workload)
	}
	sort.Strings(workloads)
	for _, workload := range workloads {
		compose := current[workload]
		if w.shown[workload] == compose {
			continue
		}
		w.shown[workload] = compose
		r.log().Warn("a remediation mapping names a container of a Compose service and has no effect; use the Compose key instead", "workload", workload, "use", compose)
	}
}
