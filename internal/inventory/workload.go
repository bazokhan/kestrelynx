package inventory

import (
	"strings"
	"unicode"
)

// WorkloadKind identifies how a Container's Workload was determined.
// WorkloadUnknown is the zero value on purpose: a Workload that was never
// set (a bug, or an adapter that made no attempt) reads as "no association
// found" rather than silently claiming a known one.
type WorkloadKind string

const (
	// WorkloadUnknown means no association could be established. This is not
	// guessed at — a standalone container is unknown, not "the workload is
	// itself".
	WorkloadUnknown WorkloadKind = ""
	// WorkloadCompose means Group/Name came from a Docker Compose project and
	// service pair.
	WorkloadCompose WorkloadKind = "compose"
	// WorkloadDeployment means Group/Name came from a Kubernetes Deployment
	// (resolved through its ReplicaSet).
	WorkloadDeployment WorkloadKind = "deployment"
	// WorkloadStatefulSet means Group/Name came from a Kubernetes StatefulSet.
	WorkloadStatefulSet WorkloadKind = "statefulset"
	// WorkloadDaemonSet means Group/Name came from a Kubernetes DaemonSet.
	WorkloadDaemonSet WorkloadKind = "daemonset"
	// WorkloadJob means Group/Name came from a Kubernetes Job that is not
	// itself owned by a CronJob.
	WorkloadJob WorkloadKind = "job"
	// WorkloadCronJob means Group/Name came from a Kubernetes CronJob
	// (resolved through its Job).
	WorkloadCronJob WorkloadKind = "cronjob"
	// WorkloadPod means the container's Pod has no controller owner
	// reference at all; Group/Name name the Pod itself, not guessed at as
	// some higher-level workload.
	WorkloadPod WorkloadKind = "pod"
)

// Workload is the higher-level grouping a Container observably belongs to.
// Group and Name are only meaningful when Kind != WorkloadUnknown.
type Workload struct {
	Kind  WorkloadKind
	Group string // compose: project. kubernetes: namespace. "" when unknown.
	Name  string // compose: service. kubernetes: top-level owner's name (or the Pod's own name for WorkloadPod). "" when unknown.
}

// Known reports whether w carries an actual workload association.
func (w Workload) Known() bool { return w.Kind != WorkloadUnknown }

// Container is one running container as observed by a Runtime Adapter,
// stripped of anything specific to that runtime. Name is a human-assigned
// display name — the container equivalent of a Kubernetes pod/container
// name — and is never confused with an opaque runtime ID.
type Container struct {
	// ID is the runtime's own identifier for this container: for Docker,
	// the 64-hex container ID (RunningContainers' "Id" field). It is the
	// join key the Sensor's evidence.ContainerRef and this package's own
	// Container agree on; "" means the adapter could not determine one.
	ID       string
	Name     string // adapter-normalized display name; "" when it couldn't be determined.
	Workload Workload
	Image    RunningImage
	// RuntimeExcluded is true when this container carries the Docker label
	// io.kestrelynx.runtime.exclude=true. A container with this label is
	// still scanned and shown normally in every other section, but it is
	// never judged, sorted on, or shown by the runtime-usage overlay
	// (analyze.AttachRuntime skips it outright, before any generation
	// matching is attempted) — for a container an operator does not want a
	// Sensor's observations about at all, e.g. one running something
	// sensitive enough that even an in-use/not-observed verdict on it is
	// unwelcome.
	RuntimeExcluded bool
	// Declared is what the workload's own definition says this container
	// should run, for adapters whose runtime reports the running image
	// separately from the definition. nil means the adapter has no such
	// notion (Docker).
	Declared *Declared
}

// Declared is the definition-side view of a running container: the image
// reference its Pod spec names and the pull policy it sets. It is read from
// the same listing as the running state and never filled in from it.
type Declared struct {
	// Ref is the spec's image reference, "" when the spec entry for the
	// container could not be found or names no image.
	Ref string
	// PullPolicy is the spec's imagePullPolicy as written ("Always",
	// "IfNotPresent", "Never"), "" when it is not set.
	PullPolicy string
}

// maxComposeNameBytes mirrors Docker Compose's own project/service name limit;
// a value over this is treated as unusable rather than truncated.
const maxComposeNameBytes = 253

// ValidComposeName reports whether v is safe to trust as a Docker Compose
// project or service name for a Workload association: non-empty, free of
// control characters (C0 including TAB, US and newlines, DEL, and the C1
// range), and no more than 253 bytes. It is the rule both the Docker adapter
// applies to container labels and configuration applies to workload keys.
func ValidComposeName(v string) bool {
	if v == "" || len(v) > maxComposeNameBytes {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// WorkloadKey identifies the workload a container belongs to, for matching a
// reference's runners across cycles and for the keys of configuration. "" means
// no usable key.
//
//   - Compose: compose/<project>/<service>
//   - Kubernetes: <kind>/<namespace>/<name>/<container>, the container being
//     the last element of the adapter's namespace/pod/container name, so a
//     sidecar is told apart from the main container of the same Pod
//   - a container with no known workload: container/<name>
func (c Container) WorkloadKey() string {
	w := c.Workload
	switch {
	case w.Kind == WorkloadCompose:
		if w.Group == "" || w.Name == "" {
			return ""
		}
		return "compose/" + w.Group + "/" + w.Name
	case w.Known():
		i := strings.LastIndexByte(c.Name, '/')
		if i < 0 || i == len(c.Name)-1 || w.Group == "" || w.Name == "" {
			return ""
		}
		return string(w.Kind) + "/" + w.Group + "/" + w.Name + "/" + c.Name[i+1:]
	default:
		if c.Name == "" {
			return ""
		}
		return "container/" + c.Name
	}
}
