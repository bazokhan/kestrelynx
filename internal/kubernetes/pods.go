package kubernetes

import "github.com/kitsunetrail/kestrelynx/internal/inventory"

// specContainer is the subset of a container spec entry this package reads.
// RestartPolicy is only ever set on an initContainers entry — it's how a
// native sidecar (an init container that keeps running alongside the main
// containers) is distinguished from an ordinary init container that runs
// once and exits.
type specContainer struct {
	Name            string `json:"name"`
	Image           string `json:"image"`
	ImagePullPolicy string `json:"imagePullPolicy"`
	RestartPolicy   string `json:"restartPolicy"`
}

// containerState is the subset of a container status's state this package
// reads: whether it's currently running. Running is non-nil exactly when
// the "running" key is present and non-null; its own fields (startedAt) are
// never needed, so it's left as an empty struct.
type containerState struct {
	Running *struct{} `json:"running"`
}

// containerStatus is the subset of a container status entry this package
// reads, shared by status.containerStatuses and
// status.initContainerStatuses.
type containerStatus struct {
	Name    string         `json:"name"`
	Image   string         `json:"image"`
	ImageID string         `json:"imageID"`
	State   containerState `json:"state"`
}

// podRaw is the subset of a Pod object this package reads. Metadata is
// shared with replicaSetRaw/jobRaw: OwnerReferences is what resolveWorkload
// walks to find the Pod's controller owner.
type podRaw struct {
	Metadata ownedMetadata `json:"metadata"`
	Spec     struct {
		NodeName       string          `json:"nodeName"`
		Containers     []specContainer `json:"containers"`
		InitContainers []specContainer `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

// nodeRaw is the subset of a Node object this package reads.
type nodeRaw struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		NodeInfo struct {
			OperatingSystem string `json:"operatingSystem"`
			Architecture    string `json:"architecture"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

// indexPlatforms builds a Node name -> Platform lookup from a Node list.
// Variant is always left empty: nodeInfo carries no variant field, so
// same-architecture builds that differ only by variant (arm/v6 vs arm/v7)
// aren't distinguished by this index.
func indexPlatforms(nodes []nodeRaw) map[string]inventory.Platform {
	m := make(map[string]inventory.Platform, len(nodes))
	for _, n := range nodes {
		if n.Metadata.Name == "" {
			continue
		}
		m[n.Metadata.Name] = inventory.Platform{
			OS:           n.Status.NodeInfo.OperatingSystem,
			Architecture: n.Status.NodeInfo.Architecture,
		}
	}
	return m
}

// mapContainers reduces pods to the running containers they observably
// contain, per RunningContainers' contract (main containers with
// state.running, plus native sidecars). platformByNode resolves each pod's
// Platform via its spec.nodeName; a pod on a node absent from the index (or
// with no nodeName) gets the zero Platform, not a guess. rsByKey/jobByKey are
// the relay indexes resolveWorkload walks a pod's owner-reference chain
// through; a pod's Workload is resolved once and shared by every container
// it contains, since they all belong to the same Pod.
func (c *Client) mapContainers(pods []podRaw, platformByNode map[string]inventory.Platform, rsByKey map[string]replicaSetRaw, jobByKey map[string]jobRaw) []inventory.Container {
	var out []inventory.Container
	for _, pod := range pods {
		namespace, name := pod.Metadata.Namespace, pod.Metadata.Name
		platform := platformByNode[pod.Spec.NodeName]
		workload := resolveWorkload(pod, rsByKey, jobByKey)

		// Native sidecars are matched by name, not array position: spec and
		// status arrays aren't guaranteed to share index order.
		initSpecByName := make(map[string]specContainer, len(pod.Spec.InitContainers))
		for _, sc := range pod.Spec.InitContainers {
			initSpecByName[sc.Name] = sc
		}
		mainSpec := indexSpecByName(pod.Spec.Containers)
		initSpec := indexSpecByName(pod.Spec.InitContainers)

		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Running == nil {
				continue
			}
			out = append(out, c.buildContainer(namespace, name, cs, platform, workload, declaredOf(mainSpec, cs.Name)))
		}
		for _, cs := range pod.Status.InitContainerStatuses {
			if cs.State.Running == nil {
				continue
			}
			sc, ok := initSpecByName[cs.Name]
			if !ok || sc.RestartPolicy != "Always" {
				// An ordinary init container has already exited by the time
				// anything is observed running here; even one caught
				// mid-run (RestartPolicy unset) is not a native sidecar and
				// is excluded.
				continue
			}
			out = append(out, c.buildContainer(namespace, name, cs, platform, workload, declaredOf(initSpec, cs.Name)))
		}
	}
	return out
}

// indexSpecByName maps container names to their spec entries. A name that
// appears more than once has no entry: the Pod spec is malformed, and which
// of the entries describes the running container is not known.
func indexSpecByName(list []specContainer) map[string]specContainer {
	m := make(map[string]specContainer, len(list))
	dup := map[string]bool{}
	for _, sc := range list {
		if _, seen := m[sc.Name]; seen {
			dup[sc.Name] = true
		}
		m[sc.Name] = sc
	}
	for name := range dup {
		delete(m, name)
	}
	return m
}

// declaredOf reads the declared reference and pull policy of the named
// container from the spec entries of its Pod. Spec and status arrays are
// matched by name, never by position. A container without a usable spec
// entry gets an empty Ref, which later stages treat as "not available" and
// never replace with the running reference.
func declaredOf(specs map[string]specContainer, name string) *inventory.Declared {
	sc, ok := specs[name]
	if !ok {
		return &inventory.Declared{}
	}
	return &inventory.Declared{Ref: sc.Image, PullPolicy: sc.ImagePullPolicy}
}

// buildContainer converts one running container status into the common
// inventory vocabulary. The running reference is the status-reported image,
// the only actual observation; the spec's image travels separately in
// Declared and is never used as Ref.
func (c *Client) buildContainer(namespace, pod string, cs containerStatus, platform inventory.Platform, workload inventory.Workload, declared *inventory.Declared) inventory.Container {
	img := inventory.RunningImage{Ref: cs.Image, Platform: platform}
	if cs.ImageID != "" {
		if ref, ok := parseImageID(cs.ImageID); ok {
			img.Registry = ref
		} else {
			// A non-empty imageID that fails the boundary check is never
			// normalized or guessed at — the common model has no place for
			// an unresolved raw value, so it stays a log-only diagnostic.
			c.log().Warn("image id failed registry digest validation",
				"ref", cs.Image, "raw_image_id", cs.ImageID)
		}
	}
	return inventory.Container{
		Name:     namespace + "/" + pod + "/" + cs.Name,
		Workload: workload,
		Image:    img,
		Declared: declared,
	}
}
