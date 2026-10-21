package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons of a Kustomize unit.
const (
	// ReasonUndeclaredAffectedWorkload: a running container that the mapping
	// does not list declares the value of the images entry, so the entry may
	// act on it too: a workload of the same namespace (or the same Helm
	// release or Flux Kustomization), or another container of a listed
	// container's Pod template.
	ReasonUndeclaredAffectedWorkload Reason = "undeclared_affected_workload"
	// ReasonInitContainerUnverified: a listed ordinary init container cannot
	// be shown to have run the image the unit's running containers run.
	ReasonInitContainerUnverified Reason = "init_container_unverified"
)

// KustomizeMapping ties the images entry of a kustomization file to the
// containers it sets the image of: the mapped workload and the others the
// entry acts on (Affects), which are fixed by the configuration.
type KustomizeMapping struct {
	// Workload is the workload key of the mapped container,
	// <kind>/<namespace>/<name>/<container>.
	Workload   string
	Repository string
	BaseBranch string
	// Path is the kustomization file and Image the name of its images entry.
	Path  string
	Image string
	// Affects are the workload keys of the other containers the entry acts on
	// (ordinary init containers included).
	Affects []string
}

// HelmValuesMapping ties the image key of a Helm values file to the containers
// it sets the image of: the mapped workload and the others the key acts on
// (Affects), which are fixed by the configuration.
type HelmValuesMapping struct {
	// Workload is the workload key of the mapped container,
	// <kind>/<namespace>/<name>/<container>.
	Workload   string
	Repository string
	BaseBranch string
	// Path is the values file and Key the dot-separated path of the key that
	// holds the image.
	Path string
	Key  string
	// Affects are the workload keys of the other containers the key acts on
	// (ordinary init containers included).
	Affects []string
}

// The routes of a shared edit point.
const (
	routeKustomize  = "kustomize"
	routeHelmValues = "helm_values"
)

// sharedMapping is a mapping of a shared edit point in the form the unit
// builder works on, whichever route names it.
type sharedMapping struct {
	Route      string
	Workload   string
	Repository string
	BaseBranch string
	Path       string
	// Item is the images entry name of a Kustomize mapping, the key of a Helm
	// values mapping.
	Item    string
	Affects []string
}

func (m KustomizeMapping) shared() sharedMapping {
	return sharedMapping{routeKustomize, m.Workload, m.Repository, m.BaseBranch, m.Path, m.Image, m.Affects}
}

func (m HelmValuesMapping) shared() sharedMapping {
	return sharedMapping{routeHelmValues, m.Workload, m.Repository, m.BaseBranch, m.Path, m.Key, m.Affects}
}

// editKey identifies the entry or key a mapping names.
func (m sharedMapping) editKey() string {
	return strings.Join([]string{m.Route, strings.ToLower(m.Repository), m.BaseBranch, m.Path, m.Item}, "|")
}

// fileKey identifies the file of a mapping.
func (m sharedMapping) fileKey() string {
	return strings.Join([]string{m.Route, strings.ToLower(m.Repository), m.BaseBranch, m.Path}, "|")
}

// noun names what the edit point is in messages.
func (m sharedMapping) noun() string {
	if m.Route == routeHelmValues {
		return "values key"
	}
	return "images entry"
}

// location is the logical location of the edit point.
func (m sharedMapping) location() string {
	if m.Route == routeHelmValues {
		return m.Item
	}
	return KustomizeLocation(m.Item)
}

// kustomizeUnitData is what a Kustomize unit carries beyond a Kubernetes
// manifest unit's fields.
type kustomizeUnitData struct {
	// route is routeKustomize or routeHelmValues, and item the name of the
	// images entry or the values key.
	route string
	item  string
	// mapped are the workload keys of the mappings; the rest of the unit's
	// workloads are the entry's other declared targets.
	mapped []string
	// viaInit are the members whose instances are ordinary init containers,
	// which no scan lists: each was shown to run the entity of a running
	// container of the same Pod.
	viaInit []string
}

// podKey is the namespace/pod of a Pod.
type podKey = string

// kustomizeEditPoint is one images entry with the set of containers declared
// for it.
type kustomizeEditPoint struct {
	key     string
	file    string
	first   sharedMapping
	mapped  []string
	members []string // sorted: the mapped workloads and their affects
}

// editPointsOf groups the mappings by the images entry they name. The members
// are the union of what the mappings of the entry declare (the configuration
// refuses mappings that declare different sets).
func editPointsOf(mappings []sharedMapping) []*kustomizeEditPoint {
	byKey := map[string]*kustomizeEditPoint{}
	var order []*kustomizeEditPoint
	for _, m := range mappings {
		ep := byKey[m.editKey()]
		if ep == nil {
			ep = &kustomizeEditPoint{key: m.editKey(), file: m.fileKey(), first: m}
			byKey[ep.key] = ep
			order = append(order, ep)
		}
		ep.mapped = append(ep.mapped, m.Workload)
		ep.members = append(ep.members, append([]string{m.Workload}, m.Affects...)...)
	}
	for _, ep := range order {
		ep.mapped = dedupeSorted(ep.mapped)
		ep.members = dedupeSorted(ep.members)
	}
	return order
}

// workloadParts splits <kind>/<namespace>/<name>/<container>.
func workloadParts(key string) (kind, namespace, name, container string, ok bool) {
	p := strings.Split(key, "/")
	if len(p) != 4 {
		return "", "", "", "", false
	}
	return p[0], p[1], p[2], p[3], true
}

// podOf is the namespace/pod part of a Kubernetes container's name.
func podOf(c inventory.Container) string {
	i := strings.LastIndexByte(c.Name, '/')
	if i < 0 {
		return ""
	}
	return c.Name[:i]
}

// workloadObject is kind/namespace/name of a workload key.
func workloadObject(key string) string {
	i := strings.LastIndexByte(key, '/')
	if i < 0 {
		return key
	}
	return key[:i]
}

// kubePod is a Pod as the running containers show it: the containers of it that
// run and the description of its spec and status they all carry.
type kubePod struct {
	id      podKey
	running []inventory.Container
	desc    *inventory.PodInit
}

// podsByObject fixes the observed Pods of every workload object
// (kind/namespace/name): the Pods any of its containers runs in, listed or not.
func podsByObject(containers []inventory.Container) map[string][]*kubePod {
	byID := map[string]*kubePod{}
	out := map[string][]*kubePod{}
	for _, c := range containers {
		if c.Declared == nil {
			continue
		}
		wk := c.WorkloadKey()
		if _, _, _, _, ok := workloadParts(wk); !ok || strings.HasPrefix(wk, "container/") {
			continue
		}
		object := workloadObject(wk)
		id := object + "|" + podOf(c)
		p := byID[id]
		if p == nil {
			p = &kubePod{id: podOf(c)}
			byID[id] = p
			out[object] = append(out[object], p)
		}
		p.running = append(p.running, c)
		if p.desc == nil {
			p.desc = c.PodInit
		}
	}
	for _, pods := range out {
		sort.Slice(pods, func(i, j int) bool { return pods[i].id < pods[j].id })
	}
	return out
}

// specEntries returns the spec entries of a Pod named name.
func (p *kubePod) specEntries(name string) []inventory.SpecContainer {
	if p.desc == nil {
		return nil
	}
	var out []inventory.SpecContainer
	for _, sc := range p.desc.Spec {
		if sc.Name == name {
			out = append(out, sc)
		}
	}
	return out
}

// initObservation returns the Pod's observation of an ordinary init container.
func (p *kubePod) initObservation(name string) *inventory.InitObservation {
	if p.desc == nil {
		return nil
	}
	for i := range p.desc.Containers {
		if p.desc.Containers[i].Name == name {
			return &p.desc.Containers[i]
		}
	}
	return nil
}

// kustomizeInstances collects the instances of every member of an edit point,
// Pod by Pod over all the observed Pods of each listed workload. In each Pod a
// listed container is a running container, or else an ordinary init container
// of the spec, which counts only if its status shows it ran the image entity
// of a running container of the set in the same Pod; an ordinary init
// container the Pod's status does not show, or no running container of the set
// to reuse, stops the unit. A listed container that is neither running nor an
// ordinary init container of a Pod (a main container that is waiting, a native
// sidecar not started) adds no instance there.
func kustomizeInstances(ep *kustomizeEditPoint, pods map[string][]*kubePod, inSet map[string]bool, itemIdx map[string]int) (map[string][]kubeInstance, map[string]bool, map[string]*unitProblem) {
	insts := map[string][]kubeInstance{}
	viaInit := map[string]bool{}
	probs := map[string]*unitProblem{}
	fail := func(member string, p *unitProblem) {
		if probs[member] == nil {
			probs[member] = p
		}
	}
	for _, w := range ep.members {
		if _, _, _, _, ok := workloadParts(w); !ok {
			fail(w, &unitProblem{ReasonInstancesMissing, fmt.Sprintf("%s is not a workload key", w)})
		}
	}
	for _, w := range ep.members {
		_, _, _, name, ok := workloadParts(w)
		if !ok {
			continue
		}
		for _, pod := range pods[workloadObject(w)] {
			var run *inventory.Container
			for i := range pod.running {
				if pod.running[i].WorkloadKey() == w {
					run = &pod.running[i]
					break
				}
			}
			if run != nil {
				in := kubeInstance{declared: run.Declared.Ref, running: run.Image.Ref, pod: pod.id}
				if run.Image.Ref != "" {
					ek, _ := inventory.EntityKeyOf(run.Image)
					in.itemKey = run.Image.Ref + "|" + entityString(ek)
				}
				insts[w] = append(insts[w], in)
				continue
			}
			// The listed container does not run in this Pod: that is acceptable
			// only where the Pod's spec shows what it is, and a Pod that does not
			// show it is a problem of its own that no other Pod makes up for.
			entries := pod.specEntries(name)
			obs := pod.initObservation(name)
			switch {
			case pod.desc == nil:
				fail(w, &unitProblem{ReasonInstancesMissing, fmt.Sprintf("pod %s has no description of its spec, so whether %s runs or ran in it cannot be verified", pod.id, w)})
				continue
			case len(entries) == 0 && obs != nil:
				// A status entry the spec has no container for.
				fail(w, &unitProblem{ReasonInitContainerUnverified, fmt.Sprintf("init container %s of pod %s: its status has an entry the spec has no container for", name, pod.id)})
				continue
			case len(entries) == 0:
				fail(w, &unitProblem{ReasonInstancesMissing, fmt.Sprintf("pod %s of the workload has no container %s in its spec, so %s cannot be verified in it", pod.id, name, w)})
				continue
			case len(entries) > 1:
				fail(w, &unitProblem{ReasonInitContainerUnverified, fmt.Sprintf("pod %s: the spec repeats the container name %s", pod.id, name)})
				continue
			case entries[0].Kind != inventory.SpecInit:
				// A main container that is waiting, a native sidecar not started.
				continue
			}
			in, p := verifyInitInstance(pod, name, obs, inSet, itemIdx)
			if p != nil {
				fail(w, p)
				continue
			}
			viaInit[w] = true
			insts[w] = append(insts[w], in)
		}
		if len(insts[w]) == 0 && probs[w] == nil {
			fail(w, &unitProblem{ReasonInstancesMissing,
				fmt.Sprintf("%s has no running instance, and no Pod of its workload runs it or shows it as an ordinary init container that ran an image of the set, so what an edit of its image changes cannot be verified", w)})
		}
	}
	return insts, viaInit, probs
}

// verifyInitInstance shows that the ordinary init container of a Pod ran the
// image entity of a running container of the set in the same Pod, under the
// reference its spec declares, and returns the instance it stands for.
func verifyInitInstance(pod *kubePod, name string, obs *inventory.InitObservation, inSet map[string]bool, itemIdx map[string]int) (kubeInstance, *unitProblem) {
	unverified := func(format string, args ...any) *unitProblem {
		return &unitProblem{ReasonInitContainerUnverified, fmt.Sprintf("init container %s of pod %s: ", name, pod.id) + fmt.Sprintf(format, args...)}
	}
	switch {
	case obs == nil || !obs.HasStatus:
		return kubeInstance{}, unverified("the Pod's status shows no ordinary init container of that name, so it cannot be verified")
	case obs.Declared.Ref == "":
		return kubeInstance{}, &unitProblem{ReasonDeclaredRefUnavailable, fmt.Sprintf("the image the pod spec names for init container %s of pod %s could not be read", name, pod.id)}
	case obs.Image.Ref == "":
		return kubeInstance{}, unverified("the status reports no image")
	case !sameReference(obs.Declared.Ref, obs.Image.Ref):
		return kubeInstance{}, &unitProblem{ReasonDeclaredRefMismatch, fmt.Sprintf("the pod spec names %s for init container %s of pod %s but its status reports %s", obs.Declared.Ref, name, pod.id, obs.Image.Ref)}
	}
	key, ok := inventory.EntityKeyOf(obs.Image)
	if !ok {
		return kubeInstance{}, unverified("its imageID does not identify an image entity, so it cannot be verified")
	}
	var sib *inventory.Container
	anySet := false
	for i := range pod.running {
		c := &pod.running[i]
		if !inSet[c.WorkloadKey()] {
			continue
		}
		anySet = true
		if sk, ok := inventory.EntityKeyOf(c.Image); ok && sk == key {
			sib = c
			break
		}
	}
	if !anySet {
		return kubeInstance{}, unverified("no running container of the set runs in the same Pod, so there is no scan to reuse")
	}
	if sib == nil {
		return kubeInstance{}, unverified("it ran an image entity that no running container of the set in the same Pod runs")
	}
	if !sameReference(sib.Image.Ref, obs.Image.Ref) {
		return kubeInstance{}, unverified("it ran the same image entity as %s but under the reference %s, not %s", sib.WorkloadKey(), obs.Image.Ref, sib.Image.Ref)
	}
	ek, _ := inventory.EntityKeyOf(sib.Image)
	in := kubeInstance{declared: obs.Declared.Ref, running: obs.Image.Ref, pod: pod.id, itemKey: sib.Image.Ref + "|" + entityString(ek)}
	if _, ok := itemIdx[in.itemKey]; !ok {
		return kubeInstance{}, unverified("the scan of %s that it would reuse is not in the plan", sib.WorkloadKey())
	}
	return in, nil
}

// ownersOf lists the Helm releases and Flux Kustomizations that manage a
// workload, from the chains of the plan's items and from those of every
// workload the cycle observed (a workload without a plan item has chains too).
func ownersOf(plan Plan, observed []WorkloadChains) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	var all []WorkloadChains
	for _, it := range plan.Items {
		all = append(all, it.Management...)
	}
	all = append(all, observed...)
	for _, m := range all {
		for _, chain := range m.Chains {
			for _, o := range chain {
				var k string
				switch {
				case o.Kind == OwnerHelm:
					k = "helm|" + o.Scope + "|" + o.Name
				case o.Kind == OwnerFlux && o.ResourceID == ResourceIDFluxKustomization:
					k = "flux-kustomization|" + o.Scope + "|" + o.Name
				default:
					continue
				}
				if out[m.Workload] == nil {
					out[m.Workload] = map[string]bool{}
				}
				out[m.Workload][k] = true
			}
		}
	}
	return out
}

// buildKustomizeUnits builds the update units of the images entries the
// mappings name. A unit is one entry (file, branch, path, image) together
// with the set of containers the configuration declares it acts on, and it is
// built only when some container of the set runs an image with a pr_candidate
// item.
//
// The set is fixed from the configuration and every member is checked: each
// must have running instances (an ordinary init container instead has the
// instances of the Pods of its workload, shown to have run the entity of a
// running container of the set), each instance must declare the reference it
// runs, all the instances of all the members must share one reference, and
// every instance must be in an adopted candidate item for one tag and digest.
// A container that is not listed but declares the entry's current value in the
// same namespace (or the same Helm release or Flux Kustomization), or in the
// same Pod template as a listed one, stops the unit.
func buildKustomizeUnits(plan Plan, containers []inventory.Container, kustomize []KustomizeMapping, helm []HelmValuesMapping, management []WorkloadChains) []*composeUnit {
	var mappings []sharedMapping
	for _, m := range kustomize {
		mappings = append(mappings, m.shared())
	}
	for _, m := range helm {
		mappings = append(mappings, m.shared())
	}
	itemIdx := map[string]int{}
	for i := range plan.Items {
		if _, dup := itemIdx[plan.Items[i].Key]; !dup {
			itemIdx[plan.Items[i].Key] = i
		}
	}
	pods := podsByObject(containers)
	owners := ownersOf(plan, management)

	var out []*composeUnit
	fileMembers := map[string][]*kubeMember{}
	var files []string
	for _, ep := range editPointsOf(mappings) {
		inSet := map[string]bool{}
		for _, w := range ep.members {
			inSet[w] = true
		}
		if _, seen := fileMembers[ep.file]; !seen {
			files = append(files, ep.file)
		}

		type memberResult struct {
			mb      *kubeMember
			insts   []kubeInstance
			viaInit bool
		}
		memberInsts, viaInitOf, memberProbs := kustomizeInstances(ep, pods, inSet, itemIdx)
		var results []memberResult
		runs := map[string]bool{}
		declaredRefs := map[string]bool{}
		for _, w := range ep.members {
			mb := &kubeMember{
				m:        KubernetesMapping{Workload: w, Repository: ep.first.Repository, BaseBranch: ep.first.BaseBranch, Path: ep.first.Path},
				byRun:    map[string][]kubeInstance{},
				raw:      map[string]string{},
				declared: map[string]bool{},
			}
			fail := func(p *unitProblem) {
				if mb.prob == nil {
					mb.prob = p
				}
			}
			insts, viaInit := memberInsts[w], viaInitOf[w]
			if prob := memberProbs[w]; prob != nil {
				fail(prob)
			}
			for _, in := range insts {
				switch {
				case in.running == "":
					fail(&unitProblem{ReasonInstancesMissing, fmt.Sprintf("an instance of %s has no running reference, so the instances cannot all be verified", w)})
				case in.declared == "":
					fail(&unitProblem{ReasonDeclaredRefUnavailable, fmt.Sprintf("the image the pod spec of %s names could not be read for a running instance", w)})
				case !sameReference(in.declared, in.running):
					fail(&unitProblem{ReasonDeclaredRefMismatch, fmt.Sprintf("the pod spec of %s names %s but an instance runs %s", w, in.declared, in.running)})
				}
				if in.declared != "" {
					mb.declared[normalizedRef(in.declared)] = true
					declaredRefs[normalizedRef(in.declared)] = true
				}
				if in.running != "" {
					n := normalizedRef(in.running)
					mb.byRun[n] = append(mb.byRun[n], in)
					runs[n] = true
					if in.declared != "" {
						if r := mb.raw[n]; r == "" || in.declared < r {
							mb.raw[n] = in.declared
						}
					}
				}
			}
			results = append(results, memberResult{mb, insts, viaInit})
			fileMembers[ep.file] = append(fileMembers[ep.file], mb)
		}

		u := &composeUnit{
			repo: ep.first.Repository, baseBranch: ep.first.BaseBranch, path: ep.first.Path,
			svcItems: map[string][]*Item{},
			kube:     &kubeUnitData{location: map[string]string{}, file: ep.file, kustomize: &kustomizeUnitData{route: ep.first.Route, item: ep.first.Item, mapped: ep.mapped}},
		}
		loc := ep.first.location()
		u.locations = []string{loc}
		runList := sortedSet(runs)
		runKey := "none"
		if len(runList) > 0 {
			runKey = runList[0]
		}
		u.normRef = runKey
		u.key = ep.key + "|" + runKey

		var problem *unitProblem
		var missing []string
		seenItem := map[int]bool{}
		relevant := false
		for _, r := range results {
			w := r.mb.m.Workload
			u.services = append(u.services, w)
			u.kube.location[w] = loc
			if r.viaInit {
				u.kube.kustomize.viaInit = append(u.kube.kustomize.viaInit, w)
			}
			if problem == nil {
				problem = r.mb.prob
			}
			for _, in := range r.insts {
				if u.current == "" || (in.running != "" && in.running < u.current) {
					u.current = in.running
				}
				if raw := in.declared; raw != "" && (u.kube.declared == "" || raw < u.kube.declared) {
					u.kube.declared = raw
				}
				i, ok := itemIdx[in.itemKey]
				if !ok {
					if in.itemKey != "" || in.running != "" {
						missing = append(missing, w)
					}
					continue
				}
				it := &plan.Items[i]
				if it.Category == CategoryPRCandidate {
					relevant = true
				}
				if !containsItem(u.svcItems[w], it) {
					u.svcItems[w] = append(u.svcItems[w], it)
				}
				if !seenItem[i] {
					seenItem[i] = true
					u.items = append(u.items, it)
				}
			}
		}
		if !relevant {
			continue
		}
		sort.Strings(u.services)
		u.workloads = append([]string(nil), u.services...)
		sort.Slice(u.items, func(a, b int) bool { return itemIdx[u.items[a].Key] < itemIdx[u.items[b].Key] })
		u.order = itemIdx[u.items[0].Key]
		sort.Strings(u.kube.kustomize.viaInit)

		switch {
		case problem != nil:
			u.manual, u.manualReason, u.manualDetail = true, problem.reason, problem.detail
		case len(missing) > 0:
			u.manual, u.manualReason = true, ReasonInstancesMissing
			u.manualDetail = fmt.Sprintf("a running instance of %s has no plan item, so the whole set cannot be verified", strings.Join(dedupeSorted(missing), ", "))
		case len(runs) > 1 || len(declaredRefs) > 1:
			u.manual, u.manualReason = true, ReasonMixedReferences
			u.manualDetail = fmt.Sprintf("the instances of the containers the %s %q acts on do not all declare, or run, one reference (%s)", ep.first.noun(), ep.first.Item,
				strings.Join(append(sortedSet(declaredRefs), runList...), ", "))
		default:
			u.checkAdopted()
		}
		if !u.manual {
			if p := undeclaredAffected(u, ep, containers, pods, owners); p != nil {
				u.manual, u.manualReason, u.manualDetail = true, p.reason, p.detail
			}
		}

		alsoSeen := map[ServiceRef]bool{}
		for _, it := range u.items {
			for _, s := range it.Services {
				if s.Workload != "" && inSet[s.Workload] {
					continue
				}
				if !alsoSeen[s] {
					alsoSeen[s] = true
					u.also = append(u.also, s)
				}
			}
			for _, m := range it.Management {
				if containsString(u.workloads, m.Workload) && !containsChains(u.kube.management, m) {
					u.kube.management = append(u.kube.management, m)
				}
			}
		}
		sortServiceRefs(u.also)
		sort.Slice(u.kube.management, func(i, j int) bool { return u.kube.management[i].Workload < u.kube.management[j].Workload })
		out = append(out, u)
	}
	holdBackFiles(out, files, fileMembers)
	sort.Slice(out, func(i, j int) bool {
		if out[i].order != out[j].order {
			return out[i].order < out[j].order
		}
		return out[i].key < out[j].key
	})
	return out
}

// undeclaredAffected is the safety net for the set the configuration fixed:
// it finds a running container that is not listed but declares the value the
// entry gives, in the same namespace as a listed container (or managed by the
// same Helm release or Flux Kustomization), and an ordinary init container of
// a listed container's Pod that declares it. Such a container may well be one
// the entry acts on, and an edit would change it unannounced.
func undeclaredAffected(u *composeUnit, ep *kustomizeEditPoint, containers []inventory.Container, pods map[string][]*kubePod, owners map[string]map[string]bool) *unitProblem {
	value := u.kube.declared
	inSet := map[string]bool{}
	namespaces := map[string]bool{}
	memberOwners := map[string]bool{}
	for _, w := range ep.members {
		inSet[w] = true
		if _, ns, _, _, ok := workloadParts(w); ok {
			namespaces[ns] = true
		}
		for k := range owners[w] {
			memberOwners[k] = true
		}
	}
	stop := func(format string, args ...any) *unitProblem {
		return &unitProblem{ReasonUndeclaredAffectedWorkload, fmt.Sprintf(format, args...) +
			fmt.Sprintf(" (list it in affects of the mapping of %s, or change what the %s acts on)", u.services[0], ep.first.noun())}
	}
	for _, c := range containers {
		if c.Declared == nil {
			continue
		}
		wk := c.WorkloadKey()
		if wk == "" {
			continue
		}
		if !inSet[wk] && c.Declared.Ref != "" && sameReference(c.Declared.Ref, value) {
			// The namespace is that of the Pod, which a container whose workload
			// is unknown has as well.
			ns, _, _ := strings.Cut(c.Name, "/")
			shared := ""
			switch {
			case namespaces[ns]:
				shared = "namespace " + ns
			default:
				for k := range owners[wk] {
					if memberOwners[k] {
						shared = "the same " + strings.ReplaceAll(strings.SplitN(k, "|", 2)[0], "-", " ")
						break
					}
				}
			}
			if shared != "" {
				return stop("%s is not listed but declares %s, the value of the %s %q, and shares %s with the listed containers", wk, c.Declared.Ref, ep.first.noun(), ep.first.Item, shared)
			}
		}
	}
	// Every container entry of the spec of each Pod of a listed workload, whether
	// it runs or not: a main container that is waiting, a native sidecar, an
	// ordinary init container.
	objects := map[string]bool{}
	for _, w := range ep.members {
		objects[workloadObject(w)] = true
	}
	var objectList []string
	for o := range objects {
		objectList = append(objectList, o)
	}
	sort.Strings(objectList)
	for _, object := range objectList {
		for _, pod := range pods[object] {
			if pod.desc == nil {
				continue
			}
			for _, sc := range pod.desc.Spec {
				if inSet[object+"/"+sc.Name] || sc.Ref == "" || !sameReference(sc.Ref, value) {
					continue
				}
				return stop("%s %s of pod %s is not listed but declares %s, the value of the %s %q", sc.Kind, sc.Name, pod.id, sc.Ref, ep.first.noun(), ep.first.Item)
			}
		}
	}
	return nil
}
