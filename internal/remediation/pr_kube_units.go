package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// KubernetesMapping ties a running Kubernetes container to the manifest file
// in a repository that defines it.
type KubernetesMapping struct {
	// Workload is the workload key, <kind>/<namespace>/<name>/<container>.
	Workload   string
	Repository string
	BaseBranch string
	// Path is the manifest file. ObjectKind and ObjectName name the object in
	// it when it differs from the running workload's own kind and name.
	Path       string
	ObjectKind string
	ObjectName string
}

// manifestTarget is the container the mapping names.
func (m KubernetesMapping) manifestTarget() (ManifestTarget, bool) {
	parts := strings.Split(m.Workload, "/")
	if len(parts) != 4 {
		return ManifestTarget{}, false
	}
	kind := inventory.WorkloadKind(parts[0])
	if _, ok := manifestKinds[kind]; !ok {
		return ManifestTarget{}, false
	}
	return ManifestTarget{Kind: kind, Namespace: parts[1], Name: parts[2], Container: parts[3], ObjectKind: m.ObjectKind, ObjectName: m.ObjectName}, true
}

// kubeUnitData is what a Kubernetes manifest unit carries beyond a Compose
// unit's fields.
type kubeUnitData struct {
	// targets are the containers to edit, sorted by workload key.
	targets []ManifestTarget
	// declared is the reference their Pod specs declare, the same for all.
	declared string
	// file identifies the manifest file (repository, branch, path).
	file string
	// location is the location of each workload's container, by workload key.
	location map[string]string
	// management are the management chains of the unit's workloads, as the
	// plan shows them.
	management []WorkloadChains
}

// Location is where the target's image is, as <Kind>/<namespace>/<name>/<container>
// with the Kind and name of the object the mapping names (the workload's own
// unless the mapping says otherwise) and the namespace of the workload. It is
// known without reading the file, which a record's identity must not wait for,
// and it changes when the mapping names another object.
func (t ManifestTarget) Location() string {
	kind, name := t.ObjectKind, t.ObjectName
	if kind == "" {
		kind = manifestKinds[t.Kind].kind
	}
	if name == "" {
		name = t.Name
	}
	return kind + "/" + t.Namespace + "/" + name + "/" + t.Container
}

// kubeFileKey identifies the manifest file a mapping names.
func kubeFileKey(m KubernetesMapping) string {
	return strings.Join([]string{"kubernetes", strings.ToLower(m.Repository), m.BaseBranch, m.Path}, "|")
}

// unitProblem is why a unit is left for a person.
type unitProblem struct {
	reason Reason
	detail string
}

// kubeInstance is one running container of a mapped workload.
type kubeInstance struct {
	declared string
	running  string
	itemKey  string
}

// kubeMember is one mapped container with what its running instances say.
type kubeMember struct {
	m        KubernetesMapping
	target   ManifestTarget
	byRun    map[string][]kubeInstance // instances by normalized running reference
	raw      map[string]string         // a normalized running reference's declared form as the specs spell it
	declared map[string]bool           // the normalized references the specs declare
	prob     *unitProblem
	hasItems bool
}

// buildKubernetesUnits groups the mapped Kubernetes containers by the manifest
// file their mapping names and by the reference their Pod specs declare. A
// unit is built only when it has at least one container in a pr_candidate
// item; the rest have nothing to propose.
//
// A unit is keyed by the reference its containers run (which they all declare
// when the unit can be edited). Every running instance of every mapped container is collected first, and a
// container's problem belongs to every unit it can be part of: a unit is manual
// unless each instance of each of its containers has a plan item, declares the
// reference it runs, shares that reference with all the others and belongs to
// an adopted candidate that is the same for all. A container that runs normally
// with nothing to fix has no plan item and takes no part in a unit of another
// image. A container that cannot be
// placed in a unit (no instance has a running reference) holds back every
// unit of its file; one that runs more than one reference is part of the unit
// of each. A pull request never covers a subset of the instances, and a set
// that is not whole (a rollout in progress, an instance without a finding) is
// left for a later cycle.
func buildKubernetesUnits(plan Plan, containers []inventory.Container, mappings []KubernetesMapping) []*composeUnit {
	itemIdx := map[string]int{}
	for i := range plan.Items {
		if _, dup := itemIdx[plan.Items[i].Key]; !dup {
			itemIdx[plan.Items[i].Key] = i
		}
	}
	byWorkload := map[string]KubernetesMapping{}
	for _, m := range mappings {
		if _, dup := byWorkload[m.Workload]; !dup {
			byWorkload[m.Workload] = m
		}
	}

	instances := map[string][]kubeInstance{}
	for _, c := range containers {
		if c.Declared == nil {
			continue
		}
		wk := c.WorkloadKey()
		if _, ok := byWorkload[wk]; !ok {
			continue
		}
		in := kubeInstance{declared: c.Declared.Ref, running: c.Image.Ref}
		if c.Image.Ref != "" {
			ek, _ := inventory.EntityKeyOf(c.Image)
			in.itemKey = c.Image.Ref + "|" + entityString(ek)
		}
		instances[wk] = append(instances[wk], in)
	}

	fileOf := kubeFileKey
	var members []*kubeMember
	for _, m := range mappings {
		if byWorkload[m.Workload] != m {
			continue // a repeated mapping of the workload
		}
		t, ok := m.manifestTarget()
		insts := instances[m.Workload]
		if !ok {
			continue
		}
		mb := &kubeMember{m: m, target: t, byRun: map[string][]kubeInstance{}, raw: map[string]string{}, declared: map[string]bool{}}
		fail := func(reason Reason, format string, args ...any) {
			if mb.prob == nil {
				mb.prob = &unitProblem{reason, fmt.Sprintf(format, args...)}
			}
		}
		if len(insts) == 0 {
			fail(ReasonInstancesMissing, "%s has no running instance, so what an edit of its image changes cannot be verified", m.Workload)
		}
		for _, in := range insts {
			switch {
			case in.running == "":
				fail(ReasonInstancesMissing, "an instance of %s has no running reference, so the instances cannot all be verified", m.Workload)
			case in.declared == "":
				fail(ReasonDeclaredRefUnavailable, "the image the pod spec of %s names could not be read for a running instance", m.Workload)
			case !sameReference(in.declared, in.running):
				fail(ReasonDeclaredRefMismatch, "the pod spec of %s names %s but an instance runs %s", m.Workload, in.declared, in.running)
			}
			if in.declared != "" {
				mb.declared[normalizedRef(in.declared)] = true
			}
			if in.running != "" {
				n := normalizedRef(in.running)
				mb.byRun[n] = append(mb.byRun[n], in)
				if in.declared != "" {
					if r := mb.raw[n]; r == "" || in.declared < r {
						mb.raw[n] = in.declared
					}
				}
			}
		}
		if len(mb.byRun) > 1 || len(mb.declared) > 1 {
			fail(ReasonMixedReferences, "the instances of %s do not all declare, or run, one reference (%s)", m.Workload,
				strings.Join(append(sortedSet(mb.declared), sortedSet(keySetOf(mb.byRun))...), ", "))
		}
		members = append(members, mb)
	}

	type group struct {
		key     string
		members []*kubeMember
		run     string
	}
	groups := map[string]*group{}
	var order []*group
	byFile := map[string][]*kubeMember{}
	var files []string
	for _, mb := range members {
		file := fileOf(mb.m)
		if _, seen := byFile[file]; !seen {
			files = append(files, file)
		}
		byFile[file] = append(byFile[file], mb)
		for run := range mb.byRun {
			gk := file + "|" + run
			g := groups[gk]
			if g == nil {
				g = &group{key: gk, run: run}
				groups[gk] = g
				order = append(order, g)
			}
			g.members = append(g.members, mb)
		}
	}
	var out []*composeUnit
	for _, g := range order {
		first := g.members[0]
		u := &composeUnit{
			key: g.key, repo: first.m.Repository, baseBranch: first.m.BaseBranch, path: first.m.Path,
			normRef: g.run, svcItems: map[string][]*Item{},
			kube: &kubeUnitData{location: map[string]string{}, file: fileOf(first.m)},
		}
		seenItem := map[int]bool{}
		relevant := false
		var problem *unitProblem
		var missing []string
		for _, mb := range g.members {
			w := mb.m.Workload
			u.services = append(u.services, w)
			u.kube.targets = append(u.kube.targets, mb.target)
			u.kube.location[w] = mb.target.Location()
			if problem == nil {
				problem = mb.prob
			}
			if raw := mb.raw[g.run]; raw != "" && (u.kube.declared == "" || raw < u.kube.declared) {
				u.kube.declared = raw
			}
			for _, in := range mb.byRun[g.run] {
				if u.current == "" || in.running < u.current {
					u.current = in.running
				}
				i, ok := itemIdx[in.itemKey]
				if !ok {
					missing = append(missing, w)
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
		for _, w := range u.services {
			u.locations = append(u.locations, u.kube.location[w])
		}
		sort.Strings(u.locations)
		sort.Slice(u.kube.targets, func(i, j int) bool { return u.kube.targets[i].Workload() < u.kube.targets[j].Workload() })
		sort.Slice(u.items, func(a, b int) bool { return itemIdx[u.items[a].Key] < itemIdx[u.items[b].Key] })
		u.order = itemIdx[u.items[0].Key]

		switch {
		case problem != nil:
			u.manual, u.manualReason, u.manualDetail = true, problem.reason, problem.detail
		case len(missing) > 0:
			u.manual, u.manualReason = true, ReasonInstancesMissing
			u.manualDetail = fmt.Sprintf("a running instance of %s has no plan item, so the whole set cannot be verified", strings.Join(dedupeSorted(missing), ", "))
		default:
			u.checkAdopted()
		}

		alsoSeen := map[ServiceRef]bool{}
		for _, it := range u.items {
			for _, s := range it.Services {
				if _, isMapped := byWorkload[s.Workload]; s.Workload != "" && isMapped {
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
	holdBackFiles(out, files, byFile)
	sort.Slice(out, func(i, j int) bool {
		if out[i].order != out[j].order {
			return out[i].order < out[j].order
		}
		return out[i].key < out[j].key
	})
	return out
}

// holdBackFiles makes a file's units all manual when anything about the file is
// not whole: a mapped container with a problem of its own (no instance, no
// running reference, a declaration that disagrees or cannot be read, more than
// one reference), or a unit that is manual for any reason (an instance of the
// image being edited without a plan item, or one that is not an adopted
// candidate). A mapped container that runs normally and has nothing to fix has
// no plan item and is no problem: its line is simply not edited. Editing part of a file's containers would leave the rest on a
// state nobody verified, so no unit of the file gets a pull request.
func holdBackFiles(units []*composeUnit, files []string, byFile map[string][]*kubeMember) {
	for _, file := range files {
		var reason Reason
		var detail string
		for _, mb := range byFile[file] {
			if mb.prob != nil {
				reason, detail = mb.prob.reason, mb.prob.detail+" ("+mb.m.Workload+" holds back every pull request for "+mb.m.Path+")"
				break
			}
		}
		var fileUnits []*composeUnit
		for _, u := range units {
			if u.kube.file == file {
				fileUnits = append(fileUnits, u)
				if reason == "" && u.manual {
					reason, detail = u.manualReason, u.manualDetail+" (it holds back every pull request for "+u.path+")"
				}
			}
		}
		if reason == "" {
			continue
		}
		for _, u := range fileUnits {
			u.manual, u.manualReason, u.manualDetail = true, reason, detail
		}
	}
}

func keySetOf[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func containsChains(list []WorkloadChains, m WorkloadChains) bool {
	for _, have := range list {
		if have.Key() == m.Key() {
			return true
		}
	}
	return false
}

// kubeBranchNames are the names the branch of a Kubernetes unit is shown
// with: those of the objects its containers belong to.
func (u *composeUnit) kubeBranchNames() []string {
	var names []string
	for _, w := range u.services {
		names = append(names, workloadService(w))
	}
	return dedupeSorted(names)
}
