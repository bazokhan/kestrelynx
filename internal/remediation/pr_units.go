package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// ComposeMapping ties a running Compose workload to the service of a Compose
// file in a repository that deploys it.
type ComposeMapping struct {
	// Workload is the Compose workload key, compose/<project>/<service>;
	// Project and Service are its parts, as the running container reports
	// them.
	Workload   string
	Project    string
	Service    string
	Repository string
	BaseBranch string
	// Path is the Compose file, ComposeService the service in it.
	Path           string
	ComposeService string
}

// composeUnit is one update unit: the mapped services of one Compose file
// (repository, branch, path) whose running image is the same reference.
type composeUnit struct {
	// A Dockerfile unit (df is set) reuses the fields below: path is the
	// Dockerfile, locations hold the edited FROM's position, current is the
	// base image the FROM names, candidate the candidate base, and services and
	// workloads the workloads built through it.
	key        string
	repo       string // as the first mapping spells it
	baseBranch string
	path       string
	// current is the running reference used to check the file, normRef its
	// normalized form.
	current string
	normRef string

	services  []string // Compose services, sorted
	locations []string // services.<svc>.image, sorted
	workloads []string // sorted
	// svcItems lists, per Compose service, the plan items of its running
	// entities.
	svcItems map[string][]*Item
	items    []*Item // distinct, in plan order
	also     []ServiceRef
	order    int

	manual       bool
	manualReason Reason
	manualDetail string

	candidate *ImageState // shared by every item when the unit is adopted

	// df is set for a Dockerfile unit, lang for a language unit and kube for a
	// Kubernetes manifest unit. A Kubernetes unit's services and workloads are
	// the workload keys of its containers; its locations are theirs images' places.
	df   *dockerfileUnitData
	lang *languageUnitData
	kube *kubeUnitData
}

// notAdoptedReason is the reason of a unit whose images are not all adopted
// candidates.
func (u *composeUnit) notAdoptedReason() Reason {
	if u.kube != nil {
		return ReasonKubernetesSetNotAdopted
	}
	return ReasonComposeSetNotAdopted
}

// locationOf is the location of one member of the unit: the image key of a
// Compose service, the location of a Kubernetes container's image in its
// object (ManifestTarget.Location).
func (u *composeUnit) locationOf(member string) string {
	if u.kube != nil {
		return u.kube.location[member]
	}
	return "services." + member + ".image"
}

// normalizedRef is the reference in the form units are grouped by: the
// normalized repository with the tag (and digest) as written. A reference
// that cannot be normalized stands for itself.
func normalizedRef(ref string) string {
	key, ok := inventory.RepositoryKey(ref)
	if !ok {
		return ref
	}
	s := key + ":" + inventory.TagOf(ref)
	if d := inventory.DigestOf(ref); d != "" {
		s += "@" + d
	}
	return s
}

// unitMember is one running container of a mapped service.
type unitMember struct {
	service  string
	workload string
	itemKey  string
	ref      string
}

// buildComposeUnits groups the running Compose containers by the Compose file
// their mapping names and by their running reference. Only units with at
// least one entity in a pr_candidate item are returned; the rest have nothing
// to propose. A unit is manual unless every running entity of every one of
// its services is in a pr_candidate item and all those items name the same
// candidate tag and top digest: a pull request never covers a subset of the
// services that run the image in the file.
func buildComposeUnits(plan Plan, containers []inventory.Container, mappings []ComposeMapping) []*composeUnit {
	itemIdx := map[string]int{}
	for i := range plan.Items {
		if _, dup := itemIdx[plan.Items[i].Key]; !dup {
			itemIdx[plan.Items[i].Key] = i
		}
	}
	byWorkload := map[string]ComposeMapping{}
	for _, m := range mappings {
		byWorkload[m.Project+"\x00"+m.Service] = m
	}
	mapped := func(project, service string) bool {
		_, ok := byWorkload[project+"\x00"+service]
		return ok
	}

	units := map[string]*composeUnit{}
	members := map[string][]unitMember{}
	for _, c := range containers {
		if c.Workload.Kind != inventory.WorkloadCompose || c.Image.Ref == "" {
			continue
		}
		m, ok := byWorkload[c.Workload.Group+"\x00"+c.Workload.Name]
		if !ok {
			continue
		}
		norm := normalizedRef(c.Image.Ref)
		key := strings.Join([]string{"compose", strings.ToLower(m.Repository), m.BaseBranch, m.Path, norm}, "|")
		u := units[key]
		if u == nil {
			u = &composeUnit{key: key, repo: m.Repository, baseBranch: m.BaseBranch, path: m.Path, current: c.Image.Ref, normRef: norm, svcItems: map[string][]*Item{}}
			units[key] = u
		}
		if c.Image.Ref < u.current {
			u.current = c.Image.Ref
		}
		ek, _ := inventory.EntityKeyOf(c.Image)
		members[key] = append(members[key], unitMember{service: m.ComposeService, workload: m.Workload, itemKey: c.Image.Ref + "|" + entityString(ek), ref: c.Image.Ref})
	}

	var out []*composeUnit
	for key, u := range units {
		svcSet, wlSet := map[string]bool{}, map[string]bool{}
		seenItem := map[int]bool{}
		relevant := false
		var missing []string
		for _, mb := range members[key] {
			svcSet[mb.service] = true
			wlSet[mb.workload] = true
			i, ok := itemIdx[mb.itemKey]
			if !ok {
				missing = append(missing, mb.workload)
				continue
			}
			it := &plan.Items[i]
			if it.Category == CategoryPRCandidate {
				relevant = true
			}
			if !containsItem(u.svcItems[mb.service], it) {
				u.svcItems[mb.service] = append(u.svcItems[mb.service], it)
			}
			if !seenItem[i] {
				seenItem[i] = true
				u.items = append(u.items, it)
			}
		}
		if !relevant {
			continue
		}
		for s := range svcSet {
			u.services = append(u.services, s)
		}
		sort.Strings(u.services)
		for _, s := range u.services {
			u.locations = append(u.locations, "services."+s+".image")
		}
		for w := range wlSet {
			u.workloads = append(u.workloads, w)
		}
		sort.Strings(u.workloads)
		sort.Slice(u.items, func(a, b int) bool { return itemIdx[u.items[a].Key] < itemIdx[u.items[b].Key] })
		u.order = itemIdx[u.items[0].Key]

		switch {
		case len(missing) > 0:
			sort.Strings(missing)
			u.manual, u.manualReason = true, ReasonComposeSetNotAdopted
			u.manualDetail = fmt.Sprintf("a running entity of %s has no plan item, so the whole service set cannot be verified", strings.Join(dedupeSorted(missing), ", "))
		default:
			u.checkAdopted()
		}

		alsoSeen := map[ServiceRef]bool{}
		for _, it := range u.items {
			for _, s := range it.Services {
				if s.Project != "" && mapped(s.Project, s.Service) {
					continue
				}
				if !alsoSeen[s] {
					alsoSeen[s] = true
					u.also = append(u.also, s)
				}
			}
		}
		sortServiceRefs(u.also)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].order != out[j].order {
			return out[i].order < out[j].order
		}
		return out[i].key < out[j].key
	})
	return out
}

// checkAdopted requires every item of the unit to be an adopted pinned-tag
// candidate for the same tag and top digest.
func (u *composeUnit) checkAdopted() {
	var cand *ImageState
	for _, it := range u.items {
		if it.Category != CategoryPRCandidate || it.Candidate == nil || it.Comparison == nil {
			u.manual, u.manualReason = true, u.notAdoptedReason()
			u.manualDetail = fmt.Sprintf("%s is %s, not an adopted candidate; a pull request never covers part of the services running the image", it.Current.Ref, it.Category)
			return
		}
		if cand == nil {
			cand = it.Candidate
			continue
		}
		if it.Candidate.Tag != cand.Tag || it.Candidate.TopDigest != cand.TopDigest {
			u.manual, u.manualReason = true, u.notAdoptedReason()
			u.manualDetail = fmt.Sprintf("the running entities have different candidates (%s and %s)", cand.Ref, it.Candidate.Ref)
			return
		}
	}
	c := *cand
	u.candidate = &c
}

// fixTargets returns, per location, the targets that every entity of the
// service resolves in its verified comparison: a fix is claimed for a
// location only when it holds for all of the location's running entities.
func (u *composeUnit) fixTargets() []FixTarget {
	if u.df != nil {
		return u.df.fixTargets
	}
	if u.lang != nil {
		return u.lang.fixTargets
	}
	return u.perLocation(func(it *Item) map[verdictKey]bool {
		res := resolvedPairs(it)
		out := map[verdictKey]bool{}
		for _, t := range it.Targets {
			k := verdictKey{t.VulnID, t.Package}
			if res[k] {
				out[k] = true
			}
		}
		return out
	})
}

// resolvedAll returns, per location, every pair the comparison resolved for
// all of the location's running entities, targets or not.
func (u *composeUnit) resolvedAll() []FixTarget {
	return u.perLocation(resolvedPairs)
}

func (u *composeUnit) perLocation(pairs func(*Item) map[verdictKey]bool) []FixTarget {
	if u.kube != nil && u.kube.kustomize != nil {
		return u.sharedLocation(pairs)
	}
	var out []FixTarget
	for _, s := range u.services {
		var acc map[verdictKey]bool
		for _, it := range u.svcItems[s] {
			p := pairs(it)
			if acc == nil {
				acc = p
				continue
			}
			for k := range acc {
				if !p[k] {
					delete(acc, k)
				}
			}
		}
		loc := u.locationOf(s)
		for k := range acc {
			out = append(out, FixTarget{Location: loc, VulnID: k.vuln, Package: k.coord})
		}
	}
	sortFixTargets(out)
	return out
}

// sharedLocation is perLocation for a unit whose members share one edit point:
// the images entry changes the image of every member at once, so a fix is
// claimed for the location only when it holds for the running entities of all
// of them.
func (u *composeUnit) sharedLocation(pairs func(*Item) map[verdictKey]bool) []FixTarget {
	var acc map[verdictKey]bool
	for _, s := range u.services {
		for _, it := range u.svcItems[s] {
			p := pairs(it)
			if acc == nil {
				acc = p
				continue
			}
			for k := range acc {
				if !p[k] {
					delete(acc, k)
				}
			}
		}
	}
	var out []FixTarget
	if len(u.locations) == 0 {
		return nil
	}
	for k := range acc {
		out = append(out, FixTarget{Location: u.locations[0], VulnID: k.vuln, Package: k.coord})
	}
	sortFixTargets(out)
	return out
}

func resolvedPairs(it *Item) map[verdictKey]bool {
	out := map[verdictKey]bool{}
	if it.Comparison == nil {
		return out
	}
	for _, v := range it.Comparison.Verdicts {
		if v.Outcome == OutcomeResolved {
			out[verdictKey{v.VulnID, v.Package}] = true
		}
	}
	return out
}

// evidence summarizes the comparison of every item of the unit. Findings
// with a target are listed apart from the other compared findings, as the
// plan counts only targets.
func (u *composeUnit) evidence(plan Plan) *VerificationSummary {
	if u.df != nil {
		return u.df.evidence
	}
	if u.lang != nil {
		// A language update has no comparison of images; its checks are in
		// the plan item.
		return nil
	}
	vs := &VerificationSummary{
		TrivyVersion:    plan.Conditions.TrivyVersion,
		Severities:      append([]string(nil), plan.Conditions.Severities...),
		PlanGeneratedAt: plan.GeneratedAt,
	}
	if t := plan.Conditions.VulnerabilityDB.UpdatedAt; !t.IsZero() {
		tt := t
		vs.VulnDBUpdatedAt = &tt
	}
	for _, it := range u.items {
		ev := ItemEvidence{ItemKey: it.Key, Current: it.Current, BaselineScan: it.BaselineScan, CandidateScan: it.CandidateScan}
		if it.Candidate != nil {
			ev.Candidate = *it.Candidate
		}
		for _, s := range u.services {
			if containsItem(u.svcItems[s], it) {
				if loc := u.locationOf(s); !containsString(ev.Locations, loc) {
					ev.Locations = append(ev.Locations, loc)
				}
			}
		}
		intel := map[verdictKey]Target{}
		for _, t := range it.Targets {
			intel[verdictKey{t.VulnID, t.Package}] = t
		}
		summary := func(v VulnVerdict) VulnSummary {
			s := VulnSummary{VulnID: v.VulnID, Package: v.Package, Severity: string(v.Severity)}
			if t, ok := intel[verdictKey{v.VulnID, v.Package}]; ok {
				s.Priority, s.KEV = t.Priority, t.KEV
			}
			return s
		}
		if c := it.Comparison; c != nil {
			if vs.Scope == "" {
				vs.Scope = c.Scope
			}
			if len(c.Severities) > 0 {
				vs.Severities = append([]string(nil), c.Severities...)
			}
			for _, v := range c.Verdicts {
				_, target := intel[verdictKey{v.VulnID, v.Package}]
				switch {
				case v.Outcome == OutcomeResolved && target:
					ev.Resolved = append(ev.Resolved, summary(v))
				case v.Outcome == OutcomeRemaining && target:
					ev.Remaining = append(ev.Remaining, summary(v))
				case v.Outcome == OutcomeResolved:
					ev.OtherResolved = append(ev.OtherResolved, summary(v))
				case v.Outcome == OutcomeRemaining:
					ev.OtherRemaining = append(ev.OtherRemaining, summary(v))
				}
			}
			for _, v := range c.Introduced {
				ev.Introduced = append(ev.Introduced, summary(v))
			}
		}
		vs.Items = append(vs.Items, ev)
	}
	return vs
}

func containsItem(items []*Item, it *Item) bool {
	for _, x := range items {
		if x == it {
			return true
		}
	}
	return false
}

func sortServiceRefs(s []ServiceRef) {
	sort.Slice(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Container != b.Container {
			return a.Container < b.Container
		}
		return a.Workload < b.Workload
	})
}

func sortFixTargets(f []FixTarget) {
	sort.Slice(f, func(i, j int) bool { return f[i].key() < f[j].key() })
}

// kind is the kind of update the unit proposes.
func (u *composeUnit) kind() string {
	if u.kube != nil {
		if u.kube.kustomize != nil {
			return prKindKustomize
		}
		return prKindKubernetes
	}
	if u.df != nil {
		return prKindDockerfile
	}
	if u.lang != nil {
		return prKindLanguage
	}
	return prKindCompose
}
