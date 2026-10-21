package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

const (
	kustPath      = "apps/api/overlays/prod/kustomization.yaml"
	kustFile      = "resources:\n  - ../../base\nimages:\n  - name: nginx\n    newTag: \"1.25.3\" # pinned\n  - name: busybox\n    newTag: 1.36.1\n"
	kustApp       = "deployment/shop/api/app"
	kustSidecar   = "deployment/shop/api/sidecar"
	kustCron      = "cronjob/shop/report/job"
	kustInit      = "deployment/shop/api/migrate"
	kustRunningID = "docker.io/library/nginx:1.25.3"
)

// kustContainer is a running replica of a container of a workload of the shop
// namespace whose Pod spec declares what it runs.
func kustContainer(kind inventory.WorkloadKind, workload, pod, container, ref, declared string, h byte) inventory.Container {
	return inventory.Container{
		Name:     "shop/" + pod + "/" + container,
		Workload: inventory.Workload{Kind: kind, Group: "shop", Name: workload},
		Image:    inventory.RunningImage{Ref: ref, Config: configKey(h).Digest},
		Declared: &inventory.Declared{Ref: declared, PullPolicy: "IfNotPresent"},
	}
}

func kustMapping(affects ...string) []KustomizeMapping {
	return []KustomizeMapping{{Workload: kustApp, Repository: testRepo, BaseBranch: "main", Path: kustPath, Image: "nginx", Affects: affects}}
}

// newKustPRHarness has the kustomization in the test repository, the app and
// its sidecar of one Deployment running as two replicas, and a CronJob's
// container; the entry is declared to act on all three.
func newKustPRHarness(t *testing.T) *prHarness {
	t.Helper()
	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{kustPath: kustFile})
	h.gh.humanMoved = map[string]bool{}
	h.gh.tops["docker.io/library/nginx:1.25.4"] = topDigest('1')
	h.gh.tops["docker.io/library/nginx:1.25.5"] = topDigest('2')
	h.mappings, h.kube = nil, nil
	dep := inventory.WorkloadDeployment
	h.containers = []inventory.Container{
		kustContainer(dep, "api", "api-1", "app", kustRunningID, "nginx:1.25.3", 'a'),
		kustContainer(dep, "api", "api-1", "sidecar", kustRunningID, "nginx:1.25.3", 'a'),
		kustContainer(dep, "api", "api-2", "app", kustRunningID, "nginx:1.25.3", 'a'),
		kustContainer(dep, "api", "api-2", "sidecar", kustRunningID, "nginx:1.25.3", 'a'),
		kustContainer(inventory.WorkloadCronJob, "report", "report-1", "job", kustRunningID, "nginx:1.25.3", 'a'),
	}
	h.kust = kustMapping(kustSidecar, kustCron)
	return h
}

func kustItem(workloads ...string) Item {
	if len(workloads) == 0 {
		workloads = []string{kustApp, kustSidecar, kustCron}
	}
	return kubeItemOf(kustRunningID, 'a', "1.25.4", '1', workloads...)
}

func kustPlan(items ...Item) Plan {
	if len(items) == 0 {
		items = []Item{kustItem()}
	}
	return testPlan(items...)
}

func readKust(t *testing.T, h *prHarness, sha string) string {
	t.Helper()
	f, err := h.gh.ReadFile(context.Background(), testRepo, sha, kustPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(f.Content)
}

// An images entry that three containers share is edited once, in its newTag
// only, for all three.
func TestKustomizePRCreated(t *testing.T) {
	h := newKustPRHarness(t)
	it := kustItem()
	it.Management = []WorkloadChains{{Workload: kustApp, Chains: [][]ChainOwner{{
		{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "api", Scope: "shop"},
		{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system", Confidence: ConfidenceClaimed},
	}}}}
	res := h.run(kustPlan(it))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	wantWorkloads := []string{kustSidecar, kustApp, kustCron}
	if u.Kind != "kustomize" || u.Path != kustPath || u.Current != kustRunningID || u.CandidateTag != "1.25.4" || len(u.Workloads) != 3 ||
		len(u.Locations) != 1 || u.Locations[0] != "images[nginx].newTag" {
		t.Errorf("unit = %+v (workloads should be %v)", u, wantWorkloads)
	}
	pr := h.gh.pulls(testRepo)[0]
	if pr.Title != "Update docker.io/library/nginx to 1.25.4 in "+kustPath || !strings.HasPrefix(pr.HeadRef, "kestrelynx/kustomize/") {
		t.Errorf("title %q head %q", pr.Title, pr.HeadRef)
	}
	// Only the tag of the nginx entry changed: the comment, the quotes, the
	// resources and the other entry are as they were.
	if got, want := readKust(t, h, pr.HeadSHA), strings.Replace(kustFile, `"1.25.3" # pinned`, `"1.25.4" # pinned`, 1); got != want {
		t.Errorf("edited file:\n%s\nwant:\n%s", got, want)
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Kind != "kustomize" || len(m.Affected) != 3 || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) {
		t.Fatalf("marker %+v err %v", m, err)
	}
	if m.UpdateKey != KubernetesUpdateKey(m.TargetKey, kustRunningID, "1.25.4", topDigest('1'), m.Affected) {
		t.Error("the update key does not cover the affected set")
	}
	for _, want := range []string{
		"Kustomize images entry `images[nginx].newTag`",
		"`images[nginx].newTag`: `nginx:1.25.3` to `nginx:1.25.4`",
		"deployment/shop/api/app", "deployment/shop/api/sidecar", "cronjob/shop/report/job",
		"does not render the kustomization",
		"taken to be complete",
		"Merging this pull request may deploy the change",
		"Flux Kustomization `apps` in `flux-system`",
		"Jobs that already exist are not affected",
	} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}
	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].Kind != "kustomize" || len(rec.PRs[0].Affected) != 3 || rec.Attempts[0].Kind != "kustomize" {
		t.Errorf("records = %+v", rec.PRs)
	}
	// The next cycle sees the open pull request and writes nothing; a closed one
	// is not made again.
	writes := h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(kustPlan(it))), PRStatusOpen, "")
	if h.gh.writeCount() != writes {
		t.Error("the second cycle wrote")
	}
	h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State = "closed" })
	wantStatus(t, onlyUnit(t, h.run(kustPlan(it))), PRStatusSuppressed, "")
}

// Without affects the entry acts on the mapped container only.
func TestKustomizeOnlyTheMappedContainer(t *testing.T) {
	h := newKustPRHarness(t)
	h.kust = kustMapping()
	h.containers = h.containers[:1]
	u := onlyUnit(t, h.run(kustPlan(kustItem(kustApp))))
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Workloads) != 1 || u.Workloads[0] != kustApp {
		t.Errorf("workloads = %v", u.Workloads)
	}
	// An unlisted container of the same namespace that declares the value
	// stops it (see the safety net test); one that does not, does not.
}

// The recovery of an open pull request from its marker and the keys do not
// depend on the order the set was written in.
func TestKustomizeKeysAndRecovery(t *testing.T) {
	a := newKustPRHarness(t)
	a.kust = kustMapping(kustCron, kustSidecar)
	ua := onlyUnit(t, a.run(kustPlan()))
	b := newKustPRHarness(t)
	b.kust = kustMapping(kustSidecar, kustCron)
	ub := onlyUnit(t, b.run(kustPlan()))
	if ua.UpdateKey == "" || ua.UpdateKey != ub.UpdateKey || ua.TargetKey != ub.TargetKey {
		t.Errorf("keys depend on the order of affects: %s / %s", ua.UpdateKey, ub.UpdateKey)
	}
	// Another set is another update.
	c := newKustPRHarness(t)
	c.kust = kustMapping(kustSidecar)
	c.containers = c.containers[:4]
	uc := onlyUnit(t, c.run(kustPlan(kustItem(kustApp, kustSidecar))))
	if uc.UpdateKey == ua.UpdateKey {
		t.Error("a different set of containers gave the same update key")
	}
	if uc.TargetKey != ua.TargetKey {
		t.Error("the target is the same entry whatever the set")
	}
	// The records are lost: the pull request is recognized by its marker.
	if err := removeAll(a.dir); err != nil {
		t.Fatal(err)
	}
	writes := a.gh.writeCount()
	wantStatus(t, onlyUnit(t, a.run(kustPlan())), PRStatusOpen, "")
	if a.gh.writeCount() != writes {
		t.Error("the recovered cycle wrote")
	}
	rec := a.load()
	if len(rec.PRs) != 1 || !rec.PRs[0].Recovered || rec.PRs[0].Kind != "kustomize" || len(rec.PRs[0].Affected) != 3 {
		t.Errorf("records = %+v", rec.PRs)
	}
}

func TestKustomizeMarkerNeedsTheAffectedSet(t *testing.T) {
	h := newKustPRHarness(t)
	h.run(kustPlan())
	body := h.gh.pulls(testRepo)[0].Body
	good, err := parsePRMarker(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := good.wellFormed(); err != nil {
		t.Fatal(err)
	}
	noSet := good
	noSet.Affected = nil
	if noSet.wellFormed() == nil {
		t.Error("a Kustomize marker without the affected set is well formed")
	}
	bad := good
	bad.Affected = []string{kustSidecar, kustApp}
	if bad.wellFormed() == nil {
		t.Error("an unsorted affected set is well formed")
	}
	bad = good
	bad.Affected = []string{"compose/a/b"}
	if bad.wellFormed() == nil {
		t.Error("a Compose key in the affected set is well formed")
	}
	// A marker of another kind with the set is refused, as before.
	dockerfile := good
	dockerfile.Kind = "dockerfile"
	if dockerfile.wellFormed() == nil {
		t.Error("a Dockerfile marker with the affected set is well formed")
	}
	// Changing the set breaks the recomputed keys.
	tampered := good
	tampered.Affected = []string{kustApp, kustCron}
	if tampered.verify(testRepoID) == nil {
		t.Error("a marker with another set verifies")
	}
}

// Everything that makes the set of instances unverifiable stops the unit
// before any GitHub write.
func TestKustomizeStopsOnIncompleteOrDisagreeingInstances(t *testing.T) {
	dep := inventory.WorkloadDeployment
	for name, tc := range map[string]struct {
		mutate func(h *prHarness) Plan
		reason Reason
	}{
		"a listed workload does not run": {func(h *prHarness) Plan {
			h.containers = h.containers[:4]
			return kustPlan()
		}, ReasonInstancesMissing},
		"a listed workload has no instance and nothing else of its workload runs": {func(h *prHarness) Plan {
			h.kust = kustMapping(kustSidecar, kustCron, "deployment/shop/other/app")
			return kustPlan()
		}, ReasonInstancesMissing},
		"declared differs from running in one instance": {func(h *prHarness) Plan {
			h.containers[3].Declared.Ref = "nginx:mainline"
			return kustPlan()
		}, ReasonDeclaredRefMismatch},
		"declaration unreadable": {func(h *prHarness) Plan {
			h.containers[4].Declared.Ref = ""
			return kustPlan()
		}, ReasonDeclaredRefUnavailable},
		"rollout: one workload on another reference": {func(h *prHarness) Plan {
			h.containers[4] = kustContainer(inventory.WorkloadCronJob, "report", "report-1", "job", "docker.io/library/nginx:1.25.4", "nginx:1.25.4", 'b')
			return kustPlan(kustItem(kustApp, kustSidecar), kubeItemOf("docker.io/library/nginx:1.25.4", 'b', "1.25.5", '2', kustCron))
		}, ReasonMixedReferences},
		"rollout inside one workload": {func(h *prHarness) Plan {
			h.containers[2] = kustContainer(dep, "api", "api-2", "app", "docker.io/library/nginx:1.25.4", "nginx:1.25.4", 'b')
			return kustPlan(kustItem(), kubeItemOf("docker.io/library/nginx:1.25.4", 'b', "1.25.5", '2', kustApp))
		}, ReasonMixedReferences},
		"an instance has no plan item": {func(h *prHarness) Plan {
			h.containers[4].Image.Config = configKey('c').Digest
			return kustPlan()
		}, ReasonInstancesMissing},
		"one workload's entity is not an adopted candidate": {func(h *prHarness) Plan {
			h.containers[4].Image.Config = configKey('c').Digest
			other := kubeItemOf(kustRunningID, 'c', "1.25.4", '1', kustCron)
			other.Category = CategoryNoCandidate
			return kustPlan(kustItem(kustApp, kustSidecar), other)
		}, ReasonKubernetesSetNotAdopted},
		"entities have different candidates": {func(h *prHarness) Plan {
			h.containers[4].Image.Config = configKey('c').Digest
			return kustPlan(kustItem(kustApp, kustSidecar), kubeItemOf(kustRunningID, 'c', "1.25.5", '2', kustCron))
		}, ReasonKubernetesSetNotAdopted},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKustPRHarness(t)
			plan := tc.mutate(h)
			writes := h.gh.writeCount()
			res := h.run(plan)
			if len(res.Units) == 0 {
				t.Fatal("no unit")
			}
			for _, u := range res.Units {
				wantStatus(t, u, PRStatusManual, tc.reason)
			}
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a pull request was made for a set that cannot be verified")
			}
		})
	}
}

// The listed workloads all still run the old tag while the file already names
// a newer one: the declared references are not the file's value.
func TestKustomizeListedWorkloadsFullyOnTheOldTagStop(t *testing.T) {
	h := newKustPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{kustPath: strings.Replace(kustFile, `"1.25.3"`, `"1.25.4"`, 1)})
	u := onlyUnit(t, h.run(kustPlan()))
	wantStatus(t, u, PRStatusManual, ReasonSourceMismatch)
	if len(h.gh.pulls(testRepo)) != 0 {
		t.Error("a pull request was made")
	}
}

// The safety net: a container the mapping does not list that declares the
// entry's value, in the same namespace as a listed one, stops the unit.
func TestKustomizeUnlistedWorkloadWithTheSameValueStops(t *testing.T) {
	dep := inventory.WorkloadDeployment
	for name, tc := range map[string]struct {
		extra  inventory.Container
		owners []WorkloadChains
		stops  bool
	}{
		"same namespace, same declared value": {
			extra: kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a'), stops: true,
		},
		"same namespace, the value spelled with the registry": {
			extra: kustContainer(dep, "web", "web-1", "app", kustRunningID, "docker.io/library/nginx:1.25.3", 'a'), stops: true,
		},
		"same namespace, a Pod whose owner is not known": {
			extra: func() inventory.Container {
				c := kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
				c.Name, c.Workload = "shop/orphan-1/web", inventory.Workload{}
				return c
			}(), stops: true,
		},
		"same namespace, another tag": {
			extra: kustContainer(dep, "web", "web-1", "app", "docker.io/library/nginx:1.24.0", "nginx:1.24.0", 'b'),
		},
		"same namespace, another repository": {
			extra: kustContainer(dep, "web", "web-1", "app", "docker.io/library/busybox:1.25.3", "busybox:1.25.3", 'b'),
		},
		"same namespace, declaration unreadable": {
			extra: kustContainer(dep, "web", "web-1", "app", kustRunningID, "", 'a'),
		},
		"other namespace, no common manager": {
			extra: func() inventory.Container {
				c := kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
				c.Name, c.Workload.Group = "other/web-1/app", "other"
				return c
			}(),
		},
		"other namespace, the same Helm release": {
			extra: func() inventory.Container {
				c := kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
				c.Name, c.Workload.Group = "other/web-1/app", "other"
				return c
			}(),
			owners: []WorkloadChains{
				{Workload: kustApp, Chains: [][]ChainOwner{{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "api", Scope: "shop"}, {Kind: OwnerHelm, Name: "rel", Scope: "shop", Confidence: ConfidenceClaimed}}}},
				{Workload: "deployment/other/web/app", Chains: [][]ChainOwner{{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web", Scope: "other"}, {Kind: OwnerHelm, Name: "rel", Scope: "shop", Confidence: ConfidenceClaimed}}}},
			},
			stops: true,
		},
		"other namespace, the same Flux Kustomization": {
			extra: func() inventory.Container {
				c := kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
				c.Name, c.Workload.Group = "other/web-1/app", "other"
				return c
			}(),
			owners: []WorkloadChains{
				{Workload: kustCron, Chains: [][]ChainOwner{{{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system", Confidence: ConfidenceClaimed}}}},
				{Workload: "deployment/other/web/app", Chains: [][]ChainOwner{{{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system", Confidence: ConfidenceClaimed}}}},
			},
			stops: true,
		},
		"other namespace, another Helm release": {
			extra: func() inventory.Container {
				c := kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
				c.Name, c.Workload.Group = "other/web-1/app", "other"
				return c
			}(),
			owners: []WorkloadChains{
				{Workload: kustApp, Chains: [][]ChainOwner{{{Kind: OwnerHelm, Name: "rel", Scope: "shop", Confidence: ConfidenceClaimed}}}},
				{Workload: "deployment/other/web/app", Chains: [][]ChainOwner{{{Kind: OwnerHelm, Name: "rel2", Scope: "other", Confidence: ConfidenceClaimed}}}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKustPRHarness(t)
			h.containers = append(h.containers, tc.extra)
			it := kustItem()
			it.Management = tc.owners
			plan := kustPlan(it)
			res := h.run(plan)
			u := onlyUnit(t, res)
			if tc.stops {
				wantStatus(t, u, PRStatusManual, ReasonUndeclaredAffectedWorkload)
				if !strings.Contains(u.Detail, "web") {
					t.Errorf("the detail does not name the container: %s", u.Detail)
				}
				if len(h.gh.pulls(testRepo)) != 0 {
					t.Error("a pull request was made")
				}
			} else {
				wantStatus(t, u, PRStatusCreated, "")
			}
		})
	}
}

// podOf builds the description of a Pod spec the containers of a Pod carry: the
// main containers app and sidecar, and the ordinary init container migrate when
// init is not nil.
func podDesc(init *inventory.InitObservation, extra ...inventory.SpecContainer) *inventory.PodInit {
	d := &inventory.PodInit{Spec: []inventory.SpecContainer{
		{Name: "app", Ref: "nginx:1.25.3", Kind: inventory.SpecMain},
		{Name: "sidecar", Ref: "nginx:1.25.3", Kind: inventory.SpecMain},
	}}
	if init != nil {
		d.Spec = append(d.Spec, inventory.SpecContainer{Name: init.Name, Ref: "nginx:1.25.3", Kind: inventory.SpecInit})
		d.Containers = []inventory.InitObservation{*init}
	}
	d.Spec = append(d.Spec, extra...)
	return d
}

func goodInit() inventory.InitObservation {
	return inventory.InitObservation{
		Name: "migrate", HasStatus: true, Declared: inventory.Declared{Ref: "nginx:1.25.3"},
		Image: inventory.RunningImage{Ref: kustRunningID, Config: configKey('a').Digest},
	}
}

// setDesc gives the description to every container of the api Deployment.
func setDesc(h *prHarness, d *inventory.PodInit) {
	for i := range h.containers {
		if h.containers[i].Workload.Name == "api" {
			h.containers[i].PodInit = d
		}
	}
}

// A container the Pod spec declares with the entry's value that the list lacks
// stops the unit whatever its state: an ordinary init container (with or
// without a status), a main container or a native sidecar that does not run.
func TestKustomizeUnlistedContainerOfTheSamePodSpecStops(t *testing.T) {
	for name, tc := range map[string]struct {
		init  *inventory.InitObservation
		extra []inventory.SpecContainer
		stops bool
		want  string
	}{
		"an ordinary init container with a status": {init: func() *inventory.InitObservation { i := goodInit(); return &i }(), stops: true, want: "migrate"},
		"an ordinary init container with no status (the spec has it, the status does not)": {
			init:  &inventory.InitObservation{Name: "migrate", Declared: inventory.Declared{Ref: "nginx:1.25.3"}},
			stops: true, want: "migrate"},
		"a main container that is waiting": {
			extra: []inventory.SpecContainer{{Name: "waiting", Ref: "nginx:1.25.3", Kind: inventory.SpecMain}}, stops: true, want: "waiting"},
		"a native sidecar that has not started": {
			extra: []inventory.SpecContainer{{Name: "proxy", Ref: "docker.io/library/nginx:1.25.3", Kind: inventory.SpecSidecar}}, stops: true, want: "proxy"},
		"another image in the spec": {
			extra: []inventory.SpecContainer{{Name: "waiting", Ref: "nginx:1.20.0", Kind: inventory.SpecMain}}},
		"no reference in the spec": {
			extra: []inventory.SpecContainer{{Name: "waiting", Ref: "", Kind: inventory.SpecMain}}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKustPRHarness(t)
			setDesc(h, podDesc(tc.init, tc.extra...))
			u := onlyUnit(t, h.run(kustPlan()))
			if !tc.stops {
				wantStatus(t, u, PRStatusCreated, "")
				return
			}
			wantStatus(t, u, PRStatusManual, ReasonUndeclaredAffectedWorkload)
			if !strings.Contains(u.Detail, tc.want) {
				t.Errorf("detail = %s", u.Detail)
			}
			if len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a pull request was made")
			}
		})
	}
	// The listed ones are not strangers.
	h, plan := kustInitHarness(t, nil)
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusCreated, "")
}

// kustInitHarness has the init container migrate of the Deployment api listed
// besides the running containers of its Pods.
func kustInitHarness(t *testing.T, mutate func(init *inventory.InitObservation)) (*prHarness, Plan) {
	t.Helper()
	h := newKustPRHarness(t)
	h.kust = kustMapping(kustSidecar, kustCron, kustInit)
	obs := goodInit()
	if mutate != nil {
		mutate(&obs)
	}
	setDesc(h, podDesc(&obs))
	return h, kustPlan(kustItem(kustApp, kustSidecar, kustCron, kustInit))
}

// A listed ordinary init container is a member of the set when its status
// shows it ran the entity a running container of the same Pod runs and the
// declaration, status and source agree.
func TestKustomizeInitContainerReusesTheComparison(t *testing.T) {
	h, plan := kustInitHarness(t, nil)
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Workloads) != 4 {
		t.Errorf("workloads = %v", u.Workloads)
	}
	pr := h.gh.pulls(testRepo)[0]
	for _, want := range []string{"deployment/shop/api/migrate", "Ordinary init containers among them"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}
	if m, err := parsePRMarker(pr.Body); err != nil || len(m.Affected) != 4 {
		t.Errorf("marker %+v err %v", m, err)
	}
}

func TestKustomizeInitContainerNegatives(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(init *inventory.InitObservation)
		reason Reason
	}{
		"no status entry of that name": {mutate: func(i *inventory.InitObservation) { i.HasStatus, i.Image = false, inventory.RunningImage{} }, reason: ReasonInitContainerUnverified},
		"imageID missing":              {mutate: func(i *inventory.InitObservation) { i.Image.Config = inventory.Digest{} }, reason: ReasonInitContainerUnverified},
		"imageID of another entity":    {mutate: func(i *inventory.InitObservation) { i.Image.Config = configKey('b').Digest }, reason: ReasonInitContainerUnverified},
		"same entity, another reference": {mutate: func(i *inventory.InitObservation) {
			i.Image.Ref, i.Declared.Ref = "docker.io/library/nginx:1.25", "nginx:1.25"
		}, reason: ReasonInitContainerUnverified},
		"declaration differs from the status": {mutate: func(i *inventory.InitObservation) { i.Declared.Ref = "nginx:mainline" }, reason: ReasonDeclaredRefMismatch},
		"declaration unreadable":              {mutate: func(i *inventory.InitObservation) { i.Declared.Ref = "" }, reason: ReasonDeclaredRefUnavailable},
		"status reports no image":             {mutate: func(i *inventory.InitObservation) { i.Image.Ref = "" }, reason: ReasonInitContainerUnverified},
	} {
		t.Run(name, func(t *testing.T) {
			h, plan := kustInitHarness(t, tc.mutate)
			u := onlyUnit(t, h.run(plan))
			wantStatus(t, u, PRStatusManual, tc.reason)
			if len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a pull request was made")
			}
		})
	}
	t.Run("no description of the Pod at all", func(t *testing.T) {
		h, plan := kustInitHarness(t, nil)
		setDesc(h, nil)
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInstancesMissing)
	})
	t.Run("the spec has no such init container", func(t *testing.T) {
		h, plan := kustInitHarness(t, nil)
		setDesc(h, podDesc(nil))
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInstancesMissing)
	})
	t.Run("a status entry the spec has no init container for", func(t *testing.T) {
		h, plan := kustInitHarness(t, nil)
		obs := goodInit()
		setDesc(h, &inventory.PodInit{Spec: podDesc(nil).Spec, Containers: []inventory.InitObservation{obs}})
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInitContainerUnverified)
	})
	t.Run("no listed container runs in the Pod", func(t *testing.T) {
		// Only the CronJob and the init container are listed: the Deployment's
		// running containers are not in the set, so there is no scan to reuse.
		h, plan := kustInitHarness(t, nil)
		h.kust = []KustomizeMapping{{Workload: kustCron, Repository: testRepo, BaseBranch: "main", Path: kustPath, Image: "nginx", Affects: []string{kustInit}}}
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInitContainerUnverified)
	})
	t.Run("the scan it would reuse is not in the plan", func(t *testing.T) {
		h, _ := kustInitHarness(t, nil)
		plan := kustPlan(kubeItemOf(kustRunningID, 'z', "1.25.4", '1', kustApp, kustSidecar, kustCron))
		for _, u := range h.run(plan).Units {
			wantStatus(t, u, PRStatusManual, ReasonInstancesMissing)
		}
	})
	t.Run("one Pod of the workload without the init status", func(t *testing.T) {
		h, plan := kustInitHarness(t, nil)
		noStatus := goodInit()
		noStatus.HasStatus, noStatus.Image = false, inventory.RunningImage{}
		h.containers[2].PodInit, h.containers[3].PodInit = podDesc(&noStatus), podDesc(&noStatus)
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInitContainerUnverified)
	})
}

// Every observed Pod of a listed workload is verified, including a Pod in which
// none of the listed containers runs: the init container of that Pod has nothing
// to reuse, and the Pods that are fine do not make up for it.
func TestKustomizeInitContainerOfAPodWithNoListedContainerStops(t *testing.T) {
	h, plan := kustInitHarness(t, nil)
	// Pod api-3: the listed app and sidecar do not run; an unlisted aux does, of
	// another image, and the listed init container ran something else.
	aux := kustContainer(inventory.WorkloadDeployment, "api", "api-3", "aux", "docker.io/library/busybox:1.36.1", "busybox:1.36.1", 'z')
	other := goodInit()
	other.Image.Config = configKey('z').Digest
	aux.PodInit = &inventory.PodInit{
		Spec: []inventory.SpecContainer{
			{Name: "aux", Ref: "busybox:1.36.1", Kind: inventory.SpecMain},
			{Name: "app", Ref: "nginx:1.25.3", Kind: inventory.SpecMain}, {Name: "sidecar", Ref: "nginx:1.25.3", Kind: inventory.SpecMain},
			{Name: "migrate", Ref: "nginx:1.25.3", Kind: inventory.SpecInit}},
		Containers: []inventory.InitObservation{other},
	}
	h.containers = append(h.containers, aux)
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusManual, ReasonInitContainerUnverified)
	if !strings.Contains(u.Detail, "api-3") {
		t.Errorf("detail = %s", u.Detail)
	}
	if len(h.gh.pulls(testRepo)) != 0 {
		t.Error("a pull request was made")
	}
}

// A listed init container that one Pod does not show is a problem of that Pod:
// another Pod that verifies it does not cover for it.
func TestKustomizeInitContainerMissingFromOnePodStops(t *testing.T) {
	podB := func(h *prHarness, d *inventory.PodInit) {
		for i := range h.containers {
			if strings.HasPrefix(h.containers[i].Name, "shop/api-2/") {
				h.containers[i].PodInit = d
			}
		}
	}
	for name, d := range map[string]*inventory.PodInit{
		"neither the spec nor the status has it": podDesc(nil),
		"no description of the Pod":              nil,
		"a partial description: the status only": {Containers: []inventory.InitObservation{goodInit()}},
		"a partial description: no spec entries": {},
		"the spec repeats the name": {Spec: append(podDesc(nil).Spec,
			inventory.SpecContainer{Name: "migrate", Ref: "nginx:1.25.3", Kind: inventory.SpecInit}, inventory.SpecContainer{Name: "migrate", Ref: "nginx:1.25.3", Kind: inventory.SpecInit})},
	} {
		t.Run(name, func(t *testing.T) {
			h, plan := kustInitHarness(t, nil) // Pod api-1 and Pod api-2 both verify
			podB(h, d)
			u := onlyUnit(t, h.run(plan))
			if u.Status != PRStatusManual || (u.Reason != ReasonInstancesMissing && u.Reason != ReasonInitContainerUnverified) {
				t.Fatalf("unit %s/%s (%s), want manual with instances_missing or init_container_unverified", u.Status, u.Reason, u.Detail)
			}
			if !strings.Contains(u.Detail, "api-2") {
				t.Errorf("the detail does not name the Pod: %s", u.Detail)
			}
			if len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a pull request was made")
			}
		})
	}
	// A main container that is only waiting in a Pod that shows it in its spec
	// adds no instance there and is no problem.
	h, plan := kustInitHarness(t, nil)
	waitingCronPod := kustContainer(inventory.WorkloadDeployment, "api", "api-3", "app", kustRunningID, "nginx:1.25.3", 'a')
	d := podDesc(nil)
	waitingCronPod.PodInit = d
	h.containers = append(h.containers, waitingCronPod)
	// api-3 runs app only; sidecar is waiting (in its spec) and migrate ran.
	obs := goodInit()
	d.Spec = append(d.Spec, inventory.SpecContainer{Name: "migrate", Ref: "nginx:1.25.3", Kind: inventory.SpecInit})
	d.Containers = []inventory.InitObservation{obs}
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusCreated, "")
}

// A name that is a native sidecar in one Pod and an ordinary init container in
// another is verified in each Pod as what it is there.
func TestKustomizeNameThatIsASidecarInOnePodAndAnInitContainerInAnother(t *testing.T) {
	build := func(t *testing.T, initRan inventory.RunningImage) (*prHarness, Plan) {
		h := newKustPRHarness(t)
		h.kust = kustMapping(kustSidecar, kustCron, kustInit)
		dep := inventory.WorkloadDeployment
		// Pod api-1: migrate runs as a native sidecar. Pod api-2: migrate is an
		// ordinary init container that ran, next to the running app and sidecar.
		migrate := kustContainer(dep, "api", "api-1", "migrate", kustRunningID, "nginx:1.25.3", 'a')
		pod1 := &inventory.PodInit{Spec: []inventory.SpecContainer{
			{Name: "app", Ref: "nginx:1.25.3", Kind: inventory.SpecMain}, {Name: "sidecar", Ref: "nginx:1.25.3", Kind: inventory.SpecMain},
			{Name: "migrate", Ref: "nginx:1.25.3", Kind: inventory.SpecSidecar}}}
		obs := goodInit()
		obs.Image = initRan
		pod2 := podDesc(&obs)
		h.containers = []inventory.Container{
			kustContainer(dep, "api", "api-1", "app", kustRunningID, "nginx:1.25.3", 'a'),
			kustContainer(dep, "api", "api-1", "sidecar", kustRunningID, "nginx:1.25.3", 'a'),
			migrate,
			kustContainer(dep, "api", "api-2", "app", kustRunningID, "nginx:1.25.3", 'a'),
			kustContainer(dep, "api", "api-2", "sidecar", kustRunningID, "nginx:1.25.3", 'a'),
			kustContainer(inventory.WorkloadCronJob, "report", "report-1", "job", kustRunningID, "nginx:1.25.3", 'a'),
		}
		for i := range h.containers {
			switch h.containers[i].Name {
			case "shop/api-1/app", "shop/api-1/sidecar", "shop/api-1/migrate":
				h.containers[i].PodInit = pod1
			case "shop/api-2/app", "shop/api-2/sidecar":
				h.containers[i].PodInit = pod2
			}
		}
		return h, kustPlan(kustItem(kustApp, kustSidecar, kustCron, kustInit))
	}
	t.Run("each is verified where it is", func(t *testing.T) {
		h, plan := build(t, inventory.RunningImage{Ref: kustRunningID, Config: configKey('a').Digest})
		u := onlyUnit(t, h.run(plan))
		wantStatus(t, u, PRStatusCreated, "")
		if len(u.Workloads) != 4 {
			t.Errorf("workloads = %v", u.Workloads)
		}
	})
	t.Run("the init container of the other Pod ran another entity", func(t *testing.T) {
		h, plan := build(t, inventory.RunningImage{Ref: kustRunningID, Config: configKey('b').Digest})
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInitContainerUnverified)
		if len(h.gh.pulls(testRepo)) != 0 {
			t.Error("a pull request was made")
		}
	})
}

// The management chains of workloads without a plan item are known to the
// stage from the cycle's observation.
func TestKustomizeSafetyNetUsesChainsOfWorkloadsWithoutAPlanItem(t *testing.T) {
	h := newKustPRHarness(t)
	other := kustContainer(inventory.WorkloadDeployment, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
	other.Name, other.Workload.Group = "other/web-1/app", "other"
	h.containers = append(h.containers, other)
	flux := func(w string) WorkloadChains {
		return WorkloadChains{Workload: w, Chains: [][]ChainOwner{{{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system", Confidence: ConfidenceClaimed}}}}
	}
	// No plan item names the unlisted workload or carries its chain.
	h.management = []WorkloadChains{flux(kustApp), flux("deployment/other/web/app")}
	u := onlyUnit(t, h.run(kustPlan()))
	wantStatus(t, u, PRStatusManual, ReasonUndeclaredAffectedWorkload)
	// Without the chain of the stranger it is not shared.
	h = newKustPRHarness(t)
	h.containers = append(h.containers, other)
	h.management = []WorkloadChains{flux(kustApp)}
	wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusCreated, "")
}

// A file the edit refuses leaves the unit manual with the editor's reason and
// no write.
func TestKustomizeEditRefusalsAreManual(t *testing.T) {
	for name, tc := range map[string]struct {
		file   string
		reason Reason
	}{
		"entry missing":         {"images:\n  - name: other\n    newTag: 1\n", ReasonKustomizeImageMissing},
		"two entries":           {"images:\n  - name: nginx\n    newTag: \"1.25.3\"\n  - name: nginx\n    newTag: \"1.25.3\"\n", ReasonKustomizeImageAmbiguous},
		"no newTag":             {"images:\n  - name: nginx\n", ReasonKustomizeTagNotSet},
		"numeric newTag":        {"images:\n  - name: nginx\n    newTag: 1.25\n", ReasonKustomizeNotString},
		"digest":                {"images:\n  - name: nginx\n    newTag: \"1.25.3\"\n    digest: sha256:" + strings.Repeat("a", 64) + "\n", ReasonKustomizeDigest},
		"replacements":          {"replacements: []\nimages:\n  - name: nginx\n    newTag: \"1.25.3\"\n", ReasonKustomizeUnsupported},
		"template":              {"images:\n  - name: nginx\n    newTag: \"{{ .tag }}\"\n", ReasonKustomizeTemplate},
		"duplicate key":         {"images:\n  - name: nginx\n    newTag: \"1.25.3\"\n    newTag: \"1.25.3\"\n", ReasonKustomizeInvalid},
		"two documents":         {kustFile + "---\nimages: []\n", ReasonKustomizeInvalid},
		"other repository":      {"images:\n  - name: nginx\n    newName: busybox\n    newTag: \"1.25.3\"\n", ReasonSourceMismatch},
		"Flux image automation": {"images:\n  - name: nginx\n    newTag: \"1.25.3\" # {\"$imagepolicy\": \"a:b:tag\"}\n", ReasonKustomizeImageAutomation},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKustPRHarness(t)
			h.gh.commitFiles(testRepo, "main", map[string]string{kustPath: tc.file})
			writes := h.gh.writeCount()
			u := onlyUnit(t, h.run(kustPlan()))
			wantStatus(t, u, PRStatusManual, tc.reason)
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a write was made")
			}
		})
	}
	t.Run("file missing", func(t *testing.T) {
		h := newKustPRHarness(t)
		h.kust[0].Path = "apps/api/missing/kustomization.yaml"
		wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusManual, ReasonManifestFileNotFound)
	})
}

// Two entries of one file: a problem of a container of either holds back the
// pull request of both, while an entry whose containers run normally with
// nothing to fix does not.
func TestKustomizeFileLevelAllOrNothing(t *testing.T) {
	busybox := func(h *prHarness) Plan {
		h.kust = append(h.kust, KustomizeMapping{Workload: "deployment/shop/jobs/runner", Repository: testRepo, BaseBranch: "main", Path: kustPath, Image: "busybox"})
		return kustPlan()
	}
	t.Run("a neighbour that runs normally and has nothing to fix", func(t *testing.T) {
		h := newKustPRHarness(t)
		plan := busybox(h)
		h.containers = append(h.containers, kustContainer(inventory.WorkloadDeployment, "jobs", "jobs-1", "runner", "docker.io/library/busybox:1.36.1", "busybox:1.36.1", 'b'))
		u := onlyUnit(t, h.run(plan))
		wantStatus(t, u, PRStatusCreated, "")
	})
	t.Run("a neighbour that does not run", func(t *testing.T) {
		h := newKustPRHarness(t)
		plan := busybox(h)
		u := onlyUnit(t, h.run(plan))
		wantStatus(t, u, PRStatusManual, ReasonInstancesMissing)
		if !strings.Contains(u.Detail, "holds back") {
			t.Errorf("detail = %s", u.Detail)
		}
		if len(h.gh.pulls(testRepo)) != 0 {
			t.Error("a pull request was made")
		}
	})
	t.Run("a neighbour with a declaration that disagrees", func(t *testing.T) {
		h := newKustPRHarness(t)
		plan := busybox(h)
		h.containers = append(h.containers, kustContainer(inventory.WorkloadDeployment, "jobs", "jobs-1", "runner", "docker.io/library/busybox:1.36.1", "busybox:latest", 'b'))
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonDeclaredRefMismatch)
	})
	t.Run("a neighbour that is manual in its own unit", func(t *testing.T) {
		h := newKustPRHarness(t)
		plan := busybox(h)
		h.containers = append(h.containers,
			kustContainer(inventory.WorkloadDeployment, "jobs", "jobs-1", "runner", "docker.io/library/busybox:1.36.1", "busybox:1.36.1", 'b'),
			kustContainer(inventory.WorkloadDeployment, "jobs", "jobs-2", "runner", "docker.io/library/busybox:1.36.1", "busybox:1.36.1", 'c'))
		good := kubeItemOf("docker.io/library/busybox:1.36.1", 'b', "1.36.2", '3', "deployment/shop/jobs/runner")
		bad := kubeItemOf("docker.io/library/busybox:1.36.1", 'c', "1.36.2", '3', "deployment/shop/jobs/runner")
		bad.Category = CategoryNoCandidate
		plan.Items = append(plan.Items, good, bad)
		h.gh.tops["docker.io/library/busybox:1.36.2"] = topDigest('3')
		for _, u := range h.run(plan).Units {
			wantStatus(t, u, PRStatusManual, ReasonKubernetesSetNotAdopted)
		}
		if len(h.gh.pulls(testRepo)) != 0 {
			t.Error("a pull request was made")
		}
	})
}

// A kustomize mapping that names the same entry from both of its sides is one
// unit, and a manifest mapping elsewhere is its own.
func TestKustomizeBothSidesOfOneEntryAreOneUnit(t *testing.T) {
	h := newKustPRHarness(t)
	h.kust = []KustomizeMapping{
		{Workload: kustApp, Repository: testRepo, BaseBranch: "main", Path: kustPath, Image: "nginx", Affects: []string{kustSidecar, kustCron}},
		{Workload: kustSidecar, Repository: testRepo, BaseBranch: "main", Path: kustPath, Image: "nginx", Affects: []string{kustApp, kustCron}},
	}
	u := onlyUnit(t, h.run(kustPlan()))
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Workloads) != 3 {
		t.Errorf("workloads = %v", u.Workloads)
	}
}

// Containers that run the image and are not listed are named in the body.
func TestKustomizeAlsoRunningIsNamed(t *testing.T) {
	h := newKustPRHarness(t)
	other := kustContainer(inventory.WorkloadDeployment, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
	other.Name, other.Workload.Group = "other/web-1/app", "other"
	h.containers = append(h.containers, other)
	wantStatus(t, onlyUnit(t, h.run(kustPlan(kustItem(kustApp, kustSidecar, kustCron, "deployment/other/web/app")))), PRStatusCreated, "")
	body := h.gh.pulls(testRepo)[0].Body
	if !strings.Contains(body, "Also running this image, not edited") || !strings.Contains(body, "deployment/other/web/app") {
		t.Errorf("body:\n%s", body)
	}
}

// Without a kustomize mapping no unit is built, and the other kinds are
// untouched by the new one.
func TestKustomizeNoMappingNoUnit(t *testing.T) {
	h := newKustPRHarness(t)
	h.kust = nil
	if res := h.run(kustPlan()); len(res.Units) != 0 {
		t.Errorf("units = %+v", res.Units)
	}
}
