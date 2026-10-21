package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

const (
	helmPath = "releases/api/values-prod.yaml"
	helmFile = "replicaCount: 1\nimage:\n  repository: nginx\n  tag: \"1.25.3\" # pinned\n  pullPolicy: IfNotPresent\nworker:\n  image: busybox:1.36.1\n"
)

func helmMapping(key string, affects ...string) []HelmValuesMapping {
	return []HelmValuesMapping{{Workload: kustApp, Repository: testRepo, BaseBranch: "main", Path: helmPath, Key: key, Affects: affects}}
}

// newHelmPRHarness is the Kustomize harness with the values file in place of
// the kustomization: the same containers, the key declared to act on all three.
func newHelmPRHarness(t *testing.T) *prHarness {
	t.Helper()
	h := newKustPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: helmFile})
	h.kust = nil
	h.helm = helmMapping("image", kustSidecar, kustCron)
	return h
}

func readHelm(t *testing.T, h *prHarness, sha string) string {
	t.Helper()
	f, err := h.gh.ReadFile(context.Background(), testRepo, sha, helmPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(f.Content)
}

func TestHelmValuesPRCreated(t *testing.T) {
	h := newHelmPRHarness(t)
	it := kustItem()
	it.Management = []WorkloadChains{{Workload: kustApp, Chains: [][]ChainOwner{{
		{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "api", Scope: "shop"},
		{Kind: OwnerHelm, Name: "api", Scope: "shop", Confidence: ConfidenceClaimed},
	}}}}
	u := onlyUnit(t, h.run(kustPlan(it)))
	wantStatus(t, u, PRStatusCreated, "")
	if u.Kind != "helm_values" || u.Path != helmPath || u.CandidateTag != "1.25.4" || len(u.Workloads) != 3 || len(u.Locations) != 1 || u.Locations[0] != "image" {
		t.Errorf("unit = %+v", u)
	}
	pr := h.gh.pulls(testRepo)[0]
	if !strings.HasPrefix(pr.HeadRef, "kestrelynx/helm/") || pr.Title != "Update docker.io/library/nginx to 1.25.4 in "+helmPath {
		t.Errorf("title %q head %q", pr.Title, pr.HeadRef)
	}
	// Only the tag line changed; the comment, the quotes and the rest stay.
	if got, want := readHelm(t, h, pr.HeadSHA), strings.Replace(helmFile, `"1.25.3" # pinned`, `"1.25.4" # pinned`, 1); got != want {
		t.Errorf("edited file:\n%s\nwant:\n%s", got, want)
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Kind != "helm_values" || len(m.Affected) != 3 || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) {
		t.Fatalf("marker %+v err %v", m, err)
	}
	if m.UpdateKey != KubernetesUpdateKey(m.TargetKey, kustRunningID, "1.25.4", topDigest('1'), m.Affected) {
		t.Error("the update key does not cover the affected set")
	}
	for _, want := range []string{
		"Helm values file `" + helmPath + "`", "key `image`", "`image.tag`: `nginx:1.25.3` to `nginx:1.25.4`",
		"deployment/shop/api/app", "cronjob/shop/report/job",
		"does not render the chart", "valuesObject", "taken to be complete",
		"Helm release `api` in `shop`",
	} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}
	for _, not := range []string{"Flux HelmRelease management markers", "No Helm release and no Flux HelmRelease"} {
		if strings.Contains(pr.Body, not) {
			t.Errorf("the body has %q for a plain Helm release", not)
		}
	}
	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].Kind != "helm_values" || len(rec.PRs[0].Affected) != 3 {
		t.Errorf("records = %+v", rec.PRs)
	}
	writes := h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(kustPlan(it))), PRStatusOpen, "")
	if h.gh.writeCount() != writes {
		t.Error("the second cycle wrote")
	}
}

// The body says what is not known about the deployment of the values.
func TestHelmValuesBodyNotesOnManagement(t *testing.T) {
	for name, tc := range map[string]struct {
		owners []ChainOwner
		want   string
	}{
		"a Flux HelmRelease":         {[]ChainOwner{{Kind: OwnerFlux, ResourceID: ResourceIDFluxHelmRelease, Name: "api", Scope: "flux-system", Confidence: ConfidenceClaimed}}, "Flux HelmRelease management markers were detected on these workloads (read from markers on the objects, so a claim, not a verified fact): `deployment/shop/api/app`."},
		"no Helm and no HelmRelease": {[]ChainOwner{{Kind: OwnerArgoCD, Name: "api", Confidence: ConfidenceClaimed}}, "No Helm release and no Flux HelmRelease was detected"},
		"nothing detected":           {nil, "No Helm release and no Flux HelmRelease was detected"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelmPRHarness(t)
			it := kustItem()
			if tc.owners != nil {
				it.Management = []WorkloadChains{{Workload: kustApp, Chains: [][]ChainOwner{append([]ChainOwner{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "api", Scope: "shop"}}, tc.owners...)}}}
			}
			wantStatus(t, onlyUnit(t, h.run(kustPlan(it))), PRStatusCreated, "")
			if body := h.gh.pulls(testRepo)[0].Body; !strings.Contains(body, tc.want) {
				t.Errorf("the body lacks %q:\n%s", tc.want, body)
			}
		})
	}
}

// A key that holds a repository:tag string is edited at its tag.
func TestHelmValuesStringKey(t *testing.T) {
	h := newHelmPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: "app:\n  image: nginx:1.25.3\n"})
	h.helm = helmMapping("app.image", kustSidecar, kustCron)
	wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusCreated, "")
	pr := h.gh.pulls(testRepo)[0]
	if got := readHelm(t, h, pr.HeadSHA); got != "app:\n  image: nginx:1.25.4\n" {
		t.Errorf("edited file: %q", got)
	}
	if !strings.Contains(pr.Body, "`app.image`: `nginx:1.25.3` to `nginx:1.25.4`") {
		t.Errorf("body:\n%s", pr.Body)
	}
}

func TestHelmValuesSetStops(t *testing.T) {
	dep := inventory.WorkloadDeployment
	for name, tc := range map[string]struct {
		mutate func(h *prHarness) Plan
		reason Reason
	}{
		"a listed workload does not run": {func(h *prHarness) Plan {
			h.containers = h.containers[:4]
			return kustPlan()
		}, ReasonInstancesMissing},
		"declared differs from running": {func(h *prHarness) Plan {
			h.containers[3].Declared.Ref = "nginx:mainline"
			return kustPlan()
		}, ReasonDeclaredRefMismatch},
		"rollout inside one workload": {func(h *prHarness) Plan {
			h.containers[2] = kustContainer(dep, "api", "api-2", "app", "docker.io/library/nginx:1.25.4", "nginx:1.25.4", 'b')
			return kustPlan(kustItem(), kubeItemOf("docker.io/library/nginx:1.25.4", 'b', "1.25.5", '2', kustApp))
		}, ReasonMixedReferences},
		"an entity is not an adopted candidate": {func(h *prHarness) Plan {
			h.containers[4].Image.Config = configKey('c').Digest
			other := kubeItemOf(kustRunningID, 'c', "1.25.4", '1', kustCron)
			other.Category = CategoryNoCandidate
			return kustPlan(kustItem(kustApp, kustSidecar), other)
		}, ReasonKubernetesSetNotAdopted},
		"the listed workloads are on the old tag while the file has a newer one": {func(h *prHarness) Plan {
			h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: strings.Replace(helmFile, `"1.25.3"`, `"1.25.4"`, 1)})
			return kustPlan()
		}, ReasonSourceMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelmPRHarness(t)
			plan := tc.mutate(h)
			writes := h.gh.writeCount()
			for _, u := range h.run(plan).Units {
				wantStatus(t, u, PRStatusManual, tc.reason)
			}
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a pull request was made")
			}
		})
	}
}

func TestHelmValuesSafetyNet(t *testing.T) {
	dep := inventory.WorkloadDeployment
	other := func() inventory.Container {
		c := kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a')
		c.Name, c.Workload.Group = "other/web-1/app", "other"
		return c
	}
	flux := func(w string) WorkloadChains {
		return WorkloadChains{Workload: w, Chains: [][]ChainOwner{{{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system", Confidence: ConfidenceClaimed}}}}
	}
	helmRel := func(w, name string) WorkloadChains {
		return WorkloadChains{Workload: w, Chains: [][]ChainOwner{{{Kind: OwnerHelm, Name: name, Scope: "shop", Confidence: ConfidenceClaimed}}}}
	}
	for name, tc := range map[string]struct {
		extra      inventory.Container
		management []WorkloadChains
		stops      bool
	}{
		"same namespace, same value":                                 {extra: kustContainer(dep, "web", "web-1", "app", kustRunningID, "nginx:1.25.3", 'a'), stops: true},
		"same namespace, another tag":                                {extra: kustContainer(dep, "web", "web-1", "app", "docker.io/library/nginx:1.24.0", "nginx:1.24.0", 'b')},
		"other namespace, no common manager":                         {extra: other()},
		"other namespace, the same Helm release":                     {extra: other(), management: []WorkloadChains{helmRel(kustApp, "api"), helmRel("deployment/other/web/app", "api")}, stops: true},
		"other namespace, another Helm release":                      {extra: other(), management: []WorkloadChains{helmRel(kustApp, "api"), helmRel("deployment/other/web/app", "web")}},
		"other namespace, the same Flux Kustomization, no plan item": {extra: other(), management: []WorkloadChains{flux(kustCron), flux("deployment/other/web/app")}, stops: true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelmPRHarness(t)
			h.containers = append(h.containers, tc.extra)
			h.management = tc.management
			u := onlyUnit(t, h.run(kustPlan()))
			if tc.stops {
				wantStatus(t, u, PRStatusManual, ReasonUndeclaredAffectedWorkload)
				if !strings.Contains(u.Detail, "values key") {
					t.Errorf("detail = %s", u.Detail)
				}
			} else {
				wantStatus(t, u, PRStatusCreated, "")
			}
		})
	}
	// A container of the Pod spec that is not listed, whether it runs or not.
	for name, d := range map[string]*inventory.PodInit{
		"a waiting container":                podDesc(nil, inventory.SpecContainer{Name: "waiting", Ref: "nginx:1.25.3", Kind: inventory.SpecMain}),
		"a sidecar not started":              podDesc(nil, inventory.SpecContainer{Name: "proxy", Ref: "nginx:1.25.3", Kind: inventory.SpecSidecar}),
		"an init container without a status": podDesc(&inventory.InitObservation{Name: "migrate", Declared: inventory.Declared{Ref: "nginx:1.25.3"}}),
	} {
		t.Run("spec: "+name, func(t *testing.T) {
			h := newHelmPRHarness(t)
			setDesc(h, d)
			wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusManual, ReasonUndeclaredAffectedWorkload)
		})
	}
}

func TestHelmValuesInitContainers(t *testing.T) {
	h, plan := kustInitHarness(t, nil)
	h.kust, h.helm = nil, helmMapping("image", kustSidecar, kustCron, kustInit)
	h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: helmFile})
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Workloads) != 4 || !strings.Contains(h.gh.pulls(testRepo)[0].Body, "Ordinary init containers among them") {
		t.Errorf("unit = %+v", u)
	}
	for name, mutate := range map[string]func(i *inventory.InitObservation){
		"another entity":                  func(i *inventory.InitObservation) { i.Image.Config = configKey('b').Digest },
		"declaration differs from status": func(i *inventory.InitObservation) { i.Declared.Ref = "nginx:mainline" },
		"imageID missing":                 func(i *inventory.InitObservation) { i.Image.Config = inventory.Digest{} },
		"no status":                       func(i *inventory.InitObservation) { i.HasStatus, i.Image = false, inventory.RunningImage{} },
	} {
		t.Run(name, func(t *testing.T) {
			h, plan := kustInitHarness(t, mutate)
			h.kust, h.helm = nil, helmMapping("image", kustSidecar, kustCron, kustInit)
			h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: helmFile})
			u := onlyUnit(t, h.run(plan))
			if u.Status != PRStatusManual || len(h.gh.pulls(testRepo)) != 0 {
				t.Fatalf("unit %s/%s (%s)", u.Status, u.Reason, u.Detail)
			}
		})
	}
	t.Run("one Pod without the init container", func(t *testing.T) {
		h, plan := kustInitHarness(t, nil)
		h.kust, h.helm = nil, helmMapping("image", kustSidecar, kustCron, kustInit)
		h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: helmFile})
		for i := range h.containers {
			if strings.HasPrefix(h.containers[i].Name, "shop/api-2/") {
				h.containers[i].PodInit = podDesc(nil)
			}
		}
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusManual, ReasonInstancesMissing)
	})
}

func TestHelmValuesEditRefusalsAreManual(t *testing.T) {
	for name, tc := range map[string]struct {
		file   string
		reason Reason
	}{
		"key missing":      {"other: 1\n", ReasonHelmKeyMissing},
		"no tag":           {"image:\n  repository: nginx\n", ReasonHelmTagFromChart},
		"empty tag":        {"image:\n  repository: nginx\n  tag: \"\"\n", ReasonHelmTagFromChart},
		"digest":           {"image:\n  repository: nginx\n  tag: \"1.25.3\"\n  digest: sha256:" + strings.Repeat("a", 64) + "\n", ReasonHelmDigest},
		"another shape":    {"image:\n  name: nginx\n  tag: \"1.25.3\"\n", ReasonHelmValuesShape},
		"numeric tag":      {"image:\n  repository: nginx\n  tag: 1.25\n", ReasonHelmNotString},
		"template":         {"image:\n  repository: nginx\n  tag: \"1.25.3\"\nx: \"{{ .Values.y }}\"\n", ReasonHelmTemplate},
		"two documents":    {helmFile + "---\nimage: {}\n", ReasonHelmInvalid},
		"duplicate key":    {"image:\n  repository: nginx\n  tag: \"1.25.3\"\n  tag: \"1.25.3\"\n", ReasonHelmInvalid},
		"anchor":           {"image: &i\n  repository: nginx\n  tag: \"1.25.3\"\n", ReasonHelmAnchorAlias},
		"other repository": {"image:\n  repository: busybox\n  tag: \"1.25.3\"\n", ReasonSourceMismatch},
		"Flux marker":      {"image:\n  repository: nginx\n  tag: \"1.25.3\" # {\"$imagepolicy\": \"a:b:tag\"}\n", ReasonHelmImageAutomation},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHelmPRHarness(t)
			h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: tc.file})
			writes := h.gh.writeCount()
			wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusManual, tc.reason)
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a write was made")
			}
		})
	}
	t.Run("file missing", func(t *testing.T) {
		h := newHelmPRHarness(t)
		h.helm[0].Path = "releases/missing/values.yaml"
		wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusManual, ReasonManifestFileNotFound)
	})
	t.Run("Argo CD Image Updater write-back file in the directory", func(t *testing.T) {
		for name, tc := range map[string]struct {
			files  []string
			manual bool
		}{
			"write-back file": {[]string{"values-prod.yaml", ".argocd-source-api.yaml"}, true},
			"no write-back":   {[]string{"values-prod.yaml", "argocd-source.yaml"}, false},
		} {
			t.Run(name, func(t *testing.T) {
				h := newHelmPRHarness(t)
				stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: dirSource{h.gh, tc.files}, Resolver: h.gh, Store: h.store, Limits: h.limits})
				if err != nil {
					t.Fatal(err)
				}
				res := stage.Run(context.Background(), PRStageInput{Plan: kustPlan(), Containers: h.containers, HelmValues: h.helm})
				u := onlyUnit(t, res)
				if tc.manual {
					wantStatus(t, u, PRStatusManual, ReasonImageUpdaterFile)
				} else {
					wantStatus(t, u, PRStatusCreated, "")
				}
			})
		}
	})
}

// Two keys of one values file: a problem of a container of either holds back
// both, as with two images entries of one kustomization.
func TestHelmValuesFileLevelAllOrNothing(t *testing.T) {
	second := func(h *prHarness) Plan {
		h.helm = append(h.helm, HelmValuesMapping{Workload: "deployment/shop/jobs/runner", Repository: testRepo, BaseBranch: "main", Path: helmPath, Key: "worker.image"})
		return kustPlan()
	}
	t.Run("a neighbour that runs normally", func(t *testing.T) {
		h := newHelmPRHarness(t)
		plan := second(h)
		h.containers = append(h.containers, kustContainer(inventory.WorkloadDeployment, "jobs", "jobs-1", "runner", "docker.io/library/busybox:1.36.1", "busybox:1.36.1", 'b'))
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusCreated, "")
	})
	t.Run("a neighbour that does not run", func(t *testing.T) {
		h := newHelmPRHarness(t)
		plan := second(h)
		u := onlyUnit(t, h.run(plan))
		wantStatus(t, u, PRStatusManual, ReasonInstancesMissing)
		if len(h.gh.pulls(testRepo)) != 0 {
			t.Error("a pull request was made")
		}
	})
}

// A Kustomize entry and a values key of one repository are separate edit
// points, and a Helm key of the other route does not interfere.
func TestHelmValuesAndKustomizeAreSeparateUnits(t *testing.T) {
	h := newHelmPRHarness(t)
	dep := inventory.WorkloadDeployment
	h.gh.commitFiles(testRepo, "main", map[string]string{kustPath: strings.Replace(kustFile, "nginx", "redis", 1)})
	h.gh.tops["docker.io/library/redis:1.25.4"] = topDigest('4')
	h.containers = append(h.containers, kustContainer(dep, "cache", "cache-1", "redis", "docker.io/library/redis:1.25.3", "redis:1.25.3", 'r'))
	h.kust = []KustomizeMapping{{Workload: "deployment/shop/cache/redis", Repository: testRepo, BaseBranch: "main", Path: kustPath, Image: "redis"}}
	it := kubeItemOf("docker.io/library/redis:1.25.3", 'r', "1.25.4", '4', "deployment/shop/cache/redis")
	res := h.run(kustPlan(kustItem(), it))
	if len(res.Units) != 2 {
		t.Fatalf("units = %d", len(res.Units))
	}
	kinds := map[string]bool{}
	for _, u := range res.Units {
		kinds[u.Kind] = true
	}
	if !kinds["helm_values"] || !kinds["kustomize"] {
		t.Errorf("kinds = %v", kinds)
	}
}

func TestHelmValuesKeysDoNotDependOnTheOrderOfAffects(t *testing.T) {
	a := newHelmPRHarness(t)
	a.helm = helmMapping("image", kustCron, kustSidecar)
	ua := onlyUnit(t, a.run(kustPlan()))
	b := newHelmPRHarness(t)
	b.helm = helmMapping("image", kustSidecar, kustCron)
	ub := onlyUnit(t, b.run(kustPlan()))
	if ua.UpdateKey == "" || ua.UpdateKey != ub.UpdateKey || ua.TargetKey != ub.TargetKey {
		t.Errorf("keys differ with the order of affects")
	}
	// The same key in a Kustomize unit of the same path would be a different target.
	if got := TargetKeyOf(prKindHelm, testRepoID, "main", helmPath, []string{"image"}); got == TargetKeyOf(prKindKustomize, testRepoID, "main", helmPath, []string{"image"}) {
		t.Error("the target key does not depend on the kind")
	}
}

func TestHelmValuesMarkerKinds(t *testing.T) {
	h := newHelmPRHarness(t)
	h.run(kustPlan())
	good, err := parsePRMarker(h.gh.pulls(testRepo)[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	noSet := good
	noSet.Affected = nil
	if noSet.wellFormed() == nil {
		t.Error("a Helm marker without the affected set is well formed")
	}
	tampered := good
	tampered.Affected = []string{kustApp}
	if tampered.verify(testRepoID) == nil {
		t.Error("a marker with another set verifies")
	}
	asKustomize := good
	asKustomize.Kind = "kustomize"
	if asKustomize.verify(testRepoID) == nil {
		t.Error("the marker verifies as another kind")
	}
	if err := removeAll(h.dir); err != nil {
		t.Fatal(err)
	}
	writes := h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(kustPlan())), PRStatusOpen, "")
	if h.gh.writeCount() != writes {
		t.Error("the recovered cycle wrote")
	}
	if rec := h.load(); len(rec.PRs) != 1 || !rec.PRs[0].Recovered || rec.PRs[0].Kind != "helm_values" {
		t.Errorf("records = %+v", rec.PRs)
	}
}

// The workloads with a Flux HelmRelease marker are named; the others of the set
// are not claimed to have one.
func TestHelmValuesBodyListsOnlyTheWorkloadsWithAHelmReleaseMarker(t *testing.T) {
	h := newHelmPRHarness(t)
	it := kustItem()
	it.Management = []WorkloadChains{
		{Workload: kustApp, Chains: [][]ChainOwner{{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "api", Scope: "shop"},
			{Kind: OwnerFlux, ResourceID: ResourceIDFluxHelmRelease, Name: "api", Scope: "flux-system", Confidence: ConfidenceClaimed}}}},
		{Workload: kustCron, Chains: [][]ChainOwner{{{Kind: OwnerHelm, Name: "report", Scope: "shop", Confidence: ConfidenceClaimed}}}},
	}
	wantStatus(t, onlyUnit(t, h.run(kustPlan(it))), PRStatusCreated, "")
	body := h.gh.pulls(testRepo)[0].Body
	i := strings.Index(body, "Flux HelmRelease management markers were detected on these workloads")
	if i < 0 {
		t.Fatalf("no line on the markers:\n%s", body)
	}
	line := body[i : i+strings.Index(body[i:], "\n")]
	if !strings.Contains(line, "deployment/shop/api/app") || strings.Contains(line, "cronjob/shop/report/job") || strings.Contains(line, "sidecar") {
		t.Errorf("line = %s", line)
	}
}

// The new tag is written in double quotes where the old one had none, and it
// would not be a string otherwise; a quoted tag keeps its style.
func TestHelmValuesQuotesATagThatWouldNotStayAString(t *testing.T) {
	for _, tag := range []string{"1.10", "on", "1e3", "0x1F"} {
		t.Run(tag, func(t *testing.T) {
			h := newHelmPRHarness(t)
			h.gh.tops["docker.io/library/nginx:"+tag] = topDigest('7')
			h.gh.commitFiles(testRepo, "main", map[string]string{helmPath: "image:\n  repository: nginx\n  tag: 1.25.3 # pinned\n"})
			it := kustItem()
			it.Candidate.Tag, it.Candidate.Ref = tag, "docker.io/library/nginx:"+tag
			it.Candidate.TopDigest = topDigest('7')
			wantStatus(t, onlyUnit(t, h.run(kustPlan(it))), PRStatusCreated, "")
			pr := h.gh.pulls(testRepo)[0]
			if got, want := readHelm(t, h, pr.HeadSHA), "image:\n  repository: nginx\n  tag: \""+tag+"\" # pinned\n"; got != want {
				t.Errorf("edited file %q, want %q", got, want)
			}
			if !strings.Contains(pr.Body, "written in double quotes") {
				t.Errorf("the body does not say the tag was quoted:\n%s", pr.Body)
			}
		})
	}
}
