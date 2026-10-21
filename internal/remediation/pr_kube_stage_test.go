package remediation

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

const (
	kubeRunning  = "docker.io/library/nginx:1.25.3"
	kubeManifest = `# web
apiVersion: v1
kind: ConfigMap
metadata:
  name: web
data:
  key: value
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3 # pinned
        - name: log
          image: busybox:1.36.1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
`
)

// kubeContainerOf is a running replica of a Kubernetes container whose Pod
// spec declares what it runs.
func kubeContainerOf(pod, workloadName, container, ref, declared string, h byte) inventory.Container {
	return inventory.Container{
		Name:     "shop/" + pod + "/" + container,
		Workload: inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "shop", Name: workloadName},
		Image:    inventory.RunningImage{Ref: ref, Config: configKey(h).Digest},
		Declared: &inventory.Declared{Ref: declared, PullPolicy: "IfNotPresent"},
	}
}

// kubeItemOf is an adopted candidate for the running ref of the given
// entity, run by the workloads.
func kubeItemOf(ref string, h byte, tag string, top byte, workloads ...string) Item {
	it := nginxItem(tag, top, []string{"CVE-1"}, nil)
	it.Key = ref + "|" + entityString(configKey(h))
	it.Current.Ref = ref
	it.Current.Entity = entityString(configKey(h))
	it.Candidate.Ref = "docker.io/library/nginx:" + tag
	it.Services = nil
	for _, w := range workloads {
		it.Services = append(it.Services, ServiceRef{Workload: w})
	}
	return it
}

func kubeMapping(workload, path string) KubernetesMapping {
	return KubernetesMapping{Workload: workload, Repository: testRepo, BaseBranch: "main", Path: path}
}

// newKubePRHarness has the manifest in the test repository and the web app
// container running as two replicas.
func newKubePRHarness(t *testing.T) *prHarness {
	t.Helper()
	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": kubeManifest})
	h.gh.humanMoved = map[string]bool{}
	h.gh.tops["docker.io/library/nginx:1.25.4"] = topDigest('1')
	h.gh.tops["docker.io/library/nginx:1.25.5"] = topDigest('2')
	h.mappings = nil
	h.containers = []inventory.Container{
		kubeContainerOf("web-1", "web", "app", kubeRunning, "nginx:1.25.3", 'a'),
		kubeContainerOf("web-2", "web", "app", kubeRunning, "nginx:1.25.3", 'a'),
	}
	h.kube = []KubernetesMapping{kubeMapping("deployment/shop/web/app", "apps/web.yaml")}
	return h
}

func kubePlan(items ...Item) Plan { return testPlan(items...) }

const webApp = "deployment/shop/web/app"

func TestKubernetesPRCreated(t *testing.T) {
	h := newKubePRHarness(t)
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)
	it.Management = []WorkloadChains{{Workload: webApp, Chains: [][]ChainOwner{{
		{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web", Scope: "shop"},
		{Kind: OwnerHelm, Name: "web-release", Scope: "shop", Confidence: ConfidenceClaimed},
	}}}}
	res := h.run(kubePlan(it))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if u.Kind != "kubernetes" || u.Path != "apps/web.yaml" || u.Current != kubeRunning || u.CandidateTag != "1.25.4" || u.Number != 1 ||
		len(u.Workloads) != 1 || u.Workloads[0] != webApp || len(u.Locations) != 1 || u.Locations[0] != "Deployment/shop/web/app" {
		t.Errorf("unit = %+v", u)
	}
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 1 {
		t.Fatalf("pulls = %d", len(pulls))
	}
	pr := pulls[0]
	if pr.Title != "Update docker.io/library/nginx to 1.25.4 in apps/web.yaml" || !strings.HasPrefix(pr.HeadRef, "kestrelynx/kubernetes/web-1.25.4-") {
		t.Errorf("title %q head %q", pr.Title, pr.HeadRef)
	}
	// Only the mapped container of the Deployment named web changed; the
	// ConfigMap of the same name, the other container and the api Deployment
	// that runs the same image did not.
	f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "apps/web.yaml")
	want := strings.Replace(kubeManifest, "nginx:1.25.3 # pinned", "nginx:1.25.4 # pinned", 1)
	if err != nil || string(f.Content) != want {
		t.Errorf("edited file:\n%s\nerr %v", f.Content, err)
	}

	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Kind != "kubernetes" || len(m.Affected) != 1 || m.Affected[0] != webApp || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) {
		t.Fatalf("marker %+v err %v", m, err)
	}
	if m.UpdateKey != KubernetesUpdateKey(m.TargetKey, kubeRunning, "1.25.4", topDigest('1'), []string{webApp}) || m.UpdateKey == UpdateKey(m.TargetKey, kubeRunning, "1.25.4", topDigest('1')) {
		t.Error("the update key does not cover the affected set")
	}
	for _, want := range []string{
		"Merging this pull request may deploy the change",
		"Helm release `web-release` in `shop`",
		"`Deployment/shop/web/containers/app`: `nginx:1.25.3` to `nginx:1.25.4`",
		"Image declared in the Pod specs: `nginx:1.25.3`",
		"Also running this image, not edited",
	} {
		if want == "Also running this image, not edited" {
			if strings.Contains(pr.Body, want) {
				t.Errorf("the body lists unmapped workloads that do not run the image")
			}
			continue
		}
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}
	if strings.Contains(pr.Body, "Jobs that already exist") {
		t.Error("a Deployment's pull request carries the Job note")
	}
	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].Kind != "kubernetes" || len(rec.PRs[0].Affected) != 1 || len(rec.Attempts) != 1 || len(rec.Attempts[0].Affected) != 1 || rec.Attempts[0].Kind != "kubernetes" {
		t.Errorf("records = %+v", rec)
	}

	// The next cycle sees the open pull request and writes nothing.
	writes := h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(kubePlan(it))), PRStatusOpen, "")
	if h.gh.writeCount() != writes {
		t.Error("the second cycle wrote")
	}
	// A closed pull request is not opened again, with a new base too.
	h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State = "closed" })
	wantStatus(t, onlyUnit(t, h.run(kubePlan(it))), PRStatusSuppressed, "")
	h.gh.commitFiles(testRepo, "main", map[string]string{"README": "x"})
	h.run(kubePlan(it))
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d, want the closed one only", n)
	}
}

func TestKubernetesPRRecoveredFromMarker(t *testing.T) {
	h := newKubePRHarness(t)
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)
	h.run(kubePlan(it))
	// The records are lost; the open pull request is recognized by its marker.
	if err := removeAll(h.dir); err != nil {
		t.Fatal(err)
	}
	writes := h.gh.writeCount()
	u := onlyUnit(t, h.run(kubePlan(it)))
	wantStatus(t, u, PRStatusOpen, "")
	if h.gh.writeCount() != writes {
		t.Error("the recovered cycle wrote")
	}
	rec := h.load()
	if len(rec.PRs) != 1 || !rec.PRs[0].Recovered || rec.PRs[0].Kind != "kubernetes" || len(rec.PRs[0].Affected) != 1 {
		t.Errorf("records = %+v", rec.PRs)
	}
}

func TestKubernetesCronJobBodyNote(t *testing.T) {
	h := newKubePRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/cron.yaml": "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: report\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - name: job\n              image: nginx:1.25.3\n"})
	c := kubeContainerOf("report-1", "report", "job", kubeRunning, "nginx:1.25.3", 'a')
	c.Workload.Kind = inventory.WorkloadCronJob
	h.containers = []inventory.Container{c}
	h.kube = []KubernetesMapping{kubeMapping("cronjob/shop/report/job", "apps/cron.yaml")}
	res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', "cronjob/shop/report/job")))
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	if body := h.gh.pulls(testRepo)[0].Body; !strings.Contains(body, "Jobs that already exist are not affected") {
		t.Errorf("the body lacks the note on existing Jobs:\n%s", body)
	}
}

func TestKubernetesTwoContainersOfOneFileAreOnePullRequest(t *testing.T) {
	h := newKubePRHarness(t)
	h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", kubeRunning, "nginx:1.25.3", 'a'))
	h.kube = append(h.kube, kubeMapping("deployment/shop/api/app", "apps/web.yaml"))
	res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp, "deployment/shop/api/app")))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Workloads) != 2 {
		t.Errorf("workloads = %v", u.Workloads)
	}
	f, _ := h.gh.ReadFile(context.Background(), testRepo, h.gh.pulls(testRepo)[0].HeadSHA, "apps/web.yaml")
	if strings.Count(string(f.Content), "nginx:1.25.4") != 2 || strings.Count(string(f.Content), "nginx:1.25.3") != 0 {
		t.Errorf("edited file:\n%s", f.Content)
	}
	// The update key covers both: mapping only one gives another update.
	m, _ := parsePRMarker(h.gh.pulls(testRepo)[0].Body)
	if len(m.Affected) != 2 {
		t.Errorf("affected = %v", m.Affected)
	}
}

func TestKubernetesDifferentDeclaredReferencesAreSeparateUnits(t *testing.T) {
	h := newKubePRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": strings.Replace(kubeManifest, "name: api\n  namespace: shop\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3", "name: api\n  namespace: shop\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.24.0", 1)})
	h.gh.tops["docker.io/library/nginx:1.24.1"] = topDigest('3')
	h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", "docker.io/library/nginx:1.24.0", "nginx:1.24.0", 'b'))
	h.kube = append(h.kube, kubeMapping("deployment/shop/api/app", "apps/web.yaml"))
	res := h.run(kubePlan(
		kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp),
		kubeItemOf("docker.io/library/nginx:1.24.0", 'b', "1.24.1", '3', "deployment/shop/api/app")))
	if len(res.Units) != 2 {
		t.Fatalf("units = %d, want one per declared reference", len(res.Units))
	}
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusCreated, "")
	}
}

// Everything that makes the set of instances unverifiable stops the unit
// before any GitHub write.
func TestKubernetesUnitsStopOnIncompleteOrDisagreeingInstances(t *testing.T) {
	item := func() Item { return kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp) }
	for name, tc := range map[string]struct {
		mutate func(h *prHarness) Plan
		reason Reason
	}{
		"declared differs from running": {func(h *prHarness) Plan {
			h.containers[1].Declared.Ref = "nginx:mainline"
			return kubePlan(item())
		}, ReasonDeclaredRefMismatch},
		"declaration unreadable": {func(h *prHarness) Plan {
			h.containers[0].Declared.Ref = ""
			return kubePlan(item())
		}, ReasonDeclaredRefUnavailable},
		"rollout: another reference running": {func(h *prHarness) Plan {
			h.containers[1] = kubeContainerOf("web-2", "web", "app", "docker.io/library/nginx:1.25.4", "nginx:1.25.4", 'b')
			return kubePlan(item(), kubeItemOf("docker.io/library/nginx:1.25.4", 'b', "1.25.5", '2', webApp))
		}, ReasonMixedReferences},
		"an instance has no plan item": {func(h *prHarness) Plan {
			h.containers[1].Image.Config = configKey('c').Digest // another entity, no finding
			return kubePlan(item())
		}, ReasonInstancesMissing},
		"an entity is not an adopted candidate": {func(h *prHarness) Plan {
			h.containers[1].Image.Config = configKey('c').Digest
			other := kubeItemOf(kubeRunning, 'c', "1.25.4", '1', webApp)
			other.Category = CategoryNoCandidate
			return kubePlan(item(), other)
		}, ReasonKubernetesSetNotAdopted},
		"entities have different candidates": {func(h *prHarness) Plan {
			h.containers[1].Image.Config = configKey('c').Digest
			return kubePlan(item(), kubeItemOf(kubeRunning, 'c', "1.25.5", '2', webApp))
		}, ReasonKubernetesSetNotAdopted},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			plan := tc.mutate(h)
			writes := h.gh.writeCount()
			res := h.run(plan)
			if len(res.Units) == 0 {
				t.Fatal("no unit")
			}
			// A workload running two references is in the unit of each.
			for _, u := range res.Units {
				wantStatus(t, u, PRStatusManual, tc.reason)
			}
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Error("a pull request was made for a set that cannot be verified")
			}
		})
	}
}

func TestKubernetesNoUnitWithoutAnInstanceOrAMapping(t *testing.T) {
	h := newKubePRHarness(t)
	h.containers = nil // nothing runs
	if res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp))); len(res.Units) != 0 {
		t.Errorf("units = %+v, want none for a mapped container that does not run", res.Units)
	}
	h = newKubePRHarness(t)
	h.kube = nil
	if res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp))); len(res.Units) != 0 {
		t.Errorf("units = %+v, want none without a mapping", res.Units)
	}
	// A container with no declaration (not Kubernetes) is not one either.
	h = newKubePRHarness(t)
	h.containers[0].Declared, h.containers[1].Declared = nil, nil
	if res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp))); len(res.Units) != 0 {
		t.Errorf("units = %+v, want none without declarations", res.Units)
	}
}

// Files the edit refuses leave the unit manual with the editor's reason and no
// write.
func TestKubernetesEditRefusalsAreManual(t *testing.T) {
	for name, tc := range map[string]struct {
		file   string
		reason Reason
	}{
		"digest":         {strings.Replace(kubeManifest, "nginx:1.25.3 # pinned", "nginx@sha256:"+hex64('a'), 1), ReasonManifestDigest},
		"variable":       {strings.Replace(kubeManifest, "nginx:1.25.3 # pinned", "nginx:${TAG}", 1), ReasonManifestVariable},
		"flux marker":    {strings.Replace(kubeManifest, "# pinned", `# {"$imagepolicy": "flux-system:web"}`, 1), ReasonManifestImageAutomation},
		"object missing": {strings.Replace(kubeManifest, "name: web\n  namespace: shop", "name: other\n  namespace: shop", 1), ReasonSourceObjectMissing},
		"tag differs":    {strings.Replace(kubeManifest, "nginx:1.25.3 # pinned", "nginx:1.25.2 # pinned", 1), ReasonSourceMismatch},
		"template":       {kubeManifest + "# {{ x }}\n", ReasonManifestTemplate},
		"duplicate key":  {kubeManifest + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\ndata:\n  a: 1\n  a: 2\n", ReasonManifestInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": tc.file})
			writes := h.gh.writeCount()
			u := onlyUnit(t, h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp))))
			wantStatus(t, u, PRStatusManual, tc.reason)
			if h.gh.writeCount() != writes {
				t.Error("a write was made for a file that cannot be edited")
			}
		})
	}
}

func TestKubernetesManifestFileProblems(t *testing.T) {
	h := newKubePRHarness(t)
	h.kube[0].Path = "apps/missing.yaml"
	wantStatus(t, onlyUnit(t, h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)))), PRStatusManual, ReasonManifestFileNotFound)
}

// dirSource adds directory listing to the fake GitHub.
type dirSource struct {
	*fakePRGitHub
	files []string
}

func (d dirSource) ListDirectory(_ context.Context, _, _, _ string) ([]github.Entry, error) {
	var out []github.Entry
	for _, f := range d.files {
		out = append(out, github.Entry{Name: f, Type: github.EntryFile})
	}
	return out, nil
}

func TestKubernetesImageUpdaterFileMakesTheUnitManual(t *testing.T) {
	for name, tc := range map[string]struct {
		files  []string
		manual bool
	}{
		"write-back file":        {[]string{"web.yaml", ".argocd-source-web.yaml"}, true},
		"no write-back file":     {[]string{"web.yaml", "argocd-source.yaml", ".argocd-source-web.json"}, false},
		"another directory name": {[]string{".argocd-source"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: dirSource{h.gh, tc.files}, Resolver: h.gh, Store: h.store, Limits: h.limits})
			if err != nil {
				t.Fatal(err)
			}
			res := stage.Run(context.Background(), PRStageInput{Plan: kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)), Containers: h.containers, Kubernetes: h.kube})
			u := onlyUnit(t, res)
			if tc.manual {
				wantStatus(t, u, PRStatusManual, ReasonImageUpdaterFile)
				if len(h.gh.pulls(testRepo)) != 0 {
					t.Error("a pull request was made")
				}
			} else {
				wantStatus(t, u, PRStatusCreated, "")
			}
		})
	}
}

// A newer patch for the same containers replaces the older pull request; the
// same file with another set of containers is another update and does not.
func TestKubernetesNewerPatchReplacesOlder(t *testing.T) {
	h := newKubePRHarness(t)
	h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)))
	res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.5", '2', webApp)))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if u.Number != 2 || len(u.Replaced) != 1 || u.Replaced[0] != 1 {
		t.Errorf("unit = %+v, want #2 replacing #1", u)
	}
	pulls := h.gh.pulls(testRepo)
	if pulls[0].State != "closed" || pulls[1].State != "open" {
		t.Errorf("pull states = %s, %s", pulls[0].State, pulls[1].State)
	}

	h = newKubePRHarness(t)
	h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)))
	h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", kubeRunning, "nginx:1.25.3", 'a'))
	h.kube = append(h.kube, kubeMapping("deployment/shop/api/app", "apps/web.yaml"))
	h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.5", '2', webApp, "deployment/shop/api/app")))
	for _, p := range h.gh.pulls(testRepo) {
		if p.State != "open" {
			t.Errorf("pull #%d is %s: a pull request for another set of containers must not be replaced", p.Number, p.State)
		}
	}
}

// A Dockerfile update for Kubernetes workloads is the Dockerfile update as it
// is for Docker, with the note on what merging may do and the chains.
func TestKubernetesDockerfilePullRequest(t *testing.T) {
	h := newDFPRHarness(t)
	h.containers = nil
	item := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	item.Workloads = []string{webApp}
	item.Entities[0].Services = []ServiceRef{{Workload: webApp}}
	plan := dfPlan(item)
	plan.Items = []Item{{Key: "x", Management: []WorkloadChains{{Workload: webApp, Chains: [][]ChainOwner{{
		{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web", Scope: "shop"},
		{Kind: OwnerArgoCD, Name: "web-app", Confidence: ConfidenceClaimed},
	}}}}}}
	res := h.run(plan)
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if u.Kind != "dockerfile" || len(u.Services) != 1 || u.Services[0] != "web" {
		t.Errorf("unit = %+v", u)
	}
	pr := h.gh.pulls(testRepo)[0]
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Kind != "dockerfile" || len(m.Affected) != 0 || m.verify(testRepoID) != nil {
		t.Fatalf("marker %+v err %v", m, err)
	}
	for _, want := range []string{"Merging this pull request may deploy the change", "Argo CD application `web-app`"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}
	// A Docker-mode Dockerfile body has neither.
	h2 := newDFPRHarness(t)
	h2.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)))
	if body := h2.gh.pulls(testRepo)[0].Body; strings.Contains(body, "may deploy") {
		t.Error("a Docker Dockerfile body carries the Kubernetes note")
	}
}

func removeAll(dir string) error { return os.RemoveAll(dir) }

// "Also running" names the workloads that run the image without a mapping; one
// mapped in another file is not among them.
func TestKubernetesAlsoRunningLeavesOutMappedWorkloads(t *testing.T) {
	h := newKubePRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/api.yaml": strings.ReplaceAll(strings.Replace(kubeManifest, "name: web\n  namespace: shop", "name: api2\n  namespace: shop", 1), "name: api\n", "name: api\n")})
	h.containers = append(h.containers,
		kubeContainerOf("api-1", "api", "app", kubeRunning, "nginx:1.25.3", 'a'),
		kubeContainerOf("other-1", "other", "app", kubeRunning, "nginx:1.25.3", 'a'))
	h.kube = append(h.kube, kubeMapping("deployment/shop/api/app", "apps/web.yaml"))
	h.kube[1].Path = "apps/api.yaml"
	h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp, "deployment/shop/api/app", "deployment/shop/other/app")))
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 2 {
		t.Fatalf("pulls = %d, want one per file", len(pulls))
	}
	for _, p := range pulls {
		line := ""
		for _, l := range strings.Split(p.Body, "\n") {
			if strings.HasPrefix(l, "- Also running this image") {
				line = l
			}
		}
		if !strings.Contains(line, "deployment/shop/other/app") || strings.Contains(line, "deployment/shop/api/app") || strings.Contains(line, webApp) {
			t.Errorf("also running line = %q, want only the unmapped workload", line)
		}
	}
}

// A Kubernetes pull request whose marker has no affected set, or one that does
// not give the update key, cannot be recovered from: writes to the repository
// stop instead of a second pull request being opened for the update.
func TestKubernetesMarkerWithoutOrWithWrongAffectedStopsWrites(t *testing.T) {
	for name, edit := range map[string]func(body string) string{
		"no affected set": func(b string) string { return strings.Replace(b, `,"affected":["deployment/shop/web/app"]`, "", 1) },
		"another set": func(b string) string {
			return strings.Replace(b, `"affected":["deployment/shop/web/app"]`, `"affected":["deployment/shop/web/log"]`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)
			h.run(kubePlan(it))
			h.gh.editPull(testRepo, 1, func(p *github.PullRequest) {
				if !strings.Contains(p.Body, `"affected"`) {
					t.Fatal("the marker has no affected set to edit")
				}
				p.Body = edit(p.Body)
			})
			if err := removeAll(h.dir); err != nil {
				t.Fatal(err)
			}
			writes := h.gh.writeCount()
			// Not h.run: its invariant check would object to the edited body.
			stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: h.gh, Store: h.store, Limits: h.limits})
			if err != nil {
				t.Fatal(err)
			}
			res := stage.Run(context.Background(), PRStageInput{Plan: kubePlan(it), Containers: h.containers, Kubernetes: h.kube})
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
				t.Error("a write was made although the open pull request could not be verified")
			}
			if len(res.Problems) == 0 || res.Problems[0].Code != PRProblemRecordsUnverified {
				t.Errorf("problems = %+v, want the records reported unverified", res.Problems)
			}
		})
	}
}

// Both wordings of the body render every verb.
func TestKubernetesBodyInBothLanguages(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		h := newKubePRHarness(t)
		it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)
		it.Management = []WorkloadChains{{Workload: webApp, Chains: [][]ChainOwner{{
			{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web", Scope: "shop"},
			{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system"},
		}}}}
		h.runIn(lang, kubePlan(it))
		body := h.gh.pulls(testRepo)[0].Body
		if strings.Contains(body, "%!") || strings.Contains(body, "EXTRA") {
			t.Errorf("%s: a verb is not rendered:\n%s", lang, body)
		}
		want := "Flux Kustomization `apps` in `flux-system`"
		sentence := "in `apps/web.yaml` of `example/app`"
		if lang == BodyJA {
			want = "Flux Kustomization `apps`(`flux-system`)"
			sentence = "`example/app` の `apps/web.yaml` にある"
		}
		if !strings.Contains(body, sentence) {
			t.Errorf("%s: the first sentence lacks %q", lang, sentence)
		}
		if !strings.Contains(body, want) {
			t.Errorf("%s: the body lacks %q", lang, want)
		}
	}
}

// A container that shares its image with another one of the Pod template is
// edited alone; the pull request says the other keeps its tag.
func TestKubernetesSharedImageIsEditedAloneAndReported(t *testing.T) {
	h := newKubePRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": strings.Replace(kubeManifest, "busybox:1.36.1", "nginx:1.25.3", 1)})
	res := h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)))
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	pr := h.gh.pulls(testRepo)[0]
	f, _ := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "apps/web.yaml")
	if strings.Count(string(f.Content), "nginx:1.25.4") != 1 || !strings.Contains(string(f.Content), "name: log\n          image: nginx:1.25.3") {
		t.Errorf("edited file:\n%s", f.Content)
	}
	if !strings.Contains(pr.Body, "are not changed, so they keep its tag: `Deployment/shop/web/containers/log`") {
		t.Errorf("the body does not list the unchanged container:\n%s", pr.Body)
	}
}

// What the mapping says the object is takes part in the update's identity: a
// pull request made for one object does not suppress or replace the update of
// another in the same file.
func TestKubernetesOtherObjectIsAnotherUpdate(t *testing.T) {
	h := newKubePRHarness(t)
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)
	h.run(kubePlan(it))
	first := h.load().PRs[0]

	// The same workload now maps to the api object of the file.
	h.kube[0].ObjectName = "api"
	res := h.run(kubePlan(it))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if u.Number != 2 || u.TargetKey == first.TargetKey || u.UpdateKey == first.UpdateKey || u.Locations[0] != "Deployment/shop/api/app" {
		t.Errorf("unit = %+v, want a new pull request for another object (first target %s)", u, first.TargetKey[:8])
	}
	// And a newer candidate for it does not replace the first object's pull request.
	h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.5", '2', webApp)))
	for _, p := range h.gh.pulls(testRepo) {
		if p.Number == 1 && p.State != "open" {
			t.Errorf("pull #1 of another object is %s: it was replaced", p.State)
		}
	}
}

// A workload that cannot be verified holds back the others that would be
// edited with it, in whichever way it cannot.
func TestKubernetesOneUndeterminableWorkloadHoldsBackTheFile(t *testing.T) {
	apiApp := "deployment/shop/api/app"
	setup := func(t *testing.T) *prHarness {
		h := newKubePRHarness(t)
		h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", kubeRunning, "nginx:1.25.3", 'a'))
		h.kube = append(h.kube, kubeMapping(apiApp, "apps/web.yaml"))
		return h
	}
	both := func() Plan { return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp, apiApp)) }
	for name, tc := range map[string]struct {
		mutate func(h *prHarness)
		plan   func() Plan
		reason Reason
	}{
		"web is mixed: part of it runs another tag": {func(h *prHarness) {
			h.containers[1] = kubeContainerOf("web-2", "web", "app", "docker.io/library/nginx:1.25.4", "nginx:1.25.4", 'b')
		}, func() Plan {
			return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp, apiApp), kubeItemOf("docker.io/library/nginx:1.25.4", 'b', "1.25.5", '2', webApp))
		}, ReasonMixedReferences},
		"web has an instance without a plan item": {func(h *prHarness) {
			h.containers[1].Image.Config = configKey('c').Digest
		}, both, ReasonInstancesMissing},
		"web has an instance without a running reference": {func(h *prHarness) {
			h.containers[1].Image.Ref = ""
		}, both, ReasonInstancesMissing},
		"no instance of web has a running reference": {func(h *prHarness) {
			h.containers[0].Image.Ref, h.containers[1].Image.Ref = "", ""
		}, func() Plan { return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', apiApp)) }, ReasonInstancesMissing},
		"web declares nothing readable": {func(h *prHarness) {
			h.containers[0].Declared.Ref, h.containers[1].Declared.Ref = "", ""
		}, both, ReasonDeclaredRefUnavailable},
		"web declares another image than it runs": {func(h *prHarness) {
			h.containers[0].Declared.Ref, h.containers[1].Declared.Ref = "nginx:mainline", "nginx:mainline"
		}, both, ReasonDeclaredRefMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			tc.mutate(h)
			writes := h.gh.writeCount()
			res := h.run(tc.plan())
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Errorf("a pull request was made although web cannot be verified: %+v", res.Units)
			}
			found := false
			for _, u := range res.Units {
				found = found || (u.Status == PRStatusManual && u.Reason == tc.reason)
				if u.Status == PRStatusCreated {
					t.Errorf("unit %v was created", u.Workloads)
				}
			}
			if !found {
				t.Errorf("no unit is manual with %s: %+v", tc.reason, res.Units)
			}
		})
	}
}

// A file is edited for all of its mapped containers or for none: whatever is
// wrong with one mapping holds back the pull request of every unit of the file.
func TestKubernetesFileIsAllOrNothing(t *testing.T) {
	const apiApp = "deployment/shop/api/app"
	for name, tc := range map[string]struct {
		mutate func(h *prHarness)
		plan   func() Plan
		reason Reason
	}{
		"one of two mappings has no running instance": {
			func(h *prHarness) {}, // api is mapped and does not run
			func() Plan { return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)) },
			ReasonInstancesMissing,
		},
		"a declaration is kept while a running reference changes": {
			func(h *prHarness) {
				// web declares 1.25.3 everywhere; one of its instances runs 1.25.4.
				h.containers[1] = kubeContainerOf("web-2", "web", "app", "docker.io/library/nginx:1.25.4", "nginx:1.25.3", 'b')
				h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", kubeRunning, "nginx:1.25.3", 'a'))
			},
			func() Plan {
				return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp, apiApp), kubeItemOf("docker.io/library/nginx:1.25.4", 'b', "1.25.5", '2', webApp))
			},
			ReasonDeclaredRefMismatch,
		},
		"another entity of the same image is not an adopted candidate": {
			func(h *prHarness) {
				h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", kubeRunning, "nginx:1.25.3", 'c'))
			},
			func() Plan {
				other := kubeItemOf(kubeRunning, 'c', "1.25.4", '1', apiApp)
				other.Category = CategoryManual
				return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp), other)
			},
			ReasonKubernetesSetNotAdopted,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			h.kube = append(h.kube, kubeMapping(apiApp, "apps/web.yaml"))
			tc.mutate(h)
			writes := h.gh.writeCount()
			res := h.run(tc.plan())
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
				t.Errorf("a pull request was made for a file with a mapping that cannot be verified: %+v", res.Units)
			}
			if len(res.Units) == 0 {
				t.Fatal("no unit")
			}
			for _, u := range res.Units {
				wantStatus(t, u, PRStatusManual, tc.reason)
				if !strings.Contains(u.Detail, "holds back every pull request for apps/web.yaml") {
					t.Errorf("detail %q does not name what holds the file back", u.Detail)
				}
			}
		})
	}
}

// Two mappings that resolve to the same container of the same document would
// be one edit for two sets of workloads, whatever they run.
func TestKubernetesMappingsResolvingToOnePlaceAreHeldBack(t *testing.T) {
	const doc = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3\n"
	for name, tc := range map[string]struct {
		shopRuns, prodRuns string
		prodInstance       bool
	}{
		"different running tags":   {"1.25.3", "1.25.2", true},
		"the same tag":             {"1.25.3", "1.25.3", true},
		"one side has no instance": {"1.25.3", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": doc})
			h.kube = []KubernetesMapping{kubeMapping(webApp, "apps/web.yaml"), kubeMapping("deployment/prod/web/app", "apps/web.yaml")}
			h.containers = []inventory.Container{kubeContainerOf("web-1", "web", "app", "docker.io/library/nginx:"+tc.shopRuns, "nginx:"+tc.shopRuns, 'a')}
			items := []Item{kubeItemOf("docker.io/library/nginx:"+tc.shopRuns, 'a', "1.25.4", '1', webApp)}
			if tc.prodInstance {
				c := kubeContainerOf("web-1", "web", "app", "docker.io/library/nginx:"+tc.prodRuns, "nginx:"+tc.prodRuns, 'b')
				c.Name = "prod/web-1/app"
				c.Workload.Group = "prod"
				h.containers = append(h.containers, c)
				if tc.prodRuns != tc.shopRuns {
					items = append(items, kubeItemOf("docker.io/library/nginx:"+tc.prodRuns, 'b', "1.25.4", '1', "deployment/prod/web/app"))
				}
			}
			h.gh.tops["docker.io/library/nginx:1.25.4"] = topDigest('1')
			res := h.run(kubePlan(items...))
			if len(h.gh.pulls(testRepo)) != 0 {
				t.Fatalf("a pull request was made for a container two mappings share: %+v", res.Units)
			}
			if len(res.Units) == 0 {
				t.Fatal("no unit")
			}
			for _, u := range res.Units {
				if u.Status != PRStatusManual || (u.Reason != ReasonMappingConflict && u.Reason != ReasonInstancesMissing) {
					t.Errorf("unit %v = %s/%s", u.Workloads, u.Status, u.Reason)
				}
			}
		})
	}

	// Without the second mapping nothing clashes, and the one is edited.
	h := newKubePRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": doc})
	wantStatus(t, onlyUnit(t, h.run(kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)))), PRStatusCreated, "")
}

// A mapped container that runs normally and has nothing to fix does not hold
// its file back: only the container with a fix is edited.
func TestKubernetesCleanNeighbourDoesNotHoldBackTheFile(t *testing.T) {
	for name, plan := range map[string]func() Plan{
		"no plan item": func() Plan { return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)) },
		"an item that is no candidate": func() Plan {
			other := kubeItemOf("docker.io/library/nginx:1.24.0", 'c', "1.24.1", '3', "deployment/shop/api/app")
			other.Category = CategoryNoCandidate
			return kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp), other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newKubePRHarness(t)
			h.kube = append(h.kube, kubeMapping("deployment/shop/api/app", "apps/web.yaml"))
			h.containers = append(h.containers, kubeContainerOf("api-1", "api", "app", "docker.io/library/nginx:1.24.0", "nginx:1.24.0", 'c'))
			u := onlyUnit(t, h.run(plan()))
			wantStatus(t, u, PRStatusCreated, "")
			if len(u.Workloads) != 1 || u.Workloads[0] != webApp {
				t.Errorf("workloads = %v, want web only", u.Workloads)
			}
			f, _ := h.gh.ReadFile(context.Background(), testRepo, h.gh.pulls(testRepo)[0].HeadSHA, "apps/web.yaml")
			if !strings.Contains(string(f.Content), "image: nginx:1.25.4 # pinned") || strings.Count(string(f.Content), "nginx:1.25.3") != 1 {
				t.Errorf("edited file:\n%s", f.Content)
			}
		})
	}
}

const sharedDoc = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3\n"

// sharedHarness maps one namespace-less document from two namespaces whose
// containers run different tags.
func sharedHarness(t *testing.T) (*prHarness, Plan) {
	h := newKubePRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": sharedDoc})
	h.gh.tops["docker.io/library/nginx:1.25.4"] = topDigest('1')
	h.kube = []KubernetesMapping{kubeMapping(webApp, "apps/web.yaml"), kubeMapping("deployment/prod/web/app", "apps/web.yaml")}
	prod := kubeContainerOf("web-1", "web", "app", "docker.io/library/nginx:1.25.2", "nginx:1.25.2", 'b')
	prod.Name, prod.Workload.Group = "prod/web-1/app", "prod"
	h.containers = []inventory.Container{kubeContainerOf("web-1", "web", "app", kubeRunning, "nginx:1.25.3", 'a'), prod}
	return h, kubePlan(
		kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp),
		kubeItemOf("docker.io/library/nginx:1.25.2", 'b', "1.25.4", '1', "deployment/prod/web/app"))
}

// The check of the mappings of a file is part of the edit, on the content that
// is edited: a read that fails stops the write, and the next cycle's read is
// checked in full.
func TestKubernetesConflictIsCheckedOnTheEditRead(t *testing.T) {
	h, plan := sharedHarness(t)
	h.gh.failNext("ReadFile", failError)
	writes := h.gh.writeCount()
	res := h.run(plan)
	if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 0 {
		t.Fatalf("a write was made after a failed read: %+v", res.Units)
	}
	res = h.run(plan)
	if len(h.gh.pulls(testRepo)) != 0 || h.gh.writeCount() != writes {
		t.Fatalf("a pull request was made for a container two mappings share: %+v", res.Units)
	}
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusManual, ReasonMappingConflict)
	}
}

// advancingSource moves the branch to another commit after the first time it
// is asked for the branch's commit.
type advancingSource struct {
	*fakePRGitHub
	files  map[string]string
	asked  int
	branch string
}

func (a *advancingSource) ResolveBranch(ctx context.Context, repo, branch string) (string, error) {
	sha, err := a.fakePRGitHub.ResolveBranch(ctx, repo, branch)
	a.asked++
	if a.asked == 1 {
		a.fakePRGitHub.commitFiles(repo, branch, a.files)
	}
	return sha, err
}

// What is checked is the content the edit is made from: the commit read for the
// edit, whatever the branch does around it.
func TestKubernetesConflictIsCheckedOnTheCommitThatIsEdited(t *testing.T) {
	h := newKubePRHarness(t)
	// Two namespaced documents, then one namespace-less document both map to.
	distinct := strings.Replace(sharedDoc, "  name: web\n", "  name: web\n  namespace: shop\n", 1) + "---\n" +
		strings.Replace(sharedDoc, "  name: web\n", "  name: web\n  namespace: prod\n", 1)
	h.gh.commitFiles(testRepo, "main", map[string]string{"apps/web.yaml": distinct})
	h.gh.tops["docker.io/library/nginx:1.25.4"] = topDigest('1')
	h.kube = []KubernetesMapping{kubeMapping(webApp, "apps/web.yaml"), kubeMapping("deployment/prod/web/app", "apps/web.yaml")}
	prod := kubeContainerOf("web-1", "web", "app", kubeRunning, "nginx:1.25.3", 'a')
	prod.Name, prod.Workload.Group = "prod/web-1/app", "prod"
	h.containers = []inventory.Container{kubeContainerOf("web-1", "web", "app", kubeRunning, "nginx:1.25.3", 'a'), prod}
	plan := kubePlan(kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp, "deployment/prod/web/app"))

	// The branch moves to the shared document right after the stage first reads
	// its commit: the edit is still made from, and checked against, the commit
	// read, and the base check before the pull request refuses to open it.
	src := &advancingSource{fakePRGitHub: h.gh, files: map[string]string{"apps/web.yaml": sharedDoc}}
	now := h.clock
	stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: src, Resolver: h.gh, Store: h.store, Limits: h.limits, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	// The first ResolveBranch is the stage's own check of the repository.
	src.asked = 0
	first := stage.Run(context.Background(), PRStageInput{Plan: plan, Containers: h.containers, Kubernetes: h.kube})
	if len(h.gh.pulls(testRepo)) != 0 {
		t.Fatal("a pull request was opened from a commit that was not the branch's")
	}
	if u := onlyUnit(t, first); u.Status != PRStatusDeferred || u.Reason != ReasonBaseMoved {
		t.Fatalf("first cycle: %s/%s (%s), want the base check to have refused the pull request", u.Status, u.Reason, u.Detail)
	}

	// The next cycle reads the shared document and refuses it.
	res := h.run(plan)
	if len(h.gh.pulls(testRepo)) != 0 {
		t.Fatalf("a pull request was made for a container two mappings share: %+v", res.Units)
	}
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusManual, ReasonMappingConflict)
	}
}
