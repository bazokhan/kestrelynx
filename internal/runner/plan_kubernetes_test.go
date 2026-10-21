package runner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/kubernetes"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// apiServer serves lists recorded from a K3s cluster (see the adapter's
// tests) over TLS and keeps every request it gets.
type apiServer struct {
	mu       sync.Mutex
	requests []string // "METHOD path"
	lists    map[string][]byte
	srv      *httptest.Server
}

// recorded maps the namespaced list paths of the shop namespace to the
// recorded files.
var recorded = map[string]string{
	"/api/v1/nodes":                              "nodes",
	"/api/v1/namespaces/shop/pods":               "pods",
	"/apis/apps/v1/namespaces/shop/replicasets":  "replicasets",
	"/apis/apps/v1/namespaces/shop/deployments":  "deployments",
	"/apis/apps/v1/namespaces/shop/statefulsets": "statefulsets",
	"/apis/apps/v1/namespaces/shop/daemonsets":   "daemonsets",
	"/apis/batch/v1/namespaces/shop/jobs":        "jobs",
	"/apis/batch/v1/namespaces/shop/cronjobs":    "cronjobs",
}

// newAPIServer starts the server; dropPods names Pods that are left out of the
// pod list.
func newAPIServer(t *testing.T, dropPods ...string) *apiServer {
	t.Helper()
	a := &apiServer{lists: map[string][]byte{}}
	for path, name := range recorded {
		b, err := os.ReadFile(filepath.Join("..", "kubernetes", "testdata", "k3s", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if name == "pods" && len(dropPods) > 0 {
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			var kept []any
			for _, it := range doc["items"].([]any) {
				name := it.(map[string]any)["metadata"].(map[string]any)["name"].(string)
				drop := false
				for _, d := range dropPods {
					drop = drop || strings.HasPrefix(name, d)
				}
				if !drop {
					kept = append(kept, it)
				}
			}
			doc["items"] = kept
			if b, err = json.Marshal(doc); err != nil {
				t.Fatal(err)
			}
		}
		a.lists[path] = b
	}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.requests = append(a.requests, r.Method+" "+r.URL.Path)
		a.mu.Unlock()
		b, ok := a.lists[r.URL.Path]
		if !ok || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiServer) client(t *testing.T) *kubernetes.Client {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(token, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.srv.Certificate().Raw})
	if _, err := x509.ParseCertificate(a.srv.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := kubernetes.New(kubernetes.Options{APIServer: a.srv.URL, TokenFile: token, CAFile: ca, Namespaces: []string{"shop"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// kubeScanner scans every running image as an image with one fixed OS finding
// and one fixed npm finding; the candidates come back clean.
type kubeScanner struct{ *planScanner }

func (k *kubeScanner) Scan(ctx context.Context, t scanner.ScanTarget) scanner.ImageScan {
	// With Kubernetes every scan is of a registry digest; the candidates are
	// the ones the fake registry resolves to its manifest digest.
	npmPackages := func(ver string) scanner.ResultPackages {
		return scanner.ResultPackages{
			Target: "Node.js", Class: scanner.ClassLang, Type: "node-pkg",
			Packages: []scanner.Package{{Name: "lodash", Version: ver}},
		}
	}
	if t.Subject.Key.Digest.Hex == hex64('b') {
		return scanner.ImageScan{
			Image: t.Subject.Ref, Subject: t.Subject, ScannedKey: t.Subject.Key, Pinned: true,
			Source: scanner.SourceRemote, Platform: linuxAmd64, OSFamily: "debian",
			Packages: append(osPackages("2"), npmPackages("4.17.21")),
		}
	}
	npm := scanner.Finding{
		Class: scanner.ClassLang, Type: "node-pkg", Target: "Node.js", Package: "lodash",
		InstalledVer: "4.17.20", FixedVer: "4.17.21", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-NPM",
	}
	return scanner.ImageScan{
		Image: t.Subject.Ref, Subject: t.Subject, ScannedKey: t.Subject.Key, Pinned: t.Subject.Resolved,
		Source: t.Source, Platform: linuxAmd64, OSFamily: "debian",
		Findings: []scanner.Finding{osFinding("CVE-OS"), npm}, Packages: append(osPackages("1"), npmPackages("4.17.20")),
	}
}

// readOnlyGitHub serves one npm project and records every call; it has no
// write method, as the interface the plan reads GitHub through has none.
type readOnlyGitHub struct {
	mu    sync.Mutex
	calls []string
}

const (
	npmPackageJSON = `{"name":"backend","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}}`
	npmLock        = `{"name":"backend","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"backend","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz","integrity":"sha512-e"}}}`
)

func (g *readOnlyGitHub) note(c string) {
	g.mu.Lock()
	g.calls = append(g.calls, c)
	g.mu.Unlock()
}

func (g *readOnlyGitHub) ResolveBranch(_ context.Context, repo, branch string) (string, error) {
	g.note("branch " + repo + "@" + branch)
	return strings.Repeat("c", 40), nil
}

func (g *readOnlyGitHub) ListDirectory(_ context.Context, repo, _, dir string) ([]github.Entry, error) {
	g.note("list " + repo + "/" + dir)
	return []github.Entry{
		{Name: "package.json", Path: "backend/package.json", Type: github.EntryFile, SHA: strings.Repeat("1", 40)},
		{Name: "package-lock.json", Path: "backend/package-lock.json", Type: github.EntryFile, SHA: strings.Repeat("2", 40)},
	}, nil
}

func (g *readOnlyGitHub) ReadFile(_ context.Context, repo, _, path string) (github.File, error) {
	g.note("read " + repo + "/" + path)
	switch path {
	case "backend/package.json":
		return github.File{Path: path, SHA: strings.Repeat("1", 40), Content: []byte(npmPackageJSON)}, nil
	case "backend/package-lock.json":
		return github.File{Path: path, SHA: strings.Repeat("2", 40), Content: []byte(npmLock)}, nil
	}
	return github.File{}, github.ErrNotFound
}

// kubeRegistry offers 1.25.5 as the newer patch of the series and a floating
// tag that resolves to content other than what runs.
type kubeRegistry struct{}

func (kubeRegistry) ListTagsUpTo(context.Context, string, int) (registry.TagList, error) {
	return registry.TagList{Tags: []string{"1.25.4", "1.25.5"}, Pages: 1}, nil
}

func (kubeRegistry) Resolve(context.Context, string, string, inventory.Platform) (registry.Resolution, error) {
	return registry.Resolution{
		TopDigest: "sha256:" + hex64('0'), ManifestDigest: "sha256:" + hex64('b'), ConfigDigest: "sha256:" + hex64('c'),
		PlatformVerified: true,
	}, nil
}

type kubeHarness struct {
	r     Runner
	notif *fakeNotifier
	api   *apiServer
	gh    *readOnlyGitHub
}

func newKubeHarness(t *testing.T, dropPods ...string) *kubeHarness {
	t.Helper()
	api := newAPIServer(t, dropPods...)
	gh := &readOnlyGitHub{}
	scn := &kubeScanner{&planScanner{verifyOK: true}}
	notif := &fakeNotifier{}
	r := Runner{
		Lister:        api.client(t),
		Scanner:       &fakeScanner{},
		Notifier:      notif,
		Source:        scanner.SourceRemote,
		FullReportDay: NoFullReport,
		Now:           clock,
		Environment:   inventory.Environment{Name: "k3s", Kind: inventory.KindKubernetes},
		Plan: &PlanConfig{
			Scanner:             scn,
			NewRegistry:         func(*registry.Budget) remediation.Registry { return kubeRegistry{} },
			Limits:              remediation.Limits{MaxCandidateScans: 10, MaxBaselineRescans: 10, MaxTagPages: 5},
			MaxRegistryRequests: 100,
			NewGitHub:           func() remediation.GitHubReader { return gh },
			Dependencies: []remediation.DependencyMapping{{
				Workload: "deployment/shop/pinned/app", Repository: "example/app", BaseBranch: "main", Directory: "backend",
			}},
		},
	}
	return &kubeHarness{r: r, notif: notif, api: api, gh: gh}
}

func (h *kubeHarness) run(t *testing.T) *remediation.Plan {
	t.Helper()
	if err := h.r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil {
		t.Fatalf("Message.Plan = %+v, want a plan", p)
	}
	return p.Plan
}

func itemOf(t *testing.T, plan *remediation.Plan, ref string) remediation.Item {
	t.Helper()
	for _, it := range plan.Items {
		if it.Current.Ref == ref {
			return it
		}
	}
	t.Fatalf("no plan item for %s", ref)
	return remediation.Item{}
}

// A whole K1 cycle over a recorded cluster: the plan compares the distributed
// images, guides the floating tag by pull policy, shows the management chains,
// offers language packages as candidates, and in doing so sends the cluster
// nothing but GET requests and writes nothing to GitHub.
func TestPlanKubernetes_WholeCycle(t *testing.T) {
	h := newKubeHarness(t, "aliased")
	plan := h.run(t)

	pinned := itemOf(t, plan, "docker.io/library/nginx:1.25.4")
	if pinned.Category != remediation.CategoryPRCandidate || pinned.Candidate == nil || pinned.Candidate.Tag != "1.25.5" {
		t.Errorf("pinned image = %s %+v (%s: %s), want an update candidate 1.25.5", pinned.Category, pinned.Candidate, pinned.Reason, pinned.Detail)
	}
	var keys []string
	for _, s := range pinned.Services {
		if s.Project != "" || s.Service != "" || s.Container != "" {
			t.Errorf("service %+v: a Kubernetes reference carries only the workload key", s)
		}
		keys = append(keys, s.Workload)
	}
	if got := strings.Join(keys, " "); got != "deployment/shop/pinned/app deployment/shop/web-demo/demo" {
		t.Errorf("workloads of the pinned image = %q (the two replicas are one workload)", got)
	}
	chainKinds := map[string]string{}
	for _, m := range pinned.Management {
		var layers []string
		for _, o := range m.Chains[0] {
			layers = append(layers, string(o.Kind))
		}
		chainKinds[m.Workload] = strings.Join(layers, ">")
	}
	if chainKinds["deployment/shop/pinned/app"] != "kubernetes>argocd" || chainKinds["deployment/shop/web-demo/demo"] != "kubernetes>helm" {
		t.Errorf("chains = %v", chainKinds)
	}

	floating := itemOf(t, plan, "docker.io/library/nginx:1.26")
	if floating.Category != remediation.CategoryPullAgain || floating.Kind != remediation.TagFloating {
		t.Fatalf("floating image = %s (%s: %s), want pull_again", floating.Category, floating.Reason, floating.Detail)
	}
	guidance := map[string]remediation.PullGuidance{}
	for _, a := range floating.Pull {
		guidance[a.Policy] = a.Guidance
	}
	if len(guidance) != 2 || guidance["IfNotPresent"] != remediation.GuidanceChangeTag || guidance["Never"] != remediation.GuidanceImportToNode {
		t.Errorf("pull guidance = %v", guidance)
	}

	if len(plan.LanguageItems) != 1 {
		t.Fatalf("language items = %d, want 1", len(plan.LanguageItems))
	}
	if li := plan.LanguageItems[0]; li.Category != remediation.CategoryDependencyUpdateCandidate || li.Workloads[0] != "deployment/shop/pinned/app" || li.UpdateExecuted {
		t.Errorf("language item = %s %v (%s)", li.Category, li.Workloads, li.Detail)
	}

	// Nothing but reads: Kubernetes GETs of the recorded lists, one each, and
	// only read calls to GitHub, with no pull request stage configured.
	for _, req := range h.api.requests {
		if !strings.HasPrefix(req, "GET ") {
			t.Errorf("Kubernetes request %q is not a GET", req)
		}
		if _, ok := recorded[strings.TrimPrefix(req, "GET ")]; !ok {
			t.Errorf("Kubernetes request %q is outside the read-only listing", req)
		}
	}
	if len(h.api.requests) != len(recorded) {
		t.Errorf("Kubernetes requests = %d, want one listing of %d lists: %v", len(h.api.requests), len(recorded), h.api.requests)
	}
	if h.r.Plan.PullRequests != nil || len(plan.PullRequests) != 0 || len(plan.PRProblems) != 0 || len(plan.PROperations) != 0 {
		t.Errorf("a pull request stage ran: %+v", plan.PullRequests)
	}
	for _, c := range h.gh.calls {
		if !strings.HasPrefix(c, "branch ") && !strings.HasPrefix(c, "list ") && !strings.HasPrefix(c, "read ") {
			t.Errorf("GitHub call %q is not a read", c)
		}
	}
	if len(h.gh.calls) == 0 {
		t.Error("the dependency files were not read")
	}

	// The notifications: the Slack plan message shows the guidance and the
	// chains, the webhook payload all of it.
	var slack strings.Builder
	for _, m := range notify.BuildPlanMessages(h.notif.msg, notify.LanguageEN) {
		slack.WriteString(m.Text + "\n")
		for _, b := range m.Blocks {
			slack.WriteString(b.Text + "\n")
		}
	}
	for _, want := range []string{"Pull policy", "IfNotPresent", "Never", "Managed by", "Argo CD app pinned-app", "Helm release web (shop)", "deployment/shop/pinned/app"} {
		if !strings.Contains(slack.String(), want) {
			t.Errorf("the Slack plan message lacks %q:\n%s", want, slack.String())
		}
	}
	payload, err := json.Marshal(notify.BuildWebhookPayloadWithPlan(h.notif.msg.Report, h.notif.msg.Diff, h.notif.msg.Plan))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Remediation struct {
			Items []struct {
				Category   string                                       `json:"category"`
				Declared   []struct{ Workload, Ref, PullPolicy string } `json:"declared"`
				Pull       []struct{ Guidance, Policy string }          `json:"pull"`
				Management []struct {
					Workload string `json:"workload"`
					Chains   [][]struct {
						Kind, Name, Scope, Confidence string
					} `json:"chains"`
				} `json:"management"`
			} `json:"items"`
		} `json:"remediation"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	var sawPull, sawChain, sawDeclared bool
	for _, it := range doc.Remediation.Items {
		sawPull = sawPull || (it.Category == "pull_again" && len(it.Pull) == 2)
		sawDeclared = sawDeclared || len(it.Declared) > 0
		for _, m := range it.Management {
			for _, c := range m.Chains {
				sawChain = sawChain || (len(c) == 2 && c[1].Kind == "helm" && c[1].Name == "web" && c[1].Confidence == "claimed")
			}
		}
	}
	if !sawPull || !sawChain || !sawDeclared {
		t.Errorf("webhook payload: pull guidance %v, helm chain %v, declared %v:\n%s", sawPull, sawChain, sawDeclared, payload)
	}
}

// With the container that runs under another name of the same image in the
// cluster, the image it shares with the others is not compared: no advice or
// candidate rests on a reference that is not what the spec says.
func TestPlanKubernetes_DeclaredMismatchStopsTheImage(t *testing.T) {
	h := newKubeHarness(t)
	plan := h.run(t)

	it := itemOf(t, plan, "docker.io/library/nginx:1.25.4")
	if it.Category != remediation.CategoryNotComparable || it.Reason != remediation.ReasonDeclaredRefMismatch {
		t.Fatalf("image = %s/%s (%s), want not_comparable/declared_ref_mismatch", it.Category, it.Reason, it.Detail)
	}
	if !strings.Contains(it.Detail, "deployment/shop/aliased/app") || !strings.Contains(it.Detail, "nginx:mainline") {
		t.Errorf("detail = %q, want it to name the workload and the spec's reference", it.Detail)
	}
	if it.Candidate != nil || it.Pull != nil {
		t.Errorf("candidate = %+v, pull = %+v; want none", it.Candidate, it.Pull)
	}
	// The same cycle's other image is compared as usual.
	if f := itemOf(t, plan, "docker.io/library/nginx:1.26"); f.Category != remediation.CategoryPullAgain {
		t.Errorf("floating image = %s, want pull_again", f.Category)
	}
}

// Kubernetes lists beyond the containers' are read only when the plan is on.
func TestPlanKubernetes_PlanOffListsOnlyWhatItDid(t *testing.T) {
	h := newKubeHarness(t)
	h.r.Plan = nil
	h.r.Scanner = &fakeScanner{byImage: map[string]scanner.ImageScan{}}
	if err := h.r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, req := range h.api.requests {
		for _, marker := range []string{"deployments", "statefulsets", "daemonsets", "cronjobs"} {
			if strings.HasSuffix(req, "/"+marker) {
				t.Errorf("%s listed with the plan off", marker)
			}
		}
	}
	if h.notif.msg.Plan != nil {
		t.Error("a plan came with the plan off")
	}
}

func kubeContainer(name, workload, running, declared string, digest byte, platform inventory.Platform) inventory.Container {
	c := inventory.Container{
		Name:     "shop/" + name + "/app",
		Workload: inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "shop", Name: workload},
		Image:    inventory.RunningImage{Ref: running, Platform: platform},
		Declared: &inventory.Declared{Ref: declared, PullPolicy: "IfNotPresent"},
	}
	if digest != 0 {
		d, _ := inventory.ParseDigest(inventory.DigestRegistry, "sha256:"+hex64(digest))
		c.Image.Registry = inventory.RegistryRef{Repository: "docker.io/library/nginx", Digest: d}
	}
	return c
}

// The declarations of one running reference are judged together: a problem in
// one container reaches the inputs of every entity that reports the reference,
// whatever its digest or platform, and one whose entity is unresolved.
func TestPlanInputs_DeclaredProblemReachesEveryEntityOfTheReference(t *testing.T) {
	arm := inventory.Platform{OS: "linux", Architecture: "arm64"}
	const ref = "docker.io/library/nginx:1.26"
	containers := []inventory.Container{
		kubeContainer("a-1", "a", ref, "nginx:1.26", 'a', linuxAmd64),
		kubeContainer("a-2", "a", ref, "nginx:1.26", 'e', linuxAmd64), // another digest
		kubeContainer("a-3", "a", ref, "nginx:1.26", 'a', arm),        // another platform
		kubeContainer("a-4", "a", ref, "nginx:1.26", 0, linuxAmd64),   // unresolved entity
		kubeContainer("b-1", "b", ref, "nginx:mainline", 'f', linuxAmd64),
		kubeContainer("c-1", "c", "docker.io/library/redis:7", "redis:7", 'a', linuxAmd64),
	}
	var scans []scanner.ImageScan
	var targets []scanner.ScanTarget
	seen := map[entityRef]bool{}
	for _, c := range containers {
		key, resolved := inventory.EntityKeyOf(c.Image)
		k := entityRef{c.Image.Ref, key}
		if seen[k] {
			continue
		}
		seen[k] = true
		sub := inventory.ImageSubject{Ref: c.Image.Ref, Key: key, Resolved: resolved}
		scans = append(scans, scanner.ImageScan{Image: c.Image.Ref, Subject: sub})
		targets = append(targets, scanner.ScanTarget{Subject: sub})
	}
	inputs := planInputsWith(analyze.Report{}, containers, nil, scans, targets, planConds())
	if len(inputs) != 6 {
		t.Fatalf("inputs = %d, want 6 (five entities of the reference and the redis one)", len(inputs))
	}
	for _, in := range inputs {
		problems := remediation.DeclaredProblems(in.Declared, in.Scan.Subject.Ref)
		if in.Scan.Subject.Ref == ref {
			if len(problems) != 1 || problems[0].Ref != "nginx:mainline" {
				t.Errorf("entity %v of %s: problems = %+v, want the nginx:mainline declaration", in.Scan.Subject.Key, ref, problems)
			}
		} else if len(problems) != 0 || len(in.Declared) != 1 {
			t.Errorf("redis input: declared = %+v, problems = %+v; want its own matching declaration only", in.Declared, problems)
		}
	}
}

// recordingStage is a pull request stage that records its input.
type recordingStage struct{ in *remediation.PRStageInput }

func (s recordingStage) Run(_ context.Context, in remediation.PRStageInput) remediation.PRStageResult {
	*s.in = in
	return remediation.PRStageResult{}
}

// With pull requests on, the stage gets the Kubernetes mappings and the
// cycle's containers, and language updates, which cannot run in work Pods yet,
// are reported as manual rather than started or put off.
func TestPlanKubernetes_PullRequestStageAndManualLanguage(t *testing.T) {
	h := newKubeHarness(t, "aliased")
	var got remediation.PRStageInput
	mappings := []remediation.KubernetesMapping{{Workload: "deployment/shop/pinned/app", Repository: "example/deploy", BaseBranch: "main", Path: "apps/pinned.yaml"}}
	h.r.Plan.PullRequests = &PullRequestConfig{
		NewStage:   func(remediation.CandidateResolver) (PRStage, error) { return recordingStage{&got}, nil },
		Kubernetes: mappings,
	}
	updaterBuilt := false
	h.r.Plan.Language = &LanguageUpdateConfig{
		Unavailable: &LanguageUnavailable{Reason: remediation.ReasonWorkNamespaceNotConfigured, Manual: true, Detail: "no work Pods yet"},
		NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) {
			updaterBuilt = true
			return nil, nil
		},
	}
	plan := h.run(t)

	if len(got.Kubernetes) != 1 || got.Kubernetes[0] != mappings[0] {
		t.Errorf("the stage got Kubernetes mappings %+v", got.Kubernetes)
	}
	if len(got.Containers) == 0 || got.Containers[0].Declared == nil {
		t.Error("the stage got no containers with their declarations")
	}
	if updaterBuilt {
		t.Error("a language updater was built")
	}
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("language items = %d", len(plan.LanguageItems))
	}
	li := plan.LanguageItems[0]
	if li.Category != remediation.CategoryManual || li.Reason != remediation.ReasonWorkNamespaceNotConfigured || li.UpdateExecuted {
		t.Errorf("language item = %s/%s (%s)", li.Category, li.Reason, li.Detail)
	}
}
