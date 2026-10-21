package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

const kubeWorkload = "deployment/shop/web/app"

// kubernetesPRPlan is an update candidate of a Kubernetes container with a
// pull request opened for it, and the chains the plan found.
func kubernetesPRPlan() remediation.Plan {
	const ref = "docker.io/library/nginx:1.25.3"
	item := remediation.Item{
		Key: ref + "|e", Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonAdopted, Kind: remediation.TagPinned,
		Services:  []remediation.ServiceRef{{Workload: kubeWorkload}},
		Current:   remediation.ImageState{Ref: ref, Tag: "1.25.3"},
		Candidate: &remediation.ImageState{Ref: "docker.io/library/nginx:1.25.5", Tag: "1.25.5"},
		Declared:  []remediation.DeclaredInstance{{Workload: kubeWorkload, Ref: "nginx:1.25.3", PullPolicy: "IfNotPresent"}},
		Management: []remediation.WorkloadChains{{Workload: kubeWorkload, Chains: [][]remediation.ChainOwner{{
			{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceDeployment, Name: "web", Scope: "shop"},
			{Kind: remediation.OwnerArgoCD, Name: "web-app", Confidence: remediation.ConfidenceClaimed},
		}}}},
	}
	unit := remediation.PRUnit{
		Kind: "kubernetes", Key: "k", Repo: "ex/deploy", BaseBranch: "main", Path: "apps/web.yaml",
		Services: []string{kubeWorkload}, Locations: []string{kubeWorkload}, Workloads: []string{kubeWorkload},
		Current: ref, CandidateTag: "1.25.5", CandidateDigest: "sha256:ee", Status: remediation.PRStatusCreated,
		Number: 4, URL: "https://github.com/ex/deploy/pull/4", State: remediation.PRStateOpen,
		UpdateKey: strings.Repeat("a", 64), AttemptKey: strings.Repeat("b", 64),
	}
	return remediation.Plan{
		Version: 1, GeneratedAt: time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC),
		Items: []remediation.Item{item}, PullRequests: []remediation.PRUnit{unit},
	}
}

// A Kubernetes pull request is one entry with the file, the pull request and
// the management chains; the update candidate it stands for is not listed a
// second time.
func TestSlackPlan_KubernetesPullRequest(t *testing.T) {
	p := kubernetesPRPlan()
	v := buildPlanView(&PlanInfo{Plan: &p, Changed: true, SlackChanged: true}, enMessages, planOpts{})
	if len(v.groups) != 1 {
		t.Fatalf("groups = %d, want one image section", len(v.groups))
	}
	text := strings.Join(v.groups[0].lines, "\n")
	for _, want := range []string{"File to change: apps/web.yaml in ex/deploy", "Pull request:", "#4", "Managed by (from markers): deployment shop/web → Argo CD app web-app"} {
		if !strings.Contains(text, want) {
			t.Errorf("the entry lacks %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "Update candidate"); n != 0 {
		t.Errorf("the update candidate is listed apart from its pull request (%d)\n%s", n, text)
	}
	if !strings.Contains(v.summary, "1 created") {
		t.Errorf("summary = %q", v.summary)
	}
}

func TestWebhook_KubernetesPullRequest(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := kubernetesPRPlan()
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	units := rem["pull_requests"].([]any)
	if len(units) != 1 {
		t.Fatalf("pull_requests = %v", units)
	}
	u := units[0].(map[string]any)
	if u["kind"] != "kubernetes" || u["path"] != "apps/web.yaml" || u["number"] != float64(4) {
		t.Errorf("unit = %v", u)
	}
	if ws := u["workloads"].([]any); len(ws) != 1 || ws[0] != kubeWorkload {
		t.Errorf("workloads = %v", ws)
	}
	items := rem["items"].([]any)
	if m := items[0].(map[string]any)["management"].([]any); len(m) != 1 {
		t.Errorf("item management = %v", m)
	}
}

func TestSlackPlan_KubernetesReasonsHaveText(t *testing.T) {
	for _, code := range []string{"instances_missing", "mixed_references", "kubernetes_set_not_adopted", "source_mismatch", "manifest_template", "image_updater_file", "work_namespace_not_configured", "declared_ref_mismatch"} {
		for _, lang := range []Language{LanguageEN, LanguageJA} {
			if got := planReasonText(lang, code); got == code {
				t.Errorf("%s has no %s text", code, lang)
			}
		}
	}
}
