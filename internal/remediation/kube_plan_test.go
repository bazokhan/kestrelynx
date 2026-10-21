package remediation

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestSameReference(t *testing.T) {
	d := "sha256:" + hex64('a')
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"nginx:1.26", "docker.io/library/nginx:1.26", true},
		{"nginx", "docker.io/library/nginx:latest", true},
		{"docker.io/library/nginx", "index.docker.io/library/nginx:latest", true},
		{"ghcr.io/org/app:1.2.3", "ghcr.io/org/app:1.2.3", true},
		{"org/app:v1", "docker.io/org/app:v1", true},
		{"nginx:1.26", "docker.io/library/nginx:1.25.3", false},
		{"nginx:mainline", "docker.io/library/nginx:1.25.4", false},
		{"nginx:1.26", "ghcr.io/library/nginx:1.26", false},
		{"nginx:1.26", "docker.io/library/nginx", false},
		{"nginx@" + d, "docker.io/library/nginx@" + d, true},
		{"nginx:1.26@" + d, "docker.io/library/nginx:1.26@" + d, true},
		{"nginx:1.26@" + d, "docker.io/library/nginx:1.26", false},
		{"nginx@sha256:" + hex64('b'), "docker.io/library/nginx@" + d, false},
		{"", "nginx", false},
		{"nginx", "", false},
	} {
		if got := sameReference(tc.a, tc.b); got != tc.want {
			t.Errorf("sameReference(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDeclaredCheck(t *testing.T) {
	run := "docker.io/library/nginx:1.26"
	if _, _, ok := declaredCheck(nil, run); !ok {
		t.Error("no declarations (Docker) must pass")
	}
	ok := []DeclaredInstance{{Workload: "deployment/shop/web/app", Ref: "nginx:1.26"}, {Workload: "deployment/shop/api/app", Ref: "docker.io/library/nginx:1.26"}}
	if _, _, pass := declaredCheck(ok, run); !pass {
		t.Error("matching declarations rejected")
	}
	reason, detail, pass := declaredCheck(append(ok, DeclaredInstance{Workload: "deployment/shop/old/app", Ref: "nginx:1.25"}), run)
	if pass || reason != ReasonDeclaredRefMismatch || !strings.Contains(detail, "deployment/shop/old/app") || !strings.Contains(detail, "nginx:1.25") {
		t.Errorf("mismatch: %q %q %v", reason, detail, pass)
	}
	reason, detail, pass = declaredCheck([]DeclaredInstance{{Workload: "deployment/shop/web/app"}}, run)
	if pass || reason != ReasonDeclaredRefUnavailable || !strings.Contains(detail, "deployment/shop/web/app") {
		t.Errorf("missing: %q %q %v", reason, detail, pass)
	}
}

func TestEffectivePullPolicy(t *testing.T) {
	latest, minor := ParseImageRef("web"), ParseImageRef("web:1.26")
	for _, tc := range []struct {
		declared string
		ref      ImageRef
		want     string
	}{
		{"Always", minor, "Always"},
		{"IfNotPresent", latest, "IfNotPresent"},
		{"Never", minor, "Never"},
		{"", latest, "Always"},
		{"", ParseImageRef("web:latest"), "Always"},
		{"", minor, "IfNotPresent"},
		{"Sometimes", minor, ""},
	} {
		if got := effectivePullPolicy(tc.declared, tc.ref); got != tc.want {
			t.Errorf("effectivePullPolicy(%q, %s) = %q, want %q", tc.declared, tc.ref.Raw, got, tc.want)
		}
	}
}

func TestPullAdviceGroupsByEffectivePolicy(t *testing.T) {
	got := pullAdvice([]DeclaredInstance{
		{Workload: "statefulset/shop/db/web", PullPolicy: "Never"},
		{Workload: "deployment/shop/b/app", PullPolicy: "IfNotPresent"},
		{Workload: "deployment/shop/a/app", PullPolicy: "IfNotPresent"},
		{Workload: "deployment/shop/a/app", PullPolicy: "IfNotPresent"},
		{Workload: "deployment/shop/c/app", PullPolicy: "Always"},
		{Workload: "deployment/shop/d/app", PullPolicy: "bogus"},
	}, ParseImageRef("web:1.26"))
	want := []PullAdvice{
		{Guidance: GuidanceRestart, Policy: "Always", Workloads: []string{"deployment/shop/c/app"}},
		{Guidance: GuidanceChangeTag, Policy: "IfNotPresent", Workloads: []string{"deployment/shop/a/app", "deployment/shop/b/app"}},
		{Guidance: GuidanceImportToNode, Policy: "Never", Workloads: []string{"statefulset/shop/db/web"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("advice = %+v, want %+v", got, want)
	}
	if got := pullAdvice(nil, ParseImageRef("web:1.26")); got != nil {
		t.Errorf("advice without declarations = %+v, want none", got)
	}
}

func kubeInput(ref string, h byte, declared ...DeclaredInstance) ImageInput {
	in := input(ref, h, prepared, fixedA())
	in.Services = nil
	for _, d := range declared {
		in.Services = append(in.Services, ServiceRef{Workload: d.Workload})
	}
	in.Declared = declared
	return in
}

// A Kubernetes floating tag that now points at other content is a pull_again
// item whose guidance follows the pull policy; the comparison itself is the
// one Docker gets.
func TestPlanKubernetesFloatingTagGuidance(t *testing.T) {
	e := newEnv()
	e.reg.res["docker.io/library/nginx:1.26"] = resolution('b', 'c')
	e.candidateScan("docker.io/library/nginx:1.26", nil, pkgs("libc", "2"))

	in := kubeInput("docker.io/library/nginx:1.26", 'a',
		DeclaredInstance{Workload: "deployment/shop/ifnp/app", Ref: "nginx:1.26", PullPolicy: "IfNotPresent"},
		DeclaredInstance{Workload: "statefulset/shop/never/web", Ref: "nginx:1.26", PullPolicy: "Never"},
		DeclaredInstance{Workload: "deployment/shop/always/app", Ref: "docker.io/library/nginx:1.26", PullPolicy: "Always"})
	in.Management = []WorkloadChains{{Workload: "deployment/shop/ifnp/app", Chains: [][]ChainOwner{{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "ifnp", Scope: "shop"}}}}}

	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	it := item(t, plan, 0)
	if it.Category != CategoryPullAgain || it.Kind != TagFloating {
		t.Fatalf("item = %s %s (%s: %s)", it.Category, it.Kind, it.Reason, it.Detail)
	}
	var policies []string
	for _, a := range it.Pull {
		policies = append(policies, a.Policy+"="+string(a.Guidance))
	}
	if want := "Always=restart_pulls IfNotPresent=change_tag_or_digest Never=import_to_node"; strings.Join(policies, " ") != want {
		t.Errorf("guidance = %v, want %s", policies, want)
	}
	if len(it.Declared) != 3 || len(it.Management) != 1 || it.Management[0].Workload != "deployment/shop/ifnp/app" {
		t.Errorf("declared = %+v, management = %+v", it.Declared, it.Management)
	}
	if len(it.Services) != 3 || it.Services[0].Workload == "" || it.Services[0].Project != "" {
		t.Errorf("services = %+v", it.Services)
	}
}

// A pinned tag gets no pull guidance: the update changes the reference.
func TestPlanKubernetesPinnedTagHasNoPullGuidance(t *testing.T) {
	e := newEnv()
	e.reg.tags["docker.io/library/nginx"] = registry.TagList{Tags: []string{"1.25.4", "1.25.5"}, Pages: 1}
	e.reg.res["docker.io/library/nginx:1.25.5"] = resolution('b', 'c')
	e.candidateScan("docker.io/library/nginx:1.25.5", nil, pkgs("libc", "2"))
	in := kubeInput("docker.io/library/nginx:1.25.4", 'a', DeclaredInstance{Workload: "deployment/shop/web/app", Ref: "nginx:1.25.4", PullPolicy: "IfNotPresent"})
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	it := item(t, plan, 0)
	if it.Category != CategoryPRCandidate || it.Pull != nil {
		t.Errorf("item = %s, pull = %+v; want an update candidate without pull guidance", it.Category, it.Pull)
	}
}

// When the spec and the running reference disagree, no registry request or
// scan is made for the item and it is not comparable; a missing spec is the
// same, and neither is filled in from the running reference.
func TestPlanKubernetesDeclaredRefProblemsAreNotComparable(t *testing.T) {
	for name, tc := range map[string]struct {
		declared DeclaredInstance
		reason   Reason
	}{
		"other name of the same content": {DeclaredInstance{Workload: "deployment/shop/aliased/app", Ref: "nginx:mainline", PullPolicy: "Never"}, ReasonDeclaredRefMismatch},
		"other tag":                      {DeclaredInstance{Workload: "deployment/shop/web/app", Ref: "nginx:1.25.3", PullPolicy: "Always"}, ReasonDeclaredRefMismatch},
		"spec not read":                  {DeclaredInstance{Workload: "deployment/shop/web/app"}, ReasonDeclaredRefUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv()
			e.reg.res["docker.io/library/nginx:1.26"] = resolution('b', 'c')
			e.candidateScan("docker.io/library/nginx:1.26", nil, pkgs("libc", "2"))
			in := kubeInput("docker.io/library/nginx:1.26", 'a', tc.declared)
			plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
			it := item(t, plan, 0)
			if it.Category != CategoryNotComparable || it.Reason != tc.reason {
				t.Errorf("item = %s/%s (%s), want not_comparable/%s", it.Category, it.Reason, it.Detail, tc.reason)
			}
			if it.Candidate != nil || it.Pull != nil || it.Comparison != nil {
				t.Errorf("candidate = %+v, pull = %+v, comparison = %+v; want none", it.Candidate, it.Pull, it.Comparison)
			}
			if len(e.scn.calls) != 0 || len(e.reg.resolveCnt) != 0 {
				t.Errorf("scans = %d, registry resolves = %d, want none", len(e.scn.calls), len(e.reg.resolveCnt))
			}
		})
	}
}

// One workload of several that disagrees stops the image, whatever the others
// say.
func TestPlanKubernetesOneDisagreeingWorkloadStopsTheImage(t *testing.T) {
	e := newEnv()
	e.reg.res["docker.io/library/nginx:1.26"] = resolution('b', 'c')
	e.candidateScan("docker.io/library/nginx:1.26", nil, pkgs("libc", "2"))
	in := kubeInput("docker.io/library/nginx:1.26", 'a',
		DeclaredInstance{Workload: "deployment/shop/web/app", Ref: "nginx:1.26", PullPolicy: "IfNotPresent"},
		DeclaredInstance{Workload: "deployment/shop/aliased/app", Ref: "nginx:mainline", PullPolicy: "Never"})
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	if it := item(t, plan, 0); it.Category != CategoryNotComparable || it.Reason != ReasonDeclaredRefMismatch {
		t.Errorf("item = %s/%s, want not_comparable/declared_ref_mismatch", it.Category, it.Reason)
	}
}

// Docker inputs carry no declarations and plan as they always did.
func TestPlanWithoutDeclarationsIsUnchanged(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
	it := item(t, plan, 0)
	if it.Category != CategoryPullAgain || it.Declared != nil || it.Pull != nil || it.Management != nil {
		t.Errorf("item = %+v", it)
	}
}

func TestFingerprintKubernetesParts(t *testing.T) {
	base := func() Plan {
		it := Item{Key: "k", Category: CategoryPullAgain, Current: ImageState{Ref: "nginx:1.26"},
			Services: []ServiceRef{{Workload: "deployment/shop/b/app"}, {Workload: "deployment/shop/a/app"}}}
		return Plan{Items: []Item{it}}
	}
	plain := Fingerprint(base())
	withPull := base()
	withPull.Items[0].Pull = []PullAdvice{{Guidance: GuidanceChangeTag, Policy: "IfNotPresent", Workloads: []string{"deployment/shop/a/app"}}}
	if Fingerprint(withPull) == plain {
		t.Error("pull guidance is not part of the fingerprint")
	}
	chains := base()
	chains.Items[0].Management = []WorkloadChains{{Workload: "deployment/shop/a/app", Chains: [][]ChainOwner{{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "a", Scope: "shop"}, {Kind: OwnerHelm, Name: "web", Scope: "shop"}}}}}
	if Fingerprint(chains) == plain {
		t.Error("management chains are not part of the fingerprint")
	}
	// The order of services does not change it.
	swapped := base()
	s := swapped.Items[0].Services
	s[0], s[1] = s[1], s[0]
	if Fingerprint(swapped) != plain {
		t.Error("the order of services changed the fingerprint")
	}
}

func TestNewWorkloadChains(t *testing.T) {
	chains := []OwnerChain{
		{Owners: []DeployOwner{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web", Scope: "shop"}, {Kind: OwnerHelm, Name: "web", Scope: "shop", Attribution: Attribution{Confidence: ConfidenceClaimed}}}},
		{Owners: []DeployOwner{{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web", Scope: "shop"}, {Kind: OwnerArgoCD, Name: "web-app", Attribution: Attribution{Confidence: ConfidenceClaimed}}}},
	}
	got := NewWorkloadChains("deployment/shop/web/app", chains)
	if !got.Conflicting || len(got.Chains) != 2 || got.Chains[1][1].Kind != OwnerArgoCD || got.Chains[0][1].Confidence != ConfidenceClaimed {
		t.Errorf("chains = %+v", got)
	}
	if one := NewWorkloadChains("w", chains[:1]); one.Conflicting {
		t.Error("a single chain reported as conflicting")
	}
	same := NewWorkloadChains("deployment/shop/web/app", []OwnerChain{chains[1], chains[0]})
	if same.Key() != got.Key() {
		t.Error("the order of chains changed the key")
	}
}

// The language-package part names Kubernetes workloads by their key, and only
// the mapped workload's findings reach a dependency unit.
func TestLanguagePlanKubernetesWorkloadCandidate(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "backend")
	const mapped, other = "deployment/shop/api/app", "deployment/shop/other/app"
	inputs := []ImageInput{
		{
			Scan:     configScan("api:1", 'a', []scanner.Finding{nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")}, nil),
			Services: []ServiceRef{{Workload: mapped}},
		},
		{
			Scan:     configScan("other:1", 'b', []scanner.Finding{nodeFinding("CVE-9", "express", "4.18.2", "4.19.2")}, nil),
			Services: []ServiceRef{{Workload: other}},
		},
	}
	plan := langPlan(t, gh, []DependencyMapping{{Workload: mapped, Repository: "ex/app", BaseBranch: "main", Directory: "backend"}}, nil, inputs...)
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("language items = %d, want 1", len(plan.LanguageItems))
	}
	it := plan.LanguageItems[0]
	if it.Category != CategoryDependencyUpdateCandidate || len(it.Workloads) != 1 || it.Workloads[0] != mapped {
		t.Errorf("item = %s %v (%s)", it.Category, it.Workloads, it.Detail)
	}
	if len(it.Packages) != 1 || it.Packages[0].Name != "lodash" {
		t.Errorf("packages = %+v, want lodash only: express belongs to a workload without a mapping", it.Packages)
	}
	if it.UpdateExecuted {
		t.Error("a plan must not say an update ran")
	}
}

// A declaration problem is reported for references that would otherwise be
// excluded, such as one pinned by digest.
func TestPlanKubernetesDeclaredProblemBeatsExclusion(t *testing.T) {
	d := "docker.io/library/nginx@sha256:" + hex64('d')
	for name, decl := range map[string]DeclaredInstance{
		"mismatch":    {Workload: "deployment/shop/web/app", Ref: "nginx:1.26"},
		"unavailable": {Workload: "deployment/shop/web/app"},
	} {
		in := kubeInput(d, 'a', decl)
		plan := newEnv().planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
		want := ReasonDeclaredRefMismatch
		if name == "unavailable" {
			want = ReasonDeclaredRefUnavailable
		}
		if it := item(t, plan, 0); it.Category != CategoryNotComparable || it.Reason != want {
			t.Errorf("%s: %s/%s, want not_comparable/%s", name, it.Category, it.Reason, want)
		}
	}
	// With no declaration problem the usual exclusion stands, as in Docker.
	in := kubeInput(d, 'a', DeclaredInstance{Workload: "deployment/shop/web/app", Ref: d})
	plan := newEnv().planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
	if it := item(t, plan, 0); it.Category != CategoryExcluded {
		t.Errorf("matching declaration: %s, want excluded", it.Category)
	}
	plan = newEnv().planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input(d, 'a', prepared, fixedA())})
	if it := item(t, plan, 0); it.Category != CategoryExcluded {
		t.Errorf("Docker: %s, want excluded", it.Category)
	}
}
