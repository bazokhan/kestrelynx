package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// containerdDigests are the repo digests the containerd image store gives any
// image that has a name, a build as well as a pull.
func containerdDigests(name string) []string {
	return []string{name + "@sha256:" + hex64('e')}
}

func localBuildInput(ref string, digests []string, project, service string) ImageInput {
	in := input(ref, 'a', prepared, fixedA())
	in.Scan.RegistryDigests = digests
	in.Services = []ServiceRef{{Project: project, Service: service}}
	return in
}

// withLabels sets the Compose labels of the image's own configuration.
func withLabels(in ImageInput, project, service string) ImageInput {
	in.Scan.ComposeProject, in.Scan.ComposeService = project, service
	return in
}

func TestPlanLocallyBuiltWithContainerdStore(t *testing.T) {
	cases := []struct {
		name    string
		ref     string
		digests []string
		labels  [2]string // project, service on the image
		project string    // the container's
		service string
		local   bool
	}{
		{"built by Compose: labels match the container", "regfis-infra-elasticsearch", containerdDigests("regfis-infra-elasticsearch"), [2]string{"regfis-infra", "elasticsearch"}, "regfis-infra", "elasticsearch", true},
		{"older name form", "shop_web", containerdDigests("shop_web"), [2]string{"shop", "web"}, "shop", "web", true},
		{"explicit latest", "p-s:latest", containerdDigests("p-s"), [2]string{"p", "s"}, "p", "s", true},
		{"labels match but the name is not the default one", "myteam/app:1.2.3", containerdDigests("myteam/app"), [2]string{"p", "s"}, "p", "s", false},
		{"the same with docker.io written out", "docker.io/myteam/app:1.2.3", containerdDigests("docker.io/myteam/app"), [2]string{"p", "s"}, "p", "s", false},
		{"default name with another tag", "p-s:2", containerdDigests("p-s"), [2]string{"p", "s"}, "p", "s", false},
		{"default name under a namespace", "myteam/p-s", containerdDigests("myteam/p-s"), [2]string{"p", "s"}, "p", "s", false},
		{"a name with only part of the default", "p-s2", containerdDigests("p-s2"), [2]string{"p", "s"}, "p", "s", false},
		{"default name written with a registry host", "ghcr.io/p-s:1", containerdDigests("ghcr.io/p-s"), [2]string{"p", "s"}, "p", "s", false},
		{"labels match, registry host with a port", "localhost:5000/app:1", containerdDigests("localhost:5000/app"), [2]string{"p", "s"}, "p", "s", false},
		{"classic store: no digests", "whatever", nil, [2]string{}, "p", "s", true},
		{"pulled nginx has no labels", "nginx:1.25.3", containerdDigests("nginx"), [2]string{}, "p", "web", false},
		{"named like the project and service but nothing says built", "p-web", containerdDigests("p-web"), [2]string{}, "p", "web", false},
		{"nats-streaming for project nats, service streaming", "nats-streaming", containerdDigests("nats-streaming"), [2]string{}, "nats", "streaming", false},
		{"labels of another project (built elsewhere, pulled here)", "example/app:1", containerdDigests("example/app"), [2]string{"ci", "app"}, "p", "app", false},
		{"labels of another service", "example/app:1", containerdDigests("example/app"), [2]string{"p", "other"}, "p", "app", false},
		{"only one label", "example/app:1", containerdDigests("example/app"), [2]string{"p", ""}, "p", "app", false},
		{"no Compose labels on the container", "example/app:1", containerdDigests("example/app"), [2]string{"p", "app"}, "", "", false},
	}
	for _, c := range cases {
		e := newEnv()
		in := withLabels(localBuildInput(c.ref, c.digests, c.project, c.service), c.labels[0], c.labels[1])
		plan := e.planner(t, bigLimits, registry.NewBudget(100)).Plan(context.Background(), []ImageInput{in})
		it := item(t, plan, 0)
		if got := it.Reason == ReasonLocallyBuilt; got != c.local {
			t.Errorf("%s: %s/%s, locally built = %v, want %v", c.name, it.Category, it.Reason, got, c.local)
		}
		if c.local && (e.reg.listCalls != 0 || len(e.reg.resolveCnt) != 0) {
			t.Errorf("%s: the registry was contacted (list %d, resolve %v)", c.name, e.reg.listCalls, e.reg.resolveCnt)
		}
	}
}

// A registry that does not know a name, or refuses it, is no evidence that
// the image was built here.
func TestPlanRegistryAnswersAreNotEvidenceOfALocalBuild(t *testing.T) {
	for name, err := range map[string]error{
		"not found":     registry.ErrNotFound,
		"auth required": registry.ErrAuthRequired,
	} {
		e := newEnv()
		e.reg.resErr["p-web:latest"] = err
		in := localBuildInput("p-web", containerdDigests("p-web"), "p", "web")
		it := item(t, e.planner(t, bigLimits, registry.NewBudget(100)).Plan(context.Background(), []ImageInput{in}), 0)
		if it.Reason == ReasonLocallyBuilt {
			t.Errorf("%s: called locally built on the registry's answer", name)
		}
		if e.reg.resolveCnt["p-web:latest"] != 1 {
			t.Errorf("%s: the registry was asked %d times, want once as for any floating image", name, e.reg.resolveCnt["p-web:latest"])
		}
	}
}

const buildCompose = `services:
  web:
    build: ./web
  both:
    image: ghcr.io/example/both:1.2.3
    build:
      context: .
  pulled:
    image: nginx:1.25.3
  inherited:
    extends:
      service: web
`

func TestPlanLocallyBuiltFromTheComposeMapping(t *testing.T) {
	cm := func(service string) ComposeMapping {
		return ComposeMapping{Workload: "compose/p/" + service, Project: "p", Service: service, Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: service}
	}
	cases := []struct {
		name    string
		ref     string
		service string
		digests []string
		local   bool
	}{
		{"service with build", "something-else:1", "web", containerdDigests("something-else"), true},
		{"image and build both", "ghcr.io/example/both:1.2.3", "both", nil, true},
		{"image and build both, pulled-looking", "ghcr.io/example/both:1.2.3", "both", containerdDigests("ghcr.io/example/both"), true},
		{"service without build keeps looking", "nginx:1.25.3", "pulled", containerdDigests("nginx"), false},
		{"no build in the file beats the naming rule", "p-pulled", "pulled", containerdDigests("p-pulled"), false},
	}
	for _, c := range cases {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "compose.yml", buildCompose)
		in := localBuildInput(c.ref, c.digests, "p", c.service)
		plan := e.plan(t, bigLimits, nil, []ComposeMapping{cm(c.service)}, in)
		it := item(t, plan, 0)
		if got := it.Reason == ReasonLocallyBuilt; got != c.local {
			t.Errorf("%s: %s/%s %s, locally built = %v, want %v", c.name, it.Category, it.Reason, it.Detail, got, c.local)
		}
		if c.local && !strings.Contains(it.Detail, "Compose") {
			t.Errorf("%s: detail = %q", c.name, it.Detail)
		}
	}
}

// A mapped workload whose Compose service cannot be judged is neither looked
// up in a registry nor called built.
func TestPlanMappedButUndeterminableIsNotLookedUp(t *testing.T) {
	cm := func(service string) ComposeMapping {
		return ComposeMapping{Workload: "compose/p/" + service, Project: "p", Service: service, Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: service}
	}
	const file = buildCompose + "  extendsbuild:\n    extends:\n      service: web\n    build: ./x\n"
	for name, tc := range map[string]struct {
		file     string
		service  string
		category Category
		reason   Reason
	}{
		"extends":                    {file, "inherited", CategoryManual, ReasonComposeBuildUndetermined},
		"extends with its own build": {file, "extendsbuild", CategoryExcluded, ReasonLocallyBuilt},
		"service missing from file":  {file, "nosuch", CategoryManual, ReasonComposeBuildUndetermined},
		"file does not parse":        {"services: [", "web", CategoryManual, ReasonComposeBuildUndetermined},
		"file missing in repository": {"", "web", CategoryFailed, ReasonDockerfileFileNotFound},
	} {
		e := newDFEnv()
		if tc.file != "" {
			e.gh.put("ex/app", ".", "compose.yml", tc.file)
		}
		e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4"}, Pages: 1}
		in := localBuildInput("nginx:1.25.3", containerdDigests("nginx"), "p", tc.service)
		plan := e.plan(t, bigLimits, nil, []ComposeMapping{cm(tc.service)}, in)
		it := item(t, plan, 0)
		if it.Category != tc.category || it.Reason != tc.reason {
			t.Errorf("%s: %s/%s %s; want %s/%s", name, it.Category, it.Reason, it.Detail, tc.category, tc.reason)
		}
		if e.reg.listCalls != 0 || len(e.reg.resolveCnt) != 0 {
			t.Errorf("%s: the registry was contacted", name)
		}
	}
}

// A mapped Compose service known to have no build section pulls its image,
// whatever the image's labels say (CI built it under the same project and
// service names and pushed it).
func TestPlanNoBuildInComposeBeatsTheLabels(t *testing.T) {
	cm := ComposeMapping{Workload: "compose/p/pulled", Project: "p", Service: "pulled", Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: "pulled"}
	e := newDFEnv()
	e.gh.put("ex/app", ".", "compose.yml", buildCompose)
	in := withLabels(localBuildInput("p-pulled", containerdDigests("p-pulled"), "p", "pulled"), "p", "pulled")
	it := item(t, e.plan(t, bigLimits, nil, []ComposeMapping{cm}, in), 0)
	if it.Reason == ReasonLocallyBuilt {
		t.Errorf("item = %s/%s; the confirmed absence of a build section must win", it.Category, it.Reason)
	}
	// Without the mapping the same image reads as built here.
	e2 := newEnv()
	it = item(t, e2.planner(t, bigLimits, registry.NewBudget(10)).Plan(context.Background(), []ImageInput{in}), 0)
	if it.Reason != ReasonLocallyBuilt {
		t.Errorf("unmapped: %s/%s", it.Category, it.Reason)
	}
}

// The image's own Compose labels settle what an unreadable Compose file
// cannot.
func TestPlanLabelsBeatAnUndeterminableComposeFile(t *testing.T) {
	e := newDFEnv()
	e.gh.put("ex/app", ".", "compose.yml", "services: [")
	cm := ComposeMapping{Workload: "compose/p/web", Project: "p", Service: "web", Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: "web"}
	in := withLabels(localBuildInput("p-web", containerdDigests("p-web"), "p", "web"), "p", "web")
	it := item(t, e.plan(t, bigLimits, nil, []ComposeMapping{cm}, in), 0)
	if it.Reason != ReasonLocallyBuilt {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestComposeServiceBuilds(t *testing.T) {
	for _, c := range []struct {
		name, file, service string
		want                ComposeBuild
	}{
		{"short form", "services:\n  a:\n    build: .\n", "a", ComposeBuildYes},
		{"long form", "services:\n  a:\n    build:\n      context: .\n", "a", ComposeBuildYes},
		{"image only", "services:\n  a:\n    image: x\n", "a", ComposeBuildNone},
		{"missing service", "services:\n  a:\n    image: x\n", "b", ComposeBuildUndetermined},
		{"extends without build", "services:\n  a:\n    extends:\n      service: b\n", "a", ComposeBuildUndetermined},
		{"extends with its own build", "services:\n  a:\n    extends:\n      service: b\n    build: .\n", "a", ComposeBuildYes},
		{"merge key without build", "x: &d\n  image: x\nservices:\n  a:\n    <<: *d\n", "a", ComposeBuildUndetermined},
		{"include without build", "include:\n  - other.yml\nservices:\n  a:\n    image: x\n", "a", ComposeBuildUndetermined},
		{"include with its own build", "include:\n  - other.yml\nservices:\n  a:\n    build: .\n", "a", ComposeBuildYes},
		{"build reset", "services:\n  a:\n    build: !reset null\n", "a", ComposeBuildUndetermined},
		{"build override", "services:\n  a:\n    build: !override\n      context: .\n", "a", ComposeBuildUndetermined},
		{"build null", "services:\n  a:\n    build: null\n", "a", ComposeBuildUndetermined},
		{"build tilde", "services:\n  a:\n    build: ~\n", "a", ComposeBuildUndetermined},
		{"build empty", "services:\n  a:\n    build:\n", "a", ComposeBuildUndetermined},
		{"build empty string", "services:\n  a:\n    build: \"\"\n", "a", ComposeBuildUndetermined},
		{"build a list", "services:\n  a:\n    build: [x]\n", "a", ComposeBuildUndetermined},
		{"not yaml", "services: [", "a", ComposeBuildUndetermined},
		{"no services", "name: x\n", "a", ComposeBuildUndetermined},
	} {
		got, why := ComposeServiceBuilds([]byte(c.file), "compose.yml", c.service)
		if got != c.want || (got == ComposeBuildUndetermined && why == "") {
			t.Errorf("%s: got %v (%q), want %v", c.name, got, why, c.want)
		}
	}
}
