package remediation

import (
	"errors"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// A container started with docker run is named by its container/<name> key.
// Its image is referred to by the ID of the image when the tag has been built
// again on the host, so these tests use that form for the running reference.

func idRef(h byte) string { return "sha256:" + hex64(h) }

func containerMapping(name, path, target string) DockerfileMapping {
	return DockerfileMapping{Workload: "container/" + name, Repository: "ex/app", BaseBranch: "main", Path: path, Target: target}
}

// containerInput is a scanned image of the container name, referred to by the
// ID of the image, built on top of the layers.
func containerInput(name string, h byte, layers []byte, fs ...scanner.Finding) ImageInput {
	in := input(idRef(h), h, prepared, fs...)
	for _, l := range layers {
		in.Scan.DiffIDs = append(in.Scan.DiffIDs, diffID(l))
	}
	in.Services = []ServiceRef{{Container: name}}
	return in
}

func TestDockerfileContainerCandidate(t *testing.T) {
	e := newDFEnv()
	e.standard()
	plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", "")}, nil,
		containerInput("shop-api", 'a', appLayers, standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryPRCandidate || it.Reason != ReasonAdopted || it.Candidate == nil || it.Candidate.Tag != "3.12.5-slim" {
		t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
	}
	if len(it.Workloads) != 1 || it.Workloads[0] != "container/shop-api" || it.Source.Origin != DockerfileFromMapping {
		t.Errorf("workloads %v origin %s", it.Workloads, it.Source.Origin)
	}
	if got := it.Entities[0].Running.Ref; got != idRef('a') {
		t.Errorf("running reference = %q", got)
	}
	if it.Entities[0].Layers.Status != "confirmed" {
		t.Errorf("layers = %+v", it.Entities[0].Layers)
	}
}

// The layers of the base decide, not the text of the FROM.
func TestDockerfileContainerReferencedByIDLayerChecks(t *testing.T) {
	t.Run("a pinned tag whose layers differ", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.reg.res["python:3.12.3-slim"] = baseResolution('1', '2', 'a', '9')
		plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", "")}, nil,
			containerInput("shop-api", 'a', appLayers, standardFindings()...))
		if it := onlyDockerfile(t, plan); it.Category != CategoryNotComparable || it.Reason != ReasonBaseLayersMismatch {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("a floating tag whose layers differ", func(t *testing.T) {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
		e.base("3.12-slim", baseResolution('1', '2', '9', 'b'), nil, pkgs("libc", "2"))
		plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", "")}, nil,
			containerInput("shop-api", 'a', appLayers, standardFindings()...))
		if it := onlyDockerfile(t, plan); it.Category != CategoryNotComparable || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("another FROM whose layers are the same", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		// The image was built from 3.12.3-slim; the source names 3.12.4-slim,
		// a tag with the same layers.
		e.gh.dirs["ex/app/."] = nil
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12.4-slim\nCOPY . /app\n")
		e.base("3.12.4-slim", baseResolution('5', '6', 'a', 'b'),
			[]scanner.Finding{finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh)},
			pkgs("libc", "1", "openssl", "1"))
		plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", "")}, nil,
			containerInput("shop-api", 'a', appLayers, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryPRCandidate || it.Entities[0].Layers.Status != "confirmed" {
			t.Errorf("item = %s/%s (%s), layers %+v", it.Category, it.Reason, it.Detail, it.Entities[0].Layers)
		}
	})
}

// A scan that failed has no findings: a Dockerfile with that input alone has
// no item, and beside an input with findings the failed one is judged
// scan_failed and the unit is not a pull request candidate.
func TestDockerfileContainerScanFailed(t *testing.T) {
	failed := func(name string, h byte) ImageInput {
		in := containerInput(name, h, appLayers)
		in.Scan.Pinned, in.Scan.Err = false, errors.New("the scanned image is not the one asked for")
		return in
	}
	t.Run("the only input", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", "")}, nil, failed("shop-api", 'a'))
		if len(plan.DockerfileItems) != 0 {
			t.Errorf("Dockerfile items = %+v", plan.DockerfileItems)
		}
	})
	t.Run("beside an input with findings", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", ""), containerMapping("shop-worker", "Dockerfile", "")}, nil,
			containerInput("shop-api", 'a', appLayers, standardFindings()...), failed("shop-worker", 'b'))
		it := onlyDockerfile(t, plan)
		if it.Category == CategoryPRCandidate {
			t.Errorf("the unit is a candidate: %s/%s", it.Category, it.Reason)
		}
		var sawFailed bool
		for _, en := range it.Entities {
			if en.Reason == ReasonScanFailed {
				sawFailed = true
			}
		}
		if !sawFailed {
			t.Errorf("no entity is scan_failed: %+v", it.Entities)
		}
	})
	t.Run("language packages", func(t *testing.T) {
		gh := newFakeGitHub()
		npmRepo(gh, "ex/app", ".")
		in := ImageInput{Scan: configScan(idRef('a'), 'a', []scanner.Finding{nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")}, nil), Services: []ServiceRef{{Container: "shop-api"}}}
		in.Scan.Pinned, in.Scan.Err = false, errors.New("the scanned image is not the one asked for")
		plan := langPlan(t, gh, []DependencyMapping{{Workload: "container/shop-api", Repository: "ex/app", BaseBranch: "main", Directory: "."}}, nil, in)
		if len(plan.LanguageItems) != 0 {
			t.Errorf("language items = %+v", plan.LanguageItems)
		}
	})
}

// A container and a Compose service that share a Dockerfile are one unit, and
// the unit is a candidate only when both confirm the base.
func TestDockerfileContainerSharedWithComposeService(t *testing.T) {
	maps := []DockerfileMapping{containerMapping("shop-api", "Dockerfile", ""), dfMapping("compose/p/worker", "Dockerfile", "")}
	t.Run("both confirm", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, maps, nil,
			containerInput("shop-api", 'a', appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", []byte{'a', 'b', 'd'}, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryPRCandidate || len(it.Entities) != 2 {
			t.Fatalf("item = %s/%s entities %d", it.Category, it.Reason, len(it.Entities))
		}
		if strings.Join(it.Workloads, ",") != "compose/p/worker,container/shop-api" {
			t.Errorf("workloads = %v", it.Workloads)
		}
	})
	t.Run("one cannot confirm", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, maps, nil,
			containerInput("shop-api", 'a', []byte{'a', '9', 'c'}, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", []byte{'a', 'b', 'd'}, standardFindings()...))
		if it := onlyDockerfile(t, plan); it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
}

// A container the mapping does not name, and the Compose services, are not
// part of a container's unit even when they run the same image.
func TestDockerfileContainerUnmappedContainersAreLeftOut(t *testing.T) {
	e := newDFEnv()
	e.standard()
	other := containerInput("other", 'b', appLayers, standardFindings()...)
	plan := e.plan(t, bigLimits, []DockerfileMapping{containerMapping("shop-api", "Dockerfile", "")}, nil,
		containerInput("shop-api", 'a', appLayers, standardFindings()...), other)
	it := onlyDockerfile(t, plan)
	if len(it.Entities) != 1 || len(it.Workloads) != 1 {
		t.Errorf("entities %d workloads %v", len(it.Entities), it.Workloads)
	}
}

// The mapping is trusted: a container of an unrelated application that has the
// same base image and the same vulnerable dependency as the mapped repository
// gets a candidate. Nothing ties the container to the repository.
func TestContainerMappingIsTrustedNotChecked(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.gh.put("ex/app", ".", "package.json", npmManifest)
	e.gh.put("ex/app", ".", "package-lock.json", npmLockV3)
	deps := []DependencyMapping{{Workload: "container/billing", Repository: "ex/app", BaseBranch: "main", Directory: "."}}
	fs := append(standardFindings(), nodeFinding("CVE-9", "lodash", "4.17.20", "4.17.21"))
	in := containerInput("billing", 'c', appLayers, fs...)
	in.Scan.Image = "ghcr.io/unrelated/billing:7"
	p, err := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh,
		Dockerfiles: []DockerfileMapping{containerMapping("billing", "Dockerfile", "")}, Dependencies: deps,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Plan(t.Context(), []ImageInput{in})
	if it := onlyDockerfile(t, plan); it.Category != CategoryPRCandidate {
		t.Errorf("Dockerfile item = %s/%s", it.Category, it.Reason)
	}
	if len(plan.LanguageItems) != 1 || plan.LanguageItems[0].Category != CategoryDependencyUpdateCandidate {
		t.Errorf("language items = %+v", plan.LanguageItems)
	}
}

// A container of each ecosystem gets its language item.
func TestLanguagePlan_ContainerNpmAndPip(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "web")
	gh.put("ex/app", "py", "requirements.txt", "requests==2.31.0\n")
	deps := []DependencyMapping{
		{Workload: "container/shop-web", Repository: "ex/app", BaseBranch: "main", Directory: "web"},
		{Workload: "container/shop-py", Repository: "ex/app", BaseBranch: "main", Directory: "py"},
	}
	web := ImageInput{Scan: configScan(idRef('a'), 'a', []scanner.Finding{nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")}, nil), Services: []ServiceRef{{Container: "shop-web"}}}
	py := ImageInput{Scan: configScan(idRef('b'), 'b', []scanner.Finding{pyFinding("CVE-2", "requests", "2.31.0", "2.32.0")}, nil), Services: []ServiceRef{{Container: "shop-py"}}}
	plan := langPlan(t, gh, deps, nil, web, py)
	if len(plan.LanguageItems) != 2 {
		t.Fatalf("language items = %d", len(plan.LanguageItems))
	}
	got := map[DependencyManager]string{}
	for _, it := range plan.LanguageItems {
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Errorf("%s: %s/%s (%s)", it.Manager, it.Category, it.Reason, it.Detail)
		}
		got[it.Manager] = strings.Join(it.Workloads, ",")
	}
	if got[ManagerNpm] != "container/shop-web" || got[ManagerPip] != "container/shop-py" {
		t.Errorf("workloads = %v", got)
	}
}
