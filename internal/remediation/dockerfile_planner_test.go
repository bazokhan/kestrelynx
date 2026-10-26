package remediation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func diffID(c byte) string { return "sha256:" + hex64(c) }

// layered is a finding in a layer of the running image.
func layered(f scanner.Finding, layer byte) scanner.Finding {
	f.LayerDiffID = diffID(layer)
	return f
}

// baseResolution is the registry resolution of a base image whose config has
// the layers.
func baseResolution(manifest, config byte, layers ...byte) registry.Resolution {
	r := resolution(manifest, config)
	r.RootFSType = "layers"
	for _, l := range layers {
		r.DiffIDs = append(r.DiffIDs, diffID(l))
	}
	return r
}

// dfInput is a scanned image of the Compose service svc of project p, built
// on top of the layers.
func dfInput(ref string, h byte, svc string, layers []byte, fs ...scanner.Finding) ImageInput {
	in := input(ref, h, prepared, fs...)
	for _, l := range layers {
		in.Scan.DiffIDs = append(in.Scan.DiffIDs, diffID(l))
	}
	in.Services = []ServiceRef{{Project: "p", Service: svc}}
	return in
}

const appDockerfile = "FROM python:3.12.3-slim\nCOPY . /app\n"

// dfEnv is a planner environment with a repository holding Dockerfiles.
type dfEnv struct {
	*env
	gh *fakeGitHub
}

func newDFEnv() *dfEnv {
	e := &dfEnv{env: newEnv(), gh: newFakeGitHub()}
	e.reg.tags["python"] = registry.TagList{Tags: []string{"3.12.3-slim", "3.12.4-slim", "3.12.5-slim", "3.13.0-slim", "3.12.6-slim-rc1"}, Pages: 1}
	return e
}

// base registers the resolution and the scan of a base image tag.
func (e *dfEnv) base(tag string, res registry.Resolution, fs []scanner.Finding, pk []scanner.ResultPackages) {
	e.reg.res["python:"+tag] = res
	e.candidateScan("python:"+tag, fs, pk)
}

func (e *dfEnv) plan(t *testing.T, lim Limits, dockerfiles []DockerfileMapping, composes []ComposeMapping, inputs ...ImageInput) Plan {
	t.Helper()
	p, err := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: lim,
		Intel: func(id string) (VulnIntel, bool) {
			if id == "KEV-NEW" {
				return VulnIntel{Priority: PriorityActNow, KEV: true}, true
			}
			return VulnIntel{}, false
		},
		GitHub: e.gh, Dockerfiles: dockerfiles, Composes: composes,
		Now: func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.Plan(context.Background(), inputs)
}

func dfMapping(workload, path, target string) DockerfileMapping {
	parts := strings.Split(workload, "/")
	return DockerfileMapping{Workload: workload, Project: parts[1], Service: parts[2], Repository: "ex/app", BaseBranch: "main", Path: path, Target: target}
}

func onlyDockerfile(t *testing.T, p Plan) DockerfileItem {
	t.Helper()
	if len(p.DockerfileItems) != 1 {
		t.Fatalf("plan has %d Dockerfile items: %+v", len(p.DockerfileItems), p.DockerfileItems)
	}
	return p.DockerfileItems[0]
}

// The standard scenario: the running image has two layers from the base
// (a, b) and one of its own (c); two of its fixed findings are in the base's
// layers, one above them and one has no layer.
func standardFindings() []scanner.Finding {
	return []scanner.Finding{
		layered(finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), 'b'),
		layered(finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh), 'a'),
		layered(finding("CVE-U", "pylib", "1", "2", scanner.SeverityHigh), 'c'),
		finding("CVE-N", "nolayer", "1", "2", scanner.SeverityHigh),
	}
}

var appLayers = []byte{'a', 'b', 'c'}

// standard sets up the current base python:3.12.3-slim (layers a, b) and the
// candidate python:3.12.5-slim, which fixes CVE-A only.
func (e *dfEnv) standard() {
	e.gh.put("ex/app", ".", "Dockerfile", appDockerfile)
	e.base("3.12.3-slim", baseResolution('1', '2', 'a', 'b'),
		[]scanner.Finding{finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh)},
		pkgs("libc", "1", "openssl", "1"))
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'),
		[]scanner.Finding{finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh)},
		pkgs("libc", "2", "openssl", "1"))
}

func TestDockerfilePinnedPartial(t *testing.T) {
	e := newDFEnv()
	e.standard()
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryPRCandidate || it.Reason != ReasonAdopted {
		t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
	}
	if it.BaseRef != "python:3.12.3-slim" || it.BaseKind != TagPinned || it.Candidate == nil || it.Candidate.Tag != "3.12.5-slim" {
		t.Errorf("base = %q/%s candidate = %+v", it.BaseRef, it.BaseKind, it.Candidate)
	}
	if it.Source.CommitSHA != testCommit || it.Source.Path != "Dockerfile" || it.Source.Stage == nil || *it.Source.Stage != 0 ||
		it.Source.Origin != DockerfileFromMapping || it.Source.Line != 1 {
		t.Errorf("source = %+v", it.Source)
	}
	if it.FinalImageVerified {
		t.Error("the final image is never verified")
	}
	// Two of the four findings are in the base's layers; the one above and the
	// one without a layer are not counted.
	if it.Counts.Targets != 2 || it.Counts.Resolved != 1 || it.Counts.Remaining != 1 || it.Counts.Introduced != 0 {
		t.Errorf("counts = %+v", it.Counts)
	}
	if len(it.Entities) != 1 {
		t.Fatalf("entities = %d", len(it.Entities))
	}
	en := it.Entities[0]
	if en.Layers.Status != "confirmed" || en.Layers.BaseLayers != 2 || en.Layers.ImageLayers != 3 {
		t.Errorf("layers = %+v", en.Layers)
	}
	if en.Findings != (LayerCounts{Base: 2, Upper: 1, Unknown: 1}) {
		t.Errorf("findings by layer = %+v", en.Findings)
	}
	if en.Running.Ref != "myapp:1" || en.CurrentBase == nil || en.CurrentBase.Ref != "python:3.12.3-slim" || en.CandidateBase == nil || en.CandidateBase.Ref != "python:3.12.5-slim" {
		t.Errorf("entities' images = %+v / %+v / %+v", en.Running, en.CurrentBase, en.CandidateBase)
	}
	if en.Decision == nil || en.Decision.Kind != DecisionAdoptPartial || en.Decision.Resolved != 1 || en.Decision.Targets != 2 {
		t.Errorf("decision = %+v", en.Decision)
	}
	for _, tg := range en.Targets {
		if len(tg.Layers) != 1 {
			t.Errorf("target %s layers = %v", tg.VulnID, tg.Layers)
		}
	}
	// Both bases were scanned, the running image was not.
	if plan.Usage.BaselineRescans != 1 || plan.Usage.CandidateScans != 1 || len(plan.Scans) != 2 {
		t.Errorf("usage = %+v, scans = %d", plan.Usage, len(plan.Scans))
	}
	if plan.Scans[0].Role != RoleBaseline || plan.Scans[0].Ref != "python:3.12.3-slim" || plan.Scans[1].Role != RoleCandidate || plan.Scans[1].Ref != "python:3.12.5-slim" {
		t.Errorf("scans = %+v", plan.Scans)
	}
	if e.scn.calls[0] == "myapp:1" {
		t.Error("the running image was scanned again")
	}
}

func TestDockerfilePinnedAdoptedInFull(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'), nil, pkgs("libc", "2", "openssl", "2"))
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryPRCandidate || it.Counts.Targets != 2 || it.Counts.Resolved != 2 || it.Entities[0].Decision.Kind != DecisionAdopt {
		t.Errorf("item = %s/%s counts %+v", it.Category, it.Reason, it.Counts)
	}
}

func TestDockerfileIntroducedIsManual(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'),
		[]scanner.Finding{finding("CVE-NEW", "zlib", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "2", "openssl", "2", "zlib", "1"))
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryManual || it.Reason != ReasonIntroducedFindings || it.Counts.Introduced != 1 {
		t.Errorf("item = %s/%s counts %+v", it.Category, it.Reason, it.Counts)
	}

	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'),
		[]scanner.Finding{finding("KEV-NEW", "zlib", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "2", "openssl", "2", "zlib", "1"))
	plan = e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	if it := onlyDockerfile(t, plan); it.Category != CategoryManual || it.Reason != ReasonIntroducedKEV {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestDockerfileNothingResolved(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'),
		[]scanner.Finding{finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh)},
		pkgs("libc", "1", "openssl", "1"))
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	if it := onlyDockerfile(t, plan); it.Category != CategoryNoCandidate || it.Reason != ReasonCandidateNotFixing {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestDockerfileBaseLayerChecks(t *testing.T) {
	cases := []struct {
		name   string
		res    registry.Resolution
		layers []byte
		cat    Category
		reason Reason
		status string
	}{
		{"base is not the start of the image (tag rebuilt after the build)", baseResolution('1', '2', 'a', '9'), appLayers, CategoryNotComparable, ReasonBaseLayersMismatch, "mismatch"},
		{"base has more layers than the image", baseResolution('1', '2', 'a', 'b', 'c', 'd'), appLayers, CategoryNotComparable, ReasonBaseLayersMismatch, "mismatch"},
		{"base config has no layers", func() registry.Resolution { r := resolution('1', '2'); return r }(), appLayers, CategoryNotComparable, ReasonBaseLayersUnusable, "unusable"},
		{"base rootfs type is not layers", func() registry.Resolution { r := baseResolution('1', '2', 'a', 'b'); r.RootFSType = "other"; return r }(), appLayers, CategoryNotComparable, ReasonBaseLayersUnusable, "unusable"},
		{"base has ONBUILD triggers", func() registry.Resolution { r := baseResolution('1', '2', 'a', 'b'); r.OnBuild = true; return r }(), appLayers, CategoryManual, ReasonBaseOnBuild, "not_checked"},
		{"the scan reports no layer IDs", baseResolution('1', '2', 'a', 'b'), nil, CategoryNotComparable, ReasonBaseLayersUnusable, "unusable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDFEnv()
			e.standard()
			e.reg.res["python:3.12.3-slim"] = c.res
			plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
				dfInput("myapp:1", 'a', "app", c.layers, standardFindings()...))
			it := onlyDockerfile(t, plan)
			if it.Category != c.cat || it.Reason != c.reason {
				t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			if got := it.Entities[0].Layers.Status; got != c.status {
				t.Errorf("layer status = %q, want %q", got, c.status)
			}
			if it.Counts.Resolved != 0 || it.Candidate != nil || len(plan.Scans) != 0 {
				t.Errorf("a comparison was claimed: counts %+v candidate %+v scans %d", it.Counts, it.Candidate, len(plan.Scans))
			}
		})
	}
}

func TestDockerfileCandidateOnBuildIsManual(t *testing.T) {
	e := newDFEnv()
	e.standard()
	r := baseResolution('3', '4', 'x', 'y')
	r.OnBuild = true
	e.reg.res["python:3.12.5-slim"] = r
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	if it := onlyDockerfile(t, plan); it.Category != CategoryManual || it.Reason != ReasonBaseOnBuild || len(plan.Scans) != 0 {
		t.Errorf("item = %s/%s, scans %d", it.Category, it.Reason, len(plan.Scans))
	}
}

func TestDockerfileInheritedOnBuildIsManual(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12.3-slim AS base\nONBUILD RUN echo hi\nFROM base\nCOPY . /app\n")
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	if it := onlyDockerfile(t, plan); it.Category != CategoryManual || it.Reason != ReasonDockerfileOnBuild {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}

func TestDockerfileNoBaseDerivedFindings(t *testing.T) {
	e := newDFEnv()
	e.standard()
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers,
			layered(finding("CVE-U", "pylib", "1", "2", scanner.SeverityHigh), 'c'),
			finding("CVE-N", "nolayer", "1", "2", scanner.SeverityHigh),
			layered(finding("CVE-X", "alien", "1", "2", scanner.SeverityHigh), 'q')))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryNoCandidate || it.Reason != ReasonNoBaseFindings {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
	if f := it.Entities[0].Findings; f != (LayerCounts{Base: 0, Upper: 1, Unknown: 2}) {
		t.Errorf("findings by layer = %+v", f)
	}
	if len(plan.Scans) != 0 || e.reg.listCalls != 0 {
		t.Error("work was spent on a base with no findings to fix")
	}
}

func TestDockerfileRunningImageMustBeVerified(t *testing.T) {
	e := newDFEnv()
	e.standard()
	in := dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)
	in.Scan.Pinned = false
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in)
	if it := onlyDockerfile(t, plan); it.Category != CategoryNotComparable || it.Reason != ReasonEntityUnverified {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
	if e.reg.resolveCnt["python:3.12.3-slim"] != 0 {
		t.Error("the registry was asked about a base of an unverified image")
	}
}

func TestDockerfileStaticPlatformFlag(t *testing.T) {
	for flag, want := range map[string]Reason{"linux/arm64": ReasonPlatformMismatch, "linux/arm/v7": ReasonVariantUnsupported, "linux/amd64": ""} {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM --platform="+flag+" python:3.12.3-slim\nCOPY . /app\n")
		plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if want == "" {
			if it.Category != CategoryPRCandidate {
				t.Errorf("%s: item = %s/%s", flag, it.Category, it.Reason)
			}
			continue
		}
		if it.Category != CategoryNotComparable || it.Reason != want {
			t.Errorf("%s: item = %s/%s (%s)", flag, it.Category, it.Reason, it.Detail)
		}
		if e.reg.resolveCnt["python:3.12.3-slim"] != 0 {
			t.Errorf("%s: the registry was asked", flag)
		}
	}
}

func TestDockerfileVariableAndOtherDispositions(t *testing.T) {
	cases := map[string]struct {
		file   string
		cat    Category
		reason Reason
	}{
		"ARG in the image":     {"ARG V=3.12.3\nFROM python:${V}-slim\n", CategoryManual, ReasonDockerfileVariable},
		"variable platform":    {"FROM --platform=$BUILDPLATFORM python:3.12.3-slim\n", CategoryManual, ReasonDockerfileVariable},
		"scratch":              {"FROM scratch\nCOPY a /a\n", CategoryExcluded, ReasonDockerfileScratch},
		"digest":               {"FROM python@sha256:" + hex64('e') + "\n", CategoryExcluded, ReasonDockerfileDigest},
		"other syntax":         {"# syntax=example.com/custom/frontend:1\nFROM python:3.12.3-slim\n", CategoryManual, ReasonDockerfileFrontend},
		"escape directive":     {"# escape=`\nFROM python:3.12.3-slim\n", CategoryManual, ReasonDockerfileEscape},
		"target stage missing": {"FROM python:3.12.3-slim AS other\n", CategoryManual, ReasonDockerfileTargetMissing},
		"no FROM":              {"RUN echo hi\n", CategoryManual, ReasonDockerfileInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDFEnv()
			e.standard()
			e.gh.put("ex/app", ".", "Dockerfile", c.file)
			target := ""
			if c.reason == ReasonDockerfileTargetMissing {
				target = "runtime"
			}
			plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", target)}, nil,
				dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
			if it := onlyDockerfile(t, plan); it.Category != c.cat || it.Reason != c.reason {
				t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
		})
	}
}

func TestDockerfileMultiStageTarget(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.gh.put("ex/app", ".", "Dockerfile", "FROM golang:1.22.1 AS build\nRUN go build\nFROM python:3.12.3-slim AS runtime\nCOPY --from=build /a /a\nFROM runtime AS final\nUSER app\n")
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "final")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryPRCandidate || it.Source.Stage == nil || *it.Source.Stage != 1 || it.Source.StageName != "runtime" || it.Source.Line != 3 {
		t.Errorf("item = %s/%s source %+v", it.Category, it.Reason, it.Source)
	}
	if !strings.HasSuffix(it.Key, "#stages[1]:runtime") {
		t.Errorf("key = %q, want the resolved stage in it", it.Key)
	}
}

func TestDockerfileFloatingBase(t *testing.T) {
	setup := func(e *dfEnv, current byte) {
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
		e.base("3.12-slim", baseResolution('1', '2', current, 'b'), nil, pkgs("libc", "2"))
	}
	t.Run("the tag still points at the base the image uses", func(t *testing.T) {
		e := newDFEnv()
		setup(e, 'a')
		plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryNoCandidate || it.Reason != ReasonBaseUnchanged || it.Candidate != nil || it.BaseKind != TagFloating {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		if len(plan.Scans) != 0 || e.reg.listCalls != 0 {
			t.Error("a floating base is neither listed nor scanned")
		}
	})
	t.Run("the tag moved on", func(t *testing.T) {
		e := newDFEnv()
		setup(e, '9')
		plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryNotComparable || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		// No counts and no claim of improvement.
		if it.Counts != (DockerfileCounts{}) || it.Candidate != nil || it.Entities[0].Comparison != nil || len(plan.Scans) != 0 {
			t.Errorf("a floating base carries counts or a comparison: %+v", it)
		}
	})
	t.Run("the layers cannot be compared", func(t *testing.T) {
		e := newDFEnv()
		setup(e, 'a')
		e.reg.res["python:3.12-slim"] = resolution('1', '2')
		plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
		if it := onlyDockerfile(t, plan); it.Category != CategoryNotComparable || it.Reason != ReasonBaseLayersUnusable {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("implicit latest", func(t *testing.T) {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python\nCOPY . /app\n")
		e.base("latest", baseResolution('1', '2', '9', 'b'), nil, pkgs("libc", "2"))
		plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
		if it := onlyDockerfile(t, plan); it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
}

func TestDockerfileSharedByWorkloads(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", ""), dfMapping("compose/p/worker", "Dockerfile", "")}

	t.Run("both confirm and adopt", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", []byte{'a', 'b', 'd'}, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryPRCandidate || len(it.Entities) != 2 || len(it.Workloads) != 2 {
			t.Fatalf("item = %s/%s entities %d workloads %v", it.Category, it.Reason, len(it.Entities), it.Workloads)
		}
		if plan.Usage.BaselineRescans != 1 || plan.Usage.CandidateScans != 1 {
			t.Errorf("the bases are scanned once for both images: %+v", plan.Usage)
		}
	})
	t.Run("one cannot confirm the base: the whole unit is manual", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", []byte{'a', '9', 'd'}, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted {
			t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
		if it.Entities[0].Category != CategoryPRCandidate {
			t.Error("the entity that was adopted is still recorded as such")
		}
	})
	t.Run("one has no base findings", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", appLayers, layered(finding("CVE-U", "pylib", "1", "2", scanner.SeverityHigh), 'c')))
		if it := onlyDockerfile(t, plan); it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("adopted beside one left undone by a limit: manual, reasons kept", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		// Two platforms need two scans of each base; the limit allows one.
		arm := dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...)
		arm.Scan.Platform.Architecture = "arm64"
		arm.Scan.Subject.Key.Platform = arm.Scan.Platform
		plan := e.plan(t, Limits{MaxCandidateScans: 1, MaxBaselineRescans: 5, MaxTagPages: 5}, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...), arm)
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		if it.Entities[0].Category != CategoryPRCandidate || it.Entities[1].Category != CategoryDeferred || it.Entities[1].Reason != ReasonCandidateScanLimit {
			t.Errorf("entities = %s/%s and %s/%s", it.Entities[0].Category, it.Entities[0].Reason, it.Entities[1].Category, it.Entities[1].Reason)
		}
	})
	t.Run("every image left undone: deferred", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, Limits{MaxCandidateScans: 0, MaxBaselineRescans: 5, MaxTagPages: 5}, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...))
		if it := onlyDockerfile(t, plan); it.Category != CategoryDeferred || it.Reason != ReasonCandidateScanLimit {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("every image failed: failed", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		a, b := dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...), dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...)
		a.Scan.Err, b.Scan.Err = errors.New("pull failed"), errors.New("pull failed")
		if it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil, a, b)); it.Category != CategoryFailed || it.Reason != ReasonScanFailed {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("adopted beside one whose scan failed: manual", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		w := dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...)
		w.Scan.Err = errors.New("pull failed")
		it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil, dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...), w))
		if it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted || it.Entities[1].Category != CategoryFailed {
			t.Errorf("item = %s/%s entities %+v", it.Category, it.Reason, it.Entities)
		}
	})
	t.Run("a sharing workload whose scan failed holds back the one with findings", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		// The failed one has no findings to start the exploration with.
		w := dfInput("myworker:1", 'b', "worker", appLayers)
		w.Scan.Err = errors.New("pull failed")
		it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil, dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...), w))
		if it.Category != CategoryManual || len(it.Workloads) != 2 {
			t.Errorf("item = %s/%s workloads %v", it.Category, it.Reason, it.Workloads)
		}
	})
	t.Run("a sharing workload with no findings at all holds back the one with findings", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...), dfInput("myworker:1", 'b', "worker", appLayers)))
		if it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted || len(it.Workloads) != 2 {
			t.Errorf("item = %s/%s workloads %v", it.Category, it.Reason, it.Workloads)
		}
	})
	t.Run("no workload of the location has a finding: nothing is explored", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, bigLimits, maps, nil, dfInput("myapp:1", 'a', "app", appLayers), dfInput("myworker:1", 'b', "worker", appLayers))
		if len(plan.DockerfileItems) != 0 || e.reg.resolveCnt["python:3.12.3-slim"] != 0 {
			t.Errorf("items = %+v", plan.DockerfileItems)
		}
	})
	t.Run("different targets leading to the same FROM share the unit", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12.3-slim AS base\nFROM base AS web\nFROM base AS worker\n")
		ms := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "web"), dfMapping("compose/p/worker", "Dockerfile", "worker")}
		plan := e.plan(t, bigLimits, ms, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryPRCandidate || len(it.Source.Targets) != 2 {
			t.Errorf("item = %s/%s targets %v", it.Category, it.Reason, it.Source.Targets)
		}
	})
	t.Run("different FROMs make different units", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12.3-slim AS web\nFROM python:3.12.3-slim AS worker\n")
		ms := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "web"), dfMapping("compose/p/worker", "Dockerfile", "worker")}
		plan := e.plan(t, bigLimits, ms, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...))
		if len(plan.DockerfileItems) != 2 {
			t.Fatalf("items = %d, want one per FROM", len(plan.DockerfileItems))
		}
		if plan.DockerfileItems[0].Key == plan.DockerfileItems[1].Key {
			t.Error("two edit locations share a key")
		}
	})
}

func TestDockerfileDerivedFromCompose(t *testing.T) {
	compose := func(build string) string {
		return "services:\n  app:\n    image: myapp:1\n" + build + "  other:\n    image: nginx:1.25.3\n"
	}
	cm := ComposeMapping{Workload: "compose/p/app", Project: "p", Service: "app", Repository: "ex/app", BaseBranch: "main", Path: "deploy/compose.yml", ComposeService: "app"}
	run := func(e *dfEnv, ms []DockerfileMapping, cms []ComposeMapping) Plan {
		return e.plan(t, bigLimits, ms, cms, dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	}

	t.Run("static build section", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", "deploy/app", "Dockerfile", appDockerfile)
		e.gh.put("ex/app", "deploy", "compose.yml", compose("    build: ./app\n"))
		it := onlyDockerfile(t, run(e, nil, []ComposeMapping{cm}))
		if it.Category != CategoryPRCandidate || it.Source.Origin != DockerfileFromCompose || it.Source.Path != "deploy/app/Dockerfile" ||
			it.Source.ComposePath != "deploy/compose.yml" || len(it.Source.Files) != 2 {
			t.Errorf("item = %s/%s source %+v", it.Category, it.Reason, it.Source)
		}
	})
	t.Run("build target is the stage", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", "deploy", "Dockerfile.web", "FROM python:3.12.3-slim AS base\nFROM base AS web\n")
		e.gh.put("ex/app", "deploy", "compose.yml", compose("    build:\n      context: .\n      dockerfile: Dockerfile.web\n      target: web\n"))
		it := onlyDockerfile(t, run(e, nil, []ComposeMapping{cm}))
		if it.Category != CategoryPRCandidate || it.Source.Path != "deploy/Dockerfile.web" || len(it.Source.Targets) != 1 || it.Source.Targets[0] != "web" {
			t.Errorf("item = %s/%s source %+v", it.Category, it.Reason, it.Source)
		}
	})
	t.Run("no build section is not this route", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", "deploy", "compose.yml", compose(""))
		plan := run(e, nil, []ComposeMapping{cm})
		if len(plan.DockerfileItems) != 0 {
			t.Errorf("items = %+v", plan.DockerfileItems)
		}
	})
	t.Run("unreadable Compose file is silent", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := run(e, nil, []ComposeMapping{cm})
		if len(plan.DockerfileItems) != 0 {
			t.Errorf("items = %+v", plan.DockerfileItems)
		}
	})
	t.Run("build section that cannot be followed is manual", func(t *testing.T) {
		for build, want := range map[string]Reason{
			"    build: ${CTX}\n":                                             ReasonComposeVariable,
			"    build: https://example.com/r.git\n":                          ReasonComposeBuildRemote,
			"    build:\n      context: .\n      dockerfile_inline: FROM a\n": ReasonComposeBuildInline,
			"    build: ../../outside\n":                                      ReasonComposeBuildPath,
		} {
			e := newDFEnv()
			e.standard()
			e.gh.put("ex/app", "deploy", "compose.yml", compose(build))
			it := onlyDockerfile(t, run(e, nil, []ComposeMapping{cm}))
			if it.Category != CategoryManual || it.Reason != want {
				t.Errorf("%q: item = %s/%s", build, it.Category, it.Reason)
			}
		}
	})
	t.Run("explicit mapping that agrees", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", "deploy", "compose.yml", compose("    build: ../\n"))
		it := onlyDockerfile(t, run(e, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, []ComposeMapping{cm}))
		if it.Category != CategoryPRCandidate || it.Source.Origin != DockerfileFromBoth {
			t.Errorf("item = %s/%s origin %s (%s)", it.Category, it.Reason, it.Source.Origin, it.Detail)
		}
	})
	t.Run("explicit mapping that disagrees is a configuration mismatch", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", "deploy", "compose.yml", compose("    build: ./app\n"))
		it := onlyDockerfile(t, run(e, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, []ComposeMapping{cm}))
		if it.Category != CategoryManual || it.Reason != ReasonDockerfileMappingDiffers {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		if len(plan0Scans(e)) != 0 {
			t.Error("scans were made for a mismatched configuration")
		}
	})
	t.Run("stage disagreement counts too", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", "deploy", "compose.yml", compose("    build:\n      context: ..\n      target: web\n"))
		it := onlyDockerfile(t, run(e, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, []ComposeMapping{cm}))
		if it.Reason != ReasonDockerfileMappingDiffers {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("explicit mapping in another repository is not compared", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		other := cm
		other.Repository = "ex/deploy"
		e.gh.put("ex/deploy", "deploy", "compose.yml", compose("    build: ./elsewhere\n"))
		it := onlyDockerfile(t, run(e, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, []ComposeMapping{other}))
		if it.Category != CategoryPRCandidate || it.Source.Origin != DockerfileFromMapping {
			t.Errorf("item = %s/%s origin %s", it.Category, it.Reason, it.Source.Origin)
		}
	})
}

// plan0Scans is the scans an environment's scanner made.
func plan0Scans(e *dfEnv) []string { return e.scn.calls }

func TestDockerfileSourceFailures(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	in := func() ImageInput { return dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...) }
	t.Run("Dockerfile not found", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		delete(e.gh.files, "ex/app/Dockerfile")
		if it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil, in())); it.Category != CategoryFailed || it.Reason != ReasonDockerfileFileNotFound {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("not a regular file", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.readErr["ex/app/Dockerfile"] = fmt.Errorf("x: %w", github.ErrNotRegularFile)
		if it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil, in())); it.Category != CategoryManual || it.Reason != ReasonDockerfileFileUnusable {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("branch not found", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.branchErr["ex/app"] = github.ErrNotFound
		if it := onlyDockerfile(t, e.plan(t, bigLimits, maps, nil, in())); it.Category != CategoryFailed || it.Reason != ReasonSourceNotFound {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("rate limit defers and stops further reads", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.readErr["ex/app/Dockerfile"] = &github.RateLimitedError{}
		ms := append(maps, DockerfileMapping{Workload: "compose/p/other", Project: "p", Service: "other", Repository: "ex/other", BaseBranch: "main", Path: "Dockerfile"})
		plan := e.plan(t, bigLimits, ms, nil, in(), dfInput("other:1", 'b', "other", appLayers, standardFindings()...))
		for _, it := range plan.DockerfileItems {
			if it.Category != CategoryDeferred || it.Reason != ReasonRateLimited {
				t.Errorf("%s = %s/%s", it.Key, it.Category, it.Reason)
			}
		}
		if n := e.gh.count("read:ex/other"); n != 0 {
			t.Errorf("%d reads after the rate limit", n)
		}
	})
	t.Run("the Dockerfile is read once for workloads sharing it", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		two := append(maps, dfMapping("compose/p/worker", "Dockerfile", ""))
		e.plan(t, bigLimits, two, nil, in(), dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...))
		if n := e.gh.count("read:ex/app/Dockerfile"); n != 1 {
			t.Errorf("reads = %d", n)
		}
		if n := e.gh.count("branch:"); n != 1 {
			t.Errorf("branch resolutions = %d", n)
		}
	})
}

func TestDockerfileNoRouteChangesNothing(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4"}, Pages: 1}
	e.reg.res["nginx:1.25.4"] = resolution('b', 'c')
	e.candidateScan("nginx:1.25.4", nil, pkgs("libc", "2"))
	// A workload with neither a Dockerfile nor a Compose mapping.
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, input("nginx:1.25.3", 'a', prepared, fixedA()))
	if len(plan.DockerfileItems) != 0 || len(plan.Items) != 1 || plan.Items[0].Category != CategoryPRCandidate {
		t.Errorf("plan = %+v", plan)
	}
	if n := len(e.gh.calls); n != 0 {
		t.Errorf("GitHub was called %d times for workloads without a route", n)
	}
	// And without a GitHub reader the part is off.
	p, _ := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, Dockerfiles: []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}})
	if pl := p.Plan(context.Background(), []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)}); len(pl.DockerfileItems) != 0 {
		t.Error("the Dockerfile part ran without a GitHub reader")
	}
}

func TestDockerfileCandidateSelection(t *testing.T) {
	t.Run("no newer patch", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.reg.tags["python"] = registry.TagList{Tags: []string{"3.12.3-slim", "3.13.0-slim", "3.12.5"}, Pages: 1}
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))); it.Category != CategoryNoCandidate || it.Reason != ReasonNoNewerTag {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("incomplete listing is deferred", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.reg.tags["python"] = registry.TagList{Tags: []string{"3.12.3-slim"}, Truncated: true, Pages: 3}
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))); it.Category != CategoryDeferred {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("the candidate resolves to the current content", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.reg.res["python:3.12.5-slim"] = baseResolution('1', '9', 'a', 'b')
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))); it.Category != CategoryNoCandidate || it.Reason != ReasonSameContent {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("scan limits count and defer", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		for _, lim := range []Limits{{MaxCandidateScans: 0, MaxBaselineRescans: 5, MaxTagPages: 5}, {MaxCandidateScans: 5, MaxBaselineRescans: 0, MaxTagPages: 5}} {
			plan := e.plan(t, lim, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
				dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
			it := onlyDockerfile(t, plan)
			if it.Category != CategoryDeferred || (it.Reason != ReasonCandidateScanLimit && it.Reason != ReasonBaselineRescanLimit) {
				t.Errorf("limits %+v: item = %s/%s", lim, it.Category, it.Reason)
			}
			if len(plan.Scans) != 0 {
				t.Error("one scan was spent although the other would be over its limit")
			}
		}
	})
	t.Run("registry rate limit defers", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.reg.resErr["python:3.12.3-slim"] = &registry.RateLimitedError{Host: "h"}
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))); it.Category != CategoryDeferred || it.Reason != ReasonRateLimited {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	// The refusal stands for a base named like a Docker Official Image that
	// Docker Hub does not have: a base image built on the host.
	t.Run("anonymous refusal of an official base name is a host build", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.reg.resErr["python:3.12.3-slim"] = &registry.AnonymousDeniedError{Host: "registry-1.docker.io", Path: "library/python"}
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))); it.Category != CategoryExcluded || it.Reason != ReasonLocallyBuilt {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
}

func TestDockerfileCountAllAndFingerprint(t *testing.T) {
	e := newDFEnv()
	e.standard()
	plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	if plan.CountAll(CategoryPRCandidate) != 1 || plan.CountDockerfile(CategoryPRCandidate) != 1 {
		t.Error("the Dockerfile item is not counted")
	}
	f1 := Fingerprint(plan)
	if f1 == "" {
		t.Fatal("empty fingerprint for a plan with a Dockerfile item")
	}
	// Times and scan IDs do not move the fingerprint; a different outcome does.
	again := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	again.GeneratedAt = again.GeneratedAt.Add(time.Hour)
	if Fingerprint(again) != f1 {
		t.Error("the fingerprint depends on the time")
	}
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'), nil, pkgs("libc", "2", "openssl", "2"))
	changed := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil,
		dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	if Fingerprint(changed) == f1 {
		t.Error("the fingerprint ignores the Dockerfile item's counts")
	}
	if Fingerprint(Plan{}) != "" {
		t.Error("an empty plan has a fingerprint")
	}
}

// TestDockerfileExplicitMappingStillReadsTheBuildSection: a Compose mapping of
// the same workload is read even when a Dockerfile is named, and a build
// section that is there but cannot be followed makes the unit manual.
func TestDockerfileExplicitMappingStillReadsTheBuildSection(t *testing.T) {
	compose := func(build string) string {
		return "services:\n  app:\n    image: myapp:1\n" + build
	}
	cm := ComposeMapping{Workload: "compose/p/app", Project: "p", Service: "app", Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: "app"}
	run := func(c string, cms ...ComposeMapping) (DockerfileItem, *dfEnv) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "compose.yml", c)
		return onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, cms,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))), e
	}
	for name, c := range map[string]struct {
		build  string
		reason Reason
	}{
		"dockerfile_inline":   {"    build:\n      context: .\n      dockerfile_inline: |\n        FROM a\n", ReasonComposeBuildInline},
		"remote context":      {"    build: https://example.com/r.git\n", ReasonComposeBuildRemote},
		"additional_contexts": {"    build:\n      context: .\n      additional_contexts:\n        b: ./b\n", ReasonComposeBuildAdditional},
		"variable":            {"    build: ${CTX}\n", ReasonComposeVariable},
		"path escape":         {"    build: ../../x\n", ReasonComposeBuildPath},
	} {
		t.Run(name, func(t *testing.T) {
			it, e := run(compose(c.build), cm)
			if it.Category != CategoryManual || it.Reason != c.reason {
				t.Errorf("item = %s/%s", it.Category, it.Reason)
			}
			if len(e.scn.calls) != 0 {
				t.Error("scans were made although the built Dockerfile is not known")
			}
		})
	}
	t.Run("no build section is ignored", func(t *testing.T) {
		if it, _ := run(compose(""), cm); it.Category != CategoryPRCandidate {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("a Compose mapping in another repository is read too", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/deploy", ".", "compose.yml", compose("    build: https://example.com/r.git\n"))
		other := cm
		other.Repository = "ex/deploy"
		it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, []ComposeMapping{other},
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)))
		if it.Category != CategoryManual || it.Reason != ReasonComposeBuildRemote {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
}

func TestDockerfileComposeDerivationFailureStopsTheUnit(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", ""), dfMapping("compose/p/worker", "Dockerfile", "")}
	cms := []ComposeMapping{
		{Workload: "compose/p/app", Project: "p", Service: "app", Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: "app"},
		{Workload: "compose/p/worker", Project: "p", Service: "worker", Repository: "ex/app", BaseBranch: "main", Path: "compose.yml", ComposeService: "worker"},
	}
	inputs := func() []ImageInput {
		return []ImageInput{
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
			dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...),
		}
	}
	compose := "services:\n  app:\n    image: myapp:1\n  worker:\n    image: myworker:1\n    build: ${CTX}\n"

	t.Run("a variable in the other workload's build section", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "compose.yml", compose)
		plan := e.plan(t, bigLimits, maps, cms, inputs()...)
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryManual || it.Reason != ReasonComposeVariable || len(it.Workloads) != 2 {
			t.Errorf("item = %s/%s workloads %v", it.Category, it.Reason, it.Workloads)
		}
		if len(e.scn.calls) != 0 {
			t.Error("scans were made for a unit that cannot be adopted")
		}
	})
	t.Run("the same in the other order", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "compose.yml", compose)
		in := inputs()
		plan := e.plan(t, bigLimits, []DockerfileMapping{maps[1], maps[0]}, []ComposeMapping{cms[1], cms[0]}, in[1], in[0])
		if it := onlyDockerfile(t, plan); it.Category != CategoryManual || it.Reason != ReasonComposeVariable || len(it.Workloads) != 2 {
			t.Errorf("item = %s/%s workloads %v", it.Category, it.Reason, it.Workloads)
		}
	})
	t.Run("a Compose file that cannot be read is not read as having no build section", func(t *testing.T) {
		for name, c := range map[string]struct {
			err error
			cat Category
		}{
			"not found":    {nil, CategoryFailed},
			"rate limited": {&github.RateLimitedError{}, CategoryDeferred},
			"forbidden":    {github.ErrForbidden, CategoryFailed},
		} {
			e := newDFEnv()
			e.standard()
			if c.err != nil {
				e.gh.put("ex/app", ".", "compose.yml", "services: {}\n")
				e.gh.readErr["ex/app/compose.yml"] = c.err
			}
			plan := e.plan(t, bigLimits, maps[:1], cms[:1], inputs()[0])
			if it := onlyDockerfile(t, plan); it.Category != c.cat || len(e.scn.calls) != 0 {
				t.Errorf("%s: item = %s/%s (%s), scans %d", name, it.Category, it.Reason, it.Detail, len(e.scn.calls))
			}
		}
	})
	t.Run("a Compose branch that cannot be resolved", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		other := cms[0]
		other.Repository = "ex/deploy"
		e.gh.branchErr["ex/deploy"] = github.ErrNotFound
		it := onlyDockerfile(t, e.plan(t, bigLimits, maps[:1], []ComposeMapping{other}, inputs()[0]))
		if it.Category != CategoryFailed || it.Reason != ReasonSourceNotFound {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
		e.gh.branchErr["ex/deploy"] = &github.RateLimitedError{}
		e2 := newDFEnv()
		e2.standard()
		e2.gh.branchErr["ex/deploy"] = &github.RateLimitedError{}
		if it := onlyDockerfile(t, e2.plan(t, bigLimits, maps[:1], []ComposeMapping{other}, inputs()[0])); it.Category != CategoryDeferred {
			t.Errorf("rate limited: item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("a confirmed absence is a plan input", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		e.gh.put("ex/app", ".", "compose.yml", "services:\n  app:\n    image: myapp:1\n")
		it := onlyDockerfile(t, e.plan(t, bigLimits, maps[:1], cms[:1], inputs()[0]))
		if it.Category != CategoryPRCandidate {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		var paths []string
		for _, f := range it.Source.Files {
			paths = append(paths, f.Path)
		}
		if strings.Join(paths, ",") != "compose.yml,Dockerfile" && strings.Join(paths, ",") != "Dockerfile,compose.yml" {
			t.Errorf("files = %v, want the Compose file that showed no build section and the Dockerfile", paths)
		}
	})
	t.Run("a Compose file of another repository is recorded with its place", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		other := cms[0]
		other.Repository = "ex/deploy"
		e.gh.put("ex/deploy", ".", "compose.yml", "services:\n  app:\n    image: myapp:1\n")
		it := onlyDockerfile(t, e.plan(t, bigLimits, maps[:1], []ComposeMapping{other}, inputs()[0]))
		found := false
		for _, f := range it.Source.Files {
			found = found || (f.Path == "compose.yml" && f.Repository == "ex/deploy" && f.BaseBranch == "main")
		}
		if !found {
			t.Errorf("files = %+v", it.Source.Files)
		}
	})
}

func TestDockerfileTargetsSharingAFromAreAllChecked(t *testing.T) {
	cases := map[string]struct {
		file   string
		reason Reason
	}{
		"one inherits an ONBUILD stage":              {"FROM python:3.12.3-slim AS base\nONBUILD RUN x\nFROM base AS web\n", ReasonDockerfileOnBuild},
		"a platform between one target and the FROM": {"FROM python:3.12.3-slim AS base\nFROM --platform=linux/amd64 base AS mid\nFROM mid AS web\n", ReasonDockerfileStagePlatform},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ms := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "base"), dfMapping("compose/p/worker", "Dockerfile", "web")}
			for order := 0; order < 2; order++ {
				e := newDFEnv()
				e.standard()
				e.gh.put("ex/app", ".", "Dockerfile", c.file)
				in := []ImageInput{
					dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...),
					dfInput("myworker:1", 'b', "worker", appLayers, standardFindings()...),
				}
				if order == 1 {
					ms[0], ms[1] = ms[1], ms[0]
					in[0], in[1] = in[1], in[0]
				}
				it := onlyDockerfile(t, e.plan(t, bigLimits, ms, nil, in...))
				if it.Category != CategoryManual || it.Reason != c.reason || len(it.Workloads) != 2 {
					t.Errorf("order %d: item = %s/%s workloads %v", order, it.Category, it.Reason, it.Workloads)
				}
				if len(e.scn.calls) != 0 {
					t.Errorf("order %d: scans were made", order)
				}
			}
		})
	}
}

// countEntity is a running image with targets and the comparison verdicts of
// them: resolved ones, remaining ones; compared false leaves the comparison
// out.
func countEntity(ref string, compared bool, resolved, remaining, notJudged []string) DockerfileEntity {
	e := DockerfileEntity{Running: ImageState{Ref: ref, Entity: ref}}
	if compared {
		e.Comparison = &VerificationResult{Comparable: true}
	}
	add := func(id string, o Outcome, judged bool) {
		e.Targets = append(e.Targets, Target{VulnID: id, Package: PackageCoord{Name: "p-" + id}})
		if compared && judged {
			e.Comparison.Verdicts = append(e.Comparison.Verdicts, VulnVerdict{VulnID: id, Package: PackageCoord{Name: "p-" + id}, Outcome: o})
		}
	}
	for _, id := range resolved {
		add(id, OutcomeResolved, true)
	}
	for _, id := range remaining {
		add(id, OutcomeRemaining, true)
	}
	for _, id := range notJudged {
		add(id, OutcomeUnknown, false)
	}
	return e
}

// TestDockerfileCountsPerEntityTargets: a target is judged on the images that
// have it, and an image that lacks it says nothing about it.
func TestDockerfileCountsPerEntityTargets(t *testing.T) {
	cases := []struct {
		name string
		ents []DockerfileEntity
		want DockerfileCounts
	}{
		{"each image compares only its own target", []DockerfileEntity{
			countEntity("amd64", true, []string{"X"}, nil, nil), countEntity("arm64", true, []string{"Y"}, nil, nil)},
			DockerfileCounts{Targets: 2, Resolved: 2}},
		{"an image that has the target was not compared", []DockerfileEntity{
			countEntity("amd64", true, []string{"X"}, nil, nil), countEntity("arm64", false, []string{"Y"}, nil, nil)},
			DockerfileCounts{Targets: 2, Resolved: 1}},
		{"an image whose verdict is missing for its target", []DockerfileEntity{
			countEntity("amd64", true, []string{"X"}, nil, nil), countEntity("arm64", true, nil, nil, []string{"Y"})},
			DockerfileCounts{Targets: 2, Resolved: 1}},
		{"one image leaves its target remaining", []DockerfileEntity{
			countEntity("amd64", true, []string{"X"}, nil, nil), countEntity("arm64", true, nil, []string{"Y"}, nil)},
			DockerfileCounts{Targets: 2, Resolved: 1, Remaining: 1}},
		{"a shared target remains on one of two images", []DockerfileEntity{
			countEntity("amd64", true, []string{"X"}, nil, nil), countEntity("arm64", true, nil, []string{"X"}, nil)},
			DockerfileCounts{Targets: 1, Remaining: 1}},
		{"a shared target resolved on both", []DockerfileEntity{
			countEntity("amd64", true, []string{"X"}, nil, nil), countEntity("arm64", true, []string{"X"}, nil, nil)},
			DockerfileCounts{Targets: 1, Resolved: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dockerfileCounts(c.ents); got != c.want {
				t.Errorf("counts = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestDockerfileCountsInAPlan: the same through a plan, with the comparison
// results of the two platforms split.
func TestDockerfileCountsInAPlan(t *testing.T) {
	e := newDFEnv()
	e.standard()
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'), nil, pkgs("libc", "2", "openssl", "2"))
	arm := dfInput("myworker:1", 'b', "worker", appLayers, layered(finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh), 'a'))
	arm.Scan.Platform.Architecture = "arm64"
	arm.Scan.Subject.Key.Platform = arm.Scan.Platform
	ms := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", ""), dfMapping("compose/p/worker", "Dockerfile", "")}
	it := onlyDockerfile(t, e.plan(t, bigLimits, ms, nil,
		dfInput("myapp:1", 'a', "app", appLayers, layered(finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), 'b')), arm))
	if it.Category != CategoryPRCandidate || it.Counts.Targets != 2 || it.Counts.Resolved != 2 || it.Counts.Remaining != 0 {
		t.Errorf("item = %s/%s counts %+v", it.Category, it.Reason, it.Counts)
	}
}
