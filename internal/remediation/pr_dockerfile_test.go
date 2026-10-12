package remediation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	dfBase    = "python:3.12.3-slim"
	dfContent = "FROM python:3.12.3-slim\nCOPY . /app\n"
	// dfApp is the workload that runs the image built from the Dockerfile.
	dfApp = "compose/app/svc"
)

// dfEntityOf is a running image of the Dockerfile with its comparison: every
// vulnerability in resolved is resolved by the candidate base, every one in
// remaining remains.
func dfEntityOf(ref string, h byte, cand ImageState, resolved, remaining []string) DockerfileEntity {
	en := DockerfileEntity{
		Services:      []ServiceRef{{Project: "app", Service: "svc", Container: "app-svc-1"}},
		Running:       ImageState{Ref: ref, Entity: entityString(configKey(h)), ConfigDigest: "sha256:" + hex64(h), Platform: "linux/amd64", DigestKindUnverified: true},
		CurrentBase:   &ImageState{Ref: dfBase, Tag: "3.12.3-slim", TopDigest: topDigest('0'), ManifestDigest: "sha256:" + hex64('1'), ConfigDigest: "sha256:" + hex64('2'), Platform: "linux/amd64"},
		CandidateBase: &cand,
		Layers:        LayerConfirmation{Status: "confirmed", BaseLayers: 2, ImageLayers: 3},
		Category:      CategoryPRCandidate, Reason: ReasonAdopted,
		BaselineScan: "s1", CandidateScan: "s2",
		Comparison: &VerificationResult{Comparable: true, Severities: []string{"CRITICAL", "HIGH"}, Scope: "only findings of severity CRITICAL, HIGH were evaluated"},
	}
	add := func(id string, o Outcome) {
		en.Targets = append(en.Targets, Target{VulnID: id, Package: pkgCoord("pkg-" + id), Severity: scanner.Severity("HIGH"), Layers: []string{diffID('a')}})
		en.Comparison.Verdicts = append(en.Comparison.Verdicts, VulnVerdict{VulnID: id, Package: pkgCoord("pkg-" + id), Outcome: o})
	}
	for _, id := range resolved {
		add(id, OutcomeResolved)
	}
	for _, id := range remaining {
		add(id, OutcomeRemaining)
	}
	return en
}

func dfCandidate(tag string, top byte) ImageState {
	return ImageState{Ref: "python:" + tag, Tag: tag, TopDigest: topDigest(top), ManifestDigest: "sha256:" + hex64('m'), ConfigDigest: "sha256:" + hex64('c'), Platform: "linux/amd64"}
}

// dfPlanItemOf is an adopted Dockerfile item for the Dockerfile at the root of
// the test repository, built from python:3.12.3-slim, for the running images.
func dfPlanItemOf(tag string, top byte, ents ...DockerfileEntity) DockerfileItem {
	stage := 0
	cand := dfCandidate(tag, top)
	it := DockerfileItem{
		Key:       "dockerfile:" + strings.ToLower(testRepo) + "@main:Dockerfile#stages[0]",
		Workloads: []string{dfApp},
		Category:  CategoryPRCandidate, Reason: ReasonAdopted,
		Source:  DockerfileSource{Repository: testRepo, BaseBranch: "main", Path: "Dockerfile", Stage: &stage, Line: 1, Origin: DockerfileFromMapping, Targets: []string{""}},
		BaseRef: dfBase, BaseKind: TagPinned,
		Candidate: &cand,
		Entities:  ents,
	}
	for _, e := range ents {
		it.Counts.Targets += len(e.Targets)
		it.Counts.Resolved += len(e.Targets)
	}
	return it
}

// dfPlanItem is an adopted item with one running image, myapp:1.
func dfPlanItem(tag string, top byte, resolved, remaining []string) DockerfileItem {
	it := dfPlanItemOf(tag, top, dfEntityOf("myapp:1", 'a', dfCandidate(tag, top), resolved, remaining))
	it.Counts = DockerfileCounts{Targets: len(resolved) + len(remaining), Resolved: len(resolved), Remaining: len(remaining)}
	return it
}

func dfPlan(items ...DockerfileItem) Plan {
	p := testPlan()
	p.DockerfileItems = items
	return p
}

// newDFPRHarness has the Dockerfile next to the Compose file in the test
// repository.
func newDFPRHarness(t *testing.T) *prHarness {
	t.Helper()
	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": dfContent})
	h.gh.humanMoved = map[string]bool{}
	h.gh.tops["python:3.12.5-slim"] = topDigest('5')
	h.gh.tops["python:3.12.6-slim"] = topDigest('6')
	return h
}

func TestPRStageDockerfileCreate(t *testing.T) {
	h := newDFPRHarness(t)
	res := h.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1", "CVE-2"}, []string{"CVE-3"})))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if u.Kind != "dockerfile" || u.Path != "Dockerfile" || u.Current != dfBase || u.CandidateTag != "3.12.5-slim" ||
		len(u.Locations) != 1 || u.Locations[0] != "stages[0]" || len(u.Services) != 1 || u.Services[0] != "svc" || u.Number != 1 {
		t.Errorf("unit = %+v", u)
	}
	if len(u.FixTargets) != 2 || len(u.FixTargets[0].Layers) != 1 {
		t.Errorf("fix targets = %+v", u.FixTargets)
	}
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 1 {
		t.Fatalf("pulls = %d", len(pulls))
	}
	pr := pulls[0]
	if pr.Title != "Update base image python to 3.12.5-slim in Dockerfile" || !strings.HasPrefix(pr.HeadRef, "kestrelynx/dockerfile/svc-3.12.5-slim-") {
		t.Errorf("title %q head %q", pr.Title, pr.HeadRef)
	}
	f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "Dockerfile")
	if err != nil || string(f.Content) != "FROM python:3.12.5-slim\nCOPY . /app\n" {
		t.Errorf("edited file %q err %v", f.Content, err)
	}
	if c, _ := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "compose.yml"); string(c.Content) != composeYML {
		t.Error("another file changed")
	}

	// The marker names the kind and recomputes.
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Kind != "dockerfile" || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) {
		t.Fatalf("marker %+v err %v", m, err)
	}
	for _, ft := range m.FixTargets {
		if len(ft.Layers) != 1 || len(ft.Entities) != 0 {
			t.Errorf("marker fix target = %+v, want its layers and no entities", ft)
		}
	}
	if m.TargetKey != TargetKeyOf("dockerfile", testRepoID, "main", "Dockerfile", []string{"stages[0]"}) {
		t.Error("the target key does not name the Dockerfile and its FROM")
	}

	// The body names the three images and carries no introduction to them.
	for _, want := range []string{
		"Running image: `myapp:1`", "Current base image: `python:3.12.3-slim`", "Candidate base image: `python:3.12.5-slim`",
		"Layer check: `confirmed`",
		"resolved 2, remaining 1", "introduced by the candidate base image: 0",
		"FROM on line 1: `python:3.12.3-slim` to `python:3.12.5-slim`", "`compose/app/svc`",
	} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q", want)
		}
	}
	for _, gone := range []string{"Three images are involved", "was not built or scanned"} {
		if strings.Contains(pr.Body, gone) {
			t.Errorf("the body still has %q", gone)
		}
	}
	lines := strings.Split(strings.TrimRight(pr.Body, "\n"), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], markerPrefix) {
		t.Error("the marker is not the last line")
	}

	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].Kind != "dockerfile" || rec.PRs[0].CurrentRef != dfBase || rec.Attempts[0].Kind != "dockerfile" {
		t.Errorf("records = %+v / %+v", rec.PRs, rec.Attempts)
	}
	ev := rec.PRs[0].Evidence
	if ev == nil || len(ev.Items) != 1 || ev.Items[0].CurrentBase == nil || ev.Items[0].Layers == nil || len(ev.Items[0].Resolved) != 2 || len(ev.Items[0].Remaining) != 1 {
		t.Errorf("evidence = %+v", ev)
	}
	if len(res.Operations) != 10 {
		t.Errorf("operations = %d", len(res.Operations))
	}
}

func TestPRStageDockerfileIdempotentAndSuppressed(t *testing.T) {
	h := newDFPRHarness(t)
	plan := dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil))
	res := h.run(plan)
	if err := MarkPROperationsDelivered(h.store, res.LastSeq); err != nil {
		t.Fatal(err)
	}
	writes := h.gh.writeCount()
	res2 := h.run(plan)
	wantStatus(t, onlyUnit(t, res2), PRStatusOpen, "")
	if h.gh.writeCount() != writes || len(res2.Operations) != 0 {
		t.Errorf("the second cycle wrote %d times", h.gh.writeCount()-writes)
	}

	// The base moves: the same update is not proposed again.
	h.gh.commitFiles(testRepo, "main", map[string]string{"README": "x"})
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusOpen, "")

	// Closed, then merged records are never recreated.
	h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State = "closed" })
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusSuppressed, "")
	h.gh.commitFiles(testRepo, "main", map[string]string{"README": "y"})
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusSuppressed, "")
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageDockerfileMerged(t *testing.T) {
	h := newDFPRHarness(t)
	plan := dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil))
	h.run(plan)
	h.gh.editPull(testRepo, 1, func(p *github.PullRequest) { p.State, p.Merged = "closed", true })
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusMerged, "")
}

func TestPRStageDockerfileUserModified(t *testing.T) {
	h := newDFPRHarness(t)
	h.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)))
	h.gh.pushToPull(testRepo, 1)
	// A newer candidate resolving everything would replace #1, but a pull
	// request someone changed is never replaced, commented on or closed.
	res := h.run(dfPlan(dfPlanItem("3.12.6-slim", '6', []string{"CVE-1", "CVE-2"}, nil)))
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	old := h.load().PRs[0]
	if !old.UserModified || old.State != PRStateOpen {
		t.Errorf("old record = %+v", old)
	}
	if p := h.gh.pulls(testRepo)[0]; p.State != "open" || len(h.gh.comments(testRepo, 1)) != 0 {
		t.Errorf("the changed pull request was touched: %+v", p)
	}
	wantStatus(t, onlyUnit(t, h.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)))), PRStatusOpen, "")
}

func TestPRStageDockerfileReplacement(t *testing.T) {
	h := newDFPRHarness(t)
	h.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)))
	res := h.run(dfPlan(dfPlanItem("3.12.6-slim", '6', []string{"CVE-1", "CVE-2"}, nil)))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Replaced) != 1 || u.Replaced[0] != 1 {
		t.Errorf("replaced = %v (%+v)", u.Replaced, u.Replacing)
	}
	if p := h.gh.pulls(testRepo)[0]; p.State != "closed" {
		t.Errorf("old pull request state = %s", p.State)
	}

	// An older pull request whose targets the newer one does not resolve stays.
	h2 := newDFPRHarness(t)
	h2.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1", "CVE-3"}, nil)))
	wantStatus(t, onlyUnit(t, h2.run(dfPlan(dfPlanItem("3.12.6-slim", '6', []string{"CVE-1"}, []string{"CVE-3"})))), PRStatusCreated, "")
	if p := h2.gh.pulls(testRepo)[0]; p.State != "open" {
		t.Error("the old pull request was closed although the new one does not resolve all its targets")
	}
}

func TestPRStageDockerfileRecoveryFromMarkers(t *testing.T) {
	h := newDFPRHarness(t)
	plan := dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil))
	h.run(plan)
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusOpen, "")
	rec := h.load()
	if len(rec.PRs) != 1 || !rec.PRs[0].Recovered || rec.PRs[0].Kind != "dockerfile" || !rec.PRs[0].MarkerOnly {
		t.Errorf("recovered records = %+v", rec.PRs)
	}
	if n := len(h.gh.pulls(testRepo)); n != 1 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageDockerfileAndComposeShareTheStage(t *testing.T) {
	h := newDFPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	plan.DockerfileItems = []DockerfileItem{dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)}
	res := h.run(plan)
	if len(res.Units) != 2 {
		t.Fatalf("units = %+v", res.Units)
	}
	var kinds []string
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusCreated, "")
		kinds = append(kinds, u.Kind)
	}
	if kinds[0] != "" || kinds[1] != "dockerfile" {
		t.Errorf("kinds = %q", kinds)
	}
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 2 || !strings.HasPrefix(pulls[0].HeadRef, "kestrelynx/compose/") || !strings.HasPrefix(pulls[1].HeadRef, "kestrelynx/dockerfile/") {
		t.Fatalf("pulls = %+v", pulls)
	}
	// Each pull request changes its own file only.
	if f, _ := h.gh.ReadFile(context.Background(), testRepo, pulls[0].HeadSHA, "Dockerfile"); string(f.Content) != dfContent {
		t.Error("the Compose pull request changed the Dockerfile")
	}
	if f, _ := h.gh.ReadFile(context.Background(), testRepo, pulls[1].HeadSHA, "compose.yml"); string(f.Content) != composeYML {
		t.Error("the Dockerfile pull request changed the Compose file")
	}
	// A Compose marker has no kind, so it reads as it did before.
	if strings.Contains(pulls[0].Body, `"kind"`) {
		t.Error("a Compose marker names a kind")
	}
	// Both are open on the next cycle, and recovered after the records are lost.
	res = h.run(plan)
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusOpen, "")
	}
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	res = h.run(plan)
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusOpen, "")
	}
	if n := len(h.gh.pulls(testRepo)); n != 2 {
		t.Errorf("pulls = %d", n)
	}
}

func TestPRStageDockerfileSharedLimits(t *testing.T) {
	h := newDFPRHarness(t)
	h.limits = PRLimits{NewPRsPerCycle: 1, OpenPRs: 10}
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	plan.DockerfileItems = []DockerfileItem{dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)}
	res := h.run(plan)
	wantStatus(t, res.Units[0], PRStatusCreated, "")
	wantStatus(t, res.Units[1], PRStatusDeferred, ReasonPRLimit)

	// The open limit counts both kinds.
	h.limits = PRLimits{NewPRsPerCycle: 5, OpenPRs: 1}
	res = h.run(plan)
	wantStatus(t, res.Units[0], PRStatusOpen, "")
	wantStatus(t, res.Units[1], PRStatusDeferred, ReasonPRLimit)
	h.limits = PRLimits{NewPRsPerCycle: 5, OpenPRs: 2}
	res = h.run(plan)
	wantStatus(t, res.Units[1], PRStatusCreated, "")
}

func TestPRStageDockerfileEditProblems(t *testing.T) {
	cases := map[string]struct {
		file   string
		reason Reason
	}{
		"another tag in the file":   {"FROM python:3.12.4-slim\n", ReasonDockerfileSourceMismatch},
		"another image in the file": {"FROM node:3.12.3-slim\n", ReasonDockerfileSourceMismatch},
		"a variable now":            {"ARG V=1\nFROM python:${V}\n", ReasonDockerfileVariable},
		"ONBUILD in a parent stage": {"FROM python:3.12.3-slim AS base\nONBUILD RUN x\nFROM base\n", ReasonDockerfileOnBuild},
		"the FROM moved to a stage": {"FROM alpine:3.19.1 AS tools\nFROM python:3.12.3-slim\n", ReasonDockerfileSourceMismatch},
		"not a Dockerfile any more": {"RUN echo hi\n", ReasonDockerfileInvalid},
		"digest instead of the tag": {"FROM python:3.12.3-slim@sha256:" + hex64('e') + "\n", ReasonDockerfileDigest},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newDFPRHarness(t)
			h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": c.file})
			u := onlyUnit(t, h.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil))))
			if u.Status != PRStatusManual || u.Reason != c.reason {
				t.Errorf("unit = %s/%s (%s)", u.Status, u.Reason, u.Detail)
			}
			if h.gh.writeCount() != 0 {
				t.Errorf("writes = %d", h.gh.writeCount())
			}
		})
	}
}

func TestPRStageDockerfileFileProblems(t *testing.T) {
	h := newDFPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": dfContent})
	it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	it.Source.Path = "build/Dockerfile"
	u := onlyUnit(t, h.run(dfPlan(it)))
	wantStatus(t, u, PRStatusManual, ReasonDockerfileFileNotFound)
}

func TestPRStageDockerfileSeveralTargetsMustAgree(t *testing.T) {
	h := newDFPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": "FROM python:3.12.3-slim AS base\nFROM base AS web\nFROM base AS worker\n"})
	it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	it.Source.Targets = []string{"web", "worker"}
	it.Source.StageName = "base"
	u := onlyUnit(t, h.run(dfPlan(it)))
	wantStatus(t, u, PRStatusCreated, "")
	f, _ := h.gh.ReadFile(context.Background(), testRepo, h.gh.pulls(testRepo)[0].HeadSHA, "Dockerfile")
	if string(f.Content) != "FROM python:3.12.5-slim AS base\nFROM base AS web\nFROM base AS worker\n" {
		t.Errorf("file = %q", f.Content)
	}

	// A target that now leads to another FROM stops the unit.
	h2 := newDFPRHarness(t)
	h2.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": "FROM python:3.12.3-slim AS base\nFROM python:3.12.3-slim AS worker\nFROM base AS web\n"})
	it.Source.Targets = []string{"web", "worker"}
	u = onlyUnit(t, h2.run(dfPlan(it)))
	if u.Status != PRStatusManual {
		t.Errorf("unit = %s/%s (%s)", u.Status, u.Reason, u.Detail)
	}
}

func TestPRStageDockerfileEditedStageMustBeThePlanned(t *testing.T) {
	h := newDFPRHarness(t)
	// The plan was made for stage 1; the file now has the FROM at stage 0.
	it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	one := 1
	it.Source.Stage = &one
	u := onlyUnit(t, h.run(dfPlan(it)))
	wantStatus(t, u, PRStatusManual, ReasonDockerfileSourceMismatch)
}

func TestPRStageDockerfileRepositoryOnlyInDockerfileMappings(t *testing.T) {
	h := newDFPRHarness(t)
	h.gh.addRepo("example/other", 202, map[string]string{"Dockerfile": dfContent})
	it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	it.Source.Repository = "example/other"
	h.mappings = nil
	h.gh.humanMoved = map[string]bool{}
	stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: h.gh, Store: h.store, Limits: h.limits})
	if err != nil {
		t.Fatal(err)
	}
	res := stage.Run(context.Background(), PRStageInput{Plan: dfPlan(it), Repositories: []string{"example/other"}})
	wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
	if n := len(h.gh.pulls("example/other")); n != 1 {
		t.Errorf("pulls = %d", n)
	}
	// Even without the repository listed, a unit's repository is examined.
	res = stage.Run(context.Background(), PRStageInput{Plan: dfPlan(it)})
	wantStatus(t, onlyUnit(t, res), PRStatusOpen, "")
}

func TestPRStageNonAdoptedDockerfileItemsMakeNoUnit(t *testing.T) {
	h := newDFPRHarness(t)
	manual := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	manual.Category, manual.Reason = CategoryManual, ReasonDockerfileSetNotAdopted
	floating := dfPlanItem("3.12.5-slim", '5', nil, nil)
	floating.Category, floating.Reason, floating.Candidate = CategoryNotComparable, ReasonFloatingBaseUnconfirmed, nil
	res := h.run(dfPlan(manual, floating))
	if len(res.Units) != 0 || h.gh.writeCount() != 0 {
		t.Errorf("units = %+v, writes %d", res.Units, h.gh.writeCount())
	}
}

func TestDockerfileKeysAndBranch(t *testing.T) {
	tk := TargetKeyOf("dockerfile", 1, "main", "Dockerfile", []string{"stages[0]"})
	if tk == TargetKeyOf("compose", 1, "main", "Dockerfile", []string{"stages[0]"}) {
		t.Error("the kind is not part of the target key")
	}
	if tk == TargetKeyOf("dockerfile", 1, "main", "Dockerfile", []string{"stages[1]:runtime"}) || tk == TargetKeyOf("dockerfile", 1, "main", "app/Dockerfile", []string{"stages[0]"}) ||
		tk == TargetKeyOf("dockerfile", 1, "dev", "Dockerfile", []string{"stages[0]"}) || tk == TargetKeyOf("dockerfile", 2, "main", "Dockerfile", []string{"stages[0]"}) {
		t.Error("repository, branch, Dockerfile and FROM position must each change the key")
	}
	if TargetKey(1, "main", "compose.yml", []string{"services.web.image"}) != TargetKeyOf("compose", 1, "main", "compose.yml", []string{"services.web.image"}) {
		t.Error("the Compose target key changed")
	}
	// The update key follows the base and the candidate.
	a := UpdateKey(tk, dfBase, "3.12.5-slim", topDigest('5'))
	if a == UpdateKey(tk, "python:3.12.4-slim", "3.12.5-slim", topDigest('5')) || a == UpdateKey(tk, dfBase, "3.12.6-slim", topDigest('5')) || a == UpdateKey(tk, dfBase, "3.12.5-slim", topDigest('6')) {
		t.Error("the base, candidate tag and candidate digest must each change the update key")
	}
	b, err := DockerfileBranchName([]string{"worker", "app"}, "3.12.5-slim", strings.Repeat("ab", 8))
	if err != nil || !strings.HasPrefix(b, "kestrelynx/dockerfile/app-and-1-3.12.5-slim-abababababab") {
		t.Errorf("branch = %q err %v", b, err)
	}
	if !strings.HasPrefix(dockerfileUnitTitle("python", "3.12.5-slim", "Dockerfile"), "Update base image python to 3.12.5-slim") {
		t.Error("title")
	}
}

func TestDockerfileMarkerKinds(t *testing.T) {
	m := sampleMarker()
	m.Kind = "dockerfile"
	m.TargetKey = TargetKeyOf("dockerfile", m.RepoID, m.BaseBranch, m.Path, m.Locations)
	m.UpdateKey = UpdateKey(m.TargetKey, m.CurrentRef, m.CandidateTag, m.CandidateDigest)
	m.AttemptKey = AttemptKey(m.UpdateKey, m.BaseSHA, m.InputBlobSHA, m.Changes)
	body := "text\n" + encodeMarker(m)
	got, err := parsePRMarker(body)
	if err != nil || got.Kind != "dockerfile" || got.verify(m.RepoID) != nil {
		t.Fatalf("marker %+v err %v", got, err)
	}
	// The same inputs under another kind do not verify.
	wrong := m
	wrong.Kind = ""
	if wrong.verify(m.RepoID) == nil {
		t.Error("a Dockerfile marker verified as a Compose one")
	}
	bad := m
	bad.Kind = "other"
	if _, err := parsePRMarker("x\n" + encodeMarker(bad)); err == nil {
		t.Error("an unknown kind was accepted")
	}
	// A Dockerfile attempt's branch is not a Compose one.
	if got.branchMatches(composeBranchPrefix + "x-" + got.AttemptKey[:12]) {
		t.Error("a Compose branch matched a Dockerfile marker")
	}
	if !got.branchMatches(dockerfileBranchPrefix + "x-" + got.AttemptKey[:12]) {
		t.Error("the Dockerfile branch did not match")
	}
}

// dfPlannedAt is an adopted item whose files were read at the repository's
// current base commit.
func dfPlannedAt(h *prHarness, files ...SourceFile) DockerfileItem {
	it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
	it.Source.CommitSHA = h.gh.branch(testRepo, "main")
	it.Source.Files = files
	return it
}

func dfFile(path, content string) SourceFile {
	return SourceFile{Path: path, BlobSHA: gitBlobSHA([]byte(content))}
}

func TestPRStageDockerfileDefersWhenPlannedFilesChanged(t *testing.T) {
	t.Run("unchanged files after the base moved are used", func(t *testing.T) {
		h := newDFPRHarness(t)
		it := dfPlannedAt(h, dfFile("Dockerfile", dfContent))
		h.gh.commitFiles(testRepo, "main", map[string]string{"README": "x"})
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusCreated, "")
	})
	t.Run("the platform changed", func(t *testing.T) {
		h := newDFPRHarness(t)
		it := dfPlannedAt(h, dfFile("Dockerfile", dfContent))
		h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": "FROM --platform=linux/arm64 python:3.12.3-slim\nCOPY . /app\n"})
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusDeferred, ReasonSourceChanged)
		if h.gh.writeCount() != 0 {
			t.Error("a write was made")
		}
	})
	t.Run("the build target changed in the Compose file", func(t *testing.T) {
		h := newDFPRHarness(t)
		compose := "services:\n  svc:\n    build:\n      context: .\n      target: web\n"
		h.gh.commitFiles(testRepo, "main", map[string]string{"compose.yml": compose})
		it := dfPlannedAt(h, dfFile("compose.yml", compose), dfFile("Dockerfile", dfContent))
		h.gh.commitFiles(testRepo, "main", map[string]string{"compose.yml": strings.Replace(compose, "web", "worker", 1)})
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusDeferred, ReasonSourceChanged)
	})
	t.Run("the Dockerfile moved", func(t *testing.T) {
		h := newDFPRHarness(t)
		it := dfPlannedAt(h, dfFile("old/Dockerfile", dfContent))
		it.Source.Path = "old/Dockerfile"
		h.gh.commitFiles(testRepo, "main", map[string]string{"README": "x"})
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusDeferred, ReasonSourceChanged)
	})
	t.Run("without a commit the stage and platform are still checked", func(t *testing.T) {
		h := newDFPRHarness(t)
		it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)
		h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": "FROM --platform=linux/arm64 python:3.12.3-slim\nCOPY . /app\n"})
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusManual, ReasonDockerfileSourceMismatch)

		h2 := newDFPRHarness(t)
		h2.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": "FROM python:3.12.3-slim AS other\n"})
		wantStatus(t, onlyUnit(t, h2.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1"}, nil)))), PRStatusManual, ReasonDockerfileSourceMismatch)
	})
}

// TestPRStageDockerfileTargetsKeepTheirImages: image A resolves X and Y, image
// B resolves X. A newer pull request that leaves Y for A does not replace the
// old one, and neither does one that drops B.
func TestPRStageDockerfileTargetsKeepTheirImages(t *testing.T) {
	ents := func(tag string, top byte, a, b []string) []DockerfileEntity {
		c := dfCandidate(tag, top)
		out := []DockerfileEntity{dfEntityOf("myapp:1", 'a', c, a, nil)}
		if b != nil {
			out = append(out, dfEntityOf("myworker:1", 'b', c, b, nil))
		}
		return out
	}
	first := func(h *prHarness) {
		h.run(dfPlan(dfPlanItemOf("3.12.5-slim", '5', ents("3.12.5-slim", '5', []string{"X", "Y"}, []string{"X"})...)))
		rec := h.load()
		if len(rec.PRs) != 1 || len(rec.PRs[0].FixTargets) != 2 {
			t.Fatalf("fix targets = %+v", rec.PRs)
		}
		for _, ft := range rec.PRs[0].FixTargets {
			want := 1
			if ft.VulnID == "X" {
				want = 2
			}
			if len(ft.Entities) != want || len(ft.Layers) != 1 {
				t.Errorf("fix target %s = %+v, want it with %d image(s) and its layers", ft.VulnID, ft, want)
			}
		}
	}
	cases := []struct {
		name    string
		a, b    []string
		replace bool
	}{
		{"Y left for A", []string{"X"}, []string{"X"}, false},
		{"B dropped", []string{"X", "Y"}, nil, false},
		{"X left for B", []string{"X", "Y"}, []string{}, false},
		{"everything inherited", []string{"X", "Y", "Z"}, []string{"X"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newDFPRHarness(t)
			first(h)
			u := onlyUnit(t, h.run(dfPlan(dfPlanItemOf("3.12.6-slim", '6', ents("3.12.6-slim", '6', c.a, c.b)...))))
			wantStatus(t, u, PRStatusCreated, "")
			closed := h.gh.pulls(testRepo)[0].State == "closed"
			if closed != c.replace {
				t.Errorf("old pull request closed = %v, want %v (replaced %v)", closed, c.replace, u.Replaced)
			}
		})
	}
}

func TestPRStageDockerfileRecoveryKeepsLayers(t *testing.T) {
	h := newDFPRHarness(t)
	plan := dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1", "CVE-2"}, nil))
	h.run(plan)
	before := h.load().PRs[0].FixTargets
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	h.run(plan)
	after := h.load().PRs[0].FixTargets
	if len(after) != 2 {
		t.Fatalf("recovered fix targets = %+v", after)
	}
	for i := range after {
		if len(after[i].Layers) != 1 || after[i].Layers[0] != diffID('a') || after[i].key() != before[i].key() {
			t.Errorf("recovered %+v, was %+v", after[i], before[i])
		}
	}
}

func TestPRStageDockerfileLargeMarkerKeepsLayerDigests(t *testing.T) {
	h := newDFPRHarness(t)
	var ids []string
	for i := 0; i < 220; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2031-%04d", i))
	}
	plan := dfPlan(dfPlanItem("3.12.5-slim", '5', ids, nil))
	h.run(plan)
	pr := h.gh.pulls(testRepo)[0]
	m, err := parsePRMarker(pr.Body)
	if err != nil || len(m.FixTargets) != len(ids) {
		t.Fatalf("marker err %v targets %d", err, len(m.FixTargets))
	}
	if m.FixTargets[0].Layers != nil || m.FixTargets[0].LayersDigest == "" {
		t.Errorf("fix target = %+v, want the layer set's digest", m.FixTargets[0])
	}
	before := h.load().PRs[0].FixTargets
	if len(before[0].Layers) != 1 {
		t.Error("the record lost the full layers")
	}
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	h.run(plan)
	after := h.load().PRs[0].FixTargets
	for i := range after {
		if after[i].key() != before[i].key() {
			t.Fatalf("identity of %s changed through the digest", after[i].VulnID)
		}
	}
}

func TestPRStageDockerfileShowsWhatStays(t *testing.T) {
	h := newDFPRHarness(t)
	en := dfEntityOf("myapp:1", 'a', dfCandidate("3.12.5-slim", '5'), []string{"CVE-1"}, nil)
	// A finding of the compared bases the running image has no target for.
	en.Comparison.Verdicts = append(en.Comparison.Verdicts,
		VulnVerdict{VulnID: "CVE-OLD", Package: pkgCoord("pkg-old"), Severity: scanner.Severity("HIGH"), Outcome: OutcomeRemaining},
		VulnVerdict{VulnID: "CVE-GONE", Package: pkgCoord("pkg-gone"), Outcome: OutcomeResolved})
	it := dfPlanItemOf("3.12.5-slim", '5', en)
	wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusCreated, "")
	body := h.gh.pulls(testRepo)[0].Body
	for _, want := range []string{
		"remaining 0", "Other findings of the compared base images that remain in the candidate base image: 1",
		"**Remaining among the targeted findings (0)**", "**Other findings that remain in the candidate base image (1)**", "`CVE-OLD` in `pkg-old`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the body lacks %q", want)
		}
	}
	ev := h.load().PRs[0].Evidence.Items[0]
	if len(ev.Remaining) != 0 || len(ev.OtherRemaining) != 1 || ev.OtherRemaining[0].VulnID != "CVE-OLD" || len(ev.Resolved) != 1 {
		t.Errorf("evidence = resolved %+v remaining %+v other %+v", ev.Resolved, ev.Remaining, ev.OtherRemaining)
	}
}

// TestPRStageDockerfileDefersWhenAConfirmedAbsenceEnds: the plan read the
// Compose file to confirm the service has no build section; if the file later
// gains one, nothing is edited.
func TestPRStageDockerfileDefersWhenAConfirmedAbsenceEnds(t *testing.T) {
	noBuild := "services:\n  svc:\n    image: myapp:1\n"
	withInline := noBuild + "    build:\n      dockerfile_inline: |\n        FROM alpine\n"

	t.Run("same repository", func(t *testing.T) {
		h := newDFPRHarness(t)
		h.gh.commitFiles(testRepo, "main", map[string]string{"compose.yml": noBuild})
		it := dfPlannedAt(h, dfFile("compose.yml", noBuild), dfFile("Dockerfile", dfContent))
		h.gh.commitFiles(testRepo, "main", map[string]string{"compose.yml": withInline})
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusDeferred, ReasonSourceChanged)
		if h.gh.writeCount() != 0 {
			t.Error("a write was made")
		}
	})
	t.Run("another repository, whose branch is not the unit's", func(t *testing.T) {
		h := newDFPRHarness(t)
		h.gh.addRepo("example/deploy", 303, map[string]string{"compose.yml": noBuild})
		it := dfPlannedAt(h, dfFile("Dockerfile", dfContent))
		f := dfFile("compose.yml", noBuild)
		f.Repository, f.BaseBranch = "example/deploy", "main"
		it.Source.Files = append(it.Source.Files, f)
		// The base of the unit's repository has not moved.
		wantStatus(t, onlyUnit(t, h.run(dfPlan(it))), PRStatusCreated, "")

		h2 := newDFPRHarness(t)
		h2.gh.addRepo("example/deploy", 303, map[string]string{"compose.yml": noBuild})
		it2 := dfPlannedAt(h2, dfFile("Dockerfile", dfContent))
		it2.Source.Files = append(it2.Source.Files, f)
		h2.gh.commitFiles("example/deploy", "main", map[string]string{"compose.yml": withInline})
		wantStatus(t, onlyUnit(t, h2.run(dfPlan(it2))), PRStatusDeferred, ReasonSourceChanged)
	})
}

func TestPRStageDockerfileRechecksInputsBeforeOpening(t *testing.T) {
	noBuild := "services:\n  svc:\n    image: myapp:1\n"
	h := newDFPRHarness(t)
	h.gh.addRepo("example/deploy", 303, map[string]string{"compose.yml": noBuild})
	it := dfPlannedAt(h, dfFile("Dockerfile", dfContent))
	f := dfFile("compose.yml", noBuild)
	f.Repository, f.BaseBranch = "example/deploy", "main"
	it.Source.Files = append(it.Source.Files, f)
	plan := dfPlan(it)
	h.gh.afterWrite["CreateRef"] = func() {
		h.gh.commitFiles("example/deploy", "main", map[string]string{"compose.yml": noBuild + "    build:\n      dockerfile_inline: |\n        FROM alpine\n"})
	}
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonSourceChanged)
	if countCalls(h.gh, "CreateRef") != 1 || countCalls(h.gh, "CreatePull") != 0 || len(h.gh.pulls(testRepo)) != 0 {
		t.Errorf("CreateRef %d, CreatePull %d: a pull request was opened from changed inputs", countCalls(h.gh, "CreateRef"), countCalls(h.gh, "CreatePull"))
	}
	// The branch stays and the attempt is not settled as a pull request.
	if a := h.load().Attempts; len(a) != 1 || a[0].Status.settled() {
		t.Errorf("attempts = %+v", a)
	}
}
