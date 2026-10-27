package remediation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// drunReader lets the fake GitHub list the files of a directory of a commit.
type drunReader struct{ *fakePRGitHub }

func (d drunReader) ListDirectory(_ context.Context, repo, sha, dir string) ([]github.Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rs, err := d.repo(repo)
	if err != nil {
		return nil, err
	}
	c, ok := rs.commits[sha]
	if !ok {
		return nil, github.ErrNotFound
	}
	prefix := ""
	if dir != "." && dir != "" {
		prefix = dir + "/"
	}
	var out []github.Entry
	for p, e := range rs.trees[c.tree] {
		name, found := strings.CutPrefix(p, prefix)
		if !found || strings.Contains(name, "/") {
			continue
		}
		out = append(out, github.Entry{Name: name, Path: p, Type: github.EntryFile, SHA: e.blob})
	}
	return out, nil
}

// TestIntegrationDockerRunContainerLanguagePullRequest takes a container
// started with docker run, whose image holds a vulnerable npm package, through
// the plan, the update stage and the pull request stage. Besides
// KESTRELYNX_DOCKER_IT=1 it needs the environment of the update stage
// (KESTRELYNX_WORKER_IT=1; see TestIntegrationLangUpdateToPullRequest).
func TestIntegrationDockerRunContainerLanguagePullRequest(t *testing.T) {
	e := drunSetup(t)
	if os.Getenv("KESTRELYNX_WORKER_IT") != "1" {
		t.Skip("set KESTRELYNX_WORKER_IT=1 as well to run the update stage")
	}
	w := itSetup(t)
	files := readTestdata(t, "npm", "package.json", "package-lock.json")

	id := drunRandom(t)
	cname, tag := drunNamePrefix+id, drunNamePrefix+id+":1"
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", files["package.json"])
	write("package-lock.json", files["package-lock.json"])
	write("node_modules/minimist/package.json", "{\"name\":\"minimist\",\"version\":\"1.2.5\"}\n")
	write("Dockerfile", "FROM node:22-alpine\nWORKDIR /app\nCOPY package.json package-lock.json ./\nCOPY node_modules ./node_modules\n")
	set := newDrunSet(t)
	dockerCLI(t, "build", "-q", "-t", tag, dir)
	set.tags = append(set.tags, tag)
	set.track(tag)
	set.run(cname, tag)

	c := e.observe(t, cname)
	if c.WorkloadKey() != "container/"+cname {
		t.Fatalf("key = %q", c.WorkloadKey())
	}
	in, _ := e.input(t, c, false)
	inputs := []ImageInput{in}

	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", files)
	h.gh.humanMoved = map[string]bool{}
	dep := DependencyMapping{Workload: "container/" + cname, Repository: testRepo, BaseBranch: "main", Directory: "."}
	budget := registry.NewBudget(500)
	p, err := NewPlanner(Config{
		Registry: registry.New(registry.Options{Budget: budget, MaxTagPages: 10}), Scanner: e.trivy, Prepared: e.conds, Budget: budget,
		Limits: Limits{MaxCandidateScans: 3, MaxBaselineRescans: 3, MaxTagPages: 10},
		GitHub: drunReader{h.gh}, Dependencies: []DependencyMapping{dep},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Plan(e.ctx, inputs)
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("language items = %d: %+v", len(plan.LanguageItems), plan.LanguageItems)
	}
	it := plan.LanguageItems[0]
	if it.Category != CategoryDependencyUpdateCandidate || it.Manager != ManagerNpm || len(it.Workloads) != 1 || it.Workloads[0] != "container/"+cname {
		t.Fatalf("item = %s/%s %s (%s), workloads %v", it.Category, it.Reason, it.Manager, it.Detail, it.Workloads)
	}

	up, err := NewLangUpdater(w.config(LangUpdateConfig{
		GitHub: drunReader{h.gh}, Images: ImageEnvs(inputs), MaxJobs: 2, JobIDPrefix: "drunit",
	}))
	if err != nil {
		t.Fatal(err)
	}
	up.Run(w.ctx, &plan)
	got := plan.LanguageItems[0]
	if got.Category != CategoryPRCandidate {
		t.Fatalf("the update did not pass: %s %s %s", got.Category, got.Reason, got.Detail)
	}

	stage := func() PRStageResult {
		h.clock = h.clock.Add(24 * time.Hour)
		now := h.clock
		s, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: h.gh, Store: h.store, Limits: h.limits, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		return s.Run(e.ctx, PRStageInput{Plan: plan, Containers: []inventory.Container{c}})
	}
	u := onlyUnit(t, stage())
	wantStatus(t, u, PRStatusCreated, "")
	pulls := h.gh.pulls(testRepo)
	if len(pulls) != 1 {
		t.Fatalf("pulls = %d", len(pulls))
	}
	pr := pulls[0]
	if !strings.HasPrefix(pr.HeadRef, "kestrelynx/language/"+cname+"-npm-") {
		t.Errorf("branch = %q", pr.HeadRef)
	}
	for _, a := range got.Artifacts {
		f, err := h.gh.ReadFile(e.ctx, testRepo, pr.HeadSHA, a.Path)
		if err != nil || string(f.Content) != string(a.Content) {
			t.Errorf("%s in the pull request differs from the artifact (%v)", a.Path, err)
		}
	}
	for _, want := range []string{"`container/" + cname + "`", textFor(BodyEN).SourceNote, "Scan of the dependency files before and after"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Kind != "language" || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) {
		t.Errorf("marker %+v err %v", m, err)
	}
	t.Logf("%s: fixes %d targets", pr.Title, len(u.FixTargets))
}
