package remediation

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// prReader serves the update stage from the fake GitHub the pull request
// stage writes to, so both stages see the same repository.
type prReader struct{ *fakePRGitHub }

func (prReader) ListDirectory(context.Context, string, string, string) ([]github.Entry, error) {
	return nil, os.ErrInvalid
}

// TestIntegrationLangUpdateToPullRequest runs the update stage against the
// pinned official images, a Docker daemon and Trivy, and hands its result to the
// pull request stage with a fake GitHub: an update of each manager becomes one
// commit of the changed files, and a second cycle opens nothing more. It runs
// only when KESTRELYNX_WORKER_IT=1; the optional settings of
// TestIntegrationLangUpdate apply.
func TestIntegrationLangUpdateToPullRequest(t *testing.T) {
	e := itSetup(t)
	ctx, env := e.ctx, e.image
	nodeOrigin := FindingOrigin{Entity: "img", Workload: "compose/app/web", PkgPath: "app/node_modules/minimist/package.json"}
	pyOrigin := FindingOrigin{Entity: "img", Workload: "compose/app/web", PkgPath: "usr/local/lib/python3.12/site-packages/urllib3-1.26.4.dist-info/METADATA", Target: "Python"}
	minimist := func() *findingGroup {
		return group(typeNodePkg, "minimist", "1.2.5", nodeOrigin, CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
	}
	urllib3 := func() *findingGroup {
		return group(typePythonPkg, "urllib3", "1.26.4", pyOrigin,
			CVERef{VulnID: "CVE-2021-33503", FixedVers: []string{"1.26.5"}},
			CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17", "2.0.6"}})
	}

	cases := []struct {
		name    string
		manager DependencyManager
		dir     string
		files   []string
		group   func() *findingGroup
	}{
		{"npm", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist},
		{"pnpm", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist},
		{"uv", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3},
		{"pip", ManagerPip, "pip", []string{"requirements.txt"}, urllib3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := readTestdata(t, c.dir, c.files...)
			h := newPRHarness(t)
			h.addFiles(files)
			it := itemFor(t, c.manager, files, c.group())
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("the fixture is not an update candidate: %s %s", it.Category, it.Detail)
			}
			it.Source.Repository, it.Source.CommitSHA = testRepo, h.gh.branch(testRepo, "main")
			it.Workloads = []string{"compose/app/web"}
			plan := testPlan()
			plan.LanguageItems = []LanguageItem{it}

			up, err := NewLangUpdater(e.config(LangUpdateConfig{
				GitHub: prReader{h.gh}, Images: map[string]ImageEnv{"img": env}, MaxJobs: 2, JobIDPrefix: "itpr",
			}))
			if err != nil {
				t.Fatal(err)
			}
			up.Run(ctx, &plan)
			got := plan.LanguageItems[0]
			if got.Category != CategoryPRCandidate {
				t.Fatalf("the update did not pass: %s %s %s", got.Category, got.Reason, got.Detail)
			}

			res := h.run(plan)
			u := onlyUnit(t, res)
			wantStatus(t, u, PRStatusCreated, "")
			pulls := h.gh.pulls(testRepo)
			if len(pulls) != 1 {
				t.Fatalf("pulls = %d", len(pulls))
			}
			pr := pulls[0]
			for _, a := range got.Artifacts {
				f, err := h.gh.ReadFile(ctx, testRepo, pr.HeadSHA, a.Path)
				if err != nil || string(f.Content) != string(a.Content) {
					t.Errorf("%s in the pull request differs from the artifact (%v)", a.Path, err)
				}
			}
			if n := countCalls(h.gh, "CreateCommit"); n != 1 {
				t.Errorf("commits = %d, want 1", n)
			}
			m, err := parsePRMarker(pr.Body)
			if err != nil || m.verify(testRepoID) != nil || m.Kind != "language" {
				t.Fatalf("marker %+v err %v", m, err)
			}
			for _, want := range []string{"## Not verified", "Scan of the dependency files before and after", "Resolved "} {
				if !strings.Contains(pr.Body, want) {
					t.Errorf("body lacks %q", want)
				}
			}
			t.Logf("%s: %s; fixes %d targets; files %v", c.name, pr.Title, len(u.FixTargets), func() []string {
				var ps []string
				for _, ch := range m.Changes {
					ps = append(ps, ch.Path)
				}
				return ps
			}())

			// The next cycle: the plan is made and updated again, and the pull
			// request already exists.
			plan2 := testPlan()
			it2 := itemFor(t, c.manager, files, c.group())
			it2.Source.Repository, it2.Source.CommitSHA = testRepo, h.gh.branch(testRepo, "main")
			it2.Workloads = []string{"compose/app/web"}
			plan2.LanguageItems = []LanguageItem{it2}
			// The pull request of the first cycle stands for the same inputs: the
			// stage ties the item to it and runs no job.
			use2, bound := RunLanguageUpdates(ctx, up.Run, &plan2, h.store)
			if use2.Jobs != 0 || bound != 1 || plan2.LanguageItems[0].Reason != ReasonUpdateAlreadyProposed {
				t.Fatalf("second cycle: jobs %d, tied %d, item %s/%s", use2.Jobs, bound, plan2.LanguageItems[0].Category, plan2.LanguageItems[0].Reason)
			}
			writes := h.gh.writeCount()
			u2 := onlyUnit(t, h.run(plan2))
			wantStatus(t, u2, PRStatusOpen, "")
			if u2.UpdateKey != u.UpdateKey || h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
				t.Errorf("second cycle: update key %s -> %s, writes %d -> %d, pulls %d", u.UpdateKey, u2.UpdateKey, writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
			}
		})
	}
}
