package remediation

import (
	"sort"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// --- that there was no pnpm-workspace.yaml is part of the unit's inputs ---

func TestLanguagePlan_PnpmRecordsThatThereWasNoSettingsFile(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "web")}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	plan := func(setup func(f *fakeGitHub)) LanguageItem {
		gh := newFakeGitHub()
		gh.put("ex/app", "web", "package.json", pnpmManifest)
		gh.put("ex/app", "web", "pnpm-lock.yaml", pnpmLock)
		setup(gh)
		return langPlan(t, gh, deps, nil, in).LanguageItems[0]
	}
	none := plan(func(*fakeGitHub) {})
	if none.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("item = %s / %s (%s)", none.Category, none.Reason, none.Detail)
	}
	sorted := append([]string(nil), none.Source.Absent...)
	sort.Strings(sorted)
	if strings.Join(sorted, ",") != "pnpm-workspace.yaml,web/.node-version,web/.nvmrc,web/pnpm-workspace.yaml" {
		t.Errorf("absent = %v", none.Source.Absent)
	}
	with := plan(func(f *fakeGitHub) { f.put("ex/app", "web", "pnpm-workspace.yaml", backendWorkspace) })
	if strings.Join(with.Source.Absent, ",") != "pnpm-workspace.yaml,web/.node-version,web/.nvmrc" {
		t.Errorf("absent with the file = %v", with.Source.Absent)
	}
	if LanguageInputFingerprint(none) == LanguageInputFingerprint(with) {
		t.Error("the fingerprint does not tell a project without the file from one with it")
	}
	// A project without the file at another path is another input.
	other := none
	other.Source.Absent = []string{"other/pnpm-workspace.yaml"}
	if LanguageInputFingerprint(none) == LanguageInputFingerprint(other) {
		t.Error("the fingerprint does not depend on where the file was looked for")
	}
	// npm has no such file to look for; it looks for the files that declare
	// the Node.js version.
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "web")
	if it := langPlan(t, gh, deps, nil, in).LanguageItems[0]; strings.Join(it.Source.Absent, ",") != "web/.node-version,web/.nvmrc" {
		t.Errorf("npm absent = %v", it.Source.Absent)
	}
}

func TestPnpmUpdateRefusesASettingsFileThatAppearedSincethePlan(t *testing.T) {
	setup := func(t *testing.T) *harness {
		h := newHarness(t, "pnpm")
		h.item.Source.Absent = []string{"pnpm-workspace.yaml"}
		return h
	}
	t.Run("still absent", func(t *testing.T) {
		h := setup(t)
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("it exists now", func(t *testing.T) {
		h := setup(t)
		h.gh.files["pnpm-workspace.yaml"] = []byte("supportedArchitectures:\n  os: [win32]\n")
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonSourceChanged)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
	})
	t.Run("the plan recorded it both ways", func(t *testing.T) {
		h := setup(t)
		h.gh.files["pnpm-workspace.yaml"] = []byte("allowBuilds: {}\n")
		h.item.Source.Files = append(h.item.Source.Files, SourceFile{Path: "pnpm-workspace.yaml", BlobSHA: gitBlobSHA([]byte("allowBuilds: {}\n"))})
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateInputInvalid)
	})
	t.Run("the read fails", func(t *testing.T) {
		h := setup(t)
		h.gh.err = github.ErrBudgetExhausted
		it, _ := h.run()
		if it.Category != CategoryDeferred {
			t.Errorf("category/reason = %s/%s", it.Category, it.Reason)
		}
	})
}

func TestPRStageLanguageSettingsFileThatAppearedOnTheBaseIsNotBuiltOn(t *testing.T) {
	fx := langFixtures()["pnpm"]
	for name, appears := range map[string]string{
		"supportedArchitectures": "supportedArchitectures:\n  os: [win32]\n",
		"overrides":              "overrides:\n  minimist: 1.0.0\n",
		"packages":               "packages:\n  - 'p/*'\n",
		"an empty file":          "# nothing\n",
	} {
		t.Run(name, func(t *testing.T) {
			h := langHarness(t, fx)
			item := h.langItem(fx)
			item.Source.Absent = []string{"svc/pnpm-workspace.yaml"}
			plan := prLangPlan(item)
			h.addFiles(map[string]string{"svc/pnpm-workspace.yaml": appears})
			u := onlyUnit(t, h.run(plan))
			wantStatus(t, u, PRStatusDeferred, ReasonSourceChanged)
			if !strings.Contains(u.Detail, "pnpm-workspace.yaml") {
				t.Errorf("detail = %q", u.Detail)
			}
			if h.gh.writeCount() != 0 || len(h.gh.pulls(testRepo)) != 0 {
				t.Errorf("writes = %d, pulls = %d", h.gh.writeCount(), len(h.gh.pulls(testRepo)))
			}
		})
	}
	t.Run("a base that moved without the file builds on", func(t *testing.T) {
		h := langHarness(t, fx)
		item := h.langItem(fx)
		item.Source.Absent = []string{"svc/pnpm-workspace.yaml"}
		plan := prLangPlan(item)
		h.addFiles(map[string]string{"README.md": "hello\n"})
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusCreated, "")
	})
}

// --- pnpm looks for pnpm-workspace.yaml above the project too ---

func TestLanguagePlan_PnpmWorkspaceFileInADirectoryAbove(t *testing.T) {
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	plan := func(dir string, setup func(f *fakeGitHub)) (LanguageItem, *fakeGitHub) {
		gh := newFakeGitHub()
		gh.put("ex/app", dir, "package.json", pnpmManifest)
		gh.put("ex/app", dir, "pnpm-lock.yaml", pnpmLock)
		setup(gh)
		deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", dir)}
		return langPlan(t, gh, deps, nil, in).LanguageItems[0], gh
	}
	for name, c := range map[string]struct{ dir, at string }{
		"at the root":        {"web", "."},
		"two levels down":    {"a/web", "."},
		"in the parent":      {"a/web", "a"},
		"three levels down":  {"a/b/web", "a"},
		"the root for three": {"a/b/web", "."},
	} {
		for doc, content := range map[string]string{"a workspace": "packages:\n  - 'web'\n", "settings only": backendWorkspace, "empty": "# none\n"} {
			t.Run(name+"/"+doc, func(t *testing.T) {
				it, _ := plan(c.dir, func(f *fakeGitHub) { f.put("ex/app", c.at, "pnpm-workspace.yaml", content) })
				if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, pathIn(c.at, "pnpm-workspace.yaml")) {
					t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
				}
			})
		}
	}
	t.Run("none above: every directory up to the root is recorded as without one", func(t *testing.T) {
		it, gh := plan("a/b/web", func(*fakeGitHub) {})
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
		}
		got := append([]string(nil), it.Source.Absent...)
		sort.Strings(got)
		if strings.Join(got, ",") != "a/b/pnpm-workspace.yaml,a/b/web/.node-version,a/b/web/.nvmrc,a/b/web/pnpm-workspace.yaml,a/pnpm-workspace.yaml,pnpm-workspace.yaml" {
			t.Errorf("absent = %v", got)
		}
		for _, call := range gh.calls {
			if strings.HasPrefix(call, "list:") && !strings.Contains(call, "ex/app/a/b/web@") && !strings.Contains(call, "ex/app/a/b@") && !strings.Contains(call, "ex/app/a@") && !strings.Contains(call, "ex/app/.@") {
				t.Errorf("unexpected listing %s", call)
			}
		}
	})
	t.Run("a project at the root has nothing above", func(t *testing.T) {
		it, gh := plan(".", func(*fakeGitHub) {})
		if strings.Join(it.Source.Absent, ",") != "pnpm-workspace.yaml,.node-version,.nvmrc" {
			t.Errorf("absent = %v", it.Source.Absent)
		}
		for _, call := range gh.calls {
			if strings.HasPrefix(call, "list:") && !strings.Contains(call, "ex/app/.@") {
				t.Errorf("unexpected listing %s", call)
			}
		}
	})
	t.Run("a file in a sibling directory does not count", func(t *testing.T) {
		it, _ := plan("a/web", func(f *fakeGitHub) { f.put("ex/app", "a/other", "pnpm-workspace.yaml", "packages: []\n") })
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a listing of a directory above fails", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "a/web", "package.json", pnpmManifest)
		gh.put("ex/app", "a/web", "pnpm-lock.yaml", pnpmLock)
		gh.listErr = map[string]error{"ex/app/a": github.ErrForbidden}
		deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "a/web")}
		it := langPlan(t, gh, deps, nil, in).LanguageItems[0]
		if it.Category == CategoryDependencyUpdateCandidate {
			t.Errorf("item = %s / %s", it.Category, it.Reason)
		}
	})
	t.Run("npm looks at no directory above", func(t *testing.T) {
		gh := newFakeGitHub()
		npmRepo(gh, "ex/app", "a/web")
		gh.put("ex/app", ".", "pnpm-workspace.yaml", "packages: []\n")
		deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "a/web")}
		it := langPlan(t, gh, deps, nil, in).LanguageItems[0]
		if it.Category != CategoryDependencyUpdateCandidate || strings.Join(it.Source.Absent, ",") != "a/web/.node-version,a/web/.nvmrc" {
			t.Errorf("item = %s / %s, absent %v", it.Category, it.Reason, it.Source.Absent)
		}
	})
}

func TestPnpmUpdateRefusesAWorkspaceFileThatAppearedInADirectoryAbove(t *testing.T) {
	// The project's files are in a/web; the plan found no file in a or at the root.
	h := newHarness(t, "pnpm")
	moved := map[string]string{}
	for p, c := range h.files {
		moved["a/web/"+p] = c
	}
	h.files = moved
	h.gh = ghFor(moved)
	h.cfg.GitHub = h.gh
	for i := range h.item.Source.Files {
		h.item.Source.Files[i].Path = "a/web/" + h.item.Source.Files[i].Path
	}
	h.item.Source.Directory = "a/web"
	h.item.Source.Absent = []string{"pnpm-workspace.yaml", "a/pnpm-workspace.yaml", "a/web/pnpm-workspace.yaml"}
	for _, at := range []string{"", "a/"} {
		h.gh.files[at+"pnpm-workspace.yaml"] = []byte("packages: ['*']\n")
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonSourceChanged)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
		delete(h.gh.files, at+"pnpm-workspace.yaml")
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if !isSameOrAbove(".", "a/b") || !isSameOrAbove("a", "a/b") || !isSameOrAbove("a/b", "a/b") || isSameOrAbove("a/b", "a") || isSameOrAbove("a", "ab/c") || isSameOrAbove("a/x", "a/b") {
		t.Error("isSameOrAbove misjudges")
	}
}

func TestPRStageLanguageWorkspaceFileThatAppearedAboveIsNotBuiltOn(t *testing.T) {
	fx := langFixtures()["pnpm"] // the project is in svc
	h := langHarness(t, fx)
	item := h.langItem(fx)
	item.Source.Absent = []string{"pnpm-workspace.yaml", "svc/pnpm-workspace.yaml"}
	plan := prLangPlan(item)
	h.addFiles(map[string]string{"pnpm-workspace.yaml": "packages:\n  - 'svc'\n"})
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusDeferred, ReasonSourceChanged)
	if h.gh.writeCount() != 0 || len(h.gh.pulls(testRepo)) != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}
