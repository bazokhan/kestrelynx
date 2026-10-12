package remediation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// langFixture is the files and packages of one language update: the files as
// the repository holds them, the files the update produced and the packages
// it moved.
type langFixture struct {
	manager DependencyManager
	root    string
	files   map[string]string
	updated map[string]string
	pkgs    []LanguagePackage
	edits   []ManifestEdit
}

func npmPackage(name, from, to, cve string, pos string) LanguagePackage {
	return LanguagePackage{
		Name: name, Ecosystem: "node-pkg", Installed: from, AdoptedVersion: to, SelectionLowerBound: to,
		Relation: RelationTransitive, Action: ActionUpdate,
		Occurrences: []SourceOccurrence{{Path: pos, Version: from, Matched: true}},
		CVEs:        []CVERef{{VulnID: cve, Severity: scanner.SeverityHigh, Priority: PriorityWatch}},
	}
}

func pyPackage(name, from, to, cve string, pos string) LanguagePackage {
	p := npmPackage(name, from, to, cve, pos)
	p.Ecosystem = "python-pkg"
	return p
}

// langFixtures has one update per manager, each in its own directory layout.
func langFixtures() map[string]langFixture {
	return map[string]langFixture{
		"npm": {
			manager: ManagerNpm, root: ".",
			files:   map[string]string{"package.json": "{\"name\":\"app\"}\n", "package-lock.json": "{\"lock\":1}\n"},
			updated: map[string]string{"package.json": "{\"name\":\"app\"}\n", "package-lock.json": "{\"lock\":2}\n"},
			pkgs:    []LanguagePackage{npmPackage("minimist", "1.2.5", "1.2.6", "CVE-2021-44906", "node_modules/minimist")},
		},
		"pnpm": {
			manager: ManagerPnpm, root: "svc",
			files:   map[string]string{"svc/package.json": "{\"name\":\"svc\"}\n", "svc/pnpm-lock.yaml": "lock: 1\n"},
			updated: map[string]string{"svc/pnpm-lock.yaml": "lock: 2\n"},
			pkgs:    []LanguagePackage{npmPackage("minimist", "1.2.5", "1.2.6", "CVE-2021-44906", "minimist@1.2.5")},
		},
		"uv": {
			manager: ManagerUv, root: ".",
			files:   map[string]string{"pyproject.toml": "[project]\nname = \"app\"\n", "uv.lock": "version = 1\n# a\n"},
			updated: map[string]string{"uv.lock": "version = 1\n# b\n"},
			pkgs:    []LanguagePackage{pyPackage("urllib3", "1.26.4", "1.26.17", "CVE-2023-43804", "urllib3")},
		},
		"pip": {
			manager: ManagerPip, root: "py",
			files:   map[string]string{"py/requirements.txt": "urllib3==1.26.4\n"},
			updated: map[string]string{"py/requirements.txt": "urllib3==1.26.17\n"},
			pkgs:    []LanguagePackage{pyPackage("urllib3", "1.26.4", "1.26.17", "CVE-2023-43804", "py/requirements.txt:1")},
		},
	}
}

// langHarness is a pull request harness whose repository also holds the
// fixture's files.
func langHarness(t *testing.T, fx langFixture) *prHarness {
	t.Helper()
	h := newPRHarness(t)
	h.addFiles(fx.files)
	return h
}

// addFiles puts files on the main branch as people pushing them.
func (h *prHarness) addFiles(files map[string]string) {
	h.gh.commitFiles(testRepo, "main", files)
	h.gh.humanMoved = map[string]bool{}
}

// langItem builds the plan item the update stage leaves for a fixture: a
// pr_candidate with the produced files held in memory, planned from the
// current main branch.
func (h *prHarness) langItem(fx langFixture) LanguageItem {
	it := LanguageItem{
		Key: "deps:example/app@main:" + fx.root + "#" + string(fx.manager), Workloads: []string{"compose/app/web"}, Manager: fx.manager,
		Category: CategoryPRCandidate, Reason: ReasonUpdateVerified,
		Source:   SourceRecord{Repository: testRepo, BaseBranch: "main", Directory: fx.root, CommitSHA: h.gh.branch(testRepo, "main"), Origin: OriginConfig, Confidence: ConfidenceAsserted},
		Packages: append([]LanguagePackage(nil), fx.pkgs...), UpdateExecuted: true, PostUpdateCheckExecuted: true,
	}
	for _, p := range fileNames(fx.files) {
		it.Source.Files = append(it.Source.Files, SourceFile{Path: p, BlobSHA: gitBlobSHA([]byte(fx.files[p]))})
	}
	for _, p := range fileNames(fx.updated) {
		c := []byte(fx.updated[p])
		it.Artifacts = append(it.Artifacts, ArtifactFile{Path: p, SHA256: sha256Hex(c), Size: int64(len(c)), Mode: "100644", Content: c})
	}
	it.Update = &LanguageUpdate{
		Steps: []UpdateStep{{ID: "update", Op: string(fx.manager) + ".update"}},
		Diff:  &DependencyDiff{Changed: []string{fx.pkgs[0].Occurrences[0].Path}},
	}
	for _, e := range fx.edits {
		it.Update.ManifestEdits = append(it.Update.ManifestEdits, e)
	}
	sc := &SourceCheck{CommitSHA: it.Source.CommitSHA, Conditions: testConds("db1"), Passed: true}
	for _, p := range fileNames(fx.files) {
		sc.Before = append(sc.Before, HashedFile{Path: p, SHA256: sha256Hex([]byte(fx.files[p]))})
	}
	for _, p := range fileNames(fx.updated) {
		sc.After = append(sc.After, HashedFile{Path: p, SHA256: sha256Hex([]byte(fx.updated[p]))})
	}
	for _, p := range fx.pkgs {
		for _, c := range p.CVEs {
			sc.Resolved = append(sc.Resolved, SourceVuln{Package: p.Name, Version: p.Installed, VulnID: c.VulnID, Severity: c.Severity, FixedVer: p.AdoptedVersion})
		}
	}
	sc.Counts = [3]int{len(sc.Resolved), 0, 0}
	it.SourceCheck = sc
	return it
}

func fileNames(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return sortedCopy(out)
}

func prLangPlan(items ...LanguageItem) Plan {
	p := testPlan()
	p.LanguageItems = items
	return p
}

func TestPRStageLanguageCreatesOneCommitPullPerManager(t *testing.T) {
	for name, fx := range langFixtures() {
		t.Run(name, func(t *testing.T) {
			h := langHarness(t, fx)
			plan := prLangPlan(h.langItem(fx))
			baseSHA := h.gh.branch(testRepo, "main")
			res := h.run(plan)
			u := onlyUnit(t, res)
			wantStatus(t, u, PRStatusCreated, "")
			if u.Kind != "language" || u.Number != 1 || u.ItemKey != plan.LanguageItems[0].Key || u.Language == nil ||
				u.Language.Manager != string(fx.manager) || u.Language.Root != fx.root || len(u.Language.Packages) != 1 {
				t.Errorf("unit = %+v", u)
			}
			if len(u.FixTargets) != 1 || u.FixTargets[0].VulnID == "" {
				t.Errorf("fix targets = %+v", u.FixTargets)
			}
			if !strings.HasSuffix(u.Path, fx.manager.LockfileName()) {
				t.Errorf("unit path = %q, want the lockfile", u.Path)
			}

			pulls := h.gh.pulls(testRepo)
			if len(pulls) != 1 {
				t.Fatalf("pulls = %d, want 1", len(pulls))
			}
			pr := pulls[0]
			if !strings.HasPrefix(pr.HeadRef, "kestrelynx/language/web-"+string(fx.manager)+"-") {
				t.Errorf("head ref = %q", pr.HeadRef)
			}
			// One commit on the base, holding exactly the changed files.
			h.gh.mu.Lock()
			commit := h.gh.repos[strings.ToLower(testRepo)].commits[pr.HeadSHA]
			h.gh.mu.Unlock()
			if len(commit.parents) != 1 || commit.parents[0] != baseSHA {
				t.Errorf("commit parents = %v, want [%s]", commit.parents, baseSHA)
			}
			changed := 0
			for _, p := range fileNames(fx.files) {
				f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, p)
				if err != nil {
					t.Fatal(err)
				}
				want := fx.files[p]
				if upd, ok := fx.updated[p]; ok && upd != want {
					want = upd
					changed++
				}
				if string(f.Content) != want {
					t.Errorf("%s = %q, want %q", p, f.Content, want)
				}
			}
			if c, _ := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "compose.yml"); string(c.Content) != composeYML {
				t.Error("another file changed")
			}
			if n := countCalls(h.gh, "CreateCommit"); n != 1 {
				t.Errorf("commits = %d, want 1", n)
			}
			if n := countCalls(h.gh, "CreateBlob"); n != changed {
				t.Errorf("blobs = %d, want %d (only the changed files)", n, changed)
			}
			if n := countCalls(h.gh, "CreateTree"); n != 1 {
				t.Errorf("trees = %d, want 1", n)
			}

			m, err := parsePRMarker(pr.Body)
			if err != nil || m.Kind != "language" || m.Lang == nil || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) || m.HeadSHA != pr.HeadSHA {
				t.Fatalf("marker %+v err %v", m, err)
			}
			if m.TargetKey != TargetKeyOf("language", testRepoID, "main", u.Path, []string{fx.root}) {
				t.Error("the target key does not name the lockfile and its directory")
			}
			if len(m.Changes) != changed {
				t.Errorf("marker changes = %+v", m.Changes)
			}

			// A second cycle with the same plan neither opens nor writes anything.
			writes := h.gh.writeCount()
			res = h.run(plan)
			u2 := onlyUnit(t, res)
			wantStatus(t, u2, PRStatusOpen, "")
			if u2.Number != 1 || h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
				t.Errorf("second cycle: unit %+v, writes %d -> %d, pulls %d", u2, writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
			}
		})
	}
}

func TestPRStageLanguageManifestEditIsInTheSameCommit(t *testing.T) {
	fx := langFixtures()["npm"]
	fx.updated = map[string]string{"package.json": "{\"name\":\"app\",\"dependencies\":{\"minimist\":\"^1.2.6\"}}\n", "package-lock.json": "{\"lock\":2}\n"}
	fx.pkgs[0].Relation = RelationDirect
	fx.edits = []ManifestEdit{{File: "package.json", Section: "dependencies", Name: "minimist", From: "^1.2.5", To: "^2.0.0", MajorChange: true}}
	h := langHarness(t, fx)
	u := onlyUnit(t, h.run(prLangPlan(h.langItem(fx))))
	wantStatus(t, u, PRStatusCreated, "")
	if n := countCalls(h.gh, "CreateBlob"); n != 2 {
		t.Errorf("blobs = %d, want 2", n)
	}
	if n := countCalls(h.gh, "CreateCommit"); n != 1 {
		t.Errorf("commits = %d, want 1", n)
	}
	pr := h.gh.pulls(testRepo)[0]
	for p, want := range fx.updated {
		f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, p)
		if err != nil || string(f.Content) != want {
			t.Errorf("%s = %q (%v)", p, f.Content, err)
		}
	}
	if len(u.Language.ManifestEdits) != 1 || !u.Language.ManifestEdits[0].Major {
		t.Errorf("manifest edits = %+v", u.Language.ManifestEdits)
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.verify(testRepoID) != nil || len(m.Lang.ManifestEdits) != 1 || len(m.Changes) != 2 {
		t.Fatalf("marker %+v err %v", m, err)
	}
	t.Logf("pull request body:\n%s", pr.Body)
	for _, want := range []string{"### Manifest edits", "**major version change**", "Review these first", "`^1.2.5`", "`^2.0.0`"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
}

func TestPRStageLanguageUnchangedArtifactIsNotCommitted(t *testing.T) {
	fx := langFixtures()["npm"] // package.json is among the artifacts with its old content
	h := langHarness(t, fx)
	onlyUnit(t, h.run(prLangPlan(h.langItem(fx))))
	m, err := parsePRMarker(h.gh.pulls(testRepo)[0].Body)
	if err != nil || len(m.Changes) != 1 || m.Changes[0].Path != "package-lock.json" {
		t.Fatalf("marker changes = %+v err %v", m.Changes, err)
	}
	// With no file different from the repository's, nothing is written.
	fx.updated = fx.files
	h2 := langHarness(t, fx)
	u := onlyUnit(t, h2.run(prLangPlan(h2.langItem(fx))))
	wantStatus(t, u, PRStatusFailed, ReasonArtifactsUnusable)
	if h2.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h2.gh.writeCount())
	}
}

func TestPRStageLanguageUpdateKeyIsStableAcrossBases(t *testing.T) {
	fx := langFixtures()["uv"]
	h := langHarness(t, fx)
	u1 := onlyUnit(t, h.run(prLangPlan(h.langItem(fx))))
	wantStatus(t, u1, PRStatusCreated, "")
	h.addFiles(map[string]string{"README.md": "hello\n"}) // the base moves, the plan's files do not change
	writes := h.gh.writeCount()
	u2 := onlyUnit(t, h.run(prLangPlan(h.langItem(fx))))
	wantStatus(t, u2, PRStatusOpen, "")
	if u2.UpdateKey != u1.UpdateKey || u2.TargetKey != u1.TargetKey || h.gh.writeCount() != writes {
		t.Errorf("update key %s -> %s, writes %d -> %d", u1.UpdateKey, u2.UpdateKey, writes, h.gh.writeCount())
	}
}

func TestPRStageLanguageBaseMovedWithSameFilesBuildsOnNewBase(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	plan := prLangPlan(h.langItem(fx)) // planned at the old commit
	h.addFiles(map[string]string{"README.md": "hello\n"})
	newBase := h.gh.branch(testRepo, "main")
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusCreated, "")
	pr := h.gh.pulls(testRepo)[0]
	h.gh.mu.Lock()
	parents := h.gh.repos[strings.ToLower(testRepo)].commits[pr.HeadSHA].parents
	h.gh.mu.Unlock()
	if len(parents) != 1 || parents[0] != newBase {
		t.Errorf("parents = %v, want the current base %s", parents, newBase)
	}
}

func TestPRStageLanguageSourceBlobChangedIsNotWritten(t *testing.T) {
	for name, changed := range map[string]string{"lockfile": "package-lock.json", "manifest": "package.json"} {
		t.Run(name, func(t *testing.T) {
			fx := langFixtures()["npm"]
			h := langHarness(t, fx)
			plan := prLangPlan(h.langItem(fx))
			h.addFiles(map[string]string{changed: "{\"changed\":\"by a person\"}\n"})
			u := onlyUnit(t, h.run(plan))
			wantStatus(t, u, PRStatusDeferred, ReasonSourceChanged)
			if h.gh.writeCount() != 0 || len(h.gh.pulls(testRepo)) != 0 {
				t.Errorf("writes = %d, pulls = %d", h.gh.writeCount(), len(h.gh.pulls(testRepo)))
			}
			// The next cycle plans again from the new files and succeeds.
			fx.files[changed] = "{\"changed\":\"by a person\"}\n"
			wantStatus(t, onlyUnit(t, h.run(prLangPlan(h.langItem(fx)))), PRStatusCreated, "")
		})
	}
}

func TestPRStageLanguageFileGoneFromBase(t *testing.T) {
	fx := langFixtures()["pnpm"]
	h := langHarness(t, fx)
	plan := prLangPlan(h.langItem(fx))
	plan.LanguageItems[0].Source.Files = append(plan.LanguageItems[0].Source.Files, SourceFile{Path: "svc/.npmrc", BlobSHA: strings.Repeat("a", 40)})
	h.addFiles(map[string]string{"README.md": "x\n"})
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusDeferred, ReasonSourceChanged)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

func TestPRStageLanguageItemWithoutContentIsNotWritten(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	plan := prLangPlan(h.langItem(fx))
	// A plan read back from its stored form holds no file content.
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var stored Plan
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if a := stored.LanguageItems[0].Artifacts; len(a) == 0 || len(a[0].Content) != 0 || a[0].SHA256 == "" {
		t.Fatalf("stored artifacts = %+v", a)
	}
	u := onlyUnit(t, h.run(stored))
	wantStatus(t, u, PRStatusDeferred, ReasonArtifactContentMissing)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}

	// Content that is not what the item recorded is refused as well.
	bad := prLangPlan(h.langItem(fx))
	bad.LanguageItems[0].Artifacts[1].Content = []byte("{\"lock\":3}\n")
	wantStatus(t, onlyUnit(t, h.run(bad)), PRStatusFailed, ReasonArtifactsUnusable)
	notRead := prLangPlan(h.langItem(fx))
	notRead.LanguageItems[0].Artifacts = append(notRead.LanguageItems[0].Artifacts, ArtifactFile{Path: ".github/workflows/x.yml", SHA256: sha256Hex([]byte("x")), Size: 1, Content: []byte("x")})
	wantStatus(t, onlyUnit(t, h.run(notRead)), PRStatusFailed, ReasonArtifactsUnusable)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

func TestPRStageLanguageManualUnits(t *testing.T) {
	fx := langFixtures()["npm"]
	cases := map[string]func(*LanguageItem){
		"no lockfile among the files": func(it *LanguageItem) { it.Source.Files = it.Source.Files[1:] },
		"source check not passed":     func(it *LanguageItem) { it.SourceCheck.Passed = false },
		"no source check":             func(it *LanguageItem) { it.SourceCheck = nil },
		"no artifacts":                func(it *LanguageItem) { it.Artifacts = nil },
		"package without a version":   func(it *LanguageItem) { it.Packages[0].AdoptedVersion = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := langHarness(t, fx)
			it := h.langItem(fx)
			it.Packages = append([]LanguagePackage(nil), it.Packages...)
			mutate(&it)
			u := onlyUnit(t, h.run(prLangPlan(it)))
			wantStatus(t, u, PRStatusManual, ReasonArtifactsUnusable)
			if h.gh.writeCount() != 0 {
				t.Errorf("writes = %d", h.gh.writeCount())
			}
		})
	}
}

func TestPRStageLanguageOnlyPRCandidatesBecomeUnits(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	it := h.langItem(fx)
	it.Category = CategoryDependencyUpdateCandidate
	res := h.run(prLangPlan(it))
	if len(res.Units) != 0 || h.gh.writeCount() != 0 {
		t.Errorf("units = %+v, writes = %d", res.Units, h.gh.writeCount())
	}
}

func TestPRStageLanguageSharesTheLimits(t *testing.T) {
	a, b := langFixtures()["npm"], langFixtures()["pip"]
	h := langHarness(t, a)
	h.addFiles(b.files)
	h.limits = PRLimits{NewPRsPerCycle: 1, OpenPRs: 10}
	ia, ib := h.langItem(a), h.langItem(b)
	res := h.run(prLangPlan(ia, ib))
	if len(res.Units) != 2 {
		t.Fatalf("units = %+v", res.Units)
	}
	wantStatus(t, res.Units[0], PRStatusCreated, "")
	wantStatus(t, res.Units[1], PRStatusDeferred, ReasonPRLimit)
	// The next cycle takes the deferred one; the first stays open.
	res = h.run(prLangPlan(ia, ib))
	wantStatus(t, res.Units[0], PRStatusOpen, "")
	wantStatus(t, res.Units[1], PRStatusCreated, "")
	if len(h.gh.pulls(testRepo)) != 2 {
		t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
	}

	// The open pull request limit counts them too.
	h.limits = PRLimits{NewPRsPerCycle: 5, OpenPRs: 2}
	c := langFixtures()["uv"]
	h.addFiles(c.files)
	res = h.run(prLangPlan(ia, ib, h.langItem(c)))
	wantStatus(t, res.Units[2], PRStatusDeferred, ReasonPRLimit)
}

func TestPRStageLanguageReplacesAnOlderPullRequestItCovers(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	h.run(prLangPlan(h.langItem(fx)))

	both := fx
	both.pkgs = append(append([]LanguagePackage(nil), fx.pkgs...), npmPackage("lodash", "4.17.15", "4.17.21", "CVE-2021-23337", "node_modules/lodash"))
	both.updated = map[string]string{"package-lock.json": "{\"lock\":3}\n"}
	res := h.run(prLangPlan(h.langItem(both)))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Replaced) != 1 || u.Replaced[0] != 1 || u.Number != 2 {
		t.Errorf("unit = %+v", u)
	}
	pulls := h.gh.pulls(testRepo)
	if pulls[0].State != "closed" || pulls[1].State != "open" {
		t.Errorf("states = %s, %s", pulls[0].State, pulls[1].State)
	}
	cs := h.gh.comments(testRepo, 1)
	if len(cs) != 1 || !hasSupersedeMarker(cs[0].Body, 2, u.UpdateKey) {
		t.Errorf("comments = %+v", cs)
	}
	rec := h.load()
	if rec.PRs[0].State != PRStateReplaced || rec.PRs[0].ReplacedBy != 2 || rec.PRs[0].Lang == nil {
		t.Errorf("old record = %+v", rec.PRs[0])
	}

	// The replaced one is not proposed again, and the new one stays.
	again := onlyUnit(t, h.run(prLangPlan(h.langItem(both))))
	wantStatus(t, again, PRStatusOpen, "")
	if len(h.gh.pulls(testRepo)) != 2 {
		t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
	}
}

// The vulnerabilities are not part of the update key: the same packages at the
// same places and versions are the same update, whatever is reported for them.
func TestPRStageLanguageSameUpdateWithAnotherFindingIsTheSamePullRequest(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	h.run(prLangPlan(h.langItem(fx)))
	next := fx
	next.pkgs = []LanguagePackage{npmPackage("minimist", "1.2.5", "1.2.6", "CVE-2020-7598", "node_modules/minimist")}
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(h.langItem(next)))), PRStatusOpen, "")
	if len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
	}
}

func TestPRStageLanguageDoesNotReplaceWhatItDoesNotCover(t *testing.T) {
	cases := map[string]func(fx langFixture) LanguagePackage{
		"another package": func(langFixture) LanguagePackage {
			return npmPackage("lodash", "4.17.15", "4.17.21", "CVE-2021-23337", "node_modules/lodash")
		},
		"another position": func(langFixture) LanguagePackage {
			return npmPackage("minimist", "1.2.5", "1.2.6", "CVE-2021-44906", "node_modules/b/node_modules/minimist")
		},
	}
	for name, other := range cases {
		t.Run(name, func(t *testing.T) {
			fx := langFixtures()["npm"]
			h := langHarness(t, fx)
			h.run(prLangPlan(h.langItem(fx)))

			next := fx
			next.pkgs = []LanguagePackage{other(fx)}
			res := h.run(prLangPlan(h.langItem(next)))
			u := onlyUnit(t, res)
			wantStatus(t, u, PRStatusDeferred, ReasonOpenPRNotInherited)
			pulls := h.gh.pulls(testRepo)
			if len(pulls) != 1 || pulls[0].State != "open" {
				t.Errorf("pulls = %+v", pulls)
			}
		})
	}
}

func TestPRStageLanguagePullClosedByAPersonIsNotProposedAgain(t *testing.T) {
	fx := langFixtures()["pnpm"]
	h := langHarness(t, fx)
	h.run(prLangPlan(h.langItem(fx)))
	h.gh.editPull(testRepo, 1, func(pr *github.PullRequest) { pr.State = "closed" })
	u := onlyUnit(t, h.run(prLangPlan(h.langItem(fx))))
	wantStatus(t, u, PRStatusSuppressed, "")
	if len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
	}
}

func TestPRStageLanguageRecoversFromMarkers(t *testing.T) {
	fx := langFixtures()["uv"]
	h := langHarness(t, fx)
	plan := prLangPlan(h.langItem(fx))
	h.run(plan)
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	writes := h.gh.writeCount()
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusOpen, "")
	if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("writes %d -> %d, pulls %d", writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
	}
	rec := h.load()
	if len(rec.PRs) != 1 || rec.PRs[0].Kind != "language" || !rec.PRs[0].MarkerOnly || rec.PRs[0].Lang == nil || len(rec.PRs[0].FixTargets) != 1 {
		t.Errorf("recovered record = %+v", rec.PRs)
	}
}

func TestPRStageLanguageResumesABranchWithoutAPull(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	plan := prLangPlan(h.langItem(fx))
	h.gh.failNext("CreatePull", failLostNotApplied)
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusDeferred, ReasonWriteOutcomeUnknown)
	// The next cycle finds the branch and no pull request, and opens it from
	// the same branch.
	u = onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusCreated, "")
	if n := countCalls(h.gh, "CreateCommit"); n != 1 {
		t.Errorf("commits = %d, want the one of the first cycle", n)
	}
	if len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
	}
}

func TestLanguageBodyStatesWhatWasChecked(t *testing.T) {
	fx := langFixtures()["pnpm"]
	fx.pkgs[0].Name = "evil`@octocat"
	fx.pkgs[0].CVEs = []CVERef{{VulnID: "CVE-1`@x", Severity: scanner.SeverityCritical, KEV: true, Priority: PriorityActNow}}
	h := langHarness(t, fx)
	h.run(prLangPlan(h.langItem(fx)))
	body := h.gh.pulls(testRepo)[0].Body
	for _, want := range []string{
		"Before merging, run a CI job that installs from the lockfile (for example `pnpm install --frozen-lockfile`)",
		"Scan of the dependency files before and after",
		"Resolved 1, remaining 0, introduced 0",
		"in the CISA KEV catalog",
		"priority `act_now`",
		"`svc/pnpm-lock.yaml`",
		"the npm registry",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	for _, gone := range []string{"## Not verified", "## Why these versions", "Opened by KestreLynx", "treated as untrusted", "not of an image"} {
		if strings.Contains(body, gone) {
			t.Errorf("body still has %q", gone)
		}
	}
	// An external name can neither close its code span nor start a mention.
	// The marker line is an HTML comment and carries the raw name.
	text := body[:strings.Index(body, markerPrefix)]
	if !strings.Contains(text, "`evil'@octocat`") || strings.Contains(text, "evil`@octocat") {
		t.Error("the package name was not rendered as inert code")
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "@") {
			t.Errorf("a line starts with a mention: %q", line)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(body), " -->") {
		t.Error("the marker is not last")
	}
}

func TestLanguageUpdateKeyIgnoresOrder(t *testing.T) {
	a := []LangKeyEntry{{Ecosystem: "node-pkg", Name: "a", Positions: []string{"x", "y"}, Adopted: "2"}, {Ecosystem: "node-pkg", Name: "b", Positions: []string{"z"}, Adopted: "3"}}
	b := []LangKeyEntry{{Ecosystem: "node-pkg", Name: "b", Positions: []string{"z"}, Adopted: "3"}, {Ecosystem: "node-pkg", Name: "a", Positions: []string{"y", "x"}, Adopted: "2"}}
	e1 := []LangEdit{{File: "p", Section: "s", Name: "a", From: "1", To: "2"}, {File: "p", Section: "s", Name: "b", From: "1", To: "3", Major: true}}
	e2 := []LangEdit{e1[1], e1[0]}
	e2[0].Major = false // derived, not part of the key
	if LangUpdateKey("t", a, e1) != LangUpdateKey("t", b, e2) {
		t.Error("the key depends on the order or on the derived flag")
	}
	c := append([]LangKeyEntry(nil), a...)
	c[0].Adopted = "9"
	for name, other := range map[string]string{
		"version":  LangUpdateKey("t", c, e1),
		"target":   LangUpdateKey("u", a, e1),
		"no edits": LangUpdateKey("t", a, nil),
		"position": LangUpdateKey("t", []LangKeyEntry{{Ecosystem: "node-pkg", Name: "a", Positions: []string{"x"}, Adopted: "2"}, a[1]}, e1),
	} {
		if other == LangUpdateKey("t", a, e1) {
			t.Errorf("a different %s gives the same key", name)
		}
	}
}

func TestLanguageMarkerRejectsTampering(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	h.run(prLangPlan(h.langItem(fx)))
	m, err := parsePRMarker(h.gh.pulls(testRepo)[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	m.Lang.Packages = append([]LangKeyEntry(nil), m.Lang.Packages...)
	m.Lang.Packages[0].Adopted = "9.9.9"
	if err := m.verify(testRepoID); err == nil {
		t.Error("a marker with another version verified")
	}
	m.Lang = nil
	if m.wellFormed() == nil {
		t.Error("a language marker without a language record is well formed")
	}
	// A Compose marker may not carry one.
	cm := PRMarker{Kind: "", Lang: &LangRecord{Manager: "npm"}}
	if cm.wellFormed() == nil {
		t.Error("a Compose marker with a language record is well formed")
	}
}

func TestPRStageLanguageDoesNotReplaceAPullRequestAPersonChanged(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	h.run(prLangPlan(h.langItem(fx)))
	h.gh.pushToPull(testRepo, 1)

	both := fx
	both.pkgs = append(append([]LanguagePackage(nil), fx.pkgs...), npmPackage("lodash", "4.17.15", "4.17.21", "CVE-2021-23337", "node_modules/lodash"))
	both.updated = map[string]string{"package-lock.json": "{\"lock\":3}\n"}
	u := onlyUnit(t, h.run(prLangPlan(h.langItem(both))))
	wantStatus(t, u, PRStatusCreated, "")
	if len(u.Replaced) != 0 {
		t.Errorf("replaced = %v", u.Replaced)
	}
	if pulls := h.gh.pulls(testRepo); len(pulls) != 2 || pulls[0].State != "open" {
		t.Errorf("pulls = %+v", pulls)
	}
}

// setMode moves main to a commit in which a file has the mode, with the same
// content, as a person changing the file's permissions.
func (h *prHarness) setMode(path, mode string) {
	h.gh.mu.Lock()
	defer h.gh.mu.Unlock()
	rs := h.gh.repos[strings.ToLower(testRepo)]
	parent := rs.branches["main"]
	tree := map[string]fakeEntry{}
	for p, e := range rs.trees[rs.commits[parent].tree] {
		tree[p] = e
	}
	e := tree[path]
	e.mode = mode
	tree[path] = e
	tsha := h.gh.treeSHA(tree)
	rs.trees[tsha] = tree
	h.gh.counter++
	csha := fakeSHA("mode", tsha, string(rune('a'+h.gh.counter)))
	rs.commits[csha] = fakeCommit{tree: tsha, parents: []string{parent}}
	rs.branches["main"] = csha
}

func TestPRStageLanguageFileModeChangedSincePlanWaits(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	plan := prLangPlan(h.langItem(fx)) // planned with mode 100644
	h.setMode("package-lock.json", "100755")
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusDeferred, ReasonSourceChanged)
	if !strings.Contains(u.Detail, "package-lock.json") || !strings.Contains(u.Detail, "100755") || h.gh.writeCount() != 0 {
		t.Errorf("detail %q, writes %d", u.Detail, h.gh.writeCount())
	}
	// Planned again against the new mode, the update is written with it.
	it := h.langItem(fx)
	for i := range it.Artifacts {
		it.Artifacts[i].Mode = "100755"
	}
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusCreated, "")
	pr := h.gh.pulls(testRepo)[0]
	f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "package-lock.json")
	if err != nil || f.Mode != "100755" {
		t.Errorf("mode in the pull request = %q (%v)", f.Mode, err)
	}
}

func TestPRStageLanguageUnknownPlannedModeTakesTheCurrentOne(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	h.setMode("package-lock.json", "100755")
	it := h.langItem(fx)
	for i := range it.Artifacts {
		it.Artifacts[i].Mode = ""
	}
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusCreated, "")
	f, err := h.gh.ReadFile(context.Background(), testRepo, h.gh.pulls(testRepo)[0].HeadSHA, "package-lock.json")
	if err != nil || f.Mode != "100755" {
		t.Errorf("mode = %q (%v)", f.Mode, err)
	}
}
