package remediation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// candidateOf is the item as the planner leaves it, before any update ran.
func candidateOf(it LanguageItem) LanguageItem {
	it.Category, it.Reason, it.Detail = CategoryDependencyUpdateCandidate, ReasonUpdateCandidateInSource, ""
	it.Artifacts, it.Update, it.SourceCheck = nil, nil, nil
	it.UpdateExecuted, it.PostUpdateCheckExecuted = false, false
	pk := append([]LanguagePackage(nil), it.Packages...)
	for i := range pk {
		pk[i].AdoptedVersion = ""
	}
	it.Packages = pk
	return it
}

// stageRun is an update stage that has the first max items pass, taking each
// one's result from done, and defers the rest as the real one does at its
// job limit.
type stageRun struct {
	max  int
	done map[string]LanguageItem
	saw  []string
}

func (s *stageRun) run(_ context.Context, p *Plan) LangUpdateUsage {
	jobs := 0
	for i := range p.LanguageItems {
		it := &p.LanguageItems[i]
		s.saw = append(s.saw, it.Key)
		if jobs >= s.max {
			it.Category, it.Reason = CategoryDeferred, ReasonUpdateJobLimit
			continue
		}
		jobs++
		*it = s.done[it.Key]
	}
	return LangUpdateUsage{Jobs: jobs}
}

func allFixtureHarness(t *testing.T) (*prHarness, []langFixture) {
	t.Helper()
	fxs := []langFixture{langFixtures()["npm"], langFixtures()["pnpm"], langFixtures()["pip"], langFixtures()["uv"]}
	h := newPRHarness(t)
	for _, fx := range fxs {
		h.addFiles(fx.files)
	}
	return h, fxs
}

func TestLanguageUpdateFingerprintIgnoresTheCommitAndTheUpdate(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	done := h.langItem(fx)
	cand := candidateOf(done)
	if LanguageInputFingerprint(done) != LanguageInputFingerprint(cand) {
		t.Fatal("the fingerprint of an item changes when its update runs")
	}
	moved := cand
	moved.Source.CommitSHA = strings.Repeat("9", 40)
	if LanguageInputFingerprint(moved) != LanguageInputFingerprint(cand) {
		t.Error("the fingerprint depends on the commit")
	}
	files := cand
	files.Source.Files = append([]SourceFile(nil), cand.Source.Files...)
	files.Source.Files[0].BlobSHA = strings.Repeat("8", 40)
	pk := cand
	pk.Packages = append([]LanguagePackage(nil), cand.Packages...)
	pk.Packages[0].SelectionLowerBound = "1.2.9"
	other := cand
	other.Key += "x"
	for name, it := range map[string]LanguageItem{"a file's blob": files, "a target version": pk, "the item": other} {
		if LanguageInputFingerprint(it) == LanguageInputFingerprint(cand) {
			t.Errorf("the fingerprint ignores %s", name)
		}
	}
}

func TestLanguageUpdatesTiedToOpenPullRequestsDoNotUseTheJobLimit(t *testing.T) {
	h, fxs := allFixtureHarness(t)
	var done []LanguageItem
	stage := &stageRun{max: 3, done: map[string]LanguageItem{}}
	for _, fx := range fxs {
		it := h.langItem(fx)
		done = append(done, it)
		stage.done[it.Key] = it
	}
	// Cycle 1: three units get their pull requests.
	res := h.run(prLangPlan(done[:3]...))
	for _, u := range res.Units {
		wantStatus(t, u, PRStatusCreated, "")
	}

	// Cycle 2: four candidates and a limit of three jobs. The three with a
	// pull request made from the same inputs are tied to it; the fourth runs.
	plan := prLangPlan(candidateOf(done[0]), candidateOf(done[1]), candidateOf(done[2]), candidateOf(done[3]))
	use, bound := RunLanguageUpdates(context.Background(), stage.run, &plan, h.store)
	if bound != 3 || use.Jobs != 1 || len(stage.saw) != 1 || stage.saw[0] != done[3].Key {
		t.Fatalf("bound %d, jobs %d, the stage saw %v", bound, use.Jobs, stage.saw)
	}
	for i := 0; i < 3; i++ {
		if it := plan.LanguageItems[i]; it.Category != CategoryPRCandidate || it.Reason != ReasonUpdateAlreadyProposed || !strings.Contains(it.Detail, "pull request #") {
			t.Errorf("item %d = %s/%s/%s", i, it.Category, it.Reason, it.Detail)
		}
	}
	if it := plan.LanguageItems[3]; it.Category != CategoryPRCandidate || it.Reason != ReasonUpdateVerified {
		t.Errorf("the fourth = %s/%s", it.Category, it.Reason)
	}
	writes := h.gh.writeCount()
	res = h.run(plan)
	if len(res.Units) != 4 {
		t.Fatalf("units = %+v", res.Units)
	}
	for i, u := range res.Units {
		if i < 3 {
			wantStatus(t, u, PRStatusOpen, "")
			if u.Number != i+1 || u.Language == nil || len(u.Language.Packages) == 0 || u.ItemKey != plan.LanguageItems[i].Key {
				t.Errorf("tied unit %d = %+v", i, u)
			}
		} else {
			wantStatus(t, u, PRStatusCreated, "")
		}
	}
	if len(h.gh.pulls(testRepo)) != 4 || h.gh.writeCount() == writes {
		t.Errorf("pulls %d, writes %d -> %d", len(h.gh.pulls(testRepo)), writes, h.gh.writeCount())
	}

	// Cycle 3: all four are tied; nothing runs and nothing is written.
	stage.saw = nil
	plan = prLangPlan(candidateOf(done[0]), candidateOf(done[1]), candidateOf(done[2]), candidateOf(done[3]))
	use, bound = RunLanguageUpdates(context.Background(), stage.run, &plan, h.store)
	if bound != 4 || use.Jobs != 0 || len(stage.saw) != 0 {
		t.Fatalf("bound %d, jobs %d, saw %v", bound, use.Jobs, stage.saw)
	}
	writes = h.gh.writeCount()
	for _, u := range h.run(plan).Units {
		wantStatus(t, u, PRStatusOpen, "")
	}
	if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 4 {
		t.Errorf("writes %d -> %d, pulls %d", writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
	}
}

func TestLanguageUpdateWithChangedInputsRunsAgainAndAfterTheOthers(t *testing.T) {
	h, fxs := allFixtureHarness(t)
	npm, uv := h.langItem(fxs[0]), h.langItem(fxs[3])
	h.run(prLangPlan(npm))

	// A person updates the lockfile on the base: the npm unit's inputs differ.
	changed := fxs[0]
	changed.files = map[string]string{"package-lock.json": "{\"lock\":\"newer\"}\n", "package.json": changed.files["package.json"]}
	h.addFiles(changed.files)
	npmNow := candidateOf(h.langItem(changed))
	uvNow := candidateOf(uv)
	// Planned in the order npm, uv: the unit with a pull request comes last.
	plan := prLangPlan(npmNow, uvNow)
	order, bound := BindProposedLanguageUpdates(&plan, h.store)
	if bound != 0 || len(order) != 2 || order[0] != 1 || order[1] != 0 {
		t.Errorf("order %v, bound %d, want the unit without a pull request first", order, bound)
	}
	if plan.LanguageItems[0].Category != CategoryDependencyUpdateCandidate {
		t.Errorf("the changed unit was tied: %s/%s", plan.LanguageItems[0].Category, plan.LanguageItems[0].Reason)
	}

	// At a limit of one job the unit without a pull request is the one that runs.
	stage := &stageRun{max: 1, done: map[string]LanguageItem{uv.Key: uv}}
	plan = prLangPlan(npmNow, uvNow)
	RunLanguageUpdates(context.Background(), stage.run, &plan, h.store)
	if plan.LanguageItems[1].Category != CategoryPRCandidate || plan.LanguageItems[0].Category != CategoryDeferred || plan.LanguageItems[0].Reason != ReasonUpdateJobLimit {
		t.Errorf("npm %s/%s, uv %s/%s", plan.LanguageItems[0].Category, plan.LanguageItems[0].Reason, plan.LanguageItems[1].Category, plan.LanguageItems[1].Reason)
	}
}

func TestLanguageUpdateTiedToAClosedPullRequestIsNotRunAgain(t *testing.T) {
	fx := langFixtures()["pnpm"]
	h := langHarness(t, fx)
	done := h.langItem(fx)
	h.run(prLangPlan(done))
	h.gh.editPull(testRepo, 1, func(pr *github.PullRequest) { pr.State = "closed" })
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(done))), PRStatusSuppressed, "") // the record is now closed

	stage := &stageRun{max: 3, done: map[string]LanguageItem{done.Key: done}}
	plan := prLangPlan(candidateOf(done))
	use, bound := RunLanguageUpdates(context.Background(), stage.run, &plan, h.store)
	if bound != 1 || use.Jobs != 0 || len(stage.saw) != 0 {
		t.Fatalf("bound %d, jobs %d, saw %v", bound, use.Jobs, stage.saw)
	}
	writes := h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusSuppressed, "")
	if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("writes %d -> %d, pulls %d", writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
	}
}

func TestLanguageUpdateRecordWithoutAFingerprintIsNotTiedTo(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	done := h.langItem(fx)
	h.run(prLangPlan(done))
	f := h.load()
	f.PRs[0].Lang.InputFingerprint = "" // a record made before fingerprints existed
	if err := h.store.Save(f); err != nil {
		t.Fatal(err)
	}
	plan := prLangPlan(candidateOf(done))
	order, bound := BindProposedLanguageUpdates(&plan, h.store)
	if bound != 0 || len(order) != 1 {
		t.Errorf("order %v, bound %d", order, bound)
	}
	// Without readable records nothing is tied either.
	order, bound = BindProposedLanguageUpdates(&plan, PRStore{Dir: filepath.Join(t.TempDir(), "none")})
	if bound != 0 || len(order) != 1 {
		t.Errorf("order %v, bound %d without records", order, bound)
	}
	order, bound = BindProposedLanguageUpdates(&plan, nil)
	if bound != 0 || len(order) != 1 {
		t.Errorf("order %v, bound %d without a store", order, bound)
	}
}

// A record rebuilt from a marker does not stand for an update: anyone who can
// push can write a marker. The update runs again, matches the record by its
// key and nothing is opened twice.
func TestLanguageUpdateTieDoesNotUseRecordsRebuiltFromMarkers(t *testing.T) {
	fx := langFixtures()["uv"]
	h := langHarness(t, fx)
	done := h.langItem(fx)
	h.run(prLangPlan(done))
	plan := prLangPlan(candidateOf(done))
	if _, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 1 {
		t.Fatal("not tied")
	}
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}
	// The cycle that tied the item meets lost records: it waits and writes nothing.
	writes := h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonProposalNotFound)
	if h.gh.writeCount() != writes {
		t.Errorf("writes %d -> %d", writes, h.gh.writeCount())
	}
	// The records are rebuilt from the marker, and are still not used to tie.
	plan = prLangPlan(candidateOf(done))
	order, bound := BindProposedLanguageUpdates(&plan, h.store)
	if bound != 0 || len(order) != 1 {
		t.Errorf("order %v, bound %d: a marker-only record tied an item", order, bound)
	}
	// The update runs, matches the record by its key, and opens nothing. The
	// program's own computation checks the record's inputs.
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(done))), PRStatusOpen, "")
	if len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
	}
	rec := h.load().PRs[0]
	if !rec.MarkerOnly || !rec.Recovered || !rec.InputVerified || rec.Lang.InputFingerprint != LanguageInputFingerprint(done) {
		t.Errorf("record = marker-only %v, recovered %v, verified %v, fingerprint %q", rec.MarkerOnly, rec.Recovered, rec.InputVerified, rec.Lang.InputFingerprint)
	}
	// From the next cycle it stands for the update.
	plan = prLangPlan(candidateOf(done))
	if order, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 1 || len(order) != 0 {
		t.Errorf("order %v, bound %d after the inputs were verified", order, bound)
	}
	writes = h.gh.writeCount()
	wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusOpen, "")
	if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("writes %d -> %d, pulls %d", writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
	}
}

// The mark is made by the program's own computation only: a fingerprint the
// marker carries is replaced, and a record that does not match the unit's
// target key, repository ID or manager gets no mark.
func TestPRStageLanguageVerifiesAMarkerRecordOnlyByItsOwnComputation(t *testing.T) {
	fx := langFixtures()["npm"]
	prepare := func(t *testing.T) (*prHarness, LanguageItem) {
		h := langHarness(t, fx)
		done := h.langItem(fx)
		h.run(prLangPlan(done))
		if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
			t.Fatal(err)
		}
		h.run(prLangPlan(done)) // rebuilt from the marker, and verified
		f := h.load()
		f.PRs[0].InputVerified = false
		f.PRs[0].Lang.InputFingerprint = "forged-in-the-marker"
		if err := h.store.Save(f); err != nil {
			t.Fatal(err)
		}
		return h, done
	}
	t.Run("the marker's fingerprint is replaced", func(t *testing.T) {
		h, done := prepare(t)
		h.run(prLangPlan(done))
		rec := h.load().PRs[0]
		if !rec.InputVerified || rec.Lang.InputFingerprint != LanguageInputFingerprint(done) {
			t.Errorf("record = verified %v, fingerprint %q", rec.InputVerified, rec.Lang.InputFingerprint)
		}
	})
	for name, forge := range map[string]func(*PRRecord){
		"another repository ID": func(r *PRRecord) { r.RepoID = 999 },
		"another manager":       func(r *PRRecord) { r.Lang.Manager = "pnpm" },
		"another target key":    func(r *PRRecord) { r.TargetKey = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			h, done := prepare(t)
			f := h.load()
			forge(&f.PRs[0])
			if err := h.store.Save(f); err != nil {
				t.Fatal(err)
			}
			h.run(prLangPlan(done))
			for _, rec := range h.load().PRs {
				if rec.InputVerified && rec.RepoID != testRepoID {
					t.Errorf("a record that does not match was marked: %+v", rec)
				}
				if rec.InputVerified && rec.Lang.Manager != "npm" {
					t.Errorf("a record that does not match was marked: %+v", rec)
				}
			}
		})
	}
}

// A fingerprint written into a record, or its marker, does not tie an item of
// another directory, manager or repository to the pull request.
func TestLanguageUpdateTieNeedsTheItemsOwnTarget(t *testing.T) {
	npm := langFixtures()["npm"]
	h := langHarness(t, npm)
	h.run(prLangPlan(h.langItem(npm)))

	other := langFixture{
		manager: ManagerNpm, root: "other",
		files:   map[string]string{"other/package.json": "{}\n", "other/package-lock.json": "{\"lock\":1}\n"},
		updated: map[string]string{"other/package-lock.json": "{\"lock\":2}\n"},
		pkgs:    npm.pkgs,
	}
	pnpm := langFixtures()["pnpm"]
	h.addFiles(other.files)
	h.addFiles(pnpm.files)
	for name, fx := range map[string]langFixture{"another directory": other, "another manager": pnpm} {
		cand := candidateOf(h.langItem(fx))
		f := h.load()
		f.PRs[0].Lang.InputFingerprint = LanguageInputFingerprint(cand) // forged
		if err := h.store.Save(f); err != nil {
			t.Fatal(err)
		}
		plan := prLangPlan(cand)
		if order, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 0 || len(order) != 1 {
			t.Errorf("%s: order %v, bound %d", name, order, bound)
		}
		// Not even when the item was tied by other means: the stage checks too.
		plan.LanguageItems[0].Category, plan.LanguageItems[0].Reason = CategoryPRCandidate, ReasonUpdateAlreadyProposed
		writes := h.gh.writeCount()
		wantStatus(t, onlyUnit(t, h.run(plan)), PRStatusDeferred, ReasonProposalNotFound)
		if h.gh.writeCount() != writes {
			t.Errorf("%s: writes %d -> %d", name, writes, h.gh.writeCount())
		}
	}

	// The repository ID must be the record's too.
	same := candidateOf(h.langItem(npm))
	f := h.load()
	f.PRs[0].Lang.InputFingerprint = LanguageInputFingerprint(same)
	f.PRs[0].RepoID = 999
	if err := h.store.Save(f); err != nil {
		t.Fatal(err)
	}
	fp := LanguageInputFingerprint(same)
	if rec := f.proposalFor(same, fp, testRepoID); rec != nil {
		t.Errorf("a record of repository 999 stood for an item of repository %d", testRepoID)
	}
	if rec := f.proposalFor(same, fp, 0); rec != nil {
		t.Error("a record whose target key does not belong to its repository ID stood for the item")
	}
}

func TestLanguageUpdateTiedUnitShowsMajorFromTheItemsVersions(t *testing.T) {
	fx := langFixtures()["npm"]
	fx.pkgs = append([]LanguagePackage(nil), fx.pkgs...)
	fx.pkgs[0].Installed, fx.pkgs[0].AdoptedVersion = "1.2.5", "2.0.1"
	h := langHarness(t, fx)
	done := h.langItem(fx)
	if u := onlyUnit(t, h.run(prLangPlan(done))); !u.Language.Packages[0].Major {
		t.Fatal("not major when created")
	}
	// The stored view loses its flag and versions; a tied unit does not use it.
	f := h.load()
	f.PRs[0].Language = &PRLanguage{Manager: "npm", Root: ".", Packages: []PRLanguagePackage{{Name: "minimist"}}}
	if err := h.store.Save(f); err != nil {
		t.Fatal(err)
	}
	plan := prLangPlan(candidateOf(done))
	if _, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 1 {
		t.Fatal("not tied")
	}
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusOpen, "")
	p := u.Language.Packages[0]
	if !p.Major || p.From != "1.2.5" || p.To != "2.0.1" {
		t.Errorf("package = %+v", p)
	}
}

func TestLanguageUpdateTiedToAPullRequestThatIsGoneWaits(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	plan := prLangPlan(candidateOf(h.langItem(fx)))
	plan.LanguageItems[0].Category, plan.LanguageItems[0].Reason = CategoryPRCandidate, ReasonUpdateAlreadyProposed
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusDeferred, ReasonProposalNotFound)
	if h.gh.writeCount() != 0 {
		t.Errorf("writes = %d", h.gh.writeCount())
	}
}

func TestPRStageLanguageBodyMarksMajorVersionChanges(t *testing.T) {
	cases := []struct {
		name     string
		fx       func() langFixture
		from, to string
		major    bool
	}{
		{"npm transitive major", func() langFixture { return langFixtures()["npm"] }, "1.2.5", "2.0.1", true},
		{"npm minor", func() langFixture { return langFixtures()["npm"] }, "1.2.5", "1.3.0", false},
		{"npm 0.x minor", func() langFixture { return langFixtures()["npm"] }, "0.5.1", "0.6.0", true},
		{"npm 0.x patch", func() langFixture { return langFixtures()["npm"] }, "0.5.1", "0.5.9", false},
		{"pip pin major", func() langFixture { return langFixtures()["pip"] }, "1.26.4", "2.0.6", true},
		{"uv patch", func() langFixture { return langFixtures()["uv"] }, "1.26.4", "1.26.17", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := c.fx()
			fx.pkgs = append([]LanguagePackage(nil), fx.pkgs...)
			fx.pkgs[0].Installed, fx.pkgs[0].AdoptedVersion = c.from, c.to
			h := langHarness(t, fx)
			u := onlyUnit(t, h.run(prLangPlan(h.langItem(fx))))
			wantStatus(t, u, PRStatusCreated, "")
			body := h.gh.pulls(testRepo)[0].Body
			top := body[:strings.Index(body, "## Change")]
			change := body[strings.Index(body, "## Change"):strings.Index(body, "### Vulnerabilities")]
			has := strings.Contains(top, "move to another major version") && strings.Contains(change, "**major version change**")
			if has != c.major || u.Language.Packages[0].Major != c.major {
				t.Errorf("major = %v (unit %v), want %v\n%s", has, u.Language.Packages[0].Major, c.major, body[:strings.Index(body, "## Why")])
			}
			if c.major && !strings.Contains(top, "Review these first") {
				t.Error("no note near the top")
			}
		})
	}
}

func TestPRStageLanguageAddsAMissingFingerprintToTheMatchedRecord(t *testing.T) {
	for _, state := range []string{"open", "closed"} {
		t.Run(state, func(t *testing.T) {
			fx := langFixtures()["npm"]
			h := langHarness(t, fx)
			done := h.langItem(fx)
			h.run(prLangPlan(done))
			body := h.gh.pulls(testRepo)[0].Body
			if state == "closed" {
				h.gh.editPull(testRepo, 1, func(pr *github.PullRequest) { pr.State = "closed" })
			}
			f := h.load()
			f.PRs[0].Lang.InputFingerprint = "" // made before fingerprints existed
			if err := h.store.Save(f); err != nil {
				t.Fatal(err)
			}
			plan := prLangPlan(candidateOf(done))
			if _, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 0 {
				t.Fatal("tied without a fingerprint")
			}

			// The update runs once more, matches the record by its key and
			// leaves its fingerprint there.
			res := h.run(prLangPlan(done))
			if res.Units[0].Number != 1 || len(h.gh.pulls(testRepo)) != 1 {
				t.Fatalf("unit %+v, pulls %d", res.Units[0], len(h.gh.pulls(testRepo)))
			}
			if got := h.load().PRs[0].Lang.InputFingerprint; got != LanguageInputFingerprint(done) {
				t.Errorf("fingerprint = %q", got)
			}
			if h.gh.pulls(testRepo)[0].Body != body {
				t.Error("the description was rewritten")
			}
			plan = prLangPlan(candidateOf(done))
			if _, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 1 {
				t.Error("the next cycle still runs the update")
			}
		})
	}
}

func TestPRStageLanguageKeepsAFingerprintTheRecordHas(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	done := h.langItem(fx)
	h.run(prLangPlan(done))
	f := h.load()
	f.PRs[0].Lang.InputFingerprint = "the-inputs-it-was-made-from"
	if err := h.store.Save(f); err != nil {
		t.Fatal(err)
	}
	h.run(prLangPlan(done)) // same update key, other inputs
	if got := h.load().PRs[0].Lang.InputFingerprint; got != "the-inputs-it-was-made-from" {
		t.Errorf("fingerprint = %q, want it kept", got)
	}
}
