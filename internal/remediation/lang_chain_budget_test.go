package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The project of these tests is a pnpm project of two direct dependencies:
// mkdirp, which requires minimist, and holder (^1.0.0), which requires pinned
// at exactly 2.0.0. pinned is fixed in 2.0.2, which holder 1.1.0 allows.

const chainManifest = `{"name":"fixture-chain","version":"1.0.0","private":true,"dependencies":{"holder":"^1.0.0","mkdirp":"0.5.5"}}`

func chainIntegrity(name, ver string) string {
	switch name + "@" + ver {
	case "minimist@1.2.8":
		return minimist128.Integrity
	case "minimist@1.2.5":
		return "sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw=="
	case "mkdirp@0.5.5":
		return "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ=="
	}
	return partialIntegrity(name, ver)
}

// chainLock makes the pnpm-lock.yaml of the project.
func chainLock(holder, pinned, minimist string) string {
	return fmt.Sprintf(`lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      holder:
        specifier: ^1.0.0
        version: %[1]s
      mkdirp:
        specifier: 0.5.5
        version: 0.5.5

packages:

  holder@%[1]s:
    resolution: {integrity: %[4]s}

  minimist@%[3]s:
    resolution: {integrity: %[5]s}

  mkdirp@0.5.5:
    resolution: {integrity: %[6]s}
    hasBin: true

  pinned@%[2]s:
    resolution: {integrity: %[7]s}

snapshots:

  holder@%[1]s:
    dependencies:
      pinned: %[2]s

  minimist@%[3]s: {}

  mkdirp@0.5.5:
    dependencies:
      minimist: %[3]s

  pinned@%[2]s: {}
`, holder, pinned, minimist, chainIntegrity("holder", holder), chainIntegrity("minimist", minimist), chainIntegrity("mkdirp", "0.5.5"), chainIntegrity("pinned", pinned))
}

// newChainHarness is a harness for that project with the packages named
// updated. The work container leaves the lockfile as it is on the first run
// and returns lockFor(n) on the later ones.
func newChainHarness(t *testing.T, packages []string, lockFor func(n int) string) *harness {
	t.Helper()
	files := map[string]string{"package.json": chainManifest, "pnpm-lock.yaml": chainLock("1.0.0", "2.0.0", "1.2.5")}
	origin := func(name string) FindingOrigin {
		return FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/" + name + "/package.json"}
	}
	var groups []*findingGroup
	for _, name := range packages {
		switch name {
		case "minimist":
			groups = append(groups, group(typeNodePkg, "minimist", "1.2.5", origin("minimist"), CVERef{VulnID: "CVE-A", FixedVers: []string{"1.2.8"}}))
		case "pinned":
			groups = append(groups, group(typeNodePkg, "pinned", "2.0.0", origin("pinned"), CVERef{VulnID: "CVE-B", FixedVers: []string{"2.0.2"}}))
		}
	}
	h := &harness{t: t, fx: fixtureFor("pnpm"), files: files}
	h.item = itemFor(t, ManagerPnpm, files, groups...)
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the project is not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	dist := func(name, ver string, deps map[string]string) NpmDist {
		return NpmDist{Tarball: "https://registry.npmjs.org/" + name + "/-/" + name + "-" + ver + ".tgz", Integrity: chainIntegrity(name, ver), Dependencies: deps}
	}
	h.npm = &fakeNpm{dists: map[string]NpmDist{
		"minimist@1.2.8": minimist128,
		"mkdirp@0.5.5":   dist("mkdirp", "0.5.5", map[string]string{"minimist": "^1.2.5"}),
		"holder@1.0.0":   dist("holder", "1.0.0", map[string]string{"pinned": "2.0.0"}),
		"holder@1.1.0":   dist("holder", "1.1.0", map[string]string{"pinned": "^2.0.2"}),
		"pinned@2.0.2":   dist("pinned", "2.0.2", nil),
	}}
	h.pypi = &fakePyPI{auto: true}
	h.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		lock := string(src["pnpm-lock.yaml"])
		if lockFor != nil {
			if l := lockFor(n); l != "" {
				lock = l
			}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": []byte(lock)}}}
	}}
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) {
		lock := string(in["pnpm-lock.yaml"])
		pkgs := [][2]string{{"mkdirp", "0.5.5"}}
		var vulns [][3]string
		for _, p := range [][3]string{{"holder", "1.0.0", ""}, {"holder", "1.1.0", ""}, {"minimist", "1.2.5", "CVE-A"}, {"minimist", "1.2.8", ""}, {"pinned", "2.0.0", "CVE-B"}, {"pinned", "2.0.2", ""}} {
			if strings.Contains(lock, "\n  "+p[0]+"@"+p[1]+":") {
				pkgs = append(pkgs, [2]string{p[0], p[1]})
				if p[2] != "" {
					vulns = append(vulns, [3]string{p[0], p[1], p[2]})
				}
			}
		}
		return fsReport("pnpm", pkgs, vulns), nil
	}}
	h.cfg = LangUpdateConfig{
		Scanner: h.fs, Work: h.work, PyPI: h.pypi, Npm: h.npm, GitHub: h.gh,
		Prepared: fsConds, Images: map[string]ImageEnv{"img": debianAmd64}, MaxJobs: 5,
	}
	h.cfg = withTestTools(h.t, h.cfg)
	return h
}

// runChain runs the item with the runner registered for pnpm.
func (h *harness) runChain(run chainRunner, tune func(*LangUpdater, *LanguageItem)) (LanguageItem, *LangUpdater) {
	h.t.Helper()
	up, err := NewLangUpdater(h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	up.chainRunners = nil
	if run != nil {
		up.chainRunners = map[DependencyManager]chainRunner{ManagerPnpm: run}
	}
	item := h.item
	item.Packages = append([]LanguagePackage(nil), h.item.Packages...)
	if tune != nil {
		tune(up, &item)
	}
	plan := &Plan{LanguageItems: []LanguageItem{item}}
	up.Run(context.Background(), plan)
	return plan.LanguageItems[0], up
}

// jobRunner is a chain update that runs one container, as a manager's does,
// and judges its result by the checks of the stage. The original lockfile
// stands for the baseline, which the first update already checked.
func jobRunner() chainRunner {
	return func(ctx context.Context, r *updateRun, scope *chainScope) *updateFailure {
		steps := []worker.Step{{ID: stepUpdate, Op: worker.OpPnpmRelock}, {ID: stepCheck, Op: worker.OpPnpmFrozen, Scratch: true}}
		out, fail := r.execReplacing(ctx, worker.ManagerPnpm, r.pnpmInputs(r.manifest, r.src.lock), map[string][]byte{"pnpm-lock.yaml": r.src.lock}, steps, "chain")
		if fail != nil {
			return fail
		}
		base := &jobOutput{files: map[string][]byte{worker.StepsDir + "/" + stepBaseline + "/pnpm-lock.yaml": r.src.lock}}
		return r.finishLockfile(ctx, out, steps, base)
	}
}

func failRunner(f *updateFailure) chainRunner {
	return func(context.Context, *updateRun, *chainScope) *updateFailure { return f }
}

func TestChainStageAdoptsAResultThatPassedEveryCheck(t *testing.T) {
	h := newChainHarness(t, []string{"pinned"}, func(n int) string {
		if n == 0 {
			return ""
		}
		return chainLock("1.1.0", "2.0.2", "1.2.5")
	})
	it, _ := h.runChain(jobRunner(), nil)
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 2 {
		t.Errorf("containers = %d, want the first update's and the chain's", h.work.calls)
	}
	pin := packageOf(t, it, "pinned")
	if pin.Action != ActionUpdate || pin.AdoptedVersion != "2.0.2" || strings.Join(pin.Through, ",") != "holder" {
		t.Errorf("pinned = %+v", pin)
	}
	if string(it.Artifacts[0].Content) != chainLock("1.1.0", "2.0.2", "1.2.5") {
		t.Errorf("the artifact is not the chain's lockfile")
	}
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainAdopted || c.Source != "chain_job" || len(c.Blocked) != 1 || c.Blocked[0].Parent != "holder" || c.Blocked[0].Proof != "exact" ||
		len(c.Tops) != 1 || c.Tops[0] != (ChainMove{Name: "holder", From: "1.0.0", To: "1.1.0", Kind: "top"}) || c.Usage.Containers != 2 || c.Usage.Lookups == 0 {
		t.Errorf("chain = %+v", c)
	}
	if it.SourceCheck == nil || !it.SourceCheck.Passed || it.SourceCheck.Basis != "package_version_vuln_edges_positions" {
		t.Errorf("source check = %+v", it.SourceCheck)
	}
	if it.waitIntent == nil || !it.waitIntent.Clear {
		t.Errorf("wait intent = %+v", it.waitIntent)
	}
	if b, _ := json.Marshal(it); strings.Contains(string(b), "waitIntent") {
		t.Errorf("the wait intent is in the record: %s", b)
	}
}

func TestChainStageNotRegisteredChangesNothing(t *testing.T) {
	run := func(register bool) string {
		h := newChainHarness(t, []string{"pinned"}, nil)
		var r chainRunner
		if register {
			// A runner for a manager the item does not use.
			up, _ := NewLangUpdater(h.cfg)
			up.chainRunners = map[DependencyManager]chainRunner{ManagerUv: failRunner(nil)}
			plan := &Plan{LanguageItems: []LanguageItem{h.item}}
			up.Run(context.Background(), plan)
			b, _ := json.Marshal(plan.LanguageItems[0])
			return string(b) + fmt.Sprint(h.npm.lookups, h.work.calls)
		}
		it, _ := h.runChain(r, nil)
		b, _ := json.Marshal(it)
		return string(b) + fmt.Sprint(h.npm.lookups, h.work.calls)
	}
	if a, b := run(false), run(true); a != b {
		t.Errorf("results differ:\n%s\n%s", a, b)
	}
	h := newChainHarness(t, []string{"pinned"}, nil)
	it, _ := h.runChain(nil, nil)
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	if it.Update != nil && it.Update.Chain != nil || len(h.npm.lookups) != 0 || it.waitIntent != nil {
		t.Errorf("chain = %+v, lookups = %v, intent = %+v", it.Update, h.npm.lookups, it.waitIntent)
	}
}

func TestChainStageFailuresReturnToTheFirstResult(t *testing.T) {
	cases := []struct {
		name    string
		fail    *updateFailure
		outcome string
		reason  Reason // of the package held back
		sub     Reason
	}{
		{"rejected by a check", manualFailure(ReasonSourceIntroduced, "the update introduces findings"), ChainRejected, ReasonDependentsRejected, ReasonSourceIntroduced},
		{"still short of the fixed version", pkgFailure("pinned", ReasonTargetNotUpdated, "pinned is at 2.0.1"), ChainNotFixed, ReasonDependentsNotFixed, ""},
		{"the job failed", failedFailure(ReasonUpdateJobFailed, "the job program exited with code 1"), ChainFailed, ReasonTargetNotUpdated, ReasonUpdateJobFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newChainHarness(t, []string{"pinned"}, nil)
			it, _ := h.runChain(failRunner(c.fail), nil)
			// The first update left the lockfile as it was, which is what the item
			// is settled by.
			wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
			pin := packageOf(t, it, "pinned")
			if pin.Action != ActionManual || pin.Reason != c.reason {
				t.Errorf("pinned = %+v, want reason %s", pin, c.reason)
			}
			ch := it.Update.Chain
			if ch == nil || ch.Outcome != c.outcome || ch.Reason != c.sub {
				t.Errorf("chain = %+v", ch)
			}
			if len(it.Artifacts) != 0 {
				t.Errorf("artifacts = %+v", it.Artifacts)
			}
			if it.waitIntent == nil || !it.waitIntent.Clear {
				t.Errorf("wait intent = %+v", it.waitIntent)
			}
		})
	}
	t.Run("the packages held back are refused with a reason before the attempt", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		h.npm.dists["holder@1.0.0"] = NpmDist{Dependencies: map[string]string{"pinned": "2.0.0"}, PeerDependencies: map[string]string{"pinned": "*"}}
		called := false
		it, _ := h.runChain(func(context.Context, *updateRun, *chainScope) *updateFailure { called = true; return nil }, nil)
		if called {
			t.Fatal("the chain update ran")
		}
		wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
		if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonDependentsUnsupported {
			t.Errorf("pinned = %+v", pin)
		}
		if ch := it.Update.Chain; ch == nil || ch.Outcome != ChainNotTried || ch.Reason != ReasonDependentsUnsupported {
			t.Errorf("chain = %+v", ch)
		}
	})
	t.Run("the first update's reason stands when nothing is held back by a pinning requirement", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		h.npm.dists["holder@1.0.0"] = NpmDist{Dependencies: map[string]string{"pinned": "latest"}}
		called := false
		it, _ := h.runChain(func(context.Context, *updateRun, *chainScope) *updateFailure { called = true; return nil }, nil)
		wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
		if called || packageOf(t, it, "pinned").Reason != ReasonTargetNotUpdated || it.Update != nil && it.Update.Chain != nil {
			t.Errorf("called = %v, pinned = %+v, update = %+v", called, packageOf(t, it, "pinned"), it.Update)
		}
	})
}

func TestChainStageDefersWithoutAPartialPullRequest(t *testing.T) {
	// minimist reached its target and pinned did not: the first update's result
	// stands as a pull request candidate without pinned, until the chain update
	// is put off, when the item waits and no partial result is made.
	partial := func(n int) string { return chainLock("1.0.0", "2.0.0", "1.2.8") }
	cases := []struct {
		name string
		tune func(b *itemBudget)
		kind string
	}{
		{"containers", func(b *itemBudget) { b.maxContainers = 1 }, budgetContainerWait},
		{"lookups", func(b *itemBudget) { b.maxLookups = 2 }, budgetLookupWait},
		{"bytes", func(b *itemBudget) { b.maxBytes = 1 }, budgetBytesWait},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newChainHarness(t, []string{"minimist", "pinned"}, partial)
			called := false
			it, up := h.runChain(func(context.Context, *updateRun, *chainScope) *updateFailure { called = true; return nil }, func(up *LangUpdater, _ *LanguageItem) {
				up.itemBudget = func() *itemBudget { b := newItemBudget(); c.tune(b); return b }
			})
			if called {
				t.Fatal("the chain update ran with the item's budget used up")
			}
			wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
			if len(it.Artifacts) != 0 || it.waitIntent == nil || it.waitIntent.Kind != c.kind || it.waitIntent.Clear {
				t.Errorf("artifacts = %d, intent = %+v", len(it.Artifacts), it.waitIntent)
			}
			for _, p := range it.Packages {
				if p.Action != ActionUpdate || p.LeftOut || p.AdoptedVersion != "" {
					t.Errorf("%s was changed: %+v", p.Name, p)
				}
			}
			// If the wait cannot be recorded, the passing result is used, with the
			// package held back handed to a person.
			plan := &Plan{LanguageItems: []LanguageItem{it}}
			ApplyWaitSaveFailure(plan, errors.New("disk full"))
			got := plan.LanguageItems[0]
			wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
			pin, min := packageOf(t, got, "pinned"), packageOf(t, got, "minimist")
			if pin.Reason != ReasonDependentsLimit || !strings.Contains(pin.Detail, "the wait could not be recorded") || !strings.Contains(pin.Detail, "disk full") || !pin.LeftOut {
				t.Errorf("pinned = %+v", pin)
			}
			if min.Action != ActionUpdate || min.AdoptedVersion != "1.2.8" || got.waitIntent != nil || len(got.Artifacts) != 1 {
				t.Errorf("minimist = %+v, intent = %+v", min, got.waitIntent)
			}
			_ = up
		})
	}
	t.Run("an output that was not checked in full is not adopted", func(t *testing.T) {
		// The first update moves pinned to 2.0.1, still short of its target, so
		// it asks to be run again without it; the budget has no container for
		// that and the chain update, so nothing of it is adopted.
		h := newChainHarness(t, []string{"minimist", "pinned"}, func(n int) string { return chainLock("1.0.0", "2.0.1", "1.2.8") })
		called := false
		it, _ := h.runChain(func(context.Context, *updateRun, *chainScope) *updateFailure { called = true; return nil }, func(up *LangUpdater, _ *LanguageItem) {
			up.itemBudget = func() *itemBudget { b := newItemBudget(); b.maxContainers = 2; return b }
		})
		if called || h.work.calls != 1 {
			t.Fatalf("called = %v, containers = %d", called, h.work.calls)
		}
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		ApplyWaitSaveFailure(plan, errors.New("no store"))
		got := plan.LanguageItems[0]
		if got.Category == CategoryPRCandidate || len(got.Artifacts) != 0 {
			t.Fatalf("an unchecked result was adopted: %s %s %+v", got.Category, got.Reason, got.Artifacts)
		}
		wantCategory(t, got, CategoryManual, ReasonDependentsLimit)
	})
}

func TestChainStageStopsAfterThreeStopsForTheSameKind(t *testing.T) {
	partial := func(n int) string { return chainLock("1.0.0", "2.0.0", "1.2.8") }
	tune := func(prior *LangWaitRecord) func(*LangUpdater, *LanguageItem) {
		return func(up *LangUpdater, it *LanguageItem) {
			it.priorWait = prior
			up.itemBudget = func() *itemBudget { b := newItemBudget(); b.maxContainers = 1; return b }
		}
	}
	t.Run("the second stop is a wait", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, partial)
		it, _ := h.runChain(failRunner(nil), tune(&LangWaitRecord{Kind: budgetContainerWait, Count: 1}))
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
	})
	t.Run("the third is a stop, and only a checked result is adopted", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, partial)
		it, _ := h.runChain(failRunner(nil), tune(&LangWaitRecord{Kind: budgetContainerWait, Count: 2}))
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if w := it.waitIntent; w == nil || !w.Stop || w.StopReason != ReasonChainItemBudget {
			t.Fatalf("intent = %+v", w)
		}
		pin := packageOf(t, it, "pinned")
		if pin.Reason != ReasonDependentsLimit || !pin.LeftOut || packageOf(t, it, "minimist").AdoptedVersion != "1.2.8" {
			t.Errorf("pinned = %+v", pin)
		}
		if ch := it.Update.Chain; ch == nil || ch.Outcome != ChainNotTried || ch.Reason != ReasonChainItemBudget {
			t.Errorf("chain = %+v", ch)
		}
	})
	t.Run("another kind starts again", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, partial)
		it, _ := h.runChain(failRunner(nil), tune(&LangWaitRecord{Kind: budgetLookupWait, Count: 2}))
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		if it.waitIntent.Stop {
			t.Error("a stop of another kind counted")
		}
	})
	t.Run("a stopped item goes the first update's way", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		called := false
		it, _ := h.runChain(func(context.Context, *updateRun, *chainScope) *updateFailure { called = true; return nil }, func(_ *LangUpdater, it *LanguageItem) {
			it.chainStopped = &LangWaitRecord{Kind: chainStoppedKind, StopReason: ReasonChainItemBudget}
		})
		if called {
			t.Fatal("the chain update ran for a stopped item")
		}
		wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
		if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonDependentsLimit {
			t.Errorf("pinned = %+v", pin)
		}
	})
	t.Run("a stop for a release that is too new is rejected", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		it, _ := h.runChain(failRunner(nil), func(_ *LangUpdater, it *LanguageItem) {
			it.chainStopped = &LangWaitRecord{Kind: chainStoppedKind, StopReason: ReasonReleaseTooNew}
		})
		if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonDependentsRejected {
			t.Errorf("pinned = %+v", pin)
		}
	})
}

func TestChainStageWaitsForAReleaseThatIsTooNew(t *testing.T) {
	retry := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	h := newChainHarness(t, []string{"pinned"}, nil)
	f := &updateFailure{category: CategoryDeferred, reason: ReasonReleaseTooNew, detail: "holder 1.1.0 was published 10 hours ago", wait: &langWaitIntent{Kind: releaseAgeWait, RetryAfter: retry}}
	it, _ := h.runChain(failRunner(f), nil)
	wantCategory(t, it, CategoryDeferred, ReasonReleaseTooNew)
	if it.RetryAfter == nil || !it.RetryAfter.Equal(retry) || it.waitIntent == nil || it.waitIntent.Kind != releaseAgeWait || !it.waitIntent.RetryAfter.Equal(retry) {
		t.Errorf("retry = %v, intent = %+v", it.RetryAfter, it.waitIntent)
	}
	if len(it.Artifacts) != 0 {
		t.Error("a result was made while the item waits")
	}
	if b, _ := json.Marshal(it); !strings.Contains(string(b), `"retry_after":"2026-10-20T00:00:00Z"`) {
		t.Errorf("record = %s", b)
	}
	// Three in a row stop the chain update, and the packages are rejected for it.
	h = newChainHarness(t, []string{"pinned"}, nil)
	it, _ = h.runChain(failRunner(f), func(_ *LangUpdater, it *LanguageItem) {
		it.priorWait = &LangWaitRecord{Kind: releaseAgeWait, Count: 2}
	})
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonDependentsRejected || it.waitIntent == nil || !it.waitIntent.Stop || it.waitIntent.StopReason != ReasonReleaseTooNew {
		t.Errorf("pinned = %+v, intent = %+v", pin, it.waitIntent)
	}
}

func TestChainStageWorkDeadline(t *testing.T) {
	t.Run("the time the item was given ends the attempt as a wait", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		sawCancel := false
		it, _ := h.runChain(func(ctx context.Context, r *updateRun, _ *chainScope) *updateFailure {
			<-ctx.Done()
			sawCancel = true
			// The registry, the scans and the container are given the deadline.
			if _, err := r.npmRelease(ctx, "pinned", "9.9.9"); err == nil {
				t.Error("a lookup went on after the deadline")
			}
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}, func(up *LangUpdater, _ *LanguageItem) {
			up.itemBudget = func() *itemBudget { b := newItemBudget(); b.workLimit = 30 * time.Millisecond; return b }
			up.cfg.Npm = ctxNpm{up.cfg.Npm}
		})
		if !sawCancel {
			t.Fatal("the work context did not end")
		}
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		if it.waitIntent == nil || it.waitIntent.Kind != budgetTimeWait {
			t.Errorf("intent = %+v", it.waitIntent)
		}
	})
	t.Run("the cycle's own end is not a wait", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		up, _ := NewLangUpdater(h.cfg)
		ctx, cancel := context.WithCancel(context.Background())
		up.chainRunners = map[DependencyManager]chainRunner{ManagerPnpm: func(c context.Context, r *updateRun, _ *chainScope) *updateFailure {
			cancel()
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: c.Err().Error()}
		}}
		plan := &Plan{LanguageItems: []LanguageItem{h.item}}
		up.Run(ctx, plan)
		it := plan.LanguageItems[0]
		wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
		if it.waitIntent != nil {
			t.Errorf("intent = %+v", it.waitIntent)
		}
	})
	t.Run("the checks and the scans observe it", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, func(n int) string {
			if n == 0 {
				return ""
			}
			return chainLock("1.1.0", "2.0.2", "1.2.5")
		})
		scans := 0
		h.cfg.Scanner = ctxScanner{inner: h.fs, scans: &scans}
		it, _ := h.runChain(func(ctx context.Context, r *updateRun, scope *chainScope) *updateFailure {
			<-ctx.Done()
			return r.verifyAndScan(ctx, []byte(chainLock("1.1.0", "2.0.2", "1.2.5")))
		}, func(up *LangUpdater, _ *LanguageItem) {
			up.itemBudget = func() *itemBudget { b := newItemBudget(); b.workLimit = 30 * time.Millisecond; return b }
		})
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		if it.waitIntent == nil || it.waitIntent.Kind != budgetTimeWait {
			t.Errorf("intent = %+v", it.waitIntent)
		}
		if scans != 0 {
			t.Errorf("scans = %d: the first update left the lockfile as it was and the chain's checks ended with the deadline", scans)
		}
		if len(it.Artifacts) != 0 {
			t.Error("an output that was not checked was adopted")
		}
	})
}

// ctxNpm and ctxScanner stand for clients that stop when their context does.
type ctxNpm struct{ inner NpmRegistry }

func (c ctxNpm) VersionDist(ctx context.Context, name, version string) (NpmDist, error) {
	if err := ctx.Err(); err != nil {
		return NpmDist{}, err
	}
	return c.inner.VersionDist(ctx, name, version)
}

type ctxScanner struct {
	inner FSScanner
	scans *int
}

func (c ctxScanner) ScanFS(ctx context.Context, files map[string][]byte, p scanner.ScanConditions) (scanner.FSScan, error) {
	if err := ctx.Err(); err != nil {
		return scanner.FSScan{}, err
	}
	*c.scans++
	return c.inner.ScanFS(ctx, files, p)
}

func TestItemBudget(t *testing.T) {
	t.Run("reserve sets amounts aside and refuses what does not fit", func(t *testing.T) {
		b := newItemBudget()
		if !b.reserve(2, 100, 1<<20) || !b.reserve(2, 100, 1<<20) {
			t.Fatal("reservations that fit were refused")
		}
		if b.reserve(1, 0, 0) {
			t.Error("a fifth container was reserved")
		}
		if b.containers != 0 || b.reservedContainers != 4 {
			t.Errorf("a refused reservation changed the budget: %+v", b)
		}
		if b.reserve(0, 185, 0) || b.reserve(0, 0, maxItemBytes) {
			t.Error("more lookups or bytes than the limits were reserved")
		}
		if got := b.which(1, 0, 0); got != budgetContainerWait {
			t.Errorf("which = %q", got)
		}
	})
	t.Run("spending takes from what was set aside, up to the limit", func(t *testing.T) {
		b := newItemBudget()
		b.enforced = true
		b.reserve(1, 1, 10)
		for i := 0; i < maxItemContainers; i++ {
			if err := b.spendContainer(); err != nil {
				t.Fatalf("container %d: %v", i+1, err)
			}
		}
		if err := b.spendContainer(); isItemBudget(err) != budgetContainerWait {
			t.Errorf("the fifth container: %v", err)
		}
		if b.reservedContainers != 0 {
			t.Errorf("reserved = %d", b.reservedContainers)
		}
		for i := 0; i < maxItemLookups; i++ {
			if err := b.spendLookup(); err != nil {
				t.Fatalf("lookup %d: %v", i+1, err)
			}
		}
		if err := b.spendLookup(); isItemBudget(err) != budgetLookupWait {
			t.Errorf("lookup %d: %v", maxItemLookups+1, err)
		}
		if err := b.addBytes(maxItemBytes + 1); isItemBudget(err) != budgetBytesWait {
			t.Errorf("bytes: %v", err)
		}
	})
	t.Run("the working time is two container timeouts and two minutes, capped by the parent", func(t *testing.T) {
		b := newItemBudget()
		now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
		b.now = func() time.Time { return now }
		ctx, cancel := b.workCtx(context.Background(), 6*time.Minute)
		defer cancel()
		if d, _ := ctx.Deadline(); !d.Equal(now.Add(14 * time.Minute)) {
			t.Errorf("deadline = %v", d)
		}
		parent, cancelParent := context.WithDeadline(context.Background(), now.Add(5*time.Minute))
		defer cancelParent()
		ctx2, cancel2 := newItemBudget().workCtx(parent, 6*time.Minute)
		defer cancel2()
		if d, _ := ctx2.Deadline(); d.After(now.Add(5*time.Minute)) && time.Until(d) > 6*time.Minute {
			t.Errorf("deadline = %v, past the parent's", d)
		}
	})
	t.Run("a container gets the job timeout or what is left", func(t *testing.T) {
		if got := containerTimeout(context.Background(), 6*time.Minute); got != 6*time.Minute {
			t.Errorf("no deadline: %v", got)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if got := containerTimeout(ctx, 6*time.Minute); got > time.Minute || got < 50*time.Second {
			t.Errorf("a minute left: %v", got)
		}
		if got := containerTimeout(ctx, 30*time.Second); got != 30*time.Second {
			t.Errorf("more left than the timeout: %v", got)
		}
	})
	t.Run("no container is started with too little time left", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, nil)
		it, _ := h.runChain(jobRunner(), func(up *LangUpdater, _ *LanguageItem) {
			up.itemBudget = func() *itemBudget { b := newItemBudget(); b.workLimit = 5 * time.Second; return b }
		})
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		if it.waitIntent == nil || it.waitIntent.Kind != budgetTimeWait || h.work.calls != 1 {
			t.Errorf("intent = %+v, containers = %d", it.waitIntent, h.work.calls)
		}
	})
	t.Run("a chain container's timeout is the time left", func(t *testing.T) {
		h := newChainHarness(t, []string{"pinned"}, func(n int) string {
			if n == 0 {
				return ""
			}
			return chainLock("1.1.0", "2.0.2", "1.2.5")
		})
		h.cfg.JobTimeout = 10 * time.Minute
		it, _ := h.runChain(jobRunner(), func(up *LangUpdater, _ *LanguageItem) {
			up.itemBudget = func() *itemBudget { b := newItemBudget(); b.workLimit = 2 * time.Minute; return b }
		})
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		first, chain := h.work.jobs[0].DeadlineSeconds, h.work.jobs[1].DeadlineSeconds
		if first != 600-30 || chain >= first || chain > 120 {
			t.Errorf("deadlines: first %d, chain %d", first, chain)
		}
	})
}
