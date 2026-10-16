package remediation

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// genImp is a direct dependency of a generated pnpm project, genPkg a package
// of it with the versions of the packages it requires.
type genImp struct{ name, spec, ver string }
type genPkg struct {
	name, ver string
	deps      map[string]string
}

func genPnpmLock(imps []genImp, pkgs []genPkg) string {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n")
	sort.Slice(imps, func(i, j int) bool { return imps[i].name < imps[j].name })
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].name < pkgs[j].name })
	for _, i := range imps {
		fmt.Fprintf(&b, "      %s:\n        specifier: %s\n        version: %s\n", i.name, i.spec, i.ver)
	}
	b.WriteString("\npackages:\n\n")
	for _, p := range pkgs {
		fmt.Fprintf(&b, "  %s@%s:\n    resolution: {integrity: %s}\n\n", p.name, p.ver, chainIntegrity(p.name, p.ver))
	}
	b.WriteString("snapshots:\n\n")
	for _, p := range pkgs {
		if len(p.deps) == 0 {
			fmt.Fprintf(&b, "  %s@%s: {}\n\n", p.name, p.ver)
			continue
		}
		fmt.Fprintf(&b, "  %s@%s:\n    dependencies:\n", p.name, p.ver)
		var names []string
		for n := range p.deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "      %s: %s\n", n, p.deps[n])
		}
		b.WriteString("\n")
	}
	return b.String()
}

var genEntryRE = regexp.MustCompile(`(?m)^  ([a-z0-9._-]+)@([0-9][0-9A-Za-z.\-]*):`)

// newGenHarness is a harness for a generated pnpm project. findings maps
// "name@version" to the vulnerability the scans report for it. The work
// container leaves the lockfile as it is unless lockFor(n) gives one.
func newGenHarness(t *testing.T, manifest, lock string, groups []*findingGroup, dists map[string]NpmDist, findings map[string]string, lockFor func(n int) string) *harness {
	t.Helper()
	files := map[string]string{"package.json": manifest, "pnpm-lock.yaml": lock}
	h := &harness{t: t, fx: fixtureFor("pnpm"), files: files}
	h.item = itemFor(t, ManagerPnpm, files, groups...)
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the project is not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	h.npm = &fakeNpm{dists: dists}
	h.pypi = &fakePyPI{auto: true}
	h.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		out := string(src["pnpm-lock.yaml"])
		if lockFor != nil {
			if l := lockFor(n); l != "" {
				out = l
			}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": []byte(out)}}}
	}}
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) {
		var pkgs [][2]string
		var vulns [][3]string
		seen := map[string]bool{}
		for _, m := range genEntryRE.FindAllStringSubmatch(string(in["pnpm-lock.yaml"]), -1) {
			key := m[1] + "@" + m[2]
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, [2]string{m[1], m[2]})
			if id := findings[key]; id != "" {
				vulns = append(vulns, [3]string{m[1], m[2], id})
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

func genDist(name, ver string, deps map[string]string) NpmDist {
	return NpmDist{Tarball: "https://registry.npmjs.org/" + name + "/-/" + name + "-" + ver + ".tgz", Integrity: chainIntegrity(name, ver), Dependencies: deps}
}

func genGroup(name, ver, vuln, fixed string) *findingGroup {
	return group(typeNodePkg, name, ver, FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/" + name + "/package.json"},
		CVERef{VulnID: vuln, FixedVers: []string{fixed}})
}

func TestChainSuccessKeepsThePackagesItDidNotAttempt(t *testing.T) {
	// minimist reaches its target in the first update, pinned is held by holder
	// and loose by a requirement that cannot be judged. The chain update takes
	// minimist and pinned; loose stays manual with the reason the first update
	// gave.
	manifest := `{"name":"fixture-mixed","version":"1.0.0","private":true,"dependencies":{"holder":"^1.0.0","mkdirp":"0.5.5","tagger":"1.0.0"}}`
	lock := func(holder, pinned, min string) string {
		return genPnpmLock(
			[]genImp{{"holder", "^1.0.0", holder}, {"mkdirp", "0.5.5", "0.5.5"}, {"tagger", "1.0.0", "1.0.0"}},
			[]genPkg{
				{"holder", holder, map[string]string{"pinned": pinned}}, {"pinned", pinned, nil},
				{"mkdirp", "0.5.5", map[string]string{"minimist": min}}, {"minimist", min, nil},
				{"tagger", "1.0.0", map[string]string{"loose": "1.0.0"}}, {"loose", "1.0.0", nil},
			})
	}
	dists := map[string]NpmDist{
		"minimist@1.2.8": minimist128,
		"mkdirp@0.5.5":   genDist("mkdirp", "0.5.5", map[string]string{"minimist": "^1.2.5"}),
		"holder@1.0.0":   genDist("holder", "1.0.0", map[string]string{"pinned": "2.0.0"}),
		"holder@1.1.0":   genDist("holder", "1.1.0", map[string]string{"pinned": "^2.0.2"}),
		"pinned@2.0.2":   genDist("pinned", "2.0.2", nil),
		"tagger@1.0.0":   genDist("tagger", "1.0.0", map[string]string{"loose": "latest"}),
	}
	findings := map[string]string{"minimist@1.2.5": "CVE-A", "pinned@2.0.0": "CVE-B", "loose@1.0.0": "CVE-C"}
	groups := []*findingGroup{genGroup("minimist", "1.2.5", "CVE-A", "1.2.8"), genGroup("pinned", "2.0.0", "CVE-B", "2.0.2"), genGroup("loose", "1.0.0", "CVE-C", "1.0.2")}
	h := newGenHarness(t, manifest, lock("1.0.0", "2.0.0", "1.2.5"), groups, dists, findings, func(n int) string {
		if n == 0 {
			return lock("1.0.0", "2.0.0", "1.2.8")
		}
		return lock("1.1.0", "2.0.2", "1.2.8")
	})
	it, _ := h.runChain(jobRunner(), nil)
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 2 {
		t.Fatalf("containers = %d", h.work.calls)
	}
	min, pin, loose := packageOf(t, it, "minimist"), packageOf(t, it, "pinned"), packageOf(t, it, "loose")
	if min.Action != ActionUpdate || min.AdoptedVersion != "1.2.8" {
		t.Errorf("minimist = %+v", min)
	}
	if pin.Action != ActionUpdate || pin.AdoptedVersion != "2.0.2" || strings.Join(pin.Through, ",") != "holder" {
		t.Errorf("pinned = %+v", pin)
	}
	if loose.Action != ActionManual || !loose.LeftOut || loose.AdoptedVersion != "" || loose.Reason != ReasonTargetNotUpdated || len(loose.Through) != 0 {
		t.Errorf("loose = %+v: it was not attempted and keeps the first update's reason", loose)
	}
	if string(it.Artifacts[0].Content) != lock("1.1.0", "2.0.2", "1.2.8") {
		t.Error("the artifact is not the chain's lockfile")
	}
}

func TestChainCarriesTheFirstUpdatesManifestEdits(t *testing.T) {
	// direct is declared at exactly 1.0.0 and its fix needs the declaration
	// edited; pinned is held by holder. The first update edits the declaration
	// and takes direct; the chain update does the same and takes pinned too.
	manifest := `{"name":"fixture-edit","version":"1.0.0","private":true,"dependencies":{"direct":"1.0.0","holder":"^1.0.0"}}`
	lock := func(directSpec, direct, holder, pinned string) string {
		return genPnpmLock(
			[]genImp{{"direct", directSpec, direct}, {"holder", "^1.0.0", holder}},
			[]genPkg{{"direct", direct, nil}, {"holder", holder, map[string]string{"pinned": pinned}}, {"pinned", pinned, nil}})
	}
	dists := map[string]NpmDist{
		"direct@1.0.5": genDist("direct", "1.0.5", nil),
		"holder@1.0.0": genDist("holder", "1.0.0", map[string]string{"pinned": "2.0.0"}),
		"holder@1.1.0": genDist("holder", "1.1.0", map[string]string{"pinned": "^2.0.2"}),
		"pinned@2.0.2": genDist("pinned", "2.0.2", nil),
	}
	findings := map[string]string{"direct@1.0.0": "CVE-D", "pinned@2.0.0": "CVE-B"}
	groups := []*findingGroup{genGroup("direct", "1.0.0", "CVE-D", "1.0.5"), genGroup("pinned", "2.0.0", "CVE-B", "2.0.2")}
	// Jobs: the original input checked (0), the first update (1), the chain (2).
	h := newGenHarness(t, manifest, lock("1.0.0", "1.0.0", "1.0.0", "2.0.0"), groups, dists, findings, func(n int) string {
		switch n {
		case 1:
			return lock("1.0.5", "1.0.5", "1.0.0", "2.0.0")
		case 2:
			return lock("1.0.5", "1.0.5", "1.1.0", "2.0.2")
		}
		return ""
	})
	it, _ := h.runChain(jobRunner(), nil)
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 3 {
		t.Fatalf("containers = %d, want the original's check, the first update and the chain", h.work.calls)
	}
	if got := packageOf(t, it, "direct"); got.AdoptedVersion != "1.0.5" {
		t.Errorf("direct = %+v", got)
	}
	if got := packageOf(t, it, "pinned"); got.AdoptedVersion != "2.0.2" || strings.Join(got.Through, ",") != "holder" {
		t.Errorf("pinned = %+v", got)
	}
	if len(it.Update.ManifestEdits) != 1 || it.Update.ManifestEdits[0].Name != "direct" || it.Update.ManifestEdits[0].To != "1.0.5" {
		t.Fatalf("manifest edits = %+v", it.Update.ManifestEdits)
	}
	if len(it.Artifacts) != 2 || it.Artifacts[1].Path != "package.json" || !strings.Contains(string(it.Artifacts[1].Content), `"direct":"1.0.5"`) {
		t.Errorf("artifacts = %+v", it.Artifacts)
	}
}

func TestChainRerunAfterTheChainUsesTheItemsTime(t *testing.T) {
	// The first update moves pinned to 2.0.1, still short of 2.0.2, so its result
	// needs a second run without it. Whatever the chain update does, the second
	// run is made inside the time the item was given: when that is over, the item
	// waits and nothing of the first output is adopted.
	short := func(up *LangUpdater, _ *LanguageItem) {
		up.itemBudget = func() *itemBudget { b := newItemBudget(); b.workLimit = 100 * time.Millisecond; return b }
	}
	settled := func(t *testing.T, h *harness, it LanguageItem) {
		t.Helper()
		if h.work.calls != 1 {
			t.Fatalf("containers = %d: the second run went on after the item's time", h.work.calls)
		}
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		if it.waitIntent == nil || it.waitIntent.Kind != budgetTimeWait || len(it.Artifacts) != 0 {
			t.Errorf("intent = %+v, artifacts = %d", it.waitIntent, len(it.Artifacts))
		}
	}
	first := func(n int) string { return chainLock("1.0.0", "2.0.1", "1.2.8") }
	t.Run("the chain update fails when the time is over", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, first)
		it, _ := h.runChain(func(ctx context.Context, r *updateRun, _ *chainScope) *updateFailure {
			<-ctx.Done()
			return manualFailure(ReasonSourceIntroduced, "x")
		}, short)
		settled(t, h, it)
	})
	t.Run("the chain update fails and the second run has too little time", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, first)
		it, _ := h.runChain(failRunner(manualFailure(ReasonSourceIntroduced, "x")), short)
		settled(t, h, it)
	})
	t.Run("with time left the second run is made and adopted", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, func(n int) string {
			if n == 0 {
				return chainLock("1.0.0", "2.0.1", "1.2.8")
			}
			return chainLock("1.0.0", "2.0.0", "1.2.8")
		})
		it, _ := h.runChain(failRunner(manualFailure(ReasonSourceIntroduced, "x")), nil)
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if h.work.calls != 2 || packageOf(t, it, "pinned").Reason != ReasonDependentsRejected {
			t.Errorf("containers = %d, pinned = %+v", h.work.calls, packageOf(t, it, "pinned"))
		}
	})
}

// passes runs the item through n passes of the stage against one record file
// and returns the item of each.
func passes(t *testing.T, h *harness, up *LangUpdater, store PRStore, n int) []passResult {
	t.Helper()
	var out []passResult
	for i := 1; i <= n; i++ {
		item := h.item
		item.Packages = append([]LanguagePackage(nil), h.item.Packages...)
		plan := &Plan{LanguageItems: []LanguageItem{item}}
		now := waitsNow.Add(time.Duration(i) * time.Hour)
		order, _ := BindProposedLanguageUpdatesAt(plan, store, now)
		RunLanguageUpdatesInOrder(context.Background(), up.Run, plan, order)
		if err := RecordLanguageWaits(context.Background(), store, plan, now); err != nil {
			t.Fatal(err)
		}
		out = append(out, passResult{plan.LanguageItems[0], loadWaits(t, store)})
	}
	return out
}

// passResult is the item a pass made and the waits on record after it.
type passResult struct {
	item  LanguageItem
	waits []LangWaitRecord
}

func TestOverrunsDuringWorkAreCountedAcrossPasses(t *testing.T) {
	t.Run("bytes received by the first update leave nothing for the chain update", func(t *testing.T) {
		h := newChainHarness(t, []string{"minimist", "pinned"}, func(n int) string { return chainLock("1.0.0", "2.0.0", "1.2.8") })
		for _, k := range []string{"minimist@1.2.8", "mkdirp@0.5.5"} {
			d := h.npm.dists[k]
			d.BodyBytes = 60 << 20
			h.npm.dists[k] = d
		}
		up, _ := NewLangUpdater(h.cfg)
		up.chainRunners = map[DependencyManager]chainRunner{ManagerPnpm: failRunner(nil)}
		store := waitsStore(t)
		got := passes(t, h, up, store, 4)
		for i := 0; i < 2; i++ {
			wantCategory(t, got[i].item, CategoryDeferred, ReasonChainItemBudget)
			if w := got[i].waits; len(w) != 1 || w[0].Kind != budgetBytesWait || w[0].Count != i+1 {
				t.Fatalf("pass %d: waits = %+v", i+1, w)
			}
		}
		// The third pass stops. The first update's own result passed every check,
		// so it is adopted with the held back package handed to a person; the stop
		// is on record and the pass after it does the same.
		for i := 2; i < 4; i++ {
			wantCategory(t, got[i].item, CategoryPRCandidate, ReasonUpdateVerified)
			if pin := packageOf(t, got[i].item, "pinned"); pin.Reason != ReasonDependentsLimit || !pin.LeftOut {
				t.Errorf("pass %d: pinned = %+v", i+1, pin)
			}
			if w := got[i].waits; len(w) != 1 || w[0].Kind != chainStoppedKind {
				t.Fatalf("pass %d: waits = %+v", i+1, w)
			}
		}
	})
	t.Run("containers used by the chain update", func(t *testing.T) {
		// One container is set aside for the chain update; its runner uses two.
		h := newChainHarness(t, []string{"pinned"}, nil)
		two := func(ctx context.Context, r *updateRun, _ *chainScope) *updateFailure {
			for i := 0; i < 2; i++ {
				steps := []worker.Step{{ID: stepUpdate, Op: worker.OpPnpmRelock}}
				if _, f := r.execReplacing(ctx, worker.ManagerPnpm, r.pnpmInputs(r.manifest, r.src.lock), map[string][]byte{"pnpm-lock.yaml": r.src.lock}, steps, "chain"); f != nil {
					return f
				}
			}
			return nil
		}
		up, _ := NewLangUpdater(h.cfg)
		up.chainRunners = map[DependencyManager]chainRunner{ManagerPnpm: two}
		up.itemBudget = func() *itemBudget { b := newItemBudget(); b.maxContainers = 2; return b }
		store := waitsStore(t)
		got := passes(t, h, up, store, 3)
		wantCategory(t, got[0].item, CategoryDeferred, ReasonChainItemBudget)
		if w := got[0].waits; len(w) != 1 || w[0].Kind != budgetContainerWait {
			t.Fatalf("waits = %+v", w)
		}
		wantCategory(t, got[1].item, CategoryDeferred, ReasonChainItemBudget)
		wantCategory(t, got[2].item, CategoryManual, ReasonTargetNotUpdated)
		if pin := packageOf(t, got[2].item, "pinned"); pin.Reason != ReasonDependentsLimit {
			t.Errorf("pinned = %+v", pin)
		}
	})
	t.Run("the second run of a manifest-edited update uses the original's check", func(t *testing.T) {
		manifest := `{"name":"fixture-edit","version":"1.0.0","private":true,"dependencies":{"direct":"1.0.0","holder":"^1.0.0"}}`
		lock := func(spec, direct, pinned string) string {
			return genPnpmLock([]genImp{{"direct", spec, direct}, {"holder", "^1.0.0", "1.0.0"}},
				[]genPkg{{"direct", direct, nil}, {"holder", "1.0.0", map[string]string{"pinned": pinned}}, {"pinned", pinned, nil}})
		}
		dists := map[string]NpmDist{
			"direct@1.0.5": genDist("direct", "1.0.5", nil),
			"holder@1.0.0": genDist("holder", "1.0.0", map[string]string{"pinned": "2.0.0"}),
		}
		groups := []*findingGroup{genGroup("direct", "1.0.0", "CVE-D", "1.0.5"), genGroup("pinned", "2.0.0", "CVE-B", "2.0.2")}
		// The first update moves pinned to 2.0.1, which is short of 2.0.2: it
		// asks to be run again without it. The chain update is refused.
		h := newGenHarness(t, manifest, lock("1.0.0", "1.0.0", "2.0.0"), groups, dists, map[string]string{"direct@1.0.0": "CVE-D", "pinned@2.0.0": "CVE-B"}, func(n int) string {
			if n == 1 {
				return lock("1.0.5", "1.0.5", "2.0.1")
			}
			if n == 2 {
				return lock("1.0.5", "1.0.5", "2.0.0")
			}
			return ""
		})
		it, _ := h.runChain(failRunner(manualFailure(ReasonSourceIntroduced, "x")), nil)
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if h.work.calls != 3 {
			t.Errorf("containers = %d: the check of the original input was made again", h.work.calls)
		}
	})
}

func TestLookupLimitsOfTheFirstUpdateAndTheChain(t *testing.T) {
	next := 0
	lookups := func(r *updateRun, n int) error {
		for i := 0; i < n; i++ {
			next++
			if _, err := r.npmRelease(context.Background(), fmt.Sprintf("p%04d", next), "1.0.0"); err != nil && err != ErrReleaseNotFound {
				return err
			}
		}
		return nil
	}
	fresh := func(chain bool) *updateRun {
		r := &updateRun{u: &LangUpdater{cfg: LangUpdateConfig{Npm: &fakeNpm{}}}, shared: newItemShared()}
		r.shared.budget.enforced = chain
		if chain {
			r.chain = &chainScope{}
		}
		return r
	}
	t.Run("the first update stops at 257 with a deferral that is not a wait", func(t *testing.T) {
		r := fresh(false)
		if err := lookups(r, maxRegistryChecks); err != nil {
			t.Fatalf("256 lookups: %v", err)
		}
		_, err := r.npmRelease(context.Background(), "extra", "1.0.0")
		if err != errRegistryBudget {
			t.Fatalf("257th: %v", err)
		}
		if f := lookupFailure(context.Background(), err, "x"); f.reason != ReasonRegistryCheckLimit || f.wait != nil {
			t.Errorf("failure = %+v", f)
		}
	})
	t.Run("the chain goes on past 256 up to the item's 384 and then waits", func(t *testing.T) {
		r := fresh(true)
		if err := lookups(r, maxRegistryChecks+1); err != nil {
			t.Fatalf("257 lookups: %v", err)
		}
		if err := lookups(r, maxItemLookups-maxRegistryChecks-1); err != nil {
			t.Fatalf("up to 384 lookups: %v", err)
		}
		_, err := r.npmRelease(context.Background(), "extra", "1.0.0")
		if isItemBudget(err) != budgetLookupWait {
			t.Fatalf("385th: %v", err)
		}
		if f := lookupFailure(context.Background(), err, "x"); f.reason != ReasonChainItemBudget || f.wait == nil || f.wait.Kind != budgetLookupWait {
			t.Errorf("failure = %+v", f)
		}
	})
	t.Run("the chain has what the first update left of the item's 384", func(t *testing.T) {
		first := fresh(false)
		if err := lookups(first, 200); err != nil {
			t.Fatal(err)
		}
		first.shared.budget.enforced = true
		chain := &updateRun{u: first.u, shared: first.shared, chain: &chainScope{}}
		if err := lookups(chain, 184); err != nil {
			t.Fatalf("184 more: %v", err)
		}
		if _, err := chain.npmRelease(context.Background(), "extra", "1.0.0"); isItemBudget(err) != budgetLookupWait {
			t.Fatalf("385th: %v", err)
		}
	})
}

func TestRunsThatAreNotChainRunsKeepTheirOwnLookupLimit(t *testing.T) {
	// The search for where a chain would start fills the item's shared cache;
	// the second run of the update that follows when no chain is needed counts
	// every document it uses toward its own 256, as it does without the chain
	// update.
	dists := map[string]NpmDist{}
	const n = maxRegistryChecks + 1
	for i := 0; i < n; i++ {
		dists[fmt.Sprintf("p%03d@1.0.0", i)] = NpmDist{}
	}
	look := func(r *updateRun) (ok int, err error) {
		for i := 0; i < n; i++ {
			if _, err = r.npmRelease(context.Background(), fmt.Sprintf("p%03d", i), "1.0.0"); err != nil {
				return ok, err
			}
			ok++
		}
		return ok, nil
	}
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: &fakeNpm{dists: dists}}}
	shared := newItemShared()
	search := &updateRun{u: u, shared: shared, chain: &chainScope{}}
	if ok, err := look(search); err != nil || ok != n {
		t.Fatalf("scope search: %d, %v", ok, err)
	}
	withShared, errShared := look(&updateRun{u: u, shared: shared, attempt: 1, noPartial: true})
	alone, errAlone := look(&updateRun{u: u, attempt: 1, noPartial: true})
	if errShared != errRegistryBudget || errAlone != errRegistryBudget || withShared != maxRegistryChecks || alone != maxRegistryChecks {
		t.Errorf("with the shared cache: %d, %v; without: %d, %v", withShared, errShared, alone, errAlone)
	}
	// A chain run does read it.
	if ok, err := look(&updateRun{u: u, shared: shared, chain: &chainScope{}}); err != nil || ok != n {
		t.Errorf("chain run: %d, %v", ok, err)
	}
}
