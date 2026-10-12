package remediation

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The project of these tests is a pnpm project of two direct dependencies: app,
// the package being updated, and browsers, which is not. Both require shared.
// When app is updated its new version is resolved with a new version of
// shared, and pnpm lets browsers, which requires the same package, follow.

type followSpec struct {
	app, appShared, browsersShared string
	// shared lists the versions of shared the file has.
	shared []string
	// otherShared, when set, is a third direct dependency that requires the
	// version of shared it names.
	otherShared string
	// browsersVer is the version of browsers the file has.
	browsersVer string
	// sharedIntegrity, when set, is the integrity the file records for shared
	// 1.1.0.
	sharedIntegrity string
	// appContext is a peer context the importer writes after the version of app.
	appContext string
}

func followLock(f followSpec) string {
	if f.browsersVer == "" {
		f.browsersVer = "1.0.0"
	}
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n")
	fmt.Fprintf(&b, "      app:\n        specifier: ^1.0.0\n        version: %s\n", f.app+f.appContext)
	fmt.Fprintf(&b, "      browsers:\n        specifier: 1.0.0\n        version: %s\n", f.browsersVer)
	if f.otherShared != "" {
		b.WriteString("      other:\n        specifier: 1.0.0\n        version: 1.0.0\n")
	}
	b.WriteString("\npackages:\n\n")
	pkg := func(name, ver string) {
		integrity := partialIntegrity(name, ver)
		if name == "shared" && ver == "1.1.0" && f.sharedIntegrity != "" {
			integrity = f.sharedIntegrity
		}
		fmt.Fprintf(&b, "  %s@%s:\n    resolution: {integrity: %s}\n\n", name, ver, integrity)
	}
	pkg("app", f.app)
	pkg("browsers", f.browsersVer)
	if f.otherShared != "" {
		pkg("other", "1.0.0")
	}
	for _, v := range f.shared {
		pkg("shared", v)
	}
	b.WriteString("snapshots:\n\n")
	fmt.Fprintf(&b, "  app@%s:\n    dependencies:\n      shared: %s\n\n", f.app, f.appShared)
	fmt.Fprintf(&b, "  browsers@%s:\n    dependencies:\n      shared: %s\n\n", f.browsersVer, f.browsersShared)
	if f.otherShared != "" {
		fmt.Fprintf(&b, "  other@1.0.0:\n    dependencies:\n      shared: %s\n\n", f.otherShared)
	}
	for _, v := range f.shared {
		fmt.Fprintf(&b, "  shared@%s: {}\n\n", v)
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

var followPackages = regexp.MustCompile(`(?m)^  ([a-z0-9-]+)@([0-9.]+):\n    resolution`)

// newFollowHarness is a harness over that project, with the lockfile pnpm
// makes given. The registry declares browsers and app to require shared in
// the ranges given.
func newFollowHarness(t *testing.T, before followSpec, after string, browsersRange string) *harness {
	t.Helper()
	return newFollowHarnessFrom(t, followLock(before), before.otherShared != "", after, browsersRange)
}

// newFollowHarnessFrom is newFollowHarness over a lockfile as it is written.
func newFollowHarnessFrom(t *testing.T, beforeLock string, withOther bool, after string, browsersRange string) *harness {
	t.Helper()
	files := map[string]string{
		"package.json":   `{"name":"f","version":"1.0.0","private":true,"dependencies":{"app":"^1.0.0","browsers":"1.0.0"` + map[bool]string{true: `,"other":"1.0.0"`, false: ""}[withOther] + `}}`,
		"pnpm-lock.yaml": beforeLock,
	}
	origin := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/app/package.json"}
	h := &harness{t: t, fx: fixtureFor("pnpm"), files: files}
	h.item = itemFor(t, ManagerPnpm, files, group(typeNodePkg, "app", "1.0.0", origin, CVERef{VulnID: "CVE-A", FixedVers: []string{"1.1.0"}}))
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	dist := func(name, ver string, deps map[string]string) NpmDist {
		return NpmDist{Tarball: "https://registry.npmjs.org/" + name + "/-/" + name + "-" + ver + ".tgz", Integrity: partialIntegrity(name, ver), Dependencies: deps}
	}
	h.npm = &fakeNpm{dists: map[string]NpmDist{
		"app@1.1.0":      dist("app", "1.1.0", map[string]string{"shared": "^1.0.0"}),
		"browsers@1.0.0": dist("browsers", "1.0.0", map[string]string{"shared": browsersRange}),
		"browsers@1.0.1": dist("browsers", "1.0.1", map[string]string{"shared": browsersRange}),
		"other@1.0.0":    dist("other", "1.0.0", map[string]string{"shared": "*"}),
		"shared@1.1.0":   dist("shared", "1.1.0", nil),
		"shared@1.2.0":   dist("shared", "1.2.0", nil),
	}}
	h.pypi = &fakePyPI{auto: true}
	h.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": []byte(after)}}}
	}}
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) {
		var pkgs [][2]string
		var vulns [][3]string
		for _, m := range followPackages.FindAllStringSubmatch(string(in["pnpm-lock.yaml"]), -1) {
			pkgs = append(pkgs, [2]string{m[1], m[2]})
			if m[1] == "app" && m[2] == "1.0.0" {
				vulns = append(vulns, [3]string{"app", "1.0.0", "CVE-A"})
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

var followBefore = followSpec{app: "1.0.0", appShared: "1.0.0", browsersShared: "1.0.0", shared: []string{"1.0.0"}}

func TestLangUpdateAllowsADependencyToFollowTheUpdate(t *testing.T) {
	after := followLock(followSpec{app: "1.1.0", appShared: "1.1.0", browsersShared: "1.1.0", shared: []string{"1.1.0"}})
	h := newFollowHarness(t, followBefore, after, "^1.0.0")
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	d := it.Update.Diff
	if d == nil || len(d.Followed) != 1 || d.Followed[0].Entry != "browsers@1.0.0" ||
		len(d.Followed[0].Moves) != 1 || d.Followed[0].Moves[0] != (FollowMove{Name: "shared", From: "1.0.0", To: "1.1.0"}) {
		t.Fatalf("diff = %+v", d)
	}
	if !contains(d.Removed, "shared@1.0.0") {
		t.Errorf("removed = %v: the old version nothing refers to is taken out", d.Removed)
	}
	// The registry was asked about the entry that followed, so its range was judged.
	if !contains(h.npm.lookups, "browsers@1.0.0") {
		t.Errorf("lookups = %v", h.npm.lookups)
	}
	// The unit and the pull request body carry the entries.
	u := buildLanguageUnit(&it, 0)
	if u.manual || len(u.lang.record.Followed) != 1 {
		t.Fatalf("unit = %+v", u)
	}
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		tx := textFor(lang)
		in := bodyFixtures(t, lang)["language"]
		if !strings.Contains(in, tx.LFollowedTitle) {
			t.Errorf("%s: the full fixture lacks %q", lang, tx.LFollowedTitle)
		}
	}
}

func TestLangUpdateAllowsADependencyToFollowOntoAVersionTheFileHad(t *testing.T) {
	// shared 1.1.0 is in the file already, used by another dependency, and the
	// updated package now uses it too; browsers follows it there.
	before := followBefore
	before.otherShared = "1.1.0"
	before.shared = []string{"1.0.0", "1.1.0"}
	after := followLock(followSpec{app: "1.1.0", appShared: "1.1.0", browsersShared: "1.1.0", otherShared: "1.1.0", shared: []string{"1.1.0"}})
	h := newFollowHarness(t, before, after, "^1.0.0")
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	d := it.Update.Diff
	if d == nil || len(d.Followed) != 1 || d.Followed[0].Entry != "browsers@1.0.0" || d.Followed[0].Moves[0] != (FollowMove{Name: "shared", From: "1.0.0", To: "1.1.0"}) {
		t.Fatalf("diff = %+v", d)
	}
}

func TestLangUpdateRefusesADependencyThatMovesForAnotherReason(t *testing.T) {
	good := followSpec{app: "1.1.0", appShared: "1.1.0", browsersShared: "1.1.0", shared: []string{"1.1.0"}}
	cases := []struct {
		name   string
		before followSpec
		after  func() string
		rng    string
		reason Reason
		mutate func(h *harness)
	}{
		{"the entry itself changes version", followBefore, func() string {
			f := good
			f.browsersVer = "1.0.1"
			return followLock(f)
		}, "^1.0.0", ReasonUnexplainedDiff, nil},
		{"a version unrelated to the updated package", followBefore, func() string {
			f := good
			f.browsersShared = "1.2.0"
			f.shared = []string{"1.1.0", "1.2.0"}
			return followLock(f)
		}, "^1.0.0", ReasonUnexplainedDiff, nil},
		{"outside the declared range", followBefore, func() string { return followLock(good) }, "~1.0.0", ReasonRangeExcludesFix, nil},
		{"a version the file had that no updated package reaches", func() followSpec {
			f := followBefore
			f.otherShared = "0.9.0"
			f.shared = []string{"0.9.0", "1.0.0"}
			return f
		}(), func() string {
			f := good
			f.browsersShared = "0.9.0"
			f.otherShared = "0.9.0"
			f.shared = []string{"0.9.0", "1.1.0"}
			return followLock(f)
		}, "*", ReasonUnexplainedDiff, nil},
		{"a distribution the registry does not publish", followBefore, func() string {
			return strings.Replace(followLock(good), partialIntegrity("shared", "1.1.0"), partialIntegrity("shared", "9.9.9"), 1)
		}, "^1.0.0", ReasonDistributionMismatch, nil},
		{"another requirement appears", followBefore, func() string {
			return strings.Replace(followLock(good), "  browsers@1.0.0:\n    dependencies:\n      shared: 1.1.0\n", "  browsers@1.0.0:\n    dependencies:\n      shared: 1.1.0\n      extra: 1.0.0\n", 1)
		}, "^1.0.0", ReasonUnexplainedDiff, nil},
		{"the record of the entry changes", followBefore, func() string {
			return strings.Replace(followLock(good), "  browsers@1.0.0:\n    dependencies:", "  browsers@1.0.0:\n    optional: true\n    dependencies:", 1)
		}, "^1.0.0", ReasonUnexplainedDiff, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newFollowHarness(t, c.before, c.after(), c.rng)
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, c.reason)
		})
	}
}

func TestLangUpdateChecksTheDistributionOfAVersionTheFileHadAndFollowersMovedTo(t *testing.T) {
	// shared 1.1.0 was in the file before, with an integrity the registry does
	// not publish for it; browsers moving there does not make it trustworthy.
	fake := partialIntegrity("shared", "9.9.9")
	before := followBefore
	before.otherShared = "1.1.0"
	before.shared = []string{"1.0.0", "1.1.0"}
	before.sharedIntegrity = fake
	after := followLock(followSpec{app: "1.1.0", appShared: "1.1.0", browsersShared: "1.1.0", otherShared: "1.1.0", shared: []string{"1.1.0"}, sharedIntegrity: fake})
	h := newFollowHarness(t, before, after, "^1.0.0")
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	if !strings.Contains(it.Detail, "shared 1.1.0") {
		t.Errorf("detail = %q", it.Detail)
	}
}

func TestLangUpdateJudgesTheReferencesOfTheFileAsItIs(t *testing.T) {
	// The importer asks for browsers with a peer context the file has no
	// snapshot for. Left out of both, the contexts of the updated package make
	// the references look whole; as written they are not.
	good := followLock(followSpec{app: "1.1.0", appShared: "1.1.0", browsersShared: "1.1.0", shared: []string{"1.1.0"}})
	broken := strings.Replace(good, "      browsers:\n        specifier: 1.0.0\n        version: 1.0.0\n", "      browsers:\n        specifier: 1.0.0\n        version: 1.0.0(app@0.0.0)\n", 1)
	broken = strings.Replace(broken, "  browsers@1.0.0:\n    dependencies:", "  browsers@1.0.0(app@1.1.0):\n    dependencies:", 1)
	if broken == good {
		t.Fatal("the fixture was not changed")
	}
	h := newFollowHarness(t, followBefore, broken, "^1.0.0")
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if !strings.Contains(it.Detail, "no entry satisfies") {
		t.Errorf("detail = %q", it.Detail)
	}
	// The same file with a snapshot for the context it names is whole.
	whole := strings.Replace(good, "  browsers@1.0.0:\n    dependencies:", "  browsers@1.0.0(app@1.1.0):\n    dependencies:", 1)
	whole = strings.Replace(whole, "        version: 1.0.0\n\npackages", "        version: 1.0.0(app@1.1.0)\n\npackages", 1)
	h = newFollowHarness(t, followBefore, whole, "^1.0.0")
	it, _ = h.run()
	if it.Category != CategoryPRCandidate {
		t.Errorf("a whole file with contexts: %s / %s (%s)", it.Category, it.Reason, it.Detail)
	}
}

func TestLangUpdateRequiresTheUpdatedPackageToBeReachedAsWritten(t *testing.T) {
	// The importer names app with a peer context no snapshot has, before and
	// after. Left out of both, the references look whole and app reachable; as
	// written they are neither, in the original as in the result.
	before := followBefore
	before.appContext = "(app@0.0.0)"
	after := followLock(followSpec{app: "1.1.0", appShared: "1.1.0", browsersShared: "1.1.0", shared: []string{"1.1.0"}, appContext: "(app@0.0.0)"})
	h := newFollowHarness(t, before, after, "^1.0.0")
	it, _ := h.run()
	if it.Category == CategoryPRCandidate {
		t.Fatalf("a file whose references are unmet as written was accepted")
	}
	t.Logf("%s / %s: %s", it.Category, it.Reason, it.Detail)
}

func TestLangUpdateRefusesAFollowToTheSameVersionWithAnotherContext(t *testing.T) {
	// browsers goes from shared@1.0.0(peer@1.0.0) to shared@1.0.0(peer@2.0.0):
	// the version of shared is the same, so it is not a move to another version
	// of the package.
	lock := func(app, peer string) string {
		return "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n" +
			"      app:\n        specifier: ^1.0.0\n        version: " + app + "\n      browsers:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n" +
			"  app@" + app + ":\n    resolution: {integrity: " + partialIntegrity("app", app) + "}\n\n" +
			"  browsers@1.0.0:\n    resolution: {integrity: " + partialIntegrity("browsers", "1.0.0") + "}\n\n" +
			"  peer@" + peer + ":\n    resolution: {integrity: " + partialIntegrity("peer", peer) + "}\n\n" +
			"  shared@1.0.0:\n    resolution: {integrity: " + partialIntegrity("shared", "1.0.0") + "}\n\nsnapshots:\n\n" +
			"  app@" + app + ":\n    dependencies:\n      shared: 1.0.0(peer@" + peer + ")\n\n" +
			"  browsers@1.0.0:\n    dependencies:\n      shared: 1.0.0(peer@" + peer + ")\n\n" +
			"  peer@" + peer + ": {}\n\n" +
			"  shared@1.0.0(peer@" + peer + "):\n    dependencies:\n      peer: " + peer + "\n"
	}
	h := newFollowHarnessFrom(t, lock("1.0.0", "1.0.0"), false, lock("1.1.0", "2.0.0"), "^1.0.0")
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if !strings.Contains(it.Detail, "browsers@1.0.0 changed") {
		t.Errorf("detail = %q: it is browsers that is refused", it.Detail)
	}
}

func TestLangUpdateDoesNotMakeAnUnmetReferenceReachFromTheUpdatedPackage(t *testing.T) {
	// app writes its optional shared in a way no snapshot matches, before and
	// after: with a context where the snapshot has none, or the other way round.
	// Left out of the context, the reference would reach shared@1.1.0 from app and
	// explain browsers moving there; as written it reaches nothing, so the move is
	// not one of the update's.
	for name, c := range map[string]struct{ ref, key string }{
		"the reference has a context, the snapshot has none": {"(app@0.0.0)", ""},
		"the reference has none, the snapshot has a context": {"", "(app@0.0.0)"},
	} {
		t.Run(name, func(t *testing.T) {
			lock := func(app, shared string) string {
				return "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n" +
					"      app:\n        specifier: ^1.0.0\n        version: " + app + "\n      browsers:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n" +
					"  app@" + app + ":\n    resolution: {integrity: " + partialIntegrity("app", app) + "}\n\n" +
					"  browsers@1.0.0:\n    resolution: {integrity: " + partialIntegrity("browsers", "1.0.0") + "}\n\n" +
					"  shared@" + shared + ":\n    resolution: {integrity: " + partialIntegrity("shared", shared) + "}\n\nsnapshots:\n\n" +
					"  app@" + app + ":\n    optionalDependencies:\n      shared: " + shared + c.ref + "\n\n" +
					"  browsers@1.0.0:\n    dependencies:\n      shared: " + shared + c.key + "\n\n" +
					"  shared@" + shared + c.key + ": {}\n"
			}
			h := newFollowHarnessFrom(t, lock("1.0.0", "1.0.0"), false, lock("1.1.0", "1.1.0"), "^1.0.0")
			it, _ := h.run()
			if it.Category == CategoryPRCandidate {
				t.Fatalf("a move explained by a reference the file does not resolve was accepted")
			}
			wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
			if !strings.Contains(it.Detail, "browsers@1.0.0 changed") {
				t.Errorf("detail = %q: it is the move of browsers that is refused", it.Detail)
			}
		})
	}
}

func TestCheckReferencesStaysSmallWithLongKeysAndManyUnmetRequirements(t *testing.T) {
	// One snapshot with a key of about 1KiB (the longest the reader takes as a key) that requires 100000 packages the
	// file does not have, in the original and in the result.
	key := "host@1.0.0(" + strings.Repeat("a", 900) + "@1)"
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n      host:\n        specifier: 1.0.0\n        version: " + key[len("host@"):] + "\n\npackages:\n\n  host@1.0.0:\n    resolution: {integrity: sha512-h}\n\nsnapshots:\n\n  '" + key + "':\n    dependencies:\n")
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&b, "      d%d: 9.9.9\n", i)
	}
	lock := []byte(b.String())
	r := &updateRun{it: &LanguageItem{Manager: ManagerPnpm}, src: &sourceFiles{lock: lock}, full: updateSet{targets: map[string]bool{}}}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	fail := r.checkReferences(context.Background(), lock)
	runtime.ReadMemStats(&m1)
	if fail != nil {
		t.Fatalf("the same unmet requirements before and after: %+v", fail)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %s", d)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 600<<20 {
		t.Errorf("allocated %d MiB", alloc>>20)
	}
	// The end of the time allowed is noticed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f := r.checkReferences(ctx, lock); f == nil || f.category != CategoryDeferred {
		t.Errorf("a cancelled context: %+v", f)
	}
}
