package remediation

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The project of these tests is a pnpm project of two direct dependencies:
// mkdirp, which requires minimist, and holder, which requires pinned at an
// exact version. minimist can be taken to its target; pinned cannot, because
// holder holds it back.

func partialIntegrity(name, ver string) string {
	sum := sha512.Sum512([]byte(name + "@" + ver))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// partialLock makes the pnpm-lock.yaml of the project with minimist at minVer
// and pinned at pinVer. When the manifest asks for pinned itself, the
// importer lists it too, with the specifier the manifest has.
func partialLock(minVer, pinVer string, pinnedDirect string) string {
	minIntegrity := partialIntegrity("minimist", minVer)
	switch minVer {
	case "1.2.5":
		minIntegrity = "sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw=="
	case "1.2.8":
		minIntegrity = minimist128.Integrity
	}
	direct := ""
	if pinnedDirect != "" {
		direct = fmt.Sprintf("      pinned:\n        specifier: %s\n        version: %s\n", pinnedDirect, pinVer)
	}
	return fmt.Sprintf(`lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      holder:
        specifier: 1.0.0
        version: 1.0.0
      mkdirp:
        specifier: 0.5.5
        version: 0.5.5
%s
packages:

  holder@1.0.0:
    resolution: {integrity: %s}

  minimist@%s:
    resolution: {integrity: %s}

  mkdirp@0.5.5:
    resolution: {integrity: sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==}
    hasBin: true

  pinned@%s:
    resolution: {integrity: %s}

snapshots:

  holder@1.0.0:
    dependencies:
      pinned: %s

  minimist@%s: {}

  mkdirp@0.5.5:
    dependencies:
      minimist: %s

  pinned@%s: {}
`, direct, partialIntegrity("holder", "1.0.0"), minVer, minIntegrity, pinVer, partialIntegrity("pinned", pinVer), pinVer, minVer, minVer, pinVer)
}

func partialPackageJSON(pinnedDirect string) string {
	extra := ""
	if pinnedDirect != "" {
		extra = fmt.Sprintf(",\n    \"pinned\": %q", pinnedDirect)
	}
	return `{
  "name": "fixture-partial",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "holder": "1.0.0",
    "mkdirp": "0.5.5"` + extra + `
  }
}
`
}

// newPartialHarness is a harness for that project: the work container
// returns the lockfile that lockFor gives for the job, and the filesystem scans
// list the packages of the lockfile they are given.
func newPartialHarness(t *testing.T, pinnedDirect string, packages []string, lockFor func(job worker.Job, src map[string][]byte) string) *harness {
	t.Helper()
	files := map[string]string{
		"package.json":   partialPackageJSON(pinnedDirect),
		"pnpm-lock.yaml": partialLock("1.2.5", "2.0.0", pinnedDirect),
	}
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
	h.npm = &fakeNpm{dists: map[string]NpmDist{
		"minimist@1.2.8": minimist128,
		"mkdirp@0.5.5": {Tarball: "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.5.tgz", Dependencies: map[string]string{"minimist": "^1.2.5"},
			Integrity: "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ=="},
	}}
	h.pypi = &fakePyPI{auto: true}
	h.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"pnpm-lock.yaml": []byte(lockFor(job, src))}}}
	}}
	// A scan lists the packages of the lockfile it is given, and reports the
	// vulnerability of each package at the version it has in the original.
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) {
		lock := string(in["pnpm-lock.yaml"])
		pkgs := [][2]string{{"holder", "1.0.0"}, {"mkdirp", "0.5.5"}}
		var vulns [][3]string
		for _, v := range []string{"1.2.5", "1.2.6", "1.2.8"} {
			if strings.Contains(lock, "\n  minimist@"+v+":") {
				pkgs = append(pkgs, [2]string{"minimist", v})
				if v == "1.2.5" {
					vulns = append(vulns, [3]string{"minimist", v, "CVE-A"})
				}
			}
		}
		for _, v := range []string{"2.0.0", "2.0.1", "2.0.2"} {
			if strings.Contains(lock, "\n  pinned@"+v+":") {
				pkgs = append(pkgs, [2]string{"pinned", v})
				if v == "2.0.0" {
					vulns = append(vulns, [3]string{"pinned", v, "CVE-B"})
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

func hasName(list []string, name string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

func packageOf(t *testing.T, it LanguageItem, name string) LanguagePackage {
	t.Helper()
	for _, p := range it.Packages {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no package %s in the item", name)
	return LanguagePackage{}
}

func TestLangUpdateLeavesOutAPackageThatStaysBelowItsTarget(t *testing.T) {
	// Both packages are in the set; the update takes minimist to its target
	// and leaves pinned where it was.
	h := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.8", "2.0.0", "")
	})
	before := LanguageInputFingerprint(h.item)
	it, use := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if use.Jobs != 1 || h.work.calls != 1 {
		t.Errorf("jobs = %d, containers = %d, want 1 and 1: the result is used as it is", use.Jobs, h.work.calls)
	}
	min, pin := packageOf(t, it, "minimist"), packageOf(t, it, "pinned")
	if min.Action != ActionUpdate || min.AdoptedVersion != "1.2.8" || min.Reason != ReasonUpdateVerified || min.LeftOut {
		t.Errorf("minimist = %+v", min)
	}
	if pin.Action != ActionManual || pin.Reason != ReasonTargetNotUpdated || !pin.LeftOut || pin.AdoptedVersion != "" ||
		!strings.Contains(pin.Detail, "below the target 2.0.2") {
		t.Errorf("pinned = %+v", pin)
	}
	if !strings.Contains(it.Detail, "1 package(s) did not reach their target") {
		t.Errorf("detail = %q", it.Detail)
	}
	// Only minimist was named to the update, and only it is judged by the scans.
	if got := h.work.namesIn(0); !hasName(got, "minimist") || !hasName(got, "pinned") {
		t.Errorf("the first run named %v, want both packages", got)
	}
	if it.SourceCheck == nil || !it.SourceCheck.Passed {
		t.Fatalf("source check = %+v", it.SourceCheck)
	}
	var remaining []string
	for _, v := range it.SourceCheck.Remaining {
		remaining = append(remaining, v.Package+" "+v.VulnID)
	}
	if strings.Join(remaining, ",") != "pinned CVE-B" {
		t.Errorf("remaining findings = %v, want the one of pinned", remaining)
	}
	if len(it.Artifacts) != 1 || it.Artifacts[0].Path != "pnpm-lock.yaml" {
		t.Errorf("artifacts = %+v", it.Artifacts)
	}
	// The inputs of the unit are the same before and after the stage, so a
	// pull request made from this result stands for the item in later cycles.
	if after := LanguageInputFingerprint(it); after != before {
		t.Errorf("fingerprint changed from %s to %s", before, after)
	}
}

func TestLangUpdateRunsAgainWithoutAPackageItMoved(t *testing.T) {
	// The first run takes pinned to 2.0.1, still below its target 2.0.2, so the
	// result cannot be used; the second run, which does not name pinned,
	// leaves it alone.
	h := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		if hasName(namesInUpdate(job, src), "pinned") {
			return partialLock("1.2.8", "2.0.1", "")
		}
		return partialLock("1.2.8", "2.0.0", "")
	})
	before := LanguageInputFingerprint(h.item)
	it, use := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if use.Jobs != 1 {
		t.Errorf("jobs = %d: both runs belong to the one item", use.Jobs)
	}
	if h.work.calls != 2 {
		t.Fatalf("containers = %d, want 2", h.work.calls)
	}
	if got := h.work.namesIn(1); hasName(got, "pinned") || !hasName(got, "minimist") {
		t.Errorf("the second run named %v, want minimist only", got)
	}
	if h.work.ids[0] == h.work.ids[1] {
		t.Errorf("both runs used the job id %s", h.work.ids[0])
	}
	if pin := packageOf(t, it, "pinned"); !pin.LeftOut || pin.Action != ActionManual || pin.Reason != ReasonTargetNotUpdated {
		t.Errorf("pinned = %+v", pin)
	}
	if min := packageOf(t, it, "minimist"); min.Action != ActionUpdate || min.AdoptedVersion != "1.2.8" {
		t.Errorf("minimist = %+v", min)
	}
	if string(it.Artifacts[0].Content) != partialLock("1.2.8", "2.0.0", "") {
		t.Errorf("the artifact is not the second run's lockfile")
	}
	noted := false
	for _, n := range it.Update.Notes {
		noted = noted || strings.Contains(n, "run again without it")
	}
	if !noted {
		t.Errorf("notes = %v", it.Update.Notes)
	}
	if after := LanguageInputFingerprint(it); after != before {
		t.Errorf("fingerprint changed from %s to %s", before, after)
	}
}

func TestLangUpdateRunsAgainWhenTheOthersMoveAroundAPackageLeftOut(t *testing.T) {
	// pinned stays where it is, but mkdirp, which is above minimist, changes in
	// the first run (a new record of the same version); with pinned out of the
	// set that change has no explanation, so the update is run again.
	h := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		l := partialLock("1.2.8", "2.0.0", "")
		if hasName(namesInUpdate(job, src), "pinned") {
			return strings.Replace(l, "    hasBin: true", "    hasBin: true\n    engines: {node: '>=1'}", 1)
		}
		return l
	})
	it, use := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if use.Jobs != 1 || h.work.calls != 2 {
		t.Errorf("jobs = %d, containers = %d, want 1 and 2", use.Jobs, h.work.calls)
	}
	if !packageOf(t, it, "pinned").LeftOut {
		t.Errorf("pinned = %+v", packageOf(t, it, "pinned"))
	}
}

func TestLangUpdateFailsWhenTheRunWithoutAPackageFailsToo(t *testing.T) {
	// Both runs leave a mark outside the set: the item as a whole is manual,
	// and the package that did not reach its target keeps its own reason.
	h := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.8", "2.0.1", "")
	})
	it, use := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if use.Jobs != 1 || h.work.calls != 2 {
		t.Errorf("jobs = %d, containers = %d, want 1 and 2", use.Jobs, h.work.calls)
	}
	if !strings.Contains(it.Detail, "after leaving out pinned") {
		t.Errorf("detail = %q", it.Detail)
	}
	if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonTargetNotUpdated || pin.LeftOut || pin.Action != ActionManual {
		t.Errorf("pinned = %+v", pin)
	}
	if min := packageOf(t, it, "minimist"); min.Action != ActionManual || min.Reason == ReasonUpdateVerified || min.AdoptedVersion != "" {
		t.Errorf("minimist = %+v", min)
	}
	if len(it.Artifacts) != 0 {
		t.Errorf("artifacts = %+v", it.Artifacts)
	}
}

func TestLangUpdateKeepsTheWholeFailureWhenNothingReachedItsTarget(t *testing.T) {
	// minimist moves to 1.2.6 and pinned to 2.0.1: both are below their
	// targets, so there is nothing to propose and no second run.
	h := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.6", "2.0.1", "")
	})
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	if h.work.calls != 1 {
		t.Errorf("containers = %d, want 1", h.work.calls)
	}
	for _, p := range it.Packages {
		if p.Action != ActionManual || p.LeftOut {
			t.Errorf("%s = %+v", p.Name, p)
		}
	}
}

func TestLangUpdateRunsAgainWhenTheManifestWasEditedForAPackageLeftOut(t *testing.T) {
	// pinned is a direct dependency pinned below its target, so the manifest
	// is edited for it; the first run does not take it there. The edit is not
	// kept for a package that is left out, so the update is run again with the
	// manifest as it was.
	h := newPartialHarness(t, "2.0.0", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		if strings.Contains(string(src["package.json"]), `"pinned": "2.0.2"`) {
			return partialLock("1.2.8", "2.0.0", "2.0.2")
		}
		return partialLock("1.2.8", "2.0.0", "2.0.0")
	})
	it, use := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if use.Jobs != 1 {
		t.Errorf("jobs = %d", use.Jobs)
	}
	if !packageOf(t, it, "pinned").LeftOut {
		t.Errorf("pinned = %+v", packageOf(t, it, "pinned"))
	}
	if len(it.Update.ManifestEdits) != 0 {
		t.Errorf("manifest edits = %+v, want none", it.Update.ManifestEdits)
	}
	// A base job and the edited update, then the update without the edit.
	if h.work.calls != 3 {
		t.Errorf("containers = %d, want 3", h.work.calls)
	}
	if len(it.Artifacts) != 1 {
		t.Errorf("artifacts = %+v, want the lockfile only", it.Artifacts)
	}
}

func TestPullRequestUnitOfAPartialUpdate(t *testing.T) {
	partial := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.8", "2.0.0", "")
	})
	got, _ := partial.run()
	alone := newPartialHarness(t, "", []string{"minimist"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.8", "2.0.0", "")
	})
	gotAlone, _ := alone.run()
	wantCategory(t, gotAlone, CategoryPRCandidate, ReasonUpdateVerified)

	u := buildLanguageUnit(&got, 0)
	if u.manual {
		t.Fatalf("unit is manual: %s %s", u.manualReason, u.manualDetail)
	}
	ua := buildLanguageUnit(&gotAlone, 0)
	if ua.manual {
		t.Fatalf("unit is manual: %s %s", ua.manualReason, ua.manualDetail)
	}
	rec := u.lang.record
	if len(rec.Packages) != 1 || rec.Packages[0].Name != "minimist" || rec.Packages[0].Adopted != "1.2.8" {
		t.Fatalf("record packages = %+v", rec.Packages)
	}
	if len(rec.Remaining) != 1 || rec.Remaining[0] != (LangRemaining{Ecosystem: typeNodePkg, Name: "pinned", Reason: ReasonTargetNotUpdated}) {
		t.Errorf("record remaining = %+v", rec.Remaining)
	}
	// What the pull request changes is what the same update made alone
	// changes: the update key, the places it fixes and the title are equal, so
	// a closed pull request of the one stands for the other.
	tk := TargetKeyOf(prKindLanguage, 1, "main", u.lang.lockPath, []string{"."})
	if k1, k2 := LangUpdateKey(tk, rec.Packages, rec.ManifestEdits), LangUpdateKey(tk, ua.lang.record.Packages, ua.lang.record.ManifestEdits); k1 != k2 {
		t.Errorf("update keys differ: %s and %s", k1, k2)
	}
	if fmt.Sprint(u.lang.fixTargets) != fmt.Sprint(ua.lang.fixTargets) || len(u.lang.fixTargets) == 0 {
		t.Errorf("fix targets = %+v and %+v", u.lang.fixTargets, ua.lang.fixTargets)
	}
	for _, f := range u.lang.fixTargets {
		if f.Package.Name == "pinned" {
			t.Errorf("pinned is among the fix targets: %+v", f)
		}
	}
	if u.lang.title != ua.lang.title {
		t.Errorf("titles = %q and %q", u.lang.title, ua.lang.title)
	}
	v := u.lang.view
	if len(v.Packages) != 1 || v.Packages[0].Name != "minimist" {
		t.Errorf("view packages = %+v", v.Packages)
	}
	if len(v.Remaining) != 1 {
		t.Fatalf("view remaining = %+v", v.Remaining)
	}
	if r := v.Remaining[0]; r.Name != "pinned" || r.From != "2.0.0" || r.Target != "2.0.2" || r.Reason != ReasonTargetNotUpdated || r.Ecosystem != typeNodePkg ||
		!strings.Contains(r.Detail, "below the target 2.0.2") {
		t.Errorf("view remaining = %+v", r)
	}
	if len(ua.lang.view.Remaining) != 0 || len(ua.lang.record.Remaining) != 0 {
		t.Errorf("an update without anything left out records %+v and %+v", ua.lang.view.Remaining, ua.lang.record.Remaining)
	}
	// The record survives the marker, and a record without a reason for a
	// package left out does not.
	if err := rec.wellFormed(); err != nil {
		t.Errorf("record: %v", err)
	}
	bad := *rec
	bad.Remaining = []LangRemaining{{Ecosystem: typeNodePkg, Name: "pinned"}}
	if bad.wellFormed() == nil {
		t.Errorf("a remaining package without a reason is well formed")
	}
}

func TestTiedLanguageItemShowsThePackagesLeftOut(t *testing.T) {
	h := newPartialHarness(t, "", []string{"minimist", "pinned"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.8", "2.0.0", "")
	})
	planned := h.item // the item as the next cycle plans it: nothing is run yet
	got, _ := h.run()
	u := buildLanguageUnit(&got, 0)
	rec := &PRRecord{Lang: u.lang.record}
	if fp := LanguageInputFingerprint(planned); fp != u.lang.record.InputFingerprint {
		t.Fatalf("the planned item has fingerprint %s, the record %s", fp, u.lang.record.InputFingerprint)
	}
	v := languageViewOfTied(planned, rec)
	if len(v.Packages) != 1 || v.Packages[0].Name != "minimist" || v.Packages[0].To != "1.2.8" {
		t.Errorf("packages = %+v", v.Packages)
	}
	if len(v.Remaining) != 1 || v.Remaining[0].Name != "pinned" || v.Remaining[0].Reason != ReasonTargetNotUpdated || v.Remaining[0].Target != "2.0.2" {
		t.Errorf("remaining = %+v", v.Remaining)
	}
}
