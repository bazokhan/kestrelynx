package remediation

import (
	"os"
	"path/filepath"
	"testing"
)

// A record rebuilt from a marker matches an update by its key, which does not
// name the packages the update leaves out. The record that stands for the
// update afterwards holds the packages left out of the inputs it was verified
// against, so a later cycle does not show them as moved by the pull request.
func TestPRStageLanguageKeepsThePackagesLeftOutWhenAMarkerRecordIsVerified(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)

	// The pull request was made for the first package alone.
	h.run(prLangPlan(h.langItem(fx)))
	if err := os.Remove(filepath.Join(h.dir, "prs.json")); err != nil {
		t.Fatal(err)
	}

	// Now the unit has two packages and the update leaves the second out; the
	// files it changes, and so the update key, are the same.
	second := npmPackage("qs", "6.11.0", "6.11.3", "CVE-2022-24999", "qs@6.11.0")
	both := fx
	both.pkgs = append(append([]LanguagePackage(nil), fx.pkgs...), second)
	done := h.langItem(both)
	done.Packages[1].Action, done.Packages[1].AdoptedVersion = ActionManual, ""
	done.Packages[1].Reason, done.Packages[1].LeftOut = ReasonTargetNotUpdated, true
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(done))), PRStatusOpen, "")

	rec := h.load().PRs[0]
	if !rec.InputVerified || rec.Lang.InputFingerprint != LanguageInputFingerprint(done) {
		t.Fatalf("record = verified %v, fingerprint %q", rec.InputVerified, rec.Lang.InputFingerprint)
	}
	if len(rec.Lang.Remaining) != 1 || rec.Lang.Remaining[0] != (LangRemaining{Ecosystem: "node-pkg", Name: "qs", Reason: ReasonTargetNotUpdated}) {
		t.Fatalf("record remaining = %+v", rec.Lang.Remaining)
	}

	// The next cycle plans both packages as updates; the record stands for
	// them, and the view says the pull request leaves the second one out.
	planned := candidateOf(done)
	planned.Packages = append([]LanguagePackage(nil), both.pkgs...)
	plan := prLangPlan(planned)
	if _, bound := BindProposedLanguageUpdates(&plan, h.store); bound != 1 {
		t.Fatal("the item was not tied to the pull request")
	}
	u := onlyUnit(t, h.run(plan))
	wantStatus(t, u, PRStatusOpen, "")
	if u.Language == nil || len(u.Language.Packages) != 1 || u.Language.Packages[0].Name != "minimist" {
		t.Fatalf("view packages = %+v", u.Language)
	}
	if len(u.Language.Remaining) != 1 || u.Language.Remaining[0].Name != "qs" || u.Language.Remaining[0].Reason != ReasonTargetNotUpdated {
		t.Errorf("view remaining = %+v", u.Language.Remaining)
	}
}

// A package that the record of the pull request neither updates nor lists as
// left out is not shown as an update to its target.
func TestTiedLanguageItemDoesNotShowAnUnrecordedPackageAsUpdated(t *testing.T) {
	a := npmPackage("minimist", "1.2.5", "1.2.8", "CVE-A", "minimist@1.2.5")
	b := npmPackage("qs", "6.11.0", "6.11.3", "CVE-B", "qs@6.11.0")
	it := LanguageItem{Manager: ManagerNpm, Packages: []LanguagePackage{a, b}}
	rec := &PRRecord{Lang: &LangRecord{
		Manager:  string(ManagerNpm),
		Packages: []LangKeyEntry{{Ecosystem: "node-pkg", Name: "minimist", Positions: []string{"minimist@1.2.5"}, Adopted: "1.2.8"}},
	}}
	v := languageViewOfTied(it, rec)
	if len(v.Packages) != 1 || v.Packages[0].Name != "minimist" || v.Packages[0].To != "1.2.8" {
		t.Errorf("packages = %+v", v.Packages)
	}
	if len(v.Remaining) != 1 || v.Remaining[0].Name != "qs" || v.Remaining[0].Reason != ReasonTargetNotUpdated {
		t.Errorf("remaining = %+v", v.Remaining)
	}
}
