package notify

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// leftOutFixture is a verified dependency update that leaves one package out
// because it did not reach its target.
func leftOutFixture() remediation.Plan {
	p := languageFixture()
	li := &p.LanguageItems[0]
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified
	li.UpdateExecuted, li.PostUpdateCheckExecuted = true, true
	li.Packages = []remediation.LanguagePackage{
		langPkg("express", "4.18.2", "4.19.2", true),
		{Name: "multer", Ecosystem: "node-pkg", Installed: "2.1.1", SelectionLowerBound: "2.3.0", Action: remediation.ActionManual,
			Reason: remediation.ReasonTargetNotUpdated, LeftOut: true},
	}
	li.Packages[0].AdoptedVersion = "4.19.2"
	li.Packages[0].Reason = remediation.ReasonUpdateVerified
	return p
}

func TestLanguageUpdateLines_PackagesLeftOut(t *testing.T) {
	cases := map[Language]string{
		LanguageEN: "multer 2.1.1 → 2.3.0 left out of the update, needs a person — target_not_updated",
		LanguageJA: "multer 2.1.1 → 2.3.0 は今回の更新から除外。要判断 — target_not_updated",
	}
	for lang, want := range cases {
		t.Run(string(lang), func(t *testing.T) {
			p := leftOutFixture()
			warn, _ := languageUpdateLines(p, messagesFor(lang))
			if len(warn) != 1 || !strings.Contains(warn[0], want) || !strings.Contains(warn[0], "api") {
				t.Fatalf("warn = %q, want a line with %q", warn, want)
			}
		})
	}
	t.Run("more than one", func(t *testing.T) {
		p := leftOutFixture()
		li := &p.LanguageItems[0]
		li.Packages = append(li.Packages, remediation.LanguagePackage{Name: "qs", Ecosystem: "node-pkg", Installed: "6.11.0", SelectionLowerBound: "6.11.3",
			Action: remediation.ActionManual, Reason: remediation.ReasonTargetNotUpdated, LeftOut: true})
		warn, _ := languageUpdateLines(p, messagesFor(LanguageEN))
		if len(warn) != 1 || !strings.Contains(warn[0], "multer 2.1.1 → 2.3.0 and 1 more left out") {
			t.Fatalf("warn = %q", warn)
		}
	})
	t.Run("the pull request unit's view is used when there is one", func(t *testing.T) {
		p := leftOutFixture()
		li := &p.LanguageItems[0]
		li.Packages[1].LeftOut = false // an item tied to an earlier pull request holds no marks
		p.PullRequests = []remediation.PRUnit{{
			Kind: "language", ItemKey: li.Key, Number: 12, URL: "https://github.com/ex/app/pull/12", Status: remediation.PRStatusOpen,
			Language: &remediation.PRLanguage{Remaining: []remediation.PRLanguageRemaining{{Name: "multer", From: "2.1.1", Target: "2.3.0", Reason: remediation.ReasonTargetNotUpdated}}},
		}}
		warn, _ := languageUpdateLines(p, messagesFor(LanguageEN))
		if len(warn) != 1 || !strings.Contains(warn[0], "multer 2.1.1 → 2.3.0 left out of the update") {
			t.Fatalf("warn = %q", warn)
		}
	})
	t.Run("an update that leaves nothing out says nothing", func(t *testing.T) {
		p := leftOutFixture()
		p.LanguageItems[0].Packages[1].LeftOut = false
		warn, _ := languageUpdateLines(p, messagesFor(LanguageEN))
		if len(warn) != 0 {
			t.Fatalf("warn = %q", warn)
		}
	})
}

func TestWebhookPayload_PackageLeftOut(t *testing.T) {
	p := leftOutFixture()
	pl := languageItemPayloadOf(p.LanguageItems[0], nil)
	if len(pl.Packages) != 2 || pl.Packages[0].LeftOut || !pl.Packages[1].LeftOut || pl.Packages[1].Reason != string(remediation.ReasonTargetNotUpdated) {
		t.Errorf("packages = %+v", pl.Packages)
	}
}

func TestWebhookPayload_LeftOutOfTheTiedPullRequest(t *testing.T) {
	// An item tied to a pull request of an earlier cycle was not updated again:
	// both packages are still planned as updates, and the pull request's view
	// says which one it leaves out.
	p := leftOutFixture()
	li := p.LanguageItems[0]
	li.Packages[1].LeftOut, li.Packages[1].Action, li.Packages[1].Reason = false, remediation.ActionUpdate, ""
	units := []remediation.PRUnit{{
		Kind: "language", ItemKey: li.Key, Number: 12, Status: remediation.PRStatusOpen,
		Language: &remediation.PRLanguage{Remaining: []remediation.PRLanguageRemaining{
			{Name: "multer", Ecosystem: "node-pkg", From: "2.1.1", Target: "2.3.0", Reason: remediation.ReasonTargetNotUpdated},
			{Name: "multer", Ecosystem: "pypi", From: "2.1.1", Target: "2.3.0", Reason: remediation.ReasonTargetNotUpdated},
		}},
	}}
	pl := languageItemPayloadOf(li, units)
	if len(pl.Packages) != 2 || pl.Packages[0].LeftOut || pl.Packages[0].Action == string(remediation.ActionManual) {
		t.Fatalf("packages = %+v", pl.Packages)
	}
	if m := pl.Packages[1]; !m.LeftOut || m.Action != string(remediation.ActionManual) || m.Reason != string(remediation.ReasonTargetNotUpdated) {
		t.Errorf("multer = %+v", m)
	}
}
