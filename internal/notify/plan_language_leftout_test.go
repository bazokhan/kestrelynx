package notify

import (
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
