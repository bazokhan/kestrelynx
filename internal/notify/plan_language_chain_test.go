package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// chainItem is a dependency item whose express was held back by a package that
// depends on it and was taken to its fixed version by updating mkdirp.
func chainItem(p *remediation.Plan) *remediation.LanguageItem {
	li := &p.LanguageItems[0]
	li.Packages = li.Packages[:1]
	li.Packages[0].SelectionLowerBound = "4.19.2"
	li.Update = &remediation.LanguageUpdate{Chain: &remediation.ChainUpdate{
		Outcome: remediation.ChainAdopted, Source: "chain_job",
		Blocked: []remediation.ChainBlock{{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact"}},
		Tops:    []remediation.ChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Kind: "top"}},
	}}
	return li
}

func TestPlanSlack_ChainUpdateNamesTheDirectDependency(t *testing.T) {
	r, _, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified
	li.Packages[0].AdoptedVersion = "4.19.2"
	li.Packages[0].Through = []string{"mkdirp"}
	info := &PlanInfo{Plan: &p, Changed: true}
	if got := slackPlanText(r, info, LanguageEN); !strings.Contains(got, "express 4.18.2 → 4.19.2 (with mkdirp 0.5.1 → 0.5.6)") {
		t.Errorf("en:\n%s", got)
	}
	if got := slackPlanText(r, info, LanguageJA); !strings.Contains(got, "express 4.18.2 → 4.19.2（mkdirp 0.5.1 → 0.5.6 も更新）") {
		t.Errorf("ja:\n%s", got)
	}
	// The pull request's own view says the same.
	p2 := languageFixture()
	chainItem(&p2)
	units := []remediation.PRUnit{{
		Kind: "language", ItemKey: p2.LanguageItems[0].Key, Number: 3, Status: remediation.PRStatusOpen, Repo: "ex/app", Path: "backend/package-lock.json",
		Language: &remediation.PRLanguage{
			Packages: []remediation.PRLanguagePackage{{Name: "express", From: "4.18.2", To: "4.19.2", Through: []string{"mkdirp"}}},
			Chain:    []remediation.LangChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6"}},
		},
	}}
	p2.PullRequests = units
	if got := slackPlanText(r, &PlanInfo{Plan: &p2, Changed: true}, LanguageEN); !strings.Contains(got, "express 4.18.2 → 4.19.2 (with mkdirp 0.5.1 → 0.5.6)") {
		t.Errorf("unit:\n%s", got)
	}
}

func TestPlanSlack_PackagesTheChainUpdateDidNotTake(t *testing.T) {
	r, _, _ := planCycleFixture()
	cases := []struct {
		name   string
		reason remediation.Reason
		chain  remediation.ChainUpdate
		en, ja string
	}{
		{"not fixed", remediation.ReasonDependentsNotFixed, remediation.ChainUpdate{Outcome: remediation.ChainNotFixed},
			"express 4.18.2 → 4.19.2: re-resolving mkdirp 0.5.1 within the project's ranges did not reach the fixed version this time",
			"express 4.18.2 → 4.19.2: mkdirp 0.5.1 をプロジェクトの範囲内で解決し直したが、今回の再解決では修正版に届かなかった"},
		{"rejected", remediation.ReasonDependentsRejected, remediation.ChainUpdate{Outcome: remediation.ChainRejected, Reason: remediation.ReasonSourceIntroduced},
			"express 4.18.2 → 4.19.2 needs mkdirp 0.5.1 updated as well, and that update was not adopted because the update brings new findings into the dependency files",
			"express 4.18.2 → 4.19.2 には mkdirp 0.5.1 の更新も必要だが、更新で依存関係ファイルに新たな所見が入るため採用しない"},
		{"limit", remediation.ReasonDependentsLimit, remediation.ChainUpdate{Outcome: remediation.ChainNotTried, Reason: remediation.ReasonChainItemBudget},
			"express 4.18.2 → 4.19.2 is held back by mkdirp 0.5.1, and updating mkdirp 0.5.1 was not tried because the update needs more work than one item may use",
			"express 4.18.2 → 4.19.2 は mkdirp 0.5.1 に止められていて、更新に必要な作業が1項目の上限を超えるため mkdirp 0.5.1 の更新を試していない"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := languageFixture()
			li := chainItem(&p)
			chain := c.chain
			chain.Blocked = li.Update.Chain.Blocked
			li.Update.Chain = &chain
			li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
			li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, c.reason
			info := &PlanInfo{Plan: &p, Changed: true}
			if got := slackPlanText(r, info, LanguageEN); !strings.Contains(got, c.en) {
				t.Errorf("en:\n%s", got)
			}
			if got := slackPlanText(r, info, LanguageJA); !strings.Contains(got, c.ja) {
				t.Errorf("ja:\n%s", got)
			}
		})
	}
	t.Run("without tops the line is the package's reason", func(t *testing.T) {
		p := languageFixture()
		li := chainItem(&p)
		li.Update.Chain = &remediation.ChainUpdate{Outcome: remediation.ChainNotTried, Reason: remediation.ReasonDependentsUnsupported}
		li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
		li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, remediation.ReasonDependentsUnsupported
		got := slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageEN)
		if !strings.Contains(got, "express 4.18.2 → 4.19.2: the packages that depend on it cannot be updated by this tool") {
			t.Errorf("text:\n%s", got)
		}
	})
}

func TestPlanSlack_ChainUpdateThatWaitsForAVersionToAge(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	retry := time.Date(2026, 10, 20, 3, 4, 5, 0, time.UTC)
	li.Category, li.Reason, li.RetryAfter = remediation.CategoryDeferred, remediation.ReasonReleaseTooNew, &retry
	li.Update.Chain = &remediation.ChainUpdate{Outcome: remediation.ChainDeferred, Reason: remediation.ReasonReleaseTooNew, Blocked: li.Update.Chain.Blocked}
	info := &PlanInfo{Plan: &p, Changed: true}
	if got := slackPlanText(r, info, LanguageEN); !strings.Contains(got, "express 4.18.2 → 4.19.2 needs mkdirp 0.5.1 updated as well; a version it brings in is less than 72 hours old, so it is tried again after 2026-10-20T03:04:05Z") {
		t.Errorf("en:\n%s", got)
	}
	if got := slackPlanText(r, info, LanguageJA); !strings.Contains(got, "express 4.18.2 → 4.19.2 には mkdirp 0.5.1 の更新も必要だが、入る版の公開から72時間経っていないため 2026-10-20T03:04:05Z 以降に再試行する") {
		t.Errorf("ja:\n%s", got)
	}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, info))["remediation"].(map[string]any)
	item := rem["language_items"].([]any)[0].(map[string]any)
	if item["retry_after"] != "2026-10-20T03:04:05Z" || item["reason"] != "release_too_new" {
		t.Errorf("item = %v", item)
	}
}

func TestWebhook_ChainFields(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified
	li.Packages[0].AdoptedVersion = "4.19.2"
	li.Packages[0].Through = []string{"mkdirp"}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	item := rem["language_items"].([]any)[0].(map[string]any)
	pkg := item["packages"].([]any)[0].(map[string]any)
	if th, _ := pkg["through"].([]any); len(th) != 1 || th[0] != "mkdirp" {
		t.Errorf("package = %v", pkg)
	}
	chain := item["update"].(map[string]any)["chain"].(map[string]any)
	if chain["outcome"] != "adopted" || chain["source"] != "chain_job" || len(chain["blocked"].([]any)) != 1 || len(chain["tops"].([]any)) != 1 {
		t.Errorf("chain = %v", chain)
	}
	if _, has := item["retry_after"]; has {
		t.Error("retry_after on an item that does not wait")
	}
	// An item without a chain has none of the fields.
	plain := languageFixture()
	rem = webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &plain, Changed: true}))["remediation"].(map[string]any)
	first := rem["language_items"].([]any)[0].(map[string]any)
	if _, has := first["update"]; has {
		t.Errorf("update on an item that has none: %v", first["update"])
	}
	if pk := first["packages"].([]any)[0].(map[string]any); pk["through"] != nil {
		t.Errorf("through = %v", pk["through"])
	}
}

func TestWebhook_ThroughIsKeptWhenThePlanTiesTheItemToItsPullRequest(t *testing.T) {
	// The next cycle does not update the item again: its packages carry no
	// Through, and the pull request's view does.
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateAlreadyProposed
	li.Update = nil
	p.PullRequests = []remediation.PRUnit{{
		Kind: "language", ItemKey: li.Key, Number: 3, Status: remediation.PRStatusOpen, Repo: "ex/app", Path: "backend/package-lock.json",
		Language: &remediation.PRLanguage{Packages: []remediation.PRLanguagePackage{
			{Name: "express", Ecosystem: "node-pkg", From: "4.18.2", To: "4.19.2", Through: []string{"mkdirp"}},
			{Name: "express", Ecosystem: "python-pkg", From: "1", To: "2", Through: []string{"other"}},
		}},
	}}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	pkg := rem["language_items"].([]any)[0].(map[string]any)["packages"].([]any)[0].(map[string]any)
	if th, _ := pkg["through"].([]any); len(th) != 1 || th[0] != "mkdirp" {
		t.Errorf("package = %v", pkg)
	}
}
