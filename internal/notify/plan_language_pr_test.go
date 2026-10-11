package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// languageUpdated is a dependency unit the update stage has handled: a
// pr_candidate with its checks and the files it produced.
func languageUpdated(key string) remediation.LanguageItem {
	content := []byte("a secret-looking lockfile body")
	return remediation.LanguageItem{
		Key: key, Workloads: []string{"compose/shop/web", "compose/shop/api"}, Manager: remediation.ManagerNpm,
		Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonUpdateVerified,
		Source: remediation.SourceRecord{Repository: "ex/app", BaseBranch: "main", Directory: ".", CommitSHA: strings.Repeat("a", 40),
			Files: []remediation.SourceFile{{Path: "package-lock.json", BlobSHA: strings.Repeat("b", 40)}}},
		Packages: []remediation.LanguagePackage{
			{Name: "minimist", Ecosystem: "node-pkg", Installed: "1.2.5", AdoptedVersion: "1.2.6", Action: remediation.ActionUpdate, Relation: remediation.RelationTransitive,
				CVEs: []remediation.CVERef{{VulnID: "CVE-2031-0100", KEV: true}}},
			{Name: "lodash", Ecosystem: "node-pkg", Installed: "4.17.15", AdoptedVersion: "4.17.21", Action: remediation.ActionUpdate, Relation: remediation.RelationDirect},
		},
		UpdateExecuted: true, PostUpdateCheckExecuted: true,
		Update: &remediation.LanguageUpdate{
			Steps:         []remediation.UpdateStep{{ID: "update", Op: "npm.update"}},
			Diff:          &remediation.DependencyDiff{Changed: []string{"node_modules/minimist"}},
			ManifestEdits: []remediation.ManifestEdit{{File: "package.json", Section: "dependencies", Name: "lodash", From: "^4.17.15", To: "^5.0.0", MajorChange: true}},
		},
		SourceCheck: &remediation.SourceCheck{CommitSHA: strings.Repeat("a", 40), Passed: true, Counts: [3]int{2, 0, 0},
			Resolved:   []remediation.SourceVuln{{Package: "minimist", Version: "1.2.5", VulnID: "CVE-2031-0100", Severity: scanner.SeverityHigh}},
			Conditions: scanner.ScanConditions{TrivyVersion: "0.71.2"}},
		Artifacts: []remediation.ArtifactFile{{Path: "package-lock.json", SHA256: strings.Repeat("c", 64), Size: int64(len(content)), Mode: "100644", Content: content}},
	}
}

func languageUnit(status remediation.PRUnitStatus, number int, reason remediation.Reason) remediation.PRUnit {
	u := remediation.PRUnit{
		Kind: "language", Key: "language|ex/app|main|package-lock.json", ItemKey: "deps:ex/app@main:.#npm", Repo: "ex/app", BaseBranch: "main",
		Path: "package-lock.json", Services: []string{"api", "web"}, Locations: []string{"."}, Workloads: []string{"compose/shop/api", "compose/shop/web"},
		Status: status, Reason: reason,
		Language: &remediation.PRLanguage{Manager: "npm", Root: ".", Packages: []remediation.PRLanguagePackage{
			{Name: "lodash", Ecosystem: "node-pkg", Relation: "direct", From: "4.17.15", To: "4.17.21"},
			{Name: "minimist", Ecosystem: "node-pkg", Relation: "transitive", From: "1.2.5", To: "1.2.6"},
		}, ManifestEdits: []remediation.LangEdit{{File: "package.json", Section: "dependencies", Name: "lodash", From: "^4.17.15", To: "^5.0.0", Major: true}}},
	}
	if number > 0 {
		u.Number, u.URL, u.State = number, "https://github.com/ex/app/pull/"+string(rune('0'+number)), remediation.PRStateOpen
		u.UpdateKey, u.AttemptKey, u.TargetKey = strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 64)
	}
	return u
}

func languagePlanOf(it remediation.LanguageItem, units ...remediation.PRUnit) *PlanInfo {
	p := planFixture()
	p.Items = nil
	p.LanguageItems = []remediation.LanguageItem{it}
	p.PullRequests = units
	return &PlanInfo{Plan: &p, Changed: true}
}

func TestPlanSection_LanguagePullRequestLines(t *testing.T) {
	r, changed, _ := planCycleFixture()
	cases := []struct {
		name   string
		status remediation.PRUnitStatus
		want   map[Language]string
	}{
		{"created", remediation.PRStatusCreated, map[Language]string{
			LanguageEN: "Opened <https://github.com/ex/app/pull/4|#4>: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 and 1 more — not merged yet — lockfile scan only; the image is not rebuilt or scanned — ⚠ includes a major version change",
			LanguageJA: "<https://github.com/ex/app/pull/4|#4> を作成: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 ほか1件 — 未マージ — lockfileのスキャンのみ。イメージは再ビルドもスキャンもしていない — ⚠ メジャーバージョンの変更を含む",
		}},
		{"open", remediation.PRStatusOpen, map[Language]string{
			LanguageEN: "Open <https://github.com/ex/app/pull/4|#4>: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 and 1 more — lockfile scan only",
			LanguageJA: "<https://github.com/ex/app/pull/4|#4> オープン中: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 ほか1件 — lockfileのスキャンのみ",
		}},
		{"merged", remediation.PRStatusMerged, map[Language]string{
			LanguageEN: "Merged <https://github.com/ex/app/pull/4|#4>: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 and 1 more — deployment not confirmed",
			LanguageJA: "<https://github.com/ex/app/pull/4|#4> マージ済み: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 ほか1件 — デプロイは未確認",
		}},
		{"closed", remediation.PRStatusSuppressed, map[Language]string{
			LanguageEN: "Closed without merging <https://github.com/ex/app/pull/4|#4>: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 and 1 more — not proposed again",
			LanguageJA: "<https://github.com/ex/app/pull/4|#4> 未マージでクローズ: api, web (package-lock.json) lodash 4.17.15 → 4.17.21 ほか1件 — 再提案しない",
		}},
	}
	for _, c := range cases {
		for lang, want := range c.want {
			t.Run(c.name+"/"+string(lang), func(t *testing.T) {
				info := languagePlanOf(languageUpdated("deps:ex/app@main:.#npm"), languageUnit(c.status, 4, ""))
				got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: info}, ChannelFooter{}, lang))
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in\n%s", want, got)
				}
				// The pull request speaks for the item: no second line for it.
				if strings.Contains(got, "pull request not opened") || strings.Contains(got, "Pull Requestは未作成") {
					t.Errorf("the item is listed besides its pull request:\n%s", got)
				}
			})
		}
	}
}

func TestPlanSection_LanguageCountsAndNotOpenedLines(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		name   string
		status remediation.PRUnitStatus
		reason remediation.Reason
		want   map[Language][]string
	}{
		{"deferred by a limit", remediation.PRStatusDeferred, remediation.ReasonPRLimit, map[Language][]string{
			LanguageEN: {"api, web (package-lock.json): lodash 4.17.15 → 4.17.21 and 1 more — update checked, pull request not opened: deferred (pr_limit)", "1 deferred"},
			LanguageJA: {"api, web (package-lock.json): lodash 4.17.15 → 4.17.21 ほか1件 — 更新は検査済み。Pull Requestは未作成: deferred (pr_limit)", "延期 1件"},
		}},
		{"manual", remediation.PRStatusManual, remediation.ReasonArtifactsUnusable, map[Language][]string{
			LanguageEN: {"update checked, pull request not opened: manual (artifacts_unusable)", "1 manual"},
			LanguageJA: {"Pull Requestは未作成: manual (artifacts_unusable)", "要判断 1件"},
		}},
		{"blocked", remediation.PRStatusWriteBlocked, remediation.ReasonRecordsUnverified, map[Language][]string{
			LanguageEN: {"update checked, pull request not opened: write_blocked (records_unverified)", "1 blocked or failed"},
			LanguageJA: {"Pull Requestは未作成: write_blocked (records_unverified)", "停止・失敗 1件"},
		}},
	} {
		for lang, want := range c.want {
			t.Run(c.name+"/"+string(lang), func(t *testing.T) {
				info := languagePlanOf(languageUpdated("deps:ex/app@main:.#npm"), languageUnit(c.status, 0, c.reason))
				got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: info}, ChannelFooter{}, lang))
				for _, w := range want {
					if !strings.Contains(got, w) {
						t.Errorf("missing %q in\n%s", w, got)
					}
				}
			})
		}
	}
}

func TestPlanSection_LanguageUpdateStageOutcomes(t *testing.T) {
	r, changed, _ := planCycleFixture()
	fromStage := func(c remediation.Category, reason remediation.Reason) remediation.LanguageItem {
		it := languageUpdated("deps:ex/app@main:.#npm")
		it.Category, it.Reason = c, reason
		return it
	}
	notRun := fromStage(remediation.CategoryManual, remediation.ReasonUnsupportedLockfile) // the planner's own manual item
	notRun.Update, notRun.SourceCheck = nil, nil
	for _, c := range []struct {
		name string
		item remediation.LanguageItem
		want map[Language]string
	}{
		{"manual", fromStage(remediation.CategoryManual, remediation.ReasonManifestEditRequired), map[Language]string{
			LanguageEN: "api, web (package-lock.json): dependency update needs a person — manifest_edit_required",
			LanguageJA: "api, web (package-lock.json): 依存パッケージの更新は要判断 — manifest_edit_required",
		}},
		{"failed", fromStage(remediation.CategoryFailed, remediation.ReasonUpdateJobFailed), map[Language]string{
			LanguageEN: "api, web (package-lock.json): dependency update failed — update_job_failed",
			LanguageJA: "api, web (package-lock.json): 依存パッケージの更新は失敗 — update_job_failed",
		}},
		{"deferred by the job limit", fromStage(remediation.CategoryDeferred, remediation.ReasonUpdateJobLimit), map[Language]string{
			LanguageEN: "api, web (package-lock.json): dependency update deferred — update_job_limit",
			LanguageJA: "api, web (package-lock.json): 依存パッケージの更新は延期 — update_job_limit",
		}},
		{"deferred without a work image", fromStage(remediation.CategoryDeferred, remediation.ReasonWorkImageUnavailable), map[Language]string{
			LanguageEN: "dependency update deferred — work_image_unavailable",
			LanguageJA: "依存パッケージの更新は延期 — work_image_unavailable",
		}},
		{"not comparable", fromStage(remediation.CategoryNotComparable, remediation.ReasonConditionsDiffer), map[Language]string{
			LanguageEN: "dependency update needs a person — ",
			LanguageJA: "依存パッケージの更新は要判断 — ",
		}},
	} {
		for lang, want := range c.want {
			t.Run(c.name+"/"+string(lang), func(t *testing.T) {
				got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: languagePlanOf(c.item)}, ChannelFooter{}, lang))
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in\n%s", want, got)
				}
			})
		}
	}
	// A manual item of the planner, from before any update ran, keeps being
	// counted only.
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: languagePlanOf(notRun)}, ChannelFooter{}, LanguageEN))
	if strings.Contains(got, "dependency update needs a person") {
		t.Errorf("a planner's manual item is listed as an update outcome:\n%s", got)
	}
}

func TestPlanSection_LanguagePullRequestEscapesExternalValues(t *testing.T) {
	r, changed, _ := planCycleFixture()
	it := languageUpdated("deps:ex/app@main:.#npm")
	it.Workloads = []string{"compose/shop/<!channel>"}
	u := languageUnit(remediation.PRStatusCreated, 4, "")
	u.Workloads = it.Workloads
	u.Language.Packages[0].Name = "<!here>"
	u.Language.Packages[0].To = "<!everyone>"
	u.Path = "<!channel>/package-lock.json"
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: languagePlanOf(it, u)}, ChannelFooter{}, LanguageEN))
	for _, bad := range []string{"<!channel>", "<!here>", "<!everyone>"} {
		if strings.Contains(got, bad) {
			t.Errorf("a mention %q got through:\n%s", bad, got)
		}
	}
}

func TestWebhook_LanguageUpdateResults(t *testing.T) {
	r, changed, _ := planCycleFixture()
	info := languagePlanOf(languageUpdated("deps:ex/app@main:.#npm"), languageUnit(remediation.PRStatusCreated, 4, ""))
	raw, err := json.Marshal(BuildWebhookPayloadWithPlan(r, &changed, info))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-looking") {
		t.Error("the content of an artifact is in the payload")
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	rem := payload["remediation"].(map[string]any)
	li := rem["language_items"].([]any)[0].(map[string]any)
	if li["category"] != "pr_candidate" || li["manager"] != "npm" || li["update_executed"] != true {
		t.Errorf("language item = %v", li)
	}
	upd := li["update"].(map[string]any)
	if steps := upd["steps"].([]any); len(steps) != 1 || steps[0].(map[string]any)["op"] != "npm.update" {
		t.Errorf("update steps = %v", upd["steps"])
	}
	edit := upd["manifest_edits"].([]any)[0].(map[string]any)
	if edit["file"] != "package.json" || edit["name"] != "lodash" || edit["from"] != "^4.17.15" || edit["to"] != "^5.0.0" || edit["major_change"] != true {
		t.Errorf("manifest edit = %v", edit)
	}
	if upd["diff"].(map[string]any)["changed"].([]any)[0] != "node_modules/minimist" {
		t.Errorf("diff = %v", upd["diff"])
	}
	sc := li["source_check"].(map[string]any)
	if sc["passed"] != true || len(sc["counts"].([]any)) != 3 || len(sc["resolved"].([]any)) != 1 {
		t.Errorf("source check = %v", sc)
	}
	art := li["artifacts"].([]any)[0].(map[string]any)
	if art["path"] != "package-lock.json" || art["sha256"] != strings.Repeat("c", 64) || art["size"] != float64(30) {
		t.Errorf("artifact = %v", art)
	}
	if _, has := art["Content"]; has {
		t.Error("artifact content key present")
	}
	pr := li["pull_request"].(map[string]any)
	if pr["status"] != "pr_created" || pr["number"] != float64(4) || pr["url"] != "https://github.com/ex/app/pull/4" || pr["state"] != "open" ||
		pr["update_key"] != strings.Repeat("a", 64) {
		t.Errorf("pull request = %v", pr)
	}

	unit := rem["pull_requests"].([]any)[0].(map[string]any)
	lang := unit["language"].(map[string]any)
	if unit["kind"] != "language" || unit["item_key"] != "deps:ex/app@main:.#npm" || unit["path"] != "package-lock.json" ||
		lang["manager"] != "npm" || lang["root"] != "." || len(lang["packages"].([]any)) != 2 {
		t.Errorf("unit = %v", unit)
	}
	first := lang["packages"].([]any)[0].(map[string]any)
	if first["name"] != "lodash" || first["from"] != "4.17.15" || first["to"] != "4.17.21" || first["relation"] != "direct" {
		t.Errorf("package = %v", first)
	}
}

// A plan the update stage has not handled keeps the payload it had: none of
// the new keys appears.
func TestWebhook_LanguageItemWithoutUpdateHasNoNewKeys(t *testing.T) {
	r, changed, _ := planCycleFixture()
	it := languageUpdated("deps:ex/app@main:.#npm")
	it.Category, it.Reason = remediation.CategoryDependencyUpdateCandidate, remediation.ReasonUpdateCandidateInSource
	it.Update, it.SourceCheck, it.Artifacts = nil, nil, nil
	it.UpdateExecuted, it.PostUpdateCheckExecuted = false, false
	raw, err := json.Marshal(BuildWebhookPayloadWithPlan(r, &changed, languagePlanOf(it)))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	li := payload["remediation"].(map[string]any)["language_items"].([]any)[0].(map[string]any)
	for _, k := range []string{"update", "source_check", "artifacts", "pull_request"} {
		if _, ok := li[k]; ok {
			t.Errorf("%s present on an item no update ran for", k)
		}
	}
	for _, k := range []string{"key", "category", "manager", "workloads", "source", "update_executed", "post_update_check_executed", "package_count", "packages"} {
		if _, ok := li[k]; !ok {
			t.Errorf("existing key %q is gone", k)
		}
	}
	if _, ok := payload["remediation"].(map[string]any)["pull_requests"]; ok {
		t.Error("pull_requests present without units")
	}
}

func TestPlanSection_LanguagePullRequestMajorNoteFromPackages(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		name  string
		major bool
	}{{"package major", true}, {"none", false}} {
		t.Run(c.name, func(t *testing.T) {
			u := languageUnit(remediation.PRStatusCreated, 4, "")
			u.Language.ManifestEdits = nil
			u.Language.Packages[0].Major = c.major
			got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: languagePlanOf(languageUpdated("deps:ex/app@main:.#npm"), u)}, ChannelFooter{}, LanguageEN))
			if has := strings.Contains(got, "includes a major version change"); has != c.major {
				t.Errorf("note present = %v, want %v\n%s", has, c.major, got)
			}
		})
	}
}
