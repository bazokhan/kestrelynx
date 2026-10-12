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
