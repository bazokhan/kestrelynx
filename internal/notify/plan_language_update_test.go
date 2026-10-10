package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// A dependency unit whose update was run and checked is a pr_candidate. The
// existing outputs take it without change: the webhook counts it and reports
// the adopted version but not the content of the files it would write, and
// the Slack section counts it as an update candidate.
func TestPlan_LanguagePRCandidate(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := &p.LanguageItems[0]
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified
	li.UpdateExecuted, li.PostUpdateCheckExecuted = true, true
	li.Packages[1].AdoptedVersion = "4.17.21"
	secret := "THE-LOCKFILE-CONTENT"
	li.Artifacts = []remediation.ArtifactFile{{Path: "backend/package-lock.json", SHA256: strings.Repeat("d", 64), Size: 20, Content: []byte(secret)}}

	info := &PlanInfo{Plan: &p, Changed: true}
	payload := BuildWebhookPayloadWithPlan(r, &changed, info)
	rem := webhookJSON(t, payload)["remediation"].(map[string]any)
	sum := rem["language_summary"].(map[string]any)
	if sum["pr_candidate"] != float64(1) || sum["dependency_update_candidate"] != float64(0) {
		t.Errorf("language_summary = %v", sum)
	}
	first := rem["language_items"].([]any)[0].(map[string]any)
	if first["category"] != "pr_candidate" || first["update_executed"] != true || first["post_update_check_executed"] != true {
		t.Errorf("first = %v", first)
	}
	lodash := first["packages"].([]any)[1].(map[string]any)
	if lodash["adopted_version"] != "4.17.21" {
		t.Errorf("lodash = %v", lodash)
	}
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: info}, ChannelFooter{}, lang))
		if strings.Contains(got, secret) || strings.Contains(got, "package-lock.json:") {
			t.Errorf("%s: file content in the message:\n%s", lang, got)
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("file content in the webhook")
	}
}
