package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func planTarget(id string, kev bool) remediation.Target {
	return remediation.Target{VulnID: id, Package: remediation.PackageCoord{Name: "libc"}, FixedVers: []string{"2"}, KEV: kev}
}

// planFixture is a plan with an item in every category; the pull-again item
// resolves three findings, two of them KEV-listed.
func planFixture() remediation.Plan {
	at := time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)
	adopt := func(n int) *remediation.Decision {
		return &remediation.Decision{Kind: remediation.DecisionAdopt, Propose: true, Targets: n, Resolved: n}
	}
	verdicts := func(n int) []remediation.VulnVerdict {
		var vs []remediation.VulnVerdict
		for i := 0; i < n; i++ {
			vs = append(vs, remediation.VulnVerdict{
				VulnID: fmt.Sprintf("CVE-2031-%04d", i), Package: remediation.PackageCoord{Name: "libc"},
				Severity: scanner.SeverityHigh, Outcome: remediation.OutcomeResolved,
				Disposition: remediation.DispositionVersionChanged,
			})
		}
		return vs
	}
	return remediation.Plan{
		Version:     remediation.PlanVersion,
		GeneratedAt: at,
		Conditions: scanner.ScanConditions{
			TrivyVersion:    "0.71.2",
			VulnerabilityDB: scanner.DBInfo{Version: 2, UpdatedAt: at}, JavaDB: scanner.DBInfo{Version: 1, UpdatedAt: at},
			Severities: []string{"CRITICAL", "HIGH"}, AnalysisSettings: "image;test",
			VulnerabilityDBSHA: "v", JavaDBSHA: "j", TrivySHA: "t",
		},
		Limits: remediation.Limits{MaxCandidateScans: 10, MaxBaselineRescans: 10, MaxTagPages: 20},
		Usage:  remediation.Usage{CandidateScans: 2, RegistryRequests: 7},
		Items: []remediation.Item{
			{
				Key: "web:latest|config:sha256:aa", Kind: remediation.TagFloating, Priority: remediation.PriorityActNow,
				Category: remediation.CategoryPullAgain, Reason: remediation.ReasonAdopted,
				Services: []remediation.ServiceRef{{Project: "shop", Service: "web", Container: "shop-web-1"}},
				Current:  remediation.ImageState{Ref: "web:latest", Tag: "latest", Entity: "config:sha256:aa", DigestKindUnverified: true},
				Candidate: &remediation.ImageState{Ref: "web:latest", Tag: "latest",
					ConfigDigest: "sha256:cc", ManifestDigest: "sha256:dd", TopDigest: "sha256:ee"},
				BaselineScan: "s1",
				Targets:      []remediation.Target{planTarget("CVE-2031-0000", false), planTarget("CVE-2031-0001", true), planTarget("CVE-2031-0002", true), planTarget("CVE-2031-0009", true)},
				Comparison: &remediation.VerificationResult{Comparable: true, Scope: "HIGH,CRITICAL", Verdicts: append(verdicts(3), remediation.VulnVerdict{
					VulnID: "CVE-2031-0009", Package: remediation.PackageCoord{Name: "libc"}, Severity: scanner.SeverityHigh, Outcome: remediation.OutcomeRemaining})},
				Decision: &remediation.Decision{Kind: remediation.DecisionAdoptPartial, Propose: true, Targets: 4, Resolved: 3, Remaining: 1},
			},
			{
				Key: "api:2.0.1|config:sha256:bb", Kind: remediation.TagPinned, Priority: remediation.PriorityWatch,
				Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonAdopted,
				Current:    remediation.ImageState{Ref: "api:2.0.1", Tag: "2.0.1", Entity: "config:sha256:bb"},
				Candidate:  &remediation.ImageState{Ref: "api:2.0.4", Tag: "2.0.4", ConfigDigest: "sha256:c2"},
				Targets:    []remediation.Target{planTarget("CVE-2031-0004", false)},
				Comparison: &remediation.VerificationResult{Comparable: true, Verdicts: verdicts(1)},
				Decision:   adopt(1),
			},
			{Key: "db:15.1|x", Category: remediation.CategoryManual, Reason: remediation.ReasonPartialImprovement, Current: remediation.ImageState{Ref: "db:15.1"}},
			{Key: "cache:7.0.1|x", Category: remediation.CategoryNotComparable, Reason: remediation.ReasonAuthRequired, Current: remediation.ImageState{Ref: "cache:7.0.1"}},
			{Key: "q:1.2.3|x", Category: remediation.CategoryDeferred, Reason: remediation.ReasonCandidateScanLimit, Current: remediation.ImageState{Ref: "q:1.2.3"}},
			{Key: "r:1.2.3|x", Category: remediation.CategoryNoCandidate, Reason: remediation.ReasonNoNewerTag, Current: remediation.ImageState{Ref: "r:1.2.3"}},
			{Key: "s@sha256|x", Category: remediation.CategoryExcluded, Reason: "digest_pinned", Current: remediation.ImageState{Ref: "s@sha256:ff"}},
			{Key: "t:1.2.3|x", Category: remediation.CategoryFailed, Reason: remediation.ReasonRegistryError, Detail: "boom", Current: remediation.ImageState{Ref: "t:1.2.3"}},
		},
		Scans: []remediation.ScanExecution{{ID: "s1", Role: remediation.RoleBaseline, Ref: "web:latest", DB: remediation.DBSupplied}},
	}
}

func planCycleFixture() (analyze.Report, state.Diff, state.Diff) {
	r, changed, unchanged, _ := goldenCycle(goldenModes()[0], false)
	return r, changed, unchanged
}

func planInfoFixture() *PlanInfo {
	p := planFixture()
	return &PlanInfo{Plan: &p, Changed: true}
}

func TestPlanSection_Slack(t *testing.T) {
	r, changed, unchanged := planCycleFixture()
	cases := []struct {
		name string
		m    Message
	}{
		{"full", Message{Report: r, Plan: planInfoFixture()}},
		{"diff", Message{Report: r, Diff: &changed, Plan: planInfoFixture()}},
		{"diff_unchanged", Message{Report: r, Diff: &unchanged, Plan: planInfoFixture()}},
		{"weekly", Message{Report: r, Diff: &changed, FullReport: true, Plan: planInfoFixture()}},
	}
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		for _, c := range cases {
			t.Run(string(lang)+"_"+c.name, func(t *testing.T) {
				got := allBlocksText(BuildChannelMessages(c.m, ChannelFooter{}, lang))
				msg := messagesFor(lang)
				for _, want := range []string{
					strings.TrimSpace(strings.Trim(msg.PlanHeading, "\n")),
					fmt.Sprintf(msg.PlanSegPullAgain, 1),
					fmt.Sprintf(msg.PlanSegUpdate, 1),
					fmt.Sprintf(msg.PlanSegManual, 1),
					fmt.Sprintf(msg.PlanSegNotComparable, 1),
					fmt.Sprintf(msg.PlanSegDeferred, 1),
					fmt.Sprintf(msg.PlanSegNoCandidate, 1),
					fmt.Sprintf(msg.PlanSegExcluded, 1),
					fmt.Sprintf(msg.PlanSegFailed, 1),
					fmt.Sprintf(msg.PlanPullAgainPartialLine, "web:latest", 3, 4, fmt.Sprintf(msg.PlanClauseWrap, fmt.Sprintf(msg.PlanRemainClause, 1))) + fmt.Sprintf(msg.PlanKEVSuffix, 2),
					fmt.Sprintf(msg.PlanUpdateLine, "api:2.0.1", "2.0.4", 1),
				} {
					if !strings.Contains(got, want) {
						t.Errorf("missing %q in\n%s", want, got)
					}
				}
				// Items of the other categories are counted, not listed.
				for _, not := range []string{"db:15.1", "cache:7.0.1", "boom"} {
					if strings.Contains(got, not) {
						t.Errorf("%q should not be listed in\n%s", not, got)
					}
				}
			})
		}
	}
}

func TestPlanSection_GoldenBlocks(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		name string
		lang Language
		m    Message
	}{
		{"plan_en_diff", LanguageEN, Message{Report: r, Diff: &changed, Plan: planInfoFixture()}},
		{"plan_ja_diff", LanguageJA, Message{Report: r, Diff: &changed, Plan: planInfoFixture()}},
		{"plan_en_full", LanguageEN, Message{Report: r, Plan: planInfoFixture()}},
		{"plan_ja_full", LanguageJA, Message{Report: r, Plan: planInfoFixture()}},
	} {
		t.Run(c.name, func(t *testing.T) {
			msgs := buildChannelMessages(c.m, ChannelFooter{}, messagesFor(c.lang), defaultRenderLimits)
			checkBlockGolden(t, c.name, "txt", dumpMessages(msgs))
		})
	}
}

func TestPlanSection_OffLeavesOutputUnchanged(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		without := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed}, ChannelFooter{}, lang))
		with := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &remediation.Plan{}}}, ChannelFooter{}, lang))
		// A produced plan with no items and no change adds nothing.
		if without != with {
			t.Errorf("%s: an empty, unchanged plan altered the message", lang)
		}
		if strings.Contains(without, "🔧") {
			t.Errorf("%s: plan section present without a plan", lang)
		}
	}
}

func TestPlanSection_BecameEmptyAndNotes(t *testing.T) {
	r, changed, _ := planCycleFixture()
	empty := remediation.Plan{}
	for name, tc := range map[string]struct {
		info *PlanInfo
		want func(messages) string
	}{
		"became empty":   {&PlanInfo{Plan: &empty, Changed: true}, func(m messages) string { return m.PlanNothing }},
		"unavailable db": {&PlanInfo{Unavailable: PlanDatabasesNotPrepared}, func(m messages) string { return strings.Trim(m.PlanUnavailableDB, "\n") }},
		"unavailable":    {&PlanInfo{Unavailable: PlanNotBuilt}, func(m messages) string { return strings.Trim(m.PlanUnavailableOther, "\n") }},
		"not saved":      {&PlanInfo{Plan: &empty, NotSaved: true}, func(m messages) string { return m.PlanNotSaved }},
	} {
		for _, lang := range []Language{LanguageEN, LanguageJA} {
			got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: tc.info}, ChannelFooter{}, lang))
			if want := tc.want(messagesFor(lang)); !strings.Contains(got, want) {
				t.Errorf("%s/%s: missing %q in\n%s", name, lang, want, got)
			}
		}
	}
}

func TestPlanSection_EscapesExternalValues(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := planFixture()
	p.Items = p.Items[:2]
	p.Items[0].Current.Ref = "evil<@here>&:latest"
	p.Items[1].Candidate.Tag = "<!channel>"
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	for _, bad := range []string{"<@here>", "<!channel>"} {
		if strings.Contains(got, bad) {
			t.Errorf("unescaped %q in\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "evil&lt;@here&gt;&amp;:latest") || !strings.Contains(got, "&lt;!channel&gt;") {
		t.Errorf("escaped values not found in\n%s", got)
	}
}

func TestPlanSection_ListsOnlyTopItems(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := planFixture()
	p.Items = nil
	for i := 0; i < 5; i++ {
		it := planFixture().Items[1]
		it.Current.Ref = fmt.Sprintf("img%d:1.0.0", i)
		p.Items = append(p.Items, it)
	}
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	if n := strings.Count(got, "• Updating "); n != slackTopItems {
		t.Errorf("listed %d items, want %d", n, slackTopItems)
	}
	if !strings.Contains(got, "(+2 more)") {
		t.Errorf("missing the remainder count in\n%s", got)
	}
}

func TestPlanSection_RespectsMessageLimits(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		msgs := buildChannelMessages(Message{Report: r, Diff: &changed, Plan: planInfoFixture()}, ChannelFooter{}, messagesFor(lang), testSplitLimits)
		if len(msgs) < 2 {
			t.Fatalf("%s: expected the small limits to split the message, got %d", lang, len(msgs))
		}
		joined := ""
		for _, m := range msgs {
			if len(m.Blocks) > testSplitLimits.MaxBlocks {
				t.Errorf("%s: a message has %d blocks, limit %d", lang, len(m.Blocks), testSplitLimits.MaxBlocks)
			}
			for _, b := range m.Blocks {
				if utf16Len(b.Text) > testSplitLimits.MaxTextUnits {
					t.Errorf("%s: a block has %d text units, limit %d", lang, utf16Len(b.Text), testSplitLimits.MaxTextUnits)
				}
			}
			joined += allBlocksText([]SlackMessage{m})
		}
		if !strings.Contains(joined, messagesFor(lang).PlanSegPullAgain[:0]+fmt.Sprintf(messagesFor(lang).PlanSegPullAgain, 1)) {
			t.Errorf("%s: plan counts missing from the split messages", lang)
		}
	}
}

// --- webhook ---

func webhookJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWebhook_NoPlanIsByteIdentical(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, d := range []*state.Diff{nil, &changed} {
		a, err := json.Marshal(BuildWebhookPayload(r, d))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(BuildWebhookPayloadWithPlan(r, d, nil))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Error("a nil plan changed the payload")
		}
		if strings.Contains(string(a), "remediation") {
			t.Error("payload without a plan mentions remediation")
		}
	}
}

func TestWebhook_WithPlanKeepsExistingKeys(t *testing.T) {
	r, changed, _ := planCycleFixture()
	base := webhookJSON(t, BuildWebhookPayload(r, &changed))
	with := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, planInfoFixture()))
	rem, ok := with["remediation"].(map[string]any)
	if !ok {
		t.Fatalf("remediation missing: %v", with)
	}
	delete(with, "remediation")
	a, _ := json.Marshal(base)
	b, _ := json.Marshal(with)
	if string(a) != string(b) {
		t.Error("the plan altered existing payload keys")
	}
	if rem["status"] != "ok" || rem["schema_version"] != float64(1) {
		t.Errorf("status/schema_version = %v/%v", rem["status"], rem["schema_version"])
	}
	summary := rem["summary"].(map[string]any)
	for _, c := range planSlackOrder {
		if summary[string(c)] != float64(1) {
			t.Errorf("summary[%s] = %v, want 1", c, summary[string(c)])
		}
	}
	if conds := rem["conditions"].(map[string]any); conds["trivy_version"] != "0.71.2" || conds["vulnerability_db_sha256"] != "v" {
		t.Errorf("conditions = %v", conds)
	}
	items := rem["items"].([]any)
	if len(items) != 8 {
		t.Fatalf("items = %d, want 8", len(items))
	}
	first := items[0].(map[string]any)
	if first["category"] != "pull_again" || first["reason"] != "adopted" || first["kev_targets"] != float64(3) {
		t.Errorf("first item = %v", first)
	}
	if cur := first["current"].(map[string]any); cur["ref"] != "web:latest" || cur["content"] != "config:sha256:aa" || cur["digest_kind_unverified"] != true {
		t.Errorf("current = %v", cur)
	}
	if cand := first["candidate"].(map[string]any); cand["config_digest"] != "sha256:cc" || cand["manifest_digest"] != "sha256:dd" {
		t.Errorf("candidate = %v", cand)
	}
	cmp := first["comparison"].(map[string]any)
	if cmp["resolved"] != float64(3) || cmp["remaining"] != float64(1) || cmp["targets"] != float64(4) || cmp["decision"] != "adopt_partial" || len(cmp["verdicts"].([]any)) != 4 {
		t.Errorf("comparison = %v", cmp)
	}
	if _, truncated := cmp["verdicts_truncated"]; truncated {
		t.Error("3 verdicts marked truncated")
	}
	if svc := first["services"].([]any)[0].(map[string]any); svc["service"] != "web" {
		t.Errorf("services = %v", first["services"])
	}
	if scans := first["scans"].([]any); len(scans) != 1 {
		t.Errorf("scans = %v", scans)
	}
}

func TestWebhook_VerdictListsAreCapped(t *testing.T) {
	r, _, _ := planCycleFixture()
	p := planFixture()
	var vs []remediation.VulnVerdict
	for i := 0; i < maxWebhookVerdicts+7; i++ {
		vs = append(vs, remediation.VulnVerdict{VulnID: fmt.Sprintf("CVE-%d", i), Outcome: remediation.OutcomeIntroduced})
	}
	p.Items[0].Comparison = &remediation.VerificationResult{Comparable: true, Verdicts: vs, Introduced: vs[:3]}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, nil, &PlanInfo{Plan: &p}))["remediation"].(map[string]any)
	cmp := rem["items"].([]any)[0].(map[string]any)["comparison"].(map[string]any)
	if n := len(cmp["verdicts"].([]any)); n != maxWebhookVerdicts {
		t.Errorf("verdicts = %d, want %d", n, maxWebhookVerdicts)
	}
	if cmp["verdicts_truncated"] != true {
		t.Error("verdicts_truncated not set")
	}
	if _, ok := cmp["introduced_findings_truncated"]; ok {
		t.Error("3 introduced findings marked truncated")
	}
}

func TestWebhook_Unavailable(t *testing.T) {
	r, _, _ := planCycleFixture()
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, nil, &PlanInfo{Unavailable: PlanDatabasesNotPrepared}))["remediation"].(map[string]any)
	if rem["status"] != "unavailable" || rem["unavailable_reason"] != "databases_not_prepared" {
		t.Errorf("remediation = %v", rem)
	}
	if items, ok := rem["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("items = %v, want an empty list", rem["items"])
	}
}

func TestPlanSection_PartialWording(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := planFixture()
	p.Items = []remediation.Item{
		{Key: "pg", Category: remediation.CategoryPullAgain, Reason: remediation.ReasonAdopted, Current: remediation.ImageState{Ref: "postgres:16"},
			Decision: &remediation.Decision{Kind: remediation.DecisionAdoptPartial, Propose: true, Targets: 66, Resolved: 44, Remaining: 22}},
		{Key: "ng", Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonAdopted, Current: remediation.ImageState{Ref: "nginx:1.25.3"},
			Candidate: &remediation.ImageState{Ref: "nginx:1.25.5", Tag: "1.25.5"},
			Decision:  &remediation.Decision{Kind: remediation.DecisionAdoptPartial, Propose: true, Targets: 120, Resolved: 5, Remaining: 115}},
	}
	for lang, wants := range map[Language][]string{
		LanguageEN: {"Re-pulling postgres:16 resolves 44 of 66 findings (22 remain)", "Updating nginx:1.25.3 to 1.25.5 resolves 5 of 120 findings (115 remain)"},
		LanguageJA: {"postgres:16 を再pullすると 66件中 44件の所見が解消(22件は残る)", "nginx:1.25.3 を 1.25.5 に更新すると 120件中 5件の所見が解消(115件は残る)"},
	} {
		got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, lang))
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
		if !strings.Contains(got, strings.TrimSpace(strings.Trim(messagesFor(lang).PlanHeading, "\n"))) {
			t.Errorf("%s: the header note is gone", lang)
		}
	}
}

func TestPlanSection_UndetectedShownSeparately(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := planFixture()
	p.Items = []remediation.Item{{
		Key: "pg", Category: remediation.CategoryPullAgain, Reason: remediation.ReasonAdopted, Current: remediation.ImageState{Ref: "postgres:16"},
		Decision: &remediation.Decision{Kind: remediation.DecisionAdoptPartial, Propose: true, Targets: 67, Resolved: 44, Remaining: 22, Undetected: 1},
	}, {
		Key: "ng", Category: remediation.CategoryPullAgain, Reason: remediation.ReasonAdopted, Current: remediation.ImageState{Ref: "nginx:latest"},
		Decision: &remediation.Decision{Kind: remediation.DecisionAdoptPartial, Propose: true, Targets: 5, Resolved: 4, Undetected: 1},
	}}
	for lang, wants := range map[Language][]string{
		LanguageEN: {
			"Re-pulling postgres:16 resolves 44 of 67 findings (22 remain, 1 not detected on the running image)",
			"Re-pulling nginx:latest resolves 4 of 5 findings (1 not detected on the running image)",
		},
		LanguageJA: {
			"postgres:16 を再pullすると 67件中 44件の所見が解消(22件は残る、1件は稼働中のイメージで未検出)",
			"nginx:latest を再pullすると 5件中 4件の所見が解消(1件は稼働中のイメージで未検出)",
		},
	} {
		got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, lang))
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
	}
}

func TestPlanSection_IntroducedKEVLine(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := planFixture()
	p.Items = []remediation.Item{
		{Key: "a", Kind: remediation.TagFloating, Category: remediation.CategoryPullAgain, Reason: remediation.ReasonAdopted, Current: remediation.ImageState{Ref: "ok:1"},
			Decision: &remediation.Decision{Kind: remediation.DecisionAdopt, Propose: true, Targets: 2, Resolved: 2}},
		{Key: "b", Kind: remediation.TagPinned, Category: remediation.CategoryManual, Reason: remediation.ReasonIntroducedKEV, Current: remediation.ImageState{Ref: "nginx:1.25.3"},
			Candidate: &remediation.ImageState{Ref: "nginx:1.25.5", Tag: "1.25.5"}},
		{Key: "c", Kind: remediation.TagFloating, Category: remediation.CategoryManual, Reason: remediation.ReasonIntroducedKEV, Current: remediation.ImageState{Ref: "redis:latest"}},
		{Key: "d", Kind: remediation.TagFloating, Category: remediation.CategoryManual, Reason: remediation.ReasonIntroducedFindings, Current: remediation.ImageState{Ref: "plain:1"}},
	}
	for lang, wants := range map[Language][]string{
		LanguageEN: {"Updating nginx:1.25.3 to 1.25.5 introduces a KEV-listed vulnerability — manual review", "Re-pulling redis:latest introduces a KEV-listed vulnerability — manual review"},
		LanguageJA: {"nginx:1.25.3 を 1.25.5 に更新するとKEV掲載の脆弱性が新たに入る — 要確認", "redis:latest を再pullするとKEV掲載の脆弱性が新たに入る — 要確認"},
	} {
		got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, lang))
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
		if strings.Contains(got, "plain:1") {
			t.Errorf("%s: an item introducing non-KEV findings must not get the KEV line", lang)
		}
		// Warnings come before the adopted items.
		if strings.Index(got, "nginx:1.25.3") > strings.Index(got, "ok:1") {
			t.Errorf("%s: the KEV warning should be listed first", lang)
		}
	}
}
