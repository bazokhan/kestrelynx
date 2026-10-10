package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

func prUnit(status remediation.PRUnitStatus, number int, current, tag, path string) remediation.PRUnit {
	u := remediation.PRUnit{
		Key: "ex/deploy@main:" + path + "|" + current, Repo: "ex/deploy", BaseBranch: "main", Path: path,
		Services: []string{"web"}, Locations: []string{"services.web.image"}, Workloads: []string{"compose/shop/web"},
		Current: current, CandidateTag: tag, CandidateDigest: "sha256:ee", Status: status,
	}
	if number > 0 {
		u.Number = number
		u.URL = fmt.Sprintf("https://github.com/ex/deploy/pull/%d", number)
		u.State = remediation.PRStateOpen
		u.UpdateKey = strings.Repeat("a", 64)
		u.AttemptKey = strings.Repeat("b", 64)
	}
	return u
}

// pullRequestFixture is the image plan trimmed to its first two items with
// pull request units: the update candidate api:2.0.1 has a pull request
// opened in this cycle.
func pullRequestFixture() remediation.Plan {
	p := planFixture()
	p.Items = p.Items[:2]
	created := prUnit(remediation.PRStatusCreated, 12, "api:2.0.1", "2.0.4", "deploy/compose.yml")
	created.Services = []string{"api", "api-worker"}
	created.FixTargets = []remediation.FixTarget{{Location: "services.api.image", VulnID: "CVE-2031-0004", Package: remediation.PackageCoord{Name: "libc", Ecosystem: "debian"}}}
	open := prUnit(remediation.PRStatusOpen, 9, "worker:1.4.0", "1.4.2", "compose.yml")
	open.Replacing = []remediation.Replacement{{OldNumber: 5, State: remediation.ReplacementDone}}
	merged := prUnit(remediation.PRStatusMerged, 7, "cache:7.0.1", "7.0.5", "compose.yml")
	merged.State = remediation.PRStateMerged
	closed := prUnit(remediation.PRStatusSuppressed, 3, "queue:3.1.0", "3.1.2", "compose.yml")
	closed.State = remediation.PRStateClosed
	manual := prUnit(remediation.PRStatusManual, 0, "db:15.1", "15.1.4", "compose.yml")
	manual.Reason = remediation.ReasonComposeSetNotAdopted
	deferred := prUnit(remediation.PRStatusDeferred, 0, "proxy:1.2.3", "1.2.5", "compose.yml")
	deferred.Reason = remediation.ReasonPRLimit
	p.PullRequests = []remediation.PRUnit{created, open, merged, closed, manual, deferred}
	p.PRProblems = []remediation.PRStageProblem{{Code: remediation.PRProblemWriteBlocked, Repo: "ex/deploy", Reason: remediation.ReasonRecordsUnverified}}
	return p
}

func pullRequestInfo() *PlanInfo {
	p := pullRequestFixture()
	return &PlanInfo{Plan: &p, Changed: true}
}

func TestPlanSection_PullRequestGoldenBlocks(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		name string
		lang Language
		m    Message
	}{
		{"plan_pr_en_diff", LanguageEN, Message{Report: r, Diff: &changed, Plan: pullRequestInfo()}},
		{"plan_pr_ja_diff", LanguageJA, Message{Report: r, Diff: &changed, Plan: pullRequestInfo()}},
		{"plan_pr_en_full", LanguageEN, Message{Report: r, Plan: pullRequestInfo()}},
		{"plan_pr_ja_full", LanguageJA, Message{Report: r, Plan: pullRequestInfo()}},
	} {
		t.Run(c.name, func(t *testing.T) {
			msgs := buildChannelMessages(c.m, ChannelFooter{}, messagesFor(c.lang), defaultRenderLimits)
			checkBlockGolden(t, c.name, "txt", dumpMessages(msgs))
		})
	}
}

func TestPlanSection_PullRequestLines(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for lang, want := range map[Language][]string{
		LanguageEN: {
			"Fix plan* (candidates and pull requests — nothing is merged or deployed automatically)",
			"Pull requests: 1 created · 1 open · 1 merged · 1 closed without merging · 1 manual · 1 deferred",
			"• Opened <https://github.com/ex/deploy/pull/12|#12>: api 2.0.1 → 2.0.4 in deploy/compose.yml — not merged yet",
			"• Open <https://github.com/ex/deploy/pull/9|#9>: worker 1.4.0 → 1.4.2 in compose.yml",
			"• Merged <https://github.com/ex/deploy/pull/7|#7>: cache 7.0.1 → 7.0.5 in compose.yml — deployment not confirmed",
			"⚠️ Pull request writes are stopped: a repository, branch or pull request is not in the expected state",
		},
		LanguageJA: {
			"Pull Request: 作成 1件 · オープン 1件 · マージ済み 1件 · 未マージでクローズ 1件 · 要判断 1件 · 延期 1件",
			"• <https://github.com/ex/deploy/pull/12|#12> を作成: api 2.0.1 → 2.0.4 (deploy/compose.yml) — 未マージ",
			"⚠️ Pull Requestの作成を停止中: リポジトリ、ブランチ、Pull Requestのいずれかが想定の状態でない",
		},
	} {
		got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: pullRequestInfo()}, ChannelFooter{}, lang))
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
		// The pull request line speaks for the item; a created pull request
		// is not described as resolving anything, nor as an all-clear.
		if strings.Contains(got, "api:2.0.1 to 2.0.4") || strings.Contains(got, "api:2.0.1 を 2.0.4") {
			t.Errorf("%s: the update candidate is listed beside its pull request:\n%s", lang, got)
		}
		if strings.Contains(got, messagesFor(lang).AllClear[1:12]) {
			t.Errorf("%s: all-clear shown:\n%s", lang, got)
		}
	}
}

func TestPlanSection_PullRequestCapAndEscaping(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := pullRequestFixture()
	closed := p.PullRequests[3]
	closed.Current = "evil<!channel>:1"
	closed.URL = "https://github.com/ex/deploy/pull/3|<!here>"
	p.PullRequests[3] = closed
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	if strings.Contains(got, "<!channel>") || strings.Contains(got, "<!here>") {
		t.Errorf("a mention got through:\n%s", got)
	}
	// Four units have a pull request; three are listed, one is counted.
	if !strings.Contains(got, "(+1 more)") {
		t.Errorf("no count of the unlisted pull requests:\n%s", got)
	}
	if strings.Contains(got, "Closed without merging <") {
		t.Errorf("the fourth pull request was listed:\n%s", got)
	}
}

func TestPlanSection_NoPullRequestsKeepsTodaysSection(t *testing.T) {
	r, changed, _ := planCycleFixture()
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: planInfoFixture()}, ChannelFooter{}, LanguageEN))
	if !strings.Contains(got, "candidates only — nothing is changed automatically") || strings.Contains(got, "Pull request") {
		t.Errorf("section changed without pull requests:\n%s", got)
	}
	if !strings.Contains(got, "Updating api:2.0.1 to 2.0.4 resolves 1 finding(s)") {
		t.Errorf("update candidate line missing:\n%s", got)
	}
}

func TestWebhook_PullRequests(t *testing.T) {
	r, changed, _ := planCycleFixture()
	// Not enabled: none of the keys appears.
	off := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, planInfoFixture()))["remediation"].(map[string]any)
	for _, k := range []string{"pull_requests", "pull_request_summary", "operations", "problems"} {
		if _, ok := off[k]; ok {
			t.Errorf("%s present without pull requests", k)
		}
	}

	p := pullRequestFixture()
	at := time.Date(2026, 10, 9, 3, 1, 2, 0, time.UTC)
	p.PROperations = []remediation.OperationEvent{
		{Seq: 4, ID: "op-4", At: at, Phase: remediation.PhaseResult, Kind: remediation.OpCreatePull, Repo: "ex/deploy", AttemptKey: "k", Number: 12, Result: remediation.ResultOK},
		{Seq: 5, ID: "op-5", At: at, Phase: remediation.PhaseResult, Kind: remediation.OpClosePull, Repo: "ex/deploy", Number: 5, Result: remediation.ResultFailed, Error: "boom"},
	}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	sum := rem["pull_request_summary"].(map[string]any)
	if sum["pr_created"] != float64(1) || sum["pr_open"] != float64(1) || sum["manual"] != float64(1) || sum["deferred"] != float64(1) {
		t.Errorf("pull_request_summary = %v", sum)
	}
	units := rem["pull_requests"].([]any)
	if len(units) != 6 {
		t.Fatalf("pull_requests = %d", len(units))
	}
	u := units[0].(map[string]any)
	if u["repo"] != "ex/deploy" || u["number"] != float64(12) || u["url"] != "https://github.com/ex/deploy/pull/12" ||
		u["state"] != "open" || u["status"] != "pr_created" || u["path"] != "deploy/compose.yml" ||
		u["current_ref"] != "api:2.0.1" || u["candidate_tag"] != "2.0.4" ||
		u["update_key"] != strings.Repeat("a", 64) || u["attempt_key"] != strings.Repeat("b", 64) {
		t.Errorf("created unit = %v", u)
	}
	if svc := u["services"].([]any); len(svc) != 2 || svc[0] != "api" {
		t.Errorf("services = %v", svc)
	}
	ft := u["fix_targets"].([]any)[0].(map[string]any)
	if u["fix_target_count"] != float64(1) || ft["location"] != "services.api.image" || ft["vuln_id"] != "CVE-2031-0004" || ft["package"] != "libc" {
		t.Errorf("fix_targets = %v", u["fix_targets"])
	}
	if rp := units[1].(map[string]any)["replacing"].([]any)[0].(map[string]any); rp["old_number"] != float64(5) || rp["state"] != "done" {
		t.Errorf("replacing = %v", rp)
	}
	if m := units[4].(map[string]any); m["status"] != "manual" || m["reason"] != "compose_set_not_adopted" {
		t.Errorf("manual unit = %v", m)
	}
	ops := rem["operations"].([]any)
	if len(ops) != 2 {
		t.Fatalf("operations = %v", ops)
	}
	op := ops[1].(map[string]any)
	if op["seq"] != float64(5) || op["id"] != "op-5" || op["at"] != "2026-10-09T03:01:02Z" || op["kind"] != "close_pull" ||
		op["repo"] != "ex/deploy" || op["number"] != float64(5) || op["result"] != "failed" || op["error"] != "boom" {
		t.Errorf("operation = %v", op)
	}
	pr := rem["problems"].([]any)[0].(map[string]any)
	if pr["code"] != "write_blocked" || pr["repo"] != "ex/deploy" || pr["reason"] != "records_unverified" {
		t.Errorf("problem = %v", pr)
	}
	if _, err := json.Marshal(rem); err != nil {
		t.Error(err)
	}
}

func TestWebhook_FixTargetsAreCapped(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := pullRequestFixture()
	for i := 0; i < maxWebhookFixTargets+5; i++ {
		p.PullRequests[0].FixTargets = append(p.PullRequests[0].FixTargets, remediation.FixTarget{Location: "services.api.image", VulnID: fmt.Sprintf("CVE-2031-%04d", i)})
	}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p}))["remediation"].(map[string]any)
	u := rem["pull_requests"].([]any)[0].(map[string]any)
	if len(u["fix_targets"].([]any)) != maxWebhookFixTargets || u["fix_targets_truncated"] != true || u["fix_target_count"] != float64(maxWebhookFixTargets+6) {
		t.Errorf("fix targets = %d, truncated = %v, count = %v", len(u["fix_targets"].([]any)), u["fix_targets_truncated"], u["fix_target_count"])
	}
}

func operationsOnlyInfo() *PlanInfo {
	p := planFixture()
	p.Items = nil
	at := time.Date(2026, 10, 9, 3, 1, 2, 0, time.UTC)
	ev := func(seq int64, phase remediation.OperationPhase, kind remediation.OperationKind, number int, res remediation.OperationResult, errText string) remediation.OperationEvent {
		return remediation.OperationEvent{Seq: seq, ID: fmt.Sprintf("op-%d", seq), At: at, Phase: phase, Kind: kind, Repo: "ex/deploy", Number: number, Result: res, Error: errText}
	}
	p.PROperations = []remediation.OperationEvent{
		ev(1, remediation.PhaseIntent, remediation.OpCreatePull, 0, "", ""),
		ev(2, remediation.PhaseResult, remediation.OpCreatePull, 12, remediation.ResultOK, ""),
		ev(3, remediation.PhaseResult, remediation.OpClosePull, 5, remediation.ResultFailed, "403 forbidden <!channel>"),
		ev(4, remediation.PhaseSettled, remediation.OpCreateComment, 5, remediation.ResultUnknown, ""),
		ev(5, remediation.PhaseResult, remediation.OpCreateRef, 0, remediation.ResultOK, ""),
	}
	return &PlanInfo{Plan: &p}
}

func TestPlanSection_OperationsOnlyAreShown(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for lang, want := range map[Language][]string{
		LanguageEN: {"Pull request operations:", "• open pull request ex/deploy#12: ok", "• close pull request ex/deploy#5: failed — 403 forbidden &lt;!channel&gt;", "• comment ex/deploy#5: outcome unknown", "(+1 more)"},
		LanguageJA: {"Pull Requestの操作:", "• Pull Request作成 ex/deploy#12: 成功", "• Pull Requestのクローズ ex/deploy#5: 失敗 — 403 forbidden &lt;!channel&gt;", "• コメント ex/deploy#5: 結果不明", "(ほか +1件)"},
	} {
		for name, m := range map[string]Message{
			"diff": {Report: r, Diff: &changed, Plan: operationsOnlyInfo()},
			"full": {Report: r, Plan: operationsOnlyInfo()},
		} {
			got := allBlocksText(BuildChannelMessages(m, ChannelFooter{}, lang))
			for _, w := range want {
				if !strings.Contains(got, w) {
					t.Errorf("%s %s: missing %q in\n%s", lang, name, w, got)
				}
			}
			if strings.Contains(got, "<!channel>") || strings.Contains(got, "intent") {
				t.Errorf("%s %s: unescaped or intent shown:\n%s", lang, name, got)
			}
		}
	}
	// Without a changed plan the section is still there.
	p := operationsOnlyInfo()
	p.Plan.Items = nil
	if !p.visible() {
		t.Error("a plan with only operation events hides the section")
	}
	intentOnly := &PlanInfo{Plan: &remediation.Plan{PROperations: []remediation.OperationEvent{{Seq: 1, ID: "a", Phase: remediation.PhaseIntent}}}}
	if intentOnly.visible() {
		t.Error("an intent alone opens the section")
	}
}

func TestPlanSection_OperationsGoldenBlocks(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		name string
		lang Language
		m    Message
	}{
		{"plan_ops_en_diff", LanguageEN, Message{Report: r, Diff: &changed, Plan: operationsOnlyInfo()}},
		{"plan_ops_ja_diff", LanguageJA, Message{Report: r, Diff: &changed, Plan: operationsOnlyInfo()}},
		{"plan_ops_en_full", LanguageEN, Message{Report: r, Plan: operationsOnlyInfo()}},
		{"plan_ops_ja_full", LanguageJA, Message{Report: r, Plan: operationsOnlyInfo()}},
	} {
		t.Run(c.name, func(t *testing.T) {
			msgs := buildChannelMessages(c.m, ChannelFooter{}, messagesFor(c.lang), defaultRenderLimits)
			checkBlockGolden(t, c.name, "txt", dumpMessages(msgs))
		})
	}
}
