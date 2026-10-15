package notify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// slackPlanText is the fix plan message of info as one text, shown as changed.
func slackPlanText(r analyze.Report, info *PlanInfo, lang Language) string {
	info.SlackChanged = true
	return allBlocksText(BuildPlanMessages(Message{Report: r, Plan: info}, lang))
}

func planImage(ref, project, service string) remediation.Item {
	return remediation.Item{
		Key: ref + "|x", Category: remediation.CategoryNoCandidate, Reason: remediation.ReasonNoNewerTag,
		Services: []remediation.ServiceRef{{Project: project, Service: service, Container: project + "-" + service + "-1"}},
		Current:  remediation.ImageState{Ref: ref},
	}
}

// slackPlanFixture is a plan with pull requests of the three kinds on two
// running images, one more image that has a pull request in each state, and
// proposals without a pull request.
func slackPlanFixture() remediation.Plan {
	p := planFixture()
	p.Items = nil

	backend := planImage("ghcr.io/yyac-project/regfis-backend:latest", "regfis", "backend")
	elastic := planImage("regfis-infra-elasticsearch", "regfis", "elasticsearch")
	web := planImage("nginx:1.25.3", "shop", "web")
	web.Category, web.Reason = remediation.CategoryPRCandidate, remediation.ReasonAdopted
	web.Candidate = &remediation.ImageState{Ref: "nginx:1.25.4", Tag: "1.25.4"}
	cache := planImage("cache:7.0.1", "shop", "cache")
	cache.Category, cache.Candidate = remediation.CategoryPRCandidate, &remediation.ImageState{Ref: "cache:7.0.5", Tag: "7.0.5"}
	queue := planImage("queue:3.1.0", "shop", "queue")
	queue.Category, queue.Candidate = remediation.CategoryPRCandidate, &remediation.ImageState{Ref: "queue:3.1.2", Tag: "3.1.2"}
	api := planImage("api:2.0.1", "shop", "api")
	api.Category, api.Candidate = remediation.CategoryPRCandidate, &remediation.ImageState{Ref: "api:2.0.4", Tag: "2.0.4"}
	db := planImage("db:15.1", "shop", "db")
	db.Category, db.Reason = remediation.CategoryManual, remediation.ReasonPartialImprovement
	pull := planFixture().Items[0]
	pull.Services = []remediation.ServiceRef{{Project: "shop", Service: "edge"}}
	p.Items = []remediation.Item{backend, elastic, web, cache, queue, api, db, pull}

	composeUnit := func(status remediation.PRUnitStatus, number int, current, tag string) remediation.PRUnit {
		u := prUnit(status, number, current, tag, "deploy/compose.yml")
		u.Repo = "YYAC-project/deploy"
		return u
	}
	created := composeUnit(remediation.PRStatusCreated, 12, "nginx:1.25.3", "1.25.4")
	merged := composeUnit(remediation.PRStatusMerged, 7, "cache:7.0.1", "7.0.5")
	merged.State = remediation.PRStateMerged
	closed := composeUnit(remediation.PRStatusSuppressed, 3, "queue:3.1.0", "3.1.2")
	closed.State = remediation.PRStateClosed
	deferred := composeUnit(remediation.PRStatusDeferred, 0, "api:2.0.1", "2.0.4")
	deferred.Reason = remediation.ReasonPRLimit

	lang := remediation.LanguageItem{
		Key: "deps:YYAC-project/regfis-backend@main:.#pnpm", Workloads: []string{"compose/regfis/backend"}, Manager: remediation.ManagerPnpm,
		Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonUpdateVerified,
		Source: langSource("."),
	}
	lang.Source.Repository = "YYAC-project/regfis-backend"
	langUnit := remediation.PRUnit{
		Kind: "language", Key: "language|YYAC-project/regfis-backend|main|pnpm-lock.yaml", ItemKey: lang.Key,
		Repo: "YYAC-project/regfis-backend", BaseBranch: "main", Path: "pnpm-lock.yaml",
		Services: []string{"backend"}, Workloads: lang.Workloads, Status: remediation.PRStatusCreated,
		Number: 2, URL: "https://github.com/YYAC-project/regfis-backend/pull/2", State: remediation.PRStateOpen,
		Language: &remediation.PRLanguage{Manager: "pnpm", Root: ".",
			Packages: []remediation.PRLanguagePackage{
				{Name: "proxy-addr", Ecosystem: "node-pkg", From: "2.0.7", To: "2.0.8"},
				{Name: "sharp", Ecosystem: "node-pkg", From: "0.34.5", To: "0.35.5", Major: true},
				{Name: "undici", Ecosystem: "node-pkg", From: "6.27.0", To: "6.29.0"},
			},
			Remaining: []remediation.PRLanguageRemaining{{Name: "multer", Ecosystem: "node-pkg", From: "2.1.1", Target: "2.3.0", Reason: remediation.ReasonRangeExcludesFix}},
		},
	}
	p.LanguageItems = []remediation.LanguageItem{lang}

	df := dockerfileFixture().DockerfileItems[0]
	df.Workloads = []string{"compose/regfis/elasticsearch"}
	df.Source.Repository, df.Source.Path = "YYAC-project/regfis-infra", "elasticsearch/Dockerfile"
	df.BaseRef = "docker.elastic.co/elasticsearch/elasticsearch:8.19.16"
	df.Candidate = &remediation.ImageState{Ref: "docker.elastic.co/elasticsearch/elasticsearch:8.19.23", Tag: "8.19.23"}
	stage := 0
	df.Source.Stage = &stage
	dfUnit := remediation.PRUnit{
		Kind: "dockerfile", Key: "dockerfile|YYAC-project/regfis-infra|main|elasticsearch/Dockerfile", Repo: "YYAC-project/regfis-infra", BaseBranch: "main",
		Path: "elasticsearch/Dockerfile", Locations: []string{"stages[0]"}, Services: []string{"elasticsearch"}, Workloads: df.Workloads,
		Current: df.BaseRef, CandidateTag: "8.19.23", Status: remediation.PRStatusOpen,
		Number: 1, URL: "https://github.com/YYAC-project/regfis-infra/pull/1", State: remediation.PRStateOpen,
	}
	p.DockerfileItems = []remediation.DockerfileItem{df}

	p.PullRequests = []remediation.PRUnit{langUnit, dfUnit, created, merged, closed, deferred}
	return p
}

func slackPlanInfo() *PlanInfo {
	p := slackPlanFixture()
	return &PlanInfo{Plan: &p, Changed: true}
}

// slackCandidatesInfo is a plan without pull requests: proposals only.
func slackCandidatesInfo() *PlanInfo {
	p := languageFixture()
	df := dockerfileFixture().DockerfileItems
	p.DockerfileItems = df
	return &PlanInfo{Plan: &p, Changed: true}
}

func TestPlanMessage_Golden(t *testing.T) {
	r, _, _ := planCycleFixture()
	weekly := slackPlanInfo()
	weekly.Weekly = true
	for _, c := range []struct {
		name   string
		lang   Language
		info   func() *PlanInfo
		weekly bool
		split  bool
	}{
		{"plan_slack_en_changed", LanguageEN, slackPlanInfo, false, false},
		{"plan_slack_ja_changed", LanguageJA, slackPlanInfo, false, false},
		{"plan_slack_en_weekly", LanguageEN, slackPlanInfo, true, false},
		{"plan_slack_ja_weekly", LanguageJA, slackPlanInfo, true, false},
		{"plan_slack_en_candidates", LanguageEN, slackCandidatesInfo, false, false},
		{"plan_slack_ja_candidates", LanguageJA, slackCandidatesInfo, false, false},
		{"plan_slack_ja_split", LanguageJA, slackPlanInfo, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			info := c.info()
			info.SlackChanged, info.Weekly = !c.weekly, c.weekly
			lim := defaultRenderLimits
			if c.split {
				lim = testSplitLimits
			}
			msgs := buildPlanMessages(Message{Report: r, Plan: info}, messagesFor(c.lang), lim)
			checkBlockGolden(t, c.name, "txt", dumpMessages(msgs))
		})
	}
}

// The lines the agreed format is made of, in Japanese and English.
func TestPlanMessage_Lines(t *testing.T) {
	r, _, _ := planCycleFixture()
	for lang, want := range map[Language][]string{
		LanguageJA: {
			"*🔧 修正計画*",
			"Pull Request: 作成 2件 · オープン中 1件 · マージ済み 1件 · 未マージでクローズ 1件 · 延期 1件",
			"*イメージ:* `ghcr.io/yyac-project/regfis-backend:latest`\n修正するファイル: YYAC-project/regfis-backend の pnpm-lock.yaml\nPull Request: <https://github.com/YYAC-project/regfis-backend/pull/2|#2> (今回作成)\n更新: proxy-addr 2.0.7 → 2.0.8、sharp 0.34.5 → 0.35.5、undici 6.27.0 → 6.29.0\n⚠️ メジャーバージョンの変更: sharp 0.34.5 → 0.35.5 (0.x のマイナー変更)\n要判断: multer 2.1.1 → 2.3.0 は候補または更新後の版が依存関係の制約を満たさないため除外",
			"*イメージ: regfis-infra-elasticsearch*\n修正するファイル: YYAC-project/regfis-infra の elasticsearch/Dockerfile\nPull Request: <https://github.com/YYAC-project/regfis-infra/pull/1|#1> (オープン中)\n更新: ベースイメージ docker.elastic.co/elasticsearch/elasticsearch 8.19.16 → 8.19.23",
			"Pull Request: <https://github.com/ex/deploy/pull/7|#7> (マージ済み)",
			"Pull Request: <https://github.com/ex/deploy/pull/3|#3> (未マージでクローズ)",
			"要判断: 候補では一部の所見しか解消しない",
			"保留: 1回の実行で作れる Pull Request の数の上限に達した",
			"再pull: 所見4件中3件が解消 (KEV 2件)",
		},
		LanguageEN: {
			"*🔧 Fix plan*",
			"Pull requests: 2 created · 1 open · 1 merged · 1 closed without merging · 1 deferred",
			"*Image:* `ghcr.io/yyac-project/regfis-backend:latest`\nFile to change: pnpm-lock.yaml in YYAC-project/regfis-backend\nPull request: <https://github.com/YYAC-project/regfis-backend/pull/2|#2> (opened now)\nUpdate: proxy-addr 2.0.7 → 2.0.8, sharp 0.34.5 → 0.35.5, undici 6.27.0 → 6.29.0\n⚠️ Major version change: sharp 0.34.5 → 0.35.5 (0.x minor change)\nNeeds a decision: multer 2.1.1 → 2.3.0 left out because the candidate or the updated version does not satisfy the dependency constraints",
			"Update: base image docker.elastic.co/elasticsearch/elasticsearch 8.19.16 → 8.19.23",
			"Needs a decision: the candidate resolves only some of the findings",
			"Deferred: the limit on pull requests of a run was reached",
			"Re-pull: resolves 3 of 4 findings (2 KEV)",
		},
	} {
		got := slackPlanText(r, slackPlanInfo(), lang)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
	}
}

// Items that say how far the check went, and the operation records, are not
// in the message.
func TestPlanMessage_HasNoScopeNotesOrOperations(t *testing.T) {
	r, _, _ := planCycleFixture()
	info := slackPlanInfo()
	info.Plan.PROperations = []remediation.OperationEvent{{Seq: 1, ID: "a", Phase: remediation.PhaseResult, Kind: remediation.OpCreatePull, Repo: "ex/deploy", Number: 12, Result: remediation.ResultOK}}
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		got := slackPlanText(r, info, lang)
		for _, bad := range []string{
			"lockfileのスキャンのみ", "lockfile scan only", "最終イメージは未検証", "final image not yet verified", "デプロイは未確認", "deployment not confirmed",
			"候補の提示", "candidates and pull requests", "blob", "ex/deploy#12", "target_not_updated", "constraint_excludes_fix",
		} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: the message has %q:\n%s", lang, bad, got)
			}
		}
	}
}

func TestPlanMessage_DueOnlyWhenChangedOrWeekly(t *testing.T) {
	r, _, _ := planCycleFixture()
	build := func(info *PlanInfo) []SlackMessage {
		return BuildPlanMessages(Message{Report: r, Plan: info}, LanguageEN)
	}

	info := slackPlanInfo()
	if got := build(info); got != nil {
		t.Errorf("not changed and not weekly: %d message(s)", len(got))
	}
	info.SlackChanged = true
	if got := build(info); len(got) == 0 {
		t.Error("changed: no message")
	}

	weekly := slackPlanInfo()
	weekly.Weekly = true
	text := allBlocksText(build(weekly))
	if text == "" {
		t.Fatal("weekly without a change: no message")
	}
	// The weekly list is what is still waiting: pull requests merged or closed
	// are left out, the open ones and the proposals are there.
	for _, want := range []string{"/pull/2|#2", "/pull/1|#1", "/pull/12|#12", "Deferred:"} {
		if !strings.Contains(text, want) {
			t.Errorf("weekly list lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"/pull/7|#7", "/pull/3|#3"} {
		if strings.Contains(text, not) {
			t.Errorf("weekly list has %q:\n%s", not, text)
		}
	}

	// A weekly day with nothing to list sends nothing, and so does no plan.
	empty := &PlanInfo{Plan: &remediation.Plan{}, Weekly: true}
	if got := build(empty); got != nil {
		t.Errorf("empty plan on the weekly day: %d message(s)", len(got))
	}
	var none *PlanInfo
	if none.SlackDue() || none.SlackFingerprint() != "" {
		t.Error("a missing plan is due or has a fingerprint")
	}
}

func TestPlanMessage_BecameEmptyUnavailableAndNotSaved(t *testing.T) {
	r, _, _ := planCycleFixture()
	empty := remediation.Plan{}
	for name, tc := range map[string]struct {
		info *PlanInfo
		want func(messages) string
	}{
		"became empty":   {&PlanInfo{Plan: &empty}, func(m messages) string { return m.PlanNothing }},
		"unavailable db": {&PlanInfo{Unavailable: PlanDatabasesNotPrepared}, func(m messages) string { return strings.Trim(m.PlanUnavailableDB, "\n") }},
		"unavailable":    {&PlanInfo{Unavailable: PlanNotBuilt}, func(m messages) string { return strings.Trim(m.PlanUnavailableOther, "\n") }},
		"not saved":      {&PlanInfo{Plan: &empty, NotSaved: true}, func(m messages) string { return m.PlanNotSaved }},
	} {
		for _, lang := range []Language{LanguageEN, LanguageJA} {
			got := slackPlanText(r, tc.info, lang)
			msg := messagesFor(lang)
			if want := tc.want(msg); !strings.Contains(got, want) {
				t.Errorf("%s/%s: missing %q in\n%s", name, lang, want, got)
			}
			if !strings.Contains(got, strings.TrimSpace(msg.PlanHeading)) {
				t.Errorf("%s/%s: no heading in\n%s", name, lang, got)
			}
		}
	}
}

// A pull request of the stage that is stopped is told in the message.
func TestPlanMessage_PullRequestProblem(t *testing.T) {
	r, _, _ := planCycleFixture()
	info := slackPlanInfo()
	info.Plan.PRProblems = []remediation.PRStageProblem{{Code: remediation.PRProblemWriteBlocked, Repo: "ex/deploy", Reason: remediation.ReasonRecordsUnverified}}
	for lang, want := range map[Language]string{
		LanguageEN: "⚠️ Pull request writes are stopped: a repository, branch or pull request is not in the expected state",
		LanguageJA: "⚠️ Pull Requestの作成を停止中: リポジトリ、ブランチ、Pull Requestのいずれかが想定の状態でない",
	} {
		if got := slackPlanText(r, info, lang); !strings.Contains(got, want) {
			t.Errorf("%s: missing %q in\n%s", lang, want, got)
		}
	}
}

// A plan without pull requests gets the same lines, labelled as proposals, and
// its own summary.
func TestPlanMessage_ProposalsWithoutPullRequests(t *testing.T) {
	r, _, _ := planCycleFixture()
	for lang, want := range map[Language][]string{
		LanguageJA: {
			"更新候補 3件 · 再pull 1件 · 再ビルド 2件 · 要判断 3件",
			"*イメージ: web:latest*\n再pull: 所見4件中3件が解消 (KEV 2件)",
			"更新候補: api 2.0.1 → 2.0.4 (所見1件が解消)",
			"修正するファイル: ex/app の requirements.txt\n再ビルド: urllib3 1.26.5: 再ビルドで 1.26.18 以上が入る見込み",
			"更新候補: express 4.18.2 → 4.19.2、lodash 4.17.20 → 4.17.21、qs 6.11.0 → 6.11.3 (KEV 1件)",
			"要判断: 候補でKEV掲載の脆弱性が新たに入る",
			"再ビルド: 稼働中のイメージの作成元のベースを確認できない。`docker compose build --pull` で再ビルドすると現在のベースが入る",
		},
		LanguageEN: {
			"3 update candidate(s) · 1 re-pull · 2 rebuild · 3 need a decision",
			"Update candidate: express 4.18.2 → 4.19.2, lodash 4.17.20 → 4.17.21, qs 6.11.0 → 6.11.3 (1 KEV)",
		},
	} {
		got := slackPlanText(r, slackCandidatesInfo(), lang)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
	}
}

// A file several images use is listed once under all of them.
func TestPlanMessage_ImagesSideBySide(t *testing.T) {
	r, _, _ := planCycleFixture()
	p := slackPlanFixture()
	p.LanguageItems[0].Workloads = []string{"compose/regfis/backend", "compose/shop/web"}
	p.PullRequests[0].Workloads = p.LanguageItems[0].Workloads
	got := slackPlanText(r, &PlanInfo{Plan: &p}, LanguageJA)
	want := "*イメージ:* `ghcr.io/yyac-project/regfis-backend:latest`\n*イメージ: nginx:1.25.3*\n修正するファイル: YYAC-project/regfis-backend の pnpm-lock.yaml"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in\n%s", want, got)
	}
}

func TestPlanMessage_EscapesExternalValues(t *testing.T) {
	r, _, _ := planCycleFixture()
	p := slackPlanFixture()
	p.Items[2].Current.Ref = "evil<@here>&:1"
	p.PullRequests[2].Current = "evil<@here>&:1"
	p.PullRequests[2].CandidateTag = "<!channel>"
	p.PullRequests[0].Language.Packages[0].Name = "<!everyone>"
	p.PullRequests[0].Path = "<!channel>/pnpm-lock.yaml"
	p.PullRequests[0].Language.Remaining[0].Reason = "<!here>"
	got := slackPlanText(r, &PlanInfo{Plan: &p}, LanguageEN)
	for _, bad := range []string{"<@here>", "<!channel>", "<!everyone>", "<!here>"} {
		if strings.Contains(got, bad) {
			t.Errorf("unescaped %q in\n%s", bad, got)
		}
	}
	for _, want := range []string{"evil&lt;@here&gt;&amp;", "&lt;!channel&gt;", "&lt;!everyone&gt;", "&lt;!here&gt;"} {
		if !strings.Contains(got, want) {
			t.Errorf("escaped %q not found in\n%s", want, got)
		}
	}
}

func TestPlanMessage_RespectsMessageLimits(t *testing.T) {
	r, _, _ := planCycleFixture()
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		info := slackPlanInfo()
		info.SlackChanged = true
		msgs := buildPlanMessages(Message{Report: r, Plan: info}, messagesFor(lang), testSplitLimits)
		if len(msgs) < 2 {
			t.Fatalf("%s: expected the small limits to split the message, got %d", lang, len(msgs))
		}
		for i, m := range msgs {
			if len(m.Blocks) > testSplitLimits.MaxBlocks {
				t.Errorf("%s: message %d has %d blocks, limit %d", lang, i+1, len(m.Blocks), testSplitLimits.MaxBlocks)
			}
			for _, b := range m.Blocks {
				if utf16Len(b.Text) > testSplitLimits.MaxTextUnits {
					t.Errorf("%s: a block of message %d has %d units", lang, i+1, utf16Len(b.Text))
				}
			}
			if i > 0 && !strings.Contains(m.Blocks[0].Text, strings.TrimSpace(messagesFor(lang).PlanHeading[:4])) {
				t.Errorf("%s: message %d does not open with the plan heading: %q", lang, i+1, m.Blocks[0].Text)
			}
		}
	}
}

// The vulnerability message no longer carries the plan, whatever the plan.
func TestChannelMessagesCarryNoPlan(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		without := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed}, ChannelFooter{}, lang))
		for _, info := range []*PlanInfo{slackPlanInfo(), slackCandidatesInfo(), {Unavailable: PlanNotBuilt}} {
			info.SlackChanged = true
			with := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: info}, ChannelFooter{}, lang))
			if with != without || strings.Contains(with, "🔧") {
				t.Errorf("%s: the plan changed the vulnerability message", lang)
			}
		}
	}
}

// --- change detection ---

func TestPlanSlackFingerprint(t *testing.T) {
	base := slackPlanInfo()
	fp := base.SlackFingerprint()
	if fp == "" {
		t.Fatal("empty fingerprint for a plan with content")
	}

	// A pull request opened in this cycle reads the same in the next one.
	opened := slackPlanInfo()
	for i := range opened.Plan.PullRequests {
		if opened.Plan.PullRequests[i].Status == remediation.PRStatusCreated {
			opened.Plan.PullRequests[i].Status = remediation.PRStatusOpen
		}
	}
	if opened.SlackFingerprint() != fp {
		t.Error("a created pull request and an open one differ")
	}

	// What the fingerprint is made of: the flags of the cycle, the changed flag
	// of the webhook and the language do not matter.
	flags := slackPlanInfo()
	flags.Changed, flags.SlackChanged, flags.Weekly = false, true, true
	if flags.SlackFingerprint() != fp {
		t.Error("the flags of the cycle changed the fingerprint")
	}

	// Each of these is a change of what the message shows.
	for name, edit := range map[string]func(*remediation.Plan){
		"a pull request is merged": func(p *remediation.Plan) { p.PullRequests[1].Status = remediation.PRStatusMerged },
		"a pull request is closed": func(p *remediation.Plan) { p.PullRequests[1].Status = remediation.PRStatusSuppressed },
		"a new pull request": func(p *remediation.Plan) {
			u := p.PullRequests[2]
			u.Number, u.Current = 20, "extra:1"
			p.PullRequests = append(p.PullRequests, u)
		},
		"a package is left out": func(p *remediation.Plan) {
			l := p.PullRequests[0].Language
			l.Remaining = append(l.Remaining, remediation.PRLanguageRemaining{Name: "qs", From: "6.0.0", Target: "6.1.0", Reason: remediation.ReasonTargetNotUpdated})
		},
		"a manual item appears": func(p *remediation.Plan) {
			it := p.Items[6]
			it.Current.Ref = "other:1"
			p.Items = append(p.Items, it)
		},
		"an item stops being manual": func(p *remediation.Plan) { p.Items[6].Category = remediation.CategoryNoCandidate },
		"a new update candidate": func(p *remediation.Plan) {
			it := p.Items[5]
			it.Current.Ref = "fresh:1"
			it.Services = []remediation.ServiceRef{{Project: "shop", Service: "fresh"}}
			it.Candidate = &remediation.ImageState{Ref: "fresh:2", Tag: "2"}
			p.Items = append(p.Items, it)
		},
		"a problem stops the pull requests": func(p *remediation.Plan) {
			p.PRProblems = []remediation.PRStageProblem{{Code: remediation.PRProblemStorageFull}}
		},
	} {
		changed := slackPlanInfo()
		edit(changed.Plan)
		if changed.SlackFingerprint() == fp {
			t.Errorf("%s: the fingerprint did not change", name)
		}
	}

	// These are not shown, so they are not changes.
	for name, edit := range map[string]func(*remediation.Plan){
		"an item with no candidate gets a new reason": func(p *remediation.Plan) { p.Items[0].Reason = remediation.ReasonSameContent },
		"the scans are rerun":                         func(p *remediation.Plan) { p.Usage.CandidateScans += 3 },
		"an operation is recorded": func(p *remediation.Plan) {
			p.PROperations = []remediation.OperationEvent{{Seq: 9, ID: "z", Phase: remediation.PhaseResult, Kind: remediation.OpCreatePull, Repo: "ex/deploy"}}
		},
		"an excluded item appears": func(p *remediation.Plan) {
			it := p.Items[0]
			it.Category, it.Reason, it.Current.Ref, it.Services = remediation.CategoryExcluded, "digest_only", "pinned@sha256:aa", nil
			p.Items = append(p.Items, it)
		},
	} {
		same := slackPlanInfo()
		edit(same.Plan)
		if same.SlackFingerprint() != fp {
			t.Errorf("%s: the fingerprint changed", name)
		}
	}

	// A plan with nothing to show has the empty fingerprint, whatever it holds
	// that is not shown; the plan that cannot be produced does not.
	if got := (&PlanInfo{Plan: &remediation.Plan{}}).SlackFingerprint(); got != "" {
		t.Errorf("empty plan: %q", got)
	}
	nothing := planFixture()
	nothing.Items = []remediation.Item{nothing.Items[5], nothing.Items[6]} // no candidate, excluded
	if got := (&PlanInfo{Plan: &nothing}).SlackFingerprint(); got != "" {
		t.Errorf("a plan with only unlisted items: %q", got)
	}
	if (&PlanInfo{Unavailable: PlanNotBuilt}).SlackFingerprint() == "" || (&PlanInfo{Plan: &remediation.Plan{}, NotSaved: true}).SlackFingerprint() == "" {
		t.Error("an unavailable or unsaved plan has the empty fingerprint")
	}
}

// --- reasons ---

var reasonConstRE = regexp.MustCompile(`(?:Reason|ExcludeReason)\s*=\s*"([a-z0-9_]+)"`)

// Every reason code the plan can carry has a sentence in both languages.
func TestPlanReasonTextsCoverEveryCode(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "remediation", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("remediation sources: %v (%d)", err, len(files))
	}
	codes := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range reasonConstRE.FindAllStringSubmatch(string(data), -1) {
			codes[m[1]] = true
		}
	}
	if len(codes) < 150 {
		t.Fatalf("found only %d reason codes; the pattern is out of date", len(codes))
	}
	for code := range codes {
		if code == "" {
			continue
		}
		if _, ok := planReasonTexts[code]; !ok {
			t.Errorf("reason %q has no sentence", code)
		}
	}
	for code, txt := range planReasonTexts {
		if txt.en == "" || txt.ja == "" {
			t.Errorf("reason %q lacks a language", code)
		}
		if strings.HasSuffix(txt.en, ".") || strings.HasSuffix(txt.ja, "。") {
			t.Errorf("reason %q ends with a full stop", code)
		}
		if strings.Contains(txt.ja, "製品") {
			t.Errorf("reason %q uses a banned word", code)
		}
		if strings.ContainsAny(txt.en, "<>&") || strings.ContainsAny(txt.ja, "<>&") {
			t.Errorf("reason %q has characters that need escaping", code)
		}
		if !codes[code] {
			t.Errorf("reason %q is in the table and in no source", code)
		}
	}
}

func TestPlanReasonTextOfAnUnknownCodeIsTheCode(t *testing.T) {
	if got := planReasonText(LanguageJA, "brand_new_reason"); got != "brand_new_reason" {
		t.Errorf("got %q", got)
	}
	if got := planReasonText(LanguageEN, "<!channel>"); got != "&lt;!channel&gt;" {
		t.Errorf("an unknown code is not escaped: %q", got)
	}
	if got := planReasonText(LanguageJA, "target_not_updated"); got != "更新しても目標の版に上がらなかった" {
		t.Errorf("got %q", got)
	}
	if got := planReasonText(LanguageEN, "target_not_updated"); got != "the package is not at the target version in the updated file" {
		t.Errorf("got %q", got)
	}
}

// --- delivery ---

func planMessageOf(r analyze.Report, d *state.Diff, info *PlanInfo, skip bool) Message {
	return Message{Report: r, Diff: d, Plan: info, SkipReport: skip}
}

// A webhook gets the plan after the vulnerability message, only when it is
// due, and alone when the vulnerability message is not.
func TestSlackNotifier_SendsThePlanAfterTheReport(t *testing.T) {
	r, changed, _ := planCycleFixture()
	due, quiet := slackPlanInfo(), slackPlanInfo()
	due.SlackChanged = true
	report := buildChannelMessages(Message{Report: r, Diff: &changed}, ChannelFooter{}, enMessages, defaultRenderLimits)
	plan := buildPlanMessages(planMessageOf(r, &changed, due, false), enMessages, defaultRenderLimits)
	if len(report) == 0 || len(plan) == 0 {
		t.Fatalf("fixture: %d report and %d plan message(s)", len(report), len(plan))
	}
	for name, tc := range map[string]struct {
		m    Message
		want int
		last bool // the last message is the plan
	}{
		"report and plan": {planMessageOf(r, &changed, due, false), len(report) + len(plan), true},
		"plan alone":      {planMessageOf(r, &changed, due, true), len(plan), true},
		"plan not due":    {planMessageOf(r, &changed, quiet, false), len(report), false},
		"no plan":         {planMessageOf(r, &changed, nil, false), len(report), false},
	} {
		w := newWebhookRecorder(t)
		var sleeps []time.Duration
		if err := w.notifier(&sleeps).Send(context.Background(), tc.m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(w.bodies) != tc.want {
			t.Fatalf("%s: posted %d message(s), want %d", name, len(w.bodies), tc.want)
		}
		for i, b := range w.bodies {
			isPlan := strings.Contains(fmt.Sprint(b["blocks"]), "🔧")
			if want := tc.last && i >= len(w.bodies)-len(plan); isPlan != want {
				t.Errorf("%s: message %d plan=%v, want %v", name, i+1, isPlan, want)
			}
		}
	}
}

func TestSlackAPINotifier_PostsThePlanBetweenTheReportAndItsThread(t *testing.T) {
	r, changed, _ := planCycleFixture()
	info := slackPlanInfo()
	info.SlackChanged = true
	f := newSlackFake(t)
	res := &ThreadResult{}
	m := Message{Report: r, Diff: &changed, Thread: true, Result: res, Plan: info}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	report := buildChannelMessages(m, ChannelFooter{Kind: FooterThreadNotice}, enMessages, defaultRenderLimits)
	plan := buildPlanMessages(m, enMessages, defaultRenderLimits)
	if len(f.posts) <= len(report)+len(plan) {
		t.Fatalf("posted %d message(s); want the report (%d), the plan (%d) and a thread", len(f.posts), len(report), len(plan))
	}
	for i := range f.posts {
		_, threaded := f.posts[i]["thread_ts"]
		isPlan := strings.Contains(f.blockText(i), "🔧")
		switch {
		case i < len(report):
			if threaded || isPlan {
				t.Errorf("post %d should be a top-level report message (threaded=%v plan=%v)", i, threaded, isPlan)
			}
		case i < len(report)+len(plan):
			if threaded || !isPlan {
				t.Errorf("post %d should be a top-level plan message (threaded=%v plan=%v)", i, threaded, isPlan)
			}
		default:
			if !threaded || f.posts[i]["thread_ts"] != tsFor(1) || isPlan {
				t.Errorf("post %d should be a reply under the first report message (threaded=%v)", i, threaded)
			}
		}
	}
	if res.Ref.TS != tsFor(1) {
		t.Errorf("thread ref = %+v, want the first report message", res.Ref)
	}
	if strings.Contains(f.footer(0), "🔧") || !strings.Contains(f.footer(0), "thread") {
		t.Errorf("the footer of the first message = %q", f.footer(0))
	}
}

// A plan alone is a top-level message: no vulnerability message, no thread, no
// permalink.
func TestSlackAPINotifier_PlanAloneHasNoReportOrThread(t *testing.T) {
	r, changed, _ := planCycleFixture()
	info := slackPlanInfo()
	info.SlackChanged = true
	f := newSlackFake(t)
	res := &ThreadResult{}
	m := Message{Report: r, Diff: &changed, Thread: true, Result: res, Plan: info, SkipReport: true}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	plan := buildPlanMessages(m, enMessages, defaultRenderLimits)
	if len(f.posts) != len(plan) || f.permCalls != 0 || res.Ref.TS != "" {
		t.Fatalf("posts=%d (want %d) permalink calls=%d ref=%+v", len(f.posts), len(plan), f.permCalls, res.Ref)
	}
	for i := range f.posts {
		if _, threaded := f.posts[i]["thread_ts"]; threaded || !strings.Contains(f.blockText(i), "🔧") {
			t.Errorf("post %d is not a top-level plan message", i)
		}
	}
}

// A plan that is not due leaves the vulnerability message as it was.
func TestSlackAPINotifier_PlanNotDuePostsNothingExtra(t *testing.T) {
	r, changed, _ := planCycleFixture()
	f := newSlackFake(t)
	m := Message{Report: r, Diff: &changed, Plan: slackPlanInfo()}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	want := buildChannelMessages(m, ChannelFooter{Kind: FooterThreadNotice}, enMessages, defaultRenderLimits)
	if len(f.posts) < len(want) {
		t.Fatalf("posted %d, want at least %d", len(f.posts), len(want))
	}
	for i := range f.posts {
		if strings.Contains(f.blockText(i), "🔧") {
			t.Errorf("post %d carries the plan", i)
		}
	}
}

// --- the review's cases ---

// A change that the message cuts short still changes the fingerprint.
func TestPlanSlackFingerprint_SeesWhatTheLinesCutShort(t *testing.T) {
	many := func() *PlanInfo {
		info := slackPlanInfo()
		l := info.Plan.PullRequests[0].Language
		l.Packages = nil
		for i := 0; i < 12; i++ {
			l.Packages = append(l.Packages, remediation.PRLanguagePackage{Name: string(rune('a' + i)), From: "1.0.0", To: "1.0.1"})
		}
		l.Remaining = nil
		for i := 0; i < 12; i++ {
			l.Remaining = append(l.Remaining, remediation.PRLanguageRemaining{Name: string(rune('p' + i)), From: "1.0.0", Target: "2.0.0", Reason: remediation.ReasonTargetNotUpdated})
		}
		return info
	}
	base := many().SlackFingerprint()
	sixth := many()
	sixth.Plan.PullRequests[0].Language.Packages[11].To = "1.0.9"
	if sixth.SlackFingerprint() == base {
		t.Error("the twelfth package of the list is not in the fingerprint")
	}
	fourth := many()
	fourth.Plan.PullRequests[0].Language.Remaining[11].Reason = remediation.ReasonRangeExcludesFix
	if fourth.SlackFingerprint() == base {
		t.Error("the twelfth left-out package is not in the fingerprint")
	}
	// The message itself still shows ten.
	got := slackPlanText(planReport(), many(), LanguageEN)
	if !strings.Contains(got, "and 2 more") || strings.Contains(got, "l 1.0.0") {
		t.Errorf("the list is not cut:\n%s", got)
	}
}

func planReport() analyze.Report {
	r, _, _ := planCycleFixture()
	return r
}

// Images and base images whose check failed, was put off or could not be made
// are in the message, with their reasons, and in what it is compared on.
func TestPlanMessage_ShowsFailedDeferredAndNotComparable(t *testing.T) {
	cases := []struct {
		category remediation.Category
		reason   remediation.Reason
		en, ja   string
	}{
		{remediation.CategoryFailed, remediation.ReasonRegistryError, "Failed: the registry returned an error", "失敗: レジストリがエラーを返した"},
		{remediation.CategoryDeferred, remediation.ReasonCandidateScanLimit, "Deferred: the limit on candidate scans of a run was reached", "保留: 1回の実行でスキャンできる候補数の上限に達した"},
		{remediation.CategoryNotComparable, remediation.ReasonAuthRequired, "Not comparable: the registry requires a login", "比較不能: レジストリへのログインが必要である"},
	}
	for _, c := range cases {
		image := planImage("only:1", "shop", "only")
		image.Category, image.Reason = c.category, c.reason
		p := remediation.Plan{Items: []remediation.Item{image}}
		df := dockerfileFixture().DockerfileItems[3]
		df.Category, df.Reason = c.category, c.reason
		pd := remediation.Plan{DockerfileItems: []remediation.DockerfileItem{df}}
		for name, plan := range map[string]remediation.Plan{"image": p, "dockerfile": pd} {
			info := &PlanInfo{Plan: &plan}
			if info.SlackFingerprint() == "" {
				t.Errorf("%s/%s: the fingerprint is empty", name, c.category)
			}
			for lang, want := range map[Language]string{LanguageEN: c.en, LanguageJA: c.ja} {
				got := slackPlanText(planReport(), &PlanInfo{Plan: &plan}, lang)
				if !strings.Contains(got, want) || strings.Contains(got, messagesFor(lang).PlanNothing) {
					t.Errorf("%s/%s/%s: missing %q in\n%s", name, c.category, lang, want, got)
				}
			}
			weekly := &PlanInfo{Plan: &plan, Weekly: true}
			if !weekly.SlackDue() {
				t.Errorf("%s/%s: not listed on the weekly day", name, c.category)
			}
		}
	}
	// Going from a candidate to a failure is a change that is shown.
	ok, failed := slackPlanInfo(), slackPlanInfo()
	failed.Plan.Items[5].Category, failed.Plan.Items[5].Reason = remediation.CategoryFailed, remediation.ReasonRegistryError
	if ok.SlackFingerprint() == failed.SlackFingerprint() {
		t.Error("an image going from a candidate to a failure is no change")
	}
}

// Values with characters that would format the text are shown as they are.
func TestPlanMessage_ExternalValuesAreLiteral(t *testing.T) {
	p := slackPlanFixture()
	p.PullRequests[2].Path = "*prod*/compose_`x`.yml"
	p.PullRequests[3].Path = "~old~/a.yml"
	p.PullRequests[0].Path = "_lock_/pnpm-lock.yaml"
	p.PullRequests[0].Language.Packages[0].Name = "@scope/*pkg*"
	got := slackPlanText(planReport(), &PlanInfo{Plan: &p}, LanguageEN)
	for _, want := range []string{
		"File to change: `*prod*/compose_'x'.yml` in YYAC-project/deploy",
		"`~old~/a.yml`",
		"`_lock_/pnpm-lock.yaml`",
		"`@scope/*pkg*` 2.0.7 → 2.0.8",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// No value opens a code span that is left open: every block has an even
	// number of backticks, so the links beside it stay links.
	for _, m := range BuildPlanMessages(Message{Report: planReport(), Plan: &PlanInfo{Plan: &p, SlackChanged: true}}, LanguageEN) {
		for _, b := range m.Blocks {
			if strings.Count(b.Text, "`")%2 != 0 {
				t.Errorf("odd backticks in %q", b.Text)
			}
		}
	}
	for in, want := range map[string]string{
		"plain-name_1.0": "plain-name_1.0",
		"a<b>&c":         "a&lt;b&gt;&amp;c",
		"with*star":      "`with*star`",
		"back`tick":      "`back'tick`",
		"line\nbreak":    "line break",
		"trail_":         "`trail_`",
	} {
		if got := litMrkdwn(in); got != want {
			t.Errorf("litMrkdwn(%q) = %q, want %q", in, got, want)
		}
	}
}

// A failure after the plan was posted does not lose the plan's delivery, and a
// failure of the plan does not keep the thread from being posted.
func TestSlackAPINotifier_PlanAndThreadAreDeliveredOnTheirOwn(t *testing.T) {
	r, changed, _ := planCycleFixture()
	newMsg := func(d *PlanDelivery) Message {
		info := slackPlanInfo()
		info.SlackChanged = true
		return Message{Report: r, Diff: &changed, Thread: true, Result: &ThreadResult{}, Plan: info, PlanDelivery: d}
	}

	t.Run("permalink fails after the plan", func(t *testing.T) {
		f := newSlackFake(t)
		f.failPerm = true
		d := &PlanDelivery{}
		if err := f.notifier().Send(context.Background(), newMsg(d)); err == nil {
			t.Fatal("the permalink failure was swallowed")
		}
		if !d.Posted || d.Failed {
			t.Errorf("delivery = %+v, want the plan recorded as posted", d)
		}
	})

	t.Run("the plan fails, the thread is posted", func(t *testing.T) {
		f := newSlackFake(t)
		m := newMsg(&PlanDelivery{})
		report := buildChannelMessages(m, ChannelFooter{Kind: FooterThreadNotice}, enMessages, defaultRenderLimits)
		f.failAfter = len(report)
		n := f.notifier()
		err := n.Send(context.Background(), m)
		if err == nil {
			t.Fatal("the plan failure was swallowed")
		}
		d := m.PlanDelivery
		if d.Posted || !d.Failed {
			t.Errorf("delivery = %+v, want a failed plan", d)
		}
		// The thread replies were tried although the plan failed; the fake
		// refuses every post after the report, so they fail too, but the
		// notifier did not stop at the plan.
		if f.postAttempt <= len(report)+1 {
			t.Errorf("posts attempted = %d, the thread was not tried", f.postAttempt)
		}
	})

	t.Run("the report fails, the plan is posted", func(t *testing.T) {
		f := newSlackFake(t)
		f.failPosts = 3 // the retries of the first report message
		m := newMsg(&PlanDelivery{})
		if err := f.notifier().Send(context.Background(), m); err == nil {
			t.Fatal("the report failure was swallowed")
		}
		if !m.PlanDelivery.Posted {
			t.Errorf("delivery = %+v, want the plan posted", m.PlanDelivery)
		}
	})
}

func TestSlackNotifier_ReportFailureStillPostsThePlan(t *testing.T) {
	r, changed, _ := planCycleFixture()
	w := newWebhookRecorder(t)
	w.status[1] = 500 // the first report message fails
	info := slackPlanInfo()
	info.SlackChanged = true
	m := Message{Report: r, Diff: &changed, Plan: info, PlanDelivery: &PlanDelivery{}}
	var sleeps []time.Duration
	if err := w.notifier(&sleeps).Send(context.Background(), m); err == nil {
		t.Fatal("the failure was swallowed")
	}
	if !m.PlanDelivery.Posted || len(w.bodies) == 0 || !strings.Contains(fmt.Sprint(w.bodies[len(w.bodies)-1]["blocks"]), "🔧") {
		t.Errorf("delivery = %+v, bodies = %d", m.PlanDelivery, len(w.bodies))
	}
}

// Every package a rebuild is expected to take is in the fingerprint, not only
// the one the line names.
func TestPlanSlackFingerprint_SeesEveryRebuildPackage(t *testing.T) {
	mk := func() *PlanInfo {
		p := languageFixture()
		li := &p.LanguageItems[1]
		li.Packages = append(li.Packages, remediation.LanguagePackage{Name: "idna", Installed: "3.0", SelectionLowerBound: "3.7",
			Action: remediation.ActionRebuildExpected, Reason: remediation.ReasonRangeAllowsFix})
		return &PlanInfo{Plan: &p}
	}
	base := mk().SlackFingerprint()
	for name, edit := range map[string]func(*remediation.LanguagePackage){
		"name":      func(p *remediation.LanguagePackage) { p.Name = "idna2" },
		"installed": func(p *remediation.LanguagePackage) { p.Installed = "3.1" },
		"target":    func(p *remediation.LanguagePackage) { p.SelectionLowerBound = "3.8" },
	} {
		info := mk()
		edit(&info.Plan.LanguageItems[1].Packages[1])
		if info.SlackFingerprint() == base {
			t.Errorf("the second package's %s is not in the fingerprint", name)
		}
	}
}

// An unknown reason code is shown as the literal text it is.
func TestPlanReasonTextOfAnUnknownCodeIsLiteral(t *testing.T) {
	for in, want := range map[string]string{
		"*bold* code":       "`*bold* code`",
		"back`tick":         "`back'tick`",
		"two\nlines":        "two lines",
		"<!channel> & more": "&lt;!channel&gt; &amp; more",
	} {
		if got := planReasonText(LanguageEN, in); got != want {
			t.Errorf("planReasonText(%q) = %q, want %q", in, got, want)
		}
	}
	// In a message, such a reason cannot open formatting.
	p := slackPlanFixture()
	p.PullRequests[0].Language.Remaining[0].Reason = "*x*\n`y`"
	for _, m := range BuildPlanMessages(Message{Report: planReport(), Plan: &PlanInfo{Plan: &p, SlackChanged: true}}, LanguageEN) {
		for _, b := range m.Blocks {
			if strings.Count(b.Text, "`")%2 != 0 {
				t.Errorf("odd backticks in %q", b.Text)
			}
		}
	}
}

// An item that is manual as a whole for a reason its packages have names those
// packages, like the lines of the packages left out. The line for a package
// that could not be raised says what is known and what is not.
func TestPlanMessage_ItemReasonNamesItsPackages(t *testing.T) {
	item := func(detail string, extra int) *PlanInfo {
		li := languageUpdated("deps:ex/app@main:.#npm")
		li.Category, li.Reason, li.Detail = remediation.CategoryManual, remediation.ReasonTargetNotUpdated, detail
		li.Packages = []remediation.LanguagePackage{{Name: "multer", Ecosystem: "node-pkg", Installed: "2.1.1", SelectionLowerBound: "2.3.0",
			Action: remediation.ActionManual, Reason: remediation.ReasonTargetNotUpdated}}
		for i := 0; i < extra; i++ {
			li.Packages = append(li.Packages, remediation.LanguagePackage{Name: string(rune('a' + i)), Installed: "1.0.0", SelectionLowerBound: "1.1.0",
				Action: remediation.ActionManual, Reason: remediation.ReasonTargetNotUpdated})
		}
		li.Packages = append(li.Packages, remediation.LanguagePackage{Name: "other", Installed: "1", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource})
		return languagePlanOf(li)
	}
	r := planReport()
	for lang, want := range map[Language]string{
		LanguageJA: "要判断: multer は脆弱性が直る 2.3.0 に上げられず、package-lock.json では 2.1.1 のまま（上げられない原因は KestreLynx では調べていないため、multer に依存しているパッケージの版の指定を確認してください）",
		LanguageEN: "Needs a decision: multer could not be raised to 2.3.0, which fixes the vulnerability, and stays at 2.1.1 in package-lock.json (KestreLynx did not look into why it cannot be raised, so check the version ranges of the packages that depend on multer)",
	} {
		got := slackPlanText(r, item("the update left pnpm-lock.yaml unchanged", 0), lang)
		if !strings.Contains(got, want) {
			t.Errorf("%s: missing %q in\n%s", lang, want, got)
		}
		if strings.Contains(got, "other 1") {
			t.Errorf("%s: a package with another reason is listed:\n%s", lang, got)
		}
	}
	// More than ten packages are cut at ten.
	got := slackPlanText(r, item("", 11), LanguageEN)
	if n := strings.Count(got, "Needs a decision: "); n != 11 || !strings.Contains(got, "Needs a decision: and 2 more") {
		t.Errorf("%d lines in\n%s", n, got)
	}
	// Every package, and what is known of the lockfile, is in the fingerprint.
	a, b := item("", 11), item("", 11)
	b.Plan.LanguageItems[0].Packages[11].SelectionLowerBound = "9.9.9"
	c := item("the update left x unchanged", 11)
	if a.SlackFingerprint() == b.SlackFingerprint() || a.SlackFingerprint() == c.SlackFingerprint() {
		t.Error("a cut package or the lockfile note is not in the fingerprint")
	}
}

func TestPlanMessage_ItemReasonGolden(t *testing.T) {
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		li := languageUpdated("deps:ex/app@main:.#npm")
		li.Category, li.Reason, li.Detail = remediation.CategoryManual, remediation.ReasonTargetNotUpdated, "the update left package-lock.json unchanged"
		li.Packages = []remediation.LanguagePackage{{Name: "multer", Ecosystem: "node-pkg", Installed: "2.1.1", SelectionLowerBound: "2.3.0",
			Action: remediation.ActionManual, Reason: remediation.ReasonTargetNotUpdated}}
		info := languagePlanOf(li)
		info.SlackChanged = true
		msgs := buildPlanMessages(Message{Report: planReport(), Plan: info}, messagesFor(lang), defaultRenderLimits)
		checkBlockGolden(t, "plan_slack_"+string(lang)+"_item_reason", "txt", dumpMessages(msgs))
	}
}

// The frontend of production: packages that are not in the lockfile are one
// heading and a bullet list, with no arrow and no target.
func TestPlanMessage_PackagesNotInTheLockfile(t *testing.T) {
	li := languageUpdated("deps:YYAC-project/regfis-frontend@main:.#pnpm")
	li.Manager = remediation.ManagerPnpm
	li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonNotFoundInSource
	li.Packages = nil
	for _, p := range [][2]string{{"brace-expansion", "2.0.2"}, {"ip-address", "10.1.0"}, {"pacote", "19.0.2"}, {"a", "1"}, {"b", "2"}, {"c", "3"}} {
		li.Packages = append(li.Packages, remediation.LanguagePackage{Name: p[0], Installed: p[1], Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource})
	}
	r := planReport()
	for lang, want := range map[Language]string{
		LanguageJA: "要判断: pnpm-lock.yaml に無いパッケージ（lockfile 以外の経路でイメージに入ったものとみられ、lockfile の更新では直せない）\n  • brace-expansion 2.0.2\n  • ip-address 10.1.0\n  • pacote 19.0.2\n  • a 1",
		LanguageEN: "Needs a decision: packages that are not in pnpm-lock.yaml (they probably came into the image by a route other than the lockfile, so updating the lockfile cannot fix them)\n  • brace-expansion 2.0.2\n  • ip-address 10.1.0",
	} {
		got := slackPlanText(r, languagePlanOf(li), lang)
		if !strings.Contains(got, want) || strings.Contains(got, "→") {
			t.Errorf("%s: missing %q (or an arrow) in\n%s", lang, want, got)
		}
		if strings.Count(got, "要判断:")+strings.Count(got, "Needs a decision:") != 1 {
			t.Errorf("%s: more than one heading:\n%s", lang, got)
		}
	}
	// Eleven packages: ten bullets, then the count of the rest.
	for _, n := range []int{10, 11} {
		li.Packages = nil
		for i := 0; i < n; i++ {
			li.Packages = append(li.Packages, remediation.LanguagePackage{Name: fmt.Sprintf("p%02d", i), Installed: "1", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource})
		}
		got := slackPlanText(r, languagePlanOf(li), LanguageJA)
		if bullets := strings.Count(got, "  • p"); bullets != min(n, 10) || strings.Contains(got, "ほか") != (n > 10) {
			t.Errorf("%d packages: %d bullets in\n%s", n, bullets, got)
		}
		if n > 10 && !strings.Contains(got, "ほか1件") {
			t.Errorf("no count of the rest in\n%s", got)
		}
	}
}

// A package left out because it could not be raised gets the same sentence as
// an item that is manual for it.
func TestPlanMessage_LeftOutNotUpdatedSentence(t *testing.T) {
	p := slackPlanFixture()
	p.PullRequests[0].Language.Remaining = []remediation.PRLanguageRemaining{{Name: "multer", From: "2.1.1", Target: "2.3.0", Reason: remediation.ReasonTargetNotUpdated}}
	for lang, want := range map[Language]string{
		LanguageJA: "要判断: multer は脆弱性が直る 2.3.0 に上げられず、pnpm-lock.yaml では 2.1.1 のまま（上げられない原因は KestreLynx では調べていないため、multer に依存しているパッケージの版の指定を確認してください）",
		LanguageEN: "Needs a decision: multer could not be raised to 2.3.0, which fixes the vulnerability, and stays at 2.1.1 in pnpm-lock.yaml (KestreLynx did not look into why it cannot be raised, so check the version ranges of the packages that depend on multer)",
	} {
		if got := slackPlanText(planReport(), &PlanInfo{Plan: &p}, lang); !strings.Contains(got, want) {
			t.Errorf("%s: missing %q in\n%s", lang, want, got)
		}
	}
}

// A registry host in an image reference does not break the bold heading: it is
// in a code span, which Slack does not turn into a link. References without a
// host are written as in the vulnerability message.
func TestPlanMessage_ImageHeadingWithARegistryHost(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/yyac-project/regfis-backend:latest": "`ghcr.io/yyac-project/regfis-backend:latest`",
		"localhost:5000/app:1":                       "`localhost:5000/app:1`",
		"nginx:1.25.3":                               "nginx:1.25.3",
		"library/nginx:1":                            "library/nginx:1",
		"regfis-infra-elasticsearch":                 "regfis-infra-elasticsearch",
		"evil.io/<@here>`x`":                         "`evil.io/&lt;@here&gt;'x'`",
	} {
		if got := refMrkdwn(in); got != want {
			t.Errorf("refMrkdwn(%q) = %q, want %q", in, got, want)
		}
	}
	got := slackPlanText(planReport(), slackPlanInfo(), LanguageJA)
	if !strings.Contains(got, "*イメージ:* `ghcr.io/yyac-project/regfis-backend:latest`\n") {
		t.Errorf("heading in\n%s", got)
	}
}

// The lists of a line go to ten before they are cut.
func TestPlanMessage_ListsAreCutAtTen(t *testing.T) {
	for _, n := range []int{10, 11} {
		p := slackPlanFixture()
		l := p.PullRequests[0].Language
		l.Packages, l.Remaining, l.ManifestEdits = nil, nil, nil
		for i := 0; i < n; i++ {
			l.Packages = append(l.Packages, remediation.PRLanguagePackage{Name: fmt.Sprintf("p%02d", i), From: "1.0.0", To: "1.0.1"})
		}
		got := slackPlanText(planReport(), &PlanInfo{Plan: &p}, LanguageEN)
		if strings.Contains(got, "p09 1.0.0") != true || strings.Contains(got, "p10 1.0.0") {
			t.Errorf("%d packages: wrong cut in\n%s", n, got)
		}
		if has := strings.Contains(got, "and 1 more"); has != (n == 11) {
			t.Errorf("%d packages: more clause = %v in\n%s", n, has, got)
		}
	}
}

// A plan without pull requests whose two dependency files need a person: one
// package that could not be raised, and packages the lockfile does not have.
func TestPlanMessage_ManualDependencyFilesGolden(t *testing.T) {
	backend := planImage("ghcr.io/yyac-project/regfis-backend:latest", "regfis", "backend")
	frontend := planImage("ghcr.io/yyac-project/regfis-frontend:latest", "regfis", "frontend")
	item := func(repo, service string, reason remediation.Reason, pkgs ...remediation.LanguagePackage) remediation.LanguageItem {
		li := languageUpdated("deps:" + repo)
		li.Workloads = []string{"compose/regfis/" + service}
		li.Manager, li.Category, li.Reason, li.Packages = remediation.ManagerPnpm, remediation.CategoryManual, reason, pkgs
		li.Source.Repository, li.Source.Directory = repo, "."
		return li
	}
	pkg := func(name, installed, target string, reason remediation.Reason, detail string) remediation.LanguagePackage {
		return remediation.LanguagePackage{Name: name, Installed: installed, SelectionLowerBound: target, Action: remediation.ActionManual, Reason: reason, Detail: detail}
	}
	var missing []remediation.LanguagePackage
	for _, p := range [][2]string{{"brace-expansion", "2.0.2"}, {"ip-address", "10.1.0"}, {"pacote", "19.0.2"}, {"tar-fs", "3.0.4"}, {"semver", "7.5.1"}, {"zod", "3.22.0"}} {
		missing = append(missing, pkg(p[0], p[1], "", remediation.ReasonNotFoundInSource, ""))
	}
	missing = append(missing, remediation.LanguagePackage{Name: "lodash", Installed: "4.17.15", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource,
		Occurrences: []remediation.SourceOccurrence{{Path: "node_modules/lodash", Version: "4.17.20"}}})
	plan := remediation.Plan{
		Items: []remediation.Item{backend, frontend},
		LanguageItems: []remediation.LanguageItem{
			item("YYAC-project/regfis-backend", "backend", remediation.ReasonTargetNotUpdated,
				pkg("multer", "2.1.1", "2.3.0", remediation.ReasonTargetNotUpdated, "the update left pnpm-lock.yaml unchanged")),
			item("YYAC-project/regfis-frontend", "frontend", remediation.ReasonNotFoundInSource, missing...),
		},
	}
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		info := &PlanInfo{Plan: &plan, SlackChanged: true}
		msgs := buildPlanMessages(Message{Report: planReport(), Plan: info}, messagesFor(lang), defaultRenderLimits)
		checkBlockGolden(t, "plan_slack_"+string(lang)+"_manual_files", "txt", dumpMessages(msgs))
	}
}

// A package the files list at another version than the image has is told apart
// from one they do not have.
func TestPlanMessage_PackagesAtAnotherVersion(t *testing.T) {
	li := languageUpdated("deps:YYAC-project/regfis-frontend@main:.#pnpm")
	li.Manager = remediation.ManagerPnpm
	li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonNotFoundInSource
	li.Packages = []remediation.LanguagePackage{
		{Name: "zod", Installed: "3.22.0", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource},
		{Name: "lodash", Installed: "4.17.15", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource,
			Occurrences: []remediation.SourceOccurrence{{Path: "node_modules/lodash", Version: "4.17.20"}}},
		{Name: "semver", Installed: "7.0.0", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource,
			Occurrences: []remediation.SourceOccurrence{{Path: "a/node_modules/semver", Version: "7.5.4"}, {Path: "b/node_modules/semver", Version: "7.6.0"}, {Path: "c/node_modules/semver", Version: "7.5.4"}}},
	}
	for lang, want := range map[Language][]string{
		LanguageJA: {
			"要判断: pnpm-lock.yaml に無いパッケージ（lockfile 以外の経路でイメージに入ったものとみられ、lockfile の更新では直せない）\n  • zod 3.22.0",
			"要判断: イメージに入っている版が pnpm-lock.yaml と違うパッケージ（イメージが今の pnpm-lock.yaml から作られていない可能性があるため、作り直してから確認してください）\n  • lodash: イメージは 4.17.15、pnpm-lock.yaml は 4.17.20\n  • semver: イメージは 7.0.0、pnpm-lock.yaml は 7.5.4、7.6.0",
		},
		LanguageEN: {
			"Needs a decision: packages that are not in pnpm-lock.yaml (they probably came into the image by a route other than the lockfile, so updating the lockfile cannot fix them)\n  • zod 3.22.0",
			"Needs a decision: packages whose version in the image differs from pnpm-lock.yaml (the image may not have been built from the current pnpm-lock.yaml, so rebuild it and check again)\n  • lodash: the image has 4.17.15, pnpm-lock.yaml has 4.17.20\n  • semver: the image has 7.0.0, pnpm-lock.yaml has 7.5.4, 7.6.0",
		},
	} {
		got := slackPlanText(planReport(), languagePlanOf(li), lang)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
	}
	a, b := languagePlanOf(li), languagePlanOf(li)
	other := li
	other.Packages = append([]remediation.LanguagePackage(nil), li.Packages...)
	other.Packages[1].Occurrences = []remediation.SourceOccurrence{{Path: "node_modules/lodash", Version: "4.17.21"}}
	b = languagePlanOf(other)
	if a.SlackFingerprint() == b.SlackFingerprint() {
		t.Error("the version the files list is not in the fingerprint")
	}
}

// "Pull Request:" in the summary needs a pull request that exists; units that
// only wait or need a person are counted as proposals.
func TestPlanMessage_SummaryNeedsARealPullRequest(t *testing.T) {
	unit := func(status remediation.PRUnitStatus) remediation.PRUnit {
		u := prUnit(status, 0, "app:1", "2", "compose.yml")
		u.Reason = remediation.ReasonComposeSetNotAdopted
		return u
	}
	p := remediation.Plan{PullRequests: []remediation.PRUnit{unit(remediation.PRStatusManual), unit(remediation.PRStatusManual)}}
	p.PullRequests[1].Current = "app2:1"
	for lang, want := range map[Language]string{LanguageJA: "要判断 2件", LanguageEN: "2 need a decision"} {
		got := slackPlanText(planReport(), &PlanInfo{Plan: &p}, lang)
		if !strings.Contains(got, "\n"+want+"\n") || strings.Contains(got, "Pull Request:") || strings.Contains(got, "Pull requests:") {
			t.Errorf("%s: summary in\n%s", lang, got)
		}
	}
	// One pull request that exists brings the line back.
	p.PullRequests = append(p.PullRequests, prUnit(remediation.PRStatusOpen, 5, "app3:1", "2", "compose.yml"))
	if got := slackPlanText(planReport(), &PlanInfo{Plan: &p}, LanguageJA); !strings.Contains(got, "Pull Request: オープン中 1件 · 要判断 2件") {
		t.Errorf("summary with a pull request in\n%s", got)
	}
}

// Lines that add to a proposal (the file, the major version warning, the
// candidate beside a decision) are not proposals: a unit without a pull request
// is counted once, as what keeps it from having one.
func TestPlanMessage_SupplementaryLinesAreNotCounted(t *testing.T) {
	li := languageUpdated("deps:ex/app@main:.#npm")
	for _, status := range []remediation.PRUnitStatus{remediation.PRStatusDeferred, remediation.PRStatusManual, remediation.PRStatusFailed} {
		u := languageUnit(status, 0, remediation.ReasonPRLimit)
		u.Language.Packages[0].Major = true // a package and a manifest edit both move to another major version
		u.Language.ManifestEdits = []remediation.LangEdit{{File: "package.json", Section: "dependencies", Name: "lodash", From: "^4.0.0", To: "^5.0.0", Major: true}}
		got := slackPlanText(planReport(), languagePlanOf(li, u), LanguageJA)
		want := map[remediation.PRUnitStatus]string{
			remediation.PRStatusDeferred: "保留 1件", remediation.PRStatusManual: "要判断 1件", remediation.PRStatusFailed: "失敗 1件",
		}[status]
		if !strings.Contains(got, "\n"+want+"\n") || strings.Contains(got, "更新候補 1件") || !strings.Contains(got, "⚠️ メジャーバージョンの変更") {
			t.Errorf("%s: summary in\n%s", status, got)
		}
	}
	// A manual image with a candidate is one decision, not a decision and a candidate.
	p := slackPlanFixture()
	p.Items = []remediation.Item{p.Items[6]}
	p.Items[0].Candidate = &remediation.ImageState{Ref: "db:15.2", Tag: "15.2"}
	p.Items[0].Kind = remediation.TagPinned
	p.PullRequests, p.LanguageItems, p.DockerfileItems = nil, nil, nil
	if got := slackPlanText(planReport(), &PlanInfo{Plan: &p}, LanguageJA); !strings.Contains(got, "\n要判断 1件\n") || strings.Contains(got, "更新候補 1件") {
		t.Errorf("manual image with a candidate:\n%s", got)
	}
}
