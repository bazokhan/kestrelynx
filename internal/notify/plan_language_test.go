package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func langOcc(path, ver string, direct bool) remediation.SourceOccurrence {
	return remediation.SourceOccurrence{Path: path, Version: ver, Direct: direct, Matched: true}
}

func langPkg(name, installed, target string, kev bool) remediation.LanguagePackage {
	return remediation.LanguagePackage{
		Origins: []remediation.FindingOrigin{{Entity: "config:sha256:aa", Ecosystem: "node-pkg", Class: "lang", Name: name, Version: installed,
			VulnID: "CVE-2032-0001", Target: "Node.js", PkgPath: "app/node_modules/" + name + "/package.json", Workload: "compose/shop/api"}},
		Name: name, Ecosystem: "node-pkg", Installed: installed, SelectionLowerBound: target,
		Relation: remediation.RelationDirect, Action: remediation.ActionUpdate, Reason: remediation.ReasonUpdateCandidateInSource,
		Occurrences: []remediation.SourceOccurrence{langOcc("node_modules/"+name, installed, true)},
		CVEs:        []remediation.CVERef{{VulnID: "CVE-2032-0001", Severity: scanner.SeverityHigh, FixedVers: []string{target}, KEV: kev}},
	}
}

func langSource(dir string) remediation.SourceRecord {
	return remediation.SourceRecord{
		Repository: "ex/app", BaseBranch: "main", Directory: dir, CommitSHA: strings.Repeat("a", 40),
		Files: []remediation.SourceFile{
			{Path: dir + "/package.json", BlobSHA: strings.Repeat("b", 40)},
			{Path: dir + "/package-lock.json", BlobSHA: strings.Repeat("c", 40)},
		},
		Origin: remediation.OriginConfig, Confidence: remediation.ConfidenceAsserted,
	}
}

// languageFixture is the image fixture plan with dependency units added: an
// npm candidate with three packages (one KEV-listed), a pip unit that expects
// a rebuild, a manual unit and a deferred one.
func languageFixture() remediation.Plan {
	p := planFixture()
	p.LanguageItems = []remediation.LanguageItem{
		{
			Key: "deps:ex/app@main:backend", Workloads: []string{"compose/shop/api"}, Manager: remediation.ManagerNpm,
			Priority: remediation.PriorityActNow, Category: remediation.CategoryDependencyUpdateCandidate, Reason: remediation.ReasonUpdateCandidateInSource,
			Detail: "3 of 3 packages have a target version in the dependency files; the update and its post-update check were not run",
			Source: langSource("backend"),
			Packages: []remediation.LanguagePackage{
				langPkg("express", "4.18.2", "4.19.2", true),
				langPkg("lodash", "4.17.20", "4.17.21", false),
				langPkg("qs", "6.11.0", "6.11.3", false),
				{Name: "ghost", Ecosystem: "node-pkg", Installed: "1.0.0", Action: remediation.ActionManual, Reason: remediation.ReasonNotFoundInSource},
			},
		},
		{
			Key: "deps:ex/py@main:.", Workloads: []string{"compose/shop/worker"}, Manager: remediation.ManagerPip,
			Category: remediation.CategoryRebuildExpected, Reason: remediation.ReasonRangeAllowsFix, Source: langSource("."),
			Packages: []remediation.LanguagePackage{{Name: "urllib3", Ecosystem: "python-pkg", Installed: "1.26.5", SelectionLowerBound: "1.26.18",
				Action: remediation.ActionRebuildExpected, Reason: remediation.ReasonRangeAllowsFix}},
		},
		{
			Key: "deps:ex/old@main:.", Workloads: []string{"compose/shop/old"}, Manager: remediation.ManagerNpm,
			Category: remediation.CategoryManual, Reason: remediation.ReasonUnsupportedLockfile, Detail: "package-lock.json has lockfileVersion 1", Source: langSource("."),
		},
		{
			Key: "deps:ex/more@main:.", Workloads: []string{"compose/shop/more"}, Category: remediation.CategoryDeferred, Reason: remediation.ReasonRateLimited, Source: langSource("."),
		},
	}
	return p
}

func languageInfo() *PlanInfo {
	p := languageFixture()
	return &PlanInfo{Plan: &p, Changed: true}
}

// languageCompactInfo is the fixture with a single image item, so that every
// dependency line fits within the listed-lines cap.
func languageCompactInfo() *PlanInfo {
	p := languageFixture()
	p.Items = p.Items[:1]
	return &PlanInfo{Plan: &p, Changed: true}
}

func TestPlanSection_LanguageLines(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		lang Language
		line string
		segs []string
	}{
		{LanguageEN, "api (package-lock.json): express 4.18.2 → 4.19.2 and 2 more — update not run yet (1 KEV)", []string{"1 dependency update candidate(s)", "1 rebuild expected"}},
		{LanguageJA, "api (package-lock.json): express 4.18.2 → 4.19.2 ほか2件 — 更新は未実行 (KEV 1件)", []string{"依存更新候補 1件", "再ビルドで解消見込み 1件"}},
	} {
		t.Run(string(c.lang), func(t *testing.T) {
			got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: languageInfo()}, ChannelFooter{}, c.lang))
			for _, want := range append([]string{c.line}, c.segs...) {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in\n%s", want, got)
				}
			}
			msg := messagesFor(c.lang)
			// The manual unit and the deferred unit are counted with the
			// image ones (1 image + 1 language each), not listed.
			for _, want := range []string{fmt.Sprintf(msg.PlanSegManual, 2), fmt.Sprintf(msg.PlanSegDeferred, 2)} {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in\n%s", want, got)
				}
			}
			for _, not := range []string{"urllib3", "ghost", "lockfileVersion"} {
				if strings.Contains(got, not) {
					t.Errorf("%q should be counted, not listed:\n%s", not, got)
				}
			}
		})
	}
}

func TestPlanSection_LanguageSingleCandidateHasNoMoreClause(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	p.LanguageItems = p.LanguageItems[:1]
	p.LanguageItems[0].Packages = []remediation.LanguagePackage{langPkg("lodash", "4.17.20", "4.17.21", false)}
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	want := "api (package-lock.json): lodash 4.17.20 → 4.17.21 — update not run yet"
	if !strings.Contains(got, want) || strings.Contains(got, "lodash 4.17.20 → 4.17.21 and") {
		t.Errorf("want %q without an 'and more' clause in\n%s", want, got)
	}
}

func TestPlanSection_LanguageOnlyPlanIsShown(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	p.Items = nil
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p}}, ChannelFooter{}, LanguageEN))
	if !strings.Contains(got, "express 4.18.2 → 4.19.2") {
		t.Errorf("a plan with only dependency units has no section:\n%s", got)
	}
}

func TestPlanSection_LanguageSharesTheLineCap(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	for i := 0; i < 4; i++ {
		li := p.LanguageItems[0]
		li.Key = fmt.Sprintf("deps:ex/app@main:svc%d", i)
		li.Workloads = []string{fmt.Sprintf("compose/shop/svc%d", i)}
		p.LanguageItems = append(p.LanguageItems, li)
	}
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	// Two image lines and five unit lines are candidates: three are listed.
	if n := strings.Count(got, "update not run yet"); n > slackTopItems {
		t.Errorf("%d dependency lines listed, cap is %d", n, slackTopItems)
	}
	if !strings.Contains(got, fmt.Sprintf("%d more", 7-slackTopItems)) && !strings.Contains(got, "more") {
		t.Errorf("no count of the unlisted lines:\n%s", got)
	}
}

func TestPlanSection_LanguageEscapesExternalValues(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	p.LanguageItems[0].Workloads = []string{"compose/shop/<!channel>"}
	p.LanguageItems[0].Packages[1].Name = "<!here>"
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	if strings.Contains(got, "<!channel>") || strings.Contains(got, "<!here>") {
		t.Errorf("a mention got through:\n%s", got)
	}
}

func TestPlanSection_LanguageGoldenBlocks(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for _, c := range []struct {
		name string
		lang Language
		m    Message
	}{
		{"plan_lang_en_diff", LanguageEN, Message{Report: r, Diff: &changed, Plan: languageCompactInfo()}},
		{"plan_lang_ja_diff", LanguageJA, Message{Report: r, Diff: &changed, Plan: languageCompactInfo()}},
		{"plan_lang_en_full", LanguageEN, Message{Report: r, Plan: languageCompactInfo()}},
		{"plan_lang_ja_full", LanguageJA, Message{Report: r, Plan: languageCompactInfo()}},
	} {
		t.Run(c.name, func(t *testing.T) {
			msgs := buildChannelMessages(c.m, ChannelFooter{}, messagesFor(c.lang), defaultRenderLimits)
			checkBlockGolden(t, c.name, "txt", dumpMessages(msgs))
		})
	}
}

func TestPlanSection_RebuildExpectedLines(t *testing.T) {
	r, changed, _ := planCycleFixture()
	for lang, want := range map[Language]string{
		LanguageEN: "worker (requirements.txt): urllib3 1.26.5 — rebuilding is expected to pick up ≥1.26.18",
		LanguageJA: "worker (requirements.txt): urllib3 1.26.5 — 再ビルドで 1.26.18 以上が入る見込み",
	} {
		got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: languageCompactInfo()}, ChannelFooter{}, lang))
		if !strings.Contains(got, want) {
			t.Errorf("%s: missing %q in\n%s", lang, want, got)
		}
	}

	// A second package of the unit is counted, and the line shares the cap.
	p := languageFixture()
	p.LanguageItems[1].Packages = append(p.LanguageItems[1].Packages, remediation.LanguagePackage{
		Name: "idna", Installed: "3.4", SelectionLowerBound: "3.7", Action: remediation.ActionRebuildExpected})
	got := allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	if strings.Contains(got, "urllib3 1.26.5 and 1 more") {
		// listed lines: 2 image + dependency + rebuild = 4, cap 3
		t.Errorf("the fourth line got past the cap:\n%s", got)
	}
	p.Items = p.Items[:1]
	got = allBlocksText(BuildChannelMessages(Message{Report: r, Diff: &changed, Plan: &PlanInfo{Plan: &p, Changed: true}}, ChannelFooter{}, LanguageEN))
	if !strings.Contains(got, "urllib3 1.26.5 and 1 more — rebuilding is expected to pick up ≥1.26.18") {
		t.Errorf("no 'and more' clause on the rebuild line:\n%s", got)
	}
	// A unit that expects a rebuild is not described as an update candidate.
	if strings.Contains(got, "urllib3 1.26.5 → ") {
		t.Errorf("rebuild line worded as an update:\n%s", got)
	}
}

func TestWebhook_LanguageItems(t *testing.T) {
	r, changed, _ := planCycleFixture()
	with := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, languageInfo()))
	rem := with["remediation"].(map[string]any)

	// The image part of the payload is untouched by the language items.
	imageOnly := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, planInfoFixture()))["remediation"].(map[string]any)
	if a, b := fmt.Sprint(rem["summary"]), fmt.Sprint(imageOnly["summary"]); a != b {
		t.Errorf("summary changed: %s vs %s", a, b)
	}
	if _, ok := imageOnly["language_items"]; ok {
		t.Error("language_items present without dependency units")
	}
	if _, ok := imageOnly["language_summary"]; ok {
		t.Error("language_summary present without dependency units")
	}

	sum := rem["language_summary"].(map[string]any)
	for cat, n := range map[string]float64{"dependency_update_candidate": 1, "rebuild_expected": 1, "manual": 1, "deferred": 1, "failed": 0} {
		if sum[cat] != n {
			t.Errorf("language_summary[%s] = %v, want %v", cat, sum[cat], n)
		}
	}
	items := rem["language_items"].([]any)
	if len(items) != 4 {
		t.Fatalf("language_items = %d", len(items))
	}
	first := items[0].(map[string]any)
	if first["category"] != "dependency_update_candidate" || first["reason"] != "update_candidate_in_source" || first["manager"] != "npm" ||
		first["update_executed"] != false || first["post_update_check_executed"] != false || first["package_count"] != float64(4) {
		t.Errorf("first = %v", first)
	}
	src := first["source"].(map[string]any)
	if src["commit_sha"] != strings.Repeat("a", 40) || src["origin"] != "config" || src["confidence"] != "asserted" ||
		src["repository"] != "ex/app" || src["base_branch"] != "main" || src["directory"] != "backend" {
		t.Errorf("source = %v", src)
	}
	files := src["files"].([]any)
	if f := files[1].(map[string]any); f["path"] != "backend/package-lock.json" || f["blob_sha"] != strings.Repeat("c", 40) {
		t.Errorf("files = %v", files)
	}
	pkgs := first["packages"].([]any)
	lodash := pkgs[1].(map[string]any)
	if lodash["name"] != "lodash" || lodash["installed"] != "4.17.20" || lodash["selection_lower_bound"] != "4.17.21" ||
		lodash["relation"] != "direct" || lodash["action"] != "update" || lodash["occurrence_count"] != float64(1) {
		t.Errorf("lodash = %v", lodash)
	}
	if _, ok := lodash["adopted_version"]; ok {
		t.Error("an adopted version is reported although nothing was run")
	}
	occ := lodash["occurrences"].([]any)[0].(map[string]any)
	if occ["path"] != "node_modules/lodash" || occ["direct"] != true {
		t.Errorf("occurrence = %v", occ)
	}
	org := lodash["origins"].([]any)[0].(map[string]any)
	if lodash["origin_count"] != float64(1) || org["entity"] != "config:sha256:aa" || org["workload"] != "compose/shop/api" ||
		org["vuln_id"] != "CVE-2032-0001" || org["pkg_path"] != "app/node_modules/lodash/package.json" || org["target"] != "Node.js" {
		t.Errorf("origins = %v", lodash["origins"])
	}
	if exp := pkgs[0].(map[string]any); exp["kev_count"] != float64(1) {
		t.Errorf("express = %v", exp)
	}
	if ghost := pkgs[3].(map[string]any); ghost["action"] != "manual" || ghost["reason"] != "not_found_in_source" {
		t.Errorf("ghost = %v", ghost)
	}
	if m := items[2].(map[string]any); m["reason"] != "unsupported_lockfile" || m["detail"] == "" {
		t.Errorf("manual unit = %v", m)
	}
}

func TestWebhook_LanguageSummaryCountsEveryCategory(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	p.LanguageItems = append(p.LanguageItems,
		remediation.LanguageItem{Key: "deps:ex/u@main:.#unverified", Workloads: []string{"compose/shop/u"}, Category: remediation.CategoryNotComparable,
			Reason: remediation.ReasonScanNotPinned, Source: langSource("."), Packages: []remediation.LanguagePackage{{Name: "lodash", Ecosystem: "node-pkg", Installed: "4.17.20"}}},
		remediation.LanguageItem{Key: "deps:ex/f@main:.#node-pkg", Workloads: []string{"compose/shop/f"}, Category: remediation.CategoryFailed,
			Reason: remediation.ReasonSourceNotFound, Source: langSource(".")})
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p}))["remediation"].(map[string]any)
	sum := rem["language_summary"].(map[string]any)
	want := map[string]float64{"dependency_update_candidate": 1, "rebuild_expected": 1, "manual": 1, "not_comparable": 1, "deferred": 1, "failed": 1}
	total := 0.0
	for cat, n := range want {
		if sum[cat] != n {
			t.Errorf("language_summary[%s] = %v, want %v", cat, sum[cat], n)
		}
		total += n
	}
	got := 0.0
	for _, n := range sum {
		got += n.(float64)
	}
	if got != float64(len(p.LanguageItems)) || total != float64(len(p.LanguageItems)) {
		t.Errorf("the summary counts %v items of %d", got, len(p.LanguageItems))
	}
	items := rem["language_items"].([]any)
	if last := items[len(items)-2].(map[string]any); last["category"] != "not_comparable" || last["reason"] != "scan_not_pinned" {
		t.Errorf("unverified item = %v", last)
	}
}

func TestWebhook_LanguageListsAreCapped(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := p.LanguageItems[0]
	li.Packages = nil
	for i := 0; i < maxWebhookPackages+5; i++ {
		pk := langPkg(fmt.Sprintf("pkg%03d", i), "1.0.0", "1.0.1", false)
		if i == 0 {
			for j := 0; j < maxWebhookOccurrences+3; j++ {
				pk.Occurrences = append(pk.Occurrences, langOcc(fmt.Sprintf("node_modules/x%d/node_modules/pkg000", j), "1.0.0", false))
			}
			for j := 0; j < maxWebhookOrigins+3; j++ {
				pk.Origins = append(pk.Origins, remediation.FindingOrigin{Entity: "e", Name: "pkg000", Version: "1.0.0", VulnID: fmt.Sprintf("CVE-%d", j), Workload: "compose/shop/api"})
			}
			for j := 0; j < maxWebhookCVEs+2; j++ {
				pk.CVEs = append(pk.CVEs, remediation.CVERef{VulnID: fmt.Sprintf("CVE-2032-%04d", j+10)})
			}
		}
		li.Packages = append(li.Packages, pk)
	}
	p.LanguageItems = []remediation.LanguageItem{li}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p}))["remediation"].(map[string]any)
	item := rem["language_items"].([]any)[0].(map[string]any)
	pkgs := item["packages"].([]any)
	if len(pkgs) != maxWebhookPackages || item["packages_truncated"] != true || item["package_count"] != float64(maxWebhookPackages+5) {
		t.Errorf("packages = %d, truncated = %v, count = %v", len(pkgs), item["packages_truncated"], item["package_count"])
	}
	first := pkgs[0].(map[string]any)
	if len(first["occurrences"].([]any)) != maxWebhookOccurrences || first["occurrences_truncated"] != true || first["occurrence_count"] != float64(maxWebhookOccurrences+4) {
		t.Errorf("occurrences = %d, truncated = %v, count = %v", len(first["occurrences"].([]any)), first["occurrences_truncated"], first["occurrence_count"])
	}
	if len(first["origins"].([]any)) != maxWebhookOrigins || first["origins_truncated"] != true || first["origin_count"] != float64(maxWebhookOrigins+4) {
		t.Errorf("origins = %d, truncated = %v, count = %v", len(first["origins"].([]any)), first["origins_truncated"], first["origin_count"])
	}
	if len(first["cves"].([]any)) != maxWebhookCVEs || first["cves_truncated"] != true {
		t.Errorf("cves = %d, truncated = %v", len(first["cves"].([]any)), first["cves_truncated"])
	}
	if second := pkgs[1].(map[string]any); second["occurrences_truncated"] != nil || second["packages_truncated"] != nil {
		t.Errorf("a short list was marked truncated: %v", second)
	}
	if _, err := json.Marshal(rem); err != nil {
		t.Error(err)
	}
}
