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
