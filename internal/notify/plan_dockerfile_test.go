package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func dfTarget(id string, kev bool, layer string) remediation.Target {
	return remediation.Target{VulnID: id, Package: remediation.PackageCoord{Name: "libc"}, FixedVers: []string{"2"}, KEV: kev, Layers: []string{layer}}
}

// dockerfileEntity is a running image of an edit location whose base layers
// were confirmed, with a comparison that resolves the listed vulnerabilities
// and leaves one.
func dockerfileEntity(resolved ...string) remediation.DockerfileEntity {
	en := remediation.DockerfileEntity{
		Services:      []remediation.ServiceRef{{Project: "shop", Service: "app", Container: "shop-app-1"}},
		Running:       remediation.ImageState{Ref: "shop-app:1", Entity: "config:sha256:aa", ConfigDigest: "sha256:aa", Platform: "linux/amd64", DigestKindUnverified: true},
		CurrentBase:   &remediation.ImageState{Ref: "python:3.12.3-slim", Tag: "3.12.3-slim", ConfigDigest: "sha256:b1", ManifestDigest: "sha256:b2", TopDigest: "sha256:b3", Platform: "linux/amd64"},
		CandidateBase: &remediation.ImageState{Ref: "python:3.12.5-slim", Tag: "3.12.5-slim", ConfigDigest: "sha256:c1", ManifestDigest: "sha256:c2", TopDigest: "sha256:c3", Platform: "linux/amd64"},
		Layers:        remediation.LayerConfirmation{Status: "confirmed", BaseLayers: 2, ImageLayers: 3},
		Findings:      remediation.LayerCounts{Base: 3, Upper: 1, Unknown: 1},
		Category:      remediation.CategoryPRCandidate, Reason: remediation.ReasonAdopted,
		BaselineScan: "s1", CandidateScan: "s2",
		Comparison: &remediation.VerificationResult{Comparable: true, Scope: "HIGH,CRITICAL"},
	}
	for i, id := range resolved {
		en.Targets = append(en.Targets, dfTarget(id, i == 0, "sha256:l1"))
		en.Comparison.Verdicts = append(en.Comparison.Verdicts, remediation.VulnVerdict{
			VulnID: id, Package: remediation.PackageCoord{Name: "libc"}, Severity: scanner.SeverityHigh, Outcome: remediation.OutcomeResolved})
	}
	en.Targets = append(en.Targets, dfTarget("CVE-2031-0900", false, "sha256:l2"))
	en.Comparison.Verdicts = append(en.Comparison.Verdicts, remediation.VulnVerdict{
		VulnID: "CVE-2031-0900", Package: remediation.PackageCoord{Name: "libc"}, Severity: scanner.SeverityHigh, Outcome: remediation.OutcomeRemaining})
	// A finding of the base the running image does not have is not a verdict
	// about it.
	en.Comparison.Verdicts = append(en.Comparison.Verdicts, remediation.VulnVerdict{
		VulnID: "CVE-2031-0999", Package: remediation.PackageCoord{Name: "other"}, Severity: scanner.SeverityHigh, Outcome: remediation.OutcomeResolved})
	en.Decision = &remediation.Decision{Kind: remediation.DecisionAdoptPartial, Propose: true, Targets: len(en.Targets), Resolved: len(resolved), Remaining: 1}
	return en
}

func dockerfileSource() remediation.DockerfileSource {
	stage := 0
	return remediation.DockerfileSource{
		Repository: "ex/app", BaseBranch: "main", CommitSHA: strings.Repeat("a", 40), Path: "docker/Dockerfile", Targets: []string{"runtime"},
		Origin: remediation.DockerfileFromMapping, Files: []remediation.SourceFile{{Path: "docker/Dockerfile", BlobSHA: strings.Repeat("b", 40)}},
		Stage: &stage, StageName: "runtime", Line: 3,
	}
}

// dockerfileFixture is a plan with only Dockerfile items: an adopted base
// update that resolves 12 of 40 base findings, an update that introduces a
// KEV-listed vulnerability, a floating base the image can no longer be tied
// to, and a floating base that has not changed.
func dockerfileFixture() remediation.Plan {
	p := planFixture()
	p.Items = nil
	p.Scans = []remediation.ScanExecution{
		{ID: "s1", Role: remediation.RoleBaseline, Ref: "python:3.12.3-slim", DB: remediation.DBVerified},
		{ID: "s2", Role: remediation.RoleCandidate, Ref: "python:3.12.5-slim", DB: remediation.DBVerified},
	}
	adopted := remediation.DockerfileItem{
		Key: "dockerfile:ex/app@main:docker/Dockerfile#stages[0]:runtime", Workloads: []string{"compose/shop/app"}, Priority: remediation.PriorityActNow,
		Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonAdopted, Source: dockerfileSource(),
		BaseRef: "python:3.12.3-slim", BaseKind: remediation.TagPinned,
		Candidate: &remediation.ImageState{Ref: "python:3.12.5-slim", Tag: "3.12.5-slim", TopDigest: "sha256:c3", Platform: "linux/amd64"},
		Entities:  []remediation.DockerfileEntity{dockerfileEntity("CVE-2031-0001", "CVE-2031-0002")},
		Counts:    remediation.DockerfileCounts{Targets: 40, Resolved: 12, Remaining: 28},
	}
	kev := remediation.DockerfileItem{
		Key: "dockerfile:ex/app@main:Dockerfile#stages[0]", Workloads: []string{"compose/shop/worker"},
		Category: remediation.CategoryManual, Reason: remediation.ReasonIntroducedKEV, Source: dockerfileSource(),
		BaseRef: "node:20.1.0-slim", BaseKind: remediation.TagPinned,
		Candidate: &remediation.ImageState{Ref: "node:20.1.4-slim", Tag: "20.1.4-slim"},
	}
	floating := remediation.DockerfileItem{
		Key: "dockerfile:ex/app@main:web/Dockerfile#stages[0]", Workloads: []string{"compose/shop/web"},
		Category: remediation.CategoryNotComparable, Reason: remediation.ReasonFloatingBaseUnconfirmed, Source: dockerfileSource(),
		BaseRef: "python:3.12-slim", BaseKind: remediation.TagFloating,
		Detail: "the tag no longer points at the layers the running image starts with",
	}
	unchanged := remediation.DockerfileItem{
		Key: "dockerfile:ex/app@main:cron/Dockerfile#stages[0]", Workloads: []string{"compose/shop/cron"},
		Category: remediation.CategoryNoCandidate, Reason: remediation.ReasonBaseUnchanged, Source: dockerfileSource(),
		BaseRef: "python:3.12-slim", BaseKind: remediation.TagFloating,
	}
	p.DockerfileItems = []remediation.DockerfileItem{adopted, kev, floating, unchanged}
	return p
}

func dockerfileInfo() *PlanInfo {
	p := dockerfileFixture()
	return &PlanInfo{Plan: &p, Changed: true}
}

func TestWebhook_DockerfileItems(t *testing.T) {
	r, changed, _ := planCycleFixture()
	with := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, dockerfileInfo()))
	rem := with["remediation"].(map[string]any)

	// Without Dockerfile items the payload has none of the new keys, and the
	// image part is the same.
	imageOnly := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, planInfoFixture()))["remediation"].(map[string]any)
	for _, k := range []string{"dockerfile_items", "dockerfile_summary"} {
		if _, ok := imageOnly[k]; ok {
			t.Errorf("%s present without Dockerfile items", k)
		}
	}
	// The image summary counts image items only.
	if a, b := fmt.Sprint(rem["summary"]), fmt.Sprint(imageOnly["summary"]); a == b {
		t.Errorf("summary = %s, the same as the image fixture's", a)
	}
	for _, k := range []string{"items", "usage", "limits", "conditions"} {
		if _, ok := rem[k]; !ok {
			t.Errorf("existing key %q is gone", k)
		}
	}

	sum := rem["dockerfile_summary"].(map[string]any)
	for cat, n := range map[string]float64{"pr_candidate": 1, "pull_again": 0, "manual": 1, "not_comparable": 1, "no_candidate": 1, "excluded": 0, "deferred": 0, "failed": 0} {
		if sum[cat] != n {
			t.Errorf("dockerfile_summary[%s] = %v, want %v", cat, sum[cat], n)
		}
	}
	items := rem["dockerfile_items"].([]any)
	if len(items) != 4 {
		t.Fatalf("dockerfile_items = %d", len(items))
	}
	first := items[0].(map[string]any)
	if first["kind"] != "dockerfile" || first["fix_class"] != "base_image" || first["verification"] != "base_image_comparison" || first["final_image_verified"] != false ||
		first["category"] != "pr_candidate" || first["base_ref"] != "python:3.12.3-slim" || first["base_kind"] != "pinned" {
		t.Errorf("first = %v", first)
	}
	if c := first["counts"].(map[string]any); c["targets"] != float64(40) || c["resolved"] != float64(12) || c["remaining"] != float64(28) {
		t.Errorf("counts = %v", c)
	}
	src := first["source"].(map[string]any)
	if src["repository"] != "ex/app" || src["path"] != "docker/Dockerfile" || src["commit_sha"] != strings.Repeat("a", 40) || src["stage"] != float64(0) || src["origin"] != "mapping" {
		t.Errorf("source = %v", src)
	}
	ents := first["entities"].([]any)
	en := ents[0].(map[string]any)
	// The three images are kept apart.
	run, cur, cand := en["running_image"].(map[string]any), en["current_base"].(map[string]any), en["candidate_base"].(map[string]any)
	if run["ref"] != "shop-app:1" || run["content"] != "config:sha256:aa" || cur["ref"] != "python:3.12.3-slim" || cur["manifest_digest"] != "sha256:b2" ||
		cand["ref"] != "python:3.12.5-slim" || cand["top_digest"] != "sha256:c3" {
		t.Errorf("images = %v / %v / %v", run, cur, cand)
	}
	if _, has := cur["content"]; has {
		t.Error("a base image carries a running entity")
	}
	lc := en["layer_confirmation"].(map[string]any)
	if lc["status"] != "confirmed" || lc["base_layers"] != float64(2) || lc["image_layers"] != float64(3) {
		t.Errorf("layer_confirmation = %v", lc)
	}
	if fl := en["findings_by_layer"].(map[string]any); fl["base"] != float64(3) || fl["upper"] != float64(1) || fl["unknown"] != float64(1) {
		t.Errorf("findings_by_layer = %v", fl)
	}
	cmp := en["comparison"].(map[string]any)
	if cmp["decision"] != "adopt_partial" || cmp["resolved"] != float64(2) || cmp["remaining"] != float64(1) {
		t.Errorf("comparison = %v", cmp)
	}
	// Only the findings the running image has are listed as verdicts.
	for _, v := range cmp["verdicts"].([]any) {
		if v.(map[string]any)["vuln_id"] == "CVE-2031-0999" {
			t.Errorf("a finding of the base the image does not have is listed: %v", v)
		}
	}
	if en["kev_targets"] != float64(1) || len(en["scans"].([]any)) != 2 {
		t.Errorf("entity = %v", en)
	}

	// The floating item carries no counts, candidate or comparison.
	fl := items[2].(map[string]any)
	if fl["reason"] != "floating_base_unconfirmed" || fl["base_kind"] != "floating" || fl["candidate"] != nil {
		t.Errorf("floating = %v", fl)
	}
	if c := fl["counts"].(map[string]any); c["targets"] != float64(0) || c["resolved"] != float64(0) {
		t.Errorf("floating counts = %v", c)
	}
}

func TestWebhook_DockerfilePullRequest(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := dockerfileFixture()
	p.PullRequests = []remediation.PRUnit{{
		Kind: "dockerfile", Key: "k", Repo: "ex/app", BaseBranch: "main", Path: "docker/Dockerfile", Services: []string{"app"},
		Locations: []string{"stages[0]:runtime"}, Workloads: []string{"compose/shop/app"}, Current: "python:3.12.3-slim", CandidateTag: "3.12.5-slim",
		Status: remediation.PRStatusCreated, Number: 7, URL: "https://github.com/ex/app/pull/7", State: remediation.PRStateOpen,
		FixTargets: []remediation.FixTarget{{Location: "stages[0]:runtime", VulnID: "CVE-2031-0001", Package: remediation.PackageCoord{Name: "libc"}}},
	}, {
		Key: "compose", Repo: "ex/app", BaseBranch: "main", Path: "compose.yml", Services: []string{"web"}, Current: "nginx:1.25.3", Status: remediation.PRStatusOpen, Number: 3,
	}}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	prs := rem["pull_requests"].([]any)
	if prs[0].(map[string]any)["kind"] != "dockerfile" {
		t.Errorf("pull request 0 = %v", prs[0])
	}
	if _, has := prs[1].(map[string]any)["kind"]; has {
		t.Error("a Compose pull request names a kind")
	}
	pr := rem["dockerfile_items"].([]any)[0].(map[string]any)["pull_request"].(map[string]any)
	if pr["status"] != "pr_created" || pr["number"] != float64(7) || pr["url"] != "https://github.com/ex/app/pull/7" || pr["state"] != "open" {
		t.Errorf("pull_request = %v", pr)
	}
	if _, has := rem["dockerfile_items"].([]any)[1].(map[string]any)["pull_request"]; has {
		t.Error("an item without a unit has a pull request")
	}
}

func dockerfilePRInfo() *PlanInfo {
	p := dockerfileFixture()
	p.PullRequests = []remediation.PRUnit{{
		Kind: "dockerfile", Key: "dockerfile|ex/app|main|docker/Dockerfile|stages[0]:runtime", Repo: "ex/app", BaseBranch: "main", Path: "docker/Dockerfile",
		Services: []string{"app"}, Locations: []string{"stages[0]:runtime"}, Workloads: []string{"compose/shop/app"},
		Current: "python:3.12.3-slim", CandidateTag: "3.12.5-slim", Status: remediation.PRStatusCreated, Number: 7, URL: "https://github.com/ex/app/pull/7", State: remediation.PRStateOpen,
	}}
	return &PlanInfo{Plan: &p, Changed: true}
}

// TestDockerfileKEVCountsPerEntityTargets: a KEV-listed target of one image
// counts as resolved when that image resolves it, whatever the others have.
func TestDockerfileKEVCountsPerEntityTargets(t *testing.T) {
	a, b := dockerfileEntity("CVE-2031-0001"), dockerfileEntity("CVE-2031-0002")
	b.Targets[0].KEV, a.Targets[1].KEV, b.Targets[1].KEV = true, false, false
	it := remediation.DockerfileItem{Entities: []remediation.DockerfileEntity{a, b}}
	// Only the first of a's targets and the first of b's are KEV; each is
	// resolved on the image that has it.
	if n := dockerfileKEVResolved(it); n != 2 {
		t.Errorf("KEV resolved = %d, want 2", n)
	}
}
