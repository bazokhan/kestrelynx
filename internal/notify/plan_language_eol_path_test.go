package notify

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// pathRegistry and pathScanner are never asked anything: the plan holds only
// a dependency unit.
type pathRegistry struct{}

func (pathRegistry) ListTagsUpTo(context.Context, string, int) (registry.TagList, error) {
	return registry.TagList{}, nil
}

func (pathRegistry) Resolve(context.Context, string, string, inventory.Platform) (registry.Resolution, error) {
	return registry.Resolution{}, nil
}

type pathScanner struct{}

func (pathScanner) Scan(context.Context, scanner.ScanTarget) scanner.ImageScan {
	return scanner.ImageScan{}
}
func (pathScanner) VerifyDB(context.Context, scanner.ScanConditions) (bool, error) { return true, nil }

func blobSum(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// pathGitHub serves the files of one directory.
type pathGitHub struct{ files map[string]string }

func (pathGitHub) ResolveBranch(context.Context, string, string) (string, error) {
	return "0123456789abcdef0123456789abcdef01234567", nil
}

func (g pathGitHub) ListDirectory(_ context.Context, _, _, dir string) ([]github.Entry, error) {
	var out []github.Entry
	if dir != "web" {
		return nil, nil
	}
	for name, c := range g.files {
		out = append(out, github.Entry{Name: name, Path: "web/" + name, Type: github.EntryFile, SHA: blobSum(name + c)})
	}
	return out, nil
}

func (g pathGitHub) ReadFile(_ context.Context, _, _, p string) (github.File, error) {
	c, ok := g.files[strings.TrimPrefix(p, "web/")]
	if !ok {
		return github.File{}, github.ErrNotFound
	}
	return github.File{Path: p, SHA: blobSum(strings.TrimPrefix(p, "web/") + c), Content: []byte(c)}, nil
}

// A project whose .nvmrc asks for Node.js 20 is planned as past the end of
// the runtime's support, and the Slack line and the webhook say so with the
// date.
func TestPlan_DeclaredEndOfLifeRuntimeFromPlanToNotification(t *testing.T) {
	gh := pathGitHub{files: map[string]string{
		"package.json": `{"name":"backend","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}}`,
		"package-lock.json": `{"name":"backend","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"backend","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}},
"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz","integrity":"sha512-aa=="}}}`,
		".nvmrc": "20\n",
	}}
	planner, err := remediation.NewPlanner(remediation.Config{
		Registry: pathRegistry{}, Scanner: pathScanner{}, Limits: remediation.Limits{MaxCandidateScans: 1, MaxBaselineRescans: 1, MaxTagPages: 1},
		GitHub: gh, Dependencies: []remediation.DependencyMapping{{Workload: "compose/shop/api", Project: "shop", Service: "api", Repository: "ex/app", BaseBranch: "main", Directory: "web"}},
		Now: func() time.Time { return time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := inventory.ParseDigest(inventory.DigestConfig, "sha256:"+strings.Repeat("a", 64))
	key := inventory.EntityKey{Digest: d}
	scan := scanner.ImageScan{
		Image: "shop-api:1", OSFamily: "debian", Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, Pinned: true, Source: scanner.SourceLocal,
		RegistryDigests: []string{"example@sha256:" + strings.Repeat("d", 64)},
		Subject:         inventory.ImageSubject{Ref: "shop-api:1", Key: key, Resolved: true}, ScannedKey: key,
		Findings: []scanner.Finding{{Class: inventory.ClassLang, Type: "node-pkg", Target: "Node.js", Package: "lodash", InstalledVer: "4.17.20", FixedVer: "4.17.21",
			Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1"}},
	}
	plan := planner.Plan(context.Background(), []remediation.ImageInput{{Scan: scan, Services: []remediation.ServiceRef{{Project: "shop", Service: "api", Container: "shop-api-1"}}}})
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("items = %d", len(plan.LanguageItems))
	}
	li := plan.LanguageItems[0]
	if li.Category != remediation.CategoryManual || li.Reason != remediation.ReasonRuntimeEndOfLife || li.RuntimeEOL == nil {
		t.Fatalf("item = %s / %s / %+v (%s)", li.Category, li.Reason, li.RuntimeEOL, li.Detail)
	}

	r, changed, _ := planCycleFixture()
	info := &PlanInfo{Plan: &plan, Changed: true}
	for lang, want := range map[Language]string{
		LanguageEN: "Node.js 20 reached the end of its support on 2026-04-30; upgrade the runtime before updating",
		LanguageJA: "Node.js 20 は 2026-04-30 にサポート終了。実行環境を上げてから更新してください",
	} {
		if got := slackPlanText(r, info, lang); !strings.Contains(got, want) {
			t.Errorf("%s: the line is missing:\n%s", lang, got)
		}
	}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, info))["remediation"].(map[string]any)
	first := rem["language_items"].([]any)[0].(map[string]any)
	eol, _ := first["runtime_eol"].(map[string]any)
	if first["reason"] != "runtime_eol" || eol["id"] != "node20" || eol["name"] != "Node.js 20" || eol["eol"] != "2026-04-30" {
		t.Errorf("webhook item = %v", first)
	}
}
