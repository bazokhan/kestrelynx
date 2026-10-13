package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// seenDaysAgo builds a firstSeen lookup that reports every finding as first
// seen the given number of days before genTime.
func seenDaysAgo(days int) func(image, pkg string) (time.Time, bool) {
	return func(image, pkg string) (time.Time, bool) {
		return genTime.AddDate(0, 0, -days), true
	}
}

func TestThread_TriageLayout(t *testing.T) {
	msgs := BuildThreadBlockMessages(triageReport(), Ages{Finding: seenDaysAgo(3)}, LanguageEN)
	if len(msgs) != 1 {
		t.Fatalf("expected one message, got %d", len(msgs))
	}
	out := allBlocksText(msgs)

	mustContain := []string{
		"📊 *Everything open now — 2026-06-24 09:00*",
		"*⛔ EOL base images (1)*",
		"*🚨 ACT NOW (1) — exploited or likely to be*",
		"*Image: web:1.0 — identity unconfirmed: scanned by reference*",
		"*◆ openssl*\nInstalled: 3.0.7\nFixed in: 3.0.11",
		"Top CVE: <https://nvd.nist.gov/vuln/detail/CVE-KEV|CVE-KEV> · CRITICAL · EPSS 94%\nExploitation: CISA KEV (exploited in the wild)",
		"⏱ open 3 day(s) · first seen 2026-06-21",
		"*👀 WATCH (1) — not urgent, keep an eye on*",
		"*◆ e2fsprogs*\nInstalled: 1.44\nFixed in: none — consider mitigation",
		"*🔕 LOW (1)*",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("thread missing %q\n---\n%s", s, out)
		}
	}
	// Low priority is a count, never a listing.
	if strings.Contains(out, "*◆ dpkg*") {
		t.Errorf("low-priority package must not be expanded:\n%s", out)
	}
	// Triage mode shows no per-image severity emoji: the bucket header
	// already carries the urgency signal.
	if strings.Contains(out, "🔴") {
		t.Errorf("triage thread must not show a severity emoji on image lines:\n%s", out)
	}
	// Order: urgent before watch before low.
	if !(strings.Index(out, "ACT NOW") < strings.Index(out, "WATCH") &&
		strings.Index(out, "WATCH") < strings.Index(out, "LOW")) {
		t.Errorf("bucket order wrong:\n%s", out)
	}
}

// findPkgGroup pulls one package's group out of a report section by image and
// package name, failing the test if absent.
func findPkgGroup(t *testing.T, section []analyze.ImageFindings, image, pkg string) analyze.PackageGroup {
	t.Helper()
	for _, img := range section {
		if img.Image != image {
			continue
		}
		for _, g := range img.Packages {
			if g.Package == pkg {
				return g
			}
		}
	}
	t.Fatalf("package %q not found for image %q", pkg, image)
	return analyze.PackageGroup{}
}

// The thread card shows the headline CVE's Trivy title as its own labelled
// line, but only for the headline CVE (not the other ids folded behind it).
func TestThread_TitleLine(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-A", Title: "libx: headline vulnerability title"},
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-B", Title: "libx: secondary vulnerability title"},
		},
	}}
	r := analyze.Build(scans, nil, triageRules(map[string]analyze.Enrichment{"CVE-A": {KEV: true}}), genTime)
	out := renderThread(r, Ages{})

	if !strings.Contains(out, "\nSummary: libx: headline vulnerability title\n") {
		t.Errorf("expected the headline CVE's title on its own line:\n%s", out)
	}
	if strings.Contains(out, "secondary vulnerability title") {
		t.Errorf("the other-CVEs line must not expand the secondary CVE's title:\n%s", out)
	}
}

// No Summary line at all when the headline CVE has no Title (e.g. Trivy didn't
// supply one for this CVE).
func TestThread_NoTitleLineWhenEmpty(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-A"},
		},
	}}
	r := analyze.Build(scans, nil, triageRules(map[string]analyze.Enrichment{"CVE-A": {KEV: true}}), genTime)
	out := renderThread(r, Ages{})

	if strings.Contains(out, "Summary:") {
		t.Errorf("no summary line expected without a title:\n%s", out)
	}
	want := "Top CVE: <https://nvd.nist.gov/vuln/detail/CVE-A|CVE-A> · CRITICAL · EPSS n/a\nExploitation: CISA KEV (exploited in the wild)"
	if !strings.Contains(out, want) {
		t.Errorf("expected the evidence lines:\n%s", out)
	}
}

func TestThread_FirstSeenToday(t *testing.T) {
	out := renderThread(triageReport(), Ages{Finding: seenDaysAgo(0)})
	if !strings.Contains(out, "⏱ first seen today") {
		t.Errorf("day-zero findings should read 'first seen today':\n%s", out)
	}
}

func TestThread_NilFirstSeen(t *testing.T) {
	msgs := BuildThreadBlockMessages(triageReport(), Ages{}, LanguageEN)
	if len(msgs) == 0 {
		t.Fatal("expected messages without a firstSeen lookup")
	}
	if out := allBlocksText(msgs); strings.Contains(out, "⏱") {
		t.Errorf("age lines must be omitted without a firstSeen lookup:\n%s", out)
	}
}

func TestThread_NothingOpen(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "clean:1"}}, nil, analyze.Triage{}, genTime)
	if msgs := BuildThreadBlockMessages(r, Ages{}, LanguageEN); msgs != nil {
		t.Errorf("no open findings must skip the thread (edge case 4), got %d message(s)", len(msgs))
	}
}

func TestThread_AlsoIDs(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-A"},
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-B"},
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-C"},
		},
	}}
	r := analyze.Build(scans, nil, triageRules(map[string]analyze.Enrichment{"CVE-A": {KEV: true}}), genTime)
	out := renderThread(r, Ages{})
	if !strings.Contains(out, "Other CVEs: <https://nvd.nist.gov/vuln/detail/CVE-B|CVE-B>, <https://nvd.nist.gov/vuln/detail/CVE-C|CVE-C>") {
		t.Errorf("secondary CVE ids must be listed:\n%s", out)
	}
}

// wideReport builds many single-package images so the packer has plenty of
// image-sized blocks to distribute. Each scan is pinned to its own resolved
// entity so the images are not "unresolved": this test is about
// message-splitting mechanics, and an unresolved image would additionally be
// listed in the cross-cutting "identity unconfirmed" summary section, making
// every image name appear twice and breaking the "exactly once" assertions
// below — unrelated noise for what this fixture is testing.
func wideReport(images int) analyze.Report {
	var scans []scanner.ImageScan
	enrich := map[string]analyze.Enrichment{}
	for i := 0; i < images; i++ {
		img := fmt.Sprintf("svc-%02d:1.0", i)
		id := fmt.Sprintf("CVE-%04d", i)
		scans = append(scans, pinned(scanner.ImageScan{Image: img, Findings: []scanner.Finding{
			{Image: img, Class: scanner.ClassOS, Package: "libfoo", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: id, Title: fmt.Sprintf("libfoo: crafted input flaw %04d", i)},
		}}, fmt.Sprintf("sha256:%064x", i)))
		enrich[id] = analyze.Enrichment{KEV: true}
	}
	return analyze.Build(scans, nil, triageRules(enrich), genTime)
}

func TestThread_SplitsAtLimit(t *testing.T) {
	msgs := buildThreadBlockMessages(wideReport(12), Ages{Finding: seenDaysAgo(2)}, enMessages, testSplitLimits)
	if len(msgs) < 2 {
		t.Fatalf("expected the report to split, got %d message(s)", len(msgs))
	}
	checkMessageConstraints(t, "wide thread", msgs, testSplitLimits)
	// Continuation messages repeat the section header.
	if !strings.Contains(msgs[1].Blocks[0].Text, "*🚨 ACT NOW (12) — exploited or likely to be* _(cont.)_") {
		t.Errorf("continuation must repeat the section title:\n%s", msgs[1].Blocks[0].Text)
	}
	// Every image appears exactly once across the whole thread.
	all := allBlocksText(msgs)
	for i := 0; i < 12; i++ {
		img := fmt.Sprintf("svc-%02d:1.0", i)
		if strings.Count(all, img) != 1 {
			t.Errorf("image %s should appear exactly once, got %d", img, strings.Count(all, img))
		}
	}
	// A title rides in the same card as its package: a split boundary must
	// neither drop nor duplicate it.
	for i := 0; i < 12; i++ {
		title := fmt.Sprintf("libfoo: crafted input flaw %04d", i)
		if strings.Count(all, title) != 1 {
			t.Errorf("title %q should appear exactly once, got %d", title, strings.Count(all, title))
		}
	}
}

func TestThread_TriageOffFallback(t *testing.T) {
	out := renderThread(sampleReport(), Ages{Finding: seenDaysAgo(1)})
	mustContain := []string{
		"*✅ Actionable now (fixed)*",
		"*Image: web:1.0 — identity unconfirmed: scanned by reference*",
		"🔴", // triage off: no bucket signal, severity emoji stays
		"*◆ libc-bin*",
		"*◆ setuptools*", // low-risk fixes are NOT collapsed in the thread
		"*ℹ️ No fix yet (affected / waiting on upstream)*",
		"*◆ e2fsprogs*",
		"*🔕 No fix planned for this OS release (will_not_fix)*",
		"*◆ gcc-8-base*",
		"⏱ open 1 day(s)",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("triage-off thread missing %q\n---\n%s", s, out)
		}
	}
}
