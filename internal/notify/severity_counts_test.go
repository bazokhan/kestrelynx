package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// allSeverityReport has one image whose packages carry every level: app-c
// (1 CRITICAL, 2 HIGH, 3 MEDIUM, 1 LOW, 1 UNKNOWN, all fixed so it is
// actionable) plus a MEDIUM-only package and a LOW-only package.
func allSeverityReport() analyze.Report {
	mk := func(pkg string, sev scanner.Severity, id string) scanner.Finding {
		return scanner.Finding{Image: "app:1", Class: scanner.ClassOS, Package: pkg, InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: sev, VulnID: id}
	}
	fs := []scanner.Finding{
		mk("app-c", scanner.SeverityCritical, "CVE-C1"),
		mk("app-c", scanner.SeverityHigh, "CVE-H1"),
		mk("app-c", scanner.SeverityHigh, "CVE-H2"),
		mk("app-c", scanner.SeverityMedium, "CVE-M1"),
		mk("app-c", scanner.SeverityMedium, "CVE-M2"),
		mk("app-c", scanner.SeverityMedium, "CVE-M3"),
		mk("app-c", scanner.SeverityLow, "CVE-L1"),
		mk("app-c", scanner.Severity("UNKNOWN"), "CVE-U1"),
		mk("med-only", scanner.SeverityMedium, "CVE-M4"),
		mk("low-only", scanner.SeverityLow, "CVE-L2"),
	}
	return analyze.Build([]scanner.ImageScan{{Image: "app:1", Findings: fs}}, nil, analyze.Triage{}, genTime)
}

func TestSeverityCounts_ChannelCardsShowExactCounts(t *testing.T) {
	out := renderFull(allSeverityReport())
	for _, want := range []string{
		"Findings: CRITICAL 1 / HIGH 2 / MEDIUM 3 / LOW 1 / UNKNOWN 1",
		"+2 lower-risk fixes (HIGH 0 / MEDIUM 1 / LOW 1): low-only, med-only", // collapsed line
		"🔴 CRITICAL 1 / HIGH 2 / MEDIUM 4 / LOW 2 / UNKNOWN 1",                // image heading line
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	ja := renderFull(allSeverityReport(), LanguageJA)
	if !strings.Contains(ja, "検出件数: CRITICAL 1 / HIGH 2 / MEDIUM 3 / LOW 1 / UNKNOWN 1") {
		t.Errorf("ja card lacks the exact counts:\n%s", ja)
	}
}

func TestSeverityCounts_ThreadCardShowsExactCounts(t *testing.T) {
	out := renderThread(allSeverityReport(), Ages{})
	if !strings.Contains(out, "Findings: CRITICAL 1 / HIGH 2 / MEDIUM 3 / LOW 1 / UNKNOWN 1") {
		t.Errorf("thread card lacks the exact counts:\n%s", out)
	}
}

func TestSeverityCounts_OpenNowLine(t *testing.T) {
	r := allSeverityReport()
	d, _ := state.Compute(state.State{}, r)
	if d.OpenCritical != 1 || d.OpenHigh != 2 || d.OpenSevMedium != 4 || d.OpenSevLow != 2 || d.OpenSevUnknown != 1 {
		t.Fatalf("open counts = %d/%d/%d/%d/%d", d.OpenCritical, d.OpenHigh, d.OpenSevMedium, d.OpenSevLow, d.OpenSevUnknown)
	}
	out := renderDiff(r, d, false, false)
	if !strings.Contains(out, "CRITICAL 1 / HIGH 2 / MEDIUM 4 / LOW 2 / UNKNOWN 1 across 1 image(s)") {
		t.Errorf("open-now line lacks the exact counts:\n%s", out)
	}
	ja := renderDiff(r, d, false, false, LanguageJA)
	if !strings.Contains(ja, "CRITICAL 1件 / HIGH 2件 / MEDIUM 4件 / LOW 2件 / UNKNOWN 1件、イメージ1件") {
		t.Errorf("ja open-now line lacks the exact counts:\n%s", ja)
	}
}

func TestSeverityCounts_CollapsedLine(t *testing.T) {
	cases := []struct {
		c    analyze.SeverityCounts
		want string
	}{
		{analyze.SeverityCounts{Critical: 1, High: 2}, "CRITICAL 1 / HIGH 2"},
		{analyze.SeverityCounts{High: 2}, "HIGH 2"},
		{analyze.SeverityCounts{Critical: 1, High: 2, Medium: 3, Low: 4, Unknown: 5}, "CRITICAL 1 / HIGH 2 / MEDIUM 3 / LOW 4 / UNKNOWN 5"},
		{analyze.SeverityCounts{Medium: 3}, "HIGH 0 / MEDIUM 3"},
	}
	for _, c := range cases {
		if got := collapsedSeverity(c.c); got != c.want {
			t.Errorf("collapsedSeverity(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}

func TestSeverityCounts_WebhookExactCounts(t *testing.T) {
	r := allSeverityReport()
	d, _ := state.Compute(state.State{}, r)
	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Actionable []struct {
			SeverityCounts map[string]int `json:"severity_counts"`
			Findings       []struct {
				Package        string         `json:"package"`
				SeverityCounts map[string]int `json:"severity_counts"`
			} `json:"findings"`
		} `json:"actionable"`
		Diff struct {
			New []map[string]any `json:"new"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	img := p.Actionable[0]
	wantImg := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 4, "LOW": 2, "UNKNOWN": 1}
	if len(img.SeverityCounts) != len(wantImg) {
		t.Errorf("image severity_counts = %v, want %v", img.SeverityCounts, wantImg)
	}
	for k, v := range wantImg {
		if img.SeverityCounts[k] != v {
			t.Errorf("image severity_counts[%s] = %d, want %d", k, img.SeverityCounts[k], v)
		}
	}
	for _, f := range img.Findings {
		switch f.Package {
		case "app-c":
			if f.SeverityCounts["HIGH"] != 2 || f.SeverityCounts["MEDIUM"] != 3 || f.SeverityCounts["LOW"] != 1 || f.SeverityCounts["UNKNOWN"] != 1 {
				t.Errorf("app-c severity_counts = %v", f.SeverityCounts)
			}
		case "med-only":
			if f.SeverityCounts["HIGH"] != 0 || f.SeverityCounts["MEDIUM"] != 1 {
				t.Errorf("med-only severity_counts = %v", f.SeverityCounts)
			}
			if _, ok := f.SeverityCounts["LOW"]; ok {
				t.Errorf("zero levels must be omitted: %v", f.SeverityCounts)
			}
		}
	}
	byPkg := map[string]map[string]any{}
	for _, c := range p.Diff.New {
		byPkg[c["package"].(string)] = c
	}
	c := byPkg["app-c"]
	if c["critical"] != float64(1) || c["high"] != float64(2) || c["medium"] != float64(3) || c["low"] != float64(1) || c["unknown"] != float64(1) {
		t.Errorf("app-c diff counts = %v", c)
	}
	if m := byPkg["med-only"]; m["high"] != float64(0) || m["medium"] != float64(1) {
		t.Errorf("med-only diff counts = %v", m)
	} else if _, ok := m["low"]; ok {
		t.Errorf("a zero low must be omitted: %v", m)
	}
}

// With the default scan.severity only CRITICAL and HIGH exist, and no
// output mentions another level or carries the new fields.
func TestSeverityCounts_DefaultConfigurationUnchanged(t *testing.T) {
	r, d := diffFixture()
	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`"medium"`, `"low"`, `"unknown"`, `"MEDIUM"`, `"LOW"`, `"UNKNOWN"`} {
		if strings.Contains(string(data), bad) {
			t.Errorf("default payload contains %s:\n%s", bad, data)
		}
	}
	if !strings.Contains(string(data), `"severity_counts":{"CRITICAL":1,"HIGH":0}`) {
		t.Errorf("severity_counts shape changed:\n%s", data)
	}
	for _, out := range []string{renderFull(r), renderDiff(r, d, false, false), renderThread(r, Ages{})} {
		for _, bad := range []string{"MEDIUM", "UNKNOWN", " / LOW"} {
			if strings.Contains(out, bad) {
				t.Errorf("default output mentions %q:\n%s", bad, out)
			}
		}
	}
}
