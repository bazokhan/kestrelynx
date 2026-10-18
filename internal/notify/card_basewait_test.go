package notify

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	baseWaitImage = "shop-es:1"
	baseLayer     = "sha256:base-layer"
	upperLayer    = "sha256:upper-layer"
)

func baseWaitKeyOf(t *testing.T, hex string) inventory.EntityKey {
	t.Helper()
	d, ok := inventory.ParseDigest(inventory.DigestConfig, "sha256:"+strings.Repeat(hex, 64))
	if !ok {
		t.Fatalf("bad test digest %q", hex)
	}
	return inventory.EntityKey{Digest: d}
}

func jsoupFinding(ver, id, layer, path string) scanner.Finding {
	return scanner.Finding{Image: baseWaitImage, Class: scanner.ClassLang, Package: "org.jsoup:jsoup", InstalledVer: ver, FixedVer: "1.23.2",
		Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: id, Type: "jar", PkgPath: path, LayerDiffID: layer}
}

func baseWaitFindings() []scanner.Finding {
	return []scanner.Finding{
		jsoupFinding("1.21.2", "CVE-2031-1111", baseLayer, "usr/lib/a/jsoup.jar"),
		jsoupFinding("1.21.2", "CVE-2031-2222", baseLayer, "usr/lib/a/jsoup.jar"),
		{Image: baseWaitImage, Class: scanner.ClassLang, Package: "other-lib", InstalledVer: "2.0", FixedVer: "2.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-3333", Type: "jar", LayerDiffID: baseLayer},
	}
}

func baseWaitScan(t *testing.T, hex string, fs []scanner.Finding) scanner.ImageScan {
	key := baseWaitKeyOf(t, hex)
	return scanner.ImageScan{Image: baseWaitImage, Subject: inventory.ImageSubject{Ref: baseWaitImage, Key: key, Resolved: true},
		ScannedKey: key, Pinned: true, Source: scanner.SourceLocal, Findings: fs}
}

func baseWaitReportOf(t *testing.T, scans ...scanner.ImageScan) analyze.Report {
	return analyze.Build(scans, nil, analyze.Triage{}, genTime)
}

func baseWaitReport(t *testing.T) analyze.Report {
	return baseWaitReportOf(t, baseWaitScan(t, "a", baseWaitFindings()))
}

func baseWaitTarget(f scanner.Finding) remediation.Target {
	r := f.PackageRef()
	return remediation.Target{VulnID: f.VulnID, Package: remediation.PackageCoord{Ecosystem: r.Ecosystem, Class: r.Class, Name: r.Name}, Layers: []string{baseLayer}}
}

// baseWaitPlan is a plan with one Dockerfile item for the entity "a" of
// baseWaitImage whose base has no newer tag; it targets jsoup's two
// findings (reported in the base layer) but not other-lib's.
func baseWaitPlan(t *testing.T, cat remediation.Category, reason remediation.Reason) *PlanInfo {
	fs := baseWaitFindings()
	ent := remediation.DockerfileEntity{
		Running:     remediation.ImageState{Ref: baseWaitImage, Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a"))},
		CurrentBase: &remediation.ImageState{Ref: "docker.elastic.co/elasticsearch/elasticsearch:8.19.23", Tag: "8.19.23"},
		Category:    cat, Reason: reason,
		Targets: []remediation.Target{baseWaitTarget(fs[0]), baseWaitTarget(fs[1])},
	}
	it := remediation.DockerfileItem{
		Key: "dockerfile:ex/es@main:Dockerfile#stages[0]", Category: cat, Reason: reason,
		BaseRef:  "docker.elastic.co/elasticsearch/elasticsearch:8.19.23",
		Entities: []remediation.DockerfileEntity{ent},
	}
	return &PlanInfo{Plan: &remediation.Plan{DockerfileItems: []remediation.DockerfileItem{it}}}
}

func baseWaitNoNewer(t *testing.T) *PlanInfo {
	return baseWaitPlan(t, remediation.CategoryNoCandidate, remediation.ReasonNoNewerTag)
}

func renderChannelWithPlan(r analyze.Report, p *PlanInfo, lang Language) string {
	return allBlocksText(BuildChannelMessages(Message{Report: r, Plan: p}, ChannelFooter{}, lang))
}

func TestBaseWait_LineInChannelCard(t *testing.T) {
	r := baseWaitReport(t)
	cases := []struct {
		lang Language
		want string
	}{
		{LanguageJA, "対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列に新しい版なし）"},
		{LanguageEN, "Action: waiting for a newer base image of elasticsearch 8.19.23 (no newer tag in the same series)"},
	}
	for _, c := range cases {
		out := renderChannelWithPlan(r, baseWaitNoNewer(t), c.lang)
		if n := strings.Count(out, c.want); n != 1 {
			t.Errorf("%s: line appears %d times, want 1 (only jsoup):\n%s", c.lang, n, out)
		}
		if strings.Contains(out, "docker.elastic.co") {
			t.Errorf("%s: the registry host must not be shown:\n%s", c.lang, out)
		}
	}
}

func TestBaseWait_LineInThreadCard(t *testing.T) {
	out := allBlocksText(buildThreadBlockMessagesWithPlan(baseWaitReport(t), Ages{}, baseWaitNoNewer(t), jaMessages, defaultRenderLimits))
	if !strings.Contains(out, "対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列に新しい版なし）") {
		t.Errorf("thread card lacks the line:\n%s", out)
	}
}

func TestBaseWait_LineFollowsCountsAndPrecedesTopCVE(t *testing.T) {
	out := renderChannelWithPlan(baseWaitReport(t), baseWaitNoNewer(t), LanguageJA)
	i, j := strings.Index(out, "検出件数"), strings.Index(out, "対応: ")
	if i < 0 || j < i {
		t.Errorf("action line should follow the findings line:\n%s", out)
	}
}

func TestBaseWait_UnchangedWhenNotApplicable(t *testing.T) {
	r := baseWaitReport(t)
	for _, lang := range []Language{LanguageJA, LanguageEN} {
		want := renderChannelWithPlan(r, nil, lang)
		wantThread := allBlocksText(BuildThreadBlockMessages(r, Ages{}, lang))
		if strings.Contains(want, "対応: ") || strings.Contains(want, "Action: ") {
			t.Fatalf("%s: baseline already has the line:\n%s", lang, want)
		}
		plans := map[string]*PlanInfo{
			"unavailable":       {Unavailable: PlanNotBuilt},
			"empty plan":        {Plan: &remediation.Plan{}},
			"pr candidate":      baseWaitPlan(t, remediation.CategoryPRCandidate, remediation.ReasonAdopted),
			"base unchanged":    baseWaitPlan(t, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged),
			"not comparable":    baseWaitPlan(t, remediation.CategoryNotComparable, remediation.ReasonBaseLayersMismatch),
			"other image":       renamedRunning(baseWaitNoNewer(t), "other:1"),
			"no current base":   noCurrentBase(baseWaitNoNewer(t)),
			"entity differs":    entityReason(baseWaitNoNewer(t), remediation.ReasonBaseUnchanged),
			"different package": retargeted(baseWaitNoNewer(t), "CVE-2031-9999"),
		}
		for name, p := range plans {
			if got := renderChannelWithPlan(r, p, lang); got != want {
				t.Errorf("%s/%s: channel output changed:\n%s", lang, name, got)
			}
			if got := allBlocksText(buildThreadBlockMessagesWithPlan(r, Ages{}, p, messagesFor(lang), defaultRenderLimits)); got != wantThread {
				t.Errorf("%s/%s: thread output changed:\n%s", lang, name, got)
			}
		}
	}
}

func TestBaseWait_PartiallyTargetedPackageHasNoLine(t *testing.T) {
	// jsoup has two fixed findings; the plan targets only one of them.
	p := baseWaitNoNewer(t)
	e := &p.Plan.DockerfileItems[0].Entities[0]
	e.Targets = e.Targets[:1]
	out := renderChannelWithPlan(baseWaitReport(t), p, LanguageEN)
	if strings.Contains(out, "Action: ") {
		t.Errorf("line shown for a partly targeted package:\n%s", out)
	}
}

func TestBaseWait_TwoBasesForOneFindingHaveNoLine(t *testing.T) {
	p := baseWaitNoNewer(t)
	e := p.Plan.DockerfileItems[0].Entities[0]
	e.CurrentBase = &remediation.ImageState{Ref: "docker.elastic.co/elasticsearch/elasticsearch:8.18.1", Tag: "8.18.1"}
	p.Plan.DockerfileItems = append(p.Plan.DockerfileItems, remediation.DockerfileItem{
		Category: remediation.CategoryNoCandidate, Reason: remediation.ReasonNoNewerTag,
		Entities: []remediation.DockerfileEntity{e},
	})
	if out := renderChannelWithPlan(baseWaitReport(t), p, LanguageEN); strings.Contains(out, "Action: ") {
		t.Errorf("line shown although the finding has two bases:\n%s", out)
	}
}

func TestBaseWait_NameIsLiteral(t *testing.T) {
	p := baseWaitNoNewer(t)
	p.Plan.DockerfileItems[0].Entities[0].CurrentBase = &remediation.ImageState{Ref: "ghcr.io/org/my__base:1.0", Tag: "1.0"}
	out := renderChannelWithPlan(baseWaitReport(t), p, LanguageEN)
	if !strings.Contains(out, "base image of `my__base` 1.0") {
		t.Errorf("a name with formatting characters should be a code span:\n%s", out)
	}
	if strings.Contains(out, "ghcr.io") {
		t.Errorf("host shown:\n%s", out)
	}
}

func renamedRunning(p *PlanInfo, ref string) *PlanInfo {
	p.Plan.DockerfileItems[0].Entities[0].Running.Ref = ref
	return p
}

func noCurrentBase(p *PlanInfo) *PlanInfo {
	p.Plan.DockerfileItems[0].Entities[0].CurrentBase = nil
	return p
}

func entityReason(p *PlanInfo, r remediation.Reason) *PlanInfo {
	p.Plan.DockerfileItems[0].Entities[0].Reason = r
	return p
}

func retargeted(p *PlanInfo, id string) *PlanInfo {
	ts := p.Plan.DockerfileItems[0].Entities[0].Targets
	for i := range ts {
		ts[i].VulnID = id
	}
	return p
}

func TestBaseWait_LineInTriageDetailAndWatchCards(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-2031-1111": {KEV: true, EPSS: 0.9, EPSSKnown: true}}
	r := analyze.Build([]scanner.ImageScan{baseWaitScan(t, "a", baseWaitFindings())}, nil, triageRules(enrich), genTime)
	out := renderChannelWithPlan(r, baseWaitNoNewer(t), LanguageEN)
	if !strings.Contains(out, "Action: waiting for a newer base image of elasticsearch 8.19.23") {
		t.Errorf("triage cards lack the line:\n%s", out)
	}
	if renderChannelWithPlan(r, nil, LanguageEN) == out {
		t.Error("output without a plan equals output with one")
	}
}

func countAction(out string) int { return strings.Count(out, "Action: ") }

func TestBaseWait_UpperLayerCopyOfAnotherVersionHasNoLine(t *testing.T) {
	// Same CVEs, but jsoup 1.22.1 sits in a later layer: only the 1.21.2
	// card may wait for the base.
	fs := append(baseWaitFindings(),
		jsoupFinding("1.22.1", "CVE-2031-1111", upperLayer, "app/lib/jsoup.jar"),
		jsoupFinding("1.22.1", "CVE-2031-2222", upperLayer, "app/lib/jsoup.jar"))
	out := renderChannelWithPlan(baseWaitReportOf(t, baseWaitScan(t, "a", fs)), baseWaitNoNewer(t), LanguageEN)
	if n := countAction(out); n != 1 {
		t.Fatalf("action lines = %d, want 1 (the base-layer 1.21.2 card):\n%s", n, out)
	}
	i, j := strings.Index(out, "Installed: 1.21.2"), strings.Index(out, "Action: ")
	k := strings.Index(out, "Installed: 1.22.1")
	if i < 0 || k < 0 || j < i {
		t.Errorf("the line belongs to the 1.21.2 card:\n%s", out)
	}
	if k >= 0 && j > k {
		t.Errorf("line follows the 1.22.1 card:\n%s", out)
	}
}

func TestBaseWait_SameVersionAtAnotherLocationInUpperLayerHasNoLine(t *testing.T) {
	fs := append(baseWaitFindings(),
		jsoupFinding("1.21.2", "CVE-2031-1111", upperLayer, "app/lib/jsoup.jar"),
		jsoupFinding("1.21.2", "CVE-2031-2222", upperLayer, "app/lib/jsoup.jar"))
	out := renderChannelWithPlan(baseWaitReportOf(t, baseWaitScan(t, "a", fs)), baseWaitNoNewer(t), LanguageEN)
	if n := countAction(out); n != 0 {
		t.Errorf("line shown although one copy is in an upper layer:\n%s", out)
	}
}

func TestBaseWait_UnattributedLayerHasNoLine(t *testing.T) {
	fs := baseWaitFindings()
	fs[1].LayerDiffID = ""
	out := renderChannelWithPlan(baseWaitReportOf(t, baseWaitScan(t, "a", fs)), baseWaitNoNewer(t), LanguageEN)
	if n := countAction(out); n != 0 {
		t.Errorf("line shown for a finding without a layer:\n%s", out)
	}
}

func TestBaseWait_SameReferenceOtherEntityHasNoLine(t *testing.T) {
	// Entities a and b run under one reference; the plan judged only a.
	a, b := baseWaitScan(t, "a", baseWaitFindings()), baseWaitScan(t, "b", baseWaitFindings())
	out := renderChannelWithPlan(baseWaitReportOf(t, a, b), baseWaitNoNewer(t), LanguageEN)
	if n := countAction(out); n != 1 {
		t.Errorf("action lines = %d, want 1 (entity a only):\n%s", n, out)
	}
	// Only entity b is in the report: the plan's entity is not running.
	if out := renderChannelWithPlan(baseWaitReportOf(t, b), baseWaitNoNewer(t), LanguageEN); countAction(out) != 0 {
		t.Errorf("line shown for an entity the plan did not judge:\n%s", out)
	}
}

func TestBaseWait_UnresolvedEntityHasNoLine(t *testing.T) {
	sc := baseWaitScan(t, "a", baseWaitFindings())
	sc.Subject, sc.ScannedKey, sc.Pinned = inventory.ImageSubject{}, inventory.EntityKey{}, false
	if out := renderChannelWithPlan(baseWaitReportOf(t, sc), baseWaitNoNewer(t), LanguageEN); countAction(out) != 0 {
		t.Errorf("line shown for an unresolved entity:\n%s", out)
	}
}

func TestBaseWait_ChangeCardNeedsAUniqueEntity(t *testing.T) {
	g := func(r analyze.Report) analyze.PackageGroup {
		for _, img := range r.Actionable {
			for _, pg := range img.Packages {
				if pg.Package == "org.jsoup:jsoup" {
					return pg
				}
			}
		}
		t.Fatal("jsoup group missing")
		return analyze.PackageGroup{}
	}
	newView := func(r analyze.Report) *chView {
		return &chView{r: r, msg: enMessages, waits: newBaseWaitIndex(baseWaitNoNewer(t))}
	}
	one := baseWaitReport(t)
	if c := newView(one).newChangeCard(baseWaitImage, g(one), cardOpts{}); c.BaseWait == nil {
		t.Error("a diff card of a uniquely identified entity should get the wait")
	}
	two := baseWaitReportOf(t, baseWaitScan(t, "a", baseWaitFindings()), baseWaitScan(t, "b", baseWaitFindings()))
	if c := newView(two).newChangeCard(baseWaitImage, g(two), cardOpts{}); c.BaseWait != nil {
		t.Error("a diff card whose entity is ambiguous must not get the wait")
	}
}

func TestBaseWait_ChangeCardWithFixedAndAffectedGroupsOfOnePackage(t *testing.T) {
	// The same package version has a fixed group and an affected group in
	// one entity; the diff card of the fixed group still finds its entry.
	aff := jsoupFinding("1.21.2", "CVE-2031-7777", baseLayer, "usr/lib/a/jsoup.jar")
	aff.Status, aff.FixedVer = scanner.StatusAffected, ""
	r := baseWaitReportOf(t, baseWaitScan(t, "a", append(baseWaitFindings(), aff)))
	var g analyze.PackageGroup
	for _, pg := range r.Actionable[0].Packages {
		if pg.Package == "org.jsoup:jsoup" {
			g = pg
		}
	}
	if g.Package == "" || len(r.Watch) == 0 {
		t.Fatalf("fixture lacks a fixed and an affected jsoup group: %+v", r)
	}
	v := &chView{r: r, msg: enMessages, waits: newBaseWaitIndex(baseWaitNoNewer(t))}
	if c := v.newChangeCard(baseWaitImage, g, cardOpts{}); c.BaseWait == nil {
		t.Error("the fixed group's diff card lost the wait because an affected group exists")
	}
}
