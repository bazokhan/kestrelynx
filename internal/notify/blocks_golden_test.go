package notify

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// updateBlocks rewrites testdata/golden/blocks from the current output. It is
// separate from -update-golden so refreshing the Block Kit goldens can never
// touch the text goldens.
var updateBlocks = flag.Bool("update-blocks", false, "rewrite testdata/golden/blocks from current output")

// dumpBlockKit, when set to a directory, writes one {"blocks":[...]} file
// per message of every golden case there, ready to paste into Slack's Block
// Kit Builder.
var dumpBlockKit = flag.String("dump-blockkit", "", "write each golden case's messages as Block Kit Builder payloads into this directory")

// testSplitLimits are small limits that make the golden fixtures split, so
// the split points are pinned along with the content.
var testSplitLimits = RenderLimits{MaxBlocks: 12, MaxTextUnits: 3000, MaxMessageUnits: 1500, MaxFallbackUnits: 4000}

// dumpMessages renders messages in the structure-dump format the goldens use.
func dumpMessages(msgs []SlackMessage) string {
	var b strings.Builder
	for i, m := range msgs {
		fmt.Fprintf(&b, "===== message %d/%d =====\n", i+1, len(msgs))
		fmt.Fprintf(&b, "TEXT: %s\n", m.Text)
		for _, blk := range m.Blocks {
			fmt.Fprintf(&b, "--- %s ---\n", blk.Kind)
			if blk.Kind != BlockDivider {
				b.WriteString(blk.Text + "\n")
			}
		}
	}
	return b.String()
}

// marshalMessages renders messages as indented JSON without HTML escaping.
func marshalMessages(t *testing.T, msgs []SlackMessage) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(msgs); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf.String()
}

func checkBlockGolden(t *testing.T, name, ext, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", "blocks", name+"."+ext)
	if *updateBlocks {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update-blocks to create it)", path, err)
	}
	if got != string(want) {
		t.Errorf("%s: output differs from golden\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// blockCase is one rendering the Block Kit goldens and constraint tests
// cover: the same input as one of the text goldens.
type blockCase struct {
	name  string
	build func(lim RenderLimits) []SlackMessage
	// split cases are built with testSplitLimits instead of the defaults.
	split bool
	// report is the input's report, for checking package identities.
	report analyze.Report
	// json also pins the JSON form.
	json bool
}

func (c blockCase) limits() RenderLimits {
	if c.split {
		return testSplitLimits
	}
	return defaultRenderLimits
}

func channelCase(name string, lang Language, r analyze.Report, d *state.Diff, weekly bool) blockCase {
	// The diff is copied: callers reuse their variables for the next fixture.
	var dc *state.Diff
	if d != nil {
		v := *d
		dc = &v
	}
	m := Message{Report: r, Diff: dc, FullReport: weekly}
	return blockCase{
		name:   name,
		report: r,
		build: func(lim RenderLimits) []SlackMessage {
			return buildChannelMessages(m, ChannelFooter{Kind: FooterThreadNotice}, messagesFor(lang), lim)
		},
	}
}

func threadCase(name string, lang Language, r analyze.Report, st state.State, split bool) blockCase {
	ages := Ages{Finding: st.FirstSeen, EOL: st.EOLFirstSeen}
	return blockCase{
		name:   name,
		report: r,
		split:  split,
		build: func(lim RenderLimits) []SlackMessage {
			return buildThreadBlockMessages(r, ages, messagesFor(lang), lim)
		},
	}
}

// allBlockCases builds every case, mirroring the fixtures of the text
// golden tests.
func allBlockCases(t *testing.T) []blockCase {
	t.Helper()
	var cases []blockCase
	add := func(c ...blockCase) { cases = append(cases, c...) }

	// Three-status fixture, end-of-life base image fixture and end-of-life
	// package fixture, in every triage mode.
	for _, m := range goldenModes() {
		r, changed, unchanged, next := goldenCycle(m, false)
		p := "status3_" + m.name + "_"
		add(
			channelCase(p+"slack_full", LanguageEN, r, nil, false),
			channelCase(p+"slack_diff_changes", LanguageEN, r, &changed, false),
			channelCase(p+"slack_diff_nochanges", LanguageEN, r, &unchanged, false),
			channelCase(p+"slack_diff_weekly", LanguageEN, r, &changed, true),
			channelCase(p+"slack_diff_weekly_nochanges", LanguageEN, r, &unchanged, true),
			threadCase(p+"thread", LanguageEN, r, next, false),
			threadCase(p+"thread_split", LanguageEN, r, next, true),
		)

		r, changed, unchanged, next = goldenCycle(m, true)
		p = "eosl_" + m.name + "_"
		add(
			channelCase(p+"slack_full", LanguageEN, r, nil, false),
			channelCase(p+"slack_diff_changes", LanguageEN, r, &changed, false),
			channelCase(p+"slack_diff_nochanges", LanguageEN, r, &unchanged, false),
			threadCase(p+"thread", LanguageEN, r, next, false),
		)

		r, changed, unchanged, next = eolCycle(m)
		p = "eolpkg_" + m.name + "_"
		add(
			channelCase(p+"slack_full", LanguageEN, r, nil, false),
			channelCase(p+"slack_diff_changes", LanguageEN, r, &changed, false),
			channelCase(p+"slack_diff_nochanges", LanguageEN, r, &unchanged, false),
			channelCase(p+"slack_diff_weekly_nochanges", LanguageEN, r, &unchanged, true),
			threadCase(p+"thread", LanguageEN, r, next, false),
			threadCase(p+"thread_split", LanguageEN, r, next, true),
		)

		// Failure cycles: a scan fails while state still holds findings.
		_, _, _, st := goldenCycle(m, true)
		webFailed := pinned(scanner.ImageScan{Image: "web:1.0", Err: errString("pull failed")}, goldenContentWeb)
		today := goldenTodayScans(true)
		failedCycle := analyze.Build([]scanner.ImageScan{webFailed, today[1]}, nil, m.triage(goldenTodayEnrich()), genTime.AddDate(0, 0, 1))
		d, _ := state.Compute(st, failedCycle)
		add(channelCase("failure_"+m.name+"_eosl_failed", LanguageEN, failedCycle, &d, false))
		apiClean := pinned(scanner.ImageScan{Image: "api:2.0"}, goldenContentAPI)
		_, webOnly := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{goldenTodayScans(false)[0]}, nil, m.triage(goldenTodayEnrich()), genTime))
		cleanCycle := analyze.Build([]scanner.ImageScan{webFailed, apiClean}, nil, m.triage(goldenTodayEnrich()), genTime.AddDate(0, 0, 1))
		d2, _ := state.Compute(webOnly, cleanCycle)
		add(channelCase("failure_"+m.name+"_all_failed_clean", LanguageEN, cleanCycle, &d2, false))
	}

	// Japanese counterparts.
	modes := goldenModes()
	jaR, jaChanged, jaUnchanged, jaNext := goldenCycle(modes[0], false)
	jaRN, _, _, _ := goldenCycle(modes[1], false)
	jaRD, _, _, _ := goldenCycle(modes[2], false)
	jaEOSL, _, _, _ := goldenCycle(modes[0], true)
	jaEOL, _, _, _ := eolCycle(modes[0])
	add(
		channelCase("ja_status3_triage_slack_full", LanguageJA, jaR, nil, false),
		channelCase("ja_status3_notriage_slack_full", LanguageJA, jaRN, nil, false),
		channelCase("ja_status3_degraded_slack_full", LanguageJA, jaRD, nil, false),
		channelCase("ja_status3_triage_slack_diff_changes", LanguageJA, jaR, &jaChanged, false),
		channelCase("ja_status3_triage_slack_diff_nochanges", LanguageJA, jaR, &jaUnchanged, false),
		channelCase("ja_status3_triage_slack_diff_weekly", LanguageJA, jaR, &jaChanged, true),
		threadCase("ja_status3_triage_thread", LanguageJA, jaR, jaNext, false),
		threadCase("ja_status3_triage_thread_split", LanguageJA, jaR, jaNext, true),
		channelCase("ja_eosl_triage_slack_full", LanguageJA, jaEOSL, nil, false),
		channelCase("ja_eolpkg_triage_slack_full", LanguageJA, jaEOL, nil, false),
	)

	// Reference changes: a workload moved to another tag, and one to a
	// digest-pinned reference.
	rcR, _, rcUnchanged, _ := goldenCycle(modes[0], false)
	rcDiff := refChangeDiff(rcUnchanged)
	add(
		channelCase("refchange_slack_diff", LanguageEN, rcR, &rcDiff, false),
		channelCase("ja_refchange_slack_diff", LanguageJA, rcR, &rcDiff, false),
	)

	// Runtime fixtures.
	healthy := rtGoldenReport(t)
	rtGoldenAttach(t, &healthy)
	add(
		channelCase("runtime_healthy_slack_full", LanguageEN, healthy, nil, false),
		channelCase("ja_runtime_healthy_slack_full", LanguageJA, healthy, nil, false),
		threadCase("runtime_healthy_thread", LanguageEN, healthy, state.State{}, false),
		threadCase("ja_runtime_healthy_thread", LanguageJA, healthy, state.State{}, false),
	)
	notReporting := rtGoldenReport(t)
	analyze.AttachRuntime(&notReporting, analyze.RuntimeInfo{NotReporting: true, LoadFailed: true}, rtevidence.Snapshot{}, analyze.GenerationInspect{}, genTime)
	add(
		channelCase("runtime_not_reporting_slack_full", LanguageEN, notReporting, nil, false),
		channelCase("ja_runtime_not_reporting_slack_full", LanguageJA, notReporting, nil, false),
	)
	ebpf := rtGoldenReport(t)
	{
		genWeb, genAPI := rtGoldenGenWeb(), rtGoldenGenAPI()
		sensor := rtGoldenSensorInfo()
		sensor.Events = rtevidence.EventsInfo{Status: rtevidence.EventsUnavailable, Reason: rtevidence.EventsReasonBTFMissing}
		genWeb.EventsCoverage, genAPI.EventsCoverage = rtevidence.CoverageNone, rtevidence.CoverageNone
		snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: sensor, Generations: []rtevidence.Generation{genWeb, genAPI}}
		insp := analyze.GenerationInspect{
			ByContainer: map[string]docker.InspectResult{
				rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, ebpf, "web:1.0"), rtGoldenWebPorts()),
				rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, ebpf, "api:2.0"), nil),
			},
			BootTime: rtGoldenBoot,
		}
		analyze.AttachRuntime(&ebpf, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)
	}
	add(
		channelCase("runtime_ebpf_unavailable_slack_full", LanguageEN, ebpf, nil, false),
		channelCase("ja_runtime_ebpf_unavailable_slack_full", LanguageJA, ebpf, nil, false),
	)
	ambiguous := rtGoldenReport(t)
	{
		genWeb := rtGoldenGenWeb()
		genWeb.OSPackages = []rtevidence.OSPackageEvidence{
			{Name: "openssl", Version: "3.0.7", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
				rtevidence.KindExe:           {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
				rtevidence.KindMappedLibrary: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
			}, Observations: []rtevidence.ProcessObservation{
				{Exe: "/usr/bin/helper", EffectiveUID: 1000, LastSeen: genTime},
				{Exe: "/app/server", EffectiveUID: 0, LastSeen: genTime},
			}},
		}
		genAPI := rtGoldenGenAPI()
		snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(), Generations: []rtevidence.Generation{genWeb, genAPI}}
		insp := analyze.GenerationInspect{
			ByContainer: map[string]docker.InspectResult{
				rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, ambiguous, "web:1.0"), nil),
				rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, ambiguous, "api:2.0"), nil),
			},
			BootTime: rtGoldenBoot,
		}
		analyze.AttachRuntime(&ambiguous, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)
	}
	add(
		channelCase("runtime_ambiguous_os_package_slack", LanguageEN, ambiguous, nil, false),
		threadCase("runtime_ambiguous_os_package_thread", LanguageEN, ambiguous, state.State{}, false),
	)
	nonTriage := rtGoldenReportNoTriage(t)
	rtGoldenAttach(t, &nonTriage)
	add(
		channelCase("runtime_nontriage_slack_full", LanguageEN, nonTriage, nil, false),
		threadCase("runtime_nontriage_thread", LanguageEN, nonTriage, state.State{}, false),
	)
	diffOn, _ := state.Compute(state.State{}, healthy)
	diffOff, _ := state.Compute(state.State{}, nonTriage)
	add(
		channelCase("runtime_diff_triage_slack", LanguageEN, healthy, &diffOn, false),
		channelCase("runtime_diff_nontriage_slack", LanguageEN, nonTriage, &diffOff, false),
	)

	// Muting.
	muted := muteGoldenReport(t)
	muteGoldenAttach(t, &muted, true)
	muteDiff, _ := state.Compute(state.State{}, muted)
	add(
		channelCase("mute_slack_full", LanguageEN, muted, nil, false),
		channelCase("ja_mute_slack_full", LanguageJA, muted, nil, false),
		threadCase("mute_thread", LanguageEN, muted, state.State{}, false),
		channelCase("mute_slack_diff", LanguageEN, muted, &muteDiff, false),
	)
	cycle1 := muteGoldenReport(t)
	muteGoldenAttach(t, &cycle1, true)
	_, prev := state.Compute(state.State{}, cycle1)
	cycle2 := muteGoldenReport(t)
	{
		gen := muteGoldenGenWeb()
		gen.OSPackages = append(gen.OSPackages, rtevidence.OSPackageEvidence{
			Name: "curl", Version: "8.0.0", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
				rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
			}, Observations: []rtevidence.ProcessObservation{
				{Exe: "/usr/bin/curl", EffectiveUID: 0, LastSeen: genTime},
			},
		})
		snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(), Generations: []rtevidence.Generation{gen}}
		insp := analyze.GenerationInspect{
			ByContainer: map[string]docker.InspectResult{
				rtGoldenWebContainer: rtGoldenInspect(gen, rtGoldenSubject(t, cycle2, "web:1.0"), rtGoldenWebPorts()),
			},
			BootTime: rtGoldenBoot,
		}
		analyze.AttachRuntime(&cycle2, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)
		analyze.ApplyMuting(&cycle2, genTime)
	}
	lostDiff, _ := state.Compute(prev, cycle2)
	add(
		channelCase("mute_lost_slack_diff", LanguageEN, cycle2, &lostDiff, false),
		channelCase("ja_mute_lost_slack_diff", LanguageJA, cycle2, &lostDiff, false),
	)
	eolCycle2 := muteGoldenReportWithCurlEOL(t)
	muteGoldenAttach(t, &eolCycle2, true)
	eolLostDiff, _ := state.Compute(prev, eolCycle2)
	add(channelCase("mute_lost_eol_slack_diff", LanguageEN, eolCycle2, &eolLostDiff, false))

	for i := range cases {
		switch cases[i].name {
		case "ja_runtime_healthy_slack_full", "ja_status3_triage_slack_diff_changes", "ja_status3_triage_thread_split", "runtime_healthy_slack_full":
			cases[i].json = true
		}
	}
	sort.SliceStable(cases, func(i, j int) bool { return cases[i].name < cases[j].name })
	return cases
}

// TestBlockKitGoldens pins the structure dump of every case, and the JSON of
// the representative ones.
func TestBlockKitGoldens(t *testing.T) {
	for _, c := range allBlockCases(t) {
		t.Run(c.name, func(t *testing.T) {
			msgs := c.build(c.limits())
			checkBlockGolden(t, c.name, "golden", dumpMessages(msgs))
			if c.json {
				checkBlockGolden(t, c.name, "json", marshalMessages(t, msgs))
			}
		})
	}
}

// checkMessageConstraints verifies what Slack and the renderer's own rules
// require of every message.
func checkMessageConstraints(t *testing.T, name string, msgs []SlackMessage, lim RenderLimits) {
	t.Helper()
	if len(msgs) == 0 {
		t.Errorf("%s: no messages", name)
	}
	for i, m := range msgs {
		where := fmt.Sprintf("%s message %d/%d", name, i+1, len(msgs))
		if strings.TrimSpace(m.Text) == "" {
			t.Errorf("%s: empty fallback text", where)
		}
		if n := utf16Len(m.Text); n > lim.MaxFallbackUnits {
			t.Errorf("%s: fallback text is %d units, limit %d", where, n, lim.MaxFallbackUnits)
		}
		if len(m.Blocks) == 0 {
			t.Errorf("%s: no blocks", where)
			continue
		}
		if len(m.Blocks) > lim.MaxBlocks {
			t.Errorf("%s: %d blocks, limit %d", where, len(m.Blocks), lim.MaxBlocks)
		}
		if m.Blocks[0].Kind != BlockSection {
			t.Errorf("%s: opens with a %s, want a section", where, m.Blocks[0].Kind)
		}
		total := 0
		for j, b := range m.Blocks {
			switch b.Kind {
			case BlockDivider:
				if b.Text != "" {
					t.Errorf("%s block %d: divider with text", where, j)
				}
				if j == len(m.Blocks)-1 {
					t.Errorf("%s: ends with a divider", where)
				}
				if j == 0 {
					t.Errorf("%s: starts with a divider", where)
				}
				if j > 0 && m.Blocks[j-1].Kind == BlockDivider {
					t.Errorf("%s block %d: two dividers in a row", where, j)
				}
			default:
				if strings.TrimSpace(b.Text) == "" {
					t.Errorf("%s block %d: empty %s", where, j, b.Kind)
				}
				if n := utf16Len(b.Text); n > lim.MaxTextUnits {
					t.Errorf("%s block %d: %d units, limit %d", where, j, n, lim.MaxTextUnits)
				}
				total += utf16Len(b.Text)
			}
		}
		if total > lim.MaxMessageUnits {
			t.Errorf("%s: %d units of block text, limit %d", where, total, lim.MaxMessageUnits)
		}
		if m.Blocks[len(m.Blocks)-1].Kind == BlockContext && len(m.Blocks) == 1 {
			t.Errorf("%s: a lone context", where)
		}
		data, err := json.Marshal(m)
		if err != nil || !json.Valid(data) {
			t.Errorf("%s: JSON does not marshal: %v", where, err)
		}
	}
}

// TestBlockKitConstraints holds every golden case to the limits and
// well-formedness rules.
func TestBlockKitConstraints(t *testing.T) {
	for _, c := range allBlockCases(t) {
		t.Run(c.name, func(t *testing.T) {
			checkMessageConstraints(t, c.name, c.build(c.limits()), c.limits())
			// The default limits too, for the cases that normally split.
			if c.split {
				checkMessageConstraints(t, c.name+" (default limits)", c.build(defaultRenderLimits), defaultRenderLimits)
			}
		})
	}
}

var (
	reURL    = regexp.MustCompile(`https?://[^|>\s]+`)
	reCVE    = regexp.MustCompile(`CVE-[0-9A-Z-]+`)
	reCode   = regexp.MustCompile("`[^`]+`")
	reCounts = regexp.MustCompile(`CRITICAL \d+ / HIGH \d+`)
	reEPSS   = regexp.MustCompile(`EPSS (?:n/a|<0\.1%|>99%|[0-9.]+%)`)
	reDate   = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	reImage  = regexp.MustCompile(`\b(?:web|api|broken|legacy|old|app|clean):[0-9.]+\b`)
)

// allBlocksText is every block text of msgs, newline-joined.
func allBlocksText(msgs []SlackMessage) string {
	var parts []string
	for _, m := range msgs {
		for _, b := range m.Blocks {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// savedOldOutput is the plain-text rendering of the case's input that the
// saved file under testdata/legacy-text pins, from before the Block Kit
// layout; cases with no saved counterpart are skipped.
func savedOldOutput(t *testing.T, c blockCase) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "legacy-text", c.name+".golden"))
	if os.IsNotExist(err) {
		t.Skip("no saved text rendering for this case")
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestBlockKitPreservesInformation checks that every identifier, link, path
// and count the text renderers show reaches the Block Kit output as well:
// the new layout only moves and relabels information.
func TestBlockKitPreservesInformation(t *testing.T) {
	for _, c := range allBlockCases(t) {
		t.Run(c.name, func(t *testing.T) {
			old := savedOldOutput(t, c)
			// The blocks carry escaped text; the text renderers do not.
			got := unescapeMrkdwn(allBlocksText(c.build(c.limits())))
			for _, re := range []*regexp.Regexp{reURL, reCVE, reCode, reCounts, reEPSS, reDate, reImage} {
				for _, tok := range re.FindAllString(old, -1) {
					if !strings.Contains(got, tok) {
						t.Errorf("%q is in the text rendering but missing from the blocks", tok)
					}
				}
			}
			// Package names and versions the text rendering shows.
			for _, section := range [][]analyze.ImageFindings{c.report.Actionable, c.report.Watch, c.report.WontFix, c.report.EOLPackages} {
				for _, img := range section {
					for _, g := range img.Packages {
						for _, tok := range []string{g.Package, g.InstalledVer, g.FixedVer} {
							if tok != "" && strings.Contains(old, tok) && !strings.Contains(got, tok) {
								t.Errorf("%s (%s) is in the text rendering but missing from the blocks", tok, g.Package)
							}
						}
					}
				}
			}
		})
	}
}

// TestBlockKitDump writes each case's messages as Block Kit Builder
// payloads when -dump-blockkit names a directory; it is a development aid
// and a no-op otherwise.
func TestBlockKitDump(t *testing.T) {
	dir := *dumpBlockKit
	if dir == "" {
		t.Skip("-dump-blockkit not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range allBlockCases(t) {
		for i, m := range c.build(c.limits()) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(struct {
				Blocks []Block `json:"blocks"`
			}{m.Blocks}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, fmt.Sprintf("%s.%d.json", c.name, i+1))
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
