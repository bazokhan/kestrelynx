package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func runtimeRebuildItem(origin remediation.DockerfileOrigin) remediation.DockerfileItem {
	it := dockerfileFixture().DockerfileItems[2]
	it.Source.Origin = origin
	it.BaseRef = "node:22-alpine"
	it.RebuildRuntimes = []remediation.RuntimeRebuild{{
		Package: "Node.js", Installed: "22.23.3", BaseVersion: "22.23.4", Disappearing: []string{"CVE-1", "CVE-2", "CVE-3"},
	}}
	return it
}

func rebuildPlanText(t *testing.T, it remediation.DockerfileItem, lang Language) string {
	t.Helper()
	r, _, _ := planCycleFixture()
	p := dockerfileFixture()
	p.DockerfileItems = []remediation.DockerfileItem{it}
	return slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, lang)
}

// The rebuild guidance follows how the Dockerfile was found, and the runtime
// line names the version a rebuild would take over.
func TestPlanMessage_DockerfileRebuildRuntime(t *testing.T) {
	compose := map[Language]string{
		LanguageJA: "稼働中のイメージの作成元のベースを確認できない。`docker compose build --pull` で再ビルドすると現在のベースが入る",
		LanguageEN: "rebuilding with `docker compose build --pull` picks up the current base",
	}
	mapping := map[Language]string{
		LanguageJA: "ベースを取り直して再ビルドし(`docker build --pull` など)、デプロイし直す",
		LanguageEN: "pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again",
	}
	line := map[Language]string{
		LanguageJA: "現在の node:22-alpine の Node.js は 22.23.4。この版を引き継げば、検出中の Node.js 22.23.3 の 3 件のうち 3 件は出なくなる見込み(再ビルド後のイメージは未確認)",
		LanguageEN: "Node.js in the current node:22-alpine is 22.23.4; if the rebuild takes over this version, 3 of the 3 findings of the detected Node.js 22.23.3 are expected to disappear (the rebuilt image is not checked)",
	}
	for _, lang := range []Language{LanguageJA, LanguageEN} {
		for origin, guide := range map[remediation.DockerfileOrigin]map[Language]string{
			remediation.DockerfileFromCompose: compose, remediation.DockerfileFromBoth: compose, remediation.DockerfileFromMapping: mapping,
		} {
			got := rebuildPlanText(t, runtimeRebuildItem(origin), lang)
			if !strings.Contains(got, guide[lang]) {
				t.Errorf("%s/%s: missing %q in\n%s", lang, origin, guide[lang], got)
			}
			other := mapping[lang]
			if guide[lang] == mapping[lang] {
				other = compose[lang]
			}
			if strings.Contains(got, other) {
				t.Errorf("%s/%s: has the other guidance %q", lang, origin, other)
			}
			if !strings.Contains(got, line[lang]) {
				t.Errorf("%s/%s: missing %q in\n%s", lang, origin, line[lang], got)
			}
		}
	}

	// Findings the base still has are part of the total only.
	it := runtimeRebuildItem(remediation.DockerfileFromCompose)
	it.RebuildRuntimes[0].Disappearing = []string{"CVE-1"}
	it.RebuildRuntimes[0].Remaining = []string{"CVE-2", "CVE-3"}
	if got := rebuildPlanText(t, it, LanguageJA); !strings.Contains(got, "22.23.3 の 3 件のうち 1 件は出なくなる") {
		t.Errorf("partial: %s", got)
	}
	// No record, no runtime line.
	it.RebuildRuntimes = nil
	if got := rebuildPlanText(t, it, LanguageJA); strings.Contains(got, "引き継げば") {
		t.Errorf("a runtime line without a record: %s", got)
	}
}

// An end-of-life runtime asks for a new series; other end-of-life packages
// keep the existing note.
func TestCard_RuntimeEndOfLifeNote(t *testing.T) {
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		msg := messagesFor(lang)
		for _, notes := range []bool{false, true} {
			card := func(eco inventory.Ecosystem, name string, class inventory.PkgClass) pkgCard {
				g := analyze.PackageGroup{Package: name, Ecosystem: eco, Class: class, Status: scanner.StatusEndOfLife}
				return newPkgCard(analyze.Report{}, "img", g, cardOpts{notes: notes}, msg)
			}
			ordinary, ordinaryOS := msg.EOLPackageText, msg.EOLPackageText
			if notes {
				ordinary, ordinaryOS = msg.FixNoteEOL, msg.FixNoteEOL
			}
			wantRuntime := msg.EOLRuntimeText
			if notes {
				wantRuntime = msg.FixNoteEOLRuntime
			}
			for _, rt := range []struct {
				eco  inventory.Ecosystem
				name string
			}{{inventory.EcosystemNodeRuntime, "Node.js"}, {inventory.EcosystemPythonRuntime, "Python runtime"}} {
				if got := card(rt.eco, rt.name, inventory.ClassLang).FixNote; got != wantRuntime {
					t.Errorf("%s notes=%v %s: note = %q, want %q", lang, notes, rt.name, got, wantRuntime)
				}
			}
			if got := card(inventory.EcosystemNpm, "node", inventory.ClassLang).FixNote; got != ordinary {
				t.Errorf("%s notes=%v npm: note = %q", lang, notes, got)
			}
			if got := card("debian", "libc", inventory.ClassOS).FixNote; got != ordinaryOS {
				t.Errorf("%s notes=%v os: note = %q", lang, notes, got)
			}
		}
	}
	ja := messagesFor(LanguageJA)
	if !strings.Contains(ja.EOLRuntimeText, "系列を上げる必要がある(手動)") || !strings.Contains(ja.FixNoteEOLRuntime, "系列を上げる必要がある(手動)") {
		t.Errorf("ja = %q / %q", ja.EOLRuntimeText, ja.FixNoteEOLRuntime)
	}
}

func TestWebhook_DockerfileRebuildRuntimes(t *testing.T) {
	it := runtimeRebuildItem(remediation.DockerfileFromCompose)
	it.Entities = []remediation.DockerfileEntity{{
		Category: it.Category, Reason: it.Reason, RebuildRuntimes: it.RebuildRuntimes,
	}}
	data, err := json.Marshal(dockerfileItemPayloadOf(it, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"package": "Node.js", "installed": "22.23.3", "base_version": "22.23.4", "disappearing": []any{"CVE-1", "CVE-2", "CVE-3"}}
	for name, v := range map[string]any{"item": m["rebuild_runtimes"], "entity": m["entities"].([]any)[0].(map[string]any)["rebuild_runtimes"]} {
		list, ok := v.([]any)
		if !ok || len(list) != 1 {
			t.Fatalf("%s rebuild_runtimes = %v", name, v)
		}
		got := list[0].(map[string]any)
		if _, has := got["remaining"]; has {
			t.Errorf("%s: empty remaining is not omitted: %v", name, got)
		}
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		if string(gj) != string(wj) {
			t.Errorf("%s = %s, want %s", name, gj, wj)
		}
	}

	it.RebuildRuntimes, it.Entities[0].RebuildRuntimes = nil, nil
	data, _ = json.Marshal(dockerfileItemPayloadOf(it, nil, nil))
	if strings.Contains(string(data), "rebuild_runtimes") {
		t.Errorf("an empty record is written: %s", data)
	}
}
