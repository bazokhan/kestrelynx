package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func uncheckedReport(refs ...string) analyze.Report {
	return uncheckedReportOf([]string{inventory.NodeRuntimePackage}, refs...)
}

// uncheckedReportOf marks every image in refs as having the given runtimes
// unchecked.
func uncheckedReportOf(pkgs []string, refs ...string) analyze.Report {
	var scans []scanner.ImageScan
	for _, ref := range refs {
		scans = append(scans, scanner.ImageScan{Image: ref, RuntimeUnchecked: pkgs})
	}
	return analyze.Build(scans, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC))
}

func TestRuntimeUncheckedNote(t *testing.T) {
	both := []string{inventory.PythonRuntimePackage, inventory.NodeRuntimePackage}
	cases := []struct {
		name string
		lang Language
		r    analyze.Report
		want string
	}{
		{"one runtime", LanguageEN, uncheckedReport("a:1", "b:1"), "ℹ️ Advisories for Node.js could not be fetched, so the runtime of 2 image(s) was not checked."},
		{"one runtime", LanguageJA, uncheckedReport("a:1", "b:1"), "ℹ️ Node.js の脆弱性情報を取得できなかったため、2 件のイメージの本体を照合していません。"},
		{"two runtimes", LanguageEN, uncheckedReportOf(both, "a:1", "b:1"), "ℹ️ Advisories for Node.js, Python runtime could not be fetched, so the runtime of 2 image(s) was not checked."},
		{"two runtimes", LanguageJA, uncheckedReportOf(both, "a:1", "b:1"), "ℹ️ Node.js・Python runtime の脆弱性情報を取得できなかったため、2 件のイメージの本体を照合していません。"},
		// One image with two runtimes counts once.
		{"one image", LanguageEN, uncheckedReportOf(both, "a:1"), "Node.js, Python runtime could not be fetched, so the runtime of 1 image(s) was not checked."},
		{"one image", LanguageJA, uncheckedReportOf(both, "a:1"), "Node.js・Python runtime の脆弱性情報を取得できなかったため、1 件のイメージの本体を照合していません。"},
	}
	for _, c := range cases {
		r := c.r
		if got := renderFull(r, c.lang); !strings.Contains(got, c.want) {
			t.Errorf("%s %s full view lacks the note %q:\n%s", c.name, c.lang, c.want, got)
		}
		d, _ := state.Compute(state.State{}, r)
		if got := renderDiff(r, d, false, false, c.lang); !strings.Contains(got, c.want) {
			t.Errorf("%s %s diff view lacks the note %q:\n%s", c.name, c.lang, c.want, got)
		}
	}
}

func TestRuntimeUncheckedNoteAbsentWhenChecked(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "a:1"}}, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC))
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		got := renderFull(r, lang)
		if strings.Contains(got, "Node.js") {
			t.Errorf("%s: unexpected Node.js note:\n%s", lang, got)
		}
	}
}

func TestWebhookRuntimeUnchecked(t *testing.T) {
	data, err := json.Marshal(BuildWebhookPayload(uncheckedReport("b:1", "a:1"), nil))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	got, _ := m["runtime_unchecked"].([]any)
	if len(got) != 2 {
		t.Fatalf("runtime_unchecked = %v, want two objects", m["runtime_unchecked"])
	}
	for i, img := range []string{"a:1", "b:1"} {
		e, _ := got[i].(map[string]any)
		if e["image"] != img || e["package"] != inventory.NodeRuntimePackage || len(e) != 2 {
			t.Errorf("runtime_unchecked[%d] = %v, want image %s, package %s", i, got[i], img, inventory.NodeRuntimePackage)
		}
	}

	data, err = json.Marshal(BuildWebhookPayload(uncheckedReportOf([]string{inventory.PythonRuntimePackage, inventory.NodeRuntimePackage}, "a:1"), nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"runtime_unchecked":[{"image":"a:1","package":"Node.js"},{"image":"a:1","package":"Python runtime"}]`; !strings.Contains(string(data), want) {
		t.Errorf("payload lacks %s:\n%s", want, data)
	}

	data, _ = json.Marshal(BuildWebhookPayload(analyze.Build(nil, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)), nil))
	if strings.Contains(string(data), "runtime_unchecked") {
		t.Errorf("runtime_unchecked must be omitted when empty: %s", data)
	}
}
