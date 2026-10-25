package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func uncheckedReport(refs ...string) analyze.Report {
	var scans []scanner.ImageScan
	for _, ref := range refs {
		scans = append(scans, scanner.ImageScan{Image: ref, RuntimeUnchecked: true})
	}
	return analyze.Build(scans, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC))
}

func TestRuntimeUncheckedNote(t *testing.T) {
	cases := []struct {
		lang Language
		want string
	}{
		{LanguageEN, "Node.js advisories could not be fetched, so the Node.js runtime of 2 image(s) was not checked."},
		{LanguageJA, "Node.js の脆弱性情報を取得できなかったため、2 件のイメージの Node.js 本体を照合していません。"},
	}
	for _, c := range cases {
		r := uncheckedReport("a:1", "b:1")
		if got := renderFull(r, c.lang); !strings.Contains(got, c.want) {
			t.Errorf("%s full view lacks the note %q:\n%s", c.lang, c.want, got)
		}
		d, _ := state.Compute(state.State{}, r)
		if got := renderDiff(r, d, false, false, c.lang); !strings.Contains(got, c.want) {
			t.Errorf("%s diff view lacks the note %q:\n%s", c.lang, c.want, got)
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
	if len(got) != 2 || got[0] != "a:1" || got[1] != "b:1" {
		t.Errorf("runtime_unchecked = %v, want [a:1 b:1]", m["runtime_unchecked"])
	}

	data, _ = json.Marshal(BuildWebhookPayload(analyze.Build(nil, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)), nil))
	if strings.Contains(string(data), "runtime_unchecked") {
		t.Errorf("runtime_unchecked must be omitted when empty: %s", data)
	}
}
