package nodecore

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	octoberURL = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
	testNow    = "2026-10-25T12:00:00Z"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var (
	fixtureOnce sync.Once
	fixtureSnap *Snapshot
	fixtureErr  error
)

// fixtureSnapshot builds a snapshot from the recorded datasets: the
// security-wg index, the release list and schedule, and the posts of the
// last 180 days (October, July, June 2026).
func fixtureSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	fixtureOnce.Do(func() {
		log := quietLog()
		wg, skipped, err := parseSecurityWG(readTestdata(t, "core-index.json"), log)
		if err != nil {
			fixtureErr = err
			return
		}
		releases, err := parseReleases(readTestdata(t, "dist-index.json"))
		if err != nil {
			fixtureErr = err
			return
		}
		eol, err := parseSchedule(readTestdata(t, "schedule.json"))
		if err != nil {
			fixtureErr = err
			return
		}
		var blog []blogAdvisory
		dropped := 0
		for _, post := range []string{"october", "july", "june"} {
			slug := post + "-2026-security-releases"
			a, d := parseBlogPost(slug, readTestdata(t, slug+".md"), time.Time{}, log)
			blog = append(blog, a...)
			dropped += d
		}
		fixtureSnap = newSnapshot(wg, skipped, blog, dropped, releases, eol)
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return fixtureSnap
}

func byID(advs []Advisory) map[string]Advisory {
	m := map[string]Advisory{}
	for _, a := range advs {
		m[a.VulnID] = a
	}
	return m
}

func TestSecurityWGFixtureParses(t *testing.T) {
	data := readTestdata(t, "core-index.json")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var npm []string
	for id, msg := range raw {
		_, isNPM, err := parseWGEntry(id, msg)
		if err != nil {
			t.Errorf("entry %s does not parse: %v", id, err)
		}
		if isNPM {
			npm = append(npm, id)
		}
	}
	sort.Strings(npm)
	if got, want := strings.Join(npm, ","), "26,78,81,82,87"; got != want {
		t.Errorf("npm-excluded ids = %s, want %s", got, want)
	}

	entries, skipped, err := parseSecurityWG(data, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if got, want := len(entries), len(raw)-len(npm); got != want {
		t.Errorf("entries = %d, want %d", got, want)
	}
}

func TestParseWGEntryUnparseable(t *testing.T) {
	for name, msg := range map[string]string{
		"bad range":   `{"cve":["CVE-1"],"vulnerable":"~1.2.3","patched":"^1.2.4","affectedEnvironments":["all"]}`,
		"bad patched": `{"cve":["CVE-1"],"vulnerable":"1.x","patched":"","affectedEnvironments":["all"]}`,
		"bad json":    `{"cve":"CVE-1"}`,
	} {
		if _, _, err := parseWGEntry("5", json.RawMessage(msg)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, _, err := parseWGEntry("x", json.RawMessage(`{}`)); err == nil {
		t.Error("non-numeric id: want error")
	}

	// One bad entry is counted and skipped; the rest still parse.
	data := `{"1":{"cve":["CVE-1"],"vulnerable":"1.x","patched":"^1.2.4","affectedEnvironments":["all"]},
		"2":{"cve":["CVE-2"],"vulnerable":"wat","patched":"^1.2.4","affectedEnvironments":["all"]}}`
	entries, skipped, err := parseSecurityWG([]byte(data), quietLog())
	if err != nil || len(entries) != 1 || skipped != 1 {
		t.Errorf("entries=%d skipped=%d err=%v, want 1, 1, nil", len(entries), skipped, err)
	}
}

func TestMatchRealData(t *testing.T) {
	sn := fixtureSnapshot(t)
	tests := []struct {
		name    string
		version string
		os      string
		present map[string]string // CVE -> "severity/status/fixed"
		absent  []string
	}{
		{
			name: "22.23.3 gets October fixes", version: "22.23.3",
			present: map[string]string{"CVE-2026-111497": "HIGH/fixed/22.23.4"},
			absent:  []string{"CVE-2026-105483", "CVE-2026-106070", "CVE-2026-58045"},
		},
		{
			name: "24.22.0", version: "24.22.0",
			present: map[string]string{"CVE-2026-105483": "HIGH/fixed/24.22.1", "CVE-2026-111497": "HIGH/fixed/24.22.1"},
		},
		{
			name: "26.12.0 line 26 only advisory", version: "26.12.0",
			present: map[string]string{"CVE-2026-106070": "LOW/fixed/26.12.1"},
		},
		{
			name: "22.23.1 also gets July", version: "22.23.1",
			present: map[string]string{
				"CVE-2026-58045":  "MEDIUM/fixed/22.23.2",
				"CVE-2026-56846":  "HIGH/fixed/22.23.2",
				"CVE-2026-111497": "HIGH/fixed/22.23.4",
			},
		},
		{
			name: "explicit patched range wins over EOL", version: "7.10.1",
			absent: []string{"CVE-2017-1000381"},
			// line 7 ended in 2017; a later advisory is still an EOL finding
			present: map[string]string{"CVE-2026-111497": "HIGH/end_of_life/"},
		},
		{
			name: "EOL line gets October blog CVEs", version: "20.20.0",
			present: map[string]string{
				"CVE-2026-111497": "HIGH/end_of_life/",
				"CVE-2026-105483": "HIGH/end_of_life/",
				"CVE-2026-106070": "LOW/end_of_life/",
			},
		},
		{
			name: "ranges decide over EOL for a line they cover", version: "20.20.0",
			present: map[string]string{"CVE-2026-21637": "HIGH/fixed/20.20.2"},
		},
		{
			name: "patched line is not reported", version: "20.20.2",
			absent: []string{"CVE-2026-21637"},
		},
		{
			name: "win32-only entries are not reported on linux", version: "4.0.0", os: "linux",
			absent: win32OnlyCVEs(t),
		},
		{
			name: "empty os means linux", version: "22.23.3", os: "",
			present: map[string]string{"CVE-2026-111497": "HIGH/fixed/22.23.4"},
		},
		{
			name: "future line gets no EOL rule", version: "28.0.0",
			absent: []string{"CVE-2026-111497", "CVE-2026-58045"},
		},
		{
			name: "unscheduled line gets no EOL rule", version: "3.0.0",
			absent: []string{"CVE-2026-111497"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := byID(sn.Match(tc.version, tc.os))
			for cve, want := range tc.present {
				a, ok := got[cve]
				if !ok {
					t.Errorf("%s missing", cve)
					continue
				}
				if want == "" {
					continue
				}
				if s := a.Severity + "/" + string(a.Status) + "/" + a.FixedVer; s != want {
					t.Errorf("%s = %s, want %s", cve, s, want)
				}
			}
			for _, cve := range tc.absent {
				if _, ok := got[cve]; ok {
					t.Errorf("%s should not be reported", cve)
				}
			}
		})
	}
}

// win32OnlyCVEs lists CVEs that only win32-only entries carry.
func win32OnlyCVEs(t *testing.T) []string {
	t.Helper()
	var raw map[string]wgRaw
	if err := json.Unmarshal(readTestdata(t, "core-index.json"), &raw); err != nil {
		t.Fatal(err)
	}
	other := map[string]bool{}
	for _, e := range raw {
		if !(len(e.AffectedEnvironments) == 1 && e.AffectedEnvironments[0] == "win32") {
			for _, c := range e.CVE {
				other[c] = true
			}
		}
	}
	var out []string
	for _, e := range raw {
		if len(e.AffectedEnvironments) == 1 && e.AffectedEnvironments[0] == "win32" {
			for _, c := range e.CVE {
				if !other[c] {
					out = append(out, c)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("fixture has no win32-only CVE")
	}
	return out
}

func TestMatchEntryFields(t *testing.T) {
	sn := fixtureSnapshot(t)
	got := byID(sn.Match("22.23.3", "linux"))

	// Blog-sourced (not in security-wg): heading title and the post URL.
	a := got["CVE-2026-111497"]
	if a.URL != octoberURL {
		t.Errorf("URL = %q, want %q", a.URL, octoberURL)
	}
	if want := "Node.js Brotli decoder out-of-bounds write permits remote code execution"; a.Title != want {
		t.Errorf("Title = %q, want %q", a.Title, want)
	}

	// security-wg-sourced: its own description and ref.
	b := byID(sn.Match("22.23.1", "linux"))["CVE-2026-58045"]
	if !strings.HasPrefix(b.Title, "Reachable assertion in node:zlib") || !strings.Contains(b.URL, "july-2026-security-releases") {
		t.Errorf("security-wg advisory = %+v", b)
	}
}

func TestMatchJuneLines(t *testing.T) {
	sn := fixtureSnapshot(t)
	// Fixed in 26.3.1 only for line 26: 26.3.0 is below it.
	if a, ok := byID(sn.Match("26.3.0", "linux"))["CVE-2026-48936"]; !ok || a.FixedVer != "26.3.1" {
		t.Errorf("26.3.0 CVE-2026-48936 = %+v, %v", a, ok)
	}
	for _, v := range []string{"22.22.2", "24.16.0"} {
		if _, ok := byID(sn.Match(v, "linux"))["CVE-2026-48936"]; ok {
			t.Errorf("%s should not get CVE-2026-48936", v)
		}
	}
	for _, v := range []string{"22.22.2", "24.16.0"} {
		if _, ok := byID(sn.Match(v, "linux"))["CVE-2026-48937"]; !ok {
			t.Errorf("%s should get CVE-2026-48937", v)
		}
	}
	if _, ok := byID(sn.Match("26.3.0", "linux"))["CVE-2026-48937"]; ok {
		t.Error("26.3.0 should not get CVE-2026-48937")
	}
}

func TestBlogPostParsing(t *testing.T) {
	log := quietLog()
	t.Run("march uses 20.x and v25.x forms", func(t *testing.T) {
		advs, dropped := parseBlogPost("march-2026-security-releases", readTestdata(t, "march-2026-security-releases.md"), time.Time{}, log)
		if dropped != 0 || len(advs) != 9 {
			t.Fatalf("advs=%d dropped=%d, want 9, 0", len(advs), dropped)
		}
		for _, a := range advs {
			switch a.cves[0] {
			case "CVE-2026-21710":
				if len(a.affected) != 4 || !a.affected[25] || !a.affected[20] {
					t.Errorf("CVE-2026-21710 affected = %v", a.affected)
				}
			case "CVE-2026-21714": // "Node.js 20, 22, 24 and 25"
				if len(a.affected) != 4 || !a.affected[20] || !a.affected[25] {
					t.Errorf("CVE-2026-21714 affected = %v", a.affected)
				}
			case "CVE-2026-21711":
				if len(a.affected) != 1 || !a.affected[25] {
					t.Errorf("CVE-2026-21711 affected = %v", a.affected)
				}
			}
			if a.fixed[20].String() != "20.20.2" {
				t.Errorf("%v fixed[20] = %v", a.cves, a.fixed[20])
			}
		}
	})
	t.Run("june uses Node.js N form and front matter date", func(t *testing.T) {
		advs, _ := parseBlogPost("june-2026-security-releases", readTestdata(t, "june-2026-security-releases.md"), time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), log)
		if len(advs) != 12 {
			t.Fatalf("advs = %d, want 12", len(advs))
		}
		for _, a := range advs {
			if a.posted.Format("2006-01-02") != "2026-06-18" {
				t.Errorf("%v posted = %v", a.cves, a.posted)
			}
		}
	})
}

func TestBlogPostEdgeCases(t *testing.T) {
	fallback := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	post := `## Something (CVE-2026-1) - (HIGH)

No lines named here at all.

## Fix for npm (CVE-2026-2) - (low)

This vulnerability affects Node.js 22.

## Two at once (CVE-2026-3, CVE-2026-4) - (Medium)

Affects 22.x.

## Downloads and release details

- [Node.js v22.1.0](/blog/release/v22.1.0/)
`
	advs, dropped := parseBlogPost("p", []byte(post), fallback, quietLog())
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (the section without affected lines)", dropped)
	}
	if len(advs) != 1 {
		t.Fatalf("advs = %d, want 1 (npm heading is excluded)", len(advs))
	}
	a := advs[0]
	if len(a.cves) != 2 || a.severity != "Medium" || !a.affected[22] || a.fixed[22].String() != "22.1.0" || !a.posted.Equal(fallback) {
		t.Errorf("advisory = %+v", a)
	}

	advs, dropped = parseBlogPost("hashdos", []byte("---\ndate: 2026-03-24\n---\n\n## An analysis article\n\nText.\n"), fallback, quietLog())
	if len(advs) != 0 || dropped != 0 {
		t.Errorf("article without advisory headings: advs=%d dropped=%d", len(advs), dropped)
	}
}

func TestLineMajors(t *testing.T) {
	tests := map[string][]int{
		"This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.":                                        {22, 24, 26},
		"This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**.": {22, 24, 26},
		"affects HTTP2 users on Node.js 20, 22, 24 and 25.":                                                           {20, 22, 24, 25},
		"affects all Node.js HTTP servers on **20.x, 22.x, 24.x, and v25.x**":                                         {20, 22, 24, 25},
		"affects Node.js 22.23.1 and later":                                                                           nil,
		"affects nothing numbered":                                                                                    nil,
	}
	for line, want := range tests {
		got := lineMajors(line)
		if len(got) != len(want) {
			t.Errorf("%q = %v, want %v", line, got, want)
			continue
		}
		for _, n := range want {
			if !got[n] {
				t.Errorf("%q = %v, want %v", line, got, want)
			}
		}
	}
}

func TestMatchDuplicateCVEUsesLowestID(t *testing.T) {
	data := `{
	  "7": {"cve":["CVE-1"],"vulnerable":"22.x","patched":"^22.23.9","severity":"low","description":"seven","affectedEnvironments":["all"]},
	  "3": {"cve":["CVE-1","CVE-2"],"vulnerable":"22.x","patched":"^22.23.5","severity":"high","description":"three","affectedEnvironments":["all"]},
	  "9": {"cve":[],"vulnerable":"22.x","patched":"^22.23.6","severity":"","description":"","overview":"first line\nsecond","affectedEnvironments":["all"]}
	}`
	wg, _, err := parseSecurityWG([]byte(data), quietLog())
	if err != nil {
		t.Fatal(err)
	}
	sn := newSnapshot(wg, 0, nil, 0, map[version]time.Time{}, map[int]time.Time{})
	got := byID(sn.Match("22.23.0", "linux"))
	if a := got["CVE-1"]; a.Title != "three" || a.FixedVer != "22.23.5" {
		t.Errorf("CVE-1 = %+v, want entry 3", a)
	}
	if _, ok := got["CVE-2"]; !ok {
		t.Error("CVE-2 missing")
	}
	a, ok := got["NSWG-CORE-9"]
	if !ok || a.Severity != "UNKNOWN" || a.Title != "first line" {
		t.Errorf("NSWG-CORE-9 = %+v, %v", a, ok)
	}
}

func TestMatchInvalidVersion(t *testing.T) {
	if got := fixtureSnapshot(t).Match("22.1", "linux"); got != nil {
		t.Errorf("invalid version matched %v", got)
	}
}
