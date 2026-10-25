package pycore

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var (
	fixtureOnce sync.Once
	fixtureSnap *Snapshot
	fixtureErr  error
)

// fixtureSnapshot joins the recorded datasets: the PSF archive, every CVE
// record, the release list and the release cycle.
func fixtureSnapshot(t testing.TB) *Snapshot {
	t.Helper()
	fixtureOnce.Do(func() {
		advs, err := parseArchive(readTestdata(t, "psf-advisory-database.tar.gz"))
		if err != nil {
			fixtureErr = err
			return
		}
		records := map[string]cveInfo{}
		for _, a := range advs {
			if a.withdrawn {
				continue
			}
			for _, c := range a.cves {
				info, err := parseCVE(c, realCVERecords(t)[c+".json"])
				if err != nil {
					fixtureErr = err
					return
				}
				records[c] = info
			}
		}
		finals, err := parseReleases(readTestdata(t, "python-releases.json"))
		if err != nil {
			fixtureErr = err
			return
		}
		eol, err := parseReleaseCycle(readTestdata(t, "release-cycle.json"))
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureSnap = newSnapshot(advs, records, finals, eol)
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return fixtureSnap
}

func mustVersion(t testing.TB, s string) version {
	t.Helper()
	v, ok := parseVersion(s)
	if !ok {
		t.Fatalf("bad version %q", s)
	}
	return v
}

func matchIDs(advs []Advisory) []string {
	ids := make([]string, len(advs))
	for i, a := range advs {
		ids[i] = a.VulnID
	}
	sort.Strings(ids)
	return ids
}

func countStatus(advs []Advisory) (fixed, affected, eol int) {
	for _, a := range advs {
		switch a.Status {
		case scanner.StatusFixed:
			fixed++
		case scanner.StatusAffected:
			affected++
		case scanner.StatusEndOfLife:
			eol++
		}
	}
	return
}

func bySeverity(advs []Advisory, sevs ...string) []Advisory {
	want := map[string]bool{}
	for _, s := range sevs {
		want[s] = true
	}
	var out []Advisory
	for _, a := range advs {
		if want[a.Severity] {
			out = append(out, a)
		}
	}
	return out
}

func find(advs []Advisory, id string) (Advisory, bool) {
	for _, a := range advs {
		if a.VulnID == id {
			return a, true
		}
	}
	return Advisory{}, false
}

func TestVersionOrder(t *testing.T) {
	order := []string{"3.15.0a1", "3.15.0a2", "3.15.0b1", "3.15.0b4", "3.15.0rc1", "3.15.0rc2", "3.15.0", "3.15.1", "3.16.0a1"}
	for i := range order {
		for j := range order {
			got := mustVersion(t, order[i]).compare(mustVersion(t, order[j]))
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	for _, s := range order {
		if got := mustVersion(t, s).String(); got != s {
			t.Errorf("String(%s) = %s", s, got)
		}
	}
	for _, bad := range []string{"", "3", "3.12", "3.012.1", "v3.12.1", "3.12.1-rc1", "3.12.1c1", "3.12.1rc", "3.12.1 ", "3.1234567890.1"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("parseVersion(%q) accepted", bad)
		}
	}
}

func TestOutOfScopeCVEsAreSkipped(t *testing.T) {
	sn := fixtureSnapshot(t)
	if len(sn.cves) != 77 {
		t.Errorf("in-scope CVEs = %d, want 77", len(sn.cves))
	}
	// 182 CVE aliases: 77 with CNA ranges, 1 rejected, the rest without.
	if sn.outOfScope != 104 || sn.rejected != 1 || sn.withdrawn != 0 {
		t.Errorf("outOfScope=%d rejected=%d withdrawn=%d, want 104/1/0", sn.outOfScope, sn.rejected, sn.withdrawn)
	}
	for _, c := range sn.cves {
		if c.id == "CVE-2022-45061" || c.id == "CVE-2013-1752" {
			t.Errorf("%s must not be matched", c.id)
		}
	}
	for _, v := range []string{"3.7.0", "3.8.0", "3.10.22", "3.12.0"} {
		if _, ok := find(sn.Match(mustVersion(t, v), "linux"), "CVE-2022-45061"); ok {
			t.Errorf("CVE-2022-45061 reported for %s", v)
		}
	}
}

func TestMatchCounts(t *testing.T) {
	sn := fixtureSnapshot(t)
	// "NONE" is a CVSS rating the record of CVE-2026-3479 carries.
	all := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"}
	tests := []struct {
		ver                string
		sevs               []string
		n, fixed, affected int
		eol                int
		fixedVer           string // the highest per-CVE fix
	}{
		{"3.12.14", all, 19, 8, 11, 0, "3.12.15"},
		{"3.12.14", []string{"HIGH", "CRITICAL"}, 4, 3, 1, 0, "3.12.15"},
		{"3.12.15", all, 11, 0, 11, 0, ""},
		{"3.13.8", all, 51, 45, 6, 0, "3.13.16"},
		{"3.10.22", all, 16, 0, 0, 16, ""},
		{"3.14.4", all, 33, 29, 4, 0, "3.14.9"},
		{"3.12.0", all, 73, 62, 11, 0, "3.12.15"},
	}
	for _, tc := range tests {
		advs := bySeverity(sn.Match(mustVersion(t, tc.ver), "linux"), tc.sevs...)
		fixed, affected, eol := countStatus(advs)
		if len(advs) != tc.n || fixed != tc.fixed || affected != tc.affected || eol != tc.eol {
			t.Errorf("%s %v: n=%d fixed=%d affected=%d eol=%d, want %d/%d/%d/%d",
				tc.ver, tc.sevs, len(advs), fixed, affected, eol, tc.n, tc.fixed, tc.affected, tc.eol)
		}
		var highest version
		for _, a := range advs {
			if a.Status == scanner.StatusFixed {
				if v := mustVersion(t, a.FixedVer); v.compare(highest) > 0 {
					highest = v
				}
			} else if a.FixedVer != "" {
				t.Errorf("%s %s: FixedVer %q on status %s", tc.ver, a.VulnID, a.FixedVer, a.Status)
			}
		}
		if tc.fixedVer != "" && highest.String() != tc.fixedVer {
			t.Errorf("%s: highest per-CVE fix = %s, want %s", tc.ver, highest, tc.fixedVer)
		}
	}

	// The standard severities leave out the one NONE rating.
	std := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	if got := len(bySeverity(sn.Match(mustVersion(t, "3.12.14"), "linux"), std...)); got != 18 {
		t.Errorf("3.12.14 with the five standard severities = %d findings, want 18", got)
	}
}

func TestMatchNoFixCritical(t *testing.T) {
	sn := fixtureSnapshot(t)
	a, ok := find(sn.Match(mustVersion(t, "3.12.14"), "linux"), "CVE-2026-115557")
	if !ok {
		t.Fatal("CVE-2026-115557 missing")
	}
	if a.Severity != "CRITICAL" || a.Status != scanner.StatusAffected || a.FixedVer != "" {
		t.Errorf("CVE-2026-115557 = %+v, want CRITICAL affected without fix", a)
	}
	if a.Title == "" || !strings.HasPrefix(a.URL, "https://") {
		t.Errorf("title=%q url=%q", a.Title, a.URL)
	}
}

func TestEndOfLifeLine(t *testing.T) {
	sn := fixtureSnapshot(t)
	advs := sn.Match(mustVersion(t, "3.10.22"), "linux")
	if len(advs) != 16 {
		t.Fatalf("findings = %d, want 16", len(advs))
	}
	for _, a := range advs {
		if a.Status != scanner.StatusEndOfLife || a.FixedVer != "" {
			t.Errorf("%s: status=%s fixed=%q, want end_of_life without fix", a.VulnID, a.Status, a.FixedVer)
		}
	}
}

func TestPerCVEFixedVersion(t *testing.T) {
	sn := fixtureSnapshot(t)
	var cve cveAdvisory
	for _, c := range sn.cves {
		if c.id == "CVE-2026-6019" {
			cve = c
		}
	}
	if cve.id == "" {
		t.Fatal("CVE-2026-6019 missing")
	}
	var ranges []versionRange
	for _, it := range cve.items {
		ranges = append(ranges, it.ranges...)
	}
	// The 3.14 range ends at 3.14.5rc1: the fix is the first final release
	// above it.
	fix, ok := sn.fixedIn(mustVersion(t, "3.14.4"), ranges)
	if !ok || fix.String() != "3.14.5" {
		t.Errorf("fixedIn(3.14.4) = %v, %v, want 3.14.5", fix, ok)
	}
	// 3.13.8 is in the 0..3.13.14 range.
	fix, ok = sn.fixedIn(mustVersion(t, "3.13.8"), ranges)
	if !ok || fix.String() != "3.13.14" {
		t.Errorf("fixedIn(3.13.8) = %v, %v, want 3.13.14", fix, ok)
	}
	a, ok := find(sn.Match(mustVersion(t, "3.14.4"), "linux"), "CVE-2026-6019")
	if !ok || a.Status != scanner.StatusFixed || a.FixedVer != "3.14.5" || a.Severity != "LOW" {
		t.Errorf("Match = %+v, %v", a, ok)
	}
}

func TestFixedInNeedsAllLaterReleasesClear(t *testing.T) {
	// A fix that is followed by an affected release (a regression, or a
	// range that skips one) is not a fix.
	sn := &Snapshot{finals: map[int][]version{
		12: {{3, 12, 1, phaseFinal, 0}, {3, 12, 2, phaseFinal, 0}, {3, 12, 3, phaseFinal, 0}, {3, 12, 4, phaseFinal, 0}},
	}}
	ranges := []versionRange{
		{noLower: true, hi: version{3, 12, 2, phaseFinal, 0}},
		{lo: version{3, 12, 3, phaseFinal, 0}, hi: version{3, 12, 3, phaseFinal, 0}, inclusive: true},
	}
	fix, ok := sn.fixedIn(version{3, 12, 1, phaseFinal, 0}, ranges)
	if !ok || fix.String() != "3.12.4" {
		t.Errorf("fix = %v, %v, want 3.12.4 (3.12.2 is followed by affected 3.12.3)", fix, ok)
	}
	if _, ok := sn.fixedIn(version{3, 12, 1, phaseFinal, 0}, append(ranges, versionRange{noLower: true, hi: version{3, 12, 4, phaseFinal, 0}, inclusive: true})); ok {
		t.Error("a range covering the newest release leaves no fix")
	}
}

func TestPlatforms(t *testing.T) {
	sn := fixtureSnapshot(t)
	advs := sn.Match(mustVersion(t, "3.12.0"), "linux")
	a, ok := find(advs, "CVE-2023-6507")
	if !ok {
		t.Fatal("CVE-2023-6507 (platforms POSIX) must apply to linux")
	}
	if a.Status != scanner.StatusFixed || a.FixedVer != "3.12.1" {
		t.Errorf("CVE-2023-6507 = %+v", a)
	}
	for _, osName := range []string{"linux", "", "Linux"} {
		for _, v := range []string{"3.8.0", "3.9.0", "3.10.0", "3.11.0", "3.12.0", "3.13.0", "3.14.0"} {
			if _, ok := find(sn.Match(mustVersion(t, v), osName), "CVE-2024-4030"); ok {
				t.Errorf("CVE-2024-4030 (Windows only) applied to %s on os %q", v, osName)
			}
		}
	}
	// It is in the data, though, and applies to a Windows image.
	found := false
	for _, v := range []string{"3.12.0", "3.11.0", "3.10.0", "3.9.0", "3.8.0"} {
		if _, ok := find(sn.Match(mustVersion(t, v), "windows"), "CVE-2024-4030"); ok {
			found = true
		}
	}
	if !found {
		t.Error("CVE-2024-4030 never applies to a Windows image either")
	}
	if _, ok := find(sn.Match(mustVersion(t, "3.12.0"), ""), "CVE-2023-6507"); !ok {
		t.Error("an empty OS must count as linux")
	}
}

func TestPlatformApplies(t *testing.T) {
	tests := []struct {
		platforms []string
		os        string
		want      bool
	}{
		{nil, "linux", true},
		{[]string{"Linux"}, "linux", true},
		{[]string{"POSIX"}, "linux", true},
		{[]string{"Unix"}, "", true},
		{[]string{"linux", "Windows"}, "linux", true},
		{[]string{"GNU/Linux"}, "linux", true},
		{[]string{"Windows"}, "linux", false},
		{[]string{"MacOS", "iOS", "Android", "WASI", "Emscripten"}, "linux", false},
		{[]string{"macOS", "Windows"}, "Linux", false},
		{[]string{"Windows", "Plan 9"}, "linux", true},
		{[]string{"BSD"}, "linux", true},
		{[]string{"Windows"}, "windows", true},
		{[]string{"Linux"}, "windows", false},
	}
	for _, tc := range tests {
		if got := platformApplies(tc.platforms, tc.os); got != tc.want {
			t.Errorf("platformApplies(%v, %q) = %v, want %v", tc.platforms, tc.os, got, tc.want)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		name, json, want string
	}{
		{"v4 first", `{"containers":{"cna":{"metrics":[{"cvssV3_1":{"baseSeverity":"HIGH"}},{"cvssV4_0":{"baseSeverity":"low"}}]}}}`, "LOW"},
		{"v3.1 over v3.0", `{"containers":{"cna":{"metrics":[{"cvssV3_0":{"baseSeverity":"LOW"}},{"cvssV3_1":{"baseSeverity":"medium"}}]}}}`, "MEDIUM"},
		{"v3.0", `{"containers":{"cna":{"metrics":[{"cvssV3_0":{"baseSeverity":"CRITICAL"}}]}}}`, "CRITICAL"},
		{"adp fallback", `{"containers":{"cna":{"metrics":[{"other":{}}]},"adp":[{"metrics":[{"cvssV3_1":{"baseSeverity":"HIGH"}}]}]}}`, "HIGH"},
		{"cna wins over adp", `{"containers":{"cna":{"metrics":[{"cvssV3_0":{"baseSeverity":"LOW"}}]},"adp":[{"metrics":[{"cvssV4_0":{"baseSeverity":"HIGH"}}]}]}}`, "LOW"},
		{"first adp with one", `{"containers":{"adp":[{"metrics":[{"other":{}}]},{"metrics":[{"cvssV3_1":{"baseSeverity":"MEDIUM"}}]},{"metrics":[{"cvssV3_1":{"baseSeverity":"HIGH"}}]}]}}`, "MEDIUM"},
		{"none", `{"containers":{"cna":{}}}`, "UNKNOWN"},
	}
	for _, tc := range tests {
		var raw rawCVE
		if err := jsonUnmarshal(tc.json, &raw); err != nil {
			t.Fatal(err)
		}
		if got := severityOf(raw); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestTitleAndURL(t *testing.T) {
	adv := func(id, summary, details, url string) advisory {
		return advisory{id: id, summary: summary, details: details, url: url, cves: []string{"CVE-2026-1" + id[len(id)-1:] + "000"}}
	}
	cve := func(id string) string { return id }
	advs := []advisory{
		adv("PSF-2026-1", "A summary", "Details. More.", "https://example.test/a"),
		adv("PSF-2026-2", "", "The first sentence. The second one.", ""),
		adv("PSF-2026-3", "", "Only one line without a period", ""),
		adv("PSF-2026-4", "", "A hard-wrapped\nsentence. Next.", ""),
		adv("PSF-2026-5", "", "First paragraph\n\nSecond paragraph.", ""),
	}
	records := map[string]cveInfo{}
	for _, a := range advs {
		records[cve(a.cves[0])] = cveInfo{ranged: true, severity: "HIGH"}
	}
	sn := newSnapshot(advs, records, nil, nil)
	want := map[string][2]string{
		"CVE-2026-11000": {"A summary", "https://example.test/a"},
		"CVE-2026-12000": {"The first sentence.", "https://osv.dev/vulnerability/PSF-2026-2"},
		"CVE-2026-13000": {"Only one line without a period", "https://osv.dev/vulnerability/PSF-2026-3"},
		"CVE-2026-14000": {"A hard-wrapped sentence.", "https://osv.dev/vulnerability/PSF-2026-4"},
		"CVE-2026-15000": {"First paragraph", "https://osv.dev/vulnerability/PSF-2026-5"},
	}
	if len(sn.cves) != 5 {
		t.Fatalf("cves = %d", len(sn.cves))
	}
	for _, c := range sn.cves {
		if w := want[c.id]; c.title != w[0] || c.url != w[1] {
			t.Errorf("%s: title=%q url=%q, want %q %q", c.id, c.title, c.url, w[0], w[1])
		}
	}
}

func TestParseCVEUnevaluable(t *testing.T) {
	tests := []struct {
		name     string
		versions string
		extra    string
	}{
		{"changes", `[{"version":"3.12.0","lessThan":"3.12.5","status":"affected","changes":[{"at":"3.12.2","status":"unaffected"}]}]`, ""},
		{"unknown versionType", `[{"version":"0","lessThan":"3.12.5","status":"affected","versionType":"semver"}]`, ""},
		{"git versionType", `[{"version":"0","lessThan":"abc123","status":"affected","versionType":"git"}]`, ""},
		{"bad upper bound", `[{"version":"0","lessThan":"3.12","status":"affected"}]`, ""},
		{"bad lower bound", `[{"version":"3.x","lessThan":"3.12.5","status":"affected"}]`, ""},
		{"bad inclusive bound", `[{"version":"0","lessThanOrEqual":"latest","status":"affected"}]`, ""},
		{"unaffected range", `[{"version":"3.12.0","lessThan":"3.12.5","status":"unaffected"}]`, ""},
		{"two upper bounds", `[{"version":"0","lessThan":"3.12.5","lessThanOrEqual":"3.12.6","status":"affected"}]`, ""},
		{"changes next to a good range", `[{"version":"0","lessThan":"3.12.5","status":"affected"},{"version":"3.13.0","status":"affected","changes":[]}]`, ""},
	}
	for _, tc := range tests {
		_, err := parseCVE("CVE-2026-1", []byte(recordJSON("CVE-2026-1", "PUBLISHED", tc.versions, tc.extra)))
		if err == nil {
			t.Errorf("%s: parsed, want an error", tc.name)
		}
	}
	for _, versionType := range []string{"python", "custom"} {
		v := `[{"version":"0","lessThan":"3.12.5","status":"affected","versionType":"` + versionType + `"}]`
		if _, err := parseCVE("CVE-2026-1", []byte(recordJSON("CVE-2026-1", "PUBLISHED", v, ""))); err != nil {
			t.Errorf("versionType %s: %v", versionType, err)
		}
	}
	if _, err := parseCVE("CVE-2026-1", []byte(recordJSON("CVE-2026-1", "PUBLISHED", `[{"version":"0","lessThan":"3.12.5","status":"affected"}]`, ""))); err != nil {
		t.Errorf("absent versionType: %v", err)
	}
}

func TestParseCVEScope(t *testing.T) {
	rejected, err := parseCVE("CVE-2026-1", []byte(recordJSON("CVE-2026-1", "REJECTED", `[{"version":"0","lessThan":"zzz","status":"affected","versionType":"semver"}]`, "")))
	if err != nil || !rejected.rejected {
		t.Errorf("REJECTED = %+v, %v; want rejected without evaluating the ranges", rejected, err)
	}
	// Another vendor or product, and items without upper bounds, are not
	// CPython ranges.
	other := `{"cveMetadata":{"cveId":"CVE-2026-1","state":"PUBLISHED"},"containers":{"cna":{"affected":[
		{"vendor":"Someone","product":"CPython","versions":[{"version":"0","lessThan":"3.12.5","status":"affected"}]},
		{"vendor":"Python Software Foundation","product":"pip","versions":[{"version":"0","lessThan":"24.0","status":"affected"}]},
		{"vendor":"Python Software Foundation","product":"CPython","versions":[{"version":"3.12.0","status":"affected"}]}]}}}`
	info, err := parseCVE("CVE-2026-1", []byte(other))
	if err != nil || info.ranged || info.rejected {
		t.Errorf("no CPython ranges = %+v, %v", info, err)
	}
	if _, err := parseCVE("CVE-2026-2", []byte(other)); err == nil {
		t.Error("record of another CVE accepted")
	}
}

func TestInclusiveAndLowerBounds(t *testing.T) {
	rec := recordJSON("CVE-2026-1", "PUBLISHED", `[{"version":"3.11.2","lessThanOrEqual":"3.11.4","status":"affected"},{"version":"3.13.0a1","lessThan":"3.13.0rc1","status":"affected"}]`, "")
	info, err := parseCVE("CVE-2026-1", []byte(rec))
	if err != nil {
		t.Fatal(err)
	}
	var rs []versionRange
	for _, it := range info.items {
		rs = append(rs, it.ranges...)
	}
	in := map[string]bool{
		"3.11.1": false, "3.11.2": true, "3.11.4": true, "3.11.5": false,
		"3.13.0a1": true, "3.13.0b4": true, "3.13.0rc1": false, "3.13.0": false,
	}
	for v, want := range in {
		if got := anyContains(rs, mustVersion(t, v)); got != want {
			t.Errorf("contains(%s) = %v, want %v", v, got, want)
		}
	}
}

func TestRecordURL(t *testing.T) {
	s := &Source{CVERecordBaseURL: "https://example.test/cves"}
	for cve, want := range map[string]string{
		"CVE-2026-115557": "https://example.test/cves/2026/115xxx/CVE-2026-115557.json",
		"CVE-2026-6019":   "https://example.test/cves/2026/6xxx/CVE-2026-6019.json",
		"CVE-2007-0450":   "https://example.test/cves/2007/0xxx/CVE-2007-0450.json",
		"CVE-2024-12345":  "https://example.test/cves/2024/12xxx/CVE-2024-12345.json",
	} {
		if got := s.recordURL(cve); got != want {
			t.Errorf("recordURL(%s) = %s, want %s", cve, got, want)
		}
		if p := recordPath(cve); !strings.HasSuffix(want, p[len("/cves"):]) {
			t.Errorf("test helper recordPath(%s) = %s disagrees with %s", cve, p, want)
		}
	}
}
