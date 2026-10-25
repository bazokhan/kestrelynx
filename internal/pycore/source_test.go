package pycore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	realCVEs = 182 // CVE aliases of the recorded PSF advisories
	hour     = time.Hour
)

func loadOK(t *testing.T, s *Source) *Snapshot {
	t.Helper()
	sn, err := s.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if sn == nil {
		t.Fatal("Load returned a nil snapshot without an error")
	}
	return sn
}

func loadFails(t *testing.T, s *Source) error {
	t.Helper()
	sn, err := s.Load(context.Background())
	if err == nil || sn != nil {
		t.Fatalf("Load = %v, %v; want an unusable snapshot", sn, err)
	}
	return err
}

func TestLoadFresh(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	sn := loadOK(t, src)

	if len(sn.cves) != 77 || sn.outOfScope != 104 || sn.rejected != 1 {
		t.Errorf("cves=%d outOfScope=%d rejected=%d, want 77/104/1", len(sn.cves), sn.outOfScope, sn.rejected)
	}
	for _, p := range []string{"/db", "/releases", "/cycle"} {
		if site.hitCount(p) != 1 {
			t.Errorf("%s fetched %d times, want 1", p, site.hitCount(p))
		}
	}
	if hits, _ := site.recordHits(); hits != realCVEs {
		t.Errorf("record requests = %d, want %d", hits, realCVEs)
	}
	// The result matches what the recorded datasets give directly.
	want := fixtureSnapshot(t).Match(mustVersion(t, "3.12.14"), "linux")
	got := sn.Match(mustVersion(t, "3.12.14"), "linux")
	if len(got) != 19 || strings.Join(matchIDs(got), ",") != strings.Join(matchIDs(want), ",") {
		t.Errorf("Load snapshot matches %d CVEs, fixture %d", len(got), len(want))
	}
	for _, f := range []string{archiveFile, releasesFile, releaseCycleFile, metaFile, "cves/CVE-2026-115557.json"} {
		if _, err := os.Stat(filepath.Join(src.CacheDir, f)); err != nil {
			t.Errorf("cache file %s: %v", f, err)
		}
	}
}

func TestLoadReusesFreshCache(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	before := site.totalHits()

	c.advance(19 * hour)
	loadOK(t, src)
	if site.totalHits() != before {
		t.Errorf("a cache 19h old caused %d requests", site.totalHits()-before)
	}
}

func TestLoadRevalidatesRecordsWithETag(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	hits0, _ := site.recordHits()

	c.advance(21 * hour)
	sn := loadOK(t, src)
	hits1, nm := site.recordHits()
	if hits1-hits0 != realCVEs || nm != realCVEs {
		t.Errorf("revalidation: %d requests, %d answered 304; want %d each", hits1-hits0, nm, realCVEs)
	}
	if len(sn.cves) != 77 {
		t.Errorf("cves = %d", len(sn.cves))
	}
	for _, p := range []string{"/db", "/releases", "/cycle"} {
		if site.hitCount(p) != 2 {
			t.Errorf("%s fetched %d times, want 2", p, site.hitCount(p))
		}
	}

	// A 304 renews the record's fetch time: 19h later nothing is asked.
	c.advance(19 * hour)
	before := site.totalHits()
	loadOK(t, src)
	if site.totalHits() != before {
		t.Errorf("after a 304 the record cache should count as fresh, got %d requests", site.totalHits()-before)
	}
}

func TestLoadUsesChangedRecord(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)

	// The CVE gets a lower severity upstream without the PSF list changing.
	rec := string(realCVERecords(t)["CVE-2026-115557.json"])
	changed := strings.ReplaceAll(rec, `"baseSeverity":"CRITICAL"`, `"baseSeverity":"LOW"`)
	if changed == rec {
		t.Fatal("test record has no CRITICAL severity to change")
	}
	site.set(recordPath("CVE-2026-115557"), []byte(changed))
	c.advance(21 * hour)
	sn := loadOK(t, src)
	a, ok := find(sn.Match(mustVersion(t, "3.12.14"), "linux"), "CVE-2026-115557")
	if !ok || a.Severity != "LOW" {
		t.Errorf("CVE-2026-115557 = %+v, %v; want the updated severity", a, ok)
	}
	if _, nm := site.recordHits(); nm != realCVEs-1 {
		t.Errorf("304s = %d, want %d", nm, realCVEs-1)
	}
}

func TestLoadStaleFallback(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)

	site.forceAll(500)
	c.advance(6 * 24 * hour)
	sn := loadOK(t, src)
	if len(sn.cves) != 77 {
		t.Errorf("stale snapshot has %d CVEs", len(sn.cves))
	}

	c.advance(24*hour + time.Minute) // 7d1m since the fetch
	err := loadFails(t, src)
	if !strings.Contains(err.Error(), "older than") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadEachDatasetIsRequired(t *testing.T) {
	for _, path := range []string{"/db", "/releases", "/cycle"} {
		site := newSite(t)
		c := newClock(t)
		src := site.source(t, c)
		site.force(path, 500)
		loadFails(t, src)
		site.force(path, 404)
		loadFails(t, src)
		site.clear()
		loadOK(t, src)
	}
}

func TestLoadRecordNotFound(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)

	// With a cached copy, a 404 (or any failure) keeps using it for 7 days.
	site.force(recordPath("CVE-2026-115557"), 404)
	site.force(recordPath("CVE-2026-6019"), 503)
	c.advance(21 * hour)
	sn := loadOK(t, src)
	if _, ok := find(sn.Match(mustVersion(t, "3.12.14"), "linux"), "CVE-2026-115557"); !ok {
		t.Error("cached record not used after a 404")
	}
	c.advance(7 * 24 * hour)
	err := loadFails(t, src)
	if !strings.Contains(err.Error(), "CVE-2026-115557") && !strings.Contains(err.Error(), "CVE-2026-6019") {
		t.Errorf("err = %v, want it to name the record", err)
	}

	// Without a cached copy it is unusable.
	site.clear()
	site.force(recordPath("CVE-2026-115557"), 404)
	err = loadFails(t, site.source(t, newClock(t)))
	if !strings.Contains(err.Error(), "CVE-2026-115557") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadKeepsCacheWhenArchiveLosesAnAdvisory(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	cachePath := filepath.Join(src.CacheDir, archiveFile)
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	// A new archive without one advisory (a rollback or truncation).
	var kept []tarEntry
	for name, body := range readTarGz(t, readTestdata(t, "psf-advisory-database.tar.gz")) {
		if name == "PSF-2026-3.json" || !strings.HasPrefix(name, "PSF-") {
			continue
		}
		kept = append(kept, tarEntry{name: psfFile(strings.TrimSuffix(name, ".json")), body: string(body)})
	}
	if len(kept) != 196 {
		t.Fatalf("kept %d advisories", len(kept))
	}
	site.set("/db", makeArchive(t, kept))
	c.advance(21 * hour)
	sn := loadOK(t, src)
	if len(sn.cves) != 77 {
		t.Errorf("cves = %d", len(sn.cves))
	}
	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the cached archive was replaced by one missing an advisory")
	}
	if site.hitCount("/db") != 2 {
		t.Errorf("/db fetched %d times", site.hitCount("/db"))
	}

	// An archive that gains advisories does replace it.
	kept = append(kept, tarEntry{name: psfFile("PSF-2026-3"), body: string(readTarGz(t, before)["PSF-2026-3.json"])},
		tarEntry{name: psfFile("PSF-2026-90000"), body: advisoryJSON("PSF-2026-90000", false)})
	site.set("/db", makeArchive(t, kept))
	c.advance(21 * hour)
	loadOK(t, src)
	after, _ = os.ReadFile(cachePath)
	if string(after) == string(before) {
		t.Error("a superset archive did not replace the cache")
	}
}

func TestLoadBadDownloadsDoNotReplaceCache(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	want := map[string][]byte{}
	for _, f := range []string{archiveFile, releasesFile, releaseCycleFile} {
		b, err := os.ReadFile(filepath.Join(src.CacheDir, f))
		if err != nil {
			t.Fatal(err)
		}
		want[f] = b
	}

	site.set("/db", []byte("<html>error</html>"))
	site.set("/releases", []byte(`{"not":"a list"}`))
	site.set("/cycle", []byte(`[]`))
	c.advance(21 * hour)
	loadOK(t, src) // stale fallback
	for f, b := range want {
		got, _ := os.ReadFile(filepath.Join(src.CacheDir, f))
		if string(got) != string(b) {
			t.Errorf("%s was replaced by a bad download", f)
		}
	}
}

func TestLoadBadRecordDownloadDoesNotReplaceCache(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	path := filepath.Join(src.CacheDir, "cves", "CVE-2026-115557.json")
	before, _ := os.ReadFile(path)

	site.set(recordPath("CVE-2026-115557"), []byte(recordJSON("CVE-2026-1", "PUBLISHED", rangeThrough, "")))
	c.advance(21 * hour)
	loadOK(t, src)
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Error("a record for another CVE replaced the cache")
	}
}

func TestLoadRecordLimits(t *testing.T) {
	t.Run("size cap", func(t *testing.T) {
		site := newSite(t)
		huge := recordJSON("CVE-2026-115557", "PUBLISHED", rangeThrough, "") + strings.Repeat(" ", maxRecordBytes)
		site.set(recordPath("CVE-2026-115557"), []byte(huge))
		loadFails(t, site.source(t, newClock(t)))

		// Right at the cap is accepted.
		base := recordJSON("CVE-2026-115557", "PUBLISHED", rangeThrough, "")
		site.set(recordPath("CVE-2026-115557"), []byte(base+strings.Repeat(" ", maxRecordBytes-len(base))))
		loadOK(t, site.source(t, newClock(t)))
	})
	t.Run("cve id mismatch", func(t *testing.T) {
		site := newSite(t)
		site.set(recordPath("CVE-2026-115557"), []byte(recordJSON("CVE-2026-6019", "PUBLISHED", rangeThrough, "")))
		err := loadFails(t, site.source(t, newClock(t)))
		if !strings.Contains(err.Error(), "CVE-2026-115557") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("not a record", func(t *testing.T) {
		site := newSite(t)
		site.set(recordPath("CVE-2026-115557"), []byte("<html>"))
		loadFails(t, site.source(t, newClock(t)))
	})
	t.Run("fetch cap", func(t *testing.T) {
		site := newSite(t)
		src := site.source(t, newClock(t))
		src.maxFetches = 10
		err := loadFails(t, src)
		if !strings.Contains(err.Error(), "record requests") {
			t.Errorf("err = %v", err)
		}
		if hits, _ := site.recordHits(); hits > 11 {
			t.Errorf("%d record requests after hitting the cap of 10", hits)
		}
		src.maxFetches = realCVEs
		loadOK(t, src)
	})
	t.Run("cache size cap", func(t *testing.T) {
		site := newSite(t)
		src := site.source(t, newClock(t))
		src.maxCacheBytes = 100 << 10
		err := loadFails(t, src)
		if !strings.Contains(err.Error(), "cached records") {
			t.Errorf("err = %v", err)
		}
		src.maxCacheBytes = 0
		loadOK(t, src)
	})
}

func TestLoadDeadline(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)

	// Cached records exist and are within 7 days, but a Load that ran out of
	// time must not quietly fall back to them.
	for name := range realCVERecords(t) {
		site.setDelay(recordPath(strings.TrimSuffix(name, ".json")), 5*time.Second)
	}
	c.advance(21 * hour)
	src.timeout = 300 * time.Millisecond
	start := time.Now()
	err := loadFails(t, src)
	if time.Since(start) > 3*time.Second {
		t.Errorf("Load took %s past its deadline", time.Since(start))
	}
	if !strings.Contains(err.Error(), "deadline") {
		t.Errorf("err = %v, want the deadline", err)
	}

	site.clear()
	src.timeout = 0
	loadOK(t, src)
}

func TestLoadCancelled(t *testing.T) {
	site := newSite(t)
	src := site.source(t, newClock(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sn, err := src.Load(ctx); err == nil || sn != nil {
		t.Errorf("Load = %v, %v", sn, err)
	}
}

func TestLoadPrunesUnreferencedRecords(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	stray := filepath.Join(src.CacheDir, "cves", "CVE-2020-0001.json")
	if err := os.WriteFile(stray, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	loadOK(t, src)
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Errorf("stray record not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(src.CacheDir, "cves", "CVE-2026-115557.json")); err != nil {
		t.Errorf("referenced record removed: %v", err)
	}
}

func TestLoadCorruptMetaRefetches(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	if err := os.WriteFile(filepath.Join(src.CacheDir, metaFile), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	loadOK(t, src)
	if site.hitCount("/db") != 2 {
		t.Errorf("/db fetched %d times, want a refetch after meta was lost", site.hitCount("/db"))
	}
}

// --- hand-made lists: what is and is not usable ---

func TestLoadRejectedCVEIsDropped(t *testing.T) {
	site := miniSite(t,
		map[string]string{
			"PSF-2026-1": advisoryJSON("PSF-2026-1", false, "CVE-2026-1001"),
			"PSF-2026-2": advisoryJSON("PSF-2026-2", false, "CVE-2026-1002"),
		},
		map[string]string{
			"CVE-2026-1001": recordJSON("CVE-2026-1001", "REJECTED", `[{"version":"0","lessThan":"zzz","status":"affected","versionType":"semver"}]`, ""),
			"CVE-2026-1002": recordJSON("CVE-2026-1002", "PUBLISHED", rangeThrough, ""),
		})
	sn := loadOK(t, site.source(t, newClock(t)))
	if len(sn.cves) != 1 || sn.cves[0].id != "CVE-2026-1002" || sn.rejected != 1 {
		t.Errorf("cves=%+v rejected=%d", sn.cves, sn.rejected)
	}
	advs := sn.Match(mustVersion(t, "3.12.0"), "linux")
	if len(advs) != 1 || advs[0].VulnID != "CVE-2026-1002" || advs[0].Severity != "HIGH" {
		t.Errorf("advisories = %+v", advs)
	}
}

func TestLoadWithdrawnAdvisoryIsNotUsed(t *testing.T) {
	site := miniSite(t,
		map[string]string{
			"PSF-2026-1": advisoryJSON("PSF-2026-1", true, "CVE-2026-1001"),
			"PSF-2026-2": advisoryJSON("PSF-2026-2", false, "CVE-2026-1002"),
		},
		map[string]string{
			// Not even fetched: it would be unevaluable.
			"CVE-2026-1001": recordJSON("CVE-2026-1001", "PUBLISHED", `[{"version":"0","lessThan":"3.12.5","status":"affected","versionType":"semver"}]`, ""),
			"CVE-2026-1002": recordJSON("CVE-2026-1002", "PUBLISHED", rangeThrough, ""),
		})
	sn := loadOK(t, site.source(t, newClock(t)))
	if len(sn.cves) != 1 || sn.withdrawn != 1 {
		t.Errorf("cves=%+v withdrawn=%d", sn.cves, sn.withdrawn)
	}
	if site.hitCount(recordPath("CVE-2026-1001")) != 0 {
		t.Error("the CVE of a withdrawn advisory was fetched")
	}
}

func TestLoadUnevaluableRangeIsUnusable(t *testing.T) {
	good := recordJSON("CVE-2026-1002", "PUBLISHED", rangeThrough, "")
	for name, bad := range map[string]string{
		"changes":      `[{"version":"3.12.0","lessThan":"3.12.5","status":"affected","changes":[{"at":"3.12.2","status":"unaffected"}]}]`,
		"versionType":  `[{"version":"0","lessThan":"3.12.5","status":"affected","versionType":"git"}]`,
		"bound":        `[{"version":"0","lessThan":"3.12.5-patched","status":"affected"}]`,
		"lower bound":  `[{"version":"3.12","lessThan":"3.12.5","status":"affected"}]`,
		"upper (<=)":   `[{"version":"0","lessThanOrEqual":"3.x","status":"affected"}]`,
		"later fields": `[{"version":"0","lessThan":"3.12.5","status":"affected"},{"version":"3.13.0","lessThan":"3.13.0rc","status":"affected"}]`,
	} {
		site := miniSite(t,
			map[string]string{
				"PSF-2026-1": advisoryJSON("PSF-2026-1", false, "CVE-2026-1001"),
				"PSF-2026-2": advisoryJSON("PSF-2026-2", false, "CVE-2026-1002"),
			},
			map[string]string{
				"CVE-2026-1001": recordJSON("CVE-2026-1001", "PUBLISHED", bad, ""),
				"CVE-2026-1002": good,
			})
		src := site.source(t, newClock(t))
		err := loadFails(t, src)
		if !strings.Contains(err.Error(), "CVE-2026-1001") {
			t.Errorf("%s: err = %v, want it to name the CVE", name, err)
		}
	}
}

func TestLoadUnevaluableRangeRecovers(t *testing.T) {
	// An unevaluable range arriving upstream makes the next Load unusable
	// instead of dropping the CVE; once it is fixed upstream, the next
	// refresh recovers.
	site := miniSite(t,
		map[string]string{"PSF-2026-1": advisoryJSON("PSF-2026-1", false, "CVE-2026-1001")},
		map[string]string{"CVE-2026-1001": recordJSON("CVE-2026-1001", "PUBLISHED", rangeThrough, "")})
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	site.set(recordPath("CVE-2026-1001"), []byte(recordJSON("CVE-2026-1001", "PUBLISHED", `[{"version":"0","lessThan":"3.12.5","status":"affected","versionType":"semver"}]`, "")))
	c.advance(21 * hour)
	loadFails(t, src)
	site.set(recordPath("CVE-2026-1001"), []byte(recordJSON("CVE-2026-1001", "PUBLISHED", rangeThrough, "")))
	c.advance(21 * hour)
	loadOK(t, src)
}

func TestLoadPlatformsInRecords(t *testing.T) {
	win := recordJSON("CVE-2026-1001", "PUBLISHED", rangeThrough, `,"platforms":["Windows"]`)
	site := miniSite(t,
		map[string]string{
			"PSF-2026-1": advisoryJSON("PSF-2026-1", false, "CVE-2026-1001"),
			"PSF-2026-2": advisoryJSON("PSF-2026-2", false, "CVE-2026-1002"),
			"PSF-2026-3": advisoryJSON("PSF-2026-3", false, "CVE-2026-1003"),
		},
		map[string]string{
			"CVE-2026-1001": win,
			"CVE-2026-1002": recordJSON("CVE-2026-1002", "PUBLISHED", rangeThrough, `,"platforms":["Windows","Plan 9"]`),
			"CVE-2026-1003": recordJSON("CVE-2026-1003", "PUBLISHED", rangeThrough, `,"platforms":["Linux"]`),
		})
	sn := loadOK(t, site.source(t, newClock(t)))
	got := matchIDs(sn.Match(mustVersion(t, "3.12.0"), "linux"))
	if strings.Join(got, ",") != "CVE-2026-1002,CVE-2026-1003" {
		t.Errorf("linux matches %v", got)
	}
}

func TestLoadSharedCVEIsFetchedOnce(t *testing.T) {
	site := miniSite(t,
		map[string]string{
			"PSF-2026-1": advisoryJSON("PSF-2026-1", false, "CVE-2026-1001"),
			"PSF-2026-2": advisoryJSON("PSF-2026-2", false, "CVE-2026-1001"),
		},
		map[string]string{"CVE-2026-1001": recordJSON("CVE-2026-1001", "PUBLISHED", rangeThrough, "")})
	sn := loadOK(t, site.source(t, newClock(t)))
	if len(sn.cves) != 1 || site.hitCount(recordPath("CVE-2026-1001")) != 1 {
		t.Errorf("cves=%d, fetches=%d", len(sn.cves), site.hitCount(recordPath("CVE-2026-1001")))
	}
	if !strings.HasSuffix(sn.cves[0].url, "PSF-2026-1") {
		t.Errorf("url = %s, want the lowest advisory's", sn.cves[0].url)
	}
}

func TestRefresher(t *testing.T) {
	site := newSite(t)
	src := site.source(t, newClock(t))
	a := &Advisor{}
	r := Refresher{Source: src, Advisor: a}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if aug := a.Augment(pyScan("3.12.14"), allSeverities); len(aug.Findings) != 19 || len(aug.Unchecked) > 0 {
		t.Errorf("after Refresh: %d findings, unchecked %v", len(aug.Findings), aug.Unchecked)
	}
	site.forceAll(500)
	src.CacheDir = t.TempDir()
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded against a failing site")
	}
	if aug := a.Augment(pyScan("3.12.14"), allSeverities); len(aug.Unchecked) != 1 {
		t.Errorf("after a failed Refresh: %+v, want unchecked", aug)
	}
}

func TestLoadTruncatedRecordKeepsCache(t *testing.T) {
	truncated := []byte(`{"cveMetadata":{"cveId":"CVE-2026-115557","state":"PUBLISHED"}}`)

	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	site.set(recordPath("CVE-2026-115557"), truncated)
	c.advance(21 * hour)
	sn := loadOK(t, src)
	if _, ok := find(sn.Match(mustVersion(t, "3.12.14"), "linux"), "CVE-2026-115557"); !ok {
		t.Error("a record without the CNA affected list replaced the cached one")
	}

	// Without a cached copy the record is missing, so nothing is matched.
	fresh := newSite(t)
	fresh.set(recordPath("CVE-2026-115557"), truncated)
	loadFails(t, fresh.source(t, newClock(t)))
}

func TestLoadRecordLosingRangesKeepsCache(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)

	// Still published, but the CPython ranges are gone.
	noRanges := `{"cveMetadata":{"cveId":"CVE-2026-115557","state":"PUBLISHED"},` +
		`"containers":{"cna":{"affected":[{"vendor":"n/a","product":"n/a","versions":[{"version":"n/a","status":"affected"}]}]}}}`
	site.set(recordPath("CVE-2026-115557"), []byte(noRanges))
	c.advance(21 * hour)
	sn := loadOK(t, src)
	if _, ok := find(sn.Match(mustVersion(t, "3.12.14"), "linux"), "CVE-2026-115557"); !ok {
		t.Error("a record that dropped its CPython ranges replaced the cached one")
	}
}

func TestLoadCacheCapCountsWhatIsOnDisk(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	dir := filepath.Join(src.CacheDir, "cves")
	used, err := dirSize(dir)
	if err != nil {
		t.Fatal(err)
	}

	// The cache is full: a larger copy of a record must not be written, so
	// the cached copy is served and the disk stays within the cap.
	src.maxCacheBytes = used
	path := filepath.Join(dir, "CVE-2026-115557.json")
	before, _ := os.ReadFile(path)
	site.set(recordPath("CVE-2026-115557"), append(append([]byte(nil), before[:len(before)-1]...), []byte(strings.Repeat(" ", 4096)+"}")...))
	for i := 0; i < 3; i++ {
		c.advance(21 * hour)
		loadOK(t, src)
		if n, _ := dirSize(dir); n > used {
			t.Fatalf("cycle %d: record cache grew to %d bytes past the cap of %d", i, n, used)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the larger record was written past the cap")
	}
}

func TestLoadPrunesUnreferencedRecordsEvenWhenItFails(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	stray := filepath.Join(src.CacheDir, "cves", "CVE-2020-0001.json")
	if err := os.WriteFile(stray, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A record with no cached copy fails, so this update is unusable.
	site.force(recordPath("CVE-2026-115557"), 500)
	if err := os.Remove(filepath.Join(src.CacheDir, "cves", "CVE-2026-115557.json")); err != nil {
		t.Fatal(err)
	}
	loadFails(t, src)
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Errorf("stray record kept after a failed update: %v", err)
	}
}

func TestLoadDataset404UsesCache(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	for _, p := range []string{"/db", "/releases", "/cycle"} {
		site.force(p, 404)
	}
	c.advance(21 * hour)
	loadOK(t, src)

	c.advance(7 * 24 * hour)
	loadFails(t, src)
}

func TestLoadRecordLosingRangesAfterAnUnevaluableOne(t *testing.T) {
	site := newSite(t)
	c := newClock(t)
	src := site.source(t, c)
	loadOK(t, src)
	rec := string(realCVERecords(t)["CVE-2026-115557.json"])

	// An unevaluable copy is cached (the update is unusable) ...
	unevaluable := strings.Replace(rec, `"versionType":"python"`, `"versionType":"semver"`, 1)
	if unevaluable == rec {
		t.Fatal("test record has no python versionType to change")
	}
	site.set(recordPath("CVE-2026-115557"), []byte(unevaluable))
	c.advance(21 * hour)
	loadFails(t, src)

	// ... and a copy without any CPython ranges must still not replace it.
	noRanges := `{"cveMetadata":{"cveId":"CVE-2026-115557","state":"PUBLISHED"},` +
		`"containers":{"cna":{"affected":[{"vendor":"n/a","product":"n/a","versions":[{"version":"n/a","status":"affected"}]}]}}}`
	site.set(recordPath("CVE-2026-115557"), []byte(noRanges))
	c.advance(21 * hour)
	loadFails(t, src)
	cached, _ := os.ReadFile(filepath.Join(src.CacheDir, "cves", "CVE-2026-115557.json"))
	if string(cached) != unevaluable {
		t.Error("a record without CPython ranges replaced a cached record that had them")
	}
}
