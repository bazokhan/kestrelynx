package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// kevFixture mirrors the real catalog shape (verified against the live feed,
// 2026-07-06): vulnerabilities[].cveID / knownRansomwareCampaignUse.
const kevFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "count": 3,
  "vulnerabilities": [
    {"cveID": "CVE-2026-1111", "knownRansomwareCampaignUse": "Known", "notes": "https://vendor.test/advisory; https://nvd.nist.gov/vuln/detail/CVE-2026-1111"},
    {"cveID": "CVE-2026-2222", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2020-9999", "knownRansomwareCampaignUse": "Unknown"}
  ]
}`

// epssRows mirrors the real CSV (comment line, header, then rows).
const epssRows = "#model_version:v2026.06.15,score_date:2026-07-05T12:03:40Z\n" +
	"cve,epss,percentile\n" +
	"CVE-2026-1111,0.94321,0.99954\n" +
	"CVE-2026-3333,0.03351,0.87224\n" +
	"CVE-2020-9999,0.00042,0.05127\n"

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// testFeeds serves the two fixtures and counts hits per path.
type testFeeds struct {
	srv      *httptest.Server
	kevHits  int
	epssHits int
	kevBody  func() ([]byte, int)
	epssBody func() ([]byte, int)
}

func newTestFeeds(t *testing.T) *testFeeds {
	t.Helper()
	f := &testFeeds{}
	f.kevBody = func() ([]byte, int) { return []byte(kevFixture), http.StatusOK }
	epss := gzipBytes(t, epssRows)
	f.epssBody = func() ([]byte, int) { return epss, http.StatusOK }
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			f.kevHits++
			body, code := f.kevBody()
			w.WriteHeader(code)
			w.Write(body)
		case "/epss.csv.gz":
			f.epssHits++
			body, code := f.epssBody()
			w.WriteHeader(code)
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newSource(t *testing.T, f *testFeeds, now *time.Time) *Source {
	t.Helper()
	return &Source{
		CacheDir: filepath.Join(t.TempDir(), "intel"),
		KEVURL:   f.srv.URL + "/kev.json",
		EPSSURL:  f.srv.URL + "/epss.csv.gz",
		Client:   f.srv.Client(),
		Now:      func() time.Time { return *now },
	}
}

var ids = []string{"CVE-2026-1111", "CVE-2026-3333", "GHSA-xxxx-yyyy", "CVE-1999-0000"}

func TestLookupFreshFetch(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	got, fresh, err := s.Lookup(context.Background(), ids)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !fresh.KEVOK || !fresh.EPSSOK || fresh.Degraded() || fresh.StaleDays != 0 {
		t.Errorf("freshness = %+v, want both OK and 0 stale days", fresh)
	}
	e := got["CVE-2026-1111"]
	if !e.KEV || !e.Ransomware || !e.EPSSKnown || e.EPSS != 0.94321 {
		t.Errorf("CVE-2026-1111 = %+v, want KEV+ransomware+EPSS 0.94321", e)
	}
	e = got["CVE-2026-3333"]
	if e.KEV || !e.EPSSKnown || e.EPSS != 0.03351 {
		t.Errorf("CVE-2026-3333 = %+v, want EPSS only", e)
	}
	if _, ok := got["GHSA-xxxx-yyyy"]; ok {
		t.Errorf("GHSA id unexpectedly enriched")
	}
	if _, ok := got["CVE-2020-9999"]; ok {
		t.Errorf("unrequested CVE leaked into result")
	}
}

func TestLookupUsesCacheWithinRefreshWindow(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	if _, _, err := s.Lookup(context.Background(), ids); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Hour) // same day: within refreshAfter
	if _, _, err := s.Lookup(context.Background(), ids); err != nil {
		t.Fatal(err)
	}
	if feeds.kevHits != 1 || feeds.epssHits != 1 {
		t.Errorf("hits = kev %d epss %d, want 1 each (cache reuse)", feeds.kevHits, feeds.epssHits)
	}

	now = now.Add(18 * time.Hour) // past refreshAfter: next cycle re-fetches
	if _, _, err := s.Lookup(context.Background(), ids); err != nil {
		t.Fatal(err)
	}
	if feeds.kevHits != 2 || feeds.epssHits != 2 {
		t.Errorf("hits = kev %d epss %d, want 2 each (refresh)", feeds.kevHits, feeds.epssHits)
	}
}

func TestLookupFailOpenOnFetchError(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	if _, _, err := s.Lookup(context.Background(), ids); err != nil {
		t.Fatal(err)
	}

	feeds.kevBody = func() ([]byte, int) { return nil, http.StatusServiceUnavailable }
	feeds.epssBody = func() ([]byte, int) { return nil, http.StatusServiceUnavailable }

	now = now.Add(3 * 24 * time.Hour) // stale but within maxStale
	got, fresh, err := s.Lookup(context.Background(), ids)
	if err == nil {
		t.Errorf("want fetch error surfaced for logging")
	}
	if !fresh.KEVOK || !fresh.EPSSOK {
		t.Errorf("freshness = %+v, want stale cache still usable", fresh)
	}
	if fresh.StaleDays != 3 {
		t.Errorf("StaleDays = %d, want 3", fresh.StaleDays)
	}
	if e := got["CVE-2026-1111"]; !e.KEV || !e.EPSSKnown {
		t.Errorf("CVE-2026-1111 = %+v, want served from stale cache", e)
	}

	now = now.Add(5 * 24 * time.Hour) // now past maxStale
	got, fresh, _ = s.Lookup(context.Background(), ids)
	if fresh.KEVOK || fresh.EPSSOK || !fresh.Degraded() {
		t.Errorf("freshness = %+v, want degraded past maxStale", fresh)
	}
	if len(got) != 0 {
		t.Errorf("got %d enrichments from expired cache, want none", len(got))
	}
}

func TestLookupDegradedWithNoCacheAndNoNetwork(t *testing.T) {
	feeds := newTestFeeds(t)
	feeds.kevBody = func() ([]byte, int) { return nil, http.StatusServiceUnavailable }
	feeds.epssBody = func() ([]byte, int) { return nil, http.StatusServiceUnavailable }
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	got, fresh, err := s.Lookup(context.Background(), ids)
	if err == nil {
		t.Errorf("want error")
	}
	if !fresh.Degraded() || len(got) != 0 {
		t.Errorf("want fully degraded empty result, got %+v, %d enrichments", fresh, len(got))
	}
}

func TestBadDownloadDoesNotClobberGoodCache(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	if _, _, err := s.Lookup(context.Background(), ids); err != nil {
		t.Fatal(err)
	}

	// Next day the endpoints return 200 with garbage (captive portal etc.).
	feeds.kevBody = func() ([]byte, int) { return []byte("<html>login</html>"), http.StatusOK }
	feeds.epssBody = func() ([]byte, int) { return []byte("not gzip"), http.StatusOK }

	now = now.Add(24 * time.Hour)
	got, fresh, err := s.Lookup(context.Background(), ids)
	if err == nil {
		t.Errorf("want validation error surfaced")
	}
	if !fresh.KEVOK || !fresh.EPSSOK || fresh.StaleDays != 1 {
		t.Errorf("freshness = %+v, want yesterday's cache in use", fresh)
	}
	if e := got["CVE-2026-1111"]; !e.KEV || !e.EPSSKnown {
		t.Errorf("CVE-2026-1111 = %+v, want served from previous cache", e)
	}
}

func TestLookupSurvivesDeletedCacheWithStaleMeta(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	if _, _, err := s.Lookup(context.Background(), ids); err != nil {
		t.Fatal(err)
	}
	// Cache files vanish (volume wipe) but meta survives: must re-fetch, not
	// trust the recorded fetch time.
	if err := os.Remove(filepath.Join(s.CacheDir, kevFile)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	got, fresh, err := s.Lookup(context.Background(), ids)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !fresh.KEVOK {
		t.Errorf("freshness = %+v, want KEV re-fetched", fresh)
	}
	if e := got["CVE-2026-1111"]; !e.KEV {
		t.Errorf("CVE-2026-1111 = %+v, want KEV after re-fetch", e)
	}
	if feeds.kevHits != 2 {
		t.Errorf("kev hits = %d, want 2", feeds.kevHits)
	}
}

func TestKEVSet(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	set, err := s.KEVSet(context.Background())
	if err != nil {
		t.Fatalf("KEVSet: %v", err)
	}
	if !set["CVE-2026-1111"] || set["CVE-2026-3333"] {
		t.Errorf("set = %v, want the KEV-listed CVE only", set)
	}
	if feeds.epssHits != 0 {
		t.Error("KEVSet must not fetch EPSS")
	}
	// A second call within the refresh window reuses the cache.
	if _, err := s.KEVSet(context.Background()); err != nil || feeds.kevHits != 1 {
		t.Errorf("second call: err=%v hits=%d, want the cached catalog", err, feeds.kevHits)
	}
}

func TestKEVSetUnavailableIsAnError(t *testing.T) {
	feeds := newTestFeeds(t)
	feeds.kevBody = func() ([]byte, int) { return nil, http.StatusServiceUnavailable }
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)
	if set, err := s.KEVSet(context.Background()); err == nil || set != nil {
		t.Errorf("set=%v err=%v, want an error without a catalog", set, err)
	}
}
