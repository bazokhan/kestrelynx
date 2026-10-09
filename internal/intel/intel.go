// Package intel fetches, caches, and serves the vulnerability-intelligence
// datasets behind the Phase 1+ triage layer (docs/TRIAGE_SPEC.md): the CISA KEV
// catalog (confirmed in-the-wild exploitation) and daily EPSS scores (predicted
// exploitation probability).
//
// Both datasets are bulk downloads joined locally by CVE ID (ADR-007): the
// user's CVE list — which reveals what they run — never leaves the host, and a
// scan cycle costs at most two unauthenticated GETs per day.
package intel

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Default feed URLs. Both are overridable in config for air-gapped mirrors.
const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

const (
	// refreshAfter is the cache age past which a dataset is re-downloaded at
	// the start of a scan cycle. Slightly under a day so a daily schedule
	// refreshes every cycle, while a twice-a-day schedule doesn't double-fetch.
	refreshAfter = 20 * time.Hour
	// maxStale is how old a cached dataset may be and still be used when
	// re-downloading fails. Past this the dataset is treated as unavailable.
	maxStale = 7 * 24 * time.Hour
	// maxFeedBytes caps a feed download; both feeds are single-digit MB, so
	// this only guards against a rogue endpoint.
	maxFeedBytes = 256 << 20
)

// Enrichment is what the triage layer knows about one vulnerability ID beyond
// the scanner's output. The zero value means "nothing known" (not in KEV, no
// EPSS score), which is also what non-CVE IDs (e.g. GHSA-…) resolve to.
type Enrichment struct {
	KEV        bool    // listed in the CISA KEV catalog
	Ransomware bool    // KEV: known use in ransomware campaigns
	EPSS       float64 // exploitation probability [0,1]; valid only when EPSSKnown
	EPSSKnown  bool
	KEVNoteURL string // vendor advisory / CISA alert extracted from the KEV notes
}

// Freshness reports how trustworthy a Lookup result is, so analyze can pick
// the fail-open rules (ADR-011) and notify can annotate the message.
type Freshness struct {
	KEVOK     bool // KEV data present and within maxStale
	EPSSOK    bool // EPSS data present and within maxStale
	StaleDays int  // age in whole days of the oldest usable dataset; 0 = fetched today
}

// Degraded reports whether no intel is usable at all: triage must fall back to
// severity-only judgement rather than inventing an "ignorable" bucket.
func (f Freshness) Degraded() bool { return !f.KEVOK && !f.EPSSOK }

// Source fetches and caches the datasets and answers lookups. The zero fields
// fall back to defaults; only CacheDir is required.
type Source struct {
	CacheDir    string
	KEVURL      string // empty = DefaultKEVURL
	EPSSURL     string // empty = DefaultEPSSURL
	HNSearchURL string // empty = DefaultHNSearchURL (see refs.go)
	Client      *http.Client
	Now         func() time.Time
	Log         *slog.Logger
}

// cache file names under CacheDir.
const (
	kevFile  = "kev.json"
	epssFile = "epss.csv.gz"
	metaFile = "meta.json"
)

// meta records when each cached dataset was fetched.
type meta struct {
	KEVFetchedAt  time.Time `json:"kev_fetched_at"`
	EPSSFetchedAt time.Time `json:"epss_fetched_at"`
}

// Lookup returns the enrichment for the given vulnerability IDs (IDs with no
// data are simply absent from the map). It refreshes the cached datasets first
// when they are older than refreshAfter. Fetch or parse failures never fail the
// lookup: the result degrades per dataset (Freshness) and the joined error is
// returned for logging alongside the usable data.
func (s *Source) Lookup(ctx context.Context, ids []string) (map[string]Enrichment, Freshness, error) {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := map[string]Enrichment{}
	var errs []error

	m := s.loadMeta()
	now := s.now()

	kevAt, err := s.ensure(ctx, kevFile, s.kevURL(), m.KEVFetchedAt, s.validateKEV)
	if err != nil {
		errs = append(errs, fmt.Errorf("kev: %w", err))
	}
	epssAt, err := s.ensure(ctx, epssFile, s.epssURL(), m.EPSSFetchedAt, s.validateEPSS)
	if err != nil {
		errs = append(errs, fmt.Errorf("epss: %w", err))
	}
	s.saveMeta(meta{KEVFetchedAt: kevAt, EPSSFetchedAt: epssAt})

	var f Freshness
	if usable(kevAt, now) {
		if err := s.readKEV(want, out); err != nil {
			errs = append(errs, fmt.Errorf("kev: %w", err))
		} else {
			f.KEVOK = true
		}
	}
	if usable(epssAt, now) {
		if err := s.readEPSS(want, out); err != nil {
			errs = append(errs, fmt.Errorf("epss: %w", err))
		} else {
			f.EPSSOK = true
		}
	}
	f.StaleDays = staleDays(now, kevAt, epssAt, f)
	return out, f, errors.Join(errs...)
}

// KEVSet returns the IDs of the CISA KEV catalog, refreshing the cached
// catalog when it is stale. It reads no EPSS data. An error means no usable
// catalog is available.
func (s *Source) KEVSet(ctx context.Context) (map[string]bool, error) {
	m := s.loadMeta()
	at, err := s.ensure(ctx, kevFile, s.kevURL(), m.KEVFetchedAt, s.validateKEV)
	if !usable(at, s.now()) {
		return nil, errors.Join(err, errors.New("kev catalog unavailable"))
	}
	s.saveMeta(meta{KEVFetchedAt: at, EPSSFetchedAt: m.EPSSFetchedAt})
	data, rerr := os.ReadFile(filepath.Join(s.CacheDir, kevFile))
	if rerr != nil {
		return nil, rerr
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse kev catalog: %w", err)
	}
	ids := make(map[string]bool, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		ids[v.CVEID] = true
	}
	return ids, nil
}

// ensure re-downloads the dataset when its cache is older than refreshAfter.
// It returns the fetch time of whatever usable file is now cached (the fresh
// download, or the previous cache when downloading failed), or the zero time
// when there is nothing usable on disk.
func (s *Source) ensure(ctx context.Context, name, url string, fetchedAt time.Time, validate func(string) error) (time.Time, error) {
	path := filepath.Join(s.CacheDir, name)
	if _, err := os.Stat(path); err != nil {
		fetchedAt = time.Time{} // meta may lie (deleted cache); treat as absent
	}
	now := s.now()
	if !fetchedAt.IsZero() && now.Sub(fetchedAt) < refreshAfter {
		return fetchedAt, nil
	}
	if err := s.download(ctx, url, path, validate); err != nil {
		return fetchedAt, err // keep whatever cache we had
	}
	return now, nil
}

// download fetches url into path atomically. The payload is validated before
// it replaces the previous cache, so a bad response (captive portal, truncated
// body) can never clobber a good dataset.
func (s *Source) download(ctx context.Context, url, path string, validate func(string) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, err = io.Copy(f, io.LimitReader(resp.Body, maxFeedBytes))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = validate(tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("download %s: %w", url, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// --- KEV ---

// kevCatalog is the subset of the CISA KEV JSON schema KestreLynx reads.
type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

func (s *Source) readKEV(want map[string]bool, out map[string]Enrichment) error {
	data, err := os.ReadFile(filepath.Join(s.CacheDir, kevFile))
	if err != nil {
		return err
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return fmt.Errorf("parse kev catalog: %w", err)
	}
	for _, v := range cat.Vulnerabilities {
		if !want[v.CVEID] {
			continue
		}
		e := out[v.CVEID]
		e.KEV = true
		e.Ransomware = v.KnownRansomwareCampaignUse == "Known"
		e.KEVNoteURL = noteURL(v.Notes)
		out[v.CVEID] = e
	}
	return nil
}

// validateKEV rejects a download that is not a plausible KEV catalog.
func (s *Source) validateKEV(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return fmt.Errorf("not a kev catalog: %w", err)
	}
	if len(cat.Vulnerabilities) == 0 {
		return fmt.Errorf("kev catalog has no vulnerabilities")
	}
	return nil
}

// --- EPSS ---

// readEPSS streams the gzipped CSV (~350k rows: "cve,epss,percentile" after a
// "#model_version:…" comment line) and keeps only the requested IDs, so the
// full dataset is never held in memory.
func (s *Source) readEPSS(want map[string]bool, out map[string]Enrichment) error {
	return s.scanEPSS(filepath.Join(s.CacheDir, epssFile), func(cve string, score float64) {
		if !want[cve] {
			return
		}
		e := out[cve]
		e.EPSS = score
		e.EPSSKnown = true
		out[cve] = e
	})
}

// validateEPSS rejects a download whose first data row does not parse.
func (s *Source) validateEPSS(path string) error {
	rows := 0
	err := s.scanEPSS(path, func(string, float64) { rows++ })
	if err == nil && rows == 0 {
		return fmt.Errorf("epss csv has no rows")
	}
	return err
}

func (s *Source) scanEPSS(path string, visit func(cve string, score float64)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("epss not gzip: %w", err)
	}
	defer gz.Close()

	r := csv.NewReader(gz)
	r.Comment = '#'
	r.FieldsPerRecord = -1 // tolerate trailing column changes
	header := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse epss csv: %w", err)
		}
		if header { // "cve,epss,percentile"
			header = false
			continue
		}
		if len(rec) < 2 {
			return fmt.Errorf("parse epss csv: row has %d column(s)", len(rec))
		}
		score, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			return fmt.Errorf("parse epss score %q: %w", rec[1], err)
		}
		visit(rec[0], score)
	}
}

// --- meta / freshness helpers ---

func (s *Source) loadMeta() meta {
	var m meta
	data, err := os.ReadFile(filepath.Join(s.CacheDir, metaFile))
	if err != nil {
		return m
	}
	_ = json.Unmarshal(data, &m) // corrupt meta = re-fetch, not an error
	return m
}

func (s *Source) saveMeta(m meta) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	if err := os.MkdirAll(s.CacheDir, 0o755); err != nil {
		return
	}
	path := filepath.Join(s.CacheDir, metaFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		s.log().Warn("write intel meta failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.log().Warn("write intel meta failed", "err", err)
	}
}

// usable reports whether a dataset fetched at t may still be served (fail-open
// window: stale up to maxStale beats absent).
func usable(t, now time.Time) bool {
	return !t.IsZero() && now.Sub(t) <= maxStale
}

// staleDays is the age in whole days of the oldest dataset actually in use.
func staleDays(now, kevAt, epssAt time.Time, f Freshness) int {
	oldest := time.Time{}
	if f.KEVOK {
		oldest = kevAt
	}
	if f.EPSSOK && (oldest.IsZero() || epssAt.Before(oldest)) {
		oldest = epssAt
	}
	if oldest.IsZero() {
		return 0
	}
	days := int(now.Sub(oldest).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

func (s *Source) kevURL() string {
	if s.KEVURL != "" {
		return s.KEVURL
	}
	return DefaultKEVURL
}

func (s *Source) epssURL() string {
	if s.EPSSURL != "" {
		return s.EPSSURL
	}
	return DefaultEPSSURL
}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return defaultClient
}

var defaultClient = &http.Client{Timeout: 2 * time.Minute}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}
