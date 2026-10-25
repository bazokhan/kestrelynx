package pycore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// refreshAfter is the cache age past which a dataset is re-downloaded at
	// the start of a scan cycle (see the same constant in package intel).
	refreshAfter = 20 * time.Hour
	// maxStale is how old a cached dataset may be and still be used when
	// re-downloading fails. Past this the dataset is unusable.
	maxStale = 7 * 24 * time.Hour

	// Size limits of one download. They only guard against a rogue
	// endpoint; the real datasets are far below them.
	maxReleasesBytes     = 8 << 20
	maxReleaseCycleBytes = 1 << 20
	maxRecordBytes       = 2 << 20

	// maxRecordCacheBytes caps the CVE records kept in the cache, in total.
	maxRecordCacheBytes = 256 << 20
	// maxRecordFetches bounds the record requests of one Load. A list that
	// needs more is not one this package can trust.
	maxRecordFetches = 5000
	// loadTimeout bounds one Load, all downloads included.
	loadTimeout = 10 * time.Minute
)

// cache file names under CacheDir.
const (
	archiveFile      = "advisory-db.tar.gz"
	releasesFile     = "releases.json"
	releaseCycleFile = "release-cycle.json"
	recordsDir       = "cves"
	metaFile         = "meta.json"
)

// Source fetches and caches the advisory datasets. Only CacheDir is
// required; it should be a directory of its own, since the datasets and
// their meta.json are kept directly in it. Empty URLs fall back to the
// defaults.
type Source struct {
	CacheDir         string
	AdvisoryDBURL    string
	CVERecordBaseURL string
	ReleasesURL      string
	ReleaseCycleURL  string
	Client           *http.Client
	Now              func() time.Time
	Log              *slog.Logger

	// Overrides of the limits above for tests; zero uses the limit.
	timeout       time.Duration
	maxFetches    int
	maxCacheBytes int64
}

// notFoundError is a 404 from a dataset URL.
type notFoundError struct{ url string }

func (e *notFoundError) Error() string { return fmt.Sprintf("fetch %s: not found", e.url) }

// cacheMeta records when each cached file was fetched and the ETag it came
// with, by file name relative to the dataset directory.
type cacheMeta struct {
	Fetched map[string]time.Time `json:"fetched"`
	ETags   map[string]string    `json:"etags"`
}

func newCacheMeta() *cacheMeta {
	return &cacheMeta{Fetched: map[string]time.Time{}, ETags: map[string]string{}}
}

// Load refreshes the cached datasets as needed and parses them. It returns a
// non-nil Snapshot only when every dataset is usable; the error explains
// which were not.
func (s *Source) Load(ctx context.Context) (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, s.loadTimeout())
	defer cancel()

	dir := s.CacheDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	meta := s.loadMeta(dir)
	defer func() { s.saveMeta(dir, meta) }()
	log := s.log()

	var problems []error
	fail := func(dataset string, err error) {
		problems = append(problems, fmt.Errorf("%s: %w", dataset, err))
	}

	var advs []advisory
	if data, err := s.archive(ctx, dir, meta); err != nil {
		fail("advisory database", err)
	} else if advs, err = parseArchive(data); err != nil {
		fail("advisory database", err)
	}

	var finals map[int][]version
	if data, err := s.dataset(ctx, dir, meta, releasesFile, s.releasesURL(), maxReleasesBytes, validateReleases); err != nil {
		fail("releases", err)
	} else if finals, err = parseReleases(data); err != nil {
		fail("releases", err)
	}

	var eol map[int]bool
	if data, err := s.dataset(ctx, dir, meta, releaseCycleFile, s.releaseCycleURL(), maxReleaseCycleBytes, validateReleaseCycle); err != nil {
		fail("release cycle", err)
	} else if eol, err = parseReleaseCycle(data); err != nil {
		fail("release cycle", err)
	}

	var records map[string]cveInfo
	if advs != nil {
		var err error
		if records, err = s.loadRecords(ctx, dir, meta, advs); err != nil {
			fail("cve records", err)
		}
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("python advisories unavailable: %w", errors.Join(problems...))
	}
	snap := newSnapshot(advs, records, finals, eol)
	log.Info("python advisories loaded",
		"advisories", len(advs), "cves", len(snap.cves),
		"out_of_scope_cves", snap.outOfScope, "rejected_cves", snap.rejected,
		"withdrawn_advisories", snap.withdrawn)
	return snap, nil
}

// loadRecords returns the parsed CVE record of every CVE alias of the
// non-withdrawn advisories. Any record that is missing, or cannot be
// evaluated, makes the whole set unusable: matching without it would drop
// findings that state would then treat as resolved.
func (s *Source) loadRecords(ctx context.Context, dir string, meta *cacheMeta, advs []advisory) (map[string]cveInfo, error) {
	var ids []string
	seen := map[string]bool{}
	for _, a := range advs {
		if a.withdrawn {
			continue
		}
		for _, id := range a.cves {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)

	// Records the accepted list no longer refers to are dropped first, so
	// they never count against the cache limit, even when this update fails.
	s.pruneRecords(dir, meta, seen)

	records := make(map[string]cveInfo, len(ids))
	fetches := 0
	var cacheBytes int64
	for _, id := range ids {
		data, err := s.record(ctx, dir, meta, id, &fetches)
		if err != nil {
			return nil, err
		}
		cacheBytes += int64(len(data))
		if cacheBytes > s.recordCacheLimit() {
			return nil, fmt.Errorf("cached records are larger than %d bytes", s.recordCacheLimit())
		}
		info, err := parseCVE(id, data)
		if err != nil {
			return nil, err
		}
		records[id] = info
	}
	return records, nil
}

// pruneRecords removes cached records no advisory refers to any more, so the
// record cache does not grow past the current list.
func (s *Source) pruneRecords(dir string, meta *cacheMeta, keep map[string]bool) {
	entries, err := os.ReadDir(filepath.Join(dir, recordsDir))
	if err != nil {
		return
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && keep[id] {
			continue
		}
		name := recordsDir + "/" + e.Name()
		if err := os.Remove(filepath.Join(dir, recordsDir, e.Name())); err == nil {
			delete(meta.Fetched, name)
			delete(meta.ETags, name)
		}
	}
}

// record returns the content of one CVE record, re-downloading it when the
// cache is older than refreshAfter (conditionally, when an ETag is known).
// Any failure of the download, a 404 included, falls back to the cache while
// it is within maxStale. A cancelled or expired ctx never falls back: the
// Load is over.
func (s *Source) record(ctx context.Context, dir string, meta *cacheMeta, cve string, fetches *int) ([]byte, error) {
	name := recordsDir + "/" + cve + ".json"
	path := filepath.Join(dir, recordsDir, cve+".json")
	cached, err := os.ReadFile(path)
	at := meta.Fetched[name]
	if err != nil {
		cached, at = nil, time.Time{} // meta may lie (deleted cache); treat as absent
	}
	now := s.now()
	if cached != nil && !at.IsZero() && now.Sub(at) < refreshAfter {
		return cached, nil
	}

	*fetches++
	if *fetches > s.fetchLimit() {
		return nil, fmt.Errorf("more than %d CVE record requests in one update", s.fetchLimit())
	}
	etag := ""
	if cached != nil {
		etag = meta.ETags[name]
	}
	res, err := s.get(ctx, s.recordURL(cve), maxRecordBytes, etag)
	if err == nil && res.notModified {
		if cached == nil {
			err = fmt.Errorf("fetch %s: not modified, but nothing is cached", cve)
		} else {
			meta.Fetched[name] = now
			return cached, nil
		}
	}
	if err == nil {
		if err = s.checkNewRecord(dir, cve, cached, res.data); err != nil {
			err = fmt.Errorf("download %s: %w", s.recordURL(cve), err)
		} else if err = writeFile(path, res.data); err == nil {
			meta.Fetched[name] = now
			if res.etag != "" {
				meta.ETags[name] = res.etag
			} else {
				delete(meta.ETags, name)
			}
			return res.data, nil
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", cve, err)
	}
	if cached != nil && usable(at, now) {
		s.log().Warn("using stale python CVE record", "cve", cve, "fetched_at", at, "err", err)
		return cached, nil
	}
	if cached != nil {
		return nil, fmt.Errorf("%s: cache from %s is older than %s: %w", cve, at.Format(time.RFC3339), maxStale, err)
	}
	return nil, fmt.Errorf("%s: %w", cve, err)
}

// checkNewRecord decides whether a downloaded record may replace the cached
// one. Besides being a complete record for cve, it must not drop CPython
// ranges the cached copy had while the CVE is still published: that would
// make a detected CVE silently leave the matching. It must also fit in the
// record cache: the limit is checked against what is on disk, before writing.
func (s *Source) checkNewRecord(dir, cve string, cached, data []byte) error {
	if err := checkCVERecord(cve, data); err != nil {
		return err
	}
	if cached != nil && hasCPythonRanges(cached) && !hasCPythonRanges(data) && !isRejected(data) {
		return fmt.Errorf("record no longer has the CPython ranges the cached copy has")
	}
	used, err := dirSize(filepath.Join(dir, recordsDir))
	if err != nil {
		return err
	}
	if used-int64(len(cached))+int64(len(data)) > s.recordCacheLimit() {
		return fmt.Errorf("cached records would be larger than %d bytes", s.recordCacheLimit())
	}
	return nil
}

// dirSize is the total size of the regular files directly in dir; a missing
// dir is empty.
func dirSize(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, err
		}
		n += info.Size()
	}
	return n, nil
}

// archive returns the advisory archive. A new one that lacks an advisory the
// cached one has is not accepted: withdrawals are marked in the advisory, the
// file never goes away, so a missing one means a truncated or rolled-back
// download.
func (s *Source) archive(ctx context.Context, dir string, meta *cacheMeta) ([]byte, error) {
	path := filepath.Join(dir, archiveFile)
	var cachedIDs map[string]bool
	if data, err := os.ReadFile(path); err == nil {
		if advs, err := parseArchive(data); err == nil {
			cachedIDs = advisoryIDs(advs)
		}
	}
	validate := func(data []byte) error {
		advs, err := parseArchive(data)
		if err != nil {
			return err
		}
		have := advisoryIDs(advs)
		var missing []string
		for id := range cachedIDs {
			if !have[id] {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("archive lacks %d advisories the cached copy has (first: %s)", len(missing), missing[0])
		}
		return nil
	}
	return s.dataset(ctx, dir, meta, archiveFile, s.advisoryDBURL(), maxArchiveBytes, validate)
}

// dataset returns the content of a cached file, re-downloading it first when
// the cache is older than refreshAfter. A failed download, a 404 included,
// falls back to the cache while it is within maxStale.
func (s *Source) dataset(ctx context.Context, dir string, meta *cacheMeta, name, url string, limit int64, validate func([]byte) error) ([]byte, error) {
	path := filepath.Join(dir, filepath.FromSlash(name))
	at := meta.Fetched[name]
	if _, err := os.Stat(path); err != nil {
		at = time.Time{} // meta may lie (deleted cache); treat as absent
	}
	now := s.now()
	if at.IsZero() || now.Sub(at) >= refreshAfter {
		err := s.download(ctx, url, path, limit, validate)
		if err == nil {
			at = now
			meta.Fetched[name] = at
		} else {
			if ctx.Err() != nil {
				return nil, err
			}
			if !usable(at, now) {
				if at.IsZero() {
					return nil, err
				}
				return nil, fmt.Errorf("cache from %s is older than %s: %w", at.Format(time.RFC3339), maxStale, err)
			}
			s.log().Warn("using stale python advisory data", "file", name, "fetched_at", at, "err", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// download fetches url into path atomically. The payload is validated before
// it replaces the previous cache, so a bad response can never clobber a good
// dataset.
func (s *Source) download(ctx context.Context, url, path string, limit int64, validate func([]byte) error) error {
	res, err := s.get(ctx, url, limit, "")
	if err != nil {
		return err
	}
	if err := validate(res.data); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	return writeFile(path, res.data)
}

// response is a successful answer of get.
type response struct {
	data        []byte
	etag        string
	notModified bool
}

// get requests url, sending If-None-Match when etag is set. A body larger
// than limit is an error.
func (s *Source) get(ctx context.Context, url string, limit int64, etag string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return response{}, fmt.Errorf("build request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return response{}, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return response{}, &notFoundError{url: url}
	case resp.StatusCode == http.StatusNotModified && etag != "":
		return response{notModified: true}, nil
	case resp.StatusCode != http.StatusOK:
		return response{}, fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return response{}, fmt.Errorf("download %s: %w", url, err)
	}
	if int64(len(data)) > limit {
		return response{}, fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}
	return response{data: data, etag: resp.Header.Get("ETag")}, nil
}

// writeFile replaces path with data atomically.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// --- validation: reject a download that is not a plausible dataset ---

func validateReleases(data []byte) error {
	_, err := parseReleases(data)
	return err
}

func validateReleaseCycle(data []byte) error {
	_, err := parseReleaseCycle(data)
	return err
}

// --- meta / freshness helpers ---

func (s *Source) loadMeta(dir string) *cacheMeta {
	m := newCacheMeta()
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return m
	}
	var loaded cacheMeta
	if err := json.Unmarshal(data, &loaded); err != nil {
		return m // corrupt meta = re-fetch, not an error
	}
	if loaded.Fetched != nil {
		m.Fetched = loaded.Fetched
	}
	if loaded.ETags != nil {
		m.ETags = loaded.ETags
	}
	return m
}

func (s *Source) saveMeta(dir string, m *cacheMeta) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	if err := writeFile(filepath.Join(dir, metaFile), data); err != nil {
		s.log().Warn("write python advisory meta failed", "err", err)
	}
}

// usable reports whether a dataset fetched at t may still be served.
func usable(t, now time.Time) bool {
	return !t.IsZero() && now.Sub(t) <= maxStale
}

func (s *Source) advisoryDBURL() string { return orDefault(s.AdvisoryDBURL, DefaultAdvisoryDBURL) }
func (s *Source) releasesURL() string   { return orDefault(s.ReleasesURL, DefaultReleasesURL) }
func (s *Source) releaseCycleURL() string {
	return orDefault(s.ReleaseCycleURL, DefaultReleaseCycleURL)
}

// recordURL is <base><year>/<n/1000>xxx/<CVE>.json, the layout of the CVE
// list repository. cve has already matched cveIDRe.
func (s *Source) recordURL(cve string) string {
	base := orDefault(s.CVERecordBaseURL, DefaultCVERecordBaseURL)
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	m := cveIDRe.FindStringSubmatch(cve)
	n, _ := strconv.Atoi(m[2])
	return base + m[1] + "/" + strconv.Itoa(n/1000) + "xxx/" + cve + ".json"
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (s *Source) loadTimeout() time.Duration {
	if s.timeout > 0 {
		return s.timeout
	}
	return loadTimeout
}

func (s *Source) fetchLimit() int {
	if s.maxFetches > 0 {
		return s.maxFetches
	}
	return maxRecordFetches
}

func (s *Source) recordCacheLimit() int64 {
	if s.maxCacheBytes > 0 {
		return s.maxCacheBytes
	}
	return maxRecordCacheBytes
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
