package pycore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testNow = "2026-10-25T12:00:00Z"

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// tarEntry is one entry of a test archive.
type tarEntry struct {
	name string
	typ  byte // 0 = regular file
	body string
	link string
}

// makeArchive builds a gzip-compressed tar from entries.
func makeArchive(t testing.TB, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Linkname: e.link}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readTarGz returns the regular files of a tar.gz by base name.
func readTarGz(t testing.TB, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		name := hdr.Name
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		out[name] = b
	}
}

var (
	realOnce    sync.Once
	realRecords map[string][]byte // "CVE-....json" -> record
)

// realCVERecords are the recorded CVE records of every PSF alias.
func realCVERecords(t testing.TB) map[string][]byte {
	t.Helper()
	realOnce.Do(func() {
		realRecords = readTarGz(t, readTestdata(t, "cve-records.tar.gz"))
	})
	return realRecords
}

// recordPath is the URL path the CVE list repository files a CVE under,
// derived by string slicing so the test does not share code with the
// package.
func recordPath(cve string) string {
	parts := strings.Split(cve, "-")
	num := parts[2]
	thousands := "0"
	if len(num) > 3 {
		thousands = strings.TrimLeft(num[:len(num)-3], "0")
		if thousands == "" {
			thousands = "0"
		}
	}
	return "/cves/" + parts[1] + "/" + thousands + "xxx/" + cve + ".json"
}

// site is a fake of the four public endpoints. Every response carries an
// ETag and honours If-None-Match.
type site struct {
	mu     sync.Mutex
	body   map[string][]byte
	status map[string]int
	delay  map[string]time.Duration
	hits   map[string]int
	cond   map[string]int // conditional requests answered 304
	srv    *httptest.Server
}

func newEmptySite(t testing.TB) *site {
	t.Helper()
	s := &site{
		body: map[string][]byte{}, status: map[string]int{}, delay: map[string]time.Duration{},
		hits: map[string]int{}, cond: map[string]int{},
	}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

// newSite serves the recorded datasets.
func newSite(t testing.TB) *site {
	t.Helper()
	s := newEmptySite(t)
	s.body["/db"] = readTestdata(t, "psf-advisory-database.tar.gz")
	s.body["/releases"] = readTestdata(t, "python-releases.json")
	s.body["/cycle"] = readTestdata(t, "release-cycle.json")
	for name, b := range realCVERecords(t) {
		s.body[recordPath(strings.TrimSuffix(name, ".json"))] = b
	}
	return s
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	code, forced := s.status[r.URL.Path]
	body, ok := s.body[r.URL.Path]
	delay := s.delay[r.URL.Path]
	s.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if forced {
		http.Error(w, "forced", code)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		s.mu.Lock()
		s.cond[r.URL.Path]++
		s.mu.Unlock()
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Write(body)
}

func (s *site) set(path string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body[path] = body
	delete(s.status, path)
}

func (s *site) remove(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.body, path)
}

func (s *site) force(path string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[path] = code
}

func (s *site) forceAll(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.body {
		s.status[p] = code
	}
}

func (s *site) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = map[string]int{}
	s.delay = map[string]time.Duration{}
}

func (s *site) setDelay(path string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay[path] = d
}

func (s *site) hitCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *site) totalHits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hits {
		n += h
	}
	return n
}

func (s *site) recordHits() (hits, notModified int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, h := range s.hits {
		if strings.HasPrefix(p, "/cves/") {
			hits += h
		}
	}
	for p, h := range s.cond {
		if strings.HasPrefix(p, "/cves/") {
			notModified += h
		}
	}
	return hits, notModified
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newClock(t testing.TB) *clock {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return &clock{now: now}
}

func (s *site) source(t testing.TB, c *clock) *Source {
	t.Helper()
	return &Source{
		CacheDir:         t.TempDir(),
		AdvisoryDBURL:    s.srv.URL + "/db",
		CVERecordBaseURL: s.srv.URL + "/cves/",
		ReleasesURL:      s.srv.URL + "/releases",
		ReleaseCycleURL:  s.srv.URL + "/cycle",
		Client:           s.srv.Client(),
		Now:              c.Now,
		Log:              quietLog(),
	}
}

// --- synthetic datasets ---

// psfFile is the archive path of an advisory.
func psfFile(id string) string { return "advisory-database-main/advisories/python/" + id + ".json" }

// advisoryJSON is a minimal PSF advisory.
func advisoryJSON(id string, withdrawn bool, cves ...string) string {
	aliases := make([]string, len(cves))
	for i, c := range cves {
		aliases[i] = strconv.Quote(c)
	}
	w := ""
	if withdrawn {
		w = `"withdrawn":"2026-01-01T00:00:00Z",`
	}
	return fmt.Sprintf(`{%s"id":%q,"aliases":[%s],"summary":"summary of %s","details":"First sentence. Second sentence.","references":[{"type":"ADVISORY","url":"https://example.test/%s"}]}`,
		w, id, strings.Join(aliases, ","), id, id)
}

// recordJSON is a minimal CVE record with one CPython item. versions is the
// JSON array of the item's versions; extra is spliced into the item.
func recordJSON(cve, state, versions, extra string) string {
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":%q},"containers":{"cna":{"affected":[{"vendor":"Python Software Foundation","product":"CPython"%s,"versions":%s}],"metrics":[{"cvssV3_1":{"baseSeverity":"high"}}]}}}`,
		cve, state, extra, versions)
}

const rangeThrough = `[{"version":"0","lessThan":"3.12.5","status":"affected","versionType":"python"}]`

// miniSite serves a hand-made list: the given advisories (ID -> JSON), the
// recorded releases and release cycle, and the given records (CVE -> JSON).
func miniSite(t testing.TB, advs map[string]string, records map[string]string) *site {
	t.Helper()
	s := newEmptySite(t)
	var entries []tarEntry
	for id, body := range advs {
		entries = append(entries, tarEntry{name: psfFile(id), body: body})
	}
	s.set("/db", makeArchive(t, entries))
	s.set("/releases", readTestdata(t, "python-releases.json"))
	s.set("/cycle", readTestdata(t, "release-cycle.json"))
	for cve, body := range records {
		s.set(recordPath(cve), []byte(body))
	}
	return s
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
