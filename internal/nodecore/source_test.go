package nodecore

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// site is a fake of the five public endpoints, serving the recorded data.
type site struct {
	mu     sync.Mutex
	body   map[string]string // path -> body
	status map[string]int    // path -> forced status
	hits   map[string]int
	srv    *httptest.Server
}

func newSite(t *testing.T) *site {
	t.Helper()
	s := &site{body: map[string]string{}, status: map[string]int{}, hits: map[string]int{}}
	s.body["/wg"] = string(readTestdata(t, "core-index.json"))
	s.body["/releases"] = string(readTestdata(t, "dist-index.json"))
	s.body["/schedule"] = string(readTestdata(t, "schedule.json"))
	s.body["/feed"] = string(readTestdata(t, "vuln-feed.xml"))
	for _, p := range []string{"october", "july", "june", "march"} {
		slug := p + "-2026-security-releases"
		s.body["/posts/"+slug+".md"] = string(readTestdata(t, slug+".md"))
	}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[r.URL.Path]++
	if code, ok := s.status[r.URL.Path]; ok {
		http.Error(w, "forced", code)
		return
	}
	body, ok := s.body[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, body)
}

func (s *site) set(path, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body[path] = body
	delete(s.status, path)
}

func (s *site) force(path string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[path] = code
}

func (s *site) forceAll(code int) {
	for _, p := range []string{"/wg", "/releases", "/schedule", "/feed"} {
		s.force(p, code)
	}
	s.mu.Lock()
	paths := make([]string, 0, len(s.body))
	for p := range s.body {
		paths = append(paths, p)
	}
	s.mu.Unlock()
	for _, p := range paths {
		s.force(p, code)
	}
}

func (s *site) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = map[string]int{}
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

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func (s *site) source(t *testing.T, c *clock) *Source {
	t.Helper()
	return &Source{
		CacheDir:        t.TempDir(),
		SecurityWGURL:   s.srv.URL + "/wg",
		BlogFeedURL:     s.srv.URL + "/feed",
		BlogPostBaseURL: s.srv.URL + "/posts/",
		ReleasesURL:     s.srv.URL + "/releases",
		ScheduleURL:     s.srv.URL + "/schedule",
		Client:          s.srv.Client(),
		Now:             c.Now,
		Log:             quietLog(),
	}
}

func newClock(t *testing.T) *clock {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return &clock{now: now}
}

func feedWith(items ...[2]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel><title>x</title>`)
	for _, it := range items {
		fmt.Fprintf(&b, "<item><title>t</title><link>https://nodejs.org/en/blog/vulnerability/%s</link><pubDate>%s</pubDate></item>", it[0], it[1])
	}
	b.WriteString(`</channel></rss>`)
	return b.String()
}

func mustLoad(t *testing.T, s *Source) *Snapshot {
	t.Helper()
	snap, err := s.Load(context.Background())
	if err != nil || snap == nil {
		t.Fatalf("Load = %v, %v", snap, err)
	}
	return snap
}

func TestLoadFreshFetch(t *testing.T) {
	st := newSite(t)
	snap := mustLoad(t, st.source(t, newClock(t)))

	for _, p := range []string{"/wg", "/feed", "/releases", "/schedule",
		"/posts/october-2026-security-releases.md", "/posts/july-2026-security-releases.md", "/posts/june-2026-security-releases.md"} {
		if n := st.hitCount(p); n != 1 {
			t.Errorf("%s fetched %d times, want 1", p, n)
		}
	}
	// March is older than 180 days and the old cycles' posts are not read.
	if n := st.hitCount("/posts/march-2026-security-releases.md"); n != 0 {
		t.Errorf("march post fetched %d times, want 0", n)
	}
	a := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]
	if a.FixedVer != "22.23.4" || a.Severity != "HIGH" || a.URL != octoberURL {
		t.Errorf("advisory = %+v", a)
	}
	if got := byID(snap.Match("22.23.1", "linux")); got["CVE-2026-58045"].FixedVer != "22.23.2" {
		t.Errorf("July CVE = %+v", got["CVE-2026-58045"])
	}
}

func TestLoadCacheReuseAndRefresh(t *testing.T) {
	st := newSite(t)
	c := newClock(t)
	src := st.source(t, c)
	mustLoad(t, src)
	first := st.totalHits()

	c.advance(19 * time.Hour)
	mustLoad(t, src)
	if got := st.totalHits(); got != first {
		t.Errorf("hits within 20h: %d, want %d (cache reuse)", got, first)
	}

	c.advance(2 * time.Hour) // 21h since the fetch
	mustLoad(t, src)
	if got := st.totalHits(); got != 2*first {
		t.Errorf("hits after 21h: %d, want %d (refresh)", got, 2*first)
	}

	// A new Source over the same directory reuses the cache too.
	src2 := *src
	src2.Client = &http.Client{Transport: failTransport{}}
	if snap, err := src2.Load(context.Background()); err != nil || snap == nil {
		t.Errorf("second Source over the same cache: %v, %v", snap, err)
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network down")
}

func TestLoadStaleFallbackAndExpiry(t *testing.T) {
	st := newSite(t)
	c := newClock(t)
	src := st.source(t, c)
	mustLoad(t, src)

	st.forceAll(http.StatusInternalServerError)
	c.advance(6 * 24 * time.Hour)
	snap := mustLoad(t, src)
	if _, ok := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]; !ok {
		t.Error("stale snapshot lost data")
	}

	c.advance(2 * 24 * time.Hour) // 8 days since the fetch
	snap, err := src.Load(context.Background())
	if snap != nil || err == nil {
		t.Fatalf("Load after 7 days of failure = %v, %v; want nil and an error", snap, err)
	}
	for _, name := range []string{"security-wg", "blog", "releases", "schedule"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}

	// Recovery: the next successful cycle refreshes everything.
	st.clear()
	mustLoad(t, src)
}

func TestLoadBadDownloadKeepsCache(t *testing.T) {
	st := newSite(t)
	c := newClock(t)
	src := st.source(t, c)
	mustLoad(t, src)

	st.set("/schedule", "<html>captive portal</html>")
	st.set("/wg", "{}")
	c.advance(21 * time.Hour)
	snap := mustLoad(t, src)
	if _, ok := byID(snap.Match("20.20.0", "linux"))["CVE-2026-111497"]; !ok {
		t.Error("cache was clobbered by a bad download")
	}
	data, err := os.ReadFile(filepath.Join(src.CacheDir, "schedule.json"))
	if err != nil || !strings.Contains(string(data), `"v22"`) {
		t.Errorf("cached schedule replaced: %v", err)
	}
}

func TestLoadNoCacheAndOneDatasetDown(t *testing.T) {
	for _, tc := range []struct{ path, name string }{
		{"/wg", "security-wg"}, {"/feed", "blog"}, {"/releases", "releases"}, {"/schedule", "schedule"},
		{"/posts/october-2026-security-releases.md", "blog"},
	} {
		t.Run(tc.name+tc.path, func(t *testing.T) {
			st := newSite(t)
			st.force(tc.path, http.StatusServiceUnavailable)
			snap, err := st.source(t, newClock(t)).Load(context.Background())
			if snap != nil || err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Errorf("Load = %v, %v; want nil and an error naming %s", snap, err, tc.name)
			}
			// Only the named dataset is reported.
			for _, other := range []string{"security-wg", "blog", "releases", "schedule"} {
				if other != tc.name && strings.Contains(err.Error(), " "+other+":") {
					t.Errorf("error %q names %s too", err, other)
				}
			}
		})
	}
}

func TestLoadPost404(t *testing.T) {
	st := newSite(t)
	st.set("/feed", feedWith(
		[2]string{"october-2026-security-releases", "Wed, 21 Oct 2026 22:00:00 GMT"},
		[2]string{"october-2026-analysis", "Tue, 20 Oct 2026 20:00:00 GMT"},
		[2]string{"june-2026-security-releases", "Thu, 18 Jun 2026 04:00:00 GMT"},
	))
	snap := mustLoad(t, st.source(t, newClock(t)))
	if _, ok := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]; !ok {
		t.Error("advisories of the other posts missing")
	}
	if st.hitCount("/posts/october-2026-analysis.md") == 0 {
		t.Error("the analysis post was never requested")
	}
}

func TestLoadAllRecentPosts404(t *testing.T) {
	st := newSite(t)
	st.set("/feed", feedWith(
		[2]string{"a-post", "Wed, 21 Oct 2026 22:00:00 GMT"},
		[2]string{"b-post", "Tue, 20 Oct 2026 20:00:00 GMT"},
	))
	snap, err := st.source(t, newClock(t)).Load(context.Background())
	if snap != nil || err == nil || !strings.Contains(err.Error(), "blog") || !strings.Contains(err.Error(), "404") {
		t.Errorf("Load = %v, %v; want nil and a blog 404 error", snap, err)
	}
}

func TestLoadNoRecentPosts(t *testing.T) {
	st := newSite(t)
	st.set("/feed", feedWith([2]string{"march-2026-security-releases", "Tue, 24 Mar 2026 03:00:00 GMT"}))
	snap := mustLoad(t, st.source(t, newClock(t)))
	// With no recent post the blog contributes nothing; security-wg still does.
	if _, ok := byID(snap.Match("22.23.1", "linux"))["CVE-2026-58045"]; !ok {
		t.Error("security-wg advisories missing")
	}
	if _, ok := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]; ok {
		t.Error("October advisory should be absent without its post")
	}
}

func TestLoadPostFailureUsesStaleCache(t *testing.T) {
	st := newSite(t)
	c := newClock(t)
	src := st.source(t, c)
	mustLoad(t, src)

	st.force("/posts/october-2026-security-releases.md", http.StatusBadGateway)
	c.advance(21 * time.Hour)
	snap := mustLoad(t, src)
	if _, ok := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]; !ok {
		t.Error("cached post not used after a transient failure")
	}
}

func TestLoadDefaultsAndPostBaseURL(t *testing.T) {
	var s Source
	if s.securityWGURL() != DefaultSecurityWGURL || s.blogFeedURL() != DefaultBlogFeedURL ||
		s.releasesURL() != DefaultReleasesURL || s.scheduleURL() != DefaultScheduleURL {
		t.Error("empty URLs should fall back to the defaults")
	}
	if got, want := s.postURL("x"), DefaultBlogPostBaseURL+"x.md"; got != want {
		t.Errorf("postURL = %q, want %q", got, want)
	}
	s.BlogPostBaseURL = "https://mirror.example/posts"
	if got, want := s.postURL("x"), "https://mirror.example/posts/x.md"; got != want {
		t.Errorf("postURL = %q, want %q", got, want)
	}
}

func TestParseFeed(t *testing.T) {
	items, err := parseFeed(readTestdata(t, "vuln-feed.xml"), quietLog())
	if err != nil || len(items) == 0 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	if items[0].Slug != "october-2026-security-releases" || items[0].Date.Format("2006-01-02") != "2026-10-21" {
		t.Errorf("first item = %+v", items[0])
	}
	items, err = parseFeed([]byte(feedWith(
		[2]string{"..", "Wed, 21 Oct 2026 22:00:00 GMT"},
		[2]string{"ok", "garbage"},
		[2]string{"fine", "Wed, 21 Oct 2026 22:00:00 +0000"},
	)), quietLog())
	if err != nil || len(items) != 1 || items[0].Slug != "fine" {
		t.Errorf("items = %+v, err = %v; want only the safe, dated item", items, err)
	}
	if _, err := parseFeed([]byte("<html/>"), quietLog()); err == nil {
		t.Error("non-RSS body should fail")
	}
}

func TestRefresher(t *testing.T) {
	st := newSite(t)
	src := st.source(t, newClock(t))
	var a Advisor
	r := Refresher{Source: src, Advisor: &a}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if aug := a.Augment(nodeScan("22.23.3"), allSeverities); aug.Unchecked || len(aug.Findings) == 0 {
		t.Errorf("after Refresh: %+v", aug)
	}

	// A failing cycle leaves no snapshot behind rather than yesterday's.
	st.forceAll(http.StatusInternalServerError)
	src.CacheDir = t.TempDir()
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if aug := a.Augment(nodeScan("22.23.3"), allSeverities); !aug.Unchecked {
		t.Errorf("after failed Refresh: %+v, want Unchecked", aug)
	}
}

// feedWithTitles is feedWith with each item's title: {slug, date, title}.
func feedWithTitles(items ...[3]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel><title>x</title>`)
	for _, it := range items {
		fmt.Fprintf(&b, "<item><title><![CDATA[%s]]></title><link>https://nodejs.org/en/blog/vulnerability/%s</link><pubDate>%s</pubDate></item>", it[2], it[0], it[1])
	}
	b.WriteString(`</channel></rss>`)
	return b.String()
}

func TestLoadPost404AfterCachingKeepsAdvisories(t *testing.T) {
	st := newSite(t)
	c := newClock(t)
	src := st.source(t, c)
	mustLoad(t, src)

	st.force("/posts/october-2026-security-releases.md", http.StatusNotFound)
	c.advance(30 * 24 * time.Hour) // far past maxStale: a cached post has no age limit
	snap := mustLoad(t, src)
	if _, ok := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]; !ok {
		t.Error("a post that now 404s must still be served from its cached copy")
	}
}

func TestLoadErrorPageDoesNotReplacePost(t *testing.T) {
	for name, body := range map[string]string{
		"html error page": "<html><body>Service unavailable</body></html>",
		"no advisories":   "---\ndate: 2026-10-21T22:00:00.000Z\ntitle: x\n---\n\nNothing here.\n",
	} {
		t.Run(name, func(t *testing.T) {
			st := newSite(t)
			c := newClock(t)
			src := st.source(t, c)
			mustLoad(t, src)

			st.set("/posts/october-2026-security-releases.md", body)
			c.advance(21 * time.Hour)
			snap := mustLoad(t, src)
			if _, ok := byID(snap.Match("22.23.3", "linux"))["CVE-2026-111497"]; !ok {
				t.Error("the cached post was replaced by a response without its advisories")
			}
			cached, err := os.ReadFile(filepath.Join(src.CacheDir, postsDir, "october-2026-security-releases.md"))
			if err != nil || !strings.Contains(string(cached), "CVE-2026-111497") {
				t.Errorf("cached post overwritten: %v", err)
			}
		})
	}
}

func TestLoadUncachedSecurityReleasePost404IsUnusable(t *testing.T) {
	st := newSite(t)
	st.set("/feed", feedWithTitles(
		[3]string{"october-2026-security-releases", "Wed, 21 Oct 2026 22:00:00 GMT", "Wednesday, October 21, 2026 Security Releases"},
		[3]string{"november-2026-security-releases", "Thu, 22 Oct 2026 22:00:00 GMT", "Thursday, October 22, 2026 Security Releases"},
	))
	snap, err := st.source(t, newClock(t)).Load(context.Background())
	if snap != nil || err == nil || !strings.Contains(err.Error(), "security release post") {
		t.Errorf("Load = %v, %v; want nil and a security release post error", snap, err)
	}
}

func TestLoadTooManyRecentPostsIsUnusable(t *testing.T) {
	st := newSite(t)
	var items [][2]string
	for i := 0; i <= maxRecentPosts; i++ {
		items = append(items, [2]string{fmt.Sprintf("post-%d", i), "Wed, 21 Oct 2026 22:00:00 GMT"})
	}
	st.set("/feed", feedWith(items...))
	snap, err := st.source(t, newClock(t)).Load(context.Background())
	if snap != nil || err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("Load = %v, %v; want nil and a too-many-posts error", snap, err)
	}
	if n := st.hitCount("/posts/post-0.md"); n != 0 {
		t.Errorf("posts fetched despite the bound: %d", n)
	}
}

func TestLoadOversizedPostIsUnusable(t *testing.T) {
	st := newSite(t)
	st.set("/posts/october-2026-security-releases.md",
		"---\ndate: 2026-10-21T22:00:00.000Z\n---\n"+strings.Repeat("x", maxPostBytes))
	snap, err := st.source(t, newClock(t)).Load(context.Background())
	if snap != nil || err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("Load = %v, %v; want nil and a size error", snap, err)
	}
}
