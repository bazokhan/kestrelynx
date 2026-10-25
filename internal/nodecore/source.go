package nodecore

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
	"regexp"
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
	// maxDownloadBytes caps one download; the largest dataset is a few
	// hundred KB, so this only guards against a rogue endpoint.
	maxDownloadBytes = 64 << 20
	// recentWindow is how far back the feed's posts are read.
	recentWindow = 180 * 24 * time.Hour
	// maxRecentPosts bounds how many posts one feed can make Load fetch.
	// Node.js publishes a handful of posts in recentWindow; a feed listing
	// more is not one this package can trust, so the blog is unusable.
	maxRecentPosts = 30
	// maxPostBytes caps one post download; a security post is ~10 KB.
	maxPostBytes = 1 << 20
)

// securityReleaseTitleRe matches the title Node.js gives a security release
// post ("Wednesday, October 21, 2026 Security Releases"). Such a post must
// be readable: its advisories are what the blog dataset is for.
var securityReleaseTitleRe = regexp.MustCompile(`(?i)\bsecurity\s+releases?\b`)

// cache file names under CacheDir.
const (
	securityWGFile = "security-wg.json"
	feedFile       = "feed.xml"
	releasesFile   = "releases.json"
	scheduleFile   = "schedule.json"
	postsDir       = "posts"
	metaFile       = "meta.json"
)

// Source fetches and caches the advisory datasets. Only CacheDir is
// required; it should be a directory of its own, since the datasets and
// their meta.json are kept directly in it. Empty URLs fall back to the
// defaults.
type Source struct {
	CacheDir        string
	SecurityWGURL   string
	BlogFeedURL     string
	BlogPostBaseURL string
	ReleasesURL     string
	ScheduleURL     string
	Client          *http.Client
	Now             func() time.Time
	Log             *slog.Logger
}

// notFoundError is a 404 from a dataset URL.
type notFoundError struct{ url string }

func (e *notFoundError) Error() string { return fmt.Sprintf("fetch %s: not found", e.url) }

// fetchTimes records when each cached file was fetched, by file name
// relative to the dataset directory.
type fetchTimes map[string]time.Time

// Load refreshes the cached datasets as needed and parses them. It returns a
// non-nil Snapshot only when every dataset is usable; the error explains
// which were not.
func (s *Source) Load(ctx context.Context) (*Snapshot, error) {
	dir := s.CacheDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	times := s.loadMeta(dir)
	defer func() { s.saveMeta(dir, times) }()
	log := s.log()

	var problems []error
	fail := func(dataset string, err error) {
		problems = append(problems, fmt.Errorf("%s: %w", dataset, err))
	}

	var wg []wgEntry
	var wgSkipped int
	if data, err := s.dataset(ctx, dir, times, securityWGFile, s.securityWGURL(), validateSecurityWG); err != nil {
		fail("security-wg", err)
	} else if wg, wgSkipped, err = parseSecurityWG(data, log); err != nil {
		fail("security-wg", err)
	}

	blog, blogDropped, err := s.loadBlog(ctx, dir, times)
	if err != nil {
		fail("blog", err)
	}

	var releases map[version]time.Time
	if data, err := s.dataset(ctx, dir, times, releasesFile, s.releasesURL(), validateReleases); err != nil {
		fail("releases", err)
	} else if releases, err = parseReleases(data); err != nil {
		fail("releases", err)
	}

	var eol map[int]time.Time
	if data, err := s.dataset(ctx, dir, times, scheduleFile, s.scheduleURL(), validateSchedule); err != nil {
		fail("schedule", err)
	} else if eol, err = parseSchedule(data); err != nil {
		fail("schedule", err)
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("node.js advisories unavailable: %w", errors.Join(problems...))
	}
	snap := newSnapshot(wg, wgSkipped, blog, blogDropped, releases, eol)
	log.Info("node.js advisories loaded",
		"security_wg_entries", len(snap.wg), "security_wg_skipped", wgSkipped,
		"blog_advisories", len(snap.blog), "blog_dropped", blogDropped)
	return snap, nil
}

// loadBlog reads the feed and the recent posts' advisories.
func (s *Source) loadBlog(ctx context.Context, dir string, times fetchTimes) ([]blogAdvisory, int, error) {
	log := s.log()
	data, err := s.dataset(ctx, dir, times, feedFile, s.blogFeedURL(), validateFeed)
	if err != nil {
		return nil, 0, fmt.Errorf("feed: %w", err)
	}
	items, err := parseFeed(data, log)
	if err != nil {
		return nil, 0, err
	}

	now := s.now()
	var recent []feedItem
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.Slug] || now.Sub(it.Date) > recentWindow {
			continue
		}
		seen[it.Slug] = true
		recent = append(recent, it)
	}
	if len(recent) > maxRecentPosts {
		return nil, 0, fmt.Errorf("feed lists %d posts within %s, more than %d", len(recent), recentWindow, maxRecentPosts)
	}

	var advs []blogAdvisory
	dropped, notFound := 0, 0
	for _, it := range recent {
		body, err := s.post(ctx, dir, times, it)
		var nf *notFoundError
		if errors.As(err, &nf) {
			if securityReleaseTitleRe.MatchString(it.Title) {
				return nil, 0, fmt.Errorf("security release post %s: %w", it.Slug, err)
			}
			// Not every post in the feed is a security release (analysis
			// articles are filed there too) and those have no advisory file.
			log.Warn("skip blog post without an advisory file", "post", it.Slug)
			notFound++
			continue
		}
		if err != nil {
			return nil, 0, fmt.Errorf("post %s: %w", it.Slug, err)
		}
		a, d := parseBlogPost(it.Slug, body, it.Date, log)
		advs = append(advs, a...)
		dropped += d
	}
	if len(recent) > 0 && notFound == len(recent) {
		return nil, 0, fmt.Errorf("all %d recent posts returned 404", notFound)
	}
	return advs, dropped, nil
}

// post returns the content of one blog post, re-downloading it when the
// cache is older than refreshAfter. Unlike the other datasets, a post that
// was cached once is served from the cache whatever its age when the
// download fails, 404 included: a post is a published announcement, so an
// old copy still holds its advisories, while dropping it would make them
// look resolved. A new download that holds no advisories does not replace a
// cached copy that did. A 404 with nothing cached is returned as such.
func (s *Source) post(ctx context.Context, dir string, times fetchTimes, it feedItem) ([]byte, error) {
	name := postsDir + "/" + it.Slug + ".md"
	path := filepath.Join(dir, filepath.FromSlash(name))
	cached, cerr := os.ReadFile(path)
	if cerr != nil {
		cached = nil
	}
	at := times[name]
	if cached == nil {
		at = time.Time{}
	}
	now := s.now()
	if !at.IsZero() && now.Sub(at) < refreshAfter {
		return cached, nil
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	cachedAdvisories := 0
	if cached != nil {
		a, _ := parseBlogPost(it.Slug, cached, it.Date, quiet)
		cachedAdvisories = len(a)
	}
	validate := func(data []byte) error {
		if err := validatePost(data); err != nil {
			return err
		}
		if a, _ := parseBlogPost(it.Slug, data, it.Date, quiet); cachedAdvisories > 0 && len(a) == 0 {
			return fmt.Errorf("post has no advisories, while the cached copy has %d", cachedAdvisories)
		}
		return nil
	}
	err := s.download(ctx, s.postURL(it.Slug), path, maxPostBytes, validate)
	if err == nil {
		times[name] = now
		return os.ReadFile(path)
	}
	if cached == nil {
		return nil, err
	}
	s.log().Warn("using cached node.js blog post", "post", it.Slug, "fetched_at", at, "err", err)
	return cached, nil
}

// dataset returns the content of a cached file, re-downloading it first when
// the cache is older than refreshAfter. A failed download falls back to the
// cache while it is within maxStale. A 404 is always returned as such.
func (s *Source) dataset(ctx context.Context, dir string, times fetchTimes, name, url string, validate func([]byte) error) ([]byte, error) {
	path := filepath.Join(dir, filepath.FromSlash(name))
	at := times[name]
	if _, err := os.Stat(path); err != nil {
		at = time.Time{} // meta may lie (deleted cache); treat as absent
	}
	now := s.now()
	if at.IsZero() || now.Sub(at) >= refreshAfter {
		err := s.download(ctx, url, path, maxDownloadBytes, validate)
		if err == nil {
			at = now
			times[name] = at
		} else {
			var nf *notFoundError
			if errors.As(err, &nf) {
				return nil, err
			}
			if !usable(at, now) {
				if at.IsZero() {
					return nil, err
				}
				return nil, fmt.Errorf("cache from %s is older than %s: %w", at.Format(time.RFC3339), maxStale, err)
			}
			s.log().Warn("using stale node.js advisory data", "file", name, "fetched_at", at, "err", err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &notFoundError{url: url}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}
	if err := validate(data); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}

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

func validateSecurityWG(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("not a security-wg index: %w", err)
	}
	if len(raw) == 0 {
		return errors.New("security-wg index has no entries")
	}
	return nil
}

func validateFeed(data []byte) error {
	_, err := parseFeed(data, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return err
}

// validatePost accepts only a markdown post with front matter carrying a
// date, so an error page served with status 200 never replaces a post.
func validatePost(data []byte) error {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return errors.New("blog post has no front matter")
	}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if l == "---" {
			break
		}
		if strings.HasPrefix(l, "date:") {
			return nil
		}
	}
	return errors.New("blog post front matter has no date")
}

func validateReleases(data []byte) error {
	_, err := parseReleases(data)
	return err
}

func validateSchedule(data []byte) error {
	_, err := parseSchedule(data)
	return err
}

// --- meta / freshness helpers ---

func (s *Source) loadMeta(dir string) fetchTimes {
	t := fetchTimes{}
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return t
	}
	if err := json.Unmarshal(data, &t); err != nil || t == nil {
		return fetchTimes{} // corrupt meta = re-fetch, not an error
	}
	return t
}

func (s *Source) saveMeta(dir string, t fetchTimes) {
	data, err := json.Marshal(t)
	if err != nil {
		return
	}
	path := filepath.Join(dir, metaFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		s.log().Warn("write node.js advisory meta failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.log().Warn("write node.js advisory meta failed", "err", err)
	}
}

// usable reports whether a dataset fetched at t may still be served.
func usable(t, now time.Time) bool {
	return !t.IsZero() && now.Sub(t) <= maxStale
}

func (s *Source) securityWGURL() string { return orDefault(s.SecurityWGURL, DefaultSecurityWGURL) }
func (s *Source) blogFeedURL() string   { return orDefault(s.BlogFeedURL, DefaultBlogFeedURL) }
func (s *Source) releasesURL() string   { return orDefault(s.ReleasesURL, DefaultReleasesURL) }
func (s *Source) scheduleURL() string   { return orDefault(s.ScheduleURL, DefaultScheduleURL) }

func (s *Source) postURL(slug string) string {
	base := orDefault(s.BlogPostBaseURL, DefaultBlogPostBaseURL)
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + slug + ".md"
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
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
