package nodecore

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// blogHeadingRe matches an advisory heading:
// "## <title> (CVE-…[, CVE-…]) - (<severity>)".
var blogHeadingRe = regexp.MustCompile(`(?i)^##\s+(.*?)\s*\(\s*(CVE-\d+-\d+(?:\s*,\s*CVE-\d+-\d+)*)\s*\)\s*-\s*\(\s*([a-z]+)\s*\)\s*$`)

var (
	cveRe         = regexp.MustCompile(`CVE-\d+-\d+`)
	majorXRe      = regexp.MustCompile(`(?:^|[^0-9.])v?(\d+)\.x`)
	nodeJSRe      = regexp.MustCompile(`Node\.js\s+`)
	releaseLinkRe = regexp.MustCompile(`\bv(\d+\.\d+\.\d+)\b`)
	headingRe     = regexp.MustCompile(`^#{1,2}\s`)
)

// parseBlogPost reads the advisories of one security blog post. posted is
// the post's date, used when the front matter has none. Sections whose
// affected lines cannot be found are dropped and counted: assuming every
// line is affected would report Node.js lines the advisory never covered.
// A post without advisory headings yields nothing.
func parseBlogPost(slug string, data []byte, posted time.Time, log *slog.Logger) (advs []blogAdvisory, dropped int) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	posted = frontMatterDate(lines, posted)

	type section struct {
		m     []string // heading match
		lines []string
	}
	var sections []section
	var fixed map[int]version
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !headingRe.MatchString(line) {
			continue
		}
		end := i + 1
		for end < len(lines) && !headingRe.MatchString(lines[end]) {
			end++
		}
		body := lines[i+1 : end]
		if strings.HasPrefix(strings.ToLower(strings.TrimLeft(line, "# ")), "downloads and release details") {
			fixed = parseFixedVersions(body)
		} else if m := blogHeadingRe.FindStringSubmatch(line); m != nil {
			sections = append(sections, section{m: m, lines: body})
		}
	}

	for _, sec := range sections {
		title := strings.TrimSpace(sec.m[1])
		if npmWordRe.MatchString(title) {
			continue
		}
		majors := sectionMajors(sec.lines)
		if len(majors) == 0 {
			dropped++
			log.Warn("drop blog advisory without affected lines", "post", slug, "title", title)
			continue
		}
		advs = append(advs, blogAdvisory{
			cves:     cveRe.FindAllString(sec.m[2], -1),
			title:    title,
			severity: sec.m[3],
			slug:     slug,
			posted:   posted,
			affected: majors,
			fixed:    fixed,
		})
	}
	return advs, dropped
}

// frontMatterDate reads "date:" from the leading front matter.
func frontMatterDate(lines []string, fallback time.Time) time.Time {
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return fallback
	}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "---" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "date" {
			if t, ok := parseDate(strings.Trim(strings.TrimSpace(v), `"'`)); ok {
				return t
			}
			break
		}
	}
	return fallback
}

// parseFixedVersions reads the fixed version of each line from the release
// links ("[Node.js v22.23.4](…)") of the downloads section.
func parseFixedVersions(body []string) map[int]version {
	out := map[int]version{}
	for _, l := range body {
		for _, m := range releaseLinkRe.FindAllStringSubmatch(l, -1) {
			v, ok := parseVersion(m[1])
			if !ok {
				continue
			}
			if _, dup := out[v[0]]; !dup {
				out[v[0]] = v
			}
		}
	}
	return out
}

// sectionMajors returns the lines named by the first line of the section
// that mentions "affect" and names any.
func sectionMajors(body []string) map[int]bool {
	for _, l := range body {
		if !strings.Contains(strings.ToLower(l), "affect") {
			continue
		}
		if m := lineMajors(l); len(m) > 0 {
			return m
		}
	}
	return nil
}

// lineMajors collects the Node.js lines a sentence names, in both forms the
// posts use: "22.x" and "Node.js 22" (also "Node.js 20, 22 and 24").
func lineMajors(l string) map[int]bool {
	out := map[int]bool{}
	for _, m := range majorXRe.FindAllStringSubmatch(l, -1) {
		if n, ok := atoiBounded(m[1]); ok {
			out[n] = true
		}
	}
	for _, loc := range nodeJSRe.FindAllStringIndex(l, -1) {
		for _, n := range scanMajorList(l[loc[1]:]) {
			out[n] = true
		}
	}
	return out
}

// scanMajorList reads "22", "22, 24 and 25" or "**22**" from the start of s.
// A full version such as 22.1.0 ends the list without being counted.
func scanMajorList(s string) []int {
	var out []int
	i := 0
	skip := func(chars string) {
		for i < len(s) && strings.IndexByte(chars, s[i]) >= 0 {
			i++
		}
	}
	for {
		skip("* \t")
		if i < len(s) && s[i] == 'v' {
			i++
		}
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return out
		}
		if i+1 < len(s) && s[i] == '.' && s[i+1] >= '0' && s[i+1] <= '9' {
			return out
		}
		if n, ok := atoiBounded(s[start:i]); ok {
			out = append(out, n)
		}
		if i < len(s) && s[i] == '.' {
			return out // "22.x"
		}
		skip("* \t")
		sep := false
		if i < len(s) && s[i] == ',' {
			i++
			sep = true
			skip(" \t")
		}
		if rest := s[i:]; strings.HasPrefix(rest, "and ") || strings.HasPrefix(rest, "or ") {
			i += strings.IndexByte(rest, ' ') + 1
			sep = true
		}
		if !sep {
			return out
		}
	}
}

func atoiBounded(s string) (int, bool) {
	if len(s) > maxVersionDigits {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// feedItem is one item of the vulnerability RSS feed.
type feedItem struct {
	Slug  string
	Title string
	Date  time.Time
}

// parseFeed reads the RSS feed into items, newest first as published. Items
// without a usable link slug or date are skipped.
func parseFeed(data []byte, log *slog.Logger) ([]feedItem, error) {
	var rss struct {
		XMLName xml.Name `xml:"rss"`
		Items   []struct {
			Title   string `xml:"title"`
			Link    string `xml:"link"`
			PubDate string `xml:"pubDate"`
		} `xml:"channel>item"`
	}
	if err := xml.Unmarshal(data, &rss); err != nil {
		return nil, fmt.Errorf("parse blog feed: %w", err)
	}
	var out []feedItem
	for _, it := range rss.Items {
		link := strings.TrimRight(strings.TrimSpace(it.Link), "/")
		slug := link[strings.LastIndex(link, "/")+1:]
		if !slugRe.MatchString(slug) {
			log.Warn("skip blog feed item with unusable link", "link", it.Link)
			continue
		}
		t, err := parseRSSDate(it.PubDate)
		if err != nil {
			log.Warn("skip blog feed item with unusable date", "link", it.Link, "date", it.PubDate)
			continue
		}
		out = append(out, feedItem{Slug: slug, Title: strings.TrimSpace(it.Title), Date: t})
	}
	return out, nil
}

// slugRe keeps a feed-supplied slug safe to use as a file name and URL part.
var slugRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func parseRSSDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	var err error
	for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
		var t time.Time
		if t, err = time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, err
}
