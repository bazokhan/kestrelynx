package pycore

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// osvURLBase is where an advisory without an ADVISORY reference is linked.
const osvURLBase = "https://osv.dev/vulnerability/"

// Snapshot is one consistent set of the parsed datasets.
type Snapshot struct {
	cves []cveAdvisory // sorted by VulnID
	// finals are the final releases of each 3.Y line, ascending.
	finals map[int][]version
	// eol are the 3.Y lines the release cycle lists as end-of-life.
	eol map[int]bool

	outOfScope int // CVEs without CPython version ranges, not matched
	rejected   int // CVEs the CNA rejected
	withdrawn  int // withdrawn advisories
}

// cveAdvisory is one CVE to match, with the PSF advisory it was found in.
type cveAdvisory struct {
	id       string
	title    string
	url      string
	severity string
	items    []rangeItem
}

// Advisory is one matched CVE for a version.
type Advisory struct {
	VulnID   string
	Title    string
	URL      string
	Severity string // upper case
	Status   scanner.Status
	FixedVer string // set only with scanner.StatusFixed
}

var (
	releaseNameRe = regexp.MustCompile(`^Python (3\.[0-9]+\.[0-9]+)$`)
	cycleLineRe   = regexp.MustCompile(`^3\.(0|[1-9][0-9]*)$`)
)

// parseReleases reads the python.org release list into the final releases of
// each 3.Y line. Pre-releases and other major versions are not needed.
func parseReleases(data []byte) (map[int][]version, error) {
	var raw []struct {
		Name        string `json:"name"`
		PreRelease  bool   `json:"pre_release"`
		IsPublished *bool  `json:"is_published"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not a release list: %w", err)
	}
	finals := map[int][]version{}
	n := 0
	for _, r := range raw {
		m := releaseNameRe.FindStringSubmatch(r.Name)
		if m == nil || r.PreRelease || (r.IsPublished != nil && !*r.IsPublished) {
			continue
		}
		v, ok := parseVersion(m[1])
		if !ok || !v.final() {
			continue
		}
		finals[v.minor] = append(finals[v.minor], v)
		n++
	}
	if n == 0 {
		return nil, errors.New("release list has no CPython 3 releases")
	}
	for _, vs := range finals {
		sort.Slice(vs, func(i, j int) bool { return vs[i].compare(vs[j]) < 0 })
	}
	return finals, nil
}

// parseReleaseCycle reads the 3.Y lines that are end-of-life.
func parseReleaseCycle(data []byte) (map[int]bool, error) {
	var raw map[string]struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not a release cycle: %w", err)
	}
	eol := map[int]bool{}
	lines := 0
	for k, v := range raw {
		m := cycleLineRe.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		minor, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		lines++
		if v.Status == "end-of-life" {
			eol[minor] = true
		}
	}
	if lines == 0 {
		return nil, errors.New("release cycle has no 3.Y lines")
	}
	return eol, nil
}

// newSnapshot joins the parsed datasets. records holds the parsed CVE record
// of every CVE alias of the non-withdrawn advisories.
func newSnapshot(advs []advisory, records map[string]cveInfo, finals map[int][]version, eol map[int]bool) *Snapshot {
	sn := &Snapshot{finals: finals, eol: eol}
	seen := map[string]bool{}
	for _, a := range advs {
		if a.withdrawn {
			sn.withdrawn++
			continue
		}
		for _, id := range a.cves {
			if seen[id] {
				continue // the lowest advisory ID owns a CVE
			}
			seen[id] = true
			rec := records[id]
			switch {
			case rec.rejected:
				sn.rejected++
				continue
			case !rec.ranged:
				sn.outOfScope++
				continue
			}
			title := a.summary
			if title == "" {
				title = firstSentence(a.details)
			}
			url := a.url
			if url == "" {
				url = osvURLBase + a.id
			}
			sn.cves = append(sn.cves, cveAdvisory{
				id: id, title: title, url: url, severity: rec.severity, items: rec.items,
			})
		}
	}
	sort.Slice(sn.cves, func(i, j int) bool { return sn.cves[i].id < sn.cves[j].id })
	return sn
}

// Match returns the CVEs that affect v on an image of the given OS ("linux"
// when empty), each with its status and the version that fixes it.
func (sn *Snapshot) Match(v version, osName string) []Advisory {
	var out []Advisory
	for _, c := range sn.cves {
		var ranges []versionRange
		for _, it := range c.items {
			if platformApplies(it.platforms, osName) {
				ranges = append(ranges, it.ranges...)
			}
		}
		if !anyContains(ranges, v) {
			continue
		}
		adv := Advisory{VulnID: c.id, Title: c.title, URL: c.url, Severity: c.severity}
		if fix, ok := sn.fixedIn(v, ranges); ok {
			adv.Status, adv.FixedVer = scanner.StatusFixed, fix.String()
		} else if sn.eol[v.minor] {
			adv.Status = scanner.StatusEndOfLife
		} else {
			adv.Status = scanner.StatusAffected
		}
		out = append(out, adv)
	}
	return out
}

// fixedIn is the smallest final release R of v's line above v such that R
// and every later final release of the line are outside ranges. The release
// list decides, not the ranges' bounds: an upper bound may be a
// pre-release that no final release equals. ok is false when no published
// release of the line is clear of the ranges.
func (sn *Snapshot) fixedIn(v version, ranges []versionRange) (fix version, ok bool) {
	finals := sn.finals[v.minor]
	if v.major != 3 {
		return version{}, false
	}
	for i := len(finals) - 1; i >= 0; i-- {
		r := finals[i]
		if r.compare(v) <= 0 || anyContains(ranges, r) {
			break
		}
		fix, ok = r, true
	}
	return fix, ok
}
