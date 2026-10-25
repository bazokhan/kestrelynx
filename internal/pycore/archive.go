package pycore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Limits on the PSF advisory archive. The real one is about 120 KB with
// 200 advisories; anything past these is not an archive this package can
// trust, so the list is unusable rather than truncated.
const (
	maxArchiveBytes      = 16 << 20 // compressed
	maxArchiveTotalBytes = 64 << 20 // uncompressed, all entries
	maxArchiveEntries    = 20000
	maxAdvisoryBytes     = 1 << 20
	maxAdvisories        = 2000
	maxAliases           = 32
)

var (
	advisoryIDRe   = regexp.MustCompile(`^PSF-[0-9]{4}-[0-9]{1,6}$`)
	advisoryFileRe = regexp.MustCompile(`^(PSF-[0-9]{4}-[0-9]{1,6})\.json$`)
	cveIDRe        = regexp.MustCompile(`^CVE-([0-9]{4})-([0-9]{4,8})$`)
)

// advisory is one PSF advisory, reduced to what the matching uses.
type advisory struct {
	id        string
	cves      []string // CVE aliases, in the advisory's order
	summary   string
	details   string
	url       string // the ADVISORY reference, empty when there is none
	withdrawn bool
}

type rawAdvisory struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	Withdrawn  string   `json:"withdrawn"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// errLimit is returned when the archive's uncompressed size passes its cap.
var errLimit = errors.New("archive larger than the uncompressed limit")

// capReader fails, instead of silently ending, once more than n bytes have
// been read through it.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n < 0 {
		return 0, errLimit
	}
	if int64(len(p)) > c.n+1 {
		p = p[:c.n+1]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	if c.n < 0 {
		return n, errLimit
	}
	return n, err
}

// parseArchive reads the advisories out of a gzip-compressed tar stream
// without extracting anything to disk. Only regular files named
// <root>/advisories/python/PSF-<year>-<n>.json are read; links, special
// files and every other path are skipped. The result is sorted by ID.
func parseArchive(data []byte) ([]advisory, error) {
	if len(data) > maxArchiveBytes {
		return nil, fmt.Errorf("archive larger than %d bytes", maxArchiveBytes)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&capReader{r: gz, n: maxArchiveTotalBytes})

	var out []advisory
	seen := map[string]bool{}
	root := ""
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		entries++
		if entries > maxArchiveEntries {
			return nil, fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(hdr.Name, "./"), "/")
		if len(parts) != 4 || parts[0] == "" || parts[0] == "." || parts[0] == ".." ||
			parts[1] != "advisories" || parts[2] != "python" {
			continue
		}
		m := advisoryFileRe.FindStringSubmatch(parts[3])
		if m == nil {
			continue
		}
		if root == "" {
			root = parts[0]
		} else if parts[0] != root {
			return nil, fmt.Errorf("archive has more than one root directory (%q, %q)", root, parts[0])
		}
		if hdr.Size > maxAdvisoryBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", hdr.Name, maxAdvisoryBytes)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		if len(body) > maxAdvisoryBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", hdr.Name, maxAdvisoryBytes)
		}
		if seen[m[1]] {
			return nil, fmt.Errorf("duplicate advisory %s", m[1])
		}
		seen[m[1]] = true
		if len(out) >= maxAdvisories {
			return nil, fmt.Errorf("archive has more than %d advisories", maxAdvisories)
		}
		adv, err := parseAdvisory(m[1], body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		out = append(out, adv)
	}
	if len(out) == 0 {
		return nil, errors.New("archive has no advisories")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// parseAdvisory parses one advisory file; its ID must be the file's name.
func parseAdvisory(fileID string, data []byte) (advisory, error) {
	var raw rawAdvisory
	if err := json.Unmarshal(data, &raw); err != nil {
		return advisory{}, fmt.Errorf("invalid advisory: %w", err)
	}
	if !advisoryIDRe.MatchString(raw.ID) || raw.ID != fileID {
		return advisory{}, fmt.Errorf("advisory id %q does not match file name %s", raw.ID, fileID)
	}
	if len(raw.Aliases) > maxAliases {
		return advisory{}, fmt.Errorf("advisory %s has more than %d aliases", raw.ID, maxAliases)
	}
	adv := advisory{
		id:        raw.ID,
		summary:   strings.TrimSpace(raw.Summary),
		details:   strings.TrimSpace(raw.Details),
		withdrawn: raw.Withdrawn != "",
	}
	seen := map[string]bool{}
	for _, a := range raw.Aliases {
		if cveIDRe.MatchString(a) && !seen[a] {
			seen[a] = true
			adv.cves = append(adv.cves, a)
		}
	}
	for _, r := range raw.References {
		if r.Type == "ADVISORY" && r.URL != "" {
			adv.url = r.URL
			break
		}
	}
	return adv, nil
}

// advisoryIDs is the set of IDs in an archive, for the check that a new
// archive has not dropped any advisory the previous one had.
func advisoryIDs(advs []advisory) map[string]bool {
	ids := make(map[string]bool, len(advs))
	for _, a := range advs {
		ids[a.id] = true
	}
	return ids
}

// firstSentence is the text of s up to its first sentence end or paragraph
// end. Advisory details are often hard-wrapped, so a single line break is
// read as a space rather than as the end of the sentence.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i+1]
	}
	return strings.TrimSpace(s)
}
