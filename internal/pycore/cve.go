package pycore

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	cnaVendor  = "Python Software Foundation"
	cnaProduct = "CPython"
)

// cveInfo is what the matching uses of one CVE record.
type cveInfo struct {
	rejected bool
	// ranged is true when the CNA gave CPython version ranges. A CVE
	// without them is out of scope.
	ranged   bool
	severity string // upper case; "UNKNOWN" when the record gave none
	items    []rangeItem
}

// rangeItem is one CNA affected item with CPython ranges, with the
// platforms it is limited to (none = every OS).
type rangeItem struct {
	platforms []string
	ranges    []versionRange
}

type rawCVE struct {
	CVEMetadata struct {
		CVEID string `json:"cveId"`
		State string `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Affected []rawAffected `json:"affected"`
			Metrics  []rawMetric   `json:"metrics"`
		} `json:"cna"`
		ADP []struct {
			Metrics []rawMetric `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

type rawAffected struct {
	Vendor    string       `json:"vendor"`
	Product   string       `json:"product"`
	Platforms []string     `json:"platforms"`
	Versions  []rawVersion `json:"versions"`
}

type rawVersion struct {
	Version         string          `json:"version"`
	LessThan        string          `json:"lessThan"`
	LessThanOrEqual string          `json:"lessThanOrEqual"`
	Status          string          `json:"status"`
	VersionType     string          `json:"versionType"`
	Changes         json.RawMessage `json:"changes"`
}

type rawMetric struct {
	V4  *rawScore `json:"cvssV4_0"`
	V31 *rawScore `json:"cvssV3_1"`
	V30 *rawScore `json:"cvssV3_0"`
}

type rawScore struct {
	BaseSeverity string `json:"baseSeverity"`
}

// checkCVERecord is the download-time validation of a record: it must be a
// complete CVE record for the CVE that was asked for. A published record
// always carries the CNA's affected list, so one without it is a truncated
// or broken download, not a CVE without ranges. Whether its ranges can be
// evaluated is decided by parseCVE, so a record that cannot be evaluated is
// not mistaken for a bad download.
func checkCVERecord(cve string, data []byte) error {
	var raw rawCVE
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("not a CVE record: %w", err)
	}
	if raw.CVEMetadata.CVEID != cve {
		return fmt.Errorf("record is for %q, want %s", raw.CVEMetadata.CVEID, cve)
	}
	switch {
	case strings.EqualFold(raw.CVEMetadata.State, "REJECTED"):
		return nil
	case !strings.EqualFold(raw.CVEMetadata.State, "PUBLISHED"):
		return fmt.Errorf("record state is %q", raw.CVEMetadata.State)
	case len(raw.Containers.CNA.Affected) == 0:
		return fmt.Errorf("published record has no CNA affected list")
	}
	return nil
}

// hasCPythonRanges reports whether a published record has a CPython item of
// the CNA with an upper-bounded version, whether or not its ranges can be
// evaluated: losing them must be noticed even after a record that could not
// be evaluated was cached.
func hasCPythonRanges(data []byte) bool {
	var raw rawCVE
	if json.Unmarshal(data, &raw) != nil || strings.EqualFold(raw.CVEMetadata.State, "REJECTED") {
		return false
	}
	for _, a := range raw.Containers.CNA.Affected {
		if a.Vendor != cnaVendor || a.Product != cnaProduct {
			continue
		}
		for _, v := range a.Versions {
			if v.LessThan != "" || v.LessThanOrEqual != "" {
				return true
			}
		}
	}
	return false
}

// isRejected reports whether data is a record of a rejected CVE.
func isRejected(data []byte) bool {
	var raw rawCVE
	return json.Unmarshal(data, &raw) == nil && strings.EqualFold(raw.CVEMetadata.State, "REJECTED")
}

// parseCVE reads the CNA's CPython ranges, the severity and the state out of
// a CVE record. An error means a CPython range this package cannot evaluate:
// skipping it would make a detected CVE disappear and look resolved, so the
// caller must not match at all.
func parseCVE(cve string, data []byte) (cveInfo, error) {
	var raw rawCVE
	if err := json.Unmarshal(data, &raw); err != nil {
		return cveInfo{}, fmt.Errorf("%s: not a CVE record: %w", cve, err)
	}
	if raw.CVEMetadata.CVEID != cve {
		return cveInfo{}, fmt.Errorf("%s: record is for %q", cve, raw.CVEMetadata.CVEID)
	}
	info := cveInfo{severity: "UNKNOWN"}
	if strings.EqualFold(raw.CVEMetadata.State, "REJECTED") {
		info.rejected = true
		return info, nil
	}
	for _, a := range raw.Containers.CNA.Affected {
		if a.Vendor != cnaVendor || a.Product != cnaProduct {
			continue
		}
		item, ranged, err := parseItem(a)
		if err != nil {
			return cveInfo{}, fmt.Errorf("%s: %w", cve, err)
		}
		if !ranged {
			continue
		}
		info.ranged = true
		info.items = append(info.items, item)
	}
	info.severity = severityOf(raw)
	return info, nil
}

// parseItem reads one CPython affected item. ranged is false when none of its
// versions has an upper bound.
func parseItem(a rawAffected) (item rangeItem, ranged bool, err error) {
	for _, v := range a.Versions {
		if v.LessThan != "" || v.LessThanOrEqual != "" {
			ranged = true
			break
		}
	}
	if !ranged {
		return rangeItem{}, false, nil
	}
	item.platforms = a.Platforms
	for _, v := range a.Versions {
		if len(v.Changes) > 0 {
			return rangeItem{}, false, fmt.Errorf("affected version %q has changes, which cannot be evaluated", v.Version)
		}
		switch v.VersionType {
		case "", "python", "custom":
		default:
			return rangeItem{}, false, fmt.Errorf("affected version %q has unknown versionType %q", v.Version, v.VersionType)
		}
		hasUpper := v.LessThan != "" || v.LessThanOrEqual != ""
		if v.Status != "affected" {
			if hasUpper {
				return rangeItem{}, false, fmt.Errorf("range from %q has status %q, which cannot be evaluated", v.Version, v.Status)
			}
			continue
		}
		var r versionRange
		if v.Version == "0" {
			r.noLower = true
		} else {
			lo, ok := parseVersion(v.Version)
			if !ok {
				return rangeItem{}, false, fmt.Errorf("lower bound %q is not a CPython version", v.Version)
			}
			r.lo = lo
		}
		switch {
		case v.LessThan != "" && v.LessThanOrEqual != "":
			return rangeItem{}, false, fmt.Errorf("range from %q has two upper bounds", v.Version)
		case v.LessThan != "":
			hi, ok := parseVersion(v.LessThan)
			if !ok {
				return rangeItem{}, false, fmt.Errorf("upper bound %q is not a CPython version", v.LessThan)
			}
			r.hi = hi
		case v.LessThanOrEqual != "":
			hi, ok := parseVersion(v.LessThanOrEqual)
			if !ok {
				return rangeItem{}, false, fmt.Errorf("upper bound %q is not a CPython version", v.LessThanOrEqual)
			}
			r.hi, r.inclusive = hi, true
		default:
			// A single affected version.
			if r.noLower {
				return rangeItem{}, false, fmt.Errorf("version %q without an upper bound cannot be evaluated", v.Version)
			}
			r.hi, r.inclusive = r.lo, true
		}
		item.ranges = append(item.ranges, r)
	}
	return item, true, nil
}

// severityOf is the CNA's CVSS severity (4.0, then 3.1, then 3.0), else the
// first ADP metric that has one, else UNKNOWN.
func severityOf(raw rawCVE) string {
	if s := firstSeverity(raw.Containers.CNA.Metrics); s != "" {
		return s
	}
	for _, adp := range raw.Containers.ADP {
		if s := firstSeverity(adp.Metrics); s != "" {
			return s
		}
	}
	return "UNKNOWN"
}

// firstSeverity is the severity of the first metric that carries one,
// preferring CVSS 4.0, then 3.1, then 3.0 across the list.
func firstSeverity(metrics []rawMetric) string {
	pick := func(get func(rawMetric) *rawScore) string {
		for _, m := range metrics {
			if sc := get(m); sc != nil {
				if s := strings.ToUpper(strings.TrimSpace(sc.BaseSeverity)); s != "" {
					return s
				}
			}
		}
		return ""
	}
	for _, get := range []func(rawMetric) *rawScore{
		func(m rawMetric) *rawScore { return m.V4 },
		func(m rawMetric) *rawScore { return m.V31 },
		func(m rawMetric) *rawScore { return m.V30 },
	} {
		if s := pick(get); s != "" {
			return s
		}
	}
	return ""
}

// knownOtherOS are the platform names that are not Linux.
var knownOtherOS = map[string]bool{
	"windows": true, "macos": true, "ios": true,
	"android": true, "wasi": true, "emscripten": true,
}

// platformApplies reports whether an item limited to platforms applies to an
// image of the given OS ("linux" for an empty one). No platforms means every
// OS; an unknown platform name never rules the item out.
func platformApplies(platforms []string, osName string) bool {
	if len(platforms) == 0 {
		return true
	}
	osName = strings.ToLower(strings.TrimSpace(osName))
	if osName == "" {
		osName = "linux"
	}
	for _, p := range platforms {
		p = strings.ToLower(strings.TrimSpace(p))
		linuxLike := strings.Contains(p, "linux") || strings.Contains(p, "posix") || strings.Contains(p, "unix")
		switch {
		case !linuxLike && !knownOtherOS[p]:
			return true // unknown value: not ruled out
		case osName == "linux" && linuxLike, osName != "linux" && p == osName:
			return true
		}
	}
	return false
}
