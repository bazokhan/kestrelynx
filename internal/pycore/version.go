package pycore

import (
	"fmt"
	"regexp"
	"strconv"
)

// Release phases in their order: a < b < rc < final.
const (
	phaseAlpha = iota
	phaseBeta
	phaseRC
	phaseFinal
)

// version is a CPython version: major.minor.micro with an optional
// pre-release marker (a1, b4, rc1), ordered as CPython orders them
// (3.15.0a1 < 3.15.0b4 < 3.15.0rc1 < 3.15.0).
type version struct {
	major, minor, micro int
	phase, pre          int
}

// maxVersionDigits bounds one version component so it always fits an int.
const maxVersionDigits = 9

var versionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:(a|b|rc)(0|[1-9][0-9]*))?$`)

// parseVersion parses a CPython version: decimal components without leading
// zeros, optionally followed by a pre-release marker.
func parseVersion(s string) (version, bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	var n [4]int
	for i, idx := range [4]int{1, 2, 3, 5} {
		if m[idx] == "" {
			continue
		}
		if len(m[idx]) > maxVersionDigits {
			return version{}, false
		}
		v, err := strconv.Atoi(m[idx])
		if err != nil {
			return version{}, false
		}
		n[i] = v
	}
	v := version{major: n[0], minor: n[1], micro: n[2], phase: phaseFinal}
	switch m[4] {
	case "a":
		v.phase, v.pre = phaseAlpha, n[3]
	case "b":
		v.phase, v.pre = phaseBeta, n[3]
	case "rc":
		v.phase, v.pre = phaseRC, n[3]
	}
	return v, true
}

func (v version) final() bool { return v.phase == phaseFinal }

func (v version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.micro)
	switch v.phase {
	case phaseAlpha:
		s += fmt.Sprintf("a%d", v.pre)
	case phaseBeta:
		s += fmt.Sprintf("b%d", v.pre)
	case phaseRC:
		s += fmt.Sprintf("rc%d", v.pre)
	}
	return s
}

// compare returns -1, 0 or 1 as v is below, equal to or above o.
func (v version) compare(o version) int {
	a := [5]int{v.major, v.minor, v.micro, v.phase, v.pre}
	b := [5]int{o.major, o.minor, o.micro, o.phase, o.pre}
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// versionRange is one affected range of a CVE: from lo (or from the start of
// time when noLower) up to hi, exclusive unless inclusive.
type versionRange struct {
	lo        version
	noLower   bool
	hi        version
	inclusive bool
}

func (r versionRange) contains(v version) bool {
	if !r.noLower && v.compare(r.lo) < 0 {
		return false
	}
	c := v.compare(r.hi)
	return c < 0 || (c == 0 && r.inclusive)
}

func anyContains(rs []versionRange, v version) bool {
	for _, r := range rs {
		if r.contains(v) {
			return true
		}
	}
	return false
}
