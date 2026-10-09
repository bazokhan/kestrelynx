package remediation

import (
	"regexp"
	"strconv"
	"strings"
)

// scheme is a version ordering: the rules of Node.js (semver) or of Python
// (a subset of PEP 440).
type scheme int

const (
	schemeSemver scheme = iota
	schemePEP440
)

// version is a parsed version of one scheme. Only versions of the same scheme
// are compared.
type version interface {
	compare(other version) int
}

// parseVersion parses s under the scheme; ok is false for anything the scheme
// does not accept, which callers treat as a reason to hand the package to a
// person rather than guess an order.
func parseVersion(sc scheme, s string) (version, bool) {
	if sc == schemePEP440 {
		v, ok := parsePEP440(s)
		return v, ok
	}
	v, ok := parseSemver(s)
	return v, ok
}

// compareVersions orders two version strings of one scheme. ok is false when
// either does not parse.
func compareVersions(sc scheme, a, b string) (cmp int, ok bool) {
	va, ok1 := parseVersion(sc, a)
	vb, ok2 := parseVersion(sc, b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return va.compare(vb), true
}

// --- semver ---

type semver struct {
	// major, minor and patch are decimal strings without leading zeros, so a
	// component of any length compares correctly and nothing overflows.
	major, minor, patch string
	pre                 []string // empty for a release
}

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// parseSemver parses a strict semantic version. Build metadata is accepted and
// ignored, as it does not take part in ordering.
func parseSemver(s string) (semver, bool) {
	m := semverRE.FindStringSubmatch(s)
	if m == nil {
		return semver{}, false
	}
	v := semver{major: m[1], minor: m[2], patch: m[3]}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
		for _, id := range v.pre {
			if isDigits(id) && len(id) > 1 && id[0] == '0' {
				return semver{}, false // numeric identifiers have no leading zero
			}
		}
	}
	return v, true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cmpNum compares two decimal strings without leading zeros (or "0") by
// length, then lexically, which is numeric order for any length.
func cmpNum(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// trimZeros drops leading zeros of a digit string, keeping "0" for zero.
func trimZeros(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

func (a semver) compare(o version) int {
	b := o.(semver)
	if c := cmpNum(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpNum(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpNum(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1 // a release is above its prereleases
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := isDigits(x), isDigits(y)
		switch {
		case xn && yn:
			if c := cmpNum(x, y); c != 0 {
				return c
			}
		case xn:
			return -1 // numeric identifiers sort below alphanumeric ones
		case yn:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpNum(strconv.Itoa(len(a.pre)), strconv.Itoa(len(b.pre)))
}

// isPrerelease reports a semver prerelease.
func (a semver) isPrerelease() bool { return len(a.pre) > 0 }

// --- PEP 440 subset ---

// pyVersion is a parsed Python version: epoch, release segments, pre-release,
// post-release, dev-release and a local label. Every number is a decimal
// string without leading zeros, so components of any length compare correctly
// and nothing overflows.
type pyVersion struct {
	epoch   string
	release []string
	preKind int // 0 a, 1 b, 2 rc; meaningful when hasPre
	preNum  string
	hasPre  bool
	postNum string
	hasPost bool
	devNum  string
	hasDev  bool
	local   []string
}

// The pattern is the one PEP 440 gives for normalizing user input.
var pep440RE = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d*))?` +
	`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?` +
	`(?:[-_.]?(dev)[-_.]?(\d*))?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// parsePEP440 parses a version in the forms PEP 440 allows, normalizing
// spelling variants (alpha, beta, c, pre, rev, r, separators).
func parsePEP440(s string) (pyVersion, bool) {
	m := pep440RE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pyVersion{}, false
	}
	v := pyVersion{epoch: trimZeros(m[1])}
	for _, seg := range strings.Split(m[2], ".") {
		v.release = append(v.release, trimZeros(seg))
	}
	if m[3] != "" {
		v.hasPre = true
		switch m[3] {
		case "a", "alpha":
			v.preKind = 0
		case "b", "beta":
			v.preKind = 1
		default:
			v.preKind = 2
		}
		v.preNum = trimZeros(m[4])
	}
	switch {
	case m[5] != "":
		v.hasPost, v.postNum = true, trimZeros(m[5])
	case m[6] != "":
		v.hasPost, v.postNum = true, trimZeros(m[7])
	}
	if m[8] != "" {
		v.hasDev, v.devNum = true, trimZeros(m[9])
	}
	if m[10] != "" {
		v.local = strings.FieldsFunc(m[10], func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	}
	return v, true
}

// isPrerelease reports a pre-release or a dev release, which pip does not
// select unless asked to.
func (v pyVersion) isPrerelease() bool { return v.hasPre || v.hasDev }

// trimmedRelease drops trailing zero segments, so 1.0 equals 1.0.0.
func (v pyVersion) trimmedRelease() []string {
	r := v.release
	for len(r) > 1 && r[len(r)-1] == "0" {
		r = r[:len(r)-1]
	}
	return r
}

// orderedNum is a segment that may be absent: below everything (rank -1), a
// value (rank 0, ordered by kind, then number) or above everything (rank 1).
type orderedNum struct {
	rank int
	kind int
	n    string
}

func cmpOrdered(a, b orderedNum) int {
	if a.rank != b.rank {
		if a.rank < b.rank {
			return -1
		}
		return 1
	}
	if a.kind != b.kind {
		if a.kind < b.kind {
			return -1
		}
		return 1
	}
	return cmpNum(a.n, b.n)
}

func (v pyVersion) preKey() orderedNum {
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		return orderedNum{rank: -1} // 1.0.dev1 sorts below 1.0a1
	case !v.hasPre:
		return orderedNum{rank: 1} // a release sorts above its pre-releases
	}
	return orderedNum{rank: 0, kind: v.preKind, n: v.preNum}
}

func (v pyVersion) postKey() orderedNum {
	if !v.hasPost {
		return orderedNum{rank: -1}
	}
	return orderedNum{rank: 0, n: v.postNum}
}

func (v pyVersion) devKey() orderedNum {
	if !v.hasDev {
		return orderedNum{rank: 1}
	}
	return orderedNum{rank: 0, n: v.devNum}
}

func (a pyVersion) compare(o version) int {
	b := o.(pyVersion)
	if c := cmpNum(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := cmpOrdered(a.preKey(), b.preKey()); c != 0 {
		return c
	}
	if c := cmpOrdered(a.postKey(), b.postKey()); c != 0 {
		return c
	}
	if c := cmpOrdered(a.devKey(), b.devKey()); c != 0 {
		return c
	}
	return cmpLocal(a.local, b.local)
}

// cmpRelease compares release segments, a missing segment counting as zero.
func cmpRelease(a, b []string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// cmpLocal orders local labels: a version without one is below any with one;
// numeric segments are above alphabetic ones.
func cmpLocal(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	case len(b) == 0:
		return 1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		xn, yn := isDigits(x), isDigits(y)
		switch {
		case xn && yn:
			if c := cmpNum(trimZeros(x), trimZeros(y)); c != 0 {
				return c
			}
		case xn:
			return 1
		case yn:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpNum(strconv.Itoa(len(a)), strconv.Itoa(len(b)))
}

// normalizePyName applies the PEP 503 name normalization: lower case, with
// runs of "-", "_" and "." collapsed to one "-".
func normalizePyName(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r == '-' || r == '_' || r == '.' {
			dash = true
			continue
		}
		if dash {
			b.WriteByte('-')
			dash = false
		}
		b.WriteRune(r)
	}
	if dash {
		b.WriteByte('-')
	}
	return b.String()
}
