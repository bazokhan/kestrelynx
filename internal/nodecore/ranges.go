package nodecore

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// version is a Node.js version as major, minor, patch.
type version [3]int

// maxVersionDigits bounds one version component so it always fits an int.
const maxVersionDigits = 9

var exactVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// parseVersion parses a plain X.Y.Z decimal version: no prefix, no suffix and
// no leading zeros.
func parseVersion(s string) (version, bool) {
	m := exactVersionRe.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	var v version
	for i := range v {
		if len(m[i+1]) > maxVersionDigits {
			return version{}, false
		}
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return version{}, false
		}
		v[i] = n
	}
	return v, true
}

func (v version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// compare returns -1, 0 or 1 as v is below, equal to or above o.
func (v version) compare(o version) int {
	for i := range v {
		switch {
		case v[i] < o[i]:
			return -1
		case v[i] > o[i]:
			return 1
		}
	}
	return 0
}

// interval is the half-open version interval [lo, hi), or [lo, inf) when
// unbounded. Every comparator of the supported range grammar describes one.
type interval struct {
	lo        version
	hi        version
	unbounded bool
}

func (iv interval) empty() bool {
	return !iv.unbounded && iv.lo.compare(iv.hi) >= 0
}

func (iv interval) contains(v version) bool {
	if v.compare(iv.lo) < 0 {
		return false
	}
	return iv.unbounded || v.compare(iv.hi) < 0
}

func (iv interval) intersect(o interval) interval {
	r := iv
	if o.lo.compare(r.lo) > 0 {
		r.lo = o.lo
	}
	switch {
	case iv.unbounded:
		r.hi, r.unbounded = o.hi, o.unbounded
	case !o.unbounded && o.hi.compare(iv.hi) < 0:
		r.hi = o.hi
	}
	return r
}

// touchesMajor reports whether the interval contains any version of major m.
func (iv interval) touchesMajor(m int) bool {
	if iv.empty() {
		return false
	}
	return !iv.intersect(interval{lo: version{m, 0, 0}, hi: version{m + 1, 0, 0}}).empty()
}

// versionRange is an OR of intervals: the parsed form of an npm-style range.
type versionRange []interval

func (r versionRange) contains(v version) bool {
	for _, iv := range r {
		if iv.contains(v) {
			return true
		}
	}
	return false
}

func (r versionRange) touchesMajor(m int) bool {
	for _, iv := range r {
		if iv.touchesMajor(m) {
			return true
		}
	}
	return false
}

// lowerBounds are the lower bounds of the non-empty alternatives.
func (r versionRange) lowerBounds() []version {
	var out []version
	for _, iv := range r {
		if !iv.empty() {
			out = append(out, iv.lo)
		}
	}
	return out
}

var operatorSpaceRe = regexp.MustCompile(`(>=|<=|>|<|=|\^)\s+`)

// parseRange parses the npm range subset security-wg uses: exact versions,
// x-ranges and partials (N, N.x, N.M, N.M.x), caret ranges, the comparators
// >=, >, <=, < and =, whitespace-separated AND, and ||. With patched set, an
// alternative that is a bare exact version X.Y.Z means ">=X.Y.Z <(X+1).0.0":
// a patched list names the release that fixed a line, and every later
// release of that line is fixed too.
func parseRange(s string, patched bool) (versionRange, error) {
	var out versionRange
	for _, alt := range strings.Split(s, "||") {
		iv, err := parseAlternative(alt, patched)
		if err != nil {
			return nil, fmt.Errorf("range %q: %w", s, err)
		}
		out = append(out, iv)
	}
	return out, nil
}

func parseAlternative(s string, patched bool) (interval, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return interval{}, fmt.Errorf("empty alternative")
	}
	if patched {
		if v, ok := parseVersion(s); ok {
			return interval{lo: v, hi: version{v[0] + 1, 0, 0}}, nil
		}
	}
	iv := interval{unbounded: true}
	for _, tok := range strings.Fields(operatorSpaceRe.ReplaceAllString(s, "$1")) {
		c, err := parseComparator(tok)
		if err != nil {
			return interval{}, err
		}
		iv = iv.intersect(c)
	}
	return iv, nil
}

// parseComparator parses one operator-prefixed (possibly partial) version.
func parseComparator(tok string) (interval, error) {
	op := ""
	for _, o := range []string{">=", "<=", ">", "<", "=", "^"} {
		if strings.HasPrefix(tok, o) {
			op = o
			break
		}
	}
	rest := tok[len(op):]
	parts := strings.Split(rest, ".")
	if rest == "" || len(parts) > 3 {
		return interval{}, fmt.Errorf("bad version %q", tok)
	}
	var nums []int
	wild := false
	for _, p := range parts {
		if p == "x" || p == "X" || p == "*" {
			wild = true
			continue
		}
		if wild || len(p) > maxVersionDigits || !isDecimal(p) {
			return interval{}, fmt.Errorf("bad version %q", tok)
		}
		n, _ := strconv.Atoi(p)
		nums = append(nums, n)
	}

	var lo version
	copy(lo[:], nums)
	p := len(nums)
	next := lo // lo with its last specified component incremented
	if p > 0 {
		next[p-1]++
		for i := p; i < 3; i++ {
			next[i] = 0
		}
	}
	all := interval{unbounded: true}

	switch op {
	case "", "=":
		if p == 0 {
			return all, nil
		}
		return interval{lo: lo, hi: next}, nil
	case ">=":
		return interval{lo: lo, unbounded: true}, nil
	case ">":
		if p == 0 {
			return interval{}, fmt.Errorf("bad version %q", tok)
		}
		return interval{lo: next, unbounded: true}, nil
	case "<=":
		if p == 0 {
			return all, nil
		}
		return interval{hi: next}, nil
	case "<":
		if p == 0 {
			return interval{}, fmt.Errorf("bad version %q", tok)
		}
		return interval{hi: lo}, nil
	default: // "^"
		if p == 0 {
			return all, nil
		}
		var hi version
		switch {
		case lo[0] > 0 || p == 1:
			hi = version{lo[0] + 1, 0, 0}
		case lo[1] > 0 || p == 2:
			hi = version{0, lo[1] + 1, 0}
		default:
			hi = version{0, 0, lo[2] + 1}
		}
		return interval{lo: lo, hi: hi}, nil
	}
}

func isDecimal(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
