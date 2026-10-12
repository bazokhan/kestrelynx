package remediation

import (
	"sort"
	"strings"
)

// A declaration of a version is a set of versions: a full version is one
// point, a partial one ("20", "20.11") is the interval it opens, and a range is
// a union of intervals. Whether declarations agree is whether the sets share a
// version. Versions are major.minor.patch releases; pre-release bounds are not
// read.

// bound is one end of an interval; open excludes the version itself.
type bound struct {
	set  bool
	v    triple
	open bool
}

// interval is the versions between lo and hi; an end that is not set is
// unbounded.
type interval struct{ lo, hi bound }

// versionSet is a union of intervals.
type versionSet []interval

// tighterLow returns the higher of two lower bounds.
func tighterLow(a, b bound) bound {
	switch {
	case !a.set:
		return b
	case !b.set:
		return a
	}
	c := a.v.cmp(b.v)
	switch {
	case c > 0:
		return a
	case c < 0:
		return b
	}
	a.open = a.open || b.open
	return a
}

// tighterHigh returns the lower of two upper bounds.
func tighterHigh(a, b bound) bound {
	switch {
	case !a.set:
		return b
	case !b.set:
		return a
	}
	c := a.v.cmp(b.v)
	switch {
	case c < 0:
		return a
	case c > 0:
		return b
	}
	a.open = a.open || b.open
	return a
}

func (iv interval) empty() bool {
	if !iv.lo.set || !iv.hi.set {
		return false
	}
	c := iv.lo.v.cmp(iv.hi.v)
	return c > 0 || (c == 0 && (iv.lo.open || iv.hi.open))
}

func (iv interval) contains(v triple) bool {
	if iv.lo.set {
		if c := v.cmp(iv.lo.v); c < 0 || (c == 0 && iv.lo.open) {
			return false
		}
	}
	if iv.hi.set {
		if c := v.cmp(iv.hi.v); c > 0 || (c == 0 && iv.hi.open) {
			return false
		}
	}
	return true
}

func (s versionSet) contains(v triple) bool {
	for _, iv := range s {
		if iv.contains(v) {
			return true
		}
	}
	return false
}

// Bounds on what a range is read from. A longer text, or one with more
// alternatives, is not read; with them a set stays small and the work to
// combine sets is bounded by the product of two small numbers.
const (
	maxRangeBytes        = 1024
	maxRangeAlternatives = 32
)

// lowBefore reports whether the lower bound a starts before b.
func lowBefore(a, b bound) bool {
	switch {
	case !a.set:
		return b.set
	case !b.set:
		return false
	}
	if c := a.v.cmp(b.v); c != 0 {
		return c < 0
	}
	return !a.open && b.open
}

// highAfter reports whether the upper bound a ends after b.
func highAfter(a, b bound) bool {
	switch {
	case !a.set:
		return b.set
	case !b.set:
		return false
	}
	if c := a.v.cmp(b.v); c != 0 {
		return c > 0
	}
	return !a.open && b.open
}

// normalize drops empty intervals and merges those that overlap or touch, so
// the result is sorted and its intervals are disjoint.
func (s versionSet) normalize() versionSet {
	ivs := make(versionSet, 0, len(s))
	for _, iv := range s {
		if !iv.empty() {
			ivs = append(ivs, iv)
		}
	}
	sort.SliceStable(ivs, func(i, j int) bool { return lowBefore(ivs[i].lo, ivs[j].lo) })
	var out versionSet
	for _, iv := range ivs {
		if n := len(out); n > 0 {
			cur := &out[n-1]
			joins := !cur.hi.set || !iv.lo.set
			if !joins {
				c := iv.lo.v.cmp(cur.hi.v)
				joins = c < 0 || (c == 0 && !(cur.hi.open && iv.lo.open))
			}
			if joins {
				if highAfter(iv.hi, cur.hi) {
					cur.hi = iv.hi
				}
				continue
			}
		}
		out = append(out, iv)
	}
	return out
}

// intersect is the versions in both sets. Both are normalized first, so the
// result has at most as many intervals as the two together.
func (s versionSet) intersect(o versionSet) versionSet {
	s, o = s.normalize(), o.normalize()
	var out versionSet
	for _, a := range s {
		for _, b := range o {
			iv := interval{tighterLow(a.lo, b.lo), tighterHigh(a.hi, b.hi)}
			if !iv.empty() {
				out = append(out, iv)
			}
		}
	}
	return out.normalize()
}

func (s versionSet) isEmpty() bool { return len(s) == 0 }

// allVersions is the set of every version.
func allVersions() versionSet { return versionSet{{}} }

// pointSet is the set of one version.
func pointSet(v triple) versionSet {
	return versionSet{{lo: bound{set: true, v: v}, hi: bound{set: true, v: v}}}
}

// partialSet is the set a partial version opens: "20" is 20.0.0 up to 21.0.0.
func partialSet(p partial) versionSet {
	if p.n == 0 {
		return allVersions()
	}
	if p.n == 3 {
		return pointSet(p.low())
	}
	return versionSet{{lo: bound{set: true, v: p.low()}, hi: bound{set: true, v: p.next(p.n - 1), open: true}}}
}

// rangeSet reads a node-semver range into a set. ok is false for text that is
// not read (a tag, a pre-release bound, ...).
func rangeSet(spec string) (versionSet, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return allVersions(), true
	}
	if len(spec) > maxRangeBytes || strings.Count(spec, "||") >= maxRangeAlternatives {
		return nil, false
	}
	var out versionSet
	for _, alt := range strings.Split(spec, "||") {
		preds, ok := rangePredicates(alt)
		if !ok {
			return nil, false
		}
		iv := interval{}
		for _, p := range preds {
			b := bound{set: true, v: p.val}
			switch p.op {
			case ">=":
				iv.lo = tighterLow(iv.lo, b)
			case ">":
				b.open = true
				iv.lo = tighterLow(iv.lo, b)
			case "<":
				b.open = true
				iv.hi = tighterHigh(iv.hi, b)
			case "<=":
				iv.hi = tighterHigh(iv.hi, b)
			default:
				return nil, false
			}
		}
		if !iv.empty() {
			out = append(out, iv)
		}
	}
	return out.normalize(), true
}

// fullVersion reads "X.Y.Z" (an optional leading "v" or "=" allowed) as one
// version; ok is false for anything else.
func fullVersion(s string) (triple, bool) {
	p, ok := parsePartial(strings.TrimSpace(s))
	if !ok || p.n != 3 {
		return triple{}, false
	}
	return p.low(), true
}
