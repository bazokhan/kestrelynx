package toolfetch

import (
	"strconv"
	"strings"
)

// version is major.minor.patch of a release.
type version [3]int64

func (a version) cmp(b version) int {
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

func (a version) String() string {
	return strconv.FormatInt(a[0], 10) + "." + strconv.FormatInt(a[1], 10) + "." + strconv.FormatInt(a[2], 10)
}

// parseExact reads "X.Y.Z" made of plain decimal numbers; anything else
// (a pre-release, build metadata, a prefix, leading zeros) is not an exact
// release version.
func parseExact(s string) (version, bool) {
	fields := strings.Split(s, ".")
	if len(fields) != 3 {
		return version{}, false
	}
	var v version
	for i, f := range fields {
		n, ok := decimal(f)
		if !ok {
			return version{}, false
		}
		v[i] = n
	}
	return v, true
}

func decimal(f string) (int64, bool) {
	if f == "" || len(f) > 9 || (len(f) > 1 && f[0] == '0') {
		return 0, false
	}
	for _, c := range f {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(f, 10, 64)
	return n, err == nil
}

// predicate is one bound of a range: op is ">=", ">", "<" or "<=".
type predicate struct {
	op  string
	val version
}

func (p predicate) holds(v version) bool {
	c := v.cmp(p.val)
	switch p.op {
	case ">=":
		return c >= 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	}
	return false
}

// rangeAllows reports whether the release v satisfies a node-semver range as
// engines.node writes it: alternatives separated by "||", each a set of
// comparators (exact versions, ^, ~, >, >=, <, <=, = and x-ranges) or a hyphen
// range. ok is false when the text cannot be read, which includes pre-release
// bounds.
func rangeAllows(spec string, v version) (allowed, ok bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true, true
	}
	found := false
	for _, alt := range strings.Split(spec, "||") {
		preds, valid := altPredicates(alt)
		if !valid {
			return false, false
		}
		all := true
		for _, p := range preds {
			if !p.holds(v) {
				all = false
				break
			}
		}
		found = found || all
	}
	return found, true
}

type partial struct {
	parts [3]int64
	n     int // how many leading parts are given
}

func parsePartial(s string) (partial, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "=")
	if s == "" || strings.ContainsAny(s, "-+") {
		return partial{}, false
	}
	fields := strings.Split(s, ".")
	if len(fields) > 3 {
		return partial{}, false
	}
	var p partial
	open := false
	for i, f := range fields {
		switch {
		case f == "x" || f == "X" || f == "*":
			open = true
		default:
			n, ok := decimal(f)
			if !ok || open {
				return partial{}, false
			}
			p.parts[i] = n
			p.n = i + 1
		}
	}
	return p, true
}

func (p partial) low() version { return version{p.parts[0], p.parts[1], p.parts[2]} }

// next raises the part at index i by one and zeroes the lower parts.
func (p partial) next(i int) version {
	v := p.low()
	v[i]++
	for j := i + 1; j < 3; j++ {
		v[j] = 0
	}
	return v
}

func altPredicates(alt string) ([]predicate, bool) {
	toks := joinOperators(strings.Fields(alt))
	var out []predicate
	for i := 0; i < len(toks); i++ {
		if i+2 < len(toks) && toks[i+1] == "-" {
			lo, ok1 := parsePartial(toks[i])
			hi, ok2 := parsePartial(toks[i+2])
			if !ok1 || !ok2 {
				return nil, false
			}
			out = append(out, predicate{">=", lo.low()})
			switch hi.n {
			case 3:
				out = append(out, predicate{"<=", hi.low()})
			case 0:
			default:
				out = append(out, predicate{"<", hi.next(hi.n - 1)})
			}
			i += 2
			continue
		}
		preds, ok := comparator(toks[i])
		if !ok {
			return nil, false
		}
		out = append(out, preds...)
	}
	return out, true
}

func joinOperators(toks []string) []string {
	var out []string
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "^", "~", "~>", ">", "<", "=", ">=", "<=":
			if i+1 < len(toks) {
				out = append(out, toks[i]+toks[i+1])
				i++
				continue
			}
		}
		out = append(out, toks[i])
	}
	return out
}

func comparator(tok string) ([]predicate, bool) {
	op := ""
	for _, o := range []string{">=", "<=", "~>", ">", "<", "^", "~", "="} {
		if strings.HasPrefix(tok, o) {
			op, tok = o, tok[len(o):]
			break
		}
	}
	if op == "~>" {
		op = "~"
	}
	p, ok := parsePartial(tok)
	if !ok {
		return nil, false
	}
	if p.n == 0 {
		switch op {
		case "", "^", "~", "=", ">=", "<=":
			return nil, true
		}
		return nil, false
	}
	switch op {
	case "", "=":
		if p.n == 3 {
			return []predicate{{">=", p.low()}, {"<=", p.low()}}, true
		}
		return []predicate{{">=", p.low()}, {"<", p.next(p.n - 1)}}, true
	case "^":
		i := 0
		for i < p.n-1 && p.parts[i] == 0 {
			i++
		}
		return []predicate{{">=", p.low()}, {"<", p.next(i)}}, true
	case "~":
		i := 1
		if p.n == 1 {
			i = 0
		}
		return []predicate{{">=", p.low()}, {"<", p.next(i)}}, true
	case ">=":
		return []predicate{{">=", p.low()}}, true
	case ">":
		if p.n == 3 {
			return []predicate{{">", p.low()}}, true
		}
		return []predicate{{">=", p.next(p.n - 1)}}, true
	case "<":
		return []predicate{{"<", p.low()}}, true
	case "<=":
		if p.n == 3 {
			return []predicate{{"<=", p.low()}}, true
		}
		return []predicate{{"<", p.next(p.n - 1)}}, true
	}
	return nil, false
}
