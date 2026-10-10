package remediation

import (
	"strings"
)

// npmRangeAllows reports whether the release version v satisfies the npm
// version range spec of a package.json dependency. evaluable is false when
// the answer cannot be given: the spec is a tag, an alias, a URL or another
// form that is not a version range, it has a pre-release bound, or v is
// itself a pre-release (which a range admits only under extra rules).
//
// It reads the grammar of node-semver ranges that package.json files use:
// alternatives separated by "||", each a set of space-separated comparators
// (exact versions, ^, ~, >, >=, <, <=, = and x-ranges such as 1.x or *) or a
// hyphen range ("1.2.3 - 2.0.0").
func npmRangeAllows(spec string, v semver) (ok, evaluable bool) {
	if v.isPrerelease() {
		return false, false
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true, true // an empty range means "*"
	}
	anyAlt := false
	for _, alt := range strings.Split(spec, "||") {
		preds, valid := rangePredicates(alt)
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
		if all {
			anyAlt = true
		}
	}
	return anyAlt, true
}

// triple is major.minor.patch as decimal strings without leading zeros.
type triple [3]string

func (a triple) cmp(b triple) int {
	for i := range a {
		if c := cmpNum(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

// predicate is one bound: op is ">=", ">", "<" or "<=".
type predicate struct {
	op  string
	val triple
}

func (p predicate) holds(v semver) bool {
	c := triple{v.major, v.minor, v.patch}.cmp(p.val)
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

// partial is a version with some parts left open ("1.2", "1.x", "*").
type partial struct {
	parts [3]string // "" for an open part
	n     int       // how many leading parts are given
}

func parsePartial(s string) (partial, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "=")
	if s == "" || strings.ContainsAny(s, "-+") {
		return partial{}, false // pre-release and build parts are not interpreted
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
		case isDigits(f) && (f == "0" || f[0] != '0'):
			if open {
				return partial{}, false // 1.x.3
			}
			p.parts[i] = f
			p.n = i + 1
		default:
			return partial{}, false
		}
	}
	return p, true
}

// low fills the open parts with zero.
func (p partial) low() triple {
	t := triple{"0", "0", "0"}
	for i := 0; i < p.n; i++ {
		t[i] = p.parts[i]
	}
	return t
}

// next is the smallest version above every version the partial covers, with
// the part at index i (0 major, 1 minor, 2 patch) raised by one and the lower
// parts zero.
func (p partial) next(i int) triple {
	t := p.low()
	t[i] = incDecimal(t[i])
	for j := i + 1; j < 3; j++ {
		t[j] = "0"
	}
	return t
}

// incDecimal adds one to a decimal string.
func incDecimal(s string) string {
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < '9' {
			b[i]++
			return string(b)
		}
		b[i] = '0'
	}
	return "1" + string(b)
}

// rangePredicates turns one "||" alternative into bounds that must all hold.
func rangePredicates(alt string) ([]predicate, bool) {
	toks := joinOperators(strings.Fields(alt))
	if len(toks) == 0 {
		return nil, true // whitespace only means "*"
	}
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
		preds, ok := comparatorPredicates(toks[i])
		if !ok {
			return nil, false
		}
		out = append(out, preds...)
	}
	return out, true
}

// joinOperators glues an operator written apart from its version (">" "1.2").
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

func comparatorPredicates(tok string) ([]predicate, bool) {
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
	if p.n == 0 { // "*"
		switch op {
		case "", "^", "~", "=", ">=", "<=":
			return nil, true
		}
		return nil, false // ">*" and "<*" match nothing sensible; not interpreted
	}
	switch op {
	case "", "=":
		if p.n == 3 {
			return []predicate{{">=", p.low()}, {"<=", p.low()}}, true
		}
		return []predicate{{">=", p.low()}, {"<", p.next(p.n - 1)}}, true
	case "^":
		// The leftmost non-zero part is fixed.
		i := 0
		for i < p.n-1 && p.parts[i] == "0" {
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

// pythonRequirement splits a PEP 508 requirement string (an entry of
// pyproject.toml dependencies) into the PEP 503 name and the version
// specifier, with its whitespace removed. ok is false for a string the plan
// does not read: a direct URL reference or a malformed specifier.
func pythonRequirement(s string) (name, constraint string, ok bool) {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	m := pipNameRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", false
	}
	rest := strings.TrimSpace(m[3])
	if strings.HasPrefix(rest, "@") {
		return "", "", false
	}
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
	if rest == "" {
		return normalizePyName(m[1]), "", true
	}
	var clauses []string
	for _, c := range strings.Split(rest, ",") {
		cm := pipClauseRE.FindStringSubmatch(strings.TrimSpace(c))
		if cm == nil {
			return "", "", false
		}
		clauses = append(clauses, cm[1]+cm[2])
	}
	return normalizePyName(m[1]), strings.Join(clauses, ","), true
}
