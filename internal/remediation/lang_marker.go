package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// markerEnv is the environment PEP 508 markers are evaluated in: the one pip
// resolves for. Only what that environment fixes is known:
//
//   - python_version is X.Y; python_full_version and implementation_version
//     are known only as X.Y.something, so a comparison on them is decided only
//     when it comes out the same for every patch level;
//   - sys_platform is linux, platform_system Linux, os_name posix,
//     platform_machine the architecture, implementation_name cpython and
//     platform_python_implementation CPython;
//   - extra: a marker is evaluated once for each extra that was asked for, with
//     extra bound to that one name, and once with no extra; the requirement is in
//     force if any of those evaluations is true (the way pip reads a marker that
//     mentions extra);
//   - platform_release, platform_version and any other variable are unknown.
//
// A marker that cannot be decided is an error, never a guess.
type markerEnv struct {
	pyMinor string // "3.12"
	machine string // "x86_64" or "aarch64"
	extras  map[string]bool
	// extra is the one extra a single evaluation is bound to.
	extra string
	// budget, when set, counts every evaluation (one per extra binding) and
	// watches the deadline.
	budget *markerBudget
	// pythonOnly makes every variable but python_version and
	// python_full_version unknown: the environment is any one that runs this
	// Python (a lockfile that holds every platform at once).
	pythonOnly bool
}

// markerBudget bounds the evaluations of markers in one piece of work.
type markerBudget struct {
	ctx   context.Context
	evals int
	max   int
	// toks holds the tokens of the markers read so far, by marker text, so
	// that a marker met again is not scanned again.
	toks map[string][]markerTok
}

// Bounds on one marker: its size and its number of tokens. A larger one is
// not read.
const (
	maxMarkerBytes  = 4096
	maxMarkerTokens = 512
)

// tokens returns the tokens of a marker, from the cache when there is one.
func (b *markerBudget) tokens(marker string) ([]markerTok, error) {
	if b != nil {
		if t, ok := b.toks[marker]; ok {
			return t, nil
		}
	}
	t, err := markerTokens(marker)
	if err != nil {
		return nil, err
	}
	if b != nil {
		if b.toks == nil {
			b.toks = map[string][]markerTok{}
		}
		b.toks[marker] = t
	}
	return t, nil
}

// errMarkerBudget: the work needed more marker evaluations than it may.
var errMarkerBudget = errors.New("the marker evaluations of the update are over their budget")

func (b *markerBudget) spend() error {
	if b.evals++; b.evals > b.max {
		return errMarkerBudget
	}
	return b.ctx.Err()
}

var errMarkerUnknown = errors.New("the marker cannot be decided for this environment")

type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// eval decides a marker: true if it is true for any of the extras asked for
// (or for none), false if it is false for all of them, an error if some
// evaluation cannot be decided and none is true.
func (e markerEnv) eval(marker string) (bool, error) {
	toks, err := e.budget.tokens(marker)
	if err != nil {
		return false, err
	}
	bindings := make([]string, 0, len(e.extras)+1)
	for x := range e.extras {
		bindings = append(bindings, x)
	}
	sort.Strings(bindings)
	bindings = append(bindings, "")
	unknown := false
	for _, x := range bindings {
		if e.budget != nil {
			if err := e.budget.spend(); err != nil {
				return false, err
			}
		}
		env := e
		env.extra = x
		p := &markerParser{toks: toks, env: env}
		v, err := p.or()
		if err != nil {
			return false, err
		}
		if p.pos != len(p.toks) {
			return false, fmt.Errorf("marker %q has trailing text", marker)
		}
		switch v {
		case triTrue:
			return true, nil
		case triUnknown:
			unknown = true
		}
	}
	if unknown {
		return false, fmt.Errorf("marker %q: %w", marker, errMarkerUnknown)
	}
	return false, nil
}

type markerTok struct {
	kind string // "str", "word", "op", "(", ")"
	val  string
}

func markerTokens(s string) ([]markerTok, error) {
	if len(s) > maxMarkerBytes {
		return nil, fmt.Errorf("a marker is over %d bytes", maxMarkerBytes)
	}
	var out []markerTok
	for i := 0; i < len(s); {
		if len(out) > maxMarkerTokens {
			return nil, fmt.Errorf("a marker has over %d tokens", maxMarkerTokens)
		}
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			out = append(out, markerTok{string(c), string(c)})
			i++
		case c == '"' || c == '\'':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return nil, fmt.Errorf("marker %q has an unterminated string", s)
			}
			out = append(out, markerTok{"str", s[i+1 : i+1+j]})
			i += j + 2
		case strings.ContainsRune("=!<>~", rune(c)):
			j := i
			for j < len(s) && strings.ContainsRune("=!<>~", rune(s[j])) {
				j++
			}
			out = append(out, markerTok{"op", s[i:j]})
			i = j
		case c == '_' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			out = append(out, markerTok{"word", s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("marker %q has the character %q", s, c)
		}
	}
	return out, nil
}

type markerParser struct {
	toks  []markerTok
	pos   int
	env   markerEnv
	depth int
}

func (p *markerParser) peek() markerTok {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return markerTok{}
}

func (p *markerParser) or() (tri, error) {
	l, err := p.and()
	if err != nil {
		return 0, err
	}
	for p.peek().kind == "word" && p.peek().val == "or" {
		p.pos++
		r, err := p.and()
		if err != nil {
			return 0, err
		}
		switch {
		case l == triTrue || r == triTrue:
			l = triTrue
		case l == triUnknown || r == triUnknown:
			l = triUnknown
		default:
			l = triFalse
		}
	}
	return l, nil
}

func (p *markerParser) and() (tri, error) {
	l, err := p.atom()
	if err != nil {
		return 0, err
	}
	for p.peek().kind == "word" && p.peek().val == "and" {
		p.pos++
		r, err := p.atom()
		if err != nil {
			return 0, err
		}
		switch {
		case l == triFalse || r == triFalse:
			l = triFalse
		case l == triUnknown || r == triUnknown:
			l = triUnknown
		default:
			l = triTrue
		}
	}
	return l, nil
}

func (p *markerParser) atom() (tri, error) {
	if p.peek().kind == "(" {
		if p.depth++; p.depth > 32 {
			return 0, errors.New("marker nests too deeply")
		}
		p.pos++
		v, err := p.or()
		if err != nil {
			return 0, err
		}
		if p.peek().kind != ")" {
			return 0, errors.New("marker has an unclosed parenthesis")
		}
		p.pos++
		p.depth--
		return v, nil
	}
	left, ok := p.operand()
	if !ok {
		return 0, errors.New("marker has no operand where one is expected")
	}
	op, ok := p.operator()
	if !ok {
		return 0, errors.New("marker has no comparison operator where one is expected")
	}
	right, ok := p.operand()
	if !ok {
		return 0, errors.New("marker has no operand where one is expected")
	}
	return p.env.compare(left, op, right), nil
}

// operand is a variable or a quoted string.
type markerOperand struct {
	variable bool
	name     string
	literal  string
}

func (p *markerParser) operand() (markerOperand, bool) {
	t := p.peek()
	switch t.kind {
	case "str":
		p.pos++
		return markerOperand{literal: t.val}, true
	case "word":
		if t.val == "and" || t.val == "or" || t.val == "in" || t.val == "not" {
			return markerOperand{}, false
		}
		p.pos++
		return markerOperand{variable: true, name: t.val}, true
	}
	return markerOperand{}, false
}

func (p *markerParser) operator() (string, bool) {
	t := p.peek()
	switch {
	case t.kind == "op":
		switch t.val {
		case "==", "!=", "<", "<=", ">", ">=", "~=", "===":
			p.pos++
			return t.val, true
		}
	case t.kind == "word" && t.val == "in":
		p.pos++
		return "in", true
	case t.kind == "word" && t.val == "not":
		if p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == "word" && p.toks[p.pos+1].val == "in" {
			p.pos += 2
			return "not in", true
		}
	}
	return "", false
}

// values returns the values a variable can have in the environment: one,
// or the samples of a version known only up to its minor. known is false for
// a variable the environment does not fix.
func (e markerEnv) values(name string) (vals []string, known bool) {
	if e.pythonOnly && name != "python_version" && name != "python_full_version" {
		return nil, false
	}
	switch name {
	case "python_version":
		return []string{e.pyMinor}, true
	case "python_full_version", "implementation_version":
		return []string{e.pyMinor + ".0", e.pyMinor + ".9999"}, true
	case "sys_platform":
		return []string{"linux"}, true
	case "platform_system":
		return []string{"Linux"}, true
	case "os_name":
		return []string{"posix"}, true
	case "platform_machine":
		return []string{e.machine}, true
	case "implementation_name":
		return []string{"cpython"}, true
	case "platform_python_implementation":
		return []string{"CPython"}, true
	}
	return nil, false
}

var flipOp = map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!=", "===": "===", "~=": "~=", "in": "in", "not in": "not in"}

func (e markerEnv) compare(l markerOperand, op string, r markerOperand) tri {
	if l.variable && l.name == "extra" || r.variable && r.name == "extra" {
		return e.compareExtra(l, op, r)
	}
	if l.variable == r.variable {
		// Two literals or two variables are not a form markers use.
		return triUnknown
	}
	if l.variable {
		return e.compareVar(l.name, op, r.literal, false)
	}
	return e.compareVar(r.name, op, l.literal, true)
}

func normExtra(s string) string { return normalizePyName(s) }

func (e markerEnv) compareExtra(l markerOperand, op string, r markerOperand) tri {
	lit := l.literal
	if l.variable {
		lit = r.literal
	}
	if l.variable == r.variable || (op != "==" && op != "!=") {
		return triUnknown
	}
	has := e.extra != "" && normExtra(e.extra) == normExtra(lit)
	if op == "==" {
		return triOf(has)
	}
	return triOf(!has)
}

// compareVar compares a variable with a literal; swapped means the literal
// was written on the left.
func (e markerEnv) compareVar(name, op, lit string, swapped bool) tri {
	vals, known := e.values(name)
	if !known {
		return triUnknown
	}
	if name == "python_full_version" || name == "implementation_version" {
		// Known only up to its minor: a test of a substring or of the exact
		// text of a value that is not known is not decided.
		if op == "in" || op == "not in" || op == "===" {
			return triUnknown
		}
	}
	if swapped {
		if op == "in" || op == "not in" {
			// "x" in variable: the literal is searched in the variable's value.
			return e.eachValue(vals, func(v string) tri { return triOf(strings.Contains(v, lit) == (op == "in")) })
		}
		op = flipOp[op]
	} else if op == "in" || op == "not in" {
		// variable in "literal": the value is searched in the literal.
		return e.eachValue(vals, func(v string) tri { return triOf(strings.Contains(lit, v) == (op == "in")) })
	}
	isVersion := name == "python_version" || name == "python_full_version" || name == "implementation_version"
	// A version known only up to its minor may be the very patch level the
	// literal names, so that patch level is one of the values to try.
	if (name == "python_full_version" || name == "implementation_version") && strings.HasPrefix(lit, e.pyMinor+".") {
		if _, ok := parsePEP440(lit); ok && !strings.Contains(lit, "*") {
			vals = append(append([]string(nil), vals...), lit)
		}
	}
	return e.eachValue(vals, func(v string) tri {
		if isVersion {
			pv, ok := parsePEP440(v)
			if !ok {
				return triUnknown
			}
			if op == "===" {
				return triOf(v == lit)
			}
			ok, evaluable := pySatisfies(pv, op+lit)
			if !evaluable {
				return triUnknown
			}
			return triOf(ok)
		}
		switch op {
		case "==", "===":
			return triOf(v == lit)
		case "!=":
			return triOf(v != lit)
		}
		return triUnknown
	})
}

// eachValue evaluates f for each sample value; the answer stands only if
// every sample gives it.
func (e markerEnv) eachValue(vals []string, f func(string) tri) tri {
	first := f(vals[0])
	for _, v := range vals[1:] {
		if f(v) != first {
			return triUnknown
		}
	}
	return first
}

// requirementOf splits a requires_dist string into the PEP 503 name, the
// version specifier and the marker.
func requirementOf(s string) (name, constraint, marker string, ok bool) {
	req, mk, _ := strings.Cut(s, ";")
	name, constraint, ok = pythonRequirement(req)
	return name, constraint, strings.TrimSpace(mk), ok
}

// applies reports whether a requires_dist requirement is in force in the
// environment. An empty marker always is. A marker that cannot be decided is
// an error.
func (e markerEnv) applies(reqDist string) (name, constraint string, in bool, err error) {
	name, constraint, marker, ok := requirementOf(reqDist)
	if !ok {
		return "", "", false, fmt.Errorf("the requirement %q cannot be read", clip(reqDist, 100))
	}
	if marker == "" {
		return name, constraint, true, nil
	}
	in, err = e.eval(marker)
	return name, constraint, in, err
}

// requirementExtras returns the extras a requires_dist string asks of the
// package it names ("urllib3[socks,brotli]>=1.26"), as PEP 685 names.
func requirementExtras(s string) []string {
	req, _, _ := strings.Cut(s, ";")
	m := pipNameRE.FindStringSubmatch(strings.TrimSpace(req))
	if m == nil {
		return nil
	}
	var out []string
	for _, x := range pipExtras(m[2]) {
		out = append(out, normExtra(x))
	}
	return out
}
