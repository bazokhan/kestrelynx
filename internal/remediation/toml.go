package remediation

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// parseTOML reads a TOML document into nested maps, slices, strings, int64,
// float64 and bool values; a date or time is kept as its text. It is written
// for reading lockfile and project metadata: every construct is handled
// strictly, and anything it does not understand is an error rather than a
// guess.
func parseTOML(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("toml: not valid UTF-8")
	}
	p := &tomlParser{src: string(data), line: 1, headers: map[string]bool{}, dotted: map[string]bool{}}
	p.src = strings.TrimPrefix(p.src, "\xef\xbb\xbf")
	root := map[string]any{}
	if err := p.document(root); err != nil {
		return nil, fmt.Errorf("toml line %d: %w", p.line, err)
	}
	return tomlPlain(root).(map[string]any), nil
}

// inlineTable is an inline table while parsing: it is complete where it is
// written and cannot be extended by a later key or table header. tableArray
// is an array of tables made by [[...]] headers, which static arrays cannot
// be extended into. Both become plain maps and slices when parsing ends.
type (
	inlineTable map[string]any
	tableArray  struct{ items []map[string]any }
)

// tomlPlain turns the parser's internal values into maps and slices.
func tomlPlain(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = tomlPlain(e)
		}
		return t
	case inlineTable:
		m := map[string]any(t)
		for k, e := range m {
			m[k] = tomlPlain(e)
		}
		return m
	case *tableArray:
		out := make([]any, 0, len(t.items))
		for _, it := range t.items {
			out = append(out, tomlPlain(it))
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = tomlPlain(e)
		}
		return t
	}
	return v
}

type tomlParser struct {
	src  string
	pos  int
	line int
	// headers are the tables named by a [header]; dotted are the tables made
	// by a dotted key. Both are by canonical path, and a table can be defined
	// in only one of the two ways, once.
	headers map[string]bool
	dotted  map[string]bool
	inlines int
	depth   int // current nesting of arrays and inline tables
}

// maxTOMLDepth bounds how deeply arrays and inline tables nest, and how many
// parts a dotted key or table header has. Real lockfiles and project files
// stay far below it; the bound keeps hostile input from exhausting the stack
// in the parser or in the conversion that follows.
const maxTOMLDepth = 32

func (p *tomlParser) eof() bool { return p.pos >= len(p.src) }

func (p *tomlParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.src[p.pos]
}

func (p *tomlParser) has(s string) bool { return strings.HasPrefix(p.src[p.pos:], s) }

func (p *tomlParser) next() byte {
	c := p.src[p.pos]
	p.pos++
	if c == '\n' {
		p.line++
	}
	return c
}

// skipSpace skips blanks and tabs.
func (p *tomlParser) skipSpace() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

// skipComment skips a comment up to, not including, the line break.
func (p *tomlParser) skipComment() error {
	if p.peek() != '#' {
		return nil
	}
	for !p.eof() && p.peek() != '\n' {
		c := p.peek()
		if c < 0x20 && c != '\t' && c != '\r' || c == 0x7f {
			return errors.New("control character in comment")
		}
		p.pos++
	}
	return nil
}

// skipBlank skips blanks, comments and line breaks.
func (p *tomlParser) skipBlank() error {
	for !p.eof() {
		switch p.peek() {
		case ' ', '\t', '\r', '\n':
			p.next()
		case '#':
			if err := p.skipComment(); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

// endOfLine requires the rest of the line to be blank or a comment.
func (p *tomlParser) endOfLine() error {
	p.skipSpace()
	if err := p.skipComment(); err != nil {
		return err
	}
	if p.eof() {
		return nil
	}
	if p.has("\r\n") {
		p.pos++
	}
	if p.peek() != '\n' {
		return fmt.Errorf("unexpected %q after a value", p.peek())
	}
	p.next()
	return nil
}

func (p *tomlParser) document(root map[string]any) error {
	cur, curKey := root, ""
	for {
		if err := p.skipBlank(); err != nil {
			return err
		}
		if p.eof() {
			return nil
		}
		switch {
		case p.has("[["):
			p.pos += 2
			path, err := p.keyPath("]]")
			if err != nil {
				return err
			}
			if cur, curKey, err = p.appendTable(root, path); err != nil {
				return err
			}
		case p.peek() == '[':
			p.pos++
			path, err := p.keyPath("]")
			if err != nil {
				return err
			}
			if cur, curKey, err = p.openHeader(root, path); err != nil {
				return err
			}
		default:
			path, err := p.keyPath("=")
			if err != nil {
				return err
			}
			v, err := p.value()
			if err != nil {
				return err
			}
			if err := p.set(cur, curKey, path, v); err != nil {
				return err
			}
		}
		if err := p.endOfLine(); err != nil {
			return err
		}
	}
}

// keyPath reads a dotted key and the closing token that ends it.
func (p *tomlParser) keyPath(closer string) ([]string, error) {
	var path []string
	for {
		p.skipSpace()
		k, err := p.key()
		if err != nil {
			return nil, err
		}
		if path = append(path, k); len(path) > maxTOMLDepth {
			return nil, fmt.Errorf("a key has more than %d parts", maxTOMLDepth)
		}
		p.skipSpace()
		if p.peek() == '.' {
			p.pos++
			continue
		}
		if !p.has(closer) {
			return nil, fmt.Errorf("expected %q after key %q", closer, k)
		}
		p.pos += len(closer)
		return path, nil
	}
}

func isBareKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (p *tomlParser) key() (string, error) {
	switch p.peek() {
	case '"':
		return p.basicString()
	case '\'':
		return p.literalString()
	}
	start := p.pos
	for !p.eof() && isBareKeyChar(p.peek()) {
		p.pos++
	}
	if p.pos == start {
		return "", fmt.Errorf("expected a key, found %q", p.peek())
	}
	return p.src[start:p.pos], nil
}

func (p *tomlParser) value() (any, error) {
	p.skipSpace()
	if p.eof() {
		return nil, errors.New("missing value")
	}
	switch c := p.peek(); {
	case p.has(`"""`):
		return p.multiBasicString()
	case p.has(`'''`):
		return p.multiLiteralString()
	case c == '"':
		return p.basicString()
	case c == '\'':
		return p.literalString()
	case c == '[':
		return p.array()
	case c == '{':
		return p.inlineTable()
	}
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if c == ',' || c == ']' || c == '}' || c == '#' || c == '\t' || c == '\n' || c == '\r' || c == ' ' && !p.dateSpace(start) {
			break
		}
		p.pos++
	}
	return scalarToken(strings.TrimRight(p.src[start:p.pos], " \t"))
}

// dateSpace reports whether the space at the cursor sits between the date
// and the time of an offset or local date-time, which TOML allows.
func (p *tomlParser) dateSpace(start int) bool {
	tok := p.src[start:p.pos]
	rest := p.src[p.pos+1:]
	return len(tok) == 10 && tok[4] == '-' && tok[7] == '-' && len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9'
}

var (
	tomlDecimalRE = regexp.MustCompile(`^[+-]?(0|[1-9](_?[0-9])*)$`)
	tomlRadixRE   = regexp.MustCompile(`^0(x[0-9A-Fa-f](_?[0-9A-Fa-f])*|o[0-7](_?[0-7])*|b[01](_?[01])*)$`)
	tomlFloatRE   = regexp.MustCompile(`^[+-]?(0|[1-9](_?[0-9])*)(\.[0-9](_?[0-9])*)?([eE][+-]?[0-9](_?[0-9])*)?$`)
	tomlDateRE    = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})?)?|[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?)$`)
)

// scalarToken reads a boolean, a number or a date from its text under the
// TOML grammar: no leading zeros, underscores only between digits, a fraction
// or exponent with digits on both sides.
func scalarToken(tok string) (any, error) {
	switch tok {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "":
		return nil, errors.New("missing value")
	case "inf", "+inf", "-inf", "nan", "+nan", "-nan":
		f, _ := strconv.ParseFloat(strings.TrimLeft(tok, "+"), 64)
		return f, nil
	}
	switch {
	case tomlDecimalRE.MatchString(tok):
		n, err := strconv.ParseInt(strings.ReplaceAll(tok, "_", ""), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("integer %q is out of range", tok)
		}
		return n, nil
	case tomlRadixRE.MatchString(tok):
		n, err := strconv.ParseInt(strings.ReplaceAll(tok, "_", ""), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("integer %q is out of range", tok)
		}
		return n, nil
	case tomlFloatRE.MatchString(tok):
		f, err := strconv.ParseFloat(strings.ReplaceAll(tok, "_", ""), 64)
		if err != nil {
			return nil, fmt.Errorf("float %q is out of range", tok)
		}
		return f, nil
	case tomlDateRE.MatchString(tok):
		return tok, nil
	}
	return nil, fmt.Errorf("unsupported value %q", tok)
}

func (p *tomlParser) array() (any, error) {
	if p.depth++; p.depth > maxTOMLDepth {
		return nil, fmt.Errorf("arrays and inline tables nest deeper than %d levels", maxTOMLDepth)
	}
	defer func() { p.depth-- }()
	p.pos++ // [
	out := []any{}
	for {
		if err := p.skipBlank(); err != nil {
			return nil, err
		}
		if p.eof() {
			return nil, errors.New("unterminated array")
		}
		if p.peek() == ']' {
			p.pos++
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if err := p.skipBlank(); err != nil {
			return nil, err
		}
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
		default:
			return nil, errors.New("expected , or ] in an array")
		}
	}
}

func (p *tomlParser) inlineTable() (any, error) {
	if p.depth++; p.depth > maxTOMLDepth {
		return nil, fmt.Errorf("arrays and inline tables nest deeper than %d levels", maxTOMLDepth)
	}
	defer func() { p.depth-- }()
	p.pos++ // {
	out := inlineTable{}
	p.inlines++
	scope := fmt.Sprintf("\x01inline%d", p.inlines)
	p.skipSpace()
	if p.peek() == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.skipSpace()
		path, err := p.keyPath("=")
		if err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if err := p.set(out, scope, path, v); err != nil {
			return nil, err
		}
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return out, nil
		default:
			return nil, errors.New("expected , or } in an inline table")
		}
	}
}

func (p *tomlParser) literalString() (string, error) {
	p.pos++ // '
	start := p.pos
	for !p.eof() && p.peek() != '\'' {
		if p.peek() == '\n' {
			return "", errors.New("unterminated string")
		}
		p.pos++
	}
	if p.eof() {
		return "", errors.New("unterminated string")
	}
	s := p.src[start:p.pos]
	p.pos++
	return s, nil
}

func (p *tomlParser) multiLiteralString() (string, error) {
	p.pos += 3
	p.trimFirstNewline()
	end := strings.Index(p.src[p.pos:], "'''")
	if end < 0 {
		return "", errors.New("unterminated multi-line string")
	}
	s := p.src[p.pos : p.pos+end]
	p.line += strings.Count(s, "\n")
	p.pos += end + 3
	// Up to two further quotes may belong to the content.
	for n := 0; n < 2 && p.peek() == '\''; n++ {
		s += "'"
		p.pos++
	}
	return s, nil
}

func (p *tomlParser) trimFirstNewline() {
	if p.has("\r\n") {
		p.pos += 2
		p.line++
	} else if p.peek() == '\n' {
		p.next()
	}
}

func (p *tomlParser) basicString() (string, error) {
	p.pos++ // "
	var b strings.Builder
	for {
		if p.eof() || p.peek() == '\n' {
			return "", errors.New("unterminated string")
		}
		c := p.next()
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			if err := p.escape(&b); err != nil {
				return "", err
			}
		default:
			if c < 0x20 && c != '\t' || c == 0x7f {
				return "", errors.New("control character in a string")
			}
			b.WriteByte(c)
		}
	}
}

func (p *tomlParser) multiBasicString() (string, error) {
	p.pos += 3
	p.trimFirstNewline()
	var b strings.Builder
	for {
		if p.eof() {
			return "", errors.New("unterminated multi-line string")
		}
		if p.has(`"""`) {
			p.pos += 3
			for n := 0; n < 2 && p.peek() == '"'; n++ {
				b.WriteByte('"')
				p.pos++
			}
			return b.String(), nil
		}
		c := p.next()
		if c == '\\' {
			// A backslash at the end of a line trims the whitespace and
			// line breaks that follow.
			save := p.pos
			p.skipSpace()
			if p.peek() == '\n' || p.has("\r\n") {
				for !p.eof() && strings.IndexByte(" \t\r\n", p.peek()) >= 0 {
					p.next()
				}
				continue
			}
			p.pos = save
			if err := p.escape(&b); err != nil {
				return "", err
			}
			continue
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7f {
			return "", errors.New("control character in a string")
		}
		b.WriteByte(c)
	}
}

func (p *tomlParser) escape(b *strings.Builder) error {
	if p.eof() {
		return errors.New("unterminated escape")
	}
	c := p.next()
	switch c {
	case 'b':
		b.WriteByte('\b')
	case 't':
		b.WriteByte('\t')
	case 'n':
		b.WriteByte('\n')
	case 'f':
		b.WriteByte('\f')
	case 'r':
		b.WriteByte('\r')
	case '"':
		b.WriteByte('"')
	case '\\':
		b.WriteByte('\\')
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if p.pos+n > len(p.src) {
			return errors.New("short unicode escape")
		}
		r, err := strconv.ParseUint(p.src[p.pos:p.pos+n], 16, 32)
		if err != nil || !utf8.ValidRune(rune(r)) {
			return errors.New("invalid unicode escape")
		}
		p.pos += n
		b.WriteRune(rune(r))
	default:
		return fmt.Errorf("unknown escape \\%c", c)
	}
	return nil
}

// tableOf returns the table a value is, for navigation: only tables made by
// headers or dotted keys can be entered, never an inline table or a static
// array.
func tableOf(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// set stores v at the dotted path below t, whose canonical path is prefix. A
// key set twice is an error, and so is a dotted key that goes through a table
// defined any other way.
func (p *tomlParser) set(t map[string]any, prefix string, path []string, v any) error {
	for _, k := range path[:len(path)-1] {
		prefix += "\x00" + k
		sub, ok := t[k]
		if !ok {
			m := map[string]any{}
			t[k] = m
			p.dotted[prefix] = true
			t = m
			continue
		}
		m, isTable := tableOf(sub)
		if !isTable || !p.dotted[prefix] {
			return fmt.Errorf("key %q cannot be extended here", k)
		}
		t = m
	}
	last := path[len(path)-1]
	if _, dup := t[last]; dup {
		return fmt.Errorf("key %q is set twice", last)
	}
	t[last] = v
	return nil
}

// walk returns the table at path, creating missing ones as implicit tables;
// an array of tables on the way continues in its last element. key is the
// canonical path.
func (p *tomlParser) walk(root map[string]any, path []string) (map[string]any, string, error) {
	t, key := root, ""
	for _, k := range path {
		key += "\x00" + k
		sub, ok := t[k]
		if !ok {
			m := map[string]any{}
			t[k] = m
			t = m
			continue
		}
		switch s := sub.(type) {
		case map[string]any:
			t = s
		case *tableArray:
			last := len(s.items) - 1
			key += fmt.Sprintf("[%d]", last)
			t = s.items[last]
		default:
			return nil, "", fmt.Errorf("key %q is not a table", k)
		}
	}
	return t, key, nil
}

// openHeader opens the table a [header] names. A table can be named by a
// header once, and not if a dotted key already made it. An array of tables
// is never redefined as a table, though a header may go through one to reach
// a sub-table of its last element.
func (p *tomlParser) openHeader(root map[string]any, path []string) (map[string]any, string, error) {
	parent, pkey, err := p.walk(root, path[:len(path)-1])
	if err != nil {
		return nil, "", err
	}
	last := path[len(path)-1]
	key := pkey + "\x00" + last
	var t map[string]any
	switch sub := parent[last].(type) {
	case nil:
		t = map[string]any{}
		parent[last] = t
	case map[string]any:
		t = sub
	case *tableArray:
		return nil, "", fmt.Errorf("%q is an array of tables and cannot be defined as a table", strings.Join(path, "."))
	default:
		return nil, "", fmt.Errorf("key %q is not a table", last)
	}
	if p.headers[key] || p.dotted[key] {
		return nil, "", fmt.Errorf("table %q is defined twice", strings.Join(path, "."))
	}
	p.headers[key] = true
	return t, key, nil
}

// appendTable adds a table to the array of tables a [[header]] names.
func (p *tomlParser) appendTable(root map[string]any, path []string) (map[string]any, string, error) {
	parent, pkey, err := p.walk(root, path[:len(path)-1])
	if err != nil {
		return nil, "", err
	}
	last := path[len(path)-1]
	m := map[string]any{}
	switch existing := parent[last].(type) {
	case nil:
		parent[last] = &tableArray{items: []map[string]any{m}}
	case *tableArray:
		existing.items = append(existing.items, m)
	default:
		return nil, "", fmt.Errorf("key %q is not an array of tables", last)
	}
	ta := parent[last].(*tableArray)
	return m, fmt.Sprintf("%s\x00%s[%d]", pkey, last, len(ta.items)-1), nil
}
