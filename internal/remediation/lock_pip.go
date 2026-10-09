package remediation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// pipOptionsIgnored are the requirements-file options that change neither
// what is installed nor from where, so a line holding one is skipped.
var pipOptionsIgnored = map[string]bool{
	"--require-hashes": true,
	"--prefer-binary":  true,
	"--only-binary":    true,
}

var (
	pipCommentRE = regexp.MustCompile(`(^|\s)#.*$`)
	pipNameRE    = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$`)
	pipClauseRE  = regexp.MustCompile(`^(===|==|!=|<=|>=|~=|<|>)\s*(\S+)$`)
	pipHashRE    = regexp.MustCompile(`^--hash=[A-Za-z0-9_]+:[0-9a-fA-F]+$`)
)

// parseRequirements reads a UTF-8 requirements.txt. A line naming a package
// with an exact pin is an occurrence with that version; any other
// requirement is an occurrence without one, carrying its specifier. Anything
// that pulls in other files, changes where packages come from or cannot be
// told apart from a requirement makes the whole file unsupported: such a line
// can affect the packages the plan is about, and an include is never taken as
// resolved.
func parseRequirements(data []byte) (*lockfile, error) {
	if !utf8.Valid(data) {
		return nil, unsupported(ReasonUnsupportedRequirements, "requirements.txt is not valid UTF-8")
	}
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	text = strings.ReplaceAll(text, "\r\n", "\n")

	l := newLockfile(ManagerPip)
	var logical strings.Builder
	start := 0
	flush := func() error {
		line := strings.TrimSpace(logical.String())
		logical.Reset()
		if line == "" {
			return nil
		}
		return pipLine(l, line, start)
	}
	for i, raw := range strings.Split(text, "\n") {
		phys := strings.TrimRight(pipCommentRE.ReplaceAllString(raw, ""), " \t")
		if logical.Len() == 0 {
			start = i + 1
		}
		if strings.HasSuffix(phys, "\\") {
			logical.WriteString(strings.TrimSuffix(phys, "\\"))
			logical.WriteByte(' ')
			continue
		}
		logical.WriteString(phys)
		if err := flush(); err != nil {
			return nil, err
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return l.finish(), nil
}

func pipLine(l *lockfile, line string, n int) error {
	if strings.HasPrefix(line, "-") {
		opt := strings.Fields(line)[0]
		if i := strings.IndexByte(opt, '='); i >= 0 {
			opt = opt[:i]
		}
		if pipOptionsIgnored[opt] {
			return nil
		}
		return unsupported(ReasonUnsupportedRequirements, "requirements.txt line %d uses the option %s", n, opt)
	}

	// Per-requirement options (hashes) follow the requirement.
	req := line
	if i := strings.Index(line, " --"); i >= 0 {
		req = strings.TrimSpace(line[:i])
		for _, tok := range strings.Fields(line[i:]) {
			if !pipHashRE.MatchString(tok) {
				return unsupported(ReasonUnsupportedRequirements, "requirements.txt line %d has the option %s", n, tok)
			}
		}
	}

	marker, hasMarker := "", false
	if i := strings.IndexByte(req, ';'); i >= 0 {
		req, marker, hasMarker = strings.TrimSpace(req[:i]), strings.TrimSpace(req[i+1:]), true
	}
	m := pipNameRE.FindStringSubmatch(req)
	if m == nil {
		return unsupported(ReasonUnsupportedRequirements, "requirements.txt line %d is not a requirement the plan reads", n)
	}
	name, rest := m[1], strings.TrimSpace(m[3])
	path := fmt.Sprintf("requirements.txt:%d", n)
	o := SourceOccurrence{Path: path, Direct: true, Marker: marker, Extras: pipExtras(m[2])}
	if hasMarker {
		// Environment markers are not evaluated, so whether the line applies
		// to the image is not known; the line is left to a person.
		if why := markerProblem(marker); why != "" {
			o.ManualReason, o.Detail = ReasonInvalidMarker, why
		} else {
			o.ManualReason, o.Detail = ReasonMarkerNotEvaluated, "the requirement has an environment marker"
		}
	}

	if strings.HasPrefix(rest, "@") {
		if o.ManualReason == "" {
			o.ManualReason, o.Detail = ReasonNonRegistrySource, "required from a URL or path"
		}
		l.add(name, o)
		return nil
	}
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
	o.Unpinned = true
	if rest == "" {
		l.add(name, o)
		return nil
	}
	var clauses []string
	for _, c := range strings.Split(rest, ",") {
		c = strings.TrimSpace(c)
		cm := pipClauseRE.FindStringSubmatch(c)
		if cm == nil {
			return unsupported(ReasonUnsupportedRequirements, "requirements.txt line %d has the version specifier %q", n, c)
		}
		clause := cm[1] + cm[2]
		// A clause that breaks the specifier grammar is an error in pip
		// itself; arbitrary equality is valid and left to a person later.
		if _, grammar, _ := parseSpecifierClause(clause); !grammar {
			return unsupported(ReasonUnsupportedRequirements, "requirements.txt line %d has the version specifier %q, which is not valid", n, c)
		}
		clauses = append(clauses, clause)
	}
	if len(clauses) == 1 && strings.HasPrefix(clauses[0], "==") && !strings.HasPrefix(clauses[0], "===") {
		v := strings.TrimPrefix(clauses[0], "==")
		if !strings.Contains(v, "*") {
			if _, ok := parsePEP440(v); !ok {
				return unsupported(ReasonUnparsableVersion, "requirements.txt line %d pins %s to %q, which is not a version", n, name, v)
			}
			o.Version, o.Unpinned = v, false
			l.add(name, o)
			return nil
		}
	}
	o.Constraint = strings.Join(clauses, ",")
	l.add(name, o)
	return nil
}

// pipExtras lists the extras of a "[a,b]" group, lower-cased in the order
// written; they select optional dependencies and do not change the package's
// own version.
func pipExtras(group string) []string {
	group = strings.TrimSpace(strings.Trim(group, "[]"))
	if group == "" {
		return nil
	}
	var out []string
	for _, e := range strings.Split(group, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// markerProblem returns why an environment marker is not well formed, or ""
// when its quotes and parentheses balance and it names something. It does not
// evaluate the marker.
func markerProblem(m string) string {
	if strings.TrimSpace(m) == "" {
		return "the environment marker is empty"
	}
	depth := 0
	var quote byte
	for i := 0; i < len(m); i++ {
		c := m[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth < 0 {
				return "the environment marker has an unmatched )"
			}
		}
	}
	switch {
	case quote != 0:
		return "the environment marker has an unterminated string"
	case depth != 0:
		return "the environment marker has an unmatched ("
	}
	return ""
}
