package remediation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons a Dockerfile's base image is not edited or not recommended for
// editing. Each one names a property of the file that makes a byte-level tag
// rewrite unsafe, unverifiable or pointless; the first two are malformed
// input, the rest leave the file for a person or out of scope.
const (
	ReasonDockerfileInvalid        Reason = "dockerfile_invalid"             // not a Dockerfile this parser can read, or the edit failed verification
	ReasonDockerfileTargetMissing  Reason = "dockerfile_target_missing"      // the requested build stage does not exist
	ReasonDockerfileStageCycle     Reason = "dockerfile_stage_cycle"         // following stage references never reaches an image
	ReasonDockerfileVariable       Reason = "dockerfile_variable"            // an image or --platform in the chain contains "$"
	ReasonDockerfileScratch        Reason = "dockerfile_scratch"             // the base is scratch
	ReasonDockerfileDigest         Reason = "dockerfile_digest"              // the base carries a digest
	ReasonDockerfileTagUnsupported Reason = "dockerfile_tag_unsupported"     // the tag is a prerelease or a shape no candidate is looked up for
	ReasonDockerfileFrontend       Reason = "dockerfile_frontend"            // a "# syntax" directive names a frontend other than Docker's
	ReasonDockerfileEscape         Reason = "dockerfile_escape"              // the file sets the escape directive
	ReasonDockerfileAmbiguous      Reason = "dockerfile_ambiguous_range"     // the bytes of the tag cannot be located exactly
	ReasonDockerfileOnBuild        Reason = "dockerfile_onbuild"             // a stage the target inherits from has ONBUILD
	ReasonDockerfileStagePlatform  Reason = "dockerfile_stage_platform"      // a FROM between the target and the base carries --platform
	ReasonDockerfileNotEditable    Reason = "dockerfile_not_editable"        // the base is not a pinned tag
	ReasonDockerfileSourceMismatch Reason = "dockerfile_source_mismatch"     // the file names another repository or tag than the one expected
	ReasonDockerfileMappingDiffers Reason = "dockerfile_mapping_differs"     // derived and configured Dockerfile locations disagree
	ReasonComposeNoBuild           Reason = "compose_no_build"               // the service has no build section
	ReasonComposeBuildRemote       Reason = "compose_build_remote_context"   // the build context is a URL or repository
	ReasonComposeBuildInline       Reason = "compose_build_inline"           // the build uses dockerfile_inline
	ReasonComposeBuildAdditional   Reason = "compose_build_additional"       // the build uses additional_contexts
	ReasonComposeBuildPath         Reason = "compose_build_path"             // a build path is absolute, escapes the repository or is malformed
	ReasonComposeBuildShape        Reason = "compose_build_unsupported_form" // the build section has a form this reader does not interpret
)

// maxDockerfileBytes bounds the file the parser reads.
const maxDockerfileBytes = 1 << 20

var (
	// dockerfileDirectiveRE is a parser directive line: "# name=value".
	dockerfileDirectiveRE = regexp.MustCompile(`^#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$`)
	// dockerfileStageNameRE is a stage name once lower-cased.
	dockerfileStageNameRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
	// dockerfileHeredocRE is one word that opens a here-document: an optional
	// file descriptor, "<<", an optional "-" and the delimiter.
	dockerfileHeredocRE = regexp.MustCompile(`^[0-9]*<<(-?)([^<]+)$`)
	// dockerfileHeredocOpRE is the operator alone, its delimiter being the
	// next word.
	dockerfileHeredocOpRE = regexp.MustCompile(`^[0-9]*<<-?$`)
)

// DockerfileProblem says why a Dockerfile (or a Compose build section it was
// derived from) was not used.
type DockerfileProblem struct {
	Reason Reason
	Detail string
}

func (p *DockerfileProblem) Error() string { return fmt.Sprintf("%s: %s", p.Reason, p.Detail) }

func dockerfileProblem(r Reason, format string, args ...any) *DockerfileProblem {
	return &DockerfileProblem{Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// DockerfileStage is one FROM of a Dockerfile.
type DockerfileStage struct {
	Index    int    // position among the stages, from 0
	Name     string // the AS name as written, "" when the stage has none
	Image    string // the FROM operand as written: an image reference or an earlier stage's name
	Platform string // the --platform value as written, "" when absent
	Line     int    // 1-based line of the FROM keyword
	OnBuild  bool   // the stage contains an ONBUILD instruction

	// imageOffs holds, for each byte of Image, its offset in the file; nil when
	// the operand contains quotes or escapes, so its source bytes are not
	// those of Image.
	imageOffs []int
}

// dockerInstr is the extent of one instruction in the file: its keyword and
// the byte range from the start of its first line to the end of its last
// (continuation lines and here-document bodies included, the final line
// break not).
type dockerInstr struct {
	keyword    string // upper-cased
	start, end int
}

// Dockerfile is a parsed Dockerfile reduced to what choosing and editing a
// base image needs.
type Dockerfile struct {
	Stages []DockerfileStage

	// Syntax is the value of the "# syntax" parser directive, "" when absent.
	Syntax string
	// HasEscape is true when the file sets the escape parser directive.
	HasEscape bool

	instrs []dockerInstr
}

type dockerLine struct {
	start, end, next int // [start, end) is the text without its line break; next starts the following line
}

// splitDockerLines splits content at "\n" or "\r\n"; a lone "\r" stays in the
// text. A leading byte order mark is skipped.
func splitDockerLines(content []byte) []dockerLine {
	var lines []dockerLine
	pos := 0
	if bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}) {
		pos = 3
	}
	for pos < len(content) {
		nl := bytes.IndexByte(content[pos:], '\n')
		if nl < 0 {
			lines = append(lines, dockerLine{pos, len(content), len(content)})
			break
		}
		end := pos + nl
		next := end + 1
		if end > pos && content[end-1] == '\r' {
			end--
		}
		lines = append(lines, dockerLine{pos, end, next})
		pos = next
	}
	return lines
}

func isBlankOrComment(text []byte) bool {
	t := bytes.TrimLeft(text, " \t")
	return len(t) == 0 || t[0] == '#'
}

// ParseDockerfile reads the instruction structure of a Dockerfile: line
// continuations (with the default escape character or the one the escape
// directive sets), comments, parser directives at the top, here-documents of
// RUN, COPY and ADD (their bodies are never instructions) and
// case-insensitive instruction names. Only FROM and ONBUILD are interpreted;
// every other instruction is skipped over.
//
// A file the parser cannot place with certainty is refused, never guessed at:
// a malformed FROM, an unterminated here-document, a repeated parser
// directive, a duplicate stage name, no FROM at all.
func ParseDockerfile(content []byte) (d *Dockerfile, prob *DockerfileProblem) {
	defer func() {
		if r := recover(); r != nil {
			d, prob = nil, dockerfileProblem(ReasonDockerfileInvalid, "internal error while parsing: %v", r)
		}
	}()
	if len(content) > maxDockerfileBytes {
		return nil, dockerfileProblem(ReasonDockerfileInvalid, "the file is larger than %d bytes", maxDockerfileBytes)
	}
	if bytes.IndexByte(content, 0) >= 0 {
		return nil, dockerfileProblem(ReasonDockerfileInvalid, "the file contains a NUL byte")
	}
	if bytes.HasPrefix(content, []byte{0xFF, 0xFE}) || bytes.HasPrefix(content, []byte{0xFE, 0xFF}) {
		return nil, dockerfileProblem(ReasonDockerfileInvalid, "UTF-16 files are not read")
	}

	lines := splitDockerLines(content)
	d = &Dockerfile{}
	escape := byte('\\')

	// Parser directives: consecutive lines at the top, each possibly indented
	// (a byte order mark was already skipped). Any other line, including a
	// blank one or an unknown "# name=value" comment, ends them.
	seen := map[string]bool{}
	for _, l := range lines {
		m := dockerfileDirectiveRE.FindStringSubmatch(string(bytes.TrimLeft(content[l.start:l.end], " \t")))
		if m == nil {
			break
		}
		name := strings.ToLower(m[1])
		if name != "syntax" && name != "escape" && name != "check" {
			break
		}
		if seen[name] {
			return nil, dockerfileProblem(ReasonDockerfileInvalid, "the parser directive %q is repeated", name)
		}
		seen[name] = true
		switch name {
		case "syntax":
			d.Syntax = m[2]
		case "escape":
			d.HasEscape = true
			if m[2] != "\\" && m[2] != "`" {
				return nil, dockerfileProblem(ReasonDockerfileInvalid, "the escape directive %q is neither \\ nor `", m[2])
			}
			escape = m[2][0]
		}
	}

	var cur *DockerfileStage
	names := map[string]bool{}
	for i := 0; i < len(lines); {
		first := lines[i]
		if isBlankOrComment(content[first.start:first.end]) {
			i++
			continue
		}

		// Join the physical lines of one instruction. Comment and blank lines
		// inside a continuation are dropped, as Docker does.
		var logical []byte
		var offs []int
		lastEnd := first.end
		firstLine := i
		for isFirst := true; i < len(lines); isFirst = false {
			l := lines[i]
			text := content[l.start:l.end]
			if !isFirst && isBlankOrComment(text) {
				i++
				lastEnd = l.end
				continue
			}
			body, cont := trimContinuation(text, escape)
			for k := range body {
				offs = append(offs, l.start+k)
			}
			logical = append(logical, body...)
			lastEnd = l.end
			i++
			if !cont {
				break
			}
		}

		lead := len(logical) - len(bytes.TrimLeft(logical, " \t"))
		kwEnd := lead
		for kwEnd < len(logical) && logical[kwEnd] != ' ' && logical[kwEnd] != '\t' {
			kwEnd++
		}
		keyword := strings.ToUpper(string(logical[lead:kwEnd]))
		args := logical[kwEnd:]
		argOffs := offs[kwEnd:]

		for _, hd := range heredocsOfInstruction(keyword, args) {
			end, ok := skipHeredoc(content, lines, &i, hd)
			if !ok {
				return nil, dockerfileProblem(ReasonDockerfileInvalid, "line %d: here-document %q is not terminated", firstLine+1, hd.name)
			}
			lastEnd = end
		}
		d.instrs = append(d.instrs, dockerInstr{keyword: keyword, start: first.start, end: lastEnd})

		switch keyword {
		case "FROM":
			st, prob := parseFromArgs(args, argOffs)
			if prob != nil {
				return nil, dockerfileProblem(ReasonDockerfileInvalid, "line %d: %s", firstLine+1, prob.Detail)
			}
			st.Index = len(d.Stages)
			st.Line = firstLine + 1
			if st.Name != "" {
				key := strings.ToLower(st.Name)
				if names[key] {
					return nil, dockerfileProblem(ReasonDockerfileInvalid, "line %d: stage name %q is used twice", firstLine+1, st.Name)
				}
				names[key] = true
			}
			d.Stages = append(d.Stages, st)
			cur = &d.Stages[len(d.Stages)-1]
		case "ONBUILD":
			if cur != nil {
				cur.OnBuild = true
			}
		}
	}
	if len(d.Stages) == 0 {
		return nil, dockerfileProblem(ReasonDockerfileInvalid, "the file has no FROM instruction")
	}
	return d, nil
}

type heredoc struct {
	name  string
	strip bool // "<<-": leading tabs of the body lines and the delimiter line are ignored
}

// trimContinuation applies the line-continuation rule of the Dockerfile
// parser to one physical line. A line continues when, after trailing spaces
// and tabs, it ends with the escape character and that character is either the
// whole line or not itself preceded by the escape character, so an escaped
// escape ("\\" at the end) does not continue. The returned body is the line
// without the continuation character and the whitespace after it.
func trimContinuation(text []byte, escape byte) (body []byte, continues bool) {
	t := bytes.TrimRight(text, " \t")
	n := len(t)
	if n == 0 || t[n-1] != escape || (n >= 2 && t[n-2] == escape) {
		return text, false
	}
	return t[:n-1], true
}

// heredocsOfInstruction lists the here-documents an instruction opens. Only
// RUN, COPY and ADD can, directly or as the instruction an ONBUILD wraps, and
// not in their JSON (exec) form.
func heredocsOfInstruction(keyword string, args []byte) []heredoc {
	if keyword == "ONBUILD" {
		rest := bytes.TrimLeft(args, " \t")
		end := bytes.IndexAny(rest, " \t")
		if end < 0 {
			return nil
		}
		keyword, args = strings.ToUpper(string(rest[:end])), rest[end:]
	}
	if keyword != "RUN" && keyword != "COPY" && keyword != "ADD" {
		return nil
	}
	if isJSONArgs(args) {
		return nil
	}
	return heredocsOf(args)
}

// isJSONArgs reports whether instruction arguments are written as a JSON
// array of strings, the exec form.
func isJSONArgs(args []byte) bool {
	t := bytes.TrimSpace(args)
	if len(t) == 0 || t[0] != '[' {
		return false
	}
	var list []string
	return json.Unmarshal(t, &list) == nil
}

// heredocsOf lists the here-documents an instruction's arguments open, in
// order. The arguments are split into words the way a shell would, keeping
// quotes and escapes in place; a word opens one when it is "<<" or "<<-"
// followed by a delimiter (directly or after blanks), optionally quoted and
// optionally preceded by a file descriptor number. The delimiter is the word with its quoting removed, so it
// may contain spaces.
func heredocsOf(args []byte) []heredoc {
	var out []heredoc
	words := shellWords(string(args))
	for i := 0; i < len(words); i++ {
		m := dockerfileHeredocRE.FindStringSubmatch(words[i])
		var strip bool
		var raw string
		switch {
		case dockerfileHeredocOpRE.MatchString(words[i]):
			if i+1 >= len(words) {
				continue
			}
			// The delimiter follows the operator after blanks: "<< EOF".
			strip, raw = strings.HasSuffix(words[i], "-"), words[i+1]
			i++
		case m != nil:
			strip, raw = m[1] == "-", m[2]
		default:
			continue
		}
		name := unquoteShellWord(raw)
		if name == "" {
			continue
		}
		out = append(out, heredoc{name: name, strip: strip})
	}
	return out
}

// shellWords splits s at unquoted spaces, tabs and line breaks. Single quotes
// are literal, double quotes and unquoted text honor backslash escapes, and
// all quotes and escapes stay in the returned words. An unterminated quote
// runs to the end.
func shellWords(s string) []string {
	var out []string
	var cur []byte
	inWord := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			cur = append(cur, c)
			if c == '\'' {
				quote = 0
			}
		case quote == '"':
			cur = append(cur, c)
			if c == '\\' && i+1 < len(s) {
				i++
				cur = append(cur, s[i])
			} else if c == '"' {
				quote = 0
			}
		case c == '\\':
			inWord = true
			cur = append(cur, c)
			if i+1 < len(s) {
				i++
				cur = append(cur, s[i])
			}
		case c == '\'' || c == '"':
			inWord = true
			quote = c
			cur = append(cur, c)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				out = append(out, string(cur))
				cur, inWord = nil, false
			}
		default:
			inWord = true
			cur = append(cur, c)
		}
	}
	if inWord {
		out = append(out, string(cur))
	}
	return out
}

// unquoteShellWord removes the quotes and escapes of one word from shellWords.
func unquoteShellWord(w string) string {
	var out []byte
	var quote byte
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				out = append(out, c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(w) && strings.IndexByte("\"\\$", w[i+1]) >= 0:
				i++
				out = append(out, w[i])
			default:
				out = append(out, c)
			}
		case c == '\\' && i+1 < len(w):
			i++
			out = append(out, w[i])
		case c == '\'' || c == '"':
			quote = c
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// skipHeredoc consumes the body of one here-document from lines[*i:], up to
// and including its delimiter line, and returns the end offset of that line.
func skipHeredoc(content []byte, lines []dockerLine, i *int, hd heredoc) (int, bool) {
	for *i < len(lines) {
		l := lines[*i]
		*i++
		text := content[l.start:l.end]
		if hd.strip {
			text = bytes.TrimLeft(text, "\t")
		}
		if string(text) == hd.name {
			return l.end, true
		}
	}
	return 0, false
}

type dockerToken struct {
	text       string
	start, end int // [start, end) in the joined instruction text
}

func dockerTokens(args []byte) []dockerToken {
	var out []dockerToken
	for i := 0; i < len(args); {
		if args[i] == ' ' || args[i] == '\t' {
			i++
			continue
		}
		j := i
		for j < len(args) && args[j] != ' ' && args[j] != '\t' {
			j++
		}
		out = append(out, dockerToken{string(args[i:j]), i, j})
		i = j
	}
	return out
}

// parseFromArgs reads "[--platform=P] image [AS name]".
func parseFromArgs(args []byte, offs []int) (DockerfileStage, *DockerfileProblem) {
	var st DockerfileStage
	toks := dockerTokens(args)
	i := 0
	for i < len(toks) && strings.HasPrefix(toks[i].text, "--") {
		name, val, found := strings.Cut(toks[i].text[2:], "=")
		if !found || val == "" || strings.ToLower(name) != "platform" || st.Platform != "" {
			return st, dockerfileProblem(ReasonDockerfileInvalid, "FROM flag %q is not a single --platform=<value>", toks[i].text)
		}
		st.Platform = val
		i++
	}
	if i >= len(toks) {
		return st, dockerfileProblem(ReasonDockerfileInvalid, "FROM has no image")
	}
	img := toks[i]
	i++
	st.Image = img.text
	if !strings.ContainsAny(img.text, "\"'\\") {
		st.imageOffs = offs[img.start:img.end]
	}
	switch {
	case i == len(toks):
	case len(toks)-i == 2 && strings.EqualFold(toks[i].text, "AS"):
		st.Name = toks[i+1].text
		if !dockerfileStageNameRE.MatchString(strings.ToLower(st.Name)) {
			return st, dockerfileProblem(ReasonDockerfileInvalid, "%q is not a valid stage name", st.Name)
		}
	default:
		return st, dockerfileProblem(ReasonDockerfileInvalid, "FROM is not \"image [AS name]\"")
	}
	return st, nil
}

// DockerfileDisposition is how the base of a build target is handled.
type DockerfileDisposition string

const (
	// DockerfilePinned is an external image with a pinned tag the file can be
	// edited to move: the candidate is a newer patch of the same series.
	DockerfilePinned DockerfileDisposition = "pinned"
	// DockerfileFloating is an external image with a floating tag. It is not
	// edited; its candidate is whatever the tag points at now.
	DockerfileFloating DockerfileDisposition = "floating"
	// DockerfileExcluded is a base no candidate is looked up for: scratch, a
	// digest reference, or an unsupported tag.
	DockerfileExcluded DockerfileDisposition = "excluded"
	// DockerfileManual is a base the file cannot be safely edited for; a
	// person decides.
	DockerfileManual DockerfileDisposition = "manual"
)

// DockerfileBase is the external image the build of a target stage starts
// from, and how it is handled.
type DockerfileBase struct {
	// Target is the requested stage name, "" for the last stage.
	Target string
	// Chain lists stage indexes from the target stage back to the stage whose
	// FROM names an external image; it has one element when the target
	// names the image itself.
	Chain []int
	// Stage is the index of the stage holding the external FROM, the last
	// element of Chain, and Line is that FROM's line.
	Stage int
	Line  int
	Image string   // the operand as written
	Ref   ImageRef // Image classified; zero when Image is not a reference
	// Platform is the --platform value of the external FROM, "" when absent.
	Platform string

	Disposition DockerfileDisposition
	Reason      Reason // why the disposition is Excluded or Manual; "" otherwise
	Detail      string

	// OnBuildInherited is true when a stage the target inherits from (not the
	// target itself) contains ONBUILD. A consumer treats the base as manual
	// whatever its Disposition says.
	OnBuildInherited bool

	tagStart, tagEnd int // byte range of the tag in the file; valid when tagOK
	tagOK            bool
}

// AutoEditable reports whether the file may be edited for this base without
// a person: a pinned tag, no inherited ONBUILD, nothing ambiguous.
func (b DockerfileBase) AutoEditable() bool {
	return b.Disposition == DockerfilePinned && !b.OnBuildInherited && b.tagOK
}

// IsOfficialDockerfileFrontend reports whether a "# syntax" directive value
// names one of Docker's own Dockerfile frontends, by any tag or digest.
func IsOfficialDockerfileFrontend(v string) bool {
	v = strings.TrimSpace(v)
	for _, p := range []string{"docker.io/", "index.docker.io/"} {
		v = strings.TrimPrefix(v, p)
	}
	if i := strings.IndexAny(v, ":@"); i >= 0 {
		v = v[:i]
	}
	return v == "docker/dockerfile" || v == "docker/dockerfile-upstream"
}

// ResolveBase finds the external image the target stage is built from and
// classifies it. target names the stage (compared without regard to case); ""
// is the last stage. A FROM that names an earlier stage is followed until a
// FROM names an image; a name that matches no earlier stage is an image.
//
// A missing target and a reference cycle are problems. Everything else is a
// DockerfileBase whose Disposition says whether the file can be edited.
func (d *Dockerfile) ResolveBase(target string) (DockerfileBase, *DockerfileProblem) {
	ti := len(d.Stages) - 1
	if target != "" {
		ti = -1
		for _, s := range d.Stages {
			if s.Name != "" && strings.EqualFold(s.Name, target) {
				ti = s.Index
				break
			}
		}
		if ti < 0 {
			return DockerfileBase{}, dockerfileProblem(ReasonDockerfileTargetMissing, "the file has no stage named %q", target)
		}
	}

	chain := []int{ti}
	visited := map[int]bool{ti: true}
	cur := ti
	for {
		st := d.Stages[cur]
		next := -1
		for j := 0; j < cur; j++ {
			if n := d.Stages[j].Name; n != "" && strings.EqualFold(n, st.Image) {
				next = j
				break
			}
		}
		if next < 0 {
			break
		}
		if visited[next] {
			return DockerfileBase{}, dockerfileProblem(ReasonDockerfileStageCycle, "stage %q refers back to a stage already followed", st.Image)
		}
		visited[next] = true
		chain = append(chain, next)
		cur = next
	}

	ext := d.Stages[cur]
	b := DockerfileBase{
		Target: target, Chain: chain, Stage: cur, Line: ext.Line,
		Image: ext.Image, Platform: ext.Platform,
	}
	for _, idx := range chain[1:] {
		if d.Stages[idx].OnBuild {
			b.OnBuildInherited = true
		}
	}
	b.Ref = ParseImageRef(ext.Image)

	manual := func(r Reason, format string, args ...any) (DockerfileBase, *DockerfileProblem) {
		b.Disposition, b.Reason, b.Detail = DockerfileManual, r, fmt.Sprintf(format, args...)
		return b, nil
	}
	switch {
	case d.Syntax != "" && !IsOfficialDockerfileFrontend(d.Syntax):
		return manual(ReasonDockerfileFrontend, "the file selects the frontend %q", d.Syntax)
	case d.HasEscape:
		return manual(ReasonDockerfileEscape, "the file sets the escape directive")
	}
	for _, idx := range chain {
		st := d.Stages[idx]
		if strings.Contains(st.Image, "$") || strings.Contains(st.Platform, "$") {
			return manual(ReasonDockerfileVariable, "the FROM on line %d uses a variable", st.Line)
		}
		if idx != cur && st.Platform != "" {
			return manual(ReasonDockerfileStagePlatform, "the FROM on line %d between the target and its base sets --platform", st.Line)
		}
	}

	excluded := func(r Reason, format string, args ...any) (DockerfileBase, *DockerfileProblem) {
		b.Disposition, b.Reason, b.Detail = DockerfileExcluded, r, fmt.Sprintf(format, args...)
		return b, nil
	}
	if ext.Image == "scratch" {
		return excluded(ReasonDockerfileScratch, "the base is scratch")
	}
	switch b.Ref.Exclude {
	case ExcludeNone:
	case ExcludeDigestOnly, ExcludeTagAndDigest, ExcludeBareDigest:
		return excluded(ReasonDockerfileDigest, "the base %q carries a digest", ext.Image)
	case ExcludeUnparsable:
		return manual(ReasonDockerfileInvalid, "the base %q is not a well-formed image reference", ext.Image)
	default:
		return excluded(ReasonDockerfileTagUnsupported, "the base %q has a tag no candidate is looked up for (%s)", ext.Image, b.Ref.Exclude)
	}
	if b.Ref.Kind == TagFloating {
		b.Disposition = DockerfileFloating
		return b, nil
	}

	// Pinned: locate the tag's bytes, which must be one unbroken run equal to
	// the tag.
	b.Disposition = DockerfilePinned
	tag := b.Ref.Tag
	if ext.imageOffs == nil || b.Ref.ImplicitTag || !strings.HasSuffix(ext.Image, ":"+tag) {
		return manual(ReasonDockerfileAmbiguous, "the tag of %q cannot be located in the file", ext.Image)
	}
	offs := ext.imageOffs[len(ext.Image)-len(tag):]
	for k := 1; k < len(offs); k++ {
		if offs[k] != offs[k-1]+1 {
			return manual(ReasonDockerfileAmbiguous, "the tag of %q is split across lines", ext.Image)
		}
	}
	b.tagStart, b.tagEnd, b.tagOK = offs[0], offs[len(offs)-1]+1, true
	return b, nil
}

// DockerfileEditRequest asks for the tag of the external image behind one
// build target to be rewritten.
type DockerfileEditRequest struct {
	Content []byte // the file as read from Git
	Target  string // the build stage, "" for the last
	Current string // the image reference the file must name, with an explicit tag
	NewTag  string // the tag to write
}

// DockerfileChange is the rewritten FROM.
type DockerfileChange struct {
	Stage    int    // index of the stage holding the FROM
	Line     int    // 1-based line of the FROM
	Old, New string // the full image operand before and after
}

// DockerfileEdit is the edited file and its one change.
type DockerfileEdit struct {
	Content []byte
	Change  DockerfileChange
}

// EditDockerfileBaseTag rewrites the tag of the external image the target
// stage is built from, and nothing else: the --platform flag, the AS name and
// every other byte of the file stay. It refuses unless the base is a pinned
// tag that is safe to edit (see DockerfileBase.AutoEditable) and names the
// same repository and tag as the running image.
//
// The result is verified before it is returned: bytes outside the tag are
// identical, a re-parse finds the same instructions at the same (shifted)
// positions and the same stages, and only that FROM's image differs, in its
// tag.
func EditDockerfileBaseTag(req DockerfileEditRequest) (res DockerfileEdit, prob *DockerfileProblem) {
	defer func() {
		if r := recover(); r != nil {
			res, prob = DockerfileEdit{}, dockerfileProblem(ReasonDockerfileInvalid, "internal error while editing: %v", r)
		}
	}()
	if !composeTagRE.MatchString(req.NewTag) {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileInvalid, "%q is not a valid tag", req.NewTag)
	}
	curKey, ok := inventory.RepositoryKey(req.Current)
	if !ok {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileInvalid, "running image %q is not a well-formed reference", req.Current)
	}
	curTag := inventory.TagOf(req.Current)
	if curTag == "" || inventory.DigestOf(req.Current) != "" {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileInvalid, "running image %q needs an explicit tag and no digest", req.Current)
	}
	if req.NewTag == curTag {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileInvalid, "the new tag equals the running tag %q; there is nothing to change", curTag)
	}

	d, prob := ParseDockerfile(req.Content)
	if prob != nil {
		return DockerfileEdit{}, prob
	}
	base, prob := d.ResolveBase(req.Target)
	if prob != nil {
		return DockerfileEdit{}, prob
	}
	switch {
	case base.OnBuildInherited:
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileOnBuild, "a stage the target inherits from has ONBUILD")
	case base.Disposition == DockerfileManual || base.Disposition == DockerfileExcluded:
		return DockerfileEdit{}, &DockerfileProblem{Reason: base.Reason, Detail: base.Detail}
	case !base.AutoEditable():
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileNotEditable, "the base %q is not a pinned tag", base.Image)
	}
	key, _ := inventory.RepositoryKey(base.Image)
	if key != curKey {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileSourceMismatch, "the file names repository %q, not the running image's", base.Ref.Repository)
	}
	if base.Ref.Tag != curTag {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileSourceMismatch, "the file has tag %q, the running image has %q", base.Ref.Tag, curTag)
	}
	if string(req.Content[base.tagStart:base.tagEnd]) != base.Ref.Tag {
		return DockerfileEdit{}, dockerfileProblem(ReasonDockerfileAmbiguous, "the source bytes of the tag differ from the parsed tag")
	}

	span := composeSpan{start: base.tagStart, end: base.tagEnd, repl: req.NewTag}
	out := spliceSpans(req.Content, []composeSpan{span})
	change := DockerfileChange{
		Stage: base.Stage, Line: base.Line,
		Old: base.Image,
		New: base.Image[:len(base.Image)-len(base.Ref.Tag)] + req.NewTag,
	}
	if prob := verifyDockerfileEdit(req.Content, out, span, d, req.Target, change); prob != nil {
		return DockerfileEdit{}, prob
	}
	return DockerfileEdit{Content: out, Change: change}, nil
}

// verifyDockerfileEdit checks an edit against the original.
func verifyDockerfileEdit(orig, edited []byte, span composeSpan, od *Dockerfile, target string, ch DockerfileChange) *DockerfileProblem {
	bad := func(format string, args ...any) *DockerfileProblem {
		return dockerfileProblem(ReasonDockerfileInvalid, "verification of the edit failed: "+format, args...)
	}
	if !bytes.Equal(orig[:span.start], edited[:span.start]) {
		return bad("bytes before the edited tag changed")
	}
	if !bytes.Equal(orig[span.end:], edited[span.start+len(span.repl):]) {
		return bad("bytes after the edited tag changed")
	}
	nd, prob := ParseDockerfile(edited)
	if prob != nil {
		return bad("the result does not parse: %s", prob.Detail)
	}
	if nd.Syntax != od.Syntax || nd.HasEscape != od.HasEscape {
		return bad("parser directives changed")
	}
	delta := len(span.repl) - (span.end - span.start)
	shift := func(pos int, isEnd bool) int {
		if pos > span.start || (isEnd && pos >= span.end) {
			return pos + delta
		}
		return pos
	}
	if len(nd.instrs) != len(od.instrs) {
		return bad("the number of instructions changed")
	}
	for i, a := range od.instrs {
		b := nd.instrs[i]
		if a.keyword != b.keyword || shift(a.start, false) != b.start || shift(a.end, true) != b.end {
			return bad("instruction %d (%s) moved or changed", i+1, a.keyword)
		}
	}
	if len(nd.Stages) != len(od.Stages) {
		return bad("the number of stages changed")
	}
	for i, a := range od.Stages {
		b := nd.Stages[i]
		wantImage := a.Image
		if i == ch.Stage {
			wantImage = ch.New
		}
		if a.Name != b.Name || a.Platform != b.Platform || a.Line != b.Line || a.OnBuild != b.OnBuild || b.Image != wantImage {
			return bad("stage %d differs beyond the target image", i)
		}
	}
	nb, prob := nd.ResolveBase(target)
	if prob != nil {
		return bad("the result no longer resolves: %s", prob.Detail)
	}
	if nb.Stage != ch.Stage || nb.Image != ch.New || nb.Disposition != DockerfilePinned || nb.OnBuildInherited {
		return bad("the result resolves to %q (%s), want %q", nb.Image, nb.Disposition, ch.New)
	}
	return nil
}
