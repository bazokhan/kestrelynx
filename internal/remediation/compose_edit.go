package remediation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons a Compose file is not edited. Each one names a property of the file
// (or of the request) that makes a byte-level tag rewrite unsafe or
// unverifiable; a file that trips any of them is left for a person.
const (
	ReasonComposeInvalid        Reason = "compose_invalid"            // not one well-formed Compose document, or the request or the result failed verification
	ReasonComposeServiceMissing Reason = "compose_service_missing"    // a target service or its image key is absent
	ReasonComposeBuild          Reason = "compose_build"              // a target service builds its image
	ReasonComposeIncludeExtends Reason = "compose_include_or_extends" // top-level include, or extends on a target service
	ReasonComposeMergeKey       Reason = "compose_merge_key"          // a "<<" key on the path to a target image
	ReasonComposeAnchorAlias    Reason = "compose_anchor_or_alias"    // an anchor or alias on a node whose edit could reach other places
	ReasonComposeNotString      Reason = "compose_not_string"         // the image value is not a plain string scalar
	ReasonComposeBlockScalar    Reason = "compose_block_scalar"       // the image value is a block scalar
	ReasonComposeVariable       Reason = "compose_variable"           // the image value contains "$"
	ReasonComposeDigest         Reason = "compose_digest"             // the image value carries a digest
	ReasonComposeSourceMismatch Reason = "compose_source_mismatch"    // the file names another repository or tag than the running image
)

// composeTagRE is a valid image tag.
var composeTagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// ComposeEditRequest asks for the tag of the image of a fixed set of services
// to be rewritten in one Compose file.
type ComposeEditRequest struct {
	Content  []byte   // the file as read from Git
	Services []string // the target services; duplicates are ignored
	Current  string   // the running image reference the file must denote, with an explicit tag
	NewTag   string   // the tag to write
}

// ComposeChange is one rewritten image.
type ComposeChange struct {
	Service  string // the service name
	Location string // structural location, "services.<name>.image"
	Old, New string // the full image strings as written in the file, without quotes
}

// ComposeEdit is the edited file and the changes made to it.
type ComposeEdit struct {
	Content []byte
	Changes []ComposeChange // sorted by Service
}

// ComposeEditProblem says why a file was not edited.
type ComposeEditProblem struct {
	Reason  Reason
	Service string // the service the problem was found on, "" for the file as a whole
	Detail  string
}

func (p *ComposeEditProblem) Error() string {
	if p.Service != "" {
		return fmt.Sprintf("%s: service %q: %s", p.Reason, p.Service, p.Detail)
	}
	return fmt.Sprintf("%s: %s", p.Reason, p.Detail)
}

func composeProblem(r Reason, service, format string, args ...any) *ComposeEditProblem {
	return &ComposeEditProblem{Reason: r, Service: service, Detail: fmt.Sprintf(format, args...)}
}

// composeSpan is one tag to replace: the byte range [start, end) of content.
type composeSpan struct {
	start, end int
	repl       string
}

// EditComposeImageTag rewrites the tag of the image of every requested
// service and nothing else. It never edits part of the set: when any service
// fails any check, no edit is returned.
//
// Only a restricted subset of Compose files is edited. The file must be one
// YAML document; the image of each target must be a plain, single-quoted or
// double-quoted string without "$", digest, anchor, alias, tag or merge key,
// and the services must not use include, extends or build. Flow mappings
// ("web: {image: nginx:1.25.3}") are edited like block mappings, because the
// scalar's position is located and verified in the source bytes either way.
// A reference written without a tag is refused rather than given one.
//
// The result is verified before it is returned: bytes outside the replaced
// tags are identical, and a re-parse differs from the original exactly at
// the target images, which hold the new values.
func EditComposeImageTag(req ComposeEditRequest) (res ComposeEdit, prob *ComposeEditProblem) {
	defer func() {
		if r := recover(); r != nil {
			res, prob = ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "internal error while editing: %v", r)
		}
	}()

	services := dedupeSorted(req.Services)
	if len(services) == 0 {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "no target service")
	}
	for _, s := range services {
		if s == "" {
			return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "empty service name")
		}
	}
	if !composeTagRE.MatchString(req.NewTag) {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "%q is not a valid tag", req.NewTag)
	}
	curKey, ok := inventory.RepositoryKey(req.Current)
	if !ok {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "running image %q is not a well-formed reference", req.Current)
	}
	curTag := inventory.TagOf(req.Current)
	if curTag == "" || inventory.DigestOf(req.Current) != "" {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "running image %q needs an explicit tag and no digest", req.Current)
	}

	if req.NewTag == curTag {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "the new tag equals the running tag %q; there is nothing to change", curTag)
	}

	content := req.Content
	if bytes.HasPrefix(content, []byte{0xFF, 0xFE}) || bytes.HasPrefix(content, []byte{0xFE, 0xFF}) {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "UTF-16 files are not edited")
	}
	root, prob := parseComposeDocument(content)
	if prob != nil {
		return ComposeEdit{}, prob
	}
	if prob := checkComposeDuplicateKeys(root); prob != nil {
		return ComposeEdit{}, prob
	}
	if root.Anchor != "" {
		return ComposeEdit{}, composeProblem(ReasonComposeAnchorAlias, "", "the document root has an anchor")
	}
	if hasMergeKey(root) {
		return ComposeEdit{}, composeProblem(ReasonComposeMergeKey, "", "the document root has a merge key")
	}
	if mapValue(root, "include") != nil {
		return ComposeEdit{}, composeProblem(ReasonComposeIncludeExtends, "", "the file has a top-level include")
	}
	svcs := mapValue(root, "services")
	if svcs == nil {
		return ComposeEdit{}, composeProblem(ReasonComposeServiceMissing, "", "the file has no services")
	}
	if svcs.Kind == yaml.AliasNode || svcs.Anchor != "" {
		return ComposeEdit{}, composeProblem(ReasonComposeAnchorAlias, "", "services has an anchor or is an alias")
	}
	if svcs.Kind != yaml.MappingNode {
		return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "services is not a mapping")
	}
	if hasMergeKey(svcs) {
		return ComposeEdit{}, composeProblem(ReasonComposeMergeKey, "", "services has a merge key")
	}

	starts := composeLineStarts(content)
	var spans []composeSpan
	var changes []ComposeChange
	for _, name := range services {
		svc := mapValue(svcs, name)
		if svc == nil {
			return ComposeEdit{}, composeProblem(ReasonComposeServiceMissing, name, "the service is not in the file")
		}
		if svc.Kind == yaml.AliasNode || svc.Anchor != "" {
			return ComposeEdit{}, composeProblem(ReasonComposeAnchorAlias, name, "the service mapping has an anchor or is an alias")
		}
		if svc.Kind != yaml.MappingNode {
			return ComposeEdit{}, composeProblem(ReasonComposeInvalid, name, "the service is not a mapping")
		}
		if hasMergeKey(svc) {
			return ComposeEdit{}, composeProblem(ReasonComposeMergeKey, name, "the service mapping has a merge key")
		}
		if mapValue(svc, "extends") != nil {
			return ComposeEdit{}, composeProblem(ReasonComposeIncludeExtends, name, "the service uses extends")
		}
		if mapValue(svc, "build") != nil {
			return ComposeEdit{}, composeProblem(ReasonComposeBuild, name, "the service has a build section")
		}
		img := mapValue(svc, "image")
		if img == nil {
			return ComposeEdit{}, composeProblem(ReasonComposeServiceMissing, name, "the service has no image")
		}
		sp, ch, prob := planComposeImageEdit(content, starts, name, img, curKey, curTag, req.NewTag)
		if prob != nil {
			return ComposeEdit{}, prob
		}
		spans = append(spans, sp)
		changes = append(changes, ch)
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return ComposeEdit{}, composeProblem(ReasonComposeInvalid, "", "two edits overlap")
		}
	}
	out := spliceSpans(content, spans)

	if prob := verifyComposeEdit(content, out, spans, root, changes); prob != nil {
		return ComposeEdit{}, prob
	}
	return ComposeEdit{Content: out, Changes: changes}, nil
}

// planComposeImageEdit checks the image node of one target and finds the
// bytes of its tag.
func planComposeImageEdit(content []byte, starts []int, name string, img *yaml.Node, curKey, curTag, newTag string) (composeSpan, ComposeChange, *ComposeEditProblem) {
	var zeroSpan composeSpan
	var zeroChange ComposeChange
	fail := func(r Reason, format string, args ...any) (composeSpan, ComposeChange, *ComposeEditProblem) {
		return zeroSpan, zeroChange, composeProblem(r, name, format, args...)
	}
	switch {
	case img.Kind == yaml.AliasNode || img.Anchor != "":
		return fail(ReasonComposeAnchorAlias, "the image has an anchor or is an alias")
	case img.Kind != yaml.ScalarNode:
		return fail(ReasonComposeNotString, "the image is not a scalar")
	case img.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return fail(ReasonComposeBlockScalar, "the image is a block scalar")
	case img.Style&yaml.TaggedStyle != 0:
		return fail(ReasonComposeNotString, "the image has an explicit tag")
	case img.Tag != "!!str":
		return fail(ReasonComposeNotString, "the image is not a string (%s)", img.Tag)
	}
	value := img.Value
	if strings.Contains(value, "$") {
		return fail(ReasonComposeVariable, "the image %q contains a variable", value)
	}
	repo, ok := inventory.RepositoryOf(value)
	if !ok {
		return fail(ReasonComposeInvalid, "the image %q is not a well-formed reference", value)
	}
	if inventory.DigestOf(value) != "" || strings.Contains(value, "@") {
		return fail(ReasonComposeDigest, "the image %q carries a digest", value)
	}
	key, _ := inventory.RepositoryKey(value)
	if key != curKey {
		return fail(ReasonComposeSourceMismatch, "the file names repository %q, not the running image's", repo)
	}
	tag := inventory.TagOf(value)
	if tag == "" {
		return fail(ReasonComposeSourceMismatch, "the image %q has no explicit tag", value)
	}
	if tag != curTag {
		return fail(ReasonComposeSourceMismatch, "the file has tag %q, the running image has %q", tag, curTag)
	}
	if !strings.HasSuffix(value, ":"+tag) {
		return fail(ReasonComposeInvalid, "the image %q does not end in its tag", value)
	}

	var raw string
	quote := 0
	switch {
	case img.Style&yaml.DoubleQuotedStyle != 0:
		raw, quote = `"`+value+`"`, 1
	case img.Style&yaml.SingleQuotedStyle != 0:
		raw, quote = "'"+strings.ReplaceAll(value, "'", "''")+"'", 1
	default:
		raw = value
	}
	pos, ok := locateComposeScalar(content, starts, img.Line, img.Column, raw)
	if !ok {
		return fail(ReasonComposeInvalid, "the source text of the image %q cannot be located exactly (escapes or line folding?)", value)
	}
	tagStart := pos + quote + len(value) - len(tag)
	return composeSpan{start: tagStart, end: tagStart + len(tag), repl: newTag},
		ComposeChange{
			Service:  name,
			Location: "services." + name + ".image",
			Old:      value,
			New:      value[:len(value)-len(tag)] + newTag,
		}, nil
}

// parseComposeDocument parses content as exactly one YAML document whose top
// level is a mapping.
func parseComposeDocument(content []byte) (*yaml.Node, *ComposeEditProblem) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, composeProblem(ReasonComposeInvalid, "", "the file is empty")
		}
		return nil, composeProblem(ReasonComposeInvalid, "", "the file cannot be parsed: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, composeProblem(ReasonComposeInvalid, "", "the file has more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, composeProblem(ReasonComposeInvalid, "", "the file is not one YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, composeProblem(ReasonComposeInvalid, "", "the top level is not a mapping")
	}
	return root, nil
}

// checkComposeDuplicateKeys refuses a document in which any mapping repeats
// a key.
func checkComposeDuplicateKeys(n *yaml.Node) *ComposeEditProblem {
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				continue
			}
			if seen[k.Value] {
				return composeProblem(ReasonComposeInvalid, "", "duplicate key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if p := checkComposeDuplicateKeys(c); p != nil {
			return p
		}
	}
	return nil
}

// mapValue returns the value of the scalar key in mapping m, nil when m is
// not a mapping or has no such key.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// hasMergeKey reports whether mapping m has a "<<" key.
func hasMergeKey(m *yaml.Node) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && (k.Value == "<<" || k.Tag == "!!merge") {
			return true
		}
	}
	return false
}

func dedupeSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// composeLineStarts returns the byte offset at which each line begins, using
// the line breaks the YAML parser counts: "\n", "\r\n", "\r", U+0085, U+2028
// and U+2029.
func composeLineStarts(b []byte) []int {
	starts := []int{0}
	for i := 0; i < len(b); {
		switch {
		case b[i] == '\n':
			i++
		case b[i] == '\r':
			i++
			if i < len(b) && b[i] == '\n' {
				i++
			}
		case bytes.HasPrefix(b[i:], []byte("\u0085")), bytes.HasPrefix(b[i:], []byte(" ")), bytes.HasPrefix(b[i:], []byte(" ")):
			_, w := utf8.DecodeRune(b[i:])
			i += w
		default:
			i++
			continue
		}
		starts = append(starts, i)
	}
	return starts
}

// locateComposeScalar finds the byte offset of the scalar whose source text
// is raw and which the parser placed at the 1-based line and column. The
// column counts characters, not bytes, and a leading byte order mark may or
// may not be counted, so each reading is tried; the result is accepted only
// when exactly one position holds raw.
func locateComposeScalar(content []byte, starts []int, line, column int, raw string) (int, bool) {
	if line < 1 || line > len(starts) || column < 1 || raw == "" {
		return 0, false
	}
	origins := []int{starts[line-1]}
	if line == 1 && bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}) {
		origins = append(origins, 3)
	}
	found := map[int]bool{}
	for _, o := range origins {
		cands := []int{o + column - 1}
		p := o
		for i := 0; i < column-1 && p < len(content); i++ {
			_, w := utf8.DecodeRune(content[p:])
			p += w
		}
		cands = append(cands, p)
		for _, c := range cands {
			if c >= 0 && c <= len(content) && bytes.HasPrefix(content[c:], []byte(raw)) {
				found[c] = true
			}
		}
	}
	if len(found) != 1 {
		return 0, false
	}
	for c := range found {
		return c, true
	}
	return 0, false
}

// spliceSpans replaces the spans, sorted and non-overlapping, in content.
func spliceSpans(content []byte, spans []composeSpan) []byte {
	var out []byte
	prev := 0
	for _, s := range spans {
		out = append(out, content[prev:s.start]...)
		out = append(out, s.repl...)
		prev = s.end
	}
	return append(out, content[prev:]...)
}

// verifyComposeEdit checks an edit against the original: the bytes outside
// the replaced tags are unchanged, and the edited file parses to the same
// tree except at the target images, which hold the new values.
func verifyComposeEdit(orig, edited []byte, spans []composeSpan, origRoot *yaml.Node, changes []ComposeChange) *ComposeEditProblem {
	bad := func(format string, args ...any) *ComposeEditProblem {
		return composeProblem(ReasonComposeInvalid, "", "verification of the edit failed: "+format, args...)
	}

	// Bytes outside the spans.
	oi, ei := 0, 0
	for _, s := range spans {
		gap := s.start - oi
		if ei+gap > len(edited) || !bytes.Equal(orig[oi:s.start], edited[ei:ei+gap]) {
			return bad("bytes outside the edited tags changed")
		}
		ei += gap + len(s.repl)
		oi = s.end
	}
	if !bytes.Equal(orig[oi:], edited[min(ei, len(edited)):]) {
		return bad("bytes after the last edited tag changed")
	}

	newRoot, prob := parseComposeDocument(edited)
	if prob != nil {
		return bad("the result does not parse: %s", prob.Detail)
	}
	want := map[string]string{}
	for _, c := range changes {
		want[c.Location] = c.New
	}
	var diffs []string
	diffComposeNodes(origRoot, newRoot, "", &diffs)
	if len(diffs) != len(want) {
		return bad("the result differs at %v, expected only the %d target images", diffs, len(want))
	}
	seen := map[string]bool{}
	for _, loc := range diffs {
		if _, ok := want[loc]; !ok || seen[loc] {
			return bad("the result differs at %s, which is not a target", loc)
		}
		seen[loc] = true
	}
	// Each target now holds the new value.
	for _, c := range changes {
		svcs := mapValue(newRoot, "services")
		img := mapValue(mapValue(svcs, c.Service), "image")
		if img == nil || img.Kind != yaml.ScalarNode || img.Value != c.New {
			return bad("%s does not hold %q", c.Location, c.New)
		}
	}
	return nil
}

// diffComposeNodes appends the structural path of every place where a and b
// differ in kind, style, tag, value or anchor, without descending into a
// differing node. Positions and comments are not compared.
func diffComposeNodes(a, b *yaml.Node, path string, diffs *[]string) {
	if a.Kind != b.Kind || a.Style != b.Style || a.Tag != b.Tag || a.Value != b.Value ||
		a.Anchor != b.Anchor || len(a.Content) != len(b.Content) {
		*diffs = append(*diffs, path)
		return
	}
	if a.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(a.Content); i += 2 {
			k := a.Content[i]
			diffComposeNodes(k, b.Content[i], path, diffs)
			sub := path
			if k.Kind == yaml.ScalarNode {
				if sub != "" {
					sub += "."
				}
				sub += k.Value
			}
			diffComposeNodes(a.Content[i+1], b.Content[i+1], sub, diffs)
		}
		return
	}
	for i := range a.Content {
		diffComposeNodes(a.Content[i], b.Content[i], fmt.Sprintf("%s[%d]", path, i), diffs)
	}
}
