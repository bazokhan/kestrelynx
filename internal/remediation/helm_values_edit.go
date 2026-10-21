package remediation

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons a Helm values file is not edited.
const (
	ReasonHelmInvalid         Reason = "helm_invalid"          // not one well-formed YAML document, a repeated key, or the request or the result failed verification
	ReasonHelmKeyMissing      Reason = "helm_key_missing"      // the file has no value at the key
	ReasonHelmTagFromChart    Reason = "helm_tag_from_chart"   // the key has no tag (or an empty one), so the chart's own default is used
	ReasonHelmDigest          Reason = "helm_digest"           // the image is pinned by a digest
	ReasonHelmValuesShape     Reason = "helm_values_shape"     // the key holds neither repository and tag nor a repository:tag string
	ReasonHelmNotString       Reason = "helm_not_string"       // a value is not a plain string scalar (a number, for one)
	ReasonHelmBlockScalar     Reason = "helm_block_scalar"     // a value is a block scalar
	ReasonHelmVariable        Reason = "helm_variable"         // a value contains "$"
	ReasonHelmTemplate        Reason = "helm_template"         // the file holds a template expression ("{{")
	ReasonHelmAnchorAlias     Reason = "helm_anchor_or_alias"  // an anchor or alias on a node whose edit could reach other places
	ReasonHelmMergeKey        Reason = "helm_merge_key"        // a "<<" key on the path to the image
	ReasonHelmImageAutomation Reason = "helm_image_automation" // a line of the image carries a Flux image automation marker
)

// HelmValuesEditRequest asks for the tag at one key of a Helm values file to be
// rewritten.
type HelmValuesEditRequest struct {
	Content []byte // the file as read from Git
	// Key is the dot-separated path of the image key.
	Key string
	// Current is the running reference the key must denote, with an explicit tag.
	Current string
	// Declared is the reference the Pod specs declare, which must equal Current.
	Declared string
	NewTag   string
}

// HelmValuesChange is the rewrite made.
type HelmValuesChange struct {
	// Location is the structural place: <key>.tag when the key holds a mapping,
	// <key> when it holds a repository:tag string.
	Location string
	// Repository is the repository the key denotes (registry and repository
	// joined, or the string's repository).
	Repository string
	Old, New   string // the tags
	// Quoted says the new tag was written in double quotes where the old one
	// had none, because it would not be read as a string otherwise.
	Quoted bool
}

// HelmValuesEdit is the edited file and the change made to it.
type HelmValuesEdit struct {
	Content []byte
	Change  HelmValuesChange
}

// HelmValuesEditProblem says why a file was not edited.
type HelmValuesEditProblem struct {
	Reason Reason
	Detail string
}

func (p *HelmValuesEditProblem) Error() string { return fmt.Sprintf("%s: %s", p.Reason, p.Detail) }

func helmProblem(r Reason, format string, args ...any) *HelmValuesEditProblem {
	return &HelmValuesEditProblem{Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// helmImageMapKeys are the keys of an image mapping this code reads; the
// others (pullPolicy and the like) are left alone, except those that show the
// image is described in another way (helmForeignKeys).
var helmForeignKeys = map[string]bool{"name": true, "image": true}

// EditHelmValuesTag rewrites the tag at the named key of a values file and
// nothing else. The key must hold a mapping with repository and tag (and
// optionally registry), or a "repository:tag" string. The file must be one
// YAML document without a repeated key, anchor, alias or merge key on the path,
// and without "{{"; the tag must be a plain, single-quoted or double-quoted
// string without "$", and no digest may be set. The repository (joined with the
// registry when there is one) with the tag must be the reference the Pod specs
// declare and the containers run.
//
// The result is verified: bytes outside the replaced tag are identical, the
// result parses to the same tree except at the tag, which holds the new value,
// and no mapping repeats a key.
func EditHelmValuesTag(req HelmValuesEditRequest) (res HelmValuesEdit, prob *HelmValuesEditProblem) {
	defer func() {
		if r := recover(); r != nil {
			res, prob = HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "internal error while editing: %v", r)
		}
	}()
	if req.Key == "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "no key")
	}
	if !composeTagRE.MatchString(req.NewTag) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "%q is not a valid tag", req.NewTag)
	}
	if _, ok := inventory.RepositoryKey(req.Current); !ok {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "running image %q is not a well-formed reference", req.Current)
	}
	curTag := inventory.TagOf(req.Current)
	if curTag == "" || inventory.DigestOf(req.Current) != "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "running image %q needs an explicit tag and no digest", req.Current)
	}
	if req.NewTag == curTag {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "the new tag equals the running tag %q; there is nothing to change", curTag)
	}
	if !sameReference(req.Declared, req.Current) {
		return HelmValuesEdit{}, helmProblem(ReasonSourceMismatch, "the declared image %q is not the running image %q", req.Declared, req.Current)
	}

	content := req.Content
	if bytes.HasPrefix(content, []byte{0xFF, 0xFE}) || bytes.HasPrefix(content, []byte{0xFE, 0xFF}) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "UTF-16 files are not edited")
	}
	if bytes.Contains(content, []byte("{{")) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmTemplate, "the file holds a template expression, so what it produces depends on a rendering that is not done here")
	}
	root, kp := parseKustomizeDocument(content)
	if kp != nil {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "%s", kp.Detail)
	}
	if p := checkComposeDuplicateKeys(root); p != nil {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "%s", p.Detail)
	}
	if root.Anchor != "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmAnchorAlias, "the document root has an anchor")
	}
	if hasMergeKey(root) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmMergeKey, "the document root has a merge key")
	}

	if p := checkHelmKeys(root); p != nil {
		return HelmValuesEdit{}, p
	}

	// The path to the key: every node on it a plain mapping.
	node := root
	segs := strings.Split(req.Key, ".")
	for i, seg := range segs {
		if hasMergeKey(node) {
			return HelmValuesEdit{}, helmProblem(ReasonHelmMergeKey, "the mapping above %q has a merge key", seg)
		}
		if p := checkStringKeys(node, strings.Join(segs[:i], ".")); p != nil {
			return HelmValuesEdit{}, p
		}
		next := mapValue(node, seg)
		if next == nil {
			return HelmValuesEdit{}, helmProblem(ReasonHelmKeyMissing, "the file has no %q (at %q)", req.Key, strings.Join(segs[:i+1], "."))
		}
		if next.Kind == yaml.AliasNode || next.Anchor != "" {
			return HelmValuesEdit{}, helmProblem(ReasonHelmAnchorAlias, "%q has an anchor or is an alias", strings.Join(segs[:i+1], "."))
		}
		node = next
	}

	switch node.Kind {
	case yaml.MappingNode:
		return editHelmImageMapping(content, root, node, req, curTag)
	case yaml.ScalarNode:
		return editHelmImageString(content, root, node, req, curTag)
	}
	return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q holds neither a mapping with repository and tag nor a repository:tag string", req.Key)
}

// helmString reads a plain, single-quoted or double-quoted string scalar.
func helmString(n *yaml.Node, what string) (string, *HelmValuesEditProblem) {
	switch {
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		return "", helmProblem(ReasonHelmAnchorAlias, "%s has an anchor or is an alias", what)
	case n.Kind != yaml.ScalarNode:
		return "", helmProblem(ReasonHelmNotString, "%s is not a scalar", what)
	case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return "", helmProblem(ReasonHelmBlockScalar, "%s is a block scalar", what)
	case n.Style&yaml.TaggedStyle != 0:
		return "", helmProblem(ReasonHelmNotString, "%s has an explicit tag", what)
	case n.Tag != "!!str":
		return "", helmProblem(ReasonHelmNotString, "%s is not read as a string (%s); a number is quoted to keep it one", what, n.Tag)
	case strings.Contains(n.Value, "$"):
		return "", helmProblem(ReasonHelmVariable, "%s %q contains a variable", what, n.Value)
	}
	return n.Value, nil
}

// helmMarkerOnLine refuses a Flux image automation marker on the line of n.
func helmMarkerOnLine(content []byte, n *yaml.Node, what string) *HelmValuesEditProblem {
	starts := composeLineStarts(content)
	if n.Line < 1 || n.Line > len(starts) {
		return nil
	}
	end := len(content)
	if n.Line < len(starts) {
		end = starts[n.Line]
	}
	if bytes.Contains(content[starts[n.Line-1]:end], []byte("$imagepolicy")) {
		return helmProblem(ReasonHelmImageAutomation, "the line of %s carries a Flux image automation marker, so another tool owns the tag", what)
	}
	return nil
}

func editHelmImageMapping(content []byte, root, m *yaml.Node, req HelmValuesEditRequest, curTag string) (HelmValuesEdit, *HelmValuesEditProblem) {
	if p := checkEditableHelmMapping(m, req.Key); p != nil {
		return HelmValuesEdit{}, p
	}
	if p := checkStringKeys(m, req.Key); p != nil {
		return HelmValuesEdit{}, p
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; helmForeignKeys[k.Value] {
			return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q has a %q key, so the image is not described by repository and tag alone", req.Key, k.Value)
		}
	}
	if d := mapValue(m, "digest"); d != nil {
		s, p := helmString(d, req.Key+".digest")
		if p != nil {
			return HelmValuesEdit{}, p
		}
		if s != "" {
			return HelmValuesEdit{}, helmProblem(ReasonHelmDigest, "%q pins a digest, which is not updated", req.Key)
		}
	}
	repoNode := mapValue(m, "repository")
	if repoNode == nil {
		return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q has no repository", req.Key)
	}
	repo, p := helmString(repoNode, req.Key+".repository")
	if p != nil {
		return HelmValuesEdit{}, p
	}
	registry := ""
	var regNode *yaml.Node
	if regNode = mapValue(m, "registry"); regNode != nil {
		if registry, p = helmString(regNode, req.Key+".registry"); p != nil {
			return HelmValuesEdit{}, p
		}
	}
	if repo == "" || strings.Contains(repo, "@") || inventory.TagOf(repo) != "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q.repository %q is not a repository without a tag or a digest", req.Key, repo)
	}
	effective := repo
	if registry != "" {
		if strings.ContainsAny(registry, "@ \t") {
			return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q.registry %q is not a registry host", req.Key, registry)
		}
		effective = strings.TrimSuffix(registry, "/") + "/" + repo
	}
	tagNode := mapValue(m, "tag")
	if tagNode == nil {
		return HelmValuesEdit{}, helmProblem(ReasonHelmTagFromChart, "%q has no tag, so the chart's own default (its appVersion) is used, which a values file edit cannot change", req.Key)
	}
	tag, p := helmString(tagNode, req.Key+".tag")
	if p != nil {
		return HelmValuesEdit{}, p
	}
	if tag == "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmTagFromChart, "%q has an empty tag, so the chart's own default (its appVersion) is used, which a values file edit cannot change", req.Key)
	}
	if !composeTagRE.MatchString(tag) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "tag %q is not a valid tag", tag)
	}
	for _, n := range []struct {
		node *yaml.Node
		what string
	}{{tagNode, req.Key + ".tag"}, {repoNode, req.Key + ".repository"}, {regNode, req.Key + ".registry"}} {
		if n.node != nil {
			if p := helmMarkerOnLine(content, n.node, n.what); p != nil {
				return HelmValuesEdit{}, p
			}
		}
	}
	ref := effective + ":" + tag
	if _, ok := inventory.RepositoryKey(ref); !ok {
		return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q does not make a well-formed image reference", ref)
	}
	if !sameReference(ref, req.Current) || !sameReference(ref, req.Declared) {
		return HelmValuesEdit{}, helmProblem(ReasonSourceMismatch, "the values give %q, the pod specs declare %q and the containers run %q", ref, req.Declared, req.Current)
	}
	// Helm reads the file the YAML 1.1 way: an unquoted tag that looks like a
	// number or a boolean is not a string there, whatever this parser says.
	unquoted := tagNode.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0
	if unquoted && !staysString(tag) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmNotString, "%s.tag %q is not written in quotes and would be read as something other than a string", req.Key, tag)
	}
	span, p := helmTagSpan(content, tagNode, tag, req.NewTag)
	if p != nil {
		return HelmValuesEdit{}, p
	}
	change := HelmValuesChange{Location: req.Key + ".tag", Repository: effective, Old: tag, New: req.NewTag}
	if unquoted && !staysString(req.NewTag) {
		// Written in double quotes, which keep it a string.
		span.repl = `"` + req.NewTag + `"`
		change.Quoted = true
	}
	return finishHelmEdit(content, root, span, req, change)
}

func editHelmImageString(content []byte, root, n *yaml.Node, req HelmValuesEditRequest, curTag string) (HelmValuesEdit, *HelmValuesEditProblem) {
	value, p := helmString(n, req.Key)
	if p != nil {
		return HelmValuesEdit{}, p
	}
	if strings.Contains(value, "@") || inventory.DigestOf(value) != "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmDigest, "%q carries a digest, which is not updated", req.Key)
	}
	if _, ok := inventory.RepositoryOf(value); !ok {
		return HelmValuesEdit{}, helmProblem(ReasonHelmValuesShape, "%q holds %q, which is not an image reference", req.Key, value)
	}
	tag := inventory.TagOf(value)
	if tag == "" {
		return HelmValuesEdit{}, helmProblem(ReasonHelmTagFromChart, "%q has no explicit tag", req.Key)
	}
	if !strings.HasSuffix(value, ":"+tag) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "%q does not end in its tag", value)
	}
	if p := helmMarkerOnLine(content, n, req.Key); p != nil {
		return HelmValuesEdit{}, p
	}
	if !sameReference(value, req.Current) || !sameReference(value, req.Declared) {
		return HelmValuesEdit{}, helmProblem(ReasonSourceMismatch, "the values give %q, the pod specs declare %q and the containers run %q", value, req.Declared, req.Current)
	}
	raw, quote := value, 0
	switch {
	case n.Style&yaml.DoubleQuotedStyle != 0:
		raw, quote = `"`+value+`"`, 1
	case n.Style&yaml.SingleQuotedStyle != 0:
		raw, quote = "'"+strings.ReplaceAll(value, "'", "''")+"'", 1
	}
	pos, ok := locateComposeScalar(content, composeLineStarts(content), n.Line, n.Column, raw)
	if !ok {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "the source text of %q cannot be located exactly (escapes or line folding?)", value)
	}
	start := pos + quote + len(value) - len(tag)
	span := composeSpan{start: start, end: start + len(tag), repl: req.NewTag}
	change := HelmValuesChange{Location: req.Key, Repository: strings.TrimSuffix(value, ":"+tag), Old: tag, New: req.NewTag}
	return finishHelmEdit(content, root, span, req, change)
}

// checkEditableHelmMapping refuses an image mapping that is an alias, has an
// anchor or a merge key.
func checkEditableHelmMapping(m *yaml.Node, key string) *HelmValuesEditProblem {
	if m.Kind == yaml.AliasNode || m.Anchor != "" {
		return helmProblem(ReasonHelmAnchorAlias, "%q has an anchor or is an alias", key)
	}
	if hasMergeKey(m) {
		return helmProblem(ReasonHelmMergeKey, "%q has a merge key", key)
	}
	return nil
}

// helmTagSpan finds the bytes of the tag value.
func helmTagSpan(content []byte, tagNode *yaml.Node, tag, newTag string) (composeSpan, *HelmValuesEditProblem) {
	raw, quote := tag, 0
	switch {
	case tagNode.Style&yaml.DoubleQuotedStyle != 0:
		raw, quote = `"`+tag+`"`, 1
	case tagNode.Style&yaml.SingleQuotedStyle != 0:
		raw, quote = "'"+strings.ReplaceAll(tag, "'", "''")+"'", 1
	}
	pos, ok := locateComposeScalar(content, composeLineStarts(content), tagNode.Line, tagNode.Column, raw)
	if !ok {
		return composeSpan{}, helmProblem(ReasonHelmInvalid, "the source text of the tag %q cannot be located exactly (escapes or line folding?)", tag)
	}
	start := pos + quote
	return composeSpan{start: start, end: start + len(tag), repl: newTag}, nil
}

// finishHelmEdit applies the span and verifies the result.
func finishHelmEdit(content []byte, root *yaml.Node, span composeSpan, req HelmValuesEditRequest, change HelmValuesChange) (HelmValuesEdit, *HelmValuesEditProblem) {
	out := spliceSpans(content, []composeSpan{span})
	bad := func(format string, args ...any) (HelmValuesEdit, *HelmValuesEditProblem) {
		return HelmValuesEdit{}, helmProblem(ReasonHelmInvalid, "verification of the edit failed: "+format, args...)
	}
	if !bytes.Equal(content[:span.start], out[:span.start]) || !bytes.Equal(content[span.end:], out[span.start+len(span.repl):]) {
		return bad("bytes outside the edited tag changed")
	}
	newRoot, kp := parseKustomizeDocument(out)
	if kp != nil {
		return bad("the result does not parse: %s", kp.Detail)
	}
	if p := checkComposeDuplicateKeys(newRoot); p != nil {
		return bad("the result has %s", p.Detail)
	}
	var diffs []string
	diffComposeNodes(root, newRoot, "", &diffs)
	if len(diffs) != 1 || diffs[0] != req.Key {
		// diffComposeNodes reports the path of the differing node; for the
		// mapping form that is <key>.tag.
		if !(len(diffs) == 1 && diffs[0] == change.Location) {
			return bad("the result differs at %v, expected only %s", diffs, change.Location)
		}
	}
	node := newRoot
	for _, seg := range strings.Split(req.Key, ".") {
		node = mapValue(node, seg)
		if node == nil {
			return bad("%s is gone from the result", req.Key)
		}
	}
	if node.Kind == yaml.MappingNode {
		node = mapValue(node, "tag")
		if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value != change.New {
			return bad("the tag is not the string %q", change.New)
		}
		if node.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0 && !staysString(change.New) {
			return bad("the tag %q would not be read as a string", change.New)
		}
	} else if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || !strings.HasSuffix(node.Value, ":"+change.New) {
		return bad("%s is not a string ending in %q", req.Key, change.New)
	}
	return HelmValuesEdit{Content: out, Change: change}, nil
}

// checkHelmKeys refuses a mapping key anywhere in the document that is an alias
// or is not a plain scalar: an aliased key resolves to a name this code does
// not see, and could shadow or repeat the key it edits.
func checkHelmKeys(n *yaml.Node) *HelmValuesEditProblem {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			switch {
			case k.Kind == yaml.AliasNode:
				return helmProblem(ReasonHelmAnchorAlias, "a mapping key (line %d) is an alias, which resolves to a name that is not read here", k.Line)
			case k.Kind != yaml.ScalarNode:
				return helmProblem(ReasonHelmInvalid, "a mapping key (line %d) is not a plain scalar", k.Line)
			}
		}
	}
	for _, c := range n.Content {
		if p := checkHelmKeys(c); p != nil {
			return p
		}
	}
	return nil
}

// checkStringKeys requires every key of a mapping on the path to the image, and
// of the image mapping, to be a plain string as Helm reads it. Helm reads YAML
// 1.1, where an unquoted on, yes, 1 or ~ is not a string, so two spellings can
// be one key there ("true" and on are both true); an unquoted key that is not
// a string for Helm is refused, and so are two keys that Helm resolves to one.
func checkStringKeys(m *yaml.Node, where string) *HelmValuesEditProblem {
	resolved := map[string]string{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
			return helmProblem(ReasonHelmInvalid, "the mapping at %q has a key (line %d) that is not a plain string or has an anchor", where, k.Line)
		}
		quoted := k.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0
		id := k.Value
		if !quoted && !staysString(k.Value) {
			// What Helm reads it as: the boolean and null words each have one
			// identity, so that "true" and on, or null and ~, meet.
			id = yaml11Identity(k.Value)
			if first, dup := resolved[id]; dup {
				return helmProblem(ReasonHelmInvalid, "the mapping at %q has the keys %q and %q (line %d), which Helm resolves to one key", where, first, k.Value, k.Line)
			}
			resolved[id] = k.Value
			return helmProblem(ReasonHelmInvalid, "the mapping at %q has the unquoted key %q (line %d), which Helm does not read as a string", where, k.Value, k.Line)
		}
		if first, dup := resolved[id]; dup {
			return helmProblem(ReasonHelmInvalid, "the mapping at %q has the keys %q and %q (line %d), which Helm resolves to one key", where, first, k.Value, k.Line)
		}
		resolved[id] = k.Value
	}
	return nil
}

// yaml11Identity names the key an unquoted scalar becomes for Helm when it is
// not a string. Helm turns every key into text, so on is the key "true", ~ is
// "null", and the quoted key "true" is the same key.
func yaml11Identity(s string) string {
	switch strings.ToLower(s) {
	case "y", "yes", "on", "true":
		return "true"
	case "n", "no", "off", "false":
		return "false"
	case "null", "~", "":
		return "null"
	}
	return s
}

var (
	yaml11Words   = map[string]bool{"y": true, "n": true, "yes": true, "no": true, "on": true, "off": true, "true": true, "false": true, "null": true, "~": true}
	yaml11Number  = regexp.MustCompile(`^[-+]?([0-9][0-9_]*)?(\.[0-9_]*)?([eE][-+]?[0-9]+)?$`)
	yaml11Special = regexp.MustCompile(`(?i)^(0[xob][0-9a-f_]+|[-+]?\.(inf|nan)|[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}.*)$`)
)

// staysString reports whether an unquoted scalar with the value s is a string
// under YAML 1.2 as this parser reads it and under YAML 1.1 as Helm reads it:
// not a boolean or null word in any case, not a number in any base, not a
// timestamp.
func staysString(s string) bool {
	if s == "" || yaml11Words[strings.ToLower(s)] {
		return false
	}
	if (yaml11Number.MatchString(s) && strings.ContainsAny(s, "0123456789")) || yaml11Special.MatchString(s) {
		return false
	}
	var n yaml.Node
	if err := yaml.Unmarshal([]byte("k: "+s+"\n"), &n); err != nil || len(n.Content) == 0 || n.Content[0].Kind != yaml.MappingNode || len(n.Content[0].Content) < 2 {
		return false
	}
	v := n.Content[0].Content[1]
	return v.Kind == yaml.ScalarNode && v.Tag == "!!str" && v.Value == s
}
