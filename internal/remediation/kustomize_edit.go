package remediation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons a kustomization file is not edited.
const (
	ReasonKustomizeInvalid         Reason = "kustomize_invalid"             // not one well-formed YAML document, a repeated key, or the request or the result failed verification
	ReasonKustomizeImageMissing    Reason = "kustomize_image_missing"       // the file has no images entry of that name
	ReasonKustomizeImageAmbiguous  Reason = "kustomize_image_ambiguous"     // more than one images entry has that name
	ReasonKustomizeTagNotSet       Reason = "kustomize_tag_not_set"         // the entry has no newTag
	ReasonKustomizeUnsupported     Reason = "kustomize_unsupported_feature" // the file uses a feature that can change what an entry acts on
	ReasonKustomizeDigest          Reason = "kustomize_digest"              // the entry pins a digest
	ReasonKustomizeAnchorAlias     Reason = "kustomize_anchor_or_alias"     // an anchor or alias on a node whose edit could reach other places
	ReasonKustomizeMergeKey        Reason = "kustomize_merge_key"           // a "<<" key on the path to the entry
	ReasonKustomizeNotString       Reason = "kustomize_not_string"          // a value is not a plain string scalar (a number, for one)
	ReasonKustomizeBlockScalar     Reason = "kustomize_block_scalar"        // a value is a block scalar
	ReasonKustomizeVariable        Reason = "kustomize_variable"            // a value contains "$"
	ReasonKustomizeTemplate        Reason = "kustomize_template"            // the file holds a template expression ("{{")
	ReasonKustomizeImageChained    Reason = "kustomize_image_chained"       // another images entry acts on the entry's name or on its result
	ReasonKustomizeImageAutomation Reason = "kustomize_image_automation"    // the line carries a Flux image automation marker
)

// kustomizeUnsupported are the top-level keys that can change which
// containers an images entry acts on or what its result is, so that the entry
// the file shows is not the one the cluster gets.
var kustomizeUnsupported = map[string]bool{
	"replacements": true, "patches": true, "patchesStrategicMerge": true, "patchesJson6902": true,
	"components": true, "imageTags": true, "helmCharts": true, "helmGlobals": true, "generators": true, "transformers": true, "vars": true,
}

// kustomizeRemoteRE matches a resource that is fetched rather than read from
// the repository: a URL, an scp-style address, or a host-style path.
var kustomizeRemoteRE = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*://|git@|[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+/)|\?ref=|\.git(/|$)`)

// KustomizeEditRequest asks for the newTag of one images entry of a
// kustomization file to be rewritten.
type KustomizeEditRequest struct {
	Content []byte // the file as read from Git
	Image   string // the name of the images entry
	Current string // the running reference the entry must denote, with an explicit tag
	// Declared is the reference the Pod specs declare, which must equal Current.
	Declared string
	NewTag   string
}

// KustomizeChange is the rewrite made.
type KustomizeChange struct {
	// Location is the structural place, images[<name>].newTag.
	Location string
	// Repository is the repository the entry's result names (newName, or the
	// name when there is none).
	Repository string
	Old, New   string // the tags
}

// KustomizeEdit is the edited file and the change made to it.
type KustomizeEdit struct {
	Content []byte
	Change  KustomizeChange
}

// KustomizeEditProblem says why a file was not edited.
type KustomizeEditProblem struct {
	Reason Reason
	Detail string
}

func (p *KustomizeEditProblem) Error() string { return fmt.Sprintf("%s: %s", p.Reason, p.Detail) }

func kustomizeProblem(r Reason, format string, args ...any) *KustomizeEditProblem {
	return &KustomizeEditProblem{Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// KustomizeLocation is the location of an images entry's tag.
func KustomizeLocation(image string) string { return "images[" + image + "].newTag" }

// EditKustomizeNewTag rewrites the newTag of the images entry named Image and
// nothing else. The file must be one YAML document without a repeated key;
// the entry's name must be the only one of its name, it must have a newTag
// that is a plain, single-quoted or double-quoted string without "$", no
// digest, and its result (newName, or the name, with the newTag) must be the
// reference the Pod specs declare and the container runs. Features that can
// change what an entry acts on or what the file produces (patches,
// replacements, components, helm charts, remote resources) are refused.
//
// The result is verified: bytes outside the replaced tag are identical, the
// result parses to the same tree except at the tag, which holds the new
// value, and no mapping repeats a key.
func EditKustomizeNewTag(req KustomizeEditRequest) (res KustomizeEdit, prob *KustomizeEditProblem) {
	defer func() {
		if r := recover(); r != nil {
			res, prob = KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "internal error while editing: %v", r)
		}
	}()
	if req.Image == "" {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "no images entry name")
	}
	if !composeTagRE.MatchString(req.NewTag) {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "%q is not a valid tag", req.NewTag)
	}
	if _, ok := inventory.RepositoryKey(req.Current); !ok {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "running image %q is not a well-formed reference", req.Current)
	}
	curTag := inventory.TagOf(req.Current)
	if curTag == "" || inventory.DigestOf(req.Current) != "" {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "running image %q needs an explicit tag and no digest", req.Current)
	}
	if req.NewTag == curTag {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "the new tag equals the running tag %q; there is nothing to change", curTag)
	}
	if !sameReference(req.Declared, req.Current) {
		return KustomizeEdit{}, kustomizeProblem(ReasonSourceMismatch, "the declared image %q is not the running image %q", req.Declared, req.Current)
	}

	content := req.Content
	if bytes.HasPrefix(content, []byte{0xFF, 0xFE}) || bytes.HasPrefix(content, []byte{0xFE, 0xFF}) {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "UTF-16 files are not edited")
	}
	if bytes.Contains(content, []byte("{{")) {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeTemplate, "the file holds a template expression, so what it produces depends on a rendering that is not done here")
	}
	root, prob := parseKustomizeDocument(content)
	if prob != nil {
		return KustomizeEdit{}, prob
	}
	if p := checkComposeDuplicateKeys(root); p != nil {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "%s", p.Detail)
	}
	if root.Anchor != "" {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeAnchorAlias, "the document root has an anchor")
	}
	if hasMergeKey(root) {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeMergeKey, "the document root has a merge key")
	}
	if p := checkKustomizeFieldSpelling(root, kustomizeFields, "the file"); p != nil {
		return KustomizeEdit{}, p
	}
	if p := checkKustomizeFeatures(root); p != nil {
		return KustomizeEdit{}, p
	}

	images := mapValue(root, "images")
	if images == nil {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeImageMissing, "the file has no images list; if the tag is set in the manifest, map it with manifest")
	}
	if images.Kind == yaml.AliasNode || images.Anchor != "" {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeAnchorAlias, "images has an anchor or is an alias")
	}
	if images.Kind != yaml.SequenceNode {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "images is not a list")
	}
	// Every entry is read before one is chosen: a name or an output name that
	// cannot be read as a plain string, or a field spelled the way Kustomize
	// reads but this code does not, would hide an entry from the search.
	type imageEntry struct {
		name, newName string
		tag           string
		node          *yaml.Node
	}
	var entries []imageEntry
	for i, e := range images.Content {
		if e.Kind == yaml.AliasNode || e.Anchor != "" {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeAnchorAlias, "images[%d] has an anchor or is an alias", i)
		}
		if e.Kind != yaml.MappingNode {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "images[%d] is not a mapping", i)
		}
		if hasMergeKey(e) {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeMergeKey, "images[%d] has a merge key", i)
		}
		if p := checkKustomizeFieldSpelling(e, kustomizeImageFields, fmt.Sprintf("images[%d]", i)); p != nil {
			return KustomizeEdit{}, p
		}
		nameNode := mapValue(e, "name")
		if nameNode == nil {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "images[%d] has no name", i)
		}
		name, p := kustomizeStringValue(nameNode, fmt.Sprintf("the name of images[%d]", i))
		if p != nil {
			return KustomizeEdit{}, p
		}
		ie := imageEntry{name: name, node: e}
		if nn := mapValue(e, "newName"); nn != nil {
			if ie.newName, p = kustomizeStringValue(nn, fmt.Sprintf("the newName of images[%d]", i)); p != nil {
				return KustomizeEdit{}, p
			}
		}
		if t := mapValue(e, "newTag"); t != nil {
			if t.Kind == yaml.ScalarNode && t.Anchor == "" {
				ie.tag = t.Value
			}
		}
		entries = append(entries, ie)
	}
	// Kustomize puts an entry's name into a regular expression unescaped, so
	// a name that is not one cannot be judged, and the target's own must compile.
	for i, e := range entries {
		if _, err := regexp.Compile("^" + e.name + "(@sha256)?(:[a-zA-Z0-9_.{}-]*)?$"); err != nil {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "the name of images[%d] (%q) is not a valid regular expression, which Kustomize matches image names with: %v", i, e.name, err)
		}
	}
	index, entry := -1, (*yaml.Node)(nil)
	for i, e := range entries {
		if e.name != req.Image {
			continue
		}
		if entry != nil {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeImageAmbiguous, "more than one images entry is named %q", req.Image)
		}
		index, entry = i, e.node
	}
	if entry == nil {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeImageMissing, "the file has no images entry named %q; if the tag is set in the manifest, map it with manifest", req.Image)
	}

	if d := mapValue(entry, "digest"); d != nil {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeDigest, "the entry %q pins a digest, which is not updated", req.Image)
	}
	repo, p := kustomizeEntryRepository(entry, req.Image)
	if p != nil {
		return KustomizeEdit{}, p
	}
	// Kustomize applies every entry to the result of the ones before it, and an
	// entry that renames to this one's name, or that matches the name this
	// entry's result has, would act on what this edit sets.
	for i, e := range entries {
		if i == index {
			continue
		}
		if why, err := kustomizeInterference(e.name, e.newName, e.tag, req.Image, repo, curTag, req.NewTag); err != nil {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeInvalid, "images[%d]: %v", i, err)
		} else if why != "" {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeImageChained, "images[%d] (name %q): %s", i, e.name, why)
		}
		if sameImageName(e.name, repo) || (e.newName != "" && (sameImageName(e.newName, req.Image) || sameImageName(e.newName, repo))) {
			return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeImageChained,
				"images[%d] (name %q, newName %q) acts on the name %q the entry %q has or produces, so its tag is not the file's last word", i, e.name, e.newName, repo, req.Image)
		}
	}
	tagNode := mapValue(entry, "newTag")
	if tagNode == nil {
		return KustomizeEdit{}, kustomizeProblem(ReasonKustomizeTagNotSet, "the entry %q has no newTag", req.Image)
	}
	span, change, p := planKustomizeTagEdit(content, tagNode, repo, req)
	if p != nil {
		return KustomizeEdit{}, p
	}
	change.Location = KustomizeLocation(req.Image)
	out := spliceSpans(content, []composeSpan{span})
	if p := verifyKustomizeEdit(content, out, span, root, index, change); p != nil {
		return KustomizeEdit{}, p
	}
	return KustomizeEdit{Content: out, Change: change}, nil
}

// parseKustomizeDocument parses content as exactly one YAML document whose
// top level is a mapping.
func parseKustomizeDocument(content []byte) (*yaml.Node, *KustomizeEditProblem) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, kustomizeProblem(ReasonKustomizeInvalid, "the file is empty")
		}
		return nil, kustomizeProblem(ReasonKustomizeInvalid, "the file cannot be parsed: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, kustomizeProblem(ReasonKustomizeInvalid, "the file has more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, kustomizeProblem(ReasonKustomizeInvalid, "the file is not one YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, kustomizeProblem(ReasonKustomizeInvalid, "the top level is not a mapping")
	}
	return root, nil
}

// checkKustomizeFeatures refuses the top-level keys that can change what an
// images entry acts on, and resources fetched from elsewhere.
func checkKustomizeFeatures(root *yaml.Node) *KustomizeEditProblem {
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Kind == yaml.ScalarNode && kustomizeUnsupported[k.Value] {
			return kustomizeProblem(ReasonKustomizeUnsupported, "the file uses %s, which can change what an images entry acts on", k.Value)
		}
	}
	for _, key := range []string{"resources", "bases"} {
		list := mapValue(root, key)
		if list == nil {
			continue
		}
		if list.Kind != yaml.SequenceNode {
			return kustomizeProblem(ReasonKustomizeUnsupported, "%s is not a list of local paths", key)
		}
		for _, r := range list.Content {
			if r.Kind != yaml.ScalarNode || kustomizeRemoteRE.MatchString(r.Value) {
				return kustomizeProblem(ReasonKustomizeUnsupported, "%s names a resource that is not a local path (%q), whose images cannot be seen", key, r.Value)
			}
		}
	}
	return nil
}

// kustomizeEntryRepository reads the repository the entry's result names:
// newName when it is set, the name otherwise. Both must be plain strings
// without "$" or a digest.
func kustomizeEntryRepository(entry *yaml.Node, name string) (string, *KustomizeEditProblem) {
	repo := name
	if v := mapValue(entry, "newName"); v != nil {
		s, p := kustomizeStringValue(v, "newName")
		if p != nil {
			return "", p
		}
		if s != "" {
			repo = s
		}
	}
	if strings.ContainsAny(repo, "@") || inventory.DigestOf(repo) != "" {
		return "", kustomizeProblem(ReasonKustomizeDigest, "the entry's image name %q carries a digest", repo)
	}
	if _, ok := inventory.RepositoryOf(repo); !ok || inventory.TagOf(repo) != "" {
		return "", kustomizeProblem(ReasonKustomizeInvalid, "the entry's image name %q is not a repository without a tag", repo)
	}
	return repo, nil
}

// kustomizeStringValue reads a plain, single-quoted or double-quoted string
// scalar.
func kustomizeStringValue(n *yaml.Node, what string) (string, *KustomizeEditProblem) {
	switch {
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		return "", kustomizeProblem(ReasonKustomizeAnchorAlias, "%s has an anchor or is an alias", what)
	case n.Kind != yaml.ScalarNode:
		return "", kustomizeProblem(ReasonKustomizeNotString, "%s is not a scalar", what)
	case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return "", kustomizeProblem(ReasonKustomizeBlockScalar, "%s is a block scalar", what)
	case n.Style&yaml.TaggedStyle != 0:
		return "", kustomizeProblem(ReasonKustomizeNotString, "%s has an explicit tag", what)
	case n.Tag != "!!str":
		return "", kustomizeProblem(ReasonKustomizeNotString, "%s is not read as a string (%s); quote it", what, n.Tag)
	case strings.Contains(n.Value, "$"):
		return "", kustomizeProblem(ReasonKustomizeVariable, "%s %q contains a variable", what, n.Value)
	}
	return n.Value, nil
}

// planKustomizeTagEdit checks the newTag node and finds the bytes of its
// value.
func planKustomizeTagEdit(content []byte, tag *yaml.Node, repo string, req KustomizeEditRequest) (composeSpan, KustomizeChange, *KustomizeEditProblem) {
	if tag.Line >= 1 {
		starts := composeLineStarts(content)
		if tag.Line <= len(starts) {
			end := len(content)
			if tag.Line < len(starts) {
				end = starts[tag.Line]
			}
			if bytes.Contains(content[starts[tag.Line-1]:end], []byte("$imagepolicy")) {
				return composeSpan{}, KustomizeChange{}, kustomizeProblem(ReasonKustomizeImageAutomation, "the line of newTag carries a Flux image automation marker, so another tool owns the tag")
			}
		}
	}
	value, p := kustomizeStringValue(tag, "newTag")
	if p != nil {
		return composeSpan{}, KustomizeChange{}, p
	}
	if value == "" {
		return composeSpan{}, KustomizeChange{}, kustomizeProblem(ReasonKustomizeTagNotSet, "newTag is empty")
	}
	if !composeTagRE.MatchString(value) {
		return composeSpan{}, KustomizeChange{}, kustomizeProblem(ReasonKustomizeInvalid, "newTag %q is not a valid tag", value)
	}
	effective := repo + ":" + value
	if !sameReference(effective, req.Current) || !sameReference(effective, req.Declared) {
		return composeSpan{}, KustomizeChange{}, kustomizeProblem(ReasonSourceMismatch,
			"the entry gives %q, the pod specs declare %q and the containers run %q", effective, req.Declared, req.Current)
	}
	raw, quote := value, 0
	switch {
	case tag.Style&yaml.DoubleQuotedStyle != 0:
		raw, quote = `"`+value+`"`, 1
	case tag.Style&yaml.SingleQuotedStyle != 0:
		raw, quote = "'"+strings.ReplaceAll(value, "'", "''")+"'", 1
	}
	pos, ok := locateComposeScalar(content, composeLineStarts(content), tag.Line, tag.Column, raw)
	if !ok {
		return composeSpan{}, KustomizeChange{}, kustomizeProblem(ReasonKustomizeInvalid, "the source text of newTag %q cannot be located exactly (escapes or line folding?)", value)
	}
	start := pos + quote
	return composeSpan{start: start, end: start + len(value), repl: req.NewTag},
		KustomizeChange{Repository: repo, Old: value, New: req.NewTag}, nil
}

// verifyKustomizeEdit checks an edit against the original.
func verifyKustomizeEdit(orig, edited []byte, span composeSpan, origRoot *yaml.Node, index int, change KustomizeChange) *KustomizeEditProblem {
	bad := func(format string, args ...any) *KustomizeEditProblem {
		return kustomizeProblem(ReasonKustomizeInvalid, "verification of the edit failed: "+format, args...)
	}
	if !bytes.Equal(orig[:span.start], edited[:span.start]) {
		return bad("bytes before the edited tag changed")
	}
	if !bytes.Equal(orig[span.end:], edited[span.start+len(span.repl):]) {
		return bad("bytes after the edited tag changed")
	}
	newRoot, prob := parseKustomizeDocument(edited)
	if prob != nil {
		return bad("the result does not parse: %s", prob.Detail)
	}
	if p := checkComposeDuplicateKeys(newRoot); p != nil {
		return bad("the result has %s", p.Detail)
	}
	var diffs []string
	diffComposeNodes(origRoot, newRoot, "", &diffs)
	want := fmt.Sprintf("images[%d].newTag", index)
	if len(diffs) != 1 || diffs[0] != want {
		return bad("the result differs at %v, expected only %s", diffs, want)
	}
	entry := newRoot
	if imgs := mapValue(newRoot, "images"); imgs != nil && index < len(imgs.Content) {
		entry = imgs.Content[index]
	}
	if nt := mapValue(entry, "newTag"); nt == nil || nt.Kind != yaml.ScalarNode || nt.Tag != "!!str" || nt.Value != change.New {
		return bad("newTag does not hold %q", change.New)
	}
	return nil
}

// sameImageName reports whether two image names are the same repository.
func sameImageName(a, b string) bool {
	if a == b {
		return true
	}
	ak, ok1 := inventory.RepositoryKey(a)
	bk, ok2 := inventory.RepositoryKey(b)
	return ok1 && ok2 && ak == bk
}

// kustomizeFields are the top-level fields of a kustomization that Kustomize
// reads; kustomizeImageFields those of an images entry. Kustomize matches
// them without regard to case (the file is decoded like JSON), so a spelling
// other than the canonical one, or two keys that differ only in case, would
// say something this code does not see.
var kustomizeFields = []string{
	"apiVersion", "kind", "metadata", "namespace", "namePrefix", "nameSuffix", "commonLabels", "labels", "commonAnnotations",
	"patchesStrategicMerge", "patches", "patchesJson6902", "replicas", "images", "imageTags", "replacements", "resources", "bases",
	"components", "crds", "configMapGenerator", "secretGenerator", "generatorOptions", "vars", "openapi", "helmCharts", "helmGlobals",
	"helmChartInflationGenerator", "generators", "transformers", "buildMetadata", "sortOptions", "configurations", "inventory",
}

var kustomizeImageFields = []string{"name", "newName", "newTag", "digest"}

// checkKustomizeFieldSpelling refuses a mapping that has a key that matches a
// known field only without regard to case, two keys that differ only in case,
// or a key that is not a plain string.
func checkKustomizeFieldSpelling(m *yaml.Node, known []string, where string) *KustomizeEditProblem {
	seen := map[string]string{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode || k.Anchor != "" {
			return kustomizeProblem(ReasonKustomizeInvalid, "%s has a key that is not a plain string", where)
		}
		lower := strings.ToLower(k.Value)
		if first, dup := seen[lower]; dup {
			return kustomizeProblem(ReasonKustomizeInvalid, "%s has the keys %q and %q, which Kustomize reads as one field", where, first, k.Value)
		}
		seen[lower] = k.Value
		for _, f := range known {
			if k.Value != f && strings.EqualFold(k.Value, f) {
				return kustomizeProblem(ReasonKustomizeInvalid, "%s spells the field %q as %q, which Kustomize reads without regard to case", where, f, k.Value)
			}
		}
	}
	return nil
}

// kustomizeImageMatches is Kustomize's test of whether an images entry named
// name applies to the image string s: the name is put into a regular
// expression as it is written, with an optional "@sha256" and an optional tag
// after it.
func kustomizeImageMatches(s, name string) (bool, error) {
	pattern, err := regexp.Compile("^" + name + "(@sha256)?(:[a-zA-Z0-9_.{}-]*)?$")
	if err != nil {
		return false, err
	}
	return pattern.MatchString(s), nil
}

// kustomizeInterference tells whether another images entry (its name, newName
// and newTag) could act on what the target entry sets, or the target on what
// that entry sets, under Kustomize's own matching: it returns the reason when
// it could and "" when it could not. The strings tried are the target's name
// and the references the target has before and after the edit, and the
// other's name and what it produces.
func kustomizeInterference(otherName, otherNewName, otherTag, targetName, targetRepo, curTag, newTag string) (string, error) {
	withTag := func(n string, tags ...string) []string {
		out := []string{n}
		for _, t := range tags {
			if t != "" {
				out = append(out, n+":"+t)
			}
		}
		return out
	}
	mine := append(withTag(targetName, curTag, newTag), withTag(targetRepo, curTag, newTag)...)
	for _, s := range mine {
		ok, err := kustomizeImageMatches(s, otherName)
		if err != nil {
			return "", err
		}
		if ok {
			return fmt.Sprintf("its name matches %q, which the entry %q has or produces, so Kustomize applies it as well", s, targetName), nil
		}
	}
	theirs := withTag(otherName, otherTag)
	if otherNewName != "" {
		theirs = append(theirs, withTag(otherNewName, otherTag)...)
	}
	for _, s := range theirs {
		ok, err := kustomizeImageMatches(s, targetName)
		if err != nil {
			return "", err
		}
		if ok {
			return fmt.Sprintf("the name of the entry %q matches %q, which it has or produces, so both act on the same images", targetName, s), nil
		}
	}
	return "", nil
}
