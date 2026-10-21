package remediation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons a Kubernetes manifest is not edited. Each one names a property of
// the file (or of the request) that makes a byte-level tag rewrite unsafe or
// unverifiable; a file that trips any of them is left for a person.
const (
	ReasonManifestInvalid         Reason = "manifest_invalid"          // not well-formed YAML, a repeated key, or the request or the result failed verification
	ReasonManifestAnchorAlias     Reason = "manifest_anchor_or_alias"  // an anchor or alias on a node whose edit could reach other places
	ReasonManifestMergeKey        Reason = "manifest_merge_key"        // a "<<" key on the path to a target image
	ReasonManifestNotString       Reason = "manifest_not_string"       // the image value is not a plain string scalar
	ReasonManifestBlockScalar     Reason = "manifest_block_scalar"     // the image value is a block scalar
	ReasonManifestVariable        Reason = "manifest_variable"         // the image value contains "$"
	ReasonManifestDigest          Reason = "manifest_digest"           // the image value carries a digest
	ReasonManifestTagMissing      Reason = "manifest_tag_missing"      // the image value has no explicit tag
	ReasonManifestImageAutomation Reason = "manifest_image_automation" // the line carries a Flux image automation marker
	ReasonManifestTemplate        Reason = "manifest_template"         // the file holds a template expression ("{{"), so it is not a plain manifest
	ReasonSourceObjectMissing     Reason = "source_object_missing"     // no document of the file is the workload's object
	ReasonSourceObjectAmbiguous   Reason = "source_object_ambiguous"   // more than one document is the workload's object
	ReasonSourceContainerMissing  Reason = "source_container_missing"  // the object has no editable container of that name
	ReasonSourceMismatch          Reason = "source_mismatch"           // the file names another image than the one declared and running
)

// manifestMaxDocuments bounds the documents of one manifest file.
const manifestMaxDocuments = 500

// ManifestTarget is one container whose image is edited: the workload key's
// parts and, when the file names the object differently from the running
// workload (a name prefix added by a later tool, for example), the kind and
// name to look for.
type ManifestTarget struct {
	Kind       inventory.WorkloadKind
	Namespace  string
	Name       string
	Container  string
	ObjectKind string // "Deployment", ...; empty means the kind of Kind
	ObjectName string // empty means Name
}

// Workload is the target's workload key.
func (t ManifestTarget) Workload() string {
	return string(t.Kind) + "/" + t.Namespace + "/" + t.Name + "/" + t.Container
}

// manifestKinds maps a workload kind to the Kind and apiVersion of its object
// and to the path of its Pod template spec.
var manifestKinds = map[inventory.WorkloadKind]struct {
	kind, apiVersion string
	podSpec          []string
}{
	inventory.WorkloadDeployment:  {"Deployment", "apps/v1", []string{"spec", "template", "spec"}},
	inventory.WorkloadStatefulSet: {"StatefulSet", "apps/v1", []string{"spec", "template", "spec"}},
	inventory.WorkloadDaemonSet:   {"DaemonSet", "apps/v1", []string{"spec", "template", "spec"}},
	inventory.WorkloadJob:         {"Job", "batch/v1", []string{"spec", "template", "spec"}},
	inventory.WorkloadCronJob:     {"CronJob", "batch/v1", []string{"spec", "jobTemplate", "spec", "template", "spec"}},
	inventory.WorkloadPod:         {"Pod", "v1", []string{"spec"}},
}

// ManifestKindName is the Kind a workload kind's object has in a manifest, ""
// for a kind that has none.
func ManifestKindName(k inventory.WorkloadKind) string { return manifestKinds[k].kind }

// ManifestEditRequest asks for the tag of the image of a set of containers to
// be rewritten in one manifest file.
type ManifestEditRequest struct {
	Content  []byte // the file as read from Git
	Targets  []ManifestTarget
	Current  string // the running reference, with an explicit tag
	Declared string // the reference the Pod specs declare
	NewTag   string
}

// ManifestImageChange is one rewritten image.
type ManifestImageChange struct {
	Workload string // the workload key
	Location string // <Kind>/<namespace>/<name>/containers/<container>, the namespace as the file has it
	Old, New string // the full image strings as written, without quotes
}

// ManifestImageEdit is the edited file and the changes made to it.
type ManifestImageEdit struct {
	Content []byte
	Changes []ManifestImageChange // sorted by Location
	// Unchanged are the other containers of an edited Pod template that use the
	// same image in their own image fields and were left as they are, as
	// <Kind>/<namespace>/<name>/containers|initContainers/<container>, sorted.
	Unchanged []string
}

// ManifestEditProblem says why a file was not edited.
type ManifestEditProblem struct {
	Reason   Reason
	Workload string // the workload the problem was found for, "" for the file as a whole
	Detail   string
}

func (p *ManifestEditProblem) Error() string {
	if p.Workload != "" {
		return fmt.Sprintf("%s: %s: %s", p.Reason, p.Workload, p.Detail)
	}
	return fmt.Sprintf("%s: %s", p.Reason, p.Detail)
}

func manifestProblem(r Reason, workload, format string, args ...any) *ManifestEditProblem {
	return &ManifestEditProblem{Reason: r, Workload: workload, Detail: fmt.Sprintf(format, args...)}
}

// manifestSite is a container found for a target: where its image is.
type manifestSite struct {
	target   ManifestTarget
	doc      int
	list     string // "containers" or "initContainers"
	index    int
	podSpec  *yaml.Node
	image    *yaml.Node
	location string
	// podLocationPrefix is <Kind>/<namespace>/<name> of the object, the
	// namespace as the file has it.
	podLocationPrefix string
	path              string // structural path of the image value, as diffComposeNodes writes it
}

// EditManifestImageTag rewrites the tag of the image of every requested
// container and nothing else. It never edits part of the set: when any target
// fails any check, no edit is returned.
//
// The file may hold several YAML documents. Each target is found by the
// object's apiVersion, kind, name and (when the file has one) namespace, which
// must select exactly one document, and then by the container's name in the
// object's Pod template; a native sidecar is a container of initContainers
// that restarts always, and an ordinary init container is not edited. The
// image must be a plain, single-quoted or double-quoted string without "$",
// digest, anchor, alias, tag or merge key, with an explicit tag, naming the
// declared and the running image. The other containers of a Pod template that
// use the same image are not edited and are reported as unchanged. A file with
// a template expression ("{{") anywhere is not edited.
//
// The result is verified before it is returned: bytes outside the replaced
// tags are identical, no mapping repeats a key, and a re-parse of every
// document differs from the original exactly at the target images, which hold
// the new values.
func EditManifestImageTag(req ManifestEditRequest) (res ManifestImageEdit, prob *ManifestEditProblem) {
	defer func() {
		if r := recover(); r != nil {
			res, prob = ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "internal error while editing: %v", r)
		}
	}()

	if len(req.Targets) == 0 {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "no target container")
	}
	if !composeTagRE.MatchString(req.NewTag) {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "%q is not a valid tag", req.NewTag)
	}
	curKey, ok := inventory.RepositoryKey(req.Current)
	if !ok {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "running image %q is not a well-formed reference", req.Current)
	}
	curTag := inventory.TagOf(req.Current)
	if curTag == "" || inventory.DigestOf(req.Current) != "" {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "running image %q needs an explicit tag and no digest", req.Current)
	}
	if req.NewTag == curTag {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "the new tag equals the running tag %q; there is nothing to change", curTag)
	}
	if !sameReference(req.Declared, req.Current) {
		return ManifestImageEdit{}, manifestProblem(ReasonSourceMismatch, "", "the declared image %q is not the running image %q", req.Declared, req.Current)
	}
	_ = curKey

	content := req.Content
	if bytes.HasPrefix(content, []byte{0xFF, 0xFE}) || bytes.HasPrefix(content, []byte{0xFE, 0xFF}) {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "UTF-16 files are not edited")
	}
	if bytes.Contains(content, []byte("{{")) {
		return ManifestImageEdit{}, manifestProblem(ReasonManifestTemplate, "", "the file holds a template expression, so what it deploys depends on a rendering that is not done here")
	}
	docs, prob := parseManifestDocuments(content)
	if prob != nil {
		return ManifestImageEdit{}, prob
	}

	targets := append([]ManifestTarget(nil), req.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Workload() < targets[j].Workload() })
	isTarget := map[string]bool{}
	var sites []manifestSite
	for _, t := range targets {
		site, prob := findManifestSite(docs, t)
		if prob != nil {
			return ManifestImageEdit{}, prob
		}
		if isTarget[site.key()] {
			return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, t.Workload(), "two targets name the same container (%s)", site.location)
		}
		isTarget[site.key()] = true
		sites = append(sites, site)
	}

	starts := composeLineStarts(content)
	var spans []composeSpan
	var changes []ManifestImageChange
	unchanged := map[string]bool{}
	for _, s := range sites {
		for _, u := range sameImageElsewhere(s, isTarget) {
			unchanged[u] = true
		}
		sp, ch, prob := planManifestImageEdit(content, starts, s, req)
		if prob != nil {
			return ManifestImageEdit{}, prob
		}
		spans = append(spans, sp)
		changes = append(changes, ch)
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return ManifestImageEdit{}, manifestProblem(ReasonManifestInvalid, "", "two edits overlap")
		}
	}
	out := spliceSpans(content, spans)
	if prob := verifyManifestEdit(content, out, spans, docs, sites, changes); prob != nil {
		return ManifestImageEdit{}, prob
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Location < changes[j].Location })
	return ManifestImageEdit{Content: out, Changes: changes, Unchanged: sortedSet(unchanged)}, nil
}

// key identifies the container a site stands for.
func (s manifestSite) key() string {
	return fmt.Sprintf("%d/%s/%d", s.doc, s.list, s.index)
}

// parseManifestDocuments parses content as a stream of YAML documents. A
// document without content (a comment, or nothing between two separators) is
// kept as nil so that positions in the stream stay aligned. Every mapping of
// every document is checked for a repeated key.
func parseManifestDocuments(content []byte) ([]*yaml.Node, *ManifestEditProblem) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, manifestProblem(ReasonManifestInvalid, "", "the file cannot be parsed: %v", err)
		}
		if len(docs) >= manifestMaxDocuments {
			return nil, manifestProblem(ReasonManifestInvalid, "", "the file has more than %d documents", manifestMaxDocuments)
		}
		if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
			return nil, manifestProblem(ReasonManifestInvalid, "", "a document is not one YAML node")
		}
		root := doc.Content[0]
		if root.Kind == yaml.ScalarNode && root.Tag == "!!null" && root.Value == "" {
			docs = append(docs, nil)
			continue
		}
		if p := checkComposeDuplicateKeys(root); p != nil {
			return nil, manifestProblem(ReasonManifestInvalid, "", "document %d: %s", len(docs)+1, p.Detail)
		}
		docs = append(docs, root)
	}
	if len(docs) == 0 {
		return nil, manifestProblem(ReasonManifestInvalid, "", "the file is empty")
	}
	return docs, nil
}

// scalarString returns the value of a plain string scalar node.
func scalarString(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", false
	}
	return n.Value, true
}

// findManifestSite finds the container of one target.
func findManifestSite(docs []*yaml.Node, t ManifestTarget) (manifestSite, *ManifestEditProblem) {
	w := t.Workload()
	mk, known := manifestKinds[t.Kind]
	if !known {
		return manifestSite{}, manifestProblem(ReasonManifestInvalid, w, "%q is not a kind of workload with a manifest", t.Kind)
	}
	objKind, objName := t.ObjectKind, t.ObjectName
	if objKind == "" {
		objKind = mk.kind
	}
	if objName == "" {
		objName = t.Name
	}
	if objKind != mk.kind {
		return manifestSite{}, manifestProblem(ReasonManifestInvalid, w, "the object kind %q is not %q, the kind of the workload", objKind, mk.kind)
	}

	var matches []int
	hasList := false
	for i, d := range docs {
		if d == nil || d.Kind != yaml.MappingNode {
			continue
		}
		if prob := checkIdentityNodes(d, w); prob != nil {
			return manifestSite{}, prob
		}
		if k, ok := scalarString(mapValue(d, "kind")); ok && k == "List" {
			hasList = true
		}
		api, ok1 := scalarString(mapValue(d, "apiVersion"))
		kind, ok2 := scalarString(mapValue(d, "kind"))
		md := mapValue(d, "metadata")
		name, ok3 := scalarString(mapValue(md, "name"))
		if !ok1 || !ok2 || !ok3 || api != mk.apiVersion || kind != objKind || name != objName {
			continue
		}
		if nsNode := mapValue(md, "namespace"); nsNode != nil {
			ns, isStr := scalarString(nsNode)
			if !isStr && !(nsNode.Kind == yaml.ScalarNode && nsNode.Tag == "!!null") {
				continue
			}
			if ns != "" && ns != t.Namespace {
				continue
			}
		}
		matches = append(matches, i)
	}
	switch {
	case len(matches) == 0:
		extra := ""
		if hasList {
			extra = " (objects inside a List are not read)"
		}
		return manifestSite{}, manifestProblem(ReasonSourceObjectMissing, w, "no document is %s %s of namespace %s%s", objKind, objName, t.Namespace, extra)
	case len(matches) > 1:
		return manifestSite{}, manifestProblem(ReasonSourceObjectAmbiguous, w, "%d documents are %s %s of namespace %s", len(matches), objKind, objName, t.Namespace)
	}
	di := matches[0]
	root := docs[di]
	if prob := checkEditableNode(root, w, "the document"); prob != nil {
		return manifestSite{}, prob
	}

	// Walk to the Pod template's spec.
	node := root
	path := ""
	for _, key := range mk.podSpec {
		next := mapValue(node, key)
		if next == nil {
			return manifestSite{}, manifestProblem(ReasonSourceContainerMissing, w, "the object has no %s", strings.Join(mk.podSpec, "."))
		}
		if prob := checkEditableNode(next, w, key); prob != nil {
			return manifestSite{}, prob
		}
		node = next
		if path != "" {
			path += "."
		}
		path += key
	}

	var found []manifestSite
	for _, list := range []string{"containers", "initContainers"} {
		seq := mapValue(node, list)
		if seq == nil {
			continue
		}
		if seq.Kind != yaml.SequenceNode {
			return manifestSite{}, manifestProblem(ReasonManifestInvalid, w, "%s is not a list", list)
		}
		if seq.Kind == yaml.AliasNode || seq.Anchor != "" {
			return manifestSite{}, manifestProblem(ReasonManifestAnchorAlias, w, "%s has an anchor", list)
		}
		for idx, item := range seq.Content {
			if item.Kind == yaml.AliasNode || item.Anchor != "" {
				return manifestSite{}, manifestProblem(ReasonManifestAnchorAlias, w, "an entry of %s has an anchor or is an alias", list)
			}
			if item.Kind != yaml.MappingNode {
				continue
			}
			name, ok := scalarString(mapValue(item, "name"))
			if !ok || name != t.Container {
				continue
			}
			if list == "initContainers" {
				if rp, _ := scalarString(mapValue(item, "restartPolicy")); rp != "Always" {
					return manifestSite{}, manifestProblem(ReasonSourceContainerMissing, w, "%q is an ordinary init container, which is not edited", t.Container)
				}
			}
			found = append(found, manifestSite{
				target: t, doc: di, list: list, index: idx, podSpec: node,
				path: fmt.Sprintf("%s.%s[%d].image", path, list, idx),
			})
		}
	}
	switch len(found) {
	case 0:
		return manifestSite{}, manifestProblem(ReasonSourceContainerMissing, w, "the object has no container %q", t.Container)
	case 1:
	default:
		return manifestSite{}, manifestProblem(ReasonManifestInvalid, w, "the object has %d containers named %q", len(found), t.Container)
	}
	s := found[0]
	item := mapValue(node, s.list).Content[s.index]
	if prob := checkEditableNode(item, w, "the container"); prob != nil {
		return manifestSite{}, prob
	}
	s.image = mapValue(item, "image")
	if s.image == nil {
		return manifestSite{}, manifestProblem(ReasonSourceContainerMissing, w, "the container has no image")
	}
	ns, _ := scalarString(mapValue(mapValue(root, "metadata"), "namespace"))
	s.podLocationPrefix = fmt.Sprintf("%s/%s/%s", objKind, ns, objName)
	s.location = fmt.Sprintf("%s/%s/%s", s.podLocationPrefix, s.list, t.Container)
	return s, nil
}

// checkIdentityNodes refuses a document whose identity (apiVersion, kind,
// metadata with its name and namespace) is written with an anchor, an alias or
// a merge key: what such a document is cannot be told from its text, so it
// could be the target or hide another one.
func checkIdentityNodes(doc *yaml.Node, workload string) *ManifestEditProblem {
	if hasMergeKey(doc) {
		return manifestProblem(ReasonManifestMergeKey, workload, "a document has a merge key at its top level, so its identity cannot be read from its text")
	}
	nodes := []*yaml.Node{mapValue(doc, "apiVersion"), mapValue(doc, "kind"), mapValue(doc, "metadata")}
	md := mapValue(doc, "metadata")
	if md != nil && md.Kind == yaml.MappingNode {
		if hasMergeKey(md) {
			return manifestProblem(ReasonManifestMergeKey, workload, "the metadata of a document has a merge key, so its name and namespace cannot be read from its text")
		}
		nodes = append(nodes, mapValue(md, "name"), mapValue(md, "namespace"))
	}
	for _, n := range nodes {
		if n != nil && (n.Kind == yaml.AliasNode || n.Anchor != "") {
			return manifestProblem(ReasonManifestAnchorAlias, workload, "the identity of a document is written with an anchor or an alias")
		}
	}
	return nil
}

// checkEditableNode refuses a mapping that is an alias, has an anchor or has a
// merge key: an edit under it could be reached from, or come from, elsewhere.
func checkEditableNode(n *yaml.Node, workload, what string) *ManifestEditProblem {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return manifestProblem(ReasonManifestAnchorAlias, workload, "%s has an anchor or is an alias", what)
	}
	if n.Kind != yaml.MappingNode {
		return manifestProblem(ReasonManifestInvalid, workload, "%s is not a mapping", what)
	}
	if hasMergeKey(n) {
		return manifestProblem(ReasonManifestMergeKey, workload, "%s has a merge key", what)
	}
	return nil
}

// sameImageElsewhere lists the containers of the site's Pod template that are
// not edited but use the same image in their own image field. They keep their
// tag; the edit says so, because the containers of one Pod then run two tags.
func sameImageElsewhere(s manifestSite, isTarget map[string]bool) []string {
	mine, _ := scalarString(s.image)
	var out []string
	for _, list := range []string{"containers", "initContainers"} {
		seq := mapValue(s.podSpec, list)
		if seq == nil {
			continue
		}
		for idx, item := range seq.Content {
			other := manifestSite{doc: s.doc, list: list, index: idx}
			if other.key() == s.key() || isTarget[other.key()] || item.Kind != yaml.MappingNode {
				continue
			}
			img, ok := scalarString(mapValue(item, "image"))
			if !ok || !sameReferenceLoose(img, mine) {
				continue
			}
			name, _ := scalarString(mapValue(item, "name"))
			out = append(out, s.podLocationPrefix+"/"+list+"/"+name)
		}
	}
	return out
}

// sameReferenceLoose is sameReference for two values read from a file: either
// may be written without a tag or with a digest.
func sameReferenceLoose(a, b string) bool {
	if a == b {
		return true
	}
	ak, ok1 := inventory.RepositoryKey(a)
	bk, ok2 := inventory.RepositoryKey(b)
	return ok1 && ok2 && ak == bk && inventory.TagOf(a) == inventory.TagOf(b) && inventory.DigestOf(a) == inventory.DigestOf(b)
}

// planManifestImageEdit checks the image node of one target and finds the
// bytes of its tag.
func planManifestImageEdit(content []byte, starts []int, s manifestSite, req ManifestEditRequest) (composeSpan, ManifestImageChange, *ManifestEditProblem) {
	w := s.target.Workload()
	img := s.image
	fail := func(r Reason, format string, args ...any) (composeSpan, ManifestImageChange, *ManifestEditProblem) {
		return composeSpan{}, ManifestImageChange{}, manifestProblem(r, w, format, args...)
	}
	switch {
	case img.Kind == yaml.AliasNode || img.Anchor != "":
		return fail(ReasonManifestAnchorAlias, "the image has an anchor or is an alias")
	case img.Kind != yaml.ScalarNode:
		return fail(ReasonManifestNotString, "the image is not a scalar")
	case img.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return fail(ReasonManifestBlockScalar, "the image is a block scalar")
	case img.Style&yaml.TaggedStyle != 0:
		return fail(ReasonManifestNotString, "the image has an explicit tag")
	case img.Tag != "!!str":
		return fail(ReasonManifestNotString, "the image is not a string (%s)", img.Tag)
	}
	value := img.Value
	if strings.Contains(value, "$") {
		return fail(ReasonManifestVariable, "the image %q contains a variable", value)
	}
	if _, ok := inventory.RepositoryOf(value); !ok {
		return fail(ReasonManifestInvalid, "the image %q is not a well-formed reference", value)
	}
	if inventory.DigestOf(value) != "" || strings.Contains(value, "@") {
		return fail(ReasonManifestDigest, "the image %q carries a digest", value)
	}
	tag := inventory.TagOf(value)
	if tag == "" {
		return fail(ReasonManifestTagMissing, "the image %q has no explicit tag", value)
	}
	if !sameReference(value, req.Current) || !sameReference(value, req.Declared) {
		return fail(ReasonSourceMismatch, "the file has %q, the pod spec declares %q and the container runs %q", value, req.Declared, req.Current)
	}
	if !strings.HasSuffix(value, ":"+tag) {
		return fail(ReasonManifestInvalid, "the image %q does not end in its tag", value)
	}
	if img.Line >= 1 && img.Line <= len(starts) {
		end := len(content)
		if img.Line < len(starts) {
			end = starts[img.Line]
		}
		if bytes.Contains(content[starts[img.Line-1]:end], []byte("$imagepolicy")) {
			return fail(ReasonManifestImageAutomation, "the line of the image carries a Flux image automation marker, so another tool owns the tag")
		}
	}

	raw, quote := value, 0
	switch {
	case img.Style&yaml.DoubleQuotedStyle != 0:
		raw, quote = `"`+value+`"`, 1
	case img.Style&yaml.SingleQuotedStyle != 0:
		raw, quote = "'"+strings.ReplaceAll(value, "'", "''")+"'", 1
	}
	pos, ok := locateComposeScalar(content, starts, img.Line, img.Column, raw)
	if !ok {
		return fail(ReasonManifestInvalid, "the source text of the image %q cannot be located exactly (escapes or line folding?)", value)
	}
	tagStart := pos + quote + len(value) - len(tag)
	return composeSpan{start: tagStart, end: tagStart + len(tag), repl: req.NewTag},
		ManifestImageChange{Workload: w, Location: s.location, Old: value, New: value[:len(value)-len(tag)] + req.NewTag}, nil
}

// verifyManifestEdit checks an edit against the original: the bytes outside
// the replaced tags are unchanged, no mapping of the result repeats a key, and
// every document parses to the same tree except at the target images, which
// hold the new values.
func verifyManifestEdit(orig, edited []byte, spans []composeSpan, origDocs []*yaml.Node, sites []manifestSite, changes []ManifestImageChange) *ManifestEditProblem {
	bad := func(format string, args ...any) *ManifestEditProblem {
		return manifestProblem(ReasonManifestInvalid, "", "verification of the edit failed: "+format, args...)
	}
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

	newDocs, prob := parseManifestDocuments(edited)
	if prob != nil {
		return bad("the result does not parse: %s", prob.Detail)
	}
	if len(newDocs) != len(origDocs) {
		return bad("the result has %d documents, not %d", len(newDocs), len(origDocs))
	}
	want := map[string]bool{}
	for _, s := range sites {
		want[fmt.Sprintf("%d:%s", s.doc, s.path)] = true
	}
	var diffs []string
	for i := range origDocs {
		if (origDocs[i] == nil) != (newDocs[i] == nil) {
			return bad("document %d changed between empty and not", i+1)
		}
		if origDocs[i] == nil {
			continue
		}
		var d []string
		diffComposeNodes(origDocs[i], newDocs[i], "", &d)
		for _, p := range d {
			diffs = append(diffs, fmt.Sprintf("%d:%s", i, p))
		}
	}
	if len(diffs) != len(want) {
		return bad("the result differs at %v, expected only the %d target images", diffs, len(want))
	}
	for _, d := range diffs {
		if !want[d] {
			return bad("the result differs at %s, which is not a target", d)
		}
	}
	byLoc := map[string]string{}
	for _, c := range changes {
		byLoc[c.Location] = c.New
	}
	for _, s := range sites {
		root := newDocs[s.doc]
		node := root
		for _, key := range manifestKinds[s.target.Kind].podSpec {
			node = mapValue(node, key)
		}
		seq := mapValue(node, s.list)
		if seq == nil || s.index >= len(seq.Content) {
			return bad("%s is gone from the result", s.location)
		}
		img := mapValue(seq.Content[s.index], "image")
		if img == nil || img.Kind != yaml.ScalarNode || img.Tag != "!!str" || img.Value != byLoc[s.location] {
			return bad("%s does not hold %q", s.location, byLoc[s.location])
		}
	}
	return nil
}
