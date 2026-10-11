package remediation

import (
	"gopkg.in/yaml.v3"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// ReasonComposeBuildUndetermined: the workload is mapped to a Compose file
// whose service cannot be read with confidence, so whether the running image
// was built on the host is not known, and it is not looked up in a registry
// on a guess.
const ReasonComposeBuildUndetermined Reason = "compose_build_undetermined"

// ComposeBuild is what a Compose file says about building a service.
type ComposeBuild int

const (
	// ComposeBuildUndetermined: the file or the service cannot be read with
	// confidence (it does not parse, has duplicate keys, aliases, merge keys,
	// include or extends that could supply or hide a build section, or lacks
	// the service).
	ComposeBuildUndetermined ComposeBuild = iota
	// ComposeBuildNone: the service is read in full and has no build section.
	ComposeBuildNone
	// ComposeBuildYes: the service has a build section of its own.
	ComposeBuildYes
)

// ComposeServiceBuilds reads whether the service has a build section in the
// Compose file. A build key written in the service itself, with a mapping or a
// string as its value, counts whatever else the file does (extends or a merge
// key could add keys but not take that one away). A service without one is ComposeBuildNone only when nothing in
// the file could have supplied it; otherwise the answer is undetermined and
// why says what stopped it.
func ComposeServiceBuilds(content []byte, composePath, service string) (result ComposeBuild, why string) {
	defer func() {
		if r := recover(); r != nil {
			result, why = ComposeBuildUndetermined, "internal error while reading the Compose file"
		}
	}()
	if !github.ValidPath(composePath, false) || service == "" || len(content) > maxDockerfileBytes {
		return ComposeBuildUndetermined, "the Compose path or service is unusable or the file is too large"
	}
	root, p := parseComposeDocument(content)
	if p != nil {
		return ComposeBuildUndetermined, p.Detail
	}
	if p := checkComposeDuplicateKeys(root); p != nil {
		return ComposeBuildUndetermined, p.Detail
	}
	svcs := mapValue(root, "services")
	if svcs == nil || svcs.Kind != yaml.MappingNode || hasMergeKey(svcs) {
		return ComposeBuildUndetermined, "the file has no plain services mapping"
	}
	svc := mapValue(svcs, service)
	if svc == nil {
		return ComposeBuildUndetermined, "the service is not in the file"
	}
	if svc.Kind != yaml.MappingNode {
		return ComposeBuildUndetermined, "the service is an alias or not a mapping"
	}
	if b := mapValue(svc, "build"); b != nil {
		// A build value that is a mapping or a string is a build section. One
		// that carries a tag (!reset, !override and the like) or is null may
		// remove the section instead of defining it.
		switch {
		case b.Kind == yaml.MappingNode && b.ShortTag() == "!!map",
			b.Kind == yaml.ScalarNode && b.ShortTag() == "!!str" && b.Value != "":
			return ComposeBuildYes, ""
		}
		return ComposeBuildUndetermined, "the service's build value is empty, null or tagged, so it may remove the section"
	}
	switch {
	case root.Anchor != "" || hasMergeKey(root):
		return ComposeBuildUndetermined, "the document root has an anchor or a merge key"
	case mapValue(root, "include") != nil:
		return ComposeBuildUndetermined, "the file has a top-level include"
	case hasMergeKey(svc):
		return ComposeBuildUndetermined, "the service has a merge key"
	case mapValue(svc, "extends") != nil:
		return ComposeBuildUndetermined, "the service uses extends"
	}
	return ComposeBuildNone, ""
}
