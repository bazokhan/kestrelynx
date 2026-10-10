package remediation

import (
	"path"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// DockerfileLocation is where a workload's Dockerfile is and which of its
// stages the running image is built from.
type DockerfileLocation struct {
	Path   string // repository-relative, normalized
	Target string // the build stage; "" for the last stage
}

// DeriveComposeDockerfile reads the Dockerfile a Compose service builds from
// the service's build section, for a Compose file at composePath
// (repository-relative). It is a pure function of the file's bytes.
//
// Only static values are followed. A string "build: ./app" names the context
// directory, resolved against the Compose file's directory, and the file
// "Dockerfile" in it. The mapping form names context (default "."),
// dockerfile (relative to the context, default "Dockerfile") and target.
//
// Everything else is refused with the reason: no build section, a remote
// context (URL or git), dockerfile_inline, additional_contexts, a path that is
// absolute or leaves the repository, a "$" in any of the three values, an
// alias, a merge key, include or extends, and values that are not plain
// strings. A refusal means the Dockerfile must be named in the configuration
// or left to a person.
func DeriveComposeDockerfile(content []byte, composePath, service string) (loc DockerfileLocation, prob *DockerfileProblem) {
	defer func() {
		if r := recover(); r != nil {
			loc, prob = DockerfileLocation{}, dockerfileProblem(ReasonComposeInvalid, "internal error while reading the build section: %v", r)
		}
	}()
	if !github.ValidPath(composePath, false) {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeInvalid, "compose path %q is not a normalized path inside the repository", composePath)
	}
	if service == "" {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeInvalid, "no service name")
	}
	if len(content) > maxDockerfileBytes {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeInvalid, "the Compose file is larger than %d bytes", maxDockerfileBytes)
	}
	root, p := parseComposeDocument(content)
	if p != nil {
		return DockerfileLocation{}, &DockerfileProblem{Reason: p.Reason, Detail: p.Detail}
	}
	if p := checkComposeDuplicateKeys(root); p != nil {
		return DockerfileLocation{}, &DockerfileProblem{Reason: p.Reason, Detail: p.Detail}
	}
	if root.Anchor != "" || hasMergeKey(root) {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeMergeKey, "the document root has an anchor or a merge key")
	}
	if mapValue(root, "include") != nil {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeIncludeExtends, "the file has a top-level include")
	}
	svcs := mapValue(root, "services")
	if svcs == nil || svcs.Kind != yaml.MappingNode || hasMergeKey(svcs) {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeServiceMissing, "the file has no plain services mapping")
	}
	svc := mapValue(svcs, service)
	if svc == nil {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeServiceMissing, "service %q is not in the file", service)
	}
	if svc.Kind != yaml.MappingNode {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeAnchorAlias, "service %q is an alias or not a mapping", service)
	}
	if hasMergeKey(svc) {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeMergeKey, "service %q has a merge key", service)
	}
	if mapValue(svc, "extends") != nil {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeIncludeExtends, "service %q uses extends", service)
	}
	build := mapValue(svc, "build")
	if build == nil {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeNoBuild, "service %q has no build section", service)
	}

	composeDir := path.Dir(composePath)
	switch build.Kind {
	case yaml.ScalarNode:
		ctx, prob := composeBuildString(build, "build")
		if prob != nil {
			return DockerfileLocation{}, prob
		}
		dir, prob := composeBuildContextDir(composeDir, ctx)
		if prob != nil {
			return DockerfileLocation{}, prob
		}
		return composeBuildLocation(dir, "Dockerfile", "")
	case yaml.MappingNode:
		if hasMergeKey(build) {
			return DockerfileLocation{}, dockerfileProblem(ReasonComposeMergeKey, "the build section has a merge key")
		}
		if mapValue(build, "dockerfile_inline") != nil {
			return DockerfileLocation{}, dockerfileProblem(ReasonComposeBuildInline, "the build uses dockerfile_inline")
		}
		if mapValue(build, "additional_contexts") != nil {
			return DockerfileLocation{}, dockerfileProblem(ReasonComposeBuildAdditional, "the build uses additional_contexts")
		}
		ctx := "."
		if n := mapValue(build, "context"); n != nil {
			v, prob := composeBuildString(n, "build.context")
			if prob != nil {
				return DockerfileLocation{}, prob
			}
			ctx = v
		}
		dockerfile := "Dockerfile"
		if n := mapValue(build, "dockerfile"); n != nil {
			v, prob := composeBuildString(n, "build.dockerfile")
			if prob != nil {
				return DockerfileLocation{}, prob
			}
			dockerfile = v
		}
		target := ""
		if n := mapValue(build, "target"); n != nil {
			v, prob := composeBuildString(n, "build.target")
			if prob != nil {
				return DockerfileLocation{}, prob
			}
			if !validStageName(v) {
				return DockerfileLocation{}, dockerfileProblem(ReasonComposeBuildShape, "build.target %q is not a stage name", v)
			}
			target = v
		}
		dir, prob := composeBuildContextDir(composeDir, ctx)
		if prob != nil {
			return DockerfileLocation{}, prob
		}
		return composeBuildLocation(dir, dockerfile, target)
	case yaml.AliasNode:
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeAnchorAlias, "the build section is an alias")
	default:
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeBuildShape, "the build section is a sequence")
	}
}

// AgreeDockerfileLocation checks that a Dockerfile location read from a
// Compose build section is the one an explicit mapping names for the same
// workload: the same path and the same stage (compared without regard to
// case; "" means the last stage and agrees only with "").
func AgreeDockerfileLocation(derived, explicit DockerfileLocation) *DockerfileProblem {
	if derived.Path != explicit.Path {
		return dockerfileProblem(ReasonDockerfileMappingDiffers, "the Compose build names %q, the mapping names %q", derived.Path, explicit.Path)
	}
	if !strings.EqualFold(derived.Target, explicit.Target) {
		return dockerfileProblem(ReasonDockerfileMappingDiffers, "the Compose build targets stage %q, the mapping targets %q", derived.Target, explicit.Target)
	}
	return nil
}

// composeBuildString returns the value of a build-section scalar that must be
// a plain, non-empty string without a variable.
func composeBuildString(n *yaml.Node, what string) (string, *DockerfileProblem) {
	switch {
	case n.Kind == yaml.AliasNode:
		return "", dockerfileProblem(ReasonComposeAnchorAlias, "%s is an alias", what)
	case n.Kind != yaml.ScalarNode:
		return "", dockerfileProblem(ReasonComposeNotString, "%s is not a string", what)
	case n.Style&yaml.TaggedStyle != 0 || n.Tag != "!!str":
		return "", dockerfileProblem(ReasonComposeNotString, "%s is not a plain string", what)
	case strings.Contains(n.Value, "$"):
		return "", dockerfileProblem(ReasonComposeVariable, "%s %q contains a variable", what, n.Value)
	case strings.TrimSpace(n.Value) == "" || strings.TrimSpace(n.Value) != n.Value:
		return "", dockerfileProblem(ReasonComposeBuildPath, "%s %q is empty or has surrounding whitespace", what, n.Value)
	}
	for _, r := range n.Value {
		if unicode.IsControl(r) {
			return "", dockerfileProblem(ReasonComposeBuildPath, "%s contains a control character", what)
		}
	}
	return n.Value, nil
}

// composeBuildContextDir resolves a static build context against the Compose
// file's directory. A URL or git reference is a remote context; a path that
// is absolute, starts with "~" or leaves the repository is refused.
func composeBuildContextDir(composeDir, ctx string) (string, *DockerfileProblem) {
	lower := strings.ToLower(ctx)
	if strings.Contains(ctx, "://") || strings.HasPrefix(lower, "git@") || strings.HasPrefix(lower, "github.com/") {
		return "", dockerfileProblem(ReasonComposeBuildRemote, "the build context %q is remote", ctx)
	}
	return resolveRepoPath(composeDir, ctx, "the build context")
}

// resolveRepoPath joins a relative path onto a repository-relative directory
// and requires the result to stay inside the repository. The result is "."
// for the repository root.
func resolveRepoPath(dir, rel, what string) (string, *DockerfileProblem) {
	if strings.Contains(rel, "\\") || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "~") {
		return "", dockerfileProblem(ReasonComposeBuildPath, "%s %q is absolute or not a plain relative path", what, rel)
	}
	joined := path.Join(dir, rel)
	if joined == ".." || strings.HasPrefix(joined, "../") || path.IsAbs(joined) {
		return "", dockerfileProblem(ReasonComposeBuildPath, "%s %q leaves the repository", what, rel)
	}
	return joined, nil
}

func composeBuildLocation(contextDir, dockerfile, target string) (DockerfileLocation, *DockerfileProblem) {
	p, prob := resolveRepoPath(contextDir, dockerfile, "the Dockerfile path")
	if prob != nil {
		return DockerfileLocation{}, prob
	}
	if !github.ValidPath(p, false) {
		return DockerfileLocation{}, dockerfileProblem(ReasonComposeBuildPath, "the Dockerfile path %q is not a file path inside the repository", p)
	}
	return DockerfileLocation{Path: p, Target: target}, nil
}

// validStageName reports whether s can name a Dockerfile build stage.
func validStageName(s string) bool {
	return len(s) <= 128 && dockerfileStageNameRE.MatchString(strings.ToLower(s))
}
