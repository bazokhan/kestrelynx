package remediation

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// pnpm-workspace.yaml is where pnpm 10 and later read their settings, whether
// or not the directory is a workspace. A directory whose file holds only
// settings that do not change what is resolved is one project, like one
// without the file. The keys below are the ones read that way, with what each
// means (the pnpm documentation, "Settings" and "Dependency Resolution"):
//
//   - allowBuilds maps package matchers to true or false: whether the
//     package's install scripts may run. The update runs every manager command
//     with scripts turned off, so the map does not change what is resolved.
//     pnpm itself adds entries with a placeholder text for packages it found
//     with unreviewed scripts, which is why a text is accepted as well as a
//     boolean.
//   - onlyBuiltDependencies, ignoredBuiltDependencies and
//     neverBuiltDependencies are the lists that allowBuilds replaces (v10
//     names): the same permission to run install scripts, the same reason.
//   - supportedArchitectures (os, cpu, libc) names the platforms whose
//     optional dependencies are installed and recorded in the lockfile, so it
//     changes the resolved result. It is handed to the work container with
//     the file, and the entries it makes (one per platform) are compared with
//     the registry like any other.
//
// Any other key may change what is resolved or how the project is composed
// (packages, catalog, catalogs, overrides, packageExtensions,
// patchedDependencies, minimumReleaseAge, registries, ...), or is not known,
// and is left to a person. A file with a "packages" key declares a workspace.

// Bounds on the file's lists and maps.
const (
	maxWorkspaceEntries = 4096
	maxWorkspaceText    = 512
)

var (
	pnpmWorkspaceListKeys = keySet("onlyBuiltDependencies", "ignoredBuiltDependencies", "neverBuiltDependencies")
	pnpmArchKeys          = keySet("os", "cpu", "libc")
	pnpmArchValueRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
)

// pnpmWorkspaceProblem reads the content of a pnpm-workspace.yaml and returns,
// when the unit cannot be updated with it, the reason and a detail naming the
// keys or the place that is the cause. It returns "" when the file holds only
// the settings above, in the types they have.
func pnpmWorkspaceProblem(data []byte) (Reason, string) {
	root, err := readYAMLRoot(data)
	if errors.Is(err, io.EOF) {
		return "", "" // an empty file, or one of comments only
	}
	if err != nil {
		return ReasonUnparsableSource, fmt.Sprintf("pnpm-workspace.yaml cannot be read: %v", err)
	}
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return "", ""
	}
	if root.Kind != yaml.MappingNode {
		return ReasonUnparsableSource, "pnpm-workspace.yaml is not a mapping"
	}
	members, err := yamlMembers(root)
	if err != nil {
		return ReasonUnparsableSource, fmt.Sprintf("pnpm-workspace.yaml cannot be read: %v", err)
	}
	if _, ok := members["packages"]; ok {
		return ReasonWorkspaceUnsupported, "pnpm-workspace.yaml declares packages, so the directory is a workspace"
	}
	var unknown []string
	for k := range members {
		if k != "supportedArchitectures" && k != "allowBuilds" && !pnpmWorkspaceListKeys[k] {
			unknown = append(unknown, clip(k, 60))
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		if len(unknown) > 5 {
			unknown = append(unknown[:5], fmt.Sprintf("and %d more", len(unknown)-5))
		}
		return ReasonWorkspaceSettingsUnsupported, "pnpm-workspace.yaml sets " + strings.Join(unknown, ", ") + ", which can change what is resolved or how the project is composed, or is not known"
	}
	names := make([]string, 0, len(members))
	for k := range members {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if why := pnpmWorkspaceValueProblem(k, members[k]); why != "" {
			return ReasonWorkspaceSettingsUnsupported, fmt.Sprintf("pnpm-workspace.yaml: %s %s", k, why)
		}
	}
	return "", ""
}

// pnpmWorkspaceValueProblem returns why the value of a setting is not of the
// type the setting has, or "".
func pnpmWorkspaceValueProblem(key string, v *yaml.Node) string {
	// A scalar is judged by its YAML type, not by its text: 123 and true are
	// not names, and a name is not a number or a boolean.
	scalar := func(n *yaml.Node, tags ...string) bool {
		if n.Kind != yaml.ScalarNode || n.Value == "" || len(n.Value) > maxWorkspaceText || strings.ContainsAny(n.Value, "\n\r\x00") {
			return false
		}
		for _, t := range tags {
			if n.Tag == t {
				return true
			}
		}
		return false
	}
	switch {
	case key == "allowBuilds":
		if v.Kind != yaml.MappingNode {
			return "is not a mapping"
		}
		if len(v.Content)/2 > maxWorkspaceEntries {
			return fmt.Sprintf("has more than %d entries", maxWorkspaceEntries)
		}
		for i := 0; i+1 < len(v.Content); i += 2 {
			if !scalar(v.Content[i], "!!str") || !scalar(v.Content[i+1], "!!bool", "!!str") {
				return "has an entry that is not a matcher with a boolean or a text"
			}
		}
	case pnpmWorkspaceListKeys[key]:
		if v.Kind != yaml.SequenceNode {
			return "is not a list"
		}
		if len(v.Content) > maxWorkspaceEntries {
			return fmt.Sprintf("has more than %d entries", maxWorkspaceEntries)
		}
		for _, e := range v.Content {
			if !scalar(e, "!!str") {
				return "has an element that is not a text"
			}
		}
	case key == "supportedArchitectures":
		if v.Kind != yaml.MappingNode {
			return "is not a mapping"
		}
		for i := 0; i+1 < len(v.Content); i += 2 {
			k, list := v.Content[i], v.Content[i+1]
			if !scalar(k, "!!str") || !pnpmArchKeys[k.Value] {
				return "has a member other than os, cpu and libc"
			}
			if list.Kind != yaml.SequenceNode || len(list.Content) > 64 {
				return fmt.Sprintf("has %s that is not a short list", k.Value)
			}
			for _, e := range list.Content {
				if !scalar(e, "!!str") || !pnpmArchValueRE.MatchString(e.Value) {
					return fmt.Sprintf("has %s with an element that is not a platform name", k.Value)
				}
			}
		}
	}
	return ""
}
