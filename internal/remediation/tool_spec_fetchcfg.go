package remediation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Settings that make a package manager fetch a tool, a runtime or settings by
// itself, or change what it resolves from outside the lockfile and the
// manifest, are not run: the update controls what is fetched and from where.

// pnpmPackageJSONKeys are the members of package.json's "pnpm" field that
// only say whether install scripts may run or which platforms' optional
// dependencies are installed. Any other (configDependencies, executionEnv,
// overrides, patchedDependencies, ...) is refused.
var pnpmPackageJSONKeys = keySet("onlyBuiltDependencies", "ignoredBuiltDependencies", "neverBuiltDependencies", "allowBuilds", "supportedArchitectures")

// uvToolKeys are the members of [tool.uv] in pyproject.toml that are read.
// workspace is refused earlier, with its own reason.
var uvToolKeys = keySet("required-version", "dev-dependencies", "sources", "package")

// lockRuntime returns where a pnpm lockfile records a runtime that the manager
// downloads: a package (or snapshot) named "<runtime>@runtime:<version>", or a
// dependency whose specifier or version is "runtime:<version>". It reads the
// parsed document, so every way of writing the same YAML is seen.
func lockRuntime(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	doc, err := readPnpmLock(data)
	if err != nil {
		return "", err
	}
	return findRuntime(doc.top, 0), nil
}

func findRuntime(v any, depth int) string {
	if depth > maxYAMLDepth {
		return ""
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(k, "@runtime:") || strings.HasPrefix(k, "runtime:") {
				return k
			}
			if found := findRuntime(x[k], depth+1); found != "" {
				return found
			}
		}
	case []any:
		for _, e := range x {
			if found := findRuntime(e, depth+1); found != "" {
				return found
			}
		}
	case string:
		if strings.HasPrefix(x, "runtime:") || strings.Contains(x, "@runtime:") {
			return x
		}
	}
	return ""
}

// nodeFetchConfigProblem checks the settings of an npm or pnpm unit that
// fetch things.
func nodeFetchConfigProblem(in ToolSpecInput) *UnsupportedError {
	top, err := strictObject(in.Manifest)
	if err != nil || top == nil {
		return unsupported(ReasonUnparsableSource, "package.json cannot be read")
	}
	if in.Manager == ManagerPnpm {
		if raw, ok := top["pnpm"]; ok {
			members, err := nameMap(raw)
			if err != nil || members == nil {
				return unsupported(ReasonToolFetchConfigUnsupported, "package.json pnpm is not an object")
			}
			var bad []string
			for k := range members {
				if !pnpmPackageJSONKeys[k] {
					bad = append(bad, clip(k, 60))
				}
			}
			if len(bad) > 0 {
				sort.Strings(bad)
				return unsupported(ReasonToolFetchConfigUnsupported, "package.json sets pnpm.%s, which can fetch tools or change what is resolved", listKeys(bad))
			}
		}
		if _, ok := top["resolutions"]; ok {
			return unsupported(ReasonToolFetchConfigUnsupported, "package.json sets resolutions, which pnpm applies as overrides from outside the lockfile")
		}
		found, err := lockRuntime(in.Lock)
		if err != nil {
			return unsupported(ReasonUnparsableSource, "pnpm-lock.yaml cannot be read: %v", err)
		}
		if found != "" {
			return unsupported(ReasonToolFetchConfigUnsupported, "pnpm-lock.yaml records the runtime %s, which pnpm downloads", clip(found, 80))
		}
	}
	engines, uerr := objectField(top, "engines", ReasonNodeSpecInvalid)
	if uerr != nil {
		return uerr
	}
	dev, uerr := objectField(top, "devEngines", ReasonNodeSpecInvalid)
	if uerr != nil {
		return uerr
	}
	for where, raw := range map[string]json.RawMessage{"devEngines.runtime": dev["runtime"], "engines.runtime": engines["runtime"]} {
		if raw == nil {
			continue
		}
		entries, uerr := entryList(raw, where, ReasonNodeSpecInvalid)
		if uerr != nil {
			return uerr
		}
		for _, e := range entries {
			if e.onFail == "download" {
				return unsupported(ReasonToolFetchConfigUnsupported, "%s asks the manager to download %s (onFail: download)", where, clip(e.name, 40))
			}
		}
	}
	return nil
}

// uvFetchConfigProblem checks the settings of a uv unit that fetch things or
// change what uv reads.
func uvFetchConfigProblem(in ToolSpecInput) *UnsupportedError {
	if len(in.UvToml) > 0 {
		paths := append([]string(nil), in.UvToml...)
		sort.Strings(paths)
		return unsupported(ReasonToolFetchConfigUnsupported, "%s exists, and uv reads its settings (which may change the index, the Python it uses or what it fetches)", strings.Join(paths, ", "))
	}
	py, err := parseTOML(in.Manifest)
	if err != nil {
		return unsupported(ReasonUnparsableSource, "pyproject.toml cannot be read: %v", err)
	}
	tool, _ := py["tool"].(map[string]any)
	uv, _ := tool["uv"].(map[string]any)
	var bad []string
	for k := range uv {
		if !uvToolKeys[k] {
			bad = append(bad, clip(k, 60))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return unsupported(ReasonToolFetchConfigUnsupported, "pyproject.toml sets [tool.uv] %s, which can change what uv fetches or resolves", listKeys(bad))
	}
	return nil
}

func listKeys(keys []string) string {
	if len(keys) > 5 {
		keys = append(keys[:5:5], fmt.Sprintf("and %d more", len(keys)-5))
	}
	return strings.Join(keys, ", ")
}
