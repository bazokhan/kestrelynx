package evidence

import (
	"path"
	"regexp"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// embeddedEcosystems are the ecosystems whose packages are judged by
// matching a Trivy Result.Target against an observed executable's path:
// compiled languages, where the package is embedded directly into the
// binary rather than loaded by a separate runtime, and the Node.js runtime
// binary itself, whose Target is the node executable.
var embeddedEcosystems = map[inventory.Ecosystem]bool{
	inventory.EcosystemGoBinary:    true,
	inventory.EcosystemRustBinary:  true,
	inventory.EcosystemNodeRuntime: true,
}

// runtimeRule is one ecosystem's runtime-executable-name condition: a set of
// exact names, plus an optional regexp for a versioned form (e.g.
// python3.11, php-fpm8.2). Both are checked against an executable's
// resolved final path element, never its symlink name.
type runtimeRule struct {
	exact     map[string]bool
	versionRE *regexp.Regexp // nil if this ecosystem has no versioned form
}

// runtimeRules is the initial mapping from a language ecosystem whose
// packages are loaded by a runtime process to the executable names that
// runtime is observed under.
var runtimeRules = map[inventory.Ecosystem]runtimeRule{
	// python-pkg and conda-pkg share the same condition: both are read by
	// whichever Python interpreter is running.
	inventory.EcosystemPythonPkg: {
		exact:     map[string]bool{"python": true, "python3": true},
		versionRE: regexp.MustCompile(`^python3\.\d+$`),
	},
	inventory.EcosystemCondaPkg: {
		exact:     map[string]bool{"python": true, "python3": true},
		versionRE: regexp.MustCompile(`^python3\.\d+$`),
	},
	inventory.EcosystemNodePkg: {
		exact: map[string]bool{"node": true, "nodejs": true},
	},
	inventory.EcosystemJar: {
		exact: map[string]bool{"java": true},
	},
	inventory.EcosystemGemSpec: {
		exact: map[string]bool{"ruby": true},
	},
	// Trivy's actual Result.Type for a composer.lock scan is "composer"
	// (inventory.EcosystemComposer), and for a vendor/ tree scan is
	// "composer-vendor" (inventory.EcosystemComposerVendor). Both are PHP's
	// package manager output, read the same way.
	inventory.EcosystemComposer: {
		exact:     map[string]bool{"php": true, "php-fpm": true},
		versionRE: regexp.MustCompile(`^php-fpm[0-9]+(\.[0-9]+)?$`),
	},
	inventory.EcosystemComposerVendor: {
		exact:     map[string]bool{"php": true, "php-fpm": true},
		versionRE: regexp.MustCompile(`^php-fpm[0-9]+(\.[0-9]+)?$`),
	},
	inventory.EcosystemDotNetCore: {
		exact: map[string]bool{"dotnet": true},
	},
}

// EcosystemMapped reports whether eco has a runtime-matching entry at all,
// embedded or runtime-loaded. An ecosystem outside this set is
// ecosystem_unmapped, never silently treated as not-observed.
func EcosystemMapped(eco inventory.Ecosystem) bool {
	if embeddedEcosystems[eco] {
		return true
	}
	_, ok := runtimeRules[eco]
	return ok
}

// IsEmbeddedEcosystem reports whether eco's packages are judged by matching
// a compiled binary's path, as opposed to a runtime process's name.
func IsEmbeddedEcosystem(eco inventory.Ecosystem) bool {
	return embeddedEcosystems[eco]
}

// normalizeContainerPath strips exactly one leading "/" so that Trivy's
// Result.Target (recorded without one, e.g. "usr/local/bin/trivy") and the
// Sensor's executables[].path (a container root-relative absolute path,
// which always has one) compare equal.
func normalizeContainerPath(p string) string {
	return strings.TrimPrefix(p, "/")
}

// RuntimeNameMatches reports whether execPath's final path element is one of
// eco's runtime executable names, from the table above. execPath is expected
// to already be a symlink-resolved path — the Sensor records
// executables[].path after resolving /proc/<pid>/exe or bpf_d_path, never a
// symlink's own name — this function only takes the final element, it does
// not resolve anything itself.
func RuntimeNameMatches(eco inventory.Ecosystem, execPath string) bool {
	rule, ok := runtimeRules[eco]
	if !ok {
		return false
	}
	name := path.Base(execPath)
	if rule.exact[name] {
		return true
	}
	return rule.versionRE != nil && rule.versionRE.MatchString(name)
}
