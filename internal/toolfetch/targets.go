package toolfetch

import (
	"fmt"
	"strings"
)

// Manager names a package manager the package fetches.
type Manager string

const (
	ManagerNpm  Manager = "npm"
	ManagerPnpm Manager = "pnpm"
	ManagerUv   Manager = "uv"
)

// Archive formats of the files handed out.
const (
	FormatNpmTgz = "npm-tgz"
	FormatWheel  = "wheel"
)

// Platforms the files are fetched for.
const (
	PlatformAmd64 = "linux/amd64"
	PlatformArm64 = "linux/arm64"
)

// defaultVersions holds, per runtime id, the exact version of each manager
// used when a project does not declare one. A value is the newest stable
// release that was past its waiting period when the table was made, and that
// is known to work with the runtime's Node.js (or Python).
var defaultVersions = map[string]map[Manager]string{
	"node24":     {ManagerPnpm: "11.28.5", ManagerNpm: "11.21.0"},
	"node22":     {ManagerPnpm: "11.28.5", ManagerNpm: "11.21.0"},
	"node20":     {ManagerPnpm: "10.34.6"},
	"python3.11": {ManagerUv: "0.13.0"},
	"python3.12": {ManagerUv: "0.13.0"},
	"python3.13": {ManagerUv: "0.13.0"},
	"python3.14": {ManagerUv: "0.13.0"},
}

// DefaultVersion returns the exact version of the manager that runs in the
// runtime (an id such as "node24" or "python3.13") when the project declares
// none, or "" when the table has none for the pair.
func DefaultVersion(manager Manager, runtimeID string) string {
	return defaultVersions[runtimeID][manager]
}

// managerNodeEngines holds, per manager and major version, the engines.node
// range the registry publishes for the releases of that major version (the
// same for every release of 9 to 12 of pnpm and npm published when the table
// was made). pnpm 12 publishes ">=18.*", which is written here as ">=18.0.0".
var managerNodeEngines = map[Manager]map[int]string{
	ManagerNpm: {
		9:  "^14.17.0 || ^16.13.0 || >=18.0.0",
		10: "^18.17.0 || >=20.5.0",
		11: "^20.17.0 || >=22.9.0",
		12: "^22.22.2 || ^24.15.0 || >=26.0.0",
	},
	ManagerPnpm: {
		9:  ">=18.12.0",
		10: ">=18.12.0",
		11: ">=22.13.0",
		12: ">=18.0.0",
	},
}

// NodeEngines returns the range of Node.js versions a release of the manager
// declares it runs on (its engines.node), and false for a manager or a
// version the table has no range for. It is the range of the major version of
// the release as the registry publishes it; whether a release is taken is
// still decided from its own document when it is provided.
func NodeEngines(manager Manager, version string) (string, bool) {
	v, ok := parseExact(version)
	if !ok {
		return "", false
	}
	r, ok := managerNodeEngines[manager][int(v[0])]
	return r, ok
}

// Supported ranges of the managers.
const (
	minUv = "0.12.22"
)

// target is what a request resolves to: the packages to fetch and how the
// result is handed out.
type target struct {
	manager Manager
	ver     version
	version string
	// main is the file handed out; wrapper, when set, is a second file that
	// only the hash a project declared is checked against (pnpm 12, whose
	// declared hash is the wrapper package's).
	main    source
	wrapper *source
	format  string
	entry   string
	runNode bool
}

// source names one file in a registry.
type source struct {
	registry string // "npm" or "pypi"
	name     string // package name
	// filePick selects the PyPI file by platform; unused for npm.
	platform string
}

// resolve checks that a request is inside the supported range and names the
// packages to fetch.
func resolve(req Request) (target, *Error) {
	var t target
	v, ok := parseExact(req.Version)
	if !ok {
		why := "is not an exact release version"
		if strings.ContainsAny(req.Version, "-+") {
			why = "is a pre-release or carries build metadata"
		}
		return t, manual(CodeVersionUnsupported, "%s %q %s", req.Manager, req.Version, why)
	}
	t.manager, t.ver, t.version = req.Manager, v, req.Version
	var arch string
	switch req.Platform {
	case PlatformAmd64:
		arch = "x64"
	case PlatformArm64:
		arch = "arm64"
	default:
		return t, manual(CodeVersionUnsupported, "platform %q is not supported", req.Platform)
	}
	switch req.Manager {
	case ManagerNpm:
		if v[0] < 9 || v[0] > 12 {
			return t, manual(CodeVersionUnsupported, "npm %s is outside the supported range 9 to 12", req.Version)
		}
		t.main = source{registry: "npm", name: "npm"}
		t.format, t.entry, t.runNode = FormatNpmTgz, "bin/npm-cli.js", true
	case ManagerPnpm:
		switch {
		case v[0] < 9 || v[0] > 12:
			return t, manual(CodeVersionUnsupported, "pnpm %s is outside the supported range 9 to 12", req.Version)
		case v[0] == 12:
			t.main = source{registry: "npm", name: "@pnpm/exe.linux-" + arch}
			t.wrapper = &source{registry: "npm", name: "pnpm"}
			t.format, t.entry, t.runNode = FormatNpmTgz, "pnpm", false
		default:
			t.main = source{registry: "npm", name: "pnpm"}
			t.format, t.runNode = FormatNpmTgz, true
			t.entry = "bin/pnpm.cjs"
			if v[0] == 11 {
				t.entry = "bin/pnpm.mjs"
			}
		}
	case ManagerUv:
		floor, _ := parseExact(minUv)
		if v.cmp(floor) < 0 {
			return t, manual(CodeVersionUnsupported, "uv %s is older than %s, which rewrites the lockfile revision when it updates", req.Version, minUv)
		}
		t.main = source{registry: "pypi", name: "uv", platform: req.Platform}
		t.format = FormatWheel
		t.entry = fmt.Sprintf("uv-%s.data/scripts/uv", req.Version)
	default:
		return t, manual(CodeVersionUnsupported, "manager %q is not fetched", req.Manager)
	}
	return t, nil
}

// CheckVersion reports whether the version of a manager is one the package
// fetches: an exact release inside the supported range. why says what is
// wrong when it is not. It looks at the version alone; whether the release
// exists, is old enough or runs on the Node.js of a job is decided when it is
// provided.
func CheckVersion(manager Manager, version string) (ok bool, why string) {
	if _, err := resolve(Request{Manager: manager, Version: version, Platform: PlatformAmd64}); err != nil {
		return false, err.Detail
	}
	return true, ""
}
