package inventory

// PkgClass distinguishes OS packages (distro versioning, not semver) from
// language packages (semver). This drives whether analyze applies a semver
// breaking-change judgement, and is the common vocabulary both scanner
// (Trivy's os-pkgs/lang-pkgs) and remediation (which manifest a fix belongs
// in) build on.
type PkgClass string

const (
	ClassOS   PkgClass = "os"
	ClassLang PkgClass = "lang"
)

// Ecosystem identifies the package manager or language runtime a package
// belongs to, taken verbatim from Trivy's Result.Type. It is an allowlist,
// not a passthrough: a value outside the allowlist becomes EcosystemUnknown
// rather than being trusted as-is, since an unrecognized Type could be a
// scanner upgrade introducing a new one, or a malformed report, and neither
// case should be treated as if it were a known ecosystem.
type Ecosystem string

// EcosystemUnknown is the zero value: either Result.Type was empty, or it
// was outside the allowlist. It is never guessed at.
const EcosystemUnknown Ecosystem = ""

// OS ecosystems: every OSType Trivy can report for a Class == os-pkgs
// Result (aquasecurity/trivy pkg/fanal/types, v0.71.2).
const (
	EcosystemActiveState        Ecosystem = "activestate"
	EcosystemAlma               Ecosystem = "alma"
	EcosystemAlpine             Ecosystem = "alpine"
	EcosystemAmazon             Ecosystem = "amazon"
	EcosystemAzureLinux         Ecosystem = "azurelinux"
	EcosystemBottlerocket       Ecosystem = "bottlerocket"
	EcosystemCBLMariner         Ecosystem = "cbl-mariner"
	EcosystemCentOS             Ecosystem = "centos"
	EcosystemCentOSStream       Ecosystem = "centos-stream"
	EcosystemChainguard         Ecosystem = "chainguard"
	EcosystemCoreOS             Ecosystem = "coreos"
	EcosystemDebian             Ecosystem = "debian"
	EcosystemEcho               Ecosystem = "echo"
	EcosystemFedora             Ecosystem = "fedora"
	EcosystemMinimOS            Ecosystem = "minimos"
	EcosystemOpenSUSE           Ecosystem = "opensuse"
	EcosystemOpenSUSELeap       Ecosystem = "opensuse-leap"
	EcosystemOpenSUSETumbleweed Ecosystem = "opensuse-tumbleweed"
	EcosystemOracle             Ecosystem = "oracle"
	EcosystemPhoton             Ecosystem = "photon"
	EcosystemRedHat             Ecosystem = "redhat"
	EcosystemRocky              Ecosystem = "rocky"
	EcosystemSLEMicro           Ecosystem = "slem"
	EcosystemSLES               Ecosystem = "sles"
	EcosystemUbuntu             Ecosystem = "ubuntu"
	EcosystemWolfi              Ecosystem = "wolfi"
)

// Language ecosystems: every LangType Trivy can report for a Class ==
// lang-pkgs Result that names an actual package manager or language runtime
// (aquasecurity/trivy pkg/fanal/types, v0.71.2). Trivy's Kubernetes
// distribution types (kubernetes/eks/gke/aks/rke/ocp) are config-file scan
// results, not packages, and are deliberately excluded.
const (
	EcosystemBundler        Ecosystem = "bundler"
	EcosystemGemSpec        Ecosystem = "gemspec"
	EcosystemCargo          Ecosystem = "cargo"
	EcosystemComposer       Ecosystem = "composer"
	EcosystemComposerVendor Ecosystem = "composer-vendor"
	EcosystemNpm            Ecosystem = "npm"
	EcosystemBun            Ecosystem = "bun"
	EcosystemNuGet          Ecosystem = "nuget"
	EcosystemDotNetCore     Ecosystem = "dotnet-core"
	EcosystemPackagesProps  Ecosystem = "packages-props"
	EcosystemPip            Ecosystem = "pip"
	EcosystemPipenv         Ecosystem = "pipenv"
	EcosystemPoetry         Ecosystem = "poetry"
	EcosystemUv             Ecosystem = "uv"
	EcosystemPyLock         Ecosystem = "pylock"
	EcosystemCondaPkg       Ecosystem = "conda-pkg"
	EcosystemCondaEnv       Ecosystem = "conda-environment"
	EcosystemPythonPkg      Ecosystem = "python-pkg"
	EcosystemNodePkg        Ecosystem = "node-pkg"
	EcosystemYarn           Ecosystem = "yarn"
	EcosystemPnpm           Ecosystem = "pnpm"
	EcosystemJar            Ecosystem = "jar"
	EcosystemPom            Ecosystem = "pom"
	EcosystemGradle         Ecosystem = "gradle"
	EcosystemSbt            Ecosystem = "sbt"
	EcosystemGoBinary       Ecosystem = "gobinary"
	EcosystemGoModule       Ecosystem = "gomod"
	EcosystemJavaScript     Ecosystem = "javascript"
	EcosystemRustBinary     Ecosystem = "rustbinary"
	EcosystemConan          Ecosystem = "conan"
	EcosystemCocoapods      Ecosystem = "cocoapods"
	EcosystemSwift          Ecosystem = "swift"
	EcosystemPub            Ecosystem = "pub"
	EcosystemHex            Ecosystem = "hex"
	EcosystemBitnami        Ecosystem = "bitnami"
	EcosystemJulia          Ecosystem = "julia"
)

// EcosystemNodeRuntime is the Node.js runtime itself as installed outside a
// package manager (the official node images unpack nodejs.org's tarball into
// /usr/local). Trivy never reports it: KestreLynx adds these findings itself,
// so this value never appears as a Trivy Result.Type.
const EcosystemNodeRuntime Ecosystem = "node-runtime"

// NodeRuntimePackage is the package name of EcosystemNodeRuntime findings. It
// cannot be an npm package name (npm rejects upper case) and differs from the
// distro package name "nodejs", so it never shares an aggregation or state
// key with either.
const NodeRuntimePackage = "Node.js"

// EcosystemPythonRuntime is the CPython runtime itself as built into the
// official python images (under /usr/local, outside any package manager).
// Like EcosystemNodeRuntime, Trivy never reports it.
const EcosystemPythonRuntime Ecosystem = "python-runtime"

// PythonRuntimePackage is the package name of EcosystemPythonRuntime
// findings. It contains a space, which neither a PyPI project name nor a
// distro package name can, so it never shares a key with either.
const PythonRuntimePackage = "Python runtime"

// knownEcosystems is the allowlist ParseEcosystem checks against.
var knownEcosystems = map[Ecosystem]bool{
	EcosystemActiveState:        true,
	EcosystemAlma:               true,
	EcosystemAlpine:             true,
	EcosystemAmazon:             true,
	EcosystemAzureLinux:         true,
	EcosystemBottlerocket:       true,
	EcosystemCBLMariner:         true,
	EcosystemCentOS:             true,
	EcosystemCentOSStream:       true,
	EcosystemChainguard:         true,
	EcosystemCoreOS:             true,
	EcosystemDebian:             true,
	EcosystemEcho:               true,
	EcosystemFedora:             true,
	EcosystemMinimOS:            true,
	EcosystemOpenSUSE:           true,
	EcosystemOpenSUSELeap:       true,
	EcosystemOpenSUSETumbleweed: true,
	EcosystemOracle:             true,
	EcosystemPhoton:             true,
	EcosystemRedHat:             true,
	EcosystemRocky:              true,
	EcosystemSLEMicro:           true,
	EcosystemSLES:               true,
	EcosystemUbuntu:             true,
	EcosystemWolfi:              true,

	EcosystemBundler:        true,
	EcosystemGemSpec:        true,
	EcosystemCargo:          true,
	EcosystemComposer:       true,
	EcosystemComposerVendor: true,
	EcosystemNpm:            true,
	EcosystemBun:            true,
	EcosystemNuGet:          true,
	EcosystemDotNetCore:     true,
	EcosystemPackagesProps:  true,
	EcosystemPip:            true,
	EcosystemPipenv:         true,
	EcosystemPoetry:         true,
	EcosystemUv:             true,
	EcosystemPyLock:         true,
	EcosystemCondaPkg:       true,
	EcosystemCondaEnv:       true,
	EcosystemPythonPkg:      true,
	EcosystemNodePkg:        true,
	EcosystemYarn:           true,
	EcosystemPnpm:           true,
	EcosystemJar:            true,
	EcosystemPom:            true,
	EcosystemGradle:         true,
	EcosystemSbt:            true,
	EcosystemGoBinary:       true,
	EcosystemGoModule:       true,
	EcosystemJavaScript:     true,
	EcosystemRustBinary:     true,
	EcosystemConan:          true,
	EcosystemCocoapods:      true,
	EcosystemSwift:          true,
	EcosystemPub:            true,
	EcosystemHex:            true,
	EcosystemBitnami:        true,
	EcosystemJulia:          true,
	EcosystemNodeRuntime:    true,
	EcosystemPythonRuntime:  true,
}

// ParseEcosystem maps a raw Trivy Result.Type to an Ecosystem, falling back
// to EcosystemUnknown for anything outside the allowlist. No normalization
// or guessing is applied: a near-miss (wrong case, a deprecated alias) is
// unknown, not corrected.
func ParseEcosystem(trivyType string) Ecosystem {
	e := Ecosystem(trivyType)
	if knownEcosystems[e] {
		return e
	}
	return EcosystemUnknown
}

// PackageRef is a package's identity: which ecosystem it was installed
// through, whether it's an OS or language package, its name, and its
// installed version. It is the aggregation key findings and package groups
// key on, and deliberately not a PURL string — purl construction is
// ecosystem-specific and an incorrectly assembled one is worse than no
// identifier at all, since it invites false matches against other tools.
type PackageRef struct {
	Ecosystem Ecosystem
	Class     PkgClass
	Name      string
	Version   string // the installed version, as reported by the scanner
}
