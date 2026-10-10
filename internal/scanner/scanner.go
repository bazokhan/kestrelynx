// Package scanner runs Trivy against container images and converts its JSON
// output into KestreLynx's neutral Finding/ImageScan types.
//
// The neutral types deliberately hide Trivy's schema so that downstream
// packages (analyze, notify) never import Trivy-shaped data, and so a
// different scanner could be substituted later. See docs/TRIVY_OUTPUT.md for
// the validated field mapping this code depends on.
package scanner

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// PkgClass distinguishes OS packages (distro versioning, not semver) from
// language packages (semver). This drives whether analyze applies a semver
// breaking-change judgement.
//
// PkgClass itself now lives in inventory (the shared observation vocabulary
// scanner, analyze, and remediation all build on); this is a type alias so
// every existing scanner.PkgClass call site keeps compiling unchanged.
type PkgClass = inventory.PkgClass

const (
	ClassOS   = inventory.ClassOS
	ClassLang = inventory.ClassLang
)

// Status mirrors Trivy's vulnerability status and is the primary axis for
// triage (more meaningful than "has a fixed version"). See docs/TRIVY_OUTPUT.md §5.
//
// Trivy defines eight values. The raw value is kept as-is (apart from the
// missing-key case, see ParseReport), including values outside this list:
// deciding what a status means for the report is analyze's job, not the
// parser's.
type Status string

const (
	StatusFixed              Status = "fixed"
	StatusAffected           Status = "affected"
	StatusWontFix            Status = "will_not_fix"
	StatusFixDeferred        Status = "fix_deferred"
	StatusUnderInvestigation Status = "under_investigation"
	StatusEndOfLife          Status = "end_of_life"
	StatusNotAffected        Status = "not_affected"
	StatusUnknown            Status = "unknown"
)

// Severity is restricted in practice to HIGH/CRITICAL because KestreLynx asks
// Trivy to filter, but the raw string is preserved as-is.
type Severity string

const (
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is one vulnerability in one package of one image.
type Finding struct {
	Image        string
	Class        PkgClass
	Package      string
	InstalledVer string
	FixedVer     string // empty unless Status == fixed
	Status       Status
	Severity     Severity
	VulnID       string
	URL          string
	Title        string // short human-readable summary of the vulnerability, if Trivy supplied one

	// Type is Trivy's raw Result.Type for the package's Result. It is kept
	// verbatim (not just the PackageRef.Ecosystem it normalizes to through
	// the allowlist) so a value outside that allowlist is not lost, only
	// classified as unknown for aggregation purposes.
	Type string
	// Target is Trivy's Result.Target with a single leading "/" stripped if
	// present, so it compares equal to the container-rooted paths runtime
	// evidence reports. For an OS Result this is a descriptive label
	// ("image:tag (distro version)"), not a path; for a lang Result it is
	// either a path (a compiled binary) or a runtime label ("Python",
	// "Node.js", "Java").
	Target string
	// PkgPath is Trivy's per-vulnerability PkgPath (e.g. the site-packages
	// METADATA file, or the node_modules package.json) a language package
	// was found at, normalized the same way as Target. Empty when Trivy
	// didn't report one (typically OS packages, and any language package
	// resolved without a distinct file path).
	PkgPath string
	// LayerDiffID and LayerDigest are Trivy's Layer.DiffID and Layer.Digest of
	// the layer the vulnerable package was attributed to, verbatim. Either is
	// empty when the report carried none (Trivy attributes a package to a
	// layer only for images it could read layer by layer). LayerDiffID is the
	// value that can be looked up in ImageScan.DiffIDs.
	LayerDiffID string
	LayerDigest string
}

// PackageRef is f's aggregation identity: Ecosystem (Type normalized through
// the allowlist), Class, Name (== Package), and Version (== InstalledVer).
// It is a method, not a stored field, so there is exactly one place that
// computes it: every caller — analyze's aggregation, a test fixture built by
// hand that never set Type — gets a value that is always consistent with
// Class/Package/InstalledVer/Type, rather than a second, independently
// settable copy that could silently drift from them.
func (f Finding) PackageRef() inventory.PackageRef {
	return inventory.PackageRef{
		Ecosystem: inventory.ParseEcosystem(f.Type),
		Class:     f.Class,
		Name:      f.Package,
		Version:   f.InstalledVer,
	}
}

// ScanSource distinguishes where a scan target's bytes are fetched from: it
// determines both the trivy invocation shape and how analyze treats a scan
// that could not be pinned (see docs/development/image-identity-model.md).
type ScanSource string

const (
	// SourceLocal is the runtime's own image store (Docker): a scan that
	// fell back to scanning by reference there had no better option, and a
	// clean result is trusted the same way it always has been.
	SourceLocal ScanSource = "local"
	// SourceRemote is a registry (Kubernetes, reached over the network): a
	// scan that could not be pinned there is scanning whatever a mutable tag
	// currently resolves to, so a clean result must not be trusted the same
	// way — see analyze's unconfirmed accounting.
	SourceRemote ScanSource = "remote"
)

// ImageScan is the result of scanning a single image. Err is non-nil when the
// scan itself failed (e.g. image could not be pulled); callers should surface
// it rather than dropping it.
type ImageScan struct {
	Image    string
	OSFamily string
	// OSName is Metadata.OS.Name verbatim: the OS release the family is at
	// ("12.5" for Debian, "22.04" for Ubuntu, "3.19.1" for Alpine); empty when
	// the report carried none.
	OSName   string
	OSEOSL   bool // base OS is end-of-life: no more security updates
	Findings []Finding
	Err      error

	// Identity fields. They describe what was actually scanned, separately
	// from Image (the display name pinned to the caller's reference). See
	// docs/development/image-identity-model.md.
	Subject         inventory.ImageSubject // the identity this scan was asked to confirm (ScanTarget.Subject)
	ScannedKey      inventory.EntityKey    // the entity Trivy's own metadata resolved to scanning, zero value if it didn't resolve one
	RegistryDigests []string               // Metadata.RepoDigests, sorted; a display/correlation attribute, never an identity
	// Platform is Metadata.ImageConfig.{os,architecture,variant}, copied
	// through without validation or normalization (empty stays empty; never
	// guessed). For a registry-kind pin it is the evidence reconcileTarget
	// checks against the requested Subject.Key.Platform.
	Platform inventory.Platform
	// Pinned is true only when Subject.Resolved, the scan itself succeeded
	// (Err == nil), and ScannedKey equals Subject.Key — it is derived from
	// those three facts alone and never set independently of them.
	Pinned bool
	Source ScanSource // where this scan's bytes came from

	// DiffIDs is Metadata.DiffIDs, the image's filesystem layer IDs from the
	// bottom layer up, verbatim; nil when the report carried none.
	DiffIDs []string

	// TrivyVersion is the report's Trivy.Version, "" when the report did not
	// carry one.
	TrivyVersion string
	// Packages lists, per Result, every package Trivy reported (not only the
	// vulnerable ones), in report order. At most maxRetainedPackages packages
	// are kept across the whole scan.
	Packages []ResultPackages
	// PackagesTruncated is true when the report held more packages than
	// maxRetainedPackages, so Packages is a prefix of the full list and must
	// not be read as complete.
	PackagesTruncated bool
}

// maxRetainedPackages bounds how many packages ParseReport keeps per scan, so
// a hostile or corrupt report cannot make the parser hold unbounded memory.
// Real images list a few thousand packages at most.
const maxRetainedPackages = 200000

// ResultPackages is the package list of one Trivy Result.
type ResultPackages struct {
	Target   string // Result.Target, normalized like Finding.Target
	Class    PkgClass
	Type     string // Result.Type, verbatim
	Packages []Package
}

// Package is one installed package from a Trivy Result.
type Package struct {
	Name    string
	Version string // formatted like Finding.InstalledVer (epoch and release included)
	// PkgPath is the file the package was found at, normalized like
	// Finding.PkgPath; empty when Trivy reported none.
	PkgPath string
}

// ScanTarget names the image to scan. Subject carries the identity to pin
// to: Subject.Ref is always the display name pinned to the result;
// Subject.Key, when Subject.Resolved, is the entity the caller wants Trivy
// to confirm instead of a reference that could move between enumeration and
// scan. Registry is where to fetch from when Source is SourceRemote (zero
// value for Docker).
type ScanTarget struct {
	Subject  inventory.ImageSubject
	Registry inventory.RegistryRef
	Source   ScanSource
}

// trivyReport is the subset of Trivy's JSON schema (SchemaVersion 2) that
// KestreLynx depends on. Fields we don't use are intentionally omitted.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Trivy        struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Metadata struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			EOSL   bool   `json:"EOSL"`
		} `json:"OS"`
		ImageID     string   `json:"ImageID"`
		DiffIDs     []string `json:"DiffIDs"`
		RepoDigests []string `json:"RepoDigests"`
		ImageConfig struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"ImageConfig"`
	} `json:"Metadata"`
	Results []struct {
		Class    string `json:"Class"`
		Type     string `json:"Type"`
		Target   string `json:"Target"`
		Packages []struct {
			Name     string `json:"Name"`
			Version  string `json:"Version"`
			Release  string `json:"Release"`
			Epoch    int    `json:"Epoch"`
			FilePath string `json:"FilePath"`
		} `json:"Packages"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Status           string `json:"Status"`
			Severity         string `json:"Severity"`
			PrimaryURL       string `json:"PrimaryURL"`
			Title            string `json:"Title"`
			Layer            struct {
				Digest string `json:"Digest"`
				DiffID string `json:"DiffID"`
			} `json:"Layer"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseReport converts one Trivy JSON report into an ImageScan. It is pure and
// fully testable, kept separate from CLI execution so parsing can be verified
// against recorded fixtures.
func ParseReport(data []byte) (ImageScan, error) {
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return ImageScan{}, fmt.Errorf("parse trivy report: %w", err)
	}

	var diffIDs []string
	if len(r.Metadata.DiffIDs) > 0 {
		diffIDs = append([]string(nil), r.Metadata.DiffIDs...)
	}

	var registryDigests []string
	if len(r.Metadata.RepoDigests) > 0 {
		registryDigests = append([]string(nil), r.Metadata.RepoDigests...)
		sort.Strings(registryDigests)
	}

	scan := ImageScan{
		Image:           r.ArtifactName,
		OSFamily:        r.Metadata.OS.Family,
		OSName:          r.Metadata.OS.Name,
		OSEOSL:          r.Metadata.OS.EOSL,
		TrivyVersion:    r.Trivy.Version,
		DiffIDs:         diffIDs,
		RegistryDigests: registryDigests,
		Platform: inventory.Platform{
			OS:           r.Metadata.ImageConfig.OS,
			Architecture: r.Metadata.ImageConfig.Architecture,
			Variant:      r.Metadata.ImageConfig.Variant,
		},
	}
	// A Metadata.ImageID that fails the boundary check is never normalized
	// or guessed at: ScannedKey simply stays the zero value, same as an
	// entity that never resolved one.
	if d, ok := inventory.ParseDigest(inventory.DigestConfig, r.Metadata.ImageID); ok {
		scan.ScannedKey = inventory.EntityKey{Digest: d}
	}

	retained := 0
	for _, res := range r.Results {
		class := classOf(res.Class)
		target := trimLeadingSlash(res.Target)
		if len(res.Packages) > 0 {
			rp := ResultPackages{Target: target, Class: class, Type: res.Type}
			for _, p := range res.Packages {
				if retained >= maxRetainedPackages {
					scan.PackagesTruncated = true
					break
				}
				rp.Packages = append(rp.Packages, Package{
					Name:    p.Name,
					Version: formatPackageVersion(p.Epoch, p.Version, p.Release),
					PkgPath: trimLeadingSlash(p.FilePath),
				})
				retained++
			}
			if len(rp.Packages) > 0 {
				scan.Packages = append(scan.Packages, rp)
			}
		}
		for _, v := range res.Vulnerabilities {
			// Trivy stores the status as an enum whose zero value is
			// "unknown" and serializes it with omitempty, so an unknown
			// status arrives as a missing key rather than the string.
			status := Status(v.Status)
			if status == "" {
				status = StatusUnknown
			}
			scan.Findings = append(scan.Findings, Finding{
				Image:        r.ArtifactName,
				Class:        class,
				Package:      v.PkgName,
				InstalledVer: v.InstalledVersion,
				FixedVer:     v.FixedVersion,
				Status:       status,
				Severity:     Severity(v.Severity),
				VulnID:       v.VulnerabilityID,
				URL:          v.PrimaryURL,
				Title:        v.Title,
				Type:         res.Type,
				Target:       target,
				PkgPath:      trimLeadingSlash(v.PkgPath),
				LayerDiffID:  v.Layer.DiffID,
				LayerDigest:  v.Layer.Digest,
			})
		}
	}

	return scan, nil
}

// classOf maps Trivy's Result.Class to our PkgClass. Trivy uses "os-pkgs" for
// distro packages and "lang-pkgs" for language dependencies; anything else is
// treated as a language package (the conservative choice, since OS handling
// suppresses semver and we'd rather not wrongly suppress it).
func classOf(trivyClass string) PkgClass {
	if trivyClass == "os-pkgs" {
		return ClassOS
	}
	return ClassLang
}

// trimLeadingSlash strips a single leading "/" from a Trivy path field
// (Result.Target, Vulnerability.PkgPath) so it compares equal to the
// container-rooted, slash-stripped paths runtime evidence reports. Values
// that aren't paths at all (an OS Result's descriptive Target, a language
// runtime label like "Python") never start with "/" and pass through
// unchanged.
func trimLeadingSlash(s string) string {
	if len(s) > 0 && s[0] == '/' {
		return s[1:]
	}
	return s
}

// formatPackageVersion renders a package version the way Trivy writes
// Vulnerability.InstalledVersion: "[epoch:]version[-release]", the epoch
// omitted when zero.
func formatPackageVersion(epoch int, version, release string) string {
	v := version
	if release != "" {
		v += "-" + release
	}
	if epoch != 0 {
		v = fmt.Sprintf("%d:%s", epoch, v)
	}
	return v
}
