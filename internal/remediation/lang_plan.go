package remediation

import (
	"context"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Plan categories of the language-package part. The other categories (manual,
// deferred, failed) are shared with the distributed-image part.
const (
	// CategoryDependencyUpdateCandidate: the dependency files hold the
	// packages at the affected versions and a target version was chosen from
	// the reported fixes. Neither the update nor a check of its result has
	// been run, so it says nothing about what a package manager would do.
	CategoryDependencyUpdateCandidate Category = "dependency_update_candidate"
	// CategoryRebuildExpected: a requirement that is not an exact pin allows
	// a fixed version, so building the image again is expected to take it.
	CategoryRebuildExpected Category = "rebuild_expected"
)

// Reasons of the language-package part.
const (
	// Reasons for a candidate or an expectation.
	ReasonUpdateCandidateInSource Reason = "update_candidate_in_source"
	ReasonRangeAllowsFix          Reason = "range_allows_fix"

	// Reasons for the dependency files of a unit.
	ReasonDependencyFilesNotFound Reason = "dependency_files_not_found"
	ReasonAmbiguousDependencyFile Reason = "ambiguous_dependency_files"
	ReasonDependencyFileUnusable  Reason = "dependency_file_unusable"
	ReasonUnsupportedLockfile     Reason = "unsupported_lockfile"
	ReasonWorkspaceUnsupported    Reason = "workspace_unsupported"
	// ReasonWorkspaceSettingsUnsupported: a pnpm-workspace.yaml that is not a
	// workspace sets something other than the settings the plan accepts.
	ReasonWorkspaceSettingsUnsupported Reason = "workspace_settings_unsupported"
	ReasonDynamicMetadata              Reason = "dynamic_metadata"
	ReasonUnsupportedRequirements      Reason = "unsupported_requirements"
	ReasonUnparsableSource             Reason = "unparsable_source"
	ReasonUnsupportedSource            Reason = "unsupported_source_settings"
	ReasonScanNotPinned                Reason = "scan_not_pinned"

	// Reasons for a package.
	ReasonNotFoundInSource   Reason = "not_found_in_source"
	ReasonNonRegistrySource  Reason = "non_registry_source"
	ReasonSdistOnly          Reason = "sdist_only"
	ReasonForcedByOverride   Reason = "forced_by_override"
	ReasonMarkerNotEvaluated Reason = "marker_not_evaluated"
	ReasonInvalidMarker      Reason = "invalid_marker"
	ReasonMultipleVersions   Reason = "multiple_versions"
	ReasonUnparsableVersion  Reason = "unparsable_version"
	ReasonNoFixedVersion     Reason = "no_fixed_version_above_installed"
	ReasonRangeExcludesFix   Reason = "constraint_excludes_fix"
	ReasonRangeNotEvaluable  Reason = "constraint_not_evaluable"

	// Reasons for reading the source.
	ReasonSourceNotFound     Reason = "source_not_found"
	ReasonSourceAccessDenied Reason = "source_access_denied"
	ReasonSourceTooLarge     Reason = "source_too_large"
	ReasonFileTooLarge       Reason = "file_too_large"
	ReasonByteBudget         Reason = "byte_budget_exhausted"
	ReasonSourceError        Reason = "source_error"
	ReasonGitHubBudget       Reason = "github_budget_exhausted"
)

// DependencyManager is the package manager a unit's files belong to.
type DependencyManager string

const (
	ManagerNpm  DependencyManager = "npm"
	ManagerPnpm DependencyManager = "pnpm"
	ManagerUv   DependencyManager = "uv"
	ManagerPip  DependencyManager = "pip"
)

// LockfileName is the file whose entries the unit's packages are matched
// against.
func (m DependencyManager) LockfileName() string {
	switch m {
	case ManagerNpm:
		return "package-lock.json"
	case ManagerPnpm:
		return "pnpm-lock.yaml"
	case ManagerUv:
		return "uv.lock"
	case ManagerPip:
		return "requirements.txt"
	}
	return ""
}

// scheme is the version ordering of the manager's ecosystem.
func (m DependencyManager) scheme() scheme {
	if m == ManagerUv || m == ManagerPip {
		return schemePEP440
	}
	return schemeSemver
}

// DependencyMapping ties running Compose workloads to the directory of a
// repository whose dependency files resolve their language packages.
type DependencyMapping struct {
	// Workload is the Compose workload key, compose/<project>/<service>, with
	// Project and Service as its parts; or the Kubernetes key, or
	// container/<name> for a container started outside Compose, with both
	// parts empty.
	Workload   string
	Project    string
	Service    string
	Repository string
	BaseBranch string
	Directory  string // "." for the repository root
}

// GitHubReader is the part of the read-only GitHub client the planner uses.
type GitHubReader interface {
	ResolveBranch(ctx context.Context, repo, branch string) (string, error)
	ListDirectory(ctx context.Context, repo, sha, dir string) ([]github.Entry, error)
	ReadFile(ctx context.Context, repo, sha, path string) (github.File, error)
}

var _ GitHubReader = (*github.Client)(nil)

// SourceFile is a source file read at the unit's commit.
type SourceFile struct {
	Path    string `json:"path"`
	BlobSHA string `json:"blob_sha"`
	// Repository and BaseBranch name where the file was read when that is not
	// the repository and branch of the item that lists it (a Compose file in a
	// deployment repository beside a Dockerfile elsewhere); empty otherwise.
	Repository string `json:"repository,omitempty"`
	BaseBranch string `json:"base_branch,omitempty"`
}

// SourceRecord says where a unit's dependency files came from. The mapping
// that names it is the user's own configuration, so it is asserted, not
// verified: matching names and versions show that the files list the package,
// not that the running image was built from them.
type SourceRecord struct {
	Repository string `json:"repository"`
	BaseBranch string `json:"base_branch"`
	Directory  string `json:"directory"`
	// CommitSHA is the commit the branch resolved to; every file was read
	// from it. Empty when the branch could not be resolved.
	CommitSHA string       `json:"commit_sha,omitempty"`
	Files     []SourceFile `json:"files,omitempty"`
	// Absent are the files the plan looked for and did not find, because
	// their presence would change the unit's inputs (a pnpm-workspace.yaml
	// added later is a setting nothing here has seen). They are repository
	// paths, like Files.
	Absent     []string   `json:"absent,omitempty"`
	Origin     OriginKind `json:"origin"`
	Confidence Confidence `json:"confidence"`
}

// Relation says how a package is required: by the project itself (direct),
// by other packages (transitive) or both.
type Relation string

const (
	RelationDirect     Relation = "direct"
	RelationTransitive Relation = "transitive"
	RelationMixed      Relation = "mixed"
)

// PackageAction is what the plan proposes for one package of a unit.
type PackageAction string

const (
	ActionUpdate          PackageAction = "update"
	ActionRebuildExpected PackageAction = "rebuild_expected"
	ActionManual          PackageAction = "manual"
)

// SourceOccurrence is one place a package appears in the dependency files.
type SourceOccurrence struct {
	// Path locates it: an npm lockfile path (node_modules/a/node_modules/b),
	// a pnpm snapshot key, a uv package, or a requirements line (file:line).
	Path string `json:"path,omitempty"`
	// Version is the locked or pinned version; empty for a requirement that
	// is not an exact pin.
	Version string `json:"version,omitempty"`
	Direct  bool   `json:"direct"`
	// Unpinned marks a requirement that is not an exact pin; Constraint is
	// its version specifier, empty when it names no version.
	Unpinned   bool   `json:"unpinned,omitempty"`
	Constraint string `json:"constraint,omitempty"`
	// Marker is the environment marker of a requirements line; Extras are the
	// extras it names. Extras do not change how the package's own version is
	// handled; a marker is not evaluated, so a line with one is not updated.
	Marker string   `json:"marker,omitempty"`
	Extras []string `json:"extras,omitempty"`
	// Matched marks the occurrences of the version the image runs.
	Matched bool `json:"matched,omitempty"`
	// ManualReason, when set, says this occurrence cannot be updated
	// automatically.
	ManualReason Reason `json:"manual_reason,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// CVERef is one vulnerability a package update is meant to fix.
type CVERef struct {
	VulnID    string           `json:"vuln_id"`
	Severity  scanner.Severity `json:"severity,omitempty"`
	FixedVers []string         `json:"fixed_vers,omitempty"` // every fixed version reported, sorted
	Priority  Priority         `json:"priority,omitempty"`
	KEV       bool             `json:"kev,omitempty"`
}

// FindingOrigin is one finding of a running image that a package entry came
// from: which image content, which package, which vulnerability, where the
// scanner saw it and for which workload. Together they are the correspondence
// between the running image and the unit's dependency files.
type FindingOrigin struct {
	Entity    string `json:"entity"` // the verified entity key of the scanned image
	Ecosystem string `json:"ecosystem,omitempty"`
	Class     string `json:"class,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	VulnID    string `json:"vuln_id"`
	Target    string `json:"target,omitempty"`
	PkgPath   string `json:"pkg_path,omitempty"`
	Workload  string `json:"workload"`
}

// key is the origin as one comparable string.
func (o FindingOrigin) key() string {
	return strings.Join([]string{o.Entity, o.Ecosystem, o.Class, o.Name, o.Version, o.VulnID, o.Target, o.PkgPath, o.Workload}, "\x00")
}

// LanguagePackage is one package version running in the image, with what the
// unit's dependency files say about it.
type LanguagePackage struct {
	Name string `json:"name"` // as the image reports it
	// Normalized is the Python name used for matching (PEP 503); empty for
	// other ecosystems.
	Normalized string `json:"normalized,omitempty"`
	Ecosystem  string `json:"ecosystem"` // the scanner's result type
	Installed  string `json:"installed"`
	// SelectionLowerBound is the lowest version that fixes every target
	// vulnerability, taken from the reported fixes. It is where candidate
	// selection starts, not a version anything was updated to.
	SelectionLowerBound string `json:"selection_lower_bound,omitempty"`
	// AdoptedVersion is the version an update actually resolved to: the
	// lowest version of the package the updated files hold. Nothing is run in
	// a plan, so only the update stage sets it.
	AdoptedVersion string             `json:"adopted_version,omitempty"`
	Relation       Relation           `json:"relation,omitempty"`
	Occurrences    []SourceOccurrence `json:"occurrences,omitempty"`
	CVEs           []CVERef           `json:"cves,omitempty"`
	// Origins are the findings the entry came from, sorted.
	Origins []FindingOrigin `json:"origins,omitempty"`
	Action  PackageAction   `json:"action"`
	Reason  Reason          `json:"reason,omitempty"`
	Detail  string          `json:"detail,omitempty"`
	// LeftOut marks a package that was planned for an update and then left
	// out of it: the update did not take it to its target while it took the
	// other packages of the unit, so the unit's result is proposed without it.
	// Its action is manual and its reason says why it was left out. It still
	// counts among the inputs the update was made from, so the fingerprint of
	// the unit does not change when some of its packages are left out.
	LeftOut bool `json:"left_out,omitempty"`
	// Through names the direct dependencies an update moved to bring the
	// package to its fixed version, when the packages that held it back had to
	// be updated too.
	Through []string `json:"through,omitempty"`
}

// KEVCount is how many of the package's vulnerabilities are KEV-listed.
func (p LanguagePackage) KEVCount() int {
	n := 0
	for _, c := range p.CVEs {
		if c.KEV {
			n++
		}
	}
	return n
}

// LanguageItem is the plan entry of one dependency unit: a directory of a
// repository at one commit, shared by every workload mapped to it.
type LanguageItem struct {
	Key       string            `json:"key"`
	Workloads []string          `json:"workloads"`
	Manager   DependencyManager `json:"manager,omitempty"`
	Priority  Priority          `json:"priority,omitempty"` // strongest priority among the packages' vulnerabilities

	Category Category `json:"category"`
	Reason   Reason   `json:"reason,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	// RuntimeEOL is set with the reason runtime_eol: the runtime the update
	// would run in and the date its support ended.
	RuntimeEOL *RuntimeEOLInfo `json:"runtime_eol,omitempty"`

	Source   SourceRecord      `json:"source"`
	Packages []LanguagePackage `json:"packages,omitempty"`

	// UpdateExecuted and PostUpdateCheckExecuted are false in a plan the
	// update stage has not handled: no package manager was run and no result
	// was inspected, so a candidate shows what the files list, not what an
	// update would produce. The update stage sets UpdateExecuted when the
	// update step ran to the end, and PostUpdateCheckExecuted when it got the
	// result of the job and inspected it (the inspection may have rejected
	// it).
	UpdateExecuted          bool `json:"update_executed"`
	PostUpdateCheckExecuted bool `json:"post_update_check_executed"`

	// The following are set by the update stage. Artifacts are the files to
	// write for a pr_candidate (their content is not part of the stored
	// plan), Update records the run and SourceCheck the filesystem check of
	// the dependency files before and after.
	Artifacts   []ArtifactFile  `json:"artifacts,omitempty"`
	Update      *LanguageUpdate `json:"update,omitempty"`
	SourceCheck *SourceCheck    `json:"source_check,omitempty"`

	// RetryAfter is when an item deferred for the age of a release is tried
	// again.
	RetryAfter *time.Time `json:"retry_after,omitempty"`

	// The following are kept only while a pass runs. inputFingerprint is the
	// fingerprint of the inputs before the update stage changed any package;
	// waitIntent is what the pass found out about waiting (see
	// RecordLanguageWaits) and waitFallback the outcome to use when a wait
	// cannot be recorded; chainStopped and priorWait come from the records of
	// earlier passes.
	inputFingerprint string
	waitIntent       *langWaitIntent
	waitFallback     *LanguageItem
	chainStopped     *LangWaitRecord
	priorWait        *LangWaitRecord
}

// Count returns how many of the item's packages have action a.
func (it LanguageItem) Count(a PackageAction) int {
	n := 0
	for _, p := range it.Packages {
		if p.Action == a {
			n++
		}
	}
	return n
}

// CountLanguage returns how many language items are in category c.
func (p Plan) CountLanguage(c Category) int {
	n := 0
	for _, it := range p.LanguageItems {
		if it.Category == c {
			n++
		}
	}
	return n
}

// CountAll returns how many items, image, language and Dockerfile, are in
// category c.
func (p Plan) CountAll(c Category) int { return p.Count(c) + p.CountLanguage(c) + p.CountDockerfile(c) }
