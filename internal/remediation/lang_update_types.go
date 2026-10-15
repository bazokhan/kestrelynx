package remediation

import (
	"context"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Reasons of the dependency update stage. An item the stage could not turn
// into a result is manual (its files or the update need a person), not
// comparable (the check could not be made under the cycle's conditions),
// failed (something broke while working) or deferred (a limit or the cycle's
// deadline stopped it).
const (
	// Deferred.
	ReasonUpdateJobLimit   Reason = "update_job_limit"
	ReasonUpdateInputLimit Reason = "update_input_limit"

	// Failed: the work itself broke.
	ReasonUpdateJobFailed       Reason = "update_job_failed"
	ReasonUpdateResultInvalid   Reason = "update_result_invalid"
	ReasonUpdateJobTimedOut     Reason = "update_job_timed_out"
	ReasonDistributionLookup    Reason = "distribution_lookup_failed"
	ReasonSourceScanFailed      Reason = "source_scan_failed"
	ReasonSourceReadFailed      Reason = "source_read_failed"
	ReasonUpdateInputInvalid    Reason = "update_input_invalid"
	ReasonUpdateJobInputRefused Reason = "update_job_input_rejected"

	// Manual: before the update.
	ReasonManifestEditRequired Reason = "manifest_edit_required"
	// ReasonWorkInputModified: a step changed a settings file it only reads.
	ReasonWorkInputModified         Reason = "input_modified"
	ReasonRequiresPythonUnsupported Reason = "requires_python_unsupported"
	ReasonLockfileInconsistent      Reason = "lockfile_inconsistent"
	ReasonNoWheelForVersion         Reason = "no_wheel_for_version"
	ReasonReleaseYanked             Reason = "release_yanked"
	ReasonPipTargetUndecidable      Reason = "pip_target_undecidable"
	ReasonPipTargetMismatch         Reason = "pip_target_mismatch"
	ReasonRequirementsRewrite       Reason = "requirements_rewrite_unsupported"
	ReasonUpdateSetNotApplied       Reason = "update_set_not_applied"
	// ReasonTargetNotInLockfile: a package to update has no entry in the
	// lockfile, so there is nothing to update it by.
	ReasonTargetNotInLockfile Reason = "target_not_in_lockfile"
	// ReasonNoReresolveTrigger: the project has no direct dependency, other
	// than the packages being updated, that can be taken out of the lockfile to
	// make pnpm resolve again.
	ReasonNoReresolveTrigger Reason = "no_reresolve_trigger"
	// ReasonPnpm12RemovalUnsupported: the project runs a pnpm 12 release
	// before minPnpm12Removal. Those releases either lack --fix-lockfile, stop
	// on a lockfile with entries missing that other entries refer to, or write
	// the lockfile as two documents, so the update by taking entries out
	// cannot be made with them.
	ReasonPnpm12RemovalUnsupported Reason = "pnpm12_removal_unsupported"

	// minPnpm12Removal is the first pnpm 12 release that, given
	// --fix-lockfile, resolves again the entries taken out of its lockfile and
	// keeps the lockfile one document.
	minPnpm12Removal = "12.10.0"

	// Manual: what the job did.
	ReasonUpdateStepFailed       Reason = "update_step_failed"
	ReasonPostUpdateCheckFailed  Reason = "post_update_check_failed"
	ReasonUnexpectedFiles        Reason = "unexpected_files"
	ReasonReleaseAgeViolation    Reason = "release_age_violation"
	ReasonManifestChanged        Reason = "manifest_changed"
	ReasonOutputFilesInvalid     Reason = "output_files_invalid"
	ReasonLockfileFormatChanged  Reason = "lockfile_format_changed"
	ReasonTargetNotUpdated       Reason = "target_not_updated"
	ReasonTargetRemoved          Reason = "target_removed"
	ReasonFixConditionNotMet     Reason = "fix_condition_not_met"
	ReasonUnexplainedDiff        Reason = "unexplained_dependency_diff"
	ReasonDistributionMismatch   Reason = "distribution_mismatch"
	ReasonRegistryCheckLimit     Reason = "registry_check_limit"
	ReasonUpdatePackageLimit     Reason = "update_package_limit"
	ReasonResolvedSourceChanged  Reason = "resolved_source_changed"
	ReasonPostUpdateLockUnstable Reason = "post_update_lockfile_unstable"
	// ReasonDropSideEffect: the dependency that was taken out of the lockfile
	// to make pnpm resolve again did not come back as it was.
	ReasonDropSideEffect Reason = "drop_side_effect"

	// Manual or not comparable: the filesystem check of the dependency files.
	ReasonSourceTargetNotDetectedBefore Reason = "source_target_not_detected_before"
	ReasonSourceTargetNotAnalysedAfter  Reason = "source_target_not_analysed_after"
	ReasonSourceTargetStillDetected     Reason = "source_target_still_detected"
	ReasonSourceIntroduced              Reason = "source_introduced_findings"
	ReasonSourceIntroducedKEV           Reason = "source_introduced_kev"
	ReasonSourceScanIncomplete          Reason = "source_scan_incomplete"

	// Re-resolving the packages that depend on a package that is held back by
	// them: the package reasons of an item whose update needed that, and the
	// reasons below them that say why it did not go through.
	ReasonDependentsNotFixed    Reason = "dependents_update_not_fixed"
	ReasonDependentsRejected    Reason = "dependents_update_rejected"
	ReasonDependentsUnsupported Reason = "dependents_update_unsupported"
	ReasonDependentsLimit       Reason = "dependents_update_limit"
	// ReasonReleaseTooNew: a version the update brings in was published less
	// than the minimum age ago; the item is tried again later.
	ReasonReleaseTooNew Reason = "release_too_new"
	// ReasonChainDowngrade: the update would move a package to an older
	// version on some path, or the versions on the paths cannot be matched.
	ReasonChainDowngrade Reason = "chain_downgrade"
	// ReasonChainMoveLimit: the update changes more entries than allowed.
	ReasonChainMoveLimit Reason = "chain_move_limit"
	// ReasonChainItemBudget: the update needs more work than one item may use.
	ReasonChainItemBudget Reason = "chain_item_budget"
)

// WorkRunner is the part of the work container client the update stage uses.
type WorkRunner interface {
	RunJob(ctx context.Context, spec docker.JobSpec) (docker.JobResult, error)
}

var _ WorkRunner = (*docker.WorkClient)(nil)

// FSScanner scans dependency files for vulnerabilities under the cycle's
// prepared conditions (see scanner.Trivy.ScanFS).
type FSScanner interface {
	ScanFS(ctx context.Context, files map[string][]byte, prepared scanner.ScanConditions) (scanner.FSScan, error)
}

var _ FSScanner = scanner.Trivy{}

// ArtifactFile is one file an update produced, to be written to the
// repository at Path. Content is held for the pull request stage and never
// stored in the plan; the plan keeps the path, size and hash.
type ArtifactFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Mode is the tree entry mode of the file being replaced.
	Mode    string `json:"mode,omitempty"`
	Content []byte `json:"-"`
}

// UpdateStep records one operation of an update job, as the job reported it.
type UpdateStep struct {
	ID         string `json:"id"`
	Op         string `json:"op"`
	Scratch    bool   `json:"scratch,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
}

// DependencyDiff lists the lockfile entries an update added, changed and
// removed, by their identity in the file, each list cut at maxDiffEntries.
type DependencyDiff struct {
	Added     []string `json:"added,omitempty"`
	Changed   []string `json:"changed,omitempty"`
	Removed   []string `json:"removed,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	// Followed are the entries that are neither updated packages nor below
	// them whose dependencies moved to new versions the update brought in.
	Followed []FollowedEntry `json:"followed,omitempty"`
	// touched are the entries added or changed, not cut; the update stage
	// checks each against the registry.
	touched []string
}

// FollowedEntry is an entry of the dependency file that the update did not
// aim at and that changed only in what its dependencies point to: each of its
// dependencies in Moves went to a version the update added.
type FollowedEntry struct {
	Entry string       `json:"entry"`
	Moves []FollowMove `json:"moves"`
}

// FollowMove is one dependency of a FollowedEntry going from one version to
// another.
type FollowMove struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// maxDiffEntries bounds each list of a DependencyDiff.
const maxDiffEntries = 100

// LanguageUpdate records what the update stage did for one item.
type LanguageUpdate struct {
	Steps []UpdateStep `json:"steps,omitempty"`
	// Notes are facts about the run worth keeping that did not stop it, such
	// as a package manager's warning about the declared packageManager.
	Notes []string        `json:"notes,omitempty"`
	Diff  *DependencyDiff `json:"diff,omitempty"`
	// Runtime and Tool are what the update ran in and with. Records from
	// before they were kept have neither.
	Runtime *RuntimeRecord `json:"runtime,omitempty"`
	Tool    *ToolRecord    `json:"tool,omitempty"`
	// DeprecatedChanged is how many lockfile entries gained, lost or changed a
	// deprecated note, each equal to what the npm registry publishes for that
	// version.
	DeprecatedChanged int `json:"deprecated_changed,omitempty"`
	// DeprecatedNotes names those package versions and what happened to the
	// note of each.
	DeprecatedNotes []DeprecationChange `json:"deprecated_notes,omitempty"`
	// ManifestEdits are the version specifiers of direct dependencies this
	// program changed in the manifest before the update ran, because the
	// specifier did not allow a fixed version. Empty when the manifest was
	// left as it was.
	ManifestEdits []ManifestEdit `json:"manifest_edits,omitempty"`
	// Chain records the re-resolution of the packages that depend on a held
	// back package, when the update tried it.
	Chain *ChainUpdate `json:"chain,omitempty"`
}

// Outcomes of ChainUpdate.
const (
	ChainAdopted  = "adopted"
	ChainNotFixed = "not_fixed"
	ChainRejected = "rejected"
	ChainFailed   = "failed"
	ChainNotTried = "not_tried"
	ChainDeferred = "deferred"
)

// ChainUpdate records an update that moved the packages a held back package
// depends on, the direct dependencies the project declares among them, and
// what became of it.
type ChainUpdate struct {
	Outcome string `json:"outcome"`
	Reason  Reason `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// Source is "chain_job" for an update made for the purpose and
	// "first_run" for the result of the first update, checked again.
	Source    string       `json:"source"`
	Blocked   []ChainBlock `json:"blocked"`
	Tops      []ChainMove  `json:"tops"`
	Moves     []ChainMove  `json:"moves,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
	Usage     ChainUsage   `json:"usage"`
}

// ChainBlock is a requirement that holds a package at a version below the
// fixed one: Parent at ParentVersion asks for Package at Range, and Proof says
// how that was established ("exact" or "upper_bound").
type ChainBlock struct {
	Package       string `json:"package"`
	Version       string `json:"version"`
	Parent        string `json:"parent"`
	ParentVersion string `json:"parent_version"`
	Range         string `json:"range"`
	Proof         string `json:"proof"`
}

// ChainMove is an entry the chain moved: From is empty for an added entry and
// To for a removed one; Kind is top, ancestor, added, removed or followed.
type ChainMove struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	Kind string `json:"kind"`
}

// ChainUsage is what the item spent on the chain, over all of its runs.
type ChainUsage struct {
	Containers int   `json:"containers"`
	Lookups    int   `json:"lookups"`
	Bytes      int64 `json:"bytes"`
	ElapsedMS  int64 `json:"elapsed_ms"`
}

// ChainCount is a count of entries or requirements for a vulnerable version
// before and after an update.
type ChainCount struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	VulnID  string `json:"vuln_id"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
}

// What happened to the deprecation note of a package version.
const (
	DeprecationGained  = "gained"
	DeprecationChanged = "changed"
	DeprecationLost    = "lost"
	// DeprecationPresent: the updated version is deprecated; the version that
	// was there before is another release, so nothing is said about a change.
	DeprecationPresent = "present"
)

// DeprecationChange is a package version whose deprecation note the update
// gained, changed or lost, as the lockfile records it.
type DeprecationChange struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// ManifestEdit is one version specifier changed in a manifest.
type ManifestEdit struct {
	File string `json:"file"` // repository-relative, as in Artifacts
	// Section is where the dependency is declared: "dependencies",
	// "optionalDependencies" and so on for package.json, "project.dependencies"
	// for pyproject.toml.
	Section string `json:"section"`
	Name    string `json:"name"`
	From    string `json:"from"`
	To      string `json:"to"`
	// MajorChange marks an edit whose new specifier no longer allows the
	// major version (for 0.x, the minor version) the old one allowed.
	MajorChange bool `json:"major_change,omitempty"`
}

// SourceVuln is one vulnerability a filesystem scan reported for a package.
type SourceVuln struct {
	Package  string           `json:"package"`
	Version  string           `json:"version"`
	VulnID   string           `json:"vuln_id"`
	Severity scanner.Severity `json:"severity,omitempty"`
	FixedVer string           `json:"fixed_ver,omitempty"`
	KEV      bool             `json:"kev,omitempty"`
}

// HashedFile identifies the content of a dependency file by its hash.
type HashedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SourceCheck is the filesystem check of an update: the dependency files
// before and after, scanned under the same Trivy, databases, severities and
// settings. It is a check of the source files, kept apart from the
// comparison of a running image (VerificationResult), and is identified by
// the commit the files were read from and the hashes of the files scanned.
type SourceCheck struct {
	CommitSHA  string                 `json:"commit_sha"`
	Before     []HashedFile           `json:"before"`
	After      []HashedFile           `json:"after"`
	Conditions scanner.ScanConditions `json:"conditions"`
	// Resolved are the vulnerabilities found before and not after, Remaining
	// those found in both scans (the same package and vulnerability, at
	// whichever version) and Introduced those found only after. The lists
	// cover every package of the files, not only the updated ones.
	// Counts are the number of resolved, remaining and introduced findings;
	// the lists are cut at maxSourceVulns each and Truncated says so.
	Counts     [3]int       `json:"counts"`
	Truncated  bool         `json:"truncated,omitempty"`
	Resolved   []SourceVuln `json:"resolved,omitempty"`
	Remaining  []SourceVuln `json:"remaining,omitempty"`
	Introduced []SourceVuln `json:"introduced,omitempty"`
	// Passed is true when every target was found before, was not found in any
	// occurrence after, and nothing was introduced.
	Passed bool `json:"passed"`
	// Basis names what a chain update's findings were compared by
	// ("package_version_vuln_edges": package, version and vulnerability, and
	// the entries and requirements they appear in). The following lists are
	// that comparison's findings, each cut at maxSourceVulns.
	Basis            string       `json:"basis,omitempty"`
	ChainNewTriples  []SourceVuln `json:"chain_new_findings,omitempty"`
	ChainEntryGrowth []ChainCount `json:"chain_entry_growth,omitempty"`
	ChainEdgeGrowth  []ChainCount `json:"chain_edge_growth,omitempty"`
}
