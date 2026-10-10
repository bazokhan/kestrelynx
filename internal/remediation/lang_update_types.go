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
	ReasonManifestEditRequired      Reason = "manifest_edit_required"
	ReasonRequiresPythonUnsupported Reason = "requires_python_unsupported"
	ReasonLockfileInconsistent      Reason = "lockfile_inconsistent"
	ReasonNoWheelForVersion         Reason = "no_wheel_for_version"
	ReasonReleaseYanked             Reason = "release_yanked"
	ReasonPipTargetUndecidable      Reason = "pip_target_undecidable"
	ReasonPipTargetMismatch         Reason = "pip_target_mismatch"
	ReasonRequirementsRewrite       Reason = "requirements_rewrite_unsupported"
	ReasonUpdateSetNotApplied       Reason = "update_set_not_applied"

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

	// Manual or not comparable: the filesystem check of the dependency files.
	ReasonSourceTargetNotDetectedBefore Reason = "source_target_not_detected_before"
	ReasonSourceTargetNotAnalysedAfter  Reason = "source_target_not_analysed_after"
	ReasonSourceTargetStillDetected     Reason = "source_target_still_detected"
	ReasonSourceIntroduced              Reason = "source_introduced_findings"
	ReasonSourceIntroducedKEV           Reason = "source_introduced_kev"
	ReasonSourceScanIncomplete          Reason = "source_scan_incomplete"
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
	// touched are the entries added or changed, not cut; the update stage
	// checks each against the registry.
	touched []string
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
}
