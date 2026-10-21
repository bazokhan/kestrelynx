package remediation

import "time"

// PRUnitStatus is the outcome of one Compose update unit in the pull request
// stage.
type PRUnitStatus string

const (
	// PRStatusCreated: a pull request was opened for the unit in this cycle.
	PRStatusCreated PRUnitStatus = "pr_created"
	// PRStatusOpen: a pull request for the same update is already open; no
	// new one is opened, whatever the base commit.
	PRStatusOpen PRUnitStatus = "pr_open"
	// PRStatusMerged: the pull request of this update was merged. Whether the
	// merge was deployed is not confirmed.
	PRStatusMerged PRUnitStatus = "pr_merged"
	// PRStatusSuppressed: the pull request of this update was closed without
	// merging (by a person or as replaced); the update is never proposed
	// again.
	PRStatusSuppressed PRUnitStatus = "pr_suppressed"
	// PRStatusManual: the unit cannot be edited automatically; Reason says why.
	PRStatusManual PRUnitStatus = "manual"
	// PRStatusDeferred: the work was left for a later cycle (a limit, a rate
	// limit, the deadline, a changed candidate or base).
	PRStatusDeferred PRUnitStatus = "deferred"
	// PRStatusFailed: GitHub refused a write for a reason that is not a limit.
	PRStatusFailed PRUnitStatus = "failed"
	// PRStatusWriteBlocked: writes to the repository are stopped this cycle
	// (records that cannot be verified, a reconciliation failure, a storage
	// problem, a branch or pull request that is not as recorded).
	PRStatusWriteBlocked PRUnitStatus = "write_blocked"
	// PRStatusWriteDisabled: pull requests are not enabled; the unit is shown
	// for information. The stage itself never produces it.
	PRStatusWriteDisabled PRUnitStatus = "write_disabled"
)

// Reasons of the pull request stage.
const (
	ReasonComposeSetNotAdopted Reason = "compose_set_not_adopted"
	// ReasonKubernetesSetNotAdopted: a container of the unit runs an image that
	// is not an adopted candidate, or the images have different candidates; a
	// pull request never covers part of the containers that run the image in
	// the file.
	ReasonKubernetesSetNotAdopted Reason = "kubernetes_set_not_adopted"
	// ReasonInstancesMissing: a mapped container has no running instance, or an
	// instance has no plan item, so the set of what the edit changes cannot be
	// verified. ReasonMixedReferences: the running instances of the mapped
	// containers do not all run, or declare, the same reference (a rollout in
	// progress, for example).
	ReasonInstancesMissing Reason = "instances_missing"
	// ReasonMappingConflict: two mappings of the same file resolve to the same
	// container of the same document, so one edit would change both.
	ReasonMappingConflict Reason = "mapping_conflict"
	ReasonMixedReferences Reason = "mixed_references"
	// ReasonManifestFileNotFound and ReasonManifestFileUnusable: the mapped
	// manifest is absent at the base branch, or cannot be edited as text (not a
	// regular file, a Git LFS pointer, too large).
	ReasonManifestFileNotFound Reason = "manifest_file_not_found"
	ReasonManifestFileUnusable Reason = "manifest_file_unusable"
	// ReasonImageUpdaterFile: the manifest's directory holds the write-back file
	// of Argo CD Image Updater, so another tool owns the tags there.
	ReasonImageUpdaterFile    Reason = "image_updater_file"
	ReasonComposeFileNotFound Reason = "compose_file_not_found"
	ReasonComposeFileUnusable Reason = "compose_file_unusable"
	ReasonPRLimit             Reason = "pr_limit"
	ReasonCandidateChanged    Reason = "candidate_changed"
	ReasonBaseMoved           Reason = "base_moved"
	ReasonGitHubRateLimited   Reason = "github_rate_limited"
	ReasonWriteOutcomeUnknown Reason = "write_outcome_unknown"
	ReasonStoreLocked         Reason = "store_locked"
	ReasonStorageFailed       Reason = "storage_failed"
	ReasonStorageFull         Reason = "storage_full"
	ReasonRecordsUnverified   Reason = "records_unverified"
	ReasonReconcileFailed     Reason = "reconciliation_failed"
	ReasonRepositoryMismatch  Reason = "repository_mismatch"
	ReasonAttemptUnsettled    Reason = "attempt_unsettled"
	ReasonBranchNotOurs       Reason = "branch_not_ours"
	ReasonPullNotAsCreated    Reason = "pull_request_not_as_created"
	ReasonGitHubRefused       Reason = "github_refused"
	ReasonGitHubError         Reason = "github_error"
	ReasonRegistryRecheck     Reason = "candidate_recheck_failed"
	// ReasonSourceChanged: the base branch moved and a file the plan was made
	// from is no longer the same.
	ReasonSourceChanged Reason = "source_changed"
	// ReasonArtifactContentMissing: a language update's files are not held in
	// memory (the item was read back from a stored plan), so nothing can be
	// written from it. The next cycle updates again.
	ReasonArtifactContentMissing Reason = "artifact_content_missing"
	// ReasonArtifactsUnusable: the files of a language update are not what the
	// stage can write: no lockfile among the plan's files, a file the plan did
	// not read, a size or hash that differs from the record, or no change.
	ReasonArtifactsUnusable Reason = "artifacts_unusable"
	// ReasonOpenPRNotInherited: an open pull request of this tool for the same
	// lockfile fixes something this update does not, so a second pull request
	// for the file would only conflict with it.
	ReasonOpenPRNotInherited Reason = "open_pr_not_inherited"
	// ReasonLanguageSetTooLarge: the set of fixed packages is too large for
	// the marker of a pull request description.
	ReasonLanguageSetTooLarge Reason = "language_set_too_large"
	// ReasonWorkImageNotConfigured and ReasonWorkImageUnavailable: language
	// package updates cannot run because no work image is configured or the
	// configured one could not be made ready; nothing is run in this process
	// instead.
	// ReasonUpdateAlreadyProposed: the item's inputs are those a pull request of
	// this tool was made from, so the update was not run again; the pull
	// request stands for it. ReasonProposalNotFound: that pull request is no
	// longer in the records, and the next cycle updates again.
	ReasonUpdateAlreadyProposed  Reason = "update_already_proposed"
	ReasonProposalNotFound       Reason = "proposal_not_found"
	ReasonWorkImageNotConfigured Reason = "work_image_not_configured"
	ReasonWorkImageUnavailable   Reason = "work_image_unavailable"
	// ReasonWorkNamespaceNotConfigured: language package updates on Kubernetes
	// run in work Pods of a dedicated namespace, and none is available.
	ReasonWorkNamespaceNotConfigured Reason = "work_namespace_not_configured"
)

// PRState is the state of a pull request record.
type PRState string

const (
	PRStateOpen   PRState = "open"
	PRStateClosed PRState = "closed" // closed without merging
	PRStateMerged PRState = "merged"
	// PRStateReplaced: closed by this tool in favour of a newer pull request
	// for the same file and services.
	PRStateReplaced PRState = "replaced"
)

// AttemptStatus is how far the creation of one pull request got.
type AttemptStatus string

const (
	AttemptIntent        AttemptStatus = "intent"
	AttemptBlobCreated   AttemptStatus = "blob_created"
	AttemptTreeCreated   AttemptStatus = "tree_created"
	AttemptCommitCreated AttemptStatus = "commit_created"
	AttemptRefCreated    AttemptStatus = "ref_created"
	AttemptPRRequested   AttemptStatus = "pr_requested"
	// AttemptPRCreated: the pull request exists and is recorded. Settled.
	AttemptPRCreated AttemptStatus = "pr_created"
	// AttemptAbandoned: nothing but unreferenced git objects (harmless) was
	// left; the attempt may start again from the beginning. Settled.
	AttemptAbandoned AttemptStatus = "abandoned"
	// AttemptAbandonedWithoutPR: the branch exists at the recorded commit but
	// the base moved, so no pull request will be opened from it. The branch
	// is kept. Settled.
	AttemptAbandonedWithoutPR AttemptStatus = "abandoned_without_pr"
	// AttemptBlocked: the branch or the pull requests found for it are not as
	// recorded, so the attempt cannot be settled; no new attempt for the same
	// target starts while it lasts. It is examined again every cycle.
	AttemptBlocked AttemptStatus = "blocked"
)

// settled reports whether nothing about the attempt remains to be found out.
func (s AttemptStatus) settled() bool {
	return s == AttemptPRCreated || s == AttemptAbandoned || s == AttemptAbandonedWithoutPR
}

// FixTarget is one vulnerability in one package, at one location of the
// edited file, that a pull request resolves according to its verified
// comparison.
type FixTarget struct {
	Location string       `json:"location"`
	VulnID   string       `json:"vuln_id"`
	Package  PackageCoord `json:"package"`
	// Layers are the filesystem layers of the running image the finding was
	// found in (Dockerfile updates only) and are part of the target's
	// identity. A marker too large to hold them carries LayersDigest, the
	// digest of the sorted layer set, instead.
	Layers       []string `json:"layers,omitempty"`
	LayersDigest string   `json:"layers_digest,omitempty"`
	// Entities are the running images (Dockerfile updates only) for which the
	// comparison resolves the target; the target is claimed for each of them
	// and for no other.
	Entities []string `json:"entities,omitempty"`
}

// layerSetKey identifies the layer set of a Dockerfile target, "" for none.
func (f FixTarget) layerSetKey() string {
	if len(f.Layers) > 0 {
		return layerSetDigest(f.Layers)
	}
	return f.LayersDigest
}

// layerSetDigest is the digest of a set of layer IDs, independent of order.
func layerSetDigest(layers []string) string {
	return hashCanonical(sortedCopy(layers))
}

func (f FixTarget) key() string {
	k := f.Location + "\x00" + f.VulnID + "\x00" + string(f.Package.Ecosystem) + "\x00" + string(f.Package.Class) + "\x00" + f.Package.Name
	if l := f.layerSetKey(); l != "" {
		k += "\x00" + l
	}
	return k
}

// ReplacementState is the progress of replacing one older pull request.
type ReplacementState string

const (
	// ReplacementPending: decided, nothing sent yet.
	ReplacementPending ReplacementState = "pending"
	// ReplacementCommented: the supersede comment is on the old pull request.
	ReplacementCommented ReplacementState = "commented"
	// ReplacementClosed: the close was sent and its outcome is not known yet;
	// the next cycle reads the old pull request to settle it.
	ReplacementClosed ReplacementState = "closed"
	// ReplacementDone: the old pull request is recorded as replaced.
	ReplacementDone ReplacementState = "done"
	// ReplacementAbandoned: a condition failed; the old pull request was left
	// as it is.
	ReplacementAbandoned ReplacementState = "abandoned"
)

// Replacement is one older pull request a new one replaces.
type Replacement struct {
	OldNumber int              `json:"old_number"`
	State     ReplacementState `json:"state"`
	Detail    string           `json:"detail,omitempty"`
	// PendingOp is the operation whose outcome is unknown, if any.
	PendingOp string `json:"pending_op,omitempty"`
}

func (r Replacement) terminal() bool {
	return r.State == ReplacementDone || r.State == ReplacementAbandoned
}

// VulnSummary is one vulnerability of a verification summary.
type VulnSummary struct {
	VulnID   string       `json:"vuln_id"`
	Package  PackageCoord `json:"package"`
	Severity string       `json:"severity,omitempty"`
	Priority Priority     `json:"priority,omitempty"`
	KEV      bool         `json:"kev,omitempty"`
	// Layers are the layers of the running image the finding was found in
	// (Dockerfile updates only).
	Layers []string `json:"layers,omitempty"`
}

// ItemEvidence is the verification of one running entity of a unit, kept
// with the attempt and the pull request record so the evidence survives the
// plan file being replaced.
type ItemEvidence struct {
	ItemKey string     `json:"item_key"`
	Current ImageState `json:"current"`
	// CurrentBase and Layers are set by Dockerfile updates: Current is then
	// the running image, CurrentBase the base image the FROM names today and
	// Candidate the candidate base; Layers is how the running image's layers
	// were matched against CurrentBase's.
	CurrentBase   *ImageState        `json:"current_base,omitempty"`
	Layers        *LayerConfirmation `json:"layers,omitempty"`
	Candidate     ImageState         `json:"candidate"`
	BaselineScan  string             `json:"baseline_scan,omitempty"`
	CandidateScan string             `json:"candidate_scan,omitempty"`
	Locations     []string           `json:"locations"`
	// Resolved and Remaining are the outcomes of the update's targets.
	Resolved  []VulnSummary `json:"resolved,omitempty"`
	Remaining []VulnSummary `json:"remaining,omitempty"`
	// OtherResolved (image tag updates only) are compared findings the
	// running image has no target for that the candidate no longer reports.
	OtherResolved []VulnSummary `json:"other_resolved,omitempty"`
	// OtherRemaining are compared findings the running image has no target
	// for that remain in the candidate (for Dockerfile updates, the candidate
	// base): what stays whatever the update resolves.
	OtherRemaining []VulnSummary `json:"other_remaining,omitempty"`
	Introduced     []VulnSummary `json:"introduced,omitempty"`
}

// VerificationSummary is the compact evidence of a unit's comparison.
type VerificationSummary struct {
	TrivyVersion    string         `json:"trivy_version,omitempty"`
	VulnDBUpdatedAt *time.Time     `json:"vuln_db_updated_at,omitempty"`
	Severities      []string       `json:"severities,omitempty"`
	Scope           string         `json:"scope,omitempty"`
	PlanGeneratedAt time.Time      `json:"plan_generated_at"`
	Items           []ItemEvidence `json:"items"`
}

// PRRecord is one pull request this tool opened (or recovered from GitHub).
type PRRecord struct {
	Repo       string `json:"repo"`
	RepoID     int64  `json:"repo_id"`
	Kind       string `json:"kind"`
	TargetKey  string `json:"target_key"`
	UpdateKey  string `json:"update_key"`
	AttemptKey string `json:"attempt_key"`
	Branch     string `json:"branch"`
	Number     int    `json:"number"`
	URL        string `json:"url"`
	BaseBranch string `json:"base_branch"`
	BaseSHA    string `json:"base_sha"`
	// HeadSHA is the commit this tool created; a pull request whose head
	// differs from it was changed by someone else.
	HeadSHA   string   `json:"head_sha"`
	Path      string   `json:"path"`
	Locations []string `json:"locations"`
	State     PRState  `json:"state"`
	// ReplacedBy is the pull request that replaced this one (state replaced).
	ReplacedBy int `json:"replaced_by,omitempty"`
	// SupersededBy names a newer pull request whose supersede comment is on
	// this one when it is not certain this tool closed it.
	SupersededBy int `json:"superseded_by,omitempty"`
	// UserModified marks a pull request whose head, base or head repository
	// is not what this tool created. It still suppresses its update but is
	// never resumed from, replaced or used to replace another.
	UserModified    bool        `json:"user_modified,omitempty"`
	ModifiedReason  string      `json:"modified_reason,omitempty"`
	FixTargets      []FixTarget `json:"fix_targets,omitempty"`
	Services        []string    `json:"services,omitempty"`
	CurrentRef      string      `json:"current_ref"`
	CandidateTag    string      `json:"candidate_tag"`
	CandidateDigest string      `json:"candidate_digest"`
	// Affected are the workload keys a Kubernetes update changes; the other
	// kinds have none.
	Affected  []string      `json:"affected,omitempty"`
	Replacing []Replacement `json:"replacing,omitempty"`
	// Recovered marks a record rebuilt from GitHub; it has no evidence.
	Recovered bool `json:"recovered,omitempty"`
	// MarkerOnly marks a pull request known to be this tool's only by the
	// marker in its description, with no creation record of this store
	// behind it. A marker can be written by anyone with push access, so such
	// a pull request only suppresses its update and counts as open; it is
	// never commented on, closed, or used to replace another.
	MarkerOnly bool                 `json:"marker_only,omitempty"`
	Evidence   *VerificationSummary `json:"evidence,omitempty"`
	// InputVerified marks a record rebuilt from a marker whose update this
	// program has since run itself and found to have the same update key,
	// target key, repository ID and manager; the input fingerprint it holds is
	// then its own, not the marker's. MarkerOnly keeps its meaning.
	InputVerified bool `json:"input_verified,omitempty"`
	// Lang identifies a language update; the other kinds have none.
	Lang *LangRecord `json:"lang,omitempty"`
	// Language is what the pull request changes, for display; a record
	// rebuilt from a marker has none.
	Language  *PRLanguage `json:"language,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// AttemptRecord is the recovery data of one attempt to open a pull request:
// enough to find out after a crash what exists on GitHub without relying on
// the operation log.
type AttemptRecord struct {
	// Kind is the kind of update; empty for a Compose tag update.
	Kind       string `json:"kind,omitempty"`
	AttemptKey string `json:"attempt_key"`
	UpdateKey  string `json:"update_key"`
	TargetKey  string `json:"target_key"`
	Repo       string `json:"repo"`
	RepoID     int64  `json:"repo_id"`
	Branch     string `json:"branch"`
	BaseBranch string `json:"base_branch"`
	BaseSHA    string `json:"base_sha"`
	Path       string `json:"path"`
	Mode       string `json:"mode"`
	// InputSHA is the blob of the file before the edit, NewBlobSHA after.
	InputSHA   string        `json:"input_sha"`
	NewBlobSHA string        `json:"new_blob_sha"`
	TreeSHA    string        `json:"tree_sha,omitempty"`
	CommitSHA  string        `json:"commit_sha,omitempty"`
	Status     AttemptStatus `json:"status"`
	Detail     string        `json:"detail,omitempty"`
	PRNumber   int           `json:"pr_number,omitempty"`
	// PendingOp is the write whose outcome is unknown, settled by reading.
	PendingOp       string   `json:"pending_op,omitempty"`
	Services        []string `json:"services,omitempty"`
	Locations       []string `json:"locations"`
	CurrentRef      string   `json:"current_ref"`
	CandidateTag    string   `json:"candidate_tag"`
	CandidateDigest string   `json:"candidate_digest"`
	// Affected are the workload keys a Kubernetes update changes.
	Affected   []string             `json:"affected,omitempty"`
	FixTargets []FixTarget          `json:"fix_targets,omitempty"`
	Evidence   *VerificationSummary `json:"evidence,omitempty"`
	// Changes are the files of the commit when it holds more than the one
	// file Path, Mode and NewBlobSHA describe (a language update); Lang is
	// what identifies a language update.
	Changes   []FileChange `json:"changes,omitempty"`
	Lang      *LangRecord  `json:"lang,omitempty"`
	Language  *PRLanguage  `json:"language,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// fileChanges are the files the attempt's commit changes.
func (a *AttemptRecord) fileChanges() []FileChange {
	if len(a.Changes) > 0 {
		return a.Changes
	}
	return []FileChange{{Path: a.Path, Mode: a.Mode, BlobSHA: a.NewBlobSHA}}
}

// OperationPhase says which part of an operation an event records.
type OperationPhase string

const (
	PhaseIntent OperationPhase = "intent"
	PhaseResult OperationPhase = "result"
	// PhaseSettled: a later cycle found out the outcome of an operation whose
	// result was unknown. Its result stays unknown only for a blob, tree or
	// commit of an attempt that starts again, whose objects are never used.
	PhaseSettled OperationPhase = "settled"
)

// OperationKind is the external write an operation makes.
type OperationKind string

const (
	OpCreateBlob    OperationKind = "create_blob"
	OpCreateTree    OperationKind = "create_tree"
	OpCreateCommit  OperationKind = "create_commit"
	OpCreateRef     OperationKind = "create_ref"
	OpCreatePull    OperationKind = "create_pull"
	OpCreateComment OperationKind = "create_comment"
	OpClosePull     OperationKind = "close_pull"
)

// OperationResult is the outcome of an operation.
type OperationResult string

const (
	ResultOK      OperationResult = "ok"
	ResultFailed  OperationResult = "failed"
	ResultUnknown OperationResult = "unknown"
)

// OperationEvent is one entry of the append-only operation log. The intent,
// the result and any later settlement of one operation are separate events
// sharing ID, each with its own sequence number, so an outcome found out
// after the unknown result was delivered is delivered again.
type OperationEvent struct {
	Seq        int64           `json:"seq"`
	ID         string          `json:"id"`
	At         time.Time       `json:"at"`
	Phase      OperationPhase  `json:"phase"`
	Kind       OperationKind   `json:"kind"`
	Repo       string          `json:"repo"`
	AttemptKey string          `json:"attempt_key,omitempty"`
	Number     int             `json:"number,omitempty"`
	Intent     string          `json:"intent,omitempty"`
	Result     OperationResult `json:"result,omitempty"`
	// Ref is what the write returned: an object SHA, a branch, a pull request
	// number.
	Ref   string `json:"ref,omitempty"`
	Error string `json:"error,omitempty"`
}

// PRProblemCode is a condition of the pull request stage that persists until
// it is resolved, reported every cycle while it lasts.
type PRProblemCode string

const (
	PRProblemWriteBlocked      PRProblemCode = "write_blocked"
	PRProblemStorageFailed     PRProblemCode = "storage_failed"
	PRProblemStorageFull       PRProblemCode = "storage_full"
	PRProblemRecordsUnverified PRProblemCode = "records_unverified"
)

// PRStageProblem is one problem; Repo is empty when it concerns every
// repository.
type PRStageProblem struct {
	Code PRProblemCode `json:"code"`
	Repo string        `json:"repo,omitempty"`
	// Target names the Compose file and image locations a problem is
	// limited to, empty when it concerns the whole repository.
	Target string `json:"target,omitempty"`
	Reason Reason `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// PRUnit is the outcome of one update unit: the services of one Compose file
// whose running image is the same reference, the workloads built from one
// FROM of a Dockerfile, or the packages updated in one lockfile.
type PRUnit struct {
	// Kind is "dockerfile" for a base image update, "language" for a
	// lockfile update, "kubernetes" for a manifest tag update and empty for a
	// Compose tag update. For a Kubernetes update Services, Locations and
	// Workloads are all the workload keys of the edited containers. For a Dockerfile,
	// Path is the Dockerfile, Locations hold the
	// edited FROM's position, Services the services of Workloads and Current
	// the base image the FROM names.
	Kind string `json:"kind,omitempty"`
	// Key identifies the unit by repository, branch, file and running
	// reference; it does not depend on GitHub.
	Key        string `json:"key"`
	TargetKey  string `json:"target_key,omitempty"`
	UpdateKey  string `json:"update_key,omitempty"`
	AttemptKey string `json:"attempt_key,omitempty"`
	Repo       string `json:"repo"`
	BaseBranch string `json:"base_branch"`
	Path       string `json:"path"`
	// Services are the Compose services edited, Locations their image keys.
	Services  []string `json:"services"`
	Locations []string `json:"locations"`
	// Workloads are the running workloads of the services.
	Workloads []string `json:"workloads"`
	// AlsoRunning are other services running the same image that no Compose
	// mapping covers; they are not edited.
	AlsoRunning     []ServiceRef `json:"also_running,omitempty"`
	Current         string       `json:"current"`
	CandidateTag    string       `json:"candidate_tag,omitempty"`
	CandidateDigest string       `json:"candidate_digest,omitempty"`

	Status PRUnitStatus `json:"status"`
	Reason Reason       `json:"reason,omitempty"`
	Detail string       `json:"detail,omitempty"`

	Number       int           `json:"number,omitempty"`
	URL          string        `json:"url,omitempty"`
	State        PRState       `json:"state,omitempty"`
	UserModified bool          `json:"user_modified,omitempty"`
	FixTargets   []FixTarget   `json:"fix_targets,omitempty"`
	ReplacedBy   int           `json:"replaced_by,omitempty"`
	Replacing    []Replacement `json:"replacing,omitempty"`
	// Replaced are the pull requests closed in favour of this one.
	Replaced []int `json:"replaced,omitempty"`

	// ItemKey and Language are set by a language update ("language"): ItemKey
	// is the plan's language item, Path the lockfile, Locations the dependency
	// directory and Services the services of Workloads.
	ItemKey  string      `json:"item_key,omitempty"`
	Language *PRLanguage `json:"language,omitempty"`
}

// PRLanguage describes what a language update changes, for display.
type PRLanguage struct {
	Manager       string              `json:"manager"`
	Root          string              `json:"root"`
	Packages      []PRLanguagePackage `json:"packages"`
	ManifestEdits []LangEdit          `json:"manifest_edits,omitempty"`
	// Chain are the direct dependencies a chain update moved along with the
	// packages.
	Chain []LangChainMove `json:"chain,omitempty"`
	// Remaining are the packages the update was planned for and left out, with
	// why. The pull request does not change them.
	Remaining []PRLanguageRemaining `json:"remaining,omitempty"`
}

// PRLanguageRemaining is one package a language update leaves out.
type PRLanguageRemaining struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Relation  string `json:"relation,omitempty"`
	// From is the version the image runs and Target the version the update was
	// meant to take the package to.
	From   string `json:"from"`
	Target string `json:"target"`
	Reason Reason `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// PRLanguagePackage is one package a language update moves.
type PRLanguagePackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Relation  string `json:"relation,omitempty"`
	From      string `json:"from"`
	To        string `json:"to"`
	// Major marks a move to another major version (for 0.x, another minor).
	Major bool `json:"major,omitempty"`
	// Through names the direct dependencies a chain update moved to bring the
	// package to its version.
	Through []string `json:"through,omitempty"`
}

// PRStageResult is what one run of the pull request stage reports.
type PRStageResult struct {
	Units []PRUnit `json:"units"`
	// Operations are the operation events not yet delivered in a
	// notification, oldest first; LastSeq is the highest sequence among them
	// (0 when there are none), to pass to MarkPROperationsDelivered after a
	// successful notification.
	Operations []OperationEvent `json:"operations,omitempty"`
	LastSeq    int64            `json:"last_seq,omitempty"`
	Problems   []PRStageProblem `json:"problems,omitempty"`
}

// Attach copies the stage result into the plan.
func (r PRStageResult) Attach(p *Plan) {
	p.PullRequests = r.Units
	p.PROperations = r.Operations
	p.PRProblems = r.Problems
}
