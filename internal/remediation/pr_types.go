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
	ReasonComposeFileNotFound  Reason = "compose_file_not_found"
	ReasonComposeFileUnusable  Reason = "compose_file_unusable"
	ReasonPRLimit              Reason = "pr_limit"
	ReasonCandidateChanged     Reason = "candidate_changed"
	ReasonBaseMoved            Reason = "base_moved"
	ReasonGitHubRateLimited    Reason = "github_rate_limited"
	ReasonWriteOutcomeUnknown  Reason = "write_outcome_unknown"
	ReasonStoreLocked          Reason = "store_locked"
	ReasonStorageFailed        Reason = "storage_failed"
	ReasonStorageFull          Reason = "storage_full"
	ReasonRecordsUnverified    Reason = "records_unverified"
	ReasonReconcileFailed      Reason = "reconciliation_failed"
	ReasonRepositoryMismatch   Reason = "repository_mismatch"
	ReasonAttemptUnsettled     Reason = "attempt_unsettled"
	ReasonBranchNotOurs        Reason = "branch_not_ours"
	ReasonPullNotAsCreated     Reason = "pull_request_not_as_created"
	ReasonGitHubRefused        Reason = "github_refused"
	ReasonGitHubError          Reason = "github_error"
	ReasonRegistryRecheck      Reason = "candidate_recheck_failed"
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
// Compose file, that a pull request resolves according to its verified
// comparison.
type FixTarget struct {
	Location string       `json:"location"`
	VulnID   string       `json:"vuln_id"`
	Package  PackageCoord `json:"package"`
}

func (f FixTarget) key() string {
	return f.Location + "\x00" + f.VulnID + "\x00" + string(f.Package.Ecosystem) + "\x00" + string(f.Package.Class) + "\x00" + f.Package.Name
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
}

// ItemEvidence is the verification of one running entity of a unit, kept
// with the attempt and the pull request record so the evidence survives the
// plan file being replaced.
type ItemEvidence struct {
	ItemKey       string        `json:"item_key"`
	Current       ImageState    `json:"current"`
	Candidate     ImageState    `json:"candidate"`
	BaselineScan  string        `json:"baseline_scan,omitempty"`
	CandidateScan string        `json:"candidate_scan,omitempty"`
	Locations     []string      `json:"locations"`
	Resolved      []VulnSummary `json:"resolved,omitempty"`
	Remaining     []VulnSummary `json:"remaining,omitempty"`
	Introduced    []VulnSummary `json:"introduced,omitempty"`
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
	UserModified    bool          `json:"user_modified,omitempty"`
	ModifiedReason  string        `json:"modified_reason,omitempty"`
	FixTargets      []FixTarget   `json:"fix_targets,omitempty"`
	Services        []string      `json:"services,omitempty"`
	CurrentRef      string        `json:"current_ref"`
	CandidateTag    string        `json:"candidate_tag"`
	CandidateDigest string        `json:"candidate_digest"`
	Replacing       []Replacement `json:"replacing,omitempty"`
	// Recovered marks a record rebuilt from GitHub; it has no evidence.
	Recovered bool `json:"recovered,omitempty"`
	// MarkerOnly marks a pull request known to be this tool's only by the
	// marker in its description, with no creation record of this store
	// behind it. A marker can be written by anyone with push access, so such
	// a pull request only suppresses its update and counts as open; it is
	// never commented on, closed, or used to replace another.
	MarkerOnly bool                 `json:"marker_only,omitempty"`
	Evidence   *VerificationSummary `json:"evidence,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
}

// AttemptRecord is the recovery data of one attempt to open a pull request:
// enough to find out after a crash what exists on GitHub without relying on
// the operation log.
type AttemptRecord struct {
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
	PendingOp       string               `json:"pending_op,omitempty"`
	Services        []string             `json:"services,omitempty"`
	Locations       []string             `json:"locations"`
	CurrentRef      string               `json:"current_ref"`
	CandidateTag    string               `json:"candidate_tag"`
	CandidateDigest string               `json:"candidate_digest"`
	FixTargets      []FixTarget          `json:"fix_targets,omitempty"`
	Evidence        *VerificationSummary `json:"evidence,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
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

// PRUnit is the outcome of one Compose update unit: the services of one
// Compose file whose running image is the same reference.
type PRUnit struct {
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
