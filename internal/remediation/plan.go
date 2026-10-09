package remediation

import (
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// PlanVersion is the format version of a stored Plan.
const PlanVersion = 1

// Category is the plan classification of one image.
type Category string

const (
	// CategoryPRCandidate: a pinned tag has a newer patch that the comparison
	// supports. The plan proposes it; no pull request is created by planning.
	CategoryPRCandidate Category = "pr_candidate"
	// CategoryPullAgain: a floating tag now points at content the comparison
	// supports; pulling the image again would take it.
	CategoryPullAgain Category = "pull_again"
	// CategoryManual: a candidate was compared but is not proposed (a partial
	// improvement, or new findings); a person decides.
	CategoryManual Category = "manual"
	// CategoryNotComparable: the candidate or the baseline could not be
	// compared under equal conditions.
	CategoryNotComparable Category = "not_comparable"
	// CategoryDeferred: work was left undone for a limit, a rate limit or the
	// cycle deadline; it says nothing about the image.
	CategoryDeferred Category = "deferred"
	// CategoryNoCandidate: no newer or different content exists, or the
	// candidate does not resolve the targets.
	CategoryNoCandidate Category = "no_candidate"
	// CategoryExcluded: the reference is not one a candidate is looked up for.
	CategoryExcluded Category = "excluded"
	// CategoryFailed: processing failed for a reason that is not a limit.
	CategoryFailed Category = "failed"
)

// Reasons for plan outcomes other than a failed comparison (see compare.go).
const (
	ReasonNoNewerTag          Reason = "no_newer_tag"
	ReasonSameContent         Reason = "same_content"
	ReasonCandidateNotFixing  Reason = "candidate_does_not_resolve_targets"
	ReasonAuthRequired        Reason = "auth_required"
	ReasonPlatformNotFound    Reason = "platform_not_found"
	ReasonPlatformAmbiguous   Reason = "platform_ambiguous"
	ReasonPlatformMismatch    Reason = "platform_mismatch"
	ReasonRegistryError       Reason = "registry_error"
	ReasonTargetsNotDetected  Reason = "targets_not_detected_on_baseline"
	ReasonAnalysisIncomplete  Reason = "analysis_incomplete"
	ReasonTagListIncomplete   Reason = "tag_listing_incomplete"
	ReasonCandidateScanLimit  Reason = "candidate_scan_limit"
	ReasonBaselineRescanLimit Reason = "baseline_rescan_limit"
	ReasonTagPageLimit        Reason = "tag_page_limit"
	ReasonRegistryBudget      Reason = "registry_budget_exhausted"
	ReasonRateLimited         Reason = "rate_limited"
	ReasonCycleDeadline       Reason = "cycle_deadline"
	ReasonPartialImprovement  Reason = "partial_improvement"
	ReasonIntroducedFindings  Reason = "introduced_findings"
	ReasonIntroducedKEV       Reason = "introduced_kev"
	ReasonAdopted             Reason = "adopted"
)

// ServiceRef names a service running an image, as the caller identifies it.
type ServiceRef struct {
	Project   string `json:"project,omitempty"`
	Service   string `json:"service,omitempty"`
	Container string `json:"container,omitempty"`
}

// Limits caps the work of one planning pass. A value of zero allows none of
// that work, so every limit is set explicitly. The registry request budget
// is the registry.Budget the client was built with.
type Limits struct {
	MaxCandidateScans  int `json:"max_candidate_scans"`
	MaxBaselineRescans int `json:"max_baseline_rescans"`
	// MaxTagPages caps the tag listing pages requested for one repository.
	// Each repository's listing gets up to this many pages, independently of
	// the others; a listing the cap stops is incomplete and its item is
	// deferred.
	MaxTagPages int `json:"max_tag_pages"`
}

// Usage records what a planning pass spent.
type Usage struct {
	CandidateScans   int `json:"candidate_scans"`
	BaselineRescans  int `json:"baseline_rescans"`
	TagPages         int `json:"tag_pages"`
	RegistryRequests int `json:"registry_requests"`
}

// ImageState is the content of an image as the plan knows it.
type ImageState struct {
	Ref            string `json:"ref"`
	Tag            string `json:"tag,omitempty"`
	Entity         string `json:"entity,omitempty"`          // the verified entity key
	ConfigDigest   string `json:"config_digest,omitempty"`   // image config digest when known
	ManifestDigest string `json:"manifest_digest,omitempty"` // platform manifest, candidates only
	TopDigest      string `json:"top_digest,omitempty"`      // what the tag pointed at, candidates only
	Platform       string `json:"platform,omitempty"`
	// DigestKindUnverified is set on a running image whose digest came from
	// the container runtime and is typed as a config digest: the runtime may
	// have reported an index or manifest digest instead, so the kind (and
	// ConfigDigest, which repeats the value) is not confirmed.
	DigestKindUnverified bool `json:"digest_kind_unverified,omitempty"`
}

// ScanRole says what a recorded scan was used as.
type ScanRole string

const (
	RoleBaseline  ScanRole = "baseline"
	RoleCandidate ScanRole = "candidate"
)

// DBCheck is the result of checking the vulnerability databases after a scan.
type DBCheck string

const (
	// DBVerified: the databases were re-read after the scan and are the
	// prepared ones.
	DBVerified DBCheck = "verified"
	// DBChanged: the databases differ from the prepared ones.
	DBChanged DBCheck = "changed"
	// DBCheckFailed: the check itself could not be made.
	DBCheckFailed DBCheck = "check_failed"
	// DBSupplied: the scan was not run by the planner; its conditions are
	// what the caller stated.
	DBSupplied DBCheck = "supplied_by_caller"
	// DBNotChecked: the scan failed, so no check was made.
	DBNotChecked DBCheck = "not_checked"
)

// ScanExecution records one scan a comparison used.
type ScanExecution struct {
	ID     string             `json:"id"`
	Role   ScanRole           `json:"role"`
	Source scanner.ScanSource `json:"source,omitempty"`
	Ref    string             `json:"ref"`
	// Requested is the entity the scan was asked to confirm, Confirmed the
	// one it confirmed. Either is Unconfirmed when no identity was
	// established.
	Requested string     `json:"requested"`
	Confirmed string     `json:"confirmed"`
	ScannedAt *time.Time `json:"scanned_at,omitempty"` // nil for a scan the planner did not run
	DB        DBCheck    `json:"db"`
	DBCheckAt *time.Time `json:"db_checked_at,omitempty"`
	DBError   string     `json:"db_error,omitempty"`
	Failure   string     `json:"failure,omitempty"`
}

// Item is the plan entry of one running image.
type Item struct {
	Key      string       `json:"key"`
	Services []ServiceRef `json:"services,omitempty"`
	Kind     TagKind      `json:"kind"`
	Priority Priority     `json:"priority,omitempty"` // strongest priority among the targets

	Category Category `json:"category"`
	Reason   Reason   `json:"reason,omitempty"`
	Detail   string   `json:"detail,omitempty"`

	Current   ImageState  `json:"current"`
	Candidate *ImageState `json:"candidate,omitempty"`

	// BaselineScan and CandidateScan are IDs into Plan.Scans.
	BaselineScan  string `json:"baseline_scan,omitempty"`
	CandidateScan string `json:"candidate_scan,omitempty"`

	Targets    []Target            `json:"targets,omitempty"`
	Comparison *VerificationResult `json:"comparison,omitempty"`
	Decision   *Decision           `json:"decision,omitempty"`
}

// Plan is the outcome of one planning pass; Items follow the order the
// planner handled them in. It is read-only: nothing in it
// has been applied anywhere.
type Plan struct {
	Version     int                    `json:"version"`
	GeneratedAt time.Time              `json:"generated_at"`
	Conditions  scanner.ScanConditions `json:"conditions"` // the cycle's prepared scan conditions
	Limits      Limits                 `json:"limits"`
	Usage       Usage                  `json:"usage"`
	Items       []Item                 `json:"items"`
	// Scans are the scans the comparisons used, shared between items that
	// compared against the same scan.
	Scans []ScanExecution `json:"scans,omitempty"`
	// LanguageItems are the dependency units of the language-package part,
	// one per repository directory, in the order they were handled.
	LanguageItems []LanguageItem `json:"language_items,omitempty"`
}

// Count returns how many items are in category c.
func (p Plan) Count(c Category) int {
	n := 0
	for _, it := range p.Items {
		if it.Category == c {
			n++
		}
	}
	return n
}
