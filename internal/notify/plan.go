package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// PlanUnavailable says why no fix plan was produced in a cycle that has the
// plan enabled. It is a fixed code, never error text.
type PlanUnavailable string

const (
	// PlanAvailable is the zero value: a plan was produced.
	PlanAvailable PlanUnavailable = ""
	// PlanDatabasesNotPrepared: the scan databases could not be prepared, so
	// no comparison under equal conditions was possible.
	PlanDatabasesNotPrepared PlanUnavailable = "databases_not_prepared"
	// PlanNotBuilt: the planner could not be set up.
	PlanNotBuilt PlanUnavailable = "planner_not_built"
)

// PlanInfo is the fix plan of a Message. Plan is nil exactly when
// Unavailable is set. NotSaved marks a plan that was built but could not be
// written to its file.
type PlanInfo struct {
	Plan        *remediation.Plan
	Unavailable PlanUnavailable
	NotSaved    bool
	// Changed says the plan differs from the last one delivered to the
	// generic webhook.
	Changed bool
	// SlackChanged says what the Slack fix plan message shows differs from the
	// last one delivered (see SlackFingerprint). The message is sent when it
	// is set, and on the weekly day (Weekly) whatever it says.
	SlackChanged bool
	Weekly       bool
}

// maxWebhookVerdicts caps each per-vulnerability verdict list of one item in
// the webhook payload; a list past the cap is marked truncated.
const maxWebhookVerdicts = 50

// planSlackOrder is the order the Slack counts line names the categories in.
var planSlackOrder = []remediation.Category{
	remediation.CategoryPullAgain,
	remediation.CategoryPRCandidate,
	remediation.CategoryManual,
	remediation.CategoryNotComparable,
	remediation.CategoryDeferred,
	remediation.CategoryNoCandidate,
	remediation.CategoryExcluded,
	remediation.CategoryFailed,
}

// planLanguageOrder is the order of the language summary of the webhook.
var planLanguageOrder = []remediation.Category{
	remediation.CategoryPRCandidate,
	remediation.CategoryDependencyUpdateCandidate,
	remediation.CategoryRebuildExpected,
	remediation.CategoryManual,
	remediation.CategoryNotComparable,
	remediation.CategoryDeferred,
	remediation.CategoryFailed,
}

// kevTargets counts the targets of an item that are KEV-listed.
func kevTargets(it remediation.Item) int {
	n := 0
	for _, t := range it.Targets {
		if t.KEV {
			n++
		}
	}
	return n
}

// splitImageRef splits a reference into the image and its tag for display;
// a digest suffix is dropped and a reference without a tag is returned whole.
func splitImageRef(ref string) (image, tag string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

// pullRequestProblemLine is the single line that names the conditions that
// stop pull request writes, or "" without any.
func pullRequestProblemLine(plan remediation.Plan, msg messages) string {
	var reasons []string
	seen := map[remediation.PRProblemCode]bool{}
	for _, c := range []struct {
		code remediation.PRProblemCode
		text string
	}{
		{remediation.PRProblemStorageFailed, msg.PlanPRProblemStorage},
		{remediation.PRProblemStorageFull, msg.PlanPRProblemFull},
		{remediation.PRProblemRecordsUnverified, msg.PlanPRProblemUnverified},
		{remediation.PRProblemWriteBlocked, msg.PlanPRProblemBlocked},
	} {
		for _, pp := range plan.PRProblems {
			if pp.Code == c.code && !seen[c.code] {
				seen[c.code] = true
				reasons = append(reasons, c.text)
			}
		}
	}
	if len(reasons) == 0 {
		return ""
	}
	return fmt.Sprintf(msg.PlanPRProblemLine, strings.Join(reasons, msg.PlanPRProblemJoin))
}

// workloadService is the service part of a compose/<project>/<service> key.
func workloadService(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

// resolvedKEVTargets counts the KEV-listed targets the candidate resolves.
// An item without a recorded comparison counts every KEV-listed target.
func resolvedKEVTargets(it remediation.Item) int {
	if it.Comparison == nil {
		return kevTargets(it)
	}
	resolved := map[string]bool{}
	for _, v := range it.Comparison.Verdicts {
		if v.Outcome == remediation.OutcomeResolved {
			resolved[v.VulnID+"|"+v.Package.Name+"|"+string(v.Package.Ecosystem)+"|"+string(v.Package.Class)] = true
		}
	}
	n := 0
	for _, t := range it.Targets {
		if t.KEV && resolved[t.VulnID+"|"+t.Package.Name+"|"+string(t.Package.Ecosystem)+"|"+string(t.Package.Class)] {
			n++
		}
	}
	return n
}

// partialOf reports whether the item's candidate resolves only some of the
// targeted findings, and how many were targeted.
func partialOf(it remediation.Item) (targeted int, partial bool) {
	if it.Decision == nil || it.Decision.Resolved >= it.Decision.Targets {
		return 0, false
	}
	return it.Decision.Targets, true
}

// resolvedCount is how many targets the item's candidate resolves.
func resolvedCount(it remediation.Item) int {
	if it.Decision != nil {
		return it.Decision.Resolved
	}
	return 0
}

// --- generic webhook ---

// remediationSchemaVersion is the format version of the webhook's
// remediation object.
const remediationSchemaVersion = 1

type remediationPayload struct {
	SchemaVersion int `json:"schema_version"`
	// Status is "ok" when a plan was produced and "unavailable" otherwise.
	Status            string `json:"status"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	NotSaved          bool   `json:"not_saved,omitempty"`

	GeneratedAt string                   `json:"generated_at,omitempty"`
	Conditions  *conditionsPayload       `json:"conditions,omitempty"`
	Limits      *remediation.Limits      `json:"limits,omitempty"`
	Usage       *remediation.Usage       `json:"usage,omitempty"`
	Summary     map[string]int           `json:"summary,omitempty"`
	Items       []remediationItemPayload `json:"items"`
	// LanguageSummary counts the language items by category; the items
	// themselves are in LanguageItems. Both are left out without a
	// dependency mapping.
	LanguageSummary map[string]int        `json:"language_summary,omitempty"`
	LanguageItems   []languageItemPayload `json:"language_items,omitempty"`

	// DockerfileSummary counts the Dockerfile base image items by category;
	// the items themselves are in DockerfileItems. Both are left out without
	// such an item.
	DockerfileSummary map[string]int          `json:"dockerfile_summary,omitempty"`
	DockerfileItems   []dockerfileItemPayload `json:"dockerfile_items,omitempty"`

	// PullRequestSummary counts the pull request units by status. The units
	// are in PullRequests, the operation events not yet delivered in
	// Operations and the conditions that stop writes in Problems; all
	// four are left out when pull requests are not enabled.
	PullRequestSummary map[string]int       `json:"pull_request_summary,omitempty"`
	PullRequests       []prUnitPayload      `json:"pull_requests,omitempty"`
	Operations         []prOperationPayload `json:"operations,omitempty"`
	Problems           []prProblemPayload   `json:"problems,omitempty"`
}

// conditionsPayload identifies the scan conditions every comparison of the
// plan was made under.
type conditionsPayload struct {
	TrivyVersion         string   `json:"trivy_version"`
	TrivySHA256          string   `json:"trivy_sha256,omitempty"`
	VulnerabilityDBAt    string   `json:"vulnerability_db_updated_at,omitempty"`
	VulnerabilityDBSHA   string   `json:"vulnerability_db_sha256,omitempty"`
	JavaDBAt             string   `json:"java_db_updated_at,omitempty"`
	JavaDBSHA            string   `json:"java_db_sha256,omitempty"`
	Severities           []string `json:"severities,omitempty"`
	AnalysisSettingsHash string   `json:"analysis_settings,omitempty"`
}

type remediationItemPayload struct {
	Key      string                   `json:"key"`
	Category string                   `json:"category"`
	Reason   string                   `json:"reason,omitempty"`
	Detail   string                   `json:"detail,omitempty"`
	Kind     string                   `json:"tag_kind,omitempty"`
	Priority string                   `json:"priority,omitempty"`
	Services []remediation.ServiceRef `json:"services,omitempty"`
	// Declared, Pull and Management are present for Kubernetes workloads
	// only. Declared are the images and pull policies the Pod specs name.
	// Pull is the guidance for taking the new content of a floating tag, by
	// effective pull policy. Management are the management chains read from
	// markers on the workload objects (claims, not verified facts).
	Declared   []remediation.DeclaredInstance `json:"declared,omitempty"`
	Pull       []remediation.PullAdvice       `json:"pull,omitempty"`
	Management []remediation.WorkloadChains   `json:"management,omitempty"`

	Current   imageStatePayload  `json:"current"`
	Candidate *imageStatePayload `json:"candidate,omitempty"`

	Targets    int                    `json:"targets"`
	KEVTargets int                    `json:"kev_targets,omitempty"`
	Comparison *comparisonPayload     `json:"comparison,omitempty"`
	Scans      []remediationScanEntry `json:"scans,omitempty"`
}

type imageStatePayload struct {
	Ref            string `json:"ref"`
	Tag            string `json:"tag,omitempty"`
	Content        string `json:"content,omitempty"` // the verified entity, running images only
	ConfigDigest   string `json:"config_digest,omitempty"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	TopDigest      string `json:"top_digest,omitempty"`
	Platform       string `json:"platform,omitempty"`
	// DigestKindUnverified: Content and ConfigDigest repeat a digest from
	// the container runtime whose kind (config, manifest or index) is not
	// confirmed.
	DigestKindUnverified bool `json:"digest_kind_unverified,omitempty"`
}

type comparisonPayload struct {
	Comparable bool   `json:"comparable"`
	Reason     string `json:"reason,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Decision   string `json:"decision,omitempty"`

	Targets    int `json:"targets"`
	Resolved   int `json:"resolved"`
	Remaining  int `json:"remaining"`
	Unknown    int `json:"unknown"`
	Undetected int `json:"undetected"`
	Introduced int `json:"introduced"`

	Verdicts            []verdictPayload `json:"verdicts,omitempty"`
	VerdictsTruncated   bool             `json:"verdicts_truncated,omitempty"`
	IntroducedFindings  []verdictPayload `json:"introduced_findings,omitempty"`
	IntroducedTruncated bool             `json:"introduced_findings_truncated,omitempty"`
}

type verdictPayload struct {
	VulnID         string   `json:"vuln_id"`
	Package        string   `json:"package"`
	Ecosystem      string   `json:"ecosystem,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Outcome        string   `json:"outcome"`
	Disposition    string   `json:"disposition,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	BeforeVersions []string `json:"before_versions,omitempty"`
	AfterVersions  []string `json:"after_versions,omitempty"`
}

// remediationScanEntry is one scan a comparison used.
type remediationScanEntry struct {
	Role      string `json:"role"`
	Ref       string `json:"ref"`
	Requested string `json:"requested"`
	Confirmed string `json:"confirmed"`
	DB        string `json:"db"`
	ScannedAt string `json:"scanned_at,omitempty"`
	Failure   string `json:"failure,omitempty"`
}

func remediationPayloadOf(p *PlanInfo) *remediationPayload {
	out := &remediationPayload{
		SchemaVersion: remediationSchemaVersion,
		Status:        "ok",
		NotSaved:      p.NotSaved,
		Items:         []remediationItemPayload{},
	}
	if p.Plan == nil {
		out.Status = "unavailable"
		out.UnavailableReason = string(p.Unavailable)
		return out
	}
	plan := *p.Plan
	out.GeneratedAt = plan.GeneratedAt.Format(time.RFC3339)
	out.Conditions = conditionsPayloadOf(plan.Conditions)
	limits, usage := plan.Limits, plan.Usage
	out.Limits, out.Usage = &limits, &usage
	out.Summary = map[string]int{}
	for _, c := range planSlackOrder {
		out.Summary[string(c)] = plan.Count(c)
	}
	scans := map[string]remediation.ScanExecution{}
	for _, s := range plan.Scans {
		scans[s.ID] = s
	}
	for _, it := range plan.Items {
		out.Items = append(out.Items, remediationItemPayloadOf(it, scans))
	}
	if len(plan.LanguageItems) > 0 {
		out.LanguageSummary = map[string]int{}
		for _, c := range planLanguageOrder {
			out.LanguageSummary[string(c)] = plan.CountLanguage(c)
		}
		for _, li := range plan.LanguageItems {
			out.LanguageItems = append(out.LanguageItems, languageItemPayloadOf(li, plan.PullRequests))
		}
	}
	if len(plan.DockerfileItems) > 0 {
		out.DockerfileSummary = map[string]int{}
		for _, c := range planSlackOrder {
			out.DockerfileSummary[string(c)] = plan.CountDockerfile(c)
		}
		for _, di := range plan.DockerfileItems {
			out.DockerfileItems = append(out.DockerfileItems, dockerfileItemPayloadOf(di, scans, plan.PullRequests))
		}
	}
	if len(plan.PullRequests) > 0 {
		out.PullRequestSummary = map[string]int{}
		for _, u := range plan.PullRequests {
			out.PullRequestSummary[string(u.Status)]++
			out.PullRequests = append(out.PullRequests, prUnitPayloadOf(u))
		}
	}
	for _, ev := range plan.PROperations {
		out.Operations = append(out.Operations, prOperationPayloadOf(ev))
	}
	for _, pp := range plan.PRProblems {
		out.Problems = append(out.Problems, prProblemPayload{Code: string(pp.Code), Repo: pp.Repo, Target: pp.Target, Reason: string(pp.Reason), Detail: pp.Detail})
	}
	return out
}

// maxWebhookFixTargets caps the fix targets of one pull request unit in the
// webhook payload; a list past the cap is marked truncated.
const maxWebhookFixTargets = 100

type prUnitPayload struct {
	// Kind is "dockerfile" for a base image update, "language" for a
	// lockfile update, "kubernetes" for a manifest tag update and "kustomize"
	// for a Kustomize images entry update (Services,
	// Workloads and Locations are then all workload keys); absent for a
	// Compose tag update. For a Dockerfile,
	// Path is the Dockerfile, Services the services of its workloads and
	// CurrentRef the base image its FROM names. For a language update, Path
	// is the lockfile, ItemKey the language item and Language what it
	// changes; the image reference and candidate are empty.
	Kind       string   `json:"kind,omitempty"`
	Key        string   `json:"key"`
	Repo       string   `json:"repo"`
	BaseBranch string   `json:"base_branch"`
	Path       string   `json:"path"`
	Services   []string `json:"services"`
	Workloads  []string `json:"workloads,omitempty"`
	// AlsoRunning are services running the same image that no Compose mapping
	// covers; they are not edited.
	AlsoRunning     []remediation.ServiceRef `json:"also_running,omitempty"`
	CurrentRef      string                   `json:"current_ref"`
	CandidateTag    string                   `json:"candidate_tag,omitempty"`
	CandidateDigest string                   `json:"candidate_digest,omitempty"`

	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`

	Number       int    `json:"number,omitempty"`
	URL          string `json:"url,omitempty"`
	State        string `json:"state,omitempty"`
	UserModified bool   `json:"user_modified,omitempty"`
	TargetKey    string `json:"target_key,omitempty"`
	UpdateKey    string `json:"update_key,omitempty"`
	AttemptKey   string `json:"attempt_key,omitempty"`

	FixTargetCount      int                `json:"fix_target_count"`
	FixTargets          []fixTargetPayload `json:"fix_targets,omitempty"`
	FixTargetsTruncated bool               `json:"fix_targets_truncated,omitempty"`
	ReplacedBy          int                `json:"replaced_by,omitempty"`
	Replacing           []replacingPayload `json:"replacing,omitempty"`
	// Replaced are the pull requests closed in favour of this one.
	Replaced []int `json:"replaced,omitempty"`

	ItemKey  string                  `json:"item_key,omitempty"`
	Language *remediation.PRLanguage `json:"language,omitempty"`
}

type fixTargetPayload struct {
	Location  string `json:"location"`
	VulnID    string `json:"vuln_id"`
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type replacingPayload struct {
	OldNumber int    `json:"old_number"`
	State     string `json:"state"`
}

func prUnitPayloadOf(u remediation.PRUnit) prUnitPayload {
	out := prUnitPayload{
		Kind: u.Kind,
		Key:  u.Key, Repo: u.Repo, BaseBranch: u.BaseBranch, Path: u.Path,
		Services: u.Services, Workloads: u.Workloads, AlsoRunning: u.AlsoRunning,
		CurrentRef: u.Current, CandidateTag: u.CandidateTag, CandidateDigest: u.CandidateDigest,
		Status: string(u.Status), Reason: string(u.Reason), Detail: u.Detail,
		Number: u.Number, URL: u.URL, State: string(u.State), UserModified: u.UserModified,
		TargetKey: u.TargetKey, UpdateKey: u.UpdateKey, AttemptKey: u.AttemptKey,
		FixTargetCount: len(u.FixTargets), ReplacedBy: u.ReplacedBy, Replaced: u.Replaced,
		ItemKey: u.ItemKey, Language: u.Language,
	}
	if out.Services == nil {
		out.Services = []string{}
	}
	targets := u.FixTargets
	if len(targets) > maxWebhookFixTargets {
		targets, out.FixTargetsTruncated = targets[:maxWebhookFixTargets], true
	}
	for _, t := range targets {
		out.FixTargets = append(out.FixTargets, fixTargetPayload{
			Location: t.Location, VulnID: t.VulnID, Package: t.Package.Name, Ecosystem: string(t.Package.Ecosystem)})
	}
	for _, r := range u.Replacing {
		out.Replacing = append(out.Replacing, replacingPayload{OldNumber: r.OldNumber, State: string(r.State)})
	}
	return out
}

// prOperationPayload is one operation event not yet delivered. The intent,
// the result and any later settlement of one operation share an ID.
type prOperationPayload struct {
	Seq        int64  `json:"seq"`
	ID         string `json:"id"`
	At         string `json:"at"`
	Phase      string `json:"phase"`
	Kind       string `json:"kind"`
	Repo       string `json:"repo"`
	AttemptKey string `json:"attempt_key,omitempty"`
	Number     int    `json:"number,omitempty"`
	Result     string `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

func prOperationPayloadOf(ev remediation.OperationEvent) prOperationPayload {
	return prOperationPayload{
		Seq: ev.Seq, ID: ev.ID, At: ev.At.UTC().Format(time.RFC3339), Phase: string(ev.Phase), Kind: string(ev.Kind),
		Repo: ev.Repo, AttemptKey: ev.AttemptKey, Number: ev.Number, Result: string(ev.Result), Error: ev.Error,
	}
}

type prProblemPayload struct {
	Code   string `json:"code"`
	Repo   string `json:"repo,omitempty"`
	Target string `json:"target,omitempty"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Caps on the lists of one language item in the webhook payload; a list past
// its cap is marked truncated and its full size is given.
const (
	maxWebhookPackages    = 100
	maxWebhookOccurrences = 20
	maxWebhookCVEs        = 50
	maxWebhookOrigins     = 50
)

type languageItemPayload struct {
	Key       string                   `json:"key"`
	Category  string                   `json:"category"`
	Reason    string                   `json:"reason,omitempty"`
	Detail    string                   `json:"detail,omitempty"`
	Manager   string                   `json:"manager,omitempty"`
	Priority  string                   `json:"priority,omitempty"`
	Workloads []string                 `json:"workloads"`
	Source    remediation.SourceRecord `json:"source"`
	// RuntimeEOL is the runtime (id, name) and the date its support ended,
	// set with the reason runtime_eol.
	RuntimeEOL *remediation.RuntimeEOLInfo `json:"runtime_eol,omitempty"`
	// UpdateExecuted and PostUpdateCheckExecuted are false in a plan: no
	// package manager was run and no result was inspected.
	UpdateExecuted          bool `json:"update_executed"`
	PostUpdateCheckExecuted bool `json:"post_update_check_executed"`

	// RetryAfter is when an item deferred for the age of a release is tried
	// again.
	RetryAfter *time.Time `json:"retry_after,omitempty"`

	PackageCount      int                      `json:"package_count"`
	Packages          []languagePackagePayload `json:"packages,omitempty"`
	PackagesTruncated bool                     `json:"packages_truncated,omitempty"`

	// The following are set once the update stage has handled the item.
	// Update is what was run and changed (steps, notes, the lockfile diff and
	// the manifest edits), SourceCheck the scan of the dependency files before
	// and after, Artifacts the files an update produced (path, hash and size;
	// never the content) and PullRequest the state of its pull request.
	Update      *remediation.LanguageUpdate `json:"update,omitempty"`
	SourceCheck *remediation.SourceCheck    `json:"source_check,omitempty"`
	Artifacts   []remediation.ArtifactFile  `json:"artifacts,omitempty"`
	PullRequest *languagePRPayload          `json:"pull_request,omitempty"`
}

// languagePRPayload is the state of the pull request unit of a language item.
type languagePRPayload struct {
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Number     int    `json:"number,omitempty"`
	URL        string `json:"url,omitempty"`
	State      string `json:"state,omitempty"`
	TargetKey  string `json:"target_key,omitempty"`
	UpdateKey  string `json:"update_key,omitempty"`
	AttemptKey string `json:"attempt_key,omitempty"`
}

type languagePackagePayload struct {
	Name                string `json:"name"`
	Normalized          string `json:"normalized,omitempty"`
	Ecosystem           string `json:"ecosystem"`
	Installed           string `json:"installed"`
	SelectionLowerBound string `json:"selection_lower_bound,omitempty"`
	AdoptedVersion      string `json:"adopted_version,omitempty"`
	Relation            string `json:"relation,omitempty"`
	Action              string `json:"action,omitempty"`
	Reason              string `json:"reason,omitempty"`
	Detail              string `json:"detail,omitempty"`
	// LeftOut marks a package that was planned for an update and left out of
	// the update.
	LeftOut bool `json:"left_out,omitempty"`
	// Through names the direct dependencies a chain update moved to bring the
	// package to its version.
	Through []string `json:"through,omitempty"`

	OccurrenceCount      int                            `json:"occurrence_count"`
	Occurrences          []remediation.SourceOccurrence `json:"occurrences,omitempty"`
	OccurrencesTruncated bool                           `json:"occurrences_truncated,omitempty"`
	CVECount             int                            `json:"cve_count"`
	KEVCount             int                            `json:"kev_count,omitempty"`
	CVEs                 []remediation.CVERef           `json:"cves,omitempty"`
	CVEsTruncated        bool                           `json:"cves_truncated,omitempty"`
	// Origins are the findings of the running images the package came from.
	OriginCount      int                         `json:"origin_count"`
	Origins          []remediation.FindingOrigin `json:"origins,omitempty"`
	OriginsTruncated bool                        `json:"origins_truncated,omitempty"`
}

func languageItemPayloadOf(li remediation.LanguageItem, units []remediation.PRUnit) languageItemPayload {
	out := languageItemPayload{
		Key: li.Key, Category: string(li.Category), Reason: string(li.Reason), Detail: li.Detail,
		Manager: string(li.Manager), Priority: string(li.Priority), Workloads: li.Workloads,
		Source: li.Source, RuntimeEOL: li.RuntimeEOL,
		UpdateExecuted: li.UpdateExecuted, PostUpdateCheckExecuted: li.PostUpdateCheckExecuted,
		PackageCount: len(li.Packages), RetryAfter: li.RetryAfter,
		Update: li.Update, SourceCheck: li.SourceCheck, Artifacts: li.Artifacts,
	}
	if li.Update != nil {
		// The webhook keeps the fields it has always had: the names of the
		// deprecation notes are for the pull request body.
		update := *li.Update
		update.DeprecatedNotes = nil
		out.Update = &update
	}
	u := languageUnitOf(li, units)
	if u != nil {
		out.PullRequest = &languagePRPayload{
			Status: string(u.Status), Reason: string(u.Reason), Detail: u.Detail, Number: u.Number, URL: u.URL, State: string(u.State),
			TargetKey: u.TargetKey, UpdateKey: u.UpdateKey, AttemptKey: u.AttemptKey,
		}
	}
	pkgs := li.Packages
	if len(pkgs) > maxWebhookPackages {
		pkgs, out.PackagesTruncated = pkgs[:maxWebhookPackages], true
	}
	var leftOut []remediation.PRLanguageRemaining
	if u != nil && u.Language != nil {
		leftOut = u.Language.Remaining
	}
	var moved []remediation.PRLanguagePackage
	if u != nil && u.Language != nil {
		moved = u.Language.Packages
	}
	for _, p := range pkgs {
		pp := languagePackagePayload{
			Name: p.Name, Normalized: p.Normalized, Ecosystem: p.Ecosystem, Installed: p.Installed,
			SelectionLowerBound: p.SelectionLowerBound, AdoptedVersion: p.AdoptedVersion,
			Relation: string(p.Relation), Action: string(p.Action), Reason: string(p.Reason), Detail: p.Detail, LeftOut: p.LeftOut, Through: p.Through,
			OccurrenceCount: len(p.Occurrences), Occurrences: p.Occurrences,
			CVECount: len(p.CVEs), KEVCount: p.KEVCount(), CVEs: p.CVEs,
			OriginCount: len(p.Origins), Origins: p.Origins,
		}
		// An item tied to a pull request made in an earlier cycle was not
		// updated again and does not say which direct dependencies the update
		// moved; the pull request's view does.
		if len(pp.Through) == 0 {
			for _, x := range moved {
				if x.Name == p.Name && x.Ecosystem == p.Ecosystem && len(x.Through) > 0 {
					pp.Through = x.Through
					break
				}
			}
		}
		// An item tied to a pull request made in an earlier cycle was not
		// updated again and holds no left-out marks; the pull request's view
		// says which packages it leaves out.
		for _, x := range leftOut {
			if x.Name == p.Name && x.Ecosystem == p.Ecosystem {
				pp.LeftOut, pp.Action, pp.Reason = true, string(remediation.ActionManual), string(x.Reason)
				if x.Detail != "" {
					pp.Detail = x.Detail
				}
				break
			}
		}
		if len(pp.Origins) > maxWebhookOrigins {
			pp.Origins, pp.OriginsTruncated = pp.Origins[:maxWebhookOrigins], true
		}
		if len(pp.Occurrences) > maxWebhookOccurrences {
			pp.Occurrences, pp.OccurrencesTruncated = pp.Occurrences[:maxWebhookOccurrences], true
		}
		if len(pp.CVEs) > maxWebhookCVEs {
			pp.CVEs, pp.CVEsTruncated = pp.CVEs[:maxWebhookCVEs], true
		}
		out.Packages = append(out.Packages, pp)
	}
	return out
}

func conditionsPayloadOf(c scanner.ScanConditions) *conditionsPayload {
	if c.TrivyVersion == "" && !c.VulnerabilityDB.Known() {
		return nil
	}
	return &conditionsPayload{
		TrivyVersion:         c.TrivyVersion,
		TrivySHA256:          c.TrivySHA,
		VulnerabilityDBAt:    formatTimeOrEmpty(c.VulnerabilityDB.UpdatedAt),
		VulnerabilityDBSHA:   c.VulnerabilityDBSHA,
		JavaDBAt:             formatTimeOrEmpty(c.JavaDB.UpdatedAt),
		JavaDBSHA:            c.JavaDBSHA,
		Severities:           c.Severities,
		AnalysisSettingsHash: c.AnalysisSettings,
	}
}

func imageStatePayloadOf(s remediation.ImageState, running bool) imageStatePayload {
	out := imageStatePayload{
		Ref:            s.Ref,
		Tag:            s.Tag,
		ConfigDigest:   s.ConfigDigest,
		ManifestDigest: s.ManifestDigest,
		TopDigest:      s.TopDigest,
		Platform:       s.Platform,

		DigestKindUnverified: s.DigestKindUnverified,
	}
	if running {
		out.Content = s.Entity
	}
	return out
}

func remediationItemPayloadOf(it remediation.Item, scans map[string]remediation.ScanExecution) remediationItemPayload {
	out := remediationItemPayload{
		Key:        it.Key,
		Category:   string(it.Category),
		Reason:     string(it.Reason),
		Detail:     it.Detail,
		Kind:       string(it.Kind),
		Priority:   string(it.Priority),
		Services:   it.Services,
		Declared:   it.Declared,
		Pull:       it.Pull,
		Management: it.Management,
		Current:    imageStatePayloadOf(it.Current, true),
		Targets:    len(it.Targets),
		KEVTargets: kevTargets(it),
	}
	if it.Candidate != nil {
		c := imageStatePayloadOf(*it.Candidate, false)
		out.Candidate = &c
	}
	if it.Comparison != nil {
		out.Comparison = comparisonPayloadOf(it)
	}
	out.Scans = scanEntries(scans, it.BaselineScan, it.CandidateScan)
	return out
}

// scanEntries lists the recorded scans with the given IDs, skipping unknown
// ones.
func scanEntries(scans map[string]remediation.ScanExecution, ids ...string) []remediationScanEntry {
	var out []remediationScanEntry
	for _, id := range ids {
		s, ok := scans[id]
		if !ok {
			continue
		}
		e := remediationScanEntry{
			Role:      string(s.Role),
			Ref:       s.Ref,
			Requested: s.Requested,
			Confirmed: s.Confirmed,
			DB:        string(s.DB),
			Failure:   s.Failure,
		}
		if s.ScannedAt != nil {
			e.ScannedAt = s.ScannedAt.Format(time.RFC3339)
		}
		out = append(out, e)
	}
	return out
}

func comparisonPayloadOf(it remediation.Item) *comparisonPayload {
	return comparisonPayloadFor(*it.Comparison, it.Decision, len(it.Targets))
}

// comparisonPayloadFor renders a comparison with the decision made on it and
// the number of targets it was judged on.
func comparisonPayloadFor(vr remediation.VerificationResult, dec *remediation.Decision, targets int) *comparisonPayload {
	resolved, remaining, introduced := vr.Counts()
	out := &comparisonPayload{
		Comparable: vr.Comparable,
		Reason:     string(vr.Reason),
		Scope:      vr.Scope,
		Targets:    targets,
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	}
	if d := dec; d != nil {
		out.Decision = string(d.Kind)
		out.Resolved, out.Remaining = d.Resolved, d.Remaining
		out.Unknown, out.Undetected = d.Unknown, d.Undetected
		out.Targets = d.Targets
	}
	out.Verdicts, out.VerdictsTruncated = verdictPayloads(vr.Verdicts)
	out.IntroducedFindings, out.IntroducedTruncated = verdictPayloads(vr.Introduced)
	return out
}

func verdictPayloads(vs []remediation.VulnVerdict) ([]verdictPayload, bool) {
	truncated := false
	if len(vs) > maxWebhookVerdicts {
		vs, truncated = vs[:maxWebhookVerdicts], true
	}
	var out []verdictPayload
	for _, v := range vs {
		out = append(out, verdictPayload{
			VulnID:         v.VulnID,
			Package:        v.Package.Name,
			Ecosystem:      string(v.Package.Ecosystem),
			Severity:       string(v.Severity),
			Outcome:        string(v.Outcome),
			Disposition:    string(v.Disposition),
			Reason:         string(v.Reason),
			BeforeVersions: remediation.Versions(v.Before),
			AfterVersions:  remediation.Versions(v.After),
		})
	}
	return out, truncated
}
