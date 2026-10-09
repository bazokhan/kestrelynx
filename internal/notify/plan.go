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

// PlanInfo is the fix plan section of a Message. Plan is nil exactly when
// Unavailable is set. NotSaved marks a plan that was built but could not be
// written to its file.
type PlanInfo struct {
	Plan        *remediation.Plan
	Unavailable PlanUnavailable
	NotSaved    bool
	// Changed says the plan differs from the last one delivered. It decides
	// whether Slack mentions a plan with no items at all (a plan that became
	// empty), which is otherwise left out.
	Changed bool
}

// visible reports whether the Slack message has a fix plan section: always
// for an unavailable or unsaved plan, otherwise when there is something to
// show or the plan just became empty.
func (p *PlanInfo) visible() bool {
	if p == nil {
		return false
	}
	return p.Plan == nil || p.NotSaved || len(p.Plan.Items) > 0 || p.Changed
}

// slackTopItems is how many pull-again and update-candidate items the Slack
// section lists by name; the webhook carries every item.
const slackTopItems = 3

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

// planSegment is the counts-line wording of category c.
func planSegment(c remediation.Category, n int, msg messages) string {
	var f string
	switch c {
	case remediation.CategoryPullAgain:
		f = msg.PlanSegPullAgain
	case remediation.CategoryPRCandidate:
		f = msg.PlanSegUpdate
	case remediation.CategoryManual:
		f = msg.PlanSegManual
	case remediation.CategoryNotComparable:
		f = msg.PlanSegNotComparable
	case remediation.CategoryDeferred:
		f = msg.PlanSegDeferred
	case remediation.CategoryNoCandidate:
		f = msg.PlanSegNoCandidate
	case remediation.CategoryExcluded:
		f = msg.PlanSegExcluded
	case remediation.CategoryFailed:
		f = msg.PlanSegFailed
	default:
		return ""
	}
	return fmt.Sprintf(f, n)
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

// planLines are the lines of the Slack fix plan section.
func planLines(p *PlanInfo, webhook bool, msg messages) []string {
	lines := []string{trimNL(msg.PlanHeading)}
	if p.Plan == nil {
		if p.Unavailable == PlanDatabasesNotPrepared {
			lines = append(lines, trimNL(msg.PlanUnavailableDB))
		} else {
			lines = append(lines, trimNL(msg.PlanUnavailableOther))
		}
		return lines
	}
	plan := *p.Plan
	var segs []string
	for _, c := range planSlackOrder {
		if n := plan.Count(c); n > 0 {
			segs = append(segs, planSegment(c, n, msg))
		}
	}
	if len(segs) == 0 {
		lines = append(lines, trimNL(msg.PlanNothing))
	} else {
		lines = append(lines, strings.Join(segs, " · "))
	}
	// Items that need a person's attention come first, then the adopted
	// ones; only the first slackTopItems are listed.
	var warn, adopted []string
	for _, it := range plan.Items {
		ref := escMrkdwn(it.Current.Ref)
		switch {
		case it.Category == remediation.CategoryManual && it.Reason == remediation.ReasonIntroducedKEV:
			if it.Kind == remediation.TagPinned && it.Candidate != nil {
				warn = append(warn, fmt.Sprintf(msg.PlanIntroducedKEVUpdateLine, ref, escMrkdwn(it.Candidate.Tag)))
			} else {
				warn = append(warn, fmt.Sprintf(msg.PlanIntroducedKEVPullLine, ref))
			}
		case it.Category == remediation.CategoryPullAgain:
			if n, ok := partialOf(it); ok {
				adopted = append(adopted, fmt.Sprintf(msg.PlanPullAgainPartialLine, ref, resolvedCount(it), n, remainderClause(it, msg))+kevSuffix(it, msg))
			} else {
				adopted = append(adopted, fmt.Sprintf(msg.PlanPullAgainLine, ref, resolvedCount(it))+kevSuffix(it, msg))
			}
		case it.Category == remediation.CategoryPRCandidate && it.Candidate != nil:
			tag := escMrkdwn(it.Candidate.Tag)
			if n, ok := partialOf(it); ok {
				adopted = append(adopted, fmt.Sprintf(msg.PlanUpdatePartialLine, ref, tag, resolvedCount(it), n, remainderClause(it, msg))+kevSuffix(it, msg))
			} else {
				adopted = append(adopted, fmt.Sprintf(msg.PlanUpdateLine, ref, tag, resolvedCount(it))+kevSuffix(it, msg))
			}
		}
	}
	all := append(warn, adopted...)
	total, shown := len(all), len(all)
	if shown > slackTopItems {
		shown = slackTopItems
	}
	for _, l := range all[:shown] {
		lines = append(lines, trimNL(l))
	}
	if total > shown {
		lines = append(lines, strings.TrimSpace(fmt.Sprintf(msg.MoreCount, total-shown)))
	}
	if p.NotSaved {
		lines = append(lines, trimNL(msg.PlanNotSaved))
	}
	if webhook {
		lines = append(lines, trimNL(msg.DetailsInWebhook))
	}
	return lines
}

// kevSuffix is the plan line's count of resolved KEV-listed findings.
func kevSuffix(it remediation.Item, msg messages) string {
	if k := resolvedKEVTargets(it); k > 0 {
		return fmt.Sprintf(msg.PlanKEVSuffix, k)
	}
	return ""
}

// remainderClause says how many targeted findings the candidate leaves: the
// ones observed still present, and — only when there are any — the ones the
// comparison scan of the running image did not show.
func remainderClause(it remediation.Item, msg messages) string {
	var parts []string
	if d := it.Decision; d != nil {
		if d.Remaining > 0 {
			parts = append(parts, fmt.Sprintf(msg.PlanRemainClause, d.Remaining))
		}
		if d.Undetected > 0 {
			parts = append(parts, fmt.Sprintf(msg.PlanUndetectedClause, d.Undetected))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf(msg.PlanClauseWrap, strings.Join(parts, msg.PlanClauseJoin))
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

// planSection emits the fix plan section as a group of its own and reports
// whether there was one to emit.
func (v *chView) planSection() bool {
	if !v.plan.visible() {
		return false
	}
	v.l.group()
	v.l.section(v.rd.lim, planLines(v.plan, v.r.GenericWebhookConfigured, v.msg), false)
	return true
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
	for _, id := range []string{it.BaselineScan, it.CandidateScan} {
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
		out.Scans = append(out.Scans, e)
	}
	return out
}

func comparisonPayloadOf(it remediation.Item) *comparisonPayload {
	vr := *it.Comparison
	resolved, remaining, introduced := vr.Counts()
	out := &comparisonPayload{
		Comparable: vr.Comparable,
		Reason:     string(vr.Reason),
		Scope:      vr.Scope,
		Targets:    len(it.Targets),
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	}
	if d := it.Decision; d != nil {
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
