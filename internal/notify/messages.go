// User-facing wording for the Slack channel message and thread report, kept
// in one typed dictionary so a translation only ever has to fill in this
// file. Everything else in this package renders vulnerability data (CVE ids,
// package names, versions, image references, Trivy titles, URLs) untouched —
// only the surrounding English prose lives here.
//
// A finding's severity/status vocabulary (CRITICAL, HIGH, fixed, ...) and
// Slack mrkdwn syntax (*, _, <url|text>) are not translated either: the
// former is scanner-standard terminology callers already rely on verbatim
// (e.g. the generic webhook's severity_counts keys), and the latter is
// Slack's own markup, not prose.
package notify

// Language selects which messages dictionary a rendering uses.
type Language string

const (
	// LanguageEN is the default: the wording every existing deployment has
	// always seen. enMessages is the historical, byte-pinned English text —
	// changing any of its values changes what a live deployment shows.
	LanguageEN Language = "en"
	// LanguageJA selects the Japanese dictionary.
	LanguageJA Language = "ja"
)

// messages is every translatable string the Slack channel message and
// thread report can print. Fields group roughly by the view that uses them;
// each is a fmt format string — arguments are documented at each call site,
// and any field taking two or more verbs uses positional (%[1]s-style)
// verbs so a translation can reorder them freely.
type messages struct {
	// Lang is the language of the dictionary.
	Lang Language

	// --- header / role line ---
	HeaderNamed                string // "🛡️ *KestreLynx* [%[1]s] — scan results for %[2]s\n" (environment name, generated-at)
	HeaderDefault              string // "🛡️ *KestreLynx* — scan results for %s\n" (generated-at)
	RoleEverythingOpen         string // "Everything currently open."
	RoleChangesSinceLastScan   string // "Changes since the last scan."
	ImagesScannedAffected      string // "%[1]d images scanned, %[2]d affected\n"
	AllClear                   string // "\n✅ All clear (no HIGH/CRITICAL vulnerabilities found)\n"
	LowerRiskSummarizedWebhook string // "\n_%d lower-risk fix(es) summarized — full list in the generic webhook payload._\n"
	LowerRiskSummarized        string // "\n_%d lower-risk fix(es) summarized._\n"

	// --- diff mode framing ---
	NoChangesSinceLastScan  string // "\nNo changes since last scan.\n"
	HeadingNewEOSL          string // "\n*⛔ New: base OS end-of-life (top priority)*\n"
	WeeklyFullReportHeading string // "\n*📋 Weekly full report — everything currently open*\n"

	// --- replaced images ---
	ReplacedHeading string // "\n*🔄 Image content changed (%d)*\n"
	ReplacedLine    string // "• %[1]s: image updated (%[2]s → %[3]s)\n" (ref, prev digests, new digests)

	// --- reference changes (history carried to a new tag or digest) ---
	RefChangeLine string // "🔄 Image reference updated: %[1]s %[2]s → %[3]s (history carried over)\n" (repository, old tag, new tag)

	// --- identity / unresolved references ---
	IdentityUnconfirmed string // "identity unconfirmed: scanned by reference"
	UnresolvedRefsLine  string // "⚠️ %[1]s — %[2]s\n" (IdentityUnconfirmed text, comma-joined refs)
	UnconfirmedRefsLine string // "⏳ unconfirmed this cycle, holding previous findings — %s\n" (comma-joined refs)
	// RuntimeUncheckedLine says a language runtime of some images was not
	// matched against advisories this cycle: "ℹ️ Advisories for %[1]s could not be fetched, so the runtime of %[2]d image(s) was not checked.\n"
	// (runtime names joined with RuntimeNameSeparator, count of distinct images)
	RuntimeUncheckedLine string
	RuntimeNameSeparator string // ", " between the runtime names of RuntimeUncheckedLine

	// --- new/changed findings ---
	NewSinceLastScanHeading string // "\n*🆕 New since last scan (%d)*\n"
	MoreCount               string // " (+%d more)" — shared by the new-CVE-id list, the collapsed lower-risk list, the runtime process list and the thread's "also:" list
	EscalatedTo             string // "⬆️ escalated to %s" (priority label: ACT NOW/WATCH/LOW)
	FixNowAvailable         string // "fix now available"
	Unmuted                 string // "↩️ Unmuted (%s)" (unmutedReason text)

	// --- resolved findings ---
	ResolvedHeading       string // "\n*✅ Resolved since last scan (%d)*\n"
	BaseOSNoLongerEOL     string // "• %s — base OS no longer EOL\n" (ref)
	ResolvedImagePackages string // "• %[1]s: %[2]s\n" (ref, comma-joined packages)
	NoLongerEndOfLife     string // "• %[1]s: %[2]s — no longer end-of-life\n" (ref, package)

	// --- "open now" heartbeat, triage-off ---
	OpenNowUnconfirmedHolding string // "\n📌 Open now: unconfirmed — holding previous findings until re-confirmed\n"
	OpenNowNotRescanned       string // "\n📌 Open now: not re-scanned — holding previous findings until the next successful scan\n"
	OpenNowAllClear           string // "\n🎉 Open now: none — all clear\n"
	OpenNowCriticalHigh       string // "CRITICAL %[1]d / HIGH %[2]d%[4]s across %[3]d image(s)" (%[4]s: the OpenNowSevExtra parts for levels below HIGH, "" when none)
	OpenNowSevExtra           string // " / %[1]s %[2]d" (level name, count) for a level below HIGH in the open-now line
	OpenNowPrefix             string // "\n📌 Open now: %s" (joined segments)
	OldestUnresolvedStale     string // " — ⏰ oldest unresolved %d day(s)"
	OldestUnresolved          string // " — oldest unresolved %d day(s)"
	DetailsInWebhook          string // "_Details in the generic webhook payload._\n"

	// --- EOL/CRITICAL/care/safe segments ---
	SegEOLBase    string // "⛔ %d EOL base"
	SegEOLPackage string // "⛔ %d EOL package"
	SegCritical   string // "🔴 %d CRITICAL"
	SegNeedCare   string // "🟠 %d need care"
	SegSafe       string // "🟢 %d safe"
	SegWatch      string // "👀 %d watch" — shared by the priority line and the open-now line
	SegLow        string // "🔕 %d low" — shared by the priority line and the open-now line
	PriorityLine  string // "*Priority:* %s\n" (joined segments)

	// --- scan failures ---
	ScanFailuresHeading string // "\n*⚠️ Scan failures*\n"
	ScanFailureLine     string // "• %[1]s — %[2]s\n" (ref, error text)

	// --- status sections, triage off ---
	ActionableTitle     string // "✅ Actionable now (fixed)" (bare title; format.go wraps it "\n*%s*\n", thread.go wraps it "*%s*")
	WatchSectionTitle   string // "ℹ️ No fix yet (affected / waiting on upstream)"
	WontFixSectionTitle string // "🔕 No fix planned for this OS release (will_not_fix)"

	// --- upgrade-risk labels ---
	RiskDistroUpdate string // "🟢 upgrade: distro security patch"
	RiskSafe         string // "🟢 upgrade: low-risk"
	RiskCaution      string // "🟠 upgrade: major version bump — needs care"
	RiskUnknown      string // "⚪ upgrade: risk unknown"

	// --- end-of-life wording ---
	EOLPackageText   string // "end-of-life: no fix planned for this release"
	EOLRuntimeText   string // "end-of-life: no fix will be released for this series; upgrade the series (manual)" (a language runtime itself)
	EOLSectionReason string // "vendor reports these CVEs as out of support for this release"

	// --- triage headline / intel warnings ---
	SegActNow            string // "🚨 %d act now" (the priority line only; the open-now line uses OpenNowActNow instead)
	IntelDegradedWarning string // "⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low\n"
	IntelKEVUnavailable  string // "⚠️ CISA KEV data unavailable — act-now detection may be incomplete\n"
	IntelEPSSUnavailable string // "⚠️ EPSS data unavailable — triage is using KEV and severity only\n"
	IntelStale           string // "\n_Intel data is %d day(s) old (feeds unreachable)._\n"

	// --- act now / watch / low buckets ---
	ActNowHeading       string // "\n*🚨 Act now (%d) — exploited or likely to be*\n"
	WatchHeading        string // "\n*👀 Watch (%d) — not urgent, keep an eye on*\n"
	LowHeading          string // "\n*🔕 Low priority (%[1]d)* — %[2]d finding(s) across %[3]d image(s), no exploitation signal (not in KEV, EPSS below threshold)."
	TriageLowInUseCount string // " · ▶ %d in use"

	// --- evidence lines ---
	EvidenceMoreCVEs  string // " (+%d more CVE(s) in this package)"
	AdvisoryLinkLabel string // "advisory" (Slack link label text)
	// VendorAdvisoryLinkLabel replaces analyze.Ref.Label as the Slack link
	// text for a "vendor" reference (the KEV note's advisory link) — display
	// only: analyze.Ref.Label itself and the webhook payload's ref label
	// always stay the English "vendor advisory" (analyze/triage.go,
	// format.go's refPayload). A "discussion" reference (the HN link) is
	// unaffected and keeps using ref.Label as-is.
	VendorAdvisoryLinkLabel string // "vendor advisory"
	EvidenceSeverityOnly    string // "severity only (intel unavailable)"
	EvidenceKEV             string // "CISA KEV (exploited in the wild)"
	EvidenceEPSSPrefix      string // "EPSS %s" (epssString result)
	EvidenceRansomware      string // "🧨 ransomware campaign"

	// --- diff-mode triage ---
	OpenNowActNow          string // "🚨 %d act-now"
	OldestActNowWatchStale string // " — ⏰ oldest act-now/watch unresolved %d day(s)"
	OldestActNowWatch      string // " — oldest act-now/watch unresolved %d day(s)"
	PriorityLabelActNow    string // "ACT NOW"
	PriorityLabelWatch     string // "WATCH"
	PriorityLabelLow       string // "LOW"

	// --- end-of-life sections ---
	EOSLHeading               string // "\n*⛔ Base OS end-of-life (top priority)*\n"
	EOLPackageHeading         string // "\n*⛔ Package end-of-life (%[1]d) — %[2]s*\n" (count, EOLSectionReason)
	EOLPackagesChangedHeading string // "\n*⛔ New: package end-of-life (%[1]d) — %[2]s*\n" (count, EOLSectionReason)
	EOLFoldNewPackages        string // "%d package(s) newly end-of-life"
	EOLFoldWithNewCVEs        string // "%d end-of-life package(s) with new CVEs"

	// --- thread report ---
	ThreadTitle              string // "📊 *Everything open now — %s*" (generated-at)
	EOLBaseImagesHeading     string // "*⛔ EOL base images (%d)*"
	MutedLine                string // "🔇 Muted — no fix available and not in use for 7+ days: %d\n"
	ThreadActNowHeading      string // "*🚨 ACT NOW (%d) — exploited or likely to be*"
	ThreadWatchHeading       string // "*👀 WATCH (%d) — not urgent, keep an eye on*"
	ThreadLowHeading         string // "\n*🔕 LOW (%d)* — no exploitation signal"
	ThreadLowDetailsSuffix   string // "; details in the generic webhook payload"
	ThreadLowInUseCount      string // "▶ in use among low: %d\n"
	EOLPackagesThreadHeading string // "*⛔ EOL packages (%[1]d) — %[2]s*" (count, EOLSectionReason)
	ThreadContinued          string // " _(cont.)_" (appended to a section title repeated on a later message)

	// --- runtime warnings ---
	RuntimeWarningUnavailable       string // "⚠️ Runtime evidence unavailable: %s\n" (status text)
	RuntimeWarningEventsUnavailable string // "⚠️ Short-lived programs are not observed (eBPF unavailable: %s); using sampling only\n" (events reason text)

	// --- Sensor status text ---
	StatusTextNotReporting      string // "the Sensor has not reported yet"
	StatusTextEvidenceInvalid   string // "the evidence file failed validation"
	StatusTextStale             string // "the Sensor's last report is stale"
	StatusTextPermissionDenied  string // "the Sensor's reads are being denied"
	StatusTextIsolationFailed   string // "the Sensor's sandbox failed to start"
	StatusTextIsolationDegraded string // "the Sensor's sandbox is running degraded"
	StatusTextDegraded          string // "the Sensor is degraded"
	StatusTextOK                string // "ok"
	StatusTextUnknown           string // "unknown" (runtimeStatusText's own default branch)

	// --- unavailable-package reason text ---
	ReasonSensorNotReporting   string // "sensor not reporting"
	ReasonSensorStale          string // "sensor report is stale"
	ReasonEvidenceInvalid      string // "evidence invalid"
	ReasonIsolationFailed      string // "sensor isolation failed"
	ReasonPermissionDenied     string // "permission denied"
	ReasonInitializing         string // "index not built yet"
	ReasonStalled              string // "worker stalled"
	ReasonParseFailed          string // "package database parse failed"
	ReasonTruncated            string // "evidence truncated"
	ReasonIncomplete           string // "evidence incomplete"
	ReasonGenerationUnverified string // "container generation unverified"
	ReasonContainerNotObserved string // "container not observed"
	ReasonDBAbsent             string // "package database absent"
	ReasonDBError              string // "package database error"
	ReasonDBUnsupported        string // "package database unsupported"
	ReasonNoFileList           string // "no file list for this package"
	ReasonAttributionAmbiguous string // "multiple owners"
	ReasonFileReplaced         string // "file replaced"
	ReasonVersionMismatch      string // "version mismatch"
	ReasonEcosystemUnmapped    string // "ecosystem not mapped"
	ReasonBinaryPathUnknown    string // "binary path unknown"
	ReasonUnknown              string // "unknown" (reasonText's own default branch)

	// --- eBPF events-unavailable reason text ---
	EventsReasonKernelUnsupported string // "kernel unsupported"
	EventsReasonBTFMissing        string // "BTF missing"
	EventsReasonPermission        string // "permission denied"
	EventsReasonAttachFailed      string // "attach failed"
	EventsReasonCgroupV1          string // "cgroup v1"
	EventsReasonUnknown           string // "unknown" (eventsReasonText's own default branch)

	// --- in-use evidence phrasing ---
	KindRunningAs        string // "running as" (+ escaped executable path)
	KindLoadedBy         string // "loaded by" (+ escaped executable path)
	KindExecutedEvt      string // "executed" (+ escaped executable path)
	KindLibraryLoadEvent string // "library loaded" (+ escaped executable path)
	KindBinaryRunning    string // "in running binary" (+ escaped executable path)
	KindBinaryExecuted   string // "binary executed" (+ escaped executable path)
	KindRuntimeRunning   string // "runtime is running" (+ escaped executable path)
	KindRuntimeExecuted  string // "runtime executed" (+ escaped executable path)
	RuntimeInUseFallback string // "in use" — the shared, normally-unreachable fallback word for an unrecognized evidence kind, an evidence-kind-less in-use container, and the unattributed phrase's own fallback
	InUsePrefix          string // "▶ in use (%s)" (evidence kind phrase) — the act-now/thread full line
	InUseFallbackArrow   string // "▶ in use" — representativeContainer's own not-reached fallback
	HighPrivilegeNote    string // "runs with elevated privilege"
	LastConfirmedPrefix  string // "last confirmed %s" (formatted timestamp)

	// --- unattributed evidence phrasing ---
	UnattrRunning             string // "running"
	UnattrLoadedAsLibrary     string // "loaded as a library"
	UnattrExecuted            string // "executed"
	UnattrLibraryLoadObserved string // "library load observed"
	ProcessesPrefix           string // "processes: %s" (comma-joined executable names)

	// --- compact watch-bucket wording ---
	ShortWordRunning  string // "running"
	ShortWordLoaded   string // "loaded"
	ShortWordExecuted string // "executed" (runtimeShortWord's own default branch)

	// --- exposure phrasing ---
	ExposurePublishedAll      string // "published on all interfaces"
	ExposurePublishedLoopback string // "published on loopback only"
	ExposureListening         string // "listening (not published)"

	// --- muting ---
	UnmutedNowInUse                string // "now in use"
	UnmutedActNow                  string // "act now"
	UnmutedFixAvailable            string // "fix available"
	UnmutedNowEndOfLife            string // "now end-of-life"
	UnmutedInsufficientObservation string // "insufficient observation"
	UnmutedNotEligible             string // "not an eligible status"
	RuntimeSummaryCounts           string // "\n🔎 Runtime: ▶ %[1]d in use · %[2]d not observed · %[3]d unavailable\n"
	RuntimeSummaryNote             string // "_In use: an OS package is executed or loaded by a running program; a language package is in a running binary or its runtime (python, node, java, …) is running. Not observed covers the observation window only and does not mean unused._\n"

	// --- thread per-package runtime line ---
	ThreadNotObserved        string // "▷ not observed"
	ThreadRuntimeUnavailable string // "▷ runtime evidence unavailable (%s)" (reason text)

	// --- Slack Web API delivery ---
	// These two lines close the first channel message as its footer: the
	// pointer at the thread, or the link to the last posted one.
	ThreadPostedNotice string // "\n_📊 Everything open now is in this message's thread ↓_\n"
	LastReportLink     string // "\n🔗 Everything open as of the last report → <%s|thread>\n" (permalink URL; the link label "thread" is part of this string)

	// --- Block Kit cards ---
	// Labels are bare words: the renderer adds the ": " separator and the
	// surrounding mrkdwn.
	LblImage        string // "Image"
	LblInstalled    string // "Installed"
	LblFixed        string // "Fixed in"
	LblFixedNone    string // "none" (value of the fixed-in line when no fix exists)
	LblUpgradeRisk  string // "Upgrade risk"
	LblFindings     string // "Findings"
	LblTopCVE       string // "Top CVE"
	LblExploitation string // "Exploitation"
	LblSummary      string // "Summary"
	LblReferences   string // "References"
	LblOtherCVEs    string // "Other CVEs"
	LblRuntime      string // "Runtime"
	LblEvidence     string // "Evidence"
	LblExposure     string // "Exposure"
	LblPrivilege    string // "Privilege"
	LblLastSeen     string // "Last seen"
	LblChange       string // "Change"
	LblDetails      string // "Details"
	LblStatus       string // "Status"
	LblAction       string // "Action"

	// Upgrade-risk values, without the leading "upgrade:" the RiskXxx labels carry.
	RiskValueDistroUpdate string // "🟢 distro security patch"
	RiskValueSafe         string // "🟢 low-risk"
	RiskValueCaution      string // "🟠 major version bump — needs care"
	RiskValueUnknown      string // "⚪ risk unknown"

	// What to do when there is no fix, shown after the fixed-in "none".
	FixNoteMitigate   string // "consider mitigation"
	FixNoteWontFix    string // "no fix planned for this OS release, consider replacing"
	FixNoteEOL        string // "end-of-life: no fix planned for this release, consider a supported version"
	FixNoteEOLRuntime string // the same as EOLRuntimeText, for a language runtime itself

	CardNewCVEs      string // "new CVEs: %s" (linked CVE ids)
	CardKEVShort     string // "CISA KEV"
	CardSeeActNow    string // "🚨 see Act now"
	CardEOSLStatus   string // "base OS is EOL (no more security updates coming)"
	CardFoldedEOL    string // "includes %d end-of-life package(s)"
	CardNewEOSLNote  string // "includes %d newly end-of-life package(s)"
	CardBaseEOL      string // "base OS already EOL"
	CardCollapsed    string // "+%[1]d lower-risk fixes (%[2]s): %[3]s" (count, severity summary, comma-joined names)
	CardCounts       string // "CRITICAL %[1]d / HIGH %[2]d"
	CardBaseWait     string // value of the action line: %[1]s base image name, %[2]s its tag
	CardAgeLine      string // "⏱ open %[1]d day(s) · first seen %[2]s" (days, formatted date)
	CardAgeToday     string // "⏱ first seen today"
	ChannelContinued string // " _(cont. %[1]d/%[2]d)_" (message number, total) appended to the channel header of a continuation message

	// Fallback text (the notification preview / screen-reader text).
	FbFull               string // "KestreLynx %[1]s %[2]s — %[3]s" (generated-at, role, joined segments)
	FbPlain              string // "KestreLynx %[1]s %[2]s" (generated-at, role)
	FbContinued          string // "KestreLynx %[1]s %[2]s (cont. %[3]d/%[4]d)" (generated-at, role, number, total)
	FbRoleEverythingOpen string // "Everything currently open" (the role phrase of the fallback text, without the role line's period)
	FbRoleChanges        string // "Changes since the last scan"
	FbRoleNoChanges      string // "No changes since last scan"
	FbRoleWeekly         string // "📋 Weekly full report — everything currently open"
	FbSegNew             string // "🆕 %d new"
	FbSegResolved        string // "✅ %d resolved"
	FbSegScanFailed      string // "⚠️ %d scan failure(s)"
	FbSegEOLNew          string // "⛔ %d new EOL"
	FbSegReplaced        string // "🔄 %d image(s) updated"
	FbSegRefChanged      string // "🔄 %d reference update(s)"
	FbSegActionable      string // "✅ %d fixable"
	FbSegNoFix           string // "ℹ️ %d no fix yet"
	FbSegWontFix         string // "🔕 %d with no fix planned for this OS release"
	FbThread             string // "%[1]s — %[2]s · %[3]s" (role, short section name, first image)
	FbThreadCont         string // " (cont.)"
	FbThreadMoreImage    string // " +%d more image(s)"
	FbThreadPackages     string // " (%d package(s))"
	ShortEOLBase         string // "⛔ EOL base"
	ShortEOLPackage      string // "⛔ EOL packages"

	// --- fix plan ---
	// The fix plan is a message of its own: a heading, one summary line and,
	// per image, the files that are changed or proposed to change.
	PlanHeading          string // "*🔧 Fix plan*"
	PlanNothing          string // "No updates to propose."
	PlanNotSaved         string // "_The fix plan could not be saved._"
	PlanUnavailableDB    string // "_Fix plan unavailable this cycle: the scan databases could not be prepared._"
	PlanUnavailableOther string // "_Fix plan unavailable this cycle._"
	PlanFallback         string // "KestreLynx %[1]s fix plan — %[2]s" (generated-at time, summary)
	PlanFallbackCont     string // "KestreLynx %[1]s fix plan (%[2]d/%[3]d)"

	// Summary lines: the pull requests by status, or without any, the
	// proposals by kind.
	PlanPRCounts         string // "Pull requests: %s" (the joined segments)
	PlanPRSegCreated     string // "%d created" (opened in this cycle)
	PlanPRSegOpen        string // "%d open"
	PlanPRSegMerged      string // "%d merged"
	PlanPRSegClosed      string // "%d closed without merging"
	PlanPRSegManual      string // "%d need a decision"
	PlanPRSegDeferred    string // "%d deferred"
	PlanPRSegBlocked     string // "%d blocked or failed"
	PlanCounts           string // "%s" (the joined segments)
	PlanSegCandidate     string // "%d update candidate(s)"
	PlanSegRepull        string // "%d re-pull"
	PlanSegRebuild       string // "%d rebuild"
	PlanSegDecide        string // "%d need a decision"
	PlanSegNotComparable string // "%d not comparable"
	PlanSegFailed        string // "%d failed"
	PlanSegDeferred      string // "%d deferred"

	// Labels of the lines of an item.
	PlanLblService       string // "Service"
	PlanLblFile          string // "File to change"
	PlanLblPR            string // "Pull request"
	PlanLblUpdate        string // "Update"
	PlanLblCandidate     string // "Update candidate"
	PlanLblRepull        string // "Re-pull"
	PlanLblRebuild       string // "Rebuild"
	PlanLblDecide        string // "Needs a decision"
	PlanLblNotComparable string // "Not comparable"
	PlanLblFailed        string // "Failed"
	PlanLblDeferred      string // "Deferred"
	PlanLblMajor         string // "⚠️ Major version change"
	PlanLblPullPolicy    string // "Pull policy"
	PlanLblManagedBy     string // "Managed by (from markers)"

	// Values.
	PlanPullRestart              string // "restarting the Pods pulls the new content"
	PlanPullChangeTag            string // "nodes keep the image they have, so a restart does not help; a fixed tag or a digest is needed"
	PlanPullImportToNode         string // "the image has to be brought to the node"
	PlanPullValue                string // "%[1]s: %[2]s (%[3]s)" (policy, guidance, workloads)
	PlanOwnerHelm                string // "Helm release %[1]s (%[2]s)" (name, namespace)
	PlanOwnerArgoCD              string // "Argo CD app %s"
	PlanOwnerFluxKust            string // "Flux Kustomization %[2]s/%[1]s" (name, namespace)
	PlanOwnerFluxHelm            string // "Flux HelmRelease %[2]s/%[1]s" (name, namespace)
	PlanManagedValue             string // "%[1]s: %[2]s" (workload, chain), when several workloads are shown
	PlanFileValue                string // "%[2]s in %[1]s" (repository, path)
	PlanPRValue                  string // "%[1]s (%[2]s)" (link, status)
	PlanPRStatusCreated          string // "opened now"
	PlanPRStatusOpen             string // "open"
	PlanPRStatusMerged           string // "merged"
	PlanPRStatusClosed           string // "closed without merging"
	PlanChange                   string // "%[1]s %[2]s → %[3]s" (name, old version, new version)
	PlanBaseImageValue           string // "base image %[1]s %[2]s → %[3]s" (image, old tag, new tag)
	PlanListSep                  string // ", " (between the items of a value)
	PlanMore                     string // " and %d more" (after a list cut at ten)
	PlanMajorZero                string // "%s (0.x minor change)" (a package change)
	PlanMajorEdit                string // "%[1]s specifier %[2]s → %[3]s (%[4]s)" (package, old, new, file)
	PlanResolves                 string // "resolves %d finding(s)"
	PlanResolvesPartial          string // "resolves %[1]d of %[2]d findings" (resolved, targeted)
	PlanKEVClause                string // "%d KEV"
	PlanUndetectedClause         string // "%d not detected on the running image"
	PlanClauseJoin               string // ", " (between the clauses)
	PlanClauseWrap               string // " (%s)" (around the joined clauses)
	PlanPackageReason            string // "%[1]s %[2]s → %[3]s: %[4]s%[5]s" (name, installed, target, reason, the lockfile note)
	PlanLockfileUnchanged        string // " (the lockfile did not change)"
	PlanLeftOut                  string // "%[1]s %[2]s → %[3]s left out because %[4]s" (name, old, target, reason)
	PlanChangeWith               string // "%[1]s %[2]s → %[3]s (with %[4]s)" (name, old, new, the direct dependencies updated with it)
	PlanChainNotFixed            string // "%[1]s %[2]s → %[3]s: re-resolving %[4]s ... did not reach the fixed version this time" (name, installed, target, the direct dependencies)
	PlanChainRejected            string // "%[1]s %[2]s → %[3]s needs %[4]s updated as well, and that update was not adopted because %[5]s" (..., why)
	PlanChainHeld                string // "%[1]s %[2]s → %[3]s is held back by %[4]s, and updating %[4]s was not tried because %[5]s" (..., why)
	PlanChainWaiting             string // "... a version it brings in is less than 72 hours old, so it is tried again after %[5]s" (..., the time)
	PlanNotUpdated               string // "%[1]s could not be raised to %[2]s, which fixes the vulnerability, and stays at %[3]s in %[4]s (...)" (name, target, installed, lockfile)
	PlanNotInFile                string // "packages that are not in %s (...)" (lockfile)
	PlanWrongVersion             string // "packages whose version in the image differs from %s (...)" (lockfile)
	PlanBulletVersions           string // "  • %[1]s: the image has %[2]s, %[3]s has %[4]s" (name, image version, lockfile, lockfile versions)
	PlanBullet                   string // "  • %[1]s %[2]s" (name, installed)
	PlanRebuildValue             string // "%[1]s %[2]s: a rebuild is expected to pick up %[3]s or later" (name, installed, lowest fixed version)
	PlanDockerfileRebuild        string // "which base the running image was built from cannot be confirmed; rebuilding with `docker compose build --pull` picks up the current base"
	PlanDockerfileRebuildMapping string // the same for an image built outside Compose: pull the base again, rebuild and deploy again
	PlanDockerfileRebuildMixed   string // the same for a Dockerfile shared by Compose services and containers started with docker run
	PlanRebuildRuntime           string // "%[1]s has %[2]s %[3]s now; ... %[5]d of the %[6]d findings of %[2]s %[4]s are expected to disappear ..." (base ref, runtime, base version, installed version, disappearing, total)
	PlanRuntimeEOL               string // "%[1]s reached the end of its support on %[2]s; upgrade the runtime before updating" (runtime name, date)
	PlanRuntimeEOLNoDate         string // the same for a runtime the table has no date for (runtime name)

	// Conditions that stop pull request writes.
	PlanPRProblemLine       string // "⚠️ Pull request writes are stopped: %s" (the joined reasons)
	PlanPRProblemJoin       string // "; " (between the reasons)
	PlanPRProblemBlocked    string // "a repository, branch or pull request is not in the expected state"
	PlanPRProblemStorage    string // "the pull request records could not be saved"
	PlanPRProblemFull       string // "the operation log is full"
	PlanPRProblemUnverified string // "existing pull requests could not be verified"
}

// enMessages is the historical English wording, unchanged byte-for-byte from
// what this package printed before the language dictionary existed. Every
// golden test in testdata/golden pins this text; do not edit a value here
// without regenerating every affected golden file and checking each one by
// eye.
var enMessages = messages{
	Lang:                       LanguageEN,
	HeaderNamed:                "🛡️ *KestreLynx* [%[1]s] — scan results for %[2]s\n",
	HeaderDefault:              "🛡️ *KestreLynx* — scan results for %s\n",
	RoleEverythingOpen:         "Everything currently open.",
	RoleChangesSinceLastScan:   "Changes since the last scan.",
	ImagesScannedAffected:      "%[1]d images scanned, %[2]d affected\n",
	AllClear:                   "\n✅ All clear (no HIGH/CRITICAL vulnerabilities found)\n",
	LowerRiskSummarizedWebhook: "\n_%d lower-risk fix(es) summarized — full list in the generic webhook payload._\n",
	LowerRiskSummarized:        "\n_%d lower-risk fix(es) summarized._\n",

	NoChangesSinceLastScan:  "\nNo changes since last scan.\n",
	HeadingNewEOSL:          "\n*⛔ New: base OS end-of-life (top priority)*\n",
	WeeklyFullReportHeading: "\n*📋 Weekly full report — everything currently open*\n",

	ReplacedHeading: "\n*🔄 Image content changed (%d)*\n",
	ReplacedLine:    "• %[1]s: image updated (%[2]s → %[3]s)\n",

	RefChangeLine: "🔄 Image reference updated: %[1]s %[2]s → %[3]s (history carried over)\n",

	IdentityUnconfirmed:  "identity unconfirmed: scanned by reference",
	UnresolvedRefsLine:   "⚠️ %[1]s — %[2]s\n",
	UnconfirmedRefsLine:  "⏳ unconfirmed this cycle, holding previous findings — %s\n",
	RuntimeUncheckedLine: "ℹ️ Advisories for %[1]s could not be fetched, so the runtime of %[2]d image(s) was not checked.\n",
	RuntimeNameSeparator: ", ",

	NewSinceLastScanHeading: "\n*🆕 New since last scan (%d)*\n",
	MoreCount:               " (+%d more)",
	EscalatedTo:             "⬆️ escalated to %s",
	FixNowAvailable:         "fix now available",
	Unmuted:                 "↩️ Unmuted (%s)",

	ResolvedHeading:       "\n*✅ Resolved since last scan (%d)*\n",
	BaseOSNoLongerEOL:     "• %s — base OS no longer EOL\n",
	ResolvedImagePackages: "• %[1]s: %[2]s\n",
	NoLongerEndOfLife:     "• %[1]s: %[2]s — no longer end-of-life\n",

	OpenNowUnconfirmedHolding: "\n📌 Open now: unconfirmed — holding previous findings until re-confirmed\n",
	OpenNowNotRescanned:       "\n📌 Open now: not re-scanned — holding previous findings until the next successful scan\n",
	OpenNowAllClear:           "\n🎉 Open now: none — all clear\n",
	OpenNowCriticalHigh:       "CRITICAL %[1]d / HIGH %[2]d%[4]s across %[3]d image(s)",
	OpenNowSevExtra:           " / %[1]s %[2]d",
	OpenNowPrefix:             "\n📌 Open now: %s",
	OldestUnresolvedStale:     " — ⏰ oldest unresolved %d day(s)",
	OldestUnresolved:          " — oldest unresolved %d day(s)",
	DetailsInWebhook:          "_Details in the generic webhook payload._\n",

	SegEOLBase:    "⛔ %d EOL base",
	SegEOLPackage: "⛔ %d EOL package",
	SegCritical:   "🔴 %d CRITICAL",
	SegNeedCare:   "🟠 %d need care",
	SegSafe:       "🟢 %d safe",
	SegWatch:      "👀 %d watch",
	SegLow:        "🔕 %d low",
	PriorityLine:  "*Priority:* %s\n",

	ScanFailuresHeading: "\n*⚠️ Scan failures*\n",
	ScanFailureLine:     "• %[1]s — %[2]s\n",

	ActionableTitle:     "✅ Actionable now (fixed)",
	WatchSectionTitle:   "ℹ️ No fix yet (affected / waiting on upstream)",
	WontFixSectionTitle: "🔕 No fix planned for this OS release (will_not_fix)",

	RiskDistroUpdate: "🟢 upgrade: distro security patch",
	RiskSafe:         "🟢 upgrade: low-risk",
	RiskCaution:      "🟠 upgrade: major version bump — needs care",
	RiskUnknown:      "⚪ upgrade: risk unknown",

	EOLPackageText:   "end-of-life: no fix planned for this release",
	EOLRuntimeText:   "end-of-life: no fix will be released for this series, so the series has to be upgraded (manual)",
	EOLSectionReason: "vendor reports these CVEs as out of support for this release",

	SegActNow:            "🚨 %d act now",
	IntelDegradedWarning: "⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low\n",
	IntelKEVUnavailable:  "⚠️ CISA KEV data unavailable — act-now detection may be incomplete\n",
	IntelEPSSUnavailable: "⚠️ EPSS data unavailable — triage is using KEV and severity only\n",
	IntelStale:           "\n_Intel data is %d day(s) old (feeds unreachable)._\n",

	ActNowHeading:       "\n*🚨 Act now (%d) — exploited or likely to be*\n",
	WatchHeading:        "\n*👀 Watch (%d) — not urgent, keep an eye on*\n",
	LowHeading:          "\n*🔕 Low priority (%[1]d)* — %[2]d finding(s) across %[3]d image(s), no exploitation signal (not in KEV, EPSS below threshold).",
	TriageLowInUseCount: " · ▶ %d in use",

	EvidenceMoreCVEs:        " (+%d more CVE(s) in this package)",
	AdvisoryLinkLabel:       "advisory",
	VendorAdvisoryLinkLabel: "vendor advisory",
	EvidenceSeverityOnly:    "severity only (intel unavailable)",
	EvidenceKEV:             "CISA KEV (exploited in the wild)",
	EvidenceEPSSPrefix:      "EPSS %s",
	EvidenceRansomware:      "🧨 ransomware campaign",

	OpenNowActNow:          "🚨 %d act-now",
	OldestActNowWatchStale: " — ⏰ oldest act-now/watch unresolved %d day(s)",
	OldestActNowWatch:      " — oldest act-now/watch unresolved %d day(s)",
	PriorityLabelActNow:    "ACT NOW",
	PriorityLabelWatch:     "WATCH",
	PriorityLabelLow:       "LOW",

	EOSLHeading:               "\n*⛔ Base OS end-of-life (top priority)*\n",
	EOLPackageHeading:         "\n*⛔ Package end-of-life (%[1]d) — %[2]s*\n",
	EOLPackagesChangedHeading: "\n*⛔ New: package end-of-life (%[1]d) — %[2]s*\n",
	EOLFoldNewPackages:        "%d package(s) newly end-of-life",
	EOLFoldWithNewCVEs:        "%d end-of-life package(s) with new CVEs",

	ThreadTitle:              "📊 *Everything open now — %s*",
	EOLBaseImagesHeading:     "*⛔ EOL base images (%d)*",
	MutedLine:                "🔇 Muted — no fix available and not in use for 7+ days: %d\n",
	ThreadActNowHeading:      "*🚨 ACT NOW (%d) — exploited or likely to be*",
	ThreadWatchHeading:       "*👀 WATCH (%d) — not urgent, keep an eye on*",
	ThreadLowHeading:         "\n*🔕 LOW (%d)* — no exploitation signal",
	ThreadLowDetailsSuffix:   "; details in the generic webhook payload",
	ThreadLowInUseCount:      "▶ in use among low: %d\n",
	EOLPackagesThreadHeading: "*⛔ EOL packages (%[1]d) — %[2]s*",
	ThreadContinued:          " _(cont.)_",

	RuntimeWarningUnavailable:       "⚠️ Runtime evidence unavailable: %s\n",
	RuntimeWarningEventsUnavailable: "⚠️ Short-lived programs are not observed (eBPF unavailable: %s); using sampling only\n",

	StatusTextNotReporting:      "the Sensor has not reported yet",
	StatusTextEvidenceInvalid:   "the evidence file failed validation",
	StatusTextStale:             "the Sensor's last report is stale",
	StatusTextPermissionDenied:  "the Sensor's reads are being denied",
	StatusTextIsolationFailed:   "the Sensor's sandbox failed to start",
	StatusTextIsolationDegraded: "the Sensor's sandbox is running degraded",
	StatusTextDegraded:          "the Sensor is degraded",
	StatusTextOK:                "ok",
	StatusTextUnknown:           "unknown",

	ReasonSensorNotReporting:   "sensor not reporting",
	ReasonSensorStale:          "sensor report is stale",
	ReasonEvidenceInvalid:      "evidence invalid",
	ReasonIsolationFailed:      "sensor isolation failed",
	ReasonPermissionDenied:     "permission denied",
	ReasonInitializing:         "index not built yet",
	ReasonStalled:              "worker stalled",
	ReasonParseFailed:          "package database parse failed",
	ReasonTruncated:            "evidence truncated",
	ReasonIncomplete:           "evidence incomplete",
	ReasonGenerationUnverified: "container generation unverified",
	ReasonContainerNotObserved: "container not observed",
	ReasonDBAbsent:             "package database absent",
	ReasonDBError:              "package database error",
	ReasonDBUnsupported:        "package database unsupported",
	ReasonNoFileList:           "no file list for this package",
	ReasonAttributionAmbiguous: "multiple owners",
	ReasonFileReplaced:         "file replaced",
	ReasonVersionMismatch:      "version mismatch",
	ReasonEcosystemUnmapped:    "ecosystem not mapped",
	ReasonBinaryPathUnknown:    "binary path unknown",
	ReasonUnknown:              "unknown",

	EventsReasonKernelUnsupported: "kernel unsupported",
	EventsReasonBTFMissing:        "BTF missing",
	EventsReasonPermission:        "permission denied",
	EventsReasonAttachFailed:      "attach failed",
	EventsReasonCgroupV1:          "cgroup v1",
	EventsReasonUnknown:           "unknown",

	KindRunningAs:        "running as",
	KindLoadedBy:         "loaded by",
	KindExecutedEvt:      "executed",
	KindLibraryLoadEvent: "library loaded",
	KindBinaryRunning:    "in running binary",
	KindBinaryExecuted:   "binary executed",
	KindRuntimeRunning:   "runtime is running",
	KindRuntimeExecuted:  "runtime executed",
	RuntimeInUseFallback: "in use",
	InUsePrefix:          "▶ in use (%s)",
	InUseFallbackArrow:   "▶ in use",
	HighPrivilegeNote:    "runs with elevated privilege",
	LastConfirmedPrefix:  "last confirmed %s",

	UnattrRunning:             "running",
	UnattrLoadedAsLibrary:     "loaded as a library",
	UnattrExecuted:            "executed",
	UnattrLibraryLoadObserved: "library load observed",
	ProcessesPrefix:           "processes: %s",

	ShortWordRunning:  "running",
	ShortWordLoaded:   "loaded",
	ShortWordExecuted: "executed",

	ExposurePublishedAll:      "published on all interfaces",
	ExposurePublishedLoopback: "published on loopback only",
	ExposureListening:         "listening (not published)",

	UnmutedNowInUse:                "now in use",
	UnmutedActNow:                  "act now",
	UnmutedFixAvailable:            "fix available",
	UnmutedNowEndOfLife:            "now end-of-life",
	UnmutedInsufficientObservation: "insufficient observation",
	UnmutedNotEligible:             "not an eligible status",
	RuntimeSummaryCounts:           "\n🔎 Runtime: ▶ %[1]d in use · %[2]d not observed · %[3]d unavailable\n",
	RuntimeSummaryNote:             "_In use: an OS package is executed or loaded by a running program; a language package is in a running binary or its runtime (python, node, java, …) is running. Not observed covers the observation window only and does not mean unused._\n",

	ThreadNotObserved:        "▷ not observed",
	ThreadRuntimeUnavailable: "▷ runtime evidence unavailable (%s)",

	ThreadPostedNotice: "\n_📊 Everything open now is in this message's thread ↓_\n",
	LastReportLink:     "\n🔗 Everything open as of the last report → <%s|thread>\n",

	LblImage:        "Image",
	LblInstalled:    "Installed",
	LblFixed:        "Fixed in",
	LblFixedNone:    "none",
	LblUpgradeRisk:  "Upgrade risk",
	LblFindings:     "Findings",
	LblTopCVE:       "Top CVE",
	LblExploitation: "Exploitation",
	LblSummary:      "Summary",
	LblReferences:   "References",
	LblOtherCVEs:    "Other CVEs",
	LblRuntime:      "Runtime",
	LblEvidence:     "Evidence",
	LblExposure:     "Exposure",
	LblPrivilege:    "Privilege",
	LblLastSeen:     "Last seen",
	LblChange:       "Change",
	LblDetails:      "Details",
	LblStatus:       "Status",
	LblAction:       "Action",

	RiskValueDistroUpdate: "🟢 distro security patch",
	RiskValueSafe:         "🟢 low-risk",
	RiskValueCaution:      "🟠 major version bump — needs care",
	RiskValueUnknown:      "⚪ risk unknown",

	FixNoteMitigate:   "consider mitigation",
	FixNoteWontFix:    "no fix planned for this OS release, consider replacing",
	FixNoteEOL:        "end-of-life: no fix planned for this release, consider a supported version",
	FixNoteEOLRuntime: "end-of-life: no fix will be released for this series, so the series has to be upgraded (manual)",

	CardNewCVEs:      "new CVEs: %s",
	CardKEVShort:     "CISA KEV",
	CardSeeActNow:    "🚨 see Act now",
	CardEOSLStatus:   "base OS is EOL (no more security updates coming)",
	CardFoldedEOL:    "includes %d end-of-life package(s)",
	CardNewEOSLNote:  "includes %d newly end-of-life package(s)",
	CardBaseEOL:      "base OS already EOL",
	CardCollapsed:    "+%[1]d lower-risk fixes (%[2]s): %[3]s",
	CardCounts:       "CRITICAL %[1]d / HIGH %[2]d",
	CardBaseWait:     "waiting for a newer base image of %[1]s %[2]s (no newer tag in the same series)",
	CardAgeLine:      "⏱ open %[1]d day(s) · first seen %[2]s",
	CardAgeToday:     "⏱ first seen today",
	ChannelContinued: " _(cont. %[1]d/%[2]d)_",

	FbFull:               "KestreLynx %[1]s %[2]s — %[3]s",
	FbPlain:              "KestreLynx %[1]s %[2]s",
	FbContinued:          "KestreLynx %[1]s %[2]s (cont. %[3]d/%[4]d)",
	FbRoleEverythingOpen: "Everything currently open",
	FbRoleChanges:        "Changes since the last scan",
	FbRoleNoChanges:      "No changes since last scan",
	FbRoleWeekly:         "📋 Weekly full report — everything currently open",
	FbSegNew:             "🆕 %d new",
	FbSegResolved:        "✅ %d resolved",
	FbSegScanFailed:      "⚠️ %d scan failure(s)",
	FbSegEOLNew:          "⛔ %d new EOL",
	FbSegReplaced:        "🔄 %d image(s) updated",
	FbSegRefChanged:      "🔄 %d reference update(s)",
	FbSegActionable:      "✅ %d fixable",
	FbSegNoFix:           "ℹ️ %d no fix yet",
	FbSegWontFix:         "🔕 %d with no fix planned for this OS release",
	FbThread:             "%[1]s — %[2]s · %[3]s",
	FbThreadCont:         " (cont.)",
	FbThreadMoreImage:    " +%d more image(s)",
	FbThreadPackages:     " (%d package(s))",
	ShortEOLBase:         "⛔ EOL base",
	ShortEOLPackage:      "⛔ EOL packages",

	PlanHeading:          "*🔧 Fix plan*",
	PlanNothing:          "No updates to propose.",
	PlanNotSaved:         "_The fix plan could not be saved._",
	PlanUnavailableDB:    "_Fix plan unavailable this cycle: the scan databases could not be prepared._",
	PlanUnavailableOther: "_Fix plan unavailable this cycle._",
	PlanFallback:         "KestreLynx %[1]s fix plan — %[2]s",
	PlanFallbackCont:     "KestreLynx %[1]s fix plan (%[2]d/%[3]d)",

	PlanPRCounts:         "Pull requests: %s",
	PlanPRSegCreated:     "%d created",
	PlanPRSegOpen:        "%d open",
	PlanPRSegMerged:      "%d merged",
	PlanPRSegClosed:      "%d closed without merging",
	PlanPRSegManual:      "%d need a decision",
	PlanPRSegDeferred:    "%d deferred",
	PlanPRSegBlocked:     "%d blocked or failed",
	PlanCounts:           "%s",
	PlanSegCandidate:     "%d update candidate(s)",
	PlanSegRepull:        "%d re-pull",
	PlanSegRebuild:       "%d rebuild",
	PlanSegDecide:        "%d need a decision",
	PlanSegNotComparable: "%d not comparable",
	PlanSegFailed:        "%d failed",
	PlanSegDeferred:      "%d deferred",

	PlanLblService:       "Service",
	PlanLblFile:          "File to change",
	PlanLblPR:            "Pull request",
	PlanLblUpdate:        "Update",
	PlanLblCandidate:     "Update candidate",
	PlanLblRepull:        "Re-pull",
	PlanLblRebuild:       "Rebuild",
	PlanLblDecide:        "Needs a decision",
	PlanLblNotComparable: "Not comparable",
	PlanLblFailed:        "Failed",
	PlanLblDeferred:      "Deferred",
	PlanLblMajor:         "⚠️ Major version change",
	PlanLblPullPolicy:    "Pull policy",
	PlanLblManagedBy:     "Managed by (from markers)",

	PlanPullRestart:              "restarting the Pods pulls the new content",
	PlanPullChangeTag:            "nodes keep the image they have, so a restart does not help; a fixed tag or a digest is needed",
	PlanPullImportToNode:         "the image has to be brought to the node",
	PlanPullValue:                "%[1]s: %[2]s (%[3]s)",
	PlanOwnerHelm:                "Helm release %[1]s (%[2]s)",
	PlanOwnerArgoCD:              "Argo CD app %s",
	PlanOwnerFluxKust:            "Flux Kustomization %[2]s/%[1]s",
	PlanOwnerFluxHelm:            "Flux HelmRelease %[2]s/%[1]s",
	PlanManagedValue:             "%[1]s: %[2]s",
	PlanFileValue:                "%[2]s in %[1]s",
	PlanPRValue:                  "%[1]s (%[2]s)",
	PlanPRStatusCreated:          "opened now",
	PlanPRStatusOpen:             "open",
	PlanPRStatusMerged:           "merged",
	PlanPRStatusClosed:           "closed without merging",
	PlanChange:                   "%[1]s %[2]s → %[3]s",
	PlanBaseImageValue:           "base image %[1]s %[2]s → %[3]s",
	PlanListSep:                  ", ",
	PlanMore:                     " and %d more",
	PlanMajorZero:                "%s (0.x minor change)",
	PlanMajorEdit:                "%[1]s specifier %[2]s → %[3]s (%[4]s)",
	PlanResolves:                 "resolves %d finding(s)",
	PlanResolvesPartial:          "resolves %[1]d of %[2]d findings",
	PlanKEVClause:                "%d KEV",
	PlanUndetectedClause:         "%d not detected on the running image",
	PlanClauseJoin:               ", ",
	PlanClauseWrap:               " (%s)",
	PlanPackageReason:            "%[1]s %[2]s → %[3]s: %[4]s%[5]s",
	PlanLockfileUnchanged:        " (the lockfile did not change)",
	PlanLeftOut:                  "%[1]s %[2]s → %[3]s left out because %[4]s",
	PlanChangeWith:               "%[1]s %[2]s → %[3]s (with %[4]s)",
	PlanChainNotFixed:            "%[1]s %[2]s → %[3]s: re-resolving %[4]s within the project's ranges did not reach the fixed version this time",
	PlanChainRejected:            "%[1]s %[2]s → %[3]s needs %[4]s updated as well, and that update was not adopted because %[5]s",
	PlanChainHeld:                "%[1]s %[2]s → %[3]s is held back by %[4]s, and updating %[4]s was not tried because %[5]s",
	PlanChainWaiting:             "%[1]s %[2]s → %[3]s needs %[4]s updated as well; a version it brings in is less than 72 hours old, so it is tried again after %[5]s",
	PlanNotUpdated:               "%[1]s could not be raised to %[2]s, which fixes the vulnerability, and stays at %[3]s in %[4]s (KestreLynx did not look into why it cannot be raised, so check the version ranges of the packages that depend on %[1]s)",
	PlanNotInFile:                "packages that are not in %s (they probably came into the image by a route other than the lockfile, so updating the lockfile cannot fix them)",
	PlanWrongVersion:             "packages whose version in the image differs from %s (the image may not have been built from the current %[1]s, so rebuild it and check again)",
	PlanBulletVersions:           "  • %[1]s: the image has %[2]s, %[3]s has %[4]s",
	PlanBullet:                   "  • %[1]s %[2]s",
	PlanRebuildValue:             "%[1]s %[2]s: a rebuild is expected to pick up %[3]s or later",
	PlanDockerfileRebuild:        "which base the running image was built from cannot be confirmed; rebuilding with `docker compose build --pull` picks up the current base",
	PlanDockerfileRebuildMapping: "which base the running image was built from cannot be confirmed; pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again",
	PlanDockerfileRebuildMixed:   "which base the running image was built from cannot be confirmed; rebuild with `docker compose build --pull` for the Compose services and with `docker build --pull` or the like for the `docker run` containers, then recreate the containers",
	PlanRebuildRuntime:           "%[2]s in the current %[1]s is %[3]s; if the rebuild takes over this version, %[5]d of the %[6]d findings of the detected %[2]s %[4]s are expected to disappear (the rebuilt image is not checked)",
	PlanRuntimeEOL:               "%[1]s reached the end of its support on %[2]s; upgrade the runtime before updating",
	PlanRuntimeEOLNoDate:         "%[1]s is past the end of its support; upgrade the runtime before updating",

	PlanPRProblemLine:       "⚠️ Pull request writes are stopped: %s",
	PlanPRProblemJoin:       "; ",
	PlanPRProblemBlocked:    "a repository, branch or pull request is not in the expected state",
	PlanPRProblemStorage:    "the pull request records could not be saved",
	PlanPRProblemFull:       "the operation log is full",
	PlanPRProblemUnverified: "existing pull requests could not be verified",
}

// jaMessages is the Japanese dictionary.
var jaMessages = messages{
	Lang:                       LanguageJA,
	HeaderNamed:                "🛡️ *KestreLynx* [%[1]s] — %[2]sのスキャン結果\n",
	HeaderDefault:              "🛡️ *KestreLynx* — %sのスキャン結果\n",
	RoleEverythingOpen:         "未解決の所見の全体",
	RoleChangesSinceLastScan:   "前回のスキャンからの変化",
	ImagesScannedAffected:      "イメージ%[1]d件をスキャン、%[2]d件に影響あり\n",
	AllClear:                   "\n✅ 問題なし (HIGH/CRITICALの脆弱性なし)\n",
	LowerRiskSummarizedWebhook: "\n_低リスクの修正%d件を集約 — 全件は汎用Webhookのペイロードに記載_\n",
	LowerRiskSummarized:        "\n_低リスクの修正%d件を集約_\n",

	NoChangesSinceLastScan:  "\n前回のスキャンから変化なし\n",
	HeadingNewEOSL:          "\n*⛔ 新規: ベースOSのサポート終了(EOL) (最優先)*\n",
	WeeklyFullReportHeading: "\n*📋 週次全体レポート — 未解決の所見の全体*\n",

	ReplacedHeading: "\n*🔄 イメージの内容が変化 (%d件)*\n",
	ReplacedLine:    "• %[1]s: イメージ更新 (%[2]s → %[3]s)\n",

	RefChangeLine: "🔄 イメージ参照の更新: %[1]s %[2]s → %[3]s(検出履歴を引き継ぎ)\n",

	IdentityUnconfirmed:  "実体未確認: 参照によるスキャン",
	UnresolvedRefsLine:   "⚠️ %[1]s — %[2]s\n",
	UnconfirmedRefsLine:  "⏳ 今回は未確認、前回の所見を保持 — %s\n",
	RuntimeUncheckedLine: "ℹ️ %[1]s の脆弱性情報を取得できなかったため、%[2]d 件のイメージの本体を照合していません。\n",
	RuntimeNameSeparator: "・",

	NewSinceLastScanHeading: "\n*🆕 前回のスキャンからの新規検出 (%d件)*\n",
	MoreCount:               " (ほか +%d件)",
	EscalatedTo:             "⬆️ %sに優先度昇格",
	FixNowAvailable:         "修正版が利用可能",
	Unmuted:                 "↩️ 通知を再開 (%s)",

	ResolvedHeading:       "\n*✅ 前回のスキャンからの解消 (%d件)*\n",
	BaseOSNoLongerEOL:     "• %s — ベースOSのEOLが解消\n",
	ResolvedImagePackages: "• %[1]s: %[2]s\n",
	NoLongerEndOfLife:     "• %[1]s: %[2]s — サポート終了(EOL)が解消\n",

	OpenNowUnconfirmedHolding: "\n📌 現在の未解決: 未確認 — 再確認まで前回の所見を保持\n",
	OpenNowNotRescanned:       "\n📌 現在の未解決: 未再スキャン — 次のスキャン成功まで前回の所見を保持\n",
	OpenNowAllClear:           "\n🎉 現在の未解決: なし — 問題なし\n",
	OpenNowCriticalHigh:       "CRITICAL %[1]d件 / HIGH %[2]d件%[4]s、イメージ%[3]d件",
	OpenNowSevExtra:           " / %[1]s %[2]d件",
	OpenNowPrefix:             "\n📌 現在の未解決: %s",
	OldestUnresolvedStale:     " — ⏰ 未解決の最長期間%d日",
	OldestUnresolved:          " — 未解決の最長期間%d日",
	DetailsInWebhook:          "_詳細は汎用Webhookのペイロードに記載_\n",

	SegEOLBase:    "⛔ EOLのベースOS%d件",
	SegEOLPackage: "⛔ EOLのパッケージ%d件",
	SegCritical:   "🔴 CRITICAL %d件",
	SegNeedCare:   "🟠 要注意%d件",
	SegSafe:       "🟢 安全%d件",
	SegWatch:      "👀 要監視%d件",
	SegLow:        "🔕 低優先度%d件",
	PriorityLine:  "*優先度:* %s\n",

	ScanFailuresHeading: "\n*⚠️ スキャン失敗*\n",
	ScanFailureLine:     "• %[1]s — %[2]s\n",

	ActionableTitle:     "✅ 今すぐ対応可能 (fixed)",
	WatchSectionTitle:   "ℹ️ 修正版なし (affected / 上流の対応待ち)",
	WontFixSectionTitle: "🔕 このOSリリースでは修正予定なし (will_not_fix)",

	RiskDistroUpdate: "🟢 アップグレード: ディストリのセキュリティパッチ",
	RiskSafe:         "🟢 アップグレード: 低リスク",
	RiskCaution:      "🟠 アップグレード: メジャーバージョン更新 — 要注意",
	RiskUnknown:      "⚪ アップグレード: リスク不明",

	EOLPackageText:   "サポート終了(EOL): このリリースでは修正予定なし",
	EOLRuntimeText:   "サポート終了(EOL): この系列には修正版が出ないため、系列を上げる必要がある(手動)",
	EOLSectionReason: "ベンダーがこれらのCVEをこのリリースのサポート対象外と報告",

	SegActNow:            "🚨 今すぐ対応%d件",
	IntelDegradedWarning: "⚠️ 脅威情報 (KEV/EPSS) が利用できない — 深刻度のみで優先度を判定、低優先度への引き下げなし\n",
	IntelKEVUnavailable:  "⚠️ CISA KEVデータが利用できない — 今すぐ対応の検出に漏れの可能性あり\n",
	IntelEPSSUnavailable: "⚠️ EPSSデータが利用できない — KEVと深刻度のみで優先度を判定\n",
	IntelStale:           "\n_脅威情報は%d日前のもの (配信元に接続できない)_\n",

	ActNowHeading:       "\n*🚨 今すぐ対応 (%d件) — 悪用あり、または悪用の可能性が高い*\n",
	WatchHeading:        "\n*👀 要監視 (%d件) — 緊急性は低いが継続監視*\n",
	LowHeading:          "\n*🔕 低優先度 (%[1]d件)* — イメージ%[3]d件で所見%[2]d件、悪用の兆候なし (KEV未掲載、EPSSはしきい値未満)",
	TriageLowInUseCount: " · ▶ 使用中%d件",

	EvidenceMoreCVEs:     " (このパッケージにほか +%d件のCVE)",
	AdvisoryLinkLabel:    "アドバイザリ",
	EvidenceSeverityOnly: "深刻度のみ (脅威情報が利用できない)",
	EvidenceKEV:          "CISA KEV (実際の攻撃で悪用あり)",
	EvidenceEPSSPrefix:   "EPSS %s",
	EvidenceRansomware:   "🧨 ランサムウェア攻撃",

	OpenNowActNow:          "🚨 今すぐ対応%d件",
	OldestActNowWatchStale: " — ⏰ 今すぐ対応/要監視の未解決の最長期間%d日",
	OldestActNowWatch:      " — 今すぐ対応/要監視の未解決の最長期間%d日",
	PriorityLabelActNow:    "今すぐ対応",
	PriorityLabelWatch:     "要監視",
	PriorityLabelLow:       "低優先度",

	EOSLHeading:               "\n*⛔ ベースOSのサポート終了(EOL) (最優先)*\n",
	EOLPackageHeading:         "\n*⛔ パッケージのサポート終了(EOL) (%[1]d件) — %[2]s*\n",
	EOLPackagesChangedHeading: "\n*⛔ 新規: パッケージのサポート終了(EOL) (%[1]d件) — %[2]s*\n",
	EOLFoldNewPackages:        "パッケージ%d件が新たにサポート終了(EOL)",
	EOLFoldWithNewCVEs:        "新規CVEのあるサポート終了(EOL)のパッケージ%d件",

	ThreadTitle:              "📊 *未解決の所見の全体 — %s*",
	EOLBaseImagesHeading:     "*⛔ EOLのベースOSのイメージ (%d件)*",
	MutedLine:                "🔇 通知オフ — 修正版がなく7日以上使用が確認されない: %d件\n",
	ThreadActNowHeading:      "*🚨 今すぐ対応 (%d件) — 悪用あり、または悪用の可能性が高い*",
	ThreadWatchHeading:       "*👀 要監視 (%d件) — 緊急性は低いが継続監視*",
	ThreadLowHeading:         "\n*🔕 低優先度 (%d件)* — 悪用の兆候なし",
	ThreadLowDetailsSuffix:   "; 詳細は汎用Webhookのペイロードに記載",
	ThreadLowInUseCount:      "▶ 低優先度のうち使用中: %d件\n",
	EOLPackagesThreadHeading: "*⛔ EOLのパッケージ (%[1]d件) — %[2]s*",
	ThreadContinued:          " _(続き)_",

	RuntimeWarningUnavailable:       "⚠️ 稼働時の証拠が利用できない: %s\n",
	RuntimeWarningEventsUnavailable: "⚠️ 短命なプログラムは観測できない (eBPFが利用できない: %s); サンプリングのみ使用\n",

	StatusTextNotReporting:      "Sensorからの報告がまだない",
	StatusTextEvidenceInvalid:   "証拠ファイルの検証失敗",
	StatusTextStale:             "Sensorの最終報告が古い",
	StatusTextPermissionDenied:  "Sensorの読み取りが拒否されている",
	StatusTextIsolationFailed:   "Sensorのサンドボックス起動失敗",
	StatusTextIsolationDegraded: "Sensorのサンドボックスが一部制限の効かない状態で稼働中",
	StatusTextDegraded:          "Sensorの一部機能が利用できない",
	StatusTextOK:                "正常",
	StatusTextUnknown:           "不明",

	ReasonSensorNotReporting:   "Sensorの報告なし",
	ReasonSensorStale:          "Sensorの報告が古い",
	ReasonEvidenceInvalid:      "証拠が無効",
	ReasonIsolationFailed:      "Sensorの隔離失敗",
	ReasonPermissionDenied:     "権限不足",
	ReasonInitializing:         "索引が未構築",
	ReasonStalled:              "ワーカーの処理が停滞",
	ReasonParseFailed:          "パッケージデータベースの解析失敗",
	ReasonTruncated:            "証拠の切り詰め",
	ReasonIncomplete:           "証拠が不完全",
	ReasonGenerationUnverified: "コンテナの世代が未確認",
	ReasonContainerNotObserved: "コンテナが未観測",
	ReasonDBAbsent:             "パッケージデータベースなし",
	ReasonDBError:              "パッケージデータベースのエラー",
	ReasonDBUnsupported:        "パッケージデータベースが未対応",
	ReasonNoFileList:           "このパッケージのファイル一覧なし",
	ReasonAttributionAmbiguous: "所有元が複数",
	ReasonFileReplaced:         "ファイルが置き換えられている",
	ReasonVersionMismatch:      "バージョン不一致",
	ReasonEcosystemUnmapped:    "エコシステムの対応付けなし",
	ReasonBinaryPathUnknown:    "バイナリのパス不明",
	ReasonUnknown:              "不明",

	EventsReasonKernelUnsupported: "カーネルが未対応",
	EventsReasonBTFMissing:        "BTFなし",
	EventsReasonPermission:        "権限不足",
	EventsReasonAttachFailed:      "アタッチ失敗",
	EventsReasonCgroupV1:          "cgroup v1",
	EventsReasonUnknown:           "不明",

	KindRunningAs:        "実行中:",
	KindLoadedBy:         "読み込んだプログラム:",
	KindExecutedEvt:      "実行を観測:",
	KindLibraryLoadEvent: "ライブラリ読み込みを観測:",
	KindBinaryRunning:    "組み込み先の実行中バイナリ:",
	KindBinaryExecuted:   "バイナリの実行を観測:",
	KindRuntimeRunning:   "稼働中の実行環境:",
	KindRuntimeExecuted:  "実行環境の実行を観測:",
	RuntimeInUseFallback: "使用中",
	InUsePrefix:          "▶ 使用中 (%s)",
	InUseFallbackArrow:   "▶ 使用中",
	HighPrivilegeNote:    "高い権限で実行",
	LastConfirmedPrefix:  "最終確認%s",

	UnattrRunning:             "実行中",
	UnattrLoadedAsLibrary:     "ライブラリとして読み込み済み",
	UnattrExecuted:            "実行を観測",
	UnattrLibraryLoadObserved: "ライブラリの読み込みを観測",
	ProcessesPrefix:           "プロセス: %s",

	ShortWordRunning:  "実行中",
	ShortWordLoaded:   "読み込み済み",
	ShortWordExecuted: "実行を観測",

	ExposurePublishedAll:      "全インターフェースに公開",
	ExposurePublishedLoopback: "ループバックのみに公開",
	ExposureListening:         "待ち受け中 (未公開)",

	UnmutedNowInUse:                "使用中になった",
	UnmutedActNow:                  "今すぐ対応",
	UnmutedFixAvailable:            "修正版あり",
	UnmutedNowEndOfLife:            "サポート終了(EOL)となった",
	UnmutedInsufficientObservation: "観測不足",
	UnmutedNotEligible:             "対象外の状態",
	RuntimeSummaryCounts:           "\n🔎 稼働時の使用状況: ▶ 使用中%[1]d件 · 使用が確認されない%[2]d件 · 判定できない%[3]d件\n",
	RuntimeSummaryNote:             "_使用中: OSパッケージは稼働中のプログラムが実行または読み込み。言語パッケージは稼働中のバイナリに含まれるか、その実行環境 (python, node, java, …) が稼働中。使用が確認されないとは観測期間内に限った状態であり、未使用を意味しない。_\n",

	ThreadNotObserved:        "▷ 使用が確認されない",
	ThreadRuntimeUnavailable: "▷ 稼働時の使用状況を判定できない (%s)",

	VendorAdvisoryLinkLabel: "ベンダーのアドバイザリ",

	ThreadPostedNotice: "\n_📊 未解決の所見の全体はこのメッセージのスレッド ↓_\n",
	LastReportLink:     "\n🔗 前回のレポート時点の未解決の所見の全体 → <%s|スレッド>\n",

	LblImage:        "イメージ",
	LblInstalled:    "現在",
	LblFixed:        "修正版",
	LblFixedNone:    "なし",
	LblUpgradeRisk:  "更新の注意度",
	LblFindings:     "検出件数",
	LblTopCVE:       "代表CVE",
	LblExploitation: "悪用情報",
	LblSummary:      "説明",
	LblReferences:   "参照",
	LblOtherCVEs:    "ほかのCVE",
	LblRuntime:      "使用状況",
	LblEvidence:     "観測根拠",
	LblExposure:     "公開状態",
	LblPrivilege:    "権限",
	LblLastSeen:     "最終確認",
	LblChange:       "変化",
	LblDetails:      "詳細",
	LblStatus:       "状態",
	LblAction:       "対応",

	RiskValueDistroUpdate: "🟢 ディストリのセキュリティパッチ",
	RiskValueSafe:         "🟢 低リスク",
	RiskValueCaution:      "🟠 メジャーバージョン更新 — 要注意",
	RiskValueUnknown:      "⚪ リスク不明",

	FixNoteMitigate:   "緩和策を検討",
	FixNoteWontFix:    "このOSリリースでは修正予定なし、置き換えを検討",
	FixNoteEOL:        "サポート終了(EOL): このリリースでは修正予定なし、サポート中のバージョンを検討",
	FixNoteEOLRuntime: "サポート終了(EOL): この系列には修正版が出ないため、系列を上げる必要がある(手動)",

	CardNewCVEs:      "新しいCVE %s",
	CardKEVShort:     "CISA KEV",
	CardSeeActNow:    "🚨 今すぐ対応を参照",
	CardEOSLStatus:   "ベースOSがEOL (今後のセキュリティ更新なし)",
	CardFoldedEOL:    "サポート終了(EOL)のパッケージ%d件を含む",
	CardNewEOSLNote:  "新たにサポート終了(EOL)となったパッケージ%d件を含む",
	CardBaseEOL:      "ベースOSは既にEOL",
	CardCollapsed:    "低リスクの修正 +%[1]d件 (%[2]s): %[3]s",
	CardCounts:       "CRITICAL %[1]d / HIGH %[2]d",
	CardBaseWait:     "元イメージ %[1]s %[2]s の新しい版待ち（同じ系列に新しい版なし）",
	CardAgeLine:      "⏱ 未解決%[1]d日 · 初回検出%[2]s",
	CardAgeToday:     "⏱ 本日初検出",
	ChannelContinued: " _(続き %[1]d/%[2]d)_",

	FbFull:               "KestreLynx %[1]s %[2]s — %[3]s",
	FbPlain:              "KestreLynx %[1]s %[2]s",
	FbContinued:          "KestreLynx %[1]s %[2]s (続き %[3]d/%[4]d)",
	FbRoleEverythingOpen: "未解決の所見の全体",
	FbRoleChanges:        "前回のスキャンからの変化",
	FbRoleNoChanges:      "前回のスキャンから変化なし",
	FbRoleWeekly:         "📋 週次全体レポート — 未解決の所見の全体",
	FbSegNew:             "🆕 新規検出%d件",
	FbSegResolved:        "✅ 解消%d件",
	FbSegScanFailed:      "⚠️ スキャン失敗%d件",
	FbSegEOLNew:          "⛔ 新規EOL%d件",
	FbSegReplaced:        "🔄 イメージ更新%d件",
	FbSegRefChanged:      "🔄 参照の更新%d件",
	FbSegActionable:      "✅ 修正版あり%d件",
	FbSegNoFix:           "ℹ️ 修正版なし%d件",
	FbSegWontFix:         "🔕 このOSリリースでは修正予定なし%d件",
	FbThread:             "%[1]s — %[2]s · %[3]s",
	FbThreadCont:         " (続き)",
	FbThreadMoreImage:    " ほか%dイメージ",
	FbThreadPackages:     " (%dパッケージ)",
	ShortEOLBase:         "⛔ EOLのベースOS",
	ShortEOLPackage:      "⛔ EOLのパッケージ",

	PlanHeading:          "*🔧 修正計画*",
	PlanNothing:          "提案できる更新はありません。",
	PlanNotSaved:         "_修正計画を保存できませんでした。_",
	PlanUnavailableDB:    "_今回は修正計画を作成できませんでした: スキャン用データベースを用意できませんでした。_",
	PlanUnavailableOther: "_今回は修正計画を作成できませんでした。_",
	PlanFallback:         "KestreLynx %[1]s 修正計画 — %[2]s",
	PlanFallbackCont:     "KestreLynx %[1]s 修正計画 (%[2]d/%[3]d)",

	PlanPRCounts:         "Pull Request: %s",
	PlanPRSegCreated:     "作成 %d件",
	PlanPRSegOpen:        "オープン中 %d件",
	PlanPRSegMerged:      "マージ済み %d件",
	PlanPRSegClosed:      "未マージでクローズ %d件",
	PlanPRSegManual:      "要判断 %d件",
	PlanPRSegDeferred:    "延期 %d件",
	PlanPRSegBlocked:     "停止・失敗 %d件",
	PlanCounts:           "%s",
	PlanSegCandidate:     "更新候補 %d件",
	PlanSegRepull:        "再pull %d件",
	PlanSegRebuild:       "再ビルド %d件",
	PlanSegDecide:        "要判断 %d件",
	PlanSegNotComparable: "比較不能 %d件",
	PlanSegFailed:        "失敗 %d件",
	PlanSegDeferred:      "保留 %d件",

	PlanLblService:       "サービス",
	PlanLblFile:          "修正するファイル",
	PlanLblPR:            "Pull Request",
	PlanLblUpdate:        "更新",
	PlanLblCandidate:     "更新候補",
	PlanLblRepull:        "再pull",
	PlanLblRebuild:       "再ビルド",
	PlanLblDecide:        "要判断",
	PlanLblNotComparable: "比較不能",
	PlanLblFailed:        "失敗",
	PlanLblDeferred:      "保留",
	PlanLblMajor:         "⚠️ メジャーバージョンの変更",
	PlanLblPullPolicy:    "pullポリシー",
	PlanLblManagedBy:     "管理元(目印による推定)",

	PlanPullRestart:              "Podを再起動すると新しい中身を取得する",
	PlanPullChangeTag:            "ノードにある古い中身が使われるため再起動では直らない。固定タグへの変更かdigest指定が要る",
	PlanPullImportToNode:         "ノードへのイメージの取り込みが要る",
	PlanPullValue:                "%[1]s: %[2]s (%[3]s)",
	PlanOwnerHelm:                "Helmリリース %[1]s (%[2]s)",
	PlanOwnerArgoCD:              "Argo CDアプリ %s",
	PlanOwnerFluxKust:            "Flux Kustomization %[2]s/%[1]s",
	PlanOwnerFluxHelm:            "Flux HelmRelease %[2]s/%[1]s",
	PlanManagedValue:             "%[1]s: %[2]s",
	PlanFileValue:                "%[1]s の %[2]s",
	PlanPRValue:                  "%[1]s (%[2]s)",
	PlanPRStatusCreated:          "今回作成",
	PlanPRStatusOpen:             "オープン中",
	PlanPRStatusMerged:           "マージ済み",
	PlanPRStatusClosed:           "未マージでクローズ",
	PlanChange:                   "%[1]s %[2]s → %[3]s",
	PlanBaseImageValue:           "ベースイメージ %[1]s %[2]s → %[3]s",
	PlanListSep:                  "、",
	PlanMore:                     " ほか%d件",
	PlanMajorZero:                "%s (0.x のマイナー変更)",
	PlanMajorEdit:                "%[1]s の指定 %[2]s → %[3]s (%[4]s)",
	PlanResolves:                 "所見%d件が解消",
	PlanResolvesPartial:          "所見%[2]d件中%[1]d件が解消",
	PlanKEVClause:                "KEV %d件",
	PlanUndetectedClause:         "稼働中のイメージで未検出 %d件",
	PlanClauseJoin:               "、",
	PlanClauseWrap:               " (%s)",
	PlanPackageReason:            "%[1]s %[2]s → %[3]s は%[4]s%[5]s",
	PlanLockfileUnchanged:        " (lockfile は変わらず)",
	PlanLeftOut:                  "%[1]s %[2]s → %[3]s は%[4]sため除外",
	PlanChangeWith:               "%[1]s %[2]s → %[3]s（%[4]s も更新）",
	PlanChainNotFixed:            "%[1]s %[2]s → %[3]s: %[4]s をプロジェクトの範囲内で解決し直したが、今回の再解決では修正版に届かなかった",
	PlanChainRejected:            "%[1]s %[2]s → %[3]s には %[4]s の更新も必要だが、%[5]sため採用しない",
	PlanChainHeld:                "%[1]s %[2]s → %[3]s は %[4]s に止められていて、%[5]sため %[4]s の更新を試していない",
	PlanChainWaiting:             "%[1]s %[2]s → %[3]s には %[4]s の更新も必要だが、入る版の公開から72時間経っていないため %[5]s 以降に再試行する",
	PlanNotUpdated:               "%[1]s は脆弱性が直る %[2]s に上げられず、%[4]s では %[3]s のまま（上げられない原因は KestreLynx では調べていないため、%[1]s に依存しているパッケージの版の指定を確認してください）",
	PlanNotInFile:                "%s に無いパッケージ（lockfile 以外の経路でイメージに入ったものとみられ、lockfile の更新では直せない）",
	PlanWrongVersion:             "イメージに入っている版が %s と違うパッケージ（イメージが今の %[1]s から作られていない可能性があるため、作り直してから確認してください）",
	PlanBulletVersions:           "  • %[1]s: イメージは %[2]s、%[3]s は %[4]s",
	PlanBullet:                   "  • %[1]s %[2]s",
	PlanRebuildValue:             "%[1]s %[2]s: 再ビルドで %[3]s 以上が入る見込み",
	PlanDockerfileRebuild:        "稼働中のイメージの作成元のベースを確認できない。`docker compose build --pull` で再ビルドすると現在のベースが入る",
	PlanDockerfileRebuildMapping: "稼働中のイメージの作成元のベースを確認できない。ベースを取り直して再ビルドし(`docker build --pull` など)、デプロイし直す",
	PlanDockerfileRebuildMixed:   "稼働中のイメージの作成元のベースを確認できない。Compose のサービスは `docker compose build --pull` で、`docker run` のコンテナは `docker build --pull` などで再ビルドし、それぞれコンテナを作り直す",
	PlanRebuildRuntime:           "現在の %[1]s の %[2]s は %[3]s。この版を引き継げば、検出中の %[2]s %[4]s の %[6]d 件のうち %[5]d 件は出なくなる見込み(再ビルド後のイメージは未確認)",
	PlanRuntimeEOL:               "%[1]s は %[2]s にサポート終了。実行環境を上げてから更新してください",
	PlanRuntimeEOLNoDate:         "%[1]s はサポート終了。実行環境を上げてから更新してください",

	PlanPRProblemLine:       "⚠️ Pull Requestの作成を停止中: %s",
	PlanPRProblemJoin:       "、",
	PlanPRProblemBlocked:    "リポジトリ、ブランチ、Pull Requestのいずれかが想定の状態でない",
	PlanPRProblemStorage:    "Pull Requestの記録を保存できない",
	PlanPRProblemFull:       "操作ログが満杯",
	PlanPRProblemUnverified: "既存のPull Requestを確認できない",
}

// messagesFor resolves a Language to its dictionary, defaulting to English
// for the zero value or any value config validation should already have
// rejected.
func messagesFor(lang Language) messages {
	if lang == LanguageJA {
		return jaMessages
	}
	return enMessages
}
