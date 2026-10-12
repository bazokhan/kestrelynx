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
	OpenNowCriticalHigh       string // "CRITICAL %[1]d / HIGH %[2]d across %[3]d image(s)"
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
	WontFixSectionTitle string // "🔕 Upstream won't fix (will_not_fix)"

	// --- upgrade-risk labels ---
	RiskDistroUpdate string // "🟢 upgrade: distro security patch"
	RiskSafe         string // "🟢 upgrade: low-risk"
	RiskCaution      string // "🟠 upgrade: major version bump — needs care"
	RiskUnknown      string // "⚪ upgrade: risk unknown"

	// --- end-of-life wording ---
	EOLPackageText   string // "end-of-life: no fix planned for this release"
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

	// Upgrade-risk values, without the leading "upgrade:" the RiskXxx labels carry.
	RiskValueDistroUpdate string // "🟢 distro security patch"
	RiskValueSafe         string // "🟢 low-risk"
	RiskValueCaution      string // "🟠 major version bump — needs care"
	RiskValueUnknown      string // "⚪ risk unknown"

	// What to do when there is no fix, shown after the fixed-in "none".
	FixNoteMitigate string // "consider mitigation"
	FixNoteWontFix  string // "upstream won't fix, consider replacing"
	FixNoteEOL      string // "end-of-life: no fix planned for this release, consider a supported version"

	CardNewCVEs      string // "new CVEs: %s" (linked CVE ids)
	CardKEVShort     string // "CISA KEV"
	CardSeeActNow    string // "🚨 see Act now"
	CardEOSLStatus   string // "base OS is EOL (no more security updates coming)"
	CardFoldedEOL    string // "includes %d end-of-life package(s)"
	CardNewEOSLNote  string // "includes %d newly end-of-life package(s)"
	CardBaseEOL      string // "base OS already EOL"
	CardCollapsed    string // "+%[1]d lower-risk fixes (%[2]s): %[3]s" (count, severity summary, comma-joined names)
	CardCounts       string // "CRITICAL %[1]d / HIGH %[2]d"
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
	FbSegWontFix         string // "🔕 %d upstream won't fix"
	FbThread             string // "%[1]s — %[2]s · %[3]s" (role, short section name, first image)
	FbThreadCont         string // " (cont.)"
	FbThreadMoreImage    string // " +%d more image(s)"
	FbThreadPackages     string // " (%d package(s))"
	ShortEOLBase         string // "⛔ EOL base"
	ShortEOLPackage      string // "⛔ EOL packages"

	// --- fix plan ---
	// The plan only proposes candidates: nothing is pulled, changed or
	// created, and the heading says so.
	PlanHeading                 string // "\n*🔧 Fix plan* (candidates only — nothing is changed automatically)\n"
	PlanSegPullAgain            string // "%d re-pull" (count of images a fresh pull would fix)
	PlanSegUpdate               string // "%d update candidate(s)" (count of newer tags that would fix)
	PlanSegManual               string // "%d manual"
	PlanSegNotComparable        string // "%d not comparable"
	PlanSegDeferred             string // "%d deferred"
	PlanSegNoCandidate          string // "%d no candidate"
	PlanSegExcluded             string // "%d excluded"
	PlanSegFailed               string // "%d failed"
	PlanNothing                 string // "No updates to propose."
	PlanPullAgainLine           string // "• Re-pulling %[1]s resolves %[2]d finding(s)" (image reference, count)
	PlanUpdateLine              string // "• Updating %[1]s to %[2]s resolves %[3]d finding(s)" (image reference, candidate tag, count)
	PlanPullAgainPartialLine    string // "• Re-pulling %[1]s resolves %[2]d of %[3]d findings%[4]s" (image reference, resolved, targeted, remainder clause)
	PlanUpdatePartialLine       string // "• Updating %[1]s to %[2]s resolves %[3]d of %[4]d findings%[5]s" (image reference, candidate tag, resolved, targeted, remainder clause)
	PlanRemainClause            string // "%d remain" (findings still present on the candidate)
	PlanUndetectedClause        string // "%d not detected on the running image" (targeted findings the comparison scan of the running image did not show)
	PlanClauseJoin              string // ", " (between the remainder clauses)
	PlanClauseWrap              string // " (%s)" (around the joined clauses)
	PlanIntroducedKEVPullLine   string // "• Re-pulling %[1]s introduces a KEV-listed vulnerability — manual review" (image reference)
	PlanIntroducedKEVUpdateLine string // "• Updating %[1]s to %[2]s introduces a KEV-listed vulnerability — manual review" (image reference, candidate tag)
	PlanKEVSuffix               string // " (%d KEV)" (appended to a plan line; counts the resolved KEV-listed findings)
	PlanNotSaved                string // "_The fix plan could not be saved._"
	PlanUnavailableDB           string // "_Fix plan unavailable this cycle: the scan databases could not be prepared._"
	PlanUnavailableOther        string // "_Fix plan unavailable this cycle._"
	PlanSegDepUpdate            string // "%d dependency update candidate(s)" (dependency units with a target version in their files)
	PlanSegRebuild              string // "%d rebuild expected" (dependency units whose version ranges allow the fix)
	PlanDepLine                 string // "• %[1]s (%[2]s): %[3]s %[4]s → %[5]s%[6]s — update not run yet" (service names, lockfile, package, installed, target, the "and more" clause)
	PlanDepMore                 string // " and %d more" (other packages of the same unit)
	PlanRebuildLine             string // "• %[1]s (%[2]s): %[3]s %[4]s%[6]s — rebuilding is expected to pick up ≥%[5]s" (service names, requirements file, package, installed, lowest fixed version, the "and more" clause)

	// Base image updates of Dockerfiles. The counts are those of the
	// comparison of the current base image with the candidate base image on
	// the findings the running image has in the base's layers; the image
	// rebuilt from the new Dockerfile is not checked, and none of these lines
	// is a statement about it.
	PlanDockerfileLine        string // "• %[1]s (Dockerfile): %[2]s → %[3]s — base image comparison resolves all %[4]d base findings (final image not yet verified)" (service names, base image, candidate tag, count)
	PlanDockerfilePartialLine string // "• %[1]s (Dockerfile): %[2]s → %[3]s — base image comparison resolves %[4]d of %[5]d base findings (final image not yet verified)" (service names, base image, candidate tag, resolved, targeted)
	PlanDockerfileKEVLine     string // "• %[1]s (Dockerfile): updating the base %[2]s to %[3]s introduces a KEV-listed vulnerability — manual review" (service names, base image, candidate tag)
	PlanDockerfilePRNote      string // " — base image comparison; final image not yet verified" (appended to the line of a base image pull request)
	PlanDockerfileRebuildLine string // "• %[1]s (Dockerfile): %[2]s — which base the running image was built from could not be confirmed; rebuilding with `docker compose build --pull` picks up the current base" (service names, base image)

	// Pull requests of the fix plan (only with pull requests enabled). A
	// line names the pull request link, the image, the old and new tag and
	// the Compose file; none of them says a finding is resolved.
	PlanHeadingPR     string // "\n*🔧 Fix plan* (candidates and pull requests — nothing is merged or deployed automatically)\n"
	PlanPRCounts      string // "Pull requests: %s" (the joined segments)
	PlanPRSegCreated  string // "%d created" (opened in this cycle)
	PlanPRSegOpen     string // "%d open"
	PlanPRSegMerged   string // "%d merged"
	PlanPRSegClosed   string // "%d closed without merging"
	PlanPRSegManual   string // "%d manual"
	PlanPRSegDeferred string // "%d deferred"
	PlanPRSegBlocked  string // "%d blocked or failed"
	PlanPRCreatedLine string // "• Opened %[1]s: %[2]s %[3]s → %[4]s in %[5]s — not merged yet" (link, image, old tag, new tag, Compose file)
	PlanPROpenLine    string // "• Open %[1]s: %[2]s %[3]s → %[4]s in %[5]s"
	PlanPRMergedLine  string // "• Merged %[1]s: %[2]s %[3]s → %[4]s in %[5]s — deployment not confirmed"
	PlanPRClosedLine  string // "• Closed without merging %[1]s: %[2]s %[3]s → %[4]s in %[5]s — not proposed again"
	// Pull requests that update a lockfile (language packages). A line names
	// the link, the services, the lockfile and the first package's change; a
	// scan of the lockfile is all that was checked, never the rebuilt image.
	PlanPRLangCreatedLine   string // "• Opened %[1]s: %[2]s (%[3]s) %[4]s%[5]s — not merged yet" (link, services, lockfile, first package change, the "and more" clause)
	PlanPRLangOpenLine      string // "• Open %[1]s: %[2]s (%[3]s) %[4]s%[5]s"
	PlanPRLangMergedLine    string // "• Merged %[1]s: %[2]s (%[3]s) %[4]s%[5]s — deployment not confirmed"
	PlanPRLangClosedLine    string // "• Closed without merging %[1]s: %[2]s (%[3]s) %[4]s%[5]s — not proposed again"
	PlanPRLangNote          string // " — lockfile scan only; the image is not rebuilt or scanned" (appended to the line of a lockfile pull request)
	PlanPRLangMajorNote     string // " — ⚠ includes a major version change" (appended when a package or a manifest edit changes the major version)
	PlanDepNotOpenedLine    string // "• %[1]s (%[2]s): %[3]s%[4]s — update checked, pull request not opened: %[5]s" (services, lockfile, first package change, the "and more" clause, the status and reason)
	PlanDepManualLine       string // "• %[1]s (%[2]s): dependency update needs a person — %[3]s" (services, lockfile, reason)
	PlanDepFailedLine       string // "• %[1]s (%[2]s): dependency update failed — %[3]s"
	PlanDepDeferredLine     string // "• %[1]s (%[2]s): dependency update deferred — %[3]s"
	PlanDepLeftOutLine      string // "• %[1]s (%[2]s): %[3]s%[4]s left out of the update, needs a person — %[5]s" (services, lockfile, first package change, the "and more" clause, the reason)
	PlanPRProblemLine       string // "⚠️ Pull request writes are stopped: %s" (the joined reasons)
	PlanPRProblemJoin       string // "; " (between the reasons)
	PlanPRProblemBlocked    string // "a repository, branch or pull request is not in the expected state"
	PlanPRProblemStorage    string // "the pull request records could not be saved"
	PlanPRProblemFull       string // "the operation log is full"
	PlanPRProblemUnverified string // "existing pull requests could not be verified"
	PlanOpsLabel            string // "Pull request operations:"
	PlanOpLine              string // "• %[1]s %[2]s: %[3]s%[4]s" (operation, target, result, error clause)
	PlanOpErrorClause       string // " — %s" (the short error text)
	PlanOpTargetRef         string // "%[1]s (%[2]s)" (repository, branch)
	PlanOpResultOK          string // "ok"
	PlanOpResultFailed      string // "failed"
	PlanOpResultUnknown     string // "outcome unknown"
	PlanOpBlob              string // "create blob"
	PlanOpTree              string // "create tree"
	PlanOpCommit            string // "create commit"
	PlanOpRef               string // "create branch"
	PlanOpPull              string // "open pull request"
	PlanOpComment           string // "comment"
	PlanOpClose             string // "close pull request"
}

// enMessages is the historical English wording, unchanged byte-for-byte from
// what this package printed before the language dictionary existed. Every
// golden test in testdata/golden pins this text; do not edit a value here
// without regenerating every affected golden file and checking each one by
// eye.
var enMessages = messages{
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

	IdentityUnconfirmed: "identity unconfirmed: scanned by reference",
	UnresolvedRefsLine:  "⚠️ %[1]s — %[2]s\n",
	UnconfirmedRefsLine: "⏳ unconfirmed this cycle, holding previous findings — %s\n",

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
	OpenNowCriticalHigh:       "CRITICAL %[1]d / HIGH %[2]d across %[3]d image(s)",
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
	WontFixSectionTitle: "🔕 Upstream won't fix (will_not_fix)",

	RiskDistroUpdate: "🟢 upgrade: distro security patch",
	RiskSafe:         "🟢 upgrade: low-risk",
	RiskCaution:      "🟠 upgrade: major version bump — needs care",
	RiskUnknown:      "⚪ upgrade: risk unknown",

	EOLPackageText:   "end-of-life: no fix planned for this release",
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

	RiskValueDistroUpdate: "🟢 distro security patch",
	RiskValueSafe:         "🟢 low-risk",
	RiskValueCaution:      "🟠 major version bump — needs care",
	RiskValueUnknown:      "⚪ risk unknown",

	FixNoteMitigate: "consider mitigation",
	FixNoteWontFix:  "upstream won't fix, consider replacing",
	FixNoteEOL:      "end-of-life: no fix planned for this release, consider a supported version",

	CardNewCVEs:      "new CVEs: %s",
	CardKEVShort:     "CISA KEV",
	CardSeeActNow:    "🚨 see Act now",
	CardEOSLStatus:   "base OS is EOL (no more security updates coming)",
	CardFoldedEOL:    "includes %d end-of-life package(s)",
	CardNewEOSLNote:  "includes %d newly end-of-life package(s)",
	CardBaseEOL:      "base OS already EOL",
	CardCollapsed:    "+%[1]d lower-risk fixes (%[2]s): %[3]s",
	CardCounts:       "CRITICAL %[1]d / HIGH %[2]d",
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
	FbSegWontFix:         "🔕 %d upstream won't fix",
	FbThread:             "%[1]s — %[2]s · %[3]s",
	FbThreadCont:         " (cont.)",
	FbThreadMoreImage:    " +%d more image(s)",
	FbThreadPackages:     " (%d package(s))",
	ShortEOLBase:         "⛔ EOL base",
	ShortEOLPackage:      "⛔ EOL packages",

	PlanHeading:                 "\n*🔧 Fix plan* (candidates only — nothing is changed automatically)\n",
	PlanSegPullAgain:            "%d re-pull",
	PlanSegUpdate:               "%d update candidate(s)",
	PlanSegManual:               "%d manual",
	PlanSegNotComparable:        "%d not comparable",
	PlanSegDeferred:             "%d deferred",
	PlanSegNoCandidate:          "%d no candidate",
	PlanSegExcluded:             "%d excluded",
	PlanSegFailed:               "%d failed",
	PlanNothing:                 "No updates to propose.",
	PlanPullAgainLine:           "• Re-pulling %[1]s resolves %[2]d finding(s)",
	PlanUpdateLine:              "• Updating %[1]s to %[2]s resolves %[3]d finding(s)",
	PlanPullAgainPartialLine:    "• Re-pulling %[1]s resolves %[2]d of %[3]d findings%[4]s",
	PlanUpdatePartialLine:       "• Updating %[1]s to %[2]s resolves %[3]d of %[4]d findings%[5]s",
	PlanRemainClause:            "%d remain",
	PlanUndetectedClause:        "%d not detected on the running image",
	PlanClauseJoin:              ", ",
	PlanClauseWrap:              " (%s)",
	PlanIntroducedKEVPullLine:   "• Re-pulling %[1]s introduces a KEV-listed vulnerability — manual review",
	PlanIntroducedKEVUpdateLine: "• Updating %[1]s to %[2]s introduces a KEV-listed vulnerability — manual review",
	PlanKEVSuffix:               " (%d KEV)",
	PlanNotSaved:                "_The fix plan could not be saved._",
	PlanUnavailableDB:           "_Fix plan unavailable this cycle: the scan databases could not be prepared._",
	PlanUnavailableOther:        "_Fix plan unavailable this cycle._",
	PlanSegDepUpdate:            "%d dependency update candidate(s)",
	PlanSegRebuild:              "%d rebuild expected",
	PlanDepLine:                 "• %[1]s (%[2]s): %[3]s %[4]s → %[5]s%[6]s — update not run yet",
	PlanDepMore:                 " and %d more",
	PlanRebuildLine:             "• %[1]s (%[2]s): %[3]s %[4]s%[6]s — rebuilding is expected to pick up ≥%[5]s",
	PlanDockerfileLine:          "• %[1]s (Dockerfile): %[2]s → %[3]s — base image comparison resolves all %[4]d base findings (final image not yet verified)",
	PlanDockerfilePartialLine:   "• %[1]s (Dockerfile): %[2]s → %[3]s — base image comparison resolves %[4]d of %[5]d base findings (final image not yet verified)",
	PlanDockerfilePRNote:        " — base image comparison; final image not yet verified",
	PlanDockerfileKEVLine:       "• %[1]s (Dockerfile): updating the base %[2]s to %[3]s introduces a KEV-listed vulnerability — manual review",
	PlanDockerfileRebuildLine:   "• %[1]s (Dockerfile): %[2]s — which base the running image was built from could not be confirmed; rebuilding with `docker compose build --pull` picks up the current base",

	PlanHeadingPR:           "\n*🔧 Fix plan* (candidates and pull requests — nothing is merged or deployed automatically)\n",
	PlanPRCounts:            "Pull requests: %s",
	PlanPRSegCreated:        "%d created",
	PlanPRSegOpen:           "%d open",
	PlanPRSegMerged:         "%d merged",
	PlanPRSegClosed:         "%d closed without merging",
	PlanPRSegManual:         "%d manual",
	PlanPRSegDeferred:       "%d deferred",
	PlanPRSegBlocked:        "%d blocked or failed",
	PlanPRCreatedLine:       "• Opened %[1]s: %[2]s %[3]s → %[4]s in %[5]s — not merged yet",
	PlanPROpenLine:          "• Open %[1]s: %[2]s %[3]s → %[4]s in %[5]s",
	PlanPRMergedLine:        "• Merged %[1]s: %[2]s %[3]s → %[4]s in %[5]s — deployment not confirmed",
	PlanPRClosedLine:        "• Closed without merging %[1]s: %[2]s %[3]s → %[4]s in %[5]s — not proposed again",
	PlanPRLangCreatedLine:   "• Opened %[1]s: %[2]s (%[3]s) %[4]s%[5]s — not merged yet",
	PlanPRLangOpenLine:      "• Open %[1]s: %[2]s (%[3]s) %[4]s%[5]s",
	PlanPRLangMergedLine:    "• Merged %[1]s: %[2]s (%[3]s) %[4]s%[5]s — deployment not confirmed",
	PlanPRLangClosedLine:    "• Closed without merging %[1]s: %[2]s (%[3]s) %[4]s%[5]s — not proposed again",
	PlanPRLangNote:          " — lockfile scan only; the image is not rebuilt or scanned",
	PlanPRLangMajorNote:     " — ⚠ includes a major version change",
	PlanDepNotOpenedLine:    "• %[1]s (%[2]s): %[3]s%[4]s — update checked, pull request not opened: %[5]s",
	PlanDepManualLine:       "• %[1]s (%[2]s): dependency update needs a person — %[3]s",
	PlanDepFailedLine:       "• %[1]s (%[2]s): dependency update failed — %[3]s",
	PlanDepDeferredLine:     "• %[1]s (%[2]s): dependency update deferred — %[3]s",
	PlanDepLeftOutLine:      "• %[1]s (%[2]s): %[3]s%[4]s left out of the update, needs a person — %[5]s",
	PlanPRProblemLine:       "⚠️ Pull request writes are stopped: %s",
	PlanPRProblemJoin:       "; ",
	PlanPRProblemBlocked:    "a repository, branch or pull request is not in the expected state",
	PlanPRProblemStorage:    "the pull request records could not be saved",
	PlanPRProblemFull:       "the operation log is full",
	PlanPRProblemUnverified: "existing pull requests could not be verified",
	PlanOpsLabel:            "Pull request operations:",
	PlanOpLine:              "• %[1]s %[2]s: %[3]s%[4]s",
	PlanOpErrorClause:       " — %s",
	PlanOpTargetRef:         "%[1]s (%[2]s)",
	PlanOpResultOK:          "ok",
	PlanOpResultFailed:      "failed",
	PlanOpResultUnknown:     "outcome unknown",
	PlanOpBlob:              "create blob",
	PlanOpTree:              "create tree",
	PlanOpCommit:            "create commit",
	PlanOpRef:               "create branch",
	PlanOpPull:              "open pull request",
	PlanOpComment:           "comment",
	PlanOpClose:             "close pull request",
}

// jaMessages is the Japanese dictionary.
var jaMessages = messages{
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

	IdentityUnconfirmed: "実体未確認: 参照によるスキャン",
	UnresolvedRefsLine:  "⚠️ %[1]s — %[2]s\n",
	UnconfirmedRefsLine: "⏳ 今回は未確認、前回の所見を保持 — %s\n",

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
	OpenNowCriticalHigh:       "CRITICAL %[1]d件 / HIGH %[2]d件、イメージ%[3]d件",
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
	WontFixSectionTitle: "🔕 上流では修正予定なし (will_not_fix)",

	RiskDistroUpdate: "🟢 アップグレード: ディストリのセキュリティパッチ",
	RiskSafe:         "🟢 アップグレード: 低リスク",
	RiskCaution:      "🟠 アップグレード: メジャーバージョン更新 — 要注意",
	RiskUnknown:      "⚪ アップグレード: リスク不明",

	EOLPackageText:   "サポート終了(EOL): このリリースでは修正予定なし",
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

	RiskValueDistroUpdate: "🟢 ディストリのセキュリティパッチ",
	RiskValueSafe:         "🟢 低リスク",
	RiskValueCaution:      "🟠 メジャーバージョン更新 — 要注意",
	RiskValueUnknown:      "⚪ リスク不明",

	FixNoteMitigate: "緩和策を検討",
	FixNoteWontFix:  "上流では修正予定なし、置き換えを検討",
	FixNoteEOL:      "サポート終了(EOL): このリリースでは修正予定なし、サポート中のバージョンを検討",

	CardNewCVEs:      "新しいCVE %s",
	CardKEVShort:     "CISA KEV",
	CardSeeActNow:    "🚨 今すぐ対応を参照",
	CardEOSLStatus:   "ベースOSがEOL (今後のセキュリティ更新なし)",
	CardFoldedEOL:    "サポート終了(EOL)のパッケージ%d件を含む",
	CardNewEOSLNote:  "新たにサポート終了(EOL)となったパッケージ%d件を含む",
	CardBaseEOL:      "ベースOSは既にEOL",
	CardCollapsed:    "低リスクの修正 +%[1]d件 (%[2]s): %[3]s",
	CardCounts:       "CRITICAL %[1]d / HIGH %[2]d",
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
	FbSegWontFix:         "🔕 上流の修正予定なし%d件",
	FbThread:             "%[1]s — %[2]s · %[3]s",
	FbThreadCont:         " (続き)",
	FbThreadMoreImage:    " ほか%dイメージ",
	FbThreadPackages:     " (%dパッケージ)",
	ShortEOLBase:         "⛔ EOLのベースOS",
	ShortEOLPackage:      "⛔ EOLのパッケージ",

	PlanHeading:                 "\n*🔧 修正計画* (候補の提示のみ — 自動では何も変更しない)\n",
	PlanSegPullAgain:            "再pull %d件",
	PlanSegUpdate:               "更新候補 %d件",
	PlanSegManual:               "要判断 %d件",
	PlanSegNotComparable:        "比較不能 %d件",
	PlanSegDeferred:             "延期 %d件",
	PlanSegNoCandidate:          "候補なし %d件",
	PlanSegExcluded:             "対象外 %d件",
	PlanSegFailed:               "失敗 %d件",
	PlanNothing:                 "提案できる更新はありません。",
	PlanPullAgainLine:           "• %[1]s を再pullすると %[2]d件の所見が解消",
	PlanUpdateLine:              "• %[1]s を %[2]s に更新すると %[3]d件の所見が解消",
	PlanPullAgainPartialLine:    "• %[1]s を再pullすると %[3]d件中 %[2]d件の所見が解消%[4]s",
	PlanUpdatePartialLine:       "• %[1]s を %[2]s に更新すると %[4]d件中 %[3]d件の所見が解消%[5]s",
	PlanRemainClause:            "%d件は残る",
	PlanUndetectedClause:        "%d件は稼働中のイメージで未検出",
	PlanClauseJoin:              "、",
	PlanClauseWrap:              "(%s)",
	PlanIntroducedKEVPullLine:   "• %[1]s を再pullするとKEV掲載の脆弱性が新たに入る — 要確認",
	PlanIntroducedKEVUpdateLine: "• %[1]s を %[2]s に更新するとKEV掲載の脆弱性が新たに入る — 要確認",
	PlanKEVSuffix:               " (KEV %d件)",
	PlanNotSaved:                "_修正計画を保存できなかった_",
	PlanUnavailableDB:           "_今回は修正計画を作成できない: スキャン用データベースを準備できなかった_",
	PlanUnavailableOther:        "_今回は修正計画を作成できない_",
	PlanSegDepUpdate:            "依存更新候補 %d件",
	PlanSegRebuild:              "再ビルドで解消見込み %d件",
	PlanDepLine:                 "• %[1]s (%[2]s): %[3]s %[4]s → %[5]s%[6]s — 更新は未実行",
	PlanDepMore:                 " ほか%d件",
	PlanRebuildLine:             "• %[1]s (%[2]s): %[3]s %[4]s%[6]s — 再ビルドで %[5]s 以上が入る見込み",
	PlanDockerfileLine:          "• %[1]s (Dockerfile): %[2]s → %[3]s — ベースイメージの比較で %[4]d件すべてが解消見込み(最終イメージは未検証)",
	PlanDockerfilePartialLine:   "• %[1]s (Dockerfile): %[2]s → %[3]s — ベースイメージの比較で %[5]d件中 %[4]d件が解消見込み(最終イメージは未検証)",
	PlanDockerfilePRNote:        " — ベースイメージの比較による。最終イメージは未検証",
	PlanDockerfileKEVLine:       "• %[1]s (Dockerfile): ベース %[2]s を %[3]s に更新するとKEV掲載の脆弱性が新たに入る — 要確認",
	PlanDockerfileRebuildLine:   "• %[1]s (Dockerfile): %[2]s — 稼働中のイメージがどのベースから作られたかを確認できない。`docker compose build --pull` で再ビルドすると現在のベースが入る",

	PlanHeadingPR:           "\n*🔧 修正計画* (候補の提示とPull Requestの作成のみ — マージとデプロイは自動では行わない)\n",
	PlanPRCounts:            "Pull Request: %s",
	PlanPRSegCreated:        "作成 %d件",
	PlanPRSegOpen:           "オープン %d件",
	PlanPRSegMerged:         "マージ済み %d件",
	PlanPRSegClosed:         "未マージでクローズ %d件",
	PlanPRSegManual:         "要判断 %d件",
	PlanPRSegDeferred:       "延期 %d件",
	PlanPRSegBlocked:        "停止・失敗 %d件",
	PlanPRCreatedLine:       "• %[1]s を作成: %[2]s %[3]s → %[4]s (%[5]s) — 未マージ",
	PlanPROpenLine:          "• %[1]s オープン中: %[2]s %[3]s → %[4]s (%[5]s)",
	PlanPRMergedLine:        "• %[1]s マージ済み: %[2]s %[3]s → %[4]s (%[5]s) — デプロイは未確認",
	PlanPRClosedLine:        "• %[1]s 未マージでクローズ: %[2]s %[3]s → %[4]s (%[5]s) — 再提案しない",
	PlanPRLangCreatedLine:   "• %[1]s を作成: %[2]s (%[3]s) %[4]s%[5]s — 未マージ",
	PlanPRLangOpenLine:      "• %[1]s オープン中: %[2]s (%[3]s) %[4]s%[5]s",
	PlanPRLangMergedLine:    "• %[1]s マージ済み: %[2]s (%[3]s) %[4]s%[5]s — デプロイは未確認",
	PlanPRLangClosedLine:    "• %[1]s 未マージでクローズ: %[2]s (%[3]s) %[4]s%[5]s — 再提案しない",
	PlanPRLangNote:          " — lockfileのスキャンのみ。イメージは再ビルドもスキャンもしていない",
	PlanPRLangMajorNote:     " — ⚠ メジャーバージョンの変更を含む",
	PlanDepNotOpenedLine:    "• %[1]s (%[2]s): %[3]s%[4]s — 更新は検査済み。Pull Requestは未作成: %[5]s",
	PlanDepManualLine:       "• %[1]s (%[2]s): 依存パッケージの更新は要判断 — %[3]s",
	PlanDepFailedLine:       "• %[1]s (%[2]s): 依存パッケージの更新は失敗 — %[3]s",
	PlanDepDeferredLine:     "• %[1]s (%[2]s): 依存パッケージの更新は延期 — %[3]s",
	PlanDepLeftOutLine:      "• %[1]s (%[2]s): %[3]s%[4]s は今回の更新から除外。要判断 — %[5]s",
	PlanPRProblemLine:       "⚠️ Pull Requestの作成を停止中: %s",
	PlanPRProblemJoin:       "、",
	PlanPRProblemBlocked:    "リポジトリ、ブランチ、Pull Requestのいずれかが想定の状態でない",
	PlanPRProblemStorage:    "Pull Requestの記録を保存できない",
	PlanPRProblemFull:       "操作ログが満杯",
	PlanPRProblemUnverified: "既存のPull Requestを確認できない",
	PlanOpsLabel:            "Pull Requestの操作:",
	PlanOpLine:              "• %[1]s %[2]s: %[3]s%[4]s",
	PlanOpErrorClause:       " — %s",
	PlanOpTargetRef:         "%[1]s (%[2]s)",
	PlanOpResultOK:          "成功",
	PlanOpResultFailed:      "失敗",
	PlanOpResultUnknown:     "結果不明",
	PlanOpBlob:              "blob作成",
	PlanOpTree:              "tree作成",
	PlanOpCommit:            "commit作成",
	PlanOpRef:               "ブランチ作成",
	PlanOpPull:              "Pull Request作成",
	PlanOpComment:           "コメント",
	PlanOpClose:             "Pull Requestのクローズ",
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
