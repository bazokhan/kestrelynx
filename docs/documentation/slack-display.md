# Reading Slack notifications

## Where to find reports {#slack-display}

Slack channel notifications show changes and unresolved state, while Bot threads provide details.
See [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks) for the remediation plan display.

### Channel reports {#channel-display}

| Report | Content |
| --- | --- |
| `diff` mode | Changes since the previous scan and the current unresolved state |
| `full` mode | Unresolved findings confirmed by the current scan |
| Weekly report | A full report of current unresolved findings, added to the diff notification |

Diff notifications with changes display `Changes since the last scan.`, and full mode displays `Everything currently open.`
The weekly report heading is `📋 Weekly full report — everything currently open`.

Empty sections are omitted.
With triage enabled, Low remains count-only even in a full report; complete details are available in the [generic webhook](webhook-reference.md#generic-webhook).

When a generic webhook is configured, the message includes `Details in the generic webhook payload.`
See [Scan notification conditions](notification-conditions.md#notification-conditions) for when notifications are sent.

### Thread reports {#thread-display}

Bot threads show details as of that report under the heading `📊 Everything open now — YYYY-MM-DD HH:MM`.
The thread attaches to the first channel message, even when the channel report spans multiple messages.

| Footer of the first channel message | Destination |
| --- | --- |
| `📊 Everything open now is in this message's thread ↓` | The thread posted this cycle |
| `🔗 Everything open as of the last report → thread` | The previously posted report thread |

The previous report link points to the content as it was when that report was created.
See the channel's [current unresolved counts](#open-now) for the current unresolved state.

Long notifications are split into multiple messages, with `(cont.)` on continued headings and a part number such as `(cont. 2/3)` on channel continuations.
The footer is omitted when no valid link exists or the link cannot be displayed.

See [Slack thread delivery conditions](notification-conditions.md#slack-thread-delivery) for when a new thread is posted.

## Notification language {#notification-language}

Slack's standard text uses the configured notification language.
See [Configuration](configuration.md) for language settings and their scope.

| Content | Handling in Japanese notifications |
| --- | --- |
| Headings, sections, changes, warnings, runtime usage, and guidance | Displayed in Japanese |
| CVE IDs, package names, versions, paths, commands, and image names | Original notation preserved |
| Severities such as `CRITICAL` and `HIGH` | Original notation preserved |
| Trivy descriptions, scan failure errors, and discussion link labels | Displayed without translation |

## Section order {#section-order}

Depending on the report type, changes appear first or current unresolved findings appear by section.

### Diff report order {#diff-order}

Cycles with changes and weekly reports use the following order.
Sections without applicable content are omitted.

| Order | Content |
| --- | --- |
| Beginning | Header, image counts, and Sensor warnings |
| Before changes | Warnings about unavailable threat intelligence sources |
| Image changes | Content changes and reference updates |
| EOL changes | New EOL base operating systems and EOL package changes |
| Package changes | Ordinary new or changed findings, resolutions, and EOL clearances |
| End | Weekly current-state report, or scan failures and current unresolved state |

Unchanged notifications outside the weekly report day show `No changes since last scan.` followed by scan failures and the current unresolved state.
Identity-unconfirmed and holding annotations follow the unresolved state or full report.

With triage enabled, ordinary new or changed findings are ordered by priority, image name, and package name.

### Current-state report order {#current-order}

With triage enabled, unresolved findings appear in the following order.
Bot threads use the same section order.

| Order | Japanese section | English section |
| --- | --- | --- |
| First | ベースOSのサポート終了(EOL) | EOL base |
| Next | パッケージのサポート終了(EOL) | EOL package |
| By priority | 今すぐ対応 → 要監視 → 低優先度 | Act now → Watch → Low |

In full channel reports, threat intelligence warnings appear immediately after the `Priority:` line, before the EOL sections.
In weekly reports, these warnings appear near the beginning of the diff portion and are not repeated in the full report.

Scan failures and stale intelligence notes appear after the sections of the channel's current-state report.

When runtime usage is enabled, packages in use and images containing them appear first within each priority.
Exposure and privilege also affect the order among packages in use, but do not change priority itself.

### Order with triage disabled {#triage-disabled-display}

With triage disabled, findings appear by fix status after the EOL sections.

| Order | Displayed section |
| --- | --- |
| Fix available | `✅ Actionable now (fixed)` |
| No fix available | `ℹ️ No fix yet (affected / waiting on upstream)` |
| No fix planned | `🔕 No fix planned for this OS release (will_not_fix)` |

`Actionable now` means a fix is available and differs from the triage priority `Act now`.
See [Fix status](scan-logic.md#status) for status meanings.

In the channel, fixed findings that need attention appear individually, and the remaining findings are summarized by image.
Runtime usage does not affect the order.

## Reading counts {#counts}

Images, packages, and CVEs use different counting units.
Counts within the same notification may therefore differ.

### Image counts {#image-counts}

The header's `N images scanned, M affected` uses the following counting units.

| Japanese display | English | Counting unit |
| --- | --- | --- |
| スキャンした件数 | images scanned | Distinct image reference-and-identity pairs, including failures |
| 影響ありの件数 | affected | Image references with a selected vulnerability or an EOL base OS |

Separate references count separately in the scanned count, even when they share the same scan result.
References with only scan failures are excluded from the affected count.

### Current unresolved counts {#open-now}

`📌 Open now:` shows the unresolved state remaining after the current scan.
EOL and priority counts include history retained from the previous cycle.

| Display | Counting unit |
| --- | --- |
| `⛔ N EOL base` | Image references recorded as EOL |
| `⛔ N EOL package` | Image reference-and-package pairs not folded into a base OS |
| `🚨 N act-now` | Image reference-and-package pairs with Act now priority on the ordinary or EOL side |
| `👀 N watch` · `🔕 N low` | Pairs by ordinary package priority, excluding those counted as Act now |

EOL Watch and Low findings are not added to the priority counts.
EOL package and Act now counts may overlap.

With triage disabled, `CRITICAL` and `HIGH` sum the CVE counts of each package group in the current report.
The same CVE is counted separately if it appears in different groups.

When the current report contains no findings, the following states appear instead of counts.

| State | Display |
| --- | --- |
| Package history retained because Kubernetes identities are unconfirmed | `📌 Open now: unconfirmed — holding previous findings until re-confirmed` |
| Previous history retained for another reason | `📌 Open now: not re-scanned — holding previous findings until the next successful scan` |
| No retained history either | `🎉 Open now: none — all clear` |

### Priority line counts {#priority-counts}

`Priority:` in a current-state report counts package groups in the current report.
Groups with different fix statuses or different identities under the same reference count separately.

| Count | Included items |
| --- | --- |
| EOL base | EOL image references |
| EOL package | EOL groups not folded into a base OS |
| Act now | Act now groups, including EOL groups |
| Watch and Low | Ordinary package groups at each priority |

This differs from [current unresolved counts](#open-now), which combine findings for the same reference and package.
See [Muted findings](#muted-display) for exclusions due to muting.

### Unresolved age {#unresolved-age}

The oldest unresolved age is measured from the earliest first-seen timestamp among the included records.
The age appears after one day, with `⏰` added at 14 days or more.

| Triage | Included in the oldest unresolved age |
| --- | --- |
| Enabled | Ordinary Act now and Watch findings, EOL base operating systems, and individually displayed EOL packages |
| Disabled | All ordinary packages and EOL findings |

EOL packages folded into a base OS use the base OS's first-seen-as-EOL date.
However, Act now EOL packages contribute their own first-seen-as-EOL date even when folded.

Retained history is also included.
With triage enabled, ordinary packages determined to be muted this cycle are excluded from the oldest unresolved age.

| Example display | Meaning |
| --- | --- |
| `⏰ oldest act-now/watch unresolved 20 day(s)` | Oldest unresolved age with triage enabled, including EOL |
| `⏰ oldest unresolved 20 day(s)` | Oldest unresolved age with triage disabled |
| `⏱ open 20 day(s) · first seen 2026-06-04` | That package's age on a thread card |
| `⏱ first seen today` | Thread card display when the age is zero days |

The generic webhook uses a different set of records for its age calculation.
See [Oldest unresolved age](webhook-reference.md#oldest-open-days) when comparing them.

## Reading package cards {#package-card}

Packages appear in cards headed `◆ name`.
In the channel, Act now uses detailed cards, while Watch and other findings use compact cards.

| Item | Detailed card | Compact card |
| --- | --- | --- |
| Installed and fixed versions | Separate lines | Same line |
| Upgrade risk | `Upgrade risk:` line | In parentheses after the fixed version |
| Finding counts | `CRITICAL` and `HIGH` counts | Same |
| CVEs | Top CVE, exploitation information, and references | Top CVE when available |
| Runtime usage | Evidence of observed use | Short display when in use |

`Findings:` counts distinct CVE IDs within that package and fix-status group.
When no fixed version is available, `Fixed in: none` appears, and detailed cards may include mitigation or replacement guidance.

### CVE details {#cve-details}

`Top CVE:` is the CVE with the strongest assessment in the group.
Selection uses priority, whether an EPSS score is available, higher EPSS, and then CVE ID.

| Location | Other CVEs |
| --- | --- |
| Detailed channel card | Adds `(+N more CVE(s) in this package)` to the `Top CVE:` line |
| Thread | Lists IDs under `Other CVEs:` and summarizes omitted IDs as `(+N more)` |
| Diff card | Shows added IDs as `Change: new CVEs: ...` |

`EPSS n/a` in a detailed card means no score is available.
Very small values appear as `<0.1%`, and very large values as `>99%`.

`Summary:` in a thread displays Trivy's description.
See [Vulnerability fields](webhook-reference.md#vulnerability-fields) for complete CVE data without omissions.

### Upgrade risk {#upgrade-risk}

Upgrade risk describes the type of version change to the fixed version.

| Display | Meaning |
| --- | --- |
| `🟢 distro security patch` | Fixed version of an OS package |
| `🟢 low-risk` | Language-package change without a major version increase |
| `🟠 major version bump — needs care` | Language-package change that increases the major version |
| `⚪ risk unknown` | Change whose versions cannot be compared |

Green indicators do not guarantee update safety or compatibility.

### Ecosystem labels {#ecosystem-labels}

Language-package names include an ecosystem tag, such as `◆ setuptools [python-pkg]`.

| Display | Applies to |
| --- | --- |
| `[python-pkg]`, `[npm-pkg]`, `[gobinary]`, `[jar]`, and similar tags | Language-package type identified by Trivy |
| `[lang]` | Language package whose type cannot be identified |
| No tag | OS package |

These tags appear whether or not the Sensor is enabled.

### Reference links {#reference-links}

`References:` shows links related to the top CVE.

| Display | Destination |
| --- | --- |
| `advisory` | Primary advisory provided by Trivy |
| `vendor advisory` | Vendor or CISA information from KEV notes |
| `💬 HN (N pts)` | Related Hacker News discussion (N is its points) |

CVE IDs on the `Top CVE:`, `Other CVEs:`, and `Change:` lines link to NVD.
Non-CVE identifiers such as GHSA and DLA IDs appear as plain text.

`CISA KEV (exploited in the wild)` and `🧨 ransomware campaign` under `Exploitation:` describe information available for the top CVE.
See [Exploitation-based priority](scan-logic.md#triage) for priority decisions.

## Change labels {#change-labels}

Diff notifications show image, package, and EOL changes separately.
See [Change and history decisions](diff-logic.md#comparison-baseline) for the rules that establish a change.

### Image changes {#image-change-labels}

| Display | Meaning |
| --- | --- |
| `🔄 Image content changed (N)` | Section for image identity changes under the same reference |
| `image updated (old → new)` | Short digests before and after the change |
| `🔄 Image reference updated: repo sha-A → sha-B (history carried over)` | Reference update with detection history carried over |

Reference update lines show the repository name and the tags before and after the change.
Digest-pinned references use short digests, and references with neither a tag nor a digest use `latest`.

When a reference has multiple identities, current-state image headings distinguish them with short digests and platforms such as `linux/amd64`.

### Package changes {#package-change-labels}

| Display | Meaning |
| --- | --- |
| `🆕 New since last scan (N)` | New packages and changed known packages |
| `Change: ⬆️ escalated to ACT NOW` | A known package's priority increased |
| `Change: ⬆️ escalated to WATCH` | Priority increased to Watch |
| `Change: new CVEs: CVE-ID` | Newly added CVE |
| `Change: fix now available` | A fixed version became available |
| `✅ Resolved since last scan (N)` | Section combining package resolutions and EOL clearances |

The count in the new-findings heading is the number of displayed image reference-and-package pairs.
It may differ from the number of cards when a pair has multiple fix statuses.

New packages may have no dedicated `Change:` line.
See [Muted findings](#muted-display) for labels when notifications resume after muting.

### EOL display {#eol-display}

When an image has an EOL base OS, its EOL packages are folded into the base-OS line.
Act now EOL packages also show details in the Act now section, even when folded.

| Display | Meaning |
| --- | --- |
| `includes N end-of-life package(s)` | EOL packages folded into the base-OS line |
| `Details: 🚨 see Act now` | EOL package details appear in the Act now section |
| `includes N newly end-of-life package(s)` | Packages detected alongside a new EOL base OS and folded into its line |
| `N package(s) newly end-of-life` | Newly EOL packages under an already EOL base OS |
| `N end-of-life package(s) with new CVEs` | Added CVEs for packages under an already EOL base OS |
| `base OS no longer EOL` | Change where the base-OS EOL record is removed |
| `no longer end-of-life` | EOL package moved to ordinary findings |

New EOL packages other than Act now that are folded into a new EOL base OS are excluded from the EOL package diff heading count.
Changes folded into an already EOL base OS are included in the diff heading count.

Vulnerability findings may remain after EOL clears.
See [Finding classification](scan-logic.md#finding-classification) for EOL meanings and [Resolution decisions](diff-logic.md#resolved-findings) for clearance rules.

## Runtime usage display {#runtime-display}

When Sensor information is available, packages show runtime usage.
See [Runtime usage](runtime-usage.md) for usage decisions and observation limits.

### Usage labels {#usage-labels}

| Japanese display | English | Meaning |
| --- | --- | --- |
| `▶ 使用中` | in use | Finding with confirmed use |
| `▷ 使用が確認されない` | not observed | Finding with no use confirmed during the observation window |
| `▷ 稼働時の使用状況を判定できない (理由)` | unavailable | Finding without the evidence needed to determine usage |

Channel messages show runtime usage for findings in use.
Detailed thread cards also show when use was not observed or could not be determined.

Compact cards use a short display such as `Runtime: ▶ in use (running)`.
In current-state reports and the thread, Low findings have no individual cards; the section count includes the number in use.
In the changes, new Low findings and added CVEs are shown as compact cards.

The following phrases describe why usage cannot be determined.

| Area | Reason text |
| --- | --- |
| Sensor or evidence collection | `sensor not reporting`, `sensor report is stale`, `evidence invalid`, `sensor isolation failed`, `permission denied` |
| Observation preparation and continuity | `index not built yet`, `worker stalled`, `evidence truncated`, `evidence incomplete` |
| Container | `container generation unverified`, `container not observed` |
| Package information | `package database parse failed`, `package database absent`, `package database error`, `package database unsupported` |
| File attribution | `no file list for this package`, `multiple owners`, `file replaced`, `version mismatch` |
| Language-package attribution | `ecosystem not mapped`, `binary path unknown` |
| Other | `unknown` |

### Runtime evidence {#runtime-evidence}

Detailed cards show `Evidence:` after `Runtime:`.
Exposure, privilege, and the last confirmation time also appear when available.

| Display | Meaning |
| --- | --- |
| `running as` · `loaded by` | Program confirmed to be running or loading the package |
| `executed` · `library loaded` | Activity confirmed through events |
| `in running binary` · `binary executed` | Observation of a binary containing the language package |
| `runtime is running` · `runtime executed` | Observation of the runtime associated with the language package |
| `published on all interfaces` | Port published on all host interfaces |
| `published on loopback only` | Port published on host loopback |
| `listening (not published)` | Listening without publishing a port |
| `runs with elevated privilege` | Evidence of execution with elevated privilege |
| `last confirmed` | Time use was last confirmed |

Detailed in-use displays show observations from a representative container.
When multiple programs use a package, activity and the `processes:` list may appear separately.

```text
Runtime: ▶ in use
Evidence: running as /usr/sbin/nginx
Exposure: published on all interfaces · runs with elevated privilege · last confirmed 06-24 09:00
```

### Muted findings {#muted-display}

Muted findings have no individual lines and appear as a count instead.

```text
🔇 Muted — no fix available and not in use for 7+ days: 3
```

- Excluded from `Priority:` counts and current unresolved priority counts
- Excluded from current unresolved `CRITICAL` and `HIGH` counts when triage is disabled
- Included in “not observed” runtime counts, so those counts overlap with the muted count
- Included in retained unresolved counts when previous history is retained and muting cannot be evaluated this cycle

When notifications resume, a label such as `Change: ↩️ Unmuted (now in use)` appears.
If a change such as a newly available fix or a priority escalation applies, that change's label is used.

See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for muting conditions and reasons notifications resume.

## Reading warnings {#warnings}

Warnings describe limitations when interpreting the current results.
Scan, threat intelligence, and Sensor warnings cover different areas.

### Scan warnings {#scan-warnings}

| Display | Meaning |
| --- | --- |
| `⚠️ Scan failures` | Scan failure or digest or platform verification failure |
| `identity unconfirmed: scanned by reference` | Reference containing an identity that could not be identified by a Docker config digest at discovery |
| `⚠️ identity unconfirmed: scanned by reference — reference list` | Annotation listing those references |
| `⏳ unconfirmed this cycle, holding previous findings — reference list` | Kubernetes references containing targets whose identities could not be pinned despite successful scans |

Identity-unconfirmed annotations use discovery information independently of scan results.
They may list every Kubernetes reference.

The holding annotation may also appear for references without previous history.
References whose scans all failed this cycle are excluded from this holding list.

Slack's identity-unconfirmed annotation and each image's identity verification result in the webhook cover different scopes.
See [Image identity](webhook-reference.md#image-identity) for the corresponding data and [Failed scans](scan-logic.md#scan-failures) for retention behavior.

### Threat intelligence warnings {#intel-warnings}

| Display | Limitation |
| --- | --- |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | Neither source is available |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | KEV information is unavailable |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | EPSS information is unavailable |
| `Intel data is N day(s) old (feeds unreachable).` | Previously retrieved information is used because it could not be refreshed |

See [Section order](#section-order) for warning placement and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for the effect on decisions.

### Sensor warnings {#sensor-warnings}

When Sensor information has a problem, a warning appears near the beginning of the channel report.

```text
⚠️ Runtime evidence unavailable: the Sensor has not reported yet
```

The following phrases describe the reason.

- `the Sensor has not reported yet`
- `the evidence file failed validation`
- `the Sensor's last report is stale`
- `the Sensor's reads are being denied`
- `the Sensor's sandbox failed to start`
- `the Sensor's sandbox is running degraded`
- `the Sensor is degraded`

Even when the Sensor status is healthy, unavailable eBPF event observation produces a warning such as the following.

```text
⚠️ Short-lived programs are not observed (eBPF unavailable: kernel unsupported); using sampling only
```

Event observation reasons are `kernel unsupported`, `BTF missing`, `permission denied`, `attach failed`, `cgroup v1`, and `unknown`.
See [Runtime usage](runtime-usage.md) for Sensor status meanings and observation limits.
