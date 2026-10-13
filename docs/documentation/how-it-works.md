# How KestreLynx works

KestreLynx uses Trivy scan results for running images to report changes since the previous scan and findings that remain unresolved. For Docker and Compose, [remediation plans and pull requests (experimental)](remediation.md) support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

- The Slack channel shows changes since the previous scan in the default `diff` mode.
- Slack Bot threads show the current state, and the generic webhook provides all findings and changes.
- See [Configuration](configuration.md) for setup instructions.

The overall scan flow is:

```text
Docker host / Kubernetes cluster
    │
    ▼
Discover running containers (Chapter 1)
    │
    ▼
Derive distinct images by identity (Chapter 1)
    │
    ▼
Scan each image with Trivy (Chapter 1)
    │
    ▼
Group findings by image, package, and fix status (Chapter 2)
    │
    ▼
Assign priority using CISA KEV and EPSS (Chapter 3)
    │
    ▼
Build a remediation plan when enabled (Docker only)
    │
    ▼
Optionally update dependencies in work containers and create GitHub pull requests
    │
    ▼
Compare with persisted state to detect changes (Chapter 4)
    │
    ├── Slack summary: changes since the previous scan (Chapters 5 and 6)
    ├── Slack thread: current unresolved findings (Chapter 6)
    └── Generic webhook: structured current state and diff (Chapter 7)
```

[Remediation plans and pull requests (experimental)](remediation.md) cover
published image tags, Dockerfile base images, and language packages managed
with npm, pnpm, pip, or uv. Both are disabled by default and work without a
Sensor. Planning reads sources and compares image scans under matching
conditions; it does not write to GitHub or start work containers. With pull
requests enabled, language updates run in work containers and their output
and before/after dependency-file scans are checked before proposing a PR.
Candidate comparisons and PR creation do not resolve findings in the running-image report.

## 1. Scan cycle

Scans cover images used by running containers. One instance monitors one Docker host or one Kubernetes cluster. Stopped containers and images not used by a running container are outside the scan scope.

Identical reference-and-identity pairs are combined into one entry. The same reference with different digests produces separate entries. Each image is scanned with Trivy, and findings are grouped by package.

`scan.severity` selects the severity levels to include. The default is `HIGH,CRITICAL`.

### Image and container identification

Docker and Kubernetes scan targets depend on the identity information available. Docker connections use `docker.socket`. Set `kubernetes.enabled: true` to monitor Kubernetes.

Kubernetes discovery includes running containers and currently running init containers with `restartPolicy: Always`. Ordinary init containers and ephemeral containers are excluded. `kubernetes.namespaces` can restrict discovery to selected namespaces.

Container and workload information is included only in the generic webhook. If the associated workload cannot be identified, it is recorded as `unknown`.

### Discovery retries

If listing containers fails, the cycle ends without changing saved state and retries on the next scheduled cycle. In Kubernetes, even a partial listing failure discards the partial results and leaves state unchanged for that cycle.

### Scan targets and identity verification

When an image's identity is known, the scan targets that identity. A result that does not match the requested digest or platform is treated as a scan failure.

When the identity is unknown, the image is scanned by reference and annotated with `identity unconfirmed: scanned by reference`.

### Failed scans and unconfirmed identities

A failed scan retains the target's previous findings. Unverified results cannot resolve previous findings. Failure to scan one image does not stop the remaining scans, and failures appear under Scan failures in Slack.

When only some identities under the same reference fail, previous CVE IDs, fix availability, and the higher priority are retained. In Kubernetes, even a successful reference scan retains previous findings and does not resolve ordinary packages or clear EOL packages.

### Package-level grouping

Findings are grouped by image reference and identity, package, and canonical fix status. Different fix statuses produce separate groups even for the same package.

Each group deduplicates CVE IDs and retains versions, CRITICAL and HIGH counts, reference URLs, and the highest priority in the group. State and diffs are keyed by image reference and package.

When a reference has multiple identities, Slack distinguishes them with labels such as `web:1.0 (3f2a9c1b7d4e)` or `web:1.0 (3f2a9c1b7d4e linux/amd64)`.

??? note "Technical details"

    Scan results are obtained as JSON from the Trivy CLI.

    Docker can start a container's process before marking it as running in `GET /containers/json`. On the process's first listing, KestreLynx retries every 200 ms until its own container appears, with a total limit of 5 seconds including API calls, then scans the returned list. This prevents a startup listing delay from incorrectly resolving findings for its own image. At the limit, it logs a warning and continues with the last list; if no list was obtained, it returns a listing error.

    The container ID comes from `/containers/<64-character ID>/` in the mount-source path for `/etc/hostname` in `/proc/self/mountinfo`, with `/etc/resolv.conf` and `/etc/hosts` as fallbacks. No wait occurs when the ID is unknown, such as outside Docker or in Kubernetes, or on subsequent listings.

    | Item | Docker | Kubernetes |
    | --- | --- | --- |
    | Container listing | `GET /containers/json`: `Image`, `ImageID`, `Names`, and `Labels`. | Read-only LIST requests for nodes, pods, replicasets, and jobs. `kubernetes.namespaces` applies to all except nodes. |
    | Container names and running status | Leading slashes and link aliases are removed from `Names`. | Regular containers are considered running when `state.running` is present. |
    | Image identity | Config digest from `ImageID`, accepted only as `sha256:` followed by 64 hexadecimal digits. | Reference from `containerStatus.image`. Registry digest from `<repo>@sha256:<hex>` in `containerStatus.imageID`, optionally prefixed with `docker-pullable://`. A bare `sha256:...` uses a reference scan. |
    | Platform | Not applicable. | The node's `status.nodeInfo.operatingSystem` and `architecture`. No variant is inferred. The platform also contributes to image identity. |
    | Workload resolution | Compose when both `com.docker.compose.project` and `com.docker.compose.service` are valid. | `ownerReferences` resolves to a Deployment, StatefulSet, DaemonSet, CronJob, Job, or bare Pod. |
    | Trivy scan method | Local image selected by config digest with `--image-src docker`. | When the registry digest and platform are known, `<repo>@sha256:<hex>` with `--image-src remote` and `--platform <os>/<arch>`. |
    | Scan result verification | `Metadata.ImageID` must match the requested config digest. | `Metadata.RepoDigests` must contain the requested digest, and `Metadata.ImageConfig` must match the requested OS and architecture. |

    - Kubernetes LIST requests use pages of up to 500 objects and retry each page independently. Transport errors, HTTP 429, and server errors are retried up to 3 times with `Retry-After` and exponential backoff; HTTP 410 restarts the listing up to 2 times; HTTP 401 causes the ServiceAccount token to be read again.
    - The ServiceAccount token and CA are read each scan cycle.
    - Aliases for the same identity share only results that successfully confirm that identity. After a failed or unconfirmed scan, the next alias is scanned again.
    - When only some identities under the same reference fail, `content_id` is cleared and the union of CVE IDs is retained.
    - Slack considers a reference confirmed only when every identity under it was identified by a Docker config digest at discovery. This check is independent of scan results, and Kubernetes registry digests count as unconfirmed.

## 2. Severity, fix status, and EOL

Severity, fix status, and priority describe different information.

- Severity describes the potential impact reported by Trivy and advisory data.
- Fix status describes fix availability and support status reported by Trivy.
- Priority describes the urgency of review based on exploitation evidence.

### Status handling

Fix status comes from Trivy's `Status` and is not inferred from fix availability. A missing or empty `Status` is treated as `unknown`. Unrecognized statuses are included in `affected` rather than excluded.

When the original status differs from the canonical group status, it is available in the webhook's `vulns[].status`.

| Trivy status | Meaning in KestreLynx |
| --- | --- |
| `fixed` | A fixed version is available. Included in `fixed`. |
| `affected` | The package is affected, but no fix is available. Included in `affected`. |
| `will_not_fix` | No current plan to fix it on the target platform. Included in `will_not_fix`. For OS packages, this is the policy for the target OS release; it does not mean that a fix is unavailable from the software's developer or in another OS release. |
| `fix_deferred` | A fix is deferred. Included in `affected`. |
| `end_of_life` | The OS distributor treats the package as outside its support scope and has not checked whether the CVE applies, so no fix is provided. Included in EOL package. |
| `unknown` | The fix status is unknown. Included in `affected`. |
| `under_investigation` | The vulnerability is under investigation. Included in `affected`. |
| `not_affected` | Excluded from grouping, notifications, and priority classification. |

### EOL base and EOL package

EOL describes states related to the end or scope of support. Package `end_of_life` means the OS distributor treats the package as outside its support scope and has not checked whether the CVE applies. These states are handled separately from CVE priority. Base OS and package status appear as follows.

- EOL base indicates that Trivy reported the base OS as end of life and appears at the top.
- EOL package contains packages with `end_of_life` status and appears after EOL base, whether triage is enabled or disabled.

The usual response to EOL base is to rebuild on a supported base image. If the base OS is also EOL, the reference's EOL packages are folded into the base-OS line with `includes N end-of-life package(s)`.

Act now EOL packages show their details in Act now whether or not they are folded, including during degraded triage. Unfolded packages show `🚨 see Act now` in the EOL section, so EOL package and Act now counts can overlap.

EOL packages with Watch or Low priority appear only in their dedicated EOL section and are not repeated in the ordinary Watch or Low sections.

??? note "Technical details"

    - If the same CVE ID has multiple original statuses within one group, the canonical group status takes precedence when present; otherwise, the lexically smaller status is retained.

## 3. Exploitation-based triage

Triage indicates review priority based on exploitation evidence and is enabled by default. Each package group receives the highest priority of any CVE in that group.

- CISA KEV identifies vulnerabilities known to have been exploited in the wild.
- EPSS estimates the probability of exploitation activity in the next 30 days.

EPSS does not establish impact or guarantee exploitability in the monitored environment.

### CVE priority rules {#cve-priority-rules}

Normal triage assigns the following priorities using KEV membership, EPSS, and severity. `triage.act_now_epss` and `triage.watch_epss` configure the thresholds.

| Priority | Default condition |
| --- | --- |
| **Act now** | Listed in KEV, or EPSS is at least `0.10` (10%). |
| **Watch** | Not Act now, and EPSS is at least `0.01` (1%) or severity is CRITICAL. |
| **Low** | No rule above matched. This includes HIGH findings below the EPSS threshold and not in KEV. |

If no EPSS score is available, EPSS conditions are skipped rather than treating the score as 0. The KEV ransomware-campaign flag is displayed as evidence but does not create a separate priority.

Fix status affects priority as follows.

| Fix status | Relationship to priority |
| --- | --- |
| All reportable statuses | Act now is retained. When no fix is available, consider mitigation, replacement, or a supported version. |
| `will_not_fix` | Watch is reduced to Low during normal triage. |
| `affected`, `fix_deferred`, `under_investigation`, `unknown` | The same priority rules apply. |
| `end_of_life` | The reduction from Watch to Low does not apply. |
| All reportable statuses | Low is retained regardless of fix status. |
| `not_affected` | Excluded from priority classification. |

### Feeds and degraded operation

If intelligence refresh fails, triage continues using a validated cache for up to 7 days. The cache is stored in the `intel` directory beside `state.path` and refreshed after about 20 hours.

Limited source availability is handled as follows.

- If only one source is usable, triage continues with that source and the notification identifies the unavailable source.
- If neither source is usable, degraded triage assigns CRITICAL findings to Act now and other selected severities to Watch.

During degraded triage, nothing is classified as Low, and ordinary and EOL priority-escalation notifications are suppressed.

When `triage.discussion_links` is enabled, Hacker News discussions are added for Act now CVEs. A discussion must match the CVE ID and have at least 20 points. Set `triage.discussion_links: false` to stop sending CVE IDs for discussion searches.

Feed matching does not send the host's complete CVE list to external services.

??? note "Technical details"

    - KEV and EPSS are downloaded in bulk, and CVE IDs are matched locally.
    - Normal triage evaluates the priority table from top to bottom.
    - Discussion searches send only Act now CVE IDs to the Hacker News search API.

## 4. Diff state and change detection

In `diff` mode, the history in `state.path` is compared with current results to identify changes since the previous scan. The default state file is `/var/lib/kestrelynx/state.json`, and its directory should be persisted.

One state file holds one environment and must not be shared by multiple instances. Adding, changing, or removing `environment.name` does not reset history or first-seen dates.

Ordinary and EOL package state can coexist for the same image reference and package. Older state files load without conversion, but if `eol_packages` is absent, current EOL packages are reported as newly detected EOL packages.

### Changes included in the diff

For ordinary packages, notifications cover new findings, priority escalations, added CVEs, newly available fixes, and resumption after muting. If multiple changes apply at once, only one reason is reported.

- New means that the image reference and package combination was absent from the previous state.
- Escalated means that the priority rose above the saved maximum priority.
- New CVEs means that new CVE IDs were added to a known package.
- Now fixable means that no fix was previously available and at least 1 fix is now available.
- Unmuted means that a muted package no longer meets the muting conditions; newly available fixes, priority escalations, and added CVEs use their existing change labels.

Priority decreases are saved without notification, and later escalations use the saved value as their baseline. Moving from EOL back to ordinary findings alone does not count as New or New CVEs.

EOL package changes are reported independently of ordinary changes.

- Newly detected EOL means that no previous EOL record exists, including a move from ordinary findings or a return after EOL cleared.
- Escalation to Act now means that an EOL package rose from its saved EOL priority to Act now; missing saved priority, degraded triage, and a rise from Low to Watch do not qualify.
- New EOL CVEs means that new EOL CVE IDs were added to a known EOL package.

A package being “resolved” means that its findings have left the current scope; it does not prove that a patch was installed. A previous image reference and package combination is resolved when it is absent from both ordinary and EOL findings in the current successful scan.

Moving all ordinary findings to EOL does not resolve the package. A combination that disappears from both sides is counted once in Slack. If ordinary findings remain after EOL clears, Slack shows `no longer end-of-life` rather than treating the vulnerabilities as resolved.

Base-OS changes also report newly detected EOL and references no longer recorded as EOL.

Image replacement is a diff independent of package changes and is reported even for images without findings. It applies when the previous and current verified content-ID sets for the same reference are both nonempty and differ, such as when `:latest` points to new content. The first observation does not count as a replacement.

State keys include the image reference, including its tag, and package name. When an update changes a reference, such as `repo:sha-A` to `repo:sha-B`, KestreLynx carries the old reference's history over to the new reference before computing the ordinary diff if all of the following conditions hold.

- The same workload moves to a different reference in the same repository.
- The old reference is absent from the current observations, and the new reference is absent from the previous image records.
- Both references identify the same repository after removing tags and digests, preserving registry ports and treating `app` and `docker.io/library/app` as equivalent.
- The match is one-to-one across all candidates, both per reference and per shared workload, including candidates with failed or unconfirmed scans.
- The new reference's scan succeeds in full and confirms a single image identity, with no failed, partially failed, unconfirmed, or ambiguous result.
- The new reference has no existing history.

Workload matching uses the Compose project and service; the Kubernetes controller kind, namespace, name, and container name within the Pod; or the container name for a standalone Docker container with no known workload. A shared reference splitting into multiple references, or multiple references merging into one, does not qualify.

The carried history includes first-seen dates, priorities, CVE IDs, fix availability, EOL package records, base-OS EOL dates, and muting history. Added CVEs still produce ordinary changes such as `new_cves`, and packages that disappear are resolved under the new reference. Muting is reassessed after the transfer, so a new container with less than 7 days of observation can cause notifications to resume. The old image's metadata, including content IDs, does not become the new reference's current metadata.

If the conditions are not met, history stays with its original reference and ordinary per-reference rules apply: findings under a new reference are new, and findings under the old reference are resolved when they leave the scan scope, subject to the scan-failure and identity-retention rules. This includes rolling updates where both references are still running and older state files without workload records.

Resolutions and EOL clearances are not reported when previous state is retained because of fully or partially failed scans or unconfirmed Kubernetes identities.

### State persistence and repeated notifications

When a notification is required, state is saved only after delivery succeeds to every configured destination. Delivery is attempted to all destinations even if some fail, so a destination that succeeded may receive the same change again on the next cycle.

When no notification is required, the new state is saved directly.

The first run, a missing or corrupt state file, or a state-format version mismatch starts fresh and reports current packages as new. A corrupt state file also produces a log warning.

??? note "Technical details"

    - Ordinary package state stores the first-seen timestamp, CVE ID set, fix availability, maximum priority, and `content_id` for a single verified identity.
    - Package-state `content_id` is empty when the reference is ambiguous or some scans fail.
    - The state file's `images` map is keyed by reference and records sorted `content_ids`, `registry_digests`, `ambiguous`, `last_seen`, and `workloads`, the sorted list of distinct workload keys running that reference.
    - `workloads` is omitted when empty, and older state files without it are read as having no recorded workload keys.
    - Base-OS EOL first-seen timestamps are stored separately from ordinary package state.
    - EOL package first-seen-as-EOL timestamps, CVE ID sets, and maximum priorities are stored separately from ordinary package state.
    - The state-format version remains `1`.
    - Ordinary package changes are evaluated in the order New, Escalated, New CVEs, Now fixable, and Unmuted, with only the highest-precedence reason reported when several apply.
    - Ordinary comparisons also use previous EOL history.
    - EOL package changes are evaluated in the order newly detected EOL, escalation to Act now, and new EOL CVEs.
    - Retention caused by fully or partially failed scans or unconfirmed Kubernetes identities takes precedence over transitions between ordinary and EOL state.
    - State is written to a temporary file and then replaced atomically.

## 5. Notification conditions

The default `notify.mode: diff` reports changes and current unresolved counts. `notify_on_clean` (`notify.notify_on_clean`) controls whether cycles without vulnerabilities also send notifications.

- When findings exist and something changed, the notification includes changes and unresolved counts.
- When findings exist but nothing changed, a short heartbeat is sent.
- When the final finding is resolved, the notification includes the resolution and an all-clear status.
- When there are no findings or changes, `notify_on_clean: false` suppresses the notification.

Scan failures, image replacements, and reference updates with carried history trigger notifications even when there are no vulnerability findings or other changes.

When an unconfirmed Kubernetes identity causes previous package findings to be retained, including EOL packages, a notification is sent even if nothing changed. Retained base-OS EOL history alone does not meet this holding-notification condition.

On the weekday selected by `notify.full_report_day`, a full Slack report is added to cycles that qualify for notification. The default is Monday, and `never` disables it. Even on the weekly report day, no notification is forced for a cycle without findings or changes when `notify_on_clean: false`.

With `notify.mode: full`, diff state is not used, and every cycle with findings or scan failures sends the current report. Without either, `notify_on_clean: true` or the remediation conditions below can trigger a report.

With remediation enabled, both notification modes also report changes from the
last successfully delivered plan, including changes in plan availability or
saving failures. Generation timestamps alone do not count as changes.
Undelivered PR operation events and problems that block PR writes also trigger
delivery; blocking problems are reported each cycle while they persist.
Delivery failures leave the plan and operation events pending, so notifications
can repeat without repeating a successful PR creation.

See [Remediation plans and pull requests (experimental)](remediation.md) for
notification meanings and the checks described in pull requests.

## 6. Slack presentation

In diff mode, Slack channels show changes; in full mode, they show current unresolved findings. Bot threads show the current unresolved findings under `Everything open now`. Empty sections are omitted, and Low remains count-only even in a full report. The generic webhook provides the complete per-CVE data.

Channel messages and threads use Block Kit cards with a bold `◆ name` heading and labeled lines for each package. Language-package headings add one space followed by an ecosystem tag such as `[jar]`. Dividers separate sections and detailed cards, and each message includes a short summary for notification previews and screen readers. The examples below show visible text, with `───` for dividers and display names for links.

The image counts in the header have the following meanings.

- `images scanned` counts distinct reference-and-identity pairs, including failed scans; separate references count separately even when they share a scan.
- `affected` counts images with a selected vulnerability or an EOL base OS and excludes images with only a scan failure.

Times use the process's local timezone, configured through `TZ` in a container. `environment.name` appears only in the channel header.

### Notification language {#notification-language}

`notify.language` accepts `en` (default) or `ja`; other values are configuration
errors. `notify.language: ja` translates all fixed text in Slack channel
messages and threads: headings, section descriptions, upgrade-risk labels,
change types, Open now, warnings, runtime usage, muting, thread structure,
and guidance lines.

CVE IDs, package names and versions, image names, severity words such as
CRITICAL and HIGH, Trivy CVE descriptions (Title), scan-failure error messages,
and Hacker News discussion link names remain unchanged. Generic webhook JSON
remains in English regardless of this setting.

| English | Japanese notification |
| --- | --- |
| Act now | 今すぐ対応 |
| Watch | 要監視 |
| Low | 低優先度 |
| in use | 使用中 |
| not observed | 使用が確認されない |
| unavailable | 判定できない |
| Muted | 通知オフ |
| Installed | 現在 |
| Fixed in | 修正版 |
| Upgrade risk | 更新の注意度 |
| Findings | 検出件数 |
| Top CVE | 代表CVE |
| Exploitation | 悪用情報 |
| Summary | 説明 |
| References | 参照 |
| Other CVEs | ほかのCVE |
| Runtime | 使用状況 |
| Evidence | 観測根拠 |
| Exposure | 公開状態 |
| Privilege | 権限 |
| Last seen | 最終確認 |
| Change | 変化 |
| Image | イメージ |

An excerpt from a Japanese diff notification showing a priority escalation:

```text
───
イメージ: web:1.0

◆ openssl
変化: ⬆️ 今すぐ対応に優先度昇格
現在: 3.0.7
修正版: 3.0.11
更新の注意度: 🟢 ディストリのセキュリティパッチ
検出件数: CRITICAL 1 / HIGH 0

代表CVE: CVE-2031-0001 · CRITICAL · EPSS 94%
悪用情報: CISA KEV (実際の攻撃で悪用あり) · 🧨 ランサムウェア攻撃
参照: アドバイザリ · ベンダーのアドバイザリ
```

### Section order

Diff notifications show changes since the previous scan, while current-state reports show unresolved findings by EOL status and priority. Each notification uses the following display order.

- Diff notifications use this order: common header → image content changes → image reference updates → new EOL base → EOL package changes → intelligence-source warnings → ordinary new or changed findings → resolutions and EOL clearances → weekly report or scan failures and Open now → identity-unconfirmed and holding annotations → Bot report link.
- Current-state reports use this order: EOL base → unfolded EOL package → Act now → Watch → Low → scan failures and intelligence-freshness warnings → identity-unconfirmed and holding annotations.
- Bot threads use this order: EOL base → EOL packages → ACT NOW → WATCH → LOW.

Reference updates appear after the `🔄 Image content changed` section in a separate section without a heading, with one line per update.

```text
🔄 Image reference updated: repo sha-A → sha-B (history carried over)
```

Each line shows the repository followed by the old and new tags. A digest-pinned reference without a tag shows a shortened digest, and a reference with neither a tag nor a digest shows `latest`. The preview text includes `🔄 N reference update(s)`. The `🔄 Image content changed` line continues to report content changes under the same reference.

Warnings about unavailable intelligence sources appear immediately after the current-state report's Priority line, before the EOL sections.

Ordinary new and changed entries are sorted by priority, image name, and package name. When runtime usage and triage are enabled, packages in use and their images appear first within the same priority; usage does not change priority. `New since last scan (N)` counts ordinary image reference and package combinations that changed.

Act now EOL changes are shown individually. Other EOL changes are summarized as counts for each existing EOL base-OS reference. When a base OS and its packages become newly EOL in the same cycle, packages other than Act now are folded into the base-OS line and excluded from the EOL package diff heading's count.

### Open now and counts

Open now shows unresolved state after the latest scan, including retained records. EOL counts appear before priority counts and use the following units.

- EOL base counts retained EOL base-image references.
- EOL package counts image reference and package combinations not folded into a base OS.
- Act now, Watch, and Low count each reference and package once, using Act now if either its ordinary or EOL findings are Act now, and otherwise using its ordinary priority.

EOL Watch and Low findings do not contribute to priority counts. EOL package and Act now counts can overlap.

The current-state report's Priority line counts package groups by fix status, so one package may contribute more than once.

With `runtime.mute_unfixable_not_in_use: true`, eligible findings are omitted
from Slack lines and from priority counts in the Priority line and Open now.
A `🔇 Muted — no fix available and not in use for 7+ days: N` line shows the muted
count without changing priority. Conditions and resumption reasons are described
in [Runtime usage](runtime-usage.md#muting-findings-without-a-fix).

Open now varies with current findings and retained state.

- If the current report contains findings or EOL base images, counts are shown.
- `🎉 Open now: none — all clear` appears only when neither the current report nor retained state contains findings and no unconfirmed-identity holding condition applies.
- If the current report has no findings or EOL base images and packages are retained because of unconfirmed Kubernetes identities, an unconfirmed holding status is shown.
- Otherwise, if the current report has no findings but records are retained, a holding status is shown until the next successful scan.

### Unresolved age

The heartbeat's age is measured from the oldest first-seen date among included items. It shows the age after 1 day and adds a clock after 14 days. Retained records are included.

- With triage enabled, the age includes ordinary Act now and Watch findings, EOL base images, unfolded EOL packages, and folded EOL packages with Act now priority.
- With triage disabled, the age includes all ordinary packages and EOL records.

With triage enabled, ordinary Low findings are excluded, and the label remains `oldest act-now/watch unresolved N day(s)` even when EOL records contribute. With triage disabled, the label is `oldest unresolved N day(s)`.

EOL packages use their first-seen-as-EOL date. Folded EOL packages other than Act now use the base OS's first-seen-as-EOL date. Act now EOL packages contribute their own first-seen-as-EOL date even when folded.

### Label meanings

Labels identify changes, review priority, and reasons results could not be confirmed. Green upgrade icons describe only the type of version change and do not guarantee safety.

CRITICAL and HIGH count distinct CVE IDs within each package and fix-status group.

| Label | Meaning |
| --- | --- |
| `⛔ EOL base` | The base OS is end of life. |
| `⛔ EOL package` | A package with `end_of_life` status: the OS distributor treats it as outside its support scope and has not checked the selected CVEs. |
| `⛔ N EOL base` | EOL base-image count in the Priority line. |
| `⛔ N EOL package` | EOL group count in the Priority line, excluding groups folded into a base OS. |
| `🚨 N act now` | Act now group count in the Priority line, including Act now EOL groups. |
| `⛔ Package end-of-life (N) — vendor reports these CVEs as out of support for this release` | Current-state EOL package section. |
| `⛔ New: package end-of-life (N) — vendor reports these CVEs as out of support for this release` | Newly detected EOL packages, escalations to Act now, and added CVEs. |
| `⛔ EOL packages (N) — vendor reports these CVEs as out of support for this release` | EOL package section in a thread. |
| `🚨 Act now` | Known exploitation or EPSS at or above the threshold; also includes CRITICAL findings during degraded triage. |
| `👀 Watch` | Findings to review and monitor. |
| `🔕 Low` | No signal reaches the threshold; this does not mean there is no vulnerability. |
| `🔄 Image content changed` | A verified content-ID set changed. |
| `🔄 Image reference updated` | A workload moved to another reference in the same repository, carrying its detection history over. |
| `🆕 New since last scan` | New packages and changed known packages. |
| `✅ Resolved since last scan` | Resolved packages and EOL base images, and cleared EOL package records. |
| `📌 Open now` | Unresolved state after the latest scan. |
| `📌 Open now: unconfirmed — holding previous findings until re-confirmed` | No current findings, with previous ordinary or EOL package findings retained because of unconfirmed Kubernetes identities. |
| `📌 Open now: not re-scanned — holding previous findings until the next successful scan` | No current findings, with previous records retained outside the unconfirmed holding condition. |
| `⏰ oldest ... unresolved` | An included item has been unresolved for at least 14 days. |
| `<ref> — identity unconfirmed: scanned by reference` | A reference includes an identity that was not identified by a Docker config digest at discovery. |
| `<ref> (<12hex>)`, `<ref> (<12hex> linux/amd64)` | Digest and platform distinguish multiple identities under one reference. |
| `⚠️ identity unconfirmed: scanned by reference — a, b` | References containing identities not identified by Docker config digests at discovery, independent of scan results; this may list every Kubernetes reference. |
| `⏳ unconfirmed this cycle, holding previous findings — a, b` | Kubernetes references containing targets whose remote scans succeeded without pinning their identities; references with only failures are excluded, and the line may appear even without history. |
| `⚠️ Scan failures` | Failed scans, including digest or platform verification failures. |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | Neither source is usable, so triage uses severity alone and does not reduce anything to Low. |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | Triage uses EPSS and severity, and Act now detection may be incomplete. |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | Triage uses KEV and severity. |
| `_Intel data is N day(s) old (feeds unreachable)._` | Refresh failed, and a validated stale cache is in use. |
| `📋 Weekly full report` | Current-state report for the configured weekday. |
| `_Changes since the last scan._` | Italic line immediately after `N images scanned, N affected` in diff-mode channel messages with changes; omitted on unchanged and weekly-full-report days. |
| `_Everything currently open._` | Italic line in the same position in full-mode channel messages (`notify.mode: full`). |
| `📊 *Everything open now — YYYY-MM-DD HH:MM*` | Heading for current unresolved findings in a Bot thread. |
| `📊 Everything open now is in this message's thread ↓` | Context footer at the end of the first channel message when a thread is posted. |
| `🔗 Everything open as of the last report → thread` | Context footer on the first channel message when no new thread is posted and a valid previous report link fits; the linked findings are from the time of that report. |
| `_Details in the generic webhook payload._` | LOW detail guidance shown only when a generic webhook is configured; weekly full reports do not contain LOW details. |
| `✅ Actionable now (fixed)` | Fix-available section when triage is disabled, separate from Act now. |

| Package or change label | Meaning |
| --- | --- |
| `🟢 distro security patch` | Upgrade-risk value for an OS package update treated as a distribution revision without SemVer comparison. |
| `🟢 low-risk` | Upgrade-risk value for a language-package change that does not increase the major version. |
| `🟠 major version bump — needs care` | Upgrade-risk value for a language-package change that increases the major version and may break compatibility. |
| `⚪ risk unknown` | Upgrade-risk value when versions could not be parsed reliably. |
| `[<ecosystem>]` | Language-package ecosystem from Trivy, such as `[python-pkg]`, `[npm-pkg]`, `[gobinary]`, or `[jar]`, placed after one space following the package heading; applies independently of the Sensor, and OS packages have no tag. |
| `[lang]` | Language-package fallback only when the Trivy type is unknown. |
| `Fixed in: none` | No fixed version is available, with guidance appended in detailed cards. |
| `Change: ⬆️ escalated to ACT NOW/WATCH` | A known package's maximum priority increased. |
| `Change: new CVEs: CVE-…, CVE-… (+N more)` | Added CVEs are linked, with up to 3 IDs shown and the remainder shown as a count. |
| `Change: fix now available` | No fix was previously available, and at least 1 fix is now available. |
| `Change: ↩️ Unmuted (<reason>)` | Notification resumed after muting, unless a newly available fix, a priority escalation, or added CVEs use an existing change label. |
| `Fixed in: none — end-of-life: no fix planned for this release` | Indicates `end_of_life`: the OS distributor treats the package as outside its support scope and has not checked the selected CVEs. |
| `Details: 🚨 see Act now` | The EOL package's details appear in Act now. |
| `includes N end-of-life package(s)` | Count of EOL groups folded into the base-OS line. |
| `includes N newly end-of-life package(s)` | Count of newly EOL packages other than Act now folded into a new EOL base. |
| `N package(s) newly end-of-life (base OS already EOL)` | Count of newly EOL packages other than Act now under an existing EOL base. |
| `N end-of-life package(s) with new CVEs (base OS already EOL)` | EOL packages other than Act now under an existing EOL base gained CVEs. |
| `no longer end-of-life` | Ordinary findings remain after EOL clears. |

| Evidence or reference label | Meaning |
| --- | --- |
| `CISA KEV (exploited in the wild)` | Listed in the usable KEV catalog. |
| `EPSS N%` | EPSS probability; missing scores use `n/a`, very small values use `<0.1%`, and very large values use `>99%`. |
| `🧨 ransomware campaign` | CISA identifies known use in ransomware campaigns. |
| `severity only (intel unavailable)` | Neither source is usable, so only severity is used. |
| `Fixed in: none — consider mitigation` | An `affected` group has no fix, so mitigation should be considered. |
| `Fixed in: none — no fix planned for this OS release, consider replacing` | The group is `will_not_fix`, so replacement or another response should be considered. |
| `Fixed in: none — end-of-life: no fix planned for this release, consider a supported version` | A supported version should be considered for the EOL package. |
| `advisory` | Trivy's primary advisory, linked on the `References:` line. |
| `vendor advisory` | A vendor or CISA reference from KEV notes, linked on the `References:` line. |
| `💬 HN (N pts)` | A qualifying Hacker News discussion and its point count, linked on the `References:` line. |

### Runtime usage

[Runtime usage](runtime-usage.md) is an experimental feature.

With `runtime.enabled: true`, Slack marks findings for packages observed in use.
Usage does not change priority. Within each priority, packages in use and images
containing them appear first. With triage disabled, results are not reordered.

Act now cards show usage in a separate section with `Runtime:` and `Evidence:`
lines, followed by exposure, privilege, and the last confirmation time when
available. Watch and compact diff entries show a short `Runtime:` line only
when use is observed.

The following excerpt shows the Act now and Watch sections of a full report:

```text
───
🚨 Act now (1) — exploited or likely to be
Image: web:1.0

◆ openssl
Installed: 3.0.7
Fixed in: none — consider mitigation
Findings: CRITICAL 1 / HIGH 0

Top CVE: CVE-OPENSSL · CRITICAL · EPSS n/a
Exploitation: CISA KEV (exploited in the wild)
References: advisory

Runtime: ▶ in use
Evidence: running as /usr/sbin/nginx
Exposure: published on all interfaces · runs with elevated privilege · last confirmed 06-24 09:00
───
👀 Watch (2) — not urgent, keep an eye on

Image: api:2.0
◆ setuptools [python-pkg]
Installed: 53.0.0 · Fixed in: none
Findings: CRITICAL 0 / HIGH 1
Top CVE: CVE-SETUP · EPSS 2%
Runtime: ▶ in use (running)

Image: web:1.0
◆ curl
Installed: 8.0.0 · Fixed in: none
Findings: CRITICAL 0 / HIGH 1
Top CVE: CVE-CURL · EPSS 2%
```

- Low's count line ends with ` · ▶ N in use` when N > 0.
- Diff entries use the same detailed or compact runtime layout as their package cards.
- With triage disabled, the full channel view adds a short `Runtime:` line for packages in use without reordering them.

| Runtime label | Meaning |
| --- | --- |
| `Exposure: published on all interfaces` | Published on all host interfaces. |
| `Exposure: published on loopback only` | Published only on host loopback. |
| `Exposure: listening (not published)` | Listening without a published port. |
| `runs with elevated privilege` | UID 0 without a user namespace, dangerous capabilities, or privileged mode, shown on the `Exposure:` line or a separate `Privilege:` line. |
| `last confirmed 06-24 09:00` / `Last seen: 06-24 09:00` | Time use was last confirmed, appended to exposure or privilege information or shown on its own line. |

When several programs use one OS package, the English display can read:

```text
Runtime: ▶ in use
Evidence: running; loaded as a library; processes: /usr/bin/helper, /app/server
Privilege: runs with elevated privilege · last confirmed 06-24 09:00
```

Bot threads show runtime information after the CVE details for each ACT NOW
and WATCH package. For example, an in-use language package has:

```text
Runtime: ▶ in use
Evidence: runtime is running /usr/bin/python3.11
Last seen: 06-24 09:00
```

A package without observed use has:

```text
Runtime: ▷ not observed
```

Not observed describes only the observation window and does not mean unused,
including for containers already running before the Sensor starts.
There is no additional short-lived-program annotation on this line.
Insufficient evidence is shown as
`Runtime: ▷ runtime evidence unavailable (<reason>)`; the reason values are
listed in the webhook section below. The LOW section shows
`▶ in use among low: N`.

Sensor problems add a warning line at the beginning:

```text
⚠️ Runtime evidence unavailable: <reason>
```

| Sensor status | Warning reason |
| --- | --- |
| `not_reporting` | `the Sensor has not reported yet` |
| `evidence_invalid` | `the evidence file failed validation` |
| `stale` | `the Sensor's last report is stale` |
| `permission_denied` | `the Sensor's reads are being denied` |
| `isolation_failed` | `the Sensor's sandbox failed to start` |
| `isolation_degraded` | `the Sensor's sandbox is running degraded` |
| `degraded` | `the Sensor is degraded` |

When eBPF is unavailable, the warning reads:

```text
⚠️ Short-lived programs are not observed (eBPF unavailable: <reason>); using sampling only
```

The reason is `kernel unsupported`, `permission denied`, `attach failed`,
or `cgroup v1`. Sampling continues, but short-lived programs are not observed.

See [Runtime usage](runtime-usage.md) for package usage rules, Sensor setup,
status meanings, and observation limits.

### Details and threads

Act now uses detailed cards with sections for package versions and counts, the strongest CVE and references, and runtime evidence when available. Dividers separate detailed cards and report sections. Watch and compact diff entries use one section per package, with installed and fixed versions on the same line, findings, a representative CVE when available, and a short runtime line only for packages in use.

Detailed cards use `Upgrade risk:` for the update assessment, while compact cards put the same value in parentheses after the fixed version. Priority escalations, newly available fixes, added CVEs, and notification resumption appear on a `Change:` line.

In detailed channel cards, other CVEs are summarized as `(+N more CVE(s) in this package)` on the `Top CVE:` line. Compact diff entries show `Top CVE: CVE-ID · KEV/EPSS`, or `Top CVE: CVE-ID · SEVERITY` when intelligence is unavailable. CVE IDs on the `Top CVE:`, `Other CVEs:`, and `Change:` lines link to NVD, while other identifiers, such as GHSA and DLA IDs, appear as plain text.

Thread dividers appear only between packages and before headings where the section or image changes. No divider separates a heading from the first package below it, including repeated headings in continued replies. Each package contains sections for package versions and counts, CVE details, and runtime information when available. `Summary:` contains Trivy's Title, `References:` contains advisory and discussion links, and `Other CVEs:` lists up to 8 other IDs with the remainder summarized as `(+N more)`. Empty sections are omitted.

A context line at the end of the card gives its age as `⏱ open N day(s) · first seen YYYY-MM-DD`, or `⏱ first seen today` on the day of detection. An Act now thread card reads as follows:

```text
◆ openssl
Installed: 3.0.7
Fixed in: 3.0.11
Upgrade risk: 🟢 distro security patch
Findings: CRITICAL 1 / HIGH 0

Top CVE: CVE-2031-0001 · CRITICAL · EPSS 94%
Exploitation: CISA KEV (exploited in the wild) · 🧨 ransomware campaign
Summary: openssl: buffer overread
References: advisory · vendor advisory

⏱ open 20 day(s) · first seen 2026-06-04
```

Long channel reports and threads are split into multiple messages at package boundaries where possible. Continued messages repeat the section and image headings with `(cont.)`, or `(続き)` in Japanese, and channel continuation headers also include a part number such as `(cont. 2/3)`. The thread is attached to the first channel message.

The following settings configure delivery methods and destinations.

- `notify.slack_webhook_url` supports channel notifications only.
- `slack_bot_token` (`notify.slack_bot_token`) enables Bot delivery and, together with `slack_channel`, supports thread reports and links to the previous report.
- `slack_channel` (`notify.slack_channel`) selects the Bot's destination channel.

The Bot posts current state in a thread when findings change or the weekly report is due, and links to the latest report on unchanged days. It also creates a new thread on the first notification, after a channel change, or when no valid previous permalink exists.

When a thread is posted, the first channel message ends with the context footer `📊 Everything open now is in this message's thread ↓`. Without a new thread, a valid previous report link appears as `🔗 Everything open as of the last report → thread`. No footer appears if neither applies or if the previous permalink is too long to display.

An unchanged-day Open now excerpt is:

```text
📌 Open now: 🚨 3 act-now / 👀 1 watch / 🔕 3 low
⏰ oldest act-now/watch unresolved 20 day(s)
```

??? note "Technical details"

    - Slack messages use Block Kit `section`, `divider`, and `context` blocks with a short top-level `text` for notification previews and screen readers.
    - Rendering respects the limits of 50 blocks per message and 3,000 characters per text, splitting long lines and continuing oversized cards when needed.
    - Trivy titles, package names, versions, image references, error messages, and other scan-derived values escape Slack's `&`, `<`, and `>` control characters so text such as `<!channel>` does not trigger a mention.
    - The strongest CVE is selected by priority, whether an EPSS score is known, higher EPSS, and then CVE ID.
    - Bot and Incoming Webhook delivery post messages sequentially with a 1-second interval between posts.
    - HTTP 429 responses cause a wait based on `Retry-After`, capped at 30 seconds, with at most 3 attempts per message including the initial attempt.
    - If delivery fails partway through, already posted messages remain, the saved thread reference is not updated, and the next notification attempt posts the report again.
    - Slack's Block Kit presentation leaves the generic webhook JSON payload unchanged.

## 7. Generic webhook

The generic webhook provides the complete current report as structured JSON. It sends to `notify.generic_webhook_url` only when a cycle meets the notification conditions and includes changes in `diff` mode.

The payload includes Low findings, muted findings, EOL packages folded in Slack, containers, and workloads. It can be used alongside either Slack delivery method, but it does not convert the payload into a Discord- or Teams-specific message format.

The top-level `watch` array is a fix-status section, separate from the Watch priority. `not_affected` is excluded from every finding section.

### Top-level fields and environment

Top-level fields provide the scan time, environment, findings by fix status, failures, and changes. `environment` is always present; only `name` is omitted when no environment name is configured.

| Field | Type | Meaning |
| --- | --- | --- |
| `generated_at` | string | Scan time in RFC 3339 format. |
| `environment` | object | Adapter kind and optional environment name. |
| `environment.kind` | string | `docker` or `kubernetes`. |
| `environment.name` | string | Configured `environment.name`; omitted when unset. |
| `summary` | object | Counts and intelligence status. |
| `eosl_images` | array of strings or `null` | EOL base images; may be `null` when none. |
| `actionable` | array of image objects | Current `fixed` groups. |
| `watch` | array of image objects | Current groups normalized to `affected`. |
| `wont_fix` | array of image objects | Current `will_not_fix` groups. |
| `eol_packages` | array of image objects | All `end_of_life` groups; `[]` when empty. |
| `scan_errors` | array of objects | Per-image scan failures. |
| `scan_errors[].image` | string | Image reference. |
| `scan_errors[].error` | string | Error details. |
| `diff` | object | Current changes; omitted in full mode. |
| `runtime` | object | Optional Sensor status and usage counts when `runtime.enabled` is true. |
| `remediation` | object | Remediation plan and optional PR results; omitted when remediation is disabled. |

### Remediation plans and pull requests

The `remediation` object is independent of the Sensor and is included in both
full and diff payloads when enabled. It describes the current plan and PR
operation events awaiting delivery, without changing the meaning of ordinary
findings or `diff.resolved`.

| `remediation` field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Format version of this object, currently `1`. |
| `status` | string | `ok` when a plan was produced, or `unavailable`. |
| `unavailable_reason` | string | Reason no plan was produced; omitted otherwise. |
| `not_saved` | boolean | `true` when the plan could not be saved; omitted otherwise. |
| `generated_at` | string | Plan generation time in RFC 3339 format, when a plan exists. |
| `conditions` | object | Comparison scan conditions, including `trivy_version` and `severities` when available. |
| `limits` | object | Planning limits named `max_candidate_scans`, `max_baseline_rescans`, and `max_tag_pages`. |
| `usage` | object | Work counts named `candidate_scans`, `baseline_rescans`, `tag_pages`, and `registry_requests`. |
| `summary` / `items` | object / array | Published-image category counts and items with `current`, optional `candidate`, and comparison results. |
| `dockerfile_summary` / `dockerfile_items` | object / array | Base-image category counts and items, when present. |
| `language_summary` / `language_items` | object / array | Language-package category counts and items, when present. |
| `pull_request_summary` / `pull_requests` | object / array | PR processing status counts and units, when present. |
| `operations` | array | Undelivered PR operation events with `phase`, `kind`, `repo`, and optional `result` and `error`. |
| `problems` | array | Problems blocking PR writes, with `code` and optional `reason` and `detail`. |

Items use `category` and optional `reason` and `detail` to explain outcomes.
`dockerfile_items[].final_image_verified` is `false`: comparing base images
does not verify a rebuilt application image. Language items distinguish
`update_executed` and `post_update_check_executed` and can include `update`,
`source_check`, `artifacts`, and `pull_request`.
Manifest changes appear in `language_items[].update.manifest_edits`, with
`file`, `section`, `name`, `from`, `to`, and optional `major_change`.

See [Remediation plans and pull requests (experimental)](remediation.md) for
how to read notifications, PR checks, and their limits.

### Summary

`summary` provides image counts and, when triage is enabled, priority counts and intelligence status.

`priority_counts` includes EOL packages only when they are Act now. Its counts can therefore overlap with `eol_packages`, and the sum of its 3 values is not necessarily the total number of groups.

| `summary` field | Type | Meaning |
| --- | --- | --- |
| `images_total` | integer | Distinct reference-and-identity pairs, including failed scans. |
| `images_affected` | integer | Images with a selected vulnerability or an EOL base OS. |
| `priority_counts` | object | Integer package-group counts named `act_now`, `watch`, and `low`; present only with triage. |
| `intel` | object | Intelligence availability and freshness; present only with triage. |
| `intel.degraded` | boolean | Whether neither intelligence source is usable. |
| `intel.kev_ok` | boolean | Whether KEV data is usable. |
| `intel.epss_ok` | boolean | Whether EPSS data is usable. |
| `intel.stale_days` | integer | Age in days of stale intelligence data in use. |

### Images and containers

Each entry in `actionable`, `watch`, `wont_fix`, and `eol_packages` represents a reference and identity within that fix-status section. Even for an ambiguous reference, `containers` includes only containers matching that identity.

`registry_digests` is the union for the reference, while `identity_resolved` describes the individual entry.

| Field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Display reference. |
| `severity_counts` | object | Integer counts named `CRITICAL` and `HIGH`. |
| `findings` | array of finding objects | Package groups for this image and fix status. |
| `containers` | array of container objects | Matching running containers; `[]` when none. |
| `content_id` | string | `sha256:<hex>` from a confirmed Docker config-digest scan; omitted for registry-digest and reference scans. |
| `registry_digests` | array of strings | Union of `RepoDigests` for the reference from successful confirmed scans; never `null`. |
| `identity_resolved` | boolean | Whether this scan confirmed the running image's identity. |
| `scan_target_kind` | string | `content_id`, `registry_digest`, or `reference`. |
| `containers[].name` | string | Docker container name with the leading slash removed and link aliases excluded, or `<namespace>/<pod>/<container>` in Kubernetes. |
| `containers[].workload` | object | Workload association, always present. |
| `containers[].workload.kind` | string | `unknown`, `compose`, `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, or `pod`; always present. |
| `containers[].workload.group` | string | Compose project or namespace; omitted when unknown. |
| `containers[].workload.name` | string | Compose service, resolved workload name, or bare Pod name; omitted when unknown. |

### Findings and vulnerabilities

`findings` provides package groups, and `vulns` provides individual vulnerabilities. The `priority` field in both findings and vulnerabilities is omitted when triage is disabled.

When `vulns[].status` is omitted, it has the same value as the finding's `status`.

| Finding field | Type | Meaning |
| --- | --- | --- |
| `package` | string | Package name. |
| `class` | string | `os` or `lang`; independent of the Sensor. |
| `ecosystem` | string | Trivy type, such as `debian` or `python-pkg`; empty when unknown, independent of the Sensor. |
| `runtime` | object | Optional runtime evidence when `runtime.enabled` is true. |
| `installed` | string | Installed version. |
| `fixed` | string | Fixed version, or `""` when none is available. |
| `status` | string | `fixed`, `affected`, `will_not_fix`, or `end_of_life`. |
| `severity_counts` | object | Integer counts named `CRITICAL` and `HIGH`. |
| `upgrade_risk` | string | `""`, `distro_update`, `safe`, `caution`, or `unknown`. |
| `priority` | string | `act_now`, `watch`, or `low`. |
| `vuln_ids` | array of strings | Sorted vulnerability IDs. |
| `vulns` | array of vulnerability objects | Per-vulnerability details. |

| Vulnerability field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Vulnerability ID without Slack link markup. |
| `severity` | string | Trivy severity. |
| `status` | string | Original Trivy status, included only when it differs from the canonical group status; a missing original `Status` is represented as `unknown`. |
| `url` | string | Primary advisory URL; omitted when unavailable. |
| `title` | string | Short title supplied by Trivy; omitted when unavailable. |
| `kev` | boolean | Whether the vulnerability is in the usable KEV catalog. |
| `ransomware` | boolean | KEV ransomware-campaign flag; omitted when `false`. |
| `epss` | number or `null` | EPSS probability; `null` when unknown. |
| `priority` | string | `act_now`, `watch`, or `low`. |
| `refs` | array of reference objects | Additional references; omitted when empty. |
| `refs[].kind` | string | `vendor` or `discussion`. |
| `refs[].label` | string | Display label. |
| `refs[].url` | string | Reference URL. |

### Runtime evidence

Runtime fields are added only when `runtime.enabled` is true. All keys in this
section are optional. The top-level `runtime` object describes Sensor status,
observation rules, and usage counts:

```json
{
  "runtime": {
    "sensor_status": "ok",
    "heartbeat_at": "RFC3339",
    "interval_seconds": 30,
    "rules": {
      "os_packages": "executed_or_loaded_by_running_process",
      "lang_packages_binary": "in_running_binary",
      "lang_packages_runtime": "runtime_process_running"
    },
    "events_status": "ok",
    "events_reason": "",
    "counts": { "in_use": 0, "not_observed": 0, "unavailable": 0 }
  }
}
```

| `runtime` field | Type | Meaning |
| --- | --- | --- |
| `sensor_status` | string | `ok`, `degraded`, `stale`, `not_reporting`, `permission_denied`, `evidence_invalid`, `isolation_failed`, or `isolation_degraded`. |
| `heartbeat_at` | string | Sensor heartbeat time in RFC 3339 format. |
| `interval_seconds` | integer | Sampling interval in seconds. |
| `rules` | object | OS-package, compiled-language-package, and runtime-language-package rules shown above. |
| `events_status` | string | `ok` or `unavailable`; empty if the Sensor has not reported. |
| `events_reason` | string | Reason associated with event-observation status. |
| `counts` | object | Counts named `in_use`, `not_observed`, `unavailable`, and `muted`. |
| `counts.muted` | integer | Muted count. |

Each `findings[].runtime` describes package usage and container evidence.
The following fragment shows the fields; `process` requires an observation,
and `instances` is included only for language packages.

```json
{
  "runtime": {
    "usage": "in_use",
    "reason": "",
    "evidence_kinds": ["exe"],
    "events_coverage": "since_start",
    "exposure": "host_published_all",
    "high_privilege": true,
    "containers": [{
      "name": "web-1",
      "container_id": "<64hex>",
      "generation_started_at": "RFC3339",
      "usage": "in_use",
      "reason": "",
      "last_seen": "RFC3339",
      "ports": ["0.0.0.0:443/tcp"],
      "process": {
        "exe": "/usr/sbin/nginx",
        "effective_uid": 0,
        "userns": false,
        "dangerous_caps": [],
        "privileged": false
      },
      "instances": [{
        "type": "gobinary",
        "target": "app/api",
        "usage": "in_use"
      }]
    }]
  }
}
```

| `findings[].runtime` field | Type | Meaning |
| --- | --- | --- |
| `muted` | boolean | `true` when muted; otherwise omitted. |
| `muted_reason` | string | `no_fix_not_in_use_7d` for muted findings. |
| `usage` | string | `in_use`, `not_observed`, or `unavailable`. |
| `reason` | string | Reason for `unavailable`, listed below. |
| `evidence_kinds` | array of strings | `exe`: execution confirmed by sampling; `mapped_library`: library loading confirmed by sampling; `exec_event`: execution observed by eBPF; `library_load_event`: library loading observed by eBPF. |
| `events_coverage` | string | `since_start`: eBPF observation began before container startup with no gaps; `partial`: partial coverage; `none`: eBPF is not running. |
| `exposure` | string | `host_published_all`, `host_published_loopback`, `container_listening`, or `unknown`. |
| `high_privilege` | boolean | UID 0 without a user namespace, dangerous capabilities, or privileged mode. |
| `containers` | array of objects | Container evidence. For `in_use`, the strongest container is first, comparing exposure before privilege. |
| `containers[].name` | string | Container name. |
| `containers[].container_id` | string | Container ID, 64 hexadecimal characters. |
| `containers[].generation_started_at` | string | Container generation start time in RFC 3339 format. |
| `containers[].usage` / `containers[].reason` | string | Container usage and reason for unavailable evidence. |
| `containers[].last_seen` | string | Last confirmation time in RFC 3339 format. |
| `containers[].ports` | array of strings | Port evidence, such as `0.0.0.0:443/tcp`. |
| `containers[].process` | object | Observed `exe`, `effective_uid`, `userns`, `dangerous_caps`, and `privileged`; included only when observed. |
| `containers[].instances` | array of objects | Language-package instances with `type`, `target`, and `usage`; language packages only. |

`kinds_ambiguous` and `process_exes` appear only when multiple programs use one
OS package and evidence kinds cannot be associated with individual programs.

Unavailable reason codes correspond to the following thread text.

| Webhook `reason` | Thread reason |
| --- | --- |
| `sensor_not_reporting` | `sensor not reporting` |
| `sensor_stale` | `sensor report is stale` |
| `evidence_invalid` | `evidence invalid` |
| `isolation_failed` | `sensor isolation failed` |
| `permission_denied` | `permission denied` |
| `initializing` | `index not built yet` |
| `stalled` | `worker stalled` |
| `parse_failed` | `package database parse failed` |
| `truncated` | `evidence truncated` |
| `incomplete` | `evidence incomplete` |
| `generation_unverified` | `container generation unverified` |
| `container_not_observed` | `container not observed` |
| `db_absent` | `package database absent` |
| `db_error` | `package database error` |
| `db_unsupported` | `package database unsupported` |
| `no_file_list` | `no file list for this package` |
| `attribution_ambiguous` | `multiple owners` |
| `file_replaced` | `file replaced` |
| `version_mismatch` | `version mismatch` |
| `ecosystem_unmapped` | `ecosystem not mapped` |
| `binary_path_unknown` | `binary path unknown` |

Sensor status meanings and observation limits are described in
[Runtime usage](runtime-usage.md).

### Diff

`diff` provides changes since the previous scan by type. It is present only in diff mode, and empty arrays are returned as `[]` rather than `null`, except that `reference_changes` is omitted when empty. Reference updates add this optional field without changing existing keys.

| `diff` field | Type | Meaning |
| --- | --- | --- |
| `new` | array of change objects | New or changed ordinary findings. |
| `resolved` | array of objects | Resolved combinations. |
| `resolved[].image` | string | Image reference. |
| `resolved[].package` | string | Package name. |
| `replaced` | array of replacement objects | References whose verified content-ID sets changed. |
| `reference_changes` | array of reference-change objects | Reference updates with carried history; omitted when none. |
| `new_eosl` | array of strings | Newly detected EOL base-image references. |
| `resolved_eosl` | array of strings | References no longer recorded as EOL. |
| `new_eol_packages` | array of EOL change objects | New or changed EOL findings, including those folded in Slack. |
| `resolved_eol_packages` | array of EOL resolution objects | Packages that left the EOL section. |
| `oldest_open_days` | integer | Whole days since the earliest included first-seen date across all ordinary packages, EOL base images, unfolded EOL packages, and folded Act now EOL packages; fractional days are rounded down. |

`oldest_open_days` includes retained records and ordinary Low findings, so its scope differs from the Slack age when triage is enabled. EOL packages use their first-seen-as-EOL date, while folded EOL packages other than Act now use the base OS's first-seen-as-EOL date.

| `new[]` field | Type | Meaning |
| --- | --- | --- |
| `ecosystems` | array of strings | Sorted, deduplicated ecosystem names across all groups combined into this change; independent of the Sensor. |
| `runtime_usage` | string | `in_use`, `not_observed`, or `unavailable`, only when runtime usage is enabled; omitted without an assessment. |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `new`, `escalated`, `new_cves`, `now_fixable`, or `unmuted`. |
| `muted` | boolean | `true` when every group in this change is muted; otherwise omitted. |
| `new_cve_count` | integer | Added CVE count; included only for `new_cves`. |
| `new_cve_ids` | array of strings | Added IDs without Slack link markup, included only for `new_cves`; the length matches `new_cve_count`. |
| `critical` | integer | CRITICAL count. |
| `high` | integer | HIGH count. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when unavailable. |
| `reason` | string | Plain-text evidence for an escalation, or the reason for `unmuted`; omitted otherwise. |

| `new_eol_packages[]` field | Type | Meaning |
| --- | --- | --- |
| `ecosystems` | array of strings | Sorted, deduplicated ecosystem names across all groups combined into this change; independent of the Sensor. |
| `runtime_usage` | string | `in_use`, `not_observed`, or `unavailable`, only when runtime usage is enabled; omitted without an assessment. |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `eol_new` for newly detected EOL, `eol_new_cves` for added CVEs, or `eol_escalated` for escalation to Act now. |
| `new_cve_ids` | array of strings | Sorted added EOL IDs without Slack link markup; included only for `eol_new_cves`. |
| `critical` | integer | CRITICAL count across current EOL groups. |
| `high` | integer | HIGH count across current EOL groups. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `reason` | string | Evidence included only for `eol_escalated`. |

EOL changes have no `new_cve_count` field. Use the length of `new_cve_ids` to obtain the added count.

| `resolved_eol_packages[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `still_open` | boolean | `true` when ordinary findings remain for the same reference and package; present even when `false`. |

| `replaced[]` field | Type | Meaning |
| --- | --- | --- |
| `ref` | string | Image reference. |
| `prev_content_ids` | array of strings | Sorted previous verified content-ID set. |
| `content_ids` | array of strings | Sorted current verified content-ID set. |

| `reference_changes[]` field | Type | Meaning |
| --- | --- | --- |
| `repository` | string | Repository as written in the new reference, without its tag or digest, preserving the registry port. |
| `previous_ref` | string | Full previous image reference. |
| `ref` | string | Full new image reference. |
| `workloads` | array of strings | Sorted shared workload keys that link the old and new references. |

Workload keys use `compose/<project>/<service>` for Compose, `<kind>/<namespace>/<name>/<container>` for Kubernetes, and `container/<name>` for a standalone Docker container with no known workload.

### Backward compatibility

Ecosystem and runtime fields are additions only; existing fields are unchanged.
Ecosystem fields apply independently of the Sensor, while runtime fields require
`runtime.enabled: true`.

Existing fields and the structure organized by fix status are preserved. Fix-status sections and `priority` are handled separately.

- `actionable` represents `fixed`.
- `watch` represents groups normalized to `affected`.
- `wont_fix` represents `will_not_fix`.
- `eol_packages` represents `end_of_life`.

`diff.new[].kind` also supports `unmuted`, with its reason in `diff.new[].reason`.

EOL changes use separate arrays and `kind` values. `diff.new_eol_packages` and `diff.resolved_eol_packages` return `[]` even when empty. EOL support preserves existing fields and adds new arrays and the optional `vulns[].status` field.

## 8. Triage disabled

With `triage.enabled: false`, priority classification stops, and Slack shows results by fix status. KEV, EPSS, and discussion-link lookups also stop.

Slack uses this order: EOL base → EOL package → fix available → waiting for an upstream fix → no current plan to fix on the target platform. EOL sections and folding into the base OS work as they do with triage enabled. The waiting-for-an-upstream-fix section includes `affected`, `fix_deferred`, `under_investigation`, and `unknown`.

Open now starts with EOL counts, including retained records. The following CRITICAL, HIGH, and affected-image counts come from current findings. If there are no current findings and only retained records remain, the same holding display is used as with triage enabled.

New, New CVEs, Now fixable, Unmuted, Resolved, newly detected EOL, new EOL CVEs, and EOL clearances are still detected. Ordinary priority escalations and EOL package escalations to Act now are not detected.

In the full view, the line grouping low-risk fixes includes
`— full list in the generic webhook payload` only when a generic webhook is configured.
