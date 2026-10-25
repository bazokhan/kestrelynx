# Webhook field reference

## Payload scope {#generic-webhook}

The generic webhook sends current scan results as structured JSON.
In diff mode, it also includes changes since the previous scan.

The payload includes Low findings, muted findings, EOL packages folded in Slack, and affected containers and workloads.
It can be used alongside Slack, but does not convert the payload into Discord- or Teams-specific message formats.

See [Configuration](configuration.md) for destinations and [Notification conditions](notification-conditions.md#notification-conditions) for delivery timing.
Remediation plan JSON is described in [Webhook remediation fields](webhook-remediation-reference.md#remediation-fields).

## Report fields {#report-fields}

Field names in each table are relative to the object indicated by that table.
Fields without an omission condition are included whenever the object is present.

Counts for `MEDIUM`, `LOW`, and `UNKNOWN` are included only when `scan.severity` selects the corresponding levels.
With the default `[HIGH, CRITICAL]`, Slack display, webhook payloads, and logs remain unchanged.

### Top level {#top-level}

| Field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `generated_at` | string | Scan time in RFC 3339 format. |
| `environment` | object | [Environment](#environment). |
| `summary` | object | [Summary](#summary). |
| `eosl_images` | array of strings or `null` | EOL base-image references; may be `null` when none apply. |
| `actionable` | array of objects | [Images](#images) with `fixed` findings; `[]` when none apply. |
| `watch` | array of objects | Images with findings normalized to `affected`; `[]` when none apply. |
| `wont_fix` | array of objects | Images with `will_not_fix` findings; `[]` when none apply. |
| `eol_packages` | array of objects | Images containing all `end_of_life` groups; `[]` when none apply. |
| `scan_errors` | array of objects | [Scan failures](#scan-errors); `[]` when none apply. |

| `runtime_unchecked` | array of strings | Image references whose Node.js runtime was not checked because advisory data was unavailable; omitted when none apply. |
| `diff` | object | [Changes](#diff); omitted in full mode. |
| `runtime` | object | [Sensor information and usage counts](#runtime); omitted when runtime usage is disabled. |
| `remediation` | object | [Remediation plans and PR processing results](webhook-remediation-reference.md#remediation-fields); omitted when remediation planning is disabled. |

`watch` is a fix-status section, separate from the Watch priority.
`not_affected` findings are excluded from all finding arrays.

### Environment {#environment}

| `environment` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `kind` | string | `docker` or `kubernetes`. |
| `name` | string | Configured environment name; omitted when unset. |

### Summary {#summary}

| `summary` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `images_total` | integer | Number of unique image-reference and content-identity combinations, including scan failures. |
| `images_affected` | integer | Number of images with eligible vulnerabilities or an EOL base OS. |
| `priority_counts` | object | Package-group counts by priority; omitted when triage is disabled. |
| `priority_counts.act_now` | integer | Act now count. |
| `priority_counts.watch` | integer | Watch count. |
| `priority_counts.low` | integer | Low count. |
| `intel` | object | KEV and EPSS availability and freshness; omitted when triage is disabled. |
| `intel.degraded` | boolean | `true` when both KEV and EPSS are unavailable. |
| `intel.kev_ok` | boolean | `true` when KEV is available. |
| `intel.epss_ok` | boolean | `true` when EPSS is available. |
| `intel.stale_days` | integer | Age in days of the stale threat intelligence in use. |

`priority_counts` includes EOL packages only when their priority is Act now.
Its scope overlaps with `eol_packages`, so the three counts do not necessarily sum to the total number of package groups.

Images whose Node.js runtime could not be checked are listed in the top-level `runtime_unchecked` field.
Notification and history handling are described in [Unavailable Node.js advisory data](scan-logic.md#node-runtime-unavailable).

### Scan failures {#scan-errors}

| `scan_errors[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference whose scan failed. |
| `error` | string | Error details. |

See [Handling scan failures](scan-logic.md#scan-failures) for how results are handled after a failure.

## Image fields {#images}

Each element of `actionable`, `watch`, `wont_fix`, and `eol_packages` represents an image reference and content identity for a particular fix status.

### Image identity {#image-identity}

| Field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `image` | string | Image reference for display. |
| `severity_counts` | object | Integer counts by severity; `CRITICAL` and `HIGH` are always included, and `HIGH` counts only HIGH vulnerabilities. |
| `findings` | array of objects | [Package groups](#package-fields) belonging to this image and fix status. |
| `containers` | array of objects | [Containers](#containers) matching this content identity; `[]` when none apply. |
| `content_id` | string | `sha256:<hex>` for a Docker scan targeting a config digest whose content identity was verified; omitted otherwise. |
| `registry_digests` | array of strings | Registry digests collected for the same reference from successful scans with verified content identities; `[]` when unavailable. |
| `identity_resolved` | boolean | `true` when this element's scan verified the running image's content identity. |
| `scan_target_kind` | string | `content_id`, `registry_digest`, or `reference`. |
| `severity_counts.MEDIUM` | integer | MEDIUM count; omitted when `0`. |
| `severity_counts.LOW` | integer | LOW count; omitted when `0`. |
| `severity_counts.UNKNOWN` | integer | UNKNOWN count, including unrecognized severities; omitted when `0`. |

`registry_digests` covers the entire reference, while `identity_resolved` and `scan_target_kind` describe each element.
See [Scan warnings](slack-display.md#scan-warnings) for the corresponding Slack annotations.

### Containers {#containers}

| `containers[]` field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Docker name without the leading slash or link aliases, or `<namespace>/<pod>/<container>` for Kubernetes. |
| `workload` | object | [Workload association](#workloads), included even when the association is unknown. |

Even when one reference points to multiple content identities, each element includes only the containers matching its content identity.

### Workloads {#workloads}

| `containers[].workload` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `kind` | string | `unknown`, `compose`, `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, or `pod`. |
| `group` | string | Compose project or namespace; omitted when unknown. |
| `name` | string | Compose service, resolved workload name, or standalone Pod name; omitted when unknown. |

## Finding fields {#findings}

`findings[]` represents package groups, and its nested `vulns[]` represents individual vulnerabilities.

### Packages {#package-fields}

| `findings[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `package` | string | Package name. |
| `class` | string | `os` or `lang`. |
| `ecosystem` | string | Type such as `debian` or `python-pkg`; `""` when unknown. |
| `installed` | string | Installed version. |
| `fixed` | string | Fixed version; `""` when none is available. |
| `status` | string | `fixed`, `affected`, `will_not_fix`, or `end_of_life`. |
| `severity_counts` | object | Integer counts by severity; `CRITICAL` and `HIGH` are always included, and `HIGH` counts only HIGH vulnerabilities. |
| `upgrade_risk` | string | `""`, `distro_update`, `safe`, `caution`, or `unknown`. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `vuln_ids` | array of strings | Sorted vulnerability IDs. |
| `vulns` | array of objects | [Details for each vulnerability](#vulnerability-fields). |
| `runtime` | object | [Finding usage](#finding-runtime); omitted when no usage assessment is attached. |
| `severity_counts.MEDIUM` | integer | MEDIUM count; omitted when `0`. |
| `severity_counts.LOW` | integer | LOW count; omitted when `0`. |
| `severity_counts.UNKNOWN` | integer | UNKNOWN count, including unrecognized severities; omitted when `0`. |

`class` and `ecosystem` are included even when runtime usage is disabled.
See [Finding classification](scan-logic.md#finding-classification) and [Exploitation-based triage](scan-logic.md#triage) for fix-status and priority decisions.

### Vulnerabilities {#vulnerability-fields}

| `vulns[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `id` | string | Vulnerability ID without Slack link markup. |
| `severity` | string | Vulnerability severity. |
| `status` | string | Original vulnerability status when it differs from the group's status; omitted when they match. |
| `url` | string | Primary advisory URL; omitted when unavailable. |
| `title` | string | Short vulnerability title; omitted when unavailable. |
| `kev` | boolean | `true` when listed in the available KEV catalog. |
| `ransomware` | boolean | KEV ransomware flag; omitted when `false`. |
| `epss` | number or `null` | EPSS probability; `null` when unknown. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `refs` | array of objects | [Additional references](#reference-fields); omitted when empty. |

When `status` is omitted, read it as the same value as the containing `findings[]` element's `status`.
If the original vulnerability status is missing, the value is `unknown`.

### Additional references {#reference-fields}

| `refs[]` field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `vendor` or `discussion`. |
| `label` | string | Display label. |
| `url` | string | Reference URL. |

## Runtime fields {#runtime}

Runtime fields are added when runtime usage is enabled.
See [Runtime usage](runtime-usage.md) for Sensor status meanings and observation limits.

### Sensor information {#sensor-fields}

| Top-level `runtime` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `sensor_status` | string | `ok`, `degraded`, `stale`, `not_reporting`, `permission_denied`, `evidence_invalid`, `isolation_failed`, or `isolation_degraded`. |
| `heartbeat_at` | string | Sensor report time in RFC 3339 format; omitted when no report time is available. |
| `interval_seconds` | integer | Sampling interval in seconds; omitted when `0`. |
| `rules` | object | Rules for assessing usage. |
| `rules.os_packages` | string | `executed_or_loaded_by_running_process`. |
| `rules.lang_packages_binary` | string | `in_running_binary`. |
| `rules.lang_packages_runtime` | string | `runtime_process_running`. |
| `events_status` | string | `ok` or `unavailable`; `""` when the Sensor has not reported. |
| `events_reason` | string | Reason associated with event-observation status; omitted when empty. |
| `counts` | object | [Usage counts](#runtime-counts). |

### Usage counts {#runtime-counts}

| `runtime.counts` field | Type | Meaning |
| --- | --- | --- |
| `in_use` | integer | Number of package groups in use. |
| `not_observed` | integer | Number of package groups whose use was not observed. |
| `unavailable` | integer | Number of package groups whose usage could not be assessed. |
| `muted` | integer | Number of muted package groups. |

Counts cover all groups in the four finding arrays, and each count is included even when `0`.
`muted` overlaps with the usage counts, so do not sum all four values as a total.

### Finding usage {#finding-runtime}

| `findings[].runtime` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `usage` | string | `in_use`, `not_observed`, or `unavailable`. |
| `reason` | string | [Reason usage is unavailable](#runtime-reasons); omitted when empty. |
| `evidence_kinds` | array of strings | Observation types; omitted when empty. |
| `events_coverage` | string | `since_start`, `partial`, or `none`; omitted when unavailable. |
| `exposure` | string | `host_published_all`, `host_published_loopback`, `container_listening`, or `unknown`; omitted when unavailable. |
| `high_privilege` | boolean | `true` for UID 0 without a user namespace, dangerous capabilities, or privileged mode; omitted otherwise. |
| `containers` | array of objects | [Container evidence](#container-evidence); omitted when empty. |
| `muted` | boolean | `true` when muted; omitted otherwise. |
| `muted_reason` | string | Muting reason `no_fix_not_in_use_7d`; omitted when no reason applies. |

| `evidence_kinds[]` value | Meaning |
| --- | --- |
| `exe` | Execution confirmed by sampling. |
| `mapped_library` | Library loading confirmed by sampling. |
| `exec_event` | Execution observed by eBPF. |
| `library_load_event` | Library loading observed by eBPF. |

| `events_coverage` value | Meaning |
| --- | --- |
| `since_start` | eBPF observation began before container startup with no gaps. |
| `partial` | Some periods or events were observed. |
| `none` | No event observation through eBPF. |

See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for muting conditions.

### Container evidence {#container-evidence}

The following table describes fields in `findings[].runtime.containers[]`.
For findings in use, the container with the strongest evidence is listed first, comparing exposure before privilege.

| Field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `name` | string | Container name. |
| `container_id` | string | Container ID, 64 hexadecimal characters. |
| `generation_started_at` | string | Container generation start time in RFC 3339 format; omitted when unknown. |
| `usage` | string | `in_use`, `not_observed`, or `unavailable`. |
| `reason` | string | Reason usage could not be assessed; omitted when empty. |
| `last_seen` | string | Last confirmation time in RFC 3339 format; omitted when unknown. |
| `ports` | array of strings | Port evidence, such as `0.0.0.0:443/tcp`; omitted when empty. |
| `kinds_ambiguous` | boolean | `true` when multiple observation types for an OS package cannot be associated with individual processes; omitted otherwise. |
| `process_exes` | array of strings | Deduplicated list of observed executables when `kinds_ambiguous` is true; omitted when empty. |
| `process` | object | Included only when a process was observed. |
| `process.exe` | string | Executable path; omitted when empty. |
| `process.effective_uid` | integer | Effective UID; included even when `0`. |
| `process.userns` | boolean | Whether a user namespace is used; included even when `false`. |
| `process.dangerous_caps` | array of strings | Dangerous capabilities; omitted when empty. |
| `process.privileged` | boolean | Whether privileged mode is used; included even when `false`. |
| `instances` | array of objects | Language-package instances; omitted when empty. |
| `instances[].type` | string | Instance type; omitted when empty. |
| `instances[].target` | string | Target, such as an executable; omitted when empty. |
| `instances[].pkg_path` | string | Package path; omitted when empty. |
| `instances[].usage` | string | `in_use`, `not_observed`, or `unavailable`. |
| `instances[].reason` | string | Reason usage could not be assessed; omitted when empty. |

When `kinds_ambiguous` is `true`, do not interpret individual `evidence_kinds` values as corresponding to `process.exe` or individual entries in `process_exes`.

### Reasons usage is unavailable {#runtime-reasons}

The `reason` fields for findings, containers, and instances use the following reason codes.

| Reason code | Meaning |
| --- | --- |
| `sensor_not_reporting` | No report from the Sensor. |
| `sensor_stale` | The Sensor report is stale. |
| `evidence_invalid` | Evidence validation failed. |
| `isolation_failed` | Sensor isolation failed. |
| `permission_denied` | Read permission is unavailable. |
| `initializing` | The package index is being prepared. |
| `stalled` | Observation processing exceeded its time limit. |
| `parse_failed` | Package database parsing failed. |
| `truncated` | Read limits left insufficient evidence. |
| `incomplete` | Some observations are missing. |
| `generation_unverified` | The association between the container generation and scan target could not be verified. |
| `container_not_observed` | No observation of the matching container. |
| `db_absent` | No package database. |
| `db_error` | Package database read or parse error. |
| `db_unsupported` | Unsupported package database. |
| `no_file_list` | No file list for the package. |
| `attribution_ambiguous` | The package owning the observed path could not be uniquely identified. |
| `file_replaced` | The observed file has been replaced. |
| `version_mismatch` | Package versions do not match. |
| `ecosystem_unmapped` | The runtime corresponding to the ecosystem could not be identified. |
| `binary_path_unknown` | The executable path is unknown. |

## Diff fields {#diff}

`diff` describes changes since the previous scan by type.
See [Change and history decisions](diff-logic.md#comparison-baseline) for the conditions that establish a change.

### Diff object {#diff-fields}

| `diff` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `new` | array of objects | [Ordinary package changes](#new-fields); `[]` when none apply. |
| `resolved` | array of objects | [Package resolutions](#resolved-fields); `[]` when none apply. |
| `replaced` | array of objects | [Image content changes](#image-replacement-fields); `[]` when none apply. |
| `reference_changes` | array of objects | [Image reference updates](#reference-change-fields); omitted when none apply. |
| `new_eosl` | array of strings | [New EOL base images](#eol-base-fields); `[]` when none apply. |
| `resolved_eosl` | array of strings | [References no longer recorded as EOL](#eol-base-fields); `[]` when none apply. |
| `new_eol_packages` | array of objects | [EOL package changes](#eol-change-fields); `[]` when none apply. |
| `resolved_eol_packages` | array of objects | [EOL package clearances](#eol-resolved-fields); `[]` when none apply. |
| `oldest_open_days` | integer | [Oldest unresolved age](#oldest-open-days); included even when `0`. |

### Ordinary package changes {#new-fields}

| `diff.new[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `new`, `escalated`, `new_cves`, `now_fixable`, or `unmuted`. |
| `ecosystems` | array of strings | Sorted, deduplicated ecosystems of the groups combined into this change, including `""` for unknown types. |
| `runtime_usage` | string | `in_use`, `not_observed`, or `unavailable`; omitted when no usage assessment is available. |
| `muted` | boolean | `true` when every group in this change is muted; omitted otherwise. |
| `new_cve_count` | integer | Added CVE count for `new_cves`; omitted when `0`. |
| `new_cve_ids` | array of strings | Added IDs for `new_cves`; omitted when empty. |
| `critical` | integer | CRITICAL count. |
| `high` | integer | HIGH count (HIGH only). |
| `medium` | integer | MEDIUM count; omitted when `0`. |
| `low` | integer | LOW count; omitted when `0`. |
| `unknown` | integer | UNKNOWN count, including unrecognized severities; omitted when `0`. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when no priority is available. |
| `reason` | string | Evidence for `escalated` or the reason for `unmuted`; omitted when empty. |

`new_cve_ids` contains no Slack link markup, and its length matches `new_cve_count`.
The explanatory text in `reason` is in English regardless of the notification language setting.

### Package resolutions {#resolved-fields}

| `diff.resolved[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name no longer present in ordinary findings. |

See [Resolution decisions](diff-logic.md#resolved-findings) for what resolution means.

### Image content changes {#image-replacement-fields}

| `diff.replaced[]` field | Type | Meaning |
| --- | --- | --- |
| `ref` | string | Image reference. |
| `prev_content_ids` | array of strings | Sorted previous verified content-ID set. |
| `content_ids` | array of strings | Sorted current verified content-ID set. |

Empty arrays are returned as `[]`, not `null`.

### Image reference updates {#reference-change-fields}

| `diff.reference_changes[]` field | Type | Meaning |
| --- | --- | --- |
| `repository` | string | Repository from the new reference without its tag or digest, preserving the registry port. |
| `previous_ref` | string | Full previous image reference. |
| `ref` | string | Full new image reference. |
| `workloads` | array of strings | Sorted workload keys shared by the old and new references; `[]` when empty. |

| Target | Workload key format |
| --- | --- |
| Compose | `compose/<project>/<service>` |
| Kubernetes | `<kind>/<namespace>/<name>/<container>` |
| Standalone Docker container with no known workload | `container/<name>` |

See [Image reference updates](diff-logic.md#reference-changes) for conditions for carrying history over.

### Base OS EOL changes {#eol-base-fields}

| Field | Element type | Meaning |
| --- | --- | --- |
| `diff.new_eosl[]` | string | Base-image reference newly recorded as EOL. |
| `diff.resolved_eosl[]` | string | Image reference no longer recorded as EOL. |

### EOL package changes {#eol-change-fields}

Changes to EOL packages folded in Slack are also included.

| `diff.new_eol_packages[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `eol_new`, `eol_new_cves`, or `eol_escalated`. |
| `ecosystems` | array of strings | Sorted, deduplicated ecosystems of the groups combined into this change, including `""` for unknown types. |
| `runtime_usage` | string | `in_use`, `not_observed`, or `unavailable`; omitted when no usage assessment is available. |
| `new_cve_ids` | array of strings | Sorted added IDs for `eol_new_cves`; omitted when empty. |
| `critical` | integer | CRITICAL count across current EOL groups. |
| `high` | integer | HIGH count across current EOL groups (HIGH only). |
| `medium` | integer | MEDIUM count across current EOL groups; omitted when `0`. |
| `low` | integer | LOW count across current EOL groups; omitted when `0`. |
| `unknown` | integer | UNKNOWN count across current EOL groups, including unrecognized severities; omitted when `0`. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `reason` | string | Evidence in English for `eol_escalated`; omitted when empty. |

`new_cve_ids` contains no Slack link markup.
There is no `new_cve_count` field, so use the length of `new_cve_ids` for the added count.

### EOL package clearances {#eol-resolved-fields}

| `diff.resolved_eol_packages[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name no longer present in the EOL section. |
| `still_open` | boolean | `true` when ordinary findings remain for the same reference and package; included even when `false`. |

### Oldest unresolved age {#oldest-open-days}

`diff.oldest_open_days` is the number of days since the earliest first-seen date among eligible records.
Fractional days are rounded down, and the value is `0` when no records qualify.

| Target | First-seen date used |
| --- | --- |
| Ordinary packages | First seen among ordinary findings, including Low, muted, and retained records. |
| EOL base OS | Date the base OS was first detected as EOL. |
| Unfolded EOL packages | Date the package was first detected as EOL. |
| Folded Act now EOL packages | Date the package was first detected as EOL. |
| Folded EOL packages other than Act now | Not counted individually; the base OS's first-seen-as-EOL date is used. |

The scope differs from the age shown in Slack when triage is enabled.
See [Unresolved age](slack-display.md#unresolved-age) for the Slack definition.

## Compatibility {#compatibility}

Ecosystem, runtime usage, EOL, and reference-update information are additions that preserve existing fields and the structure organized by fix status.

Receivers should accept unknown additional fields and handle omissions according to each table.
Treat omission, `null`, `[]`, and `""` as distinct values.
