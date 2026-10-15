# Webhook remediation fields

## Common remediation plan fields {#remediation-fields}

When remediation planning is enabled, `remediation` is included in both full and diff payloads.
See [Webhook field reference](webhook-reference.md#top-level) for the overall report format.

Field names in each table are relative to the object indicated by that table.
Fields without an omission condition are included whenever the object is present.

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `schema_version` | integer | Format version of this object, currently `1`. |
| `status` | string | `ok` when a plan was produced, or `unavailable` when it could not be produced. |
| `unavailable_reason` | string | Reason no plan was produced; omitted otherwise. |
| `not_saved` | boolean | `true` when the plan could not be saved; omitted otherwise. |
| `generated_at` | string | Plan generation time in RFC 3339 format; omitted when there is no plan. |
| `conditions` | object | Comparison scan conditions; omitted when both the Trivy version and vulnerability database identity are unknown. |
| `conditions.trivy_version` | string | Trivy version. |
| `conditions.trivy_sha256` | string | Trivy SHA-256; omitted when unknown. |
| `conditions.vulnerability_db_updated_at` / `conditions.java_db_updated_at` | string | Each database's update time in RFC 3339 format; omitted when unknown. |
| `conditions.vulnerability_db_sha256` / `conditions.java_db_sha256` | string | Each database's SHA-256; omitted when unknown. |
| `conditions.severities` | array of strings | Severities included in the comparison; omitted when empty. |
| `conditions.analysis_settings` | string | Hash identifying the analysis settings; omitted when unknown. |
| `limits` | object | Planning limits; omitted when there is no plan. |
| `limits.max_candidate_scans` | integer | Candidate-image scan limit. |
| `limits.max_baseline_rescans` | integer | Baseline rescan limit. |
| `limits.max_tag_pages` | integer | Tag-list retrieval limit per repository. |
| `usage` | object | Work counts during planning; omitted when there is no plan. |
| `usage.candidate_scans` / `usage.baseline_rescans` | integer | Candidate scan and baseline rescan counts. |
| `usage.tag_pages` / `usage.registry_requests` | integer | Tag-list retrieval and registry request counts. |

`unavailable_reason` uses `databases_not_prepared` or `planner_not_built`.
Even when there is no plan, [published-image `items`](#remediation-image-fields) is included as `[]`.

See [Plan category values](remediation-reference.md#category-values) for each item's `category` and [Reason codes](remediation-reference.md#reason-codes) for `reason`.
The item's `reason` and supplementary `detail` are omitted when empty.

## Published image fields {#remediation-image-fields}

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `summary` | object | Published-image counts with category values as keys and integer counts as values; omitted when there is no plan. |
| `items` | array of objects | Published-image items; `[]` when none apply. |
| `items[].key` | string | Item identifier. |
| `items[].category` | string | Plan category value. |
| `items[].reason` / `items[].detail` | string | Reason and additional details; omitted when empty. |
| `items[].tag_kind` | string | Current tag classification; omitted when unknown. |
| `items[].priority` | string | Target priority; omitted when unavailable. |
| `items[].services` | array of objects | Associated service information; omitted when empty. |
| `items[].current` | object | Current image information. |
| `items[].candidate` | object | Candidate image information; omitted when there is no candidate. |
| `items[].targets` | integer | Number of findings targeted for comparison. |
| `items[].kev_targets` | integer | Number of comparison targets listed in KEV; omitted when `0`. |
| `items[].comparison` | object | Comparison result; omitted when no result is available. |
| `items[].scans` | array of objects | Records of scans used for comparison; omitted when empty. |

Image information in `current` and `candidate` uses the following format.
Image information in base-image items uses the same format.

| Image information field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `ref` | string | Image reference. |
| `tag` | string | Tag; omitted when unknown. |
| `content` | string | Running image's content identity; omitted when unavailable or for candidate images. |
| `config_digest` / `manifest_digest` / `top_digest` | string | Respective digests; omitted when unknown. |
| `platform` | string | Platform; omitted when unknown. |
| `digest_kind_unverified` | boolean | `true` when the running image's digest kind has not been verified; omitted otherwise. |

| `comparison` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `comparable` | boolean | `true` when comparison is possible. |
| `reason` / `scope` / `decision` | string | Comparison reason, scope, and decision; omitted when empty. |
| `targets` / `resolved` / `remaining` | integer | Target, resolved, and remaining counts. |
| `unknown` / `undetected` / `introduced` | integer | Counts of indeterminate findings, findings not detected in the baseline, and newly detected findings. |
| `verdicts` | array of objects | Verdicts for individual target vulnerabilities; omitted when empty. |
| `introduced_findings` | array of objects | Verdicts for individual newly detected vulnerabilities; omitted when empty. |
| `verdicts_truncated` / `introduced_findings_truncated` | boolean | `true` when part of the corresponding list was omitted; omitted otherwise. |

| `scans[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `role` / `ref` | string | Scan role and image reference. |
| `requested` / `confirmed` | string | Requested and confirmed targets. |
| `db` | string | Identity of the database used. |
| `scanned_at` | string | Scan time in RFC 3339 format; omitted when no record is available. |
| `failure` | string | Scan failure information; omitted when empty. |

See [Scan comparison conditions](remediation-logic.md#comparison-conditions) for comparison conditions and [Resolution in comparison results](remediation-results.md#verification-results) for interpreting results.

## Base image fields {#remediation-dockerfile-fields}

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `dockerfile_summary` | object | Counts with category values as keys and integer counts as values; omitted when no items apply. |
| `dockerfile_items` | array of objects | Base-image items; omitted when none apply. |
| `dockerfile_items[].key` | string | Item identifier. |
| `dockerfile_items[].kind` | string | `dockerfile`. |
| `dockerfile_items[].fix_class` | string | `base_image`. |
| `dockerfile_items[].verification` | string | `base_image_comparison`. |
| `dockerfile_items[].category` | string | Plan category value. |
| `dockerfile_items[].reason` / `dockerfile_items[].detail` | string | Reason and additional details; omitted when empty. |
| `dockerfile_items[].priority` | string | Target priority; omitted when unavailable. |
| `dockerfile_items[].workloads` | array of strings | Target workloads; `[]` when none apply. |
| `dockerfile_items[].source` | object | Dockerfile repository, branch, and path, plus available commit, stage, and other information. |
| `dockerfile_items[].base_ref` / `dockerfile_items[].base_kind` | string | Current base-image reference and tag classification; omitted when empty. |
| `dockerfile_items[].candidate` | object | Candidate [image information](#remediation-image-fields); omitted when there is no candidate. |
| `dockerfile_items[].counts` | object | Integer counts named `targets`, `resolved`, `remaining`, and `introduced`. |
| `dockerfile_items[].entities` | array of objects | Matching and comparison results for each running image; omitted when empty. |
| `dockerfile_items[].final_image_verified` | boolean | Whether the rebuilt application image has been verified; always `false`. |
| `dockerfile_items[].pull_request` | object | Matching [PR processing](#remediation-pr-fields); omitted when there is no match. |

| `dockerfile_items[].entities[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `running_image` | object | Running image information. |
| `current_base` / `candidate_base` | object | Current and candidate base-image information; omitted when unavailable. |
| `layer_confirmation` / `findings_by_layer` | object | Base-layer matching results and finding counts by layer. |
| `category` | string | Category value for the running image. |
| `reason` / `detail` | string | Reason and additional details; omitted when empty. |
| `services` | array of objects | Associated services; omitted when empty. |
| `targets` | integer | Number of findings targeted for comparison. |
| `kev_targets` | integer | Number of comparison targets listed in KEV; omitted when `0`. |
| `comparison` | object | [Comparison result](#remediation-image-fields); omitted when no result is available. |
| `scans` | array of objects | [Scan records](#remediation-image-fields); omitted when empty. |

See [Verification scope by target](remediation-logic.md#verification-scope) for the scope of checks.

## Language package fields {#remediation-language-fields}

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `language_summary` | object | Counts with category values as keys and integer counts as values; omitted when no items apply. |
| `language_items` | array of objects | Language-package items; omitted when none apply. |
| `language_items[].key` | string | Item identifier. |
| `language_items[].category` | string | Plan category value. |
| `language_items[].reason` / `language_items[].detail` | string | Reason and additional details; omitted when empty. |
| `language_items[].manager` / `language_items[].priority` | string | Package manager and priority; omitted when empty. |
| `language_items[].workloads` | array of strings or `null` | Target workloads. |
| `language_items[].source` | object | Source information such as the dependency files' repository, branch, and directory. |
| `language_items[].pull_request` | object | Matching [PR processing](#remediation-pr-fields); omitted when there is no match. |

### Package results {#language-package-fields}

| Field relative to `language_items[]` | Type | Meaning and omission conditions |
| --- | --- | --- |
| `package_count` | integer | Total package count. |
| `packages` | array of objects | Per-package results; omitted when empty. |
| `packages_truncated` | boolean | `true` when part of the list was omitted; omitted otherwise. |
| `packages[].name` / `packages[].ecosystem` / `packages[].installed` | string | Package name, ecosystem, and running version. |
| `packages[].normalized` | string | Normalized package name; omitted when empty. |
| `packages[].selection_lower_bound` / `packages[].adopted_version` | string | Update-target lower bound and adopted version; omitted when unavailable. |
| `packages[].relation` | string | Dependency relationship classification; omitted when empty. |
| `packages[].action` / `packages[].reason` / `packages[].detail` | string | Action, reason, and additional details; omitted when empty. |
| `packages[].left_out` | boolean | `true` when excluded from the planned update; omitted otherwise. |
| `packages[].occurrence_count` / `packages[].cve_count` / `packages[].origin_count` | integer | Counts of occurrences in dependency files, vulnerabilities, and original findings. |
| `packages[].kev_count` | integer | Number of vulnerabilities listed in KEV; omitted when `0`. |
| `packages[].occurrences` / `packages[].cves` / `packages[].origins` | array of objects | Lists of occurrences, vulnerabilities, and original findings; omitted when empty. |
| `packages[].occurrences_truncated` / `packages[].cves_truncated` / `packages[].origins_truncated` | boolean | `true` when part of the corresponding list was omitted; omitted otherwise. |

See [Package action values](remediation-reference.md#action-values) for `action` definitions and [Update targets and adopted versions](remediation-results.md#target-and-adopted-version) for interpreting versions.

### Runtime {#language-runtime-fields}

| Field relative to `language_items[]` | Type | Meaning and omission conditions |
| --- | --- | --- |
| `runtime_eol` | object | Runtime requiring manual action because support has ended; omitted when none applies. |
| `runtime_eol.id` / `runtime_eol.name` | string | Runtime identifier and name. |
| `runtime_eol.eol` | string | End-of-support date in `YYYY-MM-DD` format; omitted when unknown. |
| `update.runtime` | object | Runtime used for the update; omitted when no record is available. |
| `update.runtime.id` / `update.runtime.version` | string | Runtime identifier and version. |
| `update.runtime.pip` | string | pip version included in the Python image; omitted when unavailable. |
| `update.runtime.image` / `update.runtime.platform` / `update.runtime.digest` | string | Work image, platform, and digest; omitted when unavailable. |
| `update.runtime.support` / `update.runtime.eol` | string | Support status and end date; omitted when unavailable. |
| `update.runtime.basis` | string | Runtime selection basis; omitted when unavailable. |
| `update.runtime.declared` | array of objects | Version declarations with `source` and `value`; omitted when empty. |
| `update.runtime.excluded` | array of objects | `id`, `why`, and additional information for version series not selected; omitted when empty. |
| `update.runtime.engines_floor` | string | Lowest Node.js version checked for dependency compatibility; omitted when no record is available. |

See [Runtime selection](remediation-logic.md#runtime-and-tool-versions) for the selection method.

### Tools {#language-tool-fields}

`language_items[].update.tool` is included when a record of the tool used for the update is available.

| `update.tool` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `name` / `version` | string | Tool name and version. |
| `source` | string | Version selection basis: `declared`, `default`, or `default_in_range`. |
| `sha256` | string | Distribution SHA-256. |
| `format` | string | Distribution format; omitted when empty. |
| `size` | integer | Distribution size in bytes; omitted when `0`. |
| `sha512` | string | Distribution SHA-512; omitted when empty. |
| `published_at` | string | Publication time in RFC 3339 format. |
| `registry_digest` | string | Distribution digest reported by the registry; omitted when empty. |
| `spec_hash` | string | Hash declared by the project and verified against the distribution; omitted when empty. |

See [Tool version selection](remediation-logic.md#tool-version-selection) for the meaning of each selection basis.

### Update records {#language-update-fields}

| Field relative to `language_items[]` | Type | Meaning and omission conditions |
| --- | --- | --- |
| `update_executed` | boolean | Whether the dependency update ran in this cycle; included even when `false`. |
| `post_update_check_executed` | boolean | Whether the post-update check ran in this cycle; included even when `false`. |
| `update` | object | Update record; omitted when no record is available. |
| `update.steps` | array of objects | Records of executed operations; omitted when empty. |
| `update.notes` | array of strings | Additional notes about update processing; omitted when empty. |
| `update.manifest_edits` | array of objects | Manifest changes; omitted when empty. |
| `update.manifest_edits[].file` / `section` / `name` / `from` / `to` | string | File, section, dependency name, previous value, and new value. |
| `update.manifest_edits[].major_change` | boolean | `true` for a major-version change; omitted otherwise. |
| `update.deprecated_changed` | integer | Number of lockfile entries with added, removed, or changed deprecation notes; omitted when `0`. |
| `update.diff` | object | Lockfile diff; omitted when no record is available. |
| `update.diff.added` / `update.diff.changed` / `update.diff.removed` | array of strings | Added, changed, and removed entries; omitted when empty. |
| `update.diff.truncated` | boolean | `true` when part of the diff lists was omitted; omitted otherwise. |
| `update.diff.followed` | array of objects | Entries whose dependency versions changed as a consequence of the update; omitted when empty. |
| `update.diff.followed[].entry` | string | Changed entry. |
| `update.diff.followed[].moves` | array of objects | Dependency changes with string fields `name`, `from`, and `to`. |
| `source_check` | object | Dependency-file scan results before and after the update; omitted when no record is available. |
| `source_check.counts` | array of integers | Three counts in the order resolved, remaining, and newly detected. |
| `source_check.resolved` / `source_check.remaining` / `source_check.introduced` | array of objects | Corresponding vulnerability lists; omitted when empty. |
| `source_check.truncated` | boolean | `true` when part of the vulnerability lists was omitted; omitted otherwise. |
| `source_check.passed` | boolean | Whether the post-update check passed; included even when `false`. |

The webhook includes the count of changed deprecation notes, but not the names of affected entries.
The PR body lists those names and whether notes were added, removed, or changed.

### Updated files {#language-artifact-fields}

`language_items[].artifacts` is included when information about updated files is available.
File contents are excluded.

| `artifacts[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `path` | string | File path within the repository. |
| `sha256` | string | SHA-256 of the file contents. |
| `size` | integer | File size in bytes. |
| `mode` | string | File mode; omitted when unavailable. |

## PR processing fields {#remediation-pr-fields}

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `pull_request_summary` | object | Counts with status values as keys and integer counts as values; omitted when there are no processing units. |
| `pull_requests` | array of objects | PR processing units; omitted when none apply. |
| `pull_requests[].key` | string | Processing-unit identifier. |
| `pull_requests[].kind` | string | `dockerfile` for base-image updates or `language` for language-package updates; omitted for Compose tag updates. |
| `pull_requests[].repo` / `pull_requests[].base_branch` / `pull_requests[].path` | string | Target repository, base branch, and file path. |
| `pull_requests[].status` | string | PR processing status. |
| `pull_requests[].reason` / `pull_requests[].detail` | string | Reason and additional details; omitted when empty. |
| `pull_requests[].number` | integer | PR number; omitted when `0`. |
| `pull_requests[].url` / `pull_requests[].state` | string | PR URL and state on GitHub; omitted when empty. |
| `pull_requests[].item_key` | string | Identifier of the associated language-package item; omitted when unavailable. |
| `pull_requests[].language` | object | Language-package update details; omitted when none apply. |
| `pull_requests[].language.remaining` | array of objects | Packages excluded from the PR; omitted when empty. |
| `dockerfile_items[].pull_request` | object | Matching operation's `status` and optional `reason`, `number`, `url`, and `state`; omitted when there is no match. |
| `language_items[].pull_request` | object | Matching operation's `status` and optional reason, details, PR information, and matching identifiers; omitted when there is no match. |

| `pull_requests[].language.remaining[]` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `name` / `ecosystem` | string | Package name and ecosystem. |
| `from` / `target` | string | Running version and planned update target. |
| `reason` | string | Reason for exclusion from the update. |
| `relation` / `detail` | string | Dependency relationship classification and additional details; omitted when empty. |

When a cycle matches an existing PR, package exclusion information is supplemented from the PR's `language.remaining`.
`packages[]` may include `left_out`, `action`, and `reason` even when update and check execution flags are `false` for that cycle.

See [PR status values](remediation-reference.md#pr-status-values) for status definitions and [Partial PRs](remediation-results.md#partial-pull-requests) for interpreting partial PRs.

## PR operation event fields {#remediation-operation-fields}

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `operations` | array of objects | Undelivered PR operation events; omitted when none apply. |
| `operations[].seq` | integer | Event sequence number. |
| `operations[].id` | string | Operation identifier. |
| `operations[].at` | string | Time in RFC 3339 format. |
| `operations[].phase` / `operations[].kind` / `operations[].repo` | string | Operation phase, kind, and target repository. |
| `operations[].attempt_key` | string | Attempt identifier; omitted when empty. |
| `operations[].number` | integer | PR number; omitted when `0`. |
| `operations[].result` / `operations[].error` | string | Operation result and error; omitted when empty. |

See [Remediation plan redelivery](notification-conditions.md#remediation-redelivery) for delivery and redelivery behavior.

## Write-blocking problem fields {#remediation-problem-fields}

| `remediation` field | Type | Meaning and omission conditions |
| --- | --- | --- |
| `problems` | array of objects | Problems that block PR writes; omitted when none apply. |
| `problems[].code` | string | Problem classification code. |
| `problems[].repo` / `problems[].target` | string | Target repository and update-target identifier; omitted when empty. |
| `problems[].reason` / `problems[].detail` | string | Reason and additional details; omitted when empty. |

See [Stopping writes](remediation-logic.md#write-stops) for stop conditions and [Reason codes](remediation-reference.md#reason-codes) for reasons.

## Remediation plan JSON example {#remediation-json-example}

This example shows selected key fields from a payload containing a partial PR.
`example-b` was excluded from the update and is recorded in both the package results and the PR's `remaining` list.

```json
{
  "remediation": {
    "language_items": [
      {
        "category": "pr_candidate",
        "update_executed": true,
        "post_update_check_executed": true,
        "packages": [
          {
            "name": "example-a",
            "ecosystem": "node-pkg",
            "installed": "1.0.0",
            "adopted_version": "1.0.1",
            "action": "update",
            "reason": "update_verified"
          },
          {
            "name": "example-b",
            "ecosystem": "node-pkg",
            "installed": "2.0.0",
            "selection_lower_bound": "2.0.1",
            "action": "manual",
            "reason": "target_not_updated",
            "left_out": true
          }
        ]
      }
    ],
    "pull_requests": [
      {
        "kind": "language",
        "language": {
          "remaining": [
            {
              "name": "example-b",
              "ecosystem": "node-pkg",
              "from": "2.0.0",
              "target": "2.0.1",
              "reason": "target_not_updated"
            }
          ]
        }
      }
    ]
  }
}
```

See [Partial PR selection conditions](remediation-logic.md#partial-pr-selection) for acceptance conditions.
