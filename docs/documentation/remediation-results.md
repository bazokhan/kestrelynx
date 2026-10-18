# Reading the results

Remediation plans show update candidates, PR states, and items that require manual handling.
A proposed candidate or merged PR does not mean that vulnerabilities have been resolved in running containers.

## Remediation plans in Slack {#reading-results-in-slack-and-webhooks}

### Example {#slack-example}

The following is an example. In Slack, image references are bold and PR numbers are links.

```text
🔧 Fix plan
Pull requests: 1 created · 1 open

Image: example/app:latest
File to change: pnpm-lock.yaml in example/application
Pull request: #12 (opened now)
Update: package-a 1.2.3 → 1.2.4
Needs a decision: package-b could not be raised to 2.3.0, which fixes the vulnerability, and stays at 2.1.1 in pnpm-lock.yaml (KestreLynx did not look into why it cannot be raised, so check the version ranges of the packages that depend on package-b)

Image: example/service:latest
File to change: docker/Dockerfile in example/application
Pull request: #13 (open)
Update: base image python 3.12.3-slim → 3.12.4-slim
```

### Displayed fields {#slack-fields}

| Display | Meaning |
| --- | --- |
| Image | The running image that produced the findings. |
| Service | The target service, shown when an image reference cannot be used as the heading or in similar cases. |
| File to change | The mapped repository and the file to change. |
| Pull request | A PR link and its status: opened now, open, merged, or closed without merging. |
| Update | Image tag or package changes proposed by the PR. |
| Update candidate | A proposed change that does not necessarily have a PR yet. |
| Re-pull | The comparison supports updating to new content under the same tag. |
| Rebuild | Expected resolution based on a dependency version constraint, or guidance to pull the base again and rebuild. |
| Needs a decision | Manual handling is needed for the source, version constraints, update method, comparison results, or similar issues. |
| Deferred | Processing could not proceed because of limits, waiting periods, retrieval problems, or similar issues. |
| Not comparable | Information or conditions needed for the comparison were missing. |
| Failed | A scan, retrieval, update, or other operation failed. |
| ⚠️ Major version change | An update changes the major version, or the minor version for a 0.x package. |
| ⚠️ Pull request writes are stopped | PR writes have stopped because of problems with records, GitHub state, or similar issues. |

Packages with an update target that need a decision appear on individual lines.
Packages without a target are grouped by reason, with a package list below each reason.

For reason definitions, see [Reason codes](remediation-reference.md#reason-codes); for troubleshooting steps, see [When no candidate or pull request appears](remediation-troubleshooting.md).

### Reading counts {#reading-counts}

| Summary | Unit counted |
| --- | --- |
| `Pull requests: … created · … open` and similar summaries | The status of each update unit handled by PR processing. |
| `… update candidate(s) · … need a decision` and similar summaries | Display categories for each item, such as a file to change or an image to re-pull. |
| `resolves … finding(s)` | Findings no longer detected in the comparison. |
| `… KEV` | Counts related to vulnerabilities in the CISA KEV catalog included in the displayed results. |

When results include a PR number, the opening summary groups counts by PR processing status.
This summary also includes “need a decision,” “deferred,” and “blocked or failed” update units that do not yet have a PR.

- PR counts differ from the number of packages or vulnerabilities being updated
- An item with both a candidate and a need for a decision counts once in each category
- Even when several packages in the same item need a decision, the decision count does not necessarily match the package count
- Packages left out of a created PR still need a decision

### Finding omitted details {#omitted-details}

Slack may shorten long package lists and similar content with “and … more.”

| Information needed | Where to find it |
| --- | --- |
| Versions, reasons, and exclusion details for each package | [Webhook details](#webhook-details) |
| The actual proposed file changes | The PR diff |
| Source information and check results at planning time | [Saved record details](#saved-details) |
| Details of retrieval or execution failures | [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics) |

## Interpreting update results {#interpreting-updates}

### Update targets and adopted versions {#target-and-adopted-version}

| Displayed version | Interpretation |
| --- | --- |
| Running version | The version detected in the scanned image. |
| Update target lower bound | The minimum version used when selecting an update, derived from reported fixed-version information. |
| Adopted version | The version confirmed in the updated dependency files, or the lowest version if multiple versions remain. |

The update target is not necessarily the version the package manager actually selected.
Planning alone does not run dependency updates, so do not interpret the update target as a verified adopted version.

For the lower-bound calculation, see [Fixed-version lower bound](remediation-logic.md#fix-lower-bound); for differences in processing, see [Execution scope of plans and PRs](remediation-logic.md#plan-and-pr-execution).

### Partial PRs {#partial-pull-requests}

For npm, pnpm, and uv, a PR may include only the planned package updates that passed the checks.

| Result | Interpretation |
| --- | --- |
| A package listed under “Update” for the PR | A change included in this PR. |
| A package shown under “Needs a decision” or marked “left out because” | A target excluded from this update that needs separate handling. |
| A package reported as unable to reach the target version and still at its original version | A target that did not reach a fixed version, without necessarily establishing why the update was unsuccessful. |
| An open PR with exclusion details | Packages still need handling even for an update matched to an existing PR. |

“Left out” does not mean that the package was removed from the image.
An item being a PR candidate also does not mean that every package was updated.

Pinned-version pip updates are not split into partial PRs.
For eligibility conditions, see [Partial PR selection](remediation-logic.md#partial-pr-selection); for checks to perform, see [Checking update failures](remediation-troubleshooting.md#check-update-failure).

### Results of re-resolution through dependent packages {#dependent-reresolution-results}

For npm, pnpm, and uv, updating a target package to a fixed version may also update dependent packages within the ranges declared by the project.
Slack shows these dependent packages alongside the target update.

| Example display | Interpretation |
| --- | --- |
| `target old-version → adopted-version (with dependent old-version → new-version)` | The dependent package's version changes along with the target update. |
| `did not reach the fixed version this time` | Dependent packages are resolved again, but the target does not reach a fixed version in this attempt. |
| `needs … updated as well, and that update was not adopted because …` | The result is not adopted, for example because re-resolution checks fail. |
| `updating … was not tried because …` | Re-resolution is skipped because of unsupported forms, limits, or similar conditions. |
| `a version it brings in is less than 72 hours old, so it is tried again after …` | A newly introduced version does not yet satisfy the release waiting requirement. |

- A result that does not reach a fixed version does not establish that other update methods cannot resolve the vulnerability.
- If direct dependency versions remain unchanged and only intermediate dependent packages change, Slack shows the names of those dependent packages.
- Slack lists up to three dependent packages and gives a count for the rest.
- A normal update that passes the checks may still produce a PR even when the re-resolution result is not adopted.

When direct dependency versions change, the PR body lists their before/after versions under “Packages updated along with the fix.”
It also lists the targets held at older versions and their required ranges, with the name of any intermediate package that declares the requirement.

The scan comparison line in the PR body depends on `source_check.basis`.
When carried vulnerabilities are present, one line gives the record count and the first example and states that the update does not fix them.

| Record | PR body display |
| --- | --- |
| `package_version_vuln_edges_positions` | A comparison by package name, version, and vulnerability ID, entry and requirement counts, and the positions of changed requirements |
| `package_version_vuln_edges` | A comparison by package name, version, and vulnerability ID, and entry and requirement counts |
| Example of carried vulnerabilities | 2 vulnerabilities stay at the same place in a version the update moved to (for example `CVE-2026-0001` for `rc` `1.2.8` to `1.2.9`); the update does not fix them. |

- The displayed count of carried vulnerabilities is the number of recorded `chain_carried` elements, not the total number of positions.
- When a list exceeds its limit, the PR body also displays a truncation notice.
- The Slack display remains unchanged, with no dedicated lists for carried vulnerabilities or position checks.

| Information needed | Webhook location |
| --- | --- |
| Dependent packages changed along with the update | `language_items[].packages[].through` |
| Packages requiring older versions and their required ranges | `language_items[].update.chain.blocked` |
| Re-resolution starting points and outcome | `language_items[].update.chain.tops` and `outcome` |
| Detailed reasons for rejected or skipped re-resolution | `language_items[].update.chain.reason` and `detail` |
| Reassessment of the initial update result or additional re-resolution | `language_items[].update.chain.source` |
| Scan comparison basis | `language_items[].source_check.basis` |
| Vulnerabilities remaining at the same positions | `language_items[].source_check.chain_carried` |
| Position check refusals | `language_items[].source_check.chain_position_refusals` |
| Earliest retry time | `language_items[].retry_after` |
| Direct dependency changes included in the PR | `pull_requests[].language.chain` |

See [Re-resolution through dependent packages](remediation-logic.md#dependent-reresolution) for processing conditions and [Records of re-resolution through dependent packages](webhook-remediation-reference.md#language-chain-fields) for field specifications.

### Re-pull guidance {#repull-guidance}

“Re-pull” means that a comparison with the content currently referenced by the same tag confirmed an improvement.
Because the tag string does not change, this guidance alone does not create a PR to update the Compose tag.

`resolves 3 of 4 findings` means that three of the four findings being compared were no longer detected in the candidate.
It does not mean that running containers have been replaced with that content.

### Rebuild guidance {#rebuild-guidance}

| Displayed content | Interpretation |
| --- | --- |
| `a rebuild is expected to pick up … or later` | The pip dependency range permits a fixed version, so a rebuild is expected to resolve the finding. |
| `which base the running image was built from cannot be confirmed` | The base behind a floating tag could not be confirmed, so the guidance is to pull the current base and rebuild. |
| Guidance to run `docker compose build --pull` | Instructions to pull the base again, without a confirmed improvement in vulnerabilities. |

Neither case confirms the version actually installed by a rebuild or resolution in the running image after deployment.
For details, see [Direct dependency version constraints](remediation-logic.md#direct-dependencies) and [Base layer matching](remediation-logic.md#base-layer-matching).

### Resolved findings in comparisons {#verification-results}

| Display | Meaning |
| --- | --- |
| `Resolved` | Findings present in the comparison target before the update but no longer detected after the update. |
| Remaining | Findings still present in the comparison target after the update. |
| Introduced | Findings absent from the comparison target before the update but detected after the update. |

The comparison targets depend on the type of update.

| Update type | What the comparison represents |
| --- | --- |
| Distributed image | The baseline image and the candidate image. |
| Dockerfile base image | The current base image and the candidate base image. |
| Language package | Dependency files before and after the update. |

!!! note "Resolution and running state"

    Resolution reported in a PR or Slack refers to a comparison result. It does not establish resolution in the complete rebuilt image or in running containers after deployment.

For the limits of these checks, see [Verification scope by target](remediation-logic.md#verification-scope); for comparison conditions, see [Scan comparison conditions](remediation-logic.md#comparison-conditions).
Dependency installation and application behavior have not been checked.

## Finding detailed results {#detailed-results}

### Webhook details {#webhook-details}

| Information needed | Field specification |
| --- | --- |
| Plan status, comparison conditions, processing limits, and usage | [Common remediation plan fields](webhook-remediation-reference.md#remediation-fields) |
| Distributed image candidates and comparison results | [Distributed image fields](webhook-remediation-reference.md#remediation-image-fields) |
| Base image candidates and layer verification results | [Base image fields](webhook-remediation-reference.md#remediation-dockerfile-fields) |
| Versions, processing, and exclusion reasons for each package, runtimes, tools, and update checks | [Language package fields](webhook-remediation-reference.md#remediation-language-fields) |
| PR status and packages left out of the PR that still need handling | [PR processing fields](webhook-remediation-reference.md#remediation-pr-fields) |
| Results of operations such as PR creation and reconciliation | [PR operation event fields](webhook-remediation-reference.md#remediation-operation-fields) |
| Problems that stopped PR writes | [Write-stopping problem fields](webhook-remediation-reference.md#remediation-problem-fields) |
| Example notification data including a partial PR | [Remediation plan JSON example](webhook-remediation-reference.md#remediation-json-example) |

### Saved record details {#saved-details}

Use `plan.json` for information from planning time and `prs.json` for ongoing PR records.
Check notifications for the current run's results after PR processing.

For stored contents and when they are recorded, see [Stored records](remediation-reference.md#stored-records); for retrieval steps, see [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics).
