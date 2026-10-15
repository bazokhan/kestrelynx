# Scan and priority decisions

## Processing flow {#scan-cycle}

On each scan, KestreLynx checks running containers and updates findings and priorities.

1. Discover target containers on the Docker host or Kubernetes cluster
2. Combine scan targets by image reference and identity
3. Scan each target with Trivy and verify that the result matches the requested identity
4. Group findings by package and fix status
5. If triage is enabled, assign priorities using exploitation intelligence and severity

These results are used for [change and history decisions](diff-logic.md#comparison-baseline) and [notification decisions](notification-conditions.md#notification-conditions).
For processing when remediation planning is enabled, see [Remediation processing flow](remediation-logic.md#processing-flow).

## Scan targets {#scan-targets}

One KestreLynx instance monitors one Docker host or one Kubernetes cluster.

### Docker targets {#docker-targets}

On Docker, scans cover images used by running containers, including containers managed by Compose.

- Stopped containers and images not used by running containers are excluded
- Work containers that KestreLynx uses for dependency updates in remediation plans are excluded

See [Configuration](configuration.md) for Docker connection settings.

### Kubernetes targets {#kubernetes-targets}

On Kubernetes, targets are selected by each container's running state.

| Container type | Inclusion condition |
| --- | --- |
| Regular container | Running |
| Init container with `restartPolicy: Always` | Running |
| Ordinary init container | Excluded |
| Ephemeral container | Excluded |

See [Configuration](configuration.md) for selecting target namespaces.

### Image identity {#image-identity}

An image reference is a name such as `web:1.0`.
An image identity identifies the actual image content running under that reference.

| Environment | Information used to identify image content |
| --- | --- |
| Docker | Config digest reported by Docker |
| Kubernetes | Registry digest and the running node's OS and architecture |

Identical reference-and-identity pairs are combined into one entry.
Different identities under the same reference remain separate, while images whose identities are unknown are grouped by reference.

## Scan result verification {#scan-verification}

Before processing results, KestreLynx checks that discovery returned a complete list and verifies the identity of the scanned image.

### Container discovery failures {#discovery-failures}

If container discovery fails, the cycle ends without changing saved history.
During continuous operation, discovery is retried on the next scheduled cycle.

On Kubernetes, scanning does not proceed with partial results if only some of the required lists were retrieved.
This prevents containers missing from the returned lists from being treated as stopped.

### Image identity verification {#identity-verification}

When an image's identity is known, the scan targets that identity.

| Environment | Scan target | Result verification |
| --- | --- | --- |
| Docker | Local image selected by config digest | Matches the requested config digest |
| Kubernetes | Image selected by registry digest and platform | Matches the requested digest, OS, and architecture |

A result that cannot be verified against the requested identity is treated as a scan failure.
When the identity is unknown, the image is scanned by reference.

A reference scan alone cannot confirm that the running image content was scanned.
See [Scan warnings](slack-display.md#scan-warnings) for notification annotations.

### Handling scan failures {#scan-failures}

Failure to scan one target does not stop the remaining scans.
For references with saved history, previous findings are retained according to the following rules.

| Current state | Handling of previous findings |
| --- | --- |
| All scans for the same reference fail | Retain previous findings |
| Some scans for the same reference fail | Incorporate successful results and retain previous findings that may belong to failed identities |
| A Kubernetes reference scan succeeds but the identity remains unconfirmed | Retain findings using the same rules as for partial failures |

For partial failures, previous and current CVE IDs are combined and the higher priority is retained, separately for ordinary and EOL findings.
Previous fix availability is also retained for ordinary findings.

See [Retained history](diff-logic.md#retained-findings) for its effect on diffs.

## Package-level grouping {#package-grouping}

Findings are combined into one group when the following attributes match.

- Image reference and identity
- Package ecosystem, OS or language package class, name, and installed version
- Normalized fix status

Packages with the same name remain separate when their ecosystem, installed version, or fix status differs.
CVE IDs are deduplicated within each group.

See [Exploitation-based priority](#triage) for group priorities and [Comparison baseline](diff-logic.md#comparison-baseline) for how history is compared.

## Finding classification {#finding-classification}

Severity, fix status, EOL, and priority describe different aspects of a finding.

| Classification | Meaning |
| --- | --- |
| Severity | Potential impact of the vulnerability |
| Fix status | Fix or investigation status on the target platform |
| EOL | End or scope of support for the base OS or package |
| Priority | Urgency of attention based on exploitation intelligence |

### Severity {#severity}

KestreLynx uses the severity reported by Trivy.
See [Configuration](configuration.md) for selecting severity levels and their defaults.

Severity and priority do not necessarily match.
Priority follows the [Priority rules](#cve-priority-rules).

### Fix status {#status}

Fix status comes from Trivy's `Status` and is not inferred from the fixed-version field.
Statuses are normalized during grouping as follows.

| Trivy `Status` | Meaning | Grouped as |
| --- | --- | --- |
| `fixed` | A fixed version is available | `fixed` |
| `affected` | Affected, with no fix available | `affected` |
| `will_not_fix` | No current plan to fix it on the target platform | `will_not_fix` |
| `fix_deferred` | Fix deferred | `affected` |
| `under_investigation` | Under investigation | `affected` |
| `unknown` | Fix status unknown | `affected` |
| `end_of_life` | Outside the support scope | `end_of_life` |
| `not_affected` | Not affected | Excluded from grouping, notifications, and priority classification |
| Missing or empty | Treated as `unknown` | `affected` |
| Any other value | Preserved as an undefined status | `affected` |

For OS packages, `will_not_fix` describes the policy for the target OS release.
It does not mean that a fix is unavailable from the software's developer or in another OS release.

See [Webhook vulnerability fields](webhook-reference.md#vulnerability-fields) for the field that exposes the original status.

### Base OS EOL {#eol-base}

Base OS EOL is determined from the OS end-of-support status reported by Trivy.
It is handled independently of individual CVE priorities.

If the base OS is EOL, consider updating to a supported base image and rebuilding.
See [EOL display](slack-display.md#eol-display) for how this appears in Slack.

### Package EOL {#eol-package}

Package EOL findings have a Trivy `Status` of `end_of_life`.
The distributor treats these CVEs as outside the target release's support scope, with no fix planned for that release.

EOL findings are handled separately from ordinary findings, and both can exist for the same package.
This classification continues when triage is disabled.

## Exploitation-based priority {#triage}

Triage uses exploitation intelligence to assign a priority to each CVE.
Each package group receives the highest priority of any CVE it contains.

| Source | Information used |
| --- | --- |
| CISA KEV | Inclusion in the catalog of vulnerabilities known to have been exploited |
| EPSS | Estimated probability of exploitation activity being observed in the next 30 days |

EPSS does not directly measure vulnerability impact or the probability of exploitation in the monitored environment.

### Priority rules {#cve-priority-rules}

When usable threat intelligence is available, the following table is evaluated from top to bottom.
See [Configuration](configuration.md) for threshold settings and defaults.

| Priority | Condition |
| --- | --- |
| Act now | Listed in KEV, or a known EPSS score meets or exceeds the Act now threshold |
| Watch | Does not qualify for Act now, and either a known EPSS score meets or exceeds the Watch threshold or severity is CRITICAL |
| Low | Neither condition above applies |

- For CVEs without an EPSS score, EPSS conditions are skipped rather than treating the score as 0
- KEV ransomware information does not create a separate priority

### Priority adjustments by fix status {#status-priority}

During normal triage, the assigned priority is handled as follows.

| Fix status | Priority handling |
| --- | --- |
| `will_not_fix` | Reduce Watch to Low; retain Act now and Low |
| `fixed`, `affected`, `end_of_life` | Retain the assigned priority |
| Other statuses grouped as `affected` | Apply the same rules as `affected` |

Act now is never lowered because no fix is available.
Even when a fix is unavailable, consider mitigation, replacement, or migration to a supported version.

### Threat intelligence updates {#intel-cache}

During each scan, KestreLynx checks the age of the KEV and EPSS caches and attempts a refresh if at least 20 hours have passed since retrieval.
If a refresh fails, a validated cache remains usable for up to 7 days after retrieval.

Caches older than this limit are treated as unavailable for priority decisions.
See [Configuration](configuration.md) for cache storage and persistence.

### Unavailable threat intelligence {#degraded-triage}

The decision method depends on which sources are usable.

| Available intelligence | Decision method |
| --- | --- |
| KEV and EPSS | Apply normal rules using both sources |
| KEV only | Use KEV and severity |
| EPSS only | Use EPSS and severity |
| Neither | Assign CRITICAL to Act now and other selected severities to Watch |

When neither source is usable, KestreLynx uses degraded triage.
During degraded triage, nothing is classified as Low, and `will_not_fix` does not reduce Watch to Low.

See [Ordinary package changes](diff-logic.md#normal-changes) and [EOL package changes](diff-logic.md#eol-package-changes) for escalation diffs during degraded triage.
See [Threat intelligence warnings](slack-display.md#intel-warnings) for how unavailable sources and stale caches are displayed.

### Decisions with triage disabled {#triage-disabled}

When triage is disabled, CVEs and package groups receive no priority.
KEV and EPSS downloads and Hacker News discussion-link searches also stop.

Scanning and fix-status classification continue.
See [Configuration](configuration.md) for enabling or disabling triage and [Section order with triage disabled](slack-display.md#triage-disabled-display) for the display.
