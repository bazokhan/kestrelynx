# Outbound communication

## Communication destinations {#outbound-communication}

This page lists destinations contacted by KestreLynx and the tools used for scanning and dependency updates.
Communication depends on the enabled features and the work required in each cycle.

### KEV downloads {#kev-download}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `www.cisa.gov` by default | Bulk download of the KEV feed | Triage is enabled and the feed needs to be downloaded or refreshed. |

Detected CVEs are matched locally; the list of detected CVEs is not sent to the download source.

See [Configuration](configuration.md) for the source, and [Threat intelligence updates](scan-logic.md#intel-cache) and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for updates and download failure handling.

### EPSS downloads {#epss-download}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `epss.empiricalsecurity.com` by default | Bulk download of the EPSS feed | Triage is enabled and the feed needs to be downloaded or refreshed. |

Detected CVEs are matched locally; the list of detected CVEs is not sent to the download source.

See [Configuration](configuration.md) for the source, and [Threat intelligence updates](scan-logic.md#intel-cache) and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for updates and download failure handling.

### Node.js advisory downloads {#node-runtime-download}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `raw.githubusercontent.com` by default | Bulk download of the `nodejs/security-wg` core index containing CVEs, severities, affected ranges, and fixed ranges | Node.js runtime checks are enabled and the data needs to be downloaded or refreshed. |
| KestreLynx | `nodejs.org` and `raw.githubusercontent.com` by default | Retrieve the security blog listing through RSS and post bodies as Markdown from `nodejs/nodejs.org` to supplement CVEs missing from security-wg | Node.js runtime checks are enabled and the data needs to be downloaded or refreshed. |
| KestreLynx | `nodejs.org` by default | Bulk download of `dist/index.json` containing release dates | Node.js runtime checks are enabled and the data needs to be downloaded or refreshed. |
| KestreLynx | `raw.githubusercontent.com` by default | Bulk download of `nodejs/Release`'s `schedule.json` containing release-line EOL dates | Node.js runtime checks are enabled and the data needs to be downloaded or refreshed. |

The security blog supplements security-wg because index updates can lag releases by several weeks or longer.
These public datasets are matched locally; image information and detected CVEs are not sent to the download sources.

Sources and mirror settings are described in [Node.js runtime checks](configuration.md#node-runtime), with refresh rules in [Threat intelligence updates](scan-logic.md#intel-cache) and failure handling in [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable).

### Python advisory downloads {#python-runtime-download}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `codeload.github.com` by default | Bulk download of the PSF `advisory-database` as a `tar.gz` archive containing the advisory list | Python runtime checks are enabled and the data needs to be downloaded or refreshed. |
| KestreLynx | `raw.githubusercontent.com` by default | Retrieve official records from `CVEProject/cvelistV5` for all CVEs in the PSF list, containing PSF-authored CPython version ranges and target OS information, severity, and `REJECTED` status | Python runtime checks are enabled and the records need to be downloaded or revalidated. |
| KestreLynx | `www.python.org` by default | Bulk download of the release list through the API, providing final releases in each release line | Python runtime checks are enabled and the data needs to be downloaded or refreshed. |
| KestreLynx | `peps.python.org` by default | Bulk download of release-cycle data providing each release line's EOL status | Python runtime checks are enabled and the data needs to be downloaded or refreshed. |

These public datasets are retrieved in full and matched locally; image information and detected CVEs are not sent to the download sources.
CVE record requests cover the PSF list rather than being selected from image findings.

Sources and mirror settings are described in [Python runtime checks](configuration.md#python-runtime), with refresh rules in [Threat intelligence updates](scan-logic.md#intel-cache) and failure handling in [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable).

### Hacker News searches {#hacker-news-search}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `hn.algolia.com` | Send CVE IDs classified as Act now by exploitation intelligence as search queries and retrieve discussion links | Triage and discussion links are enabled and an eligible CVE needs to be searched. |

See [Configuration](configuration.md) to enable searches.
[Notification delivery](#notification-delivery) continues when searches are disabled.

### Trivy downloads {#trivy-downloads}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| Trivy | Vulnerability database distribution registries | Download databases required for scanning | Databases need to be prepared for ordinary or comparison scans. |
| Trivy | Target image registries and distribution download destinations | Download images for scanning or comparison | Images required for scanning need to be downloaded from a registry. |

See [Scan comparison conditions](remediation-logic.md#comparison-conditions) for comparison conditions.

### GitHub communication {#github-communication}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `api.github.com` | Read mapped repositories, branches, and source files | Remediation planning checks sources. |
| KestreLynx | `api.github.com` | Match existing PRs and past operation results | PR processing is enabled. |
| KestreLynx | `api.github.com` | Create commits, branches, PRs, and replacement comments, and close eligible older PRs | PR processing is enabled and write conditions are met. |

PRs may contain image references and digests, workload names, repository names, source paths, and changes.
They may also contain package names and versions, vulnerability IDs, comparison results, and processing reasons.

For re-resolution PRs, KestreLynx sends dependent package names, versions before and after the update, and version requirements that block the update to GitHub to explain why packages such as `mkdirp` also need updates.
If an intermediate package requires an older version, its name is also included.

See [PR management](remediation-logic.md#pr-management) for management conditions and [Enabling PR creation](remediation-setup.md#enable-pr-creation) for workflows triggered by PRs.

### Image candidate downloads {#candidate-registry-communication}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | Public image registries or registries with configured authentication | Retrieve tag lists, manifests, configs, and other information used to verify image identity | Looking for published-image or base-image candidates. |

See [Image registry authentication](configuration.md#remediation-registries) for authentication settings and [Image candidate selection](remediation-logic.md#image-selection) for candidate discovery.

### Work image downloads {#worker-image-downloads}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| Docker or the Kubernetes node's container runtime | Docker Hub or the configured mirror | Download official Node.js and Python work images | An image required for a language-package update is not available locally. |
| Kubernetes node's container runtime | KestreLynx image registry | Download the image for the container receiving input files | An image required for a work Pod is not available locally. |

See [Work image source](configuration.md#remediation-worker-registry) for mirror settings and [Pinning official images](remediation-logic.md#worker-images) for pinning and handling unavailable images.

### Tool downloads {#tool-downloads}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `registry.npmjs.org` | Retrieve npm and pnpm version information and distributions | Tool version information needs to be checked or distributions downloaded. |
| KestreLynx | `pypi.org` and `files.pythonhosted.org` | Retrieve uv version information and distributions | Tool version information needs to be checked or distributions downloaded. |

Tool download requests and redirects are restricted to HTTPS on the hosts in this table.

See [Tool downloads and verification](remediation-logic.md#tool-verification) for retrieval and verification, and [Tool cache reuse](remediation-logic.md#tool-cache) for reuse.

### Dependency downloads {#dependency-downloads}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | `registry.npmjs.org` | Retrieve dependency versions, dependency relationships, and other metadata | Checking Node.js compatibility requirements or update results. |
| KestreLynx | `pypi.org` and `files.pythonhosted.org` | Retrieve Python package metadata and distributions | Checking Python update results. |
| KestreLynx | `registry.npmjs.org` | Retrieve dependency version requirements and publication dates and times using package names and versions | Checking requirements that block updates or whether 72 hours have elapsed since publication during npm or pnpm re-resolution. |
| KestreLynx | `pypi.org` | Retrieve dependency version requirements and distribution upload dates and times using package names and versions | Checking requirements that block updates or whether 72 hours have elapsed since publication during uv re-resolution. |

| Work container | Public npm registry, PyPI, and distribution download destinations | Retrieve metadata and distributions for dependency resolution, lockfile generation, and checks | Running language-package dependency updates. |

See [Update processing by package manager](remediation-logic.md#manager-update-methods) for update processing.

Re-resolution retrieves information about the update target `minimist`, its dependent package `mkdirp`, and newly introduced versions.
See [Re-resolution support and limits](remediation-reference.md#dependent-reresolution-limits) for limits on data transfer and other processing.

### Notification delivery {#notification-delivery}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | Configured Slack and generic webhook destinations | Send findings, plans, reasons, PR links, and operation results | The delivery conditions for each notification are met. |

Notifications may contain image references and digests, workload names, repository names, and source paths.
They may also contain package names and versions, vulnerability IDs, and comparison results, so configure destinations according to the information you can share.

Re-resolution notifications include dependent packages updated along with the targets, outcomes such as adoption, skipped attempts, or waiting periods, and their reasons.
Webhooks may also include version requirements, change lists, processing usage, and the earliest retry date and time.

To help identify remaining vulnerabilities and reasons for rejection, webhooks may also include package names, versions, dependent packages, vulnerability IDs, occurrence counts, and KEV listing information.

See [Notification conditions](notification-conditions.md#notification-conditions) for delivery conditions and [Webhook field reference](webhook-reference.md#generic-webhook) for JSON contents.

## Credential destinations {#credential-destinations}

| Credentials or communication | Destinations and restrictions |
| --- | --- |
| GitHub token | Sent only to `api.github.com` over HTTPS; redirects to other hosts are rejected. |
| Image registry credentials | Sent over HTTPS only to the configured registry and token services on the same host or allowed by `token_hosts`. |
| KestreLynx image-registry requests | Credentials are not forwarded to redirect destinations. |
| Trivy image-registry requests | Credentials may be included in redirects within the same host, but are not forwarded to other hosts. |
| Work container inputs | GitHub tokens and image registry credentials are not passed to work containers. |

Registries without configured authentication are accessed anonymously.

See [GitHub access](configuration.md#remediation-github) and [Image registry authentication](configuration.md#remediation-registries) for configuration formats.

## Work container network {#worker-network}

Docker work containers use bridge networking.
Destinations are not restricted by a network allowlist.

For Kubernetes work Pods, the user applies a NetworkPolicy.
The example in `deploy/kubernetes/work/40-networkpolicy.yaml` denies ingress and limits egress to DNS and TCP port 443 to IPv4 addresses outside the excluded ranges.

This example allows connections to public HTTPS sites generally, rather than restricting them to npm and PyPI.
A CNI that enforces NetworkPolicy is required, and standard NetworkPolicy does not block communication between a Pod and its execution node.
Until the CNI finishes applying the policy to a new Pod, egress may be unrestricted for a few seconds (observed with the default K3s CNI).

See [Kubernetes language-package updates](remediation-setup.md#kubernetes-language-updates) for installation adjustments and [Runtime restrictions](remediation-logic.md#worker-restrictions) for restrictions other than networking.

