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

See [PR management](remediation-logic.md#pr-management) for management conditions and [Enabling PR creation](remediation-setup.md#enable-pr-creation) for workflows triggered by PRs.

### Image candidate downloads {#candidate-registry-communication}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | Public image registries or registries with configured authentication | Retrieve tag lists, manifests, configs, and other information used to verify image identity | Looking for published-image or base-image candidates. |

See [Image registry authentication](configuration.md#remediation-registries) for authentication settings and [Image candidate selection](remediation-logic.md#image-selection) for candidate discovery.

### Work image downloads {#worker-image-downloads}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| Docker | Docker Hub or the configured mirror | Download official Node.js and Python work images | An image required for a language-package update is not available locally. |

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
| Work container | Public npm registry, PyPI, and distribution download destinations | Retrieve metadata and distributions for dependency resolution, lockfile generation, and checks | Running language-package dependency updates. |

See [Update processing by package manager](remediation-logic.md#manager-update-methods) for update processing.

### Notification delivery {#notification-delivery}

| Sender | Destination | Information retrieved or sent | When |
| --- | --- | --- | --- |
| KestreLynx | Configured Slack and generic webhook destinations | Send findings, plans, reasons, PR links, and operation results | The delivery conditions for each notification are met. |

Notifications may contain image references and digests, workload names, repository names, and source paths.
They may also contain package names and versions, vulnerability IDs, and comparison results, so configure destinations according to the information you can share.

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

Work containers use Docker bridge networking.
Destinations are not restricted by a network allowlist.

See [Runtime restrictions](remediation-logic.md#worker-restrictions) for restrictions other than networking.
