# Configuration

This page describes the YAML configuration file. The container image uses
`/etc/kestrelynx/config.yml` by default. Unknown YAML fields produce an error.

The complete annotated example is available in
[`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml).

## Schedule

| Option | Default | Description |
| --- | --- | --- |
| `schedule.daily_at` | empty | Local time in `HH:MM`. When empty, run every 24 hours from startup. |
| `schedule.run_on_start` | `true` | Run one scan immediately when KestreLynx starts. |

Use the container's `TZ` environment variable to select the timezone used by
`daily_at`.

## Scanning

| Option | Default | Description |
| --- | --- | --- |
| `scan.severity` | `[HIGH, CRITICAL]` | Severities retained for analysis and notification, including Node.js and Python runtime findings. |

Allowed severity values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

### Language runtime checks {#language-runtime}

KestreLynx checks the runtimes of languages whose package updates it supports: Node.js and Python.

#### Node.js runtime checks {#node-runtime}

KestreLynx checks the Node.js version recorded in `NODE_VERSION` against Node.js security advisories.
Matching rules and limitations are described in [Node.js runtime findings](scan-logic.md#node-runtime).

| Option | Default | Description |
| --- | --- | --- |
| `scan.node_runtime.enabled` | `true` | Enable advisory downloads and Node.js runtime checks; `false` disables both. |
| `scan.node_runtime.security_wg_url` | empty | Mirror URL for the security-wg core index; empty uses `https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json`. |
| `scan.node_runtime.blog_feed_url` | empty | Mirror URL for the security blog RSS feed; empty uses `https://nodejs.org/en/feed/vulnerability.xml`. |
| `scan.node_runtime.blog_post_base_url` | empty | Mirror base URL for blog post Markdown; empty uses `https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/`. |
| `scan.node_runtime.releases_url` | empty | Mirror URL for release dates; empty uses `https://nodejs.org/dist/index.json`. |
| `scan.node_runtime.schedule_url` | empty | Mirror URL for release-line EOL dates; empty uses `https://raw.githubusercontent.com/nodejs/Release/main/schedule.json`. |

The cache is stored under `nodejs/` in the same directory as `state.path`.
Download destinations are listed in [Node.js advisory downloads](outbound-communication.md#node-runtime-download).

#### Python runtime checks {#python-runtime}

KestreLynx checks the CPython version recorded in `PYTHON_VERSION` against Python security advisory data.
Matching rules and limitations are described in [Python runtime findings](scan-logic.md#python-runtime).

| Option | Default | Description |
| --- | --- | --- |
| `scan.python_runtime.enabled` | `true` | Enable advisory downloads and Python runtime checks; `false` disables both. |
| `scan.python_runtime.advisory_db_url` | empty | Mirror URL for the PSF advisory database archive; empty uses `https://codeload.github.com/psf/advisory-database/tar.gz/refs/heads/main`. |
| `scan.python_runtime.cve_record_base_url` | empty | Mirror base URL for official CVE records; empty uses `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/`. |
| `scan.python_runtime.releases_url` | empty | Mirror URL for the release list; empty uses `https://www.python.org/api/v2/downloads/release/?is_published=true`. |
| `scan.python_runtime.release_cycle_url` | empty | Mirror URL for release-cycle data; empty uses `https://peps.python.org/api/release-cycle.json`. |

The cache is stored under `python/` in the same directory as `state.path`.
Download destinations are listed in [Python advisory downloads](outbound-communication.md#python-runtime-download).

## Notification destinations

At least one destination is required.

| Option | Default | Description |
| --- | --- | --- |
| `notify.slack_webhook_url` | empty | Slack incoming webhook URL for channel notifications. |
| `notify.slack_bot_token` | empty | Slack bot token with `chat:write`. Set together with `slack_channel` to enable thread posts and links to the previous report. |
| `notify.slack_channel` | empty | Destination Slack channel ID for bot delivery. |
| `notify.generic_webhook_url` | empty | Endpoint that receives structured JSON. |
| `notify.language` | `en` | Language for Slack notifications and PR bodies: `en` or `ja`; other values are configuration errors. Generic webhook JSON remains in English. |
| `notify.notify_on_clean` | `false` | Send a notification when no vulnerabilities are found. |

Configure either `slack_webhook_url` or the bot-token pair, not both. A generic
webhook can be used alongside either Slack delivery method.

See [Thread reports](slack-display.md#thread-display) for thread placement and how to read the footers.

To use Japanese Slack notifications:

```yaml
notify:
  language: ja
```

See [Notification language](slack-display.md#notification-language) for the fixed text that is translated and the content that remains in English.

## Notification mode

| Option | Default | Description |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff` reports changes; `full` reports all current findings on every scan. |
| `notify.full_report_day` | `monday` | Weekday for a full report in diff mode. Use `never` to disable it. |

See [Package changes](diff-logic.md#package-changes) for changes treated as differences, and [Scan notification conditions](notification-conditions.md#notification-conditions) for when notifications are sent.

## State and Docker

| Option | Default | Description |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Path to the Docker socket. |
| `state.path` | `/var/lib/kestrelynx/state.json` | File used for scan history and diff calculations. |

The intel feed cache lives in an `intel` directory beside `state.path`.
The default path is `/var/lib/kestrelynx/intel`.

See [Setup instructions](getting-started.md) for persisting the directory containing `state.path`, and [History continuity](diff-logic.md#state-lifecycle) for how history is handled.

## Remediation plans and pull requests {#remediation}

See the [remediation overview](remediation.md#contents) for an entry point and [Enabling remediation](remediation-setup.md) for setup instructions.

### Enablement settings {#remediation-enablement}

| Option | Default | Description |
| --- | --- | --- |
| `remediation.enabled` | `false` | Enable read-only remediation plans in Docker or Kubernetes mode. |
| `remediation.pull_requests.enabled` | `false` | Enable fix pull requests; requires remediation plans and a GitHub token. |

See [Plan and PR execution scope](remediation-logic.md#plan-and-pr-execution) for the processing enabled by each setting.

### GitHub access {#remediation-github}

| Option | Default | Format and requirements |
| --- | --- | --- |
| `remediation.github.token` | empty | GitHub token without whitespace or control characters; required when pull requests are enabled. |

| Purpose | Required permissions |
| --- | --- |
| Plans for public repositories | Anonymous reads without a token |
| Plans for private repositories | Contents: Read on a fine-grained token limited to the target repositories |
| Creating and managing PRs | Contents and Pull requests: Read and write on a fine-grained token limited to the target repositories |

Restrict the configuration file to its owner.
See [Credential destinations](outbound-communication.md#credential-destinations) for where the token is sent.

### Storage location {#remediation-storage}

| Option | Default | Format and description |
| --- | --- | --- |
| `remediation.storage_dir` | `/var/lib/kestrelynx/remediation` | Absolute directory for plans, delivery records, PR records, and the tool cache. |

Changing `state.path` does not change this location.
See [Stored files](remediation-reference.md#stored-records) for its contents.

### Image registry authentication {#remediation-registries}

| Option | Default | Description |
| --- | --- | --- |
| `remediation.registries` | `[]` | Per-host credentials for private-image candidate selection and comparison scans. |

| Field | Default or requirement | Format and validation |
| --- | --- | --- |
| `host` | required | Hostname or IPv4 address as used in image references, with an optional port from `1` to `65535`; no scheme, path, or user information. |
| `username` | required | Nonempty string without whitespace, control characters, or `:`. |
| `password` | required | Nonempty password or access token without whitespace or control characters. |
| `token_hosts` | `[]` | Additional token service hosts allowed to receive credentials; each value uses the same format as `host`. |

- Hostnames are case-insensitive, and `docker.io`, `index.docker.io`, and `registry-1.docker.io` are treated as the same host
- Credential entries must not have duplicate `host` values after normalization
- For Docker Hub authentication, set `host: docker.io` and `token_hosts: [auth.docker.io]`

See [Credential destinations](outbound-communication.md#credential-destinations) for destination and redirect restrictions, and [Private image authentication](remediation-setup.md#configure-registry-auth) for setup instructions.

### Source mappings {#remediation-mappings}

| Option | Default | Description |
| --- | --- | --- |
| `remediation.mappings` | `[]` | Map running Compose or Kubernetes workloads, or Docker containers that do not use Compose, to their GitHub source files. |

Each entry sets `workload`, `repository`, and `base_branch`, plus exactly one source type.

- `container/<name>` is available only in Docker mode and only for `dockerfile` or `dependencies` mappings
- The name is the `NAMES` value shown by `docker ps`, assigned with `docker run --name`; it is case-sensitive and must be 2–253 bytes matching `[a-zA-Z0-9][a-zA-Z0-9_.-]+`
- Combining `container/<name>` with a `compose` mapping causes a configuration error that directs you to use `compose/<project>/<service>`
- Specifying `container/<name>` in Kubernetes mode causes a configuration error

Kubernetes mode accepts `manifest`, `kustomize`, `helm_values`, `dockerfile`, and `dependencies` mappings.
`compose` is available only in Docker mode, and `manifest`, `kustomize`, and `helm_values` only in Kubernetes mode.
When remediation plans are enabled and a mapping's namespace is outside `kubernetes.namespaces`, startup logs a warning and the mapping has no effect on the plan.

| Field within a mapping | Requirements and format |
| --- | --- |
| `workload` | Required; in Docker mode, `compose/<project>/<service>`, matching the running workload's Compose labels, or `container/<name>` for a container that does not use Compose; in Kubernetes mode, `<kind>/<namespace>/<name>/<container>`, where `kind` is `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, or `pod`. |
| `repository` | Required; GitHub repository in `owner/name` form. |
| `base_branch` | Required; valid Git branch name used to read sources and as the PR base. |
| `compose.path` / `compose.service` | Required for Compose mappings; repository-relative Compose file and service name. |
| `manifest.path` | Required for manifest mappings; repository-relative file path. |
| `manifest.object.kind` | Optional; defaults to the workload kind and, when specified, must be the matching `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, or `Pod`. |
| `manifest.object.name` | Optional; defaults to the workload name, or names the object in the file when specified. |
| `kustomize.path` | Required for Kustomize mappings; repository-relative path whose filename is `kustomization.yaml`, `kustomization.yml`, or `Kustomization`. |
| `kustomize.image` | Required; the target `images[].name`, without a tag or digest. |
| `kustomize.affects` | Optional; workload keys of every other container affected by this entry, including ordinary init containers; duplicates and the mapped `workload` itself are not allowed. Omitting it means the user has confirmed that the entry affects only the mapped container. |
| `helm_values.path` | Required for Helm values mappings; repository-relative path with a `.yaml` or `.yml` extension. |
| `helm_values.key` | Required; at most 255 bytes of nonempty names made of `[A-Za-z0-9_-]`, separated by dots. Selects the image mapping or string, such as `image` or `app.image`; keys containing literal dots are unsupported. |
| `helm_values.affects` | Optional; workload keys of every other container affected by this key, including ordinary init containers; duplicates and the mapped `workload` itself are not allowed. Omitting it means the user has confirmed that the key affects only the mapped container. |
| `dockerfile.path` | Required for Dockerfile mappings; repository-relative Dockerfile. |
| `dockerfile.target` | Optional build stage; omitting it selects the last stage; at most 128 bytes of letters, digits, `_`, `.`, or `-`, starting with a letter. |
| `dependencies.directory` | Required for dependency-file mappings; dependency directory, with `.` representing the repository root. |

- Paths must be normalized within the repository, without a leading `/`, `./`, `..`, or backslashes
- A workload can have one mapping of each source type in separate entries, but cannot combine `manifest`, `kustomize`, and `helm_values`
- Shared dependency directories or Dockerfiles must use the same base branch
- A service in the same Compose file in the same repository must not be mapped to multiple workloads
- A container of an object with the same kind, namespace, and name in the same manifest and repository must not be mapped to multiple workloads
- Every mapping to the same Kustomize entry or the same Helm values key must declare the same combined set of `workload` and `affects`
- Each container, including those listed in `affects`, must have only one location determining its image tag, including `manifest` locations
- Every mapping to the same Kustomize file or Helm values file in the same repository must specify the same `base_branch`
- Repository names are case-insensitive when checking for duplicates

See [Base image identification](remediation-logic.md#base-image-selection) for discovery from Compose `build` and matching against an explicit Dockerfile, and [Supported input formats](remediation-reference.md#supported-inputs) for supported inputs.

See [Kustomize PR configuration](remediation-setup.md#kustomize-pull-requests) and [Helm values PR configuration](remediation-setup.md#helm-values-pull-requests) for examples and how to declare affected containers.
Violating the mapping constraints above causes a startup error.

### Processing limits {#remediation-limits}

The following options are under `remediation.limits`.

| Option | Default | Units and allowed range |
| --- | --- | --- |
| `candidate_scans_per_cycle` | `10` | Candidate-image scans per cycle; positive integer. |
| `baseline_rescans_per_cycle` | `10` | Baseline rescans per cycle to match comparison conditions; positive integer. |
| `registry_requests_per_cycle` | `200` | Image-registry HTTP requests per cycle, including token exchanges; positive integer. |
| `tag_pages_per_repository` | `20` | Tag-list requests per image repository, including requests to find the target version series; positive integer. |
| `cycle_timeout` | `30m` | Deadline for planning, dependency updates, and PR processing; positive duration, excluding ordinary running-image scans. |
| `new_prs_per_cycle` | `3` | New PRs per cycle when PRs are enabled; positive integer. |
| `open_prs` | `10` | Open KestreLynx PRs across all configured repositories when PRs are enabled; positive integer. |
| `dependency_jobs_per_cycle` | `3` | Dependency update units attempted per cycle; positive integer, not a count of packages or containers. |
| `job_timeout` | `6m` | Deadline for each work container's creation, execution, and result collection; from `1m` to `60m30s`. |

See [Reason codes](remediation-reference.md#reason-codes) for outcomes caused by limits, [PR management](remediation-logic.md#pr-management) for PR handling, and [Work container execution](remediation-logic.md#worker-execution) for execution deadlines and cleanup.

### Work Pod configuration {#remediation-worker-kubernetes}

These settings apply to language-package updates in Kubernetes mode.
The user applies the work namespace and required resources following the [setup steps](remediation-setup.md#kubernetes-language-updates).

| Setting | Default | Format and scope |
| --- | --- | --- |
| `remediation.worker.kubernetes.namespace` | empty | Namespace for work Pods; when unset, language-package updates require manual action with `work_namespace_not_configured`. |
| `remediation.worker.kubernetes.service_account` | `kestrelynx-work` | ServiceAccount for work Pods; specify one without permissions or a token. |
| `remediation.worker.kubernetes.priority_class` | `kestrelynx-work` | PriorityClass for work Pods; specify one with `preemptionPolicy: Never`. |
| `remediation.worker.kubernetes.receiver_image` | empty | KestreLynx image for the container receiving input files, in `repository@sha256:...` form; empty reads the digest-pinned reference from the status of KestreLynx's own Pod. |
| `remediation.worker.kubernetes.max_concurrent_pods` | `1` | Maximum work Pods held by the same instance at once, from `1` to `16`, including finished Pods that have not been deleted and excluding Pods already being deleted; the work namespace's ResourceQuota limits the total including those. |
| `remediation.worker.kubernetes.runtime_class` | empty | Unsupported and must remain empty; setting it requires manual action with `work_runtime_class_unsupported`. |

These settings require `kubernetes.enabled: true`.
Setting other fields without `namespace`, or supplying invalid names, image references, or numeric values, causes a startup error.
### Work image source {#remediation-worker-registry}

| Option | Default | Format and validation |
| --- | --- | --- |
| `remediation.worker.registry` | empty | Docker Hub mirror in lowercase `host[:port][/path]` form; empty uses Docker Hub. |

- Do not include a scheme, tag, digest, `//`, or `..`
- Paths use lowercase letters, digits, and the separators `.`, `_`, and `-`
- The mirror must serve `library/node` and `library/python` with the same contents as the official images under the specified host and path

See [Pinning official images](remediation-logic.md#worker-images) for pinning and handling unavailable images, [Supported runtimes](remediation-reference.md#supported-runtimes) for version series, and [Work image downloads](outbound-communication.md#worker-image-downloads) for network destinations.

### Minimum tool release age {#remediation-tool-release-age}

| Option | Default | Format and allowed range |
| --- | --- | --- |
| `remediation.worker.tool_versions.min_release_age` | `72h` | Minimum wait between publication and use of npm, pnpm, or uv; positive duration such as `72h` or `30m`, excluding `0` and negative values. |

See [Waiting after tool publication](remediation-logic.md#tool-release-age) for the decision rules and [Tool downloads and verification](remediation-logic.md#tool-verification) for download checks.

### Tool cache capacity {#remediation-tool-cache}

| Option | Default | Format and allowed range |
| --- | --- | --- |
| `remediation.worker.tool_versions.cache_max_size` | `1GiB` | Maximum npm, pnpm, and uv cache size; integer bytes or an integer followed by `B`, `KiB`, `MiB`, or `GiB`, with a minimum of `128MiB`. |

See [Tool cache reuse](remediation-logic.md#tool-cache) for checks before reuse and handling insufficient capacity.

### Worker program location {#remediation-worker-program}

| Option | Default | Format and scope |
| --- | --- | --- |
| `remediation.worker.program_dir` | empty | Empty or an absolute directory containing a worker program for development; not required for standard releases. |

See [Container inputs](remediation-logic.md#worker-inputs) for checks when passing the program to a work container.

### Startup validation {#remediation-validation}

The following combinations cause startup errors.

- Enabling PRs without `remediation.enabled`
- Enabling PRs without `remediation.github.token`
- Specifying a `manifest`, `kustomize`, or `helm_values` mapping in Docker mode
- Specifying a `compose` mapping in Kubernetes mode

Token format, storage, mappings, processing limits, registry credentials, and work container settings are validated even when the feature is disabled.
These configuration checks do not establish that a remote repository or image is accessible.

## Runtime usage

[Runtime usage](runtime-usage.md) is an experimental feature.

| Option | Default | Description |
| --- | --- | --- |
| `runtime.enabled` | `false` | Read Sensor evidence and include runtime usage in notifications. Leave disabled when no Sensor is installed. |
| `runtime.mute_unfixable_not_in_use` | `false` | Mute eligible findings with no fix and no observed use for 7+ days in Slack. Requires `runtime.enabled: true`; priority is unchanged and all findings remain in the generic webhook. |
| `runtime.evidence_dir` | `/var/lib/kestrelynx-runtime` | Absolute path where the Sensor evidence volume is mounted. Must match the Sensor's `--evidence-dir`. |

With `runtime.enabled: false`, KestreLynx does not open the evidence directory
or add runtime information to notifications. Ecosystem labels and webhook
ecosystem fields apply independently of this setting.

Setting both `runtime.enabled: true` and `kubernetes.enabled: true` is a
configuration error. Runtime usage is available only for Docker.

When enabled, KestreLynx also uses Docker API `GET /containers/{id}/json`,
in addition to `GET /containers/json`. Containers with the label
`io.kestrelynx.runtime.exclude=true` are excluded from runtime usage
assessment; only the lowercase value `true` matches.

See [Runtime usage](runtime-usage.md) for Sensor setup, observation rules,
muting conditions, notification resumption, and permissions.

## Kubernetes

| Option | Default | Description |
| --- | --- | --- |
| `kubernetes.enabled` | `false` | Scan a Kubernetes cluster instead of a Docker host. |
| `kubernetes.api_server` | empty | Kubernetes API server URL. When empty, use `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`. A non-empty value must start with `https://`. |
| `kubernetes.token_file` | empty | ServiceAccount token file. When empty, use `/var/run/secrets/kubernetes.io/serviceaccount/token`. |
| `kubernetes.ca_file` | empty | Cluster CA bundle in PEM format. When empty, use `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `kubernetes.tls_server_name` | empty | Override the server name used to validate the API server's TLS certificate. Empty means no override. |
| `kubernetes.namespaces` | `[]` | Namespaces to scan. Empty or omitted means every namespace. |

Setting `docker.socket` to a value, including `""`, together with `kubernetes.enabled: true`
fails at startup. Omitting the key or setting it to `null` does not cause this conflict.
An empty `docker:` section is accepted. Remove the entire `docker:` section when enabling Kubernetes.

Inside a cluster, `api_server`, `token_file`, and `ca_file` can remain empty to
use the Pod's injected API server address and mounted ServiceAccount token and
CA. With Kubernetes enabled, startup fails if `api_server` is empty and either
API server environment variable is missing. The CA bundle must be readable and
contain valid PEM certificates at runtime; there is no insecure fallback.

Each namespace must be a DNS-1123 label: lowercase alphanumerics and hyphens,
1–63 bytes, starting and ending with an alphanumeric. When namespaces are set,
Pods, ReplicaSets, and Jobs are listed separately in each namespace. Node
listing remains cluster-wide.

## Environment

| Option | Default | Description |
| --- | --- | --- |
| `environment.name` | empty | Optional name for this instance's scan history. Empty means the unnamed default environment. |

A non-empty name must be a DNS-1123 label: lowercase alphanumerics and hyphens,
1–63 bytes, starting and ending with an alphanumeric. Values are not normalized;
uppercase letters, dots, underscores, and whitespace are rejected.

When set, the name appears as `[name]` in the Slack header and as `name` in the
generic webhook payload's `environment` object. That object always includes
`kind`, either `docker` or `kubernetes`, derived from the enabled adapter. The
environment kind is not configurable. The webhook omits `name` when it is empty.

The name labels scan history rather than identifying the host; it is not
derived from a hostname or IP address. It is safe to keep the same name across
host rebuilds and migrations while retaining the state file. Adding, changing,
or removing the name does not reset history, change first-seen dates, or
re-notify existing findings.

## Exploitation-based triage

| Option | Default | Description |
| --- | --- | --- |
| `triage.enabled` | `true` | Enable CISA KEV- and EPSS-based prioritization. |
| `triage.act_now_epss` | `0.10` | EPSS probability at or above which a CVE becomes act now. |
| `triage.watch_epss` | `0.01` | EPSS probability at or above which a CVE is at least watch. |
| `triage.kev_url` | empty | Override the CISA KEV feed URL, for example with a local mirror. |
| `triage.epss_url` | empty | Override the EPSS feed URL, for example with a local mirror. |
| `triage.discussion_links` | `true` | Look up Hacker News discussions for act-now CVEs. |

See [Outbound communication](outbound-communication.md#outbound-communication) for where KestreLynx connects and what it sends.

Thresholds must satisfy:

```text
0 < watch_epss <= act_now_epss <= 1
```
