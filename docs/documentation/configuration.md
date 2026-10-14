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
| `scan.severity` | `[HIGH, CRITICAL]` | Trivy severities retained for analysis and notification. |

Allowed severity values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

## Notification destinations

At least one destination is required.

| Option | Default | Description |
| --- | --- | --- |
| `notify.slack_webhook_url` | empty | Slack incoming webhook URL. |
| `notify.slack_bot_token` | empty | Slack bot token with `chat:write`. Set together with `slack_channel`. |
| `notify.slack_channel` | empty | Destination Slack channel ID for bot delivery. |
| `notify.generic_webhook_url` | empty | Endpoint that receives structured JSON. |
| `notify.language` | `en` | Language for Slack notifications and PR bodies: `en` or `ja`; other values are configuration errors. Generic webhook JSON remains in English. |
| `notify.notify_on_clean` | `false` | Send a notification when no vulnerabilities are found. |

Configure either `slack_webhook_url` or the bot-token pair, not both. A generic
webhook can be used alongside either Slack delivery method.

Bot threads are headed `Everything open now` (`未解決の所見の全体` in Japanese)
and attach to the first channel message when the report spans multiple messages.
When a thread is posted, that first message ends with the context footer
`📊 Everything open now is in this message's thread ↓`.
Without a new thread, a valid previous report link appears as
`🔗 Everything open as of the last report → thread` and refers to the state
at the time of that report.
No footer appears if neither applies or if the previous permalink is too long to display.

To use Japanese Slack notifications:

```yaml
notify:
  language: ja
```

The translated text and unchanged content are described in
[How KestreLynx works](how-it-works.md#notification-language).

## Notification mode

| Option | Default | Description |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff` reports changes; `full` reports all current findings on every scan. |
| `notify.full_report_day` | `monday` | Weekday for a full report in diff mode. Use `never` to disable it. |

Diff mode reports new findings, resolved findings, changes in fix availability,
priority escalations, and resumption after muting. When findings remain open but nothing changed,
KestreLynx sends a short heartbeat instead of repeating the entire report.

## State and Docker

| Option | Default | Description |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Path to the Docker socket. |
| `state.path` | `/var/lib/kestrelynx/state.json` | File used for scan history and diff calculations. |

Persist the directory containing `state.path` with a Docker volume, or a
persistent volume in Kubernetes. The intel feed cache lives in an `intel`
directory beside `state.path`, by default `/var/lib/kestrelynx/intel`.

## Remediation plans and pull requests {#remediation}

See the [remediation overview](remediation.md#contents) for an entry point and [Enabling remediation](remediation-setup.md) for setup instructions.

### Enablement settings {#remediation-enablement}

| Option | Default | Description |
| --- | --- | --- |
| `remediation.enabled` | `false` | Enable remediation plans. |
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
See [Credential destinations](how-it-works.md#credential-destinations) for where the token is sent.

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

See [Credential destinations](how-it-works.md#credential-destinations) for destination and redirect restrictions, and [Private image authentication](remediation-setup.md#configure-registry-auth) for setup instructions.

### Source mappings {#remediation-mappings}

| Option | Default | Description |
| --- | --- | --- |
| `remediation.mappings` | `[]` | Map running Compose workloads to their GitHub source files. |

Each entry sets `workload`, `repository`, and `base_branch`, plus exactly one source type.

| Field within a mapping | Requirements and format |
| --- | --- |
| `workload` | Required; `compose/<project>/<service>`, matching the running workload's Compose labels. |
| `repository` | Required; GitHub repository in `owner/name` form. |
| `base_branch` | Required; valid Git branch name used to read sources and as the PR base. |
| `compose.path` / `compose.service` | Required for Compose mappings; repository-relative Compose file and service name. |
| `dockerfile.path` | Required for Dockerfile mappings; repository-relative Dockerfile. |
| `dockerfile.target` | Optional build stage; omitting it selects the last stage; at most 128 bytes of letters, digits, `_`, `.`, or `-`, starting with a letter. |
| `dependencies.directory` | Required for dependency-file mappings; dependency directory, with `.` representing the repository root. |

- Paths must be normalized within the repository, without a leading `/`, `./`, `..`, or backslashes
- A workload can have one mapping of each source type in separate entries
- Shared dependency directories or Dockerfiles must use the same base branch
- A service in the same Compose file in the same repository must not be mapped to multiple workloads
- Repository names are case-insensitive when checking for duplicates

See [Base image identification](remediation-logic.md#base-image-selection) for discovery from Compose `build` and matching against an explicit Dockerfile, and [Supported input formats](remediation-reference.md#supported-inputs) for supported inputs.

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

### Work image source {#remediation-worker-registry}

| Option | Default | Format and validation |
| --- | --- | --- |
| `remediation.worker.registry` | empty | Docker Hub mirror in lowercase `host[:port][/path]` form; empty uses Docker Hub. |

- Do not include a scheme, tag, digest, `//`, or `..`
- Paths use lowercase letters, digits, and the separators `.`, `_`, and `-`
- The mirror must serve `library/node` and `library/python` with the same contents as the official images under the specified host and path

See [Pinning official images](remediation-logic.md#worker-images) for pinning and handling unavailable images, [Supported runtimes](remediation-reference.md#supported-runtimes) for version series, and [Work image downloads](how-it-works.md#worker-image-downloads) for network destinations.

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
- Enabling remediation plans with `kubernetes.enabled: true`

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

See [Outbound communication](how-it-works.md#outbound-communication) for where KestreLynx connects and what it sends.

Thresholds must satisfy:

```text
0 < watch_epss <= act_now_epss <= 1
```
