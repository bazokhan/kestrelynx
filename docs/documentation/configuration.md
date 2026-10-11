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
| `notify.language` | `en` | Slack notification language: `en` or `ja`. Any other value is a configuration error. Generic webhook JSON remains in English. |
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

## Remediation plans and pull requests

[Remediation plans and pull requests (experimental)](remediation.md) are available
for Docker, including Compose source mappings. Both switches default to `false`.

| Option | Default | Description |
| --- | --- | --- |
| `remediation.enabled` | `false` | Select candidates, compare scans, and notify a read-only remediation plan without GitHub writes or work containers. |
| `remediation.pull_requests.enabled` | `false` | Create GitHub pull requests from checked changes and use Docker work containers for language-package updates. |
| `remediation.github.token` | empty | GitHub token for the mapped repositories; required for pull requests. |
| `remediation.mappings` | `[]` | Map running Compose workloads to their GitHub source files. |
| `remediation.storage_dir` | `/var/lib/kestrelynx/remediation` | Absolute directory for plans, delivery records, and pull request records. |
| `remediation.worker.image` | empty | Override the release's work image with a digest-pinned reference. |

An empty token allows anonymous reads of public repositories for plans.
For private repositories, use a fine-grained token limited to the configured
repositories with Contents read access. Pull requests require Contents and
Pull requests permissions set to Read and write. Restrict the configuration
file to its owner; the token is not passed to work containers. Creating a pull
request may start the repository's CI.

Persist `remediation.storage_dir` across container recreation. Its default is
inside the supplied state volume; changing `state.path` does not move it.

### Source mappings

Each entry in `remediation.mappings` sets `workload`, `repository`, and
`base_branch`, plus exactly one source type.

| Field within a mapping | Description |
| --- | --- |
| `workload` | `compose/<project>/<service>`, matching the running workload's Compose labels. |
| `repository` | GitHub repository in `owner/name` form. |
| `base_branch` | Branch used to read source files and as the pull request base. |
| `compose.path` / `compose.service` | Repository-relative Compose file and service whose image reference can be edited. |
| `dockerfile.path` / `dockerfile.target` | Repository-relative Dockerfile and optional build stage; omitting the target selects the last stage. |
| `dependencies.directory` | Directory containing the dependency files for npm, pnpm, pip, or uv; `.` means the repository root. |

Paths must be normalized and stay inside the repository, without a leading
`/`, `./`, `..`, or backslashes. A workload can have one mapping of each
source type in separate entries. Shared dependency directories or Dockerfiles
must use the same base branch, and a Compose file's service cannot belong to
multiple workload mappings.

A Compose service with a supported static `build` section can supply its
Dockerfile path and target without a separate Dockerfile mapping. If both
are configured, they must agree.

### Processing limits

The following options are under `remediation.limits`. Work beyond a limit is
reported as deferred, rather than as having no candidate.

| Option | Default | Description |
| --- | --- | --- |
| `candidate_scans_per_cycle` | `10` | Maximum candidate-image scans per cycle. |
| `baseline_rescans_per_cycle` | `10` | Maximum baseline rescans needed to match comparison conditions per cycle. |
| `registry_requests_per_cycle` | `200` | Maximum image-registry HTTP requests per cycle, including token exchanges. |
| `tag_pages_per_repository` | `20` | Maximum tag-list pages for each image repository. |
| `cycle_timeout` | `30m` | Deadline for planning, dependency updates, and pull request processing, excluding ordinary running-image scans. |
| `new_prs_per_cycle` | `3` | Maximum new pull requests per cycle. |
| `open_prs` | `10` | Maximum open KestreLynx pull requests across the configured repositories. |
| `dependency_jobs_per_cycle` | `3` | Maximum dependency update units attempted per cycle (not packages or containers); one unit can use multiple containers, as with pip or manifest edits. |
| `job_timeout` | `6m` | Deadline for each work container's creation, execution, and result collection, from `1m` to `60m30s`; the job inside receives 30 seconds less, and cleanup has a separate 30-second deadline. |

Pull request limits apply when pull requests are enabled. Existing pull requests
are not closed merely to make room below `open_prs`.

### Work image and startup validation

Each main release specifies a digest-pinned
`ghcr.io/kitsunetrail/kestrelynx-worker` image. Leave `worker.image` empty to
use it, or set `repository@sha256:<64 lowercase hex digits>` for a mirror or a
work image you are verifying. The image is fetched when first needed.
If it cannot be fetched, or a custom build has no default image and no override,
language-package updates are deferred; package managers are never run in the
main container as a fallback.

Startup rejects pull requests without `remediation.enabled` or a token, and
rejects remediation with `kubernetes.enabled: true`. Storage paths, mappings,
positive limits, the `job_timeout` range, and any work-image override are
validated even when remediation is disabled. These configuration checks do
not establish that a remote repository or image is accessible.

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

KEV and EPSS feeds are downloaded in bulk and joined locally by CVE ID. The
host's complete CVE list is not uploaded to an external service. When discussion
links are enabled, act-now CVE IDs are sent as search queries to
`hn.algolia.com`. Set `discussion_links: false` to prevent that CVE egress, or
disable triage entirely to stop the additional intelligence-feed downloads.

Thresholds must satisfy:

```text
0 < watch_epss <= act_now_epss <= 1
```
