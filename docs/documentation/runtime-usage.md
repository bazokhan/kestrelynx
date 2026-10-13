# Runtime usage

!!! warning "Experimental feature"

    Sensor (runtime usage) is an experimental feature.
    Its configuration, display, and evidence formats may change, and the feature may be frozen.

An optional Sensor container on a Docker host marks findings for packages in use
and puts those packages and their images first within the same priority.
It does not change priority.

The Sensor observes packages used by running programs, and KestreLynx includes
the results in Slack and webhook notifications. With triage disabled, usage is
still shown, but results are not reordered.

[Remediation plans and pull requests (experimental)](remediation.md) do not require
the Sensor and can be used with `runtime.enabled: false`.

## Meaning of usage

| Usage | Meaning |
| --- | --- |
| `in_use` | Use was confirmed under the rules below. |
| `not_observed` | Use was not confirmed during the observation window. This does not mean unused. |
| `unavailable` | Evidence is insufficient to assess usage. A reason is included. |

| Package type | Rule for marking it in use |
| --- | --- |
| OS package | A running process executed a file from the package or loaded it as a library, as seen by sampling or by eBPF execution and library-load events from short-lived processes. |
| Language package compiled into a binary, such as Go or Rust | The executable identified by Trivy's Target is running as a process. |
| Language package loaded by a runtime, such as Python, Node.js, or Java | A corresponding runtime process, such as `python`, `node`, or `java`, is running in the container. All packages in that ecosystem are then considered in use. |

Treating all packages in an ecosystem as in use because its runtime process is running is KestreLynx's conservative classification rule, rather than confirmation that each dependency is actually used.

Function calls and module imports are not checked. Reading a data file does not
count as evidence of use.

With `notify.language: en`, Slack shows `Runtime: ▶ in use` in package cards.
Detailed cards put the observed activity on an `Evidence:` line, while compact
cards use a short line such as `Runtime: ▶ in use (running)`.
Threads also show `Runtime: ▷ not observed` or
`Runtime: ▷ runtime evidence unavailable (<reason>)`.
The notification text, ordering, and webhook fields are described in
[How KestreLynx works](how-it-works.md).

## Requirements

Docker and cgroup v2 are required. Runtime usage is not available on Kubernetes;
enabling both `runtime.enabled` and `kubernetes.enabled` is a configuration error.

The supplied Compose file runs the Sensor as non-root UID 65532 with these settings:

- `pid: host`
- `cgroup: host`
- `userns_mode: host`
- `network_mode: none`
- `read_only: true`
- `cap_drop: [ALL]`
- `cap_add: [SYS_PTRACE, DAC_READ_SEARCH, BPF, PERFMON]`
- The supplied seccomp profile

`cgroup: host` is required because, in its own cgroup namespace, the Sensor
reads other containers' `/proc/<pid>/cgroup` paths relative to that namespace's
root and cannot match them to any container. On a cgroup v2 host, without this
setting, the Sensor exits at startup with exit code 1 and the following error
on standard error. With `docker run`, use `--cgroupns host`.

```text
kestrelynx sensor: sensor: this container is not in the host's cgroup namespace; run it with `cgroup: host` (compose) or `--cgroupns host` (docker run)
```

`userns_mode: host` is required when the Docker daemon has userns-remap enabled;
without it, sharing the host PID namespace is refused. In other environments,
this setting is the same as the default.

eBPF observation of short-lived processes requires a kernel with BTF. Without
BPF or PERFMON, without BTF, or on a cgroup v1 host, the Sensor warns and continues
with sampling only. Short-lived processes cannot be observed in that mode.

| Environment | Verification |
| --- | --- |
| Ubuntu 26.04 | Linux 7.0, AppArmor enabled, Docker 29.5.1; x86_64, cgroup v2 with the systemd driver. |
| WSL2 | Linux 6.6, Docker Engine 29.1.3; x86_64, cgroup v2 with the systemd driver. |
| WSL2 (cgroupfs driver) | Linux 6.6, Docker Engine 29.1.3; x86_64, cgroup v2 with the cgroupfs driver. |
| WSL2 (userns-remap) | Linux 6.6, Docker Engine 29.1.3; x86_64, cgroup v2 with the systemd driver. |
| arm64 | Unverified. |

On hosts with AppArmor enabled, reads of files in unconfined or privileged
containers are denied, and those containers receive `permission denied`.
Files in containers using `docker-default` can be read.

## Sensor setup

### Start the Sensor

The repository's
[`docker-compose.sensor.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/deploy/docker/docker-compose.sensor.yml)
and
[`sensor-seccomp.json`](https://github.com/kitsunetrail/kestrelynx/blob/main/deploy/docker/sensor-seccomp.json)
from `deploy/docker/` must be in the same directory. The Sensor starts from
that directory with:

```bash
docker compose -f docker-compose.sensor.yml up -d
```

The Sensor uses the same image as KestreLynx,
`ghcr.io/kitsunetrail/kestrelynx`, with the `kestrelynx-sensor` entrypoint.
The evidence volume has the fixed name `kestrelynx-runtime`.
The Sensor never observes its own container, so it carries
`io.kestrelynx.runtime.exclude: "true"` to keep KestreLynx from judging usage for it.

### Mount the evidence volume

The main KestreLynx Compose file needs a read-only mount of the Sensor's
evidence volume:

```yaml
services:
  kestrelynx:
    volumes:
      - kestrelynx-runtime:/var/lib/kestrelynx-runtime:ro
volumes:
  kestrelynx-runtime:
    external: true
```

### Enable runtime usage

The main KestreLynx `config.yml` enables usage assessment with:

```yaml
runtime:
  enabled: true
```

Recreate the main container from its Compose directory:

```bash
docker compose up -d
```

The default `runtime.evidence_dir` is `/var/lib/kestrelynx-runtime`. A custom
path must be absolute and match the Sensor's `--evidence-dir`.
When no Sensor is installed, `runtime.enabled` stays `false`; KestreLynx
does not open the evidence directory or add runtime information to notifications.
See [Configuration](configuration.md) for the settings.

On the scan immediately after the main container restarts, the Sensor may not
yet have observed a new container. Its image can temporarily show
`container not observed`; this clears on the next scan.

### Muting findings without a fix {#muting-findings-without-a-fix}

`runtime.mute_unfixable_not_in_use` defaults to `false` and takes effect only
with `runtime.enabled: true`:

```yaml
runtime:
  enabled: true
  mute_unfixable_not_in_use: true
```

A package is muted only when all current groups for the same image and package
meet every condition below.

- No fix is available for the target platform: the status is `affected` (including `fix_deferred`, `unknown`, and related statuses) or `will_not_fix`.
- Runtime usage is `not_observed`; `unavailable` is not eligible.
- The Sensor has observed every container used in the assessment for at least 7 days, to cover weekly activity.
- Priority is not Act now.

Packages with any `fixed` or EOL groups are not muted. EOL is always
notified. Image references with failed scans or unconfirmed identities are not
muted for that cycle.

Muting does not change priority. Slack omits the matching lines and excludes
them from priority counts in the Priority line and Open now. It shows a count:

```text
🔇 Muted — no fix available and not in use for 7+ days: N
```

The generic webhook retains all muted findings. Its additional fields are
described in [How KestreLynx works](how-it-works.md).

When the muting conditions no longer hold, notification resumes on a `Change:`
line (`変化:` in Japanese).
Newly available fixes, priority escalation, and added CVEs use
`fix now available`, `⬆️ escalated to <priority>` (e.g. ACT NOW or WATCH),
and `new CVEs: CVE-…` on that line.
Other changes show `Change: ↩️ Unmuted (<reason>)`
(`変化: ↩️ 通知を再開 (<理由>)` in Japanese).

| Reason | Japanese notification |
| --- | --- |
| `now in use` | 使用中になった |
| `act now` | 今すぐ対応 |
| `fix available` | 修正版あり |
| `now end-of-life` | サポート終了(EOL)となった |
| `insufficient observation` | 観測不足 |
| `not an eligible status` | 対象外の状態 |

```text
Image: web:1.0
◆ curl
Change: ↩️ Unmuted (now in use)
Installed: 8.0.0 · Fixed in: none
Findings: CRITICAL 0 / HIGH 1
Top CVE: CVE-CURL · EPSS n/a
Runtime: ▶ in use (running)
```

### Observation options

The Sensor's Compose `command` accepts the following options.

| Option | Default | Description |
| --- | --- | --- |
| `--interval` | `30s` | Sampling interval, from `10s` to `5m`. |
| `--exclude-id` | — | Exclude a container by at least the first 12 characters of its ID. Repeatable. |
| `--evidence-dir` | `/var/lib/kestrelynx-runtime` | Evidence directory. |

Containers with `io.kestrelynx.runtime.exclude=true` are excluded from usage
assessment. Only the lowercase value `true` matches.

With runtime usage enabled, the main agent also uses Docker API
`GET /containers/{id}/json`, in addition to `GET /containers/json`.

## Sensor status

Sensor problems produce a warning at the beginning of the notification.
The webhook reports the status as `runtime.sensor_status`.

| Status | Meaning |
| --- | --- |
| `ok` | Normal operation. |
| `not_reporting` | No evidence file yet, for example before the Sensor starts or just after startup. |
| `stale` | The last report is older than the greater of 10 times the interval and 5 minutes. |
| `evidence_invalid` | The evidence file failed validation. |
| `permission_denied` | The Sensor's reads are being denied. |
| `isolation_failed` | Setting up the restrictions on operations other than reading failed, and observation has not started. |
| `isolation_degraded` | The Sensor is running with some of the restrictions on operations other than reading ineffective. |
| `degraded` | Some observations are unavailable, for example because Sensor processing is stalled. |

When the Sensor as a whole reports `isolation_failed` or `permission_denied`,
usage is unavailable except where use has already been confirmed.
When a report is stale, `not_observed` becomes `unavailable` with reason
`sensor_stale`.

## Permissions

### Access

The Sensor can read process information and files, including configuration files,
across all containers on the host.

`SYS_PTRACE` and `DAC_READ_SEARCH` allow the Sensor to read other containers'
`/proc/<pid>/` information: executables, loaded libraries, open-file lists,
and listening sockets. They also allow reads of package databases in container
filesystems.

`BPF` and `PERFMON` are used only to load eBPF programs at startup and are
dropped after loading.

### Restrictions on operations other than reading

- No network, Docker socket, or `config.yml`
- A read-only root filesystem, with writes limited to the Sensor's own evidence volume
- Self-applied no-new-privileges and clearing of the dumpable flag at startup
- A supplied seccomp profile that denies opening files for writing, ptrace, reading or writing other processes' memory, and creating sockets
- Package-database parsing in child processes restricted by Landlock and seccomp, with no writes, network, or exec

Compose does not set no-new-privileges because the image's file capabilities
must take effect at startup. On an AppArmor-enabled host, all 25 tested
dangerous operations were denied.

### Evidence file

The main agent only reads evidence files and rejects files that fail validation
of format, limits, or allowed values. Evidence is stored as `procfs.json` in
the Sensor volume, owned by the Sensor UID with permissions `0644`.

## Observation limits

- Observation begins after the Sensor starts; short-lived processes that ended earlier cannot be captured
- `not_observed` covers only the observation window and does not establish that a package is unused, including for containers already running before the Sensor starts
- Very short-lived containers that finish before the Sensor ever discovers them are outside the observation scope
- Data-file reads do not establish package use
- Runtime-based language-package assessment covers the whole ecosystem and does not establish function calls or module imports

