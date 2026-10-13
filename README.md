# KestreLynx

**English** | [日本語](README.ja.md)

[![CI](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

[Documentation](https://kestrelynx.dev/) ·
[Getting started](docs/documentation/getting-started.md) ·
[Configuration reference](docs/documentation/configuration.md)

> Open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends **changes since the last scan and priorities based on severity, CISA KEV, and EPSS** to Slack or a webhook. For Docker and Compose, **remediation plans and pull requests (experimental)** support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default.

## What it does

- **Image scanning**: HIGH / CRITICAL detection with [Trivy](https://github.com/aquasecurity/trivy) by default
- **Scan deduplication**: shared results for images confirmed to be identical
- **Prioritization**: act now / watch / low, based on severity, CISA KEV, and EPSS
- **Runtime usage (experimental)**: optional Docker Sensor marks findings for packages in use and puts them first within the same priority, without changing priority; see [Runtime usage](docs/documentation/runtime-usage.md)
- **Package grouping**: fix availability, fixed versions, and upgrade-risk annotations
- **Unpatched vulnerabilities**: inclusion of findings without available fixes
- **Base-OS and package EOL**: prominent reporting at the top, separately from CVE priority, of unsupported base operating systems (EOL base) and packages with CVEs reported by vendors as out of support for this release (EOL package)
- **Change tracking**: new findings, added CVEs, newly available fixes, priority escalations, and resolutions
- **Japanese Slack notifications**: `notify.language: ja` for channel and thread text; generic webhook JSON remains in English
- **Environment identification**: optional environment name in Slack headers
- **Container identification**: container names, Compose project/service, and Kubernetes workload information in the generic webhook
- **Running-image verification**: scan pinning to observed identifiers such as digests, with identity matching
- **Remediation plans and pull requests (experimental)**: Docker update candidates for published images, Dockerfile bases, and npm / pnpm / pip / uv dependencies, with optional GitHub pull requests

## Supported environments

| Target | Operation and scope |
| --- | --- |
| Docker | One instance per host; running images across all Compose projects and standalone containers |
| Kubernetes | In-cluster deployment; read-only ServiceAccount; all or selected namespaces |

- **Kubernetes ownership**: Deployment, StatefulSet, DaemonSet, Job, and CronJob associations (`unknown` for unresolved ownership)
- **Scan targets**: containers running at discovery time, including Kubernetes native sidecars
- **Excluded targets**: ordinary init containers and ephemeral containers
- **Verified Kubernetes setup**: Ubuntu on linux/amd64, single-node K3s 1.36 with containerd 2.3
- **Unverified Kubernetes setups**: multiple nodes, mixed architectures, arm64, EKS / GKE / AKS, CRI-O, and authenticated private registries
- **Details**: [verification record and constraints](docs/development/kubernetes-support.md)

## What a notification looks like

This example uses the default `diff` mode and English notification text. Slack uses Block Kit cards with a package heading and labeled lines.

```text
🛡️ KestreLynx [prod-vps] — scan results for 2026-06-28 09:00
12 images scanned, 3 affected
Changes since the last scan.
───
🆕 New since last scan (2)
Image: nginx:1.25.3

◆ libnghttp2-14
Installed: 1.52.0-1
Fixed in: 1.52.0-1+deb12u1
Upgrade risk: 🟢 distro security patch
Findings: CRITICAL 0 / HIGH 2

Top CVE: CVE-2023-44487 · HIGH · EPSS >99% (+1 more CVE(s) in this package)
Exploitation: CISA KEV (exploited in the wild)
References: advisory · vendor advisory · 💬 HN (166 pts)
───
Image: myapp:latest
◆ webpack [npm-pkg]
Installed: 4.46.0 · Fixed in: 5.89.0 (🟠 major version bump — needs care)
Findings: CRITICAL 0 / HIGH 1
Top CVE: CVE-2024-37890 · EPSS 0.1%
───
✅ Resolved since last scan (1)
• myapp:latest: postcss
───
📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 4 low
oldest act-now/watch unresolved 12 day(s)
```

Long notifications continue in additional messages with repeated section and image headings. Each message also includes a short summary for notification previews and screen readers.

- **Changes detected**: changed findings and open counts, including priority escalations such as KEV additions
- **Open findings, no changes**: short summary
- **No issues or changes**: no notification by default (configurable with `notify.notify_on_clean`)
- **Weekly report**: full report on Mondays by default, with day selection and disabling options
- **Reference links**: advisories, vendor guidance from KEV, and relevant Hacker News discussions

### Choosing a notification target

| Target | Delivery | Required settings |
| --- | --- | --- |
| Slack Incoming Webhook | Summary in the channel | `notify.slack_webhook_url` |
| Slack Bot | Summary plus a thread with open-finding details in diff mode | `notify.slack_bot_token` and `notify.slack_channel` |
| Generic webhook | Structured JSON POST with current scan results and, in diff mode, changes | `notify.generic_webhook_url` |

- **Slack Bot details**: evidence, references, and time open for act-now/watch findings; counts for low-priority findings
- **Report refresh**: on changes and weekly report days
- **Slack Bot on quiet days**: link to the last detailed report
- **Slack Bot requirements**: `chat:write` scope and invitation to the destination channel
- **Allowed combination**: either Slack Incoming Webhook or Slack Bot, plus the generic webhook
- **Unsupported combination**: Slack Incoming Webhook and Slack Bot together

## Remediation plans and pull requests (experimental)

### Supported targets

For Docker and Compose, KestreLynx can propose the following updates.

- **Published images**
    - Tag updates
- **Dockerfile**
    - Base image tag updates
- **Language packages**
    - Dependency updates managed with npm, pnpm, pip, or uv

### Plan and pull request settings

Both remediation plans and pull requests are disabled by default.

| Setting | Behavior when enabled |
| --- | --- |
| `remediation.enabled` | Selects candidates, compares scans, and adds a plan to notifications, without GitHub writes or work containers |
| `remediation.pull_requests.enabled` | When enabled alongside plans, creates GitHub PRs and uses Docker work containers for language-package updates |

### Required permissions and configuration errors

- **GitHub authentication**
    - Use a fine-grained token limited to the mapped repositories
    - Set Contents and Pull requests to Read and write
- **Configuration errors**
    - Enabling PRs without plans
    - Enabling remediation plans in Kubernetes mode

### Language package update selection

KestreLynx selects a lower bound for each package's update target from running-image findings.

- **Eligible findings**
    - Findings with scan status `fixed` and reported fixed versions
    - Findings without fixed-version information are excluded
- **Lower-bound selection**
    1. For each finding, take the lowest reported fix newer than the installed version
    2. Use the highest of those versions as the lower bound for the package's update target
- **Checks after selection**
    - Selecting this lower bound does not verify that the vulnerabilities are resolved
    - With PRs enabled, the updated dependency files are checked separately, including before/after scans

### PR limitations and checks before merging

- **Changes an update may require**
    - A major version change or an edit to a direct dependency's manifest constraint
    - Major version changes are flagged in the PR body and notifications
- **PR limitations**
    - A PR does not mean the running image is fixed
    - Application compatibility and tests are not checked
    - Dockerfile and dependency changes are not rebuilt into an image
- **Dependency-file checks**
    - Checks only partly verify that dependency combinations agree with registry declarations and use formats accepted by installers

Run CI that installs from the lockfile before merging.

### Details

See [Remediation plans and pull requests (experimental)](docs/documentation/remediation.md)
for notification meanings, PR checks, and permissions.

## Quick start: Docker

You need a working Docker host and at least one notification target. The distributed image includes Trivy.

```sh
# 1. Copy the repository's example configuration and set a notification target
cp config.example.yml config.yml
$EDITOR config.yml

# 2. Start the agent (change TZ to your timezone)
docker run -d --name kestrelynx \
  --restart unless-stopped \
  -e TZ=UTC \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest

# 3. Check startup and scan results
docker logs -f kestrelynx
```

- **Scan schedule**: immediately on startup and daily at 09:00 in the example configuration
- **Timezone**: the container's `TZ`
- **Persistent storage**: `kestrelynx-state` volume
- **Stored data**: diff history, first-seen dates, and intel cache
- **Recreation and updates**: reuse of the existing volume
- **Deployment unit**: one instance per host, covering all containers and Compose projects

### Running with Docker Compose

```sh
cp config.example.yml config.yml
$EDITOR config.yml
docker compose up -d
docker compose logs -f
```

- **Configuration file**: included [docker-compose.yml](docker-compose.yml)
- **Default `TZ`**: `UTC` (`Asia/Tokyo` for Japan time)

### Docker socket access

- **Discovery**: running-container listing through `GET /containers/json`; the main agent also uses `GET /containers/{id}/json` when `runtime.enabled: true`
- **Image access**: Docker API reads by Trivy
- **Container operations**: creation, startup, and removal of owned work containers for language-package updates when remediation pull requests are enabled, without modifying monitored application containers
- **Work-container restrictions**: non-root user, all capabilities dropped, no-new-privileges, and resource and time limits
- **Work-container writes**: limited to size-capped tmpfs with the distributed work image, with the same ownership and permission restrictions required for override images and no runtime inspection of all image file permissions
- **Work-container credentials**: no GitHub token, main configuration, or Docker socket, with output checked by KestreLynx
- **`:ro` limitation**: no restriction on Docker API permissions and no need to change the socket mount to `:rw` for PRs
- **Mount targets**: trusted images only

## Running on Kubernetes

1. Preparation of the [deployment manifests](deploy/kubernetes/)
2. Notification target in the [ConfigMap](deploy/kubernetes/configmap.yaml), plus optional `kubernetes.namespaces` and `environment.name`
3. `TZ` in the [Deployment](deploy/kubernetes/deployment.yaml) and storage settings in the [PVC](deploy/kubernetes/pvc.yaml)
4. Namespace creation and application of the edited manifests

```sh
kubectl create namespace kestrelynx
kubectl apply -f deploy/kubernetes/
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

- **Activation**: `kubernetes.enabled: true`
- **Switching from the example**: removal of the `docker` section in `config.example.yml` (startup error with explicit `docker.socket`)
- **Unnecessary components**: Docker socket and per-node agents
- **Connectivity requirement**: scanner Pod access to the target registry for Trivy image retrieval
- **Private registry credentials**: credential-mount example in the Deployment (unverified in a real cluster)
- **Credential inheritance**: no automatic transfer of workload `imagePullSecrets`
- **Unsupported scope**: node-only images, deleted registry digests, K3s `registries.yaml` mirrors/rewrites, and air-gapped clusters
- **History storage**: PVC, with no concurrent writes to the same state file by multiple instances
- **Supplied Deployment**: one replica with the `Recreate` strategy

## Key configuration

See [config.example.yml](config.example.yml) for all configuration options and the [configuration reference](docs/documentation/configuration.md) for notification and scheduling details.

| Setting | Behavior |
| --- | --- |
| `schedule.daily_at` | Daily scan time (`09:00` in the example; 24-hour interval if omitted or empty) |
| `schedule.run_on_start` | Startup scan (default: `true`) |
| `scan.severity` | Included severities (default: `[HIGH, CRITICAL]`) |
| `notify.language` | Slack notification language: `en` (default) or `ja`; other values are configuration errors |
| `notify.mode` | `diff`: change notifications (default); `full`: full report every scan |
| `notify.full_report_day` | Weekly report day in diff mode (default: `monday`; disabled: `never`) |
| `notify.notify_on_clean` | Notifications with no issues or changes (default: `false`) |
| `environment.name` | Optional environment name for reports (example: `prod-vps`) |
| `state.path` | History file (default: `/var/lib/kestrelynx/state.json`) |
| `triage.enabled` | `true`: KEV/EPSS prioritization (default); `false`: severity-based notifications |
| `triage.act_now_epss` / `triage.watch_epss` | EPSS thresholds (defaults: `0.10` / `0.01`) |
| `triage.discussion_links` | Hacker News discussion lookup (default: `true`) |
| `remediation.enabled` | Read-only remediation plans (default: `false`; Docker only) |
| `remediation.pull_requests.enabled` | GitHub PRs and work containers for language updates (default: `false`; requires plans and a token) |
| `remediation.github.token` | Token limited to the mapped GitHub repositories (default: empty) |
| `remediation.mappings` | Compose workload to repository, base branch, and Compose / Dockerfile / dependency source mappings |
| `remediation.storage_dir` | Persistent remediation records (default: `/var/lib/kestrelynx/remediation`) |
| `remediation.limits` | Scan, registry, PR, dependency-update, and time limits described in the configuration reference |
| `remediation.worker.image` | Digest-pinned work-image override (default: the image specified by the main release) |

- **Environment-name characters**: lowercase alphanumerics and hyphens, with alphanumeric first and last characters
- **Environment-name length**: 1–63 characters, or empty
- **Multiple environments**: separate environment names and state storage per instance
- **History continuity after rebuilds or migrations**: retention of the environment name and state

## Network access and interpreting results

- **Intel matching**: bulk KEV/EPSS downloads and local joins, without transmitting detected CVE lists
- **Default intel sources**: `www.cisa.gov` and `epss.empiricalsecurity.com`
- **Discussion search endpoint**: `hn.algolia.com`
- **Search data**: CVE IDs qualifying as act-now based on exploitation signals
- **Search opt-out**: `triage.discussion_links: false`, with CVE delivery to notification targets still enabled
- **Other traffic**: vulnerability database and image retrieval by Trivy, plus results sent to configured notification targets
- **Remediation planning**: HTTPS to public image registries and GitHub (`api.github.com`) for configured sources, plus Trivy database and candidate-image downloads
- **Language-package updates**: HTTPS to the public npm registry (`registry.npmjs.org`) and PyPI (`pypi.org` and `files.pythonhosted.org`) for package metadata and distributions
- **Work-image retrieval**: Docker daemon access to `ghcr.io/kitsunetrail/kestrelynx-worker` at the digest specified by the main release, or the registry in `remediation.worker.image`, when first needed
- **Unavailable work image**: deferred language-package updates, without running package managers in the main container
- **GitHub writes**: PRs only when separately enabled, potentially triggering the repository's CI
- **Work-container network**: Docker bridge networking without strict destination filtering
- **Failed scans or unconfirmed identity**: retention of previous findings, without resolution based on that cycle's results
- **Resolution meaning**: disappearance from the current monitored scope, including stopped containers or scope changes
- **Upgrade-risk annotations**: indicators such as version-change size, without compatibility or safety guarantees

A resolved finding is not proof of patch application. See [How KestreLynx works](docs/documentation/how-it-works.md) for notification rules and output details.

## Development

```sh
go test ./... -short   # fast unit tests (no Docker / network needed)
go test ./...          # also runs integration tests that use Trivy (needs trivy + network)
go build ./...
```

Build and preview the documentation locally:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Preview the Japanese documentation in a separate process:

```sh
mkdocs serve --config-file mkdocs.ja.yml
```

Each build generates 1200 × 630 Open Graph images and X cards for all English
and Japanese pages using the title and description metadata. The layout is in
[`overrides/social/kestrelynx.yml`](overrides/social/kestrelynx.yml); no logo is
required. The label below the service name is DEVELOPMENT LOG for `development/`,
TECHNICAL ARTICLES for `articles/`, and DOCUMENTATION elsewhere, using the same
English labels on both language sites. To add a logo later, put the image in `overrides/social/` and set
`plugins.social.cards_layout_options.logo` in `mkdocs.yml` to its repository-relative
path (for example, `overrides/social/logo.png`). Both languages share this setting.
The first build downloads Noto Sans JP from Google Fonts into `.cache/`.
Image generation also requires Cairo; on Debian/Ubuntu, install `libcairo2`
with `sudo apt-get install libcairo2` before building.

Documentation changes pushed to `main` are built and deployed by
[`docs.yml`](.github/workflows/docs.yml). Before the first deployment, select
**GitHub Actions** under **Settings → Pages → Build and deployment → Source**.

## License

[GNU AGPL-3.0](LICENSE). Copyright (c) 2026 Kitsune Trail.
