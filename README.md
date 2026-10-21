# KestreLynx

**English** | [日本語](README.ja.md)

[![CI](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

[Documentation](https://kestrelynx.dev/) ·
[Getting started](docs/documentation/getting-started.md) ·
[Configuration reference](docs/documentation/configuration.md) ·
[Trial reports](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx)

> Open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends **changes since the last scan and priorities based on severity, CISA KEV, and EPSS** to Slack or a webhook. **Remediation plans** for Docker, Compose, and Kubernetes and **pull requests (experimental)** for Docker and Compose support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default.

## What it does

- **Image scanning**: HIGH / CRITICAL detection by default for OS and language packages identified by [Trivy](https://github.com/aquasecurity/trivy) image scanning, with language-package update PRs limited to npm / pnpm / pip / uv
- **Scan deduplication**: shared results for images confirmed to be identical
- **Prioritization**: act now / watch / low, based on severity, CISA KEV, and EPSS
- **Runtime usage (experimental)**: optional Docker Sensor marks findings for packages in use and puts them first within the same priority, without changing priority; see [Runtime usage](docs/documentation/runtime-usage.md)
- **Package grouping**: fix availability, fixed versions, and upgrade-risk annotations
- **Unpatched vulnerabilities**: inclusion of findings without available fixes
- **Base-OS and package EOL**: prominent reporting at the top, separately from CVE priority, of unsupported base operating systems (EOL base) and packages with CVEs reported by vendors as out of support for this release (EOL package)
- **Change tracking**: new findings, added CVEs, newly available fixes, priority escalations, and resolutions
- **Environment identification**: optional environment name in Slack headers
- **Container identification**: container names, Compose project/service, and Kubernetes workload information in the generic webhook
- **Running-image verification**: scan pinning to observed identifiers such as digests, with identity matching
- **Remediation plans and pull requests (experimental)**: update candidates for published images and npm / pnpm / pip / uv dependencies on Docker and Kubernetes, with Dockerfile base update candidates and optional GitHub pull requests on Docker

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

- Propose image and dependency updates for Docker, Compose, and Kubernetes
- Remediation plans and optional GitHub PR creation are both disabled by default
- Users check changes, merge, deploy, and verify after deployment

These screenshots show actual output from the [demo repository](https://github.com/kitsunetrail/kestrelynx-demo), which intentionally pins older images and dependencies, with the [generated PRs available on GitHub](https://github.com/kitsunetrail/kestrelynx-demo/pulls).

The Slack fix plan lists three created PRs and a Dockerfile base update marked “Needs a decision” because the candidate introduces new findings.

![Slack fix plan showing Compose, pip, and npm update PRs and a Dockerfile base update requiring a decision](docs/assets/screenshots/slack-fix-plan.png)

[PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1) proposes updating nginx from 1.27.0 to 1.27.5 and records the candidate scan comparison: 17 targeted findings resolved, 86 remaining.

![GitHub PR body with What, Change, and Verification sections, including 94 other findings remaining and no introduced findings](docs/assets/screenshots/pr-compose-body.png)

After PR #1 was merged and the running `proxy` container was replaced with nginx 1.27.5, the next scan reported resolutions for four packages with history carried over.

![Slack scan notification showing the nginx image update and resolutions for libabsl20220623, libavif15, libfreetype6, and liblzma5](docs/assets/screenshots/slack-resolved.png)

| Topic | Detailed page |
| --- | --- |
| Find the page for your task | [Overview](docs/documentation/remediation.md) |
| Enable remediation plans and fix pull requests | [Enabling remediation](docs/documentation/remediation-setup.md) |
| Diagnose missing candidates or PRs | [When no candidate or pull request appears](docs/documentation/remediation-troubleshooting.md) |
| Read Slack and PR contents | [Reading the results](docs/documentation/remediation-results.md) |
| Understand candidate selection and PR processing | [How candidates and pull requests are decided](docs/documentation/remediation-logic.md) |
| Look up supported inputs and reason codes | [Supported inputs and reason codes](docs/documentation/remediation-reference.md) |
| Look up settings and required permissions | [Configuration reference](docs/documentation/configuration.md) |
| Check notification conditions, webhook specifications, and outbound communication | [How KestreLynx works](docs/documentation/how-it-works.md) |

## Quick start: Docker

You need a working Docker host and at least one notification target. The distributed image includes Trivy.

```sh
# 1. Clone the repository, copy the example configuration, and set a notification target
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx
cp config.example.yml config.yml
${EDITOR:-vi} config.yml

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

Trial reports are welcome in [Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx).

### Running with Docker Compose

```sh
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx
cp config.example.yml config.yml
${EDITOR:-vi} config.yml
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
| `notify.language` | Language for Slack notifications and PR bodies: `en` (default) or `ja`; other values are configuration errors, and the generic webhook remains in English |
| `notify.mode` | `diff`: change notifications (default); `full`: full report every scan |
| `notify.full_report_day` | Weekly report day in diff mode (default: `monday`; disabled: `never`) |
| `notify.notify_on_clean` | Notifications with no issues or changes (default: `false`) |
| `environment.name` | Optional environment name for reports (example: `prod-vps`) |
| `state.path` | History file (default: `/var/lib/kestrelynx/state.json`) |
| `triage.enabled` | `true`: KEV/EPSS prioritization (default); `false`: severity-based notifications |
| `triage.act_now_epss` / `triage.watch_epss` | EPSS thresholds (defaults: `0.10` / `0.01`) |
| `triage.discussion_links` | Hacker News discussion lookup (default: `true`) |

- **Environment-name characters**: lowercase alphanumerics and hyphens, with alphanumeric first and last characters
- **Environment-name length**: 1–63 characters, or empty
- **Multiple environments**: separate environment names and state storage per instance
- **History continuity after rebuilds or migrations**: retention of the environment name and state

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
