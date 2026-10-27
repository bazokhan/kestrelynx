---
template: home.html
hide:
  - navigation
  - toc
  - footer
---

<div class="kl-hero" markdown>
<div class="kl-hero__text" markdown>

Docker · Kubernetes · Trivy · CISA KEV · EPSS
{ .kl-eyebrow }

# Container image vulnerability scanning, notifications, and remediation

KestreLynx is open-source software that regularly scans images used by running
Docker and Kubernetes containers with [Trivy](https://trivy.dev/).
It sends changes since the last scan and priorities based on severity,
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and
[EPSS](https://www.first.org/epss/) to Slack, email, or a webhook.
For Docker, Compose, and Kubernetes,
[remediation plans and pull requests (experimental)](documentation/remediation.md)
support remediation by comparing rescans under the same conditions and creating
GitHub pull requests, with both features disabled by default.

[Setup](documentation/getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/kitsunetrail/kestrelynx){ .md-button }
{ .kl-actions }

Open source · AGPL-3.0
{ .kl-license }

</div>
<figure class="kl-notification">
<div class="kl-slack">
<div class="kl-slack__channel"># security-alerts</div>
<div class="kl-slack__message">
<div class="kl-slack__avatar" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/></svg></div>
<div class="kl-slack__body">
<p class="kl-slack__meta"><strong>KestreLynx</strong> <span class="kl-slack__badge">APP</span> <span class="kl-slack__time">9:00 AM</span></p>
<p>🛡️ <strong>KestreLynx</strong> [prod-vps] — scan results for 2026-06-28 09:00<br>12 images scanned, 1 affected<br><em>Changes since the last scan.</em></p>
<hr>
<p><strong>🆕 New since last scan (1)</strong><br>Image: <code>nginx:1.25.3</code></p>
<p><strong>◆ libnghttp2-14</strong><br><strong>Installed:</strong> 1.52.0-1<br><strong>Fixed in:</strong> 1.52.0-1+deb12u1<br><strong>Upgrade risk:</strong> 🟢 distro security patch<br><strong>Findings:</strong> CRITICAL 0 / HIGH 2</p>
<p><strong>Top CVE:</strong> <span class="kl-slack__link">CVE-2023-44487</span> · HIGH · EPSS &gt;99% (+1 more CVE(s) in this package)<br><strong>Exploitation:</strong> CISA KEV (exploited in the wild)<br><strong>References:</strong> <span class="kl-slack__link">advisory</span> · <span class="kl-slack__link">vendor advisory</span> · 💬 <span class="kl-slack__link">HN (166 pts)</span></p>
<hr>
<p>📌 <strong>Open now:</strong> 🚨 1 act-now</p>
</div>
</div>
</div>
<figcaption>Sample notification in the default <code>diff</code> mode. Values are illustrative, not from a live scan.</figcaption>
</figure>
</div>

<div class="kl-callouts" markdown>

- **New findings** “New since last scan” names the image and package.
- **Fix availability** “Installed” and “Fixed in” show the current and fixed versions.
- **Priority** “Open now” counts by priority; KEV and EPSS give the context.

</div>

<div class="kl-section kl-features" markdown>
<div markdown>

:material-history:

## Follow changes between scans

Diff notifications highlight new findings, added CVEs, newly available fixes,
priority escalations, and findings that leave the monitored scope. Open
findings still trigger a short update when nothing changes; Monday
notifications include a full report by default.

</div>
<div markdown>

:material-sort-variant:

## Prioritize with KEV and EPSS

KestreLynx combines severity with CISA KEV and EPSS data to group findings into
Act now, Watch, and Low. These priorities help guide review; they do not
establish whether your environment can be exploited.

</div>
<div markdown>

:material-magnify-scan:

## Scan with Trivy, review fixes by package

Trivy scans report HIGH and CRITICAL vulnerabilities by default, including
findings without available fixes. Package summaries show fixed versions when
available and annotate upgrade risk, without guaranteeing compatibility.

</div>
</div>

<div class="kl-section" markdown>

## Remediation plans and pull requests (experimental)

Kubernetes remediation plans show published-image update candidates, guidance for pulling floating tags again, and language-package update candidates.
Kubernetes PRs support image tag updates in plain manifests, [Kustomize `images[].newTag` updates](documentation/remediation-setup.md#kustomize-pull-requests), [image tag updates in Helm values](documentation/remediation-setup.md#helm-values-pull-requests), and base image updates in Dockerfiles, plus npm / pnpm / pip / uv updates when [work Pods are configured](documentation/remediation-setup.md#kubernetes-language-updates).
For npm, pnpm, and uv, this also includes re-resolution through dependent packages under the supported conditions.
For Docker and Compose, KestreLynx can propose changes to three kinds of source:

- Published image tags in Compose files
- Base image tags in Dockerfiles
- Language-package dependencies managed with npm, pnpm, pip, or uv

Both remediation plans and pull requests are disabled by default.
Plans select candidates, compare scans, and notify without writing to GitHub
or starting work containers. Enabling pull requests separately allows GitHub
changes and Docker work containers or user-configured Kubernetes work Pods for language-package updates.

These screenshots show actual output from the [demo repository](https://github.com/kitsunetrail/kestrelynx-demo), which intentionally pins older images and dependencies, with the [generated PRs available on GitHub](https://github.com/kitsunetrail/kestrelynx-demo/pulls).

The Slack fix plan lists three created PRs and a Dockerfile base update marked “Needs a decision” because the candidate introduces new findings.

![Slack fix plan showing Compose, pip, and npm update PRs and a Dockerfile base update requiring a decision](assets/screenshots/slack-fix-plan.png)

[PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1) proposes updating nginx from 1.27.0 to 1.27.5 and records the candidate scan comparison: 17 targeted findings resolved, 86 remaining.

![GitHub PR body with What, Change, and Verification sections, including 94 other findings remaining and no introduced findings](assets/screenshots/pr-compose-body.png)

After PR #1 was merged and the running `proxy` container was replaced with nginx 1.27.5, the next scan reported resolutions for four packages with history carried over.

![Slack scan notification showing the nginx image update and resolutions for libabsl20220623, libavif15, libfreetype6, and liblzma5](assets/screenshots/slack-resolved.png)

A candidate or pull request does not mean the running image has been fixed.
Review the comparison scope and run your CI before merging; rebuilding and
deploying remain separate steps.

See [Remediation plans and pull requests (experimental)](documentation/remediation.md)
for setup, notifications, and permissions.

</div>

<div class="kl-section" markdown>

## Scope and access

For self-hosted services where you want to review vulnerability changes in the
images your containers are running.

<dl class="kl-scope" markdown>
<dt>Docker</dt>
<dd markdown="span">One instance per host covers running containers across Compose projects and standalone deployments.</dd>
<dt>Kubernetes</dt>
<dd markdown="span">An in-cluster Deployment discovers running containers across all or selected namespaces through read-only API operations, with additional permissions limited to a work namespace only when language-package updates are configured.</dd>
<dt>Verified scope</dt>
<dd markdown="span">Single-node K3s with containerd on linux/amd64. Multi-node clusters, arm64, managed Kubernetes, and authenticated private registries remain unverified. [Verification record](development/kubernetes-support.md)</dd>
<dt>Discovery</dt>
<dd markdown="span">Containers must be running when discovered. Kubernetes native sidecars are included; ordinary init containers and ephemeral containers are excluded.</dd>
<dt>Docker socket access</dt>
<dd markdown="span">KestreLynx reads container information and Trivy reads images through the Docker API; with remediation pull requests enabled, KestreLynx also creates, starts, and removes work containers for language-package updates. Mounting the socket with `:ro` does not restrict API permissions and does not need to change to `:rw`, so the mounted image must be trusted.</dd>
</dl>

</div>

<div class="kl-section kl-steps" markdown>

## Setup

These steps use Docker Compose. You need a Docker host with Docker Compose and
at least one notification destination: a Slack Incoming Webhook, a Slack bot
with a destination channel, email, or a generic webhook. For Kubernetes, see
[Setup instructions](documentation/getting-started.md#run-on-kubernetes).

1. Clone the repository and enter its directory

    ```sh
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. Create the configuration file

    Copy the example to `config.yml` and set a notification destination.
    { .kl-step-note }

    ```sh
    cp config.example.yml config.yml
    ${EDITOR:-vi} config.yml
    ```

3. Check the timezone and start KestreLynx

    Scan times follow `TZ` in `docker-compose.yml`, which defaults to `UTC`;
    use `Asia/Tokyo` for Japan time.
    { .kl-step-note }

    ```sh
    ${EDITOR:-vi} docker-compose.yml
    docker compose up -d
    ```

4. Check startup and scans in the logs

    The example configuration runs one scan at startup, then scans daily at
    09:00.
    { .kl-step-note }

    ```sh
    docker compose logs -f
    ```

:material-information-outline: Keep the `kestrelynx-state` volume when
recreating the container to preserve the history used for change notifications
and first-seen dates.
{ .kl-note }

:material-information-outline: Trial reports are welcome in [Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx).
{ .kl-note }

</div>

<div class="kl-section" markdown>

## Documentation, development logs, and articles

<div class="kl-links" markdown>
<div markdown>

### Documentation

- [Setup](documentation/getting-started.md)
- [Configuration](documentation/configuration.md)
- [Remediation plans and pull requests (experimental)](documentation/remediation.md)
- [Runtime usage (experimental)](documentation/runtime-usage.md)
- [How it works](documentation/how-it-works.md)

</div>
<div markdown>

### Development logs

- [Kubernetes support](development/kubernetes-support.md)
- [Runtime evidence observation with eBPF](development/runtime-event-evidence.md)
- [All development logs →](development/index.md){ .kl-more }

</div>
<div markdown>

### Technical articles

- [Trivy Basics and How to Read Scan Results](articles/trivy-basics-scan-results.md)
- [EPSS Basics and How to Check Scores](articles/epss-exploit-prediction-scoring-system.md)
- [How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans](articles/which-container-scan-findings-are-actually-running.md)
- [All articles →](articles/index.md){ .kl-more }

</div>
</div>

Report a bug or suggest an improvement on
[GitHub Issues](https://github.com/kitsunetrail/kestrelynx/issues).
{ .kl-issues }

</div>
