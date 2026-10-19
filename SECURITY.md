# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/kitsunetrail/kestrelynx/security/advisories/new), available under **Security → Report a vulnerability**. Reports in English or Japanese are welcome.

Do not post vulnerability details in public Issues, Discussions, or pull requests.

Please include the following information in your report:

- The affected commit or image tag.
- Your setup (Docker, Docker Compose, or Kubernetes) and enabled features.
- Steps to reproduce the issue.
- The possible impact.

Remove credentials and other sensitive data.

## Supported versions

Images are published at `ghcr.io/kitsunetrail/kestrelynx` with `latest` and `sha-<short-commit>` tags. There are currently no `v*` release tags.

Security fixes are provided only through the `main` branch and the `latest` image. Older commits and images do not receive backports; deployments pinned to a SHA tag must move to a fixed build.

## Scope

In scope:

- KestreLynx scanning, notifications, remediation plans, and remediation pull requests.
- The experimental Runtime Sensor.
- Deployment files in this repository, including Kubernetes manifests.

Reports involving unintended use of Docker socket access, GitHub tokens, Slack tokens, or Kubernetes ServiceAccount permissions are especially welcome.

Out of scope:

- Vulnerabilities in upstream tools or dependencies themselves, such as Trivy; report these upstream.
- Vulnerabilities in images discovered by KestreLynx scans.
- Intentionally outdated dependencies in [`kitsunetrail/kestrelynx-demo`](https://github.com/kitsunetrail/kestrelynx-demo).

## Response and disclosure

KestreLynx is maintained by one individual. The target for an initial response is within seven days of receiving a report.

After a fix, a GitHub Security Advisory may be published as appropriate. Reporter credit is included only with the reporter’s consent.

There is no bug bounty program.
