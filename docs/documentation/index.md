# Documentation

This section covers installing, configuring, and operating KestreLynx.

## About KestreLynx

- [Setup instructions](getting-started.md) — install KestreLynx with Docker
  Compose, `docker run`, or Kubernetes.
- [Configuration](configuration.md) — configure the schedule, notification
  destinations, Kubernetes, environment name, state management, and vulnerability
  prioritization.
- [Remediation plans and pull requests (experimental)](remediation.md) — review
  update candidates, optional GitHub pull requests, and their verification limits.
- [Runtime usage (experimental)](runtime-usage.md) — add the optional Docker Sensor to mark
  packages in use without changing their priority.
- [How KestreLynx works](how-it-works.md) — learn about scanning,
  prioritization, change detection, and notification processing.

KestreLynx is under active development. Unless otherwise noted, this
documentation describes the latest container image and the current `main`
branch.

For bugs, feature requests, and documentation corrections, open an issue in the
[GitHub repository](https://github.com/kitsunetrail/kestrelynx/issues).
