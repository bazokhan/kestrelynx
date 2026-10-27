---
description: "Follow an nginx worker’s loaded libssl.so.3 through procfs, container dpkg records, and Trivy matching to confirmed loading of libssl3 in eight interactive steps, using measurements from September 12, 2026."
template: explainer.html
explainer: procfs-packages
hide:
  - navigation
  - toc
---

# Interactive Guide to the procfs Package Mapping Workflow

Published: October 5, 2026

## Overview

- This eight-step diagram follows `libssl.so.3` loaded by a worker in the running `nginx` container, through `/proc` reads and the container’s dpkg records to a match with Trivy’s reported `libssl3` version `3.0.16-1~deb12u1` and a `confirmed` loading record
- It illustrates the process-to-package mapping and scan-matching workflow described in [How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md)
- The values are actual measurements from September 12, 2026, showing one worker from the `nginx` container started from the `nginx:1.27` image

## Diagram

<div class="klx-explainer" data-klx-explainer="procfs-packages" tabindex="-1">
  <p class="klx-fallback">JavaScript is required to use this interactive guide.</p>
</div>

Measurement results, exceptions, and limitations are explained in [How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md).
The [Interactive Guide to the bpftrace Measurement Workflow](bpftrace-event-observation-interactive.md) shows how recording events as they happen can capture short-lived activity that periodic reads can miss.

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack, email, or a webhook.

Remediation plans and pull requests (experimental) for Docker, Compose, and Kubernetes support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[About KestreLynx](../index.md) · [View source on GitHub](https://github.com/kitsunetrail/kestrelynx)
