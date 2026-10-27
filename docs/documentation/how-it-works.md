# Overview

## Feature overview {#overview}

KestreLynx scans images used by running containers with Trivy and groups findings by package.
It uses exploitation intelligence to assign priorities and compares results with saved history to identify changes such as new and resolved findings.

Slack and email show changes and current findings, while the generic webhook provides structured findings and diffs.
Notification conditions and explanations of notification displays and fields are documented on separate pages.

KestreLynx can also send remediation plans for Docker, Compose, and Kubernetes and create remediation PRs on GitHub (experimental, disabled by default).
Plans propose image and dependency updates; users handle merging, building, and deployment. See [Remediation plans and pull requests](remediation.md) for details.

See [Getting started](getting-started.md) for setup instructions and [Configuration](configuration.md) for settings.

## Contents {#contents}

- [Scan and priority decisions](scan-logic.md)
    - [Processing flow](scan-logic.md#scan-cycle)
    - [Scan targets](scan-logic.md#scan-targets)
    - [Scan result verification](scan-logic.md#scan-verification)
    - [Package-level grouping](scan-logic.md#package-grouping)
    - [Finding classification](scan-logic.md#finding-classification)
    - <span id="cve"></span><span id="cve-priority-rules"></span>[Exploitation-based priority](scan-logic.md#triage)
- [Change and history decisions](diff-logic.md)
    - [Comparison baseline](diff-logic.md#comparison-baseline)
    - [Package changes](diff-logic.md#package-changes)
    - [Base OS EOL changes](diff-logic.md#eol-base-changes)
    - [Image content changes](diff-logic.md#image-content-changes)
    - [Image reference updates](diff-logic.md#reference-changes)
    - [History continuity](diff-logic.md#state-lifecycle)
- [Notification conditions](notification-conditions.md)
    - <span id="notification-conditions"></span>[Scan notification conditions](notification-conditions.md#notification-conditions)
    - [Slack thread delivery conditions](notification-conditions.md#slack-thread-delivery)
    - [Scan notification redelivery](notification-conditions.md#scan-redelivery)
    - <span id="remediation-slack-delivery"></span><span id="remediation-webhook-delivery"></span><span id="remediation-redelivery"></span>[Remediation plan delivery conditions](notification-conditions.md#remediation-delivery)
- [Reading Slack notifications](slack-display.md)
    - <span id="slack-display"></span>[Where to find reports](slack-display.md#slack-display)
    - <span id="notification-language"></span>[Notification language](slack-display.md#notification-language)
    - [Section order](slack-display.md#section-order)
    - [Reading counts](slack-display.md#counts)
    - [Reading package cards](slack-display.md#package-card)
    - [Change labels](slack-display.md#change-labels)
    - [Runtime usage display](slack-display.md#runtime-display)
    - [Reading warnings](slack-display.md#warnings)
- [Webhook field reference](webhook-reference.md)
    - <span id="generic-webhook"></span>[Payload scope](webhook-reference.md#generic-webhook)
    - [Report fields](webhook-reference.md#report-fields)
    - [Image fields](webhook-reference.md#images)
    - [Finding fields](webhook-reference.md#findings)
    - [Runtime fields](webhook-reference.md#runtime)
    - [Diff fields](webhook-reference.md#diff)
    - [Compatibility](webhook-reference.md#compatibility)
- [Webhook remediation fields](webhook-remediation-reference.md)
    - <span id="remediation-fields"></span>[Common remediation plan fields](webhook-remediation-reference.md#remediation-fields)
    - <span id="remediation-image-fields"></span>[Published-image fields](webhook-remediation-reference.md#remediation-image-fields)
    - <span id="remediation-dockerfile-fields"></span>[Base-image fields](webhook-remediation-reference.md#remediation-dockerfile-fields)
    - <span id="remediation-language-fields"></span>[Language-package fields](webhook-remediation-reference.md#remediation-language-fields)
    - <span id="remediation-pr-fields"></span>[PR processing fields](webhook-remediation-reference.md#remediation-pr-fields)
    - <span id="remediation-operation-fields"></span>[PR operation event fields](webhook-remediation-reference.md#remediation-operation-fields)
    - <span id="remediation-problem-fields"></span>[Write suspension fields](webhook-remediation-reference.md#remediation-problem-fields)
    - <span id="remediation-json-example"></span>[Remediation plan JSON example](webhook-remediation-reference.md#remediation-json-example)
- [Outbound communication](outbound-communication.md)
    - <span id="outbound-communication"></span><span id="kev-download"></span><span id="epss-download"></span><span id="hacker-news-search"></span><span id="trivy-downloads"></span><span id="github-communication"></span><span id="candidate-registry-communication"></span><span id="worker-image-downloads"></span><span id="tool-downloads"></span><span id="dependency-downloads"></span><span id="notification-delivery"></span>[Communication destinations](outbound-communication.md#outbound-communication)
    - <span id="credential-destinations"></span>[Credential destinations](outbound-communication.md#credential-destinations)
    - <span id="worker-network"></span>[Work container network](outbound-communication.md#worker-network)
