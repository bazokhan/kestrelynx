# When no candidate or pull request appears

This page explains how to isolate the cause when a remediation plan candidate or PR does not appear.

## Collecting diagnostics {#collect-diagnostics}

1. Note the target workload, image, and scan time
2. Check the item's category, reason, and details in Slack, the webhook, or the saved plan
3. For PR processing problems, check the notified PR status and operation results alongside the KestreLynx logs from the same run

For saved records, see [Stored records](remediation-reference.md#stored-records); for reason code definitions, see [Reason codes](remediation-reference.md#reason-codes).

## Checking for a missing plan {#check-missing-plan}

| Symptom | What to check | Reference |
| --- | --- | --- |
| Startup stops while loading configuration | Check the settings identified in the logs and the combination of enablement settings. | [Startup validation](configuration.md#remediation-validation) |
| The plan has no item for the target | Check the running-image scan results, selected severities, and fixed-version information. | [Image candidate selection](remediation-logic.md#image-selection), [Language package candidate selection](remediation-logic.md#package-selection) |
| A plan record exists, but no notification arrives | Check notification destinations, delivery conditions, and delivery failure logs. | [Notification conditions](notification-conditions.md#notification-conditions), [Remediation plan redelivery](notification-conditions.md#remediation-redelivery) |
| Source files cannot be retrieved, or a target file is missing | Check Compose labels or the Kubernetes workload key, mappings, the base branch, paths, and GitHub access. | [Source mappings](configuration.md#remediation-mappings), [GitHub access](configuration.md#remediation-github) |
| A Kubernetes item reports `declared_ref_mismatch` or `declared_ref_unavailable` | Check the Pod spec and running reference for every container using the same running image reference. | [Kubernetes image references and re-pull guidance](remediation-logic.md#kubernetes-image-references) |
| A private image cannot be accessed | Check the registry host, credentials, pull permissions, and token service permissions. | [Image registry authentication](configuration.md#remediation-registries) |
| No new image candidate appears | Use the reason in the notification to check for newer tags, new content, and improvements. | [Image candidate reasons](remediation-reference.md#image-reasons) |
| Tag listing stops before completion | Check retrieval failure logs and the limits on tag listing, registry requests, and processing time. | [Tag discovery](remediation-logic.md#tag-discovery), [Processing limits](configuration.md#remediation-limits) |
| An image is treated as locally built | Check Compose's `build` setting and the Dockerfile and dependency file mappings. | [Excluding local builds](remediation-logic.md#local-builds) |
| The base image cannot be confirmed | Check the target Dockerfile stage, the base used, and the matching results against the running image. | [Base layer matching](remediation-logic.md#base-layer-matching), [Image candidate reasons](remediation-reference.md#image-reasons) |

## Checking update failures {#check-update-failure}

| Symptom | What to check | Reference |
| --- | --- | --- |
| Language packages remain candidates without being updated | Check whether PR creation is enabled and the reason attached to the item. | [Enablement settings](configuration.md#remediation-enablement), [Execution scope of plans and PRs](remediation-logic.md#plan-and-pr-execution) |
| An input format or package source is reported as unsupported | Check dependency files, workspaces, additional configuration, and package sources. | [Supported input formats](remediation-reference.md#supported-inputs), [Source reasons](remediation-reference.md#source-reasons) |
| A runtime cannot be selected, or compatibility requirements are not met | Check declarations in version files and manifests, dependency requirements, and the support status of the release series. | [Runtime selection](remediation-logic.md#runtime-and-tool-versions), [Runtime reasons](remediation-reference.md#runtime-reasons) |
| The pip verification environment cannot be determined or does not match | Check the running image's Python version, OS, and platform, and the images sharing the same dependency files. | [pip verification environment](remediation-logic.md#pip-target-environment) |
| Processing is deferred until a tool release is old enough | Check the release time, configured waiting period, and availability time shown in the details. | [Minimum tool release age](configuration.md#remediation-tool-release-age), [Tool retrieval reasons](remediation-reference.md#tool-reasons) |
| A tool cannot be retrieved | Check connectivity to the download destination, retrieval limits, and notification details. | [Tool downloads](outbound-communication.md#tool-downloads), [Tool retrieval reasons](remediation-reference.md#tool-reasons) |
| A tool hash does not match | Check the declared hash and the retrieval and verification details. | [Tool version declarations](remediation-reference.md#tool-declarations), [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| The tool cache cannot be used | Check write permissions for the storage location, free space, and cache capacity settings. | [Tool cache capacity](configuration.md#remediation-tool-cache), [Tool retrieval reasons](remediation-reference.md#tool-reasons) |
| A Docker work container cannot run | Check the Docker API, the work image download source, and work environment validation logs. | [Enabling fix pull requests](remediation-setup.md#enable-pull-requests), [Work container execution](remediation-logic.md#worker-execution) |
| Kubernetes language-package updates require manual action or are deferred | Follow the reason code to check the work namespace, Kubernetes version, absence of a RuntimeClass setting, RBAC, Pod creation rules and parameters, PriorityClass, Pod count and quota, and Pod events. | [Setup steps](remediation-setup.md#kubernetes-language-updates), [Reason codes](remediation-reference.md#reason-codes) |
| Kubernetes reports `update_result_invalid` with missing result log content | Check that the execution node's `containerLogMaxSize` is at least `144Mi` and that the log has not been truncated or rotated. | [Prerequisites](remediation-setup.md#kubernetes-language-updates) |
| The worker program cannot be used | Check the distribution in use and the logs, and also check the worker program's location for custom builds. | [Worker program location](configuration.md#remediation-worker-program) |
| Processing stops at a limit or deadline | Check the limit shown in the notification, configured values, and the next scheduled run. | [Processing limits](configuration.md#remediation-limits), [Update result reasons](remediation-reference.md#update-reasons) |
| An update does not reach a fixed version, or only part of it appears in the PR | Check excluded packages, remaining versions, and parent packages' dependency ranges. | [Partial PRs](remediation-results.md#partial-pull-requests), [Update result reasons](remediation-reference.md#update-reasons) |
| Checks of updated files or accompanying changes fail | Check changed files, lockfile formats, dependency ranges, and verification results against package distributions. | [Validating accompanying changes](remediation-logic.md#change-validation), [Update result reasons](remediation-reference.md#update-reasons) |
| Results cannot be compared, findings remain, or new findings appear | Check scan logs, comparison conditions, and remaining and introduced findings after the update. | [Scan comparison conditions](remediation-logic.md#comparison-conditions), [Resolved findings in comparisons](remediation-results.md#verification-results) |

## Checking for a missing PR {#check-missing-pr}

| Symptom | What to check | Reference |
| --- | --- | --- |
| A candidate exists, but no PR appears | Check PR enablement, source mappings, and whether the target uses a supported editable format. | [Enablement settings](configuration.md#remediation-enablement), [Source mappings](configuration.md#remediation-mappings), [Supported input formats](remediation-reference.md#supported-inputs) |
| A Kustomize or Helm values update reports `undeclared_affected_workload` | Check whether the entry or key affects the container identified in the details; if it does, add it to `affects` and align the sets in every mapping to that entry or key, or change its affected scope. | [Kustomize PRs](remediation-logic.md#kustomize-prs), [Helm values PRs](remediation-logic.md#helm-values-prs) |
| A Kustomize or Helm values update reports `init_container_unverified` | Check the listed ordinary init container's Pod status and the image content, reference, and scan of a running container in the set in the same Pod. | [Kustomize PRs](remediation-logic.md#kustomize-prs), [Helm values PRs](remediation-logic.md#helm-values-prs) |
| A Kustomize update requires manual action with a `kustomize_*` reason | Check the target `images[].name`, a string `newTag`, unsupported syntax or features, interference from other `images` entries, and image automation markers. | [Kustomize formats](remediation-reference.md#kustomize-formats) |
| A Helm values update requires manual action with a `helm_*` reason | Check the selected key, image form, explicit string tag, YAML keys and syntax, and image automation markers according to the reason code. | [Helm values formats](remediation-reference.md#helm-values-formats) |
| A Helm values PR asks you to confirm the final value | Check overrides from Flux HelmRelease `spec.values`, Argo CD `parameters`, `valuesObject`, and `valuesFrom`, CI `--set`, and other values files, along with the containers affected by the selected key. | [Helm values PR configuration](remediation-setup.md#helm-values-pull-requests) |
| GitHub rejects a write | Check the token's target repositories and permissions, and the repository rules. | [GitHub access](configuration.md#remediation-github), [PR processing reasons](remediation-reference.md#pr-reasons) |
| The limit on new or open PRs is reached | Check current PRs and the configured limits. | [Processing limits](configuration.md#remediation-limits) |
| An update matches an existing PR, and no new PR is created | Check the existing PR shown in the notification and whether the same update was previously closed without merging. | [Matching existing PRs](remediation-logic.md#existing-pr-matching), [Handling closed PRs](remediation-logic.md#closed-prs) |
| Source files or candidates change during PR preparation | Check notification details and the current source and candidates, then check the next cycle's results. | [PR processing reasons](remediation-reference.md#pr-reasons) |
| A GitHub operation fails or has an unknown outcome | Check access, connectivity, and operation results, and wait for KestreLynx to reconcile operations with unknown outcomes. | [PR operation event fields](webhook-remediation-reference.md#remediation-operation-fields), [PR processing reasons](remediation-reference.md#pr-reasons) |

## Checking record reconciliation failures {#check-record-failure}

| Symptom | What to check | Reference |
| --- | --- | --- |
| Plan or PR records cannot be saved | Check the persistent volume mount, storage permissions, free space, and logs. | [Storage location](configuration.md#remediation-storage), [Storage reasons](remediation-reference.md#storage-reasons) |
| Records are locked | Check whether another KestreLynx instance is running with the same storage location. | [Storage reasons](remediation-reference.md#storage-reasons) |
| Existing PRs cannot be reconciled with records | Check GitHub access, identification markers in PR bodies, and the change history of PRs and repositories. | [Record recovery](remediation-logic.md#record-recovery), [PR processing reasons](remediation-reference.md#pr-reasons) |
| Writes stop because of record corruption, format problems, or operation history issues | Check the logs and notification details to identify the cause. | [Stopping writes](remediation-logic.md#write-stops), [Storage reasons](remediation-reference.md#storage-reasons) |

!!! warning "Preserve records"

    Do not delete PR records to force a retry. They are needed to prevent closed updates from being recreated and to reconcile previous operations.
