# Kubernetes remediation pull request development

- **Status:** Implemented (verified from PR creation through GitOps deployment on a validation host).
- **Started:** October 20, 2026
- **Last updated:** October 23, 2026

## Purpose

The aim is to make [remediation plans and pull requests](remediation-pull-requests.md) available on Kubernetes.
The design requires users to specify where changes belong and runs language package updates safely in disposable Pods within the cluster.

## Remediation targets and workflow

Consider a running Deployment whose manifest in Git specifies `image: nginx:1.27.2`.
If the fixed version is 1.27.3, KestreLynx creates a PR that changes the tag.

Manifest excerpt before the change:

```yaml
containers:
  - name: web
    image: nginx:1.27.2
```

Excerpt with the change proposed in the PR:

```yaml
containers:
  - name: web
    image: nginx:1.27.3
```

```text
Running image → Comparison of candidate fixes → PR changing files in Git
                                                        ↓ User merges
                                               User's GitOps or CI → Cluster
```

The scope includes image references in standard manifests, Kustomize `images`, and Helm `values`.

KestreLynx does not apply fixes to the cluster.
The user's GitOps or CI applies changes after merging, so merging triggers deployment when automatic synchronization is enabled.

## Approach

- **Users explicitly map change locations, without inference from Argo CD or Flux information.**
    - Information about the managing system alone does not identify the repository or file to change.
- **PR creation requires a match among the version specified in the Pod, the running version, and the version in the repository file.**
    - This prevents changes based on a version different from the running target.
- **References pinned by digest require manual action, as with Compose.**
    - These references require different change rules from tag updates.

## Decisions

### Explicit scope of effects (`affects`)

A single Helm key or Kustomize entry can affect multiple workloads.
KestreLynx does not render Helm or Kustomize configurations, so users specify the affected scope in configuration rather than having KestreLynx infer it.

The following example covers a Helm `image` key that affects the `app` container in both the mapped `web` workload and the `worker` workload.
The `affects` list identifies affected containers other than the mapped container by workload kind, namespace, workload name, and container name.

```yaml
remediation:
  mappings:
    - workload: deployment/shop/web/app
      repository: example/deployment
      base_branch: main
      helm_values:
        path: releases/shop/values.yaml
        key: image
        affects:
          - deployment/shop/worker/app
```

When `affects` is absent, KestreLynx treats this as the user's confirmation that only the mapped container is affected.
As a precaution, KestreLynx blocks PR creation if it finds an unlisted workload using the same value, for example in the same namespace, but it cannot detect every omission.

### Execution method for language package updates

In Docker environments, package managers run in job containers, but Docker is unavailable within the target cluster.
An external Docker host was rejected because of the setup burden on users, and disposable Pods in a dedicated job namespace were chosen instead.

Permissions to create Pods are granted only when the user enables language package updates, and only within that job namespace.

### Safeguards for job Pods

Language package updates target Kubernetes 1.30 and later, with the following safeguards.

- Kubernetes' built-in ValidatingAdmissionPolicy restricts the permitted Pod configuration, and KestreLynx checks that an attempt to create a noncompliant Pod is rejected before starting a job.
- KestreLynx verifies that the actual configuration of the created Pod matches the permitted configuration before passing it the source files for the update.
- Results are encrypted with a key unique to each job, and result content appears in logs only as ciphertext.
- GitHub tokens and KestreLynx configuration are not passed to job Pods.

## Verification method

### Environment

| Item | Details |
| --- | --- |
| OS | Ubuntu 26.04 (validation host) |
| K3s | v1.31.5 |
| Flux | v2.4.0 |
| Argo CD | v2.13.2 |
| Helm | v3.16.2 |
| GitHub repository for validation | Held the files to update and was used to verify PR creation, merging, and deployment |

Flux managed the manifest and Kustomize applications, while Argo CD managed the Helm application, each covering separate targets.
An application applied directly without either tool was also tested.

### Verification coverage

| Area | Method |
| --- | --- |
| Remediation PRs for each format | Placed target files in the validation repository and inspected the diffs in PRs created by KestreLynx |
| Repeated runs and record recovery | Checked for duplicate PRs and verified associations with existing PRs after repeated runs, PR closure, and record deletion |
| GitOps deployment | Merged PRs, prompted reconciliation, and checked the running targets and subsequent update decisions |
| Cases requiring manual action | Changed image references and the declared scope of effects to verify that automatic updates stopped |
| Safeguards for job Pods | Tested permissions, admission rules, and network restrictions, and checked cleanup after restarts and whether plaintext appeared in logs or other collected information |

## Verification results

Within the tested scope, remediation PR creation, association with existing PRs, GitOps deployment, and stopping when prerequisites were unmet worked as expected.
The two issues found during verification and their handling are described under “Issues found during verification” at the end of this section.

### Remediation PRs

Language package updates and re-resolution through dependent packages ran in job Pods.

| Format | Changes |
| --- | --- |
| Manifests | Updated image lines for regular containers, native sidecars, and a CronJob in one PR, preserving comments and quotation marks |
| Dockerfile | Updated the base image in `FROM` |
| Kustomize | Changed only `newTag` |
| Helm values | Changed only the tag value |
| npm and pnpm | Changed only lockfiles, updating minimist from 1.2.5 to 1.2.8 |
| pip | Changed `requirements.txt`, including distribution hashes, updating urllib3 from 1.26.4 to 2.8.0 |
| uv | Changed `pyproject.toml` and `uv.lock`, updating urllib3 from 1.26.4 to 2.8.0 |
| npm and pnpm re-resolution through dependent packages | Updated the dependent package mkdirp from 0.5.1 to 0.5.6 in the lockfile, updating minimist from 0.0.8 to 1.2.8 |

Re-resolution through dependent packages with uv remained pending because the candidate included a certifi release published less than 72 hours earlier, so no PR was created during verification.

### Repeated runs and record recovery

| Scenario | Result |
| --- | --- |
| Repeated runs for the same update | Associated the update with the existing PR without creating duplicates |
| Restart after closing the Dockerfile and pip PRs | Did not recreate PRs for the same updates |
| Deletion of local records while retaining instance identity | Recovered associations with existing PRs and their closed status from markers in PR bodies |

### GitOps deployment

| Scenario | Result |
| --- | --- |
| PR creation for applications managed by GitOps | Identified the managing Flux Kustomization or Argo CD Application in the PR body |
| Reconciliation prompted in Flux and Argo CD after merging | Updates reached the Deployment and CronJob about two minutes after merging |
| Deployment of the CronJob update | Newly started Jobs used the new version, while running Jobs continued with the old version until completion |
| Detection of mixed versions or mismatches with source files during rollout or while older Jobs were still running | Required manual action and stopped creating or updating remediation PRs |
| Rollout completion | Did not propose the same update again |

### Cases requiring manual action

| Scenario | Result |
| --- | --- |
| Image references pinned by digest | Required manual action and blocked updates to the same file |
| Lines with an `$imagepolicy` marker | Required manual action because another tool managed the tag |
| Incomplete declaration of the scope affected by Kustomize | Blocked the update because a workload using the same image in the same namespace was missing from `affects` |
| A workload listed in Helm `affects` was not running | Blocked the update because the running target could not be verified |

### Safeguards for job Pods

| Scenario | Result |
| --- | --- |
| Inspection of KestreLynx permissions | Pod creation was limited to the work namespace; writes to target workloads and reads of Secrets and ConfigMaps were denied |
| Attempts to create noncompliant Pods and checks with admission rules no longer enforced | All tested noncompliant Pods were rejected, and KestreLynx did not create job Pods when it could not verify rule enforcement |
| Administrator attempts to modify a running job Pod | Changes to labels, annotations, images, and existing tolerations, as well as the addition of ephemeral containers, were rejected |
| Exhaustion of the Pod quota in the work namespace | Waited without creating a job Pod |
| KestreLynx restart during a job | Deleted remaining job Pods at startup |
| Inspection of logs, termination messages, Pod information, and Events during language package updates | No plaintext inputs or results were found in the collected information |
| Connectivity checks after network restrictions took effect on a test Pod with the same NetworkPolicy | Among the destinations tested, only DNS to CoreDNS and external TCP port 443 were reachable |

The delay of a few seconds before network restrictions took effect is described below under “Issues found during verification.”

### Issues found during verification

#### Delays caused by terminating job Pods

| Item | Details |
| --- | --- |
| Observed behavior | Job Pods being deleted counted toward the concurrency limit, delaying subsequent jobs |
| Change | Excluded Pods being deleted from the count |
| Verification result | Even with `max_concurrent_pods` set to 1 in [Work Pod configuration](../documentation/configuration.md#remediation-worker-kubernetes), terminating Pods no longer caused language package update units to wait |

#### NetworkPolicy enforcement delay for new Pods

| Item | Details |
| --- | --- |
| Observed behavior | With the default CNI in the tested K3s environment, egress was unrestricted for a few seconds before NetworkPolicy took effect on a new Pod |
| Documentation | Recorded this limitation, which KestreLynx cannot control, under [Work container network](../documentation/outbound-communication.md#worker-network) |

## Unverified areas and next steps

- **PR replacement on GitHub**
    - No newer patch release was available in the same version series, so replacement of an older PR with a new one was verified only by unit tests, not in a real environment
- **Result size and execution environments**
    - Handling results larger than the node's log limit still requires verification in a real environment
    - Behavior on newer K3s versions and other Kubernetes distributions remains unverified
- **Additional cases requiring manual action**
    - References containing `${VAR}`, Kustomize entries without `newTag`, and empty Helm tags were verified only by unit tests

## Update history

### October 23, 2026

- Documented the Kubernetes remediation PR implementation and verification results in a real environment.
- Recorded verification of GitOps deployment and safeguards for job Pods.
- Fixed delays caused by terminating Pods and documented the delay before network restrictions take effect.
- Updated the unverified scope and next steps.

### October 20, 2026

- Documented change location mappings and version matching.
- Documented explicit declarations of the targets affected by shared configuration.
- Documented the execution method and safeguards for job Pods.
- Recorded the implementation order and plans for verification in a real environment.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
