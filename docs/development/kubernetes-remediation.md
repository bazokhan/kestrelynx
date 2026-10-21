# Kubernetes remediation pull request development

- **Status:** Design (implementation not started).
- **Started:** October 20, 2026
- **Last updated:** October 20, 2026

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

## Unverified areas and next steps

Implementation and practical verification remain pending.
The planned order is as follows.

1. Implement read-only remediation plans.
2. Implement remediation PRs for manifests and Dockerfiles.
3. Implement remediation PRs for language packages.
4. Add updates to Kustomize `images`.
5. Add updates to Helm `values`.
6. Verify behavior in a real environment with K3s, Flux, and Argo CD on a validation host, and prepare public documentation.

## Update history

### October 20, 2026

- Documented change location mappings and version matching.
- Documented explicit declarations of the targets affected by shared configuration.
- Documented the execution method and safeguards for job Pods.
- Recorded the implementation order and plans for verification in a real environment.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
