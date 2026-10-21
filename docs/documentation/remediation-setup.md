# Enabling remediation

This page explains how to enable remediation plans and fix pull requests and confirm that the settings have taken effect.
For an overview, see [Remediation plans and pull requests](remediation.md#overview).

For supported environments and inputs, see [Scope and requirements](remediation-reference.md#scope-and-requirements); for connection destinations, see [Outbound connections](outbound-communication.md#outbound-communication).

## Enabling remediation plans {#enable-fix-plans}

Merge the following examples into the relevant sections of your existing `config.yml`.
Do not add duplicate `remediation` sections to the same file.

### Kubernetes configuration {#kubernetes-plans}

Add `remediation.enabled: true` to your existing Kubernetes configuration.
Published-image comparisons need no mapping; to look for language-package candidates, map a dependency directory as follows.

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: false
  mappings:
    - workload: deployment/example/web/app
      repository: example/application
      base_branch: main
      dependencies:
        directory: .
```

Set `workload` to the workload key shown in notifications.
See [Source mappings](configuration.md#remediation-mappings) for the format and namespace restrictions.

Apply the updated ConfigMap, restart the KestreLynx Pod, and check the logs for configuration loading and planning results.
With the supplied deployment, use `kubectl logs -n kestrelynx deployment/kestrelynx -f` to view the logs.

### Preparing GitHub access {#prepare-github-access}

1. Choose the GitHub repository to map and the branch to use as the source and PR target
2. Check [GitHub access](configuration.md#remediation-github) for the permissions needed to read source files and create PRs
3. For uses that require a token, prepare one restricted to the target repositories and set it in `remediation.github.token`
4. Keep the configuration file containing the token readable only by its owner and exclude it from repository commits

### Identifying the workload {#identify-workload}

The following steps apply to Compose.
For Kubernetes, use the workload key from notifications as described in [Source mappings](configuration.md#remediation-mappings).

1. Inspect the target running container with `docker inspect`
2. Note the values of the `com.docker.compose.project` and `com.docker.compose.service` labels
3. Use those values to construct the workload key for the mapping in the format `compose/<project>/<service>`

If the project is `example` and the service is `web`, the workload key is `compose/example/web`.
For format details, see [Source mappings](configuration.md#remediation-mappings).

!!! note "Compose project name"

    Check the Compose project name used in the actual deployment. It may differ from the repository or directory name.

### Mapping source files {#map-source}

1. Choose the mapping kind for the update target from [Source mappings](configuration.md#remediation-mappings)
2. Replace the workload, repository, base branch, and target file locations with your actual values
3. Enable remediation plans with PR creation initially disabled

This minimal example maps a distributed image reference to a Compose file.

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: false
  mappings:
    - workload: compose/example/web
      repository: example/deployment
      base_branch: main
      compose:
        path: compose.yml
        service: web
```

For dependency file and Dockerfile settings and restrictions on multiple mappings, see [Source mappings](configuration.md#remediation-mappings).
For details on the enablement keys, see [Enablement settings](configuration.md#remediation-enablement).

### Authenticating to private image registries {#configure-registry-auth}

This configuration is unnecessary if you use only public images.

1. Prepare credentials with read access to the target images
2. Add the target host and credentials as described in [Image registry authentication](configuration.md#remediation-registries)
3. If the registry uses a token service on another host, check where credentials will be sent and configure `token_hosts`

```yaml
remediation:
  registries:
    - host: registry.example.com
      username: example-puller
      password: "REPLACE_WITH_REGISTRY_READ_TOKEN"
```

For key formats and configuration requirements, see [Image registry authentication](configuration.md#remediation-registries).
For the destinations that receive credentials, see [Credential destinations](outbound-communication.md#credential-destinations).

!!! note "Record storage"

    The supplied Compose configuration stores records in the state volume. If you change `remediation.storage_dir`, choose a location that persists when the container is recreated. For details, see [Storage location](configuration.md#remediation-storage).

### Verifying remediation plan startup {#verify-fix-plans}

The following steps apply to Compose; for Kubernetes startup checks, see [Kubernetes configuration](#kubernetes-plans).

1. With the supplied Compose configuration, run `docker compose up -d --force-recreate kestrelynx` in the KestreLynx deployment directory
2. Use `docker compose logs -f kestrelynx` to confirm that the configuration loaded and remediation plans are enabled
3. Check the target image scan and remediation plan results during the scan after startup or at the next scheduled time
4. Confirm that the workload, source, and update targets shown in the notification are as intended

For the meaning of each field, see [Displayed fields](remediation-results.md#slack-fields).
If startup fails, see [Startup validation](configuration.md#remediation-validation); if no plan appears, see [Checking for a missing plan](remediation-troubleshooting.md#check-missing-plan).

## Enabling fix pull requests {#enable-pull-requests}

Complete [Verifying remediation plan startup](#verify-fix-plans) before enabling PR creation.

!!! note "Docker API"

    For language package updates in Docker mode, KestreLynx creates, starts, and removes work containers through the Docker API. Mounting the Docker socket with `:ro` does not restrict API operations, so the supplied Compose configuration does not need to change to `:rw`. If you use a Docker API proxy, allow these operations.

### Kubernetes PR configuration {#kubernetes-pull-requests}

This example updates the image tag for `deployment/example/web/app` in `apps/web.yaml` and the base image for `deployment/example/api/app` in `docker/Dockerfile`.
Add the GitHub token and mappings to the existing Kubernetes configuration and enable `remediation.pull_requests.enabled`.

```yaml
remediation:
  enabled: true
  github:
    token: "REPLACE_WITH_GITHUB_TOKEN"
  pull_requests:
    enabled: true
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      manifest:
        path: apps/web.yaml
    - workload: deployment/example/api/app
      repository: example/application
      base_branch: main
      dockerfile:
        path: docker/Dockerfile
        target: runtime
```

Apply the configuration and restart the KestreLynx Pod.
These manifest and Dockerfile updates use only the read-only scanning RBAC.
Language-package updates additionally require the work Pod configuration below.

See [Manifest formats](remediation-reference.md#manifest-formats) for editable inputs and [Kubernetes manifest PRs](remediation-logic.md#kubernetes-manifest-prs) for creation requirements.

### Kubernetes language-package updates {#kubernetes-language-updates}

npm, pnpm, pip, and uv updates run in disposable Pods that KestreLynx creates in a user-provided work namespace.
The same Pods also run [re-resolution through dependent packages](remediation-reference.md#dependent-reresolution-limits) for npm, pnpm, and uv.

#### Prerequisites

- Use Kubernetes 1.30 or later and set `kubernetes.enabled: true`
- Set `containerLogMaxSize` to at least `144Mi` on every node running work Pods so that large results fit
- Configure a PID limit on every node running work Pods to limit the number of processes in a Pod
- Use a CNI that enforces NetworkPolicy

The largest result log is approximately 94.56 MiB through the API and 143.69 MiB in the node's storage format.
Results missing content because of log truncation or rotation are not adopted.

#### Manifest preparation and application

Adjust the following settings in `deploy/kubernetes/work/` for the installation.

- Keep the work namespace and ServiceAccount names consistent across `00-namespace.yaml`, `10-rbac.yaml`, `51-validatingadmissionpolicybinding.yaml`, `52-policy-params.yaml`, and the other manifests
- Set the RoleBinding's `subjects` in `10-rbac.yaml` to the ServiceAccount name and namespace used by KestreLynx
- Keep `preemptionPolicy: Never` in `20-priorityclass.yaml`, and match the configuration and `priorityClass` in `52-policy-params.yaml` if renaming it
- Set `receiverRepository` in `52-policy-params.yaml` to the KestreLynx image repository, `workRepositories` to the official image repositories or configured mirror repositories, and `arch` to the architecture of the KestreLynx Pod and execution nodes
- Adjust the DNS selectors and excluded address ranges in `40-networkpolicy.yaml` for the cluster's DNS, Pod, Service, and node networks
- Keep the ValidatingAdmissionPolicy and its binding's `metadata.name` as `kestrelynx-work`, which the verification checks use

Run the following from the repository root to apply the namespace, limits, policy parameters, policy and binding, and permissions in that order.

```sh
kubectl apply -f deploy/kubernetes/work/00-namespace.yaml
kubectl apply -f deploy/kubernetes/work/20-priorityclass.yaml
kubectl apply -f deploy/kubernetes/work/30-resourcequota.yaml
kubectl apply -f deploy/kubernetes/work/40-networkpolicy.yaml
kubectl apply -f deploy/kubernetes/work/52-policy-params.yaml
kubectl apply -f deploy/kubernetes/work/50-validatingadmissionpolicy.yaml
kubectl apply -f deploy/kubernetes/work/51-validatingadmissionpolicybinding.yaml
kubectl apply -f deploy/kubernetes/work/10-rbac.yaml
```

The work namespace enforces the Pod Security `restricted` profile, and the work ServiceAccount has no permissions or token.
The example ResourceQuota limits the namespace to 8 Pods and also caps CPU, memory, and ephemeral storage.

Additional permissions are granted to KestreLynx only within the work namespace when the user applies the Role and RoleBinding.
The scanning ClusterRole remains read-only, and no permissions to operate on Secrets or other resources are added.

| Resource | Additional operations |
| --- | --- |
| `pods` | `create`, `get`, `list`, and `delete` |
| `pods/attach` | `create` and `get` for the connection that sends input files to the receiving container's standard input |
| `pods/log` | `get` to collect encrypted results |

#### Configuration and startup verification

Keep the existing GitHub token and mappings, and merge the following into `config.yml` in `deploy/kubernetes/configmap.yaml`.
Set `namespace` to the applied work namespace and adjust `workload` and the repository for the update target.

```yaml
kubernetes:
  enabled: true
remediation:
  enabled: true
  pull_requests:
    enabled: true
  worker:
    kubernetes:
      namespace: kestrelynx-work
  mappings:
    - workload: deployment/example/api/app
      repository: example/application
      base_branch: main
      dependencies:
        directory: .
```

For the supplied deployment, run the following and check the logs and next notification for language-package update activation and processing results.

```sh
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl rollout restart -n kestrelynx deployment/kestrelynx
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

See [Work Pod configuration](configuration.md#remediation-worker-kubernetes) for defaults and [Work Pod execution](remediation-logic.md#kubernetes-work-pods) for safeguards and execution conditions.
### Enabling PR creation {#enable-pr-creation}

1. Confirm that the token configured in [Preparing GitHub access](#prepare-github-access) has the access needed to create PRs
2. Enable PR creation while keeping the existing mappings, credentials, and storage location
3. Recreate the KestreLynx container on Docker or restart its Pod on Kubernetes and confirm in the logs that PR creation is enabled

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: true
```

For key details, see [Enablement settings](configuration.md#remediation-enablement).
To adjust PR counts or dependency update processing limits, see [Processing limits](configuration.md#remediation-limits).

!!! note "Repository workflows"

    Creating a PR may start workflows triggered by `pull_request` in the target repository.

HTML comments in the PR body contain identification markers used for record reconciliation and recovery, so preserve them when editing the body.
If no PR is created, see [Checking for a missing PR](remediation-troubleshooting.md#check-missing-pr).
