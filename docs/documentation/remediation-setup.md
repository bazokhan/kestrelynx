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

    For language package updates, KestreLynx creates, starts, and removes work containers through the Docker API. Mounting the Docker socket with `:ro` does not restrict API operations, so the supplied Compose configuration does not need to change to `:rw`. If you use a Docker API proxy, allow these operations.

### Enabling PR creation {#enable-pr-creation}

1. Confirm that the token configured in [Preparing GitHub access](#prepare-github-access) has the access needed to create PRs
2. Enable PR creation while keeping the existing mappings, credentials, and storage location
3. Recreate the KestreLynx container and confirm in the logs that PR creation is enabled

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
