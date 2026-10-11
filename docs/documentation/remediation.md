# Remediation plans and pull requests

!!! warning "Experimental feature"

    Remediation plans and pull requests are an experimental feature. Their configuration, notifications, and pull request formats may change.

KestreLynx uses findings from running images to propose image and dependency updates.
This page explains how to enable remediation plans and pull requests, read their results, and check an update before deploying it.

A candidate describes a possible change. Creating or merging a pull request does not confirm that vulnerabilities have been resolved in running containers.

## Plans and pull requests

Plans and pull requests have separate enablement settings, both defaulting to `false`.

| Setting | What it does | What it does not do |
| --- | --- | --- |
| `remediation.enabled` | Selects candidates, compares image rescans where supported, reads mapped source files, and reports a plan. | Does not write to GitHub, run package managers, create work containers, or change running workloads. |
| `remediation.pull_requests.enabled` | Creates GitHub PRs for eligible candidates and runs language dependency updates in disposable Docker work containers. | Does not merge PRs, build application images, or deploy changes. |

Enabling pull requests without enabling remediation plans is a configuration error.
Enabling remediation in Kubernetes mode is also a configuration error.

Read-only planning still saves local plan and notification records.
When both settings are disabled, remediation processing does not run.

## Scope and requirements

### Supported targets

Remediation supports Docker, with source changes mapped to Compose workloads.

- Public container images and base images
- Public npm and PyPI packages
- Source files on GitHub for Compose, Dockerfile, and language dependency changes

### Unsupported targets

- Enabling remediation plans in Kubernetes mode (a configuration error)
- Private image registries or private package sources, even with a GitHub token configured
- Source files hosted outside GitHub

### Requirements

- Runtime environment
    - A running KestreLynx instance with a Slack or generic webhook destination
    - Persistent storage for remediation plan and PR records
    - Docker API access to manage disposable work containers when language package PRs are enabled
- Source mappings
    - A mapping to the file and service to edit when creating a Compose PR
    - Source mappings for Dockerfile and language package changes, required even for planning

Distributed image comparisons can appear in a plan without a source mapping.

- **Reading GitHub repositories**
    - Public repositories can be read without a token.
    - For repositories requiring authentication, use a fine-grained personal access token restricted to the mapped repositories, with Contents read access for planning.
- **Creating PRs**
    - The additional write permissions described below are also required.

## Steps to enable remediation plans

### 1. Identify the Compose workloads

Identify the workload key to use in each mapping.

1. Read the project and service from the running container's labels.
    - Project: `com.docker.compose.project`
    - Service: `com.docker.compose.service`
2. Build the workload key in the format `compose/<project>/<service>`.

!!! note "Compose project name"

    - Use the deployed Compose project name for the project.
    - The Compose project name may differ from the repository or directory name.

### 2. Map workloads to source files

Add the mappings to the existing `config.yml`.

- Add the following section, replacing the example workloads, repositories, branches, and paths.
- Specify the mapping kinds.
    - Each entry must contain exactly one of `compose`, `dependencies`, or `dockerfile`.
    - A workload can have one entry of each kind; use separate entries when it needs more than one kind of mapping.
- Set the paths and base branches.
    - Use paths relative to the repository root.
    - Use `.` for a dependency directory at the root.
    - Elsewhere, use normalized paths without a leading `/`, `./`, `..`, or backslashes.
    - Mappings that share a dependency directory or Dockerfile must agree on its base branch.

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: false
  storage_dir: /var/lib/kestrelynx/remediation
  mappings:
    - workload: compose/example/web
      repository: example/deployment
      base_branch: main
      compose:
        path: compose.yml
        service: web

    - workload: compose/example/api
      repository: example/application
      base_branch: main
      dependencies:
        directory: .

    - workload: compose/example/app
      repository: example/application
      base_branch: main
      dockerfile:
        path: docker/Dockerfile
        target: runtime
```

!!! note "Mappings and source verification"

    - KestreLynx resolves the branch to a commit before reading source files.
    - The mapping is supplied by you: matching package names and versions does not prove that the running image was built from those files.

### 3. Keep the records persistent

Configure record storage and planning limits.

- Check the storage location in `remediation.storage_dir`.
    - The default is `/var/lib/kestrelynx/remediation`, inside the state volume mounted by the supplied Compose file.
    - A custom path must be absolute and backed by persistent, writable storage.
- Configure planning limits under `remediation.limits`.
    - Refer to the following table and use positive values for all settings.

| Option | Default | Description |
| --- | --- | --- |
| `candidate_scans_per_cycle` | `10` | Maximum candidate image scans per cycle. |
| `baseline_rescans_per_cycle` | `10` | Maximum baseline image rescans per cycle. |
| `registry_requests_per_cycle` | `200` | Maximum image registry requests per cycle. |
| `tag_pages_per_repository` | `20` | Maximum tag-listing pages for each image repository. |
| `cycle_timeout` | `30m` | Deadline for the plan stage, not the entire scan cycle. |

!!! note "When a limit is reached"

    - Work beyond a limit is reported as deferred.
    - An incomplete tag listing is not used to claim that a candidate is the newest patch.

The complete configuration example is available in
[`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml).

### 4. Reload the configuration and check a scan

Reload the configuration and check the scan results.

1. Run the following commands from KestreLynx's Compose directory to recreate the container and follow its logs.

    ```bash
    docker compose up -d --force-recreate kestrelynx
    docker compose logs -f kestrelynx
    ```

2. Check the logs and the notification's `Fix plan` section.
    - With the default `schedule.run_on_start: true`, a scan starts after startup.
    - An eligible language dependency initially appears as a dependency update candidate.

!!! note "Scope of planning"

    - Planning alone does not run the update or inspect its output.

## Targets and candidate selection

### Distributed image tags

A Compose mapping identifies `services.<service>.image` in the source file.

| Running reference | Candidate selection | Result |
| --- | --- | --- |
| Full version tag, such as `nginx:1.25.3` | Newest patch from the complete tag listing, keeping the major, minor, prefix, and suffix. | An eligible candidate can become a PR that changes only the image tag. |
| Floating tag, such as `postgres:16`, `1.25`, or `latest` | Current registry content under the same tag. | An eligible comparison recommends pulling again; no PR is needed because the reference is unchanged. |
| Digest-only or tag-and-digest reference | No automatic candidate selection. | Excluded from tag updates. |
| Prerelease or unsupported tag format | No automatic candidate selection. | Excluded with a reason. |

The current image and candidate are compared using the same scanner and vulnerability database content.

- **Conditions for proposing a candidate**
    - At least one targeted finding disappears.
    - No new findings appear in the evaluated range.
    - The required analysis is complete.
- **Partial improvements**
    - Candidates that resolve only some findings are eligible, with remaining findings shown separately.
- **Candidates requiring manual judgment**
    - A candidate that introduces findings requires a person's decision.
    - A newly introduced vulnerability in the CISA KEV catalog is also reported.

Compose tag editing has the following requirements.

- **References eligible for automatic editing**
    - A literal image reference matching the running repository and tag
- **Cases requiring manual changes**
    - References using variables or digests
    - Affected locations using unsupported aliases, merge keys, `include`, or `extends`
- **Cases using the Dockerfile route**
    - Services with `build:`

### Dockerfile base images

A `dockerfile` mapping specifies the file and optionally its build `target`.

- **Build stage selection**
    - Without a target, KestreLynx uses the last stage.
    - If the selected stage inherits from an earlier stage, KestreLynx follows the chain to the external base image.
- **Reading from Compose**
    - A Compose mapping can supply this information through a static `build:` section with a repository-local context and optional `dockerfile` and `target`.
    - A separate Dockerfile mapping is unnecessary in that case.
    - If both mappings are present, they must agree.

| Base reference or input | Candidate selection and handling |
| --- | --- |
| Full version tag, such as `python:3.12.3-slim` | Compare the current base with the newest patch of the same major, minor, prefix, and suffix, and propose editing only the relevant `FROM` tag. |
| Floating tag, such as `python:3.12-slim` | Check the base layers, without creating a tag-update PR or comparing vulnerability counts for an update. |
| Base layers do not match the start of the running image's layers | Do not claim that a comparison describes the running image's base. |
| Variables in `FROM`, digest references, `scratch`, or unsupported build instructions | Require manual handling. |
| Remote Compose build contexts, `dockerfile_inline`, or `additional_contexts` | Do not derive an automatic Dockerfile edit from that build configuration. |

- **Unconfirmed floating bases**
    - The notification suggests fetching the current base and rebuilding with `docker compose build --pull`.
    - This guidance is a rebuild instruction, not a verified improvement.
- **Base-image comparison targets**
    - Only findings attributed by Trivy to the matching base layers are included.
    - Findings in later layers or without usable layer information are not treated as base-derived targets.

### Language packages

A `dependencies` mapping names the directory containing the dependency files.

| Manager | Supported files and format | Update handling |
| --- | --- | --- |
| npm | `package.json` and `package-lock.json` with `lockfileVersion` 2 or 3, for a single project. | Update the lockfile and, where supported and necessary, the direct dependency's version constraint. |
| pnpm | `package.json` and `pnpm-lock.yaml` with `lockfileVersion: '9.0'` and only the `.` importer. | Update the lockfile and eligible direct dependency constraints, then inspect the selected versions. |
| pip | `requirements.txt` with supported public PyPI requirements. | Update exact `==` pins and their hashes where present; a range that already allows a fix produces a rebuild expectation instead of a PR. |
| uv | Static `pyproject.toml` and `uv.lock` with `version = 1`, `revision = 5`, for a single project. | Update the lockfile and eligible direct dependency constraints. |

KestreLynx selects a lower bound for each package's update target from running-image findings.

- **Eligible findings**
    - Findings with scan status `fixed` and reported fixed versions
    - Findings without fixed-version information are excluded.
- **Lower-bound selection**
    1. For each targeted finding, take the lowest reported fix newer than the installed version.
    2. Use the highest of those versions as the package's update lower bound.
- **Checks after selection**
    - Selecting this lower bound does not verify that all targeted vulnerabilities are resolved.
    - With PRs enabled, KestreLynx separately inspects the updated dependency files and compares before/after scans to check that the targeted vulnerabilities are no longer detected.
    - The actual version selected by the package manager is inspected and reported, so it may differ from the lower bound.

When a direct dependency's constraint excludes the fixed version, KestreLynx can edit only its version portion while preserving the operator.

| Manager | Constraints eligible for this edit |
| --- | --- |
| npm, pnpm | `1.2.3`, `=1.2.3`, `^1.2.3`, `~1.2.3` |
| uv | `==`, `~=` |

Transitive dependency updates stay within the declared constraints.
KestreLynx does not upgrade parent packages or add overrides to force a fix.

The following inputs or update results require manual handling.

- Unsupported source structure
    - Workspaces or ambiguous dependency files
    - Git, URL, local, or unsupported registry dependencies
    - Dynamic project metadata or dependencies requiring a source build
- Dependency constraints and installation behavior
    - Constraints that need editing but are outside the supported forms
    - Packages that bundle dependencies or carry their own shrinkwrap, including dependencies beneath them
    - pip requirements using unsupported options, file includes, or environment markers that cannot be evaluated
- Package manager restrictions
    - uv projects whose `requires-python` does not admit the work image's Python 3.13, or cannot be evaluated
    - `uv.lock` revisions other than 5
    - pnpm updates involving versions published within the last 24 hours when the release-age check rejects them or the update creates an undeclared configuration file
    - Updates that rewrite the lockfile format or make unexplained changes

## Steps to enable remediation pull requests

### 1. Prepare a GitHub token and repository CI

Prepare the token and repository settings needed to create PRs.

- Create a fine-grained personal access token restricted to the repositories in the mappings, with these repository permissions.

| Permission | Access |
| --- | --- |
| Contents | Read and write |
| Pull requests | Read and write |

- Check workflows and repository rules before enabling PRs.
    - Opening a PR can start repository CI, including workflows triggered by `pull_request`.
- Store the token in `remediation.github.token`.
    - Keep `config.yml` readable only by its owner.
    - Do not commit `config.yml`.

### 2. Check Docker access and the work image

Check the work image and Docker access used for language updates.

- Configure the work image reference.
    - Leave `remediation.worker.image` unset to use the bundled reference.
    - For a mirror or validation image, set it to `repository@sha256:<64 lowercase hexadecimal digits>`.
    - Specify a work image explicitly for a build without a bundled reference.
- If access goes through a Docker API proxy, configure its policy to allow work container operations.

!!! note "Work image retrieval and constraints"

    - Language updates use `ghcr.io/kitsunetrail/kestrelynx-worker`, pinned by digest in each main image release.
        - KestreLynx pulls it when an update first needs it.
        - A tag alone is not accepted.
    - If the work image cannot be obtained, language updates are deferred.
        - KestreLynx does not run package managers inside the main container as a fallback.

!!! warning "Docker API access"

    - With pull requests enabled, language updates create, start, and remove work containers through the Docker API.
    - Mounting the Docker socket with `:ro` does not restrict API operations.
    - The supplied socket mount can stay `:ro`; changing it to `:rw` is not required.

### 3. Enable PR creation

Update the existing remediation section, keeping the source mappings.

1. Enable PR creation with the following settings.

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: true
      github:
        token: "REPLACE_WITH_YOUR_GITHUB_TOKEN"
    ```

2. Replace the placeholder with the prepared token before starting KestreLynx.
3. Configure PR and dependency update limits using the following settings under `remediation.limits`.
    - Use positive values for counts.
    - Set `job_timeout` to a value from `1m` through `60m30s`.

| Option | Default | Description |
| --- | --- | --- |
| `new_prs_per_cycle` | `3` | Maximum new PRs in one cycle. |
| `open_prs` | `10` | Maximum open KestreLynx PRs across the configured repositories. |
| `dependency_jobs_per_cycle` | `3` | Maximum dependency update units attempted per cycle (not packages or containers); one unit can use multiple containers, as with pip or manifest edits. |
| `job_timeout` | `6m` | Deadline for each work container's creation, execution, and result collection; cleanup has a separate 30-second deadline. |

!!! note "Deadlines and limits"

    - The operation inside the container receives 30 seconds less than `job_timeout`.
    - Reaching a limit defers further work.
        - KestreLynx does not close an older PR to make room under the open-PR limit.

### 4. Check the first result

Recreate KestreLynx and check the first result.

1. Recreate KestreLynx as in the planning setup.
2. Inspect the notification, logs, and PR on GitHub.
3. Before reviewing the verification results, confirm that the following are as intended.
    - Repository
    - Base branch
    - Files
    - Proposed versions

## Read the notifications

Slack displays the plan under `Fix plan`, or `修正計画` with `notify.language: ja`.

| Slack category | Meaning | Next action |
| --- | --- | --- |
| `re-pull` / `再pull` | The comparison supports fetching new content under the same image tag. | Pull and recreate the service, then check its running-image scan. |
| `update candidate(s)` / `更新候補` | An image comparison or checked dependency update supports a proposed change. | Review the candidate or linked PR. |
| `dependency update candidate(s)` / `依存更新候補` | Source files match the affected dependency and a target version was selected. | Review the proposed target; the update has not run yet. |
| `rebuild expected` / `再ビルドで解消見込み` | A pip version range allows a fixed version. | Rebuild and check what was installed and deployed. |
| `manual` / `要判断` | The source, update, or comparison needs a person's decision. | Read the reason and prepare or assess the change manually. |
| `not comparable` / `比較不能` | Required comparison evidence is missing or incompatible. | Check scan identity, analysis coverage, and the reported reason. |
| `deferred` / `延期` | A limit, deadline, rate limit, or unavailable work image prevented processing. | Check the reason and retry after addressing it or in a later cycle. |
| `no candidate` / `候補なし` | No newer content was found, or the candidate did not resolve targets. | Check the available versions and remaining findings. |
| `excluded` / `対象外` | The reference is outside automatic candidate selection. | Review the reference and update it manually if needed. |
| `failed` / `失敗` | Processing failed. | Check the reason and logs. |

- **PR summaries**
    - Separate summaries show created, open, merged, closed without merging, manual, deferred, and blocked or failed states.
    - A merged PR is not a deployment confirmation.
- **Verification scope and warnings**
    - Dockerfile results state that only base images were compared.
    - Language PRs state that dependency files were checked and the rebuilt image was not.
    - Major version changes receive an additional warning.
- **Where to find results**
    - Slack summarizes counts and limits named entries to a few results.
    - The generic webhook's `remediation` object provides individual results and reasons, including PR processing results.
    - The saved plan contains planning and dependency-update results from before PR processing.

For webhook delivery and payload information, see
[How KestreLynx works — Generic webhook](how-it-works.md#7-generic-webhook).

## Read the PR and its verification scope

PR bodies use the following sections.

| Section | Contents |
| --- | --- |
| `What` | Repository, base branch and commit, source files, and affected workloads. |
| `Change` | Image tags or package versions before and after the proposed change. |
| `Why this candidate` / `Why these versions` | The candidate selection rule. |
| `Verification` | Comparisons, scan conditions, and checks performed. |
| `Not verified` | Checks and deployment work left to the user. |

- **Additional PR body details**
    - Language PRs also list targeted vulnerabilities, manifest edits, operations run, and added, changed, or removed lockfile entries.
    - PR bodies are in English.

| Target | What KestreLynx checks | What it does not establish |
| --- | --- | --- |
| Distributed image | Current and candidate image identities, comparable scan conditions, and resolved, remaining, and introduced findings. | Application compatibility, CI success, or deployment after merge. |
| Dockerfile base image | Matching base layers and comparison of the current and candidate base images for the targeted findings. | Build provenance or the findings in an image rebuilt from the edited Dockerfile. |
| Language package | Update output, changed distribution references and integrity values against public registries, fixed-version conditions, permitted file changes, and before/after Trivy filesystem scans of dependency files. | Resolution in a rebuilt image, application compatibility, or test success. |

The verification scope has the following limits.

- **Language filesystem comparisons**
    - The comparison covers dependency files, including packages other than the update targets.
    - It uses the same database content, severity range, and scan settings before and after.
    - It does not read the repository's own Trivy configuration, ignore files, or VEX documents.
- **Trivy layer attribution**
    - Layer attribution does not prove how an image was built.
    - Reinstalling the same package version in a later Dockerfile instruction can still leave it attributed to a base layer.
    - Later build instructions can also change the final image's findings.
- **Dependency-file checks**
    - Agreement between dependency combinations and registry declarations, and acceptance of the output format by the installer, are checked only as far as possible.

Before merging, run CI that installs from the proposed dependency files.

| Manager | Example CI installation check |
| --- | --- |
| npm | `npm ci` |
| pnpm | `pnpm install --frozen-lockfile` |
| pip | `pip install -r requirements.txt` |
| uv | `uv sync --locked` |

All comparisons are limited to the configured severity range.
`Resolved` in a PR describes its comparison, not the current state of running containers.

!!! warning "Major version changes"

    - **When changes may be required**
        - Fixing all targeted vulnerabilities can require a different major version.
        - For 0.x packages, a minor version change is treated the same way.
    - **Checks before merging**
        - Review the warning in the PR and notification, including any manifest edit.
        - Run compatibility tests.

## PR management and your remaining work

KestreLynx records updates and checks their state on GitHub.

- Existing updates
    - An update with an existing PR does not produce a duplicate
    - An update closed without merging is not recreated, including after its branch is deleted
    - An unchanged language update input can reuse its open PR without another dependency job
- Branches and replacement
    - Existing branches are never overwritten or force-updated
    - PRs detected as modified by a user are excluded from automatic replacement
    - New candidates use new PRs rather than rewriting an existing PR branch

Closing an older PR requires the replacement conditions to be met.

- **Replacement conditions**
    - A new PR must be created and verified to cover every remediation target of the old one at the same edit locations.
    - Image replacements also require a newer patch in the same series.
    - A language update for another package, or one that covers only part of the old targets, is not sufficient.
- **Replacement processing**
    - KestreLynx checks both PRs before replacement, comments on the old PR with the replacement link, and then closes it.
    - If creation, verification, or the replacement comment fails, the old PR stays open.

After review and merge, deployment remains your responsibility.

1. Fetch the merged source changes
2. Pull the updated distributed image, or rebuild the application image from the changed Dockerfile and dependency files
3. Publish the rebuilt image where needed and recreate or redeploy the affected services
4. Check a subsequent KestreLynx scan of the running image for the targeted findings

- **Applying changes to running containers**
    - For floating tags, pulling or rebuilding and recreating containers is necessary even when the source does not change.
    - A merged source change alone leaves the old containers running.

## Permissions, network access, and security

### GitHub token

- **Permissions and uses**
    - The token allows access to the selected repositories.
    - With PR creation enabled, it also allows source and PR writes.
    - KestreLynx uses the GitHub API to create commits, branches, PRs, and replacement comments, and to close replaced PRs.
- **Destination and protection**
    - The token is sent to `api.github.com`.
    - It is not passed to work containers.
    - Protect the configuration file and restrict the token to the repositories that need it.

### Docker socket and work containers

- **The main container's Docker socket**
    - Socket access permits Docker API operations even when the socket is mounted `:ro`.
- **Work container inputs**
    - Work containers receive the dependency input files needed for the job.
    - They do not receive the GitHub token, main configuration, or Docker socket.
- **Execution restrictions**
    - Work containers run as non-root, drop all Linux capabilities, and use no-new-privileges.
    - They have memory, CPU, process, output, and time limits.
    - Package scripts and source builds are disabled.
- **Writable locations and file permissions**
    - With the distributed work image, the non-root job can write only to capacity-limited tmpfs locations.
    - Docker's root filesystem setting is not read-only; ownership and file permissions protect the image's writable layer and the input directory from the job.
    - Images supplied through `remediation.worker.image` must preserve the same ownership and permission restrictions.
    - Reference and digest checks do not inspect all image file permissions at runtime.
- **Result collection and cleanup**
    - After exit, KestreLynx collects results from standard output and attempts to remove the container, then inspects the collected results as untrusted data.
    - If results were collected, inspection can continue after a removal failure.
    - The failure is recorded, and removal is retried during later cleanup.

### Outbound connections and disclosed information

| Destination | Purpose and information |
| --- | --- |
| GitHub API | Read mapped repositories and files, reconcile PR state, and write proposed changes and PR descriptions when enabled. |
| Public image registries and their authentication or download endpoints | List tags, resolve image content, and retrieve images for comparisons. |
| Trivy database registries | Obtain vulnerability databases used for comparisons. |
| `ghcr.io`, or the configured work-image mirror | Pull the work image through Docker. |
| `registry.npmjs.org` | Retrieve public npm package metadata and distributions. |
| `pypi.org`, `files.pythonhosted.org` | Retrieve public PyPI metadata and distributions. |
| Configured Slack and webhook destinations | Send findings, plan results, source locations, version changes, reasons, and PR links or operation results. |

- **Work container networking**
    - Work containers use Docker bridge networking.
    - Their network access is not restricted by a destination allowlist.
- **Shared information**
    - Plan and PR information can include image references and digests, workload names, repository names, file paths, package versions, and vulnerability IDs.
    - Choose notification destinations and repository visibility that are appropriate for sharing this information.
- **Other connections**
    - The normal scan and optional intelligence-feed connections still apply.

### Stored records

- Records are kept under `remediation.storage_dir`, independently of the normal scan notification state.

| File | Contents |
| --- | --- |
| `plan.json` | Latest plan, source locations, scan evidence, and update checks, saved before PR processing. |
| `delivered.json` | Fingerprint of the last delivered plan notification. |
| `prs.json` | PR identities, update and attempt records, suppression information, and GitHub operation records. |

- **Results after PR processing**
    - PR processing results, operation events, and problems are added to the plan used for notifications after `plan.json` is saved.
    - That file is not saved again with these additions.
    - Check webhook and Slack notifications for PR processing results, and `prs.json` for stored PR and operation records.
- **Retention and limits**
    - PR and suppression records have no expiry.
    - The operation history is limited to 1,000 events, with undelivered events and unsettled operations protected from removal.
    - Writes stop if space cannot be made safely.
- **Record recovery and protection**
    - Corrupt or unsupported plan and PR records are not silently replaced with empty records.
    - When PR records are missing, KestreLynx examines open and closed PRs on its `kestrelynx/` branches and attempts to recover records from their body markers before writing.
    - Unverifiable records stop writes.
    - Keep the records persistent and preserve the PR identification markers.

## When a candidate or PR is missing

Start with the result's `category`, `reason`, and `detail` in the saved plan or generic webhook,
then check KestreLynx's logs.

| Situation or representative reason | What to check |
| --- | --- |
| No plan items | Running-image scan results, selected severities, and findings with reported fixed versions. |
| `no_newer_tag`, `same_content`, `candidate_does_not_resolve_targets` | Available tags, current content, and whether the candidate actually changes the targeted findings. |
| Missing source, `not_found_in_source`, or ambiguous dependency files | Compose project/service labels, mapping paths, base branch, GitHub access, and package versions in the source. |
| `base_layers_mismatch`, `floating_base_unconfirmed` | Dockerfile target and the base used by the running image, then the reported rebuild guidance. |
| `introduced_findings`, `introduced_kev` | New findings in the candidate comparison before deciding on a manual update. |
| `analysis_incomplete`, `entity_unverified`, or database preparation failure | Scan failures, image identity, platform, analysis coverage, and database download logs. |
| Unsupported lockfile, source, constraint, or Python environment | The supported formats and manual cases listed above. |
| `unexpected_files`, `release_age_violation`, or failed output checks | Update details, package manager behavior, and the dependency files. |
| `work_image_not_configured`, `work_image_unavailable` | The bundled or overridden digest reference, image access, and Docker API permissions. |
| Scan, registry, job, or PR limits | `remediation.limits`, rate-limit responses, and the next scheduled cycle. |
| Candidate exists but no PR | PR enablement, token permissions, source editability, closed-update suppression, and the PR status or reason. |
| GitHub write failure or unknown outcome | Repository rules, token access, and operation records; KestreLynx reconciles uncertain outcomes before retrying writes. |
| Storage failure or unverified records | Persistent volume access, free space, logs, and existing PR markers. |

Do not delete PR records to force a retry:
they preserve closed-update suppression and the evidence needed to reconcile previous operations.
