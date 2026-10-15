# Remediation plan and pull request development

- **Status:** Minimal release implementation complete.
- **Started:** October 8, 2026
- **Last updated:** October 15, 2026

## Purpose

Vulnerability notifications alone do not reduce the work of finding a fix and preparing a change. Use scan results from running containers to automatically select candidate fixes and notify users of a remediation plan.

When explicitly enabled, create remediation pull requests on GitHub. Include a comparison in each PR body showing findings that disappear, remain, or newly appear when the original and candidate are rescanned under the same conditions. Distinguish an expected fix in source files from a confirmed fix in the production image.

## Approach

- **Build a minimal scope that works from start to finish**
    - Connect remediation plans to PR creation for Compose tags, Dockerfile base images, and language packages in the minimal release, and expand the scope based on user feedback
    - Implement this within KestreLynx without relying on existing dependency update tools, to avoid additional setup for users
- **Do not execute third-party code**
    - Require manual action when updating a dependency needs a source build or another operation that executes its code
- **Keep claims of resolution within the verified scope**
    - Mark results as incomparable when comparison is unavailable, without concluding that findings have disappeared
    - Do not treat an expected fix in source files as resolution in production

## Investigation

Official documentation and source code were examined to establish how Renovate and Dependabot create PRs.

Both follow a workflow of extracting dependencies, looking up newer versions, rewriting files, regenerating lockfiles where needed, creating branches and commits, and opening PRs. A lockfile records the packages and versions selected for use as dependencies. [How Renovate works](https://docs.renovatebot.com/key-concepts/how-renovate-works/)

| Area | Renovate | Dependabot |
| --- | --- | --- |
| Duplicate and closed PRs | Uses branch names and other identifiers to find existing PRs and generally does not recreate the same update after its PR is closed | Uses branch names and other identifiers to prevent duplicates, and stopping a specific update is requested with a comment command on the PR |
| Package manager execution | Runs with the same permissions as Renovate itself | Runs in a disposable environment without GitHub write permissions and restricts network destinations |
| Container images | Handles Docker and Compose tag updates, but does not create PRs triggered by vulnerabilities in container images | Handles Docker and Compose tag updates, but does not create PRs triggered by vulnerabilities in container images |

PR handling and execution permissions are also described in [Renovate's PR documentation](https://docs.renovatebot.com/key-concepts/pull-requests/), [Renovate's permissions documentation](https://docs.renovatebot.com/security-and-permissions/), and [Dependabot's network restriction documentation](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/resolve-a-blocked-host).

- **Updates to indirectly installed dependencies have limits**
    - When installing one package also installs another package it requires, the latter is a transitive dependency
    - Both tools generally limit these updates to lockfile changes within the declared dependency constraints, with parent package upgrades supported only by Dependabot for npm
- **Regenerating a lockfile can execute third-party code**
    - Operations that appear to update only a list of versions can execute code, for example when building a Python source distribution

The limitations on parent package upgrades are documented in [Dependabot security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates).

## Decisions

### Scope and enablement

| Area | Scope or handling |
| --- | --- |
| Runtime environment | Docker Compose |
| Change destination | GitHub, accessed with a token restricted to selected repositories |
| Package sources | Public container images and public npm and PyPI packages |
| Dockerfile base images | Public base images used by images users build themselves |
| Language packages | npm and pnpm for Node.js; pip and uv for Python |
| Remediation plan notifications | Enabled as a read-only capability |
| PR creation | Explicitly enabled as a separate capability that performs writes |

### Candidates for distributed images

References such as `postgres:16` and `latest` can point to new content while retaining the same tag. Candidate selection differs between these references and references that specify a full version, such as `nginx:1.25.3`.

| Reference | Candidate | Notification or PR |
| --- | --- | --- |
| `postgres:16`, `latest`, and similar tags | New content under the same tag | Rescan and notify users of findings that would be fixed by pulling again, without creating a PR because no file changes |
| `nginx:1.25.3` and similar version tags | The latest patch within the same major and minor version, with the same suffix | Create a PR that changes the tag |

### Dockerfile base images

Images in personal projects are often built from local Dockerfiles through Compose `build:`, so Compose tag updates do not cover them. Language package updates cannot fix findings in base image layers, so the minimal release includes Dockerfile base image updates.

When a Compose mapping exists, use `build:` to locate the Dockerfile and the build target stage without additional configuration. Use the stage specified by `target`, or the last stage when it is omitted. If `FROM` refers to an earlier stage, follow it to the `FROM` that references a public base image and update only its tag.

| Reference | Candidate | Notification or PR |
| --- | --- | --- |
| Tags specifying a full version, such as `python:3.12.3-slim` | The latest patch within the same major and minor version, with the same suffix | Create a PR that changes the `FROM` tag |
| Tags whose content can change, such as `python:3.12-slim` | Do not create an update candidate | Do not create a PR or compare finding counts; only provide instructions to fetch the latest base and rebuild, such as `docker compose build --pull`, without claiming that improvement has been verified |

Only treat the running image as built from a base for comparison when its initial layers match the base image's layers. Use the layer Trivy reports for each finding to identify findings in the verified base layers as candidates originating from the base. Exclude findings in later layers and findings without a reported layer.

### Language packages and source mapping

Users specify the repository and files in configuration, and KestreLynx matches names and versions against scan results. Matches are treated as candidate change locations; a matching name and version alone does not establish the build source. Multiple possible matches require manual action.

| Target | Handling |
| --- | --- |
| Transitive dependencies | Limit changes to lockfile updates within the declared dependency constraints |
| Transitive dependencies that cannot be fixed within those constraints | Notify users that manual action is required |
| pip entries pinned with `==` | Include version changes in PRs |
| pip entries specifying a version range | Notify users that rebuilding is expected to fix the finding |
| Dependencies requiring third-party code execution, such as source distribution builds or dependencies pointing to local folders or Git repositories | Require manual action |

- **Select update lower bounds and edit direct dependency constraints**
    - Use running-image findings with scan status `fixed` and reported fixed versions, taking the lowest reported fix newer than the installed version for each finding and then the highest of those versions as the package's update lower bound
    - Exclude findings without fixed-version information from selection, which does not itself verify resolution
    - With PRs enabled, separately inspect the updated dependency files and compare before/after scans to check that the targeted vulnerabilities are no longer detected
    - Warn in the PR body and notifications when an update requires a different major version
    - When a direct dependency's manifest constraint excludes the fixed version, have KestreLynx edit only the version portion while preserving the operator
    - Support `1.2.3`, `=1.2.3`, `^1.2.3`, and `~1.2.3` for npm and pnpm, and `==` and `~=` for uv, requiring manual action for other forms that need editing
- **Apply package manager constraints**
    - Update pnpm transitive dependencies without specifying a version and inspect the selected version, because pnpm 11 and later reject version-qualified updates to transitive dependencies
    - Require manual action when an update creates undeclared files, including the configuration file pnpm adds when installing a version published within the last 24 hours
    - Require manual action for uv projects whose `requires-python` excludes Python 3.13, because uv needs a compatible Python interpreter and the job image contains only Python 3.13
    - Limit `uv.lock` support to revision 5, which does not require a format rewrite
    - Check pip dependency resolution using the running image's Python version and wheel tags derived from its OS and CPU architecture
    - Require manual action for dependencies beneath packages that bundle dependencies through `bundleDependencies` or include shrinkwrap files, because the versions actually installed cannot be verified
- **Avoid repeating updates and limit job execution**
    - When a unit has the same inputs, including dependency file contents and update targets, as an open PR, associate it with that PR without rerunning the update or consuming the update job allowance
    - Set the maximum dependency update units attempted per cycle with `remediation.limits.dependency_jobs_per_cycle`, which defaults to 3 and counts units rather than packages or containers, with multiple containers per unit possible for pip or manifest edits
    - Set the deadline for each container's creation, execution, and result collection with `remediation.limits.job_timeout`, which defaults to 6 minutes and accepts values from 1 minute to 60 minutes 30 seconds, with a separate 30-second deadline for cleanup

### Comparison and verification

Compare the original and candidate under the same conditions, using the same scanner and identical vulnerability database content.

| Evidence | Handling |
| --- | --- |
| Both scans succeed and their conditions allow comparison | Show findings that disappear, remain, or newly appear |
| Either scan fails or the conditions cannot be matched | Mark the results as incomparable without treating findings as resolved |
| A fix is expected from source changes | Present this separately from a confirmed fix in the production image |

PRs for distributed images include the image rescan comparison. Dockerfile base image PRs include results from rescanning the current and candidate bases under the same conditions, labeled as a “comparison of base images only.” Do not treat Trivy's layer attribution as proof of origin, and explicitly state that the rebuilt final image has not been verified. Language package PRs present the source comparison and the expected effect on the image, without claiming that resolution in production has been verified.

### Execution environment for updates

- **Run package managers in disposable containers**
    - KestreLynx creates a container through the Docker API for each job and removes it afterward
    - Do not pass tokens, the main application's configuration, or the Docker socket to the job container
- **Restrict permissions and execution**
    - Run as a non-root user with a read-only root filesystem and limits on time and resources
    - Inspect output before committing it

This capability introduces the creation of job containers by KestreLynx through the Docker API.

The current implementation leaves the root filesystem writable in Docker's configuration, while ownership and permissions in the distributed work image prevent the non-root job from writing anywhere in the image's writable layer. Images supplied through `remediation.worker.image` must preserve the same ownership and permission restrictions; reference and digest checks do not inspect all image file permissions at runtime. Docker rejects file transfers into containers with a read-only root filesystem, even when the destination is a tmpfs path, as confirmed with Docker 29.1.3. Allowing results to be written to the image's writable layer would leave the amount written without an enforceable limit.

- **Fix the tools and restrict writes**
    - Use a dedicated image referenced by digest, with Node.js 24.21.0, npm 11.19.0, pnpm 12.10.1, Python 3.13.16, pip 26.2.1, and uv 0.13.0
    - Place inputs before startup in a root-owned working directory that is read-only to the job, and use the distributed work image's ownership and permissions to restrict non-root job writes to tmpfs mounts with capacity limits
    - Run package managers with scripts disabled, without passing tokens, the main application's configuration, or the Docker socket
    - Accept only image references containing a digest for `remediation.worker.image`
- **Collect results through standard output**
    - Have the job write results to standard output, read them from the container logs after it exits, and attempt removal before inspecting the collected results in KestreLynx
    - Record removal failures and retry during later cleanup, allowing inspection to continue when results were collected
- **Treat job output as untrusted and inspect it in KestreLynx**
    - Check changed dependencies against the distribution URLs and integrity or SHA-256 values published by the public npm and PyPI registries
    - Check that every occurrence of each update target is at or above its fixed version
    - Check that manifests are unchanged outside the portions edited by KestreLynx and that dependency changes can be explained by the update targets
    - Scan dependency files before and after the update with Trivy's fs scan using the same vulnerability database, and confirm that the targeted vulnerabilities disappear
    - Limit output size and processing work
- **Describe the checks, limits, and their coverage**
    - Reject version and distribution mismatches with registry metadata that can be detected in supported formats
    - Limit work-container resources, input and output sizes, and processing work in the main application
    - Reject failed work-container jobs, partial output, and contradictions between step results and overall job status as successful update results
    - Check as far as possible that dependency combinations fully match registry declarations and that installers accept the output format, without guaranteeing either
    - Record these limits under `Not verified` in the PR body and leave the final check to the user's CI installing from the lockfile

### Creating and replacing PRs

| Area | Handling |
| --- | --- |
| Creation method | Create commits and PRs through the GitHub API without cloning the repository |
| Existing branches | Never overwrite them |
| New candidates | Open new PRs |
| Older PRs | Close only when the new PR covers all their remediation targets |
| Multiple locations in the same file | Combine them into one PR |
| Merging and deployment to production | Do not perform them automatically |

### Changes after implementation

Remediation plans and PRs draw on some ideas from the [Remediation Relations Model](remediation-relations-model.md), without directly implementing its types.

#### Execution environment for updates

- Use official images and fetch the required tools
    - Replace the dedicated image with official Node and Python images pinned by digest, supplying KestreLynx's job program to each container
    - Have KestreLynx fetch and verify the project-specified versions of npm, pnpm, and uv, and check them again when reusing cached copies
    - Require manual action for conflicting or unsupported version declarations, or declarations that allow only runtime versions that have reached end of support
- Restrict where update jobs can write
    - Replace the dedicated image's permission settings with confinement to temporary storage with capacity limits, and check these restrictions at runtime

#### Language package update methods and scope

- Regenerate lockfiles with package-manager-specific handling
    - For npm and pnpm, remove entries for the update targets before regenerating the lockfile, requiring manual action for pnpm 12 because it does not support this approach
    - For uv, specify a target version for each package being updated
    - Allow accompanying changes to dependencies and annotations when the checks can account for them, and show those changes in the PR body
- Support pnpm projects whose configuration files contain only supported settings
    - For pnpm 10 and later, include projects with a `pnpm-workspace.yaml` containing only settings such as packages allowed to build or supported CPU architectures
    - Continue to require manual action for workspace definitions that group multiple packages or for unsupported settings
- Allow partial PRs for language package updates
    - For npm, pnpm, and uv, create PRs containing only updates that pass verification, excluding packages that cannot reach a fixed version because of dependency constraints or other restrictions
    - Report excluded packages as requiring manual action, and do not split pip updates into partial PRs

#### Finding image candidates

- Support authentication to private image registries, lifting the restriction to public images
- Retrieve tags more efficiently by limiting requests to the target version series, without selecting candidates from incomplete tag lists
- Exclude locally built running images before querying registries, and do not guess a registry to search when the image's origin cannot be determined

#### Slack notifications

- Send remediation plans as separate messages from vulnerability notifications, including packages excluded from partial PRs and details of required manual action

#### PR body content and Japanese support

- Focus language package PR bodies on execution and inspection results and instructions for checking the update in the user's CI, removing the `Not verified` and rationale sections
- Show the comparison of base images only and the limits of layer attribution in Dockerfile PRs, removing the explicit statement that the final image has not been verified
- Apply the notification language setting to PR bodies so they can also be displayed in Japanese

## Verification results

Language package update PRs for npm, pnpm, uv, and pip are implemented, completing the minimal release scope alongside Compose tag and Dockerfile base image updates.

### Compose tag updates

- Verified Compose tag PRs in a GitHub repository used for validation
    - PRs change only the targeted tag lines
    - Repeated runs do not create duplicate PRs
    - Updates from closed PRs are not recreated, even after their branches are deleted
    - Branches modified by users are left untouched
    - Lost local records are reconstructed from markers in PR bodies
    - With read-only permissions, writes fail, leave nothing behind, and trigger a notification

### Language package updates with the previous job image

- Verified language package PRs in a GitHub repository used for validation
    - Created four PRs covering the following updates
        - npm and pnpm each updated the transitive dependency minimist from 1.2.5 to 1.2.8
        - pip updated urllib3 from 1.26.4 to 2.8.0 with hashes for verifying distributions
        - uv updated urllib3 from `==1.26.4` to `==2.8.0`, including a manifest edit
    - Repeated runs created no duplicate PRs and ran no update jobs when the source files and update targets were unchanged
    - Job containers were excluded from scan targets and removed after every run
- Verified updates with dependency sets comparable in size to those in real projects
    - Of eight updates to old transitive dependencies in dependency sets using express and axios, vite, fastapi and httpx, and requests, seven became PR candidates
    - The remaining update required manual action because uv itself could not resolve the dependencies
    - No valid output was rejected by the checks in these cases
- Verified arm64 execution under emulation
    - Built the arm64 job image using QEMU to emulate another CPU architecture on x86_64 and confirmed the same update results for all four package managers

### Verification with official images and fetched tools

- Verified the current approach in a project in active use
    - Using the backend and frontend dependency files, verified the process from fetching the declared pnpm 10.34.4 through updating with the official `node:24` image, checking the output, and rescanning the source
    - Verified updates for a project with a settings-only `pnpm-workspace.yaml` and partial updates that excluded packages unable to reach a fixed version
    - Confirmed that remediation PRs were created and merged in production use

The results for all four package managers and QEMU with the previous job image do not establish equivalent verification coverage for the current approach.

### Runtime selection based on project declarations

- **Select Node.js for npm and pnpm from project declarations**
    - Read `.nvmrc`, `.node-version`, `engines.node`, `devEngines.runtime`, and `engines.runtime`, and select a job image that also satisfies the package manager's requirements
    - Prefer the series specified by a version file when present, the oldest supported series satisfying the constraints when only ranges are declared, or the latest series currently in LTS when no version is declared
    - Check whether the `engines.node` constraints of added or changed dependencies allow the lowest Node.js version permitted by the project's declarations, requiring manual action if they do not
- **Align uv and pip operations with the Python version declared by the project or used in the running image**
    - For uv, select the oldest supported Python series satisfying `.python-version` and `requires-python`
    - For pip, check dependency resolution against the running image's Python version, requiring manual action for Python 3.10 and earlier
- **Cover all supported series in the bundled table**
    - Currently include Node.js 22, 24, and 26 and Python 3.11–3.15, requiring manual action for updates on series that have reached end of support
    - Add new series to the table only after integration tests pass for those series
- **Verified in a project in active use on October 14, 2026**
    - At startup, loaded Node.js 22, 24, and 26 and Python 3.11–3.15 as supported series for job images
    - For a backend without a Node.js version declaration, selected the default Node.js 24 (LTS) and ran the update with the declared pnpm 10.34.4
    - Confirmed in actual use that multiple supported series were loaded and that, without a runtime declaration, the latest LTS was selected and the update ran with the specified package manager

## Unverified areas and next steps

- Verify execution environments and limits
    - Updates in actual projects remain unverified for Node.js series other than 24 and for each supported Python series
    - Execution on physical arm64 hardware and rootless Docker, which runs Docker itself without administrator privileges, remain unverified with the current approach
    - Measurements supporting the default limits on update counts, execution time, and similar constraints remain unverified
    - The glibc version mapping used to determine pip's target environment needs to be checked against measurements beyond Debian 12 x86_64, where glibc is a core Linux library
- Track remediation results
    - Pick up images built by a PR's CI and rescan them to verify the results
    - Confirming resolution by rescanning the final image built and deployed after merging remains separate work from verifying PR creation and merging
- Verify the workflow that updates the official image digest table
    - Verify the workflow that creates update PRs weekly or on manual request, from execution in actual use through merging the update PR
    - Confirm that it proposes updates only after checks of image versions, configuration, and writable locations, vulnerability scans, and update job tests have passed
- Expand the supported change targets
    - Add Kubernetes definition files and automatic source identification in turn, guided by user feedback
    - Defer emergency patching that generates patched images

## Update history

### October 15, 2026

- Documented Node.js and Python runtime selection and supported series.
- Recorded verification results in actual use and the remaining unverified scope.

### October 13, 2026

- Switched to official images and fetched tools.
- Updated partial PR handling, PR body content, and remediation plan notifications.
- Separated verification results from next steps.

### October 11, 2026

- Language package update PR implementation and validation results

### October 10, 2026

- Updated implementation and validation status

### October 9, 2026

- Recorded investigation and design
- Dockerfile base image update policy

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
