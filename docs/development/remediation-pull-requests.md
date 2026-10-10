# Remediation plan and pull request development

- **Status:** Implementation in progress.
- **Started:** October 8, 2026
- **Last updated:** October 10, 2026

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

### Creating and replacing PRs

| Area | Handling |
| --- | --- |
| Creation method | Create commits and PRs through the GitHub API without cloning the repository |
| Existing branches | Never overwrite them |
| New candidates | Open new PRs |
| Older PRs | Close only when the new PR covers all their remediation targets |
| Multiple locations in the same file | Combine them into one PR |
| Merging and deployment to production | Do not perform them automatically |

## Unverified areas and next steps

Read-only remediation plans now include candidate selection, rescan comparisons, and notifications for both distributed images and language packages. Compose tag PR creation is also implemented, with the following verified in a GitHub repository used for validation.

- PRs change only the targeted tag lines
- Repeated runs do not create duplicate PRs
- Updates from closed PRs are not recreated, even after their branches are deleted
- Branches modified by users are left untouched
- Lost local records are reconstructed from markers in PR bodies
- With read-only permissions, writes fail, leave nothing behind, and trigger a notification

Next, implement Dockerfile base image PRs, followed by language package PRs.

- **Add tracking of remediation results**
    - Pick up images built by a PR's CI and rescan them to verify the results
- **Expand the supported change targets**
    - Add Kubernetes definition files and automatic source identification after the minimal release, in turn and guided by user feedback
    - Defer emergency patching that generates patched images

## Update history

### October 10, 2026

- Updated implementation and validation status

### October 9, 2026

- Recorded investigation and design
- Dockerfile base image update policy

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
