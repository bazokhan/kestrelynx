# docker run remediation pull request development

- **Status:** Implemented (local verification only).
- **Started:** October 27, 2026
- **Last updated:** October 27, 2026

## Purpose

The aim is to include containers started with `docker run` without Compose in remediation PRs that update Dockerfile base images and language package lockfiles.
Since there is no file containing the startup command, KestreLynx does not create PRs to change the image tag used at startup.

## Approach

- Users explicitly specify change locations through configuration mappings
- KestreLynx trusts the mappings and does not verify that the container was built from the specified repository
- KestreLynx verifies that the running and scanned images have the same content, and checks Dockerfile base layers and package names and versions in lockfiles
- One instance across multiple hosts is responsible for creating PRs for the same change location

## Decisions

- **Mappings by container name**
    - The workload key is `container/<name>`, using the name assigned with `docker run --name` and shown in the `NAMES` column of `docker ps`
    - Base image updates use `dockerfile`, and language package updates use `dependencies`; configuring both requires separate entries
    - Configuration instructions are provided in [Mapping docker run containers](../documentation/remediation-setup.md#docker-run-mappings)

- **Rejection of mappings by image name**
    - Public images such as `nginx` are used in multiple places, so identifying the change location would still require specifying a container; mappings by image name were therefore rejected
    - Keeping configuration easy to write and read takes priority over adding syntax and precedence rules

- **Trust in configuration and the PR body notice**
    - KestreLynx trusts the configuration mappings and does not verify that the container was built from the specified repository
    - Matching base layers or package names and versions does not prove where a container was built; reusing a name may cause PRs to be created in a different repository
    - The PR body includes a notice that the association with the change location is based on configuration and has not been verified by KestreLynx
    - If the body length limit prevents the notice from being retained, no PR is created

- **Guidance for mappings using Compose container names**
    - If a Compose container name is specified as `container/<name>`, KestreLynx does not match it and logs a warning showing the correct `compose/<project>/<service>` key
    - The warning is not repeated while the condition remains unchanged, but is issued again when, for example, the suggested key changes

- **PR creation across multiple hosts**
    - Duplicate prevention is local to each host, so one instance is responsible for creating PRs for the same Dockerfile or lockfile in the same repository
    - On other hosts, omit that mapping or disable PR creation and use plans only

## Verification method

### Environment

| Environment | Docker version | Image store |
| --- | --- | --- |
| Local Docker on WSL | 29.1.3 | containerd |
| Local Docker-in-Docker (dind) | 29.9.1 | Classic overlay2 |

- **Integration tests**
    - Used real Docker, Trivy, and Docker Hub with a simulated GitHub service in both environments
    - Tested three Dockerfile scenarios while keeping the container running: leaving the tag unchanged, using `docker tag` to reassign the tag to another image, and rebuilding with the same tag
    - In each scenario, checked consistency among the running image, scan target, and scan results, base layer matching, and the workflow from remediation planning through PR creation
    - Verified the npm update of `minimist` from 1.2.5 to 1.2.8 and PR creation
    - Verified that the cycle after Dockerfile PR creation performed no writes

- **Unit tests**
    - Verified configuration validation, warnings for mappings using Compose container names, the PR body notice and length limit, and detection of updates already covered by existing PRs
    - Unit tests passed for all packages, including existing tests

- **Scope of GitHub verification**
    - This verification did not include PR creation on real GitHub
    - PR creation uses the same mechanism as existing Compose Dockerfile PRs
    - The added PR body notice was verified through integration tests with simulated GitHub and through unit tests

## Verification results

PR creation in the tables below refers to results verified with simulated GitHub.

The following scenarios produced the same results with both image stores.

| Scenario | Result |
| --- | --- |
| Unchanged tag | Scanning and base layer matching succeeded, and a Dockerfile PR was created |
| Tag reassignment with `docker tag` | The image used by the existing container could still be scanned, and a Dockerfile PR was created |
| npm update | The update succeeded, and a PR updating `minimist` to 1.2.8 was created |
| Next cycle after Dockerfile PR creation | No additional writes |

### Differences after a rebuild with the same tag

When the image was rebuilt with the same tag while the existing container continued running, results differed by image store.

| Image store | Result |
| --- | --- |
| containerd | The old image disappeared and scanning failed; neither plan items nor PRs were created for the existing container |
| Classic overlay2 | The old image remained, scanning and matching succeeded, and a Dockerfile PR was created |

If the old image disappears with containerd, the container must be recreated using the new image.

## Unverified areas and next steps

### Verification in real environments

- Verification that recreating a container with the same name does not cause duplicate PRs for the same update
- Verification that renaming a container results in neither new PRs from the mapping for the old name nor closure of existing PRs
- Verification in real environments of Dockerfile sharing with Compose, rebuild guidance, and warnings for incorrectly specified container names, all of which have been covered by unit tests
- Verification with other Docker versions, rootless Docker, and arm64

### Usability improvements

The following improvements remain under consideration, with no implementation schedule set.

- A list of mapping keys for each observed container, allowing users to copy the displayed keys into configuration
- Support for combining multiple change locations, such as a Dockerfile and dependency directory for the same container, in a single mapping entry

## Update history

### October 27, 2026

- Added support for Dockerfile and lockfile remediation PRs for docker run containers.
- Documented mappings by container name and the extent of trust in configuration.
- Documented the PR body notice, guidance on Compose keys, and operating practices across multiple hosts.
- Recorded integration test results for two image stores and the unverified scope.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
