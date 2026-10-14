# How candidates and pull requests are decided

This page explains how KestreLynx selects update candidates, checks update results, and manages fix pull requests.
See [Supported input formats](remediation-reference.md#supported-inputs) for input requirements and [Reason codes](remediation-reference.md#reason-codes) for the codes attached to decisions.

## Processing flow {#processing-flow}

### Plan and PR execution scope {#plan-and-pr-execution}

Creating a remediation plan and creating fix pull requests involve different operations.

| Execution scope | What KestreLynx does |
| --- | --- |
| Remediation plans only | Selects candidates from running-image findings, reads mapped sources, and compares scan results for image candidates. |
| Fix pull requests enabled | Performs planning, runs language package updates and checks in work containers, and creates and manages PRs for changes that meet the requirements. |

- Planning alone does not run package managers, create work containers, or write to GitHub
- Planning alone still saves plan and delivery records locally
- Enabling fix pull requests does not merge PRs, build application images, or deploy changes

See [Enablement settings](configuration.md#remediation-enablement) for configuration.
[Notification conditions](how-it-works.md#notification-conditions) explains when notifications are sent.

### Source verification {#source-verification}

KestreLynx resolves the mapped branch to a commit before reading its source.
For language package updates, it rechecks the file contents and version declarations recorded in the plan.

- Language packages are checked by matching names and versions detected in the running image against dependency-file records
- If the base branch has advanced when a PR is created, the files used for the update and the relevant settings files are checked again
- If source changes no longer match the planning inputs, writes for that update are deferred

!!! note "Verification limits"

    Source mappings and matching package names and versions do not prove that the running image was built from that source.

See [Source mappings](configuration.md#remediation-mappings) for the mapping configuration.

## Image candidate selection {#image-selection}

### Distributed image tags {#published-image-tags}

The running image reference determines which candidate to compare.

| Tag type | Candidate selection | Treatment after adoption |
| --- | --- | --- |
| Pinned tag specifying a full version | Selects the newest patch above the current version in the same major, minor, prefix, and suffix series. | Becomes a candidate for a PR that changes the Compose tag if source-editing requirements are also met. |
| Floating tag | Selects the content the same tag currently points to in the registry. | Produces re-pull guidance if an improvement is confirmed, without a PR because the reference does not change. |

- A candidate with the same image content as the running image is not an update candidate
- If the candidate and running-image identities cannot be verified, the comparison is not used to establish improvement
- The candidate tag is checked again before PR creation, and processing is deferred if it points to different content than during the comparison

Candidate adoption follows [Scan comparison conditions](#comparison-conditions) and [Verification scope by target](#verification-scope).
See [Compose formats](remediation-reference.md#compose-formats) for editable references and unsupported forms.

### Tag discovery {#tag-discovery}

The latest patch for a pinned tag is selected only after the end of its series has been checked.
If the registry supports listing from a specified starting position, the search begins near the target series.

- Listing the entire repository is skipped if tag ordering and the end of the target series can be verified
- If tag ordering or pagination cannot be trusted, KestreLynx attempts a full listing within the remaining request budget
- Requests used to search the series also count toward the tag-listing limit

| Search result | Decision |
| --- | --- |
| The entire series was checked and a newer patch exists | Selects the latest patch in the same series. |
| The entire series was checked and no newer patch exists | Reports no candidate. |
| A limit, deadline, or other condition interrupted retrieval | Defers processing without treating the highest version retrieved as the latest patch. |

See [Processing limits](configuration.md#remediation-limits) for retrieval and time settings.

### Excluding local builds {#local-builds}

If a mapped Compose service has `build:`, its completed image is excluded from distributed-image tag searches.
An accompanying `image:` does not change this decision.

In addition to the Compose definition, the following information can identify a local build.

- The image and container have matching Compose project and service values, and the image name matches the name Compose generates
- The image reference has no registry host, and the scan did not obtain a registry digest

Identification based on Compose labels and generated names is not used when the mapped service is confirmed to have no `build:`.

- If the mapped Compose file cannot be read and other information does not establish a local build, KestreLynx does not proceed with a tag search based on a guess
- Base images are examined separately as Dockerfile updates

### Base image selection {#base-image-selection}

For a Dockerfile, KestreLynx identifies the external image inherited by the selected build stage as the base to update.

- Uses the specified `target` stage, or the last stage if `target` is omitted
- Follows inheritance through earlier stages until it reaches a `FROM` that references an external image
- Uses the context, Dockerfile, and target from Compose `build:` when they identify the edit location
- Checks consistency when both a Dockerfile mapping and an edit location derived from Compose are used

| Base tag | Processing |
| --- | --- |
| Pinned tag | Compares the latest patch with the same major, minor, prefix, and suffix, and creates a candidate to change the corresponding `FROM` tag. |
| Floating tag | Matches the base currently referenced by the tag against the running image's layers, without creating a tag-update PR or comparing before/after vulnerability counts. |

See [Dockerfile formats](remediation-reference.md#dockerfile-formats) for the inputs that allow an edit location to be identified from Dockerfile or Compose.

### Base layer matching {#base-layer-matching}

KestreLynx checks that the current base image's layer sequence matches the start of the running image's layer sequence, including the order.

| Match result | Processing |
| --- | --- |
| Match | For pinned tags, proceeds to select findings attributable to the base and compare the candidate. |
| Mismatch | Does not treat the base comparison as representative of the running image. |
| Empty or unavailable layer information | Treats the images as not comparable. |
| Match for a floating tag | Determines that no update can be confirmed from the base currently referenced by the tag. |

Base remediation targets are findings that Trivy reports as belonging to the matched base layers.

- Findings in later layers are excluded from base remediation targets
- Findings without layer information, or with a layer ID appearing both inside and outside the base, are not attributed to the base
- If floating-tag content does not match the start of the running image's layers, it is not adopted as a candidate with confirmed improvement

!!! note "Layer matching and build provenance"

    A match establishes correspondence between filesystem layers. Trivy may still attribute a package to a base layer even if a later instruction reinstalls the same name and version.

See [Rebuild guidance](remediation-results.md#rebuild-guidance) for interpreting guidance about floating-tag bases.

## Language package candidate selection {#package-selection}

### Fixed-version lower bound {#fix-lower-bound}

KestreLynx derives the update target's lower bound from findings with scan status `fixed` and reported fixed versions.
It uses each finding's fixed-version information without replacing it with separate information aggregated by package.

| Decision unit | Lower-bound calculation |
| --- | --- |
| Each vulnerability | Selects the lowest reported fixed version above the running version. |
| A running version of the same package | Uses the highest version selected across its vulnerabilities as the update target's lower bound. |

- Uninterpretable running or reported fixed versions require manual handling
- A vulnerability with no reported fixed version above the running version does not produce an update candidate
- When grouping multiple running versions of the same package, KestreLynx checks that they can share an update target and that other occurrences will also reach at least that target

After the update, KestreLynx checks both the lower bound and whether every occurrence satisfies the fixed-version conditions for each targeted vulnerability.
For regular releases, it applies the following conditions in order.

| Relationship to reported fixed versions | Requirement for the adopted version |
| --- | --- |
| A fixed version exists in the same major and minor series | Must be at least the highest reported fixed version in that series |
| No fixed version exists in the same major and minor series, but one exists in the same major series | Must be at least every reported fixed version in the same major series |
| No fixed version exists in the same major series | Must be at least every reported fixed version |

For major version `0`, minor series are used in place of major-series groupings.
A prerelease satisfies the fixed-version conditions only if that exact version is reported as fixed.

Reaching the lower bound alone is insufficient; the checks in [Adopting update results](#update-method-and-partial-pull-requests) also apply.

### Direct dependency version specifications {#direct-dependencies}

If a direct dependency's version specification excludes the update target, KestreLynx edits the version portion while preserving the operator, but only for supported forms.

- An existing version specification that allows the update target is preserved
- Required edits to unsupported specification forms or locations require manual handling
- After the update, KestreLynx checks that the manifest and lockfile specifications agree and that the adopted version is within the specified range

See the dependency-file sections for [npm](remediation-reference.md#npm-inputs), [pnpm](remediation-reference.md#pnpm-inputs), and [uv](remediation-reference.md#uv-inputs) for editable specifications and locations.

### Transitive dependency update scope {#transitive-dependencies}

Transitive dependencies are updated within the ranges declared by their parent packages.
Updated versions are checked against parent-package declarations returned by the public registry.

- Parent packages outside the update targets are not upgraded to obtain a fixed version
- Overrides are not added to force a fixed version
- Changes to targets and related dependencies are checked for violations of version requirements between dependent packages and their dependencies

[Partial PR conditions](#partial-pr-selection) explains what happens when a declared range prevents reaching the lower bound.

## Runtime selection {#runtime-and-tool-versions}

Supported runtimes are the supported series in the bundled table, currently Node.js 22, 24, and 26 and Python 3.11–3.15.
See [Supported runtimes](remediation-reference.md#supported-runtimes) for execution versions and support end dates.

### Node.js selection {#node-selection}

For npm and pnpm, KestreLynx combines project version declarations with package manager requirements to select Node.js.

| Declarations | Selection rule |
| --- | --- |
| A version file exists | Uses the specified major series, with the actual minor and patch version selected from the bundled table. |
| Only ranges are specified | Selects the oldest supported series satisfying all ranges and package manager requirements. |
| No declarations | Prefers the newest series that has entered LTS, then checks compatible combinations in other series from newest to oldest. |
| Both a version file and ranges exist | Checks that the declarations agree and that the execution version in the specified series satisfies every range. |

- Series past their support end date are not used for updates
- Conflicting declarations or the absence of a suitable execution version require manual handling
- A failed update is not retried with a different Node.js series after selection

See [Node.js version declarations](remediation-reference.md#node-declarations) for the declarations and formats read.

### Node.js compatibility requirements {#node-compatibility}

KestreLynx uses only combinations of Node.js and npm or pnpm that satisfy both sets of requirements.

- Checks that the package manager version satisfies the project's declared versions and ranges
- Checks that the package manager's own `engines.node` allows the Node.js version used for the update
- Also checks Node.js requirements in the metadata retrieved when fetching the tool

If the minimum Node.js version derived from project declarations differs from the version used for the update, KestreLynx also checks added and changed dependencies' `engines.node` against that minimum.

- Dependencies that exclude the minimum version or have uninterpretable requirements require manual handling
- Without a Node.js declaration, no minimum version is set for this check

This compares version declarations; it does not test the application on the minimum Node.js version.

### Python selection for uv {#uv-python-selection}

For uv, KestreLynx selects the Python version used to generate the lockfile from `requires-python` and version files.

| Declarations | Selection rule |
| --- | --- |
| Only `requires-python` exists | Selects the oldest supported series whose execution version satisfies the range. |
| Both a version file and `requires-python` exist | Selects the Python X.Y series from the version file and checks declaration consistency and execution-version compatibility. |
| No `requires-python` | Requires manual handling regardless of whether a version file exists. |

- The patch version in the version file may differ from the work image's patch version
- The actual Python version in the bundled table must satisfy `requires-python`
- If no supported series satisfies the requirements, declarations are not relaxed to run the update

See [Python version declarations](remediation-reference.md#python-declarations) for supported declaration formats.

### pip verification environment {#pip-target-environment}

The Python version that runs pip and the target environment for dependency-resolution verification are selected separately.
The work container uses the default Python environment in the bundled table, while verification targets the Python X.Y, platform, and ABI inferred from the running image.

- Python X.Y is inferred from information such as package paths in the scan
- An undetermined Python version or platform requires manual handling
- Conflicting verification environments among images in the same update require manual handling
- No update PR is created if the target Python version is past its support end date, even if the Python version used for the work container is still supported

See [Supported runtimes](remediation-reference.md#supported-runtimes) for work-container execution versions.

### Tool version selection {#tool-version-selection}

Project declarations take priority when selecting npm, pnpm, and uv versions.

| Declarations | Selection rule |
| --- | --- |
| Exact version | Uses that version if supported and consistent with the other declarations. |
| Ranges only | Uses the default version for the selected runtime if it satisfies every range. |
| No declarations | Uses the default version defined by KestreLynx. |
| Conflicting declarations or a default outside the range | Requires manual handling without automatically searching for another tool version within the range. |

For pip, KestreLynx uses the version included in the official Python work image.
Package managers are prevented from switching tool versions themselves.

See [Tool version declarations](remediation-reference.md#tool-declarations) for the declarations read and [Supported runtimes](remediation-reference.md#supported-runtimes) for default execution versions.

## Work container execution {#worker-execution}

### Pinning official images {#worker-images}

Language package updates use official Node.js and Python images.
Their content is pinned by digest in the bundled table and does not follow changes to the same tag.

- Docker retrieves the required images
- Mirrors must provide content with the same digest as the bundled table
- Language package updates are deferred if the image cannot be retrieved
- Retrieval failures do not cause package managers to run inside the KestreLynx container as a fallback

Pinned content and supported series change with KestreLynx updates.
See [Work image registry](configuration.md#remediation-worker-registry) for configuring the retrieval source.

### Tool retrieval and verification {#tool-verification}

KestreLynx retrieves the selected npm, pnpm, or uv version and passes the verified distribution to the work container.

| Check target | Requirements |
| --- | --- |
| Distribution metadata | Must match the requested tool and version and identify the distribution's download location and hash |
| Distribution | Retrieved content must match the registry hash, with a supported archive structure and executable |
| Project hash declaration | If declared, the distribution covered by that declaration must also match its value |
| Files passed to the container | Must match the recorded sizes and hashes |

Hash mismatches and inconsistent distributions are not ignored to proceed with execution.
See [Outbound communication](how-it-works.md#outbound-communication) for destinations and credential transmission.

### Waiting after tool release {#tool-release-age}

npm, pnpm, and uv are used only after the configured waiting period has elapsed since publication.

- Versions that have not reached the waiting period are deferred until eligible
- Versions whose publication time cannot be confirmed are also deferred
- A different tool version is not substituted during the waiting period

This check applies to the tools themselves and is separate from package manager release-age restrictions on dependencies.
See [Tool release waiting period](configuration.md#remediation-tool-release-age) for the time setting.

### Tool cache reuse {#tool-cache}

Previously retrieved tools are checked again for content integrity and eligibility before reuse.

- Files are reread and hashed to confirm that they match the recorded content
- Project hash declarations, release waiting periods, and Node.js requirements are checked again
- Cached content that cannot be verified is not used as-is for execution
- Processing is deferred if removing unused cache entries cannot free enough space

See [Tool cache capacity](configuration.md#remediation-tool-cache) for capacity settings and [Stored files](remediation-reference.md#stored-records) for stored content.

### Container inputs {#worker-inputs}

Files needed for the update, the bundled work program, and retrieved and verified tools are placed in the container before it starts.

| Input type | Treatment |
| --- | --- |
| Dependency files and corresponding settings files | Passed as needed for the update. |
| Work program and tools | Verified before being passed to the container. |
| GitHub token and image registry credentials | Not passed. |
| KestreLynx configuration file and Docker socket | Not passed. |

See [Credential destinations](how-it-works.md#credential-destinations) for where credentials are sent.

### Execution restrictions {#worker-restrictions}

Work containers have restrictions on privileges, resources, writable locations, and execution.

- Run as non-root with all Linux capabilities dropped and `no-new-privileges` enabled
- Limit memory, CPU, process count, output size, and execution time
- Restrict writable locations to capacity-limited temporary storage
- Disable package scripts and source builds
- Verify that the runtime, tools, and work program match the specified content

Docker's root filesystem setting itself is not read-only.
File ownership, permissions, and temporary mounts restrict where the non-root process can write.

See [Processing limits](configuration.md#remediation-limits) for workload settings and [Work container networking](how-it-works.md#worker-network) for network restrictions.

### Result collection {#worker-results}

After collecting results from standard output, KestreLynx attempts to remove the work container.
Collected results are inspected by KestreLynx before being used to decide whether to adopt the update.

- Checks consistency among returned files, sizes, hashes, executed operations, and exit status
- Rejects files outside the declared outputs and content that contradicts the result records
- May continue inspection after a container removal failure if results were collected
- Records removal failures and retries removal during later cleanup

## Adopting update results {#update-method-and-partial-pull-requests}

### Update methods by package manager {#manager-update-methods}

After rechecking the update inputs, KestreLynx edits direct dependency version specifications where needed and updates dependency files using the method for each package manager.

| Manager | Update method | Consistency checks |
| --- | --- | --- |
| npm | Removes target entries from a working copy of the lockfile and regenerates it. | Checks that regenerating the original input preserves the package set, then checks the update result. |
| pnpm | Removes target entries from a working copy of the lockfile and regenerates it without freezing the lockfile. | Checks dependency consistency with the lockfile frozen before and after the update. |
| uv | Updates the lockfile with a specified target version for each target package. | Checks consistency between the lockfile and project declarations before and after the update. |
| pip | Rewrites pinned versions and updates existing hashes from PyPI wheel information. | Checks dependency resolution before and after the update using dry runs targeting the running image's environment. |

When pnpm updates only transitive dependencies, direct dependency entries may also be temporarily removed to trigger resolution.

- Temporarily removed direct dependencies must return to their original versions, specifications, and dependency relationships
- Changes to those direct dependencies, or the absence of a suitable direct dependency to trigger resolution, require manual handling

If a pip version range allows the update target, KestreLynx reports an expected fix through rebuilding without rewriting the range to a pinned version.
See [Supported input formats](remediation-reference.md#supported-inputs) for supported inputs and forms that cannot be updated.

### Checking related changes {#change-validation}

Changes outside the update targets are also checked against their relationship to the update and public registry information.
The lockfile or resolution results returned by the work container are not sufficient evidence on their own.

| Change | Conditions for acceptance |
| --- | --- |
| Additions, changes, or removals of update targets and dependencies needed for the update | Dependency relationships, declared ranges, distribution references, and integrity information must pass checks |
| Added, changed, or removed npm `deprecated` notices | Must match the notice returned by the npm registry for that package version |
| A package outside the targets switches to a different version of a dependency | Must align with the same-named dependency version used by an update target, preserve the dependent package's version and other content, and satisfy range and distribution checks |
| Changes to settings files read as inputs | Rejected and require manual handling. |
| Lockfile format changes or unexplained related changes | Rejected and require manual handling. |

Dependency distribution references and hashes are checked against public registry information.
This does not unpack distributions to compare all of their contents.

### Partial PR conditions {#partial-pr-selection}

For npm, pnpm, and uv, the remaining updates may be accepted even when some packages do not reach the update target's lower bound.
Pinned-version pip updates are not split this way.

| Update result | Processing |
| --- | --- |
| No package reaches the lower bound | Does not produce a PR candidate because there is no update to adopt. |
| Some packages miss the lower bound, with their versions and manifest specifications unchanged | Excludes those packages from the targets and continues checking the remaining updates. |
| Packages that miss the lower bound have changed versions or manifest specifications | Excludes those packages and reruns the update from the original inputs. |
| The result after exclusion contains unexplained related changes | May rerun the update without the excluded packages. |

- Exclusion and rerunning are limited to one attempt, without repeatedly excluding more targets from the rerun result
- Remaining updates must pass the usual fixed-version, dependency, distribution, diff, and scan checks
- Partial PRs do not bypass inconsistent inputs or newly introduced findings
- Excluded packages and their reasons are recorded and carried forward when a later run matches an existing PR

See [Partial PRs](remediation-results.md#partial-pull-requests) for how partial PRs are displayed.

### Scan comparison conditions {#comparison-conditions}

Comparisons use the same scanner, vulnerability database content, severity range, and scan settings.
A running-image scan whose database identity cannot be verified is not reused directly as the baseline.

- Rescans the baseline within the retrieval budget if its conditions cannot be verified
- Checks the database again after comparison scans and rejects the comparison if conditions changed
- Verifies both image identities and matching OS and CPU architecture for image comparisons
- Does not infer resolution from a comparison with missing or truncated package lists
- Does not treat absent findings as resolved if the target package type was not analysed

Dependency-file comparisons receive only the files being checked.
They do not read the repository's own Trivy configuration, ignore files, or VEX documents.

Findings outside the configured severity range are excluded from both resolution and introduction assessments.

### Verification scope by target {#verification-scope}

The comparison and adoption requirements depend on the target.

| Target | Comparison | Required result for adoption |
| --- | --- | --- |
| Distributed image | Running image and candidate image | At least one target finding is resolved, no target is unanalysable, and no new findings appear within the assessment scope |
| Base image | Verified current base and candidate base | At least one target finding attributable to the base is resolved, no target is unanalysable, and no new findings appear within the assessment scope |
| Language package | Dependency files before and after the update | Target findings for adopted packages are confirmed before the update, remain in no occurrence afterward, and no new findings appear, including outside the targets |

- Image candidates can propose improvements that meet adoption requirements even if some target findings remain
- For language packages, the scan must also analyse the target package versions recorded in the updated files
- New findings are not offset against resolved counts, and newly introduced vulnerabilities on the CISA KEV list are recorded separately
- Multiple running images sharing the same Dockerfile change must be eligible for adoption together

A base-image comparison does not inspect the completed image built from the changed Dockerfile.
Dependency-file comparisons also do not verify actual installation, application behavior, or the running image after deployment.

See [Resolution in comparison results](remediation-results.md#verification-results) for interpreting comparison results.

## PR management {#pr-management}

### Matching existing PRs {#existing-pr-matching}

KestreLynx records edit locations and update contents and matches them against GitHub PRs to prevent duplicates.

| Information matched | What it distinguishes |
| --- | --- |
| Repository, base branch, file, and edit location | Change destination |
| Target image tag and digest, or adopted package versions and manifest edits | Update contents |
| Base commit and file contents before and after the change | Inputs used to create the same update |

- If a PR exists for the same update, it is matched to its open, merged, or closed record
- A trusted creation record for a language update with unchanged inputs allows matching an existing PR without rerunning the update job
- Language updates prioritize targets without an open PR for the same lockfile
- New updates create new PRs without overwriting or force-updating existing branches

If a KestreLynx-managed PR is open for the same lockfile and the new update cannot retain all of its remediation targets, the new PR is deferred.
This creation suppression does not apply to PRs with detected user changes or PRs recovered solely from identification markers.

### Closed PRs {#closed-prs}

An update identical to one closed without merging is not recreated.
Suppression based on the update record remains even after its branch is deleted.

- Advancing the base branch does not remove suppression if the update contents are unchanged
- Merged PRs also suppress duplicate creation of the same update
- PR and recreation-suppression records have no expiry

A merged status does not establish that the change has been deployed.

### Replacing older PRs {#pr-replacement}

KestreLynx may close an older PR when a new PR carries forward its fixes.
Replacement requires all of the following conditions.

- The destination repository, base branch, file, and edit location match
- The new PR fixes every target the older PR claimed to fix
- An image update uses a newer patch from the same image repository and tag series
- A base-image update carries forward the fixes for every running image targeted by the older PR
- Both PRs are open and can be verified against their creation commits, base branches, and repositories
- Neither PR has detected user changes or was recovered solely from identification markers

When these conditions hold, KestreLynx comments on the older PR with the replacement link and then closes it.
It rechecks both PRs before each write and stops replacement if the conditions no longer hold.

- For image updates, the candidate tag must still point to the content used in the comparison at replacement time
- A PR with any previously detected user change is excluded from automatic replacement even if restored to its original state
- Older PRs are not closed solely to make room under the PR limit

### Record save order {#record-order}

KestreLynx saves the plan and dependency-update check results before creating PRs or matching existing PRs.
If saving the plan fails, PR processing does not proceed in that run.

| Save point | Recorded content |
| --- | --- |
| Before PR processing | Plan and check results for dependency updates that ran |
| Before each GitHub write | Operation about to be performed |
| After each GitHub write | Operation result |
| After notification delivery | Delivered information and delivery status of operation history |

The plan is not saved again with PR processing results.
Those results appear in notifications and the PR records used for ongoing management.

See [Stored files](remediation-reference.md#stored-records) for filenames and contents.

### Record recovery {#record-recovery}

If PR records are missing, KestreLynx examines open and closed PRs in the configured repositories before writing.
It recovers records from identification markers in PR-body HTML comments for `kestrelynx/` branches in the same repository.

- Recalculates marker identifiers and verifies the repository and branch relationship
- Makes no GitHub writes during recovery from missing records until all target repositories have been checked
- Checks existing PRs in newly configured repositories before the first write
- Uses records recovered solely from identification markers to suppress duplicates, but not for automatic replacement

Identification markers alone do not prove that a language update ran and passed its checks.
Matching that skips an update job requires records created by KestreLynx or records with inputs verified by rerunning the update.

### Stopping writes {#write-stops}

If records or GitHub state cannot be verified, writes to affected targets stop.
Corrupt plan or PR records and unsupported storage formats are not replaced with empty records to continue processing.

| Stop condition | Treatment |
| --- | --- |
| Plan save failure | Skips PR processing for that run. |
| PR record read or save failure, or failure to acquire the record lock | Stops GitHub writes. |
| Existing PRs or operation results cannot be reconciled | Stops writes to the affected repository or change destination. |
| Unknown GitHub write outcome | Stops subsequent writes in that run and checks the outcome through reads in the next run. |
| Repository name or identity differs from configuration or records | Does not automatically switch writes to a transferred repository or other destination. |
| No space can be made in operation history | Does not start new GitHub operations. |
| A request, processing-time, or other limit is reached | Defers subsequent affected processing. |

Operation-history cleanup removes only delivered entries that are not needed for unsettled operations or replacements in progress.
Writes with unknown outcomes are not resent without checking.

See [Processing limits](configuration.md#remediation-limits) for settings and [Checking record reconciliation failures](remediation-troubleshooting.md#check-record-failure) for checks and corrective actions.
