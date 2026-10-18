# Supported inputs and reason codes

This page lists the input formats, runtimes, result values, and reason codes used by remediation plans and fix pull requests.
See [Setup steps](remediation-setup.md) to enable them.

## Scope and requirements {#scope-and-requirements}

### Supported environments {#supported-environments}

| Item | Support |
| --- | --- |
| Container environment | Docker mode is supported; remediation plans cannot be enabled in Kubernetes mode |
| Source mappings | Specify source edit locations for Compose workloads |
| Source host | GitHub |
| Work containers | Linux `amd64` and `arm64` |
| Language update runtimes | Series listed in [Supported runtimes](#supported-runtimes) |
| Sensor | Not required for remediation plans or fix pull requests |

### Supported targets {#supported-targets}

| Target | Source | Source mapping |
| --- | --- | --- |
| Distributed image | Public registries and private registries with authentication configured | Not required to display comparison results; required for PRs that change Compose |
| Dockerfile base image | Public registries and private registries with authentication configured | A Dockerfile or Compose mapping is required from the planning stage |
| npm and pnpm dependencies | Public npm registry | A dependency-directory mapping is required from the planning stage |
| pip and uv dependencies | Public PyPI | A dependency-directory mapping is required from the planning stage |

Private npm registries and private PyPI sources are not supported for updates.
Image registry authentication is not used to retrieve dependency packages.

## Supported input formats {#supported-inputs}

### Compose formats {#compose-formats}

| Input | Support |
| --- | --- |
| Edit location | Image reference written directly in `services.<service>.image` |
| Image reference | A string matching the running repository and tag, with an identifiable edit location |
| Pinned tag | A tag specifying a full version can be changed to a newer patch in the same series |
| Floating tag | Can produce a re-pull candidate, without a PR rewriting the same tag reference |
| Variables and digests | Unsupported in image references being edited |
| YAML anchors, aliases, and merge keys | Unsupported when they affect the edit location |
| Block scalars and non-string `image` values | Unsupported |
| `include` and `extends` on the target service | Unsupported for automatic editing |
| Services with `build:` | Completed images are excluded from distributed-image searches |

See [Distributed image tags](remediation-logic.md#published-image-tags) for tag selection and [Excluding local builds](remediation-logic.md#local-builds) for handling build targets.

### Dockerfile formats {#dockerfile-formats}

| Input | Support |
| --- | --- |
| Pinned `FROM` tag | Editable when the reference has no variables or digest and the tag location can be identified |
| Floating `FROM` tag | Used for base verification, but excluded from tag-update PRs |
| Build `target` | A stage name can be specified; defaults to the last stage |
| Inheritance from earlier stages | Supported when inheritance can be followed to an external base image |
| `--platform` | Static values are supported on the `FROM` specifying the external base, but unsupported on intermediate `FROM` instructions |
| Variables in `FROM`, `scratch`, and digest references | Unsupported for automatic editing |
| Nonstandard syntax frontends and the `escape` directive | Unsupported for automatic editing |
| `ONBUILD` in inherited stages or base images | Unsupported for automatic updates |
| Compose build context | Static paths within the repository are supported |
| Compose `dockerfile` and `target` | Supported static values can identify the Dockerfile edit location |
| Remote build contexts, `dockerfile_inline`, and `additional_contexts` | Unsupported for determining edit locations from Compose |

See [Base image selection](remediation-logic.md#base-image-selection) for determining edit locations and checking mappings.

### npm dependency files {#npm-inputs}

| Input | Support |
| --- | --- |
| Required files | `package.json` and `package-lock.json` for a single project |
| Lockfile format | `lockfileVersion` 2 or 3, with a root entry in `packages` |
| Package source | Distributions from the public npm registry |
| Workspaces | Unsupported |
| Git, URL, local references, and aliased installations | Unsupported for automatic updates of target packages |
| Bundled dependencies and package-specific shrinkwrap | Unsupported for automatic updates of target packages |
| Versions forced by `overrides` | Affected packages require manual handling |
| Private registry settings in `.npmrc` | Unsupported |
| Re-resolution through dependent packages | Limited to transitive dependencies that do not reach fixed versions through normal updates and whose dependent packages are confirmed to require older versions |

#### Re-resolution support and limits {#dependent-reresolution-limits}

This mechanism applies to transitive dependencies whose dependent packages' version requirements prevent updates to fixed versions.
The following examples assume a lowest fixed version of `1.2.8` for npm and pnpm, and `2.0.0` for uv.

| Example requirement from a dependent package | Use of this mechanism | Notes |
| --- | --- | --- |
| npm or pnpm `0.0.8` | Yes | Exact requirement for a version before the fix |
| npm or pnpm `<1.0` | Yes | The upper bound excludes fixed versions |
| uv `==1.2.3` or `<1.0` | Yes | The exact requirement or upper bound excludes fixed versions |
| uv `~=1.4` | Yes | Allows versions from 1.4 up to but excluding 2.0 when fixed versions start at 2.0 |
| npm or pnpm `^1.2.0` | No | The range allows a fixed version |
| npm or pnpm ranges containing `\|\|`, or tags such as `latest` | No | These specifications do not establish grounds for re-resolution |
| uv `!=1.2.3`, `===1.2.3`, or `==1.2.*` | No | Exclusions, arbitrary equality, and wildcards do not establish grounds for re-resolution |

The following cases are excluded.

- The project itself declares the package to fix as a direct dependency.
- The target or a required dependent package uses an alias, local, Git, or URL reference, or has its version forced by `overrides`.
- Conflicting declarations for the same dependency prevent a single version requirement from being determined.
- The project uses pip or a pnpm version outside series 9, 10, 11, and 12.x from 12.10.0.

| Limited resource | Limit and handling |
| --- | --- |
| Direct dependencies used as starting points for re-resolution | Up to 5 packages; exceeding this limit requires manual handling with `dependents_update_limit` |
| Packages added, changed, or removed outside the update targets | Up to 64 in total; results exceeding this limit fail with `chain_move_limit` |
| Work per item | Execution counts, communication volume, work time, and other resources have limits; repeated deferrals require manual handling with `dependents_update_limit` |

#### Re-resolution check conditions {#dependent-reresolution-rules}

Results with the following changes are not adopted.
In webhooks, check both the per-package `packages[].reason` and `update.chain.reason`, which gives the detailed reason.

| Example change | Recorded reason code |
| --- | --- |
| A version decreases on any path, or versions before and after the update cannot be matched | `chain_downgrade` |
| The version or reference of a direct dependency changes when it is neither a normal update target nor a starting point for re-resolution | `unexplained_dependency_diff` |
| The number of packages changed outside the update targets exceeds the limit | `chain_move_limit` |
| The vulnerability targeted for fixing remains detectable in the post-update scan | `source_target_still_detected` |
| A new vulnerable package appears | `source_introduced_findings` |
| More dependent packages use a vulnerable package | `source_introduced_findings` |
| A new version contains a vulnerability absent from the corresponding old version | `source_introduced_findings` |
| One version splits into multiple vulnerable versions, or multiple paths merge so that a single old version of the vulnerable package cannot be determined | `source_introduced_findings` |
| A KEV-listed vulnerability is introduced or is involved in the increases, splits, merges, or similar changes above | `source_introduced_kev` |

A vulnerability may qualify as carried when only the version changes at the same dependency position and vulnerabilities present in the old version remain without an increase.
See [Carried vulnerabilities](remediation-logic.md#dependent-reresolution-carried-findings) for an example.

These checks have the following limits.

- The checks cannot identify vulnerabilities absent from scan results or outside the configured severity range.
- Carried vulnerabilities remain unfixed, and a vulnerability targeted for fixing cannot pass by qualifying as carried.
- The checks do not compare the total number of paths from the project to vulnerable packages.

#### Release waiting periods and retries {#dependent-reresolution-waits}

Newly introduced versions must wait 72 hours after publication.
A package version already present in the original lockfile is exempt, and a version whose publication time cannot be confirmed is not adopted.

- The webhook's `retry_after` field shows the retry time for a release waiting period.
- Three consecutive deferrals caused by release waiting periods or by the same type of processing limit stop re-resolution for the same inputs.
- Cycles skipped before the retry time do not count toward the three deferrals.
- After re-resolution stops, normal update results that pass the checks are still adopted, and remaining targets require manual handling with the following reason codes.

| Stop cause | Reason code for remaining targets |
| --- | --- |
| Three consecutive release waits | `dependents_update_rejected` |
| Three consecutive deferrals caused by the same type of processing limit | `dependents_update_limit` |

### pnpm dependency files {#pnpm-inputs}

| Input | Support |
| --- | --- |
| Required files | `package.json` and `pnpm-lock.yaml` |
| Lockfile format | `lockfileVersion: '9.0'` with only the `.` importer |
| Manifest consistency | Direct dependency declarations must match the importer |
| Workspaces, catalogs, and patched dependencies | Unsupported |
| Sources other than the public npm registry | Unsupported for automatic updates of target packages |
| Lockfiles recording automatic runtime downloads | Unsupported |
| `resolutions`, `configDependencies`, `executionEnv`, and similar settings | Unsupported settings that alter resolution or additional downloads |
| pnpm 12 | Supported from 12.10.0; 12.x releases before 12.10.0 require manual handling |
| Re-resolution through dependent packages | Limited to transitive dependencies that do not reach fixed versions through normal updates and whose dependent packages are confirmed to require older versions |

A `pnpm-workspace.yaml` in the same directory can be read if it contains only the following settings.
The file's presence alone does not establish a workspace.

| Setting | Supported form |
| --- | --- |
| `allowBuilds` | A mapping from package specifications to boolean or string values |
| `onlyBuiltDependencies`, `ignoredBuiltDependencies`, and `neverBuiltDependencies` | Lists of package-name strings |
| `supportedArchitectures` | Lists of strings for `os`, `cpu`, and `libc` |
| `packages` | Unsupported because it is treated as a workspace declaration |
| Other keys | Unsupported |
| `pnpm-workspace.yaml` above the dependency directory | Checked up to the repository root; its presence requires manual handling |

The `pnpm` settings in `package.json` also support the build-permission and architecture settings listed above.
Scripts remain disabled during updates even when readable build-permission settings are present.

### pip dependency files {#pip-inputs}

| Input | Support |
| --- | --- |
| Required file | UTF-8 `requirements.txt` |
| Strict version pins | `name==1.2.3` can be updated |
| Version ranges or no version specification | Reports an expected fix through rebuilding if a fixed version is allowed, without rewriting to a pinned version |
| Extras | `name[extra]` can be read |
| Comments and continuation lines | Readable |
| Existing `--hash` values | Updated from PyPI wheel information when changing a pinned version |
| Environment markers | Not evaluated automatically; target packages require manual handling |
| References to other files, such as `-r` and `-c` | Unsupported |
| Options that change package sources | Unsupported |
| Git, URL, and local references | Unsupported for automatic updates of target packages |
| Versions with only source distributions | Unsupported for automatic updates |

See [pip verification environment](remediation-logic.md#pip-target-environment) for verification requirements based on the running image.

### uv dependency files {#uv-inputs}

| Input | Support |
| --- | --- |
| Required files | Static `pyproject.toml` and `uv.lock` for a single project |
| Lockfile format | `version = 1` and `revision = 5` |
| Project | Must have `[project]` and require no dynamic metadata |
| Python requirements | Automatic updates require `requires-python` in `[project]` |
| Package source | Public PyPI |
| Workspaces | Unsupported |
| Git, URL, and local references | Unsupported for automatic updates of target packages |
| Dependencies requiring source builds | Unsupported for automatic updates |
| `[tool.uv]` | `required-version`, `dev-dependencies`, `sources`, and `package` can be read |
| Other `[tool.uv]` settings | Unsupported |
| `uv.toml` | Unsupported if present anywhere from the dependency directory to the repository root |
| Re-resolution through dependent packages | Limited to transitive dependencies whose dependent packages are confirmed to require older versions, including reassessment of an initial update result rejected by dependency diff checks |

Readable `[tool.uv]` keys still require supported dependency sources and project structure.

### Node.js version declarations {#node-declarations}

| Declaration | Supported form |
| --- | --- |
| `.nvmrc` and `.node-version` | Numeric values such as `22`, `22.14`, and `22.14.0` on the first nonempty line, with an optional leading `v` |
| LTS declarations in `.nvmrc` | `lts/*` and recognized LTS series names |
| `engines.node` in `package.json` | Exact versions and interpretable ranges, including comparison operators, `^`, `~`, and wildcards |
| `devEngines.runtime` and `engines.runtime` | Objects or arrays specifying Node.js and its version range |
| Values such as `system` and `current` | Unsupported because they do not identify an execution series |
| Ranges with prerelease boundaries | Unsupported |
| `onFail: download` in runtime declarations | Unsupported |

Version files select the major series; the actual minor and patch version comes from the bundled table.
See [Node.js selection](remediation-logic.md#node-selection) for how declarations are combined.

### Python version declarations {#python-declarations}

| Declaration | Supported form |
| --- | --- |
| uv `requires-python` | Interpretable Python version conditions such as `>=3.12,<3.15` |
| `.python-version` | Values such as `3.13` and `3.13.5` on the first nonempty line |
| CPython prefixes | Forms such as `cpython-3.13` and `cpython@3.13` |
| `.python-versions` | Multiple-version declarations are unsupported |
| PyPy, GraalPy, Pyodide, and `system` | Unsupported |
| Free-threaded versions | Unsupported |

`.python-version` selects the Python X.Y series, and its patch version may differ from the execution version.
See [Python selection for uv](remediation-logic.md#uv-python-selection) for declaration consistency requirements.

### Tool version declarations {#tool-declarations}

| Declaration | Supported form |
| --- | --- |
| `packageManager` | Manager name and exact version, such as `npm@11.21.0` or `pnpm@11.28.5` |
| Hash in `packageManager` | `name@version+<algorithm>.<hex>` |
| Hash algorithms | `sha1`, `sha224`, `sha256`, `sha384`, and `sha512` |
| `devEngines.packageManager` | Manager name and an exact version or interpretable range |
| `engines.npm` and `engines.pnpm` | Exact version or interpretable range |
| `tool.uv.required-version` | Exact version such as `==0.13.0`, or an interpretable range |
| Tool versions with prerelease or build metadata | Unsupported |

| Tool | Supported versions | Default version |
| --- | --- | --- |
| npm | Versions in series 9–12 compatible with the selected Node.js version | `11.21.0` |
| pnpm | Versions in series 9–12 compatible with the selected Node.js version (12.x: 12.10.0 or later) | `11.28.5` |
| uv | Supported stable versions at or above `0.12.22` | `0.13.0` |
| pip | Version included in the official Python work image | `26.2.1` in the Python 3.13 work image |

See [Tool version selection](remediation-logic.md#tool-version-selection) for choosing declared or default versions and [Waiting after tool release](remediation-logic.md#tool-release-age) for release-age requirements.

## Supported runtimes {#supported-runtimes}

Supported runtimes are the supported series in the bundled table, currently Node.js 22, 24, and 26 and Python 3.11–3.15.
The following versions and dates are information held by KestreLynx and change with KestreLynx updates.

| Series | Execution version in the bundled table | Support end date |
| --- | --- | --- |
| Node.js 22 | `22.23.3` | 2027-04-30 |
| Node.js 24 | `24.21.0` | 2028-04-30 |
| Node.js 26 | `26.11.1` | 2029-04-30 |
| Python 3.11 | `3.11.17` | 2027-10-31 |
| Python 3.12 | `3.12.15` | 2028-10-31 |
| Python 3.13 | `3.13.16` | 2029-10-31 |
| Python 3.14 | `3.14.8` | 2030-10-31 |
| Python 3.15 | `3.15.0` | 2031-10-31 |

| Use | Default runtime |
| --- | --- |
| npm and pnpm updates without Node.js declarations | Currently Node.js 24; Node.js 26 becomes eligible on 2026-10-28 according to the LTS start date in the bundled table |
| Work containers for pip updates | Python 3.13 |
| uv updates | Selected according to Python declarations |

| Series in the bundled table whose support has ended | Support end date |
| --- | --- |
| Node.js 20 | 2026-04-30 |
| Python 3.9 | 2025-10-31 |
| Python 3.10 | 2026-10-01 |

Series past their support end date are not used for updates.
See [Runtime selection](remediation-logic.md#runtime-and-tool-versions) for selection requirements.

## Result values {#result-values}

### Plan category values {#category-values}

`category` classifies an entire plan item, such as an image or dependency directory.

| Value | Meaning |
| --- | --- |
| `pr_candidate` | A candidate that passed checks and can be proposed as a PR |
| `dependency_update_candidate` | A dependency update candidate selected from source and fixed-version information, with update results not yet verified |
| `pull_again` | A compared candidate expected to improve findings by retrieving new content under the same tag |
| `rebuild_expected` | A dependency range is expected to install a fixed version on rebuild (Slack's "Rebuild" also shows guidance for a floating-tag base, whose category is `not_comparable`) |
| `manual` | Requires a user's decision or manual handling without proceeding automatically |
| `not_comparable` | Required comparison information or conditions are missing |
| `deferred` | Processing is deferred because of limits, waiting periods, retrieval problems, or similar conditions |
| `no_candidate` | No newer candidate exists, content is unchanged, or the candidate does not resolve targets |
| `excluded` | Outside automatic candidate selection |
| `failed` | Processing failed |

### Package action values {#action-values}

`action` describes how an individual package is handled.
Check it separately from the item's overall `category`.

| Value | Meaning |
| --- | --- |
| `update` | Target for a dependency-file update |
| `rebuild_expected` | The current dependency range allows a fixed version, with resolution expected through rebuilding |
| `manual` | Target requiring manual handling |

`update` alone does not mean that update execution or verification is complete.
See [Target and adopted versions](remediation-results.md#target-and-adopted-version) for distinguishing version values.

### PR status values {#pr-status-values}

PR processing results use the following `status` values.

| Value | Meaning |
| --- | --- |
| `pr_created` | A PR was created in this run |
| `pr_open` | A PR proposing the same update is open |
| `pr_merged` | A PR for the same update was merged, without confirmation of deployment |
| `pr_suppressed` | Recreation was suppressed because the update was closed without merging |
| `manual` | Automatic editing is unavailable and manual handling is required |
| `deferred` | Processing was deferred because of limits, candidate changes, or similar conditions |
| `failed` | A GitHub write or another operation failed |
| `write_blocked` | Writes stopped because of problems with records, GitHub state, or similar conditions |
| `write_disabled` | Indicates that PR creation is disabled; not generated during normal PR processing |

PR records use the following `state` values.

| Value | Meaning |
| --- | --- |
| `open` | Open |
| `closed` | Closed without merging |
| `merged` | Merged |
| `replaced` | Closed by KestreLynx to replace it with a newer PR |

## Reason codes {#reason-codes}

A result's `reason` describes why a candidate was selected or why processing could not proceed.
The following tables give each code's meaning and related decision rules or checks.

### Image candidate reasons {#image-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `scan_failed` | A scan failed | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `entity_unverified` | The running image could not be confirmed or compared with the registry content | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `conditions_unknown` | The conditions of a scan are unknown | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `conditions_differ` | The scans were made under different conditions | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_unknown` | The platform of the image is unknown | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_differ` | The compared images are for different platforms | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `variant_unsupported` | The image variant is not supported | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `packages_missing` | The scan result has no package list | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `packages_truncated` | The package list of the scan result is truncated | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `unknown_package_type` | A finding names an unsupported package type | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `type_not_analysed` | The candidate scan did not analyse the target package type | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `no_newer_tag` | No newer tag exists | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `same_content` | The newer tag has the same content | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets` | The candidate does not resolve the target findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `auth_required` | The registry requires a login | [Private image authentication](remediation-setup.md#configure-registry-auth) |
| `platform_not_found` | The candidate has no image for the same platform | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_ambiguous` | More than one image of the candidate matches the platform | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_mismatch` | The platform of the candidate differs from the running image | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `registry_error` | The registry returned an error | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `targets_not_detected_on_baseline` | The baseline scan did not detect the target findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `analysis_incomplete` | The analysis of the image was incomplete | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `tag_listing_incomplete` | The tag list could not be read to the end | [Tag discovery](remediation-logic.md#tag-discovery) |
| `candidate_scan_limit` | The limit on candidate scans in a run was reached | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `baseline_rescan_limit` | The limit on baseline image rescans was reached | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `tag_page_limit` | The limit on tag list requests was reached | [Tag discovery](remediation-logic.md#tag-discovery) |
| `registry_budget_exhausted` | The registry request budget was exhausted | [Tag discovery](remediation-logic.md#tag-discovery) |
| `rate_limited` | The registry limited the request rate | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `cycle_deadline` | The time limit of the run was reached | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `registry_timeout` | A registry request timed out | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `locally_built` | The image was built on its host and is excluded from distributed-image searches | [Excluding local builds](remediation-logic.md#local-builds) |
| `partial_improvement` | The candidate resolves only some of the findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `introduced_findings` | The candidate brings new findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `introduced_kev` | The candidate brings a new vulnerability on the KEV list | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `adopted` | The candidate was adopted | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `digest_only` | The reference has a digest and no tag | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `tag_and_digest` | The reference has both a tag and a digest | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `prerelease` | The tag has a prerelease version format | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `bare_digest` | The reference is a bare digest with no identifiable repository | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `unparsable` | The image reference cannot be parsed | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `unsupported_tag_format` | The format of the tag is not supported | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `base_layers_mismatch` | The base image behind the tag does not match the start of the running image's layers | [Base layer matching](remediation-logic.md#base-layer-matching) |
| `base_layers_unusable` | The layers of the running image and base image cannot be compared | [Base layer matching](remediation-logic.md#base-layer-matching) |
| `base_onbuild` | The base image has `ONBUILD` triggers | [Base image selection](remediation-logic.md#base-image-selection) |
| `no_base_derived_findings` | No fixable finding lies in the base image's layers | [Base layer matching](remediation-logic.md#base-layer-matching) |
| `base_unchanged` | The layers of the base the tag points to now match the start of the running image, so no base update is visible | [Base layer matching](remediation-logic.md#base-layer-matching) |
| `floating_base_unconfirmed` | The base image the running image was built from cannot be confirmed | [Base layer matching](remediation-logic.md#base-layer-matching) |
| `dockerfile_set_not_adopted` | The same candidate could not be adopted for every workload sharing the Dockerfile (check each workload's own reason too) | [Base image selection](remediation-logic.md#base-image-selection) |
| `compose_set_not_adopted` | The same candidate could not be adopted for every service sharing the image (check each service's own reason too) | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |

### Source reasons {#source-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `dockerfile_file_not_found` | The Dockerfile is not at the configured path | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_file_unusable` | The Dockerfile is not a file that can be edited | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_invalid` | The Dockerfile cannot be parsed, or the edit failed its check | |
| `dockerfile_target_missing` | The specified build stage does not exist | [Base image selection](remediation-logic.md#base-image-selection) |
| `dockerfile_stage_cycle` | The stage references never reach an external image | [Base image selection](remediation-logic.md#base-image-selection) |
| `dockerfile_variable` | The base image or platform contains a variable | |
| `dockerfile_scratch` | The base is `scratch` | |
| `dockerfile_digest` | The base is given by a digest | |
| `dockerfile_tag_unsupported` | The base tag has a form excluded from candidate searches | [Distributed image tags](remediation-logic.md#published-image-tags) |
| `dockerfile_frontend` | The Dockerfile specifies a nonstandard syntax frontend | |
| `dockerfile_escape` | The Dockerfile sets the `escape` directive | |
| `dockerfile_ambiguous_range` | The tag cannot be located exactly in the file | |
| `dockerfile_onbuild` | An inherited stage has `ONBUILD` | |
| `dockerfile_stage_platform` | An intermediate `FROM` has `--platform` | |
| `dockerfile_not_editable` | The base is not a pinned tag | [Base image selection](remediation-logic.md#base-image-selection) |
| `dockerfile_source_mismatch` | The base image in the file differs from the expected one | [Base image selection](remediation-logic.md#base-image-selection) |
| `dockerfile_mapping_differs` | The configured Dockerfile and the one named by Compose disagree | [Base image selection](remediation-logic.md#base-image-selection) |
| `compose_no_build` | The target service has no `build` section | [Base image selection](remediation-logic.md#base-image-selection) |
| `compose_build_remote_context` | The build context is a URL or a repository | |
| `compose_build_inline` | The build uses `dockerfile_inline` | |
| `compose_build_additional` | The build uses `additional_contexts` | |
| `compose_build_path` | A build path is absolute, leaves the repository, or is malformed | |
| `compose_build_unsupported_form` | The `build` section uses an unsupported form | |
| `compose_build_undetermined` | How the service is built cannot be determined | [Excluding local builds](remediation-logic.md#local-builds) |
| `compose_invalid` | The Compose file cannot be parsed, or the edit failed its check | |
| `compose_service_missing` | The target service or its `image` key is missing from the Compose file | |
| `compose_build` | The service builds its image | [Excluding local builds](remediation-logic.md#local-builds) |
| `compose_include_or_extends` | The Compose file uses `include` or `extends` | |
| `compose_merge_key` | The path to `image` goes through a merge key | |
| `compose_anchor_or_alias` | The `image` involves a YAML anchor or alias | |
| `compose_not_string` | The `image` value is not a plain string | |
| `compose_block_scalar` | The `image` value is a block scalar | |
| `compose_variable` | The `image` value contains a variable | |
| `compose_digest` | The `image` value carries a digest | |
| `compose_source_mismatch` | The `image` in the file differs from the running image | [Source verification](remediation-logic.md#source-verification) |
| `compose_file_not_found` | The Compose file is not at the configured path | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `compose_file_unusable` | The Compose file is not a file that can be edited | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_files_not_found` | No dependency files were found | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `ambiguous_dependency_files` | More than one set of dependency files matches, so no unique set can be selected | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_file_unusable` | A dependency file cannot be used | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `unsupported_lockfile` | The lockfile format is not supported | |
| `workspace_unsupported` | The project's workspace layout is not supported | |
| `workspace_settings_unsupported` | The workspace settings file contains unsupported settings | |
| `dynamic_metadata` | The project's metadata is dynamic | |
| `unsupported_requirements` | The requirements file uses an unsupported form | |
| `unparsable_source` | A dependency file cannot be parsed | |
| `unsupported_source_settings` | The project sets an unsupported package source | |
| `scan_not_pinned` | The scan result is not tied to one image | [Source verification](remediation-logic.md#source-verification) |
| `not_found_in_source` | The dependency files do not list the package at the running version | [Source verification](remediation-logic.md#source-verification) |
| `non_registry_source` | The package does not come from a supported public registry | |
| `sdist_only` | The package has only a source distribution | |
| `forced_by_override` | The package version is forced by an override | |
| `marker_not_evaluated` | The requirement's environment marker has not been evaluated | |
| `invalid_marker` | The requirement's environment marker is invalid | |
| `multiple_versions` | Several versions or occurrences of the same package cannot be handled as one update | |
| `unparsable_version` | A package version cannot be parsed | |
| `source_not_found` | The source repository or branch was not found | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `source_access_denied` | Access to the source repository was denied | [Preparing GitHub access](remediation-setup.md#prepare-github-access) |
| `source_too_large` | The source is too large to read | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `file_too_large` | A dependency file is too large to read | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `byte_budget_exhausted` | The limit on bytes read from the source was reached | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `source_error` | Reading the source failed | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `github_budget_exhausted` | The limit on GitHub requests was reached | [Checking missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `source_read_failed` | Reading the dependency files again failed | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |

### Runtime reasons {#runtime-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `node_spec_invalid` | The declared Node.js version cannot be parsed | [Node.js selection](remediation-logic.md#node-selection) |
| `python_spec_invalid` | The declared Python version cannot be parsed | [Python selection for uv](remediation-logic.md#uv-python-selection) |
| `manager_spec_invalid` | The declared package manager version cannot be parsed | [Tool version selection](remediation-logic.md#tool-version-selection) |
| `node_spec_conflict` | The Node.js version declarations contradict each other | [Node.js selection](remediation-logic.md#node-selection) |
| `python_spec_conflict` | The Python version declarations contradict each other | [Python selection for uv](remediation-logic.md#uv-python-selection) |
| `manager_spec_conflict` | The package manager declarations contradict each other | [Tool version selection](remediation-logic.md#tool-version-selection) |
| `node_spec_unsupported` | The declared Node.js version is not supported | [Node.js selection](remediation-logic.md#node-selection) |
| `python_spec_unsupported` | The declared Python version is not supported | [Python selection for uv](remediation-logic.md#uv-python-selection) |
| `manager_spec_unsupported` | The declared package manager version is not supported | [Tool version selection](remediation-logic.md#tool-version-selection) |
| `work_program_mismatch` | The program in the work container differs from the one bundled with the running KestreLynx | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `work_environment_rejected` | The work container did not meet its program's execution requirements | [Execution restrictions](remediation-logic.md#worker-restrictions) |
| `runtime_eol` | The runtime targeted by the update is past the end of its support | [Runtime selection](remediation-logic.md#runtime-and-tool-versions) |
| `runtime_engines_mismatch` | An updated dependency does not support the minimum Node.js version declared by the project | [Node.js compatibility requirements](remediation-logic.md#node-compatibility) |
| `requires_python_unsupported` | The Python version requirement cannot be satisfied, is missing, or cannot be interpreted | [Python selection for uv](remediation-logic.md#uv-python-selection) |
| `pip_target_undecidable` | The environment the packages run in cannot be determined | [pip verification environment](remediation-logic.md#pip-target-environment) |
| `pip_target_mismatch` | The environment pip resolves for differs from the one the packages run in | [pip verification environment](remediation-logic.md#pip-target-environment) |
| `work_image_not_configured` | No work environment is available for updates | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `work_image_unavailable` | The work image could not be made ready | [Pinning official images](remediation-logic.md#worker-images) |

### Tool retrieval reasons {#tool-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `tool_fetch_config_unsupported` | The project configures the package manager to fetch tools itself or uses unsupported resolution settings | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `tool_version_unsupported` | The package manager version is not supported | [Tool version selection](remediation-logic.md#tool-version-selection) |
| `tool_version_not_found` | The specified package manager version was not found | [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| `tool_hash_mismatch` | The tool distribution does not match its checksum | [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| `tool_hash_unsupported` | The tool distribution's checksum cannot be verified | [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| `tool_artifact_invalid` | The tool distribution is invalid | [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| `tool_metadata_invalid` | The tool release metadata is invalid | [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| `tool_too_new` | The tool release cannot be confirmed to meet the waiting period | [Waiting after tool release](remediation-logic.md#tool-release-age) |
| `tool_fetch_failed` | Fetching the tool failed | [Tool retrieval and verification](remediation-logic.md#tool-verification) |
| `tool_fetch_budget` | The limit on tool retrievals was reached | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `tool_cache_full` | Enough space cannot be made in the tool cache | [Tool cache reuse](remediation-logic.md#tool-cache) |
| `tool_file_mismatch` | The cached tool distribution differs from the recorded one | [Tool cache reuse](remediation-logic.md#tool-cache) |

### Update result reasons {#update-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `update_candidate_in_source` | A fixed-version update candidate exists for the package in the source | [Fixed-version lower bound](remediation-logic.md#fix-lower-bound) |
| `range_allows_fix` | The version range allows the fixed version, so a rebuild is expected to install it | [Direct dependency version specifications](remediation-logic.md#direct-dependencies) |
| `no_fixed_version_above_installed` | There is no fixed version above the running one, or nothing to fix | [Fixed-version lower bound](remediation-logic.md#fix-lower-bound) |
| `constraint_excludes_fix` | The candidate or updated version does not satisfy the dependency constraints | [Direct dependency version specifications](remediation-logic.md#direct-dependencies), [Transitive dependency update scope](remediation-logic.md#transitive-dependencies) |
| `constraint_not_evaluable` | The version constraint cannot be evaluated, or the fixed version is a prerelease pip does not select | [Direct dependency version specifications](remediation-logic.md#direct-dependencies) |
| `packages_need_manual_update` | None of the packages can be updated automatically | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_job_limit` | The limit on update jobs in a run was reached | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_input_limit` | The update input files exceed the size limit | [Container inputs](remediation-logic.md#worker-inputs) |
| `update_job_failed` | The update job failed | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_result_invalid` | The update job result is invalid | [Result collection](remediation-logic.md#worker-results) |
| `update_job_timed_out` | The update job timed out | [Execution restrictions](remediation-logic.md#worker-restrictions) |
| `distribution_lookup_failed` | Looking up a package in the registry failed | [Checking related changes](remediation-logic.md#change-validation) |
| `source_scan_failed` | Scanning the dependency files failed | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `update_input_invalid` | The update input is invalid | [Container inputs](remediation-logic.md#worker-inputs) |
| `update_job_input_rejected` | The update job refused its input | [Container inputs](remediation-logic.md#worker-inputs) |
| `manifest_edit_required` | The manifest requires a change that automatic updates cannot make | [Direct dependency version specifications](remediation-logic.md#direct-dependencies) |
| `input_modified` | A settings file intended only for reading was changed | [Checking related changes](remediation-logic.md#change-validation) |
| `lockfile_inconsistent` | The lockfile is not consistent with the project | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `no_wheel_for_version` | The target version has no wheel for the required platform | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `release_yanked` | The target release was yanked | [Checking related changes](remediation-logic.md#change-validation) |
| `requirements_rewrite_unsupported` | The requirements file cannot be rewritten with this update method | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `update_set_not_applied` | Another package in the same update set could not be updated | [Partial PR conditions](remediation-logic.md#partial-pr-selection) |
| `target_not_in_lockfile` | The target package has no entry in the lockfile | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `no_reresolve_trigger` | No dependency can be temporarily removed to trigger resolution | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `pnpm12_removal_unsupported` | The current update method cannot be used with pnpm 12 releases before 12.10.0 | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `update_step_failed` | A step of the update failed | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `post_update_check_failed` | The check after the update failed | [Checking related changes](remediation-logic.md#change-validation) |
| `unexpected_files` | The update changed unexpected files | [Checking related changes](remediation-logic.md#change-validation) |
| `release_age_violation` | A dependency release is younger than the minimum release age set by the project | [Checking related changes](remediation-logic.md#change-validation) |
| `manifest_changed` | The update made an unpermitted manifest change | [Checking related changes](remediation-logic.md#change-validation) |
| `output_files_invalid` | The output files are invalid or cannot be read | [Result collection](remediation-logic.md#worker-results) |
| `lockfile_format_changed` | The update changed the lockfile format | [Checking related changes](remediation-logic.md#change-validation) |
| `target_not_updated` | The package did not reach the target version after the update | [Partial PR conditions](remediation-logic.md#partial-pr-selection) |
| `target_removed` | The target package is missing after the update or is no longer reachable through dependencies | [Partial PR conditions](remediation-logic.md#partial-pr-selection) |
| `fix_condition_not_met` | The updated version does not meet the vulnerability's fixed-version condition | [Partial PR conditions](remediation-logic.md#partial-pr-selection) |
| `unexplained_dependency_diff` | Dependency changes cannot be explained by the update | [Checking related changes](remediation-logic.md#change-validation) |
| `distribution_mismatch` | A package differs from what the registry publishes or pip resolution reports | [Checking related changes](remediation-logic.md#change-validation) |
| `registry_check_limit` | The limit on registry lookups during the update was reached | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_package_limit` | The update changes more packages than the limit allows | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `resolved_source_changed` | A package now resolves from another source | [Checking related changes](remediation-logic.md#change-validation) |
| `post_update_lockfile_unstable` | The lockfile changes again when regenerated | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `drop_side_effect` | A dependency temporarily removed to trigger resolution did not return to its original state | [Update methods by package manager](remediation-logic.md#manager-update-methods) |
| `source_target_not_detected_before` | The target vulnerability was not detected in the dependency files before the update | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_target_not_analysed_after` | The dependency files could not be analysed for the target after the update | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected` | The target vulnerability is still detected after the update | [Verification scope by target](remediation-logic.md#verification-scope) |
| `source_introduced_findings` | The update brings new findings into the dependency files | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_introduced_kev` | The update brings a new vulnerability on the KEV list into the dependency files | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_scan_incomplete` | The dependency-file scan was incomplete | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `update_verified` | Verification of the update result is complete | [Verification scope by target](remediation-logic.md#verification-scope) |
| `dependents_update_not_fixed` | Re-resolution of dependent packages does not reach a fixed version in this attempt | [Re-resolution through dependent packages](remediation-logic.md#dependent-reresolution) |
| `dependents_update_rejected` | The dependent-package update fails the checks | [Re-resolution check conditions](#dependent-reresolution-rules) |
| `dependents_update_unsupported` | KestreLynx cannot update the dependent packages | [Re-resolution support and limits](#dependent-reresolution-limits) |
| `dependents_update_limit` | The dependent-package update exceeds a limit | [Re-resolution support and limits](#dependent-reresolution-limits) |
| `release_too_new` | A version introduced by the update is less than 72 hours old | [Release waiting periods and retries](#dependent-reresolution-waits) |
| `chain_downgrade` | The update downgrades a package, or the correspondence between versions cannot be determined | [Re-resolution check conditions](#dependent-reresolution-rules) |
| `chain_move_limit` | The update changes more packages than the limit allows | [Re-resolution support and limits](#dependent-reresolution-limits) |
| `chain_item_budget` | The work required by the update exceeds a per-item limit | [Release waiting periods and retries](#dependent-reresolution-waits) |

Re-resolution through dependent packages records per-package reasons separately from the detailed reason for the overall re-resolution result.
In webhooks, check both `packages[].reason` and `update.chain.reason`.

- `dependents_update_rejected` also covers re-resolution stopped after three consecutive release waits.
- `dependents_update_limit` also covers stops caused by repeated deferrals for the same type of work limit or an inability to save waiting records.
- `source_introduced_findings` and `source_introduced_kev` also cover increases in vulnerable entry or requirement counts and refusals from checks of positions in the dependency relationships.
- Execution and retrieval failures also use failure codes shared with normal updates.

### PR processing reasons {#pr-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `pr_limit` | The limit on PRs created in a run, or on open PRs, was reached (`detail` says which) | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_changed` | The candidate changed while the PR was being prepared | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `base_moved` | The base branch advanced while the PR was being prepared | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `github_rate_limited` | GitHub limited the request rate | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `write_outcome_unknown` | The result of a GitHub write cannot be confirmed | [Stopping writes](remediation-logic.md#write-stops) |
| `reconciliation_failed` | Existing PRs could not be reconciled | [Matching existing PRs](remediation-logic.md#existing-pr-matching) |
| `repository_mismatch` | The repository differs from the recorded one | [Stopping writes](remediation-logic.md#write-stops) |
| `attempt_unsettled` | An earlier attempt to create the PR is not settled | [Matching existing PRs](remediation-logic.md#existing-pr-matching) |
| `branch_not_ours` | A branch with the same name exists and was not created by KestreLynx | [Stopping writes](remediation-logic.md#write-stops) |
| `pull_request_not_as_created` | The PR differs from its state at creation | [Stopping writes](remediation-logic.md#write-stops) |
| `github_refused` | GitHub refused the write | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `github_error` | GitHub returned an error | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_recheck_failed` | The candidate could not be checked again before PR creation | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `source_changed` | A file used to create the plan has changed | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `artifact_content_missing` | The updated file contents are no longer retained | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `artifacts_unusable` | The updated files cannot be written to the PR as they are | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_not_inherited` | An existing PR for the same file contains fixes this update does not carry forward | [Replacing older PRs](remediation-logic.md#pr-replacement) |
| `language_set_too_large` | Too many packages are being updated to fit in the PR record | [Checking missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `update_already_proposed` | A PR already proposes this update | [Matching existing PRs](remediation-logic.md#existing-pr-matching) |

### Storage reasons {#storage-reasons}

| Code | Meaning | Details |
| --- | --- | --- |
| `store_locked` | The PR records are locked by another process | [Checking record reconciliation failures](remediation-troubleshooting.md#check-record-failure) |
| `storage_failed` | The PR records could not be saved | [Record save order](remediation-logic.md#record-order) |
| `storage_full` | Enough space cannot be made in the PR records | [Stopping writes](remediation-logic.md#write-stops) |
| `records_unverified` | Existing PR records could not be verified | [Record recovery](remediation-logic.md#record-recovery) |
| `proposal_not_found` | The record of the PR that proposed this update cannot be found | [Matching existing PRs](remediation-logic.md#existing-pr-matching) |

## Stored files {#stored-records}

Remediation plan records are stored under `remediation.storage_dir`.

| File or directory | Contents | Save point |
| --- | --- | --- |
| `plan.json` | Latest plan, source locations, scans used for comparison, and check results for dependency updates that ran | After dependency-update processing, before PR processing |
| `delivered.json` | Separate identifiers for the delivered plan and the content displayed in Slack | After delivery of the corresponding notification |
| `prs.json` | PR identities, states, creation attempts, recreation suppression, and GitHub operation records | During PR processing, reconciliation, and operation-result recording |
| `tools` | Cache of retrieved and verified npm, pnpm, and uv distributions | During tool retrieval and related operations |

`prs.json` also stores waiting times for re-resolution through dependent packages, consecutive deferral counts by type, and stop records for each set of inputs.
These records are also updated after dependency-update processing.

`plan.json` is not saved again with PR processing results.
Notifications contain the current run's PR processing results, while `prs.json` holds the records used for ongoing management.

See [Record save order](remediation-logic.md#record-order) for the relationship between storage and PR processing and [Storage location](configuration.md#remediation-storage) for configuration.
