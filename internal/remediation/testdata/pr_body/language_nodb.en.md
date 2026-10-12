## What

KestreLynx proposes updating 2 package entries in `svc/pnpm-lock.yaml` of `example/app` with `pnpm`, against base branch `main` at commit `1111111111111111111111111111111111111111`.

- Dependency directory: `svc`
- Package manager: `pnpm`
- Workloads running these packages: `compose/app/web`
- Files changed: `svc/pnpm-lock.yaml`, `svc/package.json`

**1 package(s) move to another major version (for 0.x, another minor version). Review these first: the application may need changes.**
**1 manifest edit(s) allow a new major version and no longer allow the one before; see Manifest edits below.**

## Change

Running version to version after the update, with how the project requires the package:

- `lodash`: `4.17.20` to `4.17.21` (direct dependency)
- `minimist`: `0.2.1` to `1.2.8` (transitive dependency) — **major version change**
- `odd`: `2.0.0` to `2.0.1` (relation not known)

### Vulnerabilities this update targets

- `CVE-2026-1111` in `lodash`, severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`
- `CVE-2026-2222` in `minimist`, severity `HIGH`

### Manifest edits

The version specifier of these direct dependencies did not allow a fixed version, so it was edited before the lockfile was updated.

**1 edit(s) below allow a new major version (for 0.x, a new minor version) and no longer allow the one before. Review these first: the application may need changes.**

- `svc/package.json`, `dependencies`, `minimist`: `^0.2.0` to `^1.2.8` — **major version change**
- `svc/package.json`, `devDependencies`, `lodash`: `^4.17.0` to `^4.17.21`

## Why these versions

For each package the target is the lowest version that the vulnerability data lists as fixed for every vulnerability found in the running image; the version in the updated file is the lowest version of the package it holds.

## Verification

The update ran in a throwaway container built from a fixed work image, with fixed operations and no credentials. Its result was treated as untrusted and checked by KestreLynx itself.

**Operations run**

- `pnpm update lodash`, exit code 0
- `pnpm install --lockfile-only`, exit code 0 (run on a scratch copy; its result was only compared)

**Lockfile entries**: 1 added, 1 changed, 0 removed (the lists are cut)

Changed:

- `lodash@4.17.20 -> 4.17.21`

Added:

- `semver@7.5.4`

Every version the update added or changed was looked up in the npm registry and compared with the distribution the lockfile points at.

- Note from the run: `the declared packageManager differs from the one installed`

**Scan of the dependency files before and after (Trivy, filesystem mode)**

- Before: `svc/pnpm-lock.yaml sha256:aaaaaaaaaaaa`
- After: `svc/pnpm-lock.yaml sha256:bbbbbbbbbbbb`
- Resolved 2, remaining 1, introduced 0 (over every package of the files, not only the updated ones)
- The lists below are cut

**Resolved (2)**

- `CVE-2026-1111` in `lodash` `4.17.20`, severity `CRITICAL`, in the CISA KEV catalog, fixed in `4.17.21`
- `CVE-2026-2222` in `minimist` `0.2.1`

**Remaining (1)**

- `CVE-2026-3333` in `semver` `7.5.4`, severity `HIGH`

**Introduced (0)**

- none

Both scans used Trivy `0.71.2`, the same severity range (`CRITICAL`, `HIGH`) and the same settings; the repository's own Trivy configuration, ignore files and VEX documents were not read. The scan shows that the target vulnerabilities are no longer detected in the lockfile; it is a check of the source files, not of an image.

## Not verified

- Whether the image built from these files has the vulnerabilities resolved: the image is not rebuilt or scanned, and what a build installs can differ from the lockfile
- Whether the application works with the updated packages, and its tests: compatibility and tests were not run
- Whether the dependencies in the updated files agree exactly with what the registry declares for each version, and whether the installer accepts the format: both were checked only as far as possible, so run a CI job that installs from the lockfile (for example `pnpm install --frozen-lockfile`) before merging
- Continuous integration; opening this pull request may start the repository's CI
- Deployment after merge: merging changes the files only, and running containers keep the old image until it is built again and they are recreated
- Vulnerabilities of severities outside the range above

---

Opened by KestreLynx. Update key `uk3`, attempt key `ak3`.

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->