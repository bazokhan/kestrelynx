## What

KestreLynx proposes updating 2 package entries in `svc/package-lock.json` of `example/app` with `npm`.

- Dependency directory: `svc`
- Package manager: `npm`
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

### Packages updated along with the fix

These packages required older versions of the packages above and were updated within the ranges in `package.json`.

- `mkdirp`: `0.5.1` to `0.5.6` (it required `minimist` `0.0.8`)

### Manifest edits

The version specifier of these direct dependencies did not allow a fixed version, so it was edited before the lockfile was updated.

**1 edit(s) below allow a new major version (for 0.x, a new minor version) and no longer allow the one before. Review these first: the application may need changes.**

- `svc/package.json`, `dependencies`, `minimist`: `^0.2.0` to `^1.2.8` — **major version change**
- `svc/package.json`, `devDependencies`, `lodash`: `^4.17.0` to `^4.17.21`

## Verification

- Runtime: `node24` `24.21.0`, from the official image `node@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
- Package manager: `pnpm` `11.28.2` (this build's default version, which the version ranges the project declares allow), archive sha256 `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd`

**Operations run**

- `pnpm update lodash`, exit code 0
- `pnpm install --lockfile-only`, exit code 0 (run on a scratch copy; its result was only compared)

**Lockfile entries**: 1 added, 1 changed, 0 removed (the lists are cut)

Changed:

- `lodash@4.17.20 -> 4.17.21`

Added:

- `semver@7.5.4`

Every version the update added or changed was looked up in the npm registry and compared with the distribution the lockfile points at.

- `eslint@9.39.4` gained a deprecation note. Its author deprecated it on npm, which has nothing to do with this update
- The deprecation note of `glob@7.2.3` changed. Its author changed it on npm, which has nothing to do with this update
- `tar@6.2.1` is deprecated on npm. The note belongs to the updated version, and equals what npm publishes for it
- `rimraf@3.0.2` lost its deprecation note. Its author removed it on npm, which has nothing to do with this update

**Entries whose dependencies moved to newer versions along with the update (1)**

- `browserslist@4.28.2`: `caniuse-lite` `1.0.30001792` to `1.0.30001806`

- Note from the run: `the declared packageManager differs from the one installed`

**Scan of the dependency files before and after (Trivy, filesystem mode)**

- Before: `svc/pnpm-lock.yaml sha256:aaaaaaaaaaaa`
- After: `svc/pnpm-lock.yaml sha256:bbbbbbbbbbbb`
- Resolved 2, remaining 1, introduced 0 (over every package of the files, not only the updated ones)
- The findings of the two scans were compared by package, version and vulnerability ID; the number of lockfile entries and of requirements that point to a version with a vulnerability was compared too; and every requirement into an entry with a vulnerability that the original did not have as it is was checked place by place against the original
- 2 vulnerabilities stay at the same place in a version the update moved to (for example `CVE-2026-0001` for `rc` `1.2.8` to `1.2.9`); the update does not fix them.
- The lists below are cut

**Resolved (2)**

- `CVE-2026-1111` in `lodash` `4.17.20`, severity `CRITICAL`, in the CISA KEV catalog, fixed in `4.17.21`
- `CVE-2026-2222` in `minimist` `0.2.1`

**Remaining (1)**

- `CVE-2026-3333` in `semver` `7.5.4`, severity `HIGH`

**Introduced (0)**

- none

Both scans used Trivy `0.71.2`, the vulnerability database built at 2026-10-09T01:02:03Z, the same severity range (`CRITICAL`, `HIGH`) and the same settings; the repository's own Trivy configuration, ignore files and VEX documents were not read.

- Before merging, run a CI job that installs from the lockfile (for example `npm ci`)

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->