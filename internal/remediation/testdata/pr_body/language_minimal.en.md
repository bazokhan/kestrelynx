## What

KestreLynx proposes updating 1 package entry in `svc/pnpm-lock.yaml` of `example/app` with `uv`, against base branch `main` at commit `1111111111111111111111111111111111111111`.

- Dependency directory: `svc`
- Package manager: `uv`
- Workloads running these packages: `compose/app/web`
- Files changed: `svc/pnpm-lock.yaml`

## Change

Running version to version after the update, with how the project requires the package:

- `lodash`: `4.17.20` to `4.17.21` (direct dependency)

### Vulnerabilities this update targets

- `CVE-2026-1111` in `lodash`, severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`

## Why these versions

For each package the target is the lowest version that the vulnerability data lists as fixed for every vulnerability found in the running image; the version in the updated file is the lowest version of the package it holds.

## Verification

The update ran in a throwaway container built from a fixed work image, with fixed operations and no credentials. Its result was treated as untrusted and checked by KestreLynx itself.


## Not verified

- Whether the image built from these files has the vulnerabilities resolved: the image is not rebuilt or scanned, and what a build installs can differ from the lockfile
- Whether the application works with the updated packages, and its tests: compatibility and tests were not run
- Whether the dependencies in the updated files agree exactly with what the registry declares for each version, and whether the installer accepts the format: both were checked only as far as possible, so run a CI job that installs from the lockfile (for example `uv sync --locked`) before merging
- Continuous integration; opening this pull request may start the repository's CI
- Deployment after merge: merging changes the files only, and running containers keep the old image until it is built again and they are recreated
- Vulnerabilities of severities outside the range above

---

Opened by KestreLynx. Update key `uk3`, attempt key `ak3`.

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->