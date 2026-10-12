## What

KestreLynx proposes a newer tag for the base image of `build/Dockerfile` in `example/app`, against base branch `main` at commit `1111111111111111111111111111111111111111`.

- Base image now: `app:2.0`
- Edited: the FROM of stage 1, line 3
- Workloads built from it: `compose/app/web`

## Change

- FROM on line 3: `debian:12.5` to `debian:12.6`

## Verification

- Running image: `nginx:1.25.3`, config digest `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, platform `linux/amd64`
  - The running digest comes from the container runtime; whether it is the image config digest or an index or manifest digest is not confirmed.
- Current base image: `debian:12.5`, tag digest `sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`, platform manifest `sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`, config digest `sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd`, platform `linux/amd64`
- Candidate base image: `nginx:1.25.4`, tag digest `sha256:1111111111111111111111111111111111111111111111111111111111111111`, platform manifest `sha256:2222222222222222222222222222222222222222222222222222222222222222`, config digest `sha256:3333333333333333333333333333333333333333333333333333333333333333`, platform `linux/amd64`
- Layer check: `confirmed`; the current base image has 3 layer(s) and the running image 7. A match shows that the filesystem layers agree; it does not show how the image was built.
- Verification record: plan generated at 2026-10-09T04:00:00Z, scan of the current base `scan-base-1`, scan of the candidate base `scan-cand-1`
- Findings this update targets (fixed findings of the running image in the base image's layers): resolved 2, remaining 1
- Other findings of the compared base images that remain in the candidate base image: 1; introduced by the candidate base image: 0

**Resolved (2)**

- `CVE-2026-0001` in `libc6` (`debian`, `os`), severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`
- `CVE-2026-0002` in `openssl` (`debian`, `os`), severity `HIGH`

**Remaining among the targeted findings (1)**

- `CVE-2026-0003` in `zlib1g` (`debian`, `os`), severity `HIGH`

**Other findings that remain in the candidate base image (1)**

- `CVE-2026-0004` in `tar` (`debian`, `os`)

**Introduced (0)**

- none

Both base images were scanned by Trivy `0.71.2` with the vulnerability database built at 2026-10-09T01:02:03Z. Severity range: `CRITICAL`, `HIGH`. Scope: `os packages`.

Trivy attributes a package to the lowest layer that holds that name and version, so a package installed again by a later instruction of the Dockerfile can still be attributed to a base image layer. A finding listed above is therefore matched to the base image, not proven to come from it.

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->