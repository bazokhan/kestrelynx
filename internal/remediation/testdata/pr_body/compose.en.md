## What

KestreLynx proposes a new image tag for 2 Compose service(s) in `compose.yml` of `example/app`.

- Running image: `nginx:1.25.3`
- Services edited: `web`, `worker`
- Workloads running them: `compose/app/web`, `compose/app/worker`
- Also running this image, not edited (no Compose mapping): `app/extra (app-extra-1)`, `loose`

## Change

- `services.web.image`: `nginx:1.25.3` to `nginx:1.25.4`
- `services.worker.image`: `nginx:1.25.3` to `nginx:1.25.4`

## Verification

- Running: `nginx:1.25.3`, config digest `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, platform `linux/amd64`
  - The running digest comes from the container runtime; whether it is the image config digest or an index or manifest digest is not confirmed.
- Candidate: `nginx:1.25.4`, tag digest `sha256:1111111111111111111111111111111111111111111111111111111111111111`, platform manifest `sha256:2222222222222222222222222222222222222222222222222222222222222222`, config digest `sha256:3333333333333333333333333333333333333333333333333333333333333333`, platform `linux/amd64`
- Locations: `services.web.image`, `services.worker.image`
- Verification record: plan generated at 2026-10-09T04:00:00Z, baseline scan `scan-base-1`, candidate scan `scan-cand-1`
- Resolved 2, remaining 1, introduced 0

**Resolved (2)**

- `CVE-2026-0001` in `libc6` (`debian`, `os`), severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`
- `CVE-2026-0002` in `openssl` (`debian`, `os`), severity `HIGH`

**Remaining (1)**

- `CVE-2026-0003` in `zlib1g` (`debian`, `os`), severity `HIGH`

**Introduced (0)**

- none

Both images were scanned by Trivy `0.71.2` with the vulnerability database built at 2026-10-09T01:02:03Z. Severity range: `CRITICAL`, `HIGH`. Scope: `os packages`.

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->