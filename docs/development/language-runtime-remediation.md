# Development of remediation plans for language runtimes

- **Status:** Implemented (rebuild guidance verified in the production environment and PR creation on a validation host)
- **Started:** October 25, 2026
- **Last updated:** October 25, 2026

## Purpose

Include remediation guidance for vulnerabilities in the runtimes of official `node` and `python` images in remediation plans.
Following [Development of language runtime vulnerability notifications](language-runtime-advisories.md), connect runtime findings to base image updates and rebuild guidance.

## Background

Runtime findings are derived from versions in the image configuration and lack information about their originating layers, so they were excluded from existing remediation plans for Dockerfile base image updates.
The remedy depends on the Dockerfile's tag specification and whether the release line is still supported.

| Specification or status | Remedy |
| --- | --- |
| Pinned tag (`FROM node:22.23.3-alpine`) | Change the tag to a fixed version |
| Floating tag (`FROM node:22-alpine`) | Pull the updated base and rebuild, with no line to change |
| End-of-life release line (such as Node.js 18) | Move to a newer release line because no fixed version will be released in the current line |

## Approach

- **Integration with existing base image updates**
    - Add runtime information to existing Dockerfile base image update assessments without creating a new remediation path
- **Guidance through notification annotations**
    - Show expected rebuild outcomes for floating tags and the need to move manually to a newer release line for end-of-life runtimes

## Data sources

| Information | Purpose |
| --- | --- |
| Layer sequences and image configurations of the running image and current base | Check layer correspondence and matching `NODE_VERSION` / `PYTHON_VERSION` values |
| Runtime versions in the current base and candidate, and security information from the language developers | Use existing runtime matching to compare candidates and estimate rebuild outcomes |

## Decisions

- **Attribution and comparison for pinned tags**
    - Attribute runtime findings to the base when the current base's layer sequence matches the beginning of the running image in order and both image configurations have the same `NODE_VERSION` / `PYTHON_VERSION` value for that runtime
    - Include runtime matching when comparing the current base and candidate, and reject the candidate if matching cannot be performed on either side
- **Expected rebuild outcomes for floating tags**
    - When the base cannot be confirmed, report how many currently detected CVEs are expected to disappear if the rebuilt image inherits the runtime version in the current base
    - This does not compare completed application images, count CVEs introduced by the new version, or change the assessment
    - Also include the installed and base versions, CVEs expected to disappear, and remaining CVEs in the generic webhook's `rebuild_runtimes`
- **Guidance according to the build method**
    - Recommend `docker compose build --pull` when the Dockerfile is found through Compose's `build`
    - When the Dockerfile is found only through a configuration mapping, account for builds in CI and similar environments by recommending “pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again”
- **End-of-life release lines**
    - Put guidance to move to a newer release line in the finding's notification annotation because images without a fixed version do not receive a remediation plan item
    - Use the annotation “end-of-life: no fix will be released for this series, so the series has to be upgraded (manual)”

Detailed conditions are covered in [Base layer matching](../documentation/remediation-logic.md#base-layer-matching), and notification interpretation in [Rebuild guidance](../documentation/remediation-results.md#rebuild-guidance).

## Verification methods

- Use unit tests to check runtime attribution, candidate comparison, expected rebuild outcomes, and end-of-life annotations
- Verify remediation plans and rebuild guidance for images using floating tags in the production environment
- Verify pinned-tag images on a validation host, from base matching through PR creation

## Verification results

### Floating tags in the production environment

Both the frontend and backend use `FROM node:22-alpine` and are built in CI.
Both remediation plans showed guidance to rebuild and redeploy through CI, along with the following estimate.

> Node.js in the current node:22-alpine is 22.23.4; if the rebuild takes over this version, 3 of the 3 findings of the detected Node.js 22.23.3 are expected to disappear (the rebuilt image is not checked)

The three CVEs are CVE-2026-105482, CVE-2026-106069, and CVE-2026-111497.

### Pinned tags on the validation host

A validation repository contained a Dockerfile with `FROM node:22.23.3-alpine`, and an image built from that same Dockerfile was run.
The base's four layers matched the beginning of the running image, and `NODE_VERSION` also matched, so the Node.js findings were attributed to the base.

Comparison with the candidate `node:22.23.4-alpine` produced the following results.

| Comparison scope | Result |
| --- | --- |
| Three Node.js runtime findings | Resolved |
| Nine findings in packages under npm included in the base | Remaining |
| Newly introduced findings | 0 |

A PR changing `FROM` to `node:22.23.4-alpine` was created, and its “Resolved” section listed the three Node.js findings.
The generic webhook also reported PR creation.

## Known limitations

- **Differences between image configuration and executables**
    - Replacing only the `node` / `python` executable in an upper layer cannot be distinguished if the version environment variable remains the same
    - Reinstalling the runtime in the Dockerfile or overriding its version with `ENV` can invalidate the expected rebuild outcome
- **Verification after rebuilding**
    - Floating-tag estimates are not results from checking the rebuilt image

## Unverified areas and next steps

- **Python and end-of-life release lines**
    - PRs for pinned Python tags, expected Python rebuild outcomes, and annotations for end-of-life release lines have been checked only in unit tests
- **Other languages**
    - Support for runtimes such as PHP, Ruby, and Java remains a future consideration

## Update history

### October 25, 2026

- Recorded implementation and verification in the production environment and on a validation host

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
