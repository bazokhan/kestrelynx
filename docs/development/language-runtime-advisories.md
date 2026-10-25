# Development of language runtime vulnerability notifications

- **Status:** Implemented (notifications verified for Node.js in the production environment and Python on a validation host).
- **Started:** October 25, 2026
- **Last updated:** October 25, 2026

## Purpose

Include vulnerabilities in the runtimes of official `node` and `python` images in notifications.
The scope covers Node.js for npm and pnpm, and Python for uv.

## Background

Official images install Node.js at `/usr/local/bin/node` from a nodejs.org tarball and build CPython from source under `/usr/local`; neither runtime is an OS package or a language package, so Trivy does not detect them.
As a result, runtime vulnerabilities such as Node2Shell (CVE-2026-111497) are absent from notifications.

## Approach

- **Matching image configuration against information from the language developers**
    - Match `NODE_VERSION` and `PYTHON_VERSION` from the image configuration against security information published by each language's developers
- **Public data retrieval and local assessment**
    - Download public data and assess it within KestreLynx without sending information about scanned images externally

## Data sources

| Runtime | Data sources |
| --- | --- |
| Node.js | Version ranges from the nodejs/security-wg core index, supplemented by the nodejs.org security blog for missing CVEs, with the release list and nodejs/Release schedule |
| Python | The PSF advisory database, CPython version ranges in official CVE records, the python.org release list, and the release cycle |

Python CVEs from before mid-2023 are not matched because they lack version ranges.

## Decisions

- **Findings and Sensor usage assessment**
    - Runtime findings use `node-runtime` and `python-runtime`, separate from Trivy's types
    - Sensor assesses usage through execution evidence associated with the executable path
- **Matching and record retention with unavailable data**
    - During any cycle in which required data cannot be retrieved, skip matching for that runtime, retain its records without treating them as resolved, and annotate notifications to state that matching could not be performed
    - Node.js and Python are handled independently, so missing data for one does not prevent normal matching for the other
- **Boundary between notifications and remediation**
    - The current scope is notifications only, excluding Dockerfile base image updates and remediation PRs
    - The version in the image configuration does not necessarily match the actual binary

## Verification methods

- Use unit tests with downloaded real data to check version matching and findings
- Verify Node.js notifications and execution evidence in the production environment running Docker and Sensor
- On a validation host running Docker and Sensor, verify Python and Node.js notifications, along with which matching stops and which records are retained when Python data is unavailable

## Verification results

### Node.js in the production environment

| Target | New finding | Usage shown in the notification |
| --- | --- | --- |
| Frontend | `Node.js [node-runtime]` 22.23.3 → 22.23.4 | In use (running) |
| Backend | `Node.js [node-runtime]` 22.23.3 → 22.23.4 | In use (running) |

Three CVEs appear under the default `HIGH` and `CRITICAL` severity selection: CVE-2026-105482, CVE-2026-106069, and CVE-2026-111497.

### Python on the validation host

For `python:3.12.14-slim`, the default severity selection produces the following four findings for `Python runtime` 3.12.14.
Sensor execution evidence classifies usage as “In use (running).”

| CVE | Severity | Fixed version |
| --- | --- | --- |
| CVE-2026-115557 | `CRITICAL` | None |
| CVE-2026-19445 | `CRITICAL` | 3.12.15 |
| CVE-2026-19553 | `HIGH` | 3.12.15 |
| CVE-2026-82049 | `HIGH` | 3.12.15 |

Node.js on the same host is also checked, with six findings for the 22.23.1 Web service under the default severity selection and usage classified as in use.
The 26.12.1 container has no applicable findings.

### Unavailable Python data

With no Python cache and a nonexistent release list URL, matching is skipped only for Python.
The generic webhook's `runtime_unchecked` array contains the following item.

```json
{"image": "python:3.12.14-slim", "package": "Python runtime"}
```

The four Python records are retained without being treated as resolved.
Node.js matching proceeds normally in the same cycle.

## Known limitations

- **Dependence on image configuration**
    - Images without the corresponding `NODE_VERSION` or `PYTHON_VERSION` variable are not checked
    - For Node.js, this includes images containing only a node binary copied from another image and distroless images without `NODE_VERSION`
    - If the image configuration version differs from the actual binary, matching uses the image configuration version
- **Node.js affected ranges**
    - Blog posts do not identify the first affected version, so vulnerabilities introduced partway through a release line can also be reported for older versions in that line
    - Errors in security-wg ranges carry through to matching
- **Older Python CVEs**
    - CVEs from before mid-2023 are not matched because they lack version ranges

## Unverified areas and next steps

- **Node.js runtime remediation**
    - For floating tags such as `FROM node:22-alpine`, a candidate approach is to suggest rebuilding to obtain the fix
    - For pinned tags such as `FROM node:22.23.3-alpine`, a candidate approach is a PR changing the tag to a fixed version
    - Both approaches require a decision on how to check whether the node binary has been replaced
- **Other languages and older CVEs**
    - Official images for other languages such as PHP, Ruby, and Java, together with NVD for older CVEs, remain future considerations

## Update history

### October 25, 2026

- Runtime notifications and verification

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
