---
description: "A validation of matching procfs observations to OS packages and Trivy findings: limited ground-truth comparisons, missed short-lived processes, unsupported language packages, and unevaluated coverage."
---

# How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans

Published: September 16, 2026

## Introduction

Trivy reports many vulnerability findings, including findings for packages
that are not actually used in the container. Prioritizing findings for
packages in use requires checking each package's usage.
Trivy findings alone cannot establish usage, so runtime information
is needed.

This article examines whether files observed through procfs can be mapped
to OS packages and matched to Trivy findings. Matching worked for some
packages used by resident processes, while short-lived processes were
missed and language packages could not be mapped through OS ownership
information.[^measurements] The complete set of packages actually used
was not established, so the completeness of runtime-use detection remains
unevaluated.

This article covers the following:

- What Trivy findings alone cannot show.
- What loaded-package evidence proves, and what it leaves unanswered.
- What was tested and established with stock images, self-built images, and an operational host.
- The scope of ground-truth comparisons and the coverage that remains unevaluated.
- How to combine runtime evidence with KEV and EPSS.
- A compact way to inspect the same relationship on a Docker host.

## What Trivy findings alone cannot show

In this article, a finding is a package, installed version, and CVE
tuple produced by matching detected software against vulnerability
information. Counts are CVE × package, so multiple findings can refer to
the same package.[^trivy]
Counts describe the number of these combinations, while severity describes
the seriousness of the reported vulnerabilities.

Findings have the following limitations:

- They do not show whether the package is actually used in this container.
- They do not show whether its vulnerable functionality was reached.
- Adding KEV or EPSS does not show whether the affected package is used in this environment.
    - CISA KEV identifies CVEs with evidence of exploitation in the wild; see [KEV Catalog Basics and Usage](kev-known-exploited-vulnerabilities.md).[^kev]
    - FIRST EPSS estimates exploitation likelihood over the next 30 days; see [EPSS Basics and How to Check Scores](epss-exploit-prediction-scoring-system.md).[^epss]

Checking a package's runtime usage therefore requires information (runtime
evidence) connecting an observed process to a package and version in this
container. Confirmed package use supports addressing the associated
findings first among those with the same urgency, without changing the
urgency assessed using KEV, EPSS, severity, and other factors.
Record usage separately from KEV and EPSS assessments so that the reason
for addressing those findings first remains clear.

## Meaning of “used at runtime”

Here, “used at runtime” means that a running process has loaded an executable
or shared library from the package. Loading is observed through procfs using
`/proc/<pid>/exe` and `/proc/<pid>/maps`.[^proc][^exe][^maps]

This definition establishes the following:

- A process was executing or mapping that file at the sample time.
- The file's owning package and version match the package and version in the finding.

It does not establish the following:

- Whether a vulnerable function was executed.
    - Observing loading does not show which functions were called.
- That an unobserved package is unused.
    - It may load during another request, in a different worker, or between samples.

Confirmed package use therefore supports addressing the associated
findings first among those with the same urgency. If use cannot be
confirmed, that does not establish that the package is unused, so it is
not a reason to lower priority.[^harness]

For details on handling observed paths, ownership, and versions, see the
[procfs process-to-package mapping article](procfs-process-to-package-mapping.md).

## Validation details

The validation followed the process of reading files used by running
processes, identifying their owning OS packages and versions, and matching
them to Trivy findings for the same image. For a limited set of packages
whose use was established separately, it also checked whether the
collector detected them.

The results below separate successful mapping from detection within the
available ground-truth scope.

- **Targets**
    - Stock images: `nginx:1.27`, `postgres:16`, and `nginx-unprivileged:1.27-alpine`.
    - Self-built images, each adding a small program to an official base image to reproduce a specific situation: `python:3.12-slim` with a cryptography wheel, `debian:12-slim` with a static Go server, and Debian cases reproducing short-lived processes and temporary `dlopen`.
    - Operational sample: four containers (static Go, JVM with bundled JDK, two Node.js) on a separate Ubuntu host; one root run with AppArmor enabled.
    - Main environment: one WSL2 host, Linux 6.6.114, Docker Engine 29.1.3; scanner: Trivy v0.71.
- **Procedure**
    - Scan the running container's image ID.
    - Periodically observe `/proc/<pid>/exe` and executable mappings in `maps` for host PIDs from `docker top`.
    - Resolve file ownership through container dpkg/apk databases and match package names and versions to findings.
- **Conditions and criteria**
    - Baseline: 10 root samples, every 30 seconds over 300 seconds.
    - Compare seven intervals, windows, and start-time combinations to check short-lived process capture.
    - Confirmation requires matching the scanned image, package name, and version; never guess unknown ownership.
- **Accuracy checks**
    - Self-built images: compare program usage logs for misses and false positives within their scope.
    - Official images: manually map resident-process files to check only misses.
    - Neither confirms execution of vulnerable code itself.

The [public measurement results](../development/runtime-prioritization.md#results-2026-09-12)
describe the runs, and the measurement harness contains the collection
procedure.[^measurements][^harness] The results describe these environments
and targets. Misses and false usage classifications were not evaluated
for targets whose actual use or non-use was not established.

## Validation results for stock and self-built images

The first check was whether observed files could be assigned to packages
and matched to scan findings. This table describes that process; it does
not establish that every package in use was detected.[^measurements][^harness]

| Target | What was tested | What was established or remained unresolved |
| --- | --- | --- |
| Debian-based nginx and PostgreSQL | Match loaded files to scan findings through dpkg ownership information | Observed executables and shared libraries could be assigned to packages and linked to corresponding findings |
| Alpine-based nginx | Perform the same matching through apk ownership information | Observed files could be mapped to apk packages and matched to corresponding findings |
| Python with a cryptography wheel | Map Python and its extensions through OS ownership information | Some observed OS libraries could be matched, but Python and its extensions had no OS-package owner; pip-package findings could not be matched |
| A statically linked Go server | Identify embedded dependencies from the executable | The executable was observed, but it had no OS-package owner and its embedded Go modules could not be identified by this method |

For nginx, loaded shared-library paths were mapped to packages such as
`libssl3` and `zlib1g`, then matched to Trivy findings for the same package
names and versions. This demonstrated the path from an observed file to
a finding. It did not determine whether an unobserved package was unused
or had been missed.

## The scope of ground-truth comparisons

For packages whose use was established separately from the collector,
the comparison counted detections and misses. Nginx used manual checks of
resident-process files; the self-built cases used their programs' own
usage logs.

The table uses the baseline condition: root collection, every 30 seconds
for 300 seconds. It counts packages, not CVEs or vulnerability findings.
It includes packages with Trivy findings of any severity whose use was
established separately.[^ground-truth]

| Target | Packages independently established as used and included in the comparison | Detected by the collector | Missed |
| --- | --- | ---: | ---: |
| Resident nginx processes | 4 packages: `libc6`, `libssl3`, `zlib1g`, and `libcrypt1` | 4 | 0 |
| Self-built short-lived process case | 2 packages: `curl` and `git` | 0 | 2 |
| Self-built temporary library-loading case | 1 package: `libsqlite3-0` | 1 | 0 |

The nginx manual check covered six packages, but `nginx` and
`libpcre2-8-0` had no vulnerability findings in this scan, leaving four
packages in the comparison. Those four were detected; use outside that
comparison set was not established.

In the short-lived process case, the baseline missed both `curl` and
`git`, even though their execution was recorded in the usage logs. The
temporary-loading case detected `libsqlite3-0`, without establishing that
other loading durations would also be captured. Results under different
conditions are described below.

## Limitations observed on an operational host

The same mapping process was tried on an Ubuntu host running a static Go
service, a JVM with a bundled JDK, and two Node.js services. Collection ran
once as root with AppArmor enabled, sampling every 30 seconds for
300 seconds.[^measurements]

| Target examined | Limitation observed |
| --- | --- |
| Language packages such as Go modules, JARs, and npm packages | Could not be mapped through OS-package ownership information |
| OS packages with HIGH/CRITICAL findings | No loading of their files was observed; actual use or non-use was not established |
| `/usr/local/bin/node`, the bundled JDK, and the static Go executable | Had no ownership information in the OS package database |

The observations on this host could not be matched to HIGH/CRITICAL
findings. The check established the need for other mapping methods for
language packages and executables outside the OS package database.[^measurements][^harness]
The complete set of packages actually used was not known, so these results
do not yield recall for operational workloads.

## Limits of this measurement method

This method can miss short-lived processes and temporary library loading.
OS ownership information also cannot map language packages, statically
linked dependencies, or executables outside the package database.

### Short-lived processes

Sampling misses processes that run briefly and exit before a sample is
taken. Capture depends on the starting time as well as the interval.

- Curl, running for about 0.1 seconds every 5 seconds, was captured once in 30 samples taken every 10 seconds over 300 seconds.
- At the baseline starting offset, 30-second and 60-second intervals over 300 seconds captured curl 0 times.
- Git was captured 0 times across all seven tested conditions.[^measurements]

These are counts of samples that saw a process, not proportions of
executions captured, and they do not yield a general miss rate.

### Temporary library loading

A temporary `dlopen` can begin and end between samples.

- SQLite, loaded for 7 seconds and unloaded for 7 seconds, was confirmed in all seven conditions and captured in 3 of 10 samples under the baseline condition of sampling every 30 seconds for 300 seconds.[^measurements]

Temporary loading can be observed and needs measurement, but these results
do not guarantee capture of shorter loading periods.

### Language packages

OS ownership information cannot identify Python extensions, Go modules,
JARs, or npm packages, so a visible extension file does not establish the
language package and version reported by the scanner.
Observing Python or Node.js alone also does not confirm use of its
dependencies.[^harness]

- In Python with a cryptography wheel, pip-package findings could not be mapped through OS ownership information, and neither the Python executable nor its extensions had an OS-package owner.[^measurements]

For language software packaged by a distribution, ownership identifies
only the distribution package; a separate language-package finding still
requires additional mapping.

### Static linking

A statically linked executable has no shared-library mappings, leaving
no separate library paths and ownership information to connect its
embedded dependencies to findings.

- In the Debian-based static Go test, the executable was observed but had no owner in the OS package database, so it could not be matched to findings.[^harness]

Failure to match the executable does not mean that it has no vulnerabilities.

### Executables outside the package database

An executable outside the OS package database can be readable without an
identifiable owning package.

- On the operational host, `/usr/local/bin/node`, the bundled JDK, and the static Go executable were outside the OS package database.[^harness]

Do not infer ownership from a filename or directory; record the missing
relationship separately from a failed process read.

## Use of runtime evidence in remediation prioritization

When package use is confirmed at runtime, use that information to support
addressing the associated findings first among those with the same urgency,
without changing the urgency assessed using KEV, EPSS, severity, and other
factors. If use is not confirmed during the observation period, that does
not establish that the package is unused, so do not lower priority on that
basis.
Record usage separately from KEV and EPSS assessments and use it to inform
remediation decisions.

| Layer | What it answers | What it cannot answer |
| --- | --- | --- |
| KEV | Has exploitation of this CVE been established? | Whether this container loads the affected package[^kev] |
| EPSS | How likely is exploitation in the forecast period? | Whether this particular container will be compromised[^epss] |
| Runtime evidence | Was the package version observed through an executable or mapping here? | Whether the vulnerable function was reached[^harness] |

Keep every finding in the remediation workflow and attach its observation
result using the classifications from the procfs mapping article:

| Classification | Meaning |
| --- | --- |
| `confirmed` | A valid sample linked an executable or mapping to the finding's OS package name and version |
| `unknown` | Failed reads, missing metadata, ambiguous ownership, or identity/version problems prevented a reliable conclusion |
| `unobserved` | Valid collection produced no confirming evidence, including unsupported language-package mapping |

The `confirmed`, `unknown`, and `unobserved` classifications used in this measurement are separate from KestreLynx's [runtime usage](../documentation/runtime-usage.md) classifications of `in_use`, `not_observed`, and `unavailable`.
In KestreLynx, language ecosystems without a supported usage rule are classified as `unavailable`.

These classifications describe evidence, not severity.
Retain the observation time, successful sample count, and reason for an
unsuccessful match alongside the classification.[^harness]

Apply them as follows:

- A confirmed HIGH finding gains environment-specific evidence supporting investigation before other findings with the same urgency, without changing its assessed urgency.
- An unobserved HIGH finding for a KEV-listed CVE is still urgent; sampling absence does not cancel exploitation evidence.
- An unknown finding needs its collection problem investigated while retaining its existing remediation priority.
- An unobserved language-package finding needs appropriate mapping evidence, not a claim that its runtime never loaded it.

Avoid presenting the confirmed count as the complete fix list.
Attach an explanation such as “this installed package version was mapped
by this process at this time” to the existing finding.

## Verification procedure on your own host

This procedure manually checks whether running processes in one container
load packages reported by the scan.
It assumes a Debian-based container with `dpkg-query`, Trivy, and `jq`
available on the host.

Run these commands on the Linux Docker Engine host.
Replace placeholders with actual values before execution.

List the container's processes, then select a returned host PID.[^docker-top]

```bash
docker top '<container>' -eo pid,ppid,user
```

Extract executable file mapping paths for that PID. The expression retains
the pathname after removing the fixed columns.[^maps]

```bash
sudo awk '$2 ~ /x/ && $5 != 0 && $6 ~ /^\// {
  for (i = 0; i < 5; i++) sub(/^[^[:space:]]+[[:space:]]+/, "")
  print
}' '/proc/<host-pid>/maps'
```

Example output:

```text
/usr/sbin/nginx
/usr/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/libssl.so.3
```

Query the container's dpkg database through its process root. This example
uses the recorded libc path; a mapped `/usr/lib` path may correspond to a
database entry under `/lib`.[^root][^dpkg-query]

```bash
sudo dpkg-query --admindir='/proc/<host-pid>/root/var/lib/dpkg' \
  -S /lib/x86_64-linux-gnu/libc.so.6
```

Finally, scan the image ID used by that container and extract OS finding
identities from JSON.[^reporting]

```bash
trivy image --scanners vuln --format json '<running-image-id>' |
  jq -r '.Results[] | select(.Class == "os-pkgs") |
    .Vulnerabilities[]? |
    [.PkgName, .InstalledVersion, .VulnerabilityID] | @tsv'
```

Compare the resolved package with `PkgName`, then verify its version from
the container's package metadata against `InstalledVersion`. An ownership
query alone does not complete version confirmation.

This is a manual spot check. Repeat collection across the container's
processes before drawing conclusions about its observed packages. For
merged-`/usr` aliases, symlink ownership, permissions, and reliable version
matching, follow the [full procfs procedure](procfs-process-to-package-mapping.md).

## References

The measurements in this article were made on September 12, 2026.

- The [public development log](../development/runtime-prioritization.md#results-2026-09-12) records the measurement results and their limits.
- These results describe specific hosts and workloads, not overall recall or proof that unobserved packages are unused.

///Footnotes Go Here///

[^measurements]: [Runtime Evidence Prioritization: Feasibility Research, Results (2026-09-12)](https://kestrelynx.dev/development/runtime-prioritization/#results-2026-09-12)

[^ground-truth]: Based on the saved `gtb.json` and `csv_all/gt_b.csv` records for `1-root-30-300-p0-r2`, `9-root-30-300-p0-r1`, and `10-root-30-300-p0-r1`. Comparison-set size, detections, and misses correspond to `population`, `tp`, and `fn`. See the [published sampling collector README](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.md) for ground-truth scope and aggregation definitions.

[^trivy]: [Trivy: Vulnerability scanning](https://trivy.dev/docs/latest/guide/scanner/vulnerability/)

[^kev]: [CISA: Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

[^epss]: [FIRST: EPSS Frequently Asked Questions](https://www.first.org/epss/faq)

[^proc]: [Linux manual: proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)

[^exe]: [Linux manual: proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)

[^maps]: [Linux manual: proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)

[^docker-top]: [Docker: docker container top](https://docs.docker.com/reference/cli/docker/container/top/)

[^root]: [Linux manual: proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)

[^dpkg-query]: [Debian: dpkg-query(1)](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)

[^reporting]: [Trivy: Reporting](https://trivy.dev/docs/latest/configuration/reporting/)

[^harness]: [Runtime discovery measurement harness and README](https://github.com/kitsunetrail/kestrelynx/tree/main/experiments/runtime-discovery)

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack or a webhook. For Docker and Compose, remediation plans and pull requests (experimental) support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[Learn more about KestreLynx](../index.md) · [View the source on GitHub](https://github.com/kitsunetrail/kestrelynx)
