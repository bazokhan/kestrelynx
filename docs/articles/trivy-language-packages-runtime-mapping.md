---
description: "Documents how Trivy detects Python, Node.js, Java, and Go packages and how to map those packages to files observed at runtime. Covers RECORD, package.json, JARs, Go binaries, measured results, and the limits of file-level evidence."
---

# Mapping Language Packages Detected by Trivy to Runtime Files

Published: September 20, 2026

## Introduction

Container image vulnerability scans report more than OS packages. They also find Python packages installed with pip, npm dependencies, libraries in JARs, and modules embedded in Go binaries.
To investigate whether a running container uses these packages, scan findings need to be matched to files observed at runtime.

We tested this mapping with containers that load known dependencies, comparing file information collected through procfs with execution and file-open records collected through bpftrace.
For the Python, Java, and Go cases, extending file collection and mapping was enough to attach evidence to scan findings.
The Node.js case required events captured during loading; starting observation after the load did not confirm the package.

This article explains the information Trivy uses to identify packages and how to trace an observed file back to those packages.
For event collection itself, see [Observing Container Execution and File Opens with bpftrace](bpftrace-container-exec-open-events.md).

## What the Tests Covered

The tests covered the following four cases.
We used usage logs written by the programs inside the containers, together with package ownership information, to establish the comparison targets. We then checked whether observed files could be mapped to those packages' scan findings.[^measurements]

| Target | Container behavior | Package used for comparison |
| --- | --- | --- |
| Python | Imports cryptography and keeps the process alive | cryptography 41.0.0 |
| Node.js | Requires lodash installed through npm | lodash 4.17.15 |
| Java | Loads a log4j-core class from an ordinary JAR | org.apache.logging.log4j:log4j-core 2.14.1 |
| Go | Executes a static binary containing a dependency module | golang.org/x/text v0.3.0 |

The measurement conditions were as follows.

- OS and kernel: Linux 6.6 on WSL2
- Architecture: amd64
- Container environment: native Docker Engine, cgroup v2
- Scanner: Trivy 0.71.2
- Event collection: bpftrace 0.25.0, root privileges, `perf_rb_pages=256`
- Observation window: 300 seconds per run, with procfs sampled every 30 seconds

## How Trivy Identifies Language Packages

Trivy extracts package names and versions from metadata or binaries in the scan target and matches them against vulnerability information.
Scanning dependency definitions in a source repository uses different inputs from scanning packages installed in a container image.[^trivy-language]

| Target | Examples for source or dependency definitions | Examples for installed files |
| --- | --- | --- |
| Python | `requirements.txt` or `poetry.lock` | `.dist-info/METADATA` or `.egg-info` information[^trivy-python] |
| Node.js | `package-lock.json` or `pnpm-lock.yaml` | Each installed package's own `package.json`[^trivy-node] |
| Java | `pom.xml` or Gradle lock files | `pom.properties` and `MANIFEST.MF` inside a JAR; identification through Trivy Java DB when information is insufficient[^trivy-java] |
| Go | `go.mod` | Dependency module and Go version information embedded at build time[^trivy-go] |

Detecting a dependency establishes that the scan target contains corresponding package information.
It does not show which files a running process opened.

### What the Paths in JSON Represent

In these scans, language packages had `Class: lang-pkgs`.
The path used for mapping appeared in either `Vulnerabilities[].PkgPath` or `Results[].Target`, depending on the target.
These examples are taken from the saved JSON.[^runs]

| Target | `Type` | Field containing the path | Recorded value |
| --- | --- | --- | --- |
| Python | `python-pkg` | `PkgPath` | `usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info/METADATA` |
| Node.js | `node-pkg` | `PkgPath` | `app/node_modules/lodash/package.json` |
| Java | `jar` | `PkgPath` | `app/log4j-core-2.14.1.jar` |
| Go | `gobinary` | `Target` | `server` |

The Python and Node.js paths identify package metadata, rather than the code that ran.
Directly comparing an observed `.so` or `.js` path with those fields will therefore not produce a match.
For Java and Go, the JAR or binary itself provides the mapping entry point.

## Programs Used for the Measurements

The following published programs performed collection and matching.

| Program | Role |
| --- | --- |
| [collect.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/collect.go) and [aux.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/aux.go) | Collect executable, maps, and fd information from procfs, plus file lists and symbolic links for package mapping |
| [mapping.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/mapping.go) | Resolves observed paths to files and packages in the scan |
| [series.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/series.go) | Compares confirmed counts as collected information and event evidence are added |
| [gtb_case.py](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/tools/gtb_case.py) | Builds comparison ground truth from container usage logs and ownership information |

[case-run.sh](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/tools/case-run.sh) orchestrated the measurements.
Build instructions and execution steps are in the [experiment README](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/README.md).

## Tracing an Observed File Back to a Package

Identify which package an observed file belongs to, then match it against scan findings for the same image.
The information used differs by language.

### Python: Use the List of Installed Files

- Package ownership identified through the installed-file list in `RECORD`[^python-record]
- Package name and version in the owner's `METADATA` matched against Trivy's findings
- Test case: the loaded native extension's `.so` file mapped to cryptography

### Node.js: Check Where the File Is Installed

- Package within `node_modules` identified through the loaded file's location
- Name and version in that package's `package.json` matched against Trivy's findings
- Test case: file-open records under `node_modules/lodash` mapped to lodash's findings

### Java: Match the Open JAR

- JARs held open by the JVM identified through the process's file information
- JAR paths matched to findings for libraries contained in those JARs
- Test case: the open `log4j-core-2.14.1.jar` mapped to log4j-core's findings

### Go: Match the Running Binary

- Dependency modules included in the same executable in a static Go binary
- Running binary identified and mapped to modules Trivy detected through its embedded build information[^trivy-go]
- Test case: execution of `server` mapped to findings for its embedded golang.org/x/text module

## Results by Method

We compared confirmed counts at three stages using the same measurement records.

1. **Earlier rules:** mapping of procfs executable and maps information primarily to OS packages
2. **With additional methods:** the earlier rules plus information such as file descriptors and the language-package mappings described above
3. **With event evidence:** all information from the previous stage plus records of successful executions and file opens attributed to the target container within the observation window

The table shows results when observation began before the target operation.
The comparison covers HIGH/CRITICAL vulnerability findings for the specified package in each case.
Each method column counts how many of those findings could be linked to usage evidence.[^runs]

| Comparison target | Findings for the target package | Earlier rules | With additional methods | With event evidence |
| --- | --- | --- | --- | --- |
| cryptography | 5 | 0 | 5 | 5 |
| lodash (npm) | 4 | 0 | 0 | 4 |
| log4j-core (ordinary JAR) | 3 | 0 | 3 | 3 |
| golang.org/x/text (static Go binary) | 4 | 0 | 4 | 4 |

### Starting Observation After Loading

In the same Node.js case, starting observation after the first `require` left lodash's confirmed count at zero, even with event evidence.
The Python, Java, and Go cases retained file information that could be mapped during sampling, so their counts with additional methods did not change.[^runs]

This difference concerns how long runtime evidence remains available, rather than the scanner's detection capability.
Node.js `require` caches loaded modules, so observing for longer after missing the initial load does not guarantee that the file will be opened again.[^node-cache]

## Considerations When Interpreting the Results

This approach confirms observations of files belonging to a package, or execution of a binary containing it.
A successful file open alone does not establish that contents were read, a vulnerable function was reached, or an attack could succeed.
For Go, confirming execution of a binary does not establish that individual module functions ran.
For a JAR containing multiple libraries, opening the outer file does not establish that each library was loaded.

An unconfirmed package is not necessarily unused, either.
Loads before observation, brief file use, lost events, missing ownership metadata, and layouts outside the collection scope need to be distinguished.

This comparison used a small number of test packages in a single environment.
It does not establish coverage of complete production applications or miss rates by method.
File usage evidence can supplement remediation prioritization, but absence of evidence alone should not remove a finding from consideration.

## Summary

Language-package mapping uses installed-file lists for Python, file locations for Node.js, JAR files for Java, and executable binaries for Go.
Tracing the relationship between metadata paths reported by the scan and files observed at runtime makes it possible to attach evidence to findings.

Some measured cases retained enough information for sampling, while another required events captured during loading.
Keeping the observed file, evidence granularity, and observation window with a mapping result makes its basis clear.

## References

///Footnotes Go Here///

[^trivy-language]: [Trivy: language scanning coverage](https://trivy.dev/docs/latest/coverage/language/)

[^trivy-python]: [Trivy: Python](https://trivy.dev/docs/latest/coverage/language/python/)

[^trivy-node]: [Trivy: Node.js](https://trivy.dev/docs/latest/coverage/language/nodejs/)

[^trivy-java]: [Trivy: Java](https://trivy.dev/docs/latest/coverage/language/java/)

[^trivy-go]: [Trivy: Go](https://trivy.dev/docs/latest/coverage/language/golang/)

[^python-record]: [Python Packaging User Guide: recording installed projects](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)

[^node-cache]: [Node.js: CommonJS module caching](https://nodejs.org/api/modules.html#caching)

[^measurements]: [Runtime Evidence Observation with eBPF: measurement results](../development/runtime-event-evidence.md#results-2026-09-16)

[^runs]: `trivy_hc.json` and `csv_hc/series.csv` from saved cases 15, 17, 19, and 22, with run names `<case>-root-30-300-p0-r1-startup-nofilter256p` and `<case>-root-30-300-p0-r1-attach_running-nofilter256p`. Python uses the configuration with a `.pyc` cache; Java uses the ordinary JAR. See `case-run.sh` linked above for the procedure and the [public development log](../development/runtime-event-evidence.md#results-2026-09-16) for the results overview.

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack or a webhook. For Docker and Compose, remediation plans and pull requests (experimental) support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[About KestreLynx](../index.md) · [View source on GitHub](https://github.com/kitsunetrail/kestrelynx)
