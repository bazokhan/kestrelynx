---
description: "Observe container executions and file opens with bpftrace using the programs and results from an actual experiment. Covers tracepoints, cgroup attribution, observation timing, and lost records."
---

# Observing Container Execution and File Opens with bpftrace

Published: September 19, 2026

## Introduction

Files used by running container processes can be identified through `/proc/<pid>/exe`, `maps`, and related interfaces.
Periodic reads, however, can miss a process that exits between samples or a file that is opened only briefly.
For the procfs approach, see [How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md).

To address this gap, we tested recording program executions and file opens as they happen, using bpftrace.
In a case that repeatedly ran short-lived curl and git processes, all 116 executions independently logged within the observation window matched execution events.
However, a Node.js load that finished before observation began was not captured, and some collection configurations lost records.

This article references the programs used in those measurements to explain event collection, container attribution, and the results.

The [Interactive Guide to the bpftrace Measurement Workflow](bpftrace-event-observation-interactive.md) follows one `curl` run inside a container in nine steps, from execution and file-open activity through output lines to events with a container ID.

## What the Tests Covered

We compared application-side logs with bpftrace records in two cases.

| Case | Application-side record | Question tested |
| --- | --- | --- |
| Repeated curl and git executions | Time, PID, executable, and other details of each execution | Can events capture short-lived process executions? |
| Loading lodash in Node.js | Time of each `require` and files newly added to the module cache | Can corresponding file opens be captured, and does observation timing change the result? |

The results below come from these two cases within an investigation conducted on September 13–16, 2026.
The environment and observation conditions were as follows.[^measurements]

- OS and kernel: Linux 6.6 on WSL2
- Architecture: amd64
- Container environment: native Docker Engine
- cgroup: v2
- Collection tool: bpftrace 0.25.0
- Collector privileges: root
- Observation window: 300 seconds per run

Required privileges for non-root collection and collection overhead were not measured.

## Programs Used for the Measurements

A bpftrace script collected events, while Go code converted the records and identified their containers.
The main components in the published source are:

| Program | Role |
| --- | --- |
| [runtime-events-nofilter-512p.bt](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/bpftrace/runtime-events-nofilter-512p.bt) | Records executions and file opens with timestamps, process identity, and cgroup IDs |
| [cgroup.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/cgroup.go) | Builds and updates a mapping from cgroup IDs to container IDs |
| [convert.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/convert.go) | Pairs open entry and exit records, adds container information, and converts the records to JSONL |

The measurements were orchestrated by [case-run.sh](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/tools/case-run.sh).
Prerequisites, build instructions, and commands are in the [experiment README](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/README.md).

## Recording Executions and File Opens

bpftrace is a tracing tool that uses eBPF.
It can attach actions to Linux kernel tracepoints and collect information when events occur.[^bpftrace]
The script uses seven tracepoints:

| Activity | Tracepoints | Information collected |
| --- | --- | --- |
| Program execution | `sched:sched_process_exec` | Executable path, timestamp, and process identity |
| File-open entry | `syscalls:sys_enter_open`, `sys_enter_openat`, `sys_enter_openat2` | Supplied path and, for `openat` and `openat2`, the directory file descriptor |
| File-open exit | `syscalls:sys_exit_open`, `sys_exit_openat`, `sys_exit_openat2` | System call return value |

### Distinguishing an Execution Attempt from an Execution

`sched_process_exec` fires after a successful switch to a new program.
An attempt to execute a nonexistent file therefore does not count as an execution.
The event confirms that execution began; it does not confirm that the program's work finished successfully.[^exec-source]

### Pairing Open Entry and Exit Records

At file-open entry, the supplied path is available, but the outcome is not yet known.
The implementation pairs entry and exit using the thread ID and entry timestamp, then treats a nonnegative return value as success.[^open]
Failed opens remain in the output as `ok:false`. Records with no matching entry or exit are counted separately as unmatched.

In the measured Alpine environment, programs using musl called the legacy `open` system call, so tracing only `openat` and `openat2` missed those opens.
The script therefore includes `open` as well.[^measurements]

The recorded path is the string the program passed to the system call.
A relative path needs a base directory. This implementation leaves it unresolved when a matching working-directory record is unavailable or when it is relative to an arbitrary directory file descriptor.
It does not resolve symbolic links either.[^reference]

## Attributing Events to Containers

A short-lived process may already have exited by the time a collector receives its event and tries to inspect `/proc/<pid>`.
The script therefore records the cgroup ID at the moment of the event.

`cgroup.go` walks the host's `/sys/fs/cgroup` hierarchy and builds a mapping from directory names containing Docker container IDs.
The converter uses this mapping to add a container ID to each attributable event.
The mapping retains the history of cgroup additions and removals so that lookups can account for the event's time.[^reference]

Comparing events with logs inside a container also requires accounting for PID differences.
In the WSL2 environment, numbers in the kernel's initial PID namespace differed from those recorded inside the container.
The script records both sets of numbers, the container-side PID namespace identifier, and the process start time so that records can be matched to the same process.[^reference]

## Results for Short-Lived Executions

This case tested how many short-lived curl and git executions bpftrace could capture.
Both commands ran repeatedly, followed by a five-second wait, while the container's [loop.sh](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/cases/images/13-short-lived/loop.sh) logged each execution.
The workload started after a known event had been captured to check that bpftrace was ready.

We compared the curl and git execution records written by loop.sh with the execution events collected by bpftrace.
For each logged execution, we checked the executable path, process identity, and timestamp to find an event representing the same execution.
The rightmost column counts executions for which the two records could be paired one to one.[^exec-runs]

| Buffer setting for the run (`perf_rb_pages`) | curl and git executions in the workload log | Executions also confirmed by bpftrace |
| --- | --- | --- |
| 64 pages | 116 | 116 |
| 256 pages | 116 | 116 |
| 512 pages | 116 | 116 |

The workload log contained 116 curl and git executions in each 300-second observation window.
In all three runs, bpftrace also confirmed all 116 executions.

## Lost Records at Each Buffer Setting

Alongside checking the target executions, we checked whether records were lost during collection.
The three runs above used record buffer settings of 64, 256, and 512 pages.

The record buffer holds records emitted by the kernel-side tracing program until bpftrace reads them.
Records are lost if reading cannot keep up and the buffer overflows.[^bpftrace]

The script emits a separate record for a program execution, the start of a file open, and the end of a file open.
For example, one file open produces two records: an entry and an exit.
The following table counts records that bpftrace reported as lost, using `lost_events` collected from its loss notifications.[^exec-runs]

| Buffer setting (`perf_rb_pages`) | Records reported lost by bpftrace |
| --- | --- |
| 64 pages | 2,790 |
| 256 pages | 12 |
| 512 pages | 0 |

Losses were reported in the 64- and 256-page runs, but not in the 512-page run.
The collector implementation also changed between these runs, so this was not a comparison in which only buffer capacity changed.

These counts cover the entire collection, including host activity and other containers, as well as the target curl and git executions.
The contents of the lost records are unknown, so 2,790 or 12 cannot be translated into a number of missed executions or file opens for a particular program.
The previous table reports matches for the 116 target executions; this table counts loss reports across the collector.

### Results for Path Collection

Identifying a file requires obtaining its path as well as avoiding lost records.
We therefore also counted how often the script obtained an empty string when collecting an executable or file-open path.
An empty path is counted as a path-read failure.[^exec-runs]

| Buffer setting (`perf_rb_pages`) | Empty paths counted across the collector |
| --- | --- |
| 64 pages | 661 |
| 256 pages | 667 |
| 512 pages | 1,088 |

This is a separate count from records lost through the buffer.
Empty paths occurred even in the 512-page run, so zero reported losses alone does not establish that paths were obtained as well.

## How Observation Timing Changes the Result

In the Node.js case, [app.js](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/cases/images/17-node-require/app.js) calls `require('lodash')`.
The application compares the module cache before and after the call and records newly added files.
Those files are then checked for open events from the same process within the matching time interval.

| When observation started | Result |
| --- | --- |
| Before the first `require` | File-open evidence was found for the one uncached `require` |
| After the first `require` finished | Loading had already finished, so its file-open evidence was not captured |

Both runs used a 256-page buffer and reported zero `lost_events`.
The second `require` used the cache and was excluded from the comparison of new file loads.[^node-runs]

Event observation captures operations that happen after observation starts.
To capture a file loaded only once at startup, observation must begin before that load.

The units compared here were individual executions and `require` calls.
The total number of file opens was not independently recorded, so the proportion of all opens captured was not measured.
The implementation also excludes opens through `creat` and io_uring, and does not determine whether a file's contents were read or its code executed after it was opened.[^reference]

## Summary

Recording execution events with bpftrace lets you confirm a short-lived execution even after its process exits.
For file opens, the entry path and exit return value together identify successful operations.
Cgroup IDs recorded at event time were used to attribute activity to containers.

The measurements captured the target short-lived executions, while loads completed before observation began were not captured.
When reading results, check the observation window, lost records, and availability of fields such as paths alongside matches to the target operations.

## References

///Footnotes Go Here///

[^bpftrace]: [bpftrace 0.25: language, tracepoints, and configuration](https://bpftrace.org/docs/release_025/language)

[^exec-source]: [Linux: sched_process_exec definition](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/trace/events/sched.h?h=v6.6) and [exec implementation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exec.c?h=v6.6)

[^open]: [Linux man-pages: open(2)](https://man7.org/linux/man-pages/man2/open.2.html)

[^reference]: [Measurement program: input, output, attribution, and limitations](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/REFERENCE.md)

[^measurements]: [Runtime Evidence Observation with eBPF: measurement results](../development/runtime-event-evidence.md#results-2026-09-16)

[^exec-runs]: `csv_hc/occurrence_capture.csv` and `csv_hc/event_drops.csv` from saved runs `13-root-30-300-p0-r1-startup-nofilter64p`, `13-root-30-300-p0-r2-startup-nofilter256p`, and `13-root-30-300-p0-r3-startup-nofilter512p`. See `case-run.sh` linked above for the procedure and the [public development log](../development/runtime-event-evidence.md#results-2026-09-16) for the results overview.

[^node-runs]: `csv_hc/occurrence_capture.csv` and `csv_hc/event_drops.csv` from saved runs `17-root-30-300-p0-r1-startup-nofilter256p` and `17-root-30-300-p0-r1-attach_running-nofilter256p`, using lodash installed through npm. See `case-run.sh` linked above for the procedure and the [public development log](../development/runtime-event-evidence.md#results-2026-09-16) for the results overview.

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack or a webhook.

Remediation plans and pull requests (experimental) for Docker, Compose, and Kubernetes support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[About KestreLynx](../index.md) · [View source on GitHub](https://github.com/kitsunetrail/kestrelynx)
