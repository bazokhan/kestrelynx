---
description: "Read Linux process information without running as root. Covers CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, ptrace access checks, file permissions, measured permission combinations, and the collector used for the measurements."
---

# Reading Process Information Without Root Using Linux Capabilities

Published: September 17, 2026

## Introduction

Linux exposes a running process's executable and mapped libraries through
`/proc`. This information helps check runtime usage of packages reported
by container vulnerability scans. Reading another user's process
information, however, may require additional permissions.

Linux capabilities let a collector run as a non-root user with selected
privileges. To narrow the privileges granted to the collector, the
validation checked which capability combinations could retrieve the
information collected as root. Using root collection as the baseline,
it compared three non-root conditions: no capabilities, `CAP_SYS_PTRACE`
alone, and `CAP_SYS_PTRACE` with `CAP_DAC_READ_SEARCH`.

The following combinations worked in the measurement
environment.[^measurements][^procfs-article]

| Information collected | Capabilities required for non-root collection in the measurement |
| --- | --- |
| Executables and loaded libraries used to check package usage (`exe` and `maps`) | `CAP_SYS_PTRACE` |
| The above plus information linking listening sockets to processes (`fd/`) | `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` |

This article covers the following:

- Linux capabilities relevant to reading process information.
- How ptrace access checks and file permissions interact.
- Measured results for four root and non-root permission conditions.
- The actual measurement collector and how it records its results.
- What to check when access still fails.

## What Linux capabilities are

Linux capabilities divide traditional root privileges by operation.
They are maintained per thread; permission checks use the effective
set.[^capabilities]

Two capabilities are particularly relevant here:

| Capability | Role |
| --- | --- |
| `CAP_SYS_PTRACE` | Authorizes ptrace operations and access to protected process information under `/proc` |
| `CAP_DAC_READ_SEARCH` | Bypasses ordinary file-read and directory-read/search permission checks |

`CAP_SYS_PTRACE` also permits operations that modify another process's
memory. `CAP_DAC_READ_SEARCH` is not limited to `/proc`.
Grant these capabilities only to programs needed for collection, and
restrict which users can execute those programs.[^capabilities]

## Why CAP_SYS_PTRACE is not enough to read everything

In the measurement, granting `CAP_SYS_PTRACE` to the non-root collector
allowed it to read `exe` and `maps`. Listing `fd/` still failed with a
permission error. Adding `CAP_DAC_READ_SEARCH` allowed that operation to
succeed.[^procfs-article]

The difference comes from two separate checks: permission to access the
target process's information, and permission to access a directory.

### Permission to read exe and maps

The `exe` link identifies the executable, while `maps` describes memory
mappings, including loaded files. When these entries are read, Linux
checks whether the reader may access the target process's information.
This is the ptrace access check, where `CAP_SYS_PTRACE` is
relevant.[^exe][^maps][^ptrace]

In the measurement environment, granting `CAP_SYS_PTRACE` allowed the
collector to pass this check and identify executables and loaded
libraries.[^procfs-article]

Linux manuals call the read check used for `exe` and `maps`
`PTRACE_MODE_READ_FSCREDS`. Despite the name, this checks permission to
read information without attaching a debugger.[^ptrace]

### Permission to list fd/

The `fd/` directory contains links to a process's open files and sockets.
Inspecting them involves listing the directory first, then reading each
link.[^fd]

In the measurement, the target's `fd/` was owned by root with mode `0500`.
The non-root collector lacked permission to list it. `CAP_SYS_PTRACE`
did not bypass that restriction, so enumeration failed with `EACCES`
(permission denied).[^procfs-article][^fd-source]

Adding `CAP_DAC_READ_SEARCH` bypassed the directory-permission restriction
and allowed enumeration. Reading the links afterward also involves a
ptrace access check, as with `exe`.[^capabilities][^fd]

With only `CAP_SYS_PTRACE`, the collector could therefore confirm package
use through loaded files, but could not use `fd/` to attribute listening
sockets to processes.[^procfs-article]

Similarly, reading a container file through `/proc/<pid>/root` requires
both access to process information and permissions on the files and
directories reached through that link.[^root] Required permissions depend
on the target; procfs mount settings and Linux Security Modules (LSMs),
such as AppArmor and SELinux, also impose restrictions.[^proc][^ptrace]

## Results for four permission conditions

The September 12, 2026 measurement compared four conditions for a collector
running directly on a Docker host. The main environment was WSL2 Linux
6.6.114 and Docker Engine 29.1.3, with no `hidepid` restriction. Non-root conditions used file capabilities on the
compiled executable.[^measurements][^procfs-article][^harness]

Yama was set to `ptrace_scope=1` during the measurement. This setting does
not directly restrict the `exe` and `maps` reads used here.[^yama-source]

| Collector condition | Package-use confirmation | Listener attribution | Main result |
| --- | --- | --- | --- |
| Root | Baseline | Available | Baseline collection succeeded |
| Non-root with `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` | Same as root | Same as root | Obtained the information compared in this measurement |
| Non-root with `CAP_SYS_PTRACE` | Same as root | Unavailable | Listing `fd/` was denied |
| Non-root without capabilities | Every sample failed observation | Unknown | Required process information could not be collected |

In this environment, `CAP_SYS_PTRACE` alone allowed reading `exe`, `maps`,
namespace links, and package metadata through `root`. Permissions inside
a container may require `CAP_DAC_READ_SEARCH` for metadata access as
well.[^procfs-article]

Failure without capabilities does not mean that every procfs entry,
including `status`, was unreadable. The table describes whether collection
provided the information required to confirm package use.

Non-root capability combinations remain unverified with an AppArmor
profile applied to the collector.
In a later [operational-environment validation](../development/runtime-environment-validation.md),
the collector ran unconfined under AppArmor, and a non-root collector with
`CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` achieved 12/12 valid reads and
matched root on every compared measure.
These results do not establish a universal minimum permission set for Linux
hosts.[^measurements]

## The program used for the measurement

The four permission conditions were measured with `runtime-discovery`, a
collector implemented in Go. The published sampling version (`ed7813e`)
is available in its [README](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.md) and
[source code](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/procfs.go).

### What it reads

The collector obtains container host PIDs through the Docker API, then
reads the host's `/proc`. The main read operations are implemented in the
published version of [procfs.go](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/procfs.go).

| Function | Information read | Relevant permissions |
| --- | --- | --- |
| `readExe` | The `exe` link target | Identifying the executable involves a ptrace read access check |
| `readMaps` | Executable file mappings in `maps` | Identifying loaded files involves a ptrace read access check |
| `socketInodesForPID` | Entries in `fd/` and socket inodes from their links | Both directory permissions and ptrace checks on the links apply |
| `readStatus` | The target process's effective UID and `CapEff` | Records the privileges of the observed process |

`socketInodesForPID` first lists `fd/`, then reads each link. With only
`CAP_SYS_PTRACE`, the measurement failed at the enumeration step. Package
use could still be confirmed through mappings, but the information needed
to attribute listening sockets to a PID was unavailable.

### How permission conditions and failures are recorded

The collector's `-permission` argument labels the condition in the
results. It does not grant privileges.[^harness]

| Label | Measurement condition |
| --- | --- |
| `root` | Run as root |
| `ptrace` | Run as non-root with `CAP_SYS_PTRACE` on the compiled executable |
| `ptrace_dac` | Run as non-root with `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` |
| `none` | Run as non-root without capabilities |

The permission comparison used a compiled executable, rather than
`go run`. The published [README](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.md) describes the environment,
build, collection, and matching procedures.

Failed operations are retained in the observations. After matching,
`permissions.csv` reports the operation, result, occurrence count, and
error message, among other fields. The output is implemented in
[match_report.go](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/match_report.go). This allows comparison of which
operations failed under each permission condition and how those failures
affected package-use confirmation.

## When access still fails

### Check both the file configuration and runtime privileges

`getcap` reports file capabilities, not the privileges of an already
running process.[^getcap] Compare it with `CapEff` in the reader's
`/proc/<pid>/status`. The collector's `readStatus` function records the
observed target's privileges, so check the collector's privileges separately. Running `cat /proc/self/status` reports information about `cat`;
use the specific PID when checking another process.[^status]

| Check | Effect |
| --- | --- |
| Launcher's `NoNewPrivs` | A value of `1` prevents gaining new privileges through file capabilities |
| `nosuid` on the executable's mount | File capabilities are not applied at execution |
| Launcher's `CapBnd` | Limits capabilities obtainable at execution |
| Rebuilding or replacing the executable | File capabilities may not survive; check again |

Inspect the launcher's `/proc/<pid>/status` for `NoNewPrivs` and `CapBnd`.
Inspect mount options on the filesystem containing the collector's
executable. Execution restrictions can also cause startup
itself to fail with `Operation not permitted`, before any procfs
read.[^execve][^status]

Granting capabilities to a general-purpose interpreter such as a shell or
Python extends privileges to the programs it can execute. Limit capability grants to the collection executable and check its
ownership and write permissions.

### Check namespace visibility and host restrictions

A capability held inside a container does not necessarily authorize the
same operation on a host process. Check the relationship between the
reader's and target's user namespaces. PID namespaces also affect which
PIDs are visible: the target must exist in the reader's procfs
view.[^userns][^proc]

`hidepid` may restrict other users' process information, and AppArmor or
SELinux policies may deny access. Inspect procfs mount options and host
audit logs before adding capabilities.[^proc][^ptrace]

Record the path and operation for each failure. Distinguish permission
errors such as `EACCES` and `EPERM` from errors such as `ENOENT` caused by
a disappearing process or path. This helps determine whether additional
permissions would address the failure.

### Treat Docker API permissions separately

Reading host procfs and accessing the Docker API require separate
permissions. The measurement collector also uses the Docker API to obtain containers
and their PIDs.[^harness]

When the socket is used to obtain containers or PIDs from a conventional
rootful Docker Engine, access can itself permit root-level operations on
the host. A collector that sends only GET requests does not make its
socket access read-only.[^docker]

## References

This article is based on information verified as of September 17, 2026.
The four-condition table is based on the September 12 measurement using
the Go collector.

///Footnotes Go Here///

[^capabilities]: [Linux manual: capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
[^ptrace]: [Linux manual: ptrace(2), access mode checking](https://man7.org/linux/man-pages/man2/ptrace.2.html)
[^exe]: [Linux manual: proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
[^maps]: [Linux manual: proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
[^fd]: [Linux manual: proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
[^fd-source]: [Linux 6.6: procfs fd directory implementation](https://github.com/torvalds/linux/blob/v6.6/fs/proc/fd.c)
[^root]: [Linux manual: proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
[^proc]: [Linux kernel: The /proc Filesystem](https://docs.kernel.org/filesystems/proc.html)
[^yama-source]: [Linux 6.6: Yama access checks](https://github.com/torvalds/linux/blob/v6.6/security/yama/yama_lsm.c)
[^status]: [Linux manual: proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
[^getcap]: [libcap: getcap(8)](https://man7.org/linux/man-pages/man8/getcap.8.html)
[^execve]: [Linux manual: execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
[^userns]: [Linux manual: user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
[^docker]: [Docker: Linux post-installation steps](https://docs.docker.com/engine/install/linux-postinstall/)
[^measurements]: [Runtime evidence prioritization measurement results](../development/runtime-prioritization.md#results-2026-09-12)
[^procfs-article]: [How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md)
[^harness]: [Sampling collector README (published version ed7813e)](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.md)

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack or a webhook. For Docker and Compose, remediation plans and pull requests (experimental) support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[Learn more about KestreLynx](../index.md) · [View the source on GitHub](https://github.com/kitsunetrail/kestrelynx)
