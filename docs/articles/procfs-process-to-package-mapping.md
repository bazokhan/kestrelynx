---
description: "Map running Docker container processes to OS packages with procfs, /proc, dpkg, and apk, and understand permissions, path resolution, and sampling limits."
---

# How to Map Running Container Processes to OS Packages with procfs

Published: September 13, 2026

## Introduction

An image vulnerability scan reports findings across the packages it detects
in an image, including packages that the running application may never load.
Linux procfs, usually mounted at `/proc`, provides the executable and files
mapped into each running process, which can be connected to OS packages
using the container's package database.[^proc]

This article covers the following:

- How to collect process and loaded-file evidence from a Docker host.
- How to resolve ownership using dpkg and apk metadata.
- How to handle cases where a path cannot reliably identify a package, along with permission and sampling limits.
- The command examples assume a Linux Docker Engine host and an existing container named `web`. Run them on the machine hosting the daemon.

The [Interactive Guide to the procfs Package Mapping Workflow](procfs-package-mapping-interactive.md) follows one nginx worker inside a container in eight steps, from its loaded `libssl.so.3` through procfs and dpkg records to a match with Trivy findings and confirmation that files from `libssl3` were loaded.

## What a loaded file proves

Finding a library in a process's executable mappings establishes that the
process has loaded code from that file.

| Evidence | What it establishes |
| --- | --- |
| Package detected in an image | The scanner identified installed software |
| Executable or library observed through procfs | A process was executing or mapping that file at the sample time |
| File ownership and version match | The observed path corresponds to the package version in the finding |
| Vulnerable function reached | Not established by this method |

- Here, “used” means loaded into the process, not that a particular function has executed.
- A loaded library provides positive evidence for prioritization.
- A library absent from a sample is not proven unused: another request, worker, or short-lived process may load it later.

## Finding a container's host PIDs

Use Docker's process listing to obtain host PIDs suitable for reading the
host's `/proc/<pid>` entries.

```bash
docker top web -eo pid,ppid,user
```

Example output:

```text
PID          PPID         USER
<master-pid>  <parent-pid>  root
<worker-pid>  <master-pid>  nginx
```

- The first column, `PID`, contains the host PIDs used in `/proc/<pid>` below.
- `PPID` is the parent process's PID and shows that the worker's parent is the master.
- In this example, the row whose `USER` is `root` is the master process, and the row whose `USER` is `nginx` is the worker process.
- On the Linux Docker Engine implementation examined here, Docker obtains process IDs from the container runtime, runs `ps` on the host, and filters the output to those processes.[^docker-top][^moby-top]
- Select a returned PID for the examples below, but a collector must inspect every returned PID, including workers and child processes.

Select the first PID in the process listing and store it in the variable
`pid` for the examples below.

```bash
pid=$(docker top web -eo pid,ppid,user | awk 'NR == 2 {print $1}')
```

- `/proc/<pid>/cgroup` can corroborate membership when its path contains the container ID.
- Path layouts depend on cgroup versions, namespaces, and runtime configuration. A missing recognizable Docker ID is not sufficient reason to reject a PID returned by Docker.

## Reading process evidence under /proc

### Executable and mapped libraries

Read the `exe` link target to check the path of the target process's executable.

```bash
sudo readlink "/proc/$pid/exe"
```

Example output:

```text
/usr/sbin/nginx
```

- `/usr/sbin/nginx` is the path of the target process's executable, which will be matched against package ownership information.
- If the executable has been unlinked, the result ends in ` (deleted)`. A process can continue running after its executable has been removed.[^exe]

Read `maps` to check the executable and libraries mapped by the target process.

```bash
sudo cat "/proc/$pid/maps"
```

Example output:

```text
<range> r-xp <offset> <dev> <inode> /usr/sbin/nginx
<range> r-xp <offset> <dev> <inode> /usr/lib/x86_64-linux-gnu/libc.so.6
<range> r-xp <offset> <dev> <inode> /usr/lib/x86_64-linux-gnu/libssl.so.3
```

- The path at the end of each row identifies a mapped file; this example shows `nginx`, `libc.so.6`, and `libssl.so.3`.
- The `x` in `r-xp` in the second column indicates an executable mapping.
- The `maps` columns contain the address range, permissions, file offset, device major/minor numbers, inode, and optional pathname.[^maps]
- The measured collector keeps rows whose permissions contain `x`, pathname starts with `/`, and inode is nonzero.[^harness]
- This selects executable file mappings, not every file a process has read.
- Anonymous memory and entries such as `[heap]`, `[stack]`, and `[vdso]` do not identify package-owned files.
- Parse the pathname as the remainder of the line after the fixed columns because it can contain spaces.
- Deduplicate by `(path, dev, inode)`, while retaining which process generations mapped each file.
- Mapped files can also carry ` (deleted)`. Removing the suffix for path handling must not discard the deletion evidence.[^maps]

### Effective UID and capabilities

Extract the `Uid` and `CapEff` rows from `status` to check the target
process's effective UID and effective capabilities.

```bash
sudo awk '/^(Uid|CapEff):/' "/proc/$pid/status"
```

Example output:

```text
Uid:    101    101    101    101
CapEff: 0000000000000000
```

- The four numeric UID columns are real, effective, saved, and filesystem UIDs.
- The effective UID is the second numeric value, or field 3 when `Uid:` itself is counted; it is `101` in this example.
- `CapEff` is the effective capability bitmask in hexadecimal.[^status]
- In this example, `CapEff` is all zeros, indicating that the process has no effective capabilities.
- These fields distinguish, for example, a privileged master process from its workers. Associate them with the individual process, not every package in the container.
- With user namespace remapping, host-visible UIDs need interpretation using `/proc/<pid>/uid_map`; they are not necessarily the container-visible UIDs.

### Namespace identity and PID reuse

Record namespace identity and process generations to detect changes during
collection.

Read the namespace links to obtain the identifiers of the network, mount,
and user namespaces to which the target process belongs.

```bash
sudo readlink "/proc/$pid/ns/net" "/proc/$pid/ns/mnt" "/proc/$pid/ns/user"
```

Example output:

```text
net:[<namespace-inode>]
mnt:[<namespace-inode>]
user:[<namespace-inode>]
```

- The `net`, `mnt`, and `user` rows represent the network, mount, and user namespaces, respectively.
- Each value in square brackets identifies a namespace and is used to compare namespaces of the same type between processes or before and after collection.
- These identifiers let a collector group processes by namespace. Processes in one container are not guaranteed to share every namespace.[^namespaces]
- Record `starttime`, field 22 of `/proc/<pid>/stat`, measured in clock ticks since boot. Use `(PID, starttime)` to distinguish process generations.[^stat]
- Do not extract it with a simple whitespace field count: the parenthesized process name can contain spaces and parentheses.
- Read starttime and namespace identity before and after collection. Reject a sample whose identity changed or could not be rechecked, including filesystem and network data read through that PID.
- Recheck Docker's `State.StartedAt` to detect a container restart during collection.

### Listening sockets and their processes

`/proc/<pid>/net/tcp` and `tcp6` expose TCP tables for the process's
**network namespace**, not just sockets belonging to that PID.[^net]

1. Select LISTEN rows, whose state is `0A`.

Extract the local address and port, state, and inode from LISTEN rows to
inspect TCP sockets listening in the target process's network namespace.

```bash
sudo awk 'NR > 1 && $4 == "0A" {print $2, $4, $10}' \
  "/proc/$pid/net/tcp" "/proc/$pid/net/tcp6"
```

Example output:

```text
00000000:0050 0A <socket-inode>
```

- The first column, `00000000:0050`, is the local address and port; in this IPv4 example, it represents `0.0.0.0:80`.
- The second column, `0A`, indicates the LISTEN state.
- Match `<socket-inode>` in the third column against the file descriptor link targets of each process.

2. Enumerate each container process's `fd/` directory and match the inode in its links to the listening row.

List the file descriptor link targets to check the inodes of sockets held
by the process specified in the variable `pid`.

```bash
sudo ls -l "/proc/$pid/fd"
```

Example output:

```text
<fd-number> -> socket:[<socket-inode>]
```

- `<fd-number>` is the target process's file descriptor number.
- If the value in `socket:[<socket-inode>]` matches the inode in a LISTEN row, the process holds a file descriptor for that listening socket.
- Address decoding must account for the host's native byte order within each 32-bit word.[^tcp]
- Preserve every process holding a matching descriptor; a master and workers may share a socket.[^fd]
- Read the TCP tables once per network namespace. A namespace-wide listener without a matching process descriptor remains unattributed.
- A listening socket does not establish that Docker publishes its port or that it is reachable from the internet.

## Resolving paths inside the container

Resolve a mapped path such as `/usr/lib/x86_64-linux-gnu/libc.so.6` against
the process's root.

Store the target process's root in the variable `root` and use it to list
the container's dpkg database directory.

```bash
root="/proc/$pid/root"
sudo ls "$root/var/lib/dpkg"
```

- `/proc/<pid>/root` provides the process's filesystem view, including its mount namespace and per-process mounts.[^root]
- Looking it up in the host's package database would answer a different question.
- Absolute symlinks inside that root must stay inside it. Simply concatenating the root prefix with an arbitrary path does not enforce this.
- A collector handling mutable container filesystems needs kernel-enforced resolution, such as `openat2` with `RESOLVE_IN_ROOT`, relative to an opened root directory.[^openat2]
- The measurement implementation walks symlink components in user space. That handles its cooperative test filesystems, but resolution followed by a separate open is subject to races.[^harness]
- This implementation is not equivalent to the kernel enforcing confinement.

### Debian and Ubuntu: dpkg

Read `/var/lib/dpkg/info/*.list` to build a path-to-package index and
`/var/lib/dpkg/status` to obtain versions.

Read the corresponding `.list` file inside the container to check the
paths of files owned by `libc6:amd64`.

```bash
sudo cat "$root/var/lib/dpkg/info/libc6:amd64.list"
```

Example output:

```text
/lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

- Each row is a path recorded as a file owned by `libc6:amd64`.
- Match the observed executable and library paths against this list.
- The list provides paths, not versions. Parse the corresponding paragraph in `/var/lib/dpkg/status` for the version.

The following excerpt shows the `libc6` paragraph in
`/var/lib/dpkg/status` to inspect next.

Example output:

```text
Package: libc6
Status: install ok installed
Architecture: amd64
Version: <installed-version>
```

- `Package: libc6` and `Architecture: amd64` identify the package name and architecture corresponding to the preceding `.list` file.
- `Status: install ok installed` indicates that the package is installed.
- The `Version` value is the installed version, used to match the package against the scanner's findings.
- A filename such as `libc6:amd64.list` identifies the binary package `libc6`, with `amd64` as its architecture qualifier. Keep architecture distinct from the base package name.
- Retain package name, version, architecture, and whether its file list was available.
- `dpkg-query` can inspect an alternative database with `--admindir`, which is useful for manual checks from the host. Its ownership search uses recorded paths, so aliases still require attention.[^dpkg-query]

### Alpine: apk

Alpine's `/lib/apk/db/installed` contains package records separated by blank
lines, with file ownership stored inline.

Read the installed package database to check the names, versions, and
owned files of apk packages inside the container.

```bash
sudo cat "$root/lib/apk/db/installed"
```

Example output:

```text
P:musl
V:<installed-version>
A:x86_64
F:lib
R:ld-musl-x86_64.so.1
```

- `P` is the package name, `V` its version, and `A` its architecture; this example is a record for `musl` on `x86_64`.
- `F` sets the current directory; each following `R` names a file within it.
- This excerpt therefore assigns `/lib/ld-musl-x86_64.so.1` to `musl`.[^apk]
- Reset directory state at every record boundary. An `R` without a preceding `F` in the same record is malformed.
- Do not borrow another package's directory to make the path appear valid.

### Distroless: status.d

Read package metadata and file lists from the following layout in
Debian-based distroless images.

Example output:

```text
/var/lib/dpkg/status.d/libc6
/var/lib/dpkg/status.d/libc6.md5sums
```

- The first row is the path of the file containing metadata for `libc6`, including its name and version.
- The second row is the path of the `.md5sums` file containing checksum and relative-path pairs.

The following single-line excerpt shows the contents of `libc6.md5sums`.

Example output:

```text
<checksum>  lib/x86_64-linux-gnu/libc.so.6
```

- The first column, `<checksum>`, is the checksum, and the second column, `lib/x86_64-linux-gnu/libc.so.6`, is the file's relative path.
- Prefix the relative path with `/`, then normalize it for the ownership index. This reconstructs file lists without requiring dpkg or a shell in the image.[^distroless]
- Missing `.md5sums` means the package's file list is unavailable. It does not mean its package metadata is absent.
- Here, checksums supply filenames; the collector does not thereby verify the loaded bytes.

### Why not use docker exec?

Reading metadata through procfs keeps the collection commands on the host.

- `docker exec` starts another process inside the container being measured. A shell or package query can therefore appear in the process samples and load additional libraries.
- Distroless images also normally lack a shell and package-manager commands. Reading metadata through procfs avoids adding those dependencies to the target.

## Path and database pitfalls found on real images

### Merged-/usr aliases

On a merged-/usr image, `/lib` may point to `/usr/lib`, so the database and
kernel can describe the same file differently.

| Source | Path |
| --- | --- |
| dpkg `.list` | `/lib/x86_64-linux-gnu/libc.so.6` |
| Process `maps` | `/usr/lib/x86_64-linux-gnu/libc.so.6` |

- In the measured Debian images, `dpkg-query -S` failed on the alias form absent from its recorded list. A failed literal lookup did not mean that libc lacked a package owner.[^harness]
- Resolve directory symlinks inside the container root on both sides of the lookup.
- Apply the same rule to `/bin`, `/sbin`, `/lib64`, and other symlinked directories instead of maintaining a fixed prefix substitution.

### A symlink can belong to another package

In the measured Debian image, the symlink and its target had different owners.
The following example summarizes the observed ownership relationship.

Example output:

```text
libc-bin owns: /usr/bin/ld.so
                         -> loader owned by libc6
```

- The first row shows that `libc-bin` owns the symlink `/usr/bin/ld.so`.
- The arrow points to the target loader, which is owned by `libc6`.
- Following the final symlink while indexing database paths made both packages appear to own the loader. That invented a second owner and prevented an otherwise valid match.
- Resolve the **directory components** of database entries while preserving the final component.
- A package owning a symlink does not thereby own its target. Kernel mapping paths already identify the backing file, so the symlink's ownership need not be transferred to it.

### An empty apk package is not an incomplete database

The Alpine Redis image included the virtual package `.redis-rundeps`,
which groups dependencies and installs no files.

- Its record without `F` or `R` entries is a complete, empty file list.
- Treating it as missing made unrelated unowned files appear unresolved because the whole database was considered incomplete.
- Distinguish a valid empty list from a list that could not be read or parsed. Only the latter leaves ownership information missing.

### Some executables are outside the package database

On one operational host, `/usr/local/bin/node`, a bundled JDK, and a
static Go executable were all outside the OS package file lists.

- The JVM still loaded other libraries whose OS package owners resolved.
- When readable, complete lists contain no owner, record `unowned`.
- Do not infer ownership from an executable name, its installation directory, or a similarly named scanner finding.
- An absent database or missing file list requires a separate result: those conditions do not establish that no package owns the file.

### OverlayFS device numbers can differ

In the dynamically linked test cases, device numbers differed between
`maps` and `stat` through the container root.

- The device recorded in `maps` identified the underlying layer's file, while `stat` through the container root reported the overlay device. Inode numbers matched, but the `dev + inode` pairs did not.
- OverlayFS identity behavior depends on its configuration, so a pair mismatch did not establish file replacement.[^overlayfs]
- Calibrate comparisons against a file expected to remain unchanged, such as a libc mapping. The measured collector left replacement comparison unevaluated when calibration failed.
- Matching inodes alone were an observation, not a validated general replacement-detection method.
- Tests involving an unlinked executable, an unlinked library, and a library replaced by rename all showed deleted mappings.
- Preserve deletion markers independently. Do not assign those old mappings the version currently recorded for a replacement file at the same path.

## Permissions: what was measured and what Linux checks

Required permissions depend on the information being read and the host's
configuration.

| Operation | Relevant checks |
| --- | --- |
| Read `exe` link or `maps` | `PTRACE_MODE_READ_FSCREDS` access check |
| Read namespace links | Ptrace read-access check |
| Traverse `root` and read container files | Ptrace read-access check plus directory and file permissions |
| Enumerate `fd/` and read its links | Directory permissions plus ptrace read-access checks on links |
| Read `status` or TCP tables | Procfs visibility and ordinary permissions; not the same individual ptrace check as `maps` |
| Request Docker process lists | Access to the Docker API |

- In the WSL2 host tests, a non-root collector with `CAP_SYS_PTRACE` could read `exe`, `maps`, `status`, namespace links, TCP tables, and package metadata through `/proc/<pid>/root`.[^harness]
- The tested `fd/` directories were mode `0500` and root-owned. The non-root collector could pass the ptrace check but could not enumerate the directory; listing `fd/` additionally required `CAP_DAC_READ_SEARCH`.
- `CAP_DAC_READ_SEARCH` bypassed that read/search restriction. It may also be needed for protected files inside the container root.[^capabilities]
- A ptrace access check does not mean the collector attaches a debugger. It evaluates credentials, the target's dumpable state, capabilities, and applicable security-module restrictions.[^ptrace]
- `CAP_SYS_PTRACE` must apply in the target's user namespace.
- The capability tests ran on WSL2 Linux 6.6.114 with Docker Engine 29.1.3, Yama `ptrace_scope=1`, and no `hidepid` restriction.
- Non-root capability combinations remain unverified with an AppArmor profile applied to the collector.
- In a later [operational-environment validation](../development/runtime-environment-validation.md), the collector ran unconfined under AppArmor, and a non-root collector with `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` achieved 12/12 valid reads and matched root on every compared measure.
- Yama's `ptrace_scope` restrictions concern attach-mode operations and `PTRACE_TRACEME`; they do not directly restrict these read-mode accesses. Other security policies can still deny reads.[^ptrace]
- These measurements are not a general permission guarantee. Procfs mount options, user namespaces, file modes, and AppArmor or SELinux policies can change the outcome.[^proc]
- Record permission failures separately from processes that exited or package databases that are absent.

## Limits of process-to-package mapping

### Sampling misses short-lived activity

Periodic sampling can miss short-lived processes.

- In one measured run, curl executed for approximately 0.1 seconds every 5 seconds. Sampling every 10 seconds over 300 seconds caught it **once in 30 samples**.
- Sampling every 60 seconds over 600 seconds with no starting offset, and every 30 seconds over 300 seconds with a 7-second starting offset, also caught curl once in 10 samples each; the remaining four conditions caught it zero times, so observation duration and starting time matter as well as frequency.
- A process or a temporary `dlopen` can begin and end entirely between observations.

### Language dependencies need another mapping method

OS package ownership alone does not identify language dependencies.

- Java JARs, npm packages, pip packages, and Go modules are language package identities. This OS ownership lookup does not recover those identities from their contents.
- A JAR or native extension may be visible as a file, and a distribution may package language software, but OS ownership still identifies the distribution package.
- It does not establish which embedded language dependency corresponds to a scanner finding.
- Observing Python does not confirm every pip dependency, and observing Node.js does not confirm every npm package.

### Static linking hides separate library identities

Statically linked code has no separate library pathname for this method
to resolve.

- The tested static Go binaries had no shared-library mappings. Their own executables still appeared through `exe` and in memory mappings.
- Mapping the executable cannot reconstruct its statically linked libraries or Go modules.
- Ownership is a database claim about a path. A file overwritten without updating package metadata, or replaced through a bind mount, can break the assumed relationship between that path and the installed version.

## Putting it together

A collector can repeat the following loop:

1. Enumerate containers and record their IDs, image IDs, and start times.
2. Obtain host PIDs from Docker and establish each process's identity.
3. Read executables, executable mappings, status, namespaces, and sockets.
4. Resolve paths against each process's root and package database.
5. Recheck process and container identity before accepting the evidence.
6. Join resolved package names and versions with the scanner's findings.

- Build ownership indexes per mount namespace and database generation. Revalidate cached metadata between samples and rebuild when it changes.
- If a representative PID exits, try another PID in that mount view before concluding that the database is absent.
- For Trivy OS findings, compare the resolved binary package name with `PkgName` and its recorded version with `InstalledVersion`.
- Preserve full distribution versions, including epochs and revisions. Also verify that the scan describes the observed image; a tag alone is insufficient.

| Classification | Meaning |
| --- | --- |
| `confirmed` | A valid sample linked an executable or mapping to the finding's OS package name and version |
| `unknown` | Failed reads, missing metadata, ambiguous ownership, or identity/version problems prevented a reliable conclusion |
| `unobserved` | Valid collection produced no confirming evidence; include the reason, such as no matching mapping or unsupported language-package mapping |

- Retain timestamps, successful sample counts, failed reads, and unresolved paths alongside these classifications.
- Socket-attribution failure need not erase a valid package mapping.
- Without changing the urgency assessed using KEV, EPSS, severity, and other factors, confirmed runtime package use supports **addressing the associated findings first among those with the same urgency; failure to confirm use is not a reason to lower priority**.
- Confirmation shows observed package use within the method's limits.
- Neither `unknown` nor `unobserved` justifies suppressing a vulnerability or declaring it safe.

## References

Document reviewed: September 13, 2026.

- Measurements described here were performed on September 12, 2026. They describe specific hosts and runs.
- They are not a guarantee for other images or Linux configurations.

///Footnotes Go Here///

[^proc]: [Linux manual: proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)

[^docker-top]: [Docker: docker container top](https://docs.docker.com/reference/cli/docker/container/top/)

[^moby-top]: [Moby: Linux container process listing implementation](https://github.com/moby/moby/blob/master/daemon/top_unix.go)

[^exe]: [Linux manual: proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)

[^maps]: [Linux manual: proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)

[^status]: [Linux manual: proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)

[^namespaces]: [Linux manual: namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html)

[^stat]: [Linux manual: proc_pid_stat(5)](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)

[^net]: [Linux manual: proc_pid_net(5)](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)

[^tcp]: [Linux kernel: The proc/net/tcp and proc/net/tcp6 variables](https://docs.kernel.org/networking/proc_net_tcp.html)

[^fd]: [Linux manual: proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)

[^root]: [Linux manual: proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)

[^openat2]: [Linux manual: openat2(2), including RESOLVE_IN_ROOT](https://man7.org/linux/man-pages/man2/openat2.2.html)

[^dpkg-query]: [Debian: dpkg-query(1)](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)

[^apk]: [Alpine apk-tools v2.14.4: Package database implementation](https://github.com/alpinelinux/apk-tools/blob/v2.14.4/src/database.c)

[^distroless]: [Distroless: Package metadata specification](https://github.com/GoogleContainerTools/distroless/blob/main/PACKAGE_METADATA.md)

[^overlayfs]: [Linux kernel: Overlay Filesystem](https://docs.kernel.org/filesystems/overlayfs.html)

[^ptrace]: [Linux manual: ptrace(2), access-mode checks and Yama](https://man7.org/linux/man-pages/man2/ptrace.2.html)

[^capabilities]: [Linux manual: capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)

[^harness]: [Runtime discovery measurement harness and README](https://github.com/kitsunetrail/kestrelynx/tree/main/experiments/runtime-discovery)

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack or a webhook.

Remediation plans for Docker, Compose, and Kubernetes and pull requests for Docker and Compose (experimental) support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[Learn more about KestreLynx](../index.md) · [View the source on GitHub](https://github.com/kitsunetrail/kestrelynx)
