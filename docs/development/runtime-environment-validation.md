# Runtime Evidence Observation Environment Validation

- **Status:** Measurement complete
- **Started:** September 22, 2026
- **Last updated:** September 25, 2026

## Purpose

Before implementing the runtime evidence adopted in [Runtime Evidence Coverage Validation](runtime-coverage-validation.md), verify the permissions required for observation, the overhead of continuous observation, and the start conditions and operational workflows in a production environment.

- **Relationship to previous investigations**
    - Evaluate the observation methods examined in [Runtime Evidence Prioritization: Feasibility Research](runtime-prioritization.md) and [Runtime Evidence Observation with eBPF: Feasibility Research](runtime-event-evidence.md)
    - Define implementation requirements after adoption without repeating the coverage evaluation or adoption decision

- **Decisions this validation will inform**
    - Identify the required permission sets and the evidence unavailable when permissions are insufficient
    - Select candidates for the default sampling interval, buffer, and stop conditions
    - Define the wording for indeterminate results and the conditions needed to resolve that state

## Approach

- **Proceed from the local environment to production**
    - Measure permissions and overhead in the local environment before checking the same permissions and observation workflows in production
    - Keep previous measurements separate from the new measurements and avoid using overhead from a different configuration as the comparison baseline

- **Report what observation establishes in production**
    - Do not collect the strace ground truth used in the coverage validation to establish which packages were actually used
    - Record the proportion of findings with evidence, but do not treat it as proof that few packages were missed because the full set of packages actually used cannot be established
    - Report confirmed evidence alongside observation quality, including insufficient permissions and collection losses

- **Bound the observation**
    - Keep container and observation-target settings unchanged in production and limit observation by time and output volume
    - Align observation across a restart with a normal deployment or a restart arranged in advance

## Questions to validate

1. **How far can the required permissions be restricted?**
    - Record operation outcomes and effective permissions to identify evidence unavailable because of insufficient permissions
2. **How much continuous overhead do the observation methods selected for implementation impose?**
    - Measure CPU time, memory, event volume, losses, and output volume for periodic procfs reads and eBPF observation of exec/open tracepoints
    - Report bpftrace's own user-space CPU and memory separately as an upper-bound estimate because they differ from the implementation
3. **How much do the observation methods selected for implementation affect normal processing?**
    - Compare the effects of periodic procfs reads and eBPF observation of exec/open on operational task durations and web response times against runs without observation
    - Use the effects on the target processing to estimate the implementation's impact because the harness and implementation use the same observation mechanisms
4. **What can be shown when attaching to running containers?**
    - Identify evidence of use and limitations imposed by observation conditions for each container
5. **Can use be determined after a restart while observation continues?**
    - Check language-package evidence before and after the restart and the conditions under which the indeterminate display changes
6. **Define implementation requirements**
    - Document permissions, default settings, stop conditions, display wording, and resolution conditions with supporting records

## Verification method

### Terms

- **Observation methods**
    - Periodic procfs reads and eBPF observation of exec/open tracepoints selected for implementation

- **Observation processes**
    - The collector that reads procfs and the Docker API, and the bpftrace process that collects events

- **Permission condition**
    - A combination of permissions assigned to an observation process, distinguishing the requested configuration from the permissions actually effective

- **Observation configuration**
    - One of the configurations compared for overhead: no observation, procfs only, or procfs with events

- **Previous rules**
    - Confirmations obtained using [How to Map Running Container Processes to OS Packages with procfs](../articles/procfs-process-to-package-mapping.md)

- **With read-only additions**
    - The previous rules plus confirmations obtained using [Mapping Language Packages Detected by Trivy to Runtime Files](../articles/trivy-language-packages-runtime-mapping.md)

- **With event evidence**
    - The configuration with read-only additions plus confirmations obtained using [Observing Container Execution and File Opens with bpftrace](../articles/bpftrace-container-exec-open-events.md)

- **attach_running**
    - Observation starts after the container is already running

- **startup**
    - Observation starts before the target starts and remains active so that startup activity can be observed

- **Indeterminate**
    - A display state for a language package without confirming evidence whose container started before effective observation began, indicating that observation from startup was not established

- **CPU time**
    - CPU time is the total time the observation process actually spent processing on the CPU, excluding time spent waiting, measured using the CPU usage counter of its dedicated cgroup; 1.5 seconds of CPU time within a 300-second observation window corresponds to 0.5% utilization of one CPU core.

- **Sampling interval and read count**
    - The sampling interval was explicitly set to 30 or 10 seconds for the measurements, and the read count is the observation window length divided by that interval, giving 10 reads at a 30-second interval and 30 reads at a 10-second interval within a 300-second window.

### Permission checks

Comparing permission candidates for event observation requires repeatedly creating unprivileged users and assigning file capabilities, so compare the following four conditions in the local environment. Do not repeat this comparison in production; recheck only the minimum-permission candidate that worked locally against the administrative baseline. These are permission candidates to test, not conditions already confirmed to work.

| Permission condition | Execution conditions | What to check |
| --- | --- | --- |
| Administrative privileges | Run as root | Outcomes of the baseline operations |
| BPF and performance-monitoring permissions | Run as non-root with `CAP_BPF` and `CAP_PERFMON` | Denials caused by file access or security restrictions |
| Additional read permission | Run as non-root with the above capabilities plus `CAP_DAC_READ_SEARCH` | Whether adding permission to bypass read restrictions enables the operations |
| System-administration permission | Run as non-root with `CAP_SYS_ADMIN` | BPF operations and file access separately |

Check the following four operations under each permission condition and record every operation-and-permission combination.

| Operation | What to establish | Causes to distinguish on failure |
| --- | --- | --- |
| Load the BPF program | Whether loading was reached and succeeded | Permissions, verifier, security restrictions, resource limits |
| Attach to tracepoints | Attachment outcome and time | BPF and performance-monitoring permissions, file access, security restrictions |
| Create and read the event buffer | Buffer allocation and event retrieval | Resource limits, creation failure, read failure |
| Create the mapping between cgroup IDs and containers | Enumerating cgroups, retrieving cgroup IDs, and saving the mapping file | File access, missing attribution inputs |

Event observation requires a file mapping cgroup IDs to containers, and creating that file also requires permissions. If root prepares the mapping first, successful non-root observation does not establish that the non-root permission condition supports all the required operations. Run the mapping creation under the same permission condition as observation when determining whether that condition works.

- **Verify the actual execution conditions**
    - Assign the permissions for each condition to a dedicated copy of bpftrace while leaving the installed executable unchanged
    - Save effective permissions, applicable security restrictions, resource limits, and the executable version and hash
    - Record the outcomes of both mapping creation and event observation under the permission condition being tested
    - Record the event buffer used in this validation as the bpftrace perf buffer

- **Distinguish failure from work not performed**
    - Classify each operation as successful, failed, not reached, or not performed, linking available error numbers and logs
    - Record an unavailable error number as unknown rather than inferring it from an error message
    - Record tests with changed security settings or other environmental conditions separately

- **Combine the requirements with procfs permissions**
    - Check differences between the existing procfs results from the local environment and the current environment, then combine candidates including `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` with the successful event-observation conditions
    - Specify permissions by role when observation is split across processes
    - Record Docker API access separately from capability sets, distinguishing the use of read operations from the operations permitted by the connection

### Overhead and effects on normal processing

The measurement targets are the overhead of periodic procfs reads and eBPF observation of exec/open tracepoints selected for implementation. Because the harness and implementation use the same observation mechanisms, their effects on operational tasks and web responses provide an estimate of the implementation's impact. However, bpftrace's own user-space CPU and memory differ from the implementation, so report them separately as an upper-bound estimate rather than as implementation overhead.

Combine the following conditions in the local environment. The observation window and baseline privileges are proposals to fix before measurement.

| Comparison dimension | Conditions |
| --- | --- |
| Applications | Python web application, Node.js web application, Java application |
| Observation configurations | No observation, procfs only, procfs with events |
| Sampling intervals | 30 seconds, 10 seconds |
| Repetitions | Two runs per condition |
| Proposed start condition and window | attach_running for 300 seconds |
| Proposed baseline privileges | Administrative privileges |
| Event buffer | 512 pages when events are enabled |

- **Keep the comparisons consistent**
    - For no observation, run neither the collector nor bpftrace and run only the application and task-duration recording
    - Because no observation has no sampling interval, provide an independent control run for each comparison at 30 and 10 seconds
    - Use the configuration with read-only additions for procfs only and do not describe its overhead as that of the previous rules alone
    - Add event observation to procfs collection for procfs with events, collecting the inputs needed for confirmations with event evidence
    - Perform 36 runs across three applications, three configurations, two interval comparisons, and two repetitions, giving 180 minutes of observation windows under the 300-second proposal

- **Fix the execution conditions**
    - Use the same image, inputs, operational task periods, web request sequence, and concurrency for each application
    - Change the configuration order between repetitions, run measurements sequentially on the same machine, and record background load and cache state
    - Perform builds, vulnerability scans, observation-data conversion, and package matching outside the observation windows
    - Use the same timing method across configurations and do not run tracing for ground-truth collection concurrently

Record the following metrics, distinguishing the observation methods' effects on normal processing, collection resource use, and estimates of bpftrace's own overhead.

| Target | Metrics | Interpretation |
| --- | --- | --- |
| Collector | CPU time and peak memory in a dedicated cgroup | Resources used for periodic procfs reads and information retrieval through the Docker API |
| bpftrace | CPU time and peak memory in a separate dedicated cgroup, separating startup preparation from observation | An upper-bound estimate reported separately for bpftrace's own user-space overhead, not implementation overhead |
| Docker daemon | Increase in CPU time and possible contributions from other Docker operations | Indirect observation overhead and effects of other operations |
| Events | Total and per-container counts and events per second | Event volume handled by eBPF observation |
| Observation quality | Lost events, loss notifications, conversion failures, partial events, and unmeasured items | Limitations of the evidence obtained with each configuration |
| Output | Growth in stdout and stderr separately, growth per second, and growth across all saved artifacts | Output volume during measurement and estimates of storage requirements |
| Normal processing | Durations of curl, git, and openssl operations, web response times, successes, failures, and timeouts | Estimates of the implementation's impact on target processing from periodic procfs reads and eBPF observation |

- **Preserve the meaning of each measurement**
    - Report differences in normal processing from no observation as estimates of the impact of the observation methods selected for implementation
    - Report bpftrace's own user-space CPU and memory separately as an upper-bound estimate rather than substituting them for the implementation's resource use
    - Do not treat CPU time measured in observation-process cgroups alone as the total CPU time of the observation methods, including eBPF processing in the kernel
    - Record whether CPU and memory measurements were obtained separately and never treat unavailable values as zero
    - Report peak memory across the lifetime of the cgroup dedicated to each run rather than as a before-and-after difference
    - Distinguish CPU utilization relative to one core from utilization relative to the whole machine
    - Report counts, median, 95th percentile, maximum, and differences from no observation for each operation and repetition
    - Separate failures and timeouts from successful-operation duration distributions without omitting their counts
    - Treat two repetitions as a check for trends rather than a basis for establishing statistical significance or long-term variation

### Four stages in production

Prepare measurement and stop monitoring in the local environment before proceeding to production. Verify tracking both when a container restarts with the same Docker container ID (`docker restart`) and when a deployment recreates the container with a different container ID.

1. **Preflight checks**
    - Record the kernel, Docker, BTF, target tracepoints, observation tools, cgroups, procfs, security restrictions, and free space
    - Verify the target configuration and hash of the observation program built in the local environment
    - Proceed from preflight checks that perform no container operations to a short attachment test, recording preflight success separately from successful attachment and reading
    - Verify the existing scanning workflow can scan the running image by its identifier without changing observation-target settings

2. **Attach to running containers**
    - Observe four running containers with one collector, performing one 300-second and one 900-second attach_running run
    - Combine procfs and events with administrative privileges, using a 30-second interval and 512-page buffer as initial candidates to be fixed from local environment results
    - Report evidence categories and observation quality per container for Trivy HIGH and CRITICAL findings obtained outside the observation windows
    - Reuse saved scans when comparing the same image and record the scanner and vulnerability-database versions
    - Avoid counting the collector's total overhead separately against every container

3. **Restart while observation continues**
    - Keep event observation and target tracking active before a normal deployment or an arranged restart of one target web-application container
    - Initially plan for approximately 300 seconds before and 300 seconds after the restart, with a maximum total observation time of 1800 seconds including waiting
    - Do not add a mechanism that delays application startup for observation
    - Distinguish a restart with the same container ID from recreation with a different container ID, recording the container ID, image identifier, start time, process generation, and validity period of the mapping between cgroup IDs and containers
    - Keep old-generation evidence separate from the new generation and place attachment, restart, target detection, the first layout reading, and the first language-package evidence on a timeline
    - Scan a changed image separately and distinguish common packages from added or removed packages
    - Stop if the arranged operation does not occur within the observation window and record the check across a restart as not performed

4. **Recheck minimum permissions**
    - Test the same four operations and procfs reads in production using the minimum-permission candidate that worked in the local environment
    - Use 60 seconds per condition as the initial window proposal, limited to checking operation outcomes and reading
    - Compare effective permissions, security restrictions, and resource limits between the administrative baseline and non-root candidates
    - Record untested conditions as not performed rather than copying local environment results into production results

A restart provides an opportunity to establish observation from startup; it does not guarantee evidence for every language package. Record observation gaps and mapping limitations affecting activity before the first layout reading.

### Safeguards and stop conditions

Prepare the following stop conditions for production observation. The numerical values are initial proposals to fix before execution using local environment results and the state of the production environment.

| Monitored item | Proposed stop condition | Action |
| --- | --- | --- |
| bpftrace CPU | More than one core equivalent for three consecutive 10-second intervals | Stop the measurement processes |
| Continuing losses | Loss notifications or similar counters increase in three consecutive 10-second intervals | Stop and record the affected intervals |
| Output volume | 1 GiB per run or 4 GiB across the output location | Stop at either limit |
| Free space | Less than 20 GiB at the output location | Do not start, or stop an active run |
| Observation time | The limit for each window, with at most 1800 seconds for the restart check | Stop at the time limit |
| Service anomaly | New response failures or an operator's stop instruction | Stop immediately |

- **Verify stopping and termination**
    - Do not treat loss metrics unavailable during execution as monitored, and supplement them with aggregation after the run
    - Save logs and final counters on stopping and verify detachment and termination of the measurement processes
    - Apply any deadline-based termination only to measurement processes, leaving containers and the Docker daemon running
    - After transferring and matching the records, remove transferred programs, copies with capabilities, temporary files, and measurement cgroups

### Records to retain

- **Environment and inputs**
    - Record run identifiers, observation configurations, permission conditions, repetitions, start conditions, windows, intervals, and buffers
    - Save container and image identifiers, generations, tool and input versions, scan times, and database versions

- **Observation feasibility and overhead**
    - Record operation outcomes, effective permissions, reasons for denial, the observation methods' effects on normal processing, collection resource use, upper-bound estimates of bpftrace's own overhead, losses, and output growth
    - Retain reasons for early stopping, missing measurements, and work not performed, together with confirmation of detachment and cleanup

- **Evidence during attach_running and across a restart**
    - Record evidence types and times, corresponding packages, container generations, and changes in display categories
    - Distinguish missing evidence caused by startup before observation, collection losses, container attribution, layout information, and package mapping

Classify findings in the following order without overlap. Retain the original verdict and observation quality separately, and count packages separately from vulnerability findings.

| Display category | Classification condition | Meaning |
| --- | --- | --- |
| Confirmed | Positive evidence corresponds to the current generation and image | Use is confirmed at the granularity supported by the evidence |
| Indeterminate (started before observation) | Not confirmed, and the container for a language package started before effective observation | Observation from startup was not established |
| No evidence | No confirming evidence and neither category above applies | Does not mean unused or safe, with observation limitations recorded separately |

- **Interpret the aggregation**
    - Do not infer that an individual package was used before observation solely from the container's start time
    - Classify targets with positive evidence as confirmed even under attach_running, stating the granularity of that evidence
    - Record zero targets when there are no HIGH or CRITICAL findings rather than reporting 100% with evidence
    - Separate targets when the image changes across a restart and do not infer improved evidence collection from an increase in counts alone

### Defining implementation requirements

Define implementation requirements from the measurements, separating the verified scope, proposals, and unverified items.

| Implementation requirement | Supporting records |
| --- | --- |
| Required permission sets | Operation outcomes, effective permissions, and production rechecks |
| Handling evidence missing because of insufficient permissions | Relationships between failed reads or attachments and unavailable evidence |
| Candidates for the default interval and buffer | The observation methods' effects on normal processing, collection resource use, and losses at 30 and 10 seconds with 512 pages, with upper-bound estimates of bpftrace's own overhead reported separately |
| Stop conditions and output management | CPU, loss, and output-volume trends and stopping records |
| Indeterminate wording and resolution conditions | Observation continuity and evidence changes from attach_running through the restart |
| Remaining implementation requirements | Gaps in target tracking, attribution, layout reading, matching, and permissions |

- **Proposed display wording**
    - Use “Indeterminate (started before observation)” for the state
    - Describe the resolution condition as “If observation continues through the container's next restart, use can be assessed from startup,” accompanied by the conditions required for target tracking, collection, and matching
    - Show remaining permission problems or losses as separate reasons without suggesting that a restart alone confirms every package

- **Scope of the conclusions**
    - Describe minimum permissions as a successful candidate among the tested sets rather than claiming a minimum across all possible combinations
    - Do not call 512 pages the optimal or minimum buffer because other buffer sizes are not compared
    - Treat effects on normal processing as estimates of the impact of implementing the selected observation methods, not as guarantees of overall KestreLynx overhead
    - Treat bpftrace's own user-space CPU and memory only as an upper-bound estimate, not as implementation overhead
    - Label resource estimates extrapolated from short observations as reference estimates and distinguish them from measurements of long-term operation
    - Consider the work complete when result tables, supporting records, reasons for work not performed, implementation requirements, and proposals are available

## Results

**Conclusion**

- **Observation without root**: procfs collection with `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` obtained the same information as root, supporting a collector that runs without root, while Docker API access must be handled as a separate permission
- **Event-observation permissions**: `CAP_BPF`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH`, and `CAP_DAC_OVERRIDE` enabled all four required operations with bpftrace in both local and production environments, but whether the implementation also needs `CAP_DAC_OVERRIDE` remains unresolved because bpftrace's self-check stops execution without it
- **Continuous overhead and the default interval**: Locally, the procfs collector at a 30-second interval used less than 1% of one CPU core and bpftrace event observation used a few percent, while effects on normal processing were generally within variation between repetitions except for Java curl increases of 1.0–2.2 ms, supporting acceptable continuous overhead within the tested scope and a 30-second interval as a default candidate
- **Initial reads and memory**: Production initial reads took 17–27 seconds and require allowance for startup overhead, while most event-observation memory growth came from trace-file page cache and is not expected in an implementation that does not write the same trace files, with bpftrace's own resource use treated as an upper-bound guide for estimating implementation overhead
- **Continuous observation and indeterminate results**: Observation tracked separate container generations across both restart and recreation, and “Indeterminate (started before observation)” resolved on the next startup for applications that started, demonstrating that continuous observation and displaying and resolving indeterminate results work in production
- **Usefulness for prioritization**: All 19 HIGH and CRITICAL vulnerability findings for Elasticsearch gained evidence after restart, while the Node.js backend gained evidence for 6 findings associated with the two packages loaded by the application, `js-yaml` and `multer`, distinguishing them from unused dependencies of bundled tools and providing practical input for identifying vulnerabilities in packages actually used, with these counts referring to findings rather than packages
- **Scope and limitations**: Node.js use could not be determined after attaching to running containers until the next startup, and production checks were limited to one run per condition and a small number of containers, so these results alone cannot guarantee coverage or long-term overhead

**Event-observation permissions**

Five conditions using administrative privileges or capabilities assigned to a non-root process were compared in the local and production environments. Operation outcomes and reasons for stopping were identical in both environments. Failures include stops during prerequisite processing or startup self-checks.

| Permission condition | BPF program load | Tracepoint attachment | Event buffer creation and reading | Mapping cgroup IDs to containers | Reason for stopping |
| --- | --- | --- | --- | --- | --- |
| Administrative privileges | Successful | Successful | Successful | Successful | None |
| `CAP_BPF` + `CAP_PERFMON` | Failed | Not reached | Not reached | Successful | File read denied by tracefs permissions |
| Above plus `CAP_DAC_READ_SEARCH` | Failed | Not reached | Not reached | Successful | bpftrace self-check required `CAP_DAC_OVERRIDE` |
| Above plus `CAP_DAC_OVERRIDE` | Successful | Successful | Successful | Successful | None |
| `CAP_SYS_ADMIN` only | Failed | Not reached | Not reached | Successful | File read denied by tracefs permissions |

- **Successful candidate**: `CAP_BPF`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH`, and `CAP_DAC_OVERRIDE` enabled all four operations, but this is a candidate among tested conditions rather than an established minimum across all combinations
- **Read-permission limits**: The bpftrace self-check stops before kernel operations, leaving it unverified whether adding only `CAP_DAC_READ_SEARCH` would suffice, while `CAP_SYS_ADMIN` alone could not bypass tracefs file permissions
- **AppArmor scope**: Production test processes ran unconfined, so feasibility under an applied AppArmor profile was not verified

**Local overhead and effects on normal processing**

A Python web application, a Node.js web application, and a Java application were measured on WSL2 with Linux 6.6 and `perf_event_paranoid=2`. No observation, procfs only, and procfs with events were compared at 30-second and 10-second intervals with two repetitions, reversing configuration order in the second repetition. Each run used a 300-second attach_running window and a 512-page event buffer where applicable, and all 36 runs completed without early stopping.

The table shows minimum and maximum values across the three applications and two repetitions. Collector values include procfs only and procfs with events, while bpftrace was measured in a separate dedicated cgroup. CPU time covers the observation window, and peak memory covers each measurement cgroup's full lifetime.

| Target | Sampling interval | CPU time | Peak memory |
| --- | --- | --- | --- |
| procfs collector | 30 seconds | 1.44–2.14 seconds | 42–49 MB |
| procfs collector | 10 seconds | 4.49–6.31 seconds | 46–53 MB |
| eBPF observation (bpftrace) | 30 seconds | 8.89–12.22 seconds | 93–237 MB |
| eBPF observation (bpftrace) | 10 seconds | 9.48–14.10 seconds | 96–117 MB |

- **Read count**: The 30-second interval produced 10 reads and the 10-second interval produced 30, with the collector using approximately 0.14–0.21 seconds of CPU time per read for procfs and Docker API information retrieval
- **Outlier**: One Node.js run with events at a 30-second interval reached 237 MB of bpftrace memory, compared with 107 MB in the other repetition, with the cause unidentified
- **Event volume and losses**: Runs with events recorded 953–1429 events per second overall and 58–192 for the target container, with zero recorded lost events under every condition
- **Normal-processing comparison**: Median curl, git, and openssl durations and web response times were compared against no observation for the same application, interval comparison, and repetition, with differences generally within about ±1 ms and comparable to variation between repetitions
- **Java curl**: All four runs with events showed increases of 1.0–2.2 ms, with corresponding no-observation medians of 11.8–13.7 ms
- **Web responses and interpretation limits**: All 36 runs, including no observation, had zero response failures, but two repetitions per condition cannot establish statistical significance or long-term variation

**Production environment and measurement conditions**

- **Environment**: Used Ubuntu 26.04 LTS, Linux 7.0, Docker 29.x, bpftrace 0.25.0, and cgroup v2, confirming BTF, the required tracepoints, `perf_event_paranoid=4`, and AppArmor enabled
- **Security restrictions**: Confirmed `unprivileged_bpf_disabled=2` and `ptrace_scope=1`, with no hidepid option on procfs and kernel lockdown disabled
- **Targets and observation configuration**: Observed running Elasticsearch, a Node.js backend, a Node.js frontend (Next.js), and a service using a static Go binary with an administrative collector and event observation at a 30-second interval and a 512-page buffer
- **Scanning and interpretation limits**: Matched Trivy HIGH and CRITICAL vulnerability findings against evidence, but collected no strace ground truth, so confirmed counts are neither package counts nor a measure of coverage of all packages actually used

**Attaching to running containers and observing restart and recreation**

One 300-second and one 900-second attach_running window produced identical classifications. The table counts HIGH and CRITICAL vulnerability findings rather than packages.

| Target | Findings | Confirmed | Indeterminate (started before observation) | No evidence |
| --- | --- | --- | --- | --- |
| Elasticsearch | 19 | 17 | 2 | 0 |
| Node.js backend | 27 | 0 | 27 | 0 |
| Node.js frontend (Next.js) | 19 | 0 | 19 | 0 |
| Service using a static Go binary | 38 | 0 | 24 | 14 |

Restart and recreation were each checked during a continuous 1200-second observation in production. The three Elasticsearch and Node.js containers retained their IDs during restart, while both Node.js container IDs changed during recreation, with separate generations observed and matched before and after each operation. Classifications before the operations matched the table above, and the following table shows the results afterward. These are also counts of HIGH and CRITICAL vulnerability findings.

| Target | State after operation | Findings | Confirmed | Indeterminate (started before observation) | No evidence |
| --- | --- | --- | --- | --- | --- |
| Elasticsearch | After restart | 19 | 19 | 0 | 0 |
| Node.js backend | Same after restart and recreation | 27 | 6 | 0 | 21 |
| Node.js frontend (Next.js) | After restart (server not started, excluded from conclusions) | 19 | 0 | 0 | 19 |
| Node.js frontend (Next.js) | After recreation (server running) | 19 | 2 | 0 | 17 |

- **Elasticsearch**: File opens for `bcprov-jdk18on` confirmed the remaining 2 findings after restart, while the service was not recreated during the recreation observation and had 17 confirmed and 2 indeterminate findings
- **Backend evidence**: File opens for the two packages loaded by the application, `js-yaml` and `multer`, provided evidence for 6 vulnerability findings after both restart and recreation, while the remaining 21 involved dependencies of the npm and pnpm package-management tools bundled in the image rather than application dependencies under `/app`
- **Backend non-use**: All 49,006 opens under `/usr/local/lib/node_modules/npm` and `/usr/local/lib/node_modules/pnpm` across the restart came from the collector reading the container layout, with zero opens by any container process, so the absence of usage evidence for the 21 findings associated with these dependencies is the correct result
- **Interpreting backend counts**: The 6 of 27 breakdown means that 6 detected vulnerability findings corresponded to packages the application used during observation and does not indicate many missed uses, although the absence of ground truth prevents claiming that none were missed
- **Initial frontend restart**: Startup processing did not finish rewriting about 150 GB of page cache under `.next/server` within the observation window and the server did not start, so these results were excluded from conclusions
- **Frontend after recreation**: HTTP 200 was confirmed 5 seconds after recreation completed, observation with the server running confirmed 2 findings from 415 opens for `next`, and the host-side request loop had 296 successful request pairs and 2 failures during recreation
- **Unused frontend dependencies**: The remaining 17 findings involved npm's bundled `brace-expansion`, `ip-address`, `pacote`, `picomatch`, `sigstore`, and `tar`, plus `sharp`, `postcss`, and `nanoid` under `/app/node_modules/.pnpm`, with zero opens by processes other than the collector showing that these packages were not loaded during the window
- **Interpreting non-use**: Confirmed non-use in the backend and frontend applies only to these observation windows and does not establish non-use under other processing or inputs, or safety
- **Static Go binary**: The service was not restarted and remained in the same generation with zero confirmed, 24 indeterminate, and 14 findings without evidence. The 24 indeterminate findings corresponded to Go modules in the Trivy binary (`/usr/local/bin/trivy`) included in the same image, while there were zero HIGH or CRITICAL findings for the service binary (`/usr/local/bin/kestrelynx`). Trivy runs only during scanning and was not running during observation, so the absence of confirmed findings was consistent with its execution status. Go modules can be classified as included in an executed binary by matching the binary path reported by Trivy against the executable of a running process, and this method has been verified in synthetic cases
- **No-evidence classification**: The harness classified the backend's 21 findings as paths that could not be mapped, although no target file opens were observed, requiring a correction that separates mapping failures from missing evidence

**Non-root procfs conditions**

Four procfs-only conditions were compared on the running containers in production. Each condition used a 60-second window and a 30-second interval, with two reads per container. Non-root conditions used a regular user in the docker group with Docker API access and private collector copies with the capabilities assigned for each condition.

| Permission condition | Valid reads | Process records | maps entries | Package-database reads | Listeners | Listeners attributed to a process |
| --- | --- | --- | --- | --- | --- | --- |
| Administrative privileges | 12/12 | 18 | 174 | Successful for 6 targets | 32 | 20 |
| `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` | 12/12 | 18 | 174 | Successful for 6 targets | 32 | 20 |
| `CAP_SYS_PTRACE` only | 12/12 | 18 | 174 | Successful for 6 targets | 32 | 4 |
| No capabilities | 0/12 | 18 (identity only) | 0 | None obtained | 0 | 0 |

- **Agreement with root**: `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` matched root in every table entry, agreeing with existing local results
- **Effects of removing permissions**: `CAP_SYS_PTRACE` alone could not read `/proc/<pid>/fd` except for processes running as the same user, reducing attribution from 20 to 4, while no capabilities caused process observation and package-database reads to fail with zero valid reads
- **Execution conditions**: Effective collector capabilities matched each condition and all processes ran unconfined, but Docker API access came from docker-group membership and must be handled separately from capabilities

**Production overhead**

The table shows collector and bpftrace values for each observation, with attach_running and restart observations covering four containers together. CPU time covers each observation window, while peak memory covers each measurement cgroup's full lifetime, and these are not per-container values.

| Observation condition | Window | Collector CPU time | Collector peak memory | eBPF observation CPU time | eBPF observation peak memory |
| --- | --- | --- | --- | --- | --- |
| attach_running | 300 seconds | 36.5 seconds | 223 MB | 13.4 seconds | 192 MB |
| attach_running | 900 seconds | 58.0 seconds | 217 MB | 39.7 seconds | 702 MB |
| Across a restart | 1200 seconds | 81.1 seconds | 309 MB | 61.3 seconds | 839 MB |
| Across recreation | 1200 seconds | 27.2 seconds | 228 MB | 16.1 seconds | 156 MB |

- **Event volume and losses**: Recorded 1962 events per second for the 300-second attach_running window, 1954 for the 900-second window, 2081 across restart, and about 407 per second across recreation, with zero lost events in all observations
- **bpftrace memory**: Samples every 60 seconds across restart showed anonymous memory constant at 40 MB while trace-output page cache grew from 182 MB to 776 MB and accounted for most memory growth
- **Collector memory and reads**: Anonymous memory was about 20 MB and page cache was 39–157 MB, while initial layout and package-database reads for four containers during attach_running took 17–27 seconds of elapsed time and subsequent reads took about 1.8 seconds in total
- **Interpreting resource use**: Initial-read elapsed time differs from CPU time, cgroup peak memory does not indicate growth in the process's own memory, and observation-process CPU time alone excludes the full cost of eBPF processing in the kernel
- **Applicability to implementation**: Local and production values including bpftrace are upper-bound estimates that include its user-space cost, and differences in target counts and configurations prevent using the two environments as overhead-difference baselines

### Correction to Java response times (September 30, 2026 remeasurement)

- The 1.0–2.2 ms increases in the conclusion and Java curl results above measured the duration of the entire curl process, including startup, and do not establish an increase in the Java application's HTTP response time
- Local measurements alternated three conditions—no Sensor, Sensor without eBPF, and Sensor with eBPF—using a 30-second sampling interval for Sensor conditions and measuring curl's `time_total` after observation became active, with eight runs of 5,000 consecutive requests and four runs of 1,000 requests at 150 ms intervals per condition, for 36 runs in total
- Median response-time differences between Sensor with eBPF and no Sensor were −0.11 to +0.20 ms within comparable speed groups for consecutive requests and −0.35 to +0.30 ms for requests at 150 ms intervals, within variation between runs and without a consistent increase in response time
- All 36 runs had zero failures or timeouts, and eBPF recorded zero lost events
- Some runs with Sensor and eBPF had slightly higher p95 and p99 values, but the number of runs was insufficient to establish a trend

## Completed work

- Checked event-observation permissions and compared observation-method overhead and effects on normal processing in the local environment
- Performed production preflight checks of the kernel, required observation features, security restrictions, and observation and scanning workflows
- Checked evidence and overhead when attaching to running containers in production
- Observed across restart and recreation in production, checking generation separation, evidence changes, resolution of indeterminate results, overhead, and observation quality
- Confirmed non-use during the observation windows for backend and frontend dependencies without evidence and identified the harness classification defect
- Compared event-observation and procfs permission conditions in production

## Change log

### October 13, 2026 {#2026-10-13}

- Corrected the interpretation of Java response times and added remeasurement results

### September 22, 2026 {#2026-09-22}

- Recorded the plan

### September 23, 2026 {#2026-09-23}

- Recorded local and production results

### September 25, 2026 {#2026-09-25}

- Corrected the interpretation of the static Go result

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
