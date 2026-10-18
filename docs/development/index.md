# Development Logs

This section covers the problems being addressed, approaches tried, lessons learned during implementation, and technical decisions.

Development logs record how features were explored and implemented.
For instructions on currently available features, see [Documentation](../documentation/index.md).

- October 15, 2026 — [Development of re-resolution through dependent packages](dependent-reresolution.md) — updating dependent packages within declared ranges and checking each dependency position for vulnerability increases (implemented; PR creation verified in the production environment)
- October 8, 2026 — [Remediation plan and pull request development](remediation-pull-requests.md) — selecting candidate fixes from running container findings and connecting comparisons and notifications to GitHub PRs (implementation in progress)
- October 3, 2026 — [Short-lived container scanning development](short-lived-containers.md) — design for recording short-lived container executions and keeping the last version that ran under each image name in scan and notification scope for 14 days (design; implementation not started)
- October 2, 2026 — [Kubernetes Sensor Feasibility](kubernetes-runtime-sensor.md) — validation of the Docker Sensor's permissions and isolation on Kubernetes and the changes needed for cgroup namespaces and AppArmor (design and feasibility validation only; implementation not started)
- September 25, 2026 — [Runtime Evidence Prioritization Development](runtime-prioritization-development.md) — implementation of the Sensor and the main application's display, with overhead, notifications, and ongoing observations from continuous operation (implemented and operationally validated)
- September 22, 2026 — [Runtime Evidence Observation Environment Validation](runtime-environment-validation.md) — the permissions, continuous-observation overhead, and production start conditions and workflows verified before implementing the adopted runtime evidence (measurement complete)
- September 19, 2026 — [Runtime Evidence Coverage Validation](runtime-coverage-validation.md) — how much of the packages a workload really used each method confirmed, evaluated against independent ground truth (measured)
- September 13, 2026 — [Runtime evidence observation with eBPF: feasibility research](runtime-event-evidence.md) — whether eBPF-based execution and
  file-loading events can confirm the short-lived programs and language packages that sampling could not
- September 9, 2026 — [Runtime evidence prioritization: feasibility research](runtime-prioritization.md) — whether processes,
  listening ports, and privileges can be linked to vulnerability findings to improve prioritization (research complete)
- September 6, 2026 — [Developing Kubernetes support](kubernetes-support.md) — connecting Kubernetes workloads to scanning, prioritization,
  and diff notifications, starting with K3s + containerd (implemented; verified end to end on a real K3s cluster)
- September 5, 2026 — [The Kubernetes vulnerability scanning landscape](kubernetes-scanning-landscape.md) — what existing tools already
  cover and what we found missing, ahead of Kubernetes support (research note)
- August 31, 2026 — [Designing the remediation relations model](remediation-relations-model.md) — the relation models that connect
  a detected vulnerability to a proposal for where to fix it (models defined)
- August 25, 2026 — [Developing the environment and workload model](environment-workload-model.md) — identifying environments and
  mapping containers to services, connected to vulnerability records (implemented)
- August 22, 2026 — [Developing the image identity model](image-identity-model.md) — migration from image-name-based processing to identifying
  image content by immutable digests (implemented)
