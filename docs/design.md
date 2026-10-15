# Design

Windows Agent Cleanup shares one native application/core/backend stack between a compact Win32/DirectX 11 GUI and an Agent-oriented CLI. Interface code selects the workflow and presents results; it cannot disable core protection or expand an admitted target set.

## Boundaries

| Layer | Owns |
|---|---|
| `src/cli`, `src/gui` | Protocol/UI input, explicit authorization and bounded presentation |
| `src/app` | Workflow, protected state, reporting and control |
| `src/core`, `src/modules` | Plans, identity-based admission, scheduling, execution and module contracts |
| `src/windows` | Handle-based filesystem operations, device observations, lock coordination and protected storage |

Native interfaces are named C++ modules. WinAPI and third-party headers stay at their owning boundaries; production uses the vendor standard-library module. GUI dependencies do not become a CLI orchestration runtime.

## Batch invariants

A request declares scope and input names. Preparation enumerates, deduplicates selected names, collects identity and protection evidence, then freezes the complete admitted batch. Resource pressure can reject preparation; it cannot silently truncate input or turn input chunks into independently authorized deletions. Current quick membership remains resident in memory. Admission derives bounds from current resources and rejects a batch that cannot fit; it does not provide a disk-backed quick-plan spill path. Protected report/checkpoint storage is separate from this resident membership.

Execution revalidates the selected object's identity and necessary safety state. New or replacement targets are excluded. Different selected hardlink names are separate namespace operations. Reparse boundaries and fail-closed system protection remain active. Reports, temporary plans and execution state live outside the target scope.

Quick mode performs logical deletion without payload overwrites or readback. Initial failures are deferred so successful first-pass work can progress; lock recovery and limited retries operate only on the frozen set. CLI process interaction is noninteractive; GUI force actions require their separate approval. Directory work follows child dependencies and releases its own handle leases before parent removal.

Device-aware scheduling uses current resource and workload observations. Hardware descriptions are hints; successful throughput and latency determine useful concurrency. Capacity counters are observations affected by other processes, handles, links and storage layers, not attributable proof of bytes reclaimed by a job.

## Agent orchestration

[README_AI.md](../README_AI.md) owns cleanup plan selection and disposable-item policy. Optional Skills route there. The Agent establishes evidence and authorization; the native tool enforces filesystem execution rules. Parallel discovery is read-only, and a coordinator submits one frozen batch.

Long-running work may be partially complete when interrupted. Unknown completion requires reconciling the same job evidence; it must not trigger an automatic fresh scan. Native platform and hardware validation determine release eligibility. Measured end-to-end comparisons replace claims of a universal maximum speed.
