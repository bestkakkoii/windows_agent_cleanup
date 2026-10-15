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

A request declares scope and input names. Quick input is pulled incrementally. Bounded workers enumerate independent directories while retaining charged ancestry leases and per-worker buffers. A thread-safe staging sink writes bounded sorted runs, merges them, detects duplicate-name identity conflicts, and seals an indexed complete batch. Nothing is deleted during this work. Resource pressure cannot silently truncate input or turn input chunks into independently authorized deletions.

`secure_erase.quick_store` keeps full target strings and outcome records in protected scratch files. Record hashes and the whole-plan fingerprint bind reads to frozen membership. Compact parent/device/allocation metadata forms the resource-admitted dependency graph; each active worker loads a bounded target window. This reduces resident storage without claiming constant memory for an unlimited batch. Live RAM/commit/CPU/handle/disk budgets can reject the complete job before mutation. The scheduler reserves its state and outcome capacity before work begins. GUI pages are fetched by an application worker; rendering does not read disk or copy the full target list.

Native scratch files have explicit private ACLs, no reparse traversal, exclusive data handles and real checked allocation. Their owners retain the store lock and ancestor pins; final close removes scratch. They support only the live session. Durable intent/failure reports and authenticated overwrite checkpoints have separate retention semantics.

Execution revalidates the selected object's identity and necessary safety state. New or replacement targets are excluded. Different selected hardlink names are separate namespace operations. Reparse boundaries and fail-closed system protection remain active. Reports, temporary plans and execution state live outside the target scope.

Quick mode performs logical deletion without payload overwrites or readback. Initial failures are deferred so successful first-pass work can progress; lock recovery and limited retries operate only on the frozen set. CLI process interaction is noninteractive; GUI force actions require their separate approval. Directory work follows child dependencies and releases its own handle leases before parent removal.

Device-aware scheduling groups volumes sharing physical storage and conservatively groups unknown topology. Hardware descriptions set initial hints; throughput and latency feedback determine useful concurrency. Additional concurrency must earn repeated throughput gains, with regression rollback and cooldown. Ready directories can finish when their own children settle, without waiting for unrelated subtrees. CPU and storage observations are optimization hints; unknown identity/protection evidence still refuses mutation. Capacity counters are affected by other processes, handles, links and storage layers, not attributable proof of bytes reclaimed by a job.

## Agent orchestration

[README_AI.md](../README_AI.md) routes universal entry and engineering tasks. The shared [project-cleanup Skill](../skills/project-cleanup/SKILL.md) owns cleanup plans and disposable-item policy; its bundled references supply protocol details only when needed. The Agent establishes evidence and authorization; the native tool enforces filesystem execution rules. Parallel discovery is read-only, and a coordinator submits one frozen batch.

Long-running work may be partially complete when interrupted. Unknown completion requires reconciling the same job evidence; it must not trigger an automatic fresh scan. Native platform and hardware validation determine release eligibility. Measured end-to-end comparisons replace claims of a universal maximum speed.

RC and Release publication additionally require owner-returned Windows build/test evidence and review for the exact revision. CI test artifacts remain unpublished development sources; see [publication policy](publication.md).

## Source encoding

Owned C/C++ units, modules, headers, PowerShell/Python scripts, CMake scripts and
documentation are stored as UTF-8 with BOM. The Windows bootstrap checks owned
code before compilation; source validation checks the maintained file set.
A BOM identifies the stored file encoding; explicit compiler UTF-8 settings
cover C/C++ inputs, generated probes and vendor standard-library modules.
Pinned third-party archives and sources retain their locked bytes and use the
same UTF-8 compiler policy. Do not rewrite dependencies to hide a decoding error.

Host formats retain required exceptions: Skill frontmatter starts with `---`,
JSON/JSONL and YAML metadata use UTF-8 without BOM, and the minimal CMD launchers
use ASCII/CRLF (an unambiguous UTF-8 subset). Product protocols retain their
separate declared encoding; source file BOMs do not become stdout/manifest BOMs.
