# Design

Windows Agent Cleanup shares native core and Windows backend contracts between a Win32/DirectX 11 GUI and an Agent-oriented CLI. The current target is Windows 11+ x64, minimum build 22000; this supersedes the historical Windows 10/1809 target. A target platform or filesystem is not automatically a tested configuration.

## Boundaries

| Layer | Owns |
|---|---|
| `src/cli`, `src/gui` | Protocol/UI input, explicit authorization and bounded presentation |
| `src/app` | Application workflow, protected state, reporting and control |
| `src/core`, `src/modules` | Plans, admission, scheduling, execution and module contracts |
| `src/windows` | Handle-based filesystem operations, device observations, lock coordination and protected storage |

Native interfaces are named C++ modules. WinAPI and third-party headers stay at their owning boundaries; production uses the vendor standard-library module. GUI and CLI select workflows through the shared contracts; neither can disable protection or expand an admitted target set. GUI dependencies do not become a CLI orchestration runtime.

## Two execution modes

| Concern | Quick logical deletion | Verified logical overwrite |
|---|---|---|
| Target storage | Full strings and outcomes in indexed protected scratch; compact resident dependency metadata | Resident frozen plan and per-target state; protected durable checkpoints |
| Payload | Deletes selected names without overwriting or reading back content | One reproducible cryptographic overwrite pass, flush and complete expected-byte readback before deletion |
| Hard links | Different selected names are separate namespace operations; unselected aliases survive | Shared data is never overwritten; selected aliases collapse by identity to one deterministic name, requiring delete-only approval |
| Scheduling | Shared physical-device groups, measured concurrency feedback, ready child-parent dependencies | Bounded per-device queues and global workers; file workers finish before deepest-first directory processing |
| Recovery | Failure recovery follows the complete first pass; continuation uses the same live staged job | Resume loads an authenticated checkpoint, obtains fresh consent and revalidates identity, metadata and written prefixes |
| Lifetime | No cross-process resume or imported report as retry authority | Checkpoints survive process exit under the configured retention policy |

Neither mode proves physical NAND sanitization, removal of historical filesystem records or deletion of arbitrary backup copies. A successful logical operation is reported separately from its residual risks. Quick mode does not invoke the overwrite, payload verification, VSS inventory or TRIM workflow.

## Frozen membership and protection

A request declares scope and input names. Both modes finish admission before mutation, bind approval to the admitted plan and revalidate execution identity. New or replacement targets are excluded. Reparse ancestors and final components are rejected. Directory removal requires an empty directory; additions can therefore prevent removal without becoming new deletion targets. Reports, temporary plans and execution state stay outside the target scope.

Self-protection covers the running executable, loaded module files and their file identities, and selected directories containing those live resources. It does not protect every unrelated sibling of the executable. Windows, service, boot, recovery and private state protection retain their own tree boundaries. Uncertain identity or protection evidence refuses mutation. Safety-policy refusals remain distinct from filesystem access errors even when both carry Win32 `ERROR_ACCESS_DENIED`.

NTFS, ReFS, FAT32 and exFAT are in scope. Overwrite admission additionally requires supported storage/media evidence; ReFS, shared hard links and certain special-file states require independently authorized delete-only handling or refusal. Unknown storage topology is not permission to overwrite. Quick deletion can conservatively group unknown physical topology while retaining local-filesystem, identity and protection checks. Neither rule claims that every filesystem/device combination has passed hardware validation.

## Quick staging and scheduling

The [Quick deletion technical report](quick_delete_technical_report.md) traces
the actual Windows calls, scheduling constants, resource formulas, failure
semantics and reproducible experiments. This design document owns boundaries;
the report owns detailed implementation analysis, not a separate execution policy.

Quick input is pulled incrementally. Bounded workers enumerate independent directories while retaining charged ancestry leases and per-worker buffers. A thread-safe staging sink writes bounded sorted runs, merges them, detects duplicate-name identity conflicts, and seals an indexed complete batch. Nothing is deleted during this work. Resource pressure cannot silently truncate input or turn input chunks into independently authorized deletions.

`secure_erase.quick_store` keeps full target strings and outcome records in protected scratch files. Record hashes and the whole-plan fingerprint bind reads to frozen membership. Compact parent/device/allocation metadata forms the resource-admitted dependency graph; each active worker loads a bounded target window. This reduces resident storage without claiming constant memory for an unlimited batch. There is no fixed 100,000-target or 16-worker Quick ceiling: live memory/commit, CPU, handle and scratch-disk observations, plus any caller limit, determine admission. Metadata still grows with target count and can reject an oversized complete job.

The scheduler reserves its state and outcome capacity before work begins. Later resource loss or a device fault can stop further work after earlier targets have been deleted; pending targets remain explicitly unattempted and the result is partial or unknown where evidence is incomplete. Available-handle estimates and device-pressure observations are conservative hints, not OS reservations. These budgets do not bound total process RSS, GUI allocations, OS cache or driver memory.

Native scratch files have explicit private ACLs, no reparse traversal, exclusive data handles and checked allocation. Their owners retain the store lock and ancestor pins; final close removes scratch. They support only the live session. Durable intent/failure reports and authenticated overwrite checkpoints have separate retention semantics. GUI pages are fetched by an application worker; rendering does not read disk or copy the full target list.

Scheduling groups volumes sharing physical storage and conservatively groups unknown topology. Hardware descriptions set initial hints. Throughput and latency observation windows guide concurrency probes; extra concurrency must earn repeated gains, with regression rollback and cooldown. These thresholds are engineering heuristics, not a proof of optimal throughput. Ready directories can finish when their own children settle, without waiting for unrelated subtrees. Free-space counters are affected by other processes, handles, links and storage layers and cannot prove bytes reclaimed by this job.

Initial failures are deferred so successful first-pass work can progress. Automatic access/lock recovery and limited retries begin only after that pass finishes, operate only on the frozen set and never force-terminate processes. Interrupted first passes do not become recovery-ready batches. Any forced process action needs independent fresh authorization bound to the target, PID, process creation time and image, and is restricted to unprotected user processes.

## Overwrite and durable state

The overwrite engine uses bounded ChaCha20 output seeded by Windows cryptographic randomness. Domain-separated segment derivation supports 64-bit stream offsets without reusing the same counter range. Verification regenerates expected bytes and compares the entire accessible admitted stream set after flushing; read success alone is insufficient. ADS enumeration/access errors are reported. Files with unsupported overwrite semantics require explicit downgrade grants rather than an automatic fallback.

The native backend uses buffered write-through I/O, positioned overlapped operations for admitted SSDs and synchronous operations for HDD/USB. Each overlapped operation is awaited; no per-file multi-request pipeline or unbuffered alignment optimization is claimed. Transfer latency adapts chunk size within configured bounds. Global overwrite workers currently accept 1–16, with HDD/USB depth one and configurable SSD depth 1–4. CPU/RAM pressure and the optional shared bandwidth limit constrain work. This is distinct from Quick's resource-derived worker ceiling and measured device tuner; hardware-optimal block sizing remains unproven.

A checkpoint must save successfully before destructive work. Protected state includes the frozen plan, keys/nonces, cursors and observed metadata; authorization is not persisted as reusable consent. Resume revalidates identity, sizes, streams, timestamps and checkpoint state, then verifies saved written prefixes. A verified/deleting state that may have issued TRIM is rewritten and reverified before completing deletion. Readonly changes are handle-bound and restored for checkpoint snapshots. DPAPI, restricted ACLs, integrity checks and atomic replacement protect stored state; they do not provide anti-rollback against the same compromised principal or SYSTEM.

TRIM acceptance is an advisory logical result, not proof that old physical pages are gone. Read-only VSS inventory reports identifiable retained-copy risks and distinguishes query failure from zero snapshots. Arbitrary offline/cloud backups and historical MFT/journal remnants are outside the guarantee.

## Interfaces, authorization and diagnostics

[README_AI.md](../README_AI.md) routes universal entry and engineering tasks. The complete shared [project-cleanup Skill](../skills/project-cleanup/SKILL.md) owns cleanup plans, scope confirmation and disposable-item policy; bundled references supply details when needed. The Agent establishes evidence and authorization, while the native tool enforces filesystem execution rules. A build or development request is not cleanup authorization. Parallel discovery is read-only, and a coordinator submits one admitted batch.

The CLI is noninteractive: `capabilities` is the no-argument default; `scan`, `run`, `resume`, `locks` and `release` have explicit scope and authorization contracts. `run` may prepare and execute one authorized manifest request; it does not require a separate human prompt for every file. Quick `scan` is advisory and cannot be imported as later retry authority. Overwrite `scan` can retain a protected plan for `resume`, which requires its job ID, fingerprint and fresh irreversible consent. Downgrade and force-process permissions remain separate from ordinary run authorization. The GUI provides one current batch with queued input names, preview/confirmation, pause/cancel controls and available history; it is not a multi-job orchestration service.

Long-running work may be partially complete when interrupted. Unknown completion requires reconciling the same job evidence; it must not trigger an automatic fresh scan. Machine stdout is compact, with detailed CLI records written to the explicitly requested report directory. Those private operational reports can contain paths; masked retained event logs and bounded GUI diagnostic copies have a different disclosure scope.

GUI diagnostic copies include counts, errors, masked event evidence and available outcome-page context. A compact Quick report has no resident full-target vector; its empty vector is not evidence that the job had no targets. Diagnostic output declares sampling and pagination. Progress fields depend on the mode: overwrite exposes byte/verification progress; Quick reports namespace progress and allocation/free-space observations rather than verified overwritten bytes. Logs default to 30-day retention and eight 4 MiB rotated files; incomplete overwrite checkpoints default to no expiry until completion or an explicitly configured expiry.

## Publication and evidence

The published Latest Release `v2.0.0` is the owner-authorized first-distribution exception described in [publication policy](publication.md). Its supplied GUI/CLI EXE bytes are unchanged and still report `2.0.0-dev.1` and the original development label. The release source reference is `2b552ba92c9e81cb1ef4b8101619993677b5548a`; runtime C++ sources remain unchanged from `479c3aa44cc918ec09a4c50a8a799ad1c89d9d0d`. No independent source-to-owner-binary attestation is claimed. The published runtime ZIP and generated Source ZIP are distinct deliverables.

Owner GUI quick/overwrite smoke results and a successful 2,890-file CLI Quick pilot are available. Native CI run `38795510597`, at source revision `f6c4bcbd59fc5c2821109d81983b998129e41834`, passed 11 safe suites, four isolated suites and both source/runtime test packaging on hosted Windows Server 2025 with MSVC `19.51.36260.0` and SDK `10.0.26100.0`. CI does not execute or attest the owner-supplied binaries, prove desktop GUI operation, or cover the full physical-storage matrix. Broader CLI Agent acceptance and full hardware coverage remain pending. Current evidence and gaps are maintained in [the test plan](windows_test_plan.md) and [project metadata](../spec/project.json); individual source/test paths are not pass claims.

Normal RC/Release owner-evidence and review gates remain in force for later versions. The first-distribution exception neither marks untested configurations passed nor authorizes another publication. End-to-end measurements, rather than a universal maximum-speed claim, determine performance conclusions.

## Production Agent contracts in source

Ordinary adoption downloads the official Release's Windows x64 runtime asset,
verifies its release-record checksum before extraction and binds an Agent-chosen
portable directory. Generated source archives and compilation belong to explicit
engineering work. The small absolute-path README routes operators to the sole
Skill kernel; reuse known plan/scope/authority and load references conditionally.
The published v2.0.0 bundle retains its original v1 interfaces and instructions.

New source supports explicit `--contract-version 2`; omission retains v1 output
shape and exits. V2 capabilities observes the current effective token, numeric
Windows build and native/process architecture without target admission or store
creation. Unknown observations carry errors rather than invented false values.
Refresh readiness after an actual execution-host change; neither installation
nor host readiness grants cleanup authority. Hash-bound runtime manifests
advertise supported contracts; legacy/unadvertised bundles remain on v1.

Quick core statistics count unique frozen namespace selections, actual backend
remove calls and final successful removals, including recovery only once. Known
bytes are default-stream logical lengths captured during preparation; unknown
length/type counts remain explicit. They are not allocated or reclaimed bytes.
Checked totals, new staging/outcome formats and fingerprints bind the added
metadata, and complete admission reserves bounded statistics/report capacity.
CLI/GUI consume these shared statistics and the same at-most-128-volume space
observation helper. V2 distinguishes streamed preparation, freezing, first pass,
recovery and pre-result reporting wall times; unmeasured fields are null.
The total ends before final report/stdout delivery and process teardown.

V2 `status` inspects existing request-prefixed private reports read-only. It does
not open/create the execution store, mutate retention, acquire the writer lock,
select targets or restore Quick scratch. Bounded enumeration/read limits, unsafe
ACLs/reparses, changing evidence and multiple matches produce explicit unknown,
unavailable, incomplete or ambiguous states. A validated terminal record preserves
its original result; no lookup state authorizes replay or implies exactly-once
execution. Report creation uses the store's explicit private owner/ACL policy.

Future runtime packaging copies supplied approved EXE bytes and canonical Skill
content, renders only distribution routing, and records actual hashes, PE/build
identity and provenance. Source and runtime archive contracts remain separate;
neither a successful package check nor CI grants publication permission.
The scoped hosted Windows build/runtime evidence is recorded in
[project metadata](../spec/project.json); desktop GUI, hardware and owner
acceptance remain pending. These interfaces are not retroactively present in
the published owner binaries.

Exact-binary frozen-membership race evidence, full hardware coverage and
attributable allocation-release measurements remain open. Scheduling changes
should follow phase measurements; no universal maximum-speed claim is made.

## Source encoding

Owned C/C++ units, modules, headers, PowerShell/Python scripts, CMake scripts and documentation use UTF-8 with BOM. Windows bootstrap and source validation check the maintained file set. Explicit compiler UTF-8 settings cover project inputs, generated probes and vendor standard-library modules. Locked third-party bytes remain unchanged.

Host exceptions remain: Skill frontmatter starts with `---`; JSON/JSONL and YAML metadata use UTF-8 without BOM; minimal CMD launchers use ASCII/CRLF. Stored source BOMs do not become stdout or manifest BOMs.
