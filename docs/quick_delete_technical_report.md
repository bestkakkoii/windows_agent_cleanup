# Quick deletion on Windows: implementation and reproduction report

## Abstract and scope

Quick removes an explicitly admitted set of filesystem names through handle-bound Windows APIs. It avoids payload overwrite/readback, batches Agent requests in one native process, externalizes large target strings/results, schedules ready dependency nodes by physical-device group, and defers recovery until the first pass completes. It trades additional admission and identity work for bounded resources, diagnosable partial completion and resistance to path replacement. This is a source-derived engineering report, not a claim of theoretical maximum throughput.

Source audit: 2026-10-16; runtime baseline [`f6c4bcbd59fc5c2821109d81983b998129e41834`](https://github.com/bestkakkoii/windows_agent_cleanup/tree/f6c4bcbd59fc5c2821109d81983b998129e41834). The subsequent evidence-only commit did not change these algorithms. This report introduces no native implementation change. For a later binary, bind its exact SHA-256 and reported build identity before attributing this description or historical test evidence to it. Unknown source correspondence stays unknown. Release labels do not identify CLI contract support.

Reading order: sections 1–4 explain deletion; 5–8 reproduce scheduling/recovery; 9–11 reproduce and evaluate execution. Exact operational authority remains in the [Skill](../skills/project-cleanup/SKILL.md), architecture boundaries in [design](design.md), current acceptance in the [Windows test plan](windows_test_plan.md) and [publication policy](publication.md).

## 1. What deletion changes

A path is a name in a filesystem namespace. A handle is a live reference to an opened object. File identity distinguishes that object from a later object at the same path. Hard links are distinct names referring to the same file. Allocation is storage backing a file; logical length is the stream's end-of-file offset. These quantities are not interchangeable.

On NTFS, unlinking involves directory entries, link/reference state and allocation bookkeeping; the MFT and filesystem journals are binary metadata structures, not a few editable text pointers. ReFS/FAT/exFAT have different metadata implementations. Quick asks the filesystem to perform supported namespace operations; it never edits the MFT, allocation bitmap, raw sectors or a device's translation tables itself.

Removing a name need not release all allocation immediately: another hard link, open handle, mapping, snapshot or shared extent can retain backing storage. SSD controller reclamation is a further layer. Quick neither proves physical erasure nor requests per-file TRIM, and does not inventory VSS snapshots. It does not move data to the Recycle Bin.

Deleting one large file does not require transferring its whole payload. Deleting many tiny files requires many individual namespace/metadata operations. Approximate elapsed time as:

```text
total = startup + input/preparation + sort/freeze/admission
      + first_pass + recovery + report/output + teardown
first_pass cost depends on count, depth, metadata latency, contention and parallelism;
it is not payload_bytes / sequential_device_bandwidth.
```

This is a cost decomposition, not a fitted performance model. Antivirus/minifilters, directory-index changes and filesystem journal work can add I/O even though Quick does not read payload bytes [R1–R4].

## 2. Source map and ownership

| Source | Reproduction entry points / responsibility |
|---|---|
| [`src/modules/quick_delete.ixx`](../src/modules/quick_delete.ixx) | Frozen target/index contracts, resource observations, backend interface, options |
| [`src/core/quick_delete.cpp`](../src/core/quick_delete.cpp) | `fit_resources`, staged admission, `execution`, dependencies, `feedback`, `recover` |
| [`src/modules/quick_feedback.ixx`](../src/modules/quick_feedback.ixx) | Pure `observe_window` concurrency controller |
| [`src/core/quick_store.cpp`](../src/core/quick_store.cpp) | Record encoding, sorted runs/merge, sealed index, outcomes, integrity checks |
| [`src/windows/windows_backend.cpp`](../src/windows/windows_backend.cpp) | `prepare_stream`, `quick_observe`, `inspect_resources`, `acquire`, `remove_held` |
| [`src/windows/backend_locks.cpp`](../src/windows/backend_locks.cpp) | Restart Manager discovery, process eligibility, graceful/explicit-force actions |
| [`src/windows/state_store.cpp`](../src/windows/state_store.cpp) | Private files, ACL/handle ownership, report and state lifetime |
| [`src/app/application.cpp`](../src/app/application.cpp) | GUI-facing job lifecycle; see owning application/module contracts |
| [`src/cli/main.cpp`](../src/cli/main.cpp) | Machine CLI input, exact request binding, result/evidence delivery |

Own C++ units use named modules and `import std`; Windows headers stay at boundaries. GUI and CLI share Quick algorithms. Their presentation/startup costs differ. The deletion workers use `std::jthread`, synchronization and synchronous handle operations; this implementation has no Quick IOCP pipeline, OpenMP scheduler, GPU path or direct NTFS driver.

## 3. Preparation: enumerate once, seal the complete set

1. Consume absolute literal input names incrementally. The CLI accepts BOM-free UTF-8 JSONL; a directory explicitly selects its existing subtree. A scope root alone does not select every descendant.
2. Bind scope/protection and inspect filesystem objects by handle. Obtain canonical spelling, volume GUID, file ID, creation time, type, attributes, allocation hint and default-stream logical length. Reject uncertain protected/reparse identities. Retain typed preparation failures rather than silently losing targets.
3. Enumerate independent directories with bounded workers using `FindFirstFileExW` / `FindNextFileW`, `FindExInfoBasic`, `FIND_FIRST_EX_LARGE_FETCH` and case-sensitive enumeration. Basic information avoids requesting short-name information; large-fetch requests a larger enumeration buffer, not a guaranteed speedup [R4].
4. Charge queued work, temporary handles and retained ancestor leases. A worker that cannot enqueue more child work uses charged local traversal instead of blocking forever on its own full queue. Preparation workers and execution workers have different budgets.
5. Append observations to bounded sorted runs in the private staging store, merge runs, and deduplicate exact names. Conflicting observations of the same name refuse a consistent freeze. Preserve different selected hard-link names, even when file identity matches.
6. Seal the complete set, construct indexes/dependencies, validate fingerprints and reserve execution/outcome capacity before target deletion. Sorting chunks are storage implementation details: none becomes an independently executed destructive mini-batch.

The frozen set is a completed enumeration, not an atomic filesystem snapshot taken at command start. Items observed before sealing can enter it; anything outside that final set cannot later be added to execution. A changed/replaced selected identity is refused. New children can leave a selected directory nonempty and cause removal failure; the engine does not recursively expand its set during recovery.

Identity binds volume GUID plus the backend's file-ID representation, not a reusable drive letter alone. The backend prefers `FileIdInfo` and uses its checked legacy identity observation only for recognized unsupported-info errors. Execution additionally compares creation time, directory type and exact canonical path. This is identity checking, not payload hashing or content immutability: writers can change the same file's content without changing its identity.

## 4. Exact namespace-removal operation

### 4.1 Acquire the intended object

`remove_held` calls `acquire` with:

```cpp
FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE
// Add FILE_WRITE_ATTRIBUTES only for the recovery-access attempt.
```

The actual open is `CreateFileW(..., OPEN_EXISTING, ...)`, with:

```cpp
share = FILE_SHARE_READ | FILE_SHARE_WRITE; // no FILE_SHARE_DELETE
flags = FILE_FLAG_OPEN_REPARSE_POINT
      | FILE_FLAG_BACKUP_SEMANTICS
      | FILE_FLAG_POSIX_SEMANTICS;
```

`BACKUP_SEMANTICS` permits directory handles and participates in authorized backup/restore access semantics; it is not a blanket bypass of every access check. `OPEN_REPARSE_POINT` avoids resolving the final reparse target. Ancestors are separately pinned and checked; the flag alone cannot secure a whole path. `POSIX_SEMANTICS` on the open preserves applicable case-sensitive naming; it is distinct from the deletion flag below [R1].

The backend caches retained ancestor-handle contexts subject to a handle budget, but refreshes ancestor reparse attributes even on cache hits. It checks scope, canonical namespace, system/self/state protection and frozen identity again after opening. Omitting share-delete helps prevent concurrent rename/delete while the object is held. Existing incompatible handles can prevent this open; no deletion flag bypasses that sharing check.

### 4.2 Request deletion on that handle

The primary call is:

```cpp
FILE_DISPOSITION_INFO_EX disposition{};
disposition.Flags = FILE_DISPOSITION_FLAG_DELETE
                  | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                  | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
SetFileInformationByHandle(file, FileDispositionInfoEx,
    &disposition, sizeof(disposition));
```

| Flag | Meaning in this operation |
|---|---|
| `DELETE` | Request removal of the opened name |
| `POSIX_SEMANTICS` | Permit POSIX-style namespace removal on close of the delete handle; existing valid handles may retain access to data |
| `IGNORE_READONLY_ATTRIBUTE` | Allow supported readonly deletion without separately clearing the attribute |

The filesystem/driver performs metadata updates and enforces its constraints. POSIX deletion is neither forced handle closure nor a bypass of mapped-image, sharing, security or nonempty-directory restrictions [R2, R3]. The same handle-disposition mechanism handles files and directories; Quick does not shell out to `del`, `rmdir` or PowerShell.

### 4.3 Restricted fallback and readonly recovery

For `ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED` or `ERROR_INVALID_FUNCTION`, the backend can try `FileDispositionInfo` with `FILE_DISPOSITION_INFO{TRUE}`. These are filesystem/API capability fallbacks on the current supported host, not a separate legacy-OS mode.

There is also a recovery-only readonly/access-denied path. If a readonly attribute must be changed, require recovery permission and a single-link observation; clear it through the held handle. Do not modify shared attributes on multi-link files. If fallback deletion fails after changing the attribute, restore the observed original attributes; restoration failure becomes a critical stopping error. Other failures retain their original Win32 code instead of blindly trying every API.

### 4.4 Close, then verify namespace evidence

Close the deletion handle, keep ancestor pins, and reopen the same literal name with attribute access, share-read/write/delete, and reparse-safe flags:

- `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND`: original name is absent; accept namespace completion.
- Open succeeds and identity still equals the original: report `quick_original_name_still_present`.
- Open succeeds with a different identity: original binding is gone; accept its removal and leave the replacement untouched.
- Another open/query error: report uncertainty, e.g. `quick_deletion_not_observed_may_be_pending`; do not equate delete-pending with proven completion.

This is a namespace observation at a point in time, not power-loss durability or a free-space assertion. A third party can recreate the path later. Ordinary successful removal uses neither payload `ReadFile`/`WriteFile` nor per-target `FlushFileBuffers`; the staging/report mechanisms do perform their own I/O.

## 5. Large-batch storage and complexity

The store externalizes full variable-length targets and fixed outcome records. Current layout constants are a 152-byte index record (120 payload + 32 integrity bytes) and a 576-byte outcome slot per target. Thus these two files alone account for `728 × N` bytes, before target records, sort/merge overlap, other metadata and filesystem overhead. This is not a complete disk-space estimate. Internal layouts are implementation details, not an importable execution-plan format.

Target records have checked lengths and SHA-256 integrity, and the sealed plan fingerprint binds job/membership metadata. Native scratch has restricted ACLs, exclusive owned handles and no reparse traversal. Unkeyed hashes detect corruption/consistency failures; they do not authenticate data against an attacker who can rewrite both data and hashes. ACL/held-handle ownership is a separate trust boundary.

A bounded directory cache accelerates parent lookup; on misses, binary search over the sealed index avoids retaining every parent path in RAM. Sorting/merging has comparison work on the order of `N log N`; prefix-parent lookup can require up to `D log N` searches per target in deep/cache-miss cases. Ready heaps add logarithmic queue work. Record decoding/hashing, path conversions and filesystem calls are material costs beyond these simplified bounds.

Resident execution metadata still grows with target count. The staged estimator charges `256 × N` bytes plus shared statistics/space-observation allowance, per-device strings, staging resident buffers and bounded scratch. Each worker also has an explicitly charged target/stack/path budget. This is conservative owned-state accounting, not exact allocator usage or an OS-enforced process RSS ceiling. Quick scratch belongs to the live job and is removed on normal final close; it is not a durable cross-process resume token.

## 6. Resource admission and device grouping

### 6.1 Resource observations

- RAM/commit: `GlobalMemoryStatusEx`, `K32GetPerformanceInfo`; constrain by available global commit and applicable Job Object memory limits. Job peak usage is a conservative estimate where used.
- CPU: active logical processors, applicable affinity, physical-core observation and sampled CPU pressure.
- Handles: `GetProcessHandleCount` plus a conservative headroom heuristic, not a Windows quota reservation.
- Scratch: available space in the protected state location; staging allocation/write errors still remain possible after a sample.
- Storage: volume disk extents (`IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`), seek-penalty and bus information (`IOCTL_STORAGE_QUERY_PROPERTY`).

Overlapping observed disk sets form connected scheduling groups. Two drive letters sharing a physical disk do not earn independent throughput budgets. Unknown/RAID/virtual/Storage Spaces relationships are conservative: if any involved topology is unknown, this backend groups the observed volumes under `physical_unknown`, rather than advertising hidden backing disks as independent.

Seek-penalty/USB profiles start with concurrency hint 1; other profiles use a CPU/core-derived hint. A hint initializes group parallelism; it is not a permanent HDD cap, a measured SSD IOPS figure, or proof that the full backing topology is visible.

### 6.2 Reproduce the execution ceiling

Let `N` be admitted targets, `L` available logical processors, `R` free RAM, `C` available commit, `D` maximum ancestor depth, `T` maximum target-window bytes, and `H` the backend's estimated available handles:

```text
B = min(R, C) / 4
B = min(B, caller_memory_limit), if a nonzero limit was supplied
h = D + 4
w = 2 MiB + 4*T + 256*D                  # staged worker charge
M = charged resident-plan + execution metadata
worker_capacity = min(N, floor((B-M)/w), floor(H/h), 2*L,
                      nonzero caller_worker_limit if present)
```

All integer arithmetic is checked; insufficient complete-plan/worker headroom refuses admission. The observed `H` is approximately `max(0, floor(min(R,C)/65536) - own_handle_count)`. These engineering constants reserve headroom; they do not claim that this many handles/threads will actually be available.

CPU pressure unknown or at least 90% makes the active worker limit 1; 75–89% reduces the capacity by half, with minimum 1; below that it may use full admitted capacity. Preparation separately budgets roughly `min(R,C)/8` for its working set and limits threads by logical processors, 8 MiB per worker and conservative handle/depth charges; CPU pressure at least 85% reduces its nonzero limit by four.

The whole admitted `std::jthread` pool is created behind a latch before it can mutate targets. Thread-creation failure therefore prevents first-pass deletion. Later resource probes, nominally at 100 ms intervals when workers reach the probe point, adjust active limits within that initial capacity. They do not grow the original pool beyond admitted capacity. Topology changes, failed probes and exhausted resources can stop remaining work after earlier removals; this is not a transactional rollback.

## 7. Ready dependencies and measured concurrency

Build a node for every target, with its nearest selected parent directory and remaining-child count. Put zero-child nodes on per-group ready heaps. Each completed first-pass node, including a failed attempt, settles its dependency; once all its children settle, its parent can be attempted. A retained failed child can make that attempt fail as nonempty. Do not wait for every file on every unrelated subtree before attempting a ready directory.

The default ready priority is: ready directories first; then regular-file candidates with larger observed `AllocationSize` first (`space_first`); then deterministic index order. Allocation is a scheduling hint only. This greedy preference seeks earlier namespace/space progress, not a globally optimal deletion order, and does not imply actual reclaim equals the hint. It may sacrifice locality on some HDD workloads.

Select eligible groups round-robin, constrained by global active count and each group's active limit. Each group's initial limit is at most `min(2, global_limit, concurrency_hint)`; hints shared in one group can reduce that initial limit.

The current feedback controller is deliberately small and reproducible:

| Condition | Action |
|---|---|
| Fewer than 8 successful file completions or less than 25 ms in the window | Accumulate more observations; no adjustment |
| CPU pressure at least 75%, or a known device pressure at least 75% | Halve group concurrency, minimum 1; cancel probe; cooldown 3 completed windows |
| Two sufficiently stable non-probe windows, backlog at least 4 × group limit, known CPU pressure, capacity available | Add one concurrent operation and capture baseline |
| Two probe windows each reach at least 1.05 × baseline rate with latency at most 1.50 × baseline | Retain the extra concurrency |
| Rate below 0.90 × baseline, or latency above 1.25 × baseline without 1.05 × rate; or probe fails to earn two profitable windows | Remove the added operation and cooldown 3 windows |

Stable non-probe means rate at least 85% of the previous rate and mean operation latency at most 120% of its previous value; the first observation also seeds stability. Rate is successful file completions divided by observation-window wall time. Mean latency is accumulated operation durations divided by successful file samples. Directories and failures do not train this controller. Tiny/all-failing/directory-heavy jobs may never produce informative windows. Selection/recording and admission overhead still affect end-to-end time.

**Current limitation:** `quick_storage_pressure` explicitly leaves direct device pressure unknown; it does not enable disk performance counters or measure queue depth. Disk behavior is inferred mainly through completion-rate/latency feedback. Do not describe this implementation as complete live hardware telemetry, a learned optimizer, or a proof of maximum throughput. Global memory/CPU pressure can reduce active work even when extra concurrency previously helped.

## 8. Deferred recovery, authority and interruption

First-pass workers call `attempt(index, false)` and continue after ordinary per-target failures. Only after all first-pass workers finish without cancellation/fatal stop does a separate, currently serial recovery walk begin. Eligible failures receive an access-recovery retry; only a remaining lock-class failure triggers lock-owner discovery.

Restart Manager discovery uses `RmStartSession`, `RmRegisterResources`, `RmGetList`, then session cleanup. It is a registered-resource discovery API, not a universal handle scanner [R5]. The Quick recovery layer refuses a list above 256 processes; it deduplicates attempted close actions by `(PID, creation_time)` and bounds that set at 1,024. These are recovery protection bounds, not target-count ceilings.

For an eligible unprotected user process, requery lock ownership and verify PID, creation time, image and protection state before action. Graceful closure enumerates that process's windows and sends bounded `WM_CLOSE` through `SendMessageTimeoutW`, then waits. A process may prompt, refuse, hang or have no closable window. Another thread can retain a handle; success is never assumed from the message alone. `RmShutdown` is deliberately not called, so refreshed discovery cannot silently broaden the set of processes closed.

Automatic Quick recovery passes `force_confirmed=false`. Separately authorized force operations can use a held, revalidated process handle with `TerminateProcess`; normal batch approval does not authorize this. Quick does not duplicate/forcibly close another process's handle, stop arbitrary services, change persistent owner/DACL, load a driver, schedule reboot deletion or call `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`.

Backup/restore access recovery uses a duplicated private thread impersonation token with applicable `SeBackupPrivilege` / `SeRestorePrivilege`; it restores the prior thread token after the action. It does not permanently enable privileges on the process token. A restore failure stops further work and retains a critical diagnostic. Reparse/protection/identity refusals remain refusals despite available administrator privileges.

Cancellation/fatal stop suppresses automatic final recovery. Already removed names stay removed; unattempted work stays explicit. Reusing retained live-session evidence is distinct from restarting a job. Read-only v2 `status` can reconcile protected request evidence but cannot revive Quick scratch, infer exactly-once execution or authorize replay.

## 9. Agent integration, results and timing

Batch selected roots/names into one native request. Avoid one shell/process per file and do not require a separate advisory `scan` before every authorized `run`. Scan does not freeze a later request. Cache static capabilities by exact EXE hash; refresh host readiness after an execution-host/token change. Keep manifest and report state outside the authorized root and targets. Protocol options and authority are maintained in the Skill, not redefined here.

Default/unversioned calls retain v1. Explicit v2 adds typed readiness, shared statistics, phase timing, bounded failure categories and request status. Use the exact package's hash-bound contract advertisement; never infer support from the distribution name. v2 counts unique selected namespace entries, unique entries reaching an actual backend remove call and final completed entries; retries do not multiply these unique totals. The attempted statistic is not the total number of system calls or retry calls.

Known byte totals are snapshot default-stream logical lengths, directories contribute zero, and unknown type/size is explicit. They omit named-stream lengths and are neither allocation nor reclaimed capacity. At most 128 eligible frozen volumes receive before/after free-space observations; truncation/failures remain explicit. `GetDiskFreeSpaceExW` distinguishes caller-available space from total free space; background allocation, other handles and storage layers affect the difference [R6].

Measure with a monotonic external stopwatch around the native process as well as internal phases. Internal total ends before final result/stdout delivery and teardown; report rows and private logs are different evidence channels. Preserve exact stdout, exit code, request/job ID, fingerprint, report path, unknown fields and errors. A zero/empty error field alone does not mean the batch completed.

## 10. Reproduce the implementation and a disposable experiment

### 10.1 Build and inspect without modifying real project data

For development, check out the audited revision and follow [CONTRIBUTING.md](../CONTRIBUTING.md#build-from-source): `build_release.bat` configures/builds Release and runs safe suites. In an already elevated isolated environment, `build_release.bat -enable_isolated_destructive_tests` adds disposable destructive fixtures. Preserve `build_logs/<run_id>/`, compiler/SDK identities, EXE hashes and case-level `not_run` outcomes. Do not run destructive fixtures against real user material.

To implement the same algorithm independently, use the source-map contracts, reproduce the open/disposition/probe sequence in section 4, the sealed store/admission in sections 3/5/6 and the dependency/feedback state machine in section 7. The API sequence alone is insufficient to reproduce scope/protection and recovery guarantees. Existing focused tests cover Quick scheduler/resource behavior, staging integrity and Windows backend/state behavior; their source names are listed in [the test plan](windows_test_plan.md).

### 10.2 Minimal native experiment (PowerShell 5.1/7)

This example is deliberately destructive only to its newly created fixture subtree. Bind `$cli` to a verified advertised-v2 runtime EXE outside the fixture and run from an already elevated supported Windows host. It creates 10,000 files as a chosen experiment size, not an engine limit. It leaves evidence and the parent lab directory intact. The example has not been executed as part of this documentation update. Native stderr is retained as shell-produced text; use the Skill's maintained caller example for durable intent/result handling across interruptions.

```powershell
$ErrorActionPreference = 'Stop'
$cli = '<absolute verified tool path>\bin\secure_erase_cli.exe'
$utf8 = New-Object Text.UTF8Encoding($false, $true)
$capabilities = & $cli capabilities --contract-version 2
if ($LASTEXITCODE -ne 0) { throw 'lab.capabilities_failed' }
$lab = Join-Path ([IO.Path]::GetTempPath()) ('wac_lab_' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($lab)
$root = Join-Path $lab 'project'
$payload = Join-Path $root 'disposable'
[void][IO.Directory]::CreateDirectory($payload)
$bytes = New-Object byte[] 1024
for ($d = 0; $d -lt 100; ++$d)
{
    $directory = Join-Path $payload ('set_{0:d4}' -f $d)
    [void][IO.Directory]::CreateDirectory($directory)
    for ($f = 0; $f -lt 100; ++$f)
    {
        [IO.File]::WriteAllBytes((Join-Path $directory ('item_{0:d4}.bin' -f $f)), $bytes)
    }
}
$manifest = Join-Path $lab 'manifest.jsonl'
$reports = Join-Path $lab 'reports'
$id = 'lab_' + [Guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($manifest, ((@{path=$payload} | ConvertTo-Json -Compress) + "`n"), $utf8)
$clock = [Diagnostics.Stopwatch]::StartNew()
$raw = & $cli run --mode quick --contract-version 2 --request-id $id `
    --root $root --manifest $manifest --report-dir $reports --authorize-irreversible `
    2> (Join-Path $lab 'native_stderr.txt')
$exit_code = $LASTEXITCODE
$clock.Stop()
[IO.File]::WriteAllText((Join-Path $lab 'native_stdout.json'), ($raw -join "`n"), $utf8)
[IO.File]::WriteAllText((Join-Path $lab 'capabilities.json'), ($capabilities -join "`n"), $utf8)
[IO.File]::WriteAllText((Join-Path $lab 'measurement.json'), ((@{
    exit_code=$exit_code; native_process_ms=$clock.Elapsed.TotalMilliseconds
    payload_name_remaining=(Test-Path -LiteralPath $payload)
    cli_sha256=(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress)), $utf8)
$raw
$lab
if ($exit_code -ne 0) { throw ('lab.native_failure:' + $exit_code) }
if (Test-Path -LiteralPath $payload) { throw 'lab.payload_name_remaining' }
```

With no interference, expect 10,000 selected files, 101 selected directories, 10,240,000 known logical file bytes, no failed/pending entries, and the selected `disposable` directory absent. This is an expected fixture outcome, not a reported measurement. The enclosing `project` directory is scope, not a selected target. Inspect the original v2 result and external report; a simple absence check does not verify every protection or race invariant.

### 10.3 Fair comparison with shell deletion

Regenerate an equivalent fresh fixture for every run. For a `cmd /c rmdir /s /q` or PowerShell `Remove-Item -LiteralPath ... -Recurse -Force` baseline, select only that run's disposable subtree, preserve errors and independently verify absence. Keep the same token, device, filesystem, file count/size/depth and background conditions. These baselines do not enforce the same frozen-identity/protection contract; disclose the semantic difference.

Include process startup, enumeration/admission, reports/output and failure recovery in the primary metric. Also show internal first-pass time separately. Use successful files/s and namespace entries/s with separate directory counts; logical bytes/s must be labeled logical, not SSD bandwidth or reclaimed bytes. Report at least repeated-run median and spread with run order varied; distinguish warm/cold-cache conditions without pretending to guarantee a cold storage state.

Record CPU/model/core count, RAM/free commit, storage model/bus/topology, filesystem, Windows build, tool hash/source correspondence, worker settings, security software/minifilters and observed errors. Do not disable security software or alter production policy merely to improve a benchmark. WPR/ETW/WPA or other explicitly available read-only instrumentation can investigate where time goes; observation overhead belongs in the result. Such instrumentation is not automatically enabled by this tool.

## 11. Evidence, limits and experiments that can reject the design

This audit produced no new Windows execution, owner acceptance or throughput measurement. Previously recorded hosted CI validates its exact compiled revision and fixture scope; owner uploads with different hashes need their own binding/evidence. Current results and unexecuted cases belong in the test plan/publication records, not repeated performance figures here.

| Hypothesis / invariant | Reproduction probe | Failure evidence |
|---|---|---|
| Full admission precedes mutation | Insufficient scratch/RAM budget; injected thread-creation failure | Any selected name removed before admission/pool release |
| New/replacement targets are excluded | Replace a frozen name or add a child between sealing and execution | Replacement removed, or unexpected new child selected |
| Namespace success differs from space reclamation | Disposable hard-link pair or a compatible retained open handle | Claim of reclaimed bytes from a logical name count |
| Deferred recovery protects normal throughput | Disposable holder process on a minority of selected files | Lock discovery/closure before first pass ends |
| Physical grouping prevents false independence | Compare same-disk volumes with truly independent disks | Independent budgets assigned to known shared backing media |
| Concurrency earns observed gains | Sweep fixed worker settings versus auto over regenerated fixtures | Auto repeatedly regresses beyond ordinary run variation |
| Report semantics are consistent | Reconcile stdout, per-target report and actual names | Unique totals inflated by retries or unknowns silently zeroed |

Use isolated fixtures and relevant existing tests for race/lock/fault probes, not ad hoc mutations of production projects. These are acceptance experiments, not claims that every probe has run on every filesystem.

Practical limitations: full admission delays first deletion; external sorting/hashing and per-target metadata/security checks cost work; file operations are synchronous within each worker; recovery is serial and can wait on applications; the feedback sample favors successful files; the resource ceiling is a conservative heuristic; controller thresholds are fixed engineering choices. There is no guarantee of beating every shell command, exploiting every storage queue, instant space return or surviving arbitrary power loss with exactly-once effects.

Steam's proprietary uninstall internals have not been established by this project. Logical unlinking is a shared OS concept, not evidence that Steam uses these exact APIs, manifest policies or reboot cleanup. The implementation described here deliberately does not pretend to reproduce undocumented Steam behavior.

## References

Official primary API contracts checked 2026-10-16. Implementation-specific constants/ordering above come from the audited repository source; Microsoft describes the OS contracts, not this scheduler's performance.

- **R1:** Microsoft, [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew): access/share modes and open flags.
- **R2:** Microsoft, [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle): handle-based metadata changes.
- **R3:** Microsoft, [FILE_DISPOSITION_INFORMATION_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex) and [DeleteFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew): disposition, open-handle and namespace semantics.
- **R4:** Microsoft, [FindFirstFileExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfileexw) and [FINDEX_INFO_LEVELS](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-findex_info_levels): enumeration options and metadata freshness.
- **R5:** Microsoft, [Restart Manager functions](https://learn.microsoft.com/en-us/windows/win32/rstmgr/functions) and [RmGetList](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist): registered-resource process discovery.
- **R6:** Microsoft, [GetDiskFreeSpaceExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw): caller-available and total free space.
