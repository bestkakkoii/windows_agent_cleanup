# Windows validation and performance plan

This is the acceptance plan for Windows Agent Cleanup 2.x on Windows 11+ x64. It defines required evidence, not completed results. The owner supplies Windows compilation and hardware runs; engineering supplies the implementation, fixtures, scripts and corrections. Source inspection, portable tests and WinAPI declaration stubs do not establish native behavior.

Use only created disposable fixtures in a VM, disposable volume or dedicated test device. Capability rejection is valid evidence of refusal; it is not a supported-device pass. Do not weaken protection to make a test green.

## Build evidence

From a clean source checkout, run `build_release.bat` and `validate_windows.bat`. Build under an ordinary effective token; the CLI uses an as-invoker manifest, while the GUI uses its administrator manifest. Current CLI filesystem commands separately require an already elevated token; capabilities does not. Verify both the explicit `elevation_required` refusal and permitted elevated execution without a CLI UAC request. Opt-in fixtures that need privileges must run with those privileges already available; validation does not grant them.

Install Visual Studio x64 C++ tools with the vendor standard-library module, a complete Windows SDK 10.0.22000.0+, and a bootstrap CMake 3.15+ (VS-bundled accepted). The script builds exact hash-locked upstream-master CMake 4.5.20261015 and Ninja 1.14.0.git into ignored `build/tools`; installed Ninja is optional because `nmake` can bootstrap it. First build needs network and more compilation time; a valid binary-hash-verified cache supports offline rebuilding without global installation. Preserve all recorded exact identities. Check actual `/std:c++latest`, Release `/O2 /GL /LTCG /MT`, strict diagnostics, no debug instrumentation/PDB, native module ownership and vendor `import std`. A CMake metadata label alone does not prove compiler mode or feature completeness.

Keep the complete `build_logs/<run_id>/` output outside Git. Verify fresh first-build dependency restoration with the locked hashes, a cached offline rebuild, non-ASCII paths and spaces, PATH/fallback tool discovery, clean rebuild without prebuilt IFC/BMI, incompatible std-provider rejection, and Debug rejection. A corrupt dependency must be repaired and reverified or rejected before compilation.

`validate_windows.bat -enable_isolated_destructive_tests` explicitly registers/runs disposable native fixtures. The registered native suites are `windows_backend_isolated`, `state_store_windows_isolated` and `quick_delete_windows_isolated`; safe suites and script/module checks run separately. Fixture unavailability, skipped cases and environmental refusal stay visible at case level. A suite-level pass does not certify a fixture that never ran.

## Runtime acceptance

| Area | Required observations |
|---|---|
| Agent entry | Fresh sessions using only the absolute README path, optional Codex Skill, optional Claude Skill, and delegated discovery. Ask for the predefined plan/scope; scan does not delete; development routing never cleans the repository. |
| Disposable classification | Include known generated/cache/intermediate material, active outputs, valuable research, uncertain code, unique copies and unconfirmed local changes. Ambiguous items remain intact. Large known groups use programmatic discovery rather than per-file model context. |
| Native CLI | Verify `capabilities`, `run`, `scan` and protected overwrite resume against their current schema. One final compact stdout JSON result, bound identifiers, exact exit code and external failure report. Existing safe private report stores can be reused exclusively; `scan_partial` returns exit3 and does not delete. Unknown/duplicate input, BOM, malformed UTF-8, blank records, wildcards, ADS and invalid local paths reject. |
| Batch scale | Tens and hundreds of thousands of tiny files, including more than 100000 targets where resources permit. Measure manifest read, parallel preparation, bounded external runs, sealed indexes, outcome reservation and total peak memory. Full strings/outcomes stay in protected scratch; compact scheduling metadata still needs resource admission. Under memory/commit/handle/disk pressure, reject before deletion rather than truncate. |
| Frozen membership | Mixed and overlapping selections, duplicate selected names, root aliases, additions after preparation and replaced targets. New/replacement objects survive. A nonempty directory with unselected/new members fails without pursuing them. |
| Protection | System/boot/recovery/WRP/service resources, protected aliases, own binaries/state and inaccessible protection evidence refuse mutation. Reports and plans cannot overlap the authorized cleanup root. |
| Reparse and links | Final/ancestor junctions, symlinks, mount points, placeholders and case-sensitive names. No unexpected traversal. Distinct selected hardlink names remain distinct; quick deletion preserves unselected aliases and shared contents. Overwrite of shared links requires the advertised refusal/downgrade policy. |
| Quick recovery | First-pass success work completes before access/lock recovery. Limited final retries retain identity checks. Test read-only/access denied fixtures, user-held handles, exited/PID-reused processes, service/critical/protected/other-user processes and case ambiguity. No unattended force; explicit process actions bind the exact approved identity. |
| Overwrite | Empty, unaligned, multi-MiB and >4GiB files where supported; complete write/flush/readback comparison, all admitted ADS, sparse/compressed/EFS/resident behavior, capability change, exact per-target downgrade consent and truthful failure. |
| Checkpoint/integrity | Pause/cancel during write and verification, process/power interruption, changed identity/streams/metadata, cursor bounds, tampered/swapped/rollback blobs, unsafe ACL/reparse store, torn log tail and concurrent execution. Fresh exact-plan authorization; authenticity is not anti-rollback. |
| Cross-process behavior | Overlapping root/descendant/alias requests serialize or reject. Known compilers/watchers are coordinated. No endless rescan of new output. Repeated IDs and missing completion evidence do not imply durable exactly-once execution. Quick jobs have no persisted full membership or cross-process resume; interrupted quick work cannot be blindly re-submitted. |
| GUI | Unicode/long paths, picker/drop input, successful-target list clearing, mixed outcomes, resizing/DPI/device reset, responsive snapshots, pause/cancel, close during startup/work and protected overwrite history/resume. |
| Space observations | Remaining open handles, outside hardlinks, sparse/shared allocation and unrelated disk activity. Raw quota-visible counters and failures remain truthful; no attribution of all free-space delta to this job and no immediate-reclamation guarantee. |
| Storage/faults | NTFS/ReFS/FAT32/exFAT on applicable HDD/SSD/USB devices; same-disk partitions and independent devices. Unknown/remote/virtual/multidisk capabilities follow explicit policy. Disconnect a disposable USB or inject I/O failure and preserve partial diagnostics. |
| Retained copies | Existing/no VSS copies and provider failure are reported detected/unknown; no modification of snapshots or backups. |
| Retention | Private state/report ACLs, log rotation/expiry, incomplete checkpoint policy, completion cleanup and distinct audit/storage failure. |
| Interruption/output | Ctrl+C, host timeout, broken stdout, report-write failure and forced termination. A final acknowledged result is required for success; lost evidence is unknown/partial, without automatic fresh deletion. |

Run on the lowest claimed Windows 11 API baseline and representative newer builds. Record numeric OS builds, not only marketing labels. Record each filesystem/device case as `not_run`, `passed`, `failed` or `unsupported_expected`; unavailability cannot silently satisfy a mandatory platform case. Use [the evidence template](../spec/windows_evidence_template.json).

## Performance method

Compare the previous fixed-concurrency design, controlled fixed worker settings, the adaptive design, CMD and PowerShell using regenerated equivalent disposable data. Randomize order and repeat. Separate tracing/profiling from uninstrumented measurements. State that comparison tools can have different identity/protection costs.

Include few large files, many tiny files, deep/wide trees, long names, mixed failures, one HDD, SSD/USB, two partitions sharing a device and independent devices. Run short batches as well as sustained work; auto-tuning must not consume more time than a short job saves. Background load and filesystem/filter-driver interference belong in the record.

Primary measurement is total time from manifest/discovery through admission, deletion, final recovery and summary. Also record phase times, successful items/second, latency, CPU time, peak RAM/commit/handles/temp storage, device grouping and admission decisions, failures, and capacity observations. Agent integration comparisons include tool-call count, returned bytes and context consumption. Do not extrapolate an inner-loop rate to end-to-end speed or publish an invented improvement factor.

## Evidence and release gate

Bind logs, commands, fixture recipe, expected/actual statuses, compiler/SDK/std provider, dependency lock, OS/device/filesystem identities and source/package SHA-256 to one revision. Build logs may reveal local paths; sanitize public excerpts without losing error codes and neighboring context. Keep protected checkpoints private unless diagnosis specifically requires them.

Release requires all applicable mandatory unit/integration/isolated destructive gates and the claimed native platform matrix to pass, with no unresolved blocking safety finding. Missing native/hardware evidence limits delivery to RC. Unsupported cases must be explicitly rejected or receive only their independently authorized lower capability. Attestations establish provenance, not runtime correctness, signing or physical NAND erasure.
