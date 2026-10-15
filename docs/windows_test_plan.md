# Windows validation and performance plan

This is the acceptance plan for Windows Agent Cleanup 2.x on Windows 11+ x64. It defines required evidence, not completed results. The owner supplies Windows compilation and hardware runs; engineering supplies the implementation, fixtures, scripts and corrections. Source inspection, portable tests and WinAPI declaration stubs do not establish native behavior.

Use only created disposable fixtures in a VM, disposable volume or dedicated test device. Capability rejection is valid evidence of refusal; it is not a supported-device pass. Do not weaken protection to make a test green.

## Build evidence

From the source repository root, run `build_release.bat` under an ordinary effective
token. The same command compiles, checks embedded manifests and executes all
safe suites. Safe C++ and script fixtures, diagnostics and CLI help do not
require administrator rights.
The CLI uses an as-invoker manifest, while the GUI uses its administrator
manifest. Current CLI filesystem commands separately require an already
elevated token; capabilities does not. Verify both the explicit
`elevation_required` refusal and permitted elevated execution without a CLI UAC
request. Only the explicit `-enable_isolated_destructive_tests` switch requires
an already elevated token for privileged fixtures; the build never grants it.
An opt-in elevation refusal after successful compilation retains that
compilation and manifest evidence; neither safe nor isolated tests start for that
invocation. There is one launcher and no build-only/validation mode.

Each invocation configures and builds `build/windows_release`, then checks the
completed binaries and runs CTest. A rerun is incremental, not an automatic clean
build. For clean-build evidence, use a fresh checkout/extraction with no existing
`build/windows_release`; record tool/dependency cache reuse separately. Keep the
previous logs before replacing a disposable build directory. CMD automation may
set `SECURE_ERASE_NO_PAUSE=1` to suppress the launcher's final pause.

Install Visual Studio x64 C++ tools with the vendor standard-library module, a complete Windows SDK 10.0.22000.0+, and a bootstrap CMake 3.15+ (VS-bundled accepted). The current dependency lock pins upstream-master snapshots of CMake 4.5.20261015 and Ninja 1.14.0.git. The script builds those exact sources into ignored `build/tools`; installed Ninja is optional because `nmake` can bootstrap it. First build needs network and more compilation time; a valid binary-hash-verified tool cache together with verified dependency files supports offline rebuilding without global installation. These are pinned snapshots, not a floating download of the newest branch head. Preserve all recorded exact identities. Check actual `/std:c++latest`, Release `/O2 /GL /LTCG /MT`, strict diagnostics, no debug instrumentation/PDB, native module ownership and vendor `import std`. A CMake metadata label alone does not prove compiler mode or feature completeness.

Keep the complete `build_logs/<run_id>/` output outside Git. Verify fresh first-build dependency restoration with the locked hashes, a cached offline rebuild, non-ASCII paths and spaces, a fresh bootstrap under system code page 950 with `/utf-8` for C and C++, PATH/fallback tool discovery, clean rebuild without prebuilt IFC/BMI, incompatible std-provider rejection, and Debug rejection. A corrupt dependency must be repaired and reverified or rejected before compilation.

Owned code/build files must decode as strict UTF-8 and carry a BOM; Windows
preflight checks them before discovery/compilation. Source validation additionally
checks documentation and host-format exceptions: Markdown normally has a BOM,
Skill frontmatter does not, JSON/JSONL/YAML have no BOM, and BAT uses ASCII CRLF.
Immutable upstream files retain their original bytes and compile with explicit
UTF-8 flags. Clear inherited `CL`, `_CL_`, `LINK`, `CFLAGS`, `CXXFLAGS` and
`RCFLAGS`; the build rejects these overrides instead of accepting unreviewed flags.

`build_release.bat -enable_isolated_destructive_tests` explicitly registers/runs disposable native fixtures. The registered native suites are `agent_cli_windows_isolated`, `windows_backend_isolated`, `state_store_windows_isolated` and `quick_delete_windows_isolated`; safe suites run first through a separate CTest invocation. The current Windows registration contains 11 safe suites and 4 opt-in isolated suites; record the actual names/counts from that revision's JUnit, not a portable-suite count or an old assertion total. Fixture unavailability, skipped cases and environmental refusal stay visible at case level. A suite-level pass does not certify a fixture that never ran. The Agent CLI fixture covers actual process input/output, protected reports, mixed batches, authorization/scope rejection, exact lock identity and reparse boundaries. Deterministic console cancellation, successful forced termination and overwrite media acceptance still require their separate evidence.

On a host whose virtual disk reports unknown media, `windows_backend_isolated`
verifies that overwrite is refused and the fixture's bytes, identity and metadata
remain intact. It explicitly records supported-device overwrite cases as
`not_run`; this is refusal coverage, not successful overwrite coverage. The build
result preserves individual `status: not_run` records in `coverage_gaps`. Also
inspect JUnit/raw stdout: the Agent CLI summary lists
`deterministic_console_cancellation`, `successful_force_termination` and
`overwrite_media_validation` in its `not_run` array, which is not merged into
`coverage_gaps`. A top-level `passed` result can still contain untested cases;
a whole-suite skip instead makes the build result `incomplete` with exit code 3.
These distinctions remain necessary even when CTest exits successfully. Missing
hardware cases prevent ordinary full-platform acceptance, subject only to the
explicit publication exception below. Protection is never relaxed to make a
hosted runner look like a supported physical device.

## Runtime acceptance

| Area | Required observations |
|---|---|
| Agent entry | Fresh sessions using only the absolute README path, optional Codex Skill, optional Claude Skill, and delegated discovery. Ask for the predefined plan/scope; scan does not delete; development routing never cleans the repository. |
| Disposable classification | Include known generated/cache/intermediate material, active outputs, valuable research, uncertain code, unique copies and unconfirmed local changes. Ambiguous items remain intact. Large known groups use programmatic discovery rather than per-file model context. |
| Native CLI | Verify `capabilities`, `run`, `scan` and protected overwrite resume against their current schema. One final compact stdout JSON result, bound identifiers, exact exit code and external failure report. Existing safe private report stores can be reused exclusively; `scan_partial` returns exit code 3 and does not delete. Unknown/duplicate input, BOM, malformed UTF-8, blank records, wildcards, ADS and invalid local paths reject. |
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

Use a copy of the evidence template for each tested revision/environment; its default `not_run` entries are not results. Bind logs, exact commands and effective token, clean/incremental build state, cache reuse, fixture recipe, expected/actual statuses, compiler/SDK/std provider, dependency lock, OS/device/filesystem identities and artifact SHA-256 to that run. Preserve `result.json`, `events.jsonl`, stage logs, extracted manifests and both available JUnit files. Keep suite counts and case-level omissions separate; repeat hardware rows per actual device/filesystem combination. Build logs may reveal local paths; sanitize public excerpts without losing error codes and neighboring context. Keep protected checkpoints private unless diagnosis specifically requires them.

Release requires all applicable mandatory unit/integration/isolated destructive gates and the claimed native platform matrix to pass, with no unresolved blocking safety finding. Both RC and Release publication wait for the owner’s returned Windows build/test evidence and review for the exact revision. CI artifacts remain unpublished development test sources. After owner acceptance, incomplete platform/hardware coverage permits at most an explicitly scoped RC; full Release requires the claimed matrix to pass. Unsupported cases must be explicitly rejected or receive only their independently authorized lower capability. Attestations establish provenance, not runtime correctness, signing or physical NAND erasure.

For the first public distribution, [v2.0.0](https://github.com/bestkakkoii/windows_agent_cleanup/releases/tag/v2.0.0)
was published as the formal Latest release on 2026-10-16 (Asia/Taipei), at source
commit `2b552ba92c9e81cb1ef4b8101619993677b5548a`, under the owner's explicit
[publication exception](publication.md). Its
`windows_agent_cleanup_v2.0.0_windows_x64.zip` contains the exact owner-supplied
executables and user-facing material, without build/source/test trees. The
application reports `2.0.0-dev.1`; the distribution tag does not change its bytes.
The owner reported GUI quick deletion and verified overwrite smoke success, and
the scoped CLI Quick pilot below. Broader CLI Agent acceptance and the full
hardware matrix remain pending. The supplied
binaries have no independently authenticated binding to a source commit.

[CI run 38785317728](https://github.com/bestkakkoii/windows_agent_cleanup/actions/runs/38785317728)
passed at documentation revision `64e8fffe3f7716211cc7a1d7c1fd55bf16f84e2f`
on hosted Windows Server 2025 with MSVC
19.51.36260.0 and SDK 10.0.26100.0: 11 safe and 4 isolated suites, plus source
packaging and archive verification. That is native engineering evidence for the
runner, not a Windows 11 device-matrix pass or proof that the owner binaries came
from CI. The three Agent CLI omissions and unknown-media overwrite omissions
above remain untested even though the suites passed.

### Owner-reported CLI Quick pilot

The owner supplied matching Markdown/JSON QA reports generated on
2026-10-15 UTC for the published v2.0.0 binaries, using Windows x64 build
`10.0.26200.0` and PowerShell `5.1.26100.9444`. The archive SHA-256 matches
the published asset in [project metadata](../spec/project.json); the report's
CLI SHA-256 is `4d105dc22de7b9d9a91769639086347bee2440f1881df6032f915f7673f4057c`.
Both submitted reports were reviewed. Referenced raw per-file records, receipts
and invocation files were not supplied for independent inspection. Private
project paths, request identifiers and raw reports are excluded from Git.

| Reported observation | Result |
|---|---|
| Authorized real batch | 2,890 generated regular files; 102,250,476 logical bytes; no directories selected |
| Native result and independent caller reconciliation | Exit 0; completed 2,890; failed/pending/skipped 0; zero selected names remaining; protected product hashes unchanged |
| Native invocation wall time | 9,790.7014 ms including preparation, freezing, deletion and reporting; execution-only timing unavailable |
| Disposable fixtures | Two files / 27 logical bytes and three directories removed; Unicode/nested/empty paths covered; unselected sentinel survived |
| Expected refusals | Unelevated exit 2, out-of-scope exit 2 and junction-ancestor exit 3 (`reparse_ancestor_denied`); protected sentinels survived |

File/directory splits and logical bytes come from the caller's inventory and
reconciliation; native result.v1 confirms combined target counts, not those
additional metrics. The reported positive volume-free-space delta is not
attributable to this job. The caller's initial PowerShell 5.1 nested-array
failure occurred before a real native invocation and was a QA harness issue.
No native defect was verified in these tested cases.

This pilot does not cover GUI, overwrite, hard links or allocation release,
active-lock recovery, cancellation/resource exhaustion, deterministic frozen
addition/replacement races, the complete filesystem/device matrix, or
reproducible source-to-binary binding. Its onboarding byte count describes the
immutable tagged instructions, not the later documentation on `main`. It does
not establish maximum throughput, immediate reclamation or physical sanitization.

Keep the binary release separate from CI's unpublished development test Source
ZIP. `scripts/package.py` and `scripts/verify_package.py` create/verify that source
format, not the owner binary ZIP or GitHub's automatic source archives. The
`--offline-dependencies` source-package option includes verified ImGui files; it
does not include built CMake/Ninja tools, so a first tool bootstrap can still need
network access. Archive integrity checks bind the recorded bytes and evidence;
they do not independently reproduce a native build or complete acceptance.
