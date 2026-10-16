# Results and reconciliation

[Quick kernel](../SKILL.md) owns routine invocation/completion checks. Load this
reference for detailed fields, filtered failure evidence or uncertain outcomes.

- [Result details](#result-details)
- [Opt-in v2 details](#opt-in-v2-details)
- [Partial, missing or unknown completion](#partial-missing-or-unknown-completion)

## Result details

The final stdout object is compact; stderr is diagnostic. Reports are protected
JSONL, with intent flushed before mutation. Argument errors may precede request
binding; privilege errors may precede report creation. A `windows_agent_cleanup.result.v1`
object contains `request_id`, `job_id`, `plan_fingerprint`, `mode`, `status`,
`counts` (`targets`, `completed`, `failed`, `pending`), `error_code`,
`native_code`, `report_file`, `resumable`, `advisory`. Read
`<tool_root>/schemas/result.schema.json` only for integration/schema mismatch.
Preserve original JSON integer precision. A scan is advisory; its discovered
counts and `scan_partial` status never indicate removals or bind a later run.

Run reports omit successful path lists. Filter `windows_agent_cleanup.failure.v1`
rows by the relevant target/error rather than loading every path. Rows include
namespace/identity, precise error/native code and `deleted`; `deleted:true`
can accompany a later audit/checkpoint failure. That is neither a completed job
nor evidence that the old target is available to retry. An empty top-level
stopping error can coexist with per-target failures.

Both scan modes emit `windows_agent_cleanup.scan_target.v1`. Quick rows contain
`path`, `target_key`, `directory`, `error_code`, `native_code`; overwrite rows
contain `path`, `identity`, `capability`, `downgrade_required`, `link_count`.
Names may be extended canonical Windows paths/expanded short names. Preserve
the exact name/key pair; do not match by basename, guessed case folding or file
ID alone. V1 has no file/directory split, logical-byte total or phase timers;
do not invent those from combined counters or process wall time.

## Opt-in v2 details

Only a bound executable advertising support accepts v2; see conditional
[version negotiation](bulk_cli.md#version-negotiation). Unadvertised/v1-only
executables retain the v1 route. A v2 operation uses `windows_agent_cleanup.result.v2`; its schema is
`schemas/result.v2.schema.json`. Default v1 shape and exits remain unchanged.
V2 adds typed readiness, `next_action`/`retry_safe` and these measurements:

| Field | Interpretation |
|---|---|
| `statistics.selected/remove_attempted/completed` | Unique frozen namespace entries split into files/directories/unclassified; native remove retries do not multiply attempts or recovery successes. |
| `statistics.logical_bytes` | Known default-stream lengths at freeze, plus selected/attempted/completed unknown-size counts. Directories contribute zero; these are neither ADS totals nor allocation/reclaimed bytes. Preserve uint64 integer precision. |
| `statistics.final_failures` | Bounded final category counts after recovery, distinct from the top-level stopping error; recovered attempts are not final failures. |
| `phases_ms.manifest_preparation_ms` / `freeze_ms` | Monotonic wall times for streamed manifest/preparation and finalization/freeze. |
| `phases_ms.first_pass_ms` / `recovery_ms` | Core-owned phase wall times, not summed worker durations. Unentered/unmeasured phases are null. |
| `phases_ms.reporting_before_result_ms` / `total_to_result_ms` | Reporting before final construction, and wmain entry to final construction; both exclude final report/stdout delivery and process teardown. Neither is pure deletion/process wall time. |
| `space_observations` | At most 128 eligible frozen volumes, with truncation/error/unknown state; before/after/delta available-to-caller bytes are observations, not attributable reclamation. |

Unsupported overwrite statistics/core-phase/space measurements are null rather
than invented zeros. `next_action.action` is one of `none`, `use_supported_host`,
`request_os_consent`, `correct_input`, `inspect_report`, `wait_same_invocation`,
`reconcile_unknown`, with a bounded reason. `retry_safe:true` requires positive
pre-operation refusal evidence; it never grants new cleanup authority.

If capabilities v2 advertises `status`, the separate read-only reconciliation
command is `status --request-id <original_id> --report-dir <original_store> --contract-version 2`. It accepts no root/manifest/irreversible grant and never
creates a store, launches a worker or resumes Quick. Its
`windows_agent_cleanup.request_status.v2` result reports `terminal_result`,
`intent_only`, `no_record_observed`, `ambiguous`, `unavailable` or
`inspection_incomplete`, bounded report references and an optional unmodified
original result. Inspect `schemas/request_status.v2.schema.json` only for
integration. All lookup results have `retry_safe:false`; no record is not
proof of no execution, and multiple matches do not select the newest.

## Partial, missing or unknown completion

| Evidence available | Read-only caller behavior |
|---|---|
| Same invocation still owned by the host | Wait on that process/session; a yielded call is not a new execution opportunity. |
| Matching final JSON and final report | Interpret exit/status/counts together and retain request/job/fingerprint binding; read relevant failure rows. |
| Lost stdout; known private report directory/request ID | Inspect only that directory for exact validated request-ID prefix plus `.report.jsonl` suffix. Random report suffixes mean multiple matches are ambiguous; never choose newest. Read original intent/final rows without selecting fresh targets. |
| Intent/partial report without matching final result | Preserve original input, report and process evidence; completion remains unknown/partial. |
| No report or inaccessible report | Absence does not prove no mutation. Only positive evidence of a pre-operation refusal establishes that refusal. |

Bound manual inspection (for example at most 256 directory entries and 8 MiB
of report bytes). Report inspection as incomplete if either limit prevents
certainty; never infer uniqueness from a truncated listing. Validate request
IDs as 1–128 ASCII letters/digits/`_`/`-`, inspect literal direct children only,
reject reparse paths and keep ACLs unchanged. A single matching file is only
candidate evidence: validate its intent/result binding and terminal row.
Do not open the native state store through a mutating/creating API just to
inspect history; an active writer's refusal is unavailable/unknown, not a
reason to release its lock. Use native `status` only when the exact executable
advertises request lookup; otherwise use this bounded manual inspection route.
Never infer command support from a distribution label or newer source docs.

A crash can lose phase/byte observations; surviving names cannot reconstruct
unrecorded metrics. Quick scratch vanishes when handles close; reports cannot
rebuild safe frozen membership. No quick cross-process resume, automatic
replay, rescan-as-authority, delete-from-report or exactly-once guarantee exists.
Resolve uncertainty before any fresh owner-authorized selection. Ctrl+C is
cooperative; completed removals remain completed.

Normal Quick collects first-pass failures for final native recovery without
forced termination. Explicit lock/process/overwrite recovery requires
[exceptional operations](exceptional_operations.md). Report privilege/policy
refusal with an actionable real OS-consent handoff; never change client policy,
self-elevate or collect credentials. Observed free-space deltas are affected by
other activity/handles/hardlinks/storage layers and do not attribute reclaimed
bytes or establish physical sanitization.
