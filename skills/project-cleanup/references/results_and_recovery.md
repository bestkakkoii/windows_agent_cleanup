# Results and recovery

## Complete a running job

Wait through the host's existing process/session API for the same invocation.
A yielded tool call is not a failed batch and is never a reason to issue a
second deletion. Ctrl+C requests bounded cooperative cancellation and a final
summary when possible; completed deletions remain completed.

The CLI writes exactly one final compact JSON object to stdout, with no banner
or per-target progress stream. Detailed JSONL evidence lives in its protected
report store; intent is flushed before mutation. Stderr is diagnostic, not the
completion contract. Match `request_id` when present, then interpret status,
counts and exit code together. Argument failures can precede identifier binding.

| Exit | Meaning |
|---|---|
| `0` | Completed, scanned or capability query; check the returned status. |
| `2` | Arguments, admission or privilege rejected. |
| `3` | Partial/core/audit failure, including `scan_partial`. |
| `4` | Output or report-write failure. |
| `5` | Interrupted. |

Operation results use `windows_agent_cleanup.result.v1`, with `request_id`,
`job_id`, `plan_fingerprint`, `mode`, `status`, `counts` (`targets`, `completed`,
`failed`, `pending`), `error_code`, `native_code`, `report_file`, `resumable` and
`advisory`. Scan counters describe discovery, not completed deletions;
`scan_partial` never means deletion occurred. Read the full canonical schema at
`<tool_root>/schemas/result.schema.json` only for protocol integration or a
schema mismatch. Do not infer success from an empty error string, a removed
path, an exit code alone or missing terminal output.

Summarize totals, preserved uncertainty and material failures. Run reports omit
successful path lists; scan reports include admitted discovery and eligibility.
Filter detailed failures as needed instead of reading all paths into context.

## Partial, missing or unknown completion

Crash, forced termination, lost stdout or missing final evidence leaves
unknown/partial completion. Reconcile the original request's intent/result
reports before any next deletion. Quick scratch files vanish when handles
close: quick mode has no cross-process `resume`, and its reports do not rebuild
safe frozen membership. Do not automatically rescan or replay the old manifest;
that could select new files or replacements. Present unresolved state and obtain
any new scope/plan choice needed for a fresh batch.

First-pass failures are collected for a final native recovery phase; normal
batch operation never forcibly terminates a process. For explicit lock/process
actions read `exceptional_operations.md`. Report `elevation_required` or
host-policy denial without changing client policy or attempting a bypass.

Quick deletion does not overwrite contents or sanitize historical storage.
Other handles, hardlinks or storage layers can delay allocation release. Device
free-space differences are observations affected by unrelated activity, not
attributable reclaimed-byte counts. Report measured performance only; do not
claim theoretical hardware maximum or immediate space availability.
