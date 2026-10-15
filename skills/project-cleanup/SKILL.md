---
name: project-cleanup
description: Inspect and clean disposable Windows project residues, build products, research intermediates, caches, obsolete experimental code and confirmed redundant copies using Windows Agent Cleanup. Use for a requested default cleanup, explicit directory/list cleanup, or scan-only plan; keep uncertain material. Do not run cleanup for a request to build, debug or develop the cleanup tool.
---

# Project cleanup

1. Require local Windows 11+ x64 filesystem/process access; bind this exact distribution.
2. Reuse established plan, absolute project scope and deletion authority; ask only for missing choices.
3. Offer default automatic cleanup, custom literal selection or scan only; installation/development grants no deletion authority.
4. For default discovery/uncertain provenance read [disposal evidence](references/disposal_evidence.md); preserve uncertainty. Honor explicit custom selections; scan never mutates.
5. Bind the root from the absolute README or intact installed binding; read [tool location](references/tool_location.md) only if unbound. Never substitute PATH's EXE or auto-build missing binaries.
6. Use `<tool_root>/bin/secure_erase_cli.exe`, or the documented already-built checkout location. Query `capabilities` once per unknown EXE hash; opt into `--contract-version 2` only when the intact runtime manifest advertises it for that hash. Legacy/unadvertised bundles retain v1; cache static protocol data, never mutable host readiness.
7. Require an already elevated supported execution host. For advertised v2 use `capabilities --contract-version 2`: `filesystem_commands_ready:null` is unknown. Missing privilege needs the real OS-consent handoff; do not self-elevate, collect credentials or change policy. Refresh readiness in the actual new host; readiness does not admit targets.
8. Resolve one absolute literal authorization root; it does not select all descendants. Select a directory only if its complete existing subtree is disposable.
9. Stream one `{"path":absolute_literal_path}` object per selected target as BOM-free UTF-8 JSONL, using a standard serializer; no wildcards, ADS, dot components or invented fields.
10. Keep the manifest outside the root/targets and reports disjoint from the root in both directions. Use an existing writable parent; let the CLI protect its report store.
11. Bind `$cli`, `$root`, `$manifest`, `$reports` and a fresh `$new_id` (1–128 ASCII letters/digits/`_`/`-`) to the authorized job, then invoke once:

```powershell
$contract_args = @() # Use @('--contract-version', '2') only after advertised support.
& $cli run --mode quick --request-id $new_id --root $root `
  --manifest $manifest --report-dir $reports --authorize-irreversible @contract_args
```

12. For scan only use `scan` and omit `--authorize-irreversible`. Scan is advisory; it does not authorize/bind a later run. Do not add a redundant mandatory scan.
13. Omit scheduling overrides unless needed; submit one coordinated batch, never a process per file. Native admission has no fixed target-count ceiling.
14. Wait on the same process/session; timeout/yield never authorizes a second run. Match request ID, status, counts and exit code in the one final JSON result.
15. Exit meanings: `0` completed/scanned; `2` admission/input/privilege refusal; `3` partial/failure; `4` report/output failure; `5` interrupted. Empty `error_code` alone is not success.
16. For failures, lost/partial output or schema integration read [results and reconciliation](references/results_and_recovery.md); inspect relevant external `report_file` rows. Unknown completion means preserve intent/results and reconcile, never replay/rescan as authority.
17. Quick scratch is ephemeral: no automatic retry or cross-process resume. Logical removal proves neither physical sanitization nor immediately reusable capacity.
18. Read [bulk CLI details](references/bulk_cli.md) only for extended grammar, resource/retention overrides or maintained PS5.1/7 caller plumbing. Keep detailed path lists external and label byte totals by their actual semantics.
19. Read [exceptional operations](references/exceptional_operations.md) only for separately authorized overwrite, downgrade, overwrite recovery or process actions; normal Quick defers recovery until after its fast first pass.
20. Coordinate disjoint read-only discovery when useful; one coordinator owns deduplication and mutation. Give delegates scope/authority/exclusions and this Skill; use concise technical English and propagate that policy.
21. Report completed/failed/pending totals, retained uncertainty, material failures and evidence location; do not claim unmeasured maximum speed or token savings.
