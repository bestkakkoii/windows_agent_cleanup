---
name: project-cleanup
description: Inspect and clean disposable Windows project residues, build products, research intermediates, caches, obsolete experimental code and confirmed redundant copies using Windows Agent Cleanup. Use for a requested default cleanup, explicit directory/list cleanup, or scan-only plan; keep uncertain material. Do not run cleanup for a request to build, debug or develop the cleanup tool.
---

# Project cleanup

Use the native Windows Agent Cleanup CLI for one coordinated bulk job. Keep
reasoning about disposability in the Agent and enforce filesystem safety in the
native engine. Reading this Skill does not authorize deleting anything.

## Select the plan and scope

1. Reuse the user's existing explicit plan and absolute project scope. If either
   is missing, ask once: “Which plan: default automatic cleanup, custom
   directory/list cleanup, or scan only? Which absolute project directory?”
2. Apply the selected plan:
   - **Default automatic cleanup:** discover and remove only positively proven
     disposable project material. Preserve uncertain items without blocking the
     rest of the authorized batch.
   - **Custom directory/list cleanup:** use the user's literal selection and
     preservation rules; do not widen it.
   - **Scan only:** inspect and report candidates; never invoke deletion.
3. Read [disposal evidence](references/disposal_evidence.md) before default-plan
   discovery or whenever a candidate's provenance is unclear. Names, age,
   untracked/ignored status, missing references and equal bytes are insufficient
   by themselves. Do not infer that all project contents are disposable.
4. Treat code/build/review requests as engineering work. Read the tool's
   `AGENTS.md` or `CLAUDE.md` through the location binding below; do not clean as
   setup. Expanding scope or changing scan-only into deletion needs a new choice.

Once a cleanup plan and scope are authorized, carry it through without per-file
confirmation. Quick logical deletion is the default. Overwrite and forced
process termination require their own explicit authorization.

## Bind the tool and discover in groups

Read [tool location](references/tool_location.md) to bind this Skill to its
actual distribution. Resolve links relative to this Skill, not the target
project or current working directory. Require access to the same Windows
machine and an already elevated process for filesystem commands. Do not use an
unrelated executable from PATH or request UAC through the CLI.

Query `capabilities` once for an unknown executable revision and reuse that
binding for unchanged consecutive calls. Do not probe capabilities, storage or
locks per file. Use native directory enumeration and streamed manifests rather
than passing all filenames through the model or spawning a process per file.

Inspect provenance, regeneration steps, current consumers and retention rules.
Coordinate active builds/watchers before selecting their outputs; do not chase
newly generated files. Delegate read-only inspection of disjoint subtrees when
useful. Give each child the selected plan, absolute scope, preservation rules,
this Skill's path, and a bounded evidence summary destination. Keep one
coordinator responsible for decisions, deduplication and execution; children
must not issue overlapping deletions.

## Submit and complete one batch

1. Read [bulk CLI](references/bulk_cli.md) before the first batch or when composing
   a new command. Prefer one directory record only when its complete subtree is
   disposable. Otherwise select individual literal names. Preserve separate
   selected hardlink names. Never use wildcard expansion or select the scope
   root merely because it authorizes descendants.
2. Stream a UTF-8 JSONL manifest using a standard serializer outside the
   authorized root and all selected targets. Place reports in a private store
   outside that root in both directions. Submit one native invocation per
   coordinated root/batch, not one per file. Let automatic resource admission
   and per-device scheduling use current hardware and resource availability;
   there is no fixed maximum target count.
3. For deletion use `run --mode quick` with the irreversible authorization flag
   only after the selected plan authorizes it. For scan use `scan --mode quick`
   without that flag. Do not force a redundant scan before every quick run:
   the run itself freezes and validates its full membership before mutation.
4. Read [results and recovery](references/results_and_recovery.md) to interpret
   the final result or handle yielding, partial completion, locks or failure.
   Wait on the same process/session if the host yields. Never submit a second
   deletion merely because the first call timed out.
5. Match the one JSON result to the request, check status, counts and exit code,
   then report totals, retained uncertainty, material failures and report path.
   Missing final evidence means unknown/partial completion, not success. Read
   only filtered failure evidence; keep huge path lists out of context.

Do not automatically replay a crashed quick batch or rescan it into a new run:
new names/replacements are outside its frozen membership. Do not claim physical
sanitization, instant free-space release or theoretical maximum throughput from
a successful quick result.

## Conditional operations

Read [overwrite and process actions](references/exceptional_operations.md) only
for explicitly requested overwrite, authenticated overwrite recovery, lock
inspection or separately authorized process release. Default quick cleanup
already defers native failure recovery until after its fast first pass. Do not
preemptively inspect locks, weaken native identity checks or escalate a normal
close into forced termination.
