# Windows Agent Cleanup — Agent entry

This file is the complete starting point for Codex, Claude Code, or another AI with local file access and Windows process execution. Tool use needs the native EXE; it does not need MCP, a Skill installation, Python, Node.js, or a model SDK. A remote chat with no access to this Windows machine must report that limitation instead of claiming cleanup.

## Choose the route

**Use the cleanup tool:** follow the next section. Reading this file does not authorize deletion.

**Extend, build, debug or review this project:** go directly to [development](#extend-or-build-this-project). Do not run a cleanup plan as development setup. An engineering request is not permission to remove working files.

Resolve the tool directory from the absolute location of this README, not the shell's current directory or the project being cleaned. Use `bin/secure_erase_cli.exe` in a binary bundle, or `build/windows_release/secure_erase_cli.exe` in a built source checkout. Do not silently substitute an unrelated EXE found on PATH. The GUI is `secure_erase_gui.exe` beside the CLI.

## Ask for the cleanup plan

Before entering cleanup, ask the user which of these plans to use and which absolute project directory is authorized. A concise combined question is sufficient:

> Which plan should I use: default automatic cleanup, custom directory/list cleanup, or scan only? Which project directory is in scope?

| Plan | Agent action |
|---|---|
| **Default automatic cleanup** | Discover and remove material positively identified as disposable within the chosen scope; retain uncertainty. |
| **Custom directory/list cleanup** | Use the user's explicit selection and preservation rules; do not broaden it. |
| **Scan only** | Inspect and report a candidate plan without deleting anything. |

After the user selects a plan and scope, perform it autonomously. Do not ask per file, reinterpret a completed batch as new permission, or repeatedly ask about the same unchanged authorized batch. Expanding scope or switching from scan to deletion needs a new choice. Default mode is quick logical deletion; overwrite/sanitization requires a separate explicit request.

## Default plan: decide what is disposable

Apply evidence to groups of files rather than asking the model to read hundreds of thousands of paths. Candidates can include directories, caches, research intermediates, generated or obsolete experimental code, and redundant copies. File type alone does not decide disposal.

Positive evidence can establish that an item is a finished job's temporary output, a superseded build product, a reproducible cache with no user data or retention need, a deliberately disposable research fixture, abandoned experimental code explicitly identified as such, or an unnecessary duplicate whose retained copy has been verified and is intended to remain. Check provenance, regeneration steps, current consumers and retention rules.

Names, age, missing references, Git ignored/untracked status and equal content are individually insufficient. Preserve original research inputs, useful conclusions, user assets, active or uncertain code, unconfirmed local changes, unique copies, active jobs, repository metadata and tool configuration. Downloadability alone does not remove retention requirements. Leave uncertain material in place and summarize the reason. Shared user/machine caches are outside a project authorization unless explicitly selected.

Coordinate compilers, watchers and relevant jobs before cleanup. Do not terminate unrelated applications or chase newly produced files. Parallel subagents may inspect disjoint subtrees read-only when beneficial. Give them the tool entry path, chosen plan, scope, preservation rules and bounded output instructions. One coordinator decides, deduplicates and submits the batch; subagents do not race to delete overlapping roots.

## Prepare one native batch

Use absolute literal paths. Prefer a directory-level record when its entire subtree is confirmed disposable: native enumeration keeps both the manifest and Agent context small. Use individual names for selective cleanup. A directory target selects its existing descendants according to the native preparation rules; a file target selects that name. Keep separate selected hardlink names even when they identify the same object. Do not expand shell wildcards or treat an authorization root as a request to delete everything beneath it.

Write the manifest outside every cleanup target and the authorized project root. Choose a report directory outside the root in both directions: neither may contain the other. The CLI creates a private store under an existing writable parent, or reuses an existing safe private store under its exclusive lock. Keep these files private; diagnostics can contain sensitive paths. Generate a large manifest programmatically with a streaming UTF-8 writer, not through a huge command line or model tool payload. Each JSONL record is one object:

```json
{"path":"C:\\work\\demo\\build"}
{"path":"C:\\work\\demo\\scratch_result.bin"}
```

The actual file must contain valid JSON string escapes and UTF-8 without BOM. Use a standard JSON serializer rather than manually escaping path text. Blank lines, unknown/duplicate fields, malformed UTF-8, shell wildcards, ADS and dot components are rejected. Use absolute local drive paths and one authorization root per request. These samples illustrate the format; they are not a cleanup selection.

A plain existing directory is not automatically a valid private store. Reuse is allowed only when its access and integrity checks pass; unique per-request report filenames avoid overwriting previous reports. For a selected default/custom quick batch, the native command is:

```powershell
& 'C:/tools/windows_agent_cleanup/bin/secure_erase_cli.exe' run `
  --mode quick --request-id cleanup_001 `
  --root 'C:/work/demo' `
  --manifest 'C:/cleanup_jobs/cleanup_001/targets.jsonl' `
  --report-dir 'C:/cleanup_jobs/cleanup_001/reports' `
  --authorize-irreversible
```

For scan only, invoke `scan` with the same mode, request ID, root, manifest and a valid report directory, omitting `--authorize-irreversible`; scan rejects that flag. Request IDs use 1–128 ASCII letters, digits, `_` or `-`. Quick scans are advisory. A quick run prepares and freezes its own batch; it does not reuse an earlier quick scan as execution authority or admit later additions.

`capabilities`, `--version` and `--help` are non-mutating structured queries. Query once when binding an unknown executable revision; do not repeat discovery per file or per unchanged invocation. These queries return `windows_agent_cleanup.capabilities.v1`; filesystem commands return [windows_agent_cleanup.result.v1](schemas/result.schema.json). The [manifest record schema](schemas/manifest_record.schema.json) defines each input record.

The native core rejects protected or changed targets and reparse traversal. Quick input is read incrementally, independent directory work uses bounded parallel preparation, and protected scratch files hold sorted target records, frozen indexes and paged outcomes. Only compact scheduling metadata and bounded worker records need remain resident. Admission uses current RAM, commit, CPU, handle and disk observations; there is no fixed target-count ceiling. A batch that cannot fit its compact metadata or reserve complete staging/report capacity is rejected before deletion. Per-target refusals remain failures within the complete batch; other eligible targets may still execute. The Agent's disposability reasoning is separate from these execution checks.

Omit resource overrides for automatic quick scheduling. `--workers 0` and `--memory-bytes 0` select automatic settings; explicit values restrict the requested budget and do not guarantee admission. `--io-bytes-per-second` and `--ssd-queue-depth` apply only to overwrite. Common retention options are `--log-retention-days` and `--checkpoint-retention-days`; checkpoint retention `0` keeps incomplete jobs until completion or explicit policy/removal.

## Interpret the result

The CLI emits exactly one final compact JSON object on stdout and returns a process exit code; there is no banner or streaming progress. Detailed run failures live in the private JSONL report, with an intent record flushed before mutation. Run reports omit successful target lists; scan reports contain the admitted discovery records and their eligibility. Neither streams per-target records to stdout. Diagnostics may appear on stderr; they are not the completion contract. Never infer success from an empty terminal, a removed path, or an exit code alone when completion output is missing.

Exit codes: `0` completed/scanned/capabilities; `2` arguments/admission/privilege rejection; `3` partial/core/audit failure, including `scan_partial`; `4` output or report-write failure; `5` interruption. `scan_partial` means preparation found blocked/failed targets, not that scan deleted anything. Match returned identifiers to the submitted request when available; argument failures can precede identifier binding.

Operation result fields are `request_id`, `job_id`, `plan_fingerprint`, `mode`, `status`, `counts` (`targets`, `completed`, `failed`, `pending`), `error_code`, `native_code`, `report_file`, `resumable` and `advisory`. Scan counters describe discovery rather than completed deletions; do not assume all scan targets are completed or pending. Check status, exit code and counts together, not merely an empty `error_code`. Success, partial failure, rejection, interruption and unknown completion are distinct outcomes. Summarize totals and material failures; read a filtered portion of the report when needed, without loading every successful path into context.

Use the host's existing process/session controls to wait for the same long-running invocation. Do not submit a second deletion because a tool call yielded or timed out. Ctrl+C requests bounded cooperative cancellation and a final summary when possible; already completed deletions remain completed. Crash, forced termination, lost output or missing final evidence means unknown/partial completion. Reconcile that job's evidence before proposing a retry. Quick scratch files are ephemeral and disappear when their handles close; they are not an authenticated cross-process restart plan. Quick has no cross-process `resume`, and intent/report evidence alone cannot reconstruct safe restart membership. Do not automatically rescan or resubmit the manifest after a quick crash, or delete replacements/new files.

First-pass failures are collected for the final recovery phase. Native checks are preserved during retries. Filesystem commands currently require an already elevated token; `capabilities` works without elevation. The CLI uses an as-invoker manifest and never requests UAC elevation. An administrator account does not prove that its child process is elevated. Report `elevation_required` or host-policy denial without changing client policy or attempting a bypass. Default batch execution never forces a process to terminate.

Quick deletion does not read/overwrite file contents, securely erase history, or guarantee immediate capacity release. Other handles, hardlinks and storage layers can retain allocation. Device free-space differences are observations affected by unrelated activity, not an attributable byte count. Do not claim maximum hardware speed without measurements.

## Overwrite and explicit process actions

These operations are separate from the default quick plan. Overwrite scans persist an authenticated pending plan and return `job_id` (32 lowercase hexadecimal characters), `plan_fingerprint` (64 lowercase hexadecimal characters) and `resumable`. Resume uses the same authorization root and private report store:

```powershell
& $cli resume --request-id cleanup_resume_001 --root $root `
  --report-dir $report_dir --job-id $job_id `
  --plan-fingerprint $plan_fingerprint --authorize-irreversible
```

Here `$cli`, `$root`, `$report_dir`, `$job_id` and `$plan_fingerprint` are literal values from the chosen installation/request and authenticated scan result; do not invent them. Resume is overwrite-only and takes no `--mode`. It never re-enumerates target membership. An optional `--manifest` on resume contains only exact individual namespace records with an independently authorized `allow_downgrade` value, `delete_only` or `overwrite_best_effort`. Grants must match the observed capability and cannot authorize a whole directory's descendants. Quick manifests cannot contain downgrade grants. A changed capability requires new independent consent; ordinary batch authorization does not supply it.

Only use explicit lock/process commands for a selected target and separately authorized process action. Obtain a current `target_key` from the exact target's quick scan report; use a fresh lock report's exact `pid`, `created` and `image` tuple:

```powershell
& $cli locks --request-id lock_check_001 --root $root `
  --report-dir $report_dir --path $path --target-key $target_key

& $cli release --request-id release_001 --root $root `
  --report-dir $report_dir --path $path --target-key $target_key `
  --pid $selected_pid --created $created --image $image --authorize-close
```

These commands also return one result object; `mode` is `process`, and detailed lock records are in `report_file`. `target_key` is 64 lowercase hexadecimal characters bound to the exact selected namespace, not a directory's hidden child. Preserve `created` as an exact unsigned 64-bit integer/decimal string; do not round it through JavaScript `Number`. Do not use PowerShell's read-only `$PID` variable for the selected process; use a distinct variable such as `$selected_pid` when composing the command.

`--authorize-force` is an additional release-only flag. Add it only after independent fresh authorization for that exact process; it is never inferred from a cleanup plan, `--authorize-irreversible`, `--authorize-close`, an old PID, or a previous failed attempt. Changed or ineligible process/target identities are rejected. Do not add flags preemptively or automatically escalate a failed normal close.

## Optional Skills

The direct absolute README route is sufficient. A single portable skill source is at `skills/project-cleanup/SKILL.md`. Its installer renders the real README location into a thin discovery entry, without copying cleanup rules or requiring symlinks:

```powershell
& 'C:/tools/windows_agent_cleanup/scripts/install_skill.ps1' `
  -Client codex -ToolRoot 'C:/tools/windows_agent_cleanup'
```

Use `-Client claude` for Claude Code. Defaults are the current user's `.agents/skills/project-cleanup` and `.claude/skills/project-cleanup`; `-Destination` selects the complete skill directory, whose final component must be `project-cleanup`. Install only the chosen client entry. The installer refuses unrelated or locally modified existing entries and never edits global `AGENTS.md`, `CLAUDE.md`, registry settings or hooks.

Skill discovery does not grant cleanup authorization or operating-system rights. Shared machines and Git worktrees still require the chosen scope and coordinated execution. The raw portable skill in this source tree is not automatically registered in arbitrary projects.

## Extend or build this project

Read [AGENTS.md](AGENTS.md), [docs/design.md](docs/design.md), and relevant requirements in [spec/requirements.json](spec/requirements.json). Follow owning module interfaces under `src/modules`; core rules belong in the shared implementation, not a CLI/GUI-only check. [CONTRIBUTING.md](CONTRIBUTING.md) covers change and evidence expectations.

Target Windows 11+ x64 with installed Visual Studio x64 C++ tools, native vendor standard-library modules and a complete Windows SDK 10.0.22000.0 or later. An existing CMake 3.15+ is needed only to bootstrap; the VS-bundled copy is accepted. Installed Ninja is optional because `nmake` can bootstrap it. The one-click script builds the exact hash-locked upstream CMake 4.5.20261015 and Ninja 1.14.0.git sources into ignored `build/tools`, then uses those tools for the product. First build requires network and substantially more time; a matching binary-hash-verified cache supports offline rebuilds. No global tool installation is performed.

Use actual C++ named modules and vendor `import std`, Release `/MT`, strict diagnostics and no debug symbols. Toolchain/dependency locks preserve exact revisions; a build must not silently float them. The script records installed/compiler/SDK and bootstrapped tool identities, and restores hash-locked upstream ImGui files into ignored `build/dependencies`. Do not elevate the build merely because the GUI uses an administrator manifest.

From a Windows source checkout, run:

```powershell
.\build_release.bat
.\validate_windows.bat
```

Build outputs are `build/windows_release/secure_erase_cli.exe` and `secure_erase_gui.exe`; run logs are `build_logs/<run_id>`. Optional `-parallel_jobs N` controls build parallelism. `validate_windows.bat -enable_isolated_destructive_tests` enables the isolated destructive suites explicitly. These commands do not authorize deleting user data. Read [docs/windows_test_plan.md](docs/windows_test_plan.md) before opting into isolated destructive fixtures. Preserve logs outside the tracked source; source/build/script checks and portable tests cannot establish native Windows or hardware results. Unmet platform acceptance gates keep the delivery at RC.

For development delegation, assign disjoint files, propagate the engineering policy and return concise technical English with changed contracts, actual checks, failures and pending evidence. Do not assume a child agent inherited the original conversation. Keep generated binaries, caches, downloaded dependencies, one-off reports and temporary handoffs out of Git. Commit/push only within existing repository authorization, with reviewable changes and no assumed permission to rewrite shared history.

Source RC archives contain `package_manifest.json` and per-run evidence under
`evidence/`. For archive verification with Python 3.11+, use
`python scripts/verify_package.py C:/downloads/source.zip --expected-commit COMMIT --expected-sha256 SHA256`.
Get expected values from the trusted release/repository revision. Verification
checks bytes and recorded evidence binding without extracting or executing
members; it does not reproduce the runtime tests. Read [CONTRIBUTING.md](CONTRIBUTING.md#source-rc-publication)
for packaging/publication and [docs/windows_test_plan.md](docs/windows_test_plan.md)
for remaining platform and hardware acceptance.
