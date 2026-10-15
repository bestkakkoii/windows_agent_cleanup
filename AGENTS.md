# Repository engineering contract

Use this file for development/review. For an actual cleanup request, route
through [README_AI.md](README_AI.md) and its Skill. Reading instructions,
installation or building never authorizes deletion of project material.

## Scope and source of truth

- Target Windows 11+ x64, MSVC `/std:c++latest`, native C++26 named modules and
  vendor `import std`, Release `/MT` without symbols/debug runtime. Earlier
  Windows 10/1809 contracts are superseded by the recorded amendments. Keep
  the CLI native and machine-only, without MCP or another orchestration runtime.
- Read only the relevant decisions in [requirements](spec/requirements.json)
  and owning `src/modules/*.ixx` contracts. For cross-module changes consult
  [design](docs/design.md). Protocol procedures belong in the Skill references;
  build/package details belong in [CONTRIBUTING.md](CONTRIBUTING.md).
- Keep one authority per rule. Put repeatable cleanup procedures in the Skill,
  durable engineering rules here, and release/evidence state in
  [project metadata](spec/project.json) and [publication policy](docs/publication.md).

## Implementation invariants

- GUI/CLI share core policy. Preserve fail-closed system protection, frozen
  membership, execution identity checks, no reparse traversal, deferred Quick
  failure recovery and independent downgrade/forced-process approval.
- Quick has no fixed target-count ceiling. Admit the complete batch against
  live memory/commit/disk/handle budgets; never truncate or mutate before full
  admission. A suite pass does not establish every case or hardware capability.
- Use Allman braces, explicit braces, snake_case own names, RAII and checked
  sizes; no goto. Every owned C++ unit uses `import std`; SDK/third-party
  includes stay at boundaries. Keep locked upstream bytes unchanged.
- Owned source/docs use UTF-8+BOM. Host exceptions: JSON/JSONL/YAML and
  `SKILL.md` frontmatter use UTF-8 without BOM; BAT uses ASCII CRLF. Preserve
  strict diagnostics and the checks enforcing these formats.
- Tool placement has no prescribed drive or parent. For authorized setup,
  choose a suitable location, reuse a valid root and derive resources from the
  actual entry file. Client discovery folders are separate from the program.

## Commands and evidence

- `build_release.bat`: configure/build Release, check manifests and run safe
  suites under an ordinary token. Add `-enable_isolated_destructive_tests` only
  in an already elevated console for disposable fixtures; no separate test BAT.
- `python scripts/validate.py --output-dir build/source_validation`: source
  encoding/module checks, without a native build or runtime claim. Python 3.11+
  is for source tooling, not a native application dependency.
- Run checks justified by the change and retain stage/native error context.
  Keep `build_logs/<run_id>` and raw evidence outside Git. Distinguish source,
  portable, hosted Windows, owner-binary, GUI and hardware validation; preserve
  case-level `not_run` outcomes. Never claim physical NAND sanitization.

## Collaboration, review and delivery

Use independent agents only for useful disjoint work, with one writer per file.
Give self-contained scoped handoffs in concise technical English, cite files,
choose the simplest sufficient format and propagate this policy to delegates.
Report changed behavior, checks, failures and pending evidence.

Track maintained source/config/docs/assets/tests and dependency locks only.
Exclude outputs, caches, downloaded dependencies, archives, raw logs and temporary
handoffs. Review the staged diff, use normal authorized commits/push, and never
rewrite shared history or force-push by assumption. Publication is separately
scoped by the owner and [policy](docs/publication.md); CI alone grants no release
permission, and an existing published asset must not be silently replaced.
