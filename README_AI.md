# Windows Agent Cleanup — AI entry

Read this file from its actual absolute path, for example
`C:/tools/windows_agent_cleanup/README_AI.md`. Resolve all links from that tool
directory, never from the project being cleaned. Any local AI with file access
and Windows process execution can follow this entry; Skill registration and MCP
are unnecessary. A remote chat without access to that Windows machine must
state the limitation instead of claiming it performed cleanup.

## Choose what to read

| Requested work | Next document |
|---|---|
| Clean project residues, select a cleanup plan, or inspect candidates | Read [project-cleanup/SKILL.md](skills/project-cleanup/SKILL.md). It contains the actual plan-selection and execution workflow, with conditional bundled references. |
| Build, fix, review or extend this tool | Read [AGENTS.md](AGENTS.md), or [CLAUDE.md](CLAUDE.md) for Claude Code, then the relevant [design](docs/design.md), [requirements](spec/requirements.json) and module contracts. |
| Install optional native Skill discovery | Follow the installation section below. |

For cleanup, the Skill asks once for the missing plan and absolute project
scope: **default automatic cleanup**, **custom directory/list cleanup**, or
**scan only**. Reuse choices already given in the conversation. Default cleanup
removes only positively proven disposable residues, research intermediates,
caches, obsolete experimental code, directories or confirmed redundant copies;
uncertain material stays in place. Reading this entry or requesting development
never grants deletion authority. The native CLI remains noninteractive.

The complete operational rules live in the Skill bundle, not duplicated here.
Read only the references selected by its current step. Do not load engineering,
build and exceptional-operation manuals for an ordinary quick cleanup.

## Locate the program

The distribution root is the directory containing this file. Use
`bin/secure_erase_cli.exe` for a binary bundle or
`build/windows_release/secure_erase_cli.exe` for a built source checkout. The GUI
is `secure_erase_gui.exe` beside it. Do not silently choose an unrelated EXE from
PATH. Windows 11+ x64 and an already elevated process are required for filesystem
commands; structured `capabilities` works without elevation. No Python, Node.js,
model SDK or MCP service is needed to run the native program.

## Engineering tasks

If the EXE is missing from a source checkout, building is separate engineering
work. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the engineering contract; use
`build_release.bat`, then `validate_windows.bat`. The one-click bootstrap selects
installed MSVC/SDK components and builds exact locked CMake/Ninja sources in an
ignored private cache. First build needs network and takes longer than cached
rebuilds. Preserve `build_logs/<run_id>` for diagnosis. Before destructive
fixture opt-in read [Windows test plan](docs/windows_test_plan.md).

RC or Release publication waits for the owner's returned build/test evidence
and acceptance. CI checks or an existing tag do not replace that gate. Follow
[CONTRIBUTING.md](CONTRIBUTING.md) for packaging and publication. Verify source
archives without extracting/executing their contents using
`python scripts/verify_package.py PATH --expected-commit COMMIT --expected-sha256 SHA256`,
with expectations obtained from the trusted repository/delivery record.

## Optional Skill registration

Directly reading the absolute README and linked Skill works without installing
anything. For native Codex or Claude Code discovery, install the complete bundle
with the selected client's directory convention:

```powershell
& 'C:/tools/windows_agent_cleanup/scripts/install_skill.ps1' `
  -Client codex -ToolRoot 'C:/tools/windows_agent_cleanup'
```

Use `-Client claude` for Claude Code. Defaults are the current user's
`.agents/skills/project-cleanup` and `.claude/skills/project-cleanup` respectively.
For project-local registration pass `-Destination` with that project's complete
`.agents/skills/project-cleanup` or `.claude/skills/project-cleanup` path. The final
component must be `project-cleanup`. Explicit installation changes only that
Skill directory; it does not edit global `AGENTS.md`, `CLAUDE.md`, hooks, registry
settings or client permissions, and it does not require symlinks.

The installer copies `SKILL.md`, its referenced resources and `agents/openai.yaml`
as one bundle. It binds a small location reference to this exact distribution,
records hashes for all installed files, refuses unrelated/locally modified
entries and safely upgrades an intact older owned thin entry. After moving the
tool distribution, use a fresh destination or remove the prior owned installation
explicitly before registering the new location; stale bindings fail closed.
Do not manually copy only `SKILL.md` into a client discovery directory.

Skill metadata is discoverable; its body loads when selected, and supporting
references load only when relevant. Codex UI metadata is optional for other
Agent Skills hosts. Client-specific features and permission grants are not
required. See [Skill design](docs/skill_design.md) for the content map and
upstream design references when developing this integration.
