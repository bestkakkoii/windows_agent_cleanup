# Windows Agent Cleanup — AI entry

Use this file's actual absolute parent as `<tool_root>`; resolve bundled links
there, not from the project being cleaned. Operating requires local Windows 11+
x64 filesystem/process access. Direct reading needs no MCP, Skill registration,
compiler, Python, Node.js, SDK or global PATH change.

## Route the task

- **Operate:** read the [Project cleanup Skill](skills/project-cleanup/SKILL.md),
  the sole quick-operation kernel; load only its conditional references.
- **Develop/build/review:** read [AGENTS.md](AGENTS.md) and
  [CONTRIBUTING.md](CONTRIBUTING.md#build-from-source). Claude's
  [CLAUDE.md](CLAUDE.md) imports the shared engineering contract.
- **Optional Skill discovery:** use the
  [registration procedure](docs/skill_design.md#optional-registration).

## Obtain or bind the program

Reuse a verified installation; otherwise follow the official runtime adoption
steps in [README.md](README.md#start-with-your-agent). Choose a suitable portable
directory without a prescribed drive. Ordinary setup downloads the Release's
Windows x64 runtime ZIP and verifies its published checksum **before extraction**;
GitHub-generated source archives and source compilation are for explicit
engineering work only. Inspect provenance/dirty state before replacing an
existing directory; prefer a separate portable location over modifying a checkout.
Bind `<tool_root>/bin/secure_erase_cli.exe`, or an already-built checkout's
`build/windows_release/secure_erase_cli.exe`. An absent EXE routes to the runtime
Release; it never triggers an automatic build during cleanup.

## Engineering tasks

Follow [source build instructions](CONTRIBUTING.md#build-from-source) only for
requested engineering work. Installation, reading and development grant no
deletion authority. Published bundle instructions are fixed with their artifact;
source documentation changes do not replace existing Release bytes.
