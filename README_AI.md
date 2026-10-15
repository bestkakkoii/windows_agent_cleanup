# Windows Agent Cleanup — AI entry

Start from this file's actual absolute path. Its containing directory is
`<tool_root>`; resolve bundled links there, not from the project being cleaned.
Any local AI with access to that Windows machine can use this manual entry.
It does not require MCP, Skill registration, Python, Node.js or a model SDK.
`README_AI.md` is not a host-specific auto-loaded instruction filename.

## Select the requested route

| Task | Read next |
|---|---|
| Choose a cleanup plan, inspect residues or perform authorized cleanup | [Project cleanup Skill](skills/project-cleanup/SKILL.md), then only the references selected by its current step |
| Develop, build, fix, review or extend this tool | [AGENTS.md](AGENTS.md); Claude Code's [CLAUDE.md](CLAUDE.md) imports the same rules. Load [CONTRIBUTING.md](CONTRIBUTING.md), relevant requirements and module contracts as the task needs |
| Register optional client Skill discovery | [Registration procedure](docs/skill_design.md#optional-registration) and the actual [tool binding](skills/project-cleanup/references/tool_location.md) |
| Check release identity, evidence or publication | [Project metadata](spec/project.json) and [publication policy](docs/publication.md) |

For cleanup, the Skill asks once for missing **plan** and **absolute project
scope**, reusing choices already supplied. It offers default automatic cleanup,
custom directory/list cleanup or scan only. Default cleanup removes only
positively proven disposable material; uncertain material stays. Reading an
entry, registering a Skill or requesting engineering work grants no deletion
authority. The CLI remains noninteractive; the Agent owns plan selection and
classification. An Agent without machine access must report that limitation.

## Locate or place the tool

No drive, directory name or parent such as `D:/Tools` or `C:/tools` is mandatory.
For authorized setup, choose a suitable writable location from existing layout,
available storage, permissions and user/project scope. Reuse a valid existing
installation; choose the path without asking merely to replace an example.
Keep the tool and its diagnostic state outside material selected for cleanup.

After placement, the actual README location is authoritative. Preserve the
complete layout and use `<tool_root>/bin/secure_erase_cli.exe` in a binary bundle
or `<tool_root>/build/windows_release/secure_erase_cli.exe` in a built checkout.
The GUI is beside it. Bind an installed Skill through its
[location reference](skills/project-cleanup/references/tool_location.md), not an
example path or unrelated PATH executable. Moving an intact relative-bound
bundle and rebinding an installed absolute-bound copy are different operations;
follow that reference rather than bypassing ownership checks.

Windows 11+ x64 is required. Filesystem commands need an already elevated
process. Structured `capabilities`, `--version` and `--help` queries work without
elevation; reuse a capability binding while the executable identity is unchanged.

## Source checkout versus binary bundle

The binary distribution ships native GUI/CLI programs, runtime routing files,
the complete Skill, schemas and licenses. It has no source installer, build
scripts or engineering tree. Its routing stubs link to source documents for
engineering/registration work; direct cleanup needs none of that tooling.

In a source checkout, `build_release.bat` builds Release, checks manifests and
runs safe tests in one command. For isolated disposable tests, use its explicit
`-enable_isolated_destructive_tests` switch from an already elevated console.
Follow [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, diagnostics and
source-package verification; building is separate from cleanup and publishing.

Published distribution v2.0.0 preserves the owner EXEs, which still report
`2.0.0-dev.1`. CLI Agent acceptance and the full hardware matrix remain pending.
The [publication record](spec/project.json) separates distribution identity,
source reference and binary provenance. Documentation on `main` may be newer
than the tagged bundle; a source documentation update does not replace it.
