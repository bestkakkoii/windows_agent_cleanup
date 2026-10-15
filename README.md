<p align="center"><img src="assets/logo.svg" alt="Windows Agent Cleanup" width="88"></p>

<h1 align="center">Windows Agent Cleanup</h1>

<p align="center">Native Windows cleanup for agents. One batch, one compact result.</p>

[![Build and checks](https://github.com/bestkakkoii/windows_agent_cleanup/actions/workflows/ci.yml/badge.svg)](https://github.com/bestkakkoii/windows_agent_cleanup/actions/workflows/ci.yml)
[![GitHub stars](https://img.shields.io/github/stars/bestkakkoii/windows_agent_cleanup?style=flat&color=22d3ee)](https://github.com/bestkakkoii/windows_agent_cleanup/stargazers)
[![MIT license](https://img.shields.io/github/license/bestkakkoii/windows_agent_cleanup?color=34d399)](LICENSE)

<p align="center"><img src="assets/hero.svg" alt="Windows Agent Cleanup: a shared native core for agent CLI and desktop GUI"></p>

[繁體中文](README_zh_tw.md) · [Agent entry](README_AI.md) · [Releases](https://github.com/bestkakkoii/windows_agent_cleanup/releases) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

Windows Agent Cleanup removes large project cleanup batches through a native C++ core shared by a machine-oriented CLI and a compact desktop GUI. Quick deletion removes selected names without reading or overwriting file contents. The separate overwrite workflow provides explicit, evidence-based sanitization results.

**[Download v2.0.0 for Windows x64](https://github.com/bestkakkoii/windows_agent_cleanup/releases/tag/v2.0.0).** This published Latest Release contains the owner-supplied GUI/CLI binaries, runtime instructions, the complete Skill, schemas and licenses; application source and build/test files remain in Git. Verify the accompanying SHA-256 file before use. **The unchanged EXEs still report application version `2.0.0-dev.1`; the GUI retains its original development-build footer.** CLI Agent acceptance and the full hardware matrix remain pending, as scoped in the [publication policy](docs/publication.md). This project does not claim a hardware-independent maximum speed or physical NAND sanitization.

## Start with your agent

Extract the complete bundle to a suitable directory on the target Windows machine. The Agent may choose that directory according to available space, permissions and project or user scope; reuse an existing valid installation. No drive letter or parent directory is required. Then tell Codex, Claude Code, or another local agent to read the actual absolute path:

```text
Read <absolute path to the extracted tool>/README_AI.md
```

The path above is a placeholder, not an installation requirement. The agent asks which cleanup plan to use and which project is in scope. After you choose, it identifies disposable material, submits a bulk manifest, and interprets a compact result. Reading the manual alone does not authorize deletion.

The direct README route needs no MCP server, Skill installation, Python, Node.js, or model SDK. Optional [Agent Skills](skills/project-cleanup/SKILL.md) bundle the cleanup workflow, predefined plans and conditional protocol references. `README_AI.md` routes any agent to that shared workflow without requiring installation.

## Use the GUI

Open `bin/secure_erase_gui.exe`, choose **Quick delete** or **Overwrite and verify**,
and add or drag files/folders. **Start** prepares the batch; review **Confirm
batch** and approve the irreversible action. “Frozen targets” describes that
fixed selection, not an error. Completed inputs leave the list; incomplete
inputs remain for review. For a failure, copy the diagnostic JSON with its native
error code. Overwrite downgrade and forced-process actions require separate
approval.

## What the native core does

- Shares preparation, identity checks, scheduling, deferred failure recovery, and reporting between CLI and GUI.
- Freezes the selected batch before mutation; newly added or replacement targets are excluded.
- Preserves system protection and reparse boundaries. Distinct selected hardlink names remain distinct targets.
- Performs quick logical deletion without a content overwrite, readback pass, recycle bin, or per-file TRIM request.
- Keeps failure details in external reports while returning compact machine-readable summaries.

Capacity observations are measurements, not a guarantee that the job immediately released a specific number of bytes. Other open handles, remaining hardlinks, shared allocation, and snapshots can retain data or space.

```mermaid
flowchart TD
    agent["Codex / Claude Code"] --> cli["Native CLI"]
    desktop["Desktop user"] --> gui["Compact GUI"]
    cli --> core["Shared C++ core"]
    gui --> core
    core --> batch["Frozen batch storage"]
    core --> backend["Protected Windows operations"]
    backend --> storage["HDD / SSD / USB"]
```

## Build and inspect

Production targets Windows 11 or later on x64, MSVC, native C++ named modules and vendor `import std`. Build Release with the static MSVC runtime through `build_release.bat`. Build inputs, commands and validation boundaries are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

| Document | Purpose |
|---|---|
| [README_AI.md](README_AI.md) | Universal bootstrap and task routing |
| [Project cleanup Skill](skills/project-cleanup/SKILL.md) | Cleanup workflow, plans and on-demand references |
| [Design](docs/design.md) | Core boundaries and operational invariants |
| [Approved requirements](spec/requirements.json) | Base requirements and explicit amendments |
| [Windows test plan](docs/windows_test_plan.md) | Platform and storage evidence |

Release records bind each artifact to its source reference, binary provenance and actual validation scope. The owner-supplied v2.0.0 binaries have no independently attested source-to-binary correspondence; a documentation update on `main` does not replace the published asset. [Publication policy](docs/publication.md) separates development artifacts, approved prereleases and full Releases. Generated binaries and per-run logs do not belong in the source tree.

## Help and contributions

For a reproducible problem, [open an issue](https://github.com/bestkakkoii/windows_agent_cleanup/issues)
with the distribution/application versions, artifact hash or tested source
commit, Windows build and masked diagnostics. Follow [SECURITY.md](SECURITY.md)
for vulnerabilities and [CONTRIBUTING.md](CONTRIBUTING.md) to extend the tool.
The repository is maintained by bestkakkoii and contributors under [MIT](LICENSE).
