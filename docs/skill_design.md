# Agent Skill design

The integration follows the shared Agent Skills directory contract and the
OpenAI Skill Creator's concise workflow/progressive-disclosure guidance. A
useful Skill is not measured by file count: this bundle contains one operational
workflow, five task-specific references and optional Codex UI metadata. It has
no copied product engine, placeholder assets, extra runtime, hooks or MCP.

| File | Responsibility and loading condition |
|---|---|
| `README.md`, `README_zh_tw.md` | Human-facing purpose, download/getting started, limitations, support and contribution links. They are not always-loaded Agent policy. |
| `README_AI.md` | Manually selected universal entry: route the current task, resolve the actual program root and link deeper procedures. No claim of native autoloading. |
| `skills/project-cleanup/SKILL.md` | Trigger metadata and reusable execution workflow: predefined plans, authorization, group discovery, batching, result handling and conditional resource map. |
| `references/tool_location.md` | Small distribution-relative or installation-bound tool location. Read when binding the program; only this reference is rendered by installation. |
| `references/disposal_evidence.md` | Positive disposal criteria and preservation rules. Read during default-plan discovery and uncertain classification. |
| `references/bulk_cli.md` | Literal manifest/command contract and resource/retention controls. Read when composing a batch. |
| `references/results_and_recovery.md` | Result fields, exit codes, yielded processes and partial/unknown completion. Read to complete a job or diagnose failure. |
| `references/exceptional_operations.md` | Overwrite recovery, independent downgrade grants and explicit process actions. Read only for those requested operations. |
| `agents/openai.yaml` | Optional Codex UI display metadata generated with the official Skill Creator helper; not an authorization grant. |
| `AGENTS.md` | Concise shared repository engineering contract: durable commands, conventions and invariants; links to detailed requirements and evidence. |
| `CLAUDE.md` | Explicit relative `@AGENTS.md` import, with only Claude-specific notes; no second copy of project rules. |

## Instruction-file loading and ownership

Checked 2026-10-16 (Asia/Taipei) against the official sources below. Human
READMEs introduce the product; the neutral AI entry routes a selected task;
AGENTS holds stable repository rules; the Skill owns conditional procedures.
Keep volatile release/tool identities in their dedicated records rather than
copying them into every always-loaded instruction file.

Codex discovers repository guidance from the project root toward the working
directory, with directory-specific precedence. Claude Code currently supports
native AGENTS discovery with conditions; this repository keeps an explicit
CLAUDE entry importing the shared AGENTS file, as its documented shared-file
pattern. Relative imports resolve from the containing file. Imports still load
the referenced content and do not compress its context cost. Claude's approval
rules for paths outside its working directory still apply; no permission or
configuration changes are required by this repository. Manual cleanup routing
does not request engineering documents, but a host may already have loaded
applicable repository instructions independently.

## Source and published runtime layouts

The complete seven-file Skill keeps the same relative layout in source and in
`windows_agent_cleanup_v2.0.0_windows_x64.zip`. From its location reference,
`../../..` resolves to the distribution root in either layout. The binary
archive supplies `bin/secure_erase_cli.exe`, `bin/secure_erase_gui.exe`, two
schemas, runtime README/AI entry files and engineering-routing stubs. It does
not supply the source installer or build scripts. Direct file reading works
without registration. For optional registration, use
`scripts/install_skill.ps1` from a source checkout and pass the actual source
or binary distribution as `-ToolRoot`; the installer reads the complete Skill
from that root and renders only its location binding. Example paths impose no
drive or directory requirement: an Agent may choose a suitable writable local
location for authorized setup. Existing bindings derive from the actual entry
file, not the current directory or a hard-coded drive. Client discovery
folders are a separate host convention; `-Destination` controls registration,
not the EXE's installation root. An intact unregistered bundle can move with
its relative binding. A registered absolute binding needs deliberate safe
reinstallation; the installer refuses a receipt belonging to a different root.

The published distribution is `v2.0.0`; the unchanged owner-supplied programs
report `2.0.0-dev.1`. Owner GUI smoke results do not establish CLI Agent or full
hardware acceptance. Runtime entries point to the release manifest and source
repository instead of assuming the complete engineering tree is installed.
The repo's source bootstrap and the archive's runtime bootstrap are different
entry files; updating source documentation does not alter published ZIP bytes.

The CLI is the deterministic executable already provided by the product. An
extra Skill script duplicating native validation/deletion would add another
failure surface, so the Skill does not wrap or reimplement the engine. Agents
use standard streaming JSON writers supplied by their own environment for large
manifests. The installer is product setup tooling, outside the Skill body.

Use only portable `name` and `description` frontmatter rather than host-only
permission flags, substitutions or dynamic shell injection. Default implicit
Skill matching can start the workflow but cannot start deletion: plan/scope
selection remains required unless already explicitly supplied. This permits
arbitrary AI read-entry use and both native discovery systems without weakening
user authorization or relying on a client-specific side-effect permission.

The installer inventories and hashes every file in the complete bundle, refuses
reparse points and unrelated/modified destinations, stages beside the target,
and swaps the directory with rollback on failed promotion. Its ownership receipt
is setup state, not a copied source file. It can upgrade the previous intact v1
two-file thin entry. No installation modifies global agent instructions.

## Optional registration

Registration is setup, not cleanup authorization. Direct reading works without
it. Keep the complete tool distribution in the location the Agent selected;
choose user-scope discovery for reuse or an explicit project-local destination
for project scope. These client folders do not constrain the tool directory.

The source checkout contains `scripts/install_skill.ps1`; the v2.0.0 binary ZIP
does not. An installer from a separate source checkout can register the Skill
shipped in an actual binary root. Replace the placeholders with observed paths:

```powershell
$tool_root = '<actual directory containing the selected README_AI.md>'
$source_root = '<actual source checkout containing scripts/install_skill.ps1>'
& (Join-Path $source_root 'scripts/install_skill.ps1') -Client codex -ToolRoot $tool_root
```

For a built source checkout, both roots can be the same. Use `-Client claude`
for Claude Code. Defaults use the current user's `.agents/skills/project-cleanup`
or `.claude/skills/project-cleanup`. For project scope, pass `-Destination` with
the full corresponding client discovery path ending in `project-cleanup`.
The installer does not edit global AGENTS/CLAUDE files, hooks, registry, MCP
settings or client permissions, and requires no symlink.

The complete-copy receipt binds the chosen tool root. After moving an intact
unregistered bundle, its relative binding follows the bundle. An installed copy
instead needs a fresh valid discovery destination, or verified explicit removal
of only the old owned copy followed by registration from the new root. A plain
rerun cannot overwrite a receipt for another root. Preserve refusal of stale,
unowned or modified copies; do not patch receipts or copy only SKILL.md.

## Upstream references

Skill-standard references reviewed 2026-10-15 (UTC); instruction-file guidance
and placement patterns checked 2026-10-16 (Asia/Taipei). These design references
are not mandatory runtime reads.

- [GitHub README guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes): user-oriented introduction, getting started and links to deeper material.
- [Codex AGENTS discovery](https://learn.chatgpt.com/docs/agent-configuration/agents-md) and [customization guidance](https://learn.chatgpt.com/docs/customization/overview): short persistent repository rules, with procedures in Skills.
- [Claude Code memory/imports](https://code.claude.com/docs/en/memory#share-one-file-with-other-coding-tools) and [instruction-writing guidance](https://code.claude.com/docs/en/best-practices#write-an-effective-claudemd): shared-file imports, current AGENTS conditions, concrete concise instructions and actual loading/permission semantics.

- [OpenAI Skill Creator](https://github.com/openai/skills/blob/main/skills/.system/skill-creator/SKILL.md): concise procedural body, reusable resources, generated UI metadata, validation and independent forward testing.
- [OpenAI Codex skills](https://developers.openai.com/codex/skills): progressive loading and `.agents/skills` repository/user discovery.
- [Claude Code skills](https://code.claude.com/docs/en/skills): `.claude/skills` locations, supporting files and the shared Agent Skills format.
- [Agent Skills specification](https://agentskills.io/specification): portable frontmatter, relative references and progressive disclosure.

Placement patterns checked on 2026-10-16 (Asia/Taipei), pinned to the reviewed
revisions:

- [reverse-skill AI entry](https://github.com/zhaoxuya520/reverse-skill/blob/cab634bd855fc287f6e420c1f36fd1a6b9245960/README_AI.md#L9) permits any installation directory, derives `<SKILL_ROOT>`, and explains rebinding absolute configuration after moves.
- [reverse-skill PowerShell router](https://github.com/zhaoxuya520/reverse-skill/blob/cab634bd855fc287f6e420c1f36fd1a6b9245960/skills/scripts/master-route.ps1#L16-L20) derives its root from the script location rather than a sample drive or the caller's current directory.
- [REA Skill setup](https://github.com/morluto/rea/blob/c7f6b8bad1a34d5efb30ff2a017672dea1fcdabb/src/application/SetupSkill.ts#L78-L85) separates the tool package from client Skill discovery directories. Its Linux installation default is not a required Windows tool location.

These references inform location discovery and packaging only; this product
keeps its native CLI, existing ownership checks and authorization workflow.

Use the official creator's `generate_openai_yaml.py` and `quick_validate.py`
when updating this existing repository component. Repository integration is not
a request to install a personal ChatGPT skill; save the component with the
project's normal reviewed Git changes. Validate the installed complete bundle
and forward-test fresh Agents with task prompts and raw artifacts, without
leaking expected decisions or prior diagnoses.
