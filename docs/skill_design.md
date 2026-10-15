# Agent Skill design

The integration follows the shared Agent Skills directory contract and the
OpenAI Skill Creator's concise workflow/progressive-disclosure guidance. A
useful Skill is not measured by file count: this bundle contains one operational
workflow, five task-specific references and optional Codex UI metadata. It has
no copied product engine, placeholder assets, extra runtime, hooks or MCP.

| File | Responsibility and loading condition |
|---|---|
| `README_AI.md` | Universal absolute-path bootstrap, route selection, program location and optional registration. Any AI can start here without installation. |
| `skills/project-cleanup/SKILL.md` | Trigger metadata and reusable execution workflow: predefined plans, authorization, group discovery, batching, result handling and conditional resource map. |
| `references/tool_location.md` | Small source-relative or installation-bound tool location. Read when binding the program; only this reference is rendered by installation. |
| `references/disposal_evidence.md` | Positive disposal criteria and preservation rules. Read during default-plan discovery and uncertain classification. |
| `references/bulk_cli.md` | Literal manifest/command contract and resource/retention controls. Read when composing a batch. |
| `references/results_and_recovery.md` | Result fields, exit codes, yielded processes and partial/unknown completion. Read to complete a job or diagnose failure. |
| `references/exceptional_operations.md` | Overwrite recovery, independent downgrade grants and explicit process actions. Read only for those requested operations. |
| `agents/openai.yaml` | Optional Codex UI display metadata generated with the official Skill Creator helper; not an authorization grant. |
| `AGENTS.md`, `CLAUDE.md` | Repository engineering instructions and evidence rules. Cleanup does not load them as a side effect. |

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

## Upstream references

Reviewed 2026-10-15. These links document the design sources; they are not
mandatory runtime reads.

- [OpenAI Skill Creator](https://github.com/openai/skills/blob/main/skills/.system/skill-creator/SKILL.md): concise procedural body, reusable resources, generated UI metadata, validation and independent forward testing.
- [OpenAI Codex skills](https://developers.openai.com/codex/skills): progressive loading and `.agents/skills` repository/user discovery.
- [Claude Code skills](https://code.claude.com/docs/en/skills): `.claude/skills` locations, supporting files and the shared Agent Skills format.
- [Agent Skills specification](https://agentskills.io/specification): portable frontmatter, relative references and progressive disclosure.

Use the official creator's `generate_openai_yaml.py` and `quick_validate.py`
when updating this existing repository component. Repository integration is not
a request to install a personal ChatGPT skill; save the component with the
project's normal reviewed Git changes. Validate the installed complete bundle
and forward-test fresh Agents with task prompts and raw artifacts, without
leaking expected decisions or prior diagnoses.
