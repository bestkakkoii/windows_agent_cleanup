# Disposal evidence

Use this reference for default automatic discovery and ambiguous candidates.
Apply evidence to directories or groups; do not make one model call per file.

| Candidate | Evidence required before default deletion |
|---|---|
| Build output or cache | Known producer, reproducible regeneration, no unique user content, no active consumer, and no retention obligation. |
| Research intermediate or fixture | Its experiment is finished, useful inputs/conclusions are retained, and the output is explicitly temporary or superseded. |
| Experimental or obsolete code | Its abandoned/superseded role is established from project history or explicit intent; verify current consumers and retain unconfirmed local changes. |
| Duplicate or backup copy | Verify the intended retained copy, completeness and required metadata; establish that the extra copy has no independent purpose or retention need. |
| Empty directory | Establish that it is disposable rather than required project structure, a mount/reparse boundary or a placeholder used by tooling. |

Names such as `tmp`, `old`, `cache` or `backup`, timestamps, file extensions,
Git ignored/untracked status, absence of references and matching content are
clues rather than disposal authority. Downloadability alone does not establish
that a local copy is expendable.

Preserve original research inputs, useful conclusions, unique data, user assets,
active/uncertain source code, unconfirmed edits, active jobs, repository metadata
and tool configuration. Preserve uncertain candidates and report why briefly.
A project plan does not include shared machine/user caches or other projects.
Do not cross reparse points, expand the project boundary, follow directory
aliases into other scopes or terminate unrelated applications.

Record concise provenance outside the cleanup targets: candidate group, reason,
retained counterpart/regeneration command when relevant, and exclusions. This
reasoning supports the Agent's choice; native scope/identity/protection checks
remain mandatory and cannot prove future usefulness on the Agent's behalf.

For custom cleanup, apply the user's explicit target and exclusion rules
instead of inventing a default classification requirement. Native protection
still applies. For scan only, discovery and inspection are allowed; deletion,
forced process actions and overwrite are not implied.
