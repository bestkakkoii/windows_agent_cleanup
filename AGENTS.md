# Windows Agent Cleanup engineering contract

Scope: Windows 11+ x64; native C++26 named modules and vendor `import std`,
MSVC `/std:c++latest`, Release `/MT`, no symbols or debug runtime. Newer explicit
requirements supersede historical Windows 10/1809 and legacy CLI contracts.

For development, read the relevant approved requirements in
`spec/requirements.json`, `docs/design.md`, and owning module contracts.
`README_AI.md` is the self-contained use/development entry. A code, review or
build task is not cleanup authorization; never enter cleanup as build setup.
For cleanup use, follow its plan-selection and scope workflow.

Preserve fail-closed system protection, frozen membership, execution identity
validation, deferred lock recovery, and independent forced-process approval.
No fixed target-count ceiling: derive resident memory/commit/disk/handle budgets
from current resources; never truncate a batch or delete before full admission.
CLI is noninteractive native bulk input with compact structured results and
external reports. No MCP. Skills are optional routers, not new permissions.

Use independent agents for beneficial disjoint work, one writer per file. The
integrator owns integration/build/publication and delegates module contracts.
Internal collaboration is concise technical English, uses the simplest
sufficient format, cites paths instead of repeating large context, and
propagates this policy. Report changed files, invariants, checks, failures and
pending evidence. Give delegated agents a self-contained scoped handoff.

Allman braces, always braces, snake_case own identifiers, RAII, checked sizes,
no goto; `import std` in every owned C++ unit. SDK/third-party includes remain
at boundaries. Source/docs: UTF-8 BOM; JSON/JSONL: UTF-8 without BOM; BAT: ASCII
CRLF. Mandatory host filenames and Skill frontmatter/names follow host format.

Keep only maintained sources/config/docs/assets/tests in Git. No build output,
caches, downloaded dependencies, archives, temporary handoffs, raw logs or
per-run reports. Review staged content. Use normal commits/push only within
owner authorization; do not rewrite shared history or force-push by assumption.
Run relevant static/build checks and risk-driven tests; destructive checks use
created disposable fixtures. Never present portable/stub checks as native
Windows or hardware evidence. No NAND sanitization guarantee. Incomplete native
evidence limits delivery to RC.
