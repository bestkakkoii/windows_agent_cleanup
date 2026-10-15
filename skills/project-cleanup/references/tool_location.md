# Tool location

<!-- windows_agent_cleanup.tool_root_binding.v1 -->
The distribution root is three parent directories above this reference file:
`../../..`. Resolve it from this file's absolute location while the complete
Skill remains in its shipped source or binary layout. A source checkout's
`install_skill.ps1` replaces this binding with a literal absolute tool root.
<!-- windows_agent_cleanup.tool_root_binding.end -->

Use the actual location, not a path copied from an example. No particular drive,
`D:/Tools`, `C:/tools` or directory name is required. For an existing setup,
derive the root from the absolute README or this intact Skill layout. When
setup is authorized and no location was supplied, choose a suitable writable
local directory outside the cleanup scope; do not require a drive to exist
because an example used it. A tool installation directory is not a cleanup
authorization root.

Use `<tool_root>/bin/secure_erase_cli.exe` for a binary bundle, or
`<tool_root>/build/windows_release/secure_erase_cli.exe` for a built checkout.
The GUI is `secure_erase_gui.exe` beside it. Do not search PATH as a fallback.
Moving an intact, unregistered bundle preserves its relative binding. An
installed Skill instead has an absolute location receipt: if that location
moved, identify the new root from the moved distribution and explicitly rebind
it before use. The current installer rejects an existing receipt for a
different root; use a new valid client destination or verify and explicitly
remove only the prior owned Skill before reinstalling. Do not rewrite its
receipt to bypass ownership checks. If the executable itself is absent, follow
the bound README's source/build route instead of substituting another EXE.

For development follow `<tool_root>/README_AI.md`: source checkouts contain the
engineering documents and build scripts; binary bundles contain runtime entry
files that link to the source repository. The published `v2.0.0` binary archive
has no installer or build tooling. Its applications report `2.0.0-dev.1`; use
`release_manifest.json` for distribution identity and evidence limitations.

Direct reading needs no registration. For optional client discovery, obtain the
source checkout's `scripts/install_skill.ps1` and pass this actual distribution
root as `-ToolRoot`; the script may reside in a separate source checkout. Keep
all seven Skill files together and let that installer bind the location.
Client discovery destinations are separate: defaults use the current profile's
`.agents/skills/project-cleanup` or `.claude/skills/project-cleanup`; an explicit
`-Destination` may choose a supported project-local discovery directory and
must end in `project-cleanup`. These host conventions do not constrain the tool
root's drive or directory. Do not move a raw relative-bound copy into a client
folder or copy only `SKILL.md`. A cleanup invocation does not need to load the
engineering documents.
