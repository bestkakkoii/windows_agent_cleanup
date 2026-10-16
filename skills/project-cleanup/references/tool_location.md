# Tool location

<!-- windows_agent_cleanup.tool_root_binding.v1 -->
The distribution root is three parent directories above this reference file:
`../../..`. Resolve it from this file's absolute location while the complete
Skill remains in its shipped source or binary layout. A source checkout's
`install_skill.ps1` replaces this binding with a literal absolute tool root.
<!-- windows_agent_cleanup.tool_root_binding.end -->

Load this reference only when an absolute README route or an intact installed
binding has not already supplied the exact tool root. Never derive it from the
project being cleaned or select PATH's unrelated executable. No particular drive
or parent is mandatory; choose a suitable writable portable location for
already-authorized setup, outside cleanup scope. Installation grants no deletion
authority.

Use `<tool_root>/bin/secure_erase_cli.exe`, or an already-built checkout's
`<tool_root>/build/windows_release/secure_erase_cli.exe`. The GUI is beside it.
If the EXE is absent, obtain the official Release Windows x64 runtime asset:
verify its release-record SHA-256 before extraction and preserve the complete
bundle. Do not clone/download main/master, choose GitHub's generated Source code
archives, or compile during ordinary setup/cleanup. Explicit engineering work
uses the bound README's source route separately.

Inspect provenance and dirty state before replacement; a separate portable
directory avoids modifying a developer checkout. Read the actual distribution,
application/build identities, contract advertisement and provenance limits from
`release_manifest.json`; distribution and application versions can differ.
A source documentation update never upgrades an installed archive.

Moving an intact unregistered bundle preserves its relative binding. An
installed Skill instead has an absolute receipt: after a move, identify the
new root and explicitly rebind. The installer rejects a receipt for another
root; use a new valid client destination or verify and explicitly remove only
the prior owned copy before registration. Never rewrite the receipt to bypass
ownership checks or copy only `SKILL.md`.

Direct reading needs no registration. Optional registration is documented in
the bound README's registration link; its installer is engineering tooling,
not required for normal binary adoption. Keep all seven Skill files together.
Client discovery folders (`.agents/skills/project-cleanup` or
`.claude/skills/project-cleanup`) are separate from the program's portable root.
