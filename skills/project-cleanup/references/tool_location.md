# Tool location

<!-- windows_agent_cleanup.tool_root_binding.v1 -->
The source distribution root is three parent directories above this reference
file: `../../..`. Resolve it from this file's absolute location. This source
binding is replaced with a literal absolute tool root by `install_skill.ps1`.
<!-- windows_agent_cleanup.tool_root_binding.end -->

Use `<tool_root>/bin/secure_erase_cli.exe` for a binary bundle, or
`<tool_root>/build/windows_release/secure_erase_cli.exe` for a built checkout.
The GUI is `secure_erase_gui.exe` beside it. Do not search PATH as a fallback.
If the bound distribution moved or its executable is absent, report the exact
missing location; repair the binding/rebuild through `<tool_root>/README_AI.md`
instead of substituting another installation.

For development read `<tool_root>/AGENTS.md`, or `<tool_root>/CLAUDE.md` for
Claude Code, followed by the relevant module contracts and requirements. A
cleanup invocation does not need to load those engineering documents.
