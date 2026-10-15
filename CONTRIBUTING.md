# Contributing

Read [AGENTS.md](AGENTS.md), the development route in [README_AI.md](README_AI.md#extend-or-build-this-project), and the requirements relevant to the change. A development request does not authorize cleaning the repository or the contributor's working files.

## Changes

Keep work focused on an observable behavior. GUI and CLI use the same core; implement safety and scheduling rules there. Describe concrete before/after behavior, material tradeoffs, and the evidence collected. Keep the existing C++ module and naming conventions. Do not introduce another runtime or parallel scheduler without a demonstrated need.

Use disjoint ownership when delegating work. Internal handoffs should be concise technical English, point to exact files and contracts, and state checks, failures, and missing evidence. Read-only exploration can run in parallel; coordinate overlapping edits and cleanup.

## Validation

Run the relevant static analysis, build diagnostics, and tests justified by risk and impact. Preserve strict diagnostics rather than hiding a warning to make CI green. Destructive tests use newly created, isolated fixtures only. Portable or stub-based checks do not establish Windows runtime behavior.

A performance change needs reproducible end-to-end measurements on regenerated fixtures. Include preparation, manifest handling, deletion, recovery and reporting; record hardware, filesystem, tool versions, concurrency and background interference. Do not submit an unexplained speed multiplier.

## Pull requests and reports

Keep commits reviewable and describe the final implementation. Normal pushes require repository authorization; do not rewrite shared history or force-push by assumption. Review staged files before committing.

Include the revision, Windows build, storage/filesystem shape, exact command, status/error code, and a sanitized diagnostic excerpt when reporting a bug. Keep sensitive paths, file contents and credentials out of public reports. See [SECURITY.md](SECURITY.md) for suspected vulnerabilities.

Only maintained source, configuration, small fixtures, scripts, docs, assets and dependency locks belong in Git. Keep build outputs, downloaded dependencies, archives, private plans and per-run evidence outside the tracked source tree.
