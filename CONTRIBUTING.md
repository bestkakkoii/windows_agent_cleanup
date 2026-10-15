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

## Source RC publication

CI builds the pinned tools and native modules, runs safe and isolated fixtures,
then packages a clean Source RC with its exact commit, per-file hashes and native
evidence. `scripts/verify_package.py` checks the archive without extracting or
executing it. Optional expected commit/SHA256 values must come from a trusted
release or repository revision. Python 3.11+ is needed for these packaging tools,
not for the native application or Windows build bootstrap.

A maintainer-authorized main-branch commit containing `[publish rc]` requests a
Source RC after that exact commit's complete CI succeeds. The publication workflow
accepts only successful same-repository push runs and never publishes from fork
pull requests. It creates a prerelease tagged `source-rc-<commit prefix>` and does
not overwrite an existing release. The Windows consumer-build, GUI runtime and
storage hardware matrix still require separate acceptance; CI does not promote RC
to final Release.
