# Contributing

Read [AGENTS.md](AGENTS.md), the relevant approved requirements and the owning module contracts. Consult [design](docs/design.md) for cross-module work. The cleanup route in `README_AI.md` is not a required engineering read. A development request does not authorize cleaning the repository or the contributor's working files.

## Changes

Keep work focused on an observable behavior. GUI and CLI use the same core; implement safety and scheduling rules there. Describe concrete before/after behavior, material tradeoffs, and the evidence collected. Keep the existing C++ module and naming conventions. Do not introduce another runtime or parallel scheduler without a demonstrated need.

Update `README.md` and `README_zh_tw.md` together: preserve equivalent features,
setup order, authorization/validation limits and destinations, including new
documentation links. Keep literal application/distribution versions, artifact
hashes and acceptance history in release records, `spec/project.json` and the
publication policy, not README snapshots. Use `/releases/latest` for ordinary
downloads. The [Quick technical report](docs/quick_delete_technical_report.md)
owns implementation/reproduction detail; update it when the traced algorithm
changes rather than duplicating that detail in translated READMEs.
Apply the same release-agnostic rule to Skill references, setup/design guidance
and issue templates. Protocol versions and technical platform/build prerequisites
remain explicit; dated provenance/acceptance records retain their exact identities.

Preserve source formats: owned code/build files and regular documentation use strict UTF-8 with BOM; JSON/JSONL/YAML use UTF-8 without BOM; BAT is ASCII CRLF. `SKILL.md` frontmatter starts at byte zero without a BOM. Keep pinned upstream bytes unchanged. Windows build preflight checks owned code/build encoding; `scripts/validate.py` also checks documentation and format exceptions.

Use disjoint ownership when delegating work. Internal handoffs should be concise technical English, point to exact files and contracts, and state checks, failures, and missing evidence. Read-only exploration can run in parallel; coordinate overlapping edits and cleanup.

## Validation

Run the relevant static analysis, build diagnostics, and tests justified by risk and impact. Preserve strict diagnostics rather than hiding a warning to make CI green. Destructive tests use newly created, isolated fixtures only. Portable or stub-based checks do not establish Windows runtime behavior.

A performance change needs reproducible end-to-end measurements on regenerated fixtures. Include preparation, manifest handling, deletion, recovery and reporting; record hardware, filesystem, tool versions, concurrency and background interference. Do not submit an unexplained speed multiplier.

## Build from source

This is explicit engineering work. Ordinary Agent adoption uses the official
Release Windows x64 runtime ZIP, verifies its release checksum before extraction
and does not build source; follow [runtime setup](README.md#start-with-your-agent).
A missing checkout EXE is not permission to bootstrap a compiler or build during
cleanup. Obtain a source checkout only when development/building was requested.

From the source root, `build_release.bat` always configures/builds Release,
checks embedded manifests and runs the safe suites. It does not require an
administrator token for those tests. There is no separate validation BAT or
`-mode` argument. For isolated destructive fixtures, run
`build_release.bat -enable_isolated_destructive_tests` from an already elevated
console; the switch does not elevate the build. It registers 4 isolated suites
in addition to the current 11 Windows safe suites. A rerun is incremental; use a
fresh checkout/build directory when claiming a clean build. Set
`SECURE_ERASE_NO_PAUSE=1` in CMD automation if the final pause is unwanted.

The bootstrap needs x64 Visual Studio C++ tools with vendor `import std`, a
complete Windows SDK 10.0.22000.0+ and an installed/bootstrap CMake 3.15+.
It builds the immutable CMake/Ninja snapshots from `dependencies.lock.json`
into an ignored local cache. Installed Ninja is optional with MSVC `nmake`;
network access is needed for missing sources/dependencies. Preserve the actual
compiler mode, module provider, tool identities, `/MT` and no-PDB evidence.
Clear inherited build-flag overrides rather than bypassing their rejection.
See the [Windows test plan](docs/windows_test_plan.md) for discovery, clean-build,
UTF-8, offline-cache and platform checks.

For a source-only check with Python 3.11+, use
`python scripts/validate.py --output-dir build/source_validation`.
This checks source formats/module contracts and records runtime as `not_run`;
it neither builds nor executes the native application without a supplied build
directory. Keep `build_logs/<run_id>/` and actual JUnit results outside Git.
A successful suite may still report untested cases in `coverage_gaps` or stdout
`not_run` arrays. Record those gaps instead of treating the top-level result as
complete platform acceptance.

Source-package verification is also engineering-only:
`scripts/verify_package.py <source_archive.zip>` validates the unpublished test
Source ZIP without extracting/executing it. Use `--help` for its exact options;
it does not accept the published runtime ZIP or GitHub-generated source archives.

## Pull requests and reports

Keep commits reviewable and describe the final implementation. Normal pushes require repository authorization; do not rewrite shared history or force-push by assumption. Review staged files before committing.

Include the revision, Windows build, storage/filesystem shape, exact command, status/error code, and a sanitized diagnostic excerpt when reporting a bug. Keep sensitive paths, file contents and credentials out of public reports. See [SECURITY.md](SECURITY.md) for suspected vulnerabilities.

Only maintained source, configuration, small fixtures, scripts, docs, assets and dependency locks belong in Git. Keep build outputs, downloaded dependencies, archives, private plans and per-run evidence outside the tracked source tree.

## Test artifacts and publication

CI builds pinned tools and native modules, runs safe and isolated fixtures, and
packages unpublished development test sources bound to the exact commit and
per-file hashes. `scripts/verify_package.py` checks archive integrity and evidence
binding without extracting or executing it. That verifier applies to the development
test Source ZIP format, not the published owner-binary ZIP or GitHub-generated
source archives. `--offline-dependencies` includes pinned ImGui files, not prebuilt
CMake/Ninja tools. Python 3.11+ is needed for packaging, not the native application
or Windows build bootstrap.

Follow [publication policy](docs/publication.md). For subsequent versions,
neither a passing CI run, a tag, nor a commit message authorizes RC or Release
publication. Both require owner-returned Windows evidence and review bound to
the exact revision; full Release normally requires the claimed platform matrix.
No workflow currently creates public releases.

Specific owner-authorized distribution amendments, exact artifact identities
and publication receipts belong in the publication policy and `spec/project.json`.
Do not infer current versions from contributor instructions. Preserve approved
EXE bytes and distinguish distribution labels from actual application versions.
Owner GUI smoke success does not complete CLI Agent or hardware acceptance;
CI source evidence does not authenticate differently hashed owner binaries.
Do not extend a scoped authorization or relabel pending cases as passed.

## Agent integration

Keep persistent engineering rules in `AGENTS.md` (imported by `CLAUDE.md`), universal task
routing in `README_AI.md`, operational instructions in the shared Skill, and
conditional details in its bundled references. Follow the official Skill Creator
workflow, validate the complete bundle and forward-test realistic requests after
substantial changes. See [Skill design](docs/skill_design.md).
