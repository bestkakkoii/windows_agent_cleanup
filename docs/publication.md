# Publication policy

Current distribution: [v2.0.0](https://github.com/bestkakkoii/windows_agent_cleanup/releases/tag/v2.0.0),
published as the repository's Latest Release on 2026-10-16 (Asia/Taipei).
The canonical artifact name, hashes, source references and publication receipt
are in [spec/project.json](../spec/project.json). The application and CI
source-artifact version remain `2.0.0-dev.1`; the unchanged GUI also retains its
original development-build footer. These labels describe the supplied build,
not the publication state of the distribution.

## Owner-directed first public distribution

The owner supplied both compiled executables, reported successful GUI quick
and verified-overwrite smoke tests, and explicitly requested a formal GitHub
Release before subsequent Agent-driven CLI testing. For this first `v2.0.0`
distribution, that instruction superseded the prior full-platform-matrix gate.
It authorized publication; it did not establish that pending tests had passed.

The published ZIP preserves the exact owner-supplied EXE bytes and records their
SHA-256 values. It contains runtime instructions, the complete Skill, operational
schemas and licenses. Application source, build scripts and tests are excluded
from that binary ZIP and remain in Git. GitHub also generates its normal source
ZIP/tar downloads from the tag; those are separate from the binary asset.

The release source reference includes the unified build-and-test launcher. Its
C++ runtime sources are unchanged from `479c3aa44cc918ec09a4c50a8a799ad1c89d9d0d`.
No independently authenticated source-to-owner-binary commit binding was supplied.
A matching artifact hash identifies the received bytes; it is not a reproducible
build attestation. Keep the source reference and binary provenance distinct.

CLI Agent acceptance and the full Windows/storage hardware matrix remain pending.
Hosted native CI establishes only its recorded fixture coverage. A passing suite
can contain explicit `not_run` scenarios, including overwrite when the runner
cannot identify storage media. See the [Windows acceptance plan](windows_test_plan.md).
Do not infer physical NAND sanitization, instant space release or maximum speed.

This publication exception applies only to the recorded first distribution.
Later RC/Release publication requires a new owner authorization and the normal
gates below. Do not replace an existing published asset silently. Documentation
on `main` may be newer than the tagged bundle; a documentation commit does not
update files already distributed in that published artifact.

## Normal gates for later versions

| Artifact | Gate | GitHub presentation |
|---|---|---|
| Development test Source ZIP | Exact clean committed sources, passing package checks and recorded runtime evidence | Actions artifact or private test handoff; no Release/tag creation |
| RC | Owner-returned Windows build/test results reviewed against the exact source revision and tested artifact hash; necessary suites pass and remaining coverage is scoped | Published prerelease after separate approval; never presented as a full Latest Release |
| Release | Owner-returned results reviewed; all applicable mandatory tests and claimed Windows/device/filesystem coverage pass, with no blocking finding | Published full Release marked Latest, with a binary-only runtime ZIP and checksum; sources remain separately available in Git |

Retain the returned build logs, compiler/SDK identities, numeric Windows build,
safe/isolated fixture results, relevant GUI/storage results, source revision and
tested artifact hashes. Keep private raw evidence outside Git; publish sanitized
scope and outcomes. Changed code requires review of affected gates; results from
another revision are not evidence for those changes.

CI success is engineering evidence, not owner acceptance or publication authority.
Current workflows produce unpublished development test artifacts and do not
create Releases. Their `publication_allowed=false` and development status fields
apply to those CI artifacts, not to the separately authorized public v2.0.0
binary distribution. Commit-message markers have no publication authority.

Tags identify source revisions. A published Release adds notes and assets; full
Latest Releases are separate from drafts and prereleases. Confirm both the
published state and the repository's Releases sidebar after an authorized release.

References: [GitHub release API](https://docs.github.com/en/rest/releases/releases),
[Windows acceptance plan](windows_test_plan.md), [project contract](../spec/project.json).
