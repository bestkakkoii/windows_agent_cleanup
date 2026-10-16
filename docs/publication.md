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

Subsequent owner-supplied QA reports record one successful Agent-driven CLI Quick
pilot on Windows build 26200: 2,890 selected regular files, 102,250,476 logical
bytes and no failed, pending or remaining selected names. The reported archive
hash matches the published asset; this is scoped owner-reported runtime evidence,
not independent reproduction or full CLI acceptance. Broader CLI acceptance and
the full Windows/storage hardware matrix remain pending.
Hosted native CI establishes only its recorded fixture coverage. A passing suite
can contain explicit `not_run` scenarios, including overwrite when the runner
cannot identify storage media. See the [Windows acceptance plan](windows_test_plan.md).
Do not infer physical NAND sanitization, instant space release or maximum speed.

A later owner-supplied independent Agent assessment reports successful fresh
adoption and v2 Quick/status fixture execution for the exact CI-built Actions
runtime. Its scope, hash binding and untested cases are recorded in the
[Windows test plan](windows_test_plan.md#owner-supplied-fresh-actions-adoption-assessment).
It establishes neither new publication authority nor acceptance of differently
hashed owner-supplied EXEs. No material product defect was demonstrated by that
assessment; do not invent a redesign or extend its coverage to GUI/hardware.

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

## Future portable runtime assembly

Ordinary operator setup downloads an authorized Release's Windows x64 runtime
asset and checks its release-record SHA-256 before extraction. It does not clone
main/master, fetch GitHub-generated Source code archives, or invoke a compiler.
Keep a developer checkout separate from a portable program installation.

Engineering-only `scripts/package_runtime.py` owns future runtime archives;
`scripts/package.py` and `scripts/verify_package.py` retain their distinct,
unpublished source/evidence contract. Neither packager publishes or upgrades an
existing Release. The old v2.0.0 owner binaries and historical provenance are
unchanged; future-only PE/capability checks do not retroactively attest them.

From a clean committed checkout with the locked ImGui license restored, supply
explicit approved executable paths and a BOM-free provenance JSON file outside
Git. Its minimal shape is:

```json
{
  "schema": "windows_agent_cleanup.runtime_inputs.v1",
  "distribution_version": "2.0.0-dev.1",
  "approved_binary_sha256": {
    "bin/secure_erase_cli.exe": "<exact CLI SHA-256>",
    "bin/secure_erase_gui.exe": "<exact GUI SHA-256>"
  },
  "capabilities_capture": {
    "cli_sha256": "<same exact CLI SHA-256>",
    "result": "<replace with the unchanged object from capabilities --contract-version 2>"
  }
}
```

The `result` placeholder is an object in real input. Capture capabilities only
from the exact selected executable; packaging reads data and never executes an
input EXE. An input approval hash identifies reviewed bytes and grants no
publication authority. Do not invent a matching capability capture for legacy
binaries or substitute distribution version for their actual product version.

```text
python scripts/package_runtime.py --output <new external runtime.zip> --cli <approved CLI.exe> --gui <approved GUI.exe> --provenance <external runtime_inputs.json>
python scripts/package_runtime.py --verify <runtime.zip> --expected-sha256 <independently trusted archive SHA-256>
```

The packager checks both x64 PE VERSIONINFO resources, consistent actual
application/numeric versions and build identity, OriginalFilename, exact input
hashes, and captured v2 capabilities. It copies executable bytes unchanged,
the canonical complete Skill/references, operational schemas, licenses and
NOTICE. Runtime English/Traditional Chinese READMEs provide equivalent setup
and provenance guidance without literal application/distribution versions; the
manifest owns those identities. Their technical-report/engineering links are
pinned to the documentation source commit. Only distribution README/engineering
URLs are rendered; the Skill and
its references retain canonical bytes. README engineering and optional
registration URLs are pinned to the exact distribution source commit.

`release_manifest.json` binds every member's size/hash and
`supported_contract_versions` to the exact CLI SHA-256. Distribution source
commit, reported runtime source/dirty/build identity and actual PE version stay
separate. Unknown source identity stays unknown. These consistency checks are
not an independently authenticated or reproducible source-to-binary attestation.
The external manifest owns executable hashes; no self hash is embedded in an EXE.

Sorted entries, fixed timestamps/permissions and uncompressed ZIP storage avoid
compressor-version drift: identical canonical inputs and provenance produce
identical archive bytes. Archive and checksum destinations must be new and
outside the repository. Integrity verification never extracts or executes
members; operator trust still requires the independently obtained Release hash.

CI exercises synthetic archive-format fixtures and may assemble a non-published
runtime test artifact from that run's compiled EXEs/capabilities. Its
`publication_allowed=false` means no RC/Release authority, owner acceptance or
complete platform/hardware coverage. A runtime ZIP contains no application
source, build scripts, Python, tests, debugging symbols or developer dependencies.

PE/resource definitions follow Microsoft's
[PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) and
[VERSIONINFO resource](https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource)
contracts, checked on 2026-10-16 (Asia/Taipei). CMake captures source identity at
configuration: reconfigure after source changes before attributing a build to
that source state. The PE numeric assembly/file version `2.0.0.1` identifies the
current application development build; the string remains `2.0.0-dev.1`.
CLI `asInvoker` and GUI administrator behavior remain separate and unchanged.
