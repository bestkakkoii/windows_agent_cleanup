# Publication policy

Current status: unpublished development test source, `2.0.0-dev.1`.

| Artifact | Gate | GitHub presentation |
|---|---|---|
| Development test Source ZIP | Exact committed sources, passing package checks and recorded runtime evidence | Actions artifact or private test handoff; no release/tag creation |
| RC | Owner returns actual Windows build/test results; review binds evidence to the exact revision and archive hash, required suites pass, remaining coverage is explicitly scoped | Published prerelease after acceptance; never represented as a full Latest release |
| Release | Owner-returned results reviewed; all applicable mandatory tests and claimed Windows/device/filesystem coverage pass, no blocking finding | Full published Release marked Latest, with verified source asset and checksum |

CI success is engineering evidence, not owner acceptance. Tags identify commits;
they do not establish acceptance or create release assets. Commit-message markers
have no publication authority. Current workflows do not create public releases.

Before any later publication, retain the returned build log, compiler/SDK and
numeric Windows build identities, safe/isolated fixture results, manual GUI and
storage results where applicable, exact source commit and tested archive SHA-256.
Keep private raw evidence outside Git; publish only a sanitized evidence summary.
A result for another revision does not validate changed code. Rebuild/retest the
affected gates after fixes; scope any untested matrix honestly.

The earlier `source-rc-1b5bb2d6e6a6` prerelease predates this owner gate and is
withdrawn to a draft. Its tag and attached bytes are preserved for traceability.
Withdrawal was verified by reading the draft state and unchanged tag/asset
identities after the dedicated migration. The one-purpose migration workflow
was then removed. No publication workflow remains.

GitHub defines a full latest release separately from prereleases and drafts.
Do not promote an unaccepted candidate merely to fill the repository’s Latest
release display. Configure the repository’s Releases sidebar and mark Latest
only when an accepted full Release exists.

References: [GitHub release API](https://docs.github.com/en/rest/releases/releases),
[Windows acceptance plan](windows_test_plan.md), [current project contract](../spec/project.json).
