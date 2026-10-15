# Security

This tool intentionally performs irreversible filesystem operations. Its protection model applies to the names and identities admitted into an authorized batch. It is not a sandbox against an administrator, kernel component, compromised host, or another process that can modify its protected state.

## Reporting

Use GitHub's **Security → Report a vulnerability** when private reporting is available for this repository. If it is unavailable, open a minimal issue requesting a private contact channel; keep exploit details and sensitive data private until that channel is agreed. No private-reporting service level or response deadline is promised.

Include the affected revision, Windows build, required privileges, violated invariant, and an isolated reproduction. Avoid attaching real deletion targets, secrets or unredacted paths.

## Relevant boundaries

- System protection, frozen membership, target identity, selected-name checks and reparse handling belong in the core, not only the interface.
- Quick deletion removes selected names. It does not establish historical data erasure or immediate allocation release.
- Overwrite evidence is limited to the validated logical streams; SSD remapping, snapshots, retained copies and other storage layers can preserve data.
- Protected plans and reports may contain sensitive metadata. They must remain outside the cleanup scope and follow access and retention policy.
- Interrupted or unacknowledged operations can be partially complete. Missing completion evidence is not success and is not permission to rescan and delete new targets.
- Agent instructions and Skills do not grant operating-system privileges or override the hosting client's security policy.

Unsupported configurations or missing native evidence remain unverified; a portable test result is not a security certification.
