"""Verify Source ZIP membership, per-file hashes, commit and acceptance metadata.

No archive member is extracted or executed. Optional expected hashes/commit must
come from an independently trusted release or pinned repository revision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile


def verify(path: Path, expected_commit: str | None = None, expected_sha256: str | None = None) -> dict:
    with path.open('rb') as source:
        checksum = hashlib.file_digest(source, 'sha256').hexdigest()
    if expected_sha256 and checksum != expected_sha256.lower():
        raise ValueError('archive_sha256_mismatch')
    prefix = 'windows_agent_cleanup/'
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(set(names)) != len(names):
            raise ValueError('duplicate_archive_member')
        for info in archive.infolist():
            name = info.filename
            if (not name.startswith(prefix) or name.endswith('/') or '\\' in name or ':' in name
                    or '\x00' in name or '..' in PurePosixPath(name).parts
                    or stat.S_ISLNK(info.external_attr >> 16)):
                raise ValueError('unsafe_archive_member:' + name)
        manifest = json.loads(archive.read(prefix + 'package_manifest.json'))
        if manifest.get('schema') != 'windows_agent_cleanup.package.v1' or manifest.get('release_eligible') is not False:
            raise ValueError('package_contract_invalid')
        commit = manifest['source_commit']
        if (len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit)
                or expected_commit and commit != expected_commit):
            raise ValueError('source_commit_invalid_or_mismatched')
        listed = {entry['path']: entry for entry in manifest['files']}
        if len(listed) != len(manifest['files']):
            raise ValueError('duplicate_manifest_member')
        if set(names) != {prefix + p for p in listed} | {prefix + 'package_manifest.json'}:
            raise ValueError('archive_membership_mismatch')
        for name, entry in listed.items():
            info = archive.getinfo(prefix + name)
            if info.file_size != entry['bytes']:
                raise ValueError('member_size_mismatch:' + name)
            with archive.open(info) as source:
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
            if digest != entry['sha256']:
                raise ValueError('member_sha256_mismatch:' + name)
        validation = json.loads(archive.read(prefix + 'evidence/validation_report.json'))
        if (validation.get('source_commit') != commit or not validation.get('source_rc_eligible')
                or validation.get('release_eligible') is not False):
            raise ValueError('validation_binding_invalid')
        for entry in validation['source_snapshot']:
            if entry['path'] not in listed or listed[entry['path']]['sha256'] != entry['sha256']:
                raise ValueError('validated_source_binding_invalid:' + entry['path'])
    return {'schema': 'windows_agent_cleanup.archive_verification.v1', 'status': 'passed',
            'archive': str(path), 'sha256': checksum, 'source_commit': commit,
            'files': len(names), 'source_rc_eligible': True, 'release_eligible': False,
            'scope': 'archive integrity and recorded evidence binding; not independent runtime reproduction'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--expected-commit')
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.expected_commit, args.expected_sha256)))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exception:
        print(json.dumps({'schema': 'windows_agent_cleanup.archive_verification.v1',
                          'status': 'failed', 'error_type': type(exception).__name__, 'error': str(exception)}),
              file=sys.stderr)
        raise SystemExit(2)
