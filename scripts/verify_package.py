"""Verify unpublished test source ZIP membership, hashes, commit and acceptance metadata.

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
        if (not isinstance(manifest, dict)
                or manifest.get('schema') != 'windows_agent_cleanup.package.v2'
                or manifest.get('version') != '2.0.0-dev.1'
                or manifest.get('status') != 'unpublished_development_test_source'
                or manifest.get('distribution_kind') != 'development_test_source'
                or manifest.get('test_source_eligible') is not True
                or manifest.get('publication_allowed') is not False
                or manifest.get('owner_acceptance') != 'not_received'
                or manifest.get('source_rc_eligible') is not False
                or manifest.get('release_eligible') is not False
                or manifest.get('manifest_self_hash_excluded') is not True):
            raise ValueError('package_contract_invalid')
        commit = manifest['source_commit']
        if (not isinstance(commit, str) or len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit)
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
        if (not isinstance(validation, dict)
                or validation.get('schema') != 'windows_agent_cleanup.validation.v2'
                or validation.get('source_commit') != commit
                or validation.get('test_source_eligible') is not True
                or validation.get('source_checks_passed') is not True
                or not isinstance(validation.get('runtime'), dict)
                or validation['runtime'].get('status') != 'passed'
                or validation.get('version') != '2.0.0-dev.1'
                or validation.get('status') != 'unpublished_development_test_source'
                or validation.get('distribution_kind') != 'development_test_source'
                or validation.get('publication_allowed') is not False
                or validation.get('owner_acceptance') != 'not_received'
                or validation.get('source_rc_eligible') is not False
                or validation.get('release_eligible') is not False):
            raise ValueError('validation_binding_invalid')
        snapshot = validation.get('source_snapshot')
        if (not isinstance(snapshot, list) or not snapshot
                or any(not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                       or not isinstance(entry.get('sha256'), str) for entry in snapshot)):
            raise ValueError('validation_source_snapshot_invalid')
        if len({entry['path'] for entry in snapshot}) != len(snapshot):
            raise ValueError('validation_source_snapshot_duplicated')
        for entry in snapshot:
            if entry['path'] not in listed or listed[entry['path']]['sha256'] != entry['sha256']:
                raise ValueError('validated_source_binding_invalid:' + entry['path'])
    return {'schema': 'windows_agent_cleanup.archive_verification.v2', 'status': 'passed',
            'archive': str(path), 'sha256': checksum, 'source_commit': commit,
            'files': len(names), 'version': '2.0.0-dev.1', 'distribution_kind': 'development_test_source',
            'package_status': 'unpublished_development_test_source',
            'test_source_eligible': True, 'publication_allowed': False,
            'owner_acceptance': 'not_received', 'source_rc_eligible': False, 'release_eligible': False,
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
        print(json.dumps({'schema': 'windows_agent_cleanup.archive_verification.v2',
                          'status': 'failed', 'error_type': type(exception).__name__, 'error': str(exception)}),
              file=sys.stderr)
        raise SystemExit(2)
