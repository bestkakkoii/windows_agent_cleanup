"""Package unpublished development test sources from a clean committed tree.

Per-run evidence is attached from outside the repository. The archive uses a
fixed historical DOS timestamp so extracted CMake inputs never have future times.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile


def git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(['git', *arguments], cwd=root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--validation', type=Path, required=True)
    parser.add_argument('--offline-dependencies', action='store_true')
    parser.add_argument('--evidence', type=Path, action='append', default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if root == output or root in output.parents:
        parser.error('package_output_must_be_outside_repository')
    if git(root, 'status', '--porcelain', '--untracked-files=normal').strip():
        parser.error('package_requires_clean_committed_sources')
    validation = json.loads(args.validation.read_text(encoding='utf-8'))
    if (not isinstance(validation, dict)
            or validation.get('schema') != 'windows_agent_cleanup.validation.v2'
            or validation.get('test_source_eligible') is not True
            or validation.get('source_checks_passed') is not True
            or not isinstance(validation.get('runtime'), dict)
            or validation['runtime'].get('status') != 'passed'
            or validation.get('distribution_kind') != 'development_test_source'
            or validation.get('version') != '2.0.0-dev.1'
            or validation.get('status') != 'unpublished_development_test_source'
            or validation.get('publication_allowed') is not False
            or validation.get('owner_acceptance') != 'not_received'
            or validation.get('source_rc_eligible') is not False
            or validation.get('release_eligible') is not False):
        parser.error('unpublished_test_source_validation_required')
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    if validation.get('source_commit') != commit:
        parser.error('validation_source_commit_mismatched')
    content = {}
    for name in git(root, 'ls-files', '-z').split(b'\0'):
        if name:
            path = os.fsdecode(name)
            content[path] = (root / path).read_bytes()
    snapshot = validation.get('source_snapshot')
    if (not isinstance(snapshot, list) or not snapshot
            or any(not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                   or not isinstance(entry.get('sha256'), str) for entry in snapshot)):
        parser.error('validation_source_snapshot_invalid')
    expected = {entry['path']: entry['sha256'] for entry in snapshot}
    if len(expected) != len(snapshot):
        parser.error('validation_source_snapshot_duplicated')
    actual = {path: hashlib.sha256(data).hexdigest() for path, data in content.items()}
    if actual != expected:
        parser.error('source_membership_or_bytes_changed_after_validation')
    lock = json.loads(content['dependencies.lock.json'].decode('utf-8-sig'))
    if args.offline_dependencies:
        for dependency in lock['dependencies']:
            cache_directory = 'build/dependencies/' + dependency['directory']
            cache = root / cache_directory
            for entry in dependency['files']:
                path = cache / entry['path']
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() != entry['sha256']:
                    parser.error('offline_dependency_hash_mismatch:' + str(path))
                content[cache_directory + '/' + entry['path']] = data
    content['evidence/validation_report.json'] = (json.dumps(validation, ensure_ascii=False, indent=2) + '\n').encode()
    for path in args.evidence:
        name = 'evidence/' + path.name
        if path.suffix not in {'.json', '.xml', '.jsonl'} or name in content:
            parser.error('evidence_name_or_format_invalid:' + path.name)
        content[name] = path.read_bytes()
    manifest = {'schema': 'windows_agent_cleanup.package.v2', 'version': '2.0.0-dev.1',
                'source_commit': commit, 'status': 'unpublished_development_test_source',
                'distribution_kind': 'development_test_source',
                'test_source_eligible': True, 'publication_allowed': False,
                'owner_acceptance': 'not_received', 'source_rc_eligible': False,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'files': [{'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                          for path, data in sorted(content.items())],
                'manifest_self_hash_excluded': True, 'release_eligible': False}
    content['package_manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    timestamp = (2000, 1, 1, 0, 0, 0)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(content.items()):
            if name.startswith('/') or '..' in Path(name).parts or name.endswith('.zip'):
                parser.error('package_path_invalid:' + name)
            entry = zipfile.ZipInfo('windows_agent_cleanup/' + name, timestamp)
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or len(archive.namelist()) != len(content):
            raise ValueError('package_crc_or_membership_failed')
        for name, data in content.items():
            if archive.read('windows_agent_cleanup/' + name) != data:
                raise ValueError('package_roundtrip_failed:' + name)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(checksum + '  ' + output.name + '\n', encoding='utf-8')
    print(json.dumps({'archive': str(output), 'sha256': checksum, 'source_commit': commit,
                      'files': len(content), 'crc_verified': True, 'hashes_verified': True,
                      'version': '2.0.0-dev.1', 'distribution_kind': 'development_test_source',
                      'package_status': 'unpublished_development_test_source',
                      'test_source_eligible': True, 'publication_allowed': False,
                      'owner_acceptance': 'not_received', 'source_rc_eligible': False, 'release_eligible': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as exception:
        print(json.dumps({'schema': 'windows_agent_cleanup.package.error.v1', 'error_type': type(exception).__name__,
                          'message': str(exception)}), file=sys.stderr)
        raise SystemExit(2)
