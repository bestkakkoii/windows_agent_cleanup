"""Adversarial Source ZIP integrity fixtures; never extract or execute members."""
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import warnings
import zipfile

verify = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/verify_package.py'))['verify']
commit = 'a' * 40
checks = 0


def fixture(path, mutation=None):
    content = {'source.txt': b'owned source\n'}
    digest = hashlib.sha256(content['source.txt']).hexdigest()
    validation = {'source_commit': commit, 'source_rc_eligible': True, 'release_eligible': False,
                  'source_snapshot': [{'path': 'source.txt', 'sha256': digest}]}
    content['evidence/validation_report.json'] = json.dumps(validation).encode()
    manifest = {'schema': 'windows_agent_cleanup.package.v1', 'source_commit': commit,
                'release_eligible': False, 'manifest_self_hash_excluded': True,
                'files': [{'path': p, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                          for p, data in content.items()]}
    content['package_manifest.json'] = json.dumps(manifest).encode()
    entries = [('windows_agent_cleanup/' + name, data, False) for name, data in content.items()]
    if mutation:
        mutation(entries)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data, symbolic in entries:
                info = zipfile.ZipInfo(name)
                if symbolic:
                    info.create_system = 3
                    info.external_attr = 0o120777 << 16
                archive.writestr(info, data)


def check(name, action, rejected=False):
    global checks
    try:
        action()
        passed = not rejected
    except (ValueError, KeyError, zipfile.BadZipFile):
        passed = rejected
    checks += 1
    print(json.dumps({'test': name, 'passed': passed}))
    if not passed:
        raise SystemExit(1)


with tempfile.TemporaryDirectory(prefix='cleanup_archive_fixture_') as temp:
    path = Path(temp) / 'fixture.zip'
    fixture(path)
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
    check('valid_archive_commit_and_checksum', lambda: verify(path, commit, checksum))
    check('wrong_expected_commit_rejected', lambda: verify(path, 'b' * 40), True)
    check('wrong_expected_checksum_rejected', lambda: verify(path, commit, '0' * 64), True)
    def corrupted(entries):
        entries[0] = (entries[0][0], b'changed source\n', False)
    fixture(path, corrupted)
    check('tampered_source_rejected', lambda: verify(path), True)
    fixture(path, lambda entries: entries.append(entries[0]))
    check('duplicate_archive_name_rejected', lambda: verify(path), True)
    fixture(path, lambda entries: entries.append(('windows_agent_cleanup/extra.txt', b'extra', False)))
    check('unlisted_member_rejected', lambda: verify(path), True)
    fixture(path, lambda entries: entries.pop(0))
    check('missing_member_rejected', lambda: verify(path), True)
    fixture(path, lambda entries: entries.append(('windows_agent_cleanup/../outside', b'escape', False)))
    check('path_traversal_rejected_without_extraction', lambda: verify(path), True)
    fixture(path, lambda entries: entries.append(('windows_agent_cleanup/link', b'outside', True)))
    check('symlink_rejected_without_extraction', lambda: verify(path), True)
    fixture(path, lambda entries: entries.append(('windows_agent_cleanup/stream:ads', b'ads', False)))
    check('alternate_stream_member_rejected', lambda: verify(path), True)
    def no_unexpected_outputs():
        if set(Path(temp).iterdir()) != {path}:
            raise ValueError('verifier_created_unexpected_output')
    check('fixture_scope_retains_only_owned_archive', no_unexpected_outputs)
with tempfile.TemporaryDirectory(prefix='cleanup_package_fixture_') as temp:
    root = Path(temp) / 'source'
    (root / 'scripts').mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / 'scripts/package.py', root / 'scripts/package.py')
    (root / 'dependencies.lock.json').write_text('{"dependencies": []}\n', encoding='utf-8')
    (root / 'source.txt').write_text('fixture source\n', encoding='utf-8')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL)
    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=archive_fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    fixture_commit = git('rev-parse', 'HEAD').decode().strip()
    snapshot = [{'path': name, 'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest()}
                for name in git('ls-files').decode().splitlines()]
    validation = Path(temp) / 'validation.json'
    validation.write_text(json.dumps({'source_rc_eligible': True, 'release_eligible': False,
                                     'source_snapshot': snapshot}), encoding='utf-8')
    evidence = Path(temp) / 'fixture_evidence.json'
    evidence.write_text('{"scope": "synthetic archive-format fixture only"}', encoding='utf-8')
    output = Path(temp) / 'source.zip'
    command = [__import__('sys').executable, str(root / 'scripts/package.py'), '--output', str(output),
               '--validation', str(validation), '--evidence', str(evidence)]
    run = subprocess.run(command, cwd=root, capture_output=True, text=True)
    def produced():
        if run.returncode != 0:
            raise ValueError(run.stderr)
        verify(output, fixture_commit)
        with zipfile.ZipFile(output) as archive:
            if 'windows_agent_cleanup/evidence/fixture_evidence.json' not in archive.namelist():
                raise ValueError('missing_supplied_evidence')
    check('actual_packager_clean_tree_and_evidence_roundtrip', produced)
    (root / 'source.txt').write_text('changed source\n', encoding='utf-8')
    def rejects_dirty():
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'package_requires_clean_committed_sources' not in result.stderr:
            raise ValueError('dirty_source_not_rejected')
    check('actual_packager_rejects_uncommitted_sources', rejects_dirty)
    git('add', 'source.txt')
    git('-c', 'user.name=archive_fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'changed fixture')
    def rejects_stale_validation():
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'source_membership_or_bytes_changed_after_validation' not in result.stderr:
            raise ValueError('stale_validation_not_rejected')
    check('actual_packager_rejects_stale_validation', rejects_stale_validation)
print(json.dumps({'suite': 'source_archive_integrity', 'checks': checks, 'status': 'passed'}))
