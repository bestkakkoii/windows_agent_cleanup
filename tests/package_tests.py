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
from unittest import mock

verify = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/verify_package.py'))['verify']
commit = 'a' * 40
checks = 0


def development_metadata():
    return {'version': '2.0.0-dev.1', 'status': 'unpublished_development_test_source',
            'distribution_kind': 'development_test_source', 'test_source_eligible': True,
            'publication_allowed': False, 'owner_acceptance': 'not_received',
            'source_rc_eligible': False, 'release_eligible': False}


def fixture(path, mutation=None, manifest_changes=None, validation_changes=None):
    content = {'source.txt': b'owned source\n'}
    digest = hashlib.sha256(content['source.txt']).hexdigest()
    validation = {**development_metadata(), 'schema': 'windows_agent_cleanup.validation.v2',
                  'source_commit': commit, 'source_checks_passed': True, 'runtime': {'status': 'passed'},
                  'source_snapshot': [{'path': 'source.txt', 'sha256': digest}]}
    validation.update(validation_changes or {})
    content['evidence/validation_report.json'] = json.dumps(validation).encode()
    manifest = {**development_metadata(), 'schema': 'windows_agent_cleanup.package.v2', 'source_commit': commit,
                'manifest_self_hash_excluded': True,
                'files': [{'path': p, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                          for p, data in content.items()]}
    manifest.update(manifest_changes or {})
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
    def unpublished_archive():
        result = verify(path, commit, checksum)
        if (result['test_source_eligible'] is not True or result['publication_allowed'] is not False
                or result['owner_acceptance'] != 'not_received' or result['source_rc_eligible'] is not False
                or result['release_eligible'] is not False):
            raise ValueError('archive_verifier_promoted_unaccepted_sources')
    check('valid_archive_commit_and_checksum', unpublished_archive)
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
    for field, value in {'schema': 'windows_agent_cleanup.package.v1', 'version': '2.0.0-rc.1',
                         'status': 'source_rc_windows_hardware_validation_pending',
                         'distribution_kind': 'release', 'test_source_eligible': False,
                         'publication_allowed': True, 'owner_acceptance': 'received',
                         'source_rc_eligible': True, 'release_eligible': True}.items():
        fixture(path, manifest_changes={field: value})
        check('package_rejects_promoted_or_invalid_' + field, lambda: verify(path), True)
    for field, value in {'schema': 'windows_agent_cleanup.validation.v1', 'source_commit': 'b' * 40,
                         'version': '2.0.0-rc.1', 'status': 'approved', 'distribution_kind': 'release',
                         'test_source_eligible': False, 'source_checks_passed': False,
                         'runtime': {'status': 'not_run'}, 'publication_allowed': True,
                         'owner_acceptance': 'received', 'source_rc_eligible': True,
                         'release_eligible': True, 'source_snapshot': []}.items():
        fixture(path, validation_changes={field: value})
        check('validation_rejects_rehashed_invalid_' + field, lambda: verify(path), True)
with tempfile.TemporaryDirectory(prefix='cleanup_package_fixture_') as temp:
    root = Path(temp) / 'source'
    (root / 'scripts').mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / 'scripts/package.py', root / 'scripts/package.py')
    dependency_bytes = b'fixture dependency source only\n'
    dependency_directory = 'fixture_vendor/pinned'
    dependency_member = 'build/dependencies/' + dependency_directory + '/vendor.txt'
    dependency_file = root / dependency_member
    dependency_file.parent.mkdir(parents=True)
    dependency_file.write_bytes(dependency_bytes)
    (root / '.gitignore').write_text('build/\n', encoding='utf-8')
    (root / 'dependencies.lock.json').write_text(json.dumps({'dependencies': [{
        'directory': dependency_directory,
        'files': [{'path': 'vendor.txt', 'size': len(dependency_bytes),
                   'sha256': hashlib.sha256(dependency_bytes).hexdigest()}]
    }]}) + '\n', encoding='utf-8')
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
    validated = {**development_metadata(), 'schema': 'windows_agent_cleanup.validation.v2',
                 'source_commit': fixture_commit, 'source_checks_passed': True,
                 'runtime': {'status': 'passed'}, 'source_snapshot': snapshot}
    validation.write_text(json.dumps(validated), encoding='utf-8')
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
    offline_command = command + ['--offline-dependencies']
    def offline_roundtrip():
        result = subprocess.run(offline_command, cwd=root, capture_output=True, text=True)
        if result.returncode != 0:
            raise ValueError(result.stderr)
        verify(output, fixture_commit)
        with zipfile.ZipFile(output) as archive:
            if archive.read('windows_agent_cleanup/' + dependency_member) != dependency_bytes:
                raise ValueError('offline_dependency_cache_bytes_mismatched')
    check('actual_packager_offline_dependency_uses_restore_cache_layout', offline_roundtrip)
    dependency_file.write_bytes(b'tampered fixture dependency\n')
    def rejects_tampered_dependency():
        result = subprocess.run(offline_command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'offline_dependency_hash_mismatch' not in result.stderr:
            raise ValueError('tampered_offline_dependency_accepted')
    check('actual_packager_rejects_tampered_offline_dependency', rejects_tampered_dependency)
    dependency_file.unlink()
    def rejects_missing_dependency():
        result = subprocess.run(offline_command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'FileNotFoundError' not in result.stderr:
            raise ValueError('missing_offline_dependency_accepted')
    check('actual_packager_rejects_missing_offline_dependency', rejects_missing_dependency)
    dependency_file.write_bytes(dependency_bytes)
    def rejects_promoted_report():
        changed = dict(validated, publication_allowed=True, source_rc_eligible=True)
        validation.write_text(json.dumps(changed), encoding='utf-8')
        try:
            result = subprocess.run(command, cwd=root, capture_output=True, text=True)
            if result.returncode == 0 or 'unpublished_test_source_validation_required' not in result.stderr:
                raise ValueError('promoted_validation_accepted')
        finally:
            validation.write_text(json.dumps(validated), encoding='utf-8')
    check('actual_packager_rejects_ci_report_promoted_to_rc', rejects_promoted_report)
    git('-c', 'user.name=archive_fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '--allow-empty', '-qm', 'same bytes different source revision')
    def rejects_stale_commit():
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'validation_source_commit_mismatched' not in result.stderr:
            raise ValueError('validation_source_commit_silently_rebound')
    check('actual_packager_rejects_stale_commit_with_identical_source_bytes', rejects_stale_commit)
    validated['source_commit'] = git('rev-parse', 'HEAD').decode().strip()
    validation.write_text(json.dumps(validated), encoding='utf-8')
    (root / 'source.txt').write_text('changed source\n', encoding='utf-8')
    def rejects_dirty():
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'package_requires_clean_committed_sources' not in result.stderr:
            raise ValueError('dirty_source_not_rejected')
    check('actual_packager_rejects_uncommitted_sources', rejects_dirty)
    git('add', 'source.txt')
    git('-c', 'user.name=archive_fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'changed fixture')
    validated['source_commit'] = git('rev-parse', 'HEAD').decode().strip()
    validation.write_text(json.dumps(validated), encoding='utf-8')
    def rejects_stale_validation():
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode == 0 or 'source_membership_or_bytes_changed_after_validation' not in result.stderr:
            raise ValueError('stale_validation_not_rejected')
    check('actual_packager_rejects_stale_validation', rejects_stale_validation)
with tempfile.TemporaryDirectory(prefix='cleanup_acceptance_fixture_') as temp:
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/validate.py'))
    main = module['main']
    def fake_execute(command, root, directory, name):
        if name == 'ctest':
            (directory / 'ctest.xml').write_text('<testsuite><testcase name="safe_fixture"/></testsuite>', encoding='utf-8')
        return {'name': name, 'status': 'passed', 'exit_code': 0}
    globals_ = main.__globals__
    with mock.patch.dict(globals_, {'check_sources': lambda root: ([], []), 'execute': fake_execute}), \
            mock.patch.object(__import__('sys'), 'argv', ['validate.py', '--output-dir', temp,
                                                        '--build-dir', temp, '--skip-build']):
        result = main()
    report = json.loads((Path(temp) / 'validation_report.json').read_text(encoding='utf-8'))
    def ci_never_promotes():
        if (result != 0 or report['test_source_eligible'] is not True
                or report['runtime']['status'] != 'passed' or report['publication_allowed'] is not False
                or report['owner_acceptance'] != 'not_received' or report['source_rc_eligible'] is not False
                or report['release_eligible'] is not False):
            raise ValueError('safe_ci_pass_promoted_unaccepted_sources')
    check('actual_validation_safe_ci_pass_never_authorizes_publication', ci_never_promotes)
print(json.dumps({'suite': 'source_archive_integrity', 'checks': checks, 'status': 'passed'}))
