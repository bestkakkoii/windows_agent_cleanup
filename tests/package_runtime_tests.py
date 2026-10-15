"""Synthetic PE/archive fixtures only: no application run, cleanup or release acceptance."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile


source = Path(__file__).resolve().parents[1]
module = runpy.run_path(str(source / 'scripts/package_runtime.py'))
package = module['build_package']
verify = module['verify_runtime']
identity = module['pe_identity']
version = '2.0.0-dev.1'
build = version + '/' + '1' * 40 + '/synthetic_archive_fixture_only'


def version_block(key, value=b'', children=(), kind=0):
    data = bytearray(b'\0' * 6 + (key + '\0').encode('utf-16-le'))
    data.extend(b'\0' * (-len(data) % 4))
    data.extend(value)
    for child in children:
        data.extend(b'\0' * (-len(data) % 4))
        data.extend(child)
    struct.pack_into('<HHH', data, 0, len(data), len(value) // (2 if kind else 1), kind)
    return bytes(data)


def synthetic_pe(filename, application_version=version):
    strings = [('FileVersion', application_version), ('ProductVersion', application_version),
               ('BuildIdentity', build), ('OriginalFilename', filename)]
    entries = [version_block(key, (value + '\0').encode('utf-16-le'), kind=1) for key, value in strings]
    fixed = struct.pack('<13I', 0xfeef04bd, 0x10000, 0x20000, 1, 0x20000, 1, 0x3f, 2, 0x40004, 1, 0, 0, 0)
    blob = version_block('VS_VERSION_INFO', fixed, [version_block('StringFileInfo', children=[
        version_block('040904b0', children=entries, kind=1)], kind=1)])
    resource_size = (256 + len(blob) + 511) & ~511
    data = bytearray(512 + resource_size)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<I', data, optional + 108, 16)
    struct.pack_into('<II', data, optional + 128, 0x1000, resource_size)
    section = optional + 240
    data[section:section + 8] = b'.rsrc\0\0\0'
    struct.pack_into('<IIII', data, section + 8, resource_size, 0x1000, resource_size, 512)
    for offset, identifier, child in [(0, 16, 0x80000018), (24, 1, 0x80000030), (48, 1033, 72)]:
        struct.pack_into('<HH', data, 512 + offset + 12, 0, 1)
        struct.pack_into('<II', data, 512 + offset + 16, identifier, child)
    struct.pack_into('<IIII', data, 512 + 72, 0x1100, len(blob), 0, 0)
    data[768:768 + len(blob)] = blob
    return bytes(data)


class runtime_package_tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='runtime_archive_fixture_')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'canonical'
        self.root.mkdir()
        for name in ['README_AI.md', 'LICENSE', 'NOTICE']:
            shutil.copyfile(source / name, self.root / name)
        for name in ['skills/project-cleanup', 'schemas']:
            shutil.copytree(source / name, self.root / name)
        (self.root / '.gitignore').write_text('build/\n', encoding='ascii')
        license_data = b'explicit synthetic dependency license fixture\n'
        license_path = self.root / 'build/dependencies/imgui/fixture/LICENSE.txt'
        license_path.parent.mkdir(parents=True)
        license_path.write_bytes(license_data)
        (self.root / 'dependencies.lock.json').write_text(json.dumps({'dependencies': [
            {'name': 'dear_imgui', 'directory': 'imgui/fixture', 'files': [
                {'path': 'LICENSE.txt', 'size': len(license_data), 'sha256': hashlib.sha256(license_data).hexdigest()}]}]}), encoding='utf-8')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=runtime_fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'synthetic canonical docs')
        self.cli = self.base / 'cli.exe'
        self.gui = self.base / 'gui.exe'
        self.cli.write_bytes(synthetic_pe('secure_erase_cli.exe'))
        self.gui.write_bytes(synthetic_pe('secure_erase_gui.exe'))
        self.provenance = self.base / 'provenance.json'
        self.capture = {'schema': 'windows_agent_cleanup.runtime_inputs.v1', 'distribution_version': '0.0.0-fixture',
                        'approved_binary_sha256': {
                            'bin/secure_erase_cli.exe': hashlib.sha256(self.cli.read_bytes()).hexdigest(),
                            'bin/secure_erase_gui.exe': hashlib.sha256(self.gui.read_bytes()).hexdigest()},
                        'capabilities_capture': {'cli_sha256': hashlib.sha256(self.cli.read_bytes()).hexdigest(),
                            'result': {'schema': 'windows_agent_cleanup.capabilities.v2', 'supported_contract_versions': [1, 2],
                                'identity': {'version': version, 'source_commit': '1' * 40, 'source_commit_known': True,
                                             'source_dirty': False, 'build_identity': build}}}}
        self.save_capture()
        self.output = self.base / 'runtime.zip'

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.DEVNULL).decode().strip()

    def save_capture(self):
        self.provenance.write_text(json.dumps(self.capture), encoding='utf-8')

    def produce(self, output=None):
        return package(self.root, output or self.output, self.cli, self.gui, self.provenance)

    def test_deterministic_exact_bytes_canonical_skill_and_pinned_routing(self):
        result = self.produce()
        second = self.base / 'same_inputs.zip'
        self.produce(second)
        self.assertEqual(self.output.read_bytes(), second.read_bytes())
        self.assertFalse(result['publication_allowed'])
        with zipfile.ZipFile(self.output) as archive:
            prefix = 'windows_agent_cleanup/'
            self.assertEqual(archive.read(prefix + 'bin/secure_erase_cli.exe'), self.cli.read_bytes())
            for path in (self.root / 'skills/project-cleanup').rglob('*'):
                if path.is_file():
                    self.assertEqual(archive.read(prefix + path.relative_to(self.root).as_posix()), path.read_bytes())
            readme = archive.read(prefix + 'README_AI.md').decode('utf-8-sig')
            self.assertIn('/blob/' + self.git('rev-parse', 'HEAD') + '/CONTRIBUTING.md', readme)
            self.assertNotIn('](AGENTS.md)', readme)
            manifest = json.loads(archive.read(prefix + 'release_manifest.json'))
            self.assertEqual(manifest['contract_binding']['cli_sha256'], hashlib.sha256(self.cli.read_bytes()).hexdigest())
            self.assertEqual(manifest['runtime_build']['source_commit'], '1' * 40)
            self.assertNotEqual(manifest['distribution_source_commit'], manifest['runtime_build']['source_commit'])
            self.assertEqual(manifest['source_correspondence'], 'not_independently_attested')
        verify(self.output, hashlib.sha256(self.output.read_bytes()).hexdigest())

    def test_approved_binary_hash_required(self):
        self.cli.write_bytes(self.cli.read_bytes() + b'altered')
        with self.assertRaisesRegex(ValueError, 'approved_binary_hash_mismatch'):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_capabilities_must_bind_exact_cli(self):
        self.capture['capabilities_capture']['cli_sha256'] = '0' * 64
        self.save_capture()
        with self.assertRaisesRegex(ValueError, 'capabilities_binary_binding_mismatch'):
            self.produce()

    def test_no_inferred_v2_from_distribution_version(self):
        self.capture['capabilities_capture']['result']['supported_contract_versions'] = [1]
        self.save_capture()
        with self.assertRaisesRegex(ValueError, 'future_runtime_v2_capabilities_required'):
            self.produce()

    def test_reported_version_must_match_pe_bytes(self):
        self.capture['capabilities_capture']['result']['identity']['version'] = '9.9.9'
        self.save_capture()
        with self.assertRaisesRegex(ValueError, 'capabilities_pe_identity_mismatch'):
            self.produce()

    def test_inconsistent_gui_pair_rejected(self):
        self.gui.write_bytes(synthetic_pe('secure_erase_gui.exe', '9.9.9'))
        self.capture['approved_binary_sha256']['bin/secure_erase_gui.exe'] = hashlib.sha256(self.gui.read_bytes()).hexdigest()
        self.save_capture()
        with self.assertRaisesRegex(ValueError, 'runtime_binary_pair_identity_mismatch'):
            self.produce()

    def test_no_uncommitted_operator_rules(self):
        with (self.root / 'README_AI.md').open('ab') as stream:
            stream.write(b'changed rules')
        with self.assertRaisesRegex(ValueError, 'clean_committed_sources'):
            self.produce()

    def test_existing_output_never_overwritten(self):
        self.output.write_bytes(b'existing archive')
        with self.assertRaisesRegex(ValueError, 'new_path_outside_repository'):
            self.produce()
        self.assertEqual(self.output.read_bytes(), b'existing archive')

    def test_existing_checksum_never_overwritten(self):
        checksum = self.output.with_name(self.output.name + '.sha256')
        checksum.write_text('existing evidence', encoding='ascii')
        with self.assertRaisesRegex(ValueError, 'new_path_outside_repository'):
            self.produce()
        self.assertEqual(checksum.read_text(), 'existing evidence')
        self.assertFalse(self.output.exists())

    def test_invalid_input_object_reports_contract_failure(self):
        self.provenance.write_text('[]', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'input_contract_invalid'):
            self.produce()

    def test_locked_dependency_license_binding(self):
        (self.root / 'build/dependencies/imgui/fixture/LICENSE.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'license_binding_invalid'):
            self.produce()

    def test_archive_tamper_rejected_without_extraction(self):
        self.produce()
        broken = self.base / 'tampered.zip'
        with zipfile.ZipFile(self.output) as original, zipfile.ZipFile(broken, 'w') as archive:
            for info in original.infolist():
                data = original.read(info.filename)
                if info.filename.endswith('/README.md'):
                    data += b'changed'
                archive.writestr(info, data)
        with self.assertRaisesRegex(ValueError, 'member_bytes_mismatch'):
            verify(broken)
        self.assertFalse((self.base / 'windows_agent_cleanup').exists())

    def test_pe_reader_rejects_invalid_ranges_architecture_and_missing_resource(self):
        for data in [b'', b'MZ' + b'\0' * 62, self.cli.read_bytes()[:600]]:
            with self.assertRaises(ValueError):
                identity(data)
        bad = bytearray(self.cli.read_bytes())
        struct.pack_into('<H', bad, 0x84, 0x14c)
        with self.assertRaisesRegex(ValueError, 'x64_required'):
            identity(bytes(bad))
        bad = bytearray(self.cli.read_bytes())
        struct.pack_into('<I', bad, 512 + 16, 17)
        with self.assertRaisesRegex(ValueError, 'version_resource_required'):
            identity(bytes(bad))


if __name__ == '__main__':
    unittest.main(verbosity=2)
