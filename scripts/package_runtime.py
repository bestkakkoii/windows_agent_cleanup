"""Assemble or inspect future portable runtime ZIPs; never publish or execute input EXEs.

Engineering-only Python tooling. Operators download verified binary assets. Explicit
approval hashes are input provenance, not source-to-binary or owner-acceptance proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import zipfile


prefix = 'windows_agent_cleanup/'
repository_url = 'https://github.com/bestkakkoii/windows_agent_cleanup'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def checked_text(value: object, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError('invalid_' + name)
    return value


def sha(value: object, name: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        raise ValueError('invalid_' + name)
    return value


def pe_identity(data: bytes) -> dict:
    """Bounded PE32+ RT_VERSION reader; input is data, never loaded/executed.

    Microsoft PE/resource and VERSIONINFO layouts; no external parser dependency.
    Only one unambiguous numeric resource and matching English UTF-16 strings
    are accepted. This deliberately rejects old inputs lacking future metadata.
    """
    def unpack(fmt: str, offset: int):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('pe_range_invalid')
        return struct.unpack_from(fmt, data, offset)
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('pe_dos_header_invalid')
    start = unpack('<I', 60)[0]
    if data[start:start + 4] != b'PE\0\0':
        raise ValueError('pe_signature_invalid')
    machine, count, _, _, _, optional_size, flags = unpack('<HHIIIHH', start + 4)
    optional = start + 24
    if machine != 0x8664 or not flags & 2 or flags & 0x2000 or not 1 <= count <= 96:
        raise ValueError('pe_executable_x64_required')
    if optional_size < 136 or unpack('<H', optional)[0] != 0x20b or unpack('<I', optional + 108)[0] < 3:
        raise ValueError('pe_optional_header_invalid')
    resource_rva, resource_size = unpack('<II', optional + 128)
    if not 16 <= resource_size <= 16 * 1024 * 1024:
        raise ValueError('pe_resource_size_invalid')
    sections = []
    for index in range(count):
        offset = optional + optional_size + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = unpack('<IIII', offset + 8)
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))
    def file_offset(rva: int, size: int) -> int:
        matches = [raw + rva - address for address, _, raw, raw_size in sections
                   if address <= rva and rva + size <= address + raw_size
                   and raw + rva - address + size <= len(data)]
        if len(matches) != 1:
            raise ValueError('pe_resource_rva_invalid')
        return matches[0]
    base = file_offset(resource_rva, resource_size)
    def resource_directory(relative: int) -> list[tuple[int, int]]:
        if relative < 0 or relative + 16 > resource_size:
            raise ValueError('pe_resource_directory_invalid')
        named, ids = unpack('<HH', base + relative + 12)
        if named + ids > 4096 or relative + 16 + (named + ids) * 8 > resource_size:
            raise ValueError('pe_resource_entries_invalid')
        return [unpack('<II', base + relative + 16 + i * 8) for i in range(named + ids)]
    versions = [target for identifier, target in resource_directory(0) if identifier == 16]
    if len(versions) != 1 or not versions[0] & 0x80000000:
        raise ValueError('pe_version_resource_required')
    names = resource_directory(versions[0] & 0x7fffffff)
    if len(names) != 1 or not names[0][1] & 0x80000000:
        raise ValueError('pe_version_name_ambiguous')
    languages = resource_directory(names[0][1] & 0x7fffffff)
    if len(languages) != 1 or languages[0][1] & 0x80000000:
        raise ValueError('pe_version_language_ambiguous')
    relative = languages[0][1]
    if relative + 16 > resource_size:
        raise ValueError('pe_version_entry_invalid')
    rva, size, _, _ = unpack('<IIII', base + relative)
    if not 52 <= size <= 65536:
        raise ValueError('pe_version_data_size_invalid')
    version = data[file_offset(rva, size):file_offset(rva, size) + size]
    def block(offset: int, end: int, depth: int = 0):
        if depth > 4 or offset + 6 > end:
            raise ValueError('version_block_invalid')
        length, value_length, kind = struct.unpack_from('<HHH', version, offset)
        if length < 6 or offset + length > end or kind not in (0, 1):
            raise ValueError('version_block_length_invalid')
        cursor = offset + 6
        key_end = cursor
        while key_end + 2 <= offset + length and version[key_end:key_end + 2] != b'\0\0':
            key_end += 2
        if key_end + 2 > offset + length:
            raise ValueError('version_key_invalid')
        key = version[cursor:key_end].decode('utf-16-le')
        cursor = (key_end + 5) & ~3
        value_size = value_length * (2 if kind else 1)
        if cursor + value_size > offset + length:
            raise ValueError('version_value_invalid')
        value = version[cursor:cursor + value_size]
        cursor = (cursor + value_size + 3) & ~3
        children = []
        while cursor + 6 <= offset + length:
            child = block(cursor, offset + length, depth + 1)
            children.append(child)
            cursor = (cursor + child[3] + 3) & ~3
        return key, value, children, length
    key, fixed, children, _ = block(0, len(version))
    if key != 'VS_VERSION_INFO' or len(fixed) != 52 or struct.unpack_from('<I', fixed)[0] != 0xfeef04bd:
        raise ValueError('version_fixed_info_invalid')
    fields = struct.unpack('<13I', fixed)
    numeric_file = [fields[2] >> 16, fields[2] & 0xffff, fields[3] >> 16, fields[3] & 0xffff]
    numeric_product = [fields[4] >> 16, fields[4] & 0xffff, fields[5] >> 16, fields[5] & 0xffff]
    string_tables = [table for child in children if child[0] == 'StringFileInfo' for table in child[2]]
    if len(string_tables) != 1:
        raise ValueError('version_string_table_ambiguous')
    strings = {}
    for name, value, _, _ in string_tables[0][2]:
        if name in strings:
            raise ValueError('version_string_duplicated')
        strings[name] = value.decode('utf-16-le').rstrip('\0')
    actual = checked_text(strings.get('ProductVersion'), 'pe_product_version')
    if strings.get('FileVersion') != actual or numeric_file != numeric_product:
        raise ValueError('pe_version_inconsistent')
    return {'application_version': actual, 'numeric_version': numeric_file,
            'build_identity': checked_text(strings.get('BuildIdentity'), 'pe_build_identity'),
            'original_filename': checked_text(strings.get('OriginalFilename'), 'pe_original_filename')}


def render_readme_ai(data: bytes, commit: str) -> bytes:
    text = data.decode('utf-8-sig')
    for name in ['AGENTS.md', 'CLAUDE.md', 'CONTRIBUTING.md', 'docs/skill_design.md']:
        text = re.sub(r'\]\(' + re.escape(name) + r'(#[^)]+)?\)',
                      lambda match: '](' + repository_url + '/blob/' + commit + '/' + name +
                      (match.group(1) or '') + ')', text)
    return ('\ufeff' + text).encode('utf-8')


def build_package(root: Path, output: Path, cli: Path, gui: Path, provenance_path: Path) -> dict:
    """Package exact explicitly approved bytes against a clean canonical commit.

    Provenance is caller-supplied evidence. Capability capture is hash-bound but
    not independently authenticated; PE metadata provides additional consistency,
    not a proof of the source used to build an executable.
    """
    root = root.resolve()
    output = output.resolve()
    if (output == root or root in output.parents or output.exists()
            or output.with_name(output.name + '.sha256').exists()):
        raise ValueError('runtime_output_requires_new_path_outside_repository')
    def git(*args: str) -> str:
        return subprocess.check_output(['git', *args], cwd=root).decode('utf-8').strip()
    if git('status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('runtime_package_requires_clean_committed_sources')
    commit = sha(git('rev-parse', 'HEAD'), 'distribution_source_commit', 40)
    provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
    if not isinstance(provenance, dict) or provenance.get('schema') != 'windows_agent_cleanup.runtime_inputs.v1':
        raise ValueError('runtime_input_contract_invalid')
    distribution = checked_text(provenance.get('distribution_version'), 'distribution_version', 96)
    if not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?', distribution):
        raise ValueError('distribution_version_invalid')
    binaries = {'bin/secure_erase_cli.exe': cli.read_bytes(), 'bin/secure_erase_gui.exe': gui.read_bytes()}
    approved = provenance.get('approved_binary_sha256', {})
    if not isinstance(approved, dict):
        raise ValueError('approved_binary_hash_object_required')
    identities = {}
    for name, data in binaries.items():
        if digest(data) != sha(approved.get(name), 'approved_binary_sha256'):
            raise ValueError('runtime_approved_binary_hash_mismatch:' + name)
        identity = pe_identity(data)
        if identity['original_filename'] != PurePosixPath(name).name:
            raise ValueError('runtime_original_filename_mismatch:' + name)
        identities[name] = identity
    cli_identity = identities['bin/secure_erase_cli.exe']
    if any({key: value for key, value in identity.items() if key != 'original_filename'} !=
           {key: value for key, value in cli_identity.items() if key != 'original_filename'}
           for identity in identities.values()):
        raise ValueError('runtime_binary_pair_identity_mismatch')
    capture = provenance.get('capabilities_capture', {})
    if not isinstance(capture, dict) or capture.get('cli_sha256') != digest(binaries['bin/secure_erase_cli.exe']):
        raise ValueError('capabilities_binary_binding_mismatch')
    capabilities = capture.get('result', {})
    if (not isinstance(capabilities, dict) or capabilities.get('schema') != 'windows_agent_cleanup.capabilities.v2'
            or capabilities.get('supported_contract_versions') != [1, 2]):
        raise ValueError('future_runtime_v2_capabilities_required')
    runtime = capabilities.get('build', capabilities.get('identity', {}))
    if not isinstance(runtime, dict) or runtime.get('version') != cli_identity['application_version'] or runtime.get('build_identity') != cli_identity['build_identity']:
        raise ValueError('capabilities_pe_identity_mismatch')
    known = runtime.get('source_commit_known')
    source_commit = runtime.get('source_commit')
    if not isinstance(known, bool) or not isinstance(runtime.get('source_dirty'), (bool, type(None))):
        raise ValueError('capabilities_source_identity_invalid')
    if known:
        sha(source_commit, 'runtime_source_commit', 40)
    elif source_commit not in (None, 'unknown', ''):
        raise ValueError('unknown_runtime_commit_must_not_claim_correspondence')
    # Canonical membership comes from tracked source, not a cached release copy.
    tracked = git('ls-files').splitlines()
    selected = [name for name in tracked if name.startswith('skills/project-cleanup/') or name.startswith('schemas/')]
    selected += ['LICENSE', 'NOTICE']
    files = dict(binaries)
    for name in selected:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('canonical_file_not_regular:' + name)
        files[name] = path.read_bytes()
    if 'skills/project-cleanup/SKILL.md' not in files or not any(name.startswith('skills/project-cleanup/references/') for name in files):
        raise ValueError('canonical_skill_incomplete')
    # The locked license bytes are restored by build tooling; never download here.
    lock = json.loads((root / 'dependencies.lock.json').read_text(encoding='utf-8'))
    imgui = next(item for item in lock['dependencies'] if item['name'] == 'dear_imgui')
    license_entry = next(item for item in imgui['files'] if item['path'] == 'LICENSE.txt')
    license_path = root / 'build/dependencies' / imgui['directory'] / 'LICENSE.txt'
    license_bytes = license_path.read_bytes()
    if digest(license_bytes) != license_entry['sha256'] or len(license_bytes) != license_entry['size']:
        raise ValueError('runtime_dependency_license_binding_invalid')
    files['licenses/imgui_LICENSE.txt'] = license_bytes
    files['README_AI.md'] = render_readme_ai((root / 'README_AI.md').read_bytes(), commit)
    runtime_readme = f'''# Windows Agent Cleanup — portable runtime

Distribution: `{distribution}`. Actual application version: `{cli_identity['application_version']}`.

## Start with your agent

Windows 11+ x64. Keep this complete directory together; no compiler, Python,
Node.js, SDK, MCP service, global PATH change or Skill registration is required.
Choose a suitable directory and give the local Windows agent this directory's
absolute [README_AI.md](README_AI.md) path. Reading/installation grants no deletion authority.
GUI: `bin/secure_erase_gui.exe`; machine CLI: `bin/secure_erase_cli.exe`.

Verify this archive's SHA-256 from the authorized Release record before extraction.
This binary runtime is distinct from GitHub-generated Source code archives.
All member hashes and exact CLI contract binding are in `release_manifest.json`.
Distribution documentation source: `{commit}`. Captured runtime build identity:
`{cli_identity['build_identity']}`. Metadata/hash consistency is not independently
attested source-to-binary correspondence or physical sanitization proof.

[Engineering instructions]({repository_url}/blob/{commit}/CONTRIBUTING.md#build-from-source) ·
[Optional registration]({repository_url}/blob/{commit}/docs/skill_design.md#optional-registration).
Packaging alone grants no RC/Release publication or owner acceptance.
'''
    files['README.md'] = runtime_readme.encode('utf-8-sig')
    manifest = {'schema': 'windows_agent_cleanup.runtime_package.v1', 'distribution_kind': 'portable_runtime',
                'distribution_version': distribution, 'application_version': cli_identity['application_version'],
                'platform': {'minimum_windows_build': 22000, 'architecture': 'x64'},
                'distribution_source_commit': commit, 'runtime_build': runtime,
                'source_correspondence': 'not_independently_attested', 'publication_allowed': False,
                'supported_contract_versions': [1, 2],
                'contract_binding': {'cli_path': 'bin/secure_erase_cli.exe',
                                     'cli_sha256': digest(binaries['bin/secure_erase_cli.exe']),
                                     'basis': 'explicit_hash_bound_capabilities_capture_and_matching_pe_metadata'},
                'pe_identity': identities, 'manifest_self_hash_excluded': True,
                'files': [{'path': name, 'bytes': len(data), 'sha256': digest(data)} for name, data in sorted(files.items())]}
    files['release_manifest.json'] = canonical_json(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    # ZIP_STORED avoids compressor-version drift; fixed metadata makes same inputs
    # byte-identical. Write exclusivity prevents silently replacing an artifact.
    with output.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(prefix + name, (2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data)
    result = verify_runtime(output)
    output.with_name(output.name + '.sha256').write_text(result['sha256'] + '  ' + output.name + '\n', encoding='ascii')
    return result


def verify_runtime(path: Path, expected_sha256: str | None = None) -> dict:
    """Read-only integrity check; never extract, load or execute archive members."""
    checksum = digest(path.read_bytes())
    if expected_sha256 and checksum != sha(expected_sha256, 'expected_sha256'):
        raise ValueError('runtime_archive_sha256_mismatch')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) > 256 or len(set(names)) != len(names) or len({name.casefold() for name in names}) != len(names):
            raise ValueError('runtime_archive_membership_ambiguous')
        for info in archive.infolist():
            name = info.filename
            if (not name.startswith(prefix) or name.endswith('/') or '\\' in name or ':' in name
                    or '\0' in name or any(part in ('.', '..', '') for part in name.split('/'))
                    or stat.S_ISLNK(info.external_attr >> 16) or info.file_size > 256 * 1024 * 1024):
                raise ValueError('runtime_unsafe_archive_member:' + name)
        manifest = json.loads(archive.read(prefix + 'release_manifest.json'))
        if (not isinstance(manifest, dict) or manifest.get('schema') != 'windows_agent_cleanup.runtime_package.v1'
                or manifest.get('distribution_kind') != 'portable_runtime'
                or manifest.get('source_correspondence') != 'not_independently_attested'
                or manifest.get('publication_allowed') is not False
                or manifest.get('manifest_self_hash_excluded') is not True
                or manifest.get('supported_contract_versions') != [1, 2]):
            raise ValueError('runtime_manifest_contract_invalid')
        sha(manifest.get('distribution_source_commit'), 'distribution_source_commit', 40)
        listed = {entry['path']: entry for entry in manifest['files']}
        if len(listed) != len(manifest['files']) or set(names) != {prefix + name for name in listed} | {prefix + 'release_manifest.json'}:
            raise ValueError('runtime_manifest_membership_mismatch')
        for name, entry in listed.items():
            data = archive.read(prefix + name)
            if len(data) != entry['bytes'] or digest(data) != entry['sha256']:
                raise ValueError('runtime_member_bytes_mismatch:' + name)
            if name.endswith(('.cpp', '.ixx', '.ps1', '.py', '.bat', '.pdb', '.obj', '.lib')) or name.startswith(('src/', 'scripts/', 'tests/', 'build/')):
                raise ValueError('runtime_contains_development_material:' + name)
        required = {'README.md', 'README_AI.md', 'LICENSE', 'NOTICE', 'licenses/imgui_LICENSE.txt',
                    'skills/project-cleanup/SKILL.md', 'skills/project-cleanup/agents/openai.yaml'}
        required.update('skills/project-cleanup/references/' + name + '.md' for name in
                        ['bulk_cli', 'disposal_evidence', 'exceptional_operations', 'results_and_recovery', 'tool_location'])
        if not required.issubset(listed):
            raise ValueError('runtime_required_operator_material_missing')
        binding = manifest['contract_binding']
        cli_path = 'bin/secure_erase_cli.exe'
        if binding.get('cli_path') != cli_path or binding.get('cli_sha256') != listed.get(cli_path, {}).get('sha256'):
            raise ValueError('runtime_contract_binary_binding_invalid')
        for name in [cli_path, 'bin/secure_erase_gui.exe']:
            identity = pe_identity(archive.read(prefix + name))
            if identity != manifest['pe_identity'][name] or identity['application_version'] != manifest['application_version']:
                raise ValueError('runtime_pe_identity_binding_invalid')
    return {'schema': 'windows_agent_cleanup.runtime_archive_verification.v1', 'status': 'passed',
            'archive': str(path), 'sha256': checksum, 'files': len(names),
            'distribution_kind': 'portable_runtime', 'publication_allowed': False,
            'scope': 'byte integrity and supplied identity consistency; not independent build or owner acceptance'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cli', type=Path)
    parser.add_argument('--gui', type=Path)
    parser.add_argument('--provenance', type=Path)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.verify:
        if any([args.output, args.cli, args.gui, args.provenance]):
            parser.error('verify_and_package_options_are_exclusive')
        result = verify_runtime(args.verify, args.expected_sha256)
    else:
        if not all([args.output, args.cli, args.gui, args.provenance]) or args.expected_sha256:
            parser.error('output_cli_gui_provenance_are_required')
        result = build_package(Path(__file__).resolve().parents[1], args.output, args.cli, args.gui, args.provenance)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, StopIteration, UnicodeError,
            struct.error, zipfile.BadZipFile, subprocess.SubprocessError) as exception:
        print(json.dumps({'schema': 'windows_agent_cleanup.runtime_package.error.v1', 'status': 'failed',
                          'error_type': type(exception).__name__, 'error': str(exception)}), file=sys.stderr)
        raise SystemExit(2)
