"""Run current source/contract checks and optional existing native-module tests.

Evidence is per invocation. Diagnostics live outside tracked sources. This script
never executes a production deletion command or downloads dependencies.
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
import xml.etree.ElementTree as xml


def execute(command: list[str], root: Path, directory: Path, name: str) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    run = subprocess.run(command, cwd=root, capture_output=True, timeout=1200)
    (directory / (name + '.stdout.log')).write_bytes(run.stdout)
    (directory / (name + '.stderr.log')).write_bytes(run.stderr)
    return {'name': name, 'command': command, 'started_at': started,
            'exit_code': run.returncode, 'status': 'passed' if run.returncode == 0 else 'failed',
            'stdout': str(directory / (name + '.stdout.log')),
            'stderr': str(directory / (name + '.stderr.log'))}


def files(root: Path) -> list[Path]:
    run = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                         cwd=root, check=True, capture_output=True)
    return sorted({root / os.fsdecode(name) for name in run.stdout.split(b'\0') if name})


def check_sources(root: Path) -> tuple[list[dict], list[dict]]:
    problems = []
    snapshots = []
    forbidden = {'build', 'build_logs', 'reports', 'out', 'dist', 'third_party', '__pycache__', '.git'}
    bom_suffixes = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.inc', '.inl', '.ipp', '.tpp',
                    '.ixx', '.cppm', '.md', '.py', '.ps1', '.cmake', '.rc', '.manifest', '.svg'}
    host_exceptions = {'.gitignore', '.gitattributes', '.editorconfig', 'LICENSE'}
    for path in files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        snapshots.append({'path': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        def error(code: str) -> None:
            problems.append({'code': code, 'path': relative})
        if any(part in forbidden for part in path.relative_to(root).parts) or path.suffix in {'.zip', '.log', '.pyc', '.pdb', '.obj', '.exe', '.dll'}:
            error('unmaintained_output_in_source_set')
        if path.name in host_exceptions or path.suffix in {'.ico', '.png'}:
            continue
        if path.suffix == '.json':
            try:
                json.loads(data.decode('utf-8'))
            except (ValueError, UnicodeError):
                error('json_invalid_or_bom')
        elif path.suffix in {'.yaml', '.yml', '.jsonl'}:
            try:
                data.decode('utf-8')
                if data.startswith(b'\xef\xbb\xbf'):
                    error('machine_format_requires_utf8_without_bom')
            except UnicodeError:
                error('text_invalid_utf8')
        elif path.suffix == '.bat':
            if any(byte > 127 for byte in data) or b'\n' in data.replace(b'\r\n', b''):
                error('bat_requires_ascii_crlf')
        elif path.suffix in bom_suffixes or path.name in {'CMakeLists.txt', 'NOTICE'}:
            # Skill frontmatter parsers require the first line exactly ---.
            if path.name != 'SKILL.md' and not data.startswith(b'\xef\xbb\xbf'):
                error('authored_text_requires_utf8_bom')
            try:
                data.decode('utf-8-sig')
            except UnicodeError:
                error('text_invalid_utf8')
    for path in (root / 'scripts').glob('*.py'):
        try:
            compile(path.read_bytes(), str(path), 'exec')
        except SyntaxError as exception:
            problems.append({'code': 'python_syntax_error', 'path': path.relative_to(root).as_posix(),
                             'line': exception.lineno, 'message': exception.msg})
    lock = json.loads((root / 'dependencies.lock.json').read_text(encoding='utf-8-sig'))
    for dependency in lock.get('dependencies', []):
        if len(dependency.get('commit', '')) != 40:
            problems.append({'code': 'dependency_commit_missing', 'dependency': dependency.get('name')})
        for entry in dependency.get('files', []):
            if len(entry.get('sha256', '')) != 64:
                problems.append({'code': 'dependency_hash_missing', 'path': entry.get('path')})
    return problems, snapshots


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--cmake', default='cmake')
    parser.add_argument('--ctest', default='ctest')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    commands = []
    problems, snapshot = check_sources(root)
    source_check = {'name': 'source_integrity', 'status': 'failed' if problems else 'passed',
                    'violations': problems}
    commands.append(source_check)
    commands.append(execute([sys.executable, str(root / 'scripts/verify_modules.py'), '--root', str(root),
                             '--output', str(directory / 'module_contract.json')], root, directory, 'module_contract'))
    runtime = {'status': 'not_run', 'reason': 'build_directory_not_supplied'}
    if args.build_dir:
        build = args.build_dir.resolve()
        if not args.skip_build:
            commands.append(execute([args.cmake, '--build', str(build), '--config', 'Release', '--parallel',
                                     str(min(8, os.cpu_count() or 1))], root, directory, 'build'))
        if not any(item['status'] == 'failed' for item in commands):
            junit = directory / 'ctest.xml'
            entry = execute([args.ctest, '--test-dir', str(build), '-C', 'Release', '--output-on-failure',
                             '--output-junit', str(junit), '-LE', 'destructive'], root, directory, 'ctest')
            commands.append(entry)
            runtime = {'status': entry['status'], 'cases': 0, 'skipped': 0, 'failures': 0}
            if junit.is_file():
                tree = xml.parse(junit)
                cases = tree.findall('.//testcase')
                runtime.update(cases=len(cases), skipped=sum(item.find('skipped') is not None for item in cases),
                               failures=sum(item.find('failure') is not None or item.find('error') is not None for item in cases))
                if not cases or runtime['failures'] or runtime['skipped']:
                    runtime['status'] = 'failed' if not cases or runtime['failures'] else 'not_run'
    passed = all(item['status'] == 'passed' for item in commands)
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
    except subprocess.CalledProcessError:
        commit = None
    report = {'schema': 'windows_agent_cleanup.validation.v2', 'generated_at': datetime.now(timezone.utc).isoformat(),
              'source_commit': commit, 'source_snapshot': snapshot, 'checks': commands, 'runtime': runtime,
              'host': {'platform': sys.platform, 'python': sys.version},
              'source_checks_passed': passed, 'test_source_eligible': passed and runtime['status'] == 'passed',
              'distribution_kind': 'development_test_source',
              'version': '2.0.0-dev.1', 'status': 'unpublished_development_test_source',
              'publication_allowed': False, 'owner_acceptance': 'not_received',
              'source_rc_eligible': False, 'release_eligible': False,
              'native_windows': {'status': 'safe_tests_passed' if sys.platform == 'win32' and runtime['status'] == 'passed' else 'not_run',
                                 'scope': 'this host safe test executables only; import build/isolated/GUI/hardware evidence separately'},
              'hardware_matrix': {'status': 'not_run', 'owner': 'user'},
              'physical_sanitization_guaranteed': False}
    report_path = directory / 'validation_report.json'
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'passed' if passed else 'failed', 'report': str(report_path),
                      'runtime': runtime, 'test_source_eligible': report['test_source_eligible'],
                      'publication_allowed': False, 'owner_acceptance': 'not_received',
                      'source_rc_eligible': False, 'release_eligible': False}))
    return 0 if passed and (not args.build_dir or runtime['status'] == 'passed') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError, xml.ParseError) as exception:
        print(json.dumps({'schema': 'windows_agent_cleanup.validation.error.v1', 'error_type': type(exception).__name__,
                          'message': str(exception)}), file=sys.stderr)
        raise SystemExit(2)
