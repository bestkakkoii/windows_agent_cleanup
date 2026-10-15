#!/usr/bin/env python3
"""Compile exact case-query regions against modeled SDK declaration gates; no native claim."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def region(text, start, end):
    first = text.index(start)
    return text[first:text.index(end, first)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True,
        help='Existing actual Clang C++26 module build containing vendor std BMI')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    build = args.build.resolve()
    work = build / 'case_info_contract'
    work.mkdir(exist_ok=True)
    source_paths = ['src/windows/windows_backend.cpp', 'tests/quick_delete_windows_tests.cpp']
    texts = {name:(root / name).read_text(encoding='utf-8-sig') for name in source_paths}
    backend, fixture = [texts[name] for name in source_paths]
    selectors = [region(text, '    constexpr auto case_sensitive_info_class', '#endif') + '#endif\n'
        for text in [backend, fixture]]
    assert selectors[0] == selectors[1], 'Production and native fixture selector drift'
    method = region(backend, '        result<void> process_namespace(', '        result<void> append_target(')
    fixture_call = region(fixture, '    const bool case_enabled = ', '    const DWORD case_error = ')
    assert 'continue;' not in method, 'Unknown namespace query must fail closed'
    assert backend.count('auto permitted = held ? process_namespace(*held)') == 2
    assert 'auto removed = remove_held(value, recover_access);' in backend
    entries = json.loads((build / 'compile_commands.json').read_text())
    consumer = next(entry for entry in entries if entry['file'].endswith('tests/module_interface_tests.cpp'))
    compiler = shlex.split(consumer['command'])[0]
    modmap = build / 'CMakeFiles/secure_erase_module_interface_tests.dir/tests/module_interface_tests.cpp.o.modmap'
    std_flag = next(value for value in shlex.split(modmap.read_text()) if value.startswith('-fmodule-file=std='))
    cache = (build / 'CMakeCache.txt').read_text()
    linker_flags = shlex.split(next(line.split('=', 1)[1] for line in cache.splitlines()
        if line.startswith('CMAKE_EXE_LINKER_FLAGS:STRING=')))
    commands = []
    assertions = []
    generated = []

    def invoke(name, command):
        started = datetime.now(timezone.utc).isoformat()
        run = subprocess.run(command, cwd=build, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=120)
        entry = dict(name=name, command=command, cwd=str(build), started_at=started,
            exit_code=run.returncode, stdout=run.stdout, stderr=run.stderr)
        commands.append(entry)
        return entry

    def check(name, passed):
        assertions.append(dict(test=name, passed=bool(passed)))
        assert passed, name

    declarations = r"""
import std;
using DWORD = std::uint32_t;
using HANDLE = std::uint32_t;
constexpr DWORD ERROR_NOT_SUPPORTED = 50;
constexpr DWORD ERROR_INVALID_FUNCTION = 1;
constexpr DWORD ERROR_INVALID_PARAMETER = 87;
enum FILE_INFO_BY_HANDLE_CLASS
{
    FileRenameInfoEx = MODELED_RENAME_SELECTOR,
#if NTDDI_VERSION >= NTDDI_WIN10_19H1
    FileCaseSensitiveInfo = MODELED_CASE_SELECTOR,
#endif
};
struct FILE_CASE_SENSITIVE_INFO { DWORD Flags{}; };
struct error { std::string code; DWORD native{}; };
template<class T> using result = std::expected<T, error>;
error fail(std::string code, DWORD native) { return {std::move(code), native}; }
struct held_handle { HANDLE value{}; HANDLE get() const { return value; } };
struct quick_held { std::vector<held_handle> ancestors; };
struct response { bool success; DWORD flags; DWORD native; };
std::vector<response> responses;
std::size_t query_count{};
DWORD last_error{};
bool selector_valid{true};
DWORD GetLastError() { return last_error; }
bool GetFileInformationByHandleEx(HANDLE, FILE_INFO_BY_HANDLE_CLASS selector,
    FILE_CASE_SENSITIVE_INFO* info, std::size_t length)
{
    selector_valid = selector_valid && static_cast<unsigned>(selector) == 23u &&
        length == sizeof(FILE_CASE_SENSITIVE_INFO);
    if (query_count >= responses.size()) { last_error = ERROR_INVALID_PARAMETER; return false; }
    const auto value = responses[query_count++];
    last_error = value.native;
    info->Flags = value.flags;
    return value.success;
}
bool SetFileInformationByHandle(HANDLE, FILE_INFO_BY_HANDLE_CLASS selector,
    FILE_CASE_SENSITIVE_INFO*, std::size_t length)
{
    selector_valid = selector_valid && static_cast<unsigned>(selector) == 23u &&
        length == sizeof(FILE_CASE_SENSITIVE_INFO);
    return true;
}
struct fixture_handle { HANDLE get() const { return 7; } };
constexpr HANDLE INVALID_HANDLE_VALUE = 0;
"""
    behavior = r"""
int main()
{
    std::size_t failures{};
    const auto check = [&failures](std::string_view name, bool passed)
    {
        std::println("{{\"test\":\"{}\",\"passed\":{}}}", name, passed);
        if (!passed) { ++failures; }
    };
    const auto exercise = [&check](std::string_view name, std::vector<response> values,
        bool expected, DWORD native, std::size_t calls)
    {
        responses = std::move(values); query_count = 0; last_error = 0; selector_valid = true;
        quick_held held;
        for (std::size_t index = 0; index < responses.size(); ++index)
        { held.ancestors.push_back({static_cast<HANDLE>(index + 1)}); }
        auto result = process_namespace(held);
        check(name, result.has_value() == expected && query_count == calls && selector_valid &&
            (expected || (result.error().native == native &&
                result.error().code == (native == ERROR_NOT_SUPPORTED && responses.front().success ?
                    "quick_case_sensitive_process_action_denied" : "quick_process_namespace_query_failed"))));
    };
    exercise("known_insensitive_ancestors_allowed", {{true, 0, 0}, {true, 0, 0}}, true, 0, 2);
    exercise("known_sensitive_ancestor_denied", {{true, 1, 0}, {true, 0, 0}}, false, 50, 1);
    exercise("unsupported_query_denied", {{false, 0, 50}}, false, 50, 1);
    exercise("invalid_function_query_denied", {{false, 0, ERROR_INVALID_FUNCTION}}, false, ERROR_INVALID_FUNCTION, 1);
    exercise("invalid_parameter_query_denied", {{false, 0, 87}}, false, 87, 1);
    exercise("access_denied_query_denied", {{false, 0, 5}}, false, 5, 1);
    exercise("unknown_later_ancestor_denied", {{true, 0, 0}, {false, 0, 87}}, false, 87, 2);
    check("native_fixture_uses_typed_selector", fixture_selector_probe());
    return failures == 0 ? 0 : 1;
}
"""
    for name, ntddi, case, rename, legacy, expected in [
        ('rs5_gated_symbol_absent', '0x0A000006', 23, 22, False, True),
        ('19h1_native_symbol_present', '0x0A000007', 23, 22, False, True),
        ('wrong_case_selector_rejected', '0x0A000007', 24, 22, False, False),
        ('wrong_rename_anchor_rejected', '0x0A000006', 23, 21, False, False),
        ('legacy_ungated_symbol_rejected', '0x0A000006', 23, 22, True, False)]:
        body = method.replace('case_sensitive_info_class', 'FileCaseSensitiveInfo') if legacy else method
        probe = declarations + selectors[0] + body + '\nbool fixture_selector_probe()\n{\n' + \
            '    fixture_handle case_directory; FILE_CASE_SENSITIVE_INFO case_info{};\n' + fixture_call + \
            '    return case_enabled && selector_valid;\n}\n' + behavior
        path = work / (name + '.cpp')
        path.write_text(probe, encoding='utf-8-sig')
        generated.append(dict(name=name, source_text=probe, sha256=digest(path.read_bytes())))
        output = work / name
        command = [compiler, '--driver-mode=g++', '-stdlib=libc++', '-std=c++26', '-O3', '-DNDEBUG',
            '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-Wno-reserved-module-identifier', std_flag,
            '-DNTDDI_WIN10_19H1=0x0A000007', '-DNTDDI_VERSION=' + ntddi,
            '-DMODELED_CASE_SELECTOR=' + str(case), '-DMODELED_RENAME_SELECTOR=' + str(rename),
            str(path), '-o', str(output), *linker_flags]
        compiled = invoke(name + '_compile', command)
        check(name + '_compile_expected_result', (compiled['exit_code'] == 0) == expected)
        if expected:
            execution = invoke(name + '_run', [str(output)])
            check(name + '_run_exit_zero', execution['exit_code'] == 0)
            checks = [json.loads(line) for line in execution['stdout'].splitlines() if line.strip()]
            check(name + '_expected_behavior_count', len(checks) == 8)
            for item in checks:
                check(name + '_' + item['test'], item['passed'])
        else:
            diagnostic = 'FileCaseSensitiveInfo' if legacy else 'static assertion failed'
            check(name + '_diagnostic_matches', diagnostic in compiled['stderr'])
    evidence = dict(schema='secure_erase.case_info_contract_checks.v1',
        generated_utc=datetime.now(timezone.utc).isoformat(), status='passed',
        checks=len(assertions), failed=sum(not item['passed'] for item in assertions),
        assertions=assertions, commands=commands,
        source_sha256={name:digest((root / name).read_bytes()) for name in source_paths},
        extracted_regions=dict(selector=selectors[0], process_namespace=method, native_fixture_call=fixture_call),
        harness_sources=generated, native_windows_compiled=False, native_windows_runtime_tested=False,
        actual_std_bmi=str(std_flag), vendor_std_module_emulated=False,
        scope='Exact production selector/process_namespace and native fixture selector call compiled/run with actual Clang C++26/vendor std BMI against deliberately modeled Win32 declarations. Old/new NTDDI visibility and ABI mismatch rejection are modeled regression evidence, not Windows SDK/MSVC compilation or native filesystem/process behavior.')
    evidence['source_sha256']['scripts/verify_case_info.py'] = digest(Path(__file__).read_bytes())
    path = root / 'reports/case_info_contract_checks.json'
    path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), checks=evidence['checks'], failed=evidence['failed'])))


if __name__ == '__main__':
    main()
