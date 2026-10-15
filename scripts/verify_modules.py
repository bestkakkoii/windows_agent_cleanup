"""Check actual owned C++ module architecture; this is not a compiler substitute.

Public API: verify_project(root: str | pathlib.Path) -> JSON-serializable dict.
CLI: python scripts/verify_modules.py [--root PATH] [--output PATH]
Exit status: 0 clean, 1 source architecture violation, 2 invocation/IO error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys


source_suffixes = frozenset({".cpp", ".ixx", ".cppm", ".cxx", ".cc"})
header_suffixes = frozenset({".h", ".hpp", ".hxx", ".hh"})
required_modules = frozenset({
    "secure_erase.crypto", "secure_erase.model", "secure_erase.configuration",
    "secure_erase.platform", "secure_erase.plan", "secure_erase.engine",
    "secure_erase.codec", "secure_erase.quick_delete", "secure_erase.cli_arguments", "secure_erase.metadata",
    "secure_erase.retained_copies", "secure_erase.windows_backend",
    "secure_erase.state_store", "secure_erase.application",
    "secure_erase.engine:admission", "secure_erase.engine:execution",
})
# CONTRACT: These are external C/OS/vendor APIs, never a route to textual C++
# standard-library or project headers. stddef.h supplies the C offsetof macro
# required by Win32 ABI structures; import std cannot provide preprocessor macros.
external_includes = {
    "src/cli/main.cpp": {"windows.h", "bcrypt.h"},
    "src/app/application.cpp": {"windows.h", "bcrypt.h"},
    "src/gui/main.cpp": {
        "windows.h", "d3d11.h", "shellapi.h", "shobjidl.h", "wrl/client.h",
        "imgui.h", "imgui_impl_dx11.h", "imgui_impl_win32.h",
    },
    "src/windows/backend_locks.cpp": {"windows.h", "restartmanager.h", "winsvc.h"},
    "src/windows/windows_backend.cpp": {
        "windows.h", "aclapi.h", "bcrypt.h", "sfc.h", "winioctl.h", "winsvc.h", "stddef.h", "psapi.h", "pdh.h",
    },
    "src/windows/state_store.cpp": {
        "windows.h", "aclapi.h", "bcrypt.h", "dpapi.h", "sddl.h", "shlobj.h",
    },
    "src/windows/retained_copies.cpp": {"windows.h", "vss.h", "vswriter.h", "vsbackup.h"},
    "tests/windows_backend_tests.cpp": {"windows.h"},
    "tests/quick_delete_windows_tests.cpp": {"windows.h", "aclapi.h", "sddl.h", "winioctl.h", "stddef.h"},
    "tests/state_store_windows_tests.cpp": {"windows.h", "bcrypt.h", "winioctl.h"},
    "tests/quick_delete_integration_tests.cpp": {
        "errno.h", "fcntl.h", "stdio.h", "stdlib.h", "sys/file.h", "sys/stat.h", "unistd.h",
    },
    "tests/portable_integration_tests.cpp": {
        "errno.h", "fcntl.h", "stdio.h", "stdlib.h", "sys/file.h", "sys/stat.h", "unistd.h",
    },
}
name = r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*"
module_re = re.compile(rf"^\s*(export\s+)?module\s+({name}(?::{name})?)\s*;\s*$")
import_re = re.compile(rf"^\s*(export\s+)?import\s+(:?{name}(?::{name})?)\s*;\s*$")
global_re = re.compile(r"^\s*module\s*;\s*$")
include_re = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]\s*$')
directive_re = re.compile(r"^\s*#\s*(\w+)")


def _mask(source: str, strings: bool) -> str:
    """Preserve offsets/newlines while masking comments and optionally literals.

    Literal handling includes ordinary strings/chars and C++ raw-string delimiters.
    Preprocessor expressions are intentionally not executed: imports inside a
    conditional branch are rejected, rather than pretending to compile that branch.
    """
    output = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if source[position] not in "\r\n":
                output[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index)
            if end == -1:
                end = length
            blank(index, end)
            index = end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            blank(index, end)
            index = end
        elif source.startswith('R"', index):
            opening = source.find("(", index + 2, min(length, index + 20))
            if opening == -1:
                index += 1
                continue
            delimiter = source[index + 2:opening]
            ending = ")" + delimiter + '"'
            end = source.find(ending, opening + 1)
            end = length if end == -1 else end + len(ending)
            if strings:
                blank(index, end)
            index = end
        elif source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                elif source[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            end = min(end, length)
            if strings:
                blank(index, end)
            index = end
        else:
            index += 1
    return "".join(output)


def _cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for dependency in sorted(graph.get(node, set())):
            if state.get(dependency, 0) == 0:
                visit(dependency)
            elif state.get(dependency) == 1:
                cycle = stack[stack.index(dependency):] + [dependency]
                canonical = tuple(sorted(cycle[:-1]))
                if canonical not in seen:
                    cycles.append(cycle)
                    seen.add(canonical)
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state.get(node, 0) == 0:
            visit(node)
    return cycles


def verify_project(root: str | Path) -> dict:
    root = Path(root).resolve()
    violations: list[dict] = []
    units: list[dict] = []
    providers: dict[str, list[str]] = {}
    snapshot: dict[str, str] = {}

    def violation(code: str, path: str, line: int = 0, **details) -> None:
        violations.append({"code": code, "path": path, "line": line, **details})

    source_paths: list[Path] = []
    header_paths: list[Path] = []
    for directory in ("src", "tests", "include"):
        base = root / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in source_suffixes:
                source_paths.append(path)
            elif path.suffix.lower() in header_suffixes:
                header_paths.append(path)
    for path in sorted(header_paths):
        name = path.relative_to(root).as_posix()
        snapshot[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        violation("owned_header_forbidden", name)
    if not source_paths:
        violation("owned_sources_missing", "src")

    for path in sorted(source_paths):
        name = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        snapshot[name] = hashlib.sha256(raw).hexdigest()
        if not raw.startswith(b"\xef\xbb\xbf"):
            violation("utf8_bom_missing", name)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            violation("source_not_utf8", name, byte_offset=error.start)
            continue
        code = _mask(text, strings=True)
        comments_removed = _mask(text, strings=False)
        code_lines = code.splitlines()
        literal_lines = comments_removed.splitlines()
        declarations = []
        imports = []
        includes = []
        globals_ = []
        conditional_depth = 0
        for line_number, line in enumerate(code_lines, 1):
            literal_line = literal_lines[line_number - 1]
            directive = directive_re.match(line)
            if directive:
                command = directive.group(1)
                if command in {"if", "ifdef", "ifndef"}:
                    conditional_depth += 1
                elif command == "endif":
                    conditional_depth -= 1
                    if conditional_depth < 0:
                        violation("unbalanced_preprocessor_condition", name, line_number)
                        conditional_depth = 0
                elif command == "include":
                    included = include_re.match(literal_line)
                    if included is None:
                        violation("nonliteral_or_unreviewed_include", name, line_number)
                    else:
                        header = included.group(2)
                        includes.append({"header": header, "line": line_number})
                        if header.lower() not in external_includes.get(name, set()):
                            violation("external_include_not_allowlisted", name, line_number, header=header)
                continue
            declaration = module_re.match(line)
            imported = import_re.match(line)
            if declaration:
                declarations.append({"name": declaration.group(2), "exported": bool(declaration.group(1)), "line": line_number})
            elif imported:
                imports.append({"spelling": imported.group(2), "exported": bool(imported.group(1)), "line": line_number})
            elif global_re.match(line):
                globals_.append(line_number)
            elif re.match(r"^\s*(?:export\s+)?import\b", line):
                violation("header_unit_or_unparsed_import_forbidden", name, line_number)
            elif re.match(r"^\s*(?:export\s+)?module\b", line):
                violation("unparsed_module_declaration", name, line_number)
            if conditional_depth and (declaration or imported):
                violation("conditional_module_path_forbidden", name, line_number)
        if conditional_depth:
            violation("unbalanced_preprocessor_condition", name)
        if len(declarations) > 1:
            violation("multiple_module_declarations", name)
        if len(globals_) > 1:
            violation("multiple_global_module_fragments", name)
        declaration = declarations[0] if declarations else None
        owner = declaration["name"] if declaration else None
        interface = bool(declaration and declaration["exported"])
        partition = bool(owner and ":" in owner)
        kind = "primary_interface" if interface and not partition else "implementation_partition" if partition else "implementation_unit" if owner else "importing_translation_unit"
        if path.suffix.lower() in {".ixx", ".cppm"} and not interface:
            violation("interface_file_without_exported_module", name)
        if owner and not owner.startswith("secure_erase."):
            violation("nonproject_or_fake_standard_module_provider", name, declaration["line"], module=owner)
        if name.startswith("src/") and owner is None and name not in {"src/gui/main.cpp", "src/cli/main.cpp"}:
            violation("product_implementation_without_module_owner", name)
        if owner and name.startswith("tests/"):
            violation("test_defines_product_module", name)
        if partition and interface:
            violation("implementation_partition_must_remain_private", name)
        if interface:
            if includes:
                violation("module_interface_textual_include_forbidden", name)
            if not re.search(r"\bexport\s+namespace\b", code):
                violation("interface_lacks_owned_exported_declarations", name)
        if re.search(r"\bmodule_api\b", code):
            violation("legacy_forwarding_facade_forbidden", name)
        if sum(item["spelling"] == "std" for item in imports) != 1:
            violation("exactly_one_vendor_std_import_required", name)
        first_import = min((item["line"] for item in imports), default=10**9)
        if owner:
            if globals_ and globals_[0] > declaration["line"]:
                violation("global_fragment_after_named_module", name)
            if first_import < declaration["line"]:
                violation("import_before_named_module_declaration", name)
            if includes and (not globals_ or globals_[0] > min(item["line"] for item in includes)):
                violation("external_header_outside_global_module_fragment", name)
        elif globals_:
            violation("global_fragment_without_named_module", name)
        for included in includes:
            if included["line"] > first_import or (owner and included["line"] > declaration["line"]):
                violation("external_header_after_module_or_import", name, included["line"], header=included["header"])
        if interface or partition:
            providers.setdefault(owner, []).append(name)
        units.append({"path": name, "sha256": snapshot[name], "kind": kind,
                      "owner": owner, "declaration_line": declaration["line"] if declaration else None,
                      "global_fragment_lines": globals_, "imports": imports,
                      "external_includes": includes})

    for module, paths in sorted(providers.items()):
        if len(paths) != 1:
            violation("duplicate_module_provider", paths[0], module=module, providers=paths)
    for module in sorted(required_modules - providers.keys()):
        violation("required_module_provider_missing", "src", module=module)
    owned_graph = {module: set() for module in providers}
    exported_graph = {module: set() for module in providers}
    for unit in units:
        owner = unit["owner"]
        if owner and owner not in providers:
            violation("implementation_has_no_primary_provider", unit["path"], module=owner)
        for imported in unit["imports"]:
            spelling = imported["spelling"]
            if spelling == "std":
                imported["resolved"] = "std"
                continue
            if spelling.startswith(":"):
                if owner is None:
                    violation("relative_partition_import_without_owner", unit["path"], imported["line"])
                    continue
                resolved = owner.split(":", 1)[0] + spelling
            else:
                resolved = spelling
            imported["resolved"] = resolved
            if resolved not in providers:
                violation("unresolved_project_module_import", unit["path"], imported["line"], module=resolved)
                continue
            if ":" in resolved:
                same_owner = owner is not None and owner.split(":", 1)[0] == resolved.split(":", 1)[0]
                if not same_owner or imported["exported"] or unit["kind"] == "primary_interface":
                    violation("private_partition_boundary_breach", unit["path"], imported["line"], module=resolved)
            if owner:
                if owner == resolved:
                    violation("explicit_self_import", unit["path"], imported["line"], module=owner)
                else:
                    owned_graph.setdefault(owner, set()).add(resolved)
                    if imported["exported"]:
                        exported_graph.setdefault(owner, set()).add(resolved)
    owned_cycles = _cycles(owned_graph)
    export_cycles = _cycles(exported_graph)
    for cycle in owned_cycles:
        violation("owned_module_dependency_cycle", "src", cycle=cycle)
    for cycle in export_cycles:
        violation("exported_module_dependency_cycle", "src", cycle=cycle)

    for path in sorted([root / "CMakeLists.txt", *root.glob("cmake/*.cmake")]):
        if path.is_file():
            snapshot[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    own_script = root / "scripts/verify_modules.py"
    if own_script.is_file():
        snapshot["scripts/verify_modules.py"] = hashlib.sha256(own_script.read_bytes()).hexdigest()
    combined = "".join(f"{name}\0{digest}\n" for name, digest in sorted(snapshot.items()))
    return {
        "schema": "secure_erase.module_architecture_checks.v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "passed" if not violations else "failed",
        "scope": "static checks of actual owned source files; not compiler or runtime evidence",
        "compiler_validation_claimed": False,
        "limitations": [
            "Lexical ownership/import checks do not replace C++ name lookup, ABI, ODR or compiler validation.",
            "Conditional module routes are rejected; preprocessing expressions are not executed.",
            "Vendor std implementation and third-party source are outside the owned-source tree.",
        ],
        "counts": {"source_units": len(units), "primary_modules": sum(":" not in key for key in providers),
                   "private_partitions": sum(":" in key for key in providers),
                   "owned_headers": len(header_paths), "violations": len(violations)},
        "module_providers": {key: value for key, value in sorted(providers.items())},
        "units": units,
        "owned_dependency_graph": {key: sorted(value) for key, value in sorted(owned_graph.items())},
        "exported_dependency_graph": {key: sorted(value) for key, value in sorted(exported_graph.items())},
        "owned_dependency_cycles": owned_cycles,
        "exported_dependency_cycles": export_cycles,
        "external_api_include_allowlist": {key: sorted(value) for key, value in sorted(external_includes.items())},
        "violations": violations,
        "hash_snapshot": {key: value for key, value in sorted(snapshot.items())},
        "hash_snapshot_sha256": hashlib.sha256(combined.encode("utf-8")).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(argv)
    try:
        root = options.root.resolve()
        report = verify_project(root)
        output = options.output or root / "reports/module_architecture_checks.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(json.dumps({"schema": "secure_erase.module_architecture_checks.error.v1", "error": str(error)}))
        return 2
    print(json.dumps({"status": report["status"], "counts": report["counts"],
                      "report": str(output.resolve()), "hash_snapshot_sha256": report["hash_snapshot_sha256"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
