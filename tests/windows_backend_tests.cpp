// INTEROP: This executable consumer imports project APIs; only Windows C declarations are textual.
#include <Windows.h>

import std;
import secure_erase.model;
import secure_erase.platform;
import secure_erase.windows_backend;

namespace
{
    using namespace secure_erase::engine;

    struct fixture_tree
    {
        std::filesystem::path root;
        ~fixture_tree()
        {
            // CONTRACT: root is generated with CREATE_NEW-like CreateDirectory and never supplied
            // by caller. Standard remove_all removes symlinks themselves, never their targets.
            if (root.empty())
            {
                return;
            }
            std::error_code ignored;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root,
                std::filesystem::directory_options::skip_permission_denied, ignored))
            {
                SetFileAttributesW(entry.path().c_str(), FILE_ATTRIBUTE_NORMAL);
            }
            std::filesystem::remove_all(root, ignored);
        }
    };

    std::string path_text(const std::filesystem::path& path)
    {
        const auto value = path.u8string();
        return std::string(reinterpret_cast<const char*>(value.data()), value.size());
    }

    bool create_fixture(const std::filesystem::path& path, std::size_t size = 8193)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const std::vector<std::byte> content(size, std::byte{0x5a});
        DWORD written{};
        const bool okay = WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) &&
            written == content.size() && FlushFileBuffers(file);
        CloseHandle(file);
        return okay;
    }

    bool check(bool passed, const char* code)
    {
        std::printf("{\"test\":\"%s\",\"status\":\"%s\",\"native_code\":%lu}\n",
            code, passed ? "passed" : "failed", static_cast<unsigned long>(GetLastError()));
        return passed;
    }

    bool host_readiness_observed()
    {
        const auto observed = inspect_host_readiness();
        TOKEN_ELEVATION elevation{};
        DWORD returned{};
        const bool token_known = GetTokenInformation(GetCurrentThreadEffectiveToken(), TokenElevation,
            &elevation, sizeof(elevation), &returned) && returned >= sizeof(elevation);
        const bool privilege_agrees = token_known ?
            observed.elevated == (elevation.TokenIsElevated != 0) && !observed.elevation_error :
            !observed.elevated && observed.elevation_error.has_value();
        const bool platform_known = observed.windows_build && !observed.platform_error &&
            !observed.architecture_error && observed.native_architecture != host_architecture::unknown &&
            observed.process_architecture != host_architecture::unknown;
        const bool expected_supported = observed.windows_build && *observed.windows_build >= 22000 &&
            observed.native_architecture == host_architecture::x64 &&
            observed.process_architecture == host_architecture::x64;
        bool passed = check(observed.required_windows_build == 22000 &&
            observed.required_native_architecture == host_architecture::x64 &&
            observed.required_process_architecture == host_architecture::x64 && platform_known &&
            observed.platform_supported == expected_supported, "host_readiness_build_and_architecture_observed");
        passed &= check(privilege_agrees, "host_readiness_effective_elevation_observed");
        const auto expected_ready = expected_supported && token_known && elevation.TokenIsElevated != 0;
        passed &= check(observed.filesystem_commands_ready == expected_ready,
            "host_readiness_derived_without_path_admission");
        return passed;
    }

    std::optional<BY_HANDLE_FILE_INFORMATION> read_unchanged_fixture(const std::filesystem::path& path)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return std::nullopt;
        }
        BY_HANDLE_FILE_INFORMATION information{};
        std::array<std::byte, 8193> content{};
        DWORD read{};
        const bool valid = GetFileInformationByHandle(file, &information) &&
            information.nFileSizeHigh == 0 && information.nFileSizeLow == content.size() &&
            ReadFile(file, content.data(), static_cast<DWORD>(content.size()), &read, nullptr) &&
            read == content.size() && std::ranges::all_of(content, [](std::byte value)
            {
                return value == std::byte{0x5a};
            });
        CloseHandle(file);
        return valid ? std::optional(information) : std::nullopt;
    }

    bool same_fixture_metadata(const BY_HANDLE_FILE_INFORMATION& left, const BY_HANDLE_FILE_INFORMATION& right)
    {
        return left.dwFileAttributes == right.dwFileAttributes &&
            left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
            left.nFileIndexHigh == right.nFileIndexHigh && left.nFileIndexLow == right.nFileIndexLow &&
            left.nNumberOfLinks == right.nNumberOfLinks &&
            left.nFileSizeHigh == right.nFileSizeHigh && left.nFileSizeLow == right.nFileSizeLow &&
            left.ftCreationTime.dwHighDateTime == right.ftCreationTime.dwHighDateTime &&
            left.ftCreationTime.dwLowDateTime == right.ftCreationTime.dwLowDateTime &&
            left.ftLastWriteTime.dwHighDateTime == right.ftLastWriteTime.dwHighDateTime &&
            left.ftLastWriteTime.dwLowDateTime == right.ftLastWriteTime.dwLowDateTime;
    }

    bool overwrite_fixture(platform& backend, const target_snapshot& snapshot, bool remove)
    {
        auto held = backend.acquire(snapshot);
        if (!held)
        {
            std::printf("{\"event\":\"acquire_failed\",\"code\":\"%s\",\"native_code\":%u}\n",
                held.error().code.c_str(), held.error().native_code);
            return false;
        }
        for (const auto& stream : snapshot.streams)
        {
            std::vector<std::byte> desired(static_cast<std::size_t>(stream.size), std::byte{0xa6});
            auto written = (*held)->write(stream.name, 0, desired);
            if (!written || *written != desired.size() || !(*held)->flush(stream.name))
            {
                return false;
            }
            auto checkpoint = (*held)->checkpoint_snapshot();
            if (!checkpoint)
            {
                return false;
            }
            // Existing data handles must remain usable after checkpoint restores READONLY.
            auto rewritten = (*held)->write(stream.name, 0, desired);
            if (!rewritten || *rewritten != desired.size() || !(*held)->flush(stream.name))
            {
                return false;
            }
            std::vector<std::byte> actual(desired.size());
            auto read = (*held)->read(stream.name, 0, actual);
            if (!read || *read != actual.size() || actual != desired)
            {
                return false;
            }
        }
        if (remove)
        {
            auto deleted = (*held)->remove();
            if (!deleted)
            {
                std::printf("{\"event\":\"remove_failed\",\"code\":\"%s\",\"native_code\":%u}\n",
                    deleted.error().code.c_str(), deleted.error().native_code);
                return false;
            }
        }
        return true;
    }

    struct module_fixture
    {
        HMODULE value{};
        ~module_fixture()
        {
            if (value != nullptr)
            {
                FreeLibrary(value);
            }
        }
    };

    std::optional<std::filesystem::path> executable_path()
    {
        std::array<wchar_t, 32768> buffer{};
        const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size())
        {
            return {};
        }
        return std::filesystem::path(std::wstring_view(buffer.data(), length));
    }

    bool copied_self_protection_fixture()
    {
        namespace quick = secure_erase::quick;
        const auto executable = executable_path();
        if (!executable || executable->filename() != L"self_protection_fixture.exe" ||
            executable->parent_path().filename() != L"runtime_fixture" ||
            !executable->parent_path().parent_path().filename().wstring().starts_with(L"secure_erase_isolated_"))
        {
            return check(false, "copied_runtime_fixture_location_required");
        }
        const auto runtime = executable->parent_path();
        const auto root = runtime.parent_path();
        const auto state = root / L"state";
        if (!CreateDirectoryW(state.c_str(), nullptr))
        {
            return check(false, "copied_runtime_private_state_created");
        }
        std::array<wchar_t, 32768> system{};
        const auto system_length = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
        const auto dependency = runtime / L"runtime_dependency.dll";
        if (system_length == 0 || system_length >= system.size() ||
            !CopyFileW((std::filesystem::path(system.data()) / L"version.dll").c_str(), dependency.c_str(), TRUE))
        {
            return check(false, "copied_runtime_dependency_created");
        }
        module_fixture loaded{LoadLibraryExW(dependency.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
        if (loaded.value == nullptr)
        {
            return check(false, "copied_runtime_dependency_loaded");
        }
        const auto executable_alias = runtime / L"executable_alias.bin";
        const auto dependency_alias = runtime / L"dependency_alias.bin";
        const bool executable_linked = CreateHardLinkW(executable_alias.c_str(), executable->c_str(), nullptr) != FALSE;
        const bool dependency_linked = CreateHardLinkW(dependency_alias.c_str(), dependency.c_str(), nullptr) != FALSE;
        auto made = make_windows_quick_backend(state.wstring());
        if (!made)
        {
            return check(false, "copied_runtime_quick_backend_created");
        }
        auto& backend = **made;
        control controls;
        bool passed = true;
        const auto denied = [&](const std::filesystem::path& path, std::string_view code)
        {
            auto targets = backend.prepare({path_text(path)}, controls);
            return targets && targets->size() == 1 && targets->front().preparation_error.code == code &&
                !targets->front().type_known && !targets->front().logical_size_known;
        };
        passed &= check(denied(*executable, "quick_running_image"), "running_executable_name_protected");
        passed &= check(denied(dependency, "quick_running_image"), "loaded_dependency_name_protected");
        passed &= check(denied(runtime, "quick_running_image_ancestor"), "running_executable_parent_protected");
        passed &= check(denied(root, "quick_running_image_ancestor"), "running_executable_ancestor_protected");
        passed &= check(denied(state, "quick_protected_resource_tree"), "state_tree_protection_unchanged");
        if (executable_linked && dependency_linked)
        {
            passed &= check(denied(executable_alias, "quick_running_image") &&
                denied(dependency_alias, "quick_running_image"), "running_image_hardlink_identities_protected");
        }
        else
        {
            std::puts("{\"test\":\"running_image_hardlink_identities_protected\",\"status\":\"not_run\",\"reason\":\"filesystem_has_no_hardlinks\"}");
        }
        const auto sibling = runtime / L"CMakeCache.fixture";
        const auto directory = runtime / L"CMakeFiles.fixture";
        passed &= check(create_fixture(sibling) && CreateDirectoryW(directory.c_str(), nullptr) &&
            create_fixture(directory / L"generated.fixture"), "unrelated_same_directory_siblings_created");
        auto prepared = backend.prepare({path_text(sibling), path_text(directory)}, controls);
        const bool admitted = prepared && prepared->size() == 3 &&
            std::ranges::all_of(*prepared, [](const auto& target)
            {
                return target.preparation_error.code.empty();
            });
        passed &= check(admitted, "unrelated_same_directory_file_and_subtree_admitted");
        if (admitted)
        {
            passed &= check(std::ranges::all_of(*prepared, [](const auto& target)
            {
                return target.type_known && target.logical_size_known &&
                    target.logical_size_bytes == (target.directory ? 0 : 8193);
            }), "quick_snapshot_logical_eof_and_directory_zero_known");
            auto frozen = quick::freeze("0123456789abcdef0123456789abcdef", std::move(*prepared));
            auto removed = frozen ? quick::run(*frozen, frozen->fingerprint, true, backend, controls, {1, true}) :
                result<run_report>(std::unexpected(frozen.error()));
            passed &= check(removed && removed->status == "completed" &&
                GetFileAttributesW(sibling.c_str()) == INVALID_FILE_ATTRIBUTES &&
                GetFileAttributesW(directory.c_str()) == INVALID_FILE_ATTRIBUTES &&
                GetFileAttributesW(executable->c_str()) != INVALID_FILE_ATTRIBUTES &&
                GetFileAttributesW(dependency.c_str()) != INVALID_FILE_ATTRIBUTES,
                "unrelated_same_directory_quick_delete_preserves_running_images");
        }
        const auto late_dependency = runtime / L"late_dependency.dll";
        passed &= check(CopyFileW((std::filesystem::path(system.data()) / L"version.dll").c_str(),
            late_dependency.c_str(), TRUE) != FALSE, "late_runtime_dependency_created");
        auto late_targets = backend.prepare({path_text(late_dependency)}, controls);
        const bool late_admitted = late_targets && late_targets->size() == 1 &&
            late_targets->front().preparation_error.code.empty();
        passed &= check(late_admitted, "unloaded_same_directory_dependency_admitted");
        module_fixture late_loaded{LoadLibraryExW(late_dependency.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
        passed &= check(late_loaded.value != nullptr, "dependency_loaded_after_preview");
        if (late_admitted && late_loaded.value != nullptr)
        {
            auto frozen = quick::freeze("1123456789abcdef0123456789abcdef", std::move(*late_targets));
            auto refused = frozen ? quick::run(*frozen, frozen->fingerprint, true, backend, controls, {1, true}) :
                result<run_report>(std::unexpected(frozen.error()));
            passed &= check(refused && refused->status == "partial_failure" && refused->targets.size() == 1 &&
                !refused->targets.front().deleted && GetFileAttributesW(late_dependency.c_str()) != INVALID_FILE_ATTRIBUTES,
                "execution_refresh_protects_dependency_loaded_after_preview");
        }
        const auto overwrite = runtime / L"overwrite_sibling.fixture";
        passed &= check(create_fixture(overwrite), "unrelated_same_directory_overwrite_fixture_created");
        auto platform = make_windows_platform(state.wstring());
        if (!platform)
        {
            return check(false, "copied_runtime_overwrite_backend_created");
        }
        auto overwrite_plan = (*platform)->preview({path_text(overwrite)});
        if (!overwrite_plan && (overwrite_plan.error().code == "storage_media_unknown" ||
            overwrite_plan.error().code == "storage_bus_unknown_or_virtual" ||
            overwrite_plan.error().code == "physical_disk_topology_unknown" ||
            overwrite_plan.error().code == "multi_disk_volume_unsupported"))
        {
            // CONTRACT: Quick protection regression runs even when this host's
            // storage cannot supply a successful overwrite hardware assertion.
            std::printf("{\"test\":\"unrelated_same_directory_overwrite_allowed\",\"status\":\"not_run\",\"reason\":\"%s\"}\n",
                overwrite_plan.error().code.c_str());
        }
        else
        {
            if (overwrite_plan && overwrite_plan->size() == 1 &&
                overwrite_plan->front().support == capability::delete_only)
            {
                std::puts("{\"test\":\"unrelated_same_directory_overwrite_allowed\",\"status\":\"not_run\",\"reason\":\"ordinary_overwrite_fixture_not_supported\"}");
            }
            else
            {
                passed &= check(overwrite_plan && overwrite_plan->size() == 1 &&
                    overwrite_plan->front().support != capability::blocked &&
                    overwrite_fixture(**platform, overwrite_plan->front(), true),
                    "unrelated_same_directory_overwrite_allowed");
            }
            auto protected_plan = (*platform)->preview({path_text(*executable)});
            passed &= check(protected_plan && protected_plan->size() == 1 &&
                protected_plan->front().support == capability::blocked &&
                std::ranges::find(protected_plan->front().protection_reasons, "running_image") !=
                    protected_plan->front().protection_reasons.end(), "overwrite_running_image_protected");
        }
        return passed;
    }

    bool launch_copied_self_protection_fixture(const fixture_tree& tree)
    {
        const auto source = executable_path();
        const auto runtime = tree.root / L"runtime_fixture";
        const auto copied = runtime / L"self_protection_fixture.exe";
        if (!source || !CreateDirectoryW(runtime.c_str(), nullptr) ||
            !CopyFileW(source->c_str(), copied.c_str(), TRUE))
        {
            return check(false, "self_protection_child_created");
        }
        std::wstring command = L"\"" + copied.wstring() + L"\" --run-copied-self-protection-fixture";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION child{};
        if (!CreateProcessW(copied.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
            runtime.c_str(), &startup, &child))
        {
            return check(false, "self_protection_child_started");
        }
        CloseHandle(child.hThread);
        const auto waited = WaitForSingleObject(child.hProcess, 120000);
        DWORD exit_code{};
        const bool completed = waited == WAIT_OBJECT_0 && GetExitCodeProcess(child.hProcess, &exit_code);
        if (!completed)
        {
            // TEST HARNESS: Only the disposable child created above is stopped.
            // No product process-recovery API or external process is involved.
            TerminateProcess(child.hProcess, 1);
            WaitForSingleObject(child.hProcess, 10000);
        }
        CloseHandle(child.hProcess);
        return check(completed && exit_code == 0, "copied_runtime_self_protection_regression");
    }
}

int main(int count, char** arguments)
{
    if (count == 2 && std::string_view(arguments[1]) == "--run-copied-self-protection-fixture")
    {
        return copied_self_protection_fixture() ? 0 : 1;
    }
    if (count != 2 || std::string_view(arguments[1]) != "--run-isolated-fixtures")
    {
        std::puts("{\"status\":\"not_run\",\"reason\":\"explicit_isolated_fixture_opt_in_required\"}");
        return 77;
    }
    if (!host_readiness_observed())
    {
        return 1;
    }
    std::array<wchar_t, 32768> temporary{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
    if (length == 0 || length >= temporary.size())
    {
        return 1;
    }
    const std::wstring unique = L"secure_erase_isolated_" + std::to_wstring(GetCurrentProcessId()) +
        L"_" + std::to_wstring(GetTickCount64());
    fixture_tree tree{std::filesystem::path(temporary.data()) / unique};
    if (!CreateDirectoryW(tree.root.c_str(), nullptr))
    {
        // SECURITY: Do not cleanup a preexisting directory when unique creation failed.
        tree.root.clear();
        return 1;
    }
    auto factory = make_windows_platform((tree.root / L"state").wstring());
    if (!factory || !(*factory)->is_elevated())
    {
        std::puts("{\"status\":\"not_run\",\"reason\":\"elevated_windows_required\"}");
        return 77;
    }
    auto& backend = **factory;
    bool passed = launch_copied_self_protection_fixture(tree);
    const auto basic = tree.root / L"plain unicode_臺灣.bin";
    if (!create_fixture(basic))
    {
        return 1;
    }
    const auto basic_before = read_unchanged_fixture(basic);
    auto initial = backend.preview({path_text(basic)});
    if (!initial)
    {
        if (initial.error().code == "storage_media_unknown")
        {
            const auto basic_after = read_unchanged_fixture(basic);
            passed &= check(initial.error().native_code == ERROR_NOT_SUPPORTED && basic_before && basic_after &&
                same_fixture_metadata(*basic_before, *basic_after), "unknown_media_overwrite_refused_without_mutation");
            // CONTRACT: This host proves refusal only. It supplies no successful
            // overwrite/ADS/recovery coverage and cannot satisfy that hardware matrix.
            std::puts("{\"test\":\"supported_storage_overwrite_cases\",\"status\":\"not_run\",\"reason\":\"storage_media_unknown\",\"scope\":\"requires_identifiable_supported_test_device\"}");
            std::printf("{\"schema\":\"secure_erase.windows_backend_test_scope.v1\",\"scope\":\"unknown_media_refusal_only\",\"refusal_verified\":%s,\"supported_device_overwrite_verified\":false}\n",
                passed ? "true" : "false");
            return passed ? 0 : 1;
        }
        std::printf("{\"status\":\"not_run\",\"reason\":\"%s\",\"native_code\":%u}\n",
            initial.error().code.c_str(), initial.error().native_code);
        // Unsupported topology is not successful overwrite coverage, but cannot
        // hide a failed copied-runtime protection regression already executed.
        return passed ? 77 : 1;
    }
    if (initial->size() != 1 || initial->front().support == capability::blocked ||
        initial->front().support == capability::delete_only)
    {
        std::puts("{\"status\":\"not_run\",\"reason\":\"ordinary_overwrite_fixture_not_supported\"}");
        return passed ? 77 : 1;
    }
    passed &= check(overwrite_fixture(backend, initial->front(), true) &&
        GetFileAttributesW(basic.c_str()) == INVALID_FILE_ATTRIBUTES, "plain_write_flush_full_read_remove");

    const auto readonly = tree.root / L"readonly.bin";
    passed &= check(create_fixture(readonly) && SetFileAttributesW(readonly.c_str(), FILE_ATTRIBUTE_READONLY),
        "readonly_fixture_created");
    auto readonly_plan = backend.preview({path_text(readonly)});
    const bool readonly_overwritten = readonly_plan && overwrite_fixture(backend, readonly_plan->front(), false);
    const DWORD readonly_attributes = readonly_overwritten ? GetFileAttributesW(readonly.c_str()) : INVALID_FILE_ATTRIBUTES;
    passed &= check(readonly_overwritten && readonly_attributes != INVALID_FILE_ATTRIBUTES &&
        (readonly_attributes & FILE_ATTRIBUTE_READONLY) != 0, "readonly_restored_after_close");

    const auto normal = tree.root / L"archive_cleared.bin";
    passed &= check(create_fixture(normal) && SetFileAttributesW(normal.c_str(), FILE_ATTRIBUTE_NORMAL),
        "archive_clear_fixture_created");
    auto normal_plan = backend.preview({path_text(normal)});
    passed &= check(normal_plan && overwrite_fixture(backend, normal_plan->front(), true),
        "archive_bit_write_transition");

    const auto original = tree.root / L"identity.bin";
    const auto moved = tree.root / L"identity_old.bin";
    passed &= check(create_fixture(original), "replacement_fixture_created");
    auto replacement_plan = backend.preview({path_text(original)});
    const bool replaced = MoveFileW(original.c_str(), moved.c_str()) && create_fixture(original);
    passed &= check(replacement_plan && replaced && !backend.acquire(replacement_plan->front()),
        "replacement_identity_rejected");

    const auto ads_file = tree.root / L"ads.bin";
    const auto ads_path = std::filesystem::path(ads_file.wstring() + L":secret:$DATA");
    passed &= check(create_fixture(ads_file), "ads_base_fixture_created");
    if (create_fixture(ads_path, 271))
    {
        auto ads_plan = backend.preview({path_text(ads_file)});
        passed &= check(ads_plan && ads_plan->front().streams.size() == 2 &&
            overwrite_fixture(backend, ads_plan->front(), true), "all_ads_verified_and_deleted");
    }
    else
    {
        std::puts("{\"test\":\"all_ads_verified_and_deleted\",\"status\":\"not_run\",\"reason\":\"filesystem_has_no_ads\"}");
    }

    const auto link_source = tree.root / L"hardlink_source.bin";
    const auto link_alias = tree.root / L"hardlink_alias.bin";
    passed &= check(create_fixture(link_source), "hardlink_fixture_created");
    if (CreateHardLinkW(link_alias.c_str(), link_source.c_str(), nullptr))
    {
        auto link_plan = backend.preview({path_text(link_alias)});
        passed &= check(link_plan && link_plan->front().support == capability::delete_only,
            "hardlink_overwrite_forbidden");
        if (link_plan)
        {
            auto held = backend.acquire(link_plan->front());
            passed &= check(held && (*held)->remove() && GetFileAttributesW(link_source.c_str()) != INVALID_FILE_ATTRIBUTES,
                "hardlink_alias_delete_preserves_other_name");
        }
    }
    else
    {
        std::puts("{\"test\":\"hardlink_overwrite_forbidden\",\"status\":\"not_run\",\"reason\":\"filesystem_has_no_hardlinks\"}");
    }

    const auto directory = tree.root / L"frozen_directory";
    passed &= check(CreateDirectoryW(directory.c_str(), nullptr) != FALSE, "directory_fixture_created");
    auto directory_plan = backend.preview({path_text(directory)});
    passed &= check(create_fixture(directory / L"new_after_preview.bin"), "new_child_fixture_created");
    if (directory_plan)
    {
        auto held = backend.acquire(directory_plan->front());
        passed &= check(held && !(*held)->remove(), "nonempty_directory_not_removed");
    }
    else
    {
        passed = false;
    }

    const auto surviving = tree.root / L"metadata_handle.bin";
    passed &= check(create_fixture(surviving), "metadata_handle_fixture_created");
    auto surviving_plan = backend.preview({path_text(surviving)});
    HANDLE metadata = CreateFileW(surviving.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (metadata != INVALID_HANDLE_VALUE && surviving_plan)
    {
        auto held = backend.acquire(surviving_plan->front());
        if (held)
        {
            auto removed = (*held)->remove();
            const bool name_absent = GetFileAttributesW(surviving.c_str()) == INVALID_FILE_ATTRIBUTES &&
                (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
            passed &= check(!removed || name_absent, "pending_deletion_not_falsely_reported_success");
        }
        else
        {
            passed &= check(false, "metadata_handle_fixture_acquire");
        }
    }
    else
    {
        passed = false;
    }
    if (metadata != INVALID_HANDLE_VALUE)
    {
        CloseHandle(metadata);
    }

    const auto reparse = tree.root / L"reparse_directory";
    if (CreateSymbolicLinkW(reparse.c_str(), directory.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY))
    {
        passed &= check(!backend.preview({path_text(reparse)}), "reparse_final_rejected");
        passed &= check(!backend.preview({path_text(reparse / L"new_after_preview.bin")}), "reparse_ancestor_rejected");
    }
    else
    {
        std::puts("{\"test\":\"reparse_rejection\",\"status\":\"not_run\",\"reason\":\"symlink_privilege_unavailable\"}");
    }
    std::printf("{\"status\":\"%s\",\"scope\":\"self_created_windows_fixtures\",\"physical_sanitization_tested\":false}\n",
        passed ? "passed" : "failed");
    return passed ? 0 : 1;
}
