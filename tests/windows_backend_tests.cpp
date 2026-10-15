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
}

int main(int count, char** arguments)
{
    if (count != 2 || std::string_view(arguments[1]) != "--run-isolated-fixtures")
    {
        std::puts("{\"status\":\"not_run\",\"reason\":\"explicit_isolated_fixture_opt_in_required\"}");
        return 77;
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
    bool passed = true;
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
        // Unsupported/virtual topology is not successful platform coverage.
        return 77;
    }
    if (initial->size() != 1 || initial->front().support == capability::blocked ||
        initial->front().support == capability::delete_only)
    {
        std::puts("{\"status\":\"not_run\",\"reason\":\"ordinary_overwrite_fixture_not_supported\"}");
        return 77;
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
