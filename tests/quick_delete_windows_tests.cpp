// INTEROP: Native isolated fixtures use Windows SDK declarations; project APIs are modules.
#include <Windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <stddef.h>

import std;
import secure_erase.model;
import secure_erase.platform;
import secure_erase.quick_delete;
import secure_erase.windows_backend;

namespace
{
    using namespace secure_erase::engine;

    constexpr auto case_sensitive_info_class = FileCaseSensitiveInfo;

    struct fixture_tree
    {
        std::filesystem::path root;

        ~fixture_tree()
        {
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

    class held_file
    {
    public:
        explicit held_file(HANDLE value) noexcept : value_(value)
        {
        }

        held_file(const held_file&) = delete;
        held_file& operator=(const held_file&) = delete;

        ~held_file()
        {
            close();
        }

        HANDLE get() const noexcept
        {
            return value_;
        }

        void close() noexcept
        {
            if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr)
            {
                CloseHandle(value_);
                value_ = INVALID_HANDLE_VALUE;
            }
        }

    private:
        HANDLE value_;
    };

    std::string path_text(const std::filesystem::path& path)
    {
        const auto text = path.u8string();
        return {reinterpret_cast<const char*>(text.data()), text.size()};
    }

    std::wstring expanded_fixture_path(const std::filesystem::path& path, bool short_name)
    {
        std::array<wchar_t, 32768> buffer{};
        const DWORD length = short_name ?
            GetShortPathNameW(path.c_str(), buffer.data(), static_cast<DWORD>(buffer.size())) :
            GetLongPathNameW(path.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size())
        {
            return {};
        }
        return {buffer.data(), length};
    }

    bool create_file(const std::filesystem::path& path)
    {
        held_file file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_POSIX_SEMANTICS, nullptr));
        if (file.get() == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        constexpr std::array<unsigned char, 4> bytes{0x12, 0x34, 0xab, 0xcd};
        DWORD written{};
        return WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
            written == bytes.size();
    }


    struct junction_buffer
    {
        DWORD tag;
        WORD data_length;
        WORD reserved;
        WORD substitute_offset;
        WORD substitute_length;
        WORD print_offset;
        WORD print_length;
        wchar_t names[1];
    };

    bool set_fixture_junction(const std::filesystem::path& directory, const std::filesystem::path& destination)
    {
        // INTEROP: MS-FSCC mount-point reparse format. Only disposable fixture
        // paths are mutated, through a directory handle, never a raw volume.
        const auto substitute = L"\\??\\" + destination.wstring();
        const auto printable = destination.wstring();
        const auto name_bytes = (substitute.size() + printable.size() + 2) * sizeof(wchar_t);
        const auto bytes = offsetof(junction_buffer, names) + name_bytes;
        if (!std::in_range<WORD>(bytes - 8) || !std::in_range<WORD>(substitute.size() * sizeof(wchar_t)) ||
            !std::in_range<WORD>((substitute.size() + 1) * sizeof(wchar_t)))
        {
            SetLastError(ERROR_BUFFER_OVERFLOW);
            return false;
        }
        std::vector<std::byte> storage(bytes);
        auto* buffer = reinterpret_cast<junction_buffer*>(storage.data());
        buffer->tag = IO_REPARSE_TAG_MOUNT_POINT;
        buffer->data_length = static_cast<WORD>(bytes - 8);
        buffer->substitute_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
        buffer->print_offset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
        buffer->print_length = static_cast<WORD>(printable.size() * sizeof(wchar_t));
        std::memcpy(buffer->names, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
        std::memcpy(reinterpret_cast<std::byte*>(buffer->names) + buffer->print_offset,
            printable.c_str(), (printable.size() + 1) * sizeof(wchar_t));
        held_file file(CreateFileW(directory.c_str(), FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
        DWORD returned{};
        return file.get() != INVALID_HANDLE_VALUE && DeviceIoControl(file.get(), FSCTL_SET_REPARSE_POINT,
            storage.data(), static_cast<DWORD>(storage.size()), nullptr, 0, &returned, nullptr);
    }

    bool same_data(const std::filesystem::path& path)
    {
        held_file file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
            FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_POSIX_SEMANTICS, nullptr));
        std::array<unsigned char, 4> bytes{};
        DWORD read{};
        return file.get() != INVALID_HANDLE_VALUE && ReadFile(file.get(), bytes.data(),
            static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size() &&
            bytes == std::array<unsigned char, 4>{0x12, 0x34, 0xab, 0xcd};
    }

    std::optional<std::uint64_t> observed_allocation(const std::filesystem::path& path)
    {
        held_file file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
        FILE_STANDARD_INFO info{};
        if (file.get() == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(file.get(),
            FileStandardInfo, &info, sizeof(info)) || info.AllocationSize.QuadPart < 0)
        {
            return {};
        }
        return static_cast<std::uint64_t>(info.AllocationSize.QuadPart);
    }

    void report_space(const secure_erase::quick::space_sample& sample, const char* phase)
    {
        std::printf("{\"event\":\"quick_fixture_space_sample\",\"phase\":\"%s\","
            "\"available_to_caller\":%llu,\"total_free\":%llu,\"total_bytes\":%llu}\n", phase,
            static_cast<unsigned long long>(sample.available_to_caller),
            static_cast<unsigned long long>(sample.total_free), static_cast<unsigned long long>(sample.total_bytes));
    }

    bool fixture_path_exists(const std::filesystem::path& path)
    {
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    std::wstring security_text(const std::filesystem::path& path)
    {
        PSECURITY_DESCRIPTOR descriptor{};
        if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr,
            nullptr, nullptr, &descriptor) != ERROR_SUCCESS)
        {
            return {};
        }
        LPWSTR text{};
        const BOOL converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,
            SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr);
        std::wstring output;
        if (converted)
        {
            output = text;
            LocalFree(text);
        }
        LocalFree(descriptor);
        return output;
    }

    class denied_access
    {
    public:
        denied_access() = default;
        denied_access(const denied_access&) = delete;
        denied_access& operator=(const denied_access&) = delete;

        ~denied_access()
        {
            static_cast<void>(restore());
            if (original_ != nullptr)
            {
                LocalFree(original_);
            }
        }

        bool apply(const std::filesystem::path& path, DWORD mask)
        {
            path_ = path.wstring();
            PACL dacl{};
            if (GetNamedSecurityInfoW(path_.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, &dacl, nullptr, &original_) != ERROR_SUCCESS)
            {
                return false;
            }
            HANDLE raw{};
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            {
                return false;
            }
            held_file token(raw);
            DWORD needed{};
            GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
            if (needed == 0)
            {
                return false;
            }
            std::vector<std::byte> storage(needed);
            if (!GetTokenInformation(token.get(), TokenUser, storage.data(), needed, &needed))
            {
                return false;
            }
            EXPLICIT_ACCESSW access{};
            access.grfAccessPermissions = mask;
            access.grfAccessMode = DENY_ACCESS;
            access.grfInheritance = NO_INHERITANCE;
            access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            access.Trustee.TrusteeType = TRUSTEE_IS_USER;
            access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(
                reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid);
            PACL changed{};
            const DWORD built = SetEntriesInAclW(1, &access, dacl, &changed);
            if (built != ERROR_SUCCESS)
            {
                return false;
            }
            const DWORD applied = SetNamedSecurityInfoW(path_.data(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, changed, nullptr);
            LocalFree(changed);
            active_ = applied == ERROR_SUCCESS;
            return active_;
        }

        bool restore()
        {
            if (!active_)
            {
                return true;
            }
            if (GetFileAttributesW(path_.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
            {
                active_ = false;
                return true;
            }
            PACL dacl{};
            BOOL present{}, defaulted{};
            SECURITY_DESCRIPTOR_CONTROL control{};
            DWORD revision{};
            if (!GetSecurityDescriptorDacl(original_, &present, &dacl, &defaulted) ||
                !GetSecurityDescriptorControl(original_, &control, &revision) || !present)
            {
                return false;
            }
            const auto inheritance = (control & SE_DACL_PROTECTED) ?
                PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
            const DWORD restored = SetNamedSecurityInfoW(path_.data(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | inheritance, nullptr, nullptr, dacl, nullptr);
            active_ = restored != ERROR_SUCCESS;
            return !active_;
        }

    private:
        std::wstring path_;
        PSECURITY_DESCRIPTOR original_{};
        bool active_{};
    };

    std::size_t checks{};
    std::size_t failures{};

    bool check(bool passed, const char* name)
    {
        ++checks;
        failures += passed ? 0 : 1;
        std::printf("{\"test\":\"%s\",\"status\":\"%s\",\"native_code\":%lu}\n",
            name, passed ? "passed" : "failed", static_cast<unsigned long>(GetLastError()));
        return passed;
    }

    bool remove_target(secure_erase::quick::backend& backend, const secure_erase::quick::target& target,
        bool recover_access)
    {
        auto removed = backend.remove(target, recover_access);
        if (!removed)
        {
            std::printf("{\"event\":\"quick_fixture_remove_result\",\"code\":\"%s\","
                "\"native_code\":%u,\"recover_access\":%s}\n", removed.error().code.c_str(),
                removed.error().native_code, recover_access ? "true" : "false");
        }
        return removed.has_value();
    }

    const secure_erase::quick::target* target_ending(const std::vector<secure_erase::quick::target>& values,
        std::string_view suffix)
    {
        for (const auto& value : values)
        {
            if (value.path.ends_with(suffix))
            {
                return &value;
            }
        }
        return nullptr;
    }

    class streaming_roots final : public secure_erase::quick::root_source
    {
    public:
        explicit streaming_roots(std::vector<std::string> paths, bool fail_at_end = false)
            : paths_(std::move(paths)), fail_at_end_(fail_at_end)
        {
        }
        result<std::optional<std::string>> next() override
        {
            if (next_ == paths_.size())
            {
                if (fail_at_end_)
                {
                    return std::unexpected(error{"fixture_source_error"});
                }
                return std::optional<std::string>{};
            }
            return std::optional<std::string>(paths_[next_++]);
        }
    private:
        std::vector<std::string> paths_;
        std::size_t next_{};
        bool fail_at_end_{};
    };

    class streaming_targets final : public secure_erase::quick::target_sink
    {
    public:
        explicit streaming_targets(bool reject = false) : reject_(reject)
        {
        }
        result<void> append(secure_erase::quick::target value) override
        {
            if (reject_)
            {
                return std::unexpected(error{"fixture_sink_error"});
            }
            // Fixture only: keep its small records for exact membership checks.
            // Production CLI staging is file-backed, not this test collector.
            targets.push_back(std::move(value));
            threads.insert(GetCurrentThreadId());
            return {};
        }
        std::vector<secure_erase::quick::target> targets;
        std::set<DWORD> threads;
    private:
        bool reject_{};
    };

    std::optional<secure_erase::quick::target> freeze_one(secure_erase::quick::backend& backend,
        const std::filesystem::path& path)
    {
        control controls;
        auto prepared = backend.prepare({path_text(path)}, controls);
        if (!prepared || prepared->size() != 1 || !prepared->front().preparation_error.code.empty())
        {
            std::printf("{\"event\":\"fixture_freeze_failed\",\"code\":\"%s\"}\n",
                !prepared ? prepared.error().code.c_str() : prepared->empty() ? "empty" :
                prepared->front().preparation_error.code.c_str());
            return {};
        }
        return std::move(prepared->front());
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
    fixture_tree tree{std::filesystem::path(temporary.data()) /
        (L"secure_erase_quick_isolated_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
            std::to_wstring(GetTickCount64()))};
    if (!CreateDirectoryW(tree.root.c_str(), nullptr))
    {
        tree.root.clear();
        return 1;
    }
    auto made = make_windows_quick_backend((tree.root / L"state").wstring());
    if (!made)
    {
        return 1;
    }
    auto& backend = **made;
    auto initialized = backend.begin_execution();
    if (!initialized)
    {
        std::printf("{\"status\":\"not_run\",\"reason\":\"%s\"}\n", initialized.error().code.c_str());
        return initialized.error().code == "administrator_required" ? 77 : 1;
    }

    auto resources = backend.inspect_resources({});
    check(resources && resources->logical_processors > 0 && resources->available_memory_bytes > 0 &&
        resources->available_commit_bytes > 0 && resources->available_handles > 0 &&
        resources->temporary_disk_available_bytes > 0 && resources->devices.empty() &&
        (!resources->cpu_pressure_known || resources->cpu_pressure <= 100),
        "resource_probe_reports_live_global_headroom");

    constexpr std::string_view unknown_volume = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\";
    auto unprepared_sample = backend.sample_space(unknown_volume);
    check(!unprepared_sample && unprepared_sample.error().code == "quick_space_volume_not_prepared",
        "space_sample_requires_prepared_volume");

    const auto regular = tree.root / L"ordinary.bin";
    check(create_file(regular), "regular_fixture_created");
    auto regular_target = freeze_one(backend, regular);
    check(regular_target.has_value(), "regular_namespace_frozen");
    const auto allocation = observed_allocation(regular);
    check(regular_target && allocation && regular_target->allocated_bytes == *allocation,
        "frozen_allocation_matches_handle_metadata");
    const auto volume_key = regular_target ? regular_target->device_key : std::string{};
    const std::array<std::string_view, 1> selected_volumes{volume_key};
    auto selected_resources = backend.inspect_resources(selected_volumes);
    check(selected_resources && selected_resources->devices.size() == 1 &&
        selected_resources->devices.front().device_key == volume_key &&
        !selected_resources->devices.front().scheduling_group.empty() &&
        selected_resources->devices.front().concurrency_hint > 0 &&
        selected_resources->devices.front().io_pressure <= 100,
        "resource_probe_binds_device_group_to_frozen_volume");
    const std::array<std::string_view, 1> invalid_resource_key{"C:\\"};
    const std::array<std::string_view, 2> duplicate_resource_keys{volume_key, volume_key};
    auto invalid_resource = backend.inspect_resources(invalid_resource_key);
    auto duplicate_resource = backend.inspect_resources(duplicate_resource_keys);
    check(!invalid_resource && !duplicate_resource &&
        invalid_resource.error().code == "quick_resource_volume_not_prepared" &&
        duplicate_resource.error().code == "quick_resource_volume_not_prepared",
        "resource_probe_rejects_aliases_and_duplicate_volume_keys");
    auto before = backend.sample_space(volume_key);
    check(before && before->volume_key == volume_key && before->available_to_caller <= before->total_bytes &&
        before->available_to_caller <= before->total_free, "known_volume_space_observed_before_delete");
    if (before)
    {
        report_space(*before, "before");
    }
    auto suffixed = backend.sample_space(volume_key + "fixture_path");
    auto drive_alias = backend.sample_space("C:\\");
    auto unknown = backend.sample_space(unknown_volume);
    check(!suffixed && suffixed.error().code == "quick_space_volume_not_prepared" &&
        !drive_alias && drive_alias.error().code == "quick_space_volume_not_prepared" &&
        !unknown && unknown.error().code == "quick_space_volume_not_prepared",
        "space_sample_rejects_paths_aliases_and_unknown_guid");
    check(regular_target && remove_target(backend, *regular_target, false) && !fixture_path_exists(regular), "regular_fast_delete");
    auto after = backend.sample_space(volume_key);
    check(after && after->volume_key == volume_key && after->available_to_caller <= after->total_bytes &&
        after->available_to_caller <= after->total_free, "same_frozen_volume_space_observed_after_delete");
    if (after)
    {
        report_space(*after, "after");
    }
    // CONTRACT: Never assert a delta equals this file's allocation. Other processes,
    // metadata accounting, quotas and retained references can change these counters.

    const auto readonly = tree.root / L"readonly.bin";
    check(create_file(readonly) && SetFileAttributesW(readonly.c_str(), FILE_ATTRIBUTE_READONLY), "readonly_fixture_created");
    auto readonly_target = freeze_one(backend, readonly);
    check(readonly_target && (remove_target(backend, *readonly_target, false) || remove_target(backend, *readonly_target, true)) &&
        !fixture_path_exists(readonly), "readonly_delete_supported_or_deferred");

    const auto first = tree.root / L"selected_a.bin";
    const auto second = tree.root / L"selected_b.bin";
    const auto retained = tree.root / L"unselected_c.bin";
    check(create_file(first) && CreateHardLinkW(second.c_str(), first.c_str(), nullptr) &&
        CreateHardLinkW(retained.c_str(), first.c_str(), nullptr), "hardlink_fixture_created");
    const auto original_security = security_text(retained);
    control controls;
    auto links = backend.prepare({path_text(first), path_text(second)}, controls);
    const bool distinct_links = links && links->size() == 2 &&
        (*links)[0].preparation_error.code.empty() && (*links)[1].preparation_error.code.empty() &&
        (*links)[0].identity == (*links)[1].identity && (*links)[0].path != (*links)[1].path;
    check(distinct_links, "hardlink_selected_names_remain_distinct");
    check(distinct_links && remove_target(backend, (*links)[0], false) && remove_target(backend, (*links)[1], false) &&
        !fixture_path_exists(first) && !fixture_path_exists(second), "hardlink_both_selected_names_deleted");
    check(!original_security.empty() && same_data(retained) && security_text(retained) == original_security,
        "hardlink_unselected_data_owner_dacl_unchanged");

    const auto locked = tree.root / L"locked.bin";
    check(create_file(locked), "locked_fixture_created");
    auto locked_target = freeze_one(backend, locked);
    held_file lock(CreateFileW(locked.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    check(lock.get() != INVALID_HANDLE_VALUE && locked_target && !remove_target(backend, *locked_target, false) &&
        same_data(locked), "locked_first_pass_fails_without_content_change");
    lock.close();
    check(locked_target && remove_target(backend, *locked_target, true) && !fixture_path_exists(locked), "locked_deferred_retry_after_release");

    const auto replaced = tree.root / L"replacement.bin";
    const auto old = tree.root / L"original_moved.bin";
    check(create_file(replaced), "replacement_fixture_created");
    auto replaced_target = freeze_one(backend, replaced);
    check(MoveFileW(replaced.c_str(), old.c_str()) && create_file(replaced), "replacement_namespace_swapped");
    check(replaced_target && !remove_target(backend, *replaced_target, false) && !remove_target(backend, *replaced_target, true) &&
        same_data(replaced) && same_data(old), "replacement_rejected_in_both_passes");

    const auto directory = tree.root / L"new_child";
    const auto fresh = directory / L"late.bin";
    check(CreateDirectoryW(directory.c_str(), nullptr) != FALSE, "new_child_directory_created");
    auto directory_target = freeze_one(backend, directory);
    check(directory_target && directory_target->allocated_bytes == 0, "directory_allocation_hint_is_zero");
    check(create_file(fresh), "new_child_added_after_freeze");
    const auto directory_security = security_text(directory);
    check(directory_target && !remove_target(backend, *directory_target, false) && !remove_target(backend, *directory_target, true) &&
        same_data(fresh), "new_child_not_enumerated_or_removed_by_retry");
    check(!directory_security.empty() && directory_security == security_text(directory),
        "failed_recovery_owner_dacl_unchanged");

    const auto denied_dir = tree.root / L"denied";
    const auto denied_file = denied_dir / L"denied.bin";
    check(CreateDirectoryW(denied_dir.c_str(), nullptr) && create_file(denied_file), "access_recovery_fixture_created");
    {
        denied_access parent_acl;
        denied_access file_acl;
        const bool setup = parent_acl.apply(denied_dir, FILE_DELETE_CHILD) && file_acl.apply(denied_file, DELETE);
        check(setup, "delete_access_denied_on_parent_and_target");
        auto denied_target = freeze_one(backend, denied_file);
        const auto parent_security = security_text(denied_dir);
        check(setup && denied_target && !remove_target(backend, *denied_target, false), "access_denied_deferred_from_first_pass");
        check(setup && denied_target && remove_target(backend, *denied_target, true) && !fixture_path_exists(denied_file),
            "scoped_restore_privilege_recovers_delete_access");
        check(!parent_security.empty() && parent_security == security_text(denied_dir), "access_recovery_parent_owner_dacl_unchanged");
        check(file_acl.restore() && parent_acl.restore(), "fixture_acl_restored");
    }

    // CONTRACT: A preexisting impersonation token must be restored by identity,
    // rather than merely reverting to the process token after privileged failure.
    HANDLE process_token_raw{};
    const bool process_opened = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token_raw) != FALSE;
    held_file process_token(process_token_raw);
    HANDLE impersonation_raw{};
    const bool duplicated = process_opened && DuplicateTokenEx(process_token.get(), TOKEN_QUERY | TOKEN_IMPERSONATE |
        TOKEN_DUPLICATE, nullptr, SecurityImpersonation, TokenImpersonation, &impersonation_raw);
    held_file impersonation(impersonation_raw);
    TOKEN_STATISTICS token_statistics_before{};
    DWORD returned{};
    const bool impersonated = duplicated && GetTokenInformation(impersonation.get(), TokenStatistics,
        &token_statistics_before, sizeof(token_statistics_before), &returned) && SetThreadToken(nullptr, impersonation.get());
    check(impersonated, "preexisting_worker_impersonation_created");
    if (impersonated)
    {
        check(directory_target && !remove_target(backend, *directory_target, true), "impersonated_failed_retry_remains_failure");
        HANDLE after_raw{};
        const bool after_opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &after_raw) != FALSE;
        held_file after_token(after_raw);
        TOKEN_STATISTICS token_statistics_after{};
        check(after_opened && GetTokenInformation(after_token.get(), TokenStatistics, &token_statistics_after, sizeof(token_statistics_after), &returned) &&
            token_statistics_before.TokenId.LowPart == token_statistics_after.TokenId.LowPart &&
            token_statistics_before.TokenId.HighPart == token_statistics_after.TokenId.HighPart,
            "original_impersonation_token_identity_restored");
        if (!check(RevertToSelf() != FALSE, "fixture_impersonation_reverted"))
        {
            return 1;
        }
    }

    const auto readonly_alias = tree.root / L"readonly_shared.bin";
    const bool readonly_links = CreateHardLinkW(readonly_alias.c_str(), retained.c_str(), nullptr) &&
        SetFileAttributesW(retained.c_str(), FILE_ATTRIBUTE_READONLY);
    check(readonly_links, "shared_readonly_fixture_created");
    auto readonly_alias_target = freeze_one(backend, readonly_alias);
    if (readonly_alias_target)
    {
        auto deleted = remove_target(backend, *readonly_alias_target, false);
        if (!deleted)
        {
            deleted = remove_target(backend, *readonly_alias_target, true);
        }
        const DWORD retained_attributes = GetFileAttributesW(retained.c_str());
        check((deleted || fixture_path_exists(readonly_alias)) && same_data(retained) &&
            retained_attributes != INVALID_FILE_ATTRIBUTES && (retained_attributes & FILE_ATTRIBUTE_READONLY) != 0,
            "shared_readonly_alias_attribute_not_mutated");
    }
    else
    {
        check(false, "shared_readonly_alias_frozen");
    }
    check(SetFileAttributesW(retained.c_str(), FILE_ATTRIBUTE_NORMAL) != FALSE, "shared_readonly_fixture_restored");

    const auto protected_file = tree.root / L"state" / L"protected.bin";
    check(CreateDirectoryW((tree.root / L"state").c_str(), nullptr) && create_file(protected_file), "protected_fixture_created");
    auto protected_set = backend.prepare({path_text(protected_file)}, controls);
    check(protected_set && protected_set->size() == 1 && !protected_set->front().preparation_error.code.empty() &&
        !remove_target(backend, protected_set->front(), true) && same_data(protected_file), "state_protection_never_bypassed");

    const auto sibling = tree.root / L"accessible_sibling.bin";
    check(create_file(sibling), "sibling_fixture_created");
    auto mixed = backend.prepare({path_text(tree.root / L"missing.bin"), path_text(sibling)}, controls);
    const auto mixed_missing = mixed ? target_ending(*mixed, "\\missing.bin") : nullptr;
    const auto mixed_sibling = mixed ? target_ending(*mixed, "\\accessible_sibling.bin") : nullptr;
    check(mixed && mixed->size() == 2 && mixed_missing && !mixed_missing->preparation_error.code.empty() &&
        mixed_sibling && mixed_sibling->preparation_error.code.empty() && remove_target(backend, *mixed_sibling, false),
        "preparation_failure_does_not_abort_accessible_sibling");

    const auto destination = tree.root / L"reparse_destination";
    const auto redirect = tree.root / L"reparse_link";
    check(CreateDirectoryW(destination.c_str(), nullptr) && create_file(destination / L"kept.bin"), "reparse_fixture_created");
    if (CreateSymbolicLinkW(redirect.c_str(), destination.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY))
    {
        auto reparse = backend.prepare({path_text(redirect / L"kept.bin")}, controls);
        check(reparse && reparse->size() == 1 && !reparse->front().preparation_error.code.empty() &&
            !remove_target(backend, reparse->front(), true) && same_data(destination / L"kept.bin"), "reparse_ancestor_denied");
    }
    else
    {
        check(false, "reparse_fixture_symlink_privilege_required");
    }

    const auto prior_parent = tree.root / L"parent_before_swap";
    const auto moved_parent = tree.root / L"parent_original_retained";
    check(CreateDirectoryW(prior_parent.c_str(), nullptr) && create_file(prior_parent / L"kept.bin"),
        "ancestor_replacement_fixture_created");
    auto child_target = freeze_one(backend, prior_parent / L"kept.bin");
    const bool redirected = MoveFileW(prior_parent.c_str(), moved_parent.c_str()) &&
        CreateSymbolicLinkW(prior_parent.c_str(), destination.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY);
    check(redirected, "ancestor_replaced_after_freeze");
    check(redirected && child_target && !remove_target(backend, *child_target, false) && !remove_target(backend, *child_target, true) &&
        same_data(moved_parent / L"kept.bin") && same_data(destination / L"kept.bin"),
        "frozen_target_reparse_ancestor_replacement_denied");

    const auto case_root = tree.root / L"case_sensitive";
    check(CreateDirectoryW(case_root.c_str(), nullptr) != FALSE, "case_sensitive_fixture_created");
    held_file case_directory(CreateFileW(case_root.c_str(), FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    FILE_CASE_SENSITIVE_INFO case_info{};
    case_info.Flags = 1; // CONTRACT: FILE_CS_FLAG_CASE_SENSITIVE_DIR, Windows native flag value.
    const bool case_enabled = case_directory.get() != INVALID_HANDLE_VALUE &&
        SetFileInformationByHandle(case_directory.get(), case_sensitive_info_class, &case_info, sizeof(case_info));
    const DWORD case_error = case_enabled ? ERROR_SUCCESS : GetLastError();
    case_directory.close();
    if (case_enabled)
    {
        const auto upper = case_root / L"A";
        const auto lower = case_root / L"a";
        const bool setup = CreateDirectoryW(upper.c_str(), nullptr) && CreateDirectoryW(lower.c_str(), nullptr) &&
            create_file(upper / L"same.bin") && create_file(lower / L"same.bin");
        check(setup, "case_distinct_ancestor_fixtures_created");
        auto names = backend.prepare({path_text(upper / L"same.bin"), path_text(lower / L"same.bin")}, controls);
        const bool distinct = names && names->size() == 2 && (*names)[0].preparation_error.code.empty() &&
            (*names)[1].preparation_error.code.empty() && (*names)[0].identity != (*names)[1].identity;
        const auto upper_target = names ? target_ending(*names, "\\A\\same.bin") : nullptr;
        const auto lower_target = names ? target_ending(*names, "\\a\\same.bin") : nullptr;
        if (distinct && upper_target)
        {
            auto locks = backend.query_locks(*upper_target);
            locking_process dummy;
            auto close = backend.close_process(*upper_target, dummy, false);
            check(!locks && locks.error().code == "quick_case_sensitive_process_action_denied" &&
                !close && close.error().code == "quick_case_sensitive_process_action_denied",
                "case_sensitive_process_actions_are_withheld");
        }
        check(setup && distinct && upper_target && lower_target && remove_target(backend, *lower_target, false) &&
            same_data(upper / L"same.bin") && remove_target(backend, *upper_target, false),
            "exact_case_ancestors_and_names_remain_distinct");
    }
    else
    {
        std::printf("{\"test\":\"exact_case_ancestors_and_names_remain_distinct\",\"status\":\"not_run\","
            "\"reason\":\"case_sensitive_directory_capability_unavailable\",\"native_code\":%lu}\n",
            static_cast<unsigned long>(case_error));
    }



    const auto stream_root = tree.root / L"streaming_tree";
    bool stream_setup = CreateDirectoryW(stream_root.c_str(), nullptr) != FALSE;
    for (unsigned branch = 0; branch < 4; ++branch)
    {
        const auto stream_directory = stream_root / (L"branch_" + std::to_wstring(branch));
        stream_setup = CreateDirectoryW(stream_directory.c_str(), nullptr) && stream_setup;
        for (unsigned item = 0; item < 16; ++item)
        {
            stream_setup = create_file(stream_directory / (L"item_" + std::to_wstring(item) + L".bin")) && stream_setup;
        }
    }
    check(stream_setup, "streaming_parallel_tree_fixture_created");
    streaming_roots stream_input({path_text(stream_root)});
    streaming_targets stream_output;
    auto streamed = backend.prepare_stream(stream_input, stream_output, controls);
    std::set<std::string> streamed_names;
    bool stream_clean = streamed.has_value();
    for (const auto& value : stream_output.targets)
    {
        stream_clean = stream_clean && value.preparation_error.code.empty();
        streamed_names.insert(value.path);
    }
    check(stream_clean && streamed_names.size() == 69 && stream_output.targets.size() == 69 &&
        same_data(stream_root / L"branch_0" / L"item_0.bin"),
        "streaming_parallel_scan_freezes_every_name_without_mutation");
    std::printf("{\"event\":\"fixture_stream_preparation_workers\",\"observed_threads\":%zu}\n",
        stream_output.threads.size());
    streaming_roots failed_source({path_text(stream_root)}, true);
    streaming_targets failed_source_output;
    auto source_failed = backend.prepare_stream(failed_source, failed_source_output, controls);
    check(!source_failed && source_failed.error().code == "fixture_source_error" &&
        same_data(stream_root / L"branch_1" / L"item_1.bin"), "streaming_source_failure_prevents_any_mutation");
    streaming_roots failed_sink_input({path_text(stream_root)});
    streaming_targets failed_sink(true);
    auto sink_failed = backend.prepare_stream(failed_sink_input, failed_sink, controls);
    check(!sink_failed && sink_failed.error().code == "fixture_sink_error" &&
        same_data(stream_root / L"branch_2" / L"item_2.bin"), "streaming_sink_failure_joins_workers_without_mutation");
    control cancelled_stream;
    cancelled_stream.request.store(control_request::cancel);
    streaming_roots cancelled_input({path_text(stream_root)});
    streaming_targets cancelled_output;
    auto stream_cancelled = backend.prepare_stream(cancelled_input, cancelled_output, cancelled_stream);
    check(!stream_cancelled && stream_cancelled.error().code == "quick_preparation_cancelled" &&
        cancelled_output.targets.empty() && same_data(stream_root / L"branch_3" / L"item_3.bin"),
        "streaming_cancelled_scan_emits_no_executable_partial_plan");

    const auto lease_directory = tree.root / L"leased_directory";
    const auto lease_moved = tree.root / L"leased_directory_moved";
    const auto lease_first = lease_directory / L"a.bin";
    const auto lease_second = lease_directory / L"b.bin";
    check(CreateDirectoryW(lease_directory.c_str(), nullptr) && create_file(lease_first) && create_file(lease_second),
        "directory_lease_fixtures_created");
    auto leased = backend.prepare({path_text(lease_first), path_text(lease_second)}, controls);
    const auto lease_a = leased ? target_ending(*leased, "\\a.bin") : nullptr;
    const auto lease_b = leased ? target_ending(*leased, "\\b.bin") : nullptr;
    check(leased && leased->size() == 2 && lease_a && lease_b && remove_target(backend, *lease_a, false),
        "directory_lease_fast_path_established");
    backend.finish_execution();
    check(MoveFileW(lease_directory.c_str(), lease_moved.c_str()) != FALSE && same_data(lease_moved / L"b.bin"),
        "finish_execution_releases_every_cached_ancestor_pin");
    check(lease_b && !remove_target(backend, *lease_b, false) && same_data(lease_moved / L"b.bin"),
        "finished_context_never_redirects_frozen_name");
    backend.finish_execution();


    const auto mutation_directory = tree.root / L"mutable_ancestor";
    const auto mutation_destination = tree.root / L"mutation_destination";
    const auto mutation_first = mutation_directory / L"first.bin";
    const auto mutation_second = mutation_directory / L"second.bin";
    const auto mutation_original = tree.root / L"mutation_original.bin";
    const bool mutation_setup = CreateDirectoryW(mutation_directory.c_str(), nullptr) &&
        CreateDirectoryW(mutation_destination.c_str(), nullptr) && create_file(mutation_first) && create_file(mutation_second);
    auto mutation_targets = mutation_setup ? backend.prepare({path_text(mutation_first), path_text(mutation_second)}, controls) :
        result<std::vector<secure_erase::quick::target>>(std::unexpected(error{"fixture_setup_failed"}));
    const auto mutation_a = mutation_targets ? target_ending(*mutation_targets, "\\first.bin") : nullptr;
    const auto mutation_b = mutation_targets ? target_ending(*mutation_targets, "\\second.bin") : nullptr;
    const bool mutation_ready = mutation_targets && mutation_targets->size() == 2 && mutation_a && mutation_b &&
        remove_target(backend, *mutation_a, false) &&
        MoveFileW(mutation_second.c_str(), mutation_original.c_str()) &&
        CreateHardLinkW((mutation_destination / L"second.bin").c_str(), mutation_original.c_str(), nullptr);
    check(mutation_ready, "in_place_ancestor_mutation_fixture_prepared");
    const bool junction_changed = mutation_ready && set_fixture_junction(mutation_directory, mutation_destination);
    const DWORD mutation_error = junction_changed ? ERROR_SUCCESS : GetLastError();
    if (junction_changed)
    {
        check(!remove_target(backend, *mutation_b, false) && same_data(mutation_original) &&
            same_data(mutation_destination / L"second.bin"), "cached_ancestor_reparse_attribute_change_rejected");
    }
    else if (mutation_error == ERROR_SHARING_VIOLATION || mutation_error == ERROR_ACCESS_DENIED)
    {
        check(mutation_ready && same_data(mutation_original) && same_data(mutation_destination / L"second.bin"),
            "filesystem_withholds_reparse_mutation_on_pinned_directory");
    }
    else
    {
        std::printf("{\"test\":\"cached_ancestor_reparse_attribute_change_rejected\",\"status\":\"not_run\","
            "\"reason\":\"fixture_in_place_reparse_capability_unavailable\",\"native_code\":%lu}\n",
            static_cast<unsigned long>(mutation_error));
    }
    backend.finish_execution();
    if (junction_changed)
    {
        check(RemoveDirectoryW(mutation_directory.c_str()) != FALSE && same_data(mutation_destination / L"second.bin"),
            "fixture_junction_removed_without_touching_destination");
    }

    const auto ready_directory = tree.root / L"ready_directory";
    const auto ready_child = ready_directory / L"child.bin";
    check(CreateDirectoryW(ready_directory.c_str(), nullptr) && create_file(ready_child),
        "ready_directory_fixture_created");
    auto ready = backend.prepare({path_text(ready_directory)}, controls);
    bool ready_deleted = ready && ready->size() == 2;
    if (ready_deleted)
    {
        for (const auto& item : *ready)
        {
            if (!item.directory)
            {
                ready_deleted = remove_target(backend, item, false) && ready_deleted;
            }
        }
        for (const auto& item : *ready)
        {
            if (item.directory)
            {
                ready_deleted = remove_target(backend, item, false) && ready_deleted;
            }
        }
    }
    check(ready_deleted && !fixture_path_exists(ready_directory), "ready_directory_evicts_own_cached_leases_before_delete");
    backend.finish_execution();

    const auto scope_root = tree.root / L"scope";
    const auto scope_old = tree.root / L"scope_original";
    const auto scope_file = scope_root / L"selected.bin";
    const auto outside = tree.root / L"outside_scope.bin";
    check(CreateDirectoryW(scope_root.c_str(), nullptr) && create_file(scope_file) && create_file(outside),
        "scope_boundary_fixtures_created");
    auto scoped_factory = make_windows_quick_backend((tree.root / L"scope_reports").wstring(), scope_root.wstring());
    auto overlapping_factory = make_windows_quick_backend((scope_root / L"reports").wstring(), scope_root.wstring());
    check(scoped_factory && !overlapping_factory &&
        overlapping_factory.error().code == "scope_report_overlap_or_reparse", "scope_report_overlap_rejected");
    if (scoped_factory)
    {
        auto& scoped = **scoped_factory;
        auto outside_batch = scoped.prepare({path_text(scope_file), path_text(outside)}, controls);
        check(!outside_batch && outside_batch.error().code == "quick_target_outside_scope" &&
            same_data(scope_file) && same_data(outside), "scope_mixed_outside_request_rejected_before_mutation");
        auto outside_target = freeze_one(backend, outside);
        check(outside_target && !remove_target(scoped, *outside_target, true) && same_data(outside),
            "scope_acquire_rejects_foreign_frozen_target");
        const auto missing_outside = tree.root / L"outside_missing" / L"missing.bin";
        auto missing_outside_batch = scoped.prepare({path_text(scope_file), path_text(missing_outside)}, controls);
        check(!missing_outside_batch && missing_outside_batch.error().code == "quick_target_outside_scope" &&
            same_data(scope_file) && !fixture_path_exists(missing_outside),
            "scope_missing_outside_request_rejects_entire_batch");
        const auto missing_inside = scope_root / L"missing_inside.bin";
        auto missing_inside_batch = scoped.prepare({path_text(scope_file), path_text(missing_inside)}, controls);
        check(missing_inside_batch && missing_inside_batch->size() == 2 &&
            std::ranges::count_if(*missing_inside_batch, [](const auto& value)
            {
                return !value.preparation_error.code.empty();
            }) == 1 && same_data(scope_file) && !fixture_path_exists(missing_inside),
            "scope_missing_inside_target_remains_per_target_failure");
        auto scoped_target = freeze_one(scoped, scope_file);
        check(scoped_target && same_data(scope_file), "scope_selected_namespace_frozen_before_replacement");
        const auto scope_long_path = expanded_fixture_path(scope_file, false);
        auto long_scope_target = scope_long_path.empty() ? std::optional<secure_erase::quick::target>{} :
            freeze_one(scoped, std::filesystem::path(scope_long_path));
        check(scoped_target && long_scope_target && long_scope_target->path == scoped_target->path &&
            long_scope_target->identity == scoped_target->identity && same_data(scope_file),
            "scope_long_input_alias_binds_exact_canonical_name");
        const auto scope_short_path = expanded_fixture_path(scope_file, true);
        if (!scope_short_path.empty() && scope_short_path != scope_long_path)
        {
            auto short_scope_target = freeze_one(scoped, std::filesystem::path(scope_short_path));
            check(scoped_target && short_scope_target && short_scope_target->path == scoped_target->path &&
                short_scope_target->identity == scoped_target->identity && same_data(scope_file),
                "scope_short_input_alias_binds_exact_canonical_name");
        }
        else
        {
            std::puts("{\"test\":\"scope_short_input_alias_binds_exact_canonical_name\",\"status\":\"not_run\","
                "\"reason\":\"distinct_short_name_unavailable\"}");
        }
        const bool scope_replaced = MoveFileW(scope_root.c_str(), scope_old.c_str()) &&
            CreateDirectoryW(scope_root.c_str(), nullptr) &&
            CreateHardLinkW(scope_file.c_str(), (scope_old / L"selected.bin").c_str(), nullptr);
        check(scope_replaced && scoped_target && !remove_target(scoped, *scoped_target, false) &&
            same_data(scope_file) && same_data(scope_old / L"selected.bin"),
            "scope_root_replacement_rejected_even_with_same_child_hardlink_id");
        scoped.finish_execution();
    }

    HANDLE token{};
    const BOOL has_thread_token = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    if (has_thread_token)
    {
        CloseHandle(token);
    }
    check(!has_thread_token && GetLastError() == ERROR_NO_TOKEN, "worker_impersonation_not_leaked");
    std::printf("{\"schema\":\"secure_erase.quick_windows_tests.v1\",\"checks\":%zu,\"failures\":%zu}\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
