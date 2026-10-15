module;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <sddl.h>
#include <shlobj.h>

module secure_erase.state_store;

import std;
import secure_erase.codec;
import secure_erase.crypto;
import secure_erase.quick_store;

namespace secure_erase::storage
{
    namespace
    {
        struct close_handle
        {
            void operator()(void* value) const noexcept
            {
                if (value != nullptr && value != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(value);
                }
            }
        };

        using unique_handle = std::unique_ptr<void, close_handle>;

        struct local_free
        {
            void operator()(void* value) const noexcept
            {
                if (value != nullptr)
                {
                    LocalFree(value);
                }
            }
        };

        using local_memory = std::unique_ptr<void, local_free>;

        struct protected_blob
        {
            DATA_BLOB value{};

            ~protected_blob()
            {
                if (value.pbData != nullptr)
                {
                    SecureZeroMemory(value.pbData, value.cbData);
                    LocalFree(value.pbData);
                }
            }
        };

        struct clear_bytes
        {
            std::vector<std::byte>& bytes;

            ~clear_bytes()
            {
                clear_sensitive(bytes);
            }
        };

        engine::error failure(std::string code, DWORD native = GetLastError())
        {
            return {std::move(code), native, false};
        }

        engine::result<std::size_t> checkpoint_budget()
        {
            MEMORYSTATUSEX memory{};
            memory.dwLength = sizeof(memory);
            if (!GlobalMemoryStatusEx(&memory))
            {
                return std::unexpected(failure("state_resource_probe_failed"));
            }
            // Several encrypted/plaintext/decoded allocations may coexist. Reserve
            // at most one eighth of current physical/commit headroom for each phase.
            const auto available = (std::min)(memory.ullAvailPhys, memory.ullAvailPageFile) / 8;
            constexpr auto format_limit = static_cast<std::uint64_t>(
                (std::numeric_limits<DWORD>::max)()) - 1024 * 1024;
            const auto budget = (std::min)(available, format_limit);
            if (budget < 4096)
            {
                return std::unexpected(failure("state_resource_budget_exhausted", ERROR_NOT_ENOUGH_MEMORY));
            }
            return static_cast<std::size_t>(budget);
        }

        std::uint64_t filetime_value(const FILETIME& value) noexcept
        {
            return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        }

        std::uint64_t now_filetime() noexcept
        {
            FILETIME value{};
            GetSystemTimePreciseAsFileTime(&value);
            return filetime_value(value);
        }

        std::wstring widen_ascii(std::string_view value)
        {
            return {value.begin(), value.end()};
        }

        bool safe_options(const store_options& value) noexcept
        {
            return value.log_rotation_bytes >= 65536 && value.log_rotation_bytes <= 64ULL * 1024 * 1024
                && value.retained_log_files >= 1 && value.retained_log_files <= 64
                && value.log_retention_days <= 36500 && value.checkpoint_retention_days <= 36500;
        }

        bool expired(std::uint64_t modified, std::uint32_t days, std::uint64_t now) noexcept
        {
            constexpr std::uint64_t ticks_per_day{864000000000ULL};
            return days != 0 && modified < now && now - modified > ticks_per_day * days;
        }

        engine::result<std::wstring> final_path(HANDLE handle)
        {
            const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
            if (needed == 0 || needed > 32768)
            {
                return std::unexpected(failure("state_final_path_failed"));
            }
            std::wstring path(needed, L'\0');
            const DWORD written = GetFinalPathNameByHandleW(handle, path.data(), needed, FILE_NAME_NORMALIZED);
            if (written == 0 || written >= needed)
            {
                return std::unexpected(failure("state_final_path_failed"));
            }
            path.resize(written);
            if (path.starts_with(L"\\\\?\\"))
            {
                path.erase(0, 4);
            }
            return path;
        }

        engine::result<std::wstring> long_path(std::wstring_view path)
        {
            const std::wstring owned(path);
            const DWORD needed = GetLongPathNameW(owned.c_str(), nullptr, 0);
            if (needed == 0)
            {
                return std::unexpected(failure("state_long_path_failed"));
            }
            if (needed > 32768)
            {
                return std::unexpected(failure("state_long_path_limit", ERROR_FILENAME_EXCED_RANGE));
            }
            std::wstring expanded(needed, L'\0');
            const DWORD written = GetLongPathNameW(owned.c_str(), expanded.data(), needed);
            if (written == 0)
            {
                return std::unexpected(failure("state_long_path_failed"));
            }
            if (written >= needed)
            {
                return std::unexpected(failure("state_long_path_changed", ERROR_INSUFFICIENT_BUFFER));
            }
            expanded.resize(written);
            return expanded;
        }

        std::wstring append_component(std::wstring_view parent, std::wstring_view component)
        {
            std::wstring path(parent);
            if (!path.ends_with(L'\\'))
            {
                path += L'\\';
            }
            path += component;
            return path;
        }

        bool equal_path(std::wstring_view first, std::wstring_view second) noexcept
        {
            if (first.size() != second.size() || first.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                return false;
            }
            return CompareStringOrdinal(first.data(), static_cast<int>(first.size()), second.data(),
                static_cast<int>(second.size()), TRUE) == CSTR_EQUAL;
        }

        engine::result<std::wstring> verify_object(HANDLE handle, std::wstring_view expected, bool directory)
        {
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            FILE_STANDARD_INFO standard{};
            if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes))
                || !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)))
            {
                return std::unexpected(failure("state_metadata_failed"));
            }
            if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || standard.DeletePending || (standard.Directory != FALSE) != directory
                || (!directory && standard.NumberOfLinks != 1))
            {
                return std::unexpected(failure("state_unsafe_object", ERROR_ACCESS_DENIED));
            }
            auto actual = final_path(handle);
            if (!actual)
            {
                return std::unexpected(actual.error());
            }
            if (equal_path(*actual, expected))
            {
                return actual;
            }
            // SECURITY: Expand spelling only after this no-reparse object and every
            // ancestor are held without delete sharing. DOS 8.3 aliases may differ
            // from FILE_NAME_NORMALIZED; arbitrary redirects must still fail equality.
            auto expanded = long_path(expected);
            if (!expanded)
            {
                return std::unexpected(expanded.error());
            }
            if (!equal_path(*actual, *expanded))
            {
                return std::unexpected(failure("state_path_changed", ERROR_ACCESS_DENIED));
            }
            return actual;
        }

        engine::result<void> write_all(HANDLE handle, std::span<const std::byte> bytes)
        {
            std::size_t offset{};
            while (offset < bytes.size())
            {
                const auto wanted = static_cast<DWORD>((std::min)(bytes.size() - offset,
                    static_cast<std::size_t>(1024 * 1024)));
                DWORD written{};
                if (!WriteFile(handle, bytes.data() + offset, wanted, &written, nullptr))
                {
                    return std::unexpected(failure("state_write_failed"));
                }
                if (written == 0 || written > wanted)
                {
                    return std::unexpected(failure("state_write_no_progress", ERROR_WRITE_FAULT));
                }
                offset += written;
            }
            if (!FlushFileBuffers(handle))
            {
                return std::unexpected(failure("state_flush_failed"));
            }
            return {};
        }

        engine::result<std::vector<std::byte>> read_all(HANDLE handle, std::size_t maximum)
        {
            LARGE_INTEGER length{};
            if (!GetFileSizeEx(handle, &length))
            {
                return std::unexpected(failure("state_size_failed"));
            }
            if (length.QuadPart < 0 || static_cast<std::uint64_t>(length.QuadPart) > maximum)
            {
                return std::unexpected(failure("state_size_limit", ERROR_FILE_TOO_LARGE));
            }
            std::vector<std::byte> value(static_cast<std::size_t>(length.QuadPart));
            std::size_t offset{};
            while (offset < value.size())
            {
                const auto wanted = static_cast<DWORD>((std::min)(value.size() - offset,
                    static_cast<std::size_t>(1024 * 1024)));
                DWORD received{};
                if (!ReadFile(handle, value.data() + offset, wanted, &received, nullptr))
                {
                    clear_sensitive(value);
                    return std::unexpected(failure("state_read_failed"));
                }
                if (received == 0 || received > wanted)
                {
                    clear_sensitive(value);
                    return std::unexpected(failure("state_read_short", ERROR_HANDLE_EOF));
                }
                offset += received;
            }
            return value;
        }
    }

    struct state_store::implementation
    {
        struct staging_file;
        struct staging_factory;
        store_options settings;
        std::wstring root;
        std::vector<std::byte> user_sid;
        std::array<std::byte, SECURITY_MAX_SID_SIZE> system_sid{};
        local_memory descriptor;
        std::vector<unique_handle> pinned_directories;
        unique_handle lock_file;
        std::mutex mutex;

        SECURITY_ATTRIBUTES security_attributes() const noexcept
        {
            return {sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
        }

        engine::result<void> verify_acl(HANDLE handle) const
        {
            PSID owner{};
            PACL dacl{};
            PSECURITY_DESCRIPTOR raw{};
            const auto error = GetSecurityInfo(handle, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &raw);
            local_memory security(raw);
            if (error != ERROR_SUCCESS)
            {
                return std::unexpected(failure("state_acl_query_failed", error));
            }
            SECURITY_DESCRIPTOR_CONTROL control{};
            DWORD revision{};
            if (owner == nullptr || !EqualSid(owner, const_cast<std::byte*>(user_sid.data()))
                || dacl == nullptr || !GetSecurityDescriptorControl(raw, &control, &revision)
                || (control & SE_DACL_PROTECTED) == 0 || dacl->AceCount != 2)
            {
                return std::unexpected(failure("state_acl_not_private", ERROR_ACCESS_DENIED));
            }
            bool user_found{};
            bool system_found{};
            for (DWORD index{}; index < dacl->AceCount; ++index)
            {
                void* raw_ace{};
                if (!GetAce(dacl, index, &raw_ace))
                {
                    return std::unexpected(failure("state_acl_invalid"));
                }
                const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
                if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || (ace->Header.AceFlags & INHERIT_ONLY_ACE) != 0
                    || (ace->Mask != FILE_ALL_ACCESS && ace->Mask != GENERIC_ALL))
                {
                    return std::unexpected(failure("state_acl_not_private", ERROR_ACCESS_DENIED));
                }
                auto* sid = const_cast<DWORD*>(&ace->SidStart);
                if (EqualSid(sid, const_cast<std::byte*>(user_sid.data())))
                {
                    user_found = true;
                }
                else if (EqualSid(sid, const_cast<std::byte*>(system_sid.data())))
                {
                    system_found = true;
                }
                else
                {
                    return std::unexpected(failure("state_acl_not_private", ERROR_ACCESS_DENIED));
                }
            }
            if (!user_found || !system_found)
            {
                return std::unexpected(failure("state_acl_not_private", ERROR_ACCESS_DENIED));
            }
            return {};
        }

        engine::result<std::wstring> pin_directory(std::wstring_view path, bool create_private)
        {
            const std::wstring owned(path);
            if (create_private)
            {
                auto attributes = security_attributes();
                if (!CreateDirectoryW(owned.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
                {
                    return std::unexpected(failure("state_directory_create_failed"));
                }
            }
            // SECURITY: deny delete-sharing so every ancestor name stays bound for store lifetime.
            unique_handle handle(CreateFileW(owned.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (handle.get() == INVALID_HANDLE_VALUE)
            {
                return std::unexpected(failure("state_directory_open_failed"));
            }
            auto verified = verify_object(handle.get(), path, true);
            if (!verified)
            {
                return verified;
            }
            if (create_private)
            {
                const auto private_acl = verify_acl(handle.get());
                if (!private_acl)
                {
                    return std::unexpected(private_acl.error());
                }
            }
            pinned_directories.push_back(std::move(handle));
            return verified;
        }

        engine::result<unique_handle> open_file(std::wstring_view leaf, DWORD access, DWORD creation)
        {
            const auto path = root + L"\\" + std::wstring(leaf);
            auto attributes = security_attributes();
            unique_handle handle(CreateFileW(path.c_str(), access | READ_CONTROL | FILE_READ_ATTRIBUTES,
                0, &attributes, creation, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_WRITE_THROUGH, nullptr));
            if (handle.get() == INVALID_HANDLE_VALUE)
            {
                return std::unexpected(failure("state_file_open_failed"));
            }
            auto verified = verify_object(handle.get(), path, false);
            if (!verified)
            {
                return std::unexpected(verified.error());
            }
            const auto private_acl = verify_acl(handle.get());
            if (!private_acl)
            {
                return std::unexpected(private_acl.error());
            }
            return handle;
        }

        engine::result<void> remove_file(std::wstring_view leaf, bool missing_ok)
        {
            auto handle = open_file(leaf, DELETE, OPEN_EXISTING);
            if (!handle)
            {
                if (missing_ok && handle.error().native_code == ERROR_FILE_NOT_FOUND)
                {
                    return {};
                }
                return std::unexpected(handle.error());
            }
            FILE_DISPOSITION_INFO information{TRUE};
            if (!SetFileInformationByHandle(handle->get(), FileDispositionInfo, &information, sizeof(information)))
            {
                return std::unexpected(failure("state_remove_failed"));
            }
            return {};
        }

        engine::result<void> replace_file(std::wstring_view source, std::wstring_view destination)
        {
            // SECURITY: Source and optional destination must be private, single-link regular files.
            // App lock excludes cooperating writers; current-user/SYSTEM are trusted principals.
            auto source_handle = open_file(source, GENERIC_READ, OPEN_EXISTING);
            if (!source_handle)
            {
                return std::unexpected(source_handle.error());
            }
            auto destination_handle = open_file(destination, GENERIC_READ, OPEN_EXISTING);
            if (!destination_handle && destination_handle.error().native_code != ERROR_FILE_NOT_FOUND)
            {
                return std::unexpected(destination_handle.error());
            }
            source_handle->reset();
            if (destination_handle)
            {
                destination_handle->reset();
            }
            const auto source_path = root + L"\\" + std::wstring(source);
            const auto destination_path = root + L"\\" + std::wstring(destination);
            if (!MoveFileExW(source_path.c_str(), destination_path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                return std::unexpected(failure("state_atomic_replace_failed"));
            }
            // CONTRACT: same-directory rename plus write-through/flush is best Windows file-API
            // durability evidence; device firmware/power-loss behavior remains a platform test.
            auto committed = open_file(destination, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
            if (!committed)
            {
                return std::unexpected(committed.error());
            }
            if (!FlushFileBuffers(committed->get()))
            {
                return std::unexpected(failure("state_commit_flush_failed"));
            }
            return {};
        }

        engine::result<std::vector<checkpoint_info>> enumerate_checkpoints()
        {
            auto budget = checkpoint_budget();
            if (!budget)
            {
                return std::unexpected(budget.error());
            }
            // Account vector growth and identifier storage instead of using a
            // serialized target-count field as an in-memory directory bound.
            constexpr std::size_t entry_bytes = 2 * (sizeof(checkpoint_info) + 128);
            auto maximum_entries = *budget / entry_bytes;
            WIN32_FIND_DATAW data{};
            const auto search = root + L"\\*.checkpoint";
            const HANDLE raw = FindFirstFileW(search.c_str(), &data);
            if (raw == INVALID_HANDLE_VALUE)
            {
                if (GetLastError() == ERROR_FILE_NOT_FOUND)
                {
                    return std::vector<checkpoint_info>{};
                }
                return std::unexpected(failure("state_enumeration_failed"));
            }
            struct find_closer
            {
                HANDLE value;
                ~find_closer()
                {
                    FindClose(value);
                }
            } closer{raw};
            std::vector<checkpoint_info> entries;
            do
            {
                const std::wstring_view name(data.cFileName);
                constexpr std::wstring_view suffix{L".checkpoint"};
                if (!name.ends_with(suffix))
                {
                    continue;
                }
                const auto wide_id = name.substr(0, name.size() - suffix.size());
                if (!std::ranges::all_of(wide_id, [](wchar_t character)
                {
                    return (character >= L'0' && character <= L'9')
                        || (character >= L'a' && character <= L'f');
                }))
                {
                    return std::unexpected(failure("state_non_ascii_leaf", ERROR_INVALID_DATA));
                }
                // INVARIANT: The preceding alphabet check restricts every code unit to ASCII hex.
                std::string id;
                id.reserve(wide_id.size());
                for (const wchar_t character : wide_id)
                {
                    id.push_back(static_cast<char>(character));
                }
                if (!valid_job_id(id))
                {
                    return std::unexpected(failure("state_directory_unexpected_entry", ERROR_INVALID_DATA));
                }
                if (entries.size() % 1024 == 0)
                {
                    budget = checkpoint_budget();
                    if (!budget)
                    {
                        return std::unexpected(budget.error());
                    }
                    maximum_entries = *budget / entry_bytes;
                }
                if (entries.size() >= maximum_entries)
                {
                    return std::unexpected(failure("state_resource_budget_exhausted", ERROR_NOT_ENOUGH_MEMORY));
                }
                auto handle = open_file(name, GENERIC_READ, OPEN_EXISTING);
                if (!handle)
                {
                    return std::unexpected(handle.error());
                }
                FILETIME modified{};
                LARGE_INTEGER length{};
                if (!GetFileTime(handle->get(), nullptr, nullptr, &modified)
                    || !GetFileSizeEx(handle->get(), &length) || length.QuadPart < 0)
                {
                    return std::unexpected(failure("state_metadata_failed"));
                }
                entries.push_back({id, static_cast<std::uint64_t>(length.QuadPart), filetime_value(modified)});
            } while (FindNextFileW(raw, &data));
            if (GetLastError() != ERROR_NO_MORE_FILES)
            {
                return std::unexpected(failure("state_enumeration_failed"));
            }
            std::ranges::sort(entries, {}, &checkpoint_info::modified_filetime);
            return entries;
        }

        engine::result<void> cleanup_temporaries()
        {
            const auto pattern = root + L"\\pending_*.tmp";
            WIN32_FIND_DATAW data{};
            const auto raw = FindFirstFileW(pattern.c_str(), &data);
            if (raw == INVALID_HANDLE_VALUE)
            {
                if (GetLastError() == ERROR_FILE_NOT_FOUND)
                {
                    return {};
                }
                return std::unexpected(failure("state_temp_enumeration_failed"));
            }
            struct find_closer
            {
                HANDLE value;
                ~find_closer()
                {
                    FindClose(value);
                }
            } closer{raw};
            do
            {
                const std::wstring_view leaf(data.cFileName);
                if (leaf.size() != 44 || !leaf.starts_with(L"pending_") || !leaf.ends_with(L".tmp"))
                {
                    return std::unexpected(failure("state_temp_name_invalid", ERROR_INVALID_DATA));
                }
                const auto wide_id = leaf.substr(8, 32);
                if (!std::ranges::all_of(wide_id, [](wchar_t character)
                {
                    return (character >= L'0' && character <= L'9')
                        || (character >= L'a' && character <= L'f');
                }))
                {
                    return std::unexpected(failure("state_non_ascii_leaf", ERROR_INVALID_DATA));
                }
                // INVARIANT: The preceding alphabet check restricts every code unit to ASCII hex.
                std::string id;
                id.reserve(wide_id.size());
                for (const wchar_t character : wide_id)
                {
                    id.push_back(static_cast<char>(character));
                }
                if (!valid_job_id(id))
                {
                    return std::unexpected(failure("state_temp_name_invalid", ERROR_INVALID_DATA));
                }
                auto removed = remove_file(leaf, false);
                if (!removed)
                {
                    return removed;
                }
            } while (FindNextFileW(raw, &data));
            if (GetLastError() != ERROR_NO_MORE_FILES)
            {
                return std::unexpected(failure("state_temp_enumeration_failed"));
            }
            return {};
        }

        engine::result<std::uint64_t> recover_log_tail(HANDLE handle, std::uint64_t size)
        {
            if (size == 0)
            {
                return 0;
            }
            if (size > settings.log_rotation_bytes + 4096)
            {
                return std::unexpected(failure("state_log_size_limit", ERROR_FILE_TOO_LARGE));
            }
            LARGE_INTEGER last{};
            last.QuadPart = -1;
            if (!SetFilePointerEx(handle, last, nullptr, FILE_END))
            {
                return std::unexpected(failure("state_log_seek_failed"));
            }
            char tail{};
            DWORD received{};
            if (!ReadFile(handle, &tail, 1, &received, nullptr) || received != 1)
            {
                return std::unexpected(failure("state_log_read_failed"));
            }
            if (tail == '\n')
            {
                return 0;
            }
            LARGE_INTEGER beginning{};
            if (!SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN))
            {
                return std::unexpected(failure("state_log_seek_failed"));
            }
            auto bytes = read_all(handle, settings.log_rotation_bytes + 4096);
            if (!bytes)
            {
                return std::unexpected(bytes.error());
            }
            auto kept = bytes->size();
            while (kept > 0 && (*bytes)[kept - 1] != std::byte{'\n'})
            {
                --kept;
            }
            LARGE_INTEGER end{};
            end.QuadPart = static_cast<LONGLONG>(kept);
            if (!SetFilePointerEx(handle, end, nullptr, FILE_BEGIN) || !SetEndOfFile(handle)
                || !FlushFileBuffers(handle))
            {
                return std::unexpected(failure("state_log_recovery_failed"));
            }
            return size - kept;
        }

        engine::result<void> cleanup_expired()
        {
            const auto now = now_filetime();
            for (std::uint32_t index{}; index <= settings.retained_log_files; ++index)
            {
                const auto leaf = index == 0 ? std::wstring(L"events.jsonl")
                    : L"events_" + std::to_wstring(index) + L".jsonl";
                auto file = open_file(leaf, GENERIC_READ, OPEN_EXISTING);
                if (!file)
                {
                    if (file.error().native_code == ERROR_FILE_NOT_FOUND)
                    {
                        continue;
                    }
                    return std::unexpected(file.error());
                }
                FILETIME modified{};
                if (!GetFileTime(file->get(), nullptr, nullptr, &modified))
                {
                    return std::unexpected(failure("state_metadata_failed"));
                }
                file->reset();
                if (expired(filetime_value(modified), settings.log_retention_days, now))
                {
                    auto removed = remove_file(leaf, false);
                    if (!removed)
                    {
                        return removed;
                    }
                }
            }
            if (settings.checkpoint_retention_days != 0)
            {
                auto entries = enumerate_checkpoints();
                if (!entries)
                {
                    return std::unexpected(entries.error());
                }
                for (const auto& entry : *entries)
                {
                    if (expired(entry.modified_filetime, settings.checkpoint_retention_days, now))
                    {
                        auto removed = remove_file(widen_ascii(entry.job_id) + L".checkpoint", false);
                        if (!removed)
                        {
                            return removed;
                        }
                    }
                }
            }
            return {};
        }

        engine::result<void> rotate_logs()
        {
            for (std::uint32_t index = settings.retained_log_files; index > 0; --index)
            {
                const auto destination = L"events_" + std::to_wstring(index) + L".jsonl";
                const auto source = index == 1 ? std::wstring(L"events.jsonl")
                    : L"events_" + std::to_wstring(index - 1) + L".jsonl";
                auto source_file = open_file(source, GENERIC_READ, OPEN_EXISTING);
                if (!source_file)
                {
                    if (source_file.error().native_code == ERROR_FILE_NOT_FOUND)
                    {
                        continue;
                    }
                    return std::unexpected(source_file.error());
                }
                source_file->reset();
                auto moved = replace_file(source, destination);
                if (!moved)
                {
                    return moved;
                }
            }
            return {};
        }
    };

    struct state_store::implementation::staging_file final : quick::store::random_access_file
    {
        std::shared_ptr<implementation> owner;
        unique_handle file;
        mutable std::mutex mutex;

        staging_file(std::shared_ptr<implementation> state, unique_handle value)
            : owner(std::move(state)), file(std::move(value))
        {
        }

        engine::result<void> seek(std::uint64_t offset)
        {
            if (offset > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)()))
            {
                return std::unexpected(failure("staging_offset_invalid", ERROR_INVALID_PARAMETER));
            }
            LARGE_INTEGER position{};
            position.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(file.get(), position, nullptr, FILE_BEGIN))
            {
                return std::unexpected(failure("staging_seek_failed"));
            }
            return {};
        }

        engine::result<void> check_range(std::uint64_t offset, std::size_t length)
        {
            const auto limit = static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)());
            if (offset > limit || length > limit - offset)
            {
                return std::unexpected(failure("staging_range_invalid", ERROR_INVALID_PARAMETER));
            }
            return {};
        }

        engine::result<void> read_at(std::uint64_t offset, std::span<std::byte> output) override
        {
            const std::scoped_lock lock(mutex);
            auto positioned = check_range(offset, output.size());
            if (positioned)
            {
                positioned = seek(offset);
            }
            if (!positioned)
            {
                return positioned;
            }
            std::size_t done{};
            while (done < output.size())
            {
                const auto wanted = static_cast<DWORD>((std::min)(output.size() - done,
                    static_cast<std::size_t>(1024 * 1024)));
                DWORD received{};
                if (!ReadFile(file.get(), output.data() + done, wanted, &received, nullptr))
                {
                    return std::unexpected(failure("staging_read_failed"));
                }
                if (received == 0 || received > wanted)
                {
                    return std::unexpected(failure("staging_read_short", ERROR_HANDLE_EOF));
                }
                done += received;
            }
            return {};
        }

        engine::result<void> write_locked(std::span<const std::byte> input)
        {
            std::size_t done{};
            while (done < input.size())
            {
                const auto wanted = static_cast<DWORD>((std::min)(input.size() - done,
                    static_cast<std::size_t>(1024 * 1024)));
                DWORD written{};
                if (!WriteFile(file.get(), input.data() + done, wanted, &written, nullptr))
                {
                    return std::unexpected(failure("staging_write_failed"));
                }
                if (written == 0 || written > wanted)
                {
                    return std::unexpected(failure("staging_write_no_progress", ERROR_WRITE_FAULT));
                }
                done += written;
            }
            return {};
        }

        engine::result<void> write_at(std::uint64_t offset, std::span<const std::byte> input) override
        {
            const std::scoped_lock lock(mutex);
            auto positioned = check_range(offset, input.size());
            if (positioned)
            {
                positioned = seek(offset);
            }
            if (!positioned)
            {
                return positioned;
            }
            return write_locked(input);
        }

        engine::result<void> resize(std::uint64_t bytes) override
        {
            const std::scoped_lock lock(mutex);
            auto valid = check_range(bytes, 0);
            if (!valid)
            {
                return valid;
            }
            LARGE_INTEGER previous{};
            if (!GetFileSizeEx(file.get(), &previous) || previous.QuadPart < 0)
            {
                return std::unexpected(failure("staging_size_failed"));
            }
            const auto old_size = static_cast<std::uint64_t>(previous.QuadPart);
            if (bytes > old_size)
            {
                FILE_ALLOCATION_INFO allocation{};
                allocation.AllocationSize.QuadPart = static_cast<LONGLONG>(bytes);
                if (!SetFileInformationByHandle(file.get(), FileAllocationInfo, &allocation, sizeof(allocation)))
                {
                    const auto native = GetLastError();
                    if (native != ERROR_INVALID_FUNCTION && native != ERROR_NOT_SUPPORTED &&
                        native != ERROR_INVALID_PARAMETER)
                    {
                        return std::unexpected(failure("staging_allocation_failed", native));
                    }
                }
                valid = seek(old_size);
                if (!valid)
                {
                    return valid;
                }
                // Actual bounded writes reserve every outcome byte. Merely
                // extending EOF or setting valid-data length is insufficient.
                const std::array<std::byte, 65536> zeros{};
                auto remaining = bytes - old_size;
                while (remaining != 0)
                {
                    const auto count = static_cast<std::size_t>((std::min)(remaining,
                        static_cast<std::uint64_t>(zeros.size())));
                    valid = write_locked(std::span(zeros).first(count));
                    if (!valid)
                    {
                        return valid;
                    }
                    remaining -= count;
                }
            }
            valid = seek(bytes);
            if (!valid)
            {
                return valid;
            }
            if (!SetEndOfFile(file.get()))
            {
                return std::unexpected(failure("staging_resize_failed"));
            }
            FILE_STANDARD_INFO allocated{};
            if (!GetFileInformationByHandleEx(file.get(), FileStandardInfo, &allocated, sizeof(allocated)) ||
                allocated.AllocationSize.QuadPart < 0 ||
                static_cast<std::uint64_t>(allocated.AllocationSize.QuadPart) < bytes)
            {
                return std::unexpected(failure("staging_reservation_not_established", ERROR_DISK_FULL));
            }
            return {};
        }

        engine::result<void> flush() override
        {
            const std::scoped_lock lock(mutex);
            if (!FlushFileBuffers(file.get()))
            {
                return std::unexpected(failure("staging_flush_failed"));
            }
            return {};
        }

        engine::result<std::uint64_t> size() const override
        {
            const std::scoped_lock lock(mutex);
            LARGE_INTEGER length{};
            if (!GetFileSizeEx(file.get(), &length) || length.QuadPart < 0)
            {
                return std::unexpected(failure("staging_size_failed"));
            }
            return static_cast<std::uint64_t>(length.QuadPart);
        }
    };

    struct state_store::implementation::staging_factory final : quick::store::file_factory
    {
        std::shared_ptr<implementation> owner;
        std::mutex mutex;
        std::map<std::string, std::weak_ptr<staging_file>, std::less<>> created;

        explicit staging_factory(std::shared_ptr<implementation> value) : owner(std::move(value))
        {
        }

        engine::result<void> check_ancestry() const
        {
            for (const auto& directory : owner->pinned_directories)
            {
                FILE_ATTRIBUTE_TAG_INFO tag{};
                FILE_STANDARD_INFO standard{};
                if (!GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo, &tag, sizeof(tag)) ||
                    !GetFileInformationByHandleEx(directory.get(), FileStandardInfo, &standard, sizeof(standard)))
                {
                    return std::unexpected(failure("staging_ancestor_query_failed"));
                }
                if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                    !standard.Directory || standard.DeletePending)
                {
                    return std::unexpected(failure("staging_ancestor_changed", ERROR_ACCESS_DENIED));
                }
            }
            return owner->verify_acl(owner->pinned_directories.back().get());
        }

        engine::result<std::shared_ptr<quick::store::random_access_file>> create_private(
            std::string_view name) override
        {
            if (name.empty() || name.size() > 255 || name == "." || name == ".." ||
                name.back() == '.' || !std::ranges::all_of(name, [](char character)
                {
                    return (character >= 'a' && character <= 'z') ||
                        (character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.';
                }))
            {
                return std::unexpected(failure("staging_leaf_invalid", ERROR_INVALID_NAME));
            }
            const std::scoped_lock lock(mutex);
            if (created.contains(name))
            {
                return std::unexpected(failure("staging_leaf_already_owned", ERROR_ALREADY_EXISTS));
            }
            auto ancestors = check_ancestry();
            if (!ancestors)
            {
                return std::unexpected(ancestors.error());
            }
            const auto path = owner->root + L"\\" + widen_ascii(name);
            auto attributes = owner->security_attributes();
            unique_handle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
                0, &attributes, CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS |
                    FILE_FLAG_DELETE_ON_CLOSE, nullptr));
            if (file.get() == INVALID_HANDLE_VALUE)
            {
                return std::unexpected(failure("staging_create_failed"));
            }
            auto canonical = final_path(file.get());
            FILE_ATTRIBUTE_TAG_INFO tag{};
            FILE_STANDARD_INFO standard{};
            if (!canonical || !equal_path(*canonical, path) ||
                !GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &tag, sizeof(tag)) ||
                !GetFileInformationByHandleEx(file.get(), FileStandardInfo, &standard, sizeof(standard)) ||
                (tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_COMPRESSED |
                    FILE_ATTRIBUTE_SPARSE_FILE)) != 0 || standard.Directory ||
                standard.NumberOfLinks != 1)
            {
                return std::unexpected(failure("staging_created_object_unsafe", ERROR_ACCESS_DENIED));
            }
            ancestors = check_ancestry();
            if (!ancestors)
            {
                return std::unexpected(ancestors.error());
            }
            auto acl = owner->verify_acl(file.get());
            if (!acl)
            {
                return std::unexpected(acl.error());
            }
            auto value = std::make_shared<staging_file>(owner, std::move(file));
            created.emplace(std::string(name), value);
            return std::shared_ptr<quick::store::random_access_file>(std::move(value));
        }

        engine::result<void> remove_private(std::string_view name) override
        {
            const std::scoped_lock lock(mutex);
            const auto found = created.find(name);
            if (found == created.end())
            {
                return std::unexpected(failure("staging_leaf_not_owned", ERROR_INVALID_PARAMETER));
            }
            // The created handle already owns DELETE_ON_CLOSE. Never reopen or
            // delete a pathname: the last shared file owner releases allocation.
            created.erase(found);
            return {};
        }

        engine::result<std::uint64_t> available_bytes() override
        {
            auto valid = check_ancestry();
            if (!valid)
            {
                return std::unexpected(valid.error());
            }
            ULARGE_INTEGER available{};
            if (!GetDiskFreeSpaceExW(owner->root.c_str(), &available, nullptr, nullptr))
            {
                return std::unexpected(failure("staging_disk_space_failed"));
            }
            return available.QuadPart;
        }
    };

    engine::result<std::shared_ptr<quick::store::file_factory>> state_store::staging_files()
    {
        auto factory = std::make_shared<implementation::staging_factory>(state_);
        const auto valid = factory->check_ancestry();
        if (!valid)
        {
            return std::unexpected(valid.error());
        }
        return std::shared_ptr<quick::store::file_factory>(std::move(factory));
    }

    state_store::state_store(std::shared_ptr<implementation> state) noexcept
        : state_(std::move(state))
    {
    }

    state_store::~state_store() = default;

    engine::result<std::unique_ptr<state_store>> state_store::open(store_options settings)
    {
        return open_impl({}, settings);
    }

    engine::result<std::unique_ptr<state_store>> state_store::open_at(
        std::wstring_view private_directory, store_options settings)
    {
        if (private_directory.empty())
        {
            return std::unexpected(failure("state_invalid_root", ERROR_INVALID_PARAMETER));
        }
        return open_impl(private_directory, settings);
    }

    engine::result<std::unique_ptr<state_store>> state_store::open_impl(
        std::wstring_view private_directory, store_options settings)
    {
        if (!safe_options(settings))
        {
            return std::unexpected(failure("state_invalid_options", ERROR_INVALID_PARAMETER));
        }
        auto state = std::make_shared<implementation>();
        state->settings = settings;
        HANDLE raw_token{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        {
            return std::unexpected(failure("state_token_failed"));
        }
        unique_handle token(raw_token);
        DWORD required{};
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &required);
        if (required == 0 || required > 65536)
        {
            return std::unexpected(failure("state_token_failed"));
        }
        std::vector<std::byte> token_information(required);
        if (!GetTokenInformation(token.get(), TokenUser, token_information.data(), required, &required))
        {
            return std::unexpected(failure("state_token_failed"));
        }
        const auto* user = reinterpret_cast<const TOKEN_USER*>(token_information.data());
        if (!IsValidSid(user->User.Sid))
        {
            return std::unexpected(failure("state_invalid_sid", ERROR_INVALID_SID));
        }
        state->user_sid.resize(GetLengthSid(user->User.Sid));
        if (!CopySid(static_cast<DWORD>(state->user_sid.size()), state->user_sid.data(), user->User.Sid))
        {
            return std::unexpected(failure("state_sid_copy_failed"));
        }
        DWORD system_size = static_cast<DWORD>(state->system_sid.size());
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, state->system_sid.data(), &system_size))
        {
            return std::unexpected(failure("state_system_sid_failed"));
        }
        LPWSTR raw_sid{};
        if (!ConvertSidToStringSidW(user->User.Sid, &raw_sid))
        {
            return std::unexpected(failure("state_sid_text_failed"));
        }
        local_memory sid_text(raw_sid);
        const std::wstring descriptor_text = L"O:" + std::wstring(raw_sid)
            + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + raw_sid + L")";
        PSECURITY_DESCRIPTOR raw_descriptor{};
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor_text.c_str(),
            SDDL_REVISION_1, &raw_descriptor, nullptr))
        {
            return std::unexpected(failure("state_descriptor_failed"));
        }
        state->descriptor.reset(raw_descriptor);
        std::wstring base;
        if (private_directory.empty())
        {
            PWSTR folder{};
            const HRESULT folder_status = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT,
                nullptr, &folder);
            if (FAILED(folder_status))
            {
                return std::unexpected(failure("state_localappdata_failed", static_cast<DWORD>(folder_status)));
            }
            base = folder;
            CoTaskMemFree(folder);
        }
        else
        {
            const auto separator = private_directory.find_last_of(L'\\');
            if (separator == std::wstring_view::npos || separator < 2
                || private_directory.size() > 32000 || private_directory.find(L'\0') != std::wstring_view::npos)
            {
                return std::unexpected(failure("state_invalid_root", ERROR_INVALID_PARAMETER));
            }
            const auto leaf = private_directory.substr(separator + 1);
            if (leaf.empty() || leaf == L"." || leaf == L".." || leaf.back() == L'.' || leaf.back() == L' '
                || leaf.find_first_of(L":/<>\"|?*") != std::wstring_view::npos)
            {
                return std::unexpected(failure("state_invalid_root", ERROR_INVALID_PARAMETER));
            }
            state->root = private_directory;
            base = private_directory.substr(0, separator == 2 ? 3 : separator);
        }
        if (base.size() < 3 || base.size() > 32000 || base[1] != L':' || base[2] != L'\\'
            || !((base[0] >= L'A' && base[0] <= L'Z') || (base[0] >= L'a' && base[0] <= L'z')))
        {
            return std::unexpected(failure("state_unsafe_root", ERROR_ACCESS_DENIED));
        }
        while (base.size() > 3 && base.back() == L'\\')
        {
            base.pop_back();
        }
        if (GetDriveTypeW(base.substr(0, 3).c_str()) != DRIVE_FIXED)
        {
            return std::unexpected(failure("state_root_not_fixed_local", ERROR_ACCESS_DENIED));
        }
        auto pinned = state->pin_directory(base.substr(0, 3), false);
        if (!pinned)
        {
            return std::unexpected(pinned.error());
        }
        std::wstring canonical_base = *pinned;
        std::size_t offset = 3;
        while (offset < base.size())
        {
            auto end = base.find(L'\\', offset);
            if (end == std::wstring::npos)
            {
                end = base.size();
            }
            const auto component = std::wstring_view(base).substr(offset, end - offset);
            if (component.empty() || component == L"." || component == L".."
                || component.back() == L'.' || component.back() == L' '
                || component.find_first_of(L":/<>\"|?*") != std::wstring_view::npos)
            {
                return std::unexpected(failure("state_unsafe_root", ERROR_ACCESS_DENIED));
            }
            pinned = state->pin_directory(append_component(canonical_base, component), false);
            if (!pinned)
            {
                return std::unexpected(pinned.error());
            }
            canonical_base = *pinned;
            offset = end + 1;
        }
        if (private_directory.empty())
        {
            const auto app = append_component(canonical_base, L"windows_secure_erase");
            pinned = state->pin_directory(app, true);
            if (!pinned)
            {
                return std::unexpected(pinned.error());
            }
            state->root = append_component(*pinned, L"v1");
        }
        else
        {
            const auto separator = private_directory.find_last_of(L'\\');
            state->root = append_component(canonical_base, private_directory.substr(separator + 1));
        }
        pinned = state->pin_directory(state->root, true);
        if (!pinned)
        {
            return std::unexpected(pinned.error());
        }
        state->root = *pinned;
        auto lock = state->open_file(L"store.lock", GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS);
        if (!lock)
        {
            return std::unexpected(failure("state_store_locked_or_unsafe", lock.error().native_code));
        }
        state->lock_file = std::move(*lock);
        auto cleanup = state->cleanup_temporaries();
        if (!cleanup)
        {
            return std::unexpected(cleanup.error());
        }
        cleanup = state->cleanup_expired();
        if (!cleanup)
        {
            return std::unexpected(cleanup.error());
        }
        return std::unique_ptr<state_store>(new state_store(std::move(state)));
    }

    engine::result<void> state_store::save(const engine::checkpoint& value)
    {
        std::scoped_lock lock(state_->mutex);
        const auto budget = checkpoint_budget();
        if (!budget)
        {
            return std::unexpected(budget.error());
        }
        auto plaintext = encode_checkpoint(value, *budget);
        if (!plaintext)
        {
            return std::unexpected(plaintext.error());
        }
        clear_bytes wipe{*plaintext};
        DATA_BLOB source{static_cast<DWORD>(plaintext->size()), reinterpret_cast<BYTE*>(plaintext->data())};
        // SECURITY: Bind encrypted checkpoint to its namespace leaf; swapping valid job blobs fails.
        const auto entropy_text = std::string("secure_erase.checkpoint.v1:") + value.plan.job_id;
        DATA_BLOB entropy{static_cast<DWORD>(entropy_text.size()),
            reinterpret_cast<BYTE*>(const_cast<char*>(entropy_text.data()))};
        protected_blob ciphertext;
        if (!CryptProtectData(&source, L"secure_erase.checkpoint.v1", &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &ciphertext.value))
        {
            return std::unexpected(failure("state_dpapi_protect_failed"));
        }
        constexpr std::size_t overhead_limit{1024 * 1024};
        if (ciphertext.value.cbData > *budget + overhead_limit)
        {
            return std::unexpected(failure("state_protected_size_limit", ERROR_FILE_TOO_LARGE));
        }
        std::array<std::byte, 16> random{};
        const auto status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random.data()),
            static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0)
        {
            return std::unexpected(failure("state_temp_random_failed", static_cast<DWORD>(status)));
        }
        constexpr std::wstring_view hex{L"0123456789abcdef"};
        std::wstring temporary{L"pending_"};
        for (const auto byte : random)
        {
            const auto numeric = std::to_integer<unsigned>(byte);
            temporary += hex[numeric >> 4];
            temporary += hex[numeric & 15];
        }
        temporary += L".tmp";
        auto output = state_->open_file(temporary, GENERIC_READ | GENERIC_WRITE, CREATE_NEW);
        if (!output)
        {
            return std::unexpected(output.error());
        }
        const auto written = write_all(output->get(), std::span(
            reinterpret_cast<const std::byte*>(ciphertext.value.pbData), ciphertext.value.cbData));
        output->reset();
        if (!written)
        {
            const auto removed = state_->remove_file(temporary, true);
            (void)removed;
            return written;
        }
        const auto committed = state_->replace_file(temporary, widen_ascii(value.plan.job_id) + L".checkpoint");
        if (!committed)
        {
            const auto removed = state_->remove_file(temporary, true);
            (void)removed;
        }
        return committed;
    }

    engine::result<engine::checkpoint> state_store::load(std::string_view job_id)
    {
        std::scoped_lock lock(state_->mutex);
        if (!valid_job_id(job_id))
        {
            return std::unexpected(failure("state_invalid_job_id", ERROR_INVALID_PARAMETER));
        }
        auto input = state_->open_file(widen_ascii(job_id) + L".checkpoint", GENERIC_READ, OPEN_EXISTING);
        if (!input)
        {
            return std::unexpected(input.error());
        }
        const auto budget = checkpoint_budget();
        if (!budget)
        {
            return std::unexpected(budget.error());
        }
        auto bytes = read_all(input->get(), *budget + 1024 * 1024);
        if (!bytes)
        {
            return std::unexpected(bytes.error());
        }
        DATA_BLOB source{static_cast<DWORD>(bytes->size()), reinterpret_cast<BYTE*>(bytes->data())};
        const auto entropy_text = std::string("secure_erase.checkpoint.v1:") + std::string(job_id);
        DATA_BLOB entropy{static_cast<DWORD>(entropy_text.size()),
            reinterpret_cast<BYTE*>(const_cast<char*>(entropy_text.data()))};
        protected_blob plaintext;
        if (!CryptUnprotectData(&source, nullptr, &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &plaintext.value))
        {
            return std::unexpected(failure("state_dpapi_integrity_or_identity_failed"));
        }
        auto decoded = decode_checkpoint(std::span(
            reinterpret_cast<const std::byte*>(plaintext.value.pbData), plaintext.value.cbData), *budget);
        if (!decoded)
        {
            return std::unexpected(decoded.error());
        }
        if (decoded->plan.job_id != job_id)
        {
            clear_sensitive(*decoded);
            return std::unexpected(failure("state_job_identity_mismatch", ERROR_INVALID_DATA));
        }
        return decoded;
    }

    engine::result<void> state_store::remove(std::string_view job_id)
    {
        std::scoped_lock lock(state_->mutex);
        if (!valid_job_id(job_id))
        {
            return std::unexpected(failure("state_invalid_job_id", ERROR_INVALID_PARAMETER));
        }
        // SECURITY: Unlink encrypted state; physical destruction of former DPAPI bytes is unprovable.
        return state_->remove_file(widen_ascii(job_id) + L".checkpoint", true);
    }

    engine::result<void> state_store::emit(const engine::event& value)
    {
        return emit_batch(std::span<const engine::event>(&value, 1));
    }

    engine::result<void> state_store::emit_batch(std::span<const engine::event> values)
    {
        if (values.empty())
        {
            return {};
        }
        if (values.size() > 64)
        {
            return std::unexpected(failure("state_event_batch_limit", ERROR_INVALID_PARAMETER));
        }
        std::scoped_lock lock(state_->mutex);
        std::string line;
        // SECURITY: Reject the complete chunk before opening or rotating the log.
        // Leave bounded headroom for an existing torn-tail recovery record.
        const auto limit = static_cast<std::size_t>(state_->settings.log_rotation_bytes - 4096);
        for (const auto& value : values)
        {
            auto record = event_json(value, now_filetime());
            if (record.empty())
            {
                return std::unexpected(failure("state_invalid_event", ERROR_INVALID_DATA));
            }
            if (record.size() > limit - line.size())
            {
                return std::unexpected(failure("state_event_batch_limit", ERROR_BUFFER_OVERFLOW));
            }
            line += record;
        }
        auto output = state_->open_file(L"events.jsonl", GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS);
        if (!output)
        {
            return std::unexpected(output.error());
        }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(output->get(), &size) || size.QuadPart < 0)
        {
            return std::unexpected(failure("state_log_size_failed"));
        }
        const auto recovered = state_->recover_log_tail(output->get(), static_cast<std::uint64_t>(size.QuadPart));
        if (!recovered)
        {
            return std::unexpected(recovered.error());
        }
        if (*recovered != 0)
        {
            engine::event recovery{"log_torn_tail_removed", {}, {}, *recovered,
                static_cast<std::uint64_t>(size.QuadPart), 0};
            line = event_json(recovery, now_filetime()) + line;
            size.QuadPart -= static_cast<LONGLONG>(*recovered);
        }
        if (static_cast<std::uint64_t>(size.QuadPart) + line.size() > state_->settings.log_rotation_bytes)
        {
            output->reset();
            auto rotated = state_->rotate_logs();
            if (!rotated)
            {
                return rotated;
            }
            output = state_->open_file(L"events.jsonl", GENERIC_READ | GENERIC_WRITE, CREATE_NEW);
            if (!output)
            {
                return std::unexpected(output.error());
            }
        }
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(output->get(), zero, nullptr, FILE_END))
        {
            return std::unexpected(failure("state_log_seek_failed"));
        }
        return write_all(output->get(), std::as_bytes(std::span(line.data(), line.size())));
    }

    engine::result<std::vector<checkpoint_info>> state_store::list_checkpoints()
    {
        std::scoped_lock lock(state_->mutex);
        return state_->enumerate_checkpoints();
    }

    engine::result<std::string> state_store::read_history(std::size_t maximum_bytes)
    {
        std::scoped_lock lock(state_->mutex);
        if (maximum_bytes == 0 || maximum_bytes > 16 * 1024 * 1024)
        {
            return std::unexpected(failure("state_history_limit", ERROR_INVALID_PARAMETER));
        }
        // CONTRACT: Gather newest bounded records, then present them in chronological order.
        std::vector<std::string> pieces;
        std::size_t remaining = maximum_bytes;
        for (std::uint32_t index{}; index <= state_->settings.retained_log_files && remaining != 0; ++index)
        {
            const auto leaf = index == 0 ? std::wstring(L"events.jsonl")
                : L"events_" + std::to_wstring(index) + L".jsonl";
            auto input = state_->open_file(leaf, GENERIC_READ, OPEN_EXISTING);
            if (!input)
            {
                if (input.error().native_code == ERROR_FILE_NOT_FOUND)
                {
                    continue;
                }
                return std::unexpected(input.error());
            }
            auto bytes = read_all(input->get(), state_->settings.log_rotation_bytes + 4096);
            if (!bytes)
            {
                return std::unexpected(bytes.error());
            }
            std::string text;
            if (!bytes->empty())
            {
                text.assign(reinterpret_cast<const char*>(bytes->data()), bytes->size());
            }
            if (!valid_utf8(text) || (!text.empty() && text.back() != '\n'))
            {
                return std::unexpected(failure("state_history_incomplete", ERROR_INVALID_DATA));
            }
            if (text.size() > remaining)
            {
                const auto start = text.find('\n', text.size() - remaining);
                text = start == std::string::npos ? std::string{} : text.substr(start + 1);
            }
            remaining -= text.size();
            pieces.push_back(std::move(text));
        }
        std::string history;
        history.reserve(maximum_bytes - remaining);
        for (auto iterator = pieces.rbegin(); iterator != pieces.rend(); ++iterator)
        {
            history += *iterator;
        }
        return history;
    }

    const std::wstring& state_store::root_path() const noexcept
    {
        return state_->root;
    }
}
