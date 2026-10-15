module;

// INTEROP: Windows SDK C declarations remain in the global module fragment.
#include <Windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sfc.h>
#include <winioctl.h>
#include <winsvc.h>
#include <psapi.h>
#include <pdh.h>
#include <pdhmsg.h>
// INTEROP: import std cannot export macros; offsetof validates the SDK trailing array layout.
#include <stddef.h>

module secure_erase.windows_backend;

import std;
import secure_erase.model;
import secure_erase.platform;
import secure_erase.retained_copies;
import secure_erase.quick_delete;

namespace secure_erase::engine
{
namespace
{
    constexpr auto case_sensitive_info_class = FileCaseSensitiveInfo;

    constexpr std::size_t maximum_depth = 256;
    constexpr DWORD maximum_metadata = 1024 * 1024;

    error fail(std::string code, DWORD native = GetLastError())
    {
        const bool device = native == ERROR_DEVICE_NOT_CONNECTED || native == ERROR_IO_DEVICE ||
            native == ERROR_CRC || native == ERROR_NOT_READY || native == ERROR_GEN_FAILURE;
        return {std::move(code), native, device};
    }

    class handle
    {
    public:
        explicit handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value)
        {
        }

        ~handle()
        {
            reset();
        }

        handle(handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE))
        {
        }

        handle& operator=(handle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
            }
            return *this;
        }

        handle(const handle&) = delete;
        handle& operator=(const handle&) = delete;

        HANDLE get() const noexcept
        {
            return value_;
        }

        explicit operator bool() const noexcept
        {
            return value_ != INVALID_HANDLE_VALUE && value_ != nullptr;
        }

        void reset() noexcept
        {
            if (*this)
            {
                CloseHandle(value_);
                value_ = INVALID_HANDLE_VALUE;
            }
        }

    private:
        HANDLE value_;
    };

    struct service_handle
    {
        SC_HANDLE value{};
        ~service_handle()
        {
            if (value != nullptr)
            {
                CloseServiceHandle(value);
            }
        }
    };

    bool equal_path(std::wstring_view left, std::wstring_view right)
    {
        return std::in_range<int>(left.size()) && std::in_range<int>(right.size()) &&
            CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(),
                static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
    }

    bool within(std::wstring_view path, std::wstring_view root)
    {
        return path.size() >= root.size() && equal_path(path.substr(0, root.size()), root) &&
            (path.size() == root.size() || root.back() == L'\\' || path[root.size()] == L'\\');
    }

    result<std::wstring> wide(std::string_view value)
    {
        if (value.empty() || value.size() > 32767 * 4 || value.find('\0') != std::string_view::npos)
        {
            return std::unexpected(fail("invalid_utf8_path", ERROR_INVALID_NAME));
        }
        const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0);
        if (size <= 0)
        {
            return std::unexpected(fail("invalid_utf8_path"));
        }
        std::wstring result(static_cast<std::size_t>(size), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), size) != size)
        {
            return std::unexpected(fail("utf8_conversion_failed"));
        }
        return result;
    }

    result<std::string> utf8(std::wstring_view value)
    {
        if (value.empty())
        {
            return std::string{};
        }
        if (!std::in_range<int>(value.size()))
        {
            return std::unexpected(fail("utf16_too_long", ERROR_INVALID_NAME));
        }
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (size <= 0)
        {
            return std::unexpected(fail("invalid_utf16"));
        }
        std::string result(static_cast<std::size_t>(size), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) != size)
        {
            return std::unexpected(fail("utf16_conversion_failed"));
        }
        return result;
    }

    bool reserved(std::wstring_view component)
    {
        const auto dot = component.find(L'.');
        const auto stem = component.substr(0, dot);
        for (const auto* word : {L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$"})
        {
            if (equal_path(stem, word))
            {
                return true;
            }
        }
        return stem.size() == 4 && (equal_path(stem.substr(0, 3), L"COM") ||
            equal_path(stem.substr(0, 3), L"LPT")) &&
            ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == L'\u00b9' ||
                stem[3] == L'\u00b2' || stem[3] == L'\u00b3');
    }

    result<std::wstring> absolute(std::wstring_view input)
    {
        if (input.starts_with(L"\\\\?\\"))
        {
            input.remove_prefix(4);
        }
        if (input.empty() || input.size() > 32760 || input.find(L'\0') != input.npos ||
            input.starts_with(L"\\\\") || input.starts_with(L"\\??\\"))
        {
            return std::unexpected(fail("unsupported_path_namespace", ERROR_INVALID_NAME));
        }
        std::wstring path(input);
        std::replace(path.begin(), path.end(), L'/', L'\\');
        for (std::size_t index = 0; index < path.size(); ++index)
        {
            if (path[index] < 32 || path[index] == L'*' || path[index] == L'?' ||
                (path[index] == L':' && index != 1))
            {
                return std::unexpected(fail("invalid_path_component", ERROR_INVALID_NAME));
            }
        }
        thread_local std::array<wchar_t, 32768> buffer{};
        const DWORD count = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (count == 0 || count >= buffer.size())
        {
            return std::unexpected(fail("path_normalization_failed"));
        }
        path.assign(buffer.data(), count);
        while (path.size() > 3 && path.back() == L'\\')
        {
            path.pop_back();
        }
        if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' ||
            !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
        {
            return std::unexpected(fail("local_drive_path_required", ERROR_INVALID_NAME));
        }
        for (std::size_t begin = 3; begin < path.size();)
        {
            const auto end = path.find(L'\\', begin);
            const auto component = std::wstring_view(path).substr(begin,
                end == path.npos ? path.size() - begin : end - begin);
            if (component.empty() || reserved(component) || component.back() == L' ' || component.back() == L'.')
            {
                return std::unexpected(fail("ambiguous_path_component", ERROR_INVALID_NAME));
            }
            begin = end == path.npos ? path.size() : end + 1;
        }
        return L"\\\\?\\" + path;
    }

    result<std::wstring> final_name(HANDLE file)
    {
        thread_local std::array<wchar_t, 32768> buffer{};
        const DWORD count = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (count == 0 || count >= buffer.size())
        {
            return std::unexpected(fail("final_name_failed"));
        }
        return absolute(std::wstring_view(buffer.data(), count));
    }

    result<std::wstring> canonical_protected_path(std::wstring path)
    {
        std::wstring missing;
        for (std::size_t depth = 0; depth <= maximum_depth; ++depth)
        {
            // SECURITY: Protected roots resolve aliases (including 8.3 and junctions); target
            // selection still rejects every reparse. Resolving here cannot mutate any object.
            handle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (file)
            {
                auto canonical = final_name(file.get());
                if (!canonical)
                {
                    return std::unexpected(canonical.error());
                }
                if (canonical->ends_with(L'\\') && missing.starts_with(L'\\'))
                {
                    return *canonical + missing.substr(1);
                }
                return *canonical + missing;
            }
            const DWORD native = GetLastError();
            if (native != ERROR_FILE_NOT_FOUND && native != ERROR_PATH_NOT_FOUND)
            {
                return std::unexpected(fail("protected_path_resolution_failed", native));
            }
            const auto separator = path.find_last_of(L'\\');
            if (separator < 6 || separator == path.npos)
            {
                return std::unexpected(fail("protected_path_root_unresolved", native));
            }
            missing = path.substr(separator) + missing;
            path.resize(separator == 6 ? 7 : separator);
        }
        return std::unexpected(fail("protected_path_depth_limit", ERROR_BUFFER_OVERFLOW));
    }

    std::string hex(std::span<const unsigned char> data)
    {
        constexpr std::string_view digits = "0123456789abcdef";
        std::string text;
        text.reserve(data.size() * 2);
        for (const auto value : data)
        {
            text.push_back(digits[value >> 4]);
            text.push_back(digits[value & 15]);
        }
        return text;
    }

    result<std::string> identity(HANDLE file)
    {
        FILE_ID_INFO info{};
        if (GetFileInformationByHandleEx(file, FileIdInfo, &info, sizeof(info)))
        {
            return std::to_string(info.VolumeSerialNumber) + ":id128:" + hex(info.FileId.Identifier);
        }
        const DWORD native = GetLastError();
        if (native != ERROR_INVALID_PARAMETER && native != ERROR_NOT_SUPPORTED && native != ERROR_INVALID_FUNCTION)
        {
            return std::unexpected(fail("file_identity_failed", native));
        }
        BY_HANDLE_FILE_INFORMATION fallback{};
        if (!GetFileInformationByHandle(file, &fallback))
        {
            return std::unexpected(fail("file_identity_fallback_failed"));
        }
        const std::uint64_t index = (static_cast<std::uint64_t>(fallback.nFileIndexHigh) << 32) |
            fallback.nFileIndexLow;
        if (index == 0)
        {
            return std::unexpected(fail("file_identity_unavailable", ERROR_NOT_SUPPORTED));
        }
        return std::to_string(fallback.dwVolumeSerialNumber) + ":id64:" + std::to_string(index);
    }

    result<std::vector<handle>> pin_ancestors(const std::wstring& path, bool exact_case = false)
    {
        std::vector<handle> held;
        for (std::size_t end = 7; end < path.size();)
        {
            const std::wstring part = path.substr(0, end);
            handle directory(CreateFileW(part.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT |
                    (exact_case ? FILE_FLAG_POSIX_SEMANTICS : 0), nullptr));
            if (!directory)
            {
                return std::unexpected(fail("ancestor_pin_failed"));
            }
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (!GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo, &info, sizeof(info)))
            {
                return std::unexpected(fail("ancestor_attributes_failed"));
            }
            if (!(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            {
                return std::unexpected(fail("reparse_ancestor_denied", ERROR_ACCESS_DENIED));
            }
            held.push_back(std::move(directory));
            if (held.size() > maximum_depth)
            {
                return std::unexpected(fail("path_depth_limit", ERROR_BUFFER_OVERFLOW));
            }
            const auto next = path.find(L'\\', end + 1);
            if (next == path.npos)
            {
                break;
            }
            end = next;
        }
        return held;
    }

    result<std::vector<stream_snapshot>> streams(HANDLE file, bool directory, std::wstring_view filesystem)
    {
        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)))
        {
            return std::unexpected(fail("stream_standard_info_failed"));
        }
        if (equal_path(filesystem, L"FAT32") || equal_path(filesystem, L"exFAT"))
        {
            if (directory)
            {
                return std::vector<stream_snapshot>{};
            }
            return std::vector<stream_snapshot>{{"", static_cast<std::uint64_t>(standard.EndOfFile.QuadPart)}};
        }
        DWORD size = 4096;
        for (; size <= maximum_metadata; size *= 2)
        {
            std::vector<std::byte> buffer(size);
            if (!GetFileInformationByHandleEx(file, FileStreamInfo, buffer.data(), size))
            {
                const DWORD native = GetLastError();
                if (native == ERROR_MORE_DATA || native == ERROR_INSUFFICIENT_BUFFER || native == ERROR_BAD_LENGTH)
                {
                    continue;
                }
                if (native == ERROR_HANDLE_EOF && directory)
                {
                    return std::vector<stream_snapshot>{};
                }
                return std::unexpected(fail("stream_enumeration_failed", native));
            }
            std::vector<stream_snapshot> output;
            std::size_t offset{};
            for (;;)
            {
                constexpr auto header = offsetof(FILE_STREAM_INFO, StreamName);
                if (offset > buffer.size() || buffer.size() - offset < header)
                {
                    return std::unexpected(fail("stream_metadata_invalid", ERROR_INVALID_DATA));
                }
                const auto* info = reinterpret_cast<const FILE_STREAM_INFO*>(buffer.data() + offset);
                if (info->StreamNameLength % sizeof(wchar_t) != 0 ||
                    info->StreamNameLength > buffer.size() - offset - header || info->StreamSize.QuadPart < 0)
                {
                    return std::unexpected(fail("stream_metadata_invalid", ERROR_INVALID_DATA));
                }
                const std::wstring_view name(info->StreamName, info->StreamNameLength / sizeof(wchar_t));
                if (!name.starts_with(L':') || !name.ends_with(L":$DATA") || name.find(L'\0') != name.npos ||
                    name.find(L'\\') != name.npos || name.find(L'/') != name.npos)
                {
                    return std::unexpected(fail("unsupported_stream_type", ERROR_NOT_SUPPORTED));
                }
                auto converted = utf8(name == L"::$DATA" ? std::wstring_view{} : name);
                if (!converted)
                {
                    return std::unexpected(converted.error());
                }
                output.push_back({std::move(*converted), static_cast<std::uint64_t>(info->StreamSize.QuadPart)});
                if (info->NextEntryOffset == 0)
                {
                    break;
                }
                if (info->NextEntryOffset < header + info->StreamNameLength || info->NextEntryOffset % 8 != 0)
                {
                    return std::unexpected(fail("stream_metadata_invalid", ERROR_INVALID_DATA));
                }
                offset += info->NextEntryOffset;
            }
            std::sort(output.begin(), output.end(), [](const auto& left, const auto& right)
            {
                return left.name < right.name;
            });
            if ((!directory && (output.empty() || !output.front().name.empty())) ||
                std::adjacent_find(output.begin(), output.end(), [](const auto& left, const auto& right)
                {
                    return left.name == right.name;
                }) != output.end())
            {
                return std::unexpected(fail("stream_manifest_invalid", ERROR_INVALID_DATA));
            }
            return output;
        }
        return std::unexpected(fail("stream_metadata_limit", ERROR_BUFFER_OVERFLOW));
    }

    struct volume_facts
    {
        std::wstring filesystem;
        std::string key;
        std::string volume_key;
        media_kind media{media_kind::unknown};
        bool trim{};
        secure_erase::windows::retained_copy_observation retained;
    };

    result<volume_facts> inspect_volume(HANDLE file, const std::wstring& path)
    {
        const auto root = path.substr(0, 7);
        const auto drive_type = GetDriveTypeW(root.c_str());
        if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE)
        {
            return std::unexpected(fail("nonlocal_storage_denied", ERROR_NOT_SUPPORTED));
        }
        std::array<wchar_t, 64> filesystem{};
        DWORD flags{};
        if (!GetVolumeInformationByHandleW(file, nullptr, 0, nullptr, nullptr, &flags,
            filesystem.data(), static_cast<DWORD>(filesystem.size())))
        {
            return std::unexpected(fail("volume_information_failed"));
        }
        volume_facts output;
        output.filesystem = filesystem.data();
        if (!equal_path(output.filesystem, L"NTFS") && !equal_path(output.filesystem, L"ReFS") &&
            !equal_path(output.filesystem, L"FAT32") && !equal_path(output.filesystem, L"exFAT"))
        {
            return std::unexpected(fail("filesystem_unsupported", ERROR_NOT_SUPPORTED));
        }
        if (flags & FILE_READ_ONLY_VOLUME)
        {
            return std::unexpected(fail("readonly_volume", ERROR_WRITE_PROTECT));
        }
        std::array<wchar_t, 64> volume_name{};
        if (!GetVolumeNameForVolumeMountPointW(root.c_str(), volume_name.data(), static_cast<DWORD>(volume_name.size())))
        {
            return std::unexpected(fail("volume_identity_failed"));
        }
        auto key = utf8(volume_name.data());
        if (!key)
        {
            return std::unexpected(key.error());
        }
        output.volume_key = *key;
        std::wstring device_name = volume_name.data();
        device_name.pop_back();
        handle device(CreateFileW(device_name.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        if (!device)
        {
            return std::unexpected(fail("storage_query_open_failed"));
        }
        alignas(VOLUME_DISK_EXTENTS) std::array<std::byte,
            sizeof(VOLUME_DISK_EXTENTS) + 32 * sizeof(DISK_EXTENT)> extents_buffer{};
        DWORD extents_returned{};
        if (!DeviceIoControl(device.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
            extents_buffer.data(), static_cast<DWORD>(extents_buffer.size()), &extents_returned, nullptr) ||
            extents_returned < sizeof(VOLUME_DISK_EXTENTS))
        {
            return std::unexpected(fail("physical_disk_topology_unknown"));
        }
        const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(extents_buffer.data());
        if (extents->NumberOfDiskExtents != 1)
        {
            return std::unexpected(fail("multi_disk_volume_unsupported", ERROR_NOT_SUPPORTED));
        }
        // CONTRACT: All volumes backed by one physical disk share a scheduler key.
        output.key = "physical_disk:" + std::to_string(extents->Extents[0].DiskNumber);
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        alignas(STORAGE_DEVICE_DESCRIPTOR) std::array<std::byte, 4096> descriptor{};
        DWORD returned{};
        if (!DeviceIoControl(device.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            descriptor.data(), static_cast<DWORD>(descriptor.size()), &returned, nullptr) ||
            returned < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            return std::unexpected(fail("storage_type_unknown"));
        }
        const auto* storage = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(descriptor.data());
        if (storage->DeviceType != 0)
        {
            return std::unexpected(fail("nondisk_storage_denied", ERROR_NOT_SUPPORTED));
        }
        switch (storage->BusType)
        {
        case BusTypeUsb:
            output.media = media_kind::usb;
            break;
        case BusTypeAta:
        case BusTypeSata:
        case BusTypeScsi:
        case BusTypeSas:
        case BusTypeRAID:
        case BusTypeNvme:
            break;
        default:
            return std::unexpected(fail("storage_bus_unknown_or_virtual", ERROR_NOT_SUPPORTED));
        }
        DEVICE_SEEK_PENALTY_DESCRIPTOR seek{};
        query.PropertyId = StorageDeviceSeekPenaltyProperty;
        const bool seek_known = DeviceIoControl(device.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            &seek, sizeof(seek), &returned, nullptr) && returned >= sizeof(seek);
        if (output.media != media_kind::usb)
        {
            if (!seek_known)
            {
                return std::unexpected(fail("storage_media_unknown", ERROR_NOT_SUPPORTED));
            }
            output.media = seek.IncursSeekPenalty ? media_kind::hdd : media_kind::ssd;
        }
        DEVICE_TRIM_DESCRIPTOR trim{};
        query.PropertyId = StorageDeviceTrimProperty;
        output.trim = DeviceIoControl(device.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            &trim, sizeof(trim), &returned, nullptr) && returned >= sizeof(trim) && trim.TrimEnabled &&
            equal_path(output.filesystem, L"NTFS");
        return output;
    }

    result<std::vector<std::wstring>> protection_roots(const std::wstring& state_path)
    {
        std::vector<std::wstring> paths{state_path};
        std::vector<wchar_t> buffer(32768);
        const UINT windows_length = GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
        if (windows_length == 0 || windows_length >= buffer.size())
        {
            return std::unexpected(fail("windows_directory_unknown"));
        }
        auto windows = absolute(std::wstring_view(buffer.data(), windows_length));
        if (!windows)
        {
            return std::unexpected(windows.error());
        }
        paths.push_back(*windows);
        const DWORD executable_length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (executable_length == 0 || executable_length >= buffer.size())
        {
            return std::unexpected(fail("own_executable_unknown"));
        }
        auto executable = absolute(std::wstring_view(buffer.data(), executable_length));
        if (!executable)
        {
            return std::unexpected(executable.error());
        }
        auto canonical_executable = canonical_protected_path(*executable);
        if (!canonical_executable)
        {
            return std::unexpected(canonical_executable.error());
        }
        // SECURITY: Preserve the running application and all companion binaries/resources.
        paths.push_back(canonical_executable->substr(0, canonical_executable->find_last_of(L'\\')));
        service_handle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE)};
        if (manager.value == nullptr)
        {
            return std::unexpected(fail("service_inventory_unavailable"));
        }
        DWORD needed{}, count{}, resume{};
        EnumServicesStatusExW(manager.value, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, nullptr, 0, &needed, &count, &resume, nullptr);
        if (GetLastError() != ERROR_MORE_DATA || needed == 0 || needed > 16 * maximum_metadata)
        {
            return std::unexpected(fail("service_inventory_size_failed"));
        }
        std::vector<std::byte> services(needed);
        resume = 0;
        if (!EnumServicesStatusExW(manager.value, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, reinterpret_cast<BYTE*>(services.data()), needed, &needed, &count, &resume, nullptr))
        {
            return std::unexpected(fail("service_inventory_failed"));
        }
        const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(services.data());
        for (DWORD index = 0; index < count; ++index)
        {
            service_handle service{OpenServiceW(manager.value, entries[index].lpServiceName, SERVICE_QUERY_CONFIG)};
            if (service.value == nullptr)
            {
                return std::unexpected(fail("service_configuration_unavailable"));
            }
            DWORD bytes{};
            QueryServiceConfigW(service.value, nullptr, 0, &bytes);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0 || bytes > maximum_metadata)
            {
                return std::unexpected(fail("service_configuration_size_failed"));
            }
            std::vector<std::byte> config(bytes);
            auto* configuration = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
            if (!QueryServiceConfigW(service.value, configuration, bytes, &bytes))
            {
                return std::unexpected(fail("service_configuration_failed"));
            }
            std::wstring binary = configuration->lpBinaryPathName;
            if (binary.empty())
            {
                continue;
            }
            const DWORD expanded = ExpandEnvironmentStringsW(binary.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
            if (expanded == 0 || expanded > buffer.size())
            {
                return std::unexpected(fail("service_path_expansion_failed"));
            }
            binary = buffer.data();
            if (binary.starts_with(L'"'))
            {
                const auto end = binary.find(L'"', 1);
                if (end == binary.npos)
                {
                    return std::unexpected(fail("service_path_ambiguous", ERROR_INVALID_DATA));
                }
                binary = binary.substr(1, end - 1);
            }
            else
            {
                auto lower = binary;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c)
                {
                    return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>(c - L'A' + L'a') : c;
                });
                const auto executable_end = lower.find(L".exe");
                const auto driver_end = lower.find(L".sys");
                const auto end = (std::min)(executable_end, driver_end);
                if (end != binary.npos)
                {
                    binary.resize(end + 4);
                }
            }
            if (binary.starts_with(L"\\SystemRoot\\"))
            {
                binary = *windows + binary.substr(11);
            }
            if (binary.starts_with(L"\\??\\"))
            {
                binary.erase(0, 4);
            }
            if (binary.starts_with(L"System32\\") || binary.starts_with(L"system32\\"))
            {
                binary = *windows + L"\\" + binary;
            }
            auto normalized = absolute(binary);
            if (!normalized)
            {
                return std::unexpected(fail("service_path_unresolved", ERROR_INVALID_DATA));
            }
            auto canonical_binary = canonical_protected_path(*normalized);
            if (!canonical_binary)
            {
                return std::unexpected(canonical_binary.error());
            }
            // SECURITY: Protect service companion DLLs by denying its containing directory.
            paths.push_back(canonical_binary->substr(0, canonical_binary->find_last_of(L'\\')));
        }
        for (auto& path : paths)
        {
            auto canonical = canonical_protected_path(path);
            if (!canonical)
            {
                return std::unexpected(canonical.error());
            }
            path = std::move(*canonical);
        }
        return paths;
    }

    result<std::vector<std::string>> protection(HANDLE file, const std::wstring& path,
        const std::vector<std::wstring>& roots, DWORD attributes, bool persistent_acl)
    {
        std::vector<std::string> reasons;
        if (path.size() <= 7)
        {
            reasons.push_back("volume_root");
        }
        for (const auto& root : roots)
        {
            if (within(path, root))
            {
                reasons.push_back("protected_resource_tree");
                break;
            }
        }
        for (std::size_t begin = 7; begin < path.size();)
        {
            const auto end = path.find(L'\\', begin);
            const auto component = std::wstring_view(path).substr(begin,
                end == path.npos ? path.size() - begin : end - begin);
            if (!component.empty() && component.front() == L'$')
            {
                reasons.push_back("filesystem_metadata_name");
            }
            for (const auto* name : {L"Boot", L"EFI", L"Recovery", L"System Volume Information",
                L"Config.Msi", L"MSOCache", L"Windows.old", L"pagefile.sys", L"swapfile.sys",
                L"hiberfil.sys", L"bootmgr", L"bootnxt", L"ntldr", L"ntdetect.com", L"boot.ini"})
            {
                if (equal_path(component, name))
                {
                    reasons.push_back("boot_or_system_metadata");
                }
            }
            begin = end == path.npos ? path.size() : end + 1;
        }
        if (attributes & FILE_ATTRIBUTE_SYSTEM)
        {
            reasons.push_back("system_attribute");
        }
        if (SfcIsFileProtected(nullptr, path.c_str()))
        {
            reasons.push_back("windows_resource_protection");
        }
        if (!persistent_acl)
        {
            return reasons;
        }
        PSID owner{};
        PSECURITY_DESCRIPTOR descriptor{};
        const DWORD native = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            &owner, nullptr, nullptr, nullptr, &descriptor);
        if (native != ERROR_SUCCESS)
        {
            return std::unexpected(fail("owner_protection_query_failed", native));
        }
        if (owner == nullptr || !IsValidSid(owner))
        {
            LocalFree(descriptor);
            return std::unexpected(fail("owner_protection_unknown", ERROR_INVALID_SID));
        }
        const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        const bool service_sid = *GetSidSubAuthorityCount(owner) >= 1 &&
            std::memcmp(GetSidIdentifierAuthority(owner), &nt_authority, sizeof(nt_authority)) == 0 &&
            *GetSidSubAuthority(owner, 0) == SECURITY_SERVICE_ID_BASE_RID;
        if (service_sid || IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinLocalServiceSid) ||
            IsWellKnownSid(owner, WinNetworkServiceSid))
        {
            reasons.push_back("system_service_owner");
        }
        LocalFree(descriptor);
        return reasons;
    }

    result<target_snapshot> observe(HANDLE file, const std::wstring& path,
        const volume_facts& volume, const std::vector<std::wstring>& roots)
    {
        if (GetFileType(file) != FILE_TYPE_DISK)
        {
            return std::unexpected(fail("nondisk_handle", ERROR_NOT_SUPPORTED));
        }
        FILE_BASIC_INFO basic{};
        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) ||
            !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)))
        {
            return std::unexpected(fail("target_metadata_failed"));
        }
        if (standard.DeletePending || basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT ||
            standard.EndOfFile.QuadPart < 0)
        {
            return std::unexpected(fail("reparse_or_delete_pending_denied", ERROR_ACCESS_DENIED));
        }
        auto name = final_name(file);
        auto identifier = identity(file);
        if (!name || !identifier)
        {
            return std::unexpected(!name ? name.error() : identifier.error());
        }
        if (!equal_path(*name, path))
        {
            return std::unexpected(fail("canonical_path_changed", ERROR_INVALID_DATA));
        }
        auto converted = utf8(path);
        auto manifest = streams(file, standard.Directory != FALSE, volume.filesystem);
        auto reasons = protection(file, path, roots, basic.FileAttributes,
            equal_path(volume.filesystem, L"NTFS") || equal_path(volume.filesystem, L"ReFS"));
        if (!converted || !manifest || !reasons)
        {
            return std::unexpected(!converted ? converted.error() : !manifest ? manifest.error() : reasons.error());
        }
        target_snapshot snapshot;
        snapshot.path = *converted;
        snapshot.identity = volume.volume_key + ":" + *identifier;
        snapshot.device_key = volume.key;
        snapshot.creation_time = static_cast<std::uint64_t>(basic.CreationTime.QuadPart);
        snapshot.write_time = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
        snapshot.change_time = static_cast<std::uint64_t>(basic.ChangeTime.QuadPart);
        snapshot.attributes = basic.FileAttributes;
        snapshot.link_count = standard.NumberOfLinks;
        snapshot.directory = standard.Directory != FALSE;
        snapshot.encrypted = (basic.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) != 0;
        snapshot.compressed = (basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
        snapshot.sparse = (basic.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0;
        // SECURITY: Compression/encryption/sparse state is per-stream, not per-file.
        // Inspect named streams without reading payload. Unknown/inaccessible state blocks preview.
        for (const auto& stream : *manifest)
        {
            if (stream.name.empty())
            {
                continue;
            }
            auto suffix = wide(stream.name);
            if (!suffix)
            {
                return std::unexpected(suffix.error());
            }
            handle stream_metadata(CreateFileW((path + *suffix).c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            FILE_BASIC_INFO stream_basic{};
            if (!stream_metadata || !GetFileInformationByHandleEx(stream_metadata.get(), FileBasicInfo,
                &stream_basic, sizeof(stream_basic)))
            {
                return std::unexpected(fail("named_stream_attributes_unknown"));
            }
            snapshot.encrypted = snapshot.encrypted || (stream_basic.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) != 0;
            snapshot.compressed = snapshot.compressed || (stream_basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
            snapshot.sparse = snapshot.sparse || (stream_basic.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0;
        }
        snapshot.trim_supported = volume.trim && !snapshot.directory && !snapshot.encrypted && !snapshot.compressed;
        snapshot.media = volume.media;
        snapshot.vss_query_complete = volume.retained.complete;
        snapshot.vss_snapshot_count = volume.retained.snapshot_count;
        snapshot.vss_native_error = volume.retained.native_error;
        snapshot.residual_risks = {"filesystem_metadata_and_journals_not_sanitized",
            "backups_and_external_replicas_not_enumerable", "device_remapped_sectors_not_verifiable"};
        if (!volume.retained.complete)
        {
            snapshot.residual_risks.push_back("vss_snapshot_visibility_unknown");
        }
        if (volume.retained.snapshot_count != 0)
        {
            snapshot.residual_risks.push_back("vss_retained_snapshots_detected");
        }
        if (!snapshot.directory && snapshot.link_count > 1)
        {
            snapshot.residual_risks.push_back("other_hardlink_aliases_retained");
        }
        if (volume.media != media_kind::hdd)
        {
            snapshot.residual_risks.push_back("flash_historical_physical_pages_not_verifiable");
        }
        snapshot.streams = std::move(*manifest);
        snapshot.protection_reasons = std::move(*reasons);
        if (!snapshot.protection_reasons.empty())
        {
            snapshot.support = capability::blocked;
        }
        else if ((!snapshot.directory && snapshot.link_count > 1) || snapshot.encrypted || snapshot.compressed ||
            snapshot.sparse || equal_path(volume.filesystem, L"ReFS"))
        {
            snapshot.support = capability::delete_only;
        }
        else
        {
            snapshot.support = volume.media == media_kind::hdd ? capability::overwrite_verified : capability::overwrite_best_effort;
        }
        return snapshot;
    }

    bool same_before_execution(target_snapshot left, target_snapshot right)
    {
        // SECURITY: Child deletion changes directory timestamps; identity and streams remain mandatory.
        if (left.directory && right.directory)
        {
            left.write_time = right.write_time;
            left.change_time = right.change_time;
        }
        return left == right;
    }

    class windows_target final : public target_handle
    {
    public:
        windows_target(handle control, std::vector<handle> ancestors, std::wstring path,
            volume_facts volume, std::vector<std::wstring> roots, target_snapshot original)
            : control_(std::move(control)), ancestors_(std::move(ancestors)), path_(std::move(path)),
              volume_(std::move(volume)), roots_(std::move(roots)), original_(std::move(original))
        {
        }

        ~windows_target() override
        {
            if (readonly_changed_ && control_ && !removed_)
            {
                FILE_BASIC_INFO info{};
                if (GetFileInformationByHandleEx(control_.get(), FileBasicInfo, &info, sizeof(info)))
                {
                    info.CreationTime.QuadPart = 0;
                    info.LastAccessTime.QuadPart = 0;
                    info.LastWriteTime.QuadPart = 0;
                    info.ChangeTime.QuadPart = 0;
                    info.FileAttributes |= FILE_ATTRIBUTE_READONLY;
                    // BEST_EFFORT: destructor cannot report; inspect/next preview exposes restoration failure.
                    SetFileInformationByHandle(control_.get(), FileBasicInfo, &info, sizeof(info));
                }
            }
        }

        result<void> open_streams()
        {
            if (original_.support == capability::delete_only)
            {
                return {};
            }
            if (original_.attributes & FILE_ATTRIBUTE_READONLY)
            {
                FILE_BASIC_INFO info{};
                info.FileAttributes = original_.attributes & ~FILE_ATTRIBUTE_READONLY;
                if (info.FileAttributes == 0)
                {
                    info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                }
                if (!SetFileInformationByHandle(control_.get(), FileBasicInfo, &info, sizeof(info)))
                {
                    return std::unexpected(fail("readonly_clear_failed"));
                }
                readonly_changed_ = true;
            }
            for (const auto& stream : original_.streams)
            {
                std::wstring stream_path = path_;
                if (!stream.name.empty())
                {
                    auto suffix = wide(stream.name);
                    if (!suffix)
                    {
                        return std::unexpected(suffix.error());
                    }
                    stream_path += *suffix;
                }
                // SECURITY: Sharing is per-stream. Own control DELETE is admitted; every external
                // data reader/writer is denied. Control handle independently denies rename/delete.
                handle data(CreateFileW(stream_path.c_str(), GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT |
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN |
                    (volume_.media == media_kind::ssd ? FILE_FLAG_OVERLAPPED : 0), nullptr));
                if (!data)
                {
                    return std::unexpected(fail("exclusive_stream_open_failed"));
                }
                auto data_identity = identity(data.get());
                auto control_identity = identity(control_.get());
                if (!data_identity || !control_identity || *data_identity != *control_identity)
                {
                    return std::unexpected(fail("stream_identity_changed", ERROR_INVALID_DATA));
                }
                FILE_BASIC_INFO basic{};
                LARGE_INTEGER size{};
                if (!GetFileInformationByHandleEx(data.get(), FileBasicInfo, &basic, sizeof(basic)) ||
                    !GetFileSizeEx(data.get(), &size))
                {
                    return std::unexpected(fail("stream_metadata_query_failed"));
                }
                if ((basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_COMPRESSED |
                    FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_SPARSE_FILE)) != 0 || size.QuadPart < 0 ||
                    static_cast<std::uint64_t>(size.QuadPart) != stream.size)
                {
                    return std::unexpected(fail("stream_capability_changed_repreview", ERROR_INVALID_DATA));
                }
                const FILETIME preserve{MAXDWORD, MAXDWORD};
                if (!SetFileTime(data.get(), nullptr, &preserve, &preserve))
                {
                    return std::unexpected(fail("stream_timestamp_preservation_failed"));
                }
                data_.emplace(stream.name, std::move(data));
            }
            auto current = inspect();
            if (!current)
            {
                return std::unexpected(current.error());
            }
            auto expected = original_;
            if (readonly_changed_)
            {
                expected.attributes = current->attributes;
                expected.change_time = current->change_time;
            }
            if (!same_before_execution(expected, *current))
            {
                return std::unexpected(fail("target_changed_during_acquire", ERROR_INVALID_DATA));
            }
            return {};
        }

        result<target_snapshot> inspect() override
        {
            if (!control_)
            {
                return std::unexpected(fail("target_closed", ERROR_INVALID_HANDLE));
            }
            return observe(control_.get(), path_, volume_, roots_);
        }

        result<target_snapshot> checkpoint_snapshot() override
        {
            // SECURITY: Persist only the restored externally visible attribute state while
            // exclusive data handles remain held. Existing granted write access remains usable.
            if (readonly_changed_)
            {
                FILE_BASIC_INFO info{};
                if (!GetFileInformationByHandleEx(control_.get(), FileBasicInfo, &info, sizeof(info)))
                {
                    return std::unexpected(fail("readonly_restore_query_failed"));
                }
                info.CreationTime.QuadPart = 0;
                info.LastAccessTime.QuadPart = 0;
                info.LastWriteTime.QuadPart = 0;
                info.ChangeTime.QuadPart = 0;
                info.FileAttributes = (info.FileAttributes & ~FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_READONLY;
                if (!SetFileInformationByHandle(control_.get(), FileBasicInfo, &info, sizeof(info)))
                {
                    return std::unexpected(fail("readonly_restore_failed"));
                }
                readonly_changed_ = false;
            }
            return inspect();
        }

        result<std::size_t> read(std::string_view stream, std::uint64_t offset, std::span<std::byte> buffer) override
        {
            auto data = locate(stream, offset, buffer.size());
            if (!data)
            {
                return std::unexpected(data.error());
            }
            return transfer(*data, offset, buffer.data(), buffer.size(), false);
        }

        result<std::size_t> write(std::string_view stream, std::uint64_t offset,
            std::span<const std::byte> buffer) override
        {
            auto unchanged = invariant();
            if (!unchanged)
            {
                return std::unexpected(unchanged.error());
            }
            auto data = locate(stream, offset, buffer.size());
            if (!data)
            {
                return std::unexpected(data.error());
            }
            auto transferred = transfer(*data, offset, const_cast<std::byte*>(buffer.data()), buffer.size(), true);
            if (transferred && *transferred != 0)
            {
                wrote_ = true;
            }
            return transferred;
        }

        result<void> flush(std::string_view stream) override
        {
            const auto found = data_.find(std::string(stream));
            if (found == data_.end())
            {
                return std::unexpected(fail("unknown_stream", ERROR_INVALID_PARAMETER));
            }
            if (!FlushFileBuffers(found->second.get()))
            {
                return std::unexpected(fail("flush_failed"));
            }
            return {};
        }

        result<void> trim() override
        {
            // CONTRACT: Engine invokes after verified evidence; trim is only a storage hint.
            auto unchanged = invariant();
            if (!unchanged)
            {
                return unchanged;
            }
            if (!original_.trim_supported || original_.support == capability::delete_only)
            {
                return std::unexpected(fail("trim_not_supported", ERROR_NOT_SUPPORTED));
            }
            for (const auto& stream : original_.streams)
            {
                if (stream.size == 0)
                {
                    continue;
                }
                FILE_LEVEL_TRIM request{};
                request.Key = 0;
                request.NumRanges = 1;
                request.Ranges[0].Offset = 0;
                request.Ranges[0].Length = stream.size;
                FILE_LEVEL_TRIM_OUTPUT response{};
                DWORD returned{};
                const auto found = data_.find(stream.name);
                if (found == data_.end())
                {
                    return std::unexpected(fail("trim_stream_unknown", ERROR_INVALID_HANDLE));
                }
                handle event;
                OVERLAPPED operation{};
                OVERLAPPED* asynchronous{};
                if (volume_.media == media_kind::ssd)
                {
                    event = handle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                    if (!event)
                    {
                        return std::unexpected(fail("trim_event_creation_failed"));
                    }
                    operation.hEvent = event.get();
                    asynchronous = &operation;
                }
                const BOOL immediate = DeviceIoControl(found->second.get(), FSCTL_FILE_LEVEL_TRIM,
                    &request, sizeof(request), &response, sizeof(response), &returned, asynchronous);
                if (!immediate && !(asynchronous != nullptr && GetLastError() == ERROR_IO_PENDING))
                {
                    return std::unexpected(fail("trim_hint_failed"));
                }
                if (asynchronous != nullptr && !GetOverlappedResult(found->second.get(), &operation, &returned, TRUE))
                {
                    return std::unexpected(fail("trim_hint_completion_failed"));
                }
                if (returned < sizeof(response) || response.NumRangesProcessed != 1)
                {
                    return std::unexpected(fail("trim_hint_partial", ERROR_INVALID_DATA));
                }
            }
            return {};
        }

        result<void> remove() override
        {
            auto unchanged = invariant();
            if (!unchanged)
            {
                return unchanged;
            }
            // SECURITY: Keep every existing stream exclusively held through disposition.
            FILE_DISPOSITION_INFO_EX disposition{};
            disposition.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_FORCE_IMAGE_SECTION_CHECK |
                FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
            if (!SetFileInformationByHandle(control_.get(), FileDispositionInfoEx, &disposition, sizeof(disposition)))
            {
                const DWORD native = GetLastError();
                if (native != ERROR_INVALID_PARAMETER && native != ERROR_NOT_SUPPORTED && native != ERROR_INVALID_FUNCTION)
                {
                    return std::unexpected(fail("disposition_failed", native));
                }
                if (original_.attributes & FILE_ATTRIBUTE_READONLY)
                {
                    FILE_BASIC_INFO info{};
                    info.FileAttributes = original_.attributes & ~FILE_ATTRIBUTE_READONLY;
                    if (info.FileAttributes == 0)
                    {
                        info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                    }
                    if (!SetFileInformationByHandle(control_.get(), FileBasicInfo, &info, sizeof(info)))
                    {
                        return std::unexpected(fail("readonly_delete_clear_failed"));
                    }
                    readonly_changed_ = true;
                }
                FILE_DISPOSITION_INFO fallback{TRUE};
                if (!SetFileInformationByHandle(control_.get(), FileDispositionInfo, &fallback, sizeof(fallback)))
                {
                    return std::unexpected(fail("disposition_fallback_failed"));
                }
            }
            // SECURITY: Delete-pending blocks new opens. Re-enumerate after disposition to
            // detect an ADS created between the precheck and marking, without touching its data.
            auto after_mark = streams(control_.get(), original_.directory, volume_.filesystem);
            if (!after_mark || *after_mark != original_.streams)
            {
                FILE_DISPOSITION_INFO undo{FALSE};
                if (!SetFileInformationByHandle(control_.get(), FileDispositionInfo, &undo, sizeof(undo)))
                {
                    return std::unexpected(fail("critical_disposition_rollback_failed"));
                }
                return std::unexpected(!after_mark ? after_mark.error() :
                    fail("stream_manifest_changed_at_disposition", ERROR_INVALID_DATA));
            }
            // SECURITY: No pathname deletion; NTFS rejects nonempty directory disposition.
            removed_ = true;
            data_.clear();
            control_.reset();
            handle probe(CreateFileW(path_.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!probe)
            {
                const DWORD native = GetLastError();
                if (native == ERROR_FILE_NOT_FOUND || native == ERROR_PATH_NOT_FOUND)
                {
                    return {};
                }
                return std::unexpected(fail("deletion_not_observed_may_be_pending", native));
            }
            auto replacement = identity(probe.get());
            if (!replacement)
            {
                return std::unexpected(replacement.error());
            }
            if (volume_.volume_key + ":" + *replacement == original_.identity)
            {
                return std::unexpected(fail("original_name_still_present", ERROR_BUSY));
            }
            // CONTRACT: A replacement name may now exist; it is never modified or removed.
            return {};
        }

    private:
        result<void> invariant()
        {
            auto current = inspect();
            if (!current)
            {
                return std::unexpected(current.error());
            }
            auto expected = original_;
            expected.write_time = current->write_time;
            expected.change_time = current->change_time;
            if (readonly_changed_)
            {
                expected.attributes &= ~FILE_ATTRIBUTE_READONLY;
                if (expected.attributes == 0)
                {
                    expected.attributes = FILE_ATTRIBUTE_NORMAL;
                }
            }
            if (wrote_ && !(original_.attributes & FILE_ATTRIBUTE_ARCHIVE) &&
                (current->attributes & FILE_ATTRIBUTE_ARCHIVE))
            {
                expected.attributes |= FILE_ATTRIBUTE_ARCHIVE;
                // FILE_ATTRIBUTE_NORMAL is meaningful only when no other attribute is set.
                expected.attributes &= ~FILE_ATTRIBUTE_NORMAL;
            }
            expected.attributes &= ~FILE_ATTRIBUTE_NORMAL;
            current->attributes &= ~FILE_ATTRIBUTE_NORMAL;
            if (expected != *current)
            {
                return std::unexpected(fail("held_target_metadata_changed", ERROR_INVALID_DATA));
            }
            return {};
        }

        result<std::size_t> transfer(HANDLE data, std::uint64_t offset, void* buffer,
            std::size_t size, bool writing)
        {
            DWORD completed{};
            if (volume_.media != media_kind::ssd)
            {
                const BOOL okay = writing ? WriteFile(data, buffer, static_cast<DWORD>(size), &completed, nullptr) :
                    ReadFile(data, buffer, static_cast<DWORD>(size), &completed, nullptr);
                if (!okay)
                {
                    return std::unexpected(fail(writing ? "write_failed" : "read_failed"));
                }
                return static_cast<std::size_t>(completed);
            }
            // CONTRACT: SSD uses positioned overlapped I/O, one bounded request per worker.
            // HDD/USB remains synchronous; buffered write-through avoids unsafe alignment guesses.
            handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!event)
            {
                return std::unexpected(fail("io_event_creation_failed"));
            }
            OVERLAPPED operation{};
            operation.hEvent = event.get();
            operation.Offset = static_cast<DWORD>(offset);
            operation.OffsetHigh = static_cast<DWORD>(offset >> 32);
            const BOOL immediate = writing ? WriteFile(data, buffer, static_cast<DWORD>(size), &completed, &operation) :
                ReadFile(data, buffer, static_cast<DWORD>(size), &completed, &operation);
            if (!immediate && GetLastError() != ERROR_IO_PENDING)
            {
                return std::unexpected(fail(writing ? "overlapped_write_failed" : "overlapped_read_failed"));
            }
            if (!GetOverlappedResult(data, &operation, &completed, TRUE))
            {
                return std::unexpected(fail(writing ? "overlapped_write_completion_failed" : "overlapped_read_completion_failed"));
            }
            return static_cast<std::size_t>(completed);
        }

        result<HANDLE> locate(std::string_view name, std::uint64_t offset, std::size_t size)
        {
            const auto data = data_.find(std::string(name));
            const auto stream = std::find_if(original_.streams.begin(), original_.streams.end(), [name](const auto& value)
            {
                return value.name == name;
            });
            if (data == data_.end() || stream == original_.streams.end() || !std::in_range<DWORD>(size) ||
                offset > stream->size || size > stream->size - offset || !std::in_range<LONGLONG>(offset))
            {
                return std::unexpected(fail("stream_range_invalid", ERROR_INVALID_PARAMETER));
            }
            LARGE_INTEGER position{};
            position.QuadPart = static_cast<LONGLONG>(offset);
            if (volume_.media != media_kind::ssd && !SetFilePointerEx(data->second.get(), position, nullptr, FILE_BEGIN))
            {
                return std::unexpected(fail("seek_failed"));
            }
            return data->second.get();
        }

        handle control_;
        std::vector<handle> ancestors_;
        std::wstring path_;
        volume_facts volume_;
        std::vector<std::wstring> roots_;
        target_snapshot original_;
        std::map<std::string, handle> data_;
        bool readonly_changed_{};
        bool removed_{};
        bool wrote_{};
    };


    result<std::pair<std::string, std::string>> quick_file_identity(HANDLE file);

    struct scope_binding
    {
        std::wstring path;
        std::string identity;
        std::uint64_t creation_time{};
    };

    bool scope_contains(const scope_binding& scope, std::wstring_view path)
    {
        return path == scope.path || (path.size() > scope.path.size() && path.starts_with(scope.path) &&
            (scope.path.ends_with(L'\\') || path[scope.path.size()] == L'\\'));
    }

    result<void> validate_scope_handle(const scope_binding& scope, HANDLE file)
    {
        FILE_BASIC_INFO basic{};
        FILE_STANDARD_INFO standard{};
        auto id = quick_file_identity(file);
        if (!id || !GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) ||
            !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)))
        {
            return std::unexpected(!id ? id.error() : fail("scope_identity_query_failed"));
        }
        if (id->first != scope.identity || static_cast<std::uint64_t>(basic.CreationTime.QuadPart) != scope.creation_time ||
            !standard.Directory || standard.DeletePending || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            return std::unexpected(fail("scope_identity_changed", ERROR_ACCESS_DENIED));
        }
        return {};
    }

    result<void> validate_scope(const std::optional<scope_binding>& scope)
    {
        if (!scope)
        {
            return {};
        }
        auto pins = pin_ancestors(scope->path, true);
        if (!pins)
        {
            return std::unexpected(pins.error());
        }
        handle directory(CreateFileW(scope->path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
        if (!directory)
        {
            return std::unexpected(fail("scope_open_failed"));
        }
        return validate_scope_handle(*scope, directory.get());
    }

    result<std::optional<scope_binding>> bind_scope(std::wstring_view state, std::wstring_view root)
    {
        if (root.empty())
        {
            return std::optional<scope_binding>{};
        }
        auto normalized = absolute(root);
        if (!normalized)
        {
            return std::unexpected(normalized.error());
        }
        auto pins = pin_ancestors(*normalized, true);
        if (!pins)
        {
            return std::unexpected(pins.error());
        }
        handle directory(CreateFileW(normalized->c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
        if (!directory)
        {
            return std::unexpected(fail("scope_open_failed"));
        }
        auto canonical = final_name(directory.get());
        auto canonical_state = canonical_protected_path(std::wstring(state));
        auto id = quick_file_identity(directory.get());
        FILE_BASIC_INFO basic{};
        FILE_STANDARD_INFO standard{};
        if (!canonical || !canonical_state || !id ||
            !GetFileInformationByHandleEx(directory.get(), FileBasicInfo, &basic, sizeof(basic)) ||
            !GetFileInformationByHandleEx(directory.get(), FileStandardInfo, &standard, sizeof(standard)))
        {
            return std::unexpected(fail("scope_binding_failed", ERROR_ACCESS_DENIED));
        }
        if (!standard.Directory || standard.DeletePending || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            within(*canonical, *canonical_state) || within(*canonical_state, *canonical))
        {
            return std::unexpected(fail("scope_report_overlap_or_reparse", ERROR_ACCESS_DENIED));
        }
        return std::optional<scope_binding>(scope_binding{std::move(*canonical), std::move(id->first),
            static_cast<std::uint64_t>(basic.CreationTime.QuadPart)});
    }

    result<void> admit_scope_input(const scope_binding& scope, const std::wstring& path)
    {
        // SECURITY: An unresolved root still needs a proven scope boundary.
        // Resolve only held nofollow prefixes; never infer containment from a
        // short-name/case spelling or traverse a directory to discover targets.
        std::wstring prefix = path;
        std::wstring missing;
        for (std::size_t depth = 0; depth <= maximum_depth; ++depth)
        {
            auto ancestors = pin_ancestors(prefix, true);
            DWORD native{};
            if (ancestors)
            {
                handle file(CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
                if (file)
                {
                    FILE_ATTRIBUTE_TAG_INFO tag{};
                    auto canonical = final_name(file.get());
                    if (!canonical || !GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &tag, sizeof(tag)))
                    {
                        return std::unexpected(!canonical ? canonical.error() : fail("quick_scope_prefix_attributes_failed"));
                    }
                    if (!missing.empty() && (!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)))
                    {
                        return std::unexpected(fail("quick_scope_prefix_not_directory", ERROR_ACCESS_DENIED));
                    }
                    const auto candidate = canonical->ends_with(L'\\') && missing.starts_with(L'\\') ?
                        *canonical + missing.substr(1) : *canonical + missing;
                    if (!scope_contains(scope, candidate))
                    {
                        return std::unexpected(fail("quick_target_outside_scope", ERROR_ACCESS_DENIED));
                    }
                    return {};
                }
                native = GetLastError();
            }
            else
            {
                if (ancestors.error().code != "ancestor_pin_failed")
                {
                    return std::unexpected(ancestors.error());
                }
                native = ancestors.error().native_code;
            }
            if (native != ERROR_FILE_NOT_FOUND && native != ERROR_PATH_NOT_FOUND &&
                native != ERROR_ACCESS_DENIED && native != ERROR_SHARING_VIOLATION)
            {
                return std::unexpected(fail("quick_scope_prefix_unavailable", native));
            }
            const auto separator = prefix.find_last_of(L'\\');
            if (prefix.size() <= 7 || separator == prefix.npos || separator < 6)
            {
                return std::unexpected(fail("quick_scope_input_unresolved", ERROR_ACCESS_DENIED));
            }
            missing = prefix.substr(separator) + missing;
            prefix.resize(separator == 6 ? 7 : separator);
        }
        return std::unexpected(fail("quick_scope_input_depth_limit", ERROR_BUFFER_OVERFLOW));
    }

    class quick_cpu_counter
    {
    public:
        ~quick_cpu_counter()
        {
            if (query_ != nullptr)
            {
                PdhCloseQuery(query_);
            }
        }

        std::optional<unsigned> sample()
        {
            const auto now = GetTickCount64();
            if (query_ == nullptr && !attempted_)
            {
                attempted_ = true;
                // CONTRACT: Processor Information(_Total) aggregates all processor
                // groups. Never label GetSystemTimes' single-group result as global.
                if (PdhOpenQueryW(nullptr, 0, &query_) != ERROR_SUCCESS ||
                    PdhAddEnglishCounterW(query_, L"\\Processor Information(_Total)\\% Processor Time",
                        0, &counter_) != ERROR_SUCCESS)
                {
                    return {};
                }
                primed_ = PdhCollectQueryData(query_) == ERROR_SUCCESS;
                last_sample_ = now;
                return {};
            }
            if (counter_ == nullptr || !primed_)
            {
                return {};
            }
            if (now - last_sample_ < 1000)
            {
                return last_pressure_;
            }
            last_sample_ = now;
            PDH_FMT_COUNTERVALUE value{};
            if (PdhCollectQueryData(query_) != ERROR_SUCCESS ||
                PdhGetFormattedCounterValue(counter_, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100,
                    nullptr, &value) != ERROR_SUCCESS ||
                (value.CStatus != PDH_CSTATUS_VALID_DATA && value.CStatus != PDH_CSTATUS_NEW_DATA) ||
                !std::isfinite(value.doubleValue))
            {
                last_pressure_.reset();
                return {};
            }
            last_pressure_ = static_cast<unsigned>(std::clamp(value.doubleValue, 0.0, 100.0));
            return last_pressure_;
        }

    private:
        PDH_HQUERY query_{};
        PDH_HCOUNTER counter_{};
        bool attempted_{};
        bool primed_{};
        ULONGLONG last_sample_{};
        std::optional<unsigned> last_pressure_;
    };

    result<quick::resource_sample> collect_system_resources()
    {
        MEMORYSTATUSEX memory{};
        memory.dwLength = sizeof(memory);
        PERFORMANCE_INFORMATION performance{};
        performance.cb = sizeof(performance);
        DWORD own_handles{};
        if (!GlobalMemoryStatusEx(&memory) ||
            !K32GetPerformanceInfo(&performance, sizeof(performance)) ||
            !GetProcessHandleCount(GetCurrentProcess(), &own_handles))
        {
            return std::unexpected(fail("quick_resource_sample_failed"));
        }
        quick::resource_sample sample;
        sample.available_memory_bytes = memory.ullAvailPhys;
        // RESOURCE: ullAvailPageFile is the maximum the current process can
        // commit at this instant. Also constrain by global current headroom.
        if (performance.PageSize == 0)
        {
            return std::unexpected(fail("quick_resource_page_size_unavailable", ERROR_NOT_SUPPORTED));
        }
        const auto pages = performance.CommitLimit > performance.CommitTotal ?
            performance.CommitLimit - performance.CommitTotal : 0;
        const auto global_commit = pages > (std::numeric_limits<std::uint64_t>::max)() / performance.PageSize ?
            (std::numeric_limits<std::uint64_t>::max)() :
            static_cast<std::uint64_t>(pages) * static_cast<std::uint64_t>(performance.PageSize);
        sample.available_commit_bytes = (std::min)(memory.ullAvailPageFile, global_commit);
        BOOL in_job{};
        if (!IsProcessInJob(GetCurrentProcess(), nullptr, &in_job))
        {
            return std::unexpected(fail("quick_job_membership_query_failed"));
        }
        if (in_job)
        {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            PROCESS_MEMORY_COUNTERS_EX process{};
            process.cb = sizeof(process);
            if (!QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation,
                &limits, sizeof(limits), nullptr) ||
                !K32GetProcessMemoryInfo(GetCurrentProcess(),
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&process), sizeof(process)))
            {
                return std::unexpected(fail("quick_job_resource_query_failed"));
            }
            const auto constrain = [&](std::uint64_t limit, std::uint64_t used)
            {
                sample.available_commit_bytes = (std::min)(sample.available_commit_bytes,
                    limit > used ? limit - used : 0);
            };
            if (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY)
            {
                constrain(limits.ProcessMemoryLimit, process.PrivateUsage);
            }
            if (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY)
            {
                // Peak usage is a conservative lower-bound headroom estimate;
                // Windows can reject later allocations despite any observation.
                constrain(limits.JobMemoryLimit, limits.PeakJobMemoryUsed);
            }
        }
        sample.logical_processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        if (GetActiveProcessorGroupCount() == 1)
        {
            DWORD_PTR process_mask{}, system_mask{};
            if (GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask) && process_mask != 0)
            {
                sample.logical_processors = static_cast<std::size_t>(
                    std::popcount(static_cast<std::uint64_t>(process_mask)));
            }
        }
        if (sample.logical_processors == 0 || performance.PageSize == 0)
        {
            return std::unexpected(fail("quick_resource_topology_unavailable", ERROR_NOT_SUPPORTED));
        }
        // RESOURCE: Reserve most free commit/RAM for Windows and other work.
        // Windows exposes no exact remaining handle quota. This deliberately
        // conservative estimate is job headroom, never a guarantee of opens.
        const auto raw_handle_headroom = (std::min)(sample.available_memory_bytes,
            sample.available_commit_bytes) / 65536;
        sample.available_handles = raw_handle_headroom > own_handles ? raw_handle_headroom - own_handles : 0;
        return sample;
    }


    class windows_platform final : public platform
    {
    public:
        explicit windows_platform(std::wstring state_path, std::optional<scope_binding> scope = {})
            : state_path_(std::move(state_path)), scope_(std::move(scope))
        {
        }

        bool is_elevated() const noexcept override
        {
            HANDLE raw{};
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            {
                return false;
            }
            handle token(raw);
            TOKEN_ELEVATION elevation{};
            DWORD returned{};
            return GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &returned) &&
                returned >= sizeof(elevation) && elevation.TokenIsElevated != 0;
        }

        result<void> begin_execution() override
        {
            auto scoped = validate_scope(scope_);
            if (!scoped)
            {
                return scoped;
            }
            std::lock_guard lock(vss_mutex_);
            execution_vss_.clear();
            return {};
        }

        std::uint32_t resource_pressure() const noexcept override
        {
            MEMORYSTATUSEX memory{};
            memory.dwLength = sizeof(memory);
            const std::uint32_t memory_pressure = GlobalMemoryStatusEx(&memory) ? memory.dwMemoryLoad : 100;
            const std::scoped_lock lock(pressure_mutex_);
            const auto cpu = cpu_counter_.sample();
            return (std::min)(std::uint32_t{100}, (std::max)(memory_pressure,
                cpu ? static_cast<std::uint32_t>(*cpu) : std::uint32_t{}));
        }

        result<std::vector<target_snapshot>> preview(const std::vector<std::string>& paths) override
        {
            if (!is_elevated())
            {
                return std::unexpected(fail("administrator_required", ERROR_ELEVATION_REQUIRED));
            }
            auto roots = protection_roots(state_path_);
            if (!roots)
            {
                return std::unexpected(roots.error());
            }
            {
                std::lock_guard lock(vss_mutex_);
                preview_vss_.clear();
                execution_vss_.clear();
            }
            auto resources = collect_system_resources();
            if (!resources)
            {
                return std::unexpected(resources.error());
            }
            preview_budget_ = (std::min)(resources->available_memory_bytes, resources->available_commit_bytes) / 8;
            preview_used_ = 0;
            std::vector<target_snapshot> targets;
            std::set<std::wstring> seen;
            for (const auto& path : paths)
            {
                auto decoded = wide(path);
                if (!decoded)
                {
                    return std::unexpected(decoded.error());
                }
                auto normalized = absolute(*decoded);
                if (!normalized)
                {
                    return std::unexpected(normalized.error());
                }
                auto added = enumerate(*normalized, *roots, targets, seen, 0);
                if (!added)
                {
                    return std::unexpected(added.error());
                }
            }
            return targets;
        }

        result<std::unique_ptr<target_handle>> acquire(const target_snapshot& target) override
        {
            if (!is_elevated() || target.support == capability::blocked || !target.protection_reasons.empty())
            {
                return std::unexpected(fail("target_execution_denied", ERROR_ACCESS_DENIED));
            }
            auto roots = protection_roots(state_path_);
            auto decoded = wide(target.path);
            if (!roots || !decoded)
            {
                return std::unexpected(!roots ? roots.error() : decoded.error());
            }
            auto path = absolute(*decoded);
            if (!path)
            {
                return std::unexpected(path.error());
            }
            auto ancestors = pin_ancestors(*path);
            if (!ancestors)
            {
                return std::unexpected(ancestors.error());
            }
            handle control(CreateFileW(path->c_str(), FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!control)
            {
                return std::unexpected(fail("target_exclusive_control_failed"));
            }
            if (scope_ && !scope_contains(*scope_, *path))
            {
                return std::unexpected(fail("target_outside_scope", ERROR_ACCESS_DENIED));
            }
            auto scoped = validate_scope(scope_);
            if (!scoped)
            {
                return std::unexpected(scoped.error());
            }
            auto volume = inspect_volume(control.get(), *path);
            if (!volume)
            {
                return std::unexpected(volume.error());
            }
            auto retained = apply_retained(*volume, true);
            if (!retained)
            {
                return std::unexpected(retained.error());
            }
            auto current = observe(control.get(), *path, *volume, *roots);
            if (!current)
            {
                return std::unexpected(current.error());
            }
            if (!same_before_execution(target, *current))
            {
                return std::unexpected(fail("target_identity_metadata_or_capability_changed", ERROR_INVALID_DATA));
            }
            auto held = std::make_unique<windows_target>(std::move(control), std::move(*ancestors), *path,
                std::move(*volume), std::move(*roots), *current);
            auto opened = held->open_streams();
            if (!opened)
            {
                return std::unexpected(opened.error());
            }
            return std::unique_ptr<target_handle>(std::move(held));
        }

        result<void> random_bytes(std::span<std::byte> bytes) override
        {
            if (!std::in_range<ULONG>(bytes.size()))
            {
                return std::unexpected(fail("random_size_invalid", ERROR_INVALID_PARAMETER));
            }
            const NTSTATUS status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(bytes.data()),
                static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (status < 0)
            {
                return std::unexpected(error{"system_random_failed", static_cast<std::uint32_t>(status), false});
            }
            return {};
        }

    private:
        result<void> apply_retained(volume_facts& volume, bool execution)
        {
            std::lock_guard lock(vss_mutex_);
            auto& cache = execution ? execution_vss_ : preview_vss_;
            auto found = cache.find(volume.volume_key);
            if (found == cache.end())
            {
                auto volume_name = wide(volume.volume_key);
                if (!volume_name)
                {
                    return std::unexpected(volume_name.error());
                }
                // CONTRACT: One read-only VSS query per volume per preview/execution phase;
                // cached observation describes that phase, never continuing backup exclusion.
                found = cache.emplace(volume.volume_key,
                    secure_erase::windows::query_retained_copies(*volume_name)).first;
            }
            volume.retained = found->second;
            return {};
        }

        result<void> admit_preview(const target_snapshot& snapshot, std::size_t count)
        {
            if (count % 1024 == 0)
            {
                auto fresh = collect_system_resources();
                if (!fresh)
                {
                    return std::unexpected(fresh.error());
                }
                preview_budget_ = (std::min)(preview_budget_,
                    (std::min)(fresh->available_memory_bytes, fresh->available_commit_bytes) / 8);
            }
            // RESOURCE: Account frozen/working snapshots, stream manifests,
            // checkpoint copies, JSON escaping and protected serialization peak.
            // Admission is estimated before any mutation; allocation can still
            // fail as other processes consume resources and is never truncation.
            std::uint64_t required = (sizeof(target_snapshot) + sizeof(target_checkpoint) + sizeof(target_outcome)) * 8;
            const auto add = [&](std::uint64_t bytes) -> bool
            {
                if (bytes > ((std::numeric_limits<std::uint64_t>::max)() - required) / 16)
                {
                    return false;
                }
                required += bytes * 16;
                return true;
            };
            bool fits = add(snapshot.path.size()) && add(snapshot.identity.size()) && add(snapshot.device_key.size());
            for (const auto& stream : snapshot.streams)
            {
                fits = fits && add(sizeof(stream_snapshot)) && add(stream.name.size());
            }
            for (const auto& reason : snapshot.protection_reasons)
            {
                fits = fits && add(sizeof(std::string)) && add(reason.size());
            }
            for (const auto& risk : snapshot.residual_risks)
            {
                fits = fits && add(sizeof(std::string)) && add(risk.size());
            }
            if (!fits || preview_used_ > preview_budget_ || required > preview_budget_ - preview_used_)
            {
                return std::unexpected(fail("preview_resource_budget_exceeded", ERROR_NOT_ENOUGH_MEMORY));
            }
            preview_used_ += required;
            return {};
        }

        result<void> enumerate(const std::wstring& path, const std::vector<std::wstring>& roots,
            std::vector<target_snapshot>& output, std::set<std::wstring>& seen, std::size_t depth)
        {
            if (depth > maximum_depth)
            {
                return std::unexpected(fail("preview_resource_limit", ERROR_BUFFER_OVERFLOW));
            }
            auto ancestors = pin_ancestors(path);
            if (!ancestors)
            {
                return std::unexpected(ancestors.error());
            }
            handle control(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!control)
            {
                return std::unexpected(fail("preview_target_open_failed"));
            }
            auto canonical = final_name(control.get());
            if (!canonical)
            {
                return std::unexpected(canonical.error());
            }
            if (scope_ && !scope_contains(*scope_, *canonical))
            {
                return std::unexpected(fail("target_outside_scope", ERROR_ACCESS_DENIED));
            }
            auto scoped = validate_scope(scope_);
            if (!scoped)
            {
                return scoped;
            }
            auto seen_key = *canonical;
            std::transform(seen_key.begin(), seen_key.end(), seen_key.begin(), [](wchar_t character)
            {
                return character >= L'a' && character <= L'z' ? static_cast<wchar_t>(character - L'a' + L'A') : character;
            });
            if (!seen.insert(seen_key).second)
            {
                return {};
            }
            auto volume = inspect_volume(control.get(), *canonical);
            if (!volume)
            {
                return std::unexpected(volume.error());
            }
            auto retained = apply_retained(*volume, false);
            if (!retained)
            {
                return std::unexpected(retained.error());
            }
            auto snapshot = observe(control.get(), *canonical, *volume, roots);
            if (!snapshot)
            {
                return std::unexpected(snapshot.error());
            }
            auto admitted = admit_preview(*snapshot, output.size());
            if (!admitted)
            {
                return admitted;
            }
            output.push_back(*snapshot);
            if (!snapshot->directory || snapshot->support == capability::blocked)
            {
                return {};
            }
            // SECURITY: Pin current directory against reparse/rename while enumerating children.
            handle directory(CreateFileW(canonical->c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!directory)
            {
                return std::unexpected(fail("directory_enumeration_pin_failed"));
            }
            WIN32_FIND_DATAW entry{};
            const std::wstring pattern = *canonical + L"\\*";
            HANDLE search = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &entry, FindExSearchNameMatch,
                nullptr, FIND_FIRST_EX_LARGE_FETCH);
            if (search == INVALID_HANDLE_VALUE)
            {
                const DWORD native = GetLastError();
                if (native == ERROR_FILE_NOT_FOUND)
                {
                    return {};
                }
                return std::unexpected(fail("directory_enumeration_failed", native));
            }
            result<void> status;
            for (;;)
            {
                const std::wstring_view name(entry.cFileName);
                if (name != L"." && name != L"..")
                {
                    if (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                    {
                        status = std::unexpected(fail("reparse_child_denied", ERROR_ACCESS_DENIED));
                        break;
                    }
                    status = enumerate(*canonical + L"\\" + std::wstring(name), roots, output, seen, depth + 1);
                    if (!status)
                    {
                        break;
                    }
                }
                if (!FindNextFileW(search, &entry))
                {
                    const DWORD native = GetLastError();
                    if (native != ERROR_NO_MORE_FILES)
                    {
                        status = std::unexpected(fail("directory_enumeration_interrupted", native));
                    }
                    break;
                }
            }
            FindClose(search);
            return status;
        }

        std::wstring state_path_;
        std::optional<scope_binding> scope_;
        std::uint64_t preview_budget_{};
        std::uint64_t preview_used_{};
        std::mutex vss_mutex_;
        std::map<std::string, secure_erase::windows::retained_copy_observation> preview_vss_;
        std::map<std::string, secure_erase::windows::retained_copy_observation> execution_vss_;
        mutable std::mutex pressure_mutex_;
        mutable quick_cpu_counter cpu_counter_;
    };
    // SECURITY: Privileges exist only on a private worker-thread impersonation token.
    // The process token and every persistent owner/DACL remain unchanged.
    class quick_privileges
    {
    public:
        ~quick_privileges()
        {
            if (active_)
            {
                static_cast<void>(restore());
            }
        }

        result<void> enable(bool restore_access)
        {
            HANDLE prior{};
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                TRUE, &prior))
            {
                previous_ = handle(prior);
            }
            else if (GetLastError() != ERROR_NO_TOKEN)
            {
                return std::unexpected(fail("quick_thread_token_query_failed"));
            }
            handle process;
            HANDLE source = previous_.get();
            if (!previous_)
            {
                HANDLE raw{};
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw))
                {
                    return std::unexpected(fail("quick_process_token_query_failed"));
                }
                process = handle(raw);
                source = process.get();
            }
            HANDLE duplicate{};
            if (!DuplicateTokenEx(source, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                nullptr, SecurityImpersonation, TokenImpersonation, &duplicate))
            {
                return std::unexpected(fail("quick_private_token_failed"));
            }
            token_ = handle(duplicate);
            for (const auto* name : {L"SeBackupPrivilege", L"SeRestorePrivilege"})
            {
                if (!restore_access && equal_path(name, L"SeRestorePrivilege"))
                {
                    continue;
                }
                TOKEN_PRIVILEGES privileges{};
                privileges.PrivilegeCount = 1;
                privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (!LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid))
                {
                    return std::unexpected(fail("quick_privilege_lookup_failed"));
                }
                SetLastError(ERROR_SUCCESS);
                if (!AdjustTokenPrivileges(token_.get(), FALSE, &privileges, 0, nullptr, nullptr))
                {
                    return std::unexpected(fail("quick_privilege_enable_failed"));
                }
                const DWORD native = GetLastError();
                if (native != ERROR_SUCCESS)
                {
                    return std::unexpected(fail("quick_privilege_unavailable", native));
                }
            }
            if (!SetThreadToken(nullptr, token_.get()))
            {
                return std::unexpected(fail("quick_thread_impersonation_failed"));
            }
            active_ = true;
            return {};
        }

        result<void> restore()
        {
            if (!active_)
            {
                return {};
            }
            const BOOL restored = previous_ ? SetThreadToken(nullptr, previous_.get()) : RevertToSelf();
            if (!restored)
            {
                return std::unexpected(fail("critical_quick_thread_token_restore_failed"));
            }
            active_ = false;
            return {};
        }

    private:
        handle previous_;
        handle token_;
        bool active_{};
    };

    class quick_search
    {
    public:
        explicit quick_search(HANDLE value) noexcept : value_(value)
        {
        }

        quick_search(const quick_search&) = delete;
        quick_search& operator=(const quick_search&) = delete;

        ~quick_search()
        {
            if (value_ != INVALID_HANDLE_VALUE)
            {
                FindClose(value_);
            }
        }

        HANDLE get() const noexcept
        {
            return value_;
        }

    private:
        HANDLE value_;
    };


    struct quick_volume_facts
    {
        std::wstring filesystem;
        DWORD flags{};
    };

    struct quick_volume_cache
    {
        std::mutex mutex;
        std::map<std::string, std::shared_ptr<const quick_volume_facts>, std::less<>> values;
    };

    result<std::shared_ptr<const quick_volume_facts>> quick_volume_information(HANDLE file,
        const std::wstring& path, std::string_view volume_key, quick_volume_cache& cache)
    {
        const std::scoped_lock lock(cache.mutex);
        const auto prior = cache.values.find(volume_key);
        if (prior != cache.values.end())
        {
            return prior->second;
        }
        const auto drive_type = GetDriveTypeW(path.substr(0, 7).c_str());
        if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE)
        {
            return std::unexpected(fail("quick_nonlocal_storage_denied", ERROR_NOT_SUPPORTED));
        }
        std::array<wchar_t, 64> filesystem{};
        DWORD flags{};
        if (!GetVolumeInformationByHandleW(file, nullptr, 0, nullptr, nullptr, &flags,
            filesystem.data(), static_cast<DWORD>(filesystem.size())))
        {
            return std::unexpected(fail("quick_volume_information_failed"));
        }
        if ((!equal_path(filesystem.data(), L"NTFS") && !equal_path(filesystem.data(), L"ReFS") &&
            !equal_path(filesystem.data(), L"FAT32") && !equal_path(filesystem.data(), L"exFAT")) ||
            (flags & FILE_READ_ONLY_VOLUME))
        {
            return std::unexpected(fail("quick_filesystem_denied", ERROR_NOT_SUPPORTED));
        }
        auto facts = std::make_shared<const quick_volume_facts>(quick_volume_facts{filesystem.data(), flags});
        cache.values.emplace(std::string(volume_key), facts);
        return facts;
    }

    std::size_t quick_processor_cores(std::uint64_t metadata_budget)
    {
        DWORD size{};
        if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &size) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0 || size > metadata_budget)
        {
            return 0;
        }
        std::vector<std::byte> storage(size);
        if (!GetLogicalProcessorInformationEx(RelationProcessorCore,
            reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(storage.data()), &size) ||
            size > storage.size())
        {
            return 0;
        }
        std::size_t cores{};
        std::size_t offset{};
        while (offset < size)
        {
            if (size - offset < offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor))
            {
                return 0;
            }
            const auto* entry = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(storage.data() + offset);
            if (entry->Size < offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor) || entry->Size > size - offset)
            {
                return 0;
            }
            cores += entry->Relationship == RelationProcessorCore ? 1 : 0;
            offset += entry->Size;
        }
        return cores;
    }

    struct quick_storage_profile
    {
        std::vector<DWORD> disks;
        bool topology_known{};
        bool seek_penalty{true};
        STORAGE_BUS_TYPE bus{BusTypeUnknown};
        unsigned io_pressure{};
        bool io_pressure_known{};
    };

    quick_storage_profile quick_storage_information(std::string_view key, std::uint64_t memory_budget)
    {
        quick_storage_profile profile;
        auto decoded = wide(key);
        if (!decoded || decoded->empty())
        {
            return profile;
        }
        decoded->pop_back();
        handle volume(CreateFileW(decoded->c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!volume)
        {
            return profile;
        }
        DWORD returned{};
        std::size_t bytes = sizeof(VOLUME_DISK_EXTENTS) + sizeof(DISK_EXTENT);
        for (;;)
        {
            if (bytes > memory_budget || !std::in_range<DWORD>(bytes))
            {
                break;
            }
            std::vector<std::byte> storage(bytes);
            if (DeviceIoControl(volume.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
                storage.data(), static_cast<DWORD>(storage.size()), &returned, nullptr))
            {
                if (returned < offsetof(VOLUME_DISK_EXTENTS, Extents) || returned > storage.size())
                {
                    break;
                }
                const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(storage.data());
                const auto count = static_cast<std::size_t>(extents->NumberOfDiskExtents);
                if (count == 0 || count > (returned - offsetof(VOLUME_DISK_EXTENTS, Extents)) / sizeof(DISK_EXTENT))
                {
                    break;
                }
                for (std::size_t index = 0; index < count; ++index)
                {
                    profile.disks.push_back(extents->Extents[index].DiskNumber);
                }
                std::sort(profile.disks.begin(), profile.disks.end());
                profile.disks.erase(std::unique(profile.disks.begin(), profile.disks.end()), profile.disks.end());
                profile.topology_known = true;
                break;
            }
            if (GetLastError() != ERROR_MORE_DATA || bytes > (std::numeric_limits<std::size_t>::max)() / 2)
            {
                break;
            }
            bytes *= 2;
        }
        STORAGE_PROPERTY_QUERY query{};
        query.QueryType = PropertyStandardQuery;
        query.PropertyId = StorageDeviceSeekPenaltyProperty;
        DEVICE_SEEK_PENALTY_DESCRIPTOR seek{};
        if (DeviceIoControl(volume.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            &seek, sizeof(seek), &returned, nullptr) && returned >= sizeof(seek))
        {
            profile.seek_penalty = seek.IncursSeekPenalty != FALSE;
        }
        query.PropertyId = StorageDeviceProperty;
        alignas(STORAGE_DEVICE_DESCRIPTOR) std::array<std::byte, sizeof(STORAGE_DEVICE_DESCRIPTOR) + 1024> descriptor{};
        if (DeviceIoControl(volume.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            descriptor.data(), static_cast<DWORD>(descriptor.size()), &returned, nullptr) &&
            returned >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            profile.bus = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(descriptor.data())->BusType;
        }
        // RESOURCE: A volume extent can name a virtual/LUN disk rather than its
        // backing physical media. Hidden pool/RAID/VHD relationships must not be
        // advertised as proven independent physical devices.
        if (profile.bus == BusTypeUnknown || profile.bus == BusTypeRAID || profile.bus == BusTypeVirtual ||
            profile.bus == BusTypeFileBackedVirtual || profile.bus == BusTypeSpaces)
        {
            profile.topology_known = false;
        }
        return profile;
    }

    void quick_storage_pressure(quick_storage_profile& profile)
    {
        // CONTRACT: Do not enable disk performance counters through
        // IOCTL_DISK_PERFORMANCE. Without an already available read-only global
        // observation, pressure stays explicitly unknown; measured operation
        // latency/throughput remains the scheduler feedback signal.
        profile.io_pressure = 0;
        profile.io_pressure_known = false;
    }

    struct quick_observation
    {
        quick::target target;
        FILE_BASIC_INFO basic{};
        DWORD links{};
    };

    bool quick_volume_key_valid(std::string_view value)
    {
        constexpr std::string_view prefix = "\\\\?\\Volume{";
        constexpr std::size_t guid_length = 36;
        if (value.size() != prefix.size() + guid_length + 2 || !value.starts_with(prefix) ||
            !value.ends_with("}\\"))
        {
            return false;
        }
        const auto guid = value.substr(prefix.size(), guid_length);
        for (std::size_t index = 0; index < guid.size(); ++index)
        {
            const auto character = guid[index];
            if (index == 8 || index == 13 || index == 18 || index == 23)
            {
                if (character != '-')
                {
                    return false;
                }
                continue;
            }
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
                (character >= 'A' && character <= 'F')))
            {
                return false;
            }
        }
        return true;
    }

    result<std::pair<std::string, std::string>> quick_file_identity(HANDLE file)
    {
        auto identifier = identity(file);
        if (!identifier)
        {
            return std::unexpected(identifier.error());
        }
        thread_local std::array<wchar_t, 32768> buffer{};
        const DWORD count = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()),
            FILE_NAME_OPENED | VOLUME_NAME_GUID);
        if (count == 0 || count >= buffer.size())
        {
            return std::unexpected(fail("quick_volume_identity_failed"));
        }
        const std::wstring_view name(buffer.data(), count);
        const auto separator = name.find(L"}\\");
        if (!name.starts_with(L"\\\\?\\Volume{") || separator == name.npos)
        {
            return std::unexpected(fail("quick_volume_guid_unavailable", ERROR_NOT_SUPPORTED));
        }
        auto volume = utf8(name.substr(0, separator + 2));
        if (!volume)
        {
            return std::unexpected(volume.error());
        }
        // INVARIANT: Bind persistent file ID to the held volume GUID, not just a
        // reusable drive letter or potentially duplicated volume serial number.
        return std::pair{*volume + ":" + *identifier, std::move(*volume)};
    }

    result<quick_observation> quick_observe(HANDLE file, const std::wstring& path,
        const std::vector<std::wstring>& roots, quick_volume_cache& cache, bool canonical_known = false)
    {
        if (GetFileType(file) != FILE_TYPE_DISK)
        {
            return std::unexpected(fail("quick_nondisk_handle", ERROR_NOT_SUPPORTED));
        }
        quick_observation value;
        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(file, FileBasicInfo, &value.basic, sizeof(value.basic)) ||
            !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)))
        {
            return std::unexpected(fail("quick_metadata_failed"));
        }
        if (standard.AllocationSize.QuadPart < 0)
        {
            return std::unexpected(fail("quick_allocation_size_invalid", ERROR_INVALID_DATA));
        }
        if (standard.DeletePending || (value.basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            return std::unexpected(fail("quick_reparse_or_delete_pending_denied", ERROR_ACCESS_DENIED));
        }
        auto canonical = canonical_known ? result<std::wstring>(path) : final_name(file);
        auto identifier = quick_file_identity(file);
        if (!canonical || !identifier)
        {
            return std::unexpected(!canonical ? canonical.error() : identifier.error());
        }
        // SECURITY: Use exact canonical spelling. Case-sensitive NTFS directories and
        // distinct hardlink names must never collapse into one frozen namespace entry.
        if (*canonical != path)
        {
            return std::unexpected(fail("quick_canonical_namespace_changed", ERROR_INVALID_DATA));
        }
        auto volume = quick_volume_information(file, path, identifier->second, cache);
        if (!volume)
        {
            return std::unexpected(volume.error());
        }
        auto reasons = protection(file, path, roots, value.basic.FileAttributes,
            ((*volume)->flags & FILE_PERSISTENT_ACLS) != 0);
        if (!reasons || !reasons->empty())
        {
            return std::unexpected(!reasons ? reasons.error() :
                fail("quick_" + reasons->front(), ERROR_ACCESS_DENIED));
        }
        auto text = utf8(path);
        if (!text)
        {
            return std::unexpected(text.error());
        }
        value.target.path = std::move(*text);
        value.target.identity = std::move(identifier->first);
        value.target.device_key = std::move(identifier->second);
        value.target.creation_time = static_cast<std::uint64_t>(value.basic.CreationTime.QuadPart);
        value.target.attributes = value.basic.FileAttributes;
        value.target.directory = standard.Directory != FALSE;
        // CONTRACT: Default-stream allocation is only an observed scheduling hint.
        // Hardlinks, named streams, shared extents and open handles affect reclaim.
        value.target.allocated_bytes = value.target.directory ? 0 :
            static_cast<std::uint64_t>(standard.AllocationSize.QuadPart);
        value.links = standard.NumberOfLinks;
        return value;
    }

    struct quick_held
    {
        // INVARIANT: file closes before its ancestor pins are released.
        std::shared_ptr<const std::vector<handle>> ancestors;
        handle file;
        std::wstring path;
        quick_observation observed;
    };

    class windows_quick_backend final : public quick::backend
    {
    public:
        explicit windows_quick_backend(std::wstring state_path, std::optional<scope_binding> scope = {})
            : state_path_(std::move(state_path)), scope_(std::move(scope))
        {
        }

        result<void> begin_execution() override
        {
            if (halted_.load())
            {
                return std::unexpected(fail("critical_quick_thread_token_restore_failed", ERROR_ACCESS_DENIED));
            }
            finish_execution();
            {
                const std::scoped_lock lock(resource_mutex_);
                storage_profiles_.clear();
                physical_cores_ = 0;
            }
            {
                const std::scoped_lock lock(volume_cache_.mutex);
                volume_cache_.values.clear();
            }
            auto scoped = validate_scope(scope_);
            if (!scoped)
            {
                return scoped;
            }
            windows_platform elevation_check(state_path_);
            if (!elevation_check.is_elevated())
            {
                return std::unexpected(fail("administrator_required", ERROR_ELEVATION_REQUIRED));
            }
            auto roots = protection_roots(state_path_);
            if (!roots)
            {
                return std::unexpected(roots.error());
            }
            roots_ = std::move(*roots);
            return {};
        }


        void finish_execution() noexcept override
        {
            const std::scoped_lock lock(context_mutex_);
            contexts_.clear();
            context_handles_ = 0;
        }

        result<quick::resource_sample> inspect_resources(
            std::span<const std::string_view> frozen_device_keys) override
        {
            const std::scoped_lock lock(resource_mutex_);
            auto observed = collect_system_resources();
            if (!observed)
            {
                return std::unexpected(observed.error());
            }
            auto sample = std::move(*observed);
            {
                const std::scoped_lock context_lock(context_mutex_);
                context_handle_budget_ = sample.available_handles / 8;
                for (auto entry = contexts_.begin(); context_handles_ > context_handle_budget_ && entry != contexts_.end();)
                {
                    if (entry->second.first.use_count() == 1)
                    {
                        context_handles_ -= entry->second.first->size();
                        entry = contexts_.erase(entry);
                    }
                    else
                    {
                        ++entry;
                    }
                }
            }
            ULARGE_INTEGER available{}, total{}, free{};
            if (GetDiskFreeSpaceExW(state_path_.substr(0, 7).c_str(), &available, &total, &free))
            {
                sample.temporary_disk_available_bytes = available.QuadPart;
            }
            if (const auto cpu = cpu_counter_.sample())
            {
                sample.cpu_pressure = *cpu;
                sample.cpu_pressure_known = true;
            }
            const auto metadata_budget = (std::min)(sample.available_memory_bytes,
                sample.available_commit_bytes) / 16;
            if (physical_cores_ == 0)
            {
                physical_cores_ = quick_processor_cores(metadata_budget);
            }
            std::set<std::string, std::less<>> unique;
            bool unknown_topology{};
            for (const auto key : frozen_device_keys)
            {
                if (!quick_volume_key_valid(key) || !known_volume(key) || !unique.insert(std::string(key)).second)
                {
                    return std::unexpected(fail("quick_resource_volume_not_prepared", ERROR_INVALID_PARAMETER));
                }
                auto found = storage_profiles_.find(key);
                if (found == storage_profiles_.end())
                {
                    found = storage_profiles_.emplace(std::string(key),
                        quick_storage_information(key, metadata_budget)).first;
                }
                quick_storage_pressure(found->second);
                unknown_topology = unknown_topology || !found->second.topology_known;
            }
            std::vector<std::set<DWORD>> connected;
            std::map<DWORD, std::size_t> membership;
            for (const auto& key : unique)
            {
                const auto& profile = storage_profiles_.at(key);
                std::set<DWORD> merged(profile.disks.begin(), profile.disks.end());
                for (std::size_t index = 0; index < connected.size();)
                {
                    bool overlaps{};
                    for (const auto disk : merged)
                    {
                        overlaps = overlaps || connected[index].contains(disk);
                    }
                    if (overlaps)
                    {
                        merged.insert(connected[index].begin(), connected[index].end());
                        connected.erase(connected.begin() + static_cast<std::ptrdiff_t>(index));
                        index = 0;
                    }
                    else
                    {
                        ++index;
                    }
                }
                if (!merged.empty())
                {
                    connected.push_back(std::move(merged));
                }
            }
            for (std::size_t index = 0; index < connected.size(); ++index)
            {
                for (const auto disk : connected[index])
                {
                    membership[disk] = index;
                }
            }
            for (const auto& key : unique)
            {
                const auto& profile = storage_profiles_.at(key);
                quick::device_resource device;
                device.device_key = key;
                device.scheduling_group = "physical_unknown";
                if (!unknown_topology && !profile.disks.empty())
                {
                    device.scheduling_group = "physical_group_" + std::to_string(membership.at(profile.disks.front()));
                }
                const auto cpu_workers = (std::max)(std::size_t{1}, (std::min)(sample.logical_processors,
                    physical_cores_ != 0 ? physical_cores_ : sample.logical_processors / 2));
                device.concurrency_hint = profile.seek_penalty || profile.bus == BusTypeUsb ? 1 : cpu_workers;
                device.io_pressure = profile.io_pressure;
                device.io_pressure_known = profile.io_pressure_known;
                sample.devices.push_back(std::move(device));
            }
            return sample;
        }


        result<std::vector<quick::target>> prepare(const std::vector<std::string>& paths,
            control& controls) override
        {
            class roots_adapter final : public quick::root_source
            {
            public:
                explicit roots_adapter(const std::vector<std::string>& paths) : paths_(paths)
                {
                }
                result<std::optional<std::string>> next() override
                {
                    if (next_ == paths_.size())
                    {
                        return std::optional<std::string>{};
                    }
                    return std::optional<std::string>(paths_[next_++]);
                }
            private:
                const std::vector<std::string>& paths_;
                std::size_t next_{};
            };
            class collector final : public quick::target_sink
            {
            public:
                explicit collector(windows_quick_backend& owner) : owner_(owner)
                {
                }
                result<void> append(quick::target value) override
                {
                    return owner_.append_target(values, std::move(value), bytes_);
                }
                std::vector<quick::target> values;
            private:
                windows_quick_backend& owner_;
                std::size_t bytes_{};
            };
            roots_adapter input(paths);
            collector output(*this);
            auto prepared = prepare_stream(input, output, controls);
            if (!prepared)
            {
                return std::unexpected(prepared.error());
            }
            return std::move(output.values);
        }

        result<void> prepare_stream(quick::root_source& input, quick::target_sink& output,
            control& controls) override
        {
            finish_execution();
            {
                const std::scoped_lock lock(volumes_mutex_);
                known_volumes_.clear();
            }
            auto initialized = begin_execution();
            if (!initialized)
            {
                return initialized;
            }
            auto resources = inspect_resources({});
            if (!resources)
            {
                return std::unexpected(resources.error());
            }
            preparation_budget_.store((std::min)(resources->available_memory_bytes,
                resources->available_commit_bytes) / 8);
            const auto worker_limit = preparation_worker_limit(*resources);
            if (worker_limit == 0 || preparation_budget_.load() == 0)
            {
                return std::unexpected(fail("quick_preparation_resources_insufficient", ERROR_NOT_ENOUGH_MEMORY));
            }

            struct lease_accounting
            {
                std::mutex mutex;
                std::condition_variable changed;
                std::uint64_t bytes{};
                std::uint64_t handles{};
                std::uint64_t handle_limit{};
            };
            struct ancestry
            {
                std::shared_ptr<lease_accounting> accounting;
                std::shared_ptr<const ancestry> parent;
                std::vector<handle> owned;
                std::uint64_t byte_charge{};
                std::uint64_t handle_charge{};

                ~ancestry()
                {
                    // OWNERSHIP: Release the actual handles before returning
                    // their budget; shared parents remain charged until last use.
                    owned.clear();
                    if (accounting)
                    {
                        const std::scoped_lock lock(accounting->mutex);
                        accounting->bytes -= byte_charge;
                        accounting->handles -= handle_charge;
                        accounting->changed.notify_all();
                    }
                }
            };
            struct work
            {
                std::wstring path;
                std::shared_ptr<const ancestry> ancestors;
                std::size_t depth{};
                std::uint64_t charge{};
            };
            struct shared_state
            {
                std::mutex mutex;
                std::shared_ptr<lease_accounting> leases{std::make_shared<lease_accounting>()};
                std::deque<work> pending;
                std::uint64_t work_bytes{};
                std::uint64_t queued_bytes{};
                std::uint64_t budget{};
                std::size_t active{};
                std::size_t admitted_workers{};
                bool stopping{};
                std::optional<error> failure;
            } state;
            state.budget = (std::min)(resources->available_memory_bytes, resources->available_commit_bytes) / 16;
            state.admitted_workers = worker_limit;
            state.leases->handle_limit = resources->available_handles / 4;
            std::mutex emission_mutex;
            std::mutex workers_mutex;
            std::vector<std::jthread> workers;
            std::atomic_uint64_t emitted{};
            std::atomic<ULONGLONG> last_resource_sample{GetTickCount64()};
            std::function<void()> worker;
            std::function<result<void>(work)> process;

            const auto fail_work = [&](error reason)
            {
                const std::scoped_lock lock(state.mutex);
                if (!state.failure)
                {
                    state.failure = std::move(reason);
                }
                state.stopping = true;
                state.leases->changed.notify_all();
            };
            const auto cancelled = [&]()
            {
                if (controls.request.load() != control_request::proceed)
                {
                    return true;
                }
                const std::scoped_lock lock(state.mutex);
                return state.stopping;
            };
            const auto release_work = [&](const work& value)
            {
                const std::scoped_lock lock(state.mutex);
                state.work_bytes -= value.charge;
                --state.active;
                state.leases->changed.notify_all();
            };
            const auto grow_workers = [&]()
            {
                const std::scoped_lock worker_lock(workers_mutex);
                std::size_t desired{};
                {
                    const std::scoped_lock lock(state.mutex);
                    if (!state.stopping)
                    {
                        desired = (std::min)(worker_limit, (std::min)(state.admitted_workers,
                            state.pending.size() + state.active));
                    }
                }
                while (workers.size() < desired)
                {
                    workers.emplace_back(worker);
                }
            };
            const auto charge_work = [](const work& value) -> std::uint64_t
            {
                // RESOURCE: Include path capacity, queue node, shared lease refs
                // and proportional ancestry scratch; no target-count ceiling.
                return static_cast<std::uint64_t>(value.path.size()) * sizeof(wchar_t) * 4 +
                    sizeof(work) * 4 + static_cast<std::uint64_t>(value.depth + 1) * sizeof(HANDLE) * 4 + 512;
            };
            const auto fits_work = [&](std::uint64_t charge)
            {
                const std::scoped_lock lease_lock(state.leases->mutex);
                return state.leases->bytes <= state.budget && charge <= state.budget - state.leases->bytes &&
                    state.work_bytes <= state.budget - state.leases->bytes - charge;
            };
            const auto reserve_inline = [&](work& value) -> result<void>
            {
                value.charge = charge_work(value);
                const std::scoped_lock lock(state.mutex);
                if (state.stopping || !fits_work(value.charge))
                {
                    return std::unexpected(fail("quick_preparation_working_set_exceeded", ERROR_NOT_ENOUGH_MEMORY));
                }
                state.work_bytes += value.charge;
                return {};
            };
            const auto emit = [&](quick::target value) -> result<void>
            {
                if (cancelled())
                {
                    return std::unexpected(fail("quick_preparation_cancelled", ERROR_CANCELLED));
                }
                const auto volume = value.preparation_error.code.empty() ? value.device_key : std::string{};
                {
                    // CONTRACT: Sinks need not be concurrently writable. No full
                    // roots, targets or dedup set are retained by this pipeline.
                    const std::scoped_lock lock(emission_mutex);
                    auto appended = output.append(std::move(value));
                    if (!appended)
                    {
                        return appended;
                    }
                    if (!volume.empty() && quick_volume_key_valid(volume))
                    {
                        const std::scoped_lock volume_lock(volumes_mutex_);
                        known_volumes_.insert(volume);
                    }
                }
                const auto count = emitted.fetch_add(1) + 1;
                const auto now = GetTickCount64();
                auto previous = last_resource_sample.load();
                if (count % 1024 == 0 && now - previous >= 1000 &&
                    last_resource_sample.compare_exchange_strong(previous, now))
                {
                    auto current = inspect_resources({});
                    if (!current)
                    {
                        return std::unexpected(current.error());
                    }
                    const auto headroom = (std::min)(current->available_memory_bytes, current->available_commit_bytes);
                    reduce_preparation_budget(headroom / 8);
                    const std::scoped_lock lock(state.mutex);
                    state.budget = (std::min)(state.budget, headroom / 16);
                    state.admitted_workers = (std::min)(worker_limit, preparation_worker_limit(*current));
                    bool handle_pressure{};
                    {
                        const std::scoped_lock lease_lock(state.leases->mutex);
                        state.leases->handle_limit = current->available_handles / 4;
                        handle_pressure = state.leases->handles > state.leases->handle_limit;
                    }
                    if (state.admitted_workers == 0 || handle_pressure || !fits_work(0))
                    {
                        return std::unexpected(fail("quick_preparation_resource_pressure", ERROR_NOT_ENOUGH_MEMORY));
                    }
                    state.leases->changed.notify_all();
                }
                return {};
            };
            const auto schedule_child = [&](work value) -> result<void>
            {
                value.charge = charge_work(value);
                bool queued{};
                {
                    const std::scoped_lock lock(state.mutex);
                    const auto queue_budget = state.budget / 2;
                    if (!state.stopping && value.charge <= queue_budget &&
                        state.queued_bytes <= queue_budget - value.charge &&
                        fits_work(value.charge))
                    {
                        state.work_bytes += value.charge;
                        state.queued_bytes += value.charge;
                        // PERFORMANCE: Descendants precede unrelated queued
                        // roots so producer backlogs cannot retain one directory
                        // lease per root while starving their already-known files.
                        state.pending.push_front(value);
                        queued = true;
                        state.leases->changed.notify_all();
                    }
                }
                if (queued)
                {
                    grow_workers();
                    return {};
                }
                // PERFORMANCE: A worker never blocks while producing into its
                // own full queue. Bounded local traversal guarantees progress;
                // its active scratch is charged separately or admission fails.
                auto reserved = reserve_inline(value);
                if (!reserved)
                {
                    return reserved;
                }
                auto completed = process(value);
                {
                    const std::scoped_lock lock(state.mutex);
                    state.work_bytes -= value.charge;
                    state.leases->changed.notify_all();
                }
                return completed;
            };

            process = [&](work value) -> result<void>
            {
                if (cancelled())
                {
                    return std::unexpected(fail("quick_preparation_cancelled", ERROR_CANCELLED));
                }
                const auto rejected = [&](error reason) -> result<void>
                {
                    if (scope_ && !value.ancestors && !scope_contains(*scope_, value.path))
                    {
                        auto admitted = admit_scope_input(*scope_, value.path);
                        if (!admitted)
                        {
                            return admitted;
                        }
                    }
                    auto text = utf8(value.path);
                    if (!text)
                    {
                        return std::unexpected(text.error());
                    }
                    quick::target target;
                    target.path = std::move(*text);
                    target.preparation_error = std::move(reason);
                    return emit(std::move(target));
                };
                if (value.depth > maximum_depth)
                {
                    return rejected(fail("quick_depth_limit", ERROR_BUFFER_OVERFLOW));
                }
                std::vector<handle> owned;
                std::vector<HANDLE> ancestors;
                if (value.ancestors)
                {
                    // PERFORMANCE: Each retained node owns only its own handles.
                    // Build one active scratch chain instead of retaining O(D^2)
                    // copied vectors along a depth-D parent chain.
                    std::vector<const ancestry*> chain;
                    for (auto node = value.ancestors.get(); node != nullptr; node = node->parent.get())
                    {
                        chain.push_back(node);
                    }
                    for (auto node = chain.rbegin(); node != chain.rend(); ++node)
                    {
                        for (const auto& pin : (*node)->owned)
                        {
                            ancestors.push_back(pin.get());
                        }
                    }
                }
                else
                {
                    auto pinned = pin_ancestors(value.path, true);
                    if (!pinned)
                    {
                        return rejected(pinned.error());
                    }
                    owned = std::move(*pinned);
                    for (const auto& pin : owned)
                    {
                        ancestors.push_back(pin.get());
                    }
                    auto scoped = validate_scope(scope_);
                    if (!scoped)
                    {
                        return std::unexpected(scoped.error());
                    }
                }
                for (const auto ancestor : ancestors)
                {
                    FILE_ATTRIBUTE_TAG_INFO tag{};
                    if (!GetFileInformationByHandleEx(ancestor, FileAttributeTagInfo, &tag, sizeof(tag)))
                    {
                        return rejected(fail("quick_ancestor_attributes_changed"));
                    }
                    if (!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                    {
                        return rejected(fail("quick_reparse_ancestor_denied", ERROR_ACCESS_DENIED));
                    }
                }
                handle file(CreateFileW(value.path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
                if (!file)
                {
                    return rejected(fail("quick_preparation_open_failed"));
                }
                auto canonical = final_name(file.get());
                if (!canonical)
                {
                    return rejected(canonical.error());
                }
                // SECURITY: Enumerated children already use the held parent's
                // canonical spelling. A different resolved name is redirection,
                // not another target to silently admit into the frozen batch.
                if (value.ancestors && *canonical != value.path)
                {
                    return rejected(fail("quick_preparation_namespace_changed", ERROR_INVALID_DATA));
                }
                if (scope_ && !scope_contains(*scope_, *canonical))
                {
                    return std::unexpected(fail("quick_target_outside_scope", ERROR_ACCESS_DENIED));
                }
                if (scope_ && *canonical == scope_->path)
                {
                    auto scoped = validate_scope_handle(*scope_, file.get());
                    if (!scoped)
                    {
                        return std::unexpected(scoped.error());
                    }
                }
                auto observed = quick_observe(file.get(), *canonical, roots_, volume_cache_, true);
                if (!observed)
                {
                    return rejected(observed.error());
                }
                if (!observed->target.directory)
                {
                    return emit(std::move(observed->target));
                }
                handle directory(CreateFileW(canonical->c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
                if (!directory)
                {
                    observed->target.preparation_error = fail("quick_directory_enumeration_open_failed");
                    return emit(std::move(observed->target));
                }
                auto lease = std::make_shared<ancestry>();
                lease->parent = std::move(value.ancestors);
                lease->owned = std::move(owned);
                lease->owned.push_back(std::move(directory));
                const auto retained_handles = static_cast<std::uint64_t>(lease->owned.size());
                const auto retained_bytes = static_cast<std::uint64_t>(sizeof(ancestry)) +
                    static_cast<std::uint64_t>(lease->owned.capacity()) * sizeof(handle) * 4 + retained_handles * 4096;
                {
                    const std::scoped_lock lock(state.mutex);
                    const std::scoped_lock lease_lock(state.leases->mutex);
                    if (state.leases->bytes > state.budget || retained_bytes > state.budget - state.leases->bytes ||
                        state.work_bytes > state.budget - state.leases->bytes - retained_bytes ||
                        retained_handles > state.leases->handle_limit ||
                        state.leases->handles > state.leases->handle_limit - retained_handles)
                    {
                        return std::unexpected(fail("quick_preparation_lease_budget_exceeded", ERROR_NOT_ENOUGH_MEMORY));
                    }
                    state.leases->bytes += retained_bytes;
                    state.leases->handles += retained_handles;
                    lease->byte_charge = retained_bytes;
                    lease->handle_charge = retained_handles;
                    lease->accounting = state.leases;
                }
                WIN32_FIND_DATAW entry{};
                quick_search search(FindFirstFileExW((*canonical + L"\\*").c_str(), FindExInfoBasic, &entry,
                    FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH | FIND_FIRST_EX_CASE_SENSITIVE));
                if (search.get() == INVALID_HANDLE_VALUE)
                {
                    const auto native = GetLastError();
                    if (native != ERROR_FILE_NOT_FOUND)
                    {
                        observed->target.preparation_error = fail("quick_directory_enumeration_failed", native);
                    }
                    return emit(std::move(observed->target));
                }
                for (;;)
                {
                    const std::wstring_view name(entry.cFileName);
                    if (name != L"." && name != L"..")
                    {
                        auto queued = schedule_child(work{*canonical + L"\\" + std::wstring(name), lease, value.depth + 1});
                        if (!queued)
                        {
                            return queued;
                        }
                    }
                    if (cancelled())
                    {
                        return std::unexpected(fail("quick_preparation_cancelled", ERROR_CANCELLED));
                    }
                    if (!FindNextFileW(search.get(), &entry))
                    {
                        const auto native = GetLastError();
                        if (native != ERROR_NO_MORE_FILES)
                        {
                            observed->target.preparation_error = fail("quick_directory_enumeration_interrupted", native);
                        }
                        break;
                    }
                }
                // CONTRACT: One final directory record, including its complete
                // immediate enumeration diagnostic; staging sorts/deduplicates.
                return emit(std::move(observed->target));
            };
            worker = [&]()
            {
                quick_privileges privileges;
                auto enabled = privileges.enable(false);
                if (!enabled)
                {
                    fail_work(enabled.error());
                    return;
                }
                try
                {
                    for (;;)
                    {
                        work current;
                        {
                            std::unique_lock lock(state.mutex);
                            state.leases->changed.wait(lock, [&]()
                            {
                                return state.stopping || (!state.pending.empty() && state.active < state.admitted_workers);
                            });
                            if (state.stopping)
                            {
                                break;
                            }
                            current = std::move(state.pending.front());
                            state.pending.pop_front();
                            state.queued_bytes -= current.charge;
                            ++state.active;
                        }
                        auto completed = process(current);
                        release_work(current);
                        if (!completed)
                        {
                            fail_work(completed.error());
                            break;
                        }
                    }
                }
                catch (const std::bad_alloc&)
                {
                    fail_work(fail("quick_preparation_allocation_failed", ERROR_NOT_ENOUGH_MEMORY));
                }
                catch (...)
                {
                    fail_work(fail("quick_preparation_worker_failed", ERROR_GEN_FAILURE));
                }
                auto restored = privileges.restore();
                if (!restored)
                {
                    halted_.store(true);
                    fail_work(restored.error());
                }
            };

            quick_privileges producer_privileges;
            auto producer_enabled = producer_privileges.enable(false);
            if (!producer_enabled)
            {
                return producer_enabled;
            }
            bool any_input{};
            try
            {
                for (;;)
                {
                    if (cancelled())
                    {
                        fail_work(fail("quick_preparation_cancelled", ERROR_CANCELLED));
                        break;
                    }
                    auto next = input.next();
                    if (!next)
                    {
                        fail_work(next.error());
                        break;
                    }
                    if (!*next)
                    {
                        break;
                    }
                    any_input = true;
                    auto decoded = wide(**next);
                    auto normalized = decoded ? absolute(*decoded) : result<std::wstring>(std::unexpected(decoded.error()));
                    if (!normalized)
                    {
                        quick::target rejected;
                        rejected.path = std::move(**next);
                        rejected.preparation_error = normalized.error();
                        auto appended = emit(std::move(rejected));
                        if (!appended)
                        {
                            fail_work(appended.error());
                            break;
                        }
                        continue;
                    }
                    // SECURITY: Root spelling may contain legitimate 8.3 aliases.
                    // The worker checks held canonical scope before enumeration;
                    // even failed opens must prove their nofollow prefix in scope.
                    work value{std::move(*normalized), {}, 0};
                    value.charge = charge_work(value);
                    {
                        std::unique_lock lock(state.mutex);
                        const auto queue_budget = state.budget / 2;
                        if (value.charge > queue_budget)
                        {
                            lock.unlock();
                            fail_work(fail("quick_preparation_working_set_exceeded", ERROR_NOT_ENOUGH_MEMORY));
                            break;
                        }
                        // CONCURRENCY: Retained-lease bytes have their own mutex.
                        // A bounded recheck avoids a lost notification between
                        // inspecting that budget and sleeping on the queue mutex.
                        while (!state.leases->changed.wait_for(lock, std::chrono::milliseconds(100), [&]()
                        {
                            return state.stopping || value.charge > state.budget / 2 ||
                                (state.queued_bytes <= state.budget / 2 - value.charge && fits_work(value.charge));
                        }))
                        {
                            if (controls.request.load() != control_request::proceed)
                            {
                                lock.unlock();
                                fail_work(fail("quick_preparation_cancelled", ERROR_CANCELLED));
                                lock.lock();
                            }
                        }
                        if (state.stopping)
                        {
                            break;
                        }
                        if (value.charge > state.budget / 2)
                        {
                            lock.unlock();
                            fail_work(fail("quick_preparation_working_set_exceeded", ERROR_NOT_ENOUGH_MEMORY));
                            break;
                        }
                        state.work_bytes += value.charge;
                        state.queued_bytes += value.charge;
                        state.pending.push_back(std::move(value));
                        state.leases->changed.notify_all();
                    }
                    grow_workers();
                }
                {
                    std::unique_lock lock(state.mutex);
                    state.leases->changed.wait(lock, [&]()
                    {
                        return state.stopping || (state.pending.empty() && state.active == 0);
                    });
                    state.stopping = true;
                    state.leases->changed.notify_all();
                }
            }
            catch (const std::bad_alloc&)
            {
                fail_work(fail("quick_preparation_allocation_failed", ERROR_NOT_ENOUGH_MEMORY));
            }
            catch (...)
            {
                fail_work(fail("quick_preparation_worker_start_failed", ERROR_GEN_FAILURE));
            }
            {
                // CONTRACT: No writer can still grow the pool after stopping.
                // Join without holding either the queue or worker-vector mutex.
                std::vector<std::jthread> joining;
                {
                    const std::scoped_lock lock(workers_mutex);
                    joining = std::move(workers);
                }
                joining.clear();
            }
            {
                std::deque<work> discarded;
                {
                    const std::scoped_lock lock(state.mutex);
                    discarded.swap(state.pending);
                }
                discarded.clear();
            }
            auto producer_restored = producer_privileges.restore();
            if (!producer_restored)
            {
                halted_.store(true);
                return producer_restored;
            }
            if (state.failure)
            {
                return std::unexpected(*state.failure);
            }
            if (!any_input)
            {
                return std::unexpected(fail("quick_input_empty", ERROR_INVALID_PARAMETER));
            }
            if (controls.request.load() != control_request::proceed)
            {
                return std::unexpected(fail("quick_preparation_cancelled", ERROR_CANCELLED));
            }
            return {};
        }

        result<quick::space_sample> sample_space(std::string_view volume_key) override
        {
            if (halted_.load())
            {
                return std::unexpected(fail("critical_quick_thread_token_restore_failed", ERROR_ACCESS_DENIED));
            }
            // SECURITY: Never accept a user path, suffix, drive alias, UNC or unobserved
            // volume. This immutable allowlist comes from successfully prepared handles.
            if (!quick_volume_key_valid(volume_key) || !known_volume(volume_key))
            {
                return std::unexpected(fail("quick_space_volume_not_prepared", ERROR_INVALID_PARAMETER));
            }
            auto volume = wide(volume_key);
            if (!volume)
            {
                return std::unexpected(volume.error());
            }
            ULARGE_INTEGER available{}, total{}, free{};
            if (!GetDiskFreeSpaceExW(volume->c_str(), &available, &total, &free))
            {
                return std::unexpected(fail("quick_space_observation_failed"));
            }
            // CONTRACT: total is quota-visible to this caller, not raw disk length.
            // Concurrent activity, retained handles and shared allocation can change
            // these samples independently of this job; do not infer reclaimed bytes.
            return quick::space_sample{std::string(volume_key), available.QuadPart,
                free.QuadPart, total.QuadPart};
        }

        result<void> remove(const quick::target& value, bool recover_access) override
        {
            quick_privileges privileges;
            if (recover_access)
            {
                auto enabled = privileges.enable(true);
                if (!enabled)
                {
                    return enabled;
                }
            }
            auto removed = remove_held(value, recover_access);
            auto restored = privileges.restore();
            if (!restored)
            {
                halted_.store(true);
                return restored;
            }
            return removed;
        }

        result<std::vector<locking_process>> query_locks(const quick::target& value) override
        {
            quick_privileges privileges;
            auto enabled = privileges.enable(false);
            if (!enabled)
            {
                return std::unexpected(enabled.error());
            }
            auto held = acquire(value, FILE_READ_ATTRIBUTES | READ_CONTROL);
            auto permitted = held ? process_namespace(*held) : result<void>(std::unexpected(held.error()));
            auto queried = permitted ? query_locking_processes(value.path) :
                result<std::vector<locking_process>>(std::unexpected(permitted.error()));
            auto restored = privileges.restore();
            if (!restored)
            {
                halted_.store(true);
                return std::unexpected(restored.error());
            }
            return queried;
        }

        result<void> close_process(const quick::target& value, const locking_process& process,
            bool force_confirmed) override
        {
            quick_privileges privileges;
            auto enabled = privileges.enable(false);
            if (!enabled)
            {
                return enabled;
            }
            auto held = acquire(value, FILE_READ_ATTRIBUTES | READ_CONTROL);
            auto permitted = held ? process_namespace(*held) : result<void>(std::unexpected(held.error()));
            auto closed = permitted ? request_process_close(value.path, process, force_confirmed) :
                result<void>(std::unexpected(permitted.error()));
            auto restored = privileges.restore();
            if (!restored)
            {
                halted_.store(true);
                return restored;
            }
            return closed;
        }

    private:
        result<void> process_namespace(const quick_held& value)
        {
            // SECURITY: Restart Manager accepts names without an exact-case resolution
            // contract. Keep deletion available, but refuse ambiguous process actions.
            for (const auto& ancestor : *value.ancestors)
            {
                FILE_CASE_SENSITIVE_INFO info{};
                if (!GetFileInformationByHandleEx(ancestor.get(), case_sensitive_info_class, &info, sizeof(info)))
                {
                    const DWORD native = GetLastError();
                    // SECURITY: An unsupported query is unknown, not proof of an
                    // insensitive namespace. Delete access recovery remains independent.
                    return std::unexpected(fail("quick_process_namespace_query_failed", native));
                }
                if ((info.Flags & 1u) != 0)
                {
                    return std::unexpected(fail("quick_case_sensitive_process_action_denied", ERROR_NOT_SUPPORTED));
                }
            }
            return {};
        }

        bool known_volume(std::string_view key)
        {
            const std::scoped_lock lock(volumes_mutex_);
            return known_volumes_.contains(key);
        }

        std::size_t preparation_worker_limit(const quick::resource_sample& sample) const
        {
            const auto memory = (std::min)(sample.available_memory_bytes, sample.available_commit_bytes);
            // RESOURCE: Reserve stack/metadata/temporary open headroom per
            // worker, separately from the retained-lease quarter-budget.
            const auto memory_threads = memory / (8 * 1024 * 1024);
            const auto active_handles = sample.available_handles - sample.available_handles / 4;
            const auto handle_threads = active_handles / (4 * maximum_depth + 16);
            auto limit = (std::min)(static_cast<std::uint64_t>(sample.logical_processors),
                (std::min)(memory_threads, handle_threads));
            if (limit != 0 && sample.cpu_pressure_known && sample.cpu_pressure >= 85)
            {
                limit = (std::max)(std::uint64_t{1}, limit / 4);
            }
            return static_cast<std::size_t>(limit);
        }

        void reduce_preparation_budget(std::uint64_t value)
        {
            auto prior = preparation_budget_.load();
            while (value < prior && !preparation_budget_.compare_exchange_weak(prior, value))
            {
            }
        }

        result<void> append_target(std::vector<quick::target>& output, quick::target value,
            std::size_t& text_bytes)
        {
            if (output.size() % 1024 == 0)
            {
                auto fresh = inspect_resources({});
                if (!fresh)
                {
                    return std::unexpected(fresh.error());
                }
                reduce_preparation_budget((std::min)(fresh->available_memory_bytes, fresh->available_commit_bytes) / 8);
            }
            constexpr std::uint64_t diagnostic_reserve = 512;
            const auto text = static_cast<std::uint64_t>(value.path.size()) + value.identity.size() +
                value.device_key.size() + diagnostic_reserve;
            constexpr std::uint64_t overhead = sizeof(quick::target) * 8;
            if (text > ((std::numeric_limits<std::uint64_t>::max)() - overhead) / 8)
            {
                return std::unexpected(fail("quick_preparation_size_overflow", ERROR_ARITHMETIC_OVERFLOW));
            }
            const auto additional = text * 8 + overhead;
            const auto budget = preparation_budget_.load();
            if (text_bytes > budget || additional > budget - text_bytes)
            {
                return std::unexpected(fail("quick_preparation_resource_budget_exceeded", ERROR_NOT_ENOUGH_MEMORY));
            }
            text_bytes += static_cast<std::size_t>(additional);
            output.push_back(std::move(value));
            return {};
        }


        result<std::shared_ptr<const std::vector<handle>>> acquire_context(const std::wstring& path,
            bool directory)
        {
            const auto separator = path.find_last_of(L'\\');
            const auto parent = path.substr(0, separator == 6 ? 7 : separator);
            {
                const std::scoped_lock lock(context_mutex_);
                if (directory)
                {
                    // SECURITY: Cached leases must not keep the selected directory
                    // alive. Active child work retains its own shared lease and then
                    // deletion fails safely; the core DAG schedules only ready parents.
                    for (auto entry = contexts_.begin(); entry != contexts_.end();)
                    {
                        if (entry->first == path || (entry->first.size() > path.size() &&
                            entry->first.starts_with(path) && entry->first[path.size()] == L'\\'))
                        {
                            context_handles_ -= entry->second.first->size();
                            entry = contexts_.erase(entry);
                        }
                        else
                        {
                            ++entry;
                        }
                    }
                }
                const auto prior = contexts_.find(parent);
                if (prior != contexts_.end())
                {
                    prior->second.second = GetTickCount64();
                    return prior->second.first;
                }
            }
            // PERFORMANCE: Potentially blocking WinAPI work stays outside the
            // cache mutex; unrelated ready contexts remain available to workers.
            auto pinned = pin_ancestors(path, true);
            if (!pinned)
            {
                return std::unexpected(pinned.error());
            }
            auto scoped = validate_scope(scope_);
            if (!scoped)
            {
                return std::unexpected(scoped.error());
            }
            auto held = std::make_shared<const std::vector<handle>>(std::move(*pinned));
            const std::scoped_lock lock(context_mutex_);
            if (const auto concurrent = contexts_.find(parent); concurrent != contexts_.end())
            {
                concurrent->second.second = GetTickCount64();
                return concurrent->second.first;
            }
            while (held->size() <= context_handle_budget_ &&
                context_handles_ > context_handle_budget_ - held->size())
            {
                auto oldest = contexts_.end();
                for (auto item = contexts_.begin(); item != contexts_.end(); ++item)
                {
                    if (item->second.first.use_count() == 1 &&
                        (oldest == contexts_.end() || item->second.second < oldest->second.second))
                    {
                        oldest = item;
                    }
                }
                if (oldest == contexts_.end())
                {
                    break;
                }
                context_handles_ -= oldest->second.first->size();
                contexts_.erase(oldest);
            }
            if (held->size() <= context_handle_budget_ &&
                context_handles_ <= context_handle_budget_ - held->size())
            {
                context_handles_ += held->size();
                contexts_.emplace(parent, std::pair{held, GetTickCount64()});
            }
            return held;
        }


        result<quick_held> acquire(const quick::target& value, DWORD access)
        {
            if (halted_.load())
            {
                return std::unexpected(fail("critical_quick_thread_token_restore_failed", ERROR_ACCESS_DENIED));
            }
            if (roots_.empty() || !value.preparation_error.code.empty() || value.identity.empty())
            {
                return std::unexpected(fail("quick_unbound_or_unprepared_target", ERROR_ACCESS_DENIED));
            }
            auto decoded = wide(value.path);
            if (!decoded)
            {
                return std::unexpected(decoded.error());
            }
            auto path = absolute(*decoded);
            if (!path)
            {
                return std::unexpected(path.error());
            }
            if (scope_ && !scope_contains(*scope_, *path))
            {
                return std::unexpected(fail("quick_target_outside_scope", ERROR_ACCESS_DENIED));
            }
            auto ancestors = acquire_context(*path, value.directory);
            if (!ancestors)
            {
                return std::unexpected(ancestors.error());
            }
            // SECURITY: Sharing denies ancestor rename/delete, not all attribute
            // writes. Refresh mutable reparse state even on a cache hit; canonical
            // namespace + held target identity are checked again after open.
            for (const auto& ancestor : **ancestors)
            {
                FILE_ATTRIBUTE_TAG_INFO tag{};
                if (!GetFileInformationByHandleEx(ancestor.get(), FileAttributeTagInfo, &tag, sizeof(tag)))
                {
                    return std::unexpected(fail("quick_ancestor_attributes_changed"));
                }
                if (!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                {
                    return std::unexpected(fail("quick_reparse_ancestor_denied", ERROR_ACCESS_DENIED));
                }
            }
            handle file(CreateFileW(path->c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
            if (!file)
            {
                return std::unexpected(fail("quick_target_open_failed"));
            }
            if (scope_ && *path == scope_->path)
            {
                auto scoped = validate_scope_handle(*scope_, file.get());
                if (!scoped)
                {
                    return std::unexpected(scoped.error());
                }
            }
            auto observed = quick_observe(file.get(), *path, roots_, volume_cache_);
            if (!observed)
            {
                return std::unexpected(observed.error());
            }
            if (observed->target.identity != value.identity ||
                observed->target.creation_time != value.creation_time ||
                observed->target.directory != value.directory || observed->target.path != value.path)
            {
                return std::unexpected(fail("quick_frozen_identity_changed", ERROR_INVALID_DATA));
            }
            return quick_held{std::move(*ancestors), std::move(file), std::move(*path), std::move(*observed)};
        }

        result<void> remove_held(const quick::target& value, bool recover_access)
        {
            auto held = acquire(value, FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE |
                (recover_access ? FILE_WRITE_ATTRIBUTES : 0));
            if (!held)
            {
                return std::unexpected(held.error());
            }
            // CONTRACT: Ordinary deletion removes this name; no stream/content read,
            // overwrite, Flush, VSS enumeration, media topology query or TRIM is performed.
            FILE_DISPOSITION_INFO_EX disposition{};
            disposition.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
            if (!SetFileInformationByHandle(held->file.get(), FileDispositionInfoEx, &disposition, sizeof(disposition)))
            {
                const DWORD native = GetLastError();
                const bool readonly = (held->observed.basic.FileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
                const bool readonly_retry = recover_access && readonly && held->observed.links == 1 &&
                    native == ERROR_ACCESS_DENIED;
                if (native != ERROR_INVALID_PARAMETER && native != ERROR_NOT_SUPPORTED &&
                    native != ERROR_INVALID_FUNCTION && !readonly_retry)
                {
                    return std::unexpected(fail("quick_disposition_failed", native));
                }
                bool changed{};
                if (readonly)
                {
                    if (!recover_access || held->observed.links > 1)
                    {
                        return std::unexpected(fail("quick_readonly_recovery_required", ERROR_ACCESS_DENIED));
                    }
                    FILE_BASIC_INFO basic{};
                    basic.FileAttributes = held->observed.basic.FileAttributes & ~FILE_ATTRIBUTE_READONLY;
                    if (basic.FileAttributes == 0)
                    {
                        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                    }
                    if (!SetFileInformationByHandle(held->file.get(), FileBasicInfo, &basic, sizeof(basic)))
                    {
                        return std::unexpected(fail("quick_readonly_clear_failed"));
                    }
                    changed = true;
                }
                FILE_DISPOSITION_INFO fallback{TRUE};
                if (!SetFileInformationByHandle(held->file.get(), FileDispositionInfo, &fallback, sizeof(fallback)))
                {
                    const DWORD deletion_error = GetLastError();
                    if (changed)
                    {
                        FILE_BASIC_INFO original{};
                        original.FileAttributes = held->observed.basic.FileAttributes;
                        if (!SetFileInformationByHandle(held->file.get(), FileBasicInfo, &original, sizeof(original)))
                        {
                            return std::unexpected(fail("critical_quick_readonly_restore_failed"));
                        }
                    }
                    return std::unexpected(fail("quick_legacy_disposition_failed", deletion_error));
                }
            }
            held->file.reset();
            // SECURITY: Keep ancestors pinned while verifying namespace removal. A new
            // replacement is observed, never acted on. Delete-pending is not success.
            handle probe(CreateFileW(held->path.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
            if (!probe)
            {
                const DWORD native = GetLastError();
                if (native == ERROR_FILE_NOT_FOUND || native == ERROR_PATH_NOT_FOUND)
                {
                    return {};
                }
                return std::unexpected(fail("quick_deletion_not_observed_may_be_pending", native));
            }
            auto remaining = quick_file_identity(probe.get());
            if (!remaining)
            {
                return std::unexpected(remaining.error());
            }
            if (remaining->first == value.identity)
            {
                return std::unexpected(fail("quick_original_name_still_present", ERROR_BUSY));
            }
            return {};
        }

        std::wstring state_path_;
        std::optional<scope_binding> scope_;
        std::vector<std::wstring> roots_;
        std::mutex volumes_mutex_;
        std::set<std::string, std::less<>> known_volumes_;
        quick_volume_cache volume_cache_;
        std::mutex resource_mutex_;
        quick_cpu_counter cpu_counter_;
        std::size_t physical_cores_{};
        std::map<std::string, quick_storage_profile, std::less<>> storage_profiles_;
        std::atomic_uint64_t preparation_budget_{};
        std::uint64_t context_handle_budget_{};
        std::mutex context_mutex_;
        std::map<std::wstring, std::pair<std::shared_ptr<const std::vector<handle>>, ULONGLONG>> contexts_;
        std::uint64_t context_handles_{};
        std::atomic_bool halted_{};
    };
}

result<std::unique_ptr<quick::backend>> make_windows_quick_backend(std::wstring_view state_directory,
    std::wstring_view allowed_scope_root)
{
    auto normalized = absolute(state_directory);
    if (!normalized)
    {
        return std::unexpected(normalized.error());
    }
    auto scope = bind_scope(*normalized, allowed_scope_root);
    if (!scope)
    {
        return std::unexpected(scope.error());
    }
    return std::unique_ptr<quick::backend>(std::make_unique<windows_quick_backend>(std::move(*normalized), std::move(*scope)));
}

result<std::unique_ptr<platform>> make_windows_platform(std::wstring_view state_directory,
    std::wstring_view allowed_scope_root)
{
    auto normalized = absolute(state_directory);
    if (!normalized)
    {
        return std::unexpected(normalized.error());
    }
    auto scope = bind_scope(*normalized, allowed_scope_root);
    if (!scope)
    {
        return std::unexpected(scope.error());
    }
    return std::unique_ptr<platform>(std::make_unique<windows_platform>(std::move(*normalized), std::move(*scope)));
}
}
