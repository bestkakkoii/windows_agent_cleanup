module;

// INTEROP: Restart Manager and process APIs expose Windows SDK C declarations.
#include <Windows.h>
#include <restartmanager.h>
#include <winsvc.h>

module secure_erase.windows_backend;

import std;
import secure_erase.model;
import secure_erase.platform;

namespace secure_erase::engine
{
namespace
{
    class lock_handle
    {
    public:
        explicit lock_handle(HANDLE value = nullptr) noexcept : value_(value)
        {
        }

        ~lock_handle()
        {
            if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE)
            {
                CloseHandle(value_);
            }
        }

        lock_handle(const lock_handle&) = delete;
        lock_handle& operator=(const lock_handle&) = delete;

        HANDLE get() const noexcept
        {
            return value_;
        }

    private:
        HANDLE value_;
    };

    struct rm_session
    {
        DWORD value{};
        bool active{};
        ~rm_session()
        {
            if (active)
            {
                RmEndSession(value);
            }
        }
    };

    result<std::wstring> lock_path(std::string_view value)
    {
        if (value.empty() || value.size() > 32767 * 4 || value.find('\0') != value.npos)
        {
            return std::unexpected(error{"lock_path_invalid", ERROR_INVALID_NAME});
        }
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0);
        if (count <= 0)
        {
            return std::unexpected(error{"lock_path_encoding_invalid", GetLastError()});
        }
        std::wstring path(static_cast<std::size_t>(count), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), path.data(), count) != count)
        {
            return std::unexpected(error{"lock_path_encoding_failed", GetLastError()});
        }
        std::array<wchar_t, 32768> buffer{};
        const DWORD size = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (size == 0 || size >= buffer.size())
        {
            return std::unexpected(error{"lock_path_normalization_failed", GetLastError()});
        }
        return std::wstring(buffer.data(), size);
    }

    std::uint64_t ticks(FILETIME value)
    {
        return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }

    result<std::vector<RM_PROCESS_INFO>> rm_processes(std::string_view path)
    {
        auto converted = lock_path(path);
        if (!converted)
        {
            return std::unexpected(converted.error());
        }
        rm_session session;
        std::array<wchar_t, CCH_RM_SESSION_KEY + 1> key{};
        DWORD status = RmStartSession(&session.value, 0, key.data());
        if (status != ERROR_SUCCESS)
        {
            return std::unexpected(error{"restart_manager_start_failed", status});
        }
        session.active = true;
        constexpr UINT resource_count = 1;
        // INTEROP: SDK accepts mutable pointer slots; each referenced filename remains const.
        std::array<LPCWSTR, resource_count> resources{converted->c_str()};
        status = RmRegisterResources(session.value, resource_count, resources.data(), 0, nullptr, 0, nullptr);
        if (status != ERROR_SUCCESS)
        {
            return std::unexpected(error{"restart_manager_register_failed", status});
        }
        // SECURITY: Never call RmShutdown: it refreshes and may close newly discovered processes
        // that the operator has not reviewed. Discovery is separated from exact PID actions.
        for (int attempt = 0; attempt < 4; ++attempt)
        {
            UINT needed{}, count{};
            DWORD reason{};
            status = RmGetList(session.value, &needed, &count, nullptr, &reason);
            if (status == ERROR_SUCCESS)
            {
                return std::vector<RM_PROCESS_INFO>{};
            }
            if (status != ERROR_MORE_DATA || needed == 0 || needed > 4096)
            {
                return std::unexpected(error{"restart_manager_list_failed", status});
            }
            std::vector<RM_PROCESS_INFO> values(needed);
            count = needed;
            status = RmGetList(session.value, &needed, &count, values.data(), &reason);
            if (status == ERROR_MORE_DATA)
            {
                continue;
            }
            if (status != ERROR_SUCCESS)
            {
                return std::unexpected(error{"restart_manager_list_failed", status});
            }
            values.resize(count);
            return values;
        }
        return std::unexpected(error{"locking_process_list_unstable", ERROR_RETRY});
    }

    result<std::vector<std::byte>> token_user(HANDLE process)
    {
        HANDLE raw{};
        if (!OpenProcessToken(process, TOKEN_QUERY, &raw))
        {
            return std::unexpected(error{"process_token_unknown", GetLastError()});
        }
        lock_handle token(raw);
        DWORD needed{};
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 65536)
        {
            return std::unexpected(error{"process_token_size_invalid", GetLastError()});
        }
        std::vector<std::byte> buffer(needed);
        if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), needed, &needed))
        {
            return std::unexpected(error{"process_token_read_failed", GetLastError()});
        }
        return buffer;
    }

    result<bool> service_process(DWORD pid)
    {
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (manager == nullptr)
        {
            return std::unexpected(error{"process_service_inventory_unavailable", GetLastError()});
        }
        DWORD needed{}, count{}, resume{};
        EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_ACTIVE, nullptr, 0, &needed, &count, &resume, nullptr);
        const DWORD native = GetLastError();
        if (native != ERROR_MORE_DATA || needed == 0 || needed > 16 * 1024 * 1024)
        {
            CloseServiceHandle(manager);
            return std::unexpected(error{"process_service_inventory_size_failed", native});
        }
        std::vector<std::byte> data(needed);
        resume = 0;
        const bool okay = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_ACTIVE, reinterpret_cast<BYTE*>(data.data()), needed, &needed, &count, &resume, nullptr) != FALSE;
        const DWORD query_error = GetLastError();
        CloseServiceHandle(manager);
        if (!okay)
        {
            return std::unexpected(error{"process_service_inventory_failed", query_error});
        }
        const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(data.data());
        for (DWORD index = 0; index < count; ++index)
        {
            if (entries[index].ServiceStatusProcess.dwProcessId == pid)
            {
                return true;
            }
        }
        return false;
    }

    result<void> eligible_process(HANDLE process, const RM_PROCESS_INFO& record, std::string& image)
    {
        const DWORD pid = record.Process.dwProcessId;
        if (pid <= 4 || pid == GetCurrentProcessId() || record.ApplicationType == RmService ||
            record.ApplicationType == RmCritical || record.ApplicationType == RmExplorer ||
            record.ApplicationType == RmUnknownApp || record.strServiceShortName[0] != L'\0')
        {
            return std::unexpected(error{"process_class_protected", ERROR_ACCESS_DENIED});
        }
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(process, &created, &exited, &kernel, &user) ||
            ticks(created) != ticks(record.Process.ProcessStartTime))
        {
            return std::unexpected(error{"process_identity_changed", ERROR_INVALID_DATA});
        }
        DWORD session{}, current_session{};
        if (!ProcessIdToSessionId(pid, &session) || !ProcessIdToSessionId(GetCurrentProcessId(), &current_session) ||
            session != current_session || session == 0)
        {
            return std::unexpected(error{"process_session_protected", ERROR_ACCESS_DENIED});
        }
        BOOL critical{};
        PROCESS_PROTECTION_LEVEL_INFORMATION protection{};
        if (!IsProcessCritical(process, &critical) || critical ||
            !GetProcessInformation(process, ProcessProtectionLevelInfo, &protection, sizeof(protection)) ||
            protection.ProtectionLevel != PROTECTION_LEVEL_NONE)
        {
            return std::unexpected(error{"process_protection_unknown_or_protected", ERROR_ACCESS_DENIED});
        }
        auto owner = token_user(process);
        auto current = token_user(GetCurrentProcess());
        if (!owner || !current)
        {
            return std::unexpected(!owner ? owner.error() : current.error());
        }
        auto* owner_info = reinterpret_cast<TOKEN_USER*>(owner->data());
        auto* current_info = reinterpret_cast<TOKEN_USER*>(current->data());
        if (!IsValidSid(owner_info->User.Sid) || !IsValidSid(current_info->User.Sid) ||
            !EqualSid(owner_info->User.Sid, current_info->User.Sid) ||
            IsWellKnownSid(owner_info->User.Sid, WinLocalSystemSid) ||
            IsWellKnownSid(owner_info->User.Sid, WinLocalServiceSid) ||
            IsWellKnownSid(owner_info->User.Sid, WinNetworkServiceSid))
        {
            return std::unexpected(error{"process_owner_protected", ERROR_ACCESS_DENIED});
        }
        auto is_service = service_process(pid);
        if (!is_service || *is_service)
        {
            return std::unexpected(!is_service ? is_service.error() : error{"service_process_protected", ERROR_ACCESS_DENIED});
        }
        std::vector<wchar_t> path(32768);
        DWORD length = static_cast<DWORD>(path.size());
        if (!QueryFullProcessImageNameW(process, 0, path.data(), &length) || length == 0)
        {
            return std::unexpected(error{"process_image_unknown", GetLastError()});
        }
        std::array<wchar_t, 32768> windows{};
        const UINT windows_length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
        if (windows_length == 0 || windows_length >= windows.size())
        {
            return std::unexpected(error{"process_windows_root_unknown", GetLastError()});
        }
        if (length >= windows_length && CompareStringOrdinal(path.data(), static_cast<int>(windows_length),
            windows.data(), static_cast<int>(windows_length), TRUE) == CSTR_EQUAL &&
            (length == windows_length || path[windows_length] == L'\\'))
        {
            return std::unexpected(error{"windows_process_protected", ERROR_ACCESS_DENIED});
        }
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), static_cast<int>(length),
            nullptr, 0, nullptr, nullptr);
        if (size <= 0)
        {
            return std::unexpected(error{"process_image_encoding_failed", GetLastError()});
        }
        image.resize(static_cast<std::size_t>(size));
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), static_cast<int>(length),
            image.data(), size, nullptr, nullptr) != size)
        {
            return std::unexpected(error{"process_image_encoding_failed", GetLastError()});
        }
        return {};
    }

    struct close_context
    {
        DWORD process_id{};
        ULONGLONG deadline{};
        bool sent{};
    };

    BOOL CALLBACK close_window(HWND window, LPARAM parameter)
    {
        auto* context = reinterpret_cast<close_context*>(parameter);
        const ULONGLONG now = GetTickCount64();
        if (now >= context->deadline)
        {
            return FALSE;
        }
        DWORD pid{};
        GetWindowThreadProcessId(window, &pid);
        if (pid == context->process_id)
        {
            DWORD_PTR response{};
            const UINT timeout = static_cast<UINT>((std::min)(context->deadline - now, 250ULL));
            SendMessageTimeoutW(window, WM_CLOSE, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK,
                timeout, &response);
            context->sent = true;
        }
        return TRUE;
    }
}

result<std::vector<locking_process>> query_locking_processes(std::string_view path)
{
    auto records = rm_processes(path);
    if (!records)
    {
        return std::unexpected(records.error());
    }
    std::vector<locking_process> output;
    for (const auto& record : *records)
    {
        locking_process value;
        value.process_id = record.Process.dwProcessId;
        value.creation_time = ticks(record.Process.ProcessStartTime);
        lock_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, value.process_id));
        if (process.get() == nullptr)
        {
            value.denial_reason = "process_query_denied";
        }
        else
        {
            auto allowed = eligible_process(process.get(), record, value.image_path);
            value.eligible = allowed.has_value();
            if (!allowed)
            {
                value.denial_reason = allowed.error().code;
            }
        }
        output.push_back(std::move(value));
    }
    return output;
}

result<void> request_process_close(std::string_view path, const locking_process& requested,
    bool force_confirmed, std::uint32_t timeout_ms)
{
    if (timeout_ms == 0 || timeout_ms > 10000 || !requested.eligible)
    {
        return std::unexpected(error{"process_action_invalid", ERROR_INVALID_PARAMETER});
    }
    auto records = rm_processes(path);
    if (!records)
    {
        return std::unexpected(records.error());
    }
    const auto found = std::find_if(records->begin(), records->end(), [&requested](const auto& record)
    {
        return record.Process.dwProcessId == requested.process_id &&
            ticks(record.Process.ProcessStartTime) == requested.creation_time;
    });
    if (found == records->end())
    {
        return std::unexpected(error{"process_no_longer_registered_lock_owner", ERROR_NOT_FOUND});
    }
    const DWORD access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | (force_confirmed ? PROCESS_TERMINATE : 0);
    lock_handle process(OpenProcess(access, FALSE, requested.process_id));
    if (process.get() == nullptr)
    {
        return std::unexpected(error{"process_action_open_failed", GetLastError()});
    }
    std::string image;
    auto allowed = eligible_process(process.get(), *found, image);
    if (!allowed)
    {
        return allowed;
    }
    if (image != requested.image_path)
    {
        return std::unexpected(error{"process_image_changed", ERROR_INVALID_DATA});
    }
    close_context context{requested.process_id, GetTickCount64() + timeout_ms, false};
    EnumWindows(close_window, reinterpret_cast<LPARAM>(&context));
    const ULONGLONG now = GetTickCount64();
    const DWORD remaining = now < context.deadline ? static_cast<DWORD>(context.deadline - now) : 0;
    const DWORD waited = WaitForSingleObject(process.get(), remaining);
    if (waited == WAIT_OBJECT_0)
    {
        return {};
    }
    if (waited != WAIT_TIMEOUT)
    {
        return std::unexpected(error{"process_close_wait_failed", GetLastError()});
    }
    if (!force_confirmed)
    {
        return std::unexpected(error{context.sent ? "process_graceful_close_timeout" : "process_has_no_closable_window", WAIT_TIMEOUT});
    }
    // SECURITY: Recheck service registration and protection immediately before using held process
    // handle. PID recycling cannot redirect TerminateProcess; this handle owns the original process.
    allowed = eligible_process(process.get(), *found, image);
    if (!allowed)
    {
        return allowed;
    }
    if (!TerminateProcess(process.get(), ERROR_CANCELLED))
    {
        return std::unexpected(error{"process_termination_failed", GetLastError()});
    }
    if (WaitForSingleObject(process.get(), 5000) != WAIT_OBJECT_0)
    {
        return std::unexpected(error{"process_termination_unconfirmed", WAIT_TIMEOUT});
    }
    return {};
}
}
