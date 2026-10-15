module;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

module secure_erase.retained_copies;

import std;

namespace secure_erase::windows
{
    namespace
    {
        struct com_release
        {
            void operator()(IUnknown* value) const noexcept
            {
                if (value != nullptr)
                {
                    value->Release();
                }
            }
        };

        struct apartment_scope
        {
            bool initialized{};

            ~apartment_scope()
            {
                if (initialized)
                {
                    CoUninitialize();
                }
            }
        };

        struct snapshot_scope
        {
            VSS_OBJECT_PROP value{};

            ~snapshot_scope()
            {
                if (value.Type == VSS_OBJECT_SNAPSHOT)
                {
                    VssFreeSnapshotProperties(&value.Obj.Snap);
                }
            }
        };

        bool valid_volume(std::wstring_view value) noexcept
        {
            if (value.size() != 49 || !value.starts_with(L"\\\\?\\Volume{") || !value.ends_with(L"}\\"))
            {
                return false;
            }
            // CONTRACT: Validate canonical GUID alphabet/positions before COM use.
            const auto guid = value.substr(11, 36);
            for (std::size_t index{}; index < guid.size(); ++index)
            {
                if (index == 8 || index == 13 || index == 18 || index == 23)
                {
                    if (guid[index] != L'-')
                    {
                        return false;
                    }
                }
                else if (!((guid[index] >= L'0' && guid[index] <= L'9')
                    || (guid[index] >= L'a' && guid[index] <= L'f')
                    || (guid[index] >= L'A' && guid[index] <= L'F')))
                {
                    return false;
                }
            }
            return true;
        }

        bool same_volume(const wchar_t* observed, std::wstring_view expected) noexcept
        {
            if (observed == nullptr)
            {
                return false;
            }
            std::size_t length{};
            while (length < 32768 && observed[length] != L'\0')
            {
                ++length;
            }
            if (length != expected.size())
            {
                return false;
            }
            return CompareStringOrdinal(observed, static_cast<int>(length), expected.data(),
                static_cast<int>(expected.size()), TRUE) == CSTR_EQUAL;
        }

        retained_copy_observation unknown(HRESULT status, std::uint32_t partial_count = 0) noexcept
        {
            return {false, partial_count, static_cast<std::uint32_t>(status)};
        }
    }

    retained_copy_observation query_retained_copies(std::wstring_view volume_guid_path)
    {
        if (!valid_volume(volume_guid_path))
        {
            return unknown(E_INVALIDARG);
        }
        const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        apartment_scope apartment{SUCCEEDED(initialized)};
        if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE)
        {
            return unknown(initialized);
        }
        // SECURITY: Process-wide COM security is configured once when not already set.
        // Existing host settings are retained on RPC_E_TOO_LATE; actual query failures
        // remain explicit unknown instead of being reported as absence of snapshots.
        HRESULT status = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr,
            EOAC_DYNAMIC_CLOAKING, nullptr);
        if (FAILED(status) && status != RPC_E_TOO_LATE)
        {
            return unknown(status);
        }
        IVssBackupComponents* raw_components{};
        status = CreateVssBackupComponents(&raw_components);
        std::unique_ptr<IVssBackupComponents, com_release> components(raw_components);
        if (FAILED(status) || !components)
        {
            return unknown(FAILED(status) ? status : E_UNEXPECTED);
        }
        status = components->InitializeForBackup();
        if (FAILED(status))
        {
            return unknown(status);
        }
        status = components->SetContext(static_cast<LONG>(VSS_CTX_ALL));
        if (FAILED(status))
        {
            return unknown(status);
        }
        constexpr GUID all_objects{};
        IVssEnumObject* raw_enumeration{};
        status = components->Query(all_objects, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &raw_enumeration);
        std::unique_ptr<IVssEnumObject, com_release> enumeration(raw_enumeration);
        if (FAILED(status))
        {
            return unknown(status);
        }
        if (!enumeration)
        {
            return status == S_FALSE ? retained_copy_observation{true, 0, 0} : unknown(E_UNEXPECTED);
        }
        std::uint32_t matching{};
        constexpr std::uint32_t maximum_enumerated{65536};
        for (std::uint32_t index{}; index < maximum_enumerated; ++index)
        {
            snapshot_scope entry;
            ULONG fetched{};
            status = enumeration->Next(1, &entry.value, &fetched);
            if (FAILED(status))
            {
                return unknown(status, matching);
            }
            if (fetched == 0 && status == S_FALSE)
            {
                return {true, matching, 0};
            }
            if (fetched != 1 || entry.value.Type != VSS_OBJECT_SNAPSHOT)
            {
                return unknown(E_UNEXPECTED, matching);
            }
            if (same_volume(entry.value.Obj.Snap.m_pwszOriginalVolumeName, volume_guid_path))
            {
                ++matching;
            }
            if (status == S_FALSE)
            {
                return {true, matching, 0};
            }
        }
        return unknown(HRESULT_FROM_WIN32(ERROR_MORE_DATA), matching);
    }
}
