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

        // Evidence parsing is deliberately independent of execution admission.
        // Bounded trees validate complete JSON records, including duplicate keys;
        // only the original final bytes are returned to preserve integer precision.
        enum class evidence_kind
        {
            object,
            array,
            string,
            number,
            boolean,
            null_value
        };

        struct evidence_value
        {
            evidence_kind kind{evidence_kind::null_value};
            std::string text;
            std::vector<std::pair<std::string, evidence_value>> members;
            std::vector<evidence_value> elements;

            const evidence_value* member(std::string_view name) const noexcept
            {
                const auto found = std::ranges::find_if(members, [&](const auto& item)
                {
                    return item.first == name;
                });
                return found == members.end() ? nullptr : &found->second;
            }
        };

        class evidence_parser
        {
        public:
            explicit evidence_parser(std::string_view text) noexcept : text_(text)
            {
            }

            std::optional<evidence_value> parse()
            {
                if (!valid_utf8(text_))
                {
                    return std::nullopt;
                }
                auto value = parse_value(0);
                space();
                return position_ == text_.size() ? std::move(value) : std::nullopt;
            }

        private:
            void space() noexcept
            {
                while (position_ < text_.size() && (text_[position_] == ' ' || text_[position_] == '\t'
                    || text_[position_] == '\r' || text_[position_] == '\n'))
                {
                    ++position_;
                }
            }

            bool take(char value) noexcept
            {
                space();
                if (position_ == text_.size() || text_[position_] != value)
                {
                    return false;
                }
                ++position_;
                return true;
            }

            std::optional<std::uint32_t> hex_quad() noexcept
            {
                if (text_.size() - position_ < 4)
                {
                    return std::nullopt;
                }
                std::uint32_t point{};
                for (unsigned index{}; index < 4; ++index)
                {
                    const auto byte = text_[position_++];
                    const auto digit = byte >= '0' && byte <= '9' ? byte - '0'
                        : byte >= 'a' && byte <= 'f' ? byte - 'a' + 10
                        : byte >= 'A' && byte <= 'F' ? byte - 'A' + 10 : -1;
                    if (digit < 0)
                    {
                        return std::nullopt;
                    }
                    point = (point << 4) | static_cast<std::uint32_t>(digit);
                }
                return point;
            }

            std::optional<std::string> string()
            {
                if (!take('"'))
                {
                    return std::nullopt;
                }
                std::string value;
                while (position_ < text_.size())
                {
                    const auto byte = static_cast<unsigned char>(text_[position_++]);
                    if (byte == '"')
                    {
                        return value;
                    }
                    if (byte < 0x20)
                    {
                        return std::nullopt;
                    }
                    if (byte != '\\')
                    {
                        value.push_back(static_cast<char>(byte));
                        continue;
                    }
                    if (position_ == text_.size())
                    {
                        return std::nullopt;
                    }
                    const auto escape = text_[position_++];
                    if (escape == '"' || escape == '\\' || escape == '/')
                    {
                        value.push_back(escape);
                        continue;
                    }
                    constexpr std::string_view escapes{"bfnrt"};
                    constexpr std::array<char, 5> controls{'\b', '\f', '\n', '\r', '\t'};
                    const auto control = escapes.find(escape);
                    if (control != std::string_view::npos)
                    {
                        value.push_back(controls[control]);
                        continue;
                    }
                    if (escape != 'u')
                    {
                        return std::nullopt;
                    }
                    auto point = hex_quad();
                    if (!point || (*point >= 0xdc00 && *point <= 0xdfff))
                    {
                        return std::nullopt;
                    }
                    if (*point >= 0xd800 && *point <= 0xdbff)
                    {
                        if (text_.size() - position_ < 2 || text_[position_++] != '\\'
                            || text_[position_++] != 'u')
                        {
                            return std::nullopt;
                        }
                        const auto low = hex_quad();
                        if (!low || *low < 0xdc00 || *low > 0xdfff)
                        {
                            return std::nullopt;
                        }
                        *point = 0x10000 + ((*point - 0xd800) << 10) + *low - 0xdc00;
                    }
                    std::array<wchar_t, 2> units{};
                    int count = 1;
                    if (*point > 0xffff)
                    {
                        const auto adjusted = *point - 0x10000;
                        units[0] = static_cast<wchar_t>(0xd800 + (adjusted >> 10));
                        units[1] = static_cast<wchar_t>(0xdc00 + (adjusted & 0x3ff));
                        count = 2;
                    }
                    else
                    {
                        units[0] = static_cast<wchar_t>(*point);
                    }
                    std::array<char, 4> encoded{};
                    const auto written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                        units.data(), count, encoded.data(), static_cast<int>(encoded.size()), nullptr, nullptr);
                    if (written <= 0)
                    {
                        return std::nullopt;
                    }
                    value.append(encoded.data(), static_cast<std::size_t>(written));
                }
                return std::nullopt;
            }

            std::optional<evidence_value> parse_value(std::size_t depth)
            {
                space();
                if (depth > 32 || ++nodes_ > 8192 || position_ == text_.size())
                {
                    return std::nullopt;
                }
                evidence_value value;
                if (text_[position_] == '"')
                {
                    auto parsed = string();
                    if (!parsed)
                    {
                        return std::nullopt;
                    }
                    value.kind = evidence_kind::string;
                    value.text = std::move(*parsed);
                    return value;
                }
                if (text_[position_] == '{' || text_[position_] == '[')
                {
                    const bool object = text_[position_++] == '{';
                    value.kind = object ? evidence_kind::object : evidence_kind::array;
                    const auto close = object ? '}' : ']';
                    if (take(close))
                    {
                        return value;
                    }
                    do
                    {
                        std::optional<std::string> key;
                        if (object)
                        {
                            key = string();
                            if (!key || value.member(*key) != nullptr || !take(':'))
                            {
                                return std::nullopt;
                            }
                        }
                        auto child = parse_value(depth + 1);
                        if (!child)
                        {
                            return std::nullopt;
                        }
                        if (object)
                        {
                            value.members.emplace_back(std::move(*key), std::move(*child));
                        }
                        else
                        {
                            value.elements.push_back(std::move(*child));
                        }
                        if (take(close))
                        {
                            return value;
                        }
                    } while (take(','));
                    return std::nullopt;
                }
                for (const auto literal : {std::string_view("true"), std::string_view("false"), std::string_view("null")})
                {
                    if (text_.substr(position_).starts_with(literal))
                    {
                        position_ += literal.size();
                        value.kind = literal == "null" ? evidence_kind::null_value : evidence_kind::boolean;
                        value.text = literal;
                        return value;
                    }
                }
                const auto start = position_;
                if (text_[position_] == '-')
                {
                    ++position_;
                }
                const auto digits = [&]()
                {
                    const auto beginning = position_;
                    while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9')
                    {
                        ++position_;
                    }
                    return beginning != position_;
                };
                if (position_ < text_.size() && text_[position_] == '0')
                {
                    ++position_;
                }
                else if (!digits())
                {
                    return std::nullopt;
                }
                if (position_ < text_.size() && text_[position_] == '.')
                {
                    ++position_;
                    if (!digits())
                    {
                        return std::nullopt;
                    }
                }
                if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E'))
                {
                    ++position_;
                    if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-'))
                    {
                        ++position_;
                    }
                    if (!digits())
                    {
                        return std::nullopt;
                    }
                }
                value.kind = evidence_kind::number;
                value.text = text_.substr(start, position_ - start);
                return value;
            }

            std::string_view text_;
            std::size_t position_{};
            std::size_t nodes_{};
        };

        const std::string* evidence_string(const evidence_value& value, std::string_view key) noexcept
        {
            const auto* child = value.member(key);
            return child != nullptr && child->kind == evidence_kind::string ? &child->text : nullptr;
        }

        std::optional<std::uint64_t> evidence_integer(const evidence_value* value) noexcept
        {
            if (value == nullptr || value->kind != evidence_kind::number || value->text.empty())
            {
                return std::nullopt;
            }
            std::uint64_t number{};
            const auto parsed = std::from_chars(value->text.data(), value->text.data() + value->text.size(), number);
            return parsed.ec == std::errc{} && parsed.ptr == value->text.data() + value->text.size()
                ? std::optional(number) : std::nullopt;
        }

        bool evidence_boolean(const evidence_value& value, std::string_view key) noexcept
        {
            const auto* child = value.member(key);
            return child != nullptr && child->kind == evidence_kind::boolean;
        }

        engine::result<std::wstring> evidence_wide(std::string_view value)
        {
            if (value.empty() || value.size() > 131072 || value.find('\0') != std::string_view::npos)
            {
                return std::unexpected(failure("status_invalid_record_path", ERROR_INVALID_DATA));
            }
            const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                static_cast<int>(value.size()), nullptr, 0);
            if (count <= 0)
            {
                return std::unexpected(failure("status_invalid_record_path", ERROR_INVALID_DATA));
            }
            std::wstring wide(static_cast<std::size_t>(count), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                static_cast<int>(value.size()), wide.data(), count) != count)
            {
                return std::unexpected(failure("status_invalid_record_path", ERROR_INVALID_DATA));
            }
            return wide;
        }

        engine::result<std::string> evidence_utf8(std::wstring_view value)
        {
            if (value.size() > 32768)
            {
                return std::unexpected(failure("status_path_limit", ERROR_FILENAME_EXCED_RANGE));
            }
            const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
            if (count <= 0)
            {
                return std::unexpected(failure("status_invalid_path", ERROR_INVALID_DATA));
            }
            std::string text(static_cast<std::size_t>(count), '\0');
            if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                static_cast<int>(value.size()), text.data(), count, nullptr, nullptr) != count)
            {
                return std::unexpected(failure("status_invalid_path", ERROR_INVALID_DATA));
            }
            return text;
        }

        bool evidence_inventory(const evidence_value& value, std::initializer_list<std::string_view> keys) noexcept
        {
            return value.kind == evidence_kind::object && value.members.size() == keys.size()
                && std::ranges::all_of(keys, [&](std::string_view key)
                {
                    return value.member(key) != nullptr;
                });
        }

        bool evidence_unsigned_fields(const evidence_value& value,
            std::initializer_list<std::string_view> keys) noexcept
        {
            return evidence_inventory(value, keys) && std::ranges::all_of(keys, [&](std::string_view key)
            {
                return evidence_integer(value.member(key)).has_value();
            });
        }

        bool evidence_nullable(const evidence_value* value, evidence_kind kind) noexcept
        {
            return value != nullptr && (value->kind == evidence_kind::null_value || value->kind == kind);
        }

        bool evidence_enum(const evidence_value& value, std::string_view key,
            std::initializer_list<std::string_view> allowed) noexcept
        {
            const auto* text = evidence_string(value, key);
            return text != nullptr && std::ranges::find(allowed, *text) != allowed.end();
        }

        bool valid_readiness_record(const evidence_value& value) noexcept
        {
            if (value.kind == evidence_kind::null_value)
            {
                return true;
            }
            if (!evidence_inventory(value, {"required_windows_build", "required_native_architecture",
                "required_process_architecture", "observed_windows_build", "native_architecture",
                "process_architecture", "platform_supported", "elevated", "filesystem_commands_ready",
                "observation_errors"}))
            {
                return false;
            }
            const auto required = evidence_integer(value.member("required_windows_build"));
            const auto* observed = value.member("observed_windows_build");
            if (!required || *required > (std::numeric_limits<std::uint32_t>::max)()
                || (observed->kind != evidence_kind::null_value && (!evidence_integer(observed)
                    || *evidence_integer(observed) > (std::numeric_limits<std::uint32_t>::max)())))
            {
                return false;
            }
            for (const auto name : {"required_native_architecture", "required_process_architecture",
                "native_architecture", "process_architecture"})
            {
                if (!evidence_enum(value, name, {"unknown", "x86", "x64", "arm64", "arm", "other"}))
                {
                    return false;
                }
            }
            for (const auto name : {"platform_supported", "elevated", "filesystem_commands_ready"})
            {
                if (!evidence_nullable(value.member(name), evidence_kind::boolean))
                {
                    return false;
                }
            }
            const auto* errors = value.member("observation_errors");
            if (!evidence_inventory(*errors, {"platform", "architecture", "elevation"}))
            {
                return false;
            }
            for (const auto& [name, error] : errors->members)
            {
                static_cast<void>(name);
                if (error.kind == evidence_kind::null_value)
                {
                    continue;
                }
                const auto native = evidence_integer(error.member("native_code"));
                if (!evidence_inventory(error, {"code", "native_code"})
                    || evidence_string(error, "code") == nullptr || !native
                    || *native > (std::numeric_limits<std::uint32_t>::max)())
                {
                    return false;
                }
            }
            return true;
        }

        bool valid_statistics_record(const evidence_value& value, const evidence_value& counts) noexcept
        {
            if (value.kind == evidence_kind::null_value)
            {
                return true;
            }
            if (!evidence_inventory(value, {"selected", "remove_attempted", "completed", "logical_bytes_semantics",
                "logical_bytes", "failed", "pending", "final_failures"})
                || !evidence_enum(value, "logical_bytes_semantics", {"frozen_default_stream_snapshot"}))
            {
                return false;
            }
            for (const auto name : {"selected", "remove_attempted", "completed"})
            {
                if (!evidence_unsigned_fields(*value.member(name), {"files", "directories", "unclassified"}))
                {
                    return false;
                }
            }
            if (!evidence_unsigned_fields(*value.member("logical_bytes"), {"selected", "remove_attempted",
                "completed", "selected_unknown", "remove_attempted_unknown", "completed_unknown"})
                || !evidence_unsigned_fields(*value.member("final_failures"), {"scope_protection", "reparse",
                    "identity", "access_lock", "resource", "report_audit", "other"})
                || !evidence_integer(value.member("failed")) || !evidence_integer(value.member("pending")))
            {
                return false;
            }
            if (value.member("failed")->text != counts.member("failed")->text
                || value.member("pending")->text != counts.member("pending")->text)
            {
                return false;
            }
            for (const auto& pair : {std::pair{"selected", "targets"}, std::pair{"completed", "completed"}})
            {
                const auto* split = value.member(pair.first);
                const auto combined = *evidence_integer(counts.member(pair.second));
                std::uint64_t sum{};
                for (const auto& [name, amount] : split->members)
                {
                    static_cast<void>(name);
                    const auto number = *evidence_integer(&amount);
                    if (number > combined - sum)
                    {
                        return false;
                    }
                    sum += number;
                }
                if (sum != combined)
                {
                    return false;
                }
            }
            return true;
        }

        bool valid_phases_record(const evidence_value& value) noexcept
        {
            if (!evidence_inventory(value, {"manifest_preparation_ms", "freeze_ms", "first_pass_ms", "recovery_ms",
                "reporting_before_result_ms", "total_to_result_ms"}))
            {
                return false;
            }
            return std::ranges::all_of(value.members, [](const auto& item)
            {
                const auto& phase = item.second;
                if (phase.kind == evidence_kind::null_value)
                {
                    return true;
                }
                if (phase.kind != evidence_kind::number)
                {
                    return false;
                }
                double number{};
                const auto parsed = std::from_chars(phase.text.data(), phase.text.data() + phase.text.size(), number);
                return parsed.ec == std::errc{} && parsed.ptr == phase.text.data() + phase.text.size()
                    && std::isfinite(number) && number >= 0;
            });
        }

        bool valid_space_record(const evidence_value& value) noexcept
        {
            if (value.kind == evidence_kind::null_value)
            {
                return true;
            }
            if (!evidence_inventory(value, {"semantics", "truncated", "volumes"})
                || !evidence_enum(value, "semantics", {"observed_available_to_caller_not_attributed_reclaim"})
                || !evidence_boolean(value, "truncated"))
            {
                return false;
            }
            const auto* volumes = value.member("volumes");
            if (volumes->kind != evidence_kind::array || volumes->elements.size() > 128)
            {
                return false;
            }
            for (const auto& volume : volumes->elements)
            {
                if (!evidence_inventory(volume, {"volume_key", "before_available_to_caller_bytes",
                    "after_available_to_caller_bytes", "delta_available_to_caller_bytes", "before_error_code",
                    "before_native_code", "after_error_code", "after_native_code"}))
                {
                    return false;
                }
                for (const auto name : {"volume_key", "before_error_code", "after_error_code"})
                {
                    if (evidence_string(volume, name) == nullptr)
                    {
                        return false;
                    }
                }
                for (const auto name : {"before_available_to_caller_bytes", "after_available_to_caller_bytes"})
                {
                    const auto* amount = volume.member(name);
                    if (amount->kind != evidence_kind::null_value && !evidence_integer(amount))
                    {
                        return false;
                    }
                }
                for (const auto name : {"before_native_code", "after_native_code"})
                {
                    const auto native = evidence_integer(volume.member(name));
                    if (!native || *native > (std::numeric_limits<std::uint32_t>::max)())
                    {
                        return false;
                    }
                }
                const auto* delta = volume.member("delta_available_to_caller_bytes");
                if (delta->kind != evidence_kind::null_value)
                {
                    if (delta->kind != evidence_kind::number)
                    {
                        return false;
                    }
                    std::int64_t number{};
                    const auto parsed = std::from_chars(delta->text.data(), delta->text.data() + delta->text.size(), number);
                    if (parsed.ec != std::errc{} || parsed.ptr != delta->text.data() + delta->text.size()
                        || number == (std::numeric_limits<std::int64_t>::min)())
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        bool valid_result_record(const evidence_value& value, std::string_view request_id,
            std::wstring_view inspected_path)
        {
            const auto* schema = evidence_string(value, "schema");
            const auto* request = evidence_string(value, "request_id");
            const auto* report = evidence_string(value, "report_file");
            if (value.kind != evidence_kind::object || schema == nullptr
                || (*schema != "windows_agent_cleanup.result.v1" && *schema != "windows_agent_cleanup.result.v2")
                || request == nullptr || *request != request_id || report == nullptr)
            {
                return false;
            }
            const auto path = evidence_wide(*report);
            if (!path || !equal_path(*path, inspected_path))
            {
                return false;
            }
            for (const auto name : {"job_id", "plan_fingerprint", "mode", "status", "error_code"})
            {
                if (evidence_string(value, name) == nullptr)
                {
                    return false;
                }
            }
            if (!evidence_enum(value, "status", {"completed", "scanned", "scan_partial", "failed", "paused",
                "cancelled_partial", "partial_failure", "audit_finalization_failed", "checkpoint_cleanup_failed"}))
            {
                return false;
            }
            if (!evidence_boolean(value, "resumable") || !evidence_boolean(value, "advisory"))
            {
                return false;
            }
            const auto native = evidence_integer(value.member("native_code"));
            const auto* counts = value.member("counts");
            if (!native || *native > (std::numeric_limits<std::uint32_t>::max)()
                || counts == nullptr || counts->kind != evidence_kind::object || counts->members.size() != 4)
            {
                return false;
            }
            const auto targets = evidence_integer(counts->member("targets"));
            const auto completed = evidence_integer(counts->member("completed"));
            const auto failed = evidence_integer(counts->member("failed"));
            const auto pending = evidence_integer(counts->member("pending"));
            if (!targets || !completed || !failed || !pending || *completed > *targets || *failed > *targets
                || *pending > *targets || *completed > *targets - *failed
                || *pending > *targets - *completed - *failed)
            {
                return false;
            }
            if (*evidence_string(value, "status") == "completed"
                && (*completed != *targets || *failed != 0 || *pending != 0))
            {
                return false;
            }
            if (*schema == "windows_agent_cleanup.result.v1")
            {
                return value.members.size() == 12;
            }
            if (!evidence_inventory(value, {"schema", "request_id", "job_id", "plan_fingerprint", "mode", "status",
                "counts", "error_code", "native_code", "report_file", "resumable", "advisory", "readiness",
                "statistics", "phases_ms", "space_observations", "next_action", "retry_safe"})
                || !evidence_boolean(value, "retry_safe"))
            {
                return false;
            }
            const auto* action = value.member("next_action");
            const auto* reason = evidence_string(*action, "reason");
            return evidence_inventory(*action, {"action", "reason"}) && reason != nullptr && reason->size() <= 128
                && evidence_enum(*action, "action", {"none", "use_supported_host", "request_os_consent",
                    "correct_input", "inspect_report", "wait_same_invocation", "reconcile_unknown"})
                && valid_readiness_record(*value.member("readiness"))
                && valid_statistics_record(*value.member("statistics"), *counts)
                && valid_phases_record(*value.member("phases_ms"))
                && valid_space_record(*value.member("space_observations"));
        }

        bool valid_intent_record(const evidence_value& value, std::string_view request_id) noexcept
        {
            const auto* schema = evidence_string(value, "schema");
            const auto* request = evidence_string(value, "request_id");
            if (value.kind != evidence_kind::object || schema == nullptr
                || *schema != "windows_agent_cleanup.intent.v1" || request == nullptr || *request != request_id
                || !evidence_integer(value.member("targets")) || !evidence_boolean(value, "irreversible_authorized"))
            {
                return false;
            }
            for (const auto name : {"job_id", "plan_fingerprint", "mode", "root", "command"})
            {
                if (evidence_string(value, name) == nullptr)
                {
                    return false;
                }
            }
            return value.members.size() == 9;
        }

        bool same_intent_binding(const evidence_value& intent, const evidence_value& result) noexcept
        {
            for (const auto name : {"job_id", "plan_fingerprint", "mode"})
            {
                const auto* first = evidence_string(intent, name);
                const auto* second = evidence_string(result, name);
                if (first == nullptr || second == nullptr || *first != *second)
                {
                    return false;
                }
            }
            const auto* counts = result.member("counts");
            const auto selected = evidence_integer(intent.member("targets"));
            const auto final_selected = counts == nullptr ? std::nullopt : evidence_integer(counts->member("targets"));
            return selected && final_selected && *selected == *final_selected;
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

        engine::result<void> capture_principal()
        {
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
            user_sid.resize(GetLengthSid(user->User.Sid));
            if (!CopySid(static_cast<DWORD>(user_sid.size()), user_sid.data(), user->User.Sid))
            {
                return std::unexpected(failure("state_sid_copy_failed"));
            }
            DWORD system_size = static_cast<DWORD>(system_sid.size());
            if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid.data(), &system_size))
            {
                return std::unexpected(failure("state_system_sid_failed"));
            }
            return {};
        }

        SECURITY_ATTRIBUTES security_attributes() const noexcept
        {
            return {sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
        }

        engine::result<void> verify_acl(HANDLE handle, bool require_protected = true) const
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
                || (require_protected && (control & SE_DACL_PROTECTED) == 0) || dacl->AceCount != 2)
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
        const auto principal = state->capture_principal();
        if (!principal)
        {
            return std::unexpected(principal.error());
        }
        LPWSTR raw_sid{};
        if (!ConvertSidToStringSidW(state->user_sid.data(), &raw_sid))
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

    request_status state_store::inspect_request(
        std::wstring_view existing_private_directory, std::string_view request_id)
    {
        request_status result;
        result.request_id = request_id;
        const auto stop = [&](request_lookup_state state, engine::error error)
        {
            result.lookup_state = state;
            result.observation_error = std::move(error);
            result.original_result.reset();
            return result;
        };
        if (request_id.empty() || request_id.size() > 128
            || !std::ranges::all_of(request_id, [](char value)
            {
                return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
                    || (value >= '0' && value <= '9') || value == '_' || value == '-';
            }))
        {
            return stop(request_lookup_state::unavailable,
                failure("status_invalid_request_id", ERROR_INVALID_PARAMETER));
        }
        const auto root = existing_private_directory;
        if (root.size() < 4 || root.size() > 32000 || root[1] != L':' || root[2] != L'\\'
            || !((root[0] >= L'A' && root[0] <= L'Z') || (root[0] >= L'a' && root[0] <= L'z'))
            || root.find(L'\0') != std::wstring_view::npos || root.back() == L'\\')
        {
            return stop(request_lookup_state::unavailable,
                failure("status_invalid_root", ERROR_INVALID_PARAMETER));
        }
        if (GetDriveTypeW(std::wstring(root.substr(0, 3)).c_str()) != DRIVE_FIXED)
        {
            return stop(request_lookup_state::unavailable,
                failure("state_root_not_fixed_local", ERROR_ACCESS_DENIED));
        }
        implementation state;
        const auto principal = state.capture_principal();
        if (!principal)
        {
            return stop(request_lookup_state::unavailable, principal.error());
        }
        auto pinned = state.pin_directory(root.substr(0, 3), false);
        if (!pinned)
        {
            return stop(request_lookup_state::unavailable, pinned.error());
        }
        std::size_t offset = 3;
        while (offset < root.size())
        {
            auto end = root.find(L'\\', offset);
            if (end == std::wstring_view::npos)
            {
                end = root.size();
            }
            const auto component = root.substr(offset, end - offset);
            if (component.empty() || component == L"." || component == L".."
                || component.back() == L'.' || component.back() == L' '
                || component.find_first_of(L":/<>\"|?*") != std::wstring_view::npos)
            {
                return stop(request_lookup_state::unavailable,
                    failure("status_invalid_root_component", ERROR_INVALID_PARAMETER));
            }
            pinned = state.pin_directory(append_component(*pinned, component), false);
            if (!pinned)
            {
                return stop(request_lookup_state::unavailable, pinned.error());
            }
            offset = end + 1;
        }
        state.root = *pinned;
        const auto directory = state.pinned_directories.back().get();
        const auto private_acl = state.verify_acl(directory);
        if (!private_acl)
        {
            return stop(request_lookup_state::unavailable, private_acl.error());
        }
        FILE_BASIC_INFO directory_before{};
        if (!GetFileInformationByHandleEx(directory, FileBasicInfo, &directory_before, sizeof(directory_before)))
        {
            return stop(request_lookup_state::unavailable, failure("status_directory_metadata_failed"));
        }
        const auto prefix = widen_ascii(request_id) + L".";
        constexpr std::wstring_view suffix{L".report.jsonl"};
        constexpr std::size_t maximum_entries{4096};
        constexpr std::size_t maximum_references{8};
        std::vector<std::wstring> leaves;
        WIN32_FIND_DATAW data{};
        const auto search_path = append_component(state.root, L"*");
        const auto search = FindFirstFileExW(search_path.c_str(), FindExInfoBasic, &data,
            FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (search == INVALID_HANDLE_VALUE)
        {
            const auto native = GetLastError();
            return stop(request_lookup_state::unavailable, failure("status_directory_enumeration_failed", native));
        }
        struct close_find
        {
            HANDLE handle;

            ~close_find()
            {
                FindClose(handle);
            }
        } enumeration{search};
        std::size_t inspected{};
        bool limit_reached{};
        DWORD enumeration_error{};
        do
        {
            if (++inspected > maximum_entries)
            {
                limit_reached = true;
                break;
            }
            const std::wstring_view leaf(data.cFileName);
            if (leaf.starts_with(prefix) && leaf.ends_with(suffix)
                && leaf.size() > prefix.size() + suffix.size())
            {
                if (leaves.size() == maximum_references)
                {
                    limit_reached = true;
                    break;
                }
                leaves.emplace_back(leaf);
                auto reference = evidence_utf8(append_component(state.root, leaf));
                if (!reference)
                {
                    return stop(request_lookup_state::unavailable, reference.error());
                }
                result.report_references.push_back(std::move(*reference));
            }
            if (!FindNextFileW(search, &data))
            {
                enumeration_error = GetLastError();
                break;
            }
        } while (true);
        if (limit_reached)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_filename_inspection_limit", ERROR_MORE_DATA));
        }
        if (enumeration_error != ERROR_NO_MORE_FILES)
        {
            return stop(request_lookup_state::unavailable,
                failure("status_directory_enumeration_failed", enumeration_error));
        }
        const auto stable_directory = [&]() -> engine::result<bool>
        {
            FILE_BASIC_INFO after{};
            if (!GetFileInformationByHandleEx(directory, FileBasicInfo, &after, sizeof(after)))
            {
                return std::unexpected(failure("status_directory_metadata_failed"));
            }
            return after.ChangeTime.QuadPart == directory_before.ChangeTime.QuadPart
                && after.LastWriteTime.QuadPart == directory_before.LastWriteTime.QuadPart;
        };
        const auto initial_stability = stable_directory();
        if (!initial_stability)
        {
            return stop(request_lookup_state::unavailable, initial_stability.error());
        }
        if (!*initial_stability)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_directory_changed_during_inspection", ERROR_RETRY));
        }
        if (leaves.empty())
        {
            result.lookup_state = request_lookup_state::no_record_observed;
            return result;
        }
        if (leaves.size() != 1)
        {
            result.lookup_state = request_lookup_state::ambiguous;
            return result;
        }
        const auto path = append_component(state.root, leaves.front());
        // Existing CLI writer grants FILE_SHARE_READ but retains GENERIC_WRITE.
        // Share write/delete from this observer (the private factory retains a
        // deletion-capable FILE_OBJECT for failure cleanup). The writer itself
        // denies delete sharing; post-read identity/path checks cover closed writers.
        // Never acquire/release the store lock.
        unique_handle input(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (input.get() == INVALID_HANDLE_VALUE)
        {
            return stop(request_lookup_state::unavailable, failure("status_report_open_failed"));
        }
        const auto verified = verify_object(input.get(), path, false);
        if (!verified)
        {
            return stop(request_lookup_state::unavailable, verified.error());
        }
        // Report files inherit the verified parent's private DACL; an explicit
        // protected DACL is also accepted. Existing checkpoint policy stays strict.
        const auto report_acl = state.verify_acl(input.get(), false);
        if (!report_acl)
        {
            return stop(request_lookup_state::unavailable, report_acl.error());
        }
        FILE_STANDARD_INFO before{};
        FILE_ID_INFO identity_before{};
        FILE_BASIC_INFO basic_before{};
        if (!GetFileInformationByHandleEx(input.get(), FileStandardInfo, &before, sizeof(before))
            || !GetFileInformationByHandleEx(input.get(), FileIdInfo, &identity_before, sizeof(identity_before))
            || !GetFileInformationByHandleEx(input.get(), FileBasicInfo, &basic_before, sizeof(basic_before)))
        {
            return stop(request_lookup_state::unavailable, failure("status_report_metadata_failed"));
        }
        if (before.EndOfFile.QuadPart <= 0)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_empty_report", ERROR_INVALID_DATA));
        }
        constexpr std::size_t maximum_record_bytes{512 * 1024};
        const auto size = static_cast<std::uint64_t>(before.EndOfFile.QuadPart);
        const auto read_window = [&](std::uint64_t position, std::size_t length) -> engine::result<std::string>
        {
            LARGE_INTEGER location{};
            location.QuadPart = static_cast<LONGLONG>(position);
            if (!SetFilePointerEx(input.get(), location, nullptr, FILE_BEGIN))
            {
                return std::unexpected(failure("status_report_seek_failed"));
            }
            std::string text(length, '\0');
            DWORD received{};
            if (!ReadFile(input.get(), text.data(), static_cast<DWORD>(length), &received, nullptr))
            {
                return std::unexpected(failure("status_report_read_failed"));
            }
            if (received != length)
            {
                return std::unexpected(failure("status_report_changed_during_read", ERROR_HANDLE_EOF));
            }
            return text;
        };
        const auto window = static_cast<std::size_t>((std::min)(size,
            static_cast<std::uint64_t>(maximum_record_bytes)));
        auto head = read_window(0, window);
        if (!head)
        {
            return stop(request_lookup_state::unavailable, head.error());
        }
        const auto first_end = head->find('\n');
        if (first_end == std::string::npos)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_first_record_incomplete_or_limit", ERROR_MORE_DATA));
        }
        auto tail = size <= window ? engine::result<std::string>(*head) : read_window(size - window, window);
        if (!tail)
        {
            return stop(request_lookup_state::unavailable, tail.error());
        }
        if (tail->empty() || tail->back() != '\n')
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_partial_final_record", ERROR_INVALID_DATA));
        }
        const auto final_end = tail->size() - 1;
        const auto previous = final_end == 0 ? std::string::npos : tail->rfind('\n', final_end - 1);
        if (previous == std::string::npos && size > window)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_final_record_limit", ERROR_MORE_DATA));
        }
        const auto final_start = previous == std::string::npos ? 0 : previous + 1;
        const auto first_text = std::string_view(*head).substr(0, first_end);
        const auto final_text = std::string_view(*tail).substr(final_start, final_end - final_start);
        const auto first = evidence_parser(first_text).parse();
        const auto final = evidence_parser(final_text).parse();
        if (!first || !final)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_invalid_evidence_record", ERROR_INVALID_DATA));
        }
        FILE_STANDARD_INFO after{};
        FILE_ID_INFO identity_after{};
        FILE_BASIC_INFO basic_after{};
        if (!GetFileInformationByHandleEx(input.get(), FileStandardInfo, &after, sizeof(after))
            || !GetFileInformationByHandleEx(input.get(), FileIdInfo, &identity_after, sizeof(identity_after))
            || !GetFileInformationByHandleEx(input.get(), FileBasicInfo, &basic_after, sizeof(basic_after)))
        {
            return stop(request_lookup_state::unavailable, failure("status_report_metadata_failed"));
        }
        const auto final_stability = stable_directory();
        if (!final_stability)
        {
            return stop(request_lookup_state::unavailable, final_stability.error());
        }
        if (after.EndOfFile.QuadPart != before.EndOfFile.QuadPart || after.DeletePending
            || identity_after.VolumeSerialNumber != identity_before.VolumeSerialNumber
            || std::memcmp(identity_after.FileId.Identifier, identity_before.FileId.Identifier,
                sizeof(identity_before.FileId.Identifier)) != 0
            || basic_after.ChangeTime.QuadPart != basic_before.ChangeTime.QuadPart
            || basic_after.LastWriteTime.QuadPart != basic_before.LastWriteTime.QuadPart
            || !*final_stability)
        {
            return stop(request_lookup_state::inspection_incomplete,
                failure("status_report_changed_during_inspection", ERROR_RETRY));
        }
        const auto still_verified = verify_object(input.get(), path, false);
        const auto still_private = state.verify_acl(input.get(), false);
        if (!still_verified || !still_private)
        {
            return stop(request_lookup_state::inspection_incomplete,
                !still_verified ? still_verified.error() : still_private.error());
        }
        const bool intent = valid_intent_record(*first, request_id);
        if (valid_result_record(*final, request_id, path)
            && ((intent && same_intent_binding(*first, *final))
                || (first_text == final_text && valid_result_record(*first, request_id, path))))
        {
            result.lookup_state = request_lookup_state::terminal_result;
            result.original_result = final_text;
            return result;
        }
        if (intent)
        {
            const auto* final_schema = evidence_string(*final, "schema");
            if (final_schema != nullptr && (*final_schema == "windows_agent_cleanup.result.v1"
                || *final_schema == "windows_agent_cleanup.result.v2"))
            {
                return stop(request_lookup_state::inspection_incomplete,
                    failure("status_final_result_binding_invalid", ERROR_INVALID_DATA));
            }
            result.lookup_state = request_lookup_state::intent_only;
            return result;
        }
        return stop(request_lookup_state::inspection_incomplete,
            failure("status_missing_valid_intent_or_result", ERROR_INVALID_DATA));
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

    engine::result<std::uintptr_t> state_store::create_report_handle(std::string_view leaf)
    {
        constexpr std::string_view suffix{".report.jsonl"};
        if (!leaf.ends_with(suffix) || leaf.size() <= suffix.size() + 33
            || leaf.size() > suffix.size() + 33 + 128)
        {
            return std::unexpected(failure("report_invalid_leaf", ERROR_INVALID_PARAMETER));
        }
        const auto separator = leaf.size() - suffix.size() - 33;
        const auto request = leaf.substr(0, separator);
        const auto random = leaf.substr(separator + 1, 32);
        if (leaf[separator] != '.' || !std::ranges::all_of(request, [](char value)
            {
                return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
                    || (value >= '0' && value <= '9') || value == '_' || value == '-';
            }) || !std::ranges::all_of(random, [](char value)
            {
                return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
            }))
        {
            return std::unexpected(failure("report_invalid_leaf", ERROR_INVALID_PARAMETER));
        }
        std::scoped_lock lock(state_->mutex);
        const auto path = append_component(state_->root, widen_ascii(leaf));
        auto security = state_->security_attributes();
        unique_handle created(CreateFileW(path.c_str(), GENERIC_WRITE | DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (created.get() == INVALID_HANDLE_VALUE)
        {
            return std::unexpected(failure("report_create_failed"));
        }
        const auto discard = [&](engine::error original) -> engine::result<std::uintptr_t>
        {
            FILE_DISPOSITION_INFO disposition{TRUE};
            if (!SetFileInformationByHandle(created.get(), FileDispositionInfo, &disposition, sizeof(disposition)))
            {
                const auto native = GetLastError();
                original.code += "_owned_cleanup_failed_native_" + std::to_string(native);
            }
            return std::unexpected(std::move(original));
        };
        const auto verified = verify_object(created.get(), path, false);
        if (!verified)
        {
            return discard(verified.error());
        }
        const auto private_acl = state_->verify_acl(created.get());
        if (!private_acl)
        {
            return discard(private_acl.error());
        }
        HANDLE writer{};
        if (!DuplicateHandle(GetCurrentProcess(), created.get(), GetCurrentProcess(), &writer,
            GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES, FALSE, 0))
        {
            return discard(failure("report_handle_transfer_failed"));
        }
        return reinterpret_cast<std::uintptr_t>(writer);
    }

    const std::wstring& state_store::root_path() const noexcept
    {
        return state_->root;
    }
}
