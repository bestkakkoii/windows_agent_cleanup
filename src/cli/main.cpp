#include <Windows.h>
#include <bcrypt.h>

import std;
import secure_erase.cli_arguments;
import secure_erase.agent_protocol;
import secure_erase.engine;
import secure_erase.quick_delete;
import secure_erase.quick_store;
import secure_erase.windows_backend;
import secure_erase.state_store;
import secure_erase.crypto;
import secure_erase.metadata;

namespace
{
    namespace engine = secure_erase::engine;
    namespace quick = secure_erase::quick;
    namespace agent = secure_erase::agent;
    namespace cli = secure_erase::cli;
    namespace storage = secure_erase::storage;

    struct task_failure
    {
        engine::error error;
        int exit_code{2};
    };

    [[noreturn]] void fail(std::string code, DWORD native_code = 0, int exit_code = 2)
    {
        throw task_failure{engine::error{std::move(code), native_code}, exit_code};
    }

    template<class value_type>
    value_type require(engine::result<value_type> value, int exit_code = 2)
    {
        if (!value)
        {
            const bool interrupted = value.error().native_code == ERROR_CANCELLED ||
                value.error().code.find("cancelled") != std::string::npos;
            throw task_failure{std::move(value.error()), interrupted ? 5 : exit_code};
        }
        return std::move(*value);
    }

    void require(engine::result<void> value, int exit_code = 2)
    {
        if (!value)
        {
            const bool interrupted = value.error().native_code == ERROR_CANCELLED ||
                value.error().code.find("cancelled") != std::string::npos;
            throw task_failure{std::move(value.error()), interrupted ? 5 : exit_code};
        }
    }

    class handle
    {
    public:
        explicit handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value)
        {
        }
        ~handle()
        {
            if (valid())
            {
                CloseHandle(value_);
            }
        }
        handle(const handle&) = delete;
        handle& operator=(const handle&) = delete;
        HANDLE get() const noexcept
        {
            return value_;
        }
        bool valid() const noexcept
        {
            return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
        }
    private:
        HANDLE value_;
    };

    std::string utf8(std::wstring_view value)
    {
        if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            fail("argument_too_long");
        }
        const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (count <= 0)
        {
            fail("argument_unicode_invalid", GetLastError());
        }
        std::string output(static_cast<std::size_t>(count), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), output.data(), count, nullptr, nullptr) != count)
        {
            fail("argument_unicode_invalid", GetLastError());
        }
        return output;
    }

    std::wstring utf16(std::string_view value)
    {
        if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            fail("argument_too_long");
        }
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0);
        if (count <= 0)
        {
            fail("argument_unicode_invalid", GetLastError());
        }
        std::wstring output(static_cast<std::size_t>(count), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), output.data(), count) != count)
        {
            fail("argument_unicode_invalid", GetLastError());
        }
        return output;
    }

    std::wstring native_path(std::string_view value)
    {
        return L"\\\\?\\" + utf16(value);
    }

    std::string random_id()
    {
        std::array<unsigned char, 16> bytes{};
        const auto status = BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0)
        {
            fail("random_identifier_failed", static_cast<DWORD>(status));
        }
        constexpr std::string_view digits = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (const auto byte : bytes)
        {
            result.push_back(digits[byte >> 4]);
            result.push_back(digits[byte & 15]);
        }
        return result;
    }

    bool elevated(const engine::host_readiness& host)
    {
        if (!host.elevated)
        {
            const auto error = host.elevation_error.value_or(
                engine::host_observation_error{"token_query_failed", 0});
            fail(std::string(error.code), error.native_code);
        }
        return *host.elevated;
    }

    using monotonic_clock = std::chrono::steady_clock;

    double elapsed_ms(monotonic_clock::time_point start)
    {
        return std::chrono::duration<double, std::milli>(monotonic_clock::now() - start).count();
    }

    std::string nullable_number(const std::optional<double>& value)
    {
        return value && std::isfinite(*value) && *value >= 0 ? std::to_string(*value) : "null";
    }

    std::string readiness_json(const engine::host_readiness& value)
    {
        const auto boolean = [](const std::optional<bool>& observed)
        {
            return observed ? (*observed ? "true" : "false") : "null";
        };
        const auto error = [](const std::optional<engine::host_observation_error>& observed)
        {
            return observed ? "{\"code\":" + agent::json_quote(observed->code) +
                ",\"native_code\":" + std::to_string(observed->native_code) + "}" : std::string{"null"};
        };
        return "{\"required_windows_build\":" + std::to_string(value.required_windows_build) +
            ",\"required_native_architecture\":" + agent::json_quote(engine::host_architecture_name(value.required_native_architecture)) +
            ",\"required_process_architecture\":" + agent::json_quote(engine::host_architecture_name(value.required_process_architecture)) +
            ",\"observed_windows_build\":" + (value.windows_build ? std::to_string(*value.windows_build) : "null") +
            ",\"native_architecture\":" + agent::json_quote(engine::host_architecture_name(value.native_architecture)) +
            ",\"process_architecture\":" + agent::json_quote(engine::host_architecture_name(value.process_architecture)) +
            ",\"platform_supported\":" + boolean(value.platform_supported) +
            ",\"elevated\":" + boolean(value.elevated) +
            ",\"filesystem_commands_ready\":" + boolean(value.filesystem_commands_ready) +
            ",\"observation_errors\":{\"platform\":" + error(value.platform_error) +
            ",\"architecture\":" + error(value.architecture_error) + ",\"elevation\":" + error(value.elevation_error) + "}}";
    }

    std::string space_json(const quick::space_observation& value)
    {
        std::optional<std::int64_t> delta;
        if (value.before && value.after)
        {
            const auto before = value.before->available_to_caller;
            const auto after = value.after->available_to_caller;
            const auto magnitude = before > after ? before - after : after - before;
            if (magnitude <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            {
                delta = static_cast<std::int64_t>(magnitude) * (after < before ? -1 : 1);
            }
        }
        return "{\"volume_key\":" + agent::json_quote(value.volume_key) +
            ",\"before_available_to_caller_bytes\":" +
            (value.before ? std::to_string(value.before->available_to_caller) : "null") +
            ",\"after_available_to_caller_bytes\":" +
            (value.after ? std::to_string(value.after->available_to_caller) : "null") +
            ",\"delta_available_to_caller_bytes\":" + (delta ? std::to_string(*delta) : "null") +
            ",\"before_error_code\":" + agent::json_quote(value.before_error.code) +
            ",\"before_native_code\":" + std::to_string(value.before_error.native_code) +
            ",\"after_error_code\":" + agent::json_quote(value.after_error.code) +
            ",\"after_native_code\":" + std::to_string(value.after_error.native_code) + "}";
    }

    // SECURITY: The console handler only requests cooperative cancellation. Its
    // referenced static state remains alive until process termination.
    engine::control controls;

    BOOL WINAPI console_handler(DWORD event)
    {
        if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT)
        {
            controls.request.store(engine::control_request::cancel, std::memory_order_relaxed);
            return TRUE;
        }
        return FALSE;
    }

    struct summary
    {
        std::string request_id;
        std::string job_id;
        std::string fingerprint;
        std::string mode;
        std::string status{"failed"};
        std::string error_code;
        std::uint32_t native_code{};
        std::string report_file;
        std::uint64_t targets{};
        std::uint64_t completed{};
        std::uint64_t failed{};
        std::uint64_t pending{};
        bool resumable{};
        bool advisory{};
        std::uint32_t contract_version{1};
        std::optional<engine::host_readiness> readiness;
        engine::operation_statistics statistics;
        std::optional<double> manifest_preparation_ms;
        std::optional<double> freeze_ms;
        std::optional<double> reporting_before_result_ms;
        std::optional<double> total_to_result_ms;
        std::optional<monotonic_clock::time_point> reporting_started;
        std::vector<quick::space_observation> space_observations;
        bool space_supported{};
        bool space_truncated{};
        agent::action_guidance guidance;

        std::string json() const
        {
            auto text = "{\"schema\":\"windows_agent_cleanup.result.v1\",\"request_id\":" +
                agent::json_quote(request_id) + ",\"job_id\":" + agent::json_quote(job_id) +
                ",\"plan_fingerprint\":" + agent::json_quote(fingerprint) + ",\"mode\":" +
                agent::json_quote(mode) + ",\"status\":" + agent::json_quote(status) +
                ",\"counts\":{\"targets\":" + std::to_string(targets) + ",\"completed\":" +
                std::to_string(completed) + ",\"failed\":" + std::to_string(failed) +
                ",\"pending\":" + std::to_string(pending) + "},\"error_code\":" +
                agent::json_quote(error_code) + ",\"native_code\":" + std::to_string(native_code) +
                ",\"report_file\":" + agent::json_quote(report_file) + ",\"resumable\":" +
                (resumable ? "true" : "false") + ",\"advisory\":" + (advisory ? "true" : "false") + "}";
            if (contract_version == 1)
            {
                return text;
            }
            text.replace(text.find("result.v1"), std::string_view("result.v1").size(), "result.v2");
            text.pop_back();
            text += ",\"readiness\":" + (readiness ? readiness_json(*readiness) : "null") +
                ",\"statistics\":" + agent::statistics_json(statistics) +
                ",\"phases_ms\":{\"manifest_preparation_ms\":" + nullable_number(manifest_preparation_ms) +
                ",\"freeze_ms\":" + nullable_number(freeze_ms) +
                ",\"first_pass_ms\":" + nullable_number(statistics.first_pass_ms) +
                ",\"recovery_ms\":" + nullable_number(statistics.recovery_ms) +
                ",\"reporting_before_result_ms\":" + nullable_number(reporting_before_result_ms) +
                ",\"total_to_result_ms\":" + nullable_number(total_to_result_ms) + "},\"space_observations\":";
            if (!space_supported)
            {
                text += "null";
            }
            else
            {
                text += "{\"semantics\":\"observed_available_to_caller_not_attributed_reclaim\",\"truncated\":" +
                    std::string(space_truncated ? "true" : "false") + ",\"volumes\":[";
                for (std::size_t index = 0; index < space_observations.size(); ++index)
                {
                    text += (index == 0 ? "" : ",") + space_json(space_observations[index]);
                }
                text += "]}";
            }
            return text + "," + agent::action_guidance_json(guidance) + "}";
        }
    };

    class report_file
    {
    public:
        explicit report_file(storage::state_store& store, const std::string& request_id)
            : report_file(store, request_id + "." + random_id() + ".report.jsonl", 0)
        {
        }

        std::string path() const
        {
            return utf8(path_);
        }

        void reserve(std::uint64_t size)
        {
            if (size > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
            {
                fail("report_capacity_overflow", 0, 4);
            }
            FILE_ALLOCATION_INFO allocation{};
            allocation.AllocationSize.QuadPart = static_cast<LONGLONG>(size);
            if (!SetFileInformationByHandle(file_.get(), FileAllocationInfo, &allocation,
                static_cast<DWORD>(sizeof(allocation))))
            {
                fail("report_capacity_unavailable", GetLastError(), 4);
            }
        }

        void append(std::string text)
        {
            text.push_back('\n');
            std::size_t offset{};
            while (offset < text.size())
            {
                const auto chunk = static_cast<DWORD>(std::min<std::size_t>(text.size() - offset, 1024 * 1024));
                DWORD written{};
                if (!WriteFile(file_.get(), text.data() + offset, chunk, &written, nullptr) || written == 0)
                {
                    fail("report_write_failed", GetLastError(), 4);
                }
                offset += written;
                written_bytes_ += written;
            }
        }

        void finalize()
        {
            FILE_ALLOCATION_INFO allocation{};
            allocation.AllocationSize.QuadPart = static_cast<LONGLONG>(written_bytes_);
            if (!SetFileInformationByHandle(file_.get(), FileAllocationInfo, &allocation,
                static_cast<DWORD>(sizeof(allocation))))
            {
                fail("report_capacity_release_failed", GetLastError(), 4);
            }
            flush();
        }

        void flush()
        {
            if (!FlushFileBuffers(file_.get()))
            {
                fail("report_flush_failed", GetLastError(), 4);
            }
        }

    private:
        // SECURITY: State-store ownership constructs the same explicit private
        // owner/DACL as its other evidence. Never inherit an elevated token's
        // default Administrators owner for a current-user report.
        report_file(storage::state_store& store, const std::string& basename, int)
            : path_(store.root_path() + L"\\" + utf16(basename)),
              file_(reinterpret_cast<HANDLE>(require(store.create_report_handle(basename), 4)))
        {
        }

        std::wstring path_;
        handle file_;
        std::uint64_t written_bytes_{};
    };

    std::uint64_t input_budget(const cli::arguments& args)
    {
        MEMORYSTATUSEX memory{};
        memory.dwLength = static_cast<DWORD>(sizeof(memory));
        if (!GlobalMemoryStatusEx(&memory))
        {
            fail("input_resource_probe_failed", GetLastError());
        }
        auto budget = std::min(memory.ullAvailPhys, memory.ullAvailPageFile) / 8;
        if (args.memory_budget_bytes != 0)
        {
            budget = std::min<std::uint64_t>(budget, args.memory_budget_bytes / 4);
        }
        return budget;
    }

    struct manifest_input
    {
        std::vector<std::string> paths;
        std::unordered_map<std::string, engine::capability> grants;
        std::uint64_t accounted{};
    };

    std::string canonical_directory(std::string_view path)
    {
        handle directory(CreateFileW(native_path(path).c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!directory.valid() || !GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo,
            &attributes, static_cast<DWORD>(sizeof(attributes))))
        {
            fail("scope_open_failed", GetLastError());
        }
        if ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            fail("scope_plain_directory_required");
        }
        std::wstring canonical(32768, L'\0');
        const auto length = GetFinalPathNameByHandleW(directory.get(), canonical.data(),
            static_cast<DWORD>(canonical.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (length == 0 || length >= canonical.size())
        {
            fail("scope_canonical_path_failed", GetLastError());
        }
        canonical.resize(length);
        // CONTRACT: Read-only placement evidence only. The original scope spelling
        // still goes to the backend, which nofollow-pins and revalidates it.
        return require(agent::normalize_path(utf8(canonical)));
    }

    std::unique_ptr<handle> open_manifest(const cli::arguments& args)
    {
        const auto path = require(agent::normalize_path(args.manifest));
        if (agent::within_scope(path, args.root))
        {
            fail("manifest_must_be_outside_scope");
        }
        auto input = std::make_unique<handle>(CreateFileW(native_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!input->valid() || !GetFileInformationByHandleEx(input->get(), FileAttributeTagInfo,
            &attributes, static_cast<DWORD>(sizeof(attributes))))
        {
            fail("manifest_open_failed", GetLastError());
        }
        if ((attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0)
        {
            fail("manifest_regular_file_required");
        }
        std::wstring canonical(32768, L'\0');
        const auto length = GetFinalPathNameByHandleW(input->get(), canonical.data(),
            static_cast<DWORD>(canonical.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (length == 0 || length >= canonical.size())
        {
            fail("manifest_canonical_path_failed", GetLastError());
        }
        canonical.resize(length);
        if (agent::within_scope(require(agent::normalize_path(utf8(canonical))), canonical_directory(args.root)))
        {
            fail("manifest_must_be_outside_scope");
        }
        return input;
    }

    manifest_input read_manifest(const cli::arguments& args, bool grants_only)
    {
        manifest_input result;
        if (args.manifest.empty())
        {
            return result;
        }
        auto input = open_manifest(args);
        const auto budget = input_budget(args);
        std::array<char, 64 * 1024> buffer{};
        std::string line;
        std::unordered_set<std::string> seen;
        const auto record = [&]()
        {
            auto entry = require(agent::parse_manifest_line(line));
            if (!agent::within_scope(entry.path, args.root))
            {
                fail("manifest_target_outside_scope");
            }
            if (args.mode == "quick" && entry.downgrade)
            {
                fail("quick_downgrade_grant_forbidden");
            }
            if (grants_only && !entry.downgrade)
            {
                fail("resume_manifest_grants_only");
            }
            // CONTRACT: Admission includes worst-case vector/hash storage overhead
            // and copies. It rejects the entire input before backend preparation.
            const auto bytes = static_cast<std::uint64_t>(entry.path.size()) * 8 + 2048;
            if (bytes > budget || result.accounted > budget - bytes)
            {
                fail("manifest_resource_budget_exceeded");
            }
            if (!seen.insert(entry.path).second)
            {
                fail("manifest_duplicate_path");
            }
            result.accounted += bytes;
            if (entry.downgrade)
            {
                result.grants.emplace(entry.path, *entry.downgrade);
            }
            if (!grants_only)
            {
                result.paths.push_back(std::move(entry.path));
            }
            line.clear();
        };
        for (;;)
        {
            if (controls.request.load() != engine::control_request::proceed)
            {
                fail("cancelled_before_admission", 0, 5);
            }
            DWORD count{};
            if (!ReadFile(input->get(), buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr))
            {
                fail("manifest_read_failed", GetLastError());
            }
            if (count == 0)
            {
                break;
            }
            for (DWORD index = 0; index < count; ++index)
            {
                if (buffer[index] == '\n')
                {
                    record();
                }
                else
                {
                    if (line.size() == agent::maximum_record_bytes)
                    {
                        fail("manifest_record_size_invalid");
                    }
                    line.push_back(buffer[index]);
                }
            }
        }
        if (!line.empty())
        {
            record();
        }
        if (seen.empty())
        {
            fail("manifest_empty");
        }
        return result;
    }

    class manifest_roots final : public quick::root_source
    {
    public:
        explicit manifest_roots(const cli::arguments& args) : args_(args), input_(open_manifest(args))
        {
        }

        engine::result<std::optional<std::string>> next() override
        {
            try
            {
                for (;;)
                {
                    if (controls.request.load() != engine::control_request::proceed)
                    {
                        return std::unexpected(engine::error{"manifest_cancelled", ERROR_CANCELLED});
                    }
                    if (offset_ == available_ && !ended_)
                    {
                        if (!ReadFile(input_->get(), buffer_.data(), static_cast<DWORD>(buffer_.size()),
                            &available_, nullptr))
                        {
                            return std::unexpected(engine::error{"manifest_read_failed", GetLastError()});
                        }
                        offset_ = 0;
                        ended_ = available_ == 0;
                    }
                    if (ended_ && line_.empty())
                    {
                        if (records_ == 0)
                        {
                            return std::unexpected(engine::error{"manifest_empty"});
                        }
                        return std::optional<std::string>{};
                    }
                    const bool complete = ended_ || buffer_[offset_] == '\n';
                    if (complete)
                    {
                        if (!ended_)
                        {
                            ++offset_;
                        }
                        auto entry = agent::parse_manifest_line(line_);
                        line_.clear();
                        if (!entry)
                        {
                            return std::unexpected(entry.error());
                        }
                        if (!agent::within_scope(entry->path, args_.root))
                        {
                            return std::unexpected(engine::error{"manifest_target_outside_scope"});
                        }
                        if (entry->downgrade)
                        {
                            return std::unexpected(engine::error{"quick_downgrade_grant_forbidden"});
                        }
                        ++records_;
                        return std::optional<std::string>{std::move(entry->path)};
                    }
                    if (line_.size() == agent::maximum_record_bytes)
                    {
                        return std::unexpected(engine::error{"manifest_record_size_invalid"});
                    }
                    line_.push_back(buffer_[offset_++]);
                }
            }
            catch (const std::bad_alloc&)
            {
                return std::unexpected(engine::error{"manifest_resource_allocation_failed"});
            }
        }

    private:
        const cli::arguments& args_;
        std::unique_ptr<handle> input_;
        std::array<char, 64 * 1024> buffer_{};
        std::string line_;
        DWORD offset_{};
        DWORD available_{};
        std::uint64_t records_{};
        bool ended_{};
    };

    template<class target_type>
    void reserve_report(report_file& output, const std::vector<target_type>& targets)
    {
        std::uint64_t bytes = 2 * 1024 * 1024;
        for (const auto& target : targets)
        {
            const auto add = static_cast<std::uint64_t>(target.path.size() + target.identity.size()) * 6 + 4096;
            if (add > std::numeric_limits<std::uint64_t>::max() - bytes)
            {
                fail("report_capacity_overflow", 0, 4);
            }
            bytes += add;
        }
        output.reserve(bytes);
    }

    void audit(storage::state_store& store, const summary& result, std::string code)
    {
        require(store.emit(engine::event{std::move(code), result.job_id, result.fingerprint,
            0, 0, result.native_code, result.targets, result.completed, result.failed}), 3);
    }

    void intent(report_file& output, const cli::arguments& args, const summary& result)
    {
        output.append("{\"schema\":\"windows_agent_cleanup.intent.v1\",\"request_id\":" +
            agent::json_quote(args.request_id) + ",\"command\":" + agent::json_quote(args.command) +
            ",\"mode\":" + agent::json_quote(result.mode) + ",\"root\":" + agent::json_quote(args.root) +
            ",\"job_id\":" + agent::json_quote(result.job_id) + ",\"plan_fingerprint\":" +
            agent::json_quote(result.fingerprint) + ",\"targets\":" + std::to_string(result.targets) +
            ",\"irreversible_authorized\":" + (args.irreversible ? "true" : "false") + "}");
        output.flush();
    }

    void record_outcome(report_file& output, summary& result, const engine::target_outcome& outcome,
        std::string_view path, bool count = true)
    {
        const bool successful = outcome.deleted &&
            (outcome.code == "deleted_quick_namespace_removed" ||
             outcome.code == "deleted_logical_overwrite_verified_residual_risk" ||
             outcome.code == "deleted_only_residual_risk" ||
             outcome.code == "completed_from_authenticated_checkpoint");
        if (count && successful)
        {
            ++result.completed;
        }
        else if (count && (outcome.code == "quick_not_attempted" || outcome.code == "not_attempted"))
        {
            ++result.pending;
        }
        else if (count)
        {
            ++result.failed;
        }
        if (!successful)
        {
            output.append("{\"schema\":\"windows_agent_cleanup.failure.v1\",\"identity\":" +
                agent::json_quote(outcome.identity) + ",\"path\":" + agent::json_quote(path) +
                ",\"error_code\":" + agent::json_quote(outcome.code) + ",\"native_code\":" +
                std::to_string(outcome.native_code) + ",\"deleted\":" + (outcome.deleted ? "true" : "false") + "}");
        }
    }

    engine::approval approval(const engine::frozen_plan& plan, const manifest_input& input, bool confirmed)
    {
        engine::approval result{plan.fingerprint, confirmed, {}};
        std::size_t used{};
        for (const auto& target : plan.targets)
        {
            const auto path = require(agent::normalize_path(target.path));
            const auto grant = input.grants.find(path);
            if (grant == input.grants.end())
            {
                continue;
            }
            if (!engine::needs_downgrade(target) || target.support != grant->second)
            {
                fail("downgrade_capability_mismatch");
            }
            result.downgrade_identities.push_back(target.identity);
            ++used;
        }
        if (used != input.grants.size())
        {
            fail("downgrade_namespace_not_in_frozen_plan");
        }
        return result;
    }

    struct secrets
    {
        engine::checkpoint& value;
        ~secrets()
        {
            for (auto& target : value.targets)
            {
                secure_erase::crypto::secure_zero(target.key);
                secure_erase::crypto::secure_zero(target.nonce);
            }
        }
    };

    void run_quick(const cli::arguments& args, storage::state_store& store,
        report_file& output, summary& result, quick::root_source& roots,
        monotonic_clock::time_point preparation_started)
    {
        auto host = require(engine::make_windows_quick_backend(store.root_path(), utf16(args.root)));
        auto files = require(store.staging_files());
        const auto resources = require(host->inspect_resources({}));
        auto memory = std::min(resources.available_memory_bytes, resources.available_commit_bytes) / 16;
        if (args.memory_budget_bytes != 0)
        {
            memory = std::min(memory, args.memory_budget_bytes / 8);
        }
        const auto disk = require(files->available_bytes());
        auto staging = require(quick::store::staging_store::create(files, random_id(),
            quick::store::options{memory, disk / 2}));
        require(host->prepare_stream(roots, *staging, controls));
        result.manifest_preparation_ms = elapsed_ms(preparation_started);
        const auto freeze_started = monotonic_clock::now();
        auto frozen = require(staging->finalize());
        result.freeze_ms = elapsed_ms(freeze_started);
        staging.reset();
        const auto& info = frozen.targets->info();
        result.job_id = info.job_id;
        result.fingerprint = info.fingerprint;
        result.targets = info.target_count;
        constexpr std::uint64_t fixed = 2 * 1024 * 1024;
        constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
        auto presentation_bytes = fixed;
        if (args.contract_version == 2)
        {
            std::uint64_t maximum_key_bytes{};
            for (const auto& key : info.device_keys)
            {
                maximum_key_bytes = std::max(maximum_key_bytes, static_cast<std::uint64_t>(key.size()));
            }
            // CONTRACT: Bounded v2 statistics/readiness fit fixed storage; admit
            // 128 worst-case escaped volume keys + observation/error fields too.
            if (maximum_key_bytes > ((maximum - fixed) / 128 - 2048) / 6)
            {
                fail("report_capacity_overflow", 0, 4);
            }
            presentation_bytes += 128 * (maximum_key_bytes * 6 + 2048);
        }
        if (frozen.metrics.target_text_bytes > (maximum - presentation_bytes) / 6 ||
            info.target_count > (maximum - presentation_bytes - frozen.metrics.target_text_bytes * 6) / 4096)
        {
            fail("report_capacity_overflow", 0, 4);
        }
        output.reserve(presentation_bytes + frozen.metrics.target_text_bytes * 6 + info.target_count * 4096);
        intent(output, args, result);
        if (args.command == "scan")
        {
            if (args.contract_version == 2)
            {
                result.statistics = require(quick::summarize_selection(*frozen.targets));
                result.failed = result.statistics.failed;
                result.pending = result.statistics.pending;
            }
            result.reporting_started = monotonic_clock::now();
            for (std::size_t index = 0; index < info.target_count; ++index)
            {
                if (controls.request.load() != engine::control_request::proceed)
                {
                    fail("scan_cancelled", 0, 5);
                }
                const auto target = require(frozen.targets->load(index));
                output.append("{\"schema\":\"windows_agent_cleanup.scan_target.v1\",\"path\":" +
                    agent::json_quote(target.path) + ",\"target_key\":" + agent::json_quote(quick::target_key(target)) +
                    ",\"directory\":" + (target.directory ? "true" : "false") + ",\"error_code\":" +
                    agent::json_quote(target.preparation_error.code) + ",\"native_code\":" +
                    std::to_string(target.preparation_error.native_code) + "}");
                if (args.contract_version == 1 && !target.preparation_error.code.empty())
                {
                    ++result.failed;
                }
            }
            result.status = result.failed == 0 ? "scanned" : "scan_partial";
            result.advisory = true;
            return;
        }
        if (args.contract_version == 2)
        {
            auto observations = quick::begin_space_observations(*host, info.device_keys);
            result.space_observations = std::move(observations.first);
            result.space_truncated = observations.second;
            result.space_supported = true;
        }
        audit(store, result, "agent_quick_started");
        quick::options settings;
        settings.max_workers = args.workers;
        settings.memory_budget_bytes = args.memory_budget_bytes;
        auto execution_result = quick::run_staged(*frozen.targets, *frozen.outcomes,
            info.fingerprint, args.irreversible, *host, controls, settings);
        result.reporting_started = monotonic_clock::now();
        auto report = require(std::move(execution_result), 3);
        result.statistics = report.statistics;
        result.status = report.status;
        result.error_code = report.stopping_error.code;
        result.native_code = report.stopping_error.native_code;
        result.completed = report.completed;
        result.failed = report.failed;
        result.pending = report.unattempted;
        for (auto& observation : result.space_observations)
        {
            quick::sample_space(*host, observation, false);
        }
        for (std::size_t index = 0; index < info.target_count; ++index)
        {
            const auto outcome = require(frozen.outcomes->read(index), 4);
            if (outcome.deleted && outcome.code == "deleted_quick_namespace_removed")
            {
                continue;
            }
            const auto target = require(frozen.targets->load(index), 4);
            if (outcome.identity != quick::target_key(target))
            {
                fail("quick_outcome_identity_invalid", 0, 3);
            }
            record_outcome(output, result, outcome, target.path, false);
        }
        audit(store, result, "agent_quick_" + result.status);
    }

    void run_overwrite(const cli::arguments& args, storage::state_store& store,
        report_file& output, summary& result, manifest_input input)
    {
        auto host = require(engine::make_windows_platform(store.root_path(), utf16(args.root)));
        engine::checkpoint saved;
        secrets cleanup{saved};
        engine::frozen_plan fresh;
        const engine::frozen_plan* plan{};
        if (args.command == "resume")
        {
            saved = require(store.load(args.job_id));
            if (saved.plan.fingerprint != args.fingerprint)
            {
                fail("exact_plan_confirmation_required");
            }
            plan = &saved.plan;
        }
        else
        {
            fresh = require(engine::freeze(random_id(), require(host->preview(input.paths))));
            plan = &fresh;
        }
        std::vector<std::string>().swap(input.paths);
        result.job_id = plan->job_id;
        result.fingerprint = plan->fingerprint;
        result.targets = plan->targets.size();
        // CONTRACT: The overwrite engine may order outcomes by dependencies.
        // Build a bounded index once; never copy a GUI display plan or snapshot.
        const auto canonical_scope = canonical_directory(args.root);
        std::unordered_map<std::string_view, std::string_view> paths;
        paths.reserve(plan->targets.size());
        for (const auto& target : plan->targets)
        {
            if (!agent::within_scope(require(agent::normalize_path(target.path)), canonical_scope))
            {
                fail("checkpoint_target_outside_scope");
            }
            if (!paths.emplace(target.identity, target.path).second)
            {
                fail("overwrite_duplicate_identity");
            }
        }
        auto consent = approval(*plan, input, args.irreversible);
        input = {};
        reserve_report(output, plan->targets);
        intent(output, args, result);
        if (args.command == "scan")
        {
            saved.plan = *plan;
            for (const auto& target : plan->targets)
            {
                if (controls.request.load() != engine::control_request::proceed)
                {
                    fail("scan_cancelled", 0, 5);
                }
                if (target.support == engine::capability::blocked)
                {
                    ++result.failed;
                }
                engine::target_checkpoint progress;
                progress.identity = target.identity;
                progress.observed = target;
                saved.targets.push_back(std::move(progress));
                const std::array<std::string_view, 4> capabilities{
                    "blocked", "overwrite_verified", "overwrite_best_effort", "delete_only"};
                output.append("{\"schema\":\"windows_agent_cleanup.scan_target.v1\",\"path\":" +
                    agent::json_quote(target.path) + ",\"identity\":" + agent::json_quote(target.identity) +
                    ",\"capability\":" + agent::json_quote(capabilities[static_cast<std::size_t>(target.support)]) +
                    ",\"downgrade_required\":" + (engine::needs_downgrade(target) ? "true" : "false") +
                    ",\"link_count\":" + std::to_string(target.link_count) + "}");
            }
            require(store.save(saved), 3);
            result.status = result.failed == 0 ? "scanned" : "scan_partial";
            result.resumable = true;
            return;
        }
        auto report = require(engine::run(*plan, consent, *host, store, store, controls,
            args.execution_settings, args.command == "resume" ? &saved : nullptr), 3);
        result.reporting_started = monotonic_clock::now();
        result.status = report.status;
        result.error_code = report.stopping_error.code;
        result.native_code = report.stopping_error.native_code;
        result.resumable = report.status != "completed";
        for (const auto& outcome : report.targets)
        {
            const auto found = paths.find(outcome.identity);
            if (found == paths.end())
            {
                fail("overwrite_outcome_identity_invalid", 0, 3);
            }
            record_outcome(output, result, outcome, found->second);
        }
    }

    bool selected_process_namespace(std::span<const quick::target> prepared, const quick::target& selected)
    {
        // CONTRACT: prepare receives exactly one input root. If it emits children,
        // it also emits that root directory, including enumeration failures. A
        // proper prepared canonical ancestor therefore proves a hidden child;
        // raw input spelling is not compared with canonical long/8.3 spelling.
        return selected.preparation_error.code.empty() && !std::ranges::any_of(prepared, [&](const auto& candidate)
        {
            return candidate.directory && candidate.path.size() < selected.path.size() &&
                selected.path.starts_with(candidate.path) &&
                (candidate.path.ends_with('\\') || selected.path[candidate.path.size()] == '\\');
        });
    }

    void process_operation(const cli::arguments& args, storage::state_store& store,
        report_file& output, summary& result)
    {
        auto host = require(engine::make_windows_quick_backend(store.root_path(), utf16(args.root)));
        struct execution_guard
        {
            quick::backend& value;
            ~execution_guard()
            {
                value.finish_execution();
            }
        } guard{*host};
        auto targets = require(host->prepare({args.path}, controls));
        const auto found = std::ranges::find_if(targets, [&](const auto& target)
        {
            return quick::target_key(target) == args.target_key;
        });
        if (found == targets.end() || !selected_process_namespace(targets, *found))
        {
            fail("exact_process_target_changed");
        }
        require(host->begin_execution());
        auto processes = require(host->query_locks(*found));
        result.job_id = random_id();
        result.fingerprint = args.target_key;
        result.targets = args.command == "release" ? 1 : processes.size();
        reserve_report(output, targets);
        intent(output, args, result);
        if (args.command == "locks")
        {
            for (const auto& process : processes)
            {
                output.append("{\"schema\":\"windows_agent_cleanup.lock.v1\",\"pid\":" +
                    std::to_string(process.process_id) + ",\"created\":" + agent::json_quote(std::to_string(process.creation_time)) +
                    ",\"image\":" + agent::json_quote(process.image_path) + ",\"eligible\":" +
                    (process.eligible ? "true" : "false") + ",\"reason\":" + agent::json_quote(process.denial_reason) + "}");
            }
            result.status = "scanned";
            return;
        }
        const auto selected = std::ranges::find_if(processes, [&](const auto& process)
        {
            return process.process_id == args.process_id && process.creation_time == args.creation_time &&
                process.image_path == args.image && process.eligible;
        });
        if (selected == processes.end())
        {
            fail("exact_process_tuple_changed");
        }
        output.append("{\"schema\":\"windows_agent_cleanup.process_intent.v1\",\"pid\":" +
            std::to_string(args.process_id) + ",\"created\":" + agent::json_quote(std::to_string(args.creation_time)) +
            ",\"image\":" + agent::json_quote(args.image) + ",\"target_key\":" + agent::json_quote(args.target_key) +
            ",\"force_authorized\":" + (args.force_terminate ? "true" : "false") + "}");
        output.flush();
        audit(store, result, "agent_process_release_started");
        if (controls.request.load() != engine::control_request::proceed)
        {
            fail("process_release_cancelled", 0, 5);
        }
        require(host->close_process(*found, *selected, args.force_terminate), 3);
        result.status = "completed";
        result.completed = 1;
        audit(store, result, "agent_process_release_completed");
    }

    std::string capabilities()
    {
        return "{\"schema\":\"windows_agent_cleanup.capabilities.v1\",\"status\":\"capabilities\",\"version\":" +
            agent::json_quote(secure_erase::metadata::version()) +
            ",\"commands\":[\"scan\",\"run\",\"resume\",\"locks\",\"release\"],"
            "\"modes\":[\"quick\",\"overwrite\"],\"protocol\":\"native_jsonl_manifest\","
            "\"elevation\":\"caller_supplied_no_prompt\",\"quick_scan\":\"advisory_only\","
            "\"overwrite_scan\":\"protected_resumable_plan\",\"quick_workers\":\"automatic\","
            "\"ctrl_c\":\"cooperative_cancel\",\"physical_sanitization_guaranteed\":false,"
            "\"required_common_options\":[\"--request-id\",\"--root\",\"--report-dir\"],"
            "\"batch_options\":[\"--mode\",\"--manifest\"],"
            "\"run_authorization\":\"--authorize-irreversible\","
            "\"resume_options\":[\"--job-id\",\"--plan-fingerprint\",\"--authorize-irreversible\"],"
            "\"lock_options\":[\"--path\",\"--target-key\"],"
            "\"release_options\":[\"--path\",\"--target-key\",\"--pid\",\"--created\",\"--image\",\"--authorize-close\"],"
            "\"separate_force_option\":\"--authorize-force\","
            "\"manifest_schema\":\"schemas/manifest_record.schema.json\","
            "\"result_schema\":\"schemas/result.schema.json\","
            "\"exit_codes\":{\"success\":0,\"admission\":2,\"partial_or_failure\":3,\"report_io\":4,\"interrupted\":5}}";
    }
    agent::action_guidance host_guidance(const engine::host_readiness& host)
    {
        if (!host.platform_supported || !*host.platform_supported)
        {
            return {agent::next_action_kind::use_supported_host,
                host.platform_supported ? "unsupported_platform" : "platform_observation_unknown", true};
        }
        if (!host.elevated)
        {
            return {agent::next_action_kind::reconcile_unknown, "token_observation_unknown", true};
        }
        if (!*host.elevated)
        {
            return {agent::next_action_kind::request_os_consent, "already_elevated_execution_host_required", true};
        }
        return {agent::next_action_kind::none, "host_ready_path_admission_still_required", true};
    }

    std::string capabilities_v2()
    {
        const auto host = engine::inspect_host_readiness();
        return "{\"schema\":\"windows_agent_cleanup.capabilities.v2\",\"status\":\"capabilities\",\"version\":" +
            agent::json_quote(secure_erase::metadata::version()) +
            ",\"identity\":{\"version\":" + agent::json_quote(secure_erase::metadata::version()) +
            ",\"source_commit\":" + agent::json_quote(secure_erase::metadata::source_commit()) +
            ",\"source_commit_known\":" + (secure_erase::metadata::source_commit_known() ? "true" : "false") +
            ",\"source_dirty\":" + (secure_erase::metadata::source_dirty() ? "true" : "false") +
            ",\"source_dirty_known\":" + (secure_erase::metadata::source_dirty_known() ? "true" : "false") +
            ",\"build_identity\":" + agent::json_quote(secure_erase::metadata::build_identity()) + "}," +
            "\"supported_contract_versions\":[1,2],\"commands\":[\"scan\",\"run\",\"resume\",\"locks\",\"release\",\"status\"]," +
            "\"modes\":[\"quick\",\"overwrite\"],\"protocol\":\"native_jsonl_manifest\"," +
            "\"elevation\":\"caller_supplied_no_prompt\",\"physical_sanitization_guaranteed\":false," +
            "\"manifest_schema\":\"schemas/manifest_record.schema.json\"," +
            "\"result_schema\":\"schemas/result.v2.schema.json\"," +
            "\"capabilities_schema\":\"schemas/capabilities.v2.schema.json\"," +
            "\"request_status_schema\":\"schemas/request_status.v2.schema.json\"," +
            "\"readiness\":" + readiness_json(host) + "," + agent::action_guidance_json(host_guidance(host)) +
            ",\"exit_codes\":{\"success\":0,\"admission\":2,\"partial_or_failure\":3,\"report_io\":4,\"interrupted\":5}}";
    }

    std::string_view lookup_state_name(storage::request_lookup_state value) noexcept
    {
        switch (value)
        {
        case storage::request_lookup_state::terminal_result:
            return "terminal_result";
        case storage::request_lookup_state::intent_only:
            return "intent_only";
        case storage::request_lookup_state::no_record_observed:
            return "no_record_observed";
        case storage::request_lookup_state::ambiguous:
            return "ambiguous";
        case storage::request_lookup_state::unavailable:
            return "unavailable";
        case storage::request_lookup_state::inspection_incomplete:
            return "inspection_incomplete";
        }
        return "unavailable";
    }

    int inspect_request(const cli::arguments& args)
    {
        storage::request_status status;
        const auto path = agent::normalize_path(args.report_directory);
        if (path)
        {
            status = storage::state_store::inspect_request(utf16(*path), args.request_id);
        }
        else
        {
            status.request_id = args.request_id;
            status.observation_error = path.error();
        }
        std::string text = "{\"schema\":\"windows_agent_cleanup.request_status.v2\",\"request_id\":" +
            agent::json_quote(status.request_id) + ",\"lookup_state\":" +
            agent::json_quote(lookup_state_name(status.lookup_state)) + ",\"report_references\":[";
        for (std::size_t index = 0; index < status.report_references.size(); ++index)
        {
            text += (index == 0 ? "" : ",") + agent::json_quote(status.report_references[index]);
        }
        const bool terminal = status.lookup_state == storage::request_lookup_state::terminal_result;
        text += "],\"original_result\":" + status.original_result.value_or("null") +
            ",\"error_code\":" + agent::json_quote(status.observation_error.code) +
            ",\"native_code\":" + std::to_string(status.observation_error.native_code) + "," +
            agent::action_guidance_json({terminal ? agent::next_action_kind::inspect_report :
                agent::next_action_kind::reconcile_unknown,
                terminal ? "recorded_terminal_result_not_replay_authority" : "completion_not_established_no_replay", false}) + "}";
        std::cout << text << '\n';
        std::cout.flush();
        return std::cout ? (terminal ? 0 : 3) : 4;
    }

    void update_guidance(summary& result, int exit_code, bool operation_dispatched)
    {
        result.guidance.retry_safe = exit_code == 2 && !operation_dispatched;
        if (exit_code == 0)
        {
            result.guidance.action = agent::next_action_kind::none;
            result.guidance.reason = "recorded_result_not_replay_authority";
        }
        else if (result.error_code == "elevation_required")
        {
            result.guidance.action = agent::next_action_kind::request_os_consent;
            result.guidance.reason = "already_elevated_execution_host_required";
        }
        else if (result.error_code == "unsupported_host" || result.error_code == "host_readiness_unknown")
        {
            result.guidance.action = agent::next_action_kind::use_supported_host;
            result.guidance.reason = result.error_code;
        }
        else if (result.error_code == "token_query_failed")
        {
            result.guidance.action = agent::next_action_kind::reconcile_unknown;
            result.guidance.reason = "token_observation_unknown";
        }
        else
        {
            result.guidance.action = result.guidance.retry_safe ? agent::next_action_kind::correct_input :
                (result.report_file.empty() ? agent::next_action_kind::reconcile_unknown : agent::next_action_kind::inspect_report);
            result.guidance.reason = result.error_code.empty() ? "inspect_final_target_outcomes" : result.error_code;
        }
    }

}

int wmain(int argc, wchar_t** argv)
{
    const auto invocation_started = monotonic_clock::now();
    summary result;
    bool operation_dispatched{};
    std::unique_ptr<storage::state_store> store;
    std::unique_ptr<report_file> output;
    int exit_code{};
    try
    {
        std::vector<std::string> tokens;
        for (int index = 1; index < argc; ++index)
        {
            tokens.push_back(utf8(argv[index]));
        }
        result.contract_version = cli::requested_contract_version(tokens);
        auto args = require(cli::parse(tokens));
        result.contract_version = args.contract_version;
        if (args.command == "capabilities")
        {
            std::cout << (args.contract_version == 2 ? capabilities_v2() : capabilities()) << '\n';
            std::cout.flush();
            return std::cout ? 0 : 4;
        }
        if (args.command == "status")
        {
            return inspect_request(args);
        }
        result.request_id = args.request_id;
        result.mode = args.command == "resume" ? "overwrite" :
            (args.command == "locks" || args.command == "release" ? "process" : args.mode);
        args.root = require(agent::normalize_path(args.root));
        args.report_directory = require(agent::normalize_path(args.report_directory));
        if (agent::within_scope(args.report_directory, args.root) ||
            agent::within_scope(args.root, args.report_directory))
        {
            fail("report_scope_overlap");
        }
        result.readiness = engine::inspect_host_readiness();
        if (args.contract_version == 2 && !result.readiness->platform_supported.value_or(false))
        {
            fail(result.readiness->platform_supported ? "unsupported_host" : "host_readiness_unknown");
        }
        if (!elevated(*result.readiness))
        {
            fail("elevation_required");
        }
        if (!SetConsoleCtrlHandler(console_handler, TRUE))
        {
            fail("console_control_registration_failed", GetLastError());
        }
        if (!args.path.empty())
        {
            args.path = require(agent::normalize_path(args.path));
            if (!agent::within_scope(args.path, args.root))
            {
                fail("process_target_outside_scope");
            }
        }
        store = require(storage::state_store::open_at(utf16(args.report_directory), args.retention));
        output = std::make_unique<report_file>(*store, args.request_id);
        result.report_file = output->path();
        operation_dispatched = true;
        if (args.command == "locks" || args.command == "release")
        {
            process_operation(args, *store, *output, result);
        }
        else
        {
            if (result.mode == "quick")
            {
                const auto preparation_started = monotonic_clock::now();
                manifest_roots roots(args);
                run_quick(args, *store, *output, result, roots, preparation_started);
            }
            else
            {
                auto input = read_manifest(args, args.command == "resume");
                run_overwrite(args, *store, *output, result, std::move(input));
            }
        }
        exit_code = cli::report_exit_code(result.status);
    }
    catch (const task_failure& failure)
    {
        result.status = failure.exit_code == 5 ? "cancelled_partial" : "failed";
        result.error_code = failure.error.code;
        result.native_code = failure.error.native_code;
        exit_code = failure.exit_code;
    }
    catch (const std::bad_alloc&)
    {
        result.status = "failed";
        result.error_code = "resource_allocation_failed_completion_may_be_partial";
        exit_code = 3;
    }
    catch (...)
    {
        result.status = "failed";
        result.error_code = "unexpected_exception_completion_may_be_partial";
        exit_code = 3;
    }
    try
    {
        if (store && result.mode == "overwrite" && !result.job_id.empty())
        {
            const auto checkpoints = store->list_checkpoints();
            if (checkpoints)
            {
                result.resumable = std::ranges::any_of(*checkpoints, [&](const auto& checkpoint)
                {
                    return checkpoint.job_id == result.job_id;
                });
            }
        }
        if (result.reporting_started)
        {
            result.reporting_before_result_ms = elapsed_ms(*result.reporting_started);
        }
        result.total_to_result_ms = elapsed_ms(invocation_started);
        update_guidance(result, exit_code, operation_dispatched);
        if (output)
        {
            output->append(result.json());
            output->finalize();
        }
    }
    catch (const task_failure& failure)
    {
        result.status = "failed";
        result.error_code = failure.error.code;
        result.native_code = failure.error.native_code;
        exit_code = 4;
    }
    catch (...)
    {
        result.status = "failed";
        result.error_code = "report_finalization_failed";
        exit_code = 4;
    }
    try
    {
        update_guidance(result, exit_code, operation_dispatched);
        std::cout << result.json() << '\n';
        std::cout.flush();
        return std::cout ? exit_code : 4;
    }
    catch (...)
    {
        return 4;
    }
}
