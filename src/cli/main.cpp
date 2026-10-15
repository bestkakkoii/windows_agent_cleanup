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

    bool elevated()
    {
        HANDLE raw{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        {
            fail("token_query_failed", GetLastError());
        }
        handle token(raw);
        TOKEN_ELEVATION elevation{};
        DWORD returned{};
        if (!GetTokenInformation(token.get(), TokenElevation, &elevation,
            static_cast<DWORD>(sizeof(elevation)), &returned))
        {
            fail("token_query_failed", GetLastError());
        }
        return elevation.TokenIsElevated != 0;
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

        std::string json() const
        {
            return "{\"schema\":\"windows_agent_cleanup.result.v1\",\"request_id\":" +
                agent::json_quote(request_id) + ",\"job_id\":" + agent::json_quote(job_id) +
                ",\"plan_fingerprint\":" + agent::json_quote(fingerprint) + ",\"mode\":" +
                agent::json_quote(mode) + ",\"status\":" + agent::json_quote(status) +
                ",\"counts\":{\"targets\":" + std::to_string(targets) + ",\"completed\":" +
                std::to_string(completed) + ",\"failed\":" + std::to_string(failed) +
                ",\"pending\":" + std::to_string(pending) + "},\"error_code\":" +
                agent::json_quote(error_code) + ",\"native_code\":" + std::to_string(native_code) +
                ",\"report_file\":" + agent::json_quote(report_file) + ",\"resumable\":" +
                (resumable ? "true" : "false") + ",\"advisory\":" + (advisory ? "true" : "false") + "}";
        }
    };

    class report_file
    {
    public:
        explicit report_file(std::wstring_view directory, const std::string& request_id)
            : path_(std::wstring(directory) + L"\\" + utf16(request_id + "." + random_id() + ".report.jsonl")),
              file_(CreateFileW(path_.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr))
        {
            if (!file_.valid())
            {
                fail("report_create_failed", GetLastError(), 4);
            }
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
        report_file& output, summary& result, quick::root_source& roots)
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
        auto frozen = require(staging->finalize());
        staging.reset();
        const auto& info = frozen.targets->info();
        result.job_id = info.job_id;
        result.fingerprint = info.fingerprint;
        result.targets = info.target_count;
        constexpr std::uint64_t fixed = 2 * 1024 * 1024;
        constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
        if (frozen.metrics.target_text_bytes > (maximum - fixed) / 6 ||
            info.target_count > (maximum - fixed - frozen.metrics.target_text_bytes * 6) / 4096)
        {
            fail("report_capacity_overflow", 0, 4);
        }
        output.reserve(fixed + frozen.metrics.target_text_bytes * 6 + info.target_count * 4096);
        intent(output, args, result);
        if (args.command == "scan")
        {
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
                if (!target.preparation_error.code.empty())
                {
                    ++result.failed;
                }
            }
            result.status = result.failed == 0 ? "scanned" : "scan_partial";
            result.advisory = true;
            return;
        }
        audit(store, result, "agent_quick_started");
        quick::options settings;
        settings.max_workers = args.workers;
        settings.memory_budget_bytes = args.memory_budget_bytes;
        auto report = require(quick::run_staged(*frozen.targets, *frozen.outcomes,
            info.fingerprint, args.irreversible, *host, controls, settings), 3);
        result.status = report.status;
        result.error_code = report.stopping_error.code;
        result.native_code = report.stopping_error.native_code;
        result.completed = report.completed;
        result.failed = report.failed;
        result.pending = report.unattempted;
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
        if (found == targets.end() || !found->preparation_error.code.empty() ||
            !agent::within_scope(require(agent::normalize_path(found->path)), args.path) ||
            !agent::within_scope(args.path, require(agent::normalize_path(found->path))))
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
}

int wmain(int argc, wchar_t** argv)
{
    summary result;
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
        auto args = require(cli::parse(tokens));
        if (args.command == "capabilities")
        {
            std::cout << capabilities() << '\n';
            std::cout.flush();
            return std::cout ? 0 : 4;
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
        if (!elevated())
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
        output = std::make_unique<report_file>(store->root_path(), args.request_id);
        result.report_file = output->path();
        if (args.command == "locks" || args.command == "release")
        {
            process_operation(args, *store, *output, result);
        }
        else
        {
            if (result.mode == "quick")
            {
                manifest_roots roots(args);
                run_quick(args, *store, *output, result, roots);
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
        std::cout << result.json() << '\n';
        std::cout.flush();
        return std::cout ? exit_code : 4;
    }
    catch (...)
    {
        return 4;
    }
}
