module;

#include <Windows.h>
#include <bcrypt.h>

module secure_erase.application;

import std;
import secure_erase.engine;
import secure_erase.crypto;
import secure_erase.state_store;
import secure_erase.windows_backend;
import secure_erase.quick_delete;
import secure_erase.quick_store;

namespace secure_erase::frontend
{
    namespace
    {
        std::uint64_t target_bytes(const engine::target_snapshot& target)
        {
            std::uint64_t total{};
            for (const auto& stream : target.streams)
            {
                if (stream.size > (std::numeric_limits<std::uint64_t>::max)() - total)
                {
                    return (std::numeric_limits<std::uint64_t>::max)();
                }
                total += stream.size;
            }
            return total;
        }

        engine::result<std::string> random_job_id()
        {
            std::array<unsigned char, 16> id{};
            const auto status = BCryptGenRandom(nullptr, id.data(), static_cast<ULONG>(id.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (status < 0)
            {
                return std::unexpected(engine::error{"job_id_entropy_failed", static_cast<std::uint32_t>(status)});
            }
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result;
            result.reserve(id.size() * 2);
            for (const auto value : id)
            {
                result.push_back(digits[value >> 4]);
                result.push_back(digits[value & 15]);
            }
            return result;
        }

        bool quick_success(const engine::target_outcome& value)
        {
            return value.deleted && value.code == "deleted_quick_namespace_removed";
        }

        void erase_secrets(std::optional<engine::checkpoint>& value)
        {
            if (value)
            {
                for (auto& target : value->targets)
                {
                    crypto::secure_zero(target.key);
                    crypto::secure_zero(target.nonce);
                }
                value.reset();
            }
        }
    }

    namespace
    {
        std::string input_namespace(std::string_view path)
        {
            if (path.starts_with("\\\\?\\"))
            {
                path.remove_prefix(4);
            }
            std::string result(path);
            std::replace(result.begin(), result.end(), '/', '\\');
            while (result.size() > 3 && result.back() == '\\')
            {
                result.pop_back();
            }
            return result;
        }

        class vector_roots final : public quick::root_source
        {
        public:
            explicit vector_roots(const std::vector<std::string>& paths) : paths_(paths)
            {
            }
            engine::result<std::optional<std::string>> next() override
            {
                if (next_ == paths_.size())
                {
                    return std::optional<std::string>{};
                }
                return std::optional<std::string>{paths_[next_++]};
            }
        private:
            const std::vector<std::string>& paths_;
            std::size_t next_{};
        };

        struct input_completion_candidate
        {
            std::string original_path;
            std::string canonical_path;
            bool directory{};
            bool succeeded{};
            bool incomplete_descendant{};
        };

        void mark_incomplete_ancestors(std::string_view canonical,
            const std::unordered_map<std::string_view, input_completion_candidate*>& directories)
        {
            std::string_view ancestor = canonical;
            for (;;)
            {
                const auto selected = directories.find(ancestor);
                if (selected != directories.end())
                {
                    selected->second->incomplete_descendant = true;
                }
                const auto separator = ancestor.find_last_of('\\');
                if (separator == std::string_view::npos || separator < 3)
                {
                    break;
                }
                ancestor = ancestor.substr(0, separator);
            }
        }

        void collect_completed_inputs(std::unordered_map<std::string, input_completion_candidate>& candidates,
            completed_inputs& proof)
        {
            for (auto& [key, candidate] : candidates)
            {
                static_cast<void>(key);
                if (candidate.succeeded && !candidate.incomplete_descendant)
                {
                    proof.paths.push_back(std::move(candidate.original_path));
                }
            }
        }

        class input_tracking_sink final : public quick::target_sink
        {
        public:
            input_tracking_sink(quick::target_sink& output, const std::vector<std::string>& paths)
                : output_(output)
            {
                for (const auto& path : paths)
                {
                    originals_.emplace(input_namespace(path), path);
                }
            }
            engine::result<void> append(quick::target value) override
            {
                const auto original = originals_.find(input_namespace(value.path));
                if (original != originals_.end())
                {
                    const auto key = quick::target_key(value);
                    std::lock_guard lock(mutex_);
                    proofs_.emplace(key, input_completion_candidate{original->second,
                        input_namespace(value.path), value.directory, false, false});
                }
                return output_.append(std::move(value));
            }
            std::unordered_map<std::string, input_completion_candidate> take_proofs()
            {
                return std::move(proofs_);
            }
        private:
            quick::target_sink& output_;
            std::unordered_map<std::string, std::string> originals_;
            std::unordered_map<std::string, input_completion_candidate> proofs_;
            std::mutex mutex_;
        };
    }

    struct application::implementation final : engine::event_sink
    {
        mutable std::mutex mutex;
        std::mutex event_mutex;
        view_state view;
        observer on_event;
        storage::store_options settings;
        engine::options execution_settings;
        quick::options quick_settings;
        std::unique_ptr<storage::state_store> store;
        std::unique_ptr<engine::platform> host;
        std::unique_ptr<quick::backend> quick_host;
        std::shared_ptr<quick::target_source> quick_targets;
        std::shared_ptr<quick::outcome_sink> quick_outcomes;
        std::unordered_map<std::string, input_completion_candidate> quick_input_proofs;
        std::jthread page_worker;
        std::uint64_t page_generation{};
        std::shared_ptr<const engine::run_report> quick_report;
        std::string quick_lock_fingerprint;
        std::string quick_lock_identity;
        std::chrono::steady_clock::time_point quick_last_progress;
        std::optional<engine::checkpoint> resume;
        engine::control controls;
        std::jthread worker;
        std::chrono::steady_clock::time_point started;
        std::map<std::pair<std::string, std::string>, std::uint64_t> phase_bytes;

        ~implementation() override
        {
            controls.request.store(engine::control_request::cancel);
            if (worker.joinable())
            {
                worker.join();
            }
            page_worker.request_stop();
            if (page_worker.joinable())
            {
                page_worker.join();
            }
            erase_secrets(resume);
        }

        bool initialize(bool needs_overwrite_host)
        {
            if (!store)
            {
                auto opened = storage::state_store::open(settings);
                if (!opened)
                {
                    fail(opened.error());
                    return false;
                }
                store = std::move(*opened);
            }
            if (needs_overwrite_host && !host)
            {
                auto created = engine::make_windows_platform(store->root_path());
                if (!created)
                {
                    fail(created.error());
                    return false;
                }
                host = std::move(*created);
            }
            return true;
        }

        void fail(const engine::error& error)
        {
            std::lock_guard lock(mutex);
            view.error_code = error.code;
            view.native_code = error.native_code;
            view.status = "failed";
        }

        bool launch(std::string status, std::function<void()> operation,
            bool needs_overwrite_host = true)
        {
            {
                std::lock_guard lock(mutex);
                if (view.busy)
                {
                    return false;
                }
            }
            if (worker.joinable())
            {
                worker.join();
            }
            {
                std::lock_guard lock(mutex);
                view.busy = true;
                ++page_generation;
                page_worker.request_stop();
                view.quick_page_loading = false;
                view.status = std::move(status);
                view.error_code.clear();
                view.native_code = 0;
            }
            worker = std::jthread([this, operation = std::move(operation), needs_overwrite_host]()
            {
                if (page_worker.joinable())
                {
                    page_worker.join();
                }
                try
                {
                    if (initialize(needs_overwrite_host))
                    {
                        operation();
                    }
                }
                catch (const std::bad_alloc&)
                {
                    fail(engine::error{"application_resource_allocation_failed"});
                }
                catch (...)
                {
                    fail(engine::error{"application_worker_exception"});
                }
                std::lock_guard lock(mutex);
                view.busy = false;
                view.executing = false;
            });
            return true;
        }

        void clear_quick_locked()
        {
            // PRECONDITION: mutex held; the worker is the only backend owner.
            quick_targets.reset();
            quick_outcomes.reset();
            quick_input_proofs.clear();
            ++page_generation;
            page_worker.request_stop();
            view.quick_paged = false;
            view.quick_page_loading = false;
            view.quick_page_data.reset();
            view.quick_completed_inputs.reset();
            quick_report.reset();
            quick_lock_fingerprint.clear();
            quick_lock_identity.clear();
            view.quick_mode = false;
            view.quick_space.clear();
            view.quick_space_truncated = false;
            view.quick_stage.clear();
            view.quick_total = 0;
            view.quick_attempted = 0;
            view.quick_pending = 0;
            view.locks.clear();
            view.lock_path.clear();
        }

        bool initialize_quick()
        {
            if (!quick_host)
            {
                auto created = engine::make_windows_quick_backend(store->root_path());
                if (!created)
                {
                    fail(created.error());
                    return false;
                }
                quick_host = std::move(*created);
            }
            return true;
        }

        std::optional<quick::target> failed_quick_target_locked(std::string_view path,
            std::string_view fingerprint) const
        {
            if (!view.quick_mode || !quick_targets || !quick_report || !view.quick_page_data ||
                view.quick_pending != 0 || view.quick_attempted != view.quick_total || view.quick_total == 0 ||
                quick_targets->info().fingerprint != fingerprint || quick_report->plan_fingerprint != fingerprint ||
                quick_targets->info().job_id != quick_report->job_id ||
                view.quick_page_data->job_id != quick_report->job_id ||
                view.quick_page_data->fingerprint != fingerprint)
            {
                return {};
            }
            for (const auto& item : view.quick_page_data->items)
            {
                if (item.target.path == path && item.target.preparation_error.code.empty() &&
                    item.outcome && item.outcome->identity == quick::target_key(item.target) &&
                    !quick_success(*item.outcome) && item.outcome->code != "quick_not_attempted" &&
                    item.outcome->code != "quick_device_stopped")
                {
                    return item.target;
                }
            }
            return {};
        }

        engine::result<std::shared_ptr<const quick_page>> load_page(
            const std::shared_ptr<quick::target_source>& targets,
            const std::shared_ptr<quick::outcome_sink>& outcomes, std::uint64_t offset,
            bool incomplete, bool has_outcomes, std::uint64_t incomplete_count, std::stop_token stop = {})
        {
            const auto& info = targets->info();
            auto page = std::make_shared<quick_page>();
            page->job_id = info.job_id;
            page->fingerprint = info.fingerprint;
            page->offset = std::min<std::uint64_t>(offset, info.target_count);
            page->next_offset = page->offset;
            page->total = incomplete ? incomplete_count : info.target_count;
            page->failures_only = incomplete;
            page->items.reserve(128);
            while (page->next_offset < info.target_count && page->items.size() < 128)
            {
                if (stop.stop_requested())
                {
                    return std::unexpected(engine::error{"quick_page_cancelled"});
                }
                const auto index = static_cast<std::size_t>(page->next_offset++);
                std::optional<engine::target_outcome> outcome;
                if (has_outcomes)
                {
                    auto loaded = outcomes->read(index);
                    if (!loaded)
                    {
                        return std::unexpected(loaded.error());
                    }
                    outcome = std::move(*loaded);
                    if (incomplete && quick_success(*outcome))
                    {
                        continue;
                    }
                }
                auto target = targets->load(index);
                if (!target)
                {
                    return std::unexpected(target.error());
                }
                page->items.push_back(quick_page_item{index, std::move(*target), std::move(outcome)});
            }
            return std::shared_ptr<const quick_page>(std::move(page));
        }

        void quick_progress(const quick::progress& value)
        {
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard lock(mutex);
            // PERFORMANCE: Immutable plans/reports remain shared; mutable progress
            // publication is bounded to stage changes, completion or 30 Hz.
            if (view.quick_stage == value.stage && value.attempted != value.total &&
                now - quick_last_progress < std::chrono::milliseconds(33))
            {
                return;
            }
            quick_last_progress = now;
            view.quick_stage = value.stage;
            view.quick_total = value.total;
            view.quick_attempted = value.attempted;
            view.quick_pending = value.total > value.attempted ? value.total - value.attempted : 0;
            view.completed_count = value.completed;
            view.failed_count = value.failed;
            if (!value.stopping_error.code.empty())
            {
                view.error_code = value.stopping_error.code;
                view.native_code = value.stopping_error.native_code;
            }
        }

        void sample_quick_space(quick::space_observation& observation, bool before)
        {
            auto sampled = quick_host->sample_space(observation.volume_key);
            if (sampled && sampled->volume_key != observation.volume_key)
            {
                sampled = std::unexpected(engine::error{"quick_space_volume_mismatch"});
            }
            auto& destination = before ? observation.before : observation.after;
            auto& error = before ? observation.before_error : observation.after_error;
            if (sampled)
            {
                destination = std::move(*sampled);
            }
            else
            {
                error = sampled.error();
            }
        }

        std::pair<std::vector<quick::space_observation>, bool> begin_quick_space(const quick::staged_plan_info& plan)
        {
            // PERFORMANCE: Bound telemetry independently of target count. Only
            // eligible frozen volume keys are sampled; no namespace is enumerated.
            constexpr std::size_t maximum_volumes = 128;
            std::vector<quick::space_observation> observations;
            observations.reserve((std::min)(maximum_volumes, plan.device_keys.size()));
            std::unordered_set<std::string_view> selected;
            selected.reserve(maximum_volumes);
            bool truncated{};
            for (const auto& device_key : plan.device_keys)
            {
                if (device_key.empty() || selected.contains(device_key))
                {
                    continue;
                }
                if (selected.size() == maximum_volumes)
                {
                    truncated = true;
                    break;
                }
                selected.insert(device_key);
                quick::space_observation observation;
                observation.volume_key = device_key;
                sample_quick_space(observation, true);
                observations.push_back(std::move(observation));
            }
            return {std::move(observations), truncated};
        }

        engine::result<void> audit_batch(std::span<const engine::event> events)
        {
            std::lock_guard serialized(event_mutex);
            auto written = store->emit_batch(events);
            if (!written)
            {
                return written;
            }
            for (const auto& event : events)
            {
                if (on_event && !on_event(event))
                {
                    return std::unexpected(engine::error{"observer_output_failed"});
                }
            }
            std::lock_guard lock(mutex);
            for (const auto& event : events)
            {
                if (view.recent_events.size() == 128)
                {
                    view.recent_events.erase(view.recent_events.begin());
                }
                view.recent_events.push_back(event);
            }
            return {};
        }

        bool launch_quick(std::string fingerprint, bool irreversible_confirmed, bool retry)
        {
            std::shared_ptr<quick::target_source> targets;
            std::shared_ptr<quick::outcome_sink> outcomes;
            std::unordered_map<std::string, input_completion_candidate> input_proofs;
            {
                std::lock_guard lock(mutex);
                if (view.busy || !view.quick_mode || !quick_targets || !quick_outcomes || !view.plan ||
                    !irreversible_confirmed || fingerprint != quick_targets->info().fingerprint ||
                    view.plan->job_id != quick_targets->info().job_id ||
                    (retry ? !quick_report : static_cast<bool>(quick_report)))
                {
                    return false;
                }
                targets = quick_targets;
                outcomes = quick_outcomes;
                input_proofs = quick_input_proofs;
                ++page_generation;
                page_worker.request_stop();
                view.quick_page_loading = false;
            }
            controls.request.store(engine::control_request::proceed);
            return launch(retry ? "quick_retrying" : "quick_executing",
                [this, targets, outcomes, input_proofs = std::move(input_proofs),
                 fingerprint = std::move(fingerprint), irreversible_confirmed, retry]() mutable
            {
                if (!initialize_quick())
                {
                    return;
                }
                const auto& info = targets->info();
                // Preallocate compact publication and selected-root proof storage
                // before mutation. Expanded target/outcome collections stay on disk.
                auto report = std::make_shared<engine::run_report>();
                report->job_id = info.job_id;
                report->plan_fingerprint = info.fingerprint;
                auto proof = std::make_shared<completed_inputs>();
                proof->job_id = info.job_id;
                proof->fingerprint = info.fingerprint;
                proof->paths.reserve(input_proofs.size());
                std::unordered_map<std::string_view, input_completion_candidate*> selected_directories;
                selected_directories.reserve(input_proofs.size());
                for (auto& [key, candidate] : input_proofs)
                {
                    static_cast<void>(key);
                    if (candidate.directory)
                    {
                        selected_directories.emplace(candidate.canonical_path, &candidate);
                    }
                }
                auto intent = emit(engine::event{retry ? "quick_delete_retry_started" : "quick_delete_started",
                    info.job_id, info.fingerprint, 0, 0, 0, info.target_count, 0, 0});
                if (!intent)
                {
                    fail(intent.error());
                    return;
                }
                {
                    std::lock_guard lock(mutex);
                    view.executing = true;
                    view.report.reset();
                    view.quick_completed_inputs.reset();
                    view.quick_page_data.reset();
                    view.devices.clear();
                    view.quick_total = info.target_count;
                    view.quick_attempted = 0;
                    view.quick_pending = info.target_count;
                    view.completed_count = 0;
                    view.failed_count = 0;
                    view.quick_stage = "first_pass";
                    view.locks.clear();
                    view.lock_path.clear();
                    quick_lock_fingerprint.clear();
                    quick_lock_identity.clear();
                    quick_last_progress = {};
                }
                auto [space, truncated] = begin_quick_space(info);
                auto result = quick::run_staged(*targets, *outcomes, fingerprint,
                    irreversible_confirmed, *quick_host, controls, quick_settings,
                    [this](const quick::progress& value) { quick_progress(value); }, retry);
                for (auto& observation : space)
                {
                    sample_quick_space(observation, false);
                }
                if (!result)
                {
                    fail(result.error());
                    report->status = "partial_failure";
                    report->stopping_error = result.error();
                    std::lock_guard lock(mutex);
                    quick_report = report;
                    view.report = report;
                    view.quick_completed_inputs = proof;
                    view.quick_space = std::move(space);
                    view.quick_space_truncated = truncated;
                    return;
                }
                report->status = result->status;
                report->stopping_error = result->stopping_error;
                engine::error diagnostics;
                std::shared_ptr<const quick_page> page;
                try
                {
                    std::array<engine::event, 64> audit_events;
                    std::size_t audit_count{};
                    if (!result->stopping_error.code.empty())
                    {
                        audit_events[audit_count++] = engine::event{result->stopping_error.code,
                            info.job_id, {}, 0, 0, result->stopping_error.native_code};
                    }
                    for (std::size_t index = 0; index < info.target_count; ++index)
                    {
                        auto outcome = outcomes->read(index);
                        if (!outcome)
                        {
                            diagnostics = outcome.error();
                            break;
                        }
                        if (quick_success(*outcome))
                        {
                            const auto original = input_proofs.find(outcome->identity);
                            if (original != input_proofs.end())
                            {
                                original->second.succeeded = true;
                            }
                        }
                        else
                        {
                            if (!selected_directories.empty())
                            {
                                auto target = targets->load(index);
                                if (!target)
                                {
                                    diagnostics = target.error();
                                    break;
                                }
                                const auto canonical = input_namespace(target->path);
                                mark_incomplete_ancestors(canonical, selected_directories);
                            }
                            audit_events[audit_count++] = engine::event{outcome->code, info.job_id,
                                outcome->identity, 0, 0, outcome->native_code};
                            if (audit_count == audit_events.size())
                            {
                                auto logged = audit_batch(std::span(audit_events.data(), audit_count));
                                audit_count = 0;
                                if (!logged)
                                {
                                    diagnostics = logged.error();
                                    break;
                                }
                            }
                        }
                    }
                    if (audit_count != 0 && diagnostics.code.empty())
                    {
                        auto logged = audit_batch(std::span(audit_events.data(), audit_count));
                        if (!logged)
                        {
                            diagnostics = logged.error();
                        }
                    }
                    if (diagnostics.code.empty())
                    {
                        collect_completed_inputs(input_proofs, *proof);
                    }
                    auto loaded = load_page(targets, outcomes, 0, true, true,
                        result->failed + result->unattempted);
                    if (loaded)
                    {
                        page = std::move(*loaded);
                    }
                    else if (diagnostics.code.empty())
                    {
                        diagnostics = loaded.error();
                    }
                }
                catch (...)
                {
                    diagnostics = engine::error{"quick_result_diagnostics_failed"};
                }
                if (!diagnostics.code.empty())
                {
                    proof->paths.clear();
                    report->status = "audit_finalization_failed";
                }
                auto finished = emit(engine::event{"quick_delete_finished_" + report->status,
                    info.job_id, info.fingerprint, 0, 0, result->stopping_error.native_code,
                    result->total, result->completed, result->failed});
                if (!finished)
                {
                    diagnostics = finished.error();
                    proof->paths.clear();
                    report->status = "audit_finalization_failed";
                }
                {
                    std::lock_guard lock(mutex);
                    quick_report = report;
                    view.report = report;
                    view.quick_completed_inputs = std::move(proof);
                    view.quick_page_data = std::move(page);
                    view.quick_space = std::move(space);
                    view.quick_space_truncated = truncated;
                    view.status = report->status;
                    view.quick_stage = report->status;
                    view.quick_total = result->total;
                    view.quick_attempted = result->attempted;
                    view.completed_count = result->completed;
                    view.failed_count = result->failed;
                    view.quick_pending = result->unattempted;
                    view.error_code = diagnostics.code.empty() ? report->stopping_error.code : diagnostics.code;
                    view.native_code = diagnostics.code.empty() ? report->stopping_error.native_code : diagnostics.native_code;
                }
            }, false);
        }

        engine::result<void> emit(const engine::event& value) override
        {
            // SECURITY: Serialize observers and durable logs even if device workers
            // emit concurrently. An observer failure stops further destructive work.
            std::lock_guard event_lock(event_mutex);
            auto logged = store->emit(value);
            if (!logged)
            {
                return logged;
            }
            if (on_event && !on_event(value))
            {
                return std::unexpected(engine::error{"observer_output_failed"});
            }
            std::lock_guard lock(mutex);
            if (view.recent_events.size() == 128)
            {
                view.recent_events.erase(view.recent_events.begin());
            }
            view.recent_events.push_back(value);
            if (value.code == "target_result_completed")
            {
                ++view.completed_count;
            }
            else if (value.code == "target_result_failed")
            {
                ++view.failed_count;
            }
            if (view.plan)
            {
                auto target = std::find_if(view.plan->targets.begin(), view.plan->targets.end(),
                    [&value](const auto& item)
                    {
                        return item.identity == value.identity;
                    });
                if (target != view.plan->targets.end() && value.bytes_total != 0 &&
                    (value.code == "write_progress" || value.code == "verify_progress"))
                {
                    const auto key = std::make_pair(value.identity, value.code);
                    const auto previous = phase_bytes[key];
                    const auto current = (std::max)(previous, value.bytes_done);
                    phase_bytes[key] = current;
                    for (auto& device : view.devices)
                    {
                        if (device.device_key != target->device_key)
                        {
                            continue;
                        }
                        const auto delta = current - previous;
                        const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
                        device.transferred_bytes = delta > maximum - device.transferred_bytes ?
                            maximum : device.transferred_bytes + delta;
                        const double elapsed = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - started).count();
                        device.bytes_per_second = elapsed > 0.0 ?
                            static_cast<double>(device.transferred_bytes) / elapsed : 0.0;
                        const auto remaining = device.total_bytes > device.transferred_bytes ?
                            device.total_bytes - device.transferred_bytes : 0;
                        device.eta_seconds = device.bytes_per_second > 0.0 ?
                            static_cast<double>(remaining) / device.bytes_per_second : 0.0;
                    }
                }
            }
            return {};
        }

        void collect_history()
        {
            auto jobs = store->list_checkpoints();
            auto history = store->read_history(256 * 1024);
            if (!jobs)
            {
                fail(jobs.error());
                return;
            }
            if (!history)
            {
                fail(history.error());
                return;
            }
            std::lock_guard lock(mutex);
            view.checkpoints = std::move(*jobs);
            view.history = std::move(*history);
        }
    };

    application::application(observer on_event, storage::store_options settings,
        engine::options execution_settings)
        : state_(std::make_unique<implementation>())
    {
        state_->on_event = std::move(on_event);
        state_->settings = settings;
        state_->execution_settings = execution_settings;
    }

    application::~application() = default;

    bool application::preview(std::vector<std::string> paths)
    {
        return state_->launch("previewing", [this, paths = std::move(paths)]()
        {
            erase_secrets(state_->resume);
            {
                std::lock_guard lock(state_->mutex);
                state_->clear_quick_locked();
                state_->view.plan.reset();
                state_->view.report.reset();
                state_->view.resume_loaded = false;
            }
            auto targets = state_->host->preview(paths);
            if (!targets)
            {
                state_->fail(targets.error());
                return;
            }
            std::array<std::byte, 16> id{};
            auto random = state_->host->random_bytes(id);
            if (!random)
            {
                state_->fail(random.error());
                return;
            }
            constexpr std::string_view digits = "0123456789abcdef";
            std::string job_id;
            for (const auto byte : id)
            {
                const auto value = std::to_integer<unsigned int>(byte);
                job_id.push_back(digits[value >> 4]);
                job_id.push_back(digits[value & 15]);
            }
            auto plan = engine::freeze(std::move(job_id), std::move(*targets));
            if (!plan)
            {
                state_->fail(plan.error());
                return;
            }
            engine::checkpoint pending;
            pending.plan = *plan;
            pending.targets.reserve(plan->targets.size());
            for (const auto& target : plan->targets)
            {
                engine::target_checkpoint item;
                item.identity = target.identity;
                item.observed = target;
                pending.targets.push_back(std::move(item));
            }
            auto saved = state_->store->save(pending);
            if (!saved)
            {
                state_->fail(saved.error());
                return;
            }
            std::lock_guard lock(state_->mutex);
            state_->view.plan = std::make_shared<const engine::frozen_plan>(std::move(*plan));
            state_->view.status = "preview_ready";
        });
    }

    bool application::preview_quick(std::vector<std::string> paths)
    {
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.busy)
            {
                return false;
            }
            state_->clear_quick_locked();
            state_->view.quick_mode = true;
            state_->view.quick_paged = true;
            state_->view.plan.reset();
            state_->view.report.reset();
            state_->view.resume_loaded = false;
            state_->view.completed_count = 0;
            state_->view.failed_count = 0;
        }
        state_->controls.request.store(engine::control_request::proceed);
        return state_->launch("quick_preparing", [this, paths = std::move(paths)]()
        {
            erase_secrets(state_->resume);
            if (!state_->initialize_quick())
            {
                return;
            }
            auto job_id = random_job_id();
            auto files = state_->store->staging_files();
            auto resources = state_->quick_host->inspect_resources({});
            if (!job_id || !files || !resources)
            {
                state_->fail(!job_id ? job_id.error() : !files ? files.error() : resources.error());
                return;
            }
            auto memory = std::min(resources->available_memory_bytes, resources->available_commit_bytes) / 16;
            if (state_->quick_settings.memory_budget_bytes != 0)
            {
                memory = std::min(memory, state_->quick_settings.memory_budget_bytes / 8);
            }
            auto disk = (*files)->available_bytes();
            if (!disk)
            {
                state_->fail(disk.error());
                return;
            }
            auto staging = quick::store::staging_store::create(*files, *job_id,
                quick::store::options{memory, *disk / 2});
            if (!staging)
            {
                state_->fail(staging.error());
                return;
            }
            vector_roots roots(paths);
            input_tracking_sink tracking(**staging, paths);
            auto prepared = state_->quick_host->prepare_stream(roots, tracking, state_->controls);
            if (!prepared)
            {
                state_->fail(prepared.error());
                return;
            }
            auto frozen = (*staging)->finalize();
            if (!frozen)
            {
                state_->fail(frozen.error());
                return;
            }
            auto page = state_->load_page(frozen->targets, frozen->outcomes, 0, false, false, 0);
            if (!page)
            {
                state_->fail(page.error());
                return;
            }
            auto display = std::make_shared<engine::frozen_plan>();
            display->job_id = frozen->targets->info().job_id;
            display->fingerprint = frozen->targets->info().fingerprint;
            std::lock_guard lock(state_->mutex);
            state_->quick_targets = std::move(frozen->targets);
            state_->quick_outcomes = std::move(frozen->outcomes);
            state_->quick_input_proofs = tracking.take_proofs();
            state_->view.plan = std::move(display);
            state_->view.quick_page_data = std::move(*page);
            state_->view.quick_total = state_->quick_targets->info().target_count;
            state_->view.quick_pending = state_->view.quick_total;
            state_->view.status = "quick_preview_ready";
            state_->view.quick_stage = "prepared";
        }, false);
    }

    bool application::request_quick_page(std::uint64_t offset, bool failures_only)
    {
        std::shared_ptr<quick::target_source> targets;
        std::shared_ptr<quick::outcome_sink> outcomes;
        bool has_outcomes{};
        std::uint64_t incomplete{};
        std::uint64_t generation{};
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.busy || state_->view.quick_page_loading || !state_->quick_targets ||
                (failures_only && !state_->quick_report))
            {
                return false;
            }
            targets = state_->quick_targets;
            outcomes = state_->quick_outcomes;
            has_outcomes = static_cast<bool>(state_->quick_report);
            incomplete = state_->view.failed_count + state_->view.quick_pending;
            generation = ++state_->page_generation;
            state_->view.quick_page_loading = true;
        }
        if (state_->page_worker.joinable())
        {
            state_->page_worker.join();
        }
        state_->page_worker = std::jthread([this, targets, outcomes, offset, failures_only,
            has_outcomes, incomplete, generation](std::stop_token stop)
        {
            engine::result<std::shared_ptr<const quick_page>> page = std::unexpected(
                engine::error{"quick_page_allocation_failed"});
            try
            {
                page = state_->load_page(targets, outcomes, offset, failures_only, has_outcomes, incomplete, stop);
            }
            catch (...)
            {
            }
            std::lock_guard lock(state_->mutex);
            if (state_->page_generation != generation || state_->quick_targets != targets)
            {
                return;
            }
            state_->view.quick_page_loading = false;
            if (page)
            {
                state_->view.quick_page_data = std::move(*page);
            }
            else
            {
                state_->view.error_code = page.error().code;
                state_->view.native_code = page.error().native_code;
            }
        });
        return true;
    }

    bool application::execute_quick(std::string fingerprint, bool irreversible_confirmed)
    {
        return state_->launch_quick(std::move(fingerprint), irreversible_confirmed, false);
    }

    bool application::retry_quick(std::string fingerprint, bool irreversible_confirmed)
    {
        return state_->launch_quick(std::move(fingerprint), irreversible_confirmed, true);
    }

    bool application::query_quick_locks(std::string path, std::string fingerprint)
    {
        std::optional<quick::target> target;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.busy)
            {
                return false;
            }
            target = state_->failed_quick_target_locked(path, fingerprint);
            if (!target)
            {
                return false;
            }
            state_->view.locks.clear();
            state_->view.lock_path.clear();
            state_->quick_lock_fingerprint.clear();
            state_->quick_lock_identity.clear();
        }
        return state_->launch("querying_quick_locks", [this, target = std::move(*target),
            fingerprint = std::move(fingerprint)]()
        {
            if (!state_->initialize_quick())
            {
                return;
            }
            auto locks = state_->quick_host->query_locks(target);
            if (!locks)
            {
                state_->fail(locks.error());
                return;
            }
            std::lock_guard lock(state_->mutex);
            state_->view.locks = std::move(*locks);
            state_->view.lock_path = target.path;
            state_->quick_lock_fingerprint = fingerprint;
            state_->quick_lock_identity = quick::target_key(target);
            state_->view.status = "quick_locks_ready";
        }, false);
    }

    bool application::close_quick_process(std::string path, engine::locking_process process,
        bool individual_force_confirmation, std::string fingerprint)
    {
        std::optional<quick::target> target;
        std::string job_id;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.busy || !process.eligible || state_->quick_lock_fingerprint != fingerprint ||
                state_->view.lock_path != path)
            {
                return false;
            }
            target = state_->failed_quick_target_locked(path, fingerprint);
            if (!target || state_->quick_lock_identity != quick::target_key(*target))
            {
                return false;
            }
            const auto selected = std::find_if(state_->view.locks.begin(), state_->view.locks.end(),
                [&process](const auto& value)
                {
                    return value.eligible && value.process_id == process.process_id &&
                        value.creation_time == process.creation_time && value.image_path == process.image_path;
                });
            if (selected == state_->view.locks.end())
            {
                return false;
            }
            job_id = state_->quick_targets->info().job_id;
            // SECURITY: Consume this selection before asynchronous launch. A new
            // action needs a fresh enumeration and, for force, individual consent.
            state_->view.locks.clear();
            state_->view.lock_path.clear();
            state_->quick_lock_fingerprint.clear();
            state_->quick_lock_identity.clear();
        }
        return state_->launch("releasing_quick_lock", [this, target = std::move(*target),
            process = std::move(process), individual_force_confirmation, job_id = std::move(job_id)]()
        {
            if (!state_->initialize_quick())
            {
                return;
            }
            const std::string identity = "process:" + std::to_string(process.process_id) +
                ":" + std::to_string(process.creation_time);
            auto intent = state_->emit(engine::event{individual_force_confirmation ?
                "quick_process_force_termination_authorized" : "quick_process_close_requested", job_id, identity});
            if (!intent)
            {
                state_->fail(intent.error());
                return;
            }
            auto closed = state_->quick_host->close_process(target, process, individual_force_confirmation);
            if (!closed)
            {
                static_cast<void>(state_->emit(engine::event{closed.error().code, job_id,
                    identity, 0, 0, closed.error().native_code}));
                state_->fail(closed.error());
                return;
            }
            auto completion = state_->emit(engine::event{individual_force_confirmation ?
                "quick_process_force_termination_completed" : "quick_process_close_completed", job_id, identity});
            if (!completion)
            {
                state_->fail(completion.error());
                return;
            }
            std::lock_guard lock(state_->mutex);
            state_->view.status = "quick_process_release_requested";
        }, false);
    }

    bool application::load_job(std::string job_id)
    {
        return state_->launch("loading_checkpoint", [this, job_id = std::move(job_id)]()
        {
            erase_secrets(state_->resume);
            {
                std::lock_guard lock(state_->mutex);
                state_->clear_quick_locked();
                state_->view.plan.reset();
                state_->view.report.reset();
                state_->view.resume_loaded = false;
            }
            auto loaded = state_->store->load(job_id);
            if (!loaded)
            {
                state_->fail(loaded.error());
                return;
            }
            // SECURITY: Only a protected store result can reach the resume pointer.
            // No imported JSON, command path list, or previous approval is trusted.
            state_->resume.emplace(std::move(*loaded));
            std::lock_guard lock(state_->mutex);
            state_->view.plan = std::make_shared<const engine::frozen_plan>(state_->resume->plan);
            state_->view.resume_loaded = true;
            state_->view.status = "resume_confirmation_required";
        });
    }

    bool application::execute(std::string fingerprint, bool irreversible_confirmed,
        std::vector<std::string> downgrade_tokens)
    {
        std::shared_ptr<const engine::frozen_plan> plan;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.busy || state_->view.quick_mode || !state_->view.plan)
            {
                return false;
            }
            plan = state_->view.plan;
        }
        state_->controls.request.store(engine::control_request::proceed);
        return state_->launch("executing", [this, plan, fingerprint = std::move(fingerprint),
            irreversible_confirmed, tokens = std::move(downgrade_tokens)]()
        {
            if (!irreversible_confirmed || fingerprint != plan->fingerprint)
            {
                state_->fail(engine::error{"fresh_exact_plan_confirmation_required"});
                return;
            }
            engine::approval consent{fingerprint, true, {}};
            for (const auto& token : tokens)
            {
                const auto found = std::find_if(plan->targets.begin(), plan->targets.end(),
                    [&token](const auto& target)
                    {
                        return engine::needs_downgrade(target) && downgrade_token(target) == token;
                    });
                if (found == plan->targets.end())
                {
                    state_->fail(engine::error{"unknown_or_stale_downgrade_token"});
                    return;
                }
                consent.downgrade_identities.push_back(found->identity);
            }
            {
                std::lock_guard lock(state_->mutex);
                state_->view.executing = true;
                state_->view.report.reset();
                state_->view.devices.clear();
                state_->view.recent_events.clear();
                state_->view.completed_count = 0;
                state_->view.failed_count = 0;
                std::map<std::string, std::uint64_t> totals;
                for (const auto& target : plan->targets)
                {
                    const auto bytes = target_bytes(target);
                    auto& total = totals[target.device_key];
                    // CONTRACT: display estimates saturate; engine validates true sizes.
                    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
                    total = bytes > (maximum - total) / 2 ? maximum : total + 2 * bytes;
                }
                for (const auto& [key, total] : totals)
                {
                    state_->view.devices.push_back(device_progress{key, 0, total});
                }
                state_->started = std::chrono::steady_clock::now();
                state_->phase_bytes.clear();
            }
            auto report = engine::run(*plan, consent, *state_->host, *state_->store,
                *state_, state_->controls, state_->execution_settings, state_->resume ? &*state_->resume : nullptr);
            // SECURITY: Keys from the previous load are never kept in presentation state.
            erase_secrets(state_->resume);
            if (!report)
            {
                state_->fail(report.error());
            }
            else
            {
                std::lock_guard lock(state_->mutex);
                state_->view.report = std::make_shared<const engine::run_report>(std::move(*report));
                state_->view.status = state_->view.report->status;
                state_->view.completed_count = 0;
                state_->view.failed_count = 0;
                for (const auto& outcome : state_->view.report->targets)
                {
                    if (outcome.deleted && (outcome.code == "deleted_logical_overwrite_verified_residual_risk" ||
                        outcome.code == "deleted_only_residual_risk" || outcome.code == "completed_from_authenticated_checkpoint"))
                    {
                        ++state_->view.completed_count;
                    }
                    else
                    {
                        ++state_->view.failed_count;
                    }
                }
            }
            {
                // INVARIANT: Every run consumes the frontend plan. Resuming requires
                // authenticating the latest checkpoint and obtaining new consent.
                std::lock_guard lock(state_->mutex);
                state_->view.plan.reset();
                state_->view.resume_loaded = false;
            }
            state_->collect_history();
        });
    }

    bool application::configure_execution(engine::options settings)
    {
        std::lock_guard lock(state_->mutex);
        if (state_->view.busy)
        {
            return false;
        }
        state_->execution_settings = settings;
        return true;
    }

    bool application::configure_quick(quick::options settings)
    {
        std::lock_guard lock(state_->mutex);
        if (state_->view.busy)
        {
            return false;
        }
        state_->quick_settings = settings;
        return true;
    }

    bool application::refresh_history()
    {
        return state_->launch("loading_history", [this]()
        {
            state_->collect_history();
            std::lock_guard lock(state_->mutex);
            if (state_->view.error_code.empty())
            {
                state_->view.status = "history_ready";
            }
        });
    }

    bool application::query_locks(std::string path)
    {
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.quick_mode)
            {
                return false;
            }
        }
        return state_->launch("querying_locks", [this, path = std::move(path)]()
        {
            auto locks = engine::query_locking_processes(path);
            if (!locks)
            {
                state_->fail(locks.error());
                return;
            }
            std::lock_guard lock(state_->mutex);
            state_->view.locks = std::move(*locks);
            state_->view.lock_path = path;
            state_->view.status = "locks_ready";
        });
    }

    bool application::close_process(std::string path, engine::locking_process process,
        bool individual_force_confirmation)
    {
        {
            std::lock_guard lock(state_->mutex);
            if (state_->view.quick_mode)
            {
                return false;
            }
        }
        return state_->launch("releasing_lock", [this, path = std::move(path),
            process = std::move(process), individual_force_confirmation]()
        {
            const std::string process_identity = "process:" + std::to_string(process.process_id) +
                ":" + std::to_string(process.creation_time);
            auto intent = state_->emit(engine::event{
                individual_force_confirmation ? "process_force_termination_authorized" : "process_close_requested",
                {}, process_identity});
            if (!intent)
            {
                state_->fail(intent.error());
                return;
            }
            auto released = engine::request_process_close(path, process, individual_force_confirmation);
            if (!released)
            {
                static_cast<void>(state_->emit(engine::event{released.error().code, {}, process_identity,
                    0, 0, released.error().native_code}));
                state_->fail(released.error());
                return;
            }
            auto completion = state_->emit(engine::event{
                individual_force_confirmation ? "process_force_termination_completed" : "process_close_completed",
                {}, process_identity});
            if (!completion)
            {
                state_->fail(completion.error());
                return;
            }
            auto locks = engine::query_locking_processes(path);
            if (!locks)
            {
                state_->fail(locks.error());
                return;
            }
            std::lock_guard lock(state_->mutex);
            state_->view.locks = std::move(*locks);
            state_->view.status = "process_release_requested";
        });
    }

    void application::pause() noexcept
    {
        state_->controls.request.store(engine::control_request::pause);
    }

    void application::cancel() noexcept
    {
        state_->controls.request.store(engine::control_request::cancel);
    }

    view_state application::snapshot(bool include_details) const
    {
        std::lock_guard lock(state_->mutex);
        if (include_details)
        {
            return state_->view;
        }
        view_state result;
        const auto& view = state_->view;
        result.busy = view.busy;
        result.executing = view.executing;
        result.resume_loaded = view.resume_loaded;
        result.quick_mode = view.quick_mode;
        result.quick_paged = view.quick_paged;
        result.quick_page_loading = view.quick_page_loading;
        result.quick_page_data = view.quick_page_data;
        result.quick_completed_inputs = view.quick_completed_inputs;
        result.quick_stage = view.quick_stage;
        result.quick_total = view.quick_total;
        result.quick_attempted = view.quick_attempted;
        result.quick_pending = view.quick_pending;
        result.status = view.status;
        result.error_code = view.error_code;
        result.native_code = view.native_code;
        result.plan = view.plan;
        result.report = view.report;
        result.devices = view.devices;
        result.completed_count = view.completed_count;
        result.failed_count = view.failed_count;
        return result;
    }

    void application::wait()
    {
        if (state_->worker.joinable())
        {
            state_->worker.join();
        }
    }

    std::string_view capability_name(engine::capability value) noexcept
    {
        switch (value)
        {
        case engine::capability::blocked: return "blocked";
        case engine::capability::overwrite_verified: return "overwrite_verified";
        case engine::capability::overwrite_best_effort: return "overwrite_best_effort";
        case engine::capability::delete_only: return "delete_only";
        }
        return "unknown";
    }

    std::string_view media_name(engine::media_kind value) noexcept
    {
        switch (value)
        {
        case engine::media_kind::unknown: return "unknown";
        case engine::media_kind::hdd: return "hdd";
        case engine::media_kind::ssd: return "ssd";
        case engine::media_kind::usb: return "usb";
        }
        return "unknown";
    }

    std::string downgrade_token(const engine::target_snapshot& target)
    {
        return target.identity + "|" + std::string(capability_name(target.support));
    }

    std::string json_quote(std::string_view value)
    {
        constexpr std::string_view hex = "0123456789abcdef";
        std::string result{"\""};
        for (const char character : value)
        {
            const auto code = static_cast<unsigned char>(character);
            if (code == '"' || code == '\\')
            {
                result.push_back('\\');
                result.push_back(character);
            }
            else if (code < 0x20)
            {
                result += "\\u00";
                result.push_back(hex[code >> 4]);
                result.push_back(hex[code & 15]);
            }
            else
            {
                result.push_back(character);
            }
        }
        result.push_back('"');
        return result;
    }

    std::string event_json(const engine::event& value)
    {
        std::string text = "{\"schema\":\"secure_erase.event.v1\",\"code\":" + json_quote(value.code) +
            ",\"job_id\":" + json_quote(value.job_id) + ",\"identity\":" + json_quote(value.identity) +
            ",\"bytes_done\":" + std::to_string(value.bytes_done) +
            ",\"bytes_total\":" + std::to_string(value.bytes_total) +
            ",\"native_code\":" + std::to_string(value.native_code);
        if (value.total_targets != 0 || value.completed_targets != 0 || value.failed_targets != 0)
        {
            text += ",\"target_counts\":{\"total\":" + std::to_string(value.total_targets) +
                ",\"completed\":" + std::to_string(value.completed_targets) +
                ",\"failed\":" + std::to_string(value.failed_targets) + "}";
        }
        return text + "}";
    }

    std::string report_json(const engine::run_report& value)
    {
        std::string text = "{\"schema\":\"secure_erase.report.v1\",\"job_id\":" +
            json_quote(value.job_id) + ",\"status\":" + json_quote(value.status) +
            ",\"physical_sanitization_guaranteed\":false,\"targets\":[";
        bool first = true;
        for (const auto& target : value.targets)
        {
            if (!first)
            {
                text.push_back(',');
            }
            first = false;
            text += "{\"identity\":" + json_quote(target.identity) + ",\"code\":" +
                json_quote(target.code) + ",\"deleted\":" + (target.deleted ? "true" : "false") +
                ",\"logical_overwrite_verified\":" + (target.logical_overwrite_verified ? "true" : "false") +
                ",\"written_bytes\":" + std::to_string(target.written_bytes) +
                ",\"verified_bytes\":" + std::to_string(target.verified_bytes) +
                ",\"native_code\":" + std::to_string(target.native_code) + "}";
        }
        return text + "]}";
    }

    engine::result<std::string> utf8(std::wstring_view value)
    {
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        {
            return std::unexpected(engine::error{"unicode_input_too_long"});
        }
        if (value.empty())
        {
            return std::string{};
        }
        const int count = static_cast<int>(value.size());
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), count,
            nullptr, 0, nullptr, nullptr);
        if (size == 0)
        {
            return std::unexpected(engine::error{"invalid_utf16", GetLastError()});
        }
        std::string result(static_cast<std::size_t>(size), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), count,
            result.data(), size, nullptr, nullptr) != size)
        {
            return std::unexpected(engine::error{"utf8_conversion_failed", GetLastError()});
        }
        return result;
    }

    engine::result<std::wstring> utf16(std::string_view value)
    {
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        {
            return std::unexpected(engine::error{"unicode_input_too_long"});
        }
        if (value.empty())
        {
            return std::wstring{};
        }
        const int count = static_cast<int>(value.size());
        const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), count, nullptr, 0);
        if (size == 0)
        {
            return std::unexpected(engine::error{"invalid_utf8", GetLastError()});
        }
        std::wstring result(static_cast<std::size_t>(size), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), count,
            result.data(), size) != size)
        {
            return std::unexpected(engine::error{"utf16_conversion_failed", GetLastError()});
        }
        return result;
    }
}
