import std;
import secure_erase.quick_delete;
import secure_erase.platform;

namespace
{
namespace quick = secure_erase::quick;
namespace engine = secure_erase::engine;

struct test_results
{
    unsigned total{};
    unsigned passed{};

    void check(bool condition, std::string_view name)
    {
        ++total;
        passed += static_cast<unsigned>(condition);
        std::cout << "{\"test\":\"" << name << "\",\"passed\":" <<
            (condition ? "true" : "false") << "}\n";
    }
};

[[nodiscard]] quick::target make_target(std::string path, bool directory = false,
    std::string device = "volume:1", std::string identity = {})
{
    if (identity.empty())
    {
        identity = "id:" + path;
    }
    return {std::move(path), std::move(identity), std::move(device), 123, 0, directory, {}};
}

[[nodiscard]] quick::plan frozen(std::vector<quick::target> targets)
{
    return quick::freeze("0123456789abcdef0123456789abcdef", std::move(targets)).value();
}

struct record
{
    quick::target target;
    std::vector<engine::error> errors;
    std::vector<engine::locking_process> processes;
    std::size_t attempts{};
    bool deleted{};
    bool readonly{};
    bool locked{};
    bool delay{};
    unsigned delay_milliseconds{3};
};

class test_backend final : public quick::backend
{
public:
    std::map<std::string, record> records;
    std::vector<std::string> events;
    std::map<std::string, std::size_t> active_by_device;
    std::size_t active{};
    std::size_t maximum_active{};
    std::size_t maximum_device_active{};
    std::size_t maximum_first_sample_active{};
    std::size_t begins{};
    std::size_t queries{};
    std::size_t closes{};
    std::size_t space_samples{};
    std::size_t resource_samples{};
    std::size_t finishes{};
    std::function<void(quick::resource_sample&, std::size_t)> resource_adjustment;
    bool force_seen{};
    bool fail_begin{};
    bool fail_query{};
    bool fail_close{};
    bool close_device_fault{};
    bool contention_penalty{};
    bool flat_throughput_penalty{};
    std::mutex mutex;

    void add(const quick::plan& plan)
    {
        for (const auto& value : plan.targets)
        {
            record state;
            state.target = value;
            records.emplace(value.path, std::move(state));
        }
    }

    engine::result<std::vector<quick::target>> prepare(const std::vector<std::string>& paths,
        engine::control&) override
    {
        std::vector<quick::target> targets;
        for (const auto& path : paths)
        {
            targets.push_back(records.at(path).target);
        }
        return targets;
    }

    engine::result<void> begin_execution() override
    {
        ++begins;
        if (fail_begin)
        {
            return std::unexpected(engine::error{"test_begin_failed", 5, false});
        }
        return {};
    }

    engine::result<quick::resource_sample> inspect_resources(
        std::span<const std::string_view> device_keys) override
    {
        const std::scoped_lock lock(mutex);
        quick::resource_sample sample;
        sample.available_memory_bytes = 2ULL * 1024 * 1024 * 1024;
        sample.available_commit_bytes = 4ULL * 1024 * 1024 * 1024;
        sample.available_handles = 65536;
        sample.temporary_disk_available_bytes = 1024ULL * 1024 * 1024;
        sample.logical_processors = 2;
        sample.cpu_pressure_known = true;
        for (const auto key : device_keys)
        {
            sample.devices.push_back({std::string(key), std::string(key), 4, 0, true});
        }
        ++resource_samples;
        if (resource_adjustment)
        {
            resource_adjustment(sample, resource_samples);
        }
        return sample;
    }

    void finish_execution() noexcept override
    {
        ++finishes;
    }

    engine::result<quick::space_sample> sample_space(std::string_view volume_key) override
    {
        ++space_samples;
        return quick::space_sample{std::string(volume_key), 42, 42, 100};
    }

    engine::result<void> remove(const quick::target& target, bool recover_access) override
    {
        std::size_t admitted_concurrency = 1;
        {
            const std::scoped_lock lock(mutex);
            ++active;
            admitted_concurrency = active;
            if (resource_samples == 1)
            {
                maximum_first_sample_active = std::max(maximum_first_sample_active, active);
            }
            maximum_active = std::max(maximum_active, active);
            const auto device_active = ++active_by_device[target.device_key];
            maximum_device_active = std::max(maximum_device_active, device_active);
            events.push_back((recover_access ? "recover:" : "remove:") + target.path);
        }
        if (records.at(target.path).delay)
        {
            const auto penalty = contention_penalty ? admitted_concurrency * admitted_concurrency :
                flat_throughput_penalty ? admitted_concurrency : 1;
            std::this_thread::sleep_for(std::chrono::milliseconds(records.at(target.path).delay_milliseconds * penalty));
        }
        const std::scoped_lock lock(mutex);
        --active;
        --active_by_device.at(target.device_key);
        auto& value = records.at(target.path);
        ++value.attempts;
        if (value.target.identity != target.identity || value.target.creation_time != target.creation_time)
        {
            return std::unexpected(engine::error{"quick_frozen_identity_changed", 5, false});
        }
        if (value.attempts <= value.errors.size())
        {
            const auto& error = value.errors[value.attempts - 1];
            if (!error.code.empty())
            {
                return std::unexpected(error);
            }
        }
        if (value.readonly && !recover_access)
        {
            return std::unexpected(engine::error{"quick_readonly_recovery_required", 5, false});
        }
        if (value.locked)
        {
            return std::unexpected(engine::error{"quick_target_open_failed", 32, false});
        }
        if (target.directory)
        {
            for (const auto& [path, child] : records)
            {
                if (path.starts_with(target.path + "/") && !child.deleted)
                {
                    return std::unexpected(engine::error{"quick_disposition_failed", 145, false});
                }
            }
        }
        value.deleted = true;
        return {};
    }

    engine::result<std::vector<engine::locking_process>> query_locks(const quick::target& target) override
    {
        ++queries;
        events.push_back("query:" + target.path);
        if (fail_query)
        {
            return std::unexpected(engine::error{"test_query_failed", 5, false});
        }
        return records.at(target.path).processes;
    }

    engine::result<void> close_process(const quick::target& target,
        const engine::locking_process& process, bool force_confirmed) override
    {
        ++closes;
        force_seen = force_seen || force_confirmed;
        events.push_back("close:" + target.path);
        if (fail_close)
        {
            return std::unexpected(engine::error{"test_close_failed", 5, close_device_fault});
        }
        for (auto& [path, value] : records)
        {
            static_cast<void>(path);
            if (std::any_of(value.processes.begin(), value.processes.end(), [&](const auto& held)
            {
                return held.process_id == process.process_id && held.creation_time == process.creation_time;
            }))
            {
                value.locked = false;
            }
        }
        return {};
    }
};

[[nodiscard]] engine::result<engine::run_report> execute(const quick::plan& plan,
    test_backend& host, engine::control& control, quick::progress_observer observer = {},
    const engine::run_report* previous = nullptr, quick::options options = {})
{
    return quick::run(plan, plan.fingerprint, true, host, control, options,
        std::move(observer), previous);
}

[[nodiscard]] std::size_t event_index(const test_backend& host, std::string_view text)
{
    const auto found = std::find(host.events.begin(), host.events.end(), text);
    return static_cast<std::size_t>(std::distance(host.events.begin(), found));
}
}

int main()
{
    test_results results;
    results.check(quick::options{}.space_first, "allocation_priority_enabled_by_default");
    const auto first = make_target("/fixture/a");
    const auto second = make_target("/fixture/b");
    const auto base = frozen({first, second});
    results.check(base.fingerprint.size() == 64 && quick::fingerprint(base) == base.fingerprint,
        "quick_plan_sha256_fingerprint");
    results.check(quick::freeze(base.job_id, {first, first})->targets.size() == 1,
        "exact_duplicate_namespace_collapses");
    auto alias = first;
    alias.path = "/fixture/hardlink";
    const auto links = frozen({first, alias});
    results.check(links.targets.size() == 2 && quick::target_key(first) != quick::target_key(alias),
        "selected_hardlink_names_remain_distinct");
    auto conflict = first;
    conflict.identity = "replacement";
    results.check(!quick::freeze(base.job_id, {first, conflict}), "same_path_replacement_conflict_rejected");
    conflict = first;
    conflict.attributes = 1;
    results.check(!quick::freeze(base.job_id, {first, conflict}), "same_path_metadata_conflict_rejected");
    conflict = first;
    conflict.allocated_bytes = 4096;
    results.check(!quick::freeze(base.job_id, {first, conflict}),
        "same_namespace_conflicting_allocation_hint_rejected");
    results.check(quick::target_key(first) == quick::target_key(conflict),
        "allocation_hint_does_not_change_namespace_identity_key");
    results.check(frozen({first}).fingerprint != frozen({conflict}).fingerprint,
        "allocation_hint_is_bound_to_plan_fingerprint");
    results.check(!quick::freeze("invalid", {first}) && !quick::freeze(base.job_id, {}),
        "invalid_job_and_empty_plan_rejected");
    {
        std::vector<quick::target> large;
        large.reserve(100001);
        for (std::size_t index = 0; index < 100001; ++index)
        {
            large.push_back(make_target("/large/" + std::to_string(index)));
        }
        const auto complete = quick::freeze(base.job_id, std::move(large));
        results.check(complete && complete->targets.size() == 100001,
            "complete_batch_above_old_fixed_target_limit");
    }
    auto invalid = first;
    invalid.path = std::string(131073, 'a');
    results.check(!quick::freeze(base.job_id, {invalid}), "path_length_limit_enforced");
    invalid = first;
    invalid.path += std::string("\0tail", 5);
    results.check(!quick::freeze(base.job_id, {invalid}), "embedded_nul_rejected");
    const std::array<std::string, 5> malformed{
        std::string("\xc0\x80", 2), std::string("\xed\xa0\x80", 3),
        std::string("\xf4\x90\x80\x80", 4), std::string("\xe2\x82", 2), std::string("\x80", 1)};
    for (std::size_t index = 0; index < malformed.size(); ++index)
    {
        invalid = first;
        invalid.path += malformed[index];
        results.check(!quick::freeze(base.job_id, {invalid}), "invalid_utf8_" + std::to_string(index));
    }
    invalid = first;
    invalid.path += "\xe6\xaa\x94\xf0\x9f\x93\x81";
    results.check(quick::freeze(base.job_id, {invalid}).has_value(), "valid_unicode_path_accepted");
    invalid = first;
    invalid.identity.clear();
    results.check(!quick::freeze(base.job_id, {invalid}), "unbound_target_rejected");
    invalid.preparation_error = {"metadata_denied", 5, false};
    const auto partial = frozen({invalid, second});
    results.check(partial.targets.size() == 2 && !partial.targets.front().preparation_error.code.empty(),
        "preparation_failure_retained");
    const auto display = quick::display_plan(partial);
    results.check(display.targets.front().support == engine::capability::blocked &&
        display.targets.back().support == engine::capability::delete_only &&
        display.targets.back().identity == quick::target_key(partial.targets.back()),
        "display_plan_uses_namespace_keys_and_blocked_failures");
    {
        std::vector<quick::target> large;
        for (std::size_t index = 0; index < 514; ++index)
        {
            auto value = first;
            value.path = "/" + std::to_string(index) + std::string(131000, 'x');
            large.push_back(std::move(value));
        }
        results.check(quick::freeze(base.job_id, std::move(large)).has_value(), "no_fixed_aggregate_text_ceiling");
    }
    {
        test_backend host;
        host.add(base);
        engine::control control;
        results.check(!quick::run(base, base.fingerprint, false, host, control) && host.begins == 0,
            "irreversible_confirmation_required_before_backend");
        results.check(!quick::run(base, "wrong", true, host, control) && host.begins == 0,
            "exact_fingerprint_required_before_backend");
        auto changed = base;
        ++changed.targets.front().creation_time;
        results.check(!execute(changed, host, control) && host.begins == 0,
            "mutated_target_rejected_before_backend");
        changed = base;
        ++changed.targets.front().allocated_bytes;
        results.check(!execute(changed, host, control) && host.begins == 0,
            "mutated_allocation_hint_rejected_before_backend");
        changed = base;
        std::reverse(changed.targets.begin(), changed.targets.end());
        changed.fingerprint = quick::fingerprint(changed);
        results.check(!execute(changed, host, control), "noncanonical_plan_order_rejected");
        {
            test_backend auto_host;
            auto_host.add(base);
            test_backend explicit_host;
            explicit_host.add(base);
            results.check(execute(base, auto_host, control, {}, nullptr, {0, true}).has_value() &&
                execute(base, explicit_host, control, {}, nullptr, {17, true}).has_value(),
                "automatic_and_above_old_worker_ceiling_accepted");
        }
        host.fail_begin = true;
        results.check(!execute(base, host, control) && host.events.empty(), "backend_admission_failure_no_mutation");
    }
    {
        auto small = make_target("/schedule/a");
        small.allocated_bytes = 4096;
        auto large = make_target("/schedule/b");
        large.allocated_bytes = std::numeric_limits<std::uint64_t>::max();
        auto tied = make_target("/schedule/c");
        tied.allocated_bytes = large.allocated_bytes;
        auto zero = make_target("/schedule/z");
        auto directory = make_target("/schedule", true);
        directory.allocated_bytes = large.allocated_bytes;
        const auto plan = frozen({zero, tied, small, directory, large});
        test_backend host;
        host.add(plan);
        engine::control control;
        const auto report = execute(plan, host, control, {}, nullptr, {1, true});
        results.check(report && report->status == "completed" && host.events ==
            std::vector<std::string>{"remove:/schedule/b", "remove:/schedule/c", "remove:/schedule/a",
                "remove:/schedule/z", "remove:/schedule"},
            "allocation_priority_descending_with_path_ties_and_directory_barrier");
        results.check(report && report->targets.front().identity == quick::target_key(plan.targets.front()) &&
            plan.targets.front().path == "/schedule/a", "scheduling_preserves_canonical_plan_and_report_order");
        results.check(host.space_samples == 0, "core_scheduling_does_not_sample_free_space");
        test_backend disabled_host;
        disabled_host.add(plan);
        const auto disabled = execute(plan, disabled_host, control, {}, nullptr, {1, true, false});
        results.check(disabled && disabled->status == "completed" && disabled_host.events ==
            std::vector<std::string>{"remove:/schedule/a", "remove:/schedule/b", "remove:/schedule/c",
                "remove:/schedule/z", "remove:/schedule"},
            "disabled_allocation_priority_preserves_path_order");
    }
    {
        test_backend host;
        host.add(partial);
        engine::control control;
        const auto report = execute(partial, host, control);
        results.check(report && report->status == "partial_failure" &&
            report->targets.front().code == "metadata_denied" && report->targets.back().deleted,
            "preparation_failure_does_not_abort_valid_siblings");
        results.check(host.records.at(first.path).attempts == 0 && host.queries == 0,
            "preparation_failure_never_recovered_or_queried");
    }
    {
        test_backend host;
        host.add(links);
        engine::control control;
        const auto report = execute(links, host, control);
        results.check(report && report->status == "completed" && report->targets.size() == 2 &&
            host.records.at(first.path).deleted && host.records.at(alias.path).deleted,
            "all_selected_hardlinks_deleted_individually");
        results.check(std::all_of(report->targets.begin(), report->targets.end(), [](const auto& outcome)
        {
            return outcome.deleted && outcome.code == "deleted_quick_namespace_removed" &&
                !outcome.logical_overwrite_verified && !outcome.physical_sanitization_guaranteed &&
                outcome.written_bytes == 0 && outcome.verified_bytes == 0;
        }), "quick_success_never_claims_content_or_physical_sanitization");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).readonly = true;
        engine::control control;
        std::vector<quick::progress> progress;
        const auto report = execute(base, host, control, [&](const auto& update)
        {
            progress.push_back(update);
        });
        results.check(report && report->status == "completed" &&
            event_index(host, "remove:" + second.path) < event_index(host, "recover:" + first.path),
            "all_first_pass_work_precedes_access_recovery");
        results.check(host.records.at(first.path).attempts == 2 && host.queries == 0,
            "readonly_recovery_needs_no_lock_query");
        results.check(progress.back().stage == "recovery" && progress.back().attempted == 2 &&
            progress.back().completed == 2 && progress.back().failed == 0,
            "progress_counts_unique_targets_not_retries");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).locked = true;
        host.records.at(first.path).processes = {{10, 20, "fixture.exe", true, {}}};
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && report->status == "completed" && host.queries == 1 && host.closes == 1,
            "failed_lock_released_only_in_final_phase");
        results.check(event_index(host, "remove:" + second.path) < event_index(host, "query:" + first.path) &&
            event_index(host, "recover:" + first.path) < event_index(host, "query:" + first.path),
            "lock_detection_occurs_after_first_pass_and_access_retry");
        results.check(!host.force_seen && host.records.at(first.path).attempts == 3,
            "normal_close_only_with_bounded_three_attempts");
    }
    {
        test_backend host;
        host.add(base);
        host.fail_close = true;
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.locked = true;
            value.processes = {{10, 20, "fixture.exe", true, {}}};
        }
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && report->status == "partial_failure" && host.closes == 1 && host.queries == 2,
            "same_pid_creation_deduplicated_across_failed_paths");
        results.check(!host.force_seen && host.records.at(first.path).attempts == 3 &&
            host.records.at(second.path).attempts == 3, "failed_close_does_not_trigger_unbounded_retry");
    }
    {
        test_backend host;
        host.add(base);
        host.fail_close = true;
        host.records.at(first.path).locked = true;
        host.records.at(first.path).processes = {{10, 20, "fixture.exe", true, {}},
            {10, 21, "new.exe", true, {}}, {11, 20, "protected.exe", false, "protected"},
            {0, 1, "invalid.exe", true, {}}, {12, 0, "unknown.exe", true, {}}};
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && host.closes == 2 && !host.force_seen,
            "process_creation_distinguishes_pid_reuse_and_ineligible_skipped");
    }
    {
        test_backend host;
        host.add(base);
        host.fail_close = true;
        host.close_device_fault = true;
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.locked = true;
            value.processes = {{10, 20, "fixture.exe", true, {}},
                {11, 20, "other.exe", true, {}}};
        }
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && report->status == "partial_failure" && host.closes == 1 &&
            host.queries == 1 && host.records.at(first.path).attempts == 2 &&
            host.records.at(second.path).attempts == 1,
            "device_fault_during_close_stops_remaining_processes_and_retries");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).locked = true;
        host.records.at(first.path).processes.resize(257);
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && report->targets.front().code == "quick_lock_query_limit" &&
            host.closes == 0 && host.records.at(first.path).attempts == 2,
            "oversized_lock_list_rejected_without_actions");
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 5; ++index)
        {
            targets.push_back(make_target("/close_limit/" + std::to_string(index)));
        }
        const auto plan = frozen(std::move(targets));
        test_backend host;
        host.add(plan);
        host.fail_close = true;
        std::uint32_t next_process = 1;
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.locked = true;
            for (unsigned index = 0; index < 256; ++index)
            {
                value.processes.push_back({next_process++, 20, "fixture.exe", true, {}});
            }
        }
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report && report->status == "partial_failure" && host.closes == 1024 &&
            !host.force_seen, "global_normal_close_limit_enforced");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).locked = true;
        host.fail_query = true;
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && report->targets.front().code == "test_query_failed" &&
            host.closes == 0 && host.records.at(first.path).attempts == 2,
            "failed_lock_query_retains_failure");
    }
    {
        for (const auto& error : std::vector<engine::error>{{"quick_protected_resource_tree", 5, false},
            {"quick_frozen_identity_changed", 5, false}, {"quick_target_open_failed", 5, true},
            {"quick_deletion_not_observed_may_be_pending", 5, false}, {"unknown_error", 32, false}})
        {
            test_backend host;
            host.add(base);
            host.records.at(first.path).errors = {error};
            engine::control control;
            const auto report = execute(base, host, control);
            results.check(report && report->status == "partial_failure" &&
                host.records.at(first.path).attempts == 1 && host.queries == 0,
                "nonrecoverable_" + error.code + (error.device_fault ? "_device" : ""));
        }
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).target.identity = "replacement";
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(report && !report->targets.front().deleted && report->targets.back().deleted &&
            host.records.at(first.path).attempts == 1, "replaced_namespace_never_deleted_or_recovered");
    }
    {
        const auto plan = frozen({make_target("/tree", true), make_target("/tree/sub", true),
            make_target("/tree/sub/file"), make_target("/tree/other")});
        test_backend host;
        host.add(plan);
        host.records.at("/tree/sub/file").readonly = true;
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report && report->status == "completed" &&
            event_index(host, "remove:/tree/sub/file") < event_index(host, "remove:/tree/sub") &&
            event_index(host, "remove:/tree/sub") < event_index(host, "remove:/tree"),
            "files_then_child_first_directories");
        results.check(event_index(host, "remove:/tree") < event_index(host, "recover:/tree/sub/file") &&
            event_index(host, "recover:/tree/sub/file") < event_index(host, "recover:/tree/sub") &&
            event_index(host, "recover:/tree/sub") < event_index(host, "recover:/tree"),
            "deferred_children_recovered_before_failed_parents");
    }
    {
        const auto plan = frozen({make_target("/tree", true)});
        test_backend host;
        host.add(plan);
        record late;
        late.target = make_target("/tree/new_after_freeze");
        host.records.emplace(late.target.path, std::move(late));
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report && report->status == "partial_failure" && host.queries == 0 &&
            host.records.at("/tree/new_after_freeze").attempts == 0,
            "new_directory_child_not_enumerated_or_deleted");
    }
    for (const auto request : {engine::control_request::pause, engine::control_request::cancel})
    {
        test_backend host;
        host.add(base);
        engine::control control;
        const auto report = execute(base, host, control, [&](const auto& update)
        {
            if (update.completed == 1)
            {
                control.request.store(request);
            }
        }, nullptr, {1, true});
        results.check(report && report->targets.front().deleted &&
            report->targets.back().code == "quick_not_attempted" &&
            report->status == (request == engine::control_request::pause ? "paused" : "cancelled_partial"),
            request == engine::control_request::pause ? "pause_stops_new_work" : "cancel_stops_new_work");
        control.request.store(engine::control_request::proceed);
        const auto resumed = execute(base, host, control, {}, &*report);
        results.check(resumed && resumed->status == "completed" &&
            host.records.at(first.path).attempts == 1 && host.records.at(second.path).attempts == 1,
            request == engine::control_request::pause ? "pause_resume_skips_proven_completed" :
                "cancel_retry_skips_proven_completed");
    }
    {
        test_backend host;
        host.add(base);
        engine::control control;
        control.request.store(engine::control_request::cancel);
        const auto report = execute(base, host, control);
        results.check(report && host.events.empty() && report->status == "cancelled_partial",
            "preexisting_cancel_performs_no_target_work");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).readonly = true;
        engine::control control;
        const auto report = execute(base, host, control, [&](const auto& update)
        {
            if (update.stage == "recovery")
            {
                control.request.store(engine::control_request::cancel);
            }
        });
        results.check(report && report->status == "cancelled_partial" && host.queries == 0 &&
            host.records.at(first.path).attempts == 1, "cancel_before_recovery_prevents_remediation");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).readonly = true;
        engine::control control;
        const auto report = execute(base, host, control, {}, nullptr, {4, false});
        results.check(report && report->status == "partial_failure" &&
            std::none_of(host.events.begin(), host.events.end(), [](const auto& event)
            {
                return event.starts_with("recover:");
            }), "disabled_access_recovery_never_requests_privilege_repair");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).errors = {{"critical_quick_thread_token_restore_failed", 5, false}};
        engine::control control;
        const auto report = execute(base, host, control, {}, nullptr, {1, true});
        results.check(report && report->status == "partial_failure" &&
            host.records.at(second.path).attempts == 0 && host.queries == 0,
            "critical_privilege_restore_failure_stops_all_new_work");
    }
    {
        const auto plan = frozen({make_target("/fault/a", false, "volume:bad"),
            make_target("/fault/b", false, "volume:bad"),
            make_target("/healthy/c", false, "volume:good"),
            make_target("/fault", true, "volume:bad")});
        test_backend host;
        host.add(plan);
        host.records.at("/fault/a").errors = {{"quick_target_open_failed", 1117, true}};
        engine::control control;
        const auto report = execute(plan, host, control, {}, nullptr, {1, true});
        results.check(report && report->status == "partial_failure" &&
            host.records.at("/fault/b").attempts == 0 && host.records.at("/fault").attempts == 0 &&
            host.records.at("/healthy/c").deleted, "device_fault_stops_only_that_volume");
        results.check(report && report->targets[1].code == "quick_device_stopped" && host.queries == 0,
            "device_skips_are_explicit_and_never_recovered");
    }
    {
        test_backend host;
        host.add(base);
        host.records.at(first.path).errors = {{"critical_quick_readonly_restore_failed", 5, false}};
        engine::control control;
        const auto report = execute(base, host, control, {}, nullptr, {1, true});
        results.check(report && report->status == "partial_failure" &&
            host.records.at(second.path).attempts == 0 && host.queries == 0,
            "critical_readonly_restore_failure_stops_all_new_work");
    }
    {
        test_backend host;
        host.add(base);
        engine::control control;
        const auto report = execute(base, host, control).value();
        const auto original_events = host.events.size();
        for (unsigned change = 0; change < 10; ++change)
        {
            auto previous = report;
            switch (change)
            {
            case 0:
            {
                previous.job_id[0] = 'f';
                break;
            }
            case 1:
            {
                previous.plan_fingerprint[0] = previous.plan_fingerprint[0] == 'f' ? '0' : 'f';
                break;
            }
            case 2:
            {
                previous.targets.pop_back();
                break;
            }
            case 3:
            {
                previous.targets.back().identity = previous.targets.front().identity;
                break;
            }
            case 4:
            {
                previous.targets.front().code = "unrecognized_success";
                break;
            }
            case 5:
            {
                previous.targets.front().deleted = false;
                break;
            }
            case 6:
            {
                previous.targets.front().logical_overwrite_verified = true;
                break;
            }
            case 7:
            {
                previous.targets.front().physical_sanitization_guaranteed = true;
                break;
            }
            case 8:
            {
                previous.targets.front().written_bytes = 1;
                break;
            }
            default:
            {
                previous.status = "unknown";
                break;
            }
            }
            results.check(!execute(base, host, control, {}, &previous) && host.events.size() == original_events,
                "invalid_previous_report_" + std::to_string(change));
        }
        const auto repeat = execute(base, host, control, {}, &report);
        results.check(repeat && repeat->status == "completed" && host.events.size() == original_events,
            "completed_same_plan_is_not_deleted_twice");
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 128; ++index)
        {
            targets.push_back(make_target("/parallel/" + std::to_string(index), false,
                "volume:single"));
        }
        const auto plan = frozen(std::move(targets));
        test_backend host;
        host.add(plan);
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.delay = true;
        }
        engine::control control;
        std::atomic<unsigned> observer_active{};
        std::atomic<bool> observer_overlap{};
        const auto report = execute(plan, host, control, [&](const auto&)
        {
            if (observer_active.fetch_add(1) != 0)
            {
                observer_overlap.store(true);
            }
            std::this_thread::yield();
            observer_active.fetch_sub(1);
        });
        results.check(report && report->status == "completed" && host.maximum_active <= 4 &&
            host.maximum_active > 1, "parallel_workers_bounded_by_live_cpu_budget");
        results.check(host.maximum_device_active > 1 && host.maximum_device_active <= 4,
            "independent_names_on_one_volume_run_concurrently");
        results.check(!observer_overlap.load(), "parallel_progress_callbacks_serialized");
    }
    {
        const auto sealed = quick::freeze_admitted(base.job_id, {second, first});
        results.check(sealed && sealed->get().fingerprint == base.fingerprint,
            "sealed_plan_canonicalizes_once");
        test_backend host;
        host.add(base);
        engine::control control;
        const auto report = quick::run(*sealed, base.fingerprint, true, host, control);
        results.check(report && report->status == "completed" && host.finishes == 1,
            "sealed_plan_executes_and_releases_backend_session");
        auto changed = base;
        changed.targets.front().identity = "changed";
        results.check(!quick::admit(std::move(changed)), "mutable_import_cannot_create_invalid_sealed_plan");
    }
    {
        const auto plan = frozen({make_target("/a", true), make_target("/a/file"), make_target("/z/unrelated")});
        test_backend host;
        host.add(plan);
        engine::control control;
        const auto report = execute(plan, host, control, {}, nullptr, {1, true, false});
        results.check(report && report->status == "completed" &&
            event_index(host, "remove:/a/file") < event_index(host, "remove:/a") &&
            event_index(host, "remove:/a") < event_index(host, "remove:/z/unrelated"),
            "ready_directory_precedes_unrelated_pending_files");
    }
    {
        for (const auto& constrained : {std::string("memory"), std::string("commit"), std::string("handles")})
        {
            test_backend host;
            host.add(base);
            host.resource_adjustment = [&](auto& sample, auto)
            {
                if (constrained == "memory")
                {
                    sample.available_memory_bytes = 1024;
                }
                else if (constrained == "commit")
                {
                    sample.available_commit_bytes = 1024;
                }
                else
                {
                    sample.available_handles = 1;
                }
            };
            engine::control control;
            const auto report = execute(base, host, control);
            results.check(!report && host.events.empty() && host.finishes == 1,
                "complete_admission_refused_before_mutation_" + constrained);
        }
        test_backend host;
        host.add(base);
        engine::control control;
        const auto report = execute(base, host, control, {}, nullptr, {0, true, true, 1024});
        results.check(!report && report.error().code == "quick_complete_plan_memory_insufficient" &&
            host.events.empty(), "explicit_memory_ceiling_is_enforced_before_mutation");
    }
    {
        test_backend host;
        host.add(base);
        host.resource_adjustment = [](auto& sample, auto)
        {
            sample.devices.clear();
        };
        engine::control control;
        const auto report = execute(base, host, control);
        results.check(!report && report.error().code == "quick_resource_device_coverage_invalid" &&
            host.events.empty(), "missing_device_budget_refuses_complete_batch");
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 40; ++index)
        {
            targets.push_back(make_target("/workers/" + std::to_string(index), false,
                "volume:" + std::to_string(index)));
        }
        const auto plan = frozen(std::move(targets));
        test_backend host;
        host.add(plan);
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.delay = true;
            value.delay_milliseconds = 25;
        }
        host.resource_adjustment = [](auto& sample, auto)
        {
            sample.logical_processors = 32;
        };
        engine::control control;
        const auto report = execute(plan, host, control, {}, nullptr, {24, true});
        results.check(report && report->status == "completed" && host.maximum_active > 16 &&
            host.maximum_active <= 24, "resource_budget_can_admit_more_than_sixteen_workers");
    }
    {
        const auto plan = frozen({make_target("/one/a", false, "volume:1"),
            make_target("/two/a", false, "volume:2"), make_target("/one/b", false, "volume:1"),
            make_target("/two/b", false, "volume:2")});
        test_backend host;
        host.add(plan);
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.delay = true;
        }
        host.resource_adjustment = [](auto& sample, auto)
        {
            for (auto& device : sample.devices)
            {
                device.scheduling_group = "shared_physical_disk";
                device.concurrency_hint = 1;
            }
        };
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report && report->status == "completed" && host.maximum_active == 1,
            "partitions_on_shared_physical_disk_share_initial_budget");
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 160; ++index)
        {
            targets.push_back(make_target("/pressure/" + std::to_string(index)));
        }
        const auto plan = frozen(std::move(targets));
        test_backend host;
        host.add(plan);
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.delay = true;
        }
        host.resource_adjustment = [](auto& sample, auto sample_number)
        {
            if (sample_number > 1)
            {
                sample.available_commit_bytes = 1024;
            }
        };
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report && report->status == "partial_failure" && host.resource_samples >= 2 &&
            std::any_of(report->targets.begin(), report->targets.end(), [](const auto& outcome)
            {
                return outcome.deleted;
            }) && std::any_of(report->targets.begin(), report->targets.end(), [](const auto& outcome)
            {
                return outcome.code == "quick_not_attempted" && !outcome.deleted;
            }) && report->stopping_error.code == "quick_complete_plan_memory_insufficient",
            "midrun_resource_loss_stops_new_work_with_partial_evidence");
        results.check(host.finishes == 1 && host.queries == 0,
            "resource_stop_releases_backend_and_never_enters_recovery");
    }
    {
        test_backend host;
        host.add(base);
        host.resource_adjustment = [](auto& sample, auto)
        {
            sample.cpu_pressure_known = false;
        };
        engine::control control;
        std::size_t observed_limit = 0;
        const auto report = execute(base, host, control, [&](const auto& progress)
        {
            observed_limit = progress.worker_limit;
        });
        results.check(report && observed_limit == 1, "unknown_cpu_pressure_uses_conservative_single_worker");
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 128; ++index)
        {
            targets.push_back(make_target("/feedback/" + std::to_string(index)));
        }
        const auto plan = frozen(std::move(targets));
        for (const bool flat_throughput : {false, true})
        {
            test_backend host;
            host.add(plan);
            host.contention_penalty = !flat_throughput;
            host.flat_throughput_penalty = flat_throughput;
            for (auto& [path, value] : host.records)
            {
                static_cast<void>(path);
                value.delay = true;
                value.delay_milliseconds = 4;
            }
            host.resource_adjustment = [](auto& sample, auto)
            {
                for (auto& device : sample.devices)
                {
                    device.concurrency_hint = 1;
                }
            };
            engine::control control;
            quick::progress final_progress;
            const auto report = execute(plan, host, control, [&](const auto& update)
            {
                final_progress = update;
            });
            results.check(report && report->status == "completed" && final_progress.concurrency_increases > 0,
                "stable_success_windows_probe_above_initial_device_hint");
            results.check(final_progress.concurrency_decreases > 0 && host.maximum_active <= 4,
                flat_throughput ? "flat_throughput_rejects_unprofitable_extra_concurrency" :
                    "contention_without_throughput_gain_rolls_back_with_hysteresis");
        }
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 128; ++index)
        {
            targets.push_back(make_target("/cpu_pressure/" + std::to_string(index)));
        }
        const auto plan = frozen(std::move(targets));
        for (const bool topology_change : {false, true})
        {
            test_backend host;
            host.add(plan);
            for (auto& [path, value] : host.records)
            {
                static_cast<void>(path);
                value.delay = true;
                value.delay_milliseconds = 4;
            }
            host.resource_adjustment = [&](auto& sample, auto number)
            {
                if (number >= 2)
                {
                    if (topology_change)
                    {
                        sample.devices.front().scheduling_group = "replacement_group";
                    }
                    else
                    {
                        sample.cpu_pressure = 95;
                    }
                }
            };
            engine::control control;
            quick::progress final_progress;
            const auto report = execute(plan, host, control, [&](const auto& update)
            {
                final_progress = update;
            });
            results.check(report && host.resource_samples >= 2 &&
                (topology_change ? report->status == "partial_failure" &&
                    std::any_of(report->targets.begin(), report->targets.end(), [](const auto& outcome)
                    {
                        return outcome.code == "quick_not_attempted";
                    }) && report->stopping_error.code == "quick_resource_topology_changed" :
                    report->status == "completed" && final_progress.worker_limit == 1),
                topology_change ? "changed_device_group_stops_without_recovery" :
                    "live_cpu_pressure_reduces_global_admission_to_one");
        }
    }
    {
        test_backend host;
        host.add(base);
        engine::control control;
        const auto report = execute(base, host, control, [](const auto& update)
        {
            if (update.completed != 0)
            {
                throw std::runtime_error("fixture_observer_failure");
            }
        }, nullptr, {1, true});
        results.check(report && report->status == "partial_failure" &&
            report->targets.front().deleted && report->targets.back().code == "quick_not_attempted" &&
            report->stopping_error.code == "quick_progress_observer_failed" && host.finishes == 1,
            "observer_exception_preserves_partial_outcomes_and_stops_new_work");
    }
    {
        std::vector<quick::target> targets;
        for (std::size_t index = 0; index < 128; ++index)
        {
            targets.push_back(make_target("/warming_cpu_probe/" + std::to_string(index)));
        }
        const auto plan = frozen(std::move(targets));
        test_backend host;
        host.add(plan);
        for (auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            value.delay = true;
            value.delay_milliseconds = 4;
        }
        host.resource_adjustment = [](auto& sample, auto number)
        {
            sample.cpu_pressure_known = number > 1;
        };
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report && report->status == "completed" && host.resource_samples >= 2 &&
            host.maximum_first_sample_active == 1 && host.maximum_active > 1 && host.maximum_active <= 4,
            "unknown_then_known_cpu_can_expand_within_pre_admitted_pool_capacity");
    }
    std::cout << "{\"summary\":true,\"suite\":\"quick_delete\",\"total\":" << results.total <<
        ",\"passed\":" << results.passed << ",\"failed\":" << results.total - results.passed << "}\n";
    return results.total == results.passed ? 0 : 1;
}
