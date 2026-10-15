module secure_erase.engine;

import std;
import secure_erase.crypto;
import secure_erase.platform;
import secure_erase.plan;
import :admission;
import :execution;

namespace secure_erase::engine
{
using detail::estimate_memory;
using detail::execution;
using detail::failure;
using detail::secret_cleanup;
using detail::structural_match;
using detail::valid_hex;

result<run_report> run(const frozen_plan& plan, const approval& consent, platform& host,
    checkpoint_store& store, event_sink& events, control& controls,
    options settings, const checkpoint* resume)
{
    if (!host.is_elevated())
    {
        return std::unexpected(failure("administrative_token_required"));
    }
    if (settings.chunk_bytes < 65536 || settings.chunk_bytes > 8 * 1024 * 1024 ||
        settings.max_device_workers == 0 || settings.max_device_workers > 16 ||
        settings.ssd_queue_depth == 0 || settings.ssd_queue_depth > 4 ||
        settings.memory_budget_bytes < 2 * settings.chunk_bytes ||
        (settings.io_budget_bytes_per_second != 0 && settings.io_budget_bytes_per_second < 1024))
    {
        return std::unexpected(failure("invalid_resource_budget"));
    }
    const auto memory = estimate_memory(plan, settings.chunk_bytes);
    if (!memory || memory->fixed > settings.memory_budget_bytes ||
        memory->per_worker > settings.memory_budget_bytes - memory->fixed)
    {
        return std::unexpected(failure("manifest_and_io_memory_budget_exceeded"));
    }
    settings.max_device_workers = std::min(settings.max_device_workers,
        (settings.memory_budget_bytes - memory->fixed) / memory->per_worker);
    {
        const auto validated = freeze(plan.job_id, plan.targets);
        if (!validated || validated->fingerprint != plan.fingerprint ||
            !valid_hex(plan.fingerprint, 64) || fingerprint(plan) != plan.fingerprint)
        {
            return std::unexpected(failure("invalid_or_mutated_frozen_plan"));
        }
    }
    if (!consent.execute || consent.plan_fingerprint != plan.fingerprint)
    {
        return std::unexpected(failure("exact_plan_confirmation_required"));
    }
    const auto initialized = host.begin_execution();
    if (!initialized)
    {
        return std::unexpected(initialized.error());
    }
    checkpoint state;
    if (resume != nullptr)
    {
        if (resume->schema_version != 1 || resume->plan.fingerprint != plan.fingerprint ||
            fingerprint(resume->plan) != plan.fingerprint || resume->targets.size() != plan.targets.size())
        {
            return std::unexpected(failure("checkpoint_plan_binding_invalid"));
        }
        state = *resume;
        for (std::size_t index = 0; index < state.targets.size(); ++index)
        {
            const auto& progress = state.targets.at(index);
            const auto& target = plan.targets.at(index);
            if (progress.identity != target.identity ||
                !structural_match(target, progress.observed, false) ||
                progress.stream_index > target.streams.size() ||
                static_cast<unsigned>(progress.state) > static_cast<unsigned>(target_state::skipped) ||
                (progress.stream_index == target.streams.size() && progress.offset != 0) ||
                (progress.stream_index < target.streams.size() &&
                 progress.offset > target.streams.at(progress.stream_index).size) ||
                (progress.state != target_state::pending && progress.state != target_state::completed &&
                 target.support != capability::delete_only && !progress.key_ready))
            {
                secret_cleanup cleanup{state};
                return std::unexpected(failure("checkpoint_target_binding_invalid"));
            }
        }
    }
    else
    {
        state.plan = plan;
        for (const auto& target : plan.targets)
        {
            target_checkpoint progress;
            progress.identity = target.identity;
            progress.observed = target;
            state.targets.push_back(std::move(progress));
        }
    }
    secret_cleanup cleanup{state};
    const auto saved = store.save(state);
    if (!saved)
    {
        return std::unexpected(saved.error());
    }
    const auto started = events.emit({"job_started", plan.job_id, {}, 0, 0, 0});
    if (!started)
    {
        return std::unexpected(started.error());
    }
    execution work(plan, consent, host, store, events, controls, settings, state);
    auto report = work.perform();
    const auto finalized = events.emit({"job_" + report.status, plan.job_id, {}, 0, 0, 0});
    if (!finalized)
    {
        report.status = "audit_finalization_failed";
        return report;
    }
    if (report.status == "completed")
    {
        const auto removed = store.remove(plan.job_id);
        if (!removed)
        {
            report.status = "checkpoint_cleanup_failed";
        }
    }
    return report;
}
}
