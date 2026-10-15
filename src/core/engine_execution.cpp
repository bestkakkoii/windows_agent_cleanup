module secure_erase.engine:execution;

import std;
import secure_erase.crypto;
import secure_erase.platform;
import secure_erase.plan;
import :admission;

namespace secure_erase::engine::detail
{
using clock_type = std::chrono::steady_clock;

[[nodiscard]] std::uint64_t stream_total(const target_snapshot& target)
{
    std::uint64_t total = 0;
    for (const auto& stream : target.streams)
    {
        total += stream.size; // INVARIANT: freeze checked the complete sum.
    }
    return total;
}

[[nodiscard]] std::uint64_t preceding_bytes(const target_snapshot& target, std::size_t index)
{
    std::uint64_t total = 0;
    for (std::size_t position = 0; position < index; ++position)
    {
        total += target.streams.at(position).size;
    }
    return total;
}

struct target_cleanup
{
    target_checkpoint& value;
    ~target_cleanup()
    {
        crypto::secure_zero(value.key);
        crypto::secure_zero(value.nonce);
    }
};

struct buffer_cleanup
{
    std::vector<std::byte>& first;
    std::vector<std::byte>& second;
    ~buffer_cleanup()
    {
        crypto::secure_zero(first);
        crypto::secure_zero(second);
    }
};

struct device_queue
{
    std::string key;
    std::vector<std::size_t> indices;
    std::size_t next{};
    std::size_t active{};
    std::size_t limit{1};
    bool faulted{};
};

class execution
{
public:
    execution(const frozen_plan& plan, const approval& consent, platform& host,
        checkpoint_store& store, event_sink& events, control& controls,
        options settings, checkpoint& state)
        : plan_(plan), consent_(consent), host_(host), store_(store), events_(events),
          controls_(controls), settings_(settings), state_(state), results_(plan.targets.size()),
          terminal_reported_(plan.targets.size(), 0)
    {
        for (std::size_t index = 0; index < plan.targets.size(); ++index)
        {
            results_.at(index).identity = plan.targets.at(index).identity;
        }
    }

    [[nodiscard]] run_report perform()
    {
        std::vector<std::size_t> directories;
        for (std::size_t index = 0; index < plan_.targets.size(); ++index)
        {
            const auto& target = plan_.targets.at(index);
            if (target.directory)
            {
                directories.push_back(index);
                continue;
            }
            auto position = std::find_if(devices_.begin(), devices_.end(), [&](const auto& device)
            {
                return device.key == target.device_key;
            });
            if (position == devices_.end())
            {
                const std::size_t limit = target.media == media_kind::ssd ?
                    settings_.ssd_queue_depth : 1;
                devices_.push_back({target.device_key, {index}, 0, 0, limit, false});
            }
            else
            {
                position->indices.push_back(index);
            }
        }
        // CONTRACT: bounded workers, HDD/USB depth one; SSD depth is explicitly capped.
        std::vector<std::jthread> workers;
        const std::size_t count = std::min(settings_.max_device_workers, plan_.targets.size());
        for (std::size_t index = 0; index < count; ++index)
        {
            workers.emplace_back([this]()
            {
                worker();
            });
        }
        workers.clear(); // jthread destruction joins before directory removal begins.
        for (const auto index : directories)
        {
            bool device_faulted = false;
            {
                const std::scoped_lock lock(mutex_);
                for (const auto& device : devices_)
                {
                    if (device.key == plan_.targets.at(index).device_key && device.faulted)
                    {
                        device_faulted = true;
                    }
                }
            }
            if (device_faulted)
            {
                results_.at(index).code = "device_blocked_after_fault";
                continue;
            }
            bool fault = false;
            process(index, fault);
            terminal(index);
        }
        for (std::size_t index = 0; index < results_.size(); ++index)
        {
            if (terminal_reported_.at(index) == 0)
            {
                terminal(index);
            }
        }
        run_report report{plan_.job_id, "completed", std::move(results_)};
        if (controls_.request.load() == control_request::pause)
        {
            report.status = "paused";
        }
        else if (controls_.request.load() == control_request::cancel)
        {
            report.status = "cancelled_partial";
        }
        else if (std::any_of(report.targets.begin(), report.targets.end(), [](const auto& target)
        {
            return !target.deleted || (target.code != "deleted_logical_overwrite_verified_residual_risk" &&
                target.code != "deleted_only_residual_risk" &&
                target.code != "completed_from_authenticated_checkpoint");
        }))
        {
            report.status = "partial_failure";
        }
        return report;
    }

private:
    void worker()
    {
        while (true)
        {
            std::optional<std::pair<std::size_t, std::size_t>> claimed;
            bool unfinished = false;
            const auto pressure = host_.resource_pressure();
            {
                const std::scoped_lock lock(mutex_);
                const auto active = std::accumulate(devices_.begin(), devices_.end(), std::size_t{},
                    [](std::size_t sum, const device_queue& device)
                    {
                        return sum + device.active;
                    });
                const std::size_t load_limit = pressure >= 90 ? 1 :
                    pressure >= 75 ? std::max<std::size_t>(1, settings_.max_device_workers / 2) :
                    settings_.max_device_workers;
                for (std::size_t index = 0; index < devices_.size(); ++index)
                {
                    auto& device = devices_.at(index);
                    if (device.next >= device.indices.size())
                    {
                        unfinished = unfinished || device.active != 0;
                        continue;
                    }
                    unfinished = true;
                    if (device.faulted || halted_.load() ||
                        controls_.request.load() != control_request::proceed)
                    {
                        for (; device.next < device.indices.size(); ++device.next)
                        {
                            results_.at(device.indices.at(device.next)).code = device.faulted ?
                                "device_blocked_after_fault" : "job_interrupted_before_target";
                        }
                        continue;
                    }
                    if (device.active < device.limit && active < load_limit)
                    {
                        claimed = std::pair(index, device.indices.at(device.next));
                        ++device.next;
                        ++device.active;
                        break;
                    }
                }
            }
            if (!claimed)
            {
                if (!unfinished)
                {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            bool device_faulted = false;
            process(claimed->second, device_faulted);
            terminal(claimed->second);
            {
                const std::scoped_lock lock(mutex_);
                auto& device = devices_.at(claimed->first);
                --device.active;
                device.faulted = device.faulted || device_faulted;
            }
        }
    }

    void terminal(std::size_t index)
    {
        auto& outcome = results_.at(index);
        const bool success = outcome.deleted &&
            (outcome.code == "deleted_logical_overwrite_verified_residual_risk" ||
             outcome.code == "deleted_only_residual_risk" ||
             outcome.code == "completed_from_authenticated_checkpoint");
        const auto logged = emit(success ? "target_result_completed" : "target_result_failed",
            plan_.targets.at(index), outcome.written_bytes, outcome.native_code);
        terminal_reported_.at(index) = 1;
        if (!logged)
        {
            outcome.code = "target_result_audit_failed";
        }
    }

    [[nodiscard]] result<void> emit(std::string code, const target_snapshot& target,
        std::uint64_t done = 0, std::uint32_t native_code = 0)
    {
        const std::scoped_lock lock(mutex_);
        const auto saved = events_.emit({std::move(code), plan_.job_id, target.identity,
            done, stream_total(target), native_code});
        if (!saved)
        {
            halted_.store(true);
        }
        return saved;
    }

    [[nodiscard]] result<void> persist(std::size_t index, const target_checkpoint& value)
    {
        const std::scoped_lock lock(mutex_);
        state_.targets.at(index) = value;
        const auto saved = store_.save(state_);
        if (!saved)
        {
            halted_.store(true);
        }
        return saved;
    }

    [[nodiscard]] bool interrupted() const
    {
        return halted_.load() || controls_.request.load() != control_request::proceed;
    }

    [[nodiscard]] bool interrupted_for(const target_snapshot& target)
    {
        if (interrupted())
        {
            return true;
        }
        const std::scoped_lock lock(mutex_);
        return faulted_devices_.contains(target.device_key);
    }

    void throttle(std::size_t byte_count)
    {
        const auto pressure = host_.resource_pressure();
        if (pressure >= 75 && !interrupted())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(pressure >= 90 ? 10 : 2));
        }
        if (settings_.io_budget_bytes_per_second == 0)
        {
            return;
        }
        // CONTRACT: one global byte budget across devices and both IO phases.
        clock_type::time_point deadline;
        {
            const std::scoped_lock lock(rate_mutex_);
            const auto now = clock_type::now();
            rate_deadline_ = std::max(now, rate_deadline_);
            const long double seconds = static_cast<long double>(byte_count) /
                static_cast<long double>(settings_.io_budget_bytes_per_second);
            const auto duration = std::chrono::duration_cast<clock_type::duration>(
                std::chrono::duration<long double>(seconds));
            // Very low budgets remain interruptible; the target never holds a global lock here.
            rate_deadline_ += duration;
            deadline = rate_deadline_;
        }
        while (!interrupted() && clock_type::now() < deadline)
        {
            const auto remaining = deadline - clock_type::now();
            std::this_thread::sleep_for(std::min(remaining,
                std::chrono::duration_cast<clock_type::duration>(std::chrono::milliseconds(10))));
        }
    }

    [[nodiscard]] result<void> inspect_held(target_handle& handle,
        const target_snapshot& original, target_checkpoint& progress)
    {
        const auto observed = handle.checkpoint_snapshot();
        if (!observed)
        {
            return std::unexpected(observed.error());
        }
        if (!structural_match(original, *observed, false))
        {
            return std::unexpected(failure("target_metadata_changed_while_held"));
        }
        progress.observed = *observed;
        return {};
    }

    [[nodiscard]] result<void> exact_read(target_handle& handle, std::string_view name,
        std::uint64_t offset, std::span<std::byte> destination)
    {
        std::size_t done = 0;
        while (done < destination.size())
        {
            const auto read = handle.read(name, offset + done, destination.subspan(done));
            if (!read)
            {
                return std::unexpected(read.error());
            }
            if (*read == 0 || *read > destination.size() - done)
            {
                return std::unexpected(failure("invalid_or_zero_read_progress"));
            }
            done += *read;
        }
        return {};
    }

    [[nodiscard]] result<void> exact_write(target_handle& handle, std::string_view name,
        std::uint64_t offset, std::span<const std::byte> source, target_outcome& outcome)
    {
        std::size_t done = 0;
        while (done < source.size())
        {
            const auto written = handle.write(name, offset + done, source.subspan(done));
            if (!written)
            {
                return std::unexpected(written.error());
            }
            if (*written == 0 || *written > source.size() - done)
            {
                return std::unexpected(failure("invalid_or_zero_write_progress"));
            }
            done += *written;
            outcome.written_bytes += *written;
        }
        return {};
    }

    [[nodiscard]] result<void> verify_range(target_handle& handle,
        const target_snapshot& target, const target_checkpoint& progress,
        std::size_t stream_index, std::uint64_t length, std::vector<std::byte>& expected,
        std::vector<std::byte>& actual, target_outcome& outcome, bool honor_control)
    {
        const auto& stream = target.streams.at(stream_index);
        for (std::uint64_t offset = 0; offset < length;)
        {
            if (honor_control && interrupted_for(target))
            {
                return std::unexpected(failure("job_interrupted"));
            }
            const auto size = static_cast<std::size_t>(std::min<std::uint64_t>(
                expected.size(), length - offset));
            const auto pattern = std::span(expected).first(size);
            if (!crypto::stream_bytes(progress.key, progress.nonce, stream_index, offset, pattern))
            {
                return std::unexpected(failure("random_stream_range_rejected"));
            }
            const auto read = exact_read(handle, stream.name, offset, std::span(actual).first(size));
            if (!read)
            {
                return read;
            }
            if (!std::equal(pattern.begin(), pattern.end(), actual.begin()))
            {
                return std::unexpected(failure("readback_content_mismatch"));
            }
            outcome.verified_bytes += size;
            offset += size;
            throttle(size);
            const auto notification = emit("verify_progress", target,
                preceding_bytes(target, stream_index) + offset);
            if (!notification)
            {
                return notification;
            }
        }
        return {};
    }

    void process(std::size_t index, bool& device_faulted)
    {
        const auto& original = plan_.targets.at(index);
        auto& outcome = results_.at(index);
        target_checkpoint progress;
        {
            const std::scoped_lock lock(mutex_);
            progress = state_.targets.at(index);
        }
        target_cleanup cleanup{progress};
        auto fail = [&](const error& detail)
        {
            outcome.code = detail.code;
            outcome.native_code = detail.native_code;
            device_faulted = detail.device_fault;
            if (detail.device_fault)
            {
                const std::scoped_lock lock(mutex_);
                faulted_devices_.insert(original.device_key);
                for (auto& device : devices_)
                {
                    if (device.key == original.device_key)
                    {
                        device.faulted = true;
                    }
                }
            }
            // SECURITY: preserve the durable recovery cursor on failure. Failed state does
            // not replace writing/verifying, because a fresh owner-approved resume may retry.
            static_cast<void>(emit(detail.code, original, outcome.written_bytes, detail.native_code));
        };
        if (progress.state == target_state::completed)
        {
            outcome.code = "completed_from_authenticated_checkpoint";
            outcome.deleted = true;
            outcome.logical_overwrite_verified = original.support != capability::delete_only;
            return;
        }
        if (interrupted_for(original))
        {
            outcome.code = "job_interrupted_before_target";
            return;
        }
        if (!original.protection_reasons.empty() || original.remote ||
            original.support == capability::blocked)
        {
            outcome.code = "target_protected_or_unsupported";
            return;
        }
        if ((original.reparse_point || original.link_count > 1 || original.encrypted ||
             original.compressed || original.sparse) && original.support != capability::delete_only)
        {
            outcome.code = "special_target_requires_delete_only_preview";
            return;
        }
        if (needs_downgrade(original) && std::find(consent_.downgrade_identities.begin(),
            consent_.downgrade_identities.end(), original.identity) == consent_.downgrade_identities.end())
        {
            outcome.code = "independent_downgrade_confirmation_required";
            return;
        }
        auto opened = host_.acquire(progress.observed);
        if (!opened)
        {
            fail(opened.error());
            return;
        }
        auto& handle = **opened;
        const auto current = handle.inspect();
        if (!current)
        {
            fail(current.error());
            return;
        }
        if (!structural_match(progress.observed, *current, true) ||
            !structural_match(original, *current, false))
        {
            fail(failure("identity_metadata_or_capability_changed_repreview_required"));
            return;
        }
        progress.observed = *current;
        auto acquired_state = inspect_held(handle, original, progress);
        if (acquired_state)
        {
            acquired_state = persist(index, progress);
        }
        if (!acquired_state)
        {
            fail(acquired_state.error());
            return;
        }
        auto notification = emit("target_started", original);
        if (!notification)
        {
            fail(notification.error());
            return;
        }
        if (original.support == capability::delete_only)
        {
            progress.state = target_state::deleting;
            auto saved = persist(index, progress);
            if (!saved)
            {
                fail(saved.error());
                return;
            }
            if (interrupted_for(original))
            {
                outcome.code = "job_interrupted_before_delete";
                return;
            }
            const auto final_check = inspect_held(handle, original, progress);
            if (!final_check)
            {
                fail(final_check.error());
                return;
            }
        }
        else
        {
            if (!progress.key_ready)
            {
                auto generated = host_.random_bytes(progress.key);
                if (generated)
                {
                    generated = host_.random_bytes(progress.nonce);
                }
                if (!generated)
                {
                    fail(generated.error());
                    return;
                }
                progress.key_ready = true;
                progress.state = target_state::writing;
                const auto settled = inspect_held(handle, original, progress);
                if (!settled)
                {
                    fail(settled.error());
                    return;
                }
                const auto saved = persist(index, progress);
                if (!saved)
                {
                    fail(saved.error());
                    return;
                }
            }
            std::vector<std::byte> expected(settings_.chunk_bytes);
            std::vector<std::byte> actual(settings_.chunk_bytes);
            buffer_cleanup wipe_buffers{expected, actual};
            if ((progress.state == target_state::verified || progress.state == target_state::deleting) &&
                original.trim_supported && original.media != media_kind::hdd)
            {
                // SECURITY: previous native trim may have discarded logical reads. A
                // fresh approved resume re-overwrites fully; it never bypasses readback.
                progress.state = target_state::writing;
                progress.stream_index = 0;
                progress.offset = 0;
                auto restarted = persist(index, progress);
                if (restarted)
                {
                    restarted = emit("resume_rewrite_after_possible_trim", original);
                }
                if (!restarted)
                {
                    fail(restarted.error());
                    return;
                }
            }
            if (progress.state == target_state::writing)
            {
                // SECURITY: authenticate already-written ranges by comparing bytes, not a
                // read-success flag. Bytes beyond the durable cursor are always rewritten.
                for (std::size_t stream_index = 0; stream_index <= progress.stream_index &&
                    stream_index < original.streams.size(); ++stream_index)
                {
                    const auto prefix = stream_index < progress.stream_index ?
                        original.streams.at(stream_index).size : progress.offset;
                    const auto verified = verify_range(handle, original, progress, stream_index,
                        prefix, expected, actual, outcome, true);
                    if (!verified)
                    {
                        fail(verified.error());
                        return;
                    }
                }
                std::size_t adaptive_size = settings_.chunk_bytes;
                for (; progress.stream_index < original.streams.size(); ++progress.stream_index)
                {
                    const auto& stream = original.streams.at(progress.stream_index);
                    while (progress.offset < stream.size)
                    {
                        if (interrupted_for(original))
                        {
                            outcome.code = "job_interrupted";
                            return;
                        }
                        const auto size = static_cast<std::size_t>(std::min<std::uint64_t>(
                            adaptive_size, stream.size - progress.offset));
                        auto bytes = std::span(expected).first(size);
                        if (!crypto::stream_bytes(progress.key, progress.nonce,
                            progress.stream_index, progress.offset, bytes))
                        {
                            fail(failure("random_stream_range_rejected"));
                            return;
                        }
                        const auto start = clock_type::now();
                        auto operation = exact_write(handle, stream.name, progress.offset,
                            bytes, outcome);
                        if (!operation)
                        {
                            fail(operation.error());
                            return;
                        }
                        operation = handle.flush(stream.name);
                        if (!operation)
                        {
                            fail(operation.error());
                            return;
                        }
                        progress.offset += size;
                        operation = inspect_held(handle, original, progress);
                        if (operation)
                        {
                            operation = persist(index, progress);
                        }
                        if (!operation)
                        {
                            fail(operation.error());
                            return;
                        }
                        const auto elapsed = clock_type::now() - start;
                        if (settings_.adaptive_io)
                        {
                            // CONTRACT: latency feedback adjusts transfer size inside an
                            // already-allocated bound; it never weakens verification.
                            if (elapsed > std::chrono::milliseconds(200))
                            {
                                adaptive_size = std::max<std::size_t>(65536, adaptive_size / 2);
                            }
                            else if (elapsed < std::chrono::milliseconds(30))
                            {
                                adaptive_size = std::min(settings_.chunk_bytes, adaptive_size * 2);
                            }
                        }
                        throttle(size);
                        notification = emit("write_progress", original,
                            preceding_bytes(original, progress.stream_index) + progress.offset);
                        if (!notification)
                        {
                            fail(notification.error());
                            return;
                        }
                    }
                    progress.offset = 0;
                }
                progress.state = target_state::verifying;
                progress.stream_index = 0;
                progress.offset = 0;
                const auto saved = persist(index, progress);
                if (!saved)
                {
                    fail(saved.error());
                    return;
                }
            }
            // SECURITY: resume from verified/deleting re-verifies every stream. No cursor
            // or authenticated state can skip the full expected-byte comparison before delete.
            for (std::size_t stream_index = 0; stream_index < original.streams.size(); ++stream_index)
            {
                auto operation = handle.flush(original.streams.at(stream_index).name);
                if (operation)
                {
                    operation = verify_range(handle, original, progress, stream_index,
                        original.streams.at(stream_index).size, expected, actual, outcome, true);
                }
                if (!operation)
                {
                    fail(operation.error());
                    return;
                }
            }
            outcome.logical_overwrite_verified = true;
            auto operation = inspect_held(handle, original, progress);
            if (!operation)
            {
                fail(operation.error());
                return;
            }
            progress.state = target_state::verified;
            operation = persist(index, progress);
            if (!operation)
            {
                fail(operation.error());
                return;
            }
            if (interrupted_for(original))
            {
                outcome.code = "job_interrupted_before_delete";
                return;
            }
            // Native trim is advisory; a failure must be visible without erasing the
            // already-proven distinction between logical overwrite and physical media state.
            if (original.trim_supported && original.media != media_kind::hdd)
            {
                const auto trimmed = handle.trim();
                if (!trimmed)
                {
                    notification = emit("trim_not_completed", original, 0, trimmed.error().native_code);
                    if (!notification)
                    {
                        fail(notification.error());
                        return;
                    }
                    if (trimmed.error().device_fault)
                    {
                        fail(trimmed.error());
                        return;
                    }
                }
            }
            progress.state = target_state::deleting;
            operation = inspect_held(handle, original, progress);
            if (operation)
            {
                operation = persist(index, progress);
            }
            if (!operation)
            {
                fail(operation.error());
                return;
            }
            operation = inspect_held(handle, original, progress);
            if (!operation)
            {
                fail(operation.error());
                return;
            }
        }
        if (interrupted_for(original))
        {
            outcome.code = "job_interrupted_before_delete";
            return;
        }
        const auto removed = handle.remove();
        if (!removed)
        {
            fail(removed.error());
            return;
        }
        outcome.deleted = true;
        outcome.code = original.support == capability::delete_only ?
            "deleted_only_residual_risk" : "deleted_logical_overwrite_verified_residual_risk";
        progress.state = target_state::completed;
        crypto::secure_zero(progress.key);
        crypto::secure_zero(progress.nonce);
        progress.key_ready = false;
        const auto saved = persist(index, progress);
        if (!saved)
        {
            outcome.code = "deleted_checkpoint_finalization_failed";
            outcome.native_code = saved.error().native_code;
            return;
        }
        notification = emit(outcome.code, original, stream_total(original));
        if (!notification)
        {
            outcome.code = "deleted_audit_finalization_failed";
        }
    }

    const frozen_plan& plan_;
    const approval& consent_;
    platform& host_;
    checkpoint_store& store_;
    event_sink& events_;
    control& controls_;
    options settings_;
    checkpoint& state_;
    std::vector<target_outcome> results_;
    std::vector<std::uint8_t> terminal_reported_;
    std::vector<device_queue> devices_;
    std::set<std::string> faulted_devices_;
    std::mutex mutex_;
    std::mutex rate_mutex_;
    clock_type::time_point rate_deadline_{clock_type::now()};
    std::atomic<bool> halted_{};
};
}
