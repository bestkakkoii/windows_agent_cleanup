module secure_erase.quick_delete;

import std;
import secure_erase.crypto;
import secure_erase.platform;

namespace secure_erase::quick
{
namespace
{
[[nodiscard]] engine::error failure(std::string code)
{
    return {std::move(code), 0, false};
}

[[nodiscard]] bool valid_hex(std::string_view value, std::size_t size)
{
    return value.size() == size && std::all_of(value.begin(), value.end(), [](char ch)
    {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

[[nodiscard]] bool valid_utf8(std::string_view value)
{
    for (std::size_t index = 0; index < value.size();)
    {
        const auto first = static_cast<unsigned char>(value[index]);
        if (first == 0)
        {
            return false;
        }
        if (first < 0x80)
        {
            ++index;
            continue;
        }
        const unsigned count = first >= 0xc2 && first <= 0xdf ? 2U :
            first >= 0xe0 && first <= 0xef ? 3U : first >= 0xf0 && first <= 0xf4 ? 4U : 0U;
        if (count == 0 || count > value.size() - index)
        {
            return false;
        }
        std::uint32_t scalar = first & (count == 2 ? 0x1fU : count == 3 ? 0x0fU : 0x07U);
        for (unsigned offset = 1; offset < count; ++offset)
        {
            const auto next = static_cast<unsigned char>(value[index + offset]);
            if ((next & 0xc0U) != 0x80U)
            {
                return false;
            }
            scalar = (scalar << 6) | (next & 0x3fU);
        }
        if ((count == 2 && scalar < 0x80) || (count == 3 && scalar < 0x800) ||
            (count == 4 && scalar < 0x10000) || scalar > 0x10ffff ||
            (scalar >= 0xd800 && scalar <= 0xdfff))
        {
            return false;
        }
        index += count;
    }
    return true;
}

void append_integer(std::vector<std::byte>& bytes, std::uint64_t value)
{
    for (unsigned shift = 0; shift < 64; shift += 8)
    {
        bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_string(std::vector<std::byte>& bytes, std::string_view value)
{
    append_integer(bytes, value.size());
    const auto raw = std::as_bytes(std::span(value.data(), value.size()));
    bytes.insert(bytes.end(), raw.begin(), raw.end());
}

[[nodiscard]] bool same_target(const target& left, const target& right)
{
    return left.path == right.path && left.identity == right.identity &&
        left.device_key == right.device_key && left.creation_time == right.creation_time &&
        left.attributes == right.attributes && left.directory == right.directory &&
        left.preparation_error.code == right.preparation_error.code &&
        left.preparation_error.native_code == right.preparation_error.native_code &&
        left.preparation_error.device_fault == right.preparation_error.device_fault &&
        left.allocated_bytes == right.allocated_bytes;
}

[[nodiscard]] bool accepted(const engine::target_outcome& value)
{
    return value.deleted && value.code == "deleted_quick_namespace_removed" &&
        !value.logical_overwrite_verified && !value.physical_sanitization_guaranteed &&
        value.written_bytes == 0 && value.verified_bytes == 0 && value.native_code == 0;
}

[[nodiscard]] bool recoverable(const engine::error& value)
{
    // SECURITY: Native ACCESS_DENIED alone is insufficient; protection/identity
    // failures may carry the same native value and must never trigger remediation.
    const bool operation = value.code == "quick_target_open_failed" ||
        value.code == "ancestor_pin_failed" ||
        value.code == "quick_disposition_failed" ||
        value.code == "quick_legacy_disposition_failed" ||
        value.code == "quick_readonly_recovery_required";
    return operation && !value.device_fault &&
        (value.native_code == 5 || value.native_code == 32 || value.native_code == 33 ||
         value.native_code == 145);
}

[[nodiscard]] bool lock_failure(const engine::error& value)
{
    return recoverable(value) && value.native_code != 145;
}

[[nodiscard]] engine::result<void> validate_previous(const plan& value,
    const engine::run_report& previous, const std::vector<std::string>& keys)
{
    if (previous.stopping_error.code.size() > 512 || !valid_utf8(previous.stopping_error.code) ||
        (previous.status == "completed" && !previous.stopping_error.code.empty()) ||
        previous.job_id != value.job_id || previous.plan_fingerprint != value.fingerprint ||
        previous.targets.size() != value.targets.size() ||
        (previous.status != "completed" && previous.status != "partial_failure" &&
         previous.status != "paused" && previous.status != "cancelled_partial" &&
         previous.status != "audit_finalization_failed"))
    {
        return std::unexpected(failure("quick_previous_report_binding_invalid"));
    }
    for (std::size_t index = 0; index < keys.size(); ++index)
    {
        const auto& outcome = previous.targets[index];
        if (outcome.identity != keys[index] || outcome.code.empty() ||
            outcome.code.size() > 512 || !valid_utf8(outcome.code) ||
            outcome.logical_overwrite_verified || outcome.physical_sanitization_guaranteed ||
            outcome.written_bytes != 0 || outcome.verified_bytes != 0 ||
            (outcome.deleted && (!accepted(outcome) ||
             !value.targets[index].preparation_error.code.empty())) ||
            (!outcome.deleted && outcome.code == "deleted_quick_namespace_removed") ||
            (previous.status == "completed" && !accepted(outcome)))
        {
            return std::unexpected(failure("quick_previous_target_binding_invalid"));
        }
    }
    return {};
}

[[nodiscard]] bool canonical_less(const target& left, const target& right)
{
    if (left.directory != right.directory)
    {
        return !left.directory;
    }
    if (left.directory && left.path.size() != right.path.size())
    {
        return left.path.size() > right.path.size();
    }
    return left.path < right.path;
}

[[nodiscard]] bool valid_target(const target& value)
{
    const bool bound = !value.identity.empty() && !value.device_key.empty();
    return !value.path.empty() && value.path.size() <= 131072 &&
        value.identity.size() <= 1024 && value.device_key.size() <= 1024 &&
        value.preparation_error.code.size() <= 512 &&
        (bound || !value.preparation_error.code.empty()) &&
        valid_utf8(value.path) && valid_utf8(value.identity) &&
        valid_utf8(value.device_key) && valid_utf8(value.preparation_error.code) &&
        (!value.preparation_error.code.empty() ||
         (value.preparation_error.native_code == 0 && !value.preparation_error.device_fault));
}

[[nodiscard]] bool checked_add(std::uint64_t& value, std::uint64_t amount)
{
    if (amount > std::numeric_limits<std::uint64_t>::max() - value)
    {
        return false;
    }
    value += amount;
    return true;
}

[[nodiscard]] engine::result<admission_estimate> fit_resources(admission_estimate estimate,
    std::size_t target_count, const resource_sample& resources, const options& settings)
{
    if (resources.cpu_pressure > 100 || resources.available_memory_bytes == 0 ||
        resources.available_commit_bytes == 0 || target_count == 0)
    {
        return std::unexpected(failure("quick_resource_sample_invalid"));
    }
    estimate.memory_budget_bytes = std::min(resources.available_memory_bytes,
        resources.available_commit_bytes) / 4;
    if (settings.memory_budget_bytes != 0)
    {
        estimate.memory_budget_bytes = std::min(estimate.memory_budget_bytes, settings.memory_budget_bytes);
    }
    std::uint64_t metadata = estimate.resident_plan_bytes;
    if (!checked_add(metadata, estimate.execution_metadata_bytes) || metadata >= estimate.memory_budget_bytes)
    {
        return std::unexpected(failure("quick_complete_plan_memory_insufficient"));
    }
    const auto memory_workers = (estimate.memory_budget_bytes - metadata) / estimate.worker_bytes;
    if (memory_workers == 0)
    {
        return std::unexpected(failure("quick_worker_memory_insufficient"));
    }
    const auto handle_workers = resources.available_handles / estimate.handles_per_worker;
    if (handle_workers == 0)
    {
        return std::unexpected(failure("quick_handle_headroom_insufficient"));
    }
    const auto processors = std::max<std::size_t>(1, resources.logical_processors);
    const auto processor_workers = processors > std::numeric_limits<std::size_t>::max() / 2 ?
        std::numeric_limits<std::size_t>::max() : processors * 2;
    auto workers = std::min<std::uint64_t>({target_count, memory_workers, handle_workers, processor_workers});
    if (settings.max_workers != 0)
    {
        workers = std::min(workers, static_cast<std::uint64_t>(settings.max_workers));
    }
    estimate.worker_capacity = static_cast<std::size_t>(workers);
    if (!resources.cpu_pressure_known || resources.cpu_pressure >= 90)
    {
        workers = 1;
    }
    else if (resources.cpu_pressure >= 75)
    {
        workers = std::max<std::uint64_t>(1, workers / 2);
    }
    estimate.worker_limit = static_cast<std::size_t>(workers);
    return estimate;
}

[[nodiscard]] engine::result<void> validate_plan(const plan& value)
{
    if ((!valid_hex(value.job_id, 32) && !valid_hex(value.job_id, 64)) ||
        value.targets.empty() || !valid_hex(value.fingerprint, 64) ||
        !std::is_sorted(value.targets.begin(), value.targets.end(), canonical_less))
    {
        return std::unexpected(failure("quick_invalid_or_mutated_plan"));
    }
    std::unordered_set<std::string_view> paths;
    for (const auto& target : value.targets)
    {
        if (!valid_target(target) || !paths.insert(target.path).second)
        {
            return std::unexpected(failure("quick_invalid_or_mutated_plan"));
        }
    }
    if (fingerprint(value) != value.fingerprint)
    {
        return std::unexpected(failure("quick_invalid_or_mutated_plan"));
    }
    return {};
}

[[nodiscard]] engine::result<void> resource_coverage(const resource_sample& resources,
    std::span<const std::string_view> keys)
{
    if (resources.devices.size() != keys.size())
    {
        return std::unexpected(failure("quick_resource_device_coverage_invalid"));
    }
    std::unordered_set<std::string_view> found;
    for (const auto& device : resources.devices)
    {
        if (device.concurrency_hint == 0 || device.io_pressure > 100 ||
            device.device_key.size() > 1024 || device.scheduling_group.size() > 4096 ||
            !valid_utf8(device.device_key) || !valid_utf8(device.scheduling_group) ||
            !found.insert(device.device_key).second ||
            std::find(keys.begin(), keys.end(), device.device_key) == keys.end())
        {
            return std::unexpected(failure("quick_resource_device_coverage_invalid"));
        }
    }
    return {};
}

class execution_scope
{
public:
    explicit execution_scope(backend& host) : host_(host)
    {
    }

    ~execution_scope()
    {
        host_.finish_execution();
    }

    execution_scope(const execution_scope&) = delete;
    execution_scope& operator=(const execution_scope&) = delete;

private:
    backend& host_;
};

struct staged_failure
{
    engine::error error;
};

class execution
{
    struct node
    {
        std::size_t parent{std::numeric_limits<std::size_t>::max()};
        std::size_t remaining{};
        std::size_t group{};
    };

    struct device_state
    {
        std::string key;
        std::vector<std::size_t> ready;
        std::size_t active{};
        std::size_t limit{1};
        std::size_t ceiling{1};
        std::size_t samples{};
        std::uint64_t elapsed_nanoseconds{};
        unsigned stable_windows{};
        unsigned probe_windows{};
        unsigned profitable_windows{};
        unsigned cooldown{};
        unsigned pressure{};
        bool pressure_known{};
        bool probing{};
        double previous_rate{};
        double previous_latency{};
        double baseline_rate{};
        double baseline_latency{};
        std::chrono::steady_clock::time_point window_started{std::chrono::steady_clock::now()};
    };

public:
    execution(const plan& value, backend& host, engine::control& controls,
        const options& settings, progress_observer observer,
        std::vector<std::string> keys, const engine::run_report* previous,
        resource_sample resources, admission_estimate admission)
        : value_(&value), host_(host), controls_(controls), settings_(settings),
          observer_(std::move(observer)), errors_(value.targets.size()),
          attempted_(value.targets.size()), deleted_(value.targets.size()), nodes_(value.targets.size()),
          resources_(std::move(resources)), admission_(admission),
          worker_ceiling_(admission.worker_capacity), worker_limit_(admission.worker_limit),
          target_count_(value.targets.size())
    {
        resource_failure_.reserve(128);
        report_.status.reserve(64);
        progress_.stage.reserve(64);
        report_.stopping_error.code.reserve(512);
        progress_.stopping_error.code.reserve(128);
        report_.job_id = value.job_id;
        report_.plan_fingerprint = value.fingerprint;
        report_.targets.reserve(keys.size());
        progress_.total = keys.size();
        progress_.worker_limit = worker_limit_;
        progress_.memory_budget_bytes = admission.memory_budget_bytes;
        progress_.admitted_metadata_bytes = admission.resident_plan_bytes + admission.execution_metadata_bytes;
        for (std::size_t index = 0; index < keys.size(); ++index)
        {
            engine::target_outcome outcome;
            outcome.identity = std::move(keys[index]);
            outcome.code = "quick_not_attempted";
            if (previous != nullptr && accepted(previous->targets[index]))
            {
                outcome = previous->targets[index];
                attempted_[index] = true;
                deleted_[index] = true;
                ++progress_.attempted;
                ++progress_.completed;
            }
            else if (!value.targets[index].preparation_error.code.empty())
            {
                errors_[index] = value.targets[index].preparation_error;
                outcome.code = errors_[index].code;
                outcome.native_code = errors_[index].native_code;
                attempted_[index] = true;
                ++progress_.attempted;
                ++progress_.failed;
            }
            outcome.code.reserve(512);
            errors_[index].code.reserve(512);
            report_.targets.push_back(std::move(outcome));
        }
        build_dependencies();
    }

    execution(target_source& source, outcome_sink& outcomes, backend& host,
        engine::control& controls, const options& settings, progress_observer observer,
        resource_sample resources, admission_estimate admission)
        : source_(&source), outcomes_(&outcomes), host_(host), controls_(controls),
          settings_(settings), observer_(std::move(observer)),
          attempted_(source.info().target_count), deleted_(source.info().target_count),
          nodes_(source.info().target_count), indexes_(source.info().target_count),
          resources_(std::move(resources)), admission_(admission),
          worker_ceiling_(admission.worker_capacity), worker_limit_(admission.worker_limit),
          target_count_(source.info().target_count)
    {
        resource_failure_.reserve(128);
        report_.status.reserve(64);
        progress_.stage.reserve(64);
        report_.stopping_error.code.reserve(512);
        progress_.stopping_error.code.reserve(128);
        report_.job_id = source.info().job_id;
        report_.plan_fingerprint = source.info().fingerprint;
        progress_.total = target_count_;
        progress_.worker_limit = worker_limit_;
        progress_.memory_budget_bytes = admission.memory_budget_bytes;
        progress_.admitted_metadata_bytes = admission.resident_plan_bytes + admission.execution_metadata_bytes;
        for (std::size_t position = 0; position < target_count_; ++position)
        {
            const auto index = source.index(position);
            if (!index || (index->parent != std::numeric_limits<std::uint64_t>::max() && index->parent >= position) ||
                (index->device_index == std::numeric_limits<std::uint32_t>::max() && !index->preparation_failed) ||
                (index->device_index != std::numeric_limits<std::uint32_t>::max() &&
                 index->device_index >= source.info().device_keys.size()))
            {
                throw staged_failure{index ? failure("quick_staged_index_invalid") : index.error()};
            }
            indexes_[position] = *index;
            if (index->parent != std::numeric_limits<std::uint64_t>::max() &&
                !indexes_[static_cast<std::size_t>(index->parent)].directory)
            {
                throw staged_failure{failure("quick_staged_parent_not_directory")};
            }
            auto outcome = get_outcome(position);
            const auto identity = crypto::hex_digest(index->namespace_digest);
            if (outcome.identity != identity || outcome.code.empty() || outcome.code.size() > 512 ||
                !valid_utf8(outcome.code) || outcome.logical_overwrite_verified ||
                outcome.physical_sanitization_guaranteed || outcome.written_bytes != 0 ||
                outcome.verified_bytes != 0 || (outcome.deleted && !accepted(outcome)) ||
                (!outcome.deleted && outcome.code == "deleted_quick_namespace_removed"))
            {
                throw staged_failure{failure("quick_staged_previous_binding_invalid")};
            }
            if (outcome.deleted)
            {
                if (index->preparation_failed)
                {
                    throw staged_failure{failure("quick_staged_previous_binding_invalid")};
                }
                attempted_[position] = true;
                deleted_[position] = true;
                ++progress_.attempted;
                ++progress_.completed;
            }
            else if (index->preparation_failed)
            {
                auto target = load_target(position);
                outcome.code = target.preparation_error.code;
                outcome.native_code = target.preparation_error.native_code;
                put_outcome(position, outcome);
                attempted_[position] = true;
                ++progress_.attempted;
                ++progress_.failed;
            }
        }
        build_dependencies();
    }

    [[nodiscard]] const progress& final_progress() const noexcept
    {
        return progress_;
    }

    [[nodiscard]] engine::run_report perform()
    {
        publish("first_pass");
        const auto worker = [this]()
        {
            try
            {
                while (true)
                {
                    std::unique_lock lock(mutex_);
                    if (stopped() || settled_ == nodes_.size())
                    {
                        return;
                    }
                    const auto now = std::chrono::steady_clock::now();
                    if (!refreshing_ && now >= next_resource_probe_)
                    {
                        refreshing_ = true;
                        lock.unlock();
                        auto refreshed = host_.inspect_resources(device_keys_);
                        lock.lock();
                        refreshing_ = false;
                        next_resource_probe_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
                        apply_resources(std::move(refreshed));
                        wake_.notify_all();
                        if (stopped())
                        {
                            return;
                        }
                    }
                    const auto selected = select_ready();
                    if (!selected)
                    {
                        wake_.wait_for(lock, std::chrono::milliseconds(20));
                        continue;
                    }
                    const auto index = *selected;
                    const auto group = nodes_[index].group;
                    const bool new_attempt = !attempted_[index];
                    ++active_;
                    ++groups_[group].active;
                    lock.unlock();
                    const auto started = std::chrono::steady_clock::now();
                    if (!attempted_[index] && admit_target(index))
                    {
                        attempt(index, false);
                    }
                    const auto duration = std::chrono::steady_clock::now() - started;
                    lock.lock();
                    --active_;
                    --groups_[group].active;
                    settle(index);
                    if (new_attempt)
                    {
                        feedback(group, index, duration);
                    }
                    wake_.notify_all();
                }
            }
            catch (const staged_failure& error)
            {
                const std::scoped_lock lock(mutex_);
                resource_failure_ = error.error.code.size() < 128 ? error.error.code : "quick_staged_storage_failure";
                resource_native_error_ = error.error.native_code;
                fatal_.store(true);
                wake_.notify_all();
            }
            catch (...)
            {
                const std::scoped_lock lock(mutex_);
                resource_failure_ = "quick_worker_exception_outcome_unknown";
                fatal_.store(true);
                wake_.notify_all();
            }
        };
        if (worker_ceiling_ == 1)
        {
            worker();
        }
        else
        {
            // SECURITY: No worker mutates until the entire resource-admitted pool
            // exists. Thread-creation failure leaves every namespace untouched.
            std::latch started(1);
            std::vector<std::jthread> workers;
            workers.reserve(worker_ceiling_);
            try
            {
                for (std::size_t index = 0; index < worker_ceiling_; ++index)
                {
                    workers.emplace_back([&]()
                    {
                        started.wait();
                        worker();
                    });
                }
            }
            catch (...)
            {
                resource_failure_ = "quick_worker_start_failed";
                fatal_.store(true);
            }
            started.count_down();
        }
        if (!stopped())
        {
            try
            {
                recover();
            }
            catch (...)
            {
                resource_failure_ = "quick_recovery_exception_outcome_unknown";
                fatal_.store(true);
            }
        }
        if (!resource_failure_.empty())
        {
            // SECURITY: Preserve quick_not_attempted provenance. Frontends must
            // never mistake resource-stopped names for first-pass failures eligible
            // for manual process recovery.
            progress_.stopping_error.code.assign(resource_failure_);
            progress_.stopping_error.native_code = resource_native_error_;
            publish("resource_stopped");
        }
        else
        {
            publish(progress_.stage);
        }
        report_.stopping_error.code.assign(resource_failure_);
        report_.stopping_error.native_code = resource_native_error_;
        const auto request = controls_.request.load();
        report_.status = request == engine::control_request::pause ? "paused" :
            request == engine::control_request::cancel ? "cancelled_partial" :
            !fatal_.load() && progress_.completed == progress_.total ? "completed" : "partial_failure";
        return std::move(report_);
    }

private:
    [[nodiscard]] bool is_directory(std::size_t position) const
    {
        return value_ != nullptr ? value_->targets[position].directory : indexes_[position].directory;
    }

    [[nodiscard]] bool preparation_failed(std::size_t position) const
    {
        return value_ != nullptr ? !value_->targets[position].preparation_error.code.empty() :
            indexes_[position].preparation_failed;
    }

    [[nodiscard]] std::string_view device_key(std::size_t position) const
    {
        if (value_ != nullptr)
        {
            return value_->targets[position].device_key;
        }
        const auto device = indexes_[position].device_index;
        return device == std::numeric_limits<std::uint32_t>::max() ? std::string_view{} :
            std::string_view(source_->info().device_keys[device]);
    }

    [[nodiscard]] std::uint64_t allocated_bytes(std::size_t position) const
    {
        return value_ != nullptr ? value_->targets[position].allocated_bytes : indexes_[position].allocated_bytes;
    }

    [[nodiscard]] target load_target(std::size_t position)
    {
        if (value_ != nullptr)
        {
            return value_->targets[position];
        }
        auto loaded = source_->load(position);
        if (!loaded)
        {
            throw staged_failure{loaded.error()};
        }
        const auto& index = indexes_[position];
        const auto depth = static_cast<std::uint64_t>(std::count_if(loaded->path.begin(), loaded->path.end(),
            [](char value)
            {
                return value == '/' || value == '\\';
            }));
        std::uint64_t bytes = sizeof(target);
        if (!checked_add(bytes, loaded->path.size()) || !checked_add(bytes, loaded->identity.size()) ||
            !checked_add(bytes, loaded->device_key.size()) || !checked_add(bytes, loaded->preparation_error.code.size()) ||
            bytes > source_->info().maximum_target_bytes || depth > source_->info().maximum_ancestor_depth ||
            !valid_target(*loaded) ||
            loaded->directory != index.directory || loaded->allocated_bytes != index.allocated_bytes ||
            loaded->device_key != device_key(position) ||
            (!loaded->preparation_error.code.empty()) != index.preparation_failed ||
            target_key(*loaded) != crypto::hex_digest(index.namespace_digest))
        {
            throw staged_failure{failure("quick_staged_target_binding_invalid")};
        }
        return std::move(*loaded);
    }

    [[nodiscard]] engine::target_outcome get_outcome(std::size_t position)
    {
        if (outcomes_ == nullptr)
        {
            return report_.targets[position];
        }
        auto outcome = outcomes_->read(position);
        if (!outcome)
        {
            throw staged_failure{outcome.error()};
        }
        return std::move(*outcome);
    }

    void put_outcome(std::size_t position, const engine::target_outcome& value)
    {
        if (outcomes_ == nullptr)
        {
            report_.targets[position] = value;
            return;
        }
        const auto recorded = outcomes_->record(position, value);
        if (!recorded)
        {
            throw staged_failure{recorded.error()};
        }
    }

    [[nodiscard]] engine::error error_at(std::size_t position)
    {
        if (outcomes_ == nullptr)
        {
            return errors_[position];
        }
        const auto outcome = get_outcome(position);
        return {outcome.code, outcome.native_code, failed_devices_.contains(device_key(position))};
    }

    [[nodiscard]] bool lower_priority(std::size_t left, std::size_t right) const
    {
        if (is_directory(left) != is_directory(right))
        {
            return !is_directory(left);
        }
        if (settings_.space_first && !is_directory(left) && allocated_bytes(left) != allocated_bytes(right))
        {
            return allocated_bytes(left) < allocated_bytes(right);
        }
        return left > right;
    }

    void enqueue(std::size_t index)
    {
        auto& queue = groups_[nodes_[index].group].ready;
        queue.push_back(index);
        std::push_heap(queue.begin(), queue.end(), [this](auto left, auto right)
        {
            return lower_priority(left, right);
        });
    }

    void build_dependencies()
    {
        std::unordered_map<std::string_view, std::size_t> group_index;
        std::unordered_map<std::string_view, std::size_t> volume_index;
        groups_.reserve(resources_.devices.size() + 1);
        for (const auto& device : resources_.devices)
        {
            const auto key = device.scheduling_group.empty() ? std::string_view("unknown") :
                std::string_view(device.scheduling_group);
            auto [found, inserted] = group_index.emplace(key, groups_.size());
            if (inserted)
            {
                device_state group;
                group.key = key;
                group.ceiling = worker_ceiling_;
                group.limit = std::min<std::size_t>({2, worker_limit_, device.concurrency_hint});
                group.pressure = device.io_pressure;
                group.pressure_known = device.io_pressure_known;
                groups_.push_back(std::move(group));
            }
            else
            {
                auto& group = groups_[found->second];
                group.limit = std::min(group.limit, device.concurrency_hint);
                group.pressure = std::max(group.pressure, device.io_pressure);
                group.pressure_known = group.pressure_known || device.io_pressure_known;
            }
            volume_index.emplace(device.device_key, found->second);
            device_keys_.push_back(device.device_key);
        }
        // Unbound preparation failures are accounted without opening a target.
        const auto unbound_group = groups_.size();
        groups_.push_back(device_state{});
        if (source_ != nullptr)
        {
            for (std::size_t position = 0; position < target_count_; ++position)
            {
                const auto device = device_key(position);
                nodes_[position].group = device.empty() ? unbound_group : volume_index.at(device);
                const auto parent = indexes_[position].parent;
                if (parent != std::numeric_limits<std::uint64_t>::max())
                {
                    nodes_[position].parent = static_cast<std::size_t>(parent);
                    ++nodes_[static_cast<std::size_t>(parent)].remaining;
                }
            }
        }
        else
        {
            std::unordered_map<std::string_view, std::size_t> directories;
            for (std::size_t index = 0; index < target_count_; ++index)
            {
                const auto& target = value_->targets[index];
                if (target.directory)
                {
                    directories.emplace(target.path, index);
                }
                nodes_[index].group = target.device_key.empty() ? unbound_group : volume_index.at(target.device_key);
            }
            for (std::size_t index = 0; index < target_count_; ++index)
            {
                auto prefix = std::string_view(value_->targets[index].path);
                while (!prefix.empty())
                {
                    const auto separator = prefix.find_last_of("/\\");
                    if (separator == std::string_view::npos)
                    {
                        break;
                    }
                    prefix = prefix.substr(0, separator);
                    const auto parent = directories.find(prefix);
                    if (parent != directories.end())
                    {
                        nodes_[index].parent = parent->second;
                        ++nodes_[parent->second].remaining;
                        break;
                    }
                }
            }
        }
        for (std::size_t index = 0; index < nodes_.size(); ++index)
        {
            if (nodes_[index].remaining == 0)
            {
                enqueue(index);
            }
        }
        next_resource_probe_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    }

    [[nodiscard]] std::optional<std::size_t> select_ready()
    {
        if (active_ >= worker_limit_)
        {
            return {};
        }
        for (std::size_t offset = 0; offset < groups_.size(); ++offset)
        {
            const auto group_index = (next_group_ + offset) % groups_.size();
            auto& group = groups_[group_index];
            if (group.ready.empty() || group.active >= group.limit)
            {
                continue;
            }
            std::pop_heap(group.ready.begin(), group.ready.end(), [this](auto left, auto right)
            {
                return lower_priority(left, right);
            });
            const auto index = group.ready.back();
            group.ready.pop_back();
            next_group_ = (group_index + 1) % groups_.size();
            return index;
        }
        return {};
    }

    void settle(std::size_t index)
    {
        ++settled_;
        const auto parent = nodes_[index].parent;
        if (parent != std::numeric_limits<std::size_t>::max() && --nodes_[parent].remaining == 0)
        {
            enqueue(parent);
        }
    }

    void feedback(std::size_t group_index, std::size_t index,
        std::chrono::steady_clock::duration elapsed)
    {
        auto& group = groups_[group_index];
        if (is_directory(index) || !deleted_[index])
        {
            return;
        }
        ++group.samples;
        group.elapsed_nanoseconds += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
        const auto now = std::chrono::steady_clock::now();
        const auto interval = std::chrono::duration<double>(now - group.window_started).count();
        if (group.samples < 8 || interval < 0.025)
        {
            return;
        }
        const auto rate = static_cast<double>(group.samples) / interval;
        const auto latency = static_cast<double>(group.elapsed_nanoseconds) / static_cast<double>(group.samples);
        const bool pressure = (resources_.cpu_pressure_known && resources_.cpu_pressure >= 75) ||
            (group.pressure_known && group.pressure >= 75);
        if (pressure)
        {
            const auto reduced = std::max<std::size_t>(1, group.limit / 2);
            progress_.concurrency_decreases += static_cast<std::size_t>(reduced < group.limit);
            group.limit = reduced;
            group.stable_windows = 0;
            group.probing = false;
            group.cooldown = 3;
        }
        else if (group.probing)
        {
            // PERFORMANCE: Require two profitable windows; flat throughput does
            // not earn another worker. A material regression rolls back even when
            // per-operation latency is unchanged. Thresholds are tuning heuristics.
            ++group.probe_windows;
            const bool profitable = rate >= group.baseline_rate * 1.05 &&
                latency <= group.baseline_latency * 1.50;
            group.profitable_windows += static_cast<unsigned>(profitable);
            const bool regressed = rate < group.baseline_rate * 0.90 ||
                (latency > group.baseline_latency * 1.25 && rate < group.baseline_rate * 1.05);
            if (regressed || (group.probe_windows >= 2 && group.profitable_windows < 2))
            {
                const auto reduced = std::max<std::size_t>(1, group.limit - 1);
                progress_.concurrency_decreases += static_cast<std::size_t>(reduced < group.limit);
                group.limit = reduced;
                group.cooldown = 3;
                group.probing = false;
            }
            else if (group.profitable_windows >= 2)
            {
                group.probing = false;
            }
            group.stable_windows = 0;
        }
        else if (group.cooldown != 0)
        {
            --group.cooldown;
        }
        else if (group.previous_rate == 0 ||
            (rate >= group.previous_rate * 0.85 && latency <= group.previous_latency * 1.20))
        {
            ++group.stable_windows;
            if (group.stable_windows >= 2 && group.limit < std::min(group.ceiling, worker_limit_) &&
                group.ready.size() / 4 >= group.limit && resources_.cpu_pressure_known)
            {
                group.baseline_rate = rate;
                group.baseline_latency = latency;
                ++group.limit;
                ++progress_.concurrency_increases;
                group.probing = true;
                group.probe_windows = 0;
                group.profitable_windows = 0;
                group.stable_windows = 0;
            }
        }
        else
        {
            group.stable_windows = 0;
        }
        group.previous_rate = rate;
        group.previous_latency = latency;
        group.samples = 0;
        group.elapsed_nanoseconds = 0;
        group.window_started = now;
    }

    void apply_resources(engine::result<resource_sample> refreshed)
    {
        if (!refreshed)
        {
            resource_failure_ = "quick_resource_revalidation_failed";
            resource_native_error_ = refreshed.error().native_code;
            fatal_.store(true);
            return;
        }
        const auto covered = resource_coverage(*refreshed, device_keys_);
        if (!covered)
        {
            resource_failure_ = covered.error().code;
            fatal_.store(true);
            return;
        }
        const auto estimated = fit_resources(admission_, target_count_, *refreshed, settings_);
        if (!estimated)
        {
            resource_failure_ = estimated.error().code;
            fatal_.store(true);
            return;
        }
        if (refreshed->devices.size() != resources_.devices.size())
        {
            resource_failure_ = "quick_resource_topology_changed";
            fatal_.store(true);
            return;
        }
        for (const auto& old : resources_.devices)
        {
            const auto replacement = std::find_if(refreshed->devices.begin(), refreshed->devices.end(), [&](const auto& device)
            {
                return device.device_key == old.device_key;
            });
            if (replacement == refreshed->devices.end() || replacement->scheduling_group != old.scheduling_group)
            {
                resource_failure_ = "quick_resource_topology_changed";
                fatal_.store(true);
                return;
            }
        }
        worker_limit_ = std::min(worker_ceiling_, estimated->worker_limit);
        resources_ = std::move(*refreshed);
        // Device key views refer to resources_, so rebuild after each replacement.
        device_keys_.clear();
        for (const auto& device : resources_.devices)
        {
            device_keys_.push_back(device.device_key);
        }
        for (auto& group : groups_)
        {
            group.ceiling = worker_limit_;
            group.pressure = 0;
            group.pressure_known = false;
            for (const auto& device : resources_.devices)
            {
                const auto key = device.scheduling_group.empty() ? std::string_view("unknown") :
                    std::string_view(device.scheduling_group);
                if (group.key == key)
                {
                    group.pressure = std::max(group.pressure, device.io_pressure);
                    group.pressure_known = group.pressure_known || device.io_pressure_known;
                }
            }
            const auto pressure_limit = group.pressure_known && group.pressure >= 90 ? 1 :
                group.pressure_known && group.pressure >= 75 ? std::max<std::size_t>(1, group.ceiling / 2) : group.ceiling;
            const auto reduced = std::min(group.limit, pressure_limit);
            progress_.concurrency_decreases += static_cast<std::size_t>(reduced < group.limit);
            if (reduced < group.limit)
            {
                group.probing = false;
                group.stable_windows = 0;
                group.cooldown = 3;
            }
            group.limit = reduced;
        }
        progress_.worker_limit = worker_limit_;
        progress_.memory_budget_bytes = estimated->memory_budget_bytes;
    }

    [[nodiscard]] bool stopped() const
    {
        return fatal_.load() || controls_.request.load() != engine::control_request::proceed;
    }

    void publish(std::string_view stage)
    {
        const std::scoped_lock lock(mutex_);
        progress_.stage.assign(stage);
        last_publication_ = std::chrono::steady_clock::now();
        if (observer_)
        {
            try
            {
                observer_(progress_);
            }
            catch (...)
            {
                resource_failure_ = "quick_progress_observer_failed";
                fatal_.store(true);
            }
        }
    }

    void store_error(std::size_t index, const engine::error& error)
    {
        const auto normalized = !error.code.empty() && error.code != "deleted_quick_namespace_removed" &&
            error.code.size() <= 512 && valid_utf8(error.code) ? error : failure("quick_backend_error_invalid");
        if (outcomes_ == nullptr)
        {
            errors_[index] = normalized;
        }
        if (error.device_fault)
        {
            failed_devices_.insert(device_key(index));
        }
        if (error.code == "critical_quick_thread_token_restore_failed" ||
            error.code == "critical_quick_readonly_restore_failed")
        {
            fatal_.store(true);
        }
        auto outcome = get_outcome(index);
        outcome.code = normalized.code;
        outcome.native_code = normalized.native_code;
        put_outcome(index, outcome);
    }

    void attempt(std::size_t index, bool recover_access)
    {
        const auto target = load_target(index);
        const auto removed = host_.remove(target, recover_access);
        const std::scoped_lock lock(mutex_);
        if (!attempted_[index])
        {
            attempted_[index] = true;
            ++progress_.attempted;
            ++progress_.failed;
        }
        if (removed)
        {
            auto outcome = get_outcome(index);
            outcome.code = "deleted_quick_namespace_removed";
            outcome.native_code = 0;
            outcome.deleted = true;
            if (outcomes_ == nullptr)
            {
                errors_[index] = {};
            }
            deleted_[index] = true;
            ++progress_.completed;
            --progress_.failed;
            put_outcome(index, outcome);
        }
        else
        {
            store_error(index, removed.error());
        }
        publish_if_due();
    }

    void publish_if_due()
    {
        if (!observer_)
        {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        if (progress_.attempted == 1 || progress_.attempted % 256 == 0 ||
            now - last_publication_ >= std::chrono::milliseconds(50))
        {
            last_publication_ = now;
            try
            {
                observer_(progress_);
            }
            catch (...)
            {
                resource_failure_ = "quick_progress_observer_failed";
                fatal_.store(true);
            }
        }
    }

    [[nodiscard]] bool admit_target(std::size_t index)
    {
        const std::scoped_lock lock(mutex_);
        if (stopped())
        {
            return false;
        }
        if (!failed_devices_.contains(device_key(index)))
        {
            return true;
        }
        if (!attempted_[index])
        {
            attempted_[index] = true;
            ++progress_.attempted;
            ++progress_.failed;
        }
        store_error(index, {"quick_device_stopped", 0, true});
        publish_if_due();
        return false;
    }

    void recover()
    {
        publish("recovery");
        std::set<std::pair<std::uint32_t, std::uint64_t>> closed;
        for (std::size_t order = 0; order < target_count_ && !stopped(); ++order)
        {
            const auto index = source_ == nullptr ? order : target_count_ - order - 1;
            if (std::chrono::steady_clock::now() >= next_resource_probe_)
            {
                apply_resources(host_.inspect_resources(device_keys_));
                next_resource_probe_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
                if (stopped())
                {
                    break;
                }
            }
            if (deleted_[index] ||
                preparation_failed(index) ||
                failed_devices_.contains(device_key(index)) ||
                !recoverable(error_at(index)))
            {
                continue;
            }
            attempt(index, settings_.recover_access);
            if (stopped() || deleted_[index] || !lock_failure(error_at(index)))
            {
                continue;
            }
            const auto target = load_target(index);
            const auto processes = host_.query_locks(target);
            if (!processes)
            {
                store_error(index, processes.error());
                continue;
            }
            if (processes->size() > 256)
            {
                store_error(index, failure("quick_lock_query_limit"));
                continue;
            }
            for (const auto& process : *processes)
            {
                if (stopped() || failed_devices_.contains(device_key(index)))
                {
                    break;
                }
                if (!process.eligible || process.process_id == 0 || process.creation_time == 0)
                {
                    continue;
                }
                const auto key = std::pair(process.process_id, process.creation_time);
                if (closed.contains(key))
                {
                    continue;
                }
                if (closed.size() == 1024)
                {
                    store_error(index, failure("quick_process_close_limit"));
                    break;
                }
                closed.insert(key);
                const auto released = host_.close_process(target, process, false);
                if (!released)
                {
                    store_error(index, released.error());
                }
            }
            if (!stopped() && !failed_devices_.contains(device_key(index)))
            {
                attempt(index, settings_.recover_access);
            }
        }
    }

    const plan* value_{};
    target_source* source_{};
    outcome_sink* outcomes_{};
    backend& host_;
    engine::control& controls_;
    options settings_;
    progress_observer observer_;
    engine::run_report report_;
    std::vector<engine::error> errors_;
    std::vector<unsigned char> attempted_;
    std::vector<unsigned char> deleted_;
    std::vector<node> nodes_;
    std::vector<target_index> indexes_;
    resource_sample resources_;
    admission_estimate admission_;
    std::vector<device_state> groups_;
    std::vector<std::string_view> device_keys_;
    std::size_t worker_ceiling_{};
    std::size_t worker_limit_{};
    std::size_t target_count_{};
    std::size_t active_{};
    std::size_t settled_{};
    std::size_t next_group_{};
    bool refreshing_{};
    std::string resource_failure_;
    std::uint32_t resource_native_error_{};
    progress progress_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::atomic<bool> fatal_{};
    std::set<std::string_view> failed_devices_;
    std::chrono::steady_clock::time_point last_publication_{};
    std::chrono::steady_clock::time_point next_resource_probe_{};
};

}

std::string target_key(const target& value)
{
    std::vector<std::byte> bytes;
    append_string(bytes, "secure_erase.quick_namespace.v1");
    append_string(bytes, value.path);
    append_string(bytes, value.identity);
    append_integer(bytes, value.creation_time);
    return crypto::hex_digest(crypto::sha256(bytes));
}

std::string fingerprint(const plan& value)
{
    // FORMAT: v2 is a length-delimited SHA-256 chain. Each step binds the full
    // previous digest and one target; hashing never duplicates the whole plan.
    std::vector<std::byte> bytes;
    append_string(bytes, "secure_erase.quick_plan.v2");
    append_string(bytes, value.job_id);
    append_integer(bytes, value.targets.size());
    auto digest = crypto::sha256(bytes);
    for (const auto& target : value.targets)
    {
        bytes.clear();
        bytes.insert(bytes.end(), digest.begin(), digest.end());
        append_string(bytes, target.path);
        append_string(bytes, target.identity);
        append_string(bytes, target.device_key);
        append_integer(bytes, target.creation_time);
        append_integer(bytes, target.attributes);
        append_integer(bytes, target.directory);
        append_string(bytes, target.preparation_error.code);
        append_integer(bytes, target.preparation_error.native_code);
        append_integer(bytes, target.preparation_error.device_fault);
        append_integer(bytes, target.allocated_bytes);
        digest = crypto::sha256(bytes);
    }
    return crypto::hex_digest(digest);
}

engine::result<plan> freeze(std::string job_id, std::vector<target> targets)
{
    if ((!valid_hex(job_id, 32) && !valid_hex(job_id, 64)) || targets.empty())
    {
        return std::unexpected(failure("quick_invalid_job_or_target_count"));
    }
    try
    {
        std::sort(targets.begin(), targets.end(), [](const target& left, const target& right)
        {
            return left.path < right.path;
        });
        std::size_t unique = 0;
        for (std::size_t index = 0; index < targets.size(); ++index)
        {
            if (!valid_target(targets[index]))
            {
                return std::unexpected(failure("quick_invalid_target"));
            }
            if (unique != 0 && targets[unique - 1].path == targets[index].path)
            {
                if (!same_target(targets[unique - 1], targets[index]))
                {
                    return std::unexpected(failure("quick_conflicting_namespace"));
                }
                continue;
            }
            if (unique != index)
            {
                targets[unique] = std::move(targets[index]);
            }
            ++unique;
        }
        targets.resize(unique);
        std::sort(targets.begin(), targets.end(), canonical_less);
        plan value{std::move(job_id), {}, std::move(targets)};
        value.fingerprint = fingerprint(value);
        return value;
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_complete_plan_allocation_failed"));
    }
}

engine::result<admitted_plan> freeze_admitted(std::string job_id, std::vector<target> targets)
{
    auto frozen = freeze(std::move(job_id), std::move(targets));
    if (!frozen)
    {
        return std::unexpected(frozen.error());
    }
    try
    {
        return admitted_plan(std::make_shared<const plan>(std::move(*frozen)));
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_complete_plan_allocation_failed"));
    }
}

engine::result<admitted_plan> admit(plan value)
{
    try
    {
        const auto validated = validate_plan(value);
        if (!validated)
        {
            return std::unexpected(validated.error());
        }
        return admitted_plan(std::make_shared<const plan>(std::move(value)));
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_complete_plan_allocation_failed"));
    }
}

engine::result<admission_estimate> estimate_admission(const plan& value,
    const resource_sample& resources, const options& settings)
{
    admission_estimate estimate;
    if (resources.cpu_pressure > 100 || resources.available_memory_bytes == 0 ||
        resources.available_commit_bytes == 0 || value.targets.empty())
    {
        return std::unexpected(failure("quick_resource_sample_invalid"));
    }
    estimate.memory_budget_bytes = std::min(resources.available_memory_bytes,
        resources.available_commit_bytes) / 4;
    if (settings.memory_budget_bytes != 0)
    {
        estimate.memory_budget_bytes = std::min(estimate.memory_budget_bytes, settings.memory_budget_bytes);
    }
    const auto count = static_cast<std::uint64_t>(value.targets.size());
    if (value.targets.capacity() > std::numeric_limits<std::uint64_t>::max() / sizeof(target) ||
        count > std::numeric_limits<std::uint64_t>::max() / 2048)
    {
        return std::unexpected(failure("quick_plan_size_overflow"));
    }
    estimate.resident_plan_bytes = sizeof(plan) + value.targets.capacity() * sizeof(target);
    if (!checked_add(estimate.resident_plan_bytes, value.job_id.capacity() + 1) ||
        !checked_add(estimate.resident_plan_bytes, value.fingerprint.capacity() + 1))
    {
        return std::unexpected(failure("quick_plan_size_overflow"));
    }
    // CONTRACT: Per target includes report+error strings, identity key, queue and
    // dependency nodes, two temporary hash indexes and allocator headroom. The
    // explicit multiplier is conservative accounting, not a process-RSS promise.
    estimate.execution_metadata_bytes = count * 2048;
    // Each volume can carry a distinct topology label. Account simultaneous old
    // and fresh probe samples plus scheduler labels and per-group counters/indexes.
    for (const auto& device : resources.devices)
    {
        if (!checked_add(estimate.execution_metadata_bytes, 512) ||
            !checked_add(estimate.execution_metadata_bytes, device.device_key.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.device_key.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.scheduling_group.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.scheduling_group.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.scheduling_group.capacity() + 1))
        {
            return std::unexpected(failure("quick_plan_size_overflow"));
        }
    }
    std::uint64_t maximum_path = 0;
    std::uint64_t maximum_depth = 0;
    for (const auto& target : value.targets)
    {
        if (!checked_add(estimate.resident_plan_bytes, target.path.capacity() + 1) ||
            !checked_add(estimate.resident_plan_bytes, target.identity.capacity() + 1) ||
            !checked_add(estimate.resident_plan_bytes, target.device_key.capacity() + 1) ||
            !checked_add(estimate.resident_plan_bytes, target.preparation_error.code.capacity() + 1))
        {
            return std::unexpected(failure("quick_plan_size_overflow"));
        }
        maximum_path = std::max(maximum_path, static_cast<std::uint64_t>(target.path.size()));
        maximum_depth = std::max(maximum_depth, static_cast<std::uint64_t>(
            std::count_if(target.path.begin(), target.path.end(), [](char value)
            {
                return value == '/' || value == '\\';
            })));
    }
    estimate.handles_per_worker = maximum_depth + 4;
    // Stack reserve, path conversion, pinned ancestry and bounded backend scratch.
    estimate.worker_bytes = 2 * 1024 * 1024 + maximum_path * 8 + maximum_depth * 256;
    std::uint64_t metadata = estimate.resident_plan_bytes;
    if (!checked_add(metadata, estimate.execution_metadata_bytes) ||
        !checked_add(metadata, maximum_path * 4 + 256 * 1024) || metadata >= estimate.memory_budget_bytes)
    {
        return std::unexpected(failure("quick_complete_plan_memory_insufficient"));
    }
    // Include maximum hash scratch in the reported execution-state total.
    estimate.execution_metadata_bytes = metadata - estimate.resident_plan_bytes;
    return fit_resources(estimate, value.targets.size(), resources, settings);
}

engine::frozen_plan display_plan(const plan& value)
{
    engine::frozen_plan result;
    result.job_id = value.job_id;
    result.fingerprint = value.fingerprint;
    result.targets.reserve(value.targets.size());
    for (const auto& target : value.targets)
    {
        engine::target_snapshot display;
        display.path = target.path;
        display.identity = target_key(target);
        display.device_key = target.device_key;
        display.creation_time = target.creation_time;
        display.attributes = target.attributes;
        display.directory = target.directory;
        display.support = target.preparation_error.code.empty() ?
            engine::capability::delete_only : engine::capability::blocked;
        if (!target.preparation_error.code.empty())
        {
            display.protection_reasons.push_back(target.preparation_error.code);
        }
        display.residual_risks.push_back("quick_delete_no_content_sanitization");
        result.targets.push_back(std::move(display));
    }
    return result;
}

namespace
{
[[nodiscard]] engine::result<engine::run_report> run_prepared(const plan& value,
    std::string_view approved_fingerprint, bool irreversible_confirmed,
    backend& host, engine::control& controls, const options& settings,
    progress_observer observer, const engine::run_report* previous)
{
    if (!irreversible_confirmed || approved_fingerprint != value.fingerprint)
    {
        return std::unexpected(failure("quick_exact_plan_confirmation_required"));
    }
    try
    {
        execution_scope lifetime(host);
        const auto initialized = host.begin_execution();
        if (!initialized)
        {
            return std::unexpected(initialized.error());
        }
        std::vector<std::string_view> devices;
        std::unordered_set<std::string_view> seen_devices;
        for (const auto& target : value.targets)
        {
            if (!target.device_key.empty() && seen_devices.insert(target.device_key).second)
            {
                devices.push_back(target.device_key);
            }
        }
        auto resources = host.inspect_resources(devices);
        if (!resources)
        {
            return std::unexpected(resources.error());
        }
        const auto covered = resource_coverage(*resources, devices);
        if (!covered)
        {
            return std::unexpected(covered.error());
        }
        const auto admission = estimate_admission(value, *resources, settings);
        if (!admission)
        {
            return std::unexpected(admission.error());
        }
        std::vector<std::string> keys;
        keys.reserve(value.targets.size());
        for (const auto& target : value.targets)
        {
            keys.push_back(target_key(target));
        }
        if (previous != nullptr)
        {
            const auto valid = validate_previous(value, *previous, keys);
            if (!valid)
            {
                return std::unexpected(valid.error());
            }
        }
        execution work(value, host, controls, settings, std::move(observer), std::move(keys),
            previous, std::move(*resources), *admission);
        return work.perform();
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_complete_plan_allocation_failed"));
    }
}
}

engine::result<engine::run_report> run(const plan& value,
    std::string_view approved_fingerprint, bool irreversible_confirmed,
    backend& host, engine::control& controls, const options& settings,
    progress_observer observer, const engine::run_report* previous)
{
    try
    {
        const auto validated = validate_plan(value);
        if (!validated)
        {
            return std::unexpected(validated.error());
        }
        return run_prepared(value, approved_fingerprint, irreversible_confirmed, host,
            controls, settings, std::move(observer), previous);
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_complete_plan_allocation_failed"));
    }
}

engine::result<engine::run_report> run(const admitted_plan& value,
    std::string_view approved_fingerprint, bool irreversible_confirmed,
    backend& host, engine::control& controls, const options& settings,
    progress_observer observer, const engine::run_report* previous)
{
    return run_prepared(value.get(), approved_fingerprint, irreversible_confirmed, host,
        controls, settings, std::move(observer), previous);
}
engine::result<admission_estimate> estimate_admission(const staged_plan_info& value,
    const resource_sample& resources, const options& settings)
{
    if (value.target_count == 0 ||
        value.target_count > std::numeric_limits<std::uint64_t>::max() / 256 ||
        value.maximum_target_bytes > std::numeric_limits<std::uint64_t>::max() / 4 ||
        value.maximum_ancestor_depth > (std::numeric_limits<std::uint64_t>::max() - 4) / 256)
    {
        return std::unexpected(failure("quick_staged_size_overflow"));
    }
    admission_estimate estimate;
    estimate.resident_plan_bytes = value.resident_bytes;
    // Compact source index + dependency nodes + flags + queue entries and
    // allocator allowance. Full target strings and outcomes stay in the store.
    estimate.execution_metadata_bytes = static_cast<std::uint64_t>(value.target_count) * 256;
    for (const auto& device : resources.devices)
    {
        if (!checked_add(estimate.execution_metadata_bytes, 512) ||
            !checked_add(estimate.execution_metadata_bytes, device.device_key.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.device_key.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.scheduling_group.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.scheduling_group.capacity() + 1) ||
            !checked_add(estimate.execution_metadata_bytes, device.scheduling_group.capacity() + 1))
        {
            return std::unexpected(failure("quick_staged_size_overflow"));
        }
    }
    estimate.handles_per_worker = value.maximum_ancestor_depth + 4;
    estimate.worker_bytes = 2 * 1024 * 1024;
    if (!checked_add(estimate.worker_bytes, value.maximum_target_bytes * 4) ||
        !checked_add(estimate.worker_bytes, value.maximum_ancestor_depth * 256) ||
        !checked_add(estimate.execution_metadata_bytes, 256 * 1024))
    {
        return std::unexpected(failure("quick_staged_size_overflow"));
    }
    return fit_resources(estimate, value.target_count, resources, settings);
}

engine::result<staged_report> run_staged(target_source& source, outcome_sink& outcomes,
    std::string_view approved_fingerprint, bool irreversible_confirmed, backend& host,
    engine::control& controls, const options& settings, progress_observer observer,
    bool reuse_completed)
{
    const auto& info = source.info();
    if (!irreversible_confirmed || approved_fingerprint != info.fingerprint)
    {
        return std::unexpected(failure("quick_exact_plan_confirmation_required"));
    }
    if ((!valid_hex(info.job_id, 32) && !valid_hex(info.job_id, 64)) ||
        !valid_hex(info.fingerprint, 64) || info.target_count == 0 || info.maximum_target_bytes == 0)
    {
        return std::unexpected(failure("quick_staged_manifest_invalid"));
    }
    try
    {
        const auto validated = source.validate();
        if (!validated)
        {
            return std::unexpected(validated.error());
        }
        execution_scope lifetime(host);
        const auto initialized = host.begin_execution();
        if (!initialized)
        {
            return std::unexpected(initialized.error());
        }
        std::vector<std::string_view> devices;
        std::unordered_set<std::string_view> unique;
        for (const auto& device : info.device_keys)
        {
            if (device.empty() || device.size() > 1024 || !valid_utf8(device) || !unique.insert(device).second)
            {
                return std::unexpected(failure("quick_staged_device_table_invalid"));
            }
            devices.push_back(device);
        }
        auto resources = host.inspect_resources(devices);
        if (!resources)
        {
            return std::unexpected(resources.error());
        }
        const auto covered = resource_coverage(*resources, devices);
        if (!covered)
        {
            return std::unexpected(covered.error());
        }
        const auto admission = estimate_admission(info, *resources, settings);
        if (!admission)
        {
            return std::unexpected(admission.error());
        }
        const auto prepared = outcomes.begin(info, reuse_completed);
        if (!prepared)
        {
            return std::unexpected(prepared.error());
        }
        execution work(source, outcomes, host, controls, settings, std::move(observer),
            std::move(*resources), *admission);
        auto report = work.perform();
        const auto& counts = work.final_progress();
        staged_report summary{std::move(report.job_id), std::move(report.plan_fingerprint),
            std::move(report.status), counts.total, counts.attempted, counts.completed,
            counts.failed, counts.total - counts.attempted, std::move(report.stopping_error)};
        try
        {
            const auto finalized = outcomes.finish(summary);
            if (!finalized)
            {
                summary.status = "audit_finalization_failed";
                summary.stopping_error.code.assign(finalized.error().code.size() <= 512 &&
                    valid_utf8(finalized.error().code) ? std::string_view(finalized.error().code) :
                    std::string_view("quick_outcome_finalization_failed"));
                summary.stopping_error.native_code = finalized.error().native_code;
                summary.stopping_error.device_fault = finalized.error().device_fault;
            }
        }
        catch (...)
        {
            // SECURITY: A final persistence exception follows namespace mutation.
            // Preserve actual completion counters instead of returning a preflight
            // allocation failure that could conceal already removed names.
            summary.status = "audit_finalization_failed";
            summary.stopping_error.code.assign("quick_outcome_finalization_exception");
        }
        return summary;
    }
    catch (const staged_failure& error)
    {
        return std::unexpected(error.error);
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_complete_plan_allocation_failed"));
    }
}

}
