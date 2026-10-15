import std;
import secure_erase.engine;

namespace
{
namespace engine = secure_erase::engine;
using engine::result;

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

enum class fault
{
    none,
    acquire,
    write,
    zero_write,
    short_io,
    flush,
    read,
    corrupt_read,
    remove,
    trim,
    device,
    added_stream,
    replaced_on_acquire,
    changed_capability,
    rng
};

struct record
{
    engine::target_snapshot snapshot;
    std::map<std::string, std::vector<std::byte>> streams;
    fault injected{fault::none};
    bool deleted{};
    std::size_t writes{};
    std::size_t reads{};
    std::size_t flushes{};
    std::size_t removes{};
    bool slow{};
    bool set_archive_on_write{};
    bool settle_readonly{};
    bool trim_discards_bytes{};
};

class fake_platform;

class fake_handle final : public engine::target_handle
{
public:
    fake_handle(fake_platform& owner, record& value);
    ~fake_handle() override;
    result<engine::target_snapshot> inspect() override;
    result<engine::target_snapshot> checkpoint_snapshot() override;
    result<std::size_t> read(std::string_view stream, std::uint64_t offset,
        std::span<std::byte> bytes) override;
    result<std::size_t> write(std::string_view stream, std::uint64_t offset,
        std::span<const std::byte> bytes) override;
    result<void> flush(std::string_view) override;
    result<void> trim() override;
    result<void> remove() override;

private:
    fake_platform& owner_;
    record& value_;
    bool readonly_changed_{};
};

class fake_platform final : public engine::platform
{
public:
    std::map<std::string, record> records;
    bool elevated{true};
    bool random_failure{};
    unsigned pressure{};
    unsigned execution_phases{};
    std::mutex mutex;
    std::map<std::string, std::size_t> active;
    std::map<std::string, std::size_t> maximum;
    std::size_t active_total{};
    std::size_t maximum_total{};
    std::vector<std::string> deleted_order;

    bool is_elevated() const noexcept override
    {
        return elevated;
    }

    unsigned resource_pressure() const noexcept override
    {
        return pressure;
    }

    result<void> begin_execution() override
    {
        ++execution_phases;
        return {};
    }

    result<std::vector<engine::target_snapshot>> preview(const std::vector<std::string>& paths) override
    {
        std::vector<engine::target_snapshot> snapshots;
        for (const auto& path : paths)
        {
            snapshots.push_back(records.at(path).snapshot);
        }
        return snapshots;
    }

    result<std::unique_ptr<engine::target_handle>> acquire(const engine::target_snapshot& snapshot) override
    {
        auto& value = records.at(snapshot.path);
        if (value.injected == fault::acquire)
        {
            return std::unexpected(engine::error{"fake_acquire_failure", 1, false});
        }
        if (value.injected == fault::replaced_on_acquire)
        {
            value.snapshot.identity += "replacement";
        }
        if (value.injected == fault::changed_capability)
        {
            value.snapshot.support = engine::capability::delete_only;
        }
        return std::make_unique<fake_handle>(*this, value);
    }

    result<void> random_bytes(std::span<std::byte> bytes) override
    {
        if (random_failure)
        {
            return std::unexpected(engine::error{"fake_rng_failure", 2, false});
        }
        for (std::size_t index = 0; index < bytes.size(); ++index)
        {
            bytes[index] = static_cast<std::byte>(index & 0xffU);
        }
        return {};
    }

    void add(std::string path, std::string identity, std::string device = "disk_a",
        engine::media_kind media = engine::media_kind::hdd, std::size_t size = 140000)
    {
        record value;
        value.snapshot.path = path;
        value.snapshot.identity = std::move(identity);
        value.snapshot.device_key = std::move(device);
        value.snapshot.creation_time = 11;
        value.snapshot.write_time = 22;
        value.snapshot.change_time = 33;
        value.snapshot.media = media;
        value.snapshot.support = engine::capability::overwrite_verified;
        value.snapshot.streams.push_back({"", size});
        value.streams.emplace("", std::vector<std::byte>(size, std::byte{0xcc}));
        records.emplace(std::move(path), std::move(value));
    }
};

fake_handle::fake_handle(fake_platform& owner, record& value) : owner_(owner), value_(value)
{
    const std::scoped_lock lock(owner_.mutex);
    ++owner_.active.at(value_.snapshot.device_key);
    auto& maximum = owner_.maximum.at(value_.snapshot.device_key);
    maximum = std::max(maximum, owner_.active.at(value_.snapshot.device_key));
    ++owner_.active_total;
    owner_.maximum_total = std::max(owner_.maximum_total, owner_.active_total);
    if (value_.settle_readonly && (value_.snapshot.attributes & 1) != 0)
    {
        value_.snapshot.attributes &= ~std::uint32_t{1};
        if (value_.snapshot.attributes == 0)
        {
            value_.snapshot.attributes = 0x80;
        }
        ++value_.snapshot.change_time;
        readonly_changed_ = true;
    }
}

fake_handle::~fake_handle()
{
    const std::scoped_lock lock(owner_.mutex);
    --owner_.active.at(value_.snapshot.device_key);
    --owner_.active_total;
    if (readonly_changed_)
    {
        value_.snapshot.attributes = (value_.snapshot.attributes & ~std::uint32_t{0x80}) | 1;
        ++value_.snapshot.change_time;
    }
}

result<engine::target_snapshot> fake_handle::inspect()
{
    auto snapshot = value_.snapshot;
    if (value_.injected == fault::added_stream && value_.writes != 0)
    {
        snapshot.streams.push_back({":new_ads", 4});
    }
    return snapshot;
}

result<engine::target_snapshot> fake_handle::checkpoint_snapshot()
{
    if (readonly_changed_)
    {
        value_.snapshot.attributes = (value_.snapshot.attributes & ~std::uint32_t{0x80}) | 1;
        ++value_.snapshot.change_time;
        readonly_changed_ = false;
    }
    return inspect();
}

result<std::size_t> fake_handle::read(std::string_view stream, std::uint64_t offset,
    std::span<std::byte> bytes)
{
    ++value_.reads;
    if (value_.injected == fault::read)
    {
        return std::unexpected(engine::error{"fake_read_failure", 3, false});
    }
    auto& data = value_.streams.at(std::string(stream));
    const auto position = static_cast<std::size_t>(offset);
    auto size = std::min(bytes.size(), data.size() - position);
    if (value_.injected == fault::short_io)
    {
        size = std::min<std::size_t>(size, 7777);
    }
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(position), size, bytes.begin());
    if (value_.injected == fault::corrupt_read && size != 0)
    {
        bytes.front() ^= std::byte{1};
    }
    return size;
}

result<std::size_t> fake_handle::write(std::string_view stream, std::uint64_t offset,
    std::span<const std::byte> bytes)
{
    ++value_.writes;
    if (value_.slow)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }
    if (value_.injected == fault::write || value_.injected == fault::device)
    {
        return std::unexpected(engine::error{"fake_write_failure", 4,
            value_.injected == fault::device});
    }
    if (value_.injected == fault::zero_write)
    {
        return 0;
    }
    auto& data = value_.streams.at(std::string(stream));
    const auto position = static_cast<std::size_t>(offset);
    auto size = std::min(bytes.size(), data.size() - position);
    if (value_.injected == fault::short_io)
    {
        size = std::min<std::size_t>(size, 5000);
    }
    std::copy_n(bytes.begin(), size, data.begin() + static_cast<std::ptrdiff_t>(position));
    ++value_.snapshot.change_time;
    ++value_.snapshot.write_time;
    if (value_.set_archive_on_write)
    {
        value_.snapshot.attributes = (value_.snapshot.attributes & ~std::uint32_t{0x80}) | 0x20;
    }
    return size;
}

result<void> fake_handle::flush(std::string_view)
{
    ++value_.flushes;
    if (value_.injected == fault::flush)
    {
        return std::unexpected(engine::error{"fake_flush_failure", 5, false});
    }
    return {};
}

result<void> fake_handle::trim()
{
    if (value_.trim_discards_bytes)
    {
        for (auto& [name, bytes] : value_.streams)
        {
            static_cast<void>(name);
            std::fill(bytes.begin(), bytes.end(), std::byte{});
        }
    }
    if (value_.injected == fault::trim)
    {
        return std::unexpected(engine::error{"fake_trim_failure", 6, false});
    }
    return {};
}

result<void> fake_handle::remove()
{
    ++value_.removes;
    if (value_.injected == fault::remove)
    {
        return std::unexpected(engine::error{"fake_remove_failure", 7, false});
    }
    if (value_.snapshot.directory)
    {
        for (const auto& [path, child] : owner_.records)
        {
            if (path.starts_with(value_.snapshot.path + "/") && !child.deleted)
            {
                return std::unexpected(engine::error{"directory_not_empty", 8, false});
            }
        }
    }
    value_.deleted = true;
    const std::scoped_lock lock(owner_.mutex);
    owner_.deleted_order.push_back(value_.snapshot.path);
    return {};
}

class fake_store final : public engine::checkpoint_store
{
public:
    std::optional<engine::checkpoint> saved;
    std::size_t saves{};
    std::size_t fail_at{};
    bool fail_remove{};
    bool removed{};

    result<void> save(const engine::checkpoint& value) override
    {
        ++saves;
        if (fail_at != 0 && saves == fail_at)
        {
            return std::unexpected(engine::error{"fake_checkpoint_failure", 9, false});
        }
        saved = value;
        return {};
    }

    result<engine::checkpoint> load(std::string_view) override
    {
        if (!saved)
        {
            return std::unexpected(engine::error{"missing_checkpoint", 10, false});
        }
        return *saved;
    }

    result<void> remove(std::string_view) override
    {
        if (fail_remove)
        {
            return std::unexpected(engine::error{"fake_checkpoint_cleanup_failure", 11, false});
        }
        removed = true;
        return {};
    }
};

class fake_events final : public engine::event_sink
{
public:
    engine::control* controls{};
    engine::control_request request{engine::control_request::proceed};
    std::string trigger;
    std::string fail_code;
    std::vector<std::string> codes;

    result<void> emit(const engine::event& value) override
    {
        codes.push_back(value.code);
        if (value.code == fail_code)
        {
            return std::unexpected(engine::error{"fake_audit_failure", 12, false});
        }
        if (controls != nullptr && value.code == trigger)
        {
            controls->request.store(request);
        }
        return {};
    }
};

struct fixture
{
    fake_platform host;
    fake_store store;
    fake_events events;
    engine::control control;
    engine::frozen_plan plan;
    engine::approval approval;
    engine::options options;

    fixture()
    {
        host.add("c:/fixture/file", "volume:01");
        options.chunk_bytes = 65536;
        options.max_device_workers = 1;
    }

    void freeze()
    {
        std::vector<engine::target_snapshot> snapshots;
        for (const auto& [path, value] : host.records)
        {
            static_cast<void>(path);
            snapshots.push_back(value.snapshot);
            host.active.emplace(value.snapshot.device_key, 0);
            host.maximum.emplace(value.snapshot.device_key, 0);
        }
        plan = *engine::freeze("00112233445566778899aabbccddeeff", snapshots);
        approval = {plan.fingerprint, true, {}};
    }

    result<engine::run_report> run(const engine::checkpoint* resume = nullptr)
    {
        return engine::run(plan, approval, host, store, events, control, options, resume);
    }

    record& file()
    {
        return host.records.at("c:/fixture/file");
    }
};
}

int main()
{
    test_results tests;
    {
        fixture value;
        value.file().snapshot.streams.push_back({":notes", 1000});
        value.file().streams.emplace(":notes", std::vector<std::byte>(1000, std::byte{0xff}));
        value.freeze();
        const auto report = value.run();
        tests.check(report && report->status == "completed", "regular_and_ads_full_pipeline");
        tests.check(value.file().deleted && value.file().reads != 0 && value.file().flushes != 0,
            "delete_only_after_flush_and_readback");
        tests.check(report && report->targets.front().written_bytes == 141000 &&
            report->targets.front().verified_bytes == 141000, "all_stream_bytes_written_and_verified");
        tests.check(report && report->targets.front().logical_overwrite_verified &&
            !report->targets.front().physical_sanitization_guaranteed, "logical_and_physical_claims_separate");
        tests.check(value.store.removed, "completed_checkpoint_cleaned");
        tests.check(value.store.saved && !value.store.saved->targets.front().key_ready &&
            std::all_of(value.store.saved->targets.front().key.begin(), value.store.saved->targets.front().key.end(),
                [](std::byte byte)
                {
                    return byte == std::byte{};
                }), "completed_key_zeroized");
    }
    {
        fixture value;
        value.file().set_archive_on_write = true;
        value.file().snapshot.attributes = 0x80;
        value.freeze();
        const auto report = value.run();
        tests.check(report && report->status == "completed", "own_write_archive_bit_set_permitted");
    }
    for (const auto injected : {fault::acquire, fault::write, fault::zero_write, fault::flush,
        fault::read, fault::corrupt_read, fault::remove, fault::added_stream,
        fault::replaced_on_acquire, fault::changed_capability})
    {
        fixture value;
        value.freeze();
        value.file().injected = injected;
        const auto report = value.run();
        tests.check(report && report->status == "partial_failure" && !value.file().deleted,
            "failure_blocks_delete_" + std::to_string(static_cast<unsigned>(injected)));
        if (injected != fault::remove)
        {
            tests.check(value.file().removes == 0, "failure_never_calls_remove_" +
                std::to_string(static_cast<unsigned>(injected)));
        }
    }
    {
        fixture value;
        value.file().injected = fault::short_io;
        value.freeze();
        const auto report = value.run();
        tests.check(report && report->status == "completed" && value.file().writes > 20,
            "short_io_advances_correctly_until_full");
    }
    {
        fixture value;
        value.freeze();
        value.host.elevated = false;
        const auto report = value.run();
        tests.check(!report && value.file().writes == 0, "admin_is_core_gate");
    }
    {
        fixture value;
        value.freeze();
        value.approval.execute = false;
        const auto report = value.run();
        tests.check(!report && value.file().writes == 0, "execute_confirmation_is_core_gate");
    }
    {
        fixture value;
        value.freeze();
        value.approval.plan_fingerprint.front() = 'f';
        tests.check(!value.run() && value.file().writes == 0, "approval_bound_to_exact_plan");
    }
    {
        fixture value;
        value.freeze();
        value.plan.targets.front().streams.front().size += 1;
        tests.check(!value.run() && value.file().writes == 0, "post_preview_plan_mutation_rejected");
    }
    {
        fixture value;
        value.file().snapshot.protection_reasons.push_back("critical_system_identity");
        value.freeze();
        const auto report = value.run();
        tests.check(report && !value.file().deleted && value.file().writes == 0,
            "protected_target_cannot_be_overridden_by_execute");
    }
    for (const auto support : {engine::capability::delete_only, engine::capability::overwrite_best_effort})
    {
        fixture value;
        value.file().snapshot.support = support;
        value.freeze();
        auto report = value.run();
        tests.check(report && !value.file().deleted && value.file().writes == 0,
            "fallback_needs_independent_consent_" + std::to_string(static_cast<unsigned>(support)));
        value.approval.downgrade_identities.push_back(value.file().snapshot.identity);
        report = value.run();
        tests.check(report && value.file().deleted, "fallback_exact_consent_" +
            std::to_string(static_cast<unsigned>(support)));
        tests.check(report && report->targets.front().logical_overwrite_verified ==
            (support == engine::capability::overwrite_best_effort), "fallback_result_truthful_" +
            std::to_string(static_cast<unsigned>(support)));
    }
    for (unsigned property = 0; property < 5; ++property)
    {
        fixture value;
        if (property == 0)
        {
            value.file().snapshot.link_count = 2;
        }
        if (property == 1)
        {
            value.file().snapshot.reparse_point = true;
        }
        if (property == 2)
        {
            value.file().snapshot.encrypted = true;
        }
        if (property == 3)
        {
            value.file().snapshot.compressed = true;
        }
        if (property == 4)
        {
            value.file().snapshot.sparse = true;
        }
        value.freeze();
        const auto report = value.run();
        tests.check(report && value.file().writes == 0 && !value.file().deleted,
            "special_file_cannot_enter_regular_overwrite_" + std::to_string(property));
    }
    for (const auto failure_index : {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{4}})
    {
        fixture value;
        value.freeze();
        value.store.fail_at = failure_index;
        const auto report = value.run();
        static_cast<void>(report);
        tests.check(!value.file().deleted && value.file().removes == 0,
            "checkpoint_failure_blocks_delete_" + std::to_string(failure_index));
        if (failure_index <= 3)
        {
            tests.check(value.file().writes == 0, "checkpoint_precedes_mutation_" + std::to_string(failure_index));
        }
    }
    {
        fixture value;
        value.freeze();
        value.host.random_failure = true;
        const auto report = value.run();
        tests.check(report && value.file().writes == 0 && !value.file().deleted, "rng_failure_before_mutation");
    }
    for (const auto code : {"job_started", "target_started", "write_progress", "verify_progress"})
    {
        fixture value;
        value.freeze();
        value.events.fail_code = code;
        const auto report = value.run();
        static_cast<void>(report);
        tests.check(!value.file().deleted, "audit_failure_blocks_delete_" + std::string(code));
    }
    {
        fixture value;
        value.freeze();
        value.events.controls = &value.control;
        value.events.trigger = "write_progress";
        value.events.request = engine::control_request::pause;
        const auto paused = value.run();
        tests.check(paused && paused->status == "paused" && !value.file().deleted,
            "pause_at_durable_chunk_boundary");
        tests.check(value.store.saved && value.store.saved->targets.front().offset == 65536,
            "pause_persists_cursor_and_sensitive_state");
        auto saved = *value.store.saved;
        value.events.trigger.clear();
        value.control.request.store(engine::control_request::proceed);
        const auto resumed = value.run(&saved);
        tests.check(resumed && resumed->status == "completed" && value.file().deleted,
            "resume_revalidates_and_finishes");
        tests.check(resumed && resumed->targets.front().verified_bytes == 205536,
            "resume_verifies_saved_prefix_then_full_content");
        tests.check(value.host.execution_phases == 2, "capability_cache_reset_each_execute_resume_phase");
    }
    {
        fixture value;
        value.freeze();
        value.events.controls = &value.control;
        value.events.trigger = "write_progress";
        value.events.request = engine::control_request::pause;
        static_cast<void>(value.run());
        auto saved = *value.store.saved;
        value.file().streams.at("").front() ^= std::byte{1};
        value.events.trigger.clear();
        value.control.request.store(engine::control_request::proceed);
        const auto writes = value.file().writes;
        const auto resumed = value.run(&saved);
        tests.check(resumed && !value.file().deleted && value.file().writes == writes,
            "resume_rejects_tampered_prefix_before_more_writes");
    }
    {
        fixture value;
        value.freeze();
        value.events.controls = &value.control;
        value.events.trigger = "verify_progress";
        value.events.request = engine::control_request::cancel;
        const auto report = value.run();
        tests.check(report && report->status == "cancelled_partial" && !value.file().deleted,
            "cancel_during_verify_never_deletes");
    }
    {
        fixture value;
        value.host.add("c:/fixture/z", "volume:02");
        value.file().injected = fault::device;
        value.freeze();
        const auto report = value.run();
        tests.check(report && !value.host.records.at("c:/fixture/z").deleted &&
            value.host.records.at("c:/fixture/z").writes == 0, "device_fault_skips_remaining_same_device");
    }
    {
        fixture value;
        value.host.add("c:/fixture/z", "volume:02", "disk_b");
        value.file().injected = fault::device;
        value.freeze();
        const auto report = value.run();
        tests.check(report && value.host.records.at("c:/fixture/z").deleted,
            "device_fault_does_not_block_independent_device");
    }
    for (const bool extra_child : {false, true})
    {
        fixture value;
        value.host.add("c:/fixture", "directory:01", "disk_a", engine::media_kind::hdd, 0);
        auto& directory = value.host.records.at("c:/fixture");
        directory.snapshot.directory = true;
        directory.snapshot.streams.clear();
        value.freeze();
        if (extra_child)
        {
            value.host.add("c:/fixture/new", "volume:unapproved");
        }
        const auto report = value.run();
        tests.check(report && value.file().deleted && directory.deleted != extra_child,
            extra_child ? "new_child_not_admitted_and_parent_retained" : "directory_deleted_after_frozen_children");
        if (!extra_child)
        {
            tests.check(value.host.deleted_order.back() == "c:/fixture", "directory_order_postorder");
        }
        else
        {
            tests.check(value.host.records.at("c:/fixture/new").writes == 0,
                "new_unapproved_child_never_written");
        }
    }
    {
        fixture value;
        value.freeze();
        value.store.fail_remove = true;
        const auto report = value.run();
        tests.check(report && report->status == "checkpoint_cleanup_failed" && value.file().deleted,
            "checkpoint_cleanup_failure_not_hidden");
    }
    {
        fixture value;
        value.freeze();
        value.events.fail_code = "deleted_logical_overwrite_verified_residual_risk";
        const auto report = value.run();
        tests.check(report && report->status == "partial_failure" && value.file().deleted,
            "post_delete_audit_error_retains_honest_partial_result");
    }
    {
        fixture value;
        for (unsigned index = 1; index < 7; ++index)
        {
            const bool ssd = index >= 3;
            value.host.add("c:/fixture/" + std::to_string(index), "volume:" + std::to_string(index + 2),
                ssd ? "disk_b" : "disk_a", ssd ? engine::media_kind::ssd : engine::media_kind::hdd);
        }
        for (auto& [path, item] : value.host.records)
        {
            static_cast<void>(path);
            item.slow = true;
        }
        value.options.max_device_workers = 4;
        value.options.ssd_queue_depth = 2;
        value.freeze();
        const auto report = value.run();
        tests.check(report && report->status == "completed", "bounded_device_scheduler_completes_batch");
        tests.check(value.host.maximum.at("disk_a") == 1, "hdd_queue_depth_one");
        tests.check(value.host.maximum.at("disk_b") == 2, "ssd_bounded_parallel_queue");
        tests.check(value.host.maximum_total <= 4, "global_worker_limit_respected");
    }
    {
        fixture value;
        value.file().snapshot.attributes = 1;
        value.file().settle_readonly = true;
        value.freeze();
        value.events.controls = &value.control;
        value.events.trigger = "write_progress";
        value.events.request = engine::control_request::pause;
        const auto paused = value.run();
        tests.check(paused && paused->status == "paused" && value.file().snapshot.attributes == 1,
            "readonly_restored_while_pinned_before_pause_checkpoint");
        auto saved = *value.store.saved;
        tests.check(saved.targets.front().observed == value.file().snapshot,
            "readonly_checkpoint_matches_post_close_metadata");
        value.events.trigger.clear();
        value.control.request.store(engine::control_request::proceed);
        const auto resumed = value.run(&saved);
        tests.check(resumed && resumed->status == "completed", "readonly_pause_resume_uses_truthful_snapshot");
    }
    {
        fixture value;
        value.host.add("c:/fixture/z", "volume:02", "disk_b");
        value.file().slow = true;
        value.host.records.at("c:/fixture/z").slow = true;
        value.host.pressure = 95;
        value.options.max_device_workers = 4;
        value.freeze();
        const auto report = value.run();
        tests.check(report && report->status == "completed" && value.host.maximum_total == 1,
            "high_system_pressure_reduces_global_worker_concurrency");
    }
    {
        fixture value;
        value.file().snapshot.media = engine::media_kind::ssd;
        value.file().snapshot.trim_supported = true;
        value.file().trim_discards_bytes = true;
        value.file().injected = fault::remove;
        value.freeze();
        const auto first = value.run();
        tests.check(first && !value.file().deleted && value.store.saved &&
            value.store.saved->targets.front().state == engine::target_state::deleting,
            "trim_then_failed_remove_keeps_recovery_checkpoint");
        auto saved = *value.store.saved;
        tests.check(std::all_of(value.file().streams.at("").begin(), value.file().streams.at("").end(),
            [](std::byte byte)
                {
                    return byte == std::byte{};
                }), "fixture_native_trim_discards_logical_bytes");
        value.file().injected = fault::none;
        const auto resumed = value.run(&saved);
        tests.check(resumed && resumed->status == "completed" &&
            resumed->targets.front().written_bytes == 140000 &&
            resumed->targets.front().verified_bytes == 140000,
            "resume_after_possible_trim_rewrites_and_fully_reverifies");
    }
    {
        fixture value;
        const auto target = value.file().snapshot;
        const auto plan = engine::freeze("00112233445566778899aabbccddeeff", {target, target});
        tests.check(plan && plan->targets.size() == 1, "exact_duplicate_selection_collapses");
    }
    {
        fixture value;
        value.file().snapshot.link_count = 2;
        value.file().snapshot.support = engine::capability::delete_only;
        value.file().snapshot.residual_risks.push_back("other_hardlink_aliases_retained");
        auto alias = value.file();
        alias.snapshot.path = "c:/fixture/alias";
        value.host.records.emplace(alias.snapshot.path, alias);
        value.freeze();
        tests.check(value.plan.targets.size() == 1 && value.plan.targets.front().path == "c:/fixture/alias",
            "hardlink_alias_dedup_chooses_deterministic_namespace");
        value.approval.downgrade_identities.push_back(value.plan.targets.front().identity);
        const auto report = value.run();
        tests.check(report && report->status == "completed" && !value.file().deleted &&
            value.host.records.at("c:/fixture/alias").deleted, "hardlink_other_alias_retained");
        tests.check(value.file().writes == 0 && value.host.records.at("c:/fixture/alias").writes == 0 &&
            report && !report->targets.front().logical_overwrite_verified,
            "hardlink_shared_data_never_overwritten_or_claimed_erased");
    }
    {
        fixture value;
        value.file().snapshot.residual_risks.assign(128, std::string(512, 'r'));
        value.options.memory_budget_bytes = 300000;
        value.freeze();
        const auto report = value.run();
        tests.check(!report && report.error().code == "manifest_and_io_memory_budget_exceeded" &&
            value.file().writes == 0 && value.store.saves == 0,
            "manifest_cost_reserved_before_any_mutation_or_checkpoint");
    }
    {
        fixture value;
        value.options.chunk_bytes = 1;
        value.freeze();
        tests.check(!value.run() && value.file().writes == 0, "invalid_buffer_budget_rejected");
    }
    std::cout << "{\"summary\":true,\"total\":" << tests.total << ",\"passed\":" << tests.passed <<
        ",\"failed\":" << tests.total - tests.passed << "}\n";
    return tests.total == tests.passed ? 0 : 1;
}
