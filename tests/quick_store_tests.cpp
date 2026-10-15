import std;
import secure_erase.quick_store;

namespace
{
namespace quick = secure_erase::quick;
namespace store = secure_erase::quick::store;
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

struct faults
{
    std::uint64_t available{1024ULL * 1024 * 1024};
    std::optional<std::size_t> writes_remaining;
    bool fail_resize{};
    bool fail_flush{};
    std::mutex mutex;
};

class disk_file final : public store::random_access_file
{
public:
    disk_file(std::filesystem::path path, std::shared_ptr<faults> behavior) :
        path_(std::move(path)), faults_(std::move(behavior)),
        stream_(path_, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc)
    {
    }

    engine::result<void> read_at(std::uint64_t offset, std::span<std::byte> output) override
    {
        const std::scoped_lock lock(mutex_);
        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(offset));
        stream_.read(reinterpret_cast<char*>(output.data()), static_cast<std::streamsize>(output.size()));
        if (!stream_ || stream_.gcount() != static_cast<std::streamsize>(output.size()))
        {
            return std::unexpected(engine::error{"fixture_read_failed"});
        }
        return {};
    }

    engine::result<void> write_at(std::uint64_t offset, std::span<const std::byte> input) override
    {
        const std::scoped_lock lock(mutex_, faults_->mutex);
        if (faults_->writes_remaining)
        {
            if (*faults_->writes_remaining == 0)
            {
                return std::unexpected(engine::error{"fixture_disk_full"});
            }
            --*faults_->writes_remaining;
        }
        stream_.clear();
        stream_.seekp(static_cast<std::streamoff>(offset));
        stream_.write(reinterpret_cast<const char*>(input.data()), static_cast<std::streamsize>(input.size()));
        if (!stream_)
        {
            return std::unexpected(engine::error{"fixture_write_failed"});
        }
        return {};
    }

    engine::result<void> resize(std::uint64_t bytes) override
    {
        if (faults_->fail_resize)
        {
            return std::unexpected(engine::error{"fixture_reserve_failed"});
        }
        std::array<std::byte, 4096> zeros{};
        for (std::uint64_t offset = 0; offset < bytes;)
        {
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(zeros.size(), bytes - offset));
            auto written = write_at(offset, std::span(zeros).first(count));
            if (!written)
            {
                return written;
            }
            offset += count;
        }
        return flush();
    }

    engine::result<void> flush() override
    {
        const std::scoped_lock lock(mutex_);
        if (faults_->fail_flush)
        {
            return std::unexpected(engine::error{"fixture_flush_failed"});
        }
        stream_.flush();
        if (!stream_)
        {
            return std::unexpected(engine::error{"fixture_flush_failed"});
        }
        return {};
    }

    engine::result<std::uint64_t> size() const override
    {
        const std::scoped_lock lock(mutex_);
        stream_.flush();
        std::error_code error;
        const auto result = std::filesystem::file_size(path_, error);
        if (error)
        {
            return std::unexpected(engine::error{"fixture_size_failed"});
        }
        return result;
    }

    bool corrupt(std::uint64_t offset)
    {
        std::array<std::byte, 1> byte{};
        auto read = read_at(offset, byte);
        if (!read)
        {
            return false;
        }
        byte[0] ^= std::byte{0x55};
        return write_at(offset, byte).has_value() && flush().has_value();
    }

private:
    std::filesystem::path path_;
    std::shared_ptr<faults> faults_;
    mutable std::fstream stream_;
    mutable std::mutex mutex_;
};

class disk_factory final : public store::file_factory
{
public:
    explicit disk_factory(std::filesystem::path root) : root(std::move(root))
    {
        if (!std::filesystem::create_directory(this->root))
        {
            throw std::runtime_error("fixture_directory_not_exclusively_created");
        }
    }

    engine::result<std::shared_ptr<store::random_access_file>> create_private(std::string_view name) override
    {
        if (name.find_first_of("/\\") != std::string_view::npos || files.contains(std::string(name)))
        {
            return std::unexpected(engine::error{"fixture_name_invalid"});
        }
        auto file = std::make_shared<disk_file>(root / std::string(name), behavior);
        files.emplace(std::string(name), file);
        return std::static_pointer_cast<store::random_access_file>(file);
    }

    engine::result<void> remove_private(std::string_view name) override
    {
        const auto found = files.find(std::string(name));
        if (found == files.end())
        {
            return std::unexpected(engine::error{"fixture_not_owned"});
        }
        files.erase(found);
        std::error_code error;
        std::filesystem::remove(root / std::string(name), error);
        if (error)
        {
            return std::unexpected(engine::error{"fixture_remove_failed"});
        }
        return {};
    }

    engine::result<std::uint64_t> available_bytes() override
    {
        ++available_queries;
        return behavior->available;
    }

    std::shared_ptr<disk_file> with_size(std::uint64_t bytes)
    {
        for (const auto& [name, file] : files)
        {
            static_cast<void>(name);
            if (file->size() == bytes)
            {
                return file;
            }
        }
        return {};
    }

    std::filesystem::path root;
    std::size_t available_queries{};
    std::shared_ptr<faults> behavior{std::make_shared<faults>()};
    std::map<std::string, std::shared_ptr<disk_file>> files;
};

[[nodiscard]] quick::target target(std::string path, bool directory = false, std::string identity = {})
{
    if (identity.empty())
    {
        identity = "identity:" + path;
    }
    quick::target result;
    result.path = std::move(path);
    result.identity = std::move(identity);
    result.device_key = "device:1";
    result.creation_time = 123;
    result.directory = directory;
    result.allocated_bytes = directory ? 0 : 4096;
    result.type_known = true;
    result.logical_size_known = true;
    result.logical_size_bytes = directory ? 0 : 13;
    return result;
}

constexpr std::string_view job_id = "0123456789abcdef0123456789abcdef";
constexpr store::options budgets{65536, 128ULL * 1024 * 1024};

[[nodiscard]] std::unique_ptr<store::staging_store> builder(std::shared_ptr<disk_factory> files,
    store::options settings = budgets)
{
    return store::staging_store::create(std::move(files), std::string(job_id), settings).value();
}

[[nodiscard]] store::batch one(std::shared_ptr<disk_factory> files)
{
    auto staging = builder(std::move(files));
    staging->append(target("C:\\fixture\\file")).value();
    return staging->finalize().value();
}
}

int main()
{
    test_results tests;
    const auto fixture = std::filesystem::temp_directory_path() /
        ("windows_agent_cleanup_store_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    if (!std::filesystem::create_directory(fixture))
    {
        std::cerr << "{\"error\":\"fixture_directory_not_exclusively_created\"}\n";
        return 2;
    }
    struct cleanup
    {
        std::filesystem::path path;
        ~cleanup()
        {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    } guard{fixture};
    const auto factory = [&](std::string_view name)
    {
        return std::make_shared<disk_factory>(fixture / name);
    };

    tests.check(!store::staging_store::create(factory("zero"), std::string(job_id), {}), "zero_budgets_rejected");
    tests.check(!store::staging_store::create(factory("job"), "../escape", budgets), "unsafe_job_id_rejected");
    {
        auto files = factory("empty");
        auto stage = builder(files);
        tests.check(!stage->finalize(), "empty_plan_rejected");
    }
    {
        auto files = factory("large");
        auto stage = builder(files);
        bool appended = true;
        for (int index = 1999; index >= 0; --index)
        {
            auto value = target("C:\\fixture\\dir\\file_" + std::format("{:04}", index));
            appended = appended && stage->append(value).has_value();
            if (index % 100 == 0)
            {
                appended = appended && stage->append(std::move(value)).has_value();
            }
        }
        appended = appended && stage->append(target("C:\\fixture\\dir", true)).has_value();
        appended = appended && stage->append(target("C:\\fixture\\dir-other")).has_value();
        tests.check(appended, "streaming_reverse_many_runs_append");
        auto result = stage->finalize();
        tests.check(result.has_value(), "external_merge_admits_complete_batch");
        if (result)
        {
            tests.check(result->targets->info().target_count == 2002, "dedup_preserves_all_unique_names");
            tests.check(result->metrics.duplicate_targets == 20, "duplicates_counted_across_runs");
            tests.check(result->metrics.run_count > 1 && result->metrics.merge_passes > 1, "bounded_external_runs_actually_used");
            tests.check(result->metrics.peak_buffer_bytes <= budgets.memory_budget_bytes / 4,
                "resident_string_buffer_within_admitted_budget");
            tests.check(result->targets->info().resident_bytes < budgets.memory_budget_bytes,
                "sealed_store_reports_bounded_residency");
            tests.check(result->targets->validate().has_value(), "complete_frozen_integrity_validates");
            tests.check(files->available_queries < 1000, "disk_space_probe_batched_at_run_boundaries");
            tests.check(result->metrics.target_text_bytes > 2002 * 20,
                "report_capacity_uses_checked_unique_text_total");
            bool sorted = true;
            bool exact_parent = false;
            std::string previous;
            for (std::size_t position = 0; position < result->targets->info().target_count; ++position)
            {
                auto value = result->targets->load(position);
                sorted = sorted && value && (position == 0 || previous < value->path);
                if (value)
                {
                    previous = value->path;
                    if (value->path == "C:\\fixture\\dir\\file_0000")
                    {
                        auto node = result->targets->index(position);
                        auto parent = node ? result->targets->load(static_cast<std::size_t>(node->parent)) :
                            engine::result<quick::target>(std::unexpected(engine::error{"no_parent"}));
                        exact_parent = parent && parent->path == "C:\\fixture\\dir";
                    }
                }
            }
            tests.check(sorted, "canonical_path_order_with_paged_load");
            tests.check(exact_parent, "prefix_sibling_cannot_erase_parent_dependency");
            tests.check(!stage->append(target("C:\\late")) && !stage->finalize(), "frozen_membership_closed_to_late_append");
            stage.reset();
            tests.check(files->files.size() == 3, "obsolete_runs_released_live_source_retained");
            auto wrong = result->targets->info();
            wrong.fingerprint[0] = wrong.fingerprint[0] == 'a' ? 'b' : 'a';
            tests.check(!result->outcomes->begin(wrong, false), "outcome_storage_binds_exact_fingerprint");
            tests.check(result->outcomes->begin(result->targets->info(), false).has_value(), "outcome_storage_preallocated_before_begin");
            auto untouched = result->outcomes->read(0);
            tests.check(untouched && untouched->code == "quick_not_attempted" && !untouched->deleted,
                "untouched_outcome_remains_explicitly_unattempted");
            auto outcome = untouched.value();
            outcome.code = "deleted_quick_namespace_removed";
            outcome.deleted = true;
            outcome.remove_attempted = true;
            tests.check(result->outcomes->record(0, outcome).has_value(), "indexed_success_recorded");
            tests.check(result->outcomes->read(0)->deleted && result->outcomes->read(0)->remove_attempted,
                "indexed_success_and_unique_remove_attempt_round_trip");
            auto forged = outcome;
            forged.identity = "another_identity";
            tests.check(!result->outcomes->record(1, forged), "outcome_identity_substitution_rejected");
            forged = outcome;
            forged.physical_sanitization_guaranteed = true;
            tests.check(!result->outcomes->record(0, forged), "physical_sanitization_claim_rejected");
            forged = outcome;
            forged.deleted = false;
            forged.code.assign(513, 'x');
            tests.check(!result->outcomes->record(0, forged), "oversized_error_code_rejected_without_truncation");
            quick::staged_report report;
            report.job_id = result->targets->info().job_id;
            report.plan_fingerprint = result->targets->info().fingerprint;
            report.status = "cancelled_partial";
            report.total = 2002;
            report.attempted = 1;
            report.completed = 1;
            report.unattempted = 2001;
            tests.check(result->outcomes->finish(report).has_value(), "final_outcomes_flushed_before_acknowledgment");
            tests.check(!result->outcomes->begin(result->targets->info(), false), "second_run_cannot_reset_existing_evidence");
            tests.check(result->outcomes->begin(result->targets->info(), true).has_value(), "live_session_exact_batch_reuse_permitted");
            tests.check(result->outcomes->read(0)->deleted, "live_reuse_preserves_completed_proof");
            tests.check(result->outcomes->finish(report).has_value(), "live_reuse_finish");
            result->targets.reset();
            result->outcomes.reset();
            tests.check(files->files.empty(), "last_owner_closes_all_ephemeral_files");
        }
    }
    {
        auto files = factory("conflict");
        auto stage = builder(files);
        stage->append(target("C:\\fixture\\same", false, "original")).value();
        bool appended = true;
        for (int index = 0; index < 300; ++index)
        {
            appended = appended && stage->append(target("C:\\fixture\\x" + std::to_string(index))).has_value();
        }
        const auto conflict = stage->append(target("C:\\fixture\\same", false, "replacement"));
        const auto final = stage->finalize();
        tests.check(appended && (!conflict || !final), "cross_run_identity_conflict_rejects_whole_batch");
    }
    {
        auto files = factory("invalid");
        auto stage = builder(files);
        stage->append(target("C:\\valid")).value();
        auto invalid = target(std::string("C:\\bad") + static_cast<char>(0xff));
        tests.check(!stage->append(std::move(invalid)) && !stage->finalize(), "invalid_utf8_failure_is_sticky_no_partial_batch");
    }
    {
        auto stage = builder(factory("long"));
        tests.check(!stage->append(target("C:\\" + std::string(5000, 'x'))) && !stage->finalize(),
            "single_record_larger_than_resource_buffer_rejected");
    }
    {
        auto files = factory("hardlinks");
        auto stage = builder(files);
        stage->append(target("C:\\one", false, "shared_object")).value();
        stage->append(target("C:\\two", false, "shared_object")).value();
        const auto result = stage->finalize();
        tests.check(result && result->targets->info().target_count == 2, "hardlink_names_not_deduplicated_by_identity");
    }
    {
        auto files = factory("tamper_record");
        auto result = one(files);
        std::shared_ptr<disk_file> record;
        for (const auto& [name, file] : files->files)
        {
            static_cast<void>(name);
            const auto size = file->size().value();
            if (size != 152 && size != 576)
            {
                record = file;
            }
        }
        tests.check(record && record->corrupt(12), "record_tamper_fixture_written");
        tests.check(!result.targets->validate() && !result.targets->load(0), "record_tamper_rejected_by_full_validation_and_page_load");
    }
    {
        auto files = factory("tamper_length");
        auto result = one(files);
        bool corrupted = false;
        for (const auto& [name, file] : files->files)
        {
            static_cast<void>(name);
            if (file->size() != 152 && file->size() != 576)
            {
                std::array<std::byte, 8> length;
                length.fill(std::byte{0xff});
                corrupted = file->write_at(0, length).has_value() && file->flush().has_value();
            }
        }
        tests.check(corrupted && !result.targets->load(0), "hostile_record_length_rejected_before_allocation");
    }
    {
        auto files = factory("tamper_index");
        auto result = one(files);
        tests.check(files->with_size(152)->corrupt(20) && !result.targets->index(0) && !result.targets->validate(),
            "compact_index_tamper_rejected");
        tests.check(!result.targets->load(1) && !result.outcomes->read(1), "out_of_range_page_reads_rejected");
    }
    {
        auto files = factory("tamper_outcome");
        auto result = one(files);
        result.outcomes->begin(result.targets->info(), false).value();
        auto outcome = result.outcomes->read(0).value();
        outcome.code = "quick_target_open_failed";
        outcome.native_code = 32;
        result.outcomes->record(0, outcome).value();
        tests.check(files->with_size(576)->corrupt(34) && !result.outcomes->read(0),
            "outcome_record_integrity_checked");
    }
    {
        auto files = factory("outcome_swap");
        auto stage = builder(files);
        stage->append(target("C:\\first")).value();
        stage->append(target("C:\\second")).value();
        auto result = stage->finalize().value();
        result.outcomes->begin(result.targets->info(), false).value();
        auto outcome = result.outcomes->read(0).value();
        outcome.code = "deleted_quick_namespace_removed";
        outcome.deleted = true;
            outcome.remove_attempted = true;
        result.outcomes->record(0, outcome).value();
        auto file = files->with_size(1152);
        std::array<std::byte, 576> copied{};
        const auto copied_record = file->read_at(0, copied).has_value() &&
            file->write_at(576, copied).has_value() && file->flush().has_value();
        tests.check(copied_record && !result.outcomes->read(1),
            "intact_outcome_cannot_be_replayed_into_another_target_slot");
    }
    {
        auto files = factory("disk_budget");
        auto stage = builder(files, {65536, 600});
        stage->append(target("C:\\fixture\\file")).value();
        tests.check(!stage->finalize(), "complete_index_and_outcome_reservation_must_fit_disk_budget");
    }
    {
        auto files = factory("disk_available");
        files->behavior->available = 10;
        auto stage = builder(files);
        stage->append(target("C:\\fixture\\file")).value();
        tests.check(!stage->finalize(), "live_disk_headroom_failure_precedes_mutation");
    }
    {
        auto files = factory("write_failure");
        files->behavior->writes_remaining = 3;
        auto stage = builder(files);
        bool failed = false;
        for (int index = 0; index < 100; ++index)
        {
            if (!stage->append(target("C:\\fixture\\" + std::to_string(index))))
            {
                failed = true;
                break;
            }
        }
        tests.check(failed && !stage->finalize(), "spill_io_failure_is_sticky_and_never_yields_partial_source");
    }
    {
        auto files = factory("reserve_failure");
        files->behavior->fail_resize = true;
        auto stage = builder(files);
        stage->append(target("C:\\fixture\\file")).value();
        tests.check(!stage->finalize(), "outcome_preallocation_failure_rejects_plan");
    }
    {
        auto files = factory("flush_failure");
        files->behavior->fail_flush = true;
        auto stage = builder(files);
        stage->append(target("C:\\fixture\\file")).value();
        tests.check(!stage->finalize(), "unflushed_plan_is_never_executable");
    }
    {
        auto first_files = factory("fingerprint_a");
        auto second_files = factory("fingerprint_b");
        auto first = builder(first_files);
        auto second = builder(second_files);
        first->append(target("C:\\a")).value();
        first->append(target("C:\\b")).value();
        second->append(target("C:\\b")).value();
        second->append(target("C:\\a")).value();
        auto a = first->finalize().value();
        auto b = second->finalize().value();
        tests.check(a.targets->info().fingerprint == b.targets->info().fingerprint,
            "frozen_fingerprint_independent_of_input_order");
    }
    {
        auto files = factory("threads");
        auto stage = builder(files);
        std::atomic<bool> good{true};
        std::vector<std::jthread> writers;
        for (int thread = 0; thread < 4; ++thread)
        {
            writers.emplace_back([&, thread]
            {
                for (int index = 0; index < 100; ++index)
                {
                    if (!stage->append(target("C:\\" + std::to_string(thread) + "_" + std::to_string(index))))
                    {
                        good.store(false);
                    }
                }
            });
        }
        writers.clear();
        auto result = stage->finalize();
        tests.check(good && result && result->targets->info().target_count == 400,
            "parallel_preparation_append_is_thread_safe");
        if (result)
        {
            std::vector<std::jthread> readers;
            for (std::size_t thread = 0; thread < 4; ++thread)
            {
                readers.emplace_back([&, thread]
                {
                    for (std::size_t index = thread; index < 400; index += 4)
                    {
                        if (!result->targets->load(index) || !result->targets->index(index))
                        {
                            good.store(false);
                        }
                    }
                });
            }
            readers.clear();
            tests.check(good, "parallel_worker_page_reads_are_thread_safe");
        }
    }
    {
        auto files = factory("beyond_historical_cap");
        auto stage = builder(files, {16ULL * 1024 * 1024, 256ULL * 1024 * 1024});
        bool accepted = stage->append(target("C:\\bulk", true)).has_value();
        for (std::size_t index = 0; index < 100001 && accepted; ++index)
        {
            accepted = stage->append(target("C:\\bulk\\" + std::format("{:06}", index))).has_value();
        }
        auto result = stage->finalize();
        tests.check(accepted && result && result->targets->info().target_count == 100002,
            "more_than_one_hundred_thousand_targets_admitted_by_resources");
        tests.check(result && result->metrics.peak_buffer_bytes <= 4ULL * 1024 * 1024,
            "large_batch_full_path_residency_remains_bounded");
    }
    {
        auto files = factory("logical_metadata");
        auto stage = builder(files);
        auto known = target("C:\\metadata\\known");
        known.logical_size_bytes = 27;
        quick::target unknown;
        unknown.path = "C:\\metadata\\unknown";
        unknown.preparation_error = {"metadata_denied", 5};
        stage->append(known).value();
        stage->append(unknown).value();
        auto batch = stage->finalize().value();
        const auto restored = batch.targets->load(0);
        const auto indexed = batch.targets->index(0);
        tests.check(restored && indexed && restored->type_known && restored->logical_size_known &&
            restored->logical_size_bytes == 27 && indexed->type_known && indexed->logical_size_known &&
            indexed->logical_size_bytes == 27,
            "frozen_record_and_index_preserve_known_default_stream_snapshot");
        const auto statistics = quick::summarize_selection(*batch.targets);
        tests.check(statistics && statistics->selected.files == 1 && statistics->selected.unclassified == 1 &&
            statistics->logical_bytes.selected == 27 && statistics->logical_bytes.selected_unknown == 1 &&
            statistics->failed == 1 && statistics->pending == 0 && statistics->final_failures.access_lock == 1,
            "frozen_scan_statistics_preserve_unclassified_preparation_refusal");
        auto alternate = builder(factory("logical_metadata_alternate"));
        known.logical_size_bytes = 28;
        alternate->append(known).value();
        alternate->append(unknown).value();
        auto changed = alternate->finalize().value();
        tests.check(changed.targets->info().fingerprint != batch.targets->info().fingerprint,
            "staged_fingerprint_binds_logical_snapshot_metadata");
        auto invalid = target("C:\\metadata\\invalid");
        invalid.logical_size_known = false;
        auto rejected = builder(factory("logical_metadata_invalid"));
        tests.check(!rejected->append(invalid), "unknown_logical_size_cannot_carry_fabricated_bytes");
    }
    std::cout << "{\"total\":" << tests.total << ",\"passed\":" << tests.passed << "}\n";
    return tests.total == tests.passed ? 0 : 1;
}
