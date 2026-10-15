export module secure_erase.quick_delete;

import std;
export import secure_erase.model;
import secure_erase.platform;

export namespace secure_erase::quick
{
    struct target
    {
        std::string path;
        std::string identity;
        std::string device_key;
        std::uint64_t creation_time{};
        std::uint32_t attributes{};
        bool directory{};
        engine::error preparation_error;
        // CONTRACT: Observed allocation is a scheduling hint, never a guarantee
        // of reclaimable bytes (hardlinks, shared blocks and handles can retain it).
        std::uint64_t allocated_bytes{};
        std::uint64_t logical_size_bytes{};
        bool logical_size_known{};
        bool type_known{};
    };

    struct plan
    {
        std::string job_id;
        std::string fingerprint;
        std::vector<target> targets;
    };

    class root_source
    {
    public:
        virtual ~root_source() = default;
        [[nodiscard]] virtual engine::result<std::optional<std::string>> next() = 0;
    };

    class target_sink
    {
    public:
        virtual ~target_sink() = default;
        [[nodiscard]] virtual engine::result<void> append(target value) = 0;
    };

    struct target_index
    {
        // FORMAT: Lexical canonical-path order, nearest selected ancestor first.
        // Parent is absent or strictly less than this record index; reverse order
        // therefore suffices for child-before-parent final recovery.
        std::uint64_t parent{std::numeric_limits<std::uint64_t>::max()};
        std::uint64_t allocated_bytes{};
        std::uint32_t device_index{std::numeric_limits<std::uint32_t>::max()};
        bool directory{};
        bool preparation_failed{};
        std::array<std::byte, 32> namespace_digest{};
        std::uint64_t logical_size_bytes{};
        bool logical_size_known{};
        bool type_known{};
    };

    struct staged_plan_info
    {
        std::string job_id;
        std::string fingerprint;
        std::size_t target_count{};
        std::uint64_t maximum_target_bytes{};
        std::uint64_t maximum_ancestor_depth{};
        // CONTRACT: Store's bounded resident buffers/indexes, excluding returned
        // per-worker target objects; count these in global admission.
        std::uint64_t resident_bytes{};
        std::vector<std::string> device_keys;
    };

    class target_source
    {
    public:
        virtual ~target_source() = default;
        [[nodiscard]] virtual const staged_plan_info& info() const noexcept = 0;
        // SECURITY: Complete format, scope and fingerprint validation before any
        // deletion. A sealed held file may reuse its already verified result;
        // reopening/importing must validate again. Reads are thread-safe.
        [[nodiscard]] virtual engine::result<void> validate() = 0;
        [[nodiscard]] virtual engine::result<target_index> index(std::size_t position) = 0;
        [[nodiscard]] virtual engine::result<target> load(std::size_t position) = 0;
    };

    struct staged_report
    {
        std::string job_id;
        std::string plan_fingerprint;
        std::string status;
        std::size_t total{};
        std::size_t attempted{};
        std::size_t completed{};
        std::size_t failed{};
        std::size_t unattempted{};
        engine::error stopping_error;
        engine::operation_statistics statistics;
    };

    class outcome_sink
    {
    public:
        virtual ~outcome_sink() = default;
        // SECURITY: Bind/preallocate complete outcome storage before mutation.
        // reuse_completed permits only this live session's prior bound outcomes;
        // a reopened/incomplete job never silently gains exactly-once evidence.
        [[nodiscard]] virtual engine::result<void> begin(
            const staged_plan_info& plan, bool reuse_completed) = 0;
        [[nodiscard]] virtual engine::result<void> record(
            std::size_t position, const engine::target_outcome& value) = 0;
        // CONTRACT: Untouched slots return their bound namespace hash and
        // quick_not_attempted. Diagnostic reads are available for bounded paging.
        [[nodiscard]] virtual engine::result<engine::target_outcome> read(std::size_t position) = 0;
        [[nodiscard]] virtual engine::result<void> finish(const staged_report& value) = 0;
    };

    struct device_resource
    {
        std::string device_key;
        // CONTRACT: Volumes sharing physical media share this budget. Unknown
        // topology uses one conservative common group, never one per drive.
        std::string scheduling_group;
        std::size_t concurrency_hint{1};
        unsigned io_pressure{};
        bool io_pressure_known{};
    };

    struct resource_sample
    {
        std::uint64_t available_memory_bytes{};
        std::uint64_t available_commit_bytes{};
        // CONTRACT: Conservative estimated job headroom, not an OS guarantee.
        std::uint64_t available_handles{};
        std::uint64_t temporary_disk_available_bytes{};
        std::size_t logical_processors{};
        unsigned cpu_pressure{};
        bool cpu_pressure_known{};
        std::vector<device_resource> devices;
    };

    struct space_sample
    {
        std::string volume_key;
        std::uint64_t available_to_caller{};
        std::uint64_t total_free{};
        std::uint64_t total_bytes{};
    };

    struct space_observation
    {
        std::string volume_key;
        std::optional<space_sample> before;
        std::optional<space_sample> after;
        engine::error before_error;
        engine::error after_error;
    };

    // SECURITY: All methods retain frozen identity, nofollow ancestors and system
    // protection. prepare never mutates and preserves per-target failures.
    class backend
    {
    public:
        virtual ~backend() = default;

        [[nodiscard]] virtual engine::result<std::vector<target>> prepare(
            const std::vector<std::string>& paths, engine::control& controls) = 0;

        [[nodiscard]] virtual engine::result<void> prepare_stream(
            root_source& roots, target_sink& output, engine::control& controls)
        {
            static_cast<void>(roots);
            static_cast<void>(output);
            static_cast<void>(controls);
            return std::unexpected(engine::error{"quick_streaming_preparation_not_supported"});
        }

        [[nodiscard]] virtual engine::result<void> begin_execution() = 0;

        // CONTRACT: Read-only, covers each supplied frozen volume exactly once.
        // Resource hints never replace fresh target identity/protection checks.
        [[nodiscard]] virtual engine::result<resource_sample> inspect_resources(
            std::span<const std::string_view> frozen_device_keys)
        {
            static_cast<void>(frozen_device_keys);
            return std::unexpected(engine::error{"quick_resource_probe_not_supported"});
        }

        virtual void finish_execution() noexcept
        {
        }

        // CONTRACT: Read-only sample of the exact frozen volume, under current
        // caller quota. It cannot attribute a change to this job or force release.
        [[nodiscard]] virtual engine::result<space_sample> sample_space(std::string_view volume_key)
        {
            static_cast<void>(volume_key);
            return std::unexpected(engine::error{"quick_space_observation_not_supported"});
        }

        // CONTRACT: false is fast-pass only. true may recover DELETE access and
        // readonly state after the first pass. Neither variant queries processes.
        [[nodiscard]] virtual engine::result<void> remove(const target& value,
            bool recover_access) = 0;

        // CONTRACT: Called only for confirmed final-phase failures. Pin and
        // revalidate the frozen target throughout all process actions.
        [[nodiscard]] virtual engine::result<std::vector<engine::locking_process>> query_locks(
            const target& value) = 0;

        [[nodiscard]] virtual engine::result<void> close_process(const target& value,
            const engine::locking_process& process, bool force_confirmed) = 0;
    };

    // CONTRACT: Read-only, at most 128 unique eligible frozen volume keys;
    // truncation and observation failures remain explicit. Never scans drives.
    void sample_space(backend& host, space_observation& observation, bool before);
    [[nodiscard]] std::pair<std::vector<space_observation>, bool> begin_space_observations(
        backend& host, std::span<const std::string> frozen_device_keys);

    struct progress
    {
        std::string stage;
        std::size_t total{};
        std::size_t attempted{};
        std::size_t completed{};
        std::size_t failed{};
        std::size_t worker_limit{};
        std::uint64_t memory_budget_bytes{};
        std::uint64_t admitted_metadata_bytes{};
        std::size_t concurrency_increases{};
        std::size_t concurrency_decreases{};
        engine::error stopping_error;
        engine::operation_statistics statistics;
    };

    struct options
    {
        // CONTRACT: Zero selects the resource-derived automatic ceiling.
        std::size_t max_workers{};
        bool recover_access{true};
        bool space_first{true};
        // CONTRACT: Zero uses one quarter of current RAM/commit headroom.
        std::uint64_t memory_budget_bytes{};
    };

    struct admission_estimate
    {
        std::uint64_t resident_plan_bytes{};
        std::uint64_t execution_metadata_bytes{};
        std::uint64_t worker_bytes{};
        std::uint64_t handles_per_worker{};
        std::uint64_t memory_budget_bytes{};
        std::size_t worker_capacity{};
        std::size_t worker_limit{};
    };

    // CONTRACT: Conservative owned-state accounting, not a hard process-RSS
    // guarantee. Full resident plan/report admission precedes every mutation.
    [[nodiscard]] engine::result<admission_estimate> estimate_admission(
        const plan& value, const resource_sample& resources, const options& settings = {});

    [[nodiscard]] engine::result<admission_estimate> estimate_admission(
        const staged_plan_info& value, const resource_sample& resources, const options& settings = {});

    // CONTRACT: Advisory selection summary; pending is zero because no execution
    // outcomes exist. Source is finalized/validated; reads authenticated compact
    // metadata and only preparation-refusal records for shared classification.
    // No target observation or backend action occurs.
    [[nodiscard]] engine::result<engine::operation_statistics> summarize_selection(target_source& source);

    using progress_observer = std::function<void(const progress&)>;

    [[nodiscard]] std::string target_key(const target& value);

    [[nodiscard]] std::string fingerprint(const plan& value);

    [[nodiscard]] engine::result<plan> freeze(std::string job_id, std::vector<target> targets);

    class admitted_plan
    {
    public:
        [[nodiscard]] const plan& get() const noexcept
        {
            return *value_;
        }

    private:
        explicit admitted_plan(std::shared_ptr<const plan> value) : value_(std::move(value))
        {
        }

        std::shared_ptr<const plan> value_;
        friend engine::result<admitted_plan> admit(plan value);
        friend engine::result<admitted_plan> freeze_admitted(
            std::string job_id, std::vector<target> targets);
    };

    // CONTRACT: Only these trust-boundary constructors create immutable plans.
    // Runtime resources and target identities are still revalidated on every run.
    [[nodiscard]] engine::result<admitted_plan> admit(plan value);
    [[nodiscard]] engine::result<admitted_plan> freeze_admitted(
        std::string job_id, std::vector<target> targets);

    // CONTRACT: Presentation adapter only; never pass this lightweight plan to
    // the overwrite engine or its checkpoint codec. identities are namespace keys.
    [[nodiscard]] engine::frozen_plan display_plan(const plan& value);

    // CONTRACT: One first pass over frozen names; every failure is deferred until
    // that pass finishes. Final phase may recover access and request normal close.
    // This function never force-terminates a process. Only in-session reports may
    // be supplied as previous; no untrusted serialized report is accepted by UI.
    [[nodiscard]] engine::result<engine::run_report> run(const plan& value,
        std::string_view approved_fingerprint, bool irreversible_confirmed,
        backend& host, engine::control& controls, const options& settings = {},
        progress_observer observer = {}, const engine::run_report* previous = nullptr);
    [[nodiscard]] engine::result<engine::run_report> run(const admitted_plan& value,
        std::string_view approved_fingerprint, bool irreversible_confirmed,
        backend& host, engine::control& controls, const options& settings = {},
        progress_observer observer = {}, const engine::run_report* previous = nullptr);
    [[nodiscard]] engine::result<staged_report> run_staged(target_source& value,
        outcome_sink& outcomes, std::string_view approved_fingerprint,
        bool irreversible_confirmed, backend& host, engine::control& controls,
        const options& settings = {}, progress_observer observer = {},
        bool reuse_completed = false);

}
