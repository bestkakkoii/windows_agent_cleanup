export module secure_erase.application;

import std;

export import secure_erase.engine;
export import secure_erase.state_store;
export import secure_erase.windows_backend;
export import secure_erase.quick_delete;

// OWNERSHIP: This is the canonical frontend application interface. All declarations
// below belong to this named module; no header facade or duplicated API exists.
export namespace secure_erase::frontend
{
    struct device_progress
    {
        std::string device_key;
        std::uint64_t transferred_bytes{};
        std::uint64_t total_bytes{};
        double bytes_per_second{};
        double eta_seconds{};
    };

    struct quick_page_item
    {
        std::uint64_t index{};
        quick::target target;
        std::optional<engine::target_outcome> outcome;
    };

    struct quick_page
    {
        std::string job_id;
        std::string fingerprint;
        // CONTRACT: Opaque logical source cursors, not filtered row ordinals.
        std::uint64_t offset{};
        std::uint64_t next_offset{};
        std::uint64_t total{};
        bool failures_only{};
        std::vector<quick_page_item> items;
    };

    struct completed_inputs
    {
        std::string job_id;
        std::string fingerprint;
        std::vector<std::string> paths;
    };

    struct view_state
    {
        bool busy{};
        bool executing{};
        bool resume_loaded{};
        bool quick_mode{};
        bool quick_paged{};
        bool quick_page_loading{};
        std::shared_ptr<const quick_page> quick_page_data;
        std::shared_ptr<const completed_inputs> quick_completed_inputs;
        std::vector<quick::space_observation> quick_space;
        bool quick_space_truncated{};
        std::string quick_stage;
        std::size_t quick_total{};
        std::size_t quick_attempted{};
        std::size_t quick_pending{};
        std::string status{"ready"};
        std::string error_code;
        std::uint32_t native_code{};
        std::shared_ptr<const engine::frozen_plan> plan;
        std::shared_ptr<const engine::run_report> report;
        std::vector<device_progress> devices;
        std::vector<engine::event> recent_events;
        std::vector<storage::checkpoint_info> checkpoints;
        std::vector<engine::locking_process> locks;
        std::string lock_path;
        std::string history;
        std::size_t completed_count{};
        std::size_t failed_count{};
    };

    // CONTRACT: One UI/CLI owner starts operations; every disk operation executes on
    // the worker. snapshot() copies bounded presentation state and immutable plans.
    // SECURITY: Saved jobs restore data only. Fresh, exact-plan consent is mandatory.
    class application
    {
    public:
        using observer = std::function<bool(const engine::event&)>;

        explicit application(observer on_event = {}, storage::store_options settings = {},
            engine::options execution_settings = {});

        ~application();

        application(const application&) = delete;

        application& operator=(const application&) = delete;

        [[nodiscard]] bool preview(std::vector<std::string> paths);

        // CONTRACT: Quick plans exist only in this process. Retry never enumerates
        // paths again and always requires fresh consent for the retained exact plan.
        [[nodiscard]] bool preview_quick(std::vector<std::string> paths);

        [[nodiscard]] bool request_quick_page(std::uint64_t offset, bool failures_only);

        [[nodiscard]] bool execute_quick(std::string fingerprint, bool irreversible_confirmed);

        [[nodiscard]] bool retry_quick(std::string fingerprint, bool irreversible_confirmed);

        [[nodiscard]] bool query_quick_locks(std::string path, std::string fingerprint);

        [[nodiscard]] bool close_quick_process(std::string path, engine::locking_process process,
            bool individual_force_confirmation, std::string fingerprint);

        [[nodiscard]] bool load_job(std::string job_id);

        [[nodiscard]] bool execute(std::string fingerprint, bool irreversible_confirmed,
            std::vector<std::string> downgrade_tokens);

        [[nodiscard]] bool configure_execution(engine::options settings);

        [[nodiscard]] bool configure_quick(quick::options settings);

        [[nodiscard]] bool refresh_history();

        [[nodiscard]] bool query_locks(std::string path);

        [[nodiscard]] bool close_process(std::string path, engine::locking_process process,
            bool individual_force_confirmation);

        void pause() noexcept;

        void cancel() noexcept;

        [[nodiscard]] view_state snapshot(bool include_details = true) const;

        void wait();

    private:
        struct implementation;
        std::unique_ptr<implementation> state_;
    };

    [[nodiscard]] std::string_view capability_name(engine::capability value) noexcept;

    [[nodiscard]] std::string_view media_name(engine::media_kind value) noexcept;

    [[nodiscard]] std::string downgrade_token(const engine::target_snapshot& target);

    [[nodiscard]] std::string json_quote(std::string_view value);

    [[nodiscard]] std::string event_json(const engine::event& value);

    [[nodiscard]] std::string report_json(const engine::run_report& value);

    [[nodiscard]] engine::result<std::string> utf8(std::wstring_view value);

    [[nodiscard]] engine::result<std::wstring> utf16(std::string_view value);
}
