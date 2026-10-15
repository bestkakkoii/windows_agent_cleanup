export module secure_erase.model;

import std;

export namespace secure_erase::engine
{
enum class capability : std::uint8_t
{
    blocked,
    overwrite_verified,
    overwrite_best_effort,
    delete_only
};

enum class media_kind : std::uint8_t
{
    unknown,
    hdd,
    ssd,
    usb
};

struct locking_process
{
    std::uint32_t process_id{};
    std::uint64_t creation_time{};
    std::string image_path;
    bool eligible{};
    std::string denial_reason;
};

struct error
{
    std::string code;
    std::uint32_t native_code{};
    bool device_fault{};
};

template<class value_type>
using result = std::expected<value_type, error>;

struct stream_snapshot
{
    std::string name; // CONTRACT: UTF-8, unnamed stream represented by empty string.
    std::uint64_t size{};
    bool operator==(const stream_snapshot&) const = default;
};

struct target_snapshot
{
    std::string path; // CONTRACT: absolute normalized UTF-8 display path.
    std::string identity; // CONTRACT: volume identity + complete persistent file identifier.
    std::string device_key;
    std::uint64_t creation_time{};
    std::uint64_t write_time{};
    std::uint64_t change_time{};
    std::uint32_t attributes{};
    std::uint32_t link_count{1};
    bool directory{};
    bool reparse_point{};
    bool remote{};
    bool encrypted{};
    bool compressed{};
    bool sparse{};
    bool trim_supported{};
    bool vss_query_complete{};
    std::uint32_t vss_snapshot_count{};
    std::uint32_t vss_native_error{};
    media_kind media{media_kind::unknown};
    capability support{capability::blocked};
    std::vector<stream_snapshot> streams;
    std::vector<std::string> protection_reasons;
    std::vector<std::string> residual_risks;
    bool operator==(const target_snapshot&) const = default;
};

struct frozen_plan
{
    std::string job_id;
    std::vector<target_snapshot> targets;
    std::string fingerprint;
};

struct approval
{
    std::string plan_fingerprint;
    bool execute{};
    std::vector<std::string> downgrade_identities;
};

enum class target_state : std::uint8_t
{
    pending,
    writing,
    verifying,
    verified,
    deleting,
    completed,
    failed,
    skipped
};

struct target_checkpoint
{
    std::string identity;
    target_snapshot observed; // CONTRACT: metadata recorded while original identity is held.
    std::array<std::byte, 32> key{};
    std::array<std::byte, 12> nonce{};
    bool key_ready{};
    std::size_t stream_index{};
    std::uint64_t offset{};
    target_state state{target_state::pending};
};

struct checkpoint
{
    std::uint32_t schema_version{1};
    frozen_plan plan;
    std::vector<target_checkpoint> targets;
};

struct event
{
    std::string code;
    std::string job_id;
    std::string identity;
    std::uint64_t bytes_done{};
    std::uint64_t bytes_total{};
    std::uint32_t native_code{};
    // CONTRACT: Optional item counts for namespace-delete lifecycle events;
    // byte progress fields retain their original units and meaning.
    std::uint64_t total_targets{};
    std::uint64_t completed_targets{};
    std::uint64_t failed_targets{};
};

enum class control_request : std::uint8_t
{
    proceed,
    pause,
    cancel
};

struct target_outcome
{
    std::string identity;
    std::string code;
    bool deleted{};
    bool logical_overwrite_verified{};
    bool physical_sanitization_guaranteed{}; // INVARIANT: always false for file API.
    std::uint64_t written_bytes{};
    std::uint64_t verified_bytes{};
    std::uint32_t native_code{};
};

struct run_report
{
    std::string job_id;
    std::string status;
    std::vector<target_outcome> targets;
    // CONTRACT: Quick in-session retry binds prior outcomes to this exact plan.
    // Legacy overwrite reports leave this empty; their checkpoints own binding.
    std::string plan_fingerprint{};
    // A job-level stop does not turn unattempted targets into attempted failures.
    error stopping_error{};
};

struct options
{
    std::size_t chunk_bytes{1024 * 1024};
    std::size_t max_device_workers{4};
    std::size_t ssd_queue_depth{2};
    std::size_t memory_budget_bytes{64 * 1024 * 1024};
    std::uint64_t io_budget_bytes_per_second{}; // Zero means unthrottled.
    bool adaptive_io{true};
};
}
