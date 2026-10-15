export module secure_erase.configuration;

import std;

// OWNERSHIP: Platform-neutral configuration values do not import an OS adapter.
// CLI parsing can validate these settings without linking a native state store.
export namespace secure_erase::storage
{
    struct store_options
    {
        std::uint64_t log_rotation_bytes{4 * 1024 * 1024};
        std::uint32_t retained_log_files{8};
        std::uint32_t log_retention_days{30};
        // CONTRACT: zero retains incomplete checkpoints until explicit removal/completion.
        // A nonzero value explicitly permits expiry of abandoned incomplete jobs.
        std::uint32_t checkpoint_retention_days{};
    };
}
