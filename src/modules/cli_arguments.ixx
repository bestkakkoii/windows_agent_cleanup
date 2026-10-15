export module secure_erase.cli_arguments;

import std;
export import secure_erase.model;
export import secure_erase.configuration;

export namespace secure_erase::cli
{
    struct arguments
    {
        std::string command{"capabilities"};
        std::uint32_t contract_version{1};
        std::string mode;
        std::string request_id;
        std::string root;
        std::string manifest;
        std::string report_directory;
        std::string job_id;
        std::string fingerprint;
        std::string path;
        std::string target_key;
        std::string image;
        bool irreversible{};
        bool process_close{};
        bool force_terminate{};
        std::uint32_t process_id{};
        std::uint64_t creation_time{};
        std::size_t workers{};
        std::uint64_t memory_budget_bytes{};
        secure_erase::storage::store_options retention;
        engine::options execution_settings;
    };

    [[nodiscard]] std::uint32_t requested_contract_version(std::span<const std::string> tokens) noexcept;
    [[nodiscard]] engine::result<arguments> parse(std::span<const std::string> tokens);
    [[nodiscard]] int report_exit_code(std::string_view status) noexcept;
}
