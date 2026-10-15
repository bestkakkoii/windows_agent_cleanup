export module secure_erase.agent_protocol;

import std;
export import secure_erase.model;

export namespace secure_erase::agent
{
    struct manifest_entry
    {
        std::string path;
        std::optional<engine::capability> downgrade;
    };

    // CONTRACT: The bound follows Windows' path limit and worst-case JSON escaping,
    // not a target-count ceiling. Aggregate admission is performed by the caller.
    inline constexpr std::size_t maximum_record_bytes = 6 * 32767 + 256;
    [[nodiscard]] engine::result<manifest_entry> parse_manifest_line(std::string_view text);
    [[nodiscard]] engine::result<std::string> normalize_path(std::string_view text);
    [[nodiscard]] bool within_scope(std::string_view path, std::string_view root) noexcept;
    [[nodiscard]] std::string json_quote(std::string_view text);
}
