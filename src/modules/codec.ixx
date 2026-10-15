export module secure_erase.codec;

import std;
export import secure_erase.model;

export namespace secure_erase::storage
{
    struct codec_limits
    {
        static constexpr std::size_t maximum_checkpoint_bytes{64 * 1024 * 1024};
        // FORMAT: Counts occupy four bytes; working allocation is separately budgeted.
        static constexpr std::size_t maximum_targets{std::numeric_limits<std::uint32_t>::max()};
        static constexpr std::size_t maximum_streams{1024};
        static constexpr std::size_t maximum_string_bytes{131072};
    };

    // SECURITY: Plaintext encoding contains key material. Caller owns prompt clearing;
    // Windows store guarantees clearing before releasing temporary allocations.
    [[nodiscard]] engine::result<std::vector<std::byte>> encode_checkpoint(
        const engine::checkpoint& value,
        std::size_t maximum_bytes = codec_limits::maximum_checkpoint_bytes);

    // SECURITY: Bounded, strict, versioned binary format; authenticating is store-owned.
    // Decode does not restore live execution authorization. Fingerprint is rechecked.
    [[nodiscard]] engine::result<engine::checkpoint> decode_checkpoint(
        std::span<const std::byte> bytes,
        std::size_t maximum_bytes = codec_limits::maximum_checkpoint_bytes);

    [[nodiscard]] bool valid_job_id(std::string_view value) noexcept;

    [[nodiscard]] bool valid_utf8(std::string_view value) noexcept;

    [[nodiscard]] std::string event_json(const engine::event& value, std::uint64_t utc_filetime);

    void clear_sensitive(engine::checkpoint& value) noexcept;

    void clear_sensitive(std::span<std::byte> value) noexcept;
}
