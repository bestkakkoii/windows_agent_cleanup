export module secure_erase.crypto;

import std;

export namespace secure_erase::crypto
{
using key = std::array<std::byte, 32>;
using nonce = std::array<std::byte, 12>;
using digest = std::array<std::byte, 32>;

// SECURITY: IETF ChaCha20, initial counter zero; rejects counter wrap before output.
[[nodiscard]] bool chacha20(const key& secret, const nonce& iv, std::uint64_t offset,
    std::span<std::byte> output) noexcept;

[[nodiscard]] digest sha256(std::span<const std::byte> input) noexcept;

[[nodiscard]] std::string hex_digest(const digest& value);

void secure_zero(std::span<std::byte> value) noexcept;

[[nodiscard]] digest hmac_sha256(std::span<const std::byte> secret,
    std::span<const std::byte> input) noexcept;

// SECURITY: Domain-separated segment keys extend the stream without counter reuse.
// Rejects offset + output.size() overflow before modifying any output bytes.
[[nodiscard]] bool stream_bytes(const key& secret, const nonce& iv,
    std::uint64_t stream_index, std::uint64_t offset,
    std::span<std::byte> output) noexcept;
}
