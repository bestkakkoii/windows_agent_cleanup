module secure_erase.crypto;

import std;

namespace secure_erase::crypto
{
namespace
{
    std::uint32_t load_little(const std::byte* value) noexcept
    {
        return std::to_integer<std::uint32_t>(value[0]) |
            (std::to_integer<std::uint32_t>(value[1]) << 8) |
            (std::to_integer<std::uint32_t>(value[2]) << 16) |
            (std::to_integer<std::uint32_t>(value[3]) << 24);
    }

    std::uint32_t load_big(const std::byte* value) noexcept
    {
        return (std::to_integer<std::uint32_t>(value[0]) << 24) |
            (std::to_integer<std::uint32_t>(value[1]) << 16) |
            (std::to_integer<std::uint32_t>(value[2]) << 8) |
            std::to_integer<std::uint32_t>(value[3]);
    }

    void store_little(std::byte* output, std::uint32_t value) noexcept
    {
        for (unsigned shift = 0; shift < 32; shift += 8)
        {
            output[shift / 8] = static_cast<std::byte>((value >> shift) & 0xffU);
        }
    }

    void store_big(std::byte* output, std::uint32_t value) noexcept
    {
        for (unsigned shift = 0; shift < 32; shift += 8)
        {
            output[3 - shift / 8] = static_cast<std::byte>((value >> shift) & 0xffU);
        }
    }

    void quarter_round(std::uint32_t& a, std::uint32_t& b,
        std::uint32_t& c, std::uint32_t& d) noexcept
    {
        a += b;
        d = std::rotl(d ^ a, 16);
        c += d;
        b = std::rotl(b ^ c, 12);
        a += b;
        d = std::rotl(d ^ a, 8);
        c += d;
        b = std::rotl(b ^ c, 7);
    }

    void chacha_block(const std::array<std::uint32_t, 16>& initial,
        std::span<std::byte, 64> output) noexcept
    {
        auto state = initial;
        // CONTRACT: RFC 8439 section 2.3, ten column/diagonal double rounds.
        for (unsigned round = 0; round < 10; ++round)
        {
            quarter_round(state[0], state[4], state[8], state[12]);
            quarter_round(state[1], state[5], state[9], state[13]);
            quarter_round(state[2], state[6], state[10], state[14]);
            quarter_round(state[3], state[7], state[11], state[15]);
            quarter_round(state[0], state[5], state[10], state[15]);
            quarter_round(state[1], state[6], state[11], state[12]);
            quarter_round(state[2], state[7], state[8], state[13]);
            quarter_round(state[3], state[4], state[9], state[14]);
        }

        for (std::size_t index = 0; index < state.size(); ++index)
        {
            store_little(output.data() + index * 4, state[index] + initial[index]);
        }

        secure_zero(std::as_writable_bytes(std::span(state)));
    }

    void sha256_block(std::array<std::uint32_t, 8>& state,
        const std::byte* input) noexcept
    {
        // CONTRACT: SHA-256 constants and compression in FIPS 180-4/RFC 6234.
        constexpr std::array<std::uint32_t, 64> constants
        {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
            0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
            0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
            0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
            0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
            0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
            0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
            0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
            0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
        };
        std::array<std::uint32_t, 64> words{};
        for (std::size_t index = 0; index < 16; ++index)
        {
            words[index] = load_big(input + index * 4);
        }

        for (std::size_t index = 16; index < words.size(); ++index)
        {
            const auto first = std::rotr(words[index - 15], 7) ^
                std::rotr(words[index - 15], 18) ^ (words[index - 15] >> 3);
            const auto second = std::rotr(words[index - 2], 17) ^
                std::rotr(words[index - 2], 19) ^ (words[index - 2] >> 10);
            words[index] = words[index - 16] + first + words[index - 7] + second;
        }

        auto work = state;
        for (std::size_t index = 0; index < words.size(); ++index)
        {
            const auto upper = std::rotr(work[4], 6) ^ std::rotr(work[4], 11) ^
                std::rotr(work[4], 25);
            const auto choice = (work[4] & work[5]) ^ (~work[4] & work[6]);
            const auto first = work[7] + upper + choice + constants[index] + words[index];
            const auto lower = std::rotr(work[0], 2) ^ std::rotr(work[0], 13) ^
                std::rotr(work[0], 22);
            const auto majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^
                (work[1] & work[2]);
            const auto second = lower + majority;
            work[7] = work[6];
            work[6] = work[5];
            work[5] = work[4];
            work[4] = work[3] + first;
            work[3] = work[2];
            work[2] = work[1];
            work[1] = work[0];
            work[0] = first + second;
        }

        for (std::size_t index = 0; index < state.size(); ++index)
        {
            state[index] += work[index];
        }

        secure_zero(std::as_writable_bytes(std::span(words)));
        secure_zero(std::as_writable_bytes(std::span(work)));
    }
}

bool chacha20(const key& secret, const nonce& iv, std::uint64_t offset,
    std::span<std::byte> output) noexcept
{
    constexpr std::uint64_t stream_limit = std::uint64_t{1} << 38;
    // SECURITY: Subtraction after bounds validation prevents both addition overflow
    // and counter reuse. Reject the complete request before writing any output.
    if (offset > stream_limit || output.size() > stream_limit - offset)
    {
        return false;
    }

    if (output.empty())
    {
        return true;
    }

    std::array<std::uint32_t, 16> initial
    {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    for (std::size_t index = 0; index < 8; ++index)
    {
        initial[4 + index] = load_little(secret.data() + index * 4);
    }

    for (std::size_t index = 0; index < 3; ++index)
    {
        initial[13 + index] = load_little(iv.data() + index * 4);
    }

    std::array<std::byte, 64> block{};
    std::size_t written = 0;
    while (written < output.size())
    {
        const auto position = offset + written;
        initial[12] = static_cast<std::uint32_t>(position / block.size());
        chacha_block(initial, block);
        const auto within = static_cast<std::size_t>(position % block.size());
        const auto count = std::min(block.size() - within, output.size() - written);
        std::copy_n(block.data() + within, count, output.data() + written);
        written += count;
    }

    secure_zero(block);
    secure_zero(std::as_writable_bytes(std::span(initial)));
    return true;
}

namespace
{
digest sha256_join(std::span<const std::byte> first,
    std::span<const std::byte> second) noexcept
{
    std::array<std::uint32_t, 8> state
    {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    const auto bit_length = (static_cast<std::uint64_t>(first.size()) +
        static_cast<std::uint64_t>(second.size())) * 8U;
    std::array<std::byte, 128> tail{};
    std::size_t used = 0;
    // INVARIANT: The concatenated inputs are never allocated or copied in full.
    for (auto input : {first, second})
    {
        if (used != 0)
        {
            const auto count = std::min(64 - used, input.size());
            std::copy_n(input.begin(), count, tail.begin() + static_cast<std::ptrdiff_t>(used));
            used += count;
            input = input.subspan(count);
            if (used == 64)
            {
                sha256_block(state, tail.data());
                tail.fill(std::byte{0});
                used = 0;
            }
        }

        while (input.size() >= 64)
        {
            sha256_block(state, input.data());
            input = input.subspan(64);
        }

        if (!input.empty())
        {
            std::copy(input.begin(), input.end(), tail.begin() + static_cast<std::ptrdiff_t>(used));
            used += input.size();
        }
    }

    tail[used] = std::byte{0x80};
    const std::size_t tail_size = used < 56 ? 64 : 128;
    for (unsigned shift = 0; shift < 64; shift += 8)
    {
        tail[tail_size - 1 - shift / 8] =
            static_cast<std::byte>((bit_length >> shift) & 0xffU);
    }

    sha256_block(state, tail.data());
    if (tail_size == 128)
    {
        sha256_block(state, tail.data() + 64);
    }

    digest result{};
    for (std::size_t index = 0; index < state.size(); ++index)
    {
        store_big(result.data() + index * 4, state[index]);
    }

    secure_zero(tail);
    secure_zero(std::as_writable_bytes(std::span(state)));
    return result;
}
}

digest sha256(std::span<const std::byte> input) noexcept
{
    return sha256_join(input, {});
}

std::string hex_digest(const digest& value)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result(value.size() * 2, '0');
    for (std::size_t index = 0; index < value.size(); ++index)
    {
        const auto byte = std::to_integer<unsigned>(value[index]);
        result[index * 2] = digits[byte >> 4];
        result[index * 2 + 1] = digits[byte & 0xfU];
    }

    return result;
}

void secure_zero(std::span<std::byte> value) noexcept
{
    // SECURITY: Volatile stores prevent dead-store elimination for the supplied
    // region. This does not guarantee erasure of registers, paging, or hidden copies.
    std::atomic_signal_fence(std::memory_order_seq_cst);
    volatile std::byte* destination = value.data();
    for (std::size_t index = 0; index < value.size(); ++index)
    {
        destination[index] = std::byte{0};
    }

    std::atomic_signal_fence(std::memory_order_seq_cst);
}

digest hmac_sha256(std::span<const std::byte> secret,
    std::span<const std::byte> input) noexcept
{
    // CONTRACT: RFC 2104; SHA-256 block size is 64, digest size is 32.
    std::array<std::byte, 64> pad{};
    if (secret.size() > pad.size())
    {
        auto normalized = sha256(secret);
        std::copy(normalized.begin(), normalized.end(), pad.begin());
        secure_zero(normalized);
    }
    else
    {
        std::copy(secret.begin(), secret.end(), pad.begin());
    }

    for (auto& value : pad)
    {
        value ^= std::byte{0x36};
    }

    auto inner = sha256_join(pad, input);
    for (auto& value : pad)
    {
        value ^= std::byte{0x36 ^ 0x5c};
    }

    auto result = sha256_join(pad, inner);
    secure_zero(pad);
    secure_zero(inner);
    return result;
}

bool stream_bytes(const key& secret, const nonce& iv, std::uint64_t stream_index,
    std::uint64_t offset, std::span<std::byte> output) noexcept
{
    if (output.size() > std::numeric_limits<std::uint64_t>::max() - offset)
    {
        return false;
    }

    constexpr std::uint64_t segment_size = std::uint64_t{1} << 38;
    constexpr std::string_view domain = "wse.chacha20.segment.v1";
    // CONTRACT: HMAC input is 64 bytes: domain ASCII zero-padded to 32 bytes,
    // nonce[12], stream_index LE64, segment_index LE64, four final zero bytes.
    // SECURITY: Copy inputs before output to allow caller-provided aliasing.
    auto secret_copy = secret;
    auto iv_copy = iv;
    std::array<std::byte, 64> context{};
    for (std::size_t index = 0; index < domain.size(); ++index)
    {
        context[index] = static_cast<std::byte>(domain[index]);
    }

    std::copy(iv_copy.begin(), iv_copy.end(), context.begin() + 32);
    for (unsigned shift = 0; shift < 64; shift += 8)
    {
        context[44 + shift / 8] =
            static_cast<std::byte>((stream_index >> shift) & 0xffU);
    }

    std::size_t written = 0;
    bool success = true;
    while (written < output.size())
    {
        const auto position = offset + written;
        const auto segment_index = position / segment_size;
        const auto segment_offset = position % segment_size;
        for (unsigned shift = 0; shift < 64; shift += 8)
        {
            context[52 + shift / 8] =
                static_cast<std::byte>((segment_index >> shift) & 0xffU);
        }

        auto segment_key = hmac_sha256(secret_copy, context);
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
            output.size() - written, segment_size - segment_offset));
        success = chacha20(segment_key, iv_copy, segment_offset,
            output.subspan(written, count));
        secure_zero(segment_key);
        if (!success)
        {
            // INVARIANT: The preflight and count calculation make this unreachable.
            break;
        }

        written += count;
    }

    secure_zero(secret_copy);
    secure_zero(iv_copy);
    secure_zero(context);
    return success;
}
}
