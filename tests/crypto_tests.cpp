import std;
import secure_erase.crypto;

namespace
{
    namespace crypto = secure_erase::crypto;

    class test_runner
    {
    public:
        void check(std::string_view name, bool passed)
        {
            ++total_;
            if (!passed)
            {
                ++failed_;
            }

            std::cout << "{\"test\":\"" << name << "\",\"passed\":"
                << (passed ? "true" : "false") << "}\n";
        }

        int finish() const
        {
            std::cout << "{\"summary\":true,\"total\":" << total_
                << ",\"passed\":" << total_ - failed_ << ",\"failed\":" << failed_
                << ",\"scope\":\"crypto_algorithm_tests\","
                << "\"hardware_sanitization_verified\":false}\n";
            return failed_ == 0 ? 0 : 1;
        }

    private:
        std::size_t total_{};
        std::size_t failed_{};
    };

    std::span<const std::byte> bytes(std::string_view value)
    {
        return std::as_bytes(std::span(value.data(), value.size()));
    }

    template<std::size_t size>
    std::array<std::byte, size> decode(const char (&value)[size * 2 + 1])
    {
        const auto nibble = [](char digit) -> unsigned
        {
            return digit <= '9' ? static_cast<unsigned>(digit - '0')
                : static_cast<unsigned>(digit - 'a' + 10);
        };
        std::array<std::byte, size> result{};
        for (std::size_t index = 0; index < size; ++index)
        {
            result[index] = static_cast<std::byte>(
                (nibble(value[index * 2]) << 4) | nibble(value[index * 2 + 1]));
        }

        return result;
    }

    void sha256_vectors(test_runner& tests)
    {
        tests.check("sha256_empty", crypto::hex_digest(crypto::sha256({})) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        tests.check("sha256_abc", crypto::hex_digest(crypto::sha256(bytes("abc"))) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        tests.check("sha256_nist_56_bytes", crypto::hex_digest(crypto::sha256(bytes(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        const std::vector<std::byte> million(1'000'000, std::byte{0x61});
        tests.check("sha256_nist_million_a", crypto::hex_digest(crypto::sha256(million)) ==
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

        // EVIDENCE: Padding-boundary answers independently generated with Python
        // hashlib (OpenSSL), input bytes equal their zero-based index.
        struct vector_case
        {
            std::size_t size;
            std::string_view expected;
        };
        constexpr std::array<vector_case, 8> vectors
        {{
            {55, "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59"},
            {56, "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562"},
            {63, "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488"},
            {64, "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"},
            {65, "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781"},
            {127, "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976"},
            {128, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"},
            {129, "5099c6a56203f9687f7d33f4bfdf576d31dc91f6b695ecea38b2770c87631135"}
        }};
        for (const auto& vector : vectors)
        {
            std::vector<std::byte> input(vector.size);
            for (std::size_t index = 0; index < input.size(); ++index)
            {
                input[index] = static_cast<std::byte>(index);
            }

            tests.check("sha256_padding_" + std::to_string(vector.size),
                crypto::hex_digest(crypto::sha256(input)) == vector.expected);
        }
    }

    void hmac_vectors(test_runner& tests)
    {
        // EVIDENCE: RFC 4231 sections 4.2, 4.3, 4.7 and 4.8.
        std::array<std::byte, 20> first_key{};
        first_key.fill(std::byte{0x0b});
        tests.check("hmac_sha256_rfc4231_case_1", crypto::hex_digest(
            crypto::hmac_sha256(first_key, bytes("Hi There"))) ==
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        tests.check("hmac_sha256_rfc4231_case_2", crypto::hex_digest(
            crypto::hmac_sha256(bytes("Jefe"), bytes("what do ya want for nothing?"))) ==
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        std::array<std::byte, 131> long_key{};
        long_key.fill(std::byte{0xaa});
        tests.check("hmac_sha256_rfc4231_case_6", crypto::hex_digest(
            crypto::hmac_sha256(long_key,
                bytes("Test Using Larger Than Block-Size Key - Hash Key First"))) ==
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        tests.check("hmac_sha256_rfc4231_case_7", crypto::hex_digest(
            crypto::hmac_sha256(long_key, bytes(
                "This is a test using a larger than block-size key and a larger than "
                "block-size data. The key needs to be hashed before being used by "
                "the HMAC algorithm."))) ==
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    }

    void chacha_vectors(test_runner& tests)
    {
        const auto secret = decode<32>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const auto iv = decode<12>("000000090000004a00000000");
        const auto expected = decode<64>(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
        std::array<std::byte, 64> output{};
        // EVIDENCE: RFC 8439 section 2.3.2 uses block counter 1 (offset 64).
        tests.check("chacha20_rfc8439_counter_1",
            crypto::chacha20(secret, iv, 64, output) && output == expected);
        const auto zero_expected = decode<64>(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
        tests.check("chacha20_rfc8439_zero_counter",
            crypto::chacha20({}, {}, 0, output) && output == zero_expected);

        std::array<std::byte, 4096> full{};
        tests.check("chacha20_full_fixture", crypto::chacha20(secret, iv, 0, full));
        for (const std::size_t offset : {0U, 1U, 31U, 63U, 64U, 65U, 127U, 1023U})
        {
            std::array<std::byte, 129> part{};
            tests.check("chacha20_random_access_" + std::to_string(offset),
                crypto::chacha20(secret, iv, offset, part) &&
                std::equal(part.begin(), part.end(), full.begin() +
                    static_cast<std::ptrdiff_t>(offset)));
        }

        std::array<std::byte, 4096> split{};
        bool generated = true;
        for (std::size_t offset = 0; offset < split.size();)
        {
            const auto count = std::min<std::size_t>(73, split.size() - offset);
            generated = crypto::chacha20(secret, iv, offset,
                std::span(split).subspan(offset, count)) && generated;
            offset += count;
        }

        tests.check("chacha20_resume_chunking_independent", generated && split == full);
        constexpr std::uint64_t limit = std::uint64_t{1} << 38;
        std::array<std::byte, 64> final_block{};
        std::array<std::byte, 1> final_byte{};
        tests.check("chacha20_final_block_allowed",
            crypto::chacha20(secret, iv, limit - 64, final_block));
        tests.check("chacha20_final_byte_matches",
            crypto::chacha20(secret, iv, limit - 1, final_byte) &&
            final_byte.front() == final_block.back());
        tests.check("chacha20_empty_at_limit_allowed",
            crypto::chacha20(secret, iv, limit, {}));
        tests.check("chacha20_empty_beyond_limit_rejected",
            !crypto::chacha20(secret, iv, limit + 1, {}));
        output.fill(std::byte{0xa5});
        const auto unchanged = output;
        tests.check("chacha20_cross_limit_no_partial_write",
            !crypto::chacha20(secret, iv, limit - 63, output) && output == unchanged);
        tests.check("chacha20_past_limit_no_write",
            !crypto::chacha20(secret, iv, limit, output) && output == unchanged);
        tests.check("chacha20_offset_overflow_no_write",
            !crypto::chacha20(secret, iv, std::numeric_limits<std::uint64_t>::max(),
                output) && output == unchanged);
    }

    void extended_stream(test_runner& tests)
    {
        crypto::key secret{};
        crypto::nonce iv{};
        for (std::size_t index = 0; index < secret.size(); ++index)
        {
            secret[index] = static_cast<std::byte>(index);
        }

        for (std::size_t index = 0; index < iv.size(); ++index)
        {
            iv[index] = static_cast<std::byte>(index);
        }

        // EVIDENCE: Independent Python hmac.digest/cryptography ChaCha20 answers;
        // domain format is documented in stream_bytes. No huge allocation needed.
        const auto expected = decode<64>(
            "f14a3fdbce3ff3fb4bddf1c0507d64a672c5188d810144248888d0bb298a5003"
            "2dd9443a615e22983ba855079a9bfd586c2c099d93f91e3bab4236ae4adba395");
        std::array<std::byte, 64> first{};
        tests.check("stream_independent_first_segment_vector",
            crypto::stream_bytes(secret, iv, 7, 0, first) && first == expected);
        constexpr std::uint64_t segment = std::uint64_t{1} << 38;
        const auto cross_expected = decode<32>(
            "93f8456614e0918d4bd5790046be7c035c20ed062858dce512daaaefb2f9abd5");
        std::array<std::byte, 32> cross{};
        tests.check("stream_independent_segment_crossing_vector",
            crypto::stream_bytes(secret, iv, 7, segment - 16, cross) &&
            cross == cross_expected);
        std::array<std::byte, 32> split{};
        tests.check("stream_resume_across_segment",
            crypto::stream_bytes(secret, iv, 7, segment - 16, std::span(split).first(16)) &&
            crypto::stream_bytes(secret, iv, 7, segment, std::span(split).subspan(16)) &&
            split == cross);
        std::array<std::byte, 64> next{};
        tests.check("stream_segment_domain_separation",
            crypto::stream_bytes(secret, iv, 7, segment, next) && next != first);
        tests.check("stream_index_domain_separation",
            crypto::stream_bytes(secret, iv, 8, 0, next) && next != first);
        auto other_iv = iv;
        other_iv.front() ^= std::byte{1};
        tests.check("stream_nonce_domain_separation",
            crypto::stream_bytes(secret, other_iv, 7, 0, next) && next != first);
        auto other_key = secret;
        other_key.back() ^= std::byte{1};
        tests.check("stream_key_domain_separation",
            crypto::stream_bytes(other_key, iv, 7, 0, next) && next != first);

        constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
        const auto final_expected = decode<64>(
            "01455a0185742f7a315c2bdf206e87d6aa9320d443917db4e17f816ce09d01eae"
            "63fd3b8b0543543db7cf38c21fcf9eafa0c6e9385ed5f0e4065f8a7e81c4b65");
        tests.check("stream_uint64_final_range_independent_vector",
            crypto::stream_bytes(secret, iv, 7, maximum - 64, next) &&
            next == final_expected);
        tests.check("stream_uint64_empty_end_allowed",
            crypto::stream_bytes(secret, iv, 7, maximum, {}));
        next.fill(std::byte{0x5a});
        const auto unchanged = next;
        tests.check("stream_uint64_overflow_no_partial_write",
            !crypto::stream_bytes(secret, iv, 7, maximum - 63, next) && next == unchanged);
        tests.check("stream_uint64_out_of_range_no_write",
            !crypto::stream_bytes(secret, iv, 7, maximum, next) && next == unchanged);
    }

    void zeroization(test_runner& tests)
    {
        std::array<std::byte, 34> data{};
        data.fill(std::byte{0xa5});
        crypto::secure_zero(std::span(data).subspan(1, 32));
        tests.check("secure_zero_exact_span",
            data.front() == std::byte{0xa5} && data.back() == std::byte{0xa5} &&
            std::all_of(data.begin() + 1, data.end() - 1,
                [](std::byte value)
                {
                    return value == std::byte{0};
                }));
        crypto::secure_zero({});
        tests.check("secure_zero_empty_span", true);
    }
}

int main()
{
    test_runner tests;
    sha256_vectors(tests);
    hmac_vectors(tests);
    chacha_vectors(tests);
    extended_stream(tests);
    zeroization(tests);
    return tests.finish();
}
