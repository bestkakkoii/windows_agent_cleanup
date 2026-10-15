module secure_erase.codec;

import std;
import secure_erase.model;
import secure_erase.plan;
import secure_erase.crypto;

namespace secure_erase::storage
{
    namespace
    {
        engine::error codec_error(std::string code)
        {
            return {std::move(code), 0, false};
        }

        class writer
        {
        public:
            explicit writer(std::span<std::byte> destination, std::size_t maximum_bytes) noexcept
                : destination_(destination), maximum_bytes_(maximum_bytes)
            {
            }

            void number(std::uint64_t value, std::size_t width)
            {
                std::array<std::byte, 8> bytes{};
                for (std::size_t index{}; index < width; ++index)
                {
                    bytes[index] = static_cast<std::byte>(value >> (index * 8));
                }
                raw(std::span(bytes).first(width));
            }

            void raw(std::span<const std::byte> value)
            {
                if (!good_ || value.size() > maximum_bytes_ - used_)
                {
                    good_ = false;
                    return;
                }
                if (!destination_.empty())
                {
                    if (value.size() > destination_.size() - used_)
                    {
                        good_ = false;
                        return;
                    }
                    std::ranges::copy(value, destination_.begin() + static_cast<std::ptrdiff_t>(used_));
                }
                used_ += value.size();
            }

            void text(std::string_view value)
            {
                if (value.size() > codec_limits::maximum_string_bytes || !valid_utf8(value)
                    || value.find('\0') != std::string_view::npos)
                {
                    good_ = false;
                    return;
                }
                number(value.size(), 4);
                raw(std::as_bytes(std::span(value.data(), value.size())));
            }

            bool good() const noexcept
            {
                return good_;
            }

            std::size_t size() const noexcept
            {
                return used_;
            }

        private:
            std::span<std::byte> destination_;
            std::size_t maximum_bytes_{};
            std::size_t used_{};
            bool good_{true};
        };

        class reader
        {
        public:
            explicit reader(std::span<const std::byte> source, std::size_t allocation_budget) noexcept
                : source_(source), allocation_remaining_(allocation_budget)
            {
            }

            bool claim(std::size_t count, std::size_t unit = 1) noexcept
            {
                if (!good_ || unit == 0 || count > allocation_remaining_ / unit)
                {
                    good_ = false;
                    return false;
                }
                allocation_remaining_ -= count * unit;
                return true;
            }

            std::uint64_t number(std::size_t width)
            {
                const auto bytes = raw(width);
                std::uint64_t value{};
                for (std::size_t index{}; index < bytes.size(); ++index)
                {
                    value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                        << (index * 8);
                }
                return value;
            }

            bool boolean()
            {
                const auto value = number(1);
                if (value > 1)
                {
                    good_ = false;
                }
                return value == 1;
            }

            std::span<const std::byte> raw(std::size_t count)
            {
                if (!good_ || count > source_.size() - used_)
                {
                    good_ = false;
                    return {};
                }
                const auto value = source_.subspan(used_, count);
                used_ += count;
                return value;
            }

            std::string text(std::size_t maximum = codec_limits::maximum_string_bytes)
            {
                const auto count = number(4);
                if (!good_ || count > maximum || !claim(static_cast<std::size_t>(count)))
                {
                    good_ = false;
                    return {};
                }
                const auto value = raw(static_cast<std::size_t>(count));
                if (value.empty())
                {
                    return {};
                }
                std::string result(reinterpret_cast<const char*>(value.data()), value.size());
                if (!valid_utf8(result) || result.find('\0') != std::string::npos)
                {
                    good_ = false;
                    return {};
                }
                return result;
            }

            std::size_t count(std::size_t maximum, std::size_t minimum_encoded_size)
            {
                const auto value = number(4);
                if (!good_ || value > maximum
                    || value > (source_.size() - used_) / minimum_encoded_size)
                {
                    good_ = false;
                    return 0;
                }
                return static_cast<std::size_t>(value);
            }

            bool good() const noexcept
            {
                return good_;
            }

            bool complete() const noexcept
            {
                return good_ && used_ == source_.size();
            }

            void reject() noexcept
            {
                good_ = false;
            }

        private:
            std::span<const std::byte> source_;
            std::size_t allocation_remaining_{};
            std::size_t used_{};
            bool good_{true};
        };

        void encode_snapshot(writer& output, const engine::target_snapshot& value)
        {
            output.text(value.path);
            output.text(value.identity);
            output.text(value.device_key);
            output.number(value.creation_time, 8);
            output.number(value.write_time, 8);
            output.number(value.change_time, 8);
            output.number(value.attributes, 4);
            output.number(value.link_count, 4);
            output.number(value.directory, 1);
            output.number(value.reparse_point, 1);
            output.number(value.remote, 1);
            output.number(value.encrypted, 1);
            output.number(value.compressed, 1);
            output.number(value.sparse, 1);
            output.number(value.trim_supported, 1);
            output.number(value.vss_query_complete, 1);
            output.number(value.vss_snapshot_count, 4);
            output.number(value.vss_native_error, 4);
            output.number(static_cast<std::uint8_t>(value.media), 1);
            output.number(static_cast<std::uint8_t>(value.support), 1);
            output.number(value.streams.size(), 4);
            for (const auto& stream : value.streams)
            {
                output.text(stream.name);
                output.number(stream.size, 8);
            }
            output.number(value.protection_reasons.size(), 4);
            for (const auto& reason : value.protection_reasons)
            {
                output.text(reason);
            }
            output.number(value.residual_risks.size(), 4);
            for (const auto& risk : value.residual_risks)
            {
                output.text(risk);
            }
        }

        engine::target_snapshot decode_snapshot(reader& input)
        {
            engine::target_snapshot value;
            value.path = input.text();
            value.identity = input.text(1024);
            value.device_key = input.text(1024);
            value.creation_time = input.number(8);
            value.write_time = input.number(8);
            value.change_time = input.number(8);
            value.attributes = static_cast<std::uint32_t>(input.number(4));
            value.link_count = static_cast<std::uint32_t>(input.number(4));
            value.directory = input.boolean();
            value.reparse_point = input.boolean();
            value.remote = input.boolean();
            value.encrypted = input.boolean();
            value.compressed = input.boolean();
            value.sparse = input.boolean();
            value.trim_supported = input.boolean();
            value.vss_query_complete = input.boolean();
            value.vss_snapshot_count = static_cast<std::uint32_t>(input.number(4));
            value.vss_native_error = static_cast<std::uint32_t>(input.number(4));
            const auto media = input.number(1);
            const auto support = input.number(1);
            if (media > static_cast<unsigned>(engine::media_kind::usb)
                || support > static_cast<unsigned>(engine::capability::delete_only))
            {
                input.reject();
                return value;
            }
            value.media = static_cast<engine::media_kind>(media);
            value.support = static_cast<engine::capability>(support);
            const auto streams = input.count(codec_limits::maximum_streams, 12);
            if (!input.claim(streams, sizeof(engine::stream_snapshot)))
            {
                return value;
            }
            value.streams.reserve(streams);
            for (std::size_t index{}; index < streams && input.good(); ++index)
            {
                value.streams.push_back({input.text(), input.number(8)});
            }
            const auto reasons = input.count(128, 4);
            if (!input.claim(reasons, sizeof(std::string)))
            {
                return value;
            }
            value.protection_reasons.reserve(reasons);
            for (std::size_t index{}; index < reasons && input.good(); ++index)
            {
                value.protection_reasons.push_back(input.text(512));
            }
            const auto risks = input.count(128, 4);
            if (!input.claim(risks, sizeof(std::string)))
            {
                return value;
            }
            value.residual_risks.reserve(risks);
            for (std::size_t index{}; index < risks && input.good(); ++index)
            {
                value.residual_risks.push_back(input.text(512));
            }
            return value;
        }

        bool valid_snapshot(const engine::target_snapshot& value)
        {
            if (value.identity.size() > 1024 || value.device_key.size() > 1024
                || value.streams.size() > codec_limits::maximum_streams
                || value.protection_reasons.size() > 128 || value.residual_risks.size() > 128
                || static_cast<unsigned>(value.media) > static_cast<unsigned>(engine::media_kind::usb)
                || static_cast<unsigned>(value.support) > static_cast<unsigned>(engine::capability::delete_only))
            {
                return false;
            }
            return std::ranges::all_of(value.protection_reasons, [](const auto& reason)
            {
                return reason.size() <= 512;
            }) && std::ranges::all_of(value.residual_risks, [](const auto& risk)
            {
                return risk.size() <= 512;
            });
        }

        bool valid_checkpoint(const engine::checkpoint& value)
        {
            if (value.schema_version != 1 || !valid_job_id(value.plan.job_id)
                || value.plan.targets.empty() || value.plan.targets.size() > codec_limits::maximum_targets
                || value.targets.size() != value.plan.targets.size()
                || value.plan.fingerprint.size() != 64 || !valid_job_id(value.plan.fingerprint))
            {
                return false;
            }
            for (std::size_t index{}; index < value.targets.size(); ++index)
            {
                const auto& target = value.targets[index];
                const auto& frozen = value.plan.targets[index];
                if (!valid_snapshot(frozen) || !valid_snapshot(target.observed)
                    || target.identity != frozen.identity
                    || static_cast<unsigned>(target.state) > static_cast<unsigned>(engine::target_state::skipped))
                {
                    return false;
                }
                if (!target.observed.identity.empty() && target.observed.identity != target.identity)
                {
                    return false;
                }
                if (target.observed.identity.empty()
                    && (target.state != engine::target_state::pending || target.key_ready
                        || target.stream_index != 0 || target.offset != 0))
                {
                    return false;
                }
                if (target.stream_index > target.observed.streams.size())
                {
                    return false;
                }
                if (target.stream_index < target.observed.streams.size())
                {
                    if (target.offset > target.observed.streams[target.stream_index].size)
                    {
                        return false;
                    }
                }
                else if (target.offset != 0)
                {
                    return false;
                }
            }
            return value.plan.fingerprint == engine::fingerprint(value.plan);
        }

        void encode_body(writer& output, const engine::checkpoint& value)
        {
            constexpr std::array magic{std::byte{'s'}, std::byte{'e'}, std::byte{'c'}, std::byte{'p'},
                std::byte{'0'}, std::byte{'0'}, std::byte{'0'}, std::byte{'1'}};
            output.raw(magic);
            output.number(value.schema_version, 4);
            output.text(value.plan.job_id);
            output.text(value.plan.fingerprint);
            output.number(value.plan.targets.size(), 4);
            for (const auto& target : value.plan.targets)
            {
                encode_snapshot(output, target);
            }
            output.number(value.targets.size(), 4);
            for (const auto& target : value.targets)
            {
                output.text(target.identity);
                encode_snapshot(output, target.observed);
                output.raw(target.key);
                output.raw(target.nonce);
                output.number(target.key_ready, 1);
                output.number(target.stream_index, 8);
                output.number(target.offset, 8);
                output.number(static_cast<std::uint8_t>(target.state), 1);
            }
        }

        bool valid_event_code(std::string_view value)
        {
            if (value.empty() || value.size() > 128)
            {
                return false;
            }
            return std::ranges::all_of(value, [](char character)
            {
                return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9') || character == '_' || character == '.'
                    || character == '-';
            });
        }
    }

    bool valid_job_id(std::string_view value) noexcept
    {
        if (value.size() != 32 && value.size() != 64)
        {
            return false;
        }
        return std::ranges::all_of(value, [](char character)
        {
            return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
        });
    }

    bool valid_utf8(std::string_view value) noexcept
    {
        std::size_t index{};
        while (index < value.size())
        {
            const auto first = static_cast<unsigned char>(value[index++]);
            if (first <= 0x7f)
            {
                continue;
            }
            std::uint32_t point{};
            std::size_t continuation{};
            std::uint32_t minimum{};
            if (first >= 0xc2 && first <= 0xdf)
            {
                point = first & 0x1fU;
                continuation = 1;
                minimum = 0x80;
            }
            else if (first >= 0xe0 && first <= 0xef)
            {
                point = first & 0x0fU;
                continuation = 2;
                minimum = 0x800;
            }
            else if (first >= 0xf0 && first <= 0xf4)
            {
                point = first & 0x07U;
                continuation = 3;
                minimum = 0x10000;
            }
            else
            {
                return false;
            }
            if (continuation > value.size() - index)
            {
                return false;
            }
            for (std::size_t part{}; part < continuation; ++part)
            {
                const auto byte = static_cast<unsigned char>(value[index++]);
                if ((byte & 0xc0U) != 0x80U)
                {
                    return false;
                }
                point = (point << 6) | (byte & 0x3fU);
            }
            if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff))
            {
                return false;
            }
        }
        return true;
    }

    engine::result<std::vector<std::byte>> encode_checkpoint(const engine::checkpoint& value, std::size_t maximum_bytes)
    {
        writer measure({}, maximum_bytes);
        encode_body(measure, value);
        if (!measure.good())
        {
            return std::unexpected(codec_error("checkpoint_encoding_limit"));
        }
        if (!valid_checkpoint(value))
        {
            return std::unexpected(codec_error("checkpoint_invalid_state"));
        }
        // SECURITY: Measure then allocate exactly once: no key-bearing vector reallocation.
        std::vector<std::byte> bytes(measure.size());
        writer output(bytes, maximum_bytes);
        encode_body(output, value);
        if (!output.good() || output.size() != bytes.size())
        {
            clear_sensitive(bytes);
            return std::unexpected(codec_error("checkpoint_encoding_failed"));
        }
        return bytes;
    }

    engine::result<engine::checkpoint> decode_checkpoint(std::span<const std::byte> bytes, std::size_t maximum_bytes)
    {
        if (bytes.size() > maximum_bytes || bytes.size() < 12)
        {
            return std::unexpected(codec_error("checkpoint_size_invalid"));
        }
        reader input(bytes, maximum_bytes);
        constexpr std::array magic{std::byte{'s'}, std::byte{'e'}, std::byte{'c'}, std::byte{'p'},
            std::byte{'0'}, std::byte{'0'}, std::byte{'0'}, std::byte{'1'}};
        if (!std::ranges::equal(input.raw(magic.size()), magic) || input.number(4) != 1)
        {
            return std::unexpected(codec_error("checkpoint_version_unsupported"));
        }
        engine::checkpoint value;
        struct clear_on_exit
        {
            engine::checkpoint& value;

            ~clear_on_exit()
            {
                clear_sensitive(value);
            }
        } cleanup{value};
        value.plan.job_id = input.text(64);
        value.plan.fingerprint = input.text(64);
        const auto count = input.count(codec_limits::maximum_targets, 49);
        if (!input.claim(count, sizeof(engine::target_snapshot)))
        {
            return std::unexpected(codec_error("checkpoint_allocation_budget_exceeded"));
        }
        value.plan.targets.reserve(count);
        for (std::size_t index{}; index < count && input.good(); ++index)
        {
            value.plan.targets.push_back(decode_snapshot(input));
        }
        const auto states = input.count(codec_limits::maximum_targets, 107);
        if (states != count)
        {
            return std::unexpected(codec_error("checkpoint_count_mismatch"));
        }
        if (!input.claim(states, sizeof(engine::target_checkpoint)))
        {
            return std::unexpected(codec_error("checkpoint_allocation_budget_exceeded"));
        }
        value.targets.resize(states);
        for (auto& target : value.targets)
        {
            if (!input.good())
            {
                break;
            }
            target.identity = input.text(1024);
            target.observed = decode_snapshot(input);
            const auto key = input.raw(target.key.size());
            std::ranges::copy(key, target.key.begin());
            const auto nonce = input.raw(target.nonce.size());
            std::ranges::copy(nonce, target.nonce.begin());
            target.key_ready = input.boolean();
            const auto stream_index = input.number(8);
            if (stream_index > std::numeric_limits<std::size_t>::max())
            {
                input.reject();
            }
            target.stream_index = static_cast<std::size_t>(stream_index);
            target.offset = input.number(8);
            const auto state = input.number(1);
            if (state > static_cast<unsigned>(engine::target_state::skipped))
            {
                input.reject();
            }
            target.state = static_cast<engine::target_state>(state);
        }
        if (!input.complete() || !valid_checkpoint(value))
        {
            return std::unexpected(codec_error("checkpoint_invalid_state"));
        }
        // The guard also handles allocation/validation exceptions after earlier
        // target keys have been decoded. Only the returned owner retains keys.
        return engine::result<engine::checkpoint>(std::in_place, std::move(value));
    }

    std::string event_json(const engine::event& value, std::uint64_t utc_filetime)
    {
        if (!valid_event_code(value.code) || (!value.job_id.empty() && !valid_job_id(value.job_id))
            || value.identity.size() > 1024 || value.completed_targets > value.total_targets
            || value.failed_targets > value.total_targets - value.completed_targets)
        {
            return {};
        }
        const auto identity = value.identity.empty() ? std::string{}
            : crypto::hex_digest(crypto::sha256(std::as_bytes(
                std::span(value.identity.data(), value.identity.size()))));
        std::string counts;
        if (value.total_targets != 0 || value.completed_targets != 0 || value.failed_targets != 0)
        {
            counts = ",\"target_counts\":{\"total\":" + std::to_string(value.total_targets)
                + ",\"completed\":" + std::to_string(value.completed_targets)
                + ",\"failed\":" + std::to_string(value.failed_targets) + "}";
        }
        // CONTRACT: Event and identifier alphabets make quotes/escapes impossible here.
        return "{\"schema\":\"secure_erase.event.v1\",\"utc_filetime\":" + std::to_string(utc_filetime)
            + ",\"event\":\"" + value.code + "\",\"job_id\":\"" + value.job_id
            + "\",\"target_id\":\"" + identity + "\",\"bytes_done\":" + std::to_string(value.bytes_done)
            + ",\"bytes_total\":" + std::to_string(value.bytes_total)
            + ",\"native_error\":{\"code\":" + std::to_string(value.native_code)
            + ",\"domain\":\"win32_or_unspecified\",\"ntstatus\":null},\"paths_masked\":true" + counts + "}\n";
    }

    void clear_sensitive(engine::checkpoint& value) noexcept
    {
        for (auto& target : value.targets)
        {
            crypto::secure_zero(target.key);
            crypto::secure_zero(target.nonce);
            target.key_ready = false;
        }
    }

    void clear_sensitive(std::span<std::byte> value) noexcept
    {
        crypto::secure_zero(value);
    }
}
