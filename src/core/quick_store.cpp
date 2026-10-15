module secure_erase.quick_store;

import std;
import secure_erase.crypto;

namespace secure_erase::quick::store
{
namespace
{
constexpr std::uint64_t index_bytes = 152;
constexpr std::size_t index_payload_bytes = 120;
constexpr std::uint64_t outcome_bytes = 576;
constexpr std::uint64_t absent_parent = std::numeric_limits<std::uint64_t>::max();

[[nodiscard]] engine::error failure(std::string code)
{
    return {std::move(code), 0, false};
}

[[nodiscard]] bool add(std::uint64_t& value, std::uint64_t amount)
{
    if (amount > std::numeric_limits<std::uint64_t>::max() - value)
    {
        return false;
    }
    value += amount;
    return true;
}

void put_integer(std::span<std::byte> output, std::uint64_t value)
{
    for (unsigned index = 0; index < 8; ++index)
    {
        output[index] = static_cast<std::byte>((value >> (index * 8)) & 255U);
    }
}

[[nodiscard]] std::uint64_t get_integer(std::span<const std::byte> input)
{
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
    {
        result |= static_cast<std::uint64_t>(std::to_integer<unsigned>(input[index])) << (index * 8);
    }
    return result;
}

void append_integer(std::vector<std::byte>& output, std::uint64_t value)
{
    const auto start = output.size();
    output.resize(start + 8);
    put_integer(std::span(output).subspan(start, 8), value);
}

void append_text(std::vector<std::byte>& output, std::string_view value)
{
    append_integer(output, value.size());
    const auto bytes = std::as_bytes(std::span(value.data(), value.size()));
    output.insert(output.end(), bytes.begin(), bytes.end());
}

[[nodiscard]] bool valid_utf8(std::string_view text)
{
    for (std::size_t position = 0; position < text.size();)
    {
        const auto first = static_cast<unsigned char>(text[position++]);
        if (first == 0)
        {
            return false;
        }
        if (first < 128)
        {
            continue;
        }
        const unsigned length = first >= 0xc2 && first <= 0xdf ? 2U :
            first >= 0xe0 && first <= 0xef ? 3U : first >= 0xf0 && first <= 0xf4 ? 4U : 0U;
        if (length == 0 || length - 1 > text.size() - position)
        {
            return false;
        }
        std::uint32_t scalar = first & (length == 2 ? 31U : length == 3 ? 15U : 7U);
        for (unsigned index = 1; index < length; ++index)
        {
            const auto next = static_cast<unsigned char>(text[position++]);
            if ((next & 0xc0U) != 0x80U)
            {
                return false;
            }
            scalar = (scalar << 6) | (next & 63U);
        }
        if ((length == 2 && scalar < 128) || (length == 3 && scalar < 2048) ||
            (length == 4 && scalar < 65536) || scalar > 0x10ffff ||
            (scalar >= 0xd800 && scalar <= 0xdfff))
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool valid_target(const target& value)
{
    return !value.path.empty() && value.path.size() <= 131072 &&
        value.identity.size() <= 1024 && value.device_key.size() <= 1024 &&
        value.preparation_error.code.size() <= 512 &&
        (!value.logical_size_known || value.type_known) &&
        (value.logical_size_known || value.logical_size_bytes == 0) &&
        (!value.type_known || !value.directory || value.logical_size_bytes == 0) &&
        ((!value.identity.empty() && !value.device_key.empty()) || !value.preparation_error.code.empty()) &&
        valid_utf8(value.path) && valid_utf8(value.identity) && valid_utf8(value.device_key) &&
        valid_utf8(value.preparation_error.code) &&
        (!value.preparation_error.code.empty() ||
         (value.preparation_error.native_code == 0 && !value.preparation_error.device_fault));
}

[[nodiscard]] bool same_target(const target& left, const target& right)
{
    return left.path == right.path && left.identity == right.identity &&
        left.device_key == right.device_key && left.creation_time == right.creation_time &&
        left.attributes == right.attributes && left.directory == right.directory &&
        left.allocated_bytes == right.allocated_bytes &&
        left.logical_size_bytes == right.logical_size_bytes &&
        left.logical_size_known == right.logical_size_known && left.type_known == right.type_known &&
        left.preparation_error.code == right.preparation_error.code &&
        left.preparation_error.native_code == right.preparation_error.native_code &&
        left.preparation_error.device_fault == right.preparation_error.device_fault;
}

[[nodiscard]] std::uint64_t target_memory(const target& value)
{
    std::uint64_t bytes = sizeof(target) + 128;
    for (const auto capacity : {value.path.capacity(), value.identity.capacity(),
        value.device_key.capacity(), value.preparation_error.code.capacity()})
    {
        if (!add(bytes, capacity) || !add(bytes, 1))
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
    }
    return bytes;
}

[[nodiscard]] std::vector<std::byte> encode(const target& value)
{
    std::vector<std::byte> bytes;
    bytes.reserve(160 + value.path.size() + value.identity.size() + value.device_key.size() +
        value.preparation_error.code.size());
    append_integer(bytes, 0);
    append_text(bytes, value.path);
    append_text(bytes, value.identity);
    append_text(bytes, value.device_key);
    append_integer(bytes, value.creation_time);
    append_integer(bytes, value.attributes);
    append_integer(bytes, value.directory);
    append_text(bytes, value.preparation_error.code);
    append_integer(bytes, value.preparation_error.native_code);
    append_integer(bytes, value.preparation_error.device_fault);
    append_integer(bytes, value.allocated_bytes);
    append_integer(bytes, value.logical_size_bytes);
    append_integer(bytes, value.logical_size_known);
    append_integer(bytes, value.type_known);
    put_integer(bytes, bytes.size() - 8);
    const auto digest = crypto::sha256(std::span(bytes).subspan(8));
    bytes.insert(bytes.end(), digest.begin(), digest.end());
    return bytes;
}

[[nodiscard]] engine::result<target> decode(std::span<const std::byte> bytes)
{
    std::size_t position = 0;
    bool good = true;
    const auto integer = [&]() -> std::uint64_t
    {
        if (bytes.size() - position < 8)
        {
            good = false;
            return 0;
        }
        const auto result = get_integer(bytes.subspan(position, 8));
        position += 8;
        return result;
    };
    const auto text = [&]() -> std::string
    {
        const auto size = integer();
        if (!good || size > bytes.size() - position)
        {
            good = false;
            return {};
        }
        std::string result(reinterpret_cast<const char*>(bytes.data() + position),
            static_cast<std::size_t>(size));
        position += static_cast<std::size_t>(size);
        return result;
    };
    target result;
    result.path = text();
    result.identity = text();
    result.device_key = text();
    result.creation_time = integer();
    const auto attributes = integer();
    const auto directory = integer();
    result.preparation_error.code = text();
    const auto native = integer();
    const auto device_fault = integer();
    result.allocated_bytes = integer();
    result.logical_size_bytes = integer();
    const auto logical_size_known = integer();
    const auto type_known = integer();
    if (!good || position != bytes.size() || attributes > std::numeric_limits<std::uint32_t>::max() ||
        native > std::numeric_limits<std::uint32_t>::max() || directory > 1 || device_fault > 1 ||
        logical_size_known > 1 || type_known > 1)
    {
        return std::unexpected(failure("quick_store_record_invalid"));
    }
    result.attributes = static_cast<std::uint32_t>(attributes);
    result.directory = directory != 0;
    result.logical_size_known = logical_size_known != 0;
    result.type_known = type_known != 0;
    result.preparation_error.native_code = static_cast<std::uint32_t>(native);
    result.preparation_error.device_fault = device_fault != 0;
    if (!valid_target(result))
    {
        return std::unexpected(failure("quick_store_record_invalid"));
    }
    return result;
}

struct disk_account
{
    std::uint64_t bytes{};
    std::uint64_t peak{};
};

struct owned_file
{
    std::shared_ptr<file_factory> factory;
    std::shared_ptr<random_access_file> file;
    std::shared_ptr<disk_account> accounting;
    std::string name;
    std::uint64_t bytes{};

    ~owned_file()
    {
        if (file)
        {
            file.reset();
            try
            {
                static_cast<void>(factory->remove_private(name));
            }
            catch (...)
            {
                // SECURITY: Native DELETE_ON_CLOSE still owns cleanup; an
                // adapter diagnostic must not terminate exception unwinding.
            }
        }
        if (accounting)
        {
            accounting->bytes -= bytes;
        }
    }
};

struct run_file
{
    std::shared_ptr<owned_file> file;
    std::uint64_t count{};
};

struct read_record
{
    target value;
    crypto::digest digest{};
    std::uint64_t offset{};
    std::uint64_t payload_bytes{};
    std::uint64_t next{};
};

[[nodiscard]] engine::result<read_record> read_target(const owned_file& file,
    std::uint64_t position, std::uint64_t maximum_bytes)
{
    if (position > file.bytes || file.bytes - position < 40)
    {
        return std::unexpected(failure("quick_store_record_truncated"));
    }
    std::array<std::byte, 8> length{};
    auto read = file.file->read_at(position, length);
    if (!read)
    {
        return std::unexpected(read.error());
    }
    const auto size = get_integer(length);
    if (size > maximum_bytes || size > file.bytes - position - 40 ||
        size > std::numeric_limits<std::size_t>::max() - 32)
    {
        return std::unexpected(failure("quick_store_record_limit_exceeded"));
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size) + 32);
    read = file.file->read_at(position + 8, bytes);
    if (!read)
    {
        return std::unexpected(read.error());
    }
    const auto payload = std::span<const std::byte>(bytes).first(static_cast<std::size_t>(size));
    crypto::digest stored{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(size), 32, stored.begin());
    if (crypto::sha256(payload) != stored)
    {
        return std::unexpected(failure("quick_store_record_integrity_failed"));
    }
    auto decoded = decode(payload);
    if (!decoded)
    {
        return std::unexpected(decoded.error());
    }
    return read_record{std::move(*decoded), stored, position, size, position + size + 40};
}

[[nodiscard]] bool ancestor(std::string_view parent, std::string_view child)
{
    return child.size() > parent.size() && child.starts_with(parent) &&
        (parent.ends_with('\\') || parent.ends_with('/') ||
         child[parent.size()] == '\\' || child[parent.size()] == '/');
}

[[nodiscard]] crypto::digest namespace_digest(const target& value)
{
    const auto text = target_key(value);
    crypto::digest result{};
    const auto nibble = [](char value)
    {
        return static_cast<unsigned>(value >= 'a' ? value - 'a' + 10 : value - '0');
    };
    for (std::size_t index = 0; index < result.size(); ++index)
    {
        result[index] = static_cast<std::byte>((nibble(text[index * 2]) << 4) | nibble(text[index * 2 + 1]));
    }
    return result;
}

[[nodiscard]] bool hex_equals(const crypto::digest& bytes, std::string_view text)
{
    if (text.size() != bytes.size() * 2)
    {
        return false;
    }
    constexpr std::string_view alphabet = "0123456789abcdef";
    for (std::size_t position = 0; position < bytes.size(); ++position)
    {
        const auto value = std::to_integer<unsigned>(bytes[position]);
        if (text[position * 2] != alphabet[value >> 4] || text[position * 2 + 1] != alphabet[value & 15U])
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] crypto::digest outcome_digest(const crypto::digest& identity,
    std::uint64_t position, std::span<const std::byte> payload)
{
    std::array<std::byte, 584> bytes{};
    std::copy(identity.begin(), identity.end(), bytes.begin());
    put_integer(std::span(bytes).subspan(32), position);
    std::copy(payload.begin(), payload.end(), bytes.begin() + 40);
    return crypto::sha256(bytes);
}

[[nodiscard]] crypto::digest initial_digest(std::string_view job_id)
{
    std::vector<std::byte> bytes;
    append_text(bytes, "secure_erase.quick_store.v2");
    append_text(bytes, job_id);
    return crypto::sha256(bytes);
}

[[nodiscard]] crypto::digest chain_digest(const crypto::digest& previous,
    std::span<const std::byte> bytes)
{
    std::vector<std::byte> input(previous.begin(), previous.end());
    input.insert(input.end(), bytes.begin(), bytes.end());
    return crypto::sha256(input);
}

[[nodiscard]] std::string finish_digest(const crypto::digest& previous, std::uint64_t count)
{
    std::array<std::byte, 8> bytes{};
    put_integer(bytes, count);
    return crypto::hex_digest(chain_digest(previous, bytes));
}

class frozen_batch final : public target_source, public outcome_sink
{
public:
    staged_plan_info metadata;
    std::shared_ptr<owned_file> records;
    std::shared_ptr<owned_file> indexes;
    std::shared_ptr<owned_file> outcomes;
    std::uint64_t maximum_record_bytes{};

    [[nodiscard]] const staged_plan_info& info() const noexcept override
    {
        return metadata;
    }

    [[nodiscard]] engine::result<void> validate() override
    {
        try
        {
            const auto record_size = records->file->size();
            const auto index_size = indexes->file->size();
            const auto outcome_size = outcomes->file->size();
            if (!record_size || !index_size || !outcome_size || *record_size != records->bytes ||
                *index_size != indexes->bytes || *outcome_size != outcomes->bytes ||
                metadata.target_count > std::numeric_limits<std::uint64_t>::max() / index_bytes ||
                metadata.target_count > std::numeric_limits<std::uint64_t>::max() / outcome_bytes ||
                indexes->bytes != metadata.target_count * index_bytes ||
                outcomes->bytes != metadata.target_count * outcome_bytes)
            {
                return std::unexpected(failure("quick_store_file_size_changed"));
            }
            auto digest = initial_digest(metadata.job_id);
            std::uint64_t next = 0;
            std::string previous_path;
            for (std::size_t position = 0; position < metadata.target_count; ++position)
            {
                auto encoded_index = read_index(position);
                if (!encoded_index)
                {
                    return std::unexpected(encoded_index.error());
                }
                auto decoded = read_target(*records, get_integer(*encoded_index), maximum_record_bytes);
                if (!decoded)
                {
                    return std::unexpected(decoded.error());
                }
                const auto target_metadata = decode_index(*encoded_index);
                if (decoded->offset != next || decoded->payload_bytes != get_integer(std::span(*encoded_index).subspan(8, 8)) ||
                    !std::equal(decoded->digest.begin(), decoded->digest.end(), encoded_index->begin() + 80) ||
                    namespace_digest(decoded->value) != target_metadata.namespace_digest ||
                    (position != 0 && previous_path >= decoded->value.path) ||
                    target_metadata.allocated_bytes != decoded->value.allocated_bytes ||
                    target_metadata.logical_size_bytes != decoded->value.logical_size_bytes ||
                    target_metadata.logical_size_known != decoded->value.logical_size_known ||
                    target_metadata.type_known != decoded->value.type_known ||
                    target_metadata.directory != decoded->value.directory ||
                    target_metadata.preparation_failed != !decoded->value.preparation_error.code.empty() ||
                    (target_metadata.parent != absent_parent && target_metadata.parent >= position) ||
                    (target_metadata.device_index != std::numeric_limits<std::uint32_t>::max() &&
                     (target_metadata.device_index >= metadata.device_keys.size() ||
                      metadata.device_keys[target_metadata.device_index] != decoded->value.device_key)) ||
                    (target_metadata.device_index == std::numeric_limits<std::uint32_t>::max() &&
                     !decoded->value.device_key.empty()))
                {
                    return std::unexpected(failure("quick_store_index_binding_invalid"));
                }
                if (target_metadata.parent != absent_parent)
                {
                    auto parent = load(static_cast<std::size_t>(target_metadata.parent));
                    if (!parent || !parent->directory || !ancestor(parent->path, decoded->value.path))
                    {
                        return std::unexpected(failure("quick_store_parent_binding_invalid"));
                    }
                }
                next = decoded->next;
                previous_path = std::move(decoded->value.path);
                digest = chain_digest(digest, std::span(*encoded_index).first(index_payload_bytes));
            }
            if (next != records->bytes || finish_digest(digest, metadata.target_count) != metadata.fingerprint)
            {
                return std::unexpected(failure("quick_store_fingerprint_invalid"));
            }
            return {};
        }
        catch (const std::bad_alloc&)
        {
            return std::unexpected(failure("quick_store_validation_allocation_failed"));
        }
    }

    [[nodiscard]] engine::result<target_index> index(std::size_t position) override
    {
        auto bytes = read_index(position);
        if (!bytes)
        {
            return std::unexpected(bytes.error());
        }
        return decode_index(*bytes);
    }

    [[nodiscard]] engine::result<target> load(std::size_t position) override
    {
        try
        {
            auto bytes = read_index(position);
            if (!bytes)
            {
                return std::unexpected(bytes.error());
            }
            auto decoded = read_target(*records, get_integer(*bytes), maximum_record_bytes);
            if (!decoded)
            {
                return std::unexpected(decoded.error());
            }
            if (decoded->payload_bytes != get_integer(std::span(*bytes).subspan(8, 8)) ||
                !std::equal(decoded->digest.begin(), decoded->digest.end(), bytes->begin() + 80) ||
                namespace_digest(decoded->value) != decode_index(*bytes).namespace_digest)
            {
                return std::unexpected(failure("quick_store_loaded_record_binding_invalid"));
            }
            return std::move(decoded->value);
        }
        catch (const std::bad_alloc&)
        {
            return std::unexpected(failure("quick_store_read_allocation_failed"));
        }
    }

    [[nodiscard]] engine::result<void> begin(const staged_plan_info& plan, bool reuse_completed) override
    {
        const std::scoped_lock lock(outcome_mutex_);
        if (plan.job_id != metadata.job_id || plan.fingerprint != metadata.fingerprint ||
            plan.target_count != metadata.target_count || (begun_ && (!reuse_completed || !finished_)) ||
            (!begun_ && reuse_completed))
        {
            return std::unexpected(failure("quick_store_outcome_binding_invalid"));
        }
        const auto size = outcomes->file->size();
        if (!size || *size != outcomes->bytes)
        {
            return std::unexpected(failure("quick_store_outcome_size_changed"));
        }
        auto flushed = outcomes->file->flush();
        if (!flushed)
        {
            return flushed;
        }
        begun_ = true;
        finished_ = false;
        return {};
    }

    [[nodiscard]] engine::result<void> record(std::size_t position,
        const engine::target_outcome& value) override
    {
        const std::scoped_lock lock(outcome_mutex_);
        if (!begun_ || finished_ || position >= metadata.target_count || value.code.empty() ||
            value.code.size() > 512 || !valid_utf8(value.code) || value.logical_overwrite_verified ||
            value.physical_sanitization_guaranteed || value.written_bytes != 0 || value.verified_bytes != 0 ||
            (value.deleted && (!value.remove_attempted || value.code != "deleted_quick_namespace_removed" || value.native_code != 0)) ||
            (!value.deleted && value.code == "deleted_quick_namespace_removed"))
        {
            return std::unexpected(failure("quick_store_outcome_invalid"));
        }
        auto indexed = index(position);
        if (!indexed)
        {
            return std::unexpected(indexed.error());
        }
        if (!hex_equals(indexed->namespace_digest, value.identity) ||
            (value.remove_attempted && indexed->preparation_failed))
        {
            return std::unexpected(failure("quick_store_outcome_identity_invalid"));
        }
        std::array<std::byte, outcome_bytes> bytes{};
        put_integer(bytes, 2);
        put_integer(std::span(bytes).subspan(8), value.code.size());
        put_integer(std::span(bytes).subspan(16), static_cast<std::uint64_t>(value.deleted) |
            (static_cast<std::uint64_t>(value.remove_attempted) << 1));
        put_integer(std::span(bytes).subspan(24), value.native_code);
        const auto code = std::as_bytes(std::span(value.code.data(), value.code.size()));
        std::copy(code.begin(), code.end(), bytes.begin() + 32);
        const auto digest = outcome_digest(indexed->namespace_digest, position, std::span(bytes).first(544));
        std::copy(digest.begin(), digest.end(), bytes.begin() + 544);
        return outcomes->file->write_at(position * outcome_bytes, bytes);
    }

    [[nodiscard]] engine::result<engine::target_outcome> read(std::size_t position) override
    {
        try
        {
            return read_outcome(position);
        }
        catch (const std::bad_alloc&)
        {
            return std::unexpected(failure("quick_store_outcome_allocation_failed"));
        }
    }

    [[nodiscard]] engine::result<engine::target_outcome> read_outcome(std::size_t position)
    {
        const std::scoped_lock lock(outcome_mutex_);
        auto indexed = index(position);
        if (!indexed)
        {
            return std::unexpected(indexed.error());
        }
        std::array<std::byte, outcome_bytes> bytes{};
        auto read = outcomes->file->read_at(position * outcome_bytes, bytes);
        if (!read)
        {
            return std::unexpected(read.error());
        }
        engine::target_outcome value;
        value.identity = crypto::hex_digest(indexed->namespace_digest);
        if (std::all_of(bytes.begin(), bytes.end(), [](std::byte byte)
        {
            return byte == std::byte{};
        }))
        {
            value.code = "quick_not_attempted";
            return value;
        }
        const auto length = get_integer(std::span(bytes).subspan(8));
        const auto flags = get_integer(std::span(bytes).subspan(16));
        const auto native = get_integer(std::span(bytes).subspan(24));
        const auto digest = outcome_digest(indexed->namespace_digest, position, std::span(bytes).first(544));
        if (get_integer(bytes) != 2 || length == 0 || length > 512 || flags > 3 ||
            native > std::numeric_limits<std::uint32_t>::max() ||
            !std::equal(digest.begin(), digest.end(), bytes.begin() + 544))
        {
            return std::unexpected(failure("quick_store_outcome_integrity_failed"));
        }
        value.code.assign(reinterpret_cast<const char*>(bytes.data() + 32), static_cast<std::size_t>(length));
        value.deleted = (flags & 1) != 0;
        value.remove_attempted = (flags & 2) != 0;
        value.native_code = static_cast<std::uint32_t>(native);
        if (!valid_utf8(value.code) || (value.remove_attempted && indexed->preparation_failed) ||
            (value.deleted && (!value.remove_attempted || value.code != "deleted_quick_namespace_removed" || value.native_code != 0)) ||
            (!value.deleted && value.code == "deleted_quick_namespace_removed"))
        {
            return std::unexpected(failure("quick_store_outcome_invalid"));
        }
        return value;
    }

    [[nodiscard]] engine::result<void> finish(const staged_report& value) override
    {
        const std::scoped_lock lock(outcome_mutex_);
        if (!begun_ || finished_ || value.job_id != metadata.job_id ||
            value.plan_fingerprint != metadata.fingerprint || value.total != metadata.target_count ||
            value.completed > value.attempted || value.failed > value.attempted - value.completed ||
            value.attempted > value.total || value.unattempted != value.total - value.attempted ||
            value.status.empty() || value.status.size() > 128 || !valid_utf8(value.status) ||
            value.stopping_error.code.size() > 512 || !valid_utf8(value.stopping_error.code) ||
            (value.status == "completed" && (value.completed != value.total || value.failed != 0 ||
             value.unattempted != 0 || !value.stopping_error.code.empty())))
        {
            return std::unexpected(failure("quick_store_final_report_binding_invalid"));
        }
        auto flushed = outcomes->file->flush();
        if (flushed)
        {
            finished_ = true;
        }
        return flushed;
    }

private:
    [[nodiscard]] engine::result<std::array<std::byte, index_bytes>> read_index(std::size_t position)
    {
        if (position >= metadata.target_count)
        {
            return std::unexpected(failure("quick_store_index_out_of_range"));
        }
        std::array<std::byte, index_bytes> bytes{};
        auto read = indexes->file->read_at(position * index_bytes, bytes);
        if (!read)
        {
            return std::unexpected(read.error());
        }
        const auto digest = crypto::sha256(std::span(bytes).first(index_payload_bytes));
        if (!std::equal(digest.begin(), digest.end(), bytes.begin() + index_payload_bytes) ||
            get_integer(std::span(bytes).subspan(40)) > 15 ||
            get_integer(std::span(bytes).subspan(32)) > std::numeric_limits<std::uint32_t>::max())
        {
            return std::unexpected(failure("quick_store_index_integrity_failed"));
        }
        return bytes;
    }

    [[nodiscard]] static target_index decode_index(std::span<const std::byte> bytes)
    {
        target_index value;
        value.parent = get_integer(bytes.subspan(16));
        value.allocated_bytes = get_integer(bytes.subspan(24));
        value.device_index = static_cast<std::uint32_t>(get_integer(bytes.subspan(32)));
        const auto flags = get_integer(bytes.subspan(40));
        value.directory = (flags & 1) != 0;
        value.preparation_failed = (flags & 2) != 0;
        value.logical_size_known = (flags & 4) != 0;
        value.type_known = (flags & 8) != 0;
        value.logical_size_bytes = get_integer(bytes.subspan(112));
        std::copy_n(bytes.begin() + 48, 32, value.namespace_digest.begin());
        return value;
    }

    std::mutex outcome_mutex_;
    bool begun_{};
    bool finished_{};
};
}

struct staging_store::implementation
{
    std::shared_ptr<file_factory> files;
    std::shared_ptr<disk_account> accounting{std::make_shared<disk_account>()};
    std::string job_id;
    options settings;
    statistics metrics;
    std::list<target> buffer;
    std::uint64_t buffer_bytes{};
    std::uint64_t maximum_record_bytes{};
    std::uint64_t next_file{};
    std::uint64_t checked_disk_headroom{};
    std::vector<std::optional<run_file>> levels;
    std::mutex mutex;
    engine::error error;
    bool closed{};

    [[nodiscard]] engine::result<std::shared_ptr<owned_file>> create_file()
    {
        if (next_file == std::numeric_limits<std::uint64_t>::max())
        {
            return std::unexpected(failure("quick_store_file_sequence_exhausted"));
        }
        auto available = files->available_bytes();
        if (!available)
        {
            return std::unexpected(available.error());
        }
        checked_disk_headroom = *available;
        auto name = "quick_" + job_id + "_" + std::to_string(next_file++) + ".stage";
        auto result = std::make_shared<owned_file>();
        result->factory = files;
        result->accounting = accounting;
        result->name = std::move(name);
        auto opened = files->create_private(result->name);
        if (!opened)
        {
            return std::unexpected(opened.error());
        }
        result->file = std::move(*opened);
        return result;
    }

    [[nodiscard]] engine::result<void> claim(const std::shared_ptr<owned_file>& file, std::uint64_t amount)
    {
        // CONTRACT: Disk-space queries belong to run/reservation boundaries,
        // not every target record. Writes still propagate actual disk-full errors;
        // no deletion begins until every frozen and outcome byte is allocated.
        if (amount > checked_disk_headroom)
        {
            auto available = files->available_bytes();
            if (!available)
            {
                return std::unexpected(available.error());
            }
            checked_disk_headroom = *available;
        }
        if (accounting->bytes > settings.disk_budget_bytes ||
            amount > settings.disk_budget_bytes - accounting->bytes || amount > checked_disk_headroom ||
            amount > std::numeric_limits<std::uint64_t>::max() - file->bytes)
        {
            return std::unexpected(failure("quick_store_disk_budget_exhausted"));
        }
        checked_disk_headroom -= amount;
        accounting->bytes += amount;
        accounting->peak = std::max(accounting->peak, accounting->bytes);
        file->bytes += amount;
        return {};
    }

    [[nodiscard]] engine::result<void> append_record(run_file& run, const target& value)
    {
        auto bytes = encode(value);
        if (bytes.size() - 40 > maximum_record_bytes)
        {
            return std::unexpected(failure("quick_store_target_memory_insufficient"));
        }
        const auto position = run.file->bytes;
        auto claimed = claim(run.file, bytes.size());
        if (!claimed)
        {
            return claimed;
        }
        auto written = run.file->file->write_at(position, bytes);
        if (written)
        {
            ++run.count;
        }
        return written;
    }

    [[nodiscard]] engine::result<run_file> merge(run_file left, run_file right)
    {
        auto file = create_file();
        if (!file)
        {
            return std::unexpected(file.error());
        }
        run_file output{std::move(*file), 0};
        std::optional<read_record> first;
        std::optional<read_record> second;
        std::uint64_t left_position = 0;
        std::uint64_t right_position = 0;
        while (first || second || left_position < left.file->bytes || right_position < right.file->bytes)
        {
            if (!first && left_position < left.file->bytes)
            {
                auto record = read_target(*left.file, left_position, maximum_record_bytes);
                if (!record)
                {
                    return std::unexpected(record.error());
                }
                first = std::move(*record);
                left_position = first->next;
            }
            if (!second && right_position < right.file->bytes)
            {
                auto record = read_target(*right.file, right_position, maximum_record_bytes);
                if (!record)
                {
                    return std::unexpected(record.error());
                }
                second = std::move(*record);
                right_position = second->next;
            }
            if (first && second && first->value.path == second->value.path)
            {
                if (!same_target(first->value, second->value))
                {
                    return std::unexpected(failure("quick_conflicting_namespace"));
                }
                ++metrics.duplicate_targets;
                second.reset();
            }
            const bool take_first = first && (!second || first->value.path < second->value.path);
            auto& selected = take_first ? first : second;
            auto written = append_record(output, selected->value);
            if (!written)
            {
                return std::unexpected(written.error());
            }
            selected.reset();
        }
        auto flushed = output.file->file->flush();
        if (!flushed)
        {
            return std::unexpected(flushed.error());
        }
        ++metrics.merge_passes;
        return output;
    }

    [[nodiscard]] engine::result<void> spill()
    {
        if (buffer.empty())
        {
            return {};
        }
        buffer.sort([](const target& left, const target& right)
        {
            return left.path < right.path;
        });
        auto file = create_file();
        if (!file)
        {
            return std::unexpected(file.error());
        }
        run_file run{std::move(*file), 0};
        const target* previous = nullptr;
        for (const auto& value : buffer)
        {
            if (previous && previous->path == value.path)
            {
                if (!same_target(*previous, value))
                {
                    return std::unexpected(failure("quick_conflicting_namespace"));
                }
                ++metrics.duplicate_targets;
                continue;
            }
            auto written = append_record(run, value);
            if (!written)
            {
                return written;
            }
            previous = &value;
        }
        auto flushed = run.file->file->flush();
        if (!flushed)
        {
            return flushed;
        }
        buffer.clear();
        buffer_bytes = 0;
        ++metrics.run_count;
        std::size_t level = 0;
        while (level < levels.size() && levels[level])
        {
            auto combined = merge(std::move(*levels[level]), std::move(run));
            levels[level].reset();
            if (!combined)
            {
                return std::unexpected(combined.error());
            }
            run = std::move(*combined);
            ++level;
        }
        if (level == levels.size())
        {
            levels.emplace_back();
        }
        levels[level] = std::move(run);
        return {};
    }

    [[nodiscard]] engine::result<batch> finish()
    {
        auto flushed = spill();
        if (!flushed)
        {
            return std::unexpected(flushed.error());
        }
        std::optional<run_file> final_run;
        for (auto& level : levels)
        {
            if (!level)
            {
                continue;
            }
            if (final_run)
            {
                auto combined = merge(std::move(*final_run), std::move(*level));
                level.reset();
                if (!combined)
                {
                    return std::unexpected(combined.error());
                }
                final_run = std::move(*combined);
            }
            else
            {
                final_run = std::move(*level);
                level.reset();
            }
        }
        if (!final_run || final_run->count == 0 ||
            final_run->count > std::numeric_limits<std::size_t>::max() ||
            final_run->count > std::numeric_limits<std::uint64_t>::max() / outcome_bytes)
        {
            return std::unexpected(failure("quick_store_empty_or_unrepresentable_plan"));
        }
        auto index_file = create_file();
        auto outcome_file = create_file();
        if (!index_file)
        {
            return std::unexpected(index_file.error());
        }
        if (!outcome_file)
        {
            return std::unexpected(outcome_file.error());
        }
        auto frozen = std::make_shared<frozen_batch>();
        frozen->records = std::move(final_run->file);
        frozen->indexes = std::move(*index_file);
        frozen->outcomes = std::move(*outcome_file);
        frozen->maximum_record_bytes = maximum_record_bytes;
        frozen->metadata.job_id = job_id;
        frozen->metadata.target_count = static_cast<std::size_t>(final_run->count);
        auto claimed = claim(frozen->indexes, final_run->count * index_bytes);
        if (!claimed)
        {
            return std::unexpected(claimed.error());
        }
        claimed = claim(frozen->outcomes, final_run->count * outcome_bytes);
        if (!claimed)
        {
            return std::unexpected(claimed.error());
        }
        auto reserved = frozen->indexes->file->resize(frozen->indexes->bytes);
        if (!reserved)
        {
            return std::unexpected(reserved.error());
        }
        reserved = frozen->outcomes->file->resize(frozen->outcomes->bytes);
        if (!reserved)
        {
            return std::unexpected(reserved.error());
        }
        // FORMAT: Byte-lexical siblings such as a-b may occur between directory
        // a and child a/x. A traversal stack would lose that parent. A bounded
        // directory cache accelerates exact-prefix lookup; the sealed disk index
        // supplies binary search on every cache miss without retaining all paths.
        std::map<std::string, std::uint64_t, std::less<>> directory_cache;
        std::uint64_t cache_bytes = 0;
        const auto cache_budget = settings.memory_budget_bytes / 16;
        const auto cache_result = [&](std::string_view path, std::uint64_t value)
        {
            const auto entry_bytes = path.size() + 160;
            if (entry_bytes > cache_budget || directory_cache.contains(path))
            {
                return;
            }
            if (cache_bytes > cache_budget - entry_bytes)
            {
                directory_cache.clear();
                cache_bytes = 0;
            }
            directory_cache.emplace(std::string(path), value);
            cache_bytes += entry_bytes;
        };
        auto digest = initial_digest(job_id);
        std::uint64_t record_position = 0;
        std::uint64_t device_memory = 0;
        for (std::size_t position = 0; position < frozen->metadata.target_count; ++position)
        {
            auto current = read_target(*frozen->records, record_position, maximum_record_bytes);
            if (!current)
            {
                return std::unexpected(current.error());
            }
            if (!add(metrics.target_text_bytes, current->value.path.size()) ||
                !add(metrics.target_text_bytes, current->value.identity.size()))
            {
                return std::unexpected(failure("quick_store_report_size_unrepresentable"));
            }
            auto parent_position = absent_parent;
            auto prefix_end = current->value.path.find_last_of("\\/");
            while (prefix_end != std::string::npos)
            {
                auto length = prefix_end;
                if (prefix_end == 0 || (prefix_end > 0 && current->value.path[prefix_end - 1] == ':'))
                {
                    ++length;
                }
                const std::string_view prefix(current->value.path.data(), length);
                const auto cached = directory_cache.find(prefix);
                if (cached != directory_cache.end())
                {
                    if (cached->second != absent_parent)
                    {
                        parent_position = cached->second;
                        break;
                    }
                }
                else
                {
                    std::size_t low = 0;
                    std::size_t high = position;
                    while (low < high)
                    {
                        const auto middle = low + (high - low) / 2;
                        auto candidate = frozen->load(middle);
                        if (!candidate)
                        {
                            return std::unexpected(candidate.error());
                        }
                        if (candidate->path < prefix)
                        {
                            low = middle + 1;
                        }
                        else
                        {
                            high = middle;
                        }
                    }
                    if (low < position)
                    {
                        auto candidate = frozen->load(low);
                        if (!candidate)
                        {
                            return std::unexpected(candidate.error());
                        }
                        if (candidate->directory && candidate->path == prefix)
                        {
                            parent_position = low;
                            cache_result(prefix, low);
                            break;
                        }
                    }
                    // A selected parent is a strict lexical prefix and would
                    // already be indexed. Negative results remain valid for all
                    // subsequent names and avoid repeated full ancestor probes.
                    cache_result(prefix, absent_parent);
                }
                if (prefix_end == 0)
                {
                    break;
                }
                prefix_end = current->value.path.find_last_of("\\/", prefix_end - 1);
            }
            std::array<std::byte, index_bytes> bytes{};
            put_integer(bytes, current->offset);
            put_integer(std::span(bytes).subspan(8), current->payload_bytes);
            put_integer(std::span(bytes).subspan(16), parent_position);
            put_integer(std::span(bytes).subspan(24), current->value.allocated_bytes);
            auto device = std::numeric_limits<std::uint32_t>::max();
            if (!current->value.device_key.empty())
            {
                auto found = std::find(frozen->metadata.device_keys.begin(), frozen->metadata.device_keys.end(),
                    current->value.device_key);
                if (found == frozen->metadata.device_keys.end())
                {
                    if (frozen->metadata.device_keys.size() >= std::numeric_limits<std::uint32_t>::max() ||
                        !add(device_memory, 2 * (sizeof(std::string) + current->value.device_key.size() + 32)) ||
                        device_memory > settings.memory_budget_bytes / 8)
                    {
                        return std::unexpected(failure("quick_store_device_metadata_memory_insufficient"));
                    }
                    device = static_cast<std::uint32_t>(frozen->metadata.device_keys.size());
                    frozen->metadata.device_keys.push_back(current->value.device_key);
                }
                else
                {
                    device = static_cast<std::uint32_t>(found - frozen->metadata.device_keys.begin());
                }
            }
            put_integer(std::span(bytes).subspan(32), device);
            put_integer(std::span(bytes).subspan(40), static_cast<std::uint64_t>(current->value.directory) |
                (static_cast<std::uint64_t>(!current->value.preparation_error.code.empty()) << 1) |
                (static_cast<std::uint64_t>(current->value.logical_size_known) << 2) |
                (static_cast<std::uint64_t>(current->value.type_known) << 3));
            put_integer(std::span(bytes).subspan(112), current->value.logical_size_bytes);
            const auto name_digest = namespace_digest(current->value);
            std::copy(name_digest.begin(), name_digest.end(), bytes.begin() + 48);
            std::copy(current->digest.begin(), current->digest.end(), bytes.begin() + 80);
            const auto hash = crypto::sha256(std::span(bytes).first(index_payload_bytes));
            std::copy(hash.begin(), hash.end(), bytes.begin() + index_payload_bytes);
            auto written = frozen->indexes->file->write_at(position * index_bytes, bytes);
            if (!written)
            {
                return std::unexpected(written.error());
            }
            digest = chain_digest(digest, std::span(bytes).first(index_payload_bytes));
            frozen->metadata.maximum_target_bytes = std::max(frozen->metadata.maximum_target_bytes,
                4 * current->payload_bytes + 4 * sizeof(target) + 1024);
            const auto depth = static_cast<std::uint64_t>(std::count_if(current->value.path.begin(),
                current->value.path.end(), [](char ch)
            {
                return ch == '\\' || ch == '/';
            })) + 1;
            frozen->metadata.maximum_ancestor_depth = std::max(frozen->metadata.maximum_ancestor_depth, depth);
            if (current->value.directory)
            {
                cache_result(current->value.path, position);
            }
            record_position = current->next;
        }
        frozen->metadata.fingerprint = finish_digest(digest, frozen->metadata.target_count);
        frozen->metadata.resident_bytes = 4096 + maximum_record_bytes * 4 + device_memory;
        if (frozen->metadata.resident_bytes > settings.memory_budget_bytes)
        {
            return std::unexpected(failure("quick_store_sealed_metadata_memory_insufficient"));
        }
        for (const auto& file : {frozen->records, frozen->indexes, frozen->outcomes})
        {
            auto result = file->file->flush();
            if (!result)
            {
                return std::unexpected(result.error());
            }
        }
        auto checked = frozen->validate();
        if (!checked)
        {
            return std::unexpected(checked.error());
        }
        metrics.unique_targets = frozen->metadata.target_count;
        metrics.disk_bytes = accounting->peak;
        return batch{frozen, frozen, metrics};
    }
};

staging_store::staging_store(std::unique_ptr<implementation> state) noexcept : state_(std::move(state))
{
}

staging_store::~staging_store() = default;

engine::result<std::unique_ptr<staging_store>> staging_store::create(
    std::shared_ptr<file_factory> files, std::string job_id, options settings)
{
    if (!files || (job_id.size() != 32 && job_id.size() != 64) ||
        !std::all_of(job_id.begin(), job_id.end(), [](char ch)
        {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        }) || settings.memory_budget_bytes < 16384 || settings.disk_budget_bytes == 0)
    {
        return std::unexpected(failure("quick_store_configuration_invalid"));
    }
    try
    {
        auto value = std::make_unique<implementation>();
        value->files = std::move(files);
        value->job_id = std::move(job_id);
        value->settings = settings;
        value->maximum_record_bytes = settings.memory_budget_bytes / 16;
        return std::unique_ptr<staging_store>(new staging_store(std::move(value)));
    }
    catch (const std::bad_alloc&)
    {
        return std::unexpected(failure("quick_store_allocation_failed"));
    }
}

engine::result<void> staging_store::append(target value)
{
    const std::scoped_lock lock(state_->mutex);
    if (!state_->error.code.empty())
    {
        return std::unexpected(state_->error);
    }
    if (state_->closed)
    {
        return std::unexpected(failure("quick_store_already_finalized"));
    }
    if (!valid_target(value))
    {
        state_->error = failure("quick_invalid_target");
        return std::unexpected(state_->error);
    }
    try
    {
        const auto bytes = target_memory(value);
        if (bytes > state_->maximum_record_bytes)
        {
            state_->error = failure("quick_store_target_memory_insufficient");
            return std::unexpected(state_->error);
        }
        if (bytes > state_->settings.memory_budget_bytes / 4 - state_->buffer_bytes)
        {
            auto spilled = state_->spill();
            if (!spilled)
            {
                state_->error = spilled.error();
                return spilled;
            }
        }
        if (state_->metrics.appended_targets == std::numeric_limits<std::uint64_t>::max())
        {
            state_->error = failure("quick_store_target_count_unrepresentable");
            return std::unexpected(state_->error);
        }
        state_->buffer.push_back(std::move(value));
        state_->buffer_bytes += bytes;
        state_->metrics.peak_buffer_bytes = std::max(state_->metrics.peak_buffer_bytes, state_->buffer_bytes);
        ++state_->metrics.appended_targets;
        return {};
    }
    catch (const std::bad_alloc&)
    {
        state_->error = failure("quick_store_allocation_failed");
        return std::unexpected(state_->error);
    }
}

engine::result<batch> staging_store::finalize()
{
    const std::scoped_lock lock(state_->mutex);
    if (!state_->error.code.empty())
    {
        return std::unexpected(state_->error);
    }
    if (state_->closed)
    {
        return std::unexpected(failure("quick_store_already_finalized"));
    }
    state_->closed = true;
    try
    {
        auto result = state_->finish();
        if (!result)
        {
            state_->error = result.error();
        }
        return result;
    }
    catch (const std::bad_alloc&)
    {
        state_->error = failure("quick_store_allocation_failed");
        return std::unexpected(state_->error);
    }
}
}
