module secure_erase.engine:admission;

import std;
import secure_erase.model;
import secure_erase.crypto;

namespace secure_erase::engine::detail
{
[[nodiscard]] error failure(std::string code, bool device_fault = false)
{
    return {std::move(code), 0, device_fault};
}

[[nodiscard]] bool valid_hex(std::string_view value, std::size_t size)
{
    return value.size() == size && std::all_of(value.begin(), value.end(), [](char ch)
    {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

[[nodiscard]] bool structural_match(const target_snapshot& before,
    const target_snapshot& after, bool compare_times)
{
    // SECURITY: only READONLY and setting ARCHIVE may change during held engine IO.
    constexpr std::uint32_t readonly_attribute = 1;
    constexpr std::uint32_t archive_attribute = 0x20;
    constexpr std::uint32_t normal_attribute = 0x80;
    const auto before_attributes = before.attributes & ~normal_attribute;
    const auto after_attributes = after.attributes & ~normal_attribute;
    const bool metadata = before.path == after.path && before.identity == after.identity &&
        before.device_key == after.device_key && before.creation_time == after.creation_time &&
        ((before_attributes ^ after_attributes) & ~(readonly_attribute | archive_attribute)) == 0 &&
        ((before_attributes & archive_attribute) == 0 || (after_attributes & archive_attribute) != 0) &&
        before.link_count == after.link_count && before.directory == after.directory &&
        before.reparse_point == after.reparse_point && before.remote == after.remote &&
        before.encrypted == after.encrypted && before.compressed == after.compressed &&
        before.sparse == after.sparse && before.trim_supported == after.trim_supported &&
        before.vss_query_complete == after.vss_query_complete &&
        before.vss_snapshot_count == after.vss_snapshot_count &&
        before.vss_native_error == after.vss_native_error && before.media == after.media && before.support == after.support &&
        before.streams == after.streams && before.protection_reasons == after.protection_reasons &&
        before.residual_risks == after.residual_risks;
    if (!metadata)
    {
        return false;
    }
    if (compare_times)
    {
        const bool readonly_acquire_transition =
            (before_attributes & readonly_attribute) != 0 &&
            (after_attributes & readonly_attribute) == 0 &&
            ((before_attributes ^ after_attributes) & ~readonly_attribute) == 0 &&
            before.write_time == after.write_time;
        // CONTRACT: acquire verified the exact original snapshot before its own
        // temporary READONLY clear; all other structural fields remain identical.
        return readonly_acquire_transition || (before_attributes == after_attributes &&
            (before.directory || (before.write_time == after.write_time &&
             before.change_time == after.change_time)));
    }
    return true;
}

struct memory_estimate
{
    std::size_t fixed{};
    std::size_t per_worker{};
};

[[nodiscard]] std::optional<memory_estimate> estimate_memory(const frozen_plan& plan, std::size_t chunk)
{
    std::size_t metadata = sizeof(frozen_plan) + plan.job_id.size() + plan.fingerprint.size();
    std::size_t largest_snapshot = 0;
    auto add = [](std::size_t& destination, std::size_t count)
    {
        if (count > std::numeric_limits<std::size_t>::max() - destination)
        {
            return false;
        }
        destination += count;
        return true;
    };
    for (const auto& target : plan.targets)
    {
        std::size_t snapshot = sizeof(target_snapshot);
        if (!add(snapshot, target.path.size()) || !add(snapshot, target.identity.size()) ||
            !add(snapshot, target.device_key.size()))
        {
            return std::nullopt;
        }
        for (const auto& stream : target.streams)
        {
            if (!add(snapshot, sizeof(stream_snapshot)) || !add(snapshot, stream.name.size()))
            {
                return std::nullopt;
            }
        }
        for (const auto& reason : target.protection_reasons)
        {
            if (!add(snapshot, sizeof(std::string)) || !add(snapshot, reason.size()))
            {
                return std::nullopt;
            }
        }
        for (const auto& risk : target.residual_risks)
        {
            if (!add(snapshot, sizeof(std::string)) || !add(snapshot, risk.size()))
            {
                return std::nullopt;
            }
        }
        if (!add(metadata, snapshot))
        {
            return std::nullopt;
        }
        largest_snapshot = std::max(largest_snapshot, snapshot);
    }
    // CONTRACT: conservative application-owned manifest/state/codec copy allowance.
    // Excludes allocator overhead, GUI state, OS buffers and arbitrary user backends;
    // this is a bounded admission estimate, not a whole-process RSS guarantee.
    if (metadata > std::numeric_limits<std::size_t>::max() / 8 ||
        largest_snapshot > std::numeric_limits<std::size_t>::max() / 2)
    {
        return std::nullopt;
    }
    const auto count_overhead = plan.targets.size() *
        (sizeof(target_checkpoint) + sizeof(target_outcome) + sizeof(std::size_t) * 4);
    memory_estimate estimate{metadata * 8, largest_snapshot * 2};
    if (!add(estimate.fixed, count_overhead) || !add(estimate.per_worker, chunk * 2) ||
        !add(estimate.per_worker, sizeof(target_checkpoint) * 2))
    {
        return std::nullopt;
    }
    return estimate;
}

struct secret_cleanup
{
    checkpoint& value;
    ~secret_cleanup()
    {
        for (auto& target : value.targets)
        {
            crypto::secure_zero(target.key);
            crypto::secure_zero(target.nonce);
        }
    }
};
}
