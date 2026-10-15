module secure_erase.plan;

import std;
import secure_erase.crypto;
import secure_erase.model;

namespace secure_erase::engine
{
namespace
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

void append_integer(std::vector<std::byte>& bytes, std::uint64_t value)
{
    for (unsigned shift = 0; shift < 64; shift += 8)
    {
        bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_string(std::vector<std::byte>& bytes, std::string_view value)
{
    append_integer(bytes, value.size());
    const auto raw = std::as_bytes(std::span(value.data(), value.size()));
    bytes.insert(bytes.end(), raw.begin(), raw.end());
}

void append_target(std::vector<std::byte>& bytes, const target_snapshot& target)
{
    append_string(bytes, target.path);
    append_string(bytes, target.identity);
    append_string(bytes, target.device_key);
    append_integer(bytes, target.creation_time);
    append_integer(bytes, target.write_time);
    append_integer(bytes, target.change_time);
    append_integer(bytes, target.attributes);
    append_integer(bytes, target.link_count);
    append_integer(bytes, target.directory);
    append_integer(bytes, target.reparse_point);
    append_integer(bytes, target.remote);
    append_integer(bytes, target.encrypted);
    append_integer(bytes, target.compressed);
    append_integer(bytes, target.sparse);
    append_integer(bytes, target.trim_supported);
    append_integer(bytes, target.vss_query_complete);
    append_integer(bytes, target.vss_snapshot_count);
    append_integer(bytes, target.vss_native_error);
    append_integer(bytes, static_cast<std::uint8_t>(target.media));
    append_integer(bytes, static_cast<std::uint8_t>(target.support));
    append_integer(bytes, target.streams.size());
    for (const auto& stream : target.streams)
    {
        append_string(bytes, stream.name);
        append_integer(bytes, stream.size);
    }
    append_integer(bytes, target.protection_reasons.size());
    for (const auto& reason : target.protection_reasons)
    {
        append_string(bytes, reason);
    }
    append_integer(bytes, target.residual_risks.size());
    for (const auto& risk : target.residual_risks)
    {
        append_string(bytes, risk);
    }
}

}

std::string fingerprint(const frozen_plan& plan)
{
    std::vector<std::byte> bytes;
    append_string(bytes, "secure_erase.plan.v1");
    append_string(bytes, plan.job_id);
    append_integer(bytes, plan.targets.size());
    for (const auto& target : plan.targets)
    {
        append_target(bytes, target);
    }
    return crypto::hex_digest(crypto::sha256(bytes));
}

result<frozen_plan> freeze(std::string job_id, std::vector<target_snapshot> targets)
{
    if ((!valid_hex(job_id, 32) && !valid_hex(job_id, 64)) || targets.empty())
    {
        return std::unexpected(failure("invalid_plan_job_id_or_target_count"));
    }
    std::map<std::string, std::size_t> identities;
    std::set<std::string> paths;
    std::vector<target_snapshot> unique_targets;
    std::stable_sort(targets.begin(), targets.end(), [](const auto& left, const auto& right)
    {
        return left.path < right.path;
    });
    std::size_t text_bytes = 0;
    for (auto& target : targets)
    {
        if (target.path.empty() || target.identity.empty() || target.device_key.empty() ||
            target.path.size() > 131072 || target.identity.size() > 1024 ||
            target.device_key.size() > 1024 || target.link_count == 0 ||
            target.streams.size() > 1024 || target.protection_reasons.size() > 128 ||
            target.residual_risks.size() > 128 || (!target.directory && target.streams.empty()) ||
            target.path.find('\0') != std::string::npos || target.identity.find('\0') != std::string::npos ||
            target.device_key.find('\0') != std::string::npos ||
            static_cast<unsigned>(target.support) > static_cast<unsigned>(capability::delete_only) ||
            static_cast<unsigned>(target.media) > static_cast<unsigned>(media_kind::usb))
        {
            return std::unexpected(failure("invalid_or_duplicate_target_snapshot"));
        }
        std::set<std::string> streams;
        std::uint64_t size = 0;
        const auto add_text = [&text_bytes](std::size_t count)
        {
            if (count > std::numeric_limits<std::size_t>::max() - text_bytes)
            {
                return false;
            }
            text_bytes += count;
            return true;
        };
        if (!add_text(target.path.size()) || !add_text(target.identity.size()) ||
            !add_text(target.device_key.size()))
        {
            return std::unexpected(failure("plan_size_overflow"));
        }
        std::sort(target.streams.begin(), target.streams.end(), [](const auto& lhs, const auto& rhs)
        {
            return lhs.name < rhs.name;
        });
        for (const auto& stream : target.streams)
        {
            if (stream.name.size() > 131072 || stream.name.find('\0') != std::string::npos ||
                !streams.insert(stream.name).second ||
                stream.size > std::numeric_limits<std::uint64_t>::max() - size)
            {
                return std::unexpected(failure("invalid_stream_manifest"));
            }
            if (!add_text(stream.name.size()))
            {
                return std::unexpected(failure("plan_size_overflow"));
            }
            size += stream.size;
        }
        if (!target.directory && !streams.contains(""))
        {
            return std::unexpected(failure("unnamed_stream_missing_from_manifest"));
        }
        for (const auto& reason : target.protection_reasons)
        {
            if (reason.size() > 512)
            {
                return std::unexpected(failure("invalid_protection_reason"));
            }
            if (!add_text(reason.size()))
            {
                return std::unexpected(failure("plan_size_overflow"));
            }
        }
        for (const auto& risk : target.residual_risks)
        {
            if (risk.size() > 512)
            {
                return std::unexpected(failure("invalid_residual_risk"));
            }
            if (!add_text(risk.size()))
            {
                return std::unexpected(failure("plan_size_overflow"));
            }
        }
        // Admission budgets belong to the resource-aware caller/core. This
        // canonicalizer checks representability, not an arbitrary item/text cap.
        const auto duplicate = identities.find(target.identity);
        if (duplicate != identities.end())
        {
            const auto& existing = unique_targets.at(duplicate->second);
            auto alias = target;
            alias.path = existing.path;
            const bool same_path = target.path == existing.path;
            const bool safe_alias = !target.directory && target.link_count > 1 &&
                target.support == capability::delete_only &&
                std::find(target.residual_risks.begin(), target.residual_risks.end(),
                    "other_hardlink_aliases_retained") != target.residual_risks.end();
            if (alias != existing || (!same_path && !safe_alias))
            {
                return std::unexpected(failure("conflicting_duplicate_identity"));
            }
            // CONTRACT: exact duplicate selections collapse. Shared hardlink data is
            // never overwritten; only the canonical selected namespace may be deleted.
            continue;
        }
        if (!paths.insert(target.path).second)
        {
            return std::unexpected(failure("conflicting_duplicate_path"));
        }
        identities.emplace(target.identity, unique_targets.size());
        unique_targets.push_back(std::move(target));
    }
    targets = std::move(unique_targets);
    std::stable_sort(targets.begin(), targets.end(), [](const auto& lhs, const auto& rhs)
    {
        if (lhs.directory != rhs.directory)
        {
            return !lhs.directory;
        }
        if (lhs.directory && lhs.path.size() != rhs.path.size())
        {
            return lhs.path.size() > rhs.path.size();
        }
        return lhs.path < rhs.path;
    });
    frozen_plan plan{std::move(job_id), std::move(targets), {}};
    plan.fingerprint = fingerprint(plan);
    return plan;
}

bool needs_downgrade(const target_snapshot& target) noexcept
{
    return target.support == capability::overwrite_best_effort ||
        target.support == capability::delete_only;
}
}
