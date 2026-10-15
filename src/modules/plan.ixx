export module secure_erase.plan;

import std;
export import secure_erase.model;

export namespace secure_erase::engine
{
// CONTRACT: freeze sorts files before directories (deepest first), hashes all fields,
// rejects duplicates/invalid metadata. run re-hashes to reject later mutation.
[[nodiscard]] result<frozen_plan> freeze(std::string job_id,
    std::vector<target_snapshot> targets);

[[nodiscard]] std::string fingerprint(const frozen_plan& plan);

[[nodiscard]] bool needs_downgrade(const target_snapshot& target) noexcept;
}
