export module secure_erase.quick_store;

import std;
export import secure_erase.quick_delete;

export namespace secure_erase::quick::store
{
    // SECURITY: Native factories create exclusive private no-reparse files and
    // retain write/delete-denying handles plus the protected root for their life.
    // File operations are exact and thread-safe; resize reserves real storage
    // and zero-fills every newly exposed byte before reporting success.
    class random_access_file
    {
    public:
        virtual ~random_access_file() = default;
        [[nodiscard]] virtual engine::result<void> read_at(
            std::uint64_t offset, std::span<std::byte> output) = 0;
        [[nodiscard]] virtual engine::result<void> write_at(
            std::uint64_t offset, std::span<const std::byte> input) = 0;
        [[nodiscard]] virtual engine::result<void> resize(std::uint64_t bytes) = 0;
        [[nodiscard]] virtual engine::result<void> flush() = 0;
        [[nodiscard]] virtual engine::result<std::uint64_t> size() const = 0;
    };

    class file_factory
    {
    public:
        virtual ~file_factory() = default;
        [[nodiscard]] virtual engine::result<std::shared_ptr<random_access_file>> create_private(
            std::string_view name) = 0;
        [[nodiscard]] virtual engine::result<void> remove_private(std::string_view name) = 0;
        [[nodiscard]] virtual engine::result<std::uint64_t> available_bytes() = 0;
    };

    struct options
    {
        std::uint64_t memory_budget_bytes{};
        std::uint64_t disk_budget_bytes{};
    };

    struct statistics
    {
        std::uint64_t appended_targets{};
        std::uint64_t unique_targets{};
        std::uint64_t duplicate_targets{};
        std::uint64_t run_count{};
        std::uint64_t merge_passes{};
        std::uint64_t peak_buffer_bytes{};
        // CONTRACT: Peak owned staging capacity, not attributed freed space.
        std::uint64_t disk_bytes{};
        // CONTRACT: Checked sum of unique path+identity byte lengths.
        std::uint64_t target_text_bytes{};
    };

    struct batch
    {
        std::shared_ptr<target_source> targets;
        std::shared_ptr<outcome_sink> outcomes;
        statistics metrics;
    };

    // CONTRACT: Append is thread-safe. Finalize follows the last append and
    // performs all sorting, identity-conflict detection, index sealing and full
    // outcome-file reservation before returning an executable immutable source.
    // No imported/reopened file is accepted as an execution plan or retry proof.
    class staging_store final : public target_sink
    {
    public:
        [[nodiscard]] static engine::result<std::unique_ptr<staging_store>> create(
            std::shared_ptr<file_factory> files, std::string job_id, options settings);
        ~staging_store() override;
        staging_store(const staging_store&) = delete;
        staging_store& operator=(const staging_store&) = delete;
        [[nodiscard]] engine::result<void> append(target value) override;
        [[nodiscard]] engine::result<batch> finalize();

    private:
        struct implementation;
        explicit staging_store(std::unique_ptr<implementation> state) noexcept;
        std::unique_ptr<implementation> state_;
    };
}
