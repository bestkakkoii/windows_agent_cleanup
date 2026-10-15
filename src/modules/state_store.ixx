export module secure_erase.state_store;

import std;
export import secure_erase.platform;
export import secure_erase.configuration;
import secure_erase.quick_store;

export namespace secure_erase::storage
{
    struct checkpoint_info
    {
        std::string job_id;
        std::uint64_t protected_bytes{};
        std::uint64_t modified_filetime{};
    };

    enum class request_lookup_state
    {
        terminal_result,
        intent_only,
        no_record_observed,
        ambiguous,
        unavailable,
        inspection_incomplete
    };

    struct request_status
    {
        std::string request_id;
        request_lookup_state lookup_state{request_lookup_state::unavailable};
        std::vector<std::string> report_references;
        // Exact validated final JSON bytes, without its JSONL newline. Not a new
        // authorization or a resumable plan; presentation must preserve the object.
        std::optional<std::string> original_result;
        engine::error observation_error;
    };

    // SECURITY: Current-user DPAPI scope; protected DACL grants only current user and
    // SYSTEM. Files are no-reparse/single-link; ancestors are pinned while open.
    // One process owns the store lock. This is not a boundary against an attacker
    // already acting as the same principal or SYSTEM, and does not prevent rollback
    // of an authentic old blob. Engine fresh confirmation + revalidation is mandatory.
    class state_store final : public engine::checkpoint_store, public engine::event_sink
    {
    public:
        [[nodiscard]] static engine::result<std::unique_ptr<state_store>> open(
            store_options settings = {});

        // CONTRACT: advanced isolated-test factory; parent must already exist on a
        // local fixed volume. Creates only the final private directory, rejects
        // reparses/unsafe existing ACLs, and returns its protected root to the caller.
        [[nodiscard]] static engine::result<std::unique_ptr<state_store>> open_at(
            std::wstring_view private_directory, store_options settings = {});

        // CONTRACT: Read existing private report evidence only. Never creates a
        // store, acquires its writer lock, rotates logs or restores staging. Pins
        // no-reparse ancestry and verifies private single-link report objects.
        // Inspect <=4096 directory entries, <=8 matching references and <=1MiB
        // of first/final record bytes. Limits/races leave completion unknown.
        [[nodiscard]] static request_status inspect_request(
            std::wstring_view existing_private_directory, std::string_view request_id);

        ~state_store() override;

        state_store(const state_store&) = delete;

        state_store& operator=(const state_store&) = delete;

        [[nodiscard]] engine::result<void> save(const engine::checkpoint& value) override;

        [[nodiscard]] engine::result<engine::checkpoint> load(std::string_view job_id) override;

        [[nodiscard]] engine::result<void> remove(std::string_view job_id) override;

        [[nodiscard]] engine::result<void> emit(const engine::event& value) override;

        // CONTRACT: At most64 events; validate all before mutation, append as one
        // bounded write/flush. Empty batches are no-ops; invalid batches write none.
        [[nodiscard]] engine::result<void> emit_batch(std::span<const engine::event> values);

        [[nodiscard]] engine::result<std::vector<checkpoint_info>> list_checkpoints();

        // CONTRACT: bounded UTF-8 JSONL history, oldest retained rotation first.
        [[nodiscard]] engine::result<std::string> read_history(std::size_t maximum_bytes = 1024 * 1024);

        [[nodiscard]] const std::wstring& root_path() const noexcept;

        // CONTRACT: Create a new ASCII request.random.report.jsonl leaf under
        // this pinned store with explicit current-user/SYSTEM owner and private
        // DACL. Transfers a native write handle; caller must CloseHandle it before
        // releasing the store. Its read sharing permits read-only status lookup.
        [[nodiscard]] engine::result<std::uintptr_t> create_report_handle(std::string_view leaf);

        // Ephemeral staging files retain the store lock, private ACL and pinned
        // ancestry; closing the last handle removes the scratch allocation.
        [[nodiscard]] engine::result<std::shared_ptr<quick::store::file_factory>> staging_files();

    private:
        [[nodiscard]] static engine::result<std::unique_ptr<state_store>> open_impl(
            std::wstring_view private_directory, store_options settings);

        struct implementation;

        explicit state_store(std::shared_ptr<implementation> state) noexcept;

        std::shared_ptr<implementation> state_;
    };
}
