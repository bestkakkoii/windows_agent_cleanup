export module secure_erase.platform;

import std;
export import secure_erase.model;

export namespace secure_erase::engine
{
// CONTRACT: platform handle pins identity and ancestors, prevents external mutation,
// and never follows reparses. All operations remain attached to the held object.
class target_handle
{
public:
    virtual ~target_handle() = default;
    [[nodiscard]] virtual result<target_snapshot> inspect() = 0;
    // CONTRACT: settle engine-owned attribute changes while identity/data handles
    // remain pinned. Returned metadata must remain valid after handle destruction.
    [[nodiscard]] virtual result<target_snapshot> checkpoint_snapshot()
    {
        return inspect();
    }
    [[nodiscard]] virtual result<std::size_t> read(std::string_view stream,
        std::uint64_t offset, std::span<std::byte> buffer) = 0;
    [[nodiscard]] virtual result<std::size_t> write(std::string_view stream,
        std::uint64_t offset, std::span<const std::byte> buffer) = 0;
    [[nodiscard]] virtual result<void> flush(std::string_view stream) = 0;
    [[nodiscard]] virtual result<void> trim() = 0;
    // CONTRACT: directory removal succeeds only if empty; no recursion here.
    [[nodiscard]] virtual result<void> remove() = 0;
};

class platform
{
public:
    virtual ~platform() = default;
    [[nodiscard]] virtual bool is_elevated() const noexcept = 0;
    // CONTRACT: 0..100 CPU/RAM pressure hint; never replaces a safety check.
    [[nodiscard]] virtual unsigned resource_pressure() const noexcept
    {
        return 0;
    }
    // CONTRACT: reset read-only capability caches once per execute/resume phase.
    [[nodiscard]] virtual result<void> begin_execution()
    {
        return {};
    }
    [[nodiscard]] virtual result<std::vector<target_snapshot>> preview(
        const std::vector<std::string>& paths) = 0;
    [[nodiscard]] virtual result<std::unique_ptr<target_handle>> acquire(
        const target_snapshot& target) = 0;
    [[nodiscard]] virtual result<void> random_bytes(std::span<std::byte> bytes) = 0;
};

// SECURITY: production implementation must authenticate/encrypt all checkpoint bytes,
// restrict ACLs and atomically persist before returning success. Never log key material.
class checkpoint_store
{
public:
    virtual ~checkpoint_store() = default;
    [[nodiscard]] virtual result<void> save(const checkpoint& value) = 0;
    [[nodiscard]] virtual result<checkpoint> load(std::string_view job_id) = 0;
    [[nodiscard]] virtual result<void> remove(std::string_view job_id) = 0;
};

class event_sink
{
public:
    virtual ~event_sink() = default;
    [[nodiscard]] virtual result<void> emit(const event& value) = 0;
};

struct control
{
    std::atomic<control_request> request{control_request::proceed};
};
}
