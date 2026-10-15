export module secure_erase.windows_backend;

import std;
export import secure_erase.model;
export import secure_erase.quick_delete;
import secure_erase.platform;

export namespace secure_erase::engine
{
    enum class host_architecture : std::uint8_t
    {
        unknown,
        x86,
        x64,
        arm64,
        arm,
        other
    };

    [[nodiscard]] constexpr std::string_view host_architecture_name(host_architecture value) noexcept
    {
        switch (value)
        {
        case host_architecture::x86:
            return "x86";
        case host_architecture::x64:
            return "x64";
        case host_architecture::arm64:
            return "arm64";
        case host_architecture::arm:
            return "arm";
        case host_architecture::other:
            return "other";
        case host_architecture::unknown:
        default:
            return "unknown";
        }
    }

    struct host_observation_error
    {
        // CONTRACT: Codes have static lifetime; observations allocate no memory.
        std::string_view code;
        std::uint32_t native_code{};
    };

    struct host_readiness
    {
        std::uint32_t required_windows_build{};
        host_architecture required_native_architecture{host_architecture::x64};
        host_architecture required_process_architecture{host_architecture::x64};
        std::optional<std::uint32_t> windows_build;
        host_architecture native_architecture{host_architecture::unknown};
        host_architecture process_architecture{host_architecture::unknown};
        std::optional<bool> platform_supported;
        std::optional<bool> elevated;
        std::optional<bool> filesystem_commands_ready;
        std::optional<host_observation_error> platform_error;
        std::optional<host_observation_error> architecture_error;
        std::optional<host_observation_error> elevation_error;
    };

    // CONTRACT: Nonmutating, point-in-time observation of this execution thread's
    // effective token and host. Unknown observations retain diagnostics, never
    // become a false privilege denial. Readiness does not admit any path/job.
    [[nodiscard]] host_readiness inspect_host_readiness() noexcept;

    [[nodiscard]] result<std::unique_ptr<quick::backend>> make_windows_quick_backend(
        std::wstring_view state_directory, std::wstring_view allowed_scope_root = {});

    // CONTRACT: state_directory is an absolute local path; its entire tree is protected.
    // An explicit scope is a nofollow-bound directory, disjoint from state/report
    // storage. Scope replacement and every name outside it are rejected in core.
    [[nodiscard]] result<std::unique_ptr<platform>> make_windows_platform(
        std::wstring_view state_directory, std::wstring_view allowed_scope_root = {});

    [[nodiscard]] result<std::vector<locking_process>> query_locking_processes(
        std::string_view path);

    // SECURITY: force_confirmed authorizes exactly this PID + creation time, never a batch.
    // false sends bounded WM_CLOSE; true revalidates all protection checks before termination.
    [[nodiscard]] result<void> request_process_close(std::string_view path,
        const locking_process& process, bool force_confirmed,
        std::uint32_t timeout_ms = 5000);
}
