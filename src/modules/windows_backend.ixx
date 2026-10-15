export module secure_erase.windows_backend;

import std;
export import secure_erase.model;
export import secure_erase.quick_delete;
import secure_erase.platform;

export namespace secure_erase::engine
{
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
