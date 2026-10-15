export module secure_erase.retained_copies;

import std;

export namespace secure_erase::windows
{
    struct retained_copy_observation
    {
        bool complete{};
        std::uint32_t snapshot_count{};
        std::uint32_t native_error{}; // CONTRACT: HRESULT bit pattern, not a Win32 error.
    };

    // SECURITY: Query only. Never creates/deletes snapshots, requests writer freezes,
    // mounts snapshot devices, changes VSS configuration, or reads retained file data.
    // CONTRACT: Counts visible completed snapshots of the specified volume at query
    // time. Zero is not proof of no backups/cloud replicas/prior copies. Failure is
    // explicit unknown, with a partial observed count and HRESULT where available.
    // Call once per unique volume per observation phase, never per I/O block.
    [[nodiscard]] retained_copy_observation query_retained_copies(
        std::wstring_view volume_guid_path);
}
