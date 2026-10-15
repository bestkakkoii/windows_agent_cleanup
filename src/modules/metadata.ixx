export module secure_erase.metadata;

import std;

export namespace secure_erase::metadata
{
    [[nodiscard]] constexpr const char* version() noexcept
    {
        return SECURE_ERASE_APPLICATION_VERSION;
    }

    [[nodiscard]] constexpr const char* source_commit() noexcept
    {
        return SECURE_ERASE_SOURCE_COMMIT;
    }

    [[nodiscard]] constexpr bool source_commit_known() noexcept
    {
        return SECURE_ERASE_SOURCE_COMMIT_KNOWN != 0;
    }

    [[nodiscard]] constexpr bool source_dirty() noexcept
    {
        return SECURE_ERASE_SOURCE_DIRTY != 0;
    }

    [[nodiscard]] constexpr bool source_dirty_known() noexcept
    {
        return SECURE_ERASE_SOURCE_DIRTY_KNOWN != 0;
    }

    [[nodiscard]] constexpr const char* build_identity() noexcept
    {
        return SECURE_ERASE_BUILD_IDENTITY;
    }

    [[nodiscard]] constexpr const char* product_name() noexcept
    {
        return "windows_agent_cleanup";
    }

    [[nodiscard]] constexpr unsigned min_windows_build() noexcept
    {
        return 22000U;
    }

    [[nodiscard]] constexpr bool physical_sanitization_guaranteed() noexcept
    {
        return false;
    }
}
