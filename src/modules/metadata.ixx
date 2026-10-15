export module secure_erase.metadata;

import std;

export namespace secure_erase::metadata
{
    [[nodiscard]] constexpr const char* version() noexcept
    {
        return "2.0.0-rc.1";
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
