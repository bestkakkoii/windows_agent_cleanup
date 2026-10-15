export module secure_erase.quick_feedback;

import std;

export namespace secure_erase::quick::feedback
{
    struct state
    {
        std::size_t limit{1};
        unsigned stable_windows{};
        unsigned probe_windows{};
        unsigned profitable_windows{};
        unsigned cooldown{};
        bool probing{};
        double previous_rate{};
        double previous_latency{};
        double baseline_rate{};
        double baseline_latency{};
    };

    enum class adjustment
    {
        unchanged,
        increase,
        decrease
    };

    // CONTRACT: The execution scheduler supplies completed observation windows.
    // Keep the decision independent of clocks, sleeps and thread wake order.
    [[nodiscard]] adjustment observe_window(state& group, double rate, double latency,
        bool pressure, std::size_t ceiling, std::size_t ready_count, bool cpu_pressure_known) noexcept
    {
        const auto previous_limit = group.limit;
        if (pressure)
        {
            group.limit = std::max<std::size_t>(1, group.limit / 2);
            group.stable_windows = 0;
            group.probing = false;
            group.cooldown = 3;
        }
        else if (group.probing)
        {
            // PERFORMANCE: Require two profitable windows; flat throughput does
            // not earn another worker. A material regression rolls back even when
            // per-operation latency is unchanged. Thresholds are tuning heuristics.
            ++group.probe_windows;
            const bool profitable = rate >= group.baseline_rate * 1.05 &&
                latency <= group.baseline_latency * 1.50;
            group.profitable_windows += static_cast<unsigned>(profitable);
            const bool regressed = rate < group.baseline_rate * 0.90 ||
                (latency > group.baseline_latency * 1.25 && rate < group.baseline_rate * 1.05);
            if (regressed || (group.probe_windows >= 2 && group.profitable_windows < 2))
            {
                group.limit = std::max<std::size_t>(1, group.limit - 1);
                group.cooldown = 3;
                group.probing = false;
            }
            else if (group.profitable_windows >= 2)
            {
                group.probing = false;
            }
            group.stable_windows = 0;
        }
        else if (group.cooldown != 0)
        {
            --group.cooldown;
        }
        else if (group.previous_rate == 0 ||
            (rate >= group.previous_rate * 0.85 && latency <= group.previous_latency * 1.20))
        {
            ++group.stable_windows;
            if (group.stable_windows >= 2 && group.limit < ceiling &&
                ready_count / 4 >= group.limit && cpu_pressure_known)
            {
                group.baseline_rate = rate;
                group.baseline_latency = latency;
                ++group.limit;
                group.probing = true;
                group.probe_windows = 0;
                group.profitable_windows = 0;
                group.stable_windows = 0;
            }
        }
        else
        {
            group.stable_windows = 0;
        }
        group.previous_rate = rate;
        group.previous_latency = latency;
        return group.limit > previous_limit ? adjustment::increase :
            group.limit < previous_limit ? adjustment::decrease : adjustment::unchanged;
    }
}
