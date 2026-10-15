export module secure_erase.engine;

import std;
export import secure_erase.platform;
export import secure_erase.plan;

export namespace secure_erase::engine
{
[[nodiscard]] result<run_report> run(const frozen_plan& plan, const approval& consent,
    platform& host, checkpoint_store& store, event_sink& events, control& controls,
    options settings = {}, const checkpoint* resume = nullptr);
}
