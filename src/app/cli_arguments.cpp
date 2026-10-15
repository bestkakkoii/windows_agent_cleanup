module secure_erase.cli_arguments;

import std;

namespace secure_erase::cli
{
    namespace
    {
        bool hexadecimal(std::string_view text, std::size_t length)
        {
            return text.size() == length && std::ranges::all_of(text, [](char value)
            {
                return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
            });
        }

        template<class integer_type>
        bool number(std::string_view text, integer_type& result)
        {
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
            return !text.empty() && parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
        }
    }

    engine::result<arguments> parse(std::span<const std::string> tokens)
    {
        arguments result;
        if (tokens.empty())
        {
            return result;
        }
        result.command = tokens.front();
        if (result.command == "--help" || result.command == "--version")
        {
            result.command = "capabilities";
        }
        const std::set<std::string_view> commands{"capabilities", "scan", "run", "resume", "locks", "release"};
        if (!commands.contains(result.command))
        {
            return std::unexpected(engine::error{"unknown_command"});
        }
        std::set<std::string_view> seen;
        for (std::size_t index = 1; index < tokens.size(); ++index)
        {
            const std::string_view key = tokens[index];
            if (!seen.insert(key).second)
            {
                return std::unexpected(engine::error{"duplicate_option"});
            }
            if (key == "--authorize-irreversible")
            {
                result.irreversible = true;
                continue;
            }
            if (key == "--authorize-close")
            {
                result.process_close = true;
                continue;
            }
            if (key == "--authorize-force")
            {
                result.force_terminate = true;
                continue;
            }
            if (++index == tokens.size() || tokens[index].empty())
            {
                return std::unexpected(engine::error{"option_value_required"});
            }
            const auto& value = tokens[index];
            if (key == "--mode")
            {
                result.mode = value;
            }
            else if (key == "--request-id")
            {
                result.request_id = value;
            }
            else if (key == "--root")
            {
                result.root = value;
            }
            else if (key == "--manifest")
            {
                result.manifest = value;
            }
            else if (key == "--report-dir")
            {
                result.report_directory = value;
            }
            else if (key == "--job-id")
            {
                result.job_id = value;
            }
            else if (key == "--plan-fingerprint")
            {
                result.fingerprint = value;
            }
            else if (key == "--path")
            {
                result.path = value;
            }
            else if (key == "--target-key")
            {
                result.target_key = value;
            }
            else if (key == "--image")
            {
                result.image = value;
            }
            else if (key == "--pid" && number(value, result.process_id))
            {
            }
            else if (key == "--created" && number(value, result.creation_time))
            {
            }
            else if (key == "--workers" && number(value, result.workers))
            {
            }
            else if (key == "--memory-bytes" && number(value, result.memory_budget_bytes))
            {
            }
            else if (key == "--io-bytes-per-second" && number(value, result.execution_settings.io_budget_bytes_per_second))
            {
            }
            else if (key == "--ssd-queue-depth" && number(value, result.execution_settings.ssd_queue_depth))
            {
            }
            else if (key == "--log-retention-days" && number(value, result.retention.log_retention_days))
            {
            }
            else if (key == "--checkpoint-retention-days" && number(value, result.retention.checkpoint_retention_days))
            {
            }
            else
            {
                return std::unexpected(engine::error{"unknown_option_or_invalid_number"});
            }
        }
        if (result.command == "capabilities")
        {
            if (!seen.empty())
            {
                return std::unexpected(engine::error{"capabilities_takes_no_options"});
            }
            return result;
        }
        if (result.request_id.empty() || result.request_id.size() > 128 ||
            !std::ranges::all_of(result.request_id, [](char value)
            {
                return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                    (value >= '0' && value <= '9') || value == '_' || value == '-';
            }) || result.root.empty() || result.report_directory.empty())
        {
            return std::unexpected(engine::error{"request_scope_report_required"});
        }
        const bool batch = result.command == "run" || result.command == "scan";
        const bool resume = result.command == "resume";
        const bool process = result.command == "locks" || result.command == "release";
        if (batch && ((result.mode != "quick" && result.mode != "overwrite") || result.manifest.empty()))
        {
            return std::unexpected(engine::error{"mode_and_manifest_required"});
        }
        if ((result.command == "run" || resume) != result.irreversible)
        {
            return std::unexpected(engine::error{"irreversible_authorization_mismatch"});
        }
        if (resume && (!hexadecimal(result.job_id, 32) || !hexadecimal(result.fingerprint, 64)))
        {
            return std::unexpected(engine::error{"protected_job_and_fingerprint_required"});
        }
        if (!resume && (!result.job_id.empty() || !result.fingerprint.empty()))
        {
            return std::unexpected(engine::error{"resume_options_forbidden"});
        }
        if (resume && !result.mode.empty())
        {
            return std::unexpected(engine::error{"resume_is_overwrite_only"});
        }
        if (process && (result.path.empty() || !hexadecimal(result.target_key, 64) ||
            !result.mode.empty() || !result.manifest.empty()))
        {
            return std::unexpected(engine::error{"exact_process_target_required"});
        }
        if (!process && (!result.path.empty() || !result.target_key.empty()))
        {
            return std::unexpected(engine::error{"process_target_options_forbidden"});
        }
        if (result.command == "release")
        {
            if (!result.process_close || result.process_id == 0 || result.creation_time == 0 || result.image.empty())
            {
                return std::unexpected(engine::error{"exact_process_and_close_authorization_required"});
            }
        }
        else if (result.process_close || result.force_terminate || seen.contains("--pid") ||
            seen.contains("--created") || seen.contains("--image"))
        {
            return std::unexpected(engine::error{"release_options_forbidden"});
        }
        if (process && (seen.contains("--workers") || seen.contains("--memory-bytes") || seen.contains("--io-bytes-per-second") || seen.contains("--ssd-queue-depth")))
        {
            return std::unexpected(engine::error{"execution_limits_forbidden"});
        }
        if (result.mode == "quick" && (seen.contains("--io-bytes-per-second") || seen.contains("--ssd-queue-depth")))
        {
            return std::unexpected(engine::error{"quick_io_limit_forbidden"});
        }
        if (result.memory_budget_bytes > std::numeric_limits<std::size_t>::max())
        {
            return std::unexpected(engine::error{"memory_limit_out_of_range"});
        }
        if (result.workers != 0)
        {
            result.execution_settings.max_device_workers = result.workers;
        }
        if (result.memory_budget_bytes != 0)
        {
            result.execution_settings.memory_budget_bytes = static_cast<std::size_t>(result.memory_budget_bytes);
        }
        return result;
    }

    int report_exit_code(std::string_view status) noexcept
    {
        if (status == "completed" || status == "scanned" || status == "capabilities")
        {
            return 0;
        }
        if (status == "cancelled_partial" || status == "paused")
        {
            return 5;
        }
        return 3;
    }
}
