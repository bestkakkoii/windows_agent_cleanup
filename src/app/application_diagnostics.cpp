module secure_erase.application;

import std;
import secure_erase.crypto;

namespace secure_erase::frontend
{
    std::string json_quote(std::string_view value)
    {
        constexpr std::string_view hex = "0123456789abcdef";
        std::string result{"\""};
        for (const char character : value)
        {
            const auto code = static_cast<unsigned char>(character);
            if (code == '"' || code == '\\')
            {
                result.push_back('\\');
                result.push_back(character);
            }
            else if (code < 0x20)
            {
                result += "\\u00";
                result.push_back(hex[code >> 4]);
                result.push_back(hex[code & 15]);
            }
            else
            {
                result.push_back(character);
            }
        }
        result.push_back('"');
        return result;
    }

    std::string event_json(const engine::event& value)
    {
        std::string text = "{\"schema\":\"secure_erase.event.v1\",\"code\":" + json_quote(value.code) +
            ",\"job_id\":" + json_quote(value.job_id) + ",\"identity\":" + json_quote(value.identity) +
            ",\"bytes_done\":" + std::to_string(value.bytes_done) +
            ",\"bytes_total\":" + std::to_string(value.bytes_total) +
            ",\"native_code\":" + std::to_string(value.native_code);
        if (value.total_targets != 0 || value.completed_targets != 0 || value.failed_targets != 0)
        {
            text += ",\"target_counts\":{\"total\":" + std::to_string(value.total_targets) +
                ",\"completed\":" + std::to_string(value.completed_targets) +
                ",\"failed\":" + std::to_string(value.failed_targets) + "}";
        }
        return text + "}";
    }

    std::string report_json(const engine::run_report& value)
    {
        std::string text = "{\"schema\":\"secure_erase.report.v1\",\"job_id\":" +
            json_quote(value.job_id) + ",\"status\":" + json_quote(value.status) +
            ",\"physical_sanitization_guaranteed\":false,\"targets\":[";
        bool first = true;
        for (const auto& target : value.targets)
        {
            if (!first)
            {
                text.push_back(',');
            }
            first = false;
            text += "{\"identity\":" + json_quote(target.identity) + ",\"code\":" +
                json_quote(target.code) + ",\"deleted\":" + (target.deleted ? "true" : "false") +
                ",\"logical_overwrite_verified\":" + (target.logical_overwrite_verified ? "true" : "false") +
                ",\"written_bytes\":" + std::to_string(target.written_bytes) +
                ",\"verified_bytes\":" + std::to_string(target.verified_bytes) +
                ",\"native_code\":" + std::to_string(target.native_code) + "}";
        }
        return text + "]}";
    }

    namespace
    {
        constexpr std::size_t diagnostic_outcome_limit = 128;
        constexpr std::size_t diagnostic_event_limit = 64;
        constexpr std::size_t diagnostic_text_limit = 256;

        bool diagnostic_success(const engine::target_outcome& value)
        {
            return value.deleted && (value.code == "deleted_quick_namespace_removed" ||
                value.code == "deleted_logical_overwrite_verified_residual_risk" ||
                value.code == "deleted_only_residual_risk" ||
                value.code == "completed_from_authenticated_checkpoint");
        }

        std::string_view diagnostic_job(const view_state& value)
        {
            if (value.report)
            {
                return value.report->job_id;
            }
            return value.plan ? std::string_view(value.plan->job_id) : std::string_view(value.diagnostic_job_id);
        }

        bool diagnostic_page_current(const view_state& value)
        {
            const auto& page = value.quick_page_data;
            if (!value.quick_paged || !page || page->job_id != diagnostic_job(value))
            {
                return false;
            }
            const auto fingerprint = value.report ? std::string_view(value.report->plan_fingerprint) :
                value.plan ? std::string_view(value.plan->fingerprint) : std::string_view{};
            return !fingerprint.empty() && page->fingerprint == fingerprint;
        }

        std::string masked_diagnostic_identity(std::string_view value)
        {
            return value.empty() ? std::string{} : crypto::hex_digest(crypto::sha256(
                std::as_bytes(std::span(value.data(), value.size()))));
        }
    }

    engine::error diagnostic_failure(const view_state& value)
    {
        if (!value.error_code.empty())
        {
            return engine::error{value.error_code, value.native_code};
        }
        if (value.report && !value.report->stopping_error.code.empty())
        {
            return value.report->stopping_error;
        }
        if (diagnostic_page_current(value))
        {
            const auto& items = value.quick_page_data->items;
            for (std::size_t index = 0; index < (std::min)(items.size(), diagnostic_outcome_limit); ++index)
            {
                const auto& item = items[index];
                if (item.outcome && !diagnostic_success(*item.outcome))
                {
                    return engine::error{item.outcome->code, item.outcome->native_code};
                }
                if (!item.target.preparation_error.code.empty())
                {
                    return item.target.preparation_error;
                }
            }
        }
        if (value.report)
        {
            const auto& items = value.report->targets;
            for (std::size_t index = 0; index < (std::min)(items.size(), diagnostic_outcome_limit); ++index)
            {
                if (!diagnostic_success(items[index]))
                {
                    return engine::error{items[index].code, items[index].native_code};
                }
            }
        }
        return {};
    }

    std::string_view diagnostic_failure_kind(std::string_view code, std::uint32_t native_code) noexcept
    {
        if (code.empty())
        {
            return "none";
        }
        constexpr std::array safety_codes{
            std::string_view("protected_resource_tree"), std::string_view("quick_protected_resource_tree"),
            std::string_view("windows_resource_protection"), std::string_view("quick_windows_resource_protection"),
            std::string_view("running_image"), std::string_view("running_image_ancestor"),
            std::string_view("quick_running_image"), std::string_view("quick_running_image_ancestor"),
            std::string_view("target_protected_or_unsupported"), std::string_view("process_class_protected"),
            std::string_view("process_owner_protected"), std::string_view("process_session_protected"),
            std::string_view("service_process_protected"), std::string_view("windows_process_protected")};
        if (std::ranges::find(safety_codes, code) != safety_codes.end())
        {
            return "safety_refusal";
        }
        if (code == "target_identity_changed" || code == "quick_frozen_identity_changed" ||
            code == "scope_identity_changed" || code == "stream_identity_changed" ||
            code == "identity_metadata_or_capability_changed_repreview_required" ||
            code == "target_identity_metadata_or_capability_changed")
        {
            return "identity_refusal";
        }
        return native_code == 5 ? "access_denied" : "operation_failure";
    }

    std::string diagnostic_json(const view_state& value, std::size_t outcome_offset)
    {
        // SECURITY: No target paths, raw identities, keys, checkpoints or history
        // are copied. target_id matches the retained masked event-log correlation.
        bool text_truncated{};
        const auto quote = [&text_truncated](std::string_view text)
        {
            auto count = (std::min)(text.size(), diagnostic_text_limit);
            while (count != 0 && count < text.size() &&
                (static_cast<unsigned char>(text[count]) & 0xc0U) == 0x80U)
            {
                --count;
            }
            text_truncated = text_truncated || count != text.size();
            return json_quote(text.substr(0, count));
        };
        const auto boolean = [](bool flag) -> std::string_view { return flag ? "true" : "false"; };
        const auto error = diagnostic_failure(value);
        const auto total = value.quick_mode ? value.quick_total :
            value.report ? value.report->targets.size() : value.plan ? value.plan->targets.size() : 0;
        const bool total_known = static_cast<bool>(value.plan) || static_cast<bool>(value.report);
        const bool attempt_counts_known = value.quick_mode && total_known;
        std::string text = "{\"schema\":\"secure_erase.gui_diagnostic.v1\",\"mode\":" +
            quote(value.quick_mode ? "quick" : "overwrite") + ",\"job_id\":" + quote(diagnostic_job(value)) +
            ",\"status\":" + quote(value.status) + ",\"report_status\":" + quote(value.report ? value.report->status : "") +
            ",\"phase\":" + quote(value.operation_phase) +
            ",\"quick_stage\":" + quote(value.quick_stage) + ",\"busy\":" + std::string(boolean(value.busy)) +
            ",\"executing\":" + std::string(boolean(value.executing)) +
            ",\"error\":{\"code\":" + quote(error.code) + ",\"native_code\":" + std::to_string(error.native_code) +
            ",\"kind\":" + quote(diagnostic_failure_kind(error.code, error.native_code)) +
            "},\"stopping_error\":{\"code\":" + quote(value.report ? value.report->stopping_error.code : "") +
            ",\"native_code\":" + std::to_string(value.report ? value.report->stopping_error.native_code : 0) +
            "},\"counts\":{\"inputs\":" + (value.input_count_known ? std::to_string(value.input_count) : "null") +
            ",\"inputs_known\":" + std::string(boolean(value.input_count_known)) +
            ",\"total_known\":" + std::string(boolean(total_known)) +
            ",\"total\":" + (total_known ? std::to_string(total) : "null") +
            ",\"attempt_counts_known\":" + std::string(boolean(attempt_counts_known)) +
            ",\"attempted\":" + (attempt_counts_known ? std::to_string(value.quick_attempted) : "null") +
            ",\"completed\":" + std::to_string(value.completed_count) +
            ",\"failed\":" + std::to_string(value.failed_count) +
            ",\"failed_includes_unattempted\":" + std::string(boolean(!value.quick_mode)) +
            ",\"pending\":" + (attempt_counts_known ? std::to_string(value.quick_pending) : "null") + "}";
        const auto append_outcome = [&text, &quote, &boolean](const engine::target_outcome& item,
            std::optional<std::uint64_t> index)
        {
            text += "{\"target_id\":" + quote(masked_diagnostic_identity(item.identity));
            if (index)
            {
                text += ",\"index\":" + std::to_string(*index);
            }
            text += ",\"code\":" + quote(item.code) + ",\"native_code\":" + std::to_string(item.native_code) +
                ",\"failure_kind\":" + quote(diagnostic_failure_kind(diagnostic_success(item) ? "" : item.code,
                    item.native_code)) + ",\"deleted\":" + std::string(boolean(item.deleted)) +
                ",\"logical_overwrite_verified\":" + std::string(boolean(item.logical_overwrite_verified)) + "}";
        };
        const bool page_available = diagnostic_page_current(value);
        const auto offset = value.quick_paged ? page_available ? value.quick_page_data->offset : 0 :
            value.report ? (std::min)(outcome_offset, value.report->targets.size()) : 0;
        const auto returned = value.quick_paged ? page_available ?
            (std::min)(value.quick_page_data->items.size(), diagnostic_outcome_limit) : 0 :
            value.report ? (std::min)(value.report->targets.size() - offset, diagnostic_outcome_limit) : 0;
        const auto next = value.quick_paged ? page_available ? value.quick_page_data->next_offset : offset : offset + returned;
        const bool more = next < total;
        const bool filtered = value.quick_paged && page_available && value.quick_page_data->failures_only;
        const bool truncated = value.quick_paged ? !page_available || offset != 0 || more ||
            returned < value.quick_page_data->total || value.quick_page_data->items.size() > returned : offset != 0 || more;
        text += ",\"outcomes\":{\"storage\":" + quote(value.quick_paged ? "paged_session_store" : "in_memory_report") +
            ",\"available\":" + std::string(boolean(value.quick_paged ? page_available : static_cast<bool>(value.report))) +
            ",\"complete_report\":" + std::string(boolean(!value.quick_paged && !truncated && static_cast<bool>(value.report))) +
            ",\"failures_only\":" + std::string(boolean(filtered)) + ",\"offset\":" + std::to_string(offset) +
            ",\"next_offset\":" + std::to_string(next) + ",\"has_more\":" + std::string(boolean(more)) +
            ",\"matching_total\":" + std::to_string(value.quick_paged && page_available ? value.quick_page_data->total : total) +
            ",\"returned\":" + std::to_string(returned) + ",\"limit\":128,\"truncated\":" +
            std::string(boolean(truncated)) + ",\"items\":[";
        for (std::size_t index = 0; index < returned; ++index)
        {
            if (index != 0)
            {
                text.push_back(',');
            }
            if (value.quick_paged)
            {
                const auto& item = value.quick_page_data->items[index];
                if (item.outcome)
                {
                    append_outcome(*item.outcome, item.index);
                }
                else
                {
                    text += "{\"index\":" + std::to_string(item.index) + ",\"outcome_available\":false,\"preparation_error\":{\"code\":" +
                        quote(item.target.preparation_error.code) + ",\"native_code\":" +
                        std::to_string(item.target.preparation_error.native_code) + "}}";
                }
            }
            else
            {
                append_outcome(value.report->targets[offset + index], offset + index);
            }
        }
        const auto event_offset = value.recent_events.size() > diagnostic_event_limit ?
            value.recent_events.size() - diagnostic_event_limit : 0;
        text += "]},\"recent_events\":{\"returned\":" + std::to_string(value.recent_events.size() - event_offset) +
            ",\"limit\":64,\"available_in_memory\":" + std::to_string(value.recent_events.size()) +
            ",\"omitted_from_memory_window\":" + std::to_string(event_offset) +
            ",\"earlier_events_dropped\":" + std::to_string(value.recent_events_dropped) +
            ",\"truncated\":" + std::string(boolean(value.recent_events_dropped != 0 || event_offset != 0)) + ",\"items\":[";
        for (auto index = event_offset; index < value.recent_events.size(); ++index)
        {
            if (index != event_offset)
            {
                text.push_back(',');
            }
            const auto& event = value.recent_events[index];
            text += "{\"code\":" + quote(event.code) + ",\"job_id\":" + quote(event.job_id) +
                ",\"target_id\":" + quote(masked_diagnostic_identity(event.identity)) +
                ",\"native_code\":" + std::to_string(event.native_code) +
                ",\"bytes_done\":" + std::to_string(event.bytes_done) + ",\"bytes_total\":" + std::to_string(event.bytes_total) + "}";
        }
        text += "]},\"retained_evidence\":{\"store_available\":" + std::string(boolean(value.audit_store_available)) +
            ",\"location_template\":\"%LOCALAPPDATA%\\\\windows_secure_erase\\\\v1\",\"files\":\"events.jsonl; events_<n>.jsonl\""
            ",\"filter_by\":\"job_id and target_id\",\"log_retention_days\":" + std::to_string(value.log_retention_days) +
            ",\"retained_rotations\":" + std::to_string(value.retained_log_files) +
            ",\"complete_job_evidence_guaranteed\":false,\"note\":\"Logs are masked and rotated; quick logs retain failures and lifecycle counts, not all successful target outcomes. Preview failures may precede the first logged event. Full paged quick outcomes exist only in this live session.\"}"
            ",\"paths_masked\":true,\"strings_truncated\":" + std::string(boolean(text_truncated)) +
            ",\"physical_sanitization_guaranteed\":false}";
        return text;
    }
}
