import std;
import secure_erase.application;
import secure_erase.crypto;

namespace
{
    unsigned checks{};
    unsigned failures{};

    void expect(bool value, std::string_view name)
    {
        ++checks;
        failures += value ? 0U : 1U;
        std::cout << "{\"test\":\"" << name << "\",\"passed\":" << (value ? "true" : "false") << "}\n";
    }
}

int main()
{
    namespace frontend = secure_erase::frontend;
    namespace engine = secure_erase::engine;
    namespace crypto = secure_erase::crypto;
    frontend::view_state value;
    value.quick_mode = true;
    value.quick_paged = true;
    value.operation_phase = "quick_executing";
    value.status = "partial_failure";
    value.input_count = 10;
    value.input_count_known = true;
    value.quick_total = 10;
    value.quick_attempted = 10;
    value.failed_count = 10;
    value.audit_store_available = true;
    auto report = std::make_shared<engine::run_report>();
    report->job_id = "0123456789abcdef0123456789abcdef";
    report->plan_fingerprint = "exact_frozen_plan";
    report->status = "partial_failure";
    value.report = report;
    auto page = std::make_shared<frontend::quick_page>();
    page->job_id = report->job_id;
    page->fingerprint = report->plan_fingerprint;
    page->total = 10;
    page->next_offset = 10;
    page->failures_only = true;
    for (std::size_t index = 0; index < 10; ++index)
    {
        frontend::quick_page_item item;
        item.index = index;
        item.target.path = R"(D:\secret\target.bin)";
        item.outcome = engine::target_outcome{R"(D:\secret\identity)", "quick_protected_resource_tree"};
        item.outcome->native_code = 5;
        page->items.push_back(std::move(item));
    }
    value.quick_page_data = page;
    value.recent_events.push_back(engine::event{"quick_protected_resource_tree", report->job_id,
        R"(D:\secret\identity)", 0, 0, 5});
    auto text = frontend::diagnostic_json(value);
    std::cout << text << '\n';
    expect(report->targets.empty() && text.find("quick_protected_resource_tree") != std::string::npos,
        "paged_empty_run_report_retains_failure_reason");
    expect(text.find("\"failed\":10") != std::string::npos && text.find("\"attempted\":10") != std::string::npos &&
        text.find("\"returned\":10") != std::string::npos, "paged_summary_retains_counts_and_outcomes");
    expect(text.find("\"kind\":\"safety_refusal\"") != std::string::npos && text.find("\"native_code\":5") != std::string::npos,
        "policy_refusal_distinguished_from_os_access_denied");
    expect(text.find("D:") == std::string::npos && text.find("secret") == std::string::npos,
        "copied_diagnostics_mask_paths_and_raw_identities");
    const auto identity = std::string_view(R"(D:\secret\identity)");
    const auto masked = crypto::hex_digest(crypto::sha256(std::as_bytes(std::span(identity.data(), identity.size()))));
    expect(text.find(masked) != std::string::npos, "masked_identity_matches_retained_log_correlation");
    expect(text.find("%LOCALAPPDATA%") != std::string::npos &&
        text.find("\"complete_job_evidence_guaranteed\":false") != std::string::npos &&
        text.find("\"complete_report\":false") != std::string::npos,
        "summary_explains_retained_evidence_and_session_limit");
    expect(frontend::diagnostic_failure(value).code == "quick_protected_resource_tree", "representative_page_failure_visible");
    auto stale = std::make_shared<frontend::quick_page>(*page);
    stale->fingerprint = "another_job";
    value.quick_page_data = stale;
    text = frontend::diagnostic_json(value);
    expect(frontend::diagnostic_failure(value).code.empty() && text.find("\"available\":false") != std::string::npos &&
        text.find("quick_protected_resource_tree") != std::string::npos,
        "stale_page_refused_but_recent_job_events_preserved");
    value.quick_page_data = page;
    page->total = 500000;
    page->next_offset = 128;
    value.quick_total = 500000;
    value.quick_attempted = 500000;
    value.failed_count = 500000;
    while (page->items.size() < 128)
    {
        page->items.push_back(page->items.front());
    }
    value.recent_events.resize(128, value.recent_events.front());
    value.recent_events_dropped = 400000;
    text = frontend::diagnostic_json(value);
    expect(text.size() < 128 * 1024 && text.find("\"returned\":128") != std::string::npos &&
        text.find("\"limit\":64") != std::string::npos, "large_job_copy_is_bounded");
    expect(text.find("\"has_more\":true") != std::string::npos && text.find("\"next_offset\":128") != std::string::npos &&
        text.find("\"truncated\":true") != std::string::npos && text.find("\"earlier_events_dropped\":400000") != std::string::npos,
        "paged_and_event_truncation_explicit");
    value.error_code = std::string(300, 'x') + "\n\"";
    text = frontend::diagnostic_json(value);
    expect(text.find("\"strings_truncated\":true") != std::string::npos, "oversized_text_discloses_truncation");

    frontend::view_state preview;
    preview.quick_mode = true;
    preview.quick_paged = true;
    preview.input_count = 10;
    preview.input_count_known = true;
    preview.status = "failed";
    preview.operation_phase = "quick_preparing";
    preview.error_code = "quick_scope_proof_failed";
    preview.native_code = 5;
    text = frontend::diagnostic_json(preview);
    std::cout << text << '\n';
    expect(!preview.report && text.find("quick_scope_proof_failed") != std::string::npos &&
        text.find("\"phase\":\"quick_preparing\"") != std::string::npos, "top_level_preview_failure_without_report_copied");
    expect(text.find("\"inputs\":10") != std::string::npos && text.find("\"total_known\":false") != std::string::npos &&
        text.find("\"store_available\":false") != std::string::npos && text.find("\"total\":null") != std::string::npos &&
        text.find("\"attempted\":null") != std::string::npos && text.find("\"pending\":null") != std::string::npos,
        "preview_unknown_counts_and_missing_store_not_fabricated");
    expect(frontend::diagnostic_failure_kind("open_failed", 5) == "access_denied", "ordinary_access_denial_not_safety_refusal");
    for (const auto code : {"running_image", "running_image_ancestor", "quick_running_image", "quick_running_image_ancestor"})
    {
        expect(frontend::diagnostic_failure_kind(code, 5) == "safety_refusal", "running_image_policy_refusal_classified");
    }
    expect(frontend::diagnostic_failure_kind("protected_path_resolution_failed", 5) == "access_denied",
        "protection_inventory_access_denial_not_target_policy_refusal");
    expect(frontend::diagnostic_failure_kind("state_protected_size_limit", 223) == "operation_failure",
        "protected_storage_size_error_not_target_policy_refusal");
    expect(frontend::diagnostic_failure_kind("file_identity_failed", 5) == "access_denied",
        "identity_query_failure_not_identity_mismatch_refusal");
    expect(frontend::diagnostic_failure_kind("target_identity_changed", 0) == "identity_refusal", "identity_refusal_classified");
    for (const bool quick_mode : {false, true})
    {
        preview.quick_mode = quick_mode;
        preview.quick_paged = quick_mode;
        preview.operation_phase = quick_mode ? "quick_preparing" : "previewing";
        preview.error_code = "final_name_failed";
        preview.native_code = 1;
        text = frontend::diagnostic_json(preview);
        expect(!preview.report && text.find("final_name_failed") != std::string::npos &&
            text.find("\"native_code\":1") != std::string::npos && text.find("\"total_known\":false") != std::string::npos &&
            text.find("\"inputs\":10") != std::string::npos && text.find("\"job_id\":\"\"") != std::string::npos &&
            text.find(quick_mode ? "quick_preparing" : "previewing") != std::string::npos,
            quick_mode ? "quick_preview_final_name_failure_context_without_job" :
                "overwrite_preview_final_name_failure_context_without_job");
        std::cout << text << '\n';
    }
    preview.error_code = "error\n\"quote";
    text = frontend::diagnostic_json(preview);
    expect(text.find("error\\u000a\\\"quote") != std::string::npos, "diagnostic_strings_json_escaped");

    frontend::view_state overwrite;
    overwrite.status = "partial_failure";
    overwrite.operation_phase = "executing";
    overwrite.input_count = 20;
    overwrite.input_count_known = true;
    overwrite.failed_count = 20;
    auto overwrite_report = std::make_shared<engine::run_report>();
    overwrite_report->job_id = report->job_id;
    overwrite_report->status = "partial_failure";
    overwrite_report->stopping_error = engine::error{"audit_finalization_failed", 23};
    for (unsigned index = 0; index < 300; ++index)
    {
        overwrite_report->targets.push_back(engine::target_outcome{"id_" + std::to_string(index), "write_failed"});
    }
    overwrite.report = overwrite_report;
    text = frontend::diagnostic_json(overwrite, 200);
    std::cout << text << '\n';
    expect(text.find("\"mode\":\"overwrite\"") != std::string::npos &&
        text.find("audit_finalization_failed") != std::string::npos && text.find("\"native_code\":23") != std::string::npos,
        "overwrite_job_stop_cause_copied");
    expect(text.find("\"offset\":200") != std::string::npos && text.find("\"returned\":100") != std::string::npos &&
        text.find("\"complete_report\":false") != std::string::npos, "overwrite_requested_outcome_window_bounded");
    expect(frontend::diagnostic_json(overwrite, (std::numeric_limits<std::size_t>::max)()).find("\"returned\":0") !=
        std::string::npos, "out_of_range_window_does_not_underflow");
    value.error_code = std::string(255, 'x') + "\xe4\xb8\xad";
    text = frontend::diagnostic_json(value);
    expect(text.find("\xe4") == std::string::npos && text.find("\"strings_truncated\":true") != std::string::npos,
        "utf8_truncation_retains_complete_codepoints");
    std::cout << text << '\n';
    value.error_code = std::string(253, 'x') + "\xe4\xb8\xad";
    text = frontend::diagnostic_json(value);
    expect(text.find("\xe4\xb8\xad") != std::string::npos && text.find("\"strings_truncated\":false") != std::string::npos,
        "utf8_codepoint_at_exact_text_bound_preserved");
    std::cout << text << '\n';
    frontend::view_state checkpoint_failure;
    checkpoint_failure.status = "failed";
    checkpoint_failure.operation_phase = "loading_checkpoint";
    checkpoint_failure.diagnostic_job_id = "new_checkpoint_job";
    checkpoint_failure.error_code = "checkpoint_missing";
    text = frontend::diagnostic_json(checkpoint_failure);
    expect(text.find("new_checkpoint_job") != std::string::npos && text.find(report->job_id) == std::string::npos &&
        text.find("\"inputs\":null") != std::string::npos && text.find("\"failed\":0") != std::string::npos &&
        text.find("\"returned\":0") != std::string::npos, "fresh_checkpoint_failure_context_does_not_reuse_prior_job_metadata");
    std::cout << text << '\n';
    overwrite_report->status = "paused";
    overwrite_report->stopping_error = {};
    overwrite_report->targets.assign(20, engine::target_outcome{"untouched", "job_interrupted_before_target"});
    overwrite.status = "paused";
    overwrite.failed_count = 20;
    text = frontend::diagnostic_json(overwrite);
    expect(text.find("\"attempt_counts_known\":false") != std::string::npos &&
        text.find("\"attempted\":null") != std::string::npos && text.find("\"pending\":null") != std::string::npos &&
        text.find("\"failed_includes_unattempted\":true") != std::string::npos,
        "overwrite_cancel_before_first_target_does_not_invent_attempt_counts");
    std::cout << text << '\n';
    engine::event legacy_event{"event_code", "job", "id", 3, 7, 5, 10, 1, 2};
    expect(frontend::event_json(legacy_event) == "{\"schema\":\"secure_erase.event.v1\",\"code\":\"event_code\","
        "\"job_id\":\"job\",\"identity\":\"id\",\"bytes_done\":3,\"bytes_total\":7,\"native_code\":5,"
        "\"target_counts\":{\"total\":10,\"completed\":1,\"failed\":2}}", "legacy_cli_event_protocol_unchanged");
    engine::run_report legacy;
    legacy.job_id = "job";
    legacy.status = "partial_failure";
    expect(frontend::report_json(legacy) == "{\"schema\":\"secure_erase.report.v1\",\"job_id\":\"job\",\"status\":\"partial_failure\","
        "\"physical_sanitization_guaranteed\":false,\"targets\":[]}", "legacy_cli_report_protocol_unchanged");
    std::cout << "{\"suite\":\"application_diagnostics\",\"checks\":" << checks << ",\"failed\":" << failures << "}\n";
    return failures == 0 ? 0 : 1;
}
