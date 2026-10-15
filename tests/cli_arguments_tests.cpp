import std;
import secure_erase.cli_arguments;
namespace
{
    unsigned failures{};
    unsigned checks{};
    void expect(bool condition, std::string_view name)
    {
        ++checks;
        failures += condition ? 0U : 1U;
        std::cout << "{\"test\":\"" << name << "\",\"passed\":" << (condition ? "true" : "false") << "}\n";
    }
}

int main()
{
    namespace cli = secure_erase::cli;
    const auto parse = [](std::vector<std::string> values) { return cli::parse(values); };
    expect(parse({})->command == "capabilities" && parse({})->contract_version == 1, "default_nonmutating_v1");
    expect(parse({"capabilities", "--contract-version", "2"})->contract_version == 2,
        "explicit_v2_capabilities");
    expect(parse({"capabilities", "--contract-version", "1"})->contract_version == 1,
        "explicit_v1_capabilities");
    expect(parse({"--help", "--contract-version", "2"})->contract_version == 2, "explicit_v2_structured_help");
    for (const auto version : {"0", "3", "-1", "2x", "4294967296"})
    {
        expect(!parse({"capabilities", "--contract-version", version}), "unsupported_contract_rejected");
    }
    expect(!parse({"capabilities", "--contract-version", "2", "--contract-version", "2"}),
        "duplicate_contract_rejected");
    const std::vector<std::string> status_arguments{"status", "--request-id", "unit_status", "--report-dir", "C:\\private",
        "--contract-version", "2"};
    expect(parse(status_arguments) && parse(status_arguments)->root.empty() && parse(status_arguments)->manifest.empty(), "status_read_only_no_scope_required");
    auto invalid_status = status_arguments;
    invalid_status.pop_back();
    invalid_status.pop_back();
    expect(!parse(invalid_status), "status_requires_v2");
    for (const auto& option : std::vector<std::vector<std::string>>{
        {"--root", "C:\\scope"}, {"--manifest", "C:\\manifest.jsonl"}, {"--authorize-irreversible"},
        {"--authorize-close"}, {"--authorize-force"}, {"--mode", "quick"}, {"--workers", "1"},
        {"--log-retention-days", "0"}, {"--checkpoint-retention-days", "0"}})
    {
        invalid_status = status_arguments;
        invalid_status.insert(invalid_status.end(), option.begin(), option.end());
        expect(!parse(invalid_status), "status_rejects_all_execution_options");
    }
    expect(cli::requested_contract_version(status_arguments) == 2 && cli::requested_contract_version({}) == 1,
        "parse_failure_envelope_selects_only_explicit_v2");
    const std::vector<std::string> option_as_value{"run", "--root", "--contract-version", "2"};
    expect(cli::requested_contract_version(option_as_value) == 1, "contract_option_value_is_not_negotiation");
    expect(parse({"--help"})->command == "capabilities", "structured_help");
    expect(parse({"--version"})->command == "capabilities", "structured_version");
    expect(!parse({"capabilities", "--root", "C:\\x"}), "capabilities_no_options");
    std::vector<std::string> scan{"scan", "--mode", "quick", "--request-id", "unit_1", "--root", "C:\\fixture",
        "--manifest", "C:\\control\\input.jsonl", "--report-dir", "C:\\control\\report"};
    auto value = parse(scan);
    expect(value && value->workers == 0 && !value->irreversible, "scan_auto_no_mutation");
    auto run = scan;
    run[0] = "run";
    expect(!parse(run), "run_requires_authorization");
    run.push_back("--authorize-irreversible");
    expect(static_cast<bool>(parse(run)), "authorized_batch");
    auto v2_run = run;
    v2_run.insert(v2_run.end(), {"--contract-version", "2"});
    expect(parse(v2_run) && parse(v2_run)->contract_version == 2 && parse(v2_run)->irreversible,
        "explicit_v2_authorized_batch");
    auto retained = run;
    retained[2] = "overwrite";
    retained.insert(retained.end(), {"--ssd-queue-depth", "3", "--log-retention-days", "7",
        "--checkpoint-retention-days", "0"});
    value = parse(retained);
    expect(value && value->execution_settings.ssd_queue_depth == 3 && value->retention.log_retention_days == 7 &&
        value->retention.checkpoint_retention_days == 0, "overwrite_and_retention_settings");
    auto invalid = scan;
    invalid.push_back("--authorize-irreversible");
    expect(!parse(invalid), "scan_forbids_mutation_authorization");
    for (const auto& addition : std::vector<std::vector<std::string>>{
        {"--authorize-force"}, {"--authorize-close"}, {"--pid", "1"}, {"--pid", "0"}, {"--created", "0"},
        {"--root", "D:\\new"}, {"--unknown", "x"}, {"--workers", "-1"},
        {"--workers", "18446744073709551616"}, {"--workers", "2x"}, {"--memory-bytes"},
        {"--job-id", std::string(32, 'a')}, {"--path", "C:\\fixture\\a"}, {"C:\\shell_expanded"}})
    {
        invalid = run;
        invalid.insert(invalid.end(), addition.begin(), addition.end());
        expect(!parse(invalid), "invalid_batch_options");
    }
    invalid = run;
    invalid.insert(invalid.end(), {"--workers", "128", "--memory-bytes", "268435456"});
    value = parse(invalid);
    expect(value && value->workers == 128 && value->memory_budget_bytes == 268435456, "no_fixed_worker_cap");
    invalid = run;
    invalid.insert(invalid.end(), {"--io-bytes-per-second", "10"});
    expect(!parse(invalid), "quick_rejects_ignored_io_limit");
    invalid = scan;
    invalid[5] = "../bad";
    expect(!parse(invalid), "request_id_no_path");
    std::vector<std::string> resume{"resume", "--request-id", "resume1", "--root", "C:\\fixture",
        "--report-dir", "C:\\control\\report", "--job-id", std::string(32, 'a'),
        "--plan-fingerprint", std::string(64, 'b'), "--authorize-irreversible"};
    expect(static_cast<bool>(parse(resume)), "resume_exact_frozen_job");
    invalid = resume;
    invalid.pop_back();
    expect(!parse(invalid), "resume_requires_fresh_authorization");
    invalid = resume;
    invalid[10] = std::string(63, 'b');
    expect(!parse(invalid), "resume_rejects_invalid_fingerprint");
    std::vector<std::string> release{"release", "--request-id", "release1", "--root", "C:\\fixture",
        "--report-dir", "C:\\control\\report", "--path", "C:\\fixture\\a", "--target-key", std::string(64, 'c'),
        "--pid", "123", "--created", "18446744073709551615", "--image", "C:\\app.exe", "--authorize-close"};
    value = parse(release);
    expect(value && !value->force_terminate && value->creation_time == 18446744073709551615ULL,
        "individual_graceful_close_tuple");
    release.push_back("--authorize-force");
    value = parse(release);
    expect(value && value->force_terminate, "separate_force_authorization");
    invalid = release;
    invalid.erase(invalid.end() - 2);
    expect(!parse(invalid), "force_does_not_imply_close_grant");
    for (const auto status : {"completed", "scanned", "capabilities"})
    {
        expect(cli::report_exit_code(status) == 0, "success_exit");
    }
    for (const auto status : {"partial_failure", "audit_finalization_failed", "checkpoint_cleanup_failed", "unknown"})
    {
        expect(cli::report_exit_code(status) == 3, "failure_exit");
    }
    expect(cli::report_exit_code("cancelled_partial") == 5, "cancel_exit");
    expect(cli::report_exit_code("paused") == 5, "pause_exit");
    std::cout << "{\"checks\":" << checks << ",\"failed\":" << failures << "}\n";
    return failures == 0 ? 0 : 1;
}
