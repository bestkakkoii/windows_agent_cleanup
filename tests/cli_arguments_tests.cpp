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
    expect(parse({})->command == "capabilities", "default_nonmutating");
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
