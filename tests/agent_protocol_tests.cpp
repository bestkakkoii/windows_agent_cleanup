import std;
import secure_erase.agent_protocol;
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
    namespace agent = secure_erase::agent;
    auto record = agent::parse_manifest_line(R"({"path":"C:\\fixture\\one.bin"})");
    expect(record && record->path == "C:\\fixture\\one.bin" && !record->downgrade, "simple_path");
    record = agent::parse_manifest_line(R"( { "allow_downgrade" : "delete_only", "path" : "C:/fixture/one.bin" } )");
    expect(record && record->downgrade == secure_erase::engine::capability::delete_only, "individual_grant");
    record = agent::parse_manifest_line(R"({"path":"C:\\fixture\\\uD83D\uDE00.bin"})");
    expect(record && record->path.ends_with("\xf0\x9f\x98\x80.bin"), "surrogate_pair");
    for (const auto& invalid : std::vector<std::string>{
        "", " ", "{}", "[]", "null", "{", "{\"path\":1}",
        R"({"path":"C:\\a","path":"C:\\b"})",
        R"({"path":"C:\\a","p\u0061th":"C:\\b"})",
        R"({"path":"C:\\a","unknown":"x"})",
        R"({"path":"C:\\a",})",
        R"({"path":"C:\\a"} {})",
        R"({"path":"C:\\a","allow_downgrade":"all"})",
        R"({"path":"C:\\a","allow_downgrade":"delete_only","allow_downgrade":"delete_only"})",
        R"({"path":"C:\\a\u0000"})",
        R"({"path":"C:\\a\uD800"})",
        R"({"path":"C:\\a\uDC00"})",
        R"({"path":"C:\\a\uD800\u0041"})",
        R"({"path":"C:\\a\uZZZZ"})",
        R"({"path":"C:\\a\x12"})",
        std::string("\xef\xbb\xbf") + R"({"path":"C:\\a"})",
        std::string("{invalid")})
    {
        expect(!agent::parse_manifest_line(invalid), "invalid_record_rejected");
    }
    for (const auto& invalid_utf8 : std::vector<std::string>{
        std::string("\xc0\xaf", 2), std::string("\xed\xa0\x80", 3),
        std::string("\xf4\x90\x80\x80", 4), std::string("\x80", 1), std::string("\xe2\x82", 2)})
    {
        expect(!agent::parse_manifest_line("{\"path\":\"C:\\\\" + invalid_utf8 + "\"}"), "invalid_utf8_rejected");
    }
    for (const auto path : {"relative", "C:relative", "\\\\server\\share", "\\\\.\\C:\\x", "C:\\x:ads",
        "C:\\a\\..\\b", "C:\\a\\.\\b", "C:\\a\\\\b", "C:\\a.", "C:\\a ", "C:\\*.tmp", "C:\\a?", "C:\\a|b"})
    {
        expect(!agent::normalize_path(path), "unsafe_path_rejected");
    }
    auto path = agent::normalize_path("\\\\?\\C:/fixture/");
    expect(path && *path == "C:\\fixture", "extended_path_normalized");
    expect(agent::within_scope("c:\\fixture\\a", "C:\\fixture"), "component_child");
    expect(agent::within_scope("C:\\fixture", "C:\\fixture"), "scope_root_selected");
    expect(!agent::within_scope("C:\\fixture2", "C:\\fixture"), "prefix_sibling_rejected");
    expect(!agent::within_scope("D:\\fixture", "C:\\fixture"), "different_drive_rejected");
    expect(!agent::within_scope("C:\\fixture", ""), "empty_scope_rejected");
    expect(agent::json_quote("a\n\"\\") == "\"a\\u000a\\\"\\\\\"", "json_escape");
    expect(!agent::parse_manifest_line(std::string(agent::maximum_record_bytes + 1, ' ')), "record_bound");
    expect(agent::statistics_json({}) == "null", "unsupported_statistics_are_null");
    secure_erase::engine::operation_statistics statistics;
    statistics.supported = true;
    statistics.selected.files = 2;
    statistics.selected.directories = 3;
    statistics.logical_bytes.selected = std::numeric_limits<std::uint64_t>::max();
    statistics.logical_bytes.selected_unknown = 1;
    statistics.final_failures.reparse = 1;
    const auto statistics_text = agent::statistics_json(statistics);
    expect(statistics_text.find("18446744073709551615") != std::string::npos,
        "statistics_preserve_uint64_precision");
    expect(statistics_text.find("\"selected\":{\"files\":2,\"directories\":3,\"unclassified\":0}") != std::string::npos &&
        statistics_text.find("\"selected_unknown\":1") != std::string::npos &&
        statistics_text.find("\"logical_bytes_semantics\":\"frozen_default_stream_snapshot\"") != std::string::npos,
        "statistics_classification_and_unknown_snapshot_semantics");
    const auto guidance = agent::action_guidance_json({agent::next_action_kind::reconcile_unknown, "unknown\nresult", false});
    expect(guidance == "\"next_action\":{\"action\":\"reconcile_unknown\",\"reason\":\"unknown\\u000aresult\"},\"retry_safe\":false",
        "unknown_result_cannot_authorize_replay");
    const auto bounded_guidance = agent::action_guidance_json({agent::next_action_kind::correct_input, std::string(1024, 'x'), true});
    expect(bounded_guidance.size() < 256 && bounded_guidance.find(std::string(129, 'x')) == std::string::npos,
        "guidance_reason_is_bounded");
    std::cout << "{\"checks\":" << checks << ",\"failed\":" << failures << "}\n";
    return failures == 0 ? 0 : 1;
}
