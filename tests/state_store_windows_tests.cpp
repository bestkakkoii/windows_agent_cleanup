#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <winioctl.h>

import std;
import secure_erase.state_store;
import secure_erase.codec;
import secure_erase.plan;
import secure_erase.quick_store;
import secure_erase.agent_protocol;

namespace
{
    struct close_handle
    {
        void operator()(void* value) const noexcept
        {
            if (value != nullptr && value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(value);
            }
        }
    };

    using unique_handle = std::unique_ptr<void, close_handle>;

    class test_suite
    {
    public:
        void check(std::string_view name, bool passed)
        {
            ++count_;
            if (!passed)
            {
                ++failed_;
            }
            std::cout << "{\"test\":\"" << name << "\",\"passed\":"
                << (passed ? "true" : "false") << "}\n";
        }

        int finish() const
        {
            std::cout << "{\"suite\":\"state_store_windows\",\"assertions\":" << count_
                << ",\"failed\":" << failed_ << "}\n";
            return failed_ == 0 ? 0 : 1;
        }

    private:
        unsigned count_{};
        unsigned failed_{};
    };

    bool same_path(std::wstring_view first, std::wstring_view second)
    {
        return first.size() == second.size() && first.size() <= 32768
            && CompareStringOrdinal(first.data(), static_cast<int>(first.size()),
                second.data(), static_cast<int>(second.size()), TRUE) == CSTR_EQUAL;
    }

    std::wstring expanded_test_path(std::wstring_view path, bool short_name)
    {
        const std::wstring owned(path);
        std::array<wchar_t, 32768> output{};
        const auto length = short_name
            ? GetShortPathNameW(owned.c_str(), output.data(), static_cast<DWORD>(output.size()))
            : GetLongPathNameW(owned.c_str(), output.data(), static_cast<DWORD>(output.size()));
        if (length == 0 || length >= output.size())
        {
            return {};
        }
        return {output.data(), length};
    }

    std::wstring unique_test_root()
    {
        std::array<wchar_t, 32768> temporary{};
        const auto length = GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
        if (length == 0 || length >= temporary.size())
        {
            return {};
        }
        std::array<unsigned char, 16> random{};
        if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        {
            return {};
        }
        std::wstring root(temporary.data(), length);
        root += L"secure_erase_state_test_";
        constexpr std::wstring_view hex{L"0123456789abcdef"};
        for (const auto byte : random)
        {
            root += hex[byte >> 4];
            root += hex[byte & 15];
        }
        if (GetFileAttributesW(root.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            return {};
        }
        return root;
    }

    secure_erase::engine::checkpoint fixture(std::string id = "0123456789abcdef0123456789abcdef")
    {
        using namespace secure_erase;
        engine::checkpoint value;
        value.plan.job_id = std::move(id);
        engine::target_snapshot target;
        // CONTRACT: This path is serialized test data. No target path is opened or modified.
        target.path = "C:\\never_open_this_target\\test.bin";
        target.identity = "test_volume_1_file_2";
        target.device_key = "test_device";
        target.support = engine::capability::overwrite_verified;
        target.media = engine::media_kind::hdd;
        target.streams = {{"", 1024}};
        value.plan.targets.push_back(target);
        value.plan.fingerprint = engine::fingerprint(value.plan);
        engine::target_checkpoint progress;
        progress.identity = target.identity;
        progress.observed = target;
        progress.key.fill(std::byte{0x42});
        progress.nonce.fill(std::byte{0x84});
        progress.key_ready = true;
        progress.state = engine::target_state::writing;
        progress.offset = 512;
        value.targets.push_back(progress);
        return value;
    }

    std::wstring checkpoint_path(std::wstring_view root, std::string_view id)
    {
        return std::wstring(root) + L"\\" + std::wstring(id.begin(), id.end()) + L".checkpoint";
    }

    bool child_lock_probe(std::wstring_view root)
    {
        std::array<wchar_t, 32768> executable{};
        const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (length == 0 || length >= executable.size())
        {
            return false;
        }
        std::wstring command = L"\"" + std::wstring(executable.data(), length)
            + L"\" --probe-lock \"" + std::wstring(root) + L"\"";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
        {
            return false;
        }
        unique_handle thread(process.hThread);
        unique_handle handle(process.hProcess);
        const auto wait = WaitForSingleObject(handle.get(), 30000);
        if (wait != WAIT_OBJECT_0)
        {
            TerminateProcess(handle.get(), 99);
            return false;
        }
        DWORD code{};
        return GetExitCodeProcess(handle.get(), &code) && code == 0;
    }

    bool change_first_byte(std::wstring_view path)
    {
        const std::wstring owned(path);
        unique_handle file(CreateFileW(owned.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.get() == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        unsigned char value{};
        DWORD done{};
        if (!ReadFile(file.get(), &value, 1, &done, nullptr) || done != 1)
        {
            return false;
        }
        LARGE_INTEGER start{};
        value ^= 0xff;
        return SetFilePointerEx(file.get(), start, nullptr, FILE_BEGIN)
            && WriteFile(file.get(), &value, 1, &done, nullptr) && done == 1 && FlushFileBuffers(file.get());
    }

    bool append_torn_log(std::wstring_view root)
    {
        const auto path = std::wstring(root) + L"\\events.jsonl";
        unique_handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        constexpr std::string_view partial{"{\"incomplete"};
        DWORD done{};
        LARGE_INTEGER end{};
        return file.get() != INVALID_HANDLE_VALUE
            && SetFilePointerEx(file.get(), end, nullptr, FILE_END)
            && WriteFile(file.get(), partial.data(), static_cast<DWORD>(partial.size()), &done, nullptr)
            && done == partial.size() && FlushFileBuffers(file.get());
    }

    void compressed_parent_staging_fixture(test_suite& tests,
        secure_erase::storage::state_store& store)
    {
        unique_handle directory(CreateFileW(store.root_path().c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        tests.check("staging_compression_fixture_directory_opened", directory.get() != INVALID_HANDLE_VALUE);
        if (directory.get() == INVALID_HANDLE_VALUE)
        {
            return;
        }
        USHORT original{};
        DWORD received{};
        if (!DeviceIoControl(directory.get(), FSCTL_GET_COMPRESSION, nullptr, 0,
            &original, sizeof(original), &received, nullptr))
        {
            const auto native = GetLastError();
            if (native == ERROR_INVALID_FUNCTION || native == ERROR_NOT_SUPPORTED || native == ERROR_INVALID_PARAMETER)
            {
                std::cout << "{\"test\":\"staging_compressed_parent_rejected\",\"status\":\"not_run\","
                    "\"reason\":\"filesystem_compression_unavailable\",\"native_error\":" << native << "}\n";
            }
            else
            {
                tests.check("staging_compression_fixture_state_read", false);
            }
            return;
        }
        tests.check("staging_compression_fixture_state_read", received == sizeof(original));
        if (received != sizeof(original))
        {
            return;
        }
        USHORT compressed = COMPRESSION_FORMAT_DEFAULT;
        const bool enabled = DeviceIoControl(directory.get(), FSCTL_SET_COMPRESSION,
            &compressed, sizeof(compressed), nullptr, 0, &received, nullptr) != FALSE;
        tests.check("staging_compression_fixture_enabled", enabled);
        if (!enabled)
        {
            return;
        }
        FILE_ATTRIBUTE_TAG_INFO tag{};
        tests.check("staging_compressed_parent_attribute_observed",
            GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo, &tag, sizeof(tag)) &&
                (tag.FileAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0);
        auto factory = store.staging_files();
        tests.check("staging_compressed_parent_factory_admitted", factory.has_value());
        if (factory)
        {
            const auto rejected = (*factory)->create_private("compressed_stage_probe.bin");
            tests.check("staging_compressed_parent_rejected", !rejected &&
                rejected.error().code == "staging_created_object_unsafe");
        }
        const auto leaf = store.root_path() + L"\\compressed_stage_probe.bin";
        tests.check("staging_rejected_compressed_scratch_removed_on_close",
            GetFileAttributesW(leaf.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND);
        tests.check("staging_compression_fixture_restored", DeviceIoControl(directory.get(), FSCTL_SET_COMPRESSION,
            &original, sizeof(original), nullptr, 0, &received, nullptr) != FALSE);
    }

    std::string fixture_utf8(std::wstring_view value)
    {
        const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (count <= 0)
        {
            return {};
        }
        std::string text(static_cast<std::size_t>(count), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), text.data(), count, nullptr, nullptr) != count)
        {
            return {};
        }
        return text;
    }

    unique_handle create_report_fixture(std::wstring_view root, std::wstring_view path)
    {
        const std::wstring owned_root(root);
        DWORD required{};
        GetFileSecurityW(owned_root.c_str(), OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            nullptr, 0, &required);
        if (required == 0 || required > 65536)
        {
            return {};
        }
        std::vector<std::byte> descriptor(required);
        if (!GetFileSecurityW(owned_root.c_str(), OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            descriptor.data(), required, &required))
        {
            return {};
        }
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor.data(), FALSE};
        const std::wstring owned_path(path);
        unique_handle file(CreateFileW(owned_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
            &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        return file;
    }

    bool append_report_fixture(HANDLE file, std::string_view text)
    {
        if (file == nullptr || file == INVALID_HANDLE_VALUE || text.size() > 1024 * 1024)
        {
            return false;
        }
        DWORD written{};
        return WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr)
            && written == text.size() && FlushFileBuffers(file);
    }

    void request_status_fixtures(test_suite& tests, secure_erase::storage::state_store& store)
    {
        using namespace secure_erase;
        using lookup = storage::request_lookup_state;
        const auto root = store.root_path();
        const auto missing = root + L"_missing";
        const auto absent = storage::state_store::inspect_request(missing, "status_fixture");
        tests.check("status_missing_root_unavailable_without_creation", absent.lookup_state == lookup::unavailable
            && GetFileAttributesW(missing.c_str()) == INVALID_FILE_ATTRIBUTES);
        const auto empty = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_empty_lookup_coexists_with_live_store_lock", empty.lookup_state == lookup::no_record_observed
            && empty.report_references.empty() && !empty.original_result);
        const auto invalid = storage::state_store::inspect_request(root, "../escape");
        tests.check("status_request_identifier_validated_before_access", invalid.lookup_state == lookup::unavailable
            && invalid.observation_error.code == "status_invalid_request_id");
        const auto path = root + L"\\status_fixture.0123456789abcdef0123456789abcdef.report.jsonl";
        const auto second_path = root + L"\\status_fixture.fedcba9876543210fedcba9876543210.report.jsonl";
        const auto intent = std::string{"{\"schema\":\"windows_agent_cleanup.intent.v1\",\"request_id\":\"status_fixture\","
            "\"command\":\"run\",\"mode\":\"quick\",\"root\":\"C:\\\\never_access_this_path\","
            "\"job_id\":\"0123456789abcdef0123456789abcdef\",\"plan_fingerprint\":\"frozen_fixture\","
            "\"targets\":1,\"irreversible_authorized\":true}\n"};
        const auto final = std::string{"{\"schema\":\"windows_agent_cleanup.result.v1\",\"request_id\":\"status_fixture\","
            "\"job_id\":\"0123456789abcdef0123456789abcdef\",\"plan_fingerprint\":\"frozen_fixture\","
            "\"mode\":\"quick\",\"status\":\"completed\",\"counts\":{\"targets\":1,\"completed\":1,\"failed\":0,\"pending\":0},"
            "\"error_code\":\"\",\"native_code\":0,\"report_file\":"}
            + agent::json_quote(fixture_utf8(path)) + ",\"resumable\":false,\"advisory\":false}";
        const auto created = store.create_report_handle("status_fixture.0123456789abcdef0123456789abcdef.report.jsonl");
        unique_handle writer(created ? reinterpret_cast<HANDLE>(*created) : nullptr);
        tests.check("status_factory_rejects_unowned_names", !store.create_report_handle("../escape.report.jsonl")
            && !store.create_report_handle("status_fixture.wrong.report.jsonl"));
        const auto duplicate_factory = store.create_report_handle("status_fixture.0123456789abcdef0123456789abcdef.report.jsonl");
        tests.check("status_factory_create_new_never_replaces", !duplicate_factory
            && duplicate_factory.error().code == "report_create_failed");
        if (duplicate_factory)
        {
            CloseHandle(reinterpret_cast<HANDLE>(*duplicate_factory));
        }
        tests.check("status_private_report_fixture_created", writer && writer.get() != INVALID_HANDLE_VALUE);
        if (!writer || writer.get() == INVALID_HANDLE_VALUE)
        {
            return;
        }
        tests.check("status_fixture_intent_written", append_report_fixture(writer.get(), intent));
        const auto pending = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_flushed_intent_is_not_completion", pending.lookup_state == lookup::intent_only
            && !pending.original_result && pending.report_references.size() == 1);
        tests.check("status_fixture_final_written", append_report_fixture(writer.get(), final + "\n"));
        const auto terminal = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_final_preserves_exact_original_result", terminal.lookup_state == lookup::terminal_result
            && terminal.original_result && *terminal.original_result == final
            && terminal.report_references.size() == 1);
        LARGE_INTEGER length{};
        tests.check("status_never_changes_report_bytes", GetFileSizeEx(writer.get(), &length)
            && length.QuadPart == static_cast<LONGLONG>(intent.size() + final.size() + 1));
        auto second_writer = create_report_fixture(root, second_path);
        tests.check("status_duplicate_request_fixture_created", second_writer && second_writer.get() != INVALID_HANDLE_VALUE);
        second_writer.reset();
        const auto ambiguous = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_multiple_matching_reports_are_ambiguous", ambiguous.lookup_state == lookup::ambiguous
            && ambiguous.report_references.size() == 2 && !ambiguous.original_result);
        tests.check("status_duplicate_fixture_removed", DeleteFileW(second_path.c_str()) != FALSE);
        writer.reset();
        writer = create_report_fixture(root, path);
        tests.check("status_partial_fixture_written", append_report_fixture(writer.get(), intent + "{\"schema\":"));
        const auto partial = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_partial_final_stays_unknown", partial.lookup_state == lookup::inspection_incomplete
            && partial.observation_error.code == "status_partial_final_record" && !partial.original_result);
        writer.reset();
        writer = create_report_fixture(root, path);
        auto mismatched = final;
        const auto binding = mismatched.find("\"frozen_fixture\"");
        mismatched.replace(binding, std::string_view("\"frozen_fixture\"").size(), "\"different_fixture\"");
        tests.check("status_mismatch_fixture_written", append_report_fixture(writer.get(), intent + mismatched + "\n"));
        const auto mismatch = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_intent_final_binding_mismatch_rejected", mismatch.lookup_state == lookup::inspection_incomplete
            && mismatch.observation_error.code == "status_final_result_binding_invalid");
        writer.reset();
        writer = create_report_fixture(root, path);
        auto duplicate = final;
        duplicate.insert(1, "\"request_id\":\"status_fixture\",");
        tests.check("status_duplicate_key_fixture_written", append_report_fixture(writer.get(), intent + duplicate + "\n"));
        const auto invalid_json = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_duplicate_json_keys_rejected", invalid_json.lookup_state == lookup::inspection_incomplete
            && invalid_json.observation_error.code == "status_invalid_evidence_record");
        writer.reset();
        writer = create_report_fixture(root, path);
        tests.check("status_oversized_fixture_written", append_report_fixture(writer.get(), std::string(512 * 1024 + 1, 'x')));
        const auto limited = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_record_byte_bound_discloses_incomplete", limited.lookup_state == lookup::inspection_incomplete
            && limited.observation_error.code == "status_first_record_incomplete_or_limit");
        writer.reset();
        writer = create_report_fixture(root, path);
        tests.check("status_hardlink_fixture_written", append_report_fixture(writer.get(), intent + final + "\n"));
        writer.reset();
        const auto alias = root + L"\\status_hardlink_alias.bin";
        if (CreateHardLinkW(alias.c_str(), path.c_str(), nullptr))
        {
            const auto linked = storage::state_store::inspect_request(root, "status_fixture");
            tests.check("status_hardlinked_report_refused", linked.lookup_state == lookup::unavailable
                && linked.observation_error.code == "state_unsafe_object");
            tests.check("status_hardlink_fixture_removed", DeleteFileW(alias.c_str()) != FALSE);
        }
        else
        {
            std::cout << "{\"test\":\"status_hardlink_regression\",\"status\":\"not_run\",\"native_error\":"
                << GetLastError() << "}\n";
        }
        writer = create_report_fixture(root, path);
        auto version_two = final;
        const auto schema_version = version_two.find("windows_agent_cleanup.result.v1");
        version_two.replace(schema_version, std::string_view("windows_agent_cleanup.result.v1").size(),
            "windows_agent_cleanup.result.v2");
        version_two.pop_back();
        version_two += ",\"readiness\":null,\"statistics\":null,\"phases_ms\":{"
            "\"manifest_preparation_ms\":null,\"freeze_ms\":null,\"first_pass_ms\":null,\"recovery_ms\":null,"
            "\"reporting_before_result_ms\":null,\"total_to_result_ms\":1.25},\"space_observations\":null,"
            "\"next_action\":{\"action\":\"none\",\"reason\":\"recorded\"},\"retry_safe\":false}";
        tests.check("status_v2_fixture_written", append_report_fixture(writer.get(), intent + version_two + "\n"));
        const auto terminal_v2 = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_v2_final_retains_original_contract", terminal_v2.lookup_state == lookup::terminal_result
            && terminal_v2.original_result && *terminal_v2.original_result == version_two);
        writer.reset();
        writer = create_report_fixture(root, path);
        auto running = final;
        const auto final_status = running.find("\"completed\"");
        running.replace(final_status, std::string_view("\"completed\"").size(), "\"running\"");
        tests.check("status_nonterminal_schema_fixture_written", append_report_fixture(writer.get(), intent + running + "\n"));
        const auto nonterminal = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_result_schema_alone_does_not_prove_terminal", nonterminal.lookup_state == lookup::inspection_incomplete
            && nonterminal.observation_error.code == "status_final_result_binding_invalid");
        writer.reset();
        writer = create_report_fixture(root, path);
        auto count_mismatch_intent = intent;
        const auto intent_count = count_mismatch_intent.find("\"targets\":1");
        count_mismatch_intent.replace(intent_count, std::string_view("\"targets\":1").size(), "\"targets\":2");
        tests.check("status_count_binding_fixture_written", append_report_fixture(writer.get(), count_mismatch_intent + final + "\n"));
        const auto count_mismatch = storage::state_store::inspect_request(root, "status_fixture");
        tests.check("status_frozen_intent_target_count_is_bound", count_mismatch.lookup_state == lookup::inspection_incomplete
            && count_mismatch.observation_error.code == "status_final_result_binding_invalid");
        writer.reset();
        tests.check("status_report_fixture_removed", DeleteFileW(path.c_str()) != FALSE);
        tests.check("status_inspection_never_takes_or_breaks_store_writer_lock", !storage::state_store::open_at(root));
    }

    // SECURITY: Only removes direct children of a random directory created by this test.
    // Never follows reparses or recursively descends; any unexpected directory fails cleanup.
    bool cleanup_test_root(std::wstring_view root)
    {
        const auto owned = std::wstring(root);
        if (owned.find(L"\\secure_erase_state_test_") == std::wstring::npos)
        {
            return false;
        }
        const auto attributes = GetFileAttributesW(owned.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            return GetLastError() == ERROR_FILE_NOT_FOUND;
        }
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return false;
        }
        WIN32_FIND_DATAW data{};
        const auto find = FindFirstFileW((owned + L"\\*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        bool success = true;
        do
        {
            const std::wstring_view leaf(data.cFileName);
            if (leaf == L"." || leaf == L"..")
            {
                continue;
            }
            if ((data.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0)
            {
                success = false;
                continue;
            }
            if (!DeleteFileW((owned + L"\\" + std::wstring(leaf)).c_str()))
            {
                success = false;
            }
        } while (FindNextFileW(find, &data));
        success = GetLastError() == ERROR_NO_MORE_FILES && success;
        FindClose(find);
        return success && RemoveDirectoryW(owned.c_str());
    }
}

int wmain(int argc, wchar_t** argv)
{
    using namespace secure_erase;
    if (argc == 3 && std::wstring_view(argv[1]) == L"--probe-lock")
    {
        const auto competing = storage::state_store::open_at(argv[2]);
        return !competing && competing.error().native_code == ERROR_SHARING_VIOLATION ? 0 : 1;
    }
    if (argc != 2 || std::wstring_view(argv[1]) != L"--run-isolated-fixtures")
    {
        std::cout << "{\"event\":\"isolated_fixture_opt_in_required\"}\n";
        return 2;
    }
    test_suite tests;
    const auto root = unique_test_root();
    tests.check("isolated_random_root_selected", !root.empty());
    if (root.empty())
    {
        return tests.finish();
    }
    storage::store_options options;
    options.log_rotation_bytes = 65536;
    options.retained_log_files = 2;
    auto opened = storage::state_store::open_at(root, options);
    tests.check("private_local_store_created", opened.has_value());
    if (!opened)
    {
        std::cout << "{\"diagnostic\":\"" << opened.error().code << "\",\"native_error\":"
            << opened.error().native_code << "}\n";
        return tests.finish();
    }
    auto store = std::move(*opened);
    const auto canonical_root = expanded_test_path(root, false);
    tests.check("pinned_root_retains_canonical_long_spelling", !canonical_root.empty()
        && same_path(store->root_path(), canonical_root));
    const auto trailing_root = storage::state_store::open_at(root + L"\\");
    tests.check("trailing_separator_root_rejected", !trailing_root
        && trailing_root.error().code == "state_invalid_root");
    const auto relative_root = storage::state_store::open_at(root.substr(0, 2) + L"relative_store");
    tests.check("drive_relative_root_rejected", !relative_root
        && relative_root.error().code == "state_invalid_root");
    const auto unc_root = storage::state_store::open_at(L"\\\\localhost\\invalid_share\\state");
    tests.check("unc_root_rejected_before_access", !unc_root
        && unc_root.error().code == "state_unsafe_root");
    const auto short_root = expanded_test_path(root, true);
    if (!short_root.empty() && !same_path(short_root, canonical_root))
    {
        const auto competing_alias = storage::state_store::open_at(short_root);
        tests.check("short_alias_reaches_same_exclusive_store_lock", !competing_alias
            && competing_alias.error().native_code == ERROR_SHARING_VIOLATION);
        store.reset();
        auto alias_opened = storage::state_store::open_at(short_root, options);
        tests.check("short_alias_reopens_canonical_private_store", alias_opened
            && same_path((*alias_opened)->root_path(), canonical_root));
        if (!alias_opened)
        {
            std::cout << "{\"diagnostic\":\"" << alias_opened.error().code << "\",\"native_error\":"
                << alias_opened.error().native_code << "}\n";
            tests.check("failed_alias_fixture_cleanup", cleanup_test_root(root));
            return tests.finish();
        }
        store = std::move(*alias_opened);
    }
    else
    {
        // EVIDENCE: Volumes may disable short-name creation. Do not label this
        // capability-dependent alias regression passed when no alias exists.
        std::cout << "{\"test\":\"short_alias_regression\",\"status\":\"not_run\","
            "\"reason\":\"distinct_short_name_unavailable\"}\n";
    }
    const auto alias = root + L"_reparse";
    if (CreateSymbolicLinkW(alias.c_str(), root.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY))
    {
        const auto observed_alias = storage::state_store::inspect_request(alias, "status_fixture");
        tests.check("status_reparse_root_rejected_read_only", observed_alias.lookup_state
            == storage::request_lookup_state::unavailable && observed_alias.observation_error.code == "state_unsafe_object");
        const auto observed_ancestor = storage::state_store::inspect_request(alias + L"\\never_create", "status_fixture");
        tests.check("status_reparse_ancestor_rejected_without_creation", observed_ancestor.lookup_state
            == storage::request_lookup_state::unavailable && observed_ancestor.observation_error.code == "state_unsafe_object");
        const auto refused_leaf = storage::state_store::open_at(alias);
        tests.check("reparse_store_leaf_rejected", !refused_leaf
            && refused_leaf.error().code == "state_unsafe_object");
        const auto refused_ancestor = storage::state_store::open_at(alias + L"\\never_create");
        tests.check("reparse_store_ancestor_rejected", !refused_ancestor
            && refused_ancestor.error().code == "state_unsafe_object");
        const auto child_attributes = GetFileAttributesW((root + L"\\never_create").c_str());
        tests.check("reparse_rejection_does_not_create_target_child", child_attributes == INVALID_FILE_ATTRIBUTES
            && GetLastError() == ERROR_FILE_NOT_FOUND);
        tests.check("reparse_fixture_removed_without_following", RemoveDirectoryW(alias.c_str()) != FALSE);
    }
    else
    {
        std::cout << "{\"test\":\"state_reparse_regression\",\"status\":\"not_run\","
            "\"native_error\":" << GetLastError() << "}\n";
    }
    request_status_fixtures(tests, *store);
    tests.check("same_process_lock_exclusion", !storage::state_store::open_at(root));
    tests.check("cross_process_lock_exclusion", child_lock_probe(root));
    compressed_parent_staging_fixture(tests, *store);
    {
        auto factory_result = store->staging_files();
        tests.check("staging_private_factory_created", factory_result.has_value());
        if (factory_result)
        {
            auto factory = std::move(*factory_result);
            tests.check("staging_path_escape_rejected", !factory->create_private("../outside") &&
                !factory->create_private("stream:ads") && !factory->create_private(".."));
            auto file_result = factory->create_private("stage_probe.bin");
            tests.check("staging_exclusive_scratch_created", file_result.has_value());
            if (file_result)
            {
                auto file = std::move(*file_result);
                tests.check("staging_duplicate_leaf_rejected", !factory->create_private("stage_probe.bin"));
                const auto allocated = file->resize(131072);
                auto length = file->size();
                tests.check("staging_real_allocation_and_size", allocated && length && *length == 131072);
                std::array<std::byte, 64> zeros{};
                zeros.fill(std::byte{0x7f});
                const auto zero_read = file->read_at(65520, zeros);
                tests.check("staging_reserved_outcomes_initially_zero", zero_read &&
                    std::ranges::all_of(zeros, [](std::byte value)
                    {
                        return value == std::byte{};
                    }));
                const std::array payload{std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};
                const auto written = file->write_at(65535, payload);
                std::array<std::byte, 4> observed{};
                const auto read = file->read_at(65535, observed);
                tests.check("staging_exact_random_access_roundtrip", written && read && observed == payload && file->flush());
                tests.check("staging_invalid_ranges_and_short_reads_fail", !file->read_at(131071, observed) &&
                    !file->write_at((std::numeric_limits<std::uint64_t>::max)(), payload) &&
                    !file->resize((std::numeric_limits<std::uint64_t>::max)()));
                const auto leaf = store->root_path() + L"\\stage_probe.bin";
                unique_handle metadata(CreateFileW(leaf.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                FILE_STANDARD_INFO allocation{};
                tests.check("staging_filesystem_allocation_reserved", metadata.get() != INVALID_HANDLE_VALUE &&
                    GetFileInformationByHandleEx(metadata.get(), FileStandardInfo, &allocation, sizeof(allocation)) &&
                    allocation.AllocationSize.QuadPart >= 131072);
                metadata.reset();
                unique_handle writer(CreateFileW(leaf.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                const auto writer_error = GetLastError();
                tests.check("staging_external_write_denied", writer.get() == INVALID_HANDLE_VALUE &&
                    (writer_error == ERROR_SHARING_VIOLATION || writer_error == ERROR_ACCESS_DENIED));
                const bool externally_deleted = DeleteFileW(leaf.c_str()) != FALSE;
                const auto delete_error = GetLastError();
                tests.check("staging_external_delete_denied", !externally_deleted &&
                    (delete_error == ERROR_SHARING_VIOLATION || delete_error == ERROR_ACCESS_DENIED));
                tests.check("staging_only_owned_cleanup_names_accepted", !factory->remove_private("unrelated.bin") &&
                    factory->remove_private("stage_probe.bin"));
                store.reset();
                tests.check("staging_owners_retain_exclusive_store_lock", !storage::state_store::open_at(root));
                factory.reset();
                tests.check("staging_file_alone_retains_store_lock", !storage::state_store::open_at(root));
                file.reset();
                tests.check("staging_scratch_removed_on_final_close", GetFileAttributesW(leaf.c_str()) == INVALID_FILE_ATTRIBUTES &&
                    GetLastError() == ERROR_FILE_NOT_FOUND);
                auto reopened = storage::state_store::open_at(root, options);
                tests.check("staging_final_owner_releases_store_lock", reopened.has_value());
                if (!reopened)
                {
                    return tests.finish();
                }
                store = std::move(*reopened);
            }
        }
    }
    auto first = fixture();
    auto saved = store->save(first);
    tests.check("protected_checkpoint_save", saved.has_value());
    auto loaded = store->load(first.plan.job_id);
    tests.check("dpapi_authenticated_roundtrip", loaded && loaded->plan.targets == first.plan.targets
        && loaded->targets[0].key == first.targets[0].key && loaded->targets[0].offset == 512);
    if (loaded)
    {
        storage::clear_sensitive(*loaded);
    }
    const auto first_path = checkpoint_path(root, first.plan.job_id);
    tests.check("tamper_injected_into_private_fixture", change_first_byte(first_path));
    tests.check("dpapi_tamper_rejected", !store->load(first.plan.job_id));
    tests.check("checkpoint_atomic_replace", store->save(first).has_value());
    auto second = fixture("fedcba9876543210fedcba9876543210");
    tests.check("second_checkpoint_save", store->save(second).has_value());
    const auto second_path = checkpoint_path(root, second.plan.job_id);
    tests.check("valid_blob_leaf_swap_injected", CopyFileW(first_path.c_str(), second_path.c_str(), FALSE) != FALSE);
    tests.check("dpapi_job_namespace_swap_rejected", !store->load(second.plan.job_id));
    tests.check("checkpoint_remove", store->remove(second.plan.job_id).has_value());
    unique_handle unsafe_file(CreateFileW(second_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    tests.check("unsafe_inherited_acl_fixture_created", unsafe_file.get() != INVALID_HANDLE_VALUE);
    unsafe_file.reset();
    const auto unsafe_load = store->load(second.plan.job_id);
    tests.check("unprotected_checkpoint_acl_rejected", !unsafe_load
        && unsafe_load.error().code == "state_acl_not_private");
    tests.check("unsafe_test_leaf_cleanup", DeleteFileW(second_path.c_str()) != FALSE);
    engine::event event{"test_progress", first.plan.job_id, first.targets[0].identity, 0, 1000, 0};
    bool events_written = true;
    for (unsigned index{}; index < 800; ++index)
    {
        event.bytes_done = index;
        if (!store->emit(event))
        {
            events_written = false;
            break;
        }
    }
    tests.check("jsonl_rotation_writes", events_written);
    tests.check("bounded_rotation_files", GetFileAttributesW((root + L"\\events_2.jsonl").c_str())
        != INVALID_FILE_ATTRIBUTES && GetFileAttributesW((root + L"\\events_3.jsonl").c_str())
        == INVALID_FILE_ATTRIBUTES);
    tests.check("torn_log_tail_injected", append_torn_log(root));
    tests.check("torn_tail_recovered_before_next_event", store->emit(event).has_value());
    auto history = store->read_history(300000);
    tests.check("jsonl_history_masks_target_and_records_recovery", history
        && history->find(first.plan.targets[0].path) == std::string::npos
        && history->find("log_torn_tail_removed") != std::string::npos
        && history->find("incomplete") == std::string::npos);
    const std::array<engine::event, 2> batch{
        engine::event{"batch_first", first.plan.job_id, first.targets[0].identity},
        engine::event{"batch_second", first.plan.job_id, first.targets[0].identity}};
    tests.check("jsonl_batch_append", store->emit_batch(batch).has_value());
    const auto batch_history = store->read_history(300000);
    tests.check("jsonl_batch_order_and_masking", batch_history
        && batch_history->find("batch_first") < batch_history->find("batch_second")
        && batch_history->find("batch_second") != std::string::npos
        && batch_history->find(first.plan.targets[0].path) == std::string::npos);
    auto invalid_batch = batch;
    invalid_batch.back().code = "invalid\"event";
    tests.check("jsonl_invalid_batch_rejected", !store->emit_batch(invalid_batch));
    const auto unchanged_history = store->read_history(300000);
    tests.check("jsonl_invalid_batch_writes_nothing", batch_history && unchanged_history
        && *batch_history == *unchanged_history);
    const std::vector<engine::event> excessive_batch(65, batch.front());
    tests.check("jsonl_excessive_batch_rejected", !store->emit_batch(excessive_batch));
    tests.check("jsonl_empty_batch_noop", store->emit_batch({}).has_value());
    auto listed = store->list_checkpoints();
    tests.check("checkpoint_history_listing", listed && listed->size() == 1
        && listed->front().job_id == first.plan.job_id);
    tests.check("completed_checkpoint_cleanup", store->remove(first.plan.job_id).has_value());
    tests.check("completed_checkpoint_absent", !store->load(first.plan.job_id));
    tests.check("prepare_interrupted_temporary", store->save(first).has_value());
    store.reset();
    const auto pending = root + L"\\pending_0123456789abcdef0123456789abcdef.tmp";
    tests.check("simulate_crash_pending_rename", MoveFileExW(first_path.c_str(), pending.c_str(), 0) != FALSE);
    opened = storage::state_store::open_at(root, options);
    tests.check("reopen_cleans_private_abandoned_temporary", opened
        && GetFileAttributesW(pending.c_str()) == INVALID_FILE_ATTRIBUTES);
    if (opened)
    {
        store = std::move(*opened);
        tests.check("checkpoint_recreated_for_expiry", store->save(first).has_value());
        store.reset();
        unique_handle timestamp_file(CreateFileW(first_path.c_str(), FILE_WRITE_ATTRIBUTES, 0,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILETIME old{};
        GetSystemTimeAsFileTime(&old);
        ULARGE_INTEGER time{};
        time.LowPart = old.dwLowDateTime;
        time.HighPart = old.dwHighDateTime;
        time.QuadPart -= 2ULL * 864000000000ULL;
        old.dwLowDateTime = time.LowPart;
        old.dwHighDateTime = time.HighPart;
        tests.check("age_owned_checkpoint_fixture", timestamp_file.get() != INVALID_HANDLE_VALUE
            && SetFileTime(timestamp_file.get(), nullptr, nullptr, &old));
        timestamp_file.reset();
        options.checkpoint_retention_days = 1;
        opened = storage::state_store::open_at(root, options);
        tests.check("configured_abandoned_checkpoint_expiry", opened
            && GetFileAttributesW(first_path.c_str()) == INVALID_FILE_ATTRIBUTES);
        if (opened)
        {
            opened->reset();
        }
    }
    storage::clear_sensitive(first);
    storage::clear_sensitive(second);
    tests.check("isolated_private_test_files_removed", cleanup_test_root(root));
    const auto unsafe_root = unique_test_root();
    const bool unsafe_created = !unsafe_root.empty() && CreateDirectoryW(unsafe_root.c_str(), nullptr);
    tests.check("inherited_acl_root_fixture_created", unsafe_created);
    if (unsafe_created)
    {
        const auto unsafe_status = storage::state_store::inspect_request(unsafe_root, "status_fixture");
        tests.check("status_unprotected_root_refused_without_acl_repair", unsafe_status.lookup_state
            == storage::request_lookup_state::unavailable && unsafe_status.observation_error.code == "state_acl_not_private");
        const auto refused = storage::state_store::open_at(unsafe_root);
        tests.check("unsafe_existing_root_refused", !refused && refused.error().code == "state_acl_not_private");
        tests.check("unsafe_root_fixture_removed", RemoveDirectoryW(unsafe_root.c_str()) != FALSE);
    }
    return tests.finish();
}
