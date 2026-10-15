import std;
import secure_erase.codec;
import secure_erase.plan;

namespace
{
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
            std::cout << "{\"suite\":\"codec\",\"assertions\":" << count_
                << ",\"failed\":" << failed_ << "}\n";
            return failed_ == 0 ? 0 : 1;
        }

    private:
        unsigned count_{};
        unsigned failed_{};
    };

    secure_erase::engine::checkpoint fixture()
    {
        using namespace secure_erase;
        engine::target_snapshot target;
        target.path = "C:\\disposable\\測試.bin";
        target.identity = "volume_1_file_42";
        target.device_key = "disk_1";
        target.creation_time = 123;
        target.write_time = 456;
        target.change_time = 789;
        target.attributes = 32;
        target.link_count = 1;
        target.trim_supported = true;
        target.vss_query_complete = true;
        target.vss_snapshot_count = 3;
        target.vss_native_error = 0;
        target.media = engine::media_kind::ssd;
        target.support = engine::capability::overwrite_best_effort;
        target.streams = {{"", 4097}, {":test:$DATA", 13}};
        target.protection_reasons = {"fixture_policy_reason"};
        target.residual_risks = {"flash_physical_limit", "volume_shadow_copies_detected"};
        engine::checkpoint value;
        value.plan.job_id = "0123456789abcdef0123456789abcdef";
        value.plan.targets.push_back(target);
        value.plan.fingerprint = engine::fingerprint(value.plan);
        engine::target_checkpoint state;
        state.identity = target.identity;
        state.observed = target;
        state.key_ready = true;
        state.key.fill(std::byte{0x57});
        state.nonce.fill(std::byte{0xa9});
        state.stream_index = 1;
        state.offset = 7;
        state.state = engine::target_state::writing;
        value.targets.push_back(state);
        return value;
    }
}

int main()
{
    using namespace secure_erase;
    test_suite tests;
    auto input = fixture();
    auto encoded = storage::encode_checkpoint(input);
    tests.check("checkpoint_valid_encode", encoded.has_value());
    if (!encoded)
    {
        return tests.finish();
    }
    auto decoded = storage::decode_checkpoint(*encoded);
    tests.check("checkpoint_roundtrip_all_metadata_and_keys", decoded
        && decoded->schema_version == input.schema_version
        && decoded->plan.job_id == input.plan.job_id
        && decoded->plan.fingerprint == input.plan.fingerprint
        && decoded->plan.targets == input.plan.targets
        && decoded->targets.size() == 1
        && decoded->targets[0].identity == input.targets[0].identity
        && decoded->targets[0].observed == input.targets[0].observed
        && decoded->targets[0].key == input.targets[0].key
        && decoded->targets[0].nonce == input.targets[0].nonce
        && decoded->targets[0].key_ready
        && decoded->targets[0].stream_index == 1
        && decoded->targets[0].offset == 7
        && decoded->targets[0].state == engine::target_state::writing);
    bool all_truncated_rejected = true;
    for (std::size_t length{}; length < encoded->size(); ++length)
    {
        if (storage::decode_checkpoint(std::span(*encoded).first(length)))
        {
            all_truncated_rejected = false;
            break;
        }
    }
    tests.check("every_truncated_prefix_rejected", all_truncated_rejected);
    auto modified = *encoded;
    modified.push_back(std::byte{});
    tests.check("trailing_bytes_rejected", !storage::decode_checkpoint(modified));
    modified = *encoded;
    modified[8] = std::byte{2};
    tests.check("future_version_rejected", !storage::decode_checkpoint(modified));
    modified = *encoded;
    modified[12] = std::byte{0xff};
    modified[13] = std::byte{0xff};
    modified[14] = std::byte{0xff};
    modified[15] = std::byte{0xff};
    tests.check("hostile_string_length_rejected", !storage::decode_checkpoint(modified));
    modified = *encoded;
    modified.back() = std::byte{255};
    tests.check("unknown_checkpoint_state_rejected", !storage::decode_checkpoint(modified));
    modified = *encoded;
    modified[modified.size() - 18] = std::byte{2};
    tests.check("noncanonical_boolean_rejected", !storage::decode_checkpoint(modified));
    modified = *encoded;
    for (std::size_t index = 116; index < 120; ++index)
    {
        modified[index] = std::byte{255};
    }
    tests.check("hostile_target_count_rejected_before_allocation", !storage::decode_checkpoint(modified));
    tests.check("explicit_encoding_budget_enforced", !storage::encode_checkpoint(input, 128));
    tests.check("explicit_decoding_budget_enforced", !storage::decode_checkpoint(*encoded, 128));
    tests.check("explicit_decoding_resource_budget_accepts_valid_state",
        storage::decode_checkpoint(*encoded, 65536).has_value());
    auto invalid = input;
    invalid.plan.targets[0].path = "C:\\different.bin";
    tests.check("plan_mutation_rejected", !storage::encode_checkpoint(invalid));
    invalid = input;
    invalid.targets[0].identity = "other_object";
    tests.check("checkpoint_identity_rebinding_rejected", !storage::encode_checkpoint(invalid));
    invalid = input;
    invalid.targets[0].offset = 14;
    tests.check("out_of_stream_cursor_rejected", !storage::encode_checkpoint(invalid));
    invalid = input;
    invalid.targets[0].stream_index = 3;
    tests.check("out_of_range_stream_rejected", !storage::encode_checkpoint(invalid));
    invalid = input;
    invalid.targets[0].stream_index = 2;
    invalid.targets[0].offset = 0;
    invalid.targets[0].state = engine::target_state::verified;
    tests.check("end_of_stream_checkpoint_accepted", storage::encode_checkpoint(invalid).has_value());
    invalid = input;
    invalid.targets[0].observed.path = std::string(131073, 'a');
    tests.check("overlong_snapshot_path_rejected", !storage::encode_checkpoint(invalid));
    invalid = input;
    invalid.targets[0].observed.path = std::string("bad\0path", 8);
    tests.check("embedded_nul_rejected", !storage::encode_checkpoint(invalid));
    invalid = input;
    invalid.targets[0].observed.path = "\xed\xa0\x80";
    tests.check("utf8_surrogate_rejected", !storage::encode_checkpoint(invalid));
    tests.check("utf8_wellformed_multilingual", storage::valid_utf8("檔案😀")
        && storage::valid_utf8("ascii") && storage::valid_utf8(""));
    tests.check("utf8_invalid_sequences_rejected", !storage::valid_utf8("\xc0\x80")
        && !storage::valid_utf8("\xf4\x90\x80\x80") && !storage::valid_utf8("\xe4\xb8")
        && !storage::valid_utf8("\x80") && !storage::valid_utf8("\xff"));
    tests.check("job_leaf_path_injection_rejected", !storage::valid_job_id("../checkpoint")
        && !storage::valid_job_id("0123456789abcdef0123456789abcdeF")
        && storage::valid_job_id(input.plan.job_id));
    engine::event event{"target_writing", input.plan.job_id, "C:\\secret.bin", 7, 13, 5};
    const auto json = storage::event_json(event, 12345);
    tests.check("event_contains_diagnostics_without_plaintext_path", !json.empty()
        && json.find("secret.bin") == std::string::npos
        && json.find("\"code\":5") != std::string::npos
        && json.find("\"ntstatus\":null") != std::string::npos
        && json.ends_with("}\n"));
    event.code = "bad\"\ncode";
    tests.check("event_code_injection_rejected", storage::event_json(event, 0).empty());
    engine::event count_event{};
    count_event.code = "quick_delete_finished_partial_failure";
    count_event.job_id = input.plan.job_id;
    count_event.total_targets = 10;
    count_event.completed_targets = 7;
    count_event.failed_targets = 2;
    const auto counts = storage::event_json(count_event, 12345);
    tests.check("quick_item_counts_preserve_units", counts.find(
        "\"target_counts\":{\"total\":10,\"completed\":7,\"failed\":2}") != std::string::npos
        && counts.find("\"bytes_done\":0") != std::string::npos);
    count_event.completed_targets = 11;
    tests.check("quick_completed_count_over_total_rejected", storage::event_json(count_event, 0).empty());
    count_event.completed_targets = 9;
    tests.check("quick_failed_count_over_remaining_rejected", storage::event_json(count_event, 0).empty());
    count_event.total_targets = (std::numeric_limits<std::uint64_t>::max)();
    count_event.completed_targets = count_event.total_targets;
    count_event.failed_targets = 1;
    tests.check("quick_item_count_overflow_rejected", storage::event_json(count_event, 0).empty());
    storage::clear_sensitive(input);
    tests.check("checkpoint_key_zeroization", std::ranges::all_of(input.targets[0].key,
        [](auto byte)
        {
            return byte == std::byte{};
        })
        && std::ranges::all_of(input.targets[0].nonce, [](auto byte)
        {
            return byte == std::byte{};
        })
        && !input.targets[0].key_ready);
    storage::clear_sensitive(*encoded);
    tests.check("plaintext_buffer_zeroization", std::ranges::all_of(*encoded,
        [](auto byte)
        {
            return byte == std::byte{};
        }));
    if (decoded)
    {
        storage::clear_sensitive(*decoded);
    }
    storage::clear_sensitive(invalid);
    storage::clear_sensitive(modified);
    return tests.finish();
}
