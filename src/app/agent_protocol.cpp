module secure_erase.agent_protocol;

import std;

namespace secure_erase::agent
{
    namespace
    {
        [[nodiscard]] bool valid_utf8(std::string_view text, std::size_t& units)
        {
            units = 0;
            for (std::size_t index = 0; index < text.size();)
            {
                const auto first = static_cast<unsigned char>(text[index++]);
                std::uint32_t point = first;
                std::size_t remaining{};
                std::uint32_t minimum{};
                if (first < 0x80)
                {
                    if (first == 0)
                    {
                        return false;
                    }
                }
                else if (first >= 0xc2 && first <= 0xdf)
                {
                    point = first & 0x1f;
                    remaining = 1;
                    minimum = 0x80;
                }
                else if (first >= 0xe0 && first <= 0xef)
                {
                    point = first & 0x0f;
                    remaining = 2;
                    minimum = 0x800;
                }
                else if (first >= 0xf0 && first <= 0xf4)
                {
                    point = first & 0x07;
                    remaining = 3;
                    minimum = 0x10000;
                }
                else
                {
                    return false;
                }
                if (remaining > text.size() - index)
                {
                    return false;
                }
                for (std::size_t tail = 0; tail < remaining; ++tail)
                {
                    const auto byte = static_cast<unsigned char>(text[index++]);
                    if ((byte & 0xc0) != 0x80)
                    {
                        return false;
                    }
                    point = (point << 6) | (byte & 0x3f);
                }
                if (point < minimum || point > 0x10ffff ||
                    (point >= 0xd800 && point <= 0xdfff))
                {
                    return false;
                }
                units += point > 0xffff ? 2 : 1;
            }
            return true;
        }

        void append_utf8(std::string& text, std::uint32_t point)
        {
            if (point < 0x80)
            {
                text.push_back(static_cast<char>(point));
            }
            else if (point < 0x800)
            {
                text.push_back(static_cast<char>(0xc0 | (point >> 6)));
                text.push_back(static_cast<char>(0x80 | (point & 0x3f)));
            }
            else if (point < 0x10000)
            {
                text.push_back(static_cast<char>(0xe0 | (point >> 12)));
                text.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3f)));
                text.push_back(static_cast<char>(0x80 | (point & 0x3f)));
            }
            else
            {
                text.push_back(static_cast<char>(0xf0 | (point >> 18)));
                text.push_back(static_cast<char>(0x80 | ((point >> 12) & 0x3f)));
                text.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3f)));
                text.push_back(static_cast<char>(0x80 | (point & 0x3f)));
            }
        }

        class parser
        {
        public:
            explicit parser(std::string_view text) : text_(text)
            {
            }

            bool take(char value)
            {
                space();
                if (position_ < text_.size() && text_[position_] == value)
                {
                    ++position_;
                    return true;
                }
                return false;
            }

            bool end()
            {
                space();
                return position_ == text_.size();
            }

            engine::result<std::string> string()
            {
                if (!take('"'))
                {
                    return std::unexpected(engine::error{"manifest_json_string_required"});
                }
                std::string result;
                while (position_ < text_.size())
                {
                    const char current = text_[position_++];
                    if (current == '"')
                    {
                        std::size_t units{};
                        if (!valid_utf8(result, units))
                        {
                            return std::unexpected(engine::error{"manifest_invalid_unicode"});
                        }
                        return result;
                    }
                    if (static_cast<unsigned char>(current) < 0x20)
                    {
                        break;
                    }
                    if (current != '\\')
                    {
                        result.push_back(current);
                        continue;
                    }
                    if (position_ == text_.size())
                    {
                        break;
                    }
                    const char escaped = text_[position_++];
                    if (escaped == '"' || escaped == '\\' || escaped == '/')
                    {
                        result.push_back(escaped);
                    }
                    else if (escaped == 'b' || escaped == 'f' || escaped == 'n' ||
                        escaped == 'r' || escaped == 't')
                    {
                        const std::string_view keys = "bfnrt";
                        const std::string_view values = "\b\f\n\r\t";
                        result.push_back(values[keys.find(escaped)]);
                    }
                    else if (escaped == 'u')
                    {
                        auto point = hex();
                        if (!point)
                        {
                            return std::unexpected(point.error());
                        }
                        if (*point >= 0xd800 && *point <= 0xdbff)
                        {
                            if (text_.size() - position_ < 2 ||
                                text_.substr(position_, 2) != "\\u")
                            {
                                return std::unexpected(engine::error{"manifest_invalid_surrogate"});
                            }
                            position_ += 2;
                            auto low = hex();
                            if (!low || *low < 0xdc00 || *low > 0xdfff)
                            {
                                return std::unexpected(engine::error{"manifest_invalid_surrogate"});
                            }
                            *point = 0x10000 + ((*point - 0xd800) << 10) + *low - 0xdc00;
                        }
                        else if (*point >= 0xdc00 && *point <= 0xdfff)
                        {
                            return std::unexpected(engine::error{"manifest_invalid_surrogate"});
                        }
                        append_utf8(result, *point);
                    }
                    else
                    {
                        break;
                    }
                }
                return std::unexpected(engine::error{"manifest_invalid_json_string"});
            }

        private:
            void space()
            {
                while (position_ < text_.size() &&
                    (text_[position_] == ' ' || text_[position_] == '\t' || text_[position_] == '\r'))
                {
                    ++position_;
                }
            }

            engine::result<std::uint32_t> hex()
            {
                if (text_.size() - position_ < 4)
                {
                    return std::unexpected(engine::error{"manifest_invalid_unicode_escape"});
                }
                std::uint32_t value{};
                for (unsigned index = 0; index < 4; ++index)
                {
                    const char current = text_[position_++];
                    unsigned digit{};
                    if (current >= '0' && current <= '9')
                    {
                        digit = static_cast<unsigned>(current - '0');
                    }
                    else if (current >= 'a' && current <= 'f')
                    {
                        digit = static_cast<unsigned>(current - 'a' + 10);
                    }
                    else if (current >= 'A' && current <= 'F')
                    {
                        digit = static_cast<unsigned>(current - 'A' + 10);
                    }
                    else
                    {
                        return std::unexpected(engine::error{"manifest_invalid_unicode_escape"});
                    }
                    value = value * 16 + digit;
                }
                return value;
            }

            std::string_view text_;
            std::size_t position_{};
        };

        char lower(char value) noexcept
        {
            return value >= 'A' && value <= 'Z' ? static_cast<char>(value + 'a' - 'A') : value;
        }
    }

    engine::result<std::string> normalize_path(std::string_view text)
    {
        if (text.starts_with("\\\\?\\"))
        {
            text.remove_prefix(4);
        }
        std::size_t units{};
        if (!valid_utf8(text, units) || units > 32760 || text.size() < 3 ||
            !((text[0] >= 'A' && text[0] <= 'Z') || (text[0] >= 'a' && text[0] <= 'z')) ||
            text[1] != ':' || (text[2] != '\\' && text[2] != '/'))
        {
            return std::unexpected(engine::error{"absolute_drive_path_required"});
        }
        std::string result(text);
        std::replace(result.begin(), result.end(), '/', '\\');
        if (result.size() > 3 && result.back() == '\\')
        {
            result.pop_back();
        }
        std::size_t start = 3;
        for (std::size_t index = 3; index <= result.size(); ++index)
        {
            if (index != result.size() && result[index] != '\\')
            {
                const unsigned char value = static_cast<unsigned char>(result[index]);
                if (value < 32 || std::string_view(":*?<>\"|").find(result[index]) != std::string_view::npos)
                {
                    return std::unexpected(engine::error{"unsupported_path_character"});
                }
                continue;
            }
            const auto component = std::string_view(result).substr(start, index - start);
            if (result.size() != 3 && (component.empty() || component == "." || component == ".." ||
                component.back() == '.' || component.back() == ' '))
            {
                return std::unexpected(engine::error{"ambiguous_path_component"});
            }
            start = index + 1;
        }
        return result;
    }

    bool within_scope(std::string_view path, std::string_view root) noexcept
    {
        if (root.empty() || path.size() < root.size())
        {
            return false;
        }
        for (std::size_t index = 0; index < root.size(); ++index)
        {
            if (lower(path[index]) != lower(root[index]))
            {
                return false;
            }
        }
        return path.size() == root.size() || root.back() == '\\' || path[root.size()] == '\\';
    }

    engine::result<manifest_entry> parse_manifest_line(std::string_view text)
    {
        if (text.empty() || text.size() > maximum_record_bytes)
        {
            return std::unexpected(engine::error{"manifest_record_size_invalid"});
        }
        parser input(text);
        manifest_entry entry;
        bool path_seen{};
        bool downgrade_seen{};
        if (!input.take('{'))
        {
            return std::unexpected(engine::error{"manifest_object_required"});
        }
        do
        {
            auto key = input.string();
            if (!key || !input.take(':'))
            {
                return std::unexpected(engine::error{"manifest_invalid_member"});
            }
            auto value = input.string();
            if (!value)
            {
                return std::unexpected(value.error());
            }
            if (*key == "path" && !path_seen)
            {
                auto path = normalize_path(*value);
                if (!path)
                {
                    return std::unexpected(path.error());
                }
                entry.path = std::move(*path);
                path_seen = true;
            }
            else if (*key == "allow_downgrade" && !downgrade_seen)
            {
                if (*value == "delete_only")
                {
                    entry.downgrade = engine::capability::delete_only;
                }
                else if (*value == "overwrite_best_effort")
                {
                    entry.downgrade = engine::capability::overwrite_best_effort;
                }
                else
                {
                    return std::unexpected(engine::error{"manifest_unknown_downgrade"});
                }
                downgrade_seen = true;
            }
            else
            {
                return std::unexpected(engine::error{"manifest_unknown_or_duplicate_key"});
            }
        } while (input.take(','));
        if (!input.take('}') || !input.end() || !path_seen)
        {
            return std::unexpected(engine::error{"manifest_invalid_object"});
        }
        return entry;
    }

    std::string json_quote(std::string_view text)
    {
        constexpr std::string_view digits = "0123456789abcdef";
        std::string result{"\""};
        for (const unsigned char value : text)
        {
            if (value == '"' || value == '\\')
            {
                result.push_back('\\');
                result.push_back(static_cast<char>(value));
            }
            else if (value < 32)
            {
                result += "\\u00";
                result.push_back(digits[value >> 4]);
                result.push_back(digits[value & 15]);
            }
            else
            {
                result.push_back(static_cast<char>(value));
            }
        }
        result.push_back('"');
        return result;
    }
    std::string_view next_action_name(next_action_kind value) noexcept
    {
        switch (value)
        {
        case next_action_kind::none:
            return "none";
        case next_action_kind::use_supported_host:
            return "use_supported_host";
        case next_action_kind::request_os_consent:
            return "request_os_consent";
        case next_action_kind::correct_input:
            return "correct_input";
        case next_action_kind::inspect_report:
            return "inspect_report";
        case next_action_kind::wait_same_invocation:
            return "wait_same_invocation";
        case next_action_kind::reconcile_unknown:
            return "reconcile_unknown";
        }
        return "reconcile_unknown";
    }

    std::string action_guidance_json(const action_guidance& value)
    {
        // CONTRACT: Reasons are bounded identifiers, never executable commands.
        return "\"next_action\":{\"action\":" + json_quote(next_action_name(value.action)) +
            ",\"reason\":" + json_quote(std::string_view(value.reason).substr(0, 128)) +
            "},\"retry_safe\":" + (value.retry_safe ? "true" : "false");
    }

    std::string statistics_json(const engine::operation_statistics& value)
    {
        if (!value.supported)
        {
            return "null";
        }
        const auto counts = [](const engine::namespace_statistics& count)
        {
            return "{\"files\":" + std::to_string(count.files) + ",\"directories\":" +
                std::to_string(count.directories) + ",\"unclassified\":" + std::to_string(count.unclassified) + "}";
        };
        const auto& bytes = value.logical_bytes;
        const auto& failures = value.final_failures;
        return "{\"selected\":" + counts(value.selected) + ",\"remove_attempted\":" + counts(value.remove_attempted) +
            ",\"completed\":" + counts(value.completed) +
            ",\"logical_bytes_semantics\":\"frozen_default_stream_snapshot\",\"logical_bytes\":{\"selected\":" +
            std::to_string(bytes.selected) + ",\"remove_attempted\":" + std::to_string(bytes.remove_attempted) +
            ",\"completed\":" + std::to_string(bytes.completed) + ",\"selected_unknown\":" +
            std::to_string(bytes.selected_unknown) + ",\"remove_attempted_unknown\":" +
            std::to_string(bytes.remove_attempted_unknown) + ",\"completed_unknown\":" +
            std::to_string(bytes.completed_unknown) + "},\"failed\":" + std::to_string(value.failed) +
            ",\"pending\":" + std::to_string(value.pending) + ",\"final_failures\":{\"scope_protection\":" +
            std::to_string(failures.scope_protection) + ",\"reparse\":" + std::to_string(failures.reparse) +
            ",\"identity\":" + std::to_string(failures.identity) + ",\"access_lock\":" +
            std::to_string(failures.access_lock) + ",\"resource\":" + std::to_string(failures.resource) +
            ",\"report_audit\":" + std::to_string(failures.report_audit) + ",\"other\":" +
            std::to_string(failures.other) + "}}";
    }

}
