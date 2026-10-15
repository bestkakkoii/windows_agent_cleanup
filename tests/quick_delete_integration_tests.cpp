#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

import std;
import secure_erase.quick_delete;
import secure_erase.platform;

// CONTRACT: Test-only Linux namespace adapter. No path arguments are accepted.
// Every mutation is confined to a newly created mode-0700 fixture. This exercises
// the real quick-delete module and real unlink/hardlink behavior, not WinAPI.
namespace
{
namespace quick = secure_erase::quick;
namespace engine = secure_erase::engine;

struct totals
{
    unsigned total{};
    unsigned passed{};

    void check(bool condition, std::string_view name)
    {
        ++total;
        passed += static_cast<unsigned>(condition);
        std::cout << "{\"test\":\"" << name << "\",\"passed\":" <<
            (condition ? "true" : "false") << "}\n";
    }
};

class descriptor
{
public:
    explicit descriptor(int value = -1) : value_(value)
    {
    }

    ~descriptor()
    {
        if (value_ >= 0)
        {
            static_cast<void>(close(value_));
        }
    }

    descriptor(const descriptor&) = delete;
    descriptor& operator=(const descriptor&) = delete;

    [[nodiscard]] int get() const
    {
        return value_;
    }

private:
    int value_;
};

class fixture
{
public:
    fixture()
    {
        std::array<char, 80> pattern{};
        constexpr char name[] = "/tmp/quick_delete_isolated_XXXXXX";
        std::copy(std::begin(name), std::end(name), pattern.begin());
        const auto created = mkdtemp(pattern.data());
        if (created != nullptr)
        {
            root_ = created;
        }
    }

    ~fixture()
    {
        if (!root_.empty())
        {
            std::error_code error;
            std::filesystem::remove_all(root_, error);
        }
    }

    fixture(const fixture&) = delete;
    fixture& operator=(const fixture&) = delete;

    [[nodiscard]] const std::string& root() const
    {
        return root_;
    }

    [[nodiscard]] std::string file(std::string_view leaf)
    {
        if (root_.empty() || leaf.empty() || leaf.find("..") != std::string_view::npos)
        {
            return {};
        }
        const auto path = root_ + "/" + std::string(leaf);
        std::error_code error;
        std::filesystem::create_directories(std::filesystem::path(path).parent_path(), error);
        if (error)
        {
            return {};
        }
        std::ofstream output(path, std::ios::binary);
        output << "original_payload_must_not_be_overwritten";
        return output.good() ? path : std::string{};
    }

private:
    std::string root_;
};

[[nodiscard]] std::string identity(const struct stat& attributes)
{
    return std::to_string(attributes.st_dev) + ":" + std::to_string(attributes.st_ino);
}

[[nodiscard]] bool exists(const std::string& path)
{
    struct stat attributes{};
    return lstat(path.c_str(), &attributes) == 0;
}

[[nodiscard]] std::string contents(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

class posix_backend final : public quick::backend
{
public:
    std::vector<std::string> removals;

    explicit posix_backend(std::string root) : root_(std::move(root))
    {
    }

    engine::result<std::vector<quick::target>> prepare(const std::vector<std::string>& paths,
        engine::control&) override
    {
        std::vector<quick::target> targets;
        for (const auto& path : paths)
        {
            quick::target target;
            target.path = path;
            const auto parent = parent_descriptor(path);
            if (!parent)
            {
                target.preparation_error = parent.error();
                targets.push_back(std::move(target));
                continue;
            }
            descriptor held(*parent);
            struct stat attributes{};
            const auto leaf = std::filesystem::path(path).filename().string();
            if (fstatat(held.get(), leaf.c_str(), &attributes, AT_SYMLINK_NOFOLLOW) != 0 ||
                S_ISLNK(attributes.st_mode))
            {
                target.preparation_error = {"fixture_unbound_or_symlink", 0, false};
            }
            else
            {
                target.identity = identity(attributes);
                target.device_key = std::to_string(attributes.st_dev);
                target.directory = S_ISDIR(attributes.st_mode);
            }
            targets.push_back(std::move(target));
        }
        return targets;
    }

    engine::result<void> begin_execution() override
    {
        return {};
    }

    engine::result<quick::resource_sample> inspect_resources(
        std::span<const std::string_view> device_keys) override
    {
        // TEST INPUT: Explicit fixture resource budget; this does not probe or
        // claim Windows host-resource behavior.
        quick::resource_sample sample;
        sample.available_memory_bytes = 512ULL * 1024 * 1024;
        sample.available_commit_bytes = 512ULL * 1024 * 1024;
        sample.available_handles = 1024;
        sample.logical_processors = 2;
        sample.cpu_pressure_known = true;
        for (const auto key : device_keys)
        {
            sample.devices.push_back({std::string(key), std::string(key), 2, 0, true});
        }
        return sample;
    }

    engine::result<void> remove(const quick::target& value, bool) override
    {
        const auto parent = parent_descriptor(value.path);
        if (!parent)
        {
            return std::unexpected(parent.error());
        }
        descriptor held(*parent);
        struct stat attributes{};
        const auto leaf = std::filesystem::path(value.path).filename().string();
        if (fstatat(held.get(), leaf.c_str(), &attributes, AT_SYMLINK_NOFOLLOW) != 0 ||
            S_ISLNK(attributes.st_mode) || identity(attributes) != value.identity ||
            static_cast<bool>(S_ISDIR(attributes.st_mode)) != value.directory)
        {
            return std::unexpected(engine::error{"quick_frozen_identity_changed", 0, false});
        }
        removals.push_back(value.path);
        // TEST LIMITATION: No adversarial actor runs inside this private fixture.
        // POSIX lacks the Windows backend's handle-bound disposition contract.
        if (unlinkat(held.get(), leaf.c_str(), value.directory ? AT_REMOVEDIR : 0) != 0)
        {
            return std::unexpected(engine::error{"quick_disposition_failed",
                errno == ENOTEMPTY ? 145U : 0U, false});
        }
        return {};
    }

    engine::result<std::vector<engine::locking_process>> query_locks(const quick::target&) override
    {
        return std::unexpected(engine::error{"fixture_unexpected_lock_query", 0, false});
    }

    engine::result<void> close_process(const quick::target&, const engine::locking_process&, bool) override
    {
        return std::unexpected(engine::error{"fixture_forbidden_process_close", 0, false});
    }

private:
    [[nodiscard]] engine::result<int> parent_descriptor(const std::string& path)
    {
        if (root_.empty() || !path.starts_with(root_ + "/"))
        {
            return std::unexpected(engine::error{"fixture_outside_scope", 0, false});
        }
        const auto relative = std::filesystem::path(path.substr(root_.size() + 1));
        if (relative.empty() || relative.is_absolute())
        {
            return std::unexpected(engine::error{"fixture_invalid_relative_path", 0, false});
        }
        auto parent = open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (parent < 0)
        {
            return std::unexpected(engine::error{"fixture_root_open_failed", 0, false});
        }
        for (const auto& component : relative.parent_path())
        {
            if (component == ".." || component == ".")
            {
                static_cast<void>(close(parent));
                return std::unexpected(engine::error{"fixture_dot_component_rejected", 0, false});
            }
            const auto next = openat(parent, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            static_cast<void>(close(parent));
            if (next < 0)
            {
                return std::unexpected(engine::error{"fixture_ancestor_rejected", 0, false});
            }
            parent = next;
        }
        return parent;
    }

    std::string root_;
};

[[nodiscard]] quick::plan prepare(posix_backend& host, const std::vector<std::string>& paths)
{
    engine::control control;
    return quick::freeze("1123456789abcdef0123456789abcdef", host.prepare(paths, control).value()).value();
}

[[nodiscard]] engine::run_report execute(const quick::plan& plan, posix_backend& host,
    engine::control& control, quick::progress_observer observer = {},
    const engine::run_report* previous = nullptr)
{
    return quick::run(plan, plan.fingerprint, true, host, control, {1, true}, std::move(observer), previous).value();
}
}

int main()
{
    totals results;
    {
        fixture tree;
        const auto original = tree.file("a");
        const auto selected_alias = tree.root() + "/b";
        const auto retained_alias = tree.root() + "/retained";
        results.check(!original.empty() && link(original.c_str(), selected_alias.c_str()) == 0 &&
            link(original.c_str(), retained_alias.c_str()) == 0, "fixture_hardlinks_created");
        descriptor opened(open(original.c_str(), O_RDONLY | O_NOFOLLOW));
        posix_backend host(tree.root());
        const auto plan = prepare(host, {original, selected_alias});
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report.status == "completed" && !exists(original) && !exists(selected_alias),
            "actual_selected_hardlink_names_removed");
        results.check(contents(retained_alias) == "original_payload_must_not_be_overwritten",
            "unselected_hardlink_payload_untouched");
        std::array<char, 64> buffer{};
        const auto read_bytes = ::read(opened.get(), buffer.data(), buffer.size());
        results.check(read_bytes > 0 && std::string_view(buffer.data(), static_cast<std::size_t>(read_bytes)) ==
            "original_payload_must_not_be_overwritten", "open_handle_retains_original_payload_without_overwrite");
        results.check(std::all_of(report.targets.begin(), report.targets.end(), [](const auto& outcome)
        {
            return outcome.deleted && !outcome.logical_overwrite_verified &&
                !outcome.physical_sanitization_guaranteed;
        }), "actual_namespace_removal_has_no_sanitization_claim");
    }
    {
        fixture tree;
        const auto original = tree.file("original");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {original});
        const auto parked = tree.root() + "/parked";
        results.check(rename(original.c_str(), parked.c_str()) == 0 && tree.file("original") == original,
            "fixture_replacement_created");
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report.status == "partial_failure" && !report.targets.front().deleted &&
            exists(original) && exists(parked), "actual_replacement_preserved");
    }
    {
        fixture tree;
        const auto original = tree.file("real/data");
        const auto symbolic = tree.root() + "/symbolic";
        const auto ancestor = tree.root() + "/ancestor";
        results.check(symlink(original.c_str(), symbolic.c_str()) == 0 &&
            symlink((tree.root() + "/real").c_str(), ancestor.c_str()) == 0,
            "fixture_symbolic_links_created");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {symbolic, ancestor + "/data"});
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report.status == "partial_failure" && exists(symbolic) && exists(original),
            "actual_leaf_and_ancestor_symlinks_not_followed");
    }
    {
        fixture tree;
        const auto child = tree.file("directory/sub/file");
        const auto sibling = tree.file("sibling");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {tree.root() + "/directory", tree.root() + "/directory/sub", child});
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report.status == "completed" && !exists(child) && !exists(tree.root() + "/directory"),
            "actual_nested_directories_removed_child_first");
        results.check(contents(sibling) == "original_payload_must_not_be_overwritten",
            "unselected_sibling_remains_unchanged");
    }
    {
        fixture tree;
        const auto child = tree.file("directory/file");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {tree.root() + "/directory", child});
        const auto late = tree.file("directory/new_after_preview");
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report.status == "partial_failure" && !exists(child) && exists(late) &&
            exists(tree.root() + "/directory"), "actual_new_child_preserved_and_parent_retained");
    }
    {
        fixture tree;
        const auto valid = tree.file("valid");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {tree.root() + "/absent", valid});
        engine::control control;
        const auto report = execute(plan, host, control);
        results.check(report.status == "partial_failure" && !exists(valid) && report.targets.size() == 2,
            "actual_partial_preparation_keeps_valid_target_work");
    }
    {
        fixture tree;
        const auto first = tree.file("a");
        const auto second = tree.file("b");
        const auto third = tree.file("c");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {first, second, third});
        engine::control control;
        const auto paused = execute(plan, host, control, [&](const auto& update)
        {
            if (update.completed == 1)
            {
                control.request.store(engine::control_request::pause);
            }
        });
        results.check(paused.status == "paused" && !exists(first) && exists(second) && exists(third),
            "actual_pause_preserves_unattempted_names");
        control.request.store(engine::control_request::proceed);
        const auto resumed = execute(plan, host, control, {}, &paused);
        results.check(resumed.status == "completed" && !exists(second) && !exists(third),
            "actual_same_plan_resume_deletes_remaining_names");
    }
    {
        fixture tree;
        const auto child = tree.file("a/file");
        const auto unrelated = tree.file("z");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {tree.root() + "/a", child, unrelated});
        engine::control control;
        const auto sealed = quick::admit(plan);
        const auto report = quick::run(*sealed, plan.fingerprint, true, host, control, {1, true});
        results.check(report && report->status == "completed" && host.removals ==
            std::vector<std::string>{child, tree.root() + "/a", unrelated},
            "actual_ready_subtree_removed_before_unrelated_file_with_sealed_plan");
    }
    {
        fixture tree;
        const auto first = tree.file("a");
        const auto second = tree.file("b");
        posix_backend host(tree.root());
        const auto plan = prepare(host, {first, second});
        engine::control control;
        const auto report = quick::run(plan, plan.fingerprint, true, host, control, {0, true, true, 1024});
        results.check(!report && exists(first) && exists(second) && host.removals.empty(),
            "actual_complete_batch_resource_refusal_preserves_every_name");
    }
    std::cout << "{\"summary\":true,\"total\":" << results.total <<
        ",\"passed\":" << results.passed << ",\"failed\":" << results.total - results.passed <<
        ",\"scope\":\"isolated_posix_quick_backend_not_windows\"}\n";
    return results.total == results.passed ? 0 : 1;
}
