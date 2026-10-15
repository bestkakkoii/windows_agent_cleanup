#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

import std;
import secure_erase.engine;

// CONTRACT: Test-only POSIX backend. No user-supplied path is accepted. Every
// mutation stays in a newly created mode-0700 directory owned by this process.
// Evidence covers portable engine behavior, never Windows APIs or physical media.
namespace
{
namespace model = secure_erase::engine;

model::error failure(std::string code)
{
    return {std::move(code), static_cast<std::uint32_t>(errno), false};
}

std::uint64_t tick(const timespec& time)
{
    return static_cast<std::uint64_t>(time.tv_sec) * 1000000000ULL +
        static_cast<std::uint64_t>(time.tv_nsec);
}

model::result<model::target_snapshot> observe(int file, const std::string& path)
{
    struct stat attributes{};
    if (fstat(file, &attributes) != 0)
    {
        return std::unexpected(failure("test_stat_failed"));
    }
    model::target_snapshot value;
    value.path = path;
    value.identity = std::to_string(attributes.st_dev) + ":" + std::to_string(attributes.st_ino);
    value.device_key = std::to_string(attributes.st_dev);
    value.write_time = tick(attributes.st_mtim);
    value.change_time = tick(attributes.st_ctim);
    value.link_count = static_cast<std::uint32_t>(attributes.st_nlink);
    value.media = model::media_kind::hdd;
    value.support = model::capability::overwrite_verified;
    value.streams.push_back({"", static_cast<std::uint64_t>(attributes.st_size)});
    return value;
}

class fixture
{
public:
    fixture()
    {
        std::array<char, 80> pattern{};
        constexpr char name[] = "/tmp/secure_erase_isolated_XXXXXX";
        std::copy(std::begin(name), std::end(name), pattern.begin());
        const auto path = mkdtemp(pattern.data());
        if (path != nullptr)
        {
            root_ = path;
        }
    }

    ~fixture()
    {
        for (const auto& path : files_)
        {
            static_cast<void>(unlink(path.c_str()));
        }
        if (!root_.empty())
        {
            static_cast<void>(rmdir(root_.c_str()));
        }
    }

    fixture(const fixture&) = delete;
    fixture& operator=(const fixture&) = delete;

    std::string create(const std::string& leaf, std::size_t size)
    {
        if (root_.empty() || leaf.find('/') != std::string::npos)
        {
            return {};
        }
        const auto path = root_ + "/" + leaf;
        files_.push_back(path);
        const int file = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
        if (file < 0)
        {
            return {};
        }
        std::array<std::byte, 4096> original{};
        original.fill(std::byte{0x5a});
        bool valid = true;
        while (size != 0)
        {
            const auto count = std::min(size, original.size());
            const auto done = write(file, original.data(), count);
            if (done <= 0)
            {
                valid = false;
                break;
            }
            size -= static_cast<std::size_t>(done);
        }
        valid = fsync(file) == 0 && valid;
        static_cast<void>(close(file));
        return valid ? path : std::string{};
    }

    std::string track(const std::string& leaf)
    {
        auto path = root_ + "/" + leaf;
        files_.push_back(path);
        return path;
    }

private:
    std::string root_;
    std::vector<std::string> files_;
};

struct observations
{
    std::uint64_t writes{};
    std::uint64_t reads{};
    std::uint64_t flushes{};
    std::uint64_t removes{};
    bool corrupt_after_flush{};
    bool fail_flush{};
};

class file_handle final : public model::target_handle
{
public:
    file_handle(int file, std::string path, observations& counters)
        : file_(file), path_(std::move(path)), counters_(counters)
    {
    }

    ~file_handle() override
    {
        static_cast<void>(close(file_));
    }

    model::result<model::target_snapshot> inspect() override
    {
        return observe(file_, path_);
    }

    model::result<std::size_t> read(std::string_view stream, std::uint64_t offset,
        std::span<std::byte> buffer) override
    {
        if (!stream.empty())
        {
            return std::unexpected(failure("test_stream_invalid"));
        }
        const auto count = pread(file_, buffer.data(), buffer.size(), static_cast<off_t>(offset));
        if (count < 0)
        {
            return std::unexpected(failure("test_read_failed"));
        }
        counters_.reads += static_cast<std::uint64_t>(count);
        return static_cast<std::size_t>(count);
    }

    model::result<std::size_t> write(std::string_view stream, std::uint64_t offset,
        std::span<const std::byte> buffer) override
    {
        if (!stream.empty())
        {
            return std::unexpected(failure("test_stream_invalid"));
        }
        const auto count = pwrite(file_, buffer.data(), buffer.size(), static_cast<off_t>(offset));
        if (count < 0)
        {
            return std::unexpected(failure("test_write_failed"));
        }
        counters_.writes += static_cast<std::uint64_t>(count);
        return static_cast<std::size_t>(count);
    }

    model::result<void> flush(std::string_view) override
    {
        ++counters_.flushes;
        if (counters_.fail_flush || fsync(file_) != 0)
        {
            return std::unexpected(failure("test_flush_failed"));
        }
        if (counters_.corrupt_after_flush)
        {
            counters_.corrupt_after_flush = false;
            std::byte byte{};
            if (pread(file_, &byte, 1, 0) != 1)
            {
                return std::unexpected(failure("test_corruption_read_failed"));
            }
            byte ^= std::byte{0xff};
            if (pwrite(file_, &byte, 1, 0) != 1 || fsync(file_) != 0)
            {
                return std::unexpected(failure("test_corruption_write_failed"));
            }
        }
        return {};
    }

    model::result<void> trim() override
    {
        return std::unexpected(failure("test_trim_not_supported"));
    }

    model::result<void> remove() override
    {
        ++counters_.removes;
        if (unlink(path_.c_str()) != 0)
        {
            return std::unexpected(failure("test_unlink_failed"));
        }
        return {};
    }

private:
    int file_;
    std::string path_;
    observations& counters_;
};

class host final : public model::platform
{
public:
    explicit host(observations& counters) : counters_(counters)
    {
    }

    bool is_elevated() const noexcept override
    {
        // CONTRACT: test authority only; production backend checks the Windows token.
        return true;
    }

    model::result<std::vector<model::target_snapshot>> preview(
        const std::vector<std::string>& paths) override
    {
        std::vector<model::target_snapshot> targets;
        for (const auto& path : paths)
        {
            const int file = open(path.c_str(), O_RDONLY | O_NOFOLLOW);
            if (file < 0)
            {
                return std::unexpected(failure("test_open_failed"));
            }
            auto item = observe(file, path);
            static_cast<void>(close(file));
            if (!item)
            {
                return std::unexpected(item.error());
            }
            targets.push_back(std::move(*item));
        }
        return targets;
    }

    model::result<std::unique_ptr<model::target_handle>> acquire(
        const model::target_snapshot& target) override
    {
        const int file = open(target.path.c_str(), O_RDWR | O_NOFOLLOW);
        if (file < 0)
        {
            return std::unexpected(failure("test_acquire_failed"));
        }
        if (flock(file, LOCK_EX | LOCK_NB) != 0)
        {
            static_cast<void>(close(file));
            return std::unexpected(failure("test_lock_failed"));
        }
        return std::unique_ptr<model::target_handle>(new file_handle(file, target.path, counters_));
    }

    model::result<void> random_bytes(std::span<std::byte> bytes) override
    {
        const int file = open("/dev/urandom", O_RDONLY);
        if (file < 0)
        {
            return std::unexpected(failure("test_entropy_failed"));
        }
        std::size_t offset{};
        while (offset < bytes.size())
        {
            const auto count = ::read(file, bytes.data() + offset, bytes.size() - offset);
            if (count <= 0)
            {
                static_cast<void>(close(file));
                return std::unexpected(failure("test_entropy_read_failed"));
            }
            offset += static_cast<std::size_t>(count);
        }
        static_cast<void>(close(file));
        return {};
    }

private:
    observations& counters_;
};

class memory_store final : public model::checkpoint_store
{
public:
    model::result<void> save(const model::checkpoint& value) override
    {
        current_ = value;
        return {};
    }

    model::result<model::checkpoint> load(std::string_view) override
    {
        if (!current_)
        {
            return std::unexpected(failure("test_missing_checkpoint"));
        }
        return *current_;
    }

    model::result<void> remove(std::string_view) override
    {
        current_.reset();
        return {};
    }

private:
    std::optional<model::checkpoint> current_;
};

class events final : public model::event_sink
{
public:
    model::result<void> emit(const model::event&) override
    {
        return {};
    }
};

struct totals
{
    std::size_t count{};
    std::size_t failed{};
};

void check(totals& result, const char* name, bool passed)
{
    ++result.count;
    result.failed += passed ? 0U : 1U;
    std::cout << "{\"test\":\"" << name << "\",\"passed\":" <<
        (passed ? "true" : "false") << "}\n";
}

void run_fixture(totals& checks, const char* mode)
{
    fixture files;
    const auto path = files.create("target.bin", 2 * 1024 * 1024 + 37);
    const auto sibling = files.create("unselected.bin", 19);
    check(checks, (std::string(mode) + "_fixture_created").c_str(), !path.empty() && !sibling.empty());
    if (path.empty() || sibling.empty())
    {
        return;
    }
    observations counters;
    counters.corrupt_after_flush = std::strcmp(mode, "corruption") == 0;
    counters.fail_flush = std::strcmp(mode, "flush_failure") == 0;
    host platform(counters);
    auto preview = platform.preview({path});
    if (!preview)
    {
        check(checks, "preview_fixture", false);
        return;
    }
    auto plan = model::freeze("00112233445566778899aabbccddeeff", std::move(*preview));
    if (!plan)
    {
        check(checks, "freeze_fixture", false);
        return;
    }
    const bool replacement = std::strcmp(mode, "replacement") == 0;
    if (replacement)
    {
        const auto retained = files.track("old_target.bin");
        check(checks, "replacement_rename_original", rename(path.c_str(), retained.c_str()) == 0);
        check(checks, "replacement_create_new", !files.create("target.bin", 91).empty());
    }
    model::approval consent{plan->fingerprint, true, {}};
    memory_store store;
    events output;
    model::control control;
    const auto outcome = model::run(*plan, consent, platform, store, output, control);
    const bool success = std::strcmp(mode, "success") == 0;
    const bool target_exists = access(path.c_str(), F_OK) == 0;
    bool deleted{};
    bool verified{};
    if (outcome && !outcome->targets.empty())
    {
        deleted = outcome->targets.front().deleted;
        verified = outcome->targets.front().logical_overwrite_verified;
    }
    const auto name = std::string(mode);
    if (outcome && !success)
    {
        std::cerr << "fixture=" << mode << " status=" << outcome->status;
        for (const auto& target : outcome->targets)
        {
            std::cerr << " code=" << target.code;
        }
        std::cerr << '\n';
    }
    check(checks, (name + "_namespace_result").c_str(), target_exists != success);
    check(checks, (name + "_delete_evidence").c_str(), deleted == success && counters.removes == (success ? 1U : 0U));
    check(checks, (name + "_verification_evidence").c_str(), verified == success);
    if (success)
    {
        check(checks, "real_full_write_and_read", counters.writes == 2 * 1024 * 1024 + 37 && counters.reads >= counters.writes && counters.flushes != 0);
    }
    if (replacement)
    {
        check(checks, "replacement_no_write", counters.writes == 0);
    }
    std::array<std::byte, 19> data{};
    const int untouched = open(sibling.c_str(), O_RDONLY | O_NOFOLLOW);
    const auto count = untouched >= 0 ? ::read(untouched, data.data(), data.size()) : -1;
    if (untouched >= 0)
    {
        static_cast<void>(close(untouched));
    }
    check(checks, (name + "_unselected_sibling_unchanged").c_str(), count == 19 &&
        std::all_of(data.begin(), data.end(), [](std::byte value) { return value == std::byte{0x5a}; }));
}
}

int main()
{
    totals result;
    for (const auto* scenario : {"success", "corruption", "flush_failure", "replacement"})
    {
        run_fixture(result, scenario);
    }
    std::cout << "{\"summary\":true,\"total\":" << result.count <<
        ",\"passed\":" << result.count - result.failed << ",\"failed\":" << result.failed <<
        ",\"scope\":\"isolated_posix_test_backend_not_windows\"}\n";
    return result.failed == 0 ? 0 : 1;
}
