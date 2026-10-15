import std;
import secure_erase.application;
import secure_erase.cli_arguments;
import secure_erase.retained_copies;
import secure_erase.metadata;
import secure_erase.quick_delete;

// CONTRACT: This compiles and imports the real Windows-facing interfaces only.
// No Windows implementation is linked or invoked; no native behavior is verified.
static_assert(std::derived_from<secure_erase::storage::state_store,
    secure_erase::engine::checkpoint_store>);
static_assert(std::derived_from<secure_erase::storage::state_store,
    secure_erase::engine::event_sink>);
static_assert(!std::copy_constructible<secure_erase::storage::state_store>);
static_assert(!std::copy_constructible<secure_erase::frontend::application>);
static_assert(std::same_as<decltype(secure_erase::frontend::view_state{}.locks),
    std::vector<secure_erase::engine::locking_process>>);
static_assert(std::same_as<decltype(secure_erase::cli::arguments{}.retention),
    secure_erase::storage::store_options>);
static_assert(std::same_as<decltype(secure_erase::windows::retained_copy_observation{}.native_error),
    std::uint32_t>);

static_assert(std::is_abstract_v<secure_erase::quick::backend>);
static_assert(std::same_as<decltype(secure_erase::quick::target{}.preparation_error),
    secure_erase::engine::error>);
static_assert(std::same_as<decltype(secure_erase::engine::make_windows_quick_backend(std::wstring_view{})),
    secure_erase::engine::result<std::unique_ptr<secure_erase::quick::backend>>>);
static_assert(std::same_as<decltype(secure_erase::quick::freeze(std::string{},
    std::vector<secure_erase::quick::target>{})),
    secure_erase::engine::result<secure_erase::quick::plan>>);

static_assert(std::same_as<decltype(secure_erase::quick::target{}.allocated_bytes),
    std::uint64_t>);
static_assert(secure_erase::quick::options{}.space_first);
static_assert(std::same_as<decltype(std::declval<secure_erase::quick::backend&>().sample_space(
    std::string_view{})), secure_erase::engine::result<secure_erase::quick::space_sample>>);
static_assert(std::same_as<decltype(secure_erase::frontend::view_state{}.quick_space),
    std::vector<secure_erase::quick::space_observation>>);

int main()
{
    std::cout << "{\"suite\":\"module_interfaces\",\"compile_assertions\":15,"
        "\"failed\":0,\"windows_implementation_executed\":false}\n";
}
