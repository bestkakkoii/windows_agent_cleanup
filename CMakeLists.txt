cmake_minimum_required(VERSION 4.5)
# CONTRACT: CMake 4.5 supports automatic vendor import std. No experimental
# UUID, generated standard module, or compatibility provider is injected.
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "")
set(CMAKE_TRY_COMPILE_CONFIGURATION "Release")
option(SECURE_ERASE_PORTABLE_TEST_ONLY "Build the actual named modules and portable tests only" OFF)
option(secure_erase_enable_destructive_tests "Register isolated Windows destructive tests" OFF)
set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Release only" FORCE)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Release only" FORCE)
elseif(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "secure_erase.configuration_rejected: Release is required")
endif()
if(NOT CMAKE_GENERATOR MATCHES "^(Ninja|Ninja Multi-Config)$")
    message(FATAL_ERROR "secure_erase.generator_rejected: native import std requires Ninja")
endif()
# Native CMake compiler detection precedes target options. Initialize UTF-8 here
# so compiler checks and the vendor std provider share the product policy.
# Resource scripts use their own code_page pragma; never pass /utf-8 to rc.exe.
function(secure_erase_reject_charset_flags)
    foreach(flag_variable IN ITEMS CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_INIT
        CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE_INIT)
        string(TOLOWER "${${flag_variable}}" reviewed_flags)
        if(reviewed_flags MATCHES "(^|[ \t])[-/](source-charset|execution-charset)(:|[ =])" OR
           reviewed_flags MATCHES "(^|[ \t])[-/](utf-8-|validate-charset-)([ \t]|$)")
            message(FATAL_ERROR "secure_erase.charset_flags_rejected: ${flag_variable}; UTF-8 is mandatory")
        endif()
    endforeach()
endfunction()
if(CMAKE_HOST_WIN32)
    foreach(environment_variable IN ITEMS CL _CL_ LINK CFLAGS CXXFLAGS RCFLAGS)
        if(DEFINED ENV{${environment_variable}} AND NOT "$ENV{${environment_variable}}" STREQUAL "")
            message(FATAL_ERROR "secure_erase.external_flags_rejected: ${environment_variable}; clear it before configuring")
        endif()
    endforeach()
    secure_erase_reject_charset_flags()
    string(APPEND CMAKE_CXX_FLAGS_INIT " /utf-8")
    if(DEFINED CMAKE_CXX_FLAGS)
        string(APPEND CMAKE_CXX_FLAGS " /utf-8")
    endif()
endif()
project(windows_agent_cleanup VERSION 2.0.0 LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# One configured source identity owns native module and PE string metadata.
# A source archive without Git remains explicitly unknown; no release binding
# or reproducibility attestation is inferred from a commit-shaped label.
set(secure_erase_application_version "${PROJECT_VERSION}-dev.1")
set(secure_erase_numeric_version "${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},1")
set(secure_erase_source_commit "unknown")
set(secure_erase_source_commit_known 0)
set(secure_erase_source_dirty 1)
set(secure_erase_source_dirty_known 0)
find_package(Git QUIET)
if(Git_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE secure_erase_git_status OUTPUT_VARIABLE secure_erase_git_commit
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(secure_erase_git_status EQUAL 0 AND secure_erase_git_commit MATCHES "^[0-9a-f]+$")
        string(LENGTH "${secure_erase_git_commit}" secure_erase_commit_length)
        if(secure_erase_commit_length EQUAL 40)
            set(secure_erase_source_commit "${secure_erase_git_commit}")
            set(secure_erase_source_commit_known 1)
            execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=normal
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" RESULT_VARIABLE secure_erase_dirty_status
                OUTPUT_VARIABLE secure_erase_dirty_output ERROR_QUIET)
            if(secure_erase_dirty_status EQUAL 0)
                set(secure_erase_source_dirty_known 1)
                if(secure_erase_dirty_output STREQUAL "")
                    set(secure_erase_source_dirty 0)
                endif()
            endif()
        endif()
    endif()
endif()
set(secure_erase_build_identity "${secure_erase_application_version}/${secure_erase_source_commit}/dirty=${secure_erase_source_dirty}/known=${secure_erase_source_dirty_known}/${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION}")

if(MSVC)
    if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR MSVC_VERSION LESS 1936)
        message(FATAL_ERROR "secure_erase.platform_rejected: x64 MSVC >=19.36 with the installed std module is required")
    endif()
    # Select the highest standard metadata which CMake actually maps to latest.
    # Current upstream MSVC metadata is 23; this denotes /std:c++latest, not a
    # forced C++23 mode. Accept future native metadata without inventing flags.
    if(DEFINED CMAKE_CXX26_STANDARD_COMPILE_OPTION AND
       CMAKE_CXX26_STANDARD_COMPILE_OPTION MATCHES "std:c[+][+]latest")
        set(secure_erase_cxx_standard 26)
    elseif(CMAKE_CXX23_STANDARD_COMPILE_OPTION MATCHES "std:c[+][+]latest")
        set(secure_erase_cxx_standard 23)
    else()
        message(FATAL_ERROR "secure_erase.latest_mode_unavailable: current MSVC/CMake must provide /std:c++latest")
    endif()
    if(NOT SECURE_ERASE_PORTABLE_TEST_ONLY)
        # Keep every generated archive path prefixed by a directory. On MSVC,
        # a bare @cmake_cxx_std.lib is consumed by vs_link_exe as a response file.
        # Initialize archive targets with a directory so the real vendor archive
        # cannot begin with @ at the command boundary. Preserve the native std provider.
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
    endif()
    foreach(flag_variable IN ITEMS CMAKE_CXX_FLAGS CMAKE_EXE_LINKER_FLAGS)
        if("${${flag_variable}}" MATCHES "([/-](Zi|ZI|Z7|RTC[^ ]*|DEBUG(:FULL|:FASTLINK)?)( |$))")
            message(FATAL_ERROR "secure_erase.debug_flags_rejected: ${flag_variable}")
        endif()
    endforeach()
    secure_erase_reject_charset_flags()
    # Existing caches do not reinitialize *_FLAGS from *_FLAGS_INIT. Apply the
    # global policy on every configure; try_compile and vendor std BMIs inherit it.
    string(APPEND CMAKE_CXX_FLAGS " /utf-8")
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG" CACHE STRING "Reviewed release flags" FORCE)
elseif(SECURE_ERASE_PORTABLE_TEST_ONLY AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"
       AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 21
       AND CMAKE_CXX_STDLIB_MODULES_JSON MATCHES "libc[+][+][.]modules[.]json$")
    set(secure_erase_cxx_standard 26)
else()
    message(FATAL_ERROR "secure_erase.compiler_rejected: production requires MSVC; portable tests require Clang >=21 and libc++ with native import std")
endif()
if(NOT CMAKE_CXX_STDLIB_MODULES_JSON OR NOT EXISTS "${CMAKE_CXX_STDLIB_MODULES_JSON}")
    message(FATAL_ERROR "secure_erase.std_module_unavailable: ${CMAKE_CXX_COMPILER_IMPORT_STD_ERROR_MESSAGE}")
endif()
string(ASCII 239 187 191 secure_erase_utf8_bom)
try_compile(secure_erase_import_std_works
    SOURCE_FROM_CONTENT import_std_probe.cpp
        "${secure_erase_utf8_bom}import std;\nstatic_assert(sizeof(\"é中\") == 6);\nstatic_assert(static_cast<unsigned char>(\"é中\"[0]) == 0xc3 && static_cast<unsigned char>(\"é中\"[1]) == 0xa9 && static_cast<unsigned char>(\"é中\"[2]) == 0xe4 && static_cast<unsigned char>(\"é中\"[3]) == 0xb8 && static_cast<unsigned char>(\"é中\"[4]) == 0xad);\nstatic_assert(L\"é中\"[0] == 0x00e9 && L\"é中\"[1] == 0x4e2d);\nint main() { std::expected<std::vector<int>, int> value{std::vector<int>{1}}; return value->front() - 1; }\n"
    CXX_STANDARD ${secure_erase_cxx_standard} CXX_STANDARD_REQUIRED ON
    OUTPUT_VARIABLE secure_erase_import_std_diagnostics)
if(NOT secure_erase_import_std_works)
    message(FATAL_ERROR "secure_erase.std_module_probe_failed: ${secure_erase_import_std_diagnostics}")
endif()
if(NOT SECURE_ERASE_PORTABLE_TEST_ONLY AND NOT MSVC)
    message(FATAL_ERROR "secure_erase.platform_rejected: production requires Windows MSVC")
endif()

function(secure_erase_configure_target target)
    set_target_properties(${target} PROPERTIES CXX_STANDARD ${secure_erase_cxx_standard}
        CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF CXX_SCAN_FOR_MODULES ON)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus;/utf-8;/W4;/WX;/permissive-;/EHsc;/GS;/guard:cf;/O2;/Ob3;/GL;/Gy;/Gw;/GF>")
        target_compile_definitions(${target} PRIVATE NDEBUG)
        target_link_options(${target} PRIVATE /LTCG /INCREMENTAL:NO /OPT:REF /OPT:ICF
            /DEBUG:NONE /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT)
        set_target_properties(${target} PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded
            MSVC_DEBUG_INFORMATION_FORMAT "")
    else()
        # CMake's per-consumer std BMI inherits warnings. The vendor module must
        # be allowed to use its standard-reserved name; retain all other errors.
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror
            -Wno-reserved-module-identifier)
    endif()
endfunction()

function(secure_erase_embed_manifest target execution_level manifest_path)
    get_target_property(target_type ${target} TYPE)
    if(NOT MSVC OR NOT target_type STREQUAL "EXECUTABLE")
        message(FATAL_ERROR "secure_erase.manifest_target_rejected: ${target}")
    endif()
    file(READ "${CMAKE_SOURCE_DIR}/${manifest_path}" secure_erase_manifest_text)
    string(REGEX MATCH "assemblyIdentity version=\"([^\"]+)\"" secure_erase_manifest_identity "${secure_erase_manifest_text}")
    if(NOT CMAKE_MATCH_1 STREQUAL "${PROJECT_VERSION}.1")
        message(FATAL_ERROR "secure_erase.manifest_version_mismatch: ${manifest_path}; expected ${PROJECT_VERSION}.1")
    endif()
    # Keep the complete application manifest and align the linker's generated
    # UAC fragment with it. The entire fragment must remain one linker argument.
    target_sources(${target} PRIVATE "${manifest_path}")
    target_link_options(${target} PRIVATE
        "/MANIFESTUAC:level='${execution_level}' uiAccess='false'")
endfunction()

find_package(Threads REQUIRED)
add_library(secure_erase_engine STATIC src/core/crypto.cpp src/core/plan.cpp src/core/engine.cpp
    src/core/codec.cpp src/core/quick_delete.cpp src/core/quick_store.cpp
    src/app/cli_arguments.cpp src/app/agent_protocol.cpp)
target_sources(secure_erase_engine PUBLIC FILE_SET public_modules TYPE CXX_MODULES FILES
    src/modules/model.ixx src/modules/configuration.ixx src/modules/platform.ixx
    src/modules/crypto.ixx src/modules/plan.ixx src/modules/engine.ixx src/modules/codec.ixx src/modules/quick_delete.ixx
    src/modules/quick_feedback.ixx
    src/modules/cli_arguments.ixx src/modules/agent_protocol.ixx src/modules/metadata.ixx
    src/modules/quick_store.ixx)
target_sources(secure_erase_engine PRIVATE FILE_SET implementation_partitions TYPE CXX_MODULES FILES
    src/core/engine_admission.cpp src/core/engine_execution.cpp)
target_link_libraries(secure_erase_engine PUBLIC Threads::Threads)
secure_erase_configure_target(secure_erase_engine)
target_compile_definitions(secure_erase_engine PRIVATE
    SECURE_ERASE_APPLICATION_VERSION="${secure_erase_application_version}"
    SECURE_ERASE_SOURCE_COMMIT="${secure_erase_source_commit}"
    SECURE_ERASE_SOURCE_COMMIT_KNOWN=${secure_erase_source_commit_known}
    SECURE_ERASE_SOURCE_DIRTY=${secure_erase_source_dirty}
    SECURE_ERASE_SOURCE_DIRTY_KNOWN=${secure_erase_source_dirty_known}
    SECURE_ERASE_BUILD_IDENTITY="${secure_erase_build_identity}")
add_library(secure_erase_core ALIAS secure_erase_engine)

enable_testing()
foreach(test_name IN ITEMS crypto engine codec cli_arguments agent_protocol quick_delete quick_store)
    add_executable(secure_erase_${test_name}_tests tests/${test_name}_tests.cpp)
    target_link_libraries(secure_erase_${test_name}_tests PRIVATE secure_erase_engine)
    secure_erase_configure_target(secure_erase_${test_name}_tests)
    add_test(NAME ${test_name}_behavior COMMAND secure_erase_${test_name}_tests)
    set_tests_properties(${test_name}_behavior PROPERTIES LABELS "safe;portable;modules" TIMEOUT 120)
endforeach()
if(UNIX AND SECURE_ERASE_PORTABLE_TEST_ONLY)
    foreach(test_name IN ITEMS portable_integration quick_delete_integration)
        add_executable(secure_erase_${test_name}_tests tests/${test_name}_tests.cpp)
        target_link_libraries(secure_erase_${test_name}_tests PRIVATE secure_erase_engine)
        secure_erase_configure_target(secure_erase_${test_name}_tests)
        add_test(NAME ${test_name}_isolated COMMAND secure_erase_${test_name}_tests)
        set_tests_properties(${test_name}_isolated PROPERTIES LABELS "safe;portable;isolated;modules" TIMEOUT 120)
    endforeach()
endif()

if(SECURE_ERASE_PORTABLE_TEST_ONLY)
    # Compile the actual native-facing public modules as an API boundary check.
    # Their WinAPI implementation units are intentionally not part of this target.
    add_library(secure_erase_native_interfaces STATIC src/app/application_diagnostics.cpp)
    target_sources(secure_erase_native_interfaces PUBLIC FILE_SET public_modules TYPE CXX_MODULES FILES
        src/modules/windows_backend.ixx src/modules/state_store.ixx
        src/modules/retained_copies.ixx src/modules/application.ixx)
    target_link_libraries(secure_erase_native_interfaces PUBLIC secure_erase_engine)
    secure_erase_configure_target(secure_erase_native_interfaces)
    add_executable(secure_erase_module_interface_tests tests/module_interface_tests.cpp)
    target_link_libraries(secure_erase_module_interface_tests PRIVATE secure_erase_native_interfaces)
    secure_erase_configure_target(secure_erase_module_interface_tests)
    add_test(NAME module_interface_contract COMMAND secure_erase_module_interface_tests)
    set_tests_properties(module_interface_contract PROPERTIES LABELS "safe;portable;modules;interface_only" TIMEOUT 30)
endif()

include(cmake/verify_dependencies.cmake)
secure_erase_verify_dependencies()

if(NOT SECURE_ERASE_PORTABLE_TEST_ONLY)
    enable_language(RC)
    add_library(secure_erase_windows STATIC src/windows/windows_backend.cpp
        src/windows/backend_locks.cpp src/windows/state_store.cpp src/windows/retained_copies.cpp)
    target_sources(secure_erase_windows PUBLIC FILE_SET public_modules TYPE CXX_MODULES FILES
        src/modules/windows_backend.ixx src/modules/state_store.ixx src/modules/retained_copies.ixx)
    target_compile_definitions(secure_erase_windows PUBLIC UNICODE _UNICODE NOMINMAX
        WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A00000B)
    target_link_libraries(secure_erase_windows PUBLIC secure_erase_engine
        kernel32 advapi32 bcrypt crypt32 rstrtmgr user32 shell32 sfc ole32 vssapi pdh)
    secure_erase_configure_target(secure_erase_windows)

    add_library(secure_erase_application STATIC src/app/application.cpp src/app/application_diagnostics.cpp)
    target_sources(secure_erase_application PUBLIC FILE_SET public_modules TYPE CXX_MODULES FILES
        src/modules/application.ixx)
    target_link_libraries(secure_erase_application PUBLIC secure_erase_windows)
    secure_erase_configure_target(secure_erase_application)

    add_library(secure_erase_imgui STATIC ${secure_erase_imgui_directory}/imgui.cpp
        ${secure_erase_imgui_directory}/imgui_draw.cpp ${secure_erase_imgui_directory}/imgui_tables.cpp
        ${secure_erase_imgui_directory}/imgui_widgets.cpp ${secure_erase_imgui_directory}/backends/imgui_impl_win32.cpp
        ${secure_erase_imgui_directory}/backends/imgui_impl_dx11.cpp)
    target_include_directories(secure_erase_imgui SYSTEM PUBLIC ${secure_erase_imgui_directory} ${secure_erase_imgui_directory}/backends)
    target_compile_definitions(secure_erase_imgui PRIVATE UNICODE _UNICODE NOMINMAX
        WIN32_LEAN_AND_MEAN IMGUI_DISABLE_DEBUG_TOOLS NDEBUG)
    set_target_properties(secure_erase_imgui PROPERTIES CXX_STANDARD ${secure_erase_cxx_standard}
        CXX_STANDARD_REQUIRED ON CXX_SCAN_FOR_MODULES OFF
        MSVC_RUNTIME_LIBRARY MultiThreaded MSVC_DEBUG_INFORMATION_FORMAT "")
    # Upstream sources remain byte-identical. Only this third-party boundary uses headers.
    target_compile_options(secure_erase_imgui PRIVATE /utf-8 /W3 /EHsc /O2 /GL /GS /guard:cf)
    target_link_libraries(secure_erase_imgui PUBLIC d3d11 dxgi d3dcompiler dwmapi imm32)

    add_executable(secure_erase_cli src/cli/main.cpp src/windows/app_icon.rc)
    target_link_libraries(secure_erase_cli PRIVATE secure_erase_application)
    target_include_directories(secure_erase_cli PRIVATE assets)
    target_compile_definitions(secure_erase_cli PRIVATE
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_RESOURCE_VERSION=${secure_erase_numeric_version}>"
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_APPLICATION_VERSION=\"${secure_erase_application_version}\">"
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_BUILD_IDENTITY=\"${secure_erase_build_identity}\">"
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_ORIGINAL_FILENAME=\"secure_erase_cli.exe\">")
    secure_erase_configure_target(secure_erase_cli)
    secure_erase_embed_manifest(secure_erase_cli asInvoker src/windows/agent.manifest)
    add_executable(secure_erase_gui WIN32 src/gui/main.cpp src/windows/app_icon.rc)
    target_link_libraries(secure_erase_gui PRIVATE secure_erase_application secure_erase_imgui
        d3d11 dxgi shell32 ole32 uuid user32 comdlg32)
    target_include_directories(secure_erase_gui PRIVATE assets)
    target_compile_definitions(secure_erase_gui PRIVATE
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_RESOURCE_VERSION=${secure_erase_numeric_version}>"
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_APPLICATION_VERSION=\"${secure_erase_application_version}\">"
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_BUILD_IDENTITY=\"${secure_erase_build_identity}\">"
        "$<$<COMPILE_LANGUAGE:RC>:SECURE_ERASE_ORIGINAL_FILENAME=\"secure_erase_gui.exe\">")
    secure_erase_configure_target(secure_erase_gui)
    secure_erase_embed_manifest(secure_erase_gui requireAdministrator src/windows/application.manifest)

    add_test(NAME build_script_helpers COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
        -File ${CMAKE_SOURCE_DIR}/tests/build_script_tests.ps1)
    set_tests_properties(build_script_helpers PROPERTIES LABELS "safe;windows" TIMEOUT 30)
    add_test(NAME skill_install_helpers COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
        -File ${CMAKE_SOURCE_DIR}/tests/skill_install_tests.ps1)
    set_tests_properties(skill_install_helpers PROPERTIES LABELS "safe;windows" TIMEOUT 90)
    add_test(NAME cli_help COMMAND secure_erase_cli --help)
    set_tests_properties(cli_help PROPERTIES LABELS "safe;windows" TIMEOUT 30)
    if(secure_erase_enable_destructive_tests)
        add_test(NAME agent_cli_windows_isolated COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File ${CMAKE_SOURCE_DIR}/tests/agent_cli_windows_tests.ps1
            -cli $<TARGET_FILE:secure_erase_cli>)
        set_tests_properties(agent_cli_windows_isolated PROPERTIES LABELS "destructive;windows;agent"
            TIMEOUT 300 SKIP_RETURN_CODE 77)
        add_executable(secure_erase_windows_backend_tests tests/windows_backend_tests.cpp)
        target_link_libraries(secure_erase_windows_backend_tests PRIVATE secure_erase_windows)
        secure_erase_configure_target(secure_erase_windows_backend_tests)
        secure_erase_embed_manifest(secure_erase_windows_backend_tests requireAdministrator src/windows/application.manifest)
        add_test(NAME windows_backend_isolated COMMAND secure_erase_windows_backend_tests --run-isolated-fixtures)
        set_tests_properties(windows_backend_isolated PROPERTIES LABELS "destructive;windows" TIMEOUT 300 SKIP_RETURN_CODE 77)
        add_executable(secure_erase_state_store_windows_tests tests/state_store_windows_tests.cpp)
        target_link_libraries(secure_erase_state_store_windows_tests PRIVATE secure_erase_windows)
        secure_erase_configure_target(secure_erase_state_store_windows_tests)
        secure_erase_embed_manifest(secure_erase_state_store_windows_tests requireAdministrator src/windows/application.manifest)
        add_test(NAME state_store_windows_isolated COMMAND secure_erase_state_store_windows_tests --run-isolated-fixtures)
        set_tests_properties(state_store_windows_isolated PROPERTIES LABELS "destructive;windows;state" TIMEOUT 300)
        add_executable(secure_erase_quick_delete_windows_tests tests/quick_delete_windows_tests.cpp)
        target_link_libraries(secure_erase_quick_delete_windows_tests PRIVATE secure_erase_windows)
        secure_erase_configure_target(secure_erase_quick_delete_windows_tests)
        secure_erase_embed_manifest(secure_erase_quick_delete_windows_tests requireAdministrator src/windows/application.manifest)
        add_test(NAME quick_delete_windows_isolated COMMAND secure_erase_quick_delete_windows_tests --run-isolated-fixtures)
        set_tests_properties(quick_delete_windows_isolated PROPERTIES LABELS "destructive;windows;quick" TIMEOUT 300 SKIP_RETURN_CODE 77)
    endif()
endif()
add_executable(secure_erase_application_diagnostics_tests tests/application_diagnostics_tests.cpp)
if(SECURE_ERASE_PORTABLE_TEST_ONLY)
    target_link_libraries(secure_erase_application_diagnostics_tests PRIVATE secure_erase_native_interfaces)
else()
    target_link_libraries(secure_erase_application_diagnostics_tests PRIVATE secure_erase_application)
endif()
secure_erase_configure_target(secure_erase_application_diagnostics_tests)
add_test(NAME application_diagnostics_behavior COMMAND secure_erase_application_diagnostics_tests)
set_tests_properties(application_diagnostics_behavior PROPERTIES LABELS "safe;portable;modules" TIMEOUT 30)

message(STATUS "secure_erase.compiler=${CMAKE_CXX_COMPILER_ID}; version=${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "secure_erase.modules=native; std_provider=${CMAKE_CXX_STDLIB_MODULES_JSON}; capability_probe=${secure_erase_import_std_works}; selected_metadata=${secure_erase_cxx_standard}")
message(STATUS "secure_erase.validation=Windows compilation/runtime evidence remains owner supplied")
