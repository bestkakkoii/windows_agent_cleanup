#requires -version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source_root = Split-Path -Parent $PSScriptRoot
$tokens = $null
$parse_errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $source_root 'scripts/build_windows.ps1'), [ref]$tokens, [ref]$parse_errors)
if ($parse_errors.Count -ne 0)
{
    throw 'build_script.syntax_failed'
}
# CONTRACT: Load reviewed evidence parsers and process logging helper only; never
# execute the build entrypoint. Child-process fixtures are confined to this test directory.
foreach ($helper_name in @('read_junit_evidence', 'read_tool_version', 'read_embedded_manifest', 'invoke_logged',
    'get_file_sha256', 'ensure_locked_tools', 'assert_no_external_build_flags', 'assert_owned_source_encoding',
    'invoke_test_suites'))
{
    $helper = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $helper_name
    }, $true)
    if ($null -eq $helper)
    {
        throw ('build_script.helper_missing:' + $helper_name)
    }
    . ([ScriptBlock]::Create($helper.Extent.Text))
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('secure_erase_build_tests_' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
$fixture = Join-Path $directory 'evidence.xml'
$utf8 = New-Object Text.UTF8Encoding($false)
$utf8_bom = New-Object Text.UTF8Encoding($true)
$checks = 0
$manifest_checks = 0
$hash_checks = 0
$bootstrap_checks = 0
$source_encoding_checks = 0
$test_flow_checks = 0
$native_charset_checks = 0
$native_charset_status = 'not_run_non_windows_host'
$hash_fixture = Join-Path $directory 'hash_[literal]_fixture.bin'
$log_directory = $directory
$capture_script = Join-Path $directory 'capture_manifest_arguments.ps1'
$capture_log = Join-Path $directory 'manifest_argument_capture.log'
$script:last_tool_exit = 0
$script:captured_tool_events = New-Object System.Collections.Generic.List[object]
function write_event([string]$event, [hashtable]$fields = @{})
{
    $script:captured_tool_events.Add([PSCustomObject]@{event=$event;fields=$fields})
}
function assert_manifest_argument_capture([object]$capture, [string[]]$expected_arguments)
{
    $reason = ''
    $observed_count = $null
    if ($capture -isnot [PSCustomObject] -or
        $null -eq $capture.PSObject.Properties['schema'] -or
        $null -eq $capture.PSObject.Properties['arguments'])
    {
        $reason = 'envelope'
    }
    elseif ($capture.schema -cne 'secure_erase.test.argv.v1' -or
        $capture.arguments -isnot [Array])
    {
        $reason = 'schema_or_array'
    }
    else
    {
        $observed_count = $capture.arguments.Count
        if ($observed_count -ne ($expected_arguments.Count + 1))
        {
            $reason = 'count'
        }
        else
        {
            for ($index = 0; $index -lt $observed_count; $index += 1)
            {
                if ($capture.arguments[$index] -isnot [string] -or
                    ($index -gt 0 -and $capture.arguments[$index] -cne $expected_arguments[$index - 1]))
                {
                    $reason = 'token_' + $index
                    break
                }
            }
        }
    }
    if ($reason.Length -ne 0)
    {
        # EVIDENCE: Preserve shape/count and all generated fixture arguments in
        # CTest output, even though finally removes the temporary capture log.
        $detail = @{reason=$reason;observed_count=$observed_count;
            expected_count=($expected_arguments.Count + 1);capture=$capture} | ConvertTo-Json -Compress -Depth 8
        throw ('build_script.manifest_native_capture_invalid:' + $detail)
    }
}
try
{
    $encoding_fixture = Join-Path $directory 'encoding fixture'
    [void][IO.Directory]::CreateDirectory((Join-Path $encoding_fixture 'src'))
    $encoding_source = Join-Path $encoding_fixture 'src/fixture.cpp'
    [IO.File]::WriteAllText((Join-Path $encoding_fixture 'CMakeLists.txt'), '# owned CMake source', $utf8_bom)
    $unicode_source = "import std;`n// é中" + ('a' * 8192)
    [IO.File]::WriteAllText($encoding_source, $unicode_source, $utf8_bom)
    $encoding_result = assert_owned_source_encoding $encoding_fixture
    if ($encoding_result.checked_files -ne 2 -or -not $encoding_result.strict_utf8)
    {
        throw 'build_script.valid_source_encoding_rejected'
    }
    $source_encoding_checks += 1
    foreach ($invalid in @(
        @{bytes=$utf8.GetBytes($unicode_source);error='build.source_bom_missing:'},
        @{bytes=([byte[]]@(239, 187, 191) + $utf8.GetBytes($unicode_source) + [byte[]]@(255));error='build.source_utf8_invalid:'}))
    {
        [IO.File]::WriteAllBytes($encoding_source, $invalid.bytes)
        $observed_error = ''
        try { $null = assert_owned_source_encoding $encoding_fixture }
        catch { $observed_error = $_.Exception.Message }
        if (-not $observed_error.StartsWith($invalid.error, [StringComparison]::Ordinal))
        {
            throw ('build_script.invalid_source_encoding_accepted:' + $observed_error)
        }
        $source_encoding_checks += 1
    }
    [IO.File]::WriteAllText($encoding_source, $unicode_source, $utf8_bom)
    # Cache/vendor bytes outside the maintained roots are deliberately excluded.
    [void][IO.Directory]::CreateDirectory((Join-Path $encoding_fixture 'build'))
    [IO.File]::WriteAllBytes((Join-Path $encoding_fixture 'build/upstream.cpp'), [byte[]]@(255))
    $encoding_result = assert_owned_source_encoding $encoding_fixture
    if ($encoding_result.checked_files -ne 2)
    {
        throw 'build_script.unmaintained_vendor_source_scanned'
    }
    $source_encoding_checks += 1
    $checks += $source_encoding_checks
    # REGRESSION: Exercise the unified build/test dispatcher with only native
    # execution replaced. Real JUnit parsing remains in the path; no test binary
    # is executed by these default/opt-in/privilege fixtures.
    $test_flow_checks = & {
        $log_directory = Join-Path $directory 'test flow fixture'
        [void][IO.Directory]::CreateDirectory($log_directory)
        $stages = New-Object Collections.Generic.List[object]
        $skip_stage = ''
        $fail_stage = ''
        function invoke_logged([string]$stage, [string]$executable, [string[]]$arguments)
        {
            $stages.Add([PSCustomObject]@{stage=$stage;arguments=$arguments})
            if ($stage -ceq $fail_stage)
            {
                throw 'tool.failed:test_flow_fixture:23'
            }
            $skipped_xml = if ($stage -ceq $skip_stage) { '<skipped/>' } else { '' }
            $xml = '<testsuite><testcase name="' + $stage + '">' + $skipped_xml + '</testcase></testsuite>'
            [IO.File]::WriteAllText($arguments[-1], $xml, $utf8)
        }
        $completed = 0
        foreach ($elevated in @($false, $true))
        {
            $stages.Clear()
            $result = invoke_test_suites $false $elevated 'fixture ctest.exe' 'fixture build'
            if ($stages.Count -ne 1 -or $stages[0].stage -cne 'safe_tests' -or '-LE' -cnotin $stages[0].arguments -or
                $result.safe.status -cne 'passed' -or $result.safe.cases -ne 1 -or
                $result.isolated.status -cne 'not_run' -or $result.isolated.reason -cne 'destructive_tests_not_enabled')
            {
                throw 'build_script.default_build_did_not_run_only_safe_suites'
            }
            $completed += 1
        }
        $stages.Clear()
        $observed_error = ''
        try { $null = invoke_test_suites $true $false 'fixture ctest.exe' 'fixture build' }
        catch { $observed_error = $_.Exception.Message }
        if ($stages.Count -ne 0 -or -not $observed_error.StartsWith('validation.administrator_required:', [StringComparison]::Ordinal) -or
            -not $observed_error.Contains('build_release.bat -enable_isolated_destructive_tests') -or
            -not $observed_error.Contains('tests were not started'))
        {
            throw 'build_script.isolated_fixture_elevation_gate_bypassed'
        }
        $completed += 1
        $result = invoke_test_suites $true $true 'fixture ctest.exe' 'fixture build'
        if ($stages.Count -ne 2 -or $stages[0].stage -cne 'safe_tests' -or $stages[1].stage -cne 'isolated_destructive_tests' -or
            '-L' -cnotin $stages[1].arguments -or $result.safe.status -cne 'passed' -or $result.isolated.status -cne 'passed')
        {
            throw 'build_script.opt_in_test_contract_changed'
        }
        $completed += 1
        foreach ($skipped_stage in @('safe_tests', 'isolated_destructive_tests'))
        {
            $stages.Clear()
            $skip_stage = $skipped_stage
            $result = invoke_test_suites $true $true 'fixture ctest.exe' 'fixture build'
            $evidence = if ($skipped_stage -ceq 'safe_tests') { $result.safe } else { $result.isolated }
            if ($evidence.status -cne 'not_run' -or $evidence.skipped -ne 1)
            {
                throw ('build_script.test_skip_falsely_passed:' + $skipped_stage)
            }
            $completed += 1
        }
        $skip_stage = ''
        foreach ($failed_stage in @('safe_tests', 'isolated_destructive_tests'))
        {
            $stages.Clear()
            $fail_stage = $failed_stage
            $observed_error = ''
            try { $null = invoke_test_suites $true $true 'fixture ctest.exe' 'fixture build' }
            catch { $observed_error = $_.Exception.Message }
            $expected_stages = if ($failed_stage -ceq 'safe_tests') { 1 } else { 2 }
            if ($observed_error -cne 'tool.failed:test_flow_fixture:23' -or $stages.Count -ne $expected_stages)
            {
                throw ('build_script.failed_test_suite_ignored:' + $failed_stage)
            }
            $completed += 1
        }
        return $completed
    }
    $checks += $test_flow_checks
    # REGRESSION: Execute the actual bootstrap planner against generated source
    # archives and stand-in compiler outputs. Capture both real configure argv;
    # this tests the compiler policy at its consumer and cache-admission boundary.
    # No network, downloaded source, or native compilation happens in this block.
    $bootstrap_evidence = & {
        $source_root = Join-Path $directory 'bootstrap fixture'
        [void][IO.Directory]::CreateDirectory($source_root)
        $compiler = Join-Path $source_root 'compiler.exe'
        [IO.File]::WriteAllText($compiler, 'fixture compiler identity', $utf8)
        $fixture_locks = @()
        foreach ($name in @('cmake', 'ninja'))
        {
            $commit = if ($name -eq 'cmake') { 'a' * 40 } else { 'b' * 40 }
            $repository = if ($name -eq 'cmake') { 'Kitware/CMake' } else { 'ninja-build/ninja' }
            $archive = Join-Path $source_root ($name + '.fixture')
            [IO.File]::WriteAllText($archive, $name + ':verified archive fixture', $utf8)
            $fixture_locks += [PSCustomObject]@{name=$name;commit=$commit;source_archive=[PSCustomObject]@{
                url=('https://codeload.github.com/' + $repository + '/tar.gz/' + $commit);
                sha256=(get_file_sha256 $archive);size=(Get-Item -LiteralPath $archive).Length}}
        }
        [IO.File]::WriteAllText((Join-Path $source_root 'dependencies.lock.json'),
            (@{tool_sources=$fixture_locks} | ConvertTo-Json -Depth 6), $utf8)
        $stages = New-Object Collections.Generic.List[object]
        function Invoke-WebRequest
        {
            param([switch]$UseBasicParsing, [string]$Uri, [string]$OutFile, [int]$TimeoutSec)
            $name = if ($Uri.Contains('Kitware/CMake')) { 'cmake' } else { 'ninja' }
            [IO.File]::Copy((Join-Path $source_root ($name + '.fixture')), $OutFile)
        }
        function write_event([string]$event, [hashtable]$fields = @{}) {}
        function find_on_path([string]$name) { return $null }
        function invoke_logged([string]$stage, [string]$executable, [string[]]$arguments)
        {
            $stages.Add([PSCustomObject]@{stage=$stage;arguments=$arguments})
            if ($stage -like 'bootstrap_extract_*')
            {
                $name = $stage.Substring('bootstrap_extract_'.Length)
                $entry = @($fixture_locks | Where-Object { $_.name -ceq $name })[0]
                $prefix = if ($name -eq 'cmake') { 'CMake-' } else { 'ninja-' }
                $extracted = Join-Path (Get-Location).Path ($prefix + $entry.commit)
                [void][IO.Directory]::CreateDirectory($extracted)
                [IO.File]::WriteAllText((Join-Path $extracted 'CMakeLists.txt'), 'fixture source', $utf8)
            }
            elseif ($stage -ceq 'bootstrap_build_ninja')
            {
                [void][IO.Directory]::CreateDirectory($arguments[1])
                [IO.File]::WriteAllText((Join-Path $arguments[1] 'ninja.exe'), 'fixture ninja', $utf8)
            }
            elseif ($stage -ceq 'bootstrap_build_cmake')
            {
                $binary_directory = Join-Path $arguments[1] 'bin'
                [void][IO.Directory]::CreateDirectory($binary_directory)
                foreach ($name in @('cmake.exe', 'ctest.exe', 'cmcldeps.exe'))
                {
                    [IO.File]::WriteAllText((Join-Path $binary_directory $name), 'fixture ' + $name, $utf8)
                }
            }
        }
        $parallel_jobs = 4
        $first = ensure_locked_tools (Join-Path $source_root 'installed cmake.exe') (Join-Path $source_root 'installed ninja.exe') $compiler '10.0.26100.0'
        $completed = 0
        $compile_flags = @{}
        foreach ($stage in @('bootstrap_configure_ninja', 'bootstrap_configure_cmake'))
        {
            $configuration = @($stages | Where-Object { $_.stage -ceq $stage })
            if ($configuration.Count -ne 1)
            {
                throw ('build_script.bootstrap_configure_missing:' + $stage)
            }
            foreach ($language in @('C', 'CXX'))
            {
                $prefix = '-DCMAKE_' + $language + '_FLAGS_INIT='
                $options = @($configuration[0].arguments | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
                if ($options.Count -ne 1 -or $options[0].Substring($prefix.Length) -cne '/utf-8')
                {
                    throw ('build_script.bootstrap_utf8_policy_missing:' + $stage + ':' + $language)
                }
                $compile_flags[$language] = $options[0].Substring($prefix.Length)
                $completed += 1
            }
            if (@($configuration[0].arguments | Where-Object { $_ -like '-DCMAKE_RC_FLAGS*' }).Count -ne 0)
            {
                throw 'build_script.bootstrap_cxx_options_leaked_to_resource_compiler'
            }
            $completed += 1
        }
        $receipt = Get-Content -LiteralPath (Join-Path $first.cache 'toolchain.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $old_identity = $fixture_locks[0].commit + ':' + $fixture_locks[1].commit + ':' +
            (get_file_sha256 $compiler) + ':10.0.26100.0'
        if ($receipt.identity -ceq $old_identity -or -not $receipt.identity.Contains('/utf-8'))
        {
            throw 'build_script.bootstrap_charset_missing_from_cache_identity'
        }
        $completed += 1
        $stages.Clear()
        $second = ensure_locked_tools (Join-Path $source_root 'installed cmake.exe') (Join-Path $source_root 'installed ninja.exe') $compiler '10.0.26100.0'
        if ($stages.Count -ne 0 -or $first.cache -cne $second.cache)
        {
            throw 'build_script.bootstrap_verified_utf8_cache_not_reused'
        }
        $completed += 1
        # Ambient flags are checked before even a verified receipt can return.
        foreach ($name in @('CL', '_CL_', 'LINK', 'CFLAGS', 'CXXFLAGS', 'RCFLAGS'))
        {
            $previous = [Environment]::GetEnvironmentVariable($name, 'Process')
            try
            {
                [Environment]::SetEnvironmentVariable($name, '/source-charset:.950', 'Process')
                $observed_error = ''
                try { $null = ensure_locked_tools 'fixture cmake.exe' 'fixture ninja.exe' $compiler '10.0.26100.0' }
                catch { $observed_error = $_.Exception.Message }
                if (-not $observed_error.StartsWith('build.external_flags_rejected:' + $name + ';', [StringComparison]::Ordinal) -or
                    $stages.Count -ne 0)
                {
                    throw ('build_script.bootstrap_ambient_flags_accepted:' + $name + ':' + $observed_error)
                }
                $completed += 1
            }
            finally
            {
                [Environment]::SetEnvironmentVariable($name, $previous, 'Process')
            }
        }
        return [PSCustomObject]@{checks=$completed;compile_flags=$compile_flags;fixture_directory=$source_root}
    }
    $bootstrap_checks = $bootstrap_evidence.checks
    $checks += $bootstrap_checks
    # Native regression recreates the offending UTF-8 quote at a // comment end.
    # Explicit CP950 reproduces the user's compiler input without changing the
    # machine locale. Then each captured C/C++ policy independently decodes the
    # same source as UTF-8; conflicting charset switches are never combined.
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    {
        $native_charset_status = 'not_run_compiler_unavailable'
        $native_compiler = Get-Command cl.exe -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $native_compiler)
        {
            $native_source = Join-Path $directory 'utf8_source.c'
            $native_object = Join-Path $directory 'utf8_source.obj'
            $native_log = Join-Path $directory 'utf8_source.log'
            $native_text = "// declaration ‘rand_s’`n#if defined(__MINGW32__)`ntypedef int fixture_mingw_branch;`n#endif`nint fixture_value(void) { return 7; }`n"
            [IO.File]::WriteAllText($native_source, $native_text, $utf8)
            $native_preference = $ErrorActionPreference
            try
            {
                # PS5.1 wraps native stderr as ErrorRecord even for expected
                # compiler failures. The native exit code is decisive here.
                $ErrorActionPreference = 'Continue'
                & $native_compiler.Source /nologo /c /TC /source-charset:.950 /MT /O2 ('/Fo' + $native_object) $native_source *> $native_log
                $native_exit_code = $LASTEXITCODE
                if ($native_exit_code -eq 0 -or -not [IO.File]::ReadAllText($native_log).Contains('C1020'))
                {
                    throw ('build_script.cp950_regression_fixture_did_not_reproduce:' + [IO.File]::ReadAllText($native_log))
                }
                $native_charset_checks += 1
                # The failing source above models an immutable BOM-less upstream
                # dependency. Owned positive fixtures carry BOM, and their narrow
                # and wide literals check execution and source charset together.
                $native_text += 'typedef char fixture_utf8_execution[(sizeof("é中") == 6) ? 1 : -1];' + "`n"
                $native_text += "typedef char fixture_utf8_source[(L'中' == 0x4e2d) ? 1 : -1];`n"
                [IO.File]::WriteAllText($native_source, $native_text, $utf8_bom)
                foreach ($language in @('C', 'CXX'))
                {
                    $language_option = if ($language -ceq 'C') { '/TC' } else { '/TP' }
                    $native_arguments = @('/nologo', '/c', $language_option,
                        $bootstrap_evidence.compile_flags[$language], '/MT', '/O2', ('/Fo' + $native_object), $native_source)
                    & $native_compiler.Source @native_arguments *> $native_log
                    $native_exit_code = $LASTEXITCODE
                    if ($native_exit_code -ne 0 -or -not [IO.File]::Exists($native_object))
                    {
                        throw ('build_script.bootstrap_utf8_native_compile_failed:' + $language + ':' + [IO.File]::ReadAllText($native_log))
                    }
                    [IO.File]::Delete($native_object)
                    $native_charset_checks += 1
                }
                $native_charset_status = 'passed'
            }
            finally
            {
                $ErrorActionPreference = $native_preference
            }
        }
    }
    $checks += $native_charset_checks
    # CONTRACT: Both entry scripts remain standalone. Their small hash helpers
    # must stay identical and operate even when command-based hashing is absent.
    $hash_checks = & {
        function Get-FileHash
        {
            throw 'build_script.fixture_hash_cmdlet_unavailable'
        }
        $completed = 0
        $previous_helper = $null
        $vectors = @(
            @{name='empty';bytes=[byte[]]@();digest='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
            @{name='abc';bytes=[Text.Encoding]::ASCII.GetBytes('abc');digest='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'},
            @{name='binary';bytes=[byte[]](0..255);digest='40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880'},
            @{name='million_a';bytes=[Text.Encoding]::ASCII.GetBytes(('a' * 1000000));digest='cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'}
        )
        foreach ($script_name in @('build_windows.ps1', 'restore_dependencies.ps1'))
        {
            $hash_tokens = $null
            $hash_errors = $null
            $hash_ast = [Management.Automation.Language.Parser]::ParseFile(
                (Join-Path (Join-Path $source_root 'scripts') $script_name), [ref]$hash_tokens, [ref]$hash_errors)
            if ($hash_errors.Count -ne 0)
            {
                throw ('build_script.hash_script_syntax_failed:' + $script_name)
            }
            $hash_helper = $hash_ast.Find({ param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'get_file_sha256'
            }, $true)
            if ($null -eq $hash_helper)
            {
                throw ('build_script.hash_helper_missing:' + $script_name)
            }
            if ($null -ne $previous_helper)
            {
                if ($previous_helper -cne $hash_helper.Extent.Text)
                {
                    throw 'build_script.hash_helpers_diverged'
                }
                $completed += 1
            }
            $previous_helper = $hash_helper.Extent.Text
            . ([ScriptBlock]::Create($hash_helper.Extent.Text))
            foreach ($vector in $vectors)
            {
                [IO.File]::WriteAllBytes($hash_fixture, $vector.bytes)
                $actual = get_file_sha256 $hash_fixture
                if ($actual -isnot [string] -or $actual -cne $vector.digest)
                {
                    throw ('build_script.hash_vector_failed:' + $script_name + ':' + $vector.name)
                }
                # An exclusive reopen verifies successful hashing released its stream.
                $exclusive = [IO.File]::Open($hash_fixture, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
                $exclusive.Dispose()
                $completed += 1
            }
            foreach ($unreadable_path in @(($hash_fixture + '.missing'), $directory))
            {
                $rejected = $false
                try
                {
                    $null = get_file_sha256 $unreadable_path
                }
                catch
                {
                    $rejected = $true
                }
                if (-not $rejected)
                {
                    throw ('build_script.hash_unreadable_accepted:' + $script_name)
                }
                $completed += 1
            }
            $exclusive = [IO.File]::Open($hash_fixture, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try
            {
                $rejected = $false
                try
                {
                    $null = get_file_sha256 $hash_fixture
                }
                catch
                {
                    $rejected = $true
                }
                if (-not $rejected)
                {
                    throw ('build_script.hash_locked_file_accepted:' + $script_name)
                }
                $completed += 1
            }
            finally
            {
                $exclusive.Dispose()
            }
            if ((get_file_sha256 $hash_fixture) -cne $vectors[3].digest)
            {
                throw ('build_script.hash_after_failure_failed:' + $script_name)
            }
            $completed += 1
        }
        return $completed
    }
    $checks += $hash_checks
    [IO.File]::WriteAllText($fixture, '<testsuite><testcase name="ok" /></testsuite>', $utf8)
    $result = read_junit_evidence $fixture
    if ($result.status -ne 'passed' -or $result.cases -ne 1 -or $result.skipped -ne 0)
    {
        throw 'build_script.passed_evidence_rejected'
    }
    $checks += 1
    [IO.File]::WriteAllText($fixture, '<testsuite><testcase name="ok"/><testcase name="unsupported"><skipped message="SKIP_RETURN_CODE"/></testcase></testsuite>', $utf8)
    $result = read_junit_evidence $fixture
    if ($result.status -ne 'not_run' -or $result.cases -ne 2 -or $result.skipped -ne 1)
    {
        throw 'build_script.skipped_evidence_false_pass'
    }
    $checks += 1
    [IO.File]::WriteAllText($fixture, '<testsuite><testcase name="refusal"><system-out>{"test":"unknown_media_refused","status":"passed"}' + "`n" + '{"test":"supported_storage_overwrite_cases","status":"not_run","reason":"storage_media_unknown"}</system-out></testcase></testsuite>', $utf8)
    $result = read_junit_evidence $fixture
    if ($result.status -ne 'passed' -or $result.skipped -ne 0 -or $result.coverage_gaps.Count -ne 1 -or
        $result.coverage_gaps[0].test_case -ne 'refusal' -or
        $result.coverage_gaps[0].evidence.test -ne 'supported_storage_overwrite_cases' -or
        $result.coverage_gaps[0].evidence.reason -ne 'storage_media_unknown')
    {
        throw 'build_script.platform_coverage_gap_not_reported'
    }
    $checks += 1
    foreach ($xml in @('<testsuite/>', '<testsuite><testcase><failure/></testcase></testsuite>', '<testsuite><testcase><error/></testcase></testsuite>', '<invalid'))
    {
        [IO.File]::WriteAllText($fixture, $xml, $utf8)
        $rejected = $false
        try
        {
            $null = read_junit_evidence $fixture
        }
        catch
        {
            $rejected = $true
        }
        if (-not $rejected)
        {
            throw 'build_script.invalid_evidence_accepted'
        }
        $checks += 1
    }
    # REGRESSION: Vendor/version suffixes are supported tool builds, not malformed
    # versions. Compare only the numeric core; retain exact display evidence.
    $accepted_versions = @(
        @{tool='ninja';stdout="1.12.1`r`n";stderr='';version='1.12.1';display='1.12.1'},
        @{tool='ninja';stdout='1.12.1.git.kitware.jobserver-1';stderr='';version='1.12.1';display='1.12.1.git.kitware.jobserver-1'},
        @{tool='ninja';stdout='1.13.0.git.kitware.jobserver-pipe-1';stderr='';version='1.13.0';display='1.13.0.git.kitware.jobserver-pipe-1'},
        @{tool='ninja';stdout='1.13.1+vendor.42';stderr='';version='1.13.1';display='1.13.1+vendor.42'},
        @{tool='ninja';stdout='1.13.1-rc1';stderr='';version='1.13.1';display='1.13.1-rc1'},
        @{tool='ninja';stdout='1.11';stderr='';version='1.11.0';display='1.11'},
        @{tool='ninja';stdout="`r`n  1.12.1  `r`n";stderr='diagnostic without process failure';version='1.12.1';display='1.12.1'},
        @{tool='cmake';stdout="cmake version 4.4.4`r`n`r`nCMake suite maintained and supported by Kitware (kitware.com/cmake).`r`n";stderr='';version='4.4.4';display='4.4.4'},
        @{tool='cmake';stdout='cmake version 4.1.0-rc1';stderr='';version='4.1.0';display='4.1.0-rc1'},
        @{tool='cmake';stdout='cmake version 4.4.4-msvc6';stderr='';version='4.4.4';display='4.4.4-msvc6'},
        @{tool='cmake';stdout='cmake version 4.4.4+vendor.1';stderr='nonfatal diagnostic';version='4.4.4';display='4.4.4+vendor.1'}
    )
    foreach ($case in $accepted_versions)
    {
        $result = read_tool_version $case.tool 0 $case.stdout $case.stderr
        if ($result.version -isnot [Version] -or $result.version -ne [Version]$case.version -or
            $result.display_version -cne $case.display)
        {
            throw ('build_script.valid_version_rejected:' + $case.tool + ':' + $case.stdout)
        }
        if ($case.display -eq '1.11' -and $result.version -lt [Version]'1.11.0')
        {
            throw 'build_script.major_minor_minimum_comparison_failed'
        }
        $checks += 1
    }

    $invalid_versions = @(
        @{tool='ninja';stdout=''},
        @{tool='ninja';stdout=" `r`n`t"},
        @{tool='ninja';stdout='ninja version 1.12.1'},
        @{tool='ninja';stdout='v1.12.1'},
        @{tool='ninja';stdout='1.12.1 unexpected text'},
        @{tool='ninja';stdout="1.12.1`n1.13.2"},
        @{tool='ninja';stdout="1.12.1`n1.12.1"},
        @{tool='ninja';stdout="1.12.1`nunexpected text"},
        @{tool='ninja';stdout='999999999999999999999.12.1'},
        @{tool='ninja';stdout='1.12..git'},
        @{tool='ninja';stdout='2026-10-14'},
        @{tool='cmake';stdout=''},
        @{tool='cmake';stdout='cmake version 4.4'},
        @{tool='cmake';stdout='unrelated tool 4.4.4'},
        @{tool='cmake';stdout="cmake version 4.4.4`ncmake version 4.5.0"},
        @{tool='cmake';stdout="cmake version 4.4.4`ncmake version 4.4.4"},
        @{tool='cmake';stdout="cmake version 4.4.4`ncmake version malformed"},
        @{tool='cmake';stdout='cmake version 999999999999999999999.4.4'}
    )
    foreach ($case in $invalid_versions)
    {
        $observed_error = ''
        try
        {
            $null = read_tool_version $case.tool 0 $case.stdout ''
        }
        catch
        {
            $observed_error = $_.Exception.Message
        }
        $expected_error = 'discovery.' + $case.tool + '_version_output_invalid'
        if ($observed_error -cne $expected_error)
        {
            throw ('build_script.invalid_version_not_rejected:' + $case.tool + ':' + $case.stdout + ':' + $observed_error)
        }
        $checks += 1
    }

    # REGRESSION: Successful-looking output never overrides a native process error.
    foreach ($case in @(
        @{tool='ninja';exit_code=17;stdout='1.12.1.git.kitware.jobserver-1'},
        @{tool='ninja';exit_code=245;stdout='1.13.2'},
        @{tool='ninja';exit_code=1;stdout=''},
        @{tool='cmake';exit_code=17;stdout='cmake version 4.4.4'},
        @{tool='cmake';exit_code=1;stdout=''}
    ))
    {
        $observed_error = ''
        try
        {
            $null = read_tool_version $case.tool $case.exit_code $case.stdout 'native process diagnostic'
        }
        catch
        {
            $observed_error = $_.Exception.Message
        }
        $expected_error = 'discovery.' + $case.tool + '_version_exit_failed:' + $case.exit_code
        if ($observed_error -cne $expected_error)
        {
            throw ('build_script.nonzero_native_exit_accepted:' + $case.tool + ':' + $observed_error)
        }
        $checks += 1
    }
    # REGRESSION: Validate the final embedded resource, not a loose source manifest.
    # These parser fixtures use the actual product settings and malformed variants;
    # native mt.exe/PE extraction is separately performed by the Windows build script.
    $valid_manifest = [IO.File]::ReadAllText((Join-Path $source_root 'src/windows/application.manifest'))
    [IO.File]::WriteAllText($fixture, $valid_manifest, $utf8)
    $manifest = read_embedded_manifest $fixture
    if ($manifest.status -cne 'passed' -or $manifest.requested_execution_level -cne 'requireAdministrator' -or
        $manifest.ui_access -ne $false -or $manifest.long_path_aware -ne $true -or
        $manifest.dpi_awareness -cne 'PerMonitorV2' -or $manifest.dpi_aware -ne $true -or
        $manifest.supported_os_guid -cne '{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}')
    {
        throw 'build_script.valid_embedded_manifest_rejected'
    }
    $checks += 1
    $manifest_checks += 1
    $prefixed_manifest = @'
<asm:assembly xmlns:asm="urn:schemas-microsoft-com:asm.v1" xmlns:a3="urn:schemas-microsoft-com:asm.v3" xmlns:c="urn:schemas-microsoft-com:compatibility.v1" xmlns:s16="http://schemas.microsoft.com/SMI/2016/WindowsSettings" xmlns:s05="http://schemas.microsoft.com/SMI/2005/WindowsSettings" manifestVersion="1.0">
<a3:trustInfo><a3:security><a3:requestedPrivileges><a3:requestedExecutionLevel uiAccess="false" level="requireAdministrator"/></a3:requestedPrivileges></a3:security></a3:trustInfo>
<c:compatibility><c:application><c:supportedOS Id="{8E0F7A12-BFB3-4FE8-B9A5-48FD50A15A9A}"/></c:application></c:compatibility>
<a3:application><a3:windowsSettings><s16:longPathAware> true </s16:longPathAware><s16:dpiAwareness> PerMonitorV2 </s16:dpiAwareness><s05:dpiAware>true</s05:dpiAware></a3:windowsSettings></a3:application>
</asm:assembly>
'@
    [IO.File]::WriteAllText($fixture, $prefixed_manifest, $utf8)
    if ((read_embedded_manifest $fixture).status -cne 'passed')
    {
        throw 'build_script.namespaced_embedded_manifest_rejected'
    }
    $checks += 1
    $manifest_checks += 1
    $level_xml = '<requestedExecutionLevel level="requireAdministrator" uiAccess="false" />'
    $supported_xml = '<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />'
    $long_path_xml = '<longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>'
    $dpi_xml = '<dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>'
    $legacy_dpi_xml = '<dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>'
    $invalid_manifests = @(
        @{name='missing_execution_level';xml=$valid_manifest.Replace($level_xml, '');error='validation.manifest_execution_level_count_invalid'},
        @{name='duplicate_execution_level';xml=$valid_manifest.Replace($level_xml, $level_xml + $level_xml);error='validation.manifest_execution_level_count_invalid'},
        @{name='as_invoker';xml=$valid_manifest.Replace('level="requireAdministrator"', 'level="asInvoker"');error='validation.manifest_execution_level_invalid'},
        @{name='highest_available';xml=$valid_manifest.Replace('level="requireAdministrator"', 'level="highestAvailable"');error='validation.manifest_execution_level_invalid'},
        @{name='wrong_level_case';xml=$valid_manifest.Replace('level="requireAdministrator"', 'level="requireadministrator"');error='validation.manifest_execution_level_invalid'},
        @{name='missing_level_attribute';xml=$valid_manifest.Replace('level="requireAdministrator"', '');error='validation.manifest_execution_level_invalid'},
        @{name='ui_access_true';xml=$valid_manifest.Replace('uiAccess="false"', 'uiAccess="true"');error='validation.manifest_ui_access_invalid'},
        @{name='ui_access_wrong_case';xml=$valid_manifest.Replace('uiAccess="false"', 'uiAccess="False"');error='validation.manifest_ui_access_invalid'},
        @{name='missing_ui_access';xml=$valid_manifest.Replace('uiAccess="false"', '');error='validation.manifest_ui_access_invalid'},
        @{name='wrong_level_namespace';xml=$valid_manifest.Replace($level_xml, '<requestedExecutionLevel xmlns="urn:invalid" level="requireAdministrator" uiAccess="false" />');error='validation.manifest_execution_level_count_invalid'},
        @{name='foreign_namespace_duplicate_level';xml=$valid_manifest.Replace($level_xml, $level_xml + '<requestedExecutionLevel xmlns="urn:invalid" level="asInvoker" uiAccess="false" />');error='validation.manifest_execution_level_count_invalid'},
        @{name='missing_supported_os';xml=$valid_manifest.Replace($supported_xml, '');error='validation.manifest_supported_os_invalid'},
        @{name='duplicate_supported_os';xml=$valid_manifest.Replace($supported_xml, $supported_xml + $supported_xml);error='validation.manifest_supported_os_invalid'},
        @{name='wrong_supported_os';xml=$valid_manifest.Replace('{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}', '{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}');error='validation.manifest_supported_os_invalid'},
        @{name='wrong_supported_os_namespace';xml=$valid_manifest.Replace('urn:schemas-microsoft-com:compatibility.v1', 'urn:invalid');error='validation.manifest_supported_os_invalid'},
        @{name='missing_long_path';xml=$valid_manifest.Replace($long_path_xml, '');error='validation.manifest_setting_invalid:longPathAware'},
        @{name='duplicate_long_path';xml=$valid_manifest.Replace($long_path_xml, $long_path_xml + $long_path_xml);error='validation.manifest_setting_invalid:longPathAware'},
        @{name='long_path_false';xml=$valid_manifest.Replace($long_path_xml, $long_path_xml.Replace('>true<', '>false<'));error='validation.manifest_setting_invalid:longPathAware'},
        @{name='long_path_case';xml=$valid_manifest.Replace($long_path_xml, $long_path_xml.Replace('>true<', '>True<'));error='validation.manifest_setting_invalid:longPathAware'},
        @{name='long_path_nested_markup';xml=$valid_manifest.Replace($long_path_xml, $long_path_xml.Replace('>true<', '><unexpected>true</unexpected><'));error='validation.manifest_setting_invalid:longPathAware'},
        @{name='wrong_settings_namespace';xml=$valid_manifest.Replace('http://schemas.microsoft.com/SMI/2016/WindowsSettings', 'urn:invalid');error='validation.manifest_setting_invalid:longPathAware'},
        @{name='missing_dpi_awareness';xml=$valid_manifest.Replace($dpi_xml, '');error='validation.manifest_setting_invalid:dpiAwareness'},
        @{name='duplicate_dpi_awareness';xml=$valid_manifest.Replace($dpi_xml, $dpi_xml + $dpi_xml);error='validation.manifest_setting_invalid:dpiAwareness'},
        @{name='wrong_dpi_awareness';xml=$valid_manifest.Replace('PerMonitorV2', 'System');error='validation.manifest_setting_invalid:dpiAwareness'},
        @{name='wrong_dpi_case';xml=$valid_manifest.Replace('PerMonitorV2', 'permonitorv2');error='validation.manifest_setting_invalid:dpiAwareness'},
        @{name='missing_legacy_dpi';xml=$valid_manifest.Replace($legacy_dpi_xml, '');error='validation.manifest_setting_invalid:dpiAware'},
        @{name='duplicate_legacy_dpi';xml=$valid_manifest.Replace($legacy_dpi_xml, $legacy_dpi_xml + $legacy_dpi_xml);error='validation.manifest_setting_invalid:dpiAware'},
        @{name='legacy_dpi_false';xml=$valid_manifest.Replace($legacy_dpi_xml, $legacy_dpi_xml.Replace('>true<', '>false<'));error='validation.manifest_setting_invalid:dpiAware'},
        @{name='wrong_root_namespace';xml=$valid_manifest.Replace('urn:schemas-microsoft-com:asm.v1', 'urn:invalid');error='validation.manifest_assembly_invalid'},
        @{name='wrong_manifest_version';xml=$valid_manifest.Replace('manifestVersion="1.0"', 'manifestVersion="2.0"');error='validation.manifest_assembly_invalid'},
        @{name='malformed_xml';xml='<assembly';error='validation.manifest_xml_invalid'},
        @{name='external_entity';xml='<!DOCTYPE assembly [<!ENTITY probe SYSTEM "file:///must_not_be_read">]><assembly>&probe;</assembly>';error='validation.manifest_xml_invalid'},
        @{name='internal_entity';xml='<!DOCTYPE assembly [<!ENTITY probe "data">]><assembly>&probe;</assembly>';error='validation.manifest_xml_invalid'},
        @{name='empty_manifest';xml='';error='validation.manifest_size_invalid'},
        @{name='oversized_manifest';xml=(' ' * 1048577);error='validation.manifest_size_invalid'}
    )
    foreach ($case in $invalid_manifests)
    {
        [IO.File]::WriteAllText($fixture, $case.xml, $utf8)
        $observed_error = ''
        try
        {
            $null = read_embedded_manifest $fixture
        }
        catch
        {
            $observed_error = $_.Exception.Message
        }
        if ($observed_error -cne $case.error)
        {
            throw ('build_script.invalid_manifest_not_rejected:' + $case.name + ':' + $observed_error)
        }
        $checks += 1
        $manifest_checks += 1
    }
    [IO.File]::Delete($fixture)
    $observed_error = ''
    try
    {
        $null = read_embedded_manifest $fixture
    }
    catch
    {
        $observed_error = $_.Exception.Message
    }
    if ($observed_error -cne 'validation.manifest_missing')
    {
        throw 'build_script.missing_manifest_accepted'
    }
    $checks += 1
    $manifest_checks += 1

    # CONTRACT: Exercise the actual process-logging helper against an argv-capture
    # child using the current PowerShell host. This proves argument preservation in
    # the running host only, not native mt.exe extraction or Windows PowerShell 5.1.
    [IO.File]::WriteAllText($capture_script, '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); [Console]::Out.WriteLine((@{schema="secure_erase.test.argv.v1";arguments=@([Environment]::GetCommandLineArgs())} | ConvertTo-Json -Compress)); exit 0', $utf8_bom)
    $child_host = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $input_argument = '-inputresource:' + (Join-Path $directory 'binary with spaces.exe') + ';#1'
    $output_argument = '-out:' + (Join-Path $directory 'manifest with spaces.xml')
    invoke_logged 'manifest_argument_capture' $child_host @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $capture_script, '-nologo', $input_argument, $output_argument)
    # CONTRACT: Windows PowerShell 5.1 emits a top-level JSON array as one
    # pipeline object; @(... | ConvertFrom-Json) therefore nests that array.
    # Decode a versioned object directly and inspect its arguments property.
    # GetCommandLineArgs preserves colon-bearing tokens before -File binding.
    $capture_json = [IO.File]::ReadAllText($capture_log)
    $native_capture = ConvertFrom-Json -InputObject $capture_json
    $expected_arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        $capture_script, '-nologo', $input_argument, $output_argument)
    assert_manifest_argument_capture $native_capture $expected_arguments
    if ($script:last_tool_exit -ne 0)
    {
        throw 'build_script.manifest_child_exit_changed'
    }
    # REGRESSION: Emit the decoded object as one pipeline value, matching the
    # legacy converter contract. This is a semantic fixture, not a PS5.1 run.
    $legacy_array = @(& { param([object]$value) ,$value } $native_capture.arguments)
    if ($legacy_array.Count -ne 1 -or $legacy_array[0].Count -ne ($expected_arguments.Count + 1))
    {
        throw 'build_script.legacy_array_fixture_invalid'
    }
    $legacy_capture = & { param([object]$value) ,$value } $native_capture
    assert_manifest_argument_capture $legacy_capture $expected_arguments
    $checks += 1
    $manifest_checks += 1
    # Reject array-envelope and token corruption, not merely a nonzero exit.
    $invalid_captures = @(
        @{name='top_level_array';value=$native_capture.arguments},
        @{name='nested_arguments';value=[PSCustomObject]@{schema='secure_erase.test.argv.v1';arguments=,($native_capture.arguments)}},
        @{name='missing_schema';value=[PSCustomObject]@{arguments=$native_capture.arguments}},
        @{name='wrong_schema';value=[PSCustomObject]@{schema='secure_erase.test.argv.v2';arguments=$native_capture.arguments}},
        @{name='missing_token';value=[PSCustomObject]@{schema='secure_erase.test.argv.v1';arguments=@($native_capture.arguments | Select-Object -SkipLast 1)}},
        @{name='extra_token';value=[PSCustomObject]@{schema='secure_erase.test.argv.v1';arguments=@($native_capture.arguments) + @('unexpected')}},
        @{name='split_colon_token';value=[PSCustomObject]@{schema='secure_erase.test.argv.v1';arguments=@($native_capture.arguments | Select-Object -First 7) + @('-inputresource', $input_argument.Substring(15), $output_argument)}},
        @{name='wrong_resource';value=[PSCustomObject]@{schema='secure_erase.test.argv.v1';arguments=@($native_capture.arguments | Select-Object -First 7) + @($input_argument.Replace(';#1', ';#2'), $output_argument)}},
        @{name='changed_case';value=[PSCustomObject]@{schema='secure_erase.test.argv.v1';arguments=@($native_capture.arguments | Select-Object -First 6) + @('-NOLOGO', $input_argument, $output_argument)}}
    )
    foreach ($case in $invalid_captures)
    {
        $rejected = $false
        try
        {
            assert_manifest_argument_capture $case.value $expected_arguments
        }
        catch
        {
            $rejected = $_.Exception.Message.StartsWith('build_script.manifest_native_capture_invalid:', [StringComparison]::Ordinal)
        }
        if (-not $rejected)
        {
            throw ('build_script.invalid_manifest_capture_accepted:' + $case.name)
        }
        $checks += 1
        $manifest_checks += 1
    }
    $finished_events = @($script:captured_tool_events | Where-Object { $_.event -ceq 'tool.finished' })
    if ($finished_events.Count -ne 1 -or $finished_events[0].fields.exit_code -ne 0)
    {
        throw 'build_script.manifest_child_exit_not_recorded'
    }
    $checks += 1
    $manifest_checks += 1
    [Console]::Out.WriteLine((@{schema='secure_erase.test.v1';suite='build_script_helpers';checks=$checks;manifest_checks=$manifest_checks;hash_checks=$hash_checks;
        bootstrap_checks=$bootstrap_checks;source_encoding_checks=$source_encoding_checks;test_flow_checks=$test_flow_checks;
        native_charset_checks=$native_charset_checks;native_charset_status=$native_charset_status;status='passed'} | ConvertTo-Json -Compress))
}
finally
{
    [IO.Directory]::Delete($directory, $true)
}
