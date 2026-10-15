#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet('build', 'validate')][string]$mode = 'build',
    [switch]$enable_isolated_destructive_tests,
    [ValidateRange(1, 256)][int]$parallel_jobs = [Math]::Min(256, [Math]::Max(1, [Environment]::ProcessorCount))
)

# CONTRACT: PATH-first installed tools; no package installation, global PATH edits,
# elevated child handoff, or destructive tests without the explicit opt-in switch.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source_root = Split-Path -Parent $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$run_id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '_' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$log_directory = Join-Path $source_root ('build_logs\' + $run_id)
[void][IO.Directory]::CreateDirectory($log_directory)
$event_writer = New-Object System.IO.StreamWriter((Join-Path $log_directory 'events.jsonl'), $false, $utf8)
$event_writer.AutoFlush = $true
$script:last_tool_exit = 0

function get_file_sha256([string]$path)
{
    # CONTRACT: Hash the literal file through a bounded stream without requiring
    # PowerShell command discovery for Get-FileHash. Any open/read/hash error propagates.
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try
    {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try
        {
            $digest = $algorithm.ComputeHash($stream)
            return [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        }
        finally
        {
            if ($null -ne $algorithm)
            {
                $algorithm.Dispose()
            }
        }
    }
    finally
    {
        $stream.Dispose()
    }
}

function write_event([string]$event, [hashtable]$fields = @{})
{
    $record = [ordered]@{schema='secure_erase.build_event.v1';time_utc=[DateTime]::UtcNow.ToString('o');run_id=$run_id;event=$event}
    foreach ($key in $fields.Keys)
    {
        $record[$key] = $fields[$key]
    }
    $line = $record | ConvertTo-Json -Depth 8 -Compress
    $event_writer.WriteLine($line)
    [Console]::Out.WriteLine($line)
}

function find_on_path([string]$name)
{
    $command = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command)
    {
        return $command.Source
    }
    return $null
}

function invoke_logged([string]$stage, [string]$executable, [string[]]$arguments)
{
    write_event 'tool.started' @{stage=$stage;executable=$executable;arguments=$arguments}
    $raw_writer = New-Object System.IO.StreamWriter((Join-Path $log_directory ($stage + '.log')), $false, $utf8)
    $previous_preference = $ErrorActionPreference
    try
    {
        # CONTRACT: Windows PowerShell 5.1 wraps native stderr as ErrorRecord;
        # it is output evidence, while the actual process exit code is decisive.
        $ErrorActionPreference = 'Continue'
        & $executable @arguments 2>&1 | ForEach-Object {
            $text = $_.ToString()
            $raw_writer.WriteLine($text)
            write_event 'tool.output' @{stage=$stage;text=$text}
        }
        $script:last_tool_exit = $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference = $previous_preference
        $raw_writer.Dispose()
    }
    write_event 'tool.finished' @{stage=$stage;exit_code=$script:last_tool_exit}
    if ($script:last_tool_exit -ne 0)
    {
        throw ('tool.failed:' + $stage + ':' + $script:last_tool_exit)
    }
}

function read_junit_evidence([string]$path)
{
    $document = New-Object Xml.XmlDocument
    $document.XmlResolver = $null
    $document.Load($path)
    $cases = $document.SelectNodes('//testcase')
    $skipped = $document.SelectNodes('//testcase/skipped')
    $failed = $document.SelectNodes('//testcase/failure | //testcase/error')
    if ($cases.Count -eq 0 -or $failed.Count -gt 0)
    {
        throw ('validation.junit_failed_or_empty:' + $path)
    }
    $coverage_gaps = New-Object System.Collections.Generic.List[object]
    foreach ($test_case in $cases)
    {
        $output_node = $test_case.SelectSingleNode('system-out')
        if ($null -eq $output_node)
        {
            continue
        }
        foreach ($line in ($output_node.InnerText -split "`r?`n"))
        {
            if (-not $line.TrimStart().StartsWith('{', [StringComparison]::Ordinal))
            {
                continue
            }
            try
            {
                $record = $line | ConvertFrom-Json -ErrorAction Stop
            }
            catch
            {
                continue
            }
            if ($null -ne $record -and $null -ne $record.PSObject.Properties['status'] -and $record.status -ceq 'not_run')
            {
                $coverage_gaps.Add([PSCustomObject]@{test_case=$test_case.GetAttribute('name');evidence=$record})
            }
        }
    }
    $status = if ($skipped.Count -gt 0) { 'not_run' } else { 'passed' }
    return [PSCustomObject]@{status=$status;cases=$cases.Count;skipped=$skipped.Count;failures=$failed.Count;coverage_gaps=$coverage_gaps.ToArray()}
}

function read_embedded_manifest([string]$path, [string]$expected_level = 'requireAdministrator')
{
    if ($expected_level -notin @('asInvoker', 'requireAdministrator'))
    {
        throw 'validation.manifest_expected_level_invalid'
    }
    # SECURITY: Parse only bounded extracted XML; never resolve external entities or DTDs.
    if (-not [IO.File]::Exists($path))
    {
        throw 'validation.manifest_missing'
    }
    $document = New-Object Xml.XmlDocument
    $document.XmlResolver = $null
    $stream = $null
    $reader = $null
    try
    {
        $stream = [IO.File]::OpenRead($path)
        if ($stream.Length -eq 0 -or $stream.Length -gt 1048576)
        {
            throw 'validation.manifest_size_invalid'
        }
        $settings = New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 1048576
        $settings.MaxCharactersFromEntities = 1024
        $settings.CloseInput = $true
        $reader = [Xml.XmlReader]::Create($stream, $settings)
        $document.Load($reader)
    }
    catch
    {
        if ($_.Exception.Message -ceq 'validation.manifest_size_invalid')
        {
            throw
        }
        throw 'validation.manifest_xml_invalid'
    }
    finally
    {
        if ($null -ne $reader)
        {
            $reader.Dispose()
        }
        if ($null -ne $stream)
        {
            $stream.Dispose()
        }
    }
    $namespaces = New-Object Xml.XmlNamespaceManager($document.NameTable)
    $namespaces.AddNamespace('asm', 'urn:schemas-microsoft-com:asm.v1')
    $namespaces.AddNamespace('trust', 'urn:schemas-microsoft-com:asm.v3')
    $namespaces.AddNamespace('compat', 'urn:schemas-microsoft-com:compatibility.v1')
    $namespaces.AddNamespace('ws2016', 'http://schemas.microsoft.com/SMI/2016/WindowsSettings')
    $namespaces.AddNamespace('ws2005', 'http://schemas.microsoft.com/SMI/2005/WindowsSettings')
    $namespaces.AddNamespace('ws2019', 'http://schemas.microsoft.com/SMI/2019/WindowsSettings')
    if ($null -eq $document.DocumentElement -or $document.DocumentElement.LocalName -cne 'assembly' -or
        $document.DocumentElement.NamespaceURI -cne 'urn:schemas-microsoft-com:asm.v1' -or
        $document.DocumentElement.GetAttribute('manifestVersion') -cne '1.0')
    {
        throw 'validation.manifest_assembly_invalid'
    }
    $levels = $document.SelectNodes('/asm:assembly/trust:trustInfo/trust:security/trust:requestedPrivileges/trust:requestedExecutionLevel', $namespaces)
    $all_levels = $document.SelectNodes('//*[local-name()="requestedExecutionLevel"]')
    if ($levels.Count -ne 1 -or $all_levels.Count -ne 1)
    {
        throw 'validation.manifest_execution_level_count_invalid'
    }
    if ($levels[0].GetAttribute('level') -cne $expected_level)
    {
        throw 'validation.manifest_execution_level_invalid'
    }
    if ($levels[0].GetAttribute('uiAccess') -cne 'false')
    {
        throw 'validation.manifest_ui_access_invalid'
    }
    # CONTRACT: This GUID declares Windows 10/11 compatibility, not proof of the
    # separately required Windows 11 baseline or any particular runtime compatibility.
    $windows_guid = '{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}'
    $supported = $document.SelectNodes('/asm:assembly/compat:compatibility/compat:application/compat:supportedOS', $namespaces)
    $windows_matches = @($supported | Where-Object { $_.GetAttribute('Id') -ieq $windows_guid })
    if ($windows_matches.Count -ne 1)
    {
        throw 'validation.manifest_supported_os_invalid'
    }
    $required_settings = @(@{name='longPathAware';prefix='ws2016';value='true'})
    if ($expected_level -eq 'asInvoker')
    {
        $required_settings += @{name='activeCodePage';prefix='ws2019';value='UTF-8'}
    }
    else
    {
        $required_settings += @(
            @{name='dpiAwareness';prefix='ws2016';value='PerMonitorV2'},
            @{name='dpiAware';prefix='ws2005';value='true'}
        )
    }
    foreach ($required in $required_settings)
    {
        $xpath = '/asm:assembly/trust:application/trust:windowsSettings/' + $required.prefix + ':' + $required.name
        $nodes = $document.SelectNodes($xpath, $namespaces)
        $all_nodes = $document.SelectNodes(('//*[local-name()="' + $required.name + '"]'))
        if ($nodes.Count -ne 1 -or $all_nodes.Count -ne 1 -or
            $nodes[0].SelectNodes('*').Count -ne 0 -or $nodes[0].InnerText.Trim() -cne $required.value)
        {
            throw ('validation.manifest_setting_invalid:' + $required.name)
        }
    }
    if ($expected_level -eq 'asInvoker')
    {
        return [PSCustomObject]@{status='passed';requested_execution_level=$expected_level;ui_access=$false;supported_os_guid=$windows_guid;long_path_aware=$true;active_code_page='UTF-8'}
    }
    return [PSCustomObject]@{status='passed';requested_execution_level=$expected_level;ui_access=$false;supported_os_guid=$windows_guid;long_path_aware=$true;dpi_awareness='PerMonitorV2';dpi_aware=$true}
}

function read_tool_version([string]$tool, [int]$exit_code, [string]$stdout, [string]$stderr)
{
    if ($tool -notin @('cmake', 'ninja'))
    {
        throw 'discovery.version_tool_invalid'
    }
    if ($exit_code -ne 0)
    {
        throw ('discovery.' + $tool + '_version_exit_failed:' + $exit_code)
    }
    # CONTRACT: Preserve vendor/prerelease identity; compare only its numeric base.
    # Do not accept a random numeric substring, duplicate declarations, or a valid
    # version emitted by a failed process. stderr remains diagnostic, not version data.
    $prefix = if ($tool -eq 'cmake') { 'cmake version ' } else { '' }
    $number = if ($tool -eq 'cmake') { '[0-9]+\.[0-9]+\.[0-9]+' } else { '[0-9]+\.[0-9]+(?:\.[0-9]+)?' }
    $pattern = '^[ \t]*' + $prefix + '(?<display>(?<base>' + $number + ')(?:[.+-][A-Za-z0-9][A-Za-z0-9.+_-]*)?)[ \t]*$'
    $versions = @()
    foreach ($line in ($stdout -split '\r?\n'))
    {
        $match = [regex]::Match($line, $pattern)
        if ($match.Success)
        {
            $versions += $match
        }
        elseif ($tool -eq 'ninja' -and $line.Trim().Length -gt 0)
        {
            throw 'discovery.ninja_version_output_invalid'
        }
        elseif ($tool -eq 'cmake' -and $line.TrimStart().StartsWith('cmake version'))
        {
            throw 'discovery.cmake_version_output_invalid'
        }
    }
    if ($versions.Count -ne 1)
    {
        throw ('discovery.' + $tool + '_version_output_invalid')
    }
    $numeric = $versions[0].Groups['base'].Value
    if (($numeric -split '\.').Count -eq 2)
    {
        $numeric += '.0'
    }
    [Version]$version = $null
    if (-not [Version]::TryParse($numeric, [ref]$version))
    {
        throw ('discovery.' + $tool + '_version_output_invalid')
    }
    return [PSCustomObject]@{version=$version;display_version=$versions[0].Groups['display'].Value}
}

function get_tool_version([string]$tool, [string]$executable)
{
    if ($tool -notin @('cmake', 'ninja'))
    {
        throw 'discovery.version_tool_invalid'
    }
    write_event 'tool.version.started' @{tool=$tool;executable=$executable;arguments=@('--version')}
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $executable
    $start.Arguments = '--version'
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    $start.CreateNoWindow = $true
    $process = $null
    $native_exit_code = $null
    try
    {
        # INVARIANT: ExitCode belongs to this exact child. No PowerShell pipeline,
        # early Select-Object termination or inherited LASTEXITCODE participates.
        $process = [Diagnostics.Process]::Start($start)
        $stdout_task = $process.StandardOutput.ReadToEndAsync()
        $stderr_task = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000))
        {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw ('discovery.' + $tool + '_version_timeout')
        }
        $native_exit_code = $process.ExitCode
        $script:last_tool_exit = $native_exit_code
        if (-not $stdout_task.Wait(5000) -or -not $stderr_task.Wait(5000))
        {
            throw ('discovery.' + $tool + '_version_output_timeout')
        }
        $stdout = $stdout_task.Result
        $stderr = $stderr_task.Result
        [IO.File]::WriteAllText((Join-Path $log_directory ($tool + '_version.stdout.log')), $stdout, $utf8)
        [IO.File]::WriteAllText((Join-Path $log_directory ($tool + '_version.stderr.log')), $stderr, $utf8)
        write_event 'tool.version.output' @{tool=$tool;executable=$executable;exit_code=$native_exit_code;stdout=$stdout;stderr=$stderr}
        $version = read_tool_version $tool $native_exit_code $stdout $stderr
        write_event 'tool.version.accepted' @{tool=$tool;numeric_version=$version.version.ToString();display_version=$version.display_version}
        return $version
    }
    catch
    {
        write_event 'tool.version.failed' @{tool=$tool;executable=$executable;exit_code=$native_exit_code;error=$_.Exception.Message;hresult=$_.Exception.HResult}
        throw
    }
    finally
    {
        if ($null -ne $process)
        {
            $process.Dispose()
        }
    }
}

function find_visual_studio
{
    $candidate_list = New-Object System.Collections.Generic.List[string]
    $path_cl = find_on_path 'cl.exe'
    if ($path_cl -and $path_cl -match '^(.*)\\VC\\Tools\\MSVC\\[^\\]+\\bin\\[^\\]+\\[^\\]+\\cl\.exe$')
    {
        $candidate_list.Add($Matches[1])
        write_event 'discovery.path_compiler' @{path=$path_cl}
    }
    $vswhere = find_on_path 'vswhere.exe'
    if (-not $vswhere)
    {
        $standard_vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $standard_vswhere)
        {
            $vswhere = $standard_vswhere
        }
    }
    if ($vswhere)
    {
        $instances = & $vswhere -all -prerelease -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json -utf8 | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0)
        {
            throw 'discovery.vswhere_failed'
        }
        foreach ($instance in @($instances | Sort-Object { [Version]$_.installationVersion } -Descending))
        {
            $candidate_list.Add($instance.installationPath)
        }
    }
    foreach ($program_root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}))
    {
        foreach ($year in @('18', '2026', '2022'))
        {
            foreach ($edition in @('Enterprise', 'Professional', 'Community', 'BuildTools'))
            {
                $candidate_list.Add((Join-Path $program_root ('Microsoft Visual Studio\' + $year + '\' + $edition)))
            }
        }
    }
    foreach ($candidate in $candidate_list)
    {
        if (Test-Path -LiteralPath (Join-Path $candidate 'VC\Auxiliary\Build\vcvarsall.bat'))
        {
            return $candidate
        }
    }
    throw 'discovery.msvc_missing: install the MSVC x64 C++ workload and Windows SDK'
}

function find_windows_sdk
{
    $sdk_roots = New-Object System.Collections.Generic.List[string]
    foreach ($registry_path in @('HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots'))
    {
        $properties = Get-ItemProperty -LiteralPath $registry_path -Name KitsRoot10 -ErrorAction SilentlyContinue
        if ($null -ne $properties)
        {
            $sdk_roots.Add($properties.KitsRoot10)
        }
    }
    $sdk_roots.Add((Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'))
    $valid_sdks = @()
    foreach ($sdk_root in @($sdk_roots | Select-Object -Unique))
    {
        $lib_root = Join-Path $sdk_root 'Lib'
        if (-not (Test-Path -LiteralPath $lib_root))
        {
            continue
        }
        foreach ($directory in Get-ChildItem -LiteralPath $lib_root -Directory)
        {
            if ($directory.Name -notmatch '^10\.0\.[0-9]+\.[0-9]+$' -or [Version]$directory.Name -lt [Version]'10.0.22000.0')
            {
                continue
            }
            if ((Test-Path -LiteralPath (Join-Path $directory.FullName 'um\x64\kernel32.lib')) -and
                (Test-Path -LiteralPath (Join-Path $directory.FullName 'ucrt\x64\ucrt.lib')) -and
                (Test-Path -LiteralPath (Join-Path $sdk_root ('bin\' + $directory.Name + '\x64\rc.exe'))) -and
                (Test-Path -LiteralPath (Join-Path $sdk_root ('bin\' + $directory.Name + '\x64\mt.exe'))) -and
                (Test-Path -LiteralPath (Join-Path $sdk_root ('Include\' + $directory.Name + '\um\Windows.h'))) -and
                (Test-Path -LiteralPath (Join-Path $sdk_root ('Include\' + $directory.Name + '\ucrt\stdio.h'))))
            {
                $valid_sdks += [PSCustomObject]@{root=$sdk_root;version=$directory.Name}
            }
        }
    }
    $selected = $valid_sdks | Sort-Object { [Version]$_.version } -Descending | Select-Object -First 1
    if ($null -eq $selected)
    {
        throw 'discovery.sdk_missing: no complete x64 Windows SDK >=10.0.22000.0 found'
    }
    return $selected
}

function import_compiler_environment([string]$installation, [string]$sdk_version)
{
    $vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvarsall.bat'
    if ($vcvars.IndexOfAny([char[]]('"%!' + [char]13 + [char]10)) -ge 0 -or $source_root.IndexOfAny([char[]]('"%!' + [char]13 + [char]10)) -ge 0)
    {
        throw 'discovery.installation_path_rejected'
    }
    $temporary_cmd = Join-Path $log_directory 'compiler_environment.cmd'
    $vcvars_log = Join-Path $log_directory 'vcvarsall.log'
    $cmd_text = '@echo off' + "`r`n" + 'chcp 65001 >nul' + "`r`n" + 'call "' + $vcvars + '" x64 ' + $sdk_version + ' > "' + $vcvars_log + '" 2>&1' + "`r`n" + 'if errorlevel 1 exit /b 1' + "`r`n" + 'set' + "`r`n"
    [IO.File]::WriteAllText($temporary_cmd, $cmd_text, $utf8)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $start.Arguments = '/d /s /c ""' + $temporary_cmd + '""'
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.StandardOutputEncoding = $utf8
    $start.CreateNoWindow = $true
    try
    {
        $process = [Diagnostics.Process]::Start($start)
        # SECURITY: Environment values stay in memory and are never logged.
        $environment_text = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0)
        {
            throw 'discovery.vcvarsall_failed: inspect vcvarsall.log'
        }
        foreach ($line in ($environment_text -split "`r?`n"))
        {
            if ($line -match '^([^=][^=]*)=(.*)$')
            {
                [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
            }
        }
        $process.Dispose()
    }
    finally
    {
        Remove-Item -LiteralPath $temporary_cmd -Force -ErrorAction SilentlyContinue
    }
}

function locate_tool([string]$name, [string[]]$fallbacks)
{
    $found = find_on_path $name
    if ($found)
    {
        return $found
    }
    foreach ($fallback in $fallbacks)
    {
        if (Test-Path -LiteralPath $fallback -PathType Leaf)
        {
            return $fallback
        }
    }
    throw ('discovery.tool_missing:' + $name)
}

function ensure_locked_tools([string]$bootstrap_cmake, [string]$bootstrap_ninja,
    [string]$compiler, [string]$sdk_version)
{
    $lock_path = Join-Path $source_root 'dependencies.lock.json'
    $lock = Get-Content -LiteralPath $lock_path -Raw -Encoding UTF8 | ConvertFrom-Json
    $cmake_lock = @($lock.tool_sources | Where-Object { $_.name -eq 'cmake' })
    $ninja_lock = @($lock.tool_sources | Where-Object { $_.name -eq 'ninja' })
    if ($cmake_lock.Count -ne 1 -or $ninja_lock.Count -ne 1)
    {
        throw 'bootstrap.tool_lock_missing_or_ambiguous'
    }
    $cmake_lock = $cmake_lock[0]
    $ninja_lock = $ninja_lock[0]
    foreach ($entry in @($cmake_lock, $ninja_lock))
    {
        $repository = if ($entry.name -eq 'cmake') { 'Kitware/CMake' } else { 'ninja-build/ninja' }
        if ($entry.commit -notmatch '^[0-9a-f]{40}$' -or $entry.source_archive.sha256 -notmatch '^[0-9a-f]{64}$' -or
            $entry.source_archive.size -lt 1 -or $entry.source_archive.size -gt 268435456 -or
            $entry.source_archive.url -cne ('https://codeload.github.com/' + $repository + '/tar.gz/' + $entry.commit))
        {
            throw 'bootstrap.tool_lock_invalid'
        }
    }
    $compiler_digest = get_file_sha256 $compiler
    $identity_text = $cmake_lock.commit + ':' + $ninja_lock.commit + ':' + $compiler_digest + ':' + $sdk_version
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try
    {
        $key = [BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity_text))).Replace('-', '').ToLowerInvariant().Substring(0, 24)
    }
    finally
    {
        $algorithm.Dispose()
    }
    $cache = Join-Path $source_root ('build/tools/' + $key)
    [void][IO.Directory]::CreateDirectory($cache)
    try
    {
        $cache_lock = [IO.File]::Open((Join-Path $cache 'bootstrap.lock'),
            [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch
    {
        throw 'bootstrap.cache_busy_or_inaccessible: another build may own this exact tool cache'
    }
    try
    {
        $cmake_build = Join-Path $cache 'cmake_build'
        $ninja_build = Join-Path $cache 'ninja_build'
        $cmake_binary = Join-Path $cmake_build 'bin/cmake.exe'
        $ctest_binary = Join-Path $cmake_build 'bin/ctest.exe'
        $cmcldeps_binary = Join-Path $cmake_build 'bin/cmcldeps.exe'
        $ninja_binary = Join-Path $ninja_build 'ninja.exe'
        $receipt_path = Join-Path $cache 'toolchain.json'
        $identity = [PSCustomObject]@{cmake=$cmake_binary;ctest=$ctest_binary;cmcldeps=$cmcldeps_binary;ninja=$ninja_binary;cache=$cache;cmake_commit=$cmake_lock.commit;ninja_commit=$ninja_lock.commit}
        if (Test-Path -LiteralPath $receipt_path -PathType Leaf)
        {
            try
            {
                $receipt = Get-Content -LiteralPath $receipt_path -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($receipt.schema -ceq 'secure_erase.toolchain_cache.v2' -and $receipt.identity -ceq $identity_text -and
                    $receipt.cmake_archive_sha256 -ceq $cmake_lock.source_archive.sha256 -and
                    $receipt.ninja_archive_sha256 -ceq $ninja_lock.source_archive.sha256 -and
                    (get_file_sha256 $cmake_binary) -ceq $receipt.cmake_sha256 -and
                    (get_file_sha256 $ctest_binary) -ceq $receipt.ctest_sha256 -and
                    (get_file_sha256 $cmcldeps_binary) -ceq $receipt.cmcldeps_sha256 -and
                    (get_file_sha256 $ninja_binary) -ceq $receipt.ninja_sha256)
                {
                    write_event 'bootstrap.cache_verified' @{cache=$cache;cmake_commit=$cmake_lock.commit;ninja_commit=$ninja_lock.commit;receipt=$receipt_path}
                    return $identity
                }
            }
            catch
            {
                write_event 'bootstrap.cache_invalid' @{cache=$cache;error=$_.Exception.Message}
            }
        }
        if ([IO.Path]::GetFullPath($bootstrap_cmake).StartsWith(
            [IO.Path]::GetFullPath($cache) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))
        {
            throw 'bootstrap.external_cmake_required: cached tools need repair; select an installed CMake outside build/tools on PATH'
        }
        [void][IO.Directory]::CreateDirectory($cache)
        $sources = @{}
        foreach ($entry in @($cmake_lock, $ninja_lock))
        {
            $archive = Join-Path $cache ($entry.name + '.tar.gz')
            $valid_archive = (Test-Path -LiteralPath $archive -PathType Leaf) -and
                (get_file_sha256 $archive) -ceq $entry.source_archive.sha256 -and
                (Get-Item -LiteralPath $archive).Length -eq $entry.source_archive.size
            if (-not $valid_archive)
            {
                $temporary = $archive + '.' + [Guid]::NewGuid().ToString('N') + '.download'
                try
                {
                    write_event 'bootstrap.download_started' @{tool=$entry.name;url=$entry.source_archive.url;commit=$entry.commit}
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -UseBasicParsing -Uri $entry.source_archive.url -OutFile $temporary -TimeoutSec 180
                    if ((get_file_sha256 $temporary) -cne $entry.source_archive.sha256 -or
                        (Get-Item -LiteralPath $temporary).Length -ne $entry.source_archive.size)
                    {
                        throw ('bootstrap.archive_integrity_failed:' + $entry.name)
                    }
                    Move-Item -LiteralPath $temporary -Destination $archive -Force
                }
                finally
                {
                    if (Test-Path -LiteralPath $temporary)
                    {
                        Remove-Item -LiteralPath $temporary -Force
                    }
                }
            }
            # Only immutable hash-verified official archives reach extraction. Their
            # sources and generated outputs remain inside this ignored tool cache.
            $source_directory = Join-Path $cache ($entry.name + '_source')
            $extracted_name = if ($entry.name -eq 'cmake') { 'CMake-' + $entry.commit } else { 'ninja-' + $entry.commit }
            $extracted_directory = Join-Path $cache $extracted_name
            foreach ($stale_directory in @($source_directory, $extracted_directory))
            {
                if (Test-Path -LiteralPath $stale_directory)
                {
                    Remove-Item -LiteralPath $stale_directory -Recurse -Force
                }
            }
            Push-Location -LiteralPath $cache
            try
            {
                invoke_logged ('bootstrap_extract_' + $entry.name) $bootstrap_cmake @('-E','tar','xzf',$archive)
            }
            finally
            {
                Pop-Location
            }
            if (-not (Test-Path -LiteralPath (Join-Path $extracted_directory 'CMakeLists.txt') -PathType Leaf))
            {
                throw ('bootstrap.archive_layout_invalid:' + $entry.name)
            }
            Move-Item -LiteralPath $extracted_directory -Destination $source_directory
            $sources[$entry.name] = $source_directory
        }
        foreach ($directory in @($ninja_build, $cmake_build))
        {
            if (Test-Path -LiteralPath $directory)
            {
                Remove-Item -LiteralPath $directory -Recurse -Force
            }
        }
        $generator = if ($bootstrap_ninja) { 'Ninja' } else { 'NMake Makefiles' }
        $ninja_configure = @('-S',$sources.ninja,'-B',$ninja_build,'-G',$generator,
            '-DCMAKE_BUILD_TYPE=Release','-DBUILD_TESTING=OFF',('-DCMAKE_CXX_COMPILER=' + $compiler),
            '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded','-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=',
            '-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/INCREMENTAL:NO /DEBUG:NONE')
        if ($bootstrap_ninja)
        {
            $ninja_configure += '-DCMAKE_MAKE_PROGRAM=' + $bootstrap_ninja
        }
        elseif (-not (find_on_path 'nmake.exe'))
        {
            throw 'bootstrap.build_tool_missing: install MSVC nmake or place a Ninja bootstrap executable on PATH'
        }
        invoke_logged 'bootstrap_configure_ninja' $bootstrap_cmake $ninja_configure
        $tool_jobs = [Math]::Min(4, $parallel_jobs)
        invoke_logged 'bootstrap_build_ninja' $bootstrap_cmake @('--build',$ninja_build,'--config','Release','--parallel',$tool_jobs.ToString())
        invoke_logged 'bootstrap_configure_cmake' $bootstrap_cmake @('-S',$sources.cmake,'-B',$cmake_build,'-G','Ninja',
            ('-DCMAKE_MAKE_PROGRAM=' + $ninja_binary),('-DCMAKE_C_COMPILER=' + $compiler),('-DCMAKE_CXX_COMPILER=' + $compiler),
            '-DCMAKE_BUILD_TYPE=Release','-DBUILD_TESTING=OFF','-DBUILD_CursesDialog=OFF','-DCMake_ENABLE_DEBUGGER=OFF',
            '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded','-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=',
            '-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/INCREMENTAL:NO /DEBUG:NONE')
        # Native Ninja resource rules execute cmcldeps before rc.exe. Building
        # only cmake/ctest leaves that command empty and makes RC receive the
        # dependency-wrapper arguments as its own command line (RC1107).
        invoke_logged 'bootstrap_build_cmake' $bootstrap_cmake @('--build',$cmake_build,'--config','Release','--target','cmake','ctest','cmcldeps','--parallel',$tool_jobs.ToString())
        $receipt = [ordered]@{schema='secure_erase.toolchain_cache.v2';identity=$identity_text;generated_utc=[DateTime]::UtcNow.ToString('o');
            cmake_commit=$cmake_lock.commit;ninja_commit=$ninja_lock.commit;compiler_sha256=$compiler_digest;sdk_version=$sdk_version;
            cmake_archive_sha256=$cmake_lock.source_archive.sha256;ninja_archive_sha256=$ninja_lock.source_archive.sha256;
            cmake_sha256=(get_file_sha256 $cmake_binary);ctest_sha256=(get_file_sha256 $ctest_binary);
            cmcldeps_sha256=(get_file_sha256 $cmcldeps_binary);ninja_sha256=(get_file_sha256 $ninja_binary)}
        [IO.File]::WriteAllText($receipt_path, ($receipt | ConvertTo-Json -Depth 5), $utf8)
        write_event 'bootstrap.completed' @{cache=$cache;cmake_commit=$cmake_lock.commit;ninja_commit=$ninja_lock.commit;receipt=$receipt_path}
        return $identity
    }
    finally
    {
        $cache_lock.Dispose()
    }
}

$exit_code = 1
Push-Location -LiteralPath $source_root
try
{
    write_event 'build.started' @{mode=$mode;destructive_opt_in=[bool]$enable_isolated_destructive_tests;source_root=$source_root;powershell=$PSVersionTable.PSVersion.ToString()}
    if (-not [Environment]::Is64BitProcess)
    {
        throw 'discovery.x64_powershell_required: run the provided BAT bootstrap'
    }
    foreach ($override in @('CL', '_CL_', 'LINK'))
    {
        if ([Environment]::GetEnvironmentVariable($override, 'Process'))
        {
            throw ('build.external_flags_rejected:' + $override + '; clear it in this console to preserve the reviewed build flags')
        }
    }
    $installation = find_visual_studio
    $sdk = find_windows_sdk
    # Preserve PATH-selected CMake/Ninja before vcvars changes tool precedence.
    $path_cmake = find_on_path 'cmake.exe'
    $path_ninja = find_on_path 'ninja.exe'
    import_compiler_environment $installation $sdk.version
    if ($env:VSCMD_ARG_TGT_ARCH -ne 'x64' -or -not $env:WindowsSDKVersion -or $env:WindowsSDKVersion.TrimEnd('\') -ne $sdk.version)
    {
        throw 'discovery.compiler_environment_mismatch: expected x64 and requested SDK'
    }
    $cmake = if ($path_cmake) { $path_cmake } else { locate_tool 'cmake.exe' @((Join-Path $installation 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'), (Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe')) }
    $ninja = $path_ninja
    if (-not $ninja)
    {
        $bundled_ninja = Join-Path $installation 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
        if (Test-Path -LiteralPath $bundled_ninja -PathType Leaf)
        {
            $ninja = $bundled_ninja
        }
    }
    $ctest = Join-Path (Split-Path -Parent $cmake) 'ctest.exe'
    $compiler = find_on_path 'cl.exe'
    $manifest_tool = Join-Path $sdk.root ('bin\' + $sdk.version + '\x64\mt.exe')
    if (-not $compiler -or -not (Test-Path -LiteralPath $manifest_tool -PathType Leaf))
    {
        throw 'discovery.incomplete_toolchain'
    }
    write_event 'discovery.tools_selected' @{installation=$installation;compiler=$compiler;sdk_version=$sdk.version;cmake=$cmake;ninja=$ninja;ctest=$ctest;manifest_tool=$manifest_tool}
    $bootstrap_identity = get_tool_version 'cmake' $cmake
    if ($bootstrap_identity.version -lt [Version]'3.15.0')
    {
        throw 'bootstrap.cmake_missing: install CMake >=3.15 or the Visual Studio CMake component to bootstrap the locked current tools'
    }
    write_event 'bootstrap.tools_selected' @{cmake=$cmake;cmake_version=$bootstrap_identity.display_version;ninja=$ninja;compiler=$compiler}
    $locked_tools = ensure_locked_tools $cmake $ninja $compiler $sdk.version
    $cmake = $locked_tools.cmake
    $ninja = $locked_tools.ninja
    $ctest = $locked_tools.ctest
    $cmake_identity = get_tool_version 'cmake' $cmake
    $ninja_identity = get_tool_version 'ninja' $ninja
    $cmake_version = $cmake_identity.display_version
    $ninja_version = $ninja_identity.display_version
    write_event 'discovery.toolchain_requirements' @{cmake_minimum='4.5.0';cmake_import_std='supported_automatic_provider';ninja_minimum='1.11.0';generator='Ninja';standard_library_modules='vendor_native_required';cmake=$cmake;cmake_version=$cmake_version;ninja=$ninja;ninja_version=$ninja_version}
    if ($cmake_identity.version -lt [Version]'4.5.0' -or $ninja_identity.version -lt [Version]'1.11.0')
    {
        throw 'discovery.modules_require_cmake_4.5_or_later_ninja_1.11_or_later'
    }
    write_event 'discovery.complete' @{installation=$installation;compiler=$compiler;compiler_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($compiler).FileVersion;sdk_version=$sdk.version;sdk_root=$sdk.root;cmake=$cmake;cmake_version=$cmake_version;ninja=$ninja;ninja_version=$ninja_version}
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    invoke_logged 'dependencies' $powershell @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'restore_dependencies.ps1'))
    $destructive_setting = if ($enable_isolated_destructive_tests) { 'ON' } else { 'OFF' }
    $build_directory = Join-Path $source_root 'build\windows_release'
    # Configure even in validation mode to ensure the destructive test registration
    # exactly matches this invocation, not a previous user's cached selection.
    invoke_logged 'configure' $cmake @('--preset','windows-release',('-DCMAKE_MAKE_PROGRAM=' + $ninja),('-DCMAKE_CXX_COMPILER=' + $compiler),('-DCMAKE_SYSTEM_VERSION=' + $sdk.version),('-Dsecure_erase_enable_destructive_tests=' + $destructive_setting))
    invoke_logged 'compile' $cmake @('--build','--preset','windows-release','--parallel',$parallel_jobs.ToString())
    $symbol_files = @(Get-ChildItem -LiteralPath $build_directory -Filter '*.pdb' -Recurse -File)
    if ($symbol_files.Count -gt 0)
    {
        throw 'build.unexpected_debug_artifact: a PDB exists; use a clean build directory and inspect inherited flags'
    }
    # SECURITY: Inspect RT_MANIFEST #1 in the completed binaries without executing
    # them. Tool selection stays bound to the SDK chosen for this exact build.
    $manifest_targets = @('secure_erase_gui', 'secure_erase_cli')
    if ($enable_isolated_destructive_tests)
    {
        $manifest_targets += @('secure_erase_windows_backend_tests', 'secure_erase_state_store_windows_tests', 'secure_erase_quick_delete_windows_tests')
    }
    $manifest_evidence = @()
    foreach ($target in $manifest_targets)
    {
        $binary_path = Join-Path $build_directory ($target + '.exe')
        $extracted_manifest = Join-Path $log_directory ($target + '.embedded.manifest')
        write_event 'validation.manifest.started' @{target=$target;binary=$binary_path;resource_id=1;manifest_tool=$manifest_tool;extracted_manifest=$extracted_manifest}
        try
        {
            if (-not (Test-Path -LiteralPath $binary_path -PathType Leaf))
            {
                throw 'validation.manifest_binary_missing'
            }
            invoke_logged ('manifest_' + $target) $manifest_tool @('-nologo', ('-inputresource:' + $binary_path + ';#1'), ('-out:' + $extracted_manifest))
            $expected_level = if ($target -eq 'secure_erase_cli') { 'asInvoker' } else { 'requireAdministrator' }
            $manifest = read_embedded_manifest $extracted_manifest $expected_level
            $manifest_evidence += [PSCustomObject]@{target=$target;binary=$binary_path;binary_sha256=(get_file_sha256 $binary_path);resource_id=1;extracted_manifest=$extracted_manifest;manifest_sha256=(get_file_sha256 $extracted_manifest);settings=$manifest}
            write_event 'validation.manifest.passed' @{target=$target;resource_id=1;extracted_manifest=$extracted_manifest;settings=$manifest}
        }
        catch
        {
            write_event 'validation.manifest.failed' @{target=$target;binary=$binary_path;extracted_manifest=$extracted_manifest;error=$_.Exception.Message;hresult=$_.Exception.HResult}
            throw
        }
    }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'validation.administrator_required: binaries carry requireAdministrator; rerun this BAT as administrator'
    }
    invoke_logged 'safe_tests' $ctest @('--test-dir',$build_directory,'-C','Release','--output-on-failure','--test-output-size-passed','1048576','--test-output-size-failed','1048576','--no-tests=error','-LE','destructive','--output-junit',(Join-Path $log_directory 'safe_tests.xml'))
    $safe_evidence = read_junit_evidence (Join-Path $log_directory 'safe_tests.xml')
    $isolated_evidence = [PSCustomObject]@{status='not_run';cases=0;skipped=0;failures=0;coverage_gaps=@()}
    if ($enable_isolated_destructive_tests)
    {
        invoke_logged 'isolated_destructive_tests' $ctest @('--test-dir',$build_directory,'-C','Release','--output-on-failure','--test-output-size-passed','1048576','--test-output-size-failed','1048576','--no-tests=error','-L','destructive','--output-junit',(Join-Path $log_directory 'isolated_destructive_tests.xml'))
        $isolated_evidence = read_junit_evidence (Join-Path $log_directory 'isolated_destructive_tests.xml')
    }
    $has_skips = $safe_evidence.skipped -gt 0 -or $isolated_evidence.skipped -gt 0
    $summary = [ordered]@{schema='secure_erase.windows_build_result.v1';run_id=$run_id;status=$(if ($has_skips) { 'incomplete' } else { 'passed' });compilation='passed';embedded_manifests='passed';manifest_evidence=$manifest_evidence;safe_tests=$safe_evidence.status;safe_evidence=$safe_evidence;isolated_destructive_tests=$isolated_evidence.status;isolated_evidence=$isolated_evidence;hardware_matrix='not_run';physical_sanitization_guaranteed=$false;compiler=$compiler;sdk=$sdk.version;cmake=$cmake_version;ninja=$ninja_version;log_directory=$log_directory}
    [IO.File]::WriteAllText((Join-Path $log_directory 'result.json'), ($summary | ConvertTo-Json -Depth 8), $utf8)
    $exit_code = if ($has_skips) { 3 } else { 0 }
    write_event 'build.finished' @{exit_code=$exit_code;required_suite_skips=$has_skips;log_directory=$log_directory;release_eligibility='requires_full_owner_hardware_matrix'}
}
catch
{
    $exit_code = if ($script:last_tool_exit -ne 0) { $script:last_tool_exit } else { 1 }
    write_event 'build.failed' @{exit_code=$exit_code;error=$_.Exception.Message;position=$_.InvocationInfo.PositionMessage;stack=$_.ScriptStackTrace;log_directory=$log_directory}
    $summary = @{schema='secure_erase.windows_build_result.v1';run_id=$run_id;status='failed';exit_code=$exit_code;error=$_.Exception.Message;hardware_matrix='not_run';log_directory=$log_directory}
    [IO.File]::WriteAllText((Join-Path $log_directory 'result.json'), ($summary | ConvertTo-Json -Depth 8), $utf8)
}
finally
{
    Pop-Location
    $event_writer.Dispose()
}
exit $exit_code
