param(
    [string]$cli = (Join-Path $PSScriptRoot '..\build\windows_release\secure_erase_cli.exe')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:checks = 0
$script:failed = 0
$script:utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$fixture_root = $null
$junction = $null
$held_file = $null
$exit_code = 1

function emit_event([hashtable]$event)
{
    $event.schema = 'windows_agent_cleanup.native_cli_test.v1'
    Write-Output ($event | ConvertTo-Json -Depth 8 -Compress)
}

function check([bool]$condition, [string]$name)
{
    $script:checks++
    emit_event @{ test = $name; passed = $condition }
    if (-not $condition)
    {
        throw ('assertion_failed:' + $name)
    }
}

function quote_argument([string]$value)
{
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $slashes = 0
    foreach ($character in $value.ToCharArray())
    {
        if ($character -eq [char]92)
        {
            $slashes++
        }
        elseif ($character -eq [char]34)
        {
            [void]$builder.Append([char]92, ($slashes * 2 + 1))
            [void]$builder.Append([char]34)
            $slashes = 0
        }
        else
        {
            [void]$builder.Append([char]92, $slashes)
            [void]$builder.Append($character)
            $slashes = 0
        }
    }
    [void]$builder.Append([char]92, ($slashes * 2))
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function invoke_cli([string[]]$arguments)
{
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $script:cli_path
    $start.Arguments = (($arguments | ForEach-Object { quote_argument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $script:utf8
    $start.StandardErrorEncoding = $script:utf8
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try
    {
        if (-not $process.Start())
        {
            throw 'fixture_child_start_failed'
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000))
        {
            # Only the child created by this fixture is terminated on timeout.
            $process.Kill()
            $process.WaitForExit()
            throw 'fixture_cli_timeout_completion_unknown'
        }
        $text = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        $lines = @($text.TrimEnd([char]13, [char]10).Split([char]10))
        if ($lines.Count -ne 1 -or [string]::IsNullOrWhiteSpace($lines[0]))
        {
            throw 'fixture_expected_one_summary'
        }
        return [pscustomobject]@{
            exit_code = $process.ExitCode
            record = ($lines[0] | ConvertFrom-Json)
            stderr = $errors
        }
    }
    finally
    {
        $process.Dispose()
    }
}

function write_manifest([string]$path, [string[]]$targets)
{
    $records = @($targets | ForEach-Object { @{ path = $_ } | ConvertTo-Json -Compress })
    [System.IO.File]::WriteAllLines($path, $records, $script:utf8)
}

function get_canonical_namespace([string]$path)
{
    $file = [System.IO.File]::Open($path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
    try
    {
        return [native_cli_fixture.path_probe]::canonical_path($file.SafeFileHandle)
    }
    finally
    {
        $file.Dispose()
    }
}

function bounded_namespace([string]$value)
{
    return @{
        value = $value.Substring(0, [Math]::Min($value.Length, 1024))
        length = $value.Length
        truncated = $value.Length -gt 1024
    }
}

function select_exact_scan_target([object[]]$records, [string]$expected_namespace)
{
    return @($records | Where-Object {
        $_.schema -eq 'windows_agent_cleanup.scan_target.v1' -and
        [string]::Equals([string]$_.path, $expected_namespace, [System.StringComparison]::Ordinal)
    })
}

function read_report($result, [string]$control_directory)
{
    $path = [System.IO.Path]::GetFullPath([string]$result.record.report_file)
    $prefix = $control_directory.TrimEnd([char]92) + '\'
    if (-not $path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw 'fixture_report_escaped_control_directory'
    }
    $records = @([System.IO.File]::ReadAllLines($path, $script:utf8) |
        ForEach-Object { $_ | ConvertFrom-Json })
    if ($records.Count -lt 2 -or $records[-1].schema -ne 'windows_agent_cleanup.result.v1' -or
        $records[-1].request_id -ne $result.record.request_id -or
        $records[-1].status -ne $result.record.status)
    {
        throw 'fixture_report_summary_mismatch'
    }
    return $records
}

try
{
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT)
    {
        emit_event @{ status = 'not_run'; reason = 'windows_required'; checks = 0 }
        exit 77
    }
    $script:cli_path = [System.IO.Path]::GetFullPath($cli)
    if (-not [System.IO.File]::Exists($script:cli_path))
    {
        emit_event @{ status = 'not_run'; reason = 'built_cli_required'; checks = 0 }
        exit 77
    }
    $principal = New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        emit_event @{ status = 'not_run'; reason = 'already_elevated_token_required'; checks = 0 }
        exit 77
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace native_cli_fixture
{
    public static class path_probe
    {
        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint final_path(SafeFileHandle file, StringBuilder buffer,
            uint capacity, uint flags);

        public static string canonical_path(SafeFileHandle file)
        {
            var buffer = new StringBuilder(32768);
            // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS matches the report contract.
            uint count = final_path(file, buffer, (uint)buffer.Capacity, 0);
            if (count == 0 || count >= buffer.Capacity)
            {
                throw new Win32Exception(count == 0 ? Marshal.GetLastWin32Error() : 122);
            }
            return buffer.ToString();
        }
    }
}
'@
    $capabilities = invoke_cli @('capabilities')
    check ($capabilities.exit_code -eq 0 -and
        $capabilities.record.schema -eq 'windows_agent_cleanup.capabilities.v1' -and
        $capabilities.record.protocol -eq 'native_jsonl_manifest' -and
        $capabilities.record.physical_sanitization_guaranteed -eq $false -and
        $capabilities.record.commands -contains 'run') 'capabilities_contract'

    # All targets, retained sentinels and control files are created by this test.
    $fixture_root = Join-Path ([System.IO.Path]::GetTempPath()) ('agent_cli_fixture_' + [Guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($fixture_root)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @($identity, (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18'))))
    {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', $inheritance, 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $fixture_root -AclObject $acl
    $scope = Join-Path $fixture_root 'scope'
    $control = Join-Path $fixture_root 'control'
    $outside = Join-Path $fixture_root 'outside'
    foreach ($directory in @($scope, $control, $outside))
    {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    $single = Join-Path $scope 'single file_臺灣.txt'
    $selected_directory = Join-Path $scope 'disposable'
    $nested = Join-Path $selected_directory 'nested'
    [void][System.IO.Directory]::CreateDirectory($nested)
    $retained = Join-Path $scope 'retained.txt'
    $sentinel = Join-Path $outside 'sentinel.txt'
    foreach ($path in @($single, (Join-Path $selected_directory 'direct.txt'),
        (Join-Path $nested 'child.txt'), $retained, $sentinel))
    {
        [System.IO.File]::WriteAllText($path, 'fixture-owned-content', $script:utf8)
    }
    $single_namespace = get_canonical_namespace $single
    $manifest = Join-Path $control 'targets.jsonl'
    $reports = Join-Path $control 'reports'
    write_manifest $manifest @($single, $selected_directory)
    $common = @('--mode', 'quick', '--root', $scope, '--manifest', $manifest, '--report-dir', $reports)

    $rejected = invoke_cli (@('run', '--request-id', 'missing_auth') + $common)
    check ($rejected.exit_code -eq 2 -and $rejected.record.error_code -eq 'irreversible_authorization_mismatch' -and
        [System.IO.File]::Exists($single) -and -not [System.IO.Directory]::Exists($reports)) 'missing_authorization_no_mutation'

    $scan = invoke_cli (@('scan', '--request-id', 'scan_one') + $common)
    if ($scan.record.error_code -in @('elevation_required', 'state_root_not_fixed_local'))
    {
        emit_event @{ status = 'not_run'; reason = 'fixture_environment_unavailable'; error_code = $scan.record.error_code; checks = $script:checks }
        $exit_code = 77
    }
    else
    {
        check ($scan.exit_code -eq 0 -and $scan.record.status -eq 'scanned' -and
            $scan.record.advisory -eq $true -and $scan.record.resumable -eq $false -and
            $scan.record.counts.targets -eq 5 -and $scan.record.counts.failed -eq 0 -and
            [System.IO.File]::Exists($single)) 'scan_freezes_five_without_deletion'
        $scan_records = @(read_report $scan $control)
        $selected = @(select_exact_scan_target $scan_records $single_namespace)
        $exact_namespace_key = $selected.Count -eq 1 -and $selected[0].target_key -cmatch '^[0-9a-f]{64}$'
        if (-not $exact_namespace_key)
        {
            $scan_targets = @($scan_records | Where-Object { $_.schema -eq 'windows_agent_cleanup.scan_target.v1' })
            emit_event @{ event = 'scan_namespace_mismatch'; expected_path = (bounded_namespace $single_namespace);
                input_path = (bounded_namespace $single); exact_matches = $selected.Count; target_records = $scan_targets.Count;
                observed = @($scan_targets | Select-Object -First 8 | ForEach-Object {
                    @{ path = (bounded_namespace ([string]$_.path)); target_key = (bounded_namespace ([string]$_.target_key));
                        error_code = (bounded_namespace ([string]$_.error_code)); native_code = $_.native_code }
                }) }
        }
        check $exact_namespace_key 'scan_exact_namespace_key'

        $again = invoke_cli (@('scan', '--request-id', 'scan_again') + $common)
        check ($again.exit_code -eq 0 -and $again.record.report_file -ne $scan.record.report_file -and
            [System.IO.File]::Exists([string]$scan.record.report_file)) 'existing_private_store_unique_report'

        $bad_manifest = Join-Path $control 'malformed.jsonl'
        $valid_line = @{ path = $single } | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($bad_manifest, $valid_line + "`n" + '{"path":1}' + "`n", $script:utf8)
        $bad = invoke_cli @('run', '--mode', 'quick', '--request-id', 'bad_json', '--root', $scope,
            '--manifest', $bad_manifest, '--report-dir', $reports, '--authorize-irreversible')
        check ($bad.exit_code -eq 2 -and [System.IO.File]::Exists($single) -and
            [System.IO.Directory]::Exists($selected_directory)) 'malformed_late_record_rejects_entire_batch'

        $overlap = invoke_cli @('run', '--mode', 'quick', '--request-id', 'overlap', '--root', $scope,
            '--manifest', $manifest, '--report-dir', (Join-Path $scope 'invalid_reports'), '--authorize-irreversible')
        check ($overlap.exit_code -eq 2 -and $overlap.record.error_code -eq 'report_scope_overlap' -and
            -not [System.IO.Directory]::Exists((Join-Path $scope 'invalid_reports')) -and
            [System.IO.File]::Exists($single)) 'report_inside_scope_rejected'

        $foreign_manifest = Join-Path $control 'outside.jsonl'
        write_manifest $foreign_manifest @($sentinel)
        $foreign = invoke_cli @('run', '--mode', 'quick', '--request-id', 'outside', '--root', $scope,
            '--manifest', $foreign_manifest, '--report-dir', $reports, '--authorize-irreversible')
        check ($foreign.exit_code -eq 2 -and $foreign.record.error_code -eq 'manifest_target_outside_scope' -and
            [System.IO.File]::Exists($sentinel)) 'manifest_cannot_expand_authorized_scope'

        $held_file = [System.IO.File]::Open($single, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]'ReadWrite')
        $locks = invoke_cli @('locks', '--request-id', 'exact_locks', '--root', $scope,
            '--report-dir', $reports, '--path', $single, '--target-key', [string]$selected[0].target_key)
        check ($locks.exit_code -eq 0 -and $locks.record.status -eq 'scanned') 'exact_target_lock_query'
        $lock_records = @(read_report $locks $control)
        $our_lock = @($lock_records | Where-Object { $_.schema -eq 'windows_agent_cleanup.lock.v1' -and $_.pid -eq $PID })
        check ($our_lock.Count -eq 1) 'restart_manager_observes_fixture_owned_handle'
        $wrong_created = ([UInt64]$our_lock[0].created + [UInt64]1).ToString([Globalization.CultureInfo]::InvariantCulture)
        $release = invoke_cli @('release', '--request-id', 'stale_process', '--root', $scope,
            '--report-dir', $reports, '--path', $single, '--target-key', [string]$selected[0].target_key,
            '--pid', $PID.ToString(), '--created', $wrong_created, '--image', [string]$our_lock[0].image,
            '--authorize-close', '--authorize-force')
        check ($release.exit_code -eq 2 -and $release.record.error_code -eq 'exact_process_tuple_changed' -and
            $held_file.CanRead) 'stale_process_tuple_never_closes_fixture_host'
        $held_file.Dispose()
        $held_file = $null

        $junction = Join-Path $scope 'redirect'
        [void](New-Item -ItemType Junction -Path $junction -Target $outside)
        $link_manifest = Join-Path $control 'junction.jsonl'
        write_manifest $link_manifest @($junction)
        $link = invoke_cli @('scan', '--mode', 'quick', '--request-id', 'reparse_scan', '--root', $scope,
            '--manifest', $link_manifest, '--report-dir', $reports)
        check ($link.exit_code -eq 3 -and $link.record.status -eq 'scan_partial' -and
            $link.record.counts.failed -eq 1 -and [System.IO.File]::Exists($sentinel)) 'reparse_target_scan_partial_no_traversal'
        $link_records = @(read_report $link $control)
        check (@($link_records | Where-Object { $_.schema -eq 'windows_agent_cleanup.scan_target.v1' }).Count -eq 1) 'reparse_descendants_not_enumerated'
        $root_manifest = Join-Path $control 'junction_root.jsonl'
        write_manifest $root_manifest @((Join-Path $junction 'sentinel.txt'))
        $root_link = invoke_cli @('run', '--mode', 'quick', '--request-id', 'reparse_scope', '--root', $junction,
            '--manifest', $root_manifest, '--report-dir', $reports, '--authorize-irreversible')
        check ($root_link.exit_code -eq 2 -and [System.IO.File]::Exists($sentinel)) 'reparse_authorization_root_rejected'
        [System.IO.Directory]::Delete($junction)
        $junction = $null

        $run = invoke_cli (@('run', '--request-id', 'mixed_run') + $common + @('--authorize-irreversible'))
        check ($run.exit_code -eq 0 -and $run.record.status -eq 'completed' -and
            $run.record.counts.targets -eq 5 -and $run.record.counts.completed -eq 5 -and
            $run.record.counts.failed -eq 0 -and $run.record.counts.pending -eq 0 -and
            $run.record.resumable -eq $false) 'authorized_mixed_batch_complete_counts'
        check (-not [System.IO.File]::Exists($single) -and
            -not [System.IO.Directory]::Exists($selected_directory) -and
            [System.IO.File]::ReadAllText($retained, $script:utf8) -eq 'fixture-owned-content' -and
            [System.IO.File]::ReadAllText($sentinel, $script:utf8) -eq 'fixture-owned-content') 'only_selected_frozen_names_removed'
        $run_records = @(read_report $run $control)
        check ($run_records[-1].counts.completed -eq 5 -and
            @($run_records | Where-Object { $_.schema -eq 'windows_agent_cleanup.failure.v1' }).Count -eq 0) 'external_report_agrees_with_stdout'

        $partial_file = Join-Path $scope 'partial.txt'
        [System.IO.File]::WriteAllText($partial_file, 'disposable', $script:utf8)
        $partial_manifest = Join-Path $control 'partial.jsonl'
        write_manifest $partial_manifest @($partial_file, (Join-Path $scope 'never_created.txt'))
        $partial = invoke_cli @('run', '--mode', 'quick', '--request-id', 'partial_run', '--root', $scope,
            '--manifest', $partial_manifest, '--report-dir', $reports, '--authorize-irreversible')
        check ($partial.exit_code -eq 3 -and $partial.record.status -eq 'partial_failure' -and
            $partial.record.counts.targets -eq 2 -and $partial.record.counts.completed -eq 1 -and
            $partial.record.counts.failed -eq 1 -and -not [System.IO.File]::Exists($partial_file)) 'partial_failure_is_not_success'
        $partial_records = @(read_report $partial $control)
        check (@($partial_records | Where-Object { $_.schema -eq 'windows_agent_cleanup.failure.v1' }).Count -eq 1) 'partial_failure_external_evidence'
        $exit_code = 0
    }
}
catch
{
    $script:failed++
    emit_event @{ status = 'failed'; error = $_.Exception.Message; checks = $script:checks }
    $exit_code = 1
}
finally
{
    if ($null -ne $held_file)
    {
        $held_file.Dispose()
    }
    if ($null -ne $junction -and [System.IO.Directory]::Exists($junction))
    {
        # Remove the test-created junction itself before recursive fixture cleanup.
        [System.IO.Directory]::Delete($junction)
    }
    if ($null -ne $fixture_root -and [System.IO.Directory]::Exists($fixture_root))
    {
        try
        {
            [System.IO.Directory]::Delete($fixture_root, $true)
        }
        catch
        {
            $script:failed++
            $exit_code = 1
            emit_event @{ status = 'failed'; error = 'fixture_cleanup_failed'; fixture = $fixture_root }
        }
    }
}
emit_event @{ summary = $true; checks = $script:checks; failed = $script:failed; exit_code = $exit_code;
    not_run = @('deterministic_console_cancellation', 'successful_force_termination', 'overwrite_media_validation') }
exit $exit_code
