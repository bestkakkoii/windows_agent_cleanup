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
    if ($records.Count -lt 2 -or $records[-1].schema -notin @('windows_agent_cleanup.result.v1', 'windows_agent_cleanup.result.v2') -or
        $records[-1].schema -ne $result.record.schema -or $records[-1].request_id -ne $result.record.request_id -or
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

    $capabilities_v2 = invoke_cli @('capabilities', '--contract-version', '2')
    check ($capabilities_v2.exit_code -eq 0 -and
        $capabilities_v2.record.schema -eq 'windows_agent_cleanup.capabilities.v2' -and
        $capabilities_v2.record.supported_contract_versions -contains 2 -and
        $capabilities_v2.record.commands -contains 'status' -and
        $capabilities_v2.record.readiness.elevated -eq $true -and
        $capabilities_v2.record.readiness.filesystem_commands_ready -eq $true -and
        $capabilities_v2.record.identity.version -eq $capabilities.record.version) 'v2_effective_readiness_and_identity'

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

    $missing_reports = Join-Path $control 'not_created_by_status'
    $missing_status = invoke_cli @('status', '--request-id', 'missing', '--report-dir', $missing_reports,
        '--contract-version', '2')
    check ($missing_status.exit_code -eq 3 -and
        $missing_status.record.schema -eq 'windows_agent_cleanup.request_status.v2' -and
        $missing_status.record.lookup_state -eq 'unavailable' -and
        $missing_status.record.retry_safe -eq $false -and
        -not [System.IO.Directory]::Exists($missing_reports)) 'status_never_creates_private_store'
    $unsupported = invoke_cli (@('run', '--request-id', 'unsupported_contract') + $common +
        @('--contract-version', '3', '--authorize-irreversible'))
    check ($unsupported.exit_code -eq 2 -and $unsupported.record.error_code -eq 'unsupported_contract_version' -and
        [System.IO.File]::Exists($single) -and -not [System.IO.Directory]::Exists($reports)) 'unsupported_contract_refuses_before_store_or_mutation'

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

        $child_namespace = get_canonical_namespace (Join-Path $selected_directory 'direct.txt')
        $child_record = @(select_exact_scan_target $scan_records $child_namespace)
        if ($child_record.Count -ne 1)
        {
            throw 'fixture_child_namespace_missing'
        }
        $hidden_child = invoke_cli @('locks', '--request-id', 'hidden_child_key', '--root', $scope,
            '--report-dir', $reports, '--path', $selected_directory, '--target-key', [string]$child_record[0].target_key)
        check ($hidden_child.exit_code -eq 2 -and
            $hidden_child.record.error_code -eq 'exact_process_target_changed' -and
            [System.IO.File]::Exists((Join-Path $selected_directory 'direct.txt'))) 'directory_request_cannot_select_hidden_child_key'

        $again = invoke_cli (@('scan', '--request-id', 'scan_again') + $common)
        check ($again.exit_code -eq 0 -and $again.record.report_file -ne $scan.record.report_file -and
            [System.IO.File]::Exists([string]$scan.record.report_file)) 'existing_private_store_unique_report'

        $duplicate_id_scan = invoke_cli (@('scan', '--request-id', 'scan_again') + $common)
        check ($duplicate_id_scan.exit_code -eq 0 -and
            $duplicate_id_scan.record.report_file -ne $again.record.report_file) 'request_id_is_not_implicit_idempotency'
        $ambiguous_status = invoke_cli @('status', '--request-id', 'scan_again', '--report-dir', $reports,
            '--contract-version', '2')
        check ($ambiguous_status.exit_code -eq 3 -and $ambiguous_status.record.lookup_state -eq 'ambiguous' -and
            $null -eq $ambiguous_status.record.original_result -and $ambiguous_status.record.retry_safe -eq $false) 'status_duplicate_request_id_never_chooses_newest'

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
        $wrong_created_value = [UInt64]$our_lock[0].created + [UInt64]1
        $wrong_created = $wrong_created_value.ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($wrong_created -cnotmatch '^[0-9]+$' -or
            [UInt64]::Parse($wrong_created, [Globalization.CultureInfo]::InvariantCulture) -eq [UInt64]$our_lock[0].created)
        {
            throw 'fixture_stale_creation_time_not_exact'
        }
        # Protected lock records may deliberately omit their image. Use this
        # fixture's independently known self-image to submit a complete tuple.
        $fixture_process = [System.Diagnostics.Process]::GetCurrentProcess()
        try
        {
            $fixture_image = $fixture_process.MainModule.FileName
        }
        finally
        {
            $fixture_process.Dispose()
        }
        if ([string]::IsNullOrEmpty($fixture_image))
        {
            throw 'fixture_self_image_unavailable'
        }
        $release = invoke_cli @('release', '--request-id', 'stale_process', '--root', $scope,
            '--report-dir', $reports, '--path', $single, '--target-key', [string]$selected[0].target_key,
            '--pid', $PID.ToString(), '--created', $wrong_created, '--image', $fixture_image,
            '--authorize-close', '--authorize-force')
        $held_file_can_read = $held_file.CanRead
        $stale_tuple_rejected = $release.exit_code -eq 2 -and
            $release.record.error_code -eq 'exact_process_tuple_changed' -and $held_file_can_read
        if (-not $stale_tuple_rejected)
        {
            emit_event @{ event = 'stale_process_tuple_mismatch'; exit_code = $release.exit_code;
                status = (bounded_namespace ([string]$release.record.status));
                error_code = (bounded_namespace ([string]$release.record.error_code)); native_code = $release.record.native_code;
                request_id = (bounded_namespace ([string]$release.record.request_id));
                wrong_created = $wrong_created; wrong_created_type = $wrong_created_value.GetType().FullName;
                observed_created = (bounded_namespace ([string]$our_lock[0].created));
                observed_image = (bounded_namespace ([string]$our_lock[0].image));
                observed_eligible = $our_lock[0].eligible; observed_reason = (bounded_namespace ([string]$our_lock[0].reason));
                requested_image = (bounded_namespace $fixture_image); held_file_can_read = $held_file_can_read }
        }
        check $stale_tuple_rejected 'stale_process_tuple_never_closes_fixture_host'
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
        $link_v2 = invoke_cli @('scan', '--mode', 'quick', '--request-id', 'reparse_scan_v2', '--root', $scope,
            '--manifest', $link_manifest, '--report-dir', $reports, '--contract-version', '2')
        check ($link_v2.exit_code -eq 3 -and $link_v2.record.statistics.failed -eq 1 -and
            $link_v2.record.statistics.pending -eq 0 -and $link_v2.record.statistics.final_failures.reparse -eq 1 -and
            $link_v2.record.statistics.failed -eq $link_v2.record.counts.failed -and
            [System.IO.File]::Exists($sentinel)) 'v2_advisory_preparation_failures_reconcile_once'
        $link_v2_status = invoke_cli @('status', '--request-id', 'reparse_scan_v2', '--report-dir', $reports,
            '--contract-version', '2')
        check ($link_v2_status.exit_code -eq 0 -and $link_v2_status.record.lookup_state -eq 'terminal_result' -and
            $link_v2_status.record.original_result.status -eq 'scan_partial' -and
            $link_v2_status.record.retry_safe -eq $false) 'status_preserves_failed_advisory_result'
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

        $v2_tree = Join-Path $scope 'v2_metrics'
        $v2_nested = Join-Path $v2_tree 'nested'
        $v2_empty = Join-Path $v2_tree 'empty'
        foreach ($directory in @($v2_tree, $v2_nested, $v2_empty))
        {
            [void][System.IO.Directory]::CreateDirectory($directory)
        }
        [System.IO.File]::WriteAllText((Join-Path $v2_tree 'one.txt'), '123456789012', $script:utf8)
        [System.IO.File]::WriteAllText((Join-Path $v2_nested 'two.txt'), '123456789012345', $script:utf8)
        $v2_manifest = Join-Path $control 'v2.jsonl'
        write_manifest $v2_manifest @($v2_tree)
        $v2_common = @('--mode', 'quick', '--root', $scope, '--manifest', $v2_manifest,
            '--report-dir', $reports, '--contract-version', '2')
        $v2_scan = invoke_cli (@('scan', '--request-id', 'v2_scan') + $v2_common)
        check ($v2_scan.exit_code -eq 0 -and $v2_scan.record.schema -eq 'windows_agent_cleanup.result.v2' -and
            $v2_scan.record.statistics.selected.files -eq 2 -and
            $v2_scan.record.statistics.selected.directories -eq 3 -and
            $v2_scan.record.statistics.logical_bytes.selected -eq 27 -and
            $v2_scan.record.statistics.remove_attempted.files -eq 0 -and
            $null -eq $v2_scan.record.phases_ms.first_pass_ms -and
            [System.IO.Directory]::Exists($v2_tree)) 'v2_scan_shared_snapshot_statistics_no_removal'
        $v2_scan_status = invoke_cli @('status', '--request-id', 'v2_scan', '--report-dir', $reports,
            '--contract-version', '2')
        check ($v2_scan_status.exit_code -eq 0 -and $v2_scan_status.record.lookup_state -eq 'terminal_result' -and
            $v2_scan_status.record.original_result.advisory -eq $true -and
            $v2_scan_status.record.original_result.statistics.pending -eq 0 -and
            $v2_scan_status.record.retry_safe -eq $false) 'status_preserves_advisory_scan_statistics'
        $v2_run = invoke_cli (@('run', '--request-id', 'v2_run') + $v2_common + @('--authorize-irreversible'))
        check ($v2_run.exit_code -eq 0 -and $v2_run.record.schema -eq 'windows_agent_cleanup.result.v2' -and
            $v2_run.record.counts.completed -eq 5 -and
            $v2_run.record.statistics.selected.files -eq 2 -and
            $v2_run.record.statistics.selected.directories -eq 3 -and
            $v2_run.record.statistics.remove_attempted.files -eq 2 -and
            $v2_run.record.statistics.remove_attempted.directories -eq 3 -and
            $v2_run.record.statistics.completed.files -eq 2 -and
            $v2_run.record.statistics.completed.directories -eq 3 -and
            $v2_run.record.statistics.logical_bytes.selected -eq 27 -and
            $v2_run.record.statistics.logical_bytes.completed -eq 27 -and
            $v2_run.record.statistics.logical_bytes.completed_unknown -eq 0 -and
            $v2_run.record.retry_safe -eq $false -and
            $v2_run.record.phases_ms.first_pass_ms -ge 0 -and
            $v2_run.record.phases_ms.total_to_result_ms -ge $v2_run.record.phases_ms.first_pass_ms -and
            $v2_run.record.space_observations.semantics -eq 'observed_available_to_caller_not_attributed_reclaim' -and
            -not [System.IO.Directory]::Exists($v2_tree)) 'v2_run_shared_unique_counts_bytes_and_phase_boundaries'
        $v2_records = @(read_report $v2_run $control)
        check ($v2_records[-1].statistics.logical_bytes.completed -eq 27 -and
            $v2_records[-1].phases_ms.total_to_result_ms -eq $v2_run.record.phases_ms.total_to_result_ms) 'v2_final_report_matches_compact_result'
        $terminal = invoke_cli @('status', '--request-id', 'v2_run', '--report-dir', $reports,
            '--contract-version', '2')
        check ($terminal.exit_code -eq 0 -and $terminal.record.lookup_state -eq 'terminal_result' -and
            $terminal.record.original_result.job_id -eq $v2_run.record.job_id -and
            $terminal.record.original_result.plan_fingerprint -eq $v2_run.record.plan_fingerprint -and
            $terminal.record.original_result.statistics.logical_bytes.completed -eq 27 -and
            $terminal.record.retry_safe -eq $false) 'status_reads_bound_v2_terminal_result_without_replay'
        $legacy_terminal = invoke_cli @('status', '--request-id', 'mixed_run', '--report-dir', $reports,
            '--contract-version', '2')
        check ($legacy_terminal.exit_code -eq 0 -and
            $legacy_terminal.record.original_result.schema -eq 'windows_agent_cleanup.result.v1' -and
            $legacy_terminal.record.retry_safe -eq $false) 'status_preserves_v1_original_result'
        $unobserved = invoke_cli @('status', '--request-id', 'never_invoked', '--report-dir', $reports,
            '--contract-version', '2')
        check ($unobserved.exit_code -eq 3 -and $unobserved.record.lookup_state -eq 'no_record_observed' -and
            $unobserved.record.retry_safe -eq $false) 'missing_record_cannot_prove_no_mutation'

        $partial_file = Join-Path $scope 'partial.txt'
        [System.IO.File]::WriteAllText($partial_file, 'disposable', $script:utf8)
        $partial_manifest = Join-Path $control 'partial.jsonl'
        write_manifest $partial_manifest @($partial_file, (Join-Path $scope 'never_created.txt'))
        $partial = invoke_cli @('run', '--mode', 'quick', '--request-id', 'partial_run', '--root', $scope,
            '--manifest', $partial_manifest, '--report-dir', $reports, '--authorize-irreversible', '--contract-version', '2')
        check ($partial.exit_code -eq 3 -and $partial.record.status -eq 'partial_failure' -and
            $partial.record.counts.targets -eq 2 -and $partial.record.counts.completed -eq 1 -and
            $partial.record.counts.failed -eq 1 -and -not [System.IO.File]::Exists($partial_file)) 'partial_failure_is_not_success'
        check ($partial.record.statistics.completed.files -eq 1 -and
            $partial.record.statistics.selected.unclassified -eq 1 -and
            $partial.record.statistics.logical_bytes.selected_unknown -eq 1 -and
            $partial.record.statistics.final_failures.other -eq 1 -and
            $partial.record.retry_safe -eq $false -and $partial.record.next_action.action -eq 'inspect_report') 'v2_partial_failure_unknown_type_and_final_category'
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
