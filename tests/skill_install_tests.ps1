#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source_root = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $source_root 'scripts/install_skill.ps1'
$child_host = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$utf8 = New-Object Text.UTF8Encoding($false, $true)
$directory = Join-Path ([IO.Path]::GetTempPath()) ('cleanup_skill_tests_' + [Guid]::NewGuid().ToString('N'))
$tool_root = Join-Path $directory '工具 [literal] '' $tick` distribution'
$checks = 0

function quote_literal
{
    param([string]$value)
    return "'" + $value.Replace("'", "''") + "'"
}

function invoke_installer
{
    param([string]$destination, [string]$client = 'codex')
    $command = "`$ProgressPreference = 'SilentlyContinue'; & " + (quote_literal $installer) + ' -Client ' + (quote_literal $client) +
        ' -ToolRoot ' + (quote_literal $tool_root) + ' -Destination ' + (quote_literal $destination)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $child_host
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand ' + $encoded
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try
    {
        [void]$process.Start()
        $output_task = $process.StandardOutput.ReadToEndAsync()
        $error_task = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000))
        {
            $process.Kill()
            throw 'skill_tests.child_timeout'
        }
        $output = $output_task.GetAwaiter().GetResult()
        $error_output = $error_task.GetAwaiter().GetResult()
        $text = $output.Trim()
        if ($process.ExitCode -ne 0)
        {
            $text = $error_output.Trim()
        }
        try
        {
            if (($process.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($error_output)) -or
                ($process.ExitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($output)))
            {
                throw 'skill_tests.child_unexpected_stream_output'
            }
            $result = ConvertFrom-Json -InputObject $text -ErrorAction Stop
            if ($result -isnot [PSCustomObject] -or
                $null -eq $result.PSObject.Properties['schema'] -or
                $null -eq $result.PSObject.Properties['status'] -or
                $result.schema -cne 'windows_agent_cleanup.skill_install.v2' -or
                $result.status -cnotin @('installed', 'updated', 'failed'))
            {
                throw 'skill_tests.child_envelope_invalid'
            }
        }
        catch
        {
            # Keep exact bounded transport evidence. Never recover by selecting
            # a convenient JSON line or dropping unknown CLIXML/progress output.
            $diagnostic = [ordered]@{
                exit_code = $process.ExitCode
                stdout = $output.Substring(0, [Math]::Min(4096, $output.Length))
                stderr = $error_output.Substring(0, [Math]::Min(4096, $error_output.Length))
                stdout_length = $output.Length
                stderr_length = $error_output.Length
                parse_error = $_.Exception.Message
            }
            throw ('skill_tests.child_protocol_invalid:' + ($diagnostic | ConvertTo-Json -Compress))
        }
        return [pscustomobject]@{ exit_code = $process.ExitCode; text = $text; result = $result }
    }
    finally
    {
        $process.Dispose()
    }
}

function require
{
    param([bool]$condition, [string]$name)
    if (-not $condition)
    {
        throw ('skill_tests.' + $name)
    }
    $script:checks += 1
}

function file_hash
{
    param([string]$path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try
    {
        return [BitConverter]::ToString($algorithm.ComputeHash([IO.File]::ReadAllBytes($path))).Replace('-', '').ToLowerInvariant()
    }
    finally
    {
        $algorithm.Dispose()
    }
}

function new_legacy_entry
{
    param([string]$path)
    [void][IO.Directory]::CreateDirectory($path)
    [IO.File]::WriteAllText((Join-Path $path 'SKILL.md'), "---`nname: project-cleanup`ndescription: previous owned router`n---`nRead the previous bound README.", $utf8)
    $owner = [ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v1'
        client = 'codex'
        tool_readme = Join-Path $tool_root 'README_AI.md'
        skill_sha256 = file_hash (Join-Path $path 'SKILL.md')
    }
    [IO.File]::WriteAllText((Join-Path $path 'windows_agent_cleanup_owner.json'), ($owner | ConvertTo-Json -Compress), $utf8)
}

try
{
    [void][IO.Directory]::CreateDirectory((Join-Path $tool_root 'skills'))
    Copy-Item -LiteralPath (Join-Path $source_root 'skills/project-cleanup') -Destination (Join-Path $tool_root 'skills/project-cleanup') -Recurse
    [IO.File]::WriteAllText((Join-Path $tool_root 'README_AI.md'), '# Disposable installation fixture', $utf8)
    # Execute the actual documented streaming writer with literal-path fixtures.
    $manifest = Join-Path $directory 'targets.jsonl'
    $approved_path_stream = @('C:\work\工具\a"b.txt', 'C:\work\literal [name] $tick`')
    $bulk_text = [IO.File]::ReadAllText((Join-Path $source_root 'skills/project-cleanup/references/bulk_cli.md'), $utf8)
    $writer_example = [regex]::Match($bulk_text, '(?s)```powershell\r?\n(.*?)```')
    require ($writer_example.Success) 'streaming_writer_example_missing'
    . ([scriptblock]::Create($writer_example.Groups[1].Value))
    $manifest_bytes = [IO.File]::ReadAllBytes($manifest)
    require (-not ($manifest_bytes.Length -ge 3 -and $manifest_bytes[0] -eq 239 -and $manifest_bytes[1] -eq 187 -and $manifest_bytes[2] -eq 191)) 'streaming_writer_added_bom'
    $manifest_rows = @([IO.File]::ReadAllLines($manifest, $utf8) | ForEach-Object { $_ | ConvertFrom-Json })
    require ($manifest_rows.Count -eq 2 -and $manifest_rows[0].path -ceq $approved_path_stream[0] -and $manifest_rows[1].path -ceq $approved_path_stream[1]) 'streaming_writer_changed_paths'
    # Reject a BOM in source SKILL frontmatter rather than stripping it only
    # during validation and copying malformed original bytes to the host.
    $source_skill = Join-Path $tool_root 'skills/project-cleanup/SKILL.md'
    $skill_bytes = [IO.File]::ReadAllBytes($source_skill)
    $bom_destination = Join-Path $directory 'bom_source/project-cleanup'
    try
    {
        [IO.File]::WriteAllBytes($source_skill, [byte[]](@(239, 187, 191) + $skill_bytes))
        $bom_source_hash = file_hash $source_skill
        $run = invoke_installer $bom_destination
        require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.source_contract_invalid' -and
            -not [IO.Directory]::Exists($bom_destination) -and
            (file_hash $source_skill) -ceq $bom_source_hash) 'bom_skill_source_accepted_or_changed'
    }
    finally
    {
        [IO.File]::WriteAllBytes($source_skill, $skill_bytes)
    }
    $destination = Join-Path $directory 'codex/project-cleanup'
    $run = invoke_installer $destination
    require ($run.exit_code -eq 0 -and $run.result.status -ceq 'installed' -and $run.result.files -eq 7) 'complete_install_failed'
    foreach ($relative in @('SKILL.md', 'agents/openai.yaml', 'references/tool_location.md',
        'references/disposal_evidence.md', 'references/bulk_cli.md', 'references/results_and_recovery.md',
        'references/exceptional_operations.md'))
    {
        require ([IO.File]::Exists((Join-Path $destination $relative))) ('missing_bundle_file:' + $relative)
    }
    require ((file_hash (Join-Path $destination 'SKILL.md')) -ceq (file_hash (Join-Path $source_root 'skills/project-cleanup/SKILL.md'))) 'core_was_rewritten'
    $location = [IO.File]::ReadAllText((Join-Path $destination 'references/tool_location.md'), $utf8)
    $match = [regex]::Match($location, 'root is this literal JSON string: ("[^\r\n]+").\n')
    require ($match.Success -and ($match.Groups[1].Value | ConvertFrom-Json) -ceq $tool_root) 'literal_root_binding_changed'
    require (-not [IO.File]::Exists((Join-Path $directory 'AGENTS.md'))) 'global_instructions_created'
    $owner_path = Join-Path $destination 'windows_agent_cleanup_owner.json'
    $owner = [IO.File]::ReadAllText($owner_path, $utf8) | ConvertFrom-Json
    require ($owner.schema -ceq 'windows_agent_cleanup.skill_install.v2' -and $owner.files.Count -eq 7) 'bundle_receipt_invalid'

    $source_reference = Join-Path $tool_root 'skills/project-cleanup/references/bulk_cli.md'
    [IO.File]::AppendAllText($source_reference, "`nFixture source update.`n", $utf8)
    $run = invoke_installer $destination
    require ($run.exit_code -eq 0 -and $run.result.status -ceq 'updated') 'intact_update_failed'
    require ([IO.File]::ReadAllText((Join-Path $destination 'references/bulk_cli.md'), $utf8).EndsWith("Fixture source update.`n")) 'reference_update_missing'
    $installed_reference = Join-Path $destination 'references/bulk_cli.md'
    [IO.File]::AppendAllText($installed_reference, "`nLocal user edit.`n", $utf8)
    $edited_hash = file_hash $installed_reference
    $run = invoke_installer $destination
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.ownership_mismatch') 'local_reference_edit_overwritten'
    require ((file_hash $installed_reference) -ceq $edited_hash) 'local_edit_not_preserved'

    $legacy_destination = Join-Path $directory 'legacy/project-cleanup'
    new_legacy_entry $legacy_destination
    $run = invoke_installer $legacy_destination
    require ($run.exit_code -eq 0 -and $run.result.status -ceq 'updated' -and $run.result.files -eq 7) 'legacy_upgrade_failed'
    require ([IO.File]::Exists((Join-Path $legacy_destination 'references/bulk_cli.md'))) 'legacy_upgrade_incomplete'
    $run = invoke_installer $legacy_destination 'claude'
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.ownership_mismatch') 'other_client_overwritten'

    $extra_path = Join-Path $legacy_destination 'unrelated.md'
    [IO.File]::WriteAllText($extra_path, 'Do not replace', $utf8)
    $run = invoke_installer $legacy_destination
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.unowned_destination') 'unknown_file_overwritten'
    require ([IO.File]::ReadAllText($extra_path, $utf8) -ceq 'Do not replace') 'unknown_file_not_preserved'
    [IO.File]::Delete($extra_path)
    $empty_directory = Join-Path $legacy_destination 'unrelated'
    [void][IO.Directory]::CreateDirectory($empty_directory)
    $run = invoke_installer $legacy_destination
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.unowned_destination') 'unknown_empty_directory_removed'
    [IO.Directory]::Delete($empty_directory)

    $unowned_destination = Join-Path $directory 'unowned/project-cleanup'
    [void][IO.Directory]::CreateDirectory($unowned_destination)
    [IO.File]::WriteAllText((Join-Path $unowned_destination 'SKILL.md'), 'Unrelated skill', $utf8)
    $run = invoke_installer $unowned_destination
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.unowned_destination') 'unowned_entry_replaced'

    $tampered_legacy = Join-Path $directory 'tampered_legacy/project-cleanup'
    new_legacy_entry $tampered_legacy
    [IO.File]::AppendAllText((Join-Path $tampered_legacy 'SKILL.md'), 'User modification', $utf8)
    $run = invoke_installer $tampered_legacy
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.ownership_mismatch') 'modified_legacy_replaced'

    $run = invoke_installer (Join-Path $directory 'wrong_name')
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.destination_name_rejected') 'wrong_destination_name_accepted'
    $run = invoke_installer (Join-Path $tool_root 'skills/project-cleanup')
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.tool_location_overlap') 'source_overwrite_accepted'

    $traversal_owner_path = Join-Path $legacy_destination 'windows_agent_cleanup_owner.json'
    $traversal_owner = [IO.File]::ReadAllText($traversal_owner_path, $utf8) | ConvertFrom-Json
    $traversal_owner.files[0].path = '../outside.md'
    [IO.File]::WriteAllText($traversal_owner_path, ($traversal_owner | ConvertTo-Json -Depth 5 -Compress), $utf8)
    $run = invoke_installer $legacy_destination
    require ($run.exit_code -eq 1 -and $run.result.error_code -ceq 'skill_install.ownership_mismatch') 'receipt_traversal_accepted'

    $claude_destination = Join-Path $directory 'claude/project-cleanup'
    $run = invoke_installer $claude_destination 'claude'
    require ($run.exit_code -eq 0 -and $run.result.client -ceq 'claude' -and $run.result.files -eq 7) 'claude_bundle_failed'
    require ([IO.File]::Exists((Join-Path $claude_destination 'agents/openai.yaml'))) 'portable_metadata_not_copied'
    # Preserve unexpected transport bytes rather than accepting a convenient
    # JSON line after non-protocol progress/error text.
    $real_installer = $installer
    $installer = Join-Path $directory 'non_protocol_child.ps1'
    $child_fixture = @'
param([string]$Client, [string]$ToolRoot, [string]$Destination)
[Console]::Error.WriteLine('unexpected transport prefix')
[Console]::Error.WriteLine('{"schema":"windows_agent_cleanup.skill_install.v2","status":"failed"}')
exit 1
'@
    [IO.File]::WriteAllText($installer, $child_fixture, (New-Object Text.UTF8Encoding($true)))
    $protocol_diagnostic = $null
    try
    {
        try
        {
            $null = invoke_installer (Join-Path $directory 'protocol_fixture/project-cleanup')
        }
        catch
        {
            $prefix = 'skill_tests.child_protocol_invalid:'
            if ($_.Exception.Message.StartsWith($prefix, [StringComparison]::Ordinal))
            {
                $protocol_diagnostic = ConvertFrom-Json -InputObject $_.Exception.Message.Substring($prefix.Length)
            }
            else
            {
                throw
            }
        }
    }
    finally
    {
        $installer = $real_installer
    }
    require ($null -ne $protocol_diagnostic -and $protocol_diagnostic.exit_code -eq 1 -and
        $protocol_diagnostic.stderr.Contains('unexpected transport prefix') -and
        $protocol_diagnostic.stderr.Contains('"schema":"windows_agent_cleanup.skill_install.v2"') -and
        $protocol_diagnostic.stdout_length -eq 0) 'non_protocol_output_was_discarded'
    $leftovers = @(Get-ChildItem -LiteralPath $directory -Recurse -Force | Where-Object {
        $_.Name.StartsWith('.project-cleanup.stage.') -or $_.Name.StartsWith('.project-cleanup.previous.') })
    require ($leftovers.Count -eq 0) 'owned_staging_left_after_normal_paths'
    [Console]::Out.WriteLine((@{schema='secure_erase.test.v1';suite='skill_install';checks=$checks;status='passed'} | ConvertTo-Json -Compress))
}
finally
{
    if ([IO.Directory]::Exists($directory))
    {
        [IO.Directory]::Delete($directory, $true)
    }
}
