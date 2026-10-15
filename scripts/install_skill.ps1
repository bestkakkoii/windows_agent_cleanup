#requires -Version 5.1
[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [ValidateSet('codex', 'claude')]
    [string]$Client,

    [Parameter(Mandatory = $true)]
    [string]$ToolRoot,

    [string]$Destination
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Client = $Client.ToLowerInvariant()
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
[Console]::OutputEncoding = $utf8

function assert_no_reparse_path
{
    param([string]$path)
    $current_path = [System.IO.Path]::GetFullPath($path)
    while (-not [string]::IsNullOrEmpty($current_path))
    {
        $item = Get-Item -LiteralPath $current_path -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
        {
            throw 'skill_install.reparse_path_rejected'
        }
        $parent_path = [System.IO.Path]::GetDirectoryName($current_path)
        if ([string]::Equals($parent_path, $current_path, [System.StringComparison]::OrdinalIgnoreCase))
        {
            break
        }
        $current_path = $parent_path
    }
}

function get_sha256
{
    param([byte[]]$bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try
    {
        return [System.BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally
    {
        $algorithm.Dispose()
    }
}

function remove_owned_staging
{
    param([string]$path)
    foreach ($file_name in @('SKILL.md', 'windows_agent_cleanup_owner.json'))
    {
        $file_path = Join-Path $path $file_name
        if ([System.IO.File]::Exists($file_path))
        {
            [System.IO.File]::Delete($file_path)
        }
    }
    [System.IO.Directory]::Delete($path, $false)
}

$staging_path = $null
$backup_path = $null
$destination_path = $null
try
{
    $tool_item = Get-Item -LiteralPath $ToolRoot -Force
    if (-not $tool_item.PSIsContainer)
    {
        throw 'skill_install.tool_root_not_directory'
    }
    $tool_path = [System.IO.Path]::GetFullPath($tool_item.FullName)
    assert_no_reparse_path $tool_path
    $readme_path = Join-Path $tool_path 'README_AI.md'
    $source_path = Join-Path $tool_path 'skills/project-cleanup/SKILL.md'
    foreach ($required_file in @($readme_path, $source_path))
    {
        assert_no_reparse_path $required_file
        $required_item = Get-Item -LiteralPath $required_file -Force
        if ($required_item.PSIsContainer)
        {
            throw 'skill_install.required_file_invalid'
        }
    }

    if ([string]::IsNullOrWhiteSpace($Destination))
    {
        $user_profile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
        if ([string]::IsNullOrWhiteSpace($user_profile))
        {
            throw 'skill_install.user_profile_unavailable'
        }
        $client_directory = '.agents'
        if ($Client -eq 'claude')
        {
            $client_directory = '.claude'
        }
        $Destination = Join-Path (Join-Path $user_profile $client_directory) 'skills/project-cleanup'
    }
    $destination_path = [System.IO.Path]::GetFullPath($Destination)
    if ([System.IO.Path]::GetFileName($destination_path.TrimEnd([char[]]@('/', '\'))) -cne 'project-cleanup')
    {
        throw 'skill_install.destination_name_rejected'
    }
    $destination_prefix = $destination_path.TrimEnd([char[]]@('/', '\')) + [System.IO.Path]::DirectorySeparatorChar
    if ([string]::Equals($destination_path, $tool_path, [System.StringComparison]::OrdinalIgnoreCase) -or
        $tool_path.StartsWith($destination_prefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($destination_path, [System.IO.Path]::GetDirectoryName($source_path), [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw 'skill_install.tool_location_overlap'
    }
    assert_no_reparse_path $destination_path
    $parent_path = [System.IO.Path]::GetDirectoryName($destination_path)
    if ([string]::IsNullOrEmpty($parent_path))
    {
        throw 'skill_install.destination_parent_invalid'
    }

    $source_text = [System.IO.File]::ReadAllText($source_path, $utf8).Replace("`r`n", "`n")
    $source_link = 'Read [README_AI.md](../../README_AI.md) from the same tool distribution. Resolve this link against this SKILL.md, never against the target project or current working directory.'
    if (-not $source_text.StartsWith("---`n") -or $source_text.IndexOf($source_link, [System.StringComparison]::Ordinal) -lt 0)
    {
        throw 'skill_install.source_contract_invalid'
    }
    $readme_literal = ConvertTo-Json -InputObject $readme_path -Compress
    $readme_literal = $readme_literal.Replace('`', '\u0060')
    $replacement = 'Read README_AI.md at this literal path (JSON string): ' + $readme_literal + '. Pass the decoded path to a literal file-reading operation; never evaluate it as shell code.'
    $installed_text = $source_text.Replace($source_link, $replacement)
    $installed_bytes = $utf8.GetBytes($installed_text)
    $owner_name = 'windows_agent_cleanup_owner.json'
    $exists = Test-Path -LiteralPath $destination_path
    if ($exists)
    {
        $existing_item = Get-Item -LiteralPath $destination_path -Force
        if (-not $existing_item.PSIsContainer)
        {
            throw 'skill_install.destination_not_directory'
        }
        $existing_files = @(Get-ChildItem -LiteralPath $destination_path -Force)
        if ($existing_files.Count -ne 2 -or @($existing_files | Where-Object { $_.PSIsContainer -or $_.Name -cnotin @('SKILL.md', $owner_name) }).Count -ne 0)
        {
            throw 'skill_install.unowned_destination'
        }
        foreach ($existing_file in $existing_files)
        {
            assert_no_reparse_path $existing_file.FullName
        }
        if (@($existing_files | Where-Object { $_.Length -gt 1048576 }).Count -ne 0)
        {
            throw 'skill_install.ownership_file_too_large'
        }
        $owner_path = Join-Path $destination_path $owner_name
        $owner = [System.IO.File]::ReadAllText($owner_path, $utf8) | ConvertFrom-Json
        $existing_skill_path = Join-Path $destination_path 'SKILL.md'
        $existing_hash = get_sha256 ([System.IO.File]::ReadAllBytes($existing_skill_path))
        if ($owner.schema -cne 'windows_agent_cleanup.skill_install.v1' -or $owner.client -cne $Client -or
            -not [string]::Equals($owner.tool_readme, $readme_path, [System.StringComparison]::OrdinalIgnoreCase) -or
            $owner.skill_sha256 -cne $existing_hash)
        {
            throw 'skill_install.ownership_mismatch'
        }
    }

    [System.IO.Directory]::CreateDirectory($parent_path) | Out-Null
    assert_no_reparse_path $parent_path
    $staging_path = Join-Path $parent_path ('.project-cleanup.stage.' + [System.Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($staging_path) | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $staging_path 'SKILL.md'), $installed_bytes)
    $owner_record = [ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v1'
        client = $Client
        tool_readme = $readme_path
        skill_sha256 = get_sha256 $installed_bytes
    }
    [System.IO.File]::WriteAllText((Join-Path $staging_path $owner_name), ($owner_record | ConvertTo-Json -Compress), $utf8)
    if ($exists)
    {
        $backup_path = Join-Path $parent_path ('.project-cleanup.previous.' + [System.Guid]::NewGuid().ToString('N'))
        [System.IO.Directory]::Move($destination_path, $backup_path)
    }
    try
    {
        [System.IO.Directory]::Move($staging_path, $destination_path)
        $staging_path = $null
    }
    catch
    {
        if ($null -ne $backup_path -and -not [System.IO.Directory]::Exists($destination_path))
        {
            [System.IO.Directory]::Move($backup_path, $destination_path)
            $backup_path = $null
        }
        throw
    }
    if ($null -ne $backup_path)
    {
        remove_owned_staging $backup_path
        $backup_path = $null
    }
    $status = 'installed'
    if ($exists)
    {
        $status = 'updated'
    }
    [ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v1'
        status = $status
        client = $Client
        destination = $destination_path
        readme = $readme_path
    } | ConvertTo-Json -Compress
}
catch
{
    $failure_message = $_.Exception.Message
    $cleanup_pending = $false
    if ($null -ne $staging_path -and [System.IO.Directory]::Exists($staging_path))
    {
        try
        {
            remove_owned_staging $staging_path
        }
        catch
        {
            $cleanup_pending = $true
        }
    }
    $failure_code = 'skill_install.io_failure'
    if ($failure_message.StartsWith('skill_install.', [System.StringComparison]::Ordinal))
    {
        $failure_code = $failure_message
    }
    $failure_result = [ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v1'
        status = 'failed'
        error_code = $failure_code
        cleanup_pending = $cleanup_pending
        recovery_directory = $backup_path
    }
    [Console]::Error.WriteLine(($failure_result | ConvertTo-Json -Compress))
    exit 1
}
