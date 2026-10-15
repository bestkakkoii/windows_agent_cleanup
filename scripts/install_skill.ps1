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
$ProgressPreference = 'SilentlyContinue'
$Client = $Client.ToLowerInvariant()
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$utf8_bom = New-Object System.Text.UTF8Encoding($true, $true)
[Console]::OutputEncoding = $utf8
$owner_name = 'windows_agent_cleanup_owner.json'

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

function get_tree_inventory
{
    param([string]$path)
    assert_no_reparse_path $path
    $prefix = $path.TrimEnd([char[]]@('/', '\')) + [System.IO.Path]::DirectorySeparatorChar
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $files = New-Object 'System.Collections.Generic.List[object]'
    $directories = New-Object 'System.Collections.Generic.List[string]'
    $pending.Enqueue($path)
    while ($pending.Count -gt 0)
    {
        $directory = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force | Sort-Object Name))
        {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            {
                throw 'skill_install.reparse_path_rejected'
            }
            $relative = $item.FullName.Substring($prefix.Length).Replace('\', '/')
            if ($relative -cnotmatch '^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*$' -or
                @($relative.Split('/') | Where-Object { $_ -cin @('.', '..') }).Count -ne 0)
            {
                throw 'skill_install.bundle_path_invalid'
            }
            if ($item.PSIsContainer)
            {
                $directories.Add($relative)
                $pending.Enqueue($item.FullName)
            }
            else
            {
                $files.Add([pscustomobject]@{ path = $relative; full_path = $item.FullName; length = $item.Length })
            }
        }
    }
    return [pscustomobject]@{ files = @($files.ToArray()); directories = @($directories.ToArray()) }
}

function assert_exact_inventory
{
    param([object]$inventory, [string[]]$allowed_files)
    $expected_files = @{}
    $expected_directories = @{}
    foreach ($relative in $allowed_files)
    {
        if ($relative -cnotmatch '^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*$' -or
            @($relative.Split('/') | Where-Object { $_ -cin @('.', '..') }).Count -ne 0 -or
            $expected_files.ContainsKey($relative))
        {
            throw 'skill_install.ownership_mismatch'
        }
        $expected_files[$relative] = $true
        $parent = $relative
        while ($parent.Contains('/'))
        {
            $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
            $expected_directories[$parent] = $true
        }
    }
    if ($inventory.files.Count -ne $expected_files.Count -or
        $inventory.directories.Count -ne $expected_directories.Count)
    {
        throw 'skill_install.unowned_destination'
    }
    foreach ($file in $inventory.files)
    {
        if (-not $expected_files.ContainsKey($file.path))
        {
            throw 'skill_install.unowned_destination'
        }
    }
    foreach ($directory in $inventory.directories)
    {
        if (-not $expected_directories.ContainsKey($directory))
        {
            throw 'skill_install.unowned_destination'
        }
    }
}

function remove_owned_tree
{
    param([string]$path, [string[]]$allowed_files)
    $inventory = get_tree_inventory $path
    # Never recursively remove an unexpected addition, even from private staging.
    # A failed cleanup leaves the recovery directory for explicit reconciliation.
    $present_files = @($inventory.files | ForEach-Object { $_.path })
    foreach ($relative in $present_files)
    {
        if ($relative -cnotin $allowed_files)
        {
            throw 'skill_install.unowned_destination'
        }
    }
    # Empty directories are allowed during interrupted staging, but only ancestors
    # of our known files. Validate those using a synthetic complete inventory.
    $expected_directories = @{}
    foreach ($relative in $allowed_files)
    {
        $parent = $relative
        while ($parent.Contains('/'))
        {
            $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
            $expected_directories[$parent] = $true
        }
    }
    foreach ($directory in $inventory.directories)
    {
        if (-not $expected_directories.ContainsKey($directory))
        {
            throw 'skill_install.unowned_destination'
        }
    }
    foreach ($file in $inventory.files)
    {
        [System.IO.File]::Delete($file.full_path)
    }
    foreach ($directory in @($inventory.directories | Sort-Object { $_.Length } -Descending))
    {
        [System.IO.Directory]::Delete((Join-Path $path $directory), $false)
    }
    [System.IO.Directory]::Delete($path, $false)
}

$staging_path = $null
$backup_path = $null
$destination_path = $null
$staging_files = @()
$previous_files = @()
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
    $source_directory = Join-Path $tool_path 'skills/project-cleanup'
    foreach ($required_file in @($readme_path, (Join-Path $source_directory 'SKILL.md'),
        (Join-Path $source_directory 'references/tool_location.md'), (Join-Path $source_directory 'agents/openai.yaml')))
    {
        assert_no_reparse_path $required_file
        $required_item = Get-Item -LiteralPath $required_file -Force
        if ($required_item.PSIsContainer)
        {
            throw 'skill_install.required_file_invalid'
        }
    }
    $source_inventory = get_tree_inventory $source_directory
    $source_records = New-Object 'System.Collections.Generic.List[object]'
    $source_paths = @($source_inventory.files | ForEach-Object { $_.path })
    assert_exact_inventory $source_inventory $source_paths
    foreach ($file in $source_inventory.files)
    {
        if ($file.path -ceq $owner_name -or [System.IO.Path]::GetExtension($file.path) -cnotin @('.md', '.yaml'))
        {
            throw 'skill_install.source_contract_invalid'
        }
        $bytes = [System.IO.File]::ReadAllBytes($file.full_path)
        if ($file.path -ceq 'SKILL.md')
        {
            # Decode exact bytes and compare ordinally: culture comparisons may
            # ignore U+FEFF and accept frontmatter-breaking original bytes.
            $text = $utf8.GetString($bytes).Replace("`r`n", "`n")
            if (-not $text.StartsWith("---`n", [System.StringComparison]::Ordinal) -or $text -cnotmatch '(?m)^name: project-cleanup$')
            {
                throw 'skill_install.source_contract_invalid'
            }
        }
        if ($file.path -ceq 'references/tool_location.md')
        {
            $text = [System.IO.File]::ReadAllText($file.full_path, $utf8)
            $pattern = '(?s)<!-- windows_agent_cleanup.tool_root_binding.v1 -->.*?<!-- windows_agent_cleanup.tool_root_binding.end -->'
            if ([System.Text.RegularExpressions.Regex]::Matches($text, $pattern).Count -ne 1)
            {
                throw 'skill_install.source_contract_invalid'
            }
            $root_literal = (ConvertTo-Json -InputObject $tool_path -Compress).Replace('`', '\u0060')
            $binding = '<!-- windows_agent_cleanup.tool_root_binding.v1 -->' + "`n" +
                'The tool distribution root is this literal JSON string: ' + $root_literal + ".`n" +
                'Decode it as data and use literal file/process arguments; never evaluate it as shell code.' + "`n" +
                '<!-- windows_agent_cleanup.tool_root_binding.end -->'
            $match = [System.Text.RegularExpressions.Regex]::Match($text, $pattern)
            $text = $text.Substring(0, $match.Index) + $binding + $text.Substring($match.Index + $match.Length)
            $bytes = [byte[]]($utf8_bom.GetPreamble() + $utf8_bom.GetBytes($text))
        }
        $source_records.Add([pscustomobject]@{ path = $file.path; sha256 = get_sha256 $bytes; bytes = $bytes })
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
    $destination_path = [System.IO.Path]::GetFullPath($Destination).TrimEnd([char[]]@('/', '\'))
    if ([System.IO.Path]::GetFileName($destination_path) -cne 'project-cleanup')
    {
        throw 'skill_install.destination_name_rejected'
    }
    $destination_prefix = $destination_path + [System.IO.Path]::DirectorySeparatorChar
    $source_prefix = $source_directory.TrimEnd([char[]]@('/', '\')) + [System.IO.Path]::DirectorySeparatorChar
    if ([string]::Equals($destination_path, $tool_path, [System.StringComparison]::OrdinalIgnoreCase) -or
        $tool_path.StartsWith($destination_prefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($destination_path, $source_directory, [System.StringComparison]::OrdinalIgnoreCase) -or
        $destination_path.StartsWith($source_prefix, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw 'skill_install.tool_location_overlap'
    }
    assert_no_reparse_path $destination_path
    $parent_path = [System.IO.Path]::GetDirectoryName($destination_path)
    if ([string]::IsNullOrEmpty($parent_path))
    {
        throw 'skill_install.destination_parent_invalid'
    }
    $exists = Test-Path -LiteralPath $destination_path
    if ($exists)
    {
        if (-not (Get-Item -LiteralPath $destination_path -Force).PSIsContainer)
        {
            throw 'skill_install.destination_not_directory'
        }
        $existing_inventory = get_tree_inventory $destination_path
        $owner_path = Join-Path $destination_path $owner_name
        if (-not [System.IO.File]::Exists($owner_path))
        {
            throw 'skill_install.unowned_destination'
        }
        if ((Get-Item -LiteralPath $owner_path -Force).Length -gt 1048576)
        {
            throw 'skill_install.ownership_file_too_large'
        }
        $owner = [System.IO.File]::ReadAllText($owner_path, $utf8) | ConvertFrom-Json
        if ($owner.client -cne $Client -or
            -not [string]::Equals($owner.tool_readme, $readme_path, [System.StringComparison]::OrdinalIgnoreCase))
        {
            throw 'skill_install.ownership_mismatch'
        }
        if ($owner.schema -ceq 'windows_agent_cleanup.skill_install.v1')
        {
            $previous_files = @('SKILL.md', $owner_name)
            assert_exact_inventory $existing_inventory $previous_files
            if ($owner.skill_sha256 -cne (get_sha256 ([System.IO.File]::ReadAllBytes((Join-Path $destination_path 'SKILL.md')))))
            {
                throw 'skill_install.ownership_mismatch'
            }
        }
        elseif ($owner.schema -ceq 'windows_agent_cleanup.skill_install.v2')
        {
            $previous_files = @(@($owner.files | ForEach-Object { $_.path }) + @($owner_name))
            assert_exact_inventory $existing_inventory $previous_files
            foreach ($record in @($owner.files))
            {
                if ($record.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    $record.sha256 -cne (get_sha256 ([System.IO.File]::ReadAllBytes((Join-Path $destination_path $record.path)))))
                {
                    throw 'skill_install.ownership_mismatch'
                }
            }
        }
        else
        {
            throw 'skill_install.ownership_mismatch'
        }
    }

    [System.IO.Directory]::CreateDirectory($parent_path) | Out-Null
    assert_no_reparse_path $parent_path
    $staging_path = Join-Path $parent_path ('.project-cleanup.stage.' + [System.Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($staging_path) | Out-Null
    $staging_files = @(@($source_records | ForEach-Object { $_.path }) + @($owner_name))
    foreach ($record in $source_records)
    {
        $target_path = Join-Path $staging_path $record.path
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target_path)) | Out-Null
        [System.IO.File]::WriteAllBytes($target_path, $record.bytes)
    }
    $owner_record = [ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v2'
        client = $Client
        tool_readme = $readme_path
        files = @($source_records | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256 } })
    }
    [System.IO.File]::WriteAllText((Join-Path $staging_path $owner_name), ($owner_record | ConvertTo-Json -Depth 5 -Compress), $utf8)
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
        remove_owned_tree $backup_path $previous_files
        $backup_path = $null
    }
    $status = 'installed'
    if ($exists)
    {
        $status = 'updated'
    }
    [ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v2'
        status = $status
        client = $Client
        destination = $destination_path
        readme = $readme_path
        files = $source_records.Count
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
            remove_owned_tree $staging_path $staging_files
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
    [Console]::Error.WriteLine((([ordered]@{
        schema = 'windows_agent_cleanup.skill_install.v2'
        status = 'failed'
        error_code = $failure_code
        cleanup_pending = $cleanup_pending
        recovery_directory = $backup_path
    }) | ConvertTo-Json -Compress))
    exit 1
}
