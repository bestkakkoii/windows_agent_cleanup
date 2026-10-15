#requires -version 5.1
[CmdletBinding()]
param([switch]$repair, [string]$cache_root)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source_root = Split-Path -Parent $PSScriptRoot
if (-not $cache_root)
{
    $cache_root = Join-Path $source_root 'build/dependencies'
}
$cache_root = [IO.Path]::GetFullPath($cache_root)
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
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

function get_git_blob_sha1([string]$path)
{
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try
    {
        $algorithm = [Security.Cryptography.SHA1]::Create()
        try
        {
            $prefix = [Text.Encoding]::ASCII.GetBytes('blob ' + $stream.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + [char]0)
            [void]$algorithm.TransformBlock($prefix, 0, $prefix.Length, $prefix, 0)
            $buffer = New-Object byte[] 65536
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0)
            {
                [void]$algorithm.TransformBlock($buffer, 0, $count, $buffer, 0)
            }
            [void]$algorithm.TransformFinalBlock((New-Object byte[] 0), 0, 0)
            return [BitConverter]::ToString($algorithm.Hash).Replace('-', '').ToLowerInvariant()
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

try
{
    $lock = Get-Content -LiteralPath (Join-Path $source_root 'dependencies.lock.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($lock.schema -ne 'secure_erase.dependencies.v2' -or @($lock.dependencies).Count -ne 1)
    {
        throw 'dependency.lock_schema_rejected'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    foreach ($dependency in $lock.dependencies)
    {
        if ($dependency.name -ne 'dear_imgui' -or $dependency.directory -ne ('imgui/' + $dependency.commit) -or
            $dependency.repository -ne 'https://github.com/ocornut/imgui' -or $dependency.commit -notmatch '^[0-9a-f]{40}$')
        {
            throw 'dependency.lock_rejected'
        }
        foreach ($entry in $dependency.files)
        {
            if ($entry.path -notmatch '^(backends/)?[a-zA-Z0-9_]+\.(h|cpp|txt)$' -or
                $entry.sha256 -notmatch '^[0-9a-f]{64}$' -or $entry.git_blob_sha1 -notmatch '^[0-9a-f]{40}$' -or $entry.size -lt 1 -or $entry.size -gt 16777216)
            {
                throw 'dependency.path_or_digest_rejected'
            }
            $destination = Join-Path (Join-Path $cache_root $dependency.directory) $entry.path
            if (Test-Path -LiteralPath $destination -PathType Leaf)
            {
                $actual = get_file_sha256 $destination
                if ($actual -eq $entry.sha256 -and (Get-Item -LiteralPath $destination).Length -eq $entry.size -and
                    (get_git_blob_sha1 $destination) -eq $entry.git_blob_sha1)
                {
                    continue
                }
                if (-not $repair)
                {
                    throw ('dependency.integrity_failed: ' + $entry.path + '; use -repair only to restore upstream bytes')
                }
            }
            $parent = Split-Path -Parent $destination
            [void][IO.Directory]::CreateDirectory($parent)
            $temporary = $destination + '.' + [Guid]::NewGuid().ToString('N') + '.download'
            try
            {
                $uri = 'https://raw.githubusercontent.com/ocornut/imgui/' + $dependency.commit + '/' + $entry.path
                Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $temporary -TimeoutSec 60
                $actual = get_file_sha256 $temporary
                if ($actual -ne $entry.sha256 -or (Get-Item -LiteralPath $temporary).Length -ne $entry.size -or
                    (get_git_blob_sha1 $temporary) -ne $entry.git_blob_sha1)
                {
                    throw ('dependency.download_integrity_failed: ' + $entry.path)
                }
                Move-Item -LiteralPath $temporary -Destination $destination -Force
                [Console]::Out.WriteLine((@{event='dependency.restored';path=$entry.path;sha256=$actual} | ConvertTo-Json -Compress))
            }
            finally
            {
                if (Test-Path -LiteralPath $temporary)
                {
                    Remove-Item -LiteralPath $temporary -Force
                }
            }
        }
    }
    [Console]::Out.WriteLine('{"event":"dependency.verified","exit_code":0}')
    exit 0
}
catch
{
    [Console]::Out.WriteLine((@{event='dependency.failed';error=$_.Exception.Message;exit_code=1} | ConvertTo-Json -Compress))
    exit 1
}
