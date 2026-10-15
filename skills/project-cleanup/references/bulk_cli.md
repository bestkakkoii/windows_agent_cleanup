# Bulk CLI details

[Quick kernel](../SKILL.md) owns the normal manifest/invocation/result path.
Load this reference only for extended grammar, options or caller integration.

- [Manifest details](#manifest-details)
- [Version negotiation](#version-negotiation)
- [Resource and retention controls](#resource-and-retention-controls)
- [Conditional PowerShell 5.1/7 caller example](#conditional-powershell-517-caller-example)

## Manifest details

Each BOM-free UTF-8 line is one object with only `path` in quick mode:

```jsonl
{"path":"C:\\work\\demo\\build"}
{"path":"C:\\work\\demo\\scratch_result.bin"}
```

A directory selects its existing descendants; preserve distinct selected
hardlink names. Blank lines, unknown/duplicate fields, malformed UTF-8 and BOM
are rejected. Native parsing also rejects UNC/device paths, NUL, wildcards,
ADS syntax, empty/dot components and trailing dots/spaces. Maximum path length
is 32,760 UTF-16 code units. A final newline is optional. Manifest schema covers
fields; native admission additionally enforces path/scope/protection rules.

For an approved literal path stream, use a serializer rather than concatenated
JSON. Bind a new `$manifest` outside the root/targets; do not rewrite evidence
for an already submitted request. This streaming pattern needs no full-array
materialization:

```powershell
$writer = New-Object System.IO.StreamWriter($manifest, $false, (New-Object System.Text.UTF8Encoding($false)))
try
{
    foreach ($approved_path in $approved_path_stream)
    {
        $writer.WriteLine((@{path = $approved_path} | ConvertTo-Json -Compress))
    }
}
finally
{
    $writer.Dispose()
}
```

Bind `$approved_path_stream` to established selections, never every file below
an authorization root by implication. When a separate approved-selection file
has a root JSON array and materialization is necessary, use direct assignment
`$selected = ConvertFrom-Json -InputObject $json_text`; PS5.1 pipeline wrapping
with `@(...)` can retain one nested array. That consumer-shell behavior is not
a native CLI defect. Do not infer admission counts from pipeline shape or
shell-specific date conversion. Preserve literal strings and wide integer
precision; keep raw native JSON rather than reserializing converted numbers.

## Version negotiation

Published v2.0.0 owner binaries implement v1; the distribution version does not
advertise a protocol version. A future intact runtime `release_manifest.json`
may advertise `supported_contract_versions` bound to the exact CLI hash. Only
then select `--contract-version 2` on capabilities and the operation; default
calls stay v1. For an unpackaged future engineering build, one nonmutating v2
capabilities probe may fall back to v1 only on a positively observed
unsupported-option refusal; cache the outcome by EXE identity. Never probe a
mutating command to discover support or repeat negotiation per target.

V2 capabilities uses `windows_agent_cleanup.capabilities.v2`, lists supported
versions/commands/schema references and typed `readiness`. Its observed build,
native/process architectures and effective elevation may be unknown; inspect
`observation_errors`. `filesystem_commands_ready` reflects this token/platform,
not a manifest/path/report store's admissibility. Refresh after a different
execution host or normal OS-consent handoff; do not cache mutable readiness.
The OS loader must first be able to start the EXE. Native queries never install,
self-elevate or weaken policy. The caller example below deliberately retains
the v1 route supported by the published binary.

## Resource and retention controls

Omit overrides for automatic scheduling. `--workers 0` and `--memory-bytes 0`
select automatic budgets; explicit values constrain requests without promising
admission. Complete batch admission must succeed before mutation; never truncate
targets to a guessed ceiling. `--io-bytes-per-second` and `--ssd-queue-depth`
apply only to overwrite. Retention flags `--log-retention-days` and
`--checkpoint-retention-days` accept 0–36,500 days. Defaults: 30 days for engine
event logs, `0` for incomplete checkpoints (keep until completion or explicit
policy/removal). They do not expire CLI `*.report.jsonl` files or manifests.
Manage those separately only after reconciliation; preserve active/recovery
stores and their ACLs. Quick scratch is ephemeral; overwrite state is protected
and does not carry consent for another invocation.

## Conditional PowerShell 5.1/7 caller example

This optional caller plumbing is not a required wrapper or selection engine.
First use the kernel to bind an exact EXE, approved root/manifest and native
report directory. Allocate `$request_id` once per authorized job, retain it on
host yields/reconnects, and bind `$caller_dir` to an existing private directory
outside scope. Do not allocate a new request merely to evade an earlier intent.
The example records this execution host after any normal OS-consent handoff;
it never launches an elevation helper or changes execution policy.

```powershell
$utf8 = New-Object Text.UTF8Encoding($false, $true)
[Console]::OutputEncoding = $utf8
$intent_path = Join-Path $caller_dir ($request_id + '.caller_intent.json')
$receipt_path = Join-Path $caller_dir ($request_id + '.caller_result.json')
$stderr_path = Join-Path $caller_dir ($request_id + '.stderr.txt')
function write_new_evidence([string]$path, [object]$record)
{
    $bytes = $utf8.GetBytes(($record | ConvertTo-Json -Depth 6 -Compress))
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
    finally { $file.Dispose() }
}
if ((Test-Path -LiteralPath $intent_path) -or (Test-Path -LiteralPath $receipt_path) -or
    (Test-Path -LiteralPath $stderr_path)) { throw 'caller_prior_evidence_reconcile_only' }
$host_process = [Diagnostics.Process]::GetCurrentProcess()
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try
{
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $host_record = [ordered]@{ pid = $PID; started_utc = $host_process.StartTime.ToUniversalTime().ToString('o')
        shell = $host_process.MainModule.FileName; powershell = $PSVersionTable.PSVersion.ToString()
        user_sid = $identity.User.Value; effective_admin_role = $is_admin }
}
finally { $identity.Dispose(); $host_process.Dispose() }
if (-not $is_admin) { throw 'caller_requires_authorized_os_consent_in_execution_host' }
$native_args = @('run', '--mode', 'quick', '--request-id', $request_id, '--root', $root,
    '--manifest', $manifest, '--report-dir', $reports, '--authorize-irreversible')
write_new_evidence $intent_path ([ordered]@{ request_id = $request_id; executable = $cli
    executable_sha256 = (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash
    manifest = $manifest; manifest_sha256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash
    arguments = $native_args; execution_host = $host_record; state = 'launch_intent' })
$native_stdout = @(); $native_exit = $null; $invocation_error = $null
try
{
    $global:LASTEXITCODE = $null
    $native_stdout = @(& $cli @native_args 2> $stderr_path)
    $native_exit = $LASTEXITCODE
}
catch { $invocation_error = $_.Exception.ToString() }
$stdout_text = [string]::Join("`n", [string[]]$native_stdout)
write_new_evidence $receipt_path ([ordered]@{ request_id = $request_id; exit_code = $native_exit
    stdout = $stdout_text; stderr_file = $stderr_path; invocation_error = $invocation_error })
if ($null -ne $invocation_error -or $null -eq $native_exit -or $native_stdout.Count -ne 1)
{ throw 'caller_completion_unknown_preserve_evidence' }
$result = ConvertFrom-Json -InputObject $stdout_text -ErrorAction Stop
if ($result.schema -cne 'windows_agent_cleanup.result.v1' -or $result.request_id -cne $request_id)
{ throw 'caller_result_binding_invalid_reconcile_only' }
if ($native_exit -ne 0 -or $result.status -cne 'completed' -or $result.advisory -or
    $result.counts.failed -ne 0 -or $result.counts.pending -ne 0 -or
    $result.counts.completed -ne $result.counts.targets -or -not $result.report_file)
{ throw 'caller_inspect_original_report_no_automatic_retry' }
$report_final = Get-Content -LiteralPath $result.report_file -Encoding UTF8 -Tail 1 -ErrorAction Stop
if ([string]$report_final -cne $stdout_text)
{ throw 'caller_final_report_mismatch_reconcile_only' }
```

Invoke once and wait through the host's same process/session. If a tool API
returns a session identifier, resume waiting on that identifier rather than
running this example again. Native argument arrays keep paths as data; do not
use `Invoke-Expression`. Native stderr redirection is shell-version-specific,
so retain its file and invocation error, not a parsed/filtered substitute.
Partial/missing output or a caller exception leaves evidence for the separate
[read-only reconciliation route](results_and_recovery.md#partial-missing-or-unknown-completion).
A matching success summary should also agree with the final native report;
this example does not independently prove removal or authorize another batch.
