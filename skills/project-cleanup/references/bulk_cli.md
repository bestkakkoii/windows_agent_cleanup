# Bulk CLI contract

## Bind and compose

Use the executable identified by `tool_location.md`. Filesystem commands require
an already elevated token on Windows 11+ x64. `capabilities`, `--version` and
`--help` are non-mutating structured queries and work without elevation.
Capabilities use `windows_agent_cleanup.capabilities.v1`. Bind once for an
unknown executable revision; reuse for unchanged consecutive jobs.

Use one absolute local-drive authorization root per request. A root authorizes
checks within it; it does not select all its contents. Use absolute literal
target paths, without wildcards, alternate data stream syntax or dot components.
A directory target selects its existing descendants under native preparation
rules. Keep separate selected hardlink names even when they share an object.

Create the manifest outside the root and every target. Reports must be outside
the root in both directions: neither directory may contain the other. Use a
writable existing parent and let the CLI create a protected private report
store. Reuse a store only when its access/integrity/exclusive-lock checks pass.
Do not substitute an arbitrary existing directory or weaken its ACLs.

Stream JSONL with a standard JSON serializer and UTF-8 **without BOM**:

```jsonl
{"path":"C:\\work\\demo\\build"}
{"path":"C:\\work\\demo\\scratch_result.bin"}
```

For a programmatically discovered stream of already approved literal paths,
PowerShell can serialize each record without loading the whole list:

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

Bind `$approved_path_stream` to the reviewed discovery stream, not every file
under the root. Do not use shell string concatenation to produce JSON.

Each line is one object containing only `path` for quick mode. Blank lines,
unknown/duplicate fields, malformed UTF-8 and a BOM are rejected. Native parsing
also rejects UNC/device paths, NUL, empty/dot components and components ending
in a dot or space; paths must fit 32,760 UTF-16 code units. A final newline is
optional. Do not manually escape paths or pass huge arrays through shell
command arguments. The bundled manifest schema describes object fields; native
parsing and preparation enforce these additional path/scope rules. These paths
are format examples, not selections or authorization.

## Invoke

In PowerShell, bind `$cli`, `$root`, `$manifest` and `$report_dir` to literal
absolute paths from the selected installation/job; use a fresh request ID:

```powershell
& $cli run --mode quick --request-id cleanup_001 --root $root `
  --manifest $manifest --report-dir $report_dir --authorize-irreversible
```

For scan only replace `run` with `scan` and omit `--authorize-irreversible`;
scan rejects that flag. Request IDs contain 1–128 ASCII letters, digits, `_` or
`-`. Use the host process API with an argument array where available. Never
construct shell code from a path or evaluate input as code.

Quick scans are advisory. A quick run performs its own preparation, freezes the
entire batch and revalidates identity before mutation. It does not consume a
previous scan as authority. Added/replaced names are not admitted by retries.
No fixed target-count limit is imposed; current RAM, commit, CPU, handles and
disk control admission and scheduling. A batch that cannot reserve complete
staging/report capacity or compact metadata is refused before deletion.
Per-target preparation refusals remain recorded failures while other eligible
targets can execute. Never truncate a batch to fit a guessed limit.

## Resource and retention controls

Omit overrides for automatic quick scheduling. `--workers 0` and
`--memory-bytes 0` select automatic budgets; explicit values constrain requests
and do not guarantee admission. `--io-bytes-per-second` and
`--ssd-queue-depth` apply only to overwrite. Retention flags are
`--log-retention-days` and `--checkpoint-retention-days` (0–36,500 days).
Defaults are 30 days for engine event logs and `0` for incomplete checkpoints;
checkpoint retention `0` keeps them until completion or explicit policy/removal.
These flags do not expire the CLI's per-request `*.report.jsonl` files. Manage
those reports and manifests separately after completion is reconciled; do not
remove an active store or needed recovery evidence.

Keep manifests and diagnostic stores private and outside the source repository
when practical; paths can be sensitive. Ephemeral quick scratch is not a
recoverable saved plan. Overwrite checkpoints contain protected recovery state
and restore no authorization: every resume requires fresh explicit consent.
