# Overwrite and explicit process actions

Use this reference only after the user specifically chooses one of these
operations. Ordinary quick-plan authorization does not authorize overwrite,
downgrade, process termination or privilege-policy changes.

## Authenticated overwrite recovery

An overwrite scan persists an authenticated pending plan and returns `job_id`
(32 lowercase hexadecimal characters), `plan_fingerprint` (64 lowercase
hexadecimal characters) and `resumable`. Read back the result and use the same
root and protected report store. Resume is overwrite-only and takes no `--mode`:

```powershell
& $cli resume --request-id cleanup_resume_001 --root $root `
  --report-dir $report_dir --job-id $job_id `
  --plan-fingerprint $plan_fingerprint --authorize-irreversible
```

Bind variables from the authenticated scan/result and chosen installation;
never invent fingerprints or IDs. Membership is never re-enumerated. An
optional resume `--manifest` contains only exact individual namespace records
with an independently authorized `allow_downgrade` value, `delete_only` or
`overwrite_best_effort`. Grants must match observed capability; a directory
grant does not authorize descendants. Quick manifests reject downgrade grants.
A changed capability requires new independent consent. Logical overwrite,
Flush and full readback do not prove removal of historical NAND/snapshot data.

## Lock inspection and normal close

Use a selected target's exact `target_key` from its quick scan report:

```powershell
& $cli locks --request-id lock_check_001 --root $root `
  --report-dir $report_dir --path $path --target-key $target_key
```

For a separately authorized normal close, obtain the fresh lock report's exact
`pid`, `created` and `image` tuple:

```powershell
& $cli release --request-id release_001 --root $root `
  --report-dir $report_dir --path $path --target-key $target_key `
  --pid $selected_pid --created $created --image $image --authorize-close
```

These commands return one result object with `mode: process`; detailed lock
records are in `report_file`. The 64-character lowercase hexadecimal
`target_key` binds the exact selected namespace, not a directory's hidden child.
Preserve `created` as an exact unsigned 64-bit integer/decimal string; do not
round it through JavaScript `Number`. Avoid PowerShell's read-only `$PID`;
use `$selected_pid` for command construction.

Add release-only `--authorize-force` solely after independent fresh approval
for that exact process. Never infer it from a cleanup plan,
`--authorize-irreversible`, `--authorize-close`, an old PID or a failed normal
close. The native core rejects changed/ineligible process and target identities.
Do not preemptively inspect locks, add force flags or bypass protected processes.
