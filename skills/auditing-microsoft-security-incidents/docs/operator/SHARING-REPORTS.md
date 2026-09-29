# Sharing Reports

Use the shareable-report converter to create sanitized outputs for review. Never share `protected\`, `bundle.json`, raw adapter pages, tokens, or tenant-specific working folders.

## Usage

```powershell
pwsh -File .\skills\auditing-microsoft-security-incidents\scripts\ConvertTo-HavocShareableReport.ps1 -InputDirectory .\havoc-output\pilot-001 -OutputDirectory .\havoc-output\pilot-001-shareable
```

Optional parameters:

- `-AdditionalTerms` for extra customer terms that must be replaced.
- `-ScrubHashes` when hashes should also be pseudonymized.

The output directory must not be the input directory and must not be under `InputDirectory\protected`.

## What is scrubbed

The converter pseudonymizes common tenant and evidence identifiers in `report.md` and `report.json`, including tenant-like identifiers, protected references, accounts, hostnames, IP-style values, URLs, and harvested customer terms. It writes a forward map for the shareable bundle and keeps the reverse map under `protected\` in the source output tree.

## Fail-closed behavior

After scrubbing, a residual check searches for remaining harvested or operator-supplied terms. If any remain, shareable outputs are not written. Fix the input or add required `-AdditionalTerms`, then rerun.

Share only the sanitized output directory after review. Keep the source output and `protected\` restricted to authorized operators.
