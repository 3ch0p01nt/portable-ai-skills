# YARA Execution Runbook Template

Status: requires current source verification and authorized forensic evidence.

## Select the correct source

| Target | Source |
|---|---|
| RayInitiator and LINE VIPER on legacy ASA 5500-X core evidence | NCSC `RayInitiator & LINE VIPER` MAR |
| FIRESTARTER disk/injector | CISA AR26-113A `CISA_261290_01` |
| FIRESTARTER memory/shellcode | CISA AR26-113A `CISA_261290_02` |

Do not substitute one family's rules for another.

## Preconditions

- Evidence collection was authorized.
- Original evidence is write-protected and independently hashed.
- Analysis uses a copy whose hash is recorded.
- Rule source URL, version, date, license, and downloaded SHA-256 are recorded.
- The analyst knows the rule's tested platform/version limits.

## Execution record

```text
Case:
Artifact ID:
Original SHA-256:
Analysis-copy SHA-256:
Rule source/version:
Rule-file SHA-256:
Tool/version:
Command:
Start/end UTC:
Matches:
Errors:
Analyst:
```

## Interpretation

- A match is a strong artifact requiring independent corroboration and authority escalation.
- No match does not clear untested versions, alternate process names, victim-specific variants, or other persistence layers.
- Tool errors, truncated evidence, decompression failure, or unsupported format produce an evidence gap, not a negative result.

Do not copy proprietary signatures into this bundle. Cache rules only when redistribution rights are confirmed.
