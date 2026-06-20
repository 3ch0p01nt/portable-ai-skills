# Example: Final Report Skeleton

This skeleton is synthetic and offline.

## 1. Executive Summary

One paragraph explaining what happened, the verdict, severity, and confidence.

## 2. Seed Event Summary

- Original event:
- Why it was investigated:
- Key entities extracted:

## 3. Investigation Timeline

| Time | Entity | Activity | Evidence |
| --- | --- | --- | --- |
| 2026-06-18T14:22:11Z | HOST-042 | Office spawned encoded PowerShell. | F1 |

## 4. Key Findings

| Finding | Evidence | Confidence | MITRE ATT&CK |
| --- | --- | --- | --- |
| Office-to-PowerShell execution is suspicious. | F1 | Medium | Execution |

## 5. Root Cause Assessment

Most likely root cause, supporting evidence, gaps, and uncertainty.

## 6. Scope / Blast Radius

Affected users, hosts, resources, related indicators, and scope classification.

## 7. Suspicious Activity Discovered

Additional suspicious events found during pivoting and how they link to the seed.

## 8. Dead Ends / Ruled-Out Leads

Threads investigated that did not produce meaningful evidence and why they were closed.

## 9. Recommended Analyst Actions

- Immediate read-only validation:
- Actions requiring approval:
- Remediation:
- Detection improvements:
- Follow-up:

## 10. Queries Run

| Purpose | Query or pivot | Data source | Time range | Result summary | Execution status |
| --- | --- | --- | --- | --- | --- |
| Process tree | Drafted endpoint process query | DeviceProcessEvents | T-24h to T+24h | Query drafted only; no live results. | Execution status: not executed |

## 11. Evidence Ledger

| Finding ID | Entity | Claim | Evidence | Source | Timestamp | Confidence | MITRE ATT&CK |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F1 | HOST-042, powershell.exe | Office spawned encoded PowerShell. | Analyst-provided seed. | Seed event | 2026-06-18T14:22:11Z | Medium | T1059.001 |

## 12. Open Questions

- What remains unknown?
- What telemetry would resolve it?
