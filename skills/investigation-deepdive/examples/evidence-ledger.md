# Example: Evidence Ledger

This example is synthetic and offline.

| finding_id | claim | supporting_evidence | source | timestamp | entity | confidence | mitre_mapping |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F1 | Office spawned encoded PowerShell on HOST-042. | Analyst-provided seed says `winword.exe` launched `powershell.exe` with encoded content. | Analyst-provided seed | 2026-06-18T14:22:11Z | HOST-042, user@example.com | Medium | Execution |
| F2 | The domain requires environment-wide prevalence checks. | Analyst-provided seed includes outbound contact to `suspicious.example`; no prevalence results are available yet. | Analyst-provided seed | 2026-06-18T14:22:11Z | suspicious.example | Low | Command and Control |
| F3 | Email-origin hypothesis remains plausible but unconfirmed. | Office parent process suggests document interaction; no email delivery or click telemetry has been reviewed. | Inference from seed | 2026-06-18T14:22:11Z | user@example.com | Low | Initial Access |

## Notes

- `F1` is stronger than `F2` and `F3` because it is directly tied to the seed.
- `F3` must remain a hypothesis until email telemetry supports it.
- Missing telemetry is not negative proof.
