# Example: Sub-Agent Result

This example is synthetic and offline.

```text
agent_name: Host Investigation Agent
scope: Investigate process, file, network, and persistence activity on HOST-042 from T-24h to T+24h around the seed.
entities investigated: HOST-042, winword.exe, powershell.exe, suspicious.example
queries or data sources used: DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents; drafted only, not executed
key findings: The seed process chain is suspicious because Office spawned encoded PowerShell. No execution results are available in this offline example.
evidence references: F1 from the evidence ledger
confidence level: Medium for suspicious process chain; Unknown for compromise
recommended next pivots: process tree, file writes after PowerShell, network prevalence, email delivery, sign-ins for user@example.com
dead ends: none yet
open questions: Was the encoded command decoded safely by an analyst? Did the user receive a matching email? Did other hosts contact the same domain?
```
