# Example: Microsoft KQL Pivot Packet

This example is synthetic and offline. Use `kql-m365-azure-hunting` to review KQL syntax and query-surface assumptions before returning it to a user.

## Pivot 1: Endpoint process tree

Purpose: Find process activity around the suspicious PowerShell seed.

Data source: Defender Advanced Hunting or Sentinel `DeviceProcessEvents`.

Time range: T-24h to T+24h around `2026-06-18T14:22:11Z`.

Query:

```kql
let seedTime = datetime(2026-06-18T14:22:11Z);
let hostName = "HOST-042";
DeviceProcessEvents
| where Timestamp between ((seedTime - 24h) .. (seedTime + 24h))
| where DeviceName =~ hostName
| where FileName in~ ("winword.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
   or InitiatingProcessFileName in~ ("winword.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

Expected result shape: chronological process rows with parent and child command lines.

How to interpret results: confirm whether Office spawned PowerShell, whether PowerShell spawned additional tools, and whether command lines suggest script execution, download, persistence, or benign automation.

Execution status: not executed.

## Pivot 2: Destination prevalence

Purpose: Check whether other hosts contacted the same domain.

Data source: Defender Advanced Hunting or Sentinel `DeviceNetworkEvents`.

Time range: T-30d.

Query:

```kql
let domain = "suspicious.example";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl =~ domain
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), Devices=dcount(DeviceName), Users=dcount(InitiatingProcessAccountUpn) by RemoteUrl, RemoteIP
| order by Devices desc, EventCount desc
```

Expected result shape: prevalence summary by domain and remote IP.

How to interpret results: single-host prevalence can support targeted compromise, while broad prevalence may indicate shared infrastructure, update behavior, or common browsing.

Execution status: not executed.
