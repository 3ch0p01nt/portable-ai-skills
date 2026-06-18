# M365 Defender Advanced Hunting Reference

## Query Surface

Defender Advanced Hunting queries Microsoft Defender XDR data. Common hunting tables include `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `IdentityLogonEvents`, `CloudAppEvents`, `AlertInfo`, and `AlertEvidence`.

## Core Patterns

- Process investigation starts with `DeviceProcessEvents`.
- Network investigation starts with `DeviceNetworkEvents`.
- File investigation starts with `DeviceFileEvents`.
- Email investigation starts with `EmailEvents`, then pivots to `EmailUrlInfo` or `UrlClickEvents`.
- Incident or alert investigation starts with `AlertInfo`, then pivots to `AlertEvidence`.

## Network Rarity Pattern

```kql
let lookback = 7d;
let minHosts = 1;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ConnectionSuccess", "SslConnectionInspected")
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
| summarize HostCount=dcount(DeviceId), ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| where HostCount <= minHosts
| order by ConnectionCount asc, LastSeen desc
```

## Alert Evidence Pivot

```kql
let lookback = 14d;
AlertInfo
| where Timestamp > ago(lookback)
| project AlertId, Timestamp, Title, Severity, Category
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | project AlertId, EntityType, EvidenceRole, DeviceId, DeviceName, AccountName, RemoteIP, FileName, SHA1, SHA256
) on AlertId
```

## Schema Discipline

- If a table or column is custom, ask for schema or provide a discovery query shape.
- Do not assume `AdditionalFields` is dynamic; parse it with `todynamic()` when accessing nested properties.
- If process fields are empty on network sensor events, pivot by `DeviceId`, `RemoteIP`, `RemotePort`, and time proximity to process or connection rows that carry process context.
- When pivoting Defender file evidence, include `SHA1`; treat `SHA256` as optional and use it when populated.
