# Bad Query Rewrites

## Unsafe Input

```kql
DeviceNetworkEvents
| join DeviceProcessEvents on DeviceId
| summarize count() by RemoteUrl
```

## Findings

- No time filter.
- High-volume tables are joined before filtering.
- Join key is too broad.
- Output loses device and process context.

## Safer Rewrite

```kql
let lookback = 7d;
let network =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where isnotempty(RemoteUrl)
    | project NetworkTime=Timestamp, DeviceId, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessUniqueId, InitiatingProcessFileName;
let process =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | project ProcessTime=Timestamp, DeviceId, ProcessUniqueId, FileName, ProcessCommandLine;
network
| join kind=inner process on DeviceId, $left.InitiatingProcessUniqueId == $right.ProcessUniqueId
// Near-start filter: omit or widen for general long-lived process enrichment.
| where abs(datetime_diff('minute', NetworkTime, ProcessTime)) <= 5
| summarize ConnectionCount=count(), FirstSeen=min(NetworkTime), LastSeen=max(NetworkTime) by DeviceId, FileName, ProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by ConnectionCount desc
```
