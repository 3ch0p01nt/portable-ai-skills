# Defender Network Hunting Example

## Prompt

Find rare outbound TLS connections by process over the last 7 days.

## Query

```kql
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "SslConnectionInspected"
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
| summarize HostCount=dcount(DeviceId), ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| where HostCount <= 2
| order by HostCount asc, ConnectionCount asc, LastSeen desc
```

## Tuning

Raise `HostCount` for larger environments. Add allowlists for known update services, browsers, EDR, and corporate proxies. Pivot suspicious rows back to `DeviceProcessEvents` by device, process name, and time proximity.
