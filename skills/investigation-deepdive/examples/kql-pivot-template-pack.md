# KQL Pivot Template Pack Example

This example is synthetic and offline. It shows how to return a KQL pivot packet without claiming execution.

## Pivot Packet

Purpose: Check domain prevalence after a workbook anomaly.

Data source: Defender XDR Advanced Hunting.

Time range: 30 days.

Query:

```kql
let lookback = 30d;
let targetUrlOrDomain = "https://credential-review.example/login";
let parsedTarget = parse_url(targetUrlOrDomain);
let targetHost = tolower(iff(isnotempty(tostring(parsedTarget.Host)), tostring(parsedTarget.Host), targetUrlOrDomain));
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| extend RemoteHost = tolower(iff(RemoteUrl startswith "http", tostring(parse_url(RemoteUrl).Host), RemoteUrl))
| where tolower(RemoteUrl) =~ tolower(targetUrlOrDomain) or RemoteHost =~ targetHost or RemoteHost endswith strcat(".", targetHost)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), DeviceCount=dcount(DeviceName), UserCount=dcount(InitiatingProcessAccountUpn), Processes=make_set(InitiatingProcessFileName, 20) by RemoteUrl, RemoteHost, RemoteIP
| order by DeviceCount desc, EventCount desc
```

Expected result shape: one row per domain, extracted host, and IP pair with first seen, last seen, device count, user count, and process set.

How to interpret results: single-host prevalence can support targeted investigation, while many hosts may indicate business infrastructure, simulation, or broad campaign activity.

Execution status: not executed.
