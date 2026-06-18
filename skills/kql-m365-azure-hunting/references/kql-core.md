# KQL Core Reference

## Defaults

- Start large-table queries with a time filter.
- Prefer `let lookback = 7d;` for reusable windows.
- Use `project` to keep only needed columns before joins.
- Use `summarize` to reduce rows before expensive pivots.
- Use `parse_json()` or `todynamic()` before accessing dynamic properties when a field may be stored as a string.

## Safe Query Skeleton

```kql
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ConnectionSuccess", "SslConnectionInspected")
| project Timestamp, DeviceId, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| summarize ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| order by ConnectionCount asc
```

## Joins

- Join on stable keys: device identifiers, alert identifiers, account identifiers, IP plus port when appropriate.
- Reduce each side before joining.
- Prefer `kind=innerunique` when the left side should be de-duplicated.
- Use time-window predicates after joins when event time proximity matters.

```kql
let lookback = 7d;
let network =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | project NetworkTime=Timestamp, DeviceId, RemoteIP, RemotePort, InitiatingProcessFileName;
let process =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | project ProcessTime=Timestamp, DeviceId, InitiatingProcessFileName, ProcessCommandLine;
network
| join kind=inner process on DeviceId, InitiatingProcessFileName
| where abs(datetime_diff('minute', NetworkTime, ProcessTime)) <= 5
```

## Dynamic Fields

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| extend Additional = todynamic(AdditionalFields)
| extend Ja4 = tostring(Additional.ja4), Sni = tostring(Additional.server_name)
| where isnotempty(Ja4) or isnotempty(Sni)
```

## Anti-Patterns

- No time filter on high-volume tables.
- Direct high-cardinality joins before filtering.
- `materialize()` around a broad base scan.
- `contains` when `has` or exact equality would be more selective.
- Returning every column when the answer needs a small entity set.