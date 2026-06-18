# Multi-Source Union Example

Use `union isfuzzy=true` when a Sentinel rule supports multiple connectors and some tables may not exist in every workspace.

```kql
let lookback = 1d;
union isfuzzy=true
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4624 and LogonType == 10
    | project TimeGenerated, Account, Computer, IpAddress, SourceTable="SecurityEvent"
),
(
    WindowsEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4624
    | extend LogonType = toint(EventData.LogonType)
    | where LogonType == 10
    | extend Account = strcat(tostring(EventData.TargetDomainName), "\\", tostring(EventData.TargetUserName))
    | extend IpAddress = tostring(EventData.IpAddress)
    | project TimeGenerated, Account, Computer, IpAddress, SourceTable="WindowsEvent"
)
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), LogonCount=count() by Account, Computer, IpAddress, SourceTable
```
