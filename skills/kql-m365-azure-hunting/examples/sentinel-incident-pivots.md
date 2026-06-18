# Sentinel Incident Pivot Example

## Prompt

Start from recent Sentinel incidents and pivot to related alerts.

## Query

```kql
let lookback = 14d;
SecurityIncident
| where TimeGenerated > ago(lookback)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentTime=TimeGenerated, IncidentNumber, Title, Severity, Status, AlertIds
| mv-expand AlertId = AlertIds to typeof(string)
| join kind=leftouter (
    SecurityAlert
    | where TimeGenerated > ago(lookback)
    | project AlertTime=TimeGenerated, SystemAlertId, AlertName, ProviderName, Entities
) on $left.AlertId == $right.SystemAlertId
| project IncidentTime, IncidentNumber, Title, Severity, Status, AlertTime, AlertName, ProviderName, Entities
```

## Notes

This query assumes `AlertIds` aligns to `SecurityAlert.SystemAlertId` in the workspace. If the workspace uses a different connector shape, inspect a small sample before relying on the join.
