# Sentinel and Azure Reference

## Query Surfaces

- Microsoft Sentinel and Log Analytics query workspace tables such as `SecurityIncident`, `SecurityAlert`, `AzureActivity`, `SigninLogs`, `AuditLogs`, `CommonSecurityLog`, and ingested Defender tables when connectors are enabled.
- Azure Resource Graph queries Azure resource inventory. It uses KQL-like syntax but runs against resource metadata, not Log Analytics telemetry.
- Default to commercial Azure and M365 `.com` cloud terminology.

## Sentinel Incident Pivot

```kql
let lookback = 14d;
let incidents =
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | project IncidentTime=TimeGenerated, IncidentName, IncidentNumber, Title, Severity, Status, AlertIds;
incidents
| mv-expand AlertId = AlertIds to typeof(string)
| join kind=leftouter (
    SecurityAlert
    | where TimeGenerated > ago(lookback)
    | project AlertTime=TimeGenerated, SystemAlertId, AlertName, ProviderName, Entities
) on $left.AlertId == $right.SystemAlertId
| project IncidentTime, IncidentNumber, Title, Severity, Status, AlertTime, AlertName, ProviderName, Entities
```

## Azure Activity Pattern

```kql
let lookback = 7d;
AzureActivity
| where TimeGenerated > ago(lookback)
| where ActivityStatusValue =~ "Success"
| project TimeGenerated, SubscriptionId, ResourceGroup, ResourceProviderValue, OperationNameValue, Caller, CallerIpAddress, ResourceId
| summarize OperationCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Caller, CallerIpAddress, OperationNameValue, ResourceProviderValue
| order by OperationCount desc
```

## Azure Resource Graph Pattern

```kql
Resources
| where type =~ "microsoft.network/publicipaddresses"
| project name, resourceGroup, subscriptionId, location, sku=tostring(sku.name), allocationMethod=tostring(properties.publicIPAllocationMethod), ipAddress=tostring(properties.ipAddress)
| order by subscriptionId, resourceGroup, name
```

## Boundary Rules

- Use Sentinel or Log Analytics for event telemetry and incidents.
- Use Azure Resource Graph for resource inventory and configuration posture.
- Do not assume Defender tables exist in Sentinel unless the connector or workspace context is known.
- If cloud environment is unclear, use commercial `.com` assumptions and state that sovereign cloud endpoints may differ.