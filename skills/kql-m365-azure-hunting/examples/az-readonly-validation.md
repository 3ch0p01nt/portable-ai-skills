# Az PowerShell Read-Only Validation Examples

## Context Verification

```powershell
Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Scope Process
Get-AzSubscription | Select-Object Name, Id, TenantId, State
Set-AzContext -Scope Process -Tenant '<tenant-id>' -Subscription '<subscription-id>'
Get-AzContext | Select-Object Account, Tenant, Subscription
```

## Workspace Discovery

```powershell
Get-AzOperationalInsightsWorkspace |
    Select-Object Name, ResourceGroupName, Location, CustomerId
```

## Table and Schema Discovery

```powershell
Get-AzOperationalInsightsTable -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, Plan, RetentionInDays, TotalRetentionInDays

Get-AzOperationalInsightsSchema -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object -ExpandProperty Value |
    Select-Object Name
```

## Read-Only Workspace KQL

```powershell
$query = @'
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize IncidentCount=count() by Severity, Status
| order by IncidentCount desc
'@

Invoke-AzOperationalInsightsQuery -WorkspaceId '<workspace-customer-id>' -Query $query
```

## Sentinel Inventory

```powershell
Get-AzSentinelDataConnector -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, Kind

Get-AzSentinelAlertRule -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, DisplayName, Enabled, Severity, Kind

Get-AzSentinelIncident -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, Title, Severity, Status, CreatedTimeUtc
```

## Azure Resource Graph Inventory

```powershell
$query = @'
Resources
| where type =~ "microsoft.operationalinsights/workspaces"
| project name, resourceGroup, subscriptionId, location
| order by subscriptionId, resourceGroup, name
'@

Search-AzGraph -Query $query
```

## Out-of-Scope Mutation Examples

The read-only skill must not provide these resource mutation operations in v1:

```powershell
New-AzSentinelAlertRule
Set-AzOperationalInsightsWorkspace
Update-AzSentinelIncident
Remove-AzSentinelAlertRule
```
