# Azure PowerShell Az Reference

Use this reference when a user asks how to use Az modules, validate Azure/Sentinel/Log Analytics context, discover workspace schema, run read-only workspace KQL, or inventory Sentinel objects.

## Scope

This skill version is read-only. Prefer `Get-Az*`, `Search-AzGraph`, and read-only `Invoke-AzOperationalInsightsQuery` workflows. Do not use `New-Az*`, `Set-Az*`, `Update-Az*`, or `Remove-Az*` unless the user explicitly changes scope away from read-only validation.

## What Az Is

`Az` is the current Azure PowerShell rollup module. It wraps service-specific modules such as `Az.Accounts`, `Az.Resources`, `Az.OperationalInsights`, `Az.SecurityInsights`, and `Az.ResourceGraph`.

Use `Az`, not deprecated `AzureRM` or legacy `Azure` modules.

PowerShell 7 or higher is recommended. Azure Cloud Shell already includes Az; local machines may need installation.

## Install and Import

```powershell
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
Import-Module Az.Accounts
Import-Module Az.OperationalInsights
Import-Module Az.SecurityInsights
Import-Module Az.ResourceGraph
```

If installation is blocked by policy, use Azure Cloud Shell or ask the user how modules are managed in their environment.

## Authentication and Context

Never assume the current Az context is safe. Start by showing context verification.

```powershell
Connect-AzAccount
Get-AzContext
Get-AzSubscription | Select-Object Name, Id, TenantId, State
Set-AzContext -Tenant '<tenant-id>' -Subscription '<subscription-id>'
Get-AzContext | Select-Object Account, Tenant, Subscription
```

Use managed identity only when running inside an Azure resource configured for it:

```powershell
Connect-AzAccount -Identity
Get-AzContext
```

## Choosing the Right Surface

| User need | Use |
|---|---|
| Run hunting KQL against a Log Analytics workspace | `Invoke-AzOperationalInsightsQuery` |
| Inspect Sentinel rules, incidents, connectors, or templates | `Az.SecurityInsights` `Get-AzSentinel*` cmdlets |
| Inspect workspace tables, schema, usage, or saved searches | `Az.OperationalInsights` `Get-AzOperationalInsights*` cmdlets |
| Inventory Azure resources and configuration state | `Search-AzGraph` from `Az.ResourceGraph` |
| Write telemetry query text only | KQL references, not Az |
| Query Defender Advanced Hunting | Defender XDR hunting API or portal, not Az PowerShell |

## Workspace Discovery

```powershell
$workspaces = Get-AzOperationalInsightsWorkspace
$workspaces | Select-Object Name, ResourceGroupName, Location, CustomerId
```

For a known workspace:

```powershell
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName '<resource-group>' -Name '<workspace-name>'
$workspace | Select-Object Name, ResourceGroupName, Location, CustomerId, ResourceId
```

Do not print shared keys in normal hunting workflows. Avoid `Get-AzOperationalInsightsWorkspaceSharedKey` in this read-only skill.

## Table and Schema Discovery

```powershell
Get-AzOperationalInsightsTable -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, Plan, RetentionInDays, TotalRetentionInDays

Get-AzOperationalInsightsSchema -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object -ExpandProperty Tables |
    Select-Object Name
```

Use schema discovery before writing KQL against custom tables or uncertain connector tables.

## Read-Only KQL Execution

```powershell
$query = @'
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize IncidentCount=count() by Severity, Status
| order by IncidentCount desc
'@

Invoke-AzOperationalInsightsQuery -WorkspaceId '<workspace-customer-id>' -Query $query
```

Guidance:

- Use bounded time filters.
- Prefer the workspace customer ID for `-WorkspaceId`.
- State that live execution depends on permissions and connector/table availability.
- Do not claim results unless the command was actually run.

## Sentinel Inventory

Use `Az.SecurityInsights` for Sentinel objects. These cmdlets require workspace resource group and name.

```powershell
Get-AzSentinelDataConnector -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, Kind

Get-AzSentinelAlertRule -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, DisplayName, Enabled, Severity, Kind

Get-AzSentinelAlertRuleTemplate -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, DisplayName, Severity, Kind

Get-AzSentinelIncident -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' |
    Select-Object Name, Title, Severity, Status, CreatedTimeUtc
```

## Azure Resource Graph Inventory

Use Resource Graph for Azure resource state, not Sentinel telemetry.

```powershell
$query = @'
Resources
| where type =~ "microsoft.network/publicipaddresses"
| project name, resourceGroup, subscriptionId, location, ipAddress=tostring(properties.ipAddress)
| order by subscriptionId, resourceGroup, name
'@

Search-AzGraph -Query $query
```

## Safety Checklist

- Confirm tenant and subscription with `Get-AzContext`.
- Confirm resource group and workspace name before Sentinel or Log Analytics commands.
- Keep commands read-only unless the user explicitly changes scope.
- Do not output tokens, credentials, shared keys, or connection strings.
- Default to commercial Azure. Do not switch to `.us` or sovereign cloud assumptions unless the user asks or tenant evidence requires it.
- Explain when a request belongs to KQL, Az PowerShell, Defender Advanced Hunting, Sentinel, Log Analytics, or Azure Resource Graph.
