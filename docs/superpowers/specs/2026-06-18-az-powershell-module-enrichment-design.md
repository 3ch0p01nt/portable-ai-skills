# Az PowerShell Module Enrichment Design

## Goal

Add read-only Azure PowerShell Az module guidance to the portable `kql-m365-azure-hunting` skill pack so an AI can validate Azure, Log Analytics, and Sentinel context without mutating resources.

## Source Findings

Microsoft documents Azure PowerShell as the collection of official Microsoft PowerShell modules for managing Azure resources. The current Azure PowerShell module is `Az`, a cross-platform rollup module that wraps service-specific modules. PowerShell 7 or higher is recommended, and the deprecated `AzureRM` and legacy `Azure` modules should not be used for new work.

Azure PowerShell authentication supports interactive sign-in, service principals, managed identities, Azure Cloud Shell, and Docker. For this skill, the safe default is interactive or already-authenticated Cloud Shell use, followed by explicit tenant and subscription selection with `Set-AzContext`.

The modules most relevant to this skill are:

- `Az.Accounts` for authentication and context.
- `Az.Resources` for resource group and resource discovery.
- `Az.OperationalInsights` for Log Analytics workspaces, tables, schema, saved searches, workspace usage, and read-only KQL execution.
- `Az.SecurityInsights` for Microsoft Sentinel alert rules, rule templates, data connectors, incidents, bookmarks, entities, and threat intelligence indicators.
- `Az.ResourceGraph` for Azure Resource Graph resource inventory when the user asks for Azure resource state rather than workspace telemetry.

## Design Changes

### New reference file

Add `references\azure-powershell-az.md` as the Az module operating guide. It should cover:

- When to use Az PowerShell versus KQL, Sentinel, Defender Advanced Hunting, Azure Resource Graph, or Azure CLI.
- Installing/importing `Az` for local use and noting that Cloud Shell has Az preinstalled.
- Authenticating with `Connect-AzAccount`.
- Selecting and verifying context with `Get-AzContext`, `Get-AzSubscription`, and `Set-AzContext`.
- Discovering workspaces with `Get-AzOperationalInsightsWorkspace`.
- Inspecting workspace tables/schema with `Get-AzOperationalInsightsTable` and `Get-AzOperationalInsightsSchema`.
- Running read-only KQL with `Invoke-AzOperationalInsightsQuery`.
- Inventorying Sentinel with `Get-AzSentinelDataConnector`, `Get-AzSentinelAlertRule`, `Get-AzSentinelAlertRuleTemplate`, and `Get-AzSentinelIncident`.
- Using `Search-AzGraph` for resource inventory when Resource Graph is the correct surface.

### Existing reference updates

Update `SKILL.md` so Az module questions load `references\azure-powershell-az.md` plus `references\sentinel-azure.md`, `references\table-catalog.md`, or `references\query-review.md` as needed.

Update `references\sentinel-azure.md` to point to the Az module reference for live workspace/rule/connector discovery.

Update `references\query-review.md` so operational answers are reviewed for context safety, read-only intent, no secret disclosure, and no mutating cmdlets.

### Examples and tests

Add examples for:

- Context verification and tenant/subscription selection.
- Workspace discovery and table/schema inventory.
- Read-only Log Analytics KQL execution.
- Sentinel connector, analytics rule, rule template, and incident inventory.
- Azure Resource Graph read-only resource inventory.

Add offline fixtures that require the AI to:

- Choose the correct Az module for the task.
- Refuse `New-*`, `Set-*`, `Update-*`, and `Remove-*` cmdlets in read-only mode unless the user explicitly changes scope.
- Confirm tenant, subscription, resource group, and workspace before live commands.
- Avoid printing tokens, shared keys, or credentials.
- Explain whether a request belongs in Az PowerShell, KQL, Defender Advanced Hunting, Sentinel, or Resource Graph.

## Guardrails

Default to commercial Azure and M365 cloud behavior. Do not switch to `.us` endpoints or sovereign-cloud assumptions unless the user asks or tenant evidence requires it.

Never assume the current Az context is safe. Require the AI to show context verification steps before any live Azure query.

Keep v1 read-only. Avoid `New-Az*`, `Set-Az*`, `Update-Az*`, and `Remove-Az*` examples except to explain that they are out of scope for this version.

Do not expose secrets. Avoid `Get-AzOperationalInsightsWorkspaceSharedKey` unless the user explicitly requests shared-key administration and the task is no longer read-only.

## Self-Review

- The design adds Az module guidance without expanding into full Azure operations.
- The design keeps the portable skill static/offline while teaching safe live-validation patterns.
- The design separates Az PowerShell operations from KQL, Sentinel rule YAML, and table catalog references.
- No placeholders remain.
