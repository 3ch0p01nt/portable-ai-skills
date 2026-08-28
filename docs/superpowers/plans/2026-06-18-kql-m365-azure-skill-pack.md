# KQL M365 Azure Skill Pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Git-downloadable Superpowers skill pack that teaches an AI with no KQL, M365 Defender, Sentinel, Azure, or Az PowerShell background how to write, review, and safely validate hunting-focused KQL.

**Architecture:** Use a layered skill pack: one root `SKILL.md` controls workflow and guardrails, while focused references provide KQL, M365 Defender, Sentinel/Azure, Azure PowerShell Az, and query-review knowledge. The first version is static and offline, with prompt fixtures as acceptance tests and no tenant scripts or credentials; Az module guidance is read-only and teaches safe live-validation patterns without mutating resources.

**Tech Stack:** Markdown, Superpowers skill format, PowerShell validation commands, Git.

---

## File Structure

- Create: `README.md` - repo overview, Git install instructions, usage examples, offline constraints.
- Create: `skills\kql-m365-azure-hunting\SKILL.md` - skill entry point and operating flow.
- Create: `skills\kql-m365-azure-hunting\references\kql-core.md` - KQL rules, idioms, and anti-patterns.
- Create: `skills\kql-m365-azure-hunting\references\m365-defender.md` - Defender XDR Advanced Hunting concepts, tables, and pivots.
- Create: `skills\kql-m365-azure-hunting\references\sentinel-azure.md` - Sentinel, Log Analytics, Azure, and Resource Graph context.
- Create: `skills\kql-m365-azure-hunting\references\query-review.md` - mandatory KQL review gate.
- Create: `skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md` - Sentinel analytics rule and hunting query YAML structure.
- Create: `skills\kql-m365-azure-hunting\references\table-catalog.md` - table meanings, key fields, connector mappings, and query surface boundaries.
- Create: `skills\kql-m365-azure-hunting\references\example-style-guide.md` - portable detection/example wrapper format and source attribution rules.
- Create: `skills\kql-m365-azure-hunting\references\azure-powershell-az.md` - read-only Az PowerShell module usage for context, Log Analytics, Sentinel, and Resource Graph validation.
- Create: `skills\kql-m365-azure-hunting\examples\defender-network-hunting.md` - Defender network hunting examples.
- Create: `skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md` - Sentinel incident pivot examples.
- Create: `skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md` - unsafe query rewrites.
- Create: `skills\kql-m365-azure-hunting\examples\sentinel-rule-yaml.md` - analytics rule and hunting query YAML examples.
- Create: `skills\kql-m365-azure-hunting\examples\multi-source-union.md` - multi-source `union isfuzzy=true` and Windows event duality examples.
- Create: `skills\kql-m365-azure-hunting\examples\portable-detection-wrapper.md` - KQLSearch/GitHub-style markdown detection wrapper example.
- Create: `skills\kql-m365-azure-hunting\examples\az-readonly-validation.md` - Az PowerShell read-only validation examples.
- Create: `tests\prompt-fixtures.md` - offline acceptance prompts.
- Create: `tests\expected-behaviors.md` - expected skill behavior for each prompt.

## Task 1: Repository Skeleton and Offline Acceptance Fixtures

**Files:**
- Create: `README.md`
- Create: `tests\prompt-fixtures.md`
- Create: `tests\expected-behaviors.md`

- [ ] **Step 1: Initialize Git and directories**

Run:

```powershell
git init
New-Item -ItemType Directory -Force -Path '.\skills\kql-m365-azure-hunting\references','.\skills\kql-m365-azure-hunting\examples','.\tests' | Out-Null
```

Expected: `git init` exits 0 and all three directories exist.

- [ ] **Step 2: Write failing acceptance fixtures first**

Create `tests\prompt-fixtures.md` with this content:

```markdown
# Prompt Fixtures

These prompts are offline acceptance fixtures for the `kql-m365-azure-hunting` skill. A worker uses them to verify the skill can guide an AI with no prior KQL, M365 Defender, Sentinel, or Azure context.

## Fixture 1: Defender network hunt

User prompt:

```text
Write a Defender Advanced Hunting query that finds rare outbound TLS connections by process over the last 7 days and explains how to tune false positives.
```

## Fixture 2: Sentinel incident pivot

User prompt:

```text
Write Sentinel KQL that starts from recent SecurityIncident rows and pivots to related alert evidence, keeping the query bounded and explainable.
```

## Fixture 3: Bad KQL rewrite

User prompt:

```text
Fix this query: DeviceNetworkEvents | join DeviceProcessEvents on DeviceId | summarize count() by RemoteUrl
```

## Fixture 4: Missing schema context

User prompt:

```text
Use the ContosoCustomThreatTable table to hunt OAuth consent attacks.
```

## Fixture 5: Azure Resource Graph boundary

User prompt:

```text
Write a query to find public IP resources in Azure and explain whether it belongs in Sentinel or Azure Resource Graph.
```
```

- [ ] **Step 3: Write expected offline behaviors**

Create `tests\expected-behaviors.md` with this content:

```markdown
# Expected Behaviors

## Fixture 1: Defender network hunt

- Classifies the target as M365 Defender Advanced Hunting.
- Loads `references\kql-core.md`, `references\m365-defender.md`, and `references\query-review.md`.
- Uses `DeviceNetworkEvents` with a bounded time filter.
- Aggregates by process and remote entity before ranking rarity.
- Includes false-positive tuning guidance.

## Fixture 2: Sentinel incident pivot

- Classifies the target as Sentinel or Log Analytics.
- Loads `references\kql-core.md`, `references\sentinel-azure.md`, and `references\query-review.md`.
- Starts from `SecurityIncident` with a bounded time filter.
- Pivots to alert data without unbounded joins.
- Explains workspace/schema assumptions.

## Fixture 3: Bad KQL rewrite

- Flags the original query as unsafe because it has no time filter and joins high-volume tables directly.
- Rewrites with scoped `let` bindings and bounded join keys.
- Explains why early filtering and cardinality control matter.

## Fixture 4: Missing schema context

- Does not invent columns for `ContosoCustomThreatTable`.
- States that custom schema details are required.
- Offers a schema-discovery query shape without claiming live validation.

## Fixture 5: Azure Resource Graph boundary

- Identifies Azure Resource Graph as the correct query surface for resource inventory.
- Explains that Resource Graph uses KQL-like syntax but is not the same execution surface as Sentinel Log Analytics.
- Provides an Azure Resource Graph query and notes when Sentinel would be appropriate.
```

- [ ] **Step 4: Verify the first acceptance check fails before the skill exists**

Run:

```powershell
if (Test-Path '.\skills\kql-m365-azure-hunting\SKILL.md') { throw 'Root skill exists too early' } else { 'Expected fail state: root skill is not created yet' }
```

Expected: command exits 0 and prints `Expected fail state: root skill is not created yet`.

- [ ] **Step 5: Create initial README**

Create `README.md` with this content:

```markdown
# KQL M365 Azure Hunting Skill Pack

This repository contains a portable Superpowers-compatible skill pack for teaching an AI assistant how to write and review KQL for M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure, and Azure Resource Graph workflows.

## Scope

- Static offline skill content.
- No tenant credentials.
- No Azure or M365 live validation scripts.
- Commercial `.com` cloud terminology by default.
- `.us` cloud guidance only when the user asks for it or provides tenant evidence.

## Install from Git

Clone the repository into a named folder and enter it:

```powershell
git clone '<repository-url>' kql-m365-azure-hunting-skill-pack
Set-Location .\kql-m365-azure-hunting-skill-pack
```

Copy `skills\kql-m365-azure-hunting` into the local Superpowers skills directory used by the target AI tool.

## Use

Ask the AI to use the `kql-m365-azure-hunting` skill before writing or reviewing KQL that touches M365 Defender, Sentinel, Log Analytics, Azure, or Azure Resource Graph.

## Offline Validation

Use `tests\prompt-fixtures.md` and `tests\expected-behaviors.md` to check whether the skill selects the right references, avoids invented schema, writes bounded KQL, and applies the query-review checklist.
```

- [ ] **Step 6: Commit**

Run:

```powershell
git add README.md tests\prompt-fixtures.md tests\expected-behaviors.md
git commit -m "test: define portable skill acceptance fixtures"
```

Expected: commit exits 0.

## Task 2: Root Skill Entry Point

**Files:**
- Create: `skills\kql-m365-azure-hunting\SKILL.md`

- [ ] **Step 1: Run failing root-skill validation**

Run:

```powershell
if (-not (Test-Path '.\skills\kql-m365-azure-hunting\SKILL.md')) { 'Expected fail state: SKILL.md missing'; exit 0 } else { throw 'SKILL.md already exists' }
```

Expected: command exits 0 and prints `Expected fail state: SKILL.md missing`.

- [ ] **Step 2: Create the root skill**

Create `skills\kql-m365-azure-hunting\SKILL.md` with this content:

```markdown
# KQL M365 Azure Hunting

Use this skill when a user asks for KQL, M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure Resource Graph, or Azure security-hunting help.

## Mission

Make a blank AI safe and useful for hunting-oriented KQL. The AI must classify the query surface, load the smallest relevant reference set, state assumptions, produce bounded KQL, and run the query-review checklist before answering.

## Reference Selection

- Defender Advanced Hunting: read `references\kql-core.md`, `references\m365-defender.md`, and `references\query-review.md`.
- Sentinel or Log Analytics: read `references\kql-core.md`, `references\sentinel-azure.md`, and `references\query-review.md`.
- Azure Resource Graph: read `references\kql-core.md`, `references\sentinel-azure.md`, and `references\query-review.md`.
- Query review only: read `references\query-review.md` and the domain reference matching the query surface.
- Concept explanation: read the smallest reference that covers the requested concept.

## Operating Flow

1. Classify the user request as Defender Advanced Hunting, Sentinel or Log Analytics, Azure Resource Graph, general Azure, or conceptual explanation.
2. Identify known tables, known columns, unknown schema details, time range, and expected output.
3. Load the selected references.
4. Draft the answer or KQL.
5. Apply every relevant item in `references\query-review.md`.
6. Return assumptions, KQL, explanation, tuning guidance, and optional validation steps.

## Required Guardrails

- Default to commercial `.com` Azure and M365 terminology.
- Do not use `.us` guidance unless the user asks or tenant evidence requires it.
- Do not invent table names, column names, tenant IDs, resource names, or live results.
- Require time filters on high-volume telemetry tables.
- Avoid broad `materialize()` over large scans.
- Prefer early filters, scoped `let` bindings, bounded joins, and explainable entity pivots.
- Treat live validation as optional because this skill pack is static and offline.
- Refuse destructive or mutating Azure/M365 operations in v1; offer read-only inventory, validation, or review alternatives instead.

## Answer Shape

For KQL generation:

1. `Assumptions`
2. `Query`
3. `How it works`
4. `Tuning`
5. `Validation notes`

For KQL review:

1. `Findings`
2. `Corrected query`
3. `Why the changes matter`
4. `Remaining assumptions`
```

- [ ] **Step 3: Verify root skill references required files**

Run:

```powershell
$text = Get-Content '.\skills\kql-m365-azure-hunting\SKILL.md' -Raw
@('references\kql-core.md','references\m365-defender.md','references\sentinel-azure.md','references\query-review.md') | ForEach-Object {
  if ($text -notlike "*$_*") { throw "Missing reference $_" }
}
'Root skill references all required files'
```

Expected: command exits 0 and prints `Root skill references all required files`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\SKILL.md
git commit -m "feat: add KQL M365 Azure root skill"
```

Expected: commit exits 0.

## Task 3: KQL Core Reference

**Files:**
- Create: `skills\kql-m365-azure-hunting\references\kql-core.md`

- [ ] **Step 1: Run failing KQL reference validation**

Run:

```powershell
if (-not (Test-Path '.\skills\kql-m365-azure-hunting\references\kql-core.md')) { 'Expected fail state: KQL core reference missing'; exit 0 } else { throw 'KQL core reference already exists' }
```

Expected: command exits 0 and prints `Expected fail state: KQL core reference missing`.

- [ ] **Step 2: Create the KQL core reference**

Create `skills\kql-m365-azure-hunting\references\kql-core.md` with this content:

```markdown
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
    | project NetworkTime=Timestamp, DeviceId, RemoteIP, RemotePort, InitiatingProcessUniqueId, InitiatingProcessFileName;
let process =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | project ProcessTime=Timestamp, DeviceId, ProcessUniqueId, FileName, ProcessCommandLine;
network
| join kind=inner process on DeviceId, $left.InitiatingProcessUniqueId == $right.ProcessUniqueId
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
```

- [ ] **Step 3: Verify KQL reference covers core rules**

Run:

```powershell
$text = Get-Content '.\skills\kql-m365-azure-hunting\references\kql-core.md' -Raw
@('time filter','joins','dynamic','materialize','Safe Query Skeleton') | ForEach-Object {
  if ($text -notmatch [regex]::Escape($_)) { throw "Missing KQL topic $_" }
}
'KQL core reference covers required topics'
```

Expected: command exits 0 and prints `KQL core reference covers required topics`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\references\kql-core.md
git commit -m "feat: add KQL core reference"
```

Expected: commit exits 0.

## Task 4: M365 Defender Reference

**Files:**
- Create: `skills\kql-m365-azure-hunting\references\m365-defender.md`

- [ ] **Step 1: Run failing Defender reference validation**

Run:

```powershell
if (-not (Test-Path '.\skills\kql-m365-azure-hunting\references\m365-defender.md')) { 'Expected fail state: Defender reference missing'; exit 0 } else { throw 'Defender reference already exists' }
```

Expected: command exits 0 and prints `Expected fail state: Defender reference missing`.

- [ ] **Step 2: Create the Defender reference**

Create `skills\kql-m365-azure-hunting\references\m365-defender.md` with this content:

```markdown
# M365 Defender Advanced Hunting Reference

## Query Surface

Defender Advanced Hunting queries Microsoft Defender XDR data. Common hunting tables include `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `IdentityLogonEvents`, `CloudAppEvents`, `AlertInfo`, and `AlertEvidence`.

## Core Patterns

- Process investigation starts with `DeviceProcessEvents`.
- Network investigation starts with `DeviceNetworkEvents`.
- File investigation starts with `DeviceFileEvents`.
- Email investigation starts with `EmailEvents`, then pivots to `EmailUrlInfo` or `UrlClickEvents`.
- Incident or alert investigation starts with `AlertInfo`, then pivots to `AlertEvidence`.

## Network Rarity Pattern

```kql
let lookback = 7d;
let minHosts = 1;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ConnectionSuccess", "SslConnectionInspected")
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
| summarize HostCount=dcount(DeviceId), ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| where HostCount <= minHosts
| order by ConnectionCount asc, LastSeen desc
```

## Alert Evidence Pivot

```kql
let lookback = 14d;
AlertInfo
| where Timestamp > ago(lookback)
| project AlertId, Timestamp, Title, Severity, Category
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | project AlertId, EntityType, EvidenceRole, DeviceId, DeviceName, AccountName, RemoteIP, FileName, SHA256
) on AlertId
```

## Schema Discipline

- If a table or column is custom, ask for schema or provide a discovery query shape.
- Do not assume `AdditionalFields` is dynamic; parse it with `todynamic()` when accessing nested properties.
- If process fields are empty on network sensor events, pivot by `DeviceId`, `RemoteIP`, `RemotePort`, and time proximity to process or connection rows that carry process context.
```

- [ ] **Step 3: Verify Defender reference covers tables and pivots**

Run:

```powershell
$text = Get-Content '.\skills\kql-m365-azure-hunting\references\m365-defender.md' -Raw
@('DeviceProcessEvents','DeviceNetworkEvents','AlertInfo','AlertEvidence','Network Rarity Pattern','Schema Discipline') | ForEach-Object {
  if ($text -notmatch [regex]::Escape($_)) { throw "Missing Defender topic $_" }
}
'Defender reference covers required topics'
```

Expected: command exits 0 and prints `Defender reference covers required topics`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\references\m365-defender.md
git commit -m "feat: add M365 Defender hunting reference"
```

Expected: commit exits 0.

## Task 5: Sentinel and Azure Reference

**Files:**
- Create: `skills\kql-m365-azure-hunting\references\sentinel-azure.md`

- [ ] **Step 1: Run failing Sentinel/Azure reference validation**

Run:

```powershell
if (-not (Test-Path '.\skills\kql-m365-azure-hunting\references\sentinel-azure.md')) { 'Expected fail state: Sentinel Azure reference missing'; exit 0 } else { throw 'Sentinel Azure reference already exists' }
```

Expected: command exits 0 and prints `Expected fail state: Sentinel Azure reference missing`.

- [ ] **Step 2: Create the Sentinel/Azure reference**

Create `skills\kql-m365-azure-hunting\references\sentinel-azure.md` with this content:

```markdown
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
    | project IncidentTime=TimeGenerated, IncidentName=Name, IncidentNumber, Title, Severity, Status, AlertIds;
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
```

- [ ] **Step 3: Verify Sentinel/Azure reference covers boundaries**

Run:

```powershell
$text = Get-Content '.\skills\kql-m365-azure-hunting\references\sentinel-azure.md' -Raw
@('SecurityIncident','SecurityAlert','AzureActivity','Azure Resource Graph','commercial Azure','Boundary Rules') | ForEach-Object {
  if ($text -notmatch [regex]::Escape($_)) { throw "Missing Sentinel/Azure topic $_" }
}
'Sentinel Azure reference covers required topics'
```

Expected: command exits 0 and prints `Sentinel Azure reference covers required topics`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\references\sentinel-azure.md
git commit -m "feat: add Sentinel Azure reference"
```

Expected: commit exits 0.

## Task 6: Query Review Checklist

**Files:**
- Create: `skills\kql-m365-azure-hunting\references\query-review.md`

- [ ] **Step 1: Run failing checklist validation**

Run:

```powershell
if (-not (Test-Path '.\skills\kql-m365-azure-hunting\references\query-review.md')) { 'Expected fail state: query review reference missing'; exit 0 } else { throw 'Query review reference already exists' }
```

Expected: command exits 0 and prints `Expected fail state: query review reference missing`.

- [ ] **Step 2: Create the query-review checklist**

Create `skills\kql-m365-azure-hunting\references\query-review.md` with this content:

```markdown
# Query Review Checklist

Run this checklist before returning KQL or reviewing user-provided KQL.

## Syntax

- Query has a valid table or query root.
- Pipes are ordered so filters happen before summarization and joins.
- `let` names are descriptive and referenced correctly.
- Dynamic fields are parsed before property access.

## Scope and Performance

- High-volume tables have a bounded time filter.
- Each join side is filtered and projected before joining.
- Join keys are explicit and stable.
- Broad `materialize()` over a large base scan is avoided.
- Output columns are limited to what the user needs.

## Schema Integrity

- Known Microsoft tables and columns are used accurately.
- Custom tables or columns are treated as unknown until schema is provided.
- The answer states assumptions when schema, connector, or tenant context is missing.

## Hunting Quality

- The query explains what signal it finds.
- False-positive tuning is included when detections or hunts are proposed.
- Severity is not overstated without evidence.
- Live validation is not claimed unless it was actually performed.

## Final Answer Gate

If any required item fails, revise the KQL before answering. If revision requires tenant schema details, ask for schema or provide a safe schema-discovery query shape.
```

- [ ] **Step 3: Verify checklist covers review gates**

Run:

```powershell
$text = Get-Content '.\skills\kql-m365-azure-hunting\references\query-review.md' -Raw
@('Syntax','Scope and Performance','Schema Integrity','Hunting Quality','Final Answer Gate') | ForEach-Object {
  if ($text -notmatch [regex]::Escape($_)) { throw "Missing checklist section $_" }
}
'Query review checklist covers required gates'
```

Expected: command exits 0 and prints `Query review checklist covers required gates`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\references\query-review.md
git commit -m "feat: add KQL review checklist"
```

Expected: commit exits 0.

## Task 7: Source-Derived Reference Files

**Files:**
- Create: `skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md`
- Create: `skills\kql-m365-azure-hunting\references\table-catalog.md`
- Create: `skills\kql-m365-azure-hunting\references\example-style-guide.md`
- Modify: `skills\kql-m365-azure-hunting\SKILL.md`

- [ ] **Step 1: Run failing source-reference validation**

Run:

```powershell
$expected = @(
  '.\skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md',
  '.\skills\kql-m365-azure-hunting\references\table-catalog.md',
  '.\skills\kql-m365-azure-hunting\references\example-style-guide.md'
)
$existing = $expected | Where-Object { Test-Path $_ }
if ($existing.Count -eq 0) { 'Expected fail state: source-derived references missing'; exit 0 } else { throw 'Source-derived references already exist' }
```

Expected: command exits 0 and prints `Expected fail state: source-derived references missing`.

- [ ] **Step 2: Create Sentinel rule-structure reference**

Create `skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md` with this content:

```markdown
# Sentinel Rule Structure Reference

## Scheduled Analytics Rule YAML

```yaml
id: 00000000-0000-0000-0000-000000000000
name: Example rule name
description: |
  Explain the detection intent, signal, and expected investigation value.
severity: Medium
kind: Scheduled
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
query: |
  let queryPeriod = 1h;
  SigninLogs
  | where TimeGenerated > ago(queryPeriod)
  | where ResultType != "0"
  | extend AccountName = tostring(split(UserPrincipalName, "@")[0])
  | extend AccountUPNSuffix = tostring(split(UserPrincipalName, "@")[1])
  | project TimeGenerated, UserPrincipalName, AccountName, AccountUPNSuffix, IPAddress, AppDisplayName, ResultType
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
eventGroupingSettings:
  aggregationKind: SingleAlert
version: 1.0.0
metadata:
  source:
    kind: Community
  support:
    tier: Community
  categories:
    domains:
      - Security - Threat Protection
```

## Required Rule Metadata

- `id`: UUID for the rule.
- `name`: human-readable rule name.
- `description`: detection intent and investigation value.
- `severity`: `Informational`, `Low`, `Medium`, or `High`.
- `kind`: `Scheduled` or `NRT`.
- `requiredDataConnectors`: connector IDs and dataTypes that provide the referenced tables.
- `queryFrequency`: how often Sentinel runs a Scheduled rule.
- `queryPeriod`: how far back the query looks; must be greater than or equal to `queryFrequency`.
- `triggerOperator` and `triggerThreshold`: most scheduled detections use `gt` and `0`.
- `query`: KQL body.
- `entityMappings`: maps projected query columns to Sentinel entities.
- `tactics` and `relevantTechniques`: MITRE ATT&CK mapping.
- `eventGroupingSettings`: `SingleAlert` or `AlertPerResult`.
- `customDetails`: optional alert enrichment columns.
- `alertDetailsOverride`: optional dynamic title, description, severity, or tactics.
- `incidentConfiguration`: optional incident creation/grouping settings in ARM/API-backed rules.
- `version`, `status`, `tags`, and `metadata`: lifecycle, category, support, and source details.

## Hunting Query YAML

Hunting query YAML resembles analytics rule YAML but usually omits scheduling and trigger fields. Keep `name`, `description`, `requiredDataConnectors`, `tactics`, `relevantTechniques`, `query`, and `entityMappings` so bookmarks and investigations have context.

## Entity Mapping Rules

- Project every column referenced by `entityMappings.fieldMappings.columnName`.
- Use `Account` identifiers such as `FullName`, `Name`, and `UPNSuffix` for UPNs.
- Use `IP` identifier `Address` for IP columns.
- Use `Host` identifiers such as `HostName`, `FullName`, or `AzureID`.
- Use `URL` identifier `Url`.
- Use `FileHash` identifiers `Algorithm` and `Value` together.
- Keep entity mappings focused; Sentinel rules support a limited number of entity mappings.

## Scheduled Versus NRT

- `Scheduled` rules include `queryFrequency`, `queryPeriod`, `triggerOperator`, and `triggerThreshold`.
- `NRT` rules omit scheduled timing fields, run near real time, and must stay low-cost.
- Use Scheduled rules for baseline, prevalence, and multi-source joins.
- Use NRT only for deterministic low-cost detections.
```

- [ ] **Step 3: Create table catalog reference**

Create `skills\kql-m365-azure-hunting\references\table-catalog.md` with this content:

```markdown
# Table Catalog

## Query Surface Time Fields

| Surface | Time field | Notes |
|---|---|---|
| Defender XDR Advanced Hunting | `Timestamp` | M365 Defender tables generally use `Timestamp`. |
| Sentinel / Log Analytics | `TimeGenerated` | Workspace tables generally use `TimeGenerated`. |
| Azure Resource Graph | none required | Resource inventory is current-state unless a resource property contains time. |
| ADX custom data | schema-dependent | Confirm the table schema before writing time filters. |
| Device Query | device-query specific schema | KQL-like query surface. Do not assume Sentinel or Defender Advanced Hunting schema; confirm the Device Query schema before writing time filters. |
| Live Response | no KQL time field | Non-KQL remote shell and remediation workflow, not a query surface. |

## Defender XDR Tables

| Table | Meaning | Key fields |
|---|---|---|
| `DeviceProcessEvents` | Endpoint process creation and parent/child context | `Timestamp`, `DeviceId`, `DeviceName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName` |
| `DeviceNetworkEvents` | Endpoint network connections and inspected TLS metadata | `Timestamp`, `DeviceId`, `RemoteIP`, `RemoteUrl`, `RemotePort`, `InitiatingProcessFileName`, `AdditionalFields` |
| `DeviceFileEvents` | File create, modify, delete, and hash telemetry | `Timestamp`, `DeviceId`, `FileName`, `FolderPath`, `SHA256`, `InitiatingProcessFileName` |
| `DeviceRegistryEvents` | Registry key/value activity | `Timestamp`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `ActionType` |
| `DeviceLogonEvents` | Endpoint logon telemetry | `Timestamp`, `AccountName`, `LogonType`, `RemoteIP`, `DeviceName` |
| `AlertInfo` | Defender alert metadata | `Timestamp`, `AlertId`, `Title`, `Severity`, `Category` |
| `AlertEvidence` | Defender alert entities and evidence | `Timestamp`, `AlertId`, `EntityType`, `DeviceId`, `AccountName`, `RemoteIP`, `FileName` |
| `EmailEvents` | Defender for Office email events | `Timestamp`, `NetworkMessageId`, `RecipientEmailAddress`, `SenderFromAddress`, `Subject` |
| `EmailUrlInfo` | URLs extracted from email | `Timestamp`, `NetworkMessageId`, `Url` |
| `UrlClickEvents` | Safe Links URL click telemetry | `Timestamp`, `AccountUpn`, `Url`, `ActionType` |
| `ExposureGraphNodes` | Exposure Management graph nodes and vulnerability state | `NodeLabel`, `NodeProperties`, `Categories`, `EntityIds` |

## Sentinel / Log Analytics Tables

| Table | Meaning | Key fields |
|---|---|---|
| `SecurityIncident` | Sentinel incident records | `TimeGenerated`, `Name`, `IncidentNumber`, `Title`, `Severity`, `Status`, `AlertIds` |
| `SecurityAlert` | Sentinel and connected product alerts | `TimeGenerated`, `SystemAlertId`, `AlertName`, `ProviderName`, `Entities` |
| `SigninLogs` | Entra interactive sign-ins | `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `ResultType`, `ConditionalAccessStatus`, `AppDisplayName` |
| `AADNonInteractiveUserSignInLogs` | Entra non-interactive sign-ins | `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `ResultType`, `AppDisplayName` |
| `AuditLogs` | Entra directory and app audit events | `TimeGenerated`, `OperationName`, `Category`, `InitiatedBy`, `TargetResources` |
| `OfficeActivity` | Exchange, SharePoint, OneDrive, and Teams audit | `TimeGenerated`, `OfficeWorkload`, `Operation`, `UserId`, `ClientIP`, `Parameters` |
| `AzureActivity` | Azure Resource Manager control-plane operations | `TimeGenerated`, `OperationNameValue`, `Caller`, `CallerIpAddress`, `ResourceGroup`, `ResourceId` |
| `AzureDiagnostics` | Azure service diagnostics | `TimeGenerated`, `ResourceType`, `Category`, `ResourceId` |
| `SecurityEvent` | Windows Security Events via legacy connector | `TimeGenerated`, `EventID`, `Account`, `LogonType`, `IpAddress`, `Computer` |
| `WindowsEvent` | Windows Events via AMA | `TimeGenerated`, `EventID`, `EventData`, `Computer` |
| `CommonSecurityLog` | CEF network/security appliance logs | `TimeGenerated`, `DeviceVendor`, `DeviceProduct`, `SourceIP`, `DestinationIP`, `Activity` |
| `ThreatIntelligenceIndicator` | Threat intelligence indicators | `TimeGenerated`, `NetworkIP`, `DomainName`, `Url`, `FileHashValue`, `ExpirationDateTime` |
| `BehaviorAnalytics` | UEBA anomaly and entity behavior | `TimeGenerated`, `UserPrincipalName`, `ActivityInsights`, `InvestigationPriority` |
| `Usage` | Log Analytics ingestion and cost data | `TimeGenerated`, `DataType`, `Quantity`, `IsBillable`, `Solution` |

## Connector to Table Mapping

| Connector ID | Common tables |
|---|---|
| `AzureActiveDirectory` | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `AADServicePrincipalSignInLogs` |
| `AzureActivity` | `AzureActivity` |
| `Office365` | `OfficeActivity` |
| `MicrosoftThreatProtection` | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `AlertInfo`, `AlertEvidence` |
| `SecurityEvents` | `SecurityEvent` |
| `WindowsSecurityEvents` | `SecurityEvent`, `WindowsEvent` |
| `WindowsForwardedEvents` | `WindowsForwardedEvents` |
| `AzureMonitor(IIS)` | `W3CIISLog` |
| `WAF` | `AzureDiagnostics` for Application Gateway/WAF logs |
| `AzureFirewall` | `AzureDiagnostics` or resource-specific firewall tables depending on connector mode |
| `CEF` / `CefAma` | `CommonSecurityLog` |
| `ThreatIntelligence` / `ThreatIntelligenceTaxii` | `ThreatIntelligenceIndicator` |

## SecurityEvent Versus WindowsEvent

Use `SecurityEvent` when events are in flat columns:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType == 10
| project TimeGenerated, Account, Computer, IpAddress
```

Use `WindowsEvent` when AMA stores details in `EventData`:

```kql
WindowsEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| extend LogonType = toint(EventData.LogonType)
| where LogonType == 10
| extend Account = strcat(tostring(EventData.TargetDomainName), "\\", tostring(EventData.TargetUserName))
| extend IpAddress = tostring(EventData.IpAddress)
| project TimeGenerated, Account, Computer, IpAddress
```
```

- [ ] **Step 4: Create example style guide**

Create `skills\kql-m365-azure-hunting\references\example-style-guide.md` with this content:

```markdown
# Example Style Guide

## Portable Detection Wrapper

Use this format for examples that teach complete detections:

```markdown
# Detection Title

## Query Information

### Category

Threat Hunting

### MITRE ATT&CK Techniques

| Technique ID | Title | Link |
|---|---|---|
| T1021.001 | Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

### Description

Explain what the query detects and what security decision it supports.

### Risk

Explain why the behavior matters and what evidence increases or decreases confidence.

### False Positives

List common benign causes and tuning options.

### Blind Spots

List telemetry gaps, connector dependencies, and known ways the query can miss activity.

### Response Actions

List safe investigation steps.

### References

Link to public documentation or original source inspiration.

### Version History

| Version | Date | Impact | Notes |
|---|---|---|---|
| 1.0 | 2026-06-18 | initial | Initial portable example. |

## Defender XDR

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
```

## Sentinel

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
```
```

## Attribution Rules

- Summarize and generalize public examples instead of copying large rule bodies.
- Keep short snippets only when they teach structure or syntax.
- Link to source inspiration when known.
- State platform assumptions and connector requirements.
- Include false positives, blind spots, and response actions for detection examples.
```

- [ ] **Step 5: Update root skill reference selection**

Modify `skills\kql-m365-azure-hunting\SKILL.md` so `Reference Selection` includes:

```markdown
- Sentinel analytics rule or hunting query YAML: read `references\sentinel-rule-structure.md`, `references\kql-core.md`, `references\sentinel-azure.md`, `references\table-catalog.md`, and `references\query-review.md`.
- Table, connector, or schema question: read `references\table-catalog.md` and the matching domain reference.
- Portable example authoring: read `references\example-style-guide.md`, `references\kql-core.md`, `references\query-review.md`, and the matching domain reference.
- Device Query: read `references\table-catalog.md`, `references\kql-core.md`, and `references\query-review.md`; state that Device Query is a separate query surface from Sentinel and Defender Advanced Hunting.
- Live Response: not KQL; it is operational and remote-shell oriented, outside this read-only KQL skill except for explaining that boundary.
```

Expected: root skill points to all three new source-derived references.

- [ ] **Step 6: Verify source-derived references**

Run:

```powershell
$root = Get-Content '.\skills\kql-m365-azure-hunting\SKILL.md' -Raw
@('sentinel-rule-structure.md','table-catalog.md','example-style-guide.md') | ForEach-Object {
  if ($root -notmatch [regex]::Escape($_)) { throw "Root skill missing $_" }
}
$rule = Get-Content '.\skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md' -Raw
@('queryFrequency','queryPeriod','entityMappings','eventGroupingSettings','NRT') | ForEach-Object {
  if ($rule -notmatch [regex]::Escape($_)) { throw "Rule structure missing $_" }
}
$catalog = Get-Content '.\skills\kql-m365-azure-hunting\references\table-catalog.md' -Raw
@('SecurityEvent','WindowsEvent','DeviceNetworkEvents','ExposureGraphNodes','Connector to Table Mapping') | ForEach-Object {
  if ($catalog -notmatch [regex]::Escape($_)) { throw "Table catalog missing $_" }
}
'Source-derived references validated'
```

Expected: command exits 0 and prints `Source-derived references validated`.

- [ ] **Step 7: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\SKILL.md skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md skills\kql-m365-azure-hunting\references\table-catalog.md skills\kql-m365-azure-hunting\references\example-style-guide.md
git commit -m "feat: add source-derived KQL rule references"
```

Expected: commit exits 0.

## Task 8: Source-Derived Examples

**Files:**
- Create: `skills\kql-m365-azure-hunting\examples\defender-network-hunting.md`
- Create: `skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md`
- Create: `skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md`
- Create: `skills\kql-m365-azure-hunting\examples\sentinel-rule-yaml.md`
- Create: `skills\kql-m365-azure-hunting\examples\multi-source-union.md`
- Create: `skills\kql-m365-azure-hunting\examples\portable-detection-wrapper.md`

- [ ] **Step 1: Run failing examples validation**

Run:

```powershell
$expected = @(
  '.\skills\kql-m365-azure-hunting\examples\defender-network-hunting.md',
  '.\skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md',
  '.\skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md'
)
$existing = $expected | Where-Object { Test-Path $_ }
if ($existing.Count -eq 0) { 'Expected fail state: examples missing'; exit 0 } else { throw 'Example files already exist' }
```

Expected: command exits 0 and prints `Expected fail state: examples missing`.

- [ ] **Step 2: Create Defender network example**

Create `skills\kql-m365-azure-hunting\examples\defender-network-hunting.md` with this content:

```markdown
# Defender Network Hunting Example

## Prompt

Find rare outbound TLS connections by process over the last 7 days.

## Query

```kql
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ConnectionSuccess", "SslConnectionInspected")
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
| summarize HostCount=dcount(DeviceId), ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| where HostCount <= 2
| order by HostCount asc, ConnectionCount asc, LastSeen desc
```

## Tuning

Raise `HostCount` for larger environments. Add allowlists for known update services, browsers, EDR, and corporate proxies. Pivot suspicious rows back to `DeviceProcessEvents` by device, process name, and time proximity.
```

- [ ] **Step 3: Create Sentinel incident pivot example**

Create `skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md` with this content:

```markdown
# Sentinel Incident Pivot Example

## Prompt

Start from recent Sentinel incidents and pivot to related alerts.

## Query

```kql
let lookback = 14d;
SecurityIncident
| where TimeGenerated > ago(lookback)
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
```

- [ ] **Step 4: Create bad-query rewrite example**

Create `skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md` with this content:

```markdown
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
| where abs(datetime_diff('minute', NetworkTime, ProcessTime)) <= 5
| summarize ConnectionCount=count(), FirstSeen=min(NetworkTime), LastSeen=max(NetworkTime) by DeviceId, FileName, ProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by ConnectionCount desc
```
```

- [ ] **Step 5: Verify examples exist and include bounded KQL**

Run:

```powershell
$files = @(
  '.\skills\kql-m365-azure-hunting\examples\defender-network-hunting.md',
  '.\skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md',
  '.\skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md'
)
foreach ($file in $files) {
  $text = Get-Content $file -Raw
  if ($text -notmatch 'ago\(lookback\)') { throw "$file lacks bounded lookback usage" }
}
'Examples include bounded KQL'
```

Expected: command exits 0 and prints `Examples include bounded KQL`.

- [ ] **Step 6: Create Sentinel rule YAML example**

Create `skills\kql-m365-azure-hunting\examples\sentinel-rule-yaml.md` with this content:

```markdown
# Sentinel Rule YAML Example

## Scheduled analytics rule skeleton

```yaml
id: 00000000-0000-0000-0000-000000000000
name: RDP logon observed
description: |
  Detects successful RDP logons from Windows Security Events.
severity: Medium
kind: Scheduled
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
query: |
  let queryPeriod = 1h;
  SecurityEvent
  | where TimeGenerated > ago(queryPeriod)
  | where EventID == 4624 and LogonType == 10
  | extend AccountName = tostring(split(Account, "\\")[1])
  | project TimeGenerated, Account, AccountName, Computer, IpAddress
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
tactics:
  - LateralMovement
relevantTechniques:
  - T1021
eventGroupingSettings:
  aggregationKind: SingleAlert
version: 1.0.0
```
```

- [ ] **Step 7: Create multi-source union example**

Create `skills\kql-m365-azure-hunting\examples\multi-source-union.md` with this content:

```markdown
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
```

- [ ] **Step 8: Create portable detection wrapper example**

Create `skills\kql-m365-azure-hunting\examples\portable-detection-wrapper.md` with this content:

```markdown
# Portable Detection Wrapper Example

## Query Information

### Category

Threat Hunting

### MITRE ATT&CK Techniques

| Technique ID | Title | Link |
|---|---|---|
| T1021 | Remote Services | https://attack.mitre.org/techniques/T1021/ |

### Description

Finds successful RDP logons and prepares entity fields for Sentinel mapping.

### False Positives

Expected administrator RDP, jump hosts, vulnerability scanners, and helpdesk tooling.

### Blind Spots

Requires Windows Security Events or AMA Windows Events. Does not detect RDP if Event ID 4624 is not collected.

### Response Actions

Validate source IP, account owner, device role, and whether the logon follows expected admin workflow.

## Sentinel

```kql
let lookback = 1d;
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4624 and LogonType == 10
| extend AccountName = tostring(split(Account, "\\")[1])
| project TimeGenerated, Account, AccountName, Computer, IpAddress
```
```

- [ ] **Step 9: Verify expanded examples exist**

Run:

```powershell
$files = @(
  '.\skills\kql-m365-azure-hunting\examples\defender-network-hunting.md',
  '.\skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md',
  '.\skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md',
  '.\skills\kql-m365-azure-hunting\examples\sentinel-rule-yaml.md',
  '.\skills\kql-m365-azure-hunting\examples\multi-source-union.md',
  '.\skills\kql-m365-azure-hunting\examples\portable-detection-wrapper.md'
)
foreach ($file in $files) {
  if (-not (Test-Path $file)) { throw "$file missing" }
}
'Expanded examples exist'
```

Expected: command exits 0 and prints `Expanded examples exist`.

- [ ] **Step 10: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\examples
git commit -m "feat: add KQL hunting examples"
```

Expected: commit exits 0.

## Task 9: Source-Derived Fixture Expansion

**Files:**
- Modify: `tests\prompt-fixtures.md`
- Modify: `tests\expected-behaviors.md`

- [ ] **Step 1: Add source-derived prompt fixtures**

Append this content to `tests\prompt-fixtures.md`:

```markdown

## Fixture 6: Sentinel analytics rule YAML

User prompt:

```text
Turn this hunt into a Sentinel scheduled analytics rule YAML with connector requirements, entity mappings, MITRE tactics, and trigger settings.
```

## Fixture 7: SecurityEvent and WindowsEvent dual support

User prompt:

```text
Write Sentinel KQL for RDP lateral movement that works with both SecurityEvent and AMA WindowsEvent.
```

## Fixture 8: Query surface boundary

User prompt:

```text
This query came from Intune Device Query. Can I run it unchanged in Sentinel?
```

## Fixture 9: Portable detection wrapper

User prompt:

```text
Package this KQL as a portable detection example with MITRE mapping, false positives, blind spots, and response actions.
```
```

- [ ] **Step 2: Add source-derived expected behaviors**

Append this content to `tests\expected-behaviors.md`:

```markdown

## Fixture 6: Sentinel analytics rule YAML

- Loads `references\sentinel-rule-structure.md`, `references\table-catalog.md`, and `references\query-review.md`.
- Includes `requiredDataConnectors`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `entityMappings`, `tactics`, `relevantTechniques`, and `version`.
- Projects every column referenced by entity mappings.

## Fixture 7: SecurityEvent and WindowsEvent dual support

- Uses `union isfuzzy=true`.
- Handles flat `SecurityEvent` columns and dynamic `WindowsEvent.EventData` fields separately.
- Normalizes account and IP fields before summarizing or mapping entities.

## Fixture 8: Query surface boundary

- Explains that Device Query is a separate KQL-like surface from Sentinel and Defender Advanced Hunting.
- Treats Live Response as a non-KQL operational/remote-shell boundary, not a query surface.
- Does not claim the query can run unchanged in Sentinel.
- Offers a Sentinel translation only after identifying equivalent Sentinel tables.

## Fixture 9: Portable detection wrapper

- Uses the metadata wrapper from `references\example-style-guide.md`.
- Includes platform label, MITRE mapping, description, false positives, blind spots, response actions, references, version history, and KQL.
```

- [ ] **Step 3: Verify fixture expansion**

Run:

```powershell
$fixtures = Get-Content '.\tests\prompt-fixtures.md' -Raw
$expected = Get-Content '.\tests\expected-behaviors.md' -Raw
@('Fixture 6','Fixture 7','Fixture 8','Fixture 9') | ForEach-Object {
  if ($fixtures -notmatch $_) { throw "Prompt fixtures missing $_" }
  if ($expected -notmatch $_) { throw "Expected behaviors missing $_" }
}
'Source-derived fixtures validated'
```

Expected: command exits 0 and prints `Source-derived fixtures validated`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add tests\prompt-fixtures.md tests\expected-behaviors.md
git commit -m "test: add source-derived KQL skill fixtures"
```

Expected: commit exits 0.

## Task 10: Azure PowerShell Az Read-Only Module Guidance

**Files:**
- Create: `skills\kql-m365-azure-hunting\references\azure-powershell-az.md`
- Create: `skills\kql-m365-azure-hunting\examples\az-readonly-validation.md`
- Modify: `skills\kql-m365-azure-hunting\SKILL.md`
- Modify: `skills\kql-m365-azure-hunting\references\sentinel-azure.md`
- Modify: `skills\kql-m365-azure-hunting\references\query-review.md`
- Modify: `tests\prompt-fixtures.md`
- Modify: `tests\expected-behaviors.md`

- [ ] **Step 1: Run failing Az reference validation**

Run:

```powershell
if (-not (Test-Path '.\skills\kql-m365-azure-hunting\references\azure-powershell-az.md')) { 'Expected fail state: Az reference missing'; exit 0 } else { throw 'Az reference already exists' }
```

Expected: command exits 0 and prints `Expected fail state: Az reference missing`.

- [ ] **Step 2: Create the Az PowerShell reference**

Create `skills\kql-m365-azure-hunting\references\azure-powershell-az.md` with this content:

```markdown
# Azure PowerShell Az Reference

Use this reference when a user asks how to use Az modules, validate Azure/Sentinel/Log Analytics context, discover workspace schema, run read-only workspace KQL, or inventory Sentinel objects.

## Scope

This skill version is read-only. Prefer `Get-Az*`, `Search-AzGraph`, and read-only `Invoke-AzOperationalInsightsQuery` workflows. Resource mutation operations such as `New-Az*`, `Set-Az*`, `Update-Az*`, and `Remove-Az*` are refusals/out of scope for v1. `Set-AzContext` and `Select-AzContext` are allowed only as process-scoped context-management exceptions.

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
Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Scope Process
Get-AzContext
Get-AzSubscription | Select-Object Name, Id, TenantId, State
Set-AzContext -Scope Process -Tenant '<tenant-id>' -Subscription '<subscription-id>'
Get-AzContext | Select-Object Account, Tenant, Subscription
```

Use `Set-AzContext -Scope Process` or `Select-AzContext -Scope Process` only to select the current process context. These context-management commands do not allow resource mutation cmdlets in this read-only version.

Use managed identity only when running inside an Azure resource configured for it:

```powershell
Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Identity -Scope Process
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
    Select-Object -ExpandProperty Value |
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
- Resource mutation operations are refusals/out of scope in v1 unless explicitly redesigned.
- Do not output tokens, credentials, shared keys, or connection strings.
- Default to commercial Azure. Do not switch to `.us` or sovereign cloud assumptions unless the user asks or tenant evidence requires it.
- Explain when a request belongs to KQL, Az PowerShell, Defender Advanced Hunting, Sentinel, Log Analytics, or Azure Resource Graph.
```

- [ ] **Step 3: Update root skill reference selection**

Modify `skills\kql-m365-azure-hunting\SKILL.md` so `Reference Selection` includes this block:

```markdown
- Azure PowerShell Az module usage, Log Analytics workspace validation, Sentinel object inventory, or read-only Azure context checks: read `references\azure-powershell-az.md`.
- Read-only workspace KQL execution with Az: read `references\azure-powershell-az.md`, `references\kql-core.md`, `references\sentinel-azure.md`, `references\table-catalog.md`, and `references\query-review.md`.
- Azure resource inventory with Az modules: read `references\azure-powershell-az.md` and use Azure Resource Graph guidance when resource state is needed instead of workspace telemetry.
```

Expected: root skill points Az module questions to `references\azure-powershell-az.md`.

- [ ] **Step 4: Update Sentinel/Azure reference with Az pointer**

Append this content to `skills\kql-m365-azure-hunting\references\sentinel-azure.md`:

```markdown

## Live Validation with Az PowerShell

For read-only live validation, use `references\azure-powershell-az.md`.

- Use `Get-AzOperationalInsightsWorkspace` to discover Log Analytics workspaces.
- Use `Get-AzOperationalInsightsTable` and `Get-AzOperationalInsightsSchema` to inspect table availability before writing KQL for custom or uncertain schemas.
- Use `Invoke-AzOperationalInsightsQuery` to run bounded KQL against a workspace when the user explicitly wants live validation.
- Use `Get-AzSentinelDataConnector`, `Get-AzSentinelAlertRule`, `Get-AzSentinelAlertRuleTemplate`, and `Get-AzSentinelIncident` for read-only Sentinel inventory.
- Use `Search-AzGraph` when the user asks about Azure resource inventory or configuration state.
```

Expected: Sentinel/Azure reference delegates read-only Az operational workflows to the Az reference.

- [ ] **Step 5: Update query review with Az operational checks**

Append this content to `skills\kql-m365-azure-hunting\references\query-review.md`:

```markdown

## Az PowerShell Operational Review

Apply these checks before returning Az module commands:

- The answer verifies context with `Get-AzContext` before live commands.
- The answer requires explicit tenant, subscription, resource group, and workspace when needed.
- The answer uses read-only cmdlets by default: `Get-Az*`, `Search-AzGraph`, or `Invoke-AzOperationalInsightsQuery`.
- Resource mutation operations are refusals/out of scope in v1 unless explicitly redesigned.
- The answer does not print tokens, credentials, shared keys, or connection strings.
- The answer distinguishes Az PowerShell resource/workspace operations from KQL query text and Defender Advanced Hunting.
```

Expected: query review includes context safety, read-only intent, and no-secret checks for Az answers.

- [ ] **Step 6: Create Az read-only examples**

Create `skills\kql-m365-azure-hunting\examples\az-readonly-validation.md` with this content:

```markdown
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

Resource mutation operations are refusals/out of scope in v1 unless explicitly redesigned:

```powershell
New-AzSentinelAlertRule
Set-AzOperationalInsightsWorkspace
Update-AzSentinelIncident
Remove-AzSentinelAlertRule
```
```

- [ ] **Step 7: Add Az prompt fixtures**

Append this content to `tests\prompt-fixtures.md`:

```markdown

## Fixture 10: Az context and workspace validation

User prompt:

```text
Show me how to use Az modules to confirm my tenant, subscription, and Sentinel workspace before running KQL.
```

## Fixture 11: Az read-only Log Analytics query

User prompt:

```text
Use Az PowerShell to run a read-only Log Analytics query that counts Sentinel incidents by severity.
```

## Fixture 12: Az Sentinel inventory

User prompt:

```text
Use Az modules to list Sentinel data connectors, analytics rules, and incidents for a workspace.
```

## Fixture 13: Az mutation refusal

User prompt:

```text
Use Az PowerShell to delete disabled Sentinel analytics rules from my workspace.
```

## Fixture 14: Live Response boundary

User prompt:

```text
Is Defender Live Response just another KQL query surface, and can I use this skill to run Live Response commands?
```

## Fixture 15: Az create/update/set mutation refusal

User prompt:

```text
Use Az PowerShell to create a Sentinel analytics rule, update workspace settings, and set rule properties.
```
```

- [ ] **Step 8: Add Az expected behaviors**

Append this content to `tests\expected-behaviors.md`:

```markdown

## Fixture 10: Az context and workspace validation

- Loads `references\azure-powershell-az.md`.
- Uses `Disable-AzContextAutosave -Scope Process`, `Connect-AzAccount -Scope Process`, `Get-AzContext`, `Get-AzSubscription`, `Set-AzContext -Scope Process`, and `Get-AzOperationalInsightsWorkspace`.
- Requires explicit tenant, subscription, resource group, and workspace confirmation before live commands.

## Fixture 11: Az read-only Log Analytics query

- Uses `Invoke-AzOperationalInsightsQuery` with a bounded KQL query.
- States that the command depends on permissions and workspace table availability.
- Does not claim live results unless execution actually occurred.

## Fixture 12: Az Sentinel inventory

- Uses `Get-AzSentinelDataConnector`, `Get-AzSentinelAlertRule`, and `Get-AzSentinelIncident`.
- Keeps the workflow read-only.
- Explains that these are Sentinel object inventory commands, not KQL query text.

## Fixture 13: Az mutation refusal

- Refuses to provide delete commands under read-only v1 scope.
- Explains that `Remove-AzSentinelAlertRule` is mutating and out of scope.
- Offers a read-only inventory command to list disabled rules instead.

## Fixture 14: Live Response boundary

- States that Live Response is non-KQL operational/remote-shell functionality, not a query surface.
- Explains that Live Response is out of scope for this read-only KQL skill except for boundary explanation.
- Does not provide remote-shell, remediation, or Live Response command sequences.

## Fixture 15: Az create/update/set mutation refusal

- Refuses `New-Az*`, `Set-Az*`, and `Update-Az*` resource mutations under read-only v1 scope.
- Explains that creating analytics rules, setting workspace properties, and updating resources are out of scope unless the skill is explicitly redesigned for mutations.
- Offers read-only validation and inventory alternatives such as `Get-AzSentinelAlertRule`, `Get-AzOperationalInsightsWorkspace`, or `Search-AzGraph`.
```

- [ ] **Step 9: Verify Az coverage**

Run:

```powershell
$root = Get-Content '.\skills\kql-m365-azure-hunting\SKILL.md' -Raw
$az = Get-Content '.\skills\kql-m365-azure-hunting\references\azure-powershell-az.md' -Raw
$example = Get-Content '.\skills\kql-m365-azure-hunting\examples\az-readonly-validation.md' -Raw
$fixtures = Get-Content '.\tests\prompt-fixtures.md' -Raw
$expected = Get-Content '.\tests\expected-behaviors.md' -Raw
@('azure-powershell-az.md','Invoke-AzOperationalInsightsQuery','Get-AzSentinelAlertRule','Search-AzGraph','read-only') | ForEach-Object {
  if (($root + $az + $example) -notmatch [regex]::Escape($_)) { throw "Az content missing $_" }
}
@('Fixture 10','Fixture 11','Fixture 12','Fixture 13','Fixture 14','Fixture 15') | ForEach-Object {
  if ($fixtures -notmatch $_) { throw "Az prompt fixtures missing $_" }
  if ($expected -notmatch $_) { throw "Az expected behaviors missing $_" }
}
'Az module guidance validated'
```

Expected: command exits 0 and prints `Az module guidance validated`.

- [ ] **Step 10: Commit**

Run:

```powershell
git add skills\kql-m365-azure-hunting\SKILL.md skills\kql-m365-azure-hunting\references\azure-powershell-az.md skills\kql-m365-azure-hunting\references\sentinel-azure.md skills\kql-m365-azure-hunting\references\query-review.md skills\kql-m365-azure-hunting\examples\az-readonly-validation.md tests\prompt-fixtures.md tests\expected-behaviors.md
git commit -m "feat: add read-only Az PowerShell guidance"
```

Expected: commit exits 0.

## Task 11: Package Validation and README Finalization

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run package validation before README finalization**

Run:

```powershell
$required = @(
  '.\README.md',
  '.\skills\kql-m365-azure-hunting\SKILL.md',
  '.\skills\kql-m365-azure-hunting\references\kql-core.md',
  '.\skills\kql-m365-azure-hunting\references\m365-defender.md',
  '.\skills\kql-m365-azure-hunting\references\sentinel-azure.md',
  '.\skills\kql-m365-azure-hunting\references\query-review.md',
  '.\skills\kql-m365-azure-hunting\references\sentinel-rule-structure.md',
  '.\skills\kql-m365-azure-hunting\references\table-catalog.md',
  '.\skills\kql-m365-azure-hunting\references\example-style-guide.md',
  '.\skills\kql-m365-azure-hunting\references\azure-powershell-az.md',
  '.\skills\kql-m365-azure-hunting\examples\defender-network-hunting.md',
  '.\skills\kql-m365-azure-hunting\examples\sentinel-incident-pivots.md',
  '.\skills\kql-m365-azure-hunting\examples\bad-query-rewrites.md',
  '.\skills\kql-m365-azure-hunting\examples\sentinel-rule-yaml.md',
  '.\skills\kql-m365-azure-hunting\examples\multi-source-union.md',
  '.\skills\kql-m365-azure-hunting\examples\portable-detection-wrapper.md',
  '.\skills\kql-m365-azure-hunting\examples\az-readonly-validation.md',
  '.\tests\prompt-fixtures.md',
  '.\tests\expected-behaviors.md'
)
$missing = $required | Where-Object { -not (Test-Path $_) }
if ($missing) { $missing; throw 'Required files missing' }
'All required files exist'
```

Expected: command exits 0 and prints `All required files exist`.

- [ ] **Step 2: Replace README with final user-facing documentation**

Replace `README.md` with this content:

```markdown
# KQL M365 Azure Hunting Skill Pack

Portable Superpowers-compatible skill pack for KQL, M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure Resource Graph, and read-only Azure PowerShell Az validation workflows.

## What It Does

This skill teaches an AI assistant to:

- Classify the correct Microsoft query surface.
- Write bounded and explainable KQL.
- Review unsafe KQL before returning it.
- Use Az PowerShell read-only validation patterns for Azure, Log Analytics, and Sentinel context.
- Avoid invented schema, tenant facts, and live-validation claims.
- Default to commercial `.com` Microsoft cloud terminology.

## Install from Git

Clone the repository into a named folder and enter it:

```powershell
git clone '<repository-url>' kql-m365-azure-hunting-skill-pack
Set-Location .\kql-m365-azure-hunting-skill-pack
```

Copy the skill folder into the local Superpowers skills directory:

```powershell
Copy-Item -Recurse '.\skills\kql-m365-azure-hunting' '<superpowers-skills-directory>\kql-m365-azure-hunting'
```

Restart or reload the AI tool so it can discover the skill.

## Skill Entry Point

The root skill is:

```text
skills\kql-m365-azure-hunting\SKILL.md
```

## Offline Test Fixtures

Use these files to check behavior after installation:

```text
tests\prompt-fixtures.md
tests\expected-behaviors.md
```

## Constraints

- No credentials are included.
- No tenant-specific IDs are included.
- No live Azure or M365 validation scripts are included in v1.
- The AI must state assumptions when schema or connector context is missing.
- Sentinel tables depend on enabled connectors.
- Device Query is a separate KQL-like surface from Sentinel and Defender Advanced Hunting.
- Live Response is non-KQL operational remote-shell functionality and is out of scope except when explaining its boundary from query surfaces.
- Az module guidance is read-only in v1; mutating `New-Az*`, `Set-Az*`, `Update-Az*`, and `Remove-Az*` workflows are out of scope unless explicitly redesigned.
```

- [ ] **Step 3: Run final content validation**

Run:

```powershell
$root = Get-Content '.\skills\kql-m365-azure-hunting\SKILL.md' -Raw
$readme = Get-Content '.\README.md' -Raw
if ($root -notmatch 'commercial `\.com`') { throw 'Root skill does not preserve commercial cloud default' }
if ($root -notmatch 'Do not invent') { throw 'Root skill does not include schema invention guardrail' }
if ($readme -notmatch 'Install from Git') { throw 'README does not explain Git install' }
if ($readme -notmatch 'No live Azure or M365 validation scripts') { throw 'README does not state offline constraint' }
if ($readme -notmatch 'Device Query') { throw 'README does not state Device Query boundary' }
if ($readme -notmatch 'Az module guidance is read-only') { throw 'README does not state Az read-only boundary' }
'Final validation passed'
```

Expected: command exits 0 and prints `Final validation passed`.

- [ ] **Step 4: Commit**

Run:

```powershell
git add README.md
git commit -m "docs: finalize portable skill packaging"
```

Expected: commit exits 0.

## Task 12: Final Review

**Files:**
- Read: all created files

- [ ] **Step 1: Confirm clean Git state**

Run:

```powershell
git status --short
```

Expected: no output.

- [ ] **Step 2: Confirm the skill can be discovered by path**

Run:

```powershell
Get-ChildItem '.\skills\kql-m365-azure-hunting' -Recurse -File | Select-Object FullName
```

Expected: output lists `SKILL.md`, eight reference files, and seven example files.

- [ ] **Step 3: Manually review against acceptance fixtures**

Use `tests\prompt-fixtures.md` and `tests\expected-behaviors.md`. For each fixture, confirm the root skill points the AI to the correct reference files and the expected behavior is represented in the references or examples.

Expected:

```text
Fixture 1 maps to kql-core, m365-defender, query-review.
Fixture 2 maps to kql-core, sentinel-azure, query-review.
Fixture 3 maps to query-review and bad-query-rewrites.
Fixture 4 maps to schema discipline guardrails.
Fixture 5 maps to sentinel-azure Resource Graph boundary rules.
Fixture 6 maps to sentinel-rule-structure, kql-core, sentinel-azure, table-catalog, and query-review.
Fixture 7 maps to table-catalog, kql-core, and multi-source-union.
Fixture 8 maps to Device Query boundary rules.
Fixture 9 maps to example-style-guide, kql-core, query-review, and matching domain reference.
Fixture 10 maps to azure-powershell-az context and workspace validation.
Fixture 11 maps to azure-powershell-az read-only Log Analytics query execution.
Fixture 12 maps to azure-powershell-az Sentinel inventory.
Fixture 13 maps to azure-powershell-az Remove-Az* mutation refusal.
Fixture 14 maps to Live Response non-KQL boundary rules.
Fixture 15 maps to azure-powershell-az New-Az*/Set-Az*/Update-Az* mutation refusal.
```

- [ ] **Step 4: Commit only if review changes were needed**

If Step 3 required edits, run:

```powershell
git add README.md skills tests
git commit -m "docs: align skill pack with acceptance fixtures"
```

Expected: commit exits 0 if edits were made. If no edits were made, keep the existing clean state.

## Self-Review

- Spec coverage: Tasks 1 and 11 cover Git portability; Tasks 2 through 7 cover layered skill architecture and source-derived references; Task 8 covers examples; Task 9 covers source-derived fixtures; Task 10 covers read-only Az module guidance; Task 12 covers offline acceptance review.
- The plan avoids live tenant scripts and credentials.
- File paths are exact and Windows-compatible.
- Every created file has explicit content in the task that creates it.
- Commit steps include the required co-author trailer.
