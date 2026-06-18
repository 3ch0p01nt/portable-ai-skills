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
  | where ResultType != 0
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
