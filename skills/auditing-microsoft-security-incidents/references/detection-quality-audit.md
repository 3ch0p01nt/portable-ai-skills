# Detection Quality Audit

## Table of contents

- [Purpose](#purpose)
- [Inputs](#inputs)
- [Trace chain](#trace-chain)
- [Defect classes](#defect-classes)
- [Settings assessment](#settings-assessment)
- [Verification gaps](#verification-gaps)
- [Runner read operations](#runner-read-operations)
- [References](#references)

## Purpose

The detection quality audit explains whether the Sentinel or Defender rule that produced an alert was fit for the incident narrative. It is read-only and operates only over records already collected by the runner. Missing records become coverage gaps rather than inferred facts.

## Inputs

`New-HavocDetectionQualityAudit` accepts an incident, alerts, an optional analytics rule record, SentinelHealth rows, SentinelAudit rows, and an optional raw event sample. The analytics rule record is the ARM GET result for `Microsoft.SecurityInsights/alertRules`. The raw event sample should include table or connector name, projected columns, and synthetic row evidence when safely available.

## Trace chain

The audit traces incident to alerts, generating rule, deployed query and template version, execution health, raw events, entity mappings, grouping, and enrichment. Each hop reports `present`, `missing`, or `mismatch` and the evidence IDs used for that status.

## Defect classes

- `rule-logic`: rule identity, MITRE mapping, severity mapping, threshold, frequency, lookback, or intended behavior conflicts with supplied evidence.
- `data-quality`: raw events, connector assumptions, projected identifiers, schema, false-positive notes, or blind spots do not support the rule.
- `entity-mapping`: rule entity mappings do not match projected identifiers, raw columns, or emitted alert entities.
- `grouping`: incident creation, alert grouping, suppression, or incident settings conflict with the incident and alerts.
- `enrichment`: alert details overrides or enrichment templates reference unavailable identifiers or present unsupported context.
- `execution-health`: SentinelHealth indicates failed execution or supplied execution evidence is inconsistent.

## Settings assessment

The settings assessment records query surface, required identifiers, entity mappings, MITRE and severity mapping, frequency, lookback, threshold, grouping, suppression, incident settings, raw sample limits, alert count, entity count, known false positives, blind spots, execution evidence, and whether safe replay evidence was supplied. Historical replay is not performed by this audit.

## Verification gaps

Coverage gaps are emitted for missing rule records, execution health, change audit rows, raw event samples, entity mappings, and absent safe replay evidence when raw events are not supplied. Gaps are explicit because evidence is untrusted and the function must not guess from titles, names, or narratives.

## Runner read operations

The runner needs these commercial read surfaces:

- ARM analytics rule read: `management.azure.com` path `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules/{ruleId}` with `api-version=2025-09-01`.
- Log Analytics SentinelHealth query over the incident and detection execution window:

```kusto
SentinelHealth
| where TimeGenerated between (datetime(<start-utc>) .. datetime(<end-utc>))
| where SentinelResourceId == "<rule-resource-id>"
| project TimeGenerated, SentinelResourceId, SentinelResourceKind, OperationName, Status, Reason, Description
```

- Log Analytics SentinelAudit query over the rule change window:

```kusto
SentinelAudit
| where TimeGenerated between (datetime(<start-utc>) .. datetime(<end-utc>))
| where SentinelResourceId == "<rule-resource-id>"
| project TimeGenerated, SentinelResourceId, OperationName, Status, Caller, ExtendedProperties
```

The current request policy permits the analytics rule GET through `sentinel-analytics-rule-get` and the SentinelHealth or SentinelAudit queries through `log-analytics-query`.

## References

- Microsoft Learn: Microsoft Sentinel analytics rules, `https://learn.microsoft.com/azure/sentinel/detect-threats-built-in`
- Microsoft Learn: Microsoft Sentinel health monitoring, `https://learn.microsoft.com/azure/sentinel/monitor-data-connector-health`
- Microsoft Learn: Microsoft Sentinel audit and health tables, `https://learn.microsoft.com/azure/azure-monitor/reference/tables/sentinelaudit`
- Microsoft Learn: Microsoft Sentinel alert rule ARM resource, `https://learn.microsoft.com/azure/templates/microsoft.securityinsights/alertrules`
