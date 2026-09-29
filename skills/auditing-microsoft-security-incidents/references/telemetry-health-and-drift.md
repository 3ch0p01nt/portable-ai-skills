# Telemetry Health and Drift

## Contents

- [1. Purpose](#1-purpose)
- [2. Normative basis](#2-normative-basis)
- [3. Required records](#3-required-records)
- [4. Health interpretation rules](#4-health-interpretation-rules)
- [5. Drift and lineage rules](#5-drift-and-lineage-rules)
- [6. Detection-input health](#6-detection-input-health)
- [7. Documented health sources](#7-documented-health-sources)
- [8. Illustrative read-only KQL](#8-illustrative-read-only-kql)
- [9. Reporting language](#9-reporting-language)
- [10. Prohibited behavior](#10-prohibited-behavior)

## 1. Purpose

This reference defines the telemetry health and drift record family for the
commercial Microsoft security incident auditor. It covers source, connector,
schema, parser, DCR transformation, and detection-input health.

The goal is to prevent absence of telemetry from being treated as benign
evidence. A query that finds no events is useful only inside a verified coverage
and health boundary.

This reference extends the coverage contract in [operating-contract.md](operating-contract.md)
and the report disclosure rules in [report-contract.md](report-contract.md).
Machine-readable values MUST use [contract-vocabulary.json](contract-vocabulary.json)
and MUST remain compatible with [audit-output.schema.json](audit-output.schema.json).

## 2. Normative basis

The following requirement IDs govern this reference:

- R-017: negative evidence requires a coverage receipt.
- R-018: coverage states include healthy, degraded, failed, unmonitored,
  structurally absent, and unknown.
- R-019: absence language MUST be bounded by verified coverage.
- R-022: records preserve source event, ingestion or receipt, update, and
  retrieval clocks.
- R-036: detection audit traces incident, rule, raw events, mapping, grouping,
  enrichment, health, and history.
- R-037: historical evaluation uses bounded ad hoc query reconstruction rather
  than production detection replay.
- R-062: documented Sentinel limits and version details are recorded with their
  source page and review date.

Rows R-017 through R-036 are project methodology and MUST be labeled
`configurable_project_policy` unless an operation-specific record is a
`conditional_capability` or `explicit_gap`.

## 3. Required records

A telemetry-health record MUST include:

- `source_id` and source identity.
- `connector_id`, table name, and sensor or agent identity when observable.
- sensor or agent onboarding state.
- heartbeat, freshness, ingestion-latency, and retention observations.
- volume anomaly observations with baseline period, observed count, threshold,
  and affected time window.
- schema version and parser version.
- DCR transformation lineage, including the transformation stage and fields that
  may have been dropped, filtered, mapped, parsed, or aggregated.
- detection-input dependencies for analytics rules that consume the table or
  fields.
- an audit-output compatible `coverage_projection` that can be inserted into
  `coverage_receipts`.

The record MUST NOT include tenant IDs, subscription IDs, workspace IDs,
resource IDs, raw queries, credentials, or customer event payloads. Use an
opaque protected reference when exact details are required.

## 4. Health interpretation rules

A health gap MUST be evaluated against each negative claim's own evidence
window. A gap outside a claim's window MUST NOT weaken that claim merely because
the gap overlaps the incident window. A gap inside the claim window MUST bound
that claim even when other incident-window checks are healthy.

The pure rule is:

1. Identify negative claims from a source or table.
2. Identify heartbeat, connector, ingestion-latency, retention, or volume gaps
   whose window overlaps that specific claim's evidence window.
3. Attach the gap ID to every affected claim.
4. Replace absence wording with `not found within unverified coverage` or
   `not found within partially verified coverage`.
5. Require follow-up before using the claim to rule out activity.

A volume drop beyond the configured threshold MUST be recorded as a gap. The
threshold is project policy and MUST be emitted in the record; it MUST NOT be
represented as a universal Microsoft service limit.

Ingestion latency MUST distinguish source event time from ingestion time and
retrieval time. Late-arriving data can change a negative finding.

## 5. Drift and lineage rules

Schema drift MUST be recorded when required fields appear, disappear, change
meaning, change type, or move to a different source table.

Parser drift MUST be recorded when parser version, ASIM normalization logic,
field extraction, field mapping, or type conversion changes during or near the
incident window.

DCR transformation lineage MUST record whether transformations were client-side,
ingestion-time, multi-stage, absent, or unknown. Azure Monitor transformations
can filter or modify incoming data before it is stored in Log Analytics:
https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations

When a DCR transformation filters records at ingestion time, `not observed` is
not evidence of absence. A dropped or filtered field may make a rule, parser,
or claim non-reproducible even when the table itself is healthy.

The KQL transformation reference documents that transformations operate on
individual incoming records and support only specific operators:
https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-kql

## 6. Detection-input health

A detection-input health record MUST identify:

- analytics rule or detection ID.
- source table dependencies.
- required fields and entity mappings.
- expected schema version and parser version.
- observed schema or parser drift.
- DCR lineage that can remove or alter required records or fields.
- SentinelHealth, SentinelAudit, Usage, or Heartbeat evidence used to support or
  bound the rule-health assessment.

Schema drift in a required field MUST flag the dependent detection input.
Parser-version changes MUST flag every detection input that depends on the
affected table, even when the exact changed field is not known.

Detection-input health is not a verdict about maliciousness. It is a boundary
on rule reliability and on negative or missing-alert findings.

## 7. Documented health sources

The following Microsoft Learn pages were checked for table names and key fields.
These sources are used for commercial Log Analytics and Microsoft Sentinel
health checks only; they are not tenant calls.

- Sentinel health and audit storage: health and audit data are collected in
  `SentinelHealth` and `SentinelAudit`; Microsoft recommends the
  `_SentinelHealth()` and `_SentinelAudit()` functions for backward
  compatibility. Source:
  https://learn.microsoft.com/en-us/azure/sentinel/health-audit
- `SentinelHealth` key columns include `TimeGenerated`, `OperationName`,
  `Status`, `Reason`, `RecordId`, `SentinelResourceId`, `SentinelResourceKind`,
  `SentinelResourceName`, `SentinelResourceType`, `WorkspaceId`, and `Type`.
  Source:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/sentinelhealth
- `SentinelAudit` key columns include `TimeGenerated`, `OperationName`,
  `Status`, `CorrelationId`, `Description`, `ExtendedProperties`,
  `SentinelResourceId`, `SentinelResourceKind`, `SentinelResourceName`,
  `SentinelResourceType`, `WorkspaceId`, and `Type`. Source:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/sentinelaudit
- `Usage` is hourly usage data for each table in the workspace. Key columns
  include `TimeGenerated`, `StartTime`, `EndTime`, `DataType`, `Quantity`,
  `QuantityUnit`, `Plan`, `Solution`, and `Type`. Source:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/usage
- `Heartbeat` records Log Analytics agent health once per minute. Key columns
  include `TimeGenerated`, `Computer`, `Version`, `OSType`, `SourceSystem`,
  `ResourceId`, `_ResourceId`, `ResourceProvider`, `ResourceType`, and `Type`.
  Source:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/heartbeat

SentinelHealth and SentinelAudit support DCR workspace transformation according
to their table reference pages. Heartbeat and Usage do not support DCR workspace
transformation according to their table reference pages.

## 8. Illustrative read-only KQL

The following examples are bounded, read-only, and contain no tenant IDs. They
are illustrative packets for an adapter to parameterize with an authorized
workspace, source, and time range.

### Data connector health drifts

```kusto
let startTime = datetime(2026-09-25T09:00:00Z);
let endTime = datetime(2026-09-25T10:00:00Z);
_SentinelHealth()
| where TimeGenerated between (startTime .. endTime)
| where SentinelResourceType =~ "DataConnector"
| project TimeGenerated, OperationName, Status, Reason,
          SentinelResourceName, SentinelResourceKind, SentinelResourceType,
          WorkspaceId, RecordId
| take 100
```

### Sentinel audit changes to rules or connectors

```kusto
let startTime = datetime(2026-09-25T00:00:00Z);
let endTime = datetime(2026-09-25T10:00:00Z);
_SentinelAudit()
| where TimeGenerated between (startTime .. endTime)
| where SentinelResourceType in~ ("AlertRule", "DataConnector")
| project TimeGenerated, OperationName, Status, Description,
          SentinelResourceName, SentinelResourceKind, SentinelResourceType,
          CorrelationId, WorkspaceId
| take 100
```

### Hourly table volume drop

```kusto
let startTime = datetime(2026-09-25T09:00:00Z);
let endTime = datetime(2026-09-25T10:00:00Z);
let tableName = "DeviceProcessEvents";
Usage
| where TimeGenerated between (startTime .. endTime)
| where DataType == tableName
| summarize MBytes=sum(Quantity) by bin(TimeGenerated, 1h), DataType, Plan
| order by TimeGenerated asc
```

### Agent heartbeat gaps

```kusto
let startTime = datetime(2026-09-25T09:00:00Z);
let endTime = datetime(2026-09-25T10:00:00Z);
Heartbeat
| where TimeGenerated between (startTime .. endTime)
| summarize LastHeartbeat=max(TimeGenerated), Heartbeats=count()
    by Computer, _ResourceId, Version, OSType, SourceSystem
| extend GapMinutes = datetime_diff("minute", endTime, LastHeartbeat)
| order by GapMinutes desc
| take 100
```

### Bounded ingestion-latency estimate

```kusto
let startTime = datetime(2026-09-25T09:00:00Z);
let endTime = datetime(2026-09-25T10:00:00Z);
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| extend IngestionLatencySeconds = datetime_diff("second", ingestion_time(), TimeGenerated)
| summarize P95LatencySeconds=percentile(IngestionLatencySeconds, 95), Events=count()
    by bin(TimeGenerated, 15m)
| order by TimeGenerated asc
```

## 9. Reporting language

Use these phrases:

- `not found within verified coverage` only when the source, connector, parser,
  schema, DCR lineage, retention, permission, and latency boundaries are healthy
  for the claim scope.
- `not found within partially verified coverage` when some checks are healthy
  but non-material gaps remain.
- `not found within unverified coverage` when a health gap overlaps the incident
  window or the claim window.
- `not observed is not evidence of absence` when an ingestion-time DCR filter may
  have removed the record or field before storage.

Every material negative finding MUST cite the telemetry-health record and the
coverage receipt that bound it.

## 10. Prohibited behavior

The auditor MUST NOT:

- run live tenant queries from this reference;
- use national-cloud endpoints in the commercial profile;
- infer nonoccurrence from an empty table without a coverage receipt;
- ignore SentinelHealth, SentinelAudit, Usage, or Heartbeat gaps when they bound
  a source-dependent claim;
- treat schema or parser drift as a harmless implementation detail;
- treat a DCR-filtered absence as proof that an event did not happen;
- invoke production detection replay to test a rule;
- emit tenant IDs, workspace IDs, raw queries, credentials, or customer records
  in ordinary output.
