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