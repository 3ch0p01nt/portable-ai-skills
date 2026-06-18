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

## Fixture 6: Sentinel analytics rule YAML

User prompt:

````text
Turn this Sentinel hunt into a scheduled analytics rule YAML with connector requirements, entity mappings, MITRE tactics, and trigger settings. Treat it as Credential Access / T1110 password guessing context.

```kql
let lookback = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != 0
| summarize FailureCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserPrincipalName, IPAddress, AppDisplayName
| where FailureCount >= 5
```
````

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

````text
Package this Sentinel KQL as a portable detection example with MITRE mapping, false positives, blind spots, and response actions.

```kql
let lookback = 1d;
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4624 and LogonType == 10
| extend AccountName = tostring(split(Account, "\\")[1])
| project TimeGenerated, Account, AccountName, Computer, IpAddress
```
````