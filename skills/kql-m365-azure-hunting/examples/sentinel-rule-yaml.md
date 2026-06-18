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
