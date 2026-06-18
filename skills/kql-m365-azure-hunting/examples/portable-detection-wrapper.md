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
