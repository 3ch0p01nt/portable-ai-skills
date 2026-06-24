# Workbook Anomaly Intake Examples

These examples are synthetic and offline.

## Structured Row

Input:

```text
AnomalyName=Rare outbound domain
TimeGenerated=2026-06-19T15:10:00Z
DeviceName=HOST-042
AccountUpn=user@example.com
RemoteUrl=credential-review.example
RemoteIP=203.0.113.77
InitiatingProcessFileName=msedge.exe
BaselineDeviceCount=1
PeerGroup=Finance endpoints
AvailableTables=DeviceNetworkEvents,DeviceProcessEvents,SigninLogs
```

Output shape:

```text
Input classification: Structured workbook anomaly row
Mapped entities: HOST-042, user@example.com, credential-review.example, 203.0.113.77, msedge.exe
Assumptions: AvailableTables is analyst-supplied and not independently validated
Evidence gaps: command line, DNS logs, proxy logs, email context, raw workbook query, incident ID
Recommended playbooks: Domain or URL, IP Address, Host or Device, User or Identity, Process or Command Line
Execution status: not executed
```

## Vague Summary

Input:

```text
The workbook says one finance device contacted a rare domain after a suspicious sign-in.
```

Output shape:

```text
Input classification: Vague workbook anomaly summary
Mapped entities: unknown finance device, unknown rare domain, unknown user or sign-in
Assumptions: The source likely combines endpoint network and identity anomalies
Evidence gaps: host, user, domain, IP, timestamp, source tables, workbook query, baseline
Recommended playbooks: Weak-Context Workbook Anomaly, Domain or URL, Host or Device, User or Identity
Execution status: not executed
```
