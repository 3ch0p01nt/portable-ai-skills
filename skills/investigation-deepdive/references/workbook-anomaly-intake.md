# Workbook Anomaly Intake

Use this reference when the seed comes from a workbook row, workbook tile, anomaly chart, summarized detection, or analyst-pasted partial row.

## Input Classes

### Structured row

A structured row includes column names and values. Extract column names exactly, then map them to entities and context.

Common columns:

- `TimeGenerated`, `Timestamp`, `StartTime`, `EndTime`
- `AnomalyName`, `AlertName`, `DetectionName`, `WorkbookName`
- `DeviceName`, `DeviceId`, `Computer`, `HostName`
- `AccountUpn`, `UserPrincipalName`, `AccountName`, `AccountSid`
- `RemoteUrl`, `Url`, `Domain`, `RemoteIP`, `IPAddress`, `RemotePort`
- `FileName`, `FolderPath`, `SHA1`, `SHA256`
- `ProcessName`, `FileName`, `InitiatingProcessFileName`, `ProcessCommandLine`
- `AppId`, `ServicePrincipalId`, `ResourceId`, `ResourceGroup`, `OperationName`
- `BaselineCount`, `PeerGroup`, `RarityScore`, `AnomalyScore`, `ResultCount`
- `AvailableTables`, `MissingTables`, `SourceTable`

### Vague anomaly summary

A vague summary describes behavior without raw rows. Do not stop. Extract facts, infer likely entities, and label missing values as evidence gaps.

Examples:

- A finance endpoint contacted a rare domain after a suspicious sign-in.
- One user had failed MFA followed by success from a new country.
- A cloud resource had unusual role assignment activity.
- A process rarity score is high, but no command line is shown.

## Normalization Output

Return this normalization before pivots:

1. `Input classification`
2. `Source workbook or detection`
3. `Observed behavior`
4. `Time range`
5. `Primary entity`
6. `Secondary entities`
7. `Available tables`
8. `Missing tables`
9. `Metrics and baseline`
10. `Assumptions`
11. `Evidence gaps`

## Routing Rules

- Domain, URL, or IP in the row: route to the network and web entity playbooks.
- Host or device in the row: route to host, process, file, network, and logon playbooks.
- User or UPN in the row: route to identity, mailbox, cloud app, and endpoint activity playbooks.
- Process or command-line field in the row: route to process, file, network, and persistence playbooks.
- App ID, service principal, resource ID, or role operation in the row: route to cloud resource and OAuth app playbooks.
- Missing raw row: produce a pivot plan and ask for the exact columns only as a non-blocking next step.

## Evidence Rules

- Treat workbook anomaly scores as leads, not verdicts.
- Preserve the workbook metric and peer group in the evidence ledger.
- If a field is absent, mark it absent; do not invent it.
- If table availability is unknown, include schema-discovery or table-availability checks as read-only pivots.
- If the workbook summary says behavior is rare, still verify prevalence with entity-specific queries.
