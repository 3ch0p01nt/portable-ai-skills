# KQL Pivot Template Pack

All templates are static, synthetic, read-only, and offline. Every query has bounded time, declared parameters, and `Execution status: not executed`.

## Template 1: Sentinel Incident to Alerts

Surface: Microsoft Sentinel or Log Analytics.

Required tables: `SecurityIncident`, `SecurityAlert`.

```kql
let incidentNumber = 42;
let lookback = 7d;
let latestIncident =
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber == incidentNumber
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project IncidentNumber, Title, Severity, Status, AlertIds, FirstActivityTime, LastActivityTime;
latestIncident
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner (
    SecurityAlert
    | where TimeGenerated > ago(lookback)
    | project SystemAlertId, AlertName, AlertSeverity, Tactics, Techniques, CompromisedEntity, StartTime, EndTime, ProductName
) on $left.AlertId == $right.SystemAlertId
| project IncidentNumber, Title, Severity, AlertName, AlertSeverity, Tactics, Techniques, CompromisedEntity, StartTime, EndTime, ProductName
| order by StartTime asc
```

Execution status: not executed.

## Template 2: Defender Process Tree Around Seed

Surface: Defender XDR Advanced Hunting.

Required table: `DeviceProcessEvents`.

```kql
let seedTime = datetime(2026-06-19T15:10:00Z);
let hostName = "HOST-042";
let lookaround = 24h;
DeviceProcessEvents
| where Timestamp between ((seedTime - lookaround) .. (seedTime + lookaround))
| where DeviceName =~ hostName
| project Timestamp, DeviceName, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA1
| order by Timestamp asc
```

Execution status: not executed.

## Template 3: Domain or URL Prevalence

Surface: Defender XDR Advanced Hunting.

Required table: `DeviceNetworkEvents`.

```kql
let lookback = 30d;
let targetDomain = "credential-review.example";
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl =~ targetDomain
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), DeviceCount=dcount(DeviceName), UserCount=dcount(InitiatingProcessAccountUpn), Processes=make_set(InitiatingProcessFileName, 20) by RemoteUrl, RemoteIP
| order by DeviceCount desc, EventCount desc
```

Execution status: not executed.

## Template 4: IP Prevalence and Ports

Surface: Defender XDR Advanced Hunting.

Required table: `DeviceNetworkEvents`.

```kql
let lookback = 30d;
let targetIP = "203.0.113.77";
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteIP == targetIP
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), DeviceCount=dcount(DeviceName), UserCount=dcount(InitiatingProcessAccountUpn), Ports=make_set(RemotePort, 20), Processes=make_set(InitiatingProcessFileName, 20) by RemoteIP
| order by EventCount desc
```

Execution status: not executed.

## Template 5: Identity Failure Followed by Success

Surface: Microsoft Sentinel or Log Analytics.

Required table: `SigninLogs`.

```kql
let lookback = 7d;
let targetUser = "alex@example.com";
let failureThreshold = 5;
let failureRows =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where UserPrincipalName =~ targetUser
    | where ResultType != "0"
    | project UserPrincipalName, FailureTime=TimeGenerated, FailureIP=IPAddress, FailureLocation=Location;
let successRows =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where UserPrincipalName =~ targetUser
    | where ResultType == "0"
    | project UserPrincipalName, SuccessTime=TimeGenerated, SuccessIP=IPAddress, SuccessLocation=Location, SuccessApp=AppDisplayName;
let firstSuccessAfterFailure =
    failureRows
    | summarize FirstFailure=min(FailureTime) by UserPrincipalName
    | join kind=inner (successRows) on UserPrincipalName
    | where SuccessTime > FirstFailure
    | summarize FirstSuccessAfterFailure=min(SuccessTime) by UserPrincipalName;
let firstSuccessDetails =
    firstSuccessAfterFailure
    | join kind=inner (successRows) on UserPrincipalName
    | where SuccessTime == FirstSuccessAfterFailure
    | project UserPrincipalName, FirstSuccessAfterFailure, SuccessIP, SuccessLocation, SuccessApp;
failureRows
| join kind=inner (firstSuccessAfterFailure) on UserPrincipalName
| where FailureTime < FirstSuccessAfterFailure
| summarize FailuresBeforeSuccess=count(), FirstFailure=min(FailureTime), LastFailureBeforeSuccess=max(FailureTime), FailureIPs=make_set(FailureIP, 20), FailureLocations=make_set(FailureLocation, 20) by UserPrincipalName, FirstSuccessAfterFailure
| where FailuresBeforeSuccess >= failureThreshold
| join kind=leftouter (firstSuccessDetails) on UserPrincipalName, FirstSuccessAfterFailure
| extend VerdictHint = "Failures followed by success"
| project UserPrincipalName, FirstFailure, LastFailureBeforeSuccess, FirstSuccessAfterFailure, FailuresBeforeSuccess, SuccessIP, SuccessLocation, SuccessApp, FailureIPs, FailureLocations, VerdictHint
| order by FirstSuccessAfterFailure asc
```

Execution status: not executed.

## Template 6: OAuth Consent or App Activity

Surface: Microsoft Sentinel or Log Analytics.

Required table: `AuditLogs`.

```kql
let lookback = 30d;
let targetAppId = "00000000-0000-0000-0000-000000000000";
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("Consent", "Add service principal", "Add app role assignment")
| mv-expand TargetResources
| extend TargetId=tostring(TargetResources.id), TargetName=tostring(TargetResources.displayName), InitiatedByUser=tostring(InitiatedBy.user.userPrincipalName), InitiatedByApp=tostring(InitiatedBy.app.displayName)
| where TargetId =~ targetAppId or TargetName has targetAppId
| project TimeGenerated, OperationName, Result, TargetId, TargetName, InitiatedByUser, InitiatedByApp, CorrelationId
| order by TimeGenerated desc
```

Execution status: not executed.

## Template 7: Email Message to URL Click

Surface: Defender XDR Advanced Hunting.

Required tables: `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`.

```kql
let lookback = 7d;
let targetMessageId = "MSG-EXAMPLE-001";
let delivered =
    EmailEvents
    | where Timestamp > ago(lookback)
    | where NetworkMessageId == targetMessageId
    | project NetworkMessageId, RecipientEmailAddress, DeliveryTime=Timestamp, SenderFromAddress, SenderMailFromAddress, Subject, DeliveryAction, DeliveryLocation;
delivered
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(lookback)
    | project NetworkMessageId, Url, UrlDomain
) on NetworkMessageId
| join kind=leftouter (
    UrlClickEvents
    | where Timestamp > ago(lookback)
    | project ClickNetworkMessageId=NetworkMessageId, Url, ClickAccountUpn=AccountUpn, UrlClickTime=Timestamp, ActionType, IsClickedThrough
) on $left.NetworkMessageId == $right.ClickNetworkMessageId, $left.Url == $right.Url, $left.RecipientEmailAddress == $right.ClickAccountUpn
| extend ClickAfterDelivery = isnotempty(UrlClickTime) and UrlClickTime >= DeliveryTime
| project NetworkMessageId, ClickNetworkMessageId, RecipientEmailAddress, DeliveryTime, SenderFromAddress, Subject, DeliveryAction, DeliveryLocation, Url, UrlClickTime, ClickAccountUpn, ClickAfterDelivery, ActionType, IsClickedThrough
```

Execution status: not executed.

## Template 8: File Hash Prevalence

Surface: Defender XDR Advanced Hunting.

Required tables: `DeviceFileEvents`, `DeviceProcessEvents`.

```kql
let lookback = 30d;
let targetSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
let fileHits =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where SHA256 =~ targetSha256
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, FolderPath, SHA256, Source="DeviceFileEvents";
let processHits =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where SHA256 =~ targetSha256
    | project Timestamp, DeviceName, AccountUpn, FileName, FolderPath, SHA256, Source="DeviceProcessEvents";
union fileHits, processHits
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DeviceCount=dcount(DeviceName), UserCount=dcount(AccountUpn), Sources=make_set(Source), Devices=make_set(DeviceName, 20) by SHA256
```

Execution status: not executed.

## Template 9: Azure Role Assignment Activity

Surface: Microsoft Sentinel or Log Analytics.

Required table: `AzureActivity`.

```kql
let lookback = 14d;
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue =~ "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatusValue =~ "Succeeded"
| extend Props=parse_json(Properties)
| extend RoleName=tostring(Props.roleDefinitionName), PrincipalId=tostring(Props.principalId), PrincipalType=tostring(Props.principalType), Scope=tostring(Props.scope)
| project TimeGenerated, Caller, CallerIpAddress, RoleName, PrincipalId, PrincipalType, Scope, CorrelationId
| order by TimeGenerated desc
```

Execution status: not executed.

## Template 10: Scheduled Task or Persistence Follow-Up

Surface: Defender XDR Advanced Hunting.

Required table: `DeviceProcessEvents`.

```kql
let lookback = 7d;
let targetHost = "HOST-042";
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName =~ targetHost
| where FileName in~ ("schtasks.exe", "powershell.exe", "cmd.exe", "reg.exe", "sc.exe", "wmic.exe")
| project Timestamp, DeviceName, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA1
| order by Timestamp desc
```

Execution status: not executed.

## Review Rules

- Keep Defender Advanced Hunting templates on `Timestamp`.
- Keep Sentinel or Log Analytics templates on `TimeGenerated`.
- Include bounded time windows.
- Use declared parameters.
- Do not claim execution.
- Explain table assumptions before use.
