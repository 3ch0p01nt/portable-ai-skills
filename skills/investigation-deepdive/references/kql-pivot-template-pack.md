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
| project Timestamp, DeviceName, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA1, SHA256
| order by Timestamp asc
```

Execution status: not executed.

## Template 3: Domain or URL Prevalence

Surface: Defender XDR Advanced Hunting.

Required table: `DeviceNetworkEvents`.

```kql
let lookback = 30d;
let targetUrlOrDomain = "https://credential-review.example/login";
let targetHost = iff(targetUrlOrDomain contains "://", tostring(parse_url(targetUrlOrDomain).Host), targetUrlOrDomain);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| extend RemoteUrlValue=tostring(RemoteUrl), RemoteParsedHost=tostring(parse_url(RemoteUrlValue).Host)
| extend RemoteHost=iff(isnotempty(RemoteParsedHost), RemoteParsedHost, RemoteUrlValue)
| where RemoteUrlValue =~ targetUrlOrDomain or RemoteHost =~ targetHost or RemoteHost endswith strcat(".", targetHost)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), DeviceCount=dcount(DeviceName), UserCount=dcount(InitiatingProcessAccountUpn), Processes=make_set(InitiatingProcessFileName, 20) by RemoteUrl, RemoteHost, RemoteIP
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
let failureThreshold = 1; // Raise for broad hunts after scoping the target user.
let sequenceWindow = 1d;
let failureRows =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where UserPrincipalName =~ targetUser
    | where ResultType != "0"
    | extend FailureAuthenticationDetails=tostring(AuthenticationDetails), FailureStatus=tostring(Status), FailureMfaText=strcat(AuthenticationRequirement, " ", tostring(AuthenticationDetails), " ", tostring(Status), " ", ResultDescription)
    | extend IsMfaRelatedFailure = FailureMfaText contains "mfa" or FailureMfaText contains "multi-factor" or FailureMfaText contains "multifactor" or FailureMfaText contains "multi factor"
    | project AccountKey=tolower(UserPrincipalName), FailureDisplayUser=UserPrincipalName, FailureTime=TimeGenerated, FailureIP=IPAddress, FailureLocation=Location, FailureAuthenticationRequirement=AuthenticationRequirement, FailureAuthenticationDetails, FailureConditionalAccessStatus=ConditionalAccessStatus, FailureStatus, FailureResultDescription=ResultDescription, IsMfaRelatedFailure;
let successRows =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where UserPrincipalName =~ targetUser
    | where ResultType == "0"
    | project AccountKey=tolower(UserPrincipalName), SuccessDisplayUser=UserPrincipalName, SuccessTime=TimeGenerated, SuccessIP=IPAddress, SuccessLocation=Location, SuccessApp=AppDisplayName, SuccessAuthenticationRequirement=AuthenticationRequirement, SuccessAuthenticationDetails=tostring(AuthenticationDetails), SuccessConditionalAccessStatus=ConditionalAccessStatus, SuccessStatus=tostring(Status), SuccessResultDescription=ResultDescription;
let successBoundaries =
    successRows
    | sort by AccountKey asc, SuccessTime asc
    | serialize
    | extend PreviousSuccessTime = iff(AccountKey == prev(AccountKey), prev(SuccessTime), datetime(null))
    | project AccountKey, SuccessDisplayUser, CandidateSuccessTime=SuccessTime, PreviousSuccessTime, SuccessIP, SuccessLocation, SuccessApp, SuccessAuthenticationRequirement, SuccessAuthenticationDetails, SuccessConditionalAccessStatus, SuccessStatus, SuccessResultDescription;
let qualifyingSequences =
    failureRows
    | join kind=inner (
        successBoundaries
    ) on AccountKey
    | where FailureTime between ((CandidateSuccessTime - sequenceWindow) .. CandidateSuccessTime)
    | where FailureTime < CandidateSuccessTime
    | where isnull(PreviousSuccessTime) or FailureTime > PreviousSuccessTime
    | summarize DisplayUser=take_any(SuccessDisplayUser), FailuresBeforeSuccess=count(), MfaFailureCount=countif(IsMfaRelatedFailure), FirstFailure=min(FailureTime), LastFailureBeforeSuccess=max(FailureTime), FailureIPs=make_set(FailureIP, 20), FailureLocations=make_set(FailureLocation, 20), FailureAuthenticationRequirements=make_set(FailureAuthenticationRequirement, 20), FailureAuthenticationDetails=make_set(FailureAuthenticationDetails, 20), FailureConditionalAccessStatuses=make_set(FailureConditionalAccessStatus, 20), FailureStatuses=make_set(FailureStatus, 20), FailureResultDescriptions=make_set(FailureResultDescription, 20), SuccessIP=take_any(SuccessIP), SuccessLocation=take_any(SuccessLocation), SuccessApp=take_any(SuccessApp), SuccessAuthenticationRequirement=take_any(SuccessAuthenticationRequirement), SuccessAuthenticationDetails=take_any(SuccessAuthenticationDetails), SuccessConditionalAccessStatus=take_any(SuccessConditionalAccessStatus), SuccessStatus=take_any(SuccessStatus), SuccessResultDescription=take_any(SuccessResultDescription) by AccountKey, CandidateSuccessTime, PreviousSuccessTime
    | where FailuresBeforeSuccess >= failureThreshold
    | extend FirstSuccessAfterFailure = CandidateSuccessTime
    | summarize arg_min(FirstSuccessAfterFailure, *) by AccountKey;
qualifyingSequences
| extend VerdictHint = "Failures followed by success"
| project DisplayUser, AccountKey, FirstFailure, LastFailureBeforeSuccess, FirstSuccessAfterFailure, PreviousSuccessTime, FailuresBeforeSuccess, MfaFailureCount, SuccessIP, SuccessLocation, SuccessApp, SuccessAuthenticationRequirement, SuccessAuthenticationDetails, SuccessConditionalAccessStatus, SuccessStatus, SuccessResultDescription, FailureIPs, FailureLocations, FailureAuthenticationRequirements, FailureAuthenticationDetails, FailureConditionalAccessStatuses, FailureStatuses, FailureResultDescriptions, VerdictHint
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
let targetMessageId = "";
let targetUrl = "https://credential-review.example/login";
let urlRows =
    EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where isnotempty(targetMessageId) or isnotempty(targetUrl)
    | where isempty(targetMessageId) or NetworkMessageId == targetMessageId
    | where isempty(targetUrl) or Url =~ targetUrl
    | project NetworkMessageId, Url, UrlDomain, UrlInfoReportId=ReportId;
let delivered =
    EmailEvents
    | where Timestamp > ago(lookback)
    | where isnotempty(targetMessageId) or isnotempty(targetUrl)
    | where isempty(targetMessageId) or NetworkMessageId == targetMessageId
    | where isempty(targetUrl) or NetworkMessageId in (urlRows | project NetworkMessageId)
    | project NetworkMessageId, DeliveryReportId=ReportId, RecipientEmailAddress, RecipientKey=tolower(RecipientEmailAddress), DeliveryTime=Timestamp, SenderFromAddress, SenderMailFromAddress, Subject, DeliveryAction, DeliveryLocation;
delivered
| join kind=leftouter (
    urlRows
) on NetworkMessageId
| join kind=leftouter (
    UrlClickEvents
    | where Timestamp > ago(lookback)
    | where isempty(targetMessageId) or NetworkMessageId == targetMessageId
    | where isempty(targetUrl) or Url =~ targetUrl
    | project ClickNetworkMessageId=NetworkMessageId, ClickUrl=Url, ClickReportId=ReportId, ClickAccountUpn=AccountUpn, ClickAccountKey=tolower(AccountUpn), UrlClickTime=Timestamp, ActionType, IsClickedThrough
) on $left.NetworkMessageId == $right.ClickNetworkMessageId, $left.Url == $right.ClickUrl, $left.RecipientKey == $right.ClickAccountKey
| extend ClickAfterDelivery = isnotempty(UrlClickTime) and UrlClickTime >= DeliveryTime
| project NetworkMessageId, ClickNetworkMessageId, DeliveryReportId, UrlInfoReportId, ClickReportId, RecipientEmailAddress, RecipientKey, DeliveryTime, SenderFromAddress, Subject, DeliveryAction, DeliveryLocation, Url, UrlClickTime, ClickAccountUpn, ClickAccountKey, ClickAfterDelivery, ActionType, IsClickedThrough
```

Execution status: not executed.

## Template 8: File Hash Prevalence

Surface: Defender XDR Advanced Hunting.

Required tables: `DeviceFileEvents`, `DeviceProcessEvents`.

```kql
let lookback = 30d;
let targetSha1 = "";
let targetSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
let fileHits =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where (isnotempty(targetSha1) and SHA1 =~ targetSha1) or (isnotempty(targetSha256) and SHA256 =~ targetSha256)
    | extend MatchedHash = case(isnotempty(targetSha256) and SHA256 =~ targetSha256, SHA256, isnotempty(targetSha1) and SHA1 =~ targetSha1, SHA1, "")
    | where isnotempty(MatchedHash)
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, FolderPath, SHA1, SHA256, MatchedHash, Source="DeviceFileEvents";
let processHits =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where (isnotempty(targetSha1) and SHA1 =~ targetSha1) or (isnotempty(targetSha256) and SHA256 =~ targetSha256)
    | extend MatchedHash = case(isnotempty(targetSha256) and SHA256 =~ targetSha256, SHA256, isnotempty(targetSha1) and SHA1 =~ targetSha1, SHA1, "")
    | where isnotempty(MatchedHash)
    | project Timestamp, DeviceName, AccountUpn, FileName, FolderPath, SHA1, SHA256, MatchedHash, Source="DeviceProcessEvents";
union fileHits, processHits
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DeviceCount=dcount(DeviceName), UserCount=dcount(AccountUpn), Sources=make_set(Source), Devices=make_set(DeviceName, 20), ObservedSHA1s=make_set(SHA1, 20), ObservedSHA256s=make_set(SHA256, 20) by MatchedHash
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
| project Timestamp, DeviceName, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA1, SHA256
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
