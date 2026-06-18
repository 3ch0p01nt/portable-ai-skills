# Table Catalog

## Query Surface Time Fields

| Surface | Time field | Notes |
|---|---|---|
| Defender XDR Advanced Hunting | `Timestamp` | M365 Defender tables generally use `Timestamp`. |
| Sentinel / Log Analytics | `TimeGenerated` | Workspace tables generally use `TimeGenerated`. |
| Azure Resource Graph | none required | Resource inventory is current-state unless a resource property contains time. |
| ADX custom data | schema-dependent | Confirm the table schema before writing time filters. |
| Device Query / Live Response | device-query specific | Do not assume Sentinel or Defender Advanced Hunting schema. |

## Defender XDR Tables

| Table | Meaning | Key fields |
|---|---|---|
| `DeviceProcessEvents` | Endpoint process creation and parent/child context | `Timestamp`, `DeviceId`, `DeviceName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName` |
| `DeviceNetworkEvents` | Endpoint network connections and inspected TLS metadata | `Timestamp`, `DeviceId`, `RemoteIP`, `RemoteUrl`, `RemotePort`, `InitiatingProcessFileName`, `AdditionalFields` |
| `DeviceFileEvents` | File create, modify, delete, and hash telemetry | `Timestamp`, `DeviceId`, `FileName`, `FolderPath`, `SHA256`, `InitiatingProcessFileName` |
| `DeviceRegistryEvents` | Registry key/value activity | `Timestamp`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `ActionType` |
| `DeviceLogonEvents` | Endpoint logon telemetry | `Timestamp`, `AccountName`, `LogonType`, `RemoteIP`, `DeviceName` |
| `AlertInfo` | Defender alert metadata | `Timestamp`, `AlertId`, `Title`, `Severity`, `Category` |
| `AlertEvidence` | Defender alert entities and evidence | `Timestamp`, `AlertId`, `EntityType`, `DeviceId`, `AccountName`, `RemoteIP`, `FileName` |
| `EmailEvents` | Defender for Office email events | `Timestamp`, `NetworkMessageId`, `RecipientEmailAddress`, `SenderFromAddress`, `Subject` |
| `EmailUrlInfo` | URLs extracted from email | `Timestamp`, `NetworkMessageId`, `Url` |
| `UrlClickEvents` | Safe Links URL click telemetry | `Timestamp`, `AccountUpn`, `Url`, `ActionType` |
| `ExposureGraphNodes` | Exposure Management graph nodes and vulnerability state | `NodeLabel`, `NodeProperties`, `Categories`, `EntityIds` |

## Sentinel / Log Analytics Tables

| Table | Meaning | Key fields |
|---|---|---|
| `SecurityIncident` | Sentinel incident records | `TimeGenerated`, `Name`, `IncidentNumber`, `Title`, `Severity`, `Status`, `AlertIds` |
| `SecurityAlert` | Sentinel and connected product alerts | `TimeGenerated`, `SystemAlertId`, `AlertName`, `ProviderName`, `Entities` |
| `SigninLogs` | Entra interactive sign-ins | `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `ResultType`, `ConditionalAccessStatus`, `AppDisplayName` |
| `AADNonInteractiveUserSignInLogs` | Entra non-interactive sign-ins | `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `ResultType`, `AppDisplayName` |
| `AuditLogs` | Entra directory and app audit events | `TimeGenerated`, `OperationName`, `Category`, `InitiatedBy`, `TargetResources` |
| `OfficeActivity` | Exchange, SharePoint, OneDrive, and Teams audit | `TimeGenerated`, `OfficeWorkload`, `Operation`, `UserId`, `ClientIP`, `Parameters` |
| `AzureActivity` | Azure Resource Manager control-plane operations | `TimeGenerated`, `OperationNameValue`, `Caller`, `CallerIpAddress`, `ResourceGroup`, `ResourceId` |
| `AzureDiagnostics` | Azure service diagnostics | `TimeGenerated`, `ResourceType`, `Category`, `ResourceId` |
| `SecurityEvent` | Windows Security Events via legacy connector | `TimeGenerated`, `EventID`, `Account`, `LogonType`, `IpAddress`, `Computer` |
| `WindowsEvent` | Windows Events via AMA | `TimeGenerated`, `EventID`, `EventData`, `Computer` |
| `CommonSecurityLog` | CEF network/security appliance logs | `TimeGenerated`, `DeviceVendor`, `DeviceProduct`, `SourceIP`, `DestinationIP`, `Activity` |
| `ThreatIntelligenceIndicator` | Threat intelligence indicators | `TimeGenerated`, `NetworkIP`, `DomainName`, `Url`, `FileHashValue`, `ExpirationDateTime` |
| `BehaviorAnalytics` | UEBA anomaly and entity behavior | `TimeGenerated`, `UserPrincipalName`, `ActivityInsights`, `InvestigationPriority` |
| `Usage` | Log Analytics ingestion and cost data | `TimeGenerated`, `DataType`, `Quantity`, `IsBillable`, `Solution` |

## Connector to Table Mapping

| Connector ID | Common tables |
|---|---|
| `AzureActiveDirectory` | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `AADServicePrincipalSignInLogs` |
| `AzureActivity` | `AzureActivity` |
| `Office365` | `OfficeActivity` |
| `MicrosoftThreatProtection` | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `AlertInfo`, `AlertEvidence` |
| `SecurityEvents` | `SecurityEvent` |
| `WindowsSecurityEvents` | `SecurityEvent`, `WindowsEvent` |
| `WindowsForwardedEvents` | `WindowsForwardedEvents` |
| `AzureMonitor(IIS)` | `W3CIISLog` |
| `WAF` | `AzureDiagnostics` for Application Gateway/WAF logs |
| `AzureFirewall` | `AzureDiagnostics` or resource-specific firewall tables depending on connector mode |
| `CEF` / `CefAma` | `CommonSecurityLog` |
| `ThreatIntelligence` / `ThreatIntelligenceTaxii` | `ThreatIntelligenceIndicator` |

## SecurityEvent Versus WindowsEvent

Use `SecurityEvent` when events are in flat columns:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType == 10
| project TimeGenerated, Account, Computer, IpAddress
```

Use `WindowsEvent` when AMA stores details in `EventData`:

```kql
WindowsEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| extend LogonType = toint(EventData.LogonType)
| where LogonType == 10
| extend Account = strcat(tostring(EventData.TargetDomainName), "\\", tostring(EventData.TargetUserName))
| extend IpAddress = tostring(EventData.IpAddress)
| project TimeGenerated, Account, Computer, IpAddress
```
