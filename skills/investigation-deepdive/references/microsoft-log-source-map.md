# Microsoft Log Source Map

This skill is Microsoft-first. Use the existing `kql-m365-azure-hunting` skill for KQL syntax, query-surface selection, query review, Sentinel rule packaging, and Azure Resource Graph boundaries.

## Query Surface Rules

- Defender XDR Advanced Hunting: use Defender tables and `Timestamp`-based schemas when querying in Defender.
- Microsoft Sentinel and Log Analytics: use workspace tables and `TimeGenerated`-based schemas when querying in Sentinel.
- Azure Resource Graph: use resource inventory queries for Azure resource state, not Sentinel telemetry.
- Device Query: treat as a separate KQL-like device-management surface, not the same as Sentinel or Defender Advanced Hunting.
- Live Response: treat as operational remote-shell functionality, not KQL.

## Microsoft-First Tables

Prioritize these tables when available:

- `SecurityIncident`
- `SecurityAlert`
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`
- `DeviceNetworkInfo`
- `DeviceLogonEvents`
- `DeviceRegistryEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`
- `EmailEvents`
- `EmailUrlInfo`
- `EmailAttachmentInfo`
- `EmailPostDeliveryEvents`
- `UrlClickEvents`
- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`
- `AADServicePrincipalSignInLogs`
- `AuditLogs`
- `IdentityLogonEvents`
- `IdentityDirectoryEvents`
- `IdentityQueryEvents`
- `OfficeActivity`
- `CloudAppEvents`
- `AzureActivity`
- `MicrosoftGraphActivityLogs`
- `CommonSecurityLog`
- `Syslog`
- `SecurityEvent`
- `WindowsEvent`
- `Heartbeat`

## Pivot Families

For Microsoft environments, generate pivots for:

- Host activity around the seed time.
- User activity around the seed time.
- Process tree and parent-child relationships.
- File hash prevalence and first seen time.
- Network destination prevalence.
- Failed and successful sign-ins.
- New geography, ASN, device, or user agent.
- MFA changes and authentication method changes.
- Role and group changes.
- Mailbox rule creation and forwarding.
- OAuth consent and service principal activity.
- Rare command lines.
- Rare parent-child process pairs.
- Same IOC across hosts, users, and cloud activity.
- Same behavior across peer hosts or peer users.

## Query Ledger Requirements

For every query or analyst-run pivot, record purpose, query surface, source table or tool, time range, entity filters, result count when known, important results, and how the result changed the investigation.

If a query is drafted but not executed, say `not executed` in the result summary.
