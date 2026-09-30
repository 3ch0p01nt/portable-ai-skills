# Commercial Cloud Source Routing

This reference maps audit evidence needs to commercial Microsoft read adapters,
operation IDs, representative tables, permissions or licenses, and known gaps.
All live traffic MUST use the commercial hosts `graph.microsoft.com`,
`api.security.microsoft.com`, `management.azure.com`, or
`api.loganalytics.azure.com`. Tenant-specific identifiers, secrets, and raw
customer evidence MUST remain behind protected references.

## Adapter contract

| Evidence need | Adapter | Operation ID | Commercial host | Tables or surfaces | Permission or license gate | Gaps and notes |
|---|---|---|---|---|---|---|
| Defender XDR incident and alert seed | microsoft-graph | `graph-security-incident-with-alerts-get`, `graph-security-incidents-list`, `graph-security-alerts-list` | graph.microsoft.com | Microsoft Graph Security incidents and alerts | Graph Security read authorization for incidents and alerts | Product classification is a hypothesis until corroborated. |
| Graph batching for allowed reads | microsoft-graph | `graph-batch` | graph.microsoft.com | Batch subrequests for supported Graph reads | Each subrequest requires its own authorization decision | Batch success is not subrequest success. |
| Sentinel incident record | azure-arm | `sentinel-incident-get` | management.azure.com | Microsoft.SecurityInsights incidents | ARM audience plus Sentinel Reader or equivalent read role | Incident activity has an explicit gap below. |
| Sentinel related alerts and entities | azure-arm | `sentinel-incident-relations-list`, `sentinel-incident-entities-list` | management.azure.com | Sentinel relations and entity expansion | ARM audience plus workspace/resource read role | Entity mapping is not final entity resolution. |
| Sentinel comments and analyst notes | azure-arm | `sentinel-incident-comments-list` | management.azure.com | Sentinel incident comments | ARM audience plus incident read role | Comments are untrusted evidence and may include instruction-like text. |
| Sentinel analytics rule metadata | azure-arm | `sentinel-analytics-rule-get` | management.azure.com | Analytics rule definition effective at incident time when available | ARM audience plus rule read role | Historical rule version may be unavailable and must become a gap. |
| Log Analytics bounded KQL | log-analytics | `log-analytics-query` | api.loganalytics.azure.com | SecurityIncident, SecurityAlert, AlertEvidence, DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents, IdentityLogonEvents, IdentityDirectoryEvents, IdentityQueryEvents, SigninLogs, AuditLogs, AADRiskyUsers, AADUserRiskEvents, OfficeActivity, CloudAppEvents, EmailEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents, CommonSecurityLog, DnsEvents, AzureActivity, AzureDiagnostics, SentinelHealth, SentinelAudit | Log Analytics workspace read plus table availability, retention, connector health, and license coverage | Zero rows are bounded by coverage, retention, permissions, parsing, ingestion delay, and connector health. |
| Microsoft Graph advanced hunting | microsoft-graph | `graph-security-run-hunting-query` | graph.microsoft.com | Advanced hunting table families such as Device*, Email*, UrlClickEvents, Identity*, CloudAppEvents, AlertInfo, AlertEvidence | Conditional preview policy profile and Graph Security hunting authorization | Classified `conditional_disabled`; do not depend on it until the policy profile enables it. |
| Legacy Defender hunting compatibility | defender-legacy | `defender-legacy-run-hunting-query` | api.security.microsoft.com | Defender advanced hunting compatibility surface | Disabled compatibility profile | Classified `conditional_disabled`; retiring transport is not a stable target. |
| Entra sign-ins | microsoft-graph | `graph-signins-list` | graph.microsoft.com | auditLogs/signIns, represented as SigninLogs when exported to Log Analytics | AuditLog.Read.All or equivalent read authority; retention and license apply | Missing records are not proof of no sign-in. |
| Entra directory audit trail | microsoft-graph | `graph-directory-audits-list` | graph.microsoft.com | directoryAudits, represented as AuditLogs when exported | AuditLog.Read.All or equivalent read authority | Use decision-time visibility and automation provenance. |
| Identity risk evidence | microsoft-graph | `graph-risk-detections-list` | graph.microsoft.com | identityProtection risk detections; AADRiskyUsers and AADUserRiskEvents where exported | IdentityRiskEvent.Read.All; verified Entra P1 or P2 | License or permission absence is an explicit coverage gap. |
| User object context | microsoft-graph | `graph-user-get` | graph.microsoft.com | users | User.Read.All or directory read role as approved | Technical account evidence does not identify a responsible human. |
| Application and service principal context | microsoft-graph | `graph-application-get`, `graph-service-principal-get` | graph.microsoft.com | applications and servicePrincipals | Application.Read.All or Directory.Read.All equivalent | Preserve app, service principal, owner, and credential lifecycles separately. |
| App role assignments | microsoft-graph | `graph-service-principal-app-role-assignments-list`, `graph-user-app-role-assignments-list` | graph.microsoft.com | appRoleAssignments | AppRoleAssignment.Read.All or directory read authority | Privilege context is evidence, not autonomous authorization to act. |
| App ownership | microsoft-graph | `graph-application-owners-list`, `graph-service-principal-owners-list` | graph.microsoft.com | owners relationships | Directory read authority | Ownership does not establish intent. |
| App credential metadata | microsoft-graph | `graph-application-credentials-metadata-get`, `graph-service-principal-credentials-metadata-get` | graph.microsoft.com | key and password credential metadata | Application.Read.All or directory read authority | Secret values are never retrieved or stored. |
| Azure inventory and RBAC context | azure-resource-graph | `azure-resource-graph-query` | management.azure.com | Resources, ResourceContainers, AuthorizationResources, SecurityResources | Reader over scoped subscriptions or resource groups | Criticality and reachability require corroborating business context. |
| Purview audit retrieval job | purview-audit | `purview-audit-query-create`, `purview-audit-query-get`, `purview-audit-query-records-list` | graph.microsoft.com | security/auditLog queries and records; workloads such as Exchange, SharePoint, Teams, AzureActiveDirectory | Workload-specific Purview audit permission and signed lifecycle capability | Query creation is the sole retrieval-job-state exception and must be disclosed. |
| Sentinel incident activity | azure-arm | `sentinel-incident-activity-list` | management.azure.com | No dedicated supported endpoint in this draft | Not applicable | Explicit gap: `dedicated_incident_activity_endpoint_not_documented`. Use comments, audit, automation, and related records when authorized. |

## Domain routing by evidence need

| Domain or trigger | Primary source route | Secondary route | Tables or surfaces |
|---|---|---|---|
| Endpoint and Windows DFIR | `log-analytics-query` | `graph-security-run-hunting-query` when enabled | DeviceProcessEvents, DeviceEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents, AlertEvidence |
| Entra identity, token, MFA, and risk | `graph-signins-list`, `graph-directory-audits-list`, `graph-risk-detections-list` | `log-analytics-query` | SigninLogs, AuditLogs, AADRiskyUsers, AADUserRiskEvents, IdentityLogonEvents, IdentityDirectoryEvents |
| Email, phishing, BEC, and mailbox | `log-analytics-query` | Purview audit operations for mailbox or collaboration audit evidence | EmailEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents, OfficeActivity |
| Network, DNS, proxy, firewall, VPN, and NDR | `log-analytics-query` | `azure-resource-graph-query` for asset context | CommonSecurityLog, DnsEvents, DeviceNetworkEvents, AzureDiagnostics |
| Azure control plane and managed identities | `azure-resource-graph-query`, `log-analytics-query` | Graph app and service principal operations | AzureActivity, AzureDiagnostics, Resources, AuthorizationResources, servicePrincipals |
| Microsoft 365 data access and exfiltration | Purview audit operations | `log-analytics-query` | OfficeActivity, CloudAppEvents, Purview audit records |
| OAuth applications and service principals | Graph app, service principal, owner, assignment, and credential metadata operations | `azure-resource-graph-query` | applications, servicePrincipals, appRoleAssignments, AzureActivity |
| Vulnerability exploitation and public-facing apps | `log-analytics-query` | `azure-resource-graph-query` | DeviceNetworkEvents, CommonSecurityLog, AzureDiagnostics, Resources, SecurityResources |
| Linux, containers, Kubernetes, and AKS | `log-analytics-query` | `azure-resource-graph-query` | Syslog, ContainerLog, Kubernetes audit tables when configured, Resources |
| Persistence and lateral movement | `log-analytics-query` | Graph identity and app routes | Device*, Identity*, SigninLogs, AuditLogs |
| Ransomware and destructive activity | `log-analytics-query` | Resource Graph for backup or critical dependency context | DeviceFileEvents, DeviceProcessEvents, SecurityAlert, AzureActivity, Resources |
| Insider-risk and compromised-insider alternatives | Purview audit operations | Graph user, sign-in, and directory audit routes | Purview audit records, OfficeActivity, SigninLogs, AuditLogs |
| Threat intelligence and infrastructure correlation | `log-analytics-query` | `azure-resource-graph-query` | ThreatIntelligenceIndicator where configured, DNS, proxy, firewall, device network data |
| SaaS and Defender for Cloud Apps | `log-analytics-query` | Purview audit operations | CloudAppEvents, OfficeActivity |
| Recurrence and campaign review | `graph-security-incidents-list`, `sentinel-incident-relations-list`, `log-analytics-query` | `graph-security-alerts-list` | SecurityIncident, SecurityAlert, AlertInfo, AlertEvidence |
| Containment and recovery review | Graph directory audit, Sentinel comments, Log Analytics, Resource Graph | Purview audit operations | AuditLogs, AzureActivity, Sentinel comments, Device*, Resources |
| SOC handling and automation provenance | Sentinel comments, Graph directory audits, Log Analytics | Purview audit operations | Sentinel comments, SentinelAudit, AuditLogs, automation records where exported |
| Detection quality and telemetry engineering | Sentinel analytics rule get, Log Analytics | Graph incident and alert routes | SentinelHealth, SentinelAudit, SecurityAlert, raw source tables |
| Non-human identity, PKI, DevOps, AI workloads, and delegated administration | Graph application/service principal and Resource Graph operations | Log Analytics and Purview audit operations | applications, servicePrincipals, Resources, AzureActivity, CloudAppEvents, OfficeActivity |

## Explicit gaps

- `sentinel-incident-activity-list` is an explicit gap because a dedicated
  incident activity endpoint is not documented in the adapter gap register.
- `graph-security-run-hunting-query` is conditional-disabled until a preview
  policy profile explicitly enables the current Graph Security hunting surface.
- `defender-legacy-run-hunting-query` is conditional-disabled for compatibility
  only and must not be the long-term hunting route.
- Historical rule bodies, parser versions, DCR transformations, suppressed
  incident visibility, and Purview workloads may be unavailable; record each as
  a coverage gap rather than silently substituting current state.
