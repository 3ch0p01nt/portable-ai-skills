# Running a Live Read-Only Pilot

Run the pilot only after the tenant owner approves read-only acquisition for the target incident and window. Use placeholders in notes, for example `<tenant-id>`, `<workspace-id>`, and `<incident-id>`.

## Cloud selection and sign-in

Commercial pilot: sign in to the AzureCloud environment for the approved placeholder tenant, then run the pilot wrapper with `-Cloud Commercial`, placeholder incident and workspace identifiers, the approved time window, a local output directory such as `.\havoc-output\pilot-001`, and the read-only pilot confirmation switch.

US Gov DoD IL5 pilot: sign in to the AzureUSGovernment environment for the approved placeholder tenant and subscription, then run the same pilot wrapper with `-Cloud USGovDoD`, placeholder incident, workspace, subscription, resource group, workspace name, and Sentinel incident identifiers, the approved time window, a local output directory such as `.\havoc-output\pilot-001`, and the read-only pilot confirmation switch.

In a non-interactive shell, include the subscription during sign-in; otherwise Az can stop at the subscription selection prompt. Confirm the active context before the pilot. The active account type must be `User`. A stale AccessToken-type context can override a fresh sign-in; remove stale contexts, then reconnect.

The runner interface is `Invoke-HavocIncidentAudit.ps1 -Cloud Commercial|USGovDoD`; the pilot wrapper passes the same profile when invoking the runner. Commercial is the default. The cloud profile controls the pinned authority, Graph, ARM, and Log Analytics endpoints from `references\cloud-profiles.json`.

## Required access

- Azure roles: Microsoft Sentinel Reader and Log Analytics Reader on the target workspace.
- Graph delegated consent: `SecurityIncident.Read.All` on the Microsoft Graph PowerShell public client.
- Consent is a tenant change decided by the operator or administrator. HAVOC never grants Graph consent.

If Graph consent or token acquisition is unavailable, rerun with `-AllowGraphUnavailable` only when the operator accepts Graph as a recorded coverage gap.

Before Graph sign-in, the pilot prints an admin-consent warning. Do not grant organization-wide consent from the sign-in prompt. If consent is not already approved, cancel or use `-AllowGraphUnavailable` when the pilot owner accepts the gap.

The first live sovereign-cloud pilot on 2026-09-29 confirmed the pinned cloud profile and delegated token-shape expectations without changing tenant state. If `log-analytics-query` reports `auth_scope_missing`, the build is older than the 2026-09-29 policy update.

## Sentinel coverage attestation

`-AttestSentinelWorkspaceCoverage` means the operator attests Sentinel onboarding and connector health. It is not proof from the tool. If read-only checks later contradict the attestation, the report records a contradiction gap and downgrades clean coverage claims.

Provide `-SubscriptionId`, `-ResourceGroupName`, `-WorkspaceName`, `-SentinelIncidentId`, and optionally `-AnalyticsRuleId` when Sentinel ARM reads are in scope.

For Sentinel-native incidents that are not onboarded to the Defender portal, Graph `/security/incidents/{id}` can return HTTP 404. That is expected and should be recorded as a gap. Use the Sentinel `IncidentNumber` as `-IncidentId` because `ProviderIncidentId` equals `IncidentNumber`, and use the incident name GUID as `-SentinelIncidentId`. Current runner builds fall back to Log Analytics `SecurityIncident` and `SecurityAlert` rows for incident facts; reports note `incident_facts_from_log_analytics_fallback`.

Without `-AttestSentinelWorkspaceCoverage`, Sentinel ARM reads are recorded as `sentinel_source_not_covered`. `SentinelHealth` may be empty when diagnostics are not enabled, so connector health can only be operator-attested or carried as a gap.

To find a pilot incident and time window with read-only KQL:

```kql
SecurityIncident
| where TimeGenerated between (datetime(<start-utc>) .. datetime(<end-utc>))
| where Status == 'Closed'
| extend AlertIdList = todynamic(AlertIds)
| project TimeGenerated, LastModifiedTime, IncidentNumber, ProviderIncidentId, IncidentName, Title, Severity, Status, Classification, AlertIdList
| order by LastModifiedTime desc
| take 10
```

Use single-quoted strings for literal filters, for example `where Title has '<known-title-fragment>'`.

## Pivots

The runner lists follow-up pivots by default. Use `-ExecutePivots` only for approved bounded read-only Log Analytics pivots. `-MaxPivotQueries` defaults to 25 and accepts 1 through 100. Pivots still pass the mutation scanner and request policy.

When pivots execute, `pivot_budget_truncated` means the remaining frontier exceeded `-MaxPivotQueries`, and `pivot_result_capped` means a pivot hit the runner row cap. Both are coverage limitations: treat matching rows as evidence, but do not treat capped or unexamined pivots as a clean absence signal.

## Output directory

Use a local path that is not automatically synced, for example `.\havoc-output\pilot-001`. Avoid OneDrive and similar sync folders. The `protected\` subfolder contains raw protected evidence wrappers and must remain local and access-controlled.

## Pre-flight stops

The pilot prints a pre-flight summary and can stop before tenant reads when:

- Az context is missing, in the wrong environment, or signed into a different tenant.
- Graph delegated token acquisition fails and `-AllowGraphUnavailable` is not set.
- Graph token scopes include write-capable or excess privileges.
- ARM or Log Analytics token validation fails. These checks still run when Graph is unavailable and `-AllowGraphUnavailable` is set.
- Token audience, issuer, tenant, method, or host does not match the selected profile and request policy.

The summary masks tenant and account values. It prints token audience, issuer, tenant placeholder, permissions, and expiry for Graph when available, plus ARM and Log Analytics.

## Report sections to review

Recent reports include additional operator-facing material:

- SOC decision-time review: composed SOC handling score with known-weight normalization. `not_assessable` means too few decision snapshots or too little scored weight, not that handling was good or bad. Hindsight-only critiques are marked invalid for decision-time scoring.
- Incident taxonomy audit: severity, classification, and status history are audited when history is present. Missing history appears as a coverage gap and must not be read as "never changed."
- Frontier and saturation: frontier priority score records weighted priority and the Tier-0, critical-service, recovery-infrastructure, and high-impact asset minimum-priority floor. `minimum_priority_frontier_unexamined` blocks saturation until those items are examined or explicitly accepted as unresolved.
- Containment and recovery: live Graph incident responses do not supply the fixture-only containment/recovery review object, so live runs carry `containment_recovery_evidence_missing` unless another approved source supplies those records.

## DoD IL5 specifics

USGovDoD mode declares expected gaps from the cloud profile: Purview disabled, Resource Graph disabled, Graph PowerShell client availability unconfirmed, and Sentinel-to-Defender portal onboarding dependency. Sentinel incidents require the workspace to be onboarded to the Defender portal for Graph incidents. The DoD endpoints are only those pinned in `references\cloud-profiles.json`.

## Suggested first pilot

Start with 3 to 5 closed incidents that have a known answer key. Compare HAVOC findings against the answer key for: incident match, missing evidence, false escalation, classification challenge, detection-quality finding, SOC-handling finding, and stated coverage gaps. Treat disagreement as a review item, not as automatic tool failure.
