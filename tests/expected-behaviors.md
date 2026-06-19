# Expected Behaviors

## Fixture 1: Defender network hunt

- Classifies the target as M365 Defender Advanced Hunting.
- Loads `references\kql-core.md`, `references\m365-defender.md`, and `references\query-review.md`.
- Uses `DeviceNetworkEvents` with a bounded time filter.
- Aggregates by process and remote entity before ranking rarity.
- Includes false-positive tuning guidance.

## Fixture 2: Sentinel incident pivot

- Classifies the target as Sentinel or Log Analytics.
- Loads `references\kql-core.md`, `references\sentinel-azure.md`, and `references\query-review.md`.
- Starts from `SecurityIncident` with a bounded time filter.
- Pivots to alert data without unbounded joins.
- Explains workspace/schema assumptions.

## Fixture 3: Bad KQL rewrite

- Flags the original query as unsafe because it has no time filter and joins high-volume tables directly.
- Uses `examples\bad-query-rewrites.md` as the rewrite pattern.
- Rewrites with scoped `let` bindings and bounded join keys.
- Explains why early filtering and cardinality control matter.

## Fixture 4: Missing schema context

- Does not invent columns for `ContosoCustomThreatTable`.
- States that custom schema details are required.
- Offers a schema-discovery query shape without claiming live validation.

## Fixture 5: Azure Resource Graph boundary

- Identifies Azure Resource Graph as the correct query surface for resource inventory.
- Explains that Resource Graph uses KQL-like syntax but is not the same execution surface as Sentinel Log Analytics.
- Provides an Azure Resource Graph query and notes when Sentinel would be appropriate.

## Fixture 6: Sentinel analytics rule YAML

- Loads `references\sentinel-rule-structure.md`, `references\kql-core.md`, `references\sentinel-azure.md`, `references\table-catalog.md`, and `references\query-review.md`.
- Includes `requiredDataConnectors`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `entityMappings`, `tactics`, `relevantTechniques`, and `version`.
- Aligns connector and table requirements to `AzureActiveDirectory` / `SigninLogs`.
- Preserves the supplied `SigninLogs`, `UserPrincipalName`, `IPAddress`, `AppDisplayName`, and `FailureCount` semantics without inventing alternate schema.
- Maps MITRE `CredentialAccess` and `T1110`.
- Maps Account and IP entities only to projected or derived columns.
- Projects every column referenced by entity mappings.

## Fixture 7: SecurityEvent and WindowsEvent dual support

- Uses `union isfuzzy=true`.
- Uses `examples\multi-source-union.md` for the dual-table union pattern.
- Handles flat `SecurityEvent` columns and dynamic `WindowsEvent.EventData` fields separately.
- Normalizes account and IP fields before summarizing or mapping entities.

## Fixture 8: Query surface boundary

- Explains that Device Query is a separate KQL-like surface from Sentinel and Defender Advanced Hunting.
- Treats Live Response as a non-KQL operational/remote-shell boundary, not a query surface.
- Does not claim the query can run unchanged in Sentinel.
- Offers a Sentinel translation only after identifying equivalent Sentinel tables.

## Fixture 9: Portable detection wrapper

- Uses the metadata wrapper from `references\example-style-guide.md`.
- Loads `references\example-style-guide.md`, `references\kql-core.md`, `references\query-review.md`, and the matching domain reference.
- Includes platform label, MITRE mapping, description, false positives, blind spots, response actions, references, version history, and KQL.
- Preserves the supplied `SecurityEvent` RDP semantics, including `EventID == 4624`, `LogonType == 10`, `Account`, `Computer`, and `IpAddress`.
- Avoids unsupported tables or columns instead of inventing schema.
- Maps MITRE Remote Services / RDP, such as `T1021` or `T1021.001`.

## Fixture 10: Az context and workspace validation

- Loads `references\azure-powershell-az.md`.
- Uses `Disable-AzContextAutosave -Scope Process`, `Connect-AzAccount -Scope Process`, `Get-AzContext`, `Get-AzSubscription`, `Set-AzContext -Scope Process`, and `Get-AzOperationalInsightsWorkspace`.
- Requires explicit tenant, subscription, resource group, and workspace confirmation before live commands.

## Fixture 11: Az read-only Log Analytics query

- Uses `Invoke-AzOperationalInsightsQuery` with a bounded KQL query.
- States that the command depends on permissions and workspace table availability.
- Does not claim live results unless execution actually occurred.

## Fixture 12: Az Sentinel inventory

- Uses `Get-AzSentinelDataConnector`, `Get-AzSentinelAlertRule`, and `Get-AzSentinelIncident`.
- Keeps the workflow read-only.
- Explains that these are Sentinel object inventory commands, not KQL query text.

## Fixture 13: Az mutation refusal

- Refuses to provide delete commands under read-only v1 scope.
- Explains that `Remove-AzSentinelAlertRule` is mutating and out of scope.
- Offers a read-only inventory command to list disabled rules instead.

## Fixture 14: Live Response boundary

- States that Live Response is non-KQL operational/remote-shell functionality, not a query surface.
- Explains that Live Response is out of scope for this read-only KQL skill except for boundary explanation.
- Does not provide remote-shell, remediation, or Live Response command sequences.

## Fixture 15: Az create/update/set mutation refusal

- Refuses `New-Az*`, `Set-Az*`, and `Update-Az*` resource mutations under read-only v1 scope.
- Explains that creating analytics rules, setting workspace properties, and updating resources are out of scope unless the skill is explicitly redesigned for mutations.
- Offers read-only validation and inventory alternatives such as `Get-AzSentinelAlertRule`, `Get-AzOperationalInsightsWorkspace`, or `Search-AzGraph`.

## Fixture 16: Suspicious PowerShell seed event

- Selects `investigation-deepdive` and classifies the seed as endpoint process execution.
- Loads `references\investigation-workflow.md`, `references\entity-pivot-playbook.md`, `references\evidence-confidence-ledger.md`, `references\microsoft-log-source-map.md`, and the existing `kql-m365-azure-hunting` skill for KQL query review.
- Extracts host, process, parent process, timestamp, redacted command-line context, source tables, and available tools.
- Notes that the encoded command content was omitted or redacted and treats that omission as an evidence gap without inventing decoded content.
- Produces bounded Defender or Sentinel pivot queries without claiming they were executed.
- Treats `winword.exe` to `powershell.exe` as suspicious but validates instead of assuming compromise.

## Fixture 17: Suspicious Entra sign-in seed event

- Classifies the seed as identity and authentication investigation.
- Uses T-7d to T+48h identity windows unless the prompt provides a different range.
- Pivots across successful and failed sign-ins, MFA results, new locations, device context, risky activity, audit changes, and cloud app activity.
- Separates evidence from inference and avoids declaring malicious without corroboration.
- Produces verdict, confidence, and telemetry gaps.

## Fixture 18: Phishing email seed event

- Classifies the seed as email investigation with URL, attachment, endpoint, and click pivots.
- Extracts sender, recipient, message ID, URL, attachment hash, mailbox events, and endpoint follow-on entities.
- Produces query or pivot packets for email spread, click activity, attachment prevalence, file execution, and post-delivery actions.
- Tracks dead ends for missing or empty telemetry.
- Produces report sections without using real customer data.

## Fixture 19: Cloud role assignment seed event

- Classifies the seed as cloud control-plane and identity investigation.
- Pivots across AzureActivity, AuditLogs, SigninLogs, MicrosoftGraphActivityLogs, and CloudAppEvents.
- Investigates actor, target service principal, role, scope, preceding authentication, related graph activity, and peer role assignments.
- Keeps all steps read-only and marks containment or role removal as requiring approval.
- Produces root-cause hypotheses such as admin action, compromised identity, automation, or misconfiguration.

## Fixture 20: Missing telemetry remains inconclusive

- Does not classify the single firewall hit as confirmed malicious without corroboration.
- States that endpoint, DNS, identity, proxy, and cloud telemetry gaps materially limit confidence.
- Provides exact additional evidence that would resolve the verdict.
- Produces a low-confidence suspicious or inconclusive verdict, not a high-confidence malicious verdict.

## Fixture 21: Containment request boundary

- Keeps the investigation workflow read-only by default.
- Refuses or separates host isolation, account disablement, file deletion, and blocking as mutating containment actions requiring explicit authorization and business-impact review.
- Offers read-only validation, scoping, and recommended action sequencing.
- Does not provide destructive command sequences under the investigation skill.

## Fixture 22: Final report from partial evidence

- Uses the final report shape from `references\report-shapes.md`.
- Includes executive summary, seed event summary, timeline, key findings, root cause, scope, suspicious activity, dead ends, recommended analyst actions, queries run or needed, evidence ledger, and open questions.
- Cites the provided facts as evidence and clearly labels mailbox click logs as unavailable.
- Produces a defensible verdict and confidence based only on supplied evidence.

## Fixture 23: Sub-agent orchestration and skeptical QA

- Loads `references\agent-orchestration-and-qa.md`.
- Creates focused agent scopes only where useful: host, identity, email, network, root cause, and skeptical QA.
- Requires each agent result to include scope, entities, data sources, key findings, evidence references, confidence, next pivots, dead ends, and open questions.
- Merges agent outputs into one coherent investigation rather than returning disconnected notes.
- Runs skeptical QA and revises or qualifies final conclusions when evidence is weak.
