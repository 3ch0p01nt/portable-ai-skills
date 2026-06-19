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
