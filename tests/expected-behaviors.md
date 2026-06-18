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