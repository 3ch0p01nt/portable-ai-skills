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