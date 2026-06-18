# Query Review Checklist

Run this checklist before returning KQL or reviewing user-provided KQL.

## Syntax

- Query has a valid table or query root.
- Pipes apply base-table filters before expensive `summarize` and `join` operations; filters that depend on aggregate or joined columns may follow those operations.
- `let` names are descriptive and referenced correctly.
- Dynamic fields are parsed before property access.

## Scope and Performance

- High-volume telemetry tables have bounded time filters; inventory surfaces such as Azure Resource Graph use selective non-temporal predicates like `type`, subscription, resource group, or resource provider.
- Each join side is filtered and projected before joining.
- Join keys are explicit and stable.
- Broad `materialize()` over a large base scan is avoided.
- Output columns are limited to what the user needs.

## Schema Integrity

- Known Microsoft tables and columns are used accurately.
- Custom tables or columns are treated as unknown until schema is provided.
- The answer states assumptions when schema, connector, or tenant context is missing.

## Hunting Quality

- The query explains what signal it finds.
- False-positive tuning is included when detections or hunts are proposed.
- Severity is not overstated without evidence.
- Live validation is not claimed unless it was actually performed.

## Final Answer Gate

If any required item fails, revise the KQL before answering. If revision requires tenant schema details, ask for schema or provide a safe schema-discovery query shape.
