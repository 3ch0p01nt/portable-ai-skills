# KQL M365 Azure Hunting

Use this skill when a user asks for KQL, M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure Resource Graph, or Azure security-hunting help.

## Mission

Make a blank AI safe and useful for hunting-oriented KQL. The AI must classify the query surface, load the smallest relevant reference set, state assumptions, produce bounded KQL, and run the query-review checklist before answering.

## Reference Selection

- Defender Advanced Hunting: read `references\kql-core.md`, `references\m365-defender.md`, and `references\query-review.md`.
- Sentinel or Log Analytics: read `references\kql-core.md`, `references\sentinel-azure.md`, and `references\query-review.md`.
- Azure Resource Graph: read `references\kql-core.md`, `references\sentinel-azure.md`, and `references\query-review.md`.
- Query review only: read `references\query-review.md` and the domain reference matching the query surface.
- Concept explanation: read the smallest reference that covers the requested concept.

## Operating Flow

1. Classify the user request as Defender Advanced Hunting, Sentinel or Log Analytics, Azure Resource Graph, general Azure, or conceptual explanation.
2. Identify known tables, known columns, unknown schema details, time range, and expected output.
3. Load the selected references.
4. Draft the answer or KQL.
5. Apply every relevant item in `references\query-review.md`.
6. Return assumptions, KQL, explanation, tuning guidance, and optional validation steps.

## Required Guardrails

- Default to commercial `.com` Azure and M365 terminology.
- Do not use `.us` guidance unless the user asks or tenant evidence requires it.
- Do not invent table names, column names, tenant IDs, resource names, or live results.
- Require time filters on high-volume telemetry tables.
- Avoid broad `materialize()` over large scans.
- Prefer early filters, scoped `let` bindings, bounded joins, and explainable entity pivots.
- Treat live validation as optional because this skill pack is static and offline.
- If the user asks for destructive Azure or M365 operations, stop and request explicit scope before giving operational steps.

## Answer Shape

For KQL generation:

1. `Assumptions`
2. `Query`
3. `How it works`
4. `Tuning`
5. `Validation notes`

For KQL review:

1. `Findings`
2. `Corrected query`
3. `Why the changes matter`
4. `Remaining assumptions`