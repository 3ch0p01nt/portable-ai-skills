# KQL Source Enrichment Design

## Goal

Enrich the portable `kql-m365-azure-hunting` skill pack with source-derived knowledge from KQLSearch, Azure/Azure-Sentinel, Analytics Rules Exchange, and prominent GitHub KQL repositories.

## Source Findings

KQLSearch shows that portable examples need a query metadata wrapper, not only raw KQL. The useful offline pattern is: title, query information, category, MITRE ATT&CK techniques, description, risk, author, references, versioning, platform header, KQL, table tags, keywords, and operators. KQLSearch also separates Intune/Defender Device Query from Sentinel and Defender Advanced Hunting, which must be documented as a separate query surface.

Azure/Azure-Sentinel and Analytics Rules Exchange show that Sentinel analytics rules are YAML artifacts with a stable structure: `id`, `name`, `description`, `severity`, `kind`, `requiredDataConnectors`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `query`, `entityMappings`, `tactics`, `relevantTechniques`, `customDetails`, `alertDetailsOverride`, `eventGroupingSettings`, `incidentConfiguration`, `version`, `status`, `tags`, and `metadata`. Hunting queries are similar but usually omit scheduling and trigger fields.

The GitHub KQL ecosystem shows three durable organization patterns: product/service trees, MITRE tactic trees, and data-source trees. Mature examples include metadata, false-positive guidance, blind spots, response actions, version history, and dual-platform notes for Defender `Timestamp` versus Sentinel `TimeGenerated`.

## Design Changes

### New reference files

Add `references\sentinel-rule-structure.md` for Sentinel analytics rule YAML, hunting query YAML, entity mappings, rule scheduling, trigger semantics, severity, status, MITRE fields, connector-to-table mapping, custom details, alert overrides, incident grouping, and NRT versus Scheduled differences.

Add `references\table-catalog.md` for table meanings and key fields across Defender, Sentinel, Entra ID, Office 365, Windows Security Events, Azure, ASIM/common tables, Threat Intelligence, UEBA, Exposure Management, and Device Query boundaries.

Add `references\example-style-guide.md` for portable example format: metadata wrapper, platform labels, dual Defender/Sentinel variants when relevant, MITRE mapping, false positives, blind spots, response actions, version history, and source attribution.

### Existing reference updates

Update `references\kql-core.md` to include source-derived idioms: `union isfuzzy=true`, `columnifexists()`, `parse ... with`, `matches regex`, `contains_cs`, `bin()` time buckets, case normalization before joins, `ingestion_time()`, `parse_command_line()`, `has` versus `contains`, dynamic allowlists, public IP functions, and reduce-before-join patterns.

Update `references\m365-defender.md` to include Exposure Management (`ExposureGraphNodes`), email/collaboration tables, alert pivots, and the `Timestamp` versus `TimeGenerated` distinction.

Update `references\sentinel-azure.md` to include SecurityEvent versus WindowsEvent/AMA differences, connector-to-table mapping, AzureDiagnostics ResourceType/Category guidance, Azure Resource Graph boundaries, ASIM table caveats, and Sentinel incident/alert pivots.

Update `references\query-review.md` so KQL review checks also validate rule metadata, entity mapping output columns, connector/table alignment, query period/frequency consistency, event grouping, false-positive guidance, blind spots, and whether the requested query surface is Device Query, Defender Advanced Hunting, Sentinel, Log Analytics, Azure Resource Graph, or ADX.

### Examples and tests

Add examples for:

- A Sentinel analytics rule YAML skeleton.
- A Sentinel hunting query YAML skeleton.
- A dual SecurityEvent/WindowsEvent RDP lateral movement query.
- A multi-source `union isfuzzy=true` malformed user-agent style pattern.
- A KQLSearch-style Markdown detection wrapper.
- A Device Query boundary example.

Add offline fixtures that require the AI to classify query surface, choose the correct timestamp field, map connectors to tables, prepare entity mapping columns, and refuse to invent schema for custom tables.

## Guardrails

The skill must summarize and generalize public examples. It must not copy large third-party rule bodies wholesale. Use short snippets only when needed to teach structure or syntax.

Do not blur query surfaces. Defender Advanced Hunting, Sentinel/Log Analytics, Azure Resource Graph, ADX, and Intune/Defender Device Query have different schemas and execution assumptions.

Do not treat connector availability as guaranteed. The skill must say that Sentinel tables depend on enabled connectors.

## Self-Review

- The design captures rule structure, KQL examples, tables, table meanings, metadata, and offline test strategy.
- The design remains static/offline and portable from Git.
- The new references keep responsibilities separated and avoid one oversized file.
- No placeholders remain.
