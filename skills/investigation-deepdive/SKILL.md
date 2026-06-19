---
name: investigation-deepdive
description: Use when investigating suspicious security events, alerts, entities, hosts, users, IPs, processes, files, URLs, domains, cloud resources, identities, emails, or log records and producing an evidence-driven SOC investigation report.
---

# Investigation Deepdive

Use this skill when a user asks for a deep SOC investigation starting from a suspicious event, alert, host, user, IP address, process, file, URL, domain, cloud resource, identity, email, or log record.

## Mission

Act like an experienced incident responder, not a log summarizer. Treat the seed event as a starting clue, extract pivot entities, build a timeline, test competing hypotheses, maintain an evidence ledger, investigate blast radius, identify root cause, close dead ends, run skeptical QA, and produce a defensible verdict.

## Reference Selection

- Any seed-event investigation: read `references\investigation-workflow.md`, `references\entity-pivot-playbook.md`, and `references\evidence-confidence-ledger.md`.
- Microsoft Sentinel, Microsoft Defender XDR, Entra ID, Microsoft 365, Azure, or KQL-driven investigation: also read `references\microsoft-log-source-map.md`; invoke or apply `kql-m365-azure-hunting` for KQL syntax, query-surface selection, and query review.
- Sub-agent orchestration, branch assignment, or skeptical review: read `references\agent-orchestration-and-qa.md`.
- Final report, executive summary, query ledger, recommendations, or analyst handoff: read `references\report-shapes.md`.
- MITRE ATT&CK, Microsoft Sentinel incidents, Sentinel entities, data connectors, or Defender XDR advanced hunting grounding: read `references\public-source-notes.md`.
- Evidence confidence, verdict decisions, dead ends, or claim validation: read `references\evidence-confidence-ledger.md`.
- Load only the smallest useful reference set unless the user asks for a full investigation pack or the case spans multiple entity types.

## Operating Flow

1. Normalize the seed event and identify event type, timestamp, source product, detection name, severity, host, user, process, network, file, cloud, identity, and email context.
2. Extract every useful pivot entity: hostnames, device IDs, users, UPNs, SIDs, IPs, processes, command lines, parent processes, file paths, hashes, URLs, domains, registry keys, service names, scheduled tasks, resource IDs, app IDs, OAuth IDs, mailbox IDs, message IDs, session IDs, alert IDs, correlation IDs, ports, protocols, authentication methods, MFA results, geolocation, user agents, and device state.
3. State missing inputs and reasonable assumptions. Do not stop solely because context is incomplete.
4. Set time windows. Use T-24h to T+24h for host and process activity, T-7d to T+48h for identity and authentication, and T-30d for baselines when needed unless the prompt provides better windows.
5. Build an initial timeline around the seed event.
6. Generate competing hypotheses, including true positive compromise, authorized admin activity, software update, scanner, false positive, user mistake, phishing, credential compromise, malware, lateral movement, token abuse, misconfiguration, red team activity, and business application behavior.
7. Run or draft targeted read-only pivots. If live tools are not explicitly authorized, produce exact analyst-run queries instead of claiming execution.
8. Record major claims in the evidence ledger.
9. Recursively investigate new suspicious entities when evidence justifies another branch.
10. Close each thread as confirmed malicious, suspicious but unconfirmed, likely benign, known-good or admin activity, duplicate, or dead end due to insufficient telemetry.
11. Assess root cause and blast radius.
12. Run skeptical QA before the final answer.
13. Return the requested answer shape. Use the final investigation report shape only when the user requests a final report or when enough evidence exists for defensible final findings.

## Safety Guardrails

- Default to static offline operation and read-only analysis.
- Run live queries only when the user explicitly authorizes read-only execution and the required tools are available.
- Never disable accounts, isolate hosts, delete files, block indicators, revoke tokens, change roles, update configuration, or perform other mutating containment actions unless the user explicitly requests remediation outside this read-only investigation workflow.
- Separate recommended immediate actions, actions requiring approval, and actions that can affect business operations.
- Use time-bounded, targeted queries.
- Do not invent evidence, query results, schema, tenant context, tool access, source availability, or live validation.
- Do not include secrets, tenant IDs, customer-specific details, AOAI endpoints, API keys, deployment names, private resource names, or confidential content.
- Avoid malware reverse engineering instructions beyond high-level triage pivots.
- Avoid exploit development, destructive steps, stealth, persistence, or evasion guidance.
- Mark unavailable telemetry as a gap instead of filling it with assumptions.
- Prefer evidence over assumptions and label inference clearly.

## Answer Shapes

For an initial investigation plan:

1. `Seed summary`
2. `Extracted entities`
3. `Assumptions and missing context`
4. `Time windows`
5. `Initial hypotheses`
6. `Pivot plan`
7. `Evidence to collect`

For a query or pivot packet:

1. `Purpose`
2. `Data source`
3. `Time range`
4. `Query or pivot`
5. `Expected result shape`
6. `How to interpret results`

For a sub-agent result:

1. `agent_name`
2. `scope`
3. `entities investigated`
4. `queries or data sources used`
5. `key findings`
6. `evidence references`
7. `confidence level`
8. `recommended next pivots`
9. `dead ends`
10. `open questions`

For a final investigation report:

1. `Executive Summary`
2. `Seed Event Summary`
3. `Investigation Timeline`
4. `Key Findings`
5. `Root Cause Assessment`
6. `Scope / Blast Radius`
7. `Suspicious Activity Discovered`
8. `Dead Ends / Ruled-Out Leads`
9. `Recommended Analyst Actions`
10. `Queries Run`
11. `Evidence Ledger`
12. `Open Questions`

## Verdict Rules

- Malicious: clear evidence of unauthorized execution, compromise, persistence, credential abuse, exfiltration, malware, lateral movement, or confirmed threat infrastructure.
- Suspicious: behavior is abnormal, risky, or partially matches malicious tradecraft, but evidence is incomplete.
- Benign: evidence strongly supports approved software, admin action, expected business behavior, or known-good automation.
- Inconclusive: telemetry is insufficient or conflicting.

## Before Finalizing

Run skeptical QA. Ask whether the investigation over-trusted the alert, ignored benign explanations, confused correlation with causation, missed timestamp conflicts, lacked key logs, scoped too narrowly, failed to check before and after the seed event, missed the first known suspicious action, omitted dead ends, or made claims without evidence.
