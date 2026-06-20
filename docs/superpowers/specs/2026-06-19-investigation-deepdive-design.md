# Investigation Deepdive Skill Design

## Goal

Create `investigation-deepdive`, a standalone portable SOC investigation skill that helps an AI perform deep, evidence-driven investigations from a single suspicious event, entity, alert, host, user, IP, process, file, URL, domain, cloud resource, identity, email, or log record.

The skill must help the AI determine what happened, why it happened, whether the activity is malicious, suspicious, benign, or inconclusive, what related activity exists, what the likely root cause is, what the blast radius is, and what an analyst should do next.

## Scope

The skill is Microsoft-first and SOC-oriented. It prioritizes Microsoft Sentinel, Microsoft Defender XDR, Entra ID, Microsoft 365, Azure, and KQL-driven investigation workflows, while preserving generic incident-response reasoning that can apply to other logs or tools when the user provides them.

The default operating mode is static and offline. The skill may generate exact read-only queries and analyst-run pivot packets without needing live access. If the user explicitly authorizes live read-only querying and the necessary tools are available, the AI may run targeted, time-bounded read-only queries and record the results in a query ledger.

## Public Repository Constraints

This repository is public. The skill must not include secrets, tenant IDs, customer names, customer-specific indicators, confidential logs, AOAI endpoints, API keys, deployment names, internal URLs, private resource names, or any other sensitive operational details.

Examples must use synthetic entities such as `example.com`, `contoso.local`, placeholder hashes, generic hostnames, and clearly fictional users. Examples must not imply live validation unless the example explicitly says it is synthetic or analyst-supplied.

## Source Basis

The skill content will be based on:

- The user-approved SOC investigation orchestrator requirements captured during brainstorming.
- The existing `skills\kql-m365-azure-hunting` skill as the reference implementation for repository structure, YAML frontmatter, reference-selection style, answer shapes, examples, and offline fixtures.
- Summarized public source notes from:
  - MITRE ATT&CK Enterprise tactics: `https://attack.mitre.org/tactics/enterprise/`
  - Microsoft Sentinel incident investigation docs: `https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents`
  - Microsoft Sentinel entities docs: `https://learn.microsoft.com/en-us/azure/sentinel/entities`
  - Microsoft Sentinel data connectors reference: `https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference`
  - Microsoft Defender XDR advanced hunting overview: `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview`

The skill will summarize and generalize public documentation. It must not copy large third-party rule bodies, private detection content, or source text wholesale.

## Repository Structure

Add:

```text
skills\investigation-deepdive\SKILL.md
skills\investigation-deepdive\references\investigation-workflow.md
skills\investigation-deepdive\references\entity-pivot-playbook.md
skills\investigation-deepdive\references\microsoft-log-source-map.md
skills\investigation-deepdive\references\evidence-confidence-ledger.md
skills\investigation-deepdive\references\agent-orchestration-and-qa.md
skills\investigation-deepdive\references\report-shapes.md
skills\investigation-deepdive\references\public-source-notes.md
skills\investigation-deepdive\examples\seed-event-deep-dive.md
skills\investigation-deepdive\examples\microsoft-kql-pivot-packet.md
skills\investigation-deepdive\examples\evidence-ledger.md
skills\investigation-deepdive\examples\sub-agent-result.md
skills\investigation-deepdive\examples\final-report-skeleton.md
```

Update:

```text
README.md
tests\prompt-fixtures.md
tests\expected-behaviors.md
.claude-plugin\plugin.json
.claude-plugin\marketplace.json
```

Plugin metadata should remain valid JSON. Metadata updates should be limited to accurate repository-level description and keywords such as SOC investigation, incident response, Sentinel, Defender, and Azure. No per-tenant or deployment-specific metadata is allowed.

## Root Skill Design

`skills\investigation-deepdive\SKILL.md` will use Copilot-compatible YAML frontmatter:

```yaml
---
name: investigation-deepdive
description: Use when investigating suspicious security events, alerts, entities, hosts, users, IPs, processes, files, URLs, domains, cloud resources, identities, emails, or log records and producing an evidence-driven SOC investigation report.
---
```

The root skill will include:

- When to use the skill.
- Mission statement.
- Reference-selection rules.
- Operating flow.
- Safety guardrails.
- Live read-only authorization rules.
- Answer shapes.
- Integration note for `kql-m365-azure-hunting`.

## Reference Selection Rules

The AI should load the smallest useful reference set:

- Any seed-event investigation: `references\investigation-workflow.md`, `references\entity-pivot-playbooks.md`, and `references\evidence-confidence-ledger.md`.
- Microsoft Sentinel, Defender XDR, Entra ID, M365, Azure, or KQL investigation: add `references\microsoft-log-source-map.md` and use `kql-m365-azure-hunting` for KQL syntax, query-surface classification, and query review.
- Sub-agent orchestration, recursive branch management, or skeptical review: add `references\agent-orchestration-and-qa.md`.
- Report generation, executive summary, root cause, blast radius, recommendations, query ledger, or final answer formatting: add `references\report-shapes.md`.
- MITRE, Sentinel entities, Sentinel incident concepts, data connectors, or Defender advanced hunting source grounding: add `references\public-source-notes.md`.
- Evidence confidence, verdict, dead ends, or claim validation: add `references\evidence-confidence-ledger.md`.

The skill should avoid loading every reference by default unless the user requests a full investigation pack or the investigation has already expanded into multiple entity types.

## Operating Flow

The core workflow is:

1. Normalize and understand the seed event.
2. Extract all useful entities and observables.
3. State missing inputs and reasonable assumptions.
4. Choose time windows, defaulting to T-24h to T+24h for host/process activity, T-7d to T+48h for identity and authentication, and T-30d for baselines when needed.
5. Build an initial timeline.
6. Generate competing hypotheses.
7. Run or draft targeted read-only pivots.
8. Maintain an evidence ledger for major findings.
9. Recursively investigate new suspicious entities when evidence justifies branching.
10. Close dead ends explicitly.
11. Assess root cause and blast radius.
12. Run skeptical QA before finalizing.
13. Produce the final report with clear confidence and remaining gaps.

The skill must treat the seed event as a starting clue, not as the whole story. It must not overfit to the original alert or assume the alert is correct.

## Safety Guardrails

The skill must:

- Operate in read-only mode by default.
- Require explicit user authorization before live query execution.
- Use time-bounded and targeted queries.
- Never invent evidence, schema, tenant context, tool results, or live findings.
- Refuse destructive containment or remediation actions unless the user explicitly requests them outside this read-only investigation scope.
- Separate recommended actions from actions requiring approval.
- Avoid malware reverse engineering instructions beyond high-level triage pivots.
- Avoid exploit development, stealth, persistence, evasion, or destructive guidance.
- Avoid copying private or customer-specific investigation content.
- Mark unavailable telemetry as an investigation gap.
- Prefer evidence over assumptions and label inference clearly.

## Answer Shapes

The root skill will define these answer shapes:

- Initial investigation plan: seed summary, extracted entities, assumptions, time windows, hypotheses, pivots, expected evidence.
- Query and pivot packet: purpose, data source, time range, query, expected results, interpretation notes.
- Sub-agent result: agent name, scope, entities, queries or data sources, key findings, evidence references, confidence, next pivots, dead ends, open questions.
- Evidence ledger: finding ID, claim, evidence, source, timestamp, entity, confidence, MITRE mapping when applicable.
- Skeptical QA review: over-trust check, benign explanation check, causation check, timestamp consistency, telemetry gap check, scope check, evidence citation check, required revisions.
- Final investigation report: executive summary, seed event summary, timeline, key findings, root cause assessment, scope/blast radius, suspicious activity discovered, dead ends, recommended analyst actions, queries run, evidence ledger, open questions.

## Examples

Examples are necessary because the skill must be useful to an AI that starts with no domain knowledge.

The examples will show:

- A synthetic seed-event deep-dive workflow.
- A Microsoft KQL pivot packet that delegates KQL correctness to `kql-m365-azure-hunting`.
- A filled evidence ledger with synthetic evidence.
- A specialist sub-agent result format.
- A final report skeleton that follows the required 12-section output.

## Offline Acceptance Tests

Append investigation-specific fixtures to `tests\prompt-fixtures.md` and expected behavior entries to `tests\expected-behaviors.md`.

Planned fixtures:

- Suspicious PowerShell seed event on a host.
- Suspicious Entra sign-in seed event.
- Phishing email seed event with URL and attachment pivots.
- Cloud role assignment or service principal seed event.
- Request with missing telemetry that must remain inconclusive.
- Request asking the AI to isolate a host or disable a user, which must be treated as outside read-only scope unless explicitly authorized.
- Request asking for a final report from partial evidence.
- Request asking for sub-agent orchestration and skeptical QA.

Expected behaviors will verify that the AI selects the right references, extracts entities, creates bounded time windows, produces read-only pivots, maintains evidence and confidence, avoids invented schema or live results, tracks dead ends, applies skeptical QA, and produces the final report shape.

## Validation Plan

Run offline validation before completion:

- Parse `.claude-plugin\plugin.json` and `.claude-plugin\marketplace.json` as JSON.
- Verify `skills\investigation-deepdive\SKILL.md` exists.
- Verify `SKILL.md` has YAML frontmatter with `name` and `description`.
- Verify required references and examples exist.
- Verify `README.md` lists `investigation-deepdive` under Installed Skills.
- Verify prompt fixtures and expected behaviors contain matching investigation fixture headings.
- Scan added content for stale placeholder markers, unfinished task markers, template variables, and unresolved angle-bracket placeholders.
- Scan added content for public-repo sensitivity risks such as tenant IDs, API keys, secrets, real customer identifiers, private endpoints, and deployment names.
- Verify examples are internally consistent with the answer shapes and guardrails.

## Implementation Boundary

This design creates static markdown skill content and offline tests only. It does not add live scripts, credentials, dependencies, package managers, CI workflows, Azure resources, M365 app registrations, or executable tooling.

## Self-Review

- No placeholders remain in this design.
- The design matches the approved layered playbook approach.
- The scope is focused on one skill and can be implemented in one plan.
- Safety boundaries are explicit for a public repository.
- The source basis is named and conservative.
- The expected files match the repository structure used by the existing `kql-m365-azure-hunting` skill.
