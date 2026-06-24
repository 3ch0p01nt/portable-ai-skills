# Agent Orchestration and Skeptical QA

## Orchestrator Role

The lead investigator owns the investigation plan, branch selection, evidence ledger, hypothesis tracking, final verdict, and final report. Specialist agents are useful when a thread has a clear scope and enough evidence to investigate independently.

Create agents dynamically. Do not create agents just to create agents.

## Useful Specialist Agents

- Seed Event Triage Agent.
- Entity Extraction Agent.
- Timeline Reconstruction Agent.
- Host Investigation Agent.
- Identity Investigation Agent.
- Network Investigation Agent.
- Cloud Activity Agent.
- Email Investigation Agent.
- Endpoint Process Tree Agent.
- File, Hash, and Malware Triage Agent.
- Persistence Agent.
- Lateral Movement Agent.
- Privilege Escalation Agent.
- Data Access and Exfiltration Agent.
- Threat Intelligence Agent.
- Peer Baseline Agent.
- User Behavior Baseline Agent.
- Asset Criticality Agent.
- Detection Logic Review Agent.
- False Positive Review Agent.
- Root Cause Agent.
- Containment Recommendation Agent.
- Report Writer Agent.
- Skeptical QA Agent.

## Agent Result Shape

Each specialist result must include:

```text
agent_name:
scope:
entities investigated:
queries or data sources used:
key findings:
evidence references:
confidence level:
recommended next pivots:
dead ends:
open questions:
```

## Merge Rules

- Merge duplicate findings into one evidence-backed finding.
- Preserve disagreements and explain which evidence resolves or fails to resolve them.
- Promote only evidence-backed conclusions to the final report.
- Keep speculative leads in open questions or recommended pivots.
- Add closed branches to dead ends or ruled-out leads.
- Lower confidence when agents conflict or key telemetry is missing.

## Skeptical QA Checklist

Before finalizing, ask:

- Did we over-trust the alert?
- Did we ignore benign explanations?
- Did we confuse correlation with causation?
- Are there timestamps that do not line up?
- Are there missing logs that weaken the conclusion?
- Did we scope across enough users and hosts?
- Did we check both before and after the seed event?
- Did we identify the first known suspicious action?
- Did we document dead ends?
- Did every major claim cite evidence?

Revise the final report when QA finds weak evidence, missing scope, unsupported claims, or unresolved contradictions.
