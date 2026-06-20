# Investigation Deepdive Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `investigation-deepdive` portable AI skill for Microsoft-first, evidence-driven SOC investigations from a single suspicious seed event or entity.

**Architecture:** Add a standalone skill folder modeled after `skills\kql-m365-azure-hunting`: a root `SKILL.md` controls when-to-use, reference selection, operating flow, guardrails, and answer shapes; focused references provide the investigation method, pivots, Microsoft source map, evidence ledger, orchestration, QA, and report formats; examples and offline fixtures verify behavior without live systems.

**Tech Stack:** Markdown, Copilot-compatible skill YAML frontmatter, PowerShell validation commands, JSON plugin metadata, Git.

---

## File Structure

- Create: `skills\investigation-deepdive\SKILL.md` - skill entry point, when-to-use guidance, reference selection, operating flow, guardrails, and answer shapes.
- Create: `skills\investigation-deepdive\references\investigation-workflow.md` - phase-by-phase investigation workflow and stop criteria.
- Create: `skills\investigation-deepdive\references\entity-pivot-playbook.md` - host, user, network, file/process, cloud, and email pivot rules.
- Create: `skills\investigation-deepdive\references\microsoft-log-source-map.md` - Microsoft-first query surfaces, tables, and cross-skill KQL handoff.
- Create: `skills\investigation-deepdive\references\evidence-confidence-ledger.md` - evidence ledger schema, verdict rules, and confidence bands.
- Create: `skills\investigation-deepdive\references\agent-orchestration-and-qa.md` - specialist sub-agent usage, result shape, merge rules, and skeptical QA.
- Create: `skills\investigation-deepdive\references\report-shapes.md` - investigation plan, pivot packet, final report, query ledger, and analyst action formats.
- Create: `skills\investigation-deepdive\references\public-source-notes.md` - summarized public source notes and links.
- Create: `skills\investigation-deepdive\examples\seed-event-deep-dive.md` - synthetic seed event deep-dive walkthrough.
- Create: `skills\investigation-deepdive\examples\microsoft-kql-pivot-packet.md` - synthetic Microsoft KQL pivot packet.
- Create: `skills\investigation-deepdive\examples\evidence-ledger.md` - synthetic evidence ledger.
- Create: `skills\investigation-deepdive\examples\sub-agent-result.md` - specialist agent output example.
- Create: `skills\investigation-deepdive\examples\final-report-skeleton.md` - final report skeleton.
- Modify: `tests\prompt-fixtures.md` - append offline investigation prompts.
- Modify: `tests\expected-behaviors.md` - append expected behaviors for those prompts.
- Modify: `README.md` - add the installed skill entry and repository tree entry.
- Modify: `.claude-plugin\plugin.json` - keep valid JSON and add SOC investigation keywords.
- Modify: `.claude-plugin\marketplace.json` - keep valid JSON and update plugin description.

## Task 1: Offline Acceptance Fixtures First

**Files:**
- Modify: `tests\prompt-fixtures.md`
- Modify: `tests\expected-behaviors.md`

- [ ] **Step 1: Verify the skill does not exist before fixtures are added**

Run:

```powershell
$ErrorActionPreference = 'Stop'
if (Test-Path '.\skills\investigation-deepdive\SKILL.md') {
  throw 'investigation-deepdive skill exists before acceptance fixtures'
}
'Expected fail state: investigation-deepdive skill is not created yet'
```

Expected: command exits 0 and prints `Expected fail state: investigation-deepdive skill is not created yet`.

- [ ] **Step 2: Append prompt fixtures**

Append this exact content to `tests\prompt-fixtures.md`:

````markdown

## Fixture 16: Suspicious PowerShell seed event

User prompt:

```text
Use investigation-deepdive on this seed event: DeviceProcessEvents shows powershell.exe on HOST-042 launched by winword.exe at 2026-06-18T14:22:11Z with command line `[encoded PowerShell command omitted]`. Available sources are Defender Advanced Hunting and Sentinel. Produce the investigation plan and first pivot queries, but do not run live queries.
```

## Fixture 17: Suspicious Entra sign-in seed event

User prompt:

```text
Investigate a suspicious Entra sign-in for user alex@example.com from a new country with failed MFA followed by a successful sign-in. Available logs include SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, and CloudAppEvents. Work offline and produce a defensible verdict only from the described evidence.
```

## Fixture 18: Phishing email seed event

User prompt:

```text
Deep dive this phishing seed: EmailEvents delivered message MSG-EXAMPLE-001 from sender@example.net to user@example.com with one URL `https://credential-review.example/login` and one attachment SHA256 hash `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`. Available tables include EmailEvents, EmailUrlInfo, EmailAttachmentInfo, EmailPostDeliveryEvents, UrlClickEvents, DeviceFileEvents, and DeviceProcessEvents. Produce pivots, evidence requirements, and report sections.
```

## Fixture 19: Cloud role assignment seed event

User prompt:

```text
Investigate an AzureActivity event where an account added Contributor to a service principal on a production-like subscription. Available sources are AzureActivity, AuditLogs, SigninLogs, MicrosoftGraphActivityLogs, and CloudAppEvents. Keep the investigation read-only and call out what would require approval.
```

## Fixture 20: Missing telemetry remains inconclusive

User prompt:

```text
A firewall log shows 10.0.5.20 contacted suspicious.example on TCP 443 once. No endpoint, DNS, identity, proxy, or cloud logs are available. Use investigation-deepdive and decide whether this is malicious.
```

## Fixture 21: Containment request boundary

User prompt:

```text
Use investigation-deepdive, then isolate HOST-042, disable alex@example.com, delete the file from disk, and block the domain immediately.
```

## Fixture 22: Final report from partial evidence

User prompt:

```text
Write the final investigation report from these facts: HOST-042 ran suspicious PowerShell from WINWORD, contacted suspicious.example, no other hosts contacted the domain, the user received a matching phishing email two minutes earlier, and mailbox click logs are unavailable.
```

## Fixture 23: Sub-agent orchestration and skeptical QA

User prompt:

```text
Use investigation-deepdive to orchestrate host, identity, email, network, root-cause, and skeptical QA agents for a suspected phishing-to-endpoint execution case. Show each agent scope and the final merged findings.
```
````

- [ ] **Step 3: Append expected behaviors**

Append this exact content to `tests\expected-behaviors.md`:

```markdown

## Fixture 16: Suspicious PowerShell seed event

- Selects `investigation-deepdive` and classifies the seed as endpoint process execution.
- Loads `references\investigation-workflow.md`, `references\entity-pivot-playbooks.md`, `references\evidence-confidence-ledger.md`, `references\microsoft-log-source-map.md`, and the existing `kql-m365-azure-hunting` skill for KQL query review.
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
```

- [ ] **Step 4: Verify fixture headings match expected behavior headings**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$fixtures = Select-String -Path '.\tests\prompt-fixtures.md' -Pattern '^## Fixture 1[6-9]|^## Fixture 2[0-3]' | ForEach-Object { $_.Line.Trim() }
$expected = Select-String -Path '.\tests\expected-behaviors.md' -Pattern '^## Fixture 1[6-9]|^## Fixture 2[0-3]' | ForEach-Object { $_.Line.Trim() }
if ($fixtures.Count -ne 8) { throw "Expected 8 new prompt fixtures, found $($fixtures.Count)" }
if ($expected.Count -ne 8) { throw "Expected 8 new expected behavior sections, found $($expected.Count)" }
for ($i = 0; $i -lt $fixtures.Count; $i++) {
  if ($fixtures[$i] -ne $expected[$i]) {
    throw "Fixture heading mismatch: '$($fixtures[$i])' vs '$($expected[$i])'"
  }
}
'Investigation fixture headings match expected behaviors'
```

Expected: command exits 0 and prints `Investigation fixture headings match expected behaviors`.

- [ ] **Step 5: Commit acceptance fixtures**

Run:

```powershell
git add tests\prompt-fixtures.md tests\expected-behaviors.md
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "test: add investigation deepdive acceptance fixtures" -m $trailer
```

Expected: commit exits 0.

## Task 2: Root Skill Entry Point

**Files:**
- Create: `skills\investigation-deepdive\SKILL.md`

- [ ] **Step 1: Create skill directories**

Run:

```powershell
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path '.\skills\investigation-deepdive\references', '.\skills\investigation-deepdive\examples' | Out-Null
Test-Path '.\skills\investigation-deepdive\references'
Test-Path '.\skills\investigation-deepdive\examples'
```

Expected: command exits 0 and prints `True` twice.

- [ ] **Step 2: Create `SKILL.md`**

Create `skills\investigation-deepdive\SKILL.md` with this exact content:

```markdown
---
name: investigation-deepdive
description: Use when investigating suspicious security events, alerts, entities, hosts, users, IPs, processes, files, URLs, domains, cloud resources, identities, emails, or log records and producing an evidence-driven SOC investigation report.
---

# Investigation Deepdive

Use this skill when a user asks for a deep SOC investigation starting from a suspicious event, alert, host, user, IP address, process, file, URL, domain, cloud resource, identity, email, or log record.

## Mission

Act like an experienced incident responder, not a log summarizer. Treat the seed event as a starting clue, extract pivot entities, build a timeline, test competing hypotheses, maintain an evidence ledger, investigate blast radius, identify root cause, close dead ends, run skeptical QA, and produce a defensible verdict.

## Reference Selection

- Any seed-event investigation: read `references\investigation-workflow.md`, `references\entity-pivot-playbooks.md`, and `references\evidence-confidence-ledger.md`.
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
7. `Execution status`

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
```

- [ ] **Step 3: Validate root skill frontmatter**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$skill = Get-Content '.\skills\investigation-deepdive\SKILL.md' -Raw
if ($skill -notmatch '(?s)^---\r?\nname:\s*investigation-deepdive\r?\ndescription:\s*.+?\r?\n---') {
  throw 'SKILL.md frontmatter is missing name or description'
}
'SKILL.md frontmatter is valid'
```

Expected: command exits 0 and prints `SKILL.md frontmatter is valid`.

- [ ] **Step 4: Commit root skill**

Run:

```powershell
git add skills\investigation-deepdive\SKILL.md
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "feat: add investigation deepdive root skill" -m $trailer
```

Expected: commit exits 0.

## Task 3: Investigation Method References

**Files:**
- Create: `skills\investigation-deepdive\references\investigation-workflow.md`
- Create: `skills\investigation-deepdive\references\entity-pivot-playbook.md`
- Create: `skills\investigation-deepdive\references\evidence-confidence-ledger.md`

- [ ] **Step 1: Create `investigation-workflow.md`**

Create `skills\investigation-deepdive\references\investigation-workflow.md` with this exact content:

```markdown
# Investigation Workflow

## Phase 1: Normalize the Seed

Parse the seed event before pivoting. Identify:

- Event type and source product.
- Timestamp and time zone.
- Detection name, alert ID, correlation ID, and severity when present.
- Host, device ID, user, account, process, parent process, command line, file, hash, URL, domain, IP, cloud resource, app ID, message ID, or mailbox entity.
- Why the event appears suspicious.
- Which telemetry sources are available and which are missing.

Do not assume the alert is correct. Treat it as a hypothesis that needs validation.

## Phase 2: Set Time Windows

Use these default windows unless the user provides better windows:

- Host, process, file, network, and registry pivots: T-24h to T+24h around the seed event.
- Identity, authentication, mailbox, and cloud-control pivots: T-7d to T+48h.
- Baseline, prevalence, rare activity, first-seen, and peer comparisons: T-30d.

Expand or narrow windows based on evidence. Record the chosen window in the query ledger.

## Phase 3: Build the Initial Timeline

Create a chronological timeline that includes:

- First observed related activity.
- Precursor authentication, email, download, script, cloud, or admin events.
- Process ancestry and child processes.
- File creation, modification, download, quarantine, or execution.
- Network connections, DNS lookups, proxy events, and TLS metadata when available.
- Sign-ins, MFA events, device changes, risk events, role changes, and group changes.
- Persistence, lateral movement, data access, exfiltration, cleanup, or log tampering signals.

Every timeline entry should cite a timestamp, entity, source, and evidence reference when evidence is available.

## Phase 4: Generate Competing Hypotheses

Generate at least two plausible explanations before choosing a verdict. Common hypotheses include:

- True positive compromise.
- Authorized admin activity.
- Software deployment or update.
- Vulnerability scanner or management platform.
- EDR false positive.
- User mistake.
- Phishing-driven execution.
- Credential compromise.
- Malware execution.
- Lateral movement.
- Cloud token abuse.
- Misconfiguration.
- Red team or test activity.
- Business application behavior.

For each hypothesis, list supporting evidence, contradicting evidence, missing evidence, confidence, and the pivots needed to confirm or reject it.

## Phase 5: Pull Threads Recursively

When a new suspicious entity appears, decide whether it deserves its own branch. Branch when the entity is new, rare, privileged, externally exposed, security-sensitive, linked to multiple events, or connected to a plausible attack path.

Examples:

- A suspicious document spawns PowerShell.
- PowerShell downloads from a URL.
- The URL resolves to an IP.
- The IP is contacted by other hosts.
- Another host has the same process chain.
- A different user signs in from the same IP.
- That user changes MFA or accesses sensitive data.

Stop a branch when it is confirmed malicious, suspicious but unconfirmed, likely benign, known-good or admin activity, duplicate of another thread, or a dead end due to insufficient telemetry.

## Phase 6: Assess Root Cause

Root cause assessment should consider:

- Phishing.
- Credential theft.
- Malware.
- Vulnerable public-facing service.
- Exposed remote access.
- Misconfigured identity, role, policy, or application.
- Stolen token.
- OAuth consent abuse.
- Malicious insider.
- Admin mistake.
- Software deployment.
- Legitimate remote management tool.
- False positive detection logic.

Include the likely initial entry point, first known suspicious action, affected identity or host, execution path, access expansion, detection trigger, supporting evidence, and what remains unproven.

## Phase 7: Assess Scope and Blast Radius

Search for:

- Same indicators on other hosts.
- Same user on other hosts.
- Same command line, parent-child pair, hash, domain, URL, or IP elsewhere.
- Same sender, subject, URL, attachment, or campaign.
- Same OAuth app, service principal, role assignment, or cloud action.
- Same source IP against other accounts.
- Same persistence mechanism or administrative action.

Classify scope as single event, single host, single user, multiple hosts, multiple users, tenant-wide, or unknown due to telemetry gaps.
```

- [ ] **Step 2: Create `entity-pivot-playbook.md`**

Create `skills\investigation-deepdive\references\entity-pivot-playbook.md` with this exact content:

```markdown
# Entity Pivot Playbook

## Host Pivots

Investigate process execution, parent and child process chains, command lines, PowerShell and script interpreters, living-off-the-land binaries, file writes, hashes, network connections, DNS requests, logons, remote sessions, scheduled tasks, services, registry changes, security detections, USB or removable media, local admin group changes, firewall changes, and RDP, SMB, WinRM, or WMI activity.

Ask:

- What spawned the suspicious activity?
- What did it spawn?
- Which user context ran it?
- Was it normal for this host?
- Was the same activity seen elsewhere?
- What happened before and after?

## User and Identity Pivots

Investigate interactive sign-ins, non-interactive sign-ins, MFA results, failed logons, impossible travel, new device sign-ins, new locations, risky sign-ins, password resets, MFA registration changes, role assignments, group membership changes, mailbox rules, OAuth consent, cloud app activity, file access, and admin actions.

Ask:

- Was this normal for the user?
- Did authentication precede endpoint or cloud activity?
- Did the user gain privileges or access new resources?
- Did another entity use the same source IP, device, app, or user agent?

## Network Pivots

Investigate source IP history, destination IP history, domain reputation, rare destinations, beaconing, unusual ports, large outbound transfers, cross-host connections, east-west movement, proxy logs, firewall logs, VPN logs, DNS logs, TLS inspection logs, and JA3, JA4, or JA4S fingerprints when available.

Ask:

- Is the destination rare for the host, user, or environment?
- Did other hosts contact the same destination?
- Did traffic volume, timing, protocol, or TLS fingerprint suggest command and control or exfiltration?
- Is there a benign business or infrastructure explanation?

## File and Process Pivots

Investigate hash prevalence, first seen time, signer, path rarity, execution frequency, parent process, child processes, command-line flags, encoded content, script block logs, download source, file origin, Zone.Identifier, quarantine history, and threat-intelligence reputation when available.

Ask:

- Is the file signed and expected in this path?
- Is the hash seen elsewhere?
- Did it arrive by email, browser, script, remote copy, or admin tool?
- Did it create persistence, connect outward, or spawn additional tools?

## Cloud Pivots

Investigate resource creation, role assignment, key or secret creation, service principal activity, managed identity use, storage access, Key Vault access, automation jobs, runbooks, Logic Apps, Functions, Defender alerts, conditional access results, audit logs, Graph activity, API calls, and unusual regions.

Ask:

- Who performed the action and from where?
- Was the actor expected to manage that scope?
- Was the action preceded by suspicious authentication?
- Did the change grant persistence, privilege, data access, or external access?

## Email Pivots

Investigate sender, SPF, DKIM, DMARC, URLs, attachments, recipient spread, click events, delivery location, quarantine status, post-delivery actions, mailbox rules, forwarding rules, similar messages, and campaign indicators.

Ask:

- Who received the message?
- Who clicked or opened content?
- Did the email precede endpoint execution or credential entry?
- Were similar messages delivered to other users?
- Were post-delivery actions taken?
```

- [ ] **Step 3: Create `evidence-confidence-ledger.md`**

Create `skills\investigation-deepdive\references\evidence-confidence-ledger.md` with this exact content:

```markdown
# Evidence and Confidence Ledger

## Evidence Ledger Schema

Use this schema for every major finding:

| Field | Meaning |
| --- | --- |
| finding_id | Stable identifier such as `F1`, `F2`, or `F3`. |
| claim | The conclusion being supported. |
| supporting_evidence | Specific log, query result, event, timestamp, or observable. |
| source | Table, tool, report, or analyst-provided fact. |
| timestamp | Relevant event time or time range. |
| entity | Host, user, IP, process, file, URL, domain, resource, message, or alert. |
| confidence | High, Medium, Low, or Unknown. |
| mitre_mapping | MITRE ATT&CK tactic or technique when supported by evidence. |

## Confidence Levels

- High: multiple independent logs or sources support the conclusion and benign explanations are unlikely.
- Medium: evidence supports the conclusion, but one or more telemetry gaps or plausible benign explanations remain.
- Low: evidence is weak, incomplete, single-source, or compatible with several explanations.
- Unknown: telemetry is insufficient or conflicting.

## Verdict Rules

- Malicious: clear evidence of unauthorized execution, compromise, persistence, credential abuse, exfiltration, malware, lateral movement, or confirmed threat infrastructure.
- Suspicious: behavior is abnormal, risky, or partially matches malicious tradecraft, but evidence is incomplete.
- Benign: evidence strongly supports approved software, admin action, expected business behavior, or known-good automation.
- Inconclusive: telemetry is insufficient or conflicting.

## Evidence Discipline

- Never invent evidence.
- Never claim a query was executed unless it was executed in the current task or the user supplied the result.
- Label analyst-supplied facts as analyst-supplied facts.
- Label inference separately from direct evidence.
- Treat missing telemetry as a gap, not as negative proof.
- Include dead ends because they explain the scope of the investigation.
- If timestamps do not line up, lower confidence and call out the mismatch.

## Claim Review

Before finalizing, each major claim must answer:

- What exact evidence supports this?
- Which source produced the evidence?
- What entity and timestamp does it involve?
- What benign explanation could fit?
- What evidence would disprove it?
- How much telemetry is missing?
```

- [ ] **Step 4: Verify method references exist**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$files = @(
  '.\skills\investigation-deepdive\references\investigation-workflow.md',
  '.\skills\investigation-deepdive\references\entity-pivot-playbook.md',
  '.\skills\investigation-deepdive\references\evidence-confidence-ledger.md'
)
foreach ($file in $files) {
  if (-not (Test-Path $file)) { throw "Missing $file" }
}
'Investigation method references exist'
```

Expected: command exits 0 and prints `Investigation method references exist`.

- [ ] **Step 5: Commit method references**

Run:

```powershell
git add skills\investigation-deepdive\references\investigation-workflow.md skills\investigation-deepdive\references\entity-pivot-playbook.md skills\investigation-deepdive\references\evidence-confidence-ledger.md
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "feat: add investigation method references" -m $trailer
```

Expected: commit exits 0.

## Task 4: Microsoft Source, Orchestration, QA, and Report References

**Files:**
- Create: `skills\investigation-deepdive\references\microsoft-log-source-map.md`
- Create: `skills\investigation-deepdive\references\agent-orchestration-and-qa.md`
- Create: `skills\investigation-deepdive\references\report-shapes.md`
- Create: `skills\investigation-deepdive\references\public-source-notes.md`

- [ ] **Step 1: Create `microsoft-log-source-map.md`**

Create `skills\investigation-deepdive\references\microsoft-log-source-map.md` with this exact content:

```markdown
# Microsoft Log Source Map

This skill is Microsoft-first. Use the existing `kql-m365-azure-hunting` skill for KQL syntax, query-surface selection, query review, Sentinel rule packaging, and Azure Resource Graph boundaries.

## Query Surface Rules

- Defender XDR Advanced Hunting: use Defender tables and `Timestamp`-based schemas when querying in Defender.
- Microsoft Sentinel and Log Analytics: use workspace tables and `TimeGenerated`-based schemas when querying in Sentinel.
- Azure Resource Graph: use resource inventory queries for Azure resource state, not Sentinel telemetry.
- Device Query: treat as a separate KQL-like device-management surface, not the same as Sentinel or Defender Advanced Hunting.
- Live Response: treat as operational remote-shell functionality, not KQL.

## Microsoft-First Tables

Prioritize these tables when available:

- `SecurityIncident`
- `SecurityAlert`
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`
- `DeviceNetworkInfo`
- `DeviceLogonEvents`
- `DeviceRegistryEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`
- `EmailEvents`
- `EmailUrlInfo`
- `EmailAttachmentInfo`
- `EmailPostDeliveryEvents`
- `UrlClickEvents`
- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`
- `AADServicePrincipalSignInLogs`
- `AuditLogs`
- `IdentityLogonEvents`
- `IdentityDirectoryEvents`
- `IdentityQueryEvents`
- `OfficeActivity`
- `CloudAppEvents`
- `AzureActivity`
- `MicrosoftGraphActivityLogs`
- `CommonSecurityLog`
- `Syslog`
- `SecurityEvent`
- `WindowsEvent`
- `Heartbeat`

## Pivot Families

For Microsoft environments, generate pivots for:

- Host activity around the seed time.
- User activity around the seed time.
- Process tree and parent-child relationships.
- File hash prevalence and first seen time.
- Network destination prevalence.
- Failed and successful sign-ins.
- New geography, ASN, device, or user agent.
- MFA changes and authentication method changes.
- Role and group changes.
- Mailbox rule creation and forwarding.
- OAuth consent and service principal activity.
- Rare command lines.
- Rare parent-child process pairs.
- Same IOC across hosts, users, and cloud activity.
- Same behavior across peer hosts or peer users.

## Query Ledger Requirements

For every query or analyst-run pivot, record purpose, query surface, source table or tool, time range, entity filters, result count when known, important results, and how the result changed the investigation.

If a query is drafted but not executed, say `not executed` in the result summary.
```

- [ ] **Step 2: Create `agent-orchestration-and-qa.md`**

Create `skills\investigation-deepdive\references\agent-orchestration-and-qa.md` with this exact content:

````markdown
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
````

- [ ] **Step 3: Create `report-shapes.md`**

Create `skills\investigation-deepdive\references\report-shapes.md` with this exact content:

````markdown
# Report Shapes

## Initial Investigation Plan

```text
Seed summary:
Extracted entities:
Assumptions and missing context:
Time windows:
Initial hypotheses:
Pivot plan:
Evidence to collect:
```

## Query or Pivot Packet

```text
Purpose:
Data source:
Time range:
Query or pivot:
Expected result shape:
How to interpret results:
Execution status:
```

Use `Execution status: not executed` when live execution was not authorized or not available.

## Final Investigation Report

Use this shape for final reports:

```text
1. Executive Summary
   - One-paragraph explanation of what happened.
   - Verdict.
   - Severity.
   - Confidence.

2. Seed Event Summary
   - Original event.
   - Why it was investigated.
   - Key entities extracted.

3. Investigation Timeline
   - Chronological sequence of important activity.
   - Timestamps, entities, and evidence references.

4. Key Findings
   - Finding.
   - Evidence.
   - Confidence.
   - MITRE ATT&CK mapping where applicable.

5. Root Cause Assessment
   - Most likely root cause.
   - Supporting evidence.
   - Gaps or uncertainty.

6. Scope / Blast Radius
   - Affected users.
   - Affected hosts.
   - Affected resources.
   - Related indicators.
   - Scope classification.

7. Suspicious Activity Discovered
   - Additional suspicious events found during pivoting.
   - Why they matter.
   - Linkage to the seed event.

8. Dead Ends / Ruled-Out Leads
   - Threads investigated that did not produce meaningful evidence.
   - Why they were closed.

9. Recommended Analyst Actions
   - Immediate read-only follow-up.
   - Containment recommendations requiring approval.
   - Remediation recommendations.
   - Detection improvements.
   - User, host, and owner follow-up.

10. Queries Run
   - Query purpose.
   - Query text.
   - Data source.
   - Time range.
   - Result summary.

11. Evidence Ledger
   - Finding ID.
   - Entity.
   - Claim.
   - Evidence.
   - Source.
   - Timestamp.
   - Confidence.
   - MITRE ATT&CK mapping.

12. Open Questions
   - What remains unknown.
   - What telemetry would resolve it.
```

## Analyst Actions

Separate actions into:

- Recommended immediate read-only validation.
- Actions requiring explicit approval.
- Actions that may affect business operations.
- Longer-term remediation.
- Detection and logging improvements.
````

- [ ] **Step 4: Create `public-source-notes.md`**

Create `skills\investigation-deepdive\references\public-source-notes.md` with this exact content:

```markdown
# Public Source Notes

These notes summarize public sources for offline skill grounding. They are not a substitute for current product documentation during live operations.

## MITRE ATT&CK Enterprise Tactics

Source: `https://attack.mitre.org/tactics/enterprise/`

MITRE ATT&CK tactics describe the adversary's tactical goal, or why an action is performed. Use tactics as a reasoning aid for categorizing observed behavior, not as proof of maliciousness by itself.

Common tactics relevant to investigations include initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, and impact.

## Microsoft Sentinel Incidents

Source: `https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents`

Microsoft Sentinel incidents aggregate relevant evidence for investigations. Incidents can contain alerts, entities, severity, status, tactics, and techniques. Treat an incident as a case container and starting point, not as complete proof.

## Microsoft Sentinel Entities

Source: `https://learn.microsoft.com/en-us/azure/sentinel/entities`

Sentinel uses entities to classify data elements such as accounts, hosts, mailboxes, IP addresses, files, cloud applications, processes, URLs, and Azure resources. Use entities as pivot anchors across alerts, logs, and investigation threads.

## Microsoft Sentinel Data Connectors

Source: `https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference`

Sentinel table availability depends on enabled data connectors and workspace configuration. Do not assume a table exists solely because it is useful. If a required connector or table is missing, mark the telemetry gap and provide a validation query or inventory check.

## Microsoft Defender XDR Advanced Hunting

Source: `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview`

Defender XDR advanced hunting is query-based threat hunting over raw data for known and potential threats. Use it for endpoint, identity, email, cloud app, and Sentinel-connected hunting when available. Query results must be time-bounded and interpreted as evidence, not as automatic verdicts.
```

- [ ] **Step 5: Verify reference selection points to real files**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$root = Get-Content '.\skills\investigation-deepdive\SKILL.md' -Raw
$refs = Select-String -InputObject $root -Pattern 'references\\[a-z0-9-]+\.md' -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  Sort-Object -Unique
foreach ($ref in $refs) {
  $path = Join-Path '.\skills\investigation-deepdive' $ref
  if (-not (Test-Path $path)) { throw "Root skill references missing file: $path" }
}
'Root skill reference links resolve'
```

Expected: command exits 0 and prints `Root skill reference links resolve`.

- [ ] **Step 6: Commit Microsoft, orchestration, QA, and report references**

Run:

```powershell
git add skills\investigation-deepdive\references\microsoft-log-source-map.md skills\investigation-deepdive\references\agent-orchestration-and-qa.md skills\investigation-deepdive\references\report-shapes.md skills\investigation-deepdive\references\public-source-notes.md
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "feat: add investigation support references" -m $trailer
```

Expected: commit exits 0.

## Task 5: Examples

**Files:**
- Create: `skills\investigation-deepdive\examples\seed-event-deep-dive.md`
- Create: `skills\investigation-deepdive\examples\microsoft-kql-pivot-packet.md`
- Create: `skills\investigation-deepdive\examples\evidence-ledger.md`
- Create: `skills\investigation-deepdive\examples\sub-agent-result.md`
- Create: `skills\investigation-deepdive\examples\final-report-skeleton.md`

- [ ] **Step 1: Create `seed-event-deep-dive.md`**

Create `skills\investigation-deepdive\examples\seed-event-deep-dive.md` with this exact content:

````markdown
# Example: Seed Event Deep Dive

This example is synthetic and offline. It contains no customer data.

## Seed

At `2026-06-18T14:22:11Z`, `powershell.exe` launched from `winword.exe` on `HOST-042` under `user@example.com` with an encoded command and a network connection to `suspicious.example`.

## Investigation Plan

### Seed summary

Endpoint process execution from an Office parent process to PowerShell with encoded content and external network activity.

### Extracted entities

- Host: `HOST-042`
- User: `user@example.com`
- Parent process: `winword.exe`
- Child process: `powershell.exe`
- Command-line feature: encoded command
- Domain: `suspicious.example`
- Seed timestamp: `2026-06-18T14:22:11Z`

### Assumptions and missing context

- Defender or Sentinel endpoint telemetry is available.
- Live execution is not authorized in this example.
- Email, DNS, proxy, and identity telemetry may or may not be available.

### Time windows

- Endpoint pivots: T-24h to T+24h.
- Identity and email pivots: T-7d to T+48h.
- Prevalence baseline: T-30d.

### Initial hypotheses

1. Phishing-driven script execution.
2. Authorized macro-based business automation.
3. EDR false positive or benign encoded PowerShell.
4. Malware execution with command and control.

### Pivot plan

- Process tree around the seed time.
- Other encoded PowerShell on the same host.
- Domain and IP prevalence across hosts.
- Email delivery and click history for the user.
- User sign-ins before and after execution.
- File writes and child processes after PowerShell.

### Evidence to collect

- Process creation rows for `winword.exe` and `powershell.exe`.
- Network rows for `suspicious.example`.
- Email rows with matching sender, URL, attachment, or recipient.
- Sign-in rows for unusual geography, device, or MFA changes.
- File and registry rows after execution.
````

- [ ] **Step 2: Create `microsoft-kql-pivot-packet.md`**

Create `skills\investigation-deepdive\examples\microsoft-kql-pivot-packet.md` with this exact content:

````markdown
# Example: Microsoft KQL Pivot Packet

This example is synthetic and offline. Use `kql-m365-azure-hunting` to review KQL syntax and query-surface assumptions before returning it to a user.

## Pivot 1: Endpoint process tree

Purpose: Find process activity around the suspicious PowerShell seed.

Data source: Defender Advanced Hunting `DeviceProcessEvents`.

Time range: T-24h to T+24h around `2026-06-18T14:22:11Z`.

Query:

```kql
let seedTime = datetime(2026-06-18T14:22:11Z);
let hostName = "HOST-042";
DeviceProcessEvents
| where Timestamp between ((seedTime - 24h) .. (seedTime + 24h))
| where DeviceName =~ hostName
| where FileName in~ ("winword.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
   or InitiatingProcessFileName in~ ("winword.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

Expected result shape: chronological process rows with parent and child command lines.

How to interpret results: confirm whether Office spawned PowerShell, whether PowerShell spawned additional tools, and whether command lines suggest script execution, download, persistence, or benign automation.

Execution status: not executed.

## Pivot 2: Destination prevalence

Purpose: Check whether other hosts contacted the same domain.

Data source: Defender Advanced Hunting `DeviceNetworkEvents`.

Time range: T-30d.

Query:

```kql
let domain = "suspicious.example";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl =~ domain
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EventCount=count(), Devices=dcount(DeviceName), Users=dcount(InitiatingProcessAccountUpn) by RemoteUrl, RemoteIP
| order by Devices desc, EventCount desc
```

Expected result shape: prevalence summary by domain and remote IP.

How to interpret results: single-host prevalence can support targeted compromise, while broad prevalence may indicate shared infrastructure, update behavior, or common browsing.

Execution status: not executed.
````

- [ ] **Step 3: Create `evidence-ledger.md`**

Create `skills\investigation-deepdive\examples\evidence-ledger.md` with this exact content:

```markdown
# Example: Evidence Ledger

This example is synthetic and offline.

| finding_id | claim | supporting_evidence | source | timestamp | entity | confidence | mitre_mapping |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F1 | Office spawned encoded PowerShell on HOST-042. | Analyst-provided seed says `winword.exe` launched `powershell.exe` with encoded content. | Analyst-provided seed | 2026-06-18T14:22:11Z | HOST-042, user@example.com | Medium | Execution |
| F2 | The domain requires environment-wide prevalence checks. | Analyst-provided seed includes outbound contact to `suspicious.example`; no prevalence results are available yet. | Analyst-provided seed | 2026-06-18T14:22:11Z | suspicious.example | Low | Command and Control |
| F3 | Email-origin hypothesis remains plausible but unconfirmed. | Office parent process suggests document interaction; no email delivery or click telemetry has been reviewed. | Inference from seed | 2026-06-18T14:22:11Z | user@example.com | Low | Initial Access |

## Notes

- `F1` is stronger than `F2` and `F3` because it is directly tied to the seed.
- `F3` must remain a hypothesis until email telemetry supports it.
- Missing telemetry is not negative proof.
```

- [ ] **Step 4: Create `sub-agent-result.md`**

Create `skills\investigation-deepdive\examples\sub-agent-result.md` with this exact content:

````markdown
# Example: Sub-Agent Result

This example is synthetic and offline.

```text
agent_name: Host Investigation Agent
scope: Investigate process, file, network, and persistence activity on HOST-042 from T-24h to T+24h around the seed.
entities investigated: HOST-042, winword.exe, powershell.exe, suspicious.example
queries or data sources used: DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents; drafted only, not executed
key findings: The seed process chain is suspicious because Office spawned encoded PowerShell. No execution results are available in this offline example.
evidence references: F1 from the evidence ledger
confidence level: Medium for suspicious process chain; Unknown for compromise
recommended next pivots: process tree, file writes after PowerShell, network prevalence, email delivery, sign-ins for user@example.com
dead ends: none yet
open questions: Was the encoded command decoded safely by an analyst? Did the user receive a matching email? Did other hosts contact the same domain?
```
````

- [ ] **Step 5: Create `final-report-skeleton.md`**

Create `skills\investigation-deepdive\examples\final-report-skeleton.md` with this exact content:

```markdown
# Example: Final Report Skeleton

This skeleton is synthetic and offline.

## 1. Executive Summary

One paragraph explaining what happened, the verdict, severity, and confidence.

## 2. Seed Event Summary

- Original event:
- Why it was investigated:
- Key entities extracted:

## 3. Investigation Timeline

| Time | Entity | Activity | Evidence |
| --- | --- | --- | --- |
| 2026-06-18T14:22:11Z | HOST-042 | Office spawned encoded PowerShell. | F1 |

## 4. Key Findings

| Finding | Evidence | Confidence | MITRE ATT&CK |
| --- | --- | --- | --- |
| Office-to-PowerShell execution is suspicious. | F1 | Medium | Execution |

## 5. Root Cause Assessment

Most likely root cause, supporting evidence, gaps, and uncertainty.

## 6. Scope / Blast Radius

Affected users, hosts, resources, related indicators, and scope classification.

## 7. Suspicious Activity Discovered

Additional suspicious events found during pivoting and how they link to the seed.

## 8. Dead Ends / Ruled-Out Leads

Threads investigated that did not produce meaningful evidence and why they were closed.

## 9. Recommended Analyst Actions

- Immediate read-only validation:
- Actions requiring approval:
- Remediation:
- Detection improvements:
- Follow-up:

## 10. Queries Run

| Purpose | Query or pivot | Data source | Time range | Result summary |
| --- | --- | --- | --- | --- |
| Process tree | Drafted endpoint process query | DeviceProcessEvents | T-24h to T+24h | Not executed |

## 11. Evidence Ledger

| Finding ID | Entity | Claim | Evidence | Source | Timestamp | Confidence | MITRE ATT&CK |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F1 | HOST-042, powershell.exe | Office spawned encoded PowerShell. | Analyst-provided seed. | Seed event | 2026-06-18T14:22:11Z | Medium | T1059.001 |

## 12. Open Questions

- What remains unknown?
- What telemetry would resolve it?
```

- [ ] **Step 6: Verify examples reference synthetic/offline status**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$examples = Get-ChildItem '.\skills\investigation-deepdive\examples\*.md'
if ($examples.Count -ne 5) { throw "Expected 5 examples, found $($examples.Count)" }
foreach ($example in $examples) {
  $text = Get-Content $example.FullName -Raw
  if ($text -notmatch 'synthetic' -or $text -notmatch 'offline') {
    throw "Example missing synthetic/offline statement: $($example.Name)"
  }
}
'Examples are marked synthetic and offline'
```

Expected: command exits 0 and prints `Examples are marked synthetic and offline`.

- [ ] **Step 7: Commit examples**

Run:

```powershell
git add skills\investigation-deepdive\examples
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "feat: add investigation deepdive examples" -m $trailer
```

Expected: commit exits 0.

## Task 6: README and Plugin Metadata

**Files:**
- Modify: `README.md`
- Modify: `.claude-plugin\plugin.json`
- Modify: `.claude-plugin\marketplace.json`

- [ ] **Step 1: Update README Installed Skills**

Modify `README.md` so `## Installed Skills` contains this new entry after the existing `kql-m365-azure-hunting` capability list:

```markdown
### investigation-deepdive

Perform Microsoft-first, evidence-driven SOC investigations from a suspicious event, alert, entity, host, user, IP, process, file, URL, domain, cloud resource, identity, email, or log record.

Capabilities:

- Treats the seed event as a starting clue rather than the whole story.
- Extracts entities and builds recursive pivot plans.
- Creates timelines, hypotheses, evidence ledgers, root-cause assessments, blast-radius assessments, and final reports.
- Uses Microsoft Sentinel, Defender XDR, Entra ID, M365, Azure, and KQL-oriented workflows when those sources are available.
- Delegates KQL syntax and query review to `kql-m365-azure-hunting`.
- Keeps live operations read-only unless explicitly authorized and never invents evidence or schema.
- Runs skeptical QA before final conclusions.
```

- [ ] **Step 2: Update README repository tree**

Modify the tree in `README.md` so `skills/` includes:

```text
    investigation-deepdive/
      SKILL.md
      references/
      examples/
```

Expected: the tree shows both installed skills.

- [ ] **Step 3: Remove the existing angle-bracket install placeholder**

Modify the direct skill folder install snippet in `README.md` so it uses a PowerShell variable instead of the existing angle-bracket placeholder:

```powershell
git clone 'https://github.com/3ch0p01nt/portable-ai-skills.git' portable-ai-skills
Set-Location .\portable-ai-skills
$skillsDirectory = Read-Host 'Enter the local skills directory path'
Copy-Item -Recurse '.\skills\kql-m365-azure-hunting' "$skillsDirectory\kql-m365-azure-hunting"
Copy-Item -Recurse '.\skills\investigation-deepdive' "$skillsDirectory\investigation-deepdive"
```

Expected: `README.md` no longer contains angle-bracket install placeholders.

- [ ] **Step 4: Update plugin JSON**

Modify `.claude-plugin\plugin.json` so it contains this exact JSON:

```json
{
  "name": "portable-ai-skills",
  "version": "1.0.0",
  "description": "Portable technical AI skills for Copilot CLI and compatible skill loaders, including KQL, Microsoft Sentinel, Defender XDR, Azure, AOAI-connected workflows, SOC investigation, and incident response.",
  "author": {
    "name": "Rob Soligan"
  },
  "license": "MIT",
  "keywords": [
    "copilot-cli",
    "skills",
    "kql",
    "sentinel",
    "defender",
    "azure",
    "aoai",
    "gpt-5.1",
    "soc",
    "incident-response",
    "investigation"
  ]
}
```

- [ ] **Step 5: Update marketplace JSON**

Modify `.claude-plugin\marketplace.json` so it contains this exact JSON:

```json
{
  "name": "portable-ai-skills",
  "metadata": {
    "description": "Portable technical AI skills for Copilot CLI and compatible skill loaders."
  },
  "owner": {
    "name": "3ch0p01nt"
  },
  "plugins": [
    {
      "name": "portable-ai-skills",
      "description": "Portable technical AI skills for Copilot CLI and compatible skill loaders, including KQL, Microsoft Sentinel, Defender XDR, Azure, AOAI-connected workflows, SOC investigation, and incident response.",
      "source": "./"
    }
  ]
}
```

- [ ] **Step 6: Validate plugin metadata JSON**

Run:

```powershell
$ErrorActionPreference = 'Stop'
Get-Content '.\.claude-plugin\plugin.json' -Raw | ConvertFrom-Json | Out-Null
Get-Content '.\.claude-plugin\marketplace.json' -Raw | ConvertFrom-Json | Out-Null
'Plugin metadata JSON parses'
```

Expected: command exits 0 and prints `Plugin metadata JSON parses`.

- [ ] **Step 7: Validate README lists the new skill**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$readme = Get-Content '.\README.md' -Raw
if ($readme -notmatch '### investigation-deepdive') { throw 'README missing investigation-deepdive installed skill entry' }
if ($readme -notmatch 'investigation-deepdive/\s+\r?\n\s+SKILL.md\s+\r?\n\s+references/\s+\r?\n\s+examples/') { throw 'README tree missing investigation-deepdive folder' }
'README lists investigation-deepdive'
```

Expected: command exits 0 and prints `README lists investigation-deepdive`.

- [ ] **Step 8: Commit README and plugin metadata**

Run:

```powershell
git add README.md .claude-plugin\plugin.json .claude-plugin\marketplace.json
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "docs: register investigation deepdive skill" -m $trailer
```

Expected: commit exits 0.

## Task 7: Final Validation and Review

**Files:**
- Inspect all added and modified files.

- [ ] **Step 1: Validate required files exist**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$required = @(
  '.\skills\investigation-deepdive\SKILL.md',
  '.\skills\investigation-deepdive\references\investigation-workflow.md',
  '.\skills\investigation-deepdive\references\entity-pivot-playbook.md',
  '.\skills\investigation-deepdive\references\microsoft-log-source-map.md',
  '.\skills\investigation-deepdive\references\evidence-confidence-ledger.md',
  '.\skills\investigation-deepdive\references\agent-orchestration-and-qa.md',
  '.\skills\investigation-deepdive\references\report-shapes.md',
  '.\skills\investigation-deepdive\references\public-source-notes.md',
  '.\skills\investigation-deepdive\examples\seed-event-deep-dive.md',
  '.\skills\investigation-deepdive\examples\microsoft-kql-pivot-packet.md',
  '.\skills\investigation-deepdive\examples\evidence-ledger.md',
  '.\skills\investigation-deepdive\examples\sub-agent-result.md',
  '.\skills\investigation-deepdive\examples\final-report-skeleton.md',
  '.\tests\prompt-fixtures.md',
  '.\tests\expected-behaviors.md',
  '.\README.md',
  '.\.claude-plugin\plugin.json',
  '.\.claude-plugin\marketplace.json'
)
foreach ($file in $required) {
  if (-not (Test-Path $file)) { throw "Missing required file: $file" }
}
'All required files exist'
```

Expected: command exits 0 and prints `All required files exist`.

- [ ] **Step 2: Validate root skill frontmatter and answer shapes**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$skill = Get-Content '.\skills\investigation-deepdive\SKILL.md' -Raw
if ($skill -notmatch '(?s)^---\r?\nname:\s*investigation-deepdive\r?\ndescription:\s*.+?\r?\n---') { throw 'Invalid SKILL.md frontmatter' }
foreach ($section in @('Reference Selection','Operating Flow','Safety Guardrails','Answer Shapes','Verdict Rules','Before Finalizing')) {
  if ($skill -notmatch "## $section") { throw "Missing SKILL.md section: $section" }
}
'SKILL.md structure is valid'
```

Expected: command exits 0 and prints `SKILL.md structure is valid`.

- [ ] **Step 3: Validate fixtures match expected behaviors**

Run the same heading comparison command from Task 1, Step 4.

Expected: command exits 0 and prints `Investigation fixture headings match expected behaviors`.

- [ ] **Step 4: Validate plugin metadata parses**

Run:

```powershell
$ErrorActionPreference = 'Stop'
Get-Content '.\.claude-plugin\plugin.json' -Raw | ConvertFrom-Json | Out-Null
Get-Content '.\.claude-plugin\marketplace.json' -Raw | ConvertFrom-Json | Out-Null
'Plugin metadata JSON parses'
```

Expected: command exits 0 and prints `Plugin metadata JSON parses`.

- [ ] **Step 5: Validate example consistency**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$kqlExample = Get-Content '.\skills\investigation-deepdive\examples\microsoft-kql-pivot-packet.md' -Raw
if ($kqlExample -notmatch 'kql-m365-azure-hunting') { throw 'KQL pivot packet does not mention kql-m365-azure-hunting review' }
if ($kqlExample -notmatch 'Execution status: not executed') { throw 'KQL pivot packet must mark offline queries as not executed' }
$report = Get-Content '.\skills\investigation-deepdive\examples\final-report-skeleton.md' -Raw
foreach ($n in 1..12) {
  if ($report -notmatch "## $n\.") { throw "Final report skeleton missing section $n" }
}
'Examples are internally consistent'
```

Expected: command exits 0 and prints `Examples are internally consistent`.

- [ ] **Step 6: Scan added skill content for unresolved template markers and sensitivity risks**

Run:

```powershell
$ErrorActionPreference = 'Stop'
$paths = @(
  '.\skills\investigation-deepdive',
  '.\tests\prompt-fixtures.md',
  '.\tests\expected-behaviors.md',
  '.\README.md',
  '.\.claude-plugin\plugin.json',
  '.\.claude-plugin\marketplace.json'
)
$files = foreach ($path in $paths) {
  if (Test-Path $path -PathType Container) { Get-ChildItem $path -Recurse -File }
  else { Get-Item $path }
}
$open = [char]60
$close = [char]62
$markerPattern = 'T' + 'BD|T' + 'ODO|\{\{[^}]+\}\}|' + [regex]::Escape([string]$open) + '[^' + [regex]::Escape([string]$close) + ']+' + [regex]::Escape([string]$close)
$sensitivePattern = '(?i)(api[_-]?key|client[_-]?secret|password\s*=|bearer\s+[a-z0-9._-]{20,}|tenant\s*id\s*[:=]\s*[0-9a-f-]{36}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
foreach ($file in $files) {
  $text = Get-Content $file.FullName -Raw
  if ($text -match $markerPattern) { throw "Unresolved template marker found in $($file.FullName)" }
  if ($text -match $sensitivePattern) { throw "Potential sensitive content found in $($file.FullName)" }
}
'No unresolved template markers or sensitivity risks found in added content'
```

Expected: command exits 0 and prints `No unresolved template markers or sensitivity risks found in added content`.

- [ ] **Step 7: Run Git whitespace validation**

Run:

```powershell
git diff --check HEAD
```

Expected: command exits 0 with no output.

- [ ] **Step 8: Commit validation adjustments if any were needed**

If validation required edits, commit them:

```powershell
git add README.md tests\prompt-fixtures.md tests\expected-behaviors.md skills\investigation-deepdive .claude-plugin\plugin.json .claude-plugin\marketplace.json
$trailer = 'Co-authored-by: Copilot ' + [char]60 + '223556219+Copilot@users.noreply.github.com' + [char]62
git commit -m "fix: align investigation deepdive validation" -m $trailer
```

Expected: if there were edits, commit exits 0. If there were no edits, skip this step.

- [ ] **Step 9: Invoke completion verification skill**

Invoke `superpowers:verification-before-completion`.

Expected: the verification skill is loaded before claiming the implementation is complete.

- [ ] **Step 10: Final git status**

Run:

```powershell
git status --short --branch
```

Expected before push: branch shows no uncommitted changes. If the user asks to push, push the branch and verify the branch is clean and synced after push.

## Self-Review

- Spec coverage: Task 1 covers offline acceptance tests; Task 2 covers root `SKILL.md`; Tasks 3 and 4 cover focused references and public source notes; Task 5 covers examples; Task 6 covers README and plugin metadata; Task 7 covers required validation and completion verification.
- Placeholder scan: this plan avoids unresolved template variables and unfinished task markers in the planned skill content. The final validation command builds marker names from string fragments so the plan can describe the check without tripping the check itself.
- Type consistency: all file paths use `skills\investigation-deepdive`, all references named in `SKILL.md` are created in Tasks 3 and 4, and all example names match the design spec.
