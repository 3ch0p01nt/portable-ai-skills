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