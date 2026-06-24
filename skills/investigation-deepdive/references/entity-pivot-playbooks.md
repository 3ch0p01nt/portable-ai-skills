# Entity Pivot Playbooks

Use these playbooks after extracting entities from a seed event, incident, workbook row, or anomaly summary.

## Domain or URL

Minimum context: domain or URL, timestamp, source host or user when available, source table, and whether it came from email, browser, DNS, proxy, endpoint, or cloud logs.

Standard pivots:

- Prevalence across hosts and users.
- First seen and last seen.
- Process or browser that contacted it.
- Email delivery and click relationship.
- DNS, proxy, firewall, and endpoint network correlation.
- Same domain or URL in other alerts or incidents.
- Related IPs and certificates when available.

Benign alternatives: marketing links, CDN, SSO redirect, security awareness simulation, vendor update, proxy prefetch, browser background traffic.

Stop conditions: no host or user context, no DNS/proxy/endpoint telemetry, or only one low-context hit means low confidence.

## IP Address

Minimum context: IP, timestamp, direction, source host or user, port, protocol, and source table.

Standard pivots:

- Internal versus external classification.
- Host and user prevalence.
- Remote port and protocol patterns.
- DNS names or URLs resolving to the IP.
- Sign-ins from the IP.
- Proxy, firewall, VPN, and endpoint network history.
- Same IP in alerts, incidents, or threat intelligence when available.

Benign alternatives: CDN, NAT gateway, VPN provider, scanner, update service, shared proxy, cloud provider endpoint.

Stop conditions: IP-only hits without process, user, DNS, or proxy context remain weak evidence.

## Host or Device

Minimum context: device name or ID, timestamp, source table, user context, and anomaly description.

Standard pivots:

- Process tree around the seed time.
- File writes, hash prevalence, and image loads.
- Network connections and DNS lookups.
- Logons and remote sessions.
- Registry, scheduled task, service, and startup persistence.
- Alerts, AV detections, and quarantine events.
- Peer baseline and first-seen activity.

Benign alternatives: software update, admin tooling, vulnerability scanner, monitoring agent, backup software, business application.

Stop conditions: missing command line, process ancestry, or user context lowers confidence.

## User or Identity

Minimum context: UPN or SID, timestamp, sign-in context, source IP, device, app, and MFA/conditional access details when available.

Standard pivots:

- Successful and failed sign-ins.
- MFA failures, changes, and success after failures.
- New device, new country, new ASN, or new user agent.
- Audit changes, role assignments, group changes, and app consent.
- Mailbox rules and forwarding.
- Cloud app activity and file access.
- Endpoint activity under the same user.

Benign alternatives: travel, VPN, device replacement, password reset, helpdesk action, approved automation, break-glass process.

Stop conditions: single sign-in anomaly without post-authentication activity is suspicious or inconclusive, not confirmed compromise.

## Process or Command Line

Minimum context: process name, parent process, command line or redaction note, host, user, timestamp, and process ID when available.

Standard pivots:

- Parent and child process chain.
- Command-line features and redacted suspicious content.
- File path, signer, hash, and prevalence.
- Network connections by the process.
- File writes and persistence artifacts.
- Same parent-child pair across peer hosts.

Benign alternatives: installer, script automation, management tool, business macro, software updater, monitoring agent.

Stop conditions: missing command line or parent process must be recorded as an evidence gap.

## File Path or Hash

Minimum context: file name, path, SHA1 or SHA256, host, user, timestamp, and action type.

Standard pivots:

- Hash prevalence across devices.
- First seen and last seen.
- File origin and download source.
- Signer, path rarity, and execution count.
- Process, network, and image-load follow-on.
- AV alert, quarantine, or remediation evidence.

Benign alternatives: signed software, common library, update artifact, installer cache, known admin tool.

Stop conditions: hash reputation alone is not enough without local prevalence or execution evidence.

## Email or Message

Minimum context: sender, recipient, message ID, subject, URL, attachment hash, delivery action, and timestamp.

Standard pivots:

- Recipient spread and similar messages.
- URL inventory and click events.
- Attachment hash prevalence and endpoint execution.
- Post-delivery actions.
- Sender authentication and spoofing signals.
- Mailbox rules or forwarding changes.

Benign alternatives: marketing campaign, security simulation, mailing list, legitimate third-party sender, user-reported false positive.

Stop conditions: missing click logs or endpoint logs must be a gap, not proof of no impact.

## Cloud Resource

Minimum context: resource ID or name, operation, actor, timestamp, scope, source IP, and result.

Standard pivots:

- Resource creation, update, and access history.
- Actor sign-ins and audit activity.
- Role assignments and permission changes.
- Secret, key, storage, automation, or managed identity activity.
- Related Graph or cloud app events.
- Peer baseline for similar operations.

Benign alternatives: infrastructure deployment, break-fix, automation pipeline, policy remediation, scheduled job.

Stop conditions: resource-control anomalies require actor and scope context for meaningful confidence.

## Service Principal or OAuth App

Minimum context: app ID, service principal ID, display name, actor, consent or role operation, timestamp, and permissions when available.

Standard pivots:

- Consent grants and permission scopes.
- App role assignments.
- Service principal sign-ins.
- Graph activity.
- Ownership changes and credential additions.
- Resource access and cloud app activity.

Benign alternatives: approved enterprise app, deployment automation, managed identity, vendor integration, admin consent workflow.

Stop conditions: app ID alone is weak without consent, role, sign-in, or resource access evidence.

## Persistence Artifact

Minimum context: artifact type, host, creating user or process, timestamp, target path or command, and source table.

Standard pivots:

- Creating process and parent process.
- Target executable path and hash.
- Logon context around creation.
- Registry, service, task, startup folder, and WMI correlations.
- Same artifact across hosts.
- File prevalence and network follow-on.

Benign alternatives: updater, backup agent, monitoring tool, IT management platform, scheduled business job.

Stop conditions: artifact name alone is insufficient without target path or creator context.

## Weak-Context Workbook Anomaly

Minimum context: whatever the workbook provides.

Standard pivots:

- Identify primary entity candidate.
- Identify missing fields that block confidence.
- Draft table-availability checks.
- Draft entity-specific pivots with assumptions.
- Return low confidence until corroborated.

Benign alternatives: workbook threshold drift, peer group mismatch, data freshness issue, connector outage, noisy baseline.

Stop conditions: if only one metric exists and no entity can be extracted, return an evidence collection plan instead of a verdict.