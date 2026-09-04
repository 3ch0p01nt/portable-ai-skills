---
name: "m365-phishing-conversion-hunter"
description: "Use when investigating or validating Microsoft 365 phishing or spear-phishing from message delivery through human click, sign-in, OAuth consent, device-code authorization, session theft, mailbox/resource use, or control-plane impact. Covers BEC, AiTM, impersonation, reply-chain hijacking, Safe Links/Safe Attachments, remediation history, and campaign clustering. Do not use for generic mailbox search, message drafting, containment, remediation, or standalone identity investigations without an ema"
---

# M365 Phishing Conversion Hunter

Conduct an authorized, read-only Microsoft 365 phishing investigation. Determine whether a targeted message or collaboration contact caused identity, authorization, endpoint, mailbox, resource, or control-plane impact—not merely whether an IOC matched.

## Safety and privacy
- Perform only read-only queries and inventory.
- Never delete, quarantine, purge, block, revoke, reset, remediate, contact recipients, or change policies.
- Never browse, resolve, visit, submit, or otherwise interact with message URLs.
- Never open, download, preview, extract, execute, or detonate attachments.
- Use existing URL, attachment, sandbox, Safe Links, Safe Attachments, endpoint, and collaboration telemetry only.
- Do not retrieve or display message bodies. Minimize subjects, recipient data, attachment names, and chat content.
- Display URL host/registrable domain and a path hash; remove query strings, fragments, tokens, and user data.
- Never request or expose credentials, tokens, cookies, secrets, or private keys.
- Preserve immutable event IDs, UTC timestamps, and query text. Separate observed facts, correlations, inferences, and coverage gaps.

## Coverage gate
Before hunting, inventory available schema, retention, licensing, and ingestion health for:
- EmailEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents
- EmailPostDeliveryEvents, CampaignInfo, or equivalent locally exposed post-delivery/campaign tables; schema-probe before use
- Teams/collaboration message, call and post-delivery telemetry in CloudAppEvents, Purview, Defender XDR, or the locally available workload-specific source; never invent a table/action name
- Entra interactive and non-interactive sign-in data
- AuditLogs, CloudAppEvents, OfficeActivity, and Graph activity where available
- Safe Links, Safe Attachments, post-delivery remediation, mailbox auditing, priority-user inventory
- Approved scanner IP/User-Agent lists, trusted VPN/SWG/NAT ranges, external-tenant/vendor inventory, helpdesk/contact records, and endpoint coverage for RMM/RDP handoffs

Record exact local fields, source platform/API, and whether events are duplicated across Sentinel/XDR/Purview. Never invent or silently substitute tables or columns. “Not observed” is not “did not occur” unless coverage is verified.

## Bounded windows
- Known message/click: investigate from 15 minutes before delivery through 24 hours after click.
- Click-to-authentication/consent: prioritize 5–60 minutes; inspect 0–5 minutes for clock skew or cached flows. For a device-code lure, prioritize the documented 15-minute code-validity window, then inspect follow-on device registration and use without assuming a PRT was issued.
- First post-click action: search the following 24 hours.
- Campaign expansion: start at ±7 days; widen to 30 days only with stated retention, cost, and investigative justification.
- Identity/sender baseline: use the preceding 30 days when available, ending before the candidate window.
- Persistence check: extend to 7 days after conversion only for a material lead.
- Start expensive queries at 1–24 hours and narrow by IDs before widening.
If a timestamp is aggregated, coarse, or ingestion-delayed, retain its interval and do not force exact ordering across sources.

## Investigation workflow

1. Anchor delivery or contact.
   - For email, preserve NetworkMessageId, recipient identity, delivery time, original/latest delivery action, threat verdict, detection method, remediation time, and source event IDs.
   - For Teams or another collaboration channel, anchor on immutable message/conversation/call ID, sender and home-tenant IDs, channel/chat context, recipient, timestamp, and source; do not fabricate an email or NetworkMessageId anchor.
   - Distinguish blocked, quarantined, junked, delivered, later-remediated, post-delivery-purged, internally resent, and automatically forwarded messages.
   - A Teams-only MFA relay, device-code lure, callback pretext, or email-bomb-to-helpdesk chain can bypass the email security pipeline entirely.

2. Assess targeting.
   - Evaluate recipient count, role relevance, priority/privileged status, finance/executive/IT targeting, peer-group concentration, prior relationship, and whether the pretext is unusually specific.
   - Detect a sudden burst of otherwise legitimate subscription/newsletter mail to one recipient as an email-bomb precursor only when independently followed by an inbound external chat/call, fake-helpdesk contact, or technical action. No fixed volume threshold is portable.
   - Do not expose unnecessary personal or message content.

3. Assess sender, thread, external tenant, and forwarding anomalies.
   - Compare display name, visible From, envelope/MailFrom, Reply-To, sending domain, return path, tenant, and known-correspondent baseline where fields exist.
   - Evaluate lookalikes, homographs, misleading subdomains, new sender-recipient or external-tenant edges, and domain age/reputation only from approved telemetry.
   - SPF/DKIM/DMARC/composite-auth success is not exonerating when a legitimate sender may be compromised. Check whether an explicit transport rule, connector, trusted-sender/domain entry, or recorded override bypassed filtering; validate historical state rather than assuming current configuration.
   - For alleged thread hijacking, verify that an earlier thread/message existed before the candidate. If privacy-safe metadata cannot establish continuity, mark it unresolved.
   - For internal or auto-forwarded propagation, verify Safe Links/policy coverage for the final recipient and channel. Protection of the original recipient or prior rewrite does not by itself prove the forwarded copy was checked.

4. Assess URL and attachment evidence.
   - Use only recorded URL/domain, redirect-chain, reputation, verdict, hash, type, and detonation metadata.
   - Identify shortened links, open redirects, legitimate-cloud hosting, late weaponization, HTML/PDF/QR-image link carriers, signed RDP configuration files, and credential/AiTM/OAuth/device-code destinations without opening them.
   - QR-encoded destinations might produce neither EmailUrlInfo nor UrlClickEvents; correlate recorded image/attachment/QR classification to mobile or cross-device authentication in the bounded window and do not downgrade solely because the click bridge is absent. Do not invent a QR-source field when the local schema does not expose one.
   - Distinguish legitimate authentication transfer from malicious QR/device-code conversion using a locally verified protocol/original-transfer field, app/resource, originating product workflow, device continuity, and downstream behavior. A QR image or mobile carrier IP alone cannot distinguish them.
   - Compare delivery-time and click-time verdicts and record Safe Links warning, block, allow, or missing/bypass signals. CAPTCHA, browser-fingerprint, and IP/geolocation gating can serve benign content to scanners; a clean delivery verdict is not exonerating when the human redirect path was unobserved.
   - Record Safe Attachments verdict and timing without obtaining the file. RDP-file conversion is endpoint/session exposure, not necessarily Entra authentication; hand off to endpoint IR.

5. Classify clicks and interaction.
   - Do not equate a click event with human action.
   - Scanner/detonation indicators include pre-delivery timing, approved scanner infrastructure, scanner User-Agent, automated fan-out, identical rapid clicks across recipients, and no correlated user activity.
   - Human indicators include recipient attribution, plausible browser/device/network timing, warning click-through, normal interaction cadence, and correlated authentication or resource activity.
   - Use multiple signals. Label uncertain clicks unresolved; never suppress them solely because an IP or User-Agent appears scanner-like. For QR, callback, or Teams delivery, absence of a Safe Links click is expected and is not evidence of no human interaction.

6. Measure conversion using:
- D0 Delivery/contact only
- D1 Likely human interaction
- D2 Authentication/session or endpoint remote-control event
- D3 Consent, device-code, device-registration, authorization, or durable authentication-method change
- D4 Mailbox/resource/control-plane impact

A delivery, call, click, or email bomb alone is not confirmed conversion. A remote-support/RDP grant is D2 endpoint conversion only when retained endpoint/session evidence supports it; route execution, RMM and malware effects to endpoint IR. Preserve a device-code authorization as one evidence atom and hand lifecycle analysis to OAuth. If the locally observed client is Microsoft Authentication Broker, test the documented device-code authorization → Device Registration Service use → new device registration → subsequent PRT-compatible access chain and hand device persistence to the privilege specialist. PRT issuance isn't directly logged; do not promote to D4 unless downstream impact is observed. Correlate using immutable message/contact IDs, stable user ID, bounded time, URL host/path hash, IP/ASN, device, app/resource, and validated session/token identifiers. Treat IP and CorrelationId as supporting—not identity—evidence.

7. Classify the social-engineering/authentication mechanism.
   - Distinguish reverse-proxy cookie theft, indirect-proxy credential/MFA relay, Teams MFA-code relay, device-code authorization, authentication transfer, push fatigue, and email-bomb → fake-helpdesk → remote-support/RDP handoff.
   - Look for click/contact-adjacent authentication followed by session/non-interactive use from different infrastructure, near-concurrent successful authentications from incompatible networks, unfamiliar device/User-Agent, anomalous-token or AiTM detections, unexpected MFA/authentication-method changes, new resources, or rapid mailbox/control-plane activity.
   - For collaboration/vishing chains, preserve the mail-volume anomaly, external tenant and caller/message IDs, helpdesk ticket timing, remote-tool/session event and first process/network action as distinct evidence. A caller display name or security-themed tenant name is an untrusted label, not an identity.
   - Callback/vishing chains can convert to remote-support or RMM endpoint access without D2+ Entra identity evidence. Absence of an auth event does not clear the lure.
   - These are clues, not proof. Require ordered corroboration and state benign proxy, VPN, travel, onboarding, legitimate helpdesk, and multi-device alternatives.

8. Identify the first post-contact action.
   - Find the earliest reliably correlated sign-in, consent, device-code use, mailbox access/search, rule/forwarding change, send/delete action, Graph request, auth-method/device change, role action, app change, policy change, or remote-session/process event.
   - Preserve event ID, timestamp interval, and join quality. Do not guess across telemetry gaps.

9. Assess campaign similarity.
   - Expand by sender, external tenant, normalized subject fingerprint, recipient pattern, URL/redirect domain and path hash, attachment hash/type, reply-chain pattern, IP/ASN, app ID, redirect URI, email-bomb-to-contact motif, and ordered timing.
   - Exact hashes, app IDs, redirect paths, immutable message/contact IDs, and repeated ordered behavior are stronger than shared hosting, common SaaS, carrier/NAT egress, broad subject similarity, caller display name, or ASN alone.
   - Treat internal second-stage propagation as a linked but distinct episode; do not merge its delivery events with the original conversion atom.
   - Identify low-volume targeting of high-value recipients.

10. Run decisive TP/FP tests.
   - Was the interaction human, scanner, remote-support, or unresolved?
   - Was the observed final user redirect available?
   - Did the recipient authenticate, consent, enter a device code, transfer authentication, grant remote control, or create a new session?
   - Is the sender/tenant/domain/thread/helpdesk contact expected or independently compromised?
   - Does downstream behavior belong to the same identity/app/session/device and depart from a clean baseline?
   - Do approved SaaS, forwarding, mailing lists, VPN/SWG, travel, marketing trackers, authentication transfer, onboarding, or collaboration links explain it?
   - Is there out-of-band confirmation or denial through a channel independent of the possibly compromised identity? Record it as separate evidence; do not contact anyone.
   - Could missing telemetry or retention prevent the test?
A ticket, allowlist, familiar sender, managed device, or policy coverage is not self-validating. Require an authoritative record with exact subject/action/scope, creator/approver, valid-from/valid-until interval, and immutable reference; retroactive, expired, overbroad, or investigated-actor-created records cannot clear a lead.

## Specialist handoffs

### Sign-in specialist
Handoff when any contact-adjacent sign-in, session/token anomaly, AiTM clue, device-code use, authentication-transfer ambiguity, or unexplained authentication is found. Provide stable user ID, minimized label, message/contact/click event IDs and timestamp intervals, URL host/path hash, exact authentication window, candidate sign-in IDs/apps/resources/IPs/devices/User-Agents, exposed session/token field names and join quality, CA/risk fields, and gaps. Do not conclude credential/session theft before specialist validation.

### OAuth and persistence specialists
Handoff to OAuth when telemetry shows a Microsoft authorization endpoint, consent prompt, device-code lure, app ID, grant/consent audit, new service principal, redirect anomaly, agent/app-driven resource access, or grant restoration. The phishing lane retains delivery and D-level classification but does not rescore the same authorization event.

For a broker-client device-code event, new device registration, authentication-method change, or post-remediation durable access, send the same immutable evidence atom to persistence. Provide delivery/contact evidence, bounded timeline, appId/application-object/servicePrincipal IDs without conflation, redirect host/URI hash, tenant, publisher, consent/grant event IDs, requested/effective scopes from retained telemetry, first resource use, and gaps. Do not claim authorization-code redemption unless a retained event proves it.

### Endpoint/IR handoff
For Quick Assist, RMM, RDP, callback or malware execution, provide message/call IDs, external tenant/sender identity, recipient/device IDs, exact contact-to-session interval, process/session/network evidence IDs, and the identity findings already established. Do not reproduce endpoint forensics in this lane.

## Required output
1. Scope, UTC windows, delivery/contact channel, seed, and conversion verdict.
2. Coverage matrix with retention and gaps.
3. Delivery/remediation and Safe Links/Attachments/collaboration summary.
4. Minimized ordered or partial-order timeline with event IDs.
5. Targeting, sender/thread/tenant, URL/attachment, and interaction classification.
6. Conversion level and first post-contact action.
7. Recipient/asset value and campaign-similarity assessment.
8. TP indicators, benign alternatives, decisive tests, and validation-artifact status.
9. Sign-in/OAuth/persistence/endpoint handoff packets when triggered.
10. Confidence (confirmed, high, moderate, low, or unresolved) plus unsupported conclusions avoided.

Never fabricate results or let confidence exceed telemetry coverage.
