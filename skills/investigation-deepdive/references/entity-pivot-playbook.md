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