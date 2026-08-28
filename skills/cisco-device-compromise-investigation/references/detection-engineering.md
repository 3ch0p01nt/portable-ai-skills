# Cisco Detection Engineering

Version 1.0.0 - 2026-08-28

Detection output is a hypothesis generator, not an automatic compromise verdict.

## Required detection metadata

Every rule/template records:

- Detection ID and version.
- Platform and layer.
- Source claim and source version/date.
- Required telemetry and sensor vantage.
- Required field bindings.
- Lookback and execution frequency.
- Baseline requirement.
- Expected confidence contribution.
- False positives and exclusions.
- Expiration/review date.
- Test fixtures.
- Status: draft, validated, production, deprecated, or superseded.

## Syslog prerequisites

Before interpreting a missing or reduced message:

1. Confirm the platform/version message catalog.
2. Confirm the device emits that message ID/mnemonic.
3. Confirm remote logging severity includes it.
4. Confirm collector/SIEM ingestion does not filter it.
5. Confirm transport and loss behavior.
6. Confirm collector identity, health, restart, failover, queue, and retention.
7. Confirm a historical per-device/per-mnemonic baseline exists.
8. Confirm the device had activity that should have generated the message.

If any prerequisite is absent, record an evidence gap instead of a negative result.

### LINE VIPER ASA messages

- 302013 and 302014: pair build/teardown events using connection ID where parsed.
- 609002: severity 7; prove it was emitted and ingested before using absence.
- 710005: discarded-request volume.
- 111008: command audit path.
- 111009: severity 7 command audit path; LINE VIPER harvests commands at this path, but NCSC did not state that harvesting necessarily suppresses the message.

Do not infer LINE VIPER from one missing message. Stronger log alignment requires selective loss of documented IDs while other messages from the same device and collector remain healthy.

### Baseline method

- Use at least seven representative days when available, excluding maintenance, failover, collector outages, and known incident windows.
- Build per-device, per-message, hour-of-week distributions.
- Start with median and median absolute deviation; tune thresholds on local history.
- Track zero-expected periods separately from suppression.
- If no baseline exists, compare with same-model/same-version/role peers only as contextual evidence and mark the layer untested.

### Sequence and time

- Sequence-gap detection requires sequence numbers to be enabled and parsed.
- Counter reset and missing numbers are separate from volume suppression.
- Correlate reset with reload/failover/collector events.
- Calculate device-to-collector skew and record NTP changes.
- Preserve future-dated, uptime-derived, and timezone-unknown events without forcing exact UTC.

## AAA, VPN, MFA, and PKI

Distinguish:

- TACACS+: administrative authentication, authorization, and per-command accounting.
- RADIUS: network/VPN authentication and session accounting; not equivalent to TACACS command accounting.
- Device syslog 111008/111009: device-side command audit paths, distinct from external TACACS records.

### LINE VIPER bypass versus local fallback

Actor-device bypass:

- VPN/network activity exists.
- The ASA may show a session when output is trustworthy.
- External RADIUS/ISE receives no authentication/accounting request because the device bypassed AAA.

Local fallback:

- AAA server becomes unavailable or method-list order selects local.
- Device local-account authentication occurs.
- External AAA shows an outage/gap, while device/config state should show fallback capability.

Both can look like missing external AAA. First prove the tunnel group's AAA/accounting configuration and server availability.

### Correlation record

For each VPN session:

- Session identifier.
- Source and assigned IP pseudonyms.
- Username pseudonym and account status.
- Tunnel group/profile.
- Start/stop/interim accounting.
- MFA challenge/accept/deny evidence.
- Device syslog correlation.
- NetFlow/PCAP correlation.
- Geolocation/velocity source and uncertainty.
- Known jump host, proxy, carrier NAT, or cloud egress.

No impossible-travel event is possible to assess when AAA bypass removed the source record. Its absence is not clearance.

## Network telemetry and placement

| Behavior | Required vantage | Known blind spot |
|---|---|---|
| LINE VIPER WebVPN HTTPS | VPN endpoint or decrypting/metadata sensor | Per-victim encrypted tasking |
| LINE VIPER ICMP tasking/raw TCP | LAN-inside segment adjacent to ASA | WAN-only sensors may see nothing |
| SYNful Knock crafted TCP trigger | Full packet sensor on receiving path | NetFlow does not carry TCP initial sequence number |
| TFTP/FTP exfil | Upstream flow/PCAP/firewall | Device-native flow may be suppressed |
| SCP exfil | External AAA plus flow destination | Payload encrypted and resembles SSH |
| JumbledPath multi-hop capture | GuestShell, jump hosts, east-west flow | Each hop exposes only adjacent nodes |
| GRE/proxy relay | Upstream flow/router/firewall | Encapsulated inner traffic may be hidden |
| Hidden on-device capture | External TAP and credential-protocol baselines | `show capture` can be deceptive |

Every report states whether WAN, LAN-inside, management, OOB, and upstream visibility existed.

## Config-diff rules

Flag and explain:

- New/modified loopback, its IP, and use as tunnel source, BGP update source, or management source.
- Entire EEM applet/kron body and action changes, not only stanza names.
- VTY transport, access-class, login method, privilege, and timeout changes.
- AAA method-list order, local fallback, authorization/accounting removal, and server address/key object changes.
- SNMP community privilege, version downgrade, users/views, hosts, and trap destinations.
- Archive destination/protocol, retention maximum, time period, and write-memory behavior.
- SSH host-key regeneration/zeroize, public-key chains, version, and source interface.
- BGP peer and outbound route-map/default-originate changes.
- SPAN/ERSPAN source scope and remote destination.
- HTTP/API/NETCONF/RESTCONF/NX-API/Smart Install enablement.
- Certificate/trustpoint/enrollment and VPN profile changes.
- Logging destination/severity/facility and NTP/time changes.

Blind spots that require other evidence:

- GuestShell/Linux users, authorized keys, cron, binaries, mounts, and histories.
- ROMMON/GRUB/BOOT environment.
- Runtime memory and hidden captures.
- Unsaved running changes absent from the compared snapshot.
- Orchestrator pushes that do not produce per-command AAA.

## Platform threat modules

### BadCandy / IOS XE

- Separate account-only compromise from account-plus-implant.
- Treat `cisco_tac_admin`, `cisco_support`, and `cisco_sys_manager` as historical examples, not exhaustive IOCs.
- Parse `%SYS-5-CONFIG_P`, `%SEC_LOGIN-5-WEBLOGIN_SUCCESS`, and `%WEBUI-6-INSTALL_OPERATION_INFO` fields.
- The file `/usr/binos/conf/nginx-conf/cisco_service.conf` can exist while the implant is inactive until web-server restart.
- Three known variants changed HTTP probe behavior. A negative probe is never clearance.
- Reboot removes the implant file but not a saved privileged account.

### Salt Typhoon platform boundaries

- IOS XR: native `tpacap`; AA25-239A also documents `sshd_operns` on TCP/57722 and a non-root user with sudoers persistence. These are tradecraft, not a named IOS XR implant.
- IOS/IOS XE: Embedded Packet Capture/`monitor capture` abuse, TACACS-focused capture and export such as `tac.pcap`, Guest Shell `chvrf`, and WSMA double encoding. Treat `Proxy-Uri-Source HTTP` as a patched-device compatibility marker where documented, not an IOC by itself.
- NX-OS Nexus: JumbledPath is confirmed in actor-created GuestShell; also hunt Guest Shell `dohost`.
- Cross-platform: valid credentials, config theft, AAA/SNMP capture or redirection, SNMP SET, loopback/ACL/GRE/mGRE/IPsec changes, SPAN/ERSPAN, Linux users/keys, high-numbered SSH ports ending in `22`, web ports in the `18xxx` range, STOWAWAY, and log clearing.
- Do not assert JumbledPath on IOS XR without evidence.

### Velvet Ant / NX-OS

- Treat the implant as unnamed.
- Separate underlying-Linux process/file/listener compromise from NX-OS system-image modification.
- Correlate valid-admin access, CVE-2024-20399 exposure, high-port listeners, accounting, and filesystem evidence.

### No-named-malware platforms

For IOS XR, WLC, ISE, Catalyst Center, SD-WAN, and NSO, do not force a family name. Hunt behavior, current CVEs/KEV, controller audit, process/file anomalies, certificate changes, and fleet impact.

### Catalyst SD-WAN ED 26-03 and CVE-2026-20127

CISA KEV added CVE-2026-20127 and CVE-2022-20775 on 2026-02-25 and directs organizations to ED 26-03 plus its supplemental hunt/hardening guidance.

- CVE-2026-20127: authentication bypass in Catalyst SD-WAN Controller/Manager peering that can yield a high-privileged internal account and NETCONF configuration control.
- Hunt `/var/log/auth.log` for `Accepted publickey for vmanage-admin` from unauthorized IPs.
- Validate vManage/vSmart/vBond/edge peer type, peer system IP, public IP, timestamp, maintenance window, and role.
- Correlate controller peer changes with auth logs, NETCONF, API tokens, templates, certificates, and device pushes.
- Preserve `admin-tech` from every control component for Cisco TAC.

No named device malware is asserted from these CVEs alone.

### Legacy SD-WAN CVE-2022-20775

- This is an authenticated/local application-CLI path traversal and root command-execution branch affecting vulnerable vManage, vSmart, vBond, vEdge, and vContainer releases.
- Cisco IOS XE SD-WAN is explicitly not affected.
- Do not transfer the CVE-2026-20127 `vmanage-admin` peering indicator to this branch without independent evidence.
- Cisco updated the advisory to version 1.2 on 2026-02-25 after attempted exploitation was reported.

No named device malware is asserted from this CVE alone.

### ASA/FTD ransomware access context

CISA KEV marks CVE-2020-3259 as known ransomware-campaign use. Treat exploitation as potential VPN/session information disclosure and downstream enterprise access. Do not place the ransomware payload in the Cisco malware catalog unless evidence shows code resident on the Cisco device.

## Safe detection templates

Templates under `detections/templates` are not production rules.

- All environment-specific names remain placeholders.
- Operators validate table/index/field bindings.
- Tests prove expected positives and documented benign controls.
- Rule output produces evidence flags, not a verdict.
- FIRESTARTER uses CISA YARA/core analysis; CISA states Sigma-style log rules are ineffective for direct FIRESTARTER detection.
- Do not copy proprietary Snort/YARA content without confirmed redistribution rights.
