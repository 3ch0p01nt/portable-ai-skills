# Platform Artifact Guidance

Read this reference before requesting artifacts, assessing Cisco logs/configs, or making platform-specific claims. Request only artifacts supported by the identified model and release. Mark unsupported, unavailable, altered, or untrusted layers explicitly.

## Universal inventory

- Configuration: running/startup/candidate config, archives, checkpoints, rollback history, and known-good diffs.
- Identity: local users and privilege, SSH keys, AAA/TACACS/RADIUS settings, authorization/accounting, login records, and approved admin roster.
- Logs: local/remote syslog with original timezone, sequence, facility, severity, mnemonic, source, and forwarding path.
- Exposure: SSH, Telnet, HTTP(S), ASDM, NX-API, RESTCONF, NETCONF, gRPC, SNMP, Smart Install, VPN, API, console/OOB, management ACL, and CoPP/CPPr.
- Volatile state: sessions, connections, listeners, process state, CPU/memory, captures, and active routes/tunnels.
- Storage: flash/bootflash/disk0/harddisk/crashinfo, logs, support bundles, scripts, packages, web assets, EEM/kron/scheduler, GuestShell/app/container files, and `authorized_keys`.
- Integrity: boot variables, images/packages/SMUs/hotfixes, install history, ROMMON/firmware, Secure Boot/Trust Anchor, platform integrity, and independently computed hashes compared with Cisco sources.
- Network state: ARP/MAC, routes, BGP/OSPF/EIGRP/ISIS, policies, ACL, GRE/IPsec, VPN, NAT, SPAN/ERSPAN, NetFlow/IPFIX.
- Crypto: trustpoints, enrollment, certificates, SSH host keys, and IKE/IPsec changes.
- Independent evidence: management systems, config repositories, AAA/ISE, firewall/proxy/DNS, PCAP/NDR, jump-host EDR, DHCP/NTP, case/change, and cloud logs.

Where supported, preserve process lineage, executable/arguments, user, start/exit reason, modules, handles/environment, filesystem changes, DNS, stable event IDs, logging heartbeat/config hash, mounts, raw volatile storage, memory, and data at rest. Missing observability is a gap, not a negative result.

## IOS XE

Collect logging, users/lines/SSH, control-plane listeners, running/startup/archive, package/install state, boot variables, independent hashes, platform integrity, GuestShell/app-hosting/IOx, Web UI and nginx traces, flash/crash/core, EEM/kron, SNMP, Smart Install, APIs/telemetry, AAA, route/tunnel/ACL changes, and Embedded Packet Capture accounting.

- CVE-2023-20198/CVE-2023-20273 requires Web UI exposure. Separate privilege-15 account creation from root-level filesystem implant deployment. Cisco PSIRT does not name the implant BadCandy.
- For BadCandy, separate account-only from account-plus-implant, preserve historical usernames, web restart state, nginx artifacts, documented syslog families, and variant-sensitive HTTP-probe limitations. Reboot does not remove a saved privileged account.
- AA25-239A leads include TACACS-focused EPC/`tac.pcap`, Guest Shell `chvrf`, SNMP SET, TACACS redirection, WSMA double encoding, SPAN/ERSPAN, and GRE/mGRE/IPsec changes.
- `Proxy-Uri-Source HTTP` can be a patched-device compatibility marker; it is not a standalone IOC.
- CVE-2025-20363 applies only with Remote Access SSL VPN enabled and authenticated low-privilege access. Root execution does not identify malware.

## Classic IOS

Collect logging, running/startup/archive, users/enable/VTY, SNMP including RW communities, Smart Install TCP/4786 exposure, CDP/LLDP-facing reachability, flash/crashinfo, boot/ROMMON, independent image hashes, EEM/kron, file-copy evidence, routes/BGP/ACL/tunnels, flow, and AAA.

- SYNful Knock preserves image size; use offline hashes and preserve RAM modules before reimage. Keep its patched-image and signaling behavior distinct from Jaguar Tooth.
- Cisco's SNMP umbrella advisory includes IOS and IOS XE, but public Jaguar Tooth deployment is confirmed on classic IOS. Do not transfer implant artifacts to IOS XE.
- CVE-2025-20363 requires Remote Access SSL VPN and authenticated low privilege; exploitation is not malware attribution.

## IOS XR

Collect commit/rollback databases; active/standby RSP; admin and XR planes; logs/accounting/AAA; users/groups/keys; management ACL and APIs; packages/SMUs/install history; integrity; core/crash/filesystem; host-Linux traces; routes/protocols/MPLS/policies; and `tpacap` use/accounting.

AA25-239A leads include `sshd_operns` on TCP/57722, an unexpected non-root user with sudoers persistence, and high-numbered SSH/web listeners. `tpacap` is a legitimate utility seen in abuse, not named malware. CVE-2025-20363 is limited to 32-bit IOS XR on ASR 9001 with HTTP enabled and authenticated low privilege.

## NX-OS

Collect logfile/accounting, checkpoint before rollback, config diff, feature enablement, NX-API/HTTP(S)/SSH/SNMP/NETCONF, bootflash, bash/GuestShell/container state, scripts/EEM/scheduler, image/package integrity, VDC/vPC/fabric and route changes, SPAN/ERSPAN, core/crash, users, and keys.

- JumbledPath leads include an unknown Go ELF in actor-created GuestShell, cleared Linux history, alternate SSH, root users/keys, `dohost`, high ports, and capture evidence. It is confirmed on Nexus GuestShell, not IOS XR.
- Velvet Ant reporting describes an unnamed underlying-Linux implant. Assess high-port listeners, valid-admin/accounting history, and CVE-2024-20399 without claiming NX-OS image modification.
- NX-OS is not affected by CVE-2025-20363.

## ASA, FTD, FXOS, and FMC

For ASA/FTD collect config, logging, VPN/WebVPN/AnyConnect state, tunnel groups, certificates, users/AAA, disk0 inventory, ZIP/plugin/client bundles, `firmware_update.log`, crash/reload, failover, ASP drops, connections/captures, image, FXOS/host layer, and current Cisco/CISA/NCSC forensic artifacts.

CVE-2025-20363 can be unauthenticated RCE on vulnerable ASA/FTD, but exploitation does not prove LINE VIPER, FIRESTARTER, or another implant. Route 2024 LINE DANCER/LINE RUNNER, legacy RayInitiator/LINE VIPER, and direct LINE VIPER/FIRESTARTER through separate branches.

For FMC collect audit and deployment history, policy/object changes, admin/RBAC/API access, backups, health and security events, certificate/VPN policy, upgrade/hotfix state, HA, and sensor correlation.

## Catalyst SD-WAN / Viptela

Collect vManage/vSmart/vBond/edge logs; audit/RBAC/API; templates/policies; control connections; certificates/serials; upgrade history; OMP/BFD/tunnels; CLI evidence; syslog/flow; cloud access; and fleet template pushes.

- ED 26-03/CVE-2026-20127: hunt unauthorized `Accepted publickey for vmanage-admin` in `/var/log/auth.log`, validate peering against expected IPs/roles, and preserve each controller's `admin-tech` for TAC.
- CVE-2022-20775 is an authenticated local application-CLI path to root on legacy vManage, vSmart, vBond, vEdge, and vContainer. IOS XE SD-WAN is not affected; the peering indicator is not its defining artifact.

## Wireless, identity, and orchestration

- **WLC/AireOS/Catalyst 9800:** admin audit/syslog, config/RBAC/AAA, AP joins, rogue AP/SSID, WLAN/profile/policy, Web UI/SSH/SNMP/API, certificates, mobility tunnels, clients, integrity/reload, NAC/ISE/DHCP/DNS/WIDS.
- **ISE:** admin/policy changes, TACACS/RADIUS auth/accounting, profiling, certificates, pxGrid/API, node synchronization, backup/restore, portals, RBAC, and device-command correlation.
- **Catalyst Center/DNA:** audit, inventory/discovery, credential-vault implications, templates, SWIM/images, network settings, assurance, command runner, API/RBAC, backup, telemetry, and PnP.
- **NSO/automation:** audit, commits/rollbacks, packages, authgroups, protocol/NED/API traces, Ansible/RANCID/Oxidized/Git/CI history, and identity/source/time/change alignment.

## Syslog-only schema and limitations

Normalize: device ID/platform, original and UTC times, timezone confidence, collector receive time/node, transport, sequence, facility, severity, mnemonic/message ID, process/connection/session, endpoints, username/auth/privilege, config mode/command, interface/VRF/VPN, protocol/result, NTP offset, baseline, raw hash, and parser confidence.

Before inferring from absence or volume, prove message emission, device severity settings, collector ingestion/transport, retention, triggering activity, and per-device/per-mnemonic baseline. ASA 111009 and 609002 are severity 7; prove emission and ingestion first. In syslog-only mode return ranked hypotheses, collection gaps, and exact evidence requests.

## Config-diff routing

Flag changes to:

- users, privilege, credential types, AAA order/fallback/accounting, VTY, SSH keys, APIs, SNMP, and Smart Install;
- logging, NTP, archive, timestamps, RBAC/views, and command accounting;
- loopbacks, management sources, ACL/policy/routes/protocols, GRE/IPsec/VPN, NAT, and SPAN/ERSPAN;
- boot/packages, GuestShell/app hosting, full EEM/kron/scheduler bodies, and copy aliases;
- trustpoints, certificates, enrollment, VPN maps, and public-key chains.

Require approved change, administrator, automation source, timestamp alignment, and independent records. A config diff cannot inspect underlying Linux, memory, boot firmware, hidden captures, or unlogged orchestrator actions.
