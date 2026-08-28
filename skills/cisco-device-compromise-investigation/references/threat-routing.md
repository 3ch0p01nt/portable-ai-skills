# Threat, Campaign, and Source Routing

Read this reference for any named actor, campaign, malware, vulnerability, firmware concern, or current-source question. Treat public intelligence as hypotheses to test against platform-valid local evidence.

## Source precedence

1. Current Cisco PSIRT/CSAF for affected products, prerequisites, and fixed releases.
2. Cisco event-response and integrity guidance for collection and product-specific response.
3. The most specific primary malware analysis from Cisco Talos, CISA, or NCSC for artifacts and behavior.
4. CISA directives, KEV, joint advisories, and partner-government guidance for mandated or campaign-level response.
5. MITRE ATT&CK and reputable incident research for contextual mapping, never as a substitute for primary platform evidence.

Use `references/sources.json` for stable IDs, fallback URLs, expected versions/hashes, and manual verification state. When currentness matters, run the separate online source checker. Cite the document version/date checked. A current, more specific primary source supersedes generalized or older guidance.

## Routing table

| Lead | Platform boundary | Route and cautions |
|---|---|---|
| RayInitiator | ASA 5500-X without Secure Boot | Persistent GRUB bootkit; may exist without LINE VIPER. Read `line-viper-rayinitiator.md` and NCSC MAR. |
| LINE VIPER | ASA `lina`; legacy bootkit or direct Firepower/FXOS branch | Victim-specific memory loader; deceptive `verify`; WebVPN/ICMP tasking and selective logging. Do not expect stable hashes. |
| FIRESTARTER | FXOS layer in the direct-deployment branch | Separate ELF backdoor that can redeploy LINE VIPER. Follow current CISA/Cisco branch before core or power action. |
| ArcaneDoor | 2024 ASA/FTD LINE DANCER/LINE RUNNER and related activity | Campaign label, not a single malware family. Keep 2024 and later branches separate. |
| BadCandy/Web UI implant | IOS XE with exposed Web UI | Distinguish rogue account from filesystem implant; negative HTTP probes do not clear variants. Cisco PSIRT does not name BadCandy. |
| SYNful Knock | Classic IOS | Patched image that preserves size; compare independent hashes and preserve memory. |
| Jaguar Tooth | Publicly confirmed classic IOS deployment | APT28/CVE-2017-6742 alignment. Advisory vulnerability scope does not transfer implant evidence to IOS XE. |
| JumbledPath | NX-OS Nexus GuestShell | Legitimate GuestShell context abused for a Go ELF; do not transfer to IOS XR. |
| Salt Typhoon / AA25-239A overlap | Platform-specific IOS XE, IOS XR, and NX-OS leads | Valid credentials, config theft, capture/redirection, high listeners, and log clearing. Commercial actor names are alignment, not proof. |
| Velvet Ant | NX-OS underlying Linux | Unnamed implant in public reporting; do not claim image modification without evidence. |
| BlackTech | Router/network edge | Firmware/boot integrity and traffic-redirection hypothesis; require platform-specific evidence. |
| Volt Typhoon | Edge/SOHO and critical-infrastructure context | Living off the land, valid credentials, proxy infrastructure, long dwell time, and OT adjacency; infrastructure overlap is not attribution. |
| ZuoRAT / KV Botnet | Specified RV/SOHO models only | Keep affected model and in-memory limitations exact; consult catalog. |
| CVE or N-day lead | Only products/configurations in current PSIRT | Exploit exposure or success is not a named implant. Report vulnerability, exploit, persistence, and malware separately. |

## LINE VIPER / FIRESTARTER decision branch

- **Branch A: RayInitiator to LINE VIPER.** Legacy ASA 5500-X without Secure Boot; boot-chain persistence can survive reboot/upgrade. A negative LINE VIPER result does not clear RayInitiator.
- **Branch B: direct LINE VIPER then FIRESTARTER.** Post-exploitation Firepower/FXOS route; FIRESTARTER is later persistence and can redeploy LINE VIPER after patching.
- **2024 LINE DANCER/LINE RUNNER branch.** Do not merge its extra executable-`lina` memory guidance with the core-dump steps for later branches.

Read `references/line-viper-rayinitiator.md` before acting. For 2024 extra executable `lina` memory, current Cisco/Talos guidance says not to reboot or perform the conflicting core step. For NCSC RayInitiator/LINE VIPER, a pre-patch core attempt and immediate-reboot behavior have specific evidentiary meaning. For FIRESTARTER, current CISA/Cisco directions control. U.S. FCEB agencies must follow current ED 25-03 and supplemental stop-and-wait/submission requirements.

## Actor and campaign lens

- **ArcaneDoor / UAT4356 / STORM-1849:** ASA/FTD targeting; LINE DANCER/LINE RUNNER in 2024, later legacy RayInitiator and direct LINE VIPER/FIRESTARTER branches; possible logging suppression, AAA bypass, hidden credential captures, deceptive verification, and boot/FXOS persistence.
- **Salt Typhoon overlap:** telecom/network infrastructure; valid credentials, configuration theft, credential expansion, SNMP SET, AAA capture/redirection, NX-OS JumbledPath, IOS XR `tpacap` and `sshd_operns`, IOS XE TACACS EPC, WSMA encoding, SPAN/ERSPAN, tunnel manipulation, and log clearing.
- **Volt Typhoon:** critical-infrastructure pre-positioning, valid credentials, edge-device access, proxy infrastructure, living off the land, and disruption-readiness implications.
- **BlackTech:** stealthy edge access, traffic redirection, trusted-edge abuse, and firmware/boot integrity concerns where supported.
- **APT28 and other state-aligned activity:** router exploitation for espionage/relay, config theft, credential/SNMP abuse, and edge/VPN targeting.
- **Criminal/opportunistic activity:** scanning, credential abuse, N-day exploitation, destructive/extortion activity, proxy/botnet use, and rapid exploitation. KEV ransomware association for an ASA/FTD CVE is gateway exposure context, not proof of device-resident malware.

## Attribution discipline

Report alignment as Possible, Plausible, or Strong only when TTP pattern, victimology, timing, and multiple independent artifacts agree. Separate:

- actor tracking name;
- campaign;
- vulnerability and exploit;
- malware family;
- persistence mechanism;
- infrastructure/IOC overlap.

Prefer a platform/CVE/campaign statement over actor attribution. Include competing explanations: approved administration, automation, maintenance, failover, monitoring, backup, licensing/telemetry, known defects, and upgrades.

## Freshness and fallback rules

- Try the authoritative source, then its recorded fallback.
- Exact-hash sources must match bytes; versioned mutable pages must retain the recorded marker.
- A reachable page does not prove that every prior claim remains current; inspect material changes.
- Manual verification is allowed only when documented and no older than 30 days. The Sygnia record was manually web-verified on 2026-08-28 and expires after 2026-09-27 unless reverified.
- Unreachable, changed-hash, missing-version, expired-manual, or removed sources require review. Do not silently drop a source or its uncertainty.
- Vendor YARA and Snort content may be linked and used under its own terms; do not redistribute it in this bundle.
