# LINE VIPER, RayInitiator, and FIRESTARTER

Verified through 2026-08-28. Recheck live sources during every investigation.

## Primary source set

- UK NCSC, `RayInitiator & LINE VIPER`, Malware Analysis Report Version 1.1, October 2025:
  https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-rayinitiator-line-viper.pdf
- Cisco, `Continued Attacks Against Cisco Firewalls by the Threat Actor behind ArcaneDoor`, Version 2.3, updated 2026-04-24:
  https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_continued_attacks
- Cisco, `Detection Guide for Continued Attacks against Cisco Firewalls by the Threat Actor behind ArcaneDoor`, Version 1.2, 2026-04-24:
  https://sec.cloudapps.cisco.com/security/center/resources/detection_guide_for_continued_attacks
- CISA, FIRESTARTER Malware Analysis Report AR26-113A, 2026-04-23:
  https://www.cisa.gov/news-events/analysis-reports/ar26-113a
- Cisco Talos, `UAT-4356 deploys FIRESTARTER`, 2026:
  https://blog.talosintelligence.com/uat-4356-firestarter/
- Cisco informational advisory:
  https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-persist-CISAED25-03
- CISA V1 ED 25-03 and Supplemental Direction:
  https://www.cisa.gov/news-events/directives/v1-ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices
  https://www.cisa.gov/news-events/directives/supplemental-direction-ed-25-03-core-dump-and-hunt-instructions
- Cisco CVE-2025-20333:
  https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-z5xP8EUB
- Cisco CVE-2025-20362:
  https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-YROOTUW
- Cisco CVE-2025-20363:
  https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-code-exec-WmfP3h3O
- Cisco Talos, original ArcaneDoor report, 2024-04-24, updated 2025-09-25:
  https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/

## Identity and scope

| Item | Verified classification |
|---|---|
| Actor | UAT4356 (Cisco Talos), also tracked as STORM-1849 by Microsoft |
| Campaign | ArcaneDoor and related continued attacks |
| RayInitiator | Persistent multi-stage GRUB bootkit flashed to non-Secure-Boot Cisco ASA 5500-X devices |
| LINE VIPER | Victim-specific modular x64 user-mode shellcode loader operating in `lina` memory |
| FIRESTARTER | Separate FXOS ELF backdoor that overlaps technically with RayInitiator Stage 3 and can redeploy LINE VIPER |
| Confirmed RayInitiator target class | ASA 5500-X models without Secure Boot/Trust Anchor |
| LINE VIPER versions analyzed by NCSC | ASA 9.12(4)67 and 9.14(4)24 |
| Confirmed Cisco campaign exposure | ASA 9.12/9.14 on listed legacy ASA 5500-X models with VPN web services enabled |
| Confirmed FIRESTARTER observation | CISA observed the sample on a Cisco Firepower device running ASA software |
| Broader defensive scope | Cisco directs defenders to assess vulnerable ASA and FTD with VPN web services and FXOS-based Firepower/Secure Firewall architecture |

Do not call LINE VIPER an IOS XE implant or Salt Typhoon malware. Do not call FIRESTARTER the RayInitiator bootkit. They overlap in WebVPN XML handler tradecraft but are separately named components.

## Branch routing

### Branch A: RayInitiator to LINE VIPER

- Target class: legacy ASA 5500-X without Secure Boot/Trust Anchor.
- Persistence: RayInitiator GRUB bootkit.
- Payload: LINE VIPER loaded through RayInitiator's WebVPN form-handler path.
- Primary analysis: NCSC MAR YARA and core-dump detector, boot/ROMMON evidence, and applicable Cisco upgrade-console evidence.

### Branch B: direct LINE VIPER then FIRESTARTER

- Target class: CISA's observed Firepower device running ASA software; Cisco's defensive scope also includes vulnerable ASA/FTD on FXOS architectures.
- Assessed access: CVE-2025-20333 and/or CVE-2025-20362. Cisco states evidence strongly indicates both were used in the campaign; preserve CISA's assessed-not-confirmed wording for a specific victim unless local evidence proves it.
- Sequence: LINE VIPER deployed directly after exploitation, FIRESTARTER installed as persistence, then FIRESTARTER later redeployed LINE VIPER without re-exploiting the original vulnerabilities.
- CVE-2025-20363 was remediated in the same September 2025 release set, but public sources did not establish it as the access path in the CISA FIRESTARTER incident.
- Primary analysis: CISA AR26-113A, Cisco/Talos FIRESTARTER guidance, FXOS artifacts, and current ED 25-03 direction.

## RayInitiator execution chain

RayInitiator patches GRUB so its first stage receives control while ASA firmware loads. Subsequent stages locate the ASA loader and Linux kernel, account for KASLR where present, hook a system call used during `lina` loading, and install a handler in the WebVPN XML form-element path. The deploy stage:

1. Checks victim-specific identifiers in WebVPN XML elements.
2. Extracts a shellcode stub from a client-authentication element.
3. Copies the stub into `lina` memory and marks it executable.
4. Executes the LINE VIPER bootstrap when the matching element is processed.

NCSC states RayInitiator survives reboots and firmware upgrades. A device can contain RayInitiator without LINE VIPER currently resident.

## LINE VIPER bootstrap and communication

- Initial delivery is disguised inside a WebVPN client-authentication request.
- Observed deployment used a Base64 shellcode stub and a partial PKCS7 certificate whose decoded bytes begin with 0x80 bytes of a legitimate certificate before the main shellcode.
- The observed partial-certificate serial number is `3037644167568058970164719475676101450`.
- Victim-specific tokens and keys prevent universal hash and simple static-IOC coverage.
- LINE VIPER copies code into unused `lina` code and data areas, hooks VPN client-authentication handling, and uses temporary executable permissions for tasking code.

Two tasking methods are documented:

1. WebVPN client authentication over HTTPS. Victim tokens and a per-victim RSA key protect key exchange; tasking and output use AES-CBC-256. Captured traffic generally cannot be decrypted without victim-specific key material.
2. ICMP echo-request tasking carried inside an established VPN session to a LAN-facing ASA address. Results leave in raw TCP packets to random high ports above 60000. This traffic may never cross the external perimeter in observable plaintext.

## Documented LINE VIPER capabilities

- Grant level-15 privilege and execute ASA CLI commands.
- Create packet captures hidden from `show capture`.
- Capture RADIUS, LDAP, and TACACS traffic.
- Exfiltrate the hidden capture buffer.
- Bypass VPN Authentication, Authorization, and Accounting for actor-controlled device IDs.
- Harvest commands entered by legitimate administrators.
- Suppress selected syslog messages in memory.
- Force immediate reboot for selected forensic actions.
- Schedule a delayed reboot, observed between one and ten hours.
- Load additional shellcode modules.

## Evasion and deceptive evidence

Do not treat these checks as clearance:

- `show memory region | include lina`: unlike LINE DANCER, LINE VIPER modifies a larger code region and restores protections so the older split-`lina` artifact is not observable.
- `copy system:/text`: LINE VIPER can intercept the copy path and reboot the device.
- `verify system:/text`: LINE VIPER can return the legitimate firmware MD5 or SHA-512 rather than the modified state.
- Normal `show capture`: LINE VIPER maintains a separate hidden capture list.
- Clean AAA records: actor device IDs can bypass VPN AAA.
- Clean syslog configuration: suppression occurs in memory.
- Negative hashes: NCSC did not publish hashes because analyzed instances were victim-specific.

## Log and behavioral artifacts

NCSC documents selective suppression of:

| ASA syslog ID | Defensive use |
|---|---|
| 302013 | Watch for downward volume shift or unexpected absence of built TCP connection events |
| 302014 | Watch for downward volume shift or unexpected absence of TCP teardown events |
| 609002 | Watch for missing local-host teardown events |
| 710005 | Watch for missing discarded-request events |

LINE VIPER hooks CLI paths associated with:

| ASA syslog ID | Documented message role |
|---|---|
| 111008 | User executed a command |
| 111009 | User executed a CLI command |

Use these as platform-specific behavioral context, not as proof by themselves. Baseline each device's normal volume and account for severity configuration, retention, outages, failover, and collector loss.

Additional campaign signals from Cisco:

- `show checkheaps` total-run counter fails to increase across five one-minute observations.
- Impossible-travel VPN use, especially inactive but valid accounts.
- Unexpected reloads or a core-dump attempt that immediately reboots without creating a dump.
- VPN sessions with no expected independent AAA evidence.
- VPN web services enabled on vulnerable or legacy platforms.
- On unpatched devices, an unexpected reload may also align with the November 2025 denial-of-service variant; distinguish it from LINE VIPER anti-forensics using patch state and collection context.

## NCSC detection material

The NCSC report contains:

- Four RayInitiator YARA rules covering bootkit stages 1, 2, and stage-3 install/deploy behavior.
- LINE VIPER YARA rules for shellcode deobfuscation, initial execution, RSA-protected key generation, AES tasking/exfiltration, and ICMP tasking payloads.
- A Python detector that searches an ASA core dump for RayInitiator's malicious WebVPN form-handler pointer.

Use the rules and script from the original NCSC report rather than copying stale signatures into a case report. NCSC states no false positives were identified during its analysis, but the core detector was tested only against affected 9.12 and 9.14 samples and does not guarantee complete coverage.

## FIRESTARTER branch

CISA and Talos document FIRESTARTER as an ELF backdoor on Cisco Firepower/Secure Firewall devices:

- Observed filename/process: `lina_cs`; Cisco warns the name can change.
- Observed file: `/usr/bin/lina_cs`; FIRESTARTER deletes this file after copying itself to memory, so file absence does not clear a positive process or memory finding.
- Reboot-persistent staging file: `/opt/cisco/platform/logs/var/log/svc_samcore.log`.
- Persistence modifies `/opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST`, then restores timestamps/ownership and deletes traces after relaunch.
- It hooks a WebVPN XML handler inside LINA and executes supplied shellcode.
- Its signal-triggered staged persistence survives application updates and graceful reboots. Loss of all power interrupts the observed relaunch mechanism but destroys live evidence.
- CISA observed FIRESTARTER redeploy LINE VIPER after the victim had patched.

Primary detection:

1. Run `show kernel process | include lina_cs`.
2. If present, run Cisco's current three-step false-positive procedure: confirm `lina_cs`, use `verify` against an ASDM image on `disk0:`, then check `lina_cs` again. An arbitrary firmware file is not a substitute.
3. Hunt disk images with CISA rule `CISA_261290_01` for the injector and core/memory with `CISA_261290_02` for shellcode. Use the current rule text from AR26-113A.
4. Check for the two files and CSP mount-list changes above.
5. Use Snort rule 62949 and ClamAV signature `Unix.Malware.Generic-10059965-0` where applicable.

CISA states Sigma-style log rules do not provide effective FIRESTARTER detection because standard monitoring may have no observable event. Do not treat SIEM silence as clearance.

Do not power-cycle merely to make the process disappear. Preserve evidence and follow the current authority path first. For U.S. FCEB agencies: submit the required core dump to CISA Malware Next Generation, notify the CISA 24/7 Operations Center, and take no further action until directed. Other organizations should preserve evidence, run the applicable CISA YARA workflow, and coordinate with Cisco TAC/IR and their national authority before evidence-destructive action.

Exploit-chain network coverage is distinct from implant detection:

- Snort 65340: CVE-2025-20333 coverage.
- Snort 46897: CVE-2025-20362 coverage.
- Snort 62949: FIRESTARTER-related coverage cited by Talos.

## Cisco ROMMON and upgrade artifacts

For the legacy ASA 5500-X campaign branch:

- Cisco observed ROMMON modification only on models lacking Secure Boot/Trust Anchor.
- During the first boot into applicable fixed ASA 9.12.4.72 or 9.14.4.28 releases, monitor console output for bootloader and ROMMON verification success or failure.
- `disk0:/firmware_update.log` after upgrade can indicate that persistence was detected and removed.
- Submit the log and `show tech-support` output to Cisco TAC.
- A successful upgrade is not a historical clearance finding; configurations, passwords, certificates, and keys remain untrusted after suspected or confirmed compromise.

## Collection decision tree

1. Preserve external syslog, AAA, VPN concentrator, NetFlow, PCAP, FMC, change records, and console logs first.
2. Identify platform, version, model, Secure Boot/Trust Anchor, VPN services, HA peer, uptime, and reload reason.
3. Check the live Cisco event-response and detection-guide versions before issuing collection instructions.
4. If the 2024 split-`lina` artifact suggests LINE DANCER, stop before reboot/core dump and follow Cisco/Talos's specific first-responder procedure.
5. For continued attacks, evaluate syslog-volume suppression, checkheaps, impossible travel, ROMMON logs, `firmware_update.log`, and FIRESTARTER process/files.
6. Apply the current jurisdiction-specific direction. U.S. FCEB agencies must use the current ED 25-03 supplemental workflow; preserve and submit the required core dump before further action.
7. If a pre-patch core-dump attempt immediately reboots without a dump, record that as possible LINE VIPER anti-forensics; do not repeatedly trigger it.
8. If a core dump succeeds, use NCSC RayInitiator and LINE VIPER detection material.
9. Repeat acquisition separately on each failover peer.
10. Treat any single negative check as insufficient. State exactly which layer remains untested: memory, boot, FXOS, disk, config, AAA, network, or orchestrator.

## Confidence language

- Confirmed: primary rule or artifact match plus corroboration, or Cisco/CISA/TAC determination.
- High: multiple independent indicators across memory/process, logs, network, boot, or filesystem.
- Moderate: one strong behavioral indicator with correct platform and exposure.
- Low: campaign resemblance without a platform-specific artifact.
- Insufficient: missing volatile evidence, untrusted CLI output, or no independent telemetry.

Do not attribute UAT4356 to a country unless a current primary source does so.
