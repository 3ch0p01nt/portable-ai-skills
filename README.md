# Portable AI Skills

Portable technical AI skills for compatible skill loaders. The repository includes KQL cloud hunting and authorized Cisco network-device incident-response workflows without embedding endpoints, tenant identifiers, credentials, or deployment-specific secrets.

## Installed Skills

### kql-m365-azure-hunting

Write, review, package, and safely validate KQL for M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure Resource Graph, and read-only Azure PowerShell Az workflows.

Capabilities:

- Classifies the correct Microsoft query surface.
- Writes bounded and explainable KQL.
- Reviews unsafe KQL before returning it.
- Packages Sentinel analytics rule YAML and portable detection examples.
- Documents table, connector, and entity-mapping expectations.
- Uses read-only Az PowerShell validation patterns for Azure, Log Analytics, and Sentinel context.
- Keeps Device Query separate from Sentinel and Defender Advanced Hunting.
- Treats Live Response as non-KQL operational/remote-shell work and out of scope except for boundary explanation.

### cisco-device-compromise-investigation

Analyze sanitized local Cisco network-device evidence in live-guidance, dead-box, syslog-only, config-diff, fleet/orchestrator, and threat-intelligence-led modes.

Capabilities:

- Routes platform-specific evidence for IOS XE, IOS, IOS XR, NX-OS, ASA/FTD/FXOS/FMC, SD-WAN, wireless, ISE, and orchestrators.
- Uses preview-first recursive local-folder analysis with redaction, evidence IDs, an 18-domain rubric, and explicit gaps.
- Separates vulnerabilities, exploitation, campaigns, actors, malware, and persistence.
- Preserves volatile evidence and availability through safety-specific LINE VIPER, RayInitiator, FIRESTARTER, and ArcaneDoor branches.
- Never connects to live devices; all live-device commands are human-executed and risk labeled.

## Install

Clone the repository, then copy either skill folder into the target project's `.github\skills` directory. Each `SKILL.md` includes YAML frontmatter for discovery.

From a repository cloned inside the target project:

```powershell
git clone 'https://github.com/3ch0p01nt/portable-ai-skills.git' portable-ai-skills
Set-Location .\portable-ai-skills
$ProjectSkills = '..\.github\skills'
New-Item -ItemType Directory -Force $ProjectSkills | Out-Null
Copy-Item -Recurse -Force '.\skills\kql-m365-azure-hunting' $ProjectSkills
Copy-Item -Recurse -Force '.\skills\cisco-device-compromise-investigation' $ProjectSkills
```

For another layout, assign the target project's absolute `.github\skills` path:

```powershell
$ProjectSkills = 'C:\path\to\project\.github\skills'
New-Item -ItemType Directory -Force $ProjectSkills | Out-Null
Copy-Item -Recurse -Force '.\skills\cisco-device-compromise-investigation' $ProjectSkills
```

### Verify skill discovery

Confirm the entry point is directly beneath the configured skills directory:

```powershell
Test-Path (Join-Path $ProjectSkills 'cisco-device-compromise-investigation\SKILL.md')
```

The command must return `True`. Restart or reload the skill loader so it rescans the directory, then use its skill-listing command, such as `/skills` when supported.

Trigger the skill with a natural-language request:

```text
Investigate this folder of Cisco artifacts for possible compromise: C:\path\to\evidence
```

If discovery fails, check for an accidentally duplicated directory:

```powershell
Get-ChildItem (Join-Path $ProjectSkills 'cisco-device-compromise-investigation') -Recurse -Filter SKILL.md
```

The entry point must resolve exactly to:

```text
.github\skills\cisco-device-compromise-investigation\SKILL.md
```

## Repository Structure

```text
portable-ai-skills/
  skills/
    kql-m365-azure-hunting/
      SKILL.md
      references/
      examples/
    cisco-device-compromise-investigation/
      SKILL.md
      README.md
      references/
      detections/
      evals/
      rules/
      schemas/
      scripts/
      tests/
      tools/
  .github/
    workflows/
  tests/
    prompt-fixtures.md
    expected-behaviors.md
  docs/
    superpowers/
      specs/
      plans/
```

## Adding Future Skills

Add one folder per skill:

```text
skills/<skill-name>/SKILL.md
skills/<skill-name>/references/
skills/<skill-name>/examples/
```

Include YAML frontmatter in each `SKILL.md`, then update this README and any registry files required by the chosen loader or distribution channel.

## Offline Validation

Use the root prompt fixtures to check expected routing behavior:

```text
tests\prompt-fixtures.md
tests\expected-behaviors.md
```

The Cisco skill also ships cross-platform, standard-library validation. These commands require Python 3.11+ and do not use the network:

```text
python skills/cisco-device-compromise-investigation/scripts/validate_skill.py
python skills/cisco-device-compromise-investigation/scripts/test_skill.py --category all
```

Run source freshness separately when network access is appropriate:

```text
python skills/cisco-device-compromise-investigation/scripts/check_sources.py --strict --output source-status.json
```

## Constraints

- No credentials are included.
- No tenant-specific IDs are included.
- No AOAI endpoints, API keys, deployment names, or model-host secrets are included.
- No live Azure or M365 validation scripts are included in v1.
- The AI must state assumptions when schema or connector context is missing.
- Sentinel tables depend on enabled connectors.
- Device Query is a separate KQL-like surface from Sentinel and Defender Advanced Hunting.
- Live Response is non-KQL operational/remote-shell work and is out of scope except for boundary explanation.
- Az module guidance is read-only in v1; mutating `New-Az*`, resource-changing `Set-Az*`, `Update-Az*`, and `Remove-Az*` workflows are out of scope unless explicitly redesigned.
- Cisco evidence and reports can contain sensitive incident data; sanitize them and never publish real evidence or secrets.
- Cisco tooling processes local artifacts only and never connects to a live device.
- Missing volatile state, baselines, independent evidence, or platform visibility limits Cisco conclusions.
- Vendor YARA/Snort content is referenced at its source and is not redistributed.

## License

MIT
