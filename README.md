# Portable AI Skills

Portable technical AI skills for GitHub Copilot CLI and compatible skill loaders. This repository is designed for environments where Copilot CLI is connected to GPT 5.1, including direct GPT 5.1 API access hosted in Azure OpenAI, without embedding model endpoints, tenant identifiers, API keys, or deployment-specific secrets.

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

### investigation-deepdive

Perform Microsoft-first, evidence-driven SOC investigations from a suspicious event, alert, entity, host, user, IP, process, file, URL, domain, cloud resource, identity, email, or log record.

Capabilities:

- Treats the seed event as a starting clue rather than the whole story.
- Extracts entities and builds recursive pivot plans.
- Routes workbook anomaly rows and vague anomaly summaries into entity-specific investigation playbooks.
- Provides repeatable domain, URL, IP, host, user, process, file/hash, email, cloud resource, OAuth app, and persistence pivots.
- Includes static read-only KQL pivot templates with explicit execution status.
- Enforces hard read-only tenant safety controls and refuses executable destructive actions.
- Creates timelines, hypotheses, evidence ledgers, root-cause assessments, blast-radius assessments, and final reports.
- Uses Microsoft Sentinel, Defender XDR, Entra ID, M365, Azure, and KQL-oriented workflows when those sources are available.
- Delegates KQL syntax and query review to `kql-m365-azure-hunting`.
- Requires explicit authorization for read-only live query execution, refuses mutating or destructive tenant actions, and never invents evidence or schema.
- Runs skeptical QA before final conclusions.

## Install as a Copilot CLI Plugin

Use GitHub Copilot CLI plugin management instead of manually writing into the internal installed plugins directory.

Install directly from PowerShell:

```powershell
copilot plugin install 3ch0p01nt/portable-ai-skills
```

The equivalent interactive command inside Copilot CLI is:

```text
/plugin install 3ch0p01nt/portable-ai-skills
```

You can also run `/plugin`, choose the interactive install flow, and provide `3ch0p01nt/portable-ai-skills` when prompted. Restart or reload Copilot CLI, then use `/plugin` and `/skills` to confirm the plugin and skills are available.

## Direct Skill Folder Install

If an environment loads skills directly instead of using plugin metadata, this skill folder can be copied for Copilot-compatible skill loaders because `SKILL.md` includes YAML frontmatter:

```powershell
git clone 'https://github.com/3ch0p01nt/portable-ai-skills.git' portable-ai-skills
Set-Location .\portable-ai-skills
$skillsDirectory = Read-Host 'Enter the local skills directory path'
Copy-Item -Recurse '.\skills\kql-m365-azure-hunting' "$skillsDirectory\kql-m365-azure-hunting"
Copy-Item -Recurse '.\skills\investigation-deepdive' "$skillsDirectory\investigation-deepdive"
```

## Repository Structure

```text
portable-ai-skills/
  .claude-plugin/
    plugin.json
    marketplace.json
  skills/
    kql-m365-azure-hunting/
      SKILL.md
      references/
      examples/
    investigation-deepdive/
      SKILL.md
      references/
      examples/
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
skills/your-skill-name/SKILL.md
skills/your-skill-name/references/
skills/your-skill-name/examples/
```

Include YAML frontmatter in each `SKILL.md`, then update this README and any plugin metadata or registry files required by the chosen loader or distribution channel. Some loaders may use `.claude-plugin` metadata; update `.claude-plugin\plugin.json` or `.claude-plugin\marketplace.json` only when that loader requires it.

## Offline Validation

Use these files to check behavior after installation:

```text
tests\prompt-fixtures.md
tests\expected-behaviors.md
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

## License

MIT
