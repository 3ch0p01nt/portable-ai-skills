# KQL M365 Azure Hunting Skill Pack

Portable Superpowers-compatible skill pack for KQL, M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure Resource Graph, and read-only Azure PowerShell Az validation workflows.

## What It Does

This skill teaches an AI assistant to:

- Classify the correct Microsoft query surface.
- Write bounded and explainable KQL.
- Review unsafe KQL before returning it.
- Use Az PowerShell read-only validation patterns for Azure, Log Analytics, and Sentinel context.
- Avoid invented schema, tenant facts, and live-validation claims.
- Default to commercial `.com` Microsoft cloud terminology.

## Install from Git

Clone the repository:

```powershell
git clone <repository-url>
```

Copy the skill folder into the local Superpowers skills directory:

```powershell
Copy-Item -Recurse '.\skills\kql-m365-azure-hunting' '<superpowers-skills-directory>\kql-m365-azure-hunting'
```

Restart or reload the AI tool so it can discover the skill.

## Skill Entry Point

The root skill is:

```text
skills\kql-m365-azure-hunting\SKILL.md
```

## Offline Test Fixtures

Use these files to check behavior after installation:

```text
tests\prompt-fixtures.md
tests\expected-behaviors.md
```

## Constraints

- No credentials are included.
- No tenant-specific IDs are included.
- No live Azure or M365 validation scripts are included in v1.
- The AI must state assumptions when schema or connector context is missing.
- Sentinel tables depend on enabled connectors.
- Device Query / Live Response is a separate query surface from Sentinel and Defender Advanced Hunting.
- Az module guidance is read-only in v1; mutating `New-Az*`, `Set-Az*`, `Update-Az*`, and `Remove-Az*` workflows are out of scope unless explicitly redesigned.
