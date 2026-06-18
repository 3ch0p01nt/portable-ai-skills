# KQL M365 Azure Hunting Skill Pack

This repository contains a portable Superpowers-compatible skill pack for teaching an AI assistant how to write and review KQL for M365 Defender Advanced Hunting, Microsoft Sentinel, Log Analytics, Azure, and Azure Resource Graph workflows.

## Scope

- Static offline skill content.
- No tenant credentials.
- No Azure or M365 live validation scripts.
- Commercial `.com` cloud terminology by default.
- `.us` cloud guidance only when the user asks for it or provides tenant evidence.

## Install from Git

Clone the repository:

```powershell
git clone <repository-url>
```

Copy `skills\kql-m365-azure-hunting` into the local Superpowers skills directory used by the target AI tool.

## Use

Ask the AI to use the `kql-m365-azure-hunting` skill before writing or reviewing KQL that touches M365 Defender, Sentinel, Log Analytics, Azure, or Azure Resource Graph.

## Offline Validation

Use `tests\prompt-fixtures.md` and `tests\expected-behaviors.md` to check whether the skill selects the right references, avoids invented schema, writes bounded KQL, and applies the query-review checklist.