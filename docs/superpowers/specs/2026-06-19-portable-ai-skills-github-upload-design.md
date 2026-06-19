# Portable AI Skills GitHub Upload Design

## Goal

Publish the completed `kql-m365-azure-hunting` skill as the first skill in a new public GitHub repository designed to hold many portable skills for Copilot CLI, GPT 5.1, and AOAI-connected environments.

## Repository Decision

Create a new public repository:

```text
3ch0p01nt/portable-ai-skills
```

This is preferred over reusing `3ch0p01nt/AI_Skills` because `AI_Skills` already exists as a public Copilot CLI skill repository focused on professional-development workflows such as Connect and Perspectives. The new repository should be a neutral technical skill-pack collection that can grow independently.

## Existing GitHub Findings

`3ch0p01nt/AI_Skills` is the relevant existing pattern. It is public, uses a root `skills\` folder, and includes `.claude-plugin\plugin.json` plus `.claude-plugin\marketplace.json`. Its `marketplace.json` lists skills by name and description. This structure is the best model to reuse for Copilot CLI plugin/skill compatibility.

## Target Layout

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
  tests/
    prompt-fixtures.md
    expected-behaviors.md
  docs/
    superpowers/
      specs/
      plans/
  README.md
```

Future skills should be added as:

```text
skills/<skill-name>/SKILL.md
skills/<skill-name>/references/
skills/<skill-name>/examples/
```

Skill-specific tests may either go under `tests/<skill-name>/` when the collection grows, or stay in aggregate fixture files while the repository is small.

## Plugin Metadata

Add `.claude-plugin\plugin.json` with repository-level metadata:

- Name: `portable-ai-skills`
- Description: portable technical AI skills for Copilot CLI and compatible skill loaders.
- Author: Rob Soligan.
- License: MIT unless a different license is selected before publishing.
- Keywords: `copilot-cli`, `skills`, `kql`, `sentinel`, `defender`, `azure`, `aoai`, `gpt-5.1`.

Add `.claude-plugin\marketplace.json` with one initial skill:

- `kql-m365-azure-hunting`: write, review, package, and safely validate KQL for M365 Defender, Sentinel, Log Analytics, Azure Resource Graph, and read-only Az PowerShell workflows.

## README Requirements

The README should explain:

- How to clone the repo for Copilot CLI plugin use.
- How to copy or reference a single skill folder directly.
- That the skill content is static/offline and includes no AOAI endpoints, tenant IDs, keys, secrets, or deployment-specific details.
- That it is suitable for Copilot CLI sessions using GPT 5.1 through AOAI because it is plain skill content, not model-host-specific code.
- How future skills should be added.

## Upload Workflow

1. Create public repo `3ch0p01nt/portable-ai-skills`.
2. Rename the local branch from `master` to `main`.
3. Add `.claude-plugin` metadata files.
4. Update README with plugin install and direct skill install instructions.
5. Add the GitHub remote as `origin`.
6. Push `main` to GitHub.
7. Verify the GitHub repo contents and plugin metadata after push.

## Guardrails

- Do not include AOAI endpoint URLs, API keys, tenant IDs, client secrets, or deployment names in the public repo.
- Do not include production-only paths or machine-specific install paths except generic examples.
- Keep the repository public only because the current skill content is tenant-agnostic and contains no secrets.
- Future skills that contain customer-specific, tenant-specific, or sensitive content should go in a private repository or be sanitized before landing here.

## Self-Review

- The design uses an existing successful Copilot CLI plugin layout from `AI_Skills`.
- The design supports many future skills without mixing professional-development skills and technical security skills.
- The upload workflow preserves the existing local repo history and moves to the GitHub-standard `main` branch.
- No placeholders or secrets are included.
