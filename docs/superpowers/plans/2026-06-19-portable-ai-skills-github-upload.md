# Portable AI Skills GitHub Upload Implementation Plan

> **For agentic workers:** Execute each task in order and verify its expected result before continuing.

**Goal:** Publish the completed KQL/M365/Azure skill as the first skill in the public `3ch0p01nt/portable-ai-skills` repository.

**Architecture:** Keep one self-contained skill per folder under `skills\`. Use plain `SKILL.md` content with YAML frontmatter so compatible skill loaders can discover a copied skill folder without repository-specific metadata.

**Tech Stack:** Git, GitHub CLI (`gh`), Markdown, PowerShell.

---

## Target Layout

```text
portable-ai-skills/
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

## Task 1: Repository Documentation

Update `README.md` to:

- Describe the repository as a loader-neutral collection of portable skills.
- Explain how to clone the repository and copy an individual skill folder into a compatible loader's skills directory.
- Document the `skills\<skill-name>\SKILL.md` convention.
- State the offline, tenant-agnostic, and secret-free constraints.

Validate that the README names the skill entry point, direct folder installation, offline fixtures, and query-surface boundaries.

## Task 2: Repository Shape

Confirm these files exist:

```text
README.md
skills\kql-m365-azure-hunting\SKILL.md
tests\prompt-fixtures.md
tests\expected-behaviors.md
```

Confirm the KQL skill includes eight reference files and seven example files. Every future skill should use the same self-contained folder model, adding skill-specific tests under `tests\<skill-name>\` when aggregate fixtures become difficult to maintain.

## Task 3: Local Validation

Parse all JSON files and verify that Markdown references resolve to repository files where applicable. Scan public text for credentials, tenant identifiers, service endpoints, API keys, client secrets, or deployment-specific values.

Review `tests\prompt-fixtures.md` against `tests\expected-behaviors.md` and confirm the root skill routes each fixture to the appropriate references.

Run:

```powershell
git diff --check
git status --short
```

Expected: no whitespace errors; only intentional publication changes are present.

## Task 4: GitHub Publication

1. Confirm the target repository does not already exist.
2. Rename the default branch to `main` if needed.
3. Create the public repository with `gh repo create`.
4. Push `main`.
5. Verify the public README and `skills\kql-m365-azure-hunting\SKILL.md`.

Do not publish until local secret-pattern checks and offline validation pass.

## Task 5: Handoff

Report:

```text
Published: https://github.com/3ch0p01nt/portable-ai-skills
Default branch: main
Initial skill: skills\kql-m365-azure-hunting
Installation: copy the skill folder into a compatible loader's skills directory
Validation: local and GitHub checks passed
```

## Guardrails

- Keep skill content model-host neutral.
- Do not add machine-specific installation paths beyond generic placeholders.
- Do not include credentials, tenant-specific identifiers, endpoints, keys, secrets, or deployment names.
- Preserve existing local history when publishing.
- Sanitize any future customer-specific or sensitive content before adding it to the public repository.

## Self-Review

- The plan preserves the portable, multi-skill folder architecture.
- Installation depends only on a compatible loader discovering `SKILL.md`.
- Publication is gated on repository-shape, offline, JSON, whitespace, and secret-pattern validation.
