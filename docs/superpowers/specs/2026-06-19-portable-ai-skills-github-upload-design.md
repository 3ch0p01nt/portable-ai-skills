# Portable AI Skills GitHub Upload Design

## Goal

Publish the completed `kql-m365-azure-hunting` skill as the first skill in a public GitHub repository designed to hold portable, model-host-neutral skills.

## Repository Decision

Use the public repository:

```text
3ch0p01nt/portable-ai-skills
```

A dedicated technical skill collection keeps security and cloud workflows independent from unrelated skill sets and provides room for additional self-contained skills.

## Portable Loader Design

The repository uses a root `skills\` directory. Each child folder is independently installable and contains a `SKILL.md` entry point with YAML frontmatter. References, examples, tests, schemas, scripts, and tools that belong to a skill remain in that skill's folder.

Compatible loaders install a skill by copying its folder into their configured skills directory. The repository does not require loader-specific discovery metadata.

## Target Layout

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
  tests/
    prompt-fixtures.md
    expected-behaviors.md
  docs/
    superpowers/
      specs/
      plans/
  README.md
```

Future skills follow:

```text
skills/<skill-name>/SKILL.md
skills/<skill-name>/references/
skills/<skill-name>/examples/
```

Additional directories are allowed when the skill needs deterministic tooling, schemas, evaluations, or detections.

## Skill Discovery Contract

- `SKILL.md` is the required entry point.
- YAML frontmatter declares loader-facing identity and purpose.
- Relative paths keep references valid after direct folder installation.
- Skill content must not assume a particular model host, command-line client, or repository registry.
- The README documents direct folder installation and any loader prerequisites.

## README Requirements

The root README should explain:

- How to clone the repository.
- How to copy one skill folder into a compatible loader's skills directory.
- What each included skill does.
- How future skills should be structured.
- How to run offline validation.
- That no endpoints, tenant identifiers, keys, credentials, or deployment-specific details are included.

## Upload Workflow

1. Validate the repository shape and direct-install documentation.
2. Parse all JSON and run the available offline test suites.
3. Scan paths and text for prohibited or sensitive content.
4. Run `git diff --check`.
5. Create or configure the GitHub remote.
6. Push the `main` branch.
7. Verify the public README and skill entry points.

## Guardrails

- Keep the repository public only while its content is tenant-agnostic and contains no secrets.
- Do not include production-only paths or machine-specific installation locations except generic placeholders.
- Keep operational tooling offline by default and clearly label any network-dependent validation.
- Sanitize customer-specific, tenant-specific, or sensitive content before publication.
- Preserve useful history; do not rewrite it solely for publication.

## Self-Review

- The design supports many skills without tying discovery to one loader.
- Direct folder installation keeps each skill portable.
- The upload workflow gates publication on content, path, JSON, test, and whitespace validation.
- No placeholders beyond intentional user-supplied paths are required.
