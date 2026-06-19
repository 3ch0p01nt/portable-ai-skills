# Portable AI Skills GitHub Upload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the completed KQL/M365/Azure skill as the first skill in a new public GitHub repository named `3ch0p01nt/portable-ai-skills`.

**Architecture:** Keep the current repository as the seed repository, add Copilot CLI-compatible plugin metadata, update root documentation for plugin and direct skill install, rename the default branch to `main`, create the new public GitHub repo, and push. The repo remains a multi-skill collection with one installable skill per folder under `skills\`.

**Tech Stack:** Git, GitHub CLI (`gh`), Markdown, JSON, Copilot CLI plugin skill layout.

---

## File Structure

- Create: `.claude-plugin\plugin.json` - repository/plugin metadata for Copilot CLI plugin discovery.
- Create: `.claude-plugin\marketplace.json` - skill registry for the plugin.
- Modify: `README.md` - root documentation for the new multi-skill repository and GPT 5.1/AOAI/Copilot CLI use.
- Modify: `docs\superpowers\plans\2026-06-19-portable-ai-skills-github-upload.md` - mark task completion only if executing this plan inline.
- Remote: create `https://github.com/3ch0p01nt/portable-ai-skills`.

## Task 1: Plugin Metadata

**Files:**
- Create: `.claude-plugin\plugin.json`
- Create: `.claude-plugin\marketplace.json`

- [ ] **Step 1: Write the failing metadata validation**

Run:

```powershell
if (Test-Path '.\.claude-plugin\plugin.json') { throw 'plugin.json already exists' }
if (Test-Path '.\.claude-plugin\marketplace.json') { throw 'marketplace.json already exists' }
'Expected fail state: plugin metadata missing'
```

Expected: exits 0 and prints `Expected fail state: plugin metadata missing`.

- [ ] **Step 2: Create plugin metadata**

Create `.claude-plugin\plugin.json` with this content:

```json
{
  "name": "portable-ai-skills",
  "version": "1.0.0",
  "description": "Portable technical AI skills for Copilot CLI and compatible skill loaders, including KQL, Microsoft Sentinel, Defender XDR, Azure, and AOAI-connected workflows.",
  "author": {
    "name": "Rob Soligan"
  },
  "license": "MIT",
  "keywords": [
    "copilot-cli",
    "skills",
    "kql",
    "sentinel",
    "defender",
    "azure",
    "aoai",
    "gpt-5.1"
  ]
}
```

Create `.claude-plugin\marketplace.json` with this content:

```json
{
  "name": "portable-ai-skills",
  "metadata": {
    "description": "Portable technical AI skills for Copilot CLI and compatible skill loaders."
  },
  "owner": {
    "name": "3ch0p01nt"
  },
  "plugins": [
    {
      "name": "portable-ai-skills",
      "description": "Portable technical AI skills for Copilot CLI and compatible skill loaders, including KQL, Microsoft Sentinel, Defender XDR, Azure, and AOAI-connected workflows.",
      "source": "./"
    }
  ]
}
```

- [ ] **Step 3: Validate metadata JSON and skill folder references**

Run:

```powershell
$plugin = Get-Content '.\.claude-plugin\plugin.json' -Raw | ConvertFrom-Json
$marketplace = Get-Content '.\.claude-plugin\marketplace.json' -Raw | ConvertFrom-Json
if ($plugin.name -ne 'portable-ai-skills') { throw 'plugin name mismatch' }
if ($marketplace.name -ne 'portable-ai-skills') { throw 'marketplace name mismatch' }
if ($marketplace.metadata.description -notmatch 'Portable technical AI skills') { throw 'marketplace metadata description missing' }
if ($marketplace.owner.name -ne '3ch0p01nt') { throw 'marketplace owner mismatch' }
if ($marketplace.plugins[0].source -ne './') { throw 'marketplace source mismatch' }
if (Get-Command claude -ErrorAction SilentlyContinue) { claude plugin validate --strict . }
'Plugin metadata validated'
```

Expected: exits 0 and prints `Plugin metadata validated`.

- [ ] **Step 4: Commit plugin metadata**

Run:

```powershell
git add .claude-plugin\plugin.json .claude-plugin\marketplace.json
git commit -m "feat: add portable skills plugin metadata" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit exits 0.

## Task 2: Repository README for Multi-Skill Use

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README with multi-skill repository documentation**

Replace `README.md` with this content:

```markdown
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

## Install as a Copilot CLI Plugin

Clone this repository into your Copilot CLI installed plugins directory:

```powershell
git clone 'https://github.com/3ch0p01nt/portable-ai-skills.git' "$HOME\.copilot\installed-plugins\portable-ai-skills"
```

Restart or reload Copilot CLI, then use `/plugin` and `/skills` to confirm the plugin and skills are available.

## Direct Skill Folder Install

If an environment loads skills directly instead of using plugin metadata, copy the skill folder:

```powershell
git clone 'https://github.com/3ch0p01nt/portable-ai-skills.git' portable-ai-skills
Set-Location .\portable-ai-skills
Copy-Item -Recurse '.\skills\kql-m365-azure-hunting' '<skills-directory>\kql-m365-azure-hunting'
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

Then add the skill to `.claude-plugin\marketplace.json` and update this README.

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
```

- [ ] **Step 2: Validate README content**

Run:

```powershell
$readme = Get-Content '.\README.md' -Raw
@(
  'Portable AI Skills',
  'GitHub Copilot CLI',
  'GPT 5.1',
  'Azure OpenAI',
  'No AOAI endpoints',
  'Device Query is a separate KQL-like surface',
  'Live Response is non-KQL',
  '.claude-plugin',
  'skills/<skill-name>/SKILL.md'
) | ForEach-Object {
  if ($readme -notmatch [regex]::Escape($_)) { throw "README missing $_" }
}
'README validated'
```

Expected: exits 0 and prints `README validated`.

- [ ] **Step 3: Commit README**

Run:

```powershell
git add README.md
git commit -m "docs: update README for portable skills repo" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit exits 0.

## Task 3: Final Local Validation Before GitHub Push

**Files:**
- Read: repository files

- [ ] **Step 1: Validate repository shape**

Run:

```powershell
$required = @(
  '.\.claude-plugin\plugin.json',
  '.\.claude-plugin\marketplace.json',
  '.\README.md',
  '.\skills\kql-m365-azure-hunting\SKILL.md',
  '.\tests\prompt-fixtures.md',
  '.\tests\expected-behaviors.md'
)
$missing = $required | Where-Object { -not (Test-Path $_) }
if ($missing) { $missing; throw 'Required repository files missing' }
$refs = @(Get-ChildItem '.\skills\kql-m365-azure-hunting\references' -File)
$examples = @(Get-ChildItem '.\skills\kql-m365-azure-hunting\examples' -File)
if ($refs.Count -ne 8) { throw "Expected 8 references, got $($refs.Count)" }
if ($examples.Count -ne 7) { throw "Expected 7 examples, got $($examples.Count)" }
'Repository shape validated'
```

Expected: exits 0 and prints `Repository shape validated`.

- [ ] **Step 2: Validate no public-repo secret patterns**

Run:

```powershell
$text = Get-ChildItem . -Recurse -File -Include *.md,*.json,*.ps1,*.py,*.yml,*.yaml |
  Where-Object { $_.FullName -notmatch '\\.git\\' } |
  ForEach-Object { Get-Content $_.FullName -Raw }
$joined = $text -join "`n"
$patterns = @(
  'api[_-]?key\s*[:=]\s*["''][^"'']+',
  'client[_-]?secret\s*[:=]\s*["''][^"'']+',
  ('AZURE_' + 'OPENAI_API_KEY'),
  'https://[^\\s]+\\.openai\\.azure\\.com'
)
foreach ($pattern in $patterns) {
  if ($joined -match $pattern) { throw "Potential secret or endpoint pattern found: $pattern" }
}
'Secret-pattern validation passed'
```

Expected: exits 0 and prints `Secret-pattern validation passed`.

- [ ] **Step 3: Validate plugin metadata and strict validation**

Run:

```powershell
$plugin = Get-Content '.\.claude-plugin\plugin.json' -Raw | ConvertFrom-Json
$marketplace = Get-Content '.\.claude-plugin\marketplace.json' -Raw | ConvertFrom-Json
if ($plugin.name -ne 'portable-ai-skills') { throw 'plugin name mismatch' }
if ($marketplace.name -ne 'portable-ai-skills') { throw 'marketplace name mismatch' }
if ($marketplace.metadata.description -notmatch 'Portable technical AI skills') { throw 'marketplace metadata description missing' }
if ($marketplace.owner.name -ne '3ch0p01nt') { throw 'marketplace owner mismatch' }
if ($marketplace.plugins[0].source -ne './') { throw 'marketplace source mismatch' }
if (Get-Command claude -ErrorAction SilentlyContinue) { claude plugin validate --strict . }
'Plugin metadata validated'
```

Expected: exits 0 and prints `Plugin metadata validated`.

- [ ] **Step 4: Validate Git state**

Run:

```powershell
$status = git status --short
if ($status) { $status; throw 'Working tree is not clean' }
git --no-pager log --oneline -3
```

Expected: no status output and recent commits include plugin metadata and README commits.

## Task 4: Create GitHub Repository and Push

**Files:**
- Remote operation: create public GitHub repo and push.

- [ ] **Step 1: Confirm target repo does not already exist**

Run:

```powershell
gh repo view 3ch0p01nt/portable-ai-skills --json name,url,visibility 2>$null
if ($LASTEXITCODE -eq 0) { throw 'Repository already exists: 3ch0p01nt/portable-ai-skills' }
'Expected state: target repo does not exist yet'
```

Expected: exits 0 and prints `Expected state: target repo does not exist yet`.

- [ ] **Step 2: Rename branch to main**

Run:

```powershell
git branch --show-current
git branch -M main
git branch --show-current
```

Expected: final output is `main`.

- [ ] **Step 3: Create public GitHub repo**

Run:

```powershell
gh repo create 3ch0p01nt/portable-ai-skills --public --source . --remote origin --description "Portable technical AI skills for Copilot CLI and compatible skill loaders" --push
```

Expected: repo is created, `origin` is configured, and `main` is pushed.

- [ ] **Step 4: Verify GitHub repository**

Run:

```powershell
gh repo view 3ch0p01nt/portable-ai-skills --json name,url,visibility,defaultBranchRef
gh api repos/3ch0p01nt/portable-ai-skills/contents/.claude-plugin/marketplace.json --jq '.download_url'
gh api repos/3ch0p01nt/portable-ai-skills/contents/skills/kql-m365-azure-hunting/SKILL.md --jq '.download_url'
```

Expected: repo is public, default branch is `main`, marketplace and skill files are accessible.

## Task 5: Post-Push Verification and Handoff

**Files:**
- Read: repository state and GitHub remote state.

- [ ] **Step 1: Verify local clean state and remote tracking**

Run:

```powershell
git status --short
git branch -vv
git remote -v
```

Expected: clean status, `main` tracks `origin/main`, and `origin` points to `https://github.com/3ch0p01nt/portable-ai-skills.git`.

- [ ] **Step 2: Verify public install command**

Run:

```powershell
$readme = gh api repos/3ch0p01nt/portable-ai-skills/contents/README.md --jq '.content' | ForEach-Object {
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
}
if ($readme -notmatch "git clone 'https://github.com/3ch0p01nt/portable-ai-skills.git'") { throw 'README public clone command missing' }
if ($readme -notmatch '/plugin') { throw 'README plugin command guidance missing' }
'Public README install guidance verified'
```

Expected: exits 0 and prints `Public README install guidance verified`.

- [ ] **Step 3: Final report**

Report:

```text
Published: https://github.com/3ch0p01nt/portable-ai-skills
Default branch: main
Initial skill: skills\kql-m365-azure-hunting
Plugin metadata: .claude-plugin\plugin.json and .claude-plugin\marketplace.json
Validation: local and GitHub checks passed
```

## Self-Review

- Spec coverage: Task 1 adds plugin metadata; Task 2 updates README for GPT 5.1/AOAI/Copilot CLI; Task 3 validates local package and secret patterns; Task 4 creates the public repo and pushes `main`; Task 5 verifies public availability.
- Placeholder scan: the only placeholder is the intentional `<skills-directory>` direct-install example in README; it is a user-supplied local path placeholder, not missing implementation detail.
- Scope check: the plan covers upload and organization only; it does not add new skills or change skill behavior.
- Safety check: no AOAI endpoint, tenant ID, key, secret, or deployment-specific value is introduced.
