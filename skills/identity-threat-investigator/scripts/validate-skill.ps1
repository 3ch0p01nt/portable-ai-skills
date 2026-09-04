[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

$requiredFiles = @(
    'SKILL.md',
    'references\telemetry-and-scope.md',
    'references\baselines-and-deviations.md',
    'references\mfa-token-investigation.md',
    'references\kql-and-response.md',
    'references\sources.json',
    'schemas\investigation.schema.json',
    'rules\redaction-rules.json',
    'evals\evals.json',
    'scripts\scan-skill-security.ps1'
)

foreach ($relative in $requiredFiles) {
    Assert-True (Test-Path -LiteralPath (Join-Path $Root $relative)) "Missing required file: $relative"
}

$skill = Get-Content -Raw -LiteralPath (Join-Path $Root 'SKILL.md')
$frontmatter = [regex]::Match($skill, '(?s)^---\r?\n(.*?)\r?\n---')
Assert-True $frontmatter.Success 'SKILL.md frontmatter is missing or malformed'
Assert-True ($frontmatter.Groups[1].Value -match '(?m)^name:\s*"identity-threat-investigator"\s*$') 'Unexpected skill name'
Assert-True ($frontmatter.Groups[1].Value -match '(?m)^description:\s*".+"\s*$') 'Skill description is missing'
Assert-True (($skill -split "`r?`n").Count -le 300) 'SKILL.md exceeds the 300-line compactness gate'

$evals = Get-Content -Raw -LiteralPath (Join-Path $Root 'evals\evals.json') | ConvertFrom-Json
$sources = Get-Content -Raw -LiteralPath (Join-Path $Root 'references\sources.json') | ConvertFrom-Json
$schema = Get-Content -Raw -LiteralPath (Join-Path $Root 'schemas\investigation.schema.json') | ConvertFrom-Json
$redaction = Get-Content -Raw -LiteralPath (Join-Path $Root 'rules\redaction-rules.json') | ConvertFrom-Json

Assert-True ($evals.cases.Count -ge $evals.quality_gates.minimum_cases) 'Evaluation count is below the quality gate'
$caseIds = @($evals.cases | ForEach-Object { $_.id })
Assert-True (($caseIds | Sort-Object -Unique).Count -eq $caseIds.Count) 'Duplicate evaluation IDs found'

$sourceIds = @($sources.sources | ForEach-Object { $_.id })
Assert-True (($sourceIds | Sort-Object -Unique).Count -eq $sourceIds.Count) 'Duplicate source IDs found'
foreach ($source in $sources.sources) {
    Assert-True ([uri]::IsWellFormedUriString($source.url, [UriKind]::Absolute)) "Invalid source URL: $($source.id)"
    Assert-True $source.url.StartsWith('https://') "Non-HTTPS source URL: $($source.id)"
}

foreach ($case in $evals.cases) {
    foreach ($field in @('id', 'category', 'priority', 'mode', 'source_ids', 'input', 'expected', 'fail_if')) {
        Assert-True ($null -ne $case.$field) "Evaluation $($case.id) missing $field"
    }
    Assert-True ($case.expected.Count -gt 0) "Evaluation $($case.id) has no expected behavior"
    Assert-True ($case.fail_if.Count -gt 0) "Evaluation $($case.id) has no failure condition"
    foreach ($sourceId in $case.source_ids) {
        Assert-True ($sourceId -in $sourceIds) "Evaluation $($case.id) references unknown source $sourceId"
    }
}

foreach ($property in @('case', 'coverage', 'observations', 'hypotheses', 'data_gaps', 'next_steps', 'response_options')) {
    Assert-True ($null -ne $schema.properties.$property) "Investigation schema missing $property"
}
Assert-True ($redaction.rules.Count -ge 8) 'Insufficient redaction rule coverage'

[pscustomobject]@{
    status = 'PASS'
    required_files = $requiredFiles.Count
    eval_cases = $evals.cases.Count
    source_records = $sources.sources.Count
    redaction_rules = $redaction.rules.Count
    skill_lines = ($skill -split "`r?`n").Count
} | ConvertTo-Json
