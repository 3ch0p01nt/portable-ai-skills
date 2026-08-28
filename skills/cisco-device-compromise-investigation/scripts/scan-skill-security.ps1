[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$files = @(
    (Join-Path $Root 'SKILL.md')
) + @(
    Get-ChildItem -LiteralPath (Join-Path $Root 'references') -File -Filter '*.md' |
        ForEach-Object { $_.FullName }
)

$patterns = @(
    @{
        id = 'persona-identity-override'
        regex = '\b(you are now|pretend you are|forget you are|your new identity|your real purpose)\b'
    },
    @{
        id = 'mcp-tool-escalation'
        regex = 'mcp__[a-zA-Z_]+__(shell|execute|run_command|eval|exec)'
    },
    @{
        id = 'embedded-live-credential'
        regex = '(?im)^\s*(?:password|secret|community|pre-shared-key)\s+[^\[<\s]\S+'
    }
)

$findings = @()
foreach ($file in $files) {
    $text = Get-Content -Raw -LiteralPath $file
    foreach ($pattern in $patterns) {
        if ($text -match $pattern.regex) {
            $findings += [pscustomobject]@{
                file = $file.Substring($Root.Length + 1)
                rule = $pattern.id
            }
        }
    }
}

if ($findings.Count -gt 0) {
    $findings | ConvertTo-Json -Depth 3
    exit 1
}

[pscustomobject]@{
    status = 'PASS'
    files_scanned = $files.Count
    findings = 0
} | ConvertTo-Json
