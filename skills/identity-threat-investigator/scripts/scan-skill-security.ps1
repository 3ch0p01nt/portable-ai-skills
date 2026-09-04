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
    @{ id = 'instruction-override'; regex = '\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|established)\s+(instructions|rules)\b' },
    @{ id = 'system-prompt-exfiltration'; regex = '\b(reveal|print|show)\s+(the\s+)?(system|hidden|developer)\s+(prompt|instructions)\b' },
    @{ id = 'tool-policy-bypass'; regex = '\b(bypass|disable|override)\s+(tool|safety|approval|permission)\s+(policy|check|gate|rules?)\b' },
    @{ id = 'mcp-tool-escalation'; regex = 'mcp__[a-zA-Z_]+__(shell|execute|run_command|eval|exec)' },
    @{ id = 'jwt-material'; regex = '\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b' },
    @{ id = 'private-key-material'; regex = '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----' }
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
