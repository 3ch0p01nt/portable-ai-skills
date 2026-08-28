[CmdletBinding()]
param(
    [string]$Root
)

$arguments = @((Join-Path $PSScriptRoot 'validate_skill.py'))
if ($Root) { $arguments += @('--root', $Root) }
& python @arguments
exit $LASTEXITCODE
