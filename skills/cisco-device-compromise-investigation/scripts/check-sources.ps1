[CmdletBinding()]
param(
    [switch]$Strict,
    [int]$TimeoutSec = 20,
    [string]$Output,
    [string]$Root
)

$arguments = @(
    (Join-Path $PSScriptRoot 'check_sources.py'),
    '--timeout',
    [string]$TimeoutSec
)
if ($Strict) { $arguments += '--strict' }
if ($Output) { $arguments += @('--output', $Output) }
if ($Root) { $arguments += @('--root', $Root) }
& python @arguments
exit $LASTEXITCODE
