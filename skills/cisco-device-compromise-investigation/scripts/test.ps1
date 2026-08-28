[CmdletBinding()]
param(
    [ValidateSet('Correctness', 'Safety', 'Evidence', 'Detection', 'Parser', 'Folder', 'All')]
    [string]$Category = 'All',
    [string]$Root
)

$arguments = @(
    (Join-Path $PSScriptRoot 'test_skill.py'),
    '--category',
    $Category.ToLowerInvariant()
)
if ($Root) { $arguments += @('--root', $Root) }
& python @arguments
exit $LASTEXITCODE
