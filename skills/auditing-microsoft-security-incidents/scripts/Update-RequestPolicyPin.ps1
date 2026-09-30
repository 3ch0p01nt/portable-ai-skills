[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$PolicyPath,

    [string]$GuardPath = (Join-Path $PSScriptRoot 'Test-ReadOnlyRequest.ps1')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$policyBytes = [IO.File]::ReadAllBytes($PolicyPath)
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$policy = $utf8.GetString($policyBytes) | ConvertFrom-Json -Depth 50
if ($policy.policyVersion -isnot [string] -or
    [string]$policy.policyVersion -notmatch '^20[0-9]{2}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$') {
    throw 'Policy version is missing or invalid.'
}

$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $digest = [Convert]::ToHexString($sha256.ComputeHash($policyBytes)).ToLowerInvariant()
}
finally {
    $sha256.Dispose()
}

$guard = [IO.File]::ReadAllText($GuardPath, $utf8)
$versionPattern = '(?m)^\$PinnedPolicyVersion = ''[^'']*''\r?$'
$digestPattern = '(?m)^\$PinnedPolicySha256 = ''[^'']*''\r?$'
if ([regex]::Matches($guard, $versionPattern).Count -ne 1 -or
    [regex]::Matches($guard, $digestPattern).Count -ne 1) {
    throw 'Guard pin declarations are missing or ambiguous.'
}

$updated = [regex]::Replace(
    $guard,
    $versionPattern,
    "`$PinnedPolicyVersion = '$($policy.policyVersion)'"
)
$updated = [regex]::Replace(
    $updated,
    $digestPattern,
    "`$PinnedPolicySha256 = '$digest'"
)

if ($PSCmdlet.ShouldProcess($GuardPath, "pin policy version $($policy.policyVersion) and SHA-256 $digest")) {
    [IO.File]::WriteAllText($GuardPath, $updated, [Text.UTF8Encoding]::new($false))
}

[pscustomobject][ordered]@{
    policyVersion = [string]$policy.policyVersion
    sha256 = $digest
    policyPath = [IO.Path]::GetFullPath($PolicyPath)
    guardPath = [IO.Path]::GetFullPath($GuardPath)
} | ConvertTo-Json -Compress
