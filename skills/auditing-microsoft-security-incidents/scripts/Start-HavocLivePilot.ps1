<#
.SYNOPSIS
Starts the HAVOC Microsoft Incident Auditor live commercial read-only pilot.

.DESCRIPTION
This wrapper performs no tenant writes. It verifies the caller is already signed
in with Az.Accounts to AzureCloud for the requested tenant, builds the live
transport/auth/provenance providers, prints a pre-flight summary, and delegates
all approved read-only work to Invoke-HavocIncidentAudit.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z')]
    [string]$IncidentId,

    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z')]
    [string]$TenantId,

    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z')]
    [string]$WorkspaceId,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z')]
    [string]$SubscriptionId,

    [ValidatePattern('^(?![.])(?!.*[.]\z)[A-Za-z0-9._()\-]{1,90}\z')]
    [string]$ResourceGroupName,

    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9-]{2,61}[A-Za-z0-9])\z')]
    [string]$WorkspaceName,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z')]
    [string]$SentinelIncidentId,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z')]
    [string]$AnalyticsRuleId,

    [Parameter(Mandatory)][datetimeoffset]$StartTime,
    [Parameter(Mandatory)][datetimeoffset]$EndTime,

    [Parameter(Mandatory)][string]$OutputDirectory,

    [ValidateSet('Commercial', 'USGovDoD')]
    [string]$Cloud = 'Commercial',

    [Parameter(Mandatory)][switch]$ConfirmReadOnlyPilot,

    [switch]$AttestSentinelWorkspaceCoverage,

    [switch]$AllowGraphUnavailable,

    [scriptblock]$Sleeper = { param($Seconds) Start-Sleep -Seconds $Seconds },
    [scriptblock]$Clock = { [datetimeoffset]::UtcNow }
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot 'HavocLiveTransport.psm1'
Import-Module $modulePath -Global
Import-Module (Join-Path $PSScriptRoot 'HavocCloudProfile.psm1') -Force

function ConvertTo-HavocMaskedValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'unknown' }
    $prefixLength = [Math]::Min(4, $Value.Length)
    "$($Value.Substring(0, $prefixLength))..."
}

$profile = Get-HavocCloudProfile -Cloud $Cloud
$context = Get-HavocLiveAzContextSummary -TenantId $TenantId -Cloud $Cloud
$operations = @(
    'Microsoft Graph security incident with alerts (GET)',
    'Log Analytics SecurityIncident query (POST)',
    'Log Analytics SecurityAlert query (POST)'
)
if ($SubscriptionId -and $ResourceGroupName -and $WorkspaceName -and $SentinelIncidentId) {
    $operations += 'Azure Resource Manager Sentinel incident read (GET)'
    if ($AnalyticsRuleId) {
        $operations += 'Azure Resource Manager analytics rule read (GET)'
    }
}

Write-Host 'HAVOC live read-only pilot pre-flight summary'
Write-Host "Cloud profile: $($profile.name)"
Write-Host "Authority host: $($profile.authorityHost)"
Write-Host "Graph host: $($profile.graphHost)"
Write-Host "ARM host: $($profile.armHost)"
Write-Host "Log Analytics host: $($profile.logAnalyticsHost)"
if (@($profile.expectedCoverageGaps).Count -gt 0) {
    Write-Host 'Expected coverage gaps:'
    foreach ($gap in @($profile.expectedCoverageGaps)) {
        Write-Host " - $gap"
    }
}
Write-Host "Tenant: $(ConvertTo-HavocMaskedValue $context.TenantId)"
Write-Host "Account: $(ConvertTo-HavocMaskedValue $context.Account)"
Write-Host "Environment: $($context.Environment)"
Write-Host "WorkspaceId: $WorkspaceId"
if ($WorkspaceName) {
    Write-Host "WorkspaceName: $WorkspaceName"
}
Write-Host "Window: $($StartTime.ToUniversalTime().ToString('o')) to $($EndTime.ToUniversalTime().ToString('o'))"
Write-Host 'Operations:'
foreach ($operation in $operations) {
    Write-Host " - $operation"
}

function New-HavocPilotKeyBase64 {
    $bytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    try {
        [Convert]::ToBase64String($bytes)
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Add-HavocLivePilotLimitation {
    param(
        [Parameter(Mandatory)]$Bundle,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string[]]$Limitations
    )

    $deduped = @($Limitations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($deduped.Count -eq 0) {
        return $Bundle
    }

    if ($Bundle.PSObject.Properties.Name -contains 'livePilotLimitations') {
        $existing = @($Bundle.livePilotLimitations | ForEach-Object { [string]$_ })
        $Bundle.livePilotLimitations = @($existing + $deduped | Sort-Object -Unique)
    }
    else {
        $Bundle | Add-Member -NotePropertyName livePilotLimitations -NotePropertyValue $deduped
    }

    $reportJsonPath = Join-Path $OutputDirectory 'report.json'
    if (Test-Path -LiteralPath $reportJsonPath) {
        $Bundle | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $reportJsonPath -Encoding utf8
    }

    $markdownPath = Join-Path $OutputDirectory 'report.md'
    if (Test-Path -LiteralPath $markdownPath) {
        $lines = @('', '## Live pilot limitations')
        foreach ($limitation in $deduped) {
            $lines += "- $limitation"
        }
        Add-Content -LiteralPath $markdownPath -Value $lines -Encoding utf8
    }

    return $Bundle
}

if (-not $ConfirmReadOnlyPilot) {
    throw 'ConfirmReadOnlyPilot is required to proceed with the HAVOC live read-only pilot.'
}

$savedEnvironment = @{
    Signing = [Environment]::GetEnvironmentVariable('HAVOC_CAPABILITY_SIGNING_KEY', 'Process')
    Verification = [Environment]::GetEnvironmentVariable('HAVOC_CAPABILITY_VERIFICATION_KEY', 'Process')
    Resource = [Environment]::GetEnvironmentVariable('HAVOC_RESOURCE_BINDING_KEY', 'Process')
}

try {
    if ([string]::IsNullOrWhiteSpace($savedEnvironment.Signing) -or
        [string]::IsNullOrWhiteSpace($savedEnvironment.Verification)) {
        $capabilityKey = New-HavocPilotKeyBase64
        [Environment]::SetEnvironmentVariable('HAVOC_CAPABILITY_SIGNING_KEY', $capabilityKey, 'Process')
        [Environment]::SetEnvironmentVariable('HAVOC_CAPABILITY_VERIFICATION_KEY', $capabilityKey, 'Process')
    }
    if ([string]::IsNullOrWhiteSpace($savedEnvironment.Resource)) {
        [Environment]::SetEnvironmentVariable('HAVOC_RESOURCE_BINDING_KEY', (New-HavocPilotKeyBase64), 'Process')
    }

    $tokenCache = @{}
    $transport = New-HavocLiveTransport -TenantId $TenantId -Cloud $Cloud -TokenCache $tokenCache
    $authProvider = New-HavocAzAuthContextProvider -TenantId $TenantId -Cloud $Cloud -TokenCache $tokenCache
    $provenanceProvider = New-HavocLiveProvenanceContextProvider -AttestSentinelWorkspaceCoverage:$AttestSentinelWorkspaceCoverage
    $runner = Join-Path $PSScriptRoot 'Invoke-HavocIncidentAudit.ps1'

    Write-Host 'Graph sign-in notice: This tool never requests admin consent.'
    Write-Host "Do not click 'Consent on behalf of your organization'. If consent is not already granted, cancel and rerun with -AllowGraphUnavailable."
    $authPreflight = Get-HavocLiveAuthPreflight -TenantId $TenantId -Cloud $Cloud -TokenCache $tokenCache -AuthContextProvider $authProvider
    foreach ($summary in @($authPreflight.token_summaries)) {
        $permissions = @($summary.permissions | ForEach-Object { [string]$_ })
        $permissionText = if ($permissions.Count -gt 0) { $permissions -join ', ' } else { 'none' }
        Write-Host "$($summary.resource) token audience: $($summary.audience)"
        Write-Host "Token issuer: $($summary.issuer)"
        Write-Host "Token tenant: $($summary.tenant)"
        Write-Host "Token permissions: $permissionText"
        Write-Host "Token expires: $($summary.expires_at)"
    }
    $graphScopes = @($authPreflight.graph_scopes | ForEach-Object { [string]$_ })
    $excessGraphScopes = @($authPreflight.graph_excess_scopes | ForEach-Object { [string]$_ })
    $graphPreflightError = [string]$authPreflight.graph_error
    if ($graphScopes.Count -gt 0) {
        Write-Host "Graph scopes found: $($graphScopes -join ', ')"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($graphPreflightError)) {
        Write-Host "Graph scopes found: unavailable ($graphPreflightError)"
    }
    else {
        Write-Host 'Graph scopes found: none'
    }
    if (-not [string]::IsNullOrWhiteSpace($graphPreflightError)) {
        if (-not $AllowGraphUnavailable) {
            throw $graphPreflightError
        }
        Write-Host 'Expected gap: Microsoft Graph source will be recorded as a coverage gap because Graph token acquisition is unavailable'
    }
    if ($excessGraphScopes.Count -gt 0) {
        Write-Host "Graph excess privilege scopes: $($excessGraphScopes -join ', ')"
        throw "Graph token contains excess privilege scopes: $($excessGraphScopes -join ', '). Use a least-privilege account for the live pilot."
    }
    else {
        Write-Host 'Graph excess privilege scopes: none detected'
    }
    if ($AttestSentinelWorkspaceCoverage) {
        Write-Host 'Sentinel workspace coverage attestation: supplied by operator; Sentinel onboarding and connector health were operator-attested, not verified'
    }
    else {
        Write-Host 'Sentinel workspace coverage attestation: not supplied'
        Write-Host 'Expected gap: Sentinel ARM reads will be recorded as coverage gaps'
    }
    Write-Host 'Expected gap: RBAC excess privilege not verifiable from token'

    $runnerParameters = @{
        IncidentId = $IncidentId
        TenantId = $TenantId
        WorkspaceId = $WorkspaceId
        StartTime = $StartTime
        EndTime = $EndTime
        OutputDirectory = $OutputDirectory
        Transport = $transport
        AuthContextProvider = $authProvider
        ProvenanceContextProvider = $provenanceProvider
        Sleeper = $Sleeper
        Clock = $Clock
    }
    if ($SubscriptionId) { $runnerParameters.SubscriptionId = $SubscriptionId }
    if ($ResourceGroupName) { $runnerParameters.ResourceGroupName = $ResourceGroupName }
    if ($WorkspaceName) { $runnerParameters.WorkspaceName = $WorkspaceName }
    if ($SentinelIncidentId) { $runnerParameters.SentinelIncidentId = $SentinelIncidentId }
    if ($AnalyticsRuleId) { $runnerParameters.AnalyticsRuleId = $AnalyticsRuleId }
    $runnerParameters.Cloud = $Cloud

    $bundle = & $runner @runnerParameters
    $liveLimitations = @('RBAC excess privilege not verifiable from token')
    foreach ($gap in @($profile.expectedCoverageGaps)) {
        $liveLimitations += "Cloud profile expected coverage gap: $gap"
    }
    if (-not [string]::IsNullOrWhiteSpace($graphPreflightError) -and $AllowGraphUnavailable) {
        $liveLimitations += 'Microsoft Graph pre-flight token acquisition unavailable; Graph source recorded as coverage gap'
    }
    if ($AttestSentinelWorkspaceCoverage) {
        $liveLimitations += 'Sentinel onboarding and connector health were operator-attested, not verified'
    }
    Add-HavocLivePilotLimitation -Bundle $bundle -OutputDirectory $OutputDirectory -Limitations $liveLimitations
}
finally {
    [Environment]::SetEnvironmentVariable('HAVOC_CAPABILITY_SIGNING_KEY', $savedEnvironment.Signing, 'Process')
    [Environment]::SetEnvironmentVariable('HAVOC_CAPABILITY_VERIFICATION_KEY', $savedEnvironment.Verification, 'Process')
    [Environment]::SetEnvironmentVariable('HAVOC_RESOURCE_BINDING_KEY', $savedEnvironment.Resource, 'Process')
}
