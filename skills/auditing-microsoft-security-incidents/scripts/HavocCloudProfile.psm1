$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:PinnedCloudProfileCatalogSha256 = '997ddf176158acae9061a8b536fa4da59a59ff75b9436404c8fdefef58c99359'

function Copy-HavocCloudProfileValue {
    param($Value)
    $Value | ConvertTo-Json -Depth 50 -Compress |
        ConvertFrom-Json -Depth 50 -DateKind String
}

function Get-HavocCloudProfileCatalogHash {
    param([Parameter(Mandatory)][string]$ProfilePath)
    (Get-FileHash -Algorithm SHA256 -LiteralPath $ProfilePath).Hash.ToLowerInvariant()
}

function Test-HavocStringSetEqual {
    param($Actual, [string[]]$Expected)
    $actualText = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)
    $expectedText = @($Expected | Sort-Object -CaseSensitive)
    return (($actualText -join "`n") -ceq ($expectedText -join "`n"))
}

function Test-HavocProfileDeniedHostName {
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $normalized = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    if ($normalized -cin @('graph.microsoft.us', 'api.security.microsoft.us')) { return $true }
    if ($normalized.EndsWith('.cn') -or $normalized.EndsWith('.de')) { return $true }
    if ($normalized.EndsWith('.chinacloudapi.cn') -or $normalized.EndsWith('.microsoftazure.de')) { return $true }
    return $false
}

function Get-HavocHostFromProfileValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $candidate = $Value.Trim()
    if ($candidate -match '^[a-z][a-z0-9+.-]*://') {
        try { return ([uri]$candidate).IdnHost.ToLowerInvariant() }
        catch { return '__invalid_uri__' }
    }
    if ($candidate -match '^[0-9a-fA-F-]{36}$') { return $null }
    if ($candidate -match '^[A-Za-z][A-Za-z0-9.-]*$') { return $candidate.ToLowerInvariant() }
    return $null
}

function Assert-HavocProfileNoDeniedCloudValues {
    param($Profile)
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($propertyName in @('authorityHost', 'graphHost', 'armHost', 'logAnalyticsHost')) {
        $values.Add([string]$Profile.$propertyName)
    }
    foreach ($item in @($Profile.graphAudiences)) { $values.Add([string]$item) }
    foreach ($item in @($Profile.armAudiences)) { $values.Add([string]$item) }
    $values.Add([string]$Profile.logAnalyticsAudience)
    foreach ($item in @($Profile.graphScopes)) { $values.Add([string]$item) }
    foreach ($item in @($Profile.allowedIssuerPrefixes)) { $values.Add([string]$item) }
    foreach ($item in @($Profile.allowedIssuerTemplates)) { $values.Add(([string]$item).Replace('{tenantId}', '00000000-0000-4000-8000-000000000099')) }
    foreach ($property in @($Profile.requestScopes.PSObject.Properties)) { $values.Add([string]$property.Value) }
    if ($null -ne $Profile.resourceGraph) {
        $values.Add([string]$Profile.resourceGraph.host)
        $values.Add([string]$Profile.resourceGraph.audience)
    }
    if ($null -ne $Profile.purview) {
        $values.Add([string]$Profile.purview.host)
        $values.Add([string]$Profile.purview.audience)
    }
    foreach ($value in $values) {
        $hostName = Get-HavocHostFromProfileValue $value
        if (Test-HavocProfileDeniedHostName $hostName) {
            throw "HAVOC cloud profile '$($Profile.name)' includes a denied cloud endpoint."
        }
    }
}

function Assert-HavocExactCloudProfile {
    param($Profile)
    $expected = @{
        Commercial = [ordered]@{
            azEnvironment = 'AzureCloud'
            authorityHost = 'https://login.microsoftonline.com/'
            allowedIssuerPrefixes = @('https://login.microsoftonline.com/', 'https://sts.windows.net/')
            allowedIssuerTemplates = @('https://login.microsoftonline.com/{tenantId}/v2.0', 'https://sts.windows.net/{tenantId}/')
            graphHost = 'graph.microsoft.com'
            graphAudiences = @('https://graph.microsoft.com')
            graphScopes = @('https://graph.microsoft.com/SecurityIncident.Read.All', 'https://graph.microsoft.com/SecurityAlert.Read.All')
            armHost = 'management.azure.com'
            armAudiences = @('https://management.azure.com/')
            logAnalyticsHost = 'api.loganalytics.azure.com'
            logAnalyticsAudience = 'https://api.loganalytics.io'
            requestScopes = [ordered]@{
                graphSecurityIncidentRead = 'SecurityIncident.Read.All'
                graphSecurityAlertRead = 'SecurityIncident.Read.All'
                graphDirectoryRead = 'Directory.Read.All'
                graphApplicationRead = 'Application.Read.All'
                armDefault = 'https://management.azure.com/.default'
                logAnalyticsDefault = 'https://api.loganalytics.io/.default'
                purviewAuditRead = 'AuditLogsQuery-Entra.Read.All'
            }
            resourceGraphEnabled = $true
            resourceGraphHost = 'management.azure.com'
            resourceGraphAudience = 'https://management.azure.com/'
            purviewEnabled = $true
            purviewHost = 'graph.microsoft.com'
            purviewAudience = 'https://graph.microsoft.com'
            expectedCoverageGaps = @()
            allAllowedHosts = @('api.loganalytics.azure.com', 'api.security.microsoft.com', 'graph.microsoft.com', 'management.azure.com')
        }
        USGovDoD = [ordered]@{
            azEnvironment = 'AzureUSGovernment'
            authorityHost = 'https://login.microsoftonline.us/'
            allowedIssuerPrefixes = @('https://login.microsoftonline.us/', 'https://sts.windows.net/')
            allowedIssuerTemplates = @('https://login.microsoftonline.us/{tenantId}/v2.0', 'https://sts.windows.net/{tenantId}/')
            graphHost = 'dod-graph.microsoft.us'
            graphAudiences = @('https://dod-graph.microsoft.us', '00000003-0000-0000-c000-000000000000')
            graphScopes = @('https://dod-graph.microsoft.us/SecurityIncident.Read.All', 'https://dod-graph.microsoft.us/SecurityAlert.Read.All')
            armHost = 'management.usgovcloudapi.net'
            armAudiences = @('https://management.usgovcloudapi.net/', 'https://management.core.usgovcloudapi.net/')
            logAnalyticsHost = 'api.loganalytics.us'
            logAnalyticsAudience = 'https://api.loganalytics.us'
            requestScopes = [ordered]@{
                graphSecurityIncidentRead = 'https://dod-graph.microsoft.us/SecurityIncident.Read.All'
                graphSecurityAlertRead = 'https://dod-graph.microsoft.us/SecurityIncident.Read.All'
                graphDirectoryRead = 'https://dod-graph.microsoft.us/Directory.Read.All'
                graphApplicationRead = 'https://dod-graph.microsoft.us/Application.Read.All'
                armDefault = 'https://management.usgovcloudapi.net/.default'
                logAnalyticsDefault = 'https://api.loganalytics.us/.default'
                purviewAuditRead = 'disabled'
            }
            resourceGraphEnabled = $false
            resourceGraphHost = $null
            resourceGraphAudience = $null
            purviewEnabled = $false
            purviewHost = $null
            purviewAudience = $null
            expectedCoverageGaps = @('purview_unconfirmed_in_cloud', 'resource_graph_unconfirmed_in_cloud', 'sentinel_to_defender_portal_onboarding_dependency')
            allAllowedHosts = @('api.loganalytics.us', 'dod-graph.microsoft.us', 'management.usgovcloudapi.net')
        }
    }
    if (-not $expected.ContainsKey([string]$Profile.name)) {
        throw "Unknown HAVOC cloud profile '$($Profile.name)'."
    }
    $e = $expected[[string]$Profile.name]
    foreach ($scalarName in @('azEnvironment', 'authorityHost', 'graphHost', 'armHost', 'logAnalyticsHost', 'logAnalyticsAudience')) {
        if ([string]$Profile.$scalarName -cne [string]$e[$scalarName]) {
            throw "HAVOC cloud profile '$($Profile.name)' does not match the pinned expected values."
        }
    }
    foreach ($arrayName in @('allowedIssuerPrefixes', 'allowedIssuerTemplates', 'graphAudiences', 'graphScopes', 'armAudiences', 'expectedCoverageGaps')) {
        if (-not (Test-HavocStringSetEqual $Profile.$arrayName ([string[]]$e[$arrayName]))) {
            throw "HAVOC cloud profile '$($Profile.name)' does not match the pinned expected values."
        }
    }
    foreach ($scopeName in @($e.requestScopes.Keys)) {
        if ($Profile.requestScopes.PSObject.Properties.Name -cnotcontains $scopeName -or
            [string]$Profile.requestScopes.$scopeName -cne [string]$e.requestScopes[$scopeName]) {
            throw "HAVOC cloud profile '$($Profile.name)' does not match the pinned expected values."
        }
    }
    if (@($Profile.requestScopes.PSObject.Properties.Name).Count -ne @($e.requestScopes.Keys).Count) {
        throw "HAVOC cloud profile '$($Profile.name)' does not match the pinned expected values."
    }
    if ([bool]$Profile.resourceGraph.enabled -ne [bool]$e.resourceGraphEnabled -or
        [string]$Profile.resourceGraph.host -cne [string]$e.resourceGraphHost -or
        [string]$Profile.resourceGraph.audience -cne [string]$e.resourceGraphAudience -or
        [bool]$Profile.purview.enabled -ne [bool]$e.purviewEnabled -or
        [string]$Profile.purview.host -cne [string]$e.purviewHost -or
        [string]$Profile.purview.audience -cne [string]$e.purviewAudience) {
        throw "HAVOC cloud profile '$($Profile.name)' does not match the pinned expected values."
    }
    if ($Profile.PSObject.Properties.Name -ccontains 'allAllowedHosts' -and
        -not (Test-HavocStringSetEqual $Profile.allAllowedHosts ([string[]]$e.allAllowedHosts))) {
        throw "HAVOC cloud profile '$($Profile.name)' does not match the pinned expected values."
    }
}

function Assert-HavocPolicyProfilePin {
    param(
        [string]$PolicyPath,
        [string]$Cloud,
        [string]$CatalogHash
    )
    if ([string]::IsNullOrWhiteSpace($PolicyPath) -or
        -not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
        throw 'HAVOC cloud profile catalog pin policy is unavailable.'
    }
    $policy = Get-Content -LiteralPath $PolicyPath -Raw |
        ConvertFrom-Json -Depth 100 -DateKind String
    if ($policy.PSObject.Properties.Name -cnotcontains 'cloudProfiles') {
        throw 'HAVOC cloud profile catalog pin is missing.'
    }
    $entry = @($policy.cloudProfiles | Where-Object { [string]$_.name -ceq $Cloud })
    if ($entry.Count -ne 1 -or
        $entry[0].PSObject.Properties.Name -cnotcontains 'profileCatalogSha256' -or
        [string]$entry[0].profileCatalogSha256 -cne $CatalogHash) {
        throw 'HAVOC cloud profile catalog pin does not match the selected profile.'
    }
    if ($Cloud -ceq 'Commercial' -and
        -not (Test-HavocStringSetEqual $policy.canonicalHosts @(
            'api.loganalytics.azure.com',
            'api.security.microsoft.com',
            'graph.microsoft.com',
            'management.azure.com'
        ))) {
        throw 'HAVOC commercial cloud profile hosts do not match the pinned canonical hosts.'
    }
}

function Get-HavocCloudProfile {
    [CmdletBinding()]
    param(
        [string]$Cloud = 'Commercial',
        [string]$ProfilePath = (Join-Path $PSScriptRoot '..\references\cloud-profiles.json'),
        [string]$PolicyPath = (Join-Path $PSScriptRoot '..\references\request-policy.json')
    )

    if ([string]::IsNullOrWhiteSpace($Cloud)) {
        throw 'Unknown HAVOC cloud profile.'
    }
    if ($Cloud -cnotin @('Commercial', 'USGovDoD')) {
        throw "Unknown HAVOC cloud profile '$Cloud'."
    }
    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
        throw 'HAVOC cloud profile catalog is unavailable.'
    }
    $catalogHash = Get-HavocCloudProfileCatalogHash -ProfilePath $ProfilePath
    if ($catalogHash -cne $script:PinnedCloudProfileCatalogSha256) {
        throw 'HAVOC cloud profile catalog pin mismatch.'
    }
    Assert-HavocPolicyProfilePin -PolicyPath $PolicyPath -Cloud $Cloud -CatalogHash $catalogHash

    $catalog = Get-Content -LiteralPath $ProfilePath -Raw |
        ConvertFrom-Json -Depth 50 -DateKind String
    if ($catalog.schemaVersion -isnot [string] -or
        [string]$catalog.schemaVersion -cne '1.0.0' -or
        $catalog.PSObject.Properties.Name -cnotcontains 'profiles') {
        throw 'HAVOC cloud profile catalog is invalid.'
    }
    $matches = @($catalog.profiles | Where-Object {
        $_.PSObject.Properties.Name -ccontains 'name' -and
        [string]$_.name -ceq $Cloud
    })
    if ($matches.Count -ne 1) {
        throw "Unknown HAVOC cloud profile '$Cloud'."
    }
    $profile = Copy-HavocCloudProfileValue $matches[0]
    $required = @(
        'name', 'azEnvironment', 'authorityHost', 'allowedIssuerPrefixes',
        'allowedIssuerTemplates', 'graphHost', 'graphAudiences', 'graphScopes',
        'armHost', 'armAudiences', 'logAnalyticsHost', 'logAnalyticsAudience',
        'requestScopes', 'resourceGraph', 'purview', 'expectedCoverageGaps'
    )
    $names = @($profile.PSObject.Properties.Name)
    if (@($required | Where-Object { $names -cnotcontains $_ }).Count -gt 0 -or
        @($names | Where-Object { $required -cnotcontains $_ }).Count -gt 0) {
        throw "HAVOC cloud profile '$Cloud' is invalid."
    }
    Assert-HavocProfileNoDeniedCloudValues -Profile $profile
    Assert-HavocExactCloudProfile -Profile $profile

    $allowedHosts = [System.Collections.Generic.List[string]]::new()
    foreach ($allowedHost in @(
        [string]$profile.graphHost,
        [string]$profile.armHost,
        [string]$profile.logAnalyticsHost
    )) {
        if (-not [string]::IsNullOrWhiteSpace($allowedHost) -and
            -not $allowedHosts.Contains($allowedHost)) {
            $allowedHosts.Add($allowedHost)
        }
    }
    if ([string]$profile.name -ceq 'Commercial' -and
        -not $allowedHosts.Contains('api.security.microsoft.com')) {
        $allowedHosts.Add('api.security.microsoft.com')
    }
    if ($profile.resourceGraph.enabled -eq $true -and
        -not [string]::IsNullOrWhiteSpace([string]$profile.resourceGraph.host) -and
        -not $allowedHosts.Contains([string]$profile.resourceGraph.host)) {
        $allowedHosts.Add([string]$profile.resourceGraph.host)
    }
    if ($profile.purview.enabled -eq $true -and
        -not [string]::IsNullOrWhiteSpace([string]$profile.purview.host) -and
        -not $allowedHosts.Contains([string]$profile.purview.host)) {
        $allowedHosts.Add([string]$profile.purview.host)
    }
    $profile | Add-Member -Force -NotePropertyName allAllowedHosts `
        -NotePropertyValue @($allowedHosts | Sort-Object -CaseSensitive)
    Assert-HavocExactCloudProfile -Profile $profile
    $profile | Add-Member -Force -NotePropertyName profileCatalogSha256 `
        -NotePropertyValue $catalogHash
    $profile
}

Export-ModuleMember -Function Get-HavocCloudProfile
