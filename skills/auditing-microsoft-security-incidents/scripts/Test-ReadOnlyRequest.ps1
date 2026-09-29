[CmdletBinding()]
param(
    [string]$IntentJson,

    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\references\request-policy.json'),

    [string]$CapabilityJson,

    [string]$CapabilityPath,

    [switch]$StdinEnvelope,

    [ValidateSet('Commercial', 'USGovDoD')]
    [string]$Cloud = 'Commercial',

    [datetimeoffset]$CurrentTime
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$GuardCurrentTime = if ($PSBoundParameters.ContainsKey('CurrentTime')) {
    $CurrentTime.ToUniversalTime()
}
else { [datetimeoffset]::UtcNow }

if ($StdinEnvelope) {
    try {
        $stdinText = [Console]::In.ReadToEnd()
        $ipc = $stdinText | ConvertFrom-Json -Depth 100 -DateKind String
        $ipcNames = @($ipc.PSObject.Properties.Name | Sort-Object)
        if (($ipcNames -join ',') -cne
                'capabilities,intent,policyPath,version' -or
            [string]$ipc.version -cne '1.0.0' -or
            $null -eq $ipc.intent -or
            $null -eq $ipc.PSObject.Properties['capabilities'] -or
            [string]::IsNullOrWhiteSpace([string]$ipc.policyPath)) {
            throw 'Invalid guard IPC envelope'
        }
        $IntentJson = ConvertTo-Json -InputObject $ipc.intent -Depth 50 -Compress
        $PolicyPath = [string]$ipc.policyPath
        $CapabilityJson = if (@($ipc.capabilities).Count -gt 0) {
            @($ipc.capabilities) | ConvertTo-Json -Depth 50 -Compress -AsArray
        }
        else { $null }
        $CapabilityPath = $null
    }
    catch {
        [pscustomobject][ordered]@{
            allowed = $false
            ruleId = 'DENY-GUARD-IPC'
            reasonCode = 'guard_ipc_invalid'
            semanticClass = 'invalid'
        } | ConvertTo-Json -Depth 10 -Compress
        return
    }
}
elseif ([string]::IsNullOrWhiteSpace($IntentJson)) {
    throw 'Intent input is required'
}

$PinnedPolicyVersion = '2026-09-28.1'
$PinnedPolicySha256 = '28702b07cb98377b75ce83ee0c4969407debe83daf88047788f936ddc439ac4e'
$SafeRedirectPolicy = 'manual-reauthorization-required;automatic-follow-disabled;cross-origin-authorization-forwarding-disabled'

$cloudProfileModulePath = Join-Path $PSScriptRoot 'HavocCloudProfile.psm1'
if (-not (Test-Path -LiteralPath $cloudProfileModulePath -PathType Leaf)) {
    $cloudProfileModulePath = Join-Path $PSScriptRoot '..\skills\auditing-microsoft-security-incidents\scripts\HavocCloudProfile.psm1'
}
Import-Module $cloudProfileModulePath -Force
$script:HavocCloudProfile = Get-HavocCloudProfile -Cloud $Cloud

function Get-SafeIdentifier {
    param($Value)
    if ($null -ne $Value -and [string]$Value -match '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        return [string]$Value
    }
    return $null
}

function Get-StringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        $text = [string]$item
        if ($seen.Add($text)) {
            $result.Add($text)
        }
    }
    return @($result | Sort-Object -CaseSensitive)
}

function Get-ScopeAudit {
    param($Intent, $Policy)
    $requested = @(Get-StringArray $Intent.requestedScopes)
    $recognized = [System.Collections.Generic.List[string]]::new()
    $known = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($operation in @($Policy.operations)) {
        foreach ($scope in @($operation.requiredRequestedScopes)) {
            $known[[string]$scope] = [string]$scope
        }
    }
    foreach ($scope in $requested) {
        if ($known.ContainsKey($scope) -and $recognized -cnotcontains $known[$scope]) {
            $recognized.Add($known[$scope])
        }
    }
    [pscustomobject][ordered]@{
        ids = @($recognized | Sort-Object)
        count = $recognized.Count
        redactedCount = $requested.Count - $recognized.Count
    }
}

function New-Decision {
    param(
        [bool]$Allowed,
        [string]$RuleId,
        [string]$ReasonCode,
        $Canonical,
        [string]$SemanticClass,
        $Intent,
        $Policy
    )
    $target = $null
    if ($null -ne $Canonical -and $Canonical.Valid) {
        $target = $Canonical.NormalizedTarget
    }
    [pscustomobject][ordered]@{
        allowed = $Allowed
        ruleId = $RuleId
        reasonCode = $ReasonCode
        normalizedTarget = $target
        semanticClass = $SemanticClass
        requestedScopes = Get-ScopeAudit $Intent $Policy
        selectedCloud = [string]$script:HavocCloudProfile.name
        correlation = [pscustomobject][ordered]@{
            requestId = Get-SafeIdentifier $Intent.requestId
            correlationId = Get-SafeIdentifier $Intent.correlationId
            operationId = Get-SafeIdentifier $Intent.operationId
        }
        policyVersion = [string]$Policy.policyVersion
        redirectPolicy = [string]$Policy.redirectPolicy
    }
}

function New-PolicyInvalidDecision {
    [pscustomobject][ordered]@{
        allowed = $false
        ruleId = 'DENY-POLICY'
        reasonCode = 'policy_invalid'
        normalizedTarget = $null
        semanticClass = 'unknown'
        requestedScopes = [pscustomobject][ordered]@{
            ids = @()
            count = 0
            redactedCount = 0
        }
        correlation = [pscustomobject][ordered]@{
            requestId = $null
            correlationId = $null
            operationId = $null
        }
        policyVersion = $PinnedPolicyVersion
        redirectPolicy = $SafeRedirectPolicy
    }
}

function Test-MalformedPercentEncoding {
    param([string]$Value)
    return $Value -match '%(?![0-9A-Fa-f]{2})'
}

function ConvertFrom-QueryComponent {
    param([string]$Value)
    if ($Value.Contains('+')) {
        throw 'Ambiguous plus encoding'
    }
    return [uri]::UnescapeDataString($Value)
}

function Resolve-CanonicalUri {
    param([string]$RawUri, $Policy)

    $invalid = {
        param([string]$Reason)
        [pscustomobject]@{ Valid = $false; Reason = $Reason; NormalizedTarget = $null }
    }

    if ([string]::IsNullOrWhiteSpace($RawUri) -or $RawUri -ne $RawUri.Trim()) {
        return & $invalid 'invalid_uri'
    }
    if (-not $RawUri.IsNormalized([Text.NormalizationForm]::FormC)) {
        return & $invalid 'ambiguous_unicode'
    }
    if ($RawUri.Contains('\')) {
        return & $invalid 'invalid_uri'
    }
    if ($RawUri.Contains('#')) {
        return & $invalid 'fragment_denied'
    }
    if ($RawUri -notmatch '^(?<scheme>[^:]+)://(?<authority>[^/?#]+)(?<rest>.*)$') {
        return & $invalid 'invalid_uri'
    }

    $authority = $Matches.authority
    $rawRest = $Matches.rest
    if ($authority.Contains('@')) {
        return & $invalid 'userinfo_denied'
    }
    $hostPort = $authority
    if ($hostPort.StartsWith('[')) {
        return & $invalid 'ip_literal_denied'
    }
    $rawHost = ($hostPort -split ':', 2)[0]
    if ($rawHost.EndsWith('.') -or $rawHost.Contains('..') -or $rawHost.Contains('%')) {
        return & $invalid 'ambiguous_host'
    }
    if (Test-MalformedPercentEncoding $RawUri) {
        return & $invalid 'invalid_percent_encoding'
    }

    $rawPath = ($rawRest -split '[?#]', 2)[0]
    if ($rawPath -match '(?i)%25') {
        return & $invalid 'double_encoding'
    }
    if ($rawPath -match '(?i)%(2f|5c)') {
        return & $invalid 'encoded_path_separator'
    }
    $decodedPath = [uri]::UnescapeDataString($rawPath)
    if ($decodedPath -match '(^|/)\.{1,2}(/|$)') {
        return & $invalid 'path_traversal'
    }
    if ($decodedPath -match '[^\x20-\x7E]') {
        return & $invalid 'ambiguous_unicode'
    }

    $parsed = $null
    if (-not [uri]::TryCreate($RawUri, [UriKind]::Absolute, [ref]$parsed)) {
        return & $invalid 'invalid_uri'
    }
    if ($parsed.Scheme.ToLowerInvariant() -ne 'https') {
        return & $invalid 'scheme_not_allowed'
    }
    if (-not [string]::IsNullOrEmpty($parsed.UserInfo)) {
        return & $invalid 'userinfo_denied'
    }
    if (-not $parsed.IsDefaultPort) {
        return & $invalid 'non_default_port_denied'
    }

    $address = $null
    if ([Net.IPAddress]::TryParse($parsed.Host, [ref]$address)) {
        return & $invalid 'ip_literal_denied'
    }
    $canonicalHost = $parsed.IdnHost.ToLowerInvariant()
    if (@($Policy.canonicalHosts) -cnotcontains $canonicalHost) {
        return & $invalid 'host_not_allowed'
    }

    $path = [uri]::UnescapeDataString($parsed.AbsolutePath)
    if ($path.Length -gt 1 -and $path.EndsWith('/')) {
        return & $invalid 'trailing_slash_not_allowed'
    }

    $query = [ordered]@{}
    if (-not [string]::IsNullOrEmpty($parsed.Query)) {
        $rawQuery = $parsed.Query.Substring(1)
        if ($rawQuery -match '(?i)%25') {
            return & $invalid 'double_encoding'
        }
        foreach ($pair in $rawQuery -split '&') {
            if ([string]::IsNullOrEmpty($pair)) {
                return & $invalid 'invalid_query'
            }
            $parts = $pair -split '=', 2
            $policy = $null
            try {
                $key = ConvertFrom-QueryComponent $parts[0]
                $value = if ($parts.Count -eq 2) { ConvertFrom-QueryComponent $parts[1] } else { '' }
            }
            catch {
                return & $invalid 'invalid_query'
            }
            if ($query.Contains($key)) {
                return & $invalid 'duplicate_query_key'
            }
            $query[$key] = $value
        }
    }

    $normalizedTarget = "https://$canonicalHost$path"
    $queryKeys = @($query.Keys | Sort-Object)
    return [pscustomobject]@{
        Valid = $true
        Reason = $null
        Host = $canonicalHost
        Path = $path
        Query = $query
        QueryKeys = $queryKeys
        Origin = "https://$canonicalHost"
        NormalizedTarget = $normalizedTarget
    }
}

function Set-SafeQueryProjection {
    param($Canonical, $Operation)

    $allowedKeys = if ($null -eq $Operation) { @() } else { @($Operation.allowedQueryKeys) }
    $projected = [System.Collections.Generic.List[string]]::new()
    [int]$unknownCount = 0
    foreach ($key in @($Canonical.QueryKeys)) {
        if ($allowedKeys -ccontains [string]$key) {
            $projected.Add([string]$key)
        }
        else {
            $unknownCount++
        }
    }
    if ($unknownCount -gt 0) {
        $projected.Add("unknown-query-keys=$unknownCount")
    }
    $Canonical.NormalizedTarget = "https://$($Canonical.Host)$($Canonical.Path)"
    if ($projected.Count -gt 0) {
        $Canonical.NormalizedTarget += '?' + ($projected -join '&')
    }
}

function ConvertTo-BodyObject {
    param($Body)
    if ($null -eq $Body) {
        return [pscustomobject]@{ Valid = $false; Value = $null }
    }
    if ($Body -is [string]) {
        try {
            return [pscustomobject]@{
                Valid = $true
                Value = ($Body | ConvertFrom-Json -Depth 30 -DateKind String)
            }
        }
        catch {
            return [pscustomobject]@{ Valid = $false; Value = $null }
        }
    }
    return [pscustomobject]@{ Valid = $true; Value = $Body }
}

function Copy-JsonValue {
    param($Value)
    return $Value | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json -Depth 50 -DateKind String
}

function Test-ExactProperties {
    param($Object, [string[]]$Allowed, [string[]]$Required)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [System.Collections.IEnumerable] -and $Object -isnot [pscustomobject]) {
        return $false
    }
    $names = @($Object.PSObject.Properties.Name)
    foreach ($name in $names) {
        if ($Allowed -cnotcontains $name) { return $false }
    }
    foreach ($name in $Required) {
        if ($names -cnotcontains $name) { return $false }
    }
    return $true
}

function Get-RedirectContextError {
    param($Redirect, $Policy)

    if ($null -eq $Redirect -or
        $Redirect -is [string] -or
        ($Redirect -is [System.Collections.IEnumerable] -and $Redirect -isnot [pscustomobject])) {
        return 'redirect_context_shape_not_allowed'
    }
    $names = @($Redirect.PSObject.Properties.Name)
    if ($names -cnotcontains 'separatelyAuthorized') {
        return 'separate_authorization_required'
    }
    if (-not (Test-ExactProperties $Redirect @(
        'separatelyAuthorized',
        'originalOrigin',
        'forwardAuthorization'
    ) @(
        'separatelyAuthorized',
        'originalOrigin',
        'forwardAuthorization'
    ))) {
        return 'redirect_context_shape_not_allowed'
    }
    if ($Redirect.separatelyAuthorized -isnot [bool] -or
        $Redirect.separatelyAuthorized -ne $true) {
        return 'separate_authorization_required'
    }
    if ($Redirect.forwardAuthorization -isnot [bool] -or
        $Redirect.originalOrigin -isnot [string]) {
        return 'redirect_context_shape_not_allowed'
    }

    $origin = $null
    if (-not [uri]::TryCreate(
        [string]$Redirect.originalOrigin,
        [UriKind]::Absolute,
        [ref]$origin
    ) -or
        $origin.Scheme -cne 'https' -or
        -not $origin.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($origin.UserInfo) -or
        $origin.AbsolutePath -cne '/' -or
        -not [string]::IsNullOrEmpty($origin.Query) -or
        -not [string]::IsNullOrEmpty($origin.Fragment) -or
        @($Policy.canonicalHosts) -cnotcontains $origin.IdnHost.ToLowerInvariant() -or
        [string]$Redirect.originalOrigin -cne "https://$($origin.IdnHost.ToLowerInvariant())") {
        return 'redirect_context_shape_not_allowed'
    }
    return $null
}

function Get-Operation {
    param($Intent, $Canonical, $Policy)
    $operationId = [string]$Intent.operationId
    foreach ($operation in $Policy.operations) {
        if ([string]$operation.operationId -cne $operationId) { continue }
        if ([string]$operation.host -cne $Canonical.Host) { continue }
        if ([string]$operation.method -cne ([string]$Intent.method).ToUpperInvariant()) { continue }
        if ($operation.PSObject.Properties.Name -contains 'path') {
            if ([string]$operation.path -cne $Canonical.Path) { continue }
        }
        else {
            if ($Canonical.Path -cnotmatch [string]$operation.pathPattern) { continue }
        }
        if (@($Canonical.QueryKeys | Where-Object {
            @($operation.allowedQueryKeys) -cnotcontains [string]$_ -and
            -not (
                [string]$operation.host -ceq [string]$Policy.effectiveGraphHost -and
                [string]$operation.method -ceq 'GET' -and
                ([string]$_ -ceq '$skiptoken' -or [string]$_ -ceq '$skipToken')
            )
        }).Count -gt 0) { continue }
        if ($operation.PSObject.Properties.Name -contains 'fixedQueryValues') {
            $fixedMatch = $true
            foreach ($property in @($operation.fixedQueryValues.PSObject.Properties)) {
                if (-not $Canonical.Query.Contains($property.Name) -or
                    @($property.Value) -cnotcontains [string]$Canonical.Query[$property.Name]) {
                    $fixedMatch = $false
                    break
                }
            }
            if (-not $fixedMatch) { continue }
        }
        return $operation
    }
    return $null
}

function Test-Permissions {
    param($Intent, $Operation, $Policy)
    $requested = @(Get-StringArray $Intent.requestedScopes)
    $tokenPermissions = @(Get-StringArray @(
        @(Get-StringArray $Intent.tokenScopes)
        @(Get-StringArray $Intent.tokenRoles)
    ))

    $credentialClass = if ($Intent.PSObject.Properties.Name -ccontains
        'credentialClass') {
        [string]$Intent.credentialClass
    }
    else { 'delegated' }
    $armRbacReadApproved = $Intent.PSObject.Properties.Name -ccontains
        'armRbacReadApproved' -and $Intent.armRbacReadApproved -eq $true
    if ([string]$Operation.host -ceq [string]$Policy.effectiveArmHost -and
        $credentialClass -ceq 'application' -and
        $armRbacReadApproved) {
        if ($tokenPermissions.Count -ne 0) {
            return 'permission_not_allowed'
        }
        foreach ($required in @($Operation.requiredRequestedScopes)) {
            if ($requested -cnotcontains [string]$required) {
                return 'minimum_permission_missing'
            }
        }
        return $null
    }

    if ([string]$Operation.operationId -like 'purview-audit-query-*') {
        if ([string]$Operation.operationId -ceq 'purview-audit-query-create') {
            $bodyResult = ConvertTo-BodyObject $Intent.body
            if (-not $bodyResult.Valid) {
                return 'purview_workload_permission_mismatch'
            }
            $bodyProperties = @($bodyResult.Value.PSObject.Properties.Name)
            if ($bodyProperties -ccontains 'serviceFilters') {
                return $null
            }
            if ($bodyProperties -cnotcontains 'serviceFilter' -or
                $bodyResult.Value.serviceFilter -isnot [string]) {
                return 'purview_workload_permission_mismatch'
            }
            $services = @([string]$bodyResult.Value.serviceFilter)
            $workloadScopes = [ordered]@{
                AzureActiveDirectory = 'AuditLogsQuery-Entra.Read.All'
                Exchange = 'AuditLogsQuery-Exchange.Read.All'
                OneDrive = 'AuditLogsQuery-OneDrive.Read.All'
                SharePoint = 'AuditLogsQuery-SharePoint.Read.All'
            }
            if ($services.Count -lt 1 -or
                @($services | Where-Object {
                    $_ -isnot [string] -or
                    $workloadScopes.Keys -cnotcontains [string]$_
                }).Count -gt 0 -or
                @($services | Select-Object -Unique).Count -ne $services.Count) {
                return 'purview_workload_permission_mismatch'
            }
            $requiredWorkloadScopes = @($services | ForEach-Object {
                [string]$workloadScopes[[string]$_]
            } | Sort-Object -CaseSensitive)
            if ((@($requested | Sort-Object -CaseSensitive) -join "`n") -cne
                    ($requiredWorkloadScopes -join "`n") -or
                (@($tokenPermissions | Sort-Object -CaseSensitive) -join "`n") -cne
                    ($requiredWorkloadScopes -join "`n")) {
                return 'purview_workload_permission_mismatch'
            }
            return $null
        }
        if ($requested.Count -lt 1 -or
            (@($requested | Sort-Object -CaseSensitive) -join "`n") -cne
                (@($tokenPermissions | Sort-Object -CaseSensitive) -join "`n")) {
            return 'purview_workload_permission_mismatch'
        }
        foreach ($permission in $requested) {
            if (@($Operation.allowedRequestedScopes) -cnotcontains $permission) {
                return 'purview_workload_permission_mismatch'
            }
        }
        return $null
    }

    foreach ($permission in $requested) {
        if (@($Operation.allowedRequestedScopes) -cnotcontains $permission) {
            return 'permission_not_allowed'
        }
    }
    foreach ($permission in $tokenPermissions) {
        if (@($Operation.allowedTokenPermissions) -cnotcontains $permission) {
            return 'permission_not_allowed'
        }
    }
    foreach ($required in @($Operation.requiredRequestedScopes)) {
        if ($requested -cnotcontains [string]$required) {
            return 'minimum_permission_missing'
        }
    }
    foreach ($required in @($Operation.requiredTokenPermissions)) {
        if ($tokenPermissions -cnotcontains [string]$required) {
            return 'minimum_permission_missing'
        }
    }
    return $null
}

function ConvertTo-DateTimeOffset {
    param($Value)
    $text = [string]$Value
    if ($Value -isnot [string] -or
        $text -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$') {
        throw 'Timestamp must be an RFC3339 instant with Z or an explicit offset'
    }
    $instant = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParseExact(
        $text,
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$instant
    )) {
        throw 'Invalid RFC3339 instant'
    }
    return $instant
}

function Test-IntegerValue {
    param($Value)
    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
}

function Test-PolicyString {
    param($Value, [string]$Pattern = $null)
    if ($Value -isnot [string] -or [string]::IsNullOrEmpty([string]$Value)) {
        return $false
    }
    return $null -eq $Pattern -or [string]$Value -cmatch $Pattern
}

function Test-ProtectedReference {
    param($Value, [string[]]$AllowedPrefixes)
    if ($Value -isnot [string] -or
        [string]$Value -cnotmatch
            '^([a-z][a-z-]*):[a-z0-9][a-z0-9._/-]*$') {
        return $false
    }
    $prefix = ([string]$Value -split ':', 2)[0]
    return $AllowedPrefixes -ccontains $prefix
}

function Test-PolicyStringArray {
    param(
        $Value,
        [bool]$AllowEmpty = $false,
        [string]$Pattern = $null
    )
    if ($Value -is [string] -or
        $Value -isnot [System.Collections.IEnumerable] -or
        $Value -is [pscustomobject]) {
        return $false
    }
    $items = @($Value)
    if (-not $AllowEmpty -and $items.Count -lt 1) {
        return $false
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $items) {
        if (-not (Test-PolicyString $item $Pattern) -or -not $seen.Add([string]$item)) {
            return $false
        }
    }
    return $true
}

function Test-PositivePolicyInteger {
    param($Value)
    return (Test-IntegerValue $Value) -and [long]$Value -gt 0
}

function Test-NonNegativePolicyInteger {
    param($Value)
    return (Test-IntegerValue $Value) -and [long]$Value -ge 0
}

function Test-PolicyCapability {
    param($Capability)
    return (Test-ExactProperties $Capability @('enabled', 'reason') @('enabled', 'reason')) -and
        $Capability.enabled -is [bool] -and
        (Test-PolicyString $Capability.reason)
}

function Get-HavocProfileHostForPolicyHost {
    param([string]$PolicyHost)
    switch ($PolicyHost) {
        'graph.microsoft.com' { [string]$script:HavocCloudProfile.graphHost }
        'management.azure.com' { [string]$script:HavocCloudProfile.armHost }
        'api.loganalytics.azure.com' { [string]$script:HavocCloudProfile.logAnalyticsHost }
        'api.loganalytics.io' { [string]$script:HavocCloudProfile.logAnalyticsHost }
        default { $PolicyHost }
    }
}

function Get-HavocProfileRequestedScopesForOperation {
    param($Operation)
    if ([string]$script:HavocCloudProfile.name -ceq 'Commercial') {
        return $null
    }
    $scopes = $script:HavocCloudProfile.requestScopes
    $hostName = [string]$Operation.host
    if ($hostName -ceq 'graph.microsoft.com') {
        $mapped = [System.Collections.Generic.List[string]]::new()
        foreach ($scope in @($Operation.allowedRequestedScopes)) {
            switch ([string]$scope) {
                'SecurityIncident.Read.All' { $mapped.Add([string]$scopes.graphSecurityIncidentRead) }
                'Directory.Read.All' { $mapped.Add([string]$scopes.graphDirectoryRead) }
                'Application.Read.All' { $mapped.Add([string]$scopes.graphApplicationRead) }
                default { }
            }
        }
        return @($mapped | Sort-Object -Unique)
    }
    if ($hostName -ceq 'management.azure.com') {
        return @([string]$scopes.armDefault)
    }
    if ($hostName -in @('api.loganalytics.azure.com', 'api.loganalytics.io')) {
        return @([string]$scopes.logAnalyticsDefault)
    }
    return $null
}

function ConvertTo-HavocProfilePolicy {
    param($Policy)
    $profilePolicy = Copy-JsonValue $Policy
    $profilePolicy.canonicalHosts = @($script:HavocCloudProfile.allAllowedHosts)
    $profilePolicy | Add-Member -Force -NotePropertyName effectiveGraphHost `
        -NotePropertyValue ([string]$script:HavocCloudProfile.graphHost)
    $profilePolicy | Add-Member -Force -NotePropertyName effectiveArmHost `
        -NotePropertyValue ([string]$script:HavocCloudProfile.armHost)
    $profilePolicy | Add-Member -Force -NotePropertyName effectiveLogAnalyticsHost `
        -NotePropertyValue ([string]$script:HavocCloudProfile.logAnalyticsHost)
    $profilePolicy | Add-Member -Force -NotePropertyName selectedCloud `
        -NotePropertyValue ([string]$script:HavocCloudProfile.name)

    $operations = [System.Collections.Generic.List[object]]::new()
    foreach ($operation in @($profilePolicy.operations)) {
        if ($script:HavocCloudProfile.resourceGraph.enabled -ne $true -and
            [string]$operation.operationId -ceq 'azure-resource-graph-query') {
            continue
        }
        if ($script:HavocCloudProfile.purview.enabled -ne $true -and
            [string]$operation.operationId -like 'purview-*') {
            continue
        }
        $profileScopes = Get-HavocProfileRequestedScopesForOperation $operation
        $mappedHost = Get-HavocProfileHostForPolicyHost ([string]$operation.host)
        $operation.host = $mappedHost
        if ($null -ne $profileScopes) {
            $operation.requiredRequestedScopes = @($profileScopes)
            $operation.allowedRequestedScopes = @($profileScopes)
        }
        $operations.Add($operation)
    }
    $profilePolicy.operations = @($operations)
    $profilePolicy
}

function Test-RequestPolicy {
    param($Policy)

    $rootProperties = @(
        'allowedTimespanFormats',
        'capabilityTrust',
        'canonicalHosts',
        'cloud',
        'cloudProfiles',
        'conditionalCapabilities',
        'crossResourceFunctions',
        'globalBounds',
        'knownMutationPathPatterns',
        'odata',
        'operations',
        'policyVersion',
        'redirectPolicy',
        'responseAdapterCapabilities',
        'schemaVersion'
    )
    if (-not (Test-ExactProperties $Policy $rootProperties $rootProperties)) {
        return $false
    }
    if ($Policy.schemaVersion -isnot [string] -or [string]$Policy.schemaVersion -cne '1.0' -or
        $Policy.policyVersion -isnot [string] -or [string]$Policy.policyVersion -cne $PinnedPolicyVersion -or
        $Policy.cloud -isnot [string] -or [string]$Policy.cloud -cne 'commercial' -or
        -not (Test-PolicyString $Policy.redirectPolicy)) {
        return $false
    }

    if (-not (Test-PolicyStringArray $Policy.canonicalHosts $false '^[a-z0-9.-]+\.com$')) {
        return $false
    }
    if ($Policy.cloudProfiles -is [string] -or
        $Policy.cloudProfiles -isnot [System.Collections.IEnumerable] -or
        (@($Policy.cloudProfiles).Count -ne 2)) {
        return $false
    }
    $profileNames = [System.Collections.Generic.List[string]]::new()
    foreach ($profileRef in @($Policy.cloudProfiles)) {
        if (-not (Test-ExactProperties $profileRef @('name', 'profileReference', 'profileCatalogSha256', 'requestScopes') @('name', 'profileReference', 'profileCatalogSha256', 'requestScopes')) -or
            -not (Test-PolicyString $profileRef.name '^(Commercial|USGovDoD)$') -or
            -not (Test-PolicyString $profileRef.profileReference '^cloud-profiles\.json#/profiles/(Commercial|USGovDoD)$') -or
            -not (Test-PolicyString $profileRef.profileCatalogSha256 '^[a-f0-9]{64}$') -or
            [string]$profileRef.profileCatalogSha256 -cne [string]$script:HavocCloudProfile.profileCatalogSha256) {
            return $false
        }
        if ($profileRef.requestScopes.PSObject.Properties.Name.Count -ne 7) { return $false }
        foreach ($requiredScopeName in @('graphSecurityIncidentRead', 'graphSecurityAlertRead', 'graphDirectoryRead', 'graphApplicationRead', 'armDefault', 'logAnalyticsDefault', 'purviewAuditRead')) {
            if ($profileRef.requestScopes.PSObject.Properties.Name -cnotcontains $requiredScopeName -or
                -not (Test-PolicyString $profileRef.requestScopes.$requiredScopeName)) {
                return $false
            }
        }
        $profileNames.Add([string]$profileRef.name)
    }
    $profileNames = @($profileNames | Sort-Object -CaseSensitive)
    if (($profileNames -join ',') -cne 'Commercial,USGovDoD') {
        return $false
    }
    $hosts = @($Policy.canonicalHosts)

    $boundNames = @(
        'maxBatchRequests',
        'maxBytes',
        'maxRows',
        'maxRuntimeSeconds',
        'maxSubscriptions',
        'maxTimeRangeDays',
        'maxWorkspaces'
    )
    if (-not (Test-ExactProperties $Policy.globalBounds $boundNames $boundNames)) {
        return $false
    }
    foreach ($name in $boundNames) {
        if (-not (Test-PositivePolicyInteger $Policy.globalBounds.$name)) {
            return $false
        }
    }

    if (-not (Test-PolicyStringArray $Policy.allowedTimespanFormats) -or
        @($Policy.allowedTimespanFormats).Count -ne 1 -or
        [string]$Policy.allowedTimespanFormats[0] -cne 'start/end') {
        return $false
    }
    $requiredCrossResourceFunctions = @(
        'adx', 'app', 'arg', 'cluster', 'database', 'externaldata', 'resource', 'workspace'
    )
    if (-not (Test-PolicyStringArray $Policy.crossResourceFunctions) -or
        (@($Policy.crossResourceFunctions) -join "`n") -cne ($requiredCrossResourceFunctions -join "`n")) {
        return $false
    }

    if (-not (Test-PolicyStringArray $Policy.knownMutationPathPatterns)) {
        return $false
    }
    foreach ($pattern in @($Policy.knownMutationPathPatterns)) {
        if (-not ([string]$pattern).StartsWith('^') -or -not ([string]$pattern).EndsWith('$')) {
            return $false
        }
        try {
            [void][regex]::new([string]$pattern)
        }
        catch {
            return $false
        }
    }

    $conditionalNames = @('defenderLegacyHunting', 'graphSecurityHunting')
    if (-not (Test-ExactProperties $Policy.conditionalCapabilities $conditionalNames $conditionalNames)) {
        return $false
    }
    foreach ($name in $conditionalNames) {
        if (-not (Test-PolicyCapability $Policy.conditionalCapabilities.$name)) {
            return $false
        }
    }

    $odataNames = @('allowedFields', 'allowedOperators', 'builderRequired', 'maxLiteralLength')
    if (-not (Test-ExactProperties $Policy.odata $odataNames $odataNames) -or
        $Policy.odata.builderRequired -isnot [bool] -or
        $Policy.odata.builderRequired -ne $true -or
        -not (Test-PositivePolicyInteger $Policy.odata.maxLiteralLength) -or
        -not (Test-PolicyStringArray $Policy.odata.allowedOperators)) {
        return $false
    }
    $allowedODataOperators = @('eq', 'ne', 'ge', 'gt', 'le', 'lt')
    foreach ($operator in @($Policy.odata.allowedOperators)) {
        if ($allowedODataOperators -cnotcontains [string]$operator) {
            return $false
        }
    }
    if ($null -eq $Policy.odata.allowedFields -or
        @($Policy.odata.allowedFields.PSObject.Properties).Count -lt 1) {
        return $false
    }
    foreach ($property in @($Policy.odata.allowedFields.PSObject.Properties)) {
        if (-not (Test-PolicyString $property.Name '^[A-Za-z][A-Za-z0-9]*$') -or
            -not (Test-PolicyStringArray $property.Value)) {
            return $false
        }
        foreach ($type in @($property.Value)) {
            if (@('string', 'datetime') -cnotcontains [string]$type) {
                return $false
            }
        }
    }

    if ($Policy.responseAdapterCapabilities -is [string] -or
        $Policy.responseAdapterCapabilities -isnot [System.Collections.IEnumerable] -or
        @($Policy.responseAdapterCapabilities).Count -lt 1) {
        return $false
    }
    $adapterIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($adapter in @($Policy.responseAdapterCapabilities)) {
        if (-not (Test-ExactProperties $adapter @('adapterId', 'adapterVersion') @('adapterId', 'adapterVersion')) -or
            -not (Test-PolicyString $adapter.adapterId '^[a-z][a-z0-9-]{2,127}$') -or
            -not (Test-PolicyString $adapter.adapterVersion '^[0-9]+\.[0-9]+\.[0-9]+$') -or
            -not $adapterIds.Add("$($adapter.adapterId)`n$($adapter.adapterVersion)")) {
            return $false
        }
    }

    $capabilityTrustNames = @('issuers', 'maxClockSkewSeconds', 'maxLifetimeSeconds')
    if (-not (Test-ExactProperties $Policy.capabilityTrust $capabilityTrustNames $capabilityTrustNames) -or
        -not (Test-PositivePolicyInteger $Policy.capabilityTrust.maxLifetimeSeconds) -or
        [long]$Policy.capabilityTrust.maxLifetimeSeconds -gt 900 -or
        -not (Test-NonNegativePolicyInteger $Policy.capabilityTrust.maxClockSkewSeconds) -or
        [long]$Policy.capabilityTrust.maxClockSkewSeconds -gt 60 -or
        $Policy.capabilityTrust.issuers -is [string] -or
        $Policy.capabilityTrust.issuers -isnot [System.Collections.IEnumerable] -or
        @($Policy.capabilityTrust.issuers).Count -lt 1) {
        return $false
    }
    $issuerIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($issuer in @($Policy.capabilityTrust.issuers)) {
        if (-not (Test-ExactProperties $issuer @('issuerId', 'issuerVersion', 'keyId') @('issuerId', 'issuerVersion', 'keyId')) -or
            -not (Test-PolicyString $issuer.issuerId '^[a-z][a-z0-9-]{2,127}$') -or
            -not (Test-PolicyString $issuer.issuerVersion '^[0-9]+\.[0-9]+\.[0-9]+$') -or
            -not (Test-PolicyString $issuer.keyId '^[a-z][a-z0-9-]{2,127}$') -or
            -not $issuerIdentities.Add("$($issuer.issuerId)`n$($issuer.issuerVersion)`n$($issuer.keyId)")) {
            return $false
        }
    }

    if ($Policy.operations -is [string] -or
        $Policy.operations -isnot [System.Collections.IEnumerable] -or
        @($Policy.operations).Count -lt 1) {
        return $false
    }
    $operationIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $ruleIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $operationTargets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $operationProperties = @(
        'allowedApiVersions',
        'allowedBodyProperties',
        'allowedQueryKeys',
        'allowedRequestedScopes',
        'allowedTokenPermissions',
        'apiVersionPolicy',
        'bodyValidator',
        'conditionalCapability',
        'estimatedBytesPerRow',
        'fixedQueryValues',
        'hardSafeResponseBytes',
        'host',
        'maxRows',
        'method',
        'operationId',
        'path',
        'pathPattern',
        'preview',
        'requireTop',
        'requiredPreconditions',
        'requiredRequestedScopes',
        'requiredTokenPermissions',
        'responseEnforcementRequired',
        'retryableTransportExceptions',
        'ruleId',
        'safeSemantics',
        'sourceRefs',
        'semanticClass'
    )
    $requiredOperationProperties = @(
        'allowedQueryKeys',
        'allowedRequestedScopes',
        'allowedTokenPermissions',
        'host',
        'maxRows',
        'method',
        'operationId',
        'requiredRequestedScopes',
        'requiredTokenPermissions',
        'ruleId',
        'semanticClass'
    )
    $bodyValidators = @(
        'genericBoundedQuery',
        'graphBatch',
        'emptyBody',
        'graphHuntingQuery',
        'logAnalyticsQuery',
        'purviewRetrievalJob',
        'resourceGraphQuery',
        'sentinelIncidentEntities'
    )
    foreach ($operation in @($Policy.operations)) {
        if (-not (Test-ExactProperties $operation $operationProperties $requiredOperationProperties) -or
            -not (Test-PolicyString $operation.operationId '^[a-z][a-z0-9-]{2,127}$') -or
            -not $operationIds.Add([string]$operation.operationId) -or
            -not (Test-PolicyString $operation.ruleId '^ALLOW-[A-Z0-9-]+$') -or
            -not $ruleIds.Add([string]$operation.ruleId) -or
            $operation.host -isnot [string] -or $hosts -cnotcontains [string]$operation.host -or
            @('GET', 'POST') -cnotcontains [string]$operation.method -or
            @('read', 'read_batch', 'read_query', 'retrieval_job_state') -cnotcontains [string]$operation.semanticClass -or
            -not (Test-PositivePolicyInteger $operation.maxRows)) {
            return $false
        }
        $hasPath = $operation.PSObject.Properties.Name -ccontains 'path'
        $hasPattern = $operation.PSObject.Properties.Name -ccontains 'pathPattern'
        if ($hasPath -eq $hasPattern) {
            return $false
        }
        if ($hasPath) {
            if ($operation.path -isnot [string] -or -not ([string]$operation.path).StartsWith('/')) {
                return $false
            }
            $targetIdentity = "$($operation.host)`n$($operation.method)`npath`n$($operation.path)`n$($operation.operationId)"
        }
        else {
            if ($operation.pathPattern -isnot [string] -or
                -not ([string]$operation.pathPattern).StartsWith('^') -or
                -not ([string]$operation.pathPattern).EndsWith('$')) {
                return $false
            }
            try {
                [void][regex]::new([string]$operation.pathPattern)
            }
            catch {
                return $false
            }
            $targetIdentity = "$($operation.host)`n$($operation.method)`npattern`n$($operation.pathPattern)`n$($operation.operationId)"
        }
        if (-not $operationTargets.Add($targetIdentity)) {
            return $false
        }

        foreach ($name in @(
            'allowedRequestedScopes',
            'allowedTokenPermissions',
            'requiredRequestedScopes',
            'requiredTokenPermissions'
        )) {
            $allowEmpty = $name -in @(
                'requiredRequestedScopes', 'requiredTokenPermissions'
            )
            if (-not (Test-PolicyStringArray $operation.$name $allowEmpty)) {
                return $false
            }
        }
        foreach ($required in @($operation.requiredRequestedScopes)) {
            if (@($operation.allowedRequestedScopes) -cnotcontains [string]$required) {
                return $false
            }
        }
        foreach ($required in @($operation.requiredTokenPermissions)) {
            if (@($operation.allowedTokenPermissions) -cnotcontains [string]$required) {
                return $false
            }
        }
        if (-not (Test-PolicyStringArray $operation.allowedQueryKeys $true '^(?:\$[A-Za-z]+|api-version)$')) {
            return $false
        }
        if ($operation.PSObject.Properties.Name -ccontains 'retryableTransportExceptions' -and
            $operation.retryableTransportExceptions -isnot [bool]) {
            return $false
        }
        if ($operation.PSObject.Properties.Name -ccontains 'conditionalCapability' -and
            @('graphSecurityHunting', 'defenderLegacyHunting') -cnotcontains
                [string]$operation.conditionalCapability) {
            return $false
        }
        if ($operation.PSObject.Properties.Name -ccontains 'preview' -and
            $operation.preview -isnot [bool]) {
            return $false
        }
        if ($operation.PSObject.Properties.Name -ccontains 'sourceRefs' -and
            -not (Test-PolicyStringArray $operation.sourceRefs)) {
            return $false
        }

        foreach ($name in @('allowedApiVersions', 'allowedBodyProperties', 'requiredPreconditions')) {
            if ($operation.PSObject.Properties.Name -ccontains $name -and
                -not (Test-PolicyStringArray $operation.$name `
                    ($name -ceq 'allowedBodyProperties'))) {
                return $false
            }
        }
        if ($operation.PSObject.Properties.Name -ccontains 'requireTop' -and
            $operation.requireTop -isnot [bool]) {
            return $false
        }
        foreach ($name in @('estimatedBytesPerRow', 'hardSafeResponseBytes')) {
            if ($operation.PSObject.Properties.Name -ccontains $name -and
                -not (Test-PositivePolicyInteger $operation.$name)) {
                return $false
            }
        }
        if ([string]$operation.method -ceq 'GET' -and
            $operation.PSObject.Properties.Name -cnotcontains 'estimatedBytesPerRow' -and
            $operation.PSObject.Properties.Name -cnotcontains 'hardSafeResponseBytes') {
            return $false
        }
        if ($operation.PSObject.Properties.Name -ccontains 'apiVersionPolicy') {
            $apiVersionPolicy = $operation.apiVersionPolicy
            if (-not (Test-ExactProperties $apiVersionPolicy @('allowedValues', 'location') @('allowedValues', 'location')) -or
                @('path', 'query') -cnotcontains [string]$apiVersionPolicy.location -or
                -not (Test-PolicyStringArray $apiVersionPolicy.allowedValues)) {
                return $false
            }
        }
        if ($operation.PSObject.Properties.Name -ccontains 'fixedQueryValues') {
            if ($null -eq $operation.fixedQueryValues -or
                @($operation.fixedQueryValues.PSObject.Properties).Count -lt 1) {
                return $false
            }
            foreach ($property in @($operation.fixedQueryValues.PSObject.Properties)) {
                if (@($operation.allowedQueryKeys) -cnotcontains $property.Name -or
                    -not (Test-PolicyStringArray $property.Value)) {
                    return $false
                }
            }
        }
        if ([string]$operation.method -ceq 'POST') {
            if ($operation.PSObject.Properties.Name -cnotcontains 'bodyValidator' -or
                $operation.bodyValidator -isnot [string] -or
                $bodyValidators -cnotcontains [string]$operation.bodyValidator) {
                return $false
            }
        }
        elseif ($operation.PSObject.Properties.Name -ccontains 'bodyValidator') {
            return $false
        }
        if ($operation.PSObject.Properties.Name -ccontains 'responseEnforcementRequired' -and
            $operation.responseEnforcementRequired -isnot [bool]) {
            return $false
        }
        if ([string]$operation.method -ceq 'POST' -and [string]$operation.semanticClass -ceq 'read_query') {
            if ($operation.PSObject.Properties.Name -cnotcontains 'responseEnforcementRequired' -or
                $operation.responseEnforcementRequired -ne $true) {
                return $false
            }
        }
        if ([string]$operation.operationId -ceq 'purview-audit-query-create') {
            $purviewPreconditions = @(
                'operationalNecessityVerified',
                'lifecycleVerified',
                'persistenceVerified',
                'visibilitySharingVerified',
                'retentionExpiryVerified',
                'sideEffectsVerified',
                'leastPrivilegeVerified',
                'boundedRequestVerified',
                'commercialEndpointVerified',
                'reportDisclosurePlanned'
            )
            if ((@($operation.requiredPreconditions) -join "`n") -cne ($purviewPreconditions -join "`n")) {
                return $false
            }
        }
    }
    return $true
}

function Test-Bounds {
    param($Intent, $Operation, $Policy)
    if ($null -eq $Intent.bounds) { return 'bounds_missing' }
    try {
        $start = ConvertTo-DateTimeOffset $Intent.bounds.startTime
        $end = ConvertTo-DateTimeOffset $Intent.bounds.endTime
    }
    catch {
        return 'invalid_time_bound'
    }
    if ($end -le $start -or ($end - $start).TotalDays -gt [double]$Policy.globalBounds.maxTimeRangeDays) {
        return 'time_bound_exceeded'
    }
    if (-not (Test-IntegerValue $Intent.bounds.maxRows)) {
        return 'row_bound_exceeded'
    }
    $maxRows = [long]$Intent.bounds.maxRows
    $operationMaxRows = [Math]::Min([long]$Policy.globalBounds.maxRows, [long]$Operation.maxRows)
    if ($maxRows -lt 1 -or $maxRows -gt $operationMaxRows) {
        return 'row_bound_exceeded'
    }
    if (-not (Test-IntegerValue $Intent.bounds.maxBytes)) {
        return 'cost_bound_exceeded'
    }
    $maxBytes = [long]$Intent.bounds.maxBytes
    if ($maxBytes -lt 1 -or $maxBytes -gt [long]$Policy.globalBounds.maxBytes) {
        return 'cost_bound_exceeded'
    }
    if (-not (Test-IntegerValue $Intent.bounds.maxRuntimeSeconds)) {
        return 'runtime_bound_exceeded'
    }
    $runtime = [long]$Intent.bounds.maxRuntimeSeconds
    if ($runtime -lt 1 -or $runtime -gt [long]$Policy.globalBounds.maxRuntimeSeconds) {
        return 'runtime_bound_exceeded'
    }
    return $null
}

function Test-BodyTimeRange {
    param(
        $BodyStart,
        $BodyEnd,
        $Bounds
    )
    try {
        $authorizedStart = ConvertTo-DateTimeOffset $Bounds.startTime
        $authorizedEnd = ConvertTo-DateTimeOffset $Bounds.endTime
        $requestStart = ConvertTo-DateTimeOffset $BodyStart
        $requestEnd = ConvertTo-DateTimeOffset $BodyEnd
    }
    catch {
        return $false
    }
    return $requestStart -ge $authorizedStart -and $requestEnd -le $authorizedEnd -and $requestEnd -gt $requestStart
}

function ConvertFrom-KqlEscape {
    param([string]$Query, [ref]$Index, [Text.StringBuilder]$Value)

    $Index.Value++
    if ($Index.Value -ge $Query.Length) {
        return $false
    }
    $escape = $Query[$Index.Value]
    $simpleEscapes = @{
        "'" = "'"
        '"' = '"'
        '\' = '\'
        'a' = [char]7
        'b' = [char]8
        'f' = [char]12
        'n' = "`n"
        'r' = "`r"
        't' = "`t"
        'v' = [char]11
    }
    if ($simpleEscapes.ContainsKey([string]$escape)) {
        [void]$Value.Append($simpleEscapes[[string]$escape])
        $Index.Value++
        return $true
    }

    $digits = switch ($escape) {
        'x' { 2 }
        'u' { 4 }
        'U' { 8 }
        default { return $false }
    }
    $hexStart = $Index.Value + 1
    if ($hexStart + $digits -gt $Query.Length) {
        return $false
    }
    $hex = $Query.Substring($hexStart, $digits)
    if ($hex -notmatch "^[0-9A-Fa-f]{$digits}$") {
        return $false
    }
    try {
        $codePoint = [Convert]::ToInt32($hex, 16)
        [void]$Value.Append([char]::ConvertFromUtf32($codePoint))
    }
    catch {
        return $false
    }
    $Index.Value = $hexStart + $digits
    return $true
}

function Get-KqlLexicalAnalysis {
    param([string]$Query)

    $tokens = [System.Collections.Generic.List[object]]::new()
    $segment = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $Query.Length;) {
        $character = $Query[$index]
        $next = if ($index + 1 -lt $Query.Length) { $Query[$index + 1] } else { [char]0 }

        if ([char]::IsWhiteSpace($character)) {
            [void]$segment.Append($character)
            $index++
            continue
        }
        if ($character -eq '/' -and $next -eq '/') {
            $index += 2
            while ($index -lt $Query.Length -and $Query[$index] -ne "`r" -and $Query[$index] -ne "`n") {
                $index++
            }
            [void]$segment.Append(' ')
            continue
        }
        if ($character -eq '/' -and $next -eq '*') {
            $index += 2
            $terminated = $false
            while ($index + 1 -lt $Query.Length) {
                if ($Query[$index] -eq '*' -and $Query[$index + 1] -eq '/') {
                    $index += 2
                    $terminated = $true
                    break
                }
                $index++
            }
            if (-not $terminated) {
                return [pscustomobject]@{ Valid = $false; Tokens = @(); FinalSegment = $null }
            }
            [void]$segment.Append(' ')
            continue
        }
        if ($character -eq [char]96 -and $index + 2 -lt $Query.Length -and
            $Query[$index + 1] -eq [char]96 -and $Query[$index + 2] -eq [char]96) {
            $value = [Text.StringBuilder]::new()
            $index += 3
            $terminated = $false
            while ($index + 2 -lt $Query.Length) {
                if ($Query[$index] -eq [char]96 -and
                    $Query[$index + 1] -eq [char]96 -and
                    $Query[$index + 2] -eq [char]96) {
                    $index += 3
                    $terminated = $true
                    break
                }
                [void]$value.Append($Query[$index])
                $index++
            }
            if (-not $terminated) {
                return [pscustomobject]@{ Valid = $false; Tokens = @(); FinalSegment = $null }
            }
            $tokens.Add([pscustomobject]@{ Type = 'String'; Value = $value.ToString() })
            [void]$segment.Append(' ')
            continue
        }
        if ($character -eq "'" -or $character -eq '"') {
            $quote = $character
            $value = [Text.StringBuilder]::new()
            $index++
            $terminated = $false
            while ($index -lt $Query.Length) {
                $current = $Query[$index]
                if ($current -eq $quote) {
                    $index++
                    $terminated = $true
                    break
                }
                if ($current -eq '\') {
                    if (-not (ConvertFrom-KqlEscape $Query ([ref]$index) $value)) {
                        return [pscustomobject]@{ Valid = $false; Tokens = @(); FinalSegment = $null }
                    }
                    continue
                }
                if ($current -eq "`r" -or $current -eq "`n") {
                    return [pscustomobject]@{ Valid = $false; Tokens = @(); FinalSegment = $null }
                }
                [void]$value.Append($current)
                $index++
            }
            if (-not $terminated) {
                return [pscustomobject]@{ Valid = $false; Tokens = @(); FinalSegment = $null }
            }
            $tokens.Add([pscustomobject]@{ Type = 'String'; Value = $value.ToString() })
            [void]$segment.Append(' ')
            continue
        }
        if ([char]::IsLetter($character) -or $character -eq '_') {
            $start = $index
            $index++
            while ($index -lt $Query.Length -and
                ([char]::IsLetterOrDigit($Query[$index]) -or $Query[$index] -eq '_')) {
                $index++
            }
            $tokens.Add([pscustomobject]@{
                Type = 'Identifier'
                Value = $Query.Substring($start, $index - $start)
            })
            [void]$segment.Append($Query.Substring($start, $index - $start))
            continue
        }
        if ([char]::IsDigit($character)) {
            $start = $index
            $index++
            while ($index -lt $Query.Length -and [char]::IsDigit($Query[$index])) {
                $index++
            }
            $tokens.Add([pscustomobject]@{
                Type = 'Number'
                Value = $Query.Substring($start, $index - $start)
            })
            [void]$segment.Append($Query.Substring($start, $index - $start))
            continue
        }
        $tokens.Add([pscustomobject]@{ Type = 'Punctuation'; Value = [string]$character })
        if ($character -eq '|') {
            $segment.Clear() | Out-Null
        }
        else {
            [void]$segment.Append($character)
        }
        $index++
    }
    return [pscustomobject]@{
        Valid = $true
        Tokens = @($tokens)
        FinalSegment = $segment.ToString().Trim()
    }
}

function Get-KqlScopeError {
    param([string]$Query, $Intent, $Policy)

    $lexed = Get-KqlLexicalAnalysis $Query
    if (-not $lexed.Valid) {
        return 'malformed_kql'
    }
    $tokens = @($lexed.Tokens)
    $crossResourceFunctions = @($Policy.crossResourceFunctions)
    for ($index = 0; $index + 1 -lt $tokens.Count; $index++) {
        $token = $tokens[$index]
        if ($token.Type -cne 'Identifier' -or
            $tokens[$index + 1].Value -cne '(' -or
            $crossResourceFunctions -inotcontains [string]$token.Value) {
            continue
        }
        $functionName = ([string]$token.Value).ToLowerInvariant()
        if ($functionName -cne 'workspace') {
            return 'cross_resource_expansion_denied'
        }
        if ($index + 3 -ge $tokens.Count -or
            $tokens[$index + 2].Type -cne 'String' -or
            $tokens[$index + 3].Value -cne ')') {
            return 'cross_resource_expansion_denied'
        }
        $workspaceIds = @(Get-StringArray $Intent.bounds.workspaceIds)
        if ($workspaceIds.Count -ne 1 -or
            [string]$tokens[$index + 2].Value -cne $workspaceIds[0]) {
            return 'cross_resource_expansion_denied'
        }
    }
    return $null
}

function Get-KqlFinalPipelineSegment {
    param([string]$Query)
    $analysis = Get-KqlLexicalAnalysis $Query
    if (-not $analysis.Valid) { return $null }
    return $analysis.FinalSegment
}

function Get-StructuredResultLimitError {
    param($Body, [long]$AuthorizedRows)
    if ($Body.PSObject.Properties.Name -cnotcontains 'resultLimit') {
        return 'result_limit_missing'
    }
    if (-not (Test-IntegerValue $Body.resultLimit)) {
        return 'result_limit_invalid'
    }
    $resultLimit = [long]$Body.resultLimit
    if ($resultLimit -lt 1 -or $resultLimit -gt $AuthorizedRows) {
        return 'result_limit_invalid'
    }
    return $null
}

function Get-KqlRowBoundError {
    param([string]$Query, [long]$AuthorizedRows, [long]$ResultLimit)
    $finalSegment = Get-KqlFinalPipelineSegment $Query
    if ([string]::IsNullOrWhiteSpace($finalSegment) -or
        $finalSegment -notmatch '(?i)^(?:take|limit)\s+([1-9][0-9]*)\s*;?\s*$') {
        return 'query_row_bound_missing'
    }
    $queryLimit = [long]$Matches[1]
    if ($queryLimit -gt $AuthorizedRows -or $queryLimit -gt $ResultLimit) {
        return 'query_row_bound_exceeded'
    }
    return $null
}

function ConvertTo-CanonicalODataInstant {
    param([string]$Value)
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$') {
        return $null
    }
    $instant = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParseExact(
        $Value,
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$instant
    )) {
        return $null
    }
    return $instant.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'",
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Test-OData {
    param($Intent, $Canonical, $Operation, $Policy, $CapabilityContext, [string]$PolicyDigest)
    if ($Canonical.Query.Contains('$search')) {
        return 'search_not_allowed'
    }
    if ($Operation.PSObject.Properties.Name -contains 'fixedQueryValues') {
        foreach ($property in @($Operation.fixedQueryValues.PSObject.Properties)) {
            if (-not $Canonical.Query.Contains($property.Name) -or
                @($property.Value) -cnotcontains [string]$Canonical.Query[$property.Name]) {
                return 'query_value_not_allowed'
            }
        }
    }
    if ([bool]$Operation.requireTop -and -not $Canonical.Query.Contains('$top')) {
        return 'row_bound_missing'
    }
    if ($Canonical.Query.Contains('$top')) {
        $top = 0
        $maxRows = [Math]::Min([int]$Operation.maxRows, [int]$Intent.bounds.maxRows)
        if (-not [int]::TryParse([string]$Canonical.Query['$top'], [ref]$top) -or $top -lt 1 -or $top -gt $maxRows) {
            return 'row_bound_exceeded'
        }
        $skipTokenKey = if ($Canonical.Query.Contains('$skipToken')) {
            '$skipToken'
        }
        elseif ($Canonical.Query.Contains('$skiptoken')) {
            '$skiptoken'
        }
        else { $null }
        if ($null -ne $skipTokenKey) {
            if ([string]$Canonical.Query[$skipTokenKey] -cnotmatch
                '^[A-Za-z0-9._~+/=-]{1,4096}$') {
                return 'continuation_not_authorized'
            }
            $continuationError = Get-CapabilityEnvelopeError `
                $CapabilityContext `
                'continuation_link' `
                $Intent `
                $Canonical `
                $Operation `
                $Policy `
                $PolicyDigest
            if ($null -ne $continuationError) {
                return 'continuation_not_authorized'
            }
        }
        if ($Canonical.Query.Contains('$orderby')) {
            if ($null -eq $Intent.odata -or
                [string]$Intent.odata.mode -cne 'builder' -or
                $null -eq $Intent.odata.orderby -or
                @($Intent.odata.orderby).Count -ne 1) {
                return 'builder_mode_required'
            }
            $orderby = @($Intent.odata.orderby)[0]
            if (-not (Test-ExactProperties $orderby @('field', 'direction') `
                @('field', 'direction')) -or
                $Policy.odata.allowedFields.PSObject.Properties.Name -cnotcontains
                    [string]$orderby.field -or
                @('asc', 'desc') -cnotcontains [string]$orderby.direction -or
                [string]$Canonical.Query['$orderby'] -cne
                    "$($orderby.field) $($orderby.direction)") {
                return 'builder_output_mismatch'
            }
        }
    }
    if (-not $Canonical.Query.Contains('$filter')) {
        return $null
    }
    if ($null -eq $Intent.odata -or [string]$Intent.odata.mode -cne 'builder') {
        return 'builder_mode_required'
    }
    $clauses = @($Intent.odata.clauses)
    if ($clauses.Count -ne 1) {
        return 'odata_clause_not_allowed'
    }
    $clause = $clauses[0]
    $field = [string]$clause.field
    $operator = [string]$clause.operator
    $type = [string]$clause.type
    $value = [string]$clause.value
    if ($Policy.odata.allowedFields.PSObject.Properties.Name -cnotcontains $field) {
        return 'odata_clause_not_allowed'
    }
    if (@($Policy.odata.allowedFields.$field) -cnotcontains $type -or @($Policy.odata.allowedOperators) -cnotcontains $operator) {
        return 'odata_clause_not_allowed'
    }
    if ($value.Length -gt [int]$Policy.odata.maxLiteralLength -or $value -match '[\x00-\x1F]') {
        return 'odata_clause_not_allowed'
    }
    $expected = if ($type -ceq 'string') {
        "$field $operator '$($value.Replace("'", "''"))'"
    }
    else {
        $instant = ConvertTo-CanonicalODataInstant $value
        if ($null -eq $instant) {
            return 'odata_literal_invalid'
        }
        "$field $operator $instant"
    }
    if ([string]$Canonical.Query['$filter'] -cne $expected) {
        return 'builder_output_mismatch'
    }
    return $null
}

function Get-ResponseByteBoundError {
    param($Intent, $Canonical, $Operation)

    [long]$maxBytes = [long]$Intent.bounds.maxBytes
    if ($Operation.PSObject.Properties.Name -contains 'estimatedBytesPerRow') {
        if (-not (Test-IntegerValue $Operation.estimatedBytesPerRow) -or
            [long]$Operation.estimatedBytesPerRow -lt 1) {
            return 'response_byte_estimate_missing'
        }
        [long]$effectiveRows = [Math]::Min(
            [long]$Intent.bounds.maxRows,
            [long]$Operation.maxRows
        )
        if ($Canonical.Query.Contains('$top')) {
            $effectiveRows = [long]$Canonical.Query['$top']
        }
        [long]$bytesPerRow = [long]$Operation.estimatedBytesPerRow
        if ($effectiveRows -gt ([long]::MaxValue / $bytesPerRow)) {
            return 'estimated_response_bytes_exceeded'
        }
        if (($effectiveRows * $bytesPerRow) -gt $maxBytes) {
            return 'estimated_response_bytes_exceeded'
        }
        return $null
    }

    if ($Operation.PSObject.Properties.Name -contains 'hardSafeResponseBytes' -and
        (Test-IntegerValue $Operation.hardSafeResponseBytes) -and
        [long]$Operation.hardSafeResponseBytes -gt 0) {
        if ([long]$Operation.hardSafeResponseBytes -gt $maxBytes) {
            return 'estimated_response_bytes_exceeded'
        }
        return $null
    }
    return 'response_byte_estimate_missing'
}

function ConvertTo-CanonicalJson {
    param($Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [string]) { return ($Value | ConvertTo-Json -Compress) }
    if (Test-IntegerValue $Value) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [pscustomobject]) {
        return '[' + ((@($Value) | ForEach-Object { ConvertTo-CanonicalJson $_ }) -join ',') + ']'
    }
    $parts = foreach ($name in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) {
        (ConvertTo-CanonicalJson ([string]$name)) + ':' +
            (ConvertTo-CanonicalJson $Value.$name)
    }
    return '{' + ($parts -join ',') + '}'
}

function Get-Sha256Hex {
    param([string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Get-CanonicalRequestDigest {
    param($Intent, $Canonical)

    $query = [System.Collections.Generic.List[object]]::new()
    foreach ($key in @($Canonical.QueryKeys | Sort-Object -CaseSensitive)) {
        $query.Add([pscustomobject][ordered]@{
            key = [string]$key
            value = [string]$Canonical.Query[$key]
        })
    }
    $bodyValue = if ($Intent.PSObject.Properties.Name -ccontains 'body') {
        $Intent.body
    }
    else { $null }
    if ($bodyValue -is [string]) {
        $bodyResult = ConvertTo-BodyObject $bodyValue
        if ($bodyResult.Valid) {
            $bodyValue = $bodyResult.Value
        }
    }
    $request = [pscustomobject][ordered]@{
        version = '1'
        host = [string]$Canonical.Host
        method = ([string]$Intent.method).ToUpperInvariant()
        path = [string]$Canonical.Path
        query = @($query)
        body_sha256 = Get-Sha256Hex (ConvertTo-CanonicalJson $bodyValue)
        bounds = $Intent.bounds
        request_id = [string]$Intent.requestId
        correlation_id = [string]$Intent.correlationId
        operation_id = [string]$Intent.operationId
    }
    return Get-Sha256Hex (ConvertTo-CanonicalJson $request)
}

function Read-CapabilityInput {
    param([string]$Json, [string]$Path)

    if (-not [string]::IsNullOrWhiteSpace($Json) -and
        -not [string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Valid = $false; Present = $true; Error = 'capability_input_invalid'; Items = @() }
    }
    if ([string]::IsNullOrWhiteSpace($Json) -and
        [string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Valid = $true; Present = $false; Error = $null; Items = @() }
    }
    try {
        $text = if (-not [string]::IsNullOrWhiteSpace($Path)) {
            [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
        }
        else {
            $Json
        }
        $trimmed = $text.Trim()
        if (-not $trimmed.StartsWith('[') -or -not $trimmed.EndsWith(']')) {
            throw 'Capability input must be a JSON array'
        }
        $parsed = $trimmed | ConvertFrom-Json -Depth 50 -DateKind String -NoEnumerate
        $items = @($parsed)
        if ($items.Count -lt 1) {
            throw 'Capability input cannot be empty'
        }
        return [pscustomobject]@{ Valid = $true; Present = $true; Error = $null; Items = $items }
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Present = $true; Error = 'capability_input_invalid'; Items = @() }
    }
}

function Get-CapabilityKeyBytes {
    $encoded =
        [Environment]::GetEnvironmentVariable('HAVOC_CAPABILITY_VERIFICATION_KEY', 'Process')
    if ([string]::IsNullOrWhiteSpace($encoded) -or
        $encoded -cnotmatch '^[A-Za-z0-9+/]+={0,2}$' -or
        ($encoded.Length % 4) -ne 0) {
        return $null
    }
    try {
        $bytes = [Convert]::FromBase64String($encoded)
        if ($bytes.Length -lt 32) {
            return $null
        }
        return ,$bytes
    }
    catch {
        return $null
    }
}

function Test-CapabilityBindingHmac {
    param([string]$Value, [string]$Provided)

    $keyBytes = Get-CapabilityKeyBytes
    if ($null -eq $keyBytes) { return $false }
    $hmac = [Security.Cryptography.HMACSHA256]::new($keyBytes)
    $expected = $null
    $actual = $null
    try {
        $expected = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        $actual = [Convert]::FromBase64String($Provided)
        $actual.Length -eq 32 -and
            [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $expected,
                $actual
            )
    }
    catch {
        $false
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($keyBytes, 0, $keyBytes.Length)
        if ($null -ne $expected) { [Array]::Clear($expected, 0, $expected.Length) }
        if ($null -ne $actual) { [Array]::Clear($actual, 0, $actual.Length) }
    }
}

function Test-NonEmptyStringArrayProperty {
    param($Object, [string]$Name)

    if ($Object.PSObject.Properties.Name -cnotcontains $Name) { return $true }
    $value = $Object.$Name
    if (-not ($value -is [array])) { return $false }
    $items = @($value)
    if ($items.Count -lt 1) { return $false }
    @($items | Where-Object {
        $_ -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$_)
    }).Count -eq 0
}

function Get-CapabilityEnvelopeError {
    param(
        $CapabilityContext,
        [string]$ExpectedKind,
        $Intent,
        $Canonical,
        $Operation,
        $Policy,
        [string]$PolicyDigest
    )

    if (-not $CapabilityContext.Valid) {
        return $CapabilityContext.Error
    }
    if (-not $CapabilityContext.Present) {
        return $(if ($ExpectedKind -ceq 'response_enforcement') {
            'response_enforcement_capability_missing'
        }
        elseif ($ExpectedKind -ceq 'continuation_link' -or
            $ExpectedKind -ceq 'continuation_token') {
            'continuation_capability_missing'
        }
        else {
            'purview_lifecycle_capability_missing'
        })
    }

    $envelopeProperties = @(
        'canonical_request_digest',
        'capability_kind',
        'claims',
        'expires_at',
        'issued_at',
        'issuer_id',
        'issuer_version',
        'key_id',
        'nonce',
        'policy_digest',
        'policy_version',
        'signature',
        'signature_algorithm'
    )
    $nonces = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedRequestDigest = Get-CanonicalRequestDigest $Intent $Canonical
    [int]$expectedKindCount = 0
    $matchingCapabilities = [System.Collections.Generic.List[object]]::new()
    foreach ($capability in @($CapabilityContext.Items)) {
        if (-not (Test-ExactProperties $capability $envelopeProperties $envelopeProperties)) {
            return 'capability_shape_not_allowed'
        }
        foreach ($name in @(
            'canonical_request_digest', 'capability_kind', 'expires_at', 'issued_at',
            'issuer_id', 'issuer_version', 'key_id', 'nonce', 'policy_digest',
            'policy_version', 'signature', 'signature_algorithm'
        )) {
            if ($capability.$name -isnot [string] -or
                [string]::IsNullOrEmpty([string]$capability.$name)) {
                return 'capability_shape_not_allowed'
            }
        }
        if ([string]$capability.nonce -cnotmatch '^[A-Za-z0-9._:-]{16,128}$') {
            return 'capability_shape_not_allowed'
        }
        if (-not $nonces.Add([string]$capability.nonce)) {
            return 'duplicate_capability_nonce'
        }
        if ([string]$capability.capability_kind -ceq $ExpectedKind) {
            $expectedKindCount++
            if ([string]$capability.canonical_request_digest -ceq $expectedRequestDigest) {
                $matchingCapabilities.Add($capability)
            }
        }
    }
    if ($expectedKindCount -eq 0) {
        return 'capability_kind_mismatch'
    }
    if ($matchingCapabilities.Count -eq 0) {
        return 'capability_request_mismatch'
    }
    if ($matchingCapabilities.Count -gt 1) {
        return 'duplicate_capability'
    }
    $capability = $matchingCapabilities[0]

    $issuerAllowed = $false
    foreach ($issuer in @($Policy.capabilityTrust.issuers)) {
        if ([string]$issuer.issuerId -ceq [string]$capability.issuer_id -and
            [string]$issuer.issuerVersion -ceq [string]$capability.issuer_version -and
            [string]$issuer.keyId -ceq [string]$capability.key_id) {
            $issuerAllowed = $true
            break
        }
    }
    if (-not $issuerAllowed) {
        $knownIssuerAndVersion = @($Policy.capabilityTrust.issuers | Where-Object {
            [string]$_.issuerId -ceq [string]$capability.issuer_id -and
            [string]$_.issuerVersion -ceq [string]$capability.issuer_version
        }).Count -gt 0
        return $(if ($knownIssuerAndVersion) { 'capability_key_not_allowed' } else { 'capability_issuer_not_allowed' })
    }
    if ([string]$capability.policy_version -cne [string]$Policy.policyVersion -or
        [string]$capability.policy_digest -cne $PolicyDigest) {
        return 'capability_policy_mismatch'
    }
    if ([string]$capability.signature_algorithm -cne 'HMAC-SHA256') {
        return 'capability_signature_invalid'
    }

    try {
        $issuedAt = ConvertTo-DateTimeOffset $capability.issued_at
        $expiresAt = ConvertTo-DateTimeOffset $capability.expires_at
    }
    catch {
        return 'capability_time_invalid'
    }
    $now = $GuardCurrentTime
    $skew = [timespan]::FromSeconds([long]$Policy.capabilityTrust.maxClockSkewSeconds)
    $maximumLifetime = [timespan]::FromSeconds([long]$Policy.capabilityTrust.maxLifetimeSeconds)
    if ($issuedAt -gt ($now + $skew) -or
        $expiresAt -le $issuedAt -or
        ($expiresAt - $issuedAt) -gt $maximumLifetime) {
        return 'capability_time_invalid'
    }
    if ($expiresAt -le $now) {
        return 'capability_expired'
    }

    $keyBytes = Get-CapabilityKeyBytes
    if ($null -eq $keyBytes) {
        return 'capability_key_invalid'
    }
    try {
        $providedSignature = [Convert]::FromBase64String([string]$capability.signature)
    }
    catch {
        return 'capability_signature_invalid'
    }
    if ($providedSignature.Length -ne 32) {
        return 'capability_signature_invalid'
    }
    $unsigned = [pscustomobject][ordered]@{}
    foreach ($property in $capability.PSObject.Properties) {
        if ($property.Name -cne 'signature') {
            $unsigned | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
    }
    $hmac = [Security.Cryptography.HMACSHA256]::new($keyBytes)
    try {
        $expectedSignature = $hmac.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson $unsigned))
        )
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($keyBytes, 0, $keyBytes.Length)
    }
    if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
        $providedSignature,
        $expectedSignature
    )) {
        return 'capability_signature_invalid'
    }

    if ($ExpectedKind -ceq 'continuation_link') {
        $claimProperties = @(
            'next_link',
            'next_link_hmac',
            'operation_id',
            'rule_id'
        )
        if (-not (Test-ExactProperties $capability.claims $claimProperties $claimProperties) -or
            [string]$capability.claims.operation_id -cne [string]$Operation.operationId -or
            [string]$capability.claims.rule_id -cne [string]$Operation.ruleId -or
            [string]$capability.claims.next_link -cne [string]$Intent.uri -or
            -not (Test-CapabilityBindingHmac `
                ([string]$Intent.uri) `
                ([string]$capability.claims.next_link_hmac))) {
            return 'capability_claims_invalid'
        }
        return $null
    }

    if ($ExpectedKind -ceq 'continuation_token') {
        $claimProperties = @(
            'adapter_id',
            'adapter_version',
            'continuation_token_hmac',
            'max_bytes',
            'operation_id',
            'rule_id'
        )
        $token = ''
        if ($Intent.PSObject.Properties.Name -ccontains 'body' -and
            $null -ne $Intent.body -and
            $Intent.body.PSObject.Properties.Name -ccontains 'options' -and
            $null -ne $Intent.body.options -and
            $Intent.body.options.PSObject.Properties.Name -ccontains '$skipToken') {
            $token = [string]$Intent.body.options.'$skipToken'
        }
        if (-not (Test-ExactProperties $capability.claims $claimProperties $claimProperties) -or
            [string]$capability.claims.operation_id -cne [string]$Operation.operationId -or
            [string]$capability.claims.rule_id -cne [string]$Operation.ruleId -or
            -not (Test-IntegerValue $capability.claims.max_bytes) -or
            [long]$capability.claims.max_bytes -ne [long]$Intent.bounds.maxBytes -or
            [string]::IsNullOrWhiteSpace($token) -or
            -not (Test-CapabilityBindingHmac `
                $token `
                ([string]$capability.claims.continuation_token_hmac))) {
            return 'capability_claims_invalid'
        }
        $approvedAdapter = @($Policy.responseAdapterCapabilities | Where-Object {
            [string]$_.adapterId -ceq [string]$capability.claims.adapter_id -and
            [string]$_.adapterVersion -ceq [string]$capability.claims.adapter_version
        }).Count -eq 1
        if (-not $approvedAdapter) {
            return 'capability_claims_invalid'
        }
        return $null
    }

    if ($ExpectedKind -ceq 'response_enforcement') {
        $claimProperties = @(
            'actual_bytes_recording',
            'adapter_id',
            'adapter_version',
            'byte_limit_enforced',
            'max_bytes',
            'operation_id',
            'partial_response_detection',
            'rule_id',
            'truncation_detection'
        )
        if (-not (Test-ExactProperties $capability.claims $claimProperties $claimProperties)) {
            return 'capability_claims_invalid'
        }
        foreach ($name in @(
            'actual_bytes_recording',
            'byte_limit_enforced',
            'partial_response_detection',
            'truncation_detection'
        )) {
            if ($capability.claims.$name -isnot [bool] -or
                $capability.claims.$name -ne $true) {
                return 'capability_claims_invalid'
            }
        }
        if ([string]$capability.claims.operation_id -cne [string]$Operation.operationId -or
            [string]$capability.claims.rule_id -cne [string]$Operation.ruleId -or
            -not (Test-IntegerValue $capability.claims.max_bytes) -or
            [long]$capability.claims.max_bytes -ne [long]$Intent.bounds.maxBytes) {
            return 'capability_claims_invalid'
        }
        $approvedAdapter = @($Policy.responseAdapterCapabilities | Where-Object {
            [string]$_.adapterId -ceq [string]$capability.claims.adapter_id -and
            [string]$_.adapterVersion -ceq [string]$capability.claims.adapter_version
        }).Count -eq 1
        if (-not $approvedAdapter) {
            return 'capability_claims_invalid'
        }
        return $null
    }

    $purviewClaimProperties = @(
        'bounded_request_verified',
        'commercial_endpoint_verified',
        'least_privilege_verified',
        'lifecycle_verified',
        'operation_id',
        'operational_necessity_verified',
        'precondition_binding_hmac',
        'precondition_evidence_ref',
        'persistence_verified',
        'report_disclosure_planned',
        'retention_expiry_verified',
        'rule_id',
        'side_effects_verified',
        'visibility_sharing_verified',
        'workload_permissions',
        'workloads'
    )
    if (-not (Test-ExactProperties $capability.claims $purviewClaimProperties $purviewClaimProperties) -or
        [string]$capability.claims.operation_id -cne [string]$Operation.operationId -or
        [string]$capability.claims.rule_id -cne [string]$Operation.ruleId) {
        return 'capability_claims_invalid'
    }
    foreach ($name in @($purviewClaimProperties | Where-Object {
        $_ -notin @(
            'operation_id',
            'precondition_binding_hmac',
            'precondition_evidence_ref',
            'rule_id',
            'workload_permissions',
            'workloads'
        )
    })) {
        if ($capability.claims.$name -isnot [bool] -or
            $capability.claims.$name -ne $true) {
            return 'capability_claims_invalid'
        }
    }
    if (-not (Test-ProtectedReference `
            $capability.claims.precondition_evidence_ref `
            @('protected-evidence'))) {
        return 'capability_claims_invalid'
    }
    if (-not (Test-CapabilityBindingHmac `
            $expectedRequestDigest `
            ([string]$capability.claims.precondition_binding_hmac))) {
        return 'capability_claims_invalid'
    }
    $scopeMap = [ordered]@{
        AzureActiveDirectory = 'AuditLogsQuery-Entra.Read.All'
        Exchange = 'AuditLogsQuery-Exchange.Read.All'
        OneDrive = 'AuditLogsQuery-OneDrive.Read.All'
        SharePoint = 'AuditLogsQuery-SharePoint.Read.All'
    }
    $bodyResult = ConvertTo-BodyObject $Intent.body
    if (-not $bodyResult.Valid) {
        return 'capability_claims_invalid'
    }
    if ($bodyResult.Value.PSObject.Properties.Name -cnotcontains 'serviceFilter' -or
        $bodyResult.Value.serviceFilter -isnot [string]) {
        return 'capability_claims_invalid'
    }
    $expectedWorkloads = @([string]$bodyResult.Value.serviceFilter |
        Sort-Object -CaseSensitive)
    $expectedPermissions = @($expectedWorkloads | ForEach-Object {
        [string]$scopeMap[[string]$_]
    } | Sort-Object -CaseSensitive)
    if ((@($capability.claims.workloads) -join "`n") -cne
            ($expectedWorkloads -join "`n") -or
        (@($capability.claims.workload_permissions) -join "`n") -cne
            ($expectedPermissions -join "`n")) {
        return 'capability_claims_invalid'
    }
    return $null
}

function Get-InferredGraphOperationId {
    param([string]$Method, [string]$Path, $Policy)
    foreach ($operation in @($Policy.operations)) {
        if ([string]$operation.host -cne [string]$Policy.effectiveGraphHost -or
            [string]$operation.method -cne $Method.ToUpperInvariant()) {
            continue
        }
        if ($operation.PSObject.Properties.Name -ccontains 'path') {
            if ([string]$operation.path -ceq $Path) {
                return [string]$operation.operationId
            }
        }
        elseif ($Path -cmatch [string]$operation.pathPattern) {
            return [string]$operation.operationId
        }
    }
    return 'unknown-batch-operation'
}

function Test-RequestIntent {
    param(
        $Intent,
        $Policy,
        $CapabilityContext,
        [string]$PolicyDigest,
        [int]$Depth = 0
    )

    if ($null -eq $Intent) {
        return New-Decision $false 'DENY-INTENT' 'invalid_intent' $null 'unknown' ([pscustomobject]@{}) $Policy
    }
    $intentProperties = @(
        'armRbacReadApproved',
        'autoFollowRedirects',
        'body',
        'bounds',
        'correlationId',
        'credentialClass',
        'expected_principal_ref',
        'expected_source_scope_refs',
        'method',
        'odata',
        'operationId',
        'redirectContext',
        'requestId',
        'requestedScopes',
        'responseEnforcement',
        'tokenRoles',
        'tokenScopes',
        'uri'
    )
    $requiredIntentProperties = @(
        'bounds',
        'expected_principal_ref',
        'expected_source_scope_refs',
        'method',
        'operationId',
        'requestedScopes',
        'tokenRoles',
        'tokenScopes',
        'uri'
    )
    if (-not (Test-ExactProperties $Intent $intentProperties $requiredIntentProperties)) {
        return New-Decision $false 'DENY-INTENT' 'intent_shape_not_allowed' `
            $null 'unknown' $Intent $Policy
    }
    if ($Intent.PSObject.Properties.Name -cnotcontains
            'expected_principal_ref' -or
        -not (Test-ProtectedReference ([string]$Intent.expected_principal_ref) `
            @('protected-context')) -or
        $Intent.PSObject.Properties.Name -cnotcontains
            'expected_source_scope_refs' -or
        $Intent.expected_source_scope_refs -is [string] -or
        $Intent.expected_source_scope_refs -isnot
            [System.Collections.IEnumerable] -or
        @($Intent.expected_source_scope_refs).Count -lt 1 -or
        @($Intent.expected_source_scope_refs | Where-Object {
            -not (Test-ProtectedReference ([string]$_) @('protected-context'))
        }).Count -gt 0) {
        return New-Decision $false 'DENY-INTENT' 'expected_binding_missing' `
            $null 'unknown' $Intent $Policy
    }

    $canonical = Resolve-CanonicalUri ([string]$Intent.uri) $Policy
    if (-not $canonical.Valid) {
        return New-Decision $false 'DENY-URI' $canonical.Reason $canonical 'unknown' $Intent $Policy
    }

    if ($Intent.PSObject.Properties.Name -contains 'autoFollowRedirects' -and [bool]$Intent.autoFollowRedirects) {
        return New-Decision $false 'DENY-REDIRECT' 'automatic_redirect_denied' $canonical 'unknown' $Intent $Policy
    }
    if ($Intent.PSObject.Properties.Name -contains 'redirectContext') {
        $redirect = $Intent.redirectContext
        $redirectError = Get-RedirectContextError $redirect $Policy
        if ($null -ne $redirectError) {
            return New-Decision $false 'DENY-REDIRECT' $redirectError $canonical 'unknown' $Intent $Policy
        }
        if ($redirect.forwardAuthorization -eq $true -and
            [string]$redirect.originalOrigin -cne $canonical.Origin) {
            return New-Decision $false 'DENY-REDIRECT' 'cross_origin_authorization_denied' $canonical 'unknown' $Intent $Policy
        }
    }

    $method = ([string]$Intent.method).ToUpperInvariant()
    if (@('PUT', 'PATCH', 'DELETE') -ccontains $method) {
        return New-Decision $false 'DENY-MUTATION' 'method_mutation_denied' $canonical 'mutation' $Intent $Policy
    }
    if ($method -ceq 'POST') {
        foreach ($pattern in $Policy.knownMutationPathPatterns) {
            if ($canonical.Path -match [string]$pattern) {
                return New-Decision $false 'DENY-MUTATION' 'known_mutation_endpoint' $canonical 'mutation' $Intent $Policy
            }
        }
    }
    if ($method -ceq 'GET' -and
        $Intent.PSObject.Properties.Name -ccontains 'body') {
        return New-Decision $false 'DENY-BODY' 'body_not_allowed_on_get' `
            $canonical 'read' $Intent $Policy
    }

    if ([string]$Intent.operationId -ceq 'defender-legacy-run-hunting-query' -and -not [bool]$Policy.conditionalCapabilities.defenderLegacyHunting.enabled) {
        return New-Decision $false 'DENY-CONDITIONAL-CAPABILITY' ([string]$Policy.conditionalCapabilities.defenderLegacyHunting.reason) $canonical 'read_query' $Intent $Policy
    }
    if ([string]$Intent.operationId -ceq 'graph-security-run-hunting-query' -and -not [bool]$Policy.conditionalCapabilities.graphSecurityHunting.enabled) {
        return New-Decision $false 'DENY-CONDITIONAL-CAPABILITY' ([string]$Policy.conditionalCapabilities.graphSecurityHunting.reason) $canonical 'read_query' $Intent $Policy
    }

    $operation = Get-Operation $Intent $canonical $Policy
    if ($null -eq $operation) {
        Set-SafeQueryProjection $canonical $null
        if ([string]$Intent.operationId -ceq 'azure-resource-graph-query' -and $canonical.Path -ceq '/providers/Microsoft.ResourceGraph/resources') {
            return New-Decision $false 'DENY-API-VERSION' 'api_version_not_allowed' $canonical 'read_query' $Intent $Policy
        }
        return New-Decision $false 'DENY-UNKNOWN-OPERATION' 'operation_not_allowlisted' $canonical 'unknown' $Intent $Policy
    }

    Set-SafeQueryProjection $canonical $operation
    $semanticClass = [string]$operation.semanticClass
    foreach ($key in $canonical.QueryKeys) {
        if (@($operation.allowedQueryKeys) -cnotcontains $key) {
            if (([string]$operation.host -ceq [string]$Policy.effectiveGraphHost) -and
                ([string]$operation.method -ceq 'GET') -and
                ($key -ceq '$skiptoken' -or $key -ceq '$skipToken')) {
                continue
            }
            if ($key -ceq '$search') {
                return New-Decision $false 'DENY-ODATA' 'search_not_allowed' $canonical $semanticClass $Intent $Policy
            }
            return New-Decision $false 'DENY-QUERY' 'query_key_not_allowed' $canonical $semanticClass $Intent $Policy
        }
    }

    $permissionError = Test-Permissions $Intent $operation $Policy
    if ($null -ne $permissionError) {
        return New-Decision $false 'DENY-PERMISSION' $permissionError $canonical $semanticClass $Intent $Policy
    }

    $boundsError = Test-Bounds $Intent $operation $Policy
    if ($null -ne $boundsError) {
        return New-Decision $false 'DENY-QUERY-BOUNDS' $boundsError $canonical $semanticClass $Intent $Policy
    }

    $decisionSemanticClass = if ($method -ceq 'POST' -and
        [string]$operation.semanticClass -ceq 'read_query' -and
        $operation.PSObject.Properties.Name -ccontains 'responseEnforcementRequired' -and
        $operation.responseEnforcementRequired -eq $true) {
        'conditionally_bounded_read_query'
    }
    else {
        $semanticClass
    }
    $isResourceGraphContinuation = [string]$operation.operationId -ceq 'azure-resource-graph-query' -and
        $Intent.PSObject.Properties.Name -ccontains 'body' -and
        $null -ne $Intent.body -and
        $Intent.body.PSObject.Properties.Name -ccontains 'options' -and
        $null -ne $Intent.body.options -and
        $Intent.body.options.PSObject.Properties.Name -ccontains '$skipToken'
    if (-not $isResourceGraphContinuation -and
        $operation.PSObject.Properties.Name -ccontains 'responseEnforcementRequired' -and
        $operation.responseEnforcementRequired -eq $true) {
        $responseCapabilityError = Get-CapabilityEnvelopeError `
            $CapabilityContext `
            'response_enforcement' `
            $Intent `
            $canonical `
            $operation `
            $Policy `
            $PolicyDigest
        if ($null -ne $responseCapabilityError) {
            return New-Decision $false 'DENY-RESPONSE-ENFORCEMENT' $responseCapabilityError $canonical $decisionSemanticClass $Intent $Policy
        }
    }

    if ($method -ceq 'GET') {
        $odataError = Test-OData $Intent $canonical $operation $Policy $capabilityContext $PolicyDigest
        if ($null -ne $odataError) {
            $rule = if ($odataError -in @('row_bound_exceeded', 'row_bound_missing')) { 'DENY-QUERY-BOUNDS' } else { 'DENY-ODATA' }
            return New-Decision $false $rule $odataError $canonical $semanticClass $Intent $Policy
        }
        $byteBoundError = Get-ResponseByteBoundError $Intent $canonical $operation
        if ($null -ne $byteBoundError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $byteBoundError $canonical $semanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) 'allowed_read' $canonical $semanticClass $Intent $Policy
    }

    if ([string]$operation.bodyValidator -ceq 'emptyBody') {
        $hasBody = $Intent.PSObject.Properties.Name -ccontains 'body'
        $bodyIsEmpty = -not $hasBody -or $null -eq $Intent.body -or
            ($Intent.body -is [string] -and
                [string]::IsNullOrWhiteSpace([string]$Intent.body)) -or
            ($Intent.body -is [pscustomobject] -and
                @($Intent.body.PSObject.Properties).Count -eq 0)
        if (-not $bodyIsEmpty) {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' `
                $canonical $semanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) `
            'allowed_documented_read_semantic_post' $canonical `
            $semanticClass $Intent $Policy
    }

    $bodyResult = ConvertTo-BodyObject $Intent.body
    if (-not $bodyResult.Valid) {
        return New-Decision $false 'DENY-BODY' 'malformed_body' $canonical $semanticClass $Intent $Policy
    }
    $body = $bodyResult.Value

    if ([string]$operation.bodyValidator -ceq 'graphHuntingQuery') {
        if (-not (Test-ExactProperties $body @('Query') @('Query')) -or
            $body.Query -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$body.Query) -or
            ([string]$body.Query).Length -gt 100000 -or
            [string]$body.Query -match '(?im)\b(?:delete|drop|alter|set|append|ingest|execute)\b') {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' `
                $canonical $semanticClass $Intent $Policy
        }

        return New-Decision $true ([string]$operation.ruleId) `
            'allowed_conditional_preview_query' $canonical `
            $decisionSemanticClass $Intent $Policy
    }

    if ([string]$operation.bodyValidator -ceq 'sentinelIncidentEntities') {
        if (-not (Test-ExactProperties $body @('startTime', 'endTime') @('startTime', 'endTime'))) {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' `
                $canonical $semanticClass $Intent $Policy
        }
        try {
            $bodyStart = ConvertTo-DateTimeOffset $body.startTime
            $bodyEnd = ConvertTo-DateTimeOffset $body.endTime
        }
        catch {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' `
                $canonical $semanticClass $Intent $Policy
        }
        if ($bodyStart -ge $bodyEnd -or
            $bodyStart -ne (ConvertTo-DateTimeOffset $Intent.bounds.startTime) -or
            $bodyEnd -ne (ConvertTo-DateTimeOffset $Intent.bounds.endTime)) {
            return New-Decision $false 'DENY-BODY' 'body_bounds_mismatch' `
                $canonical $semanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) `
            'allowed_documented_read_semantic_post' $canonical $semanticClass $Intent $Policy
    }

    if ([string]$operation.operationId -ceq 'graph-batch') {
        if ($Depth -gt 0) {
            return New-Decision $false 'DENY-BATCH' 'nested_batch_denied' $canonical 'read_batch' $Intent $Policy
        }
        if (-not (Test-ExactProperties $body @('requests') @('requests'))) {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical 'read_batch' $Intent $Policy
        }
        $requests = @($body.requests)
        if ($requests.Count -lt 1 -or $requests.Count -gt [int]$Policy.globalBounds.maxBatchRequests) {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical 'read_batch' $Intent $Policy
        }
        $requestIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        [long]$aggregateRows = 0
        [long]$aggregateBytes = 0
        foreach ($request in $requests) {
            if (-not (Test-ExactProperties $request @('body', 'headers', 'id', 'method', 'responseEnforcement', 'url') @('method', 'url'))) {
                return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical 'read_batch' $Intent $Policy
            }
            $requestId = if ($request.PSObject.Properties.Name -contains 'id') {
                Get-SafeIdentifier $request.id
            }
            else {
                $null
            }
            if ($null -eq $requestId -or -not $requestIds.Add($requestId)) {
                return New-Decision $false 'DENY-BATCH' 'batch_request_id_invalid' $canonical 'read_batch' $Intent $Policy
            }
            if ($request.PSObject.Properties.Name -contains 'headers' -and $null -ne $request.headers) {
                $headerNames = @($request.headers.PSObject.Properties.Name)
                foreach ($headerName in $headerNames) {
                    $normalizedHeaderName = ([string]$headerName).Trim()
                    if ($normalizedHeaderName -ieq 'Authorization') {
                        return New-Decision $false 'DENY-BATCH' 'subrequest_authorization_denied' $canonical 'read_batch' $Intent $Policy
                    }
                    return New-Decision $false 'DENY-BATCH' 'batch_subrequest_denied' $canonical 'read_batch' $Intent $Policy
                }
            }
            $subMethod = ([string]$request.method).ToUpperInvariant()
            if ($subMethod -ceq 'GET' -and
                $request.PSObject.Properties.Name -ccontains 'body') {
                return New-Decision $false 'DENY-BATCH' 'batch_subrequest_denied' $canonical 'read_batch' $Intent $Policy
            }
            $relative = [string]$request.url
            if (-not $relative.StartsWith('/') -or $relative.StartsWith('//')) {
                return New-Decision $false 'DENY-BATCH' 'batch_subrequest_denied' $canonical 'read_batch' $Intent $Policy
            }
            $subPath = ($relative -split '[?#]', 2)[0]
            if ($subPath -ceq '/v1.0/$batch') {
                return New-Decision $false 'DENY-BATCH' 'nested_batch_denied' $canonical 'read_batch' $Intent $Policy
            }
            $subOperationId = Get-InferredGraphOperationId $subMethod $subPath $Policy
            $subBounds = Copy-JsonValue $Intent.bounds
            if ($subMethod -ceq 'POST' -and
                $request.PSObject.Properties.Name -ccontains 'responseEnforcement' -and
                $null -ne $request.responseEnforcement -and
                $request.responseEnforcement.PSObject.Properties.Name -ccontains 'maxBytes' -and
                (Test-IntegerValue $request.responseEnforcement.maxBytes) -and
                [long]$request.responseEnforcement.maxBytes -gt 0) {
                # This is only the proposed subrequest bound. The separate signed
                # capability must bind the exact value before authorization.
                $subBounds.maxBytes = [long]$request.responseEnforcement.maxBytes
            }
            if ($subMethod -ceq 'POST' -and
                $request.PSObject.Properties.Name -ccontains 'body' -and
                $null -ne $request.body -and
                $request.body.PSObject.Properties.Name -ccontains 'resultLimit' -and
                (Test-IntegerValue $request.body.resultLimit) -and
                [long]$request.body.resultLimit -gt 0) {
                $subBounds.maxRows = [long]$request.body.resultLimit
            }
            $subIntent = [pscustomobject]@{
                requestId = Get-SafeIdentifier $request.id
                correlationId = Get-SafeIdentifier $Intent.correlationId
                operationId = $subOperationId
                method = $subMethod
                uri = "https://$([string]$Policy.effectiveGraphHost)$relative"
                requestedScopes = @(Get-StringArray $Intent.requestedScopes)
                tokenScopes = @(Get-StringArray $Intent.tokenScopes)
                tokenRoles = @(Get-StringArray $Intent.tokenRoles)
                expected_principal_ref =
                    [string]$Intent.expected_principal_ref
                expected_source_scope_refs =
                    @($Intent.expected_source_scope_refs)
                autoFollowRedirects = $false
                bounds = $subBounds
            }
            if ($request.PSObject.Properties.Name -contains 'body') {
                $subIntent | Add-Member -NotePropertyName body -NotePropertyValue $request.body
            }
            $subDecision = Test-RequestIntent `
                $subIntent `
                $Policy `
                $CapabilityContext `
                $PolicyDigest `
                ($Depth + 1)
            if (-not $subDecision.allowed) {
                return New-Decision $false 'DENY-BATCH' 'batch_subrequest_denied' $canonical 'read_batch' $Intent $Policy
            }
            $subCanonical = Resolve-CanonicalUri ([string]$subIntent.uri) $Policy
            $subOperation = Get-Operation $subIntent $subCanonical $Policy
            if ($null -eq $subOperation) {
                return New-Decision $false 'DENY-BATCH' 'batch_subrequest_unbounded' $canonical 'read_batch' $Intent $Policy
            }
            [long]$subRows = if ([string]$subOperation.method -ceq 'POST' -and
                $subIntent.body.PSObject.Properties.Name -ccontains 'resultLimit' -and
                (Test-IntegerValue $subIntent.body.resultLimit)) {
                [long]$subIntent.body.resultLimit
            }
            elseif ($subCanonical.Query.Contains('$top')) {
                [long]$subCanonical.Query['$top']
            }
            elseif ([long]$subOperation.maxRows -eq 1) {
                1
            }
            else {
                return New-Decision $false 'DENY-BATCH' 'batch_subrequest_unbounded' $canonical 'read_batch' $Intent $Policy
            }
            $aggregateRows += $subRows
            [long]$subBytes = if ([string]$subOperation.method -ceq 'POST') {
                [long]$subIntent.bounds.maxBytes
            }
            elseif ($subOperation.PSObject.Properties.Name -ccontains 'estimatedBytesPerRow') {
                if ($subRows -gt ([long]::MaxValue / [long]$subOperation.estimatedBytesPerRow)) {
                    return New-Decision $false 'DENY-BATCH' 'batch_aggregate_cost_bound_exceeded' $canonical 'read_batch' $Intent $Policy
                }
                $subRows * [long]$subOperation.estimatedBytesPerRow
            }
            else {
                return New-Decision $false 'DENY-BATCH' 'batch_subrequest_unbounded' $canonical 'read_batch' $Intent $Policy
            }
            if ($subBytes -lt 0 -or $aggregateBytes -gt ([long]::MaxValue - $subBytes)) {
                return New-Decision $false 'DENY-BATCH' 'batch_aggregate_cost_bound_exceeded' $canonical 'read_batch' $Intent $Policy
            }
            $aggregateBytes += $subBytes
            if ($aggregateRows -gt [long]$Intent.bounds.maxRows) {
                return New-Decision $false 'DENY-BATCH' 'batch_aggregate_row_bound_exceeded' $canonical 'read_batch' $Intent $Policy
            }
            if ($aggregateBytes -gt [long]$Intent.bounds.maxBytes) {
                return New-Decision $false 'DENY-BATCH' 'batch_aggregate_cost_bound_exceeded' $canonical 'read_batch' $Intent $Policy
            }
        }
        return New-Decision $true ([string]$operation.ruleId) 'all_subrequests_allowed' $canonical 'read_batch' $Intent $Policy
    }

    if (-not (Test-ExactProperties $body @($operation.allowedBodyProperties) @('query'))) {
        if ([string]$operation.operationId -ceq 'purview-audit-query-create') {
            if (-not (Test-ExactProperties $body @($operation.allowedBodyProperties) @('displayName', 'filterStartDateTime', 'filterEndDateTime'))) {
                return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical $semanticClass $Intent $Policy
            }
        }
        else {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical $semanticClass $Intent $Policy
        }
    }

    if ([string]$operation.operationId -ceq 'log-analytics-query') {
        $workspaceFromPath = ($canonical.Path -split '/')[3]
        $workspaceIds = @(Get-StringArray $Intent.bounds.workspaceIds)
        if ($workspaceIds.Count -ne 1 -or $workspaceIds[0] -cne $workspaceFromPath) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' 'source_scope_mismatch' $canonical $semanticClass $Intent $Policy
        }
        $scopeError = Get-KqlScopeError ([string]$body.query) $Intent $Policy
        if ($null -ne $scopeError) {
            return New-Decision $false 'DENY-QUERY-SCOPE' $scopeError $canonical $semanticClass $Intent $Policy
        }
        if (@($Policy.allowedTimespanFormats) -cnotcontains 'start/end') {
            return New-Decision $false 'DENY-QUERY-BOUNDS' 'body_time_bound_mismatch' $canonical $semanticClass $Intent $Policy
        }
        $timespanParts = @(([string]$body.timespan) -split '/', 2)
        if ($timespanParts.Count -ne 2 -or -not (Test-BodyTimeRange $timespanParts[0] $timespanParts[1] $Intent.bounds)) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' 'body_time_bound_mismatch' $canonical $semanticClass $Intent $Policy
        }
        $authorizedRows = [Math]::Min([long]$Intent.bounds.maxRows, [long]$operation.maxRows)
        $resultLimitError = Get-StructuredResultLimitError $body $authorizedRows
        if ($null -ne $resultLimitError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $resultLimitError $canonical $semanticClass $Intent $Policy
        }
        $rowBoundError = Get-KqlRowBoundError ([string]$body.query) $authorizedRows ([long]$body.resultLimit)
        if ($null -ne $rowBoundError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $rowBoundError $canonical $semanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) 'allowed_bounded_query' $canonical $decisionSemanticClass $Intent $Policy
    }

    if ([string]$operation.operationId -ceq 'azure-resource-graph-query') {
        if (-not $canonical.Query.Contains('api-version') -or @($operation.allowedApiVersions) -cnotcontains [string]$canonical.Query['api-version']) {
            return New-Decision $false 'DENY-API-VERSION' 'api_version_not_allowed' $canonical $semanticClass $Intent $Policy
        }
        $subscriptions = @(Get-StringArray $body.subscriptions)
        $boundedSubscriptions = @(Get-StringArray $Intent.bounds.subscriptionIds)
        if ($subscriptions.Count -lt 1 -or $subscriptions.Count -gt [int]$Policy.globalBounds.maxSubscriptions -or
            ($subscriptions -join ',') -cne ($boundedSubscriptions -join ',')) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' 'source_scope_mismatch' $canonical $semanticClass $Intent $Policy
        }
        if ($body.options.PSObject.Properties.Name | Where-Object { @('$top', 'resultFormat', '$skipToken') -cnotcontains $_ }) {
            return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical $semanticClass $Intent $Policy
        }
        if ($body.options.PSObject.Properties.Name -contains '$skipToken') {
            $continuationError = Get-CapabilityEnvelopeError `
                $capabilityContext `
                'continuation_token' `
                $Intent `
                $canonical `
                $operation `
                $Policy `
                $PolicyDigest
            if ([string]::IsNullOrWhiteSpace([string]$body.options.'$skipToken') -or
                [string]$body.options.'$skipToken' -cnotmatch '^[A-Za-z0-9._~+/=-]{1,4096}$' -or
                $null -ne $continuationError) {
                return New-Decision $false 'DENY-BODY' 'continuation_not_authorized' $canonical $semanticClass $Intent $Policy
            }
        }
        $scopeError = Get-KqlScopeError ([string]$body.query) $Intent $Policy
        if ($null -ne $scopeError) {
            return New-Decision $false 'DENY-QUERY-SCOPE' $scopeError $canonical $semanticClass $Intent $Policy
        }
        $authorizedRows = [Math]::Min([long]$Intent.bounds.maxRows, [long]$operation.maxRows)
        $resultLimitError = Get-StructuredResultLimitError $body $authorizedRows
        if ($null -ne $resultLimitError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $resultLimitError $canonical $semanticClass $Intent $Policy
        }
        if (-not (Test-IntegerValue $body.options.'$top') -or
            [long]$body.options.'$top' -lt 1 -or
            [long]$body.options.'$top' -gt $authorizedRows -or
            [long]$body.options.'$top' -gt [long]$body.resultLimit) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' 'row_bound_exceeded' $canonical $semanticClass $Intent $Policy
        }
        $rowBoundError = Get-KqlRowBoundError ([string]$body.query) $authorizedRows ([long]$body.resultLimit)
        if ($null -ne $rowBoundError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $rowBoundError $canonical $semanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) 'allowed_bounded_query' $canonical $decisionSemanticClass $Intent $Policy
    }

    if ([string]$operation.bodyValidator -ceq 'genericBoundedQuery') {
        $authorizedRows = [Math]::Min([long]$Intent.bounds.maxRows, [long]$operation.maxRows)
        $resultLimitError = Get-StructuredResultLimitError $body $authorizedRows
        if ($null -ne $resultLimitError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $resultLimitError $canonical $decisionSemanticClass $Intent $Policy
        }
        $rowBoundError = Get-KqlRowBoundError ([string]$body.query) $authorizedRows ([long]$body.resultLimit)
        if ($null -ne $rowBoundError) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' $rowBoundError $canonical $decisionSemanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) 'allowed_bounded_query' $canonical $decisionSemanticClass $Intent $Policy
    }

    if ([string]$operation.operationId -ceq 'purview-audit-query-create') {
        foreach ($filterName in @(
            'ipAddressFilters',
            'objectIdFilters',
            'operationFilters',
            'recordTypeFilters',
            'userPrincipalNameFilters'
        )) {
            if (-not (Test-NonEmptyStringArrayProperty $body $filterName)) {
                return New-Decision $false 'DENY-BODY' 'body_shape_not_allowed' $canonical $semanticClass $Intent $Policy
            }
        }
        if (-not (Test-BodyTimeRange $body.filterStartDateTime $body.filterEndDateTime $Intent.bounds)) {
            return New-Decision $false 'DENY-QUERY-BOUNDS' 'body_time_bound_mismatch' $canonical $semanticClass $Intent $Policy
        }
        $purviewCapabilityError = Get-CapabilityEnvelopeError `
            $CapabilityContext `
            'purview_lifecycle' `
            $Intent `
            $canonical `
            $operation `
            $Policy `
            $PolicyDigest
        if ($null -ne $purviewCapabilityError) {
            return New-Decision $false 'DENY-RETRIEVAL-JOB' $purviewCapabilityError $canonical $semanticClass $Intent $Policy
        }
        return New-Decision $true ([string]$operation.ruleId) 'allowed_retrieval_job' $canonical $semanticClass $Intent $Policy
    }

    return New-Decision $false 'DENY-UNKNOWN-OPERATION' 'operation_not_allowlisted' $canonical 'unknown' $Intent $Policy
}

$policy = $null
$policyIsValid = $false
try {
    $policyBytes = [IO.File]::ReadAllBytes($PolicyPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $actualDigest = [Convert]::ToHexString($sha256.ComputeHash($policyBytes)).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
    if ($actualDigest -cne $PinnedPolicySha256) {
        New-PolicyInvalidDecision | ConvertTo-Json -Depth 10 -Compress
        return
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $policyText = $utf8.GetString($policyBytes)
    $policy = $policyText | ConvertFrom-Json -Depth 50
    if (-not (Test-RequestPolicy $policy)) {
        New-PolicyInvalidDecision | ConvertTo-Json -Depth 10 -Compress
        return
    }
    $policy = ConvertTo-HavocProfilePolicy $policy
    $policyIsValid = $true
    $capabilityContext = Read-CapabilityInput $CapabilityJson $CapabilityPath
    $intent = $IntentJson | ConvertFrom-Json -Depth 50 -DateKind String
    $decision = Test-RequestIntent `
        $intent `
        $policy `
        $capabilityContext `
        $actualDigest
    $decision | ConvertTo-Json -Depth 10 -Compress
    return
}
catch {
    if (-not $policyIsValid) {
        New-PolicyInvalidDecision | ConvertTo-Json -Depth 10 -Compress
        return
    }
    $fallbackPolicy = [pscustomobject]@{
        policyVersion = $PinnedPolicyVersion
        redirectPolicy = $SafeRedirectPolicy
        operations = @()
    }
    $fallbackIntent = [pscustomobject]@{
        requestedScopes = @()
        requestId = $null
        correlationId = $null
        operationId = $null
    }
    New-Decision $false 'DENY-INTENT' 'invalid_intent' $null 'unknown' $fallbackIntent $fallbackPolicy |
        ConvertTo-Json -Depth 10 -Compress
    return
}
