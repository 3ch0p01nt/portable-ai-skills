Set-StrictMode -Version Latest

$script:AdapterVersion = '1.1.0'
$script:NormalizerVersion = '1.0.0'
$script:ResponseAdapterVersion = '1.0.0'
$script:AdapterId = 'havoc-protected-store-adapter'
$script:PwshPath = (Get-Command pwsh -ErrorAction Stop).Source
$script:HavocGuardProcessStarter = $null
$script:CommercialHosts = @(
    'api.loganalytics.azure.com',
    'api.security.microsoft.com',
    'graph.microsoft.com',
    'management.azure.com'
)
$script:HavocAdapterCloud = 'Commercial'
Import-Module (Join-Path $PSScriptRoot 'HavocCloudProfile.psm1') -Force

function Set-HavocAdapterCloudProfile {
    [CmdletBinding()]
    param(
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial'
    )
    $script:HavocAdapterCloud = $Cloud
}

function Get-HavocActiveCloudProfile {
    [CmdletBinding()]
    param()
    Get-HavocCloudProfile -Cloud $script:HavocAdapterCloud
}

function ConvertTo-HavocCanonicalJson {
    param($Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [string]) { return ($Value | ConvertTo-Json -Compress) }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        return (([string]$Value) | ConvertTo-Json -Compress)
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or
        $Value -is [decimal]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [pscustomobject]) {
        return '[' + ((@($Value) | ForEach-Object { ConvertTo-HavocCanonicalJson $_ }) -join ',') + ']'
    }
    $parts = foreach ($name in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) {
        (ConvertTo-HavocCanonicalJson ([string]$name)) + ':' +
            (ConvertTo-HavocCanonicalJson $Value.$name)
    }
    return '{' + ($parts -join ',') + '}'
}

function Get-HavocSha256Hex {
    param([string]$Text)
    [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))
    ).ToLowerInvariant()
}

function Copy-HavocValue {
    param($Value)
    $Value | ConvertTo-Json -Depth 50 -Compress |
        ConvertFrom-Json -Depth 50 -DateKind String
}

function Get-HavocRequestDigest {
    param($Intent)

    $Intent = $Intent | ConvertTo-Json -Depth 100 -Compress |
        ConvertFrom-Json -Depth 100 -DateKind String
    $uri = [uri][string]$Intent.uri
    $query = [Collections.Generic.List[object]]::new()
    if (-not [string]::IsNullOrEmpty($uri.Query)) {
        foreach ($pair in $uri.Query.Substring(1) -split '&') {
            $parts = $pair -split '=', 2
            $query.Add([pscustomobject][ordered]@{
                key = [uri]::UnescapeDataString($parts[0])
                value = if ($parts.Count -eq 2) {
                    [uri]::UnescapeDataString($parts[1])
                }
                else { '' }
            })
        }
    }
    $body = if ($Intent.PSObject.Properties.Name -contains 'body') { $Intent.body } else { $null }
    $canonical = [pscustomobject][ordered]@{
        version = '1'
        host = $uri.IdnHost.ToLowerInvariant()
        method = ([string]$Intent.method).ToUpperInvariant()
        path = [uri]::UnescapeDataString($uri.AbsolutePath)
        query = @($query | Sort-Object { $_.key } -CaseSensitive)
        body_sha256 = Get-HavocSha256Hex (ConvertTo-HavocCanonicalJson $body)
        bounds = $Intent.bounds
        request_id = [string]$Intent.requestId
        correlation_id = [string]$Intent.correlationId
        operation_id = [string]$Intent.operationId
    }
    Get-HavocSha256Hex (ConvertTo-HavocCanonicalJson $canonical)
}

function Get-HavocGraphBatchContinuationIntent {
    param($Intent)
    $profile = Get-HavocActiveCloudProfile

    if ([string]$Intent.operationId -cne 'graph-batch' -or
        $Intent.PSObject.Properties.Name -cnotcontains 'body' -or
        $null -eq $Intent.body -or
        $Intent.body.PSObject.Properties.Name -cnotcontains 'requests' -or
        @($Intent.body.requests).Count -ne 1) {
        return $Intent
    }
    $request = @($Intent.body.requests)[0]
    $url = [string]$request.url
    $operationId = if ($url -cmatch '^/v1\.0/security/incidents(?:\?|$)') {
        'graph-security-incidents-list'
    }
    elseif ($url -cmatch '^/v1\.0/security/alerts_v2(?:\?|$)') {
        'graph-security-alerts-list'
    }
    elseif ($url -cmatch '^/v1\.0/security/incidents/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?:\?(?:%24|\$)expand=alerts)?$') {
        'graph-security-incident-with-alerts-get'
    }
    else {
        return $Intent
    }
    $safeId = [string]$request.id
    if ($safeId -cnotmatch '^[A-Za-z0-9._:-]{1,128}$') {
        $safeId = 'batch-continuation'
    }
    $safeCorrelationId = [string]$Intent.correlationId
    if ($safeCorrelationId -cnotmatch '^[A-Za-z0-9._:-]{1,128}$') {
        $safeCorrelationId = 'batch-continuation'
    }
    [pscustomobject][ordered]@{
        requestId = $safeId
        correlationId = $safeCorrelationId
        operationId = $operationId
        method = ([string]$request.method).ToUpperInvariant()
        uri = "https://$([string]$profile.graphHost)$url"
        requestedScopes = @($Intent.requestedScopes | ForEach-Object { [string]$_ })
        tokenScopes = @($Intent.tokenScopes | ForEach-Object { [string]$_ })
        tokenRoles = @($Intent.tokenRoles | ForEach-Object { [string]$_ })
        expected_principal_ref = [string]$Intent.expected_principal_ref
        expected_source_scope_refs = @($Intent.expected_source_scope_refs)
        autoFollowRedirects = $false
        bounds = $Intent.bounds
    }
}

function Get-HavocSigningKey {
    $encoded = [Environment]::GetEnvironmentVariable(
        'HAVOC_CAPABILITY_SIGNING_KEY',
        'Process'
    )
    if ([string]::IsNullOrWhiteSpace($encoded) -or
        $encoded -cnotmatch '^[A-Za-z0-9+/]+={0,2}$' -or
        ($encoded.Length % 4) -ne 0) {
        throw 'Adapter capability signing key is unavailable'
    }

    try {
        $bytes = [Convert]::FromBase64String($encoded)
    }
    catch {
        throw 'Adapter capability signing key is invalid'
    }
    if ($bytes.Length -lt 32) {
        [Array]::Clear($bytes, 0, $bytes.Length)
        throw 'Adapter capability signing key is invalid'
    }
    return ,$bytes
}

function Get-HavocResourceBindingKey {
    $encoded = [Environment]::GetEnvironmentVariable(
        'HAVOC_RESOURCE_BINDING_KEY',
        'Process'
    )
    if ([string]::IsNullOrWhiteSpace($encoded) -or
        $encoded -cnotmatch '^[A-Za-z0-9+/]+={0,2}$' -or
        ($encoded.Length % 4) -ne 0) {
        throw 'Resource binding key is unavailable'
    }
    try {
        $bytes = [Convert]::FromBase64String($encoded)
    }
    catch {
        throw 'Resource binding key is invalid'
    }
    if ($bytes.Length -lt 32) {
        [Array]::Clear($bytes, 0, $bytes.Length)
        throw 'Resource binding key is invalid'
    }
    return ,$bytes
}

function Get-HavocCanonicalResourceString {
    param($Intent, [string]$PolicyPath)

    $profile = Get-HavocActiveCloudProfile
    $policy = Get-Content -LiteralPath $PolicyPath -Raw |
        ConvertFrom-Json -Depth 100
    $operations = @($policy.operations | Where-Object {
        [string]$_.operationId -ceq [string]$Intent.operationId
    })
    if ($operations.Count -ne 1) {
        throw 'Canonical resource operation is unavailable'
    }
    $operation = $operations[0]
    $uri = [uri][string]$Intent.uri
    $uriHost = $uri.IdnHost.ToLowerInvariant()
    $expectedHost = switch ([string]$operation.host) {
        'graph.microsoft.com' { [string]$profile.graphHost }
        'management.azure.com' { [string]$profile.armHost }
        'api.loganalytics.azure.com' { [string]$profile.logAnalyticsHost }
        'api.loganalytics.io' { [string]$profile.logAnalyticsHost }
        default { [string]$operation.host }
    }
    if ($expectedHost -cne $uriHost) {
        throw 'Canonical resource host does not match the operation'
    }
    $path = [uri]::UnescapeDataString($uri.AbsolutePath)
    $query = [ordered]@{}
    if (-not [string]::IsNullOrEmpty($uri.Query)) {
        foreach ($pair in $uri.Query.Substring(1) -split '&') {
            if ([string]::IsNullOrEmpty($pair)) {
                throw 'Canonical resource query is invalid'
            }
            $parts = $pair -split '=', 2
            $key = [uri]::UnescapeDataString($parts[0].Replace('+', ' '))
            $value = if ($parts.Count -eq 2) {
                [uri]::UnescapeDataString($parts[1].Replace('+', ' '))
            }
            else { '' }
            if ($query.Contains($key)) {
                throw 'Canonical resource query contains duplicate keys'
            }
            $query[$key] = $value
        }
    }
    $allowedKeys = @([string[]]$operation.allowedQueryKeys)
    if ([string]$operation.host -ceq 'graph.microsoft.com' -and
        [string]$operation.method -ceq 'GET') {
        $allowedKeys += '$skiptoken'
        $allowedKeys += '$skipToken'
    }
    if (@($query.Keys | Where-Object {
        $allowedKeys -cnotcontains [string]$_
    }).Count -gt 0) {
        throw 'Canonical resource query contains an unapproved key'
    }
    $apiVersion = if ($query.Contains('api-version')) {
        [string]$query['api-version']
    }
    elseif ($path -cmatch '^/(v[0-9]+(?:\.[0-9]+)*)/') {
        [string]$Matches[1]
    }
    else { 'not-applicable' }
    $canonical = [pscustomobject][ordered]@{
        version = '1'
        operation_id = [string]$Intent.operationId
        host = $uriHost
        path = $path
        structural_query_keys = @($query.Keys | Sort-Object -CaseSensitive)
        api_version = $apiVersion
    }
    if ($Intent.PSObject.Properties.Name -ccontains 'body' -and
        $null -ne $Intent.body) {
        $scopeBody = [ordered]@{}
        foreach ($name in @('subscriptions', 'managementGroups')) {
            if ($Intent.body.PSObject.Properties.Name -ccontains $name) {
                $values = @($Intent.body.$name | ForEach-Object {
                    [string]$_
                } | Sort-Object -CaseSensitive)
                $scopeBody[$name] = @($values)
            }
        }
        if ($scopeBody.Count -gt 0) {
            $canonical | Add-Member -NotePropertyName scope_body `
                -NotePropertyValue ([pscustomobject]$scopeBody)
        }
    }
    ConvertTo-HavocCanonicalJson $canonical
}

function Get-HavocResourceBindingHmac {
    param([string]$CanonicalResource)

    $key = Get-HavocResourceBindingKey
    $hmac = [Security.Cryptography.HMACSHA256]::new($key)
    try {
        [Convert]::ToBase64String($hmac.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($CanonicalResource)
        ))
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Get-HavocCapabilityBindingHmac {
    param([string]$Value)

    $key = Get-HavocSigningKey
    $hmac = [Security.Cryptography.HMACSHA256]::new($key)
    try {
        [Convert]::ToBase64String($hmac.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($Value)
        ))
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Test-HavocResourceBindingHmac {
    param([string]$Expected, [string]$Actual)

    try {
        $expectedBytes = [Convert]::FromBase64String($Expected)
        $actualBytes = [Convert]::FromBase64String($Actual)
    }
    catch {
        return $false
    }
    try {
        if ($expectedBytes.Length -ne 32 -or $actualBytes.Length -ne 32) {
            return $false
        }
        [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
            $expectedBytes,
            $actualBytes
        )
    }
    finally {
        [Array]::Clear($expectedBytes, 0, $expectedBytes.Length)
        [Array]::Clear($actualBytes, 0, $actualBytes.Length)
    }
}

function Test-HavocMinimumVersion {
    param($Value, [version]$Minimum)

    if ($Value -isnot [string] -or
        [string]$Value -cnotmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$') {
        return $false
    }
    $parsed = $null
    if (-not [version]::TryParse([string]$Value, [ref]$parsed)) {
        return $false
    }
    $parsed -ge $Minimum
}

function New-HavocCapability {
    param(
        $Intent,
        [ValidateSet(
            'response_enforcement',
            'purview_lifecycle',
            'continuation_link',
            'continuation_token'
        )]
        [string]$Kind,
        [string]$PolicyPath,
        [scriptblock]$Clock = { [datetimeoffset]::UtcNow },
        $TrustedPreconditions = $null
    )

    $policy = Get-Content -LiteralPath $PolicyPath -Raw |
        ConvertFrom-Json -Depth 50
    $capabilityIntent = if ($Kind -ceq 'continuation_link') {
        Get-HavocGraphBatchContinuationIntent $Intent
    }
    else { $Intent }
    $operation = @($policy.operations | Where-Object {
        [string]$_.operationId -ceq [string]$capabilityIntent.operationId
    })
    if ($operation.Count -ne 1) {
        throw 'Adapter capability operation is not present in policy'
    }
    $claims = if ($Kind -ceq 'response_enforcement') {
        [pscustomobject][ordered]@{
            operation_id = [string]$operation[0].operationId
            rule_id = [string]$operation[0].ruleId
            adapter_id = $script:AdapterId
            adapter_version = $script:ResponseAdapterVersion
            max_bytes = [long]$Intent.bounds.maxBytes
            byte_limit_enforced = $true
            partial_response_detection = $true
            truncation_detection = $true
            actual_bytes_recording = $true
        }
    }
    elseif ($Kind -ceq 'continuation_link') {
        [pscustomobject][ordered]@{
            operation_id = [string]$operation[0].operationId
            rule_id = [string]$operation[0].ruleId
            next_link = [string]$capabilityIntent.uri
            next_link_hmac = Get-HavocCapabilityBindingHmac ([string]$capabilityIntent.uri)
        }
    }
    elseif ($Kind -ceq 'continuation_token') {
        $token = ''
        if ($Intent.PSObject.Properties.Name -ccontains 'body' -and
            $null -ne $Intent.body -and
            $Intent.body.PSObject.Properties.Name -ccontains 'options' -and
            $null -ne $Intent.body.options -and
            $Intent.body.options.PSObject.Properties.Name -ccontains '$skipToken') {
            $token = [string]$Intent.body.options.'$skipToken'
        }
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw 'Continuation token evidence is missing'
        }
        [pscustomobject][ordered]@{
            operation_id = [string]$operation[0].operationId
            rule_id = [string]$operation[0].ruleId
            continuation_token_hmac = Get-HavocCapabilityBindingHmac $token
            adapter_id = $script:AdapterId
            adapter_version = $script:ResponseAdapterVersion
            max_bytes = [long]$Intent.bounds.maxBytes
        }
    }
    else {
        $purviewScopeMap = [ordered]@{
            Entra = 'AuditLogsQuery-Entra.Read.All'
            AzureActiveDirectory = 'AuditLogsQuery-Entra.Read.All'
            Exchange = 'AuditLogsQuery-Exchange.Read.All'
            OneDrive = 'AuditLogsQuery-OneDrive.Read.All'
            SharePoint = 'AuditLogsQuery-SharePoint.Read.All'
        }
        if ($Intent.PSObject.Properties.Name -cnotcontains 'body' -or
            $null -eq $Intent.body -or
            $Intent.body.PSObject.Properties.Name -cnotcontains 'serviceFilter' -or
            $Intent.body.PSObject.Properties.Name -ccontains 'serviceFilters' -or
            [string]::IsNullOrWhiteSpace([string]$Intent.body.serviceFilter) -or
            $purviewScopeMap.Keys -cnotcontains [string]$Intent.body.serviceFilter) {
            throw 'Purview lifecycle precondition evidence is invalid: serviceFilter'
        }
        if ($null -eq $TrustedPreconditions) {
            throw 'Purview lifecycle precondition evidence is missing'
        }
        $preconditions = $TrustedPreconditions
        $preconditionFlags = @(
            'operational_necessity_verified',
            'lifecycle_verified',
            'persistence_verified',
            'visibility_sharing_verified',
            'retention_expiry_verified',
            'side_effects_verified',
            'least_privilege_verified',
            'bounded_request_verified',
            'commercial_endpoint_verified',
            'report_disclosure_planned'
        )
        $requestDigest = Get-HavocRequestDigest $Intent
        if ($preconditions.PSObject.Properties.Name -cnotcontains
                'canonical_request_digest' -or
            [string]$preconditions.canonical_request_digest -cne
                $requestDigest -or
            $preconditions.PSObject.Properties.Name -cnotcontains
                'request_digest_hmac' -or
            [string]$preconditions.request_digest_hmac -cne
                (Get-HavocCapabilityBindingHmac $requestDigest) -or
            $preconditions.PSObject.Properties.Name -cnotcontains 'evidence_ref' -or
            -not (Test-HavocProtectedReference $preconditions.evidence_ref @('protected-evidence')) -or
            @($preconditionFlags | Where-Object {
                $preconditions.PSObject.Properties.Name -cnotcontains $_ -or
                $preconditions.$_ -isnot [bool] -or
                -not [bool]$preconditions.$_
            }).Count -gt 0) {
            throw 'Purview lifecycle precondition evidence is incomplete'
        }
        $workloads = @([string]$Intent.body.serviceFilter)
        $workloadPermissions = @($workloads | ForEach-Object {
            [string]$purviewScopeMap[[string]$_]
        } | Sort-Object -CaseSensitive)
        $claimSet = [pscustomobject][ordered]@{
            operation_id = [string]$operation[0].operationId
            rule_id = [string]$operation[0].ruleId
            workloads = @($workloads)
            workload_permissions = @($workloadPermissions)
            precondition_evidence_ref = [string]$preconditions.evidence_ref
            precondition_binding_hmac =
                [string]$preconditions.request_digest_hmac
        }
        foreach ($flag in $preconditionFlags) {
            $claimSet | Add-Member -NotePropertyName $flag `
                -NotePropertyValue ([bool]$preconditions.$flag)
        }
        $claimSet
    }
    $now = (& $Clock).ToUniversalTime()
    $capability = [pscustomobject][ordered]@{
        capability_kind = $Kind
        issuer_id = 'havoc-adapter-orchestrator'
        issuer_version = '1.0.0'
        policy_version = [string]$policy.policyVersion
        policy_digest = (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        canonical_request_digest = Get-HavocRequestDigest $capabilityIntent
        issued_at = $now.AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        expires_at = $now.AddMinutes(2).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        nonce = [guid]::NewGuid().ToString('N')
        claims = $claims
        key_id = 'havoc-capability-hmac-v1'
        signature_algorithm = 'HMAC-SHA256'
        signature = ''
    }
    $unsigned = [pscustomobject][ordered]@{}
    foreach ($property in $capability.PSObject.Properties) {
        if ($property.Name -cne 'signature') {
            $unsigned | Add-Member -NotePropertyName $property.Name `
                -NotePropertyValue $property.Value
        }
    }
    $key = Get-HavocSigningKey
    $hmac = [Security.Cryptography.HMACSHA256]::new($key)
    try {
        $capability.signature = [Convert]::ToBase64String(
            $hmac.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes(
                    (ConvertTo-HavocCanonicalJson $unsigned)
                )
            )
        )
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($key, 0, $key.Length)
    }
    $capability
}

function Invoke-HavocGuard {
    param(
        $Intent,
        [string]$PolicyPath,
        $Capability,
        [scriptblock]$Clock = { [datetimeoffset]::UtcNow }
    )

    $guardPath = Join-Path $PSScriptRoot 'Test-ReadOnlyRequest.ps1'
    $ipc = [pscustomobject][ordered]@{
        version = '1.0.0'
        policyPath = $PolicyPath
        intent = $Intent
        capabilities = if ($null -ne $Capability) { @($Capability) } else { @() }
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:PwshPath
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-File',
        $guardPath,
        '-StdinEnvelope',
        '-Cloud',
        $script:HavocAdapterCloud
    )
    $arguments += @(
        '-CurrentTime',
        (& $Clock).ToUniversalTime().ToString('o')
    )
    foreach ($argument in $arguments) {
        $start.ArgumentList.Add($argument)
    }
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $processStarter = $script:HavocGuardProcessStarter
    $process = if ($null -ne $processStarter) {
        & $processStarter $start
    }
    else {
        [Diagnostics.Process]::Start($start)
    }
    try {
        $process.StandardInput.WriteLine(
            ($ipc | ConvertTo-Json -Depth 100 -Compress)
        )
        $process.StandardInput.Close()
        $output = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        if (-not $process.WaitForExit(10000) -or
            $process.ExitCode -ne 0 -or
            [string]::IsNullOrWhiteSpace($output)) {
            throw 'Read-only request guard failed closed'
        }
        $output | ConvertFrom-Json -Depth 50
    }
    finally {
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill($true) }
            $process.Dispose()
        }
    }
}

function Copy-HavocTransportIntent {
    param($Intent)

    $allowed = @(
        'requestId',
        'correlationId',
        'operationId',
        'method',
        'uri',
        'requestedScopes',
        'tokenScopes',
        'tokenRoles',
        'expected_principal_ref',
        'expected_source_scope_refs',
        'autoFollowRedirects',
        'bounds',
        'body',
        'credentialClass',
        'armRbacReadApproved',
        'responseEnforcement'
    )
    $copy = [pscustomobject][ordered]@{}
    foreach ($name in $allowed) {
        if ($Intent.PSObject.Properties.Name -ccontains $name) {
            if (@(
                'requestedScopes',
                'tokenScopes',
                'tokenRoles',
                'expected_source_scope_refs'
            ) -ccontains $name) {
                $list = [Collections.Generic.List[object]]::new()
                foreach ($item in @($Intent.$name)) {
                    $list.Add($item)
                }
                $copy | Add-Member -NotePropertyName $name `
                    -NotePropertyValue $list
                continue
            }
            $copy | Add-Member -NotePropertyName $name `
                -NotePropertyValue (Copy-HavocValue $Intent.$name)
        }
    }
    $copy
}

function ConvertTo-HavocHeaders {
    param($Headers)
    $result = @{}
    if ($null -eq $Headers) { return $result }
    if ($Headers -is [Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            $result[[string]$key] = [string]$Headers[$key]
        }
        return $result
    }
    foreach ($property in $Headers.PSObject.Properties) {
        $result[[string]$property.Name] = [string]$property.Value
    }
    $result
}

function Get-HavocHeader {
    param($Headers, [string]$Name)
    foreach ($key in @($Headers.Keys)) {
        if ([string]$key -ieq $Name) { return [string]$Headers[$key] }
    }
    return $null
}

function Get-HavocErrorCategory {
    param([int]$StatusCode)
    switch ($StatusCode) {
        { $_ -in 401, 403 } { return 'permission_denied' }
        402 { return 'license_unavailable' }
        408 { return 'source_unavailable' }
        429 { return 'throttled' }
        default { return 'source_unavailable' }
    }
}

function Get-HavocResponseFailure {
        param($Response)

        $serviceCode = ''
        try {
            $parsed = [string]$Response.Content |
                ConvertFrom-Json -Depth 20 -DateKind String
            if ($parsed.PSObject.Properties.Name -contains 'error' -and
                $null -ne $parsed.error -and
                $parsed.error.PSObject.Properties.Name -contains 'code' -and
                [string]$parsed.error.code -cmatch '^[A-Za-z0-9._-]{1,128}$') {
                $serviceCode = [string]$parsed.error.code
            }
        }
        catch {
        }
        switch -CaseSensitive ($serviceCode) {
            { $_ -in @('LicenseRequired', 'CapabilityNotEnabled', 'LicenseNotAvailable') } {
                return [pscustomobject]@{
                    Category = 'license_unavailable'
                    Code = 'license_or_capability_absent'
                    Message = 'The required license or source capability is unavailable.'
                }
            }
            { $_ -in @('TableNotFound', 'AuditDisabled', 'TableDisabled') } {
                return [pscustomobject]@{
                    Category = 'coverage_gap'
                    Code = 'table_or_audit_disabled'
                    Message = 'The required table or audit source is disabled or unavailable.'
                }
            }
            { $_ -in @('RetentionWindowExceeded', 'DataExpired', 'RetentionExpired') } {
                return [pscustomobject]@{
                    Category = 'retention_boundary'
                    Code = 'retention_window_exceeded'
                    Message = 'The requested evidence is outside the available retention window.'
                }
            }
            { $_ -in @('SourceNotOnboarded', 'WorkspaceNotOnboarded', 'NotOnboarded') } {
                return [pscustomobject]@{
                    Category = 'coverage_gap'
                    Code = 'source_not_onboarded'
                    Message = 'The requested source is not onboarded.'
                }
            }
        }
        [pscustomobject]@{
            Category = Get-HavocErrorCategory ([int]$Response.StatusCode)
            Code = "http_$([int]$Response.StatusCode)"
            Message = "Source returned HTTP $([int]$Response.StatusCode)."
        }
    }

    function Get-HavocAcceptedAudiences {
        param($Intent)

        $profile = Get-HavocActiveCloudProfile
        $uriHost = ([uri][string]$Intent.uri).IdnHost.ToLowerInvariant()
        if ($uriHost -ceq [string]$profile.graphHost) { return @($profile.graphAudiences) }
        if ($uriHost -ceq [string]$profile.armHost) { return @($profile.armAudiences) }
        if ($uriHost -ceq [string]$profile.logAnalyticsHost) { return @([string]$profile.logAnalyticsAudience) }
        if ($uriHost -ceq 'api.security.microsoft.com' -and [string]$profile.name -ceq 'Commercial') { return @('https://api.security.microsoft.com') }
        @('unknown')
    }

    function Get-HavocExpectedAudience {
        param($Intent)

        [string]@((Get-HavocAcceptedAudiences $Intent))[0]
    }

    function Get-HavocCanonicalResourceTemplate {
        param($Intent, $Operation)

        if ($null -ne $Operation -and
            $Operation.PSObject.Properties.Name -ccontains 'path') {
            return [string]$Operation.path
        }
        switch ([string]$Intent.operationId) {
            'sentinel-incident-get' {
                '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}'
            }
            'sentinel-incident-relations-list' {
                '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/relations'
            }
            'sentinel-incident-entities-list' {
                '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/entities'
            }
            'sentinel-incident-comments-list' {
                '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/comments'
            }
            'sentinel-analytics-rule-get' {
                '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules/{ruleId}'
            }
            'log-analytics-query' {
                '/v1/workspaces/{workspaceId}/query'
            }
            default {
                "/operation/$([string]$Intent.operationId)"
            }
        }
    }

    function Invoke-HavocProductionAuthContextProvider {
        param($Binding)

        $command = Get-Command 'Get-HavocVerifiedAuthContext' -CommandType Function, Cmdlet `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $command) {
            throw 'Verified production auth context provider is unavailable'
        }
        & $command -Binding $Binding
    }

    function Resolve-HavocAuthContext {
        param(
            $Intent,
            [string]$PolicyPath,
            [scriptblock]$AuthContextProvider,
            [scriptblock]$Clock
        )

        $profile = Get-HavocActiveCloudProfile
        $audience = Get-HavocExpectedAudience $Intent
        $expectedCloud = if ([string]$profile.name -ceq 'Commercial') { 'commercial' } else { [string]$profile.name }
        $requiredPermissions = @()
        $operationRecord = $null
        try {
            $policy = Get-Content -LiteralPath $PolicyPath -Raw |
                ConvertFrom-Json -Depth 100
            $operation = @($policy.operations | Where-Object {
                [string]$_.operationId -ceq [string]$Intent.operationId
            })
            if ($operation.Count -eq 1) {
                $operationRecord = $operation[0]
                $requiredPermissions =
                    @([string[]]$operationRecord.requiredTokenPermissions)
            }
        }
        catch {
        }
        if ($null -eq $operationRecord) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_operation_binding_missing'
            }
        }
        try {
            $canonicalResource =
                Get-HavocCanonicalResourceString $Intent $PolicyPath
            $expectedResourceHmac =
                Get-HavocResourceBindingHmac $canonicalResource
        }
        catch {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_resource_binding_key_unavailable'
            }
        }
        $binding = [pscustomobject][ordered]@{
            operationId = [string]$Intent.operationId
            requestId = [string]$Intent.requestId
            correlationId = [string]$Intent.correlationId
            cloud = $expectedCloud
            audience = $audience
            accepted_audiences = @((Get-HavocAcceptedAudiences $Intent))
            requiredPermissions = @($requiredPermissions)
            canonical_resource_string = $canonicalResource
            expected_principal_ref = if ($Intent.PSObject.Properties.Name -contains
                'expected_principal_ref') {
                [string]$Intent.expected_principal_ref
            }
            else { 'unknown:none' }
            expected_source_scope_refs = if (
                $Intent.PSObject.Properties.Name -contains
                    'expected_source_scope_refs') {
                @($Intent.expected_source_scope_refs)
            }
            else { @() }
        }
        try {
            $context = if ($null -ne $AuthContextProvider) {
                & $AuthContextProvider $binding
            }
            else {
                Invoke-HavocProductionAuthContextProvider $binding
            }
        }
        catch {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_unavailable'
                Binding = $binding
            }
        }
        if ($null -eq $context -or
            $context -isnot [pscustomobject] -and
            $context -isnot [Collections.IDictionary]) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        if ($null -eq $context -or
            ($context -isnot [pscustomobject] -and
                $context -isnot [Collections.IDictionary])) {
            return [pscustomobject]@{ Success = $false; Code = 'provenance_context_malformed' }
        }
        $required = @(
            'cloud', 'audience', 'tenant_context_ref', 'authorized_tenant',
            'expires_at', 'recognized_permissions', 'principal_ref',
            'credential_class', 'autonomous_read_approved',
            'source_scope_refs', 'arm_rbac_read_approved',
            'resource_bindings', 'excess_privilege_present',
            'license_capabilities', 'effective_retention_days_by_source',
            'auth_context_issued_at', 'provider_id', 'provider_version'
        )
        $names = @($context.PSObject.Properties.Name)
        if (@($required | Where-Object { $names -cnotcontains $_ }).Count -gt 0 -or
            @($names | Where-Object { $required -cnotcontains $_ }).Count -gt 0) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        if ($context.cloud -isnot [string] -or
            [string]$context.cloud -cne $expectedCloud) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_cloud_mismatch'
                Binding = $binding
            }
        }
        if ($context.audience -isnot [string] -or
            @($binding.accepted_audiences) -cnotcontains [string]$context.audience) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_audience_mismatch'
                Binding = $binding
            }
        }
        if ($context.authorized_tenant -isnot [bool]) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        if (-not [bool]$context.authorized_tenant) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_tenant_mismatch'
                Binding = $binding
            }
        }
        $validationNow = (& $Clock).ToUniversalTime()
        $expiry = [datetimeoffset]::MinValue
        if ($context.expires_at -isnot [string] -or
            [string]$context.expires_at -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})$' -or
            -not [datetimeoffset]::TryParse(
                [string]$context.expires_at,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor
                    [Globalization.DateTimeStyles]::AdjustToUniversal,
                [ref]$expiry
            ) -or $expiry.ToUniversalTime() -le $validationNow) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_expired'
                Binding = $binding
            }
        }
        if ($context.recognized_permissions -isnot [System.Array]) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        $permissions = @([string[]]$context.recognized_permissions)
        if (@($context.recognized_permissions | Where-Object {
            $_ -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$_) -or
            [string]$_ -cnotmatch '^(?:[A-Za-z][A-Za-z0-9.:-]{1,255}|user_impersonation)$'
        }).Count -gt 0 -or
            @($permissions | Select-Object -Unique).Count -ne
                $permissions.Count) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_scope_unrecognized'
                Binding = $binding
            }
        }
        if ([string]$context.credential_class -ceq 'delegated' -and
            @($requiredPermissions | Where-Object {
                $permissions -cnotcontains $_
            }).Count -gt 0) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_scope_missing'
                Binding = $binding
            }
        }
        if (-not (Test-HavocProtectedReference $context.tenant_context_ref @('protected-context'))) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_tenant_ref_invalid'
                Binding = $binding
            }
        }
        if (-not (Test-HavocProtectedReference $context.principal_ref @('protected-context')) -or
            @('application', 'delegated') -cnotcontains [string]$context.credential_class -or
            $context.autonomous_read_approved -isnot [bool] -or
            $context.excess_privilege_present -isnot [bool] -or
            $context.arm_rbac_read_approved -isnot [bool] -or
            $context.source_scope_refs -isnot [System.Array] -or
            $context.resource_bindings -isnot [System.Array] -or
            $context.license_capabilities -isnot [System.Array] -or
            $context.effective_retention_days_by_source -isnot [pscustomobject] -or
            $context.auth_context_issued_at -isnot [string] -or
            $context.provider_id -isnot [string] -or
            [string]$context.provider_id -cne 'havoc-auth-context-provider' -or
            -not (Test-HavocMinimumVersion $context.provider_version ([version]'3.0.0'))) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        $issuedAt = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse(
            [string]$context.auth_context_issued_at,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$issuedAt
        ) -or $issuedAt.ToUniversalTime() -gt $validationNow) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        if (@($context.source_scope_refs).Count -lt 1 -or
            @($context.resource_bindings).Count -lt 1) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_source_scope_mismatch'
                Binding = $binding
            }
        }
        $expectedScopeRefs = @([string[]]$binding.expected_source_scope_refs)
        if (@($expectedScopeRefs | Where-Object {
            -not (Test-HavocProtectedReference $_ @('protected-context'))
        }).Count -gt 0 -or
            @($expectedScopeRefs | Select-Object -Unique).Count -ne
                $expectedScopeRefs.Count) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_source_scope_mismatch'
                Binding = $binding
            }
        }
        if ([string]$Intent.operationId -ceq 'azure-resource-graph-query') {
            $bodySubscriptions = @()
            $bodyManagementGroups = @()
            if ($Intent.PSObject.Properties.Name -ccontains 'body' -and $null -ne $Intent.body) {
                if ($Intent.body.PSObject.Properties.Name -ccontains 'subscriptions') {
                    $bodySubscriptions = @([string[]]$Intent.body.subscriptions)
                }
                if ($Intent.body.PSObject.Properties.Name -ccontains 'managementGroups') {
                    $bodyManagementGroups = @([string[]]$Intent.body.managementGroups)
                }
            }
            $requiredArgScopeRefs = @(
                $bodySubscriptions | ForEach-Object { "protected-context:subscription/$_" }
                $bodyManagementGroups | ForEach-Object { "protected-context:management-group/$_" }
            )
            if ($requiredArgScopeRefs.Count -lt 1 -or
                @($requiredArgScopeRefs | Select-Object -Unique).Count -ne
                    $requiredArgScopeRefs.Count -or
                (@($expectedScopeRefs | Sort-Object -CaseSensitive) -join "`n") -cne
                    (@($requiredArgScopeRefs | Sort-Object -CaseSensitive) -join "`n")) {
                return [pscustomobject]@{
                    Success = $false
                    Code = 'auth_source_scope_mismatch'
                    Binding = $binding
                }
            }
        }
        $contextScopeRefs = @([string[]]$context.source_scope_refs)
        if (@($contextScopeRefs | Select-Object -Unique).Count -ne
                $contextScopeRefs.Count -or
            (@($contextScopeRefs | Sort-Object -CaseSensitive) -join "`n") -cne
                (@($expectedScopeRefs | Sort-Object -CaseSensitive) -join "`n")) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_source_scope_mismatch'
                Binding = $binding
            }
        }
        if (-not [bool]$context.autonomous_read_approved) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_autonomous_read_not_approved'
                Binding = $binding
            }
        }
        if ([bool]$context.excess_privilege_present) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_excess_privilege'
                Binding = $binding
            }
        }
        foreach ($reference in @($context.source_scope_refs)) {
            if (-not (Test-HavocProtectedReference $reference @('protected-context'))) {
                return [pscustomobject]@{
                    Success = $false
                    Code = 'auth_context_malformed'
                    Binding = $binding
                }
            }
        }
        if (@($profile.armAudiences) -ccontains $audience -and
            [string]$context.credential_class -ceq 'application' -and
            -not [bool]$context.arm_rbac_read_approved) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_arm_rbac_read_not_approved'
                Binding = $binding
            }
        }
        if (@($profile.armAudiences) -cnotcontains $audience -and
            [bool]$context.arm_rbac_read_approved) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        $allBindingScopeRefs = @($context.resource_bindings | ForEach-Object {
            if ($_ -is [pscustomobject] -and
                $_.PSObject.Properties.Name -ccontains 'source_scope_ref') {
                [string]$_.source_scope_ref
            }
            else { '' }
        })
        if ($allBindingScopeRefs.Count -ne $expectedScopeRefs.Count -or
            @($allBindingScopeRefs | Select-Object -Unique).Count -ne
                $allBindingScopeRefs.Count -or
            (@($allBindingScopeRefs | Sort-Object -CaseSensitive) -join "`n") -cne
                (@($expectedScopeRefs | Sort-Object -CaseSensitive) -join "`n")) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_resource_binding_mismatch'
                Binding = $binding
            }
        }
        $matchingBindings = @($context.resource_bindings | Where-Object {
            $_ -is [pscustomobject] -and
            (@($_.PSObject.Properties.Name | Sort-Object) -join ',') -ceq
                'operation_id,principal_ref,resource_binding_hmac,resource_identifier_ref,source_scope_ref' -and
            [string]$_.operation_id -ceq [string]$Intent.operationId -and
            [string]$_.principal_ref -ceq
                [string]$binding.expected_principal_ref -and
            $expectedScopeRefs -ccontains
                [string]$_.source_scope_ref -and
            $(Test-HavocResourceBindingHmac $expectedResourceHmac `
                ([string]$_.resource_binding_hmac))
        })
        if ($matchingBindings.Count -ne $expectedScopeRefs.Count -or
            (@($matchingBindings.source_scope_ref | Sort-Object -CaseSensitive) -join "`n") -cne
                (@($expectedScopeRefs | Sort-Object -CaseSensitive) -join "`n") -or
            @($matchingBindings | Where-Object {
                -not (Test-HavocProtectedReference `
                    $_.resource_identifier_ref @('protected-context')) -or
                -not (Test-HavocProtectedReference `
                    $_.principal_ref @('protected-context')) -or
                -not (Test-HavocProtectedReference `
                    $_.source_scope_ref @('protected-context'))
            }).Count -gt 0) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_resource_binding_mismatch'
                Binding = $binding
            }
        }
        $licenseValues = @('entra_free', 'entra_p1', 'entra_p2', 'sentinel')
        if (@($context.license_capabilities | Where-Object {
            $_ -isnot [string] -or $licenseValues -cnotcontains [string]$_
        }).Count -gt 0 -or
            @($context.license_capabilities | Select-Object -Unique).Count -ne
                @($context.license_capabilities).Count) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_context_malformed'
                Binding = $binding
            }
        }
        foreach ($property in @($context.effective_retention_days_by_source.PSObject.Properties)) {
            $entry = $property.Value
            if ($property.Name -notin @('entra_signins', 'entra_directory_audits') -or
                $entry -isnot [pscustomobject] -or
                (@($entry.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                    'days,evidence_ref' -or
                -not (Test-HavocInt64 $entry.days $true) -or [int64]$entry.days -lt 1 -or
                -not (Test-HavocProtectedReference $entry.evidence_ref @('protected-evidence'))) {
                return [pscustomobject]@{
                    Success = $false
                    Code = 'auth_context_malformed'
                    Binding = $binding
                }
            }
        }
        if ($binding.expected_principal_ref -ceq 'unknown:none' -or
            [string]$context.principal_ref -cne
                [string]$binding.expected_principal_ref) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_principal_binding_mismatch'
                Binding = $binding
            }
        }
        if (@($binding.expected_source_scope_refs).Count -lt 1 -or
            @($binding.expected_source_scope_refs | Where-Object {
                @($context.source_scope_refs) -cnotcontains [string]$_
            }).Count -gt 0) {
            return [pscustomobject]@{
                Success = $false
                Code = 'auth_source_scope_mismatch'
                Binding = $binding
            }
        }
        [pscustomobject]@{
            Success = $true
            Code = 'not-applicable:none'
            Binding = $binding
            Context = [pscustomobject][ordered]@{
                cloud = $expectedCloud
                audience = $audience
                authorized_tenant = $true
                expires_at = $expiry.ToUniversalTime().ToString('o')
                recognized_permissions = @($permissions)
                tenant_context_ref = [string]$context.tenant_context_ref
                principal_ref = [string]$context.principal_ref
                credential_class = [string]$context.credential_class
                autonomous_read_approved = $true
                source_scope_refs = @($context.source_scope_refs)
                arm_rbac_read_approved =
                    [bool]$context.arm_rbac_read_approved
                resource_binding = Copy-HavocValue $matchingBindings[0]
                resource_bindings = @($matchingBindings | ForEach-Object {
                    Copy-HavocValue $_
                })
                excess_privilege_present = $false
                license_capabilities = @($context.license_capabilities)
                effective_retention_days_by_source =
                    Copy-HavocValue $context.effective_retention_days_by_source
                auth_context_issued_at = [string]$context.auth_context_issued_at
                provider_id = [string]$context.provider_id
                provider_version = [string]$context.provider_version
            }
        }
}

function Invoke-HavocProductionProvenanceContextProvider {
    param($Binding)
    $command = Get-Command 'Get-HavocVerifiedProvenanceContext' `
        -CommandType Function, Cmdlet -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        throw 'Verified production provenance context provider is unavailable'
    }
    & $command -Binding $Binding
}

function Resolve-HavocProvenanceContext {
    param(
        $Intent,
        [scriptblock]$ProvenanceContextProvider,
        [string]$PolicyPath
    )

    try {
        $policy = Get-Content -LiteralPath $PolicyPath -Raw |
            ConvertFrom-Json -Depth 100
        $operations = @($policy.operations | Where-Object {
            [string]$_.operationId -ceq [string]$Intent.operationId
        })
        if ($operations.Count -ne 1) {
            throw 'Operation binding unavailable'
        }
        $resourceTemplate =
            Get-HavocCanonicalResourceString $Intent $PolicyPath
        $expectedResourceHmac =
            Get-HavocResourceBindingHmac $resourceTemplate
        $requestDigest = Get-HavocRequestDigest $Intent
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Code = 'provenance_operation_binding_missing'
        }
    }
    $binding = [pscustomobject][ordered]@{
        operationId = [string]$Intent.operationId
        requestId = [string]$Intent.requestId
        correlationId = [string]$Intent.correlationId
        canonical_resource_string = $resourceTemplate
        canonical_request_digest = $requestDigest
        expected_principal_ref = if (
            $Intent.PSObject.Properties.Name -contains
                'expected_principal_ref') {
            [string]$Intent.expected_principal_ref
        }
        else { 'unknown:none' }
        expected_source_scope_refs = if (
            $Intent.PSObject.Properties.Name -contains
                'expected_source_scope_refs') {
            @($Intent.expected_source_scope_refs)
        }
        else { @() }
    }
    try {
        $context = if ($null -ne $ProvenanceContextProvider) {
            & $ProvenanceContextProvider $binding
        }
        else {
            Invoke-HavocProductionProvenanceContextProvider $binding
        }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Code = 'provenance_context_unavailable' }
    }
    $outerRequired = @('contexts', 'provider_id', 'provider_version')
    $outerNames = @($context.PSObject.Properties.Name)
    if (@($outerRequired | Where-Object {
        $outerNames -cnotcontains $_
    }).Count -gt 0 -or
        @($outerNames | Where-Object {
            $outerRequired -cnotcontains $_
        }).Count -gt 0 -or
        $context.contexts -isnot [System.Array] -or
        @($context.contexts).Count -lt 1 -or
        [string]$context.provider_id -cne
            'havoc-provenance-context-provider' -or
        -not (Test-HavocMinimumVersion $context.provider_version ([version]'3.0.0'))) {
        return [pscustomobject]@{
            Success = $false
            Code = 'provenance_context_malformed'
        }
    }
    $expectedScopeRefs = @([string[]]$binding.expected_source_scope_refs)
    $allContextScopeRefs = @($context.contexts | ForEach-Object {
        if ($_ -is [pscustomobject] -and
            $_.PSObject.Properties.Name -ccontains 'source_scope_ref') {
            [string]$_.source_scope_ref
        }
        else { '' }
    })
    if ($allContextScopeRefs.Count -ne $expectedScopeRefs.Count -or
        @($allContextScopeRefs | Select-Object -Unique).Count -ne
            $allContextScopeRefs.Count -or
        (@($allContextScopeRefs | Sort-Object -CaseSensitive) -join "`n") -cne
            (@($expectedScopeRefs | Sort-Object -CaseSensitive) -join "`n")) {
        return [pscustomobject]@{
            Success = $false
            Code = 'provenance_resource_binding_mismatch'
        }
    }
    $matches = @($context.contexts | Where-Object {
        $_ -is [pscustomobject] -and
        [string]$_.operation_id -ceq [string]$Intent.operationId -and
        [string]$_.principal_ref -ceq
            [string]$binding.expected_principal_ref -and
        $expectedScopeRefs -ccontains
            [string]$_.source_scope_ref -and
        $(Test-HavocResourceBindingHmac $expectedResourceHmac `
            ([string]$_.resource_binding_hmac))
    })
    if ($matches.Count -ne $expectedScopeRefs.Count -or
        (@($matches.source_scope_ref | Sort-Object -CaseSensitive) -join "`n") -cne
            (@($expectedScopeRefs | Sort-Object -CaseSensitive) -join "`n")) {
        return [pscustomobject]@{
            Success = $false
            Code = 'provenance_resource_binding_mismatch'
        }
    }
    $selected = $matches[0]
    $required = @(
        'operation_id', 'resource_binding_hmac', 'resource_identifier_ref',
        'principal_ref', 'source_scope_ref',
        'workspace_context_ref', 'source_context_ref', 'connector_ref',
        'dcr_transformation_ref', 'automation_actor_source_ref', 'source_locale',
        'raw_identifier_ref', 'schema_version', 'source_version',
        'historical_detection_version_ref', 'historical_detection_effective_at',
        'evidence_refs', 'sentinel_onboarded', 'workspace_covered',
        'connector_healthy'
    )
    $names = @($selected.PSObject.Properties.Name)
    $optional = @()
    if ([string]$Intent.operationId -ceq 'purview-audit-query-create') {
        $optional += 'retrieval_job_preconditions'
    }
    if (@($required | Where-Object { $names -cnotcontains $_ }).Count -gt 0 -or
        @($names | Where-Object {
            $required -cnotcontains $_ -and $optional -cnotcontains $_
        }).Count -gt 0) {
        return [pscustomobject]@{ Success = $false; Code = 'provenance_context_malformed' }
    }
    foreach ($name in @(
        'workspace_context_ref', 'source_context_ref', 'connector_ref',
        'dcr_transformation_ref', 'automation_actor_source_ref',
        'raw_identifier_ref', 'historical_detection_version_ref'
    )) {
        if (-not (Test-HavocProtectedReference $selected.$name @(
            'protected-context', 'protected-evidence', 'protected-source',
            'unknown', 'not-applicable'
        ))) {
            return [pscustomobject]@{ Success = $false; Code = 'provenance_reference_invalid' }
        }
    }
    if (-not (Test-HavocProtectedReference `
            $selected.source_scope_ref @('protected-context')) -or
        -not (Test-HavocProtectedReference `
            $selected.principal_ref @('protected-context')) -or
        -not (Test-HavocProtectedReference `
            $selected.resource_identifier_ref @('protected-context')) -or
        $selected.evidence_refs -isnot [System.Array] -or
        @($selected.evidence_refs).Count -lt 1 -or
        @($selected.evidence_refs | Where-Object {
            -not (Test-HavocProtectedReference $_ @('protected-evidence'))
        }).Count -gt 0 -or
        $selected.sentinel_onboarded -isnot [bool] -or
        $selected.workspace_covered -isnot [bool] -or
        $selected.connector_healthy -isnot [bool] -or
        [string]$selected.source_locale -cnotmatch
            '^(?:unknown|[a-z]{2,3}(?:-[A-Z]{2})?)$') {
        return [pscustomobject]@{ Success = $false; Code = 'provenance_context_malformed' }
    }
    if ($expectedScopeRefs.Count -lt 1 -or
        $expectedScopeRefs -cnotcontains
            [string]$selected.source_scope_ref) {
        return [pscustomobject]@{
            Success = $false
            Code = 'provenance_source_scope_mismatch'
        }
    }
    $selectedContext = Copy-HavocValue $selected
    $selectedContext | Add-Member -Force -NotePropertyName provider_id `
        -NotePropertyValue ([string]$context.provider_id)
    $selectedContext | Add-Member -Force -NotePropertyName provider_version `
        -NotePropertyValue ([string]$context.provider_version)
    $selectedContext | Add-Member -Force -NotePropertyName scope_contexts `
        -NotePropertyValue @($matches)
    [pscustomobject]@{
        Success = $true
        Code = 'not-applicable:none'
        Context = $selectedContext
    }
}

function Set-HavocTrustedProvenance {
    param($Envelope, $Context)
    foreach ($name in @(
        'workspace_context_ref', 'source_context_ref', 'connector_ref',
        'dcr_transformation_ref', 'automation_actor_source_ref', 'source_locale',
        'raw_identifier_ref', 'schema_version', 'source_version',
        'historical_detection_version_ref', 'historical_detection_effective_at',
        'evidence_refs', 'sentinel_onboarded', 'workspace_covered',
        'connector_healthy', 'provider_id', 'provider_version'
    )) {
        $Envelope.provenance | Add-Member -Force -NotePropertyName $name `
            -NotePropertyValue (Copy-HavocValue $Context.$name)
    }
    $Envelope.provenance.historical_detection_gap = if (
        [string]$Context.historical_detection_version_ref -ceq 'unknown:none'
    ) { 'unavailable' } else { 'available' }
    $Envelope.queryLedger.provenance = $Envelope.provenance
    $Envelope
}

function Get-HavocSourceVersion {
    param($Intent)

    try {
        $uri = [uri][string]$Intent.uri
        $queryVersion = [Web.HttpUtility]::ParseQueryString($uri.Query)['api-version']
        if ($queryVersion -is [string] -and
            $queryVersion -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
            return [string]$queryVersion
        }
        $firstSegment = @($uri.AbsolutePath.Split(
            '/',
            [StringSplitOptions]::RemoveEmptyEntries
        ))[0]
        if ($firstSegment -is [string] -and
            $firstSegment -cmatch '^v[0-9]+(?:\.[0-9]+)*$') {
            return [string]$firstSegment
        }
    }
    catch {
    }
    'unknown'
}

function Test-HavocInt64 {
    param($Value, [bool]$NonNegative = $false)

    if ($Value -isnot [int64]) { return $false }
    -not $NonNegative -or [int64]$Value -ge 0
}

function Test-HavocTransportRetryable {
    param($Intent, [string]$PolicyPath)

    try {
        $policy = Get-Content -LiteralPath $PolicyPath -Raw |
            ConvertFrom-Json -Depth 50
        $operation = @($policy.operations | Where-Object {
            [string]$_.operationId -ceq [string]$Intent.operationId
        })
        $operation.Count -eq 1 -and
            $operation[0].PSObject.Properties.Name -ccontains 'retryableTransportExceptions' -and
            $operation[0].retryableTransportExceptions -is [bool] -and
            $operation[0].retryableTransportExceptions
    }
    catch {
        $false
    }
}

function New-HavocRuntimeBudget {
    param($Intent, [scriptblock]$Clock)
    [pscustomobject]@{
        Started = (& $Clock).ToUniversalTime()
        MaximumSeconds = [double]$Intent.bounds.maxRuntimeSeconds
        Clock = $Clock
        Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    }
}

function Test-HavocRuntimeBudget {
    param($Budget, [string]$Phase)
    $now = (& $Budget.Clock).ToUniversalTime()
    $elapsed = [Math]::Max(
        [Math]::Max(0, ($now - $Budget.Started).TotalSeconds),
        [double]$Budget.Stopwatch.Elapsed.TotalSeconds
    )
    [pscustomobject]@{
        Exhausted = ($elapsed -ge [double]$Budget.MaximumSeconds)
        ElapsedSeconds = [Math]::Max(0, $elapsed)
        RemainingSeconds = [Math]::Max(
            0,
            [double]$Budget.MaximumSeconds - $elapsed
        )
        CheckedAt = $now.ToString('o')
        Phase = $Phase
    }
}

function Test-HavocProtectedReference {
    param(
        $Reference,
        [Parameter(Mandatory)][string[]]$AllowedPrefixes
    )
    if ($Reference -isnot [string] -or [string]::IsNullOrWhiteSpace($Reference)) {
        return $false
    }
    if ($Reference -cmatch '[\x00-\x1f\x7f]') {
        return $false
    }
    $match = [regex]::Match(
        $Reference,
        '^(?<prefix>[a-z][a-z0-9-]*):(?<locator>[a-z0-9][a-z0-9._/-]*)$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or
        $AllowedPrefixes -cnotcontains $match.Groups['prefix'].Value) {
        return $false
    }
    $segments = @($match.Groups['locator'].Value -split '[./]')
    if ($segments.Count -eq 0 -or @($segments | Where-Object {
        [string]::IsNullOrEmpty($_) -or $_ -in '.', '..'
    }).Count -gt 0) {
        return $false
    }
    $forbidden = @(
        'bearer', 'token', 'secret', 'password', 'credential', 'apikey',
        'api-key', 'authorization', 'access_token', 'access-token'
    )
    @($segments | Where-Object { $forbidden -ccontains $_ }).Count -eq 0
}

function Invoke-HavocProtectedStore {
    param(
        [scriptblock]$ProtectedStore,
        [string]$Kind,
        $Value,
        $Metadata,
        [Parameter(Mandatory)][string[]]$AllowedPrefixes
    )
    try {
        $reference = & $ProtectedStore $Kind $Value $Metadata
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Code = 'protected_store_unavailable'
            Reference = 'not-applicable:none'
        }
    }
    if (-not (Test-HavocProtectedReference $reference $AllowedPrefixes)) {
        return [pscustomobject]@{
            Success = $false
            Code = 'protected_store_invalid_reference'
            Reference = 'not-applicable:none'
        }
    }
    [pscustomobject]@{
        Success = $true
        Code = 'not-applicable:none'
        Reference = [string]$reference
    }
}

function New-HavocEnvelope {
    param(
        [string]$AdapterId,
        [string]$Source,
        $Intent,
        [scriptblock]$ProtectedStore,
        [scriptblock]$Clock
    )
    $now = (& $Clock).ToUniversalTime().ToString('o')
    $queryValue = if ($Intent.PSObject.Properties.Name -contains 'body') {
        $Intent.body
    }
    else {
        ([uri][string]$Intent.uri).Query
    }
    $safeTarget = "$([string]$Intent.operationId):policy-template"
    $sourceVersion = Get-HavocSourceVersion $Intent
    $provenance = [pscustomobject][ordered]@{
        workspace_context_ref = 'unknown:none'
        source_context_ref = 'unknown:none'
        connector_ref = 'unknown:none'
        dcr_transformation_ref = 'unknown:none'
        automation_actor_source_ref = 'unknown:none'
        source_locale = 'unknown'
        raw_identifier_ref = 'unknown:none'
        schema_version = $sourceVersion
        api_version = $sourceVersion
        source_version = $sourceVersion
        adapter_version = $script:AdapterVersion
        normalizer_version = $script:NormalizerVersion
        historical_detection_version_ref = 'unknown:none'
        historical_detection_effective_at = 'unknown'
        historical_detection_gap = 'unavailable'
        tenant_context_ref = 'unknown:none'
        evidence_refs = @()
        sentinel_onboarded = $false
        workspace_covered = $false
        connector_healthy = $false
        provider_id = 'unknown'
        provider_version = 'unknown'
    }
    $envelope = [pscustomobject][ordered]@{
        adapter = [pscustomobject][ordered]@{
            id = $AdapterId
            version = $script:AdapterVersion
            source = $Source
        }
        status = 'failed'
        queryLedger = [pscustomobject][ordered]@{
            operationId = [string]$Intent.operationId
            target = $safeTarget
            method = ([string]$Intent.method).ToUpperInvariant()
            requestRef = 'not-applicable:none'
            queryRef = 'not-applicable:none'
            authorized = $false
            policyVersion = 'not_observed'
            purpose = 'authorized incident audit retrieval'
            startedAt = $now
            endedAt = $now
            correlationIds = @(
                [string]$Intent.requestId,
                [string]$Intent.correlationId
            )
            request_id = [string]$Intent.requestId
            operation_id = [string]$Intent.operationId
            source_id = $Source
            adapter_version = $script:AdapterVersion
            canonical_request_ref = 'not-applicable:none'
            time_bounds = [pscustomobject][ordered]@{
                start_inclusive = [string]$Intent.bounds.startTime
                end_exclusive = [string]$Intent.bounds.endTime
            }
            scope_bounds = @(
                $(if ($Intent.PSObject.Properties.Name -contains
                    'expected_source_scope_refs') {
                    @($Intent.expected_source_scope_refs)
                }
                else { @() }) | Where-Object {
                    Test-HavocProtectedReference $_ @('protected-context')
                }
            )
            entity_bounds = 'request-scoped'
            result_bounds = "rows<=$($Intent.bounds.maxRows);bytes<=$($Intent.bounds.maxBytes)"
            runtime_bounds = "seconds<=$($Intent.bounds.maxRuntimeSeconds)"
            response_classification = 'failed'
            started_at = $now
            ended_at = $now
            retrieval_at = $now
            pagination_state = [pscustomobject][ordered]@{
                status = 'unknown'
                detail = 'not started'
            }
            continuation_state = [pscustomobject][ordered]@{
                status = 'unknown'
                detail = 'not observed'
            }
            result_count = 0
            row_count = 0
            byte_count = 0
            truncation_state = [pscustomobject][ordered]@{
                status = 'unknown'
                detail = 'not observed'
            }
            partial_state = [pscustomobject][ordered]@{
                status = 'unknown'
                detail = 'not observed'
            }
            throttling_state = [pscustomobject][ordered]@{
                status = 'unknown'
                detail = 'not observed'
            }
            retry_state = [pscustomobject][ordered]@{
                status = 'unknown'
                detail = 'not observed'
            }
            correlation_ids = @(
                [string]$Intent.requestId,
                [string]$Intent.correlationId
            )
            status = 'failed'
            error_ref = 'not-applicable:none'
            status_or_error_ref = 'not-applicable:none'
            protected_payload_ref = 'not-applicable:none'
            provenance = $provenance
        }
        protectedResponseRef = 'not-applicable:none'
        times = [pscustomobject][ordered]@{
            retrieval = $now
            event = @()
            ingestion = @()
            update = @()
        }
        pagination = [pscustomobject][ordered]@{
            pages = 0
            state = 'not_started'
            continuationState = 'not_observed'
            pageIds = @()
        }
        counts = [pscustomobject][ordered]@{
            rows = 0
            results = 0
            bytes = 0
        }
        integrity = [pscustomobject][ordered]@{
            truncated = $false
            partial = $false
            duplicatePages = $false
        }
        throttling = [pscustomobject][ordered]@{
            attempts = 0
            retries = 0
            retryAfterSeconds = @()
            exhausted = $false
        }
        quota = [pscustomobject][ordered]@{
            remaining = 'not_observed'
            resetsAfter = 'not_observed'
        }
        schema = [pscustomobject][ordered]@{
            apiVersion = $sourceVersion
            sourceVersion = $sourceVersion
            schemaVersion = $sourceVersion
        }
        provenance = $provenance
        capability = [pscustomobject][ordered]@{
            preview = $false
            conditional = $false
            legacyFallbackUsed = $false
        }
        records = @()
        batchResponses = @()
        failedIds = @()
        lineage = @()
        coverage = [pscustomobject][ordered]@{
            state = 'unknown'
            permission = 'not_observed'
            license = 'not_observed'
            retention = 'not_observed'
            capability = 'not_observed'
            limitations = @()
            effectiveWindow = [pscustomobject][ordered]@{
                state = 'requested'
                start = [string]$Intent.bounds.startTime
                end = [string]$Intent.bounds.endTime
            }
        }
        errors = @()
    }
    $envelope | Add-Member -NotePropertyName '_clock' -NotePropertyValue $Clock
    foreach ($name in @(
        'workspace_context_ref', 'source_context_ref', 'connector_ref', 'dcr_transformation_ref',
        'automation_actor_source_ref', 'raw_identifier_ref',
        'historical_detection_version_ref'
    )) {
        if (-not (Test-HavocProtectedReference $provenance.$name @(
            'protected-context', 'protected-evidence', 'protected-source',
            'unknown', 'not-applicable'
        ))) {
            return Add-HavocError $envelope 'safety_policy_denied' `
                'Provenance contained an unsafe protected reference.' $false $false `
                'retrieval unavailable' 'provenance_reference_invalid'
        }
    }
    if ($provenance.source_locale -cnotmatch '^(?:unknown|[a-z]{2,3}(?:-[A-Z]{2})?)$' -or
        $provenance.historical_detection_effective_at -cnotmatch '^(?:unknown|[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z)$') {
        return Add-HavocError $envelope 'safety_policy_denied' `
            'Provenance metadata was malformed.' $false $false `
            'retrieval unavailable' 'provenance_metadata_invalid'
    }
    $requestResult = Invoke-HavocProtectedStore $ProtectedStore 'request' $Intent (
        [pscustomobject]@{ operationId = [string]$Intent.operationId }
    ) @('protected-request')
    if (-not $requestResult.Success) {
        $message = if ($requestResult.Code -ceq 'protected_store_invalid_reference') {
            'Protected request persistence returned an unsafe reference.'
        }
        else { 'Protected request persistence was unavailable.' }
        return Add-HavocError $envelope 'source_unavailable' $message $false $false `
            'retrieval unavailable' $requestResult.Code
    }
    $queryResult = Invoke-HavocProtectedStore $ProtectedStore 'request' $queryValue (
        [pscustomobject]@{
            operationId = [string]$Intent.operationId
            contentClass = 'literal-query'
        }
    ) @('protected-request')
    if (-not $queryResult.Success) {
        $message = if ($queryResult.Code -ceq 'protected_store_invalid_reference') {
            'Protected query persistence returned an unsafe reference.'
        }
        else { 'Protected query persistence was unavailable.' }
        return Add-HavocError $envelope 'source_unavailable' $message $false $false `
            'retrieval unavailable' $queryResult.Code
    }
    $envelope.queryLedger.requestRef = $requestResult.Reference
    $envelope.queryLedger.queryRef = $queryResult.Reference
    $envelope.queryLedger.canonical_request_ref = $requestResult.Reference
    $envelope
}

function Add-HavocError {
    param(
        $Envelope,
        [string]$Category,
        [string]$Message,
        [bool]$Retryable = $false,
        [bool]$PartialData = $false,
        [string]$CoverageEffect = 'retrieval unavailable',
        [string]$ErrorCode = '',
        [string]$DetailsRef = 'not-applicable:none'
    )
    if ($Envelope.PSObject.Properties.Name -contains '_protectedStoreFailureCode') {
        $ErrorCode = [string]$Envelope._protectedStoreFailureCode
        $Envelope.PSObject.Properties.Remove('_protectedStoreFailureCode')
        $Category = 'source_unavailable'
        $Retryable = $false
        $Message = if ($ErrorCode -ceq 'protected_store_invalid_reference') {
            'Protected persistence returned an unsafe reference.'
        }
        else { 'Protected persistence was unavailable.' }
    }
    if ([string]::IsNullOrWhiteSpace($ErrorCode)) {
        $ErrorCode = $Category
    }
    $clock = if ($Envelope.PSObject.Properties.Name -contains '_clock') {
        $Envelope._clock
    }
    else { { [datetimeoffset]::UtcNow } }
    $occurredAt = (& $clock).ToUniversalTime().ToString('o')
    $errorId = "error-$($Envelope.errors.Count + 1)"
    $errorOperationId = if (
        $Envelope.PSObject.Properties.Name -contains '_currentOperationId' -and
        -not [string]::IsNullOrWhiteSpace([string]$Envelope._currentOperationId)
    ) {
        [string]$Envelope._currentOperationId
    }
    else { [string]$Envelope.queryLedger.operation_id }
    if ($Envelope.PSObject.Properties.Name -contains '_currentOperationId') {
        $Envelope.PSObject.Properties.Remove('_currentOperationId')
    }
    $Envelope.errors += [pscustomobject][ordered]@{
        error_id = $errorId
        error_category = $Category
        error_code = $ErrorCode
        message = $Message
        retryable = $Retryable
        source_id = [string]$Envelope.adapter.source
        source_version = if (
            $Envelope.schema.sourceVersion -is [string] -and
            -not [string]::IsNullOrWhiteSpace([string]$Envelope.schema.sourceVersion)
        ) {
            [string]$Envelope.schema.sourceVersion
        }
        else { 'unknown' }
        operation_id = $errorOperationId
        occurred_at = $occurredAt
        details_ref = $DetailsRef
        partial_data_available = $PartialData
        coverage_effect = $CoverageEffect
        safe_message = $Message
        protected_detail_ref = $DetailsRef
        adapter_version = $script:AdapterVersion
        behavior_bases = @('guaranteed_behavior')
        category = $Category
        safeMessage = $Message
        partialDataAvailable = $PartialData
        coverageEffect = $CoverageEffect
        adapterVersion = $script:AdapterVersion
        occurredAt = $occurredAt
    }
    $hasAcceptedData = $PartialData -or [long]$Envelope.counts.results -gt 0 -or
        [int]$Envelope.pagination.pages -gt 0 -or
        [string]$Envelope.protectedResponseRef -cne 'not-applicable:none'
    $Envelope.status = if ($hasAcceptedData) {
        $Envelope.integrity.partial = $true
        'partial'
    }
    elseif ($Category -in @('safety_policy_denied', 'permission_denied')) {
        'denied'
    }
    elseif ($Category -ceq 'unsupported_capability') {
        'unsupported'
    }
    else { 'failed' }
    $Envelope.coverage.state = if ($Envelope.status -ceq 'unsupported') {
        'unmonitored'
    }
    elseif ($Envelope.status -ceq 'partial') { 'degraded' }
    else { 'failed' }
    $Envelope.coverage.limitations += $Message
    switch ($Category) {
        'permission_denied' { $Envelope.coverage.permission = 'denied' }
        'license_unavailable' { $Envelope.coverage.license = 'unavailable' }
        'retention_boundary' { $Envelope.coverage.retention = 'boundary_observed' }
        'coverage_gap' { $Envelope.coverage.capability = 'unavailable' }
        'unsupported_capability' { $Envelope.coverage.capability = 'unsupported' }
        'safety_policy_denied' { $Envelope.coverage.capability = 'denied' }
    }
    $Envelope.coverage.effectiveWindow.state = switch ($Category) {
        'retention_boundary' { 'retention_exceeded' }
        'coverage_gap' { 'unavailable' }
        'license_unavailable' { 'capability_absent' }
        default { [string]$Envelope.coverage.effectiveWindow.state }
    }
    $Envelope.queryLedger.endedAt = $occurredAt
    $Envelope.queryLedger.ended_at = $occurredAt
    $Envelope.queryLedger.status = $Envelope.status
    $Envelope.queryLedger.error_ref = $errorId
    $Envelope.queryLedger.result_count = [long]$Envelope.counts.results
    $Envelope.queryLedger.row_count = [long]$Envelope.counts.rows
    $Envelope.queryLedger.byte_count = [long]$Envelope.counts.bytes
    $Envelope.queryLedger.status_or_error_ref = $errorId
    $Envelope.queryLedger.protected_payload_ref = [string]$Envelope.protectedResponseRef
    $Envelope.queryLedger.pagination_state = [pscustomobject][ordered]@{
        status = if ($Envelope.pagination.pages -gt 0) { 'applicable' } else { 'unknown' }
        detail = [string]$Envelope.pagination.state
    }
    $Envelope.queryLedger.continuation_state = [pscustomobject][ordered]@{
        status = if ($Envelope.pagination.continuationState -ceq 'not_applicable') { 'not_applicable' } else { 'applicable' }
        detail = [string]$Envelope.pagination.continuationState
    }
    $Envelope.queryLedger.partial_state = [pscustomobject][ordered]@{
        status = if ($Envelope.integrity.partial) { 'applicable' } else { 'not_applicable' }
        detail = if ($Envelope.integrity.partial) { 'partial data isolated' } else { 'not observed' }
    }
    $Envelope.queryLedger.truncation_state = [pscustomobject][ordered]@{
        status = if ($Envelope.integrity.truncated) { 'applicable' } else { 'not_applicable' }
        detail = if ($Envelope.integrity.truncated) { 'truncation observed' } else { 'not observed' }
    }
    $Envelope.queryLedger.throttling_state = [pscustomobject][ordered]@{
        status = if ($Category -ceq 'throttled') { 'applicable' } else { 'not_applicable' }
        detail = if ($Category -ceq 'throttled') { 'throttled' } else { 'not observed' }
    }
    $Envelope.queryLedger.retry_state = [pscustomobject][ordered]@{
        status = if ($Envelope.throttling.retries -gt 0) { 'applicable' } else { 'not_applicable' }
        detail = if ($Envelope.throttling.retries -gt 0) { 'retried' } else { 'not retried' }
    }
    $Envelope.queryLedger.response_classification = switch ($Category) {
        'response_truncated' { 'truncated' }
        'partial_response' { 'partial' }
        'throttled' { 'throttled' }
        'safety_policy_denied' { 'denied' }
        'malformed_response' { 'malformed' }
        default { if ($hasAcceptedData) { 'partial' } else { 'failed' } }
    }
    if ($Envelope.PSObject.Properties.Name -contains '_clock') {
        $Envelope.PSObject.Properties.Remove('_clock')
    }
    $Envelope
}

function Test-HavocPolicyOperation {
    param([string]$OperationId, [string]$PolicyPath)
    $policy = Get-Content -LiteralPath $PolicyPath -Raw |
        ConvertFrom-Json -Depth 50
    if ($policy.PSObject.Properties.Name -cnotcontains 'operations') {
        return $false
    }
    @($policy.operations | Where-Object {
        [string]$_.operationId -ceq $OperationId
    }).Count -eq 1
}

function Test-HavocTransportContract {
    param($Transport)

    if ($null -eq $Transport -or
        ($Transport -isnot [pscustomobject] -and
            $Transport -isnot [Collections.IDictionary])) {
        return [pscustomobject]@{
            Success = $false
            Code = 'transport_contract_required'
        }
    }
    $required = @(
        'contract_id', 'contract_version', 'provider_id', 'provider_version',
        'authenticated', 'supports_cancellation', 'supports_deadline',
        'executor', 'state'
    )
    $names = @($Transport.PSObject.Properties.Name)
    $contractVersionValid = Test-HavocMinimumVersion `
        $Transport.contract_version ([version]'1.0.0')
    $providerVersionValid = Test-HavocMinimumVersion `
        $Transport.provider_version ([version]'1.0.0')
    if (@($required | Where-Object { $names -cnotcontains $_ }).Count -gt 0 -or
        @($names | Where-Object { $required -cnotcontains $_ }).Count -gt 0 -or
        [string]$Transport.contract_id -cne
            'havoc-trusted-transport-contract' -or
        -not $contractVersionValid -or
        [string]$Transport.provider_id -cne 'havoc-trusted-transport' -or
        -not $providerVersionValid -or
        $Transport.authenticated -isnot [bool] -or
        -not [bool]$Transport.authenticated -or
        $Transport.supports_cancellation -isnot [bool] -or
        -not [bool]$Transport.supports_cancellation -or
        $Transport.supports_deadline -isnot [bool] -or
        -not [bool]$Transport.supports_deadline -or
        $Transport.executor -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Transport.executor)) {
        return [pscustomobject]@{
            Success = $false
            Code = 'transport_contract_invalid'
        }
    }
    [pscustomobject]@{ Success = $true; Code = 'not-applicable:none' }
}

function Invoke-HavocTrustedTransport {
    param($Transport, $Request, $Budget)

    $check = Test-HavocRuntimeBudget $Budget 'before_isolated_transport'
    if ($check.Exhausted -or $check.RemainingSeconds -le 0) {
        return [pscustomobject]@{
            Success = $false
            BudgetExhausted = $true
            Code = 'budget_exhausted'
        }
    }
    $deadline = (& $Budget.Clock).ToUniversalTime().AddSeconds(
        $check.RemainingSeconds
    )
    $cts = [Threading.CancellationTokenSource]::new()
    $powershell = [powershell]::Create()
    $async = $null
    try {
        $wrapper = @'
param($Executor, $Request, $State, $CancellationToken, $DeadlineUtc)
& ([scriptblock]::Create($Executor)) $Request $State $CancellationToken $DeadlineUtc
'@
        $null = $powershell.AddScript($wrapper).
            AddArgument([string]$Transport.executor).
            AddArgument($Request).
            AddArgument($Transport.state).
            AddArgument($cts.Token).
            AddArgument($deadline)
        $async = $powershell.BeginInvoke()
        $waitMilliseconds = [Math]::Max(
            1,
            [int][Math]::Ceiling($check.RemainingSeconds * 1000)
        )
        if (-not $async.AsyncWaitHandle.WaitOne($waitMilliseconds)) {
            $cts.Cancel()
            $powershell.Stop()
            if ($Transport.state.PSObject.Properties.Name -contains
                'Stopped') {
                $Transport.state.Stopped = $true
            }
            return [pscustomobject]@{
                Success = $false
                BudgetExhausted = $true
                Code = 'budget_exhausted'
            }
        }
        $output = @($powershell.EndInvoke($async))
        if ($output.Count -ne 1) {
            return [pscustomobject]@{
                Success = $false
                BudgetExhausted = $false
                Code = 'transport_response_invalid'
            }
        }
        [pscustomobject]@{
            Success = $true
            BudgetExhausted = $false
            Code = 'not-applicable:none'
            Response = $output[0]
        }
    }
    catch {
        [pscustomobject]@{
            Success = $false
            BudgetExhausted = $false
            Code = 'transport_exception'
        }
    }
    finally {
        if ($null -ne $async) {
            $async.AsyncWaitHandle.Dispose()
        }
        $powershell.Dispose()
        $cts.Dispose()
    }
}

function Invoke-HavocAuthorizedRequest {
    param(
        $Intent,
        [string]$PolicyPath,
        $Transport,
        [scriptblock]$Sleeper,
        [int]$MaxRetries,
        [ValidateSet(
            'none',
            'response_enforcement',
            'purview_lifecycle',
            'continuation_link',
            'continuation_token'
        )]
        [string]$CapabilityKind = 'none',
        $Budget,
        [scriptblock]$AuthContextProvider,
        [scriptblock]$ProvenanceContextProvider
    )

    $attempt = 0
    $retryAfter = [Collections.Generic.List[int]]::new()
    if (([string]$Intent.method).ToUpperInvariant() -ceq 'GET' -and
        $Intent.PSObject.Properties.Name -contains 'body') {
        return [pscustomobject]@{
            Allowed = $false
            Decision = [pscustomobject][ordered]@{
                allowed = $false
                ruleId = 'DENY-BODY'
                reasonCode = 'body_not_allowed_on_get'
            }
            Attempts = 0
            Retries = 0
            RetryAfter = @()
            Exhausted = $false
            BudgetExhausted = $false
        }
    }
    $transportRetryable = Test-HavocTransportRetryable $Intent $PolicyPath
    $transportContract = Test-HavocTransportContract $Transport
    if (-not $transportContract.Success) {
        return [pscustomobject]@{
            Allowed = $false
            Decision = $null
            Attempts = 0
            Retries = 0
            RetryAfter = @()
            Exhausted = $false
            BudgetExhausted = $false
            AuthFailure = $true
            AuthErrorCode = [string]$transportContract.Code
        }
    }
    while ($true) {
        $budgetCheck = Test-HavocRuntimeBudget $Budget 'before_transport'
        if ($budgetCheck.Exhausted) {
            return [pscustomobject]@{
                Allowed = $true
                Decision = $null
                Attempts = $attempt
                Retries = [Math]::Max(0, $attempt - 1)
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $true
                BudgetCheck = $budgetCheck
            }
        }
        $auth = Resolve-HavocAuthContext $Intent $PolicyPath `
            $AuthContextProvider $Budget.Clock
        if (-not $auth.Success) {
            return [pscustomobject]@{
                Allowed = $false
                Decision = $null
                Attempts = $attempt
                Retries = [Math]::Max(0, $attempt - 1)
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $false
                AuthFailure = $true
                AuthErrorCode = [string]$auth.Code
                AuthBinding = if ($auth.PSObject.Properties.Name -contains 'Binding') {
                    $auth.Binding
                } else { $null }
            }
        }
        $provenance = Resolve-HavocProvenanceContext $Intent `
            $ProvenanceContextProvider $PolicyPath
        if (-not $provenance.Success) {
            return [pscustomobject]@{
                Allowed = $false
                Decision = $null
                Attempts = $attempt
                Retries = [Math]::Max(0, $attempt - 1)
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $false
                AuthFailure = $true
                AuthErrorCode = [string]$provenance.Code
                AuthBinding = if ($provenance.PSObject.Properties.Name -contains 'Binding') {
                    $provenance.Binding
                } else { $null }
            }
        }
        $authBinding = $auth.Context.resource_binding
        if ([string]$authBinding.operation_id -cne
                [string]$provenance.Context.operation_id -or
            [string]$authBinding.principal_ref -cne
                [string]$provenance.Context.principal_ref -or
            [string]$authBinding.source_scope_ref -cne
                [string]$provenance.Context.source_scope_ref -or
            [string]$authBinding.resource_identifier_ref -cne
                [string]$provenance.Context.resource_identifier_ref -or
            -not $(Test-HavocResourceBindingHmac `
                ([string]$authBinding.resource_binding_hmac) `
                ([string]$provenance.Context.resource_binding_hmac))) {
            return [pscustomobject]@{
                Allowed = $false
                Decision = $null
                Attempts = $attempt
                Retries = [Math]::Max(0, $attempt - 1)
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $false
                AuthFailure = $true
                AuthErrorCode = 'auth_provenance_resource_binding_mismatch'
            }
        }
        $boundIntent = Copy-HavocTransportIntent $Intent
        $boundIntent.tokenScopes = @($auth.Context.recognized_permissions)
        $boundIntent.tokenRoles = @()
        $boundIntent | Add-Member -Force -NotePropertyName credentialClass `
            -NotePropertyValue ([string]$auth.Context.credential_class)
        $boundIntent | Add-Member -Force -NotePropertyName armRbacReadApproved `
            -NotePropertyValue ([bool]$auth.Context.arm_rbac_read_approved)
        if ($boundIntent.PSObject.Properties.Name -contains 'authContext') {
            $boundIntent.PSObject.Properties.Remove('authContext')
        }
        try {
            $capability = if ($CapabilityKind -cne 'none') {
                $trustedPreconditions = if ($CapabilityKind -ceq
                        'purview_lifecycle' -and
                    $provenance.Context.PSObject.Properties.Name -contains
                        'retrieval_job_preconditions') {
                    $provenance.Context.retrieval_job_preconditions
                }
                else { $null }
                New-HavocCapability $boundIntent $CapabilityKind $PolicyPath `
                    $Budget.Clock $trustedPreconditions
            }
            else { $null }
            if ($null -ne $capability -and @($capability).Count -gt 1) {
                $capability = @($capability)[-1]
            }
        }
        catch {
            return [pscustomobject]@{
                Allowed = $false
                Decision = $null
                Attempts = $attempt
                Retries = [Math]::Max(0, $attempt - 1)
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $false
                AuthFailure = $true
                AuthErrorCode = 'capability_precondition_evidence_missing'
                AuthContext = $auth.Context
                ProvenanceContext = $provenance.Context
            }
        }
        $decision = Invoke-HavocGuard $boundIntent $PolicyPath $capability `
            $Budget.Clock
        if (-not $decision.allowed) {
            return [pscustomobject]@{
                Allowed = $false
                Decision = $decision
                Attempts = $attempt
                Retries = [Math]::Max(0, $attempt - 1)
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $false
                AuthContext = $auth.Context
                ProvenanceContext = $provenance.Context
            }
        }
        $attempt++
        $request = [pscustomobject][ordered]@{
            Method = ([string]$Intent.method).ToUpperInvariant()
            Uri = [string]$Intent.uri
            Body = if ($boundIntent.PSObject.Properties.Name -contains 'body') {
                if (([string]$Intent.method).ToUpperInvariant() -ceq 'GET') {
                    $null
                }
                else { $boundIntent.body }
            }
            else { $null }
            Intent = $boundIntent
            operationId = [string]$Intent.operationId
            Authorization = $decision
            CapabilityKind = $CapabilityKind
            Attempt = $attempt
            TransportContext = [pscustomobject][ordered]@{
                contract_id = [string]$Transport.contract_id
                contract_version = [string]$Transport.contract_version
                provider_id = [string]$Transport.provider_id
                provider_version = [string]$Transport.provider_version
                operation_id = [string]$authBinding.operation_id
                resource_binding_hmac =
                    [string]$authBinding.resource_binding_hmac
                resource_identifier_ref =
                    [string]$authBinding.resource_identifier_ref
                principal_ref = [string]$authBinding.principal_ref
                source_scope_ref = [string]$authBinding.source_scope_ref
                auth_provider_id = [string]$auth.Context.provider_id
                auth_provider_version = [string]$auth.Context.provider_version
                deadline_utc = (& $Budget.Clock).ToUniversalTime().AddSeconds(
                    (Test-HavocRuntimeBudget $Budget 'transport_deadline').
                        RemainingSeconds
                ).ToString('o')
            }
        }
        try {
            $transportResult = Invoke-HavocTrustedTransport $Transport $request $Budget
            if ($transportResult.BudgetExhausted) {
                return [pscustomobject]@{
                    Allowed = $true
                    Decision = $decision
                    Request = $request
                    Attempts = $attempt
                    Retries = $attempt - 1
                    RetryAfter = @($retryAfter)
                    Exhausted = $false
                    BudgetExhausted = $true
                    AuthContext = $auth.Context
                    ProvenanceContext = $provenance.Context
                }
            }
            if (-not $transportResult.Success) {
                throw [InvalidOperationException]::new(
                    [string]$transportResult.Code
                )
            }
            $response = $transportResult.Response
        }
        catch {
            if (-not $transportRetryable -or ($attempt - 1) -ge $MaxRetries) {
                return [pscustomobject]@{
                    Allowed = $true
                    Decision = $decision
                    Request = $request
                    OperationId = [string]$Intent.operationId
                    SourceVersion = Get-HavocSourceVersion $Intent
                    Attempts = $attempt
                    Retries = $attempt - 1
                    RetryAfter = @($retryAfter)
                    Exhausted = $false
                    BudgetExhausted = $false
                    TransportException = $true
                    TransportRetryable = $transportRetryable
                    AuthContext = $auth.Context
                    ProvenanceContext = $provenance.Context
                }
            }
            $delay = [int][Math]::Min(8, [Math]::Pow(2, $attempt - 1))
            $retryAfter.Add($delay)
            $budgetCheck = Test-HavocRuntimeBudget $Budget 'before_transport_retry_sleep'
            if ($budgetCheck.Exhausted -or
                [double]$delay -ge [double]$budgetCheck.RemainingSeconds) {
                return [pscustomobject]@{
                    Allowed = $true
                    Decision = $decision
                    Request = $request
                    OperationId = [string]$Intent.operationId
                    SourceVersion = Get-HavocSourceVersion $Intent
                    Attempts = $attempt
                    Retries = $attempt - 1
                    RetryAfter = @($retryAfter)
                    Exhausted = $false
                    BudgetExhausted = $true
                    BudgetCheck = $budgetCheck
                    TransportException = $false
                    TransportRetryable = $transportRetryable
                    AuthContext = $auth.Context
                    ProvenanceContext = $provenance.Context
                }
            }
            & $Sleeper $delay
            $budgetCheck = Test-HavocRuntimeBudget $Budget 'after_transport_retry_sleep'
            if ($budgetCheck.Exhausted) {
                return [pscustomobject]@{
                    Allowed = $true
                    Decision = $decision
                    Request = $request
                    OperationId = [string]$Intent.operationId
                    SourceVersion = Get-HavocSourceVersion $Intent
                    Attempts = $attempt
                    Retries = $attempt - 1
                    RetryAfter = @($retryAfter)
                    Exhausted = $false
                    BudgetExhausted = $true
                    BudgetCheck = $budgetCheck
                    TransportException = $false
                    TransportRetryable = $transportRetryable
                    AuthContext = $auth.Context
                    ProvenanceContext = $provenance.Context
                }
            }
            continue
        }
        $budgetCheck = Test-HavocRuntimeBudget $Budget 'after_transport'
        if ($budgetCheck.Exhausted) {
            return [pscustomobject]@{
                Allowed = $true
                Decision = $decision
                Attempts = $attempt
                Retries = $attempt - 1
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $true
                BudgetCheck = $budgetCheck
            }
        }
        $headers = ConvertTo-HavocHeaders $response.Headers
        if ([int]$response.StatusCode -ne 429) {
            return [pscustomobject]@{
                Allowed = $true
                Decision = $decision
                Response = [pscustomobject]@{
                    StatusCode = [int]$response.StatusCode
                    Headers = $headers
                    Content = [string]$response.Content
                }
                Request = $request
                Attempts = $attempt
                Retries = $attempt - 1
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $false
                AuthContext = $auth.Context
            }
        }
        if (($attempt - 1) -ge $MaxRetries) {
            return [pscustomobject]@{
                Allowed = $true
                Decision = $decision
                Response = $response
                Request = $request
                Attempts = $attempt
                Retries = $attempt - 1
                RetryAfter = @($retryAfter)
                Exhausted = $true
                BudgetExhausted = $false
                AuthContext = $auth.Context
            }
        }
        $header = Get-HavocHeader $headers 'Retry-After'
        $delay = 0
        if (-not [int]::TryParse($header, [ref]$delay) -or $delay -lt 0 -or $delay -gt 60) {
            $delay = [Math]::Min(8, [Math]::Pow(2, $attempt - 1))
        }
        $retryAfter.Add([int]$delay)
        $budgetCheck = Test-HavocRuntimeBudget $Budget 'before_sleep'
        if ($budgetCheck.Exhausted -or
            [double]$delay -ge [double]$budgetCheck.RemainingSeconds) {
            return [pscustomobject]@{
                Allowed = $true
                Decision = $decision
                Attempts = $attempt
                Retries = $attempt - 1
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $true
                BudgetCheck = $budgetCheck
            }
        }
        & $Sleeper ([int]$delay)
        $budgetCheck = Test-HavocRuntimeBudget $Budget 'after_sleep'
        if ($budgetCheck.Exhausted) {
            return [pscustomobject]@{
                Allowed = $true
                Decision = $decision
                Attempts = $attempt
                Retries = $attempt - 1
                RetryAfter = @($retryAfter)
                Exhausted = $false
                BudgetExhausted = $true
                BudgetCheck = $budgetCheck
            }
        }
    }
}

function ConvertFrom-HavocResponse {
    param([string]$Content)
    try {
        [pscustomobject]@{
            Valid = $true
            Value = $Content | ConvertFrom-Json -Depth 100 -DateKind String
        }
    }
    catch {
        [pscustomobject]@{ Valid = $false; Value = $null }
    }
}

function Get-HavocUtf8ByteCount {
    param([string]$Content)
    [Text.Encoding]::UTF8.GetByteCount($Content)
}

function Set-HavocRequestTelemetry {
    param($Envelope, $Result, $Intent)
    $Envelope.throttling.attempts += [int]$Result.Attempts
    $Envelope.throttling.retries += [int]$Result.Retries
    $Envelope.throttling.retryAfterSeconds += @($Result.RetryAfter)
    if ($Result.PSObject.Properties.Name -contains 'Exhausted') {
        $Envelope.throttling.exhausted = [bool]$Result.Exhausted
    }
    if ($null -ne $Result.Decision) {
        $Envelope.queryLedger.authorized = [bool]$Result.Decision.allowed
        if ($Result.Decision.PSObject.Properties.Name -contains
            'policyVersion') {
            $Envelope.queryLedger.policyVersion =
                [string]$Result.Decision.policyVersion
        }
    }
    if ($Result.PSObject.Properties.Name -contains 'AuthContext' -and
        $null -ne $Result.AuthContext) {
        $Envelope.provenance.tenant_context_ref =
            [string]$Result.AuthContext.tenant_context_ref
        $Envelope.queryLedger.provenance.tenant_context_ref =
            [string]$Result.AuthContext.tenant_context_ref
    }
    if ($Result.PSObject.Properties.Name -contains 'ProvenanceContext' -and
        $null -ne $Result.ProvenanceContext) {
        $null = Set-HavocTrustedProvenance $Envelope $Result.ProvenanceContext
    }
    $operationId = if ($null -ne $Intent) {
        [string]$Intent.operationId
    }
    elseif ($Result.PSObject.Properties.Name -contains 'OperationId') {
        [string]$Result.OperationId
    }
    elseif ($Result.PSObject.Properties.Name -contains 'Request' -and
        $null -ne $Result.Request) {
        [string]$Result.Request.operationId
    }
    else { '' }
    if (-not [string]::IsNullOrWhiteSpace($operationId)) {
        $Envelope | Add-Member -Force -NotePropertyName '_currentOperationId' `
            -NotePropertyValue $operationId
    }
    $sourceVersion = if ($null -ne $Intent) {
        Get-HavocSourceVersion $Intent
    }
    elseif ($Result.PSObject.Properties.Name -contains 'SourceVersion') {
        [string]$Result.SourceVersion
    }
    else { 'unknown' }
    if (-not [string]::IsNullOrWhiteSpace($sourceVersion)) {
        $Envelope.schema.sourceVersion = $sourceVersion
        $Envelope.schema.apiVersion = $sourceVersion
        $Envelope.schema.schemaVersion = $sourceVersion
        $Envelope.provenance.source_version = $sourceVersion
        $Envelope.provenance.api_version = $sourceVersion
        $Envelope.provenance.schema_version = $sourceVersion
    }
    $Envelope.queryLedger.throttling_state = [pscustomobject][ordered]@{
        status = if ($Envelope.throttling.attempts -gt 0) { 'applicable' } else { 'unknown' }
        detail = if ($Envelope.throttling.exhausted) { 'throttled and exhausted' }
            elseif ($Envelope.throttling.attempts -gt 0) { 'request attempted' }
            else { 'not observed' }
    }
    $Envelope.queryLedger.retry_state = [pscustomobject][ordered]@{
        status = if ($Envelope.throttling.retries -gt 0) { 'applicable' } else { 'not_applicable' }
        detail = if ($Envelope.throttling.retries -gt 0) { 'retried' } else { 'not retried' }
    }
}

function Set-HavocOperationContext {
    param($Envelope, $Intent)

    $operationId = [string]$Intent.operationId
    if (-not [string]::IsNullOrWhiteSpace($operationId)) {
        $Envelope | Add-Member -Force -NotePropertyName '_currentOperationId' `
            -NotePropertyValue $operationId
    }
    $sourceVersion = Get-HavocSourceVersion $Intent
    $Envelope.schema.sourceVersion = $sourceVersion
    $Envelope.schema.apiVersion = $sourceVersion
    $Envelope.schema.schemaVersion = $sourceVersion
    $Envelope.provenance.source_version = $sourceVersion
    $Envelope.provenance.api_version = $sourceVersion
    $Envelope.provenance.schema_version = $sourceVersion
}

function Add-HavocAuthFailure {
    param($Envelope, $Result)
    Add-HavocError $Envelope 'permission_denied' `
        'Trusted authorization context validation failed.' $false $false `
        'retrieval unavailable' ([string]$Result.AuthErrorCode)
}

function Get-HavocOperationGap {
    param([string]$OperationId, [string]$GapPath)
    if (-not (Test-Path -LiteralPath $GapPath -PathType Leaf)) { return $null }
    try {
        $document = Get-Content -LiteralPath $GapPath -Raw |
            ConvertFrom-Json -Depth 100
        @($document.gaps | Where-Object {
            [string]$_.operationId -ceq $OperationId
        }) | Select-Object -First 1
    }
    catch {
        $null
    }
}

function Add-HavocLineage {
    param(
        $Envelope,
        [string]$NormalizedField,
        [string]$SourceField,
        [string]$Transformation = 'protected-reference-normalization'
    )
    $Envelope.lineage += [pscustomobject][ordered]@{
        normalizedField = $NormalizedField
        sourceField = $SourceField
        transformation = $Transformation
        transformationVersion = '1.0.0'
        adapterVersion = $script:AdapterVersion
    }
}

function Complete-HavocEnvelope {
    param($Envelope)
    if ($Envelope.PSObject.Properties.Name -contains '_currentOperationId') {
        $Envelope.PSObject.Properties.Remove('_currentOperationId')
    }
    if ($Envelope.PSObject.Properties.Name -contains '_protectedStoreFailureCode') {
        return Add-HavocError $Envelope 'source_unavailable' `
            'Protected persistence failed.' $false `
            ([long]$Envelope.counts.results -gt 0) 'retrieval incomplete'
    }
    $Envelope.status = 'success'
    $Envelope.coverage.state = 'healthy'
    $Envelope.coverage.permission = 'verified_for_request'
    $Envelope.coverage.capability = 'authorized'
    $Envelope.pagination.state = 'complete'
    $clock = if ($Envelope.PSObject.Properties.Name -contains '_clock') {
        $Envelope._clock
    }
    else { { [datetimeoffset]::UtcNow } }
    $ended = (& $clock).ToUniversalTime().ToString('o')
    $Envelope.queryLedger.endedAt = $ended
    $Envelope.queryLedger.ended_at = $ended
    $Envelope.queryLedger.status = 'success'
    $Envelope.queryLedger.response_classification = 'success'
    $Envelope.queryLedger.pagination_state = [pscustomobject][ordered]@{
        status = 'applicable'
        detail = 'complete'
    }
    $Envelope.queryLedger.continuation_state = [pscustomobject][ordered]@{
        status = if ($Envelope.pagination.continuationState -ceq 'not_applicable') { 'not_applicable' } else { 'applicable' }
        detail = [string]$Envelope.pagination.continuationState
    }
    $Envelope.queryLedger.result_count = [long]$Envelope.counts.results
    $Envelope.queryLedger.row_count = [long]$Envelope.counts.rows
    $Envelope.queryLedger.byte_count = [long]$Envelope.counts.bytes
    $Envelope.queryLedger.partial_state = [pscustomobject][ordered]@{
        status = 'not_applicable'
        detail = 'not observed'
    }
    $Envelope.queryLedger.truncation_state = [pscustomobject][ordered]@{
        status = 'not_applicable'
        detail = 'not observed'
    }
    $Envelope.queryLedger.error_ref = 'not-applicable:none'
    $Envelope.queryLedger.status_or_error_ref = 'success'
    $Envelope.queryLedger.protected_payload_ref = [string]$Envelope.protectedResponseRef
    $Envelope.queryLedger.correlation_ids = @(
        $Envelope.queryLedger.correlation_ids | Select-Object -Unique
    )
    if ($Envelope.PSObject.Properties.Name -contains '_clock') {
        $Envelope.PSObject.Properties.Remove('_clock')
    }
    $Envelope
}

function Set-HavocProtectedResponse {
    param($Envelope, [scriptblock]$ProtectedStore, $Value, [string]$OperationId)
    $result = Invoke-HavocProtectedStore $ProtectedStore 'evidence' $Value ([pscustomobject]@{
        operationId = $OperationId
        bytes = $Envelope.counts.bytes
        contentClass = 'accepted-response'
    }) @('protected-evidence')
    if (-not $result.Success) {
        $Envelope | Add-Member -Force -NotePropertyName '_protectedStoreFailureCode' `
            -NotePropertyValue $result.Code
        throw [InvalidDataException]::new($result.Code)
    }
    $Envelope.protectedResponseRef = $result.Reference
}

function New-HavocProtectedRecordReference {
    param(
        [scriptblock]$ProtectedStore,
        $Identifier,
        [string]$OperationId,
        [string]$SourceId
    )
    try {
        $result = Invoke-HavocProtectedStore $ProtectedStore 'evidence' $Identifier ([pscustomobject]@{
            operationId = $OperationId
            sourceId = $SourceId
            contentClass = 'record-identifier'
        }) @('protected-evidence')
        if (-not $result.Success) {
            return [pscustomobject]@{
                Success = $false
                Code = $result.Code
            }
        }
        [pscustomobject]@{
            Success = $true
            Code = 'not-applicable:none'
            Reference = $result.Reference
        }
    }
    catch {
        [pscustomobject]@{
            Success = $false
            Code = 'protected_store_unavailable'
        }
    }
}

function Protect-HavocAcceptedEvidence {
    param(
        $Envelope,
        [scriptblock]$ProtectedStore,
        $Value,
        [string]$OperationId
    )
    if (@($Value).Count -eq 0) { return $true }
    try {
        Set-HavocProtectedResponse $Envelope $ProtectedStore $Value $OperationId
        return $true
    }
    catch {
        if ($Envelope.PSObject.Properties.Name -notcontains '_protectedStoreFailureCode') {
            $Envelope | Add-Member -Force -NotePropertyName '_protectedStoreFailureCode' `
                -NotePropertyValue 'protected_store_unavailable'
        }
        return $false
    }
}

function New-HavocUnsupportedEnvelope {
    param(
        [string]$AdapterId,
        [string]$Source,
        $Intent,
        [scriptblock]$ProtectedStore,
        [scriptblock]$Clock,
        [string]$Message
    )
    $envelope = New-HavocEnvelope $AdapterId $Source $Intent $ProtectedStore $Clock
    if ($envelope.errors.Count -gt 0) { return $envelope }
    Add-HavocError $envelope 'unsupported_capability' $Message
}

Export-ModuleMember -Function @(
    'Add-HavocError',
    'Add-HavocAuthFailure',
    'Add-HavocLineage',
    'Complete-HavocEnvelope',
    'ConvertFrom-HavocResponse',
    'Copy-HavocValue',
    'Get-HavocErrorCategory',
    'Get-HavocActiveCloudProfile',
    'Get-HavocExpectedAudience',
    'Get-HavocHeader',
    'Get-HavocResponseFailure',
    'Get-HavocSourceVersion',
    'Get-HavocUtf8ByteCount',
    'Get-HavocOperationGap',
    'Invoke-HavocProtectedStore',
    'Invoke-HavocAuthorizedRequest',
    'Invoke-HavocTrustedTransport',
    'New-HavocEnvelope',
    'New-HavocProtectedRecordReference',
    'New-HavocRuntimeBudget',
    'New-HavocUnsupportedEnvelope',
    'Protect-HavocAcceptedEvidence',
    'Resolve-HavocAuthContext',
    'Resolve-HavocProvenanceContext',
    'Set-HavocProtectedResponse',
    'Set-HavocAdapterCloudProfile',
    'Set-HavocOperationContext',
    'Set-HavocRequestTelemetry',
    'Set-HavocTrustedProvenance',
    'Test-HavocInt64',
    'Test-HavocProtectedReference',
    'Test-HavocRuntimeBudget',
    'Test-HavocPolicyOperation',
    'Test-HavocTransportContract'
)
