$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:HavocLiveHttpInvokerHook = $null
$script:HavocLiveGraphTokenProviderHook = $null
$script:HavocLiveAzTokenProviderHook = $null

Import-Module (Join-Path $PSScriptRoot 'HavocCloudProfile.psm1') -Force

function Set-HavocLiveTestHooks {
    [CmdletBinding()]
    param(
        [scriptblock]$HttpInvoker,
        [scriptblock]$GraphTokenProvider,
        [scriptblock]$AzTokenProvider
    )

    if ($PSBoundParameters.ContainsKey('HttpInvoker')) {
        $script:HavocLiveHttpInvokerHook = $HttpInvoker
    }
    if ($PSBoundParameters.ContainsKey('GraphTokenProvider')) {
        $script:HavocLiveGraphTokenProviderHook = $GraphTokenProvider
    }
    if ($PSBoundParameters.ContainsKey('AzTokenProvider')) {
        $script:HavocLiveAzTokenProviderHook = $AzTokenProvider
    }
}

function Clear-HavocLiveTestHooks {
    [CmdletBinding()]
    param()

    $script:HavocLiveHttpInvokerHook = $null
    $script:HavocLiveGraphTokenProviderHook = $null
    $script:HavocLiveAzTokenProviderHook = $null
}

function Get-HavocLiveAzContextSummary {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial'
    )

    $profile = Get-HavocCloudProfile -Cloud $Cloud

    $contextCommand = Get-Command Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $contextCommand) {
        throw "Az context is unavailable. Run Connect-AzAccount -Environment $($profile.azEnvironment) -Tenant <tenant> before starting the HAVOC live pilot."
    }
    $context = Get-AzContext
    if ($null -eq $context) {
        throw "Az context is unavailable. Run Connect-AzAccount -Environment $($profile.azEnvironment) -Tenant <tenant> before starting the HAVOC live pilot."
    }

    $environmentName = if ($context.Environment -is [string]) {
        [string]$context.Environment
    }
    elseif ($null -ne $context.Environment -and
        $context.Environment.PSObject.Properties.Name -contains 'Name') {
        [string]$context.Environment.Name
    }
    else {
        'unknown'
    }
    if ($environmentName -cne [string]$profile.azEnvironment) {
        throw "Az context environment must be $($profile.azEnvironment) for the $($profile.name) HAVOC live pilot; current environment is '$environmentName'."
    }

    $contextTenantId = if ($null -ne $context.Tenant -and
        $context.Tenant.PSObject.Properties.Name -contains 'Id') {
        [string]$context.Tenant.Id
    }
    elseif ($context.PSObject.Properties.Name -contains 'TenantId') {
        [string]$context.TenantId
    }
    else {
        ''
    }
    if ([string]::IsNullOrWhiteSpace($contextTenantId) -or
        $contextTenantId -cne $TenantId) {
        throw "Az context tenant does not match requested tenant. Re-run Connect-AzAccount -Environment $($profile.azEnvironment) -Tenant <tenant> for the target $($profile.name) tenant."
    }

    $accountId = if ($null -ne $context.Account -and
        $context.Account.PSObject.Properties.Name -contains 'Id') {
        [string]$context.Account.Id
    }
    elseif ($context.PSObject.Properties.Name -contains 'Account') {
        [string]$context.Account
    }
    else {
        'unknown'
    }

    [pscustomobject][ordered]@{
        TenantId = $contextTenantId
        Environment = $environmentName
        Account = $accountId
    }
}

function Get-HavocLiveAudienceForUri {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial'
    )

    $profile = Get-HavocCloudProfile -Cloud $Cloud
    $hostName = ([uri]$Uri).IdnHost.ToLowerInvariant()
    if ($hostName -ceq [string]$profile.graphHost) { return [string]@($profile.graphAudiences)[0] }
    if ($hostName -ceq [string]$profile.armHost) { return [string]@($profile.armAudiences)[0] }
    if ($hostName -ceq [string]$profile.logAnalyticsHost) { return [string]$profile.logAnalyticsAudience }
    'unknown'
}

function Get-HavocLiveAcceptedAudiencesForUri {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial'
    )

    $profile = Get-HavocCloudProfile -Cloud $Cloud
    $hostName = ([uri]$Uri).IdnHost.ToLowerInvariant()
    if ($hostName -ceq [string]$profile.graphHost) { return @($profile.graphAudiences) }
    if ($hostName -ceq [string]$profile.armHost) { return @($profile.armAudiences) }
    if ($hostName -ceq [string]$profile.logAnalyticsHost) { return @([string]$profile.logAnalyticsAudience) }
    @('unknown')
}

function Test-HavocLiveIssuer {
    param(
        [Parameter(Mandatory)][string]$Issuer,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)]$CloudProfile
    )
    foreach ($template in @($CloudProfile.allowedIssuerTemplates)) {
        $expected = ([string]$template).Replace('{tenantId}', $TenantId)
        if ($Issuer -ceq $expected) { return $true }
    }
    return $false
}

function ConvertTo-HavocLiveHeaderHashtable {
    param($Headers)

    $result = @{}
    if ($null -eq $Headers) {
        return $result
    }
    if ($Headers -is [Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            $result[[string]$key] = [string]$Headers[$key]
        }
        return $result
    }
    foreach ($property in @($Headers.PSObject.Properties)) {
        $result[[string]$property.Name] = [string]$property.Value
    }
    $result
}

function Get-HavocLiveResourceBindingHmac {
    param([Parameter(Mandatory)][string]$CanonicalResource)

    $encodedKey = [Environment]::GetEnvironmentVariable('HAVOC_RESOURCE_BINDING_KEY', 'Process')
    if ([string]::IsNullOrWhiteSpace($encodedKey)) {
        throw 'HAVOC_RESOURCE_BINDING_KEY is required for live auth and provenance binding.'
    }
    $key = [Convert]::FromBase64String($encodedKey)
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

function Get-HavocLiveProtectedResourceRef {
    param([Parameter(Mandatory)][string]$CanonicalResource)

    $hash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($CanonicalResource)
        )
    ).ToLowerInvariant()
    "protected-context:resource/$($hash.Substring(0, 24))"
}

function ConvertFrom-HavocLiveSecureToken {
    param($Token)

    if ($Token -is [securestring]) {
        return ConvertFrom-SecureString -SecureString $Token -AsPlainText
    }
    if ($Token -is [string] -and -not [string]::IsNullOrWhiteSpace($Token)) {
        return [string]$Token
    }
    throw 'Az token acquisition returned an unsupported token shape.'
}

function ConvertTo-HavocLiveSecureToken {
    param($Token)

    if ($Token -is [securestring]) {
        return $Token
    }
    if ($Token -is [string] -and -not [string]::IsNullOrWhiteSpace($Token)) {
        return ConvertTo-SecureString -String ([string]$Token) -AsPlainText -Force
    }
    throw 'Token acquisition returned an unsupported token shape.'
}

function ConvertFrom-HavocLiveBase64Url {
    param([Parameter(Mandatory)][string]$Value)

    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        0 { }
        default { throw 'JWT payload is not valid base64url.' }
    }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
}

function ConvertFrom-HavocLiveJwtClaims {
    param([Parameter(Mandatory)][string]$Token)

    $parts = $Token.Split('.')
    if ($parts.Count -ne 3 -or
        [string]::IsNullOrWhiteSpace($parts[0]) -or
        [string]::IsNullOrWhiteSpace($parts[1])) {
        throw 'Bearer token is not a well-formed JWT with 3 segments.'
    }
    if ([string]::IsNullOrWhiteSpace($parts[1])) {
        throw 'JWT token payload is unavailable.'
    }
    (ConvertFrom-HavocLiveBase64Url $parts[1]) |
        ConvertFrom-Json -Depth 20 -DateKind String
}

function Get-HavocLiveTokenPermissions {
    param($Claims)

    $permissions = [Collections.Generic.List[string]]::new()
    if ($Claims.PSObject.Properties.Name -contains 'scp' -and
        -not [string]::IsNullOrWhiteSpace([string]$Claims.scp)) {
        foreach ($scope in ([string]$Claims.scp).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
            $permissions.Add($scope)
        }
    }
    if ($Claims.PSObject.Properties.Name -contains 'roles' -and $null -ne $Claims.roles) {
        foreach ($role in @($Claims.roles)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$role)) {
                $permissions.Add([string]$role)
            }
        }
    }
    @($permissions | Select-Object -Unique)
}

function Get-HavocLiveExcessGraphScopes {
    param([string[]]$Permissions)

    @($Permissions | Where-Object {
        [string]$_ -match '(?i)(ReadWrite|Write|Manage|FullControl|AccessAsUser)'
    } | Sort-Object -Unique)
}

function Test-HavocLiveJwtClaims {
    param(
        [Parameter(Mandatory)]$Claims,
        [Parameter(Mandatory)][string]$Audience,
        [string[]]$AcceptedAudiences,
        [Parameter(Mandatory)][string]$TenantId,
        $CloudProfile
    )

    $audiences = if ($null -ne $AcceptedAudiences -and $AcceptedAudiences.Count -gt 0) {
        @($AcceptedAudiences)
    }
    else { @($Audience) }
    if ($Claims.PSObject.Properties.Name -notcontains 'aud' -or
        @($audiences) -cnotcontains [string]$Claims.aud) {
        throw 'Token audience does not match the requested resource.'
    }
    if ($Claims.PSObject.Properties.Name -notcontains 'tid' -or
        [string]$Claims.tid -cne $TenantId) {
        throw 'Token tenant does not match the requested tenant.'
    }
    if ($null -ne $CloudProfile) {
        if ($Claims.PSObject.Properties.Name -notcontains 'iss' -or
            [string]::IsNullOrWhiteSpace([string]$Claims.iss)) {
            throw 'Token issuer does not match the selected cloud profile.'
        }
        if (-not (Test-HavocLiveIssuer -Issuer ([string]$Claims.iss) -TenantId $TenantId -CloudProfile $CloudProfile)) {
            throw 'Token issuer does not match the selected cloud profile.'
        }
    }
    $exp = 0L
    if ($Claims.PSObject.Properties.Name -notcontains 'exp' -or
        -not [long]::TryParse([string]$Claims.exp, [ref]$exp)) {
        throw 'Token expiry claim is unavailable.'
    }
    $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds($exp).ToUniversalTime()
    if ($expiresAt -le [DateTimeOffset]::UtcNow) {
        throw 'Token is expired.'
    }
    $expiresAt
}

function Get-HavocGraphDelegatedAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$ClientId,
        [string]$AuthorityHost = 'https://login.microsoftonline.com/'
    )

    if ($null -ne $script:HavocLiveGraphTokenProviderHook) {
        return & $script:HavocLiveGraphTokenProviderHook $TenantId $Scope $ClientId
    }

    $runtime = New-HavocGraphInteractiveCredentialRuntime `
        -TenantId $TenantId `
        -Scope $Scope `
        -ClientId $ClientId `
        -AuthorityHost $AuthorityHost
    $token = $runtime.Credential.GetToken($runtime.TokenRequestContext, [Threading.CancellationToken]::None)
    [pscustomobject][ordered]@{
        Token = ConvertTo-SecureString -String ([string]$token.Token) -AsPlainText -Force
        ExpiresOn = [datetimeoffset]$token.ExpiresOn
    }
}

function New-HavocGraphInteractiveCredentialRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$ClientId,
        [string]$AuthorityHost = 'https://login.microsoftonline.com/'
    )

    Import-Module Az.Accounts -ErrorAction Stop

    $assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
    $identityAssembly = $assemblies | Where-Object {
        $_.GetName().Name -ceq 'Azure.Identity'
    } | Select-Object -First 1
    $coreAssembly = $assemblies | Where-Object {
        $_.GetName().Name -ceq 'Azure.Core'
    } | Select-Object -First 1
    if ($null -eq $identityAssembly -or $null -eq $coreAssembly) {
        throw 'Graph delegated token acquisition requires Azure.Identity and Azure.Core assemblies loaded by Az.Accounts.'
    }

    $credentialType = $identityAssembly.GetType('Azure.Identity.InteractiveBrowserCredential')
    $optionsType = $identityAssembly.GetType('Azure.Identity.InteractiveBrowserCredentialOptions')
    $tokenRequestContextType = $coreAssembly.GetType('Azure.Core.TokenRequestContext')
    if ($null -eq $tokenRequestContextType -or
        $null -eq $credentialType -or
        $null -eq $optionsType) {
        throw 'Graph delegated token acquisition requires Azure.Identity InteractiveBrowserCredential and Azure.Core TokenRequestContext from Az.Accounts.'
    }

    $options = [Activator]::CreateInstance($optionsType)
    $optionsType.GetProperty('TenantId').SetValue($options, $TenantId)
    $optionsType.GetProperty('ClientId').SetValue($options, $ClientId)
    $authorityProperty = $optionsType.GetProperty('AuthorityHost')
    if ($null -ne $authorityProperty) {
        $authorityProperty.SetValue($options, [Uri]$AuthorityHost)
    }

    $credential = [Activator]::CreateInstance($credentialType, [object[]]@($options))
    $requestContextArgs = [object[]]::new(2)
    $requestContextArgs[0] = [string[]]@($Scope)
    $requestContextArgs[1] = $null
    $requestContext = [Activator]::CreateInstance($tokenRequestContextType, $requestContextArgs)
    [pscustomobject][ordered]@{
        Credential = $credential
        TokenRequestContext = $requestContext
    }
}

function Invoke-HavocLiveDefaultHttp {
    param(
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][Threading.CancellationToken]$CancellationToken,
        [Parameter(Mandatory)][datetimeoffset]$DeadlineUtc
    )

    if ($CancellationToken.IsCancellationRequested) {
        throw 'Live transport request was cancelled before dispatch.'
    }
    $remainingSeconds = [int][Math]::Max(
        1,
        [Math]::Floor(($DeadlineUtc.ToUniversalTime() - [datetimeoffset]::UtcNow).TotalSeconds)
    )
    $parameters = @{
        Method = [string]$Request.Method
        Uri = [string]$Request.Uri
        Headers = $Request.Headers
        TimeoutSec = $remainingSeconds
        MaximumRedirection = 0
        SkipHttpErrorCheck = $true
    }
    if ($null -ne $Request.Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = if ($Request.Body -is [string]) {
            [string]$Request.Body
        }
        else {
            $Request.Body | ConvertTo-Json -Depth 100 -Compress
        }
    }
    $response = Invoke-WebRequest @parameters
    [pscustomobject][ordered]@{
        StatusCode = [int]$response.StatusCode
        Headers = ConvertTo-HavocLiveHeaderHashtable $response.Headers
        Content = [string]$response.Content
    }
}

function New-HavocLiveTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [hashtable]$TokenCache,
        [scriptblock]$HttpInvoker,
        [string]$PolicyPath = (Join-Path $PSScriptRoot '..\references\request-policy.json'),
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial',
        [int]$DefaultTimeoutSeconds = 60,
        [long]$DefaultMaxResponseBytes = 2097152
    )

    $profile = Get-HavocCloudProfile -Cloud $Cloud
    if ($null -eq $TokenCache) {
        $TokenCache = @{}
    }
    foreach ($key in @($TokenCache.Keys)) {
        if ($TokenCache[$key] -isnot [securestring]) {
            $TokenCache[$key] = ConvertTo-HavocLiveSecureToken $TokenCache[$key]
        }
    }
    if (-not (Test-Path -LiteralPath $PolicyPath)) {
        throw 'Live read-only policy could not be loaded; transport fails closed.'
    }
    $policyOperations = @{}
    $policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json -Depth 100
    $policyMaxBytes = if ($policy.PSObject.Properties.Name -contains 'globalBounds' -and
        $null -ne $policy.globalBounds -and
        $policy.globalBounds.PSObject.Properties.Name -contains 'maxBytes') {
        [int64]$policy.globalBounds.maxBytes
    }
    else {
        [int64]$DefaultMaxResponseBytes
    }
    foreach ($operation in @($policy.operations)) {
        if ($profile.resourceGraph.enabled -ne $true -and
            [string]$operation.operationId -ceq 'azure-resource-graph-query') {
            continue
        }
        if ($profile.purview.enabled -ne $true -and
            [string]$operation.operationId -like 'purview-*') {
            continue
        }
        $mappedHost = switch ([string]$operation.host) {
            'graph.microsoft.com' { [string]$profile.graphHost }
            'management.azure.com' { [string]$profile.armHost }
            'api.loganalytics.azure.com' { [string]$profile.logAnalyticsHost }
            'api.loganalytics.io' { [string]$profile.logAnalyticsHost }
            default { [string]$operation.host }
        }
        $policyOperations[[string]$operation.operationId] = [pscustomobject][ordered]@{
            Method = [string]$operation.method
            Host = $mappedHost
        }
    }
    $audienceByHost = @{
        ([string]$profile.graphHost) = [string]@($profile.graphAudiences)[0]
        ([string]$profile.armHost) = [string]@($profile.armAudiences)[0]
        ([string]$profile.logAnalyticsHost) = [string]$profile.logAnalyticsAudience
    }
    $acceptedAudiencesByHost = @{
        ([string]$profile.graphHost) = @($profile.graphAudiences)
        ([string]$profile.armHost) = @($profile.armAudiences)
        ([string]$profile.logAnalyticsHost) = @([string]$profile.logAnalyticsAudience)
    }
    $allowedHosts = @($profile.allAllowedHosts)
    $approvedPostOperations = @('log-analytics-query', 'graph-batch')
    if ($profile.resourceGraph.enabled -eq $true) {
        $approvedPostOperations += 'azure-resource-graph-query'
    }
    $state = [pscustomobject][ordered]@{
        TenantId = $TenantId
        Cloud = [string]$profile.name
        AllowedIssuerPrefixes = @($profile.allowedIssuerPrefixes)
        AllowedIssuerTemplates = @($profile.allowedIssuerTemplates)
        SecureTokenCache = $TokenCache
        HttpInvoker = if ($null -ne $HttpInvoker) { $HttpInvoker } else { $script:HavocLiveHttpInvokerHook }
        DefaultTimeoutSeconds = $DefaultTimeoutSeconds
        DefaultMaxResponseBytes = $DefaultMaxResponseBytes
        PolicyMaxResponseBytes = $policyMaxBytes
        AllowedHosts = @($allowedHosts)
        AudienceByHost = $audienceByHost
        AcceptedAudiencesByHost = $acceptedAudiencesByHost
        ApprovedPostOperations = @($approvedPostOperations)
        PolicyOperations = $policyOperations
    }

    $executor = @'
param($Request, $State, $CancellationToken, $DeadlineUtc)

function Get-AudienceForLiveUri([string]$Uri) {
    $hostName = ([uri]$Uri).IdnHost.ToLowerInvariant()
    if ($State.AudienceByHost.ContainsKey($hostName)) {
        return [string]$State.AudienceByHost[$hostName]
    }
    'unknown'
}

function Get-AcceptedAudiencesForLiveUri([string]$Uri) {
    $hostName = ([uri]$Uri).IdnHost.ToLowerInvariant()
    if ($State.AcceptedAudiencesByHost.ContainsKey($hostName)) {
        return @($State.AcceptedAudiencesByHost[$hostName])
    }
    @('unknown')
}

function Test-LiveIssuer([string]$Issuer, $State) {
    foreach ($template in @($State.AllowedIssuerTemplates)) {
        $expected = ([string]$template).Replace('{tenantId}', [string]$State.TenantId)
        if ($Issuer -ceq $expected) { return $true }
    }
    return $false
}

function ConvertFrom-LiveBase64Url([string]$Value) {
    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        0 { }
        default { throw 'JWT payload is not valid base64url.' }
    }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
}

function Test-LiveTokenClaims([string]$Token, [string]$Audience, [string[]]$AcceptedAudiences, $State) {
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[1])) {
        throw 'JWT token payload is unavailable.'
    }
    $claims = ConvertFrom-LiveBase64Url $parts[1] | ConvertFrom-Json -Depth 20
    $audiences = if ($null -ne $AcceptedAudiences -and $AcceptedAudiences.Count -gt 0) { @($AcceptedAudiences) } else { @($Audience) }
    if ($claims.PSObject.Properties.Name -notcontains 'aud' -or
        @($audiences) -cnotcontains [string]$claims.aud) {
        throw 'Token audience does not match the requested resource.'
    }
    if ($claims.PSObject.Properties.Name -notcontains 'tid' -or
        [string]$claims.tid -cne [string]$State.TenantId) {
        throw 'Token tenant does not match the requested tenant.'
    }
    if ($claims.PSObject.Properties.Name -notcontains 'iss' -or
        [string]::IsNullOrWhiteSpace([string]$claims.iss)) {
        throw 'Token issuer does not match the selected cloud profile.'
    }
    if (-not (Test-LiveIssuer ([string]$claims.iss) $State)) {
        throw 'Token issuer does not match the selected cloud profile.'
    }
    $exp = 0L
    if ($claims.PSObject.Properties.Name -notcontains 'exp' -or
        -not [long]::TryParse([string]$claims.exp, [ref]$exp) -or
        [DateTimeOffset]::FromUnixTimeSeconds($exp).ToUniversalTime() -le [DateTimeOffset]::UtcNow) {
        throw 'Token is expired.'
    }
}

function Convert-Headers($Headers) {
    $result = @{}
    if ($null -eq $Headers) { return $result }
    if ($Headers -is [Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) { $result[[string]$key] = [string]$Headers[$key] }
        return $result
    }
    foreach ($property in @($Headers.PSObject.Properties)) {
        $result[[string]$property.Name] = [string]$property.Value
    }
    $result
}

function Invoke-DefaultLiveHttp($LiveRequest, $CancellationToken, [datetimeoffset]$DeadlineUtc) {
    if ($CancellationToken.IsCancellationRequested) {
        throw 'Live transport request was cancelled before dispatch.'
    }
    $remainingSeconds = [int][Math]::Max(
        1,
        [Math]::Floor(($DeadlineUtc.ToUniversalTime() - [datetimeoffset]::UtcNow).TotalSeconds)
    )
    $parameters = @{
        Method = [string]$LiveRequest.Method
        Uri = [string]$LiveRequest.Uri
        Headers = $LiveRequest.Headers
        TimeoutSec = $remainingSeconds
        MaximumRedirection = 0
        SkipHttpErrorCheck = $true
    }
    if ($null -ne $LiveRequest.Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = if ($LiveRequest.Body -is [string]) {
            [string]$LiveRequest.Body
        }
        else {
            $LiveRequest.Body | ConvertTo-Json -Depth 100 -Compress
        }
    }
    $response = Invoke-WebRequest @parameters
    [pscustomobject][ordered]@{
        StatusCode = [int]$response.StatusCode
        Headers = Convert-Headers $response.Headers
        Content = [string]$response.Content
    }
}

$method = ([string]$Request.Method).ToUpperInvariant()
$uri = [uri][string]$Request.Uri
$hostName = $uri.IdnHost.ToLowerInvariant()
$operationId = [string]$Request.operationId
if ([string]::IsNullOrWhiteSpace($operationId) -and
    $null -ne $Request.Intent -and
    $Request.Intent.PSObject.Properties.Name -contains 'operationId') {
    $operationId = [string]$Request.Intent.operationId
}
if (-not ($Request.PSObject.Properties.Name -contains 'Authorization') -or
    $null -eq $Request.Authorization -or
    -not ($Request.Authorization.PSObject.Properties.Name -contains 'selectedCloud') -or
    [string]::IsNullOrWhiteSpace([string]$Request.Authorization.selectedCloud)) {
    throw 'Live transport rejected request because guard authorization decision is missing selectedCloud (cloud_decision_missing).'
}
if ($Request.PSObject.Properties.Name -contains 'Authorization' -and
    $null -ne $Request.Authorization -and
    $Request.Authorization.PSObject.Properties.Name -contains 'selectedCloud' -and
    [string]$Request.Authorization.selectedCloud -cne [string]$State.Cloud) {
    throw 'Live transport rejected request because guard selected cloud does not match transport selected cloud.'
}

if ($uri.Scheme -cne 'https' -or
    -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
    -not $uri.IsDefaultPort) {
    throw 'Live transport commercial HTTPS endpoint validation rejected the request URI.'
}
if (@($State.AllowedHosts) -cnotcontains $hostName) {
    throw "Live transport commercial endpoint allowlist rejected host '$hostName'."
}
if ($method -cnotin @('GET', 'POST')) {
    throw "Live read-only live transport rejected method '$method'."
}
if ($method -ceq 'POST' -and @($State.ApprovedPostOperations) -cnotcontains $operationId) {
    throw "Live transport POST operation is not approved for live read-only query execution."
}
if ($method -ceq 'POST' -and -not $State.PolicyOperations.ContainsKey($operationId)) {
    throw 'Live transport rejected POST because the operation is not bound in read-only policy.'
}
if ($State.PolicyOperations.ContainsKey($operationId)) {
    $policyOperation = $State.PolicyOperations[$operationId]
    if ([string]$policyOperation.Method -and
        [string]$policyOperation.Method -cne $method) {
        throw 'Live transport rejected request because method does not match read-only policy.'
    }
    if ([string]$policyOperation.Host -and
        [string]$policyOperation.Host -cne $hostName -and
        -not ($operationId -ceq 'log-analytics-query' -and
            @('api.loganalytics.azure.com', 'api.loganalytics.io') -ccontains $hostName)) {
        throw 'Live transport rejected request because host does not match read-only policy.'
    }
}

$audience = Get-AudienceForLiveUri ([string]$Request.Uri)
$acceptedAudiences = @(Get-AcceptedAudiencesForLiveUri ([string]$Request.Uri))
$token = ''
if ($audience -cne 'unknown' -and $State.SecureTokenCache.ContainsKey($audience)) {
    $tokenValue = $State.SecureTokenCache[$audience]
    $token = if ($tokenValue -is [securestring]) {
        ConvertFrom-SecureString -SecureString $tokenValue -AsPlainText
    }
    else {
        [string]$tokenValue
    }
}
if ([string]::IsNullOrWhiteSpace($token)) {
    throw 'Live transport token binding is unavailable for the approved request audience.'
}
if ($token.Split('.').Count -ne 3) {
    throw 'Live transport rejected bearer token because it is not a well-formed JWT with 3 segments.'
}
Test-LiveTokenClaims $token $audience $acceptedAudiences $State
$headers = @{}
if ($Request.PSObject.Properties.Name -contains 'Headers') {
    $candidateHeaders = Convert-Headers $Request.Headers
    foreach ($headerName in @($candidateHeaders.Keys)) {
        switch -Regex ($headerName) {
            '^(?i:prefer)$' {
                $headers['Prefer'] = [string]$candidateHeaders[$headerName]
            }
            '^(?i:content-type)$' {
                $headers['Content-Type'] = 'application/json'
            }
        }
    }
}
$headers['Authorization'] = ('{0} {1}' -f 'Bearer', $token)
$headers['Accept'] = 'application/json'

$liveRequest = [pscustomobject][ordered]@{
    Method = $method
    Uri = [string]$Request.Uri
    Headers = $headers
    Body = $Request.Body
}

try {
    $response = if ($null -ne $State.HttpInvoker) {
        & $State.HttpInvoker $liveRequest
    }
    else {
        Invoke-DefaultLiveHttp $liveRequest $CancellationToken ([datetimeoffset]$DeadlineUtc)
    }
}
catch {
    throw 'Live transport HTTP execution failed for the approved read-only request.'
}

$responseHeaders = Convert-Headers $response.Headers
$content = [string]$response.Content
$byteLimit = [int64]$State.DefaultMaxResponseBytes
$byteLimit = [Math]::Min($byteLimit, [int64]$State.PolicyMaxResponseBytes)
if ($null -ne $Request.Intent -and
    $Request.Intent.PSObject.Properties.Name -contains 'bounds' -and
    $null -ne $Request.Intent.bounds -and
    $Request.Intent.bounds.PSObject.Properties.Name -contains 'maxBytes') {
    $byteLimit = [Math]::Min($byteLimit, [int64]$Request.Intent.bounds.maxBytes)
}
$actualBytes = [Text.Encoding]::UTF8.GetByteCount($content)
if ($actualBytes -gt $byteLimit) {
    throw "Live transport response byte limit exceeded for the approved request."
}

[pscustomobject][ordered]@{
    StatusCode = [int]$response.StatusCode
    Headers = $responseHeaders
    Content = $content
}
'@

    [pscustomobject][ordered]@{
        contract_id = 'havoc-trusted-transport-contract'
        contract_version = '1.0.0'
        provider_id = 'havoc-trusted-transport'
        provider_version = '1.0.0'
        authenticated = $true
        supports_cancellation = $true
        supports_deadline = $true
        executor = $executor
        state = $state
    }
}

function New-HavocAzAuthContextProvider {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [hashtable]$TokenCache,
        [scriptblock]$TokenProvider,
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial'
    )

    $profile = Get-HavocCloudProfile -Cloud $Cloud
    $null = Get-HavocLiveAzContextSummary -TenantId $TenantId -Cloud $Cloud
    if ($null -eq $TokenCache) {
        $TokenCache = @{}
    }
    $azTokenProvider = if ($null -ne $TokenProvider) {
        $TokenProvider
    }
    elseif ($null -ne $script:HavocLiveAzTokenProviderHook) {
        $script:HavocLiveAzTokenProviderHook
    }
    else {
        $null
    }
    $convertSecureToken = ${function:ConvertTo-HavocLiveSecureToken}
    $convertPlainToken = ${function:ConvertFrom-HavocLiveSecureToken}
    $decodeJwtClaims = ${function:ConvertFrom-HavocLiveJwtClaims}
    $validateJwtClaims = ${function:Test-HavocLiveJwtClaims}
    $getTokenPermissions = ${function:Get-HavocLiveTokenPermissions}
    $getExcessGraphScopes = ${function:Get-HavocLiveExcessGraphScopes}
    $getGraphToken = ${function:Get-HavocGraphDelegatedAccessToken}
    $getResourceRef = ${function:Get-HavocLiveProtectedResourceRef}
    $getBindingHmac = ${function:Get-HavocLiveResourceBindingHmac}

    {
        param($Binding)

        $audience = [string]$Binding.audience
        if ([string]::IsNullOrWhiteSpace($audience) -or $audience -ceq 'unknown') {
            throw 'Auth context audience is not a commercial Azure resource.'
        }
        $expiresOn = [datetimeoffset]::UtcNow.AddMinutes(30)
        if (-not $TokenCache.ContainsKey($audience)) {
            $tokenResponse = if (@($profile.graphAudiences) -ccontains $audience) {
                try {
                    & $getGraphToken -TenantId $TenantId `
                        -Scope ([string]@($profile.graphScopes)[0]) `
                        -ClientId '14d82eec-204b-4c2f-b7e8-296a70dab67e' `
                        -AuthorityHost ([string]$profile.authorityHost)
                }
                catch {
                    throw "Graph delegated token acquisition failed for SecurityIncident.Read.All. Ensure admin/user consent exists for the Microsoft Graph PowerShell public client and retry. $($_.Exception.Message)"
                }
            }
            elseif ($null -ne $azTokenProvider) {
                & $azTokenProvider $audience
            }
            else {
                Get-AzAccessToken -ResourceUrl $audience -TenantId $TenantId -AsSecureString
            }
            if ($null -eq $tokenResponse -or
                $tokenResponse.PSObject.Properties.Name -cnotcontains 'Token') {
                throw 'Az token acquisition did not return a token.'
            }
            $TokenCache[$audience] = & $convertSecureToken $tokenResponse.Token
        }
        $plainToken = & $convertPlainToken $TokenCache[$audience]
        $claims = & $decodeJwtClaims $plainToken
        $acceptedAudiences = if (@($profile.graphAudiences) -ccontains $audience) {
            @($profile.graphAudiences)
        }
        elseif (@($profile.armAudiences) -ccontains $audience) {
            @($profile.armAudiences)
        }
        elseif ([string]$profile.logAnalyticsAudience -ceq $audience) {
            @([string]$profile.logAnalyticsAudience)
        }
        else { @($audience) }
        $expiresOn = & $validateJwtClaims -Claims $claims -Audience $audience -AcceptedAudiences $acceptedAudiences -TenantId $TenantId -CloudProfile $profile
        $tokenPermissions = @(& $getTokenPermissions $claims)
        $excessGraphScopes = if (@($profile.graphAudiences) -ccontains $audience) {
            @(& $getExcessGraphScopes $tokenPermissions)
        }
        else { @() }
        if ($excessGraphScopes.Count -gt 0) {
            throw "Graph token contains excess privilege scopes: $($excessGraphScopes -join ', '). Use a least-privilege account for the live pilot."
        }
        $scopeRefs = @($Binding.expected_source_scope_refs | ForEach-Object { [string]$_ })
        $requiredPermissions = @($Binding.requiredPermissions | ForEach-Object { [string]$_ })
        $permissions = @($tokenPermissions | Where-Object { $requiredPermissions -contains $_ })
        $resourceRef = & $getResourceRef -CanonicalResource ([string]$Binding.canonical_resource_string)
        $bindingHmac = & $getBindingHmac -CanonicalResource ([string]$Binding.canonical_resource_string)

        [pscustomobject][ordered]@{
            cloud = $(if ([string]$profile.name -ceq 'Commercial') { 'commercial' } else { [string]$profile.name })
            audience = $audience
            tenant_context_ref = "protected-context:tenant/$TenantId"
            authorized_tenant = $true
            expires_at = $expiresOn.ToString('o')
            recognized_permissions = @($permissions)
            principal_ref = [string]$Binding.expected_principal_ref
            credential_class = 'delegated'
            autonomous_read_approved = $true
            source_scope_refs = @($scopeRefs)
            arm_rbac_read_approved = (@($profile.armAudiences) -ccontains $audience)
            resource_bindings = @($scopeRefs | ForEach-Object {
                [pscustomobject][ordered]@{
                    operation_id = [string]$Binding.operationId
                    resource_binding_hmac = $bindingHmac
                    resource_identifier_ref = $resourceRef
                    principal_ref = [string]$Binding.expected_principal_ref
                    source_scope_ref = [string]$_
                }
            })
            excess_privilege_present = $false
            license_capabilities = @()
            effective_retention_days_by_source = [pscustomobject][ordered]@{}
            auth_context_issued_at = ([datetimeoffset]::UtcNow).ToString('o')
            provider_id = 'havoc-auth-context-provider'
            provider_version = '3.0.0'
        }
    }.GetNewClosure()
}

function Get-HavocLivePreflightTokenSummary {
    param(
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$Audience,
        [Parameter(Mandatory)][string[]]$AcceptedAudiences,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][hashtable]$TokenCache,
        [Parameter(Mandatory)]$CloudProfile
    )

    if (-not $TokenCache.ContainsKey($Audience)) {
        throw "$ResourceName pre-flight token validation failed: token cache missing for audience '$Audience'."
    }
    $plainToken = ConvertFrom-HavocLiveSecureToken $TokenCache[$Audience]
    try {
        $claims = ConvertFrom-HavocLiveJwtClaims $plainToken
        try {
            $expiresAt = Test-HavocLiveJwtClaims `
                -Claims $claims `
                -Audience $Audience `
                -AcceptedAudiences $AcceptedAudiences `
                -TenantId $TenantId `
                -CloudProfile $CloudProfile
        }
        catch {
            $observedAudience = if ($claims.PSObject.Properties.Name -contains 'aud') {
                [string]$claims.aud
            }
            else { '<missing>' }
            throw "$ResourceName pre-flight token validation failed; observed audience '$observedAudience'. $($_.Exception.Message)"
        }
        $issuer = if ($claims.PSObject.Properties.Name -contains 'iss') {
            ([string]$claims.iss).Replace($TenantId, '<tenant>')
        }
        else { '<missing>' }
        [pscustomobject][ordered]@{
            resource = $ResourceName
            audience = [string]$claims.aud
            issuer = $issuer
            tenant = '<tenant>'
            permissions = @(Get-HavocLiveTokenPermissions $claims)
            expires_at = $expiresAt.ToString('o')
        }
    }
    finally {
        $plainToken = $null
    }
}

function Get-HavocLiveAuthPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][hashtable]$TokenCache,
        [Parameter(Mandatory)][scriptblock]$AuthContextProvider,
        [ValidateSet('Commercial', 'USGovDoD')]
        [string]$Cloud = 'Commercial'
    )

    $profile = Get-HavocCloudProfile -Cloud $Cloud
    $graphAudience = [string]@($profile.graphAudiences)[0]
    $armAudience = [string]@($profile.armAudiences)[0]
    $logAudience = [string]$profile.logAnalyticsAudience
    $bindings = [ordered]@{
        graph = [pscustomobject][ordered]@{
            operationId = 'graph-security-incident-with-alerts-get'
            audience = $graphAudience
            requiredPermissions = @('SecurityIncident.Read.All')
            expected_principal_ref = 'protected-context:principal/live-pilot'
            expected_source_scope_refs = @('protected-context:graph-security')
            canonical_resource_string = "GET https://$([string]$profile.graphHost)/v1.0/security/incidents"
        }
        arm = [pscustomobject][ordered]@{
            operationId = 'sentinel-incident-get'
            audience = $armAudience
            requiredPermissions = @('user_impersonation')
            expected_principal_ref = 'protected-context:principal/live-pilot'
            expected_source_scope_refs = @('protected-context:sentinel-arm')
            canonical_resource_string = "GET https://$([string]$profile.armHost)/subscriptions/{subscriptionId}/providers/Microsoft.SecurityInsights/incidents/{incidentId}"
        }
        log = [pscustomobject][ordered]@{
            operationId = 'log-analytics-query'
            audience = $logAudience
            requiredPermissions = @('user_impersonation')
            expected_principal_ref = 'protected-context:principal/live-pilot'
            expected_source_scope_refs = @('protected-context:sentinel-law')
            canonical_resource_string = "POST https://$([string]$profile.logAnalyticsHost)/v1/workspaces/{workspaceId}/query"
        }
    }

    $scopeNames = @()
    $excessScopes = @()
    $errorMessage = $null
    $graphTokenSummary = $null
    try {
        $null = & $AuthContextProvider $bindings.graph
    }
    catch {
        $errorMessage = [string]$_.Exception.Message
    }

    if ($TokenCache.ContainsKey($graphAudience)) {
        try {
            $graphSummary = Get-HavocLivePreflightTokenSummary `
                -ResourceName 'Graph' `
                -Audience $graphAudience `
                -AcceptedAudiences @($profile.graphAudiences) `
                -TenantId $TenantId `
                -TokenCache $TokenCache `
                -CloudProfile $profile
            $scopeNames = @($graphSummary.permissions)
            $excessScopes = @(Get-HavocLiveExcessGraphScopes $scopeNames)
            $graphTokenSummary = $graphSummary
        }
        catch {
            $errorMessage = [string]$_.Exception.Message
        }
    }
    if ($excessScopes.Count -gt 0) {
        return [pscustomobject][ordered]@{
            graph_scopes = @($scopeNames)
            graph_excess_scopes = @($excessScopes)
            graph_error = $errorMessage
            token_summaries = @(
                if ($null -ne $graphTokenSummary) { $graphTokenSummary }
            )
        }
    }

    try { $null = & $AuthContextProvider $bindings.arm }
    catch {
        try {
            $null = Get-HavocLivePreflightTokenSummary `
                -ResourceName 'ARM' `
                -Audience $armAudience `
                -AcceptedAudiences @($profile.armAudiences) `
                -TenantId $TenantId `
                -TokenCache $TokenCache `
                -CloudProfile $profile
        }
        catch { throw $_ }
        throw
    }
    $armTokenSummary = Get-HavocLivePreflightTokenSummary `
        -ResourceName 'ARM' `
        -Audience $armAudience `
        -AcceptedAudiences @($profile.armAudiences) `
        -TenantId $TenantId `
        -TokenCache $TokenCache `
        -CloudProfile $profile

    try { $null = & $AuthContextProvider $bindings.log }
    catch {
        try {
            $null = Get-HavocLivePreflightTokenSummary `
                -ResourceName 'Log Analytics' `
                -Audience $logAudience `
                -AcceptedAudiences @([string]$profile.logAnalyticsAudience) `
                -TenantId $TenantId `
                -TokenCache $TokenCache `
                -CloudProfile $profile
        }
        catch { throw $_ }
        throw
    }
    $logTokenSummary = Get-HavocLivePreflightTokenSummary `
        -ResourceName 'Log Analytics' `
        -Audience $logAudience `
        -AcceptedAudiences @([string]$profile.logAnalyticsAudience) `
        -TenantId $TenantId `
        -TokenCache $TokenCache `
        -CloudProfile $profile

    [pscustomobject][ordered]@{
        graph_scopes = @($scopeNames)
        graph_excess_scopes = @($excessScopes)
        graph_error = $errorMessage
        token_summaries = @(
            if ($null -ne $graphTokenSummary) { $graphTokenSummary }
            $armTokenSummary
            $logTokenSummary
        )
    }
}

function New-HavocLiveProvenanceContextProvider {
    [CmdletBinding()]
    param(
        [switch]$AttestSentinelWorkspaceCoverage
    )

    $getResourceRef = ${function:Get-HavocLiveProtectedResourceRef}
    $getBindingHmac = ${function:Get-HavocLiveResourceBindingHmac}

    {
        param($Binding)

        $resourceRef = & $getResourceRef -CanonicalResource ([string]$Binding.canonical_resource_string)
        $bindingHmac = & $getBindingHmac -CanonicalResource ([string]$Binding.canonical_resource_string)
        $attestationEvidenceRef = 'protected-evidence:operator-attested/sentinel-workspace-coverage'
        [pscustomobject][ordered]@{
            contexts = @($Binding.expected_source_scope_refs | ForEach-Object {
                [pscustomobject][ordered]@{
                    operation_id = [string]$Binding.operationId
                    resource_binding_hmac = $bindingHmac
                    resource_identifier_ref = $resourceRef
                    principal_ref = [string]$Binding.expected_principal_ref
                    source_scope_ref = [string]$_
                    workspace_context_ref = 'protected-context:workspace/live-pilot'
                    source_context_ref = 'protected-context:source/live-pilot'
                    connector_ref = 'unknown:none'
                    dcr_transformation_ref = 'unknown:none'
                    automation_actor_source_ref = 'not-applicable:none'
                    source_locale = 'unknown'
                    raw_identifier_ref = 'protected-evidence:live-pilot/raw-source'
                    schema_version = 'v1.0'
                    source_version = 'unknown'
                    historical_detection_version_ref = 'unknown:none'
                    historical_detection_effective_at = 'unknown'
                    # [object[]] keeps a one-element list an array; an if-expression unrolls it to a scalar.
                    evidence_refs = [object[]]$(if ($AttestSentinelWorkspaceCoverage) {
                        @('protected-evidence:live-pilot/provenance', $attestationEvidenceRef)
                    }
                    else {
                        @('protected-evidence:live-pilot/provenance')
                    })
                    sentinel_onboarded = [bool]$AttestSentinelWorkspaceCoverage
                    workspace_covered = [bool]$AttestSentinelWorkspaceCoverage
                    connector_healthy = [bool]$AttestSentinelWorkspaceCoverage
                }
            })
            provider_id = 'havoc-provenance-context-provider'
            provider_version = '3.0.0'
        }
    }.GetNewClosure()
}

Export-ModuleMember -Function New-HavocLiveTransport, New-HavocAzAuthContextProvider, New-HavocLiveProvenanceContextProvider, Get-HavocLiveAuthPreflight, Get-HavocLiveAzContextSummary
