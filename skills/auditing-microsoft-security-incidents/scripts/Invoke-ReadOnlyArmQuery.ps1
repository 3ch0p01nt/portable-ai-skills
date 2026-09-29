[CmdletBinding()]
param(
    [Parameter(Mandatory)]$Intent,
    $Transport,
    [Parameter(Mandatory)][scriptblock]$ProtectedStore,
    [scriptblock]$AuthContextProvider,
    [scriptblock]$ProvenanceContextProvider,
    [scriptblock]$Sleeper = { param($Seconds) Start-Sleep -Seconds $Seconds },
    [scriptblock]$Clock = { [datetimeoffset]::UtcNow },
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\references\request-policy.json'),
    [ValidateSet('Commercial', 'USGovDoD')]
    [string]$Cloud = 'Commercial',
    [ValidateRange(0, 8)][int]$MaxRetries = 2
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReadOnlyAdapter.Common.psm1') -Force
Set-HavocAdapterCloudProfile -Cloud $Cloud

function Save-AcceptedArmEvidence {
    param($Envelope, $Pages, $Store, [string]$OperationId)
    if ($Pages.Count -eq 0) { return $true }
    Protect-HavocAcceptedEvidence $Envelope $Store @($Pages) $OperationId
}

$envelope = New-HavocEnvelope 'azure-arm' 'sentinel-arm' $Intent $ProtectedStore $Clock
if ($envelope.errors.Count -gt 0) { return $envelope }
if (-not (Test-HavocPolicyOperation ([string]$Intent.operationId) $PolicyPath)) {
    $gap = Get-HavocOperationGap ([string]$Intent.operationId) (
        Join-Path (Split-Path $PolicyPath -Parent) 'operation-gaps.json'
    )
    if ($null -ne $gap) {
        $envelope | Add-Member -NotePropertyName operationGap -NotePropertyValue $gap
        return Add-HavocError $envelope 'unsupported_capability' `
            'The exact endpoint is not verified in the registered primary sources.' `
            $false $false 'retrieval unavailable' 'exact_endpoint_not_verified'
    }
    return Add-HavocError $envelope 'unsupported_capability' `
        'The requested Sentinel ARM operation is not present in the approved request policy.' `
        $false $false 'retrieval unavailable' 'operation_not_supported'
}
$trustedProvenance = Resolve-HavocProvenanceContext $Intent `
    $ProvenanceContextProvider $PolicyPath
if (-not $trustedProvenance.Success) {
    return Add-HavocError $envelope 'safety_policy_denied' `
        'Trusted provenance context validation failed.' $false $false `
        'retrieval unavailable' ([string]$trustedProvenance.Code)
}
$null = Set-HavocTrustedProvenance $envelope $trustedProvenance.Context
if (-not [bool]$trustedProvenance.Context.sentinel_onboarded -or
    -not [bool]$trustedProvenance.Context.workspace_covered -or
    -not [bool]$trustedProvenance.Context.connector_healthy) {
    return Add-HavocError $envelope 'coverage_gap' `
        'Trusted Sentinel source coverage is incomplete.' $false $false `
        'retrieval unavailable' 'sentinel_source_not_covered'
}
$budget = New-HavocRuntimeBudget $Intent $Clock
$current = Copy-HavocValue $Intent
$initial = [uri][string]$Intent.uri
$visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$null = $visited.Add($initial.AbsoluteUri)
$rawPages = [Collections.Generic.List[string]]::new()
$maxPages = [Math]::Max(1, [Math]::Min(1000, [long]$Intent.bounds.maxRows + 1))
while ($true) {
    if ($envelope.pagination.pages -ge $maxPages) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'ARM page limit was exhausted.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'page_limit_exhausted'
    }
    $result = Invoke-HavocAuthorizedRequest $current $PolicyPath $Transport $Sleeper `
        $MaxRetries 'none' $budget $AuthContextProvider $ProvenanceContextProvider
    Set-HavocRequestTelemetry $envelope $result $current
    if ($result.PSObject.Properties.Name -contains 'AuthFailure' -and
        $result.AuthFailure) {
        return Add-HavocAuthFailure $envelope $result
    }
    if ($result.BudgetExhausted) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized runtime budget was exhausted.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'budget_exhausted'
    }
    if (-not $result.Allowed) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            "Request denied by rule $($result.Decision.ruleId)." $false ($rawPages.Count -gt 0)
    }
    if ($result.PSObject.Properties.Name -contains 'TransportException' -and
        $result.TransportException) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized source transport was unavailable.' `
            ([bool]$result.TransportRetryable) ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'transport_exception'
    }
    if ($result.Exhausted) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'throttled' `
            'Retry limit exhausted while the source remained throttled.' $true ($rawPages.Count -gt 0)
    }
    $response = $result.Response
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        $failure = Get-HavocResponseFailure $response
        return Add-HavocError $envelope $failure.Category $failure.Message `
            ($response.StatusCode -ge 500) ($rawPages.Count -gt 0) `
            'retrieval incomplete' $failure.Code
    }
    $bytes = Get-HavocUtf8ByteCount $response.Content
    if (($envelope.counts.bytes + $bytes) -gt [long]$Intent.bounds.maxBytes) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response byte limit exceeded before response acceptance.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'byte_limit_exceeded'
    }
    $parsed = ConvertFrom-HavocResponse $response.Content
    if (-not $parsed.Valid) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' 'Source returned malformed JSON.' `
            $false ($rawPages.Count -gt 0) 'retrieval incomplete' 'malformed_json'
    }
    $page = $parsed.Value
    if ($page.PSObject.Properties.Name -contains 'error') {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'ARM returned an HTTP-200 service error.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'http_200_service_error'
    }
    $rows = if ($page.PSObject.Properties.Name -contains 'value') {
        @($page.value).Count
    }
    else { 1 }
    if (($envelope.counts.rows + $rows) -gt [long]$Intent.bounds.maxRows) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response row limit exceeded before response acceptance.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'row_limit_exceeded'
    }
    $envelope.counts.bytes += $bytes
    $envelope.counts.rows += $rows
    $envelope.counts.results = $envelope.counts.rows
    $rawPages.Add($response.Content)
    $envelope.pagination.pages++
    $envelope.pagination.pageIds += "page-$($envelope.pagination.pages)"
    Add-HavocLineage $envelope 'counts.rows' 'value[]' 'row-count'
    if ($page.PSObject.Properties.Name -notcontains 'nextLink' -or
        [string]::IsNullOrWhiteSpace([string]$page.nextLink)) {
        $envelope.pagination.continuationState = 'exhausted'
        break
    }
    try { $next = [uri][string]$page.nextLink }
    catch {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'ARM continuation link is malformed.' $false $true `
            'retrieval incomplete' 'continuation_malformed'
    }
    if ($next.Scheme -cne 'https' -or
        $next.IdnHost.ToLowerInvariant() -cne $initial.IdnHost.ToLowerInvariant()) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            'ARM continuation link drifted from the authorized commercial origin.' `
            $false $true 'retrieval incomplete' 'continuation_scope_drift'
    }
    if (-not $visited.Add($next.AbsoluteUri)) {
        $null = Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'ARM continuation cycle detected.' $false $true `
            'retrieval incomplete' 'continuation_cycle'
    }
    $current = Copy-HavocValue $current
    $current.uri = $next.AbsoluteUri
    $current.requestId = "$($Intent.requestId)-p$($envelope.pagination.pages + 1)"
}
if (-not (Save-AcceptedArmEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId))) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Protected evidence persistence was unavailable.' $false ($rawPages.Count -gt 0) `
        'retrieval incomplete' 'protected_store_unavailable'
}
Complete-HavocEnvelope $envelope
