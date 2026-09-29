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

function Save-AcceptedArgEvidence {
    param($Envelope, $Pages, $Store, [string]$OperationId)
    if ($Pages.Count -eq 0) { return $true }
    Protect-HavocAcceptedEvidence $Envelope $Store @($Pages) $OperationId
}

$envelope = New-HavocEnvelope 'azure-resource-graph' 'azure-resource-graph' `
    $Intent $ProtectedStore $Clock
if ($envelope.errors.Count -gt 0) { return $envelope }
$activeProfile = Get-HavocActiveCloudProfile
if ($activeProfile.resourceGraph.enabled -ne $true) {
    return Add-HavocError $envelope 'coverage_gap' `
        'Azure Resource Graph retrieval is disabled for the selected cloud profile.' `
        $false $false 'retrieval unavailable' 'resource_graph_unconfirmed_in_cloud'
}
if (-not (Test-HavocPolicyOperation ([string]$Intent.operationId) $PolicyPath)) {
    return Add-HavocError $envelope 'unsupported_capability' `
        'The requested Resource Graph operation is not supported by the approved policy.'
}
$trustedProvenance = Resolve-HavocProvenanceContext $Intent `
    $ProvenanceContextProvider $PolicyPath
if (-not $trustedProvenance.Success) {
    return Add-HavocError $envelope 'safety_policy_denied' `
        'Trusted provenance context validation failed.' $false $false `
        'retrieval unavailable' ([string]$trustedProvenance.Code)
}
$null = Set-HavocTrustedProvenance $envelope $trustedProvenance.Context
$budget = New-HavocRuntimeBudget $Intent $Clock
$current = Copy-HavocValue $Intent
$continuationFromResponse = $false
$continuationTokens = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$rawPages = [Collections.Generic.List[string]]::new()
$maxPages = [Math]::Max(1, [Math]::Min(1000, [long]$Intent.bounds.maxRows + 1))

while ($true) {
    if ($envelope.pagination.pages -ge $maxPages) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Resource Graph page limit was exhausted.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'page_limit_exhausted'
    }
    $capabilityKind = if ($continuationFromResponse -and
        $current.PSObject.Properties.Name -contains 'body' -and
        $null -ne $current.body -and
        $current.body.PSObject.Properties.Name -contains 'options' -and
        $null -ne $current.body.options -and
        $current.body.options.PSObject.Properties.Name -contains '$skipToken') {
        'continuation_token'
    }
    else { 'response_enforcement' }
    $result = Invoke-HavocAuthorizedRequest $current $PolicyPath $Transport $Sleeper `
        $MaxRetries $capabilityKind $budget $AuthContextProvider `
        $ProvenanceContextProvider
    Set-HavocRequestTelemetry $envelope $result $current
    if ($result.PSObject.Properties.Name -contains 'AuthFailure' -and
        $result.AuthFailure) {
        return Add-HavocAuthFailure $envelope $result
    }
    if ($result.BudgetExhausted) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized runtime budget was exhausted.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'budget_exhausted'
    }
    if (-not $result.Allowed) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            "Request denied by rule $($result.Decision.ruleId)." $false `
            ($rawPages.Count -gt 0) 'retrieval unavailable' `
            ([string]$result.Decision.reasonCode)
    }
    if ($result.PSObject.Properties.Name -contains 'TransportException' -and
        $result.TransportException) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized source transport was unavailable.' `
            ([bool]$result.TransportRetryable) ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'transport_exception'
    }
    if ($result.Exhausted) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'throttled' `
            'Retry limit exhausted while the source remained throttled.' $true ($rawPages.Count -gt 0)
    }
    $response = $result.Response
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope (Get-HavocErrorCategory $response.StatusCode) `
            "Source returned HTTP $($response.StatusCode)." ($response.StatusCode -ge 500) `
            ($rawPages.Count -gt 0) 'retrieval incomplete' "http_$($response.StatusCode)"
    }
    $bytes = Get-HavocUtf8ByteCount $response.Content
    if (($envelope.counts.bytes + $bytes) -gt [long]$Intent.bounds.maxBytes) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response byte limit exceeded before response acceptance.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'byte_limit_exceeded'
    }
    $parsed = ConvertFrom-HavocResponse $response.Content
    if (-not $parsed.Valid) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Source returned malformed JSON.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'malformed_json'
    }
    $page = $parsed.Value
    if ($page.PSObject.Properties.Name -contains 'error') {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'Resource Graph returned an HTTP-200 service error.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'http_200_service_error'
    }
    if ($page.PSObject.Properties.Name -notcontains 'totalRecords' -or
        -not (Test-HavocInt64 $page.totalRecords $true)) {
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Resource Graph totalRecords must be a nonnegative Int64.' $false `
            ($rawPages.Count -gt 0) 'retrieval incomplete' 'total_records_invalid'
    }
    $hasContinuation = $page.PSObject.Properties.Name -contains '$skipToken' -and
        -not [string]::IsNullOrWhiteSpace([string]$page.'$skipToken')
    $token = if ($hasContinuation) { [string]$page.'$skipToken' } else { '' }
    if ($hasContinuation) {
        if (-not $continuationTokens.Add($token)) {
            $envelope.integrity.duplicatePages = $true
            $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
            return Add-HavocError $envelope 'partial_response' `
                'Resource Graph continuation cycle detected.' $false $true `
                'retrieval incomplete' 'continuation_cycle'
        }
        $tokenResult = Invoke-HavocProtectedStore $ProtectedStore 'evidence' $token (
            [pscustomobject]@{
                operationId = [string]$Intent.operationId
                contentClass = 'continuation-token'
                pageId = "page-$($envelope.pagination.pages + 1)"
            }
        ) @('protected-evidence')
        if (-not $tokenResult.Success) {
            $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
            return Add-HavocError $envelope 'source_unavailable' `
                'Protected continuation persistence failed.' $false ($rawPages.Count -gt 0) `
                'retrieval incomplete' $tokenResult.Code
        }
    }
    if ($page.PSObject.Properties.Name -notcontains 'data') {
        return Add-HavocError $envelope 'schema_incompatible' `
            'Resource Graph response omitted data.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'data_missing'
    }
    $rows = @($page.data)
    if (($envelope.counts.rows + $rows.Count) -gt [long]$Intent.bounds.maxRows) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response row limit exceeded before response acceptance.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'row_limit_exceeded'
    }
    foreach ($row in $rows) {
        if ($row.PSObject.Properties.Name -notcontains 'id') { continue }
        $record = New-HavocProtectedRecordReference $ProtectedStore ([string]$row.id) `
            ([string]$Intent.operationId) ([string]$envelope.adapter.source)
        if (-not $record.Success) {
            $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
            return Add-HavocError $envelope 'source_unavailable' `
                'Protected record persistence was unavailable.' $false ($rawPages.Count -gt 0) `
                'retrieval incomplete' $record.Code
        }
        $envelope.records += [pscustomobject][ordered]@{ recordRef = $record.Reference }
    }
    $envelope.counts.bytes += $bytes
    $envelope.counts.rows += $rows.Count
    $envelope.counts.results = $envelope.counts.rows
    $rawPages.Add($response.Content)
    $envelope.pagination.pages++
    $envelope.pagination.pageIds += "page-$($envelope.pagination.pages)"
    Add-HavocLineage $envelope 'counts.rows' 'data[]' 'row-count'
    $remaining = Get-HavocHeader $response.Headers 'x-ms-user-quota-remaining'
    [long]$remainingValue = 0
    if ([long]::TryParse($remaining, [ref]$remainingValue)) {
        $envelope.quota.remaining = $remainingValue
    }
    $reset = Get-HavocHeader $response.Headers 'x-ms-user-quota-resets-after'
    if (-not [string]::IsNullOrWhiteSpace($reset)) {
        $envelope.quota.resetsAfter = $reset
    }
    if (-not $hasContinuation) {
        if ([int64]$page.totalRecords -gt $envelope.counts.rows) {
            $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
            return Add-HavocError $envelope 'partial_response' `
                'Resource Graph omitted continuation while total records remained.' `
                $false $true 'retrieval incomplete' 'continuation_missing'
        }
        $envelope.pagination.continuationState = 'exhausted'
        break
    }
    $current = Copy-HavocValue $Intent
    $current.body.options | Add-Member -NotePropertyName '$skipToken' `
        -NotePropertyValue $token -Force
    $current.body.options.'$top' = [Math]::Min(
        [long]$Intent.body.options.'$top',
        [long]$Intent.bounds.maxRows - [long]$envelope.counts.rows
    )
    if ([long]$current.body.options.'$top' -lt 1) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Resource Graph row budget was exhausted before continuation completed.' `
            $false $true 'retrieval incomplete' 'row_limit_exhausted'
    }
    $current.requestId = "$($Intent.requestId)-p$($envelope.pagination.pages + 1)"
    $continuationFromResponse = $true
    $envelope.pagination.continuationState = 'following'
}

if (-not (Save-AcceptedArgEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId))) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Protected evidence persistence was unavailable.' $false ($rawPages.Count -gt 0) `
        'retrieval incomplete' 'protected_store_unavailable'
}
$query = [uri][string]$Intent.uri
$envelope.schema.apiVersion = [Web.HttpUtility]::ParseQueryString($query.Query)['api-version']
Complete-HavocEnvelope $envelope
