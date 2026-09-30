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
    [ValidateRange(0, 8)][int]$MaxRetries = 2,
    [ValidateRange(1, 100)][int]$MaxPolls = 10,
    [ValidateRange(0, 60)][int]$PollIntervalSeconds = 2
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReadOnlyAdapter.Common.psm1') -Force
Set-HavocAdapterCloudProfile -Cloud $Cloud

function Save-AcceptedPurviewEvidence {
    param($Envelope, $Pages, $Store, [string]$OperationId)
    if ($Pages.Count -eq 0) { return $true }
    Protect-HavocAcceptedEvidence $Envelope $Store @($Pages) $OperationId
}

$envelope = New-HavocEnvelope 'microsoft-purview' 'purview-audit' `
    $Intent $ProtectedStore $Clock
if ($envelope.errors.Count -gt 0) { return $envelope }
$activeProfile = Get-HavocActiveCloudProfile
if ($activeProfile.purview.enabled -ne $true) {
    return Add-HavocError $envelope 'coverage_gap' `
        'Purview audit retrieval is disabled for the selected cloud profile.' `
        $false $false 'retrieval unavailable' 'purview_unconfirmed_in_cloud'
}
if (-not (Test-HavocPolicyOperation ([string]$Intent.operationId) $PolicyPath)) {
    return Add-HavocError $envelope 'unsupported_capability' `
        'The requested Purview operation is not supported by the approved policy.'
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
$rawPages = [Collections.Generic.List[string]]::new()
$submit = Invoke-HavocAuthorizedRequest $Intent $PolicyPath $Transport $Sleeper `
    $MaxRetries 'purview_lifecycle' $budget $AuthContextProvider `
    $ProvenanceContextProvider
Set-HavocRequestTelemetry $envelope $submit $Intent
if ($submit.PSObject.Properties.Name -contains 'AuthFailure' -and
    $submit.AuthFailure) {
    return Add-HavocAuthFailure $envelope $submit
}
if ($submit.BudgetExhausted) {
    return Add-HavocError $envelope 'source_unavailable' `
        'The authorized runtime budget was exhausted.' $false $false `
        'retrieval unavailable' 'budget_exhausted'
}
if (-not $submit.Allowed) {
    return Add-HavocError $envelope 'safety_policy_denied' `
        "Request denied by rule $($submit.Decision.ruleId)."
}
if ($submit.PSObject.Properties.Name -contains 'TransportException' -and
    $submit.TransportException) {
    return Add-HavocError $envelope 'source_unavailable' `
        'The authorized source transport was unavailable.' `
        ([bool]$submit.TransportRetryable) $false `
        'retrieval unavailable' 'transport_exception'
}
if ($submit.Exhausted) {
    return Add-HavocError $envelope 'throttled' `
        'Retry limit exhausted while Purview remained throttled.' $true
}
if ($submit.Response.StatusCode -lt 200 -or $submit.Response.StatusCode -ge 300) {
    return Add-HavocError $envelope (Get-HavocErrorCategory $submit.Response.StatusCode) `
        "Purview submit returned HTTP $($submit.Response.StatusCode)."
}
$envelope.counts.bytes += Get-HavocUtf8ByteCount $submit.Response.Content
if ($envelope.counts.bytes -gt [long]$Intent.bounds.maxBytes) {
    return Add-HavocError $envelope 'response_truncated' `
        'Response byte limit exceeded before response acceptance.'
}
$parsed = ConvertFrom-HavocResponse $submit.Response.Content
if (-not $parsed.Valid -or
    $parsed.Value.PSObject.Properties.Name -notcontains 'id' -or
    [string]$parsed.Value.id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
    return Add-HavocError $envelope 'malformed_response' `
        'Purview submit response omitted a safe job identifier.'
}
$jobId = [string]$parsed.Value.id
$rawPages.Add($submit.Response.Content)
if (-not (Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId))) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Protected submit evidence persistence was unavailable.' $false $true `
        'retrieval incomplete' 'protected_store_unavailable'
}
$base = 'https://graph.microsoft.com/v1.0/security/auditLog/queries'
$statusIntent = Copy-HavocValue $Intent
$statusIntent.operationId = 'purview-audit-query-get'
$statusIntent.method = 'GET'
$statusIntent.uri = "$base/$jobId"
$statusIntent.requestId = "$($Intent.requestId)-status"
$statusIntent.bounds.maxRows = 1
foreach ($property in @('body', 'retrievalJobPreconditions', 'responseEnforcement')) {
    if ($statusIntent.PSObject.Properties.Name -contains $property) {
        $statusIntent.PSObject.Properties.Remove($property)
    }
}

$succeeded = $false
for ($poll = 1; $poll -le $MaxPolls; $poll++) {
    $statusResult = Invoke-HavocAuthorizedRequest $statusIntent $PolicyPath `
        $Transport $Sleeper $MaxRetries 'none' $budget $AuthContextProvider `
        $ProvenanceContextProvider
    Set-HavocRequestTelemetry $envelope $statusResult $statusIntent
    if ($statusResult.PSObject.Properties.Name -contains 'AuthFailure' -and
        $statusResult.AuthFailure) {
        return Add-HavocAuthFailure $envelope $statusResult
    }
    if ($statusResult.BudgetExhausted) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized runtime budget was exhausted.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'budget_exhausted'
    }
    if (-not $statusResult.Allowed) {
        return Add-HavocError $envelope 'safety_policy_denied' `
            'Purview status operation was denied.'
    }
    if ($statusResult.PSObject.Properties.Name -contains 'TransportException' -and
        $statusResult.TransportException) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized source transport was unavailable.' `
            ([bool]$statusResult.TransportRetryable) ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'transport_exception'
    }
    if ($statusResult.Exhausted) {
        return Add-HavocError $envelope 'throttled' `
            'Retry limit exhausted while Purview status was throttled.' $true
    }
    if ($statusResult.Response.StatusCode -lt 200 -or
        $statusResult.Response.StatusCode -ge 300) {
        return Add-HavocError $envelope `
            (Get-HavocErrorCategory $statusResult.Response.StatusCode) `
            "Purview status returned HTTP $($statusResult.Response.StatusCode)."
    }
    $envelope.counts.bytes += Get-HavocUtf8ByteCount $statusResult.Response.Content
    if ($envelope.counts.bytes -gt [long]$Intent.bounds.maxBytes) {
        return Add-HavocError $envelope 'response_truncated' `
            'Response byte limit exceeded before response acceptance.'
    }
    $statusPayload = ConvertFrom-HavocResponse $statusResult.Response.Content
    if (-not $statusPayload.Valid -or
        $statusPayload.Value.PSObject.Properties.Name -notcontains 'status') {
        return Add-HavocError $envelope 'malformed_response' `
            'Purview status response was malformed.'
    }
    $rawPages.Add($statusResult.Response.Content)
    if (-not (Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$statusIntent.operationId))) {
        return Add-HavocError $envelope 'source_unavailable' `
            'Protected status evidence persistence was unavailable.' $false $true `
            'retrieval incomplete' 'protected_store_unavailable'
    }
    $state = [string]$statusPayload.Value.status
    if ($state -ceq 'succeeded') {
        $succeeded = $true
        break
    }
    if ($state -in @('failed', 'cancelled')) {
        return Add-HavocError $envelope 'source_unavailable' `
            'Purview retrieval job did not succeed.'
    }
    if ($poll -lt $MaxPolls) {
        $budgetCheck = Test-HavocRuntimeBudget $budget 'before_poll_sleep'
        if ($budgetCheck.Exhausted -or
            [double]$PollIntervalSeconds -ge
                [double]$budgetCheck.RemainingSeconds) {
            $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
            return Add-HavocError $envelope 'source_unavailable' `
                'The authorized runtime budget was exhausted.' $false ($rawPages.Count -gt 0) `
                'retrieval incomplete' 'budget_exhausted'
        }
        & $Sleeper $PollIntervalSeconds
        $budgetCheck = Test-HavocRuntimeBudget $budget 'after_poll_sleep'
        if ($budgetCheck.Exhausted) {
            $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
            return Add-HavocError $envelope 'source_unavailable' `
                'The authorized runtime budget was exhausted.' $false ($rawPages.Count -gt 0) `
                'retrieval incomplete' 'budget_exhausted'
        }
    }
}
if (-not $succeeded) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Purview polling limit was exhausted before completion.' $true
}

$recordsIntent = Copy-HavocValue $statusIntent
$recordsIntent.operationId = 'purview-audit-query-records-list'
$recordsIntent.bounds.maxRows = [long]$Intent.bounds.maxRows
$recordsPageSize = [Math]::Min(
    [long]$Intent.bounds.maxRows,
    [Math]::Floor([long]$Intent.bounds.maxBytes / 4096)
)
if ($recordsPageSize -lt 1) {
    return Add-HavocError $envelope 'invalid_input' `
        'Purview byte bounds cannot authorize one records page.'
}
$recordsIntent.uri = "$base/$jobId/records?`$top=$recordsPageSize"
$recordsIntent.requestId = "$($Intent.requestId)-records-1"
$visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$null = $visited.Add([string]$recordsIntent.uri)
$maxRecordPages = [Math]::Max(1, [Math]::Min(1000, [long]$Intent.bounds.maxRows + 1))
while ($true) {
    if ($envelope.pagination.pages -ge $maxRecordPages) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Purview records page limit was exhausted.' $false ($envelope.counts.rows -gt 0) `
            'retrieval incomplete' 'page_limit_exhausted'
    }
    $recordsResult = Invoke-HavocAuthorizedRequest $recordsIntent $PolicyPath `
        $Transport $Sleeper $MaxRetries 'none' $budget $AuthContextProvider `
        $ProvenanceContextProvider
    Set-HavocRequestTelemetry $envelope $recordsResult $recordsIntent
    if ($recordsResult.PSObject.Properties.Name -contains 'AuthFailure' -and
        $recordsResult.AuthFailure) {
        return Add-HavocAuthFailure $envelope $recordsResult
    }
    if ($recordsResult.BudgetExhausted) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized runtime budget was exhausted.' $false ($envelope.counts.rows -gt 0) `
            'retrieval incomplete' 'budget_exhausted'
    }
    if (-not $recordsResult.Allowed) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            'Purview records operation was denied.' $false ($envelope.counts.rows -gt 0)
    }
    if ($recordsResult.PSObject.Properties.Name -contains 'TransportException' -and
        $recordsResult.TransportException) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized source transport was unavailable.' `
            ([bool]$recordsResult.TransportRetryable) ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'transport_exception'
    }
    if ($recordsResult.Exhausted) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'throttled' `
            'Retry limit exhausted while Purview records were throttled.' $true `
            ($envelope.counts.rows -gt 0)
    }
    if ($recordsResult.Response.StatusCode -lt 200 -or
        $recordsResult.Response.StatusCode -ge 300) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope `
            (Get-HavocErrorCategory $recordsResult.Response.StatusCode) `
            "Purview records returned HTTP $($recordsResult.Response.StatusCode)." `
            ($recordsResult.Response.StatusCode -ge 500) ($envelope.counts.rows -gt 0) `
            'retrieval incomplete' "http_$($recordsResult.Response.StatusCode)"
    }
    $recordBytes = Get-HavocUtf8ByteCount $recordsResult.Response.Content
    if (($envelope.counts.bytes + $recordBytes) -gt [long]$Intent.bounds.maxBytes) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response byte limit exceeded before response acceptance.' $false `
            ($envelope.counts.rows -gt 0) 'retrieval incomplete' 'byte_limit_exceeded'
    }
    $recordsPayload = ConvertFrom-HavocResponse $recordsResult.Response.Content
    if (-not $recordsPayload.Valid -or
        $recordsPayload.Value.PSObject.Properties.Name -notcontains 'value') {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Purview records response was malformed.' $false ($envelope.counts.rows -gt 0) `
            'retrieval incomplete' 'malformed_records_response'
    }
    if ($recordsPayload.Value.PSObject.Properties.Name -contains 'error') {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'Purview returned an HTTP-200 service error.' $false `
            ($envelope.counts.rows -gt 0) 'retrieval incomplete' 'http_200_service_error'
    }
    if ($null -eq $recordsPayload.Value.value -or
        $recordsPayload.Value.value -isnot [System.Array]) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$recordsIntent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Purview records value must be a non-null array.' $false $true `
            'retrieval incomplete' 'records_value_malformed'
    }
    $rows = @($recordsPayload.Value.value)
    if (($envelope.counts.rows + $rows.Count) -gt [long]$Intent.bounds.maxRows) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Purview row limit exceeded before response acceptance.' $false `
            ($envelope.counts.rows -gt 0) 'retrieval incomplete' 'row_limit_exceeded'
    }
    $envelope.counts.bytes += $recordBytes
    $envelope.counts.rows += $rows.Count
    $envelope.counts.results = $envelope.counts.rows
    $rawPages.Add($recordsResult.Response.Content)
    if (-not (Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$recordsIntent.operationId))) {
        return Add-HavocError $envelope 'source_unavailable' `
            'Protected records evidence persistence was unavailable.' $false $true `
            'retrieval incomplete' 'protected_store_unavailable'
    }
    $envelope.pagination.pages++
    $envelope.pagination.pageIds += "page-$($envelope.pagination.pages)"
    Add-HavocLineage $envelope 'counts.rows' 'value[]' 'row-count'
    if ($recordsPayload.Value.PSObject.Properties.Name -notcontains '@odata.nextLink' -or
        [string]::IsNullOrWhiteSpace([string]$recordsPayload.Value.'@odata.nextLink')) {
        $envelope.pagination.continuationState = 'exhausted'
        break
    }
    try { $next = [uri][string]$recordsPayload.Value.'@odata.nextLink' }
    catch {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Purview continuation link was malformed.' $false $true `
            'retrieval incomplete' 'continuation_malformed'
    }
    if ($next.Scheme -cne 'https' -or
        $next.IdnHost.ToLowerInvariant() -cne 'graph.microsoft.com' -or
        [uri]::UnescapeDataString($next.AbsolutePath) -cne "/v1.0/security/auditLog/queries/$jobId/records") {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            'Purview continuation link drifted from the authorized commercial path.' `
            $false $true 'retrieval incomplete' 'continuation_scope_drift'
    }
    if (-not $visited.Add($next.AbsoluteUri)) {
        $null = Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'Purview continuation cycle detected.' $false $true `
            'retrieval incomplete' 'continuation_cycle'
    }
    $recordsIntent.uri = $next.AbsoluteUri
    $recordsIntent.requestId = "$($Intent.requestId)-records-$($envelope.pagination.pages + 1)"
}
if (-not (Save-AcceptedPurviewEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId))) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Protected evidence persistence was unavailable.' $false ($rawPages.Count -gt 0) `
        'retrieval incomplete' 'protected_store_unavailable'
}
$envelope.schema.apiVersion = 'v1.0'
Complete-HavocEnvelope $envelope
