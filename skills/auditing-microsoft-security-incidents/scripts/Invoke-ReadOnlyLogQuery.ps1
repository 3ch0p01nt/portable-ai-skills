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

$envelope = New-HavocEnvelope 'log-analytics' 'sentinel-law' $Intent $ProtectedStore $Clock
if ($envelope.errors.Count -gt 0) { return $envelope }
if (-not (Test-HavocPolicyOperation ([string]$Intent.operationId) $PolicyPath)) {
    return Add-HavocError $envelope 'unsupported_capability' `
        'The requested Log Analytics operation is not supported by the approved policy.'
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
$result = Invoke-HavocAuthorizedRequest $Intent $PolicyPath $Transport $Sleeper `
    $MaxRetries 'response_enforcement' $budget $AuthContextProvider `
    $ProvenanceContextProvider
Set-HavocRequestTelemetry $envelope $result $Intent
if ($result.PSObject.Properties.Name -contains 'AuthFailure' -and
    $result.AuthFailure) {
    return Add-HavocAuthFailure $envelope $result
}
if ($result.BudgetExhausted) {
    return Add-HavocError $envelope 'source_unavailable' `
        'The authorized runtime budget was exhausted.' $false $false `
        'retrieval unavailable' 'budget_exhausted'
}
if (-not $result.Allowed) {
    return Add-HavocError $envelope 'safety_policy_denied' `
        "Request denied by rule $($result.Decision.ruleId)."
}
if ($result.PSObject.Properties.Name -contains 'TransportException' -and
    $result.TransportException) {
    return Add-HavocError $envelope 'source_unavailable' `
        'The authorized source transport was unavailable.' `
        ([bool]$result.TransportRetryable) $false `
        'retrieval unavailable' 'transport_exception'
}
if ($result.Exhausted) {
    return Add-HavocError $envelope 'throttled' `
        'Retry limit exhausted while the source remained throttled.' $true
}
$response = $result.Response
if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
    $failure = Get-HavocResponseFailure $response
    return Add-HavocError $envelope $failure.Category $failure.Message `
        ($response.StatusCode -ge 500) $false 'retrieval unavailable' $failure.Code
}
$responseBytes = Get-HavocUtf8ByteCount $response.Content
if ($responseBytes -gt [long]$Intent.bounds.maxBytes) {
    $envelope.integrity.truncated = $true
    return Add-HavocError $envelope 'response_truncated' `
        'Response byte limit exceeded before response acceptance.'
}
$parsed = ConvertFrom-HavocResponse $response.Content
if (-not $parsed.Valid) {
    return Add-HavocError $envelope 'malformed_response' 'Source returned malformed JSON.'
}
$payload = $parsed.Value
$payloadText = $payload | ConvertTo-Json -Depth 100 -Compress
if ($payload.PSObject.Properties.Name -notcontains 'tables') {
    return Add-HavocError $envelope 'schema_incompatible' `
        'Log Analytics response omitted tables.'
}
$rows = 0
foreach ($table in @($payload.tables)) {
    if ($table.PSObject.Properties.Name -notcontains 'rows') {
        return Add-HavocError $envelope 'schema_incompatible' `
            'Log Analytics table omitted rows.'
    }
    $rows += @($table.rows).Count
}
$envelope.counts.rows = $rows
$envelope.counts.results = $rows
if ($rows -gt [long]$Intent.bounds.maxRows) {
    $envelope.integrity.truncated = $true
    return Add-HavocError $envelope 'response_truncated' `
        'Response row limit exceeded before response acceptance.'
}
$envelope.counts.bytes = $responseBytes
$envelope.pagination.pages = 1
$envelope.pagination.pageIds += 'page-1'
$envelope.pagination.continuationState = 'not_applicable'
Add-HavocLineage $envelope 'counts.rows' 'tables[].rows[]' 'row-count'
if (-not (Protect-HavocAcceptedEvidence $envelope $ProtectedStore $response.Content ([string]$Intent.operationId))) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Protected evidence persistence was unavailable.' $false ($rows -gt 0) `
        'retrieval incomplete' 'protected_store_unavailable'
}
if ($payloadText -match '"truncated"\s*:\s*true|"isTruncated"\s*:\s*true') {
    $envelope.integrity.truncated = $true
    return Add-HavocError $envelope 'response_truncated' `
        'Kusto truncation metadata was present.' $false ($rows -gt 0) `
        'retrieval incomplete' 'source_reported_truncation'
}
if ($payload.PSObject.Properties.Name -contains 'error') {
    $envelope.integrity.partial = $true
    return Add-HavocError $envelope 'partial_response' `
        'Log Analytics returned a partial service error.' $false ($rows -gt 0) `
        'retrieval incomplete' 'http_200_service_error'
}
$envelope.schema.apiVersion = 'v1'
Complete-HavocEnvelope $envelope
