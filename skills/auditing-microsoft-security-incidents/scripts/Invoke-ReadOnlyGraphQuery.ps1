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
$activeProfile = Get-HavocActiveCloudProfile
$graphHost = [string]$activeProfile.graphHost

function Save-AcceptedGraphEvidence {
    param($Envelope, $Pages, $Store, [string]$OperationId)
    if ($Pages.Count -eq 0) { return $true }
    Protect-HavocAcceptedEvidence $Envelope $Store @($Pages) $OperationId
}

function Add-GraphRecord {
    param($Envelope, $Row, $Store, [string]$OperationId)
    if ($null -eq $Row -or $Row.PSObject.Properties.Name -notcontains 'id' -or
        [string]::IsNullOrWhiteSpace([string]$Row.id)) {
        return [pscustomobject]@{ Success = $false; Code = 'record_identifier_missing' }
    }
    $stored = New-HavocProtectedRecordReference $Store ([string]$Row.id) `
        $OperationId ([string]$Envelope.adapter.source
        )
    if (-not $stored.Success) {
        return [pscustomobject]@{ Success = $false; Code = $stored.Code }
    }
    $Envelope.records += [pscustomobject][ordered]@{ recordRef = $stored.Reference }
    Add-HavocLineage $Envelope 'records.recordRef' 'id'
    foreach ($mapping in @(
        @{ Source = 'createdDateTime'; Target = 'event' },
        @{ Source = 'lastUpdateDateTime'; Target = 'update' },
        @{ Source = 'ingestedDateTime'; Target = 'ingestion' }
    )) {
        if ($Row.PSObject.Properties.Name -contains $mapping.Source -and
            -not [string]::IsNullOrWhiteSpace([string]$Row.($mapping.Source))) {
            $Envelope.times.($mapping.Target) += [string]$Row.($mapping.Source)
            Add-HavocLineage $Envelope "times.$($mapping.Target)" $mapping.Source
        }
    }
    [pscustomobject]@{ Success = $true }
}

function Get-SafeGraphBatchHeaders {
    param($Headers)
    $safe = [ordered]@{}
    if ($null -eq $Headers) { return [pscustomobject]$safe }
    foreach ($property in $Headers.PSObject.Properties) {
        $name = $property.Name.ToLowerInvariant()
        $value = [string]$property.Value
        if ($name -in @('request-id', 'client-request-id') -and
            $value -cmatch '^[A-Za-z0-9._:-]{1,128}$') {
            $safe[$name] = $value
        }
        elseif ($name -ceq 'retry-after' -and $value -cmatch '^[0-9]{1,3}$') {
            $safe[$name] = $value
        }
    }
    [pscustomobject]$safe
}

function Get-GraphBatchClassification {
    param([int]$Status)
    if ($Status -ge 200 -and $Status -lt 300) { return 'success' }
    if ($Status -eq 429) { return 'throttled' }
    if ($Status -in 401, 403) { return 'denied' }
    'failed'
}

function Get-GraphBatchExpectedShape {
    param($Request)
    $url = [string]$Request.url
    if ($url -cmatch '^/v1\.0/security/incidents/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?:\?(?:%24|\$)expand=alerts)?$') {
        return 'single_incident'
    }
    if ($url -cmatch '^/v1\.0/security/(?:incidents|alerts_v2)(?:\?|$)') {
        return 'collection'
    }
    'unsupported'
}

function Get-GraphBatchOperationId {
    param($Request)
    $shape = Get-GraphBatchExpectedShape $Request
    if ($shape -ceq 'single_incident') {
        return 'graph-security-incident-with-alerts-get'
    }
    if ([string]$Request.url -cmatch '^/v1\.0/security/incidents(?:\?|$)') {
        return 'graph-security-incidents-list'
    }
    if ([string]$Request.url -cmatch '^/v1\.0/security/alerts_v2(?:\?|$)') {
        return 'graph-security-alerts-list'
    }
    'graph-batch'
}

function Get-GraphBatchBodyResult {
    param($Body, [string]$ExpectedShape)
    if ($null -eq $Body) {
        return [pscustomobject]@{
            Valid = $false
            Code = 'response_body_missing'
            Rows = @()
        }
    }
    if ($Body -isnot [pscustomobject] -and
        $Body -isnot [Collections.IDictionary]) {
        return [pscustomobject]@{
            Valid = $false
            Code = 'unexpected_response_shape'
            Rows = @()
        }
    }
    if ($Body.PSObject.Properties.Name -contains 'error') {
        return [pscustomobject]@{
            Valid = $false
            Code = 'http_200_service_error'
            Rows = @()
            ServiceError = $true
        }
    }
    if ($ExpectedShape -ceq 'single_incident') {
        $valid = $Body.PSObject.Properties.Name -contains 'id' -and
            -not [string]::IsNullOrWhiteSpace([string]$Body.id) -and
            $Body.PSObject.Properties.Name -notcontains 'value'
        return [pscustomobject]@{
            Valid = $valid
            Code = if ($valid) { 'not-applicable:none' } else { 'unexpected_response_shape' }
            Rows = if ($valid) { @($Body) } else { @() }
        }
    }
    if ($ExpectedShape -ceq 'collection') {
        $valid = $Body.PSObject.Properties.Name -contains 'value' -and
            $null -ne $Body.value -and $Body.value -is [System.Array]
        return [pscustomobject]@{
            Valid = $valid
            Code = if ($valid) { 'not-applicable:none' } else { 'unexpected_response_shape' }
            Rows = if ($valid) { @($Body.value) } else { @() }
        }
    }
    [pscustomobject]@{
        Valid = $false
        Code = 'unexpected_response_shape'
        Rows = @()
    }
}

function Add-GraphBatchSubresponseError {
    param(
        $Envelope,
        [string]$Category,
        [string]$Code,
        [string]$Message,
        [bool]$Retryable,
        [string]$OperationId = 'graph-batch'
    )
    $Envelope | Add-Member -Force -NotePropertyName '_currentOperationId' `
        -NotePropertyValue $OperationId
    $Envelope.schema.sourceVersion = 'v1.0'
    $Envelope.schema.apiVersion = 'v1.0'
    $null = Add-HavocError $Envelope $Category $Message $Retryable `
        ([long]$Envelope.counts.rows -gt 0) 'retrieval incomplete' $Code
    [string]$Envelope.errors[-1].error_id
}

$envelope = New-HavocEnvelope 'microsoft-graph' 'graph-security' $Intent $ProtectedStore $Clock
if ($envelope.errors.Count -gt 0) { return $envelope }
if ([string]$Intent.operationId -ceq 'defender-legacy-run-hunting-query') {
    return Add-HavocError $envelope 'unsupported_capability' `
        'Legacy Defender hunting compatibility is disabled.' $false $false `
        'retrieval unavailable' 'legacy_compatibility_disabled'
}
if ([string]$Intent.operationId -ceq 'graph-security-run-hunting-query') {
    $envelope.capability.preview = $true
    $envelope.capability.conditional = $true
    return Add-HavocError $envelope 'unsupported_capability' `
        'Preview Graph hunting requires a future reviewed policy profile.' $false $false `
        'retrieval unavailable' 'preview_policy_profile_required'
}
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
        'The requested Graph operation is not supported by the approved policy.' `
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
$budget = New-HavocRuntimeBudget $Intent $Clock
$preflightAuth = Resolve-HavocAuthContext $Intent $PolicyPath `
    $AuthContextProvider $Clock
if (-not $preflightAuth.Success) {
    return Add-HavocError $envelope 'permission_denied' `
        'Trusted authorization context validation failed.' $false $false `
        'retrieval unavailable' ([string]$preflightAuth.Code)
}
$envelope.provenance.tenant_context_ref =
    [string]$preflightAuth.Context.tenant_context_ref
$envelope.queryLedger.provenance.tenant_context_ref =
    [string]$preflightAuth.Context.tenant_context_ref
if ([string]$Intent.operationId -ceq 'graph-risk-detections-list' -and
    @($preflightAuth.Context.license_capabilities) -cnotcontains 'entra_p1' -and
    @($preflightAuth.Context.license_capabilities) -cnotcontains 'entra_p2') {
    $envelope.coverage.license = 'missing'
    return Add-HavocError $envelope 'license_unavailable' `
        'Verified Microsoft Entra ID P1 or P2 licensing is unavailable.' `
        $false $false 'retrieval unavailable' 'entra_p1_or_p2_required'
}
$retentionSource = switch ([string]$Intent.operationId) {
    'graph-signins-list' { 'entra_signins' }
    'graph-directory-audits-list' { 'entra_directory_audits' }
    default { $null }
}
if ($null -ne $retentionSource) {
    $retentionMap = $preflightAuth.Context.effective_retention_days_by_source
    $property = $retentionMap.PSObject.Properties[$retentionSource]
    if ($null -eq $property) {
        return Add-HavocError $envelope 'retention_boundary' `
            'Verified retention evidence is unavailable.' $false $false `
            'retrieval unavailable' 'retention_evidence_missing'
    }
    $retention = $property.Value
    $envelope.coverage.retention = 'verified'
    $envelope.coverage.effectiveWindow | Add-Member -Force `
        -NotePropertyName days -NotePropertyValue ([int64]$retention.days)
    $envelope.coverage.effectiveWindow | Add-Member -Force `
        -NotePropertyName evidence_ref -NotePropertyValue ([string]$retention.evidence_ref)
    $requestedStart = [datetimeoffset][string]$Intent.bounds.startTime
    $requestedEnd = [datetimeoffset][string]$Intent.bounds.endTime
    $retentionNow = (& $Clock).ToUniversalTime()
    $cutoff = $retentionNow.AddDays(-[int64]$retention.days)
    if ($requestedStart -lt $cutoff) {
        $envelope.coverage.effectiveWindow.state = 'exceeded'
        return Add-HavocError $envelope 'retention_boundary' `
            'The requested Entra evidence starts before the verified retention cutoff.' `
            $false $false 'retrieval unavailable' 'retention_window_exceeded'
    }
    if ($requestedEnd -gt $retentionNow) {
        $envelope.coverage.effectiveWindow.state = 'invalid'
        return Add-HavocError $envelope 'retention_boundary' `
            'The requested Entra evidence extends beyond the trusted current time.' `
            $false $false 'retrieval unavailable' 'future_time_window'
    }
    $envelope.coverage.effectiveWindow.state = 'covered'
}
$isHunting = $false

$initialUri = [uri][string]$Intent.uri
$expectedHost = $initialUri.IdnHost.ToLowerInvariant()
$expectedPath = [uri]::UnescapeDataString($initialUri.AbsolutePath)
$visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$null = $visited.Add($initialUri.AbsoluteUri)
$current = Copy-HavocValue $Intent
$continuationFromResponse = $false
$rawPages = [Collections.Generic.List[string]]::new()
$maxPages = [Math]::Max(1, [Math]::Min(1000, [long]$Intent.bounds.maxRows + 1))

while ($true) {
    if ($envelope.pagination.pages -ge $maxPages) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Graph page limit was reached before continuation completed.' $false $true `
            'retrieval incomplete' 'page_limit_exhausted'
    }
    $capabilityKind = if ($continuationFromResponse) {
        'continuation_link'
    }
    elseif ($isHunting) { 'response_enforcement' }
    else { 'none' }
    $result = Invoke-HavocAuthorizedRequest $current $PolicyPath $Transport $Sleeper `
        $MaxRetries $capabilityKind `
        $budget $AuthContextProvider $ProvenanceContextProvider
    Set-HavocRequestTelemetry $envelope $result $current
    if ($result.PSObject.Properties.Name -contains 'AuthFailure' -and
        $result.AuthFailure) {
        return Add-HavocAuthFailure $envelope $result
    }
    if ($result.BudgetExhausted) {
        $protected = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        if (-not $protected) {
            return Add-HavocError $envelope 'source_unavailable' `
                'Protected evidence persistence was unavailable.' $false ($rawPages.Count -gt 0) `
                'retrieval incomplete' 'protected_store_unavailable'
        }
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized runtime budget was exhausted.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'budget_exhausted'
    }
    if (-not $result.Allowed) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            "Request denied by rule $($result.Decision.ruleId): $($result.Decision.reasonCode)." `
            $false ($rawPages.Count -gt 0) 'retrieval unavailable' `
            ([string]$result.Decision.reasonCode)
    }
    if ($result.PSObject.Properties.Name -contains 'TransportException' -and
        $result.TransportException) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'source_unavailable' `
            'The authorized source transport was unavailable.' `
            ([bool]$result.TransportRetryable) ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'transport_exception'
    }
    if ($result.Exhausted) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'throttled' `
            'Retry limit exhausted while the source remained throttled.' $true ($rawPages.Count -gt 0)
    }
    $response = $result.Response
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        $failure = Get-HavocResponseFailure $response
        return Add-HavocError $envelope $failure.Category $failure.Message `
            ($response.StatusCode -ge 500) ($rawPages.Count -gt 0) `
            'retrieval incomplete' $failure.Code
    }
    $bytes = Get-HavocUtf8ByteCount $response.Content
    if (($envelope.counts.bytes + $bytes) -gt [long]$Intent.bounds.maxBytes) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response byte limit exceeded before response acceptance.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'byte_limit_exceeded'
    }
    $envelope.counts.bytes += $bytes
    $parsed = ConvertFrom-HavocResponse $response.Content
    if (-not $parsed.Valid) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Source returned malformed JSON.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'malformed_json'
    }
    $page = $parsed.Value
    if ($page.PSObject.Properties.Name -contains 'error') {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'Source returned an HTTP-200 service error.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'http_200_service_error'
    }

    if ([string]$Intent.operationId -ceq 'graph-batch') {
        if ($page.PSObject.Properties.Name -notcontains 'responses' -or
            $null -eq $page.responses -or
            $page.responses -isnot [System.Array]) {
            return Add-HavocError $envelope 'schema_incompatible' `
                'Graph batch response omitted a response array.' $false $false `
                'retrieval unavailable' 'batch_responses_missing'
        }
        $requestedIds = @($Intent.body.requests | ForEach-Object { [string]$_.id })
        $responses = @($page.responses)
        $responseIds = @($responses | ForEach-Object { [string]$_.id })
        if (@($responseIds | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
            return Add-HavocError $envelope 'schema_incompatible' `
                'Graph batch response contained a duplicate response ID.' $false $false `
                'retrieval unavailable' 'batch_duplicate_response_id'
        }
        if (@($responseIds | Where-Object { $requestedIds -cnotcontains $_ }).Count -gt 0) {
            return Add-HavocError $envelope 'schema_incompatible' `
                'Graph batch response contained an unrequested response ID.' $false $false `
                'retrieval unavailable' 'batch_unrequested_response_id'
        }
        $missingIds = @($requestedIds | Where-Object {
            $responseIds -cnotcontains $_
        })
        $batchFailed = $false
        $acceptedBatch = [Collections.Generic.List[object]]::new()
        $states = [ordered]@{}
        $work = [Collections.Generic.Queue[object]]::new()
        foreach ($request in @($Intent.body.requests)) {
            $id = [string]$request.id
            $safe = [pscustomobject][ordered]@{
                id = $id
                status = 'unknown'
                classification = 'pending'
                headers = [pscustomobject][ordered]@{}
                errorRef = 'not-applicable:none'
                pagination = [pscustomobject][ordered]@{
                    pages = 0
                    pageIds = @()
                    continuationState = 'not_observed'
                }
            }
            $states[$id] = [pscustomobject]@{
                Request = $request
                OperationId = Get-GraphBatchOperationId $request
                Safe = $safe
                Visited = [Collections.Generic.HashSet[string]]::new(
                    [StringComparer]::Ordinal
                )
            }
            $initialSubrequestUri = [uri]("https://$graphHost$([string]$request.url)")
            $null = $states[$id].Visited.Add(
                $initialSubrequestUri.AbsoluteUri
            )
        }
        foreach ($subresponse in $responses) {
            $work.Enqueue([pscustomobject]@{
                Response = $subresponse
                State = $states[[string]$subresponse.id]
                Page = 1
            })
        }
        while ($work.Count -gt 0) {
            $item = $work.Dequeue()
            $subresponse = $item.Response
            $state = $item.State
            $request = $state.Request
            $safe = $state.Safe
            if ($subresponse.PSObject.Properties.Name -notcontains 'status' -or
                -not (Test-HavocInt64 $subresponse.status) -or
                [int64]$subresponse.status -lt 100 -or
                [int64]$subresponse.status -gt 599) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'malformed_response'
                $safe | Add-Member -Force -NotePropertyName error -NotePropertyValue (
                    [pscustomobject][ordered]@{ code = 'batch_status_invalid' }
                )
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'malformed_response' 'batch_status_invalid' `
                    "Graph batch subresponse $($subresponse.id) returned an invalid status." `
                    $false $state.OperationId
                continue
            }
            $status = [int][int64]$subresponse.status
            $classification = Get-GraphBatchClassification $status
            $safe.status = $status
            $safe.classification = $classification
            $safe.headers = Get-SafeGraphBatchHeaders $subresponse.headers
            if ($classification -cne 'success') {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $code = if ($subresponse.PSObject.Properties.Name -contains 'body' -and
                    $null -ne $subresponse.body -and
                    $subresponse.body.PSObject.Properties.Name -contains 'error' -and
                    $subresponse.body.error.PSObject.Properties.Name -contains 'code') {
                    [string]$subresponse.body.error.code
                }
                else { "http_$status" }
                if ($code -cnotmatch '^[A-Za-z0-9._-]{1,128}$') {
                    $code = 'service_error'
                }
                $safe | Add-Member -NotePropertyName error -NotePropertyValue (
                    [pscustomobject][ordered]@{ code = $code }
                )
                $category = Get-HavocErrorCategory ([int]$subresponse.status)
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope $category `
                    $code "Graph batch subresponse $($subresponse.id) returned HTTP $status." `
                    ($status -ge 500 -or $status -eq 429) $state.OperationId
                continue
            }
            $body = if ($subresponse.PSObject.Properties.Name -contains 'body') {
                $subresponse.body
            }
            else { $null }
            $bodyResult = Get-GraphBatchBodyResult $body (
                Get-GraphBatchExpectedShape $request
            )
            if (-not $bodyResult.Valid) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = if ($bodyResult.ServiceError) {
                    'failed'
                }
                else { 'malformed_response' }
                $safe | Add-Member -NotePropertyName error -NotePropertyValue (
                    [pscustomobject][ordered]@{ code = $bodyResult.Code }
                )
                $category = if ($bodyResult.ServiceError) {
                    'partial_response'
                }
                else { 'malformed_response' }
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope $category `
                    $bodyResult.Code "Graph batch subresponse $($subresponse.id) returned an invalid body." `
                    $false $state.OperationId
                continue
            }
            $rows = @($bodyResult.Rows)
            if (($envelope.counts.rows + $rows.Count) -gt [long]$Intent.bounds.maxRows) {
                $envelope.integrity.truncated = $true
                $null = Save-AcceptedGraphEvidence $envelope $acceptedBatch `
                    $ProtectedStore ([string]$Intent.operationId)
                return Add-HavocError $envelope 'response_truncated' `
                    'Graph batch row limit exceeded before response acceptance.' $false `
                    ($envelope.counts.rows -gt 0) 'retrieval incomplete' 'row_limit_exceeded'
            }
            foreach ($row in $rows) {
                $record = Add-GraphRecord $envelope $row $ProtectedStore ([string]$Intent.operationId)
                if (-not $record.Success) {
                    $null = Save-AcceptedGraphEvidence $envelope $acceptedBatch `
                        $ProtectedStore ([string]$Intent.operationId)
                    return Add-HavocError $envelope 'source_unavailable' `
                        'Protected record persistence was unavailable.' $false `
                        ($envelope.counts.rows -gt 0) 'retrieval incomplete' $record.Code
                }
            }
            $envelope.counts.rows += $rows.Count
            $envelope.counts.results = $envelope.counts.rows
            $acceptedBatch.Add([pscustomobject][ordered]@{
                id = [string]$subresponse.id
                operation = Get-GraphBatchExpectedShape $request
                body = $body
            })
            $safe.pagination.pages++
            $pageId = "batch-$([string]$subresponse.id)-page-$($safe.pagination.pages)"
            $safe.pagination.pageIds += $pageId
            $envelope.pagination.pages++
            $envelope.pagination.pageIds += $pageId
            if ($body.PSObject.Properties.Name -notcontains '@odata.nextLink' -or
                [string]::IsNullOrWhiteSpace([string]$body.'@odata.nextLink')) {
                $safe.pagination.continuationState = 'exhausted'
                continue
            }
            try {
                $next = [uri][string]$body.'@odata.nextLink'
                $original = [uri]("https://$graphHost$([string]$request.url)")
            }
            catch {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'malformed_response'
                $safe.pagination.continuationState = 'malformed'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'malformed_response' 'continuation_malformed' `
                    "Graph batch subresponse $($subresponse.id) returned a malformed continuation." `
                    $false $state.OperationId
                continue
            }
            if ($next.Scheme -cne 'https' -or
                $next.IdnHost.ToLowerInvariant() -cne $graphHost -or
                -not $next.IsDefaultPort -or
                -not [string]::IsNullOrEmpty($next.UserInfo) -or
                -not [string]::IsNullOrEmpty($next.Fragment) -or
                [uri]::UnescapeDataString($next.AbsolutePath) -cne
                    [uri]::UnescapeDataString($original.AbsolutePath)) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'gap'
                $safe.pagination.continuationState = 'denied'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'safety_policy_denied' 'continuation_scope_drift' `
                    "Graph batch subresponse $($subresponse.id) continuation left the authorized commercial path." `
                    $false $state.OperationId
                continue
            }
            $nextQuery = [Web.HttpUtility]::ParseQueryString($next.Query)
            $originalQuery = [Web.HttpUtility]::ParseQueryString($original.Query)
            if ([string]$nextQuery['$top'] -cne [string]$originalQuery['$top']) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'gap'
                $safe.pagination.continuationState = 'denied'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'safety_policy_denied' 'continuation_scope_drift' `
                    "Graph batch subresponse $($subresponse.id) continuation changed the authorized page size." `
                    $false $state.OperationId
                continue
            }
            $continuation = Invoke-HavocProtectedStore $ProtectedStore 'evidence' `
                $next.AbsoluteUri ([pscustomobject]@{
                    operationId = $state.OperationId
                    contentClass = 'continuation-token'
                    subrequestId = [string]$subresponse.id
                    pageId = $pageId
                }) @('protected-evidence')
            if (-not $continuation.Success) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'gap'
                $safe.pagination.continuationState = 'unavailable'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'source_unavailable' $continuation.Code `
                    "Graph batch subresponse $($subresponse.id) continuation could not be protected." `
                    $false $state.OperationId
                continue
            }
            if (-not $state.Visited.Add($next.AbsoluteUri)) {
                $batchFailed = $true
                $envelope.integrity.duplicatePages = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'gap'
                $safe.pagination.continuationState = 'cycle'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'partial_response' 'continuation_cycle' `
                    "Graph batch subresponse $($subresponse.id) continuation cycle was detected." `
                    $false $state.OperationId
                continue
            }
            if ($safe.pagination.pages -ge $maxPages) {
                $batchFailed = $true
                $envelope.integrity.truncated = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'gap'
                $safe.pagination.continuationState = 'bounded'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'response_truncated' 'page_limit_exhausted' `
                    "Graph batch subresponse $($subresponse.id) page bound was exhausted." `
                    $false $state.OperationId
                continue
            }
            $continuationIntent = Copy-HavocValue $Intent
            $continuationRequest = [pscustomobject][ordered]@{
                id = [string]$subresponse.id
                method = [string]$request.method
                url = $next.PathAndQuery
            }
            $continuationIntent.body.requests = @($continuationRequest)
            $continuationIntent.requestId =
                "$($Intent.requestId)-$([string]$subresponse.id)-p$($safe.pagination.pages + 1)"
            $safe.pagination.continuationState = 'following'
            $nextResult = Invoke-HavocAuthorizedRequest $continuationIntent $PolicyPath `
                $Transport $Sleeper $MaxRetries 'continuation_link' $budget $AuthContextProvider `
                $ProvenanceContextProvider
            Set-HavocRequestTelemetry $envelope $nextResult $continuationIntent
            if ($nextResult.PSObject.Properties.Name -contains 'AuthFailure' -and
                $nextResult.AuthFailure) {
                return Add-HavocAuthFailure $envelope $nextResult
            }
            $hasResponse = $nextResult.PSObject.Properties.Name -contains 'Response' -and
                $null -ne $nextResult.Response
            if ($nextResult.BudgetExhausted -or -not $nextResult.Allowed -or
                ($nextResult.PSObject.Properties.Name -contains 'TransportException' -and
                    $nextResult.TransportException) -or
                $nextResult.Exhausted -or
                -not $hasResponse -or
                $nextResult.Response.StatusCode -lt 200 -or
                $nextResult.Response.StatusCode -ge 300) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'gap'
                $safe.pagination.continuationState = 'failed'
                $code = if ($nextResult.BudgetExhausted) { 'budget_exhausted' }
                    elseif (-not $nextResult.Allowed) { 'continuation_authorization_denied' }
                    elseif ($nextResult.PSObject.Properties.Name -contains 'TransportException' -and
                        $nextResult.TransportException) { 'transport_exception' }
                    elseif ($nextResult.Exhausted) { 'retry_exhausted' }
                    elseif (-not $hasResponse) { 'continuation_response_missing' }
                    else { "http_$($nextResult.Response.StatusCode)" }
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'source_unavailable' $code `
                    "Graph batch subresponse $($subresponse.id) continuation failed." `
                    ($code -in @('transport_exception', 'retry_exhausted') -or
                        ($hasResponse -and $nextResult.Response.StatusCode -ge 500)) $state.OperationId
                continue
            }
            $nextBytes = Get-HavocUtf8ByteCount $nextResult.Response.Content
            if (($envelope.counts.bytes + $nextBytes) -gt
                [long]$Intent.bounds.maxBytes) {
                $envelope.integrity.truncated = $true
                $null = Save-AcceptedGraphEvidence $envelope $acceptedBatch `
                    $ProtectedStore ([string]$Intent.operationId)
                return Add-HavocError $envelope 'response_truncated' `
                    'Graph batch continuation exceeded the raw response byte limit.' `
                    $false ($envelope.counts.rows -gt 0) `
                    'retrieval incomplete' 'byte_limit_exceeded'
            }
            $envelope.counts.bytes += $nextBytes
            $nextPayload = ConvertFrom-HavocResponse $nextResult.Response.Content
            if (-not $nextPayload.Valid -or
                $nextPayload.Value.PSObject.Properties.Name -notcontains 'responses' -or
                $nextPayload.Value.responses -isnot [System.Array] -or
                @($nextPayload.Value.responses).Count -ne 1 -or
                [string]$nextPayload.Value.responses[0].id -cne [string]$subresponse.id) {
                $batchFailed = $true
                $envelope.failedIds += [string]$subresponse.id
                $safe.classification = 'malformed_response'
                $safe.pagination.continuationState = 'malformed'
                $safe.errorRef = Add-GraphBatchSubresponseError $envelope `
                    'malformed_response' 'batch_continuation_response_invalid' `
                    "Graph batch subresponse $($subresponse.id) continuation response was malformed." `
                    $false $state.OperationId
                continue
            }
            $work.Enqueue([pscustomobject]@{
                Response = $nextPayload.Value.responses[0]
                State = $state
                Page = $safe.pagination.pages + 1
            })
        }
        foreach ($missingId in $missingIds) {
            $batchFailed = $true
            $envelope.failedIds += [string]$missingId
            $missingState = $states[[string]$missingId]
            $missingState.Safe.classification = 'missing'
            $missingState.Safe.pagination.continuationState = 'not_observed'
            $missingState.Safe | Add-Member -Force -NotePropertyName error `
                -NotePropertyValue ([pscustomobject][ordered]@{
                    code = 'batch_missing_response_id'
                })
            $missingState.Safe.errorRef = Add-GraphBatchSubresponseError `
                $envelope 'partial_response' 'batch_missing_response_id' `
                "Graph batch omitted requested subresponse $missingId." `
                $false $missingState.OperationId
        }
        foreach ($id in $requestedIds) {
            $envelope.batchResponses += $states[$id].Safe
        }
        $envelope.failedIds = @($envelope.failedIds | Select-Object -Unique)
        $envelope.pagination.continuationState = if ($batchFailed) {
            'partial'
        }
        else { 'exhausted' }
        if (-not (Save-AcceptedGraphEvidence $envelope $acceptedBatch $ProtectedStore ([string]$Intent.operationId))) {
            return Add-HavocError $envelope 'source_unavailable' `
                'Protected evidence persistence was unavailable.' $false ($envelope.counts.rows -gt 0) `
                'retrieval incomplete' 'protected_store_unavailable'
        }
        if ($batchFailed) {
            if ($envelope.counts.rows -gt 0) {
                foreach ($error in $envelope.errors) {
                    $error.partial_data_available = $true
                    $error.partialDataAvailable = $true
                }
            }
            Set-HavocOperationContext $envelope $Intent
            return Add-HavocError $envelope 'partial_response' `
                'One or more Graph batch subresponses failed.' $true ($envelope.counts.rows -gt 0) `
                'retrieval incomplete' 'batch_partial_failure'
        }
        break
    }

    $rows = if ($isHunting) {
        if ($page.PSObject.Properties.Name -notcontains 'results' -or
            $null -eq $page.results -or
            $page.results -isnot [System.Array] -or
            $page.PSObject.Properties.Name -notcontains 'schema' -or
            $null -eq $page.schema -or
            $page.schema -isnot [System.Array]) {
            return Add-HavocError $envelope 'schema_incompatible' `
                'Graph hunting response omitted schema or results arrays.' `
                $false ($rawPages.Count -gt 0) 'retrieval incomplete' `
                'hunting_response_shape_invalid'
        }
        @($page.results)
    }
    elseif ([string]$Intent.operationId -in @(
        'graph-security-incident-with-alerts-get',
        'graph-user-get',
        'graph-application-get',
        'graph-service-principal-get',
        'graph-application-credentials-metadata-get',
        'graph-service-principal-credentials-metadata-get'
    )) {
        @($page)
    }
    elseif ($page.PSObject.Properties.Name -contains 'value' -and
        $null -ne $page.value -and
        $page.value -is [System.Array]) {
        @($page.value)
    }
    elseif ($page.PSObject.Properties.Name -contains 'value') {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Graph collection value must be a non-null array.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'collection_value_malformed'
    }
    else {
        return Add-HavocError $envelope 'schema_incompatible' `
            'Graph collection response omitted the value collection.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'collection_value_missing'
    }
    if (($envelope.counts.rows + $rows.Count) -gt [long]$Intent.bounds.maxRows) {
        $envelope.integrity.truncated = $true
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'response_truncated' `
            'Response row limit exceeded before response acceptance.' $false ($rawPages.Count -gt 0) `
            'retrieval incomplete' 'row_limit_exceeded'
    }
    if (-not $isHunting) {
        foreach ($row in $rows) {
            $record = Add-GraphRecord $envelope $row $ProtectedStore ([string]$Intent.operationId)
            if (-not $record.Success) {
                $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
                return Add-HavocError $envelope 'source_unavailable' `
                    'Protected record persistence was unavailable.' $false ($rawPages.Count -gt 0) `
                    'retrieval incomplete' $record.Code
            }
        }
    }
    $envelope.counts.rows += $rows.Count
    $envelope.counts.results = $envelope.counts.rows
    $rawPages.Add($response.Content)
    $envelope.pagination.pages++
    $envelope.pagination.pageIds += "page-$($envelope.pagination.pages)"
    Add-HavocLineage $envelope 'counts.rows' 'value[]' 'row-count'
    foreach ($headerName in @('request-id', 'client-request-id')) {
        $headerValue = Get-HavocHeader $response.Headers $headerName
        if (-not [string]::IsNullOrWhiteSpace($headerValue)) {
            $envelope.queryLedger.correlationIds += $headerValue
            $envelope.queryLedger.correlation_ids += $headerValue
        }
    }

    if ($isHunting -or
        [string]$Intent.operationId -in @(
            'graph-security-incident-with-alerts-get',
            'graph-user-get',
            'graph-application-get',
            'graph-service-principal-get',
            'graph-application-credentials-metadata-get',
            'graph-service-principal-credentials-metadata-get'
        ) -or
        $page.PSObject.Properties.Name -notcontains '@odata.nextLink' -or
        [string]::IsNullOrWhiteSpace([string]$page.'@odata.nextLink')) {
        $envelope.pagination.continuationState = 'exhausted'
        break
    }
    try { $next = [uri][string]$page.'@odata.nextLink' }
    catch {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'malformed_response' `
            'Graph continuation link is malformed.' $false $true `
            'retrieval incomplete' 'continuation_malformed'
    }
    if ($next.Scheme -cne 'https' -or
        $next.IdnHost.ToLowerInvariant() -cne $expectedHost -or
        [uri]::UnescapeDataString($next.AbsolutePath) -cne $expectedPath) {
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'safety_policy_denied' `
            'Graph continuation link drifted from the authorized commercial origin or path.' `
            $false $true 'retrieval incomplete' 'continuation_scope_drift'
    }
    if (-not $visited.Add($next.AbsoluteUri)) {
        $envelope.integrity.duplicatePages = $true
        $null = Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId)
        return Add-HavocError $envelope 'partial_response' `
            'Graph continuation cycle detected.' $false $true `
            'retrieval incomplete' 'continuation_cycle'
    }
    $current = Copy-HavocValue $Intent
    $current.uri = $next.AbsoluteUri
    $current.requestId = "$($Intent.requestId)-p$($envelope.pagination.pages + 1)"
    $continuationFromResponse = $true
    $envelope.pagination.continuationState = 'following'
}

if ($envelope.protectedResponseRef -ceq 'not-applicable:none' -and
    -not (Save-AcceptedGraphEvidence $envelope $rawPages $ProtectedStore ([string]$Intent.operationId))) {
    return Add-HavocError $envelope 'source_unavailable' `
        'Protected evidence persistence was unavailable.' $false ($envelope.counts.rows -gt 0) `
        'retrieval incomplete' 'protected_store_unavailable'
}
$envelope.schema.apiVersion = $initialUri.AbsolutePath.Split(
    '/',
    [StringSplitOptions]::RemoveEmptyEntries
)[0]
Complete-HavocEnvelope $envelope
