Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function Get-KProp {
    param($Object, [string[]]$Names, $Default = $null)
    if ($null -eq $Object) { return $Default }
    foreach ($name in $Names) {
        $value = Get-HavocProperty -InputObject $Object -Name $name
        if ($null -ne $value) { return $value }
    }
    $Default
}

function ConvertTo-KCanonicalJson {
    param($Value)
    ConvertTo-HavocCanonicalJson -Value $Value
}

function Get-KSha256Hex {
    param([string]$Text)
    Get-HavocSha256Hex -Text $Text
}

function New-KState {
    param([string]$Status, [string]$Detail)
    [pscustomobject][ordered]@{ status = $Status; detail = $Detail }
}

function Join-KScope {
    param($Value)
    $items = @(@(Get-HavocArray -Value $Value) | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique -CaseSensitive)
    if ($items.Count -eq 0) { return 'request-scoped' }
    $items -join ';'
}

function Test-KExactState {
    param($Value, [string[]]$Allowed)
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    return $Allowed -ccontains $text
}

function New-HavocEquivalentQueryFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$QueryLedger,
        [Parameter(Mandatory)]$EffectiveWindow
    )
    $scopeRefs = @(@(Get-HavocArray -Value (Get-KProp $QueryLedger @('scope_bounds') @())) |
        ForEach-Object { [string]$_ } |
        Where-Object { $_ -match '^(protected-context|protected-evidence|not-applicable|unknown):' } |
        Sort-Object -Unique -CaseSensitive)
    $canonical = [ordered]@{
        version = '1'
        operation_id = [string](Get-KProp $QueryLedger @('operation_id','operationId') '')
        source_id = [string](Get-KProp $QueryLedger @('source_id') '')
        query_ref = [string](Get-KProp $QueryLedger @('queryRef','query_ref') 'not-applicable:none')
        canonical_request_ref = [string](Get-KProp $QueryLedger @('canonical_request_ref','requestRef') 'not-applicable:none')
        time_bounds = [ordered]@{
            start_inclusive = [string](Get-KProp (Get-KProp $QueryLedger @('time_bounds') $null) @('start_inclusive') '')
            end_exclusive = [string](Get-KProp (Get-KProp $QueryLedger @('time_bounds') $null) @('end_exclusive') '')
        }
        effective_window = [ordered]@{
            start_inclusive = [string](Get-KProp $EffectiveWindow @('start_inclusive') '')
            end_exclusive = [string](Get-KProp $EffectiveWindow @('end_exclusive') '')
        }
        scope_refs = @($scopeRefs)
        entity_bounds_ref = [string](Get-KProp $QueryLedger @('entity_bounds') 'request-scoped')
        result_bounds = [string](Get-KProp $QueryLedger @('result_bounds') '')
    }
    'eqf-v1:' + (Get-KSha256Hex (ConvertTo-KCanonicalJson $canonical))
}

function Get-KCoverageMap {
    param($Error)
    $category = [string](Get-KProp $Error @('error_category') '')
    $code = [string](Get-KProp $Error @('error_code') '')
    switch ($category) {
        'permission_denied' { return @{ Dimension = 'permission_state'; Limitation = 'permission_state: permission denied or authorization boundary reached' } }
        'license_unavailable' { return @{ Dimension = 'licensing_state'; Limitation = 'licensing_state: required license or capability unavailable' } }
        'retention_boundary' { return @{ Dimension = 'retention_state'; Limitation = 'retention_state: requested window exceeded available retention' } }
        'source_unavailable' { return @{ Dimension = 'health_state'; Limitation = 'health_state: source unavailable or budget exhausted' } }
        'unsupported_capability' { return @{ Dimension = 'capability_state'; Limitation = 'capability_state: unsupported capability' } }
        'coverage_gap' {
            if ($code -in @('table_or_audit_disabled','AuditDisabled','TableDisabled','TableNotFound')) {
                return @{ Dimension = 'capability_state'; Limitation = 'audit_enablement: table or audit source disabled' }
            }
            if ($code -in @('source_not_onboarded','SourceNotOnboarded','WorkspaceNotOnboarded','NotOnboarded')) {
                return @{ Dimension = 'connector_health'; Limitation = 'sensor_coverage: source not onboarded' }
            }
            return @{ Dimension = 'capability_state'; Limitation = 'capability_state: coverage gap observed' }
        }
        default {
            if ($code -ceq 'budget_exhausted') {
                return @{ Dimension = 'health_state'; Limitation = 'health_state: source unavailable or budget exhausted' }
            }
            return @{ Dimension = 'health_state'; Limitation = 'health_state: adapter error limited coverage' }
        }
    }
}

function ConvertFrom-HavocAdapterEnvelopeToLedgerCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Envelope,
        [Parameter(Mandatory)][string]$CoverageId
    )

    $query = Get-KProp $Envelope @('queryLedger') $null
    if ($null -eq $query) { throw 'Adapter envelope does not contain queryLedger.' }
    $coverage = Get-KProp $Envelope @('coverage') $null
    $provenance = Get-KProp $Envelope @('provenance') $null
    $counts = Get-KProp $Envelope @('counts') $null
    $pagination = Get-KProp $Envelope @('pagination') $null
    $integrity = Get-KProp $Envelope @('integrity') $null
    $adapter = Get-KProp $Envelope @('adapter') $null

    $operationId = [string](Get-KProp $query @('operation_id','operationId') 'unknown-operation')
    $sourceId = [string](Get-KProp $query @('source_id') (Get-KProp $adapter @('source') 'unknown-source'))
    $timeBounds = Get-KProp $query @('time_bounds') $null
    $effectiveWindow = [pscustomobject][ordered]@{
        start_inclusive = [string](Get-KProp (Get-KProp $coverage @('effectiveWindow') $null) @('start') (Get-KProp $timeBounds @('start_inclusive') '1970-01-01T00:00:00Z'))
        end_exclusive = [string](Get-KProp (Get-KProp $coverage @('effectiveWindow') $null) @('end') (Get-KProp $timeBounds @('end_exclusive') '1970-01-01T00:00:01Z'))
    }
    $rowCount = [int64](Get-KProp $query @('row_count') (Get-KProp $counts @('rows') 0))
    $byteCount = [int64](Get-KProp $query @('byte_count') (Get-KProp $counts @('bytes') 0))
    $resultCount = [int64](Get-KProp $query @('result_count') (Get-KProp $counts @('results') $rowCount))
    $scopeRefs = @(@(Get-HavocArray -Value (Get-KProp $query @('scope_bounds') @())) | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique -CaseSensitive)
    $errors = @(Get-HavocArray -Value (Get-KProp $Envelope @('errors') @()))
    $classification = [string](Get-KProp $query @('response_classification') 'failed')
    if ([bool](Get-KProp $integrity @('truncated') $false)) { $classification = 'truncated' }
    elseif ([bool](Get-KProp $integrity @('partial') $false)) { $classification = 'partial' }
    elseif ([bool](Get-KProp (Get-KProp $Envelope @('throttling') $null) @('exhausted') $false)) { $classification = 'throttled' }
    elseif ($classification -cnotin @('success','partial','truncated','throttled','failed','denied','malformed')) { $classification = 'failed' }
    $continuationRaw = [string](Get-KProp $pagination @('continuationState') 'not_observed')
    $continuationStatus = if ($continuationRaw -cin @('exhausted','not_applicable')) { 'not_applicable' } elseif ($continuationRaw -ceq 'not_observed' -or [string]::IsNullOrWhiteSpace($continuationRaw)) { 'unknown' } else { 'applicable' }
    $status = [string](Get-KProp $Envelope @('status') 'failed')
    if ($status -cnotin @('success','partial','failed','denied','unsupported')) { $status = 'failed' }

    $queryRecord = [pscustomobject][ordered]@{
        operation_id = $operationId
        source_id = $sourceId
        target = [string](Get-KProp $query @('target') "${operationId}:policy-template")
        canonical_request_ref = [string](Get-KProp $query @('canonical_request_ref','requestRef') 'not-applicable:none')
        time_bounds = [pscustomobject][ordered]@{
            start_inclusive = [string](Get-KProp $timeBounds @('start_inclusive') $effectiveWindow.start_inclusive)
            end_exclusive = [string](Get-KProp $timeBounds @('end_exclusive') $effectiveWindow.end_exclusive)
        }
        entity_bounds = [string](Get-KProp $query @('entity_bounds') 'request-scoped')
        scope_bounds = Join-KScope $scopeRefs
        result_bounds = [string](Get-KProp $query @('result_bounds') 'rows<=0;bytes<=0')
        runtime_bounds = [string](Get-KProp $query @('runtime_bounds') 'seconds<=0')
        adapter_version = [string](Get-KProp $query @('adapter_version') (Get-KProp $adapter @('version') '0.0.0'))
        started_at = [string](Get-KProp $query @('started_at','startedAt') '1970-01-01T00:00:00Z')
        ended_at = [string](Get-KProp $query @('ended_at','endedAt') '1970-01-01T00:00:00Z')
        retrieval_at = [string](Get-KProp $query @('retrieval_at') (Get-KProp $query @('ended_at','endedAt') '1970-01-01T00:00:00Z'))
        authorized_purpose = [string](Get-KProp $query @('authorized_purpose','purpose') 'authorized incident audit retrieval')
        response_classification = $classification
        pagination_state = New-KState $(if ([int](Get-KProp $pagination @('pages') 0) -gt 0) { 'applicable' } else { 'unknown' }) ([string](Get-KProp $pagination @('state') 'not observed'))
        continuation_state = New-KState $continuationStatus $continuationRaw
        result_count = $resultCount
        row_count = $rowCount
        byte_count = $byteCount
        correlation_ids = @(Get-HavocArray -Value (Get-KProp $query @('correlation_ids') @()) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
        status = $status
        error_ref = [string](Get-KProp $query @('error_ref') 'not-applicable:none')
        truncation_state = New-KState $(if ([bool](Get-KProp $integrity @('truncated') $false)) { 'applicable' } else { 'not_applicable' }) $(if ([bool](Get-KProp $integrity @('truncated') $false)) { 'truncation observed' } else { 'not observed' })
        partial_state = New-KState $(if ([bool](Get-KProp $integrity @('partial') $false)) { 'applicable' } else { 'not_applicable' }) $(if ([bool](Get-KProp $integrity @('partial') $false)) { 'partial data isolated' } else { 'not observed' })
        throttling_state = New-KState $(if ([bool](Get-KProp (Get-KProp $Envelope @('throttling') $null) @('exhausted') $false)) { 'applicable' } else { 'not_applicable' }) $(if ([bool](Get-KProp (Get-KProp $Envelope @('throttling') $null) @('exhausted') $false)) { 'throttled and exhausted' } else { 'not observed' })
        retry_state = New-KState $(if ([int](Get-KProp (Get-KProp $Envelope @('throttling') $null) @('retries') 0) -gt 0) { 'applicable' } else { 'not_applicable' }) $(if ([int](Get-KProp (Get-KProp $Envelope @('throttling') $null) @('retries') 0) -gt 0) { 'retried' } else { 'not retried' })
        status_or_error_ref = [string](Get-KProp $query @('status_or_error_ref') $(if ($errors.Count -gt 0) { 'error-1' } else { 'success' }))
        protected_payload_ref = [string](Get-KProp $query @('protected_payload_ref') (Get-KProp $Envelope @('protectedResponseRef') 'not-applicable:none'))
        claim_ids = [object[]]@()
        evidence_ids = [object[]]@()
        gap_ids = [object[]]@()
        error_ids = [object[]]@($errors | ForEach-Object { [string](Get-KProp $_ @('error_id') '') } | Where-Object { $_ })
        behavior_bases = @('configurable_project_policy')
        effective_window = $effectiveWindow
        equivalent_query_fingerprint = $null
        request_reference_class = 'protected-request'
        query_reference_class = 'protected-request'
        repeat_detection_scope = @($scopeRefs)
        adapter_envelope_status = $status
        coverage_contribution_id = $CoverageId
    }
    $queryRecord.equivalent_query_fingerprint = New-HavocEquivalentQueryFingerprint $query $effectiveWindow

    $limitations = [Collections.Generic.List[string]]::new()
    foreach ($limitation in @(Get-HavocArray -Value (Get-KProp $coverage @('limitations') @()))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$limitation)) { $limitations.Add([string]$limitation) }
    }
    $dimensions = @{}
    foreach ($error in $errors) {
        $map = Get-KCoverageMap $error
        $dimensions[$map.Dimension] = $map.Limitation
        if (-not $limitations.Contains($map.Limitation)) { $limitations.Add($map.Limitation) }
    }
    if ($status -cne 'success') {
        $limitation = "retrieval_integrity: adapter envelope status $status"
        if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
    }
    if ($queryRecord.response_classification -ceq 'truncated' -or $queryRecord.truncation_state.status -ceq 'applicable' -or $queryRecord.continuation_state.status -cin @('applicable','unknown')) {
        $limitation = 'retrieval_integrity: response truncated or continuation remained'
        if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
    }
    if ($queryRecord.response_classification -ceq 'partial' -or $queryRecord.partial_state.status -ceq 'applicable') {
        $limitation = 'retrieval_integrity: partial response isolated'
        if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
    }
    if ($queryRecord.response_classification -ceq 'throttled' -or $queryRecord.throttling_state.status -ceq 'applicable') {
        $limitation = 'retrieval_integrity: throttling exhausted before complete retrieval'
        if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
    }
    if (@('failed','denied','malformed') -ccontains $queryRecord.response_classification) {
        $limitation = 'retrieval_integrity: retrieval did not complete successfully'
        if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
    }
    $permissionState = if ($dimensions.ContainsKey('permission_state')) { New-KState 'unknown' $dimensions['permission_state'] } elseif (Test-KExactState (Get-KProp $coverage @('permission') '') @('verified','verified_for_request','authorized','authorized_for_request')) { New-KState 'applicable' 'permission verified for request' } else { New-KState 'unknown' 'permission not observed' }
    $licenseState = if ($dimensions.ContainsKey('licensing_state')) { New-KState 'unknown' $dimensions['licensing_state'] } elseif (Test-KExactState (Get-KProp $coverage @('license') '') @('verified','available','licensed')) { New-KState 'applicable' 'license verified for source' } else { New-KState 'unknown' 'license not observed' }
    $retentionState = if ($dimensions.ContainsKey('retention_state')) { New-KState 'unknown' $dimensions['retention_state'] } elseif (Test-KExactState (Get-KProp $coverage @('retention') '') @('verified','bounded')) { New-KState 'applicable' 'retention boundary verified' } else { New-KState 'unknown' 'retention not observed' }
    $capabilityState = if ($dimensions.ContainsKey('capability_state')) { New-KState 'unknown' $dimensions['capability_state'] } elseif (Test-KExactState (Get-KProp $coverage @('capability') '') @('authorized','verified','available')) { New-KState 'applicable' 'source capability authorized' } else { New-KState 'unknown' 'capability not observed' }
    $provenanceRefs = @((Get-KProp $provenance @('evidence_refs') @()) | ForEach-Object { [string]$_ })
    $operatorAttested = @($provenanceRefs | Where-Object { $_ -match '(?i)operator-attested|attested' }).Count -gt 0
    $healthState = if ($dimensions.ContainsKey('health_state')) { New-KState 'unknown' $dimensions['health_state'] } elseif ([bool](Get-KProp $provenance @('connector_healthy') $false)) { New-KState 'applicable' $(if ($operatorAttested) { 'source health attested' } else { 'source health verified' }) } else { New-KState 'unknown' 'source health not observed' }
    $parserState = if (Test-KExactState (Get-KProp $provenance @('parser_quality') '') @('verified')) { New-KState 'applicable' 'parser quality verified' } else { New-KState 'unknown' 'parser quality not observed' }
    $connectorState = if ($dimensions.ContainsKey('connector_health')) { New-KState 'unknown' $dimensions['connector_health'] } elseif ([bool](Get-KProp $provenance @('connector_healthy') $false)) { New-KState 'applicable' $(if ($operatorAttested) { 'connector health attested' } else { 'connector health verified' }) } else { New-KState 'unknown' 'connector health not observed' }
    $transformationState = if ([string](Get-KProp $provenance @('dcr_transformation_ref') 'unknown:none') -match '^(not-applicable|protected-)') { New-KState 'applicable' 'transformation lineage bounded' } else { New-KState 'unknown' 'transformation lineage not observed' }
    $coverageState = [string](Get-KProp $coverage @('state') 'unknown')
    if ($coverageState -cnotin @('healthy','degraded','failed','unmonitored','structurally_absent','unknown')) { $coverageState = 'unknown' }
    if ($coverageState -cne 'healthy') {
        $limitation = "coverage_state: $coverageState"
        if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
    }
    if ($coverageState -ceq 'healthy' -and $limitations.Count -gt 0) { $coverageState = 'degraded' }
    $coverageGapIds = [object[]]@()
    if ($limitations.Count -gt 0) { $coverageGapIds = [object[]]@("GAP-$CoverageId") }

    $coverageReceipt = [pscustomobject][ordered]@{
        coverage_id = $CoverageId
        source_id = $sourceId
        source_identity = [string](Get-KProp $provenance @('source_context_ref') 'unknown:none')
        coverage_state = $coverageState
        configured_state = New-KState 'applicable' 'source configured by adapter envelope'
        observed_state = New-KState $(if ($status -eq 'success') { 'applicable' } else { 'unknown' }) $status
        scope = Join-KScope $scopeRefs
        health_state = $healthState
        freshness_state = New-KState 'unknown' 'freshness not observed by adapter envelope'
        delay_state = New-KState 'unknown' 'ingestion delay not observed by adapter envelope'
        retention_state = $retentionState
        effective_window = $effectiveWindow
        permission_state = $permissionState
        licensing_state = $licenseState
        capability_state = $capabilityState
        parser_health = $parserState
        schema_health = New-KState 'applicable' ('schema version ' + [string](Get-KProp $provenance @('schema_version') 'unknown'))
        connector_health = $connectorState
        transformation_health = $transformationState
        time_bounds = $queryRecord.time_bounds
        completeness = $(if ($limitations.Count -eq 0) { 'complete' } elseif ($coverageState -ceq 'failed') { 'insufficient' } else { 'partial' })
        limitations = @($limitations | Sort-Object -Unique)
        claim_ids = [object[]]@()
        evidence_ids = [object[]]@()
        gap_ids = $coverageGapIds
        error_ids = [object[]]@($queryRecord.error_ids)
        behavior_bases = @('configurable_project_policy')
        negative_evidence_boundary = [pscustomobject][ordered]@{
            source_health = $healthState.status
            audit_enablement = if ([bool](Get-KProp $provenance @('audit_enabled') $false)) { 'applicable' } else { 'unknown' }
            licensing = $licenseState.status
            retention = $retentionState.status
            parser_quality = $parserState.status
            sensor_coverage = if (Test-KExactState (Get-KProp $provenance @('sensor_coverage') '') @('verified')) { 'applicable' } elseif ([string]::IsNullOrWhiteSpace([string](Get-KProp $provenance @('sensor_coverage') '')) -and [bool](Get-KProp $provenance @('workspace_covered') $false)) { 'applicable' } else { 'unknown' }
        }
        limitation_dimensions = @($dimensions.Keys | Sort-Object -CaseSensitive)
        adapter_error_mappings = @($errors | ForEach-Object {
            $m = Get-KCoverageMap $_
            [pscustomobject][ordered]@{
                error_id = [string](Get-KProp $_ @('error_id') '')
                error_category = [string](Get-KProp $_ @('error_category') '')
                error_code = [string](Get-KProp $_ @('error_code') '')
                coverage_dimension = [string]$m.Dimension
                limitation = [string]$m.Limitation
            }
        })
        retrieval_integrity = [pscustomobject][ordered]@{
            response_classification = $queryRecord.response_classification
            pagination_state = $queryRecord.pagination_state.detail
            continuation_state = $queryRecord.continuation_state.status
            truncation_state = $queryRecord.truncation_state.status
            row_count = $rowCount
            byte_count = $byteCount
        }
    }
    if (@($coverageReceipt.gap_ids).Count -gt 0) {
        $coverageReceipt | Add-Member -NotePropertyName gap_id -NotePropertyValue @($coverageReceipt.gap_ids)[0]
    }

    [pscustomobject][ordered]@{ query_record = $queryRecord; coverage_receipt = $coverageReceipt }
}

function Test-HavocNegativeEvidenceCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$CoverageReceipt,
        [Parameter(Mandatory)][string]$ClaimId
    )
    $boundary = Get-KProp $CoverageReceipt @('negative_evidence_boundary') $null
    $coverageState = [string](Get-KProp $CoverageReceipt @('coverage_state') 'unknown')
    if (@('healthy','degraded','failed','unmonitored','structurally_absent','unknown') -cnotcontains $coverageState) { $coverageState = 'unknown' }
    $required = [ordered]@{
        source_health = 'source health'
        audit_enablement = 'audit enablement'
        licensing = 'licensing'
        retention = 'retention'
        parser_quality = 'parser quality'
        sensor_coverage = 'sensor coverage'
    }
    $missing = [Collections.Generic.List[string]]::new()
    if ($coverageState -cne 'healthy') { $missing.Add('coverage state') }
    foreach ($key in $required.Keys) {
        if ([string](Get-KProp $boundary @($key) 'unknown') -ne 'applicable') { $missing.Add($required[$key]) }
    }
    $completeness = [string](Get-KProp $CoverageReceipt @('completeness') 'not_assessed')
    $integrity = Get-KProp $CoverageReceipt @('retrieval_integrity') $null
    $responseClassification = [string](Get-KProp $integrity @('response_classification') 'failed')
    $truncationState = [string](Get-KProp $integrity @('truncation_state') 'unknown')
    $continuationState = [string](Get-KProp $integrity @('continuation_state') 'unknown')
    if ($completeness -cne 'complete' -or @('success') -cnotcontains $responseClassification -or $truncationState -ceq 'applicable' -or $continuationState -ceq 'applicable') {
        $missing.Add('retrieval integrity')
    }
    if ($missing.Count -gt 0) {
        return [pscustomobject][ordered]@{
            claim_id = $ClaimId
            disposition = 'gap'
            coverage_state = $coverageState
            reason = 'Not observed finding is downgraded because these coverage bounds are incomplete: ' + (($missing | Sort-Object) -join ', ')
            gap_ids = @("GAP-$ClaimId-COVERAGE")
            behavior_bases = @('configurable_project_policy')
        }
    }
    [pscustomobject][ordered]@{
        claim_id = $ClaimId
        disposition = 'accepted_not_observed'
        coverage_state = $coverageState
        reason = 'Not observed finding is bounded by source health, audit enablement, licensing, retention, parser quality, and sensor coverage.'
        gap_ids = @()
        behavior_bases = @('configurable_project_policy')
    }
}

Export-ModuleMember -Function @(
    'ConvertFrom-HavocAdapterEnvelopeToLedgerCoverage',
    'New-HavocEquivalentQueryFingerprint',
    'Test-HavocNegativeEvidenceCoverage'
)
