Set-StrictMode -Version Latest

<#
Accepted Bundle keys:
reportMetadata, incidentSummary, evidenceRecords, coverageReceipts, queryRecords,
entityRecords, timelineRecords, hypothesisRecords, causalRecords, decisionRecords,
automationRecords, recurrenceRecords, recoveryRecords, privacyRecords,
businessFactRecords, legalFactRecords, qaRecords, stopReceipt, errors,
detectionQuality, entityResolutionDecisions, decisionTimeSocReconstruction,
lifecycleContinuity, telemetryDrift, qaDisagreements.

Canonical snake_case aliases are also accepted for the 19 audit-output root
collections. Optional plan items are rendered in their contract section homes:
entity resolution decisions -> Entity Resolution; decision-time SOC
reconstruction -> SOC Decision-Time Review; lifecycle continuity -> Entity,
Timeline, Recurrence, and Recovery sections; telemetry drift -> Coverage and
Detection Audit; QA disagreements -> Independent QA; detectionQuality ->
Detection Audit. No Task 14 plan item is outside the report contract.
#>

$script:SectionManifest = @(
    [pscustomobject]@{ Id = 'report_metadata'; Ordinal = 1; Label = 'Report Metadata'; Collections = @('report_metadata'); BundleKeys = @('reportMetadata') },
    [pscustomobject]@{ Id = 'executive_assessment'; Ordinal = 2; Label = 'Executive Assessment'; Collections = @('incident_summary', 'evidence_records'); BundleKeys = @('incidentSummary', 'evidenceRecords') },
    [pscustomobject]@{ Id = 'incident_comparison'; Ordinal = 3; Label = 'Original Incident and Auditor Comparison'; Collections = @('incident_summary', 'decision_records', 'evidence_records'); BundleKeys = @('incidentSummary', 'decisionRecords', 'evidenceRecords') },
    [pscustomobject]@{ Id = 'authorization_and_safety'; Ordinal = 4; Label = 'Authorization and Safety'; Collections = @('report_metadata', 'query_records', 'coverage_receipts', 'errors'); BundleKeys = @('reportMetadata', 'queryRecords', 'coverageReceipts', 'errors') },
    [pscustomobject]@{ Id = 'coverage_and_limitations'; Ordinal = 5; Label = 'Coverage and Limitations'; Collections = @('coverage_receipts', 'errors'); BundleKeys = @('coverageReceipts', 'errors', 'telemetryDrift') },
    [pscustomobject]@{ Id = 'query_and_retrieval'; Ordinal = 6; Label = 'Query and Retrieval Record'; Collections = @('query_records', 'coverage_receipts', 'errors'); BundleKeys = @('queryRecords', 'coverageReceipts', 'errors') },
    [pscustomobject]@{ Id = 'evidence_ledger'; Ordinal = 7; Label = 'Evidence Ledger'; Collections = @('evidence_records'); BundleKeys = @('evidenceRecords') },
    [pscustomobject]@{ Id = 'entity_resolution'; Ordinal = 8; Label = 'Entity Resolution'; Collections = @('entity_records', 'evidence_records'); BundleKeys = @('entityRecords', 'evidenceRecords', 'entityResolutionDecisions', 'lifecycleContinuity') },
    [pscustomobject]@{ Id = 'timeline'; Ordinal = 9; Label = 'Multi-Clock Timeline'; Collections = @('timeline_records', 'evidence_records'); BundleKeys = @('timelineRecords', 'evidenceRecords', 'lifecycleContinuity') },
    [pscustomobject]@{ Id = 'competing_hypotheses'; Ordinal = 10; Label = 'Competing Hypotheses'; Collections = @('hypothesis_records', 'evidence_records'); BundleKeys = @('hypothesisRecords', 'evidenceRecords') },
    [pscustomobject]@{ Id = 'causal_analysis'; Ordinal = 11; Label = 'Multi-Factor Causal Analysis'; Collections = @('causal_records', 'evidence_records'); BundleKeys = @('causalRecords', 'evidenceRecords') },
    [pscustomobject]@{ Id = 'soc_decision_review'; Ordinal = 12; Label = 'SOC Decision-Time Review'; Collections = @('decision_records', 'evidence_records'); BundleKeys = @('decisionRecords', 'evidenceRecords', 'decisionTimeSocReconstruction') },
    [pscustomobject]@{ Id = 'detection_audit'; Ordinal = 13; Label = 'Detection Audit'; Collections = @('query_records', 'coverage_receipts', 'evidence_records'); BundleKeys = @('queryRecords', 'coverageReceipts', 'evidenceRecords', 'detectionQuality', 'telemetryDrift') },
    [pscustomobject]@{ Id = 'automation_provenance'; Ordinal = 14; Label = 'Automation Provenance'; Collections = @('automation_records', 'evidence_records'); BundleKeys = @('automationRecords', 'evidenceRecords') },
    [pscustomobject]@{ Id = 'recurrence_review'; Ordinal = 15; Label = 'Recurrence and Related-Incident Review'; Collections = @('recurrence_records', 'evidence_records'); BundleKeys = @('recurrenceRecords', 'evidenceRecords', 'lifecycleContinuity') },
    [pscustomobject]@{ Id = 'containment_and_recovery'; Ordinal = 16; Label = 'Containment and Recovery Review'; Collections = @('recovery_records', 'evidence_records'); BundleKeys = @('recoveryRecords', 'evidenceRecords', 'lifecycleContinuity') },
    [pscustomobject]@{ Id = 'privacy_review'; Ordinal = 17; Label = 'Privacy and Evidence Handling'; Collections = @('privacy_records'); BundleKeys = @('privacyRecords') },
    [pscustomobject]@{ Id = 'business_and_legal_facts'; Ordinal = 18; Label = 'Business and Legal Fact Packet'; Collections = @('business_fact_records', 'legal_fact_records', 'evidence_records'); BundleKeys = @('businessFactRecords', 'legalFactRecords', 'evidenceRecords') },
    [pscustomobject]@{ Id = 'recommendations'; Ordinal = 19; Label = 'Non-Executable Recommendations'; Collections = @('evidence_records'); BundleKeys = @('evidenceRecords') },
    [pscustomobject]@{ Id = 'independent_qa'; Ordinal = 20; Label = 'Independent QA'; Collections = @('qa_records'); BundleKeys = @('qaRecords', 'qaDisagreements') },
    [pscustomobject]@{ Id = 'stop_and_errors'; Ordinal = 21; Label = 'Stop Receipt and Errors'; Collections = @('stop_receipt', 'errors'); BundleKeys = @('stopReceipt', 'errors') }
)

$script:RootKeyMap = [ordered]@{
    report_metadata = 'reportMetadata'
    incident_summary = 'incidentSummary'
    evidence_records = 'evidenceRecords'
    coverage_receipts = 'coverageReceipts'
    query_records = 'queryRecords'
    entity_records = 'entityRecords'
    timeline_records = 'timelineRecords'
    hypothesis_records = 'hypothesisRecords'
    causal_records = 'causalRecords'
    decision_records = 'decisionRecords'
    automation_records = 'automationRecords'
    recurrence_records = 'recurrenceRecords'
    recovery_records = 'recoveryRecords'
    privacy_records = 'privacyRecords'
    business_fact_records = 'businessFactRecords'
    legal_fact_records = 'legalFactRecords'
    qa_records = 'qaRecords'
    stop_receipt = 'stopReceipt'
    errors = 'errors'
}

$script:PlanKeys = @(
    'detectionQuality',
    'entityResolutionDecisions',
    'decisionTimeSocReconstruction',
    'lifecycleContinuity',
    'telemetryDrift',
    'qaDisagreements'
)

function Get-HavocReportProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-HavocReportProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-HavocReportArray {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    return @($Value)
}

function Copy-HavocReportValue {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100 -DateKind String)
}

function New-HavocReportExplicitState {
    param([string]$Detail = 'Synthetic report assembler placeholder state.')
    [pscustomobject][ordered]@{
        status = 'unknown'
        detail = $Detail
    }
}

function New-HavocReportBoundedWindow {
    [pscustomobject][ordered]@{
        start_inclusive = '2026-01-01T00:00:00Z'
        end_exclusive = '2026-01-02T00:00:00Z'
    }
}

function New-HavocReportMetadataPlaceholder {
    [pscustomobject][ordered]@{
        report_id = 'REP-NOT-ASSESSED-001'
        created_at = '2026-01-01T00:00:00Z'
        audit_incident_ref = 'INC-AUDIT-NOT-ASSESSED-001'
        protected_incident_link_ref = 'protected-link:incident-not-assessed-001'
        operating_mode = 'offline_fixture'
        reference_window = [pscustomobject][ordered]@{
            start_inclusive = '2026-01-01T00:00:00Z'
            end_exclusive = '2026-01-02T00:00:00Z'
            original_timezone = 'UTC'
            reason = 'Report metadata was not supplied; placeholder records explicit limitation.'
        }
        contract_version = '2.0.0'
        schema_version = '2.0.0'
        label_map_version = '1.0.0'
        policy_version = '1.0.0'
        adapter_versions = [pscustomobject]@{}
        source_versions = [pscustomobject]@{}
        report_status = 'partial'
        report_locale = 'en'
        handling_marking = 'synthetic'
        execution_identity = 'offline-report-assembler'
        authorization_purpose = 'Offline fixture report assembly without live tenant calls'
        protected_evidence_store_reference_class = 'opaque_non_bearer_locator'
        authorization_scope_ref = 'not assessed placeholder scope'
    }
}

function New-HavocIncidentSummaryPlaceholder {
    [pscustomobject][ordered]@{
        summary_id = 'SUM-NOT-ASSESSED-001'
        original_status = 'not assessed'
        original_classification = 'not assessed'
        auditor_judgment = 'Incident summary was not assessed because the Bundle did not include incidentSummary.'
        likelihood = 'not_assessed'
        analytic_confidence = 'not_assessed'
        report_status = 'partial'
        claim_ids = @('C-NOT-ASSESSED-001')
        evidence_ids = @()
        gap_ids = @('GAP-incident-summary-not-assessed')
        error_ids = @()
        behavior_bases = @('explicit_gap')
    }
}

function New-HavocStopReceiptPlaceholder {
    [pscustomobject][ordered]@{
        stop_receipt_id = 'STOP-NOT-ASSESSED-001'
        stop_cause = 'operator_stop'
        stopped_at = '2026-01-01T00:00:00Z'
        actor = 'offline-report-assembler'
        policy_version = '1.0.0'
        configured_values = [pscustomobject]@{}
        consumption = [pscustomobject]@{}
        coverage_summary = 'Stop receipt was not assessed because the Bundle did not include stopReceipt.'
        unresolved_material_frontier = @('Missing stop receipt.')
        duplicate_lineage_groups = @()
        novel_evidence_summary = 'Not assessed.'
        hypothesis_stability = 'Not assessed.'
        circuit_breaker_state = 'Not assessed.'
        last_successful_operation = 'offline-report-assembly'
        gap_ids = @('GAP-stop-receipt-not-assessed')
        error_ids = @()
        restart_conditions = @('Provide a stopReceipt from the audit runner.')
        gap_records = @()
        behavior_bases = @('explicit_gap')
    }
}

function Get-HavocReportBundleKeys {
    param([AllowNull()]$Bundle)
    if ($null -eq $Bundle) { return @() }
    if ($Bundle -is [hashtable] -or $Bundle -is [System.Collections.IDictionary]) {
        return @($Bundle.Keys | ForEach-Object { [string]$_ })
    }
    return @($Bundle.PSObject.Properties.Name)
}

function Test-HavocReportValueEmpty {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace($Value) }
    if ($Value -is [System.Collections.IEnumerable]) { return @(Get-HavocReportArray $Value).Count -eq 0 }
    return $false
}

function Get-HavocRootValue {
    param(
        [AllowNull()]$Bundle,
        [Parameter(Mandatory)][string]$RootName
    )
    $camel = $script:RootKeyMap[$RootName]
    if (Test-HavocReportProperty -InputObject $Bundle -Name $camel) {
        return Copy-HavocReportValue (Get-HavocReportProperty -InputObject $Bundle -Name $camel)
    }
    if (Test-HavocReportProperty -InputObject $Bundle -Name $RootName) {
        return Copy-HavocReportValue (Get-HavocReportProperty -InputObject $Bundle -Name $RootName)
    }
    switch ($RootName) {
        'report_metadata' { return New-HavocReportMetadataPlaceholder }
        'incident_summary' { return @(New-HavocIncidentSummaryPlaceholder) }
        'stop_receipt' { return New-HavocStopReceiptPlaceholder }
        default { return @() }
    }
}

function Test-HavocRootPresent {
    param(
        [AllowNull()]$Bundle,
        [Parameter(Mandatory)][string]$RootName
    )
    $camel = $script:RootKeyMap[$RootName]
    return (Test-HavocReportProperty -InputObject $Bundle -Name $camel) -or
        (Test-HavocReportProperty -InputObject $Bundle -Name $RootName)
}

function Get-HavocObjectIds {
    param([AllowNull()]$Record)
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @('claim_ids', 'evidence_ids', 'gap_ids', 'error_ids', 'supporting_evidence_ids', 'contradicting_evidence_ids', 'available_evidence_ids', 'later_evidence_ids', 'input_evidence_ids')) {
        foreach ($value in (Get-HavocReportArray (Get-HavocReportProperty -InputObject $Record -Name $name))) {
            $text = [string]$value
            if (-not [string]::IsNullOrWhiteSpace($text)) { $ids.Add($text) }
        }
    }
    foreach ($name in @('evidence_id', 'analytic_record_id', 'coverage_id', 'operation_id', 'request_id', 'entity_id', 'timeline_id', 'hypothesis_id', 'causal_id', 'decision_id', 'automation_id', 'recurrence_id', 'recovery_id', 'privacy_id', 'business_fact_id', 'legal_fact_id', 'qa_id', 'error_id', 'stop_receipt_id', 'summary_id')) {
        $value = Get-HavocReportProperty -InputObject $Record -Name $name
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) { $ids.Add([string]$value) }
    }
    return @($ids | Select-Object -Unique)
}

function Get-HavocSectionIds {
    param(
        [Parameter(Mandatory)]$Output,
        [Parameter(Mandatory)]$Section
    )
    $claimIds = [System.Collections.Generic.List[string]]::new()
    $evidenceIds = [System.Collections.Generic.List[string]]::new()
    $gapIds = [System.Collections.Generic.List[string]]::new()
    $errorIds = [System.Collections.Generic.List[string]]::new()

    foreach ($collectionName in $Section.Collections) {
        $value = Get-HavocReportProperty -InputObject $Output -Name $collectionName
        foreach ($record in (Get-HavocReportArray $value)) {
            foreach ($id in (Get-HavocReportArray (Get-HavocReportProperty -InputObject $record -Name 'claim_ids'))) { if ($id) { $claimIds.Add([string]$id) } }
            foreach ($id in (Get-HavocReportArray (Get-HavocReportProperty -InputObject $record -Name 'evidence_ids'))) { if ($id) { $evidenceIds.Add([string]$id) } }
            $ownEvidenceId = Get-HavocReportProperty -InputObject $record -Name 'evidence_id'
            if ($ownEvidenceId) { $evidenceIds.Add([string]$ownEvidenceId) }
            foreach ($id in (Get-HavocReportArray (Get-HavocReportProperty -InputObject $record -Name 'gap_ids'))) { if ($id) { $gapIds.Add([string]$id) } }
            foreach ($id in (Get-HavocReportArray (Get-HavocReportProperty -InputObject $record -Name 'error_ids'))) { if ($id) { $errorIds.Add([string]$id) } }
            $ownErrorId = Get-HavocReportProperty -InputObject $record -Name 'error_id'
            if ($ownErrorId) { $errorIds.Add([string]$ownErrorId) }
        }
    }

    [pscustomobject]@{
        claim_ids = @($claimIds | Select-Object -Unique)
        evidence_ids = @($evidenceIds | Select-Object -Unique)
        gap_ids = @($gapIds | Select-Object -Unique)
        error_ids = @($errorIds | Select-Object -Unique)
    }
}

function New-HavocReportSections {
    param(
        [AllowNull()]$Bundle,
        [Parameter(Mandatory)]$Output,
        [string[]]$MissingBundleKeys = @(),
        [string[]]$EmptyBundleKeys = @()
    )
    foreach ($section in $script:SectionManifest) {
        $missingForSection = @($section.BundleKeys | Where-Object {
            $_ -notin $script:PlanKeys -and
            -not (Test-HavocReportProperty -InputObject $Bundle -Name $_) -and
            -not (Test-HavocReportProperty -InputObject $Bundle -Name ((($script:RootKeyMap.GetEnumerator() | Where-Object Value -eq $_).Key) | Select-Object -First 1))
        })
        $emptyForSection = @($section.BundleKeys | Where-Object {
            $_ -notin $script:PlanKeys -and $_ -in $EmptyBundleKeys
        })
        $ids = Get-HavocSectionIds -Output $Output -Section $section
        $hasMissing = ($missingForSection.Count + $emptyForSection.Count) -gt 0
        $gapIds = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $ids.gap_ids) { $gapIds.Add([string]$id) }
        if ($hasMissing) { $gapIds.Add(('GAP-{0}-not-assessed' -f $section.Id.Replace('_', '-'))) }
        $notAssessedKeys = @($missingForSection + $emptyForSection | Select-Object -Unique)
        $summary = if ($hasMissing) {
            'Section not assessed for absent or empty Bundle keys: {0}.' -f ($notAssessedKeys -join ', ')
        }
        else {
            'Section assembled from supplied audit projection records.'
        }
        if ($section.Id -eq 'coverage_and_limitations' -and (($MissingBundleKeys.Count + $EmptyBundleKeys.Count) -gt 0)) {
            $summaryParts = [System.Collections.Generic.List[string]]::new()
            if ($MissingBundleKeys.Count -gt 0) {
                $summaryParts.Add(('Missing Bundle keys: {0}.' -f ($MissingBundleKeys -join ', ')))
            }
            if ($EmptyBundleKeys.Count -gt 0) {
                $summaryParts.Add(('Empty Bundle keys: {0}.' -f ($EmptyBundleKeys -join ', ')))
            }
            $summary = 'Coverage limitations include not assessed inputs. {0}' -f (@($summaryParts) -join ' ')
        }
        $behaviorBases = if ($hasMissing) {
            [object[]]@('configurable_project_policy', 'explicit_gap')
        }
        else {
            [object[]]@('configurable_project_policy')
        }
        $behaviorBases = [object[]]@($behaviorBases)
        [pscustomobject][ordered]@{
            section_id = $section.Id
            ordinal = $section.Ordinal
            section_status = if ($hasMissing) { 'partial' } else { 'complete' }
            evidence_completeness = if ($hasMissing) { 'not_assessed' } else { 'partial' }
            behavior_bases = $behaviorBases
            summary = $summary
            collection_refs = @($section.Collections)
            claim_ids = @($ids.claim_ids)
            evidence_ids = @($ids.evidence_ids)
            gap_ids = @($gapIds | Select-Object -Unique)
            error_ids = @($ids.error_ids)
        }
    }
}

function ConvertTo-HavocReportOutput {
    param([AllowNull()]$Bundle)
    $output = [ordered]@{}
    foreach ($rootName in $script:RootKeyMap.Keys) {
        $value = Get-HavocRootValue -Bundle $Bundle -RootName $rootName
        if ($rootName -in @('report_metadata', 'stop_receipt')) {
            $output[$rootName] = $value
        }
        else {
            $output[$rootName] = @(Get-HavocReportArray $value)
        }
    }
    foreach ($record in @(Get-HavocReportArray $output['evidence_records'])) {
        $normalized = Get-HavocReportProperty -InputObject $record -Name 'normalized_value'
        if ($normalized -is [string]) {
            $record.normalized_value = [pscustomobject][ordered]@{
                value = $normalized
                normalization_status = 'normalized'
            }
        }
    }

    $missingKeys = [System.Collections.Generic.List[string]]::new()
    $emptyKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($rootName in $script:RootKeyMap.Keys) {
        if ($rootName -eq 'report_metadata') { continue }
        $camel = $script:RootKeyMap[$rootName]
        if (-not (Test-HavocRootPresent -Bundle $Bundle -RootName $rootName)) {
            $missingKeys.Add($camel)
        }
        elseif ($rootName -notin @('stop_receipt', 'errors') -and (Test-HavocReportValueEmpty -Value $output[$rootName])) {
            $emptyKeys.Add($camel)
        }
    }
    $output['sections'] = @(New-HavocReportSections -Bundle $Bundle -Output ([pscustomobject]$output) -MissingBundleKeys @($missingKeys) -EmptyBundleKeys @($emptyKeys))
    return [pscustomobject]$output
}

function Protect-HavocMarkdownText {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $text = ([string]$Value) -replace "\r\n|\r|\n", ' '
    $encoded = [System.Net.WebUtility]::HtmlEncode($text)
    return ($encoded -replace '([\\`~*_{}\[\]()#\+=.!|-])', '\$1')
}

function Test-HavocTenantMutationText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $mutatingRestMethod = '\b(?:POST|PUT|PATCH|DELETE)\b'
    $microsoftTenantEndpoint = 'https://(?:graph\.microsoft\.com|security\.microsoft\.com|api\.securitycenter\.microsoft\.com|management\.azure\.com)/'
    if ($Text -match "(?i)\bInvoke-(?:RestMethod|WebRequest)\b(?=.*(?:^|\s)-Method\s+$mutatingRestMethod)(?=.*$microsoftTenantEndpoint)") {
        return $true
    }
    if ($Text -match "(?i)\baz\s+rest\b(?=.*(?:^|\s)(?:--method|-m)\s+$mutatingRestMethod)(?=.*$microsoftTenantEndpoint)") {
        return $true
    }
    return $Text -match '\b(?:Set|New|Remove|Update|Add|Grant|Revoke|Disable|Enable)-[A-Za-z]+' -or
        $Text -match '\baz\s+(?:ad|account|role|keyvault|storage|sentinel|monitor)\s+\S+\s+(?:create|update|delete|remove|set|assign|reset)\b'
}

function Get-HavocRecordSummaryText {
    param([AllowNull()]$Record)
    foreach ($name in @('auditor_judgment', 'normalized_value', 'summary', 'statement', 'output_summary', 'observed_action', 'fact', 'purpose', 'coverage_summary', 'safe_message', 'lifecycle_summary')) {
        $value = Get-HavocReportProperty -InputObject $Record -Name $name
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            if ($name -eq 'normalized_value' -and -not ($value -is [string])) {
                $nested = Get-HavocReportProperty -InputObject $value -Name 'value'
                if ($null -ne $nested) { $value = $nested }
            }
            if (Test-HavocTenantMutationText -Text ([string]$value)) {
                return 'Review the recommended tenant-state change through the separate approval process.'
            }
            return Protect-HavocMarkdownText $value
        }
    }
    $ids = @(Get-HavocObjectIds -Record $Record)
    if ($ids.Count -gt 0) { return Protect-HavocMarkdownText ($ids[0]) }
    return 'Record present.'
}

function Add-HavocReportPlanNote {
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [AllowNull()]$Bundle,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Test-HavocReportProperty -InputObject $Bundle -Name $Key)) { return }
    $value = Get-HavocReportProperty -InputObject $Bundle -Name $Key
    [void]$Builder.AppendLine(('- {0}: {1}' -f $Label, (Protect-HavocMarkdownText (($value | ConvertTo-Json -Depth 20 -Compress)))))
}

function Add-HavocReportRecordTable {
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [AllowNull()][object[]]$Records,
        [Parameter(Mandatory)][string[]]$Fields
    )
    $items = @(Get-HavocReportArray $Records)
    if ($items.Count -eq 0) { return }

    [void]$Builder.AppendLine(('| {0} |' -f (($Fields | ForEach-Object { Protect-HavocMarkdownText $_ }) -join ' | ')))
    [void]$Builder.AppendLine(('|{0}|' -f (($Fields | ForEach-Object { '---' }) -join '|')))
    foreach ($record in $items) {
        $cells = foreach ($field in $Fields) {
            $value = Get-HavocReportProperty -InputObject $record -Name $field
            if ($field -eq 'normalized_value' -and $null -ne $value -and -not ($value -is [string])) {
                $nested = Get-HavocReportProperty -InputObject $value -Name 'value'
                if ($null -ne $nested) { $value = $nested }
            }
            if ($null -ne $value -and $value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                Protect-HavocMarkdownText ((@(Get-HavocReportArray $value) | ForEach-Object { [string]$_ }) -join ', ')
            }
            else {
                Protect-HavocMarkdownText $value
            }
        }
        [void]$Builder.AppendLine(('| {0} |' -f ($cells -join ' | ')))
    }
    [void]$Builder.AppendLine()
}

function New-HavocReportMarkdown {
    param(
        [Parameter(Mandatory)]$Output,
        [AllowNull()]$Bundle
    )
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('# HAVOC Microsoft Incident Audit Report')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('This offline report assembly performs no live tenant calls and executes no tenant-state changes.')
    [void]$builder.AppendLine()

    foreach ($section in $Output.sections) {
        $manifest = $script:SectionManifest | Where-Object Id -eq $section.section_id | Select-Object -First 1
        [void]$builder.AppendLine(('## {0}. {1}' -f $section.ordinal, $manifest.Label))
        [void]$builder.AppendLine()
        [void]$builder.AppendLine(('Status: `{0}`; evidence completeness: `{1}`.' -f $section.section_status, $section.evidence_completeness))
        [void]$builder.AppendLine()
        [void]$builder.AppendLine(('Summary: {0}' -f (Protect-HavocMarkdownText $section.summary)))
        [void]$builder.AppendLine()
        [void]$builder.AppendLine(('Collection refs: {0}' -f (($section.collection_refs | ForEach-Object { Protect-HavocMarkdownText $_ }) -join ', ')))
        [void]$builder.AppendLine()

        if ($section.section_id -eq 'coverage_and_limitations') {
            $missing = @($Output.sections | Where-Object { $_.evidence_completeness -eq 'not_assessed' } | ForEach-Object { $_.summary })
            if ($missing.Count -gt 0) {
                [void]$builder.AppendLine('| Limitation |')
                [void]$builder.AppendLine('|---|')
                foreach ($item in $missing) { [void]$builder.AppendLine(('| {0} |' -f (Protect-HavocMarkdownText $item))) }
                [void]$builder.AppendLine()
            }
            Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'telemetryDrift' -Label 'Telemetry drift'
        }

        if ($section.section_id -eq 'evidence_ledger') {
            [void]$builder.AppendLine('| Evidence | Summary |')
            [void]$builder.AppendLine('|---|---|')
            foreach ($record in @(Get-HavocReportArray $Output.evidence_records | Select-Object -First 10)) {
                $id = Get-HavocReportProperty -InputObject $record -Name 'evidence_id'
                if (-not $id) { $id = Get-HavocReportProperty -InputObject $record -Name 'analytic_record_id' }
                [void]$builder.AppendLine(('| {0} | {1} |' -f (Protect-HavocMarkdownText $id), (Get-HavocRecordSummaryText $record)))
            }
            [void]$builder.AppendLine()
        }

        switch ($section.section_id) {
            'executive_assessment' {
                foreach ($summaryRecord in @(Get-HavocReportArray $Output.incident_summary)) {
                    [void]$builder.AppendLine(('Auditor judgment: {0}' -f (Protect-HavocMarkdownText (Get-HavocReportProperty -InputObject $summaryRecord -Name 'auditor_judgment'))))
                    [void]$builder.AppendLine(('Likelihood: {0}' -f (Protect-HavocMarkdownText (Get-HavocReportProperty -InputObject $summaryRecord -Name 'likelihood'))))
                    [void]$builder.AppendLine(('Analytic confidence: {0}' -f (Protect-HavocMarkdownText (Get-HavocReportProperty -InputObject $summaryRecord -Name 'analytic_confidence'))))
                    [void]$builder.AppendLine()
                }
                Add-HavocReportRecordTable -Builder $builder -Records $Output.incident_summary -Fields @('summary_id', 'auditor_judgment', 'likelihood', 'analytic_confidence')
            }
            'incident_comparison' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.incident_summary -Fields @('summary_id', 'original_status', 'original_classification', 'auditor_judgment')
            }
            'coverage_and_limitations' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.coverage_receipts -Fields @('coverage_id', 'source_id', 'coverage_state', 'completeness', 'limitations')
            }
            'query_and_retrieval' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.query_records -Fields @('operation_id', 'source_id', 'target', 'response_classification', 'result_count')
            }
            'entity_resolution' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.entity_records -Fields @('entity_id', 'entity_type', 'aliases', 'lifecycle_summary')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'entityResolutionDecisions' -Label 'Entity-resolution decisions'
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'lifecycleContinuity' -Label 'Lifecycle continuity'
            }
            'timeline' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.timeline_records -Fields @('timeline_id', 'event_ref', 'time_kind', 'time_value', 'uncertainty')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'lifecycleContinuity' -Label 'Lifecycle continuity'
            }
            'competing_hypotheses' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.hypothesis_records -Fields @('hypothesis_id', 'statement', 'likelihood', 'analytic_confidence')
            }
            'causal_analysis' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.causal_records -Fields @('causal_id', 'from_ref', 'to_ref', 'relationship_basis', 'statement')
            }
            'soc_decision_review' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.decision_records -Fields @('decision_id', 'decision_time', 'soc_assessment_label', 'available_evidence_ids', 'later_evidence_ids')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'decisionTimeSocReconstruction' -Label 'Decision-time SOC reconstruction'
            }
            'detection_audit' {
                [void]$builder.AppendLine('Detection Quality: optional detectionQuality input is rendered here when supplied.')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'detectionQuality' -Label 'Detection quality'
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'telemetryDrift' -Label 'Telemetry drift'
            }
            'automation_provenance' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.automation_records -Fields @('automation_id', 'actor', 'version', 'execution_state', 'output_summary', 'human_action')
            }
            'recurrence_review' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.recurrence_records -Fields @('recurrence_id', 'related_record_ref', 'relation_basis', 'relation_limitations')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'lifecycleContinuity' -Label 'Lifecycle continuity'
            }
            'containment_and_recovery' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.recovery_records -Fields @('recovery_id', 'observed_action', 'action_state', 'authority_state')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'lifecycleContinuity' -Label 'Lifecycle continuity'
            }
            'privacy_review' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.privacy_records -Fields @('privacy_id', 'purpose', 'minimization', 'pseudonymization_state', 'protected_store_use', 'export_state')
            }
            'business_and_legal_facts' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.business_fact_records -Fields @('business_fact_id', 'fact', 'determination_boundary')
                Add-HavocReportRecordTable -Builder $builder -Records $Output.legal_fact_records -Fields @('legal_fact_id', 'fact', 'human_route', 'determination_boundary')
            }
            'recommendations' {
                [void]$builder.AppendLine('Actions requiring separate approval:')
                [void]$builder.AppendLine()
                $recommendations = @(Get-HavocReportArray $Output.evidence_records | Where-Object { [string](Get-HavocReportProperty -InputObject $_ -Name 'evidence_class') -eq 'recommendation' })
                if ($recommendations.Count -eq 0) {
                    [void]$builder.AppendLine('- No tenant-changing action is authorized or executed by this report.')
                }
                else {
                    foreach ($record in $recommendations) {
                        [void]$builder.AppendLine(('- {0}' -f (Get-HavocRecordSummaryText $record)))
                    }
                }
            }
            'independent_qa' {
                Add-HavocReportRecordTable -Builder $builder -Records $Output.qa_records -Fields @('qa_id', 'reviewer_verdict', 'adjudication_state', 'limitations')
                Add-HavocReportPlanNote -Builder $builder -Bundle $Bundle -Key 'qaDisagreements' -Label 'QA disagreements'
            }
            'stop_and_errors' {
                Add-HavocReportRecordTable -Builder $builder -Records @($Output.stop_receipt) -Fields @('stop_receipt_id', 'stop_cause', 'coverage_summary', 'unresolved_material_frontier')
                Add-HavocReportRecordTable -Builder $builder -Records $Output.errors -Fields @('error_id', 'error_category', 'safe_message', 'coverage_effect')
            }
        }

        [void]$builder.AppendLine()
    }

    return $builder.ToString()
}

function New-HavocAuditReport {
    [CmdletBinding()]
    param([AllowNull()]$Bundle)

    $output = ConvertTo-HavocReportOutput -Bundle $Bundle
    $json = $output | ConvertTo-Json -Depth 100
    $markdown = New-HavocReportMarkdown -Output $output -Bundle $Bundle

    [pscustomobject][ordered]@{
        Json = $json
        Markdown = $markdown
        AcceptedBundleKeys = @($script:RootKeyMap.Values + $script:RootKeyMap.Keys + $script:PlanKeys | Select-Object -Unique)
        PlanItemsWithoutContractHome = @()
    }
}

function Test-HavocJsonWithPythonSchema {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$SchemaPath
    )

    $python = @'
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

schema_path = Path(sys.argv[1])
refs = schema_path.parent
schema = json.loads(schema_path.read_text(encoding="utf-8"))
vocab = json.loads((refs / "contract-vocabulary.json").read_text(encoding="utf-8"))
instance = json.load(sys.stdin)
registry = Registry().with_resource("contract-vocabulary.json", Resource.from_contents(vocab))
validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path)):
    path = "/" + "/".join(str(part) for part in error.path)
    print(f"{path}: {error.message}")
'@

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'python'
    [void]$startInfo.ArgumentList.Add('-c')
    [void]$startInfo.ArgumentList.Add($python)
    [void]$startInfo.ArgumentList.Add($SchemaPath)
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process.StandardInput.Write($Json)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Python schema validation failed: $stderr"
    }
    return @($stdout -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Test-HavocAuditReportBundle {
    [CmdletBinding()]
    param([AllowNull()]$Bundle)

    $errors = [System.Collections.Generic.List[string]]::new()
    $accepted = @($script:RootKeyMap.Values + $script:RootKeyMap.Keys + $script:PlanKeys | Select-Object -Unique)
    foreach ($key in (Get-HavocReportBundleKeys -Bundle $Bundle)) {
        if ($key -notin $accepted) {
            $errors.Add(('unrecognized Bundle key: {0}' -f $key))
        }
    }

    try {
        $report = New-HavocAuditReport -Bundle $Bundle
        $schemaPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'references\audit-output.schema.json'
        foreach ($schemaError in (Test-HavocJsonWithPythonSchema -Json $report.Json -SchemaPath $schemaPath)) {
            $errors.Add(('schema validation failed: {0}' -f $schemaError))
        }
    }
    catch {
        $errors.Add(('schema validation failed: {0}' -f $_.Exception.Message))
    }

    return @($errors)
}

Export-ModuleMember -Function New-HavocAuditReport, Test-HavocAuditReportBundle
