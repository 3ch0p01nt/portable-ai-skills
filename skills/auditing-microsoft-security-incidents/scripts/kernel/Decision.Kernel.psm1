Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function ConvertTo-DecisionInstant {
    param(
        [Parameter(Mandatory)]
        [object]$Value,
        [Parameter(Mandatory)]
        [string]$FieldName
    )

    try {
        return ConvertTo-HavocUtcTimestamp -Value $Value
    }
    catch {
        throw "Invalid RFC3339 timestamp in ${FieldName}: $($_.Exception.Message)"
    }
}

function ConvertTo-DecisionTimestampText {
    param(
        [Parameter(Mandatory)]
        [object]$Value,
        [Parameter(Mandatory)]
        [string]$FieldName
    )
    if ($Value -is [string]) {
        $null = ConvertTo-DecisionInstant -Value $Value -FieldName $FieldName
        return $Value
    }
    return Format-HavocTimestamp -Value (ConvertTo-DecisionInstant -Value $Value -FieldName $FieldName)
}

function Get-ArrayValue {
    param($Value)
    return @(Get-HavocArray -Value $Value)
}

function Get-StringArray {
    param($Value)
    return @(Get-HavocArray -Value $Value | ForEach-Object { [string]$_ })
}

function Add-UniqueString {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Value
    )
    if (-not [string]::IsNullOrWhiteSpace($Value) -and -not $List.Contains($Value)) {
        $List.Add($Value)
    }
}

function Test-AllEvidenceAvailable {
    param(
        [string[]]$EvidenceIds,
        [System.Collections.Generic.HashSet[string]]$AvailableEvidence
    )
    foreach ($id in @($EvidenceIds)) {
        if (-not $AvailableEvidence.Contains([string]$id)) { return $false }
    }
    return $true
}

function Get-InvalidCitationReason {
    param(
        [string[]]$EvidenceIds,
        [System.Collections.Generic.HashSet[string]]$KnownEvidence,
        [System.Collections.Generic.HashSet[string]]$LaterEvidence
    )
    foreach ($id in @($EvidenceIds)) {
        if (-not $KnownEvidence.Contains([string]$id)) {
            return "Unknown evidence citation '$id' is absent from the evidence set."
        }
    }
    foreach ($id in @($EvidenceIds)) {
        if ($LaterEvidence.Contains([string]$id)) {
            return "Evidence citation '$id' is post-decision evidence available after decision_time."
        }
    }
    return ''
}

function Assert-CitationsAvailable {
    param(
        [string]$Context,
        [string[]]$EvidenceIds,
        [System.Collections.Generic.HashSet[string]]$KnownEvidence,
        [System.Collections.Generic.HashSet[string]]$LaterEvidence,
        [bool]$RequireCitation = $false
    )
    if ($RequireCitation -and @($EvidenceIds).Count -eq 0) {
        throw "$Context requires cited evidence."
    }
    $reason = Get-InvalidCitationReason -EvidenceIds @($EvidenceIds) -KnownEvidence $KnownEvidence -LaterEvidence $LaterEvidence
    if (-not [string]::IsNullOrWhiteSpace($reason)) {
        throw "$Context rejects citation: $reason"
    }
}

function Copy-QueueState {
    param($QueueState)
    if ($null -eq $QueueState) {
        throw 'Decision queue_state is required.'
    }
    [pscustomobject][ordered]@{
        queue_depth = [int]$QueueState.queue_depth
        oldest_alert_age_minutes = [int]$QueueState.oldest_alert_age_minutes
        active_analysts = [int]$QueueState.active_analysts
        source_evidence_ids = @(Get-StringArray $QueueState.source_evidence_ids)
    }
}

function Copy-AutomationResult {
    param($Value)
    [pscustomobject][ordered]@{
        automation_id = [string]$Value.automation_id
        version = [string]$Value.version
        availability_time = [string]$Value.availability_time
        evidence_id = [string]$Value.evidence_id
        summary = [string]$Value.summary
    }
}

function Copy-TelemetryItem {
    param($Value)
    [pscustomobject][ordered]@{
        evidence_id = [string]$Value.evidence_id
        source_id = [string]$Value.source_id
        telemetry_type = [string]$Value.telemetry_type
        event_time = [string]$Value.event_time
        availability_time = [string]$Value.availability_time
        availability_kind = [string]$Value.availability_kind
        summary = [string]$Value.summary
    }
}

function Copy-ProcessDefect {
    param(
        $Value,
        [System.Collections.Generic.HashSet[string]]$KnownEvidence,
        [System.Collections.Generic.HashSet[string]]$LaterEvidence
    )
    $ids = @(Get-StringArray $Value.cited_evidence_ids)
    Assert-CitationsAvailable -Context "Process defect '$($Value.defect_id)'" -EvidenceIds $ids -KnownEvidence $KnownEvidence -LaterEvidence $LaterEvidence
    [pscustomobject][ordered]@{
        defect_id = [string]$Value.defect_id
        defect_type = [string]$Value.defect_type
        summary = [string]$Value.summary
        cited_evidence_ids = $ids
    }
}

function Copy-BiasFlag {
    param(
        $Value,
        [System.Collections.Generic.HashSet[string]]$KnownEvidence,
        [System.Collections.Generic.HashSet[string]]$LaterEvidence
    )
    $ids = @(Get-StringArray $Value.cited_evidence_ids)
    Assert-CitationsAvailable -Context "Cognitive bias flag '$($Value.bias_type)'" -EvidenceIds $ids -KnownEvidence $KnownEvidence -LaterEvidence $LaterEvidence -RequireCitation $true
    [pscustomobject][ordered]@{
        bias_type = [string]$Value.bias_type
        summary = [string]$Value.summary
        cited_evidence_ids = $ids
    }
}

function Copy-TimelinessMetric {
    param(
        $Value,
        [System.Collections.Generic.HashSet[string]]$KnownEvidence,
        [System.Collections.Generic.HashSet[string]]$LaterEvidence
    )
    $qualityIds = @(Get-StringArray $Value.quality_indicator_ids)
    if ($qualityIds.Count -eq 0) {
        throw "Timeliness metric '$($Value.metric_id)' must be paired with at least one quality indicator."
    }
    $ids = @(Get-StringArray $Value.cited_evidence_ids)
    Assert-CitationsAvailable -Context "Timeliness metric '$($Value.metric_id)'" -EvidenceIds $ids -KnownEvidence $KnownEvidence -LaterEvidence $LaterEvidence
    [pscustomobject][ordered]@{
        metric_id = [string]$Value.metric_id
        metric_type = [string]$Value.metric_type
        value = $Value.value
        quality_indicator_ids = $qualityIds
        cited_evidence_ids = $ids
    }
}

function ConvertTo-DecisionFiniteDouble {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $parsed = 0.0
    if (-not [double]::TryParse($text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
        return $null
    }
    if ([double]::IsNaN($parsed) -or [double]::IsInfinity($parsed)) {
        return $null
    }
    return $parsed
}

function Get-DesignatedTimelinessMetricType {
    param([string]$DecisionType)
    switch ($DecisionType) {
        'assign' { return 'time_to_assignment_minutes' }
        'severity_change' { return 'time_to_severity_change_minutes' }
        'classify' { return 'time_to_classify_minutes' }
        'escalate' { return 'time_to_escalate_minutes' }
        'contain_request' { return 'time_to_containment_minutes' }
        'close' { return 'time_to_close_minutes' }
        'reopen' { return 'time_to_reopen_minutes' }
        default { return $null }
    }
}

function New-DecisionDimensionScore {
    param(
        [Parameter(Mandatory)]
        [string]$Dimension,
        [Parameter(Mandatory)]
        [double]$Weight,
        [Nullable[int]]$Score,
        [string]$Rationale,
        [string[]]$EvidenceIds,
        [string[]]$ExcludedEvidenceIds = @(),
        [string[]]$MissingInputs
    )

    [pscustomobject][ordered]@{
        dimension = $Dimension
        weight = $Weight
        score = $Score
        rationale = $Rationale
        evidence_ids = @(Get-StringArray $EvidenceIds)
        excluded_evidence_ids = @(Get-StringArray $ExcludedEvidenceIds)
        missing_inputs = @(Get-StringArray $MissingInputs)
    }
}

function Get-DecisionLabelBaseScore {
    param(
        [string]$Label,
        [int]$ReasonableScore,
        [int]$QuestionableScore
    )

    switch ($Label) {
        'reasonable_with_available_evidence' { return $ReasonableScore }
        'questionable_with_available_evidence' { return $QuestionableScore }
        default { return $null }
    }
}

function Get-DecisionHandlingBand {
    param([Nullable[int]]$Score)
    if ($null -eq $Score) { return 'not_assessable' }
    if ($Score -ge 85) { return 'strong' }
    if ($Score -ge 70) { return 'adequate' }
    if ($Score -ge 50) { return 'needs_improvement' }
    return 'poor'
}

function Add-DecisionEvidenceReference {
    param(
        [System.Collections.Generic.List[string]]$EvidenceReferences,
        [System.Collections.Generic.HashSet[string]]$AvailableEvidence,
        [string[]]$EvidenceIds
    )

    foreach ($id in @(Get-StringArray $EvidenceIds)) {
        if ($AvailableEvidence.Contains($id)) {
            Add-UniqueString -List $EvidenceReferences -Value $id
        }
    }
}

function Get-DecisionEvidencePartition {
    param(
        [string[]]$EvidenceIds,
        [System.Collections.Generic.HashSet[string]]$AvailableEvidence
    )

    $included = [System.Collections.Generic.List[string]]::new()
    $excluded = [System.Collections.Generic.List[string]]::new()
    foreach ($id in @(Get-StringArray $EvidenceIds)) {
        if ($AvailableEvidence.Contains($id)) {
            Add-UniqueString -List $included -Value $id
        }
        else {
            Add-UniqueString -List $excluded -Value $id
        }
    }

    [pscustomobject][ordered]@{
        included = @($included)
        excluded = @($excluded)
    }
}

function Test-DecisionRationaleSubstantive {
    param([string]$Rationale)
    $text = if ($null -eq $Rationale) { '' } else { $Rationale.Trim() }
    $policy = Get-DecisionRationalePolicy
    if ($text.Length -lt [int]$policy.minimum_characters) { return $false }
    return @(Get-StringArray $policy.placeholders) -notcontains $text.ToLowerInvariant()
}

function Get-DecisionRationalePolicy {
    [pscustomobject][ordered]@{
        minimum_characters = 20
        placeholders = @('n/a', 'na', 'none', 'unknown', 'not assessed', 'not_assessed', 'tbd', 'todo')
        requires_decision_time_evidence_id = $true
        evidence_id_token_boundary = 'Evidence identifiers must match as whole tokens, not substrings of longer identifiers.'
    }
}

function Test-DecisionRationaleReferencesEvidence {
    param(
        [string]$Rationale,
        [string[]]$EvidenceIds
    )
    foreach ($id in @(Get-StringArray $EvidenceIds)) {
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $pattern = "(?<![A-Za-z0-9._:-])$([regex]::Escape($id))(?![A-Za-z0-9._:-])"
        if ($Rationale -cmatch $pattern) {
            return $true
        }
    }
    return $false
}

function Get-DecisionHandlingDimensionScores {
    param(
        [Parameter(Mandatory)]
        [object]$Snapshot,
        [Parameter(Mandatory)]
        [hashtable]$Weights
    )

    $availableSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in @(Get-StringArray $Snapshot.available_evidence_ids)) {
        [void]$availableSet.Add($id)
    }

    $allEvidenceReferences = [System.Collections.Generic.List[string]]::new()
    $assessment = $Snapshot.reasonable_analyst_assessment
    $assessmentCitations = @(Get-StringArray $assessment.cited_evidence_ids)
    $isOutcomeOnlyHindsight = [string]$assessment.label -eq 'outcome_only_hindsight'
    Add-DecisionEvidenceReference -EvidenceReferences $allEvidenceReferences -AvailableEvidence $availableSet -EvidenceIds $assessmentCitations

    $dimensions = [System.Collections.Generic.List[object]]::new()

    $timelinessMetrics = @(Get-ArrayValue $Snapshot.timeliness_quality_pairings)
    $designatedMetricType = Get-DesignatedTimelinessMetricType -DecisionType ([string]$Snapshot.decision_type)
    if ($timelinessMetrics.Count -eq 0) {
        $dimensions.Add((New-DecisionDimensionScore -Dimension 'timeliness' -Weight $Weights.timeliness -Score $null -Rationale 'Timeliness cannot be scored because no decision-time timeliness metric was provided.' -EvidenceIds @() -MissingInputs @('timeliness_metrics')))
    }
    elseif ([string]::IsNullOrWhiteSpace($designatedMetricType)) {
        $dimensions.Add((New-DecisionDimensionScore -Dimension 'timeliness' -Weight $Weights.timeliness -Score $null -Rationale 'Timeliness cannot be scored because the decision type has no designated minute-based timeliness metric.' -EvidenceIds @() -MissingInputs @('timeliness_metrics.metric_type')))
    }
    else {
        $designatedMetrics = @($timelinessMetrics | Where-Object { [string]$_.metric_type -eq $designatedMetricType })
        if ($designatedMetrics.Count -eq 0) {
            $dimensions.Add((New-DecisionDimensionScore -Dimension 'timeliness' -Weight $Weights.timeliness -Score $null -Rationale "Timeliness cannot be scored because no '$designatedMetricType' metric was provided for this decision type." -EvidenceIds @() -MissingInputs @('timeliness_metrics.metric_type')))
        }
        else {
            $numericValues = @($designatedMetrics | ForEach-Object { ConvertTo-DecisionFiniteDouble $_.value } | Where-Object { $null -ne $_ })
            $ids = @($designatedMetrics | ForEach-Object { Get-StringArray $_.cited_evidence_ids })
            $timelinessEvidence = Get-DecisionEvidencePartition -EvidenceIds $ids -AvailableEvidence $availableSet
            Add-DecisionEvidenceReference -EvidenceReferences $allEvidenceReferences -AvailableEvidence $availableSet -EvidenceIds $timelinessEvidence.included
            if ($numericValues.Count -eq 0) {
                $dimensions.Add((New-DecisionDimensionScore -Dimension 'timeliness' -Weight $Weights.timeliness -Score $null -Rationale "Timeliness cannot be scored because '$designatedMetricType' has no numeric finite minute value." -EvidenceIds $timelinessEvidence.included -ExcludedEvidenceIds $timelinessEvidence.excluded -MissingInputs @('timeliness_metrics.value')))
            }
            else {
                $bestMetric = ($numericValues | Measure-Object -Minimum).Minimum
                $timelinessScore = if ($bestMetric -le 60) { 100 } elseif ($bestMetric -le 240) { 70 } else { 40 }
                $dimensions.Add((New-DecisionDimensionScore -Dimension 'timeliness' -Weight $Weights.timeliness -Score $timelinessScore -Rationale "Timeliness is scored from the designated '$designatedMetricType' minute metric paired with quality indicators that cite decision-time evidence." -EvidenceIds $timelinessEvidence.included -ExcludedEvidenceIds $timelinessEvidence.excluded -MissingInputs @()))
            }
        }
    }

    $evidenceMissing = [System.Collections.Generic.List[string]]::new()
    $evidenceScore = Get-DecisionLabelBaseScore -Label ([string]$assessment.label) -ReasonableScore 100 -QuestionableScore 50
    if ($isOutcomeOnlyHindsight) {
        Add-UniqueString -List $evidenceMissing -Value 'invalid_outcome_only_hindsight_critique'
    }
    if ($null -eq $evidenceScore) {
        Add-UniqueString -List $evidenceMissing -Value 'reasonable_analyst_assessment'
    }
    if ($assessmentCitations.Count -eq 0) {
        Add-UniqueString -List $evidenceMissing -Value 'assessment.cited_evidence_ids'
        $evidenceScore = $null
    }
    $validFindings = @(Get-ArrayValue $Snapshot.finding_assessments | Where-Object { [bool]$_.valid_for_decision_time_assessment })
    if ($validFindings.Count -eq 0) {
        Add-UniqueString -List $evidenceMissing -Value 'valid_decision_time_findings'
        if ($null -ne $evidenceScore) {
            $evidenceScore = [Math]::Min([int]$evidenceScore, 40)
        }
    }
    $findingIds = @($validFindings | ForEach-Object { Get-StringArray $_.cited_evidence_ids })
    $evidenceSufficiencyIds = @($assessmentCitations + $findingIds)
    $evidenceSufficiencyEvidence = Get-DecisionEvidencePartition -EvidenceIds $evidenceSufficiencyIds -AvailableEvidence $availableSet
    if ($evidenceSufficiencyEvidence.included.Count -eq 0) {
        Add-UniqueString -List $evidenceMissing -Value 'decision_time_evidence'
        if ($null -ne $evidenceScore) {
            $evidenceScore = [Math]::Min([int]$evidenceScore, 40)
        }
    }
    elseif ($evidenceSufficiencyEvidence.included.Count -lt 2 -and $null -ne $evidenceScore) {
        Add-UniqueString -List $evidenceMissing -Value 'decision_time_evidence_count'
        $evidenceScore = [Math]::Min([int]$evidenceScore, 60)
    }
    Add-DecisionEvidenceReference -EvidenceReferences $allEvidenceReferences -AvailableEvidence $availableSet -EvidenceIds $evidenceSufficiencyEvidence.included
    $dimensions.Add((New-DecisionDimensionScore -Dimension 'evidence_sufficiency' -Weight $Weights.evidence_sufficiency -Score $evidenceScore -Rationale 'Evidence sufficiency is judged from the assessment label, cited evidence, and valid decision-time findings without using later evidence.' -EvidenceIds $evidenceSufficiencyEvidence.included -ExcludedEvidenceIds $evidenceSufficiencyEvidence.excluded -MissingInputs @($evidenceMissing)))

    $decisionType = [string]$Snapshot.decision_type
    $escalationMissing = [System.Collections.Generic.List[string]]::new()
    $escalationScore = $null
    if ([string]::IsNullOrWhiteSpace($decisionType)) {
        Add-UniqueString -List $escalationMissing -Value 'decision_type'
    }
    elseif ($isOutcomeOnlyHindsight) {
        Add-UniqueString -List $escalationMissing -Value 'invalid_outcome_only_hindsight_critique'
    }
    elseif ($decisionType -eq 'escalate') {
        $escalationScore = Get-DecisionLabelBaseScore -Label ([string]$assessment.label) -ReasonableScore 100 -QuestionableScore 60
    }
    else {
        $systemicDefects = @(Get-ArrayValue $Snapshot.process_defects | Where-Object { @('handoff', 'queue', 'staffing', 'workload') -contains [string]$_.defect_type })
        if ($systemicDefects.Count -gt 0 -and @('close', 'classify') -contains $decisionType) {
            $escalationScore = Get-DecisionLabelBaseScore -Label ([string]$assessment.label) -ReasonableScore 70 -QuestionableScore 40
        }
        else {
            $escalationScore = Get-DecisionLabelBaseScore -Label ([string]$assessment.label) -ReasonableScore 85 -QuestionableScore 45
        }
    }
    if ($null -eq $escalationScore) {
        Add-UniqueString -List $escalationMissing -Value 'escalation_rationale'
    }
    $defectIds = @(Get-ArrayValue $Snapshot.process_defects | ForEach-Object { Get-StringArray $_.cited_evidence_ids })
    $escalationEvidence = Get-DecisionEvidencePartition -EvidenceIds @($assessmentCitations + $defectIds) -AvailableEvidence $availableSet
    Add-DecisionEvidenceReference -EvidenceReferences $allEvidenceReferences -AvailableEvidence $availableSet -EvidenceIds $escalationEvidence.included
    $dimensions.Add((New-DecisionDimensionScore -Dimension 'escalation_appropriateness' -Weight $Weights.escalation_appropriateness -Score $escalationScore -Rationale 'Escalation appropriateness is scored from the action taken, decision-time assessment, and queue/handoff/workload defects.' -EvidenceIds $escalationEvidence.included -ExcludedEvidenceIds $escalationEvidence.excluded -MissingInputs @($escalationMissing)))

    $containmentMissing = [System.Collections.Generic.List[string]]::new()
    $containmentScore = Get-DecisionLabelBaseScore -Label ([string]$assessment.label) -ReasonableScore 90 -QuestionableScore 50
    if ($isOutcomeOnlyHindsight) {
        Add-UniqueString -List $containmentMissing -Value 'invalid_outcome_only_hindsight_critique'
    }
    if (@(Get-StringArray $Snapshot.available_evidence_ids).Count -eq 0) {
        Add-UniqueString -List $containmentMissing -Value 'available_evidence_ids'
        $containmentScore = $null
    }
    if ([string]::IsNullOrWhiteSpace($decisionType)) {
        Add-UniqueString -List $containmentMissing -Value 'decision_type'
        $containmentScore = $null
    }
    $containmentEvidence = Get-DecisionEvidencePartition -EvidenceIds $assessmentCitations -AvailableEvidence $availableSet
    $dimensions.Add((New-DecisionDimensionScore -Dimension 'containment_appropriateness' -Weight $Weights.containment_appropriateness -Score $containmentScore -Rationale 'Containment appropriateness is scored from the decision-time label and action context, not from post-decision outcome.' -EvidenceIds $containmentEvidence.included -ExcludedEvidenceIds $containmentEvidence.excluded -MissingInputs @($containmentMissing)))

    $documentationMissing = [System.Collections.Generic.List[string]]::new()
    $rationale = [string]$assessment.rationale
    $documentationScore = $null
    $documentationEvidence = Get-DecisionEvidencePartition -EvidenceIds $assessmentCitations -AvailableEvidence $availableSet
    if (@('not_assessable', 'outcome_only_hindsight') -contains [string]$assessment.label) {
        Add-UniqueString -List $documentationMissing -Value 'reasonable_analyst_assessment'
    }
    elseif (-not (Test-DecisionRationaleSubstantive -Rationale $rationale)) {
        Add-UniqueString -List $documentationMissing -Value 'assessment.rationale.substantive'
        $documentationScore = 20
    }
    elseif ($assessmentCitations.Count -eq 0) {
        Add-UniqueString -List $documentationMissing -Value 'assessment.cited_evidence_ids'
        $documentationScore = 40
    }
    elseif (-not (Test-DecisionRationaleReferencesEvidence -Rationale $rationale -EvidenceIds $documentationEvidence.included)) {
        Add-UniqueString -List $documentationMissing -Value 'assessment.rationale.evidence_reference'
        $documentationScore = 60
    }
    elseif ([bool]$Snapshot.notes_comments_present) {
        $documentationScore = 100
    }
    else {
        $documentationScore = 80
    }
    $dimensions.Add((New-DecisionDimensionScore -Dimension 'documentation_rationale' -Weight $Weights.documentation_rationale -Score $documentationScore -Rationale 'Documentation is scored from substantive rationale text, decision-time evidence references, citations, and decision-time notes or comments.' -EvidenceIds $documentationEvidence.included -ExcludedEvidenceIds $documentationEvidence.excluded -MissingInputs @($documentationMissing)))

    [pscustomobject][ordered]@{
        dimension_scores = @($dimensions)
        evidence_references = @($allEvidenceReferences)
    }
}

function New-DecisionHandlingAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$DecisionSnapshots
    )

    begin {
        $inputSnapshots = [System.Collections.Generic.List[object]]::new()
    }
    process {
        foreach ($snapshot in @($DecisionSnapshots)) {
            if ($null -ne $snapshot) {
                $inputSnapshots.Add($snapshot)
            }
        }
    }
    end {
        $weights = [ordered]@{
            timeliness = 0.20
            evidence_sufficiency = 0.30
            escalation_appropriateness = 0.15
            containment_appropriateness = 0.20
            documentation_rationale = 0.15
        }
        $snapshotConfidenceThreshold = 0.60
        $minimumAssessableSnapshots = 2
        $orderedSnapshots = @($inputSnapshots | Sort-Object @{ Expression = { ConvertTo-DecisionInstant -Value $_.decision_time -FieldName 'decision_time' } }, @{ Expression = { [string]$_.decision_id } })
        $missingInputs = [System.Collections.Generic.List[string]]::new()
        if ($orderedSnapshots.Count -lt 2) {
            Add-UniqueString -List $missingInputs -Value 'minimum of 2 decision snapshots required'
        }

        $breakdown = [System.Collections.Generic.List[object]]::new()
        $evidenceReferences = [System.Collections.Generic.List[string]]::new()
        foreach ($snapshot in $orderedSnapshots) {
            $dimensionResult = Get-DecisionHandlingDimensionScores -Snapshot $snapshot -Weights $weights
            $weightedScore = 0.0
            $knownWeight = 0.0
            $snapshotMissing = [System.Collections.Generic.List[string]]::new()
            $invalidCritiques = [System.Collections.Generic.List[string]]::new()
            if ([string]$snapshot.reasonable_analyst_assessment.label -eq 'outcome_only_hindsight') {
                Add-UniqueString -List $invalidCritiques -Value 'outcome_only_hindsight'
            }
            foreach ($dimension in @($dimensionResult.dimension_scores)) {
                foreach ($missing in @(Get-StringArray $dimension.missing_inputs)) {
                    Add-UniqueString -List $snapshotMissing -Value $missing
                    Add-UniqueString -List $missingInputs -Value "$($snapshot.decision_id):$missing"
                }
                if ($null -ne $dimension.score) {
                    $knownWeight += [double]$dimension.weight
                    $weightedScore += ([double]$dimension.score * [double]$dimension.weight)
                }
            }
            foreach ($evidenceId in @(Get-StringArray $dimensionResult.evidence_references)) {
                Add-UniqueString -List $evidenceReferences -Value $evidenceId
            }
            $snapshotScore = $null
            if ($knownWeight -ge $snapshotConfidenceThreshold) {
                $snapshotScore = [int][Math]::Round(($weightedScore / $knownWeight), 0)
            }
            else {
                Add-UniqueString -List $snapshotMissing -Value 'insufficient scored decision dimensions'
                Add-UniqueString -List $missingInputs -Value "$($snapshot.decision_id):insufficient scored decision dimensions"
            }
            $breakdown.Add([pscustomobject][ordered]@{
                decision_id = [string]$snapshot.decision_id
                decision_time = [string]$snapshot.decision_time
                decision_type = [string]$snapshot.decision_type
                snapshot_score = $snapshotScore
                snapshot_band = Get-DecisionHandlingBand -Score $snapshotScore
                confidence = [Math]::Round($knownWeight, 2)
                dimension_scores = @($dimensionResult.dimension_scores)
                missing_inputs = @($snapshotMissing)
                invalid_critiques = @($invalidCritiques)
            })
        }

        $assessableBreakdown = @($breakdown | Where-Object { $null -ne $_.snapshot_score })
        $overallConfidence = if ($assessableBreakdown.Count -eq 0) { 0.0 } else { [Math]::Round(((@($assessableBreakdown) | Measure-Object -Property confidence -Average).Average), 2) }
        if ($overallConfidence -lt $snapshotConfidenceThreshold) {
            Add-UniqueString -List $missingInputs -Value 'insufficient scored decision dimensions'
        }
        if ($assessableBreakdown.Count -lt $minimumAssessableSnapshots) {
            Add-UniqueString -List $missingInputs -Value 'minimum of 2 assessable decision snapshots required'
        }

        $isAssessable = $assessableBreakdown.Count -ge $minimumAssessableSnapshots -and $overallConfidence -ge $snapshotConfidenceThreshold
        $overallScore = $null
        if ($isAssessable) {
            $overallScore = [int][Math]::Round(((@($assessableBreakdown) | Measure-Object -Property snapshot_score -Average).Average), 0)
        }
        $band = Get-DecisionHandlingBand -Score $overallScore

        [pscustomobject][ordered]@{
            assessment_status = if ($isAssessable) { 'assessable' } else { 'not_assessable' }
            overall_score = $overallScore
            overall_band = $band
            confidence = $overallConfidence
            dimension_weights = [pscustomobject][ordered]@{
                timeliness = $weights.timeliness
                evidence_sufficiency = $weights.evidence_sufficiency
                escalation_appropriateness = $weights.escalation_appropriateness
                containment_appropriateness = $weights.containment_appropriateness
                documentation_rationale = $weights.documentation_rationale
            }
            rationale_policy = Get-DecisionRationalePolicy
            methodology_basis = 'SOC handling score uses decision-time evidence, avoids hindsight bias, and separates decision quality from outcome.'
            snapshot_breakdown = @($breakdown)
            evidence_references = @($evidenceReferences)
            missing_inputs = @($missingInputs)
        }
    }
}

function New-DecisionSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Decision
    )

    process {
        $decisionTimeText = ConvertTo-DecisionTimestampText $Decision.decision_time 'decision_time'
        $decisionTime = ConvertTo-DecisionInstant $Decision.decision_time 'decision_time'
        $availableIds = [System.Collections.Generic.List[string]]::new()
        $laterIds = [System.Collections.Generic.List[string]]::new()
        $telemetryAvailable = [System.Collections.Generic.List[object]]::new()
        $laterEvidence = [System.Collections.Generic.List[object]]::new()
        $automationAvailable = [System.Collections.Generic.List[object]]::new()

        $queueState = Copy-QueueState $Decision.queue_state
        foreach ($queueEvidenceId in @($queueState.source_evidence_ids)) {
            Add-UniqueString $availableIds ([string]$queueEvidenceId)
        }

        foreach ($item in Get-ArrayValue $Decision.telemetry) {
            $availability = ConvertTo-DecisionInstant $item.availability_time 'telemetry.availability_time'
            $evidenceId = [string]$item.evidence_id
            if ($availability -le $decisionTime) {
                $telemetryAvailable.Add((Copy-TelemetryItem $item))
                Add-UniqueString $availableIds $evidenceId
            }
            else {
                Add-UniqueString $laterIds $evidenceId
                $laterEvidence.Add([pscustomobject][ordered]@{
                    evidence_id = $evidenceId
                    availability_time = [string]$item.availability_time
                    exclusion_reason = 'Excluded from decision snapshot because availability time is after decision_time.'
                })
            }
        }

        foreach ($item in Get-ArrayValue $Decision.automation_results) {
            $availability = ConvertTo-DecisionInstant $item.availability_time 'automation_results.availability_time'
            $evidenceId = [string]$item.evidence_id
            if ($availability -le $decisionTime) {
                $automationAvailable.Add((Copy-AutomationResult $item))
                Add-UniqueString $availableIds $evidenceId
            }
            else {
                Add-UniqueString $laterIds $evidenceId
                $laterEvidence.Add([pscustomobject][ordered]@{
                    evidence_id = $evidenceId
                    availability_time = [string]$item.availability_time
                    exclusion_reason = 'Excluded automation evidence because availability time is after decision_time.'
                })
            }
        }

        foreach ($item in Get-ArrayValue $Decision.notes_comments) {
            $availability = ConvertTo-DecisionInstant $item.availability_time 'notes_comments.availability_time'
            $evidenceId = [string]$item.evidence_id
            if ($availability -le $decisionTime) {
                Add-UniqueString $availableIds $evidenceId
            }
            else {
                Add-UniqueString $laterIds $evidenceId
                $laterEvidence.Add([pscustomobject][ordered]@{
                    evidence_id = $evidenceId
                    availability_time = [string]$item.availability_time
                    exclusion_reason = 'Excluded note/comment because availability time is after decision_time.'
                })
            }
        }

        $availableSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in @($availableIds)) { [void]$availableSet.Add($id) }
        $laterSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in @($laterIds)) { [void]$laterSet.Add($id) }
        $knownSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in @($availableIds)) { [void]$knownSet.Add($id) }
        foreach ($id in @($laterIds)) { [void]$knownSet.Add($id) }

        foreach ($flag in Get-ArrayValue $Decision.cognitive_bias_flags) {
            $null = Copy-BiasFlag -Value $flag -KnownEvidence $knownSet -LaterEvidence $laterSet
        }
        foreach ($metric in Get-ArrayValue $Decision.timeliness_metrics) {
            $null = Copy-TimelinessMetric -Value $metric -KnownEvidence $knownSet -LaterEvidence $laterSet
        }
        foreach ($defect in Get-ArrayValue $Decision.process_defects) {
            $null = Copy-ProcessDefect -Value $defect -KnownEvidence $knownSet -LaterEvidence $laterSet
        }

        $fault = $Decision.individual_fault
        $faultAsserted = if ($null -eq $fault) { $false } else { [bool]$fault.asserted }
        $faultAvailableIds = if ($null -eq $fault) { @() } else { @(Get-StringArray $fault.available_information_evidence_ids) }
        $faultRequiredActionIds = if ($null -eq $fault) { @() } else { @(Get-StringArray $fault.required_action_documented_evidence_ids) }
        $faultSupported = $false
        $faultRationale = if ($null -ne $fault -and -not [string]::IsNullOrWhiteSpace([string]$fault.rationale)) {
            [string]$fault.rationale
        }
        else {
            'Individual fault was not asserted or lacked supporting decision-time evidence.'
        }
        if ($faultAsserted) {
            $hasAvailableInformation = @($faultAvailableIds).Count -gt 0 -and (Test-AllEvidenceAvailable -EvidenceIds @($faultAvailableIds) -AvailableEvidence $availableSet)
            $hasDocumentedRequiredAction = @($faultRequiredActionIds).Count -gt 0 -and (Test-AllEvidenceAvailable -EvidenceIds @($faultRequiredActionIds) -AvailableEvidence $availableSet)
            $faultSupported = $hasAvailableInformation -and $hasDocumentedRequiredAction
            if (-not $faultSupported) {
                $faultRationale = 'Individual fault is not supported because the material information was not available at decision time or the required action was not documented at decision time.'
            }
        }

        $findingAssessments = [System.Collections.Generic.List[object]]::new()
        foreach ($finding in Get-ArrayValue $Decision.findings) {
            $ids = @(Get-StringArray $finding.cited_evidence_ids)
            $reason = Get-InvalidCitationReason -EvidenceIds $ids -KnownEvidence $knownSet -LaterEvidence $laterSet
            $valid = [string]::IsNullOrWhiteSpace($reason)
            if ($ids.Count -eq 0) {
                $valid = $false
                $reason = 'Invalid decision finding: no cited evidence.'
            }
            $findingAssessments.Add([pscustomobject][ordered]@{
                finding_id = [string]$finding.finding_id
                summary = [string]$finding.summary
                cited_evidence_ids = $ids
                valid_for_decision_time_assessment = $valid
                invalid_reason = $reason
            })
        }

        $assessment = $Decision.assessment
        Assert-CitationsAvailable `
            -Context 'Reasonable analyst assessment' `
            -EvidenceIds @(Get-StringArray $assessment.cited_evidence_ids) `
            -KnownEvidence $knownSet `
            -LaterEvidence $laterSet `
            -RequireCitation $true
        $assessmentLabel = [string]$assessment.soc_assessment_label

        [pscustomobject][ordered]@{
            decision_id = [string]$Decision.decision_id
            decision_time = $decisionTimeText
            decision_type = [string]$Decision.decision_type
            actor_type = [string]$Decision.actor_type
            soc_assessment_label = $assessmentLabel
            alert_payload_version_available = [string]$Decision.alert_payload_version_available
            queue_state = $queueState
            automation_results_available = @($automationAvailable)
            notes_comments_present = @(Get-ArrayValue $Decision.notes_comments).Count -gt 0
            playbook_version = [string]$Decision.playbook_version
            telemetry_available = @($telemetryAvailable)
            later_evidence_excluded = @($laterEvidence)
            available_evidence_ids = @($availableIds)
            later_evidence_ids = @($laterIds)
            reasonable_analyst_assessment = [pscustomobject][ordered]@{
                label = $assessmentLabel
                rationale = [string]$assessment.reasonable_analyst_rationale
                cited_evidence_ids = @(Get-StringArray $assessment.cited_evidence_ids)
            }
            process_defects = @(Get-ArrayValue $Decision.process_defects | ForEach-Object { Copy-ProcessDefect -Value $_ -KnownEvidence $knownSet -LaterEvidence $laterSet })
            individual_fault = [pscustomobject][ordered]@{
                fault_asserted = $faultAsserted
                fault_supported = $faultSupported
                available_information_evidence_ids = @($faultAvailableIds)
                required_action_documented_evidence_ids = @($faultRequiredActionIds)
                rationale = $faultRationale
            }
            timeliness_quality_pairings = @(Get-ArrayValue $Decision.timeliness_metrics | ForEach-Object { Copy-TimelinessMetric -Value $_ -KnownEvidence $knownSet -LaterEvidence $laterSet })
            cognitive_bias_flags = @(Get-ArrayValue $Decision.cognitive_bias_flags | ForEach-Object { Copy-BiasFlag -Value $_ -KnownEvidence $knownSet -LaterEvidence $laterSet })
            finding_assessments = @($findingAssessments)
            claim_ids = @(Get-StringArray $Decision.claim_ids)
            gap_ids = @(Get-StringArray $Decision.gap_ids)
            error_ids = @(Get-StringArray $Decision.error_ids)
            behavior_bases = @(Get-StringArray $Decision.behavior_bases)
        }
    }
}

Export-ModuleMember -Function New-DecisionSnapshot, New-DecisionHandlingAssessment
