Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function ConvertTo-BaselineArray {
    param($Value)
    return @(Get-HavocArray -Value $Value)
}

function ConvertTo-BaselineTimestamp {
    param([Parameter(Mandatory)]$Value)
    return ConvertTo-HavocUtcTimestamp -Value $Value
}

function Test-BaselineWindowOverlap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BaselineWindow,
        [Parameter(Mandatory)]$DwellWindow
    )

    $baselineStart = ConvertTo-BaselineTimestamp $BaselineWindow.start_inclusive
    $baselineEnd = ConvertTo-BaselineTimestamp $BaselineWindow.end_exclusive
    $dwellStart = ConvertTo-BaselineTimestamp $DwellWindow.earliest_suspected_compromise
    $dwellEnd = ConvertTo-BaselineTimestamp $DwellWindow.detection_time

    return ($baselineStart -lt $dwellEnd) -and ($baselineEnd -gt $dwellStart)
}

function New-BaselineGapRecords {
    param(
        [Parameter(Mandatory)][string]$BaselineDefinitionId,
        [Parameter(Mandatory)]$Coverage
    )

    $records = @()
    $missingDays = @(ConvertTo-BaselineArray $Coverage.missing_days)
    if ($missingDays.Count -gt 0) {
        $records += [pscustomobject]@{
            gap_id = "G-$BaselineDefinitionId-MISSING-DAYS"
            gap_type = 'missing_days'
            description = 'Baseline window has missing calendar days; absence in those periods is a telemetry gap, not normalcy.'
            affected_days = $missingDays
            behavior_bases = @('configurable_project_policy')
        }
    }

    $telemetryGaps = @(ConvertTo-BaselineArray $Coverage.telemetry_gaps)
    if ($telemetryGaps.Count -gt 0) {
        $records += [pscustomobject]@{
            gap_id = "G-$BaselineDefinitionId-TELEMETRY"
            gap_type = 'telemetry_gap'
            description = 'Baseline source telemetry gaps reduce confidence and cannot be interpreted as normal behavior.'
            affected_telemetry = $telemetryGaps
            behavior_bases = @('configurable_project_policy')
        }
    }

    return @($records)
}

function Get-BaselineConfidenceValue {
    param(
        [Parameter(Mandatory)][bool]$OverlapsDwell,
        [Parameter(Mandatory)][int]$SampleSize,
        [Parameter(Mandatory)][int]$MinimumSampleSize,
        [Parameter(Mandatory)][double]$CoveragePercent,
        [Parameter(Mandatory)][double]$MinimumCoveragePercent,
        [Parameter(Mandatory)][int]$GapCount
    )

    if ($OverlapsDwell) { return 'low' }
    if ($SampleSize -lt $MinimumSampleSize) { return 'low' }
    if ($CoveragePercent -lt $MinimumCoveragePercent) { return 'low' }
    if ($GapCount -gt 0) { return 'moderate' }
    return 'high'
}

function New-BaselineEvidenceProjection {
    param(
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)]$Comparison,
        [Parameter(Mandatory)]$Thresholds,
        [Parameter(Mandatory)]$DwellWindow,
        [Parameter(Mandatory)][string]$Confidence,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$GapIds,
        [Parameter(Mandatory)][string]$Rationale
    )

    $stableInput = [pscustomobject]@{
        baseline_definition = [pscustomobject]@{
            baseline_definition_id = [string]$Definition.baseline_definition_id
            entity_ref = [string]$Definition.entity_ref
            source_id = [string]$Definition.source_id
            metric = [pscustomobject]@{
                name = [string]$Definition.metric.name
                unit = [string]$Definition.metric.unit
                aggregation = [string]$Definition.metric.aggregation
            }
            baseline_window = [pscustomobject]@{
                start_inclusive = [string]$Definition.baseline_window.start_inclusive
                end_exclusive = [string]$Definition.baseline_window.end_exclusive
            }
            sample_size = [int]$Definition.sample_size
            peer_group = [pscustomobject]@{
                peer_group_id = [string]$Definition.peer_group.peer_group_id
                definition = [string]$Definition.peer_group.definition
                membership_basis = [string]$Definition.peer_group.membership_basis
                members = @(ConvertTo-BaselineArray $Definition.peer_group.members | ForEach-Object { [string]$_ })
                exclusions = @(ConvertTo-BaselineArray $Definition.peer_group.exclusions | ForEach-Object { [string]$_ })
            }
            coverage = [pscustomobject]@{
                expected_days = [int]$Definition.coverage.expected_days
                observed_days = [int]$Definition.coverage.observed_days
                coverage_percent = [double]$Definition.coverage.coverage_percent
                missing_days = @(ConvertTo-BaselineArray $Definition.coverage.missing_days | ForEach-Object { [string]$_ })
                telemetry_gaps = @(ConvertTo-BaselineArray $Definition.coverage.telemetry_gaps | ForEach-Object { [string]$_ })
            }
            ledger_item_ids = @(ConvertTo-BaselineArray $Definition.ledger_item_ids | ForEach-Object { [string]$_ })
        }
        peer_comparison = [pscustomobject]@{
            comparison_id = [string]$Comparison.comparison_id
            observed_entity_ref = [string]$Comparison.observed_entity_ref
            observed_value = [double]$Comparison.observed_value
            baseline_value = [double]$Comparison.baseline_value
            rarity_state = [string]$Comparison.rarity_state
            ledger_item_ids = @(ConvertTo-BaselineArray $Comparison.ledger_item_ids | ForEach-Object { [string]$_ })
            evidence_ids = @(ConvertTo-BaselineArray $Comparison.evidence_ids | ForEach-Object { [string]$_ })
            claim_ids = @(ConvertTo-BaselineArray $Comparison.claim_ids | ForEach-Object { [string]$_ })
        }
        thresholds = [pscustomobject]@{
            minimum_sample_size = [int]$Thresholds.minimum_sample_size
            minimum_coverage_percent = [double]$Thresholds.minimum_coverage_percent
        }
        dwell_window = [pscustomobject]@{
            earliest_suspected_compromise = [string]$DwellWindow.earliest_suspected_compromise
            detection_time = [string]$DwellWindow.detection_time
        }
        emitted_assessment = [pscustomobject]@{
            analytic_confidence = $Confidence
            gap_ids = @($GapIds)
            rationale = $Rationale
        }
    }
    $canonicalInput = ConvertTo-HavocCanonicalJson -Value $stableInput
    $evidenceId = Get-HavocStableId -Prefix 'E-BASELINE-CONFIDENCE' -Parts @($canonicalInput)
    $claimId = Get-HavocStableId -Prefix 'C-BASELINE-CONFIDENCE' -Parts @($canonicalInput)

    [pscustomobject]@{
        evidence_id = $evidenceId
        material_claim_id = $claimId
        evidence_class = 'fact'
        source_id = [string]$Definition.source_id
        source_type = 'baseline_kernel'
        provenance = 'Deterministic offline baseline confidence assessment.'
        raw_ref = ('protected-evidence:{0}' -f $evidenceId.ToLowerInvariant())
        normalized_value = [pscustomobject]@{
            baseline_definition_id = [string]$Definition.baseline_definition_id
            baseline_confidence = $Confidence
            rationale = $Rationale
            gap_ids = @($GapIds)
        }
        transformation = 'baseline-confidence-projection'
        transformation_version = '1.0.0'
        source_confidence = $Confidence
        baseline_confidence = $Confidence
        upstream_evidence_ids = @()
        limitations = @('Baseline confidence is project methodology and requires cited ledger evidence for material claims.')
        handling_marking = 'synthetic'
        claim_ids = @($claimId)
        behavior_bases = @('configurable_project_policy')
    }
}

function Invoke-BaselineKernel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$InputObject
    )

    process {
        $definition = $InputObject.baseline_definition
        $comparison = $InputObject.peer_comparison
        $thresholds = $InputObject.thresholds
        $dwell = $InputObject.suspected_dwell_window

        $comparisonLedger = @(ConvertTo-BaselineArray $comparison.ledger_item_ids)
        if ($comparisonLedger.Count -eq 0) {
            throw 'Baseline peer comparison must cite query or evidence ledger items.'
        }

        $definitionLedger = @(ConvertTo-BaselineArray $definition.ledger_item_ids)
        if ($definitionLedger.Count -eq 0) {
            throw 'Baseline definition must cite query or evidence ledger items.'
        }

        $minimumSampleSize = [int]$thresholds.minimum_sample_size
        $minimumCoverage = [double]$thresholds.minimum_coverage_percent
        $sampleSize = [int]$definition.sample_size
        $coveragePercent = [double]$definition.coverage.coverage_percent
        $overlapsDwell = [bool](Test-BaselineWindowOverlap -BaselineWindow $definition.baseline_window -DwellWindow $dwell)
        $gapRecords = @(New-BaselineGapRecords -BaselineDefinitionId ([string]$definition.baseline_definition_id) -Coverage $definition.coverage)
        $gapIds = @($gapRecords | ForEach-Object { [string]$_.gap_id })
        $confidence = Get-BaselineConfidenceValue -OverlapsDwell $overlapsDwell -SampleSize $sampleSize -MinimumSampleSize $minimumSampleSize -CoveragePercent $coveragePercent -MinimumCoveragePercent $minimumCoverage -GapCount $gapRecords.Count
        $sampleState = if ($sampleSize -lt $minimumSampleSize) { 'below_minimum' } else { 'meets_minimum' }
        $coverageState = if ($coveragePercent -lt $minimumCoverage) { 'below_minimum' } else { 'meets_minimum' }

        $poisoningState = if ($overlapsDwell) { 'potentially_poisoned' } else { 'not_poisoned' }
        $capReason = if ($overlapsDwell) { 'Baseline window overlaps possible attacker dwell time; confidence capped by policy.' } else { 'No overlap with supplied possible dwell window.' }
        $gapRationale = if ($gapRecords.Count -gt 0) { ' Coverage gaps reduce confidence and are recorded as gaps rather than benign evidence.' } else { '' }
        $rationale = "$capReason Sample size state: $sampleState. Coverage state: $coverageState.$gapRationale"
        $rarity = [string]$comparison.rarity_state
        $analyticRole = if ($rarity -in @('first_seen', 'rare')) { 'lead' } else { 'context' }

        $baselineDefinitionRecord = [pscustomobject]@{
            baseline_definition_id = [string]$definition.baseline_definition_id
            entity_ref = [string]$definition.entity_ref
            source_id = [string]$definition.source_id
            metric = [pscustomobject]@{
                name = [string]$definition.metric.name
                unit = [string]$definition.metric.unit
                aggregation = [string]$definition.metric.aggregation
            }
            baseline_window = [pscustomobject]@{
                start_inclusive = [string]$definition.baseline_window.start_inclusive
                end_exclusive = [string]$definition.baseline_window.end_exclusive
            }
            sample_size = $sampleSize
            peer_group = [pscustomobject]@{
                peer_group_id = [string]$definition.peer_group.peer_group_id
                definition = [string]$definition.peer_group.definition
                membership_basis = [string]$definition.peer_group.membership_basis
                members = @(ConvertTo-BaselineArray $definition.peer_group.members | ForEach-Object { [string]$_ })
                exclusions = @(ConvertTo-BaselineArray $definition.peer_group.exclusions | ForEach-Object { [string]$_ })
                behavior_bases = @('configurable_project_policy')
            }
            coverage = [pscustomobject]@{
                expected_days = [int]$definition.coverage.expected_days
                observed_days = [int]$definition.coverage.observed_days
                coverage_percent = $coveragePercent
                missing_days = @(ConvertTo-BaselineArray $definition.coverage.missing_days | ForEach-Object { [string]$_ })
                telemetry_gaps = @(ConvertTo-BaselineArray $definition.coverage.telemetry_gaps | ForEach-Object { [string]$_ })
            }
            ledger_item_ids = @($definitionLedger | ForEach-Object { [string]$_ })
            behavior_bases = @('configurable_project_policy')
        }

        $baselineConfidenceRecord = [pscustomobject]@{
            baseline_confidence_id = "BC-$($definition.baseline_definition_id)"
            baseline_definition_id = [string]$definition.baseline_definition_id
            analytic_confidence = $confidence
            capped_by_poisoning = $overlapsDwell
            cap_reason = $capReason
            sample_size_state = $sampleState
            coverage_state = $coverageState
            gap_ids = @($gapIds)
            evidence_ids = @(ConvertTo-BaselineArray $comparison.evidence_ids | ForEach-Object { [string]$_ })
            behavior_bases = @('configurable_project_policy')
            rationale = $rationale
            evidence_record_projection = (New-BaselineEvidenceProjection -Definition $definition -Comparison $comparison -Thresholds $thresholds -DwellWindow $dwell -Confidence $confidence -GapIds $gapIds -Rationale $rationale)
        }

        [pscustomobject]@{
            schema_version = '1.0.0'
            baseline_definition = $baselineDefinitionRecord
            poisoning_assessment = [pscustomobject]@{
                poisoning_assessment_id = "PA-$($definition.baseline_definition_id)"
                baseline_definition_id = [string]$definition.baseline_definition_id
                earliest_suspected_compromise = [string]$dwell.earliest_suspected_compromise
                detection_time = [string]$dwell.detection_time
                overlaps_possible_dwell = $overlapsDwell
                poisoning_state = $poisoningState
                confidence_cap = if ($overlapsDwell) { 'low' } else { 'none' }
                rationale = $capReason
                behavior_bases = @('configurable_project_policy')
            }
            baseline_confidence = $baselineConfidenceRecord
            peer_comparison_result = [pscustomobject]@{
                comparison_id = [string]$comparison.comparison_id
                baseline_definition_id = [string]$definition.baseline_definition_id
                observed_entity_ref = [string]$comparison.observed_entity_ref
                peer_group_id = [string]$definition.peer_group.peer_group_id
                metric = [string]$definition.metric.name
                observed_value = [double]$comparison.observed_value
                baseline_value = [double]$comparison.baseline_value
                comparison_direction = if ([double]$comparison.observed_value -gt [double]$comparison.baseline_value) { 'above_baseline' } elseif ([double]$comparison.observed_value -lt [double]$comparison.baseline_value) { 'below_baseline' } else { 'matches_baseline' }
                rarity_state = $rarity
                analytic_role = $analyticRole
                verdict_boundary = 'First-seen or rare behavior is a lead, never a verdict; corroboration is required.'
                ledger_item_ids = @($comparisonLedger | ForEach-Object { [string]$_ })
                evidence_ids = @(ConvertTo-BaselineArray $comparison.evidence_ids | ForEach-Object { [string]$_ })
                claim_ids = @(ConvertTo-BaselineArray $comparison.claim_ids | ForEach-Object { [string]$_ })
                behavior_bases = @('configurable_project_policy')
            }
            gap_records = @($gapRecords)
        }
    }
}

Export-ModuleMember -Function Invoke-BaselineKernel, Test-BaselineWindowOverlap
