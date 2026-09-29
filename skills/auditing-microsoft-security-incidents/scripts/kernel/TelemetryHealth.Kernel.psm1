Set-StrictMode -Version 3.0

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function ConvertTo-HavocUtcDateTime {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Value)

    return (ConvertTo-HavocUtcTimestamp -Value $Value).UtcDateTime
}

function Test-HavocWindowOverlap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Left,
        [Parameter(Mandatory)][object]$Right
    )

    $leftStart = ConvertTo-HavocUtcDateTime $Left.start_inclusive
    $leftEnd = ConvertTo-HavocUtcDateTime $Left.end_exclusive
    $rightStart = ConvertTo-HavocUtcDateTime $Right.start_inclusive
    $rightEnd = ConvertTo-HavocUtcDateTime $Right.end_exclusive
    return ($leftStart -lt $rightEnd -and $leftEnd -gt $rightStart)
}

function Get-HavocWindowIntersection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Left,
        [Parameter(Mandatory)][object]$Right
    )

    $leftStart = ConvertTo-HavocUtcTimestamp -Value $Left.start_inclusive
    $leftEnd = ConvertTo-HavocUtcTimestamp -Value $Left.end_exclusive
    $rightStart = ConvertTo-HavocUtcTimestamp -Value $Right.start_inclusive
    $rightEnd = ConvertTo-HavocUtcTimestamp -Value $Right.end_exclusive

    $start = if ($leftStart -ge $rightStart) { $leftStart } else { $rightStart }
    $end = if ($leftEnd -le $rightEnd) { $leftEnd } else { $rightEnd }
    if ($start -ge $end) { return $null }

    return [pscustomobject][ordered]@{
        start_inclusive = Format-HavocTimestamp -Value $start
        end_exclusive = Format-HavocTimestamp -Value $end
    }
}

function Select-HavocOrdinalUnique {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Values)

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($value in @(Get-HavocArray -Value $Values)) {
        $text = [string]$value
        if ($seen.Add($text)) {
            $text
        }
    }
}

function Get-HavocPropertyArray {
    param([object]$Object, [string]$Name)
    return @(Get-HavocArray -Value (Get-HavocProperty -InputObject $Object -Name $Name))
}

function Get-HavocTelemetryAffectedClaimScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$IncidentWindow,
        [Parameter(Mandatory)][object[]]$SourceHealthRecords,
        [Parameter(Mandatory)][object[]]$ClaimRecords
    )

    foreach ($health in $SourceHealthRecords) {
        foreach ($claim in $ClaimRecords) {
            if ([string]$claim.finding_type -cne 'negative') { continue }
            if ([string]$claim.source_id -cne [string]$health.source_id) { continue }
            if ([string]$claim.table_name -cne [string]$health.table_name) { continue }

            $gapIds = [System.Collections.Generic.List[string]]::new()
            foreach ($gap in (Get-HavocPropertyArray $health 'heartbeat_gaps')) {
                if (Test-HavocWindowOverlap $claim.window $gap) {
                    $gapIds.Add([string]$gap.gap_id)
                }
            }
            foreach ($anomaly in (Get-HavocPropertyArray $health 'volume_anomalies')) {
                if (Test-HavocWindowOverlap $claim.window $anomaly) {
                    $gapIds.Add([string]$anomaly.gap_id)
                }
            }
            if ($gapIds.Count -eq 0) { continue }

            [pscustomobject][ordered]@{
                claim_id = [string]$claim.claim_id
                claim_scope = [string]$claim.claim_scope
                source_id = [string]$claim.source_id
                table_name = [string]$claim.table_name
                health_record_id = [string]$health.health_record_id
                gap_ids = @(Select-HavocOrdinalUnique -Values $gapIds)
                absence_language = 'not_found_within_unverified_coverage'
                affected_start = [string]$claim.window.start_inclusive
                affected_end = [string]$claim.window.end_exclusive
            }
        }
    }
}

function Get-HavocDetectionInputDrift {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$DetectionInputRecords,
        [Parameter(Mandatory)][object[]]$DriftRecords
    )

    foreach ($inputRecord in $DetectionInputRecords) {
        $matched = @()
        foreach ($drift in $DriftRecords) {
            if ([string]$drift.source_id -cne [string]$inputRecord.source_id) { continue }
            if ([string]$drift.table_name -cne [string]$inputRecord.table_name) { continue }

            $driftType = [string]$drift.drift_type
            $requiredFields = @($inputRecord.required_fields | ForEach-Object { [string]$_ })
            $changedFields = @($drift.changed_fields | ForEach-Object { [string]$_ })
            $intersect = @($changedFields | Where-Object { $requiredFields -ccontains $_ })

            if ($driftType -ceq 'parser_version_changed' -or $intersect.Count -gt 0) {
                $matched += [pscustomobject][ordered]@{
                    drift_record_id = [string]$drift.drift_record_id
                    drift_type = $driftType
                    changed_fields = @($changedFields)
                    affected_fields = @($intersect)
                }
            }
        }
        if ($matched.Count -eq 0) { continue }

        $affectedFields = @(Select-HavocOrdinalUnique -Values @($matched | ForEach-Object { $_.affected_fields + $_.changed_fields } | ForEach-Object { $_ }))
        [pscustomobject][ordered]@{
            detection_input_id = [string]$inputRecord.detection_input_id
            analytics_rule_id = [string]$inputRecord.analytics_rule_id
            source_id = [string]$inputRecord.source_id
            table_name = [string]$inputRecord.table_name
            drift_record_ids = @(Select-HavocOrdinalUnique -Values $matched.drift_record_id)
            drift_types = @(Select-HavocOrdinalUnique -Values $matched.drift_type)
            affected_fields = @($affectedFields)
            detection_health_state = 'requires_review'
        }
    }
}

function Get-HavocDcrAbsenceBoundary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$IncidentWindow,
        [Parameter(Mandatory)][object[]]$DcrLineageRecords,
        [Parameter(Mandatory)][object[]]$ClaimRecords
    )

    foreach ($lineage in $DcrLineageRecords) {
        if (-not [bool]$lineage.filters_records) { continue }
        if ([string]$lineage.transformation_stage -notin @('ingestion_time', 'multi_stage')) { continue }

        foreach ($claim in $ClaimRecords) {
            if ([string]$claim.finding_type -cne 'negative') { continue }
            if ([string]$claim.source_id -cne [string]$lineage.source_id) { continue }
            if ([string]$claim.table_name -cne [string]$lineage.table_name) { continue }
            $intersection = Get-HavocWindowIntersection -Left $claim.window -Right $lineage
            if ($null -eq $intersection) { continue }

            [pscustomobject][ordered]@{
                claim_id = [string]$claim.claim_id
                source_id = [string]$claim.source_id
                table_name = [string]$claim.table_name
                dcr_id = [string]$lineage.dcr_id
                lineage_id = [string]$lineage.lineage_id
                evidence_boundary = 'not_observed_is_not_absence'
                dropped_or_filtered_fields = @(Select-HavocOrdinalUnique -Values @($lineage.dropped_fields + $lineage.filtered_fields))
                affected_start = $intersection.start_inclusive
                affected_end = $intersection.end_exclusive
            }
        }
    }
}

function ConvertTo-HavocVolumeDropGap {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$VolumeMeasurements)

    foreach ($measurement in $VolumeMeasurements) {
        $rawBaseline = Get-HavocProperty -InputObject $measurement -Name 'baseline_count'
        $observed = [double]$measurement.observed_count
        $threshold = [double]$measurement.threshold_percent
        if ($null -eq $rawBaseline -or [double]$rawBaseline -le 0) {
            [pscustomobject][ordered]@{
                gap_id = [string]$measurement.gap_id
                gap_type = 'unknown_baseline'
                source_id = [string]$measurement.source_id
                table_name = [string]$measurement.table_name
                start_inclusive = [string]$measurement.start_inclusive
                end_exclusive = [string]$measurement.end_exclusive
                baseline_count = $rawBaseline
                observed_count = $observed
                drop_percent = $null
                threshold_percent = $threshold
                coverage_state = 'unknown'
            }
            continue
        }

        $baseline = [double]$rawBaseline

        $dropPercent = [math]::Round((($baseline - $observed) / $baseline) * 100, 2)
        if ($dropPercent -lt $threshold) { continue }

        [pscustomobject][ordered]@{
            gap_id = [string]$measurement.gap_id
            gap_type = 'volume_drop'
            source_id = [string]$measurement.source_id
            table_name = [string]$measurement.table_name
            start_inclusive = [string]$measurement.start_inclusive
            end_exclusive = [string]$measurement.end_exclusive
            baseline_count = $baseline
            observed_count = $observed
            drop_percent = $dropPercent
            threshold_percent = $threshold
            coverage_state = 'degraded'
        }
    }
}

Export-ModuleMember -Function Get-HavocTelemetryAffectedClaimScope, Get-HavocDetectionInputDrift, Get-HavocDcrAbsenceBoundary, ConvertTo-HavocVolumeDropGap
