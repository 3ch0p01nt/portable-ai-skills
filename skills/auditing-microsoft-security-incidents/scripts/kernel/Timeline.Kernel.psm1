Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function Get-HavocPropertyValue {
    param(
        [Parameter(Mandatory)] [object] $InputObject,
        [Parameter(Mandatory)] [string] $Name,
        [object] $Default = $null
    )
    $value = Get-HavocProperty -InputObject $InputObject -Name $Name
    if ($null -eq $value) { return $Default }
    return $value
}

function Format-HavocUtcTimestamp {
    param([Parameter(Mandatory)] [object] $Value)
    $timestamp = if ($Value -is [datetimeoffset]) { $Value } else { ConvertTo-HavocUtcTimestamp -Value $Value }
    return $timestamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-HavocUtcDateTime {
    param([Parameter(Mandatory)] [object] $Value)
    if ($Value -is [string] -and $Value -match ':60(?:\.|Z|[+-])') { throw 'Leap seconds are not supported by the timeline kernel.' }
    return ConvertTo-HavocUtcTimestamp -Value $Value
}

function ConvertTo-HavocIdArray {
    param([object] $Value)
    return @(@(Get-HavocArray -Value $Value) | ForEach-Object { [string]$_ })
}

function Get-HavocTimestampParseResult {
    param(
        [string] $RawTimestamp,
        [string] $SourceTimeZone
    )

    if ([string]::IsNullOrWhiteSpace($RawTimestamp)) {
        return [pscustomobject]@{
            Missing = $true
            Utc = $null
            StartUtc = $null
            EndUtc = $null
            Confidence = 'not_assessed'
            Reason = 'event time missing'
            Basis = 'event time missing'
        }
    }

    if ($RawTimestamp -match ':60(?:\.|Z|[+-])') {
        throw 'Leap seconds are not supported by the timeline kernel.'
    }

    $styles = [Globalization.DateTimeStyles]::AllowWhiteSpaces
    $hasOffset = $RawTimestamp -match '(Z|[+-]\d{2}:?\d{2})$'
    if ($hasOffset) {
        $utc = ConvertTo-HavocUtcTimestamp -Value $RawTimestamp
        return [pscustomobject]@{
            Missing = $false
            Utc = $utc
            StartUtc = $utc
            EndUtc = $utc
            Confidence = 'high'
            Reason = 'timestamp included an explicit UTC offset'
            Basis = 'explicit offset timestamp'
        }
    }

    if ([string]::IsNullOrWhiteSpace($SourceTimeZone)) {
        return [pscustomobject]@{
            Missing = $true
            Utc = $null
            StartUtc = $null
            EndUtc = $null
            Confidence = 'not_assessed'
            Reason = 'source timezone missing for offset-free event timestamp'
            Basis = 'event time unplaced because offset-free timestamp lacked source timezone'
        }
    }

    $local = [datetime]::Parse($RawTimestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AllowWhiteSpaces)
    $local = [datetime]::SpecifyKind($local, [datetimekind]::Unspecified)
    $tz = [TimeZoneInfo]::FindSystemTimeZoneById($SourceTimeZone)

    if ($tz.IsInvalidTime($local)) {
        throw "Invalid local timestamp '$RawTimestamp' for source timezone '$SourceTimeZone'."
    }

    if ($tz.IsAmbiguousTime($local)) {
        $utcValues = @($tz.GetAmbiguousTimeOffsets($local) | ForEach-Object { ([datetimeoffset]::new($local, $_)).ToUniversalTime() } | Sort-Object)
        return [pscustomobject]@{
            Missing = $false
            Utc = $utcValues[0]
            StartUtc = $utcValues[0]
            EndUtc = $utcValues[-1]
            Confidence = 'low'
            Reason = "ambiguous local time in $SourceTimeZone"
            Basis = 'DST ambiguous local timestamp'
        }
    }

    $converted = [TimeZoneInfo]::ConvertTimeToUtc($local, $tz)
    $convertedOffset = [datetimeoffset]::new($converted)
    return [pscustomobject]@{
        Missing = $false
        Utc = $convertedOffset
        StartUtc = $convertedOffset
        EndUtc = $convertedOffset
        Confidence = 'moderate'
        Reason = "offset-free timestamp interpreted with source timezone $SourceTimeZone"
        Basis = 'source timezone conversion'
    }
}

function New-HavocTimelineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $InputObject,
        [timespan] $LateArrivalThreshold = ([timespan]::FromHours(12))
    )

    $timelineId = [string](Get-HavocPropertyValue $InputObject 'timeline_id')
    $eventRef = [string](Get-HavocPropertyValue $InputObject 'event_ref')
    $sourceId = [string](Get-HavocPropertyValue $InputObject 'source_id')
    $upstreamRecordId = [string](Get-HavocPropertyValue $InputObject 'upstream_record_id')
    $rawTimestamp = [string](Get-HavocPropertyValue $InputObject 'raw_timestamp' '')
    $sourceTimeZoneValue = Get-HavocPropertyValue $InputObject 'source_timezone'
    $sourceTimeZone = if ($null -eq $sourceTimeZoneValue) { '' } else { [string]$sourceTimeZoneValue }
    $rawTimestampHasOffset = $rawTimestamp -match '(Z|[+-]\d{2}:?\d{2})$'
    $sourceTimeZoneForOutput = if ([string]::IsNullOrWhiteSpace($sourceTimeZone)) {
        if ($rawTimestampHasOffset) { 'explicit_offset' } else { 'not_provided' }
    } else {
        $sourceTimeZone
    }
    $ingestionUtc = ConvertTo-HavocUtcDateTime (Get-HavocPropertyValue $InputObject 'ingestion_time')
    $retrievalUtc = ConvertTo-HavocUtcDateTime (Get-HavocPropertyValue $InputObject 'retrieval_time')
    $evidenceIds = ConvertTo-HavocIdArray (Get-HavocPropertyValue $InputObject 'evidence_ids')
    $claimIds = ConvertTo-HavocIdArray (Get-HavocPropertyValue $InputObject 'claim_ids')

    if ([string]::IsNullOrWhiteSpace($upstreamRecordId)) {
        throw 'upstream_record_id is required for timeline lineage grouping.'
    }

    $parse = Get-HavocTimestampParseResult -RawTimestamp $rawTimestamp -SourceTimeZone $sourceTimeZone

    $gapIds = @()
    $errorIds = @()
    $behaviorBases = @('configurable_project_policy')
    if ($parse.Missing) {
        $gapIds += "GAP-$timelineId-event-time"
        $timeKind = 'event_time_missing'
        $timeValueUtc = $retrievalUtc
        $sourceEventTimeUtcText = ''
        $uncertainty = "$($parse.Basis); time_value is retrieval-time placeholder for schema compatibility and MUST NOT be used as event sequence evidence"
        $eventToIngestion = 0
        $eventToRetrieval = 0
        $late = $false
        $lateBasis = 'event_time_missing'
        $intervalStart = $retrievalUtc
        $intervalEnd = $retrievalUtc
    } else {
        $timeKind = 'event_time_utc'
        $timeValueUtc = $parse.Utc
        $sourceEventTimeUtcText = Format-HavocUtcTimestamp $parse.Utc
        $uncertainty = $parse.Basis
        $eventToIngestion = [int][math]::Max(0, [math]::Round(($ingestionUtc - $parse.Utc).TotalSeconds, 0))
        $eventToRetrieval = [int][math]::Max(0, [math]::Round(($retrievalUtc - $parse.Utc).TotalSeconds, 0))
        $late = ($ingestionUtc - $parse.Utc) -gt $LateArrivalThreshold
        $lateBasis = if ($late) { 'event_to_ingestion_exceeded_threshold' } else { 'within_threshold' }
        $intervalStart = $parse.StartUtc
        $intervalEnd = $parse.EndUtc
    }

    return [pscustomobject][ordered]@{
        timeline_id = $timelineId
        event_ref = $eventRef
        source_id = $sourceId
        upstream_record_id = $upstreamRecordId
        time_kind = $timeKind
        time_value = Format-HavocUtcTimestamp $timeValueUtc
        timestamp_provenance = [pscustomobject][ordered]@{
            raw_timestamp = $rawTimestamp
            source_timezone = $sourceTimeZoneForOutput
            event_time_source = if ($parse.Missing) { 'missing' } else { 'source_event_time' }
            source_event_time_utc = $sourceEventTimeUtcText
            parse_culture = 'InvariantCulture'
            normalization = 'UTC comparison time with raw value preserved'
        }
        timestamp_confidence = [pscustomobject][ordered]@{
            level = $parse.Confidence
            reason = $parse.Reason
            evidence_ids = @($evidenceIds)
        }
        uncertainty_interval = [pscustomobject][ordered]@{
            start_utc = Format-HavocUtcTimestamp $intervalStart
            end_utc = Format-HavocUtcTimestamp $intervalEnd
            basis = $parse.Basis
        }
        uncertainty = $uncertainty
        ingestion_time = Format-HavocUtcTimestamp $ingestionUtc
        retrieval_time = Format-HavocUtcTimestamp $retrievalUtc
        latency = [pscustomobject][ordered]@{
            event_to_ingestion_seconds = $eventToIngestion
            event_to_retrieval_seconds = $eventToRetrieval
            is_late_arriving = [bool]$late
            late_arrival_basis = $lateBasis
        }
        deduplication = [pscustomobject][ordered]@{
            lineage_key = "$sourceId|$upstreamRecordId"
            duplicate_count = 0
            duplicate_timeline_ids = @()
            independence_basis = 'unique upstream lineage not yet merged'
        }
        claim_ids = @($claimIds)
        evidence_ids = @($evidenceIds)
        gap_ids = @($gapIds)
        error_ids = @($errorIds)
        behavior_bases = @($behaviorBases)
    }
}

function Add-HavocClockOffsetCorrection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Record,
        [Parameter(Mandatory)] [timespan] $Offset,
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string[]] $EvidenceIds,
        [Parameter(Mandatory)] [object] $AsOf
    )

    $clone = $Record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -DateKind String
    if ($clone.time_kind -eq 'event_time_missing') {
        throw 'Cannot apply a clock-offset correction when source event time is missing.'
    }

    $sourceUtc = ConvertTo-HavocUtcDateTime $clone.timestamp_provenance.source_event_time_utc
    $corrected = $sourceUtc - $Offset
    $correctedStart = (ConvertTo-HavocUtcDateTime $clone.uncertainty_interval.start_utc) - $Offset
    $correctedEnd = (ConvertTo-HavocUtcDateTime $clone.uncertainty_interval.end_utc) - $Offset
    $appliedAt = ConvertTo-HavocUtcDateTime $AsOf
    $clone.time_kind = 'event_time_corrected_utc'
    $clone.time_value = Format-HavocUtcTimestamp $corrected
    $clone.timestamp_provenance.event_time_source = 'corrected_source_event_time'
    if ($clone.timestamp_confidence.level -eq 'high') {
        $clone.timestamp_confidence.level = 'moderate'
    }
    $clone.timestamp_confidence.reason = "source event time corrected by $([int]$Offset.TotalSeconds) seconds using $Method"
    $clone.uncertainty = 'clock-offset corrected comparison time; raw source timestamp retained'
    $clone.uncertainty_interval.start_utc = Format-HavocUtcTimestamp $correctedStart
    $clone.uncertainty_interval.end_utc = Format-HavocUtcTimestamp $correctedEnd
    $clone.uncertainty_interval.basis = "$($clone.uncertainty_interval.basis); shifted by clock-offset correction"
    $clone | Add-Member -NotePropertyName clock_offset -NotePropertyValue ([pscustomobject][ordered]@{
        offset_seconds = [int]$Offset.TotalSeconds
        method = $Method
        evidence_ids = @($EvidenceIds)
        applied_at = Format-HavocUtcTimestamp $appliedAt
    }) -Force
    return $clone
}

function Compare-HavocTimelineOrder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $First,
        [Parameter(Mandatory)] [object] $Second
    )

    if ($First.time_kind -ceq 'event_time_missing' -or $Second.time_kind -ceq 'event_time_missing') {
        return [pscustomobject][ordered]@{
            ordering = 'order_indeterminate'
            reason = 'event_time_missing'
            first_timeline_id = $First.timeline_id
            second_timeline_id = $Second.timeline_id
        }
    }

    $firstStart = ConvertTo-HavocUtcDateTime $First.uncertainty_interval.start_utc
    $firstEnd = ConvertTo-HavocUtcDateTime $First.uncertainty_interval.end_utc
    $secondStart = ConvertTo-HavocUtcDateTime $Second.uncertainty_interval.start_utc
    $secondEnd = ConvertTo-HavocUtcDateTime $Second.uncertainty_interval.end_utc

    if ($firstEnd -ge $secondStart -and $secondEnd -ge $firstStart) {
        return [pscustomobject][ordered]@{
            ordering = 'order_indeterminate'
            reason = 'uncertainty intervals overlap; no false sequence is emitted'
            first_timeline_id = $First.timeline_id
            second_timeline_id = $Second.timeline_id
        }
    }

    if ($firstEnd -lt $secondStart) { $ordering = 'first_before_second' } else { $ordering = 'second_before_first' }
    return [pscustomobject][ordered]@{
        ordering = $ordering
        reason = 'uncertainty intervals do not overlap'
        first_timeline_id = $First.timeline_id
        second_timeline_id = $Second.timeline_id
    }
}

function Merge-HavocTimelineRecords {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Records)

    $kept = New-Object System.Collections.Generic.List[object]
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($group in ($Records | Group-Object -Property { $_.deduplication.lineage_key } -CaseSensitive)) {
        $items = @($group.Group)
        $first = $items[0] | ConvertTo-Json -Depth 30 | ConvertFrom-Json -DateKind String
        if ($items.Count -gt 1) {
            $duplicateIds = @($items | Select-Object -Skip 1 | ForEach-Object { [string]$_.timeline_id })
            $first.deduplication.duplicate_count = $items.Count - 1
            $first.deduplication.duplicate_timeline_ids = @($duplicateIds)
            $first.deduplication.independence_basis = 'same source_id and upstream_record_id; treated as duplicate copies, not independent corroboration'
            $groups.Add([pscustomobject][ordered]@{
                lineage_key = [string]$group.Name
                retained_timeline_id = [string]$first.timeline_id
                duplicate_timeline_ids = @($duplicateIds)
                duplicate_count = $items.Count - 1
            }) | Out-Null
        }
        $kept.Add($first) | Out-Null
    }

    return [pscustomobject][ordered]@{
        records = @($kept.ToArray())
        duplicate_groups = @($groups.ToArray())
    }
}

function Resolve-HavocTimelinePlacement {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Records)

    $placed = New-Object System.Collections.Generic.List[object]
    $unplaced = New-Object System.Collections.Generic.List[object]
    foreach ($record in $Records) {
        if ($record.time_kind -eq 'event_time_missing') {
            $clone = $record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -DateKind String
            $clone | Add-Member -NotePropertyName unplaced_reason -NotePropertyValue 'event time missing' -Force
            $unplaced.Add($clone) | Out-Null
            continue
        }
        $placed.Add($record) | Out-Null
    }

    $orderedPlaced = @(
        $placed.ToArray() | Sort-Object `
            @{ Expression = { (ConvertTo-HavocUtcDateTime $_.uncertainty_interval.start_utc).UtcDateTime } },
            @{ Expression = { (ConvertTo-HavocUtcDateTime $_.uncertainty_interval.end_utc).UtcDateTime } },
            @{ Expression = { [string]$_.timeline_id } }
    )

    return [pscustomobject][ordered]@{
        placed_records = @($orderedPlaced)
        unplaced_records = @($unplaced.ToArray())
    }
}

function Select-HavocTimelineAuditProjection {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object] $Record)

    return [pscustomobject][ordered]@{
        timeline_id = $Record.timeline_id
        event_ref = $Record.event_ref
        time_kind = $Record.time_kind
        time_value = $Record.time_value
        uncertainty = $Record.uncertainty
        claim_ids = @($Record.claim_ids)
        evidence_ids = @($Record.evidence_ids)
        gap_ids = @($Record.gap_ids)
        error_ids = @($Record.error_ids)
        behavior_bases = @($Record.behavior_bases)
    }
}

function Get-HavocAuditTimelineProjectionSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AuditSchemaPath,
        [Parameter(Mandatory)] [string] $VocabularySchemaPath
    )

    if (-not (Test-Path -LiteralPath $AuditSchemaPath)) { throw "Audit schema not found: $AuditSchemaPath" }
    if (-not (Test-Path -LiteralPath $VocabularySchemaPath)) { throw "Vocabulary schema not found: $VocabularySchemaPath" }

    return [pscustomobject][ordered]@{
        '$schema' = 'https://json-schema.org/draft/2020-12/schema'
        type = 'object'
        required = @('timeline_id','event_ref','time_kind','time_value','uncertainty','claim_ids','evidence_ids','gap_ids','error_ids','behavior_bases')
        properties = [pscustomobject][ordered]@{
            timeline_id = [pscustomobject]@{ type = 'string'; minLength = 1; pattern = '^[A-Za-z][A-Za-z0-9._:-]*$' }
            event_ref = [pscustomobject]@{ type = 'string'; minLength = 1; pattern = '^[A-Za-z][A-Za-z0-9._:-]*$' }
            time_kind = [pscustomobject]@{ type = 'string'; minLength = 1 }
            time_value = [pscustomobject]@{ type = 'string'; format = 'date-time' }
            uncertainty = [pscustomobject]@{ type = 'string'; minLength = 1 }
            claim_ids = [pscustomobject]@{ type = 'array'; uniqueItems = $true; items = [pscustomobject]@{ type = 'string'; minLength = 1; pattern = '^[A-Za-z][A-Za-z0-9._:-]*$' } }
            evidence_ids = [pscustomobject]@{ type = 'array'; uniqueItems = $true; items = [pscustomobject]@{ type = 'string'; minLength = 1; pattern = '^[A-Za-z][A-Za-z0-9._:-]*$' } }
            gap_ids = [pscustomobject]@{ type = 'array'; uniqueItems = $true; items = [pscustomobject]@{ type = 'string'; minLength = 1; pattern = '^[A-Za-z][A-Za-z0-9._:-]*$' } }
            error_ids = [pscustomobject]@{ type = 'array'; uniqueItems = $true; items = [pscustomobject]@{ type = 'string'; minLength = 1; pattern = '^[A-Za-z][A-Za-z0-9._:-]*$' } }
            behavior_bases = [pscustomobject]@{ type = 'array'; minItems = 1; uniqueItems = $true; items = [pscustomobject]@{ type = 'string'; enum = @('guaranteed_behavior','configurable_project_policy','conditional_capability','explicit_gap') } }
        }
        additionalProperties = $true
    }
}

Export-ModuleMember -Function New-HavocTimelineRecord, Add-HavocClockOffsetCorrection, Compare-HavocTimelineOrder, Merge-HavocTimelineRecords, Resolve-HavocTimelinePlacement, Select-HavocTimelineAuditProjection, Get-HavocAuditTimelineProjectionSchema
