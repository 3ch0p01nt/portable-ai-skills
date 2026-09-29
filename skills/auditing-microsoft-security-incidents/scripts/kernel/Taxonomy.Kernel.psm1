Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:MapPath = Join-Path $PSScriptRoot '..\..\references\kernel\incident-taxonomy-map.json'
$script:TaxonomyMap = $null

function Get-IncidentTaxonomyMap {
    [CmdletBinding()]
    param()
    if ($null -eq $script:TaxonomyMap) {
        if (-not (Test-Path -LiteralPath $script:MapPath)) {
            throw "Incident taxonomy map not found: $script:MapPath"
        }
        $script:TaxonomyMap = Get-Content -LiteralPath $script:MapPath -Raw | ConvertFrom-Json -Depth 100 -DateKind String
    }
    return $script:TaxonomyMap
}

function New-TaxonomyGapRecord {
    param(
        [Parameter(Mandatory)][string]$GapType,
        [Parameter(Mandatory)][string]$Description,
        [string]$ProductValue,
        [string[]]$AffectedClaimIds = @('CLAIM-taxonomy-verdict')
    )
    $gapIdSuffix = ($GapType + '-' + ($ProductValue ?? 'value')) -replace '[^A-Za-z0-9]+','-'
    [pscustomobject][ordered]@{
        gap_id = "TAX-GAP-$gapIdSuffix"
        gap_type = $GapType
        description = $Description
        product_value = $ProductValue
        affected_claim_ids = @($AffectedClaimIds)
        follow_up = 'Verify deciding evidence and source enum documentation before recording an assessed auditor verdict.'
    }
}

function New-TaxonomyAuditorAssessment {
    param(
        [string]$AuditorVerdict,
        [string[]]$AuditorEvidenceIds,
        [string]$AuditorReasoning,
        [switch]$ForceInsufficient
    )

    $evidenceIds = @(Get-HavocArray -Value $AuditorEvidenceIds)
    if ($ForceInsufficient -or [string]::IsNullOrWhiteSpace($AuditorVerdict) -or $evidenceIds.Count -eq 0 -or [string]::IsNullOrWhiteSpace($AuditorReasoning)) {
        return [pscustomobject][ordered]@{
            assessment_state = 'insufficient_evidence'
            auditor_verdict = $null
            evidence_ids = @()
            reasoning = $null
        }
    }

    [pscustomobject][ordered]@{
        assessment_state = 'assessed'
        auditor_verdict = $AuditorVerdict
        evidence_ids = @($evidenceIds)
        reasoning = $AuditorReasoning
    }
}

function Get-TaxonomyEvidenceIds {
    param([AllowNull()][object]$InputObject)
    return @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'evidence_ids') | ForEach-Object { [string]$_ })
}

function Test-TaxonomyTruthy {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return ([string]$Value) -cin @('true','True','TRUE','1','yes','Yes','YES')
}

function Get-TaxonomySeverityRank {
    param([AllowNull()][object]$Severity)
    $value = ([string]$Severity).ToLowerInvariant()
    switch ($value) {
        'critical' { return 5 }
        'high' { return 4 }
        'medium' { return 3 }
        'moderate' { return 3 }
        'low' { return 2 }
        'informational' { return 1 }
        'info' { return 1 }
        default { return $null }
    }
}

function Test-TaxonomyReviewedChange {
    param([AllowNull()][object]$InputObject)
    if (Test-TaxonomyTruthy -Value (Get-HavocProperty -InputObject $InputObject -Name 'reviewed')) { return $true }
    foreach ($name in @('reviewed_by','reviewed_at','review_evidence_ids')) {
        $value = Get-HavocProperty -InputObject $InputObject -Name $name
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) { return $true }
    }
    return $false
}

function Resolve-TaxonomyActorSource {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$GapRecords
    )

    $declaredSource = ([string](Get-HavocProperty -InputObject $InputObject -Name 'source')).ToLowerInvariant()
    $actor = [string](Get-HavocProperty -InputObject $InputObject -Name 'actor')
    $actorType = $null
    foreach ($actorTypeName in @('actor_type','actorType','ActorType','initiated_by_type','initiatedByType')) {
        $actorTypeValue = Get-HavocProperty -InputObject $InputObject -Name $actorTypeName
        if ($null -ne $actorTypeValue -and -not [string]::IsNullOrWhiteSpace([string]$actorTypeValue)) {
            $actorType = [string]$actorTypeValue
            break
        }
    }

    $actorTypeLower = if ($null -eq $actorType) { '' } else { $actorType.ToLowerInvariant() }
    $actorLower = $actor.ToLowerInvariant()
    $sourceIsAutomation = $declaredSource -ceq 'automation'
    $sourceIsAnalyst = $declaredSource -ceq 'analyst'
    $actorTypeAutomation = $actorTypeLower -cin @('serviceprincipal','service_principal','application','app','managedidentity','managed_identity','logicapp','playbook','automation')
    $actorTypeHuman = $actorTypeLower -cin @('user','analyst','human')
    $actorExactAutomation = $actorLower -cin @('automation','microsoft 365 defender','microsoftdefender')
    $actorHasAutomationMarker = $actorLower -match '(?:automation|microsoft\s*365\s*defender|microsoftdefender|playbook|logic[-\s]?app|service[-\s]?principal|serviceprincipal)'
    if ($actorLower -match '@' -and $actorHasAutomationMarker -and -not $actorExactAutomation -and -not $actorTypeAutomation -and -not $sourceIsAutomation) {
        $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "Actor '$actor' looks like a user principal name and contains automation-like text; source is treated as unknown without explicit automation source or actor type evidence." -ProductValue 'automation_actor_ambiguous'))
        return [pscustomobject][ordered]@{
            source = 'unknown'
            basis = 'actor_ambiguous'
            note = 'UPN-looking actor contains automation-like text'
        }
    }
    $actorPatternAutomation = $actorExactAutomation -or ($actorLower -notmatch '@' -and $actorHasAutomationMarker)
    $actorPatternHuman = $actorLower -match '(^|[:/._-])analyst([:/._-]|$)'
    $actorIndicatesAutomation = $actorTypeAutomation -or $actorPatternAutomation
    $actorIndicatesHuman = $actorTypeHuman -or $actorPatternHuman

    if (($sourceIsAnalyst -and $actorIndicatesAutomation) -or ($sourceIsAutomation -and $actorIndicatesHuman)) {
        $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "Actor/source conflict for taxonomy change: declared source '$declaredSource' conflicts with actor '$actor' and actor type '$actorType'; source is treated as unknown." -ProductValue 'automation_source_actor_conflict'))
        return [pscustomobject][ordered]@{
            source = 'unknown'
            basis = 'source_actor_conflict'
            note = 'declared source conflicts with actor evidence'
        }
    }

    if ($actorTypeAutomation) {
        return [pscustomobject][ordered]@{ source = 'automation'; basis = 'actor_type'; note = '' }
    }
    if ($actorPatternAutomation) {
        return [pscustomobject][ordered]@{ source = 'automation'; basis = 'actor_pattern'; note = '' }
    }
    if ($sourceIsAutomation) {
        return [pscustomobject][ordered]@{ source = 'automation'; basis = 'source'; note = '' }
    }
    if ($sourceIsAnalyst) {
        return [pscustomobject][ordered]@{ source = 'analyst'; basis = 'source'; note = '' }
    }
    if (-not [string]::IsNullOrWhiteSpace($declaredSource)) {
        return [pscustomobject][ordered]@{ source = $declaredSource; basis = 'source'; note = '' }
    }
    return [pscustomobject][ordered]@{ source = 'unknown'; basis = 'missing'; note = 'source unavailable' }
}

function Format-TaxonomyActorSourceText {
    param([Parameter(Mandatory)][object]$ActorSource)
    $source = [string](Get-HavocProperty -InputObject $ActorSource -Name 'source')
    $basis = [string](Get-HavocProperty -InputObject $ActorSource -Name 'basis')
    if ($source -ceq 'automation' -and -not [string]::IsNullOrWhiteSpace($basis)) {
        return "$source (detection basis $basis)"
    }
    return $source
}

function New-TaxonomyDiscrepancyRecord {
    param(
        [Parameter(Mandatory)][string]$IdSuffix,
        [Parameter(Mandatory)][ValidateSet('product_auditor_assessment_disagreement','severity_mismatch','status_mismatch','closure_rationale_gap')][string]$DiscrepancyType,
        [Parameter(Mandatory)][string]$RecordedClassification,
        [Parameter(Mandatory)][string]$ProductValue,
        [Parameter(Mandatory)][string[]]$EvidenceIds,
        [Parameter(Mandatory)][string]$Message
    )
    $safeSuffix = ($IdSuffix -replace '[^A-Za-z0-9._:-]+','-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($safeSuffix)) { $safeSuffix = 'taxonomy-finding' }
    $safeProductValue = if ([string]::IsNullOrWhiteSpace($ProductValue)) { $DiscrepancyType } else { $ProductValue }
    $safeEvidenceIds = @(Get-HavocArray -Value $EvidenceIds | ForEach-Object { [string]$_ })
    if ($safeEvidenceIds.Count -eq 0) { $safeEvidenceIds = @('E-taxonomy-audit-control') }
    [pscustomobject][ordered]@{
        discrepancy_id = "TAX-DISC-$safeSuffix"
        discrepancy_type = $DiscrepancyType
        recorded_classification = $RecordedClassification
        auditor_verdict = 'inconclusive_evidence_or_coverage_gap'
        product_value = $safeProductValue
        evidence_ids = @($safeEvidenceIds)
        message = $Message
    }
}

function Get-TaxonomyHistoryAuditInput {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$ValueName,
        [AllowNull()][object[]]$History
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $evidence = [System.Collections.Generic.List[string]]::new()
    $inputItems = @(Get-HavocArray -Value $History)
    if ($inputItems.Count -eq 0) {
        $productValue = "$($Kind.ToLowerInvariant())_history_not_supplied"
        $gaps.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "$Kind change history was not supplied; do not infer that $($Kind.ToLowerInvariant()) never changed." -ProductValue $productValue))
    }

    foreach ($entry in $inputItems) {
        $entryEvidence = @(Get-TaxonomyEvidenceIds -InputObject $entry)
        foreach ($id in $entryEvidence) { $evidence.Add($id) }

        if (Test-TaxonomyTruthy -Value (Get-HavocProperty -InputObject $entry -Name 'history_unavailable')) {
            $gaps.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "$Kind change history is unavailable; do not infer that $($Kind.ToLowerInvariant()) never changed." -ProductValue "$($Kind.ToLowerInvariant())_history_unavailable"))
            continue
        }
        if (Test-TaxonomyTruthy -Value (Get-HavocProperty -InputObject $entry -Name 'history_truncated')) {
            $truncatedAtRaw = Get-HavocProperty -InputObject $entry -Name 'truncated_at'
            $truncatedAt = if ($null -ne $truncatedAtRaw -and -not [string]::IsNullOrWhiteSpace([string]$truncatedAtRaw)) { Format-HavocTimestamp -Value (ConvertTo-HavocUtcTimestamp -Value $truncatedAtRaw) } else { 'unknown time' }
            $gaps.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "$Kind change history is truncated at $truncatedAt; earlier flips may be missing." -ProductValue "$($Kind.ToLowerInvariant())_history_truncated"))
            continue
        }

        $observedRaw = Get-HavocProperty -InputObject $entry -Name 'observed_at'
        $value = Get-HavocProperty -InputObject $entry -Name $ValueName
        if ($null -eq $observedRaw -or [string]::IsNullOrWhiteSpace([string]$observedRaw) -or $null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
            $gaps.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "$Kind change history has a record missing timestamp or value; ordering is incomplete." -ProductValue "$($Kind.ToLowerInvariant())_history_gap"))
            continue
        }

        $observed = ConvertTo-HavocUtcTimestamp -Value $observedRaw
        $sortKey = (@($entryEvidence) -join '|') + '|' + [string]$value + '|' + [string](Get-HavocProperty -InputObject $entry -Name 'actor')
        $items.Add([pscustomobject][ordered]@{
            kind = $Kind
            observed_at = Format-HavocTimestamp -Value $observed
            observed = $observed
            sort_key = $sortKey
            value = [string]$value
            actor = [string](Get-HavocProperty -InputObject $entry -Name 'actor')
            source = ([string](Get-HavocProperty -InputObject $entry -Name 'source')).ToLowerInvariant()
            actor_type = [string](Get-HavocProperty -InputObject $entry -Name 'actor_type')
            rationale = [string](Get-HavocProperty -InputObject $entry -Name 'rationale')
            reviewed = Test-TaxonomyReviewedChange -InputObject $entry
            evidence_ids = @($entryEvidence)
        })
    }

    [pscustomobject][ordered]@{
        items = @($items.ToArray() | Sort-Object -Property observed_at, sort_key)
        gap_records = @($gaps.ToArray())
        evidence_ids = @($evidence.ToArray())
    }
}

function Test-TaxonomyClosedStatus {
    param([AllowNull()][object]$Status)
    return (([string]$Status).ToLowerInvariant()) -cin @('closed','resolved')
}

function Test-TaxonomyReopenStatus {
    param([AllowNull()][object]$Status)
    return (([string]$Status).ToLowerInvariant()) -cin @('active','new','inprogress','in_progress','open','reopened')
}

function Get-TaxonomyClosureIntervals {
    param(
        [AllowNull()][object[]]$StatusItems,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Discrepancies,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$GapRecords
    )

    $intervals = [System.Collections.Generic.List[object]]::new()
    $currentClosure = $null
    foreach ($item in @($StatusItems)) {
        $itemObserved = Get-HavocProperty -InputObject $item -Name 'observed'
        if ($null -eq $item -or $null -eq $itemObserved) { continue }
        $itemValue = Get-HavocProperty -InputObject $item -Name 'value'
        if (Test-TaxonomyClosedStatus -Status $itemValue) {
            if ($null -eq $currentClosure) {
                $currentClosure = $item
            } else {
                $itemObservedAt = [string](Get-HavocProperty -InputObject $item -Name 'observed_at')
                $itemEvidenceIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $item -Name 'evidence_ids') | ForEach-Object { [string]$_ })
                $closureObservedAt = [string](Get-HavocProperty -InputObject $currentClosure -Name 'observed_at')
                $evidenceText = (@($itemEvidenceIds) -join ', ')
                $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "Duplicate closure observed at $itemObservedAt while incident was already closed from $closureObservedAt; recorded as a note; evidence $evidenceText." -ProductValue 'duplicate_closure_note'))
            }
            continue
        }
        if ((Test-TaxonomyReopenStatus -Status $itemValue) -and $null -ne $currentClosure) {
            $itemObservedAt = [string](Get-HavocProperty -InputObject $item -Name 'observed_at')
            $itemEvidenceIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $item -Name 'evidence_ids') | ForEach-Object { [string]$_ })
            $closureObserved = Get-HavocProperty -InputObject $currentClosure -Name 'observed'
            $closureObservedAt = [string](Get-HavocProperty -InputObject $currentClosure -Name 'observed_at')
            $closureActor = [string](Get-HavocProperty -InputObject $currentClosure -Name 'actor')
            if ([string]::IsNullOrWhiteSpace([string](Get-HavocProperty -InputObject $item -Name 'rationale'))) {
                $evidenceText = (@($itemEvidenceIds) -join ', ')
                $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "status-reopen-without-rationale-$itemObservedAt-$evidenceText" -DiscrepancyType 'status_mismatch' -RecordedClassification 'status_change_history' -ProductValue ([string]$itemValue) -EvidenceIds $itemEvidenceIds -Message "Incident reopened at $itemObservedAt without recorded rationale; previous closure observed at $closureObservedAt; evidence $evidenceText."))
            }
            $intervals.Add([pscustomobject][ordered]@{
                closed_at = $closureObserved
                closed_at_text = $closureObservedAt
                closed_by = $closureActor
                reopened_at = $itemObserved
                reopened_at_text = $itemObservedAt
            })
            $currentClosure = $null
        }
    }
    if ($null -ne $currentClosure) {
        $intervals.Add([pscustomobject][ordered]@{
            closed_at = Get-HavocProperty -InputObject $currentClosure -Name 'observed'
            closed_at_text = [string](Get-HavocProperty -InputObject $currentClosure -Name 'observed_at')
            closed_by = [string](Get-HavocProperty -InputObject $currentClosure -Name 'actor')
            reopened_at = $null
            reopened_at_text = $null
        })
    }
    return $intervals.ToArray()
}

function Get-TaxonomyActiveClosureInterval {
    param(
        [Parameter(Mandatory)][object]$Observed,
        [AllowNull()][object[]]$ClosureIntervals
    )

    foreach ($interval in @($ClosureIntervals)) {
        $closedAt = Get-HavocProperty -InputObject $interval -Name 'closed_at'
        if ($null -eq $interval -or $null -eq $closedAt) { continue }
        $reopenedAt = Get-HavocProperty -InputObject $interval -Name 'reopened_at'
        if ($Observed -le $closedAt) { continue }
        if ($null -ne $reopenedAt -and $Observed -ge $reopenedAt) { continue }
        return $interval
    }
    return $null
}

function Test-TaxonomyClosureWorkflowChange {
    param(
        [Parameter(Mandatory)][object]$Item,
        [Parameter(Mandatory)][object]$ClosureInterval,
        [int]$ToleranceMinutes = 10
    )
    $itemActor = [string](Get-HavocProperty -InputObject $Item -Name 'actor')
    $closedBy = [string](Get-HavocProperty -InputObject $ClosureInterval -Name 'closed_by')
    if ([string]::IsNullOrWhiteSpace($itemActor) -or $itemActor -cne $closedBy) { return $false }
    $closedAt = Get-HavocProperty -InputObject $ClosureInterval -Name 'closed_at'
    $itemObserved = Get-HavocProperty -InputObject $Item -Name 'observed'
    if ($null -eq $closedAt -or $null -eq $itemObserved) { return $false }
    return ($itemObserved -le $closedAt.AddMinutes($ToleranceMinutes))
}

function Add-TaxonomyChangeFindings {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SeverityItems,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ClassificationItems,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$StatusItems,
        [AllowNull()][object[]]$ClosureIntervals,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Discrepancies,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$GapRecords
    )

    $previous = $null
    $unknownSeverityValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($SeverityItems)) {
        $currentRank = Get-TaxonomySeverityRank -Severity $item.value
        $actorSource = Resolve-TaxonomyActorSource -InputObject $item -GapRecords $GapRecords
        if ($null -eq $currentRank) {
            if ($unknownSeverityValues.Add([string]$item.value)) {
                $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "Severity change history includes unrecognized severity value '$($item.value)' and must not be interpreted as a downgrade." -ProductValue 'severity_unknown'))
            }
        }
        if ($null -ne $previous) {
            $previousRank = Get-TaxonomySeverityRank -Severity $previous.value
            if ($null -ne $currentRank -and $null -ne $previousRank -and $currentRank -lt $previousRank -and [string]::IsNullOrWhiteSpace($item.rationale)) {
                $evidenceText = (@($item.evidence_ids) -join ', ')
                $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "severity-downgrade-$($item.observed_at)-$evidenceText" -DiscrepancyType 'severity_mismatch' -RecordedClassification 'severity_change_history' -ProductValue $item.value -EvidenceIds $item.evidence_ids -Message "Severity downgraded from $($previous.value) to $($item.value) at $($item.observed_at) by $($item.actor) from $($actorSource.source) without recorded rationale; evidence $evidenceText."))
            }
            if ($actorSource.source -ceq 'automation' -and $item.value -cne $previous.value -and -not $item.reviewed) {
                $evidenceText = (@($item.evidence_ids) -join ', ')
                $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "severity-automation-unreviewed-$($item.observed_at)-$evidenceText" -DiscrepancyType 'severity_mismatch' -RecordedClassification 'severity_change_history' -ProductValue $item.value -EvidenceIds $item.evidence_ids -Message "Automation changed severity from $($previous.value) to $($item.value) at $($item.observed_at) without analyst review evidence; actor $($item.actor); detection basis $($actorSource.basis); evidence $evidenceText."))
            }
        }
        $closureInterval = Get-TaxonomyActiveClosureInterval -Observed $item.observed -ClosureIntervals $ClosureIntervals
        if ($null -ne $closureInterval) {
            $closureText = $closureInterval.closed_at_text
            $evidenceText = (@($item.evidence_ids) -join ', ')
            $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "severity-after-closure-$($item.observed_at)-$evidenceText" -DiscrepancyType 'closure_rationale_gap' -RecordedClassification 'severity_change_history' -ProductValue $item.value -EvidenceIds $item.evidence_ids -Message "severity changed after closure at $($item.observed_at); closure observed at $closureText; evidence $evidenceText."))
        }
        $previous = $item
    }

    $previous = $null
    foreach ($item in @($ClassificationItems)) {
        $actorSource = Resolve-TaxonomyActorSource -InputObject $item -GapRecords $GapRecords
        $sourceText = Format-TaxonomyActorSourceText -ActorSource $actorSource
        if ($null -ne $previous -and $item.value -cne $previous.value) {
            $evidenceText = (@($item.evidence_ids) -join ', ')
            $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "classification-flip-$($item.observed_at)-$evidenceText" -DiscrepancyType 'product_auditor_assessment_disagreement' -RecordedClassification 'classification_change_history' -ProductValue $item.value -EvidenceIds $item.evidence_ids -Message "Classification changed from $($previous.value) to $($item.value) at $($item.observed_at) by $($item.actor) from $sourceText; evidence $evidenceText."))
        }
        $closureInterval = Get-TaxonomyActiveClosureInterval -Observed $item.observed -ClosureIntervals $ClosureIntervals
        if ($null -ne $closureInterval -and -not (Test-TaxonomyClosureWorkflowChange -Item $item -ClosureInterval $closureInterval)) {
            $closureText = $closureInterval.closed_at_text
            $evidenceText = (@($item.evidence_ids) -join ', ')
            $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "classification-after-closure-$($item.observed_at)-$evidenceText" -DiscrepancyType 'closure_rationale_gap' -RecordedClassification 'classification_change_history' -ProductValue $item.value -EvidenceIds $item.evidence_ids -Message "classification changed after closure at $($item.observed_at); closure observed at $closureText; evidence $evidenceText."))
        }
        $previous = $item
    }
}

function Add-TaxonomyGroupingFindings {
    param(
        [AllowNull()][object[]]$GroupingHistory,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Discrepancies,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$GapRecords,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CitationIds
    )

    $boundedDepths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $groupingItems = @(Get-HavocArray -Value $GroupingHistory)
    if ($groupingItems.Count -eq 0) {
        $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description 'Grouping audit was not supplied; alert-to-incident correlation, merges, splits, and orphan checks were not assessed.' -ProductValue 'grouping_audit_not_supplied'))
    }

    foreach ($entry in $groupingItems) {
        $evidenceIds = @(Get-TaxonomyEvidenceIds -InputObject $entry)
        foreach ($id in $evidenceIds) { $CitationIds.Add($id) }
        $relation = [string](Get-HavocProperty -InputObject $entry -Name 'relation_type')
        $depthRaw = Get-HavocProperty -InputObject $entry -Name 'depth_reached'
        $depthValue = 0
        $depthKnown = $false
        if ($null -ne $depthRaw -and -not [string]::IsNullOrWhiteSpace([string]$depthRaw)) {
            $depthKnown = [int]::TryParse([string]$depthRaw, [ref]$depthValue)
        }
        if (-not $depthKnown) {
            $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description 'Grouping audit depth is missing or non-numeric; depth reached is unknown.' -ProductValue 'grouping_depth_unknown'))
        }
        $depthText = if ($depthKnown) { [string]$depthValue } else { 'unknown' }
        $bounded = Test-TaxonomyTruthy -Value (Get-HavocProperty -InputObject $entry -Name 'bounded_by_data_limits')
        $boundedText = if ($bounded) { 'True' } else { 'False' }
        if ($bounded) {
            $key = $depthText
            if ($boundedDepths.Add($key)) {
                $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "Grouping audit depth reached $depthText and was bounded by data limits." -ProductValue "grouping_depth_$depthText"))
            }
        }
        if ([string]::IsNullOrWhiteSpace($relation)) { continue }
        $evidenceText = (@($evidenceIds) -join ', ')
        $message = $null
        $type = 'status_mismatch'

        switch ($relation) {
            'plausible_split' { $message = "Grouping audit reached depth $depthText and was bounded_by_data_limits=$boundedText; split candidate alerts $evidenceText plausibly belong together but remained in separate incidents." }
            'over_broad_merge' { $message = "Grouping audit reached depth $depthText and was bounded_by_data_limits=$boundedText; merge $evidenceText appears over-broad against distinct alert evidence." }
            'orphaned_alert' { $message = "Grouping audit reached depth $depthText and was bounded_by_data_limits=$boundedText; orphaned alert $evidenceText has no incident correlation evidence." }
            default {
                $GapRecords.Add((New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description "Grouping audit relation type '$relation' is unrecognized and was not interpreted." -ProductValue 'grouping_unknown_relation_type'))
                continue
            }
        }

        if ([string]::IsNullOrWhiteSpace($message)) { continue }
        $Discrepancies.Add((New-TaxonomyDiscrepancyRecord -IdSuffix "grouping-$relation-depth-$depthText-$evidenceText" -DiscrepancyType $type -RecordedClassification 'grouping_depth_audit' -ProductValue $relation -EvidenceIds $evidenceIds -Message $message))
    }
}

function Resolve-IncidentTaxonomyVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('microsoft_graph_security_incident','microsoft_graph_security_alert','microsoft_sentinel_incident_arm','securityincident_log_analytics_table')][string]$Source,
        [Parameter(Mandatory)][string]$Field,
        [Parameter(Mandatory)][string]$Value,
        [string[]]$CoverageGapIds = @(),
        [ValidateSet('true_positive_malicious_activity','informational_benign_positive_expected_activity','false_positive_detection_logic','false_positive_incorrect_data','inconclusive_evidence_or_coverage_gap')][string]$AuditorVerdict,
        [string[]]$AuditorEvidenceIds = @(),
        [string]$AuditorReasoning,
        [string[]]$KnownEvidenceIds = @(),
        [string[]]$AffectedClaimIds = @('CLAIM-taxonomy-verdict')
    )

    $map = Get-IncidentTaxonomyMap
    $entry = $map.mappings | Where-Object {
        [string]$_.source -ceq $Source -and [string]$_.field -ceq $Field -and [string]$_.value -ceq $Value
    } | Select-Object -First 1

    $gapRecords = @()
    $gapIds = @(Get-HavocArray -Value $CoverageGapIds)
    $isUnknown = $false

    if ($null -eq $entry -or [string]$Value -ceq 'unknownFutureValue') {
        $isUnknown = $true
        $recordedClassification = [pscustomobject][ordered]@{
            normalized_value = 'recorded_unassessed'
            candidate_auditor_verdicts = @('inconclusive_evidence_or_coverage_gap')
            is_deterministic = $true
            is_lossy = $true
            requires_false_positive_cause = $false
            source_url = if ($null -ne $entry) { [string]$entry.recorded_classification.source_url } else { $null }
            note = 'The product enum value is unknown, future, or unverified for this taxonomy version.'
        }
        $gapRecords += New-TaxonomyGapRecord -GapType 'unknown_or_unverified_product_enum' -Description 'The product enum value is unknown, future, or unverified for this taxonomy version and must not be guessed.' -ProductValue $Value -AffectedClaimIds $AffectedClaimIds
    } else {
        $recordedClassification = $entry.recorded_classification
    }

    if ($gapIds.Count -gt 0) {
        $gapRecords += New-TaxonomyGapRecord -GapType 'coverage_gap_controls_verdict' -Description 'One or more coverage gaps affect the deciding claim; the auditor assessment remains insufficient until resolved.' -ProductValue $Value -AffectedClaimIds $AffectedClaimIds
    }

    if ([bool]$recordedClassification.requires_false_positive_cause) {
        $gapRecords += New-TaxonomyGapRecord -GapType 'false_positive_cause_required' -Description 'Closing as false positive requires distinguishing detection logic from incorrect data.' -ProductValue $Value -AffectedClaimIds $AffectedClaimIds
    }

    $knownIds = @(Get-HavocArray -Value $KnownEvidenceIds)
    $auditorIds = @(Get-HavocArray -Value $AuditorEvidenceIds)
    $assessmentRequested = (-not [string]::IsNullOrWhiteSpace($AuditorVerdict) -or $auditorIds.Count -gt 0 -or -not [string]::IsNullOrWhiteSpace($AuditorReasoning))
    $unknownAuditorIds = @()
    $citationsUnverified = $false
    if ($assessmentRequested -and $knownIds.Count -eq 0) {
        $citationsUnverified = $true
        $gapRecords += New-TaxonomyGapRecord -GapType 'citations_unverified' -Description 'An auditor assessment was requested but no known evidence set was supplied; cited evidence cannot be verified.' -ProductValue 'known_evidence_set_missing' -AffectedClaimIds $AffectedClaimIds
    } elseif ($knownIds.Count -gt 0) {
        foreach ($auditorId in $auditorIds) {
            if ($auditorId -cnotin $knownIds) {
                $unknownAuditorIds += $auditorId
                $gapRecords += New-TaxonomyGapRecord -GapType 'unknown_auditor_evidence_id' -Description 'An auditor assessment cited an evidence ID absent from the supplied known evidence set.' -ProductValue $auditorId -AffectedClaimIds $AffectedClaimIds
            }
        }
    }

    $forceInsufficient = ($gapIds.Count -gt 0 -or $unknownAuditorIds.Count -gt 0 -or $citationsUnverified)
    $assessment = New-TaxonomyAuditorAssessment -AuditorVerdict $AuditorVerdict -AuditorEvidenceIds $AuditorEvidenceIds -AuditorReasoning $AuditorReasoning -ForceInsufficient:$forceInsufficient
    $agreement = 'not_assessed'
    $discrepancies = @()
    $candidates = @(Get-HavocArray -Value $recordedClassification.candidate_auditor_verdicts)

    if ($assessment.assessment_state -ceq 'assessed') {
        if ($isUnknown) {
            $agreement = 'indeterminate'
        } elseif ($assessment.auditor_verdict -cin $candidates) {
            $agreement = 'agrees'
        } elseif ($candidates.Count -gt 0) {
            $agreement = 'disagrees'
            $discrepancies += [pscustomobject][ordered]@{
                discrepancy_id = 'TAX-DISC-product-auditor-assessment-disagreement'
                discrepancy_type = 'product_auditor_assessment_disagreement'
                recorded_classification = [string]$recordedClassification.normalized_value
                auditor_verdict = [string]$assessment.auditor_verdict
                product_value = $Value
                evidence_ids = @($assessment.evidence_ids)
                message = 'The evidence-backed auditor assessment does not agree with the recorded product classification candidate verdicts.'
            }
        } else {
            $agreement = 'indeterminate'
        }
    }

    [pscustomobject][ordered]@{
        source = $Source
        field = $Field
        product_value = $Value
        recorded_classification = [pscustomobject][ordered]@{
            normalized_value = [string]$recordedClassification.normalized_value
            candidate_auditor_verdicts = @($candidates)
            is_deterministic = [bool]$recordedClassification.is_deterministic
            is_lossy = [bool]$recordedClassification.is_lossy
            requires_false_positive_cause = [bool]$recordedClassification.requires_false_positive_cause
            source_url = $recordedClassification.source_url
            note = [string]$recordedClassification.note
        }
        auditor_assessment = $assessment
        agreement = $agreement
        is_unknown_product_value = $isUnknown
        gap_ids = @($gapIds + @($gapRecords | ForEach-Object { $_.gap_id }))
        gap_records = @($gapRecords)
        discrepancies = @($discrepancies)
    }
}

function New-HavocTaxonomyAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TaxonomyVersion,
        [Parameter(Mandatory)][ValidateSet('microsoft_graph_security_incident','microsoft_graph_security_alert','microsoft_sentinel_incident_arm','securityincident_log_analytics_table')][string]$Source,
        [Parameter(Mandatory)][string]$Field,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][object]$ProductFields,
        [AllowEmptyCollection()][object[]]$SeverityHistory = @(),
        [object[]]$ClassificationHistory = @(),
        [object[]]$StatusHistory = @(),
        [object[]]$GroupingHistory = @(),
        [string[]]$CoverageGapIds = @(),
        [Parameter(Mandatory)][string[]]$ClaimIds,
        [Parameter(Mandatory)][string[]]$EvidenceIds,
        [Parameter(Mandatory)][string[]]$BehaviorBases,
        [Parameter(Mandatory)][object]$AsOf,
        [ValidateSet('true_positive_malicious_activity','informational_benign_positive_expected_activity','false_positive_detection_logic','false_positive_incorrect_data','inconclusive_evidence_or_coverage_gap')][string]$AuditorVerdict,
        [string[]]$AuditorEvidenceIds = @(),
        [string]$AuditorReasoning,
        [string[]]$KnownEvidenceIds = @(),
        [string[]]$AffectedClaimIds = @('CLAIM-taxonomy-verdict')
    )

    $asOfText = Format-HavocTimestamp -Value (ConvertTo-HavocUtcTimestamp -Value $AsOf)
    $claims = @(Get-HavocArray -Value $ClaimIds | ForEach-Object { [string]$_ })
    $evidence = @(Get-HavocArray -Value $EvidenceIds | ForEach-Object { [string]$_ })
    $behaviors = @(Get-HavocArray -Value $BehaviorBases | ForEach-Object { [string]$_ })
    $coverageGaps = @(Get-HavocArray -Value $CoverageGapIds | ForEach-Object { [string]$_ })

    $resolutionArgs = @{
        Source = $Source
        Field = $Field
        Value = $Value
        CoverageGapIds = $coverageGaps
        AuditorEvidenceIds = $AuditorEvidenceIds
        AuditorReasoning = $AuditorReasoning
        KnownEvidenceIds = $KnownEvidenceIds
        AffectedClaimIds = $AffectedClaimIds
    }
    if (-not [string]::IsNullOrWhiteSpace($AuditorVerdict)) {
        $resolutionArgs['AuditorVerdict'] = $AuditorVerdict
    }
    $resolution = Resolve-IncidentTaxonomyVerdict @resolutionArgs

    $builderGapRecords = @()
    $builderForceInsufficient = $false
    $builderKnownIds = @(Get-HavocArray -Value $KnownEvidenceIds | ForEach-Object { [string]$_ })
    $allCitationIds = [System.Collections.Generic.List[string]]::new()
    foreach ($rootEvidenceId in $evidence) {
        $allCitationIds.Add($rootEvidenceId)
    }
    foreach ($auditorEvidenceId in @(Get-HavocArray -Value $AuditorEvidenceIds | ForEach-Object { [string]$_ })) {
        $allCitationIds.Add($auditorEvidenceId)
    }

    $severityAudit = Get-TaxonomyHistoryAuditInput -Kind 'Severity' -ValueName 'severity' -History $SeverityHistory
    $classificationAudit = Get-TaxonomyHistoryAuditInput -Kind 'Classification' -ValueName 'classification' -History $ClassificationHistory
    $statusAudit = Get-TaxonomyHistoryAuditInput -Kind 'Status' -ValueName 'status' -History $StatusHistory
    foreach ($historyEvidenceId in @($severityAudit.evidence_ids + $classificationAudit.evidence_ids + $statusAudit.evidence_ids)) {
        $allCitationIds.Add($historyEvidenceId)
    }

    $severityRecords = @()
    foreach ($item in @($severityAudit.items)) {
        $severityRecords += [pscustomobject][ordered]@{
            observed_at = $item.observed_at
            severity = [string]$item.value
            evidence_ids = @($item.evidence_ids)
        }
    }

    $historyDiscrepancies = [System.Collections.Generic.List[object]]::new()
    $historyGapRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($historyGap in @($severityAudit.gap_records + $classificationAudit.gap_records + $statusAudit.gap_records)) {
        $historyGapRecords.Add($historyGap)
    }
    $closureIntervals = Get-TaxonomyClosureIntervals -StatusItems $statusAudit.items -Discrepancies $historyDiscrepancies -GapRecords $historyGapRecords
    Add-TaxonomyChangeFindings -SeverityItems $severityAudit.items -ClassificationItems $classificationAudit.items -StatusItems $statusAudit.items -ClosureIntervals $closureIntervals -Discrepancies $historyDiscrepancies -GapRecords $historyGapRecords
    Add-TaxonomyGroupingFindings -GroupingHistory $GroupingHistory -Discrepancies $historyDiscrepancies -GapRecords $historyGapRecords -CitationIds $allCitationIds

    $sortedEvidence = @($allCitationIds.ToArray() | Sort-Object -Unique -CaseSensitive)
    if ($builderKnownIds.Count -eq 0 -and $sortedEvidence.Count -gt 0) {
        $builderForceInsufficient = $true
        $builderGapRecords += New-TaxonomyGapRecord -GapType 'citations_unverified' -Description 'Taxonomy audit record citations cannot be verified because no known evidence set was supplied.' -ProductValue 'known_evidence_set_missing' -AffectedClaimIds $AffectedClaimIds
    } elseif ($builderKnownIds.Count -gt 0) {
        foreach ($citationId in $sortedEvidence) {
            if ($citationId -cnotin $builderKnownIds) {
                $builderForceInsufficient = $true
                $builderGapRecords += New-TaxonomyGapRecord -GapType 'citations_unverified' -Description 'A taxonomy audit record citation is absent from the supplied known evidence set.' -ProductValue $citationId -AffectedClaimIds $AffectedClaimIds
            }
        }
    }

    $productFieldRecord = [ordered]@{
        severity = [string](Get-HavocProperty -InputObject $ProductFields -Name 'severity')
        status = [string](Get-HavocProperty -InputObject $ProductFields -Name 'status')
        title = [string](Get-HavocProperty -InputObject $ProductFields -Name 'title')
    }

    foreach ($optionalName in @('category','mitre_mapping','grouping')) {
        $optionalValue = Get-HavocProperty -InputObject $ProductFields -Name $optionalName
        if ($null -ne $optionalValue) {
            if ($optionalName -ceq 'mitre_mapping') {
                $productFieldRecord[$optionalName] = @(Get-HavocArray -Value $optionalValue | ForEach-Object { [string]$_ })
            } else {
                $productFieldRecord[$optionalName] = [string]$optionalValue
            }
        }
    }

    $productFieldRecord['classification'] = [string](Get-HavocProperty -InputObject $ProductFields -Name 'classification')
    foreach ($optionalName in @('determination','classification_reason')) {
        $optionalValue = Get-HavocProperty -InputObject $ProductFields -Name $optionalName
        if ($null -ne $optionalValue) {
            $productFieldRecord[$optionalName] = [string]$optionalValue
        }
    }
    $owner = [string](Get-HavocProperty -InputObject $ProductFields -Name 'owner')
    if (Test-HavocProtectedReference -Value $owner) {
        $productFieldRecord['owner'] = $owner
    } else {
        $productFieldRecord['owner'] = $null
        $builderGapRecords += New-TaxonomyGapRecord -GapType 'invalid_owner_protected_reference' -Description 'The product owner field was not a protected reference and was not emitted.' -ProductValue 'owner' -AffectedClaimIds $AffectedClaimIds
    }
    $productFieldRecord['comments_present'] = [bool](Get-HavocProperty -InputObject $ProductFields -Name 'comments_present')
    $closureReason = Get-HavocProperty -InputObject $ProductFields -Name 'closure_reason'
    if ($null -ne $closureReason) {
        $productFieldRecord['closure_reason'] = [string]$closureReason
    }
    $productFieldRecord['duplicate_handling'] = [string](Get-HavocProperty -InputObject $ProductFields -Name 'duplicate_handling')

    $recordAssessment = $resolution.auditor_assessment
    $recordAgreement = $resolution.agreement
    $recordDiscrepancies = @($resolution.discrepancies + @($historyDiscrepancies.ToArray()))
    if ($builderForceInsufficient -or $historyGapRecords.Count -gt 0) {
        $recordAssessment = [pscustomobject][ordered]@{
            assessment_state = 'insufficient_evidence'
            auditor_verdict = $null
            evidence_ids = @()
            reasoning = $null
        }
        $recordAgreement = 'not_assessed'
    }

    $classificationAuditIdParts = @($classificationAudit.items | ForEach-Object {
        [pscustomobject][ordered]@{
            observed_at = $_.observed_at
            value = $_.value
            actor = $_.actor
            source = $_.source
            rationale = $_.rationale
            reviewed = $_.reviewed
            evidence_ids = @($_.evidence_ids)
        }
    })
    $statusAuditIdParts = @($statusAudit.items | ForEach-Object {
        [pscustomobject][ordered]@{
            observed_at = $_.observed_at
            value = $_.value
            actor = $_.actor
            source = $_.source
            rationale = $_.rationale
            reviewed = $_.reviewed
            evidence_ids = @($_.evidence_ids)
        }
    })

    $auditIdParts = @(
        $TaxonomyVersion
        $Source
        $Field
        $Value
        $asOfText
        (ConvertTo-HavocCanonicalJson -Value $productFieldRecord)
        (ConvertTo-HavocCanonicalJson -Value $claims)
        (ConvertTo-HavocCanonicalJson -Value @($severityRecords))
        (ConvertTo-HavocCanonicalJson -Value @($classificationAuditIdParts))
        (ConvertTo-HavocCanonicalJson -Value @($statusAuditIdParts))
        (ConvertTo-HavocCanonicalJson -Value @($GroupingHistory))
        (ConvertTo-HavocCanonicalJson -Value @($recordDiscrepancies))
        (ConvertTo-HavocCanonicalJson -Value @($historyGapRecords.ToArray()))
        (ConvertTo-HavocCanonicalJson -Value $recordAssessment)
        $recordAgreement
        (ConvertTo-HavocCanonicalJson -Value @($sortedEvidence))
    )

    [pscustomobject][ordered]@{
        audit_id = Get-HavocStableId -Prefix 'tax-audit' -Parts $auditIdParts
        taxonomy_version = $TaxonomyVersion
        source = $Source
        product_fields = [pscustomobject]$productFieldRecord
        recorded_classification = $resolution.recorded_classification
        auditor_assessment = $recordAssessment
        agreement = $recordAgreement
        severity_history = @($severityRecords)
        coverage_gap_ids = @($coverageGaps)
        discrepancies = @($recordDiscrepancies)
        gap_records = @($resolution.gap_records + $builderGapRecords + @($historyGapRecords.ToArray()))
        claim_ids = @($claims)
        evidence_ids = @($sortedEvidence)
        behavior_bases = @($behaviors)
    }
}

Export-ModuleMember -Function Get-IncidentTaxonomyMap, Resolve-IncidentTaxonomyVerdict, New-HavocTaxonomyAuditRecord
