Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [object]$Default = $null
    )

    $value = Get-HavocProperty -InputObject $InputObject -Name $Name
    if ($null -eq $value) { return $Default }
    return $value
}

function Get-PropertyArray {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-PropertyValue -InputObject $InputObject -Name $Name -Default @()
    return @(Get-HavocArray -Value $value)
}

function New-StringArray {
    param([object]$Value)
    @(Get-HavocArray -Value $Value) | ForEach-Object { [string]$_ }
}

function ConvertTo-HavocBoundedScoreValue {
    param(
        [AllowNull()][object]$Value,
        [switch]$Invert,
        [string]$UnknownLabel
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return [pscustomobject][ordered]@{
            raw_value = $UnknownLabel
            normalized_value = 50
            status = 'unknown'
        }
    }

    $number = 0.0
    if (-not [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
        return [pscustomobject][ordered]@{
            raw_value = [string]$Value
            normalized_value = 50
            status = 'unknown'
        }
    }

    if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
        return [pscustomobject][ordered]@{
            raw_value = [string]$Value
            normalized_value = 50
            status = 'unknown'
        }
    }

    if ($number -lt 0) { $number = 0 }
    if ($number -gt 100) { $number = 100 }
    if ($Invert) { $number = 100 - $number }

    [pscustomobject][ordered]@{
        raw_value = $number
        normalized_value = [int][Math]::Floor($number)
        status = 'known'
    }
}

function Get-HavocNormalizedAssetClass {
    param([string]$AssetClass)

    $allowed = @(
        'ordinary',
        'tier0_identity',
        'critical_service',
        'recovery_infrastructure',
        'reachable_high_impact_asset'
    )

    foreach ($class in $allowed) {
        if ($class.Equals($AssetClass, [StringComparison]::OrdinalIgnoreCase)) {
            return $class
        }
    }

    if ([string]::IsNullOrWhiteSpace($AssetClass)) { return 'ordinary' }
    return $AssetClass.ToLowerInvariant()
}

function Test-HavocMinimumPriorityAssetClass {
    param([string]$AssetClass)

    $floorClasses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($class in @(
        'tier0_identity',
        'critical_service',
        'recovery_infrastructure',
        'reachable_high_impact_asset'
    )) {
        [void]$floorClasses.Add($class)
    }

    $floorClasses.Contains((Get-HavocNormalizedAssetClass -AssetClass $AssetClass))
}

function Get-HavocFrontierPriorityScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Item,
        [ValidateRange(0, 100)][int]$PriorityFloor = 60
    )

    $weights = [ordered]@{
        materiality = 20
        criticality = 30
        reachable_blast_radius = 10
        expected_information_gain = 30
        cost_latency = 10
    }
    $factorSpecs = @(
        @{ Name = 'materiality'; Invert = $false },
        @{ Name = 'criticality'; Invert = $false },
        @{ Name = 'reachable_blast_radius'; Invert = $false },
        @{ Name = 'expected_information_gain'; Invert = $false },
        @{ Name = 'cost_latency'; Invert = $true }
    )

    $entityRef = [string](Get-PropertyValue -InputObject $Item -Name 'entity_ref' -Default 'unknown:entity')
    $assetClass = Get-HavocNormalizedAssetClass -AssetClass ([string](Get-PropertyValue -InputObject $Item -Name 'asset_class' -Default 'ordinary'))
    $frontierItemId = [string](Get-PropertyValue -InputObject $Item -Name 'frontier_item_id' -Default (Get-HavocStableId -Prefix 'F' -Parts @($entityRef, $assetClass)))
    $missing = @()
    $factors = @()
    $weightedTotal = 0.0

    foreach ($spec in $factorSpecs) {
        $name = [string]$spec.Name
        $raw = Get-PropertyValue -InputObject $Item -Name $name -Default $null
        $bounded = ConvertTo-HavocBoundedScoreValue -Value $raw -Invert:([bool]$spec.Invert) -UnknownLabel 'unknown'
        $weight = [int]$weights[$name]
        $contribution = [Math]::Round(([double]$bounded.normalized_value * $weight / 100.0), 4)
        if ($bounded.status -eq 'unknown') { $missing += $name }
        $weightedTotal += $contribution
        $factors += [pscustomobject][ordered]@{
            name = $name
            raw_value = $bounded.raw_value
            normalized_value = [int]$bounded.normalized_value
            weight = $weight
            contribution = $contribution
            status = $bounded.status
        }
    }

    $baseScore = [int][Math]::Floor($weightedTotal)
    if ($baseScore -lt 0) { $baseScore = 0 }
    if ($baseScore -gt 100) { $baseScore = 100 }

    $floorApplies = Test-HavocMinimumPriorityAssetClass -AssetClass $assetClass
    $finalScore = $baseScore
    if ($floorApplies -and $finalScore -lt $PriorityFloor) {
        $finalScore = $PriorityFloor
    }

    [pscustomobject][ordered]@{
        score = $finalScore
        base_score = $baseScore
        bounded_minimum = 0
        bounded_maximum = 100
        priority_floor = $PriorityFloor
        priority_floor_applied = ($floorApplies -and $finalScore -gt $baseScore)
        minimum_priority_policy_applies = $floorApplies
        asset_class = $assetClass
        tie_breaker = $frontierItemId
        missing_inputs = @($missing)
        factors = @($factors)
        scoring_policy = 'materiality:20,criticality:30,reachable_blast_radius:10,expected_information_gain:30,cost_latency_inverse:10'
    }
}

function Get-HavocPivotSignature {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Pivot)

    $explicit = Get-PropertyValue -InputObject $Pivot -Name 'query_signature'
    if (-not [string]::IsNullOrWhiteSpace([string]$explicit)) {
        return [string]$explicit
    }

    $parts = @(
        (Get-PropertyValue -InputObject $Pivot -Name 'source_id' -Default 'unknown-source'),
        (Get-PropertyValue -InputObject $Pivot -Name 'entity_ref' -Default 'unknown-entity'),
        (Get-PropertyValue -InputObject $Pivot -Name 'query_family' -Default 'unknown-family'),
        (Get-PropertyValue -InputObject $Pivot -Name 'query_scope' -Default 'unknown-scope'),
        (Get-PropertyValue -InputObject $Pivot -Name 'query_approach' -Default 'unknown-approach')
    )

    ($parts | ForEach-Object { ([string]$_).Trim() }) -join '|'
}

function Test-HavocQueryRepeatAllowed {
    [CmdletBinding()]
    param(
        [object[]]$ExistingPivots = @(),
        [Parameter(Mandatory)][object]$CandidatePivot
    )

    $candidateSignature = Get-HavocPivotSignature -Pivot $CandidatePivot
    foreach ($pivot in @($ExistingPivots)) {
        if ((Get-HavocPivotSignature -Pivot $pivot) -ceq $candidateSignature) {
            return [pscustomobject][ordered]@{
                allowed = $false
                reason = 'equivalent_query_without_scope_or_approach_change'
                equivalent_to_pivot_id = [string](Get-PropertyValue -InputObject $pivot -Name 'pivot_id' -Default 'unknown:pivot')
                query_signature = $candidateSignature
            }
        }
    }

    [pscustomobject][ordered]@{
        allowed = $true
        reason = 'scope_or_approach_not_previously_observed'
        equivalent_to_pivot_id = 'not-applicable:none'
        query_signature = $candidateSignature
    }
}

function Get-HavocPivotNovelty {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Pivot)

    $checks = @(
        @{ Field = 'new_material_entities'; Reason = 'new_material_entity' },
        @{ Field = 'new_causal_nodes'; Reason = 'new_causal_node' },
        @{ Field = 'new_causal_edges'; Reason = 'new_causal_edge' },
        @{ Field = 'hypothesis_changes'; Reason = 'hypothesis_ranking_or_confidence_change' },
        @{ Field = 'new_control_gaps'; Reason = 'new_control_gap' },
        @{ Field = 'scope_changes'; Reason = 'scope_change' },
        @{ Field = 'blast_radius_changes'; Reason = 'blast_radius_change' }
    )

    $reasons = @()
    foreach ($check in $checks) {
        if (@(Get-PropertyArray -InputObject $Pivot -Name $check.Field).Count -gt 0) {
            $reasons += [string]$check.Reason
        }
    }

    [pscustomobject][ordered]@{
        score = @($reasons).Count
        reasons = $reasons
    }
}

function New-HavocSaturationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BranchId,
        [ValidateRange(1, 1000)][int]$Threshold = 3,
        [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$PolicyVersion = '1.0.0',
        [ValidateRange(1, 100000)][int]$FrontierLimit = 100
    )

    [pscustomobject][ordered]@{
        saturation_state_id = Get-HavocStableId -Prefix 'SAT' -Parts @($BranchId, $PolicyVersion)
        branch_id = $BranchId
        policy_version = $PolicyVersion
        consecutive_zero_novelty_threshold = $Threshold
        consecutive_zero_novelty_count = 0
        duplicate_pivot_count = 0
        novel_pivot_count = 0
        frontier_limit = $FrontierLimit
        frontier_count = 0
        sensitivity_stable = $false
        saturated = $false
        last_pivot_id = 'not-applicable:none'
        measured_thresholds = [pscustomobject][ordered]@{
            consecutive_zero_novelty = 0
            required_consecutive_zero_novelty = $Threshold
            unresolved_frontier = 0
            sensitivity_stable = $false
            unexamined_minimum_priority_frontier = 0
        }
        coverage_limitations = @()
        unresolved_frontier = @()
        unexamined_minimum_priority_frontier = @()
        saturation_block_reasons = @()
        hypothesis_state = 'not_assessed'
        pivot_records = @()
        last_pivot_result = $null
        frontier_reset_reason = 'not_reset'
        behavior_bases = @('configurable_project_policy')
    }
}

function Test-HavocBranchSaturation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$State)

    $count = [int](Get-PropertyValue -InputObject $State -Name 'consecutive_zero_novelty_count' -Default 0)
    $threshold = [int](Get-PropertyValue -InputObject $State -Name 'consecutive_zero_novelty_threshold' -Default 1)
    if ($threshold -lt 1) {
        throw 'consecutive_zero_novelty_threshold must be at least 1.'
    }
    $stable = [bool](Get-PropertyValue -InputObject $State -Name 'sensitivity_stable' -Default $false)
    $frontier = New-StringArray (Get-PropertyValue -InputObject $State -Name 'unresolved_frontier' -Default @())
    $minimumPriorityFrontier = New-StringArray (Get-PropertyValue -InputObject $State -Name 'unexamined_minimum_priority_frontier' -Default @())
    $frontierClear = @($frontier).Count -eq 0
    $minimumPriorityClear = @($minimumPriorityFrontier).Count -eq 0
    $blockReasons = @()
    if ($count -lt $threshold) { $blockReasons += 'consecutive_zero_novelty_below_threshold' }
    if (-not $stable) { $blockReasons += 'sensitivity_not_stable' }
    if (-not $frontierClear) { $blockReasons += 'unresolved_frontier_present' }
    if (-not $minimumPriorityClear) { $blockReasons += 'minimum_priority_frontier_unexamined' }
    $saturated = ($count -ge $threshold) -and $stable -and $frontierClear -and $minimumPriorityClear

    [pscustomobject][ordered]@{
        saturated = $saturated
        consecutive_zero_novelty = $count
        required_consecutive_zero_novelty = $threshold
        sensitivity_stable = $stable
        unresolved_frontier = $frontier
        unexamined_minimum_priority_frontier = $minimumPriorityFrontier
        saturation_block_reasons = @($blockReasons)
    }
}

function Update-HavocSaturationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$State,
        [Parameter(Mandatory)][object]$Pivot,
        [bool]$SensitivityStable = $false,
        [AllowNull()][string[]]$UnresolvedFrontier = $null,
        [AllowNull()][object]$FrontierRecord = $null,
        [string[]]$MarkExaminedMinimumPriorityFrontier = @(),
        [switch]$ResetFrontier,
        [string]$FrontierResetReason
    )

    if ($ResetFrontier -and [string]::IsNullOrWhiteSpace($FrontierResetReason)) {
        throw 'Resetting the frontier requires a recorded reason.'
    }

    $existingPivots = @((Get-PropertyValue -InputObject $State -Name 'pivot_records' -Default @()))
    $repeat = Test-HavocQueryRepeatAllowed -ExistingPivots $existingPivots -CandidatePivot $Pivot
    $pivotId = [string](Get-PropertyValue -InputObject $Pivot -Name 'pivot_id' -Default "P-$(@($existingPivots).Count + 1)")
    $duplicateCount = [int](Get-PropertyValue -InputObject $State -Name 'duplicate_pivot_count' -Default 0)
    $novelCount = [int](Get-PropertyValue -InputObject $State -Name 'novel_pivot_count' -Default 0)
    $zeroCount = [int](Get-PropertyValue -InputObject $State -Name 'consecutive_zero_novelty_count' -Default 0)

    if (-not $repeat.allowed) {
        $duplicateCount++
        $pivotResult = [pscustomobject][ordered]@{
            pivot_id = $pivotId
            duplicate_status = 'equivalent'
            equivalent_to_pivot_id = $repeat.equivalent_to_pivot_id
            novelty_score = 0
            novelty_reasons = @()
            query_signature = $repeat.query_signature
        }
    }
    else {
        $novelty = Get-HavocPivotNovelty -Pivot $Pivot
        if ($novelty.score -gt 0) {
            $novelCount++
            $zeroCount = 0
        }
        else {
            $zeroCount++
        }
        $pivotResult = [pscustomobject][ordered]@{
            pivot_id = $pivotId
            duplicate_status = 'unique'
            equivalent_to_pivot_id = 'not-applicable:none'
            novelty_score = $novelty.score
            novelty_reasons = @($novelty.reasons)
            query_signature = Get-HavocPivotSignature -Pivot $Pivot
        }
        $existingPivots += $Pivot
    }

    $existingFrontier = New-StringArray (Get-PropertyValue -InputObject $State -Name 'unresolved_frontier' -Default @())
    $replacementFrontierSupplied = $PSBoundParameters.ContainsKey('UnresolvedFrontier')
    $nextFrontier = if ($ResetFrontier) {
        @()
    }
    elseif ($replacementFrontierSupplied) {
        $replacement = New-StringArray $UnresolvedFrontier
        $replacementSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($item in @($replacement)) { [void]$replacementSet.Add($item) }
        $removedExisting = @($existingFrontier | Where-Object { -not $replacementSet.Contains([string]$_) })
        if (@($removedExisting).Count -gt 0) {
            throw 'Removing unresolved frontier items is a reset and requires -ResetFrontier with -FrontierResetReason.'
        }
        $replacement
    }
    else {
        $existingFrontier
    }

    $minimumPrioritySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in @(New-StringArray (Get-PropertyValue -InputObject $State -Name 'unexamined_minimum_priority_frontier' -Default @()))) {
        [void]$minimumPrioritySet.Add($item)
    }
    if ($PSBoundParameters.ContainsKey('FrontierRecord') -and $null -ne $FrontierRecord) {
        foreach ($item in @(New-StringArray (Get-PropertyValue -InputObject $FrontierRecord -Name 'minimum_priority_item_ids' -Default @()))) {
            [void]$minimumPrioritySet.Add($item)
        }
    }
    foreach ($item in @(New-StringArray $MarkExaminedMinimumPriorityFrontier)) {
        [void]$minimumPrioritySet.Remove($item)
    }
    $minimumPriorityValues = foreach ($item in $minimumPrioritySet) { [string]$item }
    $nextMinimumPriorityFrontier = @($minimumPriorityValues | Sort-Object)

    $next = [pscustomobject][ordered]@{
        saturation_state_id = [string](Get-PropertyValue -InputObject $State -Name 'saturation_state_id' -Default (Get-HavocStableId -Prefix 'SAT' -Parts @([string](Get-PropertyValue -InputObject $State -Name 'branch_id' -Default 'BR-unknown'), [string](Get-PropertyValue -InputObject $State -Name 'policy_version' -Default '1.0.0'))))
        branch_id = [string](Get-PropertyValue -InputObject $State -Name 'branch_id' -Default 'BR-unknown')
        policy_version = [string](Get-PropertyValue -InputObject $State -Name 'policy_version' -Default '1.0.0')
        consecutive_zero_novelty_threshold = [int](Get-PropertyValue -InputObject $State -Name 'consecutive_zero_novelty_threshold' -Default 3)
        consecutive_zero_novelty_count = $zeroCount
        duplicate_pivot_count = $duplicateCount
        novel_pivot_count = $novelCount
        frontier_limit = [int](Get-PropertyValue -InputObject $State -Name 'frontier_limit' -Default 100)
        frontier_count = @($nextFrontier).Count
        sensitivity_stable = $SensitivityStable
        saturated = $false
        last_pivot_id = $pivotId
        measured_thresholds = [pscustomobject][ordered]@{
            consecutive_zero_novelty = $zeroCount
            required_consecutive_zero_novelty = [int](Get-PropertyValue -InputObject $State -Name 'consecutive_zero_novelty_threshold' -Default 3)
            unresolved_frontier = @($nextFrontier).Count
            sensitivity_stable = $SensitivityStable
            unexamined_minimum_priority_frontier = @($nextMinimumPriorityFrontier).Count
        }
        coverage_limitations = New-StringArray (Get-PropertyValue -InputObject $State -Name 'coverage_limitations' -Default @())
        unresolved_frontier = @($nextFrontier)
        unexamined_minimum_priority_frontier = @($nextMinimumPriorityFrontier)
        saturation_block_reasons = @()
        hypothesis_state = [string](Get-PropertyValue -InputObject $State -Name 'hypothesis_state' -Default 'not_assessed')
        pivot_records = @($existingPivots)
        last_pivot_result = $pivotResult
        frontier_reset_reason = if ($ResetFrontier) { $FrontierResetReason } else { 'not_reset' }
        behavior_bases = @('configurable_project_policy')
    }

    $saturationCheck = Test-HavocBranchSaturation -State $next
    $next.saturated = $saturationCheck.saturated
    $next.saturation_block_reasons = @($saturationCheck.saturation_block_reasons)
    return $next
}

function Test-HavocEntityExpansion {
    [CmdletBinding()]
    param([string[]]$MaterialEffects = @())

    $allowed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($effect in @('hypothesis', 'scope', 'severity', 'root_cause', 'control_gap')) {
        [void]$allowed.Add($effect)
    }
    $matched = @($MaterialEffects | Where-Object { $allowed.Contains([string]$_) })

    [pscustomobject][ordered]@{
        expand = $matched.Count -gt 0
        material_effects = @($matched)
        reason = if ($matched.Count -gt 0) { 'material_effect_present' } else { 'no_material_effect_on_conclusion' }
    }
}

function Update-HavocFrontier {
    [CmdletBinding()]
    param(
        [object[]]$Items = @(),
        [ValidateRange(1, 100000)][int]$MaxItems = 100,
        [ValidateRange(0, 100)][int]$PriorityFloor = 60,
        [switch]$AsRecord
    )

    $excluded = @()
    $ranked = foreach ($item in @($Items)) {
        $effects = New-StringArray (Get-PropertyValue -InputObject $item -Name 'material_effects' -Default @())
        $expansion = Test-HavocEntityExpansion -MaterialEffects $effects
        $assetClass = Get-HavocNormalizedAssetClass -AssetClass ([string](Get-PropertyValue -InputObject $item -Name 'asset_class' -Default 'ordinary'))
        $score = Get-HavocFrontierPriorityScore -Item $item -PriorityFloor $PriorityFloor
        $minimumPriorityApplies = [bool]$score.minimum_priority_policy_applies
        $expectedGainFactor = @($score.factors | Where-Object { $_.name -eq 'expected_information_gain' })[0]
        $expectedGain = if ($expectedGainFactor.status -eq 'unknown') { [string]$expectedGainFactor.raw_value } else { [int]$expectedGainFactor.normalized_value }
        $entityRef = [string](Get-PropertyValue -InputObject $item -Name 'entity_ref' -Default 'unknown:entity')
        $frontierItemId = [string](Get-PropertyValue -InputObject $item -Name 'frontier_item_id' -Default (Get-HavocStableId -Prefix 'F' -Parts @($entityRef, $assetClass, ([string]$expectedGain), (@($effects) -join '|'))))
        if (-not $expansion.expand -and -not $minimumPriorityApplies) {
            $excluded += [pscustomobject][ordered]@{
                frontier_item_id = $frontierItemId
                entity_ref = $entityRef
                asset_class = $assetClass
                material_effects = @($effects)
                reason = $expansion.reason
            }
            continue
        }

        [pscustomobject][ordered]@{
            frontier_item_id = $frontierItemId
            entity_ref = $entityRef
            expected_information_gain = $expectedGain
            asset_class = $assetClass
            material_effects = @($expansion.material_effects)
            input_effects = @($effects)
            non_material_effects = @($effects | Where-Object { $_ -notin @($expansion.material_effects) })
            material_effects_status = if ($expansion.expand) { 'known_material' } elseif (@($effects).Count -eq 0) { 'unknown' } else { 'non_material_recorded_for_minimum_priority' }
            priority = [int]$score.score
            priority_score = $score
            priority_floor_applied = [bool]$score.priority_floor_applied
            minimum_priority_policy_applies = $minimumPriorityApplies
            priority_rationale = if ($score.priority_floor_applied) { "Applied minimum-priority asset floor $PriorityFloor for $assetClass." } else { 'Deterministic weighted frontier scoring policy determines priority.' }
        }
    }

    $sorted = @($ranked | Sort-Object -Property @{ Expression = 'priority'; Descending = $true }, @{ Expression = 'frontier_item_id'; Descending = $false })
    $minimumPriority = @($sorted | Where-Object { [bool]$_.minimum_priority_policy_applies })
    $ordinary = @($sorted | Where-Object { -not [bool]$_.minimum_priority_policy_applies })
    $ordinarySlots = $MaxItems - @($minimumPriority).Count
    if ($ordinarySlots -lt 0) { $ordinarySlots = 0 }
    $included = @(@($minimumPriority) + @($ordinary | Select-Object -First $ordinarySlots) |
        Sort-Object -Property @{ Expression = 'priority'; Descending = $true }, @{ Expression = 'frontier_item_id'; Descending = $false })
    $remaining = @($ordinary | Select-Object -Skip $ordinarySlots)
    $record = [pscustomobject][ordered]@{
        items = @($included)
        original_count = @($sorted).Count
        included_count = @($included).Count
        truncated_count = @($remaining).Count
        remaining_item_ids = @($remaining | ForEach-Object { [string]$_.frontier_item_id })
        minimum_priority_item_ids = @($minimumPriority | ForEach-Object { [string]$_.frontier_item_id })
        truncation_block_reasons = @($minimumPriority | ForEach-Object { "minimum_priority_item_preserved:$([string]$_.frontier_item_id)" })
        max_items_exceeded_for_protected_items = (@($included).Count -gt $MaxItems)
        excluded_items = @($excluded)
    }

    return $record
}

function Test-HavocSensitivityStability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Baseline,
        [Parameter(Mandatory)][object]$WithoutLeadingEvidence,
        [Parameter(Mandatory)][object]$WithLowReliabilityDowngraded
    )

    function Get-ConclusionSignature([object]$Value) {
        $ranking = (New-StringArray (Get-PropertyValue -InputObject $Value -Name 'ranking' -Default @())) -join '>'
        @(
            (Get-PropertyValue -InputObject $Value -Name 'leading_hypothesis_id' -Default 'unknown'),
            $ranking,
            (Get-PropertyValue -InputObject $Value -Name 'confidence' -Default 'unknown'),
            (Get-PropertyValue -InputObject $Value -Name 'severity' -Default 'unknown'),
            (Get-PropertyValue -InputObject $Value -Name 'scope_hash' -Default 'unknown'),
            (Get-PropertyValue -InputObject $Value -Name 'root_cause_hash' -Default 'unknown')
        ) -join '|'
    }

    $baselineSignature = Get-ConclusionSignature $Baseline
    $withoutSignature = Get-ConclusionSignature $WithoutLeadingEvidence
    $downgradeSignature = Get-ConclusionSignature $WithLowReliabilityDowngraded

    [pscustomobject][ordered]@{
        stable = ($baselineSignature -ceq $withoutSignature) -and ($baselineSignature -ceq $downgradeSignature)
        baseline_signature = $baselineSignature
        without_leading_evidence_signature = $withoutSignature
        low_reliability_downgraded_signature = $downgradeSignature
    }
}

function New-HavocStopReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BranchId,
        [Parameter(Mandatory)]
        [ValidateSet('saturation', 'coverage_boundary', 'quota', 'risk_budget', 'hard_cap')]
        [string]$StopReason,
        [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
        [string]$PolicyVersion = '1.0.0',
        [string]$Actor = 'havoc-saturation-kernel',
        [hashtable]$ConfiguredValues = @{},
        [hashtable]$Consumption = @{},
        [string[]]$UnresolvedFrontier = @(),
        [string]$HypothesisState = 'not_assessed',
        [string[]]$CoverageLimitations = @(),
        [string]$MissingSource,
        [string[]]$AffectedClaimIds = @(),
        [string]$FollowUp,
        [switch]$CircuitBreakerTripped,
        [string]$LastSuccessfulOperation = 'not-applicable:none',
        [AllowNull()][object]$SaturationState = $null,
        [Parameter(Mandatory)][object]$Now
    )

    $stoppedAt = Format-HavocTimestamp -Value (ConvertTo-HavocUtcTimestamp -Value $Now)

    if ($StopReason -eq 'coverage_boundary') {
        if ([string]::IsNullOrWhiteSpace($MissingSource) -or
            @(New-StringArray $AffectedClaimIds).Count -eq 0 -or
            [string]::IsNullOrWhiteSpace($FollowUp)) {
            throw 'coverage_boundary stop requires missing source, affected claims, and follow-up.'
        }
    }
    if ($StopReason -eq 'hard_cap' -and -not $CircuitBreakerTripped) {
        throw 'hard_cap is a circuit breaker and cannot be emitted as the primary saturation rule.'
    }
    if ($StopReason -eq 'saturation') {
        if ($null -eq $SaturationState) {
            throw 'saturation stop requires a saturation state.'
        }
        if (@(New-StringArray $UnresolvedFrontier).Count -gt 0) {
            throw 'saturation stop cannot include unresolved frontier items.'
        }
        $saturationCheck = Test-HavocBranchSaturation -State $SaturationState
        if (-not $saturationCheck.saturated) {
            throw 'saturation stop requires a saturated state with stable sensitivity and no unresolved frontier.'
        }
    }

    $stopCause = switch ($StopReason) {
        'saturation' { 'evidence_sufficient' }
        'coverage_boundary' { 'coverage_boundary' }
        'quota' { 'quota' }
        'risk_budget' { 'budget_exhausted' }
        'hard_cap' { 'circuit_breaker' }
    }

    $gapRecords = @()
    $gapIds = @()
    if ($StopReason -eq 'coverage_boundary') {
        $gapId = "GAP-$BranchId-coverage"
        $gapIds += $gapId
        $gapRecords += [pscustomobject][ordered]@{
            gap_id = $gapId
            gap_type = 'coverage_boundary'
            description = "Coverage boundary reached because source $MissingSource was unavailable."
            basis = "missing_source:$MissingSource"
            evidence_ids = @()
            affected_claim_ids = New-StringArray $AffectedClaimIds
            affected_section_ids = @('coverage_and_limitations', 'competing_hypotheses', 'stop_and_errors')
            follow_up = $FollowUp
            frontier = (New-StringArray $UnresolvedFrontier) -join ','
            frontier_mapping_rationale = 'Unresolved frontier depends on the missing source before the affected claims can be closed.'
            behavior_bases = @('configurable_project_policy', 'explicit_gap')
        }
    }

    $configured = [pscustomobject]@{}
    foreach ($key in $ConfiguredValues.Keys) {
        $configured | Add-Member -NotePropertyName ([string]$key) -NotePropertyValue $ConfiguredValues[$key]
    }
    $consumed = [pscustomobject]@{}
    foreach ($key in $Consumption.Keys) {
        $consumed | Add-Member -NotePropertyName ([string]$key) -NotePropertyValue $Consumption[$key]
    }
    $restartConditions = if ($StopReason -eq 'saturation') {
        @('Reopen only if new material evidence, scope, hypothesis, control-gap, or coverage information appears.')
    }
    else {
        @('Resolve the recorded boundary or budget condition and rerun the affected branch.')
    }

    [pscustomobject][ordered]@{
        stop_receipt_id = "STOP-$BranchId"
        branch_id = $BranchId
        stop_cause = $stopCause
        audit_stop_cause = $stopCause
        domain_stop_reason = $StopReason
        trigger = if ($StopReason -eq 'saturation') { 'configured_saturation_criteria_met' } else { "branch_stopped_for_$StopReason" }
        stopped_at = $stoppedAt
        actor = $Actor
        policy_version = $PolicyVersion
        configured_values = $configured
        consumption = $consumed
        coverage_summary = if (@(New-StringArray $CoverageLimitations).Count -gt 0) { (New-StringArray $CoverageLimitations) -join '; ' } else { 'No material coverage limitations recorded for this branch.' }
        unresolved_material_frontier = @(New-StringArray $UnresolvedFrontier)
        duplicate_lineage_groups = @()
        novel_evidence_summary = if ($StopReason -eq 'saturation') { 'Configured saturation criteria were met after duplicate detection and novelty scoring.' } else { "Branch stopped for $StopReason before saturation." }
        hypothesis_stability = $HypothesisState
        circuit_breaker_state = if ($CircuitBreakerTripped) { 'tripped: hard cap circuit breaker stopped runaway retrieval.' } else { 'not_tripped' }
        last_successful_operation = $LastSuccessfulOperation
        gap_ids = @($gapIds)
        error_ids = @()
        restart_conditions = @($restartConditions)
        gap_records = @($gapRecords)
        measured_thresholds = [pscustomobject][ordered]@{
            stop_reason = $StopReason
            audit_stop_cause = $stopCause
            consecutive_zero_novelty = if ($null -ne $SaturationState) { [int](Get-PropertyValue -InputObject $SaturationState -Name 'consecutive_zero_novelty_count' -Default 0) } else { 0 }
            required_consecutive_zero_novelty = if ($null -ne $SaturationState) { [int](Get-PropertyValue -InputObject $SaturationState -Name 'consecutive_zero_novelty_threshold' -Default 1) } else { 1 }
            sensitivity_stable = if ($null -ne $SaturationState) { [bool](Get-PropertyValue -InputObject $SaturationState -Name 'sensitivity_stable' -Default $false) } else { $false }
            unresolved_frontier = @(New-StringArray $UnresolvedFrontier).Count
        }
        unresolved_frontier = @(New-StringArray $UnresolvedFrontier)
        hypothesis_state = $HypothesisState
        coverage_limitations = @(New-StringArray $CoverageLimitations)
        behavior_bases = @('configurable_project_policy')
    }
}

function New-HavocSaturationKernelRecord {
    [CmdletBinding()]
    param(
        [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
        [string]$SchemaVersion = '1.0.0',
        [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
        [string]$PolicyVersion = '1.0.0',
        [object[]]$Branches = @(),
        [object[]]$FrontierItems = @(),
        [object[]]$PivotRecords = @(),
        [Parameter(Mandatory)][object]$SaturationState,
        [Parameter(Mandatory)][object]$StopReceipt
    )

    $state = [pscustomobject][ordered]@{
        saturation_state_id = [string](Get-PropertyValue -InputObject $SaturationState -Name 'saturation_state_id' -Default (Get-HavocStableId -Prefix 'SAT' -Parts @([string](Get-PropertyValue -InputObject $SaturationState -Name 'branch_id' -Default 'BR-unknown'), $PolicyVersion)))
        branch_id = [string](Get-PropertyValue -InputObject $SaturationState -Name 'branch_id' -Default 'BR-unknown')
        policy_version = [string](Get-PropertyValue -InputObject $SaturationState -Name 'policy_version' -Default $PolicyVersion)
        consecutive_zero_novelty_threshold = [int](Get-PropertyValue -InputObject $SaturationState -Name 'consecutive_zero_novelty_threshold' -Default 1)
        consecutive_zero_novelty_count = [int](Get-PropertyValue -InputObject $SaturationState -Name 'consecutive_zero_novelty_count' -Default 0)
        duplicate_pivot_count = [int](Get-PropertyValue -InputObject $SaturationState -Name 'duplicate_pivot_count' -Default 0)
        novel_pivot_count = [int](Get-PropertyValue -InputObject $SaturationState -Name 'novel_pivot_count' -Default 0)
        frontier_limit = [int](Get-PropertyValue -InputObject $SaturationState -Name 'frontier_limit' -Default 1)
        frontier_count = [int](Get-PropertyValue -InputObject $SaturationState -Name 'frontier_count' -Default 0)
        sensitivity_stable = [bool](Get-PropertyValue -InputObject $SaturationState -Name 'sensitivity_stable' -Default $false)
        saturated = [bool](Get-PropertyValue -InputObject $SaturationState -Name 'saturated' -Default $false)
        last_pivot_id = [string](Get-PropertyValue -InputObject $SaturationState -Name 'last_pivot_id' -Default 'not-applicable:none')
        measured_thresholds = Get-PropertyValue -InputObject $SaturationState -Name 'measured_thresholds' -Default ([pscustomobject][ordered]@{
            consecutive_zero_novelty = 0
            required_consecutive_zero_novelty = 1
            unresolved_frontier = 0
            sensitivity_stable = $false
        })
        coverage_limitations = @(New-StringArray (Get-PropertyValue -InputObject $SaturationState -Name 'coverage_limitations' -Default @()))
        unresolved_frontier = @(New-StringArray (Get-PropertyValue -InputObject $SaturationState -Name 'unresolved_frontier' -Default @()))
        hypothesis_state = [string](Get-PropertyValue -InputObject $SaturationState -Name 'hypothesis_state' -Default 'not_assessed')
        behavior_bases = @(New-StringArray (Get-PropertyValue -InputObject $SaturationState -Name 'behavior_bases' -Default @('configurable_project_policy')))
    }

    [pscustomobject][ordered]@{
        schema_version = $SchemaVersion
        policy_version = $PolicyVersion
        branches = @($Branches)
        frontier_items = @($FrontierItems)
        pivot_records = @($PivotRecords)
        saturation_state = $state
        stop_receipt = $StopReceipt
    }
}

Export-ModuleMember -Function @(
    'New-HavocSaturationState',
    'Get-HavocPivotSignature',
    'Test-HavocQueryRepeatAllowed',
    'Get-HavocPivotNovelty',
    'Update-HavocSaturationState',
    'Test-HavocEntityExpansion',
    'Get-HavocFrontierPriorityScore',
    'Update-HavocFrontier',
    'Test-HavocSensitivityStability',
    'Test-HavocBranchSaturation',
    'New-HavocStopReceipt',
    'New-HavocSaturationKernelRecord'
)
