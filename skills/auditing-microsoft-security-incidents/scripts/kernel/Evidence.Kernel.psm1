Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:LikelihoodBands = @(
    'highly_unlikely',
    'unlikely',
    'roughly_even',
    'likely',
    'highly_likely',
    'not_assessed'
)
$script:AnalyticConfidenceBands = @('low', 'moderate', 'high', 'not_assessed')
$script:ReliabilityGrades = @('A', 'B', 'C', 'D', 'E', 'F', 'unknown')

function New-KernelDecision {
    param(
        [bool]$Valid,
        [string]$ReasonCode,
        [string]$RecordType = 'unknown',
        [hashtable]$Extra = @{}
    )
    $ordered = [ordered]@{
        valid = $Valid
        reason_code = $ReasonCode
        record_type = $RecordType
    }
    foreach ($key in $Extra.Keys) {
        $ordered[$key] = $Extra[$key]
    }
    [pscustomobject]$ordered
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    return Get-HavocProperty -InputObject $InputObject -Name $Name
}

function Get-BaseLineageKey {
    param([Parameter(Mandatory)]$EvidenceItem)
    $lineage = Get-PropertyValue $EvidenceItem 'source_lineage'
    if ($null -eq $lineage) {
        $lineage = Get-PropertyValue $EvidenceItem 'lineage'
    }
    $canonical = Get-PropertyValue $lineage 'canonical_upstream_ref'
    if (-not [string]::IsNullOrWhiteSpace([string]$canonical)) {
        return [string]$canonical
    }
    $copyOf = Get-PropertyValue $lineage 'copy_of_evidence_id'
    if (-not [string]::IsNullOrWhiteSpace([string]$copyOf) -and [string]$copyOf -cne 'not-applicable:none') {
        return "copy-of:$copyOf"
    }
    $sourceId = [string](Get-PropertyValue $EvidenceItem 'source_id')
    $rawRef = [string](Get-PropertyValue $EvidenceItem 'raw_ref')
    if ([string]::IsNullOrWhiteSpace($rawRef)) {
        $rawRef = [string](Get-PropertyValue (Get-PropertyValue $EvidenceItem 'output_projection') 'raw_ref')
    }
    if ([string]::IsNullOrWhiteSpace($sourceId)) { $sourceId = 'unknown-source' }
    if ([string]::IsNullOrWhiteSpace($rawRef)) { $rawRef = [string](Get-PropertyValue $EvidenceItem 'evidence_id') }
    "$sourceId|$rawRef"
}

function Resolve-LineageKey {
    param(
        [Parameter(Mandatory)]$EvidenceItem,
        [Parameter(Mandatory)]$ItemsById
    )
    $current = $EvidenceItem
    $visited = [System.Collections.Generic.List[string]]::new()
    $visitedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    while ($null -ne $current) {
        $currentId = [string](Get-PropertyValue $current 'evidence_id')
        if ([string]::IsNullOrWhiteSpace($currentId)) {
            $currentId = [string](Get-PropertyValue $current 'record_id')
        }
        if ([string]::IsNullOrWhiteSpace($currentId)) {
            return Get-BaseLineageKey -EvidenceItem $current
        }
        if ($visitedSet.Contains($currentId)) {
            [string[]]$cycleIds = @($visited)
            [Array]::Sort($cycleIds, [System.StringComparer]::Ordinal)
            return 'copy-cycle:' + ($cycleIds -join '|')
        }
        $visited.Add($currentId)
        [void]$visitedSet.Add($currentId)

        $lineage = Get-PropertyValue $current 'source_lineage'
        if ($null -eq $lineage) {
            $lineage = Get-PropertyValue $current 'lineage'
        }
        $copyOf = [string](Get-PropertyValue $lineage 'copy_of_evidence_id')
        if ([string]::IsNullOrWhiteSpace($copyOf) -or $copyOf -ceq 'not-applicable:none') {
            return Get-BaseLineageKey -EvidenceItem $current
        }
        if (-not $ItemsById.ContainsKey($copyOf)) {
            return "copy-of:$copyOf"
        }
        $current = $ItemsById[$copyOf]
    }

    return Get-BaseLineageKey -EvidenceItem $EvidenceItem
}

function Get-IndependentCorroboration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$EvidenceItem
    )
    begin { $items = New-Object System.Collections.Generic.List[object] }
    process {
        foreach ($item in $EvidenceItem) { $items.Add($item) }
    }
    end {
        $itemsById = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        foreach ($item in $items) {
            $id = [string](Get-PropertyValue $item 'evidence_id')
            if ([string]::IsNullOrWhiteSpace($id)) { $id = [string](Get-PropertyValue $item 'record_id') }
            if (-not [string]::IsNullOrWhiteSpace($id) -and -not $itemsById.ContainsKey($id)) {
                $itemsById[$id] = $item
            }
        }
        $groupsByKey = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]]::new([System.StringComparer]::Ordinal)
        $groupKeys = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $items) {
            $key = Resolve-LineageKey -EvidenceItem $item -ItemsById $itemsById
            if (-not $groupsByKey.ContainsKey($key)) {
                $groupsByKey[$key] = New-Object System.Collections.Generic.List[string]
                $groupKeys.Add($key)
            }
            $id = [string](Get-PropertyValue $item 'evidence_id')
            if ([string]::IsNullOrWhiteSpace($id)) { $id = [string](Get-PropertyValue $item 'record_id') }
            if ([string]::IsNullOrWhiteSpace($id)) { $id = "item-$($groupsByKey[$key].Count + 1)" }
            $groupsByKey[$key].Add($id)
        }
        $groups = foreach ($key in $groupKeys) {
            [pscustomobject][ordered]@{
                lineage_key = $key
                evidence_ids = @($groupsByKey[$key])
                observation_count = $groupsByKey[$key].Count
                independent_count = 1
            }
        }
        [pscustomobject][ordered]@{
            independent_count = @($groups).Count
            observation_count = $items.Count
            duplicate_count = [Math]::Max(0, $items.Count - @($groups).Count)
            groups = @($groups)
        }
    }
}

function Test-ClaimCitation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Claim,
        [string[]]$LedgerEvidenceIds = @()
    )
    $projection = Get-PropertyValue $Claim 'claim_projection'
    $material = [bool](Get-PropertyValue $Claim 'material')
    $evidenceIds = @()
    if ($null -ne $projection) {
        $evidenceIds = @(Get-HavocArray -Value (Get-PropertyValue $projection 'evidence_ids'))
    }
    if ($material -and $evidenceIds.Count -eq 0) {
        return New-KernelDecision -Valid:$false -ReasonCode 'material_claim_missing_evidence_citation' -RecordType 'claim_citation'
    }
    if ($evidenceIds.Count -gt 0) {
        $ledgerSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($ledgerId in @(Get-HavocArray -Value $LedgerEvidenceIds)) {
            [void]$ledgerSet.Add([string]$ledgerId)
        }
        $missing = @($evidenceIds | Where-Object { -not $ledgerSet.Contains([string]$_) })
        if ($missing.Count -gt 0) {
            return New-KernelDecision -Valid:$false -ReasonCode 'claim_cites_unknown_evidence' -RecordType 'claim_citation' -Extra @{ missing_evidence_ids = $missing }
        }
    }
    New-KernelDecision -Valid:$true -ReasonCode 'claim_citation_valid' -RecordType 'claim_citation'
}

function Test-EvidenceKernelRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Record,
        [string[]]$LedgerEvidenceIds = @()
    )
    if ($null -eq $Record) {
        return New-KernelDecision -Valid:$false -ReasonCode 'record_null' -RecordType 'unknown'
    }
    $recordType = [string](Get-PropertyValue $Record 'record_type')
    switch ($recordType) {
        'source_lineage' {
            $invalidRefs = [System.Collections.Generic.List[string]]::new()
            foreach ($step in @(Get-HavocArray -Value (Get-PropertyValue $Record 'transformation_chain'))) {
                foreach ($name in @('input_ref', 'output_ref')) {
                    $ref = [string](Get-PropertyValue $step $name)
                    if (-not (Test-HavocProtectedReference -Value $ref)) {
                        $invalidRefs.Add($name)
                    }
                }
            }
            if ($invalidRefs.Count -gt 0) {
                return New-KernelDecision -Valid:$false -ReasonCode 'protected_reference_invalid' -RecordType $recordType -Extra @{ invalid_reference_fields = @($invalidRefs) }
            }
            return New-KernelDecision -Valid:$true -ReasonCode 'source_lineage_valid' -RecordType $recordType
        }
        'source_confidence' {
            $grade = [string](Get-PropertyValue $Record 'reliability_grade')
            $confidence = [string](Get-PropertyValue $Record 'analytic_confidence')
            if ($grade -notin $script:ReliabilityGrades) {
                return New-KernelDecision -Valid:$false -ReasonCode 'source_reliability_grade_invalid' -RecordType $recordType
            }
            if ($confidence -notin $script:AnalyticConfidenceBands) {
                return New-KernelDecision -Valid:$false -ReasonCode 'analytic_confidence_invalid' -RecordType $recordType
            }
            return New-KernelDecision -Valid:$true -ReasonCode 'source_confidence_valid' -RecordType $recordType
        }
        'claim_citation' {
            return Test-ClaimCitation -Claim $Record -LedgerEvidenceIds $LedgerEvidenceIds
        }
        'evidence_item' {
            $controlFields = @('instruction', 'authorization_scope', 'authorization', 'approved_purpose', 'endpoint_override', 'request_policy_override')
            if ([string](Get-PropertyValue $Record 'source_type') -ceq 'untrusted_text') {
                $propertyNames = if ($Record -is [System.Collections.IDictionary]) {
                    @($Record.Keys | ForEach-Object { [string]$_ })
                }
                else {
                    @($Record.PSObject.Properties.Name)
                }
                $propertySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($propertyName in $propertyNames) {
                    [void]$propertySet.Add($propertyName)
                }
                $present = @($controlFields | Where-Object { $propertySet.Contains($_) })
                if ($present.Count -gt 0) {
                    return New-KernelDecision -Valid:$false -ReasonCode 'untrusted_evidence_contains_control_fields' -RecordType $recordType -Extra @{ control_fields = $present }
                }
            }
            $kind = [string](Get-PropertyValue $Record 'evidence_kind')
            $role = [string](Get-PropertyValue $Record 'evidence_role')
            $direction = [string](Get-PropertyValue $Record 'support_direction')
            if ($kind -ceq 'missing_telemetry' -and ($direction -cne 'gap' -or $role -cne 'coverage_gap')) {
                return New-KernelDecision -Valid:$false -ReasonCode 'missing_telemetry_is_gap_not_support' -RecordType $recordType
            }
            $assessment = Get-PropertyValue $Record 'analytic_assessment'
            $likelihood = [string](Get-PropertyValue $assessment 'likelihood')
            $confidence = [string](Get-PropertyValue $assessment 'analytic_confidence')
            if ($likelihood -notin $script:LikelihoodBands) {
                return New-KernelDecision -Valid:$false -ReasonCode 'likelihood_invalid' -RecordType $recordType
            }
            if ($confidence -notin $script:AnalyticConfidenceBands) {
                return New-KernelDecision -Valid:$false -ReasonCode 'analytic_confidence_invalid' -RecordType $recordType
            }
            if ($kind -ceq 'threat_intelligence_match' -and $likelihood -ceq 'highly_likely') {
                return New-KernelDecision -Valid:$false -ReasonCode 'threat_intelligence_lead_requires_local_corroboration' -RecordType $recordType
            }
            return New-KernelDecision -Valid:$true -ReasonCode 'evidence_item_valid' -RecordType $recordType
        }
        default {
            return New-KernelDecision -Valid:$false -ReasonCode 'record_type_unknown' -RecordType $recordType
        }
    }
}

function Get-EvidenceLikelihoodAssessment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$EvidenceItem)
    $items = @($EvidenceItem)
    $threatIntelItems = @($items | Where-Object {
        [string](Get-PropertyValue $_ 'evidence_kind') -ceq 'threat_intelligence_match' -or
        [string](Get-PropertyValue $_ 'source_type') -ceq 'threat_intelligence'
    })
    if ($items.Count -gt 0 -and $threatIntelItems.Count -eq $items.Count) {
        return [pscustomobject][ordered]@{
            likelihood = 'likely'
            analytic_confidence = 'low'
            requires_local_corroboration = $true
            reason_code = 'threat_intelligence_lead_requires_local_corroboration'
        }
    }
    $hasHighQualityLocal = @($items | Where-Object {
        [string](Get-PropertyValue $_ 'evidence_kind') -ne 'threat_intelligence_match' -and
        [string](Get-PropertyValue $_ 'source_type') -ne 'threat_intelligence' -and
        [string](Get-PropertyValue $_ 'support_direction') -eq 'supporting'
    }).Count -gt 0
    [pscustomobject][ordered]@{
        likelihood = if ($hasHighQualityLocal) { 'likely' } else { 'not_assessed' }
        analytic_confidence = if ($hasHighQualityLocal) { 'moderate' } else { 'not_assessed' }
        requires_local_corroboration = -not $hasHighQualityLocal
        reason_code = if ($hasHighQualityLocal) { 'local_evidence_assessed' } else { 'insufficient_local_evidence' }
    }
}

Export-ModuleMember -Function Get-IndependentCorroboration, Test-ClaimCitation, Test-EvidenceKernelRecord, Get-EvidenceLikelihoodAssessment
