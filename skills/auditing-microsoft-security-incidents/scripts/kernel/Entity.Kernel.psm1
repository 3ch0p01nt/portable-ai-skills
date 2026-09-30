Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:StrongIdentifierKinds = @(
    'entra_object_id',
    'device_id',
    'sid',
    'mde_machine_id',
    'certificate_thumbprint',
    'application_object_id',
    'service_principal_object_id',
    'hardware_identity',
    'workload_identity'
)

function Get-HavocIdentifierStrength {
    param([Parameter(Mandatory)] [object] $Identifier)

    $kind = [string](Get-HavocProperty -InputObject $Identifier -Name 'identifier_kind')
    $derived = if ($script:StrongIdentifierKinds -ccontains $kind) { 'strong' } else { 'weak' }
    $declared = [string](Get-HavocProperty -InputObject $Identifier -Name 'strength')
    if ($derived -eq 'strong' -and $declared -ceq 'weak') { return 'weak' }
    return $derived
}

function ConvertTo-HavocIdentifierEvidenceRecord {
    param([Parameter(Mandatory)] [object] $Identifier)

    $kind = [string](Get-HavocProperty -InputObject $Identifier -Name 'identifier_kind')
    $protectedRef = [string](Get-HavocProperty -InputObject $Identifier -Name 'protected_identifier_ref')
    if (-not (Test-HavocProtectedReference -Value $protectedRef)) {
        throw 'Identifier evidence requires a protectedIdentifierRef compatible with protectedReference.'
    }

    $record = [ordered]@{
        identifier_kind = $kind
        strength = Get-HavocIdentifierStrength -Identifier $Identifier
        protected_identifier_ref = $protectedRef
        evidence_ids = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $Identifier -Name 'evidence_ids'))
    }
    $normalizedDigest = [string](Get-HavocProperty -InputObject $Identifier -Name 'normalized_digest')
    if ([string]::IsNullOrWhiteSpace($normalizedDigest)) {
        $normalizedValue = [string](Get-HavocProperty -InputObject $Identifier -Name 'normalized_value')
        if (-not [string]::IsNullOrWhiteSpace($normalizedValue)) {
            $normalizedDigest = Get-HavocSha256Hex -Text $normalizedValue
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($normalizedDigest)) { $record.normalized_digest = $normalizedDigest }
    $validityWindow = Get-HavocProperty -InputObject $Identifier -Name 'validity_window'
    if ($null -ne $validityWindow) { $record.validity_window = $validityWindow }
    return [pscustomobject]$record
}

function ConvertTo-HavocIdentifierEvidenceArray {
    param([AllowNull()] [object[]] $Identifiers)

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($identifier in @(Get-HavocArray -Value $Identifiers)) {
        $records.Add((ConvertTo-HavocIdentifierEvidenceRecord -Identifier $identifier))
    }
    return @($records.ToArray())
}

function Get-HavocEvidenceIdsFromIdentifiers {
    param([AllowNull()] [object[]] $Identifiers)

    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($identifier in @(Get-HavocArray -Value $Identifiers)) {
        $evidence = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $identifier -Name 'evidence_ids'))
        foreach ($id in $evidence) {
            if ($null -ne $id -and -not $ids.Contains([string]$id)) { $ids.Add([string]$id) }
        }
    }
    return @($ids.ToArray())
}

function Get-HavocStrongIdentifierAssessment {
    param([AllowNull()] [object[]] $Identifiers)

    $byKind = @{}
    foreach ($identifier in @(Get-HavocArray -Value $Identifiers)) {
        if ((Get-HavocIdentifierStrength -Identifier $identifier) -ne 'strong') { continue }
        $kind = [string](Get-HavocProperty -InputObject $identifier -Name 'identifier_kind')
        if (-not $byKind.ContainsKey($kind)) {
            $byKind[$kind] = [System.Collections.Generic.List[object]]::new()
        }
        $byKind[$kind].Add($identifier)
    }

    $conflicts = [System.Collections.Generic.List[object]]::new()
    $unresolved = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in $byKind.Keys) {
        $items = @($byKind[$kind].ToArray())
        $digests = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $refs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $missingDigestCount = 0
        foreach ($item in $items) {
            $digest = [string](Get-HavocProperty -InputObject $item -Name 'normalized_digest')
            if (-not [string]::IsNullOrWhiteSpace($digest)) {
                [void]$digests.Add($digest)
            } else {
                $missingDigestCount++
            }
            $protectedRef = [string](Get-HavocProperty -InputObject $item -Name 'protected_identifier_ref')
            if (-not [string]::IsNullOrWhiteSpace($protectedRef)) { [void]$refs.Add($protectedRef) }
        }

        if ($digests.Count -gt 1) {
            foreach ($item in $items) { $conflicts.Add($item) }
            continue
        }

        if ($missingDigestCount -gt 0 -and $refs.Count -gt 1) {
            foreach ($item in $items) { $unresolved.Add($item) }
        }
    }

    return [pscustomobject]@{
        contradictions = @($conflicts.ToArray())
        unresolved = @($unresolved.ToArray())
    }
}

function New-HavocIdentifierEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $IdentifierKind,
        [Parameter(Mandatory)] [ValidateSet('strong','weak')] [string] $Strength,
        [string] $ProtectedIdentifierRef,
        [string] $RawIdentifier,
        [string] $NormalizedValue,
        [string] $NormalizedDigest,
        [object] $ValidityWindow,
        [string[]] $EvidenceIds = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($RawIdentifier)) {
        throw 'Raw identifiers must not be emitted inline; use ProtectedIdentifierRef and optional normalized comparison fields.'
    }
    if ([string]::IsNullOrWhiteSpace($ProtectedIdentifierRef) -or -not (Test-HavocProtectedReference -Value $ProtectedIdentifierRef)) {
        throw 'ProtectedIdentifierRef must be an opaque non-bearer protectedReference locator.'
    }

    if ([string]::IsNullOrWhiteSpace($NormalizedDigest) -and -not [string]::IsNullOrWhiteSpace($NormalizedValue)) {
        $NormalizedDigest = Get-HavocSha256Hex -Text $NormalizedValue
    }

    $inputRecord = [pscustomobject]@{
        identifier_kind = $IdentifierKind
        strength = $Strength
        protected_identifier_ref = $ProtectedIdentifierRef
        evidence_ids = @($EvidenceIds)
    }
    if (-not [string]::IsNullOrWhiteSpace($NormalizedDigest)) { $inputRecord | Add-Member -NotePropertyName normalized_digest -NotePropertyValue $NormalizedDigest }
    if ($null -ne $ValidityWindow) { $inputRecord | Add-Member -NotePropertyName validity_window -NotePropertyValue $ValidityWindow }
    return ConvertTo-HavocIdentifierEvidenceRecord -Identifier $inputRecord
}

function New-HavocEntityResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResolutionId,
        [Parameter(Mandatory)] [ValidateSet('merge','split','distinct')] [string] $Decision,
        [Parameter(Mandatory)] [ValidateSet('low','moderate','high','not_assessed')] [string] $Confidence,
        [string[]] $SourceEntityIds = @(),
        [string] $ResultEntityId,
        [object[]] $BasisIdentifiers = @(),
        [object[]] $ContradictoryIdentifiers = @(),
        [string[]] $ProvenanceEvidenceIds = @(),
        [switch] $Reversible,
        [string] $ReversalOfResolutionId,
        [string[]] $Limitations = @(),
        [string[]] $ClaimIds = @(),
        [string[]] $EvidenceIds = @(),
        [string[]] $GapIds = @(),
        [string[]] $ErrorIds = @(),
        [string[]] $BehaviorBases = @('configurable_project_policy')
    )

    $basis = ConvertTo-HavocIdentifierEvidenceArray -Identifiers $BasisIdentifiers
    $contradictions = ConvertTo-HavocIdentifierEvidenceArray -Identifiers $ContradictoryIdentifiers
    $record = [ordered]@{
        resolution_id = $ResolutionId
        decision = $Decision
        confidence = $Confidence
        source_entity_ids = @($SourceEntityIds)
        basis_identifiers = @($basis)
        contradictory_identifiers = @($contradictions)
        provenance_evidence_ids = @($ProvenanceEvidenceIds)
        reversible = [bool]$Reversible
        claim_ids = @($ClaimIds)
        evidence_ids = @($EvidenceIds)
        gap_ids = @($GapIds)
        error_ids = @($ErrorIds)
        behavior_bases = @($BehaviorBases)
    }
    if (-not [string]::IsNullOrWhiteSpace($ResultEntityId)) { $record.result_entity_id = $ResultEntityId }
    if (-not [string]::IsNullOrWhiteSpace($ReversalOfResolutionId)) { $record.reversal_of_resolution_id = $ReversalOfResolutionId }
    if ($Limitations.Count -gt 0) { $record.limitations = @($Limitations) }
    return [pscustomobject]$record
}

function Resolve-HavocEntityResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CandidateEntityId,
        [Parameter(Mandatory)] [string] $ExistingEntityId,
        [Parameter(Mandatory)] [ValidateSet('merge','split','distinct')] [string] $Decision,
        [Parameter(Mandatory)] [ValidateSet('low','moderate','high','not_assessed')] [string] $RequestedConfidence,
        [object[]] $BasisIdentifiers = @(),
        [object[]] $ContradictoryIdentifiers = @()
    )

    $basis = @(ConvertTo-HavocIdentifierEvidenceArray -Identifiers $BasisIdentifiers)
    $contradictions = @(ConvertTo-HavocIdentifierEvidenceArray -Identifiers $ContradictoryIdentifiers)
    $strongIdentifierAssessment = Get-HavocStrongIdentifierAssessment -Identifiers $basis
    $automaticContradictions = @($strongIdentifierAssessment.contradictions)
    $automaticUnresolved = @($strongIdentifierAssessment.unresolved)
    if ($automaticContradictions.Count -gt 0) {
        $mergedContradictions = [System.Collections.Generic.List[object]]::new()
        foreach ($identifier in @($contradictions + $automaticContradictions)) {
            $mergedContradictions.Add($identifier)
        }
        $contradictions = @($mergedContradictions.ToArray())
    }
    $hasStrong = $false
    foreach ($identifier in $basis) {
        if ((Get-HavocIdentifierStrength -Identifier $identifier) -eq 'strong') { $hasStrong = $true }
    }
    $hasStrongContradiction = $false
    foreach ($identifier in $contradictions) {
        if ((Get-HavocIdentifierStrength -Identifier $identifier) -eq 'strong') { $hasStrongContradiction = $true }
    }

    $confidence = $RequestedConfidence
    $finalDecision = $Decision
    $limitations = New-Object System.Collections.Generic.List[string]
    if ($Decision -eq 'merge' -and $hasStrongContradiction) {
        $finalDecision = 'distinct'
        $confidence = 'not_assessed'
        $limitations.Add('contradictory strong identifiers block the merge')
    }
    if ($Decision -eq 'merge' -and -not $hasStrongContradiction -and $automaticUnresolved.Count -gt 0) {
        $finalDecision = 'distinct'
        $confidence = 'not_assessed'
        $limitations.Add('strong identifier agreement is unresolved because normalized digest is unavailable')
    }
    if ($Decision -eq 'merge' -and $RequestedConfidence -eq 'high' -and -not $hasStrong) {
        $confidence = 'moderate'
        $limitations.Add('weak-only match cannot produce high-confidence merge')
    }

    $provenance = Get-HavocEvidenceIdsFromIdentifiers -Identifiers $basis
    $contradictionEvidence = Get-HavocEvidenceIdsFromIdentifiers -Identifiers $contradictions
    $allEvidence = @($provenance + $contradictionEvidence | Select-Object -Unique)
    $basisRefs = @($basis | ForEach-Object { [string](Get-HavocProperty -InputObject $_ -Name 'protected_identifier_ref') })
    $contradictionRefs = @($contradictions | ForEach-Object { [string](Get-HavocProperty -InputObject $_ -Name 'protected_identifier_ref') })
    $resolutionId = Get-HavocStableId -Prefix 'ER' -Parts (@($CandidateEntityId, $ExistingEntityId, $finalDecision, $confidence) + $basisRefs + $contradictionRefs)
    $resultEntityId = if ($finalDecision -eq 'merge') { $ExistingEntityId } else { $null }
    return New-HavocEntityResolution -ResolutionId $resolutionId -Decision $finalDecision -Confidence $confidence -SourceEntityIds @($CandidateEntityId, $ExistingEntityId) -ResultEntityId $resultEntityId -BasisIdentifiers $basis -ContradictoryIdentifiers $contradictions -ProvenanceEvidenceIds $allEvidence -Reversible -Limitations @($limitations.ToArray()) -EvidenceIds $allEvidence
}

function Resolve-HavocTemporalOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $OwnershipWindows,
        [Parameter(Mandatory)] [string] $ObservedAt
    )

    $observed = ConvertTo-HavocUtcTimestamp -Value $ObservedAt
    $matches = [System.Collections.Generic.List[object]]::new()
    foreach ($window in @(Get-HavocArray -Value $OwnershipWindows)) {
        $validity = Get-HavocProperty -InputObject $window -Name 'validity_window'
        if ($null -eq $validity) { continue }
        $start = ConvertTo-HavocUtcTimestamp -Value (Get-HavocProperty -InputObject $validity -Name 'start_inclusive')
        $end = ConvertTo-HavocUtcTimestamp -Value (Get-HavocProperty -InputObject $validity -Name 'end_exclusive')
        if ($observed -ge $start -and $observed -lt $end) { $matches.Add($window) }
    }

    if ($matches.Count -gt 1) {
        return [pscustomobject]@{
            entity_id = $null
            unresolved = $true
            reason = 'overlapping_ownership_windows'
            basis = 'Multiple temporal ownership windows covered the observed time.'
        }
    }

    if ($matches.Count -eq 1) {
        return $matches[0]
    }

    return [pscustomobject]@{
        entity_id = $null
        unresolved = $true
        basis = 'No temporal ownership window covered the observed time.'
    }
}

function Test-HavocIdentityContinuity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Before,
        [Parameter(Mandatory)] [object] $After,
        [Parameter(Mandatory)] [string] $LifecycleEventType,
        [object[]] $SupportingIdentifiers = @()
    )

    $beforeObjectId = [string](Get-HavocProperty -InputObject $Before -Name 'object_id_normalized')
    $afterObjectId = [string](Get-HavocProperty -InputObject $After -Name 'object_id_normalized')
    $support = @(ConvertTo-HavocIdentifierEvidenceArray -Identifiers $SupportingIdentifiers)
    $supportingEvidence = Get-HavocEvidenceIdsFromIdentifiers -Identifiers $support
    $hasStrong = $false
    foreach ($identifier in $support) {
        if ((Get-HavocIdentifierStrength -Identifier $identifier) -eq 'strong') { $hasStrong = $true }
    }
    $supportAssessment = Get-HavocStrongIdentifierAssessment -Identifiers $support
    $supportContradictions = @($supportAssessment.contradictions)
    $supportUnresolved = @($supportAssessment.unresolved)
    $supportRefs = @($support | ForEach-Object { [string](Get-HavocProperty -InputObject $_ -Name 'protected_identifier_ref') })
    $subjectEntityId = [string](Get-HavocProperty -InputObject $After -Name 'entity_id')
    $continuityId = Get-HavocStableId -Prefix 'IC' -Parts (@($subjectEntityId, $LifecycleEventType, $beforeObjectId, $afterObjectId) + $supportRefs)

    if ($beforeObjectId -and $afterObjectId -and $beforeObjectId -cne $afterObjectId) {
        return [pscustomobject]@{
            continuity_id = $continuityId
            subject_entity_id = $subjectEntityId
            is_continuous = $false
            confidence = 'high'
            basis = "An object ID mismatch with different object ID values is not continuous across $LifecycleEventType."
            supporting_evidence_ids = @($supportingEvidence)
            contradicting_evidence_ids = @($supportingEvidence)
        }
    }

    if (@('reimage','rename','vdi_reset','secret_rollover','certificate_rollover','tenant_transfer','ownership_change') -contains $LifecycleEventType) {
        if ($supportContradictions.Count -gt 0) {
            return [pscustomobject]@{
                continuity_id = $continuityId
                subject_entity_id = $subjectEntityId
                is_continuous = $false
                confidence = 'not_assessed'
                basis = "Contradictory strong supporting identifiers do not preserve continuity across $LifecycleEventType."
                supporting_evidence_ids = @($supportingEvidence)
                contradicting_evidence_ids = @($supportingEvidence)
            }
        }
        if ($supportUnresolved.Count -gt 0) {
            return [pscustomobject]@{
                continuity_id = $continuityId
                subject_entity_id = $subjectEntityId
                is_continuous = $false
                confidence = 'not_assessed'
                basis = "Strong supporting identifier agreement is unresolved because normalized digest is unavailable across $LifecycleEventType."
                supporting_evidence_ids = @($supportingEvidence)
                contradicting_evidence_ids = @()
            }
        }
        if ($hasStrong) {
            return [pscustomobject]@{
                continuity_id = $continuityId
                subject_entity_id = $subjectEntityId
                is_continuous = $true
                confidence = 'high'
                basis = "Strong identifier evidence preserves continuity across $LifecycleEventType."
                supporting_evidence_ids = @($supportingEvidence)
                contradicting_evidence_ids = @()
            }
        }
        return [pscustomobject]@{
            continuity_id = $continuityId
            subject_entity_id = $subjectEntityId
            is_continuous = $false
            confidence = 'moderate'
            basis = "Weak-only evidence is insufficient to preserve continuity across $LifecycleEventType."
            supporting_evidence_ids = @($supportingEvidence)
            contradicting_evidence_ids = @()
        }
    }

    return [pscustomobject]@{
        continuity_id = $continuityId
        subject_entity_id = $subjectEntityId
        is_continuous = $false
        confidence = 'not_assessed'
        basis = 'Continuity was not established by the supplied lifecycle evidence.'
        supporting_evidence_ids = @($supportingEvidence)
        contradicting_evidence_ids = @()
    }
}

function Undo-HavocEntityResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $ResolutionRecord,
        [Parameter(Mandatory)] [string] $NewResolutionId,
        [string[]] $EvidenceIds = @()
    )

    $isReversible = [bool](Get-HavocProperty -InputObject $ResolutionRecord -Name 'reversible')
    if (-not $isReversible) { throw 'Resolution record is not reversible.' }

    $priorId = [string](Get-HavocProperty -InputObject $ResolutionRecord -Name 'resolution_id')
    $sourceIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $ResolutionRecord -Name 'source_entity_ids'))
    return New-HavocEntityResolution -ResolutionId $NewResolutionId -Decision 'split' -Confidence 'moderate' -SourceEntityIds $sourceIds -BasisIdentifiers @() -ProvenanceEvidenceIds @($EvidenceIds) -Reversible -ReversalOfResolutionId $priorId -EvidenceIds @($EvidenceIds)
}

function New-HavocEntityRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $EntityId,
        [Parameter(Mandatory)] [string] $EntityType,
        [string[]] $Aliases = @(),
        [Parameter(Mandatory)] [string] $LifecycleSummary,
        [Parameter(Mandatory)] [string] $AttributionBoundary,
        [object[]] $StrongIdentifiers = @(),
        [object[]] $WeakIdentifiers = @(),
        [object[]] $AliasHistory = @(),
        [object[]] $LifecycleEvents = @(),
        [object] $IdentityContinuity,
        [string[]] $ClaimIds = @(),
        [string[]] $EvidenceIds = @(),
        [string[]] $GapIds = @(),
        [string[]] $ErrorIds = @(),
        [string[]] $BehaviorBases = @('configurable_project_policy')
    )

    foreach ($alias in $Aliases) {
        if (-not (Test-HavocProtectedReference -Value $alias)) { throw 'Aliases must be protectedReference locators.' }
    }

    $strong = ConvertTo-HavocIdentifierEvidenceArray -Identifiers $StrongIdentifiers
    $weak = ConvertTo-HavocIdentifierEvidenceArray -Identifiers $WeakIdentifiers
    $record = [ordered]@{
        entity_id = $EntityId
        entity_type = $EntityType
        aliases = @($Aliases)
        lifecycle_summary = $LifecycleSummary
        attribution_boundary = $AttributionBoundary
        strong_identifiers = @($strong)
        weak_identifiers = @($weak)
        alias_history = @(Get-HavocArray -Value $AliasHistory)
        lifecycle_events = @(Get-HavocArray -Value $LifecycleEvents)
        claim_ids = @($ClaimIds)
        evidence_ids = @($EvidenceIds)
        gap_ids = @($GapIds)
        error_ids = @($ErrorIds)
        behavior_bases = @($BehaviorBases)
    }
    if ($null -ne $IdentityContinuity) { $record.identity_continuity = $IdentityContinuity }
    return [pscustomobject]$record
}

Export-ModuleMember -Function @(
    'New-HavocEntityRecord',
    'New-HavocEntityResolution',
    'Resolve-HavocEntityResolution',
    'Resolve-HavocTemporalOwner',
    'Test-HavocIdentityContinuity',
    'Undo-HavocEntityResolution',
    'New-HavocIdentifierEvidence'
)
