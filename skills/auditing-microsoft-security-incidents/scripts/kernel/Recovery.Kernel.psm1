Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:RequiredRecoveryCriteria = @{
    generic = @(
        'credential_rotation',
        'token_revocation',
        'session_invalidation',
        'key_rotation',
        'secondary_persistence_removal',
        'patching',
        'reimage_rebuild_evidence',
        'backup_integrity',
        'clean_monitoring_window',
        'recurrence_check',
        'independent_control_validation'
    )
    ransomware = @(
        'credential_rotation',
        'token_revocation',
        'session_invalidation',
        'key_rotation',
        'secondary_persistence_removal',
        'patching',
        'reimage_rebuild_evidence',
        'backup_integrity',
        'clean_monitoring_window',
        'recurrence_check',
        'independent_control_validation'
    )
    identity_compromise = @(
        'password_reset',
        'credential_rotation',
        'token_revocation',
        'session_invalidation',
        'secondary_persistence_removal',
        'clean_monitoring_window',
        'recurrence_check',
        'independent_control_validation'
    )
    email_compromise = @(
        'password_reset',
        'credential_rotation',
        'token_revocation',
        'session_invalidation',
        'secondary_persistence_removal',
        'clean_monitoring_window',
        'recurrence_check',
        'independent_control_validation'
    )
    cloud_control_plane = @(
        'credential_rotation',
        'token_revocation',
        'session_invalidation',
        'key_rotation',
        'secondary_persistence_removal',
        'patching',
        'clean_monitoring_window',
        'recurrence_check',
        'independent_control_validation'
    )
    endpoint_intrusion = @(
        'credential_rotation',
        'token_revocation',
        'session_invalidation',
        'secondary_persistence_removal',
        'patching',
        'reimage_rebuild_evidence',
        'clean_monitoring_window',
        'recurrence_check',
        'independent_control_validation'
    )
}

function Get-Array {
    param($Value)
    return @(Get-HavocArray -Value $Value)
}

function Get-UniqueStrings {
    param($Value)
    $items = if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            $item
        }
    }
    else {
        $Value
    }
    $set = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($items)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        [void]$set.Add($text)
    }
    return @($set)
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)] [string] $Name
    )
    if ($null -eq $Object) {
        return $null
    }
    return Get-HavocProperty -InputObject $Object -Name $Name
}

function Get-EvidenceIndex {
    param([Parameter(Mandatory)] $Review)
    $index = @{}
    foreach ($item in Get-Array (Get-PropertyValue $Review 'evidence_available')) {
        $id = [string](Get-PropertyValue $item 'evidence_id')
        if ($id) {
            $index[$id] = $item
        }
    }
    return $index
}

function Get-RequiredRecoveryCriteria {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $IncidentType)

    if ($script:RequiredRecoveryCriteria.ContainsKey($IncidentType)) {
        return @($script:RequiredRecoveryCriteria[$IncidentType])
    }
    return @($script:RequiredRecoveryCriteria.generic)
}

function Test-RecoveryClaimIdentifiers {
    param([AllowNull()][object[]] $Claims)

    $seen = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    $errors = New-Object System.Collections.Generic.List[object]
    $invalidIds = New-Object System.Collections.Generic.List[string]

    for ($index = 0; $index -lt $Claims.Count; $index++) {
        $recoveryId = [string](Get-PropertyValue $Claims[$index] 'recovery_id')
        if ([string]::IsNullOrWhiteSpace($recoveryId)) {
            $errors.Add([pscustomobject][ordered]@{
                claim_index = $index
                recovery_id = $recoveryId
                reason = 'missing_recovery_id'
            })
            continue
        }
        if ($seen.ContainsKey($recoveryId)) {
            $errors.Add([pscustomobject][ordered]@{
                claim_index = $index
                first_claim_index = $seen[$recoveryId]
                recovery_id = $recoveryId
                reason = 'duplicate_recovery_id'
            })
            $invalidIds.Add($recoveryId)
            continue
        }
        $seen[$recoveryId] = $index
    }

    [pscustomobject][ordered]@{
        valid = ($errors.Count -eq 0)
        errors = @($errors.ToArray())
        invalid_recovery_ids = @(Get-UniqueStrings $invalidIds.ToArray())
    }
}

function Test-RecoveryValidation {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Review)

    $incidentType = [string](Get-PropertyValue $Review 'incident_type')
    $required = @(Get-RequiredRecoveryCriteria -IncidentType $incidentType)
    $claims = @(Get-Array (Get-PropertyValue $Review 'recovery_claims'))
    $identifierValidation = Test-RecoveryClaimIdentifiers -Claims $claims
    if (-not $identifierValidation.valid) {
        return [pscustomobject][ordered]@{
            validation_state = 'invalid'
            incident_type = $incidentType
            required_criteria = @($required)
            invalid_recovery_ids = @($identifierValidation.invalid_recovery_ids)
            validation_errors = @($identifierValidation.errors)
            missing_criteria = @()
            criteria_without_evidence = @()
            criteria_with_missing_evidence_reference = @()
            criterion_results = @()
            claim_results = @()
            token_reset_distinction = [pscustomobject][ordered]@{
                password_reset_evidence_ids = @()
                credential_rotation_evidence_ids = @()
                token_revocation_evidence_ids = @()
                session_invalidation_evidence_ids = @()
                key_rotation_evidence_ids = @()
            }
        }
    }

    $criteriaWithoutEvidence = New-Object System.Collections.Generic.List[string]
    $criteriaWithMissingEvidenceReference = New-Object System.Collections.Generic.List[string]
    $evidenceIndex = Get-EvidenceIndex -Review $Review

    $tokenResetDistinction = [pscustomobject][ordered]@{
        password_reset_evidence_ids = @()
        credential_rotation_evidence_ids = @()
        token_revocation_evidence_ids = @()
        session_invalidation_evidence_ids = @()
        key_rotation_evidence_ids = @()
    }

    foreach ($claim in $claims) {
        $distinction = Get-PropertyValue $claim 'credential_token_session_review'
        if ($null -ne $distinction) {
            foreach ($propertyName in @(
                'password_reset_evidence_ids',
                'credential_rotation_evidence_ids',
                'token_revocation_evidence_ids',
                'session_invalidation_evidence_ids',
                'key_rotation_evidence_ids'
            )) {
                $tokenResetDistinction.$propertyName =
                    [string[]]@(Get-UniqueStrings @($tokenResetDistinction.$propertyName + @(Get-PropertyValue $distinction $propertyName)))
            }
        }
    }

    $allMissing = New-Object System.Collections.Generic.List[string]
    $criterionResults = New-Object System.Collections.Generic.List[object]
    $claimResults = New-Object System.Collections.Generic.List[object]
    $totalSatisfiedWithEvidence = 0

    for ($claimIndex = 0; $claimIndex -lt $claims.Count; $claimIndex++) {
        $claim = $claims[$claimIndex]
        $recoveryId = [string](Get-PropertyValue $claim 'recovery_id')
        $criteriaById = @{}
        foreach ($criterion in Get-Array (Get-PropertyValue $claim 'criteria')) {
            $id = [string](Get-PropertyValue $criterion 'criterion_id')
            if ($id -and -not $criteriaById.ContainsKey($id)) {
                $criteriaById[$id] = $criterion
            }
        }

        $claimMissing = New-Object System.Collections.Generic.List[string]
        $claimCriteriaWithoutEvidence = New-Object System.Collections.Generic.List[string]
        $claimCriteriaWithMissingEvidenceReference = New-Object System.Collections.Generic.List[string]
        $claimSatisfiedWithEvidence = 0

        foreach ($criterionId in $required) {
            if (-not $criteriaById.ContainsKey($criterionId)) {
                $claimMissing.Add($criterionId)
                $allMissing.Add($criterionId)
                $criterionResults.Add([pscustomobject][ordered]@{
                    claim_index = $claimIndex
                    recovery_id = $recoveryId
                    criterion_id = $criterionId
                    state = 'missing'
                    evidence_ids = @()
                })
                continue
            }

            $criterion = $criteriaById[$criterionId]
            $evidenceIds = @(Get-HavocArray -Value (Get-PropertyValue $criterion 'evidence_ids'))
            $assessment = [string](Get-PropertyValue $criterion 'assessment')
            if ($assessment -ne 'satisfied') {
                $claimMissing.Add($criterionId)
                $allMissing.Add($criterionId)
            }
            if ($evidenceIds.Count -eq 0) {
                $criteriaWithoutEvidence.Add($criterionId)
                $claimCriteriaWithoutEvidence.Add($criterionId)
            }
            $criterionMissingEvidenceReference = $false
            foreach ($evidenceId in $evidenceIds) {
                if (-not $evidenceIndex.ContainsKey([string]$evidenceId)) {
                    $criteriaWithMissingEvidenceReference.Add($criterionId)
                    $claimCriteriaWithMissingEvidenceReference.Add($criterionId)
                    $criterionMissingEvidenceReference = $true
                    break
                }
            }
            $state = if ($assessment -eq 'satisfied' -and $evidenceIds.Count -gt 0 -and -not $criterionMissingEvidenceReference) { 'evidenced' } elseif ($assessment -eq 'satisfied' -and -not $criterionMissingEvidenceReference) { 'claimed_without_evidence' } else { 'not_satisfied' }
            if ($state -eq 'evidenced') {
                $claimSatisfiedWithEvidence++
                $totalSatisfiedWithEvidence++
            }
            $criterionResults.Add([pscustomobject][ordered]@{
                claim_index = $claimIndex
                recovery_id = $recoveryId
                criterion_id = $criterionId
                state = $state
                evidence_ids = @(Get-UniqueStrings $evidenceIds)
            })
        }

        $claimValidationState = if (
            $required.Count -gt 0 -and
            $claimMissing.Count -eq 0 -and
            $claimCriteriaWithoutEvidence.Count -eq 0 -and
            $claimCriteriaWithMissingEvidenceReference.Count -eq 0
        ) {
            'validated'
        }
        elseif ($claimSatisfiedWithEvidence -gt 0) {
            'partially_validated'
        }
        else {
            'unverified'
        }
        $claimResults.Add([pscustomobject][ordered]@{
            claim_index = $claimIndex
            recovery_id = $recoveryId
            validation_state = $claimValidationState
            missing_criteria = @(Get-UniqueStrings $claimMissing.ToArray())
            criteria_without_evidence = @(Get-UniqueStrings $claimCriteriaWithoutEvidence.ToArray())
            criteria_with_missing_evidence_reference = @(Get-UniqueStrings $claimCriteriaWithMissingEvidenceReference.ToArray())
        })
    }

    $validationState = if (
        $required.Count -gt 0 -and
        $claimResults.Count -gt 0 -and
        @($claimResults.ToArray() | Where-Object { $_.validation_state -ne 'validated' }).Count -eq 0 -and
        $allMissing.Count -eq 0 -and
        $criteriaWithoutEvidence.Count -eq 0 -and
        $criteriaWithMissingEvidenceReference.Count -eq 0
    ) {
        'validated'
    }
    elseif ($totalSatisfiedWithEvidence -gt 0) {
        'partially_validated'
    }
    else {
        'unverified'
    }

    [pscustomobject][ordered]@{
        validation_state = $validationState
        incident_type = $incidentType
        required_criteria = @($required)
        missing_criteria = @(Get-UniqueStrings $allMissing.ToArray())
        criteria_without_evidence = @(Get-UniqueStrings $criteriaWithoutEvidence.ToArray())
        criteria_with_missing_evidence_reference = @(Get-UniqueStrings $criteriaWithMissingEvidenceReference.ToArray())
        criterion_results = @($criterionResults.ToArray())
        claim_results = @($claimResults.ToArray())
        token_reset_distinction = $tokenResetDistinction
    }
}

function Test-ContainmentDecisionEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Review)

    $evidenceIndex = Get-EvidenceIndex -Review $Review
    $violations = New-Object System.Collections.Generic.List[object]

    foreach ($decision in Get-Array (Get-PropertyValue $Review 'containment_decisions')) {
        $decisionId = [string](Get-PropertyValue $decision 'decision_id')
        $decisionTime = ConvertTo-HavocUtcTimestamp -Value (Get-PropertyValue $decision 'decision_time')
        foreach ($criterion in Get-Array (Get-PropertyValue $decision 'criteria')) {
            $criterionId = [string](Get-PropertyValue $criterion 'criterion_id')
            foreach ($evidenceIdValue in @(Get-HavocArray -Value (Get-PropertyValue $criterion 'evidence_ids'))) {
                $evidenceId = [string]$evidenceIdValue
                if (-not $evidenceIndex.ContainsKey($evidenceId)) {
                    $violations.Add([pscustomobject][ordered]@{
                        decision_id = $decisionId
                        criterion_id = $criterionId
                        evidence_id = $evidenceId
                        reason = 'evidence_not_available_in_review_record'
                    })
                    continue
                }
                $availableAt = ConvertTo-HavocUtcTimestamp -Value (Get-PropertyValue $evidenceIndex[$evidenceId] 'available_at')
                if ($availableAt -gt $decisionTime) {
                    $violations.Add([pscustomobject][ordered]@{
                        decision_id = $decisionId
                        criterion_id = $criterionId
                        evidence_id = $evidenceId
                        reason = 'evidence_available_after_decision_time'
                    })
                }
            }

        }
    }

    [pscustomobject][ordered]@{
        no_hindsight_compliant = ($violations.Count -eq 0)
        hindsight_evidence_ids = @(Get-UniqueStrings ($violations.ToArray() | ForEach-Object { $_.evidence_id }))
        violations = @($violations.ToArray())
    }
}

function Test-ContainmentCompleteness {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Review)

    $decisionResults = New-Object System.Collections.Generic.List[object]
    $allMissingEntityRefs = New-Object System.Collections.Generic.List[string]
    $allMissingActions = New-Object System.Collections.Generic.List[string]
    $gapIds = New-Object System.Collections.Generic.List[string]
    $decisions = @(Get-Array (Get-PropertyValue $Review 'containment_decisions'))

    if ($decisions.Count -eq 0) {
        $gapIds.Add('containment_decision_missing')
    }

    foreach ($decision in $decisions) {
        $decisionId = [string](Get-PropertyValue $decision 'decision_id')
        $scopedEntityRefs = @(Get-HavocArray -Value (Get-PropertyValue $decision 'scoped_entity_refs'))
        $accountedEntityRefs = @(Get-HavocArray -Value (Get-PropertyValue $decision 'accounted_entity_refs'))
        $scopedActions = @(Get-HavocArray -Value (Get-PropertyValue $decision 'scoped_actions'))
        $accountedActions = @(Get-HavocArray -Value (Get-PropertyValue $decision 'accounted_actions'))
        $decisionGapIds = New-Object System.Collections.Generic.List[string]

        if ($scopedEntityRefs.Count -eq 0 -and $scopedActions.Count -eq 0) {
            $decisionGapIds.Add('containment_scope_empty')
            $gapIds.Add('containment_scope_empty')
        }

        $missingEntityRefs = New-Object System.Collections.Generic.List[string]
        foreach ($entityRef in $scopedEntityRefs) {
            if ([string]$entityRef -cnotin @($accountedEntityRefs | ForEach-Object { [string]$_ })) {
                $missingEntityRefs.Add([string]$entityRef)
                $allMissingEntityRefs.Add([string]$entityRef)
            }
        }

        $missingActions = New-Object System.Collections.Generic.List[string]
        foreach ($action in $scopedActions) {
            if ([string]$action -cnotin @($accountedActions | ForEach-Object { [string]$_ })) {
                $missingActions.Add([string]$action)
                $allMissingActions.Add([string]$action)
            }
        }

        $decisionResults.Add([pscustomobject][ordered]@{
            decision_id = $decisionId
            complete = ($decisionGapIds.Count -eq 0 -and $missingEntityRefs.Count -eq 0 -and $missingActions.Count -eq 0)
            gap_ids = @(Get-UniqueStrings $decisionGapIds.ToArray())
            missing_entity_refs = @(Get-UniqueStrings $missingEntityRefs.ToArray())
            missing_actions = @(Get-UniqueStrings $missingActions.ToArray())
        })
    }

    [pscustomobject][ordered]@{
        complete = ($gapIds.Count -eq 0 -and $allMissingEntityRefs.Count -eq 0 -and $allMissingActions.Count -eq 0)
        gap_ids = @(Get-UniqueStrings $gapIds.ToArray())
        missing_entity_refs = @(Get-UniqueStrings $allMissingEntityRefs.ToArray())
        missing_actions = @(Get-UniqueStrings $allMissingActions.ToArray())
        decision_results = @($decisionResults.ToArray())
    }
}

function Get-RecursiveStringFinding {
    param(
        [Parameter(Mandatory)] $Value,
        [Parameter(Mandatory)] [string] $Path
    )

    $findings = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) {
        return @()
    }

    foreach ($property in @($Value.PSObject.Properties)) {
        if ($property.Name -match '(?i)(executable|command|script|api[_-]?operation|http[_-]?method)') {
            $findings.Add([pscustomobject][ordered]@{
                path = if ($Path) { "$Path.$($property.Name)" } else { $property.Name }
                reason = 'executable_field'
                matched_text = $property.Name
            })
        }
    }

    if ($Value -is [string]) {
        foreach ($match in Find-HavocMutationCommand -Text $Value -CommandContext) {
            $findings.Add([pscustomobject][ordered]@{
                path = $Path
                reason = 'mutation_command_text'
                rule = $match.rule
                matched_text = $match.match
            })
        }
        return @($findings.ToArray())
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $index = 0
        foreach ($item in $Value) {
            foreach ($finding in Get-RecursiveStringFinding -Value $item -Path "${Path}[$index]") {
                $findings.Add($finding)
            }
            $index++
        }
        return @($findings.ToArray())
    }

    foreach ($property in @($Value.PSObject.Properties)) {
        $childPath = if ($Path) { "$Path.$($property.Name)" } else { $property.Name }
        foreach ($finding in Get-RecursiveStringFinding -Value $property.Value -Path $childPath) {
            $findings.Add($finding)
        }
    }

    return @($findings.ToArray())
}

function Test-RecommendationSafety {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Review)

    $violations = New-Object System.Collections.Generic.List[object]
    foreach ($finding in Get-RecursiveStringFinding -Value (Get-PropertyValue $Review 'recommendations') -Path 'recommendations') {
        $violations.Add($finding)
    }

    foreach ($recommendation in Get-Array (Get-PropertyValue $Review 'recommendations')) {
        $approval = Get-PropertyValue $recommendation 'human_approval_required'
        if ($approval -ne $true) {
            $violations.Add([pscustomobject][ordered]@{
                path = 'recommendations.human_approval_required'
                reason = 'human_approval_not_required'
                matched_text = [string]$approval
            })
        }
    }

    [pscustomobject][ordered]@{
        safe = ($violations.Count -eq 0)
        violations = @($violations.ToArray())
    }
}

function ConvertTo-ContainmentDecisionAuditRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Review)

    $decision = @(Get-PropertyValue $Review 'containment_decisions')[0]
    if ($null -eq $decision) {
        throw 'Review does not contain a containment decision.'
    }
    $evidenceCheck = Test-ContainmentDecisionEvidence -Review $Review
    $completeness = Test-ContainmentCompleteness -Review $Review
    $decisionTime = ConvertTo-HavocUtcTimestamp -Value (Get-PropertyValue $decision 'decision_time')
    $evidenceIndex = Get-EvidenceIndex -Review $Review
    $available = New-Object System.Collections.Generic.List[string]
    $later = New-Object System.Collections.Generic.List[string]
    foreach ($criterion in Get-Array (Get-PropertyValue $decision 'criteria')) {
        foreach ($evidenceIdValue in Get-Array (Get-PropertyValue $criterion 'evidence_ids')) {
            $evidenceId = [string]$evidenceIdValue
            if ($evidenceIndex.ContainsKey($evidenceId)) {
                $availableAt = ConvertTo-HavocUtcTimestamp -Value (Get-PropertyValue $evidenceIndex[$evidenceId] 'available_at')
                if ($availableAt -le $decisionTime) {
                    $available.Add($evidenceId)
                }
                else {
                    $later.Add($evidenceId)
                }
            }
        }
    }

    [pscustomobject][ordered]@{
        decision_id = [string](Get-PropertyValue $decision 'decision_id')
        decision_time = [string](Get-PropertyValue $decision 'decision_time')
        soc_assessment_label = if (-not $evidenceCheck.no_hindsight_compliant) { 'outcome_only_hindsight' } elseif (-not $completeness.complete) { 'questionable_with_available_evidence' } else { 'not_assessable' }
        available_evidence_ids = @(Get-UniqueStrings $available)
        later_evidence_ids = @(Get-UniqueStrings $later)
        claim_ids = @(Get-UniqueStrings (Get-PropertyValue $decision 'claim_ids'))
        gap_ids = @(Get-UniqueStrings (Get-PropertyValue $decision 'gap_ids'))
        error_ids = @(Get-UniqueStrings (Get-PropertyValue $decision 'error_ids'))
        behavior_bases = @(Get-UniqueStrings (Get-PropertyValue $Review 'behavior_bases'))
    }
}

function ConvertTo-RecoveryAuditRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Review)

    $claims = @(Get-Array (Get-PropertyValue $Review 'recovery_claims'))
    if ($claims.Count -eq 0) {
        throw 'Review does not contain a recovery claim.'
    }
    $identifierValidation = Test-RecoveryClaimIdentifiers -Claims $claims
    if (-not $identifierValidation.valid) {
        $firstError = @($identifierValidation.errors)[0]
        if ($firstError.reason -eq 'missing_recovery_id') {
            throw "Cannot project recovery records with missing recovery_id at claim index $($firstError.claim_index)."
        }
        if ($firstError.reason -eq 'duplicate_recovery_id') {
            throw "Cannot project recovery records with duplicate recovery_id '$($firstError.recovery_id)'."
        }
        throw 'Cannot project recovery records with invalid recovery identifiers.'
    }
    $validation = Test-RecoveryValidation -Review $Review
    if ($validation.validation_state -eq 'invalid') {
        throw 'Cannot project invalid recovery validation results.'
    }
    for ($claimIndex = 0; $claimIndex -lt $claims.Count; $claimIndex++) {
        $claim = $claims[$claimIndex]
        $recoveryId = [string](Get-PropertyValue $claim 'recovery_id')
        $claimResult = @($validation.claim_results | Where-Object {
            $_.claim_index -eq $claimIndex -and [string]$_.recovery_id -ceq $recoveryId
        })[0]
        $claimState = if ($null -ne $claimResult) { [string]$claimResult.validation_state } else { 'unverified' }
        $evidenceIds = New-Object System.Collections.Generic.List[string]
        foreach ($criterion in Get-Array (Get-PropertyValue $claim 'criteria')) {
            foreach ($evidenceId in @(Get-HavocArray -Value (Get-PropertyValue $criterion 'evidence_ids'))) {
                $evidenceIds.Add([string]$evidenceId)
            }
        }

        [pscustomobject][ordered]@{
            recovery_id = $recoveryId
            observed_action = [string](Get-PropertyValue $claim 'claim')
            action_state = $claimState
            authority_state = 'human_approval_required'
            claim_ids = @(Get-UniqueStrings (Get-PropertyValue $claim 'claim_ids'))
            evidence_ids = @(Get-UniqueStrings $evidenceIds)
            gap_ids = @(Get-UniqueStrings (Get-PropertyValue $claim 'gap_ids'))
            error_ids = @(Get-UniqueStrings (Get-PropertyValue $claim 'error_ids'))
            behavior_bases = @(Get-UniqueStrings (Get-PropertyValue $Review 'behavior_bases'))
        }
    }
}

Export-ModuleMember -Function @(
    'Get-RequiredRecoveryCriteria',
    'Test-RecoveryValidation',
    'Test-ContainmentDecisionEvidence',
    'Test-ContainmentCompleteness',
    'Test-RecommendationSafety',
    'ConvertTo-ContainmentDecisionAuditRecord',
    'ConvertTo-RecoveryAuditRecord'
)
