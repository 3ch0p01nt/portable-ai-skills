Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function ConvertTo-RecurrenceId {
    param([string[]]$Parts)
    Get-HavocStableId -Prefix 'REC' -Parts @($Parts)
}

function Test-ProtectedRecurrenceReference {
    param([string]$Reference, [string]$Name)
    if (-not (Test-HavocProtectedReference -Value $Reference)) {
        throw "$Name must be a protected reference matching the shared pattern."
    }
}

function Get-RecurrenceOrdinalUnique {
    param([object[]]$Values)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($value in $Values) {
        $text = [string]$value
        if ($seen.Add($text)) { $text }
    }
}

function Test-VerifiedRecurrenceEvidence {
    param(
        [object]$InputObject,
        [string[]]$EvidenceIds
    )
    if ($EvidenceIds.Count -eq 0) { return $true }
    $ledger = Get-HavocProperty -InputObject $InputObject -Name 'evidence_ledger'
    if ($null -eq $ledger) { return $false }

    $known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @(Get-HavocArray -Value $ledger)) {
        $id = if ($item -is [string]) { $item } else { Get-HavocProperty -InputObject $item -Name 'evidence_id' }
        if ($null -ne $id -and -not [string]::IsNullOrWhiteSpace([string]$id)) {
            [void]$known.Add([string]$id)
        }
    }

    foreach ($id in $EvidenceIds) {
        if (-not $known.Contains($id)) {
            throw "Unknown recurrence evidence citation: $id"
        }
    }
    return $true
}

function Invoke-RecurrenceAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $current = Get-HavocProperty -InputObject $InputObject -Name 'current_incident'
    $related = Get-HavocProperty -InputObject $InputObject -Name 'related_incident'
    $currentIncidentRef = [string](Get-HavocProperty -InputObject $current -Name 'incident_ref')
    $relatedIncidentRef = [string](Get-HavocProperty -InputObject $related -Name 'incident_ref')
    Test-ProtectedRecurrenceReference -Reference $currentIncidentRef -Name 'current incident reference'
    Test-ProtectedRecurrenceReference -Reference $relatedIncidentRef -Name 'related incident reference'
    Test-ProtectedRecurrenceReference -Reference ([string](Get-HavocProperty -InputObject $current -Name 'workspace_ref')) -Name 'current workspace reference'
    Test-ProtectedRecurrenceReference -Reference ([string](Get-HavocProperty -InputObject $related -Name 'workspace_ref')) -Name 'related workspace reference'

    $observations = foreach ($observation in @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'overlap_observations'))) {
        $explicitContext = Get-HavocProperty -InputObject $observation -Name 'shared_infrastructure_context'
        $context = if ($null -ne $explicitContext) {
            ([string]$explicitContext).ToLowerInvariant()
        } else {
            'none'
        }
        $isDowngraded = ([string](Get-HavocProperty -InputObject $observation -Name 'basis') -ceq 'infrastructure' -and $context -cin @('cdn', 'shared-hosting'))
        [pscustomobject][ordered]@{
            basis = [string](Get-HavocProperty -InputObject $observation -Name 'basis')
            identifier_strength = [string](Get-HavocProperty -InputObject $observation -Name 'identifier_strength')
            identifier_ref = [string](Get-HavocProperty -InputObject $observation -Name 'identifier_ref')
            temporal_plausibility = [string](Get-HavocProperty -InputObject $observation -Name 'temporal_plausibility')
            shared_infrastructure_context = $context
            summary = [string](Get-HavocProperty -InputObject $observation -Name 'summary')
            downgraded = [bool]$isDowngraded
        }
    }
    $noOverlapObserved = @($observations).Count -eq 0
    if ($noOverlapObserved) {
        $observations = @([pscustomobject][ordered]@{
            basis = 'no_overlap_observed'
            identifier_strength = 'weak'
            identifier_ref = 'not-applicable:no-overlap-observed'
            temporal_plausibility = 'unknown'
            shared_infrastructure_context = 'none'
            summary = 'No overlap observations were supplied.'
            downgraded = $false
        })
    }

    foreach ($observation in $observations) {
        Test-ProtectedRecurrenceReference -Reference $observation.identifier_ref -Name 'overlap identifier reference'
    }

    $strongBases = @('entity', 'infrastructure', 'causal')
    $plausibleTimes = @('plausible', 'overlapping', 'ordered')
    $strongObservation = @($observations | Where-Object {
        $_.basis -cin $strongBases -and
        $_.identifier_strength -ceq 'strong' -and
        $_.temporal_plausibility -cin $plausibleTimes -and
        -not $_.downgraded
    })
    $onlyWeakRuleOrTtp = -not $strongObservation -and -not @($observations | Where-Object {
        $_.basis -cnotin @('TTP', 'detection_rule', 'time')
    })

    $suppression = Get-HavocProperty -InputObject $InputObject -Name 'suppression'
    $hiddenSuppression = $false
    $suppressionRefs = @()
    if ($null -ne $suppression) {
        $hiddenSuppression = [bool](Get-HavocProperty -InputObject $suppression -Name 'automatic_tuning_detected') -or [bool](Get-HavocProperty -InputObject $suppression -Name 'hidden_related_alerts_observed')
        $ruleRef = Get-HavocProperty -InputObject $suppression -Name 'protected_rule_ref'
        if ($null -ne $ruleRef) {
            $ref = [string]$ruleRef
            Test-ProtectedRecurrenceReference -Reference $ref -Name 'suppression rule reference'
            $suppressionRefs += $ref
        }
    }

    $limitations = [System.Collections.Generic.List[string]]::new()
    if ($noOverlapObserved) {
        $limitations.Add('no overlap observations were supplied')
    }
    if ($onlyWeakRuleOrTtp) {
        $limitations.Add('shared TTP or same detection rule alone is weak relationship evidence')
    }
    if (@($observations | Where-Object { $_.downgraded }).Count -gt 0) {
        $limitations.Add('shared-hosting or CDN infrastructure overlap was downgraded')
    }
    if ($hiddenSuppression) {
        $limitations.Add('suppression or tuning may hide downstream related alerts; visibility is source-specific and auditable')
    }
    if ($limitations.Count -eq 0) {
        $limitations.Add('relationship remains subject to coverage, source dependence, and closure-quality limits')
    }

    $strength = 'weak'
    $analyticConfidence = 'low'
    $confidence = 0.35
    if ($strongObservation.Count -gt 0) {
        $strength = 'strong'
        $analyticConfidence = 'high'
        $confidence = 0.85
    } elseif (-not $onlyWeakRuleOrTtp -and @($observations).Count -gt 1) {
        $strength = 'moderate'
        $analyticConfidence = 'moderate'
        $confidence = 0.6
    }

    $overlapBasis = @(Get-RecurrenceOrdinalUnique -Values @($observations | ForEach-Object { $_.basis }))
    $temporal = if (@($observations | Where-Object { $_.temporal_plausibility -ceq 'ordered' }).Count -gt 0) {
        'ordered'
    } elseif (@($observations | Where-Object { $_.temporal_plausibility -ceq 'overlapping' }).Count -gt 0) {
        'overlapping'
    } elseif (@($observations | Where-Object { $_.temporal_plausibility -ceq 'plausible' }).Count -gt 0) {
        'plausible'
    } elseif (@($observations | Where-Object { $_.temporal_plausibility -ceq 'implausible' }).Count -gt 0) {
        'implausible'
    } else {
        'unknown'
    }

    $priorDisposition = Get-HavocProperty -InputObject $InputObject -Name 'prior_disposition'
    Test-ProtectedRecurrenceReference -Reference ([string](Get-HavocProperty -InputObject $priorDisposition -Name 'protected_decision_ref')) -Name 'prior disposition protected decision reference'
    $boundaryCrossed = ([string](Get-HavocProperty -InputObject $current -Name 'workspace_ref') -cne [string](Get-HavocProperty -InputObject $related -Name 'workspace_ref')) -or ([string](Get-HavocProperty -InputObject $current -Name 'product') -cne [string](Get-HavocProperty -InputObject $related -Name 'product'))

    $claimIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'claim_ids'))
    $rawEvidenceIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'evidence_ids'))
    $gapIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'gap_ids'))
    $errorIds = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'error_ids'))
    $evidenceVerified = Test-VerifiedRecurrenceEvidence -InputObject $InputObject -EvidenceIds $rawEvidenceIds
    [object[]]$evidenceIds = @()
    if ($evidenceVerified) {
        $evidenceIds = @($rawEvidenceIds)
    }
    if (-not $evidenceVerified) {
        $gapIds = @(Get-RecurrenceOrdinalUnique -Values @($gapIds + 'citations_unverified'))
        $limitations.Add('evidence citations were not verified against a supplied ledger')
        $strength = 'weak'
        $analyticConfidence = 'low'
        $confidence = [Math]::Min($confidence, 0.35)
        $strongObservation = @()
    }
    $caseId = [string](Get-HavocProperty -InputObject $InputObject -Name 'case_id')

    [pscustomobject][ordered]@{
        recurrence_id = ConvertTo-RecurrenceId -Parts @($caseId, $currentIncidentRef, $relatedIncidentRef)
        related_record_ref = ConvertTo-RecurrenceId -Parts @($relatedIncidentRef)
        relation_basis = ($overlapBasis -join ',')
        relation_limitations = @($limitations)
        claim_ids = @($claimIds)
        evidence_ids = @($evidenceIds)
        gap_ids = @($gapIds)
        error_ids = @($errorIds)
        behavior_bases = @('configurable_project_policy')
        relation_type = [string](Get-HavocProperty -InputObject $InputObject -Name 'relation_type')
        overlap_basis = @($overlapBasis)
        relation_strength = $strength
        analytic_confidence = $analyticConfidence
        confidence = $confidence
        strong_linkage_supported = [bool]($strongObservation.Count -gt 0)
        temporal_plausibility = $temporal
        prior_disposition = [pscustomobject][ordered]@{
            classification = [string](Get-HavocProperty -InputObject $priorDisposition -Name 'classification')
            determination = [string](Get-HavocProperty -InputObject $priorDisposition -Name 'determination')
            closure_quality = [string](Get-HavocProperty -InputObject $priorDisposition -Name 'closure_quality')
            protected_decision_ref = [string](Get-HavocProperty -InputObject $priorDisposition -Name 'protected_decision_ref')
        }
        prior_closure_quality_auditable = $true
        prior_closure_quality = [string](Get-HavocProperty -InputObject $priorDisposition -Name 'closure_quality')
        current_disposition_inference_from_prior = 'not_supported'
        current_incident_protected_ref = $currentIncidentRef
        related_incident_protected_ref = $relatedIncidentRef
        current_workspace_protected_ref = [string](Get-HavocProperty -InputObject $current -Name 'workspace_ref')
        related_workspace_protected_ref = [string](Get-HavocProperty -InputObject $related -Name 'workspace_ref')
        current_product = [string](Get-HavocProperty -InputObject $current -Name 'product')
        related_product = [string](Get-HavocProperty -InputObject $related -Name 'product')
        boundary_crossed = [bool]$boundaryCrossed
        workspace_product_boundary_crossed = [bool]$boundaryCrossed
        hidden_related_alerts_surfaced = [bool]$hiddenSuppression
        suppression_or_tuning_refs = @(Get-RecurrenceOrdinalUnique -Values $suppressionRefs)
        overlap_observations = @($observations)
    }
}

Export-ModuleMember -Function Invoke-RecurrenceAnalysis
