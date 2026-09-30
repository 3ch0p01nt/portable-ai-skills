Set-StrictMode -Version Latest

$commonKernelPath = Join-Path $PSScriptRoot 'Common.Kernel.psm1'
Import-Module $commonKernelPath -Force

function Get-HavocQaContentDigest {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()]$InputObject)

    process {
        $canonical = ConvertTo-HavocCanonicalJson -Value $InputObject
        Get-HavocSha256Hex -Text $canonical
    }
}

function Get-HavocPropertyValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

function Test-HavocQaReviewerIndependence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Audit,
        [Parameter(Mandatory)]$Reviewer
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    $auditAuthorId = [string](Get-HavocPropertyValue $Audit 'audit_author_id')
    $auditContextId = [string](Get-HavocPropertyValue $Audit 'audit_context_id')
    $reviewerId = [string](Get-HavocPropertyValue $Reviewer 'reviewer_id')
    $authoredAudit = [bool](Get-HavocPropertyValue $Reviewer 'authored_audit')
    $independenceBasis = [string](Get-HavocPropertyValue $Reviewer 'independence_basis')
    $sharedContextIds = @(Get-HavocArray -Value (Get-HavocPropertyValue $Reviewer 'shared_context_ids'))

    if ([string]::IsNullOrWhiteSpace($reviewerId) -or [string]::IsNullOrWhiteSpace($auditAuthorId)) {
        $reasons.Add('missing_identity')
    }
    if ($authoredAudit -or ((-not [string]::IsNullOrWhiteSpace($reviewerId)) -and
        (-not [string]::IsNullOrWhiteSpace($auditAuthorId)) -and
        $reviewerId -ceq $auditAuthorId)) {
        $reasons.Add('reviewer_authored_audit')
    }
    if ($auditContextId -and ($sharedContextIds | Where-Object { [string]$_ -ceq $auditContextId })) {
        $reasons.Add('reviewer_shared_audit_context')
    }
    if ([string]::IsNullOrWhiteSpace($independenceBasis)) {
        $reasons.Add('missing_independence_basis')
    }

    [pscustomobject][ordered]@{
        is_independent = ($reasons.Count -eq 0)
        reasons = @($reasons)
        reviewer_verdict = if ($reasons.Count -eq 0) { 'pass' } else { 'not_independent' }
    }
}

function Test-HavocQaSealedVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$QaRecord)

    $violations = [System.Collections.Generic.List[string]]::new()
    $expectedDigest = Get-HavocQaContentDigest -InputObject $QaRecord.sealed_verdict.content
    $actualDigest = [string]$QaRecord.sealed_verdict.digest
    if ($expectedDigest -cne $actualDigest.ToLowerInvariant()) {
        $violations.Add('digest_mismatch')
    }
    $sealedCanonical = ConvertTo-HavocCanonicalJson -Value $QaRecord.sealed_verdict.content
    $comparisonReviewerCanonical = ConvertTo-HavocCanonicalJson -Value $QaRecord.comparison.reviewer_verdict
    if ($sealedCanonical -cne $comparisonReviewerCanonical) {
        $violations.Add('comparison_reviewer_verdict_mismatch')
    }

    $sealedAt = ConvertTo-HavocUtcTimestamp -Value ([string]$QaRecord.sealed_verdict.sealed_at)
    $revealedAt = ConvertTo-HavocUtcTimestamp -Value ([string]$QaRecord.reveal.revealed_at)
    $comparedAt = ConvertTo-HavocUtcTimestamp -Value ([string]$QaRecord.comparison.compared_at)
    if ($sealedAt -ge $revealedAt) { $violations.Add('seal_not_before_reveal') }
    if ($sealedAt -ge $comparedAt) { $violations.Add('seal_not_before_comparison') }

    [pscustomobject][ordered]@{
        valid = ($violations.Count -eq 0)
        violations = @($violations)
        expected_digest = $expectedDigest
        actual_digest = $actualDigest
    }
}

function Compare-HavocArraySet {
    param($Left, $Right)
    $leftHash = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in @(Get-HavocArray -Value $Left)) { [void]$leftHash.Add([string]$item) }
    $rightHash = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in @(Get-HavocArray -Value $Right)) { [void]$rightHash.Add([string]$item) }
    $leftSet = [string[]]$leftHash
    $rightSet = [string[]]$rightHash
    [Array]::Sort($leftSet, [StringComparer]::Ordinal)
    [Array]::Sort($rightSet, [StringComparer]::Ordinal)
    if ($leftSet.Count -ne $rightSet.Count) { return $false }
    for ($i = 0; $i -lt $leftSet.Count; $i++) {
        if ($leftSet[$i] -cne $rightSet[$i]) { return $false }
    }
    return $true
}

function Compare-HavocQaVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$QaRecord)

    $original = $QaRecord.comparison.original_audit
    $reviewer = $QaRecord.sealed_verdict.content
    $disagreements = [System.Collections.Generic.List[object]]::new()
    $materialFields = [System.Collections.Generic.List[string]]::new()

    $integrity = Test-HavocQaSealedVerdict -QaRecord $QaRecord
    if (-not $integrity.valid) {
        $materialFields.Add('sealed_verdict')
        $disagreements.Add([pscustomobject][ordered]@{
            field = 'sealed_verdict'
            classification = 'material'
            material = $true
            original_value = $integrity.actual_digest
            reviewer_value = $integrity.expected_digest
        })
    }

    $independence = Test-HavocQaReviewerIndependence `
        -Audit ([pscustomobject]@{
            audit_author_id = [string]$QaRecord.audit_author_id
            audit_context_id = [string]$QaRecord.review_context_id
        }) `
        -Reviewer ([pscustomobject]@{
            reviewer_id = [string]$QaRecord.reviewer_id
            shared_context_ids = @(Get-HavocArray -Value (Get-HavocPropertyValue $QaRecord 'shared_context_ids'))
            independence_basis = [string]$QaRecord.independence_basis
            authored_audit = $false
        })
    if (-not $independence.is_independent) {
        $materialFields.Add('reviewer_independence')
        $disagreements.Add([pscustomobject][ordered]@{
            field = 'reviewer_independence'
            classification = 'material'
            material = $true
            original_value = [string]$QaRecord.audit_author_id
            reviewer_value = [string]$QaRecord.reviewer_id
        })
    }

    $fieldMap = @(
        @{ Original = 'disposition'; Reviewer = 'disposition'; Output = 'disposition'; Material = $true },
        @{ Original = 'severity_band'; Reviewer = 'severity_band'; Output = 'severity_band'; Material = $true },
        @{ Original = 'causal_edges'; Reviewer = 'causal_edges'; Output = 'root_cause_edges'; Material = $true; Set = $true },
        @{ Original = 'soc_quality'; Reviewer = 'soc_quality'; Output = 'soc_quality'; Material = $false },
        @{ Original = 'recovery_validity'; Reviewer = 'recovery_validity'; Output = 'recovery_validity'; Material = $false }
    )

    foreach ($field in $fieldMap) {
        $left = Get-HavocPropertyValue $original $field.Original
        $right = Get-HavocPropertyValue $reviewer $field.Reviewer
        $isSetComparison = $field.ContainsKey('Set') -and [bool]$field.Set
        $same = if ($isSetComparison) { Compare-HavocArraySet $left $right } else { [string]$left -ceq [string]$right }
        if (-not $same) {
            if ($field.Material) { $materialFields.Add([string]$field.Output) }
            $disagreements.Add([pscustomobject][ordered]@{
                field = [string]$field.Output
                classification = if ($field.Material) { 'material' } else { 'minor' }
                material = [bool]$field.Material
                original_value = $left
                reviewer_value = $right
            })
        }
    }

    $originalRubric = [string]$QaRecord.comparison.rubric_version_original
    $reviewerRubric = [string]$QaRecord.rubric_version
    $rubricMismatch = $originalRubric -and $reviewerRubric -and ($originalRubric -cne $reviewerRubric)
    if ($rubricMismatch) {
        $disagreements.Add([pscustomobject][ordered]@{
            field = 'rubric_version'
            classification = 'minor'
            material = $false
            original_value = $originalRubric
            reviewer_value = $reviewerRubric
        })
    }

    $hasMaterial = $materialFields.Count -gt 0
    [pscustomobject][ordered]@{
        integrity_valid = [bool]$integrity.valid
        integrity_violations = @($integrity.violations)
        independence_valid = [bool]$independence.is_independent
        independence_reasons = @($independence.reasons)
        has_material_disagreement = $hasMaterial
        material_fields = @($materialFields)
        disagreements = @($disagreements)
        adjudication_state = if ($hasMaterial) { 'pending' } else { [string]$QaRecord.adjudication_state }
        adjudication_route = if ($hasMaterial) { 'human_adjudicator' } else { 'not_required' }
        final_status_allowed = -not $hasMaterial
        rubric_version_mismatch = [bool]$rubricMismatch
        rubric_versions = [pscustomobject][ordered]@{
            original = $originalRubric
            reviewer = $reviewerRubric
        }
    }
}

function Get-HavocQaAgreementMetric {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$PrimaryLabels,
        [Parameter(Mandatory)][string[]]$SecondaryLabels
    )

    if ($PrimaryLabels.Count -ne $SecondaryLabels.Count) {
        throw 'Primary and secondary label counts must match.'
    }
    $n = $PrimaryLabels.Count
    if ($n -eq 0) { throw 'At least one label pair is required.' }

    $agreements = 0
    $categories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($i = 0; $i -lt $n; $i++) {
        if ($PrimaryLabels[$i] -ceq $SecondaryLabels[$i]) { $agreements++ }
        [void]$categories.Add($PrimaryLabels[$i])
        [void]$categories.Add($SecondaryLabels[$i])
    }

    $po = $agreements / $n
    $pe = 0.0
    foreach ($category in $categories) {
        $primaryCount = @($PrimaryLabels | Where-Object { $_ -ceq $category }).Count
        $secondaryCount = @($SecondaryLabels | Where-Object { $_ -ceq $category }).Count
        $pe += ($primaryCount / $n) * ($secondaryCount / $n)
    }

    $kappa = if ([Math]::Abs(1.0 - $pe) -lt 0.0000000001) {
        if ([Math]::Abs(1.0 - $po) -lt 0.0000000001) { 1.0 } else { 0.0 }
    } else {
        ($po - $pe) / (1.0 - $pe)
    }

    [pscustomobject][ordered]@{
        item_count = $n
        agreement_count = $agreements
        percent_agreement = [Math]::Round($po, 10)
        expected_agreement = [Math]::Round($pe, 10)
        cohens_kappa = [Math]::Round($kappa, 10)
    }
}

Export-ModuleMember -Function @(
    'ConvertTo-HavocCanonicalJson',
    'Get-HavocQaContentDigest',
    'Test-HavocQaReviewerIndependence',
    'Test-HavocQaSealedVerdict',
    'Compare-HavocQaVerdict',
    'Get-HavocQaAgreementMetric'
)
