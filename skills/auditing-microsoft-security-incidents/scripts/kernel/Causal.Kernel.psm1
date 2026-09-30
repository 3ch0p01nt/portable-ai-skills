Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

function New-KernelValidationResult {
    param([object[]]$Errors)
    [pscustomobject]@{
        IsValid = (@($Errors).Count -eq 0)
        Errors = @($Errors)
    }
}

function New-KernelError {
    param([string]$Rule, [string]$Message, [string]$RecordId = '')
    [pscustomobject]@{
        Rule = $Rule
        Message = $Message
        RecordId = $RecordId
    }
}

function Get-PropertyValue {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name)
    Get-HavocProperty -InputObject $Object -Name $Name
}

function Get-ArrayValue {
    param($Value)
    @(Get-HavocArray -Value $Value)
}

function Test-HypothesisSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $errors = [System.Collections.Generic.List[object]]::new()
    $hypotheses = Get-ArrayValue (Get-PropertyValue $InputObject 'hypotheses')
    $active = @($hypotheses | Where-Object { -not [bool](Get-PropertyValue $_ 'ruled_out') })
    $ruledOut = @($hypotheses | Where-Object { [bool](Get-PropertyValue $_ 'ruled_out') })

    $hasMalicious = @($active | Where-Object { (Get-PropertyValue $_ 'hypothesis_type') -ceq 'malicious' }).Count -gt 0
    $hasBenign = @($active | Where-Object { (Get-PropertyValue $_ 'hypothesis_type') -ceq 'benign_expected' }).Count -gt 0
    $maliciousRuledOut = @($ruledOut | Where-Object { (Get-PropertyValue $_ 'hypothesis_type') -ceq 'malicious' -and @(Get-ArrayValue (Get-PropertyValue $_ 'rule_out_evidence_ids')).Count -gt 0 }).Count -gt 0
    $benignRuledOut = @($ruledOut | Where-Object { (Get-PropertyValue $_ 'hypothesis_type') -ceq 'benign_expected' -and @(Get-ArrayValue (Get-PropertyValue $_ 'rule_out_evidence_ids')).Count -gt 0 }).Count -gt 0
    if (-not (($hasMalicious -or $maliciousRuledOut) -and ($hasBenign -or $benignRuledOut))) {
        $errors.Add((New-KernelError -Rule 'hypothesis.minimum_malicious_and_benign' -Message 'At least one malicious and one benign/expected hypothesis must be active or explicitly ruled out with cited evidence.'))
    }

    foreach ($hypothesis in $hypotheses) {
        $likelihood = Get-PropertyValue $hypothesis 'likelihood'
        $confidence = Get-PropertyValue $hypothesis 'analytic_confidence'
        if ([string]::IsNullOrWhiteSpace($likelihood) -or [string]::IsNullOrWhiteSpace($confidence)) {
            $errors.Add((New-KernelError -Rule 'hypothesis.likelihood_confidence_separate' -Message 'Likelihood and analytic confidence must be separate populated fields.' -RecordId (Get-PropertyValue $hypothesis 'hypothesis_id')))
        }
        $human = Get-PropertyValue $hypothesis 'human_attribution_confidence'
        $intent = Get-PropertyValue $hypothesis 'intent_confidence'
        if ($human -in @('moderate', 'high') -or $intent -in @('moderate', 'high')) {
            $errors.Add((New-KernelError -Rule 'attribution.technical_logs_limit_human_intent' -Message 'Technical hypothesis records must not elevate human attribution or intent above low confidence without an authorized human review field.' -RecordId (Get-PropertyValue $hypothesis 'hypothesis_id')))
        }
    }

    foreach ($row in (Get-ArrayValue (Get-PropertyValue $InputObject 'diagnostic_evidence_matrix'))) {
        $ratings = @()
        $consistency = Get-PropertyValue $row 'consistency_by_hypothesis'
        if ($null -ne $consistency) {
            foreach ($property in $consistency.PSObject.Properties) {
                $ratings += [string]$property.Value
            }
        }
        $unique = @($ratings | Sort-Object -Unique)
        if ($ratings.Count -gt 1 -and $unique.Count -eq 1 -and $unique[0] -eq 'consistent' -and (Get-PropertyValue $row 'diagnosticity') -ne 'low') {
            $errors.Add((New-KernelError -Rule 'hypothesis.common_evidence_low_diagnosticity' -Message 'Evidence consistent with all hypotheses has low diagnosticity and cannot drive ranking.' -RecordId (Get-PropertyValue $row 'evidence_id')))
        }
    }

    New-KernelValidationResult -Errors $errors
}

function Get-HypothesisRanking {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($row in (Get-ArrayValue (Get-PropertyValue $InputObject 'diagnostic_evidence_matrix'))) {
        if ((Get-PropertyValue $row 'diagnosticity') -eq 'low') { continue }
        $ratings = @()
        $consistency = Get-PropertyValue $row 'consistency_by_hypothesis'
        if ($null -ne $consistency) {
            foreach ($property in $consistency.PSObject.Properties) { $ratings += [string]$property.Value }
        }
        $unique = @($ratings | Sort-Object -Unique)
        if ($ratings.Count -gt 1 -and $unique.Count -eq 1 -and $unique[0] -eq 'consistent') { continue }
        $ids.Add([string](Get-PropertyValue $row 'evidence_id'))
    }
    [pscustomobject]@{ RankingEvidenceIds = @($ids | Sort-Object -Unique) }
}

function ConvertTo-HypothesisAuditRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    [pscustomobject]@{
        hypothesis_id = Get-PropertyValue $InputObject 'hypothesis_id'
        statement = Get-PropertyValue $InputObject 'statement'
        likelihood = Get-PropertyValue $InputObject 'likelihood'
        analytic_confidence = Get-PropertyValue $InputObject 'analytic_confidence'
        supporting_evidence_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'supporting_evidence_ids')
        contradicting_evidence_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'contradicting_evidence_ids')
        information_needed = Get-ArrayValue (Get-PropertyValue $InputObject 'information_needed')
        claim_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'claim_ids')
        gap_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'gap_ids')
        error_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'error_ids')
        behavior_bases = Get-ArrayValue (Get-PropertyValue $InputObject 'behavior_bases')
        hypothesis_type = Get-PropertyValue $InputObject 'hypothesis_type'
        human_attribution_confidence = Get-PropertyValue $InputObject 'human_attribution_confidence'
        intent_confidence = Get-PropertyValue $InputObject 'intent_confidence'
        accountability_confidence = Get-PropertyValue $InputObject 'accountability_confidence'
    }
}

function ConvertTo-CausalAuditRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    [pscustomobject]@{
        causal_id = Get-PropertyValue $InputObject 'edge_id'
        from_ref = Get-PropertyValue $InputObject 'from_ref'
        to_ref = Get-PropertyValue $InputObject 'to_ref'
        relationship_basis = Get-PropertyValue $InputObject 'relationship_basis'
        statement = Get-PropertyValue $InputObject 'statement'
        claim_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'claim_ids')
        evidence_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'evidence_ids')
        gap_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'gap_ids')
        error_ids = Get-ArrayValue (Get-PropertyValue $InputObject 'error_ids')
        behavior_bases = Get-ArrayValue (Get-PropertyValue $InputObject 'behavior_bases')
        edge_type = Get-PropertyValue $InputObject 'edge_type'
    }
}

function Test-CausalGraph {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $errors = [System.Collections.Generic.List[object]]::new()
    $edges = Get-ArrayValue (Get-PropertyValue $InputObject 'edges')
    $nodes = Get-ArrayValue (Get-PropertyValue $InputObject 'nodes')
    $nodeIds = @($nodes | ForEach-Object { [string](Get-PropertyValue $_ 'node_id') })
    $allowedEdges = @('association', 'mechanism-supported', 'intervention-supported', 'counterfactual')

    foreach ($edge in $edges) {
        $edgeId = [string](Get-PropertyValue $edge 'edge_id')
        $edgeType = [string](Get-PropertyValue $edge 'edge_type')
        if (-not ($allowedEdges -ccontains $edgeType)) {
            $errors.Add((New-KernelError -Rule 'causal.edge_type_enum' -Message 'Causal edge type is outside the closed enum.' -RecordId $edgeId))
        }
        $timestampsValid = $true
        try {
            $cause = ConvertTo-HavocUtcTimestamp -Value (Get-PropertyValue $edge 'cause_time')
            $effect = ConvertTo-HavocUtcTimestamp -Value (Get-PropertyValue $edge 'effect_time')
        }
        catch {
            $timestampsValid = $false
            $errors.Add((New-KernelError -Rule 'causal.timestamp_parse' -Message 'Causal edge timestamps must be RFC 3339 with explicit offsets.' -RecordId $edgeId))
        }
        if ($timestampsValid) {
            $uncertainty = [int](Get-PropertyValue $edge 'time_uncertainty_seconds')
            $causeEarliest = $cause.AddSeconds(-1 * $uncertainty)
            $causeLatest = $cause.AddSeconds($uncertainty)
            $effectEarliest = $effect.AddSeconds(-1 * $uncertainty)
            $effectLatest = $effect.AddSeconds($uncertainty)
            if ($causeEarliest -gt $effectLatest) {
                $errors.Add((New-KernelError -Rule 'causal.temporal_precedence' -Message 'Causal edge requires the cause window to precede the effect window.' -RecordId $edgeId))
            }
            elseif ($causeLatest -gt $effectEarliest) {
                $errors.Add((New-KernelError -Rule 'causal.precedence_uncertain' -Message 'Overlapping cause and effect uncertainty windows cannot establish temporal precedence for a causal claim.' -RecordId $edgeId))
            }
        }
        if ($edgeType -eq 'mechanism-supported' -and @(Get-ArrayValue (Get-PropertyValue $edge 'mechanism_evidence_ids')).Count -eq 0) {
            $errors.Add((New-KernelError -Rule 'causal.mechanism_requires_citation' -Message 'Mechanism-supported edges require cited mechanism evidence.' -RecordId $edgeId))
        }
        if ($edgeType -ne 'association') {
            $mechanismLineage = @(Get-ArrayValue (Get-PropertyValue $edge 'mechanism_lineage_ids'))
            $corroborationLineage = @(Get-ArrayValue (Get-PropertyValue $edge 'corroboration_lineage_ids'))
            $independent = @($corroborationLineage | Where-Object { $_ -cnotin $mechanismLineage })
            if ($corroborationLineage.Count -eq 0 -or $independent.Count -eq 0) {
                $errors.Add((New-KernelError -Rule 'causal.independent_corroboration' -Message 'Causal claims beyond association require independent corroboration outside the same upstream lineage.' -RecordId $edgeId))
            }
        }
        if ($edgeType -eq 'association' -and [bool](Get-PropertyValue $edge 'is_root_cause')) {
            $errors.Add((New-KernelError -Rule 'causal.association_not_root_cause' -Message 'An association-only edge cannot be named root cause.' -RecordId $edgeId))
        }
        if (-not ($nodeIds -ccontains (Get-PropertyValue $edge 'from_ref')) -or -not ($nodeIds -ccontains (Get-PropertyValue $edge 'to_ref'))) {
            $errors.Add((New-KernelError -Rule 'causal.edge_endpoint_exists' -Message 'Causal edge endpoints must resolve to nodes.' -RecordId $edgeId))
        }
    }

    $requiredRoles = @('proximate_event', 'entry_vector', 'enabling_technical_condition', 'failed_control', 'organizational_process_cause', 'latent_systemic_condition')
    $factors = Get-ArrayValue (Get-PropertyValue $InputObject 'root_cause_factors')
    foreach ($role in $requiredRoles) {
        $matches = @($factors | Where-Object { (Get-PropertyValue $_ 'role') -ceq $role })
        if ($matches.Count -eq 0) {
            $errors.Add((New-KernelError -Rule 'causal.root_cause_roles_explicit' -Message "Missing root-cause role must be represented as a present factor or explicit gap: $role." -RecordId $role))
        }
    }

    if (Test-CausalCycle -Edges $edges -NodeIds $nodeIds) {
        $errors.Add((New-KernelError -Rule 'causal.graph_acyclic' -Message 'Causal graph must be acyclic.'))
    }

    $attribution = Get-PropertyValue $InputObject 'attribution'
    if ($null -ne $attribution -and [bool](Get-PropertyValue $attribution 'technical_logs_only')) {
        foreach ($field in @('human_attribution_confidence', 'intent_confidence', 'accountability_confidence')) {
            $value = [string](Get-PropertyValue $attribution $field)
            if ($value -in @('moderate', 'high')) {
                $errors.Add((New-KernelError -Rule 'attribution.technical_logs_limit_human_intent' -Message 'Technical logs alone cannot set human attribution, intent, or accountability above low confidence.' -RecordId $field))
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace([string](Get-PropertyValue $InputObject 'graph_likelihood')) -or [string]::IsNullOrWhiteSpace([string](Get-PropertyValue $InputObject 'analytic_confidence'))) {
        $errors.Add((New-KernelError -Rule 'causal.likelihood_confidence_separate' -Message 'Graph likelihood and analytic confidence must be separate populated fields.'))
    }

    New-KernelValidationResult -Errors $errors
}

function Test-CausalCycle {
    param([object[]]$Edges, [string[]]$NodeIds)
    $adjacency = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new([System.StringComparer]::Ordinal)
    foreach ($nodeId in $NodeIds) { $adjacency[$nodeId] = [System.Collections.Generic.List[string]]::new() }
    foreach ($edge in $Edges) {
        $from = [string](Get-PropertyValue $edge 'from_ref')
        $to = [string](Get-PropertyValue $edge 'to_ref')
        if ($adjacency.ContainsKey($from)) { $adjacency[$from].Add($to) }
    }
    $visiting = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    function Visit-Node {
        param([string]$Node)
        if ($visiting.Contains($Node)) { return $true }
        if ($visited.Contains($Node)) { return $false }
        [void]$visiting.Add($Node)
        foreach ($next in (Get-ArrayValue $adjacency[$Node])) {
            if (Visit-Node -Node $next) { return $true }
        }
        [void]$visiting.Remove($Node)
        [void]$visited.Add($Node)
        return $false
    }

    foreach ($node in $NodeIds) {
        if (Visit-Node -Node $node) { return $true }
    }
    return $false
}

Export-ModuleMember -Function Test-HypothesisSet, Get-HypothesisRanking, ConvertTo-HypothesisAuditRecord, Test-CausalGraph, ConvertTo-CausalAuditRecord
