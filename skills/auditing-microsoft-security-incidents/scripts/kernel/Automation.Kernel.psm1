Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:AutomationActorTypes = @(
    'user',
    'service principal',
    'managed identity',
    'Sentinel automation rule',
    'Logic App playbook',
    'Defender AIR/automated investigation',
    'Copilot for Security or other AI assistant',
    'unknown'
)

$script:AutomationAuthorshipClasses = @(
    'human-authored',
    'automation-authored',
    'automation-recommended-human-approved',
    'human-overridden-automation',
    'automation-retried',
    'inherited-via-playbook',
    'unverified_actor',
    'unknown'
)

function Get-InputValue {
    param(
        [Parameter(Mandatory)][hashtable]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )

    if ($InputObject.ContainsKey($Name) -and $null -ne $InputObject[$Name]) {
        return $InputObject[$Name]
    }

    return $Default
}

function ConvertTo-StringArray {
    param($Value)

    return @(@(Get-HavocArray -Value $Value) | ForEach-Object { [string]$_ })
}

function ConvertTo-Rfc3339SecondString {
    param($Value)

    if ($null -eq $Value) { return $null }
    return Format-HavocTimestamp -Value (ConvertTo-HavocUtcTimestamp -Value $Value)
}

function Normalize-AutomationNestedRecord {
    param($Value)

    if ($null -eq $Value -or $Value -isnot [System.Collections.IDictionary]) { return $Value }

    $copy = [ordered]@{}
    foreach ($key in $Value.Keys) {
        $item = $Value[$key]
        if ($key -in @('recommended_at', 'overridden_at', 'handoff_time')) {
            $copy[$key] = ConvertTo-Rfc3339SecondString $item
        } else {
            $copy[$key] = $item
        }
    }

    return $copy
}

function Assert-AutomationProtectedReference {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][object]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not (Test-HavocProtectedReference -Value $Value)) {
        throw "$Name must be a protected reference."
    }
    return [string]$Value
}

function Test-NonHumanAutomationActor {
    param([Parameter(Mandatory)][string]$ActorType)

    return $ActorType -notin @('user', 'unknown')
}

function Test-InteractiveHumanEvidence {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$EvidenceIds,
        [AllowNull()][object]$EvidenceLedger
    )

    if ($EvidenceIds.Count -eq 0) { return $false }
    $ledgerItems = @(Get-HavocArray -Value $EvidenceLedger)
    if ($ledgerItems.Count -eq 0) { return $false }

    foreach ($evidenceId in $EvidenceIds) {
        $matched = $false
        foreach ($item in $ledgerItems) {
            $itemId = [string](Get-HavocProperty -InputObject $item -Name 'evidence_id')
            if ($itemId -cne $evidenceId) { continue }

            $typeValues = @()
            foreach ($fieldName in @('evidence_type', 'type', 'basis', 'authorship_basis')) {
                $typeValues += @(ConvertTo-StringArray (Get-HavocProperty -InputObject $item -Name $fieldName))
            }
            if ($typeValues -ccontains 'interactive-human-action' -or $typeValues -ccontains 'interactive_human_action') {
                $matched = $true
                break
            }
        }
        if (-not $matched) { return $false }
    }
    return $true
}

function Test-HumanAutomationActor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ActorType)

    return $ActorType -eq 'user'
}

function Get-AutomationAuthorshipClass {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$InputObject)

    $actorType = [string](Get-InputValue -InputObject $InputObject -Name 'actor_type' -Default 'unknown')
    $runningAsActorType = [string](Get-InputValue -InputObject $InputObject -Name 'running_as_actor_type' -Default 'unknown')
    $requested = [string](Get-InputValue -InputObject $InputObject -Name 'requested_authorship_class' -Default '')
    $interactiveHumanEvidenceIds = @(ConvertTo-StringArray (Get-InputValue -InputObject $InputObject -Name 'interactive_human_action_evidence_ids' -Default @()))
    $hasInteractiveHumanEvidence = Test-InteractiveHumanEvidence -EvidenceIds $interactiveHumanEvidenceIds -EvidenceLedger (Get-InputValue -InputObject $InputObject -Name 'evidence_ledger' -Default @())
    $hasOverride = $InputObject.ContainsKey('override') -and $null -ne $InputObject['override']
    $hasRecommendation = $InputObject.ContainsKey('recommendation') -and $null -ne $InputObject['recommendation']
    $retryCount = [int](Get-InputValue -InputObject $InputObject -Name 'retry_count' -Default 0)
    $nonHumanContext = (Test-NonHumanAutomationActor -ActorType $actorType) -or (Test-NonHumanAutomationActor -ActorType $runningAsActorType)

    if ($actorType -eq 'unknown') { return 'unknown' }
    if ($hasOverride) {
        $override = Get-InputValue -InputObject $InputObject -Name 'override' -Default @{}
        $overrideActorType = [string](Get-HavocProperty -InputObject $override -Name 'overridden_by_actor_type')
        if ($overrideActorType -eq 'user' -and $hasInteractiveHumanEvidence -and -not (Test-NonHumanAutomationActor -ActorType $runningAsActorType)) {
            return 'human-overridden-automation'
        }
        return 'unverified_actor'
    }
    if ($retryCount -gt 0) { return 'automation-retried' }
    if ($hasRecommendation -and $actorType -eq 'user') {
        if ($hasInteractiveHumanEvidence -and -not $nonHumanContext) { return 'automation-recommended-human-approved' }
        return 'unverified_actor'
    }
    if ($requested -eq 'inherited-via-playbook') { return 'inherited-via-playbook' }
    if (Test-HumanAutomationActor -ActorType $actorType) {
        if ($hasInteractiveHumanEvidence -and -not $nonHumanContext) { return 'human-authored' }
        return 'unverified_actor'
    }
    return 'automation-authored'
}

function New-AutomationProvenanceRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$InputObject)

    $actorType = [string](Get-InputValue -InputObject $InputObject -Name 'actor_type' -Default 'unknown')
    if ($script:AutomationActorTypes -notcontains $actorType) {
        throw "Unsupported actor_type '$actorType'."
    }
    if (-not $InputObject.ContainsKey('action_time') -or $null -eq $InputObject['action_time']) {
        throw 'action_time is required.'
    }

    $sourceRecordRef = Assert-AutomationProtectedReference -Value (Get-InputValue -InputObject $InputObject -Name 'source_record_ref' -Default 'not-applicable:no-source-record') -Name 'source_record_ref'
    $actorRef = Assert-AutomationProtectedReference -Value (Get-InputValue -InputObject $InputObject -Name 'actor_ref' -Default 'protected-evidence:actors/unknown') -Name 'actor_ref'
    $runningAsActorType = [string](Get-InputValue -InputObject $InputObject -Name 'running_as_actor_type' -Default 'unknown')
    if ($script:AutomationActorTypes -notcontains $runningAsActorType) {
        throw "Unsupported running_as_actor_type '$runningAsActorType'."
    }
    $runningAsActorRef = Assert-AutomationProtectedReference -Value (Get-InputValue -InputObject $InputObject -Name 'running_as_actor_ref' -Default 'not-applicable:no-delegated-context') -Name 'running_as_actor_ref'

    $authorshipClass = Get-AutomationAuthorshipClass -InputObject $InputObject
    if ($script:AutomationAuthorshipClasses -notcontains $authorshipClass) {
        throw "Unsupported authorship_class '$authorshipClass'."
    }

    $gapIds = @(ConvertTo-StringArray (Get-InputValue -InputObject $InputObject -Name 'gap_ids' -Default @()))
    $errorIds = @(ConvertTo-StringArray (Get-InputValue -InputObject $InputObject -Name 'error_ids' -Default @()))
    $claimIds = @(ConvertTo-StringArray (Get-InputValue -InputObject $InputObject -Name 'claim_ids' -Default @('C-AUTO-PROVENANCE')))
    $evidenceIds = @(ConvertTo-StringArray (Get-InputValue -InputObject $InputObject -Name 'evidence_ids' -Default @()))
    $interactiveHumanEvidenceIds = @(ConvertTo-StringArray (Get-InputValue -InputObject $InputObject -Name 'interactive_human_action_evidence_ids' -Default @()))

    $unknownExplicit = $authorshipClass -in @('unknown', 'unverified_actor')
    if ($unknownExplicit -and $gapIds -notcontains 'G-AUTO-AUTHORSHIP-UNKNOWN') {
        $gapIds += 'G-AUTO-AUTHORSHIP-UNKNOWN'
    }
    if ($authorshipClass -eq 'unverified_actor' -and $gapIds -notcontains 'G-AUTO-HUMAN-EVIDENCE-MISSING') {
        $gapIds += 'G-AUTO-HUMAN-EVIDENCE-MISSING'
    }

    $effectiveVersion = [string](Get-InputValue -InputObject $InputObject -Name 'effective_version' -Default '')
    $currentVersion = [string](Get-InputValue -InputObject $InputObject -Name 'current_version' -Default '')
    $version = if ($effectiveVersion) { $effectiveVersion } elseif ($currentVersion) { $currentVersion } else { 'unknown' }
    $versionSelection = if ($effectiveVersion) { 'effective_at_action_time' } elseif ($currentVersion) { 'current_version_used_effective_missing' } else { 'not_observed' }

    if ((Get-InputValue -InputObject $InputObject -Name 'playbook_rule_ref' -Default '') -and -not $effectiveVersion -and $gapIds -notcontains 'G-AUTO-VERSION-EFFECTIVE-MISSING') {
        $gapIds += 'G-AUTO-VERSION-EFFECTIVE-MISSING'
    }

    $isAi = $actorType -eq 'Copilot for Security or other AI assistant'
    $hasInteractiveHumanEvidence = Test-InteractiveHumanEvidence -EvidenceIds $interactiveHumanEvidenceIds -EvidenceLedger (Get-InputValue -InputObject $InputObject -Name 'evidence_ledger' -Default @())
    if (-not $hasInteractiveHumanEvidence) {
        $interactiveHumanEvidenceIds = @()
    }
    $isHumanActor = (Test-HumanAutomationActor -ActorType $actorType) -and -not (Test-NonHumanAutomationActor -ActorType $runningAsActorType) -and $hasInteractiveHumanEvidence -and $authorshipClass -eq 'human-authored'
    $analystCreditAllowed = $isHumanActor -and -not $isAi -and $authorshipClass -eq 'human-authored'

    $recommendation = Normalize-AutomationNestedRecord (Get-InputValue -InputObject $InputObject -Name 'recommendation' -Default $null)
    $override = Normalize-AutomationNestedRecord (Get-InputValue -InputObject $InputObject -Name 'override' -Default $null)
    $executionState = if ($recommendation -and -not $override) { 'recommendation_only' } elseif ($actorType -eq 'unknown') { 'unknown' } else { 'executed' }
    if ($override) { $executionState = 'recommendation_only' }

    $humanAction = if ($override -and $authorshipClass -eq 'human-overridden-automation') {
        'Override recorded with recommendation and override timestamps.'
    } elseif ($analystCreditAllowed) {
        'Human-authored action; analyst reasoning credit may be considered only with cited decision-time evidence.'
    } elseif ($authorshipClass -eq 'unverified_actor') {
        'User-context action without cited interactive human action evidence; analyst reasoning credit is not allowed.'
    } else {
        'No analyst reasoning credit from this automation-authored or unknown-authored record.'
    }

    $playbookRuleVersion = [ordered]@{
        identity_ref = Assert-AutomationProtectedReference -Value (Get-InputValue -InputObject $InputObject -Name 'playbook_rule_ref' -Default 'not-applicable:automation-rule') -Name 'playbook_rule_ref'
        effective_version_ref = Assert-AutomationProtectedReference -Value (Get-InputValue -InputObject $InputObject -Name 'effective_version_ref' -Default 'not-applicable:effective-version') -Name 'effective_version_ref'
        current_version_ref = Assert-AutomationProtectedReference -Value (Get-InputValue -InputObject $InputObject -Name 'current_version_ref' -Default 'not-applicable:current-version') -Name 'current_version_ref'
        effective_version = if ($effectiveVersion) { $effectiveVersion } else { 'unknown' }
        current_version = if ($currentVersion) { $currentVersion } else { 'unknown' }
        version_selection = $versionSelection
    }

    $handoffChain = @(Get-InputValue -InputObject $InputObject -Name 'handoff_chain' -Default @())
    if ($handoffChain.Count -eq 0) {
        $handoffChain = @([ordered]@{
            from_actor_ref = $actorRef
            to_actor_ref = 'not-applicable:no-handoff'
            handoff_time = ConvertTo-Rfc3339SecondString (Get-InputValue -InputObject $InputObject -Name 'action_time')
            basis = 'direct_action_record'
        })
    }

    $actionText = [string](Get-InputValue -InputObject $InputObject -Name 'action' -Default 'automation action')
    $actionTime = ConvertTo-Rfc3339SecondString (Get-InputValue -InputObject $InputObject -Name 'action_time')
    $automationId = Get-HavocStableId -Prefix 'AUTO' -Parts @($actionText, $actionTime, $actorRef, $sourceRecordRef)

    $record = [ordered]@{
        automation_id = $automationId
        action = $actionText
        action_time = $actionTime
        source_product = [string](Get-InputValue -InputObject $InputObject -Name 'source_product' -Default 'unknown')
        actor_type = $actorType
        actor_ref = $actorRef
        actor = $actorType
        running_as_actor_type = $runningAsActorType
        running_as_actor_ref = $runningAsActorRef
        is_human_actor = $isHumanActor
        authorship_class = $authorshipClass
        unknown_authorship_explicit = $unknownExplicit
        analyst_reasoning_credit_allowed = $analystCreditAllowed
        ai_generated_content = $isAi
        evidence_trust_label = if ($isAi) { 'untrusted_ai_generated_evidence' } else { 'untrusted_evidence' }
        playbook_rule_version = $playbookRuleVersion
        version = $version
        execution_state = $executionState
        recommendation = if ($recommendation) { $recommendation } else { [ordered]@{ status = 'not_observed'; detail = 'No automation recommendation was observed.' } }
        override = if ($override) { $override } else { [ordered]@{ status = 'not_observed'; detail = 'No human override was observed.' } }
        retry = [ordered]@{
            retry_count = [int](Get-InputValue -InputObject $InputObject -Name 'retry_count' -Default 0)
            retry_state = if ([int](Get-InputValue -InputObject $InputObject -Name 'retry_count' -Default 0) -gt 0) { 'observed' } else { 'not_observed' }
        }
        handoff_chain = @($handoffChain)
        interactive_human_action_evidence_ids = @($interactiveHumanEvidenceIds)
        input_evidence_ids = @($evidenceIds)
        output_summary = "Automation provenance classified '$($authorshipClass)' for '$actionText'."
        human_action = $humanAction
        claim_ids = @($claimIds)
        gap_ids = @($gapIds | Select-Object -Unique)
        error_ids = @($errorIds | Select-Object -Unique)
        behavior_bases = @('configurable_project_policy')
    }

    return [pscustomobject]$record
}

function ConvertTo-AuditAutomationRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$AutomationRecord)

    process {
        [pscustomobject][ordered]@{
            automation_id = [string]$AutomationRecord.automation_id
            actor = [string]$AutomationRecord.actor
            version = [string]$AutomationRecord.version
            execution_state = [string]$AutomationRecord.execution_state
            input_evidence_ids = @($AutomationRecord.input_evidence_ids)
            output_summary = [string]$AutomationRecord.output_summary
            human_action = [string]$AutomationRecord.human_action
            claim_ids = @($AutomationRecord.claim_ids)
            gap_ids = @($AutomationRecord.gap_ids)
            error_ids = @($AutomationRecord.error_ids)
            behavior_bases = @($AutomationRecord.behavior_bases)
        }
    }
}

Export-ModuleMember -Function New-AutomationProvenanceRecord, ConvertTo-AuditAutomationRecord, Test-HumanAutomationActor
