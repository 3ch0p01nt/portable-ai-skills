Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:DefectClasses = @(
    'rule-logic',
    'data-quality',
    'entity-mapping',
    'grouping',
    'enrichment',
    'execution-health'
)

function Get-DetectionArray {
    param([AllowNull()][object]$Value)
    return @(Get-HavocArray -Value $Value)
}

function Get-DetectionProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    return Get-HavocProperty -InputObject $InputObject -Name $Name
}

function Get-DetectionNestedProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Path
    )
    $current = $InputObject
    foreach ($name in $Path) {
        if ($null -eq $current) { return $null }
        $current = Get-DetectionProperty -InputObject $current -Name $name
    }
    return $current
}

function Get-DetectionEvidenceId {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Fallback
    )
    foreach ($name in @('evidenceId', 'evidence_id', 'RecordId', 'recordId', 'id', 'name', 'providerAlertId')) {
        $value = Get-DetectionProperty -InputObject $InputObject -Name $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return [string]$value }
    }
    return $Fallback
}

function New-DetectionTraceHop {
    param(
        [Parameter(Mandatory)][string]$Hop,
        [Parameter(Mandatory)][ValidateSet('present', 'missing', 'mismatch')][string]$Status,
        [string[]]$EvidenceIds = @(),
        [string]$Rationale
    )
    [pscustomobject][ordered]@{
        hop = $Hop
        status = $Status
        evidenceIds = @(Get-DetectionArray $EvidenceIds | ForEach-Object { [string]$_ })
        rationale = $Rationale
    }
}

function New-DetectionFinding {
    param(
        [Parameter(Mandatory)][ValidateSet('rule-logic', 'data-quality', 'entity-mapping', 'grouping', 'enrichment', 'execution-health')][string]$DefectClass,
        [Parameter(Mandatory)][ValidateSet('low', 'medium', 'high')][string]$Severity,
        [Parameter(Mandatory)][string]$Rationale,
        [string[]]$EvidenceIds = @()
    )
    [pscustomobject][ordered]@{
        defectClass = $DefectClass
        severity = $Severity
        rationale = $Rationale
        evidenceIds = @(Get-DetectionArray $EvidenceIds | ForEach-Object { [string]$_ })
    }
}

function New-DetectionCoverageGap {
    param(
        [Parameter(Mandatory)][string]$GapType,
        [Parameter(Mandatory)][string]$Rationale,
        [string[]]$AffectedHops = @()
    )
    [pscustomobject][ordered]@{
        gapType = $GapType
        rationale = $Rationale
        affectedHops = @(Get-DetectionArray $AffectedHops | ForEach-Object { [string]$_ })
    }
}

function Get-DetectionRuleProperties {
    param([AllowNull()][object]$Rule)
    $properties = Get-DetectionProperty -InputObject $Rule -Name 'properties'
    if ($null -ne $properties) { return $properties }
    return $Rule
}

function Get-DetectionRuleId {
    param([AllowNull()][object]$Rule)
    foreach ($path in @(
        @('id'),
        @('properties', 'id'),
        @('name')
    )) {
        $value = Get-DetectionNestedProperty -InputObject $Rule -Path $path
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return [string]$value }
    }
    return $null
}

function Get-DetectionColumnsFromQuery {
    param([AllowNull()][AllowEmptyString()][string]$Query)
    $set = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }

    $matches = [regex]::Matches($Query, '(?i)\|\s*(?:project|project-away|extend|summarize)\s+([^|]+)')
    foreach ($match in $matches) {
        $segment = $match.Groups[1].Value
        foreach ($part in ($segment -split ',')) {
            $candidate = ($part -split '=', 2)[0].Trim()
            if ($candidate -match '^(?<name>[A-Za-z_][A-Za-z0-9_]*)') {
                [void]$set.Add($Matches.name)
            }
        }
    }
    return @($set)
}

function Get-DetectionTablesFromQuery {
    param([AllowNull()][AllowEmptyString()][string]$Query)
    $set = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }
    foreach ($statement in ($Query -split ';')) {
        $trimmed = $statement.Trim()
        if ($trimmed -match '^(?<table>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\||$)') {
            [void]$set.Add($Matches.table)
        }
    }
    return @($set)
}

function Get-DetectionEntityMappings {
    param([AllowNull()][object]$RuleProperties)
    $mapped = [System.Collections.Generic.List[object]]::new()
    foreach ($mapping in Get-DetectionArray (Get-DetectionProperty -InputObject $RuleProperties -Name 'entityMappings')) {
        $entityType = [string](Get-DetectionProperty -InputObject $mapping -Name 'entityType')
        $columns = foreach ($field in Get-DetectionArray (Get-DetectionProperty -InputObject $mapping -Name 'fieldMappings')) {
            $columnName = [string](Get-DetectionProperty -InputObject $field -Name 'columnName')
            if (-not [string]::IsNullOrWhiteSpace($columnName)) { $columnName }
        }
        $mapped.Add([pscustomobject][ordered]@{
            entityType = $entityType
            columns = @($columns)
        })
    }
    return @($mapped)
}

function Get-DetectionRawColumns {
    param([AllowNull()][object]$RawEventSample)
    $columns = @(Get-DetectionArray (Get-DetectionProperty -InputObject $RawEventSample -Name 'columns') |
        ForEach-Object { [string]$_ })
    if ($columns.Count -gt 0) { return @($columns) }
    $rows = @(Get-DetectionArray (Get-DetectionProperty -InputObject $RawEventSample -Name 'rows'))
    if ($rows.Count -eq 0) { return @() }
    return @($rows[0].PSObject.Properties.Name)
}

function Test-DetectionContains {
    param(
        [AllowNull()][object[]]$Values,
        [AllowNull()][string]$Expected
    )
    if ([string]::IsNullOrWhiteSpace($Expected)) { return $false }
    foreach ($value in Get-DetectionArray $Values) {
        if ([string]::Equals([string]$value, $Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-DetectionGraphEvidenceEntityType {
    param([AllowNull()][object]$Evidence)
    $odataType = [string](Get-DetectionProperty -InputObject $Evidence -Name '@odata.type')
    if ([string]::IsNullOrWhiteSpace($odataType)) { return $null }
    $typeName = ($odataType -replace '^#microsoft\.graph\.security\.', '') -replace 'Evidence$', ''
    $map = @{
        user = 'Account'
        device = 'Host'
        ip = 'IP'
        url = 'URL'
        file = 'File'
        process = 'Process'
        mailbox = 'Mailbox'
        cloudApplication = 'CloudApplication'
        oauthApplication = 'CloudApplication'
        registryKey = 'RegistryKey'
        registryValue = 'RegistryValue'
        securityGroup = 'SecurityGroup'
        mailboxConfiguration = 'Mailbox'
        amazonResource = 'CloudResource'
        azureResource = 'AzureResource'
        googleCloudResource = 'CloudResource'
        kubernetesCluster = 'KubernetesCluster'
        kubernetesNamespace = 'KubernetesNamespace'
        kubernetesPod = 'KubernetesPod'
        containerImage = 'ContainerImage'
        container = 'Container'
    }
    if ($map.ContainsKey($typeName)) { return $map[$typeName] }
    return $null
}

function Get-DetectionAlertEntityTypes {
    param([AllowNull()][object]$Alert)
    foreach ($entity in Get-DetectionArray (Get-DetectionProperty -InputObject $Alert -Name 'entities')) {
        $kind = Get-DetectionProperty -InputObject $entity -Name 'kind'
        if ([string]::IsNullOrWhiteSpace([string]$kind)) { $kind = Get-DetectionProperty -InputObject $entity -Name 'entityType' }
        if (-not [string]::IsNullOrWhiteSpace([string]$kind)) { [string]$kind }
    }
    foreach ($evidence in Get-DetectionArray (Get-DetectionProperty -InputObject $Alert -Name 'evidence')) {
        $mapped = Get-DetectionGraphEvidenceEntityType -Evidence $evidence
        if (-not [string]::IsNullOrWhiteSpace($mapped)) { $mapped }
    }
}

function Get-DetectionAlertRuleIdentifiers {
    param([AllowNull()][object]$Alert)
    foreach ($name in @('alertRuleId', 'AlertRuleId', 'analyticsRuleId', 'analyticRuleId', 'ruleId')) {
        $value = Get-DetectionProperty -InputObject $Alert -Name $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { [string]$value }
    }
    $extended = Get-DetectionProperty -InputObject $Alert -Name 'ExtendedProperties'
    if ($null -eq $extended) { $extended = Get-DetectionProperty -InputObject $Alert -Name 'extendedProperties' }
    foreach ($name in @('Analytic Rule Ids', 'Analytic Rule Id', 'Analytics Rule Ids', 'Analytics Rule Id', 'AlertRuleId', 'alertRuleId')) {
        $value = Get-DetectionProperty -InputObject $extended -Name $name
        foreach ($item in Get-DetectionArray $value) {
            $text = [string]$item
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            foreach ($part in ($text -split '[,;]')) {
                if (-not [string]::IsNullOrWhiteSpace($part)) { $part.Trim() }
            }
        }
    }
}

function Get-DetectionPlaceholders {
    param([AllowNull()][object]$Override)
    $set = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Override) { return @() }
    foreach ($property in $Override.PSObject.Properties) {
        foreach ($match in [regex]::Matches([string]$property.Value, '\{\{\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\}\}')) {
            [void]$set.Add($match.Groups['name'].Value)
        }
    }
    return @($set)
}

function New-HavocDetectionQualityAudit {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Incident,
        [AllowNull()][object[]]$Alerts,
        [AllowNull()][object]$Rule,
        [AllowNull()][object[]]$HealthRecords,
        [AllowNull()][object[]]$AuditRecords,
        [AllowNull()][object]$RawEventSample
    )

    $alertsArray = @(Get-DetectionArray $Alerts)
    $healthArray = @(Get-DetectionArray $HealthRecords)
    $auditArray = @(Get-DetectionArray $AuditRecords)
    $ruleProperties = Get-DetectionRuleProperties -Rule $Rule
    $ruleId = Get-DetectionRuleId -Rule $Rule
    $ruleName = [string](Get-DetectionProperty -InputObject $Rule -Name 'name')
    $ruleEvidenceId = if ($null -ne $Rule) { if ($ruleId) { $ruleId } else { Get-DetectionEvidenceId -InputObject $Rule -Fallback 'rule-supplied' } } else { $null }
    $query = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'query')
    $projected = @(Get-DetectionColumnsFromQuery -Query $query)
    $queryTables = @(Get-DetectionTablesFromQuery -Query $query)
    $rawColumns = @(Get-DetectionRawColumns -RawEventSample $RawEventSample)
    $hasRawSample = $null -ne $RawEventSample -and $rawColumns.Count -gt 0
    $entityMappings = @(Get-DetectionEntityMappings -RuleProperties $ruleProperties)
    $requiredMappingColumns = @($entityMappings | ForEach-Object { $_.columns } | Sort-Object -Unique)
    $requiredIdentifiers = @($projected + $requiredMappingColumns | Sort-Object -Unique)
    $missingRawColumns = @(if ($hasRawSample) { $requiredIdentifiers | Where-Object { -not (Test-DetectionContains -Values $rawColumns -Expected $_) } })
    $ruleTechniques = @(Get-DetectionArray (Get-DetectionProperty -InputObject $ruleProperties -Name 'techniques') | ForEach-Object { [string]$_ })
    $ruleTactics = @(Get-DetectionArray (Get-DetectionProperty -InputObject $ruleProperties -Name 'tactics') | ForEach-Object { [string]$_ })
    $ruleSeverity = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'severity')
    $incidentProperties = Get-DetectionRuleProperties -Rule $Incident
    $incidentSeverity = [string](Get-DetectionProperty -InputObject $incidentProperties -Name 'severity')

    $findings = [System.Collections.Generic.List[object]]::new()
    $coverageGaps = [System.Collections.Generic.List[object]]::new()
    $trace = [System.Collections.Generic.List[object]]::new()

    if ($null -eq $Rule) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_rule_record' -Rationale 'The generating analytics rule record was not supplied, so rule logic, version, mapping, grouping, and enrichment cannot be assessed.' -AffectedHops @('generating_rule', 'deployed_query_version', 'entity_mappings', 'grouping', 'enrichment')))
    }
    if ($healthArray.Count -eq 0) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_execution_health' -Rationale 'No SentinelHealth rows were supplied for rule execution evidence.' -AffectedHops @('execution_health')))
    }
    if ($auditArray.Count -eq 0) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_change_audit' -Rationale 'No SentinelAudit rows were supplied for rule change evidence.' -AffectedHops @('deployed_query_version')))
    }
    if (-not $hasRawSample) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_raw_event_sample' -Rationale 'No raw event sample was supplied to confirm schema, projected identifiers, and connector assumptions.' -AffectedHops @('raw_events', 'entity_mappings')))
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'safe_replay_evidence_not_supplied' -Rationale 'Historical replay is out of scope; the supplied record set did not include safe replay evidence.' -AffectedHops @('raw_events')))
    }
    if ($null -ne $Rule -and $entityMappings.Count -eq 0) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_entity_mappings' -Rationale 'The rule record did not include entity mappings.' -AffectedHops @('entity_mappings')))
    }

    $incidentEvidence = if ($null -ne $Incident) { @(Get-DetectionEvidenceId -InputObject $Incident -Fallback 'incident-supplied') } else { @() }
    $trace.Add((New-DetectionTraceHop -Hop 'incident' -Status $(if ($null -ne $Incident) { 'present' } else { 'missing' }) -EvidenceIds $incidentEvidence -Rationale 'Incident record supplied to the pure audit function.'))

    $alertEvidence = @($alertsArray | ForEach-Object { Get-DetectionEvidenceId -InputObject $_ -Fallback 'alert-supplied' })
    $trace.Add((New-DetectionTraceHop -Hop 'alerts' -Status $(if ($alertsArray.Count -gt 0) { 'present' } else { 'missing' }) -EvidenceIds $alertEvidence -Rationale 'Alert records supplied to connect the incident to the detection.'))

    $alertRuleIds = @($alertsArray | ForEach-Object {
        Get-DetectionAlertRuleIdentifiers -Alert $_
    } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $ruleLinked = $false
    if ($null -ne $Rule -and $alertRuleIds.Count -gt 0 -and ((Test-DetectionContains -Values $alertRuleIds -Expected $ruleId) -or (Test-DetectionContains -Values $alertRuleIds -Expected $ruleName))) {
        $ruleLinked = $true
    }
    if ($null -ne $Rule -and $alertRuleIds.Count -eq 0) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_rule_linkage' -Rationale 'Supplied alerts did not include a real analytics rule identifier; detectionSource and serviceSource were not treated as rule identifiers.' -AffectedHops @('generating_rule')))
    }
    if ($null -ne $Rule -and $alertRuleIds.Count -gt 0 -and -not $ruleLinked) {
        $findings.Add((New-DetectionFinding -DefectClass 'rule-logic' -Severity 'high' -Rationale 'The alert references a different generating rule than the supplied analytics rule record.' -EvidenceIds @($alertEvidence + $ruleEvidenceId)))
    }
    $trace.Add((New-DetectionTraceHop -Hop 'generating_rule' -Status $(if ($null -eq $Rule -or $alertRuleIds.Count -eq 0) { 'missing' } elseif ($ruleLinked) { 'present' } else { 'mismatch' }) -EvidenceIds @(if ($ruleEvidenceId) { $ruleEvidenceId } else { @() }) -Rationale 'Generating rule identity was compared against supplied alert rule references.'))

    $hasQueryVersion = -not [string]::IsNullOrWhiteSpace($query) -and -not [string]::IsNullOrWhiteSpace([string](Get-DetectionProperty -InputObject $ruleProperties -Name 'templateVersion'))
    $trace.Add((New-DetectionTraceHop -Hop 'deployed_query_version' -Status $(if ($null -eq $Rule -or -not $hasQueryVersion) { 'missing' } else { 'present' }) -EvidenceIds @(if ($ruleEvidenceId) { $ruleEvidenceId } else { @() }) -Rationale 'Rule query and template version were read from the supplied rule record.'))

    $matchingHealth = @($healthArray | Where-Object {
        $resourceId = [string](Get-DetectionProperty -InputObject $_ -Name 'SentinelResourceId')
        -not [string]::IsNullOrWhiteSpace($resourceId) -and
            -not [string]::IsNullOrWhiteSpace($ruleId) -and
            [string]::Equals($resourceId, $ruleId, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($healthArray.Count -gt 0 -and $matchingHealth.Count -eq 0) {
        $coverageGaps.Add((New-DetectionCoverageGap -GapType 'missing_execution_health' -Rationale 'Supplied SentinelHealth rows were unattributed or did not match the analytics rule resource ID.' -AffectedHops @('execution_health')))
    }
    $healthEvidence = @($matchingHealth | ForEach-Object { Get-DetectionEvidenceId -InputObject $_ -Fallback 'health-supplied' })
    $failedHealth = @($matchingHealth | Where-Object { [string](Get-DetectionProperty -InputObject $_ -Name 'Status') -notin @('', 'Success', 'Succeeded') })
    if ($failedHealth.Count -gt 0) {
        $findings.Add((New-DetectionFinding -DefectClass 'execution-health' -Severity 'high' -Rationale 'SentinelHealth records report a failed or non-successful analytics rule execution.' -EvidenceIds $healthEvidence))
    }
    $trace.Add((New-DetectionTraceHop -Hop 'execution_health' -Status $(if ($matchingHealth.Count -eq 0) { 'missing' } elseif ($failedHealth.Count -gt 0) { 'mismatch' } else { 'present' }) -EvidenceIds $healthEvidence -Rationale 'SentinelHealth rows were matched to the supplied analytics rule where possible.'))

    $rawEvidence = if ($null -ne $RawEventSample) { @(Get-DetectionEvidenceId -InputObject $RawEventSample -Fallback 'raw-sample-supplied') } else { @() }
    if ($hasRawSample -and $missingRawColumns.Count -gt 0) {
        $findings.Add((New-DetectionFinding -DefectClass 'data-quality' -Severity 'high' -Rationale ('Raw event sample is missing required projected or mapped identifiers: ' + ($missingRawColumns -join ', ')) -EvidenceIds $rawEvidence))
    }
    $trace.Add((New-DetectionTraceHop -Hop 'raw_events' -Status $(if (-not $hasRawSample) { 'missing' } elseif ($missingRawColumns.Count -gt 0) { 'mismatch' } else { 'present' }) -EvidenceIds $rawEvidence -Rationale 'Raw event sample columns were compared with query projections and mapping columns.'))

    $alertEntityTypes = @($alertsArray | ForEach-Object {
        Get-DetectionAlertEntityTypes -Alert $_
    } | Sort-Object -Unique)
    $mappedEntityTypes = @($entityMappings | ForEach-Object { $_.entityType } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $missingAlertEntityTypes = @($mappedEntityTypes | Where-Object { -not (Test-DetectionContains -Values $alertEntityTypes -Expected $_) })
    $missingMappedRawColumns = @(if ($hasRawSample) { $requiredMappingColumns | Where-Object { -not (Test-DetectionContains -Values $rawColumns -Expected $_) } })
    if ($null -ne $Rule -and ($missingAlertEntityTypes.Count -gt 0 -or $missingMappedRawColumns.Count -gt 0)) {
        $findings.Add((New-DetectionFinding -DefectClass 'entity-mapping' -Severity 'high' -Rationale 'Rule entity mappings do not align with supplied alert entities or raw event columns.' -EvidenceIds @($ruleEvidenceId, $rawEvidence, $alertEvidence)))
    }
    $trace.Add((New-DetectionTraceHop -Hop 'entity_mappings' -Status $(if ($null -eq $Rule -or $entityMappings.Count -eq 0) { 'missing' } elseif ($missingAlertEntityTypes.Count -gt 0 -or $missingMappedRawColumns.Count -gt 0) { 'mismatch' } else { 'present' }) -EvidenceIds @(if ($ruleEvidenceId) { $ruleEvidenceId } else { @() }) -Rationale 'Entity mapping columns and emitted alert entity kinds were compared.'))

    $incidentConfiguration = Get-DetectionProperty -InputObject $ruleProperties -Name 'incidentConfiguration'
    $groupingConfiguration = Get-DetectionProperty -InputObject $incidentConfiguration -Name 'groupingConfiguration'
    $createIncident = Get-DetectionProperty -InputObject $incidentConfiguration -Name 'createIncident'
    $groupingEnabled = Get-DetectionProperty -InputObject $groupingConfiguration -Name 'enabled'
    $groupingMismatch = $null -ne $Rule -and (($null -ne $createIncident -and -not [bool]$createIncident) -or ($null -ne $Incident -and $null -ne $groupingEnabled -and -not [bool]$groupingEnabled))
    if ($groupingMismatch) {
        $findings.Add((New-DetectionFinding -DefectClass 'grouping' -Severity 'medium' -Rationale 'Incident evidence exists but the supplied rule grouping or incident creation settings are disabled.' -EvidenceIds @($ruleEvidenceId, $incidentEvidence)))
    }
    $trace.Add((New-DetectionTraceHop -Hop 'grouping' -Status $(if ($null -eq $Rule -or $null -eq $incidentConfiguration) { 'missing' } elseif ($groupingMismatch) { 'mismatch' } else { 'present' }) -EvidenceIds @(if ($ruleEvidenceId) { $ruleEvidenceId } else { @() }) -Rationale 'Incident creation and grouping settings were assessed against the supplied incident.'))

    $alertDetailsOverride = Get-DetectionProperty -InputObject $ruleProperties -Name 'alertDetailsOverride'
    $placeholders = @(Get-DetectionPlaceholders -Override $alertDetailsOverride)
    $missingPlaceholderColumns = @(if ($hasRawSample) { $placeholders | Where-Object { -not (Test-DetectionContains -Values $rawColumns -Expected $_) } })
    if ($missingPlaceholderColumns.Count -gt 0) {
        $findings.Add((New-DetectionFinding -DefectClass 'enrichment' -Severity 'medium' -Rationale ('Alert enrichment templates reference columns absent from raw samples and projections: ' + ($missingPlaceholderColumns -join ', ')) -EvidenceIds @($ruleEvidenceId, $rawEvidence)))
    }
    $trace.Add((New-DetectionTraceHop -Hop 'enrichment' -Status $(if ($null -eq $Rule -or $null -eq $alertDetailsOverride) { 'missing' } elseif ($missingPlaceholderColumns.Count -gt 0) { 'mismatch' } else { 'present' }) -EvidenceIds @(if ($ruleEvidenceId) { $ruleEvidenceId } else { @() }) -Rationale 'Alert details override placeholders were compared with projected and sampled columns.'))

    $alertSeverities = @($alertsArray | ForEach-Object { [string](Get-DetectionProperty -InputObject $_ -Name 'severity') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $alertTechniques = @($alertsArray | ForEach-Object { Get-DetectionArray (Get-DetectionProperty -InputObject $_ -Name 'mitreTechniques') } | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($null -ne $Rule) {
        if (-not [string]::IsNullOrWhiteSpace($ruleSeverity) -and $alertSeverities.Count -gt 0 -and -not (Test-DetectionContains -Values $alertSeverities -Expected $ruleSeverity)) {
            $findings.Add((New-DetectionFinding -DefectClass 'rule-logic' -Severity 'medium' -Rationale 'Alert severity does not match the analytics rule severity mapping.' -EvidenceIds @($ruleEvidenceId, $alertEvidence)))
        }
        foreach ($technique in $alertTechniques) {
            if ($ruleTechniques.Count -gt 0 -and -not (Test-DetectionContains -Values $ruleTechniques -Expected $technique)) {
                $findings.Add((New-DetectionFinding -DefectClass 'rule-logic' -Severity 'medium' -Rationale 'Alert MITRE technique does not match the analytics rule MITRE mapping.' -EvidenceIds @($ruleEvidenceId, $alertEvidence)))
                break
            }
        }
    }

    $auditEvidence = @($auditArray | ForEach-Object { Get-DetectionEvidenceId -InputObject $_ -Fallback 'audit-supplied' })
    $safeReplayEvidenceSupplied = [bool](Get-DetectionProperty -InputObject $RawEventSample -Name 'safeReplayEvidenceSupplied')

    [pscustomobject][ordered]@{
        ruleIdentity = [pscustomobject][ordered]@{
            status = if ($null -eq $Rule) { 'missing' } else { 'present' }
            ruleId = $ruleId
            ruleName = $ruleName
            displayName = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'displayName')
            kind = [string](Get-DetectionProperty -InputObject $Rule -Name 'kind')
            intendedBehavior = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'description')
            templateName = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'ruleTemplateName')
            templateVersion = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'templateVersion')
            evidenceIds = @(if ($ruleEvidenceId) { $ruleEvidenceId } else { @() })
        }
        traceChain = @($trace)
        findings = @($findings)
        coverageGaps = @($coverageGaps)
        settingsAssessment = [pscustomobject][ordered]@{
            querySurface = [pscustomobject][ordered]@{
                tables = @($queryTables)
                projectedIdentifiers = @($projected)
                connectorAssumptions = @($queryTables)
                rawSampleColumns = @($rawColumns)
            }
            schema = [pscustomobject][ordered]@{
                requiredColumns = @($requiredIdentifiers)
                missingColumns = @($missingRawColumns)
            }
            projectedIdentifiers = [pscustomobject][ordered]@{
                required = @($requiredIdentifiers)
                present = @($requiredIdentifiers | Where-Object { Test-DetectionContains -Values $rawColumns -Expected $_ })
                missing = @($missingRawColumns)
            }
            entityMappings = [pscustomobject][ordered]@{
                mappedEntityTypes = @($mappedEntityTypes)
                alertEntityTypes = @($alertEntityTypes)
                requiredColumns = @($requiredMappingColumns)
                missingAlertEntityTypes = @($missingAlertEntityTypes)
                columnAlignmentStatus = if (-not $hasRawSample) { 'not_assessed' } elseif ($missingMappedRawColumns.Count -gt 0) { 'mismatch' } else { 'present' }
                missingRawColumns = @($missingMappedRawColumns)
            }
            enrichment = [pscustomobject][ordered]@{
                placeholders = @($placeholders)
                placeholderStatus = if (-not $hasRawSample) { 'not_assessed' } elseif ($missingPlaceholderColumns.Count -gt 0) { 'mismatch' } else { 'present' }
                missingRawColumns = @($missingPlaceholderColumns)
            }
            mitreMapping = [pscustomobject][ordered]@{
                ruleTactics = @($ruleTactics)
                ruleTechniques = @($ruleTechniques)
                alertTechniques = @($alertTechniques)
            }
            severityMapping = [pscustomobject][ordered]@{
                ruleSeverity = $ruleSeverity
                alertSeverities = @($alertSeverities)
                incidentSeverity = $incidentSeverity
            }
            frequency = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'queryFrequency')
            lookback = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'queryPeriod')
            threshold = [pscustomobject][ordered]@{
                operator = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'triggerOperator')
                value = Get-DetectionProperty -InputObject $ruleProperties -Name 'triggerThreshold'
            }
            grouping = [pscustomobject][ordered]@{
                enabled = if ($null -eq $groupingEnabled) { $null } else { [bool]$groupingEnabled }
                aggregationKind = [string](Get-DetectionNestedProperty -InputObject $ruleProperties -Path @('eventGroupingSettings', 'aggregationKind'))
                matchingMethod = [string](Get-DetectionProperty -InputObject $groupingConfiguration -Name 'matchingMethod')
                groupByEntities = @(Get-DetectionArray (Get-DetectionProperty -InputObject $groupingConfiguration -Name 'groupByEntities') | ForEach-Object { [string]$_ })
                groupByAlertDetails = @(Get-DetectionArray (Get-DetectionProperty -InputObject $groupingConfiguration -Name 'groupByAlertDetails') | ForEach-Object { [string]$_ })
                lookbackDuration = [string](Get-DetectionProperty -InputObject $groupingConfiguration -Name 'lookbackDuration')
            }
            suppression = [pscustomobject][ordered]@{
                enabled = Get-DetectionProperty -InputObject $ruleProperties -Name 'suppressionEnabled'
                duration = [string](Get-DetectionProperty -InputObject $ruleProperties -Name 'suppressionDuration')
            }
            incidentSettings = [pscustomobject][ordered]@{
                createIncident = if ($null -eq $createIncident) { $null } else { [bool]$createIncident }
            }
            limits = [pscustomobject][ordered]@{
                rawEventSampleRowCount = @(Get-DetectionArray (Get-DetectionProperty -InputObject $RawEventSample -Name 'rows')).Count
                alertCount = $alertsArray.Count
                entityCount = @($alertsArray | ForEach-Object { Get-DetectionArray (Get-DetectionProperty -InputObject $_ -Name 'entities') }).Count
                truncationEvidenceSupplied = [bool](Get-DetectionProperty -InputObject $RawEventSample -Name 'truncationEvidenceSupplied')
            }
            knownFalsePositives = @(Get-DetectionArray (Get-DetectionProperty -InputObject $ruleProperties -Name 'knownFalsePositives') | ForEach-Object { [string]$_ })
            blindSpots = @(Get-DetectionArray (Get-DetectionProperty -InputObject $ruleProperties -Name 'blindSpots') | ForEach-Object { [string]$_ })
            executionEvidence = [pscustomobject][ordered]@{
                healthEvidenceIds = @($healthEvidence)
                auditEvidenceIds = @($auditEvidence)
            }
            safeReplayEvidenceSupplied = $safeReplayEvidenceSupplied
        }
    }
}

Export-ModuleMember -Function New-HavocDetectionQualityAudit
