<#
.SYNOPSIS
Runs the HAVOC Microsoft Incident Auditor read-only incident bundle assembly.

.DESCRIPTION
This runner is an offline-testable orchestrator for the authorized commercial
Microsoft 365 E5 read-only pilot. It never performs HTTP itself. Every tenant
request is delegated to the approved read-only adapter scripts in this folder,
which enforce Test-ReadOnlyRequest.ps1 and request-policy.json.

Tests and live pilots inject the same adapter dependencies. A live caller must
supply -Transport implementing references\trusted-transport-interface.json,
-AuthContextProvider implementing references\auth-context-provider-interface.json,
and -ProvenanceContextProvider supplying trusted source provenance for the
adapter capability binding. There is no parallel transport or auth path in this
runner. If -Transport is omitted, the runner fails closed and records a coverage
gap instead of making tenant calls.

If -ProtectedStore is not supplied, the runner writes protected request and
evidence payload wrappers under OutputDirectory\protected and returns only
opaque protected-request:/protected-evidence: locators to downstream records.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z')]
    [string]$IncidentId,

    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z')]
    [string]$TenantId,

    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z')]
    [string]$WorkspaceId,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z')]
    [string]$SubscriptionId,

    [ValidatePattern('^(?![.])(?!.*[.]\z)[A-Za-z0-9._()\-]{1,90}\z')]
    [string]$ResourceGroupName,

    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9-]{2,61}[A-Za-z0-9])\z')]
    [string]$WorkspaceName,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z')]
    [string]$SentinelIncidentId,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z')]
    [string]$AnalyticsRuleId,

    [Parameter(Mandatory)][datetimeoffset]$StartTime,
    [Parameter(Mandatory)][datetimeoffset]$EndTime,

    [Parameter(Mandatory)][string]$OutputDirectory,

    [ValidateSet('Commercial', 'USGovDoD')]
    [string]$Cloud = 'Commercial',

    $Transport,

    [scriptblock]$ProtectedStore,

    [scriptblock]$AuthContextProvider,
    [scriptblock]$ProvenanceContextProvider,
    [scriptblock]$Sleeper = { param($Seconds) Start-Sleep -Seconds $Seconds },
    [scriptblock]$Clock = { [datetimeoffset]::UtcNow },

    [switch]$OfflineFixture,

    [switch]$ExecutePivots,

    [ValidateRange(1, 100)]
    [int]$MaxPivotQueries = 25
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PolicyPath = Join-Path $PSScriptRoot '..\references\request-policy.json'
$cloudProfilePath = Join-Path $PSScriptRoot 'HavocCloudProfile.psm1'
$cloudProfileResolutionError = $null
try {
    Import-Module $cloudProfilePath -Force -ErrorAction Stop
    $cloudProfile = Get-HavocCloudProfile -Cloud $Cloud
}
catch {
    $cloudProfileResolutionError = $_.Exception.Message
    $cloudProfile = [pscustomobject][ordered]@{
        name = $Cloud
        graphHost = 'unavailable.invalid'
        armHost = 'unavailable.invalid'
        logAnalyticsHost = 'unavailable.invalid'
        requestScopes = [pscustomobject][ordered]@{
            graphSecurityIncidentRead = 'unavailable'
            graphSecurityAlertRead = 'unavailable'
            armDefault = 'unavailable'
            logAnalyticsDefault = 'unavailable'
        }
        expectedCoverageGaps = @('cloud_profile_unavailable')
    }
    $Transport = $null
}
$executionMode = if ($OfflineFixture.IsPresent) { 'offline_fixture' } else { 'authorized_live_read' }
$handlingMarking = if ($executionMode -eq 'authorized_live_read') { 'tenant-read-only' } else { 'synthetic' }
$trustedTransportMissing = $null -eq $Transport

$kernelPath = Join-Path $PSScriptRoot 'kernel'
$commonKernel = Join-Path $kernelPath 'Common.Kernel.psm1'
$coverageKernel = Join-Path $kernelPath 'Coverage.Kernel.psm1'
$evidenceKernel = Join-Path $kernelPath 'Evidence.Kernel.psm1'
$entityKernel = Join-Path $kernelPath 'Entity.Kernel.psm1'
$timelineKernel = Join-Path $kernelPath 'Timeline.Kernel.psm1'
$taxonomyKernel = Join-Path $kernelPath 'Taxonomy.Kernel.psm1'
$decisionKernel = Join-Path $kernelPath 'Decision.Kernel.psm1'
$recoveryKernel = Join-Path $kernelPath 'Recovery.Kernel.psm1'
$recurrenceKernel = Join-Path $kernelPath 'Recurrence.Kernel.psm1'
$saturationKernel = Join-Path $kernelPath 'Saturation.Kernel.psm1'

foreach ($module in @(
    $commonKernel, $coverageKernel, $evidenceKernel, $entityKernel,
    $timelineKernel, $taxonomyKernel, $decisionKernel, $recoveryKernel, $recurrenceKernel,
    $saturationKernel
)) {
    Import-Module $module -Force -Global
}
$runnerCommonModule = Import-Module $commonKernel -Force -PassThru
$runnerMutationScanner = $runnerCommonModule.ExportedCommands['Find-HavocMutationCommand']
if ($null -eq $runnerMutationScanner) {
    throw 'Runner could not load the approved mutation scanner.'
}

function Get-RunnerStableId {
    param([string]$Prefix, [string[]]$Parts)
    $canonical = @($Parts | ForEach-Object { [string]$_ }) | ConvertTo-Json -Compress
    $hash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))
    ).ToLowerInvariant()
    "$Prefix-$($hash.Substring(0, 24))"
}

function New-RunnerGap {
    param(
        [string]$Source,
        [string]$Code,
        [string]$Message,
        [string[]]$AffectedClaimIds = @('CLAIM-source-retrieval')
    )
    [pscustomobject][ordered]@{
        gap_id = Get-RunnerStableId -Prefix 'GAP' -Parts @($Source, $Code, $Message)
        source = $Source
        code = $Code
        message = $Message
        affected_claim_ids = @($AffectedClaimIds)
        behavior_bases = @('configurable_project_policy')
    }
}

function New-RunnerIntent {
    param(
        [string]$OperationId,
        [string]$Method,
        [string]$Uri,
        [string[]]$RequestedScopes,
        [string[]]$TokenScopes,
        [string[]]$TokenRoles = @(),
        $Body = $null,
        [string[]]$SourceIds,
        [int]$MaxRows = 100,
        [long]$MaxBytes = 2097152
    )
    $request = [pscustomobject][ordered]@{
        requestId = "runner-$OperationId-$([guid]::NewGuid().ToString('N'))"
        correlationId = "havoc-runner-$([guid]::NewGuid().ToString('N'))"
        operationId = $OperationId
        method = $Method
        uri = $Uri
        cloud = [string]$cloudProfile.name
        requestedScopes = @($RequestedScopes)
        tokenScopes = @($TokenScopes)
        tokenRoles = @($TokenRoles)
        expected_principal_ref = 'protected-context:principal-pilot'
        expected_source_scope_refs = @($SourceIds | ForEach-Object { "protected-context:$_" })
        autoFollowRedirects = $false
        bounds = [pscustomobject][ordered]@{
            maxRows = $MaxRows
            maxBytes = $MaxBytes
            maxRuntimeSeconds = 60
            startTime = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            endTime = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            workspaceIds = @($WorkspaceId)
            sourceIds = @($SourceIds)
        }
    }
    if ($null -ne $Body) {
        $request | Add-Member -NotePropertyName body -NotePropertyValue $Body
        $request | Add-Member -NotePropertyName responseEnforcement -NotePropertyValue ([pscustomobject][ordered]@{
            adapterId = 'havoc-protected-store-adapter'
            adapterVersion = '1.0.0'
            byteLimitEnforced = $true
            partialResponseDetected = $true
            actualBytesRecorded = $true
            maxBytes = $MaxBytes
        })
    }
    $request
}

function Get-RunnerSha256Hex {
    param([string]$Text)
    [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))
    ).ToLowerInvariant()
}

function New-RunnerLogIntent {
    param(
        [string]$Query,
        [int]$MaxRows = 100,
        [string[]]$SourceIds = @('sentinel-law')
    )
    New-RunnerIntent -OperationId 'log-analytics-query' -Method ('PO' + 'ST') `
        -Uri "https://$($cloudProfile.logAnalyticsHost)/v1/workspaces/$WorkspaceId/query" `
        -RequestedScopes @([string]$cloudProfile.requestScopes.logAnalyticsDefault) -TokenScopes @('user_impersonation') `
        -SourceIds $SourceIds -MaxRows $MaxRows -Body ([pscustomobject][ordered]@{
            query = $Query
            timespan = $timeSpan
            resultLimit = $MaxRows
        })
}

function Invoke-RunnerAdapter {
    param([string]$AdapterScript, $Intent)
    try {
        $runnerIntentRecords.Add([pscustomobject][ordered]@{
            operationId = [string]$Intent.operationId
            method = [string]$Intent.method
            uri = [string]$Intent.uri
            requestedScopes = @($Intent.requestedScopes)
            cloud = [string]$cloudProfile.name
            adapter = [string]$AdapterScript
        })
        $adapterPath = Join-Path $PSScriptRoot $AdapterScript
        $adapterParameters = @{
            Intent = $Intent
            Transport = $Transport
            ProtectedStore = $AdapterProtectedStore
            AuthContextProvider = $AuthContextProvider
            ProvenanceContextProvider = $ProvenanceContextProvider
            Sleeper = $Sleeper
            Clock = $Clock
            PolicyPath = $PolicyPath
        }
        $adapterCommand = Get-Command $adapterPath -ErrorAction Stop
        if ($adapterCommand.Parameters.ContainsKey('Cloud')) {
            $adapterParameters.Cloud = [string]$Cloud
        }
        & $adapterPath @adapterParameters
    }
    catch {
        [pscustomobject][ordered]@{
            adapter = [pscustomobject][ordered]@{
                id = 'havoc-runner-adapter-call'
                version = '1.0.0'
                source = [string]$Intent.operationId
            }
            status = 'failed'
            queryLedger = [pscustomobject][ordered]@{
                operation_id = [string]$Intent.operationId
                source_id = [string]$Intent.operationId
                target = [string]$Intent.uri
                requested_scopes = @($Intent.requestedScopes)
                cloud = [string]$cloudProfile.name
                started_at = (& $Clock).ToUniversalTime().ToString('o')
                ended_at = (& $Clock).ToUniversalTime().ToString('o')
                time_bounds = [pscustomobject][ordered]@{
                    start_inclusive = [string]$Intent.bounds.startTime
                    end_exclusive = [string]$Intent.bounds.endTime
                }
                scope_bounds = @($Intent.expected_source_scope_refs)
                response_classification = 'failed'
                status = 'failed'
            }
            coverage = [pscustomobject][ordered]@{
                state = 'failed'
                limitations = @('runner: adapter invocation failed')
                effectiveWindow = [pscustomobject][ordered]@{
                    start = [string]$Intent.bounds.startTime
                    end = [string]$Intent.bounds.endTime
                }
            }
            counts = [pscustomobject][ordered]@{ rows = 0; results = 0; bytes = 0 }
            pagination = [pscustomobject][ordered]@{ pages = 0; continuationState = 'not_observed' }
            integrity = [pscustomobject][ordered]@{ truncated = $false; partial = $false }
            provenance = [pscustomobject][ordered]@{}
            errors = @([pscustomobject][ordered]@{
                error_id = Get-RunnerStableId -Prefix 'ERR' -Parts @([string]$Intent.operationId, [string]$_.Exception.Message)
                category = 'source_unavailable'
                code = 'adapter_invocation_failed'
                message = 'Approved adapter invocation failed before returning an envelope.'
            })
        }
    }
}

    function ConvertFrom-RunnerJsonValue {
        param($Value)
        $items = if ($Value -is [string]) { @($Value) } else { @($Value) }
        foreach ($item in $items) {
            if ($item -is [string]) {
                try { $item | ConvertFrom-Json -Depth 100 -DateKind String }
                catch { }
            }
            else {
                $item
            }
        }
    }

    function Get-RunnerAcceptedPayload {
        param(
            [object[]]$CapturedEvidence,
            [string]$OperationId,
            [string]$ProtectedResponseRef
        )
        foreach ($record in @($CapturedEvidence | Where-Object {
            $_.Metadata.PSObject.Properties.Name -contains 'operationId' -and
            [string]$_.Metadata.operationId -eq $OperationId -and
            $_.Metadata.PSObject.Properties.Name -contains 'contentClass' -and
            [string]$_.Metadata.contentClass -eq 'accepted-response' -and
            ([string]::IsNullOrWhiteSpace($ProtectedResponseRef) -or
                ($_.PSObject.Properties.Name -contains 'Reference' -and
                    [string]$_.Reference -eq $ProtectedResponseRef))
        })) {
            foreach ($parsed in @(ConvertFrom-RunnerJsonValue $record.Value)) {
                $parsed
            }
        }
    }

    function ConvertFrom-RunnerLogPayloadRows {
        param($Payload)
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($table in @($Payload.tables)) {
            $columns = @($table.columns | ForEach-Object { [string]$_.name })
            if ($table.PSObject.Properties.Name -notcontains 'rows' -or $null -eq $table.rows) { continue }
            foreach ($row in @($table.rows)) {
                if ($null -eq $row -or @($row).Count -eq 0) { continue }
                if ($row -is [Array] -and $row.Count -eq 0) { continue }
                $rowValues = @($row)
                if ($rowValues.Count -lt $columns.Count) { continue }
                $object = [ordered]@{}
                for ($index = 0; $index -lt $columns.Count; $index++) {
                    $object[$columns[$index]] = $rowValues[$index]
                }
                if (@($object.Values | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0) { continue }
                $rows.Add([pscustomobject]$object)
            }
        }
        @($rows)
    }

    function Get-RunnerPayloadForEnvelope {
        param($Envelope)
        if ($null -eq $Envelope -or $Envelope.PSObject.Properties.Name -notcontains 'protectedResponseRef') { return @() }
        @(Get-RunnerAcceptedPayload -CapturedEvidence @($capturedEvidence) `
            -OperationId ([string]$Envelope.queryLedger.operation_id) `
            -ProtectedResponseRef ([string]$Envelope.protectedResponseRef))
    }

    function Get-RunnerSignalState {
        param(
            [string]$Signal,
            [object[]]$Rows,
            $Envelope
        )
        $queryRef = if ($null -ne $Envelope -and $Envelope.PSObject.Properties.Name -contains 'protectedResponseRef') {
            [string]$Envelope.protectedResponseRef
        }
        else { 'not-applicable:none' }
        if ($null -eq $Envelope -or [string]$Envelope.status -ne 'success') {
            return [pscustomobject][ordered]@{
                signal = $Signal
                status = 'not_verifiable'
                basis = 'coverage verification query did not complete successfully'
                query_ref = $queryRef
                row_count = 0
                value_origin = 'verified'
            }
        }
        $rowCount = @($Rows).Count
        if ($rowCount -eq 0) {
            return [pscustomobject][ordered]@{
                signal = $Signal
                status = 'not_verifiable'
                basis = 'coverage verification query completed but returned no rows'
                query_ref = $queryRef
                row_count = 0
                value_origin = 'verified'
            }
        }
        $statuses = @($Rows | ForEach-Object {
            $row = $_
            if ($null -ne $row -and $null -ne $row.PSObject -and
                @($row.PSObject.Properties.Name) -contains 'Status') { [string]$row.Status }
            elseif ($null -ne $row -and $null -ne $row.PSObject -and
                @($row.PSObject.Properties.Name) -contains 'HealthStatus') { [string]$row.HealthStatus }
        } | Where-Object { $_ })
        if ($Signal -eq 'connector_healthy' -and @($statuses | Where-Object { Test-RunnerSentinelHealthNegativeStatus $_ }).Count -gt 0) {
            return [pscustomobject][ordered]@{
                signal = $Signal
                status = 'verified_false'
                basis = 'SentinelHealth reported an unhealthy connector or workspace status'
                query_ref = $queryRef
                row_count = $rowCount
                value_origin = 'verified'
            }
        }
        if ($Signal -eq 'connector_healthy' -and @($statuses | Where-Object { $_ -match '^(?i:Success)$' }).Count -eq 0) {
            return [pscustomobject][ordered]@{
                signal = $Signal
                status = 'not_verifiable'
                basis = 'SentinelHealth did not report a successful connector status'
                query_ref = $queryRef
                row_count = $rowCount
                value_origin = 'verified'
            }
        }
        if ($Signal -eq 'sentinel_onboarded' -and
            @($statuses | Where-Object { $_ -match '(?i)not.?onboarded|offboarded|disabled' }).Count -gt 0) {
            return [pscustomobject][ordered]@{
                signal = $Signal
                status = 'verified_false'
                basis = 'SentinelHealth explicitly reported a non-onboarded or disabled state'
                query_ref = $queryRef
                row_count = $rowCount
                value_origin = 'verified'
            }
        }
        [pscustomobject][ordered]@{
            signal = $Signal
            status = 'verified_true'
            basis = 'coverage verification query returned bounded rows for the signal'
            query_ref = $queryRef
            row_count = $rowCount
            value_origin = 'verified'
        }
    }

    function Test-RunnerSentinelHealthNegativeStatus {
        param([string]$Status)
        $normalized = ([string]$Status).Trim()
        $normalized -match '^(?i:Failure|Partial Success|Warning|Unhealthy|Disabled|Failed|Error|Not.?Healthy)$'
    }

    function Test-RunnerSentinelHealthConnectorSpecific {
        param([object[]]$Rows)
        foreach ($row in @($Rows)) {
            if ($null -eq $row -or $null -eq $row.PSObject) { continue }
            $kind = if (@($row.PSObject.Properties.Name) -contains 'SentinelResourceKind') { [string]$row.SentinelResourceKind } else { '' }
            $status = if (@($row.PSObject.Properties.Name) -contains 'Status') { [string]$row.Status } else { '' }
            $resourceType = if (@($row.PSObject.Properties.Name) -contains 'SentinelResourceType') { [string]$row.SentinelResourceType } else { '' }
            if ($resourceType -match '^(?i:Data connector)$') {
                return $true
            }
        }
        $false
    }

    function Test-RunnerConnectorFreshnessRows {
        param([object[]]$Rows)
        foreach ($row in @($Rows)) {
            if ($null -eq $row -or $null -eq $row.PSObject) { continue }
            $names = @($row.PSObject.Properties.Name)
            $dataType = if ($names -contains 'DataType') { [string]$row.DataType } else { '' }
            $quantity = if ($names -contains 'Quantity') { [string]$row.Quantity } else { '' }
            $timeGenerated = if ($names -contains 'TimeGenerated') { [string]$row.TimeGenerated } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($timeGenerated) -and
                $dataType -match '^(SecurityIncident|SecurityAlert)$' -and
                ($quantity -match '^[0-9]+(?:\.[0-9]+)?$') -and
                [double]$quantity -gt 0) {
                return $true
            }
        }
        $false
    }

    function Add-RunnerObjectNote {
        param($Object, [string]$Name, $Value)
        if ($null -ne $Object) {
            $Object | Add-Member -Force -NotePropertyName $Name -NotePropertyValue $Value
        }
        $Object
    }

    function Add-RunnerSignalAttestation {
        param(
            [Parameter(Mandatory)]$SignalRecord,
            [string]$Signal,
            $Envelope
        )
        $verifiedValue = if ([string]$SignalRecord.status -eq 'verified_true') { $true } elseif ([string]$SignalRecord.status -eq 'verified_false') { $false } else { $null }
        $attestedValue = $null
        $attestationSource = 'not_provided'
        if ($null -ne $Envelope -and $Envelope.PSObject.Properties.Name -contains 'provenance' -and $null -ne $Envelope.provenance) {
            if ($Envelope.provenance.PSObject.Properties.Name -contains $Signal) {
                $attestedValue = [bool]$Envelope.provenance.$Signal
                $attestationSource = 'provided'
            }
            $refs = @()
            if ($Envelope.provenance.PSObject.Properties.Name -contains 'evidence_refs') { $refs = @($Envelope.provenance.evidence_refs) }
            if (@($refs | Where-Object { [string]$_ -match '(?i)operator-attested|attested' }).Count -gt 0) {
                $attestationSource = 'attested'
            }
        }
        $SignalRecord | Add-Member -Force -NotePropertyName verified_value -NotePropertyValue $verifiedValue
        $SignalRecord | Add-Member -Force -NotePropertyName attested_value -NotePropertyValue $attestedValue
        $SignalRecord | Add-Member -Force -NotePropertyName attestation_source -NotePropertyValue $attestationSource
        $SignalRecord
    }

    function Get-RunnerPivotCatalog {
        $skillsRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')
        $items = [Collections.Generic.List[object]]::new()
        foreach ($dir in @(Get-ChildItem -LiteralPath $skillsRoot -Directory | Where-Object { $_.Name -like 'incident-audit-*' } | Sort-Object Name)) {
            $catalogPath = Join-Path $dir.FullName 'references\pivot-catalog.md'
            if (-not (Test-Path -LiteralPath $catalogPath)) { continue }
            $lines = Get-Content -LiteralPath $catalogPath
            $section = ''
            $inFence = $false
            $buffer = [Collections.Generic.List[string]]::new()
            $sequence = 0
            foreach ($line in $lines) {
                if (-not $inFence -and $line -match '^##\s+(.+)$') {
                    $section = $Matches[1].Trim()
                    continue
                }
                if ($line -match '^```kql\s*$') {
                    $inFence = $true
                    $buffer.Clear()
                    continue
                }
                if ($inFence -and $line -match '^```\s*$') {
                    $sequence++
                    $text = ($buffer.ToArray() -join "`n").Trim()
                    if (-not [string]::IsNullOrWhiteSpace($text)) {
                        $parameters = @([regex]::Matches($text, '<([a-z0-9-]+)>') |
                            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
                        $items.Add([pscustomobject][ordered]@{
                            skill = $dir.Name
                            name = if ([string]::IsNullOrWhiteSpace($section)) { "Pivot $sequence" } else { $section }
                            priority = 1000
                            sequence = $sequence
                            query_template = $text
                            parameters = @($parameters)
                        })
                    }
                    $inFence = $false
                    continue
                }
                if ($inFence) { $buffer.Add($line) }
            }
        }
        @($items)
    }

    function Get-RunnerMatchedDomainSkills {
        param([object[]]$Alerts)
        $matched = [Collections.Generic.List[string]]::new()
        foreach ($alert in @($Alerts)) {
            $text = ($alert | ConvertTo-Json -Depth 50 -Compress)
            if ($text -match '(?i)userEvidence|T1078|identity|account') { $matched.Add('incident-audit-identity') }
            if ($text -match '(?i)deviceEvidence|device|process|endpoint') { $matched.Add('incident-audit-endpoint') }
            if ($text -match '(?i)mail|email|urlEvidence|phish') { $matched.Add('incident-audit-email') }
            if ($text -match '(?i)ipEvidence|network|remoteIp') { $matched.Add('incident-audit-network') }
            if ($text -match '(?i)oauth|application|serviceprincipal') { $matched.Add('incident-audit-oauth-apps') }
        }
        @($matched | Sort-Object -Unique)
    }

    function Get-RunnerEntityBindings {
        param([object[]]$Alerts)
        $bindings = @{}
        $accountRecords = [Collections.Generic.List[object]]::new()
        $accountAmbiguities = [Collections.Generic.List[object]]::new()
        $entityIndex = 0
        foreach ($alert in @($Alerts)) {
            foreach ($evidence in @($alert.evidence)) {
                $entityIndex++
                $entityRef = "ENTITY-runner-$entityIndex"
                if ($evidence.PSObject.Properties.Name -contains 'userAccount' -and $null -ne $evidence.userAccount) {
                    $account = $evidence.userAccount
                    $upn = if ($account.PSObject.Properties.Name -contains 'userPrincipalName') { [string]$account.userPrincipalName } else { '' }
                    $name = if ($account.PSObject.Properties.Name -contains 'accountName') { [string]$account.accountName } else { '' }
                    $domain = if ($account.PSObject.Properties.Name -contains 'domainName') { [string]$account.domainName } else { '' }
                    $userId = if ($account.PSObject.Properties.Name -contains 'azureAdUserId') { [string]$account.azureAdUserId } else { '' }
                    if ([string]::IsNullOrWhiteSpace($upn) -and -not [string]::IsNullOrWhiteSpace($name) -and -not [string]::IsNullOrWhiteSpace($domain)) {
                        $upn = "$name@$domain"
                    }
                    $validUserId = $userId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z'
                    $validUpn = $upn -match '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z'
                    $validName = $name -match '^[A-Za-z0-9._%+-]{1,128}\z'
                    $validDomain = $domain -match '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z'
                    if (-not $validUserId -and -not $validUpn) { continue }
                    $existing = $null
                    $conflictingUpn = $false
                    foreach ($record in @($accountRecords)) {
                        if ($validUserId -and -not [string]::IsNullOrWhiteSpace([string]$record.userId) -and [string]$record.userId -ieq $userId) {
                            $existing = $record
                            break
                        }
                        if ($validUpn -and -not [string]::IsNullOrWhiteSpace([string]$record.upn) -and [string]$record.upn -ieq $upn) {
                            if ($validUserId -and -not [string]::IsNullOrWhiteSpace([string]$record.userId) -and [string]$record.userId -ine $userId) {
                                $conflictingUpn = $true
                                continue
                            }
                            $existing = $record
                            break
                        }
                    }
                    if ($conflictingUpn -and $null -eq $existing) {
                        $accountAmbiguities.Add([pscustomobject][ordered]@{
                            entity_record_ref = $entityRef
                            reason = 'same_upn_different_user_ids'
                        })
                    }
                    if ($null -eq $existing) {
                        $existing = [pscustomobject][ordered]@{
                            entity_record_ref = $entityRef
                            index = $entityIndex
                            userId = ''
                            upn = ''
                            name = ''
                            domain = ''
                        }
                        $accountRecords.Add($existing)
                    }
                    if ($validUserId -and [string]::IsNullOrWhiteSpace([string]$existing.userId)) { $existing.userId = $userId }
                    if ($validUpn -and [string]::IsNullOrWhiteSpace([string]$existing.upn)) { $existing.upn = $upn }
                    if ($validName -and [string]::IsNullOrWhiteSpace([string]$existing.name)) { $existing.name = $name }
                    if ($validDomain -and [string]::IsNullOrWhiteSpace([string]$existing.domain)) { $existing.domain = $domain }
                }
            }
        }
        $bindingSets = [Collections.Generic.List[object]]::new()
        foreach ($account in @($accountRecords)) {
            $set = @{}
            foreach ($entry in @(
                @{ Name = 'user-id'; Value = [string]$account.userId; Origin = 'incident_entity' },
                @{ Name = 'user-principal-name'; Value = [string]$account.upn; Origin = 'incident_entity' },
                @{ Name = 'account-reference'; Value = [string]$account.upn; Origin = 'derived_account_reference' },
                @{ Name = 'account-name'; Value = [string]$account.name; Origin = 'incident_entity' },
                @{ Name = 'account-domain'; Value = [string]$account.domain; Origin = 'incident_entity' }
            )) {
                if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
                    $binding = [pscustomobject][ordered]@{
                        value = [string]$entry.Value
                        entity_record_ref = [string]$account.entity_record_ref
                        value_ref = "protected-context:$($entry.Name)-$($account.index)"
                        value_origin = [string]$entry.Origin
                    }
                    $set[$entry.Name] = $binding
                    if (-not $bindings.ContainsKey($entry.Name)) {
                        $bindings[$entry.Name] = $binding
                    }
                }
            }
            $bindingSets.Add([pscustomobject][ordered]@{
                entity_record_ref = [string]$account.entity_record_ref
                bindings = $set
            })
        }
        $bindings['__sets'] = @($bindingSets)
        $bindings['__ambiguities'] = @($accountAmbiguities)
        $bindings
    }

    function Get-RunnerPivotBindingVariants {
        param(
            $Pivot,
            [hashtable]$Bindings
        )
        $accountParameters = @('user-id', 'user-principal-name', 'account-reference', 'account-name', 'account-domain')
        $requiresAccount = @($Pivot.parameters | Where-Object { [string]$_ -in $accountParameters }).Count -gt 0
        if (-not $requiresAccount) {
            return @([pscustomobject][ordered]@{
                binding_entity_ref = 'not-applicable:none'
                bound = ConvertTo-RunnerBoundQuery -Pivot $Pivot -Bindings $Bindings
            })
        }
        $variants = [Collections.Generic.List[object]]::new()
        foreach ($setRecord in @($Bindings['__sets'])) {
            $setBindings = @{}
            foreach ($key in @($Bindings.Keys | Where-Object { [string]$_ -ne '__sets' -and [string]$_ -notin $accountParameters })) {
                $setBindings[$key] = $Bindings[$key]
            }
            foreach ($key in @($setRecord.bindings.Keys)) {
                $setBindings[$key] = $setRecord.bindings[$key]
            }
            $variants.Add([pscustomobject][ordered]@{
                binding_entity_ref = [string]$setRecord.entity_record_ref
                bound = ConvertTo-RunnerBoundQuery -Pivot $Pivot -Bindings $setBindings
            })
        }
        if ($variants.Count -eq 0) {
            $variants.Add([pscustomobject][ordered]@{
                binding_entity_ref = 'not-applicable:none'
                bound = ConvertTo-RunnerBoundQuery -Pivot $Pivot -Bindings $Bindings
            })
        }
        @($variants)
    }

    function ConvertTo-RunnerBoundQuery {
        param(
            $Pivot,
            [hashtable]$Bindings
        )
        $query = [string]$Pivot.query_template
        $bound = [Collections.Generic.List[object]]::new()
        foreach ($parameter in @($Pivot.parameters)) {
            if ($parameter -eq 'unavailable') {
                return [pscustomobject][ordered]@{
                    success = $false
                    reason = 'placeholder <unavailable> is not bindable by design'
                    query = $null
                    bound_parameters = @($bound)
                }
            }
            if ($parameter -eq 'start-utc') {
                $value = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $query = $query.Replace('<start-utc>', $value)
                $bound.Add([pscustomobject][ordered]@{ name = $parameter; value_origin = 'audit_window'; value_ref = 'not-applicable:audit-window-start' })
                continue
            }
            if ($parameter -eq 'end-utc') {
                $value = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $query = $query.Replace('<end-utc>', $value)
                $bound.Add([pscustomobject][ordered]@{ name = $parameter; value_origin = 'audit_window'; value_ref = 'not-applicable:audit-window-end' })
                continue
            }
            if (-not $Bindings.ContainsKey($parameter)) {
                return [pscustomobject][ordered]@{
                    success = $false
                    reason = "missing required binding <$parameter>"
                    query = $null
                    bound_parameters = @($bound)
                }
            }
            $binding = $Bindings[$parameter]
            $safeValue = ([string]$binding.value).Replace('\', '\\').Replace('"', '\"')
            $query = $query.Replace("<$parameter>", $safeValue)
            $bound.Add([pscustomobject][ordered]@{
                name = $parameter
                entity_record_ref = [string]$binding.entity_record_ref
                value_ref = [string]$binding.value_ref
                value_origin = if ($binding.PSObject.Properties.Name -contains 'value_origin') { [string]$binding.value_origin } else { 'incident_entity' }
            })
        }
        if ($query -notmatch '(?is)\|\s*(take|limit)\s+[1-9][0-9]*\s*$') {
            $query = $query.TrimEnd() + "`n| take 100"
        }
        [pscustomobject][ordered]@{
            success = $true
            reason = 'bound'
            query = $query
            bound_parameters = @($bound)
        }
    }

    function Get-RunnerEvidenceIdsFromObject {
        param($Value)
        $ids = [Collections.Generic.List[string]]::new()
        if ($null -eq $Value) { return @() }
        if ($Value -is [string]) { return @() }
        if ($Value -is [System.Collections.IEnumerable]) {
            foreach ($item in @($Value)) {
                foreach ($id in @(Get-RunnerEvidenceIdsFromObject -Value $item)) { $ids.Add([string]$id) }
            }
            return @($ids)
        }
        if ($null -eq $Value.PSObject) { return @() }
        foreach ($property in @($Value.PSObject.Properties)) {
            if ($property.Name -eq 'evidence_id' -or $property.Name -eq 'evidence_ids' -or $property.Name -like '*_evidence_ids') {
                foreach ($id in @($property.Value)) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$id)) { $ids.Add([string]$id) }
                }
            }
            else {
                foreach ($id in @(Get-RunnerEvidenceIdsFromObject -Value $property.Value)) { $ids.Add([string]$id) }
            }
        }
        @($ids)
    }

    function Get-RunnerPropertyText {
        param($Value, [string]$Name, [string]$Default = 'unknown')
        if ($null -ne $Value -and $null -ne $Value.PSObject -and
            $Value.PSObject.Properties.Name -contains $Name -and
            -not [string]::IsNullOrWhiteSpace([string]$Value.$Name)) {
            return [string]$Value.$Name
        }
        $Default
    }

    function Get-RunnerDateTimeOffsetOrNull {
        param($Value)
        if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
        $parsed = [datetimeoffset]::MinValue
        $styles = [Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetimeoffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            return $parsed.ToUniversalTime()
        }
        $null
    }

    function ConvertTo-RunnerUtcText {
        param($Value)
        $parsed = Get-RunnerDateTimeOffsetOrNull $Value
        if ($null -eq $parsed) { return $null }
        $parsed.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    function Select-RunnerRowsWithValidTimeGenerated {
        param([object[]]$Rows, [string]$Source, [Collections.Generic.List[object]]$GapList)
        $valid = [Collections.Generic.List[object]]::new()
        foreach ($row in @($Rows)) {
            $timeValue = Get-RunnerPropertyText $row 'TimeGenerated' ''
            if ($null -ne (Get-RunnerDateTimeOffsetOrNull $timeValue)) {
                $valid.Add($row)
                continue
            }
            $gap = New-RunnerGap $Source 'malformed_timegenerated_row_skipped' "A $Source row had malformed TimeGenerated and was skipped before timeline, taxonomy, and decision reconstruction."
            $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
            $GapList.Add($gap)
        }
        @($valid)
    }

    function Get-RunnerLatestSecurityIncidentRow {
        param([object[]]$Rows)
        @($Rows | Sort-Object {
            $parsed = Get-RunnerDateTimeOffsetOrNull (Get-RunnerPropertyText $_ 'TimeGenerated' '')
            if ($null -ne $parsed) { $parsed } else { [datetimeoffset]::MinValue }
        } -Descending | Select-Object -First 1)
    }

    function New-RunnerLogAnalyticsIncidentObject {
        param($Row)
        if ($null -eq $Row) { return $null }
        $incidentId = Get-RunnerStableId -Prefix 'INC' -Parts @('SecurityIncident', (Get-RunnerPropertyText $Row 'IncidentNumber' ''), (Get-RunnerPropertyText $Row 'ProviderIncidentId' ''), (Get-RunnerPropertyText $Row 'TimeGenerated' ''))
        [pscustomobject][ordered]@{
            id = $incidentId
            displayName = 'Protected incident title from Log Analytics'
            status = Get-RunnerPropertyText $Row 'Status'
            severity = Get-RunnerPropertyText $Row 'Severity'
            classification = Get-RunnerPropertyText $Row 'Classification'
            classificationReason = Get-RunnerPropertyText $Row 'ClassificationReason' ''
            determination = 'unknown'
            createdDateTime = Get-RunnerPropertyText $Row 'CreatedTime' ''
            firstActivityDateTime = Get-RunnerPropertyText $Row 'FirstActivityTime' ''
            lastActivityDateTime = Get-RunnerPropertyText $Row 'LastActivityTime' ''
            closedDateTime = Get-RunnerPropertyText $Row 'ClosedTime' ''
            owner = if ([string]::IsNullOrWhiteSpace((Get-RunnerPropertyText $Row 'Owner' ''))) { 'unknown' } else { 'present_protected' }
            fact_source_id = 'sentinel-law'
            source_type = 'log_analytics_securityincident'
            title_ref = 'protected-evidence:log-analytics-securityincident-title'
        }
    }

    function Get-RunnerModifiedByAttribution {
        param($Row)
        $modifiedBy = Get-RunnerPropertyText $Row 'ModifiedBy' ''
        if ([string]::IsNullOrWhiteSpace($modifiedBy)) {
            return [pscustomobject][ordered]@{ actor = 'unknown'; source = 'unknown' }
        }
        $hashActor = Get-RunnerStableId -Prefix 'actor' -Parts @('ModifiedBy', $modifiedBy)
        $actorRef = "protected-context:$hashActor"
        $normalized = $modifiedBy.ToLowerInvariant()
        $source = if ($normalized -match '(automation|playbook|logic[-\s]?app|microsoft\s*sentinel|microsoft\s*365\s*defender|service[-\s]?principal|managed\s*identity)') {
            'automation'
        }
        elseif ($modifiedBy -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
            'analyst'
        }
        else { 'unknown' }
        [pscustomobject][ordered]@{ actor = $actorRef; source = $source }
    }

    function ConvertFrom-RunnerSecurityAlertEntitySeeds {
        param([object[]]$Rows)
        $records = [Collections.Generic.List[object]]::new()
        $index = 0
        foreach ($row in @($Rows)) {
            if ($null -eq $row -or $row.PSObject.Properties.Name -notcontains 'Entities' -or
                [string]::IsNullOrWhiteSpace([string]$row.Entities)) { continue }
            $entities = @()
            try { $entities = @($row.Entities | ConvertFrom-Json -Depth 50 -DateKind String) } catch { $entities = @() }
            foreach ($entity in @($entities)) {
                $type = (Get-RunnerPropertyText $entity 'Type' '').ToLowerInvariant()
                if ($type -notin @('account', 'host')) { continue }
                $index++
                $evidenceId = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityAlert', [string]$row.SystemAlertId, [string]$row.TimeGenerated)
                $entityId = Get-RunnerStableId -Prefix 'ENT' -Parts @('SecurityAlertEntity', [string]$row.SystemAlertId, [string]$row.TimeGenerated, [string]$type, [string]$index)
                $records.Add([pscustomobject][ordered]@{
                    entity_id = $entityId
                    entity_type = $type
                    aliases = @("protected:sentinel-alert-entity/$type/$index")
                    lifecycle_summary = 'Entity seed was observed in Log Analytics SecurityAlert Entities; raw entity identifiers are protected.'
                    attribution_boundary = 'Entity seed only; no identity continuity, ownership, or attribution assertion is made by the runner.'
                    source_id = 'sentinel-law'
                    raw_ref = 'protected-evidence:securityalert-entities'
                    claim_ids = @('CLAIM-incident-seed')
                    evidence_ids = @($evidenceId)
                    gap_ids = @()
                    error_ids = @()
                    behavior_bases = @('configurable_project_policy')
                })
            }
        }
        @($records)
    }

    function New-RunnerReportBundle {
        param(
            [Parameter(Mandatory)]$Bundle,
            [AllowNull()]$IncidentObject,
            [AllowEmptyCollection()][object[]]$CoverageGaps = @(),
            [Parameter(Mandatory)]$GeneratedAt
        )
        $gapIds = @($CoverageGaps | ForEach-Object { [string]$_.gap_id } | Where-Object { $_ } | Sort-Object -Unique)
        $gapLimitations = @($CoverageGaps | ForEach-Object {
            if ($_.PSObject.Properties.Name -contains 'message') { [string]$_.message }
            elseif ($_.PSObject.Properties.Name -contains 'rationale') { [string]$_.rationale }
        } | Where-Object { $_ } | Sort-Object -Unique)
        if ($gapLimitations.Count -eq 0) {
            $gapLimitations = if ($executionMode -eq 'offline_fixture') {
                @('No runner retrieval gaps were observed in the offline fixture run.')
            }
            else {
                @('No runner retrieval gaps were observed in the authorized live read run.')
            }
        }
        $title = if ($null -ne $IncidentObject -and $IncidentObject.PSObject.Properties.Name -contains 'displayName') {
            [string]$IncidentObject.displayName
        }
        else { 'Protected incident title unavailable' }
        $status = if ($null -ne $IncidentObject -and $IncidentObject.PSObject.Properties.Name -contains 'status') {
            [string]$IncidentObject.status
        }
        else { 'unknown' }
        $classification = if ($null -ne $IncidentObject -and $IncidentObject.PSObject.Properties.Name -contains 'classification') {
            [string]$IncidentObject.classification
        }
        else { 'unknown' }
        $severity = if ($null -ne $IncidentObject -and $IncidentObject.PSObject.Properties.Name -contains 'severity') {
            [string]$IncidentObject.severity
        }
        else { 'unknown' }
        $factSourceId = if ($null -ne $IncidentObject -and $IncidentObject.PSObject.Properties.Name -contains 'fact_source_id') {
            [string]$IncidentObject.fact_source_id
        }
        else { 'graph-security' }

        $coverageReceipts = @($Bundle.coverage.receipts | Where-Object { $null -ne $_ })
        if ($coverageReceipts.Count -gt 0) {
            foreach ($receipt in $coverageReceipts) {
                $existing = @()
                if ($receipt.PSObject.Properties.Name -contains 'limitations') {
                    $existing = @($receipt.limitations | ForEach-Object { [string]$_ })
                }
                $receipt.limitations = @($existing + $gapLimitations | Sort-Object -Unique)
                if ($gapIds.Count -gt 0) {
                    $receipt.gap_ids = @(@($receipt.gap_ids) + $gapIds | Sort-Object -Unique)
                }
            }
        }

        [pscustomobject][ordered]@{
            reportMetadata = [pscustomobject][ordered]@{
                report_id = "REP-runner-$executionMode-001"
                created_at = $GeneratedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
                audit_incident_ref = Get-RunnerStableId -Prefix 'INC-AUDIT' -Parts @('report-incident', $IncidentId)
                protected_incident_link_ref = "protected-link:incident-$((Get-RunnerStableId -Prefix 'inc' -Parts @('report-incident-link', $IncidentId)))"
                operating_mode = $executionMode
                reference_window = [pscustomobject][ordered]@{
                    start_inclusive = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    end_exclusive = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    original_timezone = 'UTC'
                    reason = 'Runner-provided incident audit window.'
                }
                contract_version = '2.0.0'
                schema_version = '2.0.0'
                label_map_version = '1.0.0'
                policy_version = '1.0.0'
                adapter_versions = [pscustomobject]@{}
                source_versions = [pscustomobject]@{
                    cloud_profile = [string]$cloudProfile.name
                }
                report_status = 'partial'
                report_locale = 'en'
                handling_marking = $handlingMarking
                execution_identity = 'havoc-incident-audit-runner'
                authorization_purpose = 'Authorized read-only incident audit retrieval'
                protected_evidence_store_reference_class = 'opaque_non_bearer_locator'
                authorization_scope_ref = "protected-context:tenant-$TenantId"
            }
            incidentSummary = @([pscustomobject][ordered]@{
                summary_id = 'SUM-runner-incident-001'
                original_status = $status
                original_classification = $classification
                original_severity = $severity
                fact_source_id = $factSourceId
                auditor_judgment = if ($executionMode -eq 'offline_fixture') { "Offline runner assembled core read-only evidence for $title." } else { "Authorized live read runner assembled core read-only evidence for $title." }
                likelihood = 'not_assessed'
                analytic_confidence = 'low'
                report_status = 'partial'
                claim_ids = @('CLAIM-incident-seed')
                evidence_ids = @('EVID-runner-seed')
                gap_ids = @($gapIds)
                error_ids = @()
                behavior_bases = @('configurable_project_policy')
            })
            evidenceRecords = @([pscustomobject][ordered]@{
                evidence_id = 'EVID-runner-seed'
                material_claim_id = 'CLAIM-incident-seed'
                evidence_class = 'fact'
                source_id = 'SRC-runner-core'
                source_type = 'havoc_runner_core_sources'
                provenance = 'Approved read-only adapters returned the core incident source envelopes.'
                raw_ref = 'protected-evidence:runner-seed'
                normalized_value = "Core incident source bundle for $title."
                transformation = 'runner report projection'
                transformation_version = '1.0.0'
                retrieval_time = $GeneratedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
                source_confidence = 'moderate'
                baseline_confidence = 'low'
                upstream_evidence_ids = @()
                limitations = @($gapLimitations)
                handling_marking = $handlingMarking
                claim_ids = @('CLAIM-incident-seed')
                behavior_bases = @('configurable_project_policy')
            })
            coverageReceipts = @($coverageReceipts)
            queryRecords = @($Bundle.coverage.queryLedger | Where-Object { $null -ne $_ })
            entityRecords = @($Bundle.entitySeeds | Where-Object { $null -ne $_ })
            timelineRecords = @($Bundle.timeline | Where-Object { $null -ne $_ })
            hypothesisRecords = @()
            causalRecords = @()
            decisionRecords = @($Bundle.decisions.containmentRecords | Where-Object { $null -ne $_ })
            automationRecords = @()
            recurrenceRecords = @()
            recoveryRecords = @($Bundle.recovery.records | Where-Object { $null -ne $_ })
            privacyRecords = @()
            businessFactRecords = @()
            legalFactRecords = @()
            qaRecords = @()
            stopReceipt = [pscustomobject][ordered]@{
                stop_receipt_id = 'STOP-runner-frontier-001'
                stop_cause = 'coverage_boundary'
                stopped_at = $GeneratedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
                actor = 'havoc-incident-audit-runner'
                policy_version = '1.0.0'
                configured_values = [pscustomobject]@{ frontier = 'domain micro-skill pivots' }
                consumption = [pscustomobject]@{ core_sources = @($Bundle.adapterEnvelopes).Count }
                coverage_summary = 'Core incident source retrieval completed; domain micro-skill pivots are listed as follow-up frontier.'
                unresolved_material_frontier = @('domain micro-skill pivots')
                duplicate_lineage_groups = @()
                novel_evidence_summary = 'Core incident, alert, Sentinel, analytics rule, and coverage envelopes were assembled.'
                hypothesis_stability = 'not assessed in core runner'
                circuit_breaker_state = 'not tripped'
                last_successful_operation = 'core incident source retrieval'
                gap_ids = @($gapIds)
                error_ids = @()
                restart_conditions = @('Execute domain micro-skill pivots after review gates authorize broader scope.')
                gap_records = @()
                behavior_bases = @('configurable_project_policy')
            }
            errors = @()
            detectionQuality = $Bundle.detectionQuality
            entityResolutionDecisions = @($Bundle.entities | Where-Object { $null -ne $_ })
            decisionTimeSocReconstruction = $Bundle.decisionSnapshot
            lifecycleContinuity = [pscustomobject][ordered]@{
                timeline_record_ids = @($Bundle.timeline | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.timeline_id })
                recurrence = $Bundle.recurrence
                saturation = $Bundle.saturation
            }
            telemetryDrift = [pscustomobject][ordered]@{
                limitations = @($gapLimitations)
                status = if ($gapIds.Count -gt 0) { 'partial' } else { 'not_observed' }
            }
            qaDisagreements = @()
        }
    }
function Convert-EnvelopeToGap {
    param($Envelope)
    $source = [string]$Envelope.adapter.source
    if ([string]::IsNullOrWhiteSpace($source)) { $source = [string]$Envelope.queryLedger.operation_id }
    if ([string]$Envelope.status -eq 'success') { return @() }
    if (@($Envelope.errors).Count -eq 0) {
        return @(New-RunnerGap $source 'adapter_non_success' "Adapter status was $($Envelope.status).")
    }
    @($Envelope.errors | ForEach-Object {
        $code = if ($_.PSObject.Properties.Name -contains 'code') { [string]$_.code } else { 'adapter_error' }
        $message = if ($_.PSObject.Properties.Name -contains 'message') { [string]$_.message } else { 'Adapter returned an error.' }
        New-RunnerGap $source $code $message
    })
}

function Try-Kernel {
    param([string]$Name, [scriptblock]$Body, [Collections.Generic.List[object]]$Gaps)
    try {
        & $Body
    }
    catch {
        $Gaps.Add((New-RunnerGap 'kernel' "kernel_$Name`_unavailable" "Kernel stage '$Name' could not assemble from current read-only inputs."))
        $null
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if ($null -eq $ProtectedStore) {
    $protectedDirectory = Join-Path $OutputDirectory 'protected'
    New-Item -ItemType Directory -Path $protectedDirectory -Force | Out-Null
    $ProtectedStore = {
        param($Kind, $Value, $Metadata)
        $operationId = if ($null -ne $Metadata -and $Metadata.PSObject.Properties.Name -contains 'operationId') {
            [string]$Metadata.operationId
        }
        else { 'unknown-operation' }
        $prefix = if ([string]$Kind -eq 'request') { 'protected-request' } else { 'protected-evidence' }
        $fileName = '{0}-{1}-{2}.json' -f $prefix, ($operationId -replace '[^A-Za-z0-9._-]', '-'), ([guid]::NewGuid().ToString('N'))
        $path = Join-Path $protectedDirectory $fileName
        [pscustomobject][ordered]@{
            kind = [string]$Kind
            metadata = $Metadata
            value = $Value
        } | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8
        "$prefix`:$fileName"
    }.GetNewClosure()
}

$capturedEvidence = [Collections.Generic.List[object]]::new()
$runnerIntentRecords = [Collections.Generic.List[object]]::new()
$AdapterProtectedStore = {
    param($Kind, $Value, $Metadata)
    $reference = & $ProtectedStore $Kind $Value $Metadata
    $capturedEvidence.Add([pscustomobject][ordered]@{
        Kind = $Kind
        Value = $Value
        Metadata = $Metadata
        Reference = $reference
    })
    $reference
}.GetNewClosure()

$graphIncidentUri = 'https://{0}/v1.0/security/incidents/{1}?$expand=alerts' -f ([string]$cloudProfile.graphHost), $IncidentId
$graphIntent = New-RunnerIntent -OperationId 'graph-security-incident-with-alerts-get' `
    -Method 'GET' -Uri $graphIncidentUri -RequestedScopes @('SecurityIncident.Read.All') `
    -TokenScopes @('SecurityIncident.Read.All') -SourceIds @('graph-security') -MaxRows 1
$graphIntent.requestedScopes = @([string]$cloudProfile.requestScopes.graphSecurityIncidentRead)

$timeSpan = '{0}/{1}' -f $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$incidentPredicates = @("ProviderIncidentId == '$IncidentId'")
if (-not [string]::IsNullOrWhiteSpace($SentinelIncidentId)) {
    $incidentPredicates += "IncidentName == '$SentinelIncidentId'"
}
$incidentPredicate = '(' + ($incidentPredicates -join ' or ') + ')'
$securityIncidentQuery = "SecurityIncident | where TimeGenerated >= datetime($($StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))) | where TimeGenerated < datetime($($EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))) | where $incidentPredicate | project TimeGenerated, IncidentNumber, IncidentName, ProviderIncidentId, ProviderName, Severity, Status, Classification, ClassificationReason, ModifiedBy, Owner, CreatedTime, FirstActivityTime, LastActivityTime, ClosedTime, Title, AlertIds, Labels, IncidentUrl | take 100"
$securityAlertQuery = "let MatchedIncidentAlertIds = SecurityIncident | where TimeGenerated >= datetime($($StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))) | where TimeGenerated < datetime($($EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))) | where $incidentPredicate | mv-expand AlertId = todynamic(AlertIds) | project AlertId = tostring(AlertId); SecurityAlert | where TimeGenerated >= datetime($($StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))) | where TimeGenerated < datetime($($EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))) | where SystemAlertId in (MatchedIncidentAlertIds) | project TimeGenerated, SystemAlertId, ProviderName, AlertName, AlertSeverity, Entities, ExtendedProperties, Tactics, Techniques, ProductName, StartTime, EndTime, VendorOriginalId | take 100"
$coverageLookbackStart = $StartTime.AddDays(-1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$coverageEnd = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$sentinelHealthRowLimit = 50
$sentinelHealthQuery = "SentinelHealth | where TimeGenerated >= datetime($coverageLookbackStart) | where TimeGenerated < datetime($coverageEnd) | where SentinelResourceType == 'Data connector' | summarize arg_max(TimeGenerated, *) by SentinelResourceId | project TimeGenerated, SentinelResourceType, SentinelResourceId, SentinelResourceName, Status, Description | take $sentinelHealthRowLimit"
$workspacePresenceQuery = "SecurityIncident | where TimeGenerated >= datetime($coverageLookbackStart) | where TimeGenerated < datetime($coverageEnd) | project TimeGenerated, IncidentName, ProviderIncidentId, ProviderName | take 50"
$connectorFreshnessQuery = "union isfuzzy=true (Usage | where TimeGenerated >= datetime($coverageLookbackStart) | where TimeGenerated < datetime($coverageEnd) | where DataType in ('SecurityIncident','SecurityAlert') | project TimeGenerated, DataType, Quantity), (Heartbeat | where TimeGenerated >= datetime($coverageLookbackStart) | where TimeGenerated < datetime($coverageEnd) | project TimeGenerated, DataType='Heartbeat', Quantity=1) | take 50"

$sentinelHealthIntent = New-RunnerLogIntent -Query $sentinelHealthQuery -MaxRows $sentinelHealthRowLimit
$workspacePresenceIntent = New-RunnerLogIntent -Query $workspacePresenceQuery -MaxRows 50
$connectorFreshnessIntent = New-RunnerLogIntent -Query $connectorFreshnessQuery -MaxRows 50
$logIncidentIntent = New-RunnerLogIntent -Query $securityIncidentQuery -MaxRows 100
$logAlertIntent = New-RunnerLogIntent -Query $securityAlertQuery -MaxRows 100

$envelopes = [Collections.Generic.List[object]]::new()
$coverageVerificationEnvelopes = [ordered]@{}
if (-not $trustedTransportMissing) {
    $envelopes.Add((Invoke-RunnerAdapter 'Invoke-ReadOnlyGraphQuery.ps1' $graphIntent))
    $coverageVerificationEnvelopes['sentinel_onboarded'] = Add-RunnerObjectNote (Invoke-RunnerAdapter 'Invoke-ReadOnlyLogQuery.ps1' $sentinelHealthIntent) 'runnerCoverageSignal' 'sentinel_onboarded'
    $coverageVerificationEnvelopes['workspace_covered'] = Add-RunnerObjectNote (Invoke-RunnerAdapter 'Invoke-ReadOnlyLogQuery.ps1' $workspacePresenceIntent) 'runnerCoverageSignal' 'workspace_covered'
    $coverageVerificationEnvelopes['connector_healthy'] = Add-RunnerObjectNote (Invoke-RunnerAdapter 'Invoke-ReadOnlyLogQuery.ps1' $connectorFreshnessIntent) 'runnerCoverageSignal' 'connector_healthy'
    foreach ($signalEnvelope in @($coverageVerificationEnvelopes.Values)) { $envelopes.Add($signalEnvelope) }
    $envelopes.Add((Invoke-RunnerAdapter 'Invoke-ReadOnlyLogQuery.ps1' $logIncidentIntent))
    $envelopes.Add((Invoke-RunnerAdapter 'Invoke-ReadOnlyLogQuery.ps1' $logAlertIntent))
}

if (-not $trustedTransportMissing -and $SubscriptionId -and $ResourceGroupName -and $WorkspaceName -and $SentinelIncidentId) {
    $sentinelBase = "https://$($cloudProfile.armHost)/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
    $sentinelIntent = New-RunnerIntent -OperationId 'sentinel-incident-get' -Method 'GET' `
        -Uri ('{0}/incidents/{1}?api-version=2025-09-01' -f $sentinelBase, $SentinelIncidentId) `
        -RequestedScopes @([string]$cloudProfile.requestScopes.armDefault) -TokenScopes @() `
        -TokenRoles @() -SourceIds @('sentinel-arm') -MaxRows 1
    $sentinelIntent | Add-Member -NotePropertyName credentialClass -NotePropertyValue 'application'
    $sentinelIntent | Add-Member -NotePropertyName armRbacReadApproved -NotePropertyValue $true
    $envelopes.Add((Invoke-RunnerAdapter 'Invoke-ReadOnlyArmQuery.ps1' $sentinelIntent))
    if ($AnalyticsRuleId) {
        $ruleIntent = New-RunnerIntent -OperationId 'sentinel-analytics-rule-get' -Method 'GET' `
            -Uri ('{0}/alertRules/{1}?api-version=2025-09-01' -f $sentinelBase, $AnalyticsRuleId) `
            -RequestedScopes @([string]$cloudProfile.requestScopes.armDefault) -TokenScopes @() `
            -TokenRoles @() -SourceIds @('sentinel-arm') -MaxRows 1
        $ruleIntent | Add-Member -NotePropertyName credentialClass -NotePropertyValue 'application'
        $ruleIntent | Add-Member -NotePropertyName armRbacReadApproved -NotePropertyValue $true
        $envelopes.Add((Invoke-RunnerAdapter 'Invoke-ReadOnlyArmQuery.ps1' $ruleIntent))
    }
}

$graphEnvelope = $envelopes | Where-Object { [string]$_.queryLedger.operation_id -eq 'graph-security-incident-with-alerts-get' } | Select-Object -First 1
$graphPayloads = @(Get-RunnerPayloadForEnvelope $graphEnvelope)
$graphIncident = if ($graphPayloads.Count -gt 0) { $graphPayloads[0] } else { $null }
$graphAlerts = if ($null -ne $graphIncident -and $graphIncident.PSObject.Properties.Name -contains 'alerts') {
    @($graphIncident.alerts)
}
else { @() }
$armRulePayloads = @(Get-RunnerPayloadForEnvelope ($envelopes | Where-Object { [string]$_.queryLedger.operation_id -eq 'sentinel-analytics-rule-get' } | Select-Object -First 1))
$analyticsRule = if ($armRulePayloads.Count -gt 0) { $armRulePayloads[0] } else { $null }
$sentinelHealthPayloads = @(Get-RunnerPayloadForEnvelope $coverageVerificationEnvelopes['sentinel_onboarded'])
$workspacePresencePayloads = @(Get-RunnerPayloadForEnvelope $coverageVerificationEnvelopes['workspace_covered'])
$connectorFreshnessPayloads = @(Get-RunnerPayloadForEnvelope $coverageVerificationEnvelopes['connector_healthy'])
$securityIncidentPayloads = @(Get-RunnerPayloadForEnvelope ($envelopes | Where-Object {
    [string]$_.queryLedger.operation_id -eq 'log-analytics-query' -and
    $_.PSObject.Properties.Name -notcontains 'runnerCoverageSignal' -and
    $_.PSObject.Properties.Name -notcontains 'runnerPivotName'
} | Select-Object -First 1))
$securityAlertPayloads = @(Get-RunnerPayloadForEnvelope ($envelopes | Where-Object {
    [string]$_.queryLedger.operation_id -eq 'log-analytics-query' -and
    $_.PSObject.Properties.Name -notcontains 'runnerCoverageSignal' -and
    $_.PSObject.Properties.Name -notcontains 'runnerPivotName'
} | Select-Object -Skip 1 -First 1))
$sentinelHealthRows = if ($sentinelHealthPayloads.Count -gt 0) { @(ConvertFrom-RunnerLogPayloadRows $sentinelHealthPayloads[0]) } else { @() }
$workspacePresenceRows = if ($workspacePresencePayloads.Count -gt 0) { @(ConvertFrom-RunnerLogPayloadRows $workspacePresencePayloads[0]) } else { @() }
$connectorFreshnessRows = if ($connectorFreshnessPayloads.Count -gt 0) { @(ConvertFrom-RunnerLogPayloadRows $connectorFreshnessPayloads[0]) } else { @() }
$securityIncidentRows = if ($securityIncidentPayloads.Count -gt 0) { @(ConvertFrom-RunnerLogPayloadRows $securityIncidentPayloads[0]) } else { @() }
$securityAlertRows = if ($securityAlertPayloads.Count -gt 0) { @(ConvertFrom-RunnerLogPayloadRows $securityAlertPayloads[0]) } else { @() }
$pendingRowCoverageGaps = [Collections.Generic.List[object]]::new()
$securityIncidentRows = @(Select-RunnerRowsWithValidTimeGenerated -Rows $securityIncidentRows -Source 'log_analytics_securityincident' -GapList $pendingRowCoverageGaps)
$securityAlertRows = @(Select-RunnerRowsWithValidTimeGenerated -Rows $securityAlertRows -Source 'log_analytics_securityalert' -GapList $pendingRowCoverageGaps)
$latestSecurityIncidentRow = @(Get-RunnerLatestSecurityIncidentRow -Rows $securityIncidentRows | Select-Object -First 1)
$logAnalyticsIncidentFallbackActive = $false
$effectiveIncident = $graphIncident
if ($null -eq $graphIncident -and $null -ne $graphEnvelope -and [string]$graphEnvelope.status -ne 'success' -and $latestSecurityIncidentRow.Count -gt 0) {
    $effectiveIncident = New-RunnerLogAnalyticsIncidentObject -Row $latestSecurityIncidentRow[0]
    $logAnalyticsIncidentFallbackActive = $null -ne $effectiveIncident
}
$connectorSpecificHealthRows = @($sentinelHealthRows | Where-Object {
    $names = @($_.PSObject.Properties.Name)
    $resourceType = if ($names -contains 'SentinelResourceType') { [string]$_.SentinelResourceType } else { '' }
    $resourceType -match '^(?i:Data connector)$'
})
$sentinelOnboardedSignal = Add-RunnerSignalAttestation `
    -SignalRecord (Get-RunnerSignalState -Signal 'sentinel_onboarded' -Rows $sentinelHealthRows -Envelope $coverageVerificationEnvelopes['sentinel_onboarded']) `
    -Signal 'sentinel_onboarded' -Envelope $coverageVerificationEnvelopes['sentinel_onboarded']
$workspaceCoveredSignal = Add-RunnerSignalAttestation `
    -SignalRecord (Get-RunnerSignalState -Signal 'workspace_covered' -Rows $workspacePresenceRows -Envelope $coverageVerificationEnvelopes['workspace_covered']) `
    -Signal 'workspace_covered' -Envelope $coverageVerificationEnvelopes['workspace_covered']
$connectorHasNegativeHealth = @($connectorSpecificHealthRows | Where-Object {
    $_.PSObject.Properties.Name -contains 'Status' -and (Test-RunnerSentinelHealthNegativeStatus ([string]$_.Status))
}).Count -gt 0
$connectorSignalRecord = if ($connectorHasNegativeHealth) {
    Get-RunnerSignalState -Signal 'connector_healthy' -Rows $connectorSpecificHealthRows -Envelope $coverageVerificationEnvelopes['sentinel_onboarded']
}
elseif (@($connectorSpecificHealthRows).Count -ge $sentinelHealthRowLimit) {
    [pscustomobject][ordered]@{
        signal = 'connector_healthy'
        status = 'not_verifiable'
        basis = "SentinelHealth Data connector pre-check returned the bounded cap of $sentinelHealthRowLimit rows; connector health cannot be verified true from a potentially truncated result"
        query_ref = if ($null -ne $coverageVerificationEnvelopes['sentinel_onboarded'] -and
            $coverageVerificationEnvelopes['sentinel_onboarded'].PSObject.Properties.Name -contains 'protectedResponseRef') { [string]$coverageVerificationEnvelopes['sentinel_onboarded'].protectedResponseRef } else { 'not-applicable:none' }
        row_count = @($connectorSpecificHealthRows).Count
        value_origin = 'verified'
    }
}
elseif (@($connectorSpecificHealthRows).Count -gt 0) {
    Get-RunnerSignalState -Signal 'connector_healthy' -Rows $connectorSpecificHealthRows -Envelope $coverageVerificationEnvelopes['sentinel_onboarded']
}
elseif ($null -ne $coverageVerificationEnvelopes['connector_healthy'] -and
    [string]$coverageVerificationEnvelopes['connector_healthy'].status -ne 'success') {
    Get-RunnerSignalState -Signal 'connector_healthy' -Rows $connectorFreshnessRows -Envelope $coverageVerificationEnvelopes['connector_healthy']
}
else {
    [pscustomobject][ordered]@{
        signal = 'connector_healthy'
        status = 'not_verifiable'
        basis = if (Test-RunnerConnectorFreshnessRows -Rows $connectorFreshnessRows) { 'Usage ingestion freshness was observed, but SentinelHealth did not verify connector health' } else { 'SentinelHealth did not return connector health rows' }
        query_ref = if ($null -ne $coverageVerificationEnvelopes['connector_healthy'] -and
            $coverageVerificationEnvelopes['connector_healthy'].PSObject.Properties.Name -contains 'protectedResponseRef') { [string]$coverageVerificationEnvelopes['connector_healthy'].protectedResponseRef } else { 'not-applicable:none' }
        row_count = @($connectorFreshnessRows).Count
        value_origin = 'verified'
    }
}
$connectorHealthySignal = Add-RunnerSignalAttestation -SignalRecord $connectorSignalRecord -Signal 'connector_healthy' -Envelope $coverageVerificationEnvelopes['connector_healthy']
$coverageVerification = [pscustomobject][ordered]@{
    source = 'log_analytics_precheck'
    value_origin = 'verified'
    signals = [pscustomobject][ordered]@{
        sentinel_onboarded = $sentinelOnboardedSignal
        workspace_covered = $workspaceCoveredSignal
        connector_healthy = $connectorHealthySignal
    }
}
$healthRecords = @()
$auditRecords = @()

$matchedAlertIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($alert in @($graphAlerts)) {
    foreach ($name in @('providerAlertId', 'id')) {
        if ($alert.PSObject.Properties.Name -contains $name -and -not [string]::IsNullOrWhiteSpace([string]$alert.$name)) {
            [void]$matchedAlertIds.Add([string]$alert.$name)
        }
    }
}
$historicalAlertIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($row in @($latestSecurityIncidentRow)) {
    if ($row.PSObject.Properties.Name -contains 'AlertIds' -and -not [string]::IsNullOrWhiteSpace([string]$row.AlertIds)) {
        try {
            foreach ($id in @($row.AlertIds | ConvertFrom-Json -Depth 20 -DateKind String)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$id)) { [void]$matchedAlertIds.Add([string]$id) }
            }
        }
        catch {
            foreach ($id in @(([string]$row.AlertIds) -split ',' | ForEach-Object { $_.Trim(' "', '[', ']') })) {
                if (-not [string]::IsNullOrWhiteSpace($id)) { [void]$matchedAlertIds.Add($id) }
            }
        }
    }
}
foreach ($row in @($securityIncidentRows)) {
    if ($latestSecurityIncidentRow.Count -gt 0 -and $row -eq $latestSecurityIncidentRow[0]) { continue }
    if ($row.PSObject.Properties.Name -contains 'AlertIds' -and -not [string]::IsNullOrWhiteSpace([string]$row.AlertIds)) {
        try {
            foreach ($id in @($row.AlertIds | ConvertFrom-Json -Depth 20 -DateKind String)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$id) -and -not $matchedAlertIds.Contains([string]$id)) { [void]$historicalAlertIds.Add([string]$id) }
            }
        }
        catch {
            foreach ($id in @(([string]$row.AlertIds) -split ',' | ForEach-Object { $_.Trim(' "', '[', ']') })) {
                if (-not [string]::IsNullOrWhiteSpace($id) -and -not $matchedAlertIds.Contains($id)) { [void]$historicalAlertIds.Add($id) }
            }
        }
    }
}
if ($historicalAlertIds.Count -gt 0) {
    $gap = New-RunnerGap 'sentinel-law' 'securityincident_historical_alertids_not_loaded' "Older SecurityIncident history rows referenced alert ids absent from the latest incident row; historical-only alert reference count: $($historicalAlertIds.Count). Raw alert identifiers are withheld."
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
    $pendingRowCoverageGaps.Add($gap)
}
if ($matchedAlertIds.Count -gt 0) {
    $securityAlertRows = @($securityAlertRows | Where-Object {
        $_.PSObject.Properties.Name -contains 'SystemAlertId' -and $matchedAlertIds.Contains([string]$_.SystemAlertId)
    })
}

$alertRuleIdsByAlertId = @{}
foreach ($row in @($securityAlertRows)) {
    $extended = $null
    if ($row.PSObject.Properties.Name -contains 'ExtendedProperties' -and -not [string]::IsNullOrWhiteSpace([string]$row.ExtendedProperties)) {
        try { $extended = $row.ExtendedProperties | ConvertFrom-Json -Depth 50 -DateKind String } catch { $extended = $null }
    }
    $ruleId = if ($null -ne $extended -and $extended.PSObject.Properties.Name -contains 'Analytic Rule Id') {
        [string]$extended.'Analytic Rule Id'
    }
    elseif ($null -ne $extended -and $extended.PSObject.Properties.Name -contains 'AlertRuleId') {
        [string]$extended.AlertRuleId
    }
    else { '' }
    if (-not [string]::IsNullOrWhiteSpace($ruleId) -and $row.PSObject.Properties.Name -contains 'SystemAlertId') {
        $alertRuleIdsByAlertId[[string]$row.SystemAlertId] = $ruleId
    }
}
$detectionAlerts = @($graphAlerts | ForEach-Object {
    $alert = $_
    $providerAlertId = if ($alert.PSObject.Properties.Name -contains 'providerAlertId') { [string]$alert.providerAlertId } else { [string]$alert.id }
    $ruleId = if ($alertRuleIdsByAlertId.ContainsKey($providerAlertId)) { $alertRuleIdsByAlertId[$providerAlertId] } else { $null }
    if ([string]::IsNullOrWhiteSpace($ruleId)) { $alert }
    else {
        $copy = [ordered]@{}
        foreach ($property in $alert.PSObject.Properties) { $copy[$property.Name] = $property.Value }
        $copy['alertRuleId'] = $ruleId
        [pscustomobject]$copy
    }
})
$detectionAlerts = @($detectionAlerts | ForEach-Object {
    $alert = $_
    $rawAlertId = if ($alert.PSObject.Properties.Name -contains 'providerAlertId' -and -not [string]::IsNullOrWhiteSpace([string]$alert.providerAlertId)) {
        [string]$alert.providerAlertId
    }
    elseif ($alert.PSObject.Properties.Name -contains 'id') { [string]$alert.id }
    else { '' }
    $stableAlertId = Get-RunnerStableId -Prefix 'ALERT' -Parts @('GraphSecurityAlert', $rawAlertId, (Get-RunnerPropertyText $alert 'createdDateTime' ''))
    $copy = [ordered]@{}
    foreach ($property in $alert.PSObject.Properties) { $copy[$property.Name] = $property.Value }
    $copy['id'] = $stableAlertId
    $copy['providerAlertId'] = $stableAlertId
    if ($copy.Contains('title')) { $copy['title'] = 'Protected Graph security alert title.' }
    [pscustomobject]$copy
})
if ($logAnalyticsIncidentFallbackActive -and @($detectionAlerts).Count -eq 0) {
    $detectionAlerts = @($securityAlertRows | ForEach-Object {
        $rawAlertId = Get-RunnerPropertyText $_ 'SystemAlertId'
        $alertId = Get-RunnerStableId -Prefix 'ALERT' -Parts @('SecurityAlert', $rawAlertId, (Get-RunnerPropertyText $_ 'TimeGenerated' ''))
        [pscustomobject][ordered]@{
            id = $alertId
            title = 'Protected alert title from Log Analytics'
            severity = Get-RunnerPropertyText $_ 'AlertSeverity'
            providerAlertId = $alertId
            serviceSource = 'microsoftSentinel'
            detectionSource = 'microsoftSentinel'
            productName = Get-RunnerPropertyText $_ 'ProductName' 'Microsoft Sentinel'
            createdDateTime = Get-RunnerPropertyText $_ 'TimeGenerated' ''
            firstActivityDateTime = Get-RunnerPropertyText $_ 'StartTime' ''
            lastActivityDateTime = Get-RunnerPropertyText $_ 'EndTime' ''
            mitreTechniques = @((Get-RunnerPropertyText $_ 'Techniques' '') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            categories = @((Get-RunnerPropertyText $_ 'Tactics' '') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            alertRuleId = if ($alertRuleIdsByAlertId.ContainsKey($rawAlertId)) { $alertRuleIdsByAlertId[$rawAlertId] } else { $null }
        }
    })
}

$pivotExecutionRecords = [Collections.Generic.List[object]]::new()
$pivotFrontierRecords = [Collections.Generic.List[object]]::new()
$pivotEvidenceRecords = [Collections.Generic.List[object]]::new()
$pendingPivotCoverageGaps = [Collections.Generic.List[object]]::new()
if (-not $trustedTransportMissing -and $ExecutePivots) {
    $matchedSkills = @(Get-RunnerMatchedDomainSkills -Alerts $graphAlerts)
    $entityBindings = Get-RunnerEntityBindings -Alerts $graphAlerts
    $accountAmbiguities = @($entityBindings['__ambiguities'])
    if ($accountAmbiguities.Count -gt 0) {
        $gap = New-RunnerGap 'sentinel-law' 'pivot_account_ambiguous' "Account pivot binding observed $($accountAmbiguities.Count) account identifier ambiguity record(s); affected accounts are kept separate and no raw account identifiers are emitted in this gap."
        $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
        $pendingPivotCoverageGaps.Add($gap)
    }
    $skillOrder = @(
        $matchedSkills
        @(
            'incident-audit-endpoint',
            'incident-audit-identity',
            'incident-audit-email',
            'incident-audit-network',
            'incident-audit-azure-control-plane',
            'incident-audit-persistence-lateral',
            'incident-audit-recurrence',
            'incident-audit-recovery',
            'incident-audit-oauth-apps',
            'incident-audit-m365-data',
            'incident-audit-threat-intel',
            'incident-audit-windows-forensics',
            'incident-audit-ad-hybrid',
            'incident-audit-exploitation',
            'incident-audit-linux-containers',
            'incident-audit-ransomware',
            'incident-audit-saas-mdca',
            'incident-audit-insider-risk'
        )
    ) | ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique
    $skillRank = @{}
    for ($rank = 0; $rank -lt $skillOrder.Count; $rank++) { $skillRank[$skillOrder[$rank]] = $rank }
    $candidatePivots = @(Get-RunnerPivotCatalog | Sort-Object `
        @{ Expression = { if ($skillRank.ContainsKey([string]$_.skill)) { $skillRank[[string]$_.skill] } else { 999 } } }, `
        @{ Expression = { [int]$_.priority } }, `
        @{ Expression = { [string]$_.skill } }, `
        @{ Expression = { [int]$_.sequence } })
    $executedPivotQueries = 0
    $pivotBudgetClosed = $false
    $pivotBudgetGapRecorded = $false
    foreach ($pivot in $candidatePivots) {
        if ($pivotBudgetClosed -or $executedPivotQueries -ge $MaxPivotQueries) {
            $pivotFrontierRecords.Add([pscustomobject][ordered]@{
                skill = [string]$pivot.skill
                name = [string]$pivot.name
                status = 'skipped_budget'
                reason = "MaxPivotQueries budget $MaxPivotQueries was exhausted"
                query_text_hash = 'not-applicable:budget'
            })
            if (-not $pivotBudgetGapRecorded) {
                $gap = New-RunnerGap 'sentinel-law' 'pivot_budget_truncated' "One or more pivots remained on the frontier because MaxPivotQueries budget $MaxPivotQueries was exhausted."
                $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
                $pendingPivotCoverageGaps.Add($gap)
                $pivotBudgetGapRecorded = $true
            }
            continue
        }
        $bindingVariants = @(Get-RunnerPivotBindingVariants -Pivot $pivot -Bindings $entityBindings)
        $successfulVariants = @($bindingVariants | Where-Object { $_.bound.success })
        foreach ($failedVariant in @($bindingVariants | Where-Object { -not $_.bound.success })) {
            $pivotFrontierRecords.Add([pscustomobject][ordered]@{
                skill = [string]$pivot.skill
                name = [string]$pivot.name
                status = 'skipped_binding'
                reason = [string]$failedVariant.bound.reason
                query_text_hash = 'not-applicable:binding'
                binding_entity_ref = [string]$failedVariant.binding_entity_ref
            })
        }
        if ($successfulVariants.Count -eq 0) {
            $failed = @($bindingVariants)[0]
            if ($null -eq $failed) {
                $pivotFrontierRecords.Add([pscustomobject][ordered]@{
                    skill = [string]$pivot.skill
                    name = [string]$pivot.name
                    status = 'skipped_binding'
                    reason = 'missing required binding'
                    query_text_hash = 'not-applicable:binding'
                })
            }
            continue
        }
        $remainingBudget = $MaxPivotQueries - $executedPivotQueries
        if ($successfulVariants.Count -gt $remainingBudget) {
            foreach ($variant in $successfulVariants) {
                $pivotFrontierRecords.Add([pscustomobject][ordered]@{
                    skill = [string]$pivot.skill
                    name = [string]$pivot.name
                    status = 'skipped_budget'
                    reason = "Executing this pivot for every validated account entity would exceed MaxPivotQueries budget $MaxPivotQueries"
                    query_text_hash = 'sha256:' + (Get-RunnerSha256Hex ([string]$variant.bound.query))
                    binding_entity_ref = [string]$variant.binding_entity_ref
                })
            }
            $gap = New-RunnerGap 'sentinel-law' 'pivot_budget_truncated' "Pivot '$($pivot.name)' from $($pivot.skill) was kept on the frontier because the remaining budget could not cover every validated account entity at the same depth."
            $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
            $pendingPivotCoverageGaps.Add($gap)
            $pivotBudgetGapRecorded = $true
            $pivotBudgetClosed = $true
            continue
        }
        foreach ($variant in $successfulVariants) {
            $bound = $variant.bound
            $mutationFindings = @(& $runnerMutationScanner -Text ([string]$bound.query) -KqlContext)
            if ($mutationFindings.Count -gt 0) {
                $pivotFrontierRecords.Add([pscustomobject][ordered]@{
                    skill = [string]$pivot.skill
                    name = [string]$pivot.name
                    status = 'error'
                    reason = 'pivot query failed the mutation scanner'
                    query_text_hash = 'sha256:' + (Get-RunnerSha256Hex ([string]$bound.query))
                    binding_entity_ref = [string]$variant.binding_entity_ref
                })
                $gap = New-RunnerGap 'sentinel-law' 'pivot_mutation_scanner_blocked' "Pivot '$($pivot.name)' from $($pivot.skill) was blocked by the mutation scanner and was not treated as a clean result."
                $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'high'
                $pendingPivotCoverageGaps.Add($gap)
                continue
            }
            $pivotIntent = New-RunnerLogIntent -Query ([string]$bound.query) -MaxRows 100 -SourceIds @('sentinel-law', "pivot-$($pivot.skill)")
            $pivotEnvelope = Add-RunnerObjectNote (Invoke-RunnerAdapter 'Invoke-ReadOnlyLogQuery.ps1' $pivotIntent) 'runnerPivotName' ([string]$pivot.name)
            $pivotEnvelope = Add-RunnerObjectNote $pivotEnvelope 'runnerPivotSkill' ([string]$pivot.skill)
            $envelopes.Add($pivotEnvelope)
            $executedPivotQueries++
            $pivotRowCount = [int]$pivotEnvelope.counts.rows
            $status = if ([string]$pivotEnvelope.status -eq 'success' -and $pivotRowCount -ge 100) { 'result_capped' }
                elseif ([string]$pivotEnvelope.status -eq 'success') { 'ok' }
                elseif (@($pivotEnvelope.errors | Where-Object { [string]$_.error_code -match '(?i)table|TableNotFound|table_or_audit_disabled' }).Count -gt 0) { 'table_missing' }
                elseif (@($pivotEnvelope.errors | Where-Object { [string]$_.error_category -eq 'safety_policy_denied' -or [string]$_.error_code -match '(?i)denied|Forbidden' }).Count -gt 0) { 'denied' }
                else { 'error' }
            if ($status -eq 'result_capped') {
                $gap = New-RunnerGap 'sentinel-law' 'pivot_result_capped' "Pivot '$($pivot.name)' from $($pivot.skill) returned exactly the runner row cap and may be truncated; results are evidence but not a clean absence signal."
                $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
                $pendingPivotCoverageGaps.Add($gap)
            }
            $record = [pscustomobject][ordered]@{
                skill = [string]$pivot.skill
                name = [string]$pivot.name
                status = $status
                query_text_hash = 'sha256:' + (Get-RunnerSha256Hex ([string]$bound.query))
                bound_parameters = @($bound.bound_parameters)
                binding_entity_ref = [string]$variant.binding_entity_ref
                row_count = $pivotRowCount
                evidence_ref = if ($pivotEnvelope.PSObject.Properties.Name -contains 'protectedResponseRef') { [string]$pivotEnvelope.protectedResponseRef } else { 'not-applicable:none' }
                adapter_status = [string]$pivotEnvelope.status
            }
            $pivotExecutionRecords.Add($record)
            if ($status -in @('ok', 'result_capped')) {
                $pivotEvidenceRecords.Add([pscustomobject][ordered]@{
                    evidence_id = Get-RunnerStableId -Prefix 'EVID-PIVOT' -Parts @([string]$pivot.skill, [string]$pivot.name, [string]$record.query_text_hash, [string]$variant.binding_entity_ref)
                    skill = [string]$pivot.skill
                    pivot = [string]$pivot.name
                    source_type = 'log_analytics_pivot'
                    raw_ref = [string]$record.evidence_ref
                    row_count = [int]$record.row_count
                    query_text_hash = [string]$record.query_text_hash
                })
            }
        }
    }
}

$coverageGaps = [Collections.Generic.List[object]]::new()
if ($trustedTransportMissing) {
    $coverageGaps.Add((New-RunnerGap 'transport' 'trusted_transport_required' 'A trusted transport implementing references\trusted-transport-interface.json is required; no tenant requests were attempted.'))
}
if (-not [string]::IsNullOrWhiteSpace([string]$cloudProfileResolutionError)) {
    $gap = New-RunnerGap 'cloud_profile' 'cloud_profile_unavailable' "Cloud profile '$Cloud' could not be resolved; no tenant requests were attempted."
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'high'
    $coverageGaps.Add($gap)
}
foreach ($expectedGap in @($cloudProfile.expectedCoverageGaps)) {
    if ([string]::IsNullOrWhiteSpace([string]$expectedGap)) { continue }
    $gap = New-RunnerGap 'cloud_profile' ([string]$expectedGap) "Selected cloud profile '$($cloudProfile.name)' declares expected coverage gap: $expectedGap."
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
    $coverageGaps.Add($gap)
}
foreach ($gap in @($pendingPivotCoverageGaps)) { $coverageGaps.Add($gap) }
foreach ($gap in @($pendingRowCoverageGaps)) { $coverageGaps.Add($gap) }
foreach ($envelope in @($envelopes)) {
    foreach ($gap in @(Convert-EnvelopeToGap $envelope)) { $coverageGaps.Add($gap) }
}
if ($logAnalyticsIncidentFallbackActive) {
    $gap = New-RunnerGap 'sentinel-law' 'incident_facts_from_log_analytics_fallback' 'incident_facts_from_log_analytics_fallback: Microsoft Graph incident retrieval was unavailable, so Sentinel incident facts were reconstructed from Log Analytics SecurityIncident/SecurityAlert rows with protected identifiers.'
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
    $coverageGaps.Add($gap)
}
if (-not $trustedTransportMissing -and @($securityIncidentRows).Count -eq 0) {
    $coverageGaps.Add((New-RunnerGap 'sentinel-law' 'securityincident_not_matched' 'No SecurityIncident rows matched Sentinel IncidentName or ProviderIncidentId for the requested incident.'))
}
if ([string]$coverageVerification.signals.connector_healthy.status -eq 'verified_false') {
    $gap = New-RunnerGap 'sentinel-law' 'sentinel_connector_unhealthy' 'Sentinel coverage pre-check explicitly observed unhealthy connector or workspace state.'
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'high'
    $coverageGaps.Add($gap)
}
if ([string]$coverageVerification.signals.sentinel_onboarded.status -eq 'verified_false') {
    $gap = New-RunnerGap 'sentinel-law' 'sentinel_not_onboarded' 'Sentinel coverage pre-check explicitly observed non-onboarded or disabled Sentinel state.'
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'high'
    $coverageGaps.Add($gap)
}
$contradictedSignals = @($coverageVerification.signals.PSObject.Properties | Where-Object {
    $signal = $_.Value
    [string]$signal.status -eq 'verified_false' -and
    $null -ne $signal.PSObject.Properties['attested_value'] -and
    [bool]$signal.attested_value
})
if (@($contradictedSignals).Count -gt 0) {
    $names = @($contradictedSignals | ForEach-Object { [string]$_.Name })
    $gap = New-RunnerGap 'sentinel-law' 'sentinel_attestation_contradicted' ("Operator-attested Sentinel coverage was contradicted by read-only verification for signal(s): {0}. Affected Sentinel receipts are downgraded and must not support clean coverage claims." -f ($names -join ', '))
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'high'
    $coverageGaps.Add($gap)
}
$sentinelCoverageContradicted = @($contradictedSignals).Count -gt 0
if ($sentinelCoverageContradicted) {
    $coverageVerification | Add-Member -Force -NotePropertyName arm_dispatch -NotePropertyValue ([pscustomobject][ordered]@{
        status = 'not_skipped'
        reason = 'ARM requests are assembled in the fixed runner retrieval sequence; contradicted Sentinel receipts are downgraded before reporting and must not support clean coverage claims.'
    })
}

$containmentDecisionRecords = @()
$recoveryAuditRecords = @()
$containmentRecoveryReview = if ($null -ne $graphIncident -and $graphIncident.PSObject.Properties.Name -contains 'containmentRecoveryReview') {
    $graphIncident.containmentRecoveryReview
}
else { $null }
if ($null -eq $containmentRecoveryReview) {
    $gap = New-RunnerGap 'containment-recovery' 'containment_recovery_evidence_missing' 'Containment and recovery validation evidence was not present in the read-only source bundle; containmentRecoveryReview is fixture-only because live Graph incident responses never return containmentRecoveryReview, so live runs carry this gap and validators are not treated as passing.'
    $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
    $coverageGaps.Add($gap)
}
else {
    $containmentRecoveryKnownEvidenceIds = @(
        'EVID-runner-seed'
        @($securityIncidentRows | ForEach-Object { Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityIncident', [string]$_.IncidentNumber, [string]$_.TimeGenerated) })
        @($securityAlertRows | ForEach-Object { Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityAlert', [string]$_.SystemAlertId, [string]$_.TimeGenerated) })
        @($pivotEvidenceRecords | ForEach-Object { [string]$_.evidence_id })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique
    $knownRecoveryEvidenceSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in @($containmentRecoveryKnownEvidenceIds)) { [void]$knownRecoveryEvidenceSet.Add([string]$id) }
    $unresolvedRecoveryEvidenceIds = @(Get-RunnerEvidenceIdsFromObject -Value $containmentRecoveryReview | Where-Object {
        -not $knownRecoveryEvidenceSet.Contains([string]$_)
    } | Sort-Object -Unique)
    if ($unresolvedRecoveryEvidenceIds.Count -gt 0) {
        $gap = New-RunnerGap 'containment-recovery' 'containment_recovery_evidence_unresolved' "Containment/recovery review cited evidence outside the runner evidence ledger; unresolved evidence reference count: $($unresolvedRecoveryEvidenceIds.Count). Raw evidence identifiers are withheld."
        $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
        $coverageGaps.Add($gap)
    }
    $crossCheckedContainmentRecoveryReview = $containmentRecoveryReview | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100 -DateKind String
    if ($crossCheckedContainmentRecoveryReview.PSObject.Properties.Name -contains 'evidence_available') {
        $crossCheckedContainmentRecoveryReview.evidence_available = @($crossCheckedContainmentRecoveryReview.evidence_available | Where-Object {
            $_.PSObject.Properties.Name -contains 'evidence_id' -and $knownRecoveryEvidenceSet.Contains([string]$_.evidence_id)
        })
    }
    $containmentDecisionRecords = @(Try-Kernel 'containment-recovery-decision' {
        ConvertTo-ContainmentDecisionAuditRecord -Review $crossCheckedContainmentRecoveryReview
    } $coverageGaps)
    $recoveryAuditRecords = @(Try-Kernel 'containment-recovery' {
        ConvertTo-RecoveryAuditRecord -Review $crossCheckedContainmentRecoveryReview
    } $coverageGaps)
    if (@($containmentDecisionRecords | Where-Object { $null -ne $_ }).Count -eq 0 -or
        @($recoveryAuditRecords | Where-Object { $null -ne $_ }).Count -eq 0) {
        $gap = New-RunnerGap 'containment-recovery' 'containment_recovery_validation_unavailable' 'Containment and recovery evidence was present, but validator records could not be projected from current read-only inputs.'
        $gap | Add-Member -Force -NotePropertyName severity -NotePropertyValue 'medium'
        $coverageGaps.Add($gap)
    }
}

$coverageRecords = [Collections.Generic.List[object]]::new()
$coverageIndex = 0
foreach ($envelope in @($envelopes)) {
    $coverageIndex++
    $coverageRecord = Try-Kernel "coverage-$coverageIndex" {
        ConvertFrom-HavocAdapterEnvelopeToLedgerCoverage -Envelope $envelope -CoverageId "runner-$coverageIndex"
    } $coverageGaps
    if ($null -ne $coverageRecord) {
        if ($envelope.PSObject.Properties.Name -contains 'runnerCoverageSignal') {
            $signal = [string]$envelope.runnerCoverageSignal
            $signalRecord = $coverageVerification.signals.$signal
            $coverageRecord.coverage_receipt | Add-Member -Force -NotePropertyName coverageVerification -NotePropertyValue $signalRecord
            $coverageRecord.query_record.target = "coverage-verification:$signal"
        }
        if ($envelope.PSObject.Properties.Name -contains 'runnerPivotName') {
            $coverageRecord.coverage_receipt | Add-Member -Force -NotePropertyName pivot -NotePropertyValue ([pscustomobject][ordered]@{
                skill = [string]$envelope.runnerPivotSkill
                name = [string]$envelope.runnerPivotName
            })
            $coverageRecord.query_record.target = "pivot:$($envelope.runnerPivotSkill):$($envelope.runnerPivotName)"
        }
        if ($sentinelCoverageContradicted -and
            -not ($envelope.PSObject.Properties.Name -contains 'runnerCoverageSignal') -and
            [string]$coverageRecord.coverage_receipt.source_id -in @('sentinel-law','sentinel-arm')) {
            $coverageRecord.coverage_receipt.coverage_state = 'degraded'
            $coverageRecord.coverage_receipt.completeness = 'partial'
            $coverageRecord.coverage_receipt.health_state = [pscustomobject][ordered]@{ status = 'unknown'; detail = 'operator attestation contradicted by verification' }
            $coverageRecord.coverage_receipt.connector_health = [pscustomobject][ordered]@{ status = 'unknown'; detail = 'operator attestation contradicted by verification' }
            $limitation = 'sentinel_attestation_contradicted: operator attestation contradicted by read-only verification'
            $limitations = [Collections.Generic.List[string]]::new()
            foreach ($item in @($coverageRecord.coverage_receipt.limitations)) { if (-not [string]::IsNullOrWhiteSpace([string]$item)) { $limitations.Add([string]$item) } }
            if (-not $limitations.Contains($limitation)) { $limitations.Add($limitation) }
            $coverageRecord.coverage_receipt.limitations = @($limitations)
        }
    }
    $coverageRecords.Add($coverageRecord)
}

$retrievalTime = (& $Clock).ToUniversalTime()
$evidenceItems = [Collections.Generic.List[object]]::new()
$evidenceItems.Add([pscustomobject][ordered]@{
    record_type = 'evidence_item'
    evidence_id = 'EVID-runner-seed'
    evidence_kind = 'tenant_observation'
    evidence_role = 'core_incident_seed'
    source_type = 'microsoft_graph_security_incident'
    support_direction = 'supporting'
    analytic_assessment = [pscustomobject][ordered]@{
        likelihood = 'likely'
        analytic_confidence = 'moderate'
    }
})
foreach ($row in @($securityIncidentRows)) {
    $evidenceItems.Add([pscustomobject][ordered]@{
        record_type = 'evidence_item'
        evidence_id = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityIncident', [string]$row.IncidentNumber, [string]$row.TimeGenerated)
        evidence_kind = 'tenant_observation'
        evidence_role = 'sentinel_security_incident_row'
        source_type = 'log_analytics_securityincident'
        support_direction = 'supporting'
        analytic_assessment = [pscustomobject][ordered]@{
            likelihood = 'likely'
            analytic_confidence = 'moderate'
        }
    })
}
foreach ($row in @($securityAlertRows)) {
    $evidenceItems.Add([pscustomobject][ordered]@{
        record_type = 'evidence_item'
        evidence_id = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityAlert', [string]$row.SystemAlertId, [string]$row.TimeGenerated)
        evidence_kind = 'tenant_observation'
        evidence_role = 'sentinel_security_alert_row'
        source_type = 'log_analytics_securityalert'
        support_direction = 'supporting'
        analytic_assessment = [pscustomobject][ordered]@{
            likelihood = 'likely'
            analytic_confidence = 'moderate'
        }
    })
}
$knownEvidenceIds = @($evidenceItems | ForEach-Object { [string]$_.evidence_id })
$timeline = Try-Kernel 'timeline' {
    @(
        New-HavocTimelineRecord -InputObject ([pscustomobject][ordered]@{
            timeline_id = 'runner-incident-seed'
            event_ref = 'protected-evidence:runner-incident-seed'
            source_id = 'havoc-runner'
            upstream_record_id = (Get-RunnerStableId -Prefix 'INC' -Parts @('runner-incident-seed', $IncidentId))
            raw_timestamp = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            ingestion_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            retrieval_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            evidence_ids = $knownEvidenceIds
            claim_ids = @('CLAIM-incident-seed')
        })
        foreach ($row in @($securityIncidentRows)) {
            $timeText = ConvertTo-RunnerUtcText (Get-RunnerPropertyText $row 'TimeGenerated' '')
            if ([string]::IsNullOrWhiteSpace($timeText)) { continue }
            New-HavocTimelineRecord -InputObject ([pscustomobject][ordered]@{
                timeline_id = Get-RunnerStableId -Prefix 'TL' -Parts @('SecurityIncident', [string]$row.IncidentNumber, [string]$row.TimeGenerated)
                event_ref = 'protected-evidence:securityincident-row'
                source_id = 'log_analytics_securityincident'
                upstream_record_id = (Get-RunnerStableId -Prefix 'SI' -Parts @('SecurityIncident', [string]$row.IncidentNumber, [string]$row.ProviderIncidentId, [string]$row.TimeGenerated))
                raw_timestamp = $timeText
                ingestion_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                retrieval_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                evidence_ids = $knownEvidenceIds
                claim_ids = @('CLAIM-incident-seed')
            })
        }
        foreach ($row in @($securityAlertRows)) {
            $timeText = ConvertTo-RunnerUtcText (Get-RunnerPropertyText $row 'TimeGenerated' '')
            if ([string]::IsNullOrWhiteSpace($timeText)) { continue }
            New-HavocTimelineRecord -InputObject ([pscustomobject][ordered]@{
                timeline_id = Get-RunnerStableId -Prefix 'TL' -Parts @('SecurityAlert', [string]$row.SystemAlertId, [string]$row.TimeGenerated)
                event_ref = 'protected-evidence:securityalert-row'
                source_id = 'log_analytics_securityalert'
                upstream_record_id = (Get-RunnerStableId -Prefix 'SA' -Parts @('SecurityAlert', [string]$row.SystemAlertId, [string]$row.TimeGenerated))
                raw_timestamp = $timeText
                ingestion_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                retrieval_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                evidence_ids = $knownEvidenceIds
                claim_ids = @('CLAIM-incident-seed')
            })
        }
    )
} $coverageGaps

$evidenceAssessment = Try-Kernel 'evidence' {
    Get-EvidenceLikelihoodAssessment -EvidenceItem @($evidenceItems)
} $coverageGaps

$entitySeedRecords = @(ConvertFrom-RunnerSecurityAlertEntitySeeds -Rows $securityAlertRows)
$protectedIncidentEntityRef = "protected-context:incident-$((Get-RunnerStableId -Prefix 'inc' -Parts @('entity-incident', $IncidentId)))"
$protectedIncidentRecurrenceRef = "protected:incident-$((Get-RunnerStableId -Prefix 'inc' -Parts @('recurrence-incident', $IncidentId)))"
$entities = Try-Kernel 'entity' {
    @(
        New-HavocEntityResolution -ResolutionId 'RES-runner-incident-seed' `
            -Decision 'distinct' -Confidence 'not_assessed' `
            -SourceEntityIds @($protectedIncidentEntityRef) `
            -ResultEntityId $protectedIncidentEntityRef `
            -EvidenceIds $knownEvidenceIds -GapIds @($coverageGaps | ForEach-Object { $_.gap_id })
        foreach ($seed in @($entitySeedRecords)) {
            New-HavocEntityResolution -ResolutionId ("RES-{0}" -f [string]$seed.entity_id) `
                -Decision 'distinct' -Confidence 'not_assessed' `
                -SourceEntityIds @([string]$seed.entity_id) `
                -ResultEntityId ([string]$seed.entity_id) `
                -EvidenceIds @($seed.evidence_ids) -GapIds @($coverageGaps | ForEach-Object { $_.gap_id })
        }
    )
} $coverageGaps

$incidentFactSource = if ($logAnalyticsIncidentFallbackActive) { 'securityincident_log_analytics_table' } else { 'microsoft_graph_security_incident' }
$incidentFactOwner = if ($logAnalyticsIncidentFallbackActive) { 'protected:provider/sentinel-law' } else { 'protected:provider/graph-security' }
$graphIncidentTitle = if ($null -ne $effectiveIncident -and $effectiveIncident.PSObject.Properties.Name -contains 'displayName') { [string]$effectiveIncident.displayName } else { 'protected-title' }
$graphIncidentSeverity = if ($null -ne $effectiveIncident -and $effectiveIncident.PSObject.Properties.Name -contains 'severity') { [string]$effectiveIncident.severity } else { 'unknown' }
$graphIncidentStatus = if ($null -ne $effectiveIncident -and $effectiveIncident.PSObject.Properties.Name -contains 'status') { [string]$effectiveIncident.status } else { 'unknown' }
$graphIncidentClassification = if ($null -ne $effectiveIncident -and $effectiveIncident.PSObject.Properties.Name -contains 'classification') { [string]$effectiveIncident.classification } else { 'unknown' }
$graphIncidentDetermination = if ($null -ne $effectiveIncident -and $effectiveIncident.PSObject.Properties.Name -contains 'determination') { [string]$effectiveIncident.determination } else { 'unknown' }
$sentinelClassificationReason = if ($logAnalyticsIncidentFallbackActive -and $null -ne $effectiveIncident -and $effectiveIncident.PSObject.Properties.Name -contains 'classificationReason') { [string]$effectiveIncident.classificationReason } else { $null }
$taxonomyHistoryRows = @($securityIncidentRows | Sort-Object {
    $parsed = Get-RunnerDateTimeOffsetOrNull (Get-RunnerPropertyText $_ 'TimeGenerated' '')
    if ($null -ne $parsed) { $parsed } else { [datetimeoffset]::MinValue }
})
$taxonomySeverityHistory = @($taxonomyHistoryRows | Where-Object {
    $_.PSObject.Properties.Name -contains 'Severity' -and -not [string]::IsNullOrWhiteSpace([string]$_.Severity)
} | ForEach-Object {
    $evidenceId = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityIncident', [string]$_.IncidentNumber, [string]$_.TimeGenerated)
    $timeText = ConvertTo-RunnerUtcText (Get-RunnerPropertyText $_ 'TimeGenerated' '')
    if ([string]::IsNullOrWhiteSpace($timeText)) { return }
    $actorSource = Get-RunnerModifiedByAttribution $_
    [pscustomobject][ordered]@{
        observed_at = $timeText
        severity = [string]$_.Severity
        actor = [string]$actorSource.actor
        source = [string]$actorSource.source
        evidence_ids = @($evidenceId)
    }
})
$taxonomyClassificationHistory = @($taxonomyHistoryRows | Where-Object {
    $_.PSObject.Properties.Name -contains 'Classification' -and -not [string]::IsNullOrWhiteSpace([string]$_.Classification)
} | ForEach-Object {
    $evidenceId = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityIncident', [string]$_.IncidentNumber, [string]$_.TimeGenerated)
    $timeText = ConvertTo-RunnerUtcText (Get-RunnerPropertyText $_ 'TimeGenerated' '')
    if ([string]::IsNullOrWhiteSpace($timeText)) { return }
    $actorSource = Get-RunnerModifiedByAttribution $_
    [pscustomobject][ordered]@{
        observed_at = $timeText
        classification = [string]$_.Classification
        actor = [string]$actorSource.actor
        source = [string]$actorSource.source
        evidence_ids = @($evidenceId)
    }
})
$taxonomyStatusHistory = @($taxonomyHistoryRows | Where-Object {
    $_.PSObject.Properties.Name -contains 'Status' -and -not [string]::IsNullOrWhiteSpace([string]$_.Status)
} | ForEach-Object {
    $evidenceId = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityIncident', [string]$_.IncidentNumber, [string]$_.TimeGenerated)
    $timeText = ConvertTo-RunnerUtcText (Get-RunnerPropertyText $_ 'TimeGenerated' '')
    if ([string]::IsNullOrWhiteSpace($timeText)) { return }
    $actorSource = Get-RunnerModifiedByAttribution $_
    [pscustomobject][ordered]@{
        observed_at = $timeText
        status = [string]$_.Status
        actor = [string]$actorSource.actor
        source = [string]$actorSource.source
        evidence_ids = @($evidenceId)
    }
})

$taxonomy = Try-Kernel 'taxonomy' {
    @(
        New-HavocTaxonomyAuditRecord -TaxonomyVersion '1.0.0' `
            -Source $incidentFactSource -Field 'classification' -Value $graphIncidentClassification `
            -ProductFields ([pscustomobject][ordered]@{
                severity = $graphIncidentSeverity
                status = $graphIncidentStatus
                title = $graphIncidentTitle
                classification = $graphIncidentClassification
                determination = $graphIncidentDetermination
                classification_reason = $sentinelClassificationReason
                owner = $incidentFactOwner
            }) `
            -SeverityHistory $taxonomySeverityHistory `
            -ClassificationHistory $taxonomyClassificationHistory `
            -StatusHistory $taxonomyStatusHistory `
            -CoverageGapIds @($coverageGaps | ForEach-Object { $_.gap_id }) `
            -ClaimIds @('CLAIM-taxonomy-verdict') -EvidenceIds $knownEvidenceIds `
            -BehaviorBases @('configurable_project_policy') -AsOf $retrievalTime `
            -KnownEvidenceIds $knownEvidenceIds
    )
} $coverageGaps

$decisionSnapshot = Try-Kernel 'decision' {
    New-DecisionSnapshot -Decision ([pscustomobject][ordered]@{
        decision_id = 'DEC-runner-readonly-reconstruction'
        decision_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        decision_type = 'readonly_reconstruction'
        actor_type = 'soc'
        alert_payload_version_available = if ($logAnalyticsIncidentFallbackActive) { 'log_analytics_securityalert' } else { 'graph_security_alert_v1' }
        queue_state = [pscustomobject][ordered]@{
            queue_depth = @($securityAlertRows).Count
            oldest_alert_age_minutes = 0
            active_analysts = 0
            source_evidence_ids = $knownEvidenceIds
        }
        telemetry = @($securityAlertRows | ForEach-Object {
            $timeText = ConvertTo-RunnerUtcText (Get-RunnerPropertyText $_ 'TimeGenerated' '')
            if ([string]::IsNullOrWhiteSpace($timeText)) { return }
            [pscustomobject][ordered]@{
                evidence_id = Get-RunnerStableId -Prefix 'EVID' -Parts @('SecurityAlert', [string]$_.SystemAlertId, [string]$_.TimeGenerated)
                source_id = 'log_analytics_securityalert'
                telemetry_type = 'security_alert'
                event_time = $timeText
                availability_time = $retrievalTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                availability_kind = 'available_at_reconstruction'
                summary = 'Protected SecurityAlert summary from Log Analytics.'
                protected_summary_ref = 'protected-evidence:securityalert-summary'
            }
        })
        automation_results = @()
        notes_comments = @()
        cognitive_bias_flags = @()
        timeliness_metrics = @()
        process_defects = @()
        playbook_version = 'not-assessed'
        findings = @([pscustomobject][ordered]@{
            finding_id = 'FIND-runner-core-sources'
            summary = 'Core read-only incident and alert records were available for reconstruction.'
            cited_evidence_ids = @($knownEvidenceIds | Select-Object -First 1)
        })
        assessment = [pscustomobject][ordered]@{
            soc_assessment_label = 'partial_readonly_reconstruction'
            reasonable_analyst_rationale = 'Assessment is limited to read-only source material retrieved by approved adapters.'
            cited_evidence_ids = @($knownEvidenceIds | Select-Object -First 1)
        }
        individual_fault = [pscustomobject][ordered]@{
            asserted = $false
            available_information_evidence_ids = @()
            required_action_documented_evidence_ids = @()
            rationale = 'Individual fault is not assessed by the read-only runner.'
        }
        claim_ids = @('CLAIM-incident-seed')
        gap_ids = @($coverageGaps | ForEach-Object { $_.gap_id })
        error_ids = @()
        behavior_bases = @('configurable_project_policy')
    })
} $coverageGaps

$recurrence = Try-Kernel 'recurrence' {
    Invoke-RecurrenceAnalysis -InputObject ([pscustomobject][ordered]@{
        current_incident = [pscustomobject][ordered]@{
            incident_ref = $protectedIncidentRecurrenceRef
            workspace_ref = "protected:workspace-$WorkspaceId"
            product = 'Microsoft Defender XDR'
        }
        related_incident = [pscustomobject][ordered]@{
            incident_ref = 'protected:related-incident-not-observed'
            workspace_ref = "protected:workspace-$WorkspaceId"
            product = 'Microsoft Defender XDR'
        }
        relation_type = 'candidate_recurrence'
        case_id = "runner-$IncidentId"
        prior_disposition = [pscustomobject][ordered]@{
            classification = 'unknown'
            determination = 'unknown'
            closure_quality = 'not_assessed'
            protected_decision_ref = 'protected:prior-decision-not-observed'
        }
        overlap_observations = @([pscustomobject][ordered]@{
            basis = 'detection_rule'
            identifier_strength = 'weak'
            identifier_ref = 'protected:analytics-rule-candidate'
            temporal_plausibility = 'unknown'
            shared_infrastructure_context = 'none'
            summary = 'Only the generating rule candidate is available in the core runner scope.'
        })
        claim_ids = @('CLAIM-incident-seed')
        evidence_ids = @($knownEvidenceIds | Select-Object -First 1)
        gap_ids = @($coverageGaps | ForEach-Object { $_.gap_id })
        error_ids = @()
        evidence_ledger = @($evidenceItems)
    })
} $coverageGaps

$saturationState = Try-Kernel 'saturation-state' {
    New-HavocSaturationState -BranchId 'runner-core-incident-sources' -Threshold 3 -PolicyVersion '1.0.0'
} $coverageGaps
$saturationStopReceipt = Try-Kernel 'saturation-stop-receipt' {
    New-HavocStopReceipt -BranchId 'runner-core-incident-sources' -StopReason 'coverage_boundary' `
        -MissingSource 'domain-micro-skill-pivots' `
        -AffectedClaimIds @('CLAIM-domain-frontier') `
        -FollowUp 'Route domain micro-skill pivots after the core live read-only pilot review gates.' `
        -Now $retrievalTime
} $coverageGaps

$bundle = [pscustomobject][ordered]@{
    bundleType = 'havoc-incident-audit-bundle'
    schemaVersion = '1.0.0'
    generatedAt = $retrievalTime.ToString('o')
    incident = [pscustomobject][ordered]@{
        id = $IncidentId
        tenant_ref = "protected-context:tenant-$TenantId"
        workspace_ref = "protected-context:workspace-$WorkspaceId"
        sentinel_incident_ref = if ($SentinelIncidentId) { "protected-context:sentinel-incident-$SentinelIncidentId" } else { 'not-applicable:none' }
    }
    sources = [pscustomobject][ordered]@{
        graphIncidentWithAlerts = $graphIntent.operationId
        logSecurityIncident = $logIncidentIntent.operationId
        logSecurityAlert = $logAlertIntent.operationId
        sentinelIncident = if ($SentinelIncidentId) { 'sentinel-incident-get' } else { 'not-requested' }
        analyticsRule = if ($AnalyticsRuleId) { 'sentinel-analytics-rule-get' } else { 'not-requested' }
    }
    adapterEnvelopes = @($envelopes)
    runnerIntents = @($runnerIntentRecords)
    evidence = [pscustomobject][ordered]@{
        likelihoodAssessment = $evidenceAssessment
        pivotEvidence = @($pivotEvidenceRecords)
    }
    entitySeeds = @($entitySeedRecords)
    entities = @($entities)
    timeline = @($timeline)
    taxonomy = @($taxonomy)
    decisionSnapshot = $decisionSnapshot
    decisions = [pscustomobject][ordered]@{
        containmentRecords = @($containmentDecisionRecords | Where-Object { $null -ne $_ })
    }
    recovery = [pscustomobject][ordered]@{
        records = @($recoveryAuditRecords | Where-Object { $null -ne $_ })
    }
    recurrence = $recurrence
    saturation = [pscustomobject][ordered]@{
        state = $saturationState
        stopReceipt = $saturationStopReceipt
    }
    coverage = [pscustomobject][ordered]@{
        receipts = @($coverageRecords | Where-Object { $null -ne $_ } | ForEach-Object { $_.coverage_receipt })
        queryLedger = @($coverageRecords | Where-Object { $null -ne $_ } | ForEach-Object { $_.query_record })
    }
    coverageVerification = $coverageVerification
    coverageGaps = @($coverageGaps)
    pivots = [pscustomobject][ordered]@{
        executePivots = [bool]$ExecutePivots
        maxPivotQueries = $MaxPivotQueries
        executed = @($pivotExecutionRecords)
        frontier = @($pivotFrontierRecords)
    }
    frontier = [pscustomobject][ordered]@{
        microSkillPivots = @(
            'incident-audit-endpoint',
            'incident-audit-identity',
            'incident-audit-email',
            'incident-audit-network',
            'incident-audit-azure-control-plane',
            'incident-audit-persistence-lateral',
            'incident-audit-recurrence',
            'incident-audit-recovery',
            'incident-audit-oauth-apps',
            'incident-audit-m365-data',
            'incident-audit-threat-intel',
            'incident-audit-windows-forensics',
            'incident-audit-ad-hybrid',
            'incident-audit-exploitation',
            'incident-audit-linux-containers',
            'incident-audit-ransomware',
            'incident-audit-saas-mdca',
            'incident-audit-insider-risk'
        )
        status = if ($ExecutePivots) { if (@($pivotExecutionRecords).Count -gt 0) { 'partially_executed' } else { 'attempted_no_execution' } } else { 'listed_not_executed' }
        reason = if ($ExecutePivots) { 'Domain micro-skill pivots were attempted through bounded read-only Log Analytics queries; unexecuted pivots remain frontier.' } else { 'Core runner pilot is limited to incident, alert, Sentinel, analytics rule, and coverage assembly.' }
    }
    report = [pscustomobject][ordered]@{
        status = 'unavailable'
        reason = 'Report.Kernel.psm1 exporting New-HavocAuditReport was not present.'
    }
}

$detectionKernel = Join-Path $kernelPath 'Detection.Kernel.psm1'
if (Test-Path -LiteralPath $detectionKernel) {
    Import-Module $detectionKernel -Force
    $detectionCommand = Get-Command New-HavocDetectionQualityAudit -ErrorAction SilentlyContinue
    if ($null -ne $detectionCommand) {
        try {
            $bundle | Add-Member -Force -NotePropertyName detectionQuality -NotePropertyValue (& $detectionCommand `
                -Incident $effectiveIncident -Alerts $detectionAlerts -Rule $analyticsRule `
                -HealthRecords $healthRecords -AuditRecords $auditRecords)
        }
        catch {
            $coverageGaps.Add((New-RunnerGap 'detection-quality' 'detection_quality_unavailable' 'Detection quality kernel was present but did not assemble from current inputs.'))
        }
    }
}
$bundle.coverageGaps = @($coverageGaps)

$reportKernel = Join-Path $kernelPath 'Report.Kernel.psm1'
if (Test-Path -LiteralPath $reportKernel) {
    Import-Module $reportKernel -Force
    $reportCommand = Get-Command New-HavocAuditReport -ErrorAction SilentlyContinue
    if ($null -ne $reportCommand) {
        try {
            $reportBundle = New-RunnerReportBundle -Bundle $bundle -IncidentObject $effectiveIncident `
                -CoverageGaps @($coverageGaps) -GeneratedAt $retrievalTime
            $reportBundle | ConvertTo-Json -Depth 100 |
                Set-Content -LiteralPath (Join-Path $OutputDirectory 'report-bundle.json') -Encoding utf8
            $report = & $reportCommand -Bundle $reportBundle
            $bundle.report = [pscustomobject][ordered]@{
                status = 'assembled'
                reason = 'Report kernel assembled a partial read-only report from available sources and coverage gaps.'
                outputJson = 'report.json'
                outputMarkdown = 'report.md'
                mappedBundle = 'report-bundle.json'
            }
            Set-Content -LiteralPath (Join-Path $OutputDirectory 'report.json') `
                -Value ([string]$report.Json) -Encoding utf8
            Set-Content -LiteralPath (Join-Path $OutputDirectory 'report.md') `
                -Value ([string]$report.Markdown) -Encoding utf8
        }
        catch {
            $reportFailureMessage = "Report kernel was present but did not assemble from current inputs: $($_.Exception.Message)"
            $coverageGaps.Add((New-RunnerGap 'report' 'report_assembly_failed' $reportFailureMessage))
            $bundle.coverageGaps = @($coverageGaps)
            $bundle.report = [pscustomobject][ordered]@{
                status = 'failed'
                reason = $reportFailureMessage
            }
        }
    }
}
$bundle.coverageGaps = @($coverageGaps)

$bundle | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'bundle.json') -Encoding utf8
$bundle
