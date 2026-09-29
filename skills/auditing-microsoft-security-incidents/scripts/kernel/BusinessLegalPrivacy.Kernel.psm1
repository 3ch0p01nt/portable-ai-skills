Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:RequiredInsiderAlternatives = @(
    'malicious_intent',
    'compromised_account',
    'negligence',
    'policy_violation',
    'authorized_activity'
)

$script:ConclusionKeyTokens = @('breach', 'notif', 'reportab', 'material')
$script:ConclusionKeyQualifiers = @('required', 'requires', 'confirmed', 'needed', 'mandatory', 'determination', 'determined', 'assessment', 'necessary', 'obligat', 'must', 'due')
$script:StandaloneConclusionKeys = @('breach', 'material', 'materiality', 'notif', 'notification', 'notifiable', 'reportable')

$script:DeferralSpanPatterns = @(
    '(?i)\bcounsel\s+(?:will|to|should)\s+(?:decide|determine|assess)\s+whether\s+notification\s+is\s+required\b',
    '(?i)\bfor\s+counsel\s+to\s+determine\b'
)
$script:ForbiddenValuePattern = '(?i)\b(autonomous materiality|materiality determination|material breach|is material|notification obligation|notification\b.*\b(?:mandatory|required)|notifications?\s+(?:must|shall|should|needs?\s+to|has\s+to)\s+(?:occur|be\s+made|be\s+sent|be\s+filed)|(?:obligated|required|obliged|needs?|needed)\s+to\s+notify|must notify|must be notified|constitutes\s+a\s+(?:personal\s+data\s+)?breach|qualifies\s+as\s+a\s+(?:reportable\s+)?breach|triggers\s+(?:a\s+)?notification|reportable breach|breach notification|breach determination|legal conclusion|safety determination|liability determination|disciplinary determination|intent determination|notifiable)\b'
$script:InlineEvidenceFieldPattern = '(?i)(raw_evidence|protected_evidence_inline|evidence_body|evidence_content|content_blob|source_identity_value|subject_identity_value|raw_identity)'

$script:BusinessFactProjectionFields = @(
    'business_fact_id',
    'fact',
    'determination_boundary',
    'critical_service',
    'dependencies',
    'observed_confidentiality_effect',
    'observed_integrity_effect',
    'observed_availability_effect',
    'recoverability',
    'affected_parties',
    'affected_data_categories',
    'protected_evidence_refs',
    'chain_of_custody_notes',
    'claim_ids',
    'evidence_ids',
    'gap_ids',
    'error_ids',
    'behavior_bases'
)

$script:LegalFactProjectionFields = @(
    'legal_fact_id',
    'fact',
    'human_route',
    'determination_boundary',
    'data_categories_potentially_accessed',
    'jurisdictions_indicated_by_evidence',
    'timeline_anchors',
    'chain_of_custody_notes',
    'protected_evidence_refs',
    'claim_ids',
    'evidence_ids',
    'gap_ids',
    'error_ids',
    'behavior_bases'
)

$script:PrivacyProjectionFields = @(
    'privacy_id',
    'purpose',
    'minimization',
    'pseudonymization_state',
    'protected_store_use',
    'export_state',
    'role_based_visibility',
    'export_restrictions',
    'identity_revealing_boundaries',
    'insider_risk',
    'insider_alternatives_considered',
    'protected_evidence_refs',
    'claim_ids',
    'evidence_ids',
    'gap_ids',
    'error_ids',
    'behavior_bases'
)

$script:ChainOfCustodyProjectionFields = @('actor_ref', 'preserved_at', 'action', 'evidence_ref', 'hash')
$script:HashProjectionFields = @('algorithm', 'value')
$script:TimelineAnchorProjectionFields = @('timeline_ref', 'event_time', 'retrieval_time')
$script:InsiderRiskProjectionFields = @(
    'is_insider_risk_context',
    'identity_reveal_authorized',
    'identity_reveal_state',
    'subject_pseudonym_ref',
    'subject_identity_ref',
    'authorization_record_ref'
)
$script:ArrayProjectionFields = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
@(
    'dependencies',
    'affected_parties',
    'affected_data_categories',
    'protected_evidence_refs',
    'chain_of_custody_notes',
    'claim_ids',
    'evidence_ids',
    'gap_ids',
    'error_ids',
    'behavior_bases',
    'data_categories_potentially_accessed',
    'jurisdictions_indicated_by_evidence',
    'timeline_anchors',
    'role_based_visibility',
    'export_restrictions',
    'identity_revealing_boundaries',
    'insider_alternatives_considered'
) | ForEach-Object { [void]$script:ArrayProjectionFields.Add($_) }

function Get-ObjectProperties {
    param([Parameter(Mandatory)][object]$InputObject)
    if ($null -eq $InputObject) { return @() }
    return @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -in @('NoteProperty', 'Property') })
}

function Add-ValidationError {
    param(
        [System.Collections.Generic.List[string]]$Errors,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Errors.Contains($Message)) {
        [void]$Errors.Add($Message)
    }
}

function Get-NormalizedBoundaryKey {
    param([Parameter(Mandatory)][string]$Name)
    return ($Name.ToLowerInvariant() -replace '[-_]', '')
}

function Test-ForbiddenBoundaryFieldName {
    param([Parameter(Mandatory)][string]$Name)
    $normalized = Get-NormalizedBoundaryKey -Name $Name
    if ($normalized -eq 'legalconclusion' -or $normalized -eq 'safetydetermination' -or
        $normalized -eq 'liabilitydetermination' -or $normalized -eq 'disciplinarydetermination' -or
        $normalized -eq 'intentdetermination' -or $normalized -eq 'notificationobligation') {
        return $true
    }
    $collapsed = ($Name.ToLowerInvariant() -replace '[^a-z0-9]', '')
    if ($collapsed -in $script:StandaloneConclusionKeys) { return $true }
    $presentTokens = @($script:ConclusionKeyTokens | Where-Object { $collapsed.Contains($_) })
    if ($presentTokens.Count -eq 0) { return $false }
    foreach ($qualifier in $script:ConclusionKeyQualifiers) {
        if ($collapsed.Contains($qualifier)) { return $true }
    }
    foreach ($token in $script:ConclusionKeyTokens) {
        if ($collapsed.StartsWith("is$token", [System.StringComparison]::Ordinal)) { return $true }
    }
    if ($presentTokens.Count -gt 1) { return $true }
    return $false
}

function Test-ForbiddenBoundaryValue {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $normalized = ($Text -replace '\s+', ' ').Trim()
    $conclusionRegex = [regex]::new($script:ForbiddenValuePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [timespan]::FromSeconds(1))
    $conclusionMatches = @($conclusionRegex.Matches($normalized))
    if ($conclusionMatches.Count -eq 0) { return $false }

    $deferralRanges = [System.Collections.Generic.List[object]]::new()
    foreach ($pattern in $script:DeferralSpanPatterns) {
        $deferralRegex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [timespan]::FromSeconds(1))
        foreach ($match in $deferralRegex.Matches($normalized)) {
            $deferralRanges.Add([pscustomobject]@{
                Start = $match.Index
                End = $match.Index + $match.Length
            })
        }
    }

    foreach ($match in $conclusionMatches) {
        $matchStart = $match.Index
        $matchEnd = $match.Index + $match.Length
        $insideDeferral = $false
        foreach ($range in $deferralRanges) {
            if ($matchStart -ge $range.Start -and $matchEnd -le $range.End) {
                $insideDeferral = $true
                break
            }
        }
        if (-not $insideDeferral) { return $true }
    }
    return $false
}

function Test-HavocRecordHasProperty {
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Record) { return $false }
    if ($Record -is [System.Collections.IDictionary]) { return $Record.Contains($Name) }
    return ($null -ne $Record.PSObject.Properties[$Name])
}

function Get-HavocRecordProperty {
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory)][string]$Name
    )
    return Get-HavocProperty -InputObject $Record -Name $Name
}

function Select-HavocAllowlistedProperties {
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory)][string[]]$Fields
    )

    if ($null -eq $Record) { return $null }
    $projected = [ordered]@{}
    foreach ($field in $Fields) {
        $hasField = $false
        $rawValue = $null
        if ($Record -is [System.Collections.IDictionary]) {
            if ($Record.Contains($field)) {
                $hasField = $true
                $rawValue = $Record[$field]
            }
        }
        else {
            $property = $Record.PSObject.Properties[$field]
            if ($null -ne $property) {
                $hasField = $true
                $rawValue = $property.Value
            }
        }
        if ($hasField) {
            if ($script:ArrayProjectionFields.Contains($field)) {
                $projected[$field] = @(ConvertTo-HavocArrayProjectionValue -FieldName $field -Value $rawValue)
            }
            else {
                $projected[$field] = ConvertTo-HavocProjectionValue -FieldName $field -Value $rawValue
            }
        }
    }
    return [pscustomobject]$projected
}

function ConvertTo-HavocArrayProjectionValue {
    param(
        [Parameter(Mandatory)][string]$FieldName,
        [AllowNull()][object]$Value
    )

    switch ($FieldName) {
        'chain_of_custody_notes' {
            return @(Get-HavocArray -Value $Value | ForEach-Object {
                Select-HavocAllowlistedProperties -Record $_ -Fields $script:ChainOfCustodyProjectionFields
            })
        }
        'timeline_anchors' {
            return @(Get-HavocArray -Value $Value | ForEach-Object {
                Select-HavocAllowlistedProperties -Record $_ -Fields $script:TimelineAnchorProjectionFields
            })
        }
        default {
            return @(Get-HavocArray -Value $Value)
        }
    }
}

function ConvertTo-HavocProjectionValue {
    param(
        [Parameter(Mandatory)][string]$FieldName,
        [AllowNull()][object]$Value
    )

    switch ($FieldName) {
        'hash' {
            return Select-HavocAllowlistedProperties -Record $Value -Fields $script:HashProjectionFields
        }
        'insider_risk' {
            return Select-HavocAllowlistedProperties -Record $Value -Fields $script:InsiderRiskProjectionFields
        }
        default {
            return $Value
        }
    }
}

function Test-RecursiveBoundary {
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Value,
        [System.Collections.Generic.List[string]]$Errors,
        [string]$Path = '$'
    )

    if ($null -eq $Value) { return }

    if ($Value -is [string]) {
        if (Test-ForbiddenBoundaryValue -Text $Value) {
            Add-ValidationError -Errors $Errors -Message "autonomous determination or legal conclusion value is prohibited at $Path"
        }
        return
    }

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $name = [string]$key
            if (Test-ForbiddenBoundaryFieldName -Name $name) {
                Add-ValidationError -Errors $Errors -Message "autonomous determination field is prohibited at $Path.$name"
            }
            if ($name -match $script:InlineEvidenceFieldPattern) {
                Add-ValidationError -Errors $Errors -Message "protected evidence or identity must be referenced, not inlined at $Path.$name"
            }
            Test-RecursiveBoundary -Value $Value[$key] -Errors $Errors -Path "$Path.$name"
        }
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $index = 0
        foreach ($item in $Value) {
            Test-RecursiveBoundary -Value $item -Errors $Errors -Path "$Path[$index]"
            $index++
        }
        return
    }

    if ($Value -isnot [pscustomobject]) {
        return
    }

    foreach ($property in Get-ObjectProperties -InputObject $Value) {
        $name = $property.Name
        if (Test-ForbiddenBoundaryFieldName -Name $name) {
            Add-ValidationError -Errors $Errors -Message "autonomous determination field is prohibited at $Path.$name"
        }
        if ($name -match $script:InlineEvidenceFieldPattern) {
            Add-ValidationError -Errors $Errors -Message "protected evidence or identity must be referenced, not inlined at $Path.$name"
        }
        Test-RecursiveBoundary -Value $property.Value -Errors $Errors -Path "$Path.$name"
    }
}

function Test-ProtectedReferenceArray {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$PropertyName,
        [System.Collections.Generic.List[string]]$Errors,
        [Parameter(Mandatory)][string]$RecordPath
    )

    if (-not (Test-HavocRecordHasProperty -Record $Record -Name $PropertyName)) {
        Add-ValidationError -Errors $Errors -Message "$RecordPath.$PropertyName is required"
        return
    }

    $values = @(Get-HavocArray -Value (Get-HavocRecordProperty -Record $Record -Name $PropertyName))
    if ($values.Count -eq 0) {
        Add-ValidationError -Errors $Errors -Message "$RecordPath.$PropertyName must contain protected references"
        return
    }

    foreach ($value in $values) {
        if (-not (Test-HavocProtectedReference -Value $value)) {
            Add-ValidationError -Errors $Errors -Message "$RecordPath.$PropertyName contains a non-protected reference"
        }
    }
}

function Test-ChainOfCustodyNotes {
    param(
        [Parameter(Mandatory)][object]$Record,
        [System.Collections.Generic.List[string]]$Errors,
        [Parameter(Mandatory)][string]$RecordPath
    )

    $notesValue = Get-HavocRecordProperty -Record $Record -Name 'chain_of_custody_notes'
    if (-not (Test-HavocRecordHasProperty -Record $Record -Name 'chain_of_custody_notes') -or @(Get-HavocArray -Value $notesValue).Count -eq 0) {
        Add-ValidationError -Errors $Errors -Message "$RecordPath.chain_of_custody_notes must record who, when, what evidence reference, and synthetic hash"
        return
    }

    $index = 0
    foreach ($note in @(Get-HavocArray -Value $notesValue)) {
        foreach ($required in @('actor_ref', 'preserved_at', 'action', 'evidence_ref', 'hash')) {
            if (-not (Test-HavocRecordHasProperty -Record $note -Name $required)) {
                Add-ValidationError -Errors $Errors -Message "$RecordPath.chain_of_custody_notes[$index].$required is required"
            }
        }
        $noteEvidenceRef = Get-HavocRecordProperty -Record $note -Name 'evidence_ref'
        if ((Test-HavocRecordHasProperty -Record $note -Name 'evidence_ref') -and -not (Test-HavocProtectedReference -Value $noteEvidenceRef)) {
            Add-ValidationError -Errors $Errors -Message "$RecordPath.chain_of_custody_notes[$index].evidence_ref must be a protected reference"
        }
        $noteHash = Get-HavocRecordProperty -Record $note -Name 'hash'
        if (Test-HavocRecordHasProperty -Record $note -Name 'hash') {
            $algorithm = Get-HavocRecordProperty -Record $noteHash -Name 'algorithm'
            $hashValue = Get-HavocRecordProperty -Record $noteHash -Name 'value'
            if (-not (Test-HavocRecordHasProperty -Record $noteHash -Name 'algorithm') -or $algorithm -notin @('synthetic-sha256', 'synthetic-hmac-sha256')) {
                Add-ValidationError -Errors $Errors -Message "$RecordPath.chain_of_custody_notes[$index].hash.algorithm must be synthetic"
            }
            if (-not (Test-HavocRecordHasProperty -Record $noteHash -Name 'value') -or $hashValue -notmatch '^synthetic:[a-f0-9]{64}$') {
                Add-ValidationError -Errors $Errors -Message "$RecordPath.chain_of_custody_notes[$index].hash.value must be a synthetic hash"
            }
        }
        $index++
    }
}

function Test-InsiderRiskRecord {
    param(
        [Parameter(Mandatory)][object]$Record,
        [System.Collections.Generic.List[string]]$Errors,
        [Parameter(Mandatory)][string]$RecordPath
    )

    $alternatives = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $Record -Name 'insider_alternatives_considered'))
    foreach ($required in $script:RequiredInsiderAlternatives) {
        if ($required -notin $alternatives) {
            Add-ValidationError -Errors $Errors -Message "$RecordPath.insider alternatives must separately consider malicious intent, compromised account, negligence, policy violation, and authorized activity"
            break
        }
    }

    if (Test-HavocRecordHasProperty -Record $Record -Name 'insider_risk') {
        $insider = Get-HavocRecordProperty -Record $Record -Name 'insider_risk'
        $identityRevealState = Get-HavocRecordProperty -Record $insider -Name 'identity_reveal_state'
        $identityRevealAuthorized = Get-HavocRecordProperty -Record $insider -Name 'identity_reveal_authorized'
        $subjectIdentityRef = Get-HavocRecordProperty -Record $insider -Name 'subject_identity_ref'
        $revealed = ((Test-HavocRecordHasProperty -Record $insider -Name 'identity_reveal_state') -and $identityRevealState -eq 'identity_revealed')
        $authorized = ((Test-HavocRecordHasProperty -Record $insider -Name 'identity_reveal_authorized') -and [bool]$identityRevealAuthorized)
        if ($revealed -and -not $authorized) {
            Add-ValidationError -Errors $Errors -Message "$RecordPath identity reveal is prohibited without classification authority"
        }
        if ($revealed -and (-not (Test-HavocRecordHasProperty -Record $insider -Name 'subject_identity_ref') -or -not (Test-HavocProtectedReference -Value $subjectIdentityRef))) {
            Add-ValidationError -Errors $Errors -Message "$RecordPath identity reveal must use a protected identity reference"
        }
        if (Test-HavocRecordHasProperty -Record $insider -Name 'subject_identity_value') {
            Add-ValidationError -Errors $Errors -Message "$RecordPath identity reveal must not inline identity values"
        }
    }
}

function Test-HavocBusinessLegalPrivacyPacket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][ValidateSet('BusinessLegal', 'PrivacyAccess')][string]$PacketKind
    )

    process {
        $errors = [System.Collections.Generic.List[string]]::new()
        if ($null -eq $InputObject) {
            Add-ValidationError -Errors $errors -Message 'packet is required'
            return [pscustomobject]@{
                IsValid = $false
                Errors = @($errors)
            }
        }

        Test-RecursiveBoundary -Value $InputObject -Errors $errors

        if ($PacketKind -eq 'BusinessLegal') {
            $businessRecords = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'business_fact_records'))
            $legalRecords = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'legal_fact_records'))
            $packetState = Get-HavocProperty -InputObject $InputObject -Name 'packet_state'
            $validForReporting = Get-HavocProperty -InputObject $InputObject -Name 'valid_for_reporting'

            if (($businessRecords.Count + $legalRecords.Count) -eq 0) {
                if ($packetState -ne 'no_facts_provided') {
                    Add-ValidationError -Errors $errors -Message 'no_facts_provided state is required when no business or legal facts are present'
                }
                Add-ValidationError -Errors $errors -Message 'no_facts_provided packets are not valid for reporting'
                if ($validForReporting -ne $false) {
                    Add-ValidationError -Errors $errors -Message 'no_facts_provided packets must set valid_for_reporting to false'
                }
            }

            foreach ($record in $businessRecords) {
                Test-ProtectedReferenceArray -Record $record -PropertyName 'protected_evidence_refs' -Errors $errors -RecordPath '$.business_fact_records[]'
                Test-ChainOfCustodyNotes -Record $record -Errors $errors -RecordPath '$.business_fact_records[]'
            }
            foreach ($record in $legalRecords) {
                Test-ProtectedReferenceArray -Record $record -PropertyName 'protected_evidence_refs' -Errors $errors -RecordPath '$.legal_fact_records[]'
                Test-ChainOfCustodyNotes -Record $record -Errors $errors -RecordPath '$.legal_fact_records[]'
            }
        }

        if ($PacketKind -eq 'PrivacyAccess') {
            $privacyRecords = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'privacy_records'))
            $packetState = Get-HavocProperty -InputObject $InputObject -Name 'packet_state'
            $validForReporting = Get-HavocProperty -InputObject $InputObject -Name 'valid_for_reporting'

            if ($privacyRecords.Count -eq 0) {
                if ($packetState -ne 'no_facts_provided') {
                    Add-ValidationError -Errors $errors -Message 'no_facts_provided state is required when no privacy facts are present'
                }
                Add-ValidationError -Errors $errors -Message 'no_facts_provided packets are not valid for reporting'
                if ($validForReporting -ne $false) {
                    Add-ValidationError -Errors $errors -Message 'no_facts_provided packets must set valid_for_reporting to false'
                }
            }

            foreach ($record in $privacyRecords) {
                Test-ProtectedReferenceArray -Record $record -PropertyName 'protected_evidence_refs' -Errors $errors -RecordPath '$.privacy_records[]'
                Test-InsiderRiskRecord -Record $record -Errors $errors -RecordPath '$.privacy_records[]'
            }
        }

        [pscustomobject]@{
            IsValid = ($errors.Count -eq 0)
            Errors = @($errors)
        }
    }
}

function ConvertTo-HavocBusinessLegalPrivacyAuditProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object]$InputObject,
        [Parameter(Mandatory)][ValidateSet('BusinessLegal', 'PrivacyAccess')][string]$PacketKind
    )

    process {
        $validation = Test-HavocBusinessLegalPrivacyPacket -InputObject $InputObject -PacketKind $PacketKind
        if (-not $validation.IsValid) {
            throw "Business/legal/privacy packet is invalid: $($validation.Errors -join '; ')"
        }

        if ($PacketKind -eq 'BusinessLegal') {
            return [pscustomobject]@{
                business_fact_records = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'business_fact_records') | ForEach-Object {
                    Select-HavocAllowlistedProperties -Record $_ -Fields $script:BusinessFactProjectionFields
                })
                legal_fact_records = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'legal_fact_records') | ForEach-Object {
                    Select-HavocAllowlistedProperties -Record $_ -Fields $script:LegalFactProjectionFields
                })
            }
        }

        [pscustomobject]@{
            privacy_records = @(Get-HavocArray -Value (Get-HavocProperty -InputObject $InputObject -Name 'privacy_records') | ForEach-Object {
                Select-HavocAllowlistedProperties -Record $_ -Fields $script:PrivacyProjectionFields
            })
        }
    }
}

Export-ModuleMember -Function Test-HavocBusinessLegalPrivacyPacket, ConvertTo-HavocBusinessLegalPrivacyAuditProjection
