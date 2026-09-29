Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Common.Kernel.psm1') -Force

$script:ConfusableMapVersion = 'curated-2026-09-25'
$script:ConfusableMap = @{
    0x0430 = 'a'
    0x0410 = 'A'
    0x0435 = 'e'
    0x0415 = 'E'
    0x043E = 'o'
    0x041E = 'O'
    0x0440 = 'p'
    0x0420 = 'P'
    0x0441 = 'c'
    0x0421 = 'C'
    0x0443 = 'y'
    0x0423 = 'Y'
    0x0445 = 'x'
    0x0425 = 'X'
    0x0456 = 'i'
    0x0406 = 'I'
    0x0458 = 'j'
    0x0408 = 'J'
    0x03B1 = 'a'
    0x0391 = 'A'
    0x03BF = 'o'
    0x039F = 'O'
    0x03C1 = 'p'
    0x03A1 = 'P'
    0x03B5 = 'e'
    0x0395 = 'E'
}

function ConvertTo-InternationalizedEvidenceEscapedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $builder = [System.Text.StringBuilder]::new()
    foreach ($char in $Value.ToCharArray()) {
        $code = [int][char]$char
        if ($code -ge 0x20 -and $code -le 0x7E) {
            [void]$builder.Append($char)
        }
        else {
            [void]$builder.Append(('\u{0:X4}' -f $code))
        }
    }
    $builder.ToString()
}

function Get-HavocScriptName {
    param([int]$CodePoint)

    if (($CodePoint -ge 0x0041 -and $CodePoint -le 0x005A) -or
        ($CodePoint -ge 0x0061 -and $CodePoint -le 0x007A) -or
        ($CodePoint -ge 0x00C0 -and $CodePoint -le 0x024F)) {
        return 'Latin'
    }
    if ($CodePoint -ge 0x0400 -and $CodePoint -le 0x052F) { return 'Cyrillic' }
    if ($CodePoint -ge 0x0370 -and $CodePoint -le 0x03FF) { return 'Greek' }
    if (($CodePoint -ge 0x0300 -and $CodePoint -le 0x036F) -or
        $CodePoint -eq 0x200C -or $CodePoint -eq 0x200D) {
        return 'Inherited'
    }
    if (($CodePoint -ge 0x0030 -and $CodePoint -le 0x0039) -or
        $CodePoint -eq 0x002D -or $CodePoint -eq 0x002E -or $CodePoint -eq 0x005F -or
        [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory([char]$CodePoint) -in @(
            [System.Globalization.UnicodeCategory]::SpaceSeparator,
            [System.Globalization.UnicodeCategory]::Control,
            [System.Globalization.UnicodeCategory]::Format,
            [System.Globalization.UnicodeCategory]::ConnectorPunctuation,
            [System.Globalization.UnicodeCategory]::DashPunctuation,
            [System.Globalization.UnicodeCategory]::OtherPunctuation
        )) {
        return 'Common'
    }
    'Other'
}

function New-HavocCodePointFinding {
    param(
        [int]$CodePoint,
        [int]$Index,
        [string]$Name
    )

    [pscustomobject][ordered]@{
        code_point = ('U+{0:X4}' -f $CodePoint)
        escaped = ('\u{0:X4}' -f $CodePoint)
        name = $Name
        index = $Index
    }
}

function Get-HavocControlName {
    param([int]$CodePoint)
    switch ($CodePoint) {
        0x202A { 'LEFT-TO-RIGHT EMBEDDING'; break }
        0x202B { 'RIGHT-TO-LEFT EMBEDDING'; break }
        0x202C { 'POP DIRECTIONAL FORMATTING'; break }
        0x202D { 'LEFT-TO-RIGHT OVERRIDE'; break }
        0x202E { 'RIGHT-TO-LEFT OVERRIDE'; break }
        0x2066 { 'LEFT-TO-RIGHT ISOLATE'; break }
        0x2067 { 'RIGHT-TO-LEFT ISOLATE'; break }
        0x2068 { 'FIRST STRONG ISOLATE'; break }
        0x2069 { 'POP DIRECTIONAL ISOLATE'; break }
        0x200E { 'LEFT-TO-RIGHT MARK'; break }
        0x200F { 'RIGHT-TO-LEFT MARK'; break }
        0x061C { 'ARABIC LETTER MARK'; break }
        0x00AD { 'SOFT HYPHEN'; break }
        0x180E { 'MONGOLIAN VOWEL SEPARATOR'; break }
        0x200B { 'ZERO WIDTH SPACE'; break }
        0x200C { 'ZERO WIDTH NON-JOINER'; break }
        0x200D { 'ZERO WIDTH JOINER'; break }
        0x2060 { 'WORD JOINER'; break }
        0x2061 { 'FUNCTION APPLICATION'; break }
        0x2062 { 'INVISIBLE TIMES'; break }
        0x2063 { 'INVISIBLE SEPARATOR'; break }
        0x2064 { 'INVISIBLE PLUS'; break }
        0xFEFF { 'ZERO WIDTH NO-BREAK SPACE'; break }
        default { 'UNKNOWN FORMAT CHARACTER' }
    }
}

function Get-HavocConfusableSkeleton {
    param([string]$Value)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($char in $Value.ToCharArray()) {
        $code = [int][char]$char
        if ($script:ConfusableMap.ContainsKey($code)) {
            [void]$builder.Append([string]$script:ConfusableMap[$code])
        }
        else {
            [void]$builder.Append($char)
        }
    }
    $builder.ToString().Normalize([Text.NormalizationForm]::FormKC).ToUpperInvariant().ToLowerInvariant()
}

function New-InternationalizedIdentifierRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9._:-]*$')]
        [string]$RecordId,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RawValue,

        [Parameter(Mandatory)]
        [ValidateSet('domain','filename','account','url','text','other')]
        [string]$IdentifierKind,

        [Parameter(Mandatory)]
        [string]$Locale
    )

    $rawSha256 = Get-HavocSha256Hex -Text $RawValue
    $rawRef = 'protected-evidence:i18n/raw/{0}' -f $rawSha256.Substring(0, 24)
    $nfc = $RawValue.Normalize([Text.NormalizationForm]::FormC)
    $nfkc = $RawValue.Normalize([Text.NormalizationForm]::FormKC)
    $nfkcChanged = -not [string]::Equals($RawValue, $nfkc, [StringComparison]::Ordinal)
    $invariantFold = $nfkc.ToUpperInvariant()
    $culture = [Globalization.CultureInfo]::GetCultureInfo($Locale)
    $cultureFold = $nfkc.ToUpper($culture)
    $cultureFoldDiffers = -not [string]::Equals($invariantFold, $cultureFold, [StringComparison]::Ordinal)

    $bidiCodePoints = @(0x061C,0x202A,0x202B,0x202C,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069,0x200E,0x200F)
    $zeroWidthCodePoints = @(0x00AD,0x180E,0x200B,0x200C,0x200D,0x200E,0x200F,0x2060,0x2061,0x2062,0x2063,0x2064,0xFEFF)
    $bidi = @()
    $zeroWidth = @()
    $scripts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

    for ($index = 0; $index -lt $RawValue.Length; $index++) {
        $code = [int][char]$RawValue[$index]
        [void]$scripts.Add((Get-HavocScriptName -CodePoint $code))
        if ($bidiCodePoints -contains $code) {
            $bidi += New-HavocCodePointFinding -CodePoint $code -Index $index -Name (Get-HavocControlName -CodePoint $code)
        }
        if ($zeroWidthCodePoints -contains $code) {
            $zeroWidth += New-HavocCodePointFinding -CodePoint $code -Index $index -Name (Get-HavocControlName -CodePoint $code)
        }
    }

    $strongScripts = @($scripts | Where-Object { $_ -notin @('Common','Inherited') } | Sort-Object -CaseSensitive)
    $mixedScript = $strongScripts.Count -gt 1

    $idnALabel = $null
    $idnULabel = $null
    $idnConversionState = if ($IdentifierKind -eq 'domain') { 'conversion_failed' } else { 'not_applicable' }
    if ($IdentifierKind -eq 'domain') {
        $idn = [System.Globalization.IdnMapping]::new()
        $idn.UseStd3AsciiRules = $true
        try {
            $idnALabel = $idn.GetAscii($RawValue).ToLowerInvariant()
            $idnULabel = $idn.GetUnicode($idnALabel)
            $idnConversionState = 'converted'
        }
        catch {
            $idnALabel = $null
            $idnULabel = $null
            $idnConversionState = 'conversion_failed'
        }
    }

    $skeleton = Get-HavocConfusableSkeleton -Value $nfkc
    $skeletonChanged = -not [string]::Equals($skeleton, $nfkc.ToUpperInvariant().ToLowerInvariant(), [StringComparison]::Ordinal)
    $extensionSpoofing = $false
    if ($IdentifierKind -eq 'filename' -and @($bidi | Where-Object { $_.code_point -eq 'U+202E' }).Count -gt 0) {
        $extensionSpoofing = $RawValue -match '\.[A-Za-z0-9]{1,8}$'
    }

    $comparisonKey = if ($IdentifierKind -eq 'domain' -and $idnConversionState -eq 'converted') { $idnALabel } else { $invariantFold }
    $unicodeRisks = [System.Collections.Generic.List[string]]::new()
    if ($mixedScript) { $unicodeRisks.Add('mixed-script') }
    if ($skeletonChanged) { $unicodeRisks.Add('confusable-skeleton') }
    if ($nfkcChanged) { $unicodeRisks.Add('compatibility-lookalike') }
    if ($bidi.Count -gt 0) { $unicodeRisks.Add('bidi-control') }
    if ($zeroWidth.Count -gt 0) { $unicodeRisks.Add('invisible-control') }
    if ($idnConversionState -eq 'conversion_failed') { $unicodeRisks.Add('idn-conversion-failed') }
    $limitations = @(
        'Confusable skeleton uses a small curated map for high-risk Latin lookalikes and is not the full Unicode TR39 table.',
        'Raw and normalized identifiers are represented only by protected references or SHA-256 digests in this record.',
        'Localized timestamp parsing is out of scope for this record and is deferred to the timeline family.'
    )

    $normalized = [ordered]@{
        nfc_sha256 = Get-HavocSha256Hex -Text $nfc
        nfkc_sha256 = Get-HavocSha256Hex -Text $nfkc
        invariant_case_fold_sha256 = Get-HavocSha256Hex -Text $invariantFold
        culture_case_fold_sha256 = Get-HavocSha256Hex -Text $cultureFold
        culture_case_fold_differs = [bool]$cultureFoldDiffers
        idn_conversion_state = $idnConversionState
    }
    if ($idnConversionState -eq 'converted') {
        $normalized.idn_alabel_sha256 = Get-HavocSha256Hex -Text $idnALabel
        $normalized.idn_ulabel_sha256 = Get-HavocSha256Hex -Text $idnULabel
    }

    [pscustomobject][ordered]@{
        record_id = $RecordId
        raw_value_ref = $rawRef
        raw_value_sha256 = $rawSha256
        identifier_kind = $IdentifierKind
        locale_used = $Locale
        normalized = [pscustomobject]$normalized
        nfkc_changed = [bool]$nfkcChanged
        detected_scripts = @($strongScripts)
        mixed_script = [bool]$mixedScript
        bidi_controls_present = [bool]($bidi.Count -gt 0)
        bidi_controls = @($bidi)
        zero_width_chars_present = [bool]($zeroWidth.Count -gt 0)
        zero_width_chars = @($zeroWidth)
        confusable_skeleton_sha256 = Get-HavocSha256Hex -Text $skeleton
        confusable_skeleton_changed = [bool]$skeletonChanged
        confusable_map_version = $script:ConfusableMapVersion
        homograph_risk = [bool]($mixedScript -or $skeletonChanged -or $nfkcChanged -or $bidi.Count -gt 0 -or $zeroWidth.Count -gt 0 -or $idnConversionState -eq 'conversion_failed')
        extension_spoofing_detected = [bool]$extensionSpoofing
        normalized_comparison_key_sha256 = Get-HavocSha256Hex -Text $comparisonKey
        unicode_risks = @($unicodeRisks.ToArray())
        limitations = $limitations
        behavior_bases = @('configurable_project_policy','explicit_gap')
    }
}

Export-ModuleMember -Function ConvertTo-InternationalizedEvidenceEscapedString, New-InternationalizedIdentifierRecord