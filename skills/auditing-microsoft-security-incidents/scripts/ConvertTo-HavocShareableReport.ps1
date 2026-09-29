[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string[]]$AdditionalTerms = @(),
    [switch]$ScrubHashes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-HavocFullPath {
    param([Parameter(Mandatory)][string]$Path)
    [System.IO.Path]::GetFullPath($Path)
}

function Test-HavocSamePath {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    [string]::Equals(
        (Resolve-HavocFullPath $Left).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
        (Resolve-HavocFullPath $Right).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Test-HavocPathUnder {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Parent)
    $fullPath = (Resolve-HavocFullPath $Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $fullParent = (Resolve-HavocFullPath $Parent).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $fullPath.StartsWith($fullParent + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-HavocMapTable {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Category)
    if (-not $State.Forward.ContainsKey($Category)) {
        $State.Forward[$Category] = @{}
        $State.Reverse[$Category] = [ordered]@{}
        $State.Next[$Category] = 1
    }
    $State.Forward[$Category]
}

function Get-HavocPseudonym {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Original,
        [Parameter(Mandatory)][string]$Pattern
    )
    $table = Get-HavocMapTable $State $Category
    if ($table.ContainsKey($Original)) {
        return $table[$Original]
    }
    $ordinal = [int]$State.Next[$Category]
    $State.Next[$Category] = $ordinal + 1
    $pseudonym = $Pattern -f $ordinal
    $table[$Original] = $pseudonym
    $State.Reverse[$Category][$pseudonym] = $Original
    $pseudonym
}

function Add-HavocAlias {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Original,
        [Parameter(Mandatory)][string]$Pseudonym
    )
    $table = Get-HavocMapTable $State $Category
    if (-not $table.ContainsKey($Original)) {
        $table[$Original] = $Pseudonym
    }
}

function Add-HavocHarvest {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Original,
        [Parameter(Mandatory)][string]$Replacement
    )
    if ([string]::IsNullOrWhiteSpace($Original) -or $Original.Trim().Length -lt 3) {
        return
    }
    if (-not ($State.PSObject.Properties.Name -contains 'Harvest')) {
        $State | Add-Member -NotePropertyName Harvest -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
    }
    $exists = $false
    foreach ($entry in $State.Harvest) {
        if ([string]::Equals($entry.Original, $Original, [System.StringComparison]::OrdinalIgnoreCase)) {
            $exists = $true
            break
        }
    }
    if (-not $exists) {
        $State.Harvest.Add([pscustomobject]@{
            Original = $Original
            Replacement = $Replacement
        })
    }
}

function Test-HavocDocumentationIPv4 {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -eq '127.0.0.1') { return $true }
    $parts = @($Value -split '\.' | ForEach-Object { [int]$_ })
    (($parts[0] -eq 192 -and $parts[1] -eq 0 -and $parts[2] -eq 2) -or
     ($parts[0] -eq 198 -and $parts[1] -eq 51 -and $parts[2] -eq 100) -or
     ($parts[0] -eq 203 -and $parts[1] -eq 0 -and $parts[2] -eq 113))
}

function Test-HavocDocumentationIPv6 {
    param([Parameter(Mandatory)][System.Net.IPAddress]$Address)
    if ([System.Net.IPAddress]::IsLoopback($Address)) { return $true }
    $bytes = $Address.GetAddressBytes()
    ($bytes.Length -eq 16 -and $bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8)
}

function Test-HavocAllowedGuid {
    param([Parameter(Mandatory)][string]$Value)
    $lower = $Value.ToLowerInvariant()
    ($lower -eq '14d82eec-204b-4c2f-b7e8-296a70dab67e' -or
     $lower -eq '1950a258-227b-4e31-a9cf-717495945fc2' -or
     $lower.StartsWith('00000000-0000-4000-8000-', [System.StringComparison]::Ordinal))
}

function Test-HavocAllowedHost {
    param([Parameter(Mandatory)][string]$Value)
    $lower = $Value.TrimEnd('.').ToLowerInvariant()
    $allowed = @(
        'graph.microsoft.com',
        ('dod-graph.microsoft.' + 'u' + 's'),
        'management.azure.com',
        ('management.' + 'u' + 'sgovcloudapi.net'),
        'api.loganalytics.io',
        ('api.loganalytics.' + 'u' + 's'),
        'login.microsoftonline.com',
        ('login.microsoftonline.' + 'u' + 's'),
        'sts.windows.net',
        'login.windows.net',
        'graph.windows.net',
        'redacted.example'
    )
    ($lower -in $allowed -or $lower.EndsWith('.redacted.example', [System.StringComparison]::Ordinal))
}

function Test-HavocPublicHostCandidate {
    param([Parameter(Mandatory)][string]$Value)
    $lower = $Value.TrimEnd('.').ToLowerInvariant()
    $knownTlds = @('com', 'net', 'org', 'io', 'example')
    $last = ($lower -split '\.')[-1]
    ($last -in $knownTlds)
}

function Convert-HavocResourceId {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)]$State)
    $segments = @($Value -split '/')
    $converted = [System.Collections.Generic.List[string]]::new()
    $providerSeen = $false
    $providerPayloadIndex = -1
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $segment = $segments[$index]
        if ($index -eq 0 -and $segment -eq '') {
            $converted.Add('')
            continue
        }
        $lower = $segment.ToLowerInvariant()
        if ($lower -in @('subscriptions', 'resourcegroups', 'providers')) {
            $converted.Add($segment)
            if ($lower -eq 'providers') {
                $providerSeen = $true
                $providerPayloadIndex = -1
            }
            continue
        }
        $previous = if ($index -gt 0) { $segments[$index - 1].ToLowerInvariant() } else { '' }
        if ($previous -eq 'subscriptions') {
            $converted.Add((Get-HavocPseudonym $State 'resourceId' $segment 'subscription-{0:0000}'))
            continue
        }
        if ($previous -eq 'resourcegroups') {
            $converted.Add((Get-HavocPseudonym $State 'resourceId' $segment 'resourceGroup-{0:0000}'))
            continue
        }
        if ($previous -eq 'providers') {
            $converted.Add($segment)
            $providerPayloadIndex = 0
            continue
        }
        if ($providerSeen) {
            $providerPayloadIndex++
            if (($providerPayloadIndex % 2) -eq 0) {
                $converted.Add((Get-HavocPseudonym $State 'resourceId' $segment 'resourceName-{0:0000}'))
            }
            else {
                $converted.Add($segment)
            }
            continue
        }
        $converted.Add((Get-HavocPseudonym $State 'resourceId' $segment 'resourceSegment-{0:0000}'))
    }
    ($converted -join '/')
}

function Convert-HavocHost {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)]$State)
    if (Test-HavocAllowedHost $Value) { return $Value }
    Get-HavocPseudonym $State 'host' $Value 'host-{0:0000}.redacted.example'
}

function Convert-HavocAccount {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)]$State)
    Get-HavocPseudonym $State 'upn' $Value 'user{0:0000}@redacted.example'
}

function Test-HavocHashContext {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][int]$Index)
    $start = [Math]::Max(0, $Index - 32)
    $prefix = $Text.Substring($start, $Index - $start)
    ($prefix -match '(?i)(sha|md5|hash)[\s:=`"''-]*$')
}

function Convert-HavocText {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)]$State,
        [string[]]$Terms = @(),
        [switch]$Hashes,
        [string]$JsonFieldName = ''
    )

    $result = $Text

    $result = [regex]::Replace(
        $result,
        '(?i)(?:%2f)+subscriptions(?:%2f)+[^%\s\]\)"'']+(?:%2f)+resourceGroups(?:%2f)+[^%\s\]\)"'']+(?:(?:%2f)+providers(?:%2f)+[^%\s\]\)"'']+(?:(?:%2f)+[^%\s\]\)"'']+)*)?',
        {
            param($match)
            $decoded = [System.Uri]::UnescapeDataString($match.Value)
            [System.Uri]::EscapeDataString((Convert-HavocResourceId $decoded $State))
        }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)/subscriptions/[^/\s\]\)"'']+/resourceGroups/[^/\s\]\)"'']+(?:/providers/[^/\s\]\)"'']+(?:/[^/\s\]\)"'']+)*)?',
        { param($match) Convert-HavocResourceId $match.Value $State }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)\b[A-Z0-9._%+\-]+%40[A-Z0-9.\-]+\.[A-Z]{2,}\b',
        { param($match) Convert-HavocAccount ([System.Uri]::UnescapeDataString($match.Value)) $State }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b',
        {
            param($match)
            if ($match.Value.ToLowerInvariant().EndsWith('@redacted.example', [System.StringComparison]::Ordinal)) { return $match.Value }
            Convert-HavocAccount $match.Value $State
        }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(https?://)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)(?=[:/\?#]|$)',
        { param($match) $match.Groups[1].Value + (Convert-HavocHost $match.Groups[2].Value $State) }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(\\\\)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)(?=\\)',
        { param($match) $match.Groups[1].Value + (Convert-HavocHost $match.Groups[2].Value $State) }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(?<![\\.\w-])[A-Z0-9_-]+\\[A-Z0-9_-]+\b',
        { param($match) Convert-HavocAccount $match.Value $State }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(?<![/@\\\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![/\\\w-])',
        {
            param($match)
            if (-not (Test-HavocPublicHostCandidate $match.Value)) { return $match.Value }
            Convert-HavocHost $match.Value $State
        }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])',
        {
            param($match)
            if (Test-HavocAllowedGuid $match.Value) { return $match.Value }
            Get-HavocPseudonym $State 'guid' $match.Value 'GUID-{0:0000}'
        }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])',
        {
            param($match)
            if (-not $Hashes -and (($JsonFieldName -match '(?i)(sha|md5|hash)') -or (Test-HavocHashContext $result $match.Index))) {
                return $match.Value
            }
            $category = if ($Hashes -and (($JsonFieldName -match '(?i)(sha|md5|hash)') -or (Test-HavocHashContext $result $match.Index))) { 'hash' } else { 'guid' }
            $pattern = if ($category -eq 'hash') { 'HASH-{0:0000}' } else { 'GUID-{0:0000}' }
            Get-HavocPseudonym $State $category $match.Value $pattern
        }
    )

    $result = [regex]::Replace(
        $result,
        '(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\.?\d)',
        {
            param($match)
            if (Test-HavocDocumentationIPv4 $match.Value) { return $match.Value }
            Get-HavocPseudonym $State 'ip' $match.Value 'IP-{0:0000}'
        }
    )

    $result = [regex]::Replace(
        $result,
        '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?![0-9a-f:])',
        {
            param($match)
            $address = [System.Net.IPAddress]::None
            if (-not [System.Net.IPAddress]::TryParse($match.Value, [ref]$address)) { return $match.Value }
            if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $match.Value }
            if (Test-HavocDocumentationIPv6 $address) { return $match.Value }
            Get-HavocPseudonym $State 'ip' $match.Value 'IP-{0:0000}'
        }
    )

    $result = [regex]::Replace(
        $result,
        '\bS-1-(?:5-21|12-1)-\d+(?:-\d+){1,14}\b',
        { param($match) Get-HavocPseudonym $State 'sid' $match.Value 'SID-{0:0000}' }
    )

    foreach ($term in @($Terms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)) {
        $escaped = [regex]::Escape($term)
        $result = [regex]::Replace(
            $result,
            $escaped,
            { param($match) Get-HavocPseudonym $State 'term' $match.Value 'TERM-{0:0000}' },
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    if ($JsonFieldName -match '(?i)^(hostName|deviceName|computerName|machineName|netBiosName)$' -and $result -eq $Text) {
        $result = Convert-HavocHost $Text $State
    }
    elseif ($JsonFieldName -match '(?i)^(domainName|workspaceName|resourceGroup|resourceGroupName)$' -and $result -eq $Text) {
        $result = Get-HavocPseudonym $State 'term' $Text 'TERM-{0:0000}'
    }

    if ($Hashes) {
        $result = [regex]::Replace(
            $result,
            '(?i)(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40})(?![0-9a-f])',
            { param($match) Get-HavocPseudonym $State 'hash' $match.Value 'HASH-{0:0000}' }
        )
    }

    if ($State.PSObject.Properties.Name -contains 'Harvest') {
        foreach ($entry in @($State.Harvest | Sort-Object { $_.Original.Length } -Descending)) {
            $escaped = [regex]::Escape($entry.Original)
            $result = [regex]::Replace(
                $result,
                "(?i)(?<![A-Z0-9_-])$escaped(?![A-Z0-9_-])",
                { param($match) $entry.Replacement }
            )
        }
    }

    $result
}

function Add-HavocHarvestedIdentityValue {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][AllowEmptyString()][string]$FieldName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Trim().Length -lt 3) {
        return
    }
    $field = $FieldName.ToLowerInvariant()
    $text = $Value.Trim()
    if ($field -match '(hostname|device(name)?|computer(name)?|machine(name)?|netbios(name)?|^host$)') {
        Add-HavocHarvest $State $text (Convert-HavocHost $text $State)
        return
    }
    if ($field -match '(account(name)?|userprincipalname|upn|owner|user(name)?)') {
        $accountText = if ($text -match '(?i)%40') { [System.Uri]::UnescapeDataString($text) } else { $text }
        $accountReplacement = Convert-HavocAccount $accountText $State
        Add-HavocHarvest $State $text $accountReplacement
        if ($accountText -ne $text) {
            Add-HavocHarvest $State $accountText $accountReplacement
        }
        if ($accountText -match '^(?<domain>[^\\]+)\\(?<user>[^\\]+)$') {
            $domain = $Matches.domain
            $user = $Matches.user
            $domainReplacement = Get-HavocPseudonym $State 'term' $domain 'TERM-{0:0000}'
            Add-HavocHarvest $State $domain $domainReplacement
            Add-HavocAlias $State 'upn' $user $accountReplacement
            Add-HavocHarvest $State $user $accountReplacement
        }
        return
    }
    if ($field -match '((domain|workspace|resourcegroup)(name)?s?(list)?|organization(name|displayname|id)?|tenant(display)?name)$') {
        Add-HavocHarvest $State $text (Get-HavocPseudonym $State 'term' $text 'TERM-{0:0000}')
        return
    }
    if ($field -match '(subscriptionid|tenantid|workspaceid|clientid|objectid|principalid)') {
        $replacement = Convert-HavocText -Text $text -State $State
        if ($replacement -ne $text) {
            Add-HavocHarvest $State $text $replacement
        }
    }
}

function Initialize-HavocHarvestFromJson {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)]$State,
        [string]$FieldName = ''
    )
    if ($null -eq $Value) { return }
    if ($Value -is [string]) {
        Add-HavocHarvestedIdentityValue -State $State -FieldName $FieldName -Value $Value
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary] -and $Value -isnot [string] -and $Value -isnot [pscustomobject]) {
        foreach ($item in $Value) {
            Initialize-HavocHarvestFromJson -Value $item -State $State -FieldName $FieldName
        }
        return
    }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            Initialize-HavocHarvestFromJson -Value $property.Value -State $State -FieldName $property.Name
        }
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            Initialize-HavocHarvestFromJson -Value $Value[$key] -State $State -FieldName ([string]$key)
        }
    }
}

function Convert-HavocJsonValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)]$State,
        [string[]]$Terms = @(),
        [switch]$Hashes,
        [string]$FieldName = ''
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -and $Value.Length -eq 0) { return $Value }
    if ($Value -is [string]) {
        return Convert-HavocText -Text $Value -State $State -Terms $Terms -Hashes:$Hashes -JsonFieldName $FieldName
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary] -and $Value -isnot [string] -and $Value -isnot [pscustomobject]) {
        $items = @()
        foreach ($item in $Value) {
            $items += ,(Convert-HavocJsonValue -Value $item -State $State -Terms $Terms -Hashes:$Hashes -FieldName $FieldName)
        }
        return ,$items
    }
    if ($Value -is [pscustomobject]) {
        $object = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $scrubbedName = Convert-HavocText -Text $property.Name -State $State -Terms $Terms -Hashes:$Hashes
            $object[$scrubbedName] = Convert-HavocJsonValue -Value $property.Value -State $State -Terms $Terms -Hashes:$Hashes -FieldName $property.Name
        }
        return $object
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $object = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $keyText = [string]$key
            $scrubbedName = Convert-HavocText -Text $keyText -State $State -Terms $Terms -Hashes:$Hashes
            $object[$scrubbedName] = Convert-HavocJsonValue -Value $Value[$key] -State $State -Terms $Terms -Hashes:$Hashes -FieldName $keyText
        }
        return $object
    }
    $Value
}

function Get-HavocCounts {
    param([Parameter(Mandatory)]$State)
    $counts = [ordered]@{}
    foreach ($category in @('guid', 'upn', 'ip', 'host', 'resourceId', 'sid', 'term', 'hash')) {
        $counts[$category] = if ($State.Reverse.ContainsKey($category)) { @($State.Reverse[$category].Keys).Count } else { 0 }
    }
    $counts
}

function Get-HavocDecodedText {
    param([Parameter(Mandatory)][string]$Text)
    try { [System.Uri]::UnescapeDataString($Text) } catch { $Text }
}

function Test-HavocResiduals {
    param([Parameter(Mandatory)][string]$Text, [string[]]$Terms = @(), [string[]]$HarvestedTerms = @())
    $texts = @($Text, (Get-HavocDecodedText $Text))
    foreach ($candidateText in $texts) {
        foreach ($match in [regex]::Matches($candidateText, '(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])')) {
            if (-not (Test-HavocAllowedGuid $match.Value)) { return 'guid' }
        }
        foreach ($match in [regex]::Matches($candidateText, '(?i)\b[A-Z0-9._%+\-]+(?:@|%40)[A-Z0-9.\-]+\.[A-Z]{2,}\b')) {
            if (-not $match.Value.ToLowerInvariant().EndsWith('@redacted.example', [System.StringComparison]::Ordinal)) { return 'upn' }
        }
        foreach ($match in [regex]::Matches($candidateText, '(?i)(?<![\\.\w-])[A-Z0-9_-]+\\[A-Z0-9_-]+\b')) {
            return 'domain_account'
        }
        foreach ($match in [regex]::Matches($candidateText, '(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\.?\d)')) {
            if (-not (Test-HavocDocumentationIPv4 $match.Value)) { return 'ipv4' }
        }
        foreach ($match in [regex]::Matches($candidateText, '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?![0-9a-f:])')) {
            $address = [System.Net.IPAddress]::None
            if ([System.Net.IPAddress]::TryParse($match.Value, [ref]$address) -and
                $address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and
                -not (Test-HavocDocumentationIPv6 $address)) {
                return 'ipv6'
            }
        }
        foreach ($match in [regex]::Matches($candidateText, '\bS-1-(?:5-21|12-1)-\d+(?:-\d+){1,14}\b')) {
            return 'sid'
        }
        foreach ($match in [regex]::Matches($candidateText, '(?i)/subscriptions/([^/\s\]\)"'']+)/resourceGroups/([^/\s\]\)"'']+)')) {
            if ($match.Groups[1].Value -notmatch '^subscription-\d{4}$' -or $match.Groups[2].Value -notmatch '^resourceGroup-\d{4}$') {
                return 'resource_id'
            }
        }
        foreach ($match in [regex]::Matches($candidateText, '(?i)(?<![/@\\\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![/\\\w-])')) {
            if ((Test-HavocPublicHostCandidate $match.Value) -and -not (Test-HavocAllowedHost $match.Value)) { return 'host' }
        }
        foreach ($term in @(($Terms + $HarvestedTerms) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_.Length -ge 3 })) {
            if ($candidateText.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $(if ($Terms -contains $term) { 'additional_term' } else { 'harvested_term' }) }
        }
    }
    $false
}

$inputRoot = Resolve-HavocFullPath $InputDirectory
$outputRoot = Resolve-HavocFullPath $OutputDirectory
$protectedRoot = Resolve-HavocFullPath (Join-Path $inputRoot 'protected')

if (-not (Test-Path -LiteralPath $inputRoot -PathType Container)) { throw "InputDirectory does not exist: $InputDirectory" }
if (Test-HavocSamePath $inputRoot $outputRoot) { throw 'OutputDirectory must not be the input directory.' }
if ((Test-HavocSamePath $outputRoot $protectedRoot) -or (Test-HavocPathUnder $outputRoot $protectedRoot)) { throw 'OutputDirectory must not be inside InputDirectory\protected.' }

$reportMarkdownPath = Join-Path $inputRoot 'report.md'
$reportJsonPath = Join-Path $inputRoot 'report.json'
if (-not (Test-Path -LiteralPath $reportMarkdownPath -PathType Leaf)) { throw 'InputDirectory must contain report.md.' }
if (-not (Test-Path -LiteralPath $reportJsonPath -PathType Leaf)) { throw 'InputDirectory must contain report.json.' }

$state = [pscustomobject]@{ Forward = @{}; Reverse = @{}; Next = @{}; Harvest = [System.Collections.Generic.List[object]]::new() }
$markdown = Get-Content -LiteralPath $reportMarkdownPath -Raw
$json = Get-Content -LiteralPath $reportJsonPath -Raw | ConvertFrom-Json -Depth 100 -DateKind String
Initialize-HavocHarvestFromJson -Value $json -State $state
$shareableMarkdown = Convert-HavocText -Text $markdown -State $state -Terms $AdditionalTerms -Hashes:$ScrubHashes
$shareableJson = Convert-HavocJsonValue -Value $json -State $state -Terms $AdditionalTerms -Hashes:$ScrubHashes

$protectedExists = Test-Path -LiteralPath $protectedRoot -PathType Container
$mapText = $state.Reverse | ConvertTo-Json -Depth 20
$summary = [ordered]@{
    counts = Get-HavocCounts $state
    protectedMapWritten = [bool]$protectedExists
    protectedMapNote = if ($protectedExists) { 'written' } else { 'skipped: protected directory absent' }
}
$shareableJsonText = $shareableJson | ConvertTo-Json -Depth 100
$summaryText = $summary | ConvertTo-Json -Depth 20
$postCheckText = @($shareableMarkdown, $shareableJsonText, $summaryText) -join [Environment]::NewLine
$harvestedTerms = @($state.Harvest | ForEach-Object { $_.Original })
$residualCategory = Test-HavocResiduals -Text $postCheckText -Terms $AdditionalTerms -HarvestedTerms $harvestedTerms
if ($residualCategory) {
    throw "Residual tenant identifiers remain after scrubbing (category: $residualCategory); shareable outputs were not written."
}

[void][System.IO.Directory]::CreateDirectory($outputRoot)
if ($protectedExists) {
    Set-Content -LiteralPath (Join-Path $protectedRoot 'scrub-map.json') -Value $mapText -Encoding utf8
}
Set-Content -LiteralPath (Join-Path $outputRoot 'report.shareable.md') -Value $shareableMarkdown -Encoding utf8
Set-Content -LiteralPath (Join-Path $outputRoot 'report.shareable.json') -Value $shareableJsonText -Encoding utf8
Set-Content -LiteralPath (Join-Path $outputRoot 'scrub-map-summary.json') -Value $summaryText -Encoding utf8
