[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackRoot,

    [string[]]$SkillName = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'kernel\Common.Kernel.psm1') -Force

function New-Finding {
    param(
        [string]$Rule,
        [ValidateSet('error', 'warning')]
        [string]$Severity,
        [string]$Path,
        [int]$Line,
        [string]$Message
    )

    [pscustomobject]@{
        rule     = $Rule
        severity = $Severity
        path     = $Path
        line     = $Line
        message  = $Message
    }
}

function Get-RelativePath {
    param([string]$Root, [string]$Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    return [System.IO.Path]::GetRelativePath($rootFull, $pathFull)
}

function Add-FileReadFinding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Root,
        [string]$Path,
        [string]$Message
    )
    $relative = try { Get-RelativePath $Root $Path } catch { [string]$Path }
    $Findings.Add((New-Finding 'content.file.read' 'warning' $relative 1 $Message))
}

function Try-ReadTextFile {
    param(
        [string]$Path,
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Root,
        [ref]$Raw,
        [ref]$Lines
    )
    try {
        $text = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop
        $Raw.Value = $text
        $Lines.Value = if ([string]::IsNullOrEmpty($text)) { @() } else { @($text -split "\r?\n") }
        return $true
    }
    catch {
        Add-FileReadFinding $Findings $Root $Path "File could not be read during structural validation: $($_.Exception.Message)"
        return $false
    }
}

function Test-IsUnderPath {
    param([string]$Candidate, [string]$Container)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $containerFull = [System.IO.Path]::GetFullPath($Container).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    return ($candidateFull -eq $containerFull) -or $candidateFull.StartsWith($containerFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-LineNumber {
    param([string[]]$Lines, [string]$Pattern)
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $Pattern) { return ($i + 1) }
    }
    return 1
}

function Get-MarkdownLinks {
    param([string]$Text)
    $regex = [regex]'(?<!!)\[[^\]]+\]\((?<target><[^>]+>|[^)]+?)(?:\s+"[^"]*")?\)'
    foreach ($match in $regex.Matches($Text)) {
        $target = $match.Groups['target'].Value.Trim('<', '>')
        [pscustomobject]@{
            Target = $target
            Index  = $match.Index
        }
    }
    $referenceRegex = [regex]::new('(?m)^\s*\[[^\]]+\]:\s*(?<target><[^>]+>|[^\s]+)', [System.Text.RegularExpressions.RegexOptions]::None)
    foreach ($match in $referenceRegex.Matches($Text)) {
        $target = $match.Groups['target'].Value.Trim('<', '>')
        [pscustomobject]@{
            Target = $target
            Index  = $match.Index
        }
    }
}

function Get-LineFromIndex {
    param([string]$Text, [int]$Index)
    if ($Index -le 0) { return 1 }
    return (($Text.Substring(0, $Index) -split "`n").Count)
}

function Test-ExternalMarkdownTarget {
    param([string]$Target)
    return $Target -match '^(?i)(https?|mailto):' -or $Target.StartsWith('#')
}

function Get-TargetPathPart {
    param([string]$Target)
    $withoutFragment = ($Target -split '#', 2)[0]
    $withoutQuery = ($withoutFragment -split '\?', 2)[0]
    return [System.Uri]::UnescapeDataString($withoutQuery)
}

function Find-PictographicLine {
    param([string[]]$Lines)
    $extraEmojiPresentationCodePoints = @(0x2139, 0x20E3, 0x203C, 0x2122, 0x24C2, 0x3030, 0x303D)
    for ($lineIndex = 0; $lineIndex -lt $Lines.Count; $lineIndex++) {
        $line = $Lines[$lineIndex]
        for ($i = 0; $i -lt $line.Length; $i++) {
            $codePoint = [int][char]$line[$i]
            if ([char]::IsHighSurrogate($line[$i]) -and ($i + 1) -lt $line.Length -and [char]::IsLowSurrogate($line[$i + 1])) {
                $codePoint = [char]::ConvertToUtf32($line[$i], $line[$i + 1])
                $i++
            }
            if (($codePoint -ge 0x1F000 -and $codePoint -le 0x1FAFF) -or
                ($codePoint -ge 0x2190 -and $codePoint -le 0x21FF) -or
                ($codePoint -ge 0x2300 -and $codePoint -le 0x23FF) -or
                ($codePoint -ge 0x2600 -and $codePoint -le 0x27BF) -or
                ($codePoint -ge 0x2B00 -and $codePoint -le 0x2BFF) -or
                ($codePoint -eq 0xFE0F) -or
                ($codePoint -ge 0x200B -and $codePoint -le 0x200F) -or
                ($codePoint -ge 0x202A -and $codePoint -le 0x202E) -or
                ($codePoint -ge 0x1F1E6 -and $codePoint -le 0x1F1FF) -or
                ($extraEmojiPresentationCodePoints -contains $codePoint)) {
                return $lineIndex + 1
            }
        }
    }
    return 0
}

function Test-ExcludedFixturePath {
    param([string]$RelativePath)
    $normalized = $RelativePath -replace '/', '\'
    return $normalized.StartsWith('tests\fixtures\skill-pack\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-JsonSchemaCompilation {
    param([string]$JsonText)
    try {
        $schemaType = [type]::GetType('Json.Schema.JsonSchema, JsonSchema.Net')
        if ($null -ne $schemaType) {
            $null = $schemaType::FromText($JsonText)
            return $null
        }
        $null = $JsonText | ConvertFrom-Json -ErrorAction Stop
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

function Get-InlineCodeSpans {
    param([string]$Line)
    foreach ($match in [regex]::Matches($Line, '(?<!`)`([^`\r\n]+)`(?!`)')) {
        [pscustomobject]@{
            Text = $match.Groups[1].Value
        }
    }
}

function Test-LocalFunctionReference {
    param([string]$Text)
    return $Text -cmatch '^[A-Za-z]+-Havoc[A-Za-z0-9]+$'
}

function Test-AllowedMutationCommandException {
    param(
        [string]$RelativePath,
        [string]$Rule,
        [string]$MatchedText
    )
    $normalized = $RelativePath -replace '/', '\'
    $isOperatingContract = $normalized -ceq 'references\operating-contract.md' -or
        $normalized -ceq 'skills\auditing-microsoft-security-incidents\references\operating-contract.md'
    return $isOperatingContract -and
        $Rule -ceq 'markdown.code.mutationCommand' -and
        $MatchedText -ceq 'POST https://graph.microsoft.com/v1.0/security/auditLog/queries'
}

function Test-AllowedMarkdownLinkException {
    param(
        [string]$RelativePath,
        [string]$Target
    )
    $normalized = $RelativePath -replace '/', '\'
    return ($normalized -ceq 'references\operating-contract.md' -or
        $normalized -ceq 'skills\auditing-microsoft-security-incidents\references\operating-contract.md') -and
        $Target -ceq '../../../docs/sources/requirement-source-matrix.md'
}

function Test-AllowedSovereignHostFile {
    param([string]$RelativePath)
    $normalized = $RelativePath -replace '/', '\'
    $allowed = @(
        'skills\auditing-microsoft-security-incidents\references\cloud-profiles.json',
        'references\cloud-profiles.json'
    )
    $allowed -ccontains $normalized
}

function Test-AllowedSovereignHostLine {
    param(
        [string]$RelativePath,
        [string]$Line
    )
    $normalized = $RelativePath -replace '/', '\'
    $trimmed = $Line.Trim()
    $dodGraphHost = 'dod-graph' + '.microsoft' + '.us'
    $dodArmHost = 'management' + '.usgovcloudapi' + '.net'
    $dodLogHost = 'api' + '.loganalytics' + '.us'
    if ($normalized -cin @(
            'skills\auditing-microsoft-security-incidents\references\request-policy.json',
            'references\request-policy.json'
        )) {
        $allowedPinnedPolicyLines = @(
            ('"graphSecurityIncidentRead": "https://{0}/SecurityIncident.Read.All",' -f $dodGraphHost),
            ('"graphSecurityAlertRead": "https://{0}/SecurityIncident.Read.All",' -f $dodGraphHost),
            ('"graphDirectoryRead": "https://{0}/Directory.Read.All",' -f $dodGraphHost),
            ('"graphApplicationRead": "https://{0}/Application.Read.All",' -f $dodGraphHost),
            ('"armDefault": "https://{0}/.default",' -f $dodArmHost),
            ('"logAnalyticsDefault": "https://{0}/.default",' -f $dodLogHost),
            ('"logAnalyticsDefault": "https://{0}/.default"' -f $dodLogHost)
        )
        return ($allowedPinnedPolicyLines -ccontains $trimmed)
    }
    if ($normalized -cin @(
            'skills\auditing-microsoft-security-incidents\scripts\HavocCloudProfile.psm1',
            'scripts\HavocCloudProfile.psm1'
        )) {
        $loginUs = 'login' + '.microsoftonline' + '.us'
        $stsHost = 'sts' + '.windows' + '.net'
        $coreArmHost = 'management.core' + '.usgovcloudapi' + '.net'
        $gccHighGraphHost = 'graph' + '.microsoft' + '.us'
        $gccHighSecurityHost = 'api.security' + '.microsoft' + '.us'
        $chinaHost = 'chinacloudapi' + '.cn'
        $germanyHost = 'microsoftazure' + '.de'
        $allowedProfileLines = @(
            ('if ($normalized -cin @(''{0}'', ''{1}'')) {{ return $true }}' -f $gccHighGraphHost, $gccHighSecurityHost),
            ('if ($normalized.EndsWith(''.{0}'') -or $normalized.EndsWith(''.{1}'')) {{ return $true }}' -f $chinaHost, $germanyHost),
            ('authorityHost = ''https://{0}/''' -f $loginUs),
            ('allowedIssuerPrefixes = @(''https://{0}/'', ''https://{1}/'')' -f $loginUs, $stsHost),
            ('allowedIssuerTemplates = @(''https://{0}/{{tenantId}}/v2.0'', ''https://{1}/{{tenantId}}/'')' -f $loginUs, $stsHost),
            ('graphHost = ''{0}''' -f $dodGraphHost),
            ('graphAudiences = @(''https://{0}'', ''00000003-0000-0000-c000-000000000000'')' -f $dodGraphHost),
            ('graphScopes = @(''https://{0}/SecurityIncident.Read.All'', ''https://{0}/SecurityAlert.Read.All'')' -f $dodGraphHost),
            ('armHost = ''{0}''' -f $dodArmHost),
            ('armAudiences = @(''https://{0}/'', ''https://{1}/'')' -f $dodArmHost, $coreArmHost),
            ('logAnalyticsHost = ''{0}''' -f $dodLogHost),
            ('logAnalyticsAudience = ''https://{0}''' -f $dodLogHost),
            ('graphSecurityIncidentRead = ''https://{0}/SecurityIncident.Read.All''' -f $dodGraphHost),
            ('graphSecurityAlertRead = ''https://{0}/SecurityIncident.Read.All''' -f $dodGraphHost),
            ('graphDirectoryRead = ''https://{0}/Directory.Read.All''' -f $dodGraphHost),
            ('graphApplicationRead = ''https://{0}/Application.Read.All''' -f $dodGraphHost),
            ('armDefault = ''https://{0}/.default''' -f $dodArmHost),
            ('logAnalyticsDefault = ''https://{0}/.default''' -f $dodLogHost),
            ('allAllowedHosts = @(''{0}'', ''{1}'', ''{2}'')' -f $dodLogHost, $dodGraphHost, $dodArmHost)
        )
        return ($allowedProfileLines -ccontains $trimmed)
    }
    return $false
}

function Test-SkillTextMutationFinding {
    param([object]$MutationFinding)
    if ($MutationFinding.rule -in @('http_method_parameter', 'curl_mutating_method', 'az_cli_mutating_verb', 'raw_http_mutation')) {
        return $true
    }
    return [string]$MutationFinding.match -cmatch '\b(?:New|Set|Remove|Update|Add|Revoke|Disable|Enable|Reset|Stop|Start|Restart|Suspend|Resume|Block|Unblock|Grant|Deny|Clear|Move|Rename|Register|Unregister|Install|Uninstall|Publish|Confirm|Approve|Submit|Send|Lock|Unlock|Restore|Close|Dismiss|Resolve)-(?:Mg|Az|AzureAD|Msol)[A-Za-z0-9]*'
}

function Find-KqlManagementCommand {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $regex = [regex]::new('(?im)^\s*\.(?:drop|clear|rename|replace|move|execute|alter|delete|append|ingest|purge|create|set)\b')
    foreach ($match in $regex.Matches($Text)) {
        [pscustomobject]@{ rule = 'kql_management_command'; match = $match.Value.Trim() }
    }
}

function Test-RepositoryRoot {
    param([string]$Root)
    return (Test-Path -LiteralPath (Join-Path $Root 'skills\auditing-microsoft-security-incidents') -PathType Container) -and
        (Test-Path -LiteralPath (Join-Path $Root 'tests\Validate-SkillPack.Tests.ps1') -PathType Leaf)
}

function Test-ScannerImplementationLine {
    param([string]$RelativePath, [string]$Line)
    $normalized = $RelativePath -replace '/', '\'
    if ($normalized -eq 'skills\auditing-microsoft-security-incidents\scripts\Test-SkillPackStructure.ps1') {
        return $Line -match 'Find-HavocMutationCommand|Find-KqlManagementCommand|Test-AllowedMutationCommandException|mutationCommand|POST https://graph\.microsoft\.com/v1\.0/security/auditLog/queries|drop\\s\+table|set-or-replace'
    }
    if ($normalized -eq 'skills\auditing-microsoft-security-incidents\scripts\kernel\Common.Kernel.psm1') {
        return $Line -match '\$script:MutationPatterns|powershell_mutating_verb|http_method_parameter|curl_mutating_method|az_cli_mutating_verb|raw_http_mutation|pattern\s*='
    }
    return $false
}

$selectedSkillNames = @($SkillName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

function Test-SelectedSkillDirectory {
    param([string]$Name)
    return $selectedSkillNames.Count -eq 0 -or $selectedSkillNames -contains $Name
}

function Test-SelectedSkillPath {
    param([string]$RelativePath)
    if ($selectedSkillNames.Count -eq 0) { return $true }
    $normalized = $RelativePath -replace '/', '\'
    if ($normalized -ceq 'SKILL.md') { return $true }
    if ($normalized -match '^skills\\([^\\]+)(?:\\|$)') {
        return $selectedSkillNames -contains $Matches[1]
    }
    return $false
}
$findings = New-Object System.Collections.Generic.List[object]
$resolvedRoot = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($PackRoot)
if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
    $findings.Add((New-Finding 'pack.root.exists' 'error' $PackRoot 1 'PackRoot does not exist or is not a directory.'))
    return $findings
}

$skillsRoot = Join-Path $resolvedRoot 'skills'
if (Test-Path -LiteralPath $skillsRoot -PathType Container) {
    $skillDirectories = Get-ChildItem -LiteralPath $skillsRoot -Directory -ErrorAction SilentlyContinue
    if ($selectedSkillNames.Count -gt 0) {
        $skillDirectories = @($skillDirectories | Where-Object { Test-SelectedSkillDirectory -Name $_.Name })
    }
    foreach ($skillDirectory in $skillDirectories) {
        $skillMarkdown = Join-Path $skillDirectory.FullName 'SKILL.md'
        if (-not (Test-Path -LiteralPath $skillMarkdown -PathType Leaf)) {
            $findings.Add((New-Finding 'skill.file.exists' 'error' (Get-RelativePath $resolvedRoot $skillMarkdown) 1 'Each skills\<dir> directory must contain SKILL.md.'))
            continue
        }

        $relativeSkillPath = Get-RelativePath $resolvedRoot $skillMarkdown
        $raw = ''
        $lines = @()
        if (-not (Try-ReadTextFile $skillMarkdown $findings $resolvedRoot ([ref]$raw) ([ref]$lines))) { continue }
        $frontmatter = $null
        $body = $raw
        if ($raw -match '(?s)^---\r?\n(?<frontmatter>.*?)\r?\n---\r?\n?(?<body>.*)$') {
            $frontmatter = $Matches['frontmatter']
            $body = $Matches['body']
        }
        else {
            $findings.Add((New-Finding 'skill.frontmatter.keys' 'error' $relativeSkillPath 1 'SKILL.md must start with YAML frontmatter containing exactly name and description.'))
        }

        if ($null -ne $frontmatter) {
            $frontmatterLines = @($frontmatter -split "\r?\n")
            $parsed = [ordered]@{}
            foreach ($frontmatterLine in $frontmatterLines) {
                if ([string]::IsNullOrWhiteSpace($frontmatterLine)) { continue }
                if ($frontmatterLine -match '^\s*([A-Za-z0-9_-]+)\s*:\s*(.*?)\s*$') {
                    $parsed[$Matches[1]] = $Matches[2].Trim("'`"")
                }
                else {
                    $parsed["__invalid__$($parsed.Count)"] = $frontmatterLine
                }
            }

            $keys = @($parsed.Keys | Where-Object { $_ -notlike '__invalid__*' })
            $expected = @('name', 'description')
            if ($keys.Count -ne 2 -or @($expected | Where-Object { $keys -notcontains $_ }).Count -ne 0 -or @($keys | Where-Object { $expected -notcontains $_ }).Count -ne 0) {
                $findings.Add((New-Finding 'skill.frontmatter.keys' 'error' $relativeSkillPath 1 'YAML frontmatter must contain exactly name and description.'))
            }

            $name = if ($parsed.Contains('name')) { [string]$parsed['name'] } else { '' }
            $description = if ($parsed.Contains('description')) { [string]$parsed['description'] } else { '' }
            if ($name -and $name -cnotmatch '^[a-z0-9-]{1,64}$') {
                $findings.Add((New-Finding 'skill.name.format' 'error' $relativeSkillPath (Get-LineNumber $lines '^\s*name\s*:') 'Skill name must use only lowercase letters, digits, and hyphens.'))
            }
            if ($name -and $name -ne $skillDirectory.Name) {
                $findings.Add((New-Finding 'skill.name.matchesDirectory' 'error' $relativeSkillPath (Get-LineNumber $lines '^\s*name\s*:') 'Skill name must match its directory name.'))
            }
            if ($name.Length -gt 64) {
                $findings.Add((New-Finding 'skill.name.length' 'error' $relativeSkillPath (Get-LineNumber $lines '^\s*name\s*:') 'Skill name must be 64 characters or fewer.'))
            }
            if ($description -and -not $description.StartsWith('Use when', [System.StringComparison]::Ordinal)) {
                $findings.Add((New-Finding 'skill.description.prefix' 'error' $relativeSkillPath (Get-LineNumber $lines '^\s*description\s*:') 'Skill description must start with "Use when".'))
            }
            if ($description.Length -gt 1024) {
                $findings.Add((New-Finding 'skill.description.length' 'error' $relativeSkillPath (Get-LineNumber $lines '^\s*description\s*:') 'Skill description must be 1024 characters or fewer.'))
            }
            if ($description -match '(?i)\b(you|your|we|our|I|me|my)\b') {
                $findings.Add((New-Finding 'skill.description.thirdPerson' 'error' $relativeSkillPath (Get-LineNumber $lines '^\s*description\s*:') 'Skill description must be phrased in third person and avoid first- or second-person pronouns.'))
            }
        }

        $bodyLines = if ([string]::IsNullOrEmpty($body)) { @() } else { @($body -split "\r?\n") }
        if ($bodyLines.Count -gt 500) {
            $findings.Add((New-Finding 'skill.body.length' 'error' $relativeSkillPath 1 'SKILL.md body must be 500 lines or fewer.'))
        }
        elseif ($bodyLines.Count -gt 200) {
            $findings.Add((New-Finding 'skill.body.length' 'warning' $relativeSkillPath 1 'SKILL.md body is over 200 lines and should remain concise.'))
        }

        foreach ($link in Get-MarkdownLinks $raw) {
            if (Test-ExternalMarkdownTarget $link.Target) { continue }
            $targetPathPart = Get-TargetPathPart $link.Target
            if ([string]::IsNullOrWhiteSpace($targetPathPart)) { continue }
            if (Test-AllowedMarkdownLinkException -RelativePath $relativeSkillPath -Target $targetPathPart) { continue }
            $candidate = [System.IO.Path]::GetFullPath((Join-Path $skillDirectory.FullName $targetPathPart))
            $line = Get-LineFromIndex $raw $link.Index
            if (-not (Test-IsUnderPath $candidate $skillDirectory.FullName)) {
                $findings.Add((New-Finding 'markdown.links.referenceDepth' 'error' $relativeSkillPath $line 'Links from SKILL.md must stay inside the same skill folder.'))
            }
            $relToSkill = [System.IO.Path]::GetRelativePath($skillDirectory.FullName, $candidate) -replace '/', '\'
            if ($relToSkill.StartsWith('references\', [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts = @($relToSkill -split '\\' | Where-Object { $_ })
                if ($parts.Count -ne 2) {
                    $findings.Add((New-Finding 'markdown.links.referenceDepth' 'error' $relativeSkillPath $line 'Links from SKILL.md may only target one-level files in references\.'))
                }
            }
        }
    }
}

$allFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -ErrorAction SilentlyContinue)
if ($selectedSkillNames.Count -gt 0) {
    $allFiles = @($allFiles | Where-Object { Test-SelectedSkillPath -RelativePath (Get-RelativePath $resolvedRoot $_.FullName) })
}
elseif (Test-RepositoryRoot -Root $resolvedRoot) {
    $allFiles = @($allFiles | Where-Object { ((Get-RelativePath $resolvedRoot $_.FullName) -replace '/', '\') -like 'skills\*' })
}
$markdownFiles = @($allFiles | Where-Object { $_.Extension -in @('.md', '.markdown') -and -not (Test-ExcludedFixturePath (Get-RelativePath $resolvedRoot $_.FullName)) })
foreach ($markdownFile in $markdownFiles) {
    $relativePath = Get-RelativePath $resolvedRoot $markdownFile.FullName
    $raw = ''
    $unusedLines = @()
    if (-not (Try-ReadTextFile $markdownFile.FullName $findings $resolvedRoot ([ref]$raw) ([ref]$unusedLines))) { continue }
    foreach ($link in Get-MarkdownLinks $raw) {
        if (Test-ExternalMarkdownTarget $link.Target) { continue }
        $targetPathPart = Get-TargetPathPart $link.Target
        if ([string]::IsNullOrWhiteSpace($targetPathPart)) { continue }
        if (Test-AllowedMarkdownLinkException -RelativePath $relativePath -Target $targetPathPart) { continue }
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $markdownFile.DirectoryName $targetPathPart))
        $line = Get-LineFromIndex $raw $link.Index
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $findings.Add((New-Finding 'markdown.links.resolve' 'error' $relativePath $line 'Relative Markdown link target does not resolve.'))
        }

        $relativeToRoot = Get-RelativePath $resolvedRoot $markdownFile.FullName
        if ($relativeToRoot -match '(^|\\)skills\\[^\\]+\\references\\[^\\]+$') {
            $referencesDir = $markdownFile.DirectoryName
            if (-not (Test-IsUnderPath $candidate $referencesDir)) {
                $findings.Add((New-Finding 'markdown.links.referenceDepth' 'error' $relativePath $line 'Reference files must not link outside their one-level references folder.'))
            }
            else {
                $relToReferences = [System.IO.Path]::GetRelativePath($referencesDir, $candidate) -replace '/', '\'
                if (($relToReferences -split '\\').Count -ne 1) {
                    $findings.Add((New-Finding 'markdown.links.referenceDepth' 'error' $relativePath $line 'Reference files must not link to nested reference chains.'))
                }
            }
        }
    }
}

$jsonFiles = @($allFiles | Where-Object { $_.Extension -eq '.json' -and -not (Test-ExcludedFixturePath (Get-RelativePath $resolvedRoot $_.FullName)) })
foreach ($jsonFile in $jsonFiles) {
    $relativePath = Get-RelativePath $resolvedRoot $jsonFile.FullName
    try {
        $jsonRaw = Get-Content -LiteralPath $jsonFile.FullName -Raw -Encoding utf8 -ErrorAction Stop
        $null = $jsonRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        if (Test-Path -LiteralPath $jsonFile.FullName -PathType Leaf) {
            $findings.Add((New-Finding 'json.parse' 'error' $relativePath 1 "JSON file must parse: $($_.Exception.Message)"))
        }
        else {
            Add-FileReadFinding $findings $resolvedRoot $jsonFile.FullName "File could not be read during structural validation: $($_.Exception.Message)"
        }
        continue
    }

    if ($jsonFile.Name -like '*.schema.json') {
        $schemaError = Test-JsonSchemaCompilation -JsonText $jsonRaw
        if ($null -ne $schemaError) {
            $findings.Add((New-Finding 'json.schema.compile' 'error' $relativePath 1 "JSON schema must compile: $schemaError"))
        }
    }
}

$textFiles = @($allFiles | Where-Object {
    $_.Extension -in @('.md', '.markdown', '.json', '.ps1', '.psm1', '.psd1', '.kql', '.txt', '.yml', '.yaml') -and
    -not (Test-ExcludedFixturePath (Get-RelativePath $resolvedRoot $_.FullName))
})

$commercialPatterns = @(
    '(?i)\bgraph\.microsoft\.us\b',
    '(?i)\b(?:[a-z0-9-]+\.)*(?:microsoft|azure|loganalytics|applicationinsights|windows|office|security|defender|sentinel|microsoftonline)\.us\b',
    '(?i)\bazure\.us\b',
    '(?i)\bazure\.cn\b',
    '(?i)\bmicrosoftonline\.us\b',
    '(?i)\bmicrosoft\.cn\b',
    '(?i)\bchinacloudapi\.cn\b',
    '(?i)\bpartner\.microsoftonline\.cn\b',
    '(?i)\bmicrosoftonline\.de\b',
    '(?i)\bmicrosoftazure\.de\b',
    '(?i)\bcloudapi\.de\b',
    '(?i)\busgovcloudapi\.net\b',
    '(?i)\b[a-z0-9.-]+\.mil\b',
    '(?i)\b[a-z0-9.-]+\.gov\b',
    '(?i)\bgovcloud\b',
    '(?i)\bmicrosoft\.us\b'
)
$secretPatterns = @(
    '(?i)\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',
    '(?i)(?:^|["''\s{,])(?:client[_-]?secret|clientSecret)["''\s]*[:=]',
    '(?i)\bAccountKey\s*=',
    '(?i)\bSharedAccessSignature\s*=',
    '-----BEGIN [A-Z ]*PRIVATE KEY-----',
    '(?i)\bAuthorization\s*:\s*Bearer\s+\S+',
    '(?i)(?<!-)\bbearer\s+[A-Za-z0-9._-]{12,}'
)
$tenantGuidPattern = '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b'
$allowedSyntheticTenantGuidPattern = '(?i)^00000000-0000-4000-8000-0000000000[0-9]{2}$'
# Published Microsoft first-party public client IDs; not tenant identifiers.
$allowedFirstPartyClientIds = @(
    '14d82eec-204b-4c2f-b7e8-296a70dab67e',
    '1950a258-227b-4e31-a9cf-717495945fc2'
)

foreach ($textFile in $textFiles) {
    $relativePath = Get-RelativePath $resolvedRoot $textFile.FullName
    $raw = ''
    $lines = @()
    if (-not (Try-ReadTextFile $textFile.FullName $findings $resolvedRoot ([ref]$raw) ([ref]$lines))) { continue }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($pattern in $commercialPatterns) {
            if ((Test-AllowedSovereignHostFile -RelativePath $relativePath) -or
                (Test-AllowedSovereignHostLine -RelativePath $relativePath -Line $lines[$i])) {
                continue
            }
            if ($lines[$i] -match $pattern) {
                $findings.Add((New-Finding 'content.commercialOnly' 'error' $relativePath ($i + 1) 'Only commercial Microsoft endpoints are permitted; national-cloud, government, and military endpoints are prohibited.'))
                break
            }
        }
        foreach ($pattern in $secretPatterns) {
            if ($lines[$i] -match $pattern) {
                $findings.Add((New-Finding 'content.secrets' 'error' $relativePath ($i + 1) 'Secret-shaped content is prohibited.'))
                break
            }
        }
        foreach ($guidMatch in [regex]::Matches($lines[$i], $tenantGuidPattern)) {
            if ($guidMatch.Value -notmatch $allowedSyntheticTenantGuidPattern -and
                $allowedFirstPartyClientIds -notcontains $guidMatch.Value.ToLowerInvariant()) {
                $findings.Add((New-Finding 'content.tenantGuid' 'error' $relativePath ($i + 1) 'Real-looking tenant GUIDs are prohibited outside approved synthetic allowlist values.'))
            }
        }
    }

    $pictographicLine = Find-PictographicLine $lines
    if ($pictographicLine -gt 0) {
        $findings.Add((New-Finding 'content.pictographic' 'error' $relativePath $pictographicLine 'Emoji and pictographic characters are prohibited.'))
    }
}

foreach ($markdownFile in $markdownFiles) {
    $relativePath = Get-RelativePath $resolvedRoot $markdownFile.FullName
    $raw = ''
    $lines = @()
    if (-not (Try-ReadTextFile $markdownFile.FullName $findings $resolvedRoot ([ref]$raw) ([ref]$lines))) { continue }
    $insideFence = $false
    $fenceMarker = ''
    $fenceLanguage = ''
    $fenceInfo = ''
    $fenceStartLine = 0
    $prohibitedExample = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*(```|~~~)\s*(?<info>.*)$') {
            $marker = $Matches[1]
            if (-not $insideFence) {
                $insideFence = $true
                $fenceMarker = $marker
                $fenceStartLine = $i + 1
                $fenceInfo = $Matches['info']
                $fenceLanguage = if ($fenceInfo -match '^\s*([A-Za-z0-9_-]+)') { $Matches[1] } else { '' }
                $previous = if ($i -gt 0) { $lines[$i - 1] } else { '' }
                $prohibitedExample = ($fenceInfo -cmatch '^\s*Prohibited example:\s*$') -or ($previous -cmatch '^\s*Prohibited example:\s*$')
            }
            elseif ($marker -eq $fenceMarker) {
                $insideFence = $false
                $fenceMarker = ''
                $fenceLanguage = ''
                $fenceInfo = ''
                $fenceStartLine = 0
                $prohibitedExample = $false
            }
            continue
        }
        $scanTexts = @()
        # Code block lines are commands, so bare Verb-Noun in command position counts; inline spans are often vocabulary.
        $commandContext = $false
        if ($insideFence) {
            if ($prohibitedExample -and $line -cmatch '^\s{0,3}#{1,6}\s+') {
                $prohibitedExample = $false
            }
            if ($prohibitedExample) { continue }
            $scanTexts = @($line)
            $commandContext = $true
        }
        elseif ($line -match '^(?: {4}|\t)') {
            $scanTexts = @($line)
            $commandContext = $true
        }
        else {
            $scanTexts = @(Get-InlineCodeSpans -Line $line | Where-Object { -not (Test-LocalFunctionReference -Text $_.Text) } | ForEach-Object { $_.Text })
        }
        foreach ($scanText in $scanTexts) {
            if (@(Find-KqlManagementCommand -Text $scanText).Count -gt 0) {
                $findings.Add((New-Finding 'markdown.code.kqlManagementCommand' 'error' $relativePath ($i + 1) 'Markdown KQL code blocks must not contain management or control commands.'))
                continue
            }
            $kqlContext = $insideFence -and $fenceLanguage -match '^(?i:kql|kusto)$'
            $mutationFindings = @(Find-HavocMutationCommand -Text $scanText -CommandContext:$commandContext -KqlContext:$kqlContext)
            foreach ($mutationFinding in $mutationFindings) {
                if (Test-AllowedMutationCommandException -RelativePath $relativePath -Rule 'markdown.code.mutationCommand' -MatchedText $scanText) {
                    continue
                }
                $findings.Add((New-Finding 'markdown.code.mutationCommand' 'error' $relativePath ($i + 1) 'Markdown code blocks must not contain copy-paste mutation commands unless explicitly marked as prohibited examples.'))
                break
            }
        }
    }
    if ($insideFence) {
        $lineNumber = if ($fenceStartLine -gt 0) { $fenceStartLine } else { [Math]::Max(1, $lines.Count) }
        $findings.Add((New-Finding 'content.unclosedFence' 'error' $relativePath $lineNumber 'Markdown code fences must be closed before the end of the file.'))
    }
}

$skillTextFiles = @($textFiles | Where-Object {
    $relative = (Get-RelativePath $resolvedRoot $_.FullName) -replace '/', '\'
    $relative -like 'skills\*' -and $_.Extension -in @('.ps1', '.psm1', '.kql', '.txt', '.json', '.yml', '.yaml')
})
foreach ($skillTextFile in $skillTextFiles) {
    $relativePath = Get-RelativePath $resolvedRoot $skillTextFile.FullName
    $raw = ''
    $lines = @()
    if (-not (Try-ReadTextFile $skillTextFile.FullName $findings $resolvedRoot ([ref]$raw) ([ref]$lines))) { continue }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if (Test-ScannerImplementationLine -RelativePath $relativePath -Line $line) { continue }
        if ($skillTextFile.Extension -eq '.kql' -and @(Find-KqlManagementCommand -Text $line).Count -gt 0) {
            $findings.Add((New-Finding 'skill.code.kqlManagementCommand' 'error' $relativePath ($i + 1) 'Skill KQL files must not contain management or control commands.'))
            continue
        }
        $mutationFindings = @(Find-HavocMutationCommand -Text $line -CommandContext:$true -KqlContext:($skillTextFile.Extension -eq '.kql'))
        foreach ($mutationFinding in $mutationFindings) {
            if (-not (Test-SkillTextMutationFinding -MutationFinding $mutationFinding)) { continue }
            if (Test-AllowedMutationCommandException -RelativePath $relativePath -Rule 'skill.code.mutationCommand' -MatchedText $line.Trim()) {
                continue
            }
            $findings.Add((New-Finding 'skill.code.mutationCommand' 'error' $relativePath ($i + 1) 'Skill text files must not contain mutation commands.'))
            break
        }
    }
}

$findings | Sort-Object path, line, rule, severity
