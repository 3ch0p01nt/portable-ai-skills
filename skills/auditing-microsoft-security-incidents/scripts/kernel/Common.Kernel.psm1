Set-StrictMode -Version Latest

$script:ProtectedReferencePattern = '^(?:protected(?:-link|-request|-evidence)?|not-applicable):(?!(?:[a-z0-9._/-]*[./])?(?:bearer|token|secret|password|credential|apikey|api-key|authorization|access_token|access-token)(?:[./]|$))[a-z0-9][a-z0-9._/-]*$'
$script:Rfc3339Pattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$'
$script:Rfc3339Formats = [string[]]@(
    "yyyy-MM-dd'T'HH:mm:ssK",
    "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"
)

# Mutating verbs are matched case-sensitively as Verb-Noun so prose such as "add-on" is not flagged.
# Native Windows and Defender endpoint tools that change host state. The default rule is anchored to command position
# (line or list start, separators, prompts, paths, start "", cmd /c) so KQL string literals, table rows, and prose about
# attacker activity are not flagged; the CommandContext rule below matches the same tools anywhere on a code line.
$script:NativeMutationBody = '(?:reg(?:\.exe)?\s+(?:delete|add|import|restore|load|unload|copy)\b|wevtutil(?:\.exe)?\s+(?:cl|clear-log|sl|set-log|um|uninstall-manifest)\b|vssadmin(?:\.exe)?\s+(?:delete|resize)\b|netsh(?:\.exe)?\s+(?:\S+\s+){0,3}?(?:set|add|delete|reset)\b|sc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:stop|delete|config|create|failure|pause|sdset)\b|schtasks(?:\.exe)?\s+/(?:delete|create|change|run|end)\b|taskkill(?:\.exe)?\s+/|bcdedit(?:\.exe)?\s+/(?:set|delete|deletevalue|import)\b|net(?:\.exe)?\s+(?:user|localgroup|group)\b[^\r\n]*?/(?:add|delete|active)\b|net(?:\.exe)?\s+stop\b|mdatp\s+(?:config|threat|exclusion|uninstall)\b[^\r\n]*?(?:--value|--add|--remove|remove|add|disabled|quarantine|restore)\b|(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s-(?:e|ec|en|enc|enco|encod|encodedcommand)\s|(?:del|erase)(?:\.exe)?\s+(?:/[a-z]\s+)*/[fqs]\b|(?:rd|rmdir)\s+(?:/[a-z]\s+)*/s\b|wmic(?:\.exe)?\b[^\r\n]*?\b(?:call\s+(?:terminate|delete|create|setpowerstate|uninstall)|delete)\b|icacls(?:\.exe)?\b[^\r\n]*?\s/(?:grant|deny|remove|reset|setowner|setintegritylevel)\b|attrib(?:\.exe)?\s+[+-][rhsai]\b|takeown(?:\.exe)?\s+/f\b|shutdown(?:\.exe)?\s+/[rsfpgh]\b|fsutil(?:\.exe)?\s+(?:usn\s+deletejournal|file\s+setzerodata|reparsepoint\s+delete|behavior\s+set)\b|cipher(?:\.exe)?\s+/w\b|regedit(?:\.exe)?\s+/s\b|rundll32(?:\.exe)?\s+advpack(?:\.dll)?\s*,\s*(?:DelNode|LaunchINFSection|RegisterOCX)|mpcmdrun(?:\.exe)?\b[^\r\n]*?\s-(?:RemoveDefinitions|DisableService|RestoreDefaults)\b|bitsadmin(?:\.exe)?\s+/(?:transfer|create|addfile|setnotifycmdline|resume|complete)\b|certutil(?:\.exe)?\b[^\r\n]*?\s-(?:urlcache|decode|decodehex|addstore|delstore|delkey)\b|(?:del|erase)(?:\.exe)?\s+(?:/[a-z]\s+)*(?:[a-z]:\\|\\\\|\.{1,2}\\|%\w+%)|rm\s+(?:-[a-z]+\s+)+\S|rm\s+[/~]|ri\s+(?:[a-z]:\\|\.{1,2}[\\/]|~|/|\$)|kill\s+(?:-\w+\s+)*\d+\b|(?:pkill|killall)\s+\S|systemctl\s+(?:stop|disable|mask|kill)\b|net1(?:\.exe)?\s+(?:stop|user|localgroup|group)\b|Invoke-(?:Cim|Wmi)Method\b[^\r\n]*?\b(?:Terminate|Delete|Uninstall)\b|(?<=\|[ \t]*)(?:kill|spps|rm|ri|del|erase|rmdir|rd)(?=[ \t]*(?:$|[;|&]|\s-))|move(?:\.exe)?\s+/y\b|find\b[^\r\n]*?\s-delete\b)'
$script:KqlLauncherTokenPattern = '(?i)(?:(?<![\w-])(?:cmd|command|powershell|pwsh|iex|Invoke-Expression|%ComSpec%|start|runas|forfiles|wmic|rundll32|regsvr32|mshta|cscript|wscript|bash|sh|zsh|sudo)(?:\.exe)?|"")\s*(?:[/-]\w|""|\()'
$script:KqlNamedLauncherPattern = '(?i)(?<![\w-])(?:cmd|command|powershell|pwsh|iex|Invoke-Expression|%ComSpec%|start|runas|forfiles|wmic|rundll32|regsvr32|mshta|cscript|wscript|bash|sh|zsh|sudo)(?:\.exe)?\s*(?:[/-]\w|""|\()'
$script:KqlShellLinePattern = '(?i)^\s*(?:[&.]\s*)?(?:"?[a-z]:\\[^"\r\n]*\\)?(?:cmd|command|powershell|pwsh|start|runas|forfiles|wmic|rundll32|regsvr32|mshta|cscript|wscript|bash|sh|zsh|sudo|reg|regedit|sc|net1?|netsh|schtasks|taskkill|vssadmin|wevtutil|bcdedit|del|erase|rd|rmdir|rm|ri|kill|pkill|killall|systemctl|certutil|bitsadmin|mpcmdrun|fsutil|cipher|icacls|takeown|attrib|shutdown|mdatp|move)(?:\.exe)?"?(?=\s|$)'
$script:NativeMutationAnchor = '(?m)(?:^[ \t]*(?:(?:[-*+]|\d+[.)])[ \t]+)?|;|\|\|?|&&?|\{|\$?\(|`)[ \t]*(?:(?:[A-Za-z]:\\[^>\r\n]*|PS\s[^>\r\n]*)>[ \t]*)?(?:start[ \t]+(?:""[ \t]+)?)?(?:[&.][ \t]*)?(?:cmd(?:\.exe)?(?:[ \t]+/[a-z])*?[ \t]+/[ck][ \t]+)?(?:[A-Za-z]:\\(?:[^\\\s]+\\)*)?'
$script:MutationPatterns = @(
    @{ id = 'powershell_mutating_verb'; caseSensitive = $true; pattern = '\b(?:New|Set|Remove|Update|Add|Revoke|Disable|Enable|Reset|Stop|Start|Restart|Suspend|Resume|Block|Unblock|Grant|Deny|Clear|Move|Rename|Register|Unregister|Install|Uninstall|Publish|Confirm|Approve|Submit|Send|Lock|Unlock|Restore|Undo|Redo|Merge|Split|Close|Dismiss|Resolve)-[A-Z][A-Za-z0-9]+' },
    # PowerShell cmdlet names are case-insensitive. Non-canonical casing is flagged only with nearby command syntax
    # (a -Parameter, a pipe into another cmdlet, a semicolon) that is not separated by a code-span or placeholder delimiter,
    # Bare tokens such as `split-incident` and placeholders such as <start-utc> are not flagged; PascalCase is always flagged.
    @{ id = 'powershell_mutating_verb_any_case'; caseSensitive = $false; pattern = '(?m)(?<![<\w-])(?:New|Set|Remove|Update|Add|Revoke|Disable|Enable|Reset|Stop|Start|Restart|Suspend|Resume|Block|Unblock|Grant|Deny|Clear|Move|Rename|Register|Unregister|Install|Uninstall|Publish|Confirm|Approve|Submit|Send|Lock|Unlock|Restore|Undo|Redo|Merge|Split|Close|Dismiss|Resolve)-[a-z][a-z0-9]{2,}\b(?!>)(?=[^\r\n`<>]*?(?:\s-[a-z]|\|\s*[a-z]+-[a-z]|;))' },
    # A pipe before the token is command syntax, covering mutating cmdlets as the final pipeline stage.
    @{ id = 'powershell_mutating_verb_after_pipe'; caseSensitive = $false; pattern = '\|[ \t]*(?:New|Set|Remove|Update|Add|Revoke|Disable|Enable|Reset|Stop|Start|Restart|Suspend|Resume|Block|Unblock|Grant|Deny|Clear|Move|Rename|Register|Unregister|Install|Uninstall|Publish|Confirm|Approve|Submit|Send|Lock|Unlock|Restore|Undo|Redo|Merge|Split|Close|Dismiss|Resolve)-[a-z][a-z0-9]{2,}\b(?![-.])' },
    @{ id = 'graph_mutating_action_cmdlet'; caseSensitive = $false; pattern = '\bInvoke-Mg(?:Dismiss|Confirm|Revoke|Reset|Restore|Block|Unblock|Invalidate|Retire|Wipe|Remote|Reprocess|Assign|Activate|Deactivate|Reprovision|Rotate|Renew|Cancel|Retry|Run|Start|Stop|Restart|Sync|Delete|Remove|Update|Set|Add|Create|Grant|Unlock|Lock|Clean|Reboot|Shutdown|Recover|Quarantine|Unquarantine|Isolate|Unisolate|Submit|Send|Forward|Reply|Move|Copy)[A-Za-z0-9]*\b' },
    @{ id = 'http_method_parameter'; caseSensitive = $false; pattern = '(?:^|\s)--?method(?::|=|\s+)[''"]?(?:Post|Put|Patch|Delete|Merge)\b' },
    @{ id = 'az_rest_short_method'; caseSensitive = $false; pattern = '\baz\s+rest\b[^\r\n]*?\s-m(?:=|\s+)[''"]?(?:post|put|patch|delete)\b' },
    # az rest defaults to POST when a body is supplied without an explicit read method.
    @{ id = 'az_rest_body'; caseSensitive = $false; pattern = '\baz\s+rest\b(?![^\r\n]*?(?:--method|\s-m)(?:=|\s+)[''"]?(?:get|head)\b)[^\r\n]*?\s(?:--body|-b)(?:=|\s+)' },
    @{ id = 'curl_mutating_method'; caseSensitive = $false; pattern = '\bcurl\b[^\r\n]*?(?:\s-X\s*|\s--request(?:=|\s+))[''"]?(?:POST|PUT|PATCH|DELETE)\b' },
    @{ id = 'az_cli_mutating_verb'; caseSensitive = $false; pattern = '\baz(?:\s+[a-z][a-z0-9-]*){1,6}?\s+(?:create|update|delete|set|reset|stop|start|restart|revoke|remove|add|assign|deallocate|disable|enable|purge|import|redeploy|rotate|renew|close|dismiss)\b' },
    @{ id = 'raw_http_mutation'; caseSensitive = $true; pattern = '(?m)^\s*(?:(?:[-*+]|\d+[.)])\s+)?(?:POST|PUT|PATCH|DELETE|MERGE)\s+(?:https?://|/)' },
    @{ id = 'windows_native_mutation'; caseSensitive = $false; pattern = ($script:NativeMutationAnchor + $script:NativeMutationBody) }
)

# Command-context rule: text that is itself a command (recommendations, code block lines) is executable even without
# parameters, so any-case Verb-Noun in command position (line start or list item, after & . ( ; | && or any { or backtick) is flagged.
$script:CommandContextPatterns = @(
    @{ id = 'powershell_mutating_verb_command_position'; caseSensitive = $false; pattern = '(?m)(?:^[ \t]*(?:(?:[-*+]|\d+[.)])[ \t]+)?|;|\||&&|\{|`)[ \t]*(?:[&.{(][ \t]*)*(?:New|Set|Remove|Update|Add|Revoke|Disable|Enable|Reset|Stop|Start|Restart|Suspend|Resume|Block|Unblock|Grant|Deny|Clear|Move|Rename|Register|Unregister|Install|Uninstall|Publish|Confirm|Approve|Submit|Send|Lock|Unlock|Restore|Undo|Redo|Merge|Split|Close|Dismiss|Resolve)-[a-z][a-z0-9]{2,}\b(?![-.])' },
    @{ id = 'windows_native_mutation_code_line'; caseSensitive = $false; stripQuotes = $true; pattern = ('(?<![\w-])' + $script:NativeMutationBody) }
)

function Get-HavocProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-HavocArray {
    [CmdletBinding()]
    [OutputType([object[]])]
    param([AllowNull()][object]$Value)
    $items = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Value) {
        $source = if ($Value -is [string] -or $Value -is [System.Collections.IDictionary] -or $Value -isnot [System.Collections.IEnumerable]) { @($Value) } else { $Value }
        foreach ($item in $source) {
            if ($null -eq $item) { continue }
            if ($item -is [string] -and [string]::IsNullOrWhiteSpace($item)) { continue }
            $items.Add($item)
        }
    }
    # Callers must wrap with @() to obtain an array; empty input emits nothing.
    return $items.ToArray()
}

function ConvertTo-HavocUtcTimestamp {
    [CmdletBinding()]
    [OutputType([datetimeoffset])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][object]$Value)
    if ($null -eq $Value) { throw 'Timestamp is required.' }
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetime]) {
        if ($Value.Kind -ne [System.DateTimeKind]::Utc) {
            throw 'Timestamp DateTime values must be UTC; an explicit offset is required for local or unspecified times.'
        }
        return [datetimeoffset]::new($Value)
    }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'Timestamp is required.' }
    if ($text -cnotmatch $script:Rfc3339Pattern) {
        throw 'Timestamp must be RFC 3339 with an explicit offset (Z or +/-hh:mm).'
    }
    $parsed = [datetimeoffset]::MinValue
    $ok = [datetimeoffset]::TryParseExact(
        $text,
        $script:Rfc3339Formats,
        [cultureinfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None,
        [ref]$parsed)
    if (-not $ok) { throw 'Timestamp must be RFC 3339 with an explicit offset (Z or +/-hh:mm).' }
    return $parsed.ToUniversalTime()
}

function Format-HavocTimestamp {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][datetimeoffset]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", [cultureinfo]::InvariantCulture)
}

function Get-HavocProtectedReferencePattern {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:ProtectedReferencePattern
}

function Test-HavocProtectedReference {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][object]$Value)
    if ($Value -isnot [string] -or [string]::IsNullOrEmpty($Value)) { return $false }
    return [bool]($Value -cmatch $script:ProtectedReferencePattern)
}

function Find-HavocMutationCommand {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [switch]$CommandContext, [switch]$KqlContext)
    if ([string]::IsNullOrEmpty($Text)) { return }
    # Caret escapes and Unicode spaces are shell no-ops that would otherwise split tool names or defeat anchors.
    $normalized = ($Text -replace '\^', '') -replace '[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]', ' '
    if ($KqlContext) {
        # KQL string literals and // comments describe searched-for text, not commands this line would run.
        # Lines whose first token is a shell launcher or native tool are commands, not KQL, so their quoted arguments stay visible.
        $kqlLines = foreach ($kqlLine in ($normalized -split '\r?\n')) {
            if ($kqlLine -match $script:KqlShellLinePattern) { $kqlLine; continue }
            $blankedLine = [regex]::Replace($kqlLine, '@"[^"\r\n]*"|@''[^''\r\n]*''|"(?:[^"\\\r\n]|\\.)*"|''(?:[^''\\\r\n]|\\.)*''', '""')
            $blankedLine = [regex]::Replace($blankedLine, '//.*$', '')
            # A launcher that survives blanking (after a prompt, separator, variable, or parenthesis) marks a command line.
            # On plain parse lines, adjacent blanked literals are normal syntax, so only a named launcher counts there.
            $isPlainParse = $kqlLine -match '^\s*\|\s*parse(?:-where|-kv)?\b' -and $blankedLine -notmatch '^\s*\|[^;|&{`]*[;|&{`]'
            $launcherPattern = if ($isPlainParse) { $script:KqlNamedLauncherPattern } else { $script:KqlLauncherTokenPattern }
            if ($blankedLine -match $launcherPattern) { $kqlLine } else { $blankedLine }
        }
        $normalized = $kqlLines -join "`n"
    }
    $rules = @($script:MutationPatterns)
    if ($CommandContext -or $KqlContext) { $rules += $script:CommandContextPatterns }
    foreach ($rule in $rules) {
        $options = [System.Text.RegularExpressions.RegexOptions]::None
        if (-not $rule.caseSensitive) { $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
        $subject = $normalized
        if ($rule.ContainsKey('stripQuotes') -and $rule['stripQuotes']) { $subject = $subject -replace '["'']', '' }
        $regex = [regex]::new($rule.pattern, $options, [timespan]::FromSeconds(1))
        foreach ($match in $regex.Matches($subject)) {
            [pscustomobject]@{ rule = $rule.id; match = $match.Value.Trim() }
        }
    }
}

function ConvertTo-HavocCanonicalJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        throw 'Canonical JSON requires timestamps as their original RFC 3339 string values.'
    }
    if ($Value -is [string] -or $Value -is [char]) {
        return ([string]$Value | ConvertTo-Json -Compress)
    }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [double] -or $Value -is [single]) {
        return ([double]$Value).ToString('R', [cultureinfo]::InvariantCulture)
    }
    if ($Value -is [decimal] -or $Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte] -or $Value -is [System.Numerics.BigInteger]) {
        return ([System.IFormattable]$Value).ToString($null, [cultureinfo]::InvariantCulture)
    }
    $entries = $null
    if ($Value -is [System.Collections.IDictionary]) {
        $entries = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($key in $Value.Keys) { $entries[[string]$key] = $Value[$key] }
    }
    elseif ($Value -is [System.Management.Automation.PSCustomObject] -or
        ($Value -is [psobject] -and $Value.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject])) {
        $entries = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($property in $Value.PSObject.Properties) { $entries[$property.Name] = $property.Value }
    }
    if ($null -ne $entries) {
        [string[]]$keys = @($entries.Keys)
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $parts = foreach ($key in $keys) {
            ($key | ConvertTo-Json -Compress) + ':' + (ConvertTo-HavocCanonicalJson -Value $entries[$key])
        }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) { ConvertTo-HavocCanonicalJson -Value $item }
        return '[' + (@($parts) -join ',') + ']'
    }
    throw "Unsupported canonical JSON value type: $($Value.GetType().FullName)"
}

function Get-HavocSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return ([System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
}

function Get-HavocStableId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9._-]*$')][string]$Prefix,
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Parts
    )
    $canonical = ConvertTo-HavocCanonicalJson -Value @($Parts | ForEach-Object { [string]$_ })
    return '{0}-{1}' -f $Prefix, (Get-HavocSha256Hex -Text $canonical).Substring(0, 24)
}

Export-ModuleMember -Function Get-HavocProperty, Get-HavocArray, ConvertTo-HavocUtcTimestamp, Format-HavocTimestamp,
    Get-HavocProtectedReferencePattern, Test-HavocProtectedReference, Find-HavocMutationCommand,
    ConvertTo-HavocCanonicalJson, Get-HavocSha256Hex, Get-HavocStableId
