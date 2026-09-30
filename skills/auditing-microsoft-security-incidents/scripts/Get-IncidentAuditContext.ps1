[CmdletBinding()]
param(
    [Parameter(Mandatory)][object[]]$Requests,
    $Transport,
    [Parameter(Mandatory)][scriptblock]$ProtectedStore,
    [scriptblock]$AuthContextProvider,
    [scriptblock]$ProvenanceContextProvider,
    [scriptblock]$Sleeper = { param($Seconds) Start-Sleep -Seconds $Seconds },
    [scriptblock]$Clock = { [datetimeoffset]::UtcNow },
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\references\request-policy.json')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReadOnlyAdapter.Common.psm1') -Force

$scripts = @{
    Graph = 'Invoke-ReadOnlyGraphQuery.ps1'
    Arm = 'Invoke-ReadOnlyArmQuery.ps1'
    Log = 'Invoke-ReadOnlyLogQuery.ps1'
    ResourceGraph = 'Invoke-ReadOnlyResourceGraphQuery.ps1'
    Purview = 'Invoke-ReadOnlyPurviewQuery.ps1'
}
$envelopes = [Collections.Generic.List[object]]::new()
foreach ($request in $Requests) {
    $adapterName = [string]$request.Adapter
    if (-not $scripts.ContainsKey($adapterName)) {
        $envelopes.Add(
            (New-HavocUnsupportedEnvelope 'incident-context-router' `
                $adapterName.ToLowerInvariant() $request.Intent $ProtectedStore $Clock `
                "Adapter '$adapterName' is not supported by the approved policy.")
        )
        continue
    }
    $scriptPath = Join-Path $PSScriptRoot $scripts[$adapterName]
    $envelopes.Add(
        (& $scriptPath -Intent $request.Intent -Transport $Transport `
            -ProtectedStore $ProtectedStore -Sleeper $Sleeper -Clock $Clock `
            -PolicyPath $PolicyPath -AuthContextProvider $AuthContextProvider `
            -ProvenanceContextProvider $ProvenanceContextProvider)
    )
}
$states = @($envelopes | ForEach-Object { [string]$_.status })
$overall = if ($states.Count -eq 0) {
    'failed'
}
elseif (@($states | Where-Object { $_ -ceq 'success' }).Count -eq $states.Count) {
    'complete'
}
elseif (@($states | Where-Object { $_ -ceq 'success' }).Count -gt 0) {
    'partial'
}
elseif (@($states | Where-Object { $_ -ceq 'denied' }).Count -eq $states.Count) {
    'blocked'
}
else {
    'failed'
}
[pscustomobject][ordered]@{
    adapter = [pscustomobject][ordered]@{
        id = 'incident-audit-context'
        version = '1.0.0'
        source = 'multi-source-retrieval'
    }
    status = $overall
    envelopes = @($envelopes)
    coverage = @($envelopes | ForEach-Object {
        [pscustomobject][ordered]@{
            source = $_.adapter.source
            status = $_.status
            state = $_.coverage.state
            limitations = @($_.coverage.limitations)
            errors = @($_.errors)
            effectiveWindow = $_.coverage.effectiveWindow
        }
    })
}
