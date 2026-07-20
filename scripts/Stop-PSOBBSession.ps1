[CmdletBinding()]
param(
    [ValidateSet('All', 'Client', 'Server')]
    [string]$Target = 'All',
    [ValidateSet('Stable', 'CombatCanary')]
    [string]$ServerEnvironment = 'Stable',
    [string]$RuntimeRoot,
    [switch]$ForceClient,
    [switch]$ForceServer,
    [ValidateRange(1, 120)][int]$ClientShutdownTimeoutSeconds = 20,
    [ValidateRange(5, 120)][int]$ServerShutdownTimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$environmentWasExplicit = $PSBoundParameters.ContainsKey('ServerEnvironment')
$requestedEnvironmentName = Resolve-PSOBBServerEnvironmentName `
    -Environment $ServerEnvironment
$clientResult = $null
$serverResult = $null
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
$namedClients = @(Get-PSOBBAllClientProcessRecords -Layout $layout)
$serverCensus = @(Get-PSOBBServerEnvironmentProcessRecords -Layout $layout)
if (@($namedClients | Where-Object {
            [string]$_.Classification -cne 'ApprovedExactPath' -or
            [string]$_.ServerEnvironment -notin @('Stable', 'CombatCanary')
        }).Count -gt 0 -or
    @($serverCensus | Where-Object {
            [string]$_.Classification -cne 'ApprovedExactPath' -or
            [string]$_.ServerEnvironment -notin @('Stable', 'CombatCanary')
        }).Count -gt 0) {
    throw 'The global client/server census contains an unknown or uninspectable PSOBB process; no PID action was attempted'
}
$clientEnvironments = @($namedClients.ServerEnvironment | Sort-Object -Unique)
$serverEnvironments = @($serverCensus.ServerEnvironment | Sort-Object -Unique)
if ($clientEnvironments.Count -gt 1 -or $serverEnvironments.Count -gt 1 -or
    ($clientEnvironments.Count -eq 1 -and $serverEnvironments.Count -eq 1 -and
        [string]$clientEnvironments[0] -cne [string]$serverEnvironments[0])) {
    throw 'The global client/server census is ambiguous or crosses server environments'
}
$activeEnvironment = if ($clientEnvironments.Count -eq 1) {
    [string]$clientEnvironments[0]
} elseif ($serverEnvironments.Count -eq 1) {
    [string]$serverEnvironments[0]
} else {
    $null
}
if ($environmentWasExplicit -and $activeEnvironment -and
    $activeEnvironment -cne $requestedEnvironmentName) {
    throw "The active PSOBB environment is $activeEnvironment, not explicitly selected $requestedEnvironmentName"
}
$serverEnvironmentName = if ($environmentWasExplicit) {
    $requestedEnvironmentName
} elseif ($activeEnvironment) {
    $activeEnvironment
} else {
    'Stable'
}
$serverLayout = Get-PSOBBServerEnvironmentLayout `
    -Layout $layout -Environment $serverEnvironmentName

if ($Target -in @('All', 'Client')) {
    $clientParameters = @{
        Channel = 'All'
        ServerEnvironment = $serverEnvironmentName
        RuntimeRoot = $layout.Root
        ShutdownTimeoutSeconds = $ClientShutdownTimeoutSeconds
        ClientOperationLockHeld = $true
    }
    if ($ForceClient) {
        $clientParameters.Force = $true
    }
    $clientResult = & (Join-Path $PSScriptRoot 'Stop-PSOBBClient.ps1') @clientParameters
}

if ($Target -in @('All', 'Server')) {
    $serverParameters = @{
        RuntimeRoot = $layout.Root
        ServerEnvironment = $serverEnvironmentName
        ShutdownTimeoutSeconds = $ServerShutdownTimeoutSeconds
        ClientOperationLockHeld = $true
    }
    if ($ForceServer) {
        $serverParameters.Force = $true
    }
    $serverResult = & (Join-Path $PSScriptRoot 'Stop-PSOBB.ps1') @serverParameters
    if ($serverResult -and $serverResult.PSObject.Properties['ServerEnvironment']) {
        $serverEnvironmentName = [string]$serverResult.ServerEnvironment
        $serverLayout = Get-PSOBBServerEnvironmentLayout `
            -Layout $layout -Environment $serverEnvironmentName
    }
}

[pscustomobject]@{
    Target = $Target
    ServerEnvironment = $serverEnvironmentName
    EnvironmentId = $serverLayout.EnvironmentId
    ClientStopped = if ($clientResult) { [bool]$clientResult.Stopped } else { $null }
    ClientReason = if ($clientResult -and $clientResult.PSObject.Properties['Reason']) {
        [string]$clientResult.Reason
    } else {
        $null
    }
    ClientForcedCount = if ($clientResult) { [int]$clientResult.ForcedCount } else { $null }
    ServerStopped = if ($serverResult) { [bool]$serverResult.Stopped } else { $null }
    ServerReason = if ($serverResult -and $serverResult.PSObject.Properties['Reason']) {
        [string]$serverResult.Reason
    } else {
        $null
    }
    ServerForced = if ($serverResult -and $serverResult.PSObject.Properties['Forced']) {
        [bool]$serverResult.Forced
    } else {
        $null
    }
}
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
