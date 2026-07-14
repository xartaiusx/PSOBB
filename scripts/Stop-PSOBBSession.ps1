[CmdletBinding()]
param(
    [ValidateSet('All', 'Client', 'Server')]
    [string]$Target = 'All',
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
$clientResult = $null
$serverResult = $null
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {

if ($Target -in @('All', 'Client')) {
    $clientParameters = @{
        Channel = 'All'
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
        ShutdownTimeoutSeconds = $ServerShutdownTimeoutSeconds
        ClientOperationLockHeld = $true
    }
    if ($ForceServer) {
        $serverParameters.Force = $true
    }
    $serverResult = & (Join-Path $PSScriptRoot 'Stop-PSOBB.ps1') @serverParameters
}

[pscustomobject]@{
    Target = $Target
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
