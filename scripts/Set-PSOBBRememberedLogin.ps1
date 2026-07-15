[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$RuntimeRoot,
    [ValidateSet('Enable', 'Disable')]
    [string]$Mode = 'Enable'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$registryPath = 'HKCU:\Software\SonicTeam\PSOBB'
$enabled = $Mode -ceq 'Enable'
$action = if ($enabled) {
    'enable the native local remembered-login option without reading saved credentials'
} else {
    'disable remembered login and clear the saved username and password'
}
if (-not $PSCmdlet.ShouldProcess($registryPath, $action)) {
    return
}

$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    $running = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel All)
    if ($running.Count -gt 0) {
        throw "An approved PSOBB client is running (PID(s): $($running.ProcessId -join ', ')); close it normally before changing remembered login"
    }
    $state = Set-PSOBBClientRememberedLogin `
        -Enabled $enabled `
        -ClearCredentials:(-not $enabled) `
        -RegistryPath $registryPath
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
[pscustomobject]@{
    RememberLoginEnabled = [bool]$state.RememberLoginEnabled
    RegistryPath = $registryPath
    CredentialsCleared = -not $enabled
    CredentialValuesRead = $false
    NextStep = if ($enabled) {
        'Enter the username and password once in PSOBB; later launches will preserve the native saved login'
    } else {
        'The saved username and password were cleared; future launches require manual entry'
    }
}
