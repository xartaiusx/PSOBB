[CmdletBinding()]
param(
    [ValidateSet('Stable', 'Canary', 'LocalLab', 'Native')]
    [string]$Channel,
    [ValidateSet('Stable', 'CombatCanary')]
    [string]$ServerEnvironment = 'Stable',
    [ValidateSet('ProfileDefault', 'Borderless', 'Resizable')]
    [string]$WindowMode = 'Borderless',
    [switch]$PreserveForeground,
    [string]$RuntimeRoot,
    [ValidateRange(5, 120)][int]$StartupTimeoutSeconds = 45,
    [ValidateRange(5, 300)][int]$VerificationTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Wait-PSOBBServerReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [ValidateRange(1, 120)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $process = Get-NewservProcess -Layout $Layout
        if ($process) {
            if (Test-PSOBBExactLoopbackServerListeners -ProcessId $process.Id) {
                return $process
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "newserv did not reach the exact approved loopback listener set within $TimeoutSeconds seconds"
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$serverEnvironmentName = Resolve-PSOBBServerEnvironmentName `
    -Environment $ServerEnvironment
$serverLayout = Get-PSOBBServerEnvironmentLayout `
    -Layout $layout -Environment $serverEnvironmentName
$resolvedChannel = Resolve-PSOBBClientChannelForServerEnvironment `
    -ServerEnvironment $serverEnvironmentName `
    -Channel $Channel `
    -DefaultStableChannel Canary
$resolvedWindowMode = if ($PSBoundParameters.ContainsKey('WindowMode')) {
    $WindowMode
} elseif ($serverEnvironmentName -ceq 'CombatCanary') {
    'ProfileDefault'
} else {
    'Borderless'
}
$serverStartedBySession = $false
$serverStartResult = $null
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    $runningClients = @(Get-PSOBBAllClientProcessRecords -Layout $layout)
    if ($runningClients.Count -gt 0) {
        throw "An approved PSOBB client is already running (PID(s): $($runningClients.ProcessId -join ', '))"
    }
    $serverProcess = Get-NewservProcess -Layout $serverLayout
    if (-not $serverProcess) {
        $serverStartResult = & (Join-Path $PSScriptRoot 'Start-PSOBB.ps1') `
            -RuntimeRoot $layout.Root `
            -ServerEnvironment $serverEnvironmentName `
            -ClientOperationLockHeld `
            -StartupTimeoutSeconds $StartupTimeoutSeconds `
            -VerificationTimeoutSeconds $VerificationTimeoutSeconds
        $serverStartedBySession = $true
    }

    $serverProcess = Wait-PSOBBServerReady `
        -Layout $serverLayout `
        -TimeoutSeconds $StartupTimeoutSeconds
    if ($serverEnvironmentName -ceq 'Stable') {
        & (Join-Path $PSScriptRoot 'Test-PSOBB.ps1') `
            -Suite Baseline `
            -RuntimeRoot $layout.Root | Out-Null
    }

    $clientResult = & (Join-Path $PSScriptRoot 'Start-PSOBBClient.ps1') `
        -Channel $resolvedChannel `
        -ServerEnvironment $serverEnvironmentName `
        -WindowMode $resolvedWindowMode `
        -PreserveForeground:$PreserveForeground `
        -RuntimeRoot $layout.Root `
        -ClientOperationLockHeld

    [pscustomobject]@{
        Started = $true
        RuntimeRoot = $layout.Root
        ServerEnvironment = $serverEnvironmentName
        EnvironmentId = $serverLayout.EnvironmentId
        ServerStartedBySession = $serverStartedBySession
        ServerPid = $serverProcess.Id
        ServerHostPid = if ($serverStartResult) { $serverStartResult.HostPid } else { $null }
        ClientChannel = $clientResult.Channel
        ClientPid = $clientResult.Pid
        PreserveForeground = [bool]$clientResult.PreserveForeground
        ForegroundPreserved = [bool]$clientResult.ForegroundPreserved
        ForegroundStatus = [string]$clientResult.ForegroundStatus
        ClientStartupElapsedMilliseconds = $clientResult.StartupElapsedMilliseconds
        ClientStartupReceiptPath = $clientResult.StartupReceiptPath
        ClientStartupReceiptSha256 = $clientResult.StartupReceiptSha256
        WindowMode = $clientResult.WindowMode
        Borderless = $clientResult.Borderless
        WindowWidth = $clientResult.WindowWidth
        WindowHeight = $clientResult.WindowHeight
    }
} catch {
    if ($serverStartedBySession) {
        try {
            & (Join-Path $PSScriptRoot 'Stop-PSOBB.ps1') `
                -RuntimeRoot $layout.Root `
                -ServerEnvironment $serverEnvironmentName `
                -ClientOperationLockHeld | Out-Null
        } catch {
            Write-Warning 'Session startup failed and the server also failed to stop cleanly.'
        }
    }
    throw
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
