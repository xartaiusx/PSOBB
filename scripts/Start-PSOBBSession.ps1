[CmdletBinding()]
param(
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$Channel = 'Canary',
    [ValidateSet('ProfileDefault', 'Borderless', 'Resizable')]
    [string]$WindowMode = 'Borderless',
    [switch]$PreserveForeground,
    [string]$RuntimeRoot,
    [ValidateRange(5, 120)][int]$StartupTimeoutSeconds = 45
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Wait-PSOBBServerReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [ValidateRange(1, 120)][int]$TimeoutSeconds
    )

    $expected = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $process = Get-NewservProcess -Layout $Layout
        if ($process) {
            $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $process.Id -ErrorAction SilentlyContinue)
            $actual = @($listeners | ForEach-Object {
                '{0}:{1}' -f $_.LocalAddress, $_.LocalPort
            } | Sort-Object -Unique)
            if ($actual.Count -eq $expected.Count -and
                -not (Compare-Object -ReferenceObject $expected -DifferenceObject $actual)) {
                return $process
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "newserv did not reach the exact approved loopback listener set within $TimeoutSeconds seconds"
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$serverStartedBySession = $false
$serverStartResult = $null
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    $runningClients = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel All)
    if ($runningClients.Count -gt 0) {
        throw "An approved PSOBB client is already running (PID(s): $($runningClients.ProcessId -join ', '))"
    }
    $serverProcess = Get-NewservProcess -Layout $layout
    if (-not $serverProcess) {
        $serverStartResult = & (Join-Path $PSScriptRoot 'Start-PSOBB.ps1') `
            -RuntimeRoot $layout.Root `
            -StartupTimeoutSeconds $StartupTimeoutSeconds
        $serverStartedBySession = $true
    }

    $serverProcess = Wait-PSOBBServerReady `
        -Layout $layout `
        -TimeoutSeconds $StartupTimeoutSeconds
    & (Join-Path $PSScriptRoot 'Test-PSOBB.ps1') `
        -Suite Baseline `
        -RuntimeRoot $layout.Root | Out-Null

    $clientResult = & (Join-Path $PSScriptRoot 'Start-PSOBBClient.ps1') `
        -Channel $Channel `
        -WindowMode $WindowMode `
        -PreserveForeground:$PreserveForeground `
        -RuntimeRoot $layout.Root `
        -ClientOperationLockHeld

    [pscustomobject]@{
        Started = $true
        RuntimeRoot = $layout.Root
        ServerStartedBySession = $serverStartedBySession
        ServerPid = $serverProcess.Id
        ServerHostPid = if ($serverStartResult) { $serverStartResult.HostPid } else { $null }
        ClientChannel = $clientResult.Channel
        ClientPid = $clientResult.Pid
        PreserveForeground = [bool]$clientResult.PreserveForeground
        ForegroundPreserved = [bool]$clientResult.ForegroundPreserved
        ForegroundStatus = [string]$clientResult.ForegroundStatus
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
                -ClientOperationLockHeld | Out-Null
        } catch {
            Write-Warning 'Session startup failed and the server also failed to stop cleanly.'
        }
    }
    throw
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
