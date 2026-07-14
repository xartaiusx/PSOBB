[CmdletBinding()]
param(
    [ValidateSet('All', 'Stable', 'Canary', 'LocalLab')]
    [string]$Channel = 'All',
    [string]$RuntimeRoot,
    [switch]$Force,
    [ValidateRange(1, 120)][int]$ShutdownTimeoutSeconds = 20,
    [Parameter(DontShow)][switch]$ClientOperationLockHeld
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-RevalidatedPSOBBClientProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)

    $process = Get-Process -Id ([int]$Record.ProcessId) -ErrorAction SilentlyContinue
    if (-not $process) {
        return $null
    }
    try {
        $startTimeUtc = $process.StartTime.ToUniversalTime()
    } catch {
        throw "Cannot verify the creation time for PSOBB client PID $($Record.ProcessId)"
    }
    if ([Math]::Abs(($startTimeUtc - [DateTime]$Record.StartTimeUtc).TotalSeconds) -gt 0.5) {
        throw "PSOBB client PID $($Record.ProcessId) was reused before shutdown; refusing to act"
    }
    if (-not (Test-PSOBBProcessAtExactPath `
        -Process $process `
        -Name 'Psobb' `
        -ExpectedPath ([string]$Record.ExecutablePath))) {
        return $null
    }
    $identity = Assert-PSOBBApprovedClientExecutable -Path ([string]$Record.ExecutablePath)
    if (-not $identity.Sha256.Equals(
        [string]$Record.ExecutableSha256,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The approved PSOBB client identity changed before shutdown for PID $($Record.ProcessId)"
    }
    $process
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$clientOperationMutex = if ($ClientOperationLockHeld) {
    $null
} else {
    Enter-PSOBBClientOperationLock -Layout $layout
}
try {
    $records = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel $Channel)
    if ($records.Count -eq 0) {
        return [pscustomobject]@{
            Stopped = $false
            Reason = 'not-running'
            Channel = $Channel
            GracefulCount = 0
            ForcedCount = 0
        }
    }

    $closeFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($record in $records) {
        $process = Get-RevalidatedPSOBBClientProcess -Record $record
        if (-not $process) {
            continue
        }
        try {
            if (-not $process.CloseMainWindow()) {
                $process.Refresh()
                if (-not $process.HasExited) {
                    $closeFailures.Add("PID $($record.ProcessId) did not accept a normal window-close request")
                }
            }
        } catch {
            $process.Refresh()
            if (-not $process.HasExited) {
                $closeFailures.Add("PID $($record.ProcessId): $($_.Exception.Message)")
            }
        }
    }

    if ($closeFailures.Count -gt 0 -and -not $Force) {
        throw "The PSOBB client could not be asked to close normally. $($closeFailures -join '; ') No forceful termination was attempted; rerun with -Force only after confirming the selected client should be terminated."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($ShutdownTimeoutSeconds)
    do {
        $remaining = @($records | Where-Object {
            $null -ne (Get-Process -Id ([int]$_.ProcessId) -ErrorAction SilentlyContinue)
        })
        if ($remaining.Count -eq 0 -or [DateTime]::UtcNow -ge $deadline) {
            break
        }
        Start-Sleep -Milliseconds 200
    } while ($true)

    $forcedPids = [System.Collections.Generic.List[int]]::new()
    foreach ($record in $remaining) {
        $process = Get-RevalidatedPSOBBClientProcess -Record $record
        if (-not $process) {
            continue
        }
        if (-not $Force) {
            throw "PSOBB client PID $($record.ProcessId) did not close within $ShutdownTimeoutSeconds seconds. No forceful termination was attempted."
        }

        Stop-Process -Id $process.Id -Force
        if (-not $process.WaitForExit(5000)) {
            throw "Forced termination of PSOBB client PID $($record.ProcessId) could not be confirmed"
        }
        $forcedPids.Add([int]$record.ProcessId)
    }

    $stillRunning = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel $Channel)
    if ($stillRunning.Count -gt 0) {
        throw "An approved PSOBB client is still running after shutdown (PID(s): $($stillRunning.ProcessId -join ', '))"
    }
    $allPids = @($records.ProcessId)
    $gracefulPids = @($allPids | Where-Object { -not $forcedPids.Contains([int]$_) })
    [pscustomobject]@{
        Stopped = $true
        Channel = $Channel
        Pids = $allPids
        Graceful = ($forcedPids.Count -eq 0)
        GracefulCount = $gracefulPids.Count
        ForcedCount = $forcedPids.Count
        ForcedPids = @($forcedPids)
    }
} finally {
    if ($clientOperationMutex) {
        Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
    }
}
