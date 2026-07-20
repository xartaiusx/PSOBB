[CmdletBinding()]
param(
    [ValidateSet('All', 'Stable', 'Canary', 'LocalLab', 'Native')]
    [string]$Channel = 'All',
    [ValidateSet('Stable', 'CombatCanary')]
    [string]$ServerEnvironment = 'Stable',
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
    $returnProcess = $false
    try {
        $startTimeUtc = $process.StartTime.ToUniversalTime()
        $startTimeFileTimeUtc = [long]$startTimeUtc.ToFileTimeUtc()
        if ($null -eq $Record.StartTimeFileTimeUtc -or
            $startTimeFileTimeUtc -ne [long]$Record.StartTimeFileTimeUtc) {
            throw "PSOBB client PID $($Record.ProcessId) was reused before shutdown; refusing to act"
        }
        if (-not (Test-PSOBBProcessAtExactPath `
            -Process $process `
            -Name 'Psobb' `
            -ExpectedPath ([string]$Record.ExecutablePath))) {
            return $null
        }
        $identity = Assert-PSOBBApprovedClientExecutable `
            -Path ([string]$Record.ExecutablePath)
        if (-not $identity.Sha256.Equals(
            [string]$Record.ExecutableSha256,
            [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "The approved PSOBB client identity changed before shutdown for PID $($Record.ProcessId)"
        }
        $returnProcess = $true
        $process
    } catch {
        throw "Cannot revalidate PSOBB client PID $($Record.ProcessId): $($_.Exception.Message)"
    } finally {
        if (-not $returnProcess) {
            $process.Dispose()
        }
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$serverEnvironmentName = Resolve-PSOBBServerEnvironmentName `
    -Environment $ServerEnvironment
$resolvedChannel = Resolve-PSOBBClientChannelForServerEnvironment `
    -ServerEnvironment $serverEnvironmentName -Channel $Channel -AllowAll
$clientOperationMutex = if ($ClientOperationLockHeld) {
    $null
} else {
    Enter-PSOBBClientOperationLock -Layout $layout
}
try {
    $allNamedRecords = @(Get-PSOBBAllClientProcessRecords -Layout $layout)
    $records = @(Get-PSOBBClientProcessRecords `
        -Layout $layout `
        -Channel $resolvedChannel `
        -ServerEnvironment $serverEnvironmentName)
    if ($records.Count -eq 0) {
        if ($allNamedRecords.Count -gt 0) {
            throw "No selected $serverEnvironmentName/$resolvedChannel client is running, but another named Psobb process exists"
        }
        return [pscustomobject]@{
            Stopped = $false
            Reason = 'not-running'
            ServerEnvironment = $serverEnvironmentName
            Channel = $resolvedChannel
            GracefulCount = 0
            ForcedCount = 0
        }
    }
    if ($allNamedRecords.Count -ne $records.Count -or
        @($allNamedRecords | Where-Object {
                [string]$_.ServerEnvironment -cne $serverEnvironmentName -or
                [string]$_.Classification -cne 'ApprovedExactPath' -or
                [int]$_.ProcessId -notin @($records.ProcessId)
            }).Count -gt 0) {
        throw 'The global named-client census does not exactly match the selected approved client inventory'
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
        } finally {
            $process.Dispose()
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
        try {
            if (-not $Force) {
                throw "PSOBB client PID $($record.ProcessId) did not close within $ShutdownTimeoutSeconds seconds. No forceful termination was attempted."
            }

            $process.Kill()
            if (-not $process.WaitForExit(5000)) {
                throw "Forced termination of PSOBB client PID $($record.ProcessId) could not be confirmed"
            }
            $forcedPids.Add([int]$record.ProcessId)
        } finally {
            $process.Dispose()
        }
    }

    $stillRunning = @(Get-PSOBBAllClientProcessRecords -Layout $layout)
    if ($stillRunning.Count -gt 0) {
        $details = @($stillRunning | ForEach-Object {
                'PID {0} ({1})' -f $_.ProcessId, $_.Classification
            })
        throw "A named Psobb process is still running after shutdown ($($details -join ', ')); no additional PID action was attempted"
    }
    $allPids = @($records.ProcessId)
    $gracefulPids = @($allPids | Where-Object { -not $forcedPids.Contains([int]$_) })
    [pscustomobject]@{
        Stopped = $true
        ServerEnvironment = $serverEnvironmentName
        Channel = $resolvedChannel
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
