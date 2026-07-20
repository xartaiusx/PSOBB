[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [ValidateSet('Stable', 'CombatCanary')]
    [string]$ServerEnvironment = 'Stable',
    [switch]$Force,
    [ValidateRange(5, 120)][int]$ShutdownTimeoutSeconds = 30,
    [Parameter(DontShow)][switch]$ClientOperationLockHeld
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')

function Set-LifecycleFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Set-PSOBBLifecyclePathAcl -Path $Path -Root $Root | Out-Null
}

function Assert-LifecycleFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Assert-PSOBBLifecyclePathAcl `
        -Path $Path -Root $Root -IsContainer $false | Out-Null
}

function Write-ProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Root,
        [switch]$CreateOnly
    )
    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $temporary = $safePath + '.' + [Guid]::NewGuid().ToString('N') + '.new'
    $jsonBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 6))
    $temporaryStream = $null
    try {
        $temporaryStream = [System.IO.FileStream]::new(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        $temporaryStream.Write($jsonBytes, 0, $jsonBytes.Length)
        $temporaryStream.Flush($true)
        $temporaryStream.Dispose()
        $temporaryStream = $null
        Set-LifecycleFileAcl -Path $temporary -Root $Root
        if ($CreateOnly) {
            [System.IO.File]::Move($temporary, $safePath)
        } else {
            [System.IO.File]::Move($temporary, $safePath, $true)
        }
    } finally {
        if ($temporaryStream) { $temporaryStream.Dispose() }
        [Array]::Clear($jsonBytes, 0, $jsonBytes.Length)
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Remove-LifecycleFiles {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$RootLayout
    )
    Remove-PSOBBLifecycleFilesVerified -Layout $Layout | Out-Null
    if ([string]$Layout.Environment -ceq 'Stable') {
        Remove-PSOBBRetiredLifecycleFiles -Layout $RootLayout
        $remainingRetired = @(Get-PSOBBRetiredLifecyclePaths `
            -Layout $RootLayout | Where-Object { Test-Path -LiteralPath $_ })
        if ($remainingRetired.Count -gt 0) {
            throw 'Retired lifecycle file removal could not be verified'
        }
    }
}

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $rootLayout
$environmentWasExplicit = $PSBoundParameters.ContainsKey('ServerEnvironment')
$requestedEnvironmentName = Resolve-PSOBBServerEnvironmentName `
    -Environment $ServerEnvironment
$clientOperationMutex = if ($ClientOperationLockHeld) {
    $null
} else {
    Enter-PSOBBClientOperationLock -Layout $rootLayout
}
try {
Assert-PSOBBNoRunningClients -Layout $rootLayout | Out-Null
$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
$hostProcess = $null
$process = $null
try {
    $ownsMutex = $mutex.WaitOne([TimeSpan]::FromSeconds(5))
    if (-not $ownsMutex) {
        throw 'Another PSOBB start or stop operation is already in progress'
    }

    $environmentCensus = @(Get-PSOBBServerEnvironmentProcessRecords `
        -Layout $rootLayout)
    $reservedListeners = @(Get-PSOBBReservedServerPortListeners)
    $lifecycleEvidence = @(
        Get-PSOBBServerLifecycleEvidenceRecords -Layout $rootLayout)
    $invalidCensus = @($environmentCensus | Where-Object {
            [string]$_.Classification -cne 'ApprovedExactPath' -or
            [string]$_.ServerEnvironment -notin @('Stable', 'CombatCanary')
        })
    if ($invalidCensus.Count -gt 0) {
        $details = @($invalidCensus | ForEach-Object {
                'PID {0} ({1})' -f $_.ProcessId, $_.Classification
            })
        throw "The global newserv census contains an unknown or uninspectable identity ($($details -join ', ')); no PID action was attempted"
    }
    if ($environmentCensus.Count -gt 1) {
        throw 'More than one canonical PSOBB server is running; refusing ambiguous shutdown'
    }
    $invalidEvidence = @($lifecycleEvidence | Where-Object {
            [string]$_.Classification -cne 'ExactEnvironmentBound'
        })
    if ($invalidEvidence.Count -gt 0) {
        $details = @($invalidEvidence | ForEach-Object {
                '{0} ({1})' -f $_.ServerEnvironment, $_.Classification
            })
        throw "Lifecycle evidence is invalid or incomplete ($($details -join ', ')); preserving all environments"
    }
    if ($lifecycleEvidence.Count -gt 1) {
        throw 'More than one PSOBB environment contains exact lifecycle evidence; refusing ambiguous cleanup'
    }
    if ($environmentCensus.Count -eq 1 -and
        $lifecycleEvidence.Count -eq 1 -and
        [string]$environmentCensus[0].ServerEnvironment -cne
            [string]$lifecycleEvidence[0].ServerEnvironment) {
        throw 'The active server and retained lifecycle evidence identify different environments'
    }
    $serverEnvironmentName = if ($environmentWasExplicit) {
        if ($environmentCensus.Count -eq 1 -and
            [string]$environmentCensus[0].ServerEnvironment -cne
                $requestedEnvironmentName) {
            throw "The active server is $($environmentCensus[0].ServerEnvironment), not the explicitly selected $requestedEnvironmentName environment"
        }
        if ($environmentCensus.Count -eq 0 -and
            $lifecycleEvidence.Count -eq 1 -and
            [string]$lifecycleEvidence[0].ServerEnvironment -cne
                $requestedEnvironmentName) {
            throw "Retained lifecycle evidence belongs to $($lifecycleEvidence[0].ServerEnvironment), not the explicitly selected $requestedEnvironmentName environment"
        }
        $requestedEnvironmentName
    } elseif ($environmentCensus.Count -eq 1) {
        [string]$environmentCensus[0].ServerEnvironment
    } elseif ($lifecycleEvidence.Count -eq 1) {
        [string]$lifecycleEvidence[0].ServerEnvironment
    } else {
        'Stable'
    }

    $layout = Get-PSOBBServerEnvironmentLayout `
        -Layout $rootLayout -Environment $serverEnvironmentName
    $approved = Get-PSOBBApprovedNewservExecutableIdentity `
        -Layout $rootLayout -ServerEnvironment $serverEnvironmentName
    $executable = Assert-PathWithinRoot `
        -Path $approved.ExecutablePath -Root $layout.EnvironmentRoot

    if ($environmentCensus.Count -eq 0) {
        if ($reservedListeners.Count -gt 0) {
            throw 'No canonical PSOBB server is running, but a reserved PSOBB listener is active; no owner action was attempted'
        }
        if (Test-Path -LiteralPath $layout.EnvironmentRoot -PathType Container) {
            Initialize-PSOBBLifecycleControlDirectory -Layout $layout | Out-Null
            if (Test-Path -LiteralPath $layout.PidFile -PathType Leaf) {
                Assert-LifecycleFileAcl -Path $layout.PidFile -Root $layout.Root
            }
            Wait-PSOBBRecordedSupervisorHostQuiescence -Layout $layout | Out-Null
            Remove-LifecycleFiles -Layout $layout -RootLayout $rootLayout
        } elseif ($serverEnvironmentName -ceq 'Stable') {
            throw 'The Stable runtime environment root is missing'
        }
        return [pscustomobject]@{
            Stopped = $false
            Reason = 'not-running'
            ServerEnvironment = $serverEnvironmentName
            Selection = if ($environmentWasExplicit) {
                'explicit'
            } elseif ($lifecycleEvidence.Count -eq 1) {
                'automatic-evidence'
            } else {
                'automatic-empty'
            }
        }
    }

    if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
        (Get-Item -LiteralPath $executable).Length -ne $approved.Size -or
        (Get-LowerSha256 $executable) -cne $approved.Sha256) {
        throw "The $serverEnvironmentName newserv executable does not match its exact approved component"
    }
    Initialize-PSOBBLifecycleControlDirectory -Layout $layout | Out-Null
    $exactPathProcesses = @(Get-NewservProcessesAtPath -Layout $layout)
    $processIdentity = Get-NewservProcess -Layout $layout -PassThruIdentity
    $process = if ($processIdentity) { $processIdentity.Process } else { $null }
    if (-not $process) {
        if ($exactPathProcesses.Count -gt 0) {
            throw 'An exact-path newserv process exists without a valid supervised process record; refusing unsafe PID action'
        }
        throw 'The canonical newserv census has a process without a valid supervised process record; refusing unsafe PID action'
    }

    if ($exactPathProcesses.Count -ne 1 -or
        $exactPathProcesses[0].Id -ne $process.Id -or
        $environmentCensus.Count -ne 1 -or
        [int]$environmentCensus[0].ProcessId -ne $process.Id -or
        [long]$environmentCensus[0].StartTimeFileTimeUtc -ne
            [long]$processIdentity.StartTimeFileTimeUtc -or
        [string]$environmentCensus[0].ServerEnvironment -cne $serverEnvironmentName -or
        -not (Test-PSOBBServerListenerSubsetForStop `
            -ProcessId $process.Id -ReservedPortListeners $reservedListeners)) {
        throw 'The global process/listener census conflicts with the validated selected-environment supervisor record'
    }
    Assert-LifecycleFileAcl -Path $layout.PidFile -Root $layout.Root
    $record = $processIdentity.Record
    $expectedControlIdentity = Get-PSOBBServerControlIdentity `
        -InstallationId ([string]$marker.installationId) `
        -EnvironmentId $layout.EnvironmentId `
        -ComponentId $approved.ComponentId `
        -StartupRequestId ([string]$record.startupRequestId) `
        -ExecutableSha256 ([string]$record.executableSha256)
    if ([string]$record.controlToken -notmatch '^[A-Za-z0-9_-]{43}$' -or
        [string]$record.executableSha256 -ne $approved.Sha256 -or
        [string]$record.executablePath -ne $executable -or
        [string]$record.serverEnvironment -cne $serverEnvironmentName -or
        [string]$record.environmentId -cne $layout.EnvironmentId -or
        [string]$record.componentId -cne $approved.ComponentId -or
        -not (Test-PSOBBFixedTimeTextEquals `
            -Expected $expectedControlIdentity `
            -Actual ([string]$record.controlIdentity)) -or
        [string]$record.controlProtocol -cne 'protected-filesystem-exit-v2' -or
        [int]$record.pid -ne $process.Id -or
        [long]$record.startTimeFileTimeUtc -ne
            [long]$processIdentity.StartTimeFileTimeUtc) {
        throw 'The supervised process record is incomplete or inconsistent with the approved executable'
    }

    $hostState = Get-PSOBBRecordedSupervisorHostState -Record $record
    if ($hostState.State -in @('InvalidRecord', 'Uninspectable')) {
        throw "The recorded supervisor host is $($hostState.State); no host request or wait was attempted"
    }
    $hostProcess = if ($hostState.State -ceq 'ExactActive') {
        $hostState.Process
    } else {
        $null
    }
    if (-not $hostProcess -and -not $Force) {
        throw 'The exact supervisor host is absent or its PID was reused, so no request or wait was attempted; use -Force only after confirming clients are disconnected'
    }

    $requestSent = $false
    if ($hostProcess) {
        $request = [ordered]@{
            schemaVersion = 3
            action = 'exit'
            serverEnvironment = $serverEnvironmentName
            environmentId = $layout.EnvironmentId
            componentId = $approved.ComponentId
            controlIdentity = [string]$record.controlIdentity
            startupRequestId = [string]$record.startupRequestId
            pid = $process.Id
            startTimeUtc = [string]$record.startTimeUtc
            startTimeFileTimeUtc = [long]$record.startTimeFileTimeUtc
            controlToken = [string]$record.controlToken
            requestedAtUtc = [DateTime]::UtcNow.ToString('o')
        }
        Write-ProtectedJson `
            -Path $layout.ControlRequest -Value $request -Root $layout.Root -CreateOnly
        Assert-LifecycleFileAcl -Path $layout.ControlRequest -Root $layout.Root
        $requestSent = $true
    }

    $deadline = if ($hostProcess) {
        [DateTime]::UtcNow.AddSeconds($ShutdownTimeoutSeconds)
    } else {
        [DateTime]::UtcNow
    }
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 250
    }

    $forced = $false
    $process.Refresh()
    if (-not $process.HasExited) {
        if (-not $Force) {
            throw 'newserv did not stop after the authenticated shell exit request; rerun with -Force only after confirming clients are disconnected'
        }

        # Re-read through the shared identity validator immediately before the
        # only forceful operation. This catches PID reuse, path swaps, and hash
        # changes between the request and termination.
        $revalidatedIdentity = Get-NewservProcess -Layout $layout -PassThruIdentity
        $revalidated = if ($revalidatedIdentity) {
            $revalidatedIdentity.Process
        } else { $null }
        try {
            if (-not $revalidated -or $revalidated.Id -ne $process.Id -or
                [long]$revalidatedIdentity.StartTimeFileTimeUtc -ne
                    [long]$processIdentity.StartTimeFileTimeUtc) {
                throw 'newserv identity changed before forced termination; refusing to kill a PID that was not revalidated'
            }
            $revalidated.Kill()
            $revalidated.WaitForExit(5000) | Out-Null
        } finally {
            if ($revalidated) { $revalidated.Dispose() }
        }
        $forced = $true
    }

    if ($hostProcess) {
        if (-not $hostProcess.WaitForExit(10000)) {
            throw 'The recorded supervisor host remains active after the child exited; lifecycle evidence was preserved'
        }
    }
    $process.Refresh()
    if (-not $process.HasExited) {
        throw 'The exact newserv child did not reach an exited handle state after shutdown'
    }
    $postStopCensus = @(Get-PSOBBServerEnvironmentProcessRecords -Layout $rootLayout)
    if ($postStopCensus.Count -gt 0) {
        $details = @($postStopCensus | ForEach-Object {
                'PID {0} ({1})' -f $_.ProcessId, $_.Classification
            })
        throw "A named newserv process exists after shutdown ($($details -join ', ')); lifecycle evidence was preserved and no additional PID action was attempted"
    }
    $postStopListeners = @(Get-PSOBBReservedServerPortListeners)
    if ($postStopListeners.Count -gt 0) {
        $stoppedPidListeners = @($postStopListeners | Where-Object {
                [int]$_.OwningProcess -eq $process.Id
            })
        if ($stoppedPidListeners.Count -gt 0) {
            throw 'A reserved listener remains attributed to the exited newserv PID; lifecycle evidence was preserved'
        }
        throw 'An unrelated reserved PSOBB listener appeared after shutdown; its owner was not acted on and lifecycle evidence was preserved'
    }
    Remove-LifecycleFiles -Layout $layout -RootLayout $rootLayout
    [pscustomobject]@{
        Stopped = $true
        ServerEnvironment = $serverEnvironmentName
        EnvironmentId = $layout.EnvironmentId
        ComponentId = $approved.ComponentId
        Selection = if ($environmentWasExplicit) { 'explicit' } else { 'automatic-active' }
        Pid = $process.Id
        Graceful = -not $forced
        Forced = $forced
        AuthenticatedShellExitRequested = $requestSent
    }
} finally {
    if ($process) {
        $process.Dispose()
    }
    if ($hostProcess) {
        $hostProcess.Dispose()
    }
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
} finally {
    if ($clientOperationMutex) {
        Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
    }
}
