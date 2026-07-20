[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..'))
$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
$drillPath = Join-Path $repositoryRoot 'scripts\Test-PSOBBRestoreDrill.ps1'
. $commonPath
. $drillPath

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Detail
    )
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function New-FakeRestoreDrillProcess {
    param([Parameter(Mandatory)][bool]$ExitWithinDeadline)

    $fake = [pscustomobject]@{
        HasExited = $false
        ExitWithinDeadline = $ExitWithinDeadline
        KillCalls = 0
        KillTree = $false
        WaitCalls = 0
        WaitArgument = 0
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Kill -Value {
        param([bool]$EntireProcessTree)
        $this.KillCalls++
        $this.KillTree = $EntireProcessTree
    }
    $fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
        param([int]$Milliseconds)
        $this.WaitCalls++
        $this.WaitArgument = $Milliseconds
        if ($this.ExitWithinDeadline) {
            $this.HasExited = $true
            return $true
        }
        $false
    }
    $fake
}

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $drillPath,
    [ref]$tokens,
    [ref]$parseErrors)
$drillSource = [System.IO.File]::ReadAllText($drillPath)
Add-Result 'restore drill termination source parses cleanly' `
    ($parseErrors.Count -eq 0) `
    "$($parseErrors.Count) parser error(s)"
Add-Result 'restore drill has no unbounded process wait' `
    ($drillSource -notmatch '\.WaitForExit\s*\(\s*\)' -and
     $drillSource -notmatch 'ReadToEndAsync\s*\(\s*\)' -and
     $drillSource.Contains(
        '-TerminationTimeoutMilliseconds $terminationTimeoutMilliseconds')) `
    'process waits and redirected readers use finite cancellation-aware deadlines'
Add-Result 'restore drill retains an explicit protected quarantine contract' `
    ($drillSource.Contains('.restore-drill-quarantine.json') -and
     $drillSource.Contains('.restore-drill-quarantine-incomplete.json') -and
     $drillSource.Contains('-PreserveCurrentPayload:$quarantineRequired') -and
     $drillSource.Contains('$quarantineReason = ''exit-unconfirmed''') -and
     $drillSource.Contains(
        '$quarantineReason = ''output-reader-unconfirmed''')) `
    'unconfirmed exit, output, or publication cannot fall through to work-tree deletion'

$nonExiting = New-FakeRestoreDrillProcess -ExitWithinDeadline $false
$nonExitResult = Stop-PSOBBRestoreDrillProcess `
    -Process $nonExiting -TerminationTimeoutMilliseconds 17
Add-Result 'non-exiting restore-drill process reaches a finite failure result' `
    (-not $nonExitResult.ConfirmedExited -and
     $nonExitResult.KillRequested -and
     $nonExitResult.WaitMilliseconds -eq 17 -and
     $nonExitResult.Failure -ceq 'termination-deadline-expired' -and
     $nonExiting.KillCalls -eq 1 -and
     $nonExiting.KillTree -and
     $nonExiting.WaitCalls -eq 1 -and
     $nonExiting.WaitArgument -eq 17) `
    'the fake process receives one tree-kill and one bounded wait without a real child process'

$exiting = New-FakeRestoreDrillProcess -ExitWithinDeadline $true
$exitResult = Stop-PSOBBRestoreDrillProcess `
    -Process $exiting -TerminationTimeoutMilliseconds 23
Add-Result 'confirmed restore-drill termination permits cleanup' `
    ($exitResult.ConfirmedExited -and
     $null -eq $exitResult.Failure -and
     $exiting.HasExited -and
     $exiting.KillCalls -eq 1 -and
     $exiting.WaitCalls -eq 1 -and
     $exiting.WaitArgument -eq 23) `
    'cleanup proceeds only after the bounded wait and exit-state readback agree'

$completedStdoutCancellation =
    [System.Threading.CancellationTokenSource]::new()
$completedStderrCancellation =
    [System.Threading.CancellationTokenSource]::new()
try {
    $completedOutput = Receive-PSOBBRestoreDrillOutput `
        -StandardOutputTask `
            ([System.Threading.Tasks.Task]::FromResult([string]'stdout fixture')) `
        -StandardErrorTask `
            ([System.Threading.Tasks.Task]::FromResult([string]'stderr fixture')) `
        -StandardOutputCancellation $completedStdoutCancellation `
        -StandardErrorCancellation $completedStderrCancellation `
        -TimeoutMilliseconds 31
    Add-Result 'completed restore-drill readers return exact output' `
        ($completedOutput.Confirmed -and
         $completedOutput.StandardOutput -ceq 'stdout fixture' -and
         $completedOutput.StandardError -ceq 'stderr fixture' -and
         @($completedOutput.Failures).Count -eq 0) `
        'GetResult is reached only after both task states are terminal and successful'
} finally {
    $completedStdoutCancellation.Dispose()
    $completedStderrCancellation.Dispose()
}

$nonReturningStdout =
    [System.Threading.Tasks.TaskCompletionSource[string]]::new()
$nonReturningStderr =
    [System.Threading.Tasks.TaskCompletionSource[string]]::new()
$nonReturningStdoutCancellation =
    [System.Threading.CancellationTokenSource]::new()
$nonReturningStderrCancellation =
    [System.Threading.CancellationTokenSource]::new()
try {
    $readerStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $nonReturningOutput = Receive-PSOBBRestoreDrillOutput `
        -StandardOutputTask $nonReturningStdout.Task `
        -StandardErrorTask $nonReturningStderr.Task `
        -StandardOutputCancellation $nonReturningStdoutCancellation `
        -StandardErrorCancellation $nonReturningStderrCancellation `
        -TimeoutMilliseconds 19
    $readerStopwatch.Stop()
    Add-Result 'non-returning restore-drill readers fail within finite deadlines' `
        (-not $nonReturningOutput.Confirmed -and
         @($nonReturningOutput.Failures).Count -eq 2 -and
         $nonReturningStdoutCancellation.IsCancellationRequested -and
         $nonReturningStderrCancellation.IsCancellationRequested -and
         $readerStopwatch.ElapsedMilliseconds -lt 1000) `
        'two never-completing synthetic tasks are canceled independently without a persistent process'
} finally {
    $nonReturningStdoutCancellation.Dispose()
    $nonReturningStderrCancellation.Dispose()
}

$temporaryBase = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::GetTempPath()).TrimEnd('\')
$temporaryRoot = Join-Path $temporaryBase (
    'PSOBB-RestoreDrillTerminationTests-' + [Guid]::NewGuid().ToString('N'))
$backupsRoot = Join-Path $temporaryRoot 'backups'
$quarantinedRoot = Join-Path $backupsRoot 'restore-drill-quarantined'
$quarantinedWork = Join-Path $quarantinedRoot '.work'
$incompleteRoot = Join-Path $backupsRoot 'restore-drill-incomplete'
$incompleteWork = Join-Path $incompleteRoot '.work'
$publicationFailedRoot = Join-Path $backupsRoot `
    'restore-drill-publication-failed'
$publicationFailedWork = Join-Path $publicationFailedRoot '.work'
$ordinaryRoot = Join-Path $backupsRoot 'restore-drill-ordinary'
$ordinaryPayload = Join-Path $ordinaryRoot 'ordinary.bin'
$executableRoot = Join-Path $temporaryRoot 'executable-fixture'
try {
    foreach ($directory in @(
            $backupsRoot,
            $quarantinedRoot,
            $quarantinedWork,
            $incompleteRoot,
            $incompleteWork,
            $publicationFailedRoot,
            $publicationFailedWork,
            $ordinaryRoot,
            $executableRoot)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $quarantinedWork 'retained.bin'),
        'fixture',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $incompleteWork 'retained.bin'),
        'fixture',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $publicationFailedWork 'retained.bin'),
        'fixture',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $ordinaryPayload,
        'fixture',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $backupsRoot -Root $temporaryRoot

    $quarantinePath = Join-Path $quarantinedRoot `
        '.restore-drill-quarantine.json'
    $quarantine = [ordered]@{
        schemaVersion = 2
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        processId = 4242
        processStartTimeFileTimeUtc = 133801632000000000
        serverExecutableSha256 = ('a' * 64)
        terminationTimeoutMilliseconds = 17
        reason = 'exit-unconfirmed'
        publicationState = 'complete'
        nextAction = $script:PSOBBRestoreDrillQuarantineNextAction
    } | ConvertTo-Json -Depth 3
    [System.IO.File]::WriteAllText(
        $quarantinePath,
        $quarantine,
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $quarantinePath

    $fallbackPublication = Publish-PSOBBRestoreDrillQuarantine `
        -DrillRoot $incompleteRoot -BackupsRoot $backupsRoot `
        -ProcessId 4343 `
        -ProcessStartTimeFileTimeUtc 133801632000000001 `
        -ServerExecutableSha256 ('b' * 64) `
        -TerminationTimeoutMilliseconds 19 `
        -Reason output-reader-unconfirmed `
        -InternalPrimaryPublishAction {
            throw 'injected primary quarantine publication failure'
        }
    $incompleteSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $fallbackPublication.Path -Root $incompleteRoot `
        -MaximumBytes 8KB -MaximumDepth 3 `
        -Label 'incomplete quarantine fixture'
    Add-Result 'primary quarantine failure publishes exact fallback evidence' `
        (-not $fallbackPublication.Complete -and
         $fallbackPublication.PublicationState -ceq
            'primary-publication-failed' -and
         [long]$incompleteSnapshot.Value.processId -eq 4343 -and
         [long]$incompleteSnapshot.Value.processStartTimeFileTimeUtc -eq
            133801632000000001 -and
         [string]$incompleteSnapshot.Value.serverExecutableSha256 -ceq
            ('b' * 64) -and
         (Test-PSOBBRestoreDrillQuarantine `
            -DrillRoot $incompleteRoot -BackupsRoot $backupsRoot)) `
        'fallback publication records exact PID, start time, digest, reason, and next action'

    $bothPublicationsFailed = $false
    try {
        Publish-PSOBBRestoreDrillQuarantine `
            -DrillRoot $publicationFailedRoot `
            -BackupsRoot $backupsRoot -ProcessId 4444 `
            -ProcessStartTimeFileTimeUtc 133801632000000002 `
            -ServerExecutableSha256 ('c' * 64) `
            -TerminationTimeoutMilliseconds 23 `
            -Reason exit-unconfirmed `
            -InternalPrimaryPublishAction { throw 'primary failure' } `
            -InternalFallbackPublishAction { throw 'fallback failure' } |
            Out-Null
    } catch {
        $bothPublicationsFailed = $true
    }
    Add-Result 'complete quarantine publication failure remains fail closed' `
        ($bothPublicationsFailed -and
         (Test-PSOBBRestoreDrillUnresolvedWorkTree `
            -DrillRoot $publicationFailedRoot `
            -BackupsRoot $backupsRoot)) `
        'a protected unresolved work tree is a durable cleanup hold even when neither record can publish'

    $executablePath = Join-Path $executableRoot 'newserv-windows.exe'
    $replacementPath = Join-Path $executableRoot 'replacement.exe'
    [System.IO.File]::WriteAllText(
        $executablePath,
        'leased executable fixture',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $replacementPath,
        'replacement executable fixture',
        [System.Text.UTF8Encoding]::new($false))
    $executableSha256 = Get-LowerSha256 $executablePath
    $executableIdentity = Open-PSOBBRestoreDrillExecutableIdentity `
        -Path $executablePath -Root $executableRoot `
        -ExpectedSha256 $executableSha256
    try {
        $replacementState = [pscustomobject]@{ Blocked = $false }
        $leasedDigest = Assert-PSOBBRestoreDrillExecutableIdentity `
            -Identity $executableIdentity `
            -InternalBeforeVerificationAction {
                param($Identity)
                try {
                    [System.IO.File]::Move(
                        $replacementPath, [string]$Identity.Path, $true)
                } catch {
                    $replacementState.Blocked = $true
                }
            }
        $fakeStartTime = [DateTime]::UtcNow
        $fakeProcess = [pscustomobject]@{
            Id = 4545
            StartTime = $fakeStartTime
        }
        $fakeNative = [pscustomobject]@{
            ProcessId = 4545
            ImagePath = $executableIdentity.Path
            CreationTimeFileTimeUtc = [long](
                $fakeStartTime.ToUniversalTime().ToFileTimeUtc())
            IsRunning = $true
        }
        $verifiedLaunch = Assert-PSOBBRestoreDrillLaunchedProcessIdentity `
            -Process $fakeProcess -ExecutableIdentity $executableIdentity `
            -InternalNativeProcessInfo $fakeNative
        $mismatchedLaunchRejected = $false
        try {
            $wrongNative = $fakeNative.PSObject.Copy()
            $wrongNative.ImagePath = $replacementPath
            Assert-PSOBBRestoreDrillLaunchedProcessIdentity `
                -Process $fakeProcess `
                -ExecutableIdentity $executableIdentity `
                -InternalNativeProcessInfo $wrongNative | Out-Null
        } catch {
            $mismatchedLaunchRejected = $true
        }
        Add-Result 'restore-drill executable lease blocks substitution through launch identity' `
            ($replacementState.Blocked -and
             $leasedDigest.Sha256 -ceq $executableSha256 -and
             $verifiedLaunch.ServerExecutableSha256 -ceq
                $executableSha256 -and
             $mismatchedLaunchRejected -and
             (Get-LowerSha256 $executablePath) -ceq $executableSha256) `
            'the retained lease prevents replacement and native PID, start time, and image path must all match'
    } finally {
        Close-PSOBBTrustedExecutableLease -Identity $executableIdentity
    }

    $layout = [pscustomobject]@{ Backups = $backupsRoot }
    Remove-DrillPayloads `
        -Layout $layout -Retention 5 -CurrentDrillRoot $ordinaryRoot
    Add-Result 'restore-drill retention skips a valid quarantine' `
        ((Test-Path -LiteralPath $quarantinedWork -PathType Container) -and
         (Test-Path -LiteralPath (
                Join-Path $quarantinedWork 'retained.bin') -PathType Leaf) -and
         (Test-Path -LiteralPath $incompleteWork -PathType Container) -and
         (Test-Path -LiteralPath $publicationFailedWork -PathType Container) -and
         -not (Test-Path -LiteralPath $ordinaryPayload)) `
        'valid, incomplete, and publication-failed holds survive while ordinary retained payload is removed'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $safeRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        if (-not $safeRoot.StartsWith(
                $temporaryBase + '\',
                [System.StringComparison]::OrdinalIgnoreCase) -or
            -not ([System.IO.Path]::GetFileName($safeRoot)).StartsWith(
                'PSOBB-RestoreDrillTerminationTests-',
                [System.StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected restore-drill test root'
        }
        Remove-Item -LiteralPath $safeRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) restore-drill termination test(s) failed"
}
[pscustomobject]@{
    Suite = 'RestoreDrillTermination'
    Passed = $results.Count
    Failed = 0
}
