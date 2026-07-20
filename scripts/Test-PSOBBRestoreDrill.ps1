[CmdletBinding()]
param(
    [string]$BackupPath,
    [string]$RuntimeRoot,
    [ValidateRange(1, 20)][int]$ResultRetention = 5
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedServerExecutableHash {
    (Get-PSOBBStableServerSourceLockIdentity).Sha256
}

$script:PSOBBRestoreDrillQuarantineNextAction =
    'Confirm the recorded PID, start-time identity, and executable digest are absent, and all reserved listeners are clear, before removing this one protected drill quarantine.'

function Open-PSOBBRestoreDrillExecutableIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )

    if ($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The approved restore-drill executable digest is invalid'
    }
    $identity = Open-PSOBBTrustedExecutableLease `
        -Path $Path -Root $Root -MaximumBytes 1GB `
        -Label 'restore-drill server executable'
    try {
        if ([string]$identity.Sha256 -cne $ExpectedSha256) {
            throw 'Restore-drill server executable does not match the approved source-lock hash'
        }
        $identity
        $identity = $null
    } finally {
        if ($identity) {
            Close-PSOBBTrustedExecutableLease -Identity $identity
        }
    }
}

function Assert-PSOBBRestoreDrillExecutableIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Identity,
        [scriptblock]$InternalBeforeVerificationAction
    )

    if ($InternalBeforeVerificationAction) {
        & $InternalBeforeVerificationAction $Identity
    }
    $safePath = Assert-PSOBBOrdinaryContainedPath `
        -Path ([string]$Identity.Path) -Root ([string]$Identity.Root) `
        -Kind File -Label 'restore-drill server executable'
    $digest = Get-PSOBBLeasedFileDigest `
        -Lease $Identity.Lease `
        -MaximumBytes ([long]$Identity.MaximumBytes) `
        -Label 'restore-drill server executable'
    if (-not $safePath.Equals(
            [string]$Identity.Path,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        [long]$digest.Length -ne [long]$Identity.Length -or
        [string]$digest.Sha256 -cne [string]$Identity.Sha256) {
        throw 'The leased restore-drill server executable identity changed'
    }
    $digest
}

function Assert-PSOBBRestoreDrillLaunchedProcessIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Process,
        [Parameter(Mandatory)]$ExecutableIdentity,
        [Parameter(DontShow = $true)]$InternalNativeProcessInfo
    )

    $processId = [int]$Process.Id
    $managedStartTimeFileTimeUtc = [long](
        $Process.StartTime.ToUniversalTime().ToFileTimeUtc())
    $native = if ($InternalNativeProcessInfo) {
        $InternalNativeProcessInfo
    } else {
        Get-PSOBBNativeProcessInfo -ProcessId $processId
    }
    $nativePath = [System.IO.Path]::GetFullPath([string]$native.ImagePath)
    $expectedPath = [System.IO.Path]::GetFullPath(
        [string]$ExecutableIdentity.Path)
    if ([int]$native.ProcessId -ne $processId -or
        -not [bool]$native.IsRunning -or
        [long]$native.CreationTimeFileTimeUtc -ne
            $managedStartTimeFileTimeUtc -or
        -not $nativePath.Equals(
            $expectedPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The launched restore-drill process does not match the leased executable identity'
    }
    $digest = Assert-PSOBBRestoreDrillExecutableIdentity `
        -Identity $ExecutableIdentity
    [pscustomobject]@{
        ProcessId = $processId
        ProcessStartTimeFileTimeUtc = [long]$native.CreationTimeFileTimeUtc
        ImagePath = $nativePath
        ServerExecutableSha256 = [string]$digest.Sha256
    }
}

function Receive-PSOBBRestoreDrillOutputReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Threading.Tasks.Task]$Task,
        [Parameter(Mandatory)]
        [System.Threading.CancellationTokenSource]$CancellationSource,
        [Parameter(Mandatory)][ValidateRange(1, 30000)]
        [int]$TimeoutMilliseconds,
        [Parameter(Mandatory)][string]$Label
    )

    $completedWithinDeadline = $false
    try {
        $completedWithinDeadline = [bool]$Task.Wait($TimeoutMilliseconds)
    } catch [System.AggregateException] {
        # A faulted or canceled task is already terminal and can be inspected
        # without an unbounded wait below.
        $completedWithinDeadline = $Task.IsCompleted
    }
    if (-not $completedWithinDeadline) {
        $CancellationSource.Cancel()
        $cancellationDeadline = [Math]::Min(1000, $TimeoutMilliseconds)
        try {
            [void]$Task.Wait($cancellationDeadline)
        } catch [System.AggregateException] {
            # Canceled and faulted tasks are handled by their terminal status.
        }
    }

    if (-not $Task.IsCompleted) {
        return [pscustomobject]@{
            Confirmed = $false
            Text = $null
            Failure = "$Label-reader-deadline-expired"
        }
    }
    if ($Task.Status -ne
        [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
        return [pscustomobject]@{
            Confirmed = $false
            Text = $null
            Failure = "$Label-reader-$($Task.Status.ToString().ToLowerInvariant())"
        }
    }

    [pscustomobject]@{
        Confirmed = $true
        Text = [string]$Task.GetAwaiter().GetResult()
        Failure = $null
    }
}

function Receive-PSOBBRestoreDrillOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Threading.Tasks.Task]$StandardOutputTask,
        [Parameter(Mandatory)][System.Threading.Tasks.Task]$StandardErrorTask,
        [Parameter(Mandatory)]
        [System.Threading.CancellationTokenSource]$StandardOutputCancellation,
        [Parameter(Mandatory)]
        [System.Threading.CancellationTokenSource]$StandardErrorCancellation,
        [ValidateRange(1, 30000)][int]$TimeoutMilliseconds = 5000
    )

    $standardOutput = Receive-PSOBBRestoreDrillOutputReader `
        -Task $StandardOutputTask `
        -CancellationSource $StandardOutputCancellation `
        -TimeoutMilliseconds $TimeoutMilliseconds -Label 'stdout'
    $standardError = Receive-PSOBBRestoreDrillOutputReader `
        -Task $StandardErrorTask `
        -CancellationSource $StandardErrorCancellation `
        -TimeoutMilliseconds $TimeoutMilliseconds -Label 'stderr'
    [pscustomobject]@{
        Confirmed = $standardOutput.Confirmed -and $standardError.Confirmed
        StandardOutput = [string]$standardOutput.Text
        StandardError = [string]$standardError.Text
        Failures = @($standardOutput.Failure, $standardError.Failure |
            Where-Object { $_ })
    }
}

function Test-IsStatePath([string]$RelativePath) {
    ($RelativePath -eq 'system/config.json') -or
    ($RelativePath -in @('system/licenses', 'system/players', 'system/teams')) -or
    ($RelativePath -match '^system/(licenses|players|teams)/')
}

function Remove-DrillPayloads(
    [Parameter(Mandatory)]$Layout,
    [int]$Retention,
    [Parameter(Mandatory)][string]$CurrentDrillRoot,
    [switch]$PreserveCurrentPayload
) {
    $drills = @(Get-ChildItem -LiteralPath $Layout.Backups -Directory -Filter 'restore-drill-*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending)
    foreach ($drill in $drills) {
        $isCurrent = $drill.FullName.Equals(
            $CurrentDrillRoot,
            [System.StringComparison]::OrdinalIgnoreCase)
        if (($isCurrent -and $PreserveCurrentPayload) -or
            (Test-PSOBBRestoreDrillQuarantine `
                -DrillRoot $drill.FullName -BackupsRoot $Layout.Backups) -or
            (Test-PSOBBRestoreDrillUnresolvedWorkTree `
                -DrillRoot $drill.FullName -BackupsRoot $Layout.Backups)) {
            continue
        }
        [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $drill.FullName -Root $Layout.Backups `
                -Label 'restore-drill retention tree' -RequireProtectedAcl)
        foreach ($item in @(Get-ChildItem -Force -LiteralPath $drill.FullName -ErrorAction SilentlyContinue |
            Where-Object Name -ne 'drill-result.json')) {
            Assert-PathWithinRoot -Path $item.FullName -Root $drill.FullName | Out-Null
            if ($item.PSIsContainer) {
                Remove-PSOBBRedactedRecoveryTree `
                    -Path $item.FullName -Root $drill.FullName `
                    -Label 'restore-drill retained payload' -RequireProtectedAcl
            } else {
                if (-not (Test-PSOBBProtectedAcl -Path $item.FullName) -or
                    ($item.Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Restore-drill retained payload is not an ordinary protected file'
                }
                Remove-Item -LiteralPath $item.FullName -Force
            }
        }
        if (-not $drill.FullName.Equals($CurrentDrillRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not (Test-Path -LiteralPath (Join-Path $drill.FullName 'drill-result.json') -PathType Leaf)) {
            Remove-Item -LiteralPath $drill.FullName -Force
        }
    }
    $retainedDrills = @(Get-ChildItem -LiteralPath $Layout.Backups -Directory -Filter 'restore-drill-*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Where-Object {
            -not (Test-PSOBBRestoreDrillQuarantine `
                -DrillRoot $_.FullName -BackupsRoot $Layout.Backups) -and
            -not (Test-PSOBBRestoreDrillUnresolvedWorkTree `
                -DrillRoot $_.FullName -BackupsRoot $Layout.Backups)
        })
    foreach ($expired in @($retainedDrills | Select-Object -Skip $Retention)) {
        Remove-PSOBBRedactedRecoveryTree `
            -Path $expired.FullName -Root $Layout.Backups `
            -Label 'expired restore-drill result' -RequireProtectedAcl
    }
}

function Test-PSOBBRestoreDrillQuarantine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DrillRoot,
        [Parameter(Mandatory)][string]$BackupsRoot
    )

    $safeRoot = Assert-PSOBBOrdinaryContainedPath `
        -Path $DrillRoot -Root $BackupsRoot -Kind Directory `
        -Label 'restore-drill root'
    foreach ($definition in @(
        [pscustomobject]@{
            Name = '.restore-drill-quarantine-incomplete.json'
            PublicationState = 'primary-publication-failed'
        },
        [pscustomobject]@{
            Name = '.restore-drill-quarantine.json'
            PublicationState = 'complete'
        }
    )) {
        $path = Assert-PathWithinRoot `
            -Path (Join-Path $safeRoot $definition.Name) -Root $safeRoot
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $path -Root $safeRoot -Kind File `
                -Label 'restore-drill quarantine record')
        if (-not (Test-PSOBBProtectedAcl -Path $path)) {
            throw 'Restore-drill quarantine record does not have its exact protected ACL'
        }
        $snapshot = Read-PSOBBStrictJsonSnapshot `
            -Path $path -Root $safeRoot -MaximumBytes 8KB `
            -MaximumDepth 3 -Label 'restore-drill quarantine record'
        $record = $snapshot.Value
        Assert-PSOBBStrictDataObjectProperties -Value $record -Expected @(
            'schemaVersion', 'createdAtUtc', 'processId',
            'processStartTimeFileTimeUtc', 'serverExecutableSha256',
            'terminationTimeoutMilliseconds', 'reason', 'publicationState',
            'nextAction') -Label 'restore-drill quarantine record' | Out-Null
        $createdAt = [DateTimeOffset]::MinValue
        if ($record.schemaVersion -isnot [long] -or
            $record.schemaVersion -ne 2 -or
            $record.createdAtUtc -isnot [string] -or
            -not [DateTimeOffset]::TryParse(
                [string]$record.createdAtUtc, [ref]$createdAt) -or
            $record.processId -isnot [long] -or
            $record.processId -lt 1 -or
            $record.processStartTimeFileTimeUtc -isnot [long] -or
            $record.processStartTimeFileTimeUtc -lt 1 -or
            $record.serverExecutableSha256 -isnot [string] -or
            [string]$record.serverExecutableSha256 -cnotmatch
                '^[a-f0-9]{64}$' -or
            $record.terminationTimeoutMilliseconds -isnot [long] -or
            $record.terminationTimeoutMilliseconds -lt 1 -or
            $record.terminationTimeoutMilliseconds -gt 30000 -or
            $record.reason -isnot [string] -or
            [string]$record.reason -notin @(
                'exit-unconfirmed', 'output-reader-unconfirmed') -or
            $record.publicationState -isnot [string] -or
            [string]$record.publicationState -cne
                [string]$definition.PublicationState -or
            $record.nextAction -isnot [string] -or
            [string]$record.nextAction -cne
                $script:PSOBBRestoreDrillQuarantineNextAction) {
            throw 'Restore-drill quarantine record is invalid'
        }
        return $true
    }
    $false
}

function New-PSOBBRestoreDrillQuarantineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)]
        [int]$ProcessId,
        [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)]
        [long]$ProcessStartTimeFileTimeUtc,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ServerExecutableSha256,
        [Parameter(Mandatory)][ValidateRange(1, 30000)]
        [int]$TerminationTimeoutMilliseconds,
        [Parameter(Mandatory)]
        [ValidateSet('exit-unconfirmed', 'output-reader-unconfirmed')]
        [string]$Reason,
        [Parameter(Mandatory)]
        [ValidateSet('complete', 'primary-publication-failed')]
        [string]$PublicationState
    )

    [ordered]@{
        schemaVersion = 2
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        processId = $ProcessId
        processStartTimeFileTimeUtc = $ProcessStartTimeFileTimeUtc
        serverExecutableSha256 = $ServerExecutableSha256
        terminationTimeoutMilliseconds = $TerminationTimeoutMilliseconds
        reason = $Reason
        publicationState = $PublicationState
        nextAction = $script:PSOBBRestoreDrillQuarantineNextAction
    }
}

function Write-PSOBBRestoreDrillQuarantineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$DrillRoot
    )

    $quarantineText = $Record | ConvertTo-Json -Depth 3
    $quarantineSha256 = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.UTF8Encoding]::new($false).GetBytes(
                $quarantineText))).ToLowerInvariant()
    Write-PSOBBAtomicUtf8Text `
        -Path $Path -Text $quarantineText -Root $DrillRoot `
        -ExpectedSha256 $quarantineSha256
    Set-PSOBBProtectedAcl -Path $Path
}

function Publish-PSOBBRestoreDrillQuarantine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DrillRoot,
        [Parameter(Mandatory)][string]$BackupsRoot,
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)]
        [int]$ProcessId,
        [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)]
        [long]$ProcessStartTimeFileTimeUtc,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ServerExecutableSha256,
        [Parameter(Mandatory)][ValidateRange(1, 30000)]
        [int]$TerminationTimeoutMilliseconds,
        [Parameter(Mandatory)]
        [ValidateSet('exit-unconfirmed', 'output-reader-unconfirmed')]
        [string]$Reason,
        [Parameter(DontShow = $true)]
        [scriptblock]$InternalPrimaryPublishAction,
        [Parameter(DontShow = $true)]
        [scriptblock]$InternalFallbackPublishAction
    )

    $safeRoot = Assert-PSOBBOrdinaryContainedPath `
        -Path $DrillRoot -Root $BackupsRoot -Kind Directory `
        -Label 'restore-drill root'
    $primaryPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot '.restore-drill-quarantine.json') `
        -Root $safeRoot
    $primaryRecord = New-PSOBBRestoreDrillQuarantineRecord `
        -ProcessId $ProcessId `
        -ProcessStartTimeFileTimeUtc $ProcessStartTimeFileTimeUtc `
        -ServerExecutableSha256 $ServerExecutableSha256 `
        -TerminationTimeoutMilliseconds $TerminationTimeoutMilliseconds `
        -Reason $Reason -PublicationState complete
    try {
        if ($InternalPrimaryPublishAction) {
            & $InternalPrimaryPublishAction $primaryPath $primaryRecord
        } else {
            Write-PSOBBRestoreDrillQuarantineRecord `
                -Path $primaryPath -Record $primaryRecord `
                -DrillRoot $safeRoot
        }
        if (-not (Test-PSOBBRestoreDrillQuarantine `
                -DrillRoot $safeRoot -BackupsRoot $BackupsRoot)) {
            throw 'Restore-drill quarantine record did not read back exactly'
        }
        return [pscustomobject]@{
            Complete = $true
            Path = $primaryPath
            PublicationState = 'complete'
        }
    } catch {
        $primaryFailure = $_
    }

    $fallbackPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot `
            '.restore-drill-quarantine-incomplete.json') -Root $safeRoot
    $fallbackRecord = New-PSOBBRestoreDrillQuarantineRecord `
        -ProcessId $ProcessId `
        -ProcessStartTimeFileTimeUtc $ProcessStartTimeFileTimeUtc `
        -ServerExecutableSha256 $ServerExecutableSha256 `
        -TerminationTimeoutMilliseconds $TerminationTimeoutMilliseconds `
        -Reason $Reason -PublicationState primary-publication-failed
    try {
        if ($InternalFallbackPublishAction) {
            & $InternalFallbackPublishAction $fallbackPath $fallbackRecord
        } else {
            Write-PSOBBRestoreDrillQuarantineRecord `
                -Path $fallbackPath -Record $fallbackRecord `
                -DrillRoot $safeRoot
        }
        if (-not (Test-PSOBBRestoreDrillQuarantine `
                -DrillRoot $safeRoot -BackupsRoot $BackupsRoot)) {
            throw 'Incomplete restore-drill quarantine did not read back exactly'
        }
        [pscustomobject]@{
            Complete = $false
            Path = $fallbackPath
            PublicationState = 'primary-publication-failed'
        }
    } catch {
        throw ('Primary and fallback restore-drill quarantine publication ' +
            'failed. Primary: ' + $primaryFailure.Exception.Message +
            ' Fallback: ' + $_.Exception.Message)
    }
}

function Test-PSOBBRestoreDrillUnresolvedWorkTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DrillRoot,
        [Parameter(Mandatory)][string]$BackupsRoot
    )

    $safeRoot = Assert-PSOBBOrdinaryContainedPath `
        -Path $DrillRoot -Root $BackupsRoot -Kind Directory `
        -Label 'restore-drill root'
    $workRoot = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot '.work') -Root $safeRoot
    if (-not (Test-Path -LiteralPath $workRoot)) {
        return $false
    }
    if (-not (Test-PSOBBProtectedAcl -Path $safeRoot)) {
        throw 'Unresolved restore-drill root does not have its exact protected ACL'
    }
    [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
            -Path $workRoot -Root $safeRoot `
            -Label 'unresolved restore-drill work tree')
    $true
}

function Stop-PSOBBRestoreDrillProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Process,
        [ValidateRange(1, 30000)]
        [int]$TerminationTimeoutMilliseconds = 5000
    )

    try {
        if ([bool]$Process.HasExited) {
            return [pscustomobject]@{
                ConfirmedExited = $true
                KillRequested = $false
                WaitMilliseconds = 0
                Failure = $null
            }
        }
    } catch {
        return [pscustomobject]@{
            ConfirmedExited = $false
            KillRequested = $false
            WaitMilliseconds = 0
            Failure = 'process-state-unavailable'
        }
    }

    $killRequested = $false
    $killFailure = $null
    try {
        $Process.Kill($true)
        $killRequested = $true
    } catch {
        $killFailure = 'kill-request-failed'
    }

    $waitCompleted = $false
    $waitFailure = $null
    try {
        $waitCompleted = [bool]$Process.WaitForExit(
            $TerminationTimeoutMilliseconds)
    } catch {
        $waitFailure = 'bounded-wait-failed'
    }
    $hasExited = $false
    try {
        $hasExited = [bool]$Process.HasExited
    } catch {
        $waitFailure = 'process-state-unavailable'
    }
    $confirmed = $waitCompleted -and $hasExited
    [pscustomobject]@{
        ConfirmedExited = $confirmed
        KillRequested = $killRequested
        WaitMilliseconds = $TerminationTimeoutMilliseconds
        Failure = if ($confirmed) {
            $null
        } elseif ($waitFailure) {
            $waitFailure
        } elseif ($killFailure) {
            $killFailure
        } else {
            'termination-deadline-expired'
        }
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$clientOperationMutex = $null
$mutex = $null
$ownsMutex = $false
try {
    $clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout -TimeoutSeconds 0
    $marker = Assert-PSOBBRuntimeMarker -Layout $layout
    $mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
    $mutex = [System.Threading.Mutex]::new($false, $mutexName)
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (-not $ownsMutex) {
        throw 'Another PSOBB start, stop, backup, restore, restore-drill, or patch-profile operation is already in progress'
    }
    Assert-PSOBBGlobalStoppedRuntime `
        -Layout $layout -Operation 'starting a Stable restore drill' | Out-Null

if (-not (Test-Path -LiteralPath $layout.Backups -PathType Container)) {
    New-Item -ItemType Directory -Path $layout.Backups -Force | Out-Null
}
Assert-PathWithinRoot -Path $layout.Backups -Root $layout.Root | Out-Null
Set-PSOBBProtectedAcl -Path $layout.Backups
$drillRoot = Join-Path $layout.Backups ('restore-drill-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
$workRoot = Join-Path $drillRoot '.work'
$drillServer = Join-Path $workRoot 'server\release'
$resultPath = Join-Path $drillRoot 'drill-result.json'
Assert-PathWithinRoot -Path $drillRoot -Root $layout.Backups | Out-Null
New-Item -ItemType Directory -Path $drillRoot | Out-Null
Set-PSOBBProtectedAcl -Path $drillRoot

$result = [ordered]@{
    schemaVersion = 3
    startedAtUtc = [DateTime]::UtcNow.ToString('o')
    completedAtUtc = $null
    backup = $null
    backupManifestSha256 = $null
    approvedServerExecutableSha256 = $null
    serverExecutableSha256 = $null
    processId = $null
    processStartTimeFileTimeUtc = $null
    processImageVerified = $false
    quarantineReason = $null
    quarantinePublicationState = $null
    quarantineNextAction = $null
    serverScaffoldFilesVerified = 0
    clientPatchProfile = $null
    clientPatchPolicySha256 = $null
    clientPatchConfigSha256 = $null
    installationRecordSha256 = $null
    expectedAccounts = 2
    accountsIndexed = 0
    listeners = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
    passed = $false
    failureType = $null
    failure = $null
}
$process = $null
$drillExecutableIdentity = $null
$stdoutTask = $null
$stderrTask = $null
$stdoutCancellationSource = $null
$stderrCancellationSource = $null
$credentials = @{}
$passwords = @()
$failureRecord = $null
$terminationTimeoutMilliseconds = 5000
$quarantineRequired = $false
$quarantineReason = $null
$outputReadersConfirmed = $false
$restoreDrillProcessIdentityVerified = $false
$restoreDrillProcessId = 0
$restoreDrillProcessStartTimeFileTimeUtc = 0

try {
    $result.approvedServerExecutableSha256 = Get-ApprovedServerExecutableHash
    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $latest = Get-ChildItem -LiteralPath $layout.Backups -Directory -Filter 'state-*' -ErrorAction SilentlyContinue |
            Where-Object Name -NotMatch '\.partial-' |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if (-not $latest) {
            throw 'No state backup exists for the restore drill'
        }
        $BackupPath = $latest.FullName
    }

    # Record the exact attempted input before semantic validation, so failed as
    # well as successful drills remain bound to their manifest bytes.
    $attemptedBackup = (Resolve-Path -LiteralPath $BackupPath).Path
    Assert-PathWithinRoot -Path $attemptedBackup -Root $layout.Backups | Out-Null
    $result.backup = Split-Path -Leaf $attemptedBackup
    $attemptedManifest = Join-Path $attemptedBackup 'manifest.json'
    if (Test-Path -LiteralPath $attemptedManifest -PathType Leaf) {
        $attemptedManifestSnapshot = Read-PSOBBRecoveryManifestSnapshot `
            -Path $attemptedManifest -Root $attemptedBackup
        $result.backupManifestSha256 = [string]$attemptedManifestSnapshot.Sha256
    }

    $occupied = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object LocalPort -in @(11000, 12000, 12001))
    if ($occupied.Count -gt 0) {
        throw 'A required restore-drill loopback port is already in use'
    }

    $validation = & (Join-Path $PSScriptRoot 'Restore-PSOBB.ps1') `
        -BackupPath $BackupPath -RuntimeRoot $layout.Root -ValidateOnly
    $resolvedBackup = $validation.BackupPath
    if (($result.backupManifestSha256 -cne $validation.ManifestSha256) -or
        ($result.approvedServerExecutableSha256 -cne $validation.ApprovedServerExecutableSha256)) {
        throw 'Restore validation returned evidence that differs from the attempted-input binding'
    }
    $manifestSnapshot = Read-PSOBBRecoveryManifestSnapshot `
        -Path (Join-Path $resolvedBackup 'manifest.json') -Root $resolvedBackup
    if ($manifestSnapshot.Sha256 -cne $validation.ManifestSha256) {
        throw 'The validated recovery manifest changed before drill staging'
    }
    $manifest = $manifestSnapshot.Value
    $result.clientPatchProfile = $validation.ClientPatchProfile
    $result.clientPatchPolicySha256 = $validation.ClientPatchPolicySha256
    $result.clientPatchConfigSha256 = [string]$validation.ClientPatchConfigSha256
    $result.installationRecordSha256 = [string]$validation.InstallationRecordSha256

    New-Item -ItemType Directory -Path $drillServer -Force | Out-Null

    # Build an ephemeral server scaffold. Every copied file is hashed before copy
    # and verified after copy; live state is excluded and replaced only from the
    # already validated schema-v3 backup entries below.
    $allSourceItems = @(Get-ChildItem -Force -LiteralPath $layout.Server -Recurse)
    $scaffoldOrdinal = 0
    foreach ($sourceItem in $allSourceItems) {
        $scaffoldOrdinal++
        if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Stable server scaffold item $scaffoldOrdinal is a reparse point"
        }
    }
    foreach ($sourceDirectory in @($allSourceItems | Where-Object PSIsContainer | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($layout.Server, $sourceDirectory.FullName).Replace('\', '/')
        if (-not (Test-IsStatePath $relative)) {
            $destination = Assert-PathWithinRoot -Path (Join-Path $drillServer ($relative.Replace('/', '\'))) -Root $workRoot
            New-Item -ItemType Directory -Path $destination -Force | Out-Null
        }
    }
    foreach ($sourceFile in @($allSourceItems | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($layout.Server, $sourceFile.FullName).Replace('\', '/')
        if (Test-IsStatePath $relative) {
            continue
        }
        $sourceHash = Get-LowerSha256 $sourceFile.FullName
        $destination = Assert-PathWithinRoot -Path (Join-Path $drillServer ($relative.Replace('/', '\'))) -Root $workRoot
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $sourceFile.FullName -Destination $destination
        if (((Get-Item -LiteralPath $destination).Length -ne $sourceFile.Length) -or
            ((Get-LowerSha256 $destination) -ne $sourceHash)) {
            throw "Restore-drill server scaffold copy verification failed: $relative"
        }
        $result.serverScaffoldFilesVerified++
    }

    foreach ($name in @('licenses', 'players', 'teams')) {
        New-Item -ItemType Directory -Path (Join-Path $drillServer ('system\' + $name)) -Force | Out-Null
    }
    $backupOrdinal = 0
    foreach ($entry in @($manifest.files)) {
        $backupOrdinal++
        $backupCategory = if ([string]$entry.path -match
                '^system/(licenses|players|teams)/') {
            $Matches[1]
        } else { 'Stable metadata' }
        $backupLabel = "$backupCategory item $backupOrdinal"
        $source = Assert-PathWithinRoot -Path (Join-Path $resolvedBackup (([string]$entry.path).Replace('/', '\'))) -Root $resolvedBackup
        $destinationRoot = if ([string]$entry.path -eq 'stable/installation.json') {
            $workRoot
        } else {
            $drillServer
        }
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $destinationRoot (([string]$entry.path).Replace('/', '\'))) `
            -Root $workRoot
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        [void](Copy-PSOBBRedactedRecoveryFile `
                -Source $source -SourceRoot $resolvedBackup `
                -Destination $destination -DestinationRoot $workRoot `
                -ExpectedLength ([long]$entry.size) `
                -ExpectedSha256 ([string]$entry.sha256) `
                -Label $backupLabel)
    }

    $drillPatchState = Assert-PSOBBClientPatchStateCoherent `
        -ConfigPath (Join-Path $drillServer 'system\config.json') `
        -InstallRecordPath (Join-Path $workRoot 'stable\installation.json') `
        -InstallationId ([string]$manifest.clientPatchState.installationId) `
        -RuntimeRoot $layout.Root
    if (($drillPatchState.Profile -cne $result.clientPatchProfile) -or
        ($drillPatchState.PolicySha256 -cne $result.clientPatchPolicySha256) -or
        ($drillPatchState.ConfigSha256 -cne $result.clientPatchConfigSha256) -or
        ($drillPatchState.InstallationSha256 -cne $result.installationRecordSha256)) {
        throw 'Restore-drill client-patch state differs from its validated backup manifest'
    }

    $drillExecutable = Join-Path $drillServer 'newserv-windows.exe'
    $drillExecutableIdentity = Open-PSOBBRestoreDrillExecutableIdentity `
        -Path $drillExecutable -Root $workRoot `
        -ExpectedSha256 $result.approvedServerExecutableSha256
    $result.serverExecutableSha256 =
        [string]$drillExecutableIdentity.Sha256

    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $layout.Secrets -Root $layout.Root -Kind Directory `
            -Label 'protected credential root')
    if (-not (Test-PSOBBProtectedAcl -Path $layout.Secrets)) {
        throw 'Protected credential root does not have its exact ACL'
    }
    $credentialOrdinal = 0
    foreach ($role in @('admin', 'player')) {
        $credentialOrdinal++
        $path = Join-Path $layout.Secrets ($role + '.credential.clixml')
        $credentialLabel = "credential role $credentialOrdinal"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            -not (Test-PSOBBProtectedAcl -Path $path)) {
            throw "$credentialLabel is missing or lacks its exact protected ACL"
        }
        $credentialSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
            -Path $path -Root $layout.Secrets -MaximumBytes 1MB `
            -IncludeBytes -Label $credentialLabel
        try {
            $credentialText = [System.Text.UTF8Encoding]::new(
                $false, $true).GetString([byte[]]$credentialSnapshot.Bytes)
            if ($credentialText.Length -gt 0 -and
                $credentialText[0] -eq [char]0xFEFF) {
                $credentialText = $credentialText.Substring(1)
            }
            $credentialValue = [System.Management.Automation.PSSerializer]::Deserialize(
                $credentialText)
            if ($credentialValue -isnot [System.Management.Automation.PSCredential]) {
                throw "$credentialLabel does not contain exactly one protected credential"
            }
            $credentials[$role] = $credentialValue
        } finally {
            if ($credentialSnapshot.Bytes) {
                [Array]::Clear(
                    [byte[]]$credentialSnapshot.Bytes, 0,
                    ([byte[]]$credentialSnapshot.Bytes).Length)
            }
        }
    }
    $expectedUserNames = @{
        admin = [string]$credentials.admin.UserName
        player = [string]$credentials.player.UserName
    }
    $passwords = [System.Collections.Generic.List[string]]::new()
    $passwords.Add($credentials.admin.GetNetworkCredential().Password)
    $passwords.Add($credentials.player.GetNetworkCredential().Password)
    # A restore drill may intentionally use a backup from before a password
    # rotation. Redact every verified BB license password in that backup, not
    # only the two current DPAPI-held credentials.
    $restoredUserNameCounts = [System.Collections.Generic.Dictionary[string, int]]::new(
        [System.StringComparer]::Ordinal)
    $licenseOrdinal = 0
    foreach ($licenseEntry in @($manifest.files | Where-Object path -match '^system/licenses/')) {
        $licenseOrdinal++
        $licenseLabel = "licenses item $licenseOrdinal"
        $licensePath = Join-Path $resolvedBackup (([string]$licenseEntry.path).Replace('/', '\'))
        [void](Add-PSOBBRecoveryBBLicenseRedactionTerms `
                -Path $licensePath -Root $resolvedBackup `
                -UserNameCounts $restoredUserNameCounts `
                -Passwords $passwords -Label $licenseLabel)
    }
    $passwords = @($passwords | Where-Object {
            -not [string]::IsNullOrEmpty($_)
        } | Sort-Object -Unique)
    foreach ($role in @('admin', 'player')) {
        $expectedUserName = [string]$expectedUserNames[$role]
        if (-not $restoredUserNameCounts.ContainsKey($expectedUserName) -or
            $restoredUserNameCounts[$expectedUserName] -ne 1) {
            throw "Restored license files do not index exactly one expected $role BB username"
        }
        $result.accountsIndexed++
    }

    # This second shared census is intentionally adjacent to Process.Start so a
    # listener or named process that appeared during staging cannot race launch.
    Assert-PSOBBGlobalStoppedRuntime `
        -Layout $layout -Operation 'launching the isolated Stable restore-drill server' | Out-Null
    [void](Assert-PSOBBRestoreDrillExecutableIdentity `
            -Identity $drillExecutableIdentity)
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [string]$drillExecutableIdentity.Path
    $startInfo.WorkingDirectory = $drillServer
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Restored newserv process did not start'
    }
    $stdoutCancellationSource =
        [System.Threading.CancellationTokenSource]::new()
    $stderrCancellationSource =
        [System.Threading.CancellationTokenSource]::new()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync(
        $stdoutCancellationSource.Token)
    $stderrTask = $process.StandardError.ReadToEndAsync(
        $stderrCancellationSource.Token)
    $restoreDrillProcessId = [int]$process.Id
    $restoreDrillProcessStartTimeFileTimeUtc = [long](
        $process.StartTime.ToUniversalTime().ToFileTimeUtc())
    $result.processId = $restoreDrillProcessId
    $result.processStartTimeFileTimeUtc =
        $restoreDrillProcessStartTimeFileTimeUtc
    $launchedIdentity = Assert-PSOBBRestoreDrillLaunchedProcessIdentity `
        -Process $process -ExecutableIdentity $drillExecutableIdentity
    $restoreDrillProcessId = [int]$launchedIdentity.ProcessId
    $restoreDrillProcessStartTimeFileTimeUtc =
        [long]$launchedIdentity.ProcessStartTimeFileTimeUtc
    $restoreDrillProcessIdentityVerified = $true
    $result.processImageVerified = $true
    $result.processId = $restoreDrillProcessId
    $result.processStartTimeFileTimeUtc =
        $restoreDrillProcessStartTimeFileTimeUtc
    $result.serverExecutableSha256 =
        [string]$launchedIdentity.ServerExecutableSha256

    $ready = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) {
            break
        }
        $listeners = @(Get-NetTCPConnection -OwningProcess $process.Id -State Listen -ErrorAction SilentlyContinue)
        $observedEndpoints = @($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" } | Sort-Object -Unique)
        if ((@(Compare-Object @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001') $observedEndpoints)).Count -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        throw 'Restored server did not reach its exact loopback listener state'
    }

    $process.StandardInput.WriteLine('exit')
    $process.StandardInput.Flush()
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(30000)) {
        throw 'Restored server did not exit after verification'
    }
    $output = Receive-PSOBBRestoreDrillOutput `
        -StandardOutputTask $stdoutTask `
        -StandardErrorTask $stderrTask `
        -StandardOutputCancellation $stdoutCancellationSource `
        -StandardErrorCancellation $stderrCancellationSource `
        -TimeoutMilliseconds 5000
    if (-not $output.Confirmed) {
        $quarantineRequired = $true
        $quarantineReason = 'output-reader-unconfirmed'
        throw [System.TimeoutException]::new(
            'Restore-drill output readers did not complete within their independent finite deadlines')
    }
    $outputReadersConfirmed = $true
    $stdout = [string]$output.StandardOutput
    $stderr = [string]$output.StandardError
    foreach ($password in $passwords) {
        if (-not [string]::IsNullOrEmpty($password)) {
            $stdout = $stdout.Replace($password, '[REDACTED]')
            $stderr = $stderr.Replace($password, '[REDACTED]')
        }
    }
    if (($process.ExitCode -ne 0) -or (($stdout + $stderr) -match '(?m)^FAILED:')) {
        throw 'Restored server reported a startup failure'
    }
    $result.passed = $true
} catch {
    $failureRecord = $_
    $result.failureType = $_.Exception.GetType().FullName
    $result.failure = 'Restore drill failed at a protected validation or launch boundary'
} finally {
    if ($process) {
        $processExited = $false
        $termination = $null
        try {
            $processExited = [bool]$process.HasExited
        } catch {
        }
        if (-not $processExited) {
            $termination = Stop-PSOBBRestoreDrillProcess `
                -Process $process `
                -TerminationTimeoutMilliseconds $terminationTimeoutMilliseconds
            if (-not $termination.ConfirmedExited) {
                $quarantineRequired = $true
                $quarantineReason = 'exit-unconfirmed'
                if (-not $failureRecord) {
                    $failureRecord = [System.TimeoutException]::new(
                        'Restore-drill process exit was not confirmed')
                }
                $result.failureType = [System.TimeoutException].FullName
                $result.failure = (
                    'Restore-drill process exit was not confirmed within the ' +
                    'finite cleanup deadline; its isolated work tree is retained ' +
                    'beneath the protected drill root')
                $result.passed = $false
            }
        }
        if (-not $outputReadersConfirmed -and
            $stdoutTask -and $stderrTask -and
            $stdoutCancellationSource -and
            $stderrCancellationSource) {
            $cleanupOutput = Receive-PSOBBRestoreDrillOutput `
                -StandardOutputTask $stdoutTask `
                -StandardErrorTask $stderrTask `
                -StandardOutputCancellation $stdoutCancellationSource `
                -StandardErrorCancellation $stderrCancellationSource `
                -TimeoutMilliseconds 5000
            $outputReadersConfirmed = [bool]$cleanupOutput.Confirmed
            if (-not $outputReadersConfirmed) {
                $quarantineRequired = $true
                if (-not $quarantineReason) {
                    $quarantineReason = 'output-reader-unconfirmed'
                }
                if (-not $failureRecord) {
                    $failureRecord = [System.TimeoutException]::new(
                        'Restore-drill output-reader completion was not confirmed')
                }
                $result.failureType = [System.TimeoutException].FullName
                $result.failure = (
                    'Restore-drill output-reader completion was not ' +
                    'confirmed within independent finite deadlines; its ' +
                    'isolated work tree is retained')
                $result.passed = $false
            }
        }
    }
    foreach ($password in $passwords) {
        if (-not [string]::IsNullOrEmpty($password) -and $result.failure) {
            $result.failure = $result.failure.Replace($password, '[REDACTED]')
        }
    }
    $passwords = @()
    $credentials = @{}
    if ($quarantineRequired) {
        $result.quarantineReason = $quarantineReason
        $result.quarantineNextAction =
            $script:PSOBBRestoreDrillQuarantineNextAction
        try {
            if ($restoreDrillProcessId -lt 1 -or
                $restoreDrillProcessStartTimeFileTimeUtc -lt 1 -or
                [string]$result.serverExecutableSha256 -cnotmatch
                    '^[a-f0-9]{64}$') {
                throw 'A restore-drill quarantine requires one exact process identity'
            }
            if (-not $restoreDrillProcessIdentityVerified) {
                throw ('The launched process image was not verified against ' +
                    'the retained executable lease; its digest cannot be ' +
                    'published as a trusted process association')
            }
            $publication = Publish-PSOBBRestoreDrillQuarantine `
                -DrillRoot $drillRoot -BackupsRoot $layout.Backups `
                -ProcessId $restoreDrillProcessId `
                -ProcessStartTimeFileTimeUtc `
                    $restoreDrillProcessStartTimeFileTimeUtc `
                -ServerExecutableSha256 `
                    ([string]$result.serverExecutableSha256) `
                -TerminationTimeoutMilliseconds `
                    $terminationTimeoutMilliseconds `
                -Reason $quarantineReason
            $result.quarantinePublicationState =
                [string]$publication.PublicationState
        } catch {
            if (-not $failureRecord) {
                $failureRecord = $_
            }
            $result.failureType = $_.Exception.GetType().FullName
            $result.failure = (
                'Restore-drill quarantine publication failed; exact PID, ' +
                'start-time, executable-digest, reason, and next-action ' +
                'evidence remain in the protected drill result, and the ' +
                'unresolved protected work tree is retained')
            $result.quarantinePublicationState = 'failed-work-tree-retained'
            $result.passed = $false
        }
    }
    if ($drillExecutableIdentity) {
        Close-PSOBBTrustedExecutableLease -Identity $drillExecutableIdentity
        $drillExecutableIdentity = $null
    }
    if (-not $quarantineRequired -and
        (Test-Path -LiteralPath $workRoot)) {
        try {
            Remove-PSOBBRedactedRecoveryTree `
                -Path $workRoot -Root $drillRoot `
                -Label 'restore-drill work tree'
        } catch {
            if (-not $failureRecord) {
                $failureRecord = $_
                $result.failureType = $_.Exception.GetType().FullName
                $result.failure = 'Restore-drill work-tree cleanup failed'
            }
            $result.passed = $false
        }
    }
    if ($stdoutCancellationSource) {
        $stdoutCancellationSource.Dispose()
    }
    if ($stderrCancellationSource) {
        $stderrCancellationSource.Dispose()
    }
    if ($process -and $outputReadersConfirmed) {
        try {
            if ($process.HasExited) {
                $process.Dispose()
            }
        } catch {
            # Process cleanup has already been established by the bounded
            # identity-aware path above; disposal is best-effort only.
        }
    }
}

$result.completedAtUtc = [DateTime]::UtcNow.ToString('o')
try {
    Remove-DrillPayloads `
        -Layout $layout -Retention $ResultRetention `
        -CurrentDrillRoot $drillRoot `
        -PreserveCurrentPayload:$quarantineRequired
} catch {
    if (-not $failureRecord) {
        $failureRecord = $_
        $result.failureType = $_.Exception.GetType().FullName
        $result.failure = 'Historical restore-drill cleanup failed'
    }
    $result.passed = $false
}
[System.IO.File]::WriteAllText(
    $resultPath,
    ($result | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false))
Set-PSOBBProtectedAcl -Path $resultPath

if ($failureRecord) {
    throw $result.failure
}
[pscustomobject]@{
    Passed = $true
    Backup = $result.backup
    BackupManifestSha256 = $result.backupManifestSha256
    ApprovedServerExecutableSha256 = $result.approvedServerExecutableSha256
    ClientPatchProfile = $result.clientPatchProfile
    ClientPatchPolicySha256 = $result.clientPatchPolicySha256
    DrillRoot = $drillRoot
    AccountsIndexed = $result.accountsIndexed
    Listeners = $result.listeners -join ', '
}
} finally {
    try {
        if ($ownsMutex) {
            $mutex.ReleaseMutex()
        }
    } finally {
        try {
            if ($mutex) {
                $mutex.Dispose()
            }
        } finally {
            if ($clientOperationMutex) {
                Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
            }
        }
    }
}
