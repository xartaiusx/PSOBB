[CmdletBinding()]
param(
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$Channel = 'Stable',
    [ValidateSet('ProfileDefault', 'Borderless', 'Resizable')]
    [string]$WindowMode = 'ProfileDefault',
    [switch]$PreserveForeground,
    [string]$RuntimeRoot,
    [Parameter(DontShow)][switch]$ClientOperationLockHeld
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Set-PSOBBAdminCredential.ps1')

function Wait-PSOBBClientStartupDelay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 60000)]
        [int]$DelayMilliseconds,
        [Parameter(Mandatory)][IntPtr]$ForegroundTarget,
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ClientProcessId,
        [switch]$TrackForeground
    )

    if (-not $TrackForeground) {
        Start-Sleep -Milliseconds $DelayMilliseconds
        return $ForegroundTarget
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $DelayMilliseconds) {
        $remaining = $DelayMilliseconds - [int]$stopwatch.ElapsedMilliseconds
        Start-Sleep -Milliseconds ([Math]::Min(100, [Math]::Max(1, $remaining)))
        $ForegroundTarget = Update-PSOBBNonClientForegroundWindowTarget `
            -CurrentTarget $ForegroundTarget `
            -ClientProcessId $ClientProcessId
    }
    $ForegroundTarget
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$clientOperationMutex = if ($ClientOperationLockHeld) {
    $null
} else {
    Enter-PSOBBClientOperationLock -Layout $layout
}
try {
$clientExecutable = Get-PSOBBClientExecutablePath -Layout $layout -Channel $Channel
$clientRoot = Split-Path -Parent $clientExecutable
$clientIdentity = Assert-PSOBBApprovedClientExecutable -Path $clientExecutable

$running = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel All)
if ($running.Count -gt 0) {
    throw "An approved PSOBB client is already running (PID(s): $($running.ProcessId -join ', '))"
}

$clientProfile = if ($Channel -eq 'LocalLab' -and
    $WindowMode -ne 'ProfileDefault') {
    # The presentation-owner ASI reads its mode before creating the game
    # window. Materialize an explicit launcher/CLI choice while stopped and
    # under this operation lock; the lifecycle continues to observe only.
    (Set-PSOBBLocalLabClientWindowMode `
        -Layout $layout `
        -WindowMode $WindowMode `
        -ClientOperationLockHeld).Profile
} elseif ($Channel -eq 'LocalLab') {
    Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
} else {
    & (Join-Path $PSScriptRoot 'Test-PSOBBClientGraphics.ps1') `
        -Channel $Channel `
        -RuntimeRoot $layout.Root | Out-Null
    Get-Content -Raw -LiteralPath (Join-Path $clientRoot 'client-profile.json') |
        ConvertFrom-Json -Depth 10
}
$useManagedPresentation =
    ([int]$clientProfile.schemaVersion -ge 4) -and
    (($Channel -eq 'LocalLab') -or
     ([string]$clientProfile.graphicsPreset -in @('HighFidelity2560x1600', 'Ultra3840x2880'))) -and
    ([int]$clientProfile.desktopWidth -eq 2560) -and
    ([int]$clientProfile.desktopHeight -eq 1600)
$selectedWindowMode = if ($WindowMode -eq 'ProfileDefault') {
    [string]$clientProfile.defaultWindowMode
} else {
    $WindowMode
}
$presentationOwner = if (
    $clientProfile.PSObject.Properties.Name -contains 'presentationOwner' -and
    -not [string]::IsNullOrWhiteSpace([string]$clientProfile.presentationOwner)) {
    [string]$clientProfile.presentationOwner
} else {
    'lifecycle'
}
if ($presentationOwner -notin @('application', 'client-patch', 'lifecycle')) {
    throw "The client profile declares an unsupported presentation owner: $presentationOwner"
}
if ($useManagedPresentation -and ($selectedWindowMode -notin @('Borderless', 'Resizable'))) {
    throw 'The client profile does not contain a supported default window mode'
}
if ((-not $useManagedPresentation) -and ($WindowMode -ne 'ProfileDefault')) {
    throw 'Window-mode overrides require a managed high-fidelity dgVoodoo profile'
}

$process = $null
$graphicsRegistryTransaction = $null
$startupStopwatch = [Diagnostics.Stopwatch]::StartNew()
$previousForegroundWindow = if ($PreserveForeground) {
    Get-PSOBBForegroundWindowHandle
} else {
    [IntPtr]::Zero
}
try {
    # Apply only the profile-owned GRAPHICCTRL value. Remembered ACCOUNT and
    # PASSWORD values are outside this transaction and remain untouched.
    $graphicsRegistryTransaction = Set-PSOBBClientNativeGraphics `
        -Layout $layout `
        -Profile $clientProfile
    $process = Start-PSOBBClientProcess `
        -ClientExecutable $clientExecutable `
        -WorkingDirectory $clientRoot `
        -PreserveForeground:$PreserveForeground

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds $(if ($PreserveForeground) { 100 } else { 200 })
        $process.Refresh()
        if ($process.HasExited) {
            throw "The PSOBB client exited during startup with code $($process.ExitCode)"
        }
        if ($PreserveForeground) {
            $previousForegroundWindow = Update-PSOBBNonClientForegroundWindowTarget `
                -CurrentTarget $previousForegroundWindow `
                -ClientProcessId $process.Id
        }
    } while (($process.MainWindowHandle -eq [IntPtr]::Zero) -and
        ([DateTime]::UtcNow -lt $deadline))

    if ($process.MainWindowHandle -eq [IntPtr]::Zero -or
        -not (Test-PSOBBProcessAtExactPath `
            -Process $process `
            -Name 'Psobb' `
            -ExpectedPath $clientExecutable)) {
        throw 'The PSOBB client did not create a verified game window during startup'
    }

    if ($PreserveForeground) {
        # Restore promptly after the first verified window, then keep sampling
        # for a newer user-selected application while the client settles.
        Restore-PSOBBForegroundWindowAfterClientLaunch `
            -Process $process `
            -PreviousWindow $previousForegroundWindow | Out-Null
    }

    $presentation = $null
    if ($useManagedPresentation) {
        $previousForegroundWindow = Wait-PSOBBClientStartupDelay `
            -DelayMilliseconds 3000 `
            -ForegroundTarget $previousForegroundWindow `
            -ClientProcessId $process.Id `
            -TrackForeground:$PreserveForeground
        if ($presentationOwner -eq 'client-patch') {
            # Observe only. Mutating a window already owned by the enhancement
            # module can race its device-reset and style-recreation logic.
            $previousForegroundWindow = Wait-PSOBBClientStartupDelay `
                -DelayMilliseconds 5000 `
                -ForegroundTarget $previousForegroundWindow `
                -ClientProcessId $process.Id `
                -TrackForeground:$PreserveForeground
            $presentation = Get-PSOBBClientWindowPresentation -Process $process
            if ($selectedWindowMode -eq 'Borderless') {
                if (($presentation.X -ne 0) -or ($presentation.Y -ne 0) -or
                    ($presentation.Width -ne 2560) -or ($presentation.Height -ne 1600) -or
                    (($presentation.Style -band 0x00C40000L) -ne 0)) {
                    throw 'The client-patch-owned window did not present as exact 2560x1600 borderless'
                }
            } else {
                $resizablePolicy = Get-PSOBBClientPatchResizablePresentationPolicy `
                    -Profile $clientProfile `
                    -Presentation $presentation
                if ($resizablePolicy -ceq 'CorrectLocalReference') {
                    # pso_widescreen Windowed=1 supplies the movable frame but
                    # currently chooses the render/output dimensions as its
                    # initial client area. Correct that one settled local-only
                    # reference window to the hash-bound profile dimensions.
                    # Other client patches, already-correct windows, and the
                    # future project enhancement remain observation-only.
                    if (-not (Test-PSOBBProcessAtExactPath `
                        -Process $process `
                        -Name 'Psobb' `
                        -ExpectedPath $clientExecutable)) {
                        throw 'The LocalLab reference process identity changed before presentation correction'
                    }
                    Set-PSOBBClientResizablePresentation `
                        -Process $process `
                        -ClientWidth ([int]$clientProfile.resizableClientWidth) `
                        -ClientHeight ([int]$clientProfile.resizableClientHeight) | Out-Null
                    $previousForegroundWindow = Wait-PSOBBClientStartupDelay `
                        -DelayMilliseconds 750 `
                        -ForegroundTarget $previousForegroundWindow `
                        -ClientProcessId $process.Id `
                        -TrackForeground:$PreserveForeground
                    $presentation = Get-PSOBBClientWindowPresentation -Process $process
                }
                $aspect = [double]$presentation.ClientWidth / [double]$presentation.ClientHeight
                if ($resizablePolicy -ceq 'Reject' -or
                    $presentation.ClientWidth -ne [int]$clientProfile.resizableClientWidth -or
                    $presentation.ClientHeight -ne [int]$clientProfile.resizableClientHeight -or
                    [Math]::Abs($aspect - 1.6) -gt 0.001 -or
                    (($presentation.Style -band 0x00C40000L) -ne 0x00C40000L)) {
                    throw 'The client-patch-owned window did not present as a movable 16:10 resizable window'
                }
            }
        } else {
            foreach ($attempt in 1..2) {
                $presentation = if ($selectedWindowMode -eq 'Borderless') {
                    Set-PSOBBClientBorderlessPresentation `
                        -Process $process `
                        -Width 2560 `
                        -Height 1600
                } else {
                    Set-PSOBBClientResizablePresentation `
                        -Process $process `
                        -ClientWidth ([int]$clientProfile.resizableClientWidth) `
                        -ClientHeight ([int]$clientProfile.resizableClientHeight)
                }
                if ($attempt -eq 1) {
                    $previousForegroundWindow = Wait-PSOBBClientStartupDelay `
                        -DelayMilliseconds 5000 `
                        -ForegroundTarget $previousForegroundWindow `
                        -ClientProcessId $process.Id `
                        -TrackForeground:$PreserveForeground
                }
            }
        }
    }

    $foreground = if ($PreserveForeground) {
        $previousForegroundWindow = Update-PSOBBNonClientForegroundWindowTarget `
            -CurrentTarget $previousForegroundWindow `
            -ClientProcessId $process.Id
        Restore-PSOBBForegroundWindowAfterClientLaunch `
            -Process $process `
            -PreviousWindow $previousForegroundWindow
    } else {
        [pscustomobject]@{
            Status = 'NotRequested'
            Preserved = $false
        }
    }
    if ($PreserveForeground -and -not $foreground.Preserved) {
        Write-Warning "PSOBB started successfully, but Windows did not restore the previous foreground window ($($foreground.Status)). Use Alt+Tab once to continue multitasking."
    }
    $startupStopwatch.Stop()

    $result = [pscustomobject]@{
        Started = $true
        Channel = $Channel
        Pid = $process.Id
        Executable = $clientExecutable
        WindowTitle = $process.MainWindowTitle
        RunAsInvoker = $true
        PreserveForeground = [bool]$PreserveForeground
        ForegroundPreserved = [bool]$foreground.Preserved
        ForegroundStatus = [string]$foreground.Status
        StartupElapsedMilliseconds = [Math]::Round(
            $startupStopwatch.Elapsed.TotalMilliseconds, 3)
        WindowMode = if ($presentation) { $selectedWindowMode } else { 'ApplicationControlled' }
        PresentationOwner = $presentationOwner
        NativeGraphicsPresetId = [string]$graphicsRegistryTransaction.PresetId
        GraphicCtrlSha256 = [string]$graphicsRegistryTransaction.GraphicCtrlSha256
        GraphicCtrlBackupPath = $graphicsRegistryTransaction.BackupPath
        Borderless = ($null -ne $presentation) -and ($selectedWindowMode -eq 'Borderless')
        WindowX = if ($presentation) { $presentation.X } else { $null }
        WindowY = if ($presentation) { $presentation.Y } else { $null }
        WindowWidth = if ($presentation) { $presentation.Width } else { $null }
        WindowHeight = if ($presentation) { $presentation.Height } else { $null }
        ClientWidth = if ($presentation) { $presentation.ClientWidth } else { $null }
        ClientHeight = if ($presentation) { $presentation.ClientHeight } else { $null }
    }
    $profilePath = Join-Path $clientRoot 'client-profile.json'
    $receiptRoot = Join-Path $layout.Logs 'client-startup'
    $receiptRoot = Assert-PathWithinRoot -Path $receiptRoot -Root $layout.Root
    [void][IO.Directory]::CreateDirectory($receiptRoot)
    $receiptRoot = Assert-PathWithinRoot -Path $receiptRoot -Root $layout.Root
    Set-PSOBBProtectedAcl -Path $receiptRoot
    $receiptPath = Join-Path $receiptRoot (
        $process.StartTime.ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') +
        "-$($process.Id).json")
    if (Test-Path -LiteralPath $receiptPath) {
        throw "The unique client-startup receipt already exists: $receiptPath"
    }
    $receipt = [ordered]@{
        schemaVersion = 1
        completedAtUtc = [DateTime]::UtcNow.ToString('o')
        channel = $Channel
        profileId = if ($clientProfile.PSObject.Properties.Name -contains 'profileId') {
            [string]$clientProfile.profileId
        } else { $null }
        materializedProfileSha256 = Get-LowerSha256 -Path $profilePath
        configurationSha256 = if (
            $clientProfile.PSObject.Properties.Name -contains 'configurationSha256') {
            [string]$clientProfile.configurationSha256
        } else { $null }
        processId = $process.Id
        processStartTimeUtc = $process.StartTime.ToUniversalTime().ToString('o')
        executableSize = $clientIdentity.Size
        executableSha256 = $clientIdentity.Sha256
        startupElapsedMilliseconds = $result.StartupElapsedMilliseconds
        foregroundPreserved = $result.ForegroundPreserved
        windowMode = $result.WindowMode
        window = [ordered]@{
            x = $result.WindowX
            y = $result.WindowY
            width = $result.WindowWidth
            height = $result.WindowHeight
            clientWidth = $result.ClientWidth
            clientHeight = $result.ClientHeight
        }
        nativeGraphicsPresetId = $result.NativeGraphicsPresetId
        graphicCtrlSha256 = $result.GraphicCtrlSha256
    }
    $temporaryReceipt = $receiptPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText(
            $temporaryReceipt,
            ($receipt | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $temporaryReceipt
        Move-Item -LiteralPath $temporaryReceipt -Destination $receiptPath
        Set-PSOBBProtectedAcl -Path $receiptPath
    } finally {
        if (Test-Path -LiteralPath $temporaryReceipt) {
            Remove-Item -LiteralPath $temporaryReceipt -Force
        }
    }
    $result | Add-Member -NotePropertyName StartupReceiptPath `
        -NotePropertyValue $receiptPath
    $result | Add-Member -NotePropertyName StartupReceiptSha256 `
        -NotePropertyValue (Get-LowerSha256 -Path $receiptPath)
    $result
} catch {
    $startupStopwatch.Stop()
    $startupError = $_
    if ($process -and -not $process.HasExited) {
        try {
            if (Test-PSOBBProcessAtExactPath `
                -Process $process `
                -Name 'Psobb' `
                -ExpectedPath $clientExecutable) {
                $process.Kill($true)
                $process.WaitForExit(5000) | Out-Null
            }
        } catch { }
    }
    if ($graphicsRegistryTransaction -and $graphicsRegistryTransaction.Applied) {
        try {
            Restore-PSOBBClientGraphicCtrlBackup `
                -Layout $layout `
                -BackupPath $graphicsRegistryTransaction.BackupPath | Out-Null
        } catch {
            throw ('PSOBB client startup failed and the native graphics registry ' +
                "transaction also failed to roll back. Startup: $($startupError.Exception.Message) " +
                "Rollback: $($_.Exception.Message)")
        }
    }
    throw $startupError
}
} finally {
    if ($clientOperationMutex) {
        Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
    }
}
