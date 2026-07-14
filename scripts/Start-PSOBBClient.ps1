[CmdletBinding()]
param(
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$Channel = 'Stable',
    [ValidateSet('ProfileDefault', 'Borderless', 'Resizable')]
    [string]$WindowMode = 'ProfileDefault',
    [string]$RuntimeRoot,
    [Parameter(DontShow)][switch]$ClientOperationLockHeld
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Set-PSOBBAdminCredential.ps1')

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
Assert-PSOBBApprovedClientExecutable -Path $clientExecutable | Out-Null

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
try {
    $process = Start-PSOBBClientProcess `
        -ClientExecutable $clientExecutable `
        -WorkingDirectory $clientRoot

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 200
        $process.Refresh()
        if ($process.HasExited) {
            throw "The PSOBB client exited during startup with code $($process.ExitCode)"
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

    $presentation = $null
    if ($useManagedPresentation) {
        Start-Sleep -Seconds 3
        if ($presentationOwner -eq 'client-patch') {
            # Observe only. Mutating a window already owned by the enhancement
            # module can race its device-reset and style-recreation logic.
            Start-Sleep -Seconds 5
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
                    Start-Sleep -Milliseconds 750
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
                    Start-Sleep -Seconds 5
                }
            }
        }
    }

    [pscustomobject]@{
        Started = $true
        Channel = $Channel
        Pid = $process.Id
        Executable = $clientExecutable
        WindowTitle = $process.MainWindowTitle
        RunAsInvoker = $true
        WindowMode = if ($presentation) { $selectedWindowMode } else { 'ApplicationControlled' }
        PresentationOwner = $presentationOwner
        Borderless = ($null -ne $presentation) -and ($selectedWindowMode -eq 'Borderless')
        WindowX = if ($presentation) { $presentation.X } else { $null }
        WindowY = if ($presentation) { $presentation.Y } else { $null }
        WindowWidth = if ($presentation) { $presentation.Width } else { $null }
        WindowHeight = if ($presentation) { $presentation.Height } else { $null }
        ClientWidth = if ($presentation) { $presentation.ClientWidth } else { $null }
        ClientHeight = if ($presentation) { $presentation.ClientHeight } else { $null }
    }
} catch {
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
    throw
}
} finally {
    if ($clientOperationMutex) {
        Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
    }
}
