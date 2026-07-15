[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
$clientPath = Join-Path $repositoryRoot 'scripts\Start-PSOBBClient.ps1'
$sessionPath = Join-Path $repositoryRoot 'scripts\Start-PSOBBSession.ps1'
$credentialPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1'
$commonSource = Get-Content -Raw -LiteralPath $commonPath
$clientSource = Get-Content -Raw -LiteralPath $clientPath
$sessionSource = Get-Content -Raw -LiteralPath $sessionPath
$credentialSource = Get-Content -Raw -LiteralPath $credentialPath
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail
    )

    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

foreach ($scriptPath in @($commonPath, $clientPath, $sessionPath, $credentialPath)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors) | Out-Null
    Add-Result `
        -Name "$(Split-Path -Leaf $scriptPath) parses cleanly" `
        -Passed ($parseErrors.Count -eq 0) `
        -Detail "$($parseErrors.Count) parser error(s)"
}

$presentationNoActivate =
    $commonSource -match 'private const uint SwpNoActivate = 0x0010;' -and
    ([regex]::Matches(
        $commonSource,
        'SwpFrameChanged\s*\|\s*SwpNoActivate\s*\|\s*SwpNoZOrder\s*\|\s*SwpNoOwnerZOrder').Count -eq 2)
Add-Result `
    -Name 'both managed window modes preserve foreground activation' `
    -Passed $presentationNoActivate `
    -Detail 'borderless and resizable SetWindowPos calls use SWP_NOACTIVATE without changing z-order'

$conditionalRestoration =
    $commonSource -match 'currentWindow != clientWindow' -and
    $commonSource -match 'previousProcessId == clientProcessId' -and
    $commonSource -match 'SetForegroundWindow\(previousWindow\)' -and
    $commonSource -match 'return "UserSelectedAnotherWindow";'
Add-Result `
    -Name 'foreground restoration is exact-window and user-selection aware' `
    -Passed $conditionalRestoration `
    -Detail 'restoration occurs only when the verified client still owns foreground'

$latestTargetTracking =
    $commonSource -match 'CaptureLatestNonClientForegroundWindow' -and
    $commonSource -match 'currentProcessId != unchecked\(\(uint\)clientProcessId\)' -and
    $commonSource -match 'function Update-PSOBBNonClientForegroundWindowTarget' -and
    $clientSource -match 'function Wait-PSOBBClientStartupDelay' -and
    $clientSource -match 'Start-Sleep -Milliseconds \(\[Math\]::Min\(100,' -and
    ([regex]::Matches(
        $clientSource,
        'Update-PSOBBNonClientForegroundWindowTarget').Count -ge 3)
Add-Result `
    -Name 'startup tracks the latest non-client foreground target' `
    -Passed $latestTargetTracking `
    -Detail 'bounded 100 ms sampling retains a newer user-selected application across later client focus changes'

$bestEffortRestoration =
    $commonSource -match "if \(\`$Process\.HasExited\) \{" -and
    $commonSource -notmatch
        'The PSOBB client has no live main window for foreground restoration' -and
    $commonSource -match 'return "ClientWindowUnavailable";' -and
    ([regex]::Matches(
        $clientSource,
        'Restore-PSOBBForegroundWindowAfterClientLaunch').Count -eq 2)
Add-Result `
    -Name 'focus restoration is prompt, retried, and non-destructive' `
    -Passed $bestEffortRestoration `
    -Detail 'an initial verified-window restore is retried after presentation, while a transient missing HWND becomes a warning status'

$clientContract =
    $clientSource -match '\[switch\]\$PreserveForeground' -and
    $clientSource -match 'Get-PSOBBForegroundWindowHandle' -and
    $clientSource -match 'Restore-PSOBBForegroundWindowAfterClientLaunch' -and
    $clientSource -match 'ForegroundStatus\s*=\s*\[string\]\$foreground\.Status'
Add-Result `
    -Name 'client start exposes an opt-in preserve-foreground contract' `
    -Passed $clientContract `
    -Detail 'default launch behavior remains unchanged when the switch is absent'

$sessionContract =
    $sessionSource -match '\[switch\]\$PreserveForeground' -and
    $sessionSource -match '-PreserveForeground:\$PreserveForeground' -and
    $sessionSource -match 'ForegroundPreserved\s*=\s*\[bool\]\$clientResult\.ForegroundPreserved'
Add-Result `
    -Name 'session start forwards and reports foreground preservation' `
    -Passed $sessionContract `
    -Detail 'server-plus-client starts share the same opt-in behavior'

$detachedClientStart =
    $credentialSource -match 'CreateProcessW\(' -and
    $credentialSource -match 'false,\s*\r?\n\s*CreateNoWindow,' -and
    $credentialSource -match 'ShowWindow = preserveForeground \? SwShowNoActivate : SwShowNormal' -and
    $credentialSource -match '\[PSOBBClientProcessLauncher\]::Start\('
Add-Result `
    -Name 'client process detaches caller capture handles' `
    -Passed $detachedClientStart `
    -Detail 'CreateProcess disables handle inheritance and uses no console'

. $commonPath
Initialize-PSOBBWindowPresentationType
$unavailableStatus = [PSOBBWindowPresentation]::RestoreForegroundIfClientActive(
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    0)
Add-Result `
    -Name 'invalid foreground handles fail closed without activation' `
    -Passed ($unavailableStatus -ceq 'PreviousWindowUnavailable') `
    -Detail $unavailableStatus

$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    throw "$($failed.Count) background-launch test(s) failed"
}

[pscustomobject]@{
    Suite = 'BackgroundLaunch'
    Passed = $results.Count
    Failed = 0
}
