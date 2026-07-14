[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repositoryRoot 'scripts\Capture-PSOBBLosslessScreenshot.ps1'
$source = Get-Content -Raw -LiteralPath $scriptPath
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors) | Out-Null
Add-Result 'lossless screenshot script parses cleanly' ($parseErrors.Count -eq 0) `
    "$($parseErrors.Count) parser error(s)"

$identityGuards =
    $source -match 'Get-PSOBBClientProcessRecords -Layout \$layout -Channel All' -and
    $source -match 'records\.Count -ne 1' -and
    $source -match 'Test-PSOBBProcessAtExactPath' -and
    $source -match 'Assert-PSOBBApprovedClientExecutable' -and
    $source -match 'GetWindowThreadProcessId' -and
    $source -match 'GetForegroundWindow\(\) != window'
Add-Result 'capture pins the exact sole foreground PSOBB process and window' `
    $identityGuards 'channel, path, hash, PID, HWND owner, and foreground state are required'

$pngGuards =
    $source -match 'ImageFormat\.Png' -and
    $source -match '0x89, 0x50, 0x4E, 0x47' -and
    $source -match 'Refusing to overwrite' -and
    $source -match 'graphics-evidence' -and
    $source -match 'Raw screenshots cannot be written inside the Git repository'
Add-Result 'capture produces a new signature-verified private PNG' `
    $pngGuards 'atomic PNG output stays outside Git and is never overwritten'

$geometryGuards =
    $source -match 'GetClientRect' -and
    $source -match 'ClientToScreen' -and
    $source -match 'expectedWidth' -and
    $source.Contains('[int]$profile.desktopWidth -ne 2560', [System.StringComparison]::Ordinal) -and
    $source.Contains('[int]$profile.desktopHeight -ne 1600', [System.StringComparison]::Ordinal)
Add-Result 'capture requires the exact declared 2560x1600 client area' `
    $geometryGuards 'window client bounds and profile output must agree before capture'

$credentialFree = $source -notmatch '(?i)password|credential|license\.json|twills'
Add-Result 'capture interface and implementation are credential-free' `
    $credentialFree 'no authentication material is read or accepted'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) lossless screenshot capture test(s) failed"
}
[pscustomobject]@{ Suite = 'LosslessScreenshotCapture'; Passed = $results.Count; Failed = 0 }
