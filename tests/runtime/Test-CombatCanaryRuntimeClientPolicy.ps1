[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Name, [bool]$Passed) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed })
}

function New-Entry([string]$Path, [long]$Size, [char]$HashDigit) {
    [pscustomobject]@{
        path = $Path
        size = $Size
        sha256 = ([string]$HashDigit) * 64
    }
}

$base = @(
    (New-Entry 'Psobb.exe' 4096 'a'),
    (New-Entry 'data/unit.bin' 512 'b'),
    (New-Entry 'GameGuard/0npgg.erl' 128 'c'),
    (New-Entry 'GameGuard/0npgl.erl' 192 'd'),
    (New-Entry 'GameGuard/npgl.erl' 256 'e'),
    (New-Entry 'GameGuard/npgl2.erl' 320 '9'),
    (New-Entry 'log/error.log' 0 'f'),
    (New-Entry 'log/generic.log' 0 '0'),
    (New-Entry 'log/spec.log' 32 '1'))
$profile = New-Entry 'client-profile.json' 96 '2'
$exact = @($base + $profile)

$authority = Get-PSOBBGameplayObservationAuthority `
    -RepositoryRoot $repositoryRoot
Add-Result 'tracked gameplay build and loader authorities are exact' (
    [long]$authority.ModuleSize -eq 239104 -and
    [string]$authority.ModuleSha256 -ceq
        '93288dcf8d2a70f72f27be9010f193808eaaa27f6b837517074dbee23859f9be' -and
    [long]$authority.LoaderSize -eq 5413776 -and
    [string]$authority.LoaderSha256 -ceq
        'c7277e832f6f07af64903a99ecebab2936260cbf55eda70787c5d7b2d5b9fe60')
$configurationIdentity = Get-PSOBBGameplayObservationConfigurationIdentity
$overlayBinding = [pscustomobject]@{
    loaderPath = 'runtime/client/dinput8.dll'
    loaderSize = [long]$authority.LoaderSize
    loaderSha256 = [string]$authority.LoaderSha256
    modulePath = 'runtime/client/plugins/PSOBB.Gameplay.asi'
    moduleSize = [long]$authority.ModuleSize
    moduleSha256 = [string]$authority.ModuleSha256
    configurationPath = 'runtime/client/plugins/PSOBB.Gameplay.ini'
    configurationSize = [long]$configurationIdentity.Size
    configurationSha256 = [string]$configurationIdentity.Sha256
}
$compiledOverlay = @(Get-PSOBBCombatCanaryGameplayOverlayEntries `
        -GameplayOverlay $overlayBinding -ClientRoot $repositoryRoot)
Add-Result 'schema-2 gameplay binding compiles to three exact client entries' (
    $compiledOverlay.Count -eq 3 -and
    [string]::Join(',', @($compiledOverlay.path)) -ceq
        'dinput8.dll,plugins/PSOBB.Gameplay.asi,plugins/PSOBB.Gameplay.ini')
$noncanonicalConfigurationRejected = $false
try {
    $invalidOverlay = $overlayBinding.PSObject.Copy()
    $invalidOverlay.configurationSha256 = '9' * 64
    Get-PSOBBCombatCanaryGameplayOverlayEntries `
        -GameplayOverlay $invalidOverlay -ClientRoot $repositoryRoot | Out-Null
} catch {
    $noncanonicalConfigurationRejected =
        $_.Exception.Message -match 'not canonical'
}
Add-Result 'noncanonical observation configuration is rejected' (
    $noncanonicalConfigurationRejected)

$hardLinkFixture = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-gameplay-overlay-link-' + [Guid]::NewGuid().ToString('N'))
try {
    $plugins = Join-Path $hardLinkFixture 'plugins'
    [void][System.IO.Directory]::CreateDirectory($plugins)
    $loaderPath = Join-Path $hardLinkFixture 'dinput8.dll'
    $moduleSource = Join-Path $hardLinkFixture 'module-source.bin'
    $modulePath = Join-Path $plugins 'PSOBB.Gameplay.asi'
    $configurationPath = Join-Path $plugins 'PSOBB.Gameplay.ini'
    [System.IO.File]::WriteAllBytes($loaderPath, [byte[]](1, 2, 3))
    [System.IO.File]::WriteAllBytes($moduleSource, [byte[]](4, 5, 6))
    New-Item -ItemType HardLink -Path $modulePath `
        -Target $moduleSource | Out-Null
    [System.IO.File]::WriteAllText(
        $configurationPath, $configurationIdentity.Text,
        [System.Text.UTF8Encoding]::new($false))
    $hardLinkBinding = [pscustomobject]@{
        loaderPath = 'runtime/client/dinput8.dll'
        loaderSize = [long]3
        loaderSha256 = Get-LowerSha256 $loaderPath
        modulePath = 'runtime/client/plugins/PSOBB.Gameplay.asi'
        moduleSize = [long]3
        moduleSha256 = Get-LowerSha256 $modulePath
        configurationPath = 'runtime/client/plugins/PSOBB.Gameplay.ini'
        configurationSize = [long]$configurationIdentity.Size
        configurationSha256 = [string]$configurationIdentity.Sha256
    }
    $hardLinkRejected = $false
    try {
        Get-PSOBBCombatCanaryGameplayOverlayEntries `
            -GameplayOverlay $hardLinkBinding -ClientRoot $hardLinkFixture `
            -VerifyFiles | Out-Null
    } catch {
        $hardLinkRejected = $_.Exception.Message -match 'file changed'
    }
    Add-Result 'hard-linked gameplay overlay file is rejected' $hardLinkRejected
} finally {
    if ([System.IO.Directory]::Exists($hardLinkFixture)) {
        [System.IO.Directory]::Delete($hardLinkFixture, $true)
    }
}

Add-Result 'exact base plus profile passes' (
    Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $exact `
        -ClientProfileEntry $profile)

$nativeMutable = @(
    (New-Entry 'Psobb.exe' 4096 'a'),
    (New-Entry 'data/unit.bin' 512 'b'),
    (New-Entry 'GameGuard/0npgl.erl' 256 'e'),
    (New-Entry 'GameGuard/npgl.erl' 384 '3'),
    (New-Entry 'GameGuard/npgl2.erl' 320 '9'),
    (New-Entry 'GameGuard/1npgg.erl' 128 'c'),
    (New-Entry 'GameGuard/1npgl.erl' 192 'd'),
    (New-Entry 'log/generic.log' 100 '4'),
    (New-Entry 'log/spec.log' 100 '5'),
    (New-Entry 'log/chat20260720.txt' 100 '6'),
    $profile)
Add-Result 'bounded native GameGuard and log mutations pass' (
    Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $nativeMutable `
        -ClientProfileEntry $profile)

function Test-Rejected(
    [object[]]$Actual,
    [object[]]$GameplayOverlayEntries = @()
) {
    -not (Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $Actual `
        -ClientProfileEntry $profile `
        -GameplayOverlayEntries $GameplayOverlayEntries)
}

$overlay = @(
    (New-Entry 'dinput8.dll' 2048 '3'),
    (New-Entry 'plugins/PSOBB.Gameplay.asi' 1024 '4'),
    (New-Entry 'plugins/PSOBB.Gameplay.ini' 48 '5'))
$overlayActual = @($exact + $overlay)
Add-Result 'exact declared gameplay overlay passes' (
    Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $overlayActual `
        -ClientProfileEntry $profile -GameplayOverlayEntries $overlay)
Add-Result 'overlay files remain rejected without declaration' (
    Test-Rejected -Actual $overlayActual)
Add-Result 'declared overlay must be complete' (
    Test-Rejected -Actual $overlayActual `
        -GameplayOverlayEntries @($overlay | Select-Object -First 2))
Add-Result 'declared overlay file must be present' (
    Test-Rejected `
        -Actual @($overlayActual | Where-Object {
                $_.path -cne 'plugins/PSOBB.Gameplay.ini'
            }) `
        -GameplayOverlayEntries $overlay)
Add-Result 'declared overlay identity must match' (
    Test-Rejected `
        -Actual @($overlayActual | ForEach-Object {
                if ($_.path -ceq 'plugins/PSOBB.Gameplay.asi') {
                    New-Entry $_.path $_.size '9'
                } else { $_ }
            }) `
        -GameplayOverlayEntries $overlay)
Add-Result 'case-variant overlay path rejected' (
    Test-Rejected `
        -Actual $overlayActual `
        -GameplayOverlayEntries @($overlay | ForEach-Object {
                if ($_.path -ceq 'dinput8.dll') {
                    New-Entry 'DInput8.dll' $_.size '3'
                } else { $_ }
            }))
Add-Result 'unknown overlay path rejected' (
    Test-Rejected `
        -Actual $overlayActual `
        -GameplayOverlayEntries @(
            $overlay[0], $overlay[1], (New-Entry 'plugins/extra.ini' 48 '5')))

Add-Result 'changed executable rejected' (Test-Rejected @(
        $exact | ForEach-Object {
            if ($_.path -ceq 'Psobb.exe') {
                New-Entry 'Psobb.exe' 4096 '9'
            } else { $_ }
        }))
Add-Result 'missing exact data rejected' (Test-Rejected @(
        $exact | Where-Object { $_.path -cne 'data/unit.bin' }))
Add-Result 'extra DLL rejected' (Test-Rejected @(
        $exact + (New-Entry 'version.dll' 256 '7')))
Add-Result 'changed profile rejected' (Test-Rejected @(
        $base + (New-Entry 'client-profile.json' 96 '8')))
Add-Result 'missing profile rejected' (Test-Rejected $base)
Add-Result 'case-variant path rejected' (Test-Rejected @(
        $exact | ForEach-Object {
            if ($_.path -ceq 'Psobb.exe') {
                New-Entry 'psobb.exe' 4096 'a'
            } else { $_ }
        }))
Add-Result 'unapproved log rejected' (Test-Rejected @(
        $exact + (New-Entry 'log/session.txt' 20 '7')))
Add-Result 'oversized GameGuard state rejected' (Test-Rejected @(
        $exact + (New-Entry 'GameGuard/1npgg.erl' (1MB + 1) '7')))
Add-Result 'unchanged GameGuard state remains exact' (Test-Rejected @(
        $exact | ForEach-Object {
            if ($_.path -ceq 'GameGuard/npgl2.erl') {
                New-Entry 'GameGuard/npgl2.erl' 320 '8'
            } else { $_ }
        }))
Add-Result 'invalid chat-log name rejected' (Test-Rejected @(
        $exact + (New-Entry 'log/chat-current.txt' 20 '7')))
Add-Result 'duplicate path rejected' (Test-Rejected @($exact + $profile))

$passed = @($results | Where-Object Passed).Count
$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
Write-Host "Passed: $passed / $($results.Count)"
if ($failed.Count -ne 0) {
    throw "CombatCanary runtime-client policy tests failed: $($failed.Name -join ', ')"
}
