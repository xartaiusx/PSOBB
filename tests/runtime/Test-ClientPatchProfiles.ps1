[CmdletBinding()]
param([string]$RuntimeRoot)

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$policyPath = Join-Path $repositoryRoot 'config\client-patch-profiles.json'
$sourceLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$pinnedClientFunctionsRoot = Join-Path $sourceLayout.ServerBase 'system\client-functions'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

$expectedStable = @(
    'AccurateKillCount',
    'FastTekker',
    'HungryMagSound',
    'NoRareSelling',
    'Palette'
)
$policy = Get-PSOBBClientPatchPolicy -Path $policyPath
$stableProfiles = @($policy.profiles | Where-Object id -CEQ 'stable-qol')
$baselineProfiles = @($policy.profiles | Where-Object id -CEQ 'baseline')
Add-Result 'stable-qol contains only the five approved auto-patches' (
    ($stableProfiles.Count -eq 1) -and
    (Test-ExactStringSequence -Expected $expectedStable -Actual @($stableProfiles[0].autoPatches)) -and
    (@($stableProfiles[0].bbRequiredPatches).Count -eq 0)) ($stableProfiles[0].autoPatches -join ', ')
Add-Result 'baseline is an empty rollback profile' (
    ($baselineProfiles.Count -eq 1) -and
    (@($baselineProfiles[0].autoPatches).Count -eq 0) -and
    (@($baselineProfiles[0].bbRequiredPatches).Count -eq 0)) 'AutoPatches=[]; BBRequiredPatches=[]'

$stableSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$expectedStable | ForEach-Object { [void]$stableSet.Add($_) }
$gated = @($policy.gated.sourceCanaryOnly) +
    @($policy.gated.protocolRequired) +
    @($policy.gated.migrationRequired)
Add-Result 'gated patches are disjoint from stable' (
    @($gated | Where-Object { $stableSet.Contains([string]$_) }).Count -eq 0) ($gated -join ', ')
Add-Result 'source-canary candidates remain separate' (
    Test-ExactStringSequence `
        -Expected @('DrawDistance', 'EnemyHPBars', 'ItemPickup') `
        -Actual @($policy.gated.sourceCanaryOnly)) ($policy.gated.sourceCanaryOnly -join ', ')
Add-Result 'protocol patches remain required and disabled' (
    Test-ExactStringSequence `
        -Expected @('EnemyDamageSync', 'ServerEXPDisplay', 'StackLimits') `
        -Actual @($policy.gated.protocolRequired)) ($policy.gated.protocolRequired -join ', ')

$fixtureConfig = @'
{
  "BBRequiredPatches": [
    "StackLimits",
  ],
  "AutoPatches": [
    // an inactive example must not survive profile materialization
    "DrawDistance",
  ],
}
'@
$stableConfig = Get-NewservClientPatchConfiguration `
    -Text $fixtureConfig `
    -Profile 'stable-qol' `
    -PolicyPath $policyPath
$stableSecondPass = Get-NewservClientPatchConfiguration `
    -Text $stableConfig `
    -Profile 'stable-qol' `
    -PolicyPath $policyPath
$observedStable = @(Get-ActiveConfigStringArray -Text $stableConfig -Key 'AutoPatches')
$observedRequired = @(Get-ActiveConfigStringArray -Text $stableConfig -Key 'BBRequiredPatches')
Add-Result 'stable transform is exact and idempotent' (
    (Test-ExactStringSequence -Expected $expectedStable -Actual $observedStable) -and
    ($observedRequired.Count -eq 0) -and
    ($stableConfig -ceq $stableSecondPass)) 'five AutoPatches; no BBRequiredPatches'

$baselineConfig = Get-NewservClientPatchConfiguration `
    -Text $stableConfig `
    -Profile 'baseline' `
    -PolicyPath $policyPath
Add-Result 'baseline reverses the stable transform' (
    (@(Get-ActiveConfigStringArray -Text $baselineConfig -Key 'AutoPatches').Count -eq 0) -and
    (@(Get-ActiveConfigStringArray -Text $baselineConfig -Key 'BBRequiredPatches').Count -eq 0)) 'both arrays returned to empty'

$unknownRejected = $false
try {
    Get-NewservClientPatchConfiguration `
        -Text $fixtureConfig `
        -Profile 'unknown' `
        -PolicyPath $policyPath | Out-Null
} catch {
    $unknownRejected = $_.Exception.Message -match 'Unknown client-patch profile'
}
Add-Result 'unknown profiles fail closed' $unknownRejected 'no implicit profile fallback'

$duplicateArrayRejected = $false
try {
    Get-NewservClientPatchConfiguration `
        -Text ($fixtureConfig + [Environment]::NewLine + '  "AutoPatches": [],') `
        -Profile 'stable-qol' `
        -PolicyPath $policyPath | Out-Null
} catch {
    $duplicateArrayRejected = $_.Exception.Message -match 'exactly one config array named AutoPatches'
}
Add-Result 'duplicate config arrays fail closed' $duplicateArrayRejected 'ambiguous config is never rewritten'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-ClientPatchProfileTests-' + [Guid]::NewGuid().ToString('N'))
try {
    $fixtureServer = Join-Path $temporaryRoot 'server'
    foreach ($patchName in $expectedStable) {
        $patchDirectory = Join-Path $fixtureServer ('system\client-functions\' + $patchName)
        New-Item -ItemType Directory -Path $patchDirectory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $pinnedClientFunctionsRoot (
            $patchName + '\' + $patchName + '.59NL.patch.s')) `
            -Destination (Join-Path $patchDirectory ($patchName + '.59NL.patch.s'))
    }
    $available = Assert-NewservClientPatchProfileAvailable `
        -ServerRoot $fixtureServer `
        -Profile 'stable-qol' `
        -PolicyPath $policyPath
    Add-Result 'all exact 59NL sources are required' (
        [string]$available.id -ceq 'stable-qol') 'pinned-release size and SHA-256 contract accepted'
    Remove-Item -LiteralPath (Join-Path $fixtureServer `
        'system\client-functions\Palette\Palette.59NL.patch.s') -Force
    $missingRejected = $false
    try {
        Assert-NewservClientPatchProfileAvailable `
            -ServerRoot $fixtureServer `
            -Profile 'stable-qol' `
            -PolicyPath $policyPath | Out-Null
    } catch {
        $missingRejected = $_.Exception.Message -match 'exact 59NL client patch: Palette'
    }
    Add-Result 'a missing 59NL source fails closed' $missingRejected 'profile cannot outpace pinned server contents'
    $paletteFixturePath = Join-Path $fixtureServer `
        'system\client-functions\Palette\Palette.59NL.patch.s'
    Copy-Item -LiteralPath (Join-Path $pinnedClientFunctionsRoot `
        'Palette\Palette.59NL.patch.s') -Destination $paletteFixturePath
    [System.IO.File]::AppendAllText($paletteFixturePath, '# tampered')
    $tamperRejected = $false
    try {
        Assert-NewservClientPatchProfileAvailable `
            -ServerRoot $fixtureServer `
            -Profile 'stable-qol' `
            -PolicyPath $policyPath | Out-Null
    } catch {
        $tamperRejected = $_.Exception.Message -match 'failed provenance verification: Palette'
    }
    Add-Result 'a modified 59NL source fails closed' $tamperRejected 'size and SHA-256 are lock-bound'

    $integrationRoot = Join-Path $temporaryRoot 'runtime'
    $integrationLayout = Get-PSOBBLayout -RuntimeRoot $integrationRoot
    New-Item -ItemType Directory -Path $integrationLayout.Server -Force | Out-Null
    $marker = Initialize-PSOBBRuntimeMarker -Layout $integrationLayout
    foreach ($patchName in $expectedStable) {
        $patchDirectory = Join-Path $integrationLayout.Server (
            'system\client-functions\' + $patchName)
        New-Item -ItemType Directory -Path $patchDirectory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $pinnedClientFunctionsRoot (
            $patchName + '\' + $patchName + '.59NL.patch.s')) `
            -Destination (Join-Path $patchDirectory ($patchName + '.59NL.patch.s'))
    }
    $integrationConfigPath = Join-Path $integrationLayout.Server 'system\config.json'
    [System.IO.File]::WriteAllText(
        $integrationConfigPath,
        $fixtureConfig,
        [System.Text.UTF8Encoding]::new($false))
    New-Item -ItemType Directory -Path $integrationLayout.Stable -Force | Out-Null
    [System.IO.File]::WriteAllText(
        $integrationLayout.InstallRecord,
        ([ordered]@{
            schemaVersion = 2
            installationId = $marker.installationId
        } | ConvertTo-Json),
        [System.Text.UTF8Encoding]::new($false))
    $promotionScript = Join-Path $repositoryRoot 'scripts\Set-PSOBBClientPatchProfile.ps1'
    $promotion = & $promotionScript `
        -RuntimeRoot $integrationRoot `
        -Profile stable-qol `
        -Confirm:$false
    $promotedConfig = Get-Content -Raw -LiteralPath $integrationConfigPath
    $promotedRecord = Get-Content -Raw -LiteralPath $integrationLayout.InstallRecord |
        ConvertFrom-Json
    Add-Result 'stopped-server promotion is exact and provenance-bound' (
        $promotion.Changed -and $promotion.RestartRequired -and
        (Test-ExactStringSequence `
            -Expected $expectedStable `
            -Actual @(Get-ActiveConfigStringArray -Text $promotedConfig -Key 'AutoPatches')) -and
        (@(Get-ActiveConfigStringArray -Text $promotedConfig -Key 'BBRequiredPatches').Count -eq 0) -and
        ([string]$promotedRecord.clientPatchProfile -ceq 'stable-qol') -and
        ([string]$promotedRecord.clientPatchPolicySha256 -ceq (Get-LowerSha256 $policyPath))) 'temporary runtime only; no game state or process touched'

    $rollback = & $promotionScript `
        -RuntimeRoot $integrationRoot `
        -Profile baseline `
        -Confirm:$false
    $rolledBackConfig = Get-Content -Raw -LiteralPath $integrationConfigPath
    $rolledBackRecord = Get-Content -Raw -LiteralPath $integrationLayout.InstallRecord |
        ConvertFrom-Json
    Add-Result 'baseline operation reverses an applied profile' (
        $rollback.Changed -and $rollback.RestartRequired -and
        (@(Get-ActiveConfigStringArray -Text $rolledBackConfig -Key 'AutoPatches').Count -eq 0) -and
        (@(Get-ActiveConfigStringArray -Text $rolledBackConfig -Key 'BBRequiredPatches').Count -eq 0) -and
        ([string]$rolledBackRecord.clientPatchProfile -ceq 'baseline')) 'profile metadata and both arrays rolled back together'
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$initializeSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Initialize-PSOBB.ps1')
$promotionSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Set-PSOBBClientPatchProfile.ps1')
Add-Result 'initialization records the selected patch profile' (
    $initializeSource -match "ClientPatchProfile = 'stable-qol'" -and
    $initializeSource -match 'clientPatchPolicySha256' -and
    $initializeSource -match 'Assert-NewservClientPatchProfileAvailable') 'profile and policy hash are installation provenance'
Add-Result 'runtime promotion requires stopped newserv and supports rollback' (
    $promotionSource -match 'Get-NewservProcessesAtPath' -and
    $promotionSource -match 'Stop the approved newserv process' -and
    $promotionSource -match "ValidateSet\('stable-qol', 'baseline'\)" -and
    $promotionSource -match 'Write-PSOBBAtomicText') 'explicit stable-qol/baseline operation; atomic rollback on write failure'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) client-patch-profile test(s) failed"
}
[pscustomobject]@{ Suite = 'ClientPatchProfiles'; Passed = $results.Count; Failed = 0 }
