[CmdletBinding()]
param([string]$RuntimeRoot)

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$policyPath = Join-Path $repositoryRoot 'config\client-patch-profiles.json'
$promotionSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Set-PSOBBClientPatchProfile.ps1')
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

function New-FixtureInstallationRecord(
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$RuntimeRoot,
    [string]$Profile = 'baseline'
) {
    $hash = [string]::new([char]'0', 64)
    [ordered]@{
        schemaVersion = 2
        installationId = $InstallationId
        initializedAtUtc = '2026-07-19T00:00:00.0000000+00:00'
        runtimeRoot = $RuntimeRoot
        serverVersion = 'fixture'
        serverArchiveSha256 = $hash
        serverExecutableSha256 = $hash
        serverBaseManifestSha256 = $hash
        clientVersion = 'fixture'
        clientArchiveSha256 = $hash
        baseClientExecutableSha256 = $hash
        baseClientManifestSha256 = $hash
        clientExecutableSha256 = $hash
        rendererVersion = 'fixture'
        rendererArchiveSha256 = $hash
        rendererWrapperSha256 = $hash
        rendererConfigurationSha256 = $hash
        patchManifestSha256 = $hash
        synchronizedPatchFiles = 0
        clientPatchProfile = $Profile
        clientPatchPolicySha256 = Get-LowerSha256 $policyPath
        networkScope = 'loopback-only'
    }
}
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
$integrationRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-RecoveryTests-' + [Guid]::NewGuid().ToString('N'))
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

    $integrationLayout = Get-PSOBBLayout -RuntimeRoot $integrationRoot
    New-Item -ItemType Directory -Path $integrationLayout.Server -Force | Out-Null
    $marker = Initialize-PSOBBRuntimeMarker -Layout $integrationLayout
    [System.IO.File]::WriteAllText(
        (Join-Path $integrationLayout.Root '.recovery-test.json'),
        '{"fixture":true}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl `
        -Path (Join-Path $integrationLayout.Root '.recovery-test.json')
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
        ((New-FixtureInstallationRecord `
                -InstallationId $marker.installationId `
                -RuntimeRoot $integrationLayout.Root) | ConvertTo-Json -Depth 5),
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

    $transactionRoot = Join-Path $integrationLayout.Stable `
        '.client-patch-profile-transaction'
    $configTemporary = Join-Path $integrationLayout.Server `
        'system\.client-patch-profile-config.new'
    $installationTemporary = Join-Path $integrationLayout.Stable `
        '.client-patch-profile-installation.new'
    $faultTokens = $null
    $faultParseErrors = $null
    $promotionAst = [System.Management.Automation.Language.Parser]::ParseInput(
        $promotionSource, [ref]$faultTokens, [ref]$faultParseErrors)
    if ($faultParseErrors.Count -gt 0) {
        throw 'Patch-profile source could not be parsed for fault-boundary coverage'
    }
    $commandAsts = @($promotionAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true))
    $faultPrefixesByFunction = @{
        'Write-PatchProfileArtifact' = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        'Install-PatchProfileArtifact' = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
    }
    foreach ($commandAst in @($commandAsts | Where-Object {
                $commandName = $_.GetCommandName()
                $null -ne $commandName -and
                    $faultPrefixesByFunction.ContainsKey($commandName)
            })) {
        $elements = @($commandAst.CommandElements)
        for ($elementIndex = 0; $elementIndex -lt ($elements.Count - 1); $elementIndex++) {
            if ($elements[$elementIndex] -is
                    [System.Management.Automation.Language.CommandParameterAst] -and
                $elements[$elementIndex].ParameterName -ceq 'FaultPrefix' -and
                $elements[$elementIndex + 1] -is
                    [System.Management.Automation.Language.StringConstantExpressionAst]) {
                [void]$faultPrefixesByFunction[$commandAst.GetCommandName()].Add(
                    [string]$elements[$elementIndex + 1].Value)
            }
        }
    }
    $faultPointSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $unresolvedFaultExpressions = [System.Collections.Generic.List[string]]::new()
    foreach ($commandAst in @($commandAsts | Where-Object {
                $_.GetCommandName() -ceq 'Invoke-PatchProfileInternalFault'
            })) {
        $elements = @($commandAst.CommandElements)
        $pointExpression = $null
        for ($elementIndex = 0; $elementIndex -lt ($elements.Count - 1); $elementIndex++) {
            if ($elements[$elementIndex] -is
                    [System.Management.Automation.Language.CommandParameterAst] -and
                $elements[$elementIndex].ParameterName -ceq 'Point') {
                $pointExpression = $elements[$elementIndex + 1]
                break
            }
        }
        if ($pointExpression -is
            [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [void]$faultPointSet.Add([string]$pointExpression.Value)
        } elseif ($pointExpression -is
            [System.Management.Automation.Language.ExpandableStringExpressionAst] -and
            [string]$pointExpression.Value -match '^\$FaultPrefix-(.+)$') {
            $suffix = [string]$Matches[1]
            $enclosingFunction = $pointExpression.Parent
            while ($null -ne $enclosingFunction -and
                $enclosingFunction -isnot
                    [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $enclosingFunction = $enclosingFunction.Parent
            }
            if ($null -eq $enclosingFunction -or
                -not $faultPrefixesByFunction.ContainsKey(
                    [string]$enclosingFunction.Name)) {
                $unresolvedFaultExpressions.Add([string]$commandAst.Extent.Text)
                continue
            }
            foreach ($prefix in $faultPrefixesByFunction[[string]$enclosingFunction.Name]) {
                [void]$faultPointSet.Add("$prefix-$suffix")
            }
        } else {
            $unresolvedFaultExpressions.Add([string]$commandAst.Extent.Text)
        }
    }
    $faultPoints = @($faultPointSet | Sort-Object)
    Add-Result 'fault matrix derives every implemented profile boundary' (
        $faultPrefixesByFunction['Write-PatchProfileArtifact'].Count -eq 4 -and
        $faultPrefixesByFunction['Install-PatchProfileArtifact'].Count -eq 4 -and
        $unresolvedFaultExpressions.Count -eq 0 -and
        $faultPoints.Count -eq 44) `
        "$($faultPoints.Count) exact fault points parsed from source"
    foreach ($faultPoint in $faultPoints) {
        & $promotionScript -RuntimeRoot $integrationRoot -Profile baseline `
            -Confirm:$false | Out-Null
        $faultObserved = $false
        try {
            & $promotionScript `
                -RuntimeRoot $integrationRoot -Profile stable-qol `
                -Confirm:$false `
                -InternalTestFaultPoint $faultPoint `
                -InternalTestFaultToken ([string]$marker.installationId) |
                Out-Null
        } catch {
            $faultObserved = $_.Exception.Message -match
                '(Injected|transaction failed|compensation did not complete)'
        }
        $recoverySucceeded = $true
        try {
            # A compensation-fault seam intentionally retains protected rollback.
            # A no-fault rerun must idempotently recover it before applying baseline.
            & $promotionScript -RuntimeRoot $integrationRoot -Profile baseline `
                -Confirm:$false | Out-Null
            $finalState = Assert-PSOBBClientPatchStateCoherent `
                -ConfigPath $integrationConfigPath `
                -InstallRecordPath $integrationLayout.InstallRecord `
                -InstallationId ([string]$marker.installationId) `
                -RuntimeRoot $integrationLayout.Root
            $recoverySucceeded =
                $finalState.Profile -ceq 'baseline' -and
                (Test-PSOBBProtectedAcl -Path $integrationConfigPath) -and
                (Test-PSOBBProtectedAcl -Path $integrationLayout.InstallRecord) -and
                -not (Test-Path -LiteralPath $transactionRoot) -and
                -not (Test-Path -LiteralPath $configTemporary) -and
                -not (Test-Path -LiteralPath $installationTemporary)
        } catch {
            $recoverySucceeded = $false
        }
        Add-Result "journaled profile fault recovers: $faultPoint" (
            $faultObserved -and $recoverySucceeded) `
            'original-or-candidate pair only; exact ACL; retained compensation is idempotently recovered; no debris'
    }

    function Invoke-BlockedPromotionFixture {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][scriptblock]$Prepare,
            [Parameter(Mandatory)][scriptblock]$Cleanup
        )

        $configBefore = [System.IO.File]::ReadAllBytes($integrationConfigPath)
        $recordBefore = [System.IO.File]::ReadAllBytes($integrationLayout.InstallRecord)
        $blocked = $false
        $detail = ''
        try {
            . $Prepare
            try {
                & $promotionScript `
                    -RuntimeRoot $integrationRoot `
                    -Profile stable-qol `
                    -Confirm:$false | Out-Null
            } catch {
                $blocked = $_.Exception.Message -match 'requires both server environments'
                $detail = $_.Exception.Message
            }
        } finally {
            . $Cleanup
        }
        $configAfter = [System.IO.File]::ReadAllBytes($integrationConfigPath)
        $recordAfter = [System.IO.File]::ReadAllBytes($integrationLayout.InstallRecord)
        $unchanged =
            [Convert]::ToBase64String($configBefore) -ceq
                [Convert]::ToBase64String($configAfter) -and
            [Convert]::ToBase64String($recordBefore) -ceq
                [Convert]::ToBase64String($recordAfter)
        Add-Result $Name ($blocked -and $unchanged) (
            "blocked=$blocked unchanged=$unchanged; $detail")
    }

    $stableIntegrationLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $integrationLayout -Environment Stable
    $combatIntegrationLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $integrationLayout -Environment CombatCanary
    foreach ($environmentLayout in @(
            $stableIntegrationLayout,
            $combatIntegrationLayout)) {
        Invoke-BlockedPromotionFixture `
            -Name ("$($environmentLayout.Environment) stale lifecycle evidence blocks promotion without changing bytes") `
            -Prepare {
                [System.IO.Directory]::CreateDirectory(
                    $environmentLayout.ControlDirectory) | Out-Null
                [System.IO.File]::WriteAllText(
                    $environmentLayout.ControlState,
                    '{"schemaVersion":3,"state":"failed"}',
                    [System.Text.UTF8Encoding]::new($false))
            } `
            -Cleanup {
                if (Test-Path -LiteralPath $environmentLayout.ControlState) {
                    Remove-Item -LiteralPath $environmentLayout.ControlState -Force
                }
            }
    }

    foreach ($reservedPort in @(11000, 12000, 12001)) {
        $listener = $null
        Invoke-BlockedPromotionFixture `
            -Name "reserved listener $reservedPort blocks promotion without changing bytes" `
            -Prepare {
                $listener = [System.Net.Sockets.TcpListener]::new(
                    [System.Net.IPAddress]::Loopback,
                    $reservedPort)
                $listener.Start()
            } `
            -Cleanup {
                if ($listener) {
                    $listener.Stop()
                    $listener = $null
                }
            }
    }

    $namedBlockerRoot = Join-Path $temporaryRoot 'named-blockers'
    [System.IO.Directory]::CreateDirectory($namedBlockerRoot) | Out-Null
    $pingExecutable = Join-Path $env:SystemRoot 'System32\PING.EXE'
    foreach ($processName in @('online', 'option', 'Psobb', 'newserv-windows')) {
        $blockerProcess = $null
        $blockerPath = Join-Path $namedBlockerRoot ($processName + '.exe')
        Copy-Item -LiteralPath $pingExecutable -Destination $blockerPath
        Invoke-BlockedPromotionFixture `
            -Name "named $processName identity blocks promotion without changing bytes" `
            -Prepare {
                $blockerProcess = Start-Process `
                    -FilePath $blockerPath `
                    -ArgumentList @('-n', '60', '127.0.0.1') `
                    -WindowStyle Hidden `
                    -PassThru
                $blockerProcess.Refresh()
                if ([string]$blockerProcess.ProcessName -cne $processName) {
                    throw "The named blocker fixture started as $($blockerProcess.ProcessName)"
                }
            } `
            -Cleanup {
                if ($blockerProcess) {
                    $blockerProcess.Refresh()
                    if (-not $blockerProcess.HasExited) {
                        $blockerProcess.Kill()
                        $blockerProcess.WaitForExit(5000) | Out-Null
                    }
                    $blockerProcess.Dispose()
                    $blockerProcess = $null
                }
            }
    }
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $integrationRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$initializeSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Initialize-PSOBB.ps1')
$promotionSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Set-PSOBBClientPatchProfile.ps1')
$commonSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$globalGateOffsets = @([regex]::Matches(
        $promotionSource,
        'Assert-PSOBBGlobalStoppedRuntime') | ForEach-Object Index)
$firstLockOffset = $promotionSource.IndexOf(
    'Enter-PSOBBClientOperationLock', [System.StringComparison]::Ordinal)
$serverLockOffset = $promotionSource.IndexOf(
    '$ownsMutex = $mutex.WaitOne(0)', [System.StringComparison]::Ordinal)
$firstWriteOffset = $promotionSource.IndexOf(
    '-Source $paths.CandidateConfig', [System.StringComparison]::Ordinal)
Add-Result 'initialization records the selected patch profile' (
    $initializeSource -match "ClientPatchProfile = 'baseline'" -and
    $initializeSource -match 'clientPatchPolicySha256' -and
    $initializeSource -match 'Assert-NewservClientPatchProfileAvailable') 'profile and policy hash are installation provenance'
Add-Result 'implicit patch-profile defaults preserve Stable Native baseline' (
    $promotionSource -match "\[string\]\`$Profile = 'baseline'" -and
    $commonSource -match "\[string\]\`$ClientPatchProfile = 'baseline'") `
    'stable-qol remains explicit compatibility/reference only'
Add-Result 'runtime promotion requires stopped newserv and supports rollback' (
    $globalGateOffsets.Count -eq 3 -and
    $promotionSource -match 'Enter-PSOBBClientOperationLock' -and
    $promotionSource.IndexOf(
        'Enter-PSOBBClientOperationLock', [System.StringComparison]::Ordinal) -lt
        $promotionSource.IndexOf(
            "'Local\PSOBB.Newserv.Start.'", [System.StringComparison]::Ordinal) -and
    $promotionSource.LastIndexOf(
        '$mutex.ReleaseMutex()', [System.StringComparison]::Ordinal) -lt
        $promotionSource.LastIndexOf(
            'Exit-PSOBBClientOperationLock', [System.StringComparison]::Ordinal) -and
    $promotionSource -notmatch '(?im)^\s*Stop-Process\b' -and
    $promotionSource -match "ValidateSet\('stable-qol', 'baseline'\)" -and
    $promotionSource -match 'Write-PatchProfileJournal' -and
    $promotionSource -match 'Resolve-PatchProfileInterruptedTransaction' -and
    $promotionSource -match 'Restore-PatchProfileOriginalPair') `
    'client-first global interlock; protected journal; idempotent pair recovery'
Add-Result 'global stopped-runtime gate brackets the two-file profile transaction' (
    $globalGateOffsets.Count -eq 3 -and
    $globalGateOffsets[0] -gt $firstLockOffset -and
    $globalGateOffsets[0] -gt $serverLockOffset -and
    $globalGateOffsets[1] -gt $globalGateOffsets[0] -and
    $globalGateOffsets[1] -lt $firstWriteOffset -and
    $globalGateOffsets[2] -gt $firstWriteOffset -and
    $promotionSource -notmatch 'Assert-PSOBBPatchProfileActivityStopped') `
    'both locks precede initial census; a second census precedes mutation; a third precedes acceptance'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) client-patch-profile test(s) failed"
}
[pscustomobject]@{ Suite = 'ClientPatchProfiles'; Passed = $results.Count; Failed = 0 }
