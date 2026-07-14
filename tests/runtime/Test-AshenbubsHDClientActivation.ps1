[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$activationPath = Join-Path $repositoryRoot `
    'scripts\Set-PSOBBAshenbubsHDClientActivation.ps1'
$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
$manifestPath = Join-Path $repositoryRoot `
    'src\PSOBB.LargeAssets\build-manifest.json'
$activation = Get-Content -Raw -LiteralPath $activationPath
$common = Get-Content -Raw -LiteralPath $commonPath
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

foreach ($sourcePath in @($activationPath, $commonPath)) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $sourcePath,
        [ref]$tokens,
        [ref]$errors) | Out-Null
    Add-Result "PowerShell syntax: $(Split-Path -Leaf $sourcePath)" `
        ($errors.Count -eq 0) `
        (($errors | ForEach-Object Message) -join '; ')
}

. $commonPath
$activationTokens = $null
$activationErrors = $null
$activationAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $activationPath,
    [ref]$activationTokens,
    [ref]$activationErrors)
foreach ($functionName in @(
    'Get-StrictJsonFile',
    'Get-ActivationSnapshot',
    'Resolve-PSOBBActivationTargetPath',
    'Copy-VerifiedAtomicFile',
    'Restore-ActivationSnapshot')) {
    $definitions = @($activationAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $true))
    if ($definitions.Count -ne 1) {
        throw "Could not isolate the exact $functionName implementation for snapshot regression testing"
    }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$script:AssetComponentId = 'ashenbubs-hd-psobb-v1.02-local-import'
$build = Get-PSOBBLargeAssetsBuildContract
Add-Result 'large-assets build manifest verifies source, ASI, and verifier' (
    $build.ComponentId -ceq 'project-owned-psobb-large-assets' -and
    $build.Capability -ceq 'large-assets-59nl' -and
    $build.MaximumAssetBytes -eq 100000000 -and
    $build.ArtifactSize -eq 230400 -and
    $build.ArtifactSha256 -ceq
        'bede4e0a9117a10c0b07a32712a04594604eea586dc779b1f81c34ae8a0b0bcf' -and
    $build.VerifierSize -eq 259584 -and
    $build.VerifierSha256 -ceq
        '187aed3b8701783cc6142fce64c50bd47dbb512fd9cfd418eaf5073e88fc4391') `
    'the ignored x86 build outputs exactly match the source-controlled build contract'

$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -Depth 50
Add-Result 'verifier output contract is exact' (
    [string]::Join("`n", @($manifest.verificationTool.expectedOutputContract)) -ceq
    [string]::Join("`n", @(
        'fileSizeMatched=true',
        'sha256Matched=true',
        'peContractMatched=true',
        'patchBytesMatched=true',
        'upstreamAddressEntries=18',
        'uniquePatchSites=17',
        'patchValue=100000000'))) `
    'activation cannot accept a verifier that omits a pinned executable or patch-site gate'

$verifierContract = @($manifest.verificationTool.expectedOutputContract)
$expectedExecutableSha256 =
    'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535'
$uppercaseVerifierOutput = [string]::Join("`r`n", @(
    $verifierContract
    'actualSha256=' + $expectedExecutableSha256.ToUpperInvariant()
))
$uppercaseAccepted = $false
try {
    $uppercaseAccepted = Assert-PSOBBLargeAssetsVerifierOutput `
        -StandardOutput $uppercaseVerifierOutput `
        -ExpectedContract $verifierContract `
        -ExpectedSha256 $expectedExecutableSha256
} catch { }
Add-Result 'uppercase verifier SHA-256 is accepted' $uppercaseAccepted `
    'the verifier emits uppercase hexadecimal while the approved digest is normalized lowercase'

$mismatchedRejected = $false
try {
    Assert-PSOBBLargeAssetsVerifierOutput `
        -StandardOutput ($uppercaseVerifierOutput.Replace(
            $expectedExecutableSha256.ToUpperInvariant(),
            ('0' * 64))) `
        -ExpectedContract $verifierContract `
        -ExpectedSha256 $expectedExecutableSha256 | Out-Null
} catch {
    $mismatchedRejected =
        $_.Exception.Message -ceq
            'The PSOBB.LargeAssets exact-client verifier reported an unexpected executable SHA-256'
}
Add-Result 'mismatched verifier SHA-256 is rejected' $mismatchedRejected `
    'case normalization cannot admit a different executable digest'

$duplicateRejected = $false
try {
    Assert-PSOBBLargeAssetsVerifierOutput `
        -StandardOutput ($uppercaseVerifierOutput + "`r`nactualSha256=" +
            $expectedExecutableSha256) `
        -ExpectedContract $verifierContract `
        -ExpectedSha256 $expectedExecutableSha256 | Out-Null
} catch {
    $duplicateRejected =
        $_.Exception.Message -ceq
            'The PSOBB.LargeAssets exact-client verifier did not report exactly one valid executable SHA-256'
}
Add-Result 'duplicate verifier SHA-256 is rejected' $duplicateRejected `
    'the verifier output must bind exactly one executable identity'

$snapshotFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-activation-snapshot-' + [Guid]::NewGuid().ToString('N'))
try {
    $snapshotRoot = Join-Path $snapshotFixtureRoot 'snapshot'
    $fixtureClientRoot = Join-Path $snapshotFixtureRoot 'client'
    $priorRoot = Join-Path $snapshotRoot 'prior'
    $priorAssetPath = Join-Path $priorRoot 'data\plAtex.afs'
    $priorProfilePath = Join-Path $priorRoot 'client-profile.json'
    New-Item -ItemType Directory -Path (Split-Path -Parent $priorAssetPath),
        $fixtureClientRoot -Force | Out-Null
    [System.IO.File]::WriteAllBytes($priorAssetPath, [byte[]](1..64))
    [System.IO.File]::WriteAllText(
        $priorProfilePath,
        '{}',
        [System.Text.UTF8Encoding]::new($false))
    $snapshotId = 'activation-20260714T123456789Z-deadbeef'
    $priorAssetSha256 = Get-LowerSha256 -Path $priorAssetPath
    $snapshotFixture = [ordered]@{
        schemaVersion = 1
        componentId = $script:AssetComponentId
        snapshotId = $snapshotId
        profileId = 'lab-widescreen-16x10'
        clientRoot = $fixtureClientRoot
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        profileBefore = [ordered]@{
            path = 'prior/client-profile.json'
            size = (Get-Item -LiteralPath $priorProfilePath).Length
            sha256 = Get-LowerSha256 -Path $priorProfilePath
        }
        targets = @(
            [ordered]@{
                path = 'data/plAtex.afs'
                activeSize = 128
                activeSha256 = 'a' * 64
                priorState = 'present'
                priorPath = 'prior/data/plAtex.afs'
                priorSize = (Get-Item -LiteralPath $priorAssetPath).Length
                priorSha256 = $priorAssetSha256
            },
            [ordered]@{
                path = 'plugins/PSOBB.LargeAssets.asi'
                activeSize = 1
                activeSha256 = 'b' * 64
                priorState = 'absent'
                priorPath = $null
                priorSize = 0
                priorSha256 = $null
            },
            [ordered]@{
                path = 'plugins/PSOBB.LargeAssets.ini'
                activeSize = 1
                activeSha256 = 'c' * 64
                priorState = 'absent'
                priorPath = $null
                priorSize = 0
                priorSha256 = $null
            }
        )
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $snapshotRoot 'snapshot.json'),
        ($snapshotFixture | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false))

    $snapshotAccepted = $false
    try {
        $acceptedSnapshot = Get-ActivationSnapshot -Path $snapshotRoot `
            -ExpectedId $snapshotId -ClientRoot $fixtureClientRoot
        $snapshotAccepted =
            [string]$acceptedSnapshot.snapshotId -ceq $snapshotId -and
            @($acceptedSnapshot.targets).Count -eq 3
    } catch { }
    Add-Result 'snapshot validation preserves its root parameter' $snapshotAccepted `
        'a target-local variable cannot redirect validation away from the snapshot root'

    [System.IO.File]::WriteAllBytes($priorAssetPath, [byte[]](65..128))
    $snapshotHashDriftDiagnosed = $false
    try {
        Get-ActivationSnapshot -Path $snapshotRoot -ExpectedId $snapshotId `
            -ClientRoot $fixtureClientRoot | Out-Null
    } catch {
        $snapshotHashDriftDiagnosed =
            $_.Exception.Message -ceq (
                'An activation snapshot prior file has an unexpected SHA-256: ' +
                'data/plAtex.afs; expected ' + $priorAssetSha256 +
                ', observed ' + (Get-LowerSha256 -Path $priorAssetPath))
    }
Add-Result 'snapshot prior-file SHA drift is diagnosed exactly' `
        $snapshotHashDriftDiagnosed `
        'same-size corruption reports the relative target and expected and observed hashes'
} finally {
    Remove-Item -LiteralPath $snapshotFixtureRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}

$exactActivationTimestamp = '2026-07-14T20:11:36.9704301Z'
$timestampAcceptedAsString = $false
try {
    $timestampManifest = ConvertFrom-PSOBBActivationManifestJson -Json (
        '{"createdAtUtc":"' + $exactActivationTimestamp + '"}')
    $parsedTimestamp = Assert-PSOBBActivationManifestTimestamp `
        -Activation $timestampManifest
    $timestampAcceptedAsString =
        $timestampManifest.createdAtUtc -is [string] -and
        [string]$timestampManifest.createdAtUtc -ceq $exactActivationTimestamp -and
        $parsedTimestamp.UtcDateTime.ToString('o') -ceq $exactActivationTimestamp
} catch { }
Add-Result 'activation ISO timestamp remains an exact JSON string' `
    $timestampAcceptedAsString `
    'PowerShell 7.6 date coercion cannot replace round-trip JSON text with locale output'

$malformedTimestampRejected = $false
try {
    $malformedTimestampManifest = ConvertFrom-PSOBBActivationManifestJson `
        -Json '{"createdAtUtc":"2026-07-14 20:11:36Z"}'
    Assert-PSOBBActivationManifestTimestamp `
        -Activation $malformedTimestampManifest | Out-Null
} catch {
    $malformedTimestampRejected =
        $_.Exception.Message -ceq
            'The LocalLab asset activation timestamp is invalid'
}
Add-Result 'malformed activation timestamp is rejected' `
    $malformedTimestampRejected `
    'preserving JSON strings does not relax the invariant round-trip timestamp contract'

$caseFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-activation-case-' + [Guid]::NewGuid().ToString('N'))
try {
    $caseClientRoot = Join-Path $caseFixtureRoot 'client'
    $caseSnapshotRoot = Join-Path $caseFixtureRoot 'snapshot'
    $caseSourceRoot = Join-Path $caseFixtureRoot 'source'
    $canonicalRelativePath = 'data/bm_obj_ep4_sabotenA.bml'
    $overlayRelativePath = 'data/bm_obj_ep4_sabotena.bml'
    $canonicalLeafName = [System.IO.Path]::GetFileName($canonicalRelativePath)
    $caseClientAsset = Join-Path $caseClientRoot `
        $canonicalRelativePath.Replace('/', '\')
    $caseSnapshotAsset = Join-Path $caseSnapshotRoot `
        ('prior/' + $canonicalRelativePath).Replace('/', '\')
    $caseActiveSource = Join-Path $caseSourceRoot 'bm_obj_ep4_sabotena.bml'
    $caseClientProfile = Join-Path $caseClientRoot 'client-profile.json'
    $casePriorProfile = Join-Path $caseSnapshotRoot 'prior\client-profile.json'
    New-Item -ItemType Directory -Path (Split-Path -Parent $caseClientAsset),
        (Split-Path -Parent $caseSnapshotAsset), $caseSourceRoot -Force |
        Out-Null
    $priorAssetBytes = [byte[]](1..64)
    $activeAssetBytes = [byte[]](65..128)
    [System.IO.File]::WriteAllBytes($caseClientAsset, $priorAssetBytes)
    [System.IO.File]::WriteAllBytes($caseSnapshotAsset, $priorAssetBytes)
    [System.IO.File]::WriteAllBytes($caseActiveSource, $activeAssetBytes)
    [System.IO.File]::WriteAllText(
        $caseClientProfile,
        '{"profile":"hd"}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $casePriorProfile,
        '{"profile":"clean"}',
        [System.Text.UTF8Encoding]::new($false))

    $baseFiles = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $baseFiles.Add($canonicalRelativePath, [pscustomobject]@{
        path = $canonicalRelativePath
    })
    $resolvedTargetPath = Resolve-PSOBBActivationTargetPath `
        -AssetPath $overlayRelativePath -BaseFiles $baseFiles
    $activeAssetSha256 = Get-LowerSha256 -Path $caseActiveSource
    $priorAssetSha256 = Get-LowerSha256 -Path $caseSnapshotAsset
    Copy-VerifiedAtomicFile -Source $caseActiveSource `
        -Destination (Join-Path $caseClientRoot $resolvedTargetPath.Replace('/', '\')) `
        -Size $activeAssetBytes.Length -Sha256 $activeAssetSha256 `
        -Root $caseClientRoot
    $activatedName = @(Get-ChildItem -LiteralPath `
        (Split-Path -Parent $caseClientAsset) -File | Where-Object {
            $_.Name -ieq $canonicalLeafName
        })

    $caseSnapshot = [pscustomobject]@{
        targets = @([pscustomobject]@{
            path = $resolvedTargetPath
            activeSize = $activeAssetBytes.Length
            activeSha256 = $activeAssetSha256
            priorState = 'present'
            priorPath = 'prior/' + $resolvedTargetPath
            priorSize = $priorAssetBytes.Length
            priorSha256 = $priorAssetSha256
        })
        profileBefore = [pscustomobject]@{
            size = (Get-Item -LiteralPath $casePriorProfile).Length
            sha256 = Get-LowerSha256 -Path $casePriorProfile
        }
    }
    Restore-ActivationSnapshot -SnapshotPath $caseSnapshotRoot `
        -Snapshot $caseSnapshot -ClientRoot $caseClientRoot -RequireActiveMatch
    $rolledBackName = @(Get-ChildItem -LiteralPath `
        (Split-Path -Parent $caseClientAsset) -File | Where-Object {
            $_.Name -ieq $canonicalLeafName
        })
    $canonicalActivationAndRollback =
        $resolvedTargetPath -ceq $canonicalRelativePath -and
        $activatedName.Count -eq 1 -and
        $activatedName[0].Name -ceq $canonicalLeafName -and
        $rolledBackName.Count -eq 1 -and
        $rolledBackName[0].Name -ceq $canonicalLeafName -and
        (Get-LowerSha256 -Path $caseClientAsset) -ceq $priorAssetSha256 -and
        (Get-LowerSha256 -Path $caseClientProfile) -ceq
            (Get-LowerSha256 -Path $casePriorProfile)
    Add-Result 'activation and rollback preserve base-manifest filename casing' `
        $canonicalActivationAndRollback `
        'overlay source casing remains separate while destination, snapshot, and rollback use the canonical base path'
} finally {
    Remove-Item -LiteralPath $caseFixtureRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}

Add-Result 'activation exposes only activate verify and rollback' (
    $activation -match "ValidateSet\('Activate', 'Verify', 'Rollback'\)" -and
    $activation -notmatch "ValidateSet\([^\)]*(Stable|Canary)") `
    'the mutation interface has no stable or canary selector'
Add-Result 'server and every approved client must be stopped' (
    $activation -match 'Assert-PSOBBNoRunningClients' -and
    $activation -match 'Get-NewservProcessesAtPath' -and
    $activation -match 'Get-NewservProcess' -and
    $activation -match 'Assert-PSOBBStoppedForClientAssetMutation') `
    'all three actions fail closed around active processes'
Add-Result 'current staged overlay is independently verified before locking' (
    $activation -match 'Set-PSOBBAshenbubsHDOverlay\.ps1' -and
    $activation -match '-Action Verify' -and
    $activation -match 'Get-StagedAshenbubsComposition' -and
    $activation -match 'stagedManifestSha256') `
    'activation requires both the staging verifier and its own exact file hashes'
Add-Result 'activation requirements bind exact client capability and ceiling' (
    $activation -match 'requiredClientExecutableSha256' -and
    $activation -match 'requiredComponentId -cne[\s\r\n]+\s*\$script:LargeAssetsComponentId' -and
    $activation -match "requiredCapability -cne[\s\r\n]+\s*'large-assets-59nl'" -and
    $activation -match 'requiredMaximumAssetBytes -ne 100000000') `
    'the Ephinea-only warning cannot bypass the project-owned 59NL guard'
Add-Result 'activation cannot substitute a test or attacker-controlled source lock' (
    $activation -match 'approvedSourcesLockPath' -and
    $activation -match 'requires the source-controlled production sources.lock.json') `
    'runtime-only asset hashes remain bound to the reviewed production provenance entry'
Add-Result 'every asset is copied unchanged by exact size and SHA-256' (
    $activation -match 'Copy-VerifiedAtomicFile' -and
    $activation -match '\[System\.IO\.File\]::Move\(\$temporaryPath, \$destinationPath, \$true\)' -and
    $activation -match 'Get-LowerSha256 -Path \$destinationPath') `
    'same-volume temporary files make every destination switch individually atomic'
Add-Result 'base-manifest casing owns replacement and activation-record paths' (
    $activation -match 'Resolve-PSOBBActivationTargetPath' -and
    $activation -match '-AssetPath \(\[string\]\$asset\.Path\) -BaseFiles \$baseFiles' -and
    $activation -match '\$activationFiles = @\(\$assetTargets') `
    'the private overlay path remains a source identity and cannot rename a base-client destination'
Add-Result 'unknown existing conflicts fail closed' (
    $activation -match 'approved replacement target with unknown existing bytes' -and
    $activation -match 'undeclared existing conflict' -and
    $activation -match 'Test-PSOBBDirectoryManifest -Root \$layout\.BaseClient') `
    'only a destination matching the immutable base or an absent destination may be replaced'
Add-Result 'snapshot stores exact original state before the first replacement' (
    $activation -match "snapshot\.json'" -and
    $activation -match 'profileBefore' -and
    $activation -match 'priorState' -and
    $activation -match 'priorSha256' -and
    $activation.IndexOf('Move-Item -LiteralPath $snapshotStaging -Destination $snapshotPath') -lt
        $activation.IndexOf('Copy-VerifiedAtomicFile -Source ([string]$target.SourcePath)')) `
    'profile, present files, and absent-file state are durable before client mutation'
Add-Result 'WhatIf returns before any filesystem mutation' (
    $activation.IndexOf('activate unchanged AshenbubsHD') -lt
        $activation.IndexOf('New-Item -ItemType Directory -Path $transactionRoot, $snapshotStaging')) `
    'preflight is read-only until the single high-impact activation confirmation succeeds'
Add-Result 'rollback refuses unknown active bytes' (
    $activation -match 'Restore-ActivationSnapshot' -and
    $activation -match 'RequireActiveMatch' -and
    $activation -match 'Rollback refuses an activated target with unknown bytes') `
    'rollback cannot overwrite a post-activation conflict silently'
Add-Result 'profile records private overlay and local module explicitly' (
    $activation -match 'localAssetOverlay' -and
    $activation -match 'localModules' -and
    $activation -match 'activationManifestSha256' -and
    $activation -match 'buildManifestSha256' -and
    $activation -match 'distributionClass = ''local-only''') `
    'the small profile points to a runtime-only exact per-file activation manifest'
Add-Result 'activation is a distinct no-CAS HD profile with exact rollback' (
    $activation -match '\$baseProfileId = ''lab-widescreen-16x10''' -and
    $activation -match '\$activatedProfileId = ''lab-widescreen-hd-16x10''' -and
    $activation -match '\$profile\.profileId = \$activatedProfileId' -and
    $activation -match '\$profile\.rollbackProfileId = \$baseProfileId' -and
    $common -match "profileId -cne 'lab-widescreen-hd-16x10'" -and
    $common -match "rollbackProfileId -cne 'lab-widescreen-16x10'") `
    'the private asset candidate cannot masquerade as the clean no-CAS reference profile'
Add-Result 'large-assets module and INI are adjacent and closed' (
    $activation -match 'plugins/PSOBB\.LargeAssets\.asi' -and
    $activation -match 'plugins/PSOBB\.LargeAssets\.ini' -and
    $activation -match '"\[LargeAssets\]`r`nEnabled=1`r`n"') `
    'the ASI is loader-visible and remains inert outside the one exact enabled INI'
Add-Result 'activation never writes stable or canary trees' (
    $activation -notmatch '\$layout\.(Client|Canary|Stable|Server)\s*[,\)]' -and
    $activation -match '\$clientRoot = Join-Path \$layout\.LocalLab ''runtime\\client''') `
    'stable is read only through BaseClient and all mutations are under LocalLab'
Add-Result 'automatic restoration covers failed final validation' (
    $activation -match 'Assert-PSOBBLocalLabClientRuntimeContract -Layout \$layout' -and
    $activation -match 'automatic restoration also failed' -and
    $activation -match "'failed-' \+ \[DateTime\]::UtcNow") `
    'a rejected activation restores its exact snapshot and preserves the failed record'

Add-Result 'Common admits only the exact declared local overlay' (
    $common -match 'Assert-PSOBBLocalAssetOverlayContract' -and
    $common -match 'Assert-PSOBBExactJsonProperties' -and
    $common -match 'activation record contains an undeclared extra file' -and
    $common -match 'activated asset count or composed byte total has changed') `
    'runtime validation closes profile, activation-manifest, and per-asset schemas'
Add-Result 'Common cannot accept a forged clean HD profile' (
    $common -match "profileId -ceq 'lab-widescreen-hd-16x10'" -and
    $common -match 'HD profile requires its exact asset overlay and large-assets module declarations' -and
    $common -match "'lab-widescreen-hd-16x10',[\s\r\n]+\s*'lab-widescreen-cas-16x10'") `
    'HD identity requires the private overlay and still inherits every widescreen companion-file gate'
Add-Result 'Common rejects extra loadables and data files' (
    $common.Contains("`$ExpectedLoadablePaths.Add('plugins\PSOBB.LargeAssets.asi')") -and
    $common -match 'SetEquals\(\$expectedLoadablePaths\)' -and
    $common -match 'data tree contains a missing, changed, or undeclared extra file' -and
    $common -match 'without an asset declaration does not match the exact base data manifest') `
    'the one ASI is added to the closed loadable set and declared or clean data is fully hashed'
Add-Result 'Common runs the exact-client verifier for active assets' (
    $common -match 'Invoke-PSOBBLargeAssetsExactClientVerifier' -and
    $common -match 'actualSha256=' -and
    $common -match 'VerifierOutputContract') `
    'active private assets cannot launch without all verifier output gates'
Add-Result 'credentials are absent from activation interface' (
    $activation -notmatch '(?i)password|credential|username') `
    'asset composition has no authentication inputs or outputs'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) AshenbubsHD client activation test(s) failed"
}
Write-Output "AshenbubsHD client activation tests passed: $($results.Count)/$($results.Count)"
