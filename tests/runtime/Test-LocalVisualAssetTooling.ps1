[CmdletBinding()]
param()

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$scriptPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBLocalVisualAsset.ps1'
$source = Get-Content -Raw -LiteralPath $scriptPath
$commonSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. $scriptPath
$sourcesLock = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'config\sources.lock.json') | ConvertFrom-Json -Depth 50
$graphicsEvidence = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'config\graphics-evidence.json') | ConvertFrom-Json -Depth 50

$results = [Collections.Generic.List[object]]::new()
function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

Add-Result 'approved author-origin candidate set is exact' (
    @($definitions.Keys).Count -eq 4 -and
    $definitions.ContainsKey('luthee-hd-ui-v1.1.6-local-import') -and
    $definitions.ContainsKey('higher-resolution-item-box-textures-2025-12-30-local-import') -and
    $definitions.ContainsKey('echelon-hd-effects-technics-2019-05-27-local-import') -and
    $definitions.ContainsKey('echelon-hd-blood-2018-06-16-local-import')) `
    'Luthee, item boxes, Echelon effects, and Echelon blood only'

Add-Result 'Ashenbubs is an immutable collision boundary' (
    [string]$definitions['echelon-hd-effects-technics-2019-05-27-local-import'].ReplacementPolicy -ceq
        'reject-ashenbubs-collision' -and
    [string]$definitions['echelon-hd-blood-2018-06-16-local-import'].ReplacementPolicy -ceq
        'reject-ashenbubs-collision' -and
    $source -notmatch 'AllowDeclaredReplacement' -and
    $source -match 'AshenbubsHD All is the immutable visual foundation' -and
    $commonSource -match 'AshenbubsHD All is the immutable visual foundation') `
    'no optional asset can replace an Ashenbubs-owned destination'

Add-Result 'supplemental assets require the full foundation' (
    $source -match 'Activate the full AshenbubsHD All foundation before any supplemental visual asset' -and
    $source -match "ashenbubsActivation\.selection -cne 'All'" -and
    $commonSource -match 'Supplemental visual assets require the full AshenbubsHD All foundation') `
    'stock-only and partial-pack profiles cannot accept supplemental assets'

Add-Result 'rejected candidates cannot be reactivated' (
    $source -match 'Join-Path \$repositoryRoot ''config\\graphics-evidence\.json''' -and
    $source -match 'Assert-PSOBBLocalVisualAssetCandidateDisposition' -and
    $commonSource -match "compatibilityState\.StartsWith\([\s\r\n]*'rejected-'" -and
    $commonSource -match 'rejected for this exact client stack') `
    'runtime activation follows the fail-closed source-lock and evidence disposition'

$rejectedStackBlocked = $true
foreach ($rejectedId in @(
    'luthee-hd-ui-v1.1.6-local-import',
    'higher-resolution-item-box-textures-2025-12-30-local-import')) {
    $sourceComponent = @($sourcesLock.components | Where-Object {
        [string]$_.id -ceq $rejectedId
    })
    if ($sourceComponent.Count -ne 1 -or
        -not ([string]$sourceComponent[0].compatibilityState).StartsWith(
            'rejected-', [StringComparison]::Ordinal)) {
        $rejectedStackBlocked = $false
        continue
    }
    try {
        Assert-PSOBBLocalVisualAssetCandidateDisposition `
            -ComponentId $rejectedId -SourceComponent $sourceComponent[0] `
            -Evidence $graphicsEvidence | Out-Null
        $rejectedStackBlocked = $false
    } catch {
        if ($_.Exception.Message -cnotmatch
            'rejected for this exact client stack') {
            $rejectedStackBlocked = $false
        }
    }
}
Add-Result 'pre-existing rejected stacks fail runtime validation' `
    $rejectedStackBlocked `
    'source-lock and evidence dispositions block stale or manually forged rejected layers'

Add-Result 'archive extraction is exact and path-contained' (
    $source -match 'Get-SevenZip -Sources \$sources' -and
    $source -match '\[string\]\$_.path -ceq ''7z\.dll''' -and
    $source -match 'installed 7-Zip file does not match sources\.lock\.json' -and
    $source -match 'Assert-SevenZipVisualAssetListing' -and
    $source.IndexOf('Assert-SevenZipVisualAssetListing -SevenZip') -lt
        $source.IndexOf('& $sevenZip x -bb0') -and
    $source -match '& \$sevenZip t' -and
    $source -match 'extracted archive member count does not match sources.lock.json' -and
    $source -match 'Assert-PathWithinRoot') `
    'locked archive, locked 7z.exe and 7z.dll, exact member count, and contained paths'

Add-Result 'activation is transactional and LIFO' (
    $source -match 'must be rolled back in reverse activation order' -and
    $source -match 'client-profile.before.json' -and
    $source -match '(?s)Recovery must be armed before the first destination changes\.\s*\$clientMutated = \$true\s*foreach' -and
    $source -match 'rollback failed and automatic reactivation also failed' -and
    $source -match '\$currentStaging, \$snapshotStaging, \$staging' -and
    $source -match 'automatic recovery also failed' -and
    $source -match 'snapshot.json') `
    'activation and rollback recovery are armed before mutation and partial trees are cleaned'

$lockedComponentsValid = $true
foreach ($id in @($definitions.Keys)) {
    try {
        $matches = @($sourcesLock.components | Where-Object { [string]$_.id -ceq $id })
        if ($matches.Count -ne 1 -or
            @(Get-LockedVisualAssetMembers -Component $matches[0]).Count -ne
                @($matches[0].members).Count) {
            $lockedComponentsValid = $false
        }
    } catch {
        $lockedComponentsValid = $false
    }
}
Add-Result 'source-lock members are safe and destination-unique' $lockedComponentsValid `
    'all four author-origin components have safe paths, positive sizes, exact hashes, and unique destinations'

$duplicateRejected = $false
try {
    Get-LockedVisualAssetMembers -Component ([pscustomobject]@{
        members = @(
            [pscustomobject]@{
                path = 'data/one.xvm'; destinationPath = 'data/shared.xvm'
                size = 1; sha256 = ('0' * 64)
            },
            [pscustomobject]@{
                path = 'data/two.xvm'; destinationPath = 'data/shared.xvm'
                size = 1; sha256 = ('1' * 64)
            })
    }) | Out-Null
} catch {
    $duplicateRejected = $true
}
Add-Result 'source-lock duplicate destinations fail closed' $duplicateRejected `
    'a component cannot overwrite the same client path twice in one activation'

$normalizedEscapeRejected = $false
try {
    Get-LockedVisualAssetMembers -Component ([pscustomobject]@{
        members = @([pscustomobject]@{
            path = 'data/../outside.xvm'; destinationPath = 'data/../outside.xvm'
            size = 1; sha256 = ('0' * 64)
        })
    }) | Out-Null
} catch {
    $normalizedEscapeRejected = $true
}
Add-Result 'source-lock normalized data escape fails closed' $normalizedEscapeRejected `
    'dot segments cannot route a declared data asset into another client directory'

$runtimeRoot = Get-PSOBBRuntimeRoot
$presentArchives = 0
$presentArchivesValid = $true
$sevenZip = Get-SevenZip -Sources $sourcesLock
foreach ($id in @($definitions.Keys)) {
    $component = @($sourcesLock.components | Where-Object { [string]$_.id -ceq $id })[0]
    $archive = Join-Path $runtimeRoot (
        [string]$definitions[$id].Archive).Replace('/', '\')
    if (Test-Path -LiteralPath $archive -PathType Leaf) {
        $presentArchives++
        if ((Get-Item -LiteralPath $archive -Force).Length -ne [long]$component.size -or
            (Get-LowerSha256 -Path $archive) -cne [string]$component.sha256) {
            $presentArchivesValid = $false
        }
        try {
            $locked = @(Get-LockedVisualAssetMembers -Component $component)
            $listed = @(Assert-SevenZipVisualAssetListing `
                -SevenZip $sevenZip -Archive $archive -LockedMembers $locked)
            if ($listed.Count -ne $locked.Count) {
                $presentArchivesValid = $false
            }
        } catch {
            $presentArchivesValid = $false
        }
    }
}
Add-Result 'present private archives match exact source locks' $presentArchivesValid `
    "$presentArchives optional local-only archive(s) found and verified"

Add-Result 'runtime contract composes exact ordered visual assets' (
    $commonSource -match 'function Add-PSOBBLocalVisualAssetContract' -and
    $commonSource -match 'visual-asset-activations/\$componentId/current/activation.json' -and
    $commonSource -match 'AshenbubsHD All is the immutable visual foundation' -and
    $commonSource -match 'Test-PSOBBManifestEntriesEqual') `
    'runtime validation binds profile, activation, source lock, client file, and final data manifest'

Add-Result 'all mutations require the complete materialized runtime contract' (
    $source -match '\$profile = Assert-PSOBBLocalLabClientRuntimeContract -Layout \$layout' -and
    $source -match '(?s)Assert-Stopped -Layout \$layout\s+\$rollbackMutated = \$true') `
    'profile, renderer, overlays, files, snapshots, and stopped processes are rechecked before mutation'

Add-Result 'rollback preserves unrelated current profile state' (
    $source -match '\$priorEntries = @\(if \(\$active\.Count -gt 1\)' -and
    $source -match 'Remove only this stack entry' -and
    $source -match "PSObject\.Properties\.Remove\('localVisualAssets'\)" -and
    $source -match 'Write-AtomicJson -Path \$profilePath -Value \$updatedProfile' -and
    $source -match '\$activationMoved = \$true') `
    'zero or one prior entry remains an array and LIFO rollback preserves unrelated profile choices'

Add-Result 'runtime launch requires an exact usable rollback chain' (
    $commonSource -match 'function Assert-PSOBBLocalVisualAssetSnapshotContract' -and
    $commonSource -match 'rollback snapshot contains an undeclared file' -and
    $commonSource -match 'rollback profile has a reordered or changed prior stack' -and
    $commonSource -match 'visual-asset stack is not in activation order' -and
    $commonSource -match 'approvedComponentIds') `
    'only four approved components in activation order can launch, and every rollback byte remains verified'

Add-Result 'visual asset interface has no credential fields' (
    $source -notmatch '(?i)password|username|credential|account_check|account\b') `
    'asset operations cannot receive or inspect login secrets'

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'psobb-local-visual-test-' + [Guid]::NewGuid().ToString('N'))
try {
    $sourceRoot = Join-Path $temporaryRoot 'source'
    $targetRoot = Join-Path $temporaryRoot 'target'
    New-Item -ItemType Directory -Path $sourceRoot, $targetRoot -Force | Out-Null
    $sourceFile = Join-Path $sourceRoot 'asset.bin'
    [IO.File]::WriteAllBytes($sourceFile, [byte[]](0..255))
    $sourceItem = Get-Item -LiteralPath $sourceFile
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceFile).Hash.ToLowerInvariant()
    $targetFile = Join-Path $targetRoot 'data\asset.bin'
    Copy-VerifiedFile -Source $sourceFile -Destination $targetFile `
        -Size $sourceItem.Length -Sha256 $sourceHash -Root $targetRoot
    Add-Result 'verified copy writes exact bytes within target root' (
        (Test-Path -LiteralPath $targetFile -PathType Leaf) -and
        (Get-FileHash -Algorithm SHA256 -LiteralPath $targetFile).Hash.ToLowerInvariant() -ceq
            $sourceHash) $targetFile

    $escapeRejected = $false
    try {
        Copy-VerifiedFile -Source $sourceFile `
            -Destination (Join-Path $targetRoot '..\escape.bin') `
            -Size $sourceItem.Length -Sha256 $sourceHash -Root $targetRoot
    } catch {
        $escapeRejected = $true
    }
    Add-Result 'verified copy rejects path escape' $escapeRejected `
        'destination outside the approved client root fails closed'

    $snapshotRoot = Join-Path $targetRoot 'snapshot'
    New-Item -ItemType Directory -Path (Join-Path $snapshotRoot 'previous') -Force |
        Out-Null
    $profileBefore = Join-Path $snapshotRoot 'client-profile.before.json'
    [IO.File]::WriteAllText($profileBefore, '{"schemaVersion":7}', [Text.UTF8Encoding]::new($false))
    $previousFile = Join-Path $snapshotRoot 'previous\0.bin'
    [IO.File]::WriteAllBytes($previousFile, [byte[]](255..0))
    $profileItem = Get-Item -LiteralPath $profileBefore
    $previousItem = Get-Item -LiteralPath $previousFile
    $snapshotId = 'activation-20260715T120000000Z-00000000'
    $snapshotManifest = [ordered]@{
        schemaVersion = 1
        componentId = 'unit-test-component'
        snapshotId = $snapshotId
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        profileBeforeSize = [long]$profileItem.Length
        profileBeforeSha256 = Get-LowerSha256 -Path $profileBefore
        files = @([ordered]@{
            destinationPath = 'data/asset.xvm'
            previousExisted = $true
            previousSize = [long]$previousItem.Length
            previousSha256 = Get-LowerSha256 -Path $previousFile
            snapshotPath = 'previous/0.bin'
        })
    }
    Write-AtomicJson -Path (Join-Path $snapshotRoot 'snapshot.json') `
        -Value $snapshotManifest -Root $snapshotRoot
    $snapshotContext = [pscustomobject]@{
        Root = $targetRoot
        Component = [pscustomobject]@{ id = 'unit-test-component' }
    }
    $snapshotAccepted = $null -ne (Get-VerifiedRollbackSnapshot `
        -Context $snapshotContext -SnapshotRoot $snapshotRoot `
        -SnapshotId $snapshotId `
        -ExpectedFiles @([pscustomobject]@{ destinationPath = 'data/asset.xvm' }))
    Add-Result 'rollback snapshot accepts exact active destination set' $snapshotAccepted `
        'snapshot profile and previous bytes are hash-bound before rollback mutation'

    $reorderedRejected = $false
    try {
        Get-VerifiedRollbackSnapshot -Context $snapshotContext `
            -SnapshotRoot $snapshotRoot -SnapshotId $snapshotId `
            -ExpectedFiles @([pscustomobject]@{ destinationPath = 'data/other.bin' }) |
            Out-Null
    } catch {
        $reorderedRejected = $true
    }
    Add-Result 'rollback snapshot rejects destination substitution' $reorderedRejected `
        'a drifted snapshot cannot redirect rollback to another client file'

    $approvedId = 'luthee-hd-ui-v1.1.6-local-import'
    $contractLocalLab = Join-Path $targetRoot 'local-lab'
    $contractSnapshotRoot = Join-Path $contractLocalLab (
        "visual-asset-activations\$approvedId\snapshots\$snapshotId")
    New-Item -ItemType Directory `
        -Path (Join-Path $contractSnapshotRoot 'previous') -Force | Out-Null
    $contractProfile = Join-Path $contractSnapshotRoot 'client-profile.before.json'
    [IO.File]::WriteAllText(
        $contractProfile,
        '{"schemaVersion":7}',
        [Text.UTF8Encoding]::new($false))
    $contractPrevious = Join-Path $contractSnapshotRoot 'previous\0.bin'
    [IO.File]::WriteAllBytes($contractPrevious, [byte[]](255..0))
    $contractProfileItem = Get-Item -LiteralPath $contractProfile
    $contractPreviousItem = Get-Item -LiteralPath $contractPrevious
    $contractManifest = [ordered]@{
        schemaVersion = 1
        componentId = $approvedId
        snapshotId = $snapshotId
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        profileBeforeSize = [long]$contractProfileItem.Length
        profileBeforeSha256 = Get-LowerSha256 -Path $contractProfile
        files = @([ordered]@{
            destinationPath = 'data/asset.xvm'
            previousExisted = $true
            previousSize = [long]$contractPreviousItem.Length
            previousSha256 = Get-LowerSha256 -Path $contractPrevious
            snapshotPath = 'previous/0.bin'
        })
    }
    Write-AtomicJson -Path (Join-Path $contractSnapshotRoot 'snapshot.json') `
        -Value $contractManifest -Root $contractSnapshotRoot
    $contractLayout = [pscustomobject]@{ LocalLab = $contractLocalLab }
    $snapshotContractAccepted = $null -ne (
        Assert-PSOBBLocalVisualAssetSnapshotContract `
            -Layout $contractLayout -ComponentId $approvedId `
            -SnapshotId $snapshotId `
            -ActivationFiles @([pscustomobject]@{
                destinationPath = 'data/asset.xvm'
            }) -PriorEntries @())
    Add-Result 'runtime snapshot contract accepts exact rollback inventory' `
        $snapshotContractAccepted `
        'launch-time validation proves snapshot bytes and the prior profile chain'

    [IO.File]::WriteAllText(
        (Join-Path $contractSnapshotRoot 'undeclared.bin'),
        'drift',
        [Text.UTF8Encoding]::new($false))
    $extraSnapshotFileRejected = $false
    try {
        Assert-PSOBBLocalVisualAssetSnapshotContract `
            -Layout $contractLayout -ComponentId $approvedId `
            -SnapshotId $snapshotId `
            -ActivationFiles @([pscustomobject]@{
                destinationPath = 'data/asset.xvm'
            }) -PriorEntries @() | Out-Null
    } catch {
        $extraSnapshotFileRejected = $_.Exception.Message -match 'undeclared file'
    }
    Add-Result 'runtime snapshot contract rejects undeclared rollback bytes' `
        $extraSnapshotFileRejected `
        'snapshot directories cannot hide untracked or substituted files'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) local visual-asset tooling test(s) failed"
}
[pscustomobject]@{ Suite = 'LocalVisualAssetTooling'; Passed = $results.Count; Failed = 0 }
