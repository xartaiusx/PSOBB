[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Activate', 'Verify', 'Rollback')]
    [string]$Action = 'Activate',

    [string]$SnapshotId,

    [string]$SourcesLockPath,

    [string]$RuntimeRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$script:AssetComponentId = 'ashenbubs-hd-psobb-v1.02-local-import'
$script:LargeAssetsComponentId = 'project-owned-psobb-large-assets'
$script:ActivationRelativePath =
    'asset-activations/ashenbubs-hd-psobb-v1.02/current/activation.json'

function Get-ExactComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Sources,
        [Parameter(Mandatory)][string]$Id
    )

    $matches = @($Sources.components | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "sources.lock.json must contain exactly one component named '$Id'"
    }
    $matches[0]
}

function Assert-PSOBBStoppedForClientAssetMutation {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    Assert-PSOBBGlobalStoppedRuntime -Layout $Layout | Out-Null
}

function Get-StrictJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 16)][int]$MaximumMegabytes = 1,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt ($MaximumMegabytes * 1MB)) {
        throw "$Label has an invalid size or filesystem type: $Path"
    }
    try {
        Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 100
    } catch {
        throw "$Label is not valid JSON: $($_.Exception.Message)"
    }
}

function Get-StagedAshenbubsComposition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Component
    )

    $overlayRoot = Join-Path $Layout.LocalLab `
        'asset-overlays\ashenbubs-hd-psobb-v1.02\current'
    Assert-PathWithinRoot -Path $overlayRoot -Root $Layout.LocalLab | Out-Null
    $manifestPath = Join-Path $overlayRoot 'asset-overlay.json'
    $manifest = Get-StrictJsonFile -Path $manifestPath -Label 'staged AshenbubsHD manifest'
    $selectionMap = @{
        All = @('monster', 'object-npc', 'character', 'map')
    }
    $selection = [string]$manifest.selection
    if ($selection -cne 'All' -or -not $selectionMap.ContainsKey($selection) -or
        [int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.componentId -cne $script:AssetComponentId -or
        [string]$manifest.version -cne '1.02' -or
        [string]$manifest.distributionClass -cne 'local-only' -or
        [string]$manifest.activationState -cne 'staged-not-applied' -or
        [string]$manifest.compatibilityState -cne 'ephinea-only-upstream-warning' -or
        [string]$manifest.sourceArchive.sha256 -cne [string]$Component.sha256 -or
        [long]$manifest.sourceArchive.size -ne [long]$Component.size -or
        [long]$manifest.maximumAssetBytes -ne [long]$Component.maximumAssetBytes -or
        [string]$manifest.activationRequirements.requiredClientExecutableSha256 -cne
            [string]$Component.activationRequirements.requiredClientExecutableSha256 -or
        [string]$manifest.activationRequirements.requiredComponentId -cne
            $script:LargeAssetsComponentId -or
        [string]$manifest.activationRequirements.requiredCapability -cne
            'large-assets-59nl' -or
        [long]$manifest.activationRequirements.requiredMaximumAssetBytes -ne 100000000 -or
        [string]$manifest.activationRequirements.integrationState -cne
            'not-attached-by-this-asset-materializer') {
        throw 'The current staged AshenbubsHD overlay does not meet the exact activation requirements'
    }

    $expectedPackIds = @($selectionMap[$selection] | Sort-Object)
    $actualPackIds = @($manifest.packs.id | Sort-Object)
    if ([string]::Join("`n", $expectedPackIds) -cne
        [string]::Join("`n", $actualPackIds)) {
        throw 'The staged AshenbubsHD selection does not contain its exact declared pack set'
    }

    $composed = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $expectedStagedFiles = [System.Collections.Generic.List[object]]::new()
    $compositionCollisions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    [int]$sourceEntries = 0
    [long]$sourceBytes = 0
    foreach ($pack in @($manifest.packs)) {
        $declarations = @($Component.packArchives | Where-Object {
            [string]$_.id -ceq [string]$pack.id
        })
        if ($declarations.Count -ne 1 -or
            [string]$pack.destinationRoot -cne [string]$declarations[0].destinationRoot -or
            [string]$pack.archiveMember -cne [string]$declarations[0].memberPath -or
            @($pack.files).Count -ne [int]$declarations[0].entryCount) {
            throw "The staged AshenbubsHD pack '$($pack.id)' has changed from sources.lock.json"
        }
        foreach ($file in @($pack.files)) {
            $sourceRelativePath = 'packs/{0}/{1}/{2}' -f [string]$pack.id,
                [string]$pack.destinationRoot, [string]$file.path
            $destinationRelativePath = '{0}/{1}' -f [string]$pack.destinationRoot,
                [string]$file.path
            if ($sourceRelativePath -cnotmatch
                    '^packs/[a-z0-9-]+/data(?:/scene)?/[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$' -or
                $destinationRelativePath -cnotmatch
                    '^data(?:/scene)?/[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$' -or
                [long]$file.size -le 0 -or
                [long]$file.size -gt [long]$Component.maximumAssetBytes -or
                [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw "The staged AshenbubsHD pack contains an unsafe asset: $sourceRelativePath"
            }
            $sourcePath = Assert-PathWithinRoot `
                -Path (Join-Path $overlayRoot $sourceRelativePath.Replace('/', '\')) `
                -Root $overlayRoot
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf) -or
                (Get-Item -LiteralPath $sourcePath -Force).Length -ne [long]$file.size -or
                (Get-LowerSha256 -Path $sourcePath) -cne [string]$file.sha256) {
                throw "A staged AshenbubsHD asset has drifted: $sourceRelativePath"
            }
            $entry = [pscustomobject]@{
                Path = $destinationRelativePath
                SourcePath = $sourcePath
                Size = [long]$file.size
                Sha256 = [string]$file.sha256
            }
            if ($composed.ContainsKey($destinationRelativePath)) {
                $prior = $composed[$destinationRelativePath]
                if ($prior.Size -ne $entry.Size -or $prior.Sha256 -cne $entry.Sha256 -or
                    $destinationRelativePath.ToLowerInvariant() -cnotin
                        @($Component.allowedIdenticalCollisions)) {
                    throw "The staged AshenbubsHD composition contains an undeclared collision: $destinationRelativePath"
                }
                $compositionCollisions.Add(
                    $destinationRelativePath.ToLowerInvariant()) | Out-Null
            } else {
                $composed.Add($destinationRelativePath, $entry)
            }
            $expectedStagedFiles.Add([ordered]@{
                path = $sourceRelativePath
                size = [long]$file.size
                sha256 = [string]$file.sha256
            })
            $sourceEntries++
            $sourceBytes += [long]$file.size
        }
    }
    if ($sourceEntries -ne @($manifest.packs.files).Count -or
        $sourceBytes -ne [long]$manifest.expandedAssetBytes) {
        throw 'The staged AshenbubsHD source entry count or expanded-byte total has changed'
    }
    $manifestCollisions = @($manifest.allowedIdenticalCollisions | ForEach-Object {
        ([string]$_).ToLowerInvariant()
    } | Sort-Object -Unique)
    $actualCollisions = @($compositionCollisions | Sort-Object)
    if ([string]::Join("`n", $manifestCollisions) -cne
        [string]::Join("`n", $actualCollisions)) {
        throw 'The staged AshenbubsHD identical-collision declaration has changed'
    }
    $expectedStagedFiles.Add([ordered]@{
        path = 'asset-overlay.json'
        size = (Get-Item -LiteralPath $manifestPath -Force).Length
        sha256 = Get-LowerSha256 -Path $manifestPath
    })
    if (-not (Test-PSOBBManifestEntriesEqual `
        -Left (Get-PSOBBDirectoryManifest -Root $overlayRoot) `
        -Right @($expectedStagedFiles))) {
        throw 'The staged AshenbubsHD overlay contains a missing, changed, or undeclared extra file'
    }
    $composedFiles = @($composed.Values | Sort-Object Path)
    [pscustomobject]@{
        Root = $overlayRoot
        ManifestPath = $manifestPath
        ManifestSha256 = Get-LowerSha256 -Path $manifestPath
        Manifest = $manifest
        Selection = $selection
        SourceEntryCount = $sourceEntries
        SourceExpandedAssetBytes = $sourceBytes
        Files = $composedFiles
        ComposedAssetBytes = [long](($composedFiles | Measure-Object Size -Sum).Sum)
    }
}

function Resolve-PSOBBActivationTargetPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AssetPath,
        [Parameter(Mandatory)]$BaseFiles
    )

    if ($AssetPath -cnotmatch
        '^data(?:/scene)?/[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$') {
        throw "The AshenbubsHD activation source declares an unsafe target path: $AssetPath"
    }
    if (-not $BaseFiles.ContainsKey($AssetPath)) {
        return $AssetPath
    }

    $canonicalPath = [string]$BaseFiles[$AssetPath].path
    if ($canonicalPath -cnotmatch
            '^data(?:/scene)?/[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$' -or
        -not $canonicalPath.Equals(
            $AssetPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The immutable base manifest has an invalid canonical path for activation target: $AssetPath"
    }
    $canonicalPath
}

function Copy-VerifiedAtomicFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][long]$Size,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][string]$Root
    )

    $destinationPath = Assert-PathWithinRoot -Path $Destination -Root $Root
    $parent = Split-Path -Parent $destinationPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporaryPath = Join-Path $parent ('.psobb-asset-' + [Guid]::NewGuid().ToString('N'))
    Assert-PathWithinRoot -Path $temporaryPath -Root $Root | Out-Null
    try {
        Copy-Item -LiteralPath $Source -Destination $temporaryPath
        $temporary = Get-Item -LiteralPath $temporaryPath -Force
        if ($temporary.Length -ne $Size -or
            (Get-LowerSha256 -Path $temporaryPath) -cne $Sha256) {
            throw "An asset changed while staging its atomic replacement: $Destination"
        }
        [System.IO.File]::Move($temporaryPath, $destinationPath, $true)
        if ((Get-Item -LiteralPath $destinationPath -Force).Length -ne $Size -or
            (Get-LowerSha256 -Path $destinationPath) -cne $Sha256) {
            throw "An atomic asset replacement did not preserve its exact bytes: $Destination"
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-ActivationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedId,
        [Parameter(Mandatory)][string]$ClientRoot
    )

    $manifestPath = Join-Path $Path 'snapshot.json'
    $manifest = Get-StrictJsonFile -Path $manifestPath -Label 'AshenbubsHD activation snapshot'
    Assert-PSOBBExactJsonProperties -Object $manifest `
        -Label 'AshenbubsHD activation snapshot' -Names @(
            'schemaVersion', 'componentId', 'snapshotId', 'profileId',
            'clientRoot', 'createdAtUtc', 'profileBefore', 'targets') | Out-Null
    Assert-PSOBBExactJsonProperties -Object $manifest.profileBefore `
        -Label 'AshenbubsHD activation snapshot profile' -Names @(
            'path', 'size', 'sha256') | Out-Null
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.componentId -cne $script:AssetComponentId -or
        [string]$manifest.snapshotId -cne $ExpectedId -or
        [string]$manifest.profileId -cne 'lab-widescreen-16x10' -or
        [string]$manifest.clientRoot -cne $ClientRoot -or
        @($manifest.targets).Count -lt 3 -or
        [string]$manifest.profileBefore.path -cne 'prior/client-profile.json' -or
        [string]$manifest.profileBefore.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The AshenbubsHD activation snapshot identity is invalid'
    }
    $profileBeforePath = Assert-PathWithinRoot `
        -Path (Join-Path $Path 'prior\client-profile.json') -Root $Path
    if (-not (Test-Path -LiteralPath $profileBeforePath -PathType Leaf) -or
        (Get-Item -LiteralPath $profileBeforePath -Force).Length -ne
            [long]$manifest.profileBefore.size -or
        (Get-LowerSha256 -Path $profileBeforePath) -cne
            [string]$manifest.profileBefore.sha256) {
        throw 'The activation snapshot prior client profile has drifted'
    }
    $expectedSnapshotFiles = [System.Collections.Generic.List[object]]::new()
    $expectedSnapshotFiles.Add([ordered]@{
        path = 'prior/client-profile.json'
        size = [long]$manifest.profileBefore.size
        sha256 = [string]$manifest.profileBefore.sha256
    })

    $targetNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($target in @($manifest.targets)) {
        Assert-PSOBBExactJsonProperties -Object $target `
            -Label 'AshenbubsHD activation snapshot target' -Names @(
                'path', 'activeSize', 'activeSha256', 'priorState',
                'priorPath', 'priorSize', 'priorSha256') | Out-Null
        $targetPath = [string]$target.path
        if (($targetPath -cnotmatch '^data(?:/scene)?/[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$' -and
            $targetPath -cnotin @('plugins/PSOBB.LargeAssets.asi',
                'plugins/PSOBB.LargeAssets.ini')) -or
            -not $targetNames.Add($targetPath) -or
            [string]$target.activeSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [long]$target.activeSize -le 0 -or
            [string]$target.priorState -cnotmatch '^(present|absent)$') {
            throw "The activation snapshot contains an unsafe target: $targetPath"
        }
        if ([string]$target.priorState -ceq 'present') {
            if ([string]$target.priorPath -cnotmatch '^prior/data(?:/scene)?/[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$' -or
                [string]$target.priorSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                [long]$target.priorSize -le 0) {
                throw "The activation snapshot prior declaration is invalid: $targetPath"
            }
            $priorPath = Assert-PathWithinRoot `
                -Path (Join-Path $Path ([string]$target.priorPath).Replace('/', '\')) `
                -Root $Path
            if (-not (Test-Path -LiteralPath $priorPath -PathType Leaf)) {
                throw "An activation snapshot prior file is missing: $targetPath; expected snapshot path $($target.priorPath)"
            }
            $priorItem = Get-Item -LiteralPath $priorPath -Force
            if ($priorItem.Length -ne [long]$target.priorSize) {
                throw "An activation snapshot prior file has an unexpected size: $targetPath; expected $($target.priorSize), observed $($priorItem.Length)"
            }
            $priorSha256 = Get-LowerSha256 -Path $priorPath
            if ($priorSha256 -cne [string]$target.priorSha256) {
                throw "An activation snapshot prior file has an unexpected SHA-256: $targetPath; expected $($target.priorSha256), observed $priorSha256"
            }
            $expectedSnapshotFiles.Add([ordered]@{
                path = [string]$target.priorPath
                size = [long]$target.priorSize
                sha256 = [string]$target.priorSha256
            })
        } elseif ($null -ne $target.priorPath -or $null -ne $target.priorSha256 -or
            [long]$target.priorSize -ne 0) {
            throw "An absent activation snapshot target declares unexpected prior bytes: $targetPath"
        }
    }
    $expectedSnapshotFiles.Add([ordered]@{
        path = 'snapshot.json'
        size = (Get-Item -LiteralPath $manifestPath -Force).Length
        sha256 = Get-LowerSha256 -Path $manifestPath
    })
    if (-not (Test-PSOBBManifestEntriesEqual `
        -Left (Get-PSOBBDirectoryManifest -Root $Path) `
        -Right @($expectedSnapshotFiles))) {
        throw 'The activation snapshot contains a missing, changed, or undeclared extra file'
    }
    $manifest
}

function Restore-ActivationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$ClientRoot,
        [switch]$RequireActiveMatch
    )

    foreach ($target in @($Snapshot.targets | Sort-Object path -Descending)) {
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $ClientRoot ([string]$target.path).Replace('/', '\')) `
            -Root $ClientRoot
        if ($RequireActiveMatch) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Item -LiteralPath $destination -Force).Length -ne
                    [long]$target.activeSize -or
                (Get-LowerSha256 -Path $destination) -cne
                    [string]$target.activeSha256) {
                throw "Rollback refuses an activated target with unknown bytes: $($target.path)"
            }
        }
        if ([string]$target.priorState -ceq 'present') {
            $source = Assert-PathWithinRoot `
                -Path (Join-Path $SnapshotPath ([string]$target.priorPath).Replace('/', '\')) `
                -Root $SnapshotPath
            Copy-VerifiedAtomicFile -Source $source -Destination $destination `
                -Size ([long]$target.priorSize) `
                -Sha256 ([string]$target.priorSha256) -Root $ClientRoot
        } else {
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
        }
    }
    $profileBefore = Join-Path $SnapshotPath 'prior\client-profile.json'
    Copy-VerifiedAtomicFile -Source $profileBefore `
        -Destination (Join-Path $ClientRoot 'client-profile.json') `
        -Size ([long]$Snapshot.profileBefore.size) `
        -Sha256 ([string]$Snapshot.profileBefore.sha256) `
        -Root $ClientRoot
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SourcesLockPath)) {
    $SourcesLockPath = Join-Path $repositoryRoot 'config\sources.lock.json'
}
$approvedSourcesLockPath = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot 'config\sources.lock.json'))
$requestedSourcesLockPath = [System.IO.Path]::GetFullPath($SourcesLockPath)
if (-not $requestedSourcesLockPath.Equals(
    $approvedSourcesLockPath,
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Client asset activation requires the source-controlled production sources.lock.json'
}
$SourcesLockPath = $approvedSourcesLockPath
$sources = Get-StrictJsonFile -Path $SourcesLockPath -MaximumMegabytes 2 `
    -Label 'sources lock'
if ([int]$sources.schemaVersion -ne 1) {
    throw 'sources.lock.json schema version is not supported'
}
$component = Get-ExactComponent -Sources $sources -Id $script:AssetComponentId
if ([string]$component.distributionClass -cne 'local-only' -or
    [string]$component.compatibilityState -cne 'ephinea-only-upstream-warning' -or
    [string]$component.activationRequirements.requiredComponentId -cne
        $script:LargeAssetsComponentId -or
    [string]$component.activationRequirements.requiredCapability -cne
        'large-assets-59nl' -or
    [long]$component.activationRequirements.requiredMaximumAssetBytes -ne 100000000) {
    throw 'The AshenbubsHD source lock no longer preserves the approved local-only activation gate'
}

$clientRoot = Join-Path $layout.LocalLab 'runtime\client'
$clientProfilePath = Join-Path $clientRoot 'client-profile.json'
$activationRoot = Join-Path $layout.LocalLab `
    'asset-activations\ashenbubs-hd-psobb-v1.02'
$currentActivationRoot = Join-Path $activationRoot 'current'
$snapshotsRoot = Join-Path $activationRoot 'snapshots'
$rejectedRoot = Join-Path $activationRoot 'rejected'
foreach ($path in @($clientRoot, $clientProfilePath, $activationRoot,
    $currentActivationRoot, $snapshotsRoot, $rejectedRoot)) {
    Assert-PathWithinRoot -Path $path -Root $layout.Root | Out-Null
}

if ($Action -in @('Activate', 'Verify')) {
    Assert-PSOBBStoppedForClientAssetMutation -Layout $layout
    & (Join-Path $PSScriptRoot 'Set-PSOBBAshenbubsHDOverlay.ps1') `
        -Action Verify -SourcesLockPath $SourcesLockPath `
        -RuntimeRoot $layout.Root | Out-Null
}

$mutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    Assert-PSOBBStoppedForClientAssetMutation -Layout $layout

    if ($Action -eq 'Verify') {
        $profile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
        if ($null -eq $profile.PSObject.Properties['localAssetOverlay']) {
            throw 'The LocalLab client does not have an active AshenbubsHD overlay'
        }
        $staged = Get-StagedAshenbubsComposition -Layout $layout -Component $component
        if ([string]$profile.localAssetOverlay.stagedManifestSha256 -cne
            $staged.ManifestSha256) {
            throw 'The active client is not bound to the current exact staged AshenbubsHD overlay'
        }
        [pscustomobject]@{
            Action = 'Verify'
            Valid = $true
            ProfileId = [string]$profile.profileId
            Selection = [string]$profile.localAssetOverlay.selection
            AssetFiles = [int]$profile.localAssetOverlay.composedFileCount
            SnapshotId = [string]$profile.localAssetOverlay.snapshotId
            DistributionClass = 'local-only'
        }
        return
    }

    if ($Action -eq 'Rollback') {
        $legacySchemaRollback = $false
        try {
            $rawProfile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
        } catch {
            $runtimeContractError = $_
            $rawProfile = Get-StrictJsonFile -Path $clientProfilePath `
                -Label 'LocalLab client profile'
            $clientIdentity = Assert-PSOBBApprovedClientExecutable `
                -Path (Join-Path $clientRoot 'Psobb.exe')
            if ([int]$rawProfile.schemaVersion -ne 6 -or
                [string]$rawProfile.channel -cne 'local-lab' -or
                [string]$rawProfile.profileId -cne 'lab-widescreen-hd-16x10' -or
                [string]$rawProfile.baseExecutableSha256 -cne
                    [string]$clientIdentity.Sha256 -or
                $null -eq $rawProfile.PSObject.Properties['localAssetOverlay'] -or
                $null -ne $rawProfile.PSObject.Properties['localVisualAssets']) {
                throw $runtimeContractError
            }
            # Schema 6 is the exact immediately preceding materialization. It
            # cannot launch under the current contract, but its hash-bound
            # Ashenbubs activation snapshot remains the only safe bridge to a
            # clean profile that the schema-7 materializer can replace.
            $legacySchemaRollback = $true
        }
        if ($null -ne $rawProfile.PSObject.Properties['localVisualAssets']) {
            throw ('Roll back local visual assets in reverse activation order ' +
                'before rolling back AshenbubsHD')
        }
        $profileOverlay = $rawProfile.PSObject.Properties['localAssetOverlay']
        $selectedSnapshotId = $SnapshotId
        if ([string]::IsNullOrWhiteSpace($selectedSnapshotId) -and
            $null -ne $profileOverlay -and $null -ne $profileOverlay.Value) {
            $selectedSnapshotId = [string]$profileOverlay.Value.snapshotId
        }
        if ($selectedSnapshotId -cnotmatch
            '^activation-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$') {
            throw 'Rollback requires the exact active activation snapshot ID'
        }
        if ($null -eq $profileOverlay -or
            [string]$profileOverlay.Value.snapshotId -cne $selectedSnapshotId) {
            throw 'Rollback refuses a snapshot that is not declared by the active client profile'
        }
        $snapshotPath = Assert-PathWithinRoot `
            -Path (Join-Path $snapshotsRoot $selectedSnapshotId) -Root $snapshotsRoot
        $snapshot = Get-ActivationSnapshot -Path $snapshotPath `
            -ExpectedId $selectedSnapshotId -ClientRoot $clientRoot
        if (-not $PSCmdlet.ShouldProcess(
            $clientRoot,
            "restore AshenbubsHD activation snapshot $selectedSnapshotId")) {
            return
        }
        Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null
        Restore-ActivationSnapshot -SnapshotPath $snapshotPath -Snapshot $snapshot `
            -ClientRoot $clientRoot -RequireActiveMatch
        if (Test-Path -LiteralPath $currentActivationRoot) {
            New-Item -ItemType Directory -Path $rejectedRoot -Force | Out-Null
            $rolledBackPath = Join-Path $rejectedRoot (
                'rolled-back-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
            Assert-PathWithinRoot -Path $rolledBackPath -Root $rejectedRoot | Out-Null
            Move-Item -LiteralPath $currentActivationRoot -Destination $rolledBackPath
        }
        if ($legacySchemaRollback) {
            $restoredProfile = Get-StrictJsonFile -Path $clientProfilePath `
                -Label 'Restored LocalLab client profile'
            if ([int]$restoredProfile.schemaVersion -ne 6 -or
                [string]$restoredProfile.channel -cne 'local-lab' -or
                [string]$restoredProfile.profileId -cne 'lab-widescreen-16x10' -or
                [string]$restoredProfile.baseExecutableSha256 -cne
                    [string]$clientIdentity.Sha256 -or
                $null -ne $restoredProfile.PSObject.Properties['localAssetOverlay'] -or
                $null -ne $restoredProfile.PSObject.Properties['localModules'] -or
                $null -ne $restoredProfile.PSObject.Properties['localVisualAssets']) {
                throw 'The legacy AshenbubsHD rollback did not restore the exact clean schema-6 profile'
            }
        } else {
            Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
        }
        [pscustomobject]@{
            Action = 'Rollback'
            Changed = $true
            LegacySchemaRollback = $legacySchemaRollback
            SnapshotId = $selectedSnapshotId
            ProfileId = [string]$snapshot.profileId
            RestoredAssetTargets = @($snapshot.targets).Count - 2
        }
        return
    }

    $profile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
    if ($null -ne $profile.PSObject.Properties['localVisualAssets']) {
        throw ('Activate AshenbubsHD before local visual assets; roll the ' +
            'visual-asset stack back before changing the base asset overlay')
    }
    if ($null -ne $profile.PSObject.Properties['localAssetOverlay'] -or
        $null -ne $profile.PSObject.Properties['localModules']) {
        throw 'An AshenbubsHD overlay is already active; verify it or roll it back before activating another selection'
    }
    if (Test-Path -LiteralPath $currentActivationRoot) {
        throw 'A stale asset activation record exists without a matching client profile; inspect and roll back before continuing'
    }
    $baseProfileId = 'lab-widescreen-16x10'
    $activatedProfileId = 'lab-widescreen-hd-16x10'
    if ([string]$profile.profileId -cne $baseProfileId) {
        throw "AshenbubsHD activation requires the exact no-CAS '$baseProfileId' LocalLab profile"
    }
    $graphicsCatalog = Get-StrictJsonFile `
        -Path (Join-Path $repositoryRoot 'config\graphics-profiles.json') `
        -Label 'graphics profile catalog'
    $activatedDeclarations = @($graphicsCatalog.profiles | Where-Object {
        [string]$_.id -ceq $activatedProfileId -and
        [string]$_.channel -ceq 'local-lab'
    })
    if ($activatedDeclarations.Count -ne 1 -or
        [string]$activatedDeclarations[0].rollbackProfileId -cne $baseProfileId -or
        [string]$activatedDeclarations[0].distributionClass -cne 'local-only') {
        throw "The exact '$activatedProfileId' LocalLab catalog declaration is not ready for activation"
    }
    $staged = Get-StagedAshenbubsComposition -Layout $layout -Component $component
    $identity = Assert-PSOBBApprovedClientExecutable `
        -Path (Join-Path $clientRoot 'Psobb.exe')
    if ($identity.Sha256 -cne
        [string]$component.activationRequirements.requiredClientExecutableSha256) {
        throw 'The staged AshenbubsHD overlay does not target this exact LocalLab executable'
    }
    $build = Get-PSOBBLargeAssetsBuildContract
    if ($build.ComponentId -cne
            [string]$component.activationRequirements.requiredComponentId -or
        $build.Capability -cne
            [string]$component.activationRequirements.requiredCapability -or
        $build.MaximumAssetBytes -ne
            [uint32]$component.activationRequirements.requiredMaximumAssetBytes) {
        throw 'The project-owned large-assets build does not satisfy the staged overlay requirement'
    }
    Invoke-PSOBBLargeAssetsExactClientVerifier `
        -ClientExecutablePath (Join-Path $clientRoot 'Psobb.exe') `
        -BuildContract $build | Out-Null

    $baseManifest = Get-StrictJsonFile -Path $layout.BaseClientManifest `
        -Label 'immutable base-client manifest'
    if ([int]$baseManifest.schemaVersion -ne 1 -or
        -not (Test-PSOBBDirectoryManifest -Root $layout.BaseClient `
            -Files @($baseManifest.files))) {
        throw 'The immutable base-client tree no longer matches its complete approved manifest'
    }
    $baseFiles = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($baseFile in @($baseManifest.files)) {
        $baseFiles.Add([string]$baseFile.path, $baseFile)
    }

    $largeAssetsIniText = "[LargeAssets]`r`nEnabled=1`r`n"
    $transactionRoot = Join-Path $activationRoot (
        '.activation-' + [Guid]::NewGuid().ToString('N'))
    $iniSource = Join-Path $transactionRoot 'PSOBB.LargeAssets.ini'
    $snapshotStaging = Join-Path $activationRoot (
        '.snapshot-' + [Guid]::NewGuid().ToString('N'))
    $currentStaging = Join-Path $activationRoot (
        '.current-' + [Guid]::NewGuid().ToString('N'))
    foreach ($path in @($transactionRoot, $iniSource, $snapshotStaging,
        $currentStaging)) {
        Assert-PathWithinRoot -Path $path -Root $activationRoot | Out-Null
    }
    $iniBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        $largeAssetsIniText)
    $iniSize = $iniBytes.Length
    $iniHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($iniBytes)).ToLowerInvariant()

    $assetTargets = [System.Collections.Generic.List[object]]::new()
    foreach ($asset in @($staged.Files)) {
        $assetTargets.Add([pscustomobject]@{
            Path = Resolve-PSOBBActivationTargetPath `
                -AssetPath ([string]$asset.Path) -BaseFiles $baseFiles
            SourcePath = [string]$asset.SourcePath
            ActiveSize = [long]$asset.Size
            ActiveSha256 = [string]$asset.Sha256
        })
    }
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($assetTarget in @($assetTargets)) {
        $targets.Add($assetTarget)
    }
    $targets.Add([pscustomobject]@{
        Path = 'plugins/PSOBB.LargeAssets.asi'
        SourcePath = [string]$build.ArtifactPath
        ActiveSize = [long]$build.ArtifactSize
        ActiveSha256 = [string]$build.ArtifactSha256
    })
    $targets.Add([pscustomobject]@{
        Path = 'plugins/PSOBB.LargeAssets.ini'
        SourcePath = $iniSource
        ActiveSize = [long]$iniSize
        ActiveSha256 = [string]$iniHash
    })

    $profileBefore = Get-Item -LiteralPath $clientProfilePath -Force
    $snapshotTargets = [System.Collections.Generic.List[object]]::new()
    [long]$snapshotBytes = $profileBefore.Length
    foreach ($target in @($targets)) {
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $clientRoot ([string]$target.Path).Replace('/', '\')) `
            -Root $clientRoot
        $baseDeclaration = if ($baseFiles.ContainsKey([string]$target.Path)) {
            $baseFiles[[string]$target.Path]
        } else {
            $null
        }
        if ($null -ne $baseDeclaration) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Item -LiteralPath $destination -Force).Length -ne
                    [long]$baseDeclaration.size -or
                (Get-LowerSha256 -Path $destination) -cne
                    [string]$baseDeclaration.sha256) {
                throw "Activation refuses an approved replacement target with unknown existing bytes: $($target.Path)"
            }
            $priorPath = 'prior/' + [string]$target.Path
            $snapshotBytes += [long]$baseDeclaration.size
            $snapshotTargets.Add([ordered]@{
                path = [string]$target.Path
                activeSize = [long]$target.ActiveSize
                activeSha256 = [string]$target.ActiveSha256
                priorState = 'present'
                priorPath = $priorPath
                priorSize = [long]$baseDeclaration.size
                priorSha256 = [string]$baseDeclaration.sha256
            })
        } else {
            if (Test-Path -LiteralPath $destination) {
                throw "Activation refuses an undeclared existing conflict: $($target.Path)"
            }
            $snapshotTargets.Add([ordered]@{
                path = [string]$target.Path
                activeSize = [long]$target.ActiveSize
                activeSha256 = [string]$target.ActiveSha256
                priorState = 'absent'
                priorPath = $null
                priorSize = 0
                priorSha256 = $null
            })
        }
    }

    $driveName = [System.IO.Path]::GetPathRoot($layout.Root).Substring(0, 1)
    $drive = Get-PSDrive -Name $driveName
    $requiredFreeBytes = $snapshotBytes +
        [long](($targets | Measure-Object ActiveSize -Maximum).Maximum) + 256MB
    if ($drive.Free -lt $requiredFreeBytes) {
        throw "Insufficient free space for transactional activation; require at least $requiredFreeBytes bytes"
    }
    if (-not $PSCmdlet.ShouldProcess(
        $clientRoot,
        "activate unchanged AshenbubsHD $($staged.Selection) assets with the exact project large-assets module")) {
        return
    }
    Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null

    $snapshotId = 'activation-{0}-{1}' -f
        [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'),
        [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $snapshotPath = Join-Path $snapshotsRoot $snapshotId
    Assert-PathWithinRoot -Path $snapshotPath -Root $snapshotsRoot | Out-Null
    $snapshotCreated = $false
    $activationRecordInstalled = $false
    try {
        New-Item -ItemType Directory -Path $transactionRoot, $snapshotStaging `
            -Force | Out-Null
        [System.IO.File]::WriteAllBytes($iniSource, $iniBytes)
        if ((Get-Item -LiteralPath $iniSource).Length -ne $iniSize -or
            (Get-LowerSha256 -Path $iniSource) -cne $iniHash) {
            throw 'The generated PSOBB.LargeAssets configuration changed before activation'
        }
        $snapshotPrior = Join-Path $snapshotStaging 'prior'
        New-Item -ItemType Directory -Path $snapshotPrior -Force | Out-Null
        Copy-Item -LiteralPath $clientProfilePath `
            -Destination (Join-Path $snapshotPrior 'client-profile.json')
        foreach ($entry in @($snapshotTargets | Where-Object priorState -ceq 'present')) {
            $source = Join-Path $clientRoot ([string]$entry.path).Replace('/', '\')
            $destination = Join-Path $snapshotStaging `
                ([string]$entry.priorPath).Replace('/', '\')
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force |
                Out-Null
            Copy-Item -LiteralPath $source -Destination $destination
            if ((Get-Item -LiteralPath $destination).Length -ne [long]$entry.priorSize -or
                (Get-LowerSha256 -Path $destination) -cne [string]$entry.priorSha256) {
                throw "Activation could not verify snapshot target: $($entry.path)"
            }
        }
        $snapshotManifest = [ordered]@{
            schemaVersion = 1
            componentId = $script:AssetComponentId
            snapshotId = $snapshotId
            profileId = [string]$profile.profileId
            clientRoot = $clientRoot
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
            profileBefore = [ordered]@{
                path = 'prior/client-profile.json'
                size = $profileBefore.Length
                sha256 = Get-LowerSha256 -Path $clientProfilePath
            }
            targets = @($snapshotTargets)
        }
        [System.IO.File]::WriteAllText(
            (Join-Path $snapshotStaging 'snapshot.json'),
            ($snapshotManifest | ConvertTo-Json -Depth 20),
            [System.Text.UTF8Encoding]::new($false))
        Get-ActivationSnapshot -Path $snapshotStaging -ExpectedId $snapshotId `
            -ClientRoot $clientRoot | Out-Null
        New-Item -ItemType Directory -Path $snapshotsRoot -Force | Out-Null
        Move-Item -LiteralPath $snapshotStaging -Destination $snapshotPath
        $snapshotCreated = $true

        foreach ($target in @($targets)) {
            Copy-VerifiedAtomicFile -Source ([string]$target.SourcePath) `
                -Destination (Join-Path $clientRoot `
                    ([string]$target.Path).Replace('/', '\')) `
                -Size ([long]$target.ActiveSize) `
                -Sha256 ([string]$target.ActiveSha256) `
                -Root $clientRoot
        }

        $moduleDeclaration = [ordered]@{
            componentId = $build.ComponentId
            capability = $build.Capability
            relativePath = 'plugins/PSOBB.LargeAssets.asi'
            size = $build.ArtifactSize
            sha256 = $build.ArtifactSha256
            configurationPath = 'plugins/PSOBB.LargeAssets.ini'
            configurationSha256 = $iniHash
            buildManifestSha256 = $build.ManifestSha256
        }
        $activationFiles = @($assetTargets | ForEach-Object {
            [ordered]@{
                path = [string]$_.Path
                size = [long]$_.ActiveSize
                sha256 = [string]$_.ActiveSha256
            }
        })
        $activationManifest = [ordered]@{
            schemaVersion = 1
            componentId = $script:AssetComponentId
            version = '1.02'
            distributionClass = 'local-only'
            selection = $staged.Selection
            profileId = $activatedProfileId
            baseProfileId = $baseProfileId
            baseExecutableSha256 = $identity.Sha256
            sourceArchiveSha256 = [string]$staged.Manifest.sourceArchive.sha256
            stagedManifestSha256 = $staged.ManifestSha256
            snapshotId = $snapshotId
            sourceEntryCount = $staged.SourceEntryCount
            composedFileCount = $activationFiles.Count
            sourceExpandedAssetBytes = $staged.SourceExpandedAssetBytes
            composedAssetBytes = $staged.ComposedAssetBytes
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
            files = $activationFiles
            module = $moduleDeclaration
        }
        New-Item -ItemType Directory -Path $currentStaging -Force | Out-Null
        [System.IO.File]::WriteAllText(
            (Join-Path $currentStaging 'activation.json'),
            ($activationManifest | ConvertTo-Json -Depth 20),
            [System.Text.UTF8Encoding]::new($false))
        New-Item -ItemType Directory -Path $activationRoot -Force | Out-Null
        Move-Item -LiteralPath $currentStaging -Destination $currentActivationRoot
        $activationRecordInstalled = $true
        $activationManifestPath = Join-Path $currentActivationRoot 'activation.json'
        $activationManifestHash = Get-LowerSha256 -Path $activationManifestPath

        $overlayDeclaration = [ordered]@{
            schemaVersion = 1
            componentId = $script:AssetComponentId
            version = '1.02'
            distributionClass = 'local-only'
            selection = $staged.Selection
            baseProfileId = $baseProfileId
            activationManifestPath = $script:ActivationRelativePath
            activationManifestSha256 = $activationManifestHash
            sourceArchiveSha256 = [string]$staged.Manifest.sourceArchive.sha256
            stagedManifestSha256 = $staged.ManifestSha256
            snapshotId = $snapshotId
            sourceEntryCount = $staged.SourceEntryCount
            composedFileCount = $activationFiles.Count
            sourceExpandedAssetBytes = $staged.SourceExpandedAssetBytes
            composedAssetBytes = $staged.ComposedAssetBytes
        }
        $profile.profileId = $activatedProfileId
        $profile.rollbackProfileId = $baseProfileId
        $profile | Add-Member -NotePropertyName localAssetOverlay `
            -NotePropertyValue ([pscustomobject]$overlayDeclaration)
        $profile | Add-Member -NotePropertyName localModules `
            -NotePropertyValue @([pscustomobject]$moduleDeclaration)
        $newProfilePath = Join-Path $transactionRoot 'client-profile.json'
        [System.IO.File]::WriteAllText(
            $newProfilePath,
            ($profile | ConvertTo-Json -Depth 30),
            [System.Text.UTF8Encoding]::new($false))
        Copy-VerifiedAtomicFile -Source $newProfilePath `
            -Destination $clientProfilePath `
            -Size (Get-Item -LiteralPath $newProfilePath).Length `
            -Sha256 (Get-LowerSha256 -Path $newProfilePath) -Root $clientRoot

        Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
        [pscustomobject]@{
            Action = 'Activate'
            Changed = $true
            ProfileId = $activatedProfileId
            BaseProfileId = $baseProfileId
            Selection = $staged.Selection
            AssetFiles = $activationFiles.Count
            AssetBytes = $staged.ComposedAssetBytes
            SnapshotId = $snapshotId
            LargeAssetsSha256 = $build.ArtifactSha256
            DistributionClass = 'local-only'
            RematerializationRequiresReactivation = $true
        }
    } catch {
        if ($snapshotCreated -and (Test-Path -LiteralPath $snapshotPath)) {
            try {
                $snapshot = Get-ActivationSnapshot -Path $snapshotPath `
                    -ExpectedId $snapshotId -ClientRoot $clientRoot
                Restore-ActivationSnapshot -SnapshotPath $snapshotPath `
                    -Snapshot $snapshot -ClientRoot $clientRoot
            } catch {
                throw "AshenbubsHD activation failed and automatic restoration also failed: $($_.Exception.Message)"
            }
        }
        if ($activationRecordInstalled -and
            (Test-Path -LiteralPath $currentActivationRoot)) {
            New-Item -ItemType Directory -Path $rejectedRoot -Force | Out-Null
            $failedPath = Join-Path $rejectedRoot (
                'failed-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
            Move-Item -LiteralPath $currentActivationRoot -Destination $failedPath `
                -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        foreach ($temporary in @($transactionRoot, $snapshotStaging,
            $currentStaging)) {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Recurse -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }
} finally {
    Exit-PSOBBClientOperationLock -Mutex $mutex
}
