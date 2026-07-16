[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateSet(
        'luthee-hd-ui-v1.1.6-local-import',
        'higher-resolution-item-box-textures-2025-12-30-local-import',
        'echelon-hd-effects-technics-2019-05-27-local-import',
        'echelon-hd-blood-2018-06-16-local-import')]
    [string]$ComponentId,

    [ValidateSet('Activate', 'Verify', 'Rollback')]
    [string]$Action = 'Activate',

    [string]$ArchivePath,
    [string]$RuntimeRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$definitions = @{
    'luthee-hd-ui-v1.1.6-local-import' = [ordered]@{
        Archive = 'archives/graphics-lab/local-assets/supplemental/luthee-hd-ui/PSOBB HD UI v1.1.6.zip'
        ReplacementPolicy = 'none'
    }
    'higher-resolution-item-box-textures-2025-12-30-local-import' = [ordered]@{
        Archive = 'archives/graphics-lab/local-assets/supplemental/higher-resolution-item-box-textures/HighResItemBoxes.rar'
        ReplacementPolicy = 'none'
    }
    'echelon-hd-effects-technics-2019-05-27-local-import' = [ordered]@{
        Archive = 'archives/graphics-lab/local-assets/supplemental/echelon-hd-effects/PARTICLES_-_HD_Custom_Effects_&_Technics.rar'
        ReplacementPolicy = 'reject-ashenbubs-collision'
    }
    'echelon-hd-blood-2018-06-16-local-import' = [ordered]@{
        Archive = 'archives/graphics-lab/local-assets/supplemental/echelon-hd-blood/MISC_-_HD_Blood_Splatters.rar'
        ReplacementPolicy = 'reject-ashenbubs-collision'
    }
}

function Get-ExactComponent {
    param([Parameter(Mandatory)]$Sources, [Parameter(Mandatory)][string]$Id)

    $matches = @($Sources.components | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "sources.lock.json must contain exactly one component named '$Id'"
    }
    $matches[0]
}

function Get-StrictJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 2MB) {
        throw "$Label has an invalid size or filesystem type"
    }
    try {
        Get-Content -Raw -LiteralPath $Path |
            ConvertFrom-Json -Depth 50 -DateKind String
    } catch {
        throw "$Label is not valid JSON: $($_.Exception.Message)"
    }
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Root
    )

    $target = Assert-PathWithinRoot -Path $Path -Root $Root
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    $temporary = $target + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Value | ConvertTo-Json -Depth 50),
            [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $target -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Copy-VerifiedFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][long]$Size,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][string]$Root
    )

    $target = Assert-PathWithinRoot -Path $Destination -Root $Root
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Source file is missing: $Source"
    }
    $sourceItem = Get-Item -LiteralPath $Source -Force
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $sourceItem.Length -ne $Size -or
        (Get-LowerSha256 -Path $Source) -cne $Sha256) {
        throw "Source file failed its size/hash contract: $Source"
    }
    if ((Test-Path -LiteralPath $target) -and
        -not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw "Destination exists but is not a regular file: $Destination"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    $temporary = $target + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        Copy-Item -LiteralPath $Source -Destination $temporary
        if ((Get-Item -LiteralPath $temporary -Force).Length -ne $Size -or
            (Get-LowerSha256 -Path $temporary) -cne $Sha256) {
            throw "Temporary copy failed verification: $Destination"
        }
        Move-Item -LiteralPath $temporary -Destination $target -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-Stopped {
    param([Parameter(Mandatory)]$Layout)

    Assert-PSOBBNoRunningClients -Layout $Layout | Out-Null
    if (@(Get-NewservProcessesAtPath -Layout $Layout).Count -gt 0 -or
        $null -ne (Get-NewservProcess -Layout $Layout)) {
        throw 'Local visual-asset mutation requires newserv and all approved PSOBB clients to be stopped'
    }
}

function Get-SevenZip {
    param([Parameter(Mandatory)]$Sources)

    $component = Get-ExactComponent -Sources $Sources -Id 'sevenzip-local-extraction-tool'
    $members = @($component.members)
    $dllMembers = @($members | Where-Object { [string]$_.path -ceq '7z.dll' })
    if ($members.Count -ne 1 -or $dllMembers.Count -ne 1 -or
        [long]$dllMembers[0].size -le 0 -or
        [string]$dllMembers[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The 7-Zip source lock must contain exactly one locked 7z.dll member'
    }

    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue
    $path = if ($command) { $command.Source } else { 'C:\Program Files\7-Zip\7z.exe' }
    $dllPath = Join-Path (Split-Path -Parent $path) '7z.dll'
    $contracts = @(
        [pscustomobject]@{
            Path = $path
            Size = [long]$component.size
            Sha256 = [string]$component.sha256
        },
        [pscustomobject]@{
            Path = $dllPath
            Size = [long]$dllMembers[0].size
            Sha256 = [string]$dllMembers[0].sha256
        })
    foreach ($contract in $contracts) {
        if (-not (Test-Path -LiteralPath $contract.Path -PathType Leaf)) {
            throw "The locked 7-Zip file is missing: $($contract.Path)"
        }
        $item = Get-Item -LiteralPath $contract.Path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne $contract.Size -or
            (Get-LowerSha256 -Path $contract.Path) -cne $contract.Sha256) {
            throw "The installed 7-Zip file does not match sources.lock.json: $($contract.Path)"
        }
    }
    $path
}

function Assert-SevenZipVisualAssetListing {
    param(
        [Parameter(Mandatory)][string]$SevenZip,
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][object[]]$LockedMembers
    )

    $output = @(& $SevenZip l -slt -ba -sccUTF-8 -- $Archive)
    if ($LASTEXITCODE -ne 0 -or $output.Count -eq 0) {
        throw '7-Zip could not produce a structural archive listing'
    }
    $blocks = [regex]::Split(
        ([string]::Join("`n", $output)).Trim(), "`n\s*`n")
    $expected = @{}
    foreach ($member in $LockedMembers) {
        $expected[[string]$member.path] = $member
    }
    $listedFiles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)

    foreach ($block in $blocks) {
        $fields = @{}
        foreach ($line in @($block -split "`n")) {
            if ($line -match '^([^=]+?) = (.*)$') {
                $fields[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        if (-not $fields.ContainsKey('Path') -or
            -not $fields.ContainsKey('Folder')) {
            throw '7-Zip returned an incomplete archive-entry listing'
        }
        $path = ([string]$fields.Path).Replace('\', '/')
        foreach ($segment in @($path.Split('/'))) {
            if ([string]::IsNullOrWhiteSpace($segment) -or
                $segment -in @('.', '..') -or $segment.EndsWith('.') -or
                $segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
                throw "The archive listing contains an unsafe path: $path"
            }
        }
        if ([string]$fields.Folder -ceq '+') {
            if ($path -cnotmatch '^data(?:/[A-Za-z0-9_.-]+)*$') {
                throw "The archive listing contains an unexpected directory: $path"
            }
            continue
        }
        if ([string]$fields.Folder -cne '-' -or
            -not (Test-SafeVisualAssetRelativePath -Path $path) -or
            -not $expected.ContainsKey($path) -or
            -not $listedFiles.Add($path) -or
            -not $fields.ContainsKey('Size') -or
            [long]$fields.Size -ne [long]$expected[$path].size -or
            ($fields.ContainsKey('Encrypted') -and
                [string]$fields.Encrypted -cne '-') -or
            ($fields.ContainsKey('Alternate Stream') -and
                [string]$fields.'Alternate Stream' -cne '-') -or
            ($fields.ContainsKey('Symbolic Link') -and
                -not [string]::IsNullOrWhiteSpace([string]$fields.'Symbolic Link')) -or
            ($fields.ContainsKey('Hard Link') -and
                -not [string]::IsNullOrWhiteSpace([string]$fields.'Hard Link'))) {
            throw "The archive listing does not match its exact safe source lock: $path"
        }
    }
    if ($listedFiles.Count -ne $LockedMembers.Count) {
        throw 'The archive listing member count does not match sources.lock.json'
    }
    @($listedFiles | Sort-Object)
}

function Test-SafeVisualAssetRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -cnotmatch
        '^data/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:bml|prs|xvm)$') {
        return $false
    }
    foreach ($segment in $Path.Split('/')) {
        if ($segment -in @('.', '..') -or $segment.EndsWith('.') -or
            $segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            return $false
        }
    }
    $true
}

function Get-LockedVisualAssetMembers {
    param([Parameter(Mandatory)]$Component)

    $members = @($Component.members)
    if ($members.Count -lt 1) {
        throw 'The local visual-asset source lock has no members'
    }
    $archivePaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $destinationPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($member in $members) {
        $archivePath = [string]$member.path
        $destinationPath = [string]$member.destinationPath
        if (-not (Test-SafeVisualAssetRelativePath -Path $archivePath) -or
            -not (Test-SafeVisualAssetRelativePath -Path $destinationPath) -or
            -not $archivePaths.Add($archivePath) -or
            -not $destinationPaths.Add($destinationPath) -or
            [long]$member.size -le 0 -or
            [string]$member.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw "The local visual-asset source lock has an unsafe or duplicate member: $archivePath"
        }
    }
    @($members)
}

function Get-ActiveEntries {
    param([Parameter(Mandatory)]$Profile)

    $property = $Profile.PSObject.Properties['localVisualAssets']
    if ($null -eq $property -or $null -eq $property.Value) { return @() }
    @($property.Value)
}

function Get-ActivationContext {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Component,
        [Parameter(Mandatory)][string]$Id
    )

    $root = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.LocalLab ("visual-asset-activations\$Id")) `
        -Root $Layout.LocalLab
    $currentRoot = Join-Path $root 'current'
    $manifestPath = Join-Path $currentRoot 'activation.json'
    [pscustomobject]@{
        Root = $root
        CurrentRoot = $currentRoot
        ManifestPath = $manifestPath
        RelativeManifestPath = (
            "visual-asset-activations/$Id/current/activation.json")
        Snapshots = Join-Path $root 'snapshots'
        Rejected = Join-Path $root 'rejected'
        Component = $Component
    }
}

function Assert-CurrentActivation {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ClientRoot,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$Context
    )

    $entries = @(Get-ActiveEntries -Profile $Profile | Where-Object {
        [string]$_.componentId -ceq [string]$Context.Component.id
    })
    if ($entries.Count -ne 1) {
        throw "The materialized profile does not declare exactly one '$($Context.Component.id)' activation"
    }
    $entry = $entries[0]
    if ([string]$entry.activationManifestPath -cne $Context.RelativeManifestPath -or
        [string]$entry.activationManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        -not (Test-Path -LiteralPath $Context.ManifestPath -PathType Leaf) -or
        (Get-LowerSha256 -Path $Context.ManifestPath) -cne
            [string]$entry.activationManifestSha256) {
        throw 'The local visual-asset activation record is missing or hash-mismatched'
    }
    $manifest = Get-StrictJson -Path $Context.ManifestPath -Label 'visual-asset activation manifest'
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.componentId -cne [string]$Context.Component.id -or
        [string]$manifest.version -cne [string]$Context.Component.version -or
        [string]$manifest.profileId -cne [string]$Profile.profileId -or
        [string]$manifest.baseExecutableSha256 -cne
            [string]$Profile.baseExecutableSha256 -or
        [string]$manifest.sourceArchiveSha256 -cne
            [string]$Context.Component.sha256 -or
        [string]$manifest.snapshotId -cne [string]$entry.snapshotId -or
        @($manifest.files).Count -ne [int]$entry.fileCount) {
        throw 'The local visual-asset activation manifest disagrees with the profile/source lock'
    }
    [long]$bytes = 0
    foreach ($file in @($manifest.files)) {
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $ClientRoot ([string]$file.destinationPath).Replace('/', '\')) `
            -Root $ClientRoot
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Item -LiteralPath $destination -Force).Length -ne [long]$file.size -or
            (Get-LowerSha256 -Path $destination) -cne [string]$file.sha256) {
            throw "An active local visual asset has drifted: $($file.destinationPath)"
        }
        $bytes += [long]$file.size
    }
    if ($bytes -ne [long]$entry.totalBytes) {
        throw 'The active local visual-asset byte total has changed'
    }
    [pscustomobject]@{ Entry = $entry; Manifest = $manifest }
}

function Get-VerifiedRollbackSnapshot {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$SnapshotRoot,
        [Parameter(Mandatory)][string]$SnapshotId,
        [Parameter(Mandatory)]$ExpectedFiles
    )

    $root = Assert-PathWithinRoot -Path $SnapshotRoot -Root $Context.Root
    $snapshotPath = Join-Path $root 'snapshot.json'
    $snapshot = Get-StrictJson -Path $snapshotPath -Label 'visual-asset rollback snapshot'
    Assert-PSOBBExactJsonProperties -Object $snapshot `
        -Label 'visual-asset rollback snapshot' -Names @(
            'schemaVersion', 'componentId', 'snapshotId', 'createdAtUtc',
            'profileBeforeSize', 'profileBeforeSha256', 'files') | Out-Null
    Assert-PSOBBActivationManifestTimestamp -Activation $snapshot | Out-Null

    $expected = @($ExpectedFiles)
    $files = @($snapshot.files)
    if ([int]$snapshot.schemaVersion -ne 1 -or
        [string]$snapshot.componentId -cne [string]$Context.Component.id -or
        [string]$snapshot.snapshotId -cne $SnapshotId -or
        $files.Count -ne $expected.Count -or
        [long]$snapshot.profileBeforeSize -le 0 -or
        [string]$snapshot.profileBeforeSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The rollback snapshot does not match the active component'
    }

    for ($index = 0; $index -lt $files.Count; $index++) {
        $file = $files[$index]
        Assert-PSOBBExactJsonProperties -Object $file `
            -Label 'visual-asset rollback file' -Names @(
                'destinationPath', 'previousExisted', 'previousSize',
                'previousSha256', 'snapshotPath') | Out-Null
        $destinationPath = [string]$file.destinationPath
        if ($destinationPath -cne [string]$expected[$index].destinationPath -or
            -not (Test-SafeVisualAssetRelativePath -Path $destinationPath) -or
            $file.previousExisted -isnot [bool]) {
            throw "The rollback snapshot has an unsafe or reordered destination: $destinationPath"
        }
        if ([bool]$file.previousExisted) {
            $expectedSnapshotPath = "previous/$index.bin"
            if ([string]$file.snapshotPath -cne $expectedSnapshotPath -or
                [long]$file.previousSize -le 0 -or
                [string]$file.previousSha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw "The rollback snapshot has an invalid previous-file contract: $destinationPath"
            }
            $source = Assert-PathWithinRoot `
                -Path (Join-Path $root $expectedSnapshotPath.Replace('/', '\')) `
                -Root $root
            if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
                (Get-Item -LiteralPath $source -Force).Length -ne
                    [long]$file.previousSize -or
                (Get-LowerSha256 -Path $source) -cne [string]$file.previousSha256) {
                throw "The rollback snapshot previous file has drifted: $destinationPath"
            }
        } elseif ([long]$file.previousSize -ne 0 -or
            $null -ne $file.previousSha256 -or $null -ne $file.snapshotPath) {
            throw "The rollback snapshot unexpectedly declares a previous file: $destinationPath"
        }
    }

    $profileBefore = Join-Path $root 'client-profile.before.json'
    if (-not (Test-Path -LiteralPath $profileBefore -PathType Leaf) -or
        (Get-Item -LiteralPath $profileBefore -Force).Length -ne
            [long]$snapshot.profileBeforeSize -or
        (Get-LowerSha256 -Path $profileBefore) -cne
            [string]$snapshot.profileBeforeSha256) {
        throw 'The rollback snapshot profile backup has drifted'
    }
    $snapshot
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

if ([string]::IsNullOrWhiteSpace($ComponentId)) {
    throw 'ComponentId is required'
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sourcesPath = Join-Path $repositoryRoot 'config\sources.lock.json'
$sources = Get-StrictJson -Path $sourcesPath -Label 'sources lock'
$component = Get-ExactComponent -Sources $sources -Id $ComponentId
$definition = $definitions[$ComponentId]
if ([string]$component.distributionClass -cne 'local-only' -or
    [string]$component.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
    [long]$component.size -le 0 -or @($component.members).Count -le 0) {
    throw 'The selected local visual-asset component is not fully locked'
}
$lockedMembers = @(Get-LockedVisualAssetMembers -Component $component)

$clientRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.LocalLab 'runtime\client') `
    -Root $layout.Root
$profilePath = Join-Path $clientRoot 'client-profile.json'
$context = Get-ActivationContext -Layout $layout -Component $component -Id $ComponentId
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    Assert-Stopped -Layout $layout
    $profile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout

    if ($Action -eq 'Verify') {
        $verified = Assert-CurrentActivation `
            -Layout $layout -ClientRoot $clientRoot -Profile $profile -Context $context
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
        [pscustomobject]@{
            Action = 'Verify'
            ComponentId = $ComponentId
            Files = @($verified.Manifest.files).Count
            ActivationManifestSha256 = Get-LowerSha256 -Path $context.ManifestPath
            DistributionClass = 'local-only'
        }
        return
    }

    if ($Action -eq 'Rollback') {
        $verified = Assert-CurrentActivation `
            -Layout $layout -ClientRoot $clientRoot -Profile $profile -Context $context
        $active = @(Get-ActiveEntries -Profile $profile)
        if ($active.Count -eq 0 -or [string]$active[-1].componentId -cne $ComponentId) {
            throw 'Local visual assets must be rolled back in reverse activation order'
        }
        $priorEntries = @(if ($active.Count -gt 1) {
            $active | Select-Object -First ($active.Count - 1)
        })
        $snapshotRoot = Assert-PathWithinRoot `
            -Path (Join-Path $context.Snapshots ([string]$verified.Manifest.snapshotId)) `
            -Root $context.Root
        $snapshotContract = Assert-PSOBBLocalVisualAssetSnapshotContract `
            -Layout $layout -ComponentId $ComponentId `
            -SnapshotId ([string]$verified.Manifest.snapshotId) `
            -ActivationFiles @($verified.Manifest.files) `
            -PriorEntries @($priorEntries)
        if ([string]$snapshotContract.SnapshotRoot -cne $snapshotRoot) {
            throw 'The rollback snapshot path does not match the active component'
        }
        $snapshot = $snapshotContract.Snapshot
        if (-not $PSCmdlet.ShouldProcess($clientRoot, "roll back private local asset $ComponentId")) {
            return
        }

        $rollbackRecovery = Assert-PathWithinRoot `
            -Path (Join-Path $context.Root (
                '.rollback-recovery-' + [Guid]::NewGuid().ToString('N'))) `
            -Root $context.Root
        $rollbackMutated = $false
        $preserveRecovery = $false
        $activeFiles = [Collections.Generic.List[object]]::new()
        $activationMoved = $false
        $rolledBack = $null
        try {
            New-Item -ItemType Directory -Path (Join-Path $rollbackRecovery 'files') `
                -Force | Out-Null
            $activeProfile = Get-Item -LiteralPath $profilePath -Force
            $activeProfileHash = Get-LowerSha256 -Path $profilePath
            Copy-VerifiedFile -Source $profilePath `
                -Destination (Join-Path $rollbackRecovery 'client-profile.active.json') `
                -Size ([long]$activeProfile.Length) -Sha256 $activeProfileHash `
                -Root $rollbackRecovery
            for ($index = 0; $index -lt @($verified.Manifest.files).Count; $index++) {
                $file = @($verified.Manifest.files)[$index]
                $destination = Assert-PathWithinRoot `
                    -Path (Join-Path $clientRoot `
                        ([string]$file.destinationPath).Replace('/', '\')) `
                    -Root $clientRoot
                $recoveryPath = Join-Path $rollbackRecovery "files\$index.bin"
                Copy-VerifiedFile -Source $destination -Destination $recoveryPath `
                    -Size ([long]$file.size) -Sha256 ([string]$file.sha256) `
                    -Root $rollbackRecovery
                $activeFiles.Add([pscustomobject]@{
                    Destination = $destination
                    RecoveryPath = $recoveryPath
                    Size = [long]$file.size
                    Sha256 = [string]$file.sha256
                })
            }

            $updatedProfile = ConvertFrom-Json -InputObject (
                $profile | ConvertTo-Json -Depth 50 -Compress) `
                -Depth 50 -DateKind String
            if ($priorEntries.Count -gt 0) {
                $updatedProfile.localVisualAssets = [object[]]$priorEntries
            } else {
                [void]$updatedProfile.PSObject.Properties.Remove('localVisualAssets')
            }

            # Recovery must be armed before the first destination changes.
            Assert-Stopped -Layout $layout
            $rollbackMutated = $true
            foreach ($file in @($snapshot.files)) {
                $destination = Assert-PathWithinRoot `
                    -Path (Join-Path $clientRoot `
                        ([string]$file.destinationPath).Replace('/', '\')) `
                    -Root $clientRoot
                if ([bool]$file.previousExisted) {
                    $source = Assert-PathWithinRoot `
                        -Path (Join-Path $snapshotRoot `
                            ([string]$file.snapshotPath).Replace('/', '\')) `
                        -Root $snapshotRoot
                    Copy-VerifiedFile -Source $source -Destination $destination `
                        -Size ([long]$file.previousSize) `
                        -Sha256 ([string]$file.previousSha256) -Root $clientRoot
                } elseif (Test-Path -LiteralPath $destination) {
                    Remove-Item -LiteralPath $destination -Force
                }
            }
            # Remove only this stack entry. Preserve current window mode and
            # every unrelated materialized profile field.
            Write-AtomicJson -Path $profilePath -Value $updatedProfile -Root $clientRoot
            New-Item -ItemType Directory -Path $context.Rejected -Force | Out-Null
            $rolledBack = Join-Path $context.Rejected (
                'rolled-back-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') +
                '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            Move-Item -LiteralPath $context.CurrentRoot -Destination $rolledBack
            $activationMoved = $true
            Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
            $rollbackMutated = $false
            [pscustomobject]@{
                Action = 'Rollback'
                ComponentId = $ComponentId
                RestoredFiles = @($snapshot.files).Count
                SnapshotId = [string]$snapshot.snapshotId
            }
        } catch {
            $originalError = $_
            if ($rollbackMutated) {
                try {
                    if ($activationMoved) {
                        if (Test-Path -LiteralPath $context.CurrentRoot) {
                            throw 'The active visual-asset record was unexpectedly recreated during rollback recovery'
                        }
                        Move-Item -LiteralPath $rolledBack `
                            -Destination $context.CurrentRoot
                    }
                    foreach ($file in $activeFiles) {
                        Copy-VerifiedFile -Source $file.RecoveryPath `
                            -Destination $file.Destination -Size $file.Size `
                            -Sha256 $file.Sha256 -Root $clientRoot
                    }
                    Copy-VerifiedFile `
                        -Source (Join-Path $rollbackRecovery 'client-profile.active.json') `
                        -Destination $profilePath -Size ([long]$activeProfile.Length) `
                        -Sha256 $activeProfileHash -Root $clientRoot
                    Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
                } catch {
                    $preserveRecovery = $true
                    throw "Local visual-asset rollback failed and automatic reactivation also failed; recovery is preserved at $rollbackRecovery. Reactivation error: $($_.Exception.Message). Original error: $($originalError.Exception.Message)"
                }
            }
            throw $originalError
        } finally {
            if (-not $preserveRecovery -and
                (Test-Path -LiteralPath $rollbackRecovery -PathType Container)) {
                Remove-Item -LiteralPath $rollbackRecovery -Recurse -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        return
    }

    $evidencePath = Join-Path $repositoryRoot 'config\graphics-evidence.json'
    $evidence = Get-StrictJson -Path $evidencePath -Label 'graphics evidence'
    Assert-PSOBBLocalVisualAssetCandidateDisposition `
        -ComponentId $ComponentId -SourceComponent $component `
        -Evidence $evidence | Out-Null

    if (Test-Path -LiteralPath $context.CurrentRoot) {
        throw "The component is already active; verify or roll it back first: $ComponentId"
    }
    if ([int]$profile.schemaVersion -lt 7 -or
        [string]$profile.profileId -cnotin @(
            'lab-widescreen-16x10', 'lab-widescreen-hd-16x10')) {
        throw 'Local visual assets require the current schema-7 local widescreen or HD profile'
    }
    $active = @(Get-ActiveEntries -Profile $profile)
    if (@($active | Where-Object { [string]$_.componentId -ceq $ComponentId }).Count -gt 0) {
        throw "The profile already declares this component: $ComponentId"
    }

    $hasAshenbubs = $null -ne $profile.PSObject.Properties['localAssetOverlay']
    if (-not $hasAshenbubs) {
        throw 'Activate the full AshenbubsHD All foundation before any supplemental visual asset'
    }
    $ashenbubsActivationPath = Assert-PathWithinRoot `
        -Path (Join-Path $layout.LocalLab `
            ([string]$profile.localAssetOverlay.activationManifestPath).Replace('/', '\')) `
        -Root $layout.LocalLab
    $ashenbubsActivation = Get-StrictJson `
        -Path $ashenbubsActivationPath -Label 'AshenbubsHD activation manifest'
    if ([string]$ashenbubsActivation.selection -cne 'All') {
        throw 'Supplemental visual assets require the full AshenbubsHD All foundation'
    }
    $ashenbubsDestinations = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @($ashenbubsActivation.files)) {
        [void]$ashenbubsDestinations.Add([string]$file.path)
    }
    $ashenbubsCollision = @($lockedMembers | Where-Object {
        $ashenbubsDestinations.Contains([string]$_.destinationPath)
    }) | Select-Object -First 1
    if ($ashenbubsCollision) {
        throw ('AshenbubsHD All is the immutable visual foundation; ' +
            "another asset cannot replace $($ashenbubsCollision.destinationPath)")
    }

    $existingDestinations = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $active) {
        $activationPath = Assert-PathWithinRoot `
            -Path (Join-Path $layout.LocalLab `
                ([string]$entry.activationManifestPath).Replace('/', '\')) `
            -Root $layout.LocalLab
        $activation = Get-StrictJson -Path $activationPath -Label 'existing visual-asset activation'
        foreach ($file in @($activation.files)) {
            [void]$existingDestinations.Add([string]$file.destinationPath)
        }
    }
    $duplicateDestination = @($lockedMembers | Where-Object {
        $existingDestinations.Contains([string]$_.destinationPath)
    }) | Select-Object -First 1
    if ($duplicateDestination) {
        throw "A local visual asset already owns destination: $($duplicateDestination.destinationPath)"
    }

    if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
        $ArchivePath = Join-Path $layout.Root ([string]$definition.Archive).Replace('/', '\')
    }
    $archive = Assert-PathWithinRoot -Path $ArchivePath -Root $layout.Root
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf) -or
        (Get-Item -LiteralPath $archive -Force).Length -ne [long]$component.size -or
        (Get-LowerSha256 -Path $archive) -cne [string]$component.sha256) {
        throw 'The selected archive does not match its exact source lock'
    }
    $sevenZip = Get-SevenZip -Sources $sources
    Assert-SevenZipVisualAssetListing -SevenZip $sevenZip `
        -Archive $archive -LockedMembers $lockedMembers | Out-Null
    & $sevenZip t -bb0 -y -- $archive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '7-Zip archive integrity test failed' }

    $transactionId = [Guid]::NewGuid().ToString('N')
    $snapshotRoot = $null
    $snapshotStaging = $null
    $currentStaging = $null
    $prepared = $null
    $clientMutated = $false
    $staging = Assert-PathWithinRoot `
        -Path (Join-Path $layout.LocalLab (".staging\visual-assets\$transactionId")) `
        -Root $layout.LocalLab
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        & $sevenZip x -bb0 -y ("-o$staging") -- $archive | Out-Null
        if ($LASTEXITCODE -ne 0) { throw '7-Zip extraction failed' }
        $reparse = Get-ChildItem -LiteralPath $staging -Recurse -Force `
            -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($reparse) { throw "Extracted archive contains a reparse point: $($reparse.FullName)" }

        $extracted = @(Get-ChildItem -LiteralPath $staging -File -Recurse -Force)
        if ($extracted.Count -ne $lockedMembers.Count) {
            throw 'The extracted archive member count does not match sources.lock.json'
        }
        $prepared = [Collections.Generic.List[object]]::new()
        foreach ($member in $lockedMembers) {
            $source = Assert-PathWithinRoot `
                -Path (Join-Path $staging ([string]$member.path).Replace('/', '\')) `
                -Root $staging
            if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
                (Get-Item -LiteralPath $source -Force).Length -ne [long]$member.size -or
                (Get-LowerSha256 -Path $source) -cne [string]$member.sha256) {
                throw "Extracted asset does not match its lock: $($member.path)"
            }
            $prepared.Add([pscustomobject]@{
                ArchivePath = [string]$member.path
                DestinationPath = [string]$member.destinationPath
                Source = $source
                Size = [long]$member.size
                Sha256 = [string]$member.sha256
            })
        }

        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
        $snapshotId = "activation-$stamp-$($transactionId.Substring(0,8))"
        $snapshotStaging = Assert-PathWithinRoot `
            -Path (Join-Path $context.Snapshots ($snapshotId + '.partial')) `
            -Root $context.Root
        $snapshotRoot = Join-Path $context.Snapshots $snapshotId
        New-Item -ItemType Directory -Path (Join-Path $snapshotStaging 'previous') -Force | Out-Null
        Copy-Item -LiteralPath $profilePath `
            -Destination (Join-Path $snapshotStaging 'client-profile.before.json')
        $snapshotFiles = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $prepared.Count; $index++) {
            $file = $prepared[$index]
            $destination = Assert-PathWithinRoot `
                -Path (Join-Path $clientRoot $file.DestinationPath.Replace('/', '\')) `
                -Root $clientRoot
            $previousExisted = Test-Path -LiteralPath $destination -PathType Leaf
            $snapshotPath = if ($previousExisted) { "previous/$index.bin" } else { $null }
            $previousSize = if ($previousExisted) { (Get-Item -LiteralPath $destination).Length } else { 0 }
            $previousHash = if ($previousExisted) { Get-LowerSha256 -Path $destination } else { $null }
            if ($previousExisted) {
                Copy-Item -LiteralPath $destination `
                    -Destination (Join-Path $snapshotStaging $snapshotPath.Replace('/', '\'))
            }
            $snapshotFiles.Add([ordered]@{
                destinationPath = $file.DestinationPath
                previousExisted = $previousExisted
                previousSize = [long]$previousSize
                previousSha256 = $previousHash
                snapshotPath = $snapshotPath
            })
        }
        $profileBefore = Get-Item -LiteralPath (Join-Path $snapshotStaging 'client-profile.before.json')
        $snapshotManifest = [ordered]@{
            schemaVersion = 1
            componentId = $ComponentId
            snapshotId = $snapshotId
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
            profileBeforeSize = [long]$profileBefore.Length
            profileBeforeSha256 = Get-LowerSha256 -Path $profileBefore.FullName
            files = @($snapshotFiles)
        }
        Write-AtomicJson -Path (Join-Path $snapshotStaging 'snapshot.json') `
            -Value $snapshotManifest -Root $snapshotStaging
        New-Item -ItemType Directory -Path $context.Snapshots -Force | Out-Null
        Move-Item -LiteralPath $snapshotStaging -Destination $snapshotRoot

        if (-not $PSCmdlet.ShouldProcess(
            $clientRoot,
            "activate unchanged private local asset $ComponentId")) {
            Remove-Item -LiteralPath $snapshotRoot -Recurse -Force
            return
        }

        # Recovery must be armed before the first destination changes.
        $clientMutated = $true
        foreach ($file in $prepared) {
            Copy-VerifiedFile -Source $file.Source `
                -Destination (Join-Path $clientRoot $file.DestinationPath.Replace('/', '\')) `
                -Size $file.Size -Sha256 $file.Sha256 -Root $clientRoot
        }
        $manifestFiles = @($prepared | ForEach-Object {
            [ordered]@{
                archivePath = $_.ArchivePath
                destinationPath = $_.DestinationPath
                size = [long]$_.Size
                sha256 = $_.Sha256
            }
        })
        $activationManifest = [ordered]@{
            schemaVersion = 1
            componentId = $ComponentId
            version = [string]$component.version
            distributionClass = 'local-only'
            replacementPolicy = [string]$definition.ReplacementPolicy
            profileId = [string]$profile.profileId
            baseExecutableSha256 = [string]$profile.baseExecutableSha256
            sourceArchiveSha256 = [string]$component.sha256
            snapshotId = $snapshotId
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
            files = $manifestFiles
        }
        $currentStaging = $context.CurrentRoot + '.partial-' + $transactionId
        Write-AtomicJson -Path (Join-Path $currentStaging 'activation.json') `
            -Value $activationManifest -Root $currentStaging
        New-Item -ItemType Directory -Path $context.Root -Force | Out-Null
        Move-Item -LiteralPath $currentStaging -Destination $context.CurrentRoot
        $activationHash = Get-LowerSha256 -Path $context.ManifestPath
        [long]$totalBytes = ($prepared | Measure-Object -Property Size -Sum).Sum
        $profileEntry = [pscustomobject][ordered]@{
            schemaVersion = 1
            componentId = $ComponentId
            version = [string]$component.version
            distributionClass = 'local-only'
            replacementPolicy = [string]$definition.ReplacementPolicy
            activationManifestPath = $context.RelativeManifestPath
            activationManifestSha256 = $activationHash
            sourceArchiveSha256 = [string]$component.sha256
            snapshotId = $snapshotId
            fileCount = $prepared.Count
            totalBytes = $totalBytes
        }
        $newEntries = @($active) + @($profileEntry)
        if ($profile.PSObject.Properties.Name -contains 'localVisualAssets') {
            $profile.localVisualAssets = $newEntries
        } else {
            $profile | Add-Member -NotePropertyName localVisualAssets -NotePropertyValue $newEntries
        }
        Write-AtomicJson -Path $profilePath -Value $profile -Root $clientRoot
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
        [pscustomobject]@{
            Action = 'Activate'
            ComponentId = $ComponentId
            Files = $prepared.Count
            Bytes = $totalBytes
            SnapshotId = $snapshotId
            ReplacementPolicy = [string]$definition.ReplacementPolicy
            DistributionClass = 'local-only'
        }
    } catch {
        $originalError = $_
        if ($clientMutated -and $null -ne $snapshotRoot -and
            (Test-Path -LiteralPath $snapshotRoot -PathType Container)) {
            try {
                $snapshot = Get-VerifiedRollbackSnapshot -Context $context `
                    -SnapshotRoot $snapshotRoot -SnapshotId $snapshotId `
                    -ExpectedFiles @($prepared)
                foreach ($file in @($snapshot.files)) {
                    $destination = Assert-PathWithinRoot `
                        -Path (Join-Path $clientRoot `
                            ([string]$file.destinationPath).Replace('/', '\')) `
                        -Root $clientRoot
                    if ([bool]$file.previousExisted) {
                        $source = Assert-PathWithinRoot `
                            -Path (Join-Path $snapshotRoot `
                                ([string]$file.snapshotPath).Replace('/', '\')) `
                            -Root $snapshotRoot
                        Copy-VerifiedFile -Source $source -Destination $destination `
                            -Size ([long]$file.previousSize) `
                            -Sha256 ([string]$file.previousSha256) -Root $clientRoot
                    } elseif (Test-Path -LiteralPath $destination) {
                        Remove-Item -LiteralPath $destination -Force
                    }
                }
                $profileBefore = Join-Path $snapshotRoot 'client-profile.before.json'
                Copy-VerifiedFile -Source $profileBefore -Destination $profilePath `
                    -Size ([long]$snapshot.profileBeforeSize) `
                    -Sha256 ([string]$snapshot.profileBeforeSha256) -Root $clientRoot
                if (Test-Path -LiteralPath $context.CurrentRoot) {
                    New-Item -ItemType Directory -Path $context.Rejected -Force | Out-Null
                    Move-Item -LiteralPath $context.CurrentRoot -Destination (
                        Join-Path $context.Rejected (
                            'failed-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')))
                }
                Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null
            } catch {
                throw "Local visual-asset activation failed and automatic recovery also failed: $($_.Exception.Message). Original error: $($originalError.Exception.Message)"
            }
        } elseif ($null -ne $snapshotRoot -and
            (Test-Path -LiteralPath $snapshotRoot -PathType Container)) {
            Remove-Item -LiteralPath $snapshotRoot -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
        throw $originalError
    } finally {
        foreach ($partial in @($currentStaging, $snapshotStaging, $staging)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$partial) -and
                (Test-Path -LiteralPath $partial -PathType Container)) {
                Remove-Item -LiteralPath $partial -Recurse -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
