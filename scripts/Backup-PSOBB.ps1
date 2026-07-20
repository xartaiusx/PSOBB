[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [ValidateRange(1, 100)][int]$Retention = 7,
    [ValidateSet('state', 'pre-restore')][string]$BackupKind = 'state',
    [string]$PreserveBackupPath,
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$PreserveBackupManifestSha256
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedServerExecutable {
    Get-PSOBBStableServerSourceLockIdentity
}

function Get-RecoveryItemLabel(
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][int]$Ordinal
) {
    "$Category item $Ordinal"
}

function Get-LiveStatePath(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$RelativePath
) {
    if ($RelativePath -eq 'stable/installation.json') {
        return Assert-PathWithinRoot -Path $Layout.InstallRecord -Root $Layout.Root
    }
    if (($RelativePath -eq 'system/config.json') -or
        ($RelativePath -in @('system/licenses', 'system/players', 'system/teams'))) {
        return Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Server ($RelativePath.Replace('/', '\'))) `
            -Root $Layout.Server
    }
    throw "Unsupported backup state path: $RelativePath"
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$clientOperationMutex = $null
$mutex = $null
$ownsMutex = $false
try {
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout -TimeoutSeconds 0
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
try {
    $ownsMutex = $mutex.WaitOne(0)
} catch [System.Threading.AbandonedMutexException] {
    $ownsMutex = $true
}
if (-not $ownsMutex) {
    throw 'Another PSOBB start, stop, backup, restore, or patch-profile operation is already in progress'
}
Assert-PSOBBGlobalStoppedRuntime `
    -Layout $layout -Operation 'creating a Stable backup' | Out-Null
$serverExe = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
$approvedServer = Get-ApprovedServerExecutable
if (-not (Test-Path -LiteralPath $serverExe -PathType Leaf)) {
    throw "Server executable is missing: $serverExe"
}
$serverItem = Get-Item -LiteralPath $serverExe
$serverHash = Get-LowerSha256 $serverExe
if (($serverItem.Length -ne $approvedServer.Size) -or ($serverHash -ne $approvedServer.Sha256)) {
    throw 'The installed server executable does not match the approved source-lock member'
}
$stateRoots = @(
    [ordered]@{ path = 'system/licenses'; kind = 'directory' }
    [ordered]@{ path = 'system/players'; kind = 'directory' }
    [ordered]@{ path = 'system/teams'; kind = 'directory' }
    [ordered]@{ path = 'system/config.json'; kind = 'file' }
    [ordered]@{ path = 'stable/installation.json'; kind = 'file' }
)
foreach ($stateRoot in $stateRoots) {
    $source = Get-LiveStatePath -Layout $layout -RelativePath $stateRoot.path
    $expectedType = if ($stateRoot.kind -eq 'directory') { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $source -PathType $expectedType)) {
        throw "Required $($stateRoot.kind) state root is missing: $($stateRoot.path)"
    }
    if ($stateRoot.kind -eq 'directory') {
        [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $source -Root $layout.Root `
                -Label "Stable $($stateRoot.path) state root")
    } else {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $source -Root $layout.Root -Kind File `
                -Label "Stable $($stateRoot.path) state file")
    }
}

if (-not (Test-Path -LiteralPath $layout.Backups -PathType Container)) {
    New-Item -ItemType Directory -Path $layout.Backups -Force | Out-Null
}
Assert-PathWithinRoot -Path $layout.Backups -Root $layout.Root | Out-Null
Set-PSOBBProtectedAcl -Path $layout.Backups
$preservedBackup = $null
if (-not [string]::IsNullOrWhiteSpace($PreserveBackupPath)) {
    if ([string]::IsNullOrWhiteSpace($PreserveBackupManifestSha256)) {
        throw 'A preserved backup requires its exact manifest SHA-256 binding'
    }
    try {
        $preservedBackup = (Resolve-Path -LiteralPath $PreserveBackupPath).Path
        [void](Assert-PathWithinRoot `
                -Path $preservedBackup -Root $layout.Backups)
        $preservedParent = [System.IO.Path]::GetFullPath(
            (Split-Path -Parent $preservedBackup)).TrimEnd('\')
        $backupsRoot = [System.IO.Path]::GetFullPath(
            $layout.Backups).TrimEnd('\')
        if (-not $preservedParent.Equals(
                $backupsRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'not a direct backup child'
        }
        [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $preservedBackup -Root $layout.Backups `
                -Label 'retention-preserved recovery backup' `
                -RequireProtectedAcl)
        $preservedManifest = Read-PSOBBRecoveryManifestSnapshot `
            -Path (Join-Path $preservedBackup 'manifest.json') `
            -Root $preservedBackup
        if ($preservedManifest.Sha256 -cne $PreserveBackupManifestSha256) {
            throw 'manifest binding mismatch'
        }
    } catch {
        throw 'The retention-preserved recovery backup binding is invalid'
    }
} elseif (-not [string]::IsNullOrWhiteSpace($PreserveBackupManifestSha256)) {
    throw 'A preserved backup manifest SHA-256 requires a backup path'
}
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$backup = Join-Path $layout.Backups ($BackupKind + '-' + $stamp)
$partial = $backup + '.partial-' + [Guid]::NewGuid().ToString('N')
Assert-PathWithinRoot -Path $backup -Root $layout.Backups | Out-Null
Assert-PathWithinRoot -Path $partial -Root $layout.Backups | Out-Null

$completed = $false
try {
    New-Item -ItemType Directory -Path $partial | Out-Null
    Set-PSOBBProtectedAcl -Path $partial
    foreach ($directory in @('system', 'system/licenses', 'system/players', 'system/teams', 'stable')) {
        $destination = Assert-PathWithinRoot -Path (Join-Path $partial ($directory.Replace('/', '\'))) -Root $partial
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
    }

    $manifestFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($rootName in @('licenses', 'players', 'teams')) {
        $sourceRoot = Join-Path $layout.Server ('system\' + $rootName)
        $ordinal = 0
        foreach ($sourceFile in @(Get-ChildItem -Force -LiteralPath $sourceRoot `
                -Recurse -File | Sort-Object FullName)) {
            $ordinal++
            $itemLabel = Get-RecoveryItemLabel -Category $rootName -Ordinal $ordinal
            $relativeUnderRoot = [System.IO.Path]::GetRelativePath($sourceRoot, $sourceFile.FullName)
            $relative = ('system/' + $rootName + '/' + $relativeUnderRoot.Replace('\', '/'))
            $destination = Assert-PathWithinRoot -Path (Join-Path $partial ($relative.Replace('/', '\'))) -Root $partial
            New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
            $sourceSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
                -Path $sourceFile.FullName -Root $sourceRoot -MaximumBytes 64MB `
                -AllowEmpty -IncludeBytes -Label $itemLabel
            try {
                [void](Write-PSOBBDurableFileBytes `
                        -Path $destination -Root $partial `
                        -Bytes ([byte[]]$sourceSnapshot.Bytes) -Label $itemLabel)
                $destinationSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
                    -Path $destination -Root $partial -MaximumBytes 64MB `
                    -AllowEmpty -Label $itemLabel
                if ($destinationSnapshot.Length -ne $sourceSnapshot.Length -or
                    $destinationSnapshot.Sha256 -cne $sourceSnapshot.Sha256) {
                    throw "$itemLabel failed exact backup readback"
                }
                $manifestFiles.Add([ordered]@{
                        path = $relative
                        size = [long]$sourceSnapshot.Length
                        sha256 = [string]$sourceSnapshot.Sha256
                    })
            } finally {
                if ($sourceSnapshot.Bytes) {
                    [Array]::Clear(
                        [byte[]]$sourceSnapshot.Bytes, 0,
                        ([byte[]]$sourceSnapshot.Bytes).Length)
                }
            }
        }
    }

    $fixedOrdinal = 0
    foreach ($relative in @('system/config.json', 'stable/installation.json')) {
        $fixedOrdinal++
        $itemLabel = Get-RecoveryItemLabel `
            -Category 'Stable metadata' -Ordinal $fixedOrdinal
        $source = Get-LiveStatePath -Layout $layout -RelativePath $relative
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $partial ($relative.Replace('/', '\'))) `
            -Root $partial
        $sourceSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
            -Path $source -Root $layout.Root -MaximumBytes 16MB `
            -IncludeBytes -Label $itemLabel
        try {
            [void](Write-PSOBBDurableFileBytes `
                    -Path $destination -Root $partial `
                    -Bytes ([byte[]]$sourceSnapshot.Bytes) -Label $itemLabel)
            $destinationSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
                -Path $destination -Root $partial -MaximumBytes 16MB `
                -Label $itemLabel
            if ($destinationSnapshot.Length -ne $sourceSnapshot.Length -or
                $destinationSnapshot.Sha256 -cne $sourceSnapshot.Sha256) {
                throw "$itemLabel failed exact backup readback"
            }
            $manifestFiles.Add([ordered]@{
                    path = $relative
                    size = [long]$sourceSnapshot.Length
                    sha256 = [string]$sourceSnapshot.Sha256
                })
        } finally {
            if ($sourceSnapshot.Bytes) {
                [Array]::Clear(
                    [byte[]]$sourceSnapshot.Bytes, 0,
                    ([byte[]]$sourceSnapshot.Bytes).Length)
            }
        }
    }

    $patchState = Assert-PSOBBClientPatchStateCoherent `
        -ConfigPath (Join-Path $partial 'system\config.json') `
        -InstallRecordPath (Join-Path $partial 'stable\installation.json') `
        -InstallationId ([string]$marker.installationId) `
        -RuntimeRoot $layout.Root

    $manifest = [ordered]@{
        schemaVersion = 3
        backupId = [Guid]::NewGuid().ToString('D')
        backupKind = $BackupKind
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        serverExecutable = [ordered]@{
            path = 'newserv-windows.exe'
            sourceLockComponent = $approvedServer.ComponentId
            size = [long]$serverItem.Length
            sha256 = $serverHash
        }
        clientPatchState = [ordered]@{
            profile = $patchState.Profile
            policySha256 = $patchState.PolicySha256
            configPath = 'system/config.json'
            configSha256 = $patchState.ConfigSha256
            installationPath = 'stable/installation.json'
            installationSha256 = $patchState.InstallationSha256
            installationId = $patchState.InstallationId
        }
        stateRoots = $stateRoots
        files = @($manifestFiles | Sort-Object { $_.path })
    }
    $manifestPath = Join-Path $partial 'manifest.json'
    $manifestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($manifest | ConvertTo-Json -Depth 8))
    try {
        [void](Write-PSOBBDurableFileBytes `
                -Path $manifestPath -Root $partial -Bytes $manifestBytes `
                -Label 'recovery manifest')
    } finally {
        [Array]::Clear($manifestBytes, 0, $manifestBytes.Length)
    }
    Set-PSOBBRedactedRecoveryTreeAcl `
        -Path $partial -Root $layout.Backups -Label 'backup staging tree'

    # Recheck the complete global boundary after all potentially expensive copy,
    # hashing, and ACL work and immediately before the no-clobber publication.
    Assert-PSOBBGlobalStoppedRuntime `
        -Layout $layout -Operation 'publishing a Stable backup' | Out-Null
    if (Test-Path -LiteralPath $backup) {
        throw 'The final backup name became occupied before publication'
    }
    [System.IO.Directory]::Move($partial, $backup)

    $publishedTree = Get-PSOBBRedactedRecoveryTreeSnapshot `
        -Path $backup -Root $layout.Backups -Label 'published recovery backup' `
        -RequireProtectedAcl
    $publishedManifest = Read-PSOBBRecoveryManifestSnapshot `
        -Path (Join-Path $backup 'manifest.json') -Root $backup
    if ($publishedManifest.Value.backupId -cne $manifest.backupId -or
        @($publishedManifest.Value.files).Count -ne $manifestFiles.Count) {
        throw 'Published recovery backup manifest readback differs from staging'
    }
    $readbackOrdinal = 0
    foreach ($entry in @($publishedManifest.Value.files)) {
        $readbackOrdinal++
        $category = if ([string]$entry.path -match '^system/([^/]+)/') {
            $Matches[1]
        } else { 'Stable metadata' }
        $itemLabel = Get-RecoveryItemLabel `
            -Category $category -Ordinal $readbackOrdinal
        $publishedFile = Assert-PathWithinRoot `
            -Path (Join-Path $backup (([string]$entry.path).Replace('/', '\'))) `
            -Root $backup
        $fileSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
            -Path $publishedFile -Root $backup -MaximumBytes 64MB `
            -AllowEmpty -Label $itemLabel
        if ($fileSnapshot.Length -ne [long]$entry.size -or
            $fileSnapshot.Sha256 -cne [string]$entry.sha256) {
            throw "$itemLabel failed published backup readback"
        }
    }
    $completed = $true
} finally {
    if (-not $completed -and (Test-Path -LiteralPath $partial)) {
        Remove-PSOBBRedactedRecoveryTree `
            -Path $partial -Root $layout.Backups `
            -Label 'unpublished recovery staging tree'
    }
}

Get-ChildItem -LiteralPath $layout.Backups -Directory -Filter ($BackupKind + '-*') |
    Where-Object { $_.Name -notmatch '\.partial-' } |
    Sort-Object Name -Descending |
    Select-Object -Skip $Retention |
    ForEach-Object {
        if ($_.FullName.Equals(
                $backup, [System.StringComparison]::OrdinalIgnoreCase) -or
            ($preservedBackup -and $_.FullName.Equals(
                    $preservedBackup,
                    [System.StringComparison]::OrdinalIgnoreCase))) {
            return
        }
        Remove-PSOBBRedactedRecoveryTree `
            -Path $_.FullName -Root $layout.Backups `
            -Label 'expired recovery backup' -RequireProtectedAcl
    }

$manifestPath = Join-Path $backup 'manifest.json'
[pscustomobject]@{
    BackupPath = $backup
    BackupKind = $BackupKind
    Files = $manifestFiles.Count
    ManifestSha256 = [string]$publishedManifest.Sha256
    ServerExecutableSha256 = $serverHash
    ClientPatchProfile = $patchState.Profile
    ClientPatchPolicySha256 = $patchState.PolicySha256
    Retention = $Retention
}
} finally {
    try {
        if ($ownsMutex) {
            $mutex.ReleaseMutex()
        }
    } finally {
        try {
            if ($mutex) {
                $mutex.Dispose()
            }
        } finally {
            if ($clientOperationMutex) {
                Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
            }
        }
    }
}
