[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$cleanupScript = Join-Path $repositoryRoot 'scripts\Remove-PSOBBLegacyRemnants.ps1'
. $cleanupScript
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$MessagePattern
    )
    $rejected = $false
    $detail = 'operation unexpectedly passed'
    try {
        & $Action
    } catch {
        $detail = $_.Exception.Message
        $rejected = $detail -match $MessagePattern
    }
    Add-Result $Name $rejected $detail
}

function New-DgVoodooFixture {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$CacheRoot
    )
    Add-Type -AssemblyName System.IO.Compression
    $archiveStream = [System.IO.File]::Open(
        $ArchivePath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
    $zip = [System.IO.Compression.ZipArchive]::new(
        $archiveStream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        $zip.CreateEntry('MS/') | Out-Null
        $entry = $zip.CreateEntry('MS/D3D8.dll')
        $stream = $entry.Open()
        try {
            $bytes = [byte[]](1, 2, 3, 4, 5)
            $stream.Write($bytes, 0, $bytes.Length)
        } finally {
            $stream.Dispose()
        }
    } finally {
        $zip.Dispose()
    }
    $outRoot = Join-Path $CacheRoot 'out\MS'
    New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
    Copy-Item -LiteralPath $ArchivePath -Destination (Join-Path $CacheRoot 'dg.zip')
    [System.IO.File]::WriteAllBytes(
        (Join-Path $outRoot 'D3D8.dll'),
        [byte[]](1, 2, 3, 4, 5))
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-LegacyCleanupTests-' + [Guid]::NewGuid().ToString('N'))
try {
    $allowedParent = Join-Path $temporaryRoot 'allowed'
    $protectedRepository = Join-Path $temporaryRoot 'canonical-source'
    $protectedRuntime = Join-Path $temporaryRoot 'canonical-runtime'
    foreach ($path in @($allowedParent, $protectedRepository, $protectedRuntime)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    Assert-Rejected `
        -Name 'relative paths are rejected' `
        -Action { Get-PSOBBNormalizedDirectoryPath -Path '.\relative' | Out-Null } `
        -MessagePattern 'fully qualified'

    $empty = Join-Path $allowedParent 'PSOBB'
    New-Item -ItemType Directory -Path $empty | Out-Null
    $emptyVerifier = {
        param($proposedTarget)
        $candidate = Assert-PSOBBCleanupCandidate `
            -Path $proposedTarget `
            -AllowedParent $allowedParent `
            -ExpectedName 'PSOBB' `
            -RepositoryRoot $protectedRepository `
            -CanonicalRuntimeRoot $protectedRuntime
        Assert-PSOBBEmptyCleanupDirectory -Path $candidate
    }.GetNewClosure()
    $planned = Invoke-PSOBBVerifiedDirectoryRemoval `
        -Path $empty `
        -Verifier $emptyVerifier `
        -ShouldRemove { $false }
    Add-Result 'preview preserves a verified empty directory' (
        $planned.Status -eq 'Planned' -and (Test-Path -LiteralPath $empty)) $planned.Detail

    $removed = Invoke-PSOBBVerifiedDirectoryRemoval `
        -Path $empty `
        -Verifier $emptyVerifier `
        -ShouldRemove { $true }
    Add-Result 'verified empty directory is removed nonrecursively' (
        $removed.Status -eq 'Removed' -and -not (Test-Path -LiteralPath $empty)) $removed.Detail

    $nonempty = Join-Path $allowedParent 'PSOBB'
    New-Item -ItemType Directory -Path $nonempty | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $nonempty 'keep.txt'), 'user data')
    Assert-Rejected `
        -Name 'nonempty directories are rejected' `
        -Action { Assert-PSOBBEmptyCleanupDirectory -Path $nonempty | Out-Null } `
        -MessagePattern 'nonempty'
    Add-Result 'nonempty rejection preserves user data' (
        (Test-Path -LiteralPath (Join-Path $nonempty 'keep.txt'))) 'fixture file remains'

    Assert-Rejected `
        -Name 'canonical repository overlap is rejected' `
        -Action {
            Assert-PSOBBCleanupCandidate `
                -Path $protectedRepository `
                -AllowedParent $temporaryRoot `
                -ExpectedName 'canonical-source' `
                -RepositoryRoot $protectedRepository `
                -CanonicalRuntimeRoot $protectedRuntime | Out-Null
        } `
        -MessagePattern 'canonical PSOBB root'

    Assert-Rejected `
        -Name 'canonical runtime overlap is rejected' `
        -Action {
            Assert-PSOBBCleanupCandidate `
                -Path $protectedRuntime `
                -AllowedParent $temporaryRoot `
                -ExpectedName 'canonical-runtime' `
                -RepositoryRoot $protectedRepository `
                -CanonicalRuntimeRoot $protectedRuntime | Out-Null
        } `
        -MessagePattern 'canonical PSOBB root'

    $differentTarget = Join-Path $allowedParent 'different-target'
    New-Item -ItemType Directory -Path $differentTarget | Out-Null
    Assert-Rejected `
        -Name 'verifier cannot authorize a different deletion target' `
        -Action {
            Invoke-PSOBBVerifiedDirectoryRemoval `
                -Path $differentTarget `
                -Verifier { param($proposedTarget) $protectedRepository } `
                -ShouldRemove { $true } | Out-Null
        } `
        -MessagePattern 'different target path'
    Add-Result 'mismatched-verifier rejection preserves target' (
        (Test-Path -LiteralPath $differentTarget)) 'unverified target remains'

    Assert-Rejected `
        -Name 'paths outside the exact parent allowlist are rejected' `
        -Action {
            Assert-PSOBBCleanupCandidate `
                -Path $nonempty `
                -AllowedParent $temporaryRoot `
                -ExpectedName 'PSOBB' `
                -RepositoryRoot $protectedRepository `
                -CanonicalRuntimeRoot $protectedRuntime | Out-Null
        } `
        -MessagePattern 'parent allowlist'

    $junctionTarget = Join-Path $temporaryRoot 'junction-target'
    $junctionPath = Join-Path $allowedParent 'junction'
    New-Item -ItemType Directory -Path $junctionTarget | Out-Null
    New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget | Out-Null
    Assert-Rejected `
        -Name 'top-level reparse candidates are rejected' `
        -Action { Assert-PSOBBOrdinaryDirectoryTree -Path $junctionPath | Out-Null } `
        -MessagePattern 'reparse point'
    Remove-Item -LiteralPath $junctionPath -Force

    $nestedRoot = Join-Path $allowedParent 'nested-reparse'
    New-Item -ItemType Directory -Path $nestedRoot | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $nestedRoot 'child') -Target $junctionTarget | Out-Null
    Assert-Rejected `
        -Name 'nested reparse candidates are rejected' `
        -Action { Assert-PSOBBOrdinaryDirectoryTree -Path $nestedRoot | Out-Null } `
        -MessagePattern 'reparse point'

    $ancestorTarget = Join-Path $temporaryRoot 'ancestor-target'
    $ancestorLink = Join-Path $temporaryRoot 'ancestor-link'
    New-Item -ItemType Directory -Path $ancestorTarget | Out-Null
    New-Item -ItemType Junction -Path $ancestorLink -Target $ancestorTarget | Out-Null
    Assert-Rejected `
        -Name 'reparse ancestors are rejected' `
        -Action { Assert-PSOBBNoReparsePath -Path (Join-Path $ancestorLink 'child') | Out-Null } `
        -MessagePattern 'reparse point'
    Remove-Item -LiteralPath $ancestorLink -Force

    $archivePath = Join-Path $temporaryRoot 'canonical.zip'
    $cacheRoot = Join-Path $allowedParent 'renderer-cache'
    New-DgVoodooFixture -ArchivePath $archivePath -CacheRoot $cacheRoot
    $archiveFile = Get-Item -LiteralPath $archivePath
    $lockComponent = [pscustomobject]@{
        size = $archiveFile.Length
        sha256 = Get-LowerSha256 -Path $archivePath
    }
    $locked = Assert-PSOBBDgVoodooArchiveLock `
        -ArchivePath $archivePath `
        -LockComponent $lockComponent
    $verified = Assert-PSOBBDgVoodooCacheMatchesArchive `
        -CacheDirectory $cacheRoot `
        -ArchivePath $locked
    Add-Result 'locked archive and exact extraction verify' (
        $verified.Files -eq 1 -and $verified.Directories -eq 1) 'one file and one directory'

    $dgVerifier = {
        param($proposedTarget)
        $candidate = Assert-PSOBBCleanupCandidate `
            -Path $proposedTarget `
            -AllowedParent $allowedParent `
            -RepositoryRoot $protectedRepository `
            -CanonicalRuntimeRoot $protectedRuntime
        $archive = Assert-PSOBBDgVoodooArchiveLock `
            -ArchivePath $archivePath `
            -LockComponent $lockComponent
        Assert-PSOBBDgVoodooCacheMatchesArchive `
            -CacheDirectory $candidate `
            -ArchivePath $archive | Out-Null
        $candidate
    }.GetNewClosure()
    $dgPlanned = Invoke-PSOBBVerifiedDirectoryRemoval `
        -Path $cacheRoot `
        -Verifier $dgVerifier `
        -ShouldRemove { $false } `
        -Recurse
    Add-Result 'renderer-cache preview preserves exact inventory' (
        $dgPlanned.Status -eq 'Planned' -and (Test-Path -LiteralPath $cacheRoot)) $dgPlanned.Detail

    Assert-Rejected `
        -Name 'confirmation-time renderer-cache mutation is rejected' `
        -Action {
            Invoke-PSOBBVerifiedDirectoryRemoval `
                -Path $cacheRoot `
                -Verifier $dgVerifier `
                -ShouldRemove {
                    param($target)
                    [System.IO.File]::WriteAllText((Join-Path $target 'unexpected.bin'), 'changed')
                    $true
                } `
                -Recurse | Out-Null
        } `
        -MessagePattern 'exact expected'
    Add-Result 'mutation rejection preserves the changed cache' (
        (Test-Path -LiteralPath (Join-Path $cacheRoot 'unexpected.bin'))) 'changed cache remains for review'
    Remove-Item -LiteralPath (Join-Path $cacheRoot 'unexpected.bin') -Force
    $dgRemoved = Invoke-PSOBBVerifiedDirectoryRemoval `
        -Path $cacheRoot `
        -Verifier $dgVerifier `
        -ShouldRemove { $true } `
        -Recurse
    Add-Result 'exact renderer cache is removed recursively' (
        $dgRemoved.Status -eq 'Removed' -and -not (Test-Path -LiteralPath $cacheRoot)) $dgRemoved.Detail

    New-DgVoodooFixture -ArchivePath $archivePath -CacheRoot $cacheRoot
    [System.IO.File]::WriteAllText((Join-Path $cacheRoot 'out\extra.txt'), 'unexpected')
    Assert-Rejected `
        -Name 'extra renderer-cache inventory is rejected' `
        -Action {
            Assert-PSOBBDgVoodooCacheMatchesArchive `
                -CacheDirectory $cacheRoot `
                -ArchivePath $archivePath | Out-Null
        } `
        -MessagePattern 'inventory does not match'
    Remove-Item -LiteralPath $cacheRoot -Recurse -Force

    $badLock = [pscustomobject]@{
        size = $archiveFile.Length
        sha256 = '0' * 64
    }
    Assert-Rejected `
        -Name 'altered renderer archive lock is rejected' `
        -Action {
            Assert-PSOBBDgVoodooArchiveLock `
                -ArchivePath $archivePath `
                -LockComponent $badLock | Out-Null
        } `
        -MessagePattern 'provenance lock'

    $reshadeRoot = Join-Path $allowedParent 'ReShade'
    New-Item -ItemType Directory -Path $reshadeRoot | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $reshadeRoot 'reshade-PSOBB_NeutralCAS-fixture.cso'),
        'generated cache')
    $reshadeVerifier = {
        param($proposedTarget)
        Assert-PSOBBReShadeCacheIsExclusive -CacheDirectory $proposedTarget | Out-Null
        $proposedTarget
    }.GetNewClosure()
    $reshadePlanned = Invoke-PSOBBVerifiedDirectoryRemoval `
        -Path $reshadeRoot `
        -Verifier $reshadeVerifier `
        -ShouldRemove { $false } `
        -Recurse
    Add-Result 'ReShade-cache preview preserves exclusive content' (
        $reshadePlanned.Status -eq 'Planned' -and (Test-Path -LiteralPath $reshadeRoot)) $reshadePlanned.Detail
    $reshadeRemoved = Invoke-PSOBBVerifiedDirectoryRemoval `
        -Path $reshadeRoot `
        -Verifier $reshadeVerifier `
        -ShouldRemove { $true } `
        -Recurse
    Add-Result 'exclusive PSOBB ReShade cache is removed' (
        $reshadeRemoved.Status -eq 'Removed' -and -not (Test-Path -LiteralPath $reshadeRoot)) $reshadeRemoved.Detail

    New-Item -ItemType Directory -Path $reshadeRoot | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $reshadeRoot 'other-game-cache.cso'), 'shared data')
    Assert-Rejected `
        -Name 'shared ReShade cache content is rejected' `
        -Action { Assert-PSOBBReShadeCacheIsExclusive -CacheDirectory $reshadeRoot | Out-Null } `
        -MessagePattern 'non-PSOBB file'

    $source = Get-Content -Raw -LiteralPath $cleanupScript
    $entrypointIsFixed =
        $source -notmatch 'DocumentsDirectory|TemporaryDirectory|CrashReportDirectories' -and
        $source -match "ExpectedName 'ReShade'" -and
        $source -match "id -eq 'dgvoodoo2-x86-d3d8'" -and
        $source -match 'Join-Path \$layout\.Archives ''dgVoodoo2_87_3\.zip'''
    Add-Result 'production roots and archive identity are fixed' $entrypointIsFixed 'no caller-overridable system roots or archive path'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -ne 0) {
    throw "$($failed.Count) legacy-remnant cleanup test(s) failed"
}
[pscustomobject]@{
    Suite = 'LegacyRemnantCleanup'
    Passed = $results.Count
    Failed = 0
}
