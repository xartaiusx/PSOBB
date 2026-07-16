[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,
    [string]$VerifiedDgVoodooCacheDirectory,
    [switch]$RemoveVerifiedReShadeCache,
    [switch]$SkipDocumentsDirectories,
    [switch]$SkipTemporaryDirectories,
    [switch]$SkipCrashReports
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-PSOBBNormalizedDirectoryPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw "Cleanup requires a fully qualified local Windows path: $Path"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($fullPath.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        throw "Cleanup does not accept a network path: $Path"
    }
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
    if ($fullPath.Equals($volumeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to treat a volume root as a cleanup candidate: $fullPath"
    }
    $fullPath
}

function Test-PSOBBPathOverlap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$First,
        [Parameter(Mandatory)][string]$Second
    )

    $firstFull = Get-PSOBBNormalizedDirectoryPath -Path $First
    $secondFull = Get-PSOBBNormalizedDirectoryPath -Path $Second
    $firstFull.Equals($secondFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $firstFull.StartsWith(
            $secondFull + '\',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $secondFull.StartsWith(
            $firstFull + '\',
            [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PSOBBNoReparsePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = Get-PSOBBNormalizedDirectoryPath -Path $Path
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    $cursor = $fullPath
    while ($true) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a cleanup path that traverses a reparse point: $($item.FullName)"
            }
        }
        if ($cursor.TrimEnd('\').Equals(
            $volumeRoot.TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if (-not $parent) {
            break
        }
        $next = $parent.FullName
        if ($next.TrimEnd('\').Equals(
            $cursor.TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $cursor = $next
    }
    $fullPath
}

function Assert-PSOBBOrdinaryDirectoryTree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = Assert-PSOBBNoReparsePath -Path $Path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "The cleanup candidate is not a directory: $fullPath"
    }
    $reparseItem = @(Get-ChildItem -LiteralPath $fullPath -Force -Recurse -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        } | Select-Object -First 1)
    if ($reparseItem.Count -ne 0) {
        throw "Refusing a cleanup tree that contains a reparse point: $($reparseItem[0].FullName)"
    }
    $fullPath
}

function Assert-PSOBBCleanupCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedParent,
        [string]$ExpectedName,
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$CanonicalRuntimeRoot
    )

    $fullPath = Get-PSOBBNormalizedDirectoryPath -Path $Path
    $fullParent = Assert-PSOBBNoReparsePath -Path $AllowedParent
    $parent = [System.IO.Directory]::GetParent($fullPath)
    if (-not $parent -or
        -not $parent.FullName.TrimEnd('\').Equals(
            $fullParent,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The cleanup candidate is outside its exact parent allowlist: $fullPath"
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedName) -and
        -not [System.IO.Path]::GetFileName($fullPath).Equals(
            $ExpectedName,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The cleanup candidate does not have its allowlisted name: $fullPath"
    }
    foreach ($protectedRoot in @($RepositoryRoot, $CanonicalRuntimeRoot)) {
        if (Test-PSOBBPathOverlap -First $fullPath -Second $protectedRoot) {
            throw "Refusing a cleanup candidate that overlaps a canonical PSOBB root: $fullPath"
        }
    }
    if (Test-Path -LiteralPath $fullPath) {
        Assert-PSOBBOrdinaryDirectoryTree -Path $fullPath | Out-Null
    }
    $fullPath
}

function Assert-PSOBBEmptyCleanupDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = Assert-PSOBBOrdinaryDirectoryTree -Path $Path
    if (@(Get-ChildItem -LiteralPath $fullPath -Force -ErrorAction Stop).Count -ne 0) {
        throw "Refusing to remove a nonempty legacy directory: $fullPath"
    }
    $fullPath
}

function Invoke-PSOBBVerifiedDirectoryRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][scriptblock]$Verifier,
        [Parameter(Mandatory)][scriptblock]$ShouldRemove,
        [switch]$Recurse
    )

    $requestedPath = Get-PSOBBNormalizedDirectoryPath -Path $Path
    $firstVerifiedPath = [string](& $Verifier $requestedPath)
    if ([string]::IsNullOrWhiteSpace($firstVerifiedPath)) {
        throw 'The cleanup verifier did not return its validated target path'
    }
    $firstVerifiedPath = Get-PSOBBNormalizedDirectoryPath -Path $firstVerifiedPath
    if (-not $firstVerifiedPath.Equals(
        $requestedPath,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The cleanup verifier returned a different target path'
    }
    if (-not (& $ShouldRemove $firstVerifiedPath)) {
        return [pscustomobject]@{
            Status = 'Planned'
            Detail = 'Verified; no change was requested'
        }
    }

    # Confirmation may be interactive. Revalidate the complete candidate after
    # the prompt and immediately before the filesystem operation.
    $secondVerifiedPath = [string](& $Verifier $requestedPath)
    if ([string]::IsNullOrWhiteSpace($secondVerifiedPath)) {
        throw 'The cleanup verifier did not return its validated target path after confirmation'
    }
    $secondVerifiedPath = Get-PSOBBNormalizedDirectoryPath -Path $secondVerifiedPath
    if (-not $secondVerifiedPath.Equals(
        $firstVerifiedPath,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The cleanup verifier changed its target path after confirmation'
    }
    [System.IO.Directory]::Delete($secondVerifiedPath, [bool]$Recurse)
    if (Test-Path -LiteralPath $secondVerifiedPath) {
        throw "The verified cleanup directory remains after deletion: $secondVerifiedPath"
    }
    [pscustomobject]@{
        Status = 'Removed'
        Detail = 'Revalidated immediately before removal'
    }
}

function Get-PSOBBStreamSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        [Convert]::ToHexString($sha256.ComputeHash($Stream)).ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Assert-PSOBBDgVoodooArchiveLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)]$LockComponent
    )

    $archiveFull = [System.IO.Path]::GetFullPath($ArchivePath)
    if (-not (Test-Path -LiteralPath $archiveFull -PathType Leaf)) {
        throw "The locked dgVoodoo archive is missing: $archiveFull"
    }
    Assert-PSOBBNoReparsePath -Path (Split-Path $archiveFull -Parent) | Out-Null
    $archive = Get-Item -LiteralPath $archiveFull -Force -ErrorAction Stop
    if (($archive.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [long]$LockComponent.size -ne $archive.Length -or
        [string]$LockComponent.sha256 -cne (Get-LowerSha256 -Path $archiveFull)) {
        throw 'The dgVoodoo archive does not match its exact provenance lock'
    }
    $archiveFull
}

function Assert-PSOBBDgVoodooCacheMatchesArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CacheDirectory,
        [Parameter(Mandatory)][string]$ArchivePath
    )

    $cacheRoot = Assert-PSOBBOrdinaryDirectoryTree -Path $CacheDirectory
    $topLevel = @(Get-ChildItem -LiteralPath $cacheRoot -Force | Sort-Object Name)
    if ($topLevel.Count -ne 2 -or
        $topLevel[0].Name -cne 'dg.zip' -or $topLevel[0].PSIsContainer -or
        $topLevel[1].Name -cne 'out' -or -not $topLevel[1].PSIsContainer) {
        throw 'The dgVoodoo cache does not have the exact expected dg.zip and out layout'
    }
    $cacheArchive = Join-Path $cacheRoot 'dg.zip'
    $archive = Get-Item -LiteralPath $ArchivePath -Force -ErrorAction Stop
    if ((Get-Item -LiteralPath $cacheArchive).Length -ne $archive.Length -or
        (Get-LowerSha256 -Path $cacheArchive) -cne (Get-LowerSha256 -Path $archive.FullName)) {
        throw 'The dgVoodoo cache archive does not match the locked runtime archive'
    }

    Add-Type -AssemblyName System.IO.Compression
    $extractedRoot = Join-Path $cacheRoot 'out'
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive.FullName)
    try {
        $expectedFiles = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $zip.Entries) {
            $relative = ([string]$entry.FullName).Replace('/', '\').TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($relative)) {
                continue
            }
            if ([System.IO.Path]::IsPathFullyQualified($relative) -or
                @($relative.Split('\')) -contains '..') {
                throw "The locked dgVoodoo archive contains an unsafe path: $relative"
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                if (-not $expectedDirectories.Add($relative)) {
                    throw "The locked dgVoodoo archive repeats a directory: $relative"
                }
                continue
            }
            if ($expectedFiles.ContainsKey($relative)) {
                throw "The locked dgVoodoo archive repeats a file: $relative"
            }
            $stream = $entry.Open()
            try {
                $entryHash = Get-PSOBBStreamSha256 -Stream $stream
            } finally {
                $stream.Dispose()
            }
            $expectedFiles.Add($relative, [pscustomobject]@{
                Length = [long]$entry.Length
                Sha256 = $entryHash
            })
        }

        $actualFiles = @(Get-ChildItem -LiteralPath $extractedRoot -File -Force -Recurse)
        $actualDirectories = @(Get-ChildItem -LiteralPath $extractedRoot -Directory -Force -Recurse)
        if ($actualFiles.Count -ne $expectedFiles.Count -or
            $actualDirectories.Count -ne $expectedDirectories.Count) {
            throw 'The extracted dgVoodoo cache inventory does not match the locked archive'
        }
        foreach ($directory in $actualDirectories) {
            $relative = [System.IO.Path]::GetRelativePath(
                $extractedRoot,
                $directory.FullName)
            if (-not $expectedDirectories.Contains($relative)) {
                throw "The extracted dgVoodoo cache has an unexpected directory: $relative"
            }
        }
        foreach ($file in $actualFiles) {
            $relative = [System.IO.Path]::GetRelativePath($extractedRoot, $file.FullName)
            if (-not $expectedFiles.ContainsKey($relative)) {
                throw "The extracted dgVoodoo cache has an unexpected file: $relative"
            }
            $expected = $expectedFiles[$relative]
            if ($file.Length -ne $expected.Length -or
                (Get-LowerSha256 -Path $file.FullName) -cne $expected.Sha256) {
                throw "The extracted dgVoodoo cache file differs from the archive: $relative"
            }
        }
    } finally {
        $zip.Dispose()
    }

    [pscustomobject]@{
        Files = $expectedFiles.Count
        Directories = $expectedDirectories.Count
    }
}

function Assert-PSOBBReShadeCacheIsExclusive {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CacheDirectory)

    $cacheRoot = Assert-PSOBBOrdinaryDirectoryTree -Path $CacheDirectory
    $directories = @(Get-ChildItem -LiteralPath $cacheRoot -Directory -Force -Recurse)
    $files = @(Get-ChildItem -LiteralPath $cacheRoot -File -Force -Recurse)
    if ($directories.Count -ne 0 -or $files.Count -eq 0) {
        throw 'The ReShade cache is not an exclusive flat PSOBB cache'
    }
    $unexpected = @($files | Where-Object {
        $_.Name -cnotmatch '^reshade-PSOBB_NeutralCAS-[A-Za-z0-9_.-]+\.(?:asm|cso|i)$'
    } | Select-Object -First 1)
    if ($unexpected.Count -ne 0) {
        throw "The ReShade cache contains a non-PSOBB file: $($unexpected[0].Name)"
    }
    [pscustomobject]@{
        Files = $files.Count
        Bytes = [long](($files | Measure-Object Length -Sum).Sum)
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = [System.IO.Path]::GetFullPath($script:PSOBBRepositoryRoot).TrimEnd('\')
$runtimeRootFull = [System.IO.Path]::GetFullPath($layout.Root).TrimEnd('\')
$documentsRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::MyDocuments,
    [Environment+SpecialFolderOption]::DoNotVerify)
$temporaryRoot = [System.IO.Path]::GetTempPath().TrimEnd('\')
$results = [System.Collections.Generic.List[object]]::new()
$emptyCandidates = [System.Collections.Generic.List[object]]::new()

if (-not $SkipDocumentsDirectories) {
    foreach ($name in @('PSOBB', 'PSOBB-Runtime')) {
        $emptyCandidates.Add([pscustomobject]@{
            Path = Join-Path $documentsRoot $name
            Parent = $documentsRoot
            ExpectedName = $name
            Kind = 'retired Documents directory'
        })
    }
}
if (-not $SkipTemporaryDirectories) {
    $emptyCandidates.Add([pscustomobject]@{
        Path = Join-Path $temporaryRoot 'psobb-launcher-tests'
        Parent = $temporaryRoot
        ExpectedName = 'psobb-launcher-tests'
        Kind = 'retired launcher-test directory'
    })
}
if (-not $SkipCrashReports) {
    $crashRoots = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue')
    )
    foreach ($crashRoot in $crashRoots) {
        if (-not (Test-Path -LiteralPath $crashRoot -PathType Container)) {
            continue
        }
        foreach ($directory in @(Get-ChildItem -LiteralPath $crashRoot -Directory -Force |
            Where-Object {
                $_.Name -match '^(?i:AppCrash_(?:Psobb\.exe|PSOBB\.Launcher\.e)_)'
            })) {
            $emptyCandidates.Add([pscustomobject]@{
                Path = $directory.FullName
                Parent = $crashRoot
                ExpectedName = $directory.Name
                Kind = 'empty PSOBB crash-report directory'
            })
        }
    }
}

foreach ($candidate in $emptyCandidates) {
    $displayPath = [string]$candidate.Path
    if (-not (Test-Path -LiteralPath $displayPath)) {
        $results.Add([pscustomobject]@{
            Path = $displayPath
            Kind = $candidate.Kind
            Status = 'Absent'
            Detail = 'No cleanup was needed'
        })
        continue
    }
    try {
        $verifier = {
            param($proposedTarget)
            $validated = Assert-PSOBBCleanupCandidate `
                -Path $proposedTarget `
                -AllowedParent $candidate.Parent `
                -ExpectedName $candidate.ExpectedName `
                -RepositoryRoot $repositoryRoot `
                -CanonicalRuntimeRoot $runtimeRootFull
            Assert-PSOBBEmptyCleanupDirectory -Path $validated
        }.GetNewClosure()
        $approval = {
            param($target)
            $PSCmdlet.ShouldProcess($target, "remove $($candidate.Kind)")
        }.GetNewClosure()
        $removal = Invoke-PSOBBVerifiedDirectoryRemoval `
            -Path $displayPath `
            -Verifier $verifier `
            -ShouldRemove $approval
        $status = $removal.Status
        $detail = $removal.Detail
    } catch {
        $status = 'Rejected'
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{
        Path = $displayPath
        Kind = $candidate.Kind
        Status = $status
        Detail = $detail
    })
}

if (-not [string]::IsNullOrWhiteSpace($VerifiedDgVoodooCacheDirectory)) {
    $displayPath = [string]$VerifiedDgVoodooCacheDirectory
    try {
        $displayPath = Assert-PSOBBCleanupCandidate `
            -Path $displayPath `
            -AllowedParent $temporaryRoot `
            -RepositoryRoot $repositoryRoot `
            -CanonicalRuntimeRoot $runtimeRootFull
        $dgCandidateAccepted = $true
    } catch {
        $dgCandidateAccepted = $false
        $results.Add([pscustomobject]@{
            Path = [string]$VerifiedDgVoodooCacheDirectory
            Kind = 'verified duplicate dgVoodoo cache'
            Status = 'Rejected'
            Detail = $_.Exception.Message
        })
    }
    if (-not $dgCandidateAccepted) {
        # The rejected candidate has already been recorded and is never touched.
    } elseif (-not (Test-Path -LiteralPath $displayPath)) {
        $results.Add([pscustomobject]@{
            Path = $displayPath
            Kind = 'verified duplicate dgVoodoo cache'
            Status = 'Absent'
            Detail = 'No cleanup was needed'
        })
    } else {
        try {
            $lock = Get-Content -Raw -LiteralPath (
                Join-Path $repositoryRoot 'config\sources.lock.json') |
                ConvertFrom-Json -Depth 20
            $components = @($lock.components | Where-Object id -eq 'dgvoodoo2-x86-d3d8')
            if ($components.Count -ne 1) {
                throw 'The source lock does not contain one dgVoodoo archive component'
            }
            $archivePath = Join-Path $layout.Archives 'dgVoodoo2_87_3.zip'
            $verifier = {
                param($proposedTarget)
                $cachePath = Assert-PSOBBCleanupCandidate `
                    -Path $proposedTarget `
                    -AllowedParent $temporaryRoot `
                    -RepositoryRoot $repositoryRoot `
                    -CanonicalRuntimeRoot $runtimeRootFull
                $lockedArchive = Assert-PSOBBDgVoodooArchiveLock `
                    -ArchivePath $archivePath `
                    -LockComponent $components[0]
                Assert-PSOBBDgVoodooCacheMatchesArchive `
                    -CacheDirectory $cachePath `
                    -ArchivePath $lockedArchive | Out-Null
                $cachePath
            }.GetNewClosure()
            $approval = {
                param($target)
                $PSCmdlet.ShouldProcess($target, 'remove verified duplicate dgVoodoo cache')
            }.GetNewClosure()
            $removal = Invoke-PSOBBVerifiedDirectoryRemoval `
                -Path $displayPath `
                -Verifier $verifier `
                -ShouldRemove $approval `
                -Recurse
            $status = $removal.Status
            $detail = $removal.Detail
        } catch {
            $status = 'Rejected'
            $detail = $_.Exception.Message
        }
        $results.Add([pscustomobject]@{
            Path = $displayPath
            Kind = 'verified duplicate dgVoodoo cache'
            Status = $status
            Detail = $detail
        })
    }
}

if ($RemoveVerifiedReShadeCache) {
    $displayPath = Join-Path $temporaryRoot 'ReShade'
    if (-not (Test-Path -LiteralPath $displayPath)) {
        $results.Add([pscustomobject]@{
            Path = $displayPath
            Kind = 'exclusive PSOBB ReShade cache'
            Status = 'Absent'
            Detail = 'No cleanup was needed'
        })
    } else {
        try {
            $verifier = {
                param($proposedTarget)
                $cachePath = Assert-PSOBBCleanupCandidate `
                    -Path $proposedTarget `
                    -AllowedParent $temporaryRoot `
                    -ExpectedName 'ReShade' `
                    -RepositoryRoot $repositoryRoot `
                    -CanonicalRuntimeRoot $runtimeRootFull
                Assert-PSOBBReShadeCacheIsExclusive -CacheDirectory $cachePath | Out-Null
                $cachePath
            }.GetNewClosure()
            $approval = {
                param($target)
                $PSCmdlet.ShouldProcess($target, 'remove exclusive PSOBB ReShade cache')
            }.GetNewClosure()
            $removal = Invoke-PSOBBVerifiedDirectoryRemoval `
                -Path $displayPath `
                -Verifier $verifier `
                -ShouldRemove $approval `
                -Recurse
            $status = $removal.Status
            $detail = $removal.Detail
        } catch {
            $status = 'Rejected'
            $detail = $_.Exception.Message
        }
        $results.Add([pscustomobject]@{
            Path = $displayPath
            Kind = 'exclusive PSOBB ReShade cache'
            Status = $status
            Detail = $detail
        })
    }
}

$results | Format-Table -AutoSize
$rejected = @($results | Where-Object Status -eq 'Rejected')
if ($rejected.Count -ne 0) {
    $rejectedSummary = ($rejected | ForEach-Object {
        "$($_.Path): $($_.Detail)"
    }) -join [Environment]::NewLine
    throw "$($rejected.Count) legacy PSOBB cleanup candidate(s) were rejected; no rejected directory was removed:$([Environment]::NewLine)$rejectedSummary"
}
[pscustomobject]@{
    Suite = 'LegacyRemnantCleanup'
    Removed = @($results | Where-Object Status -eq 'Removed').Count
    Planned = @($results | Where-Object Status -eq 'Planned').Count
    Absent = @($results | Where-Object Status -eq 'Absent').Count
    Rejected = 0
}
