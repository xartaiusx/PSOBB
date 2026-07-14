Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PSOBBCasPngSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 512MB)][long]$MaximumBytes = 128MB
    )

    $itemBefore = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($itemBefore.PSIsContainer -or $itemBefore.Name -cnotmatch '\.png$' -or
        ($itemBefore.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $itemBefore.Length -lt 8 -or $itemBefore.Length -gt $MaximumBytes) {
        throw "The CAS screenshot is not a regular bounded PNG file: $Path"
    }

    $stream = $null
    $sha256 = $null
    try {
        # FileShare.None proves that ReShade has closed the output handle before
        # the importer hashes or moves the screenshot.
        $stream = [System.IO.File]::Open(
            $itemBefore.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None)
        $signature = [byte[]]::new(8)
        if ($stream.Read($signature, 0, $signature.Length) -ne $signature.Length -or
            -not [System.Linq.Enumerable]::SequenceEqual(
                $signature,
                [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))) {
            throw "The CAS screenshot does not have the PNG signature: $Path"
        }
        $stream.Position = 0
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha256.ComputeHash($stream)
    } finally {
        if ($null -ne $sha256) {
            $sha256.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }

    $itemAfter = Get-Item -LiteralPath $itemBefore.FullName -Force -ErrorAction Stop
    if ($itemAfter.Length -ne $itemBefore.Length -or
        $itemAfter.LastWriteTimeUtc.Ticks -ne $itemBefore.LastWriteTimeUtc.Ticks) {
        throw "The CAS screenshot changed while it was being verified: $Path"
    }

    [pscustomobject][ordered]@{
        Path = $itemAfter.FullName
        Length = [long]$itemAfter.Length
        LastWriteTimeUtcTicks = [long]$itemAfter.LastWriteTimeUtc.Ticks
        Sha256 = ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
}

function Get-PSOBBCasF10Pair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourceDirectory)

    $directory = Get-Item -LiteralPath $SourceDirectory -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The CAS screenshot source must be a regular directory: $SourceDirectory"
    }

    $pngFiles = @(Get-ChildItem -LiteralPath $directory.FullName -File -Force |
        Where-Object { $_.Extension -ieq '.png' })
    if ($pngFiles.Count -ne 2) {
        throw "Expected exactly one ReShade F10 Before/After PNG pair, but found $($pngFiles.Count) PNG files"
    }

    $captures = @{}
    $stem = $null
    foreach ($file in $pngFiles) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A ReShade F10 screenshot is a reparse point: $($file.FullName)"
        }
        $match = [regex]::Match(
            $file.Name,
            '^(?<stem>Psobb .+) (?<kind>Before|After)\.png$',
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if (-not $match.Success) {
            throw "The PNG inventory is not an exact ReShade Psobb Before/After pair: $($file.Name)"
        }
        $candidateStem = $match.Groups['stem'].Value
        $kind = $match.Groups['kind'].Value
        if ($null -eq $stem) {
            $stem = $candidateStem
        } elseif ($stem -cne $candidateStem) {
            throw 'The ReShade Before and After screenshots do not have the same capture stem'
        }
        if ($captures.ContainsKey($kind)) {
            throw "The ReShade F10 pair contains a duplicate $kind screenshot"
        }
        $captures[$kind] = $file.FullName
    }
    if (-not $captures.ContainsKey('Before') -or -not $captures.ContainsKey('After')) {
        throw 'The ReShade F10 pair must contain exactly one Before and one After screenshot'
    }

    [pscustomobject][ordered]@{
        Stem = $stem
        BeforePath = [string]$captures['Before']
        AfterPath = [string]$captures['After']
    }
}

function Wait-PSOBBCasF10PairStable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Pair,
        [ValidateRange(2, 10)][int]$StableObservationCount = 3,
        [ValidateRange(50, 5000)][int]$PollMilliseconds = 250,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $stableCount = 0
    $previousBefore = $null
    $previousAfter = $null
    $lastFailure = $null
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try {
            $before = Get-PSOBBCasPngSnapshot -Path ([string]$Pair.BeforePath)
            $after = Get-PSOBBCasPngSnapshot -Path ([string]$Pair.AfterPath)
            $unchanged = $null -ne $previousBefore -and $null -ne $previousAfter -and
                $before.Length -eq $previousBefore.Length -and
                $before.LastWriteTimeUtcTicks -eq $previousBefore.LastWriteTimeUtcTicks -and
                $before.Sha256 -ceq $previousBefore.Sha256 -and
                $after.Length -eq $previousAfter.Length -and
                $after.LastWriteTimeUtcTicks -eq $previousAfter.LastWriteTimeUtcTicks -and
                $after.Sha256 -ceq $previousAfter.Sha256
            if ($unchanged) {
                $stableCount++
            } else {
                $stableCount = 1
            }
            $previousBefore = $before
            $previousAfter = $after
            $lastFailure = $null
            if ($stableCount -ge $StableObservationCount) {
                return [pscustomobject][ordered]@{
                    Before = $before
                    After = $after
                    StableObservations = $stableCount
                }
            }
        } catch {
            $stableCount = 0
            $previousBefore = $null
            $previousAfter = $null
            $lastFailure = $_.Exception.Message
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }

    $detail = if ([string]::IsNullOrWhiteSpace($lastFailure)) {
        'the files did not remain unchanged for the required observations'
    } else {
        $lastFailure
    }
    throw "The ReShade F10 pair did not become stable within $TimeoutSeconds seconds: $detail"
}

function Move-PSOBBCasF10PairTransactional {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceBeforePath,
        [Parameter(Mandatory)][string]$SourceAfterPath,
        [Parameter(Mandatory)][string]$StagingRoot,
        [Parameter(Mandatory)][string]$FinalRoot,
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9][a-z0-9.-]{0,63}\.png$')]
        [string]$BeforeDestinationName,
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9][a-z0-9.-]{0,63}\.png$')]
        [string]$AfterDestinationName,
        [Parameter(Mandatory)][scriptblock]$Analyze
    )

    $sourceBefore = [System.IO.Path]::GetFullPath($SourceBeforePath)
    $sourceAfter = [System.IO.Path]::GetFullPath($SourceAfterPath)
    $stage = [System.IO.Path]::GetFullPath($StagingRoot).TrimEnd('\')
    $final = [System.IO.Path]::GetFullPath($FinalRoot).TrimEnd('\')
    $stageParent = [System.IO.Directory]::GetParent($stage).FullName.TrimEnd('\')
    $finalParent = [System.IO.Directory]::GetParent($final).FullName.TrimEnd('\')
    $volume = [System.IO.Path]::GetPathRoot($stage)
    if (-not $stageParent.Equals($finalParent, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $stageParent -PathType Container) -or
        -not $volume.Equals([System.IO.Path]::GetPathRoot($final), [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $volume.Equals([System.IO.Path]::GetPathRoot($sourceBefore), [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $volume.Equals([System.IO.Path]::GetPathRoot($sourceAfter), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'CAS evidence staging, publication, and both source screenshots must share one existing local-volume parent'
    }
    if (Test-Path -LiteralPath $stage) {
        throw "Refusing to reuse an existing CAS evidence staging directory: $stage"
    }
    if (Test-Path -LiteralPath $final) {
        throw "Refusing to overwrite an existing CAS evidence run: $final"
    }

    $captures = Join-Path $stage 'captures'
    $indexes = Join-Path $stage 'indexes'
    $beforeStaged = Join-Path $captures $BeforeDestinationName
    $afterStaged = Join-Path $captures $AfterDestinationName
    $published = $false
    try {
        [System.IO.Directory]::CreateDirectory($captures) | Out-Null
        [System.IO.Directory]::CreateDirectory($indexes) | Out-Null
        [System.IO.File]::Move($sourceBefore, $beforeStaged)
        [System.IO.File]::Move($sourceAfter, $afterStaged)
        $analysis = & $Analyze $beforeStaged $afterStaged $indexes
        [System.IO.Directory]::Move($stage, $final)
        $published = $true
        [pscustomobject][ordered]@{
            PublishedRoot = $final
            BeforePath = Join-Path $final "captures\$BeforeDestinationName"
            AfterPath = Join-Path $final "captures\$AfterDestinationName"
            IndexRoot = Join-Path $final 'indexes'
            Analysis = $analysis
        }
    } catch {
        $originalFailure = $_.Exception.Message
        $rollbackFailures = [System.Collections.Generic.List[string]]::new()
        if (-not $published) {
            foreach ($move in @(
                [pscustomobject]@{ Staged = $beforeStaged; Source = $sourceBefore },
                [pscustomobject]@{ Staged = $afterStaged; Source = $sourceAfter })) {
                if (Test-Path -LiteralPath $move.Staged -PathType Leaf) {
                    try {
                        if (Test-Path -LiteralPath $move.Source) {
                            throw "the original path is occupied: $($move.Source)"
                        }
                        [System.IO.File]::Move($move.Staged, $move.Source)
                    } catch {
                        $rollbackFailures.Add($_.Exception.Message)
                    }
                }
            }
            if ($rollbackFailures.Count -eq 0 -and (Test-Path -LiteralPath $stage)) {
                try {
                    Remove-Item -LiteralPath $stage -Recurse -Force
                } catch {
                    $rollbackFailures.Add($_.Exception.Message)
                }
            }
        }
        if ($rollbackFailures.Count -gt 0) {
            throw "$originalFailure; CAS screenshot rollback also failed: $($rollbackFailures -join '; ')"
        }
        throw $originalFailure
    }
}
