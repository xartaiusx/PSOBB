[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Install', 'Verify', 'Rollback')]
    [string]$Action = 'Install',

    [ValidateSet('Characters', 'Objects', 'Monsters', 'Maps', 'All')]
    [string]$Pack = 'All',

    [string]$ArchivePath,

    [string]$SevenZipPath = 'C:\Program Files\7-Zip\7z.exe',

    [string]$SnapshotId,

    [string]$SourcesLockPath,

    [string]$RuntimeRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$script:ComponentId = 'ashenbubs-hd-psobb-v1.02-local-import'
$script:SevenZipComponentId = 'sevenzip-local-extraction-tool'
$script:OverlaySchemaVersion = 1

function Get-ExactLockedComponent {
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

function Assert-LocalRegularFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        throw "$Label must be on a local Windows volume"
    }
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    Assert-PathWithinRoot -Path $fullPath -Root $volumeRoot | Out-Null
    $item = Get-Item -LiteralPath $fullPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label cannot be a reparse point: $fullPath"
    }
    $item
}

function Assert-LockedFileIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.FileInfo]$File,
        [Parameter(Mandatory)]$Declaration,
        [Parameter(Mandatory)][string]$Label
    )

    $expectedHash = [string]$Declaration.sha256
    $expectedSize = [long]$Declaration.size
    if ($expectedSize -le 0 -or $expectedHash -cnotmatch '^[a-f0-9]{64}$') {
        throw "$Label has an invalid size or SHA-256 declaration"
    }
    if ($File.Length -ne $expectedSize -or
        (Get-LowerSha256 -Path $File.FullName) -cne $expectedHash) {
        throw "$Label does not match its locked size and SHA-256: $($File.FullName)"
    }
    $File
}

function Assert-SevenZipTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Component
    )

    $executable = Assert-LocalRegularFile -Path $Path -Label '7-Zip executable'
    if ($executable.Name -cne '7z.exe') {
        throw 'The locked extraction tool must be named 7z.exe'
    }
    Assert-LockedFileIdentity -File $executable -Declaration $Component -Label '7-Zip executable' | Out-Null

    $dllDeclarations = @($Component.members | Where-Object { [string]$_.path -ceq '7z.dll' })
    if ($dllDeclarations.Count -ne 1) {
        throw 'The 7-Zip lock entry must contain exactly one 7z.dll member'
    }
    $dllPath = Join-Path $executable.DirectoryName '7z.dll'
    $dll = Assert-LocalRegularFile -Path $dllPath -Label '7-Zip engine'
    Assert-LockedFileIdentity -File $dll -Declaration $dllDeclarations[0] -Label '7-Zip engine' | Out-Null

    foreach ($file in @($executable, $dll)) {
        if ([string]$file.VersionInfo.FileVersion -cne [string]$Component.version -or
            [string]$file.VersionInfo.CompanyName -cne 'Igor Pavlov') {
            throw "The locked 7-Zip product identity does not match: $($file.FullName)"
        }
    }
    $executable.FullName
}

function Invoke-LockedSevenZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ExecutablePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Windows did not start the locked 7-Zip process'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $detail = ($stderr + "`n" + $stdout).Trim()
            if ($detail.Length -gt 2000) {
                $detail = $detail.Substring(0, 2000)
            }
            throw "7-Zip failed with exit code $($process.ExitCode): $detail"
        }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $stdout
            StandardError = $stderr
        }
    } finally {
        $process.Dispose()
    }
}

function Get-SevenZipFileListing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][string]$ArchivePath
    )

    $result = Invoke-LockedSevenZip -ExecutablePath $ExecutablePath -Arguments @(
        'l', '-slt', '-ba', '-sccUTF-8', '--', $ArchivePath)
    $records = [System.Collections.Generic.List[object]]::new()
    $record = [ordered]@{}
    foreach ($line in @($result.StandardOutput -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($record.Contains('Path')) {
                $records.Add([pscustomobject]$record)
            }
            $record = [ordered]@{}
            continue
        }
        $separator = $line.IndexOf(' = ', [System.StringComparison]::Ordinal)
        if ($separator -lt 1) {
            throw "7-Zip returned an unrecognized technical-list line: $line"
        }
        $key = $line.Substring(0, $separator).Trim()
        if ($record.Contains($key)) {
            throw "7-Zip returned a duplicate technical-list key: $key"
        }
        $record[$key] = $line.Substring($separator + 3)
    }
    if ($record.Contains('Path')) {
        $records.Add([pscustomobject]$record)
    }
    if ($records.Count -eq 0) {
        throw "7-Zip returned no archive members: $ArchivePath"
    }
    @($records)
}

function Assert-PackArchiveListing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Entries,
        [Parameter(Mandatory)]$Pack,
        [ValidateRange(1, [long]::MaxValue)][long]$MaximumAssetBytes
    )

    $expectedCount = [int]$Pack.entryCount
    $expectedBytes = [long]$Pack.expandedBytes
    $expectedMaximum = [long]$Pack.maximumEntryBytes
    $extension = [string]$Pack.extension
    if ($expectedCount -le 0 -or $expectedBytes -le 0 -or
        $expectedMaximum -le 0 -or $expectedMaximum -gt $MaximumAssetBytes -or
        $extension -cnotmatch '^\.[a-z0-9]+$') {
        throw "Pack '$($Pack.id)' has an invalid locked inventory declaration"
    }
    if (@($Entries).Count -ne $expectedCount) {
        throw "Pack '$($Pack.id)' contains $(@($Entries).Count) entries; expected $expectedCount"
    }

    $names = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $normalized = [System.Collections.Generic.List[object]]::new()
    [long]$totalBytes = 0
    [long]$largestBytes = 0
    foreach ($entry in @($Entries)) {
        $path = [string]$entry.Path
        $sizeText = [string]$entry.Size
        $folder = $entry.PSObject.Properties['Folder']
        $encrypted = $entry.PSObject.Properties['Encrypted']
        $symbolicLink = $entry.PSObject.Properties['Symbolic Link']
        $hardLink = $entry.PSObject.Properties['Hard Link']
        $alternateStream = $entry.PSObject.Properties['Alternate Stream']
        if ($null -eq $folder -or [string]$folder.Value -ne '-' -or
            $null -eq $encrypted -or [string]$encrypted.Value -ne '-' -or
            ($null -ne $symbolicLink -and
                -not [string]::IsNullOrWhiteSpace([string]$symbolicLink.Value)) -or
            ($null -ne $hardLink -and
                -not [string]::IsNullOrWhiteSpace([string]$hardLink.Value)) -or
            ($null -ne $alternateStream -and
                -not [string]::IsNullOrWhiteSpace([string]$alternateStream.Value) -and
                [string]$alternateStream.Value -cne '-')) {
            throw "Pack '$($Pack.id)' contains a directory, link, stream, or encrypted member: $path"
        }
        if ($path -cnotmatch '^[A-Za-z0-9_.-]+$' -or
            $path -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$' -or
            [System.IO.Path]::GetExtension($path) -cne $extension -or
            -not $names.Add($path)) {
            throw "Pack '$($Pack.id)' contains an undeclared, unsafe, or duplicate asset path: $path"
        }
        [long]$size = 0
        if (-not [long]::TryParse(
            $sizeText,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$size) -or $size -le 0 -or $size -gt $MaximumAssetBytes) {
            throw "Pack '$($Pack.id)' contains an invalid or oversized asset: $path"
        }
        $crc = [string]$entry.CRC
        if ($crc -cnotmatch '^[0-9A-F]{8}$') {
            throw "Pack '$($Pack.id)' contains an asset without a valid CRC: $path"
        }
        if ($size -gt ([long]::MaxValue - $totalBytes)) {
            throw "Pack '$($Pack.id)' expanded-size arithmetic overflowed"
        }
        $totalBytes += $size
        $largestBytes = [Math]::Max($largestBytes, $size)
        $normalized.Add([pscustomobject]@{
            Path = $path
            Size = $size
            Crc = $crc
        })
    }
    if ($totalBytes -ne $expectedBytes -or $largestBytes -ne $expectedMaximum) {
        throw "Pack '$($Pack.id)' does not match its locked expanded size or maximum entry size"
    }
    @($normalized | Sort-Object Path)
}

function Assert-ExtractedPack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Listing,
        [Parameter(Mandatory)][string]$PackId
    )

    $reparse = Get-ChildItem -LiteralPath $Root -Force -Recurse -Attributes ReparsePoint `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($reparse) {
        throw "Pack '$PackId' extracted a reparse point: $($reparse.FullName)"
    }
    $manifest = @(Get-PSOBBDirectoryManifest -Root $Root)
    if ($manifest.Count -ne @($Listing).Count) {
        throw "Pack '$PackId' extracted an unexpected file count"
    }
    $expectedByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($entry in @($Listing)) {
        $expectedByPath.Add([string]$entry.Path, $entry)
    }
    foreach ($file in $manifest) {
        if (-not $expectedByPath.ContainsKey([string]$file.path) -or
            [long]$file.size -ne [long]$expectedByPath[[string]$file.path].Size) {
            throw "Pack '$PackId' extracted an unexpected or changed file: $($file.path)"
        }
    }
    @($manifest)
}

function Assert-DeclaredCompositionCollisions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$PackListings,
        [Parameter(Mandatory)]$Component
    )

    $composed = foreach ($packListing in @($PackListings)) {
        foreach ($entry in @($packListing.Entries)) {
            [pscustomobject]@{
                Destination = (([string]$packListing.DestinationRoot).Trim('/') + '/' +
                    [string]$entry.Path).ToLowerInvariant()
                Size = [long]$entry.Size
                Crc = [string]$entry.Crc
            }
        }
    }
    $composedGroups = @($composed | Group-Object Destination)
    $actualCollisions = @($composedGroups | Where-Object Count -gt 1)
    $allDeclared = @($Component.allowedIdenticalCollisions | ForEach-Object {
        ([string]$_).ToLowerInvariant()
    } | Sort-Object -Unique)
    $declared = @($allDeclared | Where-Object {
        $candidate = $_
        @($composedGroups | Where-Object { $_.Name -ceq $candidate -and $_.Count -gt 1 }).Count -eq 1
    })
    $actual = @($actualCollisions | ForEach-Object { [string]$_.Name } |
        Sort-Object -Unique)
    if ($actual.Count -ne $declared.Count -or
        [string]::Join("`n", $actual) -cne [string]::Join("`n", $declared)) {
        throw 'The pack composition collision set does not match sources.lock.json'
    }
    foreach ($collision in $actualCollisions) {
        if (@($collision.Group.Size | Sort-Object -Unique).Count -ne 1 -or
            @($collision.Group.Crc | Sort-Object -Unique).Count -ne 1) {
            throw "The declared duplicate assets are not byte-identical by size and CRC: $($collision.Name)"
        }
    }
    @($actual)
}

function Test-AshenbubsOverlay {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    Assert-PathWithinRoot -Path $Path -Root $layout.Root | Out-Null
    $manifestPath = Join-Path $Path 'asset-overlay.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "AshenbubsHD overlay manifest is missing: $manifestPath"
    }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -Depth 100
    $selectionMap = @{
        Characters = @('character')
        Objects = @('object-npc')
        Monsters = @('monster')
        Maps = @('map')
        All = @('monster', 'object-npc', 'character', 'map')
    }
    $selection = [string]$manifest.selection
    if (-not $selectionMap.ContainsKey($selection) -or
        $manifest.schemaVersion -ne $script:OverlaySchemaVersion -or
        [string]$manifest.componentId -cne $script:ComponentId -or
        [string]$manifest.distributionClass -cne 'local-only' -or
        [string]$manifest.activationState -cne 'staged-not-applied' -or
        [string]$manifest.compatibilityState -cne [string]$component.compatibilityState -or
        [long]$manifest.sourceArchive.size -ne [long]$component.size -or
        [string]$manifest.sourceArchive.sha256 -cne [string]$component.sha256 -or
        [long]$manifest.maximumAssetBytes -ne [long]$component.maximumAssetBytes -or
        @($manifest.packs).Count -ne @($selectionMap[$selection]).Count) {
        throw 'AshenbubsHD overlay manifest identity is invalid'
    }
    if ([string]$manifest.activationRequirements.requiredClientExecutableSha256 -cne
            [string]$component.activationRequirements.requiredClientExecutableSha256 -or
        [string]$manifest.activationRequirements.requiredComponentId -cne
            [string]$component.activationRequirements.requiredComponentId -or
        [string]$manifest.activationRequirements.requiredCapability -cne
            [string]$component.activationRequirements.requiredCapability -or
        [long]$manifest.activationRequirements.requiredMaximumAssetBytes -ne
            [long]$component.activationRequirements.requiredMaximumAssetBytes -or
        [string]$manifest.activationRequirements.integrationState -cne
            [string]$component.activationRequirements.integrationState) {
        throw 'AshenbubsHD overlay activation requirements have changed'
    }
    $actualPackIds = @($manifest.packs.id | Sort-Object)
    $expectedPackIds = @($selectionMap[$selection] | Sort-Object)
    if ([string]::Join("`n", $actualPackIds) -cne [string]::Join("`n", $expectedPackIds)) {
        throw 'AshenbubsHD overlay manifest does not match its declared pack selection'
    }
    $expectedFiles = [System.Collections.Generic.List[object]]::new()
    $compositionEntries = [System.Collections.Generic.List[object]]::new()
    [long]$expandedBytes = 0
    foreach ($pack in @($manifest.packs)) {
        if ([string]$pack.id -cnotmatch '^[a-z0-9-]+$' -or
            [string]$pack.destinationRoot -cnotmatch '^data(/scene)?$') {
            throw 'AshenbubsHD overlay manifest contains an unsafe pack path'
        }
        $declarations = @($component.packArchives | Where-Object {
            [string]$_.id -ceq [string]$pack.id
        })
        $member = if ($declarations.Count -eq 1) {
            @($component.members | Where-Object {
                [string]$_.path -ceq [string]$declarations[0].memberPath
            })
        } else {
            @()
        }
        if ($declarations.Count -ne 1 -or $member.Count -ne 1 -or
            [string]$pack.destinationRoot -cne [string]$declarations[0].destinationRoot -or
            [string]$pack.archiveMember -cne [string]$declarations[0].memberPath -or
            [string]$pack.archiveSha256 -cne [string]$member[0].sha256 -or
            @($pack.files).Count -ne [int]$declarations[0].entryCount) {
            throw "AshenbubsHD overlay pack '$($pack.id)' is not bound to its locked archive inventory"
        }
        [long]$packBytes = 0
        [long]$packMaximum = 0
        foreach ($file in @($pack.files)) {
            $relativePath = 'packs/{0}/{1}/{2}' -f
                [string]$pack.id,
                [string]$pack.destinationRoot,
                [string]$file.path
            if ($relativePath -cnotmatch '^packs/[a-z0-9-]+/data(/scene)?/[A-Za-z0-9_.-]+\.(bml|afs|xvm)$') {
                throw "AshenbubsHD overlay manifest contains a forbidden asset path: $relativePath"
            }
            if ([System.IO.Path]::GetExtension([string]$file.path) -cne
                    [string]$declarations[0].extension -or
                [long]$file.size -le 0 -or
                [long]$file.size -gt [long]$component.maximumAssetBytes -or
                [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw "AshenbubsHD overlay manifest contains invalid asset metadata: $relativePath"
            }
            $packBytes += [long]$file.size
            $packMaximum = [Math]::Max($packMaximum, [long]$file.size)
            $expectedFiles.Add([pscustomobject]@{
                path = $relativePath
                size = [long]$file.size
                sha256 = [string]$file.sha256
            })
            $compositionEntries.Add([pscustomobject]@{
                Destination = (([string]$pack.destinationRoot).Trim('/') + '/' +
                    [string]$file.path).ToLowerInvariant()
                Size = [long]$file.size
                Sha256 = [string]$file.sha256
            })
        }
        if ($packBytes -ne [long]$declarations[0].expandedBytes -or
            $packMaximum -ne [long]$declarations[0].maximumEntryBytes) {
            throw "AshenbubsHD overlay pack '$($pack.id)' expanded inventory has changed"
        }
        $expandedBytes += $packBytes
    }
    if ($expandedBytes -ne [long]$manifest.expandedAssetBytes) {
        throw 'AshenbubsHD overlay expanded-size total has changed'
    }
    $collisionGroups = @($compositionEntries | Group-Object Destination |
        Where-Object Count -gt 1)
    $actualCollisions = @($collisionGroups | ForEach-Object { [string]$_.Name } |
        Sort-Object -Unique)
    $manifestCollisions = @($manifest.allowedIdenticalCollisions | ForEach-Object {
        ([string]$_).ToLowerInvariant()
    } | Sort-Object -Unique)
    if ([string]::Join("`n", $actualCollisions) -cne
            [string]::Join("`n", $manifestCollisions) -or
        @($actualCollisions | Where-Object {
            $_ -cnotin @($component.allowedIdenticalCollisions)
        }).Count -gt 0) {
        throw 'AshenbubsHD overlay collision inventory has changed'
    }
    foreach ($collision in $collisionGroups) {
        if (@($collision.Group.Size | Sort-Object -Unique).Count -ne 1 -or
            @($collision.Group.Sha256 | Sort-Object -Unique).Count -ne 1) {
            throw "AshenbubsHD overlay collision is not byte-identical: $($collision.Name)"
        }
    }
    $actual = @(Get-PSOBBDirectoryManifest -Root $Path | Where-Object {
        [string]$_.path -cne 'asset-overlay.json'
    })
    if (-not (Test-PSOBBManifestEntriesEqual -Left $actual -Right @($expectedFiles))) {
        throw 'AshenbubsHD overlay asset inventory or SHA-256 has changed'
    }
    if (@(Get-PSOBBDirectoryManifest -Root $Path).Count -ne ($expectedFiles.Count + 1)) {
        throw 'AshenbubsHD overlay contains undeclared extra files'
    }
    $manifest
}

function Assert-PSOBBStoppedForAssetMutation {
    [CmdletBinding()]
    param()

    Assert-PSOBBNoRunningClients -Layout $layout | Out-Null
    $servers = @(Get-NewservProcessesAtPath -Layout $layout)
    if ($servers.Count -gt 0 -or $null -ne (Get-NewservProcess -Layout $layout)) {
        throw 'AshenbubsHD overlay changes require newserv and every approved client to be stopped'
    }
}

function New-SnapshotId {
    [CmdletBinding()]
    param([string]$Prefix = 'snapshot')

    '{0}-{1}-{2}' -f $Prefix, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'),
        [Guid]::NewGuid().ToString('N').Substring(0, 8)
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fullRepositoryRoot = [System.IO.Path]::GetFullPath($repositoryRoot).TrimEnd('\')
$fullRuntimeRoot = [System.IO.Path]::GetFullPath($layout.Root).TrimEnd('\')
if ($fullRuntimeRoot.Equals($fullRepositoryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $fullRuntimeRoot.StartsWith(
        $fullRepositoryRoot + '\',
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'AshenbubsHD proprietary assets may never be staged inside the Git repository'
}
if ([string]::IsNullOrWhiteSpace($SourcesLockPath)) {
    $SourcesLockPath = Join-Path $repositoryRoot 'config\sources.lock.json'
}
$sourcesFile = Assert-LocalRegularFile -Path $SourcesLockPath -Label 'sources lock'
$sources = Get-Content -Raw -LiteralPath $sourcesFile.FullName | ConvertFrom-Json -Depth 100
if ($sources.schemaVersion -ne 1) {
    throw 'sources.lock.json schema version is not supported'
}
$component = Get-ExactLockedComponent -Sources $sources -Id $script:ComponentId
$sevenZipComponent = Get-ExactLockedComponent -Sources $sources -Id $script:SevenZipComponentId
if ([string]$component.version -cne '1.02' -or
    [string]$component.distributionClass -cne 'local-only' -or
    [string]$component.compatibilityState -cne 'ephinea-only-upstream-warning' -or
    [long]$component.maximumAssetBytes -ne 100000000 -or
    @($component.packArchives).Count -ne 4) {
    throw 'The AshenbubsHD lock entry does not preserve the approved local-only compatibility boundary'
}
if ([string]$component.activationRequirements.requiredClientExecutableSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    [string]$component.activationRequirements.requiredComponentId -cne 'project-owned-psobb-large-assets' -or
    [string]$component.activationRequirements.requiredCapability -cne 'large-assets-59nl' -or
    [long]$component.activationRequirements.requiredMaximumAssetBytes -ne 100000000 -or
    [string]$component.activationRequirements.integrationState -cne 'not-attached-by-this-asset-materializer') {
    throw 'The AshenbubsHD activation hook is missing or does not fail closed'
}

$selectionIds = @(switch ($Pack) {
    'Characters' { @('character') }
    'Objects' { @('object-npc') }
    'Monsters' { @('monster') }
    'Maps' { @('map') }
    'All' { @('monster', 'object-npc', 'character', 'map') }
})
$selectedPackDeclarations = @($component.packArchives | Where-Object {
    [string]$_.id -cin $selectionIds
})
if ($selectedPackDeclarations.Count -ne $selectionIds.Count) {
    throw "The '$Pack' selection does not map to an exact locked pack inventory"
}

$overlayRoot = Join-Path $layout.LocalLab 'asset-overlays\ashenbubs-hd-psobb-v1.02'
$currentPath = Join-Path $overlayRoot 'current'
$snapshotsPath = Join-Path $overlayRoot 'snapshots'
$rejectedPath = Join-Path $overlayRoot 'rejected'
foreach ($path in @($overlayRoot, $currentPath, $snapshotsPath, $rejectedPath)) {
    Assert-PathWithinRoot -Path $path -Root $layout.Root | Out-Null
}

$mutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    Assert-PSOBBStoppedForAssetMutation

    if ($Action -eq 'Verify') {
        $verified = Test-AshenbubsOverlay -Path $currentPath
        [pscustomobject]@{
            Action = 'Verify'
            Valid = $true
            OverlayPath = $currentPath
            ArchiveSha256 = [string]$verified.sourceArchive.sha256
            AssetFiles = (@($verified.packs.files).Count)
            Selection = [string]$verified.selection
        }
        return
    }

    if ($Action -eq 'Rollback') {
        if (-not (Test-Path -LiteralPath $snapshotsPath -PathType Container)) {
            throw 'No AshenbubsHD overlay snapshots exist'
        }
        $candidates = @(Get-ChildItem -LiteralPath $snapshotsPath -Directory -Force | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        })
        if (-not [string]::IsNullOrWhiteSpace($SnapshotId)) {
            if ($SnapshotId -cnotmatch '^[A-Za-z0-9_.-]+$') {
                throw 'SnapshotId contains unsafe characters'
            }
            $candidates = @($candidates | Where-Object { $_.Name -ceq $SnapshotId })
        } else {
            $candidates = @($candidates | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
        }
        if ($candidates.Count -ne 1) {
            throw 'Exactly one AshenbubsHD rollback snapshot must be selected'
        }
        $selected = $candidates[0]
        Assert-PathWithinRoot -Path $selected.FullName -Root $snapshotsPath | Out-Null
        $selectedManifest = Test-AshenbubsOverlay -Path $selected.FullName
        if (-not $PSCmdlet.ShouldProcess($currentPath, "restore AshenbubsHD snapshot $($selected.Name)")) {
            return
        }

        New-Item -ItemType Directory -Path $snapshotsPath -Force | Out-Null
        New-Item -ItemType Directory -Path $rejectedPath -Force | Out-Null
        $displacedPath = $null
        if (Test-Path -LiteralPath $currentPath) {
            try {
                Test-AshenbubsOverlay -Path $currentPath | Out-Null
                $displacedPath = Join-Path $snapshotsPath (New-SnapshotId -Prefix 'pre-rollback')
            } catch {
                $displacedPath = Join-Path $rejectedPath (New-SnapshotId -Prefix 'invalid-current')
            }
            Assert-PathWithinRoot -Path $displacedPath -Root $overlayRoot | Out-Null
            Move-Item -LiteralPath $currentPath -Destination $displacedPath
        }
        try {
            Move-Item -LiteralPath $selected.FullName -Destination $currentPath
            Test-AshenbubsOverlay -Path $currentPath | Out-Null
        } catch {
            if (Test-Path -LiteralPath $currentPath) {
                $failedPath = Join-Path $rejectedPath (New-SnapshotId -Prefix 'failed-rollback')
                Move-Item -LiteralPath $currentPath -Destination $failedPath -ErrorAction SilentlyContinue
            }
            if ($displacedPath -and (Test-Path -LiteralPath $displacedPath)) {
                Move-Item -LiteralPath $displacedPath -Destination $currentPath -ErrorAction SilentlyContinue
            }
            throw
        }
        [pscustomobject]@{
            Action = 'Rollback'
            Changed = $true
            RestoredSnapshot = $selected.Name
            OverlayPath = $currentPath
            ArchiveSha256 = [string]$selectedManifest.sourceArchive.sha256
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
        $ArchivePath = Join-Path $layout.Archives `
            'graphics-lab\local-assets\AshenbubsHD-PSOBB-v1.02-cfe0fd18.zip'
    }
    $archive = Assert-LocalRegularFile -Path $ArchivePath -Label 'AshenbubsHD archive'
    Assert-LockedFileIdentity -File $archive -Declaration $component -Label 'AshenbubsHD archive' | Out-Null
    $sevenZip = Assert-SevenZipTool -Path $SevenZipPath -Component $sevenZipComponent

    Assert-PSOBBZipArchiveSafe -Path $archive.FullName -MaximumEntries 32 `
        -MaximumExpandedBytes 2GB -MaximumEntryBytes 1GB | Out-Null
    $outerManifest = @(Get-PSOBBZipContentManifest -Path $archive.FullName)
    if (-not (Test-PSOBBManifestEntriesEqual -Left $outerManifest -Right @($component.members))) {
        throw 'AshenbubsHD outer ZIP contains a missing, changed, or extra member'
    }
    if (Test-Path -LiteralPath $currentPath -PathType Container) {
        try {
            $existing = Test-AshenbubsOverlay -Path $currentPath
            if ([string]$existing.sourceArchive.sha256 -ceq [string]$component.sha256 -and
                [string]$existing.selection -ceq $Pack) {
                [pscustomobject]@{
                    Action = 'Install'
                    Changed = $false
                    OverlayPath = $currentPath
                    ArchiveSha256 = [string]$component.sha256
                    Selection = $Pack
                }
                return
            }
        } catch {
            # Preserve an invalid current tree in rejected/ during the replacement below.
        }
    }
    if (-not $PSCmdlet.ShouldProcess(
        $currentPath,
        'stage the locked local-only AshenbubsHD v1.02 asset overlay with rollback snapshot')) {
        return
    }

    $selectedExpandedBytes = [long](($selectedPackDeclarations |
        Measure-Object -Property expandedBytes -Sum).Sum)
    $requiredBytes = $selectedExpandedBytes +
        [long](($component.members | Measure-Object -Property size -Sum).Sum) + 512MB
    $drive = Get-PSDrive -Name ([System.IO.Path]::GetPathRoot($layout.Root).Substring(0, 1))
    if ($drive.Free -lt $requiredBytes) {
        throw "Insufficient free space for isolated extraction; require at least $requiredBytes bytes"
    }

    New-Item -ItemType Directory -Path $overlayRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $snapshotsPath -Force | Out-Null
    New-Item -ItemType Directory -Path $rejectedPath -Force | Out-Null
    $stagingPath = Join-Path $overlayRoot ('.staging-' + [Guid]::NewGuid().ToString('N'))
    $outerPath = Join-Path $stagingPath '.outer'
    foreach ($path in @($stagingPath, $outerPath)) {
        Assert-PathWithinRoot -Path $path -Root $overlayRoot | Out-Null
    }
    $stagingMoved = $false
    try {
        New-Item -ItemType Directory -Path $stagingPath | Out-Null
        Expand-PSOBBApprovedArchive -ArchivePath $archive.FullName `
            -DestinationPath $outerPath -RuntimeRoot $layout.Root
        if (-not (Test-PSOBBDirectoryManifest -Root $outerPath -Files @($component.members))) {
            throw 'AshenbubsHD outer ZIP extraction changed its complete locked inventory'
        }

        $packResults = [System.Collections.Generic.List[object]]::new()
        foreach ($packDeclaration in @($selectedPackDeclarations)) {
            if ([string]$packDeclaration.id -cnotmatch '^[a-z0-9-]+$' -or
                [string]$packDeclaration.destinationRoot -cnotmatch '^data(/scene)?$') {
                throw 'An AshenbubsHD pack declaration contains an unsafe output path'
            }
            $members = @($component.members | Where-Object {
                [string]$_.path -ceq [string]$packDeclaration.memberPath
            })
            if ($members.Count -ne 1) {
                throw "Pack '$($packDeclaration.id)' does not bind exactly one locked outer member"
            }
            $rarPath = Assert-PathWithinRoot `
                -Path (Join-Path $outerPath ([string]$packDeclaration.memberPath).Replace('/', '\')) `
                -Root $outerPath
            $rar = Assert-LocalRegularFile -Path $rarPath -Label "Pack '$($packDeclaration.id)' archive"
            Assert-LockedFileIdentity -File $rar -Declaration $members[0] `
                -Label "Pack '$($packDeclaration.id)' archive" | Out-Null

            Invoke-LockedSevenZip -ExecutablePath $sevenZip -Arguments @(
                't', '-bb0', '-bd', '-sccUTF-8', '--', $rar.FullName) | Out-Null
            $listing = Assert-PackArchiveListing `
                -Entries (Get-SevenZipFileListing -ExecutablePath $sevenZip -ArchivePath $rar.FullName) `
                -Pack $packDeclaration `
                -MaximumAssetBytes ([long]$component.maximumAssetBytes)

            $packRoot = Join-Path $stagingPath ('packs\' + [string]$packDeclaration.id)
            $destination = Assert-PathWithinRoot `
                -Path (Join-Path $packRoot ([string]$packDeclaration.destinationRoot).Replace('/', '\')) `
                -Root $stagingPath
            New-Item -ItemType Directory -Path $destination -Force | Out-Null
            Invoke-LockedSevenZip -ExecutablePath $sevenZip -Arguments @(
                'x', '-y', '-aoa', '-bb0', '-bd', '-sccUTF-8', "-o$destination", '--', $rar.FullName) |
                Out-Null
            $files = Assert-ExtractedPack -Root $destination -Listing $listing `
                -PackId ([string]$packDeclaration.id)
            $packResults.Add([pscustomobject]@{
                Id = [string]$packDeclaration.id
                DestinationRoot = [string]$packDeclaration.destinationRoot
                ArchiveMember = [string]$packDeclaration.memberPath
                ArchiveSha256 = [string]$members[0].sha256
                Entries = @($listing)
                Files = @($files)
            })
        }
        $collisions = Assert-DeclaredCompositionCollisions -PackListings @($packResults) -Component $component
        Remove-Item -LiteralPath $outerPath -Recurse -Force

        $overlayManifest = [ordered]@{
            schemaVersion = $script:OverlaySchemaVersion
            componentId = $script:ComponentId
            version = [string]$component.version
            distributionClass = 'local-only'
            activationState = 'staged-not-applied'
            compatibilityState = [string]$component.compatibilityState
            selection = $Pack
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
            sourceArchive = [ordered]@{
                fileName = $archive.Name
                size = $archive.Length
                sha256 = [string]$component.sha256
            }
            extractionTool = [ordered]@{
                componentId = $script:SevenZipComponentId
                version = [string]$sevenZipComponent.version
                sha256 = [string]$sevenZipComponent.sha256
            }
            maximumAssetBytes = [long]$component.maximumAssetBytes
            expandedAssetBytes = $selectedExpandedBytes
            activationRequirements = [ordered]@{
                requiredClientExecutableSha256 = [string]$component.activationRequirements.requiredClientExecutableSha256
                requiredComponentId = [string]$component.activationRequirements.requiredComponentId
                requiredCapability = [string]$component.activationRequirements.requiredCapability
                requiredMaximumAssetBytes = [long]$component.activationRequirements.requiredMaximumAssetBytes
                integrationState = [string]$component.activationRequirements.integrationState
            }
            allowedIdenticalCollisions = @($collisions)
            packs = @($packResults | ForEach-Object {
                [ordered]@{
                    id = $_.Id
                    destinationRoot = $_.DestinationRoot
                    archiveMember = $_.ArchiveMember
                    archiveSha256 = $_.ArchiveSha256
                    files = @($_.Files)
                }
            })
        }
        $manifestPath = Join-Path $stagingPath 'asset-overlay.json'
        [System.IO.File]::WriteAllText(
            $manifestPath,
            ($overlayManifest | ConvertTo-Json -Depth 100),
            [System.Text.UTF8Encoding]::new($false))
        Test-AshenbubsOverlay -Path $stagingPath | Out-Null

        $displacedPath = $null
        if (Test-Path -LiteralPath $currentPath) {
            try {
                Test-AshenbubsOverlay -Path $currentPath | Out-Null
                $displacedPath = Join-Path $snapshotsPath (New-SnapshotId)
            } catch {
                $displacedPath = Join-Path $rejectedPath (New-SnapshotId -Prefix 'invalid-current')
            }
            Assert-PathWithinRoot -Path $displacedPath -Root $overlayRoot | Out-Null
            Move-Item -LiteralPath $currentPath -Destination $displacedPath
        }
        try {
            Move-Item -LiteralPath $stagingPath -Destination $currentPath
            $stagingMoved = $true
            Test-AshenbubsOverlay -Path $currentPath | Out-Null
        } catch {
            if (Test-Path -LiteralPath $currentPath) {
                $failedPath = Join-Path $rejectedPath (New-SnapshotId -Prefix 'failed-install')
                Move-Item -LiteralPath $currentPath -Destination $failedPath -ErrorAction SilentlyContinue
            }
            if ($displacedPath -and (Test-Path -LiteralPath $displacedPath)) {
                Move-Item -LiteralPath $displacedPath -Destination $currentPath -ErrorAction SilentlyContinue
            }
            throw
        }
        [pscustomobject]@{
            Action = 'Install'
            Changed = $true
            OverlayPath = $currentPath
            ArchiveSha256 = [string]$component.sha256
            Selection = $Pack
            AssetFiles = (@($packResults.Files).Count)
            IdenticalCollisions = @($collisions).Count
            PreviousSnapshot = if ($displacedPath) { Split-Path -Leaf $displacedPath } else { $null }
        }
    } finally {
        if (-not $stagingMoved -and (Test-Path -LiteralPath $stagingPath)) {
            $safeStaging = Assert-PathWithinRoot -Path $stagingPath -Root $overlayRoot
            Remove-Item -LiteralPath $safeStaging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
} finally {
    if ($mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
