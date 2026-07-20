[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) `
        'PSOBB-Runtime'),

    [Parameter(DontShow = $true)]
    [string]$InternalTestFixtureToken,

    [Parameter(DontShow = $true)]
    [string]$InternalTestBuildContractPath,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestBeforeDelete
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

$script:RepositoryRoot = [System.IO.Path]::GetFullPath(
    (Split-Path -Parent $PSScriptRoot))
$script:CanonicalRuntimeRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
    [System.IO.Path]::GetFullPath(
        (Join-Path $script:RepositoryRoot 'PSOBB-Runtime')))
$script:CanonicalBuildContractPath = Join-Path $script:RepositoryRoot `
    'config\combat-canary-build.json'
$script:CanonicalPatchSeriesPath = Join-Path $script:RepositoryRoot `
    'patches\newserv\series.json'
$script:CurrentSourceCommit = 'd754a34e271a4fb387be63db34ef0c303e49dcf2'
$script:MaximumTreeEntries = 4096
$script:MaximumTreeBytes = 256MB
$script:MaximumStagingChildren = 64
$script:MaximumStagingEntries = 32768
$script:MaximumStagingBytes = 512MB

function Get-PSOBBCombatCanaryCleanupFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(0, 67108864)][long]$Length,
        [Parameter(Mandatory)][string]$RoleLabel,
        [ValidatePattern('^$|^[a-f0-9]{64}$')][string]$ExpectedSha256 = ''
    )

    if ($Length -eq 0) {
        $emptySha256 =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        $lease = $null
        try {
            $lease = Open-PSOBBCombatCanaryOrdinaryFileLease `
                -LiteralPath $LiteralPath -Root $Root -RoleLabel $RoleLabel
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $lease -RoleLabel $RoleLabel)
            if ($lease.Stream.Length -ne 0 -or
                (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
                    $ExpectedSha256 -cne $emptySha256)) {
                throw "The $RoleLabel does not match its expected empty digest"
            }
            return $emptySha256
        } finally {
            Close-PSOBBCombatCanaryOrdinaryFileLease -Context $lease
        }
    }
    $snapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $LiteralPath -Root $Root `
        -MaximumBytes $Length `
        -ExpectedLength $Length -ExpectedSha256 $ExpectedSha256 `
        -RoleLabel $RoleLabel -Consumer { param([byte[]]$Bytes) $Bytes.Length }
    [string]$snapshot.Sha256
}

function Assert-PSOBBCombatCanaryCleanupFixtureGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$ContractPath
    )

    $fullRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath($Root))
    $temporaryRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()))
    $match = [regex]::Match(
        [System.IO.Path]::GetFileName($fullRoot),
        '^psobb-combat-canary-staging-cleanup-test-(?<id>[0-9a-f]{32})$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $nameId = [Guid]::Empty
    $tokenId = [Guid]::Empty
    if (-not [string]::Equals(
            [System.IO.Path]::GetDirectoryName($fullRoot), $temporaryRoot,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $match.Success -or
        -not [Guid]::TryParseExact(
            $match.Groups['id'].Value, 'N', [ref]$nameId) -or
        -not [Guid]::TryParseExact($Token, 'D', [ref]$tokenId) -or
        $nameId -ne $tokenId) {
        throw 'The cleanup test fixture is not one exact OS-temporary identity'
    }

    $markerPath = Join-Path $fullRoot `
        '.psobb-combat-canary-staging-cleanup-test.json'
    $markerItem = Get-Item -Force -LiteralPath $markerPath -ErrorAction Stop
    if ($markerItem.PSIsContainer -or $markerItem.Length -le 0 -or
        $markerItem.Length -gt 4KB -or
        ($markerItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The cleanup test fixture marker is not one ordinary bounded file'
    }
    $markerJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $markerItem.FullName -Root $fullRoot -MaximumBytes 4KB `
        -ExpectedLength $markerItem.Length -RoleLabel 'Cleanup test fixture marker'
    $marker = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $markerJson -RoleLabel 'Cleanup test fixture marker'
    [void](Assert-PSOBBCombatCanaryExactProperties -Value $marker `
            -Expected @('schemaVersion', 'testRunId', 'root') `
            -RoleLabel 'Cleanup test fixture marker')
    $markerId = [Guid]::Empty
    if ($marker.schemaVersion -isnot [long] -or
        [long]$marker.schemaVersion -ne 1 -or
        -not [Guid]::TryParseExact(
            [string]$marker.testRunId, 'D', [ref]$markerId) -or
        $markerId -ne $tokenId -or
        -not [string]::Equals(
            [System.IO.Path]::TrimEndingDirectorySeparator(
                [System.IO.Path]::GetFullPath([string]$marker.root)),
            $fullRoot, [System.StringComparison]::Ordinal)) {
        throw 'The cleanup test fixture marker identity is invalid'
    }

    $safeContract = Assert-PathWithinRoot -Path $ContractPath -Root $fullRoot
    if ([System.IO.Path]::GetFileName($safeContract) -cne
            'combat-canary-build.fixture.json') {
        throw 'The cleanup test fixture contract has an unexpected name'
    }
    $contractIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $safeContract -Root $fullRoot -Directory $false `
        -RoleLabel 'cleanup test build contract'
    if ([uint32]$contractIdentity.NumberOfLinks -ne 1) {
        throw 'The cleanup test fixture contract is not one ordinary file'
    }
    $true
}

function Get-PSOBBCombatCanaryCleanupContext {
    [CmdletBinding()]
    param()

    $fullRuntimeRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath($RuntimeRoot))
    $requestedTestGate =
        -not [string]::IsNullOrWhiteSpace($InternalTestFixtureToken) -or
        -not [string]::IsNullOrWhiteSpace($InternalTestBuildContractPath) -or
        $null -ne $InternalTestBeforeDelete
    if (-not $requestedTestGate) {
        if (-not [string]::Equals(
                $fullRuntimeRoot, $script:CanonicalRuntimeRoot,
                [System.StringComparison]::Ordinal)) {
            throw "RuntimeRoot must be the exact canonical path: $($script:CanonicalRuntimeRoot)"
        }
        $contractPath = $script:CanonicalBuildContractPath
    } else {
        if ([string]::IsNullOrWhiteSpace($InternalTestFixtureToken) -or
            [string]::IsNullOrWhiteSpace($InternalTestBuildContractPath)) {
            throw 'Cleanup test controls require one complete temporary-fixture gate'
        }
        [void](Assert-PSOBBCombatCanaryCleanupFixtureGate `
                -Root $fullRuntimeRoot -Token $InternalTestFixtureToken `
                -ContractPath $InternalTestBuildContractPath)
        $contractPath = [System.IO.Path]::GetFullPath(
            $InternalTestBuildContractPath)
    }

    $layout = Get-PSOBBLayout -RuntimeRoot $fullRuntimeRoot
    $combatLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment CombatCanary
    $marker = Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $layout
    [void](Assert-PSOBBRuntimeMarker -Layout $layout)
    if ($requestedTestGate -and
        [string]$marker.installationId -cne $InternalTestFixtureToken) {
        throw 'The cleanup test token does not match the exact runtime marker'
    }

    $contractItem = Get-Item -Force -LiteralPath $contractPath -ErrorAction Stop
    if ($contractItem.PSIsContainer -or $contractItem.Length -le 0 -or
        $contractItem.Length -gt 1MB -or
        ($contractItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The combat-canary build contract is not one ordinary bounded file'
    }
    $contractRoot = if ($requestedTestGate) {
        $fullRuntimeRoot
    } else {
        $script:RepositoryRoot
    }
    $contractJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $contractItem.FullName -Root $contractRoot -MaximumBytes 1MB `
        -ExpectedLength $contractItem.Length -RoleLabel 'Combat canary build contract'
    $contract = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $contractJson -RoleLabel 'Combat canary build contract'
    [void](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $contract)

    $seriesItem = Get-Item -Force -LiteralPath $script:CanonicalPatchSeriesPath `
        -ErrorAction Stop
    if ($seriesItem.PSIsContainer -or $seriesItem.Length -le 0 -or
        $seriesItem.Length -gt 1MB -or
        ($seriesItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The current newserv patch series is not one ordinary bounded file'
    }
    $seriesSha256 = Get-PSOBBCombatCanaryCleanupFileSha256 `
        -LiteralPath $seriesItem.FullName -Root $script:RepositoryRoot `
        -Length $seriesItem.Length -RoleLabel 'Current newserv patch series'
    $seriesJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $seriesItem.FullName -Root $script:RepositoryRoot `
        -MaximumBytes 1MB -ExpectedLength $seriesItem.Length `
        -ExpectedSha256 $seriesSha256 -RoleLabel 'Current newserv patch series'
    $series = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $seriesJson -RoleLabel 'Current newserv patch series'
    [void](Assert-PSOBBCombatCanaryExactProperties -Value $series `
            -Expected @('$schema', 'schemaVersion', 'sourceCommit',
                'buildEnvironment', 'patches') `
            -RoleLabel 'Current newserv patch series')
    if ([string]$contract.source.commit -cne $script:CurrentSourceCommit -or
        [string]$series.sourceCommit -cne $script:CurrentSourceCommit -or
        [string]$contract.patchSeries.path -cne
            'patches/newserv/series.json' -or
        [string]$contract.patchSeries.sha256 -cne $seriesSha256) {
        throw 'The cleanup build contract does not bind the current source and patch series'
    }

    [pscustomobject]@{
        Layout = $layout
        CombatLayout = $combatLayout
        Marker = $marker
        Contract = $contract
        IsTestFixture = $requestedTestGate
    }
}

function Enter-PSOBBCombatCanaryCleanupBoundary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context
    )

    $identityToken = ([string]$Context.Marker.installationId).
        Replace('-', '').ToLowerInvariant()
    $buildMutex = [System.Threading.Mutex]::new(
        $false, "Local\PSOBB.CombatCanary.Build.$identityToken")
    $lifecycleMutex = $null
    $ownsBuild = $false
    $ownsLifecycle = $false
    try {
        try {
            $ownsBuild = $buildMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsBuild = $true
        }
        if (-not $ownsBuild) {
            throw 'Another combat-canary build or publication operation is active'
        }
        $lifecycleMutex = [System.Threading.Mutex]::new(
            $false, "Local\PSOBB.Newserv.Start.$identityToken")
        try {
            $ownsLifecycle = $lifecycleMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsLifecycle = $true
        }
        if (-not $ownsLifecycle) {
            throw 'The PSOBB lifecycle is changing; staging cleanup is blocked'
        }

        [void](Assert-PSOBBCombatCanaryCleanupStopped -Context $Context)

        [pscustomobject]@{
            BuildMutex = $buildMutex
            LifecycleMutex = $lifecycleMutex
            OwnsBuild = $ownsBuild
            OwnsLifecycle = $ownsLifecycle
        }
        $buildMutex = $null
        $lifecycleMutex = $null
    } finally {
        if ($null -ne $lifecycleMutex) {
            if ($ownsLifecycle) { $lifecycleMutex.ReleaseMutex() }
            $lifecycleMutex.Dispose()
        }
        if ($null -ne $buildMutex) {
            if ($ownsBuild) { $buildMutex.ReleaseMutex() }
            $buildMutex.Dispose()
        }
    }
}

function Assert-PSOBBCombatCanaryCleanupStopped {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    [void](Assert-PSOBBGlobalStoppedRuntime -Layout $Context.Layout `
            -Operation 'Combat-canary build staging cleanup')
    $named = @(Get-Process -ErrorAction Stop | Where-Object {
            $_.ProcessName -like 'newserv*' -or
            $_.ProcessName -in @('Psobb', 'online', 'option')
        })
    if ($named.Count -ne 0) {
        throw 'Combat-canary build staging cleanup requires all PSOBB and newserv processes to be stopped'
    }
    if (Test-Path -LiteralPath 'P:\') {
        throw 'Combat-canary build staging cleanup requires the deterministic P: drive to be absent'
    }
    $true
}

function Exit-PSOBBCombatCanaryCleanupBoundary {
    [CmdletBinding()]
    param($Boundary)

    if ($null -eq $Boundary) { return }
    try {
        if ([bool]$Boundary.OwnsLifecycle) {
            $Boundary.LifecycleMutex.ReleaseMutex()
        }
    } finally {
        if ($null -ne $Boundary.LifecycleMutex) {
            $Boundary.LifecycleMutex.Dispose()
        }
        try {
            if ([bool]$Boundary.OwnsBuild) {
                $Boundary.BuildMutex.ReleaseMutex()
            }
        } finally {
            if ($null -ne $Boundary.BuildMutex) {
                $Boundary.BuildMutex.Dispose()
            }
        }
    }
}

function Get-PSOBBCombatCanaryCleanupTreeInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $safeRoot = Assert-PathWithinRoot -Path $Root -Root $Root
    $rootIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $safeRoot -Root $safeRoot -Directory $true -RoleLabel $RoleLabel
    $directories = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $files = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $identities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    [void]$identities.Add(('{0:x8}:{1:x16}' -f
            [uint32]$rootIdentity.VolumeSerialNumber,
            [uint64]$rootIdentity.FileId))
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($safeRoot)
    $entries = 0
    [uint64]$aggregate = 0
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory `
                    -ErrorAction Stop)) {
            $entries++
            if ($entries -gt $script:MaximumTreeEntries) {
                throw "The $RoleLabel exceeds its 4096-descendant bound"
            }
            $childPath = Assert-PathWithinRoot -Path $child.FullName -Root $safeRoot
            $relative = [System.IO.Path]::GetRelativePath(
                $safeRoot, $childPath).Replace('\', '/')
            if ($relative -eq '.' -or $relative -match '(^|/)\.\.?(?:/|$)') {
                throw "The $RoleLabel contains an unsafe relative path"
            }
            $isDirectory = [bool]$child.PSIsContainer
            $identity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $childPath -Root $safeRoot -Directory $isDirectory `
                -RoleLabel $RoleLabel
            if (-not $isDirectory -and [uint32]$identity.NumberOfLinks -ne 1) {
                throw "The $RoleLabel contains a hard-linked file"
            }
            $identityKey = '{0:x8}:{1:x16}' -f
                [uint32]$identity.VolumeSerialNumber, [uint64]$identity.FileId
            if (-not $identities.Add($identityKey)) {
                throw "The $RoleLabel repeats one filesystem identity"
            }
            if ($isDirectory) {
                if (-not $directories.TryAdd($relative, [pscustomobject]@{
                            Path = $childPath
                            Identity = $identity
                        })) {
                    throw "The $RoleLabel contains a case-colliding directory"
                }
                $pending.Enqueue($childPath)
            } else {
                if ([uint64]::MaxValue - $aggregate -lt
                        [uint64]$identity.Length) {
                    throw "The $RoleLabel byte total overflowed"
                }
                $aggregate += [uint64]$identity.Length
                if ($aggregate -gt [uint64]$script:MaximumTreeBytes) {
                    throw "The $RoleLabel exceeds its 256 MiB bound"
                }
                if (-not $files.TryAdd($relative, [pscustomobject]@{
                            Path = $childPath
                            Identity = $identity
                        })) {
                    throw "The $RoleLabel contains a case-colliding file"
                }
            }
        }
    }
    [pscustomobject]@{
        Root = $safeRoot
        RootIdentity = $rootIdentity
        Directories = $directories
        Files = $files
        DescendantCount = $entries
        TotalBytes = [long]$aggregate
    }
}

function Assert-PSOBBCombatCanaryCleanupManifestPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $legacyDotfile = $RelativePath -cin @(
        'system/patch-bb/.metadata-cache.json',
        'system/patch-pc/.metadata-cache.json')
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.Length -gt 240 -or
        (-not $legacyDotfile -and $RelativePath -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$') -or
        $RelativePath -match '(^|/)\.\.?(?:/|$)' -or
        [System.IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath.Contains(':', [System.StringComparison]::Ordinal)) {
        throw "The $RoleLabel contains an unsafe manifest path"
    }
    $top = $RelativePath.Split('/')[0]
    if ($top -cnotin @('README.md', 'newserv-windows.exe', 'notices', 'system')) {
        throw "The $RoleLabel contains a path outside the immutable release payload"
    }
    $mutableSegments = @(
        'account', 'accounts', 'player', 'players', 'team', 'teams',
        'backup', 'backups', 'secret', 'secrets', 'credential', 'credentials',
        'license', 'licenses', 'log', 'logs', 'control', 'snapshot', 'snapshots',
        'evidence', 'quarantine', 'transaction', '.work')
    if (@($RelativePath.Split('/') | Where-Object {
                $_ -cin $mutableSegments
            }).Count -ne 0) {
        throw "The $RoleLabel contains a mutable-state path; evidence was retained"
    }
    $RelativePath
}

function Test-PSOBBCombatCanaryCleanupIdentityEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    [uint32]$Left.VolumeSerialNumber -eq [uint32]$Right.VolumeSerialNumber -and
        [uint64]$Left.FileId -eq [uint64]$Right.FileId -and
        [string]$Left.FinalPath -ieq [string]$Right.FinalPath
}

function Assert-PSOBBCombatCanaryCleanupRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Contract,
        [Parameter(Mandatory)][string]$RoleLabel,
        [switch]$RequireContractOutput
    )

    $inventory = Get-PSOBBCombatCanaryCleanupTreeInventory `
        -Root $Root -RoleLabel $RoleLabel
    if ($inventory.DescendantCount -eq 0) {
        throw "The $RoleLabel is empty and cannot be proven as a release"
    }
    if (-not $inventory.Files.ContainsKey('release-manifest.json')) {
        throw "The $RoleLabel does not contain one release manifest"
    }
    $manifestFile = $inventory.Files['release-manifest.json']
    $manifestLength = [long]$manifestFile.Identity.Length
    if ($manifestLength -le 0 -or $manifestLength -gt 4MB) {
        throw "The $RoleLabel release manifest has an invalid bounded size"
    }
    $expectedManifestSha = if ($RequireContractOutput) {
        [string]$Contract.output.releaseManifest.sha256
    } else { '' }
    $expectedManifestLength = if ($RequireContractOutput) {
        [long]$Contract.output.releaseManifest.size
    } else { $manifestLength }
    $manifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $manifestFile.Path -Root $inventory.Root -MaximumBytes 4MB `
        -ExpectedLength $expectedManifestLength `
        -ExpectedSha256 $expectedManifestSha -PassThruSnapshot `
        -RoleLabel 'Combat canary release manifest'
    if ([uint32]$manifestSnapshot.VolumeSerialNumber -ne
            [uint32]$manifestFile.Identity.VolumeSerialNumber -or
        [uint64]$manifestSnapshot.FileId -ne
            [uint64]$manifestFile.Identity.FileId) {
        throw "The $RoleLabel release manifest identity changed"
    }
    $manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $manifestSnapshot.Value -RoleLabel 'Combat canary release manifest'
    [void](Assert-PSOBBCombatCanaryExactProperties -Value $manifest `
            -Expected @('schemaVersion', 'profileId', 'sourceCommit',
                'patchSeriesSha256', 'files') `
            -RoleLabel 'Combat canary release manifest')
    if ($manifest.schemaVersion -isnot [long] -or
        [long]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.profileId -cne [string]$Contract.profileId -or
        [string]$manifest.sourceCommit -cne [string]$Contract.source.commit -or
        [string]$manifest.patchSeriesSha256 -cne
            [string]$Contract.patchSeries.sha256 -or
        $manifest.files -isnot [System.Array]) {
        throw "The $RoleLabel release manifest identity is not current and exact"
    }

    $records = @($manifest.files)
    if ($records.Count -le 0 -or $records.Count -ge
            $script:MaximumTreeEntries) {
        throw "The $RoleLabel release manifest has an invalid record count"
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [long]$payloadBytes = 0
    $executableRecord = $null
    foreach ($record in $records) {
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $record `
                -Expected @('path', 'size', 'sha256') `
                -RoleLabel 'Combat canary release file record')
        if ($record.path -isnot [string] -or
            $record.size -isnot [long] -or [long]$record.size -lt 0 -or
            $record.sha256 -isnot [string] -or
            [string]$record.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw "The $RoleLabel contains an invalid release file record"
        }
        $relative = Assert-PSOBBCombatCanaryCleanupManifestPath `
            -RelativePath ([string]$record.path) -RoleLabel $RoleLabel
        if ($relative -ceq 'release-manifest.json' -or -not $seen.Add($relative)) {
            throw "The $RoleLabel contains a duplicate or reserved manifest path"
        }
        if (-not $inventory.Files.ContainsKey($relative)) {
            throw "The $RoleLabel is missing a declared release file"
        }
        $file = $inventory.Files[$relative]
        if ([long]$file.Identity.Length -ne [long]$record.size) {
            throw "The $RoleLabel release file size does not match its manifest"
        }
        [void](Get-PSOBBCombatCanaryCleanupFileSha256 `
                -LiteralPath $file.Path -Root $inventory.Root `
                -Length ([long]$record.size) -ExpectedSha256 ([string]$record.sha256) `
                -RoleLabel 'Combat canary release payload')
        if ([long]::MaxValue - $payloadBytes -lt [long]$record.size) {
            throw "The $RoleLabel payload byte total overflowed"
        }
        $payloadBytes += [long]$record.size
        $parent = [System.IO.Path]::GetDirectoryName(
            $relative.Replace('/', '\'))
        while (-not [string]::IsNullOrWhiteSpace($parent)) {
            [void]$expectedDirectories.Add($parent.Replace('\', '/'))
            $parent = [System.IO.Path]::GetDirectoryName($parent)
        }
        if ($relative -ceq 'newserv-windows.exe') {
            $executableRecord = $record
        }
    }

    if ($inventory.Files.Count -ne $records.Count + 1) {
        throw "The $RoleLabel contains an unlisted or missing release file"
    }
    if ($inventory.Directories.Count -ne $expectedDirectories.Count -or
        @($inventory.Directories.Keys | Where-Object {
                -not $expectedDirectories.Contains($_)
            }).Count -ne 0) {
        throw "The $RoleLabel contains an unlisted release directory"
    }
    if ($null -eq $executableRecord -or
        [long]$executableRecord.size -ne
            [long]$Contract.output.executable.size -or
        [string]$executableRecord.sha256 -cne
            [string]$Contract.output.executable.sha256) {
        throw "The $RoleLabel does not contain the exact current server executable"
    }
    if ($RequireContractOutput -and
        ($records.Count -ne [long]$Contract.output.fileCount -or
            $payloadBytes -ne [long]$Contract.output.totalBytes)) {
        throw "The $RoleLabel does not match the exact published release contract"
    }

    [pscustomobject]@{
        Root = $inventory.Root
        RootIdentity = $inventory.RootIdentity
        DescendantCount = [int]$inventory.DescendantCount
        FileCount = [int]$records.Count
        TotalBytes = [long]$inventory.TotalBytes
        ManifestSha256 = [string]$manifestSnapshot.Sha256
    }
}

function Get-PSOBBCombatCanaryCleanupPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context
    )

    $stagingRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Context.CombatLayout.EnvironmentRoot '.staging') `
        -Root $Context.CombatLayout.EnvironmentRoot
    if (-not (Test-Path -LiteralPath $stagingRoot)) {
        return [pscustomobject]@{
            StagingPresent = $false
            StagingRoot = $stagingRoot
            StagingIdentity = $null
            Candidates = @()
        }
    }
    $stagingItem = Get-Item -Force -LiteralPath $stagingRoot -ErrorAction Stop
    if (-not $stagingItem.PSIsContainer -or
        ($stagingItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The combat-canary staging root is not one ordinary directory'
    }
    $stagingIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $stagingRoot -Root $Context.Layout.CombatCanary -Directory $true `
        -RoleLabel 'combat canary build staging root'
    $children = @(Get-ChildItem -Force -LiteralPath $stagingRoot `
            -ErrorAction Stop)
    if ($children.Count -gt $script:MaximumStagingChildren) {
        throw 'The combat-canary staging root exceeds its 64-child bound; evidence was retained'
    }
    $topLevelFiles = @($children | Where-Object { -not $_.PSIsContainer })
    if ($topLevelFiles.Count -ne 0) {
        throw 'The combat-canary staging root contains an unexpected top-level file; evidence was retained'
    }

    $candidates = [System.Collections.Generic.List[object]]::new()
    [long]$stagingEntries = 0
    [long]$stagingBytes = 0
    foreach ($child in @($children | Sort-Object Name)) {
        $name = [string]$child.Name
        if (($child.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The combat-canary staging root contains a reparse point; evidence was retained'
        }
        if ($name -match '^(?:failed-release-|.*(?:transaction|quarantine)).*') {
            throw 'The combat-canary staging root contains failure or transaction evidence; evidence was retained'
        }
        $emptyPattern = $name -cmatch
            '^(?:server-base|server-base-corrected|phase1-repackage)-[0-9a-f]{32}$'
        $releasePattern = $name -cmatch
            '^(?:previous-release|previous-release-phase1|retired-release)-[0-9a-f]{32}$'
        if (-not $emptyPattern -and -not $releasePattern) {
            throw 'The combat-canary staging root contains an unknown child; evidence was retained'
        }
        $childPath = Assert-PathWithinRoot -Path $child.FullName -Root $stagingRoot
        if ($emptyPattern) {
            $inventory = Get-PSOBBCombatCanaryCleanupTreeInventory `
                -Root $childPath -RoleLabel 'legacy empty build stage'
            if ($inventory.DescendantCount -ne 0) {
                throw 'A legacy empty-only build stage contains data; evidence was retained'
            }
            $candidates.Add([pscustomobject]@{
                    Name = $name
                    Kind = 'EmptyLegacyStage'
                    Root = $inventory.Root
                    RootIdentity = $inventory.RootIdentity
                    DescendantCount = 0
                    FileCount = 0
                    TotalBytes = 0L
                    ManifestSha256 = ''
                })
        } else {
            $release = Assert-PSOBBCombatCanaryCleanupRelease `
                -Root $childPath -Contract $Context.Contract `
                -RoleLabel 'retired combat canary release'
            $candidates.Add([pscustomobject]@{
                    Name = $name
                    Kind = 'RetiredRelease'
                    Root = $release.Root
                    RootIdentity = $release.RootIdentity
                    DescendantCount = $release.DescendantCount
                    FileCount = $release.FileCount
                    TotalBytes = $release.TotalBytes
                    ManifestSha256 = $release.ManifestSha256
                })
        }
        $latest = $candidates[$candidates.Count - 1]
        $stagingEntries += [long]$latest.DescendantCount
        $stagingBytes += [long]$latest.TotalBytes
        if ($stagingEntries -gt $script:MaximumStagingEntries -or
            $stagingBytes -gt $script:MaximumStagingBytes) {
            throw 'The combat-canary staging root exceeds its aggregate cleanup bounds; evidence was retained'
        }
    }
    [pscustomobject]@{
        StagingPresent = $true
        StagingRoot = $stagingRoot
        StagingIdentity = $stagingIdentity
        Candidates = @($candidates)
    }
}

function Assert-PSOBBCombatCanaryCleanupPlanUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After
    )

    if ([bool]$Before.StagingPresent -ne [bool]$After.StagingPresent -or
        -not [bool]$Before.StagingPresent -or
        -not (Test-PSOBBCombatCanaryCleanupIdentityEqual `
            -Left $Before.StagingIdentity -Right $After.StagingIdentity) -or
        @($Before.Candidates).Count -ne @($After.Candidates).Count) {
        throw 'The combat-canary staging cleanup plan changed before deletion; evidence was retained'
    }
    for ($index = 0; $index -lt @($Before.Candidates).Count; $index++) {
        $left = @($Before.Candidates)[$index]
        $right = @($After.Candidates)[$index]
        if ([string]$left.Name -cne [string]$right.Name -or
            [string]$left.Kind -cne [string]$right.Kind -or
            [int]$left.DescendantCount -ne [int]$right.DescendantCount -or
            [int]$left.FileCount -ne [int]$right.FileCount -or
            [long]$left.TotalBytes -ne [long]$right.TotalBytes -or
            [string]$left.ManifestSha256 -cne [string]$right.ManifestSha256 -or
            -not (Test-PSOBBCombatCanaryCleanupIdentityEqual `
                -Left $left.RootIdentity -Right $right.RootIdentity)) {
            throw 'The combat-canary staging cleanup plan changed before deletion; evidence was retained'
        }
    }
    $true
}

function New-PSOBBCombatCanaryCleanupResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Outcome,
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Published
    )

    $candidates = @($Plan.Candidates)
    [pscustomobject]@{
        SchemaVersion = 1
        Action = 'CombatCanaryBuildStagingCleanup'
        Outcome = $Outcome
        CandidateCount = $candidates.Count
        EmptyCandidateCount = @($candidates | Where-Object {
                $_.Kind -ceq 'EmptyLegacyStage'
            }).Count
        ReleaseCandidateCount = @($candidates | Where-Object {
                $_.Kind -ceq 'RetiredRelease'
            }).Count
        DescendantCount = [int](($candidates | Measure-Object `
                    -Property DescendantCount -Sum).Sum)
        PayloadFileCount = [int](($candidates | Measure-Object `
                    -Property FileCount -Sum).Sum)
        TotalBytes = [long](($candidates | Measure-Object `
                    -Property TotalBytes -Sum).Sum)
        PublishedManifestSha256 = [string]$Published.ManifestSha256
    }
}

$context = Get-PSOBBCombatCanaryCleanupContext
$boundary = $null
try {
    $boundary = Enter-PSOBBCombatCanaryCleanupBoundary -Context $context
    $publishedBefore = Assert-PSOBBCombatCanaryCleanupRelease `
        -Root $context.CombatLayout.ServerBase -Contract $context.Contract `
        -RoleLabel 'published combat canary server base' -RequireContractOutput
    $plan = Get-PSOBBCombatCanaryCleanupPlan -Context $context
    if (-not $plan.StagingPresent) {
        New-PSOBBCombatCanaryCleanupResult -Outcome 'AlreadyClean' `
            -Plan $plan -Published $publishedBefore
        return
    }

    $target = '{0} verified combat-canary build staging tree(s)' -f
        @($plan.Candidates).Count
    if (-not $PSCmdlet.ShouldProcess(
            $target, 'Remove exact derived build staging debris')) {
        New-PSOBBCombatCanaryCleanupResult -Outcome 'Preview' `
            -Plan $plan -Published $publishedBefore
        return
    }

    if ($null -ne $InternalTestBeforeDelete) {
        & $InternalTestBeforeDelete $plan.StagingRoot
    }
    [void](Assert-PSOBBCombatCanaryCleanupStopped -Context $context)
    $revalidated = Get-PSOBBCombatCanaryCleanupPlan -Context $context
    [void](Assert-PSOBBCombatCanaryCleanupPlanUnchanged `
            -Before $plan -After $revalidated)
    $publishedImmediatelyBefore = Assert-PSOBBCombatCanaryCleanupRelease `
        -Root $context.CombatLayout.ServerBase -Contract $context.Contract `
        -RoleLabel 'published combat canary server base' -RequireContractOutput
    if ([string]$publishedBefore.ManifestSha256 -cne
            [string]$publishedImmediatelyBefore.ManifestSha256 -or
        -not (Test-PSOBBCombatCanaryCleanupIdentityEqual `
            -Left $publishedBefore.RootIdentity `
            -Right $publishedImmediatelyBefore.RootIdentity)) {
        throw 'The published combat-canary server base changed before cleanup; staging was retained'
    }

    foreach ($candidate in @($revalidated.Candidates)) {
        Remove-PSOBBCombatCanaryOwnedTree `
            -Path $candidate.Root -Root $revalidated.StagingRoot `
            -ExpectedVolumeSerialNumber `
                $candidate.RootIdentity.VolumeSerialNumber `
            -ExpectedFileId $candidate.RootIdentity.FileId `
            -RoleLabel 'verified combat canary build staging tree'
    }
    if (@(Get-ChildItem -Force -LiteralPath $revalidated.StagingRoot `
                -ErrorAction Stop).Count -ne 0) {
        throw 'The exact combat-canary staging root is not empty after cleanup'
    }
    Remove-PSOBBCombatCanaryOwnedTree `
        -Path $revalidated.StagingRoot `
        -Root $context.CombatLayout.EnvironmentRoot `
        -ExpectedVolumeSerialNumber `
            $revalidated.StagingIdentity.VolumeSerialNumber `
        -ExpectedFileId $revalidated.StagingIdentity.FileId `
        -RoleLabel 'empty combat canary build staging root'

    $publishedAfter = Assert-PSOBBCombatCanaryCleanupRelease `
        -Root $context.CombatLayout.ServerBase -Contract $context.Contract `
        -RoleLabel 'published combat canary server base' -RequireContractOutput
    if ([string]$publishedImmediatelyBefore.ManifestSha256 -cne
            [string]$publishedAfter.ManifestSha256 -or
        -not (Test-PSOBBCombatCanaryCleanupIdentityEqual `
            -Left $publishedImmediatelyBefore.RootIdentity `
            -Right $publishedAfter.RootIdentity)) {
        throw 'The published combat-canary server base changed during staging cleanup'
    }
    New-PSOBBCombatCanaryCleanupResult -Outcome 'Removed' `
        -Plan $revalidated -Published $publishedAfter
} finally {
    Exit-PSOBBCombatCanaryCleanupBoundary -Boundary $boundary
}
