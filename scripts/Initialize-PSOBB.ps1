[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [string]$ServerName = 'PSOBB Local',
    [ValidateSet('stable-qol', 'baseline')]
    [string]$ClientPatchProfile = 'stable-qol'
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $repositoryRoot 'config\sources.lock.json'
$clientPatchPolicyPath = Join-Path $repositoryRoot 'config\client-patch-profiles.json'
$lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json -Depth 20
Get-PSOBBClientPatchPolicy -Path $clientPatchPolicyPath | Out-Null

function Get-LockedComponent([string]$Id) {
    $matches = @($lock.components | Where-Object id -eq $Id)
    if ($matches.Count -ne 1) {
        throw "sources.lock.json must contain exactly one $Id component"
    }
    $matches[0]
}

$newservLock = Get-LockedComponent 'newserv-stable-release'
$clientLock = Get-LockedComponent 'tethealla-59nl-english'
$rendererLock = Get-LockedComponent 'dgvoodoo2-x86-d3d8'
$newservMember = @($newservLock.members | Where-Object path -eq 'release/newserv-windows.exe')
$clientMember = @($clientLock.members | Where-Object path -eq 'Psobb.exe')
$rendererWrapperMember = @($rendererLock.members | Where-Object path -eq 'MS/x86/D3D8.dll')
$rendererConfigurationMember = @($rendererLock.members | Where-Object path -eq 'dgVoodoo.conf')
if (($newservMember.Count -ne 1) -or ($clientMember.Count -ne 1) -or
    ($rendererWrapperMember.Count -ne 1) -or ($rendererConfigurationMember.Count -ne 1)) {
    throw 'sources.lock.json is missing an approved executable or renderer member record'
}

$newservArchive = Join-Path $layout.Archives 'newserv-v2026-02-27-release.zip'
$clientArchive = Join-Path $layout.Archives 'TethVer12513_English.zip'
$rendererArchive = Join-Path $layout.Archives 'dgVoodoo2_87_3.zip'
foreach ($directory in @(
    $layout.Root, $layout.Archives, $layout.Stable, $layout.Canary,
    $layout.Backups, $layout.Logs, $layout.Secrets)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
$marker = Initialize-PSOBBRuntimeMarker -Layout $layout

foreach ($pair in @(
    @{ Path = $newservArchive; Lock = $newservLock },
    @{ Path = $clientArchive; Lock = $clientLock },
    @{ Path = $rendererArchive; Lock = $rendererLock })) {
    if (-not (Test-Path -LiteralPath $pair.Path -PathType Leaf)) {
        throw "Required archive is missing: $($pair.Path)"
    }
    $file = Get-Item -LiteralPath $pair.Path
    if (($file.Length -ne [long]$pair.Lock.size) -or
        ((Get-LowerSha256 $file.FullName) -ne [string]$pair.Lock.sha256)) {
        throw "Approved archive size/hash mismatch: $($pair.Path)"
    }
}

if (@(Get-NewservProcessesAtPath -Layout $layout).Count -gt 0) {
    throw 'Stop the exact PSOBB newserv process before reinitializing immutable or parity data'
}

# Derive complete expected inventories from the two hash-approved archives. This
# prevents an altered data file or injected DLL from being blessed merely because
# Psobb.exe itself still matches.
$expectedServerFiles = @(Get-PSOBBZipContentManifest -Path $newservArchive)
$expectedClientFiles = @(Get-PSOBBZipContentManifest -Path $clientArchive)
$expectedRendererFiles = @(Get-PSOBBZipContentManifest -Path $rendererArchive)
$serverBaseParent = Split-Path $layout.ServerBase -Parent
$rendererOverlay = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3'
if (-not (Test-Path -LiteralPath $serverBaseParent)) {
    Expand-PSOBBApprovedArchive -ArchivePath $newservArchive -DestinationPath $serverBaseParent -RuntimeRoot $layout.Root
}
if (-not (Test-Path -LiteralPath $layout.BaseClient)) {
    Expand-PSOBBApprovedArchive -ArchivePath $clientArchive -DestinationPath $layout.BaseClient -RuntimeRoot $layout.Root
}
if (-not (Test-Path -LiteralPath $rendererOverlay)) {
    Expand-PSOBBApprovedArchive -ArchivePath $rendererArchive -DestinationPath $rendererOverlay -RuntimeRoot $layout.Root
}
if (-not (Test-PSOBBDirectoryManifest -Root $serverBaseParent -Files $expectedServerFiles)) {
    throw 'Immutable newserv base does not exactly match the approved release archive'
}
if (-not (Test-PSOBBDirectoryManifest -Root $layout.BaseClient -Files $expectedClientFiles)) {
    throw 'Immutable client base does not exactly match the approved acquisition archive'
}
if (-not (Test-PSOBBDirectoryManifest -Root $rendererOverlay -Files $expectedRendererFiles)) {
    throw 'Immutable dgVoodoo overlay does not exactly match the approved release archive'
}
Assert-NewservClientPatchProfileAvailable `
    -ServerRoot $layout.ServerBase `
    -Profile $ClientPatchProfile `
    -PolicyPath $clientPatchPolicyPath | Out-Null

$serverBaseManifestPath = Join-Path $layout.Stable 'server-base.manifest.json'
$serverBaseManifest = [ordered]@{
    schemaVersion = 1
    sourceArchiveSha256 = [string]$newservLock.sha256
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    files = $expectedServerFiles
}
[System.IO.File]::WriteAllText(
    $serverBaseManifestPath,
    ($serverBaseManifest | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false))
$baseClientManifest = [ordered]@{
    schemaVersion = 1
    sourceArchiveSha256 = [string]$clientLock.sha256
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    files = $expectedClientFiles
}
[System.IO.File]::WriteAllText(
    $layout.BaseClientManifest,
    ($baseClientManifest | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false))

if (-not (Test-Path -LiteralPath $layout.Server)) {
    New-Item -ItemType Directory -Path $layout.Server | Out-Null
    Copy-Item -Path (Join-Path $layout.ServerBase '*') -Destination $layout.Server -Recurse -Force
}
if (-not (Test-Path -LiteralPath $layout.Client)) {
    New-Item -ItemType Directory -Path $layout.Client | Out-Null
    Copy-Item -Path (Join-Path $layout.BaseClient '*') -Destination $layout.Client -Recurse -Force
}

$serverExecutable = Join-Path $layout.Server 'newserv-windows.exe'
$baseClientExecutable = Join-Path $layout.BaseClient 'Psobb.exe'
$clientExecutable = Join-Path $layout.Client 'Psobb.exe'
$rendererWrapper = Join-Path $rendererOverlay 'MS\x86\D3D8.dll'
$rendererConfiguration = Join-Path $rendererOverlay 'dgVoodoo.conf'
foreach ($check in @(
    @{ Path = $serverExecutable; Member = $newservMember[0] },
    @{ Path = $baseClientExecutable; Member = $clientMember[0] },
    @{ Path = $clientExecutable; Member = $clientMember[0] },
    @{ Path = $rendererWrapper; Member = $rendererWrapperMember[0] },
    @{ Path = $rendererConfiguration; Member = $rendererConfigurationMember[0] })) {
    if (-not (Test-Path -LiteralPath $check.Path -PathType Leaf)) {
        throw "Required extracted executable is missing: $($check.Path)"
    }
    $file = Get-Item -LiteralPath $check.Path
    if (($file.Length -ne [long]$check.Member.size) -or
        ((Get-LowerSha256 $file.FullName) -ne [string]$check.Member.sha256)) {
        throw "Extracted executable provenance check failed: $($check.Path)"
    }
}

$configPath = Join-Path $layout.Server 'system\config.json'
$approvedConfigPath = Join-Path $layout.ServerBase 'system\config.json'
Copy-Item -LiteralPath $approvedConfigPath -Destination $configPath -Force
Set-NewservLocalConfiguration -ConfigPath $configPath -ServerName $ServerName `
    -ClientPatchProfile $ClientPatchProfile

$sourceData = Join-Path $layout.BaseClient 'data'
$patchData = Join-Path $layout.Server 'system\patch-bb\data'
$patchParent = Split-Path $patchData -Parent
$stagedPatchData = Join-Path $patchParent ('.data-new-' + [Guid]::NewGuid().ToString('N'))
$oldPatchData = Join-Path $patchParent ('.data-old-' + [Guid]::NewGuid().ToString('N'))
Assert-PathWithinRoot -Path $stagedPatchData -Root $layout.Root | Out-Null
New-Item -ItemType Directory -Path $stagedPatchData | Out-Null
$patchSwapped = $false
try {
    $files = @(Get-ChildItem -LiteralPath $sourceData -File | Where-Object {
        $_.Name -like 'map_*.dat' -or
        $_.Name -like 'map_*.evt' -or
        $_.Name -like 'unitxt_*' -or
        $_.Name -eq 'data.gsl'
    })
    if ($files.Count -eq 0) {
        throw "No BB parity files found under $sourceData"
    }
    $files | Copy-Item -Destination $stagedPatchData
    $unitxtJ = Join-Path $stagedPatchData 'unitxt_j.prs'
    if (-not (Test-Path -LiteralPath $unitxtJ -PathType Leaf)) {
        throw 'Tethealla unitxt_j.prs was not found in synchronized patch data'
    }
    Copy-Item -LiteralPath $unitxtJ -Destination (Join-Path $stagedPatchData 'unitxt_e.prs')
    $patchManifestFiles = @(Get-PSOBBDirectoryManifest -Root $stagedPatchData)

    if (Test-Path -LiteralPath $patchData) {
        Assert-PathWithinRoot -Path $patchData -Root $layout.Root | Out-Null
        Move-Item -LiteralPath $patchData -Destination $oldPatchData
    }
    Move-Item -LiteralPath $stagedPatchData -Destination $patchData
    $patchSwapped = $true
    if (Test-Path -LiteralPath $oldPatchData) {
        Remove-Item -LiteralPath (Assert-PathWithinRoot -Path $oldPatchData -Root $layout.Root) -Recurse -Force
    }
} catch {
    if (-not $patchSwapped -and (Test-Path -LiteralPath $oldPatchData) -and -not (Test-Path -LiteralPath $patchData)) {
        Move-Item -LiteralPath $oldPatchData -Destination $patchData
    }
    throw
} finally {
    foreach ($temporary in @($stagedPatchData, $oldPatchData)) {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath (Assert-PathWithinRoot -Path $temporary -Root $layout.Root) -Recurse -Force
        }
    }
}

$patchManifestPath = Join-Path $layout.Stable 'patch-bb-data.manifest.json'
[System.IO.File]::WriteAllText(
    $patchManifestPath,
    ([ordered]@{
        schemaVersion = 1
        sourceClientArchiveSha256 = [string]$clientLock.sha256
        generatedAtUtc = [DateTime]::UtcNow.ToString('o')
        files = $patchManifestFiles
    } | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false))

$record = [ordered]@{
    schemaVersion = 2
    installationId = $marker.installationId
    initializedAtUtc = [DateTime]::UtcNow.ToString('o')
    runtimeRoot = $layout.Root
    serverVersion = [string]$newservLock.version
    serverArchiveSha256 = [string]$newservLock.sha256
    serverExecutableSha256 = Get-LowerSha256 $serverExecutable
    serverBaseManifestSha256 = Get-LowerSha256 $serverBaseManifestPath
    clientVersion = [string]$clientLock.version
    clientArchiveSha256 = [string]$clientLock.sha256
    baseClientExecutableSha256 = Get-LowerSha256 $baseClientExecutable
    baseClientManifestSha256 = Get-LowerSha256 $layout.BaseClientManifest
    clientExecutableSha256 = Get-LowerSha256 $clientExecutable
    rendererVersion = [string]$rendererLock.version
    rendererArchiveSha256 = [string]$rendererLock.sha256
    rendererWrapperSha256 = Get-LowerSha256 $rendererWrapper
    rendererConfigurationSha256 = Get-LowerSha256 $rendererConfiguration
    patchManifestSha256 = Get-LowerSha256 $patchManifestPath
    synchronizedPatchFiles = $patchManifestFiles.Count
    clientPatchProfile = $ClientPatchProfile
    clientPatchPolicySha256 = Get-LowerSha256 $clientPatchPolicyPath
    networkScope = 'loopback-only'
}
[System.IO.File]::WriteAllText(
    $layout.InstallRecord,
    ($record | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    RuntimeRoot = $layout.Root
    InstallationId = $record.installationId
    Server = $layout.Server
    BaseClient = $layout.BaseClient
    Client = $layout.Client
    PatchFiles = $record.synchronizedPatchFiles
    ServerExecutableSha256 = $record.serverExecutableSha256
    ClientExecutableSha256 = $record.clientExecutableSha256
}
