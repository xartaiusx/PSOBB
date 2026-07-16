[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Native', 'DgVoodooD3D11', 'DgVoodooD3D12')]
    [string]$Renderer = 'Native',
    [ValidateSet('Stable', 'Canary')]
    [string]$Channel = 'Stable',
    [ValidateSet('Compatibility', 'HighFidelity2560x1600', 'Ultra3840x2880')]
    [string]$GraphicsPreset = 'Ultra3840x2880',
    [ValidateSet('Borderless', 'Resizable')]
    [string]$DefaultWindowMode = 'Borderless',
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$graphicsCatalogPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
$graphicsCatalog = Get-Content -Raw -LiteralPath $graphicsCatalogPath |
    ConvertFrom-Json -Depth 50
$lockPath = Join-Path $repositoryRoot 'config\sources.lock.json'
$lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json -Depth 20
$clientLocks = @($lock.components | Where-Object id -eq 'tethealla-59nl-english')
if ($clientLocks.Count -ne 1) {
    throw 'sources.lock.json must contain exactly one tethealla-59nl-english component'
}
$clientLock = $clientLocks[0]
$clientMembers = @($clientLock.members | Where-Object path -eq 'Psobb.exe')
if ($clientMembers.Count -ne 1) {
    throw 'The approved client executable member is missing from sources.lock.json'
}
$rendererLocks = @($lock.components | Where-Object id -eq 'dgvoodoo2-x86-d3d8')
if ($rendererLocks.Count -ne 1) {
    throw 'sources.lock.json must contain exactly one dgvoodoo2-x86-d3d8 component'
}
$rendererLock = $rendererLocks[0]
$wrapperMembers = @($rendererLock.members | Where-Object path -eq 'MS/x86/D3D8.dll')
$configurationMembers = @($rendererLock.members | Where-Object path -eq 'dgVoodoo.conf')
if (($wrapperMembers.Count -ne 1) -or ($configurationMembers.Count -ne 1)) {
    throw 'The approved dgVoodoo wrapper or source configuration member is missing from sources.lock.json'
}
$expectedBaseHash = [string]$clientMembers[0].sha256
$clientArchive = Join-Path $layout.Archives 'TethVer12513_English.zip'
$installRecordPath = $layout.InstallRecord
$baseManifestPath = $layout.BaseClientManifest
$baseExecutable = Join-Path $layout.BaseClient 'Psobb.exe'
$targetClient = if ($Channel -eq 'Stable') {
    $layout.Client
} else {
    Join-Path $layout.Canary 'runtime\client'
}

if (($Channel -eq 'Stable') -and ($Renderer -eq 'DgVoodooD3D12')) {
    throw 'The D3D12 renderer is canary-only; use -Channel Canary'
}

$catalogProfileId = if ($Renderer -eq 'Native') {
    'safe-native-4x3'
} else {
    'clarity-dgvoodoo-4x3'
}
$catalogProfiles = @($graphicsCatalog.profiles | Where-Object {
    [string]$_.id -ceq $catalogProfileId
})
if ([int]$graphicsCatalog.schemaVersion -ne 1 -or $catalogProfiles.Count -ne 1) {
    throw "The graphics catalog does not declare profile '$catalogProfileId' exactly once"
}
$nativeGraphicsContract = Assert-PSOBBNativeGraphicsContract `
    -NativeGraphics $catalogProfiles[0].nativeGraphics `
    -Label "Graphics catalog profile '$catalogProfileId' nativeGraphics"
$materializedNativeGraphics = [ordered]@{
    presetId = $nativeGraphicsContract.PresetId
    graphicCtrlDwords = [uint32[]]$nativeGraphicsContract.GraphicCtrlDwords
    graphicCtrlSha256 = $nativeGraphicsContract.GraphicCtrlSha256
    advancedEffectsPolicy = $nativeGraphicsContract.AdvancedEffectsPolicy
    pixelFogPolicy = $nativeGraphicsContract.PixelFogPolicy
    lowResolutionTexturesPolicy = $nativeGraphicsContract.LowResolutionTexturesPolicy
    frameSkipPolicy = $nativeGraphicsContract.FrameSkipPolicy
}

foreach ($runtimePath in @(
    $layout.Archives, $clientArchive, $layout.BaseClient, $baseManifestPath,
    $installRecordPath, $targetClient, (Split-Path -Parent $targetClient))) {
    Assert-PathWithinRoot -Path $runtimePath -Root $layout.Root | Out-Null
}

$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
foreach ($process in @(Get-Process -Name 'Psobb', 'online', 'option' -ErrorAction SilentlyContinue)) {
    try {
        $processPath = [System.IO.Path]::GetFullPath($process.Path)
        foreach ($clientRoot in @($layout.BaseClient, $targetClient)) {
            $clientPrefix = [System.IO.Path]::GetFullPath($clientRoot).TrimEnd('\') + '\'
            if ($processPath.StartsWith($clientPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'Close the PSOBB client and option processes from this runtime before rebuilding it'
            }
        }
    } catch {
        if ($_.Exception.Message -like 'Close the PSOBB client*') {
            throw
        }
        throw "Cannot verify the executable path for client PID $($process.Id)"
    }
}

if (-not (Test-Path -LiteralPath $clientArchive -PathType Leaf)) {
    throw "Approved base-client archive is missing: $clientArchive"
}
$archiveFile = Get-Item -LiteralPath $clientArchive
if (($archiveFile.Length -ne [long]$clientLock.size) -or
    ((Get-LowerSha256 $clientArchive) -ne [string]$clientLock.sha256)) {
    throw 'The base-client archive no longer matches sources.lock.json'
}
if (-not (Test-Path -LiteralPath $baseManifestPath -PathType Leaf)) {
    throw "Base-client manifest is missing: $baseManifestPath"
}
if (-not (Test-Path -LiteralPath $installRecordPath -PathType Leaf)) {
    throw "Runtime installation record is missing: $installRecordPath"
}
$baseManifest = Get-Content -Raw -LiteralPath $baseManifestPath | ConvertFrom-Json -Depth 20
$installRecord = Get-Content -Raw -LiteralPath $installRecordPath | ConvertFrom-Json -Depth 20
if (($baseManifest.schemaVersion -ne 1) -or
    -not ([string]$baseManifest.sourceArchiveSha256).Equals(
        [string]$clientLock.sha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The base-client manifest is not tied to the approved client archive'
}
if (($installRecord.schemaVersion -ne 2) -or
    -not ([string]$installRecord.installationId).Equals(
        [string]$marker.installationId, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not ([string]$installRecord.clientArchiveSha256).Equals(
        [string]$clientLock.sha256, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not ([string]$installRecord.baseClientManifestSha256).Equals(
        (Get-LowerSha256 $baseManifestPath), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The runtime installation record does not authenticate the base-client manifest'
}

$approvedArchiveFiles = @(Get-PSOBBZipContentManifest -Path $clientArchive)
if (-not (Test-PSOBBManifestEntriesEqual -Left $approvedArchiveFiles -Right @($baseManifest.files))) {
    throw 'The base-client manifest contents do not exactly match the approved archive'
}
if (-not (Test-PSOBBDirectoryManifest -Root $layout.BaseClient -Files @($baseManifest.files))) {
    throw 'The immutable base-client tree no longer matches its complete approved manifest'
}
if (((Get-Item -LiteralPath $baseExecutable).Length -ne [long]$clientMembers[0].size) -or
    ((Get-LowerSha256 $baseExecutable) -ne $expectedBaseHash)) {
    throw 'The immutable 59NL base client executable no longer matches its approved hash'
}

$runtimeParent = Split-Path -Parent $targetClient
$temporaryClient = Join-Path $runtimeParent ('.client-new-' + [Guid]::NewGuid().ToString('N'))
$lkgRoot = Join-Path $layout.Root 'last-known-good\clients'
$timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$preservedRenderer = 'none'
$existingProfilePath = Join-Path $targetClient 'client-profile.json'
if (Test-Path -LiteralPath $existingProfilePath -PathType Leaf) {
    try {
        $existingProfile = Get-Content -Raw -LiteralPath $existingProfilePath | ConvertFrom-Json
        if ([string]$existingProfile.renderer -match '^[A-Za-z0-9]+$') {
            $preservedRenderer = ([string]$existingProfile.renderer).ToLowerInvariant()
        }
    } catch {
        $preservedRenderer = 'unknown'
    }
}
$snapshotPath = Join-Path $lkgRoot ("client-$timestamp-$($Channel.ToLowerInvariant())-preserved-$preservedRenderer")
$previousMoved = $false

foreach ($runtimePath in @($temporaryClient, $lkgRoot, $snapshotPath)) {
    Assert-PathWithinRoot -Path $runtimePath -Root $layout.Root | Out-Null
}
if (Test-Path -LiteralPath $snapshotPath) {
    throw "Refusing to replace an existing client snapshot: $snapshotPath"
}
if (Test-Path -LiteralPath $targetClient) {
    Assert-PathWithinRoot -Path $targetClient -Root $layout.Root | Out-Null
    $runtimeReparsePoint = Get-ChildItem -LiteralPath $targetClient -Force -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($runtimeReparsePoint) {
        throw "Disposable client contains a reparse point: $($runtimeReparsePoint.FullName)"
    }
}

if (-not $PSCmdlet.ShouldProcess($targetClient, "Rebuild $Channel disposable client using $Renderer")) {
    return
}

New-Item -ItemType Directory -Force -Path $runtimeParent, $lkgRoot | Out-Null
try {
    New-Item -ItemType Directory -Path $temporaryClient | Out-Null
    foreach ($baseItem in @(Get-ChildItem -LiteralPath $layout.BaseClient -Force)) {
        Copy-Item -LiteralPath $baseItem.FullName -Destination $temporaryClient -Recurse -Force
    }
    if (-not (Test-PSOBBDirectoryManifest -Root $temporaryClient -Files @($baseManifest.files))) {
        throw 'Disposable client copy does not exactly match the complete immutable base'
    }

    $wrapperHash = $null
    if ($Renderer -ne 'Native') {
        $overlayRoot = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3'
        $wrapperSource = Join-Path $overlayRoot 'MS\x86\D3D8.dll'
        $configurationSource = Join-Path $overlayRoot 'dgVoodoo.conf'
        foreach ($overlayPath in @($overlayRoot, $wrapperSource, $configurationSource)) {
            Assert-PathWithinRoot -Path $overlayPath -Root $layout.Root | Out-Null
        }
        if (-not (Test-Path -LiteralPath $configurationSource -PathType Leaf)) {
            throw 'The pinned dgVoodoo configuration file is missing'
        }
        $wrapperSourceItem = Get-Item -LiteralPath $wrapperSource
        if (($wrapperSourceItem.Length -ne [long]$wrapperMembers[0].size) -or
            ((Get-LowerSha256 $wrapperSource) -ne [string]$wrapperMembers[0].sha256)) {
            throw 'The pinned x86 dgVoodoo2 D3D8 wrapper hash does not match'
        }
        $configurationSourceItem = Get-Item -LiteralPath $configurationSource
        if (($configurationSourceItem.Length -ne [long]$configurationMembers[0].size) -or
            ((Get-LowerSha256 $configurationSource) -ne [string]$configurationMembers[0].sha256)) {
            throw 'The pinned dgVoodoo2 source configuration hash does not match'
        }
        foreach ($conflict in @('d3d8.dll', 'd3d9.dll', 'ddraw.dll', 'dxgi.dll')) {
            if (Test-Path -LiteralPath (Join-Path $temporaryClient $conflict)) {
                throw "The clean base unexpectedly contains a competing renderer DLL: $conflict"
            }
        }
        Copy-Item -LiteralPath $wrapperSource -Destination (Join-Path $temporaryClient 'd3d8.dll')
        Copy-Item -LiteralPath $configurationSource -Destination (Join-Path $temporaryClient 'dgVoodoo.conf')
        $configurationPath = Join-Path $temporaryClient 'dgVoodoo.conf'
        $configuration = Get-PSOBBDgVoodooConfiguration `
            -SourceText (Get-Content -Raw -LiteralPath $configurationSource) `
            -Renderer $Renderer `
            -GraphicsPreset $GraphicsPreset
        [System.IO.File]::WriteAllText(
            $configurationPath,
            $configuration,
            [System.Text.UTF8Encoding]::new($false))
        $wrapperHash = Get-LowerSha256 (Join-Path $temporaryClient 'd3d8.dll')
    }

    $approvedDllPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @($baseManifest.files | Where-Object { [string]$_.path -like '*.dll' })) {
        [void]$approvedDllPaths.Add(([string]$file.path).Replace('/', '\'))
    }
    if ($Renderer -ne 'Native') {
        [void]$approvedDllPaths.Add('d3d8.dll')
    }
    foreach ($dll in @(Get-ChildItem -LiteralPath $temporaryClient -Filter '*.dll' -File -Force -Recurse)) {
        Assert-PathWithinRoot -Path $dll.FullName -Root $layout.Root | Out-Null
        $relativeDllPath = [System.IO.Path]::GetRelativePath($temporaryClient, $dll.FullName)
        if (-not $approvedDllPaths.Contains($relativeDllPath)) {
            throw "Disposable client contains an unexpected loadable DLL: $relativeDllPath"
        }
    }

    if ((Get-LowerSha256 (Join-Path $temporaryClient 'Psobb.exe')) -ne $expectedBaseHash) {
        throw 'Disposable client copy failed executable verification'
    }
    $profile = [ordered]@{
        schemaVersion = 5
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
        channel = $Channel.ToLowerInvariant()
        profileId = $catalogProfileId
        nativeGraphics = $materializedNativeGraphics
        renderer = $Renderer
        baseExecutableSha256 = $expectedBaseHash
        wrapperSha256 = $wrapperHash
        sourceConfigurationSha256 = if ($Renderer -eq 'Native') { $null } else { [string]$configurationMembers[0].sha256 }
        configurationSha256 = if ($Renderer -eq 'Native') { $null } else { Get-LowerSha256 (Join-Path $temporaryClient 'dgVoodoo.conf') }
        outputApi = if ($Renderer -eq 'DgVoodooD3D11') {
            'd3d11_fl11_0'
        } elseif ($Renderer -eq 'DgVoodooD3D12') {
            'd3d12_fl11_0'
        } else {
            $null
        }
        graphicsPreset = if ($Renderer -eq 'Native') { 'Native' } else { $GraphicsPreset }
        desktopWidth = if (($Renderer -ne 'Native') -and ($GraphicsPreset -ne 'Compatibility')) { 2560 } else { $null }
        desktopHeight = if (($Renderer -ne 'Native') -and ($GraphicsPreset -ne 'Compatibility')) { 1600 } else { $null }
        renderWidth = if (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'Ultra3840x2880')) {
            3840
        } elseif (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'HighFidelity2560x1600')) {
            'dynamic-max'
        } else {
            $null
        }
        renderHeight = if (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'Ultra3840x2880')) {
            2880
        } elseif (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'HighFidelity2560x1600')) {
            'dynamic-max'
        } else {
            $null
        }
        aspectPolicy = if (($Renderer -ne 'Native') -and ($GraphicsPreset -ne 'Compatibility')) {
            'preserve-4x3'
        } else {
            $null
        }
        resamplingFilter = if (($Renderer -ne 'Native') -and ($GraphicsPreset -ne 'Compatibility')) {
            'lanczos-3'
        } else {
            $null
        }
        textureFilterPolicy = if (($Renderer -ne 'Native') -and ($GraphicsPreset -ne 'Compatibility')) {
            'anisotropic-16-preserve-point-sampled'
        } else {
            $null
        }
        edgeSmoothingPolicy = if (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'Ultra3840x2880')) {
            'supersampling-only'
        } elseif (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'HighFidelity2560x1600')) {
            'msaa-8x'
        } else {
            $null
        }
        bilinear2DOperations = if (($Renderer -ne 'Native') -and ($GraphicsPreset -ne 'Compatibility')) {
            $false
        } else {
            $null
        }
        defaultWindowMode = if ($Renderer -eq 'Native') { $null } else { $DefaultWindowMode }
        resizableClientWidth = if ($Renderer -eq 'Native') { $null } else { 1600 }
        resizableClientHeight = if ($Renderer -eq 'Native') { $null } else { 1200 }
        watermarkEnabled = if ($Renderer -eq 'Native') { $null } else { $false }
        compatibilityFirst = (($Renderer -ne 'Native') -and ($GraphicsPreset -eq 'Compatibility'))
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $temporaryClient 'client-profile.json'),
        ($profile | ConvertTo-Json),
        [System.Text.UTF8Encoding]::new($false))

    if (Test-Path -LiteralPath $targetClient) {
        $lateClientProcesses = @(Get-PSOBBProcessesAtExactPath `
            -Name 'Psobb' `
            -ExpectedPath (Join-Path $targetClient 'Psobb.exe'))
        if ($lateClientProcesses.Count -gt 0) {
            throw "The target PSOBB client started during rebuild (PID(s): $($lateClientProcesses.Id -join ', '))"
        }
        Move-Item -LiteralPath $targetClient -Destination $snapshotPath
        $previousMoved = $true
    }
    Move-Item -LiteralPath $temporaryClient -Destination $targetClient

    [pscustomobject]@{
        ClientPath = $targetClient
        Channel = $Channel
        Renderer = $Renderer
        BaseExecutableSha256 = $expectedBaseHash
        WrapperSha256 = $wrapperHash
        GraphicsPreset = if ($Renderer -eq 'Native') { 'Native' } else { $GraphicsPreset }
        DefaultWindowMode = if ($Renderer -eq 'Native') { $null } else { $DefaultWindowMode }
        PreviousSnapshot = if ($previousMoved) { $snapshotPath } else { $null }
    }
} catch {
    if ($previousMoved -and -not (Test-Path -LiteralPath $targetClient) -and (Test-Path -LiteralPath $snapshotPath)) {
        Move-Item -LiteralPath $snapshotPath -Destination $targetClient
    }
    throw
} finally {
    if (Test-Path -LiteralPath $temporaryClient) {
        $safeTemporaryClient = Assert-PathWithinRoot -Path $temporaryClient -Root $layout.Root
        Remove-Item -LiteralPath $safeTemporaryClient -Recurse -Force
    }
}
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
