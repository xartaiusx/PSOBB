[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateSet(
        'lab-widescreen-16x10',
        'lab-widescreen-cas-16x10',
        'cleanroom-widescreen-canary',
        'cas-evaluation-16x10',
        'dxvk-canary',
        'd3d8to9-canary')]
    [string]$ProfileId = 'lab-widescreen-16x10',

    [ValidateSet('Borderless', 'Resizable')]
    [string]$WindowMode = 'Borderless',

    [ValidateSet('lanczos-3', 'lanczos-2', 'bicubic')]
    [string]$ScalingFilter = 'lanczos-3',

    [ValidateSet(0, 4, 8)]
    [int]$Msaa = 0,

    [int]$RenderWidth,
    [int]$RenderHeight,

    [ValidateRange(0.1, 10.0)]
    [double]$HudScale = 1.25,

    [ValidateSet('0.15', '0.25', '0.35')]
    [string]$CasStrength,

    [string]$RuntimeRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-LockedComponent {
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

function Assert-LockedArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Component,
        [string]$MemberPath,
        [string]$RuntimeArtifactPath
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "A locked graphics artifact is missing: $Path"
    }
    $file = Get-Item -LiteralPath $Path -Force
    if (-not [string]::IsNullOrWhiteSpace($RuntimeArtifactPath)) {
        if (-not [string]::IsNullOrWhiteSpace($MemberPath)) {
            throw 'MemberPath and RuntimeArtifactPath are mutually exclusive'
        }
        $artifacts = @($Component.runtimeArtifacts | Where-Object {
            [string]$_.path -ceq $RuntimeArtifactPath
        })
        if ($artifacts.Count -ne 1) {
            throw "Component '$($Component.id)' does not lock runtime artifact '$RuntimeArtifactPath' exactly once"
        }
        $expectedSize = [long]$artifacts[0].size
        $expectedHash = [string]$artifacts[0].sha256
    } elseif ([string]::IsNullOrWhiteSpace($MemberPath)) {
        $expectedSize = [long]$Component.size
        $expectedHash = [string]$Component.sha256
    } else {
        $members = @($Component.members | Where-Object { [string]$_.path -ceq $MemberPath })
        if ($members.Count -ne 1) {
            throw "Component '$($Component.id)' does not lock member '$MemberPath' exactly once"
        }
        $expectedSize = [long]$members[0].size
        $expectedHash = [string]$members[0].sha256
    }
    if ($expectedSize -le 0 -or $expectedHash -cnotmatch '^[a-f0-9]{64}$' -or
        $file.Length -ne $expectedSize -or (Get-LowerSha256 -Path $file.FullName) -cne $expectedHash) {
        throw "Graphics artifact does not match its locked size and SHA-256: $Path"
    }
    $file.FullName
}

function Set-FlatConfigurationValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    $pattern = '(?m)^(?<prefix>[ \t]*' + [regex]::Escape($Key) +
        '[ \t]*=[ \t]*)(?<value>[^\r\n]*?)(?<suffix>[ \t]*\r?)$'
    $regex = [regex]::new($pattern)
    $matches = $regex.Matches($Text)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one active setting named '$Key'"
    }
    $regex.Replace(
        $Text,
        { param($match) $match.Groups['prefix'].Value + $Value + $match.Groups['suffix'].Value },
        1)
}

function Copy-DirectoryContents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $Source -Force)) {
        Copy-Item -LiteralPath $item.FullName -Destination $Destination -Recurse -Force
    }
}

function Assert-NoActiveLocalAssetComposition {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ClientRoot)

    $profilePath = Join-Path $ClientRoot 'client-profile.json'
    if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        return
    }
    $profileFile = Get-Item -LiteralPath $profilePath -Force
    if (($profileFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $profileFile.Length -le 0 -or $profileFile.Length -gt 1MB) {
        throw 'The existing LocalLab client profile has an invalid filesystem type or size'
    }
    try {
        $currentProfile = Get-Content -Raw -LiteralPath $profilePath |
            ConvertFrom-Json -Depth 50
    } catch {
        throw "The existing LocalLab client profile is invalid JSON: $($_.Exception.Message)"
    }
    $assetOverlay = $currentProfile.PSObject.Properties['localAssetOverlay']
    $localModules = $currentProfile.PSObject.Properties['localModules']
    if (($null -ne $assetOverlay -and $null -ne $assetOverlay.Value) -or
        ($null -ne $localModules -and $null -ne $localModules.Value)) {
        throw ('The clean graphics materializer refuses to replace an active ' +
            'local asset overlay or local module composition. Run ' +
            'Set-PSOBBAshenbubsHDClientActivation.ps1 -Action Rollback first.')
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$catalogPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
$sourcesPath = Join-Path $repositoryRoot 'config\sources.lock.json'
$catalog = Get-Content -Raw -LiteralPath $catalogPath | ConvertFrom-Json -Depth 50
$sources = Get-Content -Raw -LiteralPath $sourcesPath | ConvertFrom-Json -Depth 50
$profiles = @($catalog.profiles | Where-Object {
    [string]$_.id -ceq $ProfileId -and [string]$_.channel -ceq 'local-lab'
})
if ($catalog.schemaVersion -ne 1 -or $profiles.Count -ne 1) {
    throw "The requested LocalLab profile '$ProfileId' is not declared exactly once"
}
$profileDeclaration = $profiles[0]

$candidate = if ($RenderWidth -gt 0 -or $RenderHeight -gt 0) {
    if ($RenderWidth -le 0 -or $RenderHeight -le 0) {
        throw 'RenderWidth and RenderHeight must be supplied together'
    }
    @($profileDeclaration.display.internalRenderCandidates | Where-Object {
        [int]$_.width -eq $RenderWidth -and [int]$_.height -eq $RenderHeight
    })
} else {
    @($profileDeclaration.display.internalRenderCandidates | Select-Object -First 1)
}
if ($candidate.Count -ne 1) {
    throw "The requested render dimensions are not an approved candidate for '$ProfileId'"
}
$renderWidth = [int]$candidate[0].width
$renderHeight = [int]$candidate[0].height
if ([string]$profileDeclaration.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') {
    if (@($profileDeclaration.display.scalingFilterCandidates) -cnotcontains $ScalingFilter) {
        throw "The scaling filter is not an approved candidate for '$ProfileId'"
    }
    if (@($profileDeclaration.quality.msaaCandidates) -notcontains $Msaa) {
        throw "The MSAA setting is not an approved candidate for '$ProfileId'"
    }
} elseif ($ScalingFilter -ne 'lanczos-3' -or $Msaa -ne 0) {
    throw 'Scaling-filter and MSAA experiments require a declared dgVoodoo profile'
}
if ($Msaa -gt 0 -and ($renderWidth -ne 2560 -or $renderHeight -ne 1600)) {
    throw 'MSAA experiments are intentionally limited to native 2560x1600 rendering'
}
$casProfileIds = @('lab-widescreen-cas-16x10', 'cas-evaluation-16x10')
if ($ProfileId -in $casProfileIds) {
    if ([string]::IsNullOrWhiteSpace($CasStrength)) {
        throw 'CasStrength must explicitly select 0.15, 0.25, or 0.35 for a CAS evaluation profile'
    }
} elseif (-not [string]::IsNullOrWhiteSpace($CasStrength)) {
    throw 'CasStrength is valid only for the declared CAS evaluation profiles'
}

$baseManifestPath = $layout.BaseClientManifest
if (-not (Test-Path -LiteralPath $baseManifestPath -PathType Leaf)) {
    throw "The immutable base-client manifest is missing: $baseManifestPath"
}
$baseManifest = Get-Content -Raw -LiteralPath $baseManifestPath | ConvertFrom-Json -Depth 30
if ($baseManifest.schemaVersion -ne 1 -or
    -not (Test-PSOBBDirectoryManifest -Root $layout.BaseClient -Files @($baseManifest.files))) {
    throw 'The immutable base-client tree no longer matches its complete approved manifest'
}
$baseExecutable = Join-Path $layout.BaseClient 'Psobb.exe'
$identity = Assert-PSOBBApprovedClientExecutable -Path $baseExecutable
if ([string]$catalog.baseClient.executableSha256 -cne $identity.Sha256) {
    throw 'The graphics catalog is not tied to the immutable approved client executable'
}

$artifactMap = @{
    'dgvoodoo2-x86-d3d8' = [pscustomobject]@{
        Path = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\MS\x86\D3D8.dll'
        MemberPath = 'MS/x86/D3D8.dll'
    }
    'ultimate-asi-loader-x86' = [pscustomobject]@{
        Path = Join-Path $layout.LocalLab 'overlays\ultimate-asi-loader-9.7.2\dinput8.dll'
        MemberPath = 'dinput8.dll'
    }
    'psobb-widescreen-local-evaluation' = [pscustomobject]@{
        Path = Join-Path $layout.LocalLab 'overlays\psobb-widescreen-1.0.2\patches\pso_widescreen.asi'
        MemberPath = 'patches/pso_widescreen.asi'
    }
    'project-owned-psobb-enhancement' = [pscustomobject]@{
        Path = Join-Path $repositoryRoot 'src\PSOBB.Enhancement\bin\build-x86\Release\PSOBB.Enhancement.asi'
        MemberPath = $null
        RuntimeArtifactPath = 'PSOBB.Enhancement.asi'
        AllowedRoot = $repositoryRoot
    }
    'reshade-6.7.3-local-import' = [pscustomobject]@{
        Path = Join-Path $layout.LocalLab 'overlays\reshade-6.7.3-standard\dxgi.dll'
        MemberPath = 'ReShade32.dll'
    }
    'dxvk-x86-d3d8-d3d9:d3d8.dll' = [pscustomobject]@{
        Path = Join-Path $layout.LocalLab 'overlays\dxvk-3.0.1\x32\d3d8.dll'
        MemberPath = 'x32/d3d8.dll'
    }
    'dxvk-x86-d3d8-d3d9:d3d9.dll' = [pscustomobject]@{
        Path = Join-Path $layout.LocalLab 'overlays\dxvk-3.0.1\x32\d3d9.dll'
        MemberPath = 'x32/d3d9.dll'
    }
    'd3d8to9-x86' = [pscustomobject]@{
        Path = Join-Path $layout.Archives 'graphics-lab\d3d8to9-v1.15.1-x86.dll'
        MemberPath = $null
    }
}

$moduleCopies = [System.Collections.Generic.List[object]]::new()
foreach ($module in @($profileDeclaration.renderer.d3d8Owner) + @($profileDeclaration.renderer.secondaryLayers)) {
    if ([string]::IsNullOrWhiteSpace([string]$module.componentId)) {
        continue
    }
    $mapKey = if ([string]$module.componentId -ceq 'dxvk-x86-d3d8-d3d9') {
        '{0}:{1}' -f [string]$module.componentId, [System.IO.Path]::GetFileName([string]$module.relativePath)
    } else {
        [string]$module.componentId
    }
    if (-not $artifactMap.ContainsKey($mapKey)) {
        throw "No immutable artifact mapping exists for LocalLab component '$mapKey'"
    }
    $mapping = $artifactMap[$mapKey]
    $allowedRoot = if ($mapping.PSObject.Properties.Name -contains 'AllowedRoot') {
        [string]$mapping.AllowedRoot
    } else {
        $layout.Root
    }
    $runtimeArtifactPath = if ($mapping.PSObject.Properties.Name -contains 'RuntimeArtifactPath') {
        [string]$mapping.RuntimeArtifactPath
    } else {
        $null
    }
    Assert-PathWithinRoot -Path $mapping.Path -Root $allowedRoot | Out-Null
    $component = Get-LockedComponent -Sources $sources -Id ([string]$module.componentId)
    $sourcePath = Assert-LockedArtifact `
        -Path $mapping.Path `
        -Component $component `
        -MemberPath $mapping.MemberPath `
        -RuntimeArtifactPath $runtimeArtifactPath
    $moduleCopies.Add([pscustomobject]@{
        Source = $sourcePath
        RelativePath = ([string]$module.relativePath).Replace('/', '\')
    })
}

$targetClient = Join-Path $layout.LocalLab 'runtime\client'
$stagingLab = Join-Path $layout.LocalLab ('.staging-' + [Guid]::NewGuid().ToString('N'))
$stagingClient = Join-Path $stagingLab 'runtime\client'
$snapshotRoot = Join-Path $layout.Root 'last-known-good\clients'
$timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$snapshotPath = Join-Path $snapshotRoot ("client-$timestamp-local-lab-$ProfileId")
$rejectedPath = Join-Path $layout.LocalLab ('.rejected-' + [Guid]::NewGuid().ToString('N'))
foreach ($path in @($targetClient, $stagingLab, $stagingClient, $snapshotRoot, $snapshotPath, $rejectedPath)) {
    Assert-PathWithinRoot -Path $path -Root $layout.Root | Out-Null
}

if (-not $PSCmdlet.ShouldProcess(
    $targetClient,
    "Materialize exact LocalLab profile $ProfileId at ${renderWidth}x${renderHeight}")) {
    return
}

$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
$previousMoved = $false
$newInstalled = $false
try {
    Assert-PSOBBNoRunningClients -Layout $layout | Out-Null
    Assert-NoActiveLocalAssetComposition -ClientRoot $targetClient
    if (Test-Path -LiteralPath $stagingLab) {
        throw "Refusing to reuse a LocalLab staging path: $stagingLab"
    }
    New-Item -ItemType Directory -Path $stagingClient -Force | Out-Null
    Copy-DirectoryContents -Source $layout.BaseClient -Destination $stagingClient
    if (-not (Test-PSOBBDirectoryManifest -Root $stagingClient -Files @($baseManifest.files))) {
        throw 'The staged LocalLab client does not exactly match the immutable base before overlays'
    }

    foreach ($copy in $moduleCopies) {
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $stagingClient $copy.RelativePath) `
            -Root $stagingClient
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $copy.Source -Destination $destination -Force
    }

    $configurationHash = $null
    $widescreenConfigurationPath = $null
    $widescreenConfigurationHash = $null
    $widescreenIniPath = $null
    $widescreenIniHash = $null
    $enhancementConfigurationPath = $null
    $enhancementConfigurationHash = $null
    $reshadeConfigurationPath = $null
    $reshadeConfigurationHash = $null
    $reshadeTemplatePath = $null
    $reshadeTemplateHash = $null
    $reshadePresetPath = $null
    $reshadePresetHash = $null
    $casShaderPath = $null
    $casShaderHash = $null
    if ([string]$profileDeclaration.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') {
        $dgComponent = Get-LockedComponent -Sources $sources -Id 'dgvoodoo2-x86-d3d8'
        $configurationSource = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\dgVoodoo.conf'
        $configurationSource = Assert-LockedArtifact `
            -Path $configurationSource `
            -Component $dgComponent `
            -MemberPath 'dgVoodoo.conf'
        $configuration = Get-PSOBBDgVoodooConfiguration `
            -SourceText (Get-Content -Raw -LiteralPath $configurationSource) `
            -Renderer DgVoodooD3D11 `
            -GraphicsPreset HighFidelity2560x1600
        foreach ($setting in @(
            @('General', 'ScalingMode', 'stretched_ar'),
            @('General', 'KeepWindowAspectRatio', 'true'),
            @('GeneralExt', 'Resampling', $ScalingFilter),
            @('DirectX', 'Resolution', ("${renderWidth}x${renderHeight}")),
            @('DirectX', 'Antialiasing', $(if ($Msaa -eq 0) { 'off' } else { "${Msaa}x" })),
            @('DirectX', 'Filtering', '16'),
            @('DirectX', 'Mipmapping', 'appdriven'),
            @('DirectX', 'KeepFilterIfPointSampled', 'true'),
            @('DirectX', 'Bilinear2DOperations', 'false'),
            @('DirectX', 'ForceVerticalSync', 'false'),
            @('DirectX', 'dgVoodooWatermark', 'false')
        )) {
            $configuration = Set-PSOBBIniValue `
                -Text $configuration `
                -Section $setting[0] `
                -Key $setting[1] `
                -Value $setting[2]
        }
        $configurationPath = Join-Path $stagingClient 'dgVoodoo.conf'
        [System.IO.File]::WriteAllText(
            $configurationPath,
            $configuration,
            [System.Text.UTF8Encoding]::new($false))
        $configurationHash = Get-LowerSha256 -Path $configurationPath
    }

    if ($ProfileId -in @('lab-widescreen-16x10', 'lab-widescreen-cas-16x10')) {
        $widescreenComponent = Get-LockedComponent `
            -Sources $sources `
            -Id 'psobb-widescreen-local-evaluation'
        $sourceIni = Join-Path $layout.LocalLab 'overlays\psobb-widescreen-1.0.2\patches\pso_widescreen.ini'
        $sourceIni = Assert-LockedArtifact `
            -Path $sourceIni `
            -Component $widescreenComponent `
            -MemberPath 'patches/pso_widescreen.ini'
        $widescreenIni = Get-Content -Raw -LiteralPath $sourceIni
        foreach ($setting in @(
            @('VideoEnable', '0'),
            @('NoVignette', '0'),
            @('IntegerScale', '0'),
            @('BootPosterEnabled', '0')
        )) {
            $widescreenIni = Set-FlatConfigurationValue `
                -Text $widescreenIni `
                -Key $setting[0] `
                -Value $setting[1]
        }
        # Root and plugins co-location both loaded the ASI but left it dormant.
        # Keep the single ASI in UAL's plugins scan path while placing the INI
        # at the mod release's documented patches path. The docs do not state
        # a cfg path, so this matrix candidate keeps launcher output at root.
        $patchesPath = Join-Path $stagingClient 'patches'
        New-Item -ItemType Directory -Path $patchesPath -Force | Out-Null
        $widescreenIniPath = 'patches/pso_widescreen.ini'
        $widescreenIniFullPath = Join-Path $stagingClient 'patches\pso_widescreen.ini'
        [System.IO.File]::WriteAllText(
            $widescreenIniFullPath,
            $widescreenIni,
            [System.Text.UTF8Encoding]::new($false))
        $windowedValue = if ($WindowMode -eq 'Borderless') { 2 } else { 1 }
        $widescreenConfiguration = @(
            "Width=$renderWidth",
            "Height=$renderHeight",
            ('HUDScale={0:0.00}' -f $HudScale),
            "Windowed=$windowedValue"
        ) -join "`r`n"
        $widescreenConfigurationPath = 'widescreen.cfg'
        $widescreenConfigurationFullPath = Join-Path $stagingClient 'widescreen.cfg'
        [System.IO.File]::WriteAllText(
            $widescreenConfigurationFullPath,
            $widescreenConfiguration + "`r`n",
            [System.Text.UTF8Encoding]::new($false))
        $widescreenIniHash = Get-LowerSha256 -Path $widescreenIniFullPath
        $widescreenConfigurationHash = Get-LowerSha256 -Path $widescreenConfigurationFullPath
    }

    if ($ProfileId -in @('cleanroom-widescreen-canary', 'cas-evaluation-16x10')) {
        $enhancementComponent = Get-LockedComponent `
            -Sources $sources `
            -Id 'project-owned-psobb-enhancement'
        $enhancementIniSource = Join-Path $repositoryRoot `
            'src\PSOBB.Enhancement\PSOBB.Enhancement.ini.example'
        $enhancementIniSource = Assert-LockedArtifact `
            -Path $enhancementIniSource `
            -Component $enhancementComponent `
            -MemberPath 'src/PSOBB.Enhancement/PSOBB.Enhancement.ini.example'
        $enhancementIni = Get-Content -Raw -LiteralPath $enhancementIniSource
        foreach ($setting in @(
            @('Enabled', '1'),
            @('Width', [string]$renderWidth),
            @('Height', [string]$renderHeight),
            @('WindowMode', $WindowMode),
            @('HorizontalFov', '1'),
            @('HudMinimap', '0'),
            @('AutomaticDeviceRecreation', '0')
        )) {
            $enhancementIni = Set-FlatConfigurationValue `
                -Text $enhancementIni `
                -Key $setting[0] `
                -Value $setting[1]
        }
        $enhancementConfigurationPath = 'plugins/PSOBB.Enhancement.ini'
        $enhancementConfigurationFullPath = Join-Path $stagingClient `
            'plugins\PSOBB.Enhancement.ini'
        [System.IO.File]::WriteAllText(
            $enhancementConfigurationFullPath,
            $enhancementIni,
            [System.Text.UTF8Encoding]::new($false))
        $enhancementConfigurationHash = Get-LowerSha256 -Path $enhancementConfigurationFullPath
    }

    if ($ProfileId -in $casProfileIds) {
        $casComponent = Get-LockedComponent -Sources $sources -Id 'psobb-neutral-cas-source'
        $casSource = Join-Path $repositoryRoot 'patches\reshade\PSOBB_NeutralCAS.fx'
        $casSource = Assert-LockedArtifact -Path $casSource -Component $casComponent
        $casShaderPath = 'reshade-shaders/Shaders/PSOBB_NeutralCAS.fx'
        $casShaderFullPath = Join-Path $stagingClient `
            'reshade-shaders\Shaders\PSOBB_NeutralCAS.fx'
        New-Item -ItemType Directory -Path (Split-Path -Parent $casShaderFullPath) -Force | Out-Null
        Copy-Item -LiteralPath $casSource -Destination $casShaderFullPath -Force

        $reshadeConfigurationPath = 'ReShade.ini'
        $reshadeConfigurationFullPath = Join-Path $stagingClient 'ReShade.ini'
        $reshadeConfiguration = @(
            '[GENERAL]',
            'EffectSearchPaths=.\reshade-shaders\Shaders',
            'IntermediateCachePath=.\reshade-shaders\Cache',
            'NoDebugInfo=1',
            'PerformanceMode=1',
            'PreprocessorDefinitions=',
            'PresetPath=.\PSOBB-NeutralCAS-Preset.ini',
            'SkipLoadingDisabledEffects=1',
            'TextureSearchPaths=.\reshade-shaders\Textures',
            '',
            '[INPUT]',
            'ForceShortcutModifiers=1',
            'KeyScreenshot=121,0,0,0',
            '',
            '[OVERLAY]',
            'TutorialProgress=4',
            '',
            '[SCREENSHOT]',
            'ClearAlpha=1',
            'FileFormat=1',
            'FileNaming=%AppName% %Date% %Time%_%TimeMS%',
            'JPEGQuality=90',
            'PostSaveCommand=',
            'PostSaveCommandArguments="%TargetPath%"',
            'PostSaveCommandHideWindow=0',
            'PostSaveCommandWorkingDirectory=.\',
            'SaveBeforeShot=1',
            'SaveOverlayShot=0',
            'SavePath=.\',
            'SavePresetFile=0',
            'SoundPath='
        ) -join "`r`n"
        [System.IO.File]::WriteAllText(
            $reshadeConfigurationFullPath,
            $reshadeConfiguration + "`r`n",
            [System.Text.UTF8Encoding]::new($false))

        # ReShade normalizes ReShade.ini during its first launch. Preserve a
        # separate immutable template so post-launch validation can compare
        # the normalized runtime file against an exact trusted source without
        # weakening the module, search-path, effect, or strength allowlists.
        $reshadeTemplatePath = 'PSOBB-ReShade-Template.ini'
        $reshadeTemplateFullPath = Join-Path $stagingClient $reshadeTemplatePath
        [System.IO.File]::WriteAllText(
            $reshadeTemplateFullPath,
            $reshadeConfiguration + "`r`n",
            [System.Text.UTF8Encoding]::new($false))

        $reshadePresetPath = 'PSOBB-NeutralCAS-Preset.ini'
        $reshadePresetFullPath = Join-Path $stagingClient 'PSOBB-NeutralCAS-Preset.ini'
        $reshadePreset = @(
            'PreprocessorDefinitions=',
            'Techniques=PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx',
            'TechniqueSorting=PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx',
            '',
            '[PSOBB_NeutralCAS.fx]',
            ('PSOBB_CAS_Strength={0:F6}' -f [double]$CasStrength)
        ) -join "`r`n"
        [System.IO.File]::WriteAllText(
            $reshadePresetFullPath,
            $reshadePreset + "`r`n",
            [System.Text.UTF8Encoding]::new($false))

        $casShaderHash = Get-LowerSha256 -Path $casShaderFullPath
        $reshadeConfigurationHash = Get-LowerSha256 -Path $reshadeConfigurationFullPath
        $reshadeTemplateHash = Get-LowerSha256 -Path $reshadeTemplateFullPath
        $reshadePresetHash = Get-LowerSha256 -Path $reshadePresetFullPath
    }

    $materializedProfile = [ordered]@{
        schemaVersion = 6
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
        channel = 'local-lab'
        profileId = $ProfileId
        renderer = if ([string]$profileDeclaration.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') {
            'DgVoodooD3D11'
        } elseif ($ProfileId -eq 'dxvk-canary') {
            'DxvkVulkan'
        } else {
            'D3D8To9'
        }
        outputApi = [string]$profileDeclaration.renderer.outputApi
        baseExecutableSha256 = $identity.Sha256
        configurationSha256 = $configurationHash
        widescreenConfigurationPath = $widescreenConfigurationPath
        widescreenConfigurationSha256 = $widescreenConfigurationHash
        widescreenIniPath = $widescreenIniPath
        widescreenIniSha256 = $widescreenIniHash
        enhancementConfigurationPath = $enhancementConfigurationPath
        enhancementConfigurationSha256 = $enhancementConfigurationHash
        reshadeConfigurationPath = $reshadeConfigurationPath
        reshadeConfigurationSha256 = $reshadeConfigurationHash
        reshadeTemplatePath = $reshadeTemplatePath
        reshadeTemplateSha256 = $reshadeTemplateHash
        reshadePresetPath = $reshadePresetPath
        reshadePresetSha256 = $reshadePresetHash
        casShaderPath = $casShaderPath
        casShaderSha256 = $casShaderHash
        casStrength = if ($ProfileId -in $casProfileIds) { [double]$CasStrength } else { $null }
        desktopWidth = [int]$profileDeclaration.display.output.width
        desktopHeight = [int]$profileDeclaration.display.output.height
        renderWidth = $renderWidth
        renderHeight = $renderHeight
        aspectPolicy = [string]$profileDeclaration.display.aspectPolicy
        defaultWindowMode = $WindowMode
        presentationOwner = if ($null -ne $profileDeclaration.display.PSObject.Properties['presentationOwner']) {
            [string]$profileDeclaration.display.PSObject.Properties['presentationOwner'].Value
        } else {
            'lifecycle'
        }
        resizableClientWidth = 1600
        resizableClientHeight = 1000
        scalingFilter = if ([string]$profileDeclaration.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') {
            $ScalingFilter
        } else {
            'renderer-controlled'
        }
        msaa = $Msaa
        hudScale = if ($ProfileId -in @('lab-widescreen-16x10', 'lab-widescreen-cas-16x10')) {
            $HudScale
        } else {
            $null
        }
        watermarkEnabled = $false
        redistributionClass = [string]$profileDeclaration.distributionClass
        rollbackProfileId = [string]$profileDeclaration.rollbackProfileId
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $stagingClient 'client-profile.json'),
        ($materializedProfile | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false))

    $validationLayout = $layout.PSObject.Copy()
    $validationLayout.LocalLab = $stagingLab
    Assert-PSOBBLocalLabClientRuntimeContract -Layout $validationLayout | Out-Null

    New-Item -ItemType Directory -Path (Split-Path -Parent $targetClient), $snapshotRoot -Force | Out-Null
    Assert-PSOBBNoRunningClients -Layout $layout | Out-Null
    if (Test-Path -LiteralPath $targetClient) {
        if (Test-Path -LiteralPath $snapshotPath) {
            throw "Refusing to overwrite an existing last-known-good snapshot: $snapshotPath"
        }
        Move-Item -LiteralPath $targetClient -Destination $snapshotPath
        $previousMoved = $true
    }
    Move-Item -LiteralPath $stagingClient -Destination $targetClient
    $newInstalled = $true
    Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout | Out-Null

    [pscustomobject]@{
        Materialized = $true
        ProfileId = $ProfileId
        ClientPath = $targetClient
        RenderWidth = $renderWidth
        RenderHeight = $renderHeight
        WindowMode = $WindowMode
        ScalingFilter = if ([string]$profileDeclaration.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') {
            $ScalingFilter
        } else {
            $null
        }
        Msaa = $Msaa
        CasStrength = if ($ProfileId -in $casProfileIds) { [double]$CasStrength } else { $null }
        BaseExecutableSha256 = $identity.Sha256
        ConfigurationSha256 = $configurationHash
        PreviousSnapshot = if ($previousMoved) { $snapshotPath } else { $null }
    }
} catch {
    if ($newInstalled -and (Test-Path -LiteralPath $targetClient)) {
        Move-Item -LiteralPath $targetClient -Destination $rejectedPath
    }
    if ($previousMoved -and -not (Test-Path -LiteralPath $targetClient) -and
        (Test-Path -LiteralPath $snapshotPath)) {
        Move-Item -LiteralPath $snapshotPath -Destination $targetClient
    }
    throw
} finally {
    if (Test-Path -LiteralPath $stagingLab) {
        $safeStaging = Assert-PathWithinRoot -Path $stagingLab -Root $layout.Root
        Remove-Item -LiteralPath $safeStaging -Recurse -Force
    }
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
