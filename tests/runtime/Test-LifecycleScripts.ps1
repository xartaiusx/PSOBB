[CmdletBinding()]
param([string]$RuntimeRoot)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

$scriptNames = @(
    'Stop-PSOBBClient.ps1',
    'Start-PSOBBSession.ps1',
    'Stop-PSOBBSession.ps1',
    'Install-PSOBBDesktopShortcuts.ps1',
    'Set-PSOBBRememberedLogin.ps1',
    'Set-PSOBBLocalVisualAsset.ps1',
    'Start-PSOBBClient.ps1',
    'Stop-PSOBB.ps1'
)
foreach ($scriptName in $scriptNames) {
    $tokens = $null
    $parseErrors = $null
    $scriptPath = Join-Path $repositoryRoot ('scripts\' + $scriptName)
    [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors) | Out-Null
    Add-Result "$scriptName parses cleanly" ($parseErrors.Count -eq 0) "$($parseErrors.Count) parser error(s)"
}

$identity = Get-PSOBBApprovedClientIdentity
$stableClient = Get-PSOBBClientExecutablePath -Layout $layout -Channel Stable
$stableApproved = $false
try {
    $stableIdentity = Assert-PSOBBApprovedClientExecutable -Path $stableClient
    $stableApproved = ($stableIdentity.Sha256 -eq $identity.Sha256) -and
        ($stableIdentity.Size -eq $identity.Size)
} catch { }
Add-Result 'stable client exact hash is approved' $stableApproved $stableClient

$canaryClient = Get-PSOBBClientExecutablePath -Layout $layout -Channel Canary
$canaryApproved = $false
try {
    $canaryIdentity = Assert-PSOBBApprovedClientExecutable -Path $canaryClient
    $canaryApproved = ($canaryIdentity.Sha256 -eq $identity.Sha256) -and
        ($canaryIdentity.Size -eq $identity.Size)
} catch { }
Add-Result 'canary client exact hash is approved' $canaryApproved $canaryClient

$localLabClient = Get-PSOBBClientExecutablePath -Layout $layout -Channel LocalLab
$expectedLocalLabClient = Join-Path $layout.Root 'local-lab\runtime\client\Psobb.exe'
Add-Result 'LocalLab client path is distinct and exact' (
    $localLabClient.Equals(
        $expectedLocalLabClient,
        [System.StringComparison]::OrdinalIgnoreCase)) $localLabClient

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-LifecycleTests-' + [Guid]::NewGuid().ToString('N'))
$fixtureLayout = Get-PSOBBLayout -RuntimeRoot (Join-Path $temporaryRoot 'runtime')
$shortcutRoot = Join-Path $temporaryRoot 'desktop'
try {
    New-Item -ItemType Directory -Path $fixtureLayout.Root -Force | Out-Null
    Initialize-PSOBBRuntimeMarker -Layout $fixtureLayout | Out-Null

    $missingLocalLabRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $missingLocalLabRejected = $_.Exception.Message -match 'LocalLab|approved PSOBB client'
    }
    Add-Result 'missing LocalLab runtime fails closed' $missingLocalLabRejected 'no runtime or process was created'

    $fixtureLocalLabRoot = Join-Path $fixtureLayout.LocalLab 'runtime\client'
    $fixturePlugins = Join-Path $fixtureLocalLabRoot 'plugins'
    New-Item -ItemType Directory -Path $fixturePlugins, `
        (Join-Path $fixtureLocalLabRoot 'data') -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $fixtureLayout.BaseClientManifest) `
        -Force | Out-Null
    [System.IO.File]::WriteAllText(
        $fixtureLayout.BaseClientManifest,
        ([ordered]@{
            schemaVersion = 1
            sourceArchiveSha256 = ('0' * 64)
            generatedAtUtc = [DateTime]::UtcNow.ToString('o')
            files = @()
        } | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath $stableClient -Destination (Join-Path $fixtureLocalLabRoot 'Psobb.exe')
    Copy-Item -LiteralPath (
        Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\MS\x86\D3D8.dll') `
        -Destination (Join-Path $fixtureLocalLabRoot 'd3d8.dll')
    Copy-Item -LiteralPath (
        Join-Path $layout.LocalLab 'overlays\ultimate-asi-loader-9.7.2\dinput8.dll') `
        -Destination (Join-Path $fixtureLocalLabRoot 'dinput8.dll')
    Copy-Item -LiteralPath (
        Join-Path $layout.LocalLab 'overlays\psobb-widescreen-1.0.2\patches\pso_widescreen.asi') `
        -Destination (Join-Path $fixturePlugins 'pso_widescreen.asi')
    $fixturePatches = Join-Path $fixtureLocalLabRoot 'patches'
    New-Item -ItemType Directory -Path $fixturePatches -Force | Out-Null
    $fixtureWidescreenIniPath = Join-Path $fixturePatches 'pso_widescreen.ini'
    [System.IO.File]::WriteAllText(
        $fixtureWidescreenIniPath,
        "VideoEnable=0`r`nNoVignette=0`r`nIntegerScale=0`r`nBootPosterEnabled=0`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureWidescreenConfigurationPath = Join-Path $fixtureLocalLabRoot 'widescreen.cfg'
    [System.IO.File]::WriteAllText(
        $fixtureWidescreenConfigurationPath,
        "Width=2560`r`nHeight=1600`r`nHUDScale=1.25`r`nWindowed=2`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureConfigurationPath = Join-Path $fixtureLocalLabRoot 'dgVoodoo.conf'
    $fixtureConfiguration = Get-Content -Raw -LiteralPath (
        Join-Path $layout.Canary 'runtime\client\dgVoodoo.conf')
    $fixtureConfiguration = Set-PSOBBIniValue `
        -Text $fixtureConfiguration `
        -Section 'DirectX' `
        -Key 'Resolution' `
        -Value '2560x1600'
    $fixtureConfiguration = Set-PSOBBIniValue `
        -Text $fixtureConfiguration `
        -Section 'DirectX' `
        -Key 'VRAM' `
        -Value '256'
    $fixtureConfiguration = Set-PSOBBIniValue `
        -Text $fixtureConfiguration `
        -Section 'DirectX' `
        -Key 'ForceVerticalSync' `
        -Value 'false'
    [System.IO.File]::WriteAllText(
        $fixtureConfigurationPath,
        $fixtureConfiguration,
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfilePath = Join-Path $fixtureLocalLabRoot 'client-profile.json'
    $fixtureProfile = [ordered]@{
        schemaVersion = 7
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
        channel = 'local-lab'
        profileId = 'lab-widescreen-16x10'
        renderer = 'DgVoodooD3D11'
        outputApi = 'd3d11_fl11_0'
        baseExecutableSha256 = $identity.Sha256
        configurationSha256 = Get-LowerSha256 $fixtureConfigurationPath
        widescreenConfigurationPath = 'widescreen.cfg'
        widescreenConfigurationSha256 = Get-LowerSha256 $fixtureWidescreenConfigurationPath
        widescreenIniPath = 'patches/pso_widescreen.ini'
        widescreenIniSha256 = Get-LowerSha256 $fixtureWidescreenIniPath
        enhancementConfigurationPath = $null
        enhancementConfigurationSha256 = $null
        desktopWidth = 2560
        desktopHeight = 1600
        renderWidth = 2560
        renderHeight = 1600
        aspectPolicy = 'expand-horizontal-16x10'
        defaultWindowMode = 'Borderless'
        presentationOwner = 'client-patch'
        resizableClientWidth = 1600
        resizableClientHeight = 1000
        virtualVramMb = 256
        vsyncOwner = 'none'
        nativeGraphics = [ordered]@{
            presetId = 'high-end'
            graphicCtrlDwords = @(0, 0, 0, 0, 1, 1, 1, 0, 0)
            graphicCtrlSha256 = '302f04ac1917b0eaecef147a99f7cada007b8bb8cc9ac1d9fd16b1a47d72e8a4'
            advancedEffectsPolicy = 'enabled'
            pixelFogPolicy = 'pixel'
            lowResolutionTexturesPolicy = 'disabled'
            frameSkipPolicy = 'disabled'
        }
        hudScale = 1.25
        watermarkEnabled = $false
        redistributionClass = 'local-only'
    }
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $validatedLocalLab = Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout
    Add-Result 'materialized LocalLab contract validates exact modules' (
        [string]$validatedLocalLab.profileId -ceq 'lab-widescreen-16x10') 'profile, render target, wrapper chain, and hashes are exact'

    $protectedFixturePaths = @(
        'Psobb.exe',
        'd3d8.dll',
        'dinput8.dll',
        'dgVoodoo.conf',
        'patches\pso_widescreen.ini',
        'plugins\pso_widescreen.asi'
    )
    $protectedFixtureHashes = [ordered]@{}
    foreach ($relativePath in $protectedFixturePaths) {
        $protectedFixtureHashes[$relativePath] = Get-LowerSha256 `
            -Path (Join-Path $fixtureLocalLabRoot $relativePath)
    }
    $fixtureProfile['windowModeMutationSentinel'] = [ordered]@{
        activation = 'unchanged'
        localModules = @('unchanged-module')
    }
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $resizableResult = Set-PSOBBLocalLabClientWindowMode `
        -Layout $fixtureLayout -WindowMode Resizable
    $resizableProfile = Get-Content -Raw -LiteralPath $fixtureProfilePath |
        ConvertFrom-Json -Depth 20 -DateKind String
    $protectedFixtureUnchanged = @($protectedFixtureHashes.GetEnumerator() |
        Where-Object {
            (Get-LowerSha256 -Path (Join-Path $fixtureLocalLabRoot $_.Key)) -cne
                [string]$_.Value
        }).Count -eq 0
    Add-Result 'LocalLab client-patch mode transaction materializes resizable' (
        $resizableResult.Changed -and
        [string]$resizableResult.Profile.defaultWindowMode -ceq 'Resizable' -and
        [string]$resizableProfile.defaultWindowMode -ceq 'Resizable' -and
        [string]$resizableProfile.widescreenConfigurationSha256 -ceq
            (Get-LowerSha256 -Path $fixtureWidescreenConfigurationPath) -and
        (Get-Content -Raw -LiteralPath $fixtureWidescreenConfigurationPath) -match
            '(?m)^Windowed=1\r?$') `
        'profile mode and exact widescreen configuration hash switch together before launch'
    Add-Result 'LocalLab mode transaction preserves protected runtime state' (
        $protectedFixtureUnchanged -and
        [string]$resizableProfile.configurationSha256 -ceq
            (Get-LowerSha256 -Path $fixtureConfigurationPath) -and
        [string]$resizableProfile.windowModeMutationSentinel.activation -ceq
            'unchanged' -and
        @($resizableProfile.windowModeMutationSentinel.localModules).Count -eq 1 -and
        [string]$resizableProfile.windowModeMutationSentinel.localModules[0] -ceq
            'unchanged-module') `
        'assets, modules, renderer configuration, and unrelated profile declarations are immutable'

    $borderlessResult = Set-PSOBBLocalLabClientWindowMode `
        -Layout $fixtureLayout -WindowMode Borderless
    $borderlessProfile = Get-Content -Raw -LiteralPath $fixtureProfilePath |
        ConvertFrom-Json -Depth 20 -DateKind String
    Add-Result 'LocalLab client-patch mode transaction restores borderless' (
        $borderlessResult.Changed -and
        [string]$borderlessProfile.defaultWindowMode -ceq 'Borderless' -and
        [string]$borderlessProfile.widescreenConfigurationSha256 -ceq
            (Get-LowerSha256 -Path $fixtureWidescreenConfigurationPath) -and
        (Get-Content -Raw -LiteralPath $fixtureWidescreenConfigurationPath) -match
            '(?m)^Windowed=2\r?$') `
        'the same guarded transaction supports the default exact-panel presentation'

    $noOpResult = Set-PSOBBLocalLabClientWindowMode `
        -Layout $fixtureLayout -WindowMode Borderless
    Add-Result 'LocalLab matching window mode is a no-op' (
        -not $noOpResult.Changed -and
        [string]$noOpResult.Profile.defaultWindowMode -ceq 'Borderless') `
        'repeated play and shortcut operations do not rewrite a matching contract'

    $oversizedReferencePresentation = [pscustomobject]@{
        Style = 0x14C40000L
        ClientWidth = 2560
        ClientHeight = 1581
    }
    $referenceCorrectionPolicy =
        Get-PSOBBClientPatchResizablePresentationPolicy `
            -Profile $borderlessProfile `
            -Presentation $oversizedReferencePresentation
    Add-Result 'settled local reference requests one initial resize correction' (
        $referenceCorrectionPolicy -ceq 'CorrectLocalReference') `
        'the exact pso_widescreen component has a movable frame but not its declared 1600x1000 client area'

    $exactReferencePresentation = [pscustomobject]@{
        Style = 0x14CF0000L
        ClientWidth = 1600
        ClientHeight = 1000
    }
    $alreadyCorrectPolicy = Get-PSOBBClientPatchResizablePresentationPolicy `
        -Profile $borderlessProfile `
        -Presentation $exactReferencePresentation
    Add-Result 'already-correct client-patch presentation remains observation-only' (
        $alreadyCorrectPolicy -ceq 'Observe') `
        'no lifecycle style or size mutation competes with a correct client-owned window'

    $futureEnhancementProfile = ConvertFrom-Json -InputObject (
        $borderlessProfile | ConvertTo-Json -Depth 20 -Compress) `
        -Depth 20 -DateKind String
    $futureEnhancementProfile.profileId = 'cleanroom-widescreen-canary'
    $futureEnhancementProfile.widescreenConfigurationPath = $null
    $futureEnhancementProfile.widescreenIniPath = $null
    $futureEnhancementProfile.enhancementConfigurationPath =
        'plugins/PSOBB.Enhancement.ini'
    $futureEnhancementPolicy = Get-PSOBBClientPatchResizablePresentationPolicy `
        -Profile $futureEnhancementProfile `
        -Presentation $oversizedReferencePresentation
    Add-Result 'future enhancement mismatch remains observation-only and fails closed' (
        $futureEnhancementPolicy -ceq 'Reject') `
        'the lifecycle correction is not available to the project enhancement or another component'

    $unframedReferencePresentation = [pscustomobject]@{
        Style = 0x10000000L
        ClientWidth = 2560
        ClientHeight = 1600
    }
    $unframedPolicy = Get-PSOBBClientPatchResizablePresentationPolicy `
        -Profile $borderlessProfile `
        -Presentation $unframedReferencePresentation
    Add-Result 'reference correction requires an existing movable frame' (
        $unframedPolicy -ceq 'Reject') `
        'lifecycle does not invent a resizable mode when Windowed=1 or the module did not supply it'

    $fixtureProfile.profileId = 'undeclared-local-profile'
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $undeclaredLocalLabRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $undeclaredLocalLabRejected = $_.Exception.Message -match 'not declared exactly once'
    }
    Add-Result 'undeclared LocalLab profile fails closed' $undeclaredLocalLabRejected 'catalog profile ID is mandatory'
    $fixtureProfile.profileId = 'lab-widescreen-16x10'
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))

    Copy-Item -LiteralPath (Join-Path $fixtureLocalLabRoot 'd3d8.dll') `
        -Destination (Join-Path $fixtureLocalLabRoot 'dxgi.dll')
    $competingProxyRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $competingProxyRejected = $_.Exception.Message -match 'loadable-module inventory'
    }
    Add-Result 'unexpected LocalLab proxy fails closed' $competingProxyRejected 'exactly one declared renderer chain is permitted'
    Remove-Item -LiteralPath (Join-Path $fixtureLocalLabRoot 'dxgi.dll') -Force

    Remove-Item -LiteralPath (
        Join-Path $fixturePlugins 'pso_widescreen.asi') -Force
    Remove-Item -LiteralPath $fixtureWidescreenIniPath -Force
    Remove-Item -LiteralPath $fixtureWidescreenConfigurationPath -Force
    $enhancementAsiPath = Join-Path $fixturePlugins 'PSOBB.Enhancement.asi'
    Copy-Item -LiteralPath (
        Join-Path $repositoryRoot 'src\PSOBB.Enhancement\bin\build-x86\Release\PSOBB.Enhancement.asi') `
        -Destination $enhancementAsiPath
    $enhancementIniPath = Join-Path $fixturePlugins 'PSOBB.Enhancement.ini'
    [System.IO.File]::WriteAllText(
        $enhancementIniPath,
        "[Enhancement]`r`nEnabled=1`r`nWidth=2560`r`nHeight=1600`r`nWindowMode=Borderless`r`nHorizontalFov=1`r`nHudMinimap=0`r`nAutomaticDeviceRecreation=0`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfile['profileId'] = 'cleanroom-widescreen-canary'
    $fixtureProfile['widescreenConfigurationPath'] = $null
    $fixtureProfile['widescreenConfigurationSha256'] = $null
    $fixtureProfile['widescreenIniPath'] = $null
    $fixtureProfile['widescreenIniSha256'] = $null
    $fixtureProfile['enhancementConfigurationPath'] = 'plugins/PSOBB.Enhancement.ini'
    $fixtureProfile['enhancementConfigurationSha256'] = Get-LowerSha256 $enhancementIniPath
    $fixtureProfile['reshadeConfigurationPath'] = $null
    $fixtureProfile['reshadeConfigurationSha256'] = $null
    $fixtureProfile['reshadePresetPath'] = $null
    $fixtureProfile['reshadePresetSha256'] = $null
    $fixtureProfile['casShaderPath'] = $null
    $fixtureProfile['casShaderSha256'] = $null
    $fixtureProfile['casStrength'] = $null
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $validatedCleanroom = Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout
    Add-Result 'clean-room LocalLab contract validates the partial project layer' (
        [string]$validatedCleanroom.profileId -ceq 'cleanroom-widescreen-canary') `
        'exact ASI plus fail-closed resolution, FOV, HUD, and resize configuration'

    $tamperedEnhancement = Get-Content -Raw -LiteralPath $enhancementIniPath
    $tamperedEnhancement = $tamperedEnhancement.Replace('HudMinimap=0', 'HudMinimap=1')
    [System.IO.File]::WriteAllText(
        $enhancementIniPath,
        $tamperedEnhancement,
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfile['enhancementConfigurationSha256'] = Get-LowerSha256 $enhancementIniPath
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $unsupportedEnhancementRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $unsupportedEnhancementRejected = $_.Exception.Message -match 'guarded feature contract'
    }
    Add-Result 'clean-room unsupported HUD capability fails closed' (
        $unsupportedEnhancementRejected) 'a matching file hash cannot authorize an unimplemented capability'
    [System.IO.File]::WriteAllText(
        $enhancementIniPath,
        "[Enhancement]`r`nEnabled=1`r`nWidth=2560`r`nHeight=1600`r`nWindowMode=Borderless`r`nHorizontalFov=1`r`nHudMinimap=0`r`nAutomaticDeviceRecreation=0`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfile['enhancementConfigurationSha256'] = Get-LowerSha256 $enhancementIniPath

    Copy-Item -LiteralPath (
        Join-Path $layout.LocalLab 'overlays\reshade-6.7.3-standard\dxgi.dll') `
        -Destination (Join-Path $fixtureLocalLabRoot 'dxgi.dll')
    $fixtureShaderRoot = Join-Path $fixtureLocalLabRoot 'reshade-shaders\Shaders'
    New-Item -ItemType Directory -Path $fixtureShaderRoot -Force | Out-Null
    $fixtureCasShaderPath = Join-Path $fixtureShaderRoot 'PSOBB_NeutralCAS.fx'
    Copy-Item -LiteralPath (
        Join-Path $repositoryRoot 'patches\reshade\PSOBB_NeutralCAS.fx') `
        -Destination $fixtureCasShaderPath
    $fixtureReshadeIniPath = Join-Path $fixtureLocalLabRoot 'ReShade.ini'
    [System.IO.File]::WriteAllText(
        $fixtureReshadeIniPath,
        "[GENERAL]`r`nEffectSearchPaths=.\reshade-shaders\Shaders`r`nIntermediateCachePath=.\reshade-shaders\Cache`r`nNoDebugInfo=1`r`nPerformanceMode=1`r`nPreprocessorDefinitions=`r`nPresetPath=.\PSOBB-NeutralCAS-Preset.ini`r`nSkipLoadingDisabledEffects=1`r`nTextureSearchPaths=.\reshade-shaders\Textures`r`n`r`n[INPUT]`r`nForceShortcutModifiers=1`r`nKeyScreenshot=121,0,0,0`r`n`r`n[OVERLAY]`r`nTutorialProgress=4`r`n`r`n[SCREENSHOT]`r`nClearAlpha=1`r`nFileFormat=1`r`nFileNaming=%AppName% %Date% %Time%_%TimeMS%`r`nJPEGQuality=90`r`nPostSaveCommand=`r`nPostSaveCommandArguments=`"%TargetPath%`"`r`nPostSaveCommandHideWindow=0`r`nPostSaveCommandWorkingDirectory=.\`r`nSaveBeforeShot=1`r`nSaveOverlayShot=0`r`nSavePath=.\`r`nSavePresetFile=0`r`nSoundPath=`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureReshadeTemplatePath = Join-Path $fixtureLocalLabRoot 'PSOBB-ReShade-Template.ini'
    Copy-Item -LiteralPath $fixtureReshadeIniPath -Destination $fixtureReshadeTemplatePath
    $fixtureReshadePresetPath = Join-Path $fixtureLocalLabRoot 'PSOBB-NeutralCAS-Preset.ini'
    [System.IO.File]::WriteAllText(
        $fixtureReshadePresetPath,
        "PreprocessorDefinitions=`r`nTechniques=PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx`r`nTechniqueSorting=PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx`r`n`r`n[PSOBB_NeutralCAS.fx]`r`nPSOBB_CAS_Strength=0.150000`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfile['profileId'] = 'cas-evaluation-16x10'
    $fixtureProfile['reshadeConfigurationPath'] = 'ReShade.ini'
    $fixtureProfile['reshadeConfigurationSha256'] = Get-LowerSha256 $fixtureReshadeIniPath
    $fixtureProfile['reshadeTemplatePath'] = 'PSOBB-ReShade-Template.ini'
    $fixtureProfile['reshadeTemplateSha256'] = Get-LowerSha256 $fixtureReshadeTemplatePath
    $fixtureProfile['reshadePresetPath'] = 'PSOBB-NeutralCAS-Preset.ini'
    $fixtureProfile['reshadePresetSha256'] = Get-LowerSha256 $fixtureReshadePresetPath
    $fixtureProfile['casShaderPath'] = 'reshade-shaders/Shaders/PSOBB_NeutralCAS.fx'
    $fixtureProfile['casShaderSha256'] = Get-LowerSha256 $fixtureCasShaderPath
    $fixtureProfile['casStrength'] = 0.15
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $validatedCas = Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout
    Add-Result 'CAS LocalLab contract validates one exact effect and strength' (
        [string]$validatedCas.profileId -ceq 'cas-evaluation-16x10' -and
        [double]$validatedCas.casStrength -eq 0.15) `
        'standard dxgi, generated ReShade configuration, preset, and one shader are hash-bound'

    $fixtureNormalizedReshade = @(
        '[GENERAL]',
        'EffectSearchPaths=.\reshade-shaders\Shaders',
        ('IntermediateCachePath=' + (Join-Path (
            [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'Temp\ReShade')),
        'NoDebugInfo=1',
        'NoEffectCache=0',
        'NoReloadOnInit=0',
        'PerformanceMode=1',
        'PreprocessorDefinitions=',
        'PresetPath=.\PSOBB-NeutralCAS-Preset.ini',
        'PresetShortcutKeys=',
        'PresetShortcutPaths=',
        'PresetTransitionDuration=1000',
        'SkipLoadingDisabledEffects=1',
        'StartupPresetPath=',
        'TextureSearchPaths=.\reshade-shaders\Textures',
        '',
        '[INPUT]',
        'ForceShortcutModifiers=1',
        'InputProcessing=2',
        'KeyEffects=0,0,0,0',
        'KeyFPS=0,0,0,0',
        'KeyFrametime=0,0,0,0',
        'KeyNextPreset=0,0,0,0',
        'KeyOverlay=36,0,0,0',
        'KeyPreviousPreset=0,0,0,0',
        'KeyReload=0,0,0,0',
        'KeyScreenshot=121,0,0,0',
        '',
        '[OVERLAY]',
        'AutoSavePreset=1',
        'ClockFormat=0',
        'Docking=[Docking][Data]',
        'FPSPosition=1',
        'Language=',
        'ShowClock=0',
        'ShowForceLoadEffectsButton=1',
        'ShowFPS=2',
        'ShowFrameTime=0',
        'ShowPresetName=0',
        'ShowPresetTransitionMessage=1',
        'ShowScreenshotMessage=1',
        'TutorialProgress=4',
        'VariableListHeight=200.000000',
        'VariableListUseTabs=0',
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
        'SoundPath=',
        '',
        '[STYLE]',
        'Alpha=1.000000',
        'ChildRounding=0',
        'ColFPSText=1.000000,1.000000,0.784314,1.000000',
        'EditorFont=',
        'EditorFontSize=0.000000',
        'EditorStyleIndex=0',
        'Font=',
        'FontScale=1.500000',
        'FontSize=0.000000',
        'FPSScale=1.000000',
        'FrameRounding=0',
        'GrabRounding=0',
        'HdrOverlayBrightness=203.000000',
        'HdrOverlayOverwriteColorSpaceTo=0',
        'LatinFont=',
        'PopupRounding=0',
        'ScrollbarRounding=0',
        'StyleIndex=2',
        'TabRounding=5.000000',
        'WindowRounding=0'
    ) -join "`r`n"
    [System.IO.File]::WriteAllText(
        $fixtureReshadeIniPath,
        $fixtureNormalizedReshade + "`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $validatedNormalizedCas = Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout
    Add-Result 'CAS contract accepts only the pinned ReShade first-launch normalization' (
        [string]$validatedNormalizedCas.profileId -ceq 'cas-evaluation-16x10') `
        'the immutable template remains exact while the closed normalized field set is accepted'

    $tamperedNormalizedReshade = $fixtureNormalizedReshade.Replace(
        'EffectSearchPaths=.\reshade-shaders\Shaders',
        'EffectSearchPaths=.\reshade-shaders\Shaders;C:\Unapproved')
    [System.IO.File]::WriteAllText(
        $fixtureReshadeIniPath,
        $tamperedNormalizedReshade + "`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $normalizedPathRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $normalizedPathRejected = $_.Exception.Message -match 'GENERAL/EffectSearchPaths'
    }
    Add-Result 'CAS contract rejects a normalized ReShade search-path expansion' (
        $normalizedPathRejected) 'first-launch normalization cannot authorize another effect directory'
    [System.IO.File]::WriteAllText(
        $fixtureReshadeIniPath,
        $fixtureNormalizedReshade + "`r`n",
        [System.Text.UTF8Encoding]::new($false))

    $normalizedRejectionCases = @(
        [pscustomobject]@{
            Name = 'CAS contract rejects the legacy screenshot shortcut'
            Search = 'KeyScreenshot=121,0,0,0'
            Replacement = 'KeyScreenshot=44,0,0,0'
            ErrorPattern = 'INPUT/KeyScreenshot'
            Detail = 'lossless capture remains bound to the dedicated F10 shortcut'
        },
        [pscustomobject]@{
            Name = 'CAS contract rejects a lossy screenshot format'
            Search = 'FileFormat=1'
            Replacement = 'FileFormat=2'
            ErrorPattern = 'SCREENSHOT/FileFormat'
            Detail = 'capture evidence cannot silently switch from PNG to JPEG'
        },
        [pscustomobject]@{
            Name = 'CAS contract rejects an unpaired screenshot mode'
            Search = 'SaveBeforeShot=1'
            Replacement = 'SaveBeforeShot=0'
            ErrorPattern = 'SCREENSHOT/SaveBeforeShot'
            Detail = 'pre-CAS and post-CAS evidence remain pixel-aligned from one frame'
        },
        [pscustomobject]@{
            Name = 'CAS contract rejects an incomplete tutorial state'
            Search = 'TutorialProgress=4'
            Replacement = 'TutorialProgress=0'
            ErrorPattern = 'unapproved preset or font path'
            Detail = 'the ReShade tutorial overlay cannot return in evidence captures'
        }
    )
    foreach ($rejectionCase in $normalizedRejectionCases) {
        $tamperedNormalizedReshade = $fixtureNormalizedReshade.Replace(
            [string]$rejectionCase.Search,
            [string]$rejectionCase.Replacement)
        [System.IO.File]::WriteAllText(
            $fixtureReshadeIniPath,
            $tamperedNormalizedReshade + "`r`n",
            [System.Text.UTF8Encoding]::new($false))
        $tamperRejected = $false
        try {
            Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
        } catch {
            $tamperRejected = $_.Exception.Message -match [string]$rejectionCase.ErrorPattern
        }
        Add-Result `
            ([string]$rejectionCase.Name) `
            $tamperRejected `
            ([string]$rejectionCase.Detail)
    }
    [System.IO.File]::WriteAllText(
        $fixtureReshadeIniPath,
        $fixtureNormalizedReshade + "`r`n",
        [System.Text.UTF8Encoding]::new($false))

    $trustedPreset = Get-Content -Raw -LiteralPath $fixtureReshadePresetPath
    [System.IO.File]::WriteAllText(
        $fixtureReshadePresetPath,
        $trustedPreset + 'KeyPSOBB_NeutralCAS=36,0,0,0' + "`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfile['reshadePresetSha256'] = Get-LowerSha256 $fixtureReshadePresetPath
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $extraPresetFieldRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $extraPresetFieldRejected = $_.Exception.Message -match 'undeclared field'
    }
    Add-Result 'CAS contract rejects an added preset toggle even with a matching profile hash' (
        $extraPresetFieldRejected) 'the exact one-technique preset is derived independently from the mutable profile hash'
    [System.IO.File]::WriteAllText(
        $fixtureReshadePresetPath,
        $trustedPreset,
        [System.Text.UTF8Encoding]::new($false))
    $fixtureProfile['reshadePresetSha256'] = Get-LowerSha256 $fixtureReshadePresetPath
    [System.IO.File]::WriteAllText(
        $fixtureProfilePath,
        ($fixtureProfile | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))

    $fixtureAddonPath = Join-Path $fixtureLocalLabRoot 'unexpected.addon32'
    [System.IO.File]::WriteAllBytes($fixtureAddonPath, [byte[]](1, 2, 3))
    $addonRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $addonRejected = $_.Exception.Message -match 'loadable-module inventory'
    }
    Add-Result 'CAS profile rejects an undeclared ReShade add-on module' $addonRejected `
        'standard ReShade cannot silently gain an addon or addon32 module'
    Remove-Item -LiteralPath $fixtureAddonPath -Force

    [System.IO.File]::WriteAllText(
        (Join-Path $fixtureShaderRoot 'unexpected.fx'),
        'unexpected',
        [System.Text.UTF8Encoding]::new($false))
    $extraCasShaderRejected = $false
    try {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $fixtureLayout | Out-Null
    } catch {
        $extraCasShaderRejected = $_.Exception.Message -match 'shader inventory'
    }
    Add-Result 'CAS profile rejects an undeclared shader' $extraCasShaderRejected `
        'the local ReShade import cannot silently load a shader pack'

    $notRunning = & (Join-Path $repositoryRoot 'scripts\Stop-PSOBBClient.ps1') `
        -RuntimeRoot $fixtureLayout.Root `
        -Channel All
    Add-Result 'client stop is idempotent when no client runs' (
        (-not $notRunning.Stopped) -and
        ($notRunning.Reason -eq 'not-running') -and
        ($notRunning.ForcedCount -eq 0)) 'no PID action was attempted'

    $originalInventory = (Get-Item Function:\Get-PSOBBClientProcessRecords).ScriptBlock
    try {
        Set-Item Function:\Get-PSOBBClientProcessRecords -Value {
            @([pscustomobject]@{ Channel = 'Canary'; ProcessId = 4242 })
        }
        $clientGuarded = $false
        try {
            Assert-PSOBBNoRunningClients -Layout $fixtureLayout | Out-Null
        } catch {
            $clientGuarded = $_.Exception.Message -match 'Canary PID 4242' -and
                $_.Exception.Message -match 'Stop-PSOBBSession.ps1 -Target All'
        }
        Add-Result 'server-stop client guard fails closed' $clientGuarded 'approved client inventory blocks server shutdown'
    } finally {
        Set-Item Function:\Get-PSOBBClientProcessRecords -Value $originalInventory
    }

    New-Item -ItemType Directory -Path $shortcutRoot -Force | Out-Null
    $firstInstall = & (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1') `
        -RuntimeRoot $layout.Root `
        -ShortcutDirectory $shortcutRoot `
        -PlayChannel Canary `
        -PlayWindowMode Borderless
    $secondInstall = & (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1') `
        -RuntimeRoot $layout.Root `
        -ShortcutDirectory $shortcutRoot `
        -PlayChannel Canary `
        -PlayWindowMode Borderless
    $shortcutFiles = @(Get-ChildItem -LiteralPath $shortcutRoot -Filter '*.lnk' -File)
    Add-Result 'shortcut installation is idempotent' (
        $firstInstall.Installed -and
        $firstInstall.Changed -and
        $secondInstall.Installed -and
        (-not $secondInstall.Changed) -and
        ($shortcutFiles.Count -eq 3)) "$($shortcutFiles.Count) shortcut(s)"

    $shell = New-Object -ComObject WScript.Shell
    try {
        $startServer = $shell.CreateShortcut((Join-Path $shortcutRoot 'PSOBB Start Server.lnk'))
        $stopServer = $shell.CreateShortcut((Join-Path $shortcutRoot 'PSOBB Stop Server.lnk'))
        $play = $shell.CreateShortcut((Join-Path $shortcutRoot 'PSOBB Play.lnk'))
        $launcherPath = Join-Path $layout.Stable 'launcher\PSOBB.Launcher.exe'
        $expectedStartArguments = '--start-server --runtime-root "{0}"' -f $layout.Root
        $expectedStopArguments = '--stop-all --runtime-root "{0}"' -f $layout.Root
        $expectedPlayArguments = '--play --channel canary --profile clarity-dgvoodoo-4x3 --window-mode borderless --runtime-root "{0}"' -f $layout.Root
        $definitionsValid =
            ([string]$startServer.Arguments -ceq $expectedStartArguments) -and
            ([string]$stopServer.Arguments -ceq $expectedStopArguments) -and
            ([string]$play.Arguments -ceq $expectedPlayArguments) -and
            ([System.IO.Path]::GetFullPath([string]$startServer.TargetPath)).Equals(
                [System.IO.Path]::GetFullPath($launcherPath),
                [System.StringComparison]::OrdinalIgnoreCase) -and
            ([System.IO.Path]::GetFullPath([string]$stopServer.TargetPath)).Equals(
                [System.IO.Path]::GetFullPath($launcherPath),
                [System.StringComparison]::OrdinalIgnoreCase) -and
            ([System.IO.Path]::GetFullPath([string]$play.TargetPath)).Equals(
                [System.IO.Path]::GetFullPath($launcherPath),
                [System.StringComparison]::OrdinalIgnoreCase) -and
            -not (([string]$startServer.Arguments, [string]$stopServer.Arguments, [string]$play.Arguments) -match
                '(?i)(password|credential|username|identity|secret)')
        Add-Result 'shortcuts have exact credential-free launcher definitions' $definitionsValid $expectedPlayArguments
    } finally {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }

    $hdShortcutRoot = Join-Path $temporaryRoot 'hd-shortcuts'
    New-Item -ItemType Directory -Path $hdShortcutRoot -Force | Out-Null
    $hdInstall = & (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1') `
        -RuntimeRoot $layout.Root `
        -ShortcutDirectory $hdShortcutRoot `
        -PlayChannel LocalLab `
        -PlayProfile lab-widescreen-hd-16x10 `
        -PlayWindowMode Borderless `
        -PlayPreserveForeground
    $hdShell = New-Object -ComObject WScript.Shell
    try {
        $hdPlay = $hdShell.CreateShortcut((Join-Path $hdShortcutRoot 'PSOBB Play.lnk'))
        $expectedHdArguments = '--play --channel local-lab --profile lab-widescreen-hd-16x10 --window-mode borderless --runtime-root "{0}" --preserve-foreground' -f $layout.Root
        Add-Result 'PSOBB Play can bind the exact private LocalLab HD background profile' (
            $hdInstall.Installed -and
            [string]$hdPlay.Arguments -ceq $expectedHdArguments) $expectedHdArguments
    } finally {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($hdShell)
    }

    $casProfileRejected = $false
    try {
        & (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1') `
            -RuntimeRoot $layout.Root `
            -ShortcutDirectory $hdShortcutRoot `
            -PlayChannel LocalLab `
            -PlayProfile lab-widescreen-cas-16x10 `
            -PlayWindowMode Borderless | Out-Null
    } catch {
        $casProfileRejected = $_.Exception.Message -match
            'lab-widescreen-cas-16x10' -and $_.Exception.Message -match
            '(?i)(validation set|ValidateSet|does not belong)'
    }
    Add-Result 'evidence-only LocalLab CAS profile is rejected by shortcut input' (
        $casProfileRejected) 'CAS remains catalog/materializer evidence and is not playable'

    $profileMismatchRejected = $false
    try {
        & (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1') `
            -RuntimeRoot $layout.Root `
            -ShortcutDirectory $hdShortcutRoot `
            -PlayChannel Canary `
            -PlayProfile lab-widescreen-hd-16x10 `
            -PlayWindowMode Borderless | Out-Null
    } catch {
        $profileMismatchRejected = $_.Exception.Message -match 'not valid for the Canary channel'
    }
    Add-Result 'shortcut profile and channel mismatch fails closed' (
        $profileMismatchRejected) 'LocalLab HD cannot be launched through Canary'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$stopServerSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Stop-PSOBB.ps1')
$serverGuardWired = $stopServerSource -match 'Enter-PSOBBClientOperationLock' -and
    $stopServerSource -match 'Assert-PSOBBNoRunningClients' -and
    $stopServerSource -match 'Exit-PSOBBClientOperationLock'
Add-Result 'server stop holds the client-operation guard' $serverGuardWired 'client start cannot race server shutdown'

$startSessionSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Start-PSOBBSession.ps1')
$startServerSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Start-PSOBB.ps1')
$supervisorDetached = $startServerSource -match 'NativeSupervisorLauncher' -and
    $startServerSource -match 'CreateProcessW\(' -and
    $startServerSource -match 'false,\s*\r?\n\s*CreateNoWindow \| CreateSuspended,' -and
    $startServerSource -match 'GetProcessTimes\(' -and
    $startServerSource -match 'ResumeThread\(processInformation\.hThread\)' -and
    $startServerSource -notmatch 'RedirectStandard(?:Input|Output|Error)\s*=\s*\$true'
Add-Result 'server supervisor detaches caller capture handles' $supervisorDetached 'start returns while the hidden supervisor remains alive'
$startSessionLocked = $startSessionSource -match 'Enter-PSOBBClientOperationLock' -and
    $startSessionSource -match 'Get-PSOBBClientProcessRecords' -and
    $startSessionSource -match 'ClientOperationLockHeld' -and
    $startSessionSource -match 'Exit-PSOBBClientOperationLock'
Add-Result 'session start is one guarded lifecycle transaction' $startSessionLocked 'server readiness and client start share the client-operation lock'

$startClientSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Start-PSOBBClient.ps1')
$credentialPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1'
$credentialSource = Get-Content -Raw -LiteralPath $credentialPath
$credentialTokens = $null
$credentialParseErrors = $null
$credentialAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $credentialPath,
    [ref]$credentialTokens,
    [ref]$credentialParseErrors)
$clientProcessFunctions = @($credentialAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Start-PSOBBClientProcess'
}, $true))
$clientProcessSource = if ($clientProcessFunctions.Count -eq 1) {
    $clientProcessFunctions[0].Extent.Text
} else {
    ''
}
$registryInitializationSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Initialize-PSOBBClientRegistry.ps1')
$rememberedLoginSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Set-PSOBBRememberedLogin.ps1')
$resetClientSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Reset-PSOBBClientRuntime.ps1')
Add-Result 'central client process helper validates login persistence before process creation' (
    $credentialParseErrors.Count -eq 0 -and
    $clientProcessFunctions.Count -eq 1 -and
    $clientProcessSource -match
        'Assert-PSOBBClientLoginRegistry\s*\|\s*Out-Null\s*\r?\n\s*\$processId\s*=\s*\[PSOBBClientProcessLauncher\]::Start\(') `
    'launcher, shortcut, session, and credential-relaunch starts preserve the native login policy without reading secrets'
Add-Result 'registry initialization creates manual authentication only when missing' (
    $registryInitializationSource -match
        "names -cnotcontains 'ACCOUNT_CHECK'[\s\S]*?-PropertyType DWord -Value 0" -and
    $registryInitializationSource -match 'ExistingLoginValuesPreserved\s*=') `
    'existing saved-login values are preserved while a fresh key starts with manual authentication'
Add-Result 'registry initialization writes a protected GRAPHICCTRL-only backup' (
    $registryInitializationSource -match 'New-PSOBBClientGraphicCtrlBackup' -and
    $registryInitializationSource -match 'BackupContainsCredentials\s*=\s*\$false' -and
    $registryInitializationSource -notmatch 'reg\.exe\s+export' -and
    $registryInitializationSource -notmatch 'BackupMayContainPriorCredentials') `
    'no whole-key or credential-bearing registry export remains'
Add-Result 'client launch applies profile-owned native graphics before process creation' (
    $startClientSource -match
        'Set-PSOBBClientNativeGraphics[\s\S]*?Start-PSOBBClientProcess' -and
    $startClientSource -match 'Restore-PSOBBClientGraphicCtrlBackup' -and
    $startClientSource -match 'GraphicCtrlSha256') `
    'GRAPHICCTRL is hash verified and rolls back when client startup fails'
Add-Result 'client and session report verified startup latency' (
    $startClientSource -match 'startupStopwatch' -and
    $startClientSource -match 'StartupElapsedMilliseconds' -and
    $startClientSource -match 'client-startup' -and
    $startClientSource -match 'StartupReceiptSha256' -and
    $startSessionSource -match 'ClientStartupElapsedMilliseconds' -and
    $startSessionSource -match 'ClientStartupReceiptSha256') `
    'hash-bound load-time evidence ends only after the verified window and presentation settle'
Add-Result 'client startup receipts receive explicit protected DACLs' (
    $startClientSource -match
        '\$receiptRoot\s*=\s*Assert-PathWithinRoot\s+-Path\s+\$receiptRoot\s+-Root\s+\$layout\.Root[\s\S]*?CreateDirectory\(\$receiptRoot\)[\s\S]*?\$receiptRoot\s*=\s*Assert-PathWithinRoot\s+-Path\s+\$receiptRoot\s+-Root\s+\$layout\.Root' -and
    $startClientSource -match
        'Set-PSOBBProtectedAcl\s+-Path\s+\$receiptRoot' -and
    $startClientSource -match
        'Set-PSOBBProtectedAcl\s+-Path\s+\$temporaryReceipt' -and
    $startClientSource -match
        'Move-Item\s+-LiteralPath\s+\$temporaryReceipt\s+-Destination\s+\$receiptPath[\s\S]*?Set-PSOBBProtectedAcl\s+-Path\s+\$receiptPath') `
    'receipt directory, staged file, and final file are protected before evidence is returned'
Add-Result 'stable and canary rebuilds materialize catalog-owned native graphics' (
    $resetClientSource -match "'safe-native-4x3'" -and
    $resetClientSource -match "'clarity-dgvoodoo-4x3'" -and
    $resetClientSource -match 'Assert-PSOBBNativeGraphicsContract' -and
    $resetClientSource -match 'nativeGraphics\s*=\s*\$materializedNativeGraphics') `
    'all ordinary launch channels carry the same exact vector-and-digest contract'
Add-Result 'admin relaunch returns through the guarded client lifecycle' (
    $credentialSource -match "Start-PSOBBClient\.ps1'\)" -and
    $credentialSource -match '-Channel Stable' -and
    $credentialSource -match '-WindowMode ProfileDefault') `
    'credential relaunch cannot bypass profile-owned GRAPHICCTRL application'
Add-Result 'remembered-login changes share the lifecycle lock and reject a live client' (
    $rememberedLoginSource -match 'Enter-PSOBBClientOperationLock\s+-Layout\s+\$layout' -and
    $rememberedLoginSource -match 'Get-PSOBBClientProcessRecords\s+-Layout\s+\$layout\s+-Channel\s+All' -and
    $rememberedLoginSource -match '\$running\.Count\s+-gt\s+0' -and
    $rememberedLoginSource -match 'Exit-PSOBBClientOperationLock\s+-Mutex\s+\$clientOperationMutex') `
    'enable and disable cannot race a running approved client or another lifecycle operation'
Add-Result 'client-patch presentation has one reference-only initial correction' (
    $startClientSource -match "presentationOwner -eq 'client-patch'" -and
    $startClientSource -match 'Set-PSOBBLocalLabClientWindowMode' -and
    $startClientSource -match 'Get-PSOBBClientPatchResizablePresentationPolicy' -and
    $startClientSource -match "resizablePolicy -ceq 'CorrectLocalReference'" -and
    $startClientSource -match 'Set-PSOBBClientResizablePresentation' -and
    $startClientSource -match 'Get-PSOBBClientWindowPresentation' -and
    $startClientSource -match 'client-patch-owned window did not present') `
    'the stopped contract is materialized first; only a mismatched settled pso_widescreen frame receives its declared initial client area'
$localLabExposedSafely = $startClientSource -match "ValidateSet\('Stable', 'Canary', 'LocalLab'\)" -and
    $startClientSource -match 'Assert-PSOBBLocalLabClientRuntimeContract' -and
    $startSessionSource -match "ValidateSet\('Stable', 'Canary', 'LocalLab'\)" -and
    (Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1')) -match
        "ValidateSet\('Stable', 'Canary', 'LocalLab'\)"
Add-Result 'LocalLab start is exposed only through its runtime guard' $localLabExposedSafely 'Stable and Canary behavior remains unchanged'

$stopSessionSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Stop-PSOBBSession.ps1')
$stopSessionLocked = $stopSessionSource -match 'Enter-PSOBBClientOperationLock' -and
    $stopSessionSource -match "'Stop-PSOBBClient.ps1'" -and
    $stopSessionSource -match "'Stop-PSOBB.ps1'" -and
    $stopSessionSource -match 'ClientOperationLockHeld' -and
    $stopSessionSource -match 'Exit-PSOBBClientOperationLock'
Add-Result 'stop-all is one guarded lifecycle transaction' $stopSessionLocked 'a concurrent client start cannot enter between client and server shutdown'

$stopClientSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'scripts\Stop-PSOBBClient.ps1')
$safeStopWired = $stopClientSource -match 'CloseMainWindow' -and
    $stopClientSource -match 'Get-RevalidatedPSOBBClientProcess' -and
    $stopClientSource -match 'Assert-PSOBBApprovedClientExecutable' -and
    $stopClientSource -match 'Stop-Process -Id \$process.Id -Force'
Add-Result 'client force fallback is identity-revalidated' $safeStopWired 'normal close precedes explicit validated force'
Add-Result 'client stop preserves saved credential fields' (
    $stopClientSource -notmatch 'Set-PSOBBClientManualLogin|Clear-PSOBBClientSavedCredentials') `
    'normal and idempotent shutdown paths do not mutate the native login cache'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) lifecycle-script test(s) failed"
}
[pscustomobject]@{ Suite = 'LifecycleScripts'; Passed = $results.Count; Failed = 0 }
