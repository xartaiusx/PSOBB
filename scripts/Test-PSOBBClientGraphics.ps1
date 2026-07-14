[CmdletBinding()]
param(
    [ValidateSet('Stable', 'Canary')]
    [string]$Channel = 'Stable',
    [ValidateSet('', 'Native', 'DgVoodooD3D11', 'DgVoodooD3D12')]
    [string]$ExpectedRenderer = '',
    [ValidateSet('', 'Compatibility', 'HighFidelity2560x1600', 'Ultra3840x2880')]
    [string]$ExpectedGraphicsPreset = '',
    [ValidateSet('', 'Borderless', 'Resizable')]
    [string]$ExpectedWindowMode = '',
    [switch]$RequireRunning,
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$lock = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'config\sources.lock.json') |
    ConvertFrom-Json -Depth 20
$clientRoot = if ($Channel -eq 'Stable') {
    $layout.Client
} else {
    Join-Path $layout.Canary 'runtime\client'
}
$clientRoot = Assert-PathWithinRoot -Path $clientRoot -Root $layout.Root
$profilePath = Join-Path $clientRoot 'client-profile.json'
$clientExecutable = Join-Path $clientRoot 'Psobb.exe'
$results = [System.Collections.Generic.List[object]]::new()

function Add-GraphicsCheck {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Get-IniValue {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key
    )

    $sectionMatch = [regex]::Match(
        $Text,
        '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*\r?\n(?<body>.*?)(?=^\[|\z)')
    if (-not $sectionMatch.Success) {
        return $null
    }
    $keyMatches = [regex]::Matches(
        $sectionMatch.Groups['body'].Value,
        '(?m)^[ \t]*' + [regex]::Escape($Key) + '[ \t]*=[ \t]*(?<value>[^;\r\n]*?)[ \t]*\r?$')
    if ($keyMatches.Count -ne 1) {
        return $null
    }
    $keyMatches[0].Groups['value'].Value.Trim()
}

$clientLocks = @($lock.components | Where-Object id -eq 'tethealla-59nl-english')
$rendererLocks = @($lock.components | Where-Object id -eq 'dgvoodoo2-x86-d3d8')
$clientMembers = if ($clientLocks.Count -eq 1) {
    @($clientLocks[0].members | Where-Object path -eq 'Psobb.exe')
} else { @() }
$wrapperMembers = if ($rendererLocks.Count -eq 1) {
    @($rendererLocks[0].members | Where-Object path -eq 'MS/x86/D3D8.dll')
} else { @() }
$configurationMembers = if ($rendererLocks.Count -eq 1) {
    @($rendererLocks[0].members | Where-Object path -eq 'dgVoodoo.conf')
} else { @() }
$clientArchive = Join-Path $layout.Archives 'TethVer12513_English.zip'
$baseManifestPath = $layout.BaseClientManifest

Add-GraphicsCheck 'graphics lock contract' (
    ($clientMembers.Count -eq 1) -and
    ($wrapperMembers.Count -eq 1) -and
    ($configurationMembers.Count -eq 1)) 'client, wrapper, and source configuration each have one lock member'

$baseManifest = $null
$baseManifestTrusted = $false
try {
    $archiveItem = Get-Item -LiteralPath $clientArchive
    $baseManifest = Get-Content -Raw -LiteralPath $baseManifestPath | ConvertFrom-Json -Depth 20
    $archiveFiles = @(Get-PSOBBZipContentManifest -Path $clientArchive)
    $baseManifestTrusted =
        ($archiveItem.Length -eq [long]$clientLocks[0].size) -and
        ((Get-LowerSha256 $clientArchive) -eq [string]$clientLocks[0].sha256) -and
        ([int]$baseManifest.schemaVersion -eq 1) -and
        ([string]$baseManifest.sourceArchiveSha256).Equals(
            [string]$clientLocks[0].sha256,
            [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-PSOBBManifestEntriesEqual -Left $archiveFiles -Right @($baseManifest.files))
} catch { }
Add-GraphicsCheck 'base-client manifest derives from locked archive' $baseManifestTrusted $baseManifestPath

$reparsePoint = Get-ChildItem -LiteralPath $clientRoot -Force -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue |
    Select-Object -First 1
Add-GraphicsCheck 'client tree has no reparse points' ($null -eq $reparsePoint) $(
    if ($reparsePoint) { $reparsePoint.FullName } else { $clientRoot })

$clientExact = $false
if (($clientMembers.Count -eq 1) -and (Test-Path -LiteralPath $clientExecutable -PathType Leaf)) {
    $clientItem = Get-Item -LiteralPath $clientExecutable
    $clientExact = ($clientItem.Length -eq [long]$clientMembers[0].size) -and
        ((Get-LowerSha256 $clientExecutable) -eq [string]$clientMembers[0].sha256)
}
Add-GraphicsCheck 'immutable-base executable preserved' $clientExact $clientExecutable

$profile = $null
try {
    $profile = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -Depth 10
} catch { }
$profileSchemaValid = ($null -ne $profile) -and ([int]$profile.schemaVersion -in @(1, 2, 3, 4, 5))
Add-GraphicsCheck 'client graphics profile is readable' $profileSchemaValid $profilePath
if (-not $profileSchemaValid) {
    $results | Format-Table -AutoSize
    throw 'The client graphics profile is missing or invalid'
}

$renderer = [string]$profile.renderer
if (-not [string]::IsNullOrEmpty($ExpectedRenderer)) {
    Add-GraphicsCheck 'expected renderer selected' ($renderer -ceq $ExpectedRenderer) "expected=$ExpectedRenderer; actual=$renderer"
}
$channelValid = if ([int]$profile.schemaVersion -eq 1) {
    ($Channel -eq 'Stable') -and ($renderer -eq 'Native')
} else {
    [string]$profile.channel -ceq $Channel.ToLowerInvariant()
}
Add-GraphicsCheck 'profile channel contract' $channelValid "channel=$Channel; schema=$($profile.schemaVersion)"
Add-GraphicsCheck 'profile base hash contract' (
    ([string]$profile.baseExecutableSha256).Equals(
        [string]$clientMembers[0].sha256,
        [System.StringComparison]::OrdinalIgnoreCase)) 'profile is tied to the approved 59NL executable'

$graphicsPreset = if ($renderer -eq 'Native') {
    'Native'
} elseif ([int]$profile.schemaVersion -ge 3) {
    [string]$profile.graphicsPreset
} else {
    'Compatibility'
}
if (-not [string]::IsNullOrEmpty($ExpectedGraphicsPreset)) {
    Add-GraphicsCheck 'expected graphics preset selected' (
        $graphicsPreset -ceq $ExpectedGraphicsPreset) "expected=$ExpectedGraphicsPreset; actual=$graphicsPreset"
}
$windowMode = if (($renderer -ne 'Native') -and ([int]$profile.schemaVersion -ge 4)) {
    [string]$profile.defaultWindowMode
} else {
    'ApplicationControlled'
}
if ((-not $RequireRunning.IsPresent) -and
    -not [string]::IsNullOrEmpty($ExpectedWindowMode)) {
    Add-GraphicsCheck 'expected default window mode selected' (
        $windowMode -ceq $ExpectedWindowMode) "expected=$ExpectedWindowMode; actual=$windowMode"
}
if ($graphicsPreset -eq 'Ultra3840x2880') {
    Add-GraphicsCheck 'ultra supersampling metadata' (
        ([int]$profile.renderWidth -eq 3840) -and
        ([int]$profile.renderHeight -eq 2880) -and
        ([int]$profile.desktopWidth -eq 2560) -and
        ([int]$profile.desktopHeight -eq 1600) -and
        ([string]$profile.aspectPolicy -ceq 'preserve-4x3') -and
        ([string]$profile.resamplingFilter -ceq 'lanczos-3') -and
        ([string]$profile.textureFilterPolicy -ceq 'anisotropic-16-preserve-point-sampled') -and
        ([string]$profile.edgeSmoothingPolicy -ceq 'supersampling-only') -and
        ($profile.bilinear2DOperations -eq $false)) (
            "render=$($profile.renderWidth)x$($profile.renderHeight); " +
            "desktop=$($profile.desktopWidth)x$($profile.desktopHeight); " +
            "aspect=$($profile.aspectPolicy); edge=$($profile.edgeSmoothingPolicy)")
}

$runtimeTreeExact = $baseManifestTrusted
$runtimeTreeDetail = [System.Collections.Generic.List[string]]::new()
if ($baseManifestTrusted) {
    $actualFiles = @(Get-ChildItem -LiteralPath $clientRoot -File -Force -Recurse | ForEach-Object {
        [pscustomobject]@{
            path = [System.IO.Path]::GetRelativePath($clientRoot, $_.FullName).Replace('\', '/')
            item = $_
        }
    })
    $actualByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $actualFiles) {
        if ($actualByPath.ContainsKey([string]$entry.path)) {
            $runtimeTreeExact = $false
            $runtimeTreeDetail.Add("duplicate:$($entry.path)")
        } else {
            $actualByPath.Add([string]$entry.path, $entry)
        }
    }
    $baseByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($baseManifest.files)) {
        $baseByPath.Add([string]$entry.path, $entry)
        if (([string]$entry.path -match '^GameGuard/[^/]+\.erl$') -or
            ([string]$entry.path -match '^log/(spec|error|generic)\.log$')) {
            # The legacy GameGuard bootstrap renames and rewrites its .erl state
            # while the client is running. These files are data, not Windows
            # loadable modules; the executable/DLL inventory remains exact.
            continue
        }
        if (-not $actualByPath.ContainsKey([string]$entry.path)) {
            $runtimeTreeExact = $false
            $runtimeTreeDetail.Add("missing:$($entry.path)")
            continue
        }
        $actual = $actualByPath[[string]$entry.path].item
        $actualHash = try { Get-LowerSha256 $actual.FullName } catch { '' }
        if (($actual.Length -ne [long]$entry.size) -or
            -not $actualHash.Equals(
                [string]$entry.sha256,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            $runtimeTreeExact = $false
            $runtimeTreeDetail.Add("modified:$($entry.path)")
        }
    }
    $allowedGeneratedFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @(
        'client-profile.json',
        'GameGuard/1npgg.erl',
        'GameGuard/1npgl.erl',
        'GameGuard/1npgm.erl',
        'GameGuard/1npgmup.erl',
        'GameGuard/1npsc.erl')) {
        [void]$allowedGeneratedFiles.Add($path)
    }
    if ($renderer -in @('DgVoodooD3D11', 'DgVoodooD3D12')) {
        [void]$allowedGeneratedFiles.Add('d3d8.dll')
        [void]$allowedGeneratedFiles.Add('dgVoodoo.conf')
    }
    foreach ($entry in $actualFiles) {
        $path = [string]$entry.path
        if ($baseByPath.ContainsKey($path) -or $allowedGeneratedFiles.Contains($path) -or
            $path -match '^log/(chat\d{8}\.txt|(spec|error|generic)\.log)$') {
            continue
        }
        $runtimeTreeExact = $false
        $runtimeTreeDetail.Add("unexpected:$path")
    }
}
Add-GraphicsCheck 'complete disposable client inventory' $runtimeTreeExact $(
    if ($runtimeTreeDetail.Count -eq 0) { 'base exact; only approved overlay/runtime files present' }
    else { ($runtimeTreeDetail | Select-Object -First 8) -join ', ' })

$proxyNames = @('d3d8.dll', 'd3d9.dll', 'ddraw.dll', 'dxgi.dll')
$presentProxies = @($proxyNames | Where-Object {
    Test-Path -LiteralPath (Join-Path $clientRoot $_) -PathType Leaf
})
$configurationPath = Join-Path $clientRoot 'dgVoodoo.conf'

if ($renderer -eq 'Native') {
    Add-GraphicsCheck 'native profile has no renderer proxy' ($presentProxies.Count -eq 0) ($presentProxies -join ', ')
    Add-GraphicsCheck 'native profile has no dgVoodoo configuration' (
        -not (Test-Path -LiteralPath $configurationPath)) $configurationPath
    Add-GraphicsCheck 'native profile records no wrapper hash' (
        [string]::IsNullOrEmpty([string]$profile.wrapperSha256)) 'wrapperSha256=null'
} elseif ($renderer -in @('DgVoodooD3D11', 'DgVoodooD3D12')) {
    $wrapperPath = Join-Path $clientRoot 'd3d8.dll'
    $wrapperExact = $false
    if (($wrapperMembers.Count -eq 1) -and (Test-Path -LiteralPath $wrapperPath -PathType Leaf)) {
        $wrapperItem = Get-Item -LiteralPath $wrapperPath
        $wrapperExact = ($wrapperItem.Length -eq [long]$wrapperMembers[0].size) -and
            ((Get-LowerSha256 $wrapperPath) -eq [string]$wrapperMembers[0].sha256)
    }
    Add-GraphicsCheck 'exact approved x86 D3D8 wrapper' $wrapperExact $wrapperPath
    Add-GraphicsCheck 'exactly one renderer proxy chain' (
        ($presentProxies.Count -eq 1) -and ($presentProxies[0] -ieq 'd3d8.dll')) ($presentProxies -join ', ')
    Add-GraphicsCheck 'profile wrapper hash contract' (
        ([string]$profile.wrapperSha256).Equals(
            [string]$wrapperMembers[0].sha256,
            [System.StringComparison]::OrdinalIgnoreCase)) 'profile wrapper matches sources.lock.json'

    $configurationText = if (Test-Path -LiteralPath $configurationPath -PathType Leaf) {
        Get-Content -Raw -LiteralPath $configurationPath
    } else { '' }
    $configurationHash = if ([string]::IsNullOrEmpty($configurationText)) {
        ''
    } else {
        Get-LowerSha256 $configurationPath
    }
    Add-GraphicsCheck 'profile source configuration contract' (
        ([string]$profile.sourceConfigurationSha256).Equals(
            [string]$configurationMembers[0].sha256,
            [System.StringComparison]::OrdinalIgnoreCase)) 'source dgVoodoo.conf is locked before transformation'
    $sourceConfigurationPath = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\dgVoodoo.conf'
    $sourceConfigurationTrusted = $false
    $expectedConfiguration = $null
    try {
        $sourceConfigurationItem = Get-Item -LiteralPath $sourceConfigurationPath
        $sourceConfigurationTrusted =
            ($sourceConfigurationItem.Length -eq [long]$configurationMembers[0].size) -and
            ((Get-LowerSha256 $sourceConfigurationPath) -eq [string]$configurationMembers[0].sha256)
        if ($sourceConfigurationTrusted -and
            ($graphicsPreset -in @('Compatibility', 'HighFidelity2560x1600', 'Ultra3840x2880'))) {
            $expectedConfiguration = Get-PSOBBDgVoodooConfiguration `
                -SourceText (Get-Content -Raw -LiteralPath $sourceConfigurationPath) `
                -Renderer $renderer `
                -GraphicsPreset $graphicsPreset
        }
    } catch { }
    Add-GraphicsCheck 'locked source configuration is intact' $sourceConfigurationTrusted $sourceConfigurationPath
    Add-GraphicsCheck 'transformed configuration is deterministically derived' (
        ($null -ne $expectedConfiguration) -and
        ($configurationText -ceq $expectedConfiguration)) $configurationHash
    Add-GraphicsCheck 'profile transformed hash is informationally consistent' (
        -not [string]::IsNullOrEmpty($configurationHash) -and
        $configurationHash.Equals(
            [string]$profile.configurationSha256,
            [System.StringComparison]::OrdinalIgnoreCase)) $configurationHash

    $expectedOutputApi = if ($renderer -eq 'DgVoodooD3D11') {
        'd3d11_fl11_0'
    } else {
        'd3d12_fl11_0'
    }
    Add-GraphicsCheck 'exact renderer backend' (
        (Get-IniValue -Text $configurationText -Section 'General' -Key 'OutputAPI') -ceq $expectedOutputApi) $expectedOutputApi
    $requiredSettings = if ($graphicsPreset -in @('HighFidelity2560x1600', 'Ultra3840x2880')) {
        $expectedResolution = if ($graphicsPreset -eq 'Ultra3840x2880') { '3840x2880' } else { 'max' }
        $expectedAntialiasing = if ($graphicsPreset -eq 'Ultra3840x2880') { 'off' } else { '8x' }
        [ordered]@{
            'General/ScalingMode' = 'stretched_ar'
            'General/FullScreenMode' = 'false'
            'General/KeepWindowAspectRatio' = 'true'
            'General/CenterAppWindow' = 'true'
            'GeneralExt/DesktopResolution' = '2560x1600'
            'GeneralExt/Resampling' = 'lanczos-3'
            'GeneralExt/WindowedAttributes' = 'borderless, fullscreensize'
            'DirectX/Filtering' = '16'
            'DirectX/Mipmapping' = 'appdriven'
            'DirectX/KeepFilterIfPointSampled' = 'true'
            'DirectX/Resolution' = $expectedResolution
            'DirectX/Antialiasing' = $expectedAntialiasing
            'DirectX/AppControlledScreenMode' = 'false'
            'DirectX/Bilinear2DOperations' = 'false'
            'DirectX/ForceVerticalSync' = 'false'
            'DirectX/dgVoodooWatermark' = 'false'
        }
    } else {
        [ordered]@{
            'General/ScalingMode' = 'unspecified'
            'DirectX/Filtering' = 'appdriven'
            'DirectX/Mipmapping' = 'appdriven'
            'DirectX/Resolution' = 'unforced'
            'DirectX/Antialiasing' = 'appdriven'
            'DirectX/dgVoodooWatermark' = 'false'
        }
    }
    foreach ($setting in $requiredSettings.GetEnumerator()) {
        $parts = $setting.Key.Split('/', 2)
        $actual = Get-IniValue -Text $configurationText -Section $parts[0] -Key $parts[1]
        Add-GraphicsCheck "approved preset $($setting.Key)" ($actual -ceq $setting.Value) "actual=$actual"
    }
} else {
    Add-GraphicsCheck 'supported renderer profile' $false $renderer
}

$running = @(Get-PSOBBProcessesAtExactPath -Name 'Psobb' -ExpectedPath $clientExecutable)
Add-GraphicsCheck 'running-state requirement' (
    -not $RequireRunning.IsPresent -or ($running.Count -eq 1)) "matchingProcesses=$($running.Count)"
if ($running.Count -gt 1) {
    Add-GraphicsCheck 'single matching client process' $false ($running.Id -join ', ')
} elseif ($running.Count -eq 1) {
    try {
        $loadedModules = @($running[0].Modules)
        $loadedD3D8 = @($loadedModules | Where-Object ModuleName -ieq 'd3d8.dll')
        if ($renderer -eq 'Native') {
            $localWrapperPath = Join-Path $clientRoot 'd3d8.dll'
            Add-GraphicsCheck 'running Native client uses no local D3D8 proxy' (
                ($loadedD3D8.Count -eq 1) -and
                -not ([System.IO.Path]::GetFullPath($loadedD3D8[0].FileName)).Equals(
                    [System.IO.Path]::GetFullPath($localWrapperPath),
                    [System.StringComparison]::OrdinalIgnoreCase)) $(
                    if ($loadedD3D8.Count -eq 1) { $loadedD3D8[0].FileName } else { 'not loaded exactly once' })
        } else {
            $expectedLoadedWrapper = [System.IO.Path]::GetFullPath((Join-Path $clientRoot 'd3d8.dll'))
            Add-GraphicsCheck 'running client loaded the approved local wrapper' (
                ($loadedD3D8.Count -eq 1) -and
                ([System.IO.Path]::GetFullPath($loadedD3D8[0].FileName)).Equals(
                    $expectedLoadedWrapper,
                    [System.StringComparison]::OrdinalIgnoreCase)) $(
                    if ($loadedD3D8.Count -eq 1) { $loadedD3D8[0].FileName } else { 'not loaded exactly once' })
            $backendModule = if ($renderer -eq 'DgVoodooD3D11') { 'd3d11.dll' } else { 'd3d12.dll' }
            $loadedBackend = @($loadedModules | Where-Object ModuleName -ieq $backendModule)
            Add-GraphicsCheck 'running client loaded the selected modern backend' (
                $loadedBackend.Count -eq 1) $backendModule
            if ($graphicsPreset -in @('HighFidelity2560x1600', 'Ultra3840x2880')) {
                $windowPresentation = Get-PSOBBClientWindowPresentation -Process $running[0]
                $runningWindowMode = if ([string]::IsNullOrEmpty($ExpectedWindowMode)) {
                    $windowMode
                } else {
                    $ExpectedWindowMode
                }
                if ($runningWindowMode -eq 'Borderless') {
                    Add-GraphicsCheck 'running client uses exact 2560x1600 window bounds' (
                        ($windowPresentation.X -eq 0) -and
                        ($windowPresentation.Y -eq 0) -and
                        ($windowPresentation.Width -eq 2560) -and
                        ($windowPresentation.Height -eq 1600)) (
                            "x=$($windowPresentation.X); y=$($windowPresentation.Y); " +
                            "width=$($windowPresentation.Width); height=$($windowPresentation.Height)")
                    Add-GraphicsCheck 'running client uses borderless window style' (
                        ($windowPresentation.Style -band 0x00C40000L) -eq 0) (
                            'style=0x{0:X}' -f $windowPresentation.Style)
                } elseif ($runningWindowMode -eq 'Resizable') {
                    Add-GraphicsCheck 'running client uses 1600x1200 movable client area' (
                        ($windowPresentation.ClientWidth -eq 1600) -and
                        ($windowPresentation.ClientHeight -eq 1200)) (
                            "clientWidth=$($windowPresentation.ClientWidth); " +
                            "clientHeight=$($windowPresentation.ClientHeight)")
                    Add-GraphicsCheck 'running client uses captioned resizable window style' (
                        ($windowPresentation.Style -band 0x00C40000L) -eq 0x00C40000L) (
                            'style=0x{0:X}' -f $windowPresentation.Style)
                } else {
                    Add-GraphicsCheck 'running managed window mode' $false $runningWindowMode
                }
            }
        }
    } catch {
        Add-GraphicsCheck 'running renderer module inspection' $false $_.Exception.Message
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) client graphics check(s) failed"
}
[pscustomobject]@{
    Suite = 'ClientGraphics'
    Channel = $Channel
    Renderer = $renderer
    GraphicsPreset = $graphicsPreset
    WindowMode = $windowMode
    Passed = $results.Count
    Failed = 0
    Running = ($running.Count -eq 1)
}
