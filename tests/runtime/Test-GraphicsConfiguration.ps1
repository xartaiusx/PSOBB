[CmdletBinding()]
param()

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

$sourceConfiguration = @'
[General]
OutputAPI = bestavailable
ScalingMode = unspecified
FullScreenMode = true
KeepWindowAspectRatio = false
CenterAppWindow = false

[GeneralExt]
DesktopResolution =
Resampling = bilinear
WindowedAttributes =

[DirectX]
Filtering = appdriven
Mipmapping = appdriven
KeepFilterIfPointSampled = false
Resolution = unforced
Antialiasing = appdriven
AppControlledScreenMode = true
Bilinear2DOperations = true
ForceVerticalSync = true
dgVoodooWatermark = true
'@

function Get-TestIniValue {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key
    )

    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\]\s*\r?\n' +
        '(?<body>.*?)(?=^\[|\z)'
    $sectionMatch = [regex]::Match($Text, $sectionPattern)
    if (-not $sectionMatch.Success) {
        throw "Missing test INI section: $Section"
    }
    $keyPattern = '(?m)^\s*' + [regex]::Escape($Key) + '\s*=\s*(?<value>[^;\r\n]*)'
    $matches = [regex]::Matches($sectionMatch.Groups['body'].Value, $keyPattern)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one test INI value for $Section/$Key"
    }
    $matches[0].Groups['value'].Value.Trim()
}

$configuration = Get-PSOBBDgVoodooConfiguration `
    -SourceText $sourceConfiguration `
    -Renderer DgVoodooD3D11 `
    -GraphicsPreset Ultra3840x2880
$secondPass = Get-PSOBBDgVoodooConfiguration `
    -SourceText $sourceConfiguration `
    -Renderer DgVoodooD3D11 `
    -GraphicsPreset Ultra3840x2880

$expected = [ordered]@{
    'General/OutputAPI' = 'd3d11_fl11_0'
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
    'DirectX/Resolution' = '3840x2880'
    'DirectX/Antialiasing' = 'off'
    'DirectX/AppControlledScreenMode' = 'false'
    'DirectX/Bilinear2DOperations' = 'false'
    'DirectX/ForceVerticalSync' = 'false'
    'DirectX/dgVoodooWatermark' = 'false'
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($setting in $expected.GetEnumerator()) {
    $parts = $setting.Key.Split('/', 2)
    $actual = Get-TestIniValue -Text $configuration -Section $parts[0] -Key $parts[1]
    $results.Add([pscustomobject]@{
        Name = $setting.Key
        Passed = $actual -ceq $setting.Value
        Detail = "expected=$($setting.Value); actual=$actual"
    })
}
$results.Add([pscustomobject]@{
    Name = 'deterministic transform'
    Passed = $configuration -ceq $secondPass
    Detail = 'identical source and profile produce identical bytes'
})

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) graphics-configuration test(s) failed"
}
[pscustomobject]@{ Suite = 'GraphicsConfiguration'; Passed = $results.Count; Failed = 0 }
