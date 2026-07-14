[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repositoryRoot 'scripts\New-PSOBBGraphicsLabRuntime.ps1'
$source = Get-Content -Raw -LiteralPath $scriptPath
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

Add-Result 'materializer exposes only declared LocalLab profiles' (
    $source -match "'lab-widescreen-16x10',[\s\r\n]+\s*'lab-widescreen-cas-16x10',[\s\r\n]+\s*'cleanroom-widescreen-canary',[\s\r\n]+\s*'cas-evaluation-16x10',[\s\r\n]+\s*'dxvk-canary',[\s\r\n]+\s*'d3d8to9-canary'" ) `
    'stable and canary release trees cannot be selected'
Add-Result 'materializer validates immutable base manifest' (
    $source -match 'Test-PSOBBDirectoryManifest' -and
    $source -match 'Assert-PSOBBApprovedClientExecutable') `
    'base tree and executable identity are checked before overlays'
Add-Result 'materializer validates locked graphics artifacts' (
    $source -match 'Assert-LockedArtifact' -and
    $source -match 'Get-LowerSha256') `
    'every selected binary is size and SHA-256 checked'
Add-Result 'materializer stages before atomic swap' (
    $source -match "\.staging-" -and
    $source -match 'Assert-PSOBBLocalLabClientRuntimeContract -Layout \$validationLayout' -and
    $source -match 'Move-Item -LiteralPath \$stagingClient -Destination \$targetClient') `
    'the complete profile is validated outside the live runtime first'
Add-Result 'materializer restores previous runtime on failure' (
    $source -match "\.rejected-" -and
    $source -match 'Move-Item -LiteralPath \$snapshotPath -Destination \$targetClient') `
    'failed final validation cannot strand the previous profile'
Add-Result 'materializer serializes client changes' (
    $source -match 'Enter-PSOBBClientOperationLock' -and
    $source -match 'Assert-PSOBBNoRunningClients') `
    'concurrent or active-client mutation fails closed'
Add-Result 'materializer refuses active local asset and module compositions' (
    $source -match 'Assert-NoActiveLocalAssetComposition' -and
    $source -match "PSObject\.Properties\['localAssetOverlay'\]" -and
    $source -match "PSObject\.Properties\['localModules'\]" -and
    $source -match 'Set-PSOBBAshenbubsHDClientActivation\.ps1 -Action Rollback first' -and
    $source -notmatch "ValidateSet\([\s\S]*?'lab-widescreen-hd-16x10'") `
    'private HD activation must be explicitly rolled back and is never a clean-materializer target'

$temporaryClient = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-GraphicsMaterializer-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $temporaryClient -Force | Out-Null
    . $scriptPath
    $profilePath = Join-Path $temporaryClient 'client-profile.json'
    [System.IO.File]::WriteAllText(
        $profilePath,
        '{"profileId":"lab-widescreen-16x10"}',
        [System.Text.UTF8Encoding]::new($false))
    $cleanAccepted = $true
    try {
        Assert-NoActiveLocalAssetComposition -ClientRoot $temporaryClient
    } catch {
        $cleanAccepted = $false
    }
    Add-Result 'clean profile passes local composition preflight' $cleanAccepted `
        'ordinary LocalLab profile replacement remains available'

    [System.IO.File]::WriteAllText(
        $profilePath,
        '{"profileId":"lab-widescreen-hd-16x10","localAssetOverlay":{"componentId":"fixture"}}',
        [System.Text.UTF8Encoding]::new($false))
    $overlayRejected = $false
    try {
        Assert-NoActiveLocalAssetComposition -ClientRoot $temporaryClient
    } catch {
        $overlayRejected = $_.Exception.Message -match 'Action Rollback first'
    }
    Add-Result 'active localAssetOverlay fails preflight' $overlayRejected `
        'explicit transactional rollback is required before replacement'

    [System.IO.File]::WriteAllText(
        $profilePath,
        '{"profileId":"lab-widescreen-hd-16x10","localModules":[{"componentId":"fixture"}]}',
        [System.Text.UTF8Encoding]::new($false))
    $moduleRejected = $false
    try {
        Assert-NoActiveLocalAssetComposition -ClientRoot $temporaryClient
    } catch {
        $moduleRejected = $_.Exception.Message -match 'Action Rollback first'
    }
    Add-Result 'active localModules fails preflight' $moduleRejected `
        'clean materialization cannot discard a module-backed private composition'
} finally {
    if (Test-Path -LiteralPath $temporaryClient) {
        Remove-Item -LiteralPath $temporaryClient -Recurse -Force
    }
}
Add-Result 'widescreen experiment is source-faithful by default' (
    $source -match "@\('VideoEnable', '0'\)" -and
    $source -match "@\('NoVignette', '0'\)" -and
    $source -match "@\('IntegerScale', '0'\)" -and
    $source -match "@\('BootPosterEnabled', '0'\)") `
    'videos, vignette removal, integer scaling, and boot poster are disabled'
Add-Result 'widescreen black-box candidate uses one loader-coincident layout' (
    $source -match "widescreenIniPath = 'patches/pso_widescreen.ini'" -and
    $source -match "widescreenConfigurationPath = 'widescreen.cfg'" -and
    $source -notmatch "stagingClient 'pso_widescreen.ini'" -and
    $source -notmatch "stagingClient 'plugins\\pso_widescreen.ini'") `
    'the single ASI remains loader-visible while its INI follows the release layout and cfg remains at root'
Add-Result 'widescreen companion files are hash-bound to the profile' (
    $source -match "MemberPath 'patches/pso_widescreen.ini'" -and
    $source -match 'widescreenConfigurationSha256 = \$widescreenConfigurationHash' -and
    $source -match 'widescreenIniSha256 = \$widescreenIniHash') `
    'runtime validation can detect stale or edited local-only configuration'
Add-Result 'watermark is always disabled' (
    $source -match "@\('DirectX', 'dgVoodooWatermark', 'false'\)" -and
    $source -match 'watermarkEnabled = \$false') `
    'configuration and profile agree'
Add-Result 'MSAA is isolated from supersampling' (
    $source -match 'MSAA experiments are intentionally limited to native 2560x1600 rendering') `
    '3840x2400 cannot be combined with MSAA'
Add-Result 'clean-room profile uses exact project artifact and fail-closed configuration' (
    $source -match "RuntimeArtifactPath = 'PSOBB.Enhancement.asi'" -and
    $source -match "enhancementConfigurationPath = 'plugins/PSOBB.Enhancement.ini'" -and
    $source -match "@\('HudMinimap', '0'\)" -and
    $source -match "@\('AutomaticDeviceRecreation', '0'\)") `
    'the ignored build artifact is digest-bound and unimplemented capability gates remain disabled'
Add-Result 'clean-room profile has no implicit post-process layer' (
    $source -match "ProfileId -in @\('cleanroom-widescreen-canary', 'cas-evaluation-16x10'\)" -and
    $source -match "casProfileIds = @\('lab-widescreen-cas-16x10', 'cas-evaluation-16x10'\)" ) `
    'ReShade materialization is confined to the explicit CAS profile branch'
Add-Result 'CAS strength is explicit and limited to three candidates' (
    $source -match "ValidateSet\('0.15', '0.25', '0.35'\)" -and
    $source -match 'CasStrength must explicitly select 0.15, 0.25, or 0.35') `
    'CAS cannot silently select or accept an unreviewed strength'
Add-Result 'CAS profile imports only standard ReShade and the project shader' (
    $source -match "reshade-6.7.3-standard\\dxgi.dll" -and
    $source -match "reshadeTemplatePath = 'PSOBB-ReShade-Template.ini'" -and
    $source -match 'reshadeTemplateSha256 = \$reshadeTemplateHash' -and
    $source -match "casShaderPath = 'reshade-shaders/Shaders/PSOBB_NeutralCAS.fx'" -and
    $source -match 'Techniques=PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx' -and
    $source -match 'TechniqueSorting=PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx') `
    'one dxgi layer, one effect source, and one enabled technique are generated'
Add-Result 'CAS capture is pinned to lossless post-effect PNG without tutorial overlay' (
    $source -match 'KeyScreenshot=121,0,0,0' -and
    $source -match 'TutorialProgress=4' -and
    $source -match 'FileFormat=1' -and
    $source -match 'SaveBeforeShot=1' -and
    $source -match 'SaveOverlayShot=0') `
    'F10 writes pixel-aligned pre-CAS and post-CAS PNGs while the tutorial and overlay stay out of evidence'
Add-Result 'reference-layout CAS and clean-room CAS are distinct materializations' (
    $source -match "ProfileId -in @\('lab-widescreen-16x10', 'lab-widescreen-cas-16x10'\)" -and
    $source -match "ProfileId -in @\('cleanroom-widescreen-canary', 'cas-evaluation-16x10'\)") `
    'the proven local widescreen reference is not represented as the partial clean-room enhancement'
Add-Result 'credentials are absent from the materializer interface' (
    $source -notmatch '(?i)password|credential|username') `
    'graphics materialization has no authentication inputs'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) graphics-lab materialization test(s) failed"
}
Write-Output "Graphics-lab materialization tests passed: $($results.Count)/$($results.Count)"
