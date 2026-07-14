[CmdletBinding()]
param(
    [string]$ProfilesPath,
    [string]$EvidencePath,
    [string]$SourcesLockPath,
    [switch]$Quiet
)

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProfilesPath)) {
    $ProfilesPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
}
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $repositoryRoot 'config\graphics-evidence.json'
}
if ([string]::IsNullOrWhiteSpace($SourcesLockPath)) {
    $SourcesLockPath = Join-Path $repositoryRoot 'config\sources.lock.json'
}

$profileSchemaPath = Join-Path $repositoryRoot 'config\schemas\graphics-profiles.schema.json'
$evidenceSchemaPath = Join-Path $repositoryRoot 'config\schemas\graphics-evidence.schema.json'
$results = [System.Collections.Generic.List[object]]::new()

function Add-GraphicsProfileCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail
    )

    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function Test-Sha256Text {
    param([AllowNull()][string]$Value)

    -not [string]::IsNullOrEmpty($Value) -and $Value -cmatch '^[a-f0-9]{64}$'
}

function Test-RelativeModulePath {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value) -or
        [System.IO.Path]::IsPathRooted($Value) -or
        $Value.Contains(':', [System.StringComparison]::Ordinal) -or
        $Value -match '(^|[\\/])\.\.([\\/]|$)') {
        return $false
    }
    $extension = [System.IO.Path]::GetExtension($Value)
    $extension -cin @('.dll', '.asi')
}

function Test-AspectRatio {
    param(
        [Parameter(Mandatory)][object]$Resolution,
        [Parameter(Mandatory)][double]$Expected
    )

    if (($null -eq $Resolution) -or ([double]$Resolution.height -le 0)) {
        return $false
    }
    [Math]::Abs(([double]$Resolution.width / [double]$Resolution.height) - $Expected) -le 0.001
}

function Test-ResolutionSelected {
    param(
        [AllowNull()][object]$Selected,
        [Parameter(Mandatory)][object[]]$Candidates
    )

    if ($null -eq $Selected) {
        return $true
    }
    @($Candidates | Where-Object {
        ([int]$_.width -eq [int]$Selected.width) -and
        ([int]$_.height -eq [int]$Selected.height)
    }).Count -eq 1
}

function Find-SensitivePropertyNames {
    param([AllowNull()][object]$Value)

    $found = [System.Collections.Generic.List[string]]::new()
    $sensitive = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @(
        'password', 'passwordHash', 'username', 'credential', 'credentials',
        'secret', 'secrets', 'token', 'accessToken', 'refreshToken')) {
        [void]$sensitive.Add($name)
    }

    function Visit-Value {
        param([AllowNull()][object]$Node, [string]$Path)

        if (($null -eq $Node) -or ($Node -is [string]) -or
            ($Node -is [ValueType])) {
            return
        }
        if ($Node -is [System.Collections.IEnumerable] -and
            -not ($Node -is [pscustomobject])) {
            $index = 0
            foreach ($item in $Node) {
                Visit-Value -Node $item -Path "$Path[$index]"
                $index++
            }
            return
        }
        foreach ($property in $Node.PSObject.Properties) {
            $propertyPath = if ([string]::IsNullOrEmpty($Path)) {
                $property.Name
            } else {
                "$Path.$($property.Name)"
            }
            if ($sensitive.Contains($property.Name)) {
                $found.Add($propertyPath)
            }
            Visit-Value -Node $property.Value -Path $propertyPath
        }
    }

    Visit-Value -Node $Value -Path ''
    @($found)
}

function Get-ProfileComponentIds {
    param([Parameter(Mandatory)][object]$Profile)

    $ids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $ownerId = [string]$Profile.renderer.d3d8Owner.componentId
    if (-not [string]::IsNullOrWhiteSpace($ownerId)) {
        [void]$ids.Add($ownerId)
    }
    foreach ($layer in @($Profile.renderer.secondaryLayers)) {
        [void]$ids.Add([string]$layer.componentId)
    }
    $effectId = [string]$Profile.postProcessing.effectComponentId
    if (-not [string]::IsNullOrWhiteSpace($effectId)) {
        [void]$ids.Add($effectId)
    }
    $assetProperty = $Profile.PSObject.Properties['localAssetOverlay']
    if ($null -ne $assetProperty -and $null -ne $assetProperty.Value) {
        [void]$ids.Add([string]$assetProperty.Value.componentId)
    }
    $modulesProperty = $Profile.PSObject.Properties['localModules']
    if ($null -ne $modulesProperty -and $null -ne $modulesProperty.Value) {
        foreach ($module in @($modulesProperty.Value)) {
            [void]$ids.Add([string]$module.componentId)
        }
    }
    @($ids)
}

foreach ($path in @(
    $ProfilesPath,
    $EvidencePath,
    $SourcesLockPath,
    $profileSchemaPath,
    $evidenceSchemaPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required graphics contract file is missing: $path"
    }
}

$profilesJson = Get-Content -Raw -LiteralPath $ProfilesPath
$evidenceJson = Get-Content -Raw -LiteralPath $EvidencePath
$sourcesJson = Get-Content -Raw -LiteralPath $SourcesLockPath
$profilesDocument = $profilesJson | ConvertFrom-Json -Depth 50
$evidenceDocument = $evidenceJson | ConvertFrom-Json -Depth 50
$sourcesDocument = $sourcesJson | ConvertFrom-Json -Depth 50

$profileSchemaValid = Test-Json -Json $profilesJson -SchemaFile $profileSchemaPath -ErrorAction Stop
$evidenceSchemaValid = Test-Json -Json $evidenceJson -SchemaFile $evidenceSchemaPath -ErrorAction Stop
Add-GraphicsProfileCheck 'graphics-profile JSON schema' $profileSchemaValid $ProfilesPath
Add-GraphicsProfileCheck 'graphics-evidence JSON schema' $evidenceSchemaValid $EvidencePath

$sensitiveProperties = @(
    Find-SensitivePropertyNames $profilesDocument
    Find-SensitivePropertyNames $evidenceDocument
)
Add-GraphicsProfileCheck 'graphics contracts contain no credential fields' (
    $sensitiveProperties.Count -eq 0) ($sensitiveProperties -join ', ')

$sourceIds = @($sourcesDocument.components | ForEach-Object { [string]$_.id })
$duplicateSourceIds = @($sourceIds | Group-Object | Where-Object Count -ne 1)
Add-GraphicsProfileCheck 'source-lock component IDs are unique' (
    $duplicateSourceIds.Count -eq 0) (($duplicateSourceIds.Name) -join ', ')

$invalidSourceHashes = @($sourcesDocument.components | Where-Object {
    ($null -ne $_.sha256) -and -not (Test-Sha256Text ([string]$_.sha256))
} | ForEach-Object { [string]$_.id })
Add-GraphicsProfileCheck 'source-lock component hashes are canonical SHA-256' (
    $invalidSourceHashes.Count -eq 0) ($invalidSourceHashes -join ', ')

$invalidMemberLocks = @($sourcesDocument.components | ForEach-Object {
    $componentId = [string]$_.id
    if ($null -ne $_.members) {
        @($_.members | Where-Object {
            ($null -eq $_.size) -or ([long]$_.size -le 0) -or
            -not (Test-Sha256Text ([string]$_.sha256))
        } | ForEach-Object { "$componentId/$($_.path)" })
    }
})
Add-GraphicsProfileCheck 'source-lock member hashes and sizes are complete' (
    $invalidMemberLocks.Count -eq 0) ($invalidMemberLocks -join ', ')

$invalidRuntimeArtifactLocks = @($sourcesDocument.components | ForEach-Object {
    $componentId = [string]$_.id
    if ($_.PSObject.Properties.Name -contains 'runtimeArtifacts') {
        @($_.runtimeArtifacts | Where-Object {
            ([long]$_.size -le 0) -or
            -not (Test-Sha256Text ([string]$_.sha256)) -or
            [string]::IsNullOrWhiteSpace([string]$_.path)
        } | ForEach-Object { "$componentId/$($_.path)" })
    }
})
Add-GraphicsProfileCheck 'source-lock runtime artifact hashes and sizes are complete' (
    $invalidRuntimeArtifactLocks.Count -eq 0) ($invalidRuntimeArtifactLocks -join ', ')

$acquiredGraphicsIds = @(
    'newserv-canary-source',
    'blue-burst-patch-project',
    'ultimate-asi-loader-x86',
    'psobb-widescreen-local-evaluation',
    'reshade-6.7.3-local-import',
    'dxvk-x86-d3d8-d3d9',
    'd3d8to9-x86',
    'presentmon-portable',
    'renderdoc-diagnostic',
    'project-owned-psobb-enhancement',
    'ashenbubs-hd-psobb-v1.02-local-import',
    'project-owned-psobb-large-assets'
)
$incompleteAcquiredLocks = [System.Collections.Generic.List[string]]::new()
foreach ($componentId in $acquiredGraphicsIds) {
    $component = @($sourcesDocument.components | Where-Object id -ceq $componentId)
    if (($component.Count -ne 1) -or
        ($null -eq $component[0].retrievedAtUtc) -or
        ($null -eq $component[0].size) -or
        -not (Test-Sha256Text ([string]$component[0].sha256)) -or
        [string]::IsNullOrWhiteSpace([string]$component[0].scanState)) {
        $incompleteAcquiredLocks.Add($componentId)
    }
}
Add-GraphicsProfileCheck 'acquired graphics artifacts retain scan-complete locks' (
    $incompleteAcquiredLocks.Count -eq 0) ($incompleteAcquiredLocks -join ', ')

$clientLocks = @($sourcesDocument.components | Where-Object id -ceq 'tethealla-59nl-english')
$clientMembers = if ($clientLocks.Count -eq 1) {
    @($clientLocks[0].members | Where-Object path -ceq 'Psobb.exe')
} else {
    @()
}
$baseClientValid = ($clientLocks.Count -eq 1) -and
    ($clientMembers.Count -eq 1) -and
    ([string]$profilesDocument.baseClient.componentId -ceq 'tethealla-59nl-english') -and
    ([string]$profilesDocument.baseClient.executableSha256 -ceq [string]$clientMembers[0].sha256)
Add-GraphicsProfileCheck 'graphics profiles bind to exact 59NL executable' $baseClientValid (
    [string]$profilesDocument.baseClient.executableSha256)

$expectedProfileIds = @(
    'safe-native-4x3',
    'clarity-dgvoodoo-4x3',
    'lab-widescreen-16x10',
    'lab-widescreen-hd-16x10',
    'lab-widescreen-cas-16x10',
    'cleanroom-widescreen-canary',
    'cas-evaluation-16x10',
    'fidelity-modern-16x10',
    'dxvk-canary',
    'd3d8to9-canary'
)
$actualProfileIds = @($profilesDocument.profiles | ForEach-Object { [string]$_.id })
$profileIdsExact = ($actualProfileIds.Count -eq $expectedProfileIds.Count) -and
    (@(Compare-Object $expectedProfileIds $actualProfileIds -CaseSensitive).Count -eq 0) -and
    (@($actualProfileIds | Group-Object | Where-Object Count -ne 1).Count -eq 0)
Add-GraphicsProfileCheck 'required graphics profile set is exact' $profileIdsExact (
    $actualProfileIds -join ', ')

$sourceIdSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($id in $sourceIds) {
    [void]$sourceIdSet.Add($id)
}
$profileIdSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($id in $actualProfileIds) {
    [void]$profileIdSet.Add($id)
}

foreach ($profile in @($profilesDocument.profiles)) {
    $profileId = [string]$profile.id
    $owner = $profile.renderer.d3d8Owner
    $layers = @($profile.renderer.secondaryLayers)
    $ownerCandidates = @($layers | Where-Object {
        ([string]$_.role -ceq 'd3d8-owner') -or
        ([System.IO.Path]::GetFileName([string]$_.relativePath) -ieq 'd3d8.dll')
    })
    $ownerValid = [string]$owner.role -ceq 'd3d8-owner'
    if ([string]$owner.kind -ceq 'application') {
        $ownerValid = $ownerValid -and
            ($null -eq $owner.componentId) -and
            ($null -eq $owner.relativePath) -and
            ([string]$profile.renderer.outputApi -ceq 'd3d8-native')
    } else {
        $ownerValid = $ownerValid -and
            ($ownerCandidates.Count -eq 0) -and
            ($sourceIdSet.Contains([string]$owner.componentId)) -and
            ([string]$owner.relativePath -ceq 'd3d8.dll')
    }
    Add-GraphicsProfileCheck "$profileId has exactly one D3D8 owner" $ownerValid (
        "kind=$($owner.kind); component=$($owner.componentId); secondaryConflicts=$($ownerCandidates.Count)")

    $modulePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $owner.relativePath) {
        [void]$modulePaths.Add([string]$owner.relativePath)
    }
    $invalidLayers = [System.Collections.Generic.List[string]]::new()
    foreach ($layer in $layers) {
        $path = [string]$layer.relativePath
        if (-not $sourceIdSet.Contains([string]$layer.componentId) -or
            -not (Test-RelativeModulePath $path) -or
            -not $modulePaths.Add($path)) {
            $invalidLayers.Add($path)
        }
    }
    Add-GraphicsProfileCheck "$profileId has an explicit non-conflicting module chain" (
        $invalidLayers.Count -eq 0) ($invalidLayers -join ', ')

    $referencedIds = @(Get-ProfileComponentIds $profile)
    $missingComponents = @($referencedIds | Where-Object { -not $sourceIdSet.Contains($_) })
    Add-GraphicsProfileCheck "$profileId references locked components" (
        $missingComponents.Count -eq 0) ($missingComponents -join ', ')

    $assetProperty = $profile.PSObject.Properties['localAssetOverlay']
    $modulesProperty = $profile.PSObject.Properties['localModules']
    $hasAssetComposition = ($null -ne $assetProperty -and $null -ne $assetProperty.Value) -or
        ($null -ne $modulesProperty -and $null -ne $modulesProperty.Value)
    $assetCompositionScopeValid = if ($profileId -ceq 'lab-widescreen-hd-16x10') {
        ($null -ne $assetProperty -and $null -ne $assetProperty.Value) -and
            ($null -ne $modulesProperty -and @($modulesProperty.Value).Count -eq 1)
    } else {
        -not $hasAssetComposition
    }
    Add-GraphicsProfileCheck "$profileId local asset composition scope is exact" (
        $assetCompositionScopeValid) "hasLocalComposition=$hasAssetComposition"

    $rollbackId = [string]$profile.rollbackProfileId
    $rollbackValid = [string]::IsNullOrEmpty($rollbackId) -or
        ($profileIdSet.Contains($rollbackId) -and
         -not $rollbackId.Equals($profileId, [System.StringComparison]::OrdinalIgnoreCase))
    Add-GraphicsProfileCheck "$profileId has a valid rollback target" $rollbackValid $rollbackId

    $windowModes = @($profile.display.windowModes | ForEach-Object { [string]$_ })
    $defaultWindowModeValid = $windowModes -ccontains [string]$profile.display.defaultWindowMode
    Add-GraphicsProfileCheck "$profileId default window mode is declared" (
        $defaultWindowModeValid) ([string]$profile.display.defaultWindowMode)

    $resolutionSelectionValid = Test-ResolutionSelected `
        -Selected $profile.display.selectedInternalRender `
        -Candidates @($profile.display.internalRenderCandidates)
    $filterSelectionValid = ($null -eq $profile.display.selectedScalingFilter) -or
        (@($profile.display.scalingFilterCandidates) -ccontains [string]$profile.display.selectedScalingFilter)
    $msaaSelectionValid = ($null -eq $profile.quality.selectedMsaa) -or
        (@($profile.quality.msaaCandidates) -contains [int]$profile.quality.selectedMsaa)
    Add-GraphicsProfileCheck "$profileId selections come from candidate sets" (
        $resolutionSelectionValid -and $filterSelectionValid -and $msaaSelectionValid) (
        "resolution=$resolutionSelectionValid; filter=$filterSelectionValid; msaa=$msaaSelectionValid")

    $usesDgVoodoo = [string]$owner.componentId -ceq 'dgvoodoo2-x86-d3d8'
    $dgVoodooValid = (-not $usesDgVoodoo) -or (
        ([string]$profile.renderer.outputApi -ceq 'd3d11_fl11_0') -and
        ([string]$profile.renderer.featureLevel -ceq '11_0') -and
        ($profile.quality.watermarkEnabled -eq $false))
    Add-GraphicsProfileCheck "$profileId renderer safety policy" (
        $dgVoodooValid -and ([string]$profile.renderer.outputApi -cnotmatch 'd3d12')) (
        "api=$($profile.renderer.outputApi); feature=$($profile.renderer.featureLevel); watermark=$($profile.quality.watermarkEnabled)")

    $aspectValid = $true
    if ([string]$profile.display.aspectPolicy -ceq 'expand-horizontal-16x10') {
        $ceiling = $profilesDocument.acceptanceTarget.trueWidescreenRenderCeiling
        $aspectValid = ([int]$profile.display.output.width -eq 2560) -and
            ([int]$profile.display.output.height -eq 1600) -and
            ([int]$profile.display.renderCeiling.width -le [int]$ceiling.width) -and
            ([int]$profile.display.renderCeiling.height -le [int]$ceiling.height)
        foreach ($candidate in @($profile.display.internalRenderCandidates)) {
            $aspectValid = $aspectValid -and
                (Test-AspectRatio -Resolution $candidate -Expected 1.6) -and
                ([int]$candidate.width -le [int]$ceiling.width) -and
                ([int]$candidate.height -le [int]$ceiling.height)
        }
    } else {
        foreach ($candidate in @($profile.display.internalRenderCandidates)) {
            $aspectValid = $aspectValid -and
                (Test-AspectRatio -Resolution $candidate -Expected (4.0 / 3.0))
        }
    }
    Add-GraphicsProfileCheck "$profileId aspect and render ceiling are valid" $aspectValid (
        "$($profile.display.aspectPolicy); ceiling=$($profile.display.renderCeiling.width)x$($profile.display.renderCeiling.height)")
}

$cleanroomProfiles = @($profilesDocument.profiles | Where-Object {
    [string]$_.id -ceq 'cleanroom-widescreen-canary'
})
$cleanroomProfileValid = $cleanroomProfiles.Count -eq 1
if ($cleanroomProfileValid) {
    $cleanroom = $cleanroomProfiles[0]
    $cleanroomComponents = @(Get-ProfileComponentIds $cleanroom)
    $cleanroomLimitations = @($cleanroom.knownLimitations | ForEach-Object { [string]$_ })
    $cleanroomProfileValid = ([string]$cleanroom.channel -ceq 'local-lab') -and
        ([string]$cleanroom.distributionClass -ceq 'public-gated') -and
        ($cleanroomComponents -ccontains 'project-owned-psobb-enhancement') -and
        ($cleanroomComponents -cnotcontains 'reshade-6.7.3-local-import') -and
        ([string]$cleanroom.postProcessing.effectComponentId -ceq '') -and
        (@($cleanroom.renderer.secondaryLayers | Where-Object {
            [string]$_.role -ceq 'project-widescreen-partial'
        }).Count -eq 1) -and
        (@($cleanroomLimitations | Where-Object {
            $_ -match 'HUD and minimap transformation are not implemented'
        }).Count -eq 1) -and
        (@($cleanroomLimitations | Where-Object {
            $_ -match 'does not automatically recreate the D3D device'
        }).Count -eq 1)
}
Add-GraphicsProfileCheck 'clean-room canary declares only implemented widescreen scope' (
    $cleanroomProfileValid) 'partial project layer, no ReShade, explicit HUD/minimap and dynamic-resize limitations'

$casEvaluationProfiles = @($profilesDocument.profiles | Where-Object {
    [string]$_.id -ceq 'cas-evaluation-16x10'
})
$casEvaluationValid = $casEvaluationProfiles.Count -eq 1
if ($casEvaluationValid) {
    $casEvaluation = $casEvaluationProfiles[0]
    $casStrengths = @($casEvaluation.postProcessing.strengthCandidates)
    $casEvaluationValid = ([string]$casEvaluation.channel -ceq 'local-lab') -and
        ([string]$casEvaluation.distributionClass -ceq 'local-only') -and
        ([string]$casEvaluation.postProcessing.effectComponentId -ceq 'psobb-neutral-cas-source') -and
        ($casEvaluation.postProcessing.enabledByDefault -eq $false) -and
        ($null -eq $casEvaluation.postProcessing.selectedStrength) -and
        ($casStrengths.Count -eq 3) -and
        ([double]$casStrengths[0] -eq 0.15) -and
        ([double]$casStrengths[1] -eq 0.25) -and
        ([double]$casStrengths[2] -eq 0.35) -and
        (@($casEvaluation.renderer.secondaryLayers | Where-Object {
            [string]$_.componentId -ceq 'reshade-6.7.3-local-import' -and
            [string]$_.relativePath -ceq 'dxgi.dll' -and
            [string]$_.role -ceq 'post-process'
        }).Count -eq 1)
}
Add-GraphicsProfileCheck 'CAS evaluation is isolated, local-only, and strength-gated' (
    $casEvaluationValid) 'standard ReShade dxgi plus only 0.15, 0.25, and 0.35 project CAS candidates'

$referenceCasProfiles = @($profilesDocument.profiles | Where-Object {
    [string]$_.id -ceq 'lab-widescreen-cas-16x10'
})
$referenceCasValid = $referenceCasProfiles.Count -eq 1
if ($referenceCasValid) {
    $referenceCas = $referenceCasProfiles[0]
    $referenceCasComponents = @(Get-ProfileComponentIds $referenceCas)
    $referenceCasStrengths = @($referenceCas.postProcessing.strengthCandidates)
    $referenceCasLimitations = @($referenceCas.knownLimitations | ForEach-Object { [string]$_ })
    $referenceCasValid = ([string]$referenceCas.channel -ceq 'local-lab') -and
        ([string]$referenceCas.distributionClass -ceq 'local-only') -and
        ([string]$referenceCas.rollbackProfileId -ceq 'lab-widescreen-16x10') -and
        ($referenceCasComponents -ccontains 'psobb-widescreen-local-evaluation') -and
        ($referenceCasComponents -ccontains 'reshade-6.7.3-local-import') -and
        ($referenceCasComponents -cnotcontains 'project-owned-psobb-enhancement') -and
        ([string]$referenceCas.postProcessing.effectComponentId -ceq 'psobb-neutral-cas-source') -and
        ($referenceCasStrengths.Count -eq 3) -and
        ([double]$referenceCasStrengths[0] -eq 0.15) -and
        ([double]$referenceCasStrengths[1] -eq 0.25) -and
        ([double]$referenceCasStrengths[2] -eq 0.35) -and
        (@($referenceCasLimitations | Where-Object {
            $_ -match 'does not represent clean-room implementation readiness'
        }).Count -eq 1)
}
Add-GraphicsProfileCheck 'reference-layout CAS stays local-only and separate from clean-room readiness' (
    $referenceCasValid) 'widescreen reference plus standard ReShade/CAS; no project enhancement claim'

$hdProfiles = @($profilesDocument.profiles | Where-Object {
    [string]$_.id -ceq 'lab-widescreen-hd-16x10'
})
$hdProfileValid = $hdProfiles.Count -eq 1
$hdDetail = [System.Collections.Generic.List[string]]::new()
if ($hdProfileValid) {
    $hd = $hdProfiles[0]
    $overlay = $hd.PSObject.Properties['localAssetOverlay']
    $modules = @($hd.PSObject.Properties['localModules'].Value)
    $secondaryLargeAssets = @($hd.renderer.secondaryLayers | Where-Object {
        [string]$_.componentId -ceq 'project-owned-psobb-large-assets' -and
        [string]$_.relativePath -ceq 'plugins/PSOBB.LargeAssets.asi' -and
        [string]$_.role -ceq 'large-asset-patch' -and
        [int]$_.declaredOrder -eq 40
    })
    $hdProfileValid = ([string]$hd.channel -ceq 'local-lab') -and
        ([string]$hd.distributionClass -ceq 'local-only') -and
        ([string]$hd.rollbackProfileId -ceq 'lab-widescreen-16x10') -and
        ([string]$hd.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') -and
        ($secondaryLargeAssets.Count -eq 1) -and
        ($hd.postProcessing.enabledByDefault -eq $false) -and
        ($null -eq $hd.postProcessing.effectComponentId) -and
        (@($hd.postProcessing.strengthCandidates).Count -eq 0) -and
        ($null -eq $hd.postProcessing.selectedStrength) -and
        ($null -ne $overlay) -and
        ([string]$overlay.Value.componentId -ceq 'ashenbubs-hd-psobb-v1.02-local-import') -and
        ([string]$overlay.Value.version -ceq '1.02') -and
        ([string]$overlay.Value.distributionClass -ceq 'local-only') -and
        ([string]$overlay.Value.baseProfileId -ceq 'lab-widescreen-16x10') -and
        ([string]$overlay.Value.activationScript -ceq
            'scripts/Set-PSOBBAshenbubsHDClientActivation.ps1') -and
        ($modules.Count -eq 1) -and
        ([string]$modules[0].componentId -ceq 'project-owned-psobb-large-assets') -and
        ([string]$modules[0].capability -ceq 'large-assets-59nl') -and
        ([string]$modules[0].relativePath -ceq 'plugins/PSOBB.LargeAssets.asi') -and
        ([string]$modules[0].configurationPath -ceq 'plugins/PSOBB.LargeAssets.ini')
}

$assetLocks = @($sourcesDocument.components | Where-Object {
    [string]$_.id -ceq 'ashenbubs-hd-psobb-v1.02-local-import'
})
$largeAssetsLocks = @($sourcesDocument.components | Where-Object {
    [string]$_.id -ceq 'project-owned-psobb-large-assets'
})
$largeAssetsManifestPath = Join-Path $repositoryRoot `
    'src\PSOBB.LargeAssets\build-manifest.json'
$hdComponentBindingValid = $assetLocks.Count -eq 1 -and
    $largeAssetsLocks.Count -eq 1 -and
    (Test-Path -LiteralPath $largeAssetsManifestPath -PathType Leaf)
if ($hdComponentBindingValid) {
    try {
        $largeAssetsManifest = Get-Content -Raw -LiteralPath $largeAssetsManifestPath |
            ConvertFrom-Json -Depth 50
        $largeRuntimeArtifacts = @($largeAssetsLocks[0].runtimeArtifacts)
        $largeManifestArtifacts = @($largeAssetsManifest.artifacts)
        $hdComponentBindingValid =
            ([string]$assetLocks[0].version -ceq '1.02') -and
            ([string]$assetLocks[0].distributionClass -ceq 'local-only') -and
            ([string]$assetLocks[0].compatibilityState -ceq
                'ephinea-only-upstream-warning') -and
            ([string]$assetLocks[0].activationRequirements.requiredComponentId -ceq
                'project-owned-psobb-large-assets') -and
            ([string]$assetLocks[0].activationRequirements.requiredCapability -ceq
                'large-assets-59nl') -and
            ([long]$assetLocks[0].activationRequirements.requiredMaximumAssetBytes -eq
                100000000) -and
            ([string]$largeAssetsManifest.componentId -ceq
                'project-owned-psobb-large-assets') -and
            ([string]$largeAssetsManifest.version -ceq [string]$largeAssetsLocks[0].version) -and
            ([string]$largeAssetsManifest.baseClient.sha256 -ceq
                [string]$profilesDocument.baseClient.executableSha256) -and
            ([uint32]$largeAssetsManifest.patchContract.replacementUint32 -eq 100000000) -and
            ($largeRuntimeArtifacts.Count -eq 1) -and
            ($largeManifestArtifacts.Count -eq 1) -and
            ([string]$largeRuntimeArtifacts[0].path -ceq
                [string]$largeManifestArtifacts[0].runtimeName) -and
            ([long]$largeRuntimeArtifacts[0].size -eq
                [long]$largeManifestArtifacts[0].size) -and
            ([string]$largeRuntimeArtifacts[0].sha256 -ceq
                [string]$largeManifestArtifacts[0].sha256)
    } catch {
        $hdComponentBindingValid = $false
        $hdDetail.Add($_.Exception.Message)
    }
}
Add-GraphicsProfileCheck 'HD local-lab profile is exact, local-only, and no-CAS' (
    $hdProfileValid) 'private AshenbubsHD overlay; one exact large-assets ASI/INI; rollback to clean widescreen'
Add-GraphicsProfileCheck 'HD profile binds exact AshenbubsHD and LargeAssets contracts' (
    $hdComponentBindingValid) ($hdDetail -join ', ')

$modernProfiles = @($profilesDocument.profiles | Where-Object id -ceq 'fidelity-modern-16x10')
$modernCasValid = $modernProfiles.Count -eq 1
if ($modernCasValid) {
    $modern = $modernProfiles[0]
    $strengths = @($modern.postProcessing.strengthCandidates)
    $modernCasValid = ([string]$modern.postProcessing.effectComponentId -ceq 'psobb-neutral-cas-source') -and
        ($modern.postProcessing.enabledByDefault -eq $false) -and
        ($null -eq $modern.postProcessing.selectedStrength) -and
        ($strengths.Count -eq 3) -and
        ([double]$strengths[0] -eq 0.15) -and
        ([double]$strengths[1] -eq 0.25) -and
        ([double]$strengths[2] -eq 0.35)
}
Add-GraphicsProfileCheck 'modern profile CAS remains evidence-gated' $modernCasValid (
    'strengths=0.15,0.25,0.35; disabled until accepted')

$widescreenLocks = @($sourcesDocument.components | Where-Object id -ceq 'psobb-widescreen-local-evaluation')
$widescreenPinValid = ($widescreenLocks.Count -eq 1) -and
    ([string]$widescreenLocks[0].tagObjectSha -ceq '4927d5599692eddd3acc0ec6241b7d27c6838b3e') -and
    ([string]$widescreenLocks[0].commit -ceq 'c5703cd304215b629ceb2d00e847ee20ca8d8c17')
Add-GraphicsProfileCheck 'widescreen tag object and peeled commit are distinct and exact' (
    $widescreenPinValid) (
    "tag=$($widescreenLocks[0].tagObjectSha); commit=$($widescreenLocks[0].commit)")

$expectedVersions = @{
    'dgvoodoo2-x86-d3d8' = '2.87.3'
    'dxvk-x86-d3d8-d3d9' = 'v3.0.1'
    'd3d8to9-x86' = 'v1.15.1'
    'ultimate-asi-loader-x86' = 'v9.7.2'
    'reshade-6.7.3-local-import' = 'v6.7.3'
    'presentmon-portable' = 'v2.5.1'
    'renderdoc-diagnostic' = 'v1.45'
}
$versionFailures = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $expectedVersions.GetEnumerator()) {
    $component = @($sourcesDocument.components | Where-Object id -ceq $entry.Key)
    if (($component.Count -ne 1) -or ([string]$component[0].version -cne $entry.Value)) {
        $versionFailures.Add($entry.Key)
    }
}
Add-GraphicsProfileCheck 'researched graphics pins use current verified versions' (
    $versionFailures.Count -eq 0) ($versionFailures -join ', ')

$repoComponents = @($sourcesDocument.components | Where-Object {
    ([string]$_.sourceUrl).StartsWith('repo:', [System.StringComparison]::Ordinal) -and
    ($null -ne $_.retrievedAtUtc)
})
$repoHashFailures = [System.Collections.Generic.List[string]]::new()
foreach ($component in $repoComponents) {
    $relativePath = ([string]$component.sourceUrl).Substring('repo:'.Length).Replace('/', '\')
    $path = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $repoHashFailures.Add("missing:$($component.id)")
        continue
    }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if (($item.Length -ne [long]$component.size) -or ($hash -cne [string]$component.sha256)) {
        $repoHashFailures.Add("mismatch:$($component.id)")
    }
    foreach ($member in @($component.members)) {
        if ($null -eq $member) {
            continue
        }
        $memberPath = Join-Path $repositoryRoot ([string]$member.path).Replace('/', '\')
        if (-not (Test-Path -LiteralPath $memberPath -PathType Leaf)) {
            $repoHashFailures.Add("missing:$($component.id)/$($member.path)")
            continue
        }
        $memberItem = Get-Item -LiteralPath $memberPath
        $memberHash = (Get-FileHash -LiteralPath $memberPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if (($memberItem.Length -ne [long]$member.size) -or
            ($memberHash -cne [string]$member.sha256)) {
            $repoHashFailures.Add("mismatch:$($component.id)/$($member.path)")
        }
    }
}
Add-GraphicsProfileCheck 'project-owned graphics source hashes match the lock' (
    $repoHashFailures.Count -eq 0) ($repoHashFailures -join ', ')

$enhancementLocks = @($sourcesDocument.components | Where-Object {
    [string]$_.id -ceq 'project-owned-psobb-enhancement'
})
$enhancementManifestPath = Join-Path $repositoryRoot `
    'src\PSOBB.Enhancement\build-manifest.json'
$enhancementLicensePath = Join-Path $repositoryRoot `
    'src\PSOBB.Enhancement\LICENSE.md'
$enhancementManifestValid = ($enhancementLocks.Count -eq 1) -and
    (Test-Path -LiteralPath $enhancementManifestPath -PathType Leaf) -and
    (Test-Path -LiteralPath $enhancementLicensePath -PathType Leaf)
$enhancementManifestFailures = [System.Collections.Generic.List[string]]::new()
if ($enhancementManifestValid) {
    try {
        $enhancementManifest = Get-Content -Raw -LiteralPath $enhancementManifestPath |
            ConvertFrom-Json -Depth 50
        $runtimeArtifacts = @($enhancementLocks[0].runtimeArtifacts)
        $manifestArtifacts = @($enhancementManifest.artifacts)
        $enhancementManifestValid = ([int]$enhancementManifest.schemaVersion -eq 1) -and
            ([string]$enhancementManifest.componentId -ceq 'project-owned-psobb-enhancement') -and
            ([string]$enhancementManifest.version -ceq [string]$enhancementLocks[0].version) -and
            ([string]$enhancementManifest.baseClient.sha256 -ceq
                [string]$profilesDocument.baseClient.executableSha256) -and
            ($runtimeArtifacts.Count -eq 1) -and
            ($manifestArtifacts.Count -eq 1) -and
            ([string]$runtimeArtifacts[0].path -ceq [string]$manifestArtifacts[0].runtimeName) -and
            ([long]$runtimeArtifacts[0].size -eq [long]$manifestArtifacts[0].size) -and
            ([string]$runtimeArtifacts[0].sha256 -ceq [string]$manifestArtifacts[0].sha256) -and
            ([string]$runtimeArtifacts[0].authenticode -ceq 'NotSigned') -and
            ([string]$enhancementManifest.license -ceq 'MIT') -and
            ((Get-Content -Raw -LiteralPath $enhancementLicensePath).Contains(
                'MIT License', [System.StringComparison]::Ordinal))
        foreach ($sourceInput in @($enhancementManifest.sourceInputs)) {
            $relativePath = ([string]$sourceInput.path).Replace('/', '\')
            if ([string]::IsNullOrWhiteSpace($relativePath) -or
                [System.IO.Path]::IsPathRooted($relativePath) -or
                $relativePath.Contains(':', [System.StringComparison]::Ordinal) -or
                $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
                $enhancementManifestFailures.Add("unsafe:$relativePath")
                continue
            }
            $sourcePath = Join-Path $repositoryRoot $relativePath
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                $enhancementManifestFailures.Add("missing:$relativePath")
                continue
            }
            $sourceItem = Get-Item -LiteralPath $sourcePath -Force
            $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($sourceItem.Length -ne [long]$sourceInput.size -or
                $sourceHash -cne [string]$sourceInput.sha256) {
                $enhancementManifestFailures.Add("mismatch:$relativePath")
            }
        }
    } catch {
        $enhancementManifestValid = $false
        $enhancementManifestFailures.Add($_.Exception.Message)
    }
}
$enhancementManifestValid = $enhancementManifestValid -and
    ($enhancementManifestFailures.Count -eq 0)
Add-GraphicsProfileCheck 'clean-room enhancement license and reproducible build manifest are exact' (
    $enhancementManifestValid) ($enhancementManifestFailures -join ', ')

$projectLicensePath = Join-Path $repositoryRoot 'patches\reshade\LICENSE.md'
$thirdPartyNoticePath = Join-Path $repositoryRoot 'patches\reshade\THIRD-PARTY-NOTICES.md'
$projectNoticesValid = (Test-Path -LiteralPath $projectLicensePath -PathType Leaf) -and
    (Test-Path -LiteralPath $thirdPartyNoticePath -PathType Leaf) -and
    (Get-Content -Raw -LiteralPath $projectLicensePath).Contains(
        'MIT License', [System.StringComparison]::Ordinal) -and
    (Get-Content -Raw -LiteralPath $thirdPartyNoticePath).Contains(
        '9fabcc9a2c45f958aff55ddfda337e74ef894b7f',
        [System.StringComparison]::Ordinal)
Add-GraphicsProfileCheck 'project-owned CAS license and AMD notice are present' (
    $projectNoticesValid) 'MIT project license plus pinned FidelityFX CAS notice'

$casSourcePath = Join-Path $repositoryRoot 'patches\reshade\PSOBB_NeutralCAS.fx'
$casSourceText = if (Test-Path -LiteralPath $casSourcePath -PathType Leaf) {
    Get-Content -Raw -LiteralPath $casSourcePath
} else {
    ''
}
Add-GraphicsProfileCheck 'project-owned CAS has no implicit shader-pack dependency' (
    $casSourceText -notmatch '(?i)#include\s+["<]ReShade\.fxh[">]' -and
    $casSourceText -match 'PSOBB_BackBufferTex\s*:\s*COLOR' -and
    $casSourceText -match 'BUFFER_RCP_WIDTH' -and
    $casSourceText -match 'PSOBB_FullscreenVS') `
    'the locked shader source contains its own color-buffer sampler and fullscreen vertex stage'

$candidateIds = @($evidenceDocument.candidates | ForEach-Object { [string]$_.profileId })
$candidateSetExact = ($candidateIds.Count -eq $actualProfileIds.Count) -and
    (@(Compare-Object $actualProfileIds $candidateIds -CaseSensitive).Count -eq 0) -and
    (@($candidateIds | Group-Object | Where-Object Count -ne 1).Count -eq 0)
Add-GraphicsProfileCheck 'evidence has exactly one candidate per profile' (
    $candidateSetExact) ($candidateIds -join ', ')

$requiredGates = @($evidenceDocument.acceptancePolicy.requiredPassGates | ForEach-Object { [string]$_ })
$artifactGates = @($evidenceDocument.acceptancePolicy.artifactRequiredGates | ForEach-Object { [string]$_ })
$naGates = @($evidenceDocument.acceptancePolicy.allowNotApplicableForAcceptance | ForEach-Object { [string]$_ })
$acceptedFailures = [System.Collections.Generic.List[string]]::new()
foreach ($candidate in @($evidenceDocument.candidates)) {
    $failedGatePresent = @($candidate.gates.PSObject.Properties | Where-Object {
        [string]$_.Value.state -ceq 'fail'
    }).Count -gt 0
    if ($failedGatePresent -and ([string]$candidate.disposition -cne 'rejected')) {
        $acceptedFailures.Add("$($candidate.profileId):fail-not-rejected")
    }
    if ([string]$candidate.disposition -ceq 'blocked' -and @($candidate.blockers).Count -eq 0) {
        $acceptedFailures.Add("$($candidate.profileId):blocked-without-reason")
    }
    if ([string]$candidate.disposition -ceq 'rejected' -and
        [string]::IsNullOrWhiteSpace([string]$candidate.rejectionReason)) {
        $acceptedFailures.Add("$($candidate.profileId):rejected-without-reason")
    }
    if ([string]$candidate.disposition -cne 'accepted') {
        continue
    }

    if ([string]$candidate.stage -cne 'evidence-complete' -or
        @($candidate.blockers).Count -ne 0 -or
        -not [string]::IsNullOrEmpty([string]$candidate.rejectionReason)) {
        $acceptedFailures.Add("$($candidate.profileId):accepted-state")
    }
    foreach ($gateName in $requiredGates) {
        $gate = $candidate.gates.PSObject.Properties[$gateName].Value
        $gateAccepted = [string]$gate.state -ceq 'pass'
        if (([string]$gate.state -ceq 'not-applicable') -and ($naGates -ccontains $gateName)) {
            $gateAccepted = $true
        }
        if (-not $gateAccepted) {
            $acceptedFailures.Add("$($candidate.profileId):$gateName")
        }
        if (($artifactGates -ccontains $gateName) -and @($gate.artifactRefs).Count -eq 0) {
            $acceptedFailures.Add("$($candidate.profileId):$gateName-artifact")
        }
    }

    $profile = @($profilesDocument.profiles | Where-Object id -ceq $candidate.profileId)[0]
    foreach ($componentId in @(Get-ProfileComponentIds $profile)) {
        $component = @($sourcesDocument.components | Where-Object id -ceq $componentId)
        if (($component.Count -ne 1) -or
            ($null -eq $component[0].retrievedAtUtc) -or
            -not (Test-Sha256Text ([string]$component[0].sha256))) {
            $acceptedFailures.Add("$($candidate.profileId):unacquired-$componentId")
        }
    }
}
Add-GraphicsProfileCheck 'candidate disposition fails closed' (
    $acceptedFailures.Count -eq 0) ($acceptedFailures -join ', ')

if (-not $Quiet) {
    $results | Format-Table -AutoSize
}
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) graphics-profile contract check(s) failed"
}

[pscustomobject]@{
    Suite = 'GraphicsProfiles'
    Passed = $results.Count
    Failed = 0
    Profiles = $actualProfileIds.Count
}
