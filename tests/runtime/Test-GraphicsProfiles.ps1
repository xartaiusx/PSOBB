[CmdletBinding()]
param()

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$validatorPath = Join-Path $repositoryRoot 'scripts\Test-PSOBBGraphicsProfiles.ps1'
$profilesPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
$evidencePath = Join-Path $repositoryRoot 'config\graphics-evidence.json'
$sourcesPath = Join-Path $repositoryRoot 'config\sources.lock.json'
$results = [System.Collections.Generic.List[object]]::new()

function Add-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Detail)

    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function Invoke-MutatedContractFailure {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Mutation
    )

    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'psobb-graphics-contract-' + [Guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($temporaryRoot)
    try {
        $temporaryProfiles = Join-Path $temporaryRoot 'graphics-profiles.json'
        $temporaryEvidence = Join-Path $temporaryRoot 'graphics-evidence.json'
        $temporarySources = Join-Path $temporaryRoot 'sources.lock.json'
        Copy-Item -LiteralPath $profilesPath -Destination $temporaryProfiles
        Copy-Item -LiteralPath $evidencePath -Destination $temporaryEvidence
        Copy-Item -LiteralPath $sourcesPath -Destination $temporarySources

        $profiles = Get-Content -Raw -LiteralPath $temporaryProfiles | ConvertFrom-Json -Depth 50
        $evidence = Get-Content -Raw -LiteralPath $temporaryEvidence | ConvertFrom-Json -Depth 50
        $sources = Get-Content -Raw -LiteralPath $temporarySources | ConvertFrom-Json -Depth 50
        & $Mutation $profiles $evidence $sources
        [System.IO.File]::WriteAllText(
            $temporaryProfiles,
            ($profiles | ConvertTo-Json -Depth 50),
            [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText(
            $temporaryEvidence,
            ($evidence | ConvertTo-Json -Depth 50),
            [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText(
            $temporarySources,
            ($sources | ConvertTo-Json -Depth 50),
            [System.Text.UTF8Encoding]::new($false))

        $failedClosed = $false
        $message = ''
        try {
            & $validatorPath `
                -ProfilesPath $temporaryProfiles `
                -EvidencePath $temporaryEvidence `
                -SourcesLockPath $temporarySources `
                -Quiet 2>$null | Out-Null
        } catch {
            $failedClosed = $true
            $message = $_.Exception.Message
        }
        Add-TestResult -Name $Name -Passed $failedClosed -Detail $message
    } finally {
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
        }
    }
}

function Set-AcceptedGraphicsCandidate {
    param(
        [Parameter(Mandatory)][object]$Candidate,
        [Parameter(Mandatory)][object]$Profile
    )

    $Candidate.stage = 'evidence-complete'
    $Candidate.disposition = 'accepted'
    $Candidate.blockers = @()
    $Candidate.rejectionReason = $null
    foreach ($gate in $Candidate.gates.PSObject.Properties) {
        $gate.Value.state = 'pass'
        if (@($gate.Value.artifactRefs).Count -eq 0) {
            $gate.Value.artifactRefs = @('repo:config/graphics-evidence.json')
        }
    }

    $Profile.display.selectedInternalRender = $Profile.display.internalRenderCandidates[0]
    $Profile.display.selectedScalingFilter = [string]$Profile.display.scalingFilterCandidates[0]
    $Profile.display.selectedWindowMode = [string]$Profile.display.windowModes[0]
    $Profile.quality.selectedMsaa = $Profile.quality.msaaCandidates[0]
    $Profile.quality.selectedVirtualVramMb = $Profile.quality.virtualVramMbCandidates[0]
    $Profile.quality.selectedVsyncOwner = [string]$Profile.quality.vsyncOwnerCandidates[0]
    if (@($Profile.postProcessing.strengthCandidates).Count -gt 0) {
        $Profile.postProcessing.selectedStrength = $Profile.postProcessing.strengthCandidates[0]
    }
}

$productionPassed = $false
$productionDetail = ''
try {
    $production = & $validatorPath -Quiet
    $productionPassed = ($production.Failed -eq 0) -and ($production.Profiles -eq 10)
    $productionDetail = "checks=$($production.Passed); profiles=$($production.Profiles)"
} catch {
    $productionDetail = $_.Exception.Message
}
Add-TestResult 'production graphics contracts validate' $productionPassed $productionDetail

$productionEvidence = Get-Content -Raw -LiteralPath $evidencePath |
    ConvertFrom-Json -Depth 50
$completionStateFailClosed =
    ($productionEvidence.LocalPrivateGraphicallyAccepted -eq $false) -and
    ($productionEvidence.PublicDistributableGraphicallyAccepted -eq $false)
Add-TestResult `
    'graphical completion state remains explicitly pending' `
    $completionStateFailClosed `
    ("local={0}; public={1}" -f
        $productionEvidence.LocalPrivateGraphicallyAccepted,
        $productionEvidence.PublicDistributableGraphicallyAccepted)
$expectedAssetMatrix = @(
    'ashenbubs-hd-psobb-v1.02-local-import|10|pending|immutable-foundation|composed-activation-manifest|ashenbubs-hd-psobb-v1.02-local-import',
    'luthee-hd-ui-v1.1.6-local-import|20|rejected|additive-no-foundation-collision|source-lock-member-map|luthee-hd-ui-v1.1.6-local-import',
    'higher-resolution-item-box-textures-2025-12-30-local-import|30|rejected|additive-no-foundation-collision|source-lock-member-map|higher-resolution-item-box-textures-2025-12-30-local-import',
    'echelon-hd-effects-technics-2019-05-27-local-import|40|rejected|reject-immutable-foundation-collision|source-lock-conflict-map|ashenbubs-hd-psobb-v1.02-local-import',
    'echelon-hd-blood-2018-06-16-local-import|50|rejected|reject-immutable-foundation-collision|source-lock-conflict-map|ashenbubs-hd-psobb-v1.02-local-import'
)
$actualAssetMatrix = @($productionEvidence.assetCandidates | ForEach-Object {
    '{0}|{1}|{2}|{3}|{4}|{5}' -f
        [string]$_.componentId,
        [int]$_.activationOrder,
        [string]$_.disposition,
        [string]$_.collisionPolicy,
        [string]$_.destinationOwnership.source,
        [string]$_.destinationOwnership.ownerComponentId
})
$rejectedAssetCandidates = @($productionEvidence.assetCandidates | Where-Object {
    [string]$_.disposition -ceq 'rejected'
})
$assetMatrixExact =
    ($actualAssetMatrix.Count -eq $expectedAssetMatrix.Count) -and
    (@(Compare-Object $expectedAssetMatrix $actualAssetMatrix -SyncWindow 0 -CaseSensitive).Count -eq 0) -and
    ($rejectedAssetCandidates.Count -eq 4) -and
    (@($rejectedAssetCandidates | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.rejectionReason)
    }).Count -eq 0)
Add-TestResult `
    'asset candidate matrix preserves exact order and dispositions' `
    $assetMatrixExact `
    ($actualAssetMatrix -join '; ')
$rejectedIds = @($productionEvidence.candidates | Where-Object {
    [string]$_.disposition -ceq 'rejected'
} | ForEach-Object { [string]$_.profileId })
$expectedRejectedIds = @(
    'cleanroom-widescreen-canary',
    'cas-evaluation-16x10',
    'dxvk-canary',
    'd3d8to9-canary'
)
$referenceWide = @($productionEvidence.candidates | Where-Object {
    [string]$_.profileId -ceq 'lab-widescreen-16x10'
})[0]
$referenceCas = @($productionEvidence.candidates | Where-Object {
    [string]$_.profileId -ceq 'lab-widescreen-cas-16x10'
})[0]
$privateHd = @($productionEvidence.candidates | Where-Object {
    [string]$_.profileId -ceq 'lab-widescreen-hd-16x10'
})[0]
$reconciledDispositionsValid =
    (@(Compare-Object $expectedRejectedIds $rejectedIds -CaseSensitive).Count -eq 0) -and
    ([string]$referenceWide.stage -ceq 'runtime-verified') -and
    ([string]$referenceWide.disposition -ceq 'pending') -and
    ([string]$referenceWide.gates.runtimeModuleAllowlist.state -ceq 'pass') -and
    ([string]$referenceWide.gates.liveWindow.state -ceq 'pass') -and
    ([string]$referenceCas.stage -ceq 'runtime-verified') -and
    ([string]$referenceCas.disposition -ceq 'pending') -and
    ([string]$referenceCas.gates.runtimeModuleAllowlist.state -ceq 'pending') -and
    (@($referenceCas.gates.runtimeModuleAllowlist.artifactRefs).Count -eq 0) -and
    ([string]$referenceCas.gates.runtimeModuleAllowlist.note -cmatch 'canonical relocation') -and
    ([string]$referenceCas.gates.liveWindow.state -ceq 'pass') -and
    ([string]$privateHd.stage -ceq 'runtime-verified') -and
    ([string]$privateHd.disposition -ceq 'pending') -and
    ([string]$privateHd.gates.runtimeModuleAllowlist.state -ceq 'pass') -and
    ([string]$privateHd.gates.liveWindow.state -ceq 'pending') -and
    ([string]$privateHd.gates.framePacing.state -ceq 'pass') -and
    ([string]$privateHd.gates.stabilitySoak.state -ceq 'pending') -and
    ([string]$privateHd.gates.rollback.state -ceq 'pending') -and
    ([string]$privateHd.gates.framePacing.note -cmatch 'exact High-profile') -and
    (@($privateHd.gates.framePacing.artifactRefs).Count -gt 0) -and
    (@($privateHd.gates.stabilitySoak.artifactRefs).Count -gt 0) -and
    (@($privateHd.gates.rollback.artifactRefs).Count -gt 0) -and
    ([string]$privateHd.gates.casHaloAndClipping.state -ceq 'not-applicable')
Add-TestResult `
    'runtime dispositions preserve exact rejections and current HD evidence' `
    $reconciledDispositionsValid `
    ("rejected={0}; wide={1}/{2}; cas={3}/{4}; hd={5}/{6}" -f
        ($rejectedIds -join ','),
        $referenceWide.stage,
        $referenceWide.disposition,
        $referenceCas.stage,
        $referenceCas.disposition,
        $privateHd.stage,
        $privateHd.disposition)

$casGateNote = [string]$referenceCas.gates.casHaloAndClipping.note
$frameGateNote = [string]$referenceCas.gates.framePacing.note
$casArtifactRefs = @($referenceCas.gates.casHaloAndClipping.artifactRefs |
    ForEach-Object { [string]$_ })
$frameArtifactRefs = @($referenceCas.gates.framePacing.artifactRefs |
    ForEach-Object { [string]$_ })
$casReconciliationValid =
    ([string]$referenceCas.gates.casHaloAndClipping.state -ceq 'pending') -and
    ($casGateNote -cmatch '12 exact-black pixels \(0\.000293%\)') -and
    ($casGateNote -cmatch '6\.27451% maximum halo overshoot') -and
    ($casGateNote -cmatch '3% limit \(p95 2\.352941%\)') -and
    ($frameGateNote -cmatch 'actually captured character selection') -and
    ($frameGateNote -cmatch 'quarantined from lobby acceptance') -and
    (@($casArtifactRefs | Where-Object {
        $_ -cmatch 'cas-0\.15\.json#sha256=4b029bdce40f393dea86b77cbd070e20605fc1e3d7aef8e4260e8ac50fba86a5$'
    }).Count -eq 1) -and
    (@($frameArtifactRefs | Where-Object {
        $_ -cmatch 'capture-manifest\.json#sha256=c0ff966b0b4da34be48f5f5b6ad3bf496fa2b62d44b2971465855b55916b4614$'
    }).Count -eq 1)
Add-TestResult `
    'CAS 0.15 failure and mislabeled 0.25 trace remain explicit' `
    $casReconciliationValid `
    '0.15 metrics are exact; the character-selection trace cannot satisfy lobby acceptance'

Invoke-MutatedContractFailure 'competing D3D8 owner is rejected' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-16x10')[0]
    $profile.renderer.secondaryLayers = @($profile.renderer.secondaryLayers) + [pscustomobject]@{
        componentId = 'd3d8to9-x86'
        relativePath = 'd3d8.dll'
        role = 'translation-dependency'
        declaredOrder = 99
    }
}

Invoke-MutatedContractFailure 'true-widescreen render above 3840x2400 is rejected' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'fidelity-modern-16x10')[0]
    $profile.display.internalRenderCandidates[1].width = 5120
    $profile.display.internalRenderCandidates[1].height = 3200
}

Invoke-MutatedContractFailure 'native GRAPHICCTRL vector and SHA cannot drift independently' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $profile.nativeGraphics.graphicCtrlDwords[0] = 1
}

Invoke-MutatedContractFailure 'pending profile cannot preselect virtual VRAM' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $profile.quality.selectedVirtualVramMb = 1024
}

Invoke-MutatedContractFailure 'pending profile cannot preselect its VSync winner' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $profile.quality.selectedVsyncOwner = 'dgvoodoo'
}

Invoke-MutatedContractFailure 'asset candidate matrix cannot omit a required candidate' {
    param($profiles, $evidence, $sources)

    $evidence.assetCandidates = @($evidence.assetCandidates | Select-Object -Skip 1)
}

Invoke-MutatedContractFailure 'asset candidate activation order cannot be reordered' {
    param($profiles, $evidence, $sources)

    $first = $evidence.assetCandidates[0]
    $evidence.assetCandidates[0] = $evidence.assetCandidates[1]
    $evidence.assetCandidates[1] = $first
}

Invoke-MutatedContractFailure 'rejected Echelon collision cannot return to pending' {
    param($profiles, $evidence, $sources)

    $candidate = @($evidence.assetCandidates | Where-Object {
        [string]$_.componentId -ceq 'echelon-hd-effects-technics-2019-05-27-local-import'
    })[0]
    $candidate.disposition = 'pending'
    $candidate.rejectionReason = $null
}

Invoke-MutatedContractFailure 'accepted HD assets must follow accepted activation order' {
    param($profiles, $evidence, $sources)

    foreach ($assetCandidate in @($evidence.assetCandidates | Select-Object -First 3)) {
        $assetCandidate.disposition = 'accepted'
    }
    $profile = @($profiles.profiles | Where-Object {
        [string]$_.id -ceq 'lab-widescreen-hd-16x10'
    })[0]
    $candidate = @($evidence.candidates | Where-Object {
        [string]$_.profileId -ceq 'lab-widescreen-hd-16x10'
    })[0]
    Set-AcceptedGraphicsCandidate -Candidate $candidate -Profile $profile
    $profile.selectedAssetComponentIds = @(
        'luthee-hd-ui-v1.1.6-local-import',
        'ashenbubs-hd-psobb-v1.02-local-import',
        'higher-resolution-item-box-textures-2025-12-30-local-import'
    )
}

Invoke-MutatedContractFailure 'local completion requires every asset disposition to be closed' {
    param($profiles, $evidence, $sources)

    foreach ($profileId in @('safe-native-4x3', 'lab-widescreen-16x10')) {
        $profile = @($profiles.profiles | Where-Object {
            [string]$_.id -ceq $profileId
        })[0]
        $candidate = @($evidence.candidates | Where-Object {
            [string]$_.profileId -ceq $profileId
        })[0]
        Set-AcceptedGraphicsCandidate -Candidate $candidate -Profile $profile
    }
    $evidence.LocalPrivateGraphicallyAccepted = $true
}

Invoke-MutatedContractFailure 'local completion requires the accepted HD foundation profile' {
    param($profiles, $evidence, $sources)

    $ashenbubs = @($evidence.assetCandidates | Where-Object {
        [string]$_.componentId -ceq 'ashenbubs-hd-psobb-v1.02-local-import'
    })[0]
    $ashenbubs.disposition = 'accepted'
    $ashenbubs.artifactRefs = @(
        'repo:config/sources.lock.json',
        ('runtime:local-lab/asset-activations/ashenbubs-hd-psobb-v1.02/' +
            'current/activation.json#sha256=' + ('a' * 64)))

    foreach ($profileId in @('safe-native-4x3', 'lab-widescreen-16x10')) {
        $profile = @($profiles.profiles | Where-Object {
            [string]$_.id -ceq $profileId
        })[0]
        $candidate = @($evidence.candidates | Where-Object {
            [string]$_.profileId -ceq $profileId
        })[0]
        Set-AcceptedGraphicsCandidate -Candidate $candidate -Profile $profile
    }
    $evidence.LocalPrivateGraphicallyAccepted = $true
}

Invoke-MutatedContractFailure 'accepted disposition without evidence is rejected' {
    param($profiles, $evidence, $sources)

    $candidate = @($evidence.candidates | Where-Object profileId -eq 'clarity-dgvoodoo-4x3')[0]
    $candidate.stage = 'evidence-complete'
    $candidate.disposition = 'accepted'
}

Invoke-MutatedContractFailure 'pending artifact hash drift is rejected' {
    param($profiles, $evidence, $sources)

    $candidate = @($evidence.candidates | Where-Object {
        [string]$_.profileId -ceq 'clarity-dgvoodoo-4x3'
    })[0]
    $candidate.gates.runtimeModuleAllowlist.artifactRefs = @(
        'runtime:canary/runtime/client/missing-profile.json#sha256=' + ('0' * 64))
}

Invoke-MutatedContractFailure 'accepted profile cannot retain unresolved selections' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $candidate = @($evidence.candidates | Where-Object profileId -eq 'lab-widescreen-hd-16x10')[0]
    $candidate.stage = 'evidence-complete'
    $candidate.disposition = 'accepted'
    $candidate.blockers = @()
    $candidate.rejectionReason = $null
    foreach ($gate in $candidate.gates.PSObject.Properties) {
        $gate.Value.state = 'pass'
        if (@($gate.Value.artifactRefs).Count -eq 0) {
            $gate.Value.artifactRefs = @('repo:config/graphics-evidence.json')
        }
    }
    $profile.quality.selectedVirtualVramMb = 256
    $profile.quality.selectedVsyncOwner = 'none'
}

Invoke-MutatedContractFailure 'local completion cannot bypass accepted profile prerequisites' {
    param($profiles, $evidence, $sources)

    $evidence.LocalPrivateGraphicallyAccepted = $true
}

Invoke-MutatedContractFailure 'public completion cannot bypass local completion' {
    param($profiles, $evidence, $sources)

    $evidence.PublicDistributableGraphicallyAccepted = $true
}

Invoke-MutatedContractFailure 'project-owned shader hash drift is rejected' {
    param($profiles, $evidence, $sources)

    $component = @($sources.components | Where-Object id -eq 'psobb-neutral-cas-source')[0]
    $component.sha256 = '0000000000000000000000000000000000000000000000000000000000000000'
}

Invoke-MutatedContractFailure 'source-lock generation cannot predate provenance checks' {
    param($profiles, $evidence, $sources)

    $sources.generatedAtUtc = '2026-01-01T00:00:00Z'
}

Invoke-MutatedContractFailure 'clean-room profile cannot silently add ReShade' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'cleanroom-widescreen-canary')[0]
    $profile.renderer.secondaryLayers = @($profile.renderer.secondaryLayers) + [pscustomobject]@{
        componentId = 'reshade-6.7.3-local-import'
        relativePath = 'dxgi.dll'
        role = 'post-process'
        declaredOrder = 40
    }
}

Invoke-MutatedContractFailure 'CAS evaluation rejects unapproved strength' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'cas-evaluation-16x10')[0]
    $profile.postProcessing.strengthCandidates[1] = 0.2
}

Invoke-MutatedContractFailure 'reference CAS cannot claim clean-room enhancement readiness' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-cas-16x10')[0]
    $profile.renderer.secondaryLayers[1].componentId = 'project-owned-psobb-enhancement'
}

Invoke-MutatedContractFailure 'HD profile cannot add CAS' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $profile.postProcessing.effectComponentId = 'psobb-neutral-cas-source'
    $profile.postProcessing.strengthCandidates = @(0.15)
}

Invoke-MutatedContractFailure 'HD profile cannot change its private asset component' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $profile.localAssetOverlay.componentId = 'psobb-widescreen-local-evaluation'
}

Invoke-MutatedContractFailure 'HD profile cannot change its exact large-assets capability' {
    param($profiles, $evidence, $sources)

    $profile = @($profiles.profiles | Where-Object id -eq 'lab-widescreen-hd-16x10')[0]
    $profile.localModules[0].capability = 'generic-large-assets'
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) graphics-profile regression test(s) failed"
}
[pscustomobject]@{
    Suite = 'GraphicsProfileRegression'
    Passed = $results.Count
    Failed = 0
}
