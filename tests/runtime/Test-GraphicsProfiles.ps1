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
    ([string]$referenceCas.gates.runtimeModuleAllowlist.state -ceq 'pass') -and
    ([string]$referenceCas.gates.liveWindow.state -ceq 'pass') -and
    ([string]$privateHd.stage -ceq 'runtime-verified') -and
    ([string]$privateHd.disposition -ceq 'pending') -and
    ([string]$privateHd.gates.casHaloAndClipping.state -ceq 'not-applicable')
Add-TestResult `
    'runtime graphics dispositions preserve accepted loads and exact rejections' `
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

Invoke-MutatedContractFailure 'accepted disposition without evidence is rejected' {
    param($profiles, $evidence, $sources)

    $candidate = @($evidence.candidates | Where-Object profileId -eq 'clarity-dgvoodoo-4x3')[0]
    $candidate.stage = 'evidence-complete'
    $candidate.disposition = 'accepted'
}

Invoke-MutatedContractFailure 'project-owned shader hash drift is rejected' {
    param($profiles, $evidence, $sources)

    $component = @($sources.components | Where-Object id -eq 'psobb-neutral-cas-source')[0]
    $component.sha256 = '0000000000000000000000000000000000000000000000000000000000000000'
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
