[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string]$SceneId,
    [Parameter(Mandatory)][string]$ValidationSpecPath,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')]
    [string]$RunId,
    [ValidateRange(2, 10)][int]$StableObservationCount = 3,
    [ValidateRange(50, 5000)][int]$PollMilliseconds = 250,
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'support\PSOBB.CasF10Pair.ps1')

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$profile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
$allowedProfiles = @('lab-widescreen-cas-16x10', 'cas-evaluation-16x10')
$allowedStrengths = [double[]]@(0.15, 0.25, 0.35)
if ([string]$profile.profileId -cnotin $allowedProfiles -or
    $null -eq $profile.casStrength -or
    $allowedStrengths -cnotcontains [double]$profile.casStrength) {
    throw 'The LocalLab runtime must be an approved CAS profile materialized at exactly 0.15, 0.25, or 0.35'
}

$clientExecutable = Get-PSOBBClientExecutablePath -Layout $layout -Channel LocalLab
$clientRoot = Assert-PathWithinRoot -Path (Split-Path -Parent $clientExecutable) -Root $layout.Root
$profilePath = Assert-PathWithinRoot -Path (Join-Path $clientRoot 'client-profile.json') -Root $layout.Root
$profileHash = Get-LowerSha256 -Path $profilePath

$validationSpec = Get-Item -LiteralPath $ValidationSpecPath -Force -ErrorAction Stop
if ($validationSpec.PSIsContainer -or $validationSpec.Extension -ine '.json' -or
    ($validationSpec.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $validationSpec.Length -le 0 -or $validationSpec.Length -gt 1MB) {
    throw 'ValidationSpecPath must identify one regular bounded JSON file'
}

$pair = Get-PSOBBCasF10Pair -SourceDirectory $clientRoot
$stable = Wait-PSOBBCasF10PairStable `
    -Pair $pair `
    -StableObservationCount $StableObservationCount `
    -PollMilliseconds $PollMilliseconds `
    -TimeoutSeconds $TimeoutSeconds

# Re-enumerate immediately before moving so a second F10 press or an unrelated
# PNG cannot silently enter an evidence run after the stability observation.
$confirmedPair = Get-PSOBBCasF10Pair -SourceDirectory $clientRoot
if ($confirmedPair.Stem -cne $pair.Stem -or
    $confirmedPair.BeforePath -cne $pair.BeforePath -or
    $confirmedPair.AfterPath -cne $pair.AfterPath) {
    throw 'The ReShade F10 screenshot inventory changed after stability verification'
}

$strength = [double]$profile.casStrength
$strengthText = $strength.ToString('0.00', [System.Globalization.CultureInfo]::InvariantCulture)
$strengthSlug = switch ($strengthText) {
    '0.15' { '015' }
    '0.25' { '025' }
    '0.35' { '035' }
    default { throw "Unsupported CAS strength: $strengthText" }
}
$candidateId = "cas-$strengthText"
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = 'cas-comparison-' + [DateTime]::UtcNow.ToString(
        'yyyyMMddTHHmmssfffZ',
        [System.Globalization.CultureInfo]::InvariantCulture).ToLowerInvariant() +
        '-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
}

$evidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Root 'graphics-evidence') `
    -Root $layout.Root
$profileEvidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $evidenceRoot ([string]$profile.profileId)) `
    -Root $evidenceRoot
[System.IO.Directory]::CreateDirectory($profileEvidenceRoot) | Out-Null
$finalRoot = Assert-PathWithinRoot `
    -Path (Join-Path $profileEvidenceRoot $RunId) `
    -Root $profileEvidenceRoot
$stagingRoot = Assert-PathWithinRoot `
    -Path (Join-Path $profileEvidenceRoot ('.import-' + [Guid]::NewGuid().ToString('N'))) `
    -Root $profileEvidenceRoot
$analyzerPath = Join-Path $PSScriptRoot 'Get-PSOBBScreenshotEvidence.ps1'
if (-not (Test-Path -LiteralPath $analyzerPath -PathType Leaf)) {
    throw "The screenshot evidence analyzer is missing: $analyzerPath"
}

$analysisCallback = {
    param($beforeStaged, $afterStaged, $indexRoot)

    $beforeMoved = Get-PSOBBCasPngSnapshot -Path $beforeStaged
    $afterMoved = Get-PSOBBCasPngSnapshot -Path $afterStaged
    if ($beforeMoved.Length -ne $stable.Before.Length -or
        $beforeMoved.Sha256 -cne $stable.Before.Sha256 -or
        $afterMoved.Length -ne $stable.After.Length -or
        $afterMoved.Sha256 -cne $stable.After.Sha256) {
        throw 'A CAS screenshot changed between stability verification and evidence staging'
    }
    if (@(Get-ChildItem -LiteralPath $clientRoot -File -Force |
        Where-Object { $_.Extension -ieq '.png' }).Count -ne 0) {
        throw 'A new PNG appeared in the client directory while importing the single F10 pair'
    }

    $indexPath = Join-Path $indexRoot "$candidateId.json"
    $result = & $analyzerPath `
        -ScreenshotPath $afterStaged `
        -ReferencePath $beforeStaged `
        -ProfileId ([string]$profile.profileId) `
        -CandidateId $candidateId `
        -SceneId $SceneId `
        -Channel local-lab `
        -Disposition pending `
        -ValidationSpecPath $validationSpec.FullName `
        -OutputPath $indexPath

    $profileAfter = Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
    if ([string]$profileAfter.profileId -cne [string]$profile.profileId -or
        [double]$profileAfter.casStrength -ne $strength -or
        (Get-LowerSha256 -Path $profilePath) -cne $profileHash) {
        throw 'The LocalLab CAS profile changed while the F10 pair was being analyzed'
    }
    if (@(Get-ChildItem -LiteralPath $clientRoot -File -Force |
        Where-Object { $_.Extension -ieq '.png' }).Count -ne 0) {
        throw 'A new PNG appeared in the client directory while the F10 pair was being analyzed'
    }
    $result
}

$transaction = Move-PSOBBCasF10PairTransactional `
    -SourceBeforePath $pair.BeforePath `
    -SourceAfterPath $pair.AfterPath `
    -StagingRoot $stagingRoot `
    -FinalRoot $finalRoot `
    -BeforeDestinationName "cas-$strengthSlug-before.png" `
    -AfterDestinationName "cas-$strengthSlug-after.png" `
    -Analyze $analysisCallback

[pscustomobject][ordered]@{
    ProfileId = [string]$profile.profileId
    CasStrength = $strength
    CandidateId = $candidateId
    SceneId = $SceneId
    EvidenceRoot = $transaction.PublishedRoot
    BeforePath = $transaction.BeforePath
    AfterPath = $transaction.AfterPath
    IndexPath = Join-Path $transaction.IndexRoot "$candidateId.json"
    AutomaticTechnicalState = [string]$transaction.Analysis.disposition.automaticTechnicalState
    StableObservations = [int]$stable.StableObservations
}
