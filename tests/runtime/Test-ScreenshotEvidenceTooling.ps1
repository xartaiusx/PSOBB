[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$toolPath = Join-Path $repositoryRoot 'scripts\Get-PSOBBScreenshotEvidence.ps1'
$analyzerPath = Join-Path $repositoryRoot 'scripts\support\PSOBB.ScreenshotAnalyzer.cs'
$toolSource = Get-Content -Raw -LiteralPath $toolPath
$analyzerSource = Get-Content -Raw -LiteralPath $analyzerPath
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
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

foreach ($sourcePath in @($toolPath, $analyzerPath)) {
    if ($sourcePath.EndsWith('.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $sourcePath,
            [ref]$tokens,
            [ref]$parseErrors) | Out-Null
        Add-Result `
            -Name "$(Split-Path -Leaf $sourcePath) parses cleanly" `
            -Passed ($parseErrors.Count -eq 0) `
            -Detail "$($parseErrors.Count) parser error(s)"
    }
}

$sourceOnlyContract =
    $toolSource -match 'PSOBB\.ScreenshotAnalyzer\.cs' -and
    $toolSource -match 'System\.Drawing\.Common\.dll' -and
    $toolSource -notmatch '(?i)python|pillow|numpy|imagemagick|download|invoke-webrequest' -and
    $analyzerSource -notmatch '(?i)http://|https://|nuget'
Add-Result 'analyzer uses only source and Windows/.NET platform assemblies' `
    $sourceOnlyContract 'no Python, package, download, or production dependency'

$privacyContract =
    $toolSource -match 'Assert-PSOBBPathOutsideTrackedSource' -and
    $toolSource -match 'rawArtifactsCopiedIntoRepository\s*=\s*\$false' -and
    $toolSource -match 'rawPathsRecorded\s*=\s*\$false' -and
    $toolSource -match 'rawFileNamesRecorded\s*=\s*\$false' -and
    $toolSource -match 'Refusing to overwrite an existing screenshot index'
Add-Result 'private PNG and redacted-index boundaries are explicit' `
    $privacyContract 'raw inputs stay in ignored runtime state; JSON output is path-free and atomic'

$metricContract =
    $analyzerSource -match 'DetectedLeftPillarWidthPixels' -and
    $analyzerSource -match 'MeanAbsoluteGradient' -and
    $analyzerSource -match 'P95AbsoluteGradient' -and
    $analyzerSource -match 'LaplacianVariance' -and
    $analyzerSource -match 'IntroducedBlackClipPixelCount' -and
    $analyzerSource -match 'MaximumHaloOvershootPercent' -and
    $toolSource -match 'caller-supplied-landmark-diameters'
Add-Result 'required pillar, sharpness, geometry, clipping, and halo metrics exist' `
    $metricContract 'edge bands, gradients, Laplacian, landmarks, and CAS deltas'

Add-Type -AssemblyName System.Drawing

function New-PatternPng {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('reference', 'cas-pass', 'cas-fail', 'pillar')]
        [string]$Variant
    )

    $width = 320
    $height = 200
    $bitmap = [System.Drawing.Bitmap]::new(
        $width,
        $height,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        for ($y = 0; $y -lt $height; $y++) {
            for ($x = 0; $x -lt $width; $x++) {
                if ($Variant -ceq 'pillar' -and ($x -lt 27 -or $x -ge 293)) {
                    $value = 0
                } else {
                    $checker = (([Math]::Floor($x / 20) + [Math]::Floor($y / 20)) % 2) -eq 0
                    $value = if ($checker) { 64 } else { 192 }
                    if ($Variant -in @('cas-pass', 'cas-fail') -and
                        $x -gt 0 -and ($x % 20) -eq 0) {
                        if ($Variant -ceq 'cas-pass') {
                            $value = if ($checker) { 60 } else { 196 }
                        } else {
                            $value = if ($checker) { 0 } else { 255 }
                        }
                    }
                }
                $bitmap.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(
                    255,
                    $value,
                    $value,
                    $value))
            }
        }
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bitmap.Dispose()
    }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-ScreenshotTests-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
try {
    $referencePath = Join-Path $temporaryRoot 'reference-private.png'
    $passingPath = Join-Path $temporaryRoot 'candidate-pass-private.png'
    $failingPath = Join-Path $temporaryRoot 'candidate-fail-private.png'
    $pillarPath = Join-Path $temporaryRoot 'pillar-private.png'
    $specPath = Join-Path $temporaryRoot 'validation.json'
    $indexPath = Join-Path $temporaryRoot 'redacted-index.json'

    New-PatternPng -Path $referencePath -Variant reference
    New-PatternPng -Path $passingPath -Variant cas-pass
    New-PatternPng -Path $failingPath -Variant cas-fail
    New-PatternPng -Path $pillarPath -Variant pillar

    $spec = [ordered]@{
        schemaVersion = 1
        expectedOutput = [ordered]@{ width = 320; height = 200 }
        expectedOutputAspectRatio = 1.6
        expectedContentAspectRatio = 1.6
        maximumAspectErrorPercent = 0.1
        maximumPillarSymmetryDeltaPixels = 1
        requiresCircleChecks = $true
        casExpected = $true
        maximumCasHaloOvershootPercent = 3
        circles = @(
            [ordered]@{
                id = 'hud-circle'
                horizontalDiameterPixels = 50
                verticalDiameterPixels = 50
                maximumAxisErrorPercent = 0.1
            }
        )
        aspects = @(
            [ordered]@{
                id = 'viewport-landmarks'
                observedWidthPixels = 160
                observedHeightPixels = 100
                expectedRatio = 1.6
                maximumErrorPercent = 0.1
            }
        )
    }
    [System.IO.File]::WriteAllText(
        $specPath,
        ($spec | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))

    $accepted = & $toolPath `
        -ScreenshotPath $passingPath `
        -ReferencePath $referencePath `
        -ProfileId 'lab-widescreen-16x10' `
        -CandidateId 'cas-0.15' `
        -SceneId 'synthetic-grid' `
        -ValidationSpecPath $specPath `
        -EdgeBandWidth 16 `
        -Disposition accepted `
        -OutputPath $indexPath

    $expectedHash = (Get-FileHash -LiteralPath $passingPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $artifactValid =
        [string]$accepted.candidate.artifact.sha256 -ceq $expectedHash -and
        [int]$accepted.candidate.artifact.width -eq 320 -and
        [int]$accepted.candidate.artifact.height -eq 200 -and
        [long]$accepted.candidate.artifact.byteSize -eq (Get-Item $passingPath).Length -and
        [long]$accepted.candidate.artifact.nonOpaquePixelCount -eq 0
    Add-Result 'PNG identity records exact SHA-256, byte size, dimensions, and alpha state' `
        $artifactValid "hash=$($accepted.candidate.artifact.sha256); 320x200"

    $sharpnessValid =
        [long]$accepted.candidate.sharpness.sampleCount -gt 0 -and
        [double]$accepted.candidate.sharpness.meanAbsoluteGradient -gt 0 -and
        [double]$accepted.candidate.sharpness.p95AbsoluteGradient -gt 0 -and
        [double]$accepted.candidate.sharpness.laplacianVariance -gt 0 -and
        [double]$accepted.candidate.sharpness.edgeDensityPercent -gt 0
    Add-Result 'objective sharpness metrics are populated from active content' `
        $sharpnessValid "gradient=$($accepted.candidate.sharpness.meanAbsoluteGradient); laplacian=$($accepted.candidate.sharpness.laplacianVariance)"

    $geometryValid =
        [string]$accepted.geometry.state -ceq 'pass' -and
        @($accepted.geometry.checks | Where-Object state -ceq 'fail').Count -eq 0 -and
        [string]$accepted.geometry.circles[0].id -ceq 'hud-circle' -and
        [double]$accepted.geometry.circles[0].errorPercent -eq 0 -and
        [string]$accepted.geometry.aspects[0].id -ceq 'viewport-landmarks' -and
        [double]$accepted.geometry.aspects[0].errorPercent -eq 0
    Add-Result 'dimension, aspect, pillar, circle, and landmark hooks pass' `
        $geometryValid "checks=$(@($accepted.geometry.checks).Count)"

    $casPassValid =
        [string]$accepted.gates.casHaloAndClipping -ceq 'pass' -and
        [long]$accepted.comparison.halo.referenceEdgeSampleCount -gt 0 -and
        [double]$accepted.comparison.halo.maximumOvershootPercent -gt 0 -and
        [double]$accepted.comparison.halo.maximumOvershootPercent -le 3 -and
        [long]$accepted.comparison.clipping.introducedBlackPixelCount -eq 0 -and
        [long]$accepted.comparison.clipping.introducedWhitePixelCount -eq 0 -and
        [string]$accepted.disposition.automaticTechnicalState -ceq 'pass'
    Add-Result 'CAS comparison passes bounded overshoot with no introduced clipping' `
        $casPassValid "maxHalo=$($accepted.comparison.halo.maximumOvershootPercent)%"

    $writtenJson = [System.IO.File]::ReadAllText($indexPath)
    $writtenIndex = $writtenJson | ConvertFrom-Json -Depth 30
    $redactedValid =
        [int]$writtenIndex.schemaVersion -eq 1 -and
        -not $writtenJson.Contains($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $writtenJson.Contains('candidate-pass-private.png', [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $writtenJson.Contains('reference-private.png', [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $writtenIndex.privacy.rawArtifactsCopiedIntoRepository -and
        -not $writtenIndex.privacy.rawPathsRecorded -and
        -not $writtenIndex.privacy.rawFileNamesRecorded
    Add-Result 'written JSON index is reusable and contains no raw path or filename' `
        $redactedValid $indexPath

    $pillar = & $toolPath `
        -ScreenshotPath $pillarPath `
        -ProfileId 'clarity-dgvoodoo-4x3' `
        -CandidateId 'pillar-baseline' `
        -SceneId 'synthetic-grid' `
        -EdgeBandWidth 16
    $pillarValid =
        [int]$pillar.candidate.edgeBands.detectedLeftPillarWidthPixels -eq 27 -and
        [int]$pillar.candidate.edgeBands.detectedRightPillarWidthPixels -eq 27 -and
        [int]$pillar.candidate.edgeBands.pillarSymmetryDeltaPixels -eq 0 -and
        [int]$pillar.candidate.edgeBands.activeContentWidthPixels -eq 266 -and
        [string]$pillar.gates.geometry -ceq 'pending'
    Add-Result 'edge-band analysis detects exact symmetric synthetic pillars' `
        $pillarValid "left=$($pillar.candidate.edgeBands.detectedLeftPillarWidthPixels); right=$($pillar.candidate.edgeBands.detectedRightPillarWidthPixels)"

    $failedCas = & $toolPath `
        -ScreenshotPath $failingPath `
        -ReferencePath $referencePath `
        -ProfileId 'lab-widescreen-16x10' `
        -CandidateId 'cas-rejected' `
        -SceneId 'synthetic-grid' `
        -ValidationSpecPath $specPath `
        -EdgeBandWidth 16 `
        -Disposition rejected `
        -RejectionReason 'Introduces clipping and exceeds the halo limit'
    $casFailureValid =
        [string]$failedCas.gates.casHaloAndClipping -ceq 'fail' -and
        [string]$failedCas.disposition.automaticTechnicalState -ceq 'fail' -and
        [string]$failedCas.disposition.state -ceq 'rejected' -and
        ([long]$failedCas.comparison.clipping.introducedBlackPixelCount -gt 0 -or
            [long]$failedCas.comparison.clipping.introducedWhitePixelCount -gt 0) -and
        [double]$failedCas.comparison.halo.maximumOvershootPercent -gt 3
    Add-Result 'CAS clipping or halo excess produces a failed technical gate' `
        $casFailureValid "maxHalo=$($failedCas.comparison.halo.maximumOvershootPercent)%"

    $falseAcceptanceRejected = $false
    try {
        & $toolPath `
            -ScreenshotPath $failingPath `
            -ReferencePath $referencePath `
            -ProfileId 'lab-widescreen-16x10' `
            -CandidateId 'cas-false-acceptance' `
            -SceneId 'synthetic-grid' `
            -ValidationSpecPath $specPath `
            -EdgeBandWidth 16 `
            -Disposition accepted | Out-Null
    } catch {
        $falseAcceptanceRejected = $_.Exception.Message -match 'automatic technical state is fail'
    }
    Add-Result 'failed automatic evidence cannot be marked accepted' `
        $falseAcceptanceRejected 'acceptance fails closed before writing an index'

    $missingGeometryRejected = $false
    try {
        & $toolPath `
            -ScreenshotPath $passingPath `
            -ProfileId 'lab-widescreen-16x10' `
            -CandidateId 'missing-geometry' `
            -SceneId 'synthetic-grid' `
            -Disposition accepted | Out-Null
    } catch {
        $missingGeometryRejected = $_.Exception.Message -match 'automatic technical state is pending'
    }
    Add-Result 'acceptance requires an explicit geometry validation specification' `
        $missingGeometryRejected 'unannotated geometry remains pending'

    $overwriteRejected = $false
    try {
        & $toolPath `
            -ScreenshotPath $passingPath `
            -ProfileId 'lab-widescreen-16x10' `
            -CandidateId 'overwrite-attempt' `
            -SceneId 'synthetic-grid' `
            -OutputPath $indexPath | Out-Null
    } catch {
        $overwriteRejected = $_.Exception.Message -match 'Refusing to overwrite'
    }
    Add-Result 'existing redacted index is never overwritten silently' `
        $overwriteRejected 'caller must choose a new evidence index path'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) screenshot evidence tooling test(s) failed"
}
[pscustomobject]@{
    Suite = 'ScreenshotEvidenceTooling'
    Passed = $results.Count
    Failed = 0
}
