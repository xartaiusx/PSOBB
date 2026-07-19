[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ScreenshotPath,
    [string]$ReferencePath,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string]$ProfileId,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string]$CandidateId,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string]$SceneId,
    [ValidateSet('stable', 'canary', 'local-lab')]
    [string]$Channel = 'local-lab',
    [ValidateSet('pending', 'accepted', 'rejected')]
    [string]$Disposition = 'pending',
    [ValidateLength(0, 500)]
    [string]$RejectionReason,
    [string]$ValidationSpecPath,
    [ValidateRange(1, 2048)]
    [int]$EdgeBandWidth = 64,
    [ValidateRange(0, 32)]
    [int]$NearBlackThreshold = 8,
    [ValidateRange(50, 100)]
    [double]$PillarColumnNearBlackMinimumPercent = 98,
    [ValidateRange(1, 1020)]
    [int]$SharpnessEdgeThreshold = 32,
    [ValidateRange(1, 510)]
    [int]$HaloReferenceEdgeThreshold = 16,
    [ValidateRange(0, 100)]
    [double]$MaximumCasHaloOvershootPercent = 3,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$analyzerSourcePath = Join-Path $PSScriptRoot 'support\PSOBB.ScreenshotAnalyzer.cs'

function Assert-PSOBBPrivatePngPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Purpose
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not $item.PSIsContainer -and $item.Extension -ieq '.png') {
        $fullPath = [System.IO.Path]::GetFullPath($item.FullName)
        return Assert-PSOBBPathOutsideTrackedSource -Path $fullPath -Purpose $Purpose
    }
    throw "$Purpose must be an existing PNG file"
}

function Get-PSOBBOptionalProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    $property.Value
}

function Assert-PSOBBAllowedProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string]$Context
    )

    $unexpected = @($Object.PSObject.Properties.Name | Where-Object { $_ -notin $Allowed })
    if ($unexpected.Count -gt 0) {
        throw "$Context contains unsupported properties: $($unexpected -join ', ')"
    }
}

function ConvertTo-PSOBBFiniteNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Name,
        [double]$Minimum = 0,
        [double]$Maximum = [double]::MaxValue,
        [switch]$ExclusiveMinimum
    )

    [double]$number = 0
    if (-not [double]::TryParse(
        [string]$Value,
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$number) -or
        [double]::IsNaN($number) -or
        [double]::IsInfinity($number) -or
        $(if ($ExclusiveMinimum) { $number -le $Minimum } else { $number -lt $Minimum }) -or
        $number -gt $Maximum) {
        throw "$Name is outside the accepted numeric range"
    }
    $number
}

function ConvertTo-PSOBBBoolean {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Value -is [bool]) {
        return [bool]$Value
    }
    throw "$Name must be a JSON boolean"
}

function Get-PSOBBAspectErrorPercent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$Observed,
        [Parameter(Mandatory)][double]$Expected
    )

    if ($Observed -le 0 -or $Expected -le 0) {
        return [double]::PositiveInfinity
    }
    [Math]::Round(100.0 * [Math]::Abs(($Observed / $Expected) - 1.0), 6)
}

function New-PSOBBGeometryCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)]$Observed,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][double]$ErrorPercent,
        [Parameter(Mandatory)][double]$MaximumErrorPercent,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$MeasurementSource
    )

    [pscustomobject][ordered]@{
        id = $Id
        kind = $Kind
        observed = $Observed
        expected = $Expected
        errorPercent = if ([double]::IsPositiveInfinity($ErrorPercent)) {
            $null
        } else {
            $ErrorPercent
        }
        maximumErrorPercent = $MaximumErrorPercent
        measurementSource = $MeasurementSource
        state = if ($Passed) { 'pass' } else { 'fail' }
    }
}

function Read-PSOBBValidationSpec {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Extension -ine '.json') {
        throw 'The screenshot validation specification must be a JSON file'
    }
    $json = [System.IO.File]::ReadAllText(
        $item.FullName,
        [System.Text.UTF8Encoding]::new($false, $true))
    $spec = $json | ConvertFrom-Json -Depth 30
    Assert-PSOBBAllowedProperties -Object $spec -Context 'validation specification' -Allowed @(
        'schemaVersion',
        'expectedOutput',
        'expectedOutputAspectRatio',
        'expectedContentAspectRatio',
        'maximumAspectErrorPercent',
        'maximumPillarSymmetryDeltaPixels',
        'requiresCircleChecks',
        'casExpected',
        'maximumCasHaloOvershootPercent',
        'circles',
        'aspects'
    )
    if ([int](Get-PSOBBOptionalProperty -Object $spec -Name 'schemaVersion') -ne 1) {
        throw 'The screenshot validation specification schemaVersion must be 1'
    }
    $spec
}

$normalizedRejectionReason = if ([string]::IsNullOrWhiteSpace($RejectionReason)) {
    $null
} else {
    $RejectionReason
}
if ($null -ne $normalizedRejectionReason -and
    $normalizedRejectionReason -match '(?i)(?:[a-z]:\\|\\\\)') {
    throw 'RejectionReason must not contain an absolute or UNC path'
}
if ($Disposition -ceq 'rejected' -and $null -eq $normalizedRejectionReason) {
    throw 'A rejected screenshot candidate requires a path-free RejectionReason'
}
if ($Disposition -cne 'rejected' -and $null -ne $normalizedRejectionReason) {
    throw 'RejectionReason is valid only when Disposition is rejected'
}

$privateCandidatePath = Assert-PSOBBPrivatePngPath `
    -Path $ScreenshotPath `
    -Purpose 'The candidate screenshot'
if (-not [string]::IsNullOrWhiteSpace($ReferencePath)) {
    $privateReferencePath = Assert-PSOBBPrivatePngPath `
        -Path $ReferencePath `
        -Purpose 'The reference screenshot'
} else {
    $privateReferencePath = $null
}

if ($null -eq ('PSOBB.GraphicsEvidence.ScreenshotAnalyzer' -as [type])) {
    if (-not (Test-Path -LiteralPath $analyzerSourcePath -PathType Leaf)) {
        throw "The screenshot analyzer source is missing: $analyzerSourcePath"
    }
    $analyzerReferences = @(
        'System.Private.CoreLib.dll',
        'System.Runtime.dll',
        'System.Drawing.Common.dll',
        'System.Drawing.Primitives.dll',
        'System.Private.Windows.GdiPlus.dll',
        'System.Private.Windows.Core.dll',
        'System.Security.Cryptography.dll'
    ) | ForEach-Object {
        $assemblyReferencePath = Join-Path $PSHOME $_
        if (-not (Test-Path -LiteralPath $assemblyReferencePath -PathType Leaf)) {
            throw "The supported PowerShell runtime is missing a screenshot analyzer reference: $_"
        }
        $assemblyReferencePath
    }
    Add-Type -Path $analyzerSourcePath -ReferencedAssemblies $analyzerReferences
}

$candidate = [PSOBB.GraphicsEvidence.ScreenshotAnalyzer]::Analyze([string]$privateCandidatePath, [int]$EdgeBandWidth, [int]$NearBlackThreshold, [double]$PillarColumnNearBlackMinimumPercent, [int]$SharpnessEdgeThreshold)

$spec = if (-not [string]::IsNullOrWhiteSpace($ValidationSpecPath)) {
    Read-PSOBBValidationSpec -Path $ValidationSpecPath
} else {
    $null
}
$geometryChecks = [System.Collections.Generic.List[object]]::new()
$circleResults = [System.Collections.Generic.List[object]]::new()
$aspectResults = [System.Collections.Generic.List[object]]::new()
$maximumAspectError = 0.1
$requiresCircleChecks = $false
$casExpected = $null -ne $privateReferencePath

if ($null -ne $spec) {
    $specifiedAspectMaximum = Get-PSOBBOptionalProperty -Object $spec -Name 'maximumAspectErrorPercent'
    if ($null -ne $specifiedAspectMaximum) {
        $maximumAspectError = ConvertTo-PSOBBFiniteNumber `
            -Value $specifiedAspectMaximum `
            -Name 'maximumAspectErrorPercent' `
            -Minimum 0 `
            -Maximum 100
    }
    $specifiedCircleRequirement = Get-PSOBBOptionalProperty `
        -Object $spec `
        -Name 'requiresCircleChecks'
    if ($null -ne $specifiedCircleRequirement) {
        $requiresCircleChecks = ConvertTo-PSOBBBoolean `
            -Value $specifiedCircleRequirement `
            -Name 'requiresCircleChecks'
    }
    $specifiedCasExpectation = Get-PSOBBOptionalProperty -Object $spec -Name 'casExpected'
    if ($null -ne $specifiedCasExpectation) {
        $casExpected = ConvertTo-PSOBBBoolean `
            -Value $specifiedCasExpectation `
            -Name 'casExpected'
    }
    $specifiedCasMaximum = Get-PSOBBOptionalProperty `
        -Object $spec `
        -Name 'maximumCasHaloOvershootPercent'
    if ($null -ne $specifiedCasMaximum) {
        $MaximumCasHaloOvershootPercent = ConvertTo-PSOBBFiniteNumber `
            -Value $specifiedCasMaximum `
            -Name 'maximumCasHaloOvershootPercent' `
            -Minimum 0 `
            -Maximum 100
    }

    $expectedOutput = Get-PSOBBOptionalProperty -Object $spec -Name 'expectedOutput'
    if ($null -ne $expectedOutput) {
        Assert-PSOBBAllowedProperties -Object $expectedOutput -Context 'expectedOutput' `
            -Allowed @('width', 'height')
        $expectedWidth = [int](ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $expectedOutput -Name 'width') `
            -Name 'expectedOutput.width' `
            -Minimum 0 `
            -Maximum 16384 `
            -ExclusiveMinimum)
        $expectedHeight = [int](ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $expectedOutput -Name 'height') `
            -Name 'expectedOutput.height' `
            -Minimum 0 `
            -Maximum 16384 `
            -ExclusiveMinimum)
        $dimensionPass = $candidate.Width -eq $expectedWidth -and
            $candidate.Height -eq $expectedHeight
        $geometryChecks.Add((New-PSOBBGeometryCheck `
            -Id 'output-dimensions' `
            -Kind 'exact-dimensions' `
            -Observed ([pscustomobject]@{ width = $candidate.Width; height = $candidate.Height }) `
            -Expected ([pscustomobject]@{ width = $expectedWidth; height = $expectedHeight }) `
            -ErrorPercent $(if ($dimensionPass) { 0 } else { 100 }) `
            -MaximumErrorPercent 0 `
            -Passed $dimensionPass `
            -MeasurementSource 'decoded-png-ihdr-and-pixels'))
    }

    $expectedOutputAspect = Get-PSOBBOptionalProperty `
        -Object $spec `
        -Name 'expectedOutputAspectRatio'
    if ($null -ne $expectedOutputAspect) {
        $expectedOutputAspect = ConvertTo-PSOBBFiniteNumber `
            -Value $expectedOutputAspect `
            -Name 'expectedOutputAspectRatio' `
            -Minimum 0 `
            -ExclusiveMinimum
        $observedOutputAspect = $candidate.Width / [double]$candidate.Height
        $error = Get-PSOBBAspectErrorPercent $observedOutputAspect $expectedOutputAspect
        $geometryChecks.Add((New-PSOBBGeometryCheck `
            -Id 'output-aspect' `
            -Kind 'aspect-ratio' `
            -Observed ([Math]::Round($observedOutputAspect, 6)) `
            -Expected $expectedOutputAspect `
            -ErrorPercent $error `
            -MaximumErrorPercent $maximumAspectError `
            -Passed ($error -le $maximumAspectError) `
            -MeasurementSource 'decoded-png-dimensions'))
    }

    $expectedContentAspect = Get-PSOBBOptionalProperty `
        -Object $spec `
        -Name 'expectedContentAspectRatio'
    if ($null -ne $expectedContentAspect) {
        $expectedContentAspect = ConvertTo-PSOBBFiniteNumber `
            -Value $expectedContentAspect `
            -Name 'expectedContentAspectRatio' `
            -Minimum 0 `
            -ExclusiveMinimum
        $contentError = Get-PSOBBAspectErrorPercent `
            $candidate.EdgeBands.ActiveContentAspectRatio `
            $expectedContentAspect
        $geometryChecks.Add((New-PSOBBGeometryCheck `
            -Id 'active-content-aspect' `
            -Kind 'aspect-ratio' `
            -Observed $candidate.EdgeBands.ActiveContentAspectRatio `
            -Expected $expectedContentAspect `
            -ErrorPercent $contentError `
            -MaximumErrorPercent $maximumAspectError `
            -Passed ($contentError -le $maximumAspectError) `
            -MeasurementSource 'near-black-pillar-detection'))
    }

    $maximumPillarDelta = Get-PSOBBOptionalProperty `
        -Object $spec `
        -Name 'maximumPillarSymmetryDeltaPixels'
    if ($null -ne $maximumPillarDelta) {
        $maximumPillarDelta = [int](ConvertTo-PSOBBFiniteNumber `
            -Value $maximumPillarDelta `
            -Name 'maximumPillarSymmetryDeltaPixels' `
            -Minimum 0 `
            -Maximum 16384)
        $pillarPass = $candidate.EdgeBands.PillarSymmetryDeltaPixels -le $maximumPillarDelta
        $geometryChecks.Add((New-PSOBBGeometryCheck `
            -Id 'pillar-symmetry' `
            -Kind 'pixel-delta' `
            -Observed $candidate.EdgeBands.PillarSymmetryDeltaPixels `
            -Expected "at-most-$maximumPillarDelta" `
            -ErrorPercent $(if ($pillarPass) { 0 } else { 100 }) `
            -MaximumErrorPercent 0 `
            -Passed $pillarPass `
            -MeasurementSource 'near-black-pillar-detection'))
    }

    $circles = @(Get-PSOBBOptionalProperty -Object $spec -Name 'circles')
    $circles = @($circles | Where-Object { $null -ne $_ })
    $circleIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($circle in $circles) {
        Assert-PSOBBAllowedProperties -Object $circle -Context 'circle measurement' -Allowed @(
            'id',
            'horizontalDiameterPixels',
            'verticalDiameterPixels',
            'maximumAxisErrorPercent'
        )
        $id = [string](Get-PSOBBOptionalProperty -Object $circle -Name 'id')
        if ($id -cnotmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or -not $circleIds.Add($id)) {
            throw 'Circle measurement IDs must be unique lowercase safe identifiers'
        }
        $horizontal = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $circle -Name 'horizontalDiameterPixels') `
            -Name "$id.horizontalDiameterPixels" `
            -Minimum 0 `
            -Maximum $candidate.Width `
            -ExclusiveMinimum
        $vertical = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $circle -Name 'verticalDiameterPixels') `
            -Name "$id.verticalDiameterPixels" `
            -Minimum 0 `
            -Maximum $candidate.Height `
            -ExclusiveMinimum
        $axisMaximum = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $circle -Name 'maximumAxisErrorPercent') `
            -Name "$id.maximumAxisErrorPercent" `
            -Minimum 0 `
            -Maximum 100
        $axisRatio = $horizontal / $vertical
        $axisError = Get-PSOBBAspectErrorPercent $axisRatio 1.0
        $result = New-PSOBBGeometryCheck `
            -Id $id `
            -Kind 'circle-axis-ratio' `
            -Observed ([pscustomobject]@{
                horizontalDiameterPixels = $horizontal
                verticalDiameterPixels = $vertical
                axisRatio = [Math]::Round($axisRatio, 6)
            }) `
            -Expected 1.0 `
            -ErrorPercent $axisError `
            -MaximumErrorPercent $axisMaximum `
            -Passed ($axisError -le $axisMaximum) `
            -MeasurementSource 'caller-supplied-landmark-diameters'
        $circleResults.Add($result)
        $geometryChecks.Add($result)
    }
    if ($requiresCircleChecks -and $circleResults.Count -eq 0) {
        $geometryChecks.Add((New-PSOBBGeometryCheck `
            -Id 'required-circle-measurement' `
            -Kind 'measurement-presence' `
            -Observed 0 `
            -Expected 'at-least-one' `
            -ErrorPercent 100 `
            -MaximumErrorPercent 0 `
            -Passed $false `
            -MeasurementSource 'validation-specification'))
    }

    $aspects = @(Get-PSOBBOptionalProperty -Object $spec -Name 'aspects')
    $aspects = @($aspects | Where-Object { $null -ne $_ })
    $aspectIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($aspect in $aspects) {
        Assert-PSOBBAllowedProperties -Object $aspect -Context 'aspect measurement' -Allowed @(
            'id',
            'observedWidthPixels',
            'observedHeightPixels',
            'expectedRatio',
            'maximumErrorPercent'
        )
        $id = [string](Get-PSOBBOptionalProperty -Object $aspect -Name 'id')
        if ($id -cnotmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or -not $aspectIds.Add($id)) {
            throw 'Aspect measurement IDs must be unique lowercase safe identifiers'
        }
        $observedWidth = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $aspect -Name 'observedWidthPixels') `
            -Name "$id.observedWidthPixels" `
            -Minimum 0 `
            -Maximum $candidate.Width `
            -ExclusiveMinimum
        $observedHeight = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $aspect -Name 'observedHeightPixels') `
            -Name "$id.observedHeightPixels" `
            -Minimum 0 `
            -Maximum $candidate.Height `
            -ExclusiveMinimum
        $expectedRatio = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $aspect -Name 'expectedRatio') `
            -Name "$id.expectedRatio" `
            -Minimum 0 `
            -ExclusiveMinimum
        $aspectMaximum = ConvertTo-PSOBBFiniteNumber `
            -Value (Get-PSOBBOptionalProperty -Object $aspect -Name 'maximumErrorPercent') `
            -Name "$id.maximumErrorPercent" `
            -Minimum 0 `
            -Maximum 100
        $observedRatio = $observedWidth / $observedHeight
        $error = Get-PSOBBAspectErrorPercent $observedRatio $expectedRatio
        $result = New-PSOBBGeometryCheck `
            -Id $id `
            -Kind 'landmark-aspect-ratio' `
            -Observed ([pscustomobject]@{
                widthPixels = $observedWidth
                heightPixels = $observedHeight
                ratio = [Math]::Round($observedRatio, 6)
            }) `
            -Expected $expectedRatio `
            -ErrorPercent $error `
            -MaximumErrorPercent $aspectMaximum `
            -Passed ($error -le $aspectMaximum) `
            -MeasurementSource 'caller-supplied-landmark-dimensions'
        $aspectResults.Add($result)
        $geometryChecks.Add($result)
    }
}

$geometryState = if ($null -eq $spec -or $geometryChecks.Count -eq 0) {
    'pending'
} elseif (@($geometryChecks | Where-Object state -ceq 'fail').Count -gt 0) {
    'fail'
} else {
    'pass'
}

$reference = $null
$comparison = $null
$casState = if ($casExpected) { 'pending' } else { 'not-applicable' }
if ($null -ne $privateReferencePath) {
    $reference = [PSOBB.GraphicsEvidence.ScreenshotAnalyzer]::Analyze([string]$privateReferencePath, [int]$EdgeBandWidth, [int]$NearBlackThreshold, [double]$PillarColumnNearBlackMinimumPercent, [int]$SharpnessEdgeThreshold)
    $comparison = [PSOBB.GraphicsEvidence.ScreenshotAnalyzer]::Compare([string]$privateReferencePath, [string]$privateCandidatePath, [int]$HaloReferenceEdgeThreshold)
    $casState = if (
        $comparison.ReferenceEdgeSampleCount -gt 0 -and
        $comparison.MaximumHaloOvershootPercent -le $MaximumCasHaloOvershootPercent -and
        $comparison.IntroducedBlackClipPixelCount -eq 0 -and
        $comparison.IntroducedWhiteClipPixelCount -eq 0) {
        'pass'
    } else {
        'fail'
    }
}

$automaticTechnicalState = if ($geometryState -ceq 'fail' -or $casState -ceq 'fail') {
    'fail'
} elseif ($geometryState -ceq 'pending' -or $casState -ceq 'pending') {
    'pending'
} else {
    'pass'
}
if ($Disposition -ceq 'accepted' -and $automaticTechnicalState -cne 'pass') {
    throw "Cannot mark a screenshot accepted while its automatic technical state is $automaticTechnicalState"
}

$candidateRecord = [pscustomobject][ordered]@{
    artifact = [pscustomobject][ordered]@{
        format = 'png'
        sha256 = [string]$candidate.Sha256
        byteSize = [long]$candidate.ByteSize
        width = [int]$candidate.Width
        height = [int]$candidate.Height
        nonOpaquePixelCount = [long]$candidate.NonOpaquePixelCount
    }
    edgeBands = [pscustomobject][ordered]@{
        bandWidthPixels = [int]$candidate.EdgeBands.BandWidthPixels
        nearBlackThreshold = [int]$candidate.EdgeBands.NearBlackThreshold
        pillarColumnNearBlackMinimumPercent =
            [double]$candidate.EdgeBands.PillarColumnNearBlackMinimumPercent
        leftBandMeanLuma = [double]$candidate.EdgeBands.LeftBandMeanLuma
        rightBandMeanLuma = [double]$candidate.EdgeBands.RightBandMeanLuma
        leftBandNearBlackPercent = [double]$candidate.EdgeBands.LeftBandNearBlackPercent
        rightBandNearBlackPercent = [double]$candidate.EdgeBands.RightBandNearBlackPercent
        detectedLeftPillarWidthPixels =
            [int]$candidate.EdgeBands.DetectedLeftPillarWidthPixels
        detectedRightPillarWidthPixels =
            [int]$candidate.EdgeBands.DetectedRightPillarWidthPixels
        pillarSymmetryDeltaPixels = [int]$candidate.EdgeBands.PillarSymmetryDeltaPixels
        entireFrameNearBlack = [bool]$candidate.EdgeBands.EntireFrameNearBlack
        activeContentWidthPixels = [int]$candidate.EdgeBands.ActiveContentWidthPixels
        activeContentAspectRatio = [double]$candidate.EdgeBands.ActiveContentAspectRatio
    }
    sharpness = [pscustomobject][ordered]@{
        region = [string]$candidate.Sharpness.Region
        sampleCount = [long]$candidate.Sharpness.SampleCount
        edgeThreshold = [int]$candidate.Sharpness.EdgeThreshold
        meanAbsoluteGradient = [double]$candidate.Sharpness.MeanAbsoluteGradient
        p95AbsoluteGradient = [double]$candidate.Sharpness.P95AbsoluteGradient
        laplacianVariance = [double]$candidate.Sharpness.LaplacianVariance
        edgeDensityPercent = [double]$candidate.Sharpness.EdgeDensityPercent
    }
    tone = [pscustomobject][ordered]@{
        pixelCount = [long]$candidate.Tone.PixelCount
        exactBlackPixelCount = [long]$candidate.Tone.ExactBlackPixelCount
        exactWhitePixelCount = [long]$candidate.Tone.ExactWhitePixelCount
        exactBlackPixelPercent = [double]$candidate.Tone.ExactBlackPixelPercent
        exactWhitePixelPercent = [double]$candidate.Tone.ExactWhitePixelPercent
    }
}

$referenceRecord = if ($null -eq $reference) {
    $null
} else {
    [pscustomobject][ordered]@{
        artifact = [pscustomobject][ordered]@{
            format = 'png'
            sha256 = [string]$reference.Sha256
            byteSize = [long]$reference.ByteSize
            width = [int]$reference.Width
            height = [int]$reference.Height
            nonOpaquePixelCount = [long]$reference.NonOpaquePixelCount
        }
        sharpness = [pscustomobject][ordered]@{
            region = [string]$reference.Sharpness.Region
            sampleCount = [long]$reference.Sharpness.SampleCount
            edgeThreshold = [int]$reference.Sharpness.EdgeThreshold
            meanAbsoluteGradient = [double]$reference.Sharpness.MeanAbsoluteGradient
            p95AbsoluteGradient = [double]$reference.Sharpness.P95AbsoluteGradient
            laplacianVariance = [double]$reference.Sharpness.LaplacianVariance
            edgeDensityPercent = [double]$reference.Sharpness.EdgeDensityPercent
        }
    }
}

$comparisonRecord = if ($null -eq $comparison) {
    $null
} else {
    [pscustomobject][ordered]@{
        pixelCount = [long]$comparison.PixelCount
        meanAbsoluteLumaDifference = [double]$comparison.MeanAbsoluteLumaDifference
        rootMeanSquareLumaDifference = [double]$comparison.RootMeanSquareLumaDifference
        psnrDb = if ([double]::IsPositiveInfinity($comparison.PsnrDb)) {
            'infinite-identical'
        } else {
            [double]$comparison.PsnrDb
        }
        clipping = [pscustomobject][ordered]@{
            introducedBlackPixelCount = [long]$comparison.IntroducedBlackClipPixelCount
            introducedWhitePixelCount = [long]$comparison.IntroducedWhiteClipPixelCount
            introducedBlackPixelPercent = [double]$comparison.IntroducedBlackClipPixelPercent
            introducedWhitePixelPercent = [double]$comparison.IntroducedWhiteClipPixelPercent
            state = if (
                $comparison.IntroducedBlackClipPixelCount -eq 0 -and
                $comparison.IntroducedWhiteClipPixelCount -eq 0) {
                'pass'
            } else {
                'fail'
            }
        }
        halo = [pscustomobject][ordered]@{
            referenceEdgeThreshold = [int]$comparison.ReferenceEdgeThreshold
            referenceEdgeSampleCount = [long]$comparison.ReferenceEdgeSampleCount
            overshootPixelCount = [long]$comparison.HaloOvershootPixelCount
            overshootAffectedEdgePercent =
                [double]$comparison.HaloOvershootAffectedEdgePercent
            meanOvershootPercent = [double]$comparison.MeanHaloOvershootPercent
            p95OvershootPercent = [double]$comparison.P95HaloOvershootPercent
            maximumOvershootPercent = [double]$comparison.MaximumHaloOvershootPercent
            maximumAllowedPercent = [double]$MaximumCasHaloOvershootPercent
            state = if (
                $comparison.ReferenceEdgeSampleCount -gt 0 -and
                $comparison.MaximumHaloOvershootPercent -le
                    $MaximumCasHaloOvershootPercent) {
                'pass'
            } else {
                'fail'
            }
        }
    }
}

$result = [pscustomobject][ordered]@{
    schemaVersion = 1
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    profileId = $ProfileId
    candidateId = $CandidateId
    sceneId = $SceneId
    channel = $Channel
    disposition = [pscustomobject][ordered]@{
        state = $Disposition
        rejectionReason = $normalizedRejectionReason
        automaticTechnicalState = $automaticTechnicalState
    }
    privacy = [pscustomobject][ordered]@{
        rawArtifactsCopiedIntoRepository = $false
        rawPathsRecorded = $false
        rawFileNamesRecorded = $false
        indexContent = 'hashes-dimensions-metrics-and-safe-ids-only'
    }
    candidate = $candidateRecord
    reference = $referenceRecord
    comparison = $comparisonRecord
    geometry = [pscustomobject][ordered]@{
        state = $geometryState
        validationSpecPresent = $null -ne $spec
        measurementPolicy =
            'decoded dimensions plus caller-supplied landmark measurements; no shape is inferred without landmarks'
        checks = @($geometryChecks)
        circles = @($circleResults)
        aspects = @($aspectResults)
    }
    gates = [pscustomobject][ordered]@{
        pngIntegrity = 'pass'
        geometry = $geometryState
        casHaloAndClipping = $casState
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    if ([System.IO.Path]::GetExtension($OutputPath) -ine '.json') {
        throw 'The redacted screenshot index output must use the .json extension'
    }
    if (Test-Path -LiteralPath $OutputPath) {
        throw "Refusing to overwrite an existing screenshot index: $OutputPath"
    }
    $outputDirectory = Split-Path -Parent $OutputPath
    [void][System.IO.Directory]::CreateDirectory($outputDirectory)
    $json = $result | ConvertTo-Json -Depth 30
    foreach ($privatePath in @($privateCandidatePath, $privateReferencePath) |
        Where-Object { $null -ne $_ }) {
        if ($json.Contains($privatePath, [System.StringComparison]::OrdinalIgnoreCase) -or
            $json.Contains(
                [System.IO.Path]::GetFileName($privatePath),
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The generated screenshot index unexpectedly contains private path metadata'
        }
    }
    $temporaryPath = $OutputPath + '.new'
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $json,
            [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $OutputPath
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

$result
