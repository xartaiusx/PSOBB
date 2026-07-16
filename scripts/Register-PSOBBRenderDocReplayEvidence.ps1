[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)]
    [int]$PresentEventId,
    [Parameter(Mandatory)][ValidateRange(1, 16384)]
    [int]$BackbufferWidth,
    [Parameter(Mandatory)][ValidateRange(1, 16384)]
    [int]$BackbufferHeight,
    [Parameter(Mandatory)][ValidateRange(1, 16384)]
    [int]$InternalRenderWidth,
    [Parameter(Mandatory)][ValidateRange(1, 16384)]
    [int]$InternalRenderHeight,
    [Parameter(Mandatory)][ValidatePattern('^DXGI_FORMAT_[A-Z0-9_]+$')]
    [string]$BackbufferFormat,
    [Parameter(Mandatory)][ValidatePattern('^DXGI_FORMAT_[A-Z0-9_]+$')]
    [string]$InternalRenderFormat,
    [Parameter(Mandatory)][switch]$ReplayConfirmed,
    [string]$RuntimeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-StrictPrivateJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    $contained = Assert-PathWithinRoot -Path $Path -Root $Root
    if (-not (Test-Path -LiteralPath $contained -PathType Leaf)) {
        throw "$Label is missing: $contained"
    }
    $item = Get-Item -LiteralPath $contained -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 1MB) {
        throw "$Label has an invalid size or filesystem type"
    }
    try {
        Get-Content -Raw -LiteralPath $contained | ConvertFrom-Json -Depth 40
    } catch {
        throw "$Label is not valid JSON: $($_.Exception.Message)"
    }
}

function Get-StableSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $before = Get-Item -LiteralPath $Path -Force
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
    $after = Get-Item -LiteralPath $Path -Force
    if ($before.Length -ne $after.Length -or
        $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
        throw "Evidence changed while its identity was computed: $Path"
    }
    [pscustomobject]@{ Size = [long]$after.Length; Sha256 = $hash }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$evidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Root 'graphics-evidence') -Root $layout.Root
$RunRoot = Assert-PathWithinRoot -Path $RunRoot -Root $evidenceRoot
if (-not (Test-Path -LiteralPath $RunRoot -PathType Container) -or
    (Get-Item -LiteralPath $RunRoot -Force).Attributes -band
        [IO.FileAttributes]::ReparsePoint) {
    throw 'The RenderDoc run root is missing or unsafe'
}

$artifactPath = Join-Path $RunRoot 'renderdoc-capture-artifact.json'
$artifact = Get-StrictPrivateJson -Path $artifactPath -Root $evidenceRoot `
    -Label 'RenderDoc capture artifact'
if ([int]$artifact.schemaVersion -ne 1 -or
    [string]$artifact.kind -cne 'psobb-renderdoc-capture-artifact' -or
    [string]$artifact.runId -cne (Split-Path -Leaf $RunRoot) -or
    [string]$artifact.replayEvidence.status -cne 'not-provided' -or
    [string]$artifact.capture.validationClass -cne 'artifact-integrity-only' -or
    [string]$artifact.capture.sha256 -cnotmatch '^[a-f0-9]{64}$') {
    throw 'The RenderDoc capture artifact is not eligible for replay attestation'
}

$captureRelative = ([string]$artifact.capture.file).Replace('/', '\')
if ([IO.Path]::IsPathRooted($captureRelative) -or
    $captureRelative.Contains(':', [StringComparison]::Ordinal) -or
    $captureRelative -match '(^|\\)\.\.(\\|$)' -or
    [IO.Path]::GetExtension($captureRelative) -cne '.rdc') {
    throw 'The registered RenderDoc capture path is unsafe'
}
$capturePath = Assert-PathWithinRoot `
    -Path (Join-Path $RunRoot $captureRelative) -Root $RunRoot
if (-not (Test-Path -LiteralPath $capturePath -PathType Leaf)) {
    throw 'The registered RenderDoc capture is missing'
}
$captureIdentity = Get-StableSha256 -Path $capturePath
if ($captureIdentity.Size -ne [long]$artifact.capture.byteSize -or
    $captureIdentity.Sha256 -cne [string]$artifact.capture.sha256) {
    throw 'The RenderDoc capture no longer matches its registered identity'
}

$expectedInternal = $artifact.profile.requestedExpectations.internalRender
$expectedOutput = $artifact.profile.requestedExpectations.output
$dimensionsMatch = $BackbufferWidth -eq [int]$expectedOutput.width -and
    $BackbufferHeight -eq [int]$expectedOutput.height -and
    $InternalRenderWidth -eq [int]$expectedInternal.width -and
    $InternalRenderHeight -eq [int]$expectedInternal.height
if (-not $ReplayConfirmed -or -not $dimensionsMatch) {
    throw 'Replay evidence does not confirm the exact configured output and internal render dimensions'
}

$outputPath = Join-Path $RunRoot 'renderdoc-replay-evidence.json'
if (Test-Path -LiteralPath $outputPath) {
    throw 'Refusing to overwrite existing RenderDoc replay evidence'
}
if (-not $PSCmdlet.ShouldProcess(
        $outputPath,
        'record a manual qrenderdoc replay attestation for the exact registered capture')) {
    return
}

$artifactIdentity = Get-StableSha256 -Path $artifactPath
$record = [ordered]@{
    schemaVersion = 1
    kind = 'psobb-renderdoc-replay-evidence'
    runId = [string]$artifact.runId
    profileId = [string]$artifact.profile.id
    profileSha256 = [string]$artifact.profile.materializedSha256
    reviewedAtUtc = [DateTime]::UtcNow.ToString('o')
    reviewMethod = 'manual-qrenderdoc-v1.45-replay'
    captureArtifact = [ordered]@{
        file = 'renderdoc-capture-artifact.json'
        byteSize = $artifactIdentity.Size
        sha256 = $artifactIdentity.Sha256
    }
    capture = [ordered]@{
        file = [string]$artifact.capture.file
        byteSize = $captureIdentity.Size
        sha256 = $captureIdentity.Sha256
    }
    presentEventId = $PresentEventId
    observedOutput = [ordered]@{
        width = $BackbufferWidth
        height = $BackbufferHeight
        format = $BackbufferFormat
    }
    observedInternalRender = [ordered]@{
        width = $InternalRenderWidth
        height = $InternalRenderHeight
        format = $InternalRenderFormat
    }
    requestedDimensionsMatched = $true
    status = 'replay-inspected-pass'
    limitation = 'This record attests manually inspected qrenderdoc values; it does not infer dimensions from configuration or the RDC file hash.'
}
$temporary = $outputPath + '.new'
try {
    [IO.File]::WriteAllText(
        $temporary,
        ($record | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $outputPath
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force
    }
}

$identity = Get-StableSha256 -Path $outputPath
[pscustomobject]@{
    Registered = $true
    RunId = [string]$artifact.runId
    ProfileId = [string]$artifact.profile.id
    EvidencePath = $outputPath
    EvidenceSha256 = $identity.Sha256
    ObservedOutput = "${BackbufferWidth}x${BackbufferHeight}"
    ObservedInternalRender = "${InternalRenderWidth}x${InternalRenderHeight}"
    Status = 'replay-inspected-pass'
}
