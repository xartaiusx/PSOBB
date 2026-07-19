[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$CapturePath,
    [string]$RuntimeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Assert-PSOBBPrivateRenderDocEvidencePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$Purpose
    )

    $fullPath = Assert-PathWithinRoot -Path $Path -Root $EvidenceRoot
    Assert-PSOBBPathOutsideTrackedSource -Path $fullPath -Purpose $Purpose
}

function Get-PSOBBStableFileIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $before = Get-Item -LiteralPath $Path -Force
    if ($before.Length -le 0 -or $before.Length -gt 64GB) {
        throw 'The RenderDoc capture has an invalid byte size'
    }
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $hash = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    } finally {
        $stream.Dispose()
    }
    $after = Get-Item -LiteralPath $Path -Force
    if ($before.Length -ne $after.Length -or
        $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
        throw 'The RenderDoc capture changed while its identity was being computed'
    }
    [pscustomobject]@{
        Size = [long]$after.Length
        Sha256 = $hash
        LastWriteTimeUtc = $after.LastWriteTimeUtc
    }
}

function Write-PSOBBJsonAtomically {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to overwrite existing RenderDoc capture metadata: $Path"
    }
    $temporaryPath = $Path + '.new'
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            ($Value | ConvertTo-Json -Depth 30),
            [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $Path
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$evidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Root 'graphics-evidence') `
    -Root $layout.Root
if (-not (Test-Path -LiteralPath $evidenceRoot -PathType Container)) {
    throw "The graphics-evidence root does not exist: $evidenceRoot"
}
$RunRoot = Assert-PSOBBPrivateRenderDocEvidencePath `
    -Path $RunRoot `
    -EvidenceRoot $evidenceRoot `
    -Purpose 'RenderDoc run evidence'
if (-not (Test-Path -LiteralPath $RunRoot -PathType Container)) {
    throw "The RenderDoc run directory does not exist: $RunRoot"
}

$launchManifestPath = Assert-PSOBBPrivateRenderDocEvidencePath `
    -Path (Join-Path $RunRoot 'renderdoc-launch-manifest.json') `
    -EvidenceRoot $evidenceRoot `
    -Purpose 'RenderDoc launch manifest'
if (-not (Test-Path -LiteralPath $launchManifestPath -PathType Leaf)) {
    throw "The RenderDoc launch manifest is missing: $launchManifestPath"
}
$launchManifestItem = Get-Item -LiteralPath $launchManifestPath -Force
if ($launchManifestItem.Length -le 0 -or $launchManifestItem.Length -gt 256KB) {
    throw 'The RenderDoc launch manifest has an invalid byte size'
}
try {
    $launch = Get-Content -Raw -LiteralPath $launchManifestPath |
        ConvertFrom-Json -Depth 40
} catch {
    throw "The RenderDoc launch manifest is not valid JSON: $($_.Exception.Message)"
}
if ([int]$launch.schemaVersion -ne 1 -or
    [string]$launch.kind -cne 'psobb-renderdoc-launch' -or
    [string]$launch.state -cne 'capture-armed-awaiting-manual-trigger' -or
    [string]$launch.runId -cnotmatch '^\d{8}T\d{9}Z-renderdoc-[a-f0-9]{12}$' -or
    [string]$launch.channel -cne 'local-lab' -or
    [string]$launch.profile.id -cnotmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
    [string]$launch.profile.materializedSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    [string]$launch.renderDoc.version -cne 'v1.45' -or
    [string]$launch.renderDoc.archiveSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    [string]$launch.renderDoc.executableSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    [uint64]$launch.renderDoc.captureIdentity -eq 0 -or
    [string]$launch.capture.trigger -cne 'manual-f12' -or
    [string]$launch.renderTargetEvidence.status -cne 'pending-replay-inspection') {
    throw 'The RenderDoc launch manifest does not satisfy the capture-registration contract'
}
if ((Split-Path -Leaf $RunRoot) -cne [string]$launch.runId -or
    (Split-Path -Leaf (Split-Path -Parent $RunRoot)) -cne [string]$launch.profile.id) {
    throw 'The RenderDoc run directory does not match the manifest run and profile identities'
}

$templateRelative = [string]$launch.capture.template
if ($templateRelative -cnotmatch '^capture/[a-z0-9]+(?:-[a-z0-9]+)*$' -or
    [System.IO.Path]::IsPathRooted($templateRelative) -or
    $templateRelative.Contains(':', [System.StringComparison]::Ordinal) -or
    $templateRelative -match '(^|/)\.\.(/|$)') {
    throw 'The RenderDoc capture template is not a safe run-relative path'
}
$templatePath = Assert-PSOBBPrivateRenderDocEvidencePath `
    -Path (Join-Path $RunRoot $templateRelative.Replace('/', '\')) `
    -EvidenceRoot $evidenceRoot `
    -Purpose 'RenderDoc capture template'
$captureDirectory = Split-Path -Parent $templatePath
$templateName = Split-Path -Leaf $templatePath

$CapturePath = Assert-PSOBBPrivateRenderDocEvidencePath `
    -Path $CapturePath `
    -EvidenceRoot $evidenceRoot `
    -Purpose 'Raw RenderDoc capture'
if (-not (Test-Path -LiteralPath $CapturePath -PathType Leaf)) {
    throw "The RenderDoc capture does not exist: $CapturePath"
}
if (-not ([System.IO.Path]::GetDirectoryName($CapturePath)).Equals(
        $captureDirectory,
        [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.IO.Path]::GetExtension($CapturePath) -cne '.rdc' -or
    [System.IO.Path]::GetFileNameWithoutExtension($CapturePath) -cnotmatch (
        '^' + [regex]::Escape($templateName) + '_frame[0-9]+$')) {
    throw 'The RenderDoc capture path does not match the exact private capture template'
}

$artifactManifestPath = Join-Path $RunRoot 'renderdoc-capture-artifact.json'
if (Test-Path -LiteralPath $artifactManifestPath) {
    throw "Refusing to overwrite existing RenderDoc capture metadata: $artifactManifestPath"
}
$captureIdentity = Get-PSOBBStableFileIdentity -Path $CapturePath
$launchManifestIdentity = Get-PSOBBStableFileIdentity -Path $launchManifestPath

$requestedInternal = $launch.profile.requestedExpectations.internalRender
$requestedOutput = $launch.profile.requestedExpectations.output
if ([int]$requestedInternal.width -lt 1 -or [int]$requestedInternal.height -lt 1 -or
    [string]$requestedInternal.evidenceClass -cne 'configuration-only' -or
    [int]$requestedOutput.width -lt 1 -or [int]$requestedOutput.height -lt 1 -or
    [string]$requestedOutput.evidenceClass -cne 'configuration-and-window-only') {
    throw 'The launch manifest has invalid configured resolution expectations'
}

$relativeCapture = [System.IO.Path]::GetRelativePath($RunRoot, $CapturePath).Replace('\', '/')
$artifact = [ordered]@{
    schemaVersion = 1
    kind = 'psobb-renderdoc-capture-artifact'
    runId = [string]$launch.runId
    registeredAtUtc = [DateTime]::UtcNow.ToString('o')
    launchManifest = [ordered]@{
        file = 'renderdoc-launch-manifest.json'
        byteSize = $launchManifestIdentity.Size
        sha256 = $launchManifestIdentity.Sha256
    }
    profile = [ordered]@{
        id = [string]$launch.profile.id
        materializedSha256 = [string]$launch.profile.materializedSha256
        requestedExpectations = [ordered]@{
            internalRender = [ordered]@{
                width = [int]$requestedInternal.width
                height = [int]$requestedInternal.height
                evidenceClass = 'configuration-only'
            }
            output = [ordered]@{
                width = [int]$requestedOutput.width
                height = [int]$requestedOutput.height
                evidenceClass = 'configuration-and-window-only'
            }
            aspectPolicy = [string]$launch.profile.requestedExpectations.aspectPolicy
            outputApi = [string]$launch.profile.requestedExpectations.outputApi
        }
    }
    renderDoc = [ordered]@{
        version = [string]$launch.renderDoc.version
        commit = [string]$launch.renderDoc.commit
        archiveSha256 = [string]$launch.renderDoc.archiveSha256
        executableSha256 = [string]$launch.renderDoc.executableSha256
        captureIdentity = [uint64]$launch.renderDoc.captureIdentity
    }
    capture = [ordered]@{
        file = $relativeCapture
        byteSize = $captureIdentity.Size
        sha256 = $captureIdentity.Sha256
        lastWriteTimeUtc = $captureIdentity.LastWriteTimeUtc.ToString('o')
        validationClass = 'artifact-integrity-only'
    }
    replayEvidence = [ordered]@{
        status = 'not-provided'
        observedInternalRender = $null
        observedOutput = $null
        note = 'SHA-256 and byte size do not prove render-target dimensions; replay inspection is still required.'
    }
}
Write-PSOBBJsonAtomically -Value $artifact -Path $artifactManifestPath

[pscustomobject]@{
    Registered = $true
    RunId = [string]$launch.runId
    ProfileId = [string]$launch.profile.id
    CapturePath = $CapturePath
    CaptureByteSize = $captureIdentity.Size
    CaptureSha256 = $captureIdentity.Sha256
    ArtifactManifestPath = $artifactManifestPath
    RequestedInternalResolution = '{0}x{1}' -f `
        [int]$requestedInternal.width, [int]$requestedInternal.height
    RequestedOutputResolution = '{0}x{1}' -f `
        [int]$requestedOutput.width, [int]$requestedOutput.height
    ReplayEvidence = 'not-provided'
    DimensionClaim = 'none'
}
