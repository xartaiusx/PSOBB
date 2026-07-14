[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$SigningPrivateKeyPath,
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repositoryRoot 'src\PSOBB.Launcher\PSOBB.Launcher.csproj'
$trustPath = Join-Path $repositoryRoot 'config\release-trust.json'
$publicKey = Join-Path $layout.Stable 'release-public-key.pem'
if (-not (Test-Path -LiteralPath $publicKey -PathType Leaf)) {
    throw 'The pinned release public key must exist before publishing the launcher'
}
if ([string]::IsNullOrWhiteSpace($SigningPrivateKeyPath)) {
    $SigningPrivateKeyPath = Join-Path $layout.Secrets 'local-acceptance-signing-private.pem'
}
if (-not (Test-Path -LiteralPath $SigningPrivateKeyPath -PathType Leaf)) {
    throw 'A matching offline/local-acceptance signing private key is required to sign the launcher payload index'
}

$trust = Get-Content -Raw -LiteralPath $trustPath | ConvertFrom-Json
$activeKeys = @($trust.keys | Where-Object id -eq $trust.activeKeyId)
if (($trust.schemaVersion -ne 1) -or ($activeKeys.Count -ne 1) -or
    ([string]$activeKeys[0].spkiSha256 -notmatch '^[0-9a-f]{64}$')) {
    throw 'release-trust.json does not contain one valid active trust anchor'
}
$key = [System.Security.Cryptography.ECDsa]::Create()
try {
    $key.ImportFromPem([System.IO.File]::ReadAllText($publicKey))
    $actualSpki = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($key.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
} finally {
    $key.Dispose()
}
if ($actualSpki -ne [string]$activeKeys[0].spkiSha256) {
    throw 'Runtime release public key does not match the repository trust anchor'
}
$loaderSource = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'src\PSOBB.Launcher\Services\LauncherManifestLoader.cs')
if ($loaderSource -notmatch [regex]::Escape($actualSpki)) {
    throw 'The launcher compiled trust anchor does not match release-trust.json'
}

[xml]$projectXml = Get-Content -Raw -LiteralPath $projectPath
$targetFramework = [string]$projectXml.Project.PropertyGroup.TargetFramework
if ([string]::IsNullOrWhiteSpace($targetFramework)) {
    throw 'Could not derive TargetFramework from the launcher project'
}

$launcherRoot = Join-Path $layout.Stable 'launcher'
$temporaryRoot = Join-Path $layout.Stable ('.launcher-new-' + [Guid]::NewGuid().ToString('N'))
$lkgRoot = Join-Path $layout.Root 'last-known-good\launchers'
$snapshot = Join-Path $lkgRoot ('launcher-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Force -Path $lkgRoot | Out-Null
$movedExisting = $false
$installedNew = $false

try {
    & dotnet publish $projectPath -c $Configuration --nologo --no-restore --output $temporaryRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'dotnet publish failed for PSOBB.Launcher'
    }
    Copy-Item -LiteralPath $publicKey -Destination (Join-Path $temporaryRoot 'release-public-key.pem')
    $launcherExecutable = Join-Path $temporaryRoot 'PSOBB.Launcher.exe'
    if (-not (Test-Path -LiteralPath $launcherExecutable -PathType Leaf)) {
        throw 'Published launcher executable is missing'
    }

    # The signed build record indexes every payload file. Like any detached
    # manifest, it intentionally does not recursively hash itself or its signature.
    $payloadFiles = @(Get-ChildItem -LiteralPath $temporaryRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            path = [System.IO.Path]::GetRelativePath($temporaryRoot, $_.FullName).Replace('\', '/')
            size = $_.Length
            sha256 = Get-LowerSha256 $_.FullName
        }
    })
    $payloadIndex = ($payloadFiles | ForEach-Object { "$($_.path)`0$($_.size)`0$($_.sha256)" }) -join "`n"
    $payloadHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($payloadIndex))).ToLowerInvariant()
    $buildRecordPath = Join-Path $temporaryRoot 'launcher-build.json'
    $buildRecord = [ordered]@{
        schemaVersion = 2
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
        configuration = $Configuration
        targetFramework = $targetFramework
        sdkVersion = (& dotnet --version).Trim()
        launcherSha256 = Get-LowerSha256 $launcherExecutable
        payloadSha256 = $payloadHash
        payloadIndexExcludes = @('launcher-build.json', 'launcher-build.json.sig')
        authenticode = (Get-AuthenticodeSignature -LiteralPath $launcherExecutable).Status.ToString()
        releasePublicKeySpkiSha256 = $actualSpki
        trustKeyId = [string]$trust.activeKeyId
        productionCodeSigning = 'pending certificate approval'
        files = $payloadFiles
    }
    [System.IO.File]::WriteAllText(
        $buildRecordPath,
        ($buildRecord | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    & (Join-Path $PSScriptRoot 'New-PSOBBManifestSignature.ps1') `
        -ManifestPath $buildRecordPath `
        -PrivateKeyPath $SigningPrivateKeyPath `
        -PublicKeyPath (Join-Path $temporaryRoot 'release-public-key.pem') `
        -RuntimeRoot $layout.Root | Out-Null

    if (Test-Path -LiteralPath $launcherRoot) {
        Move-Item -LiteralPath $launcherRoot -Destination $snapshot
        $movedExisting = $true
    }
    try {
        Move-Item -LiteralPath $temporaryRoot -Destination $launcherRoot
        $installedNew = $true
    } catch {
        if ($movedExisting -and -not (Test-Path -LiteralPath $launcherRoot) -and (Test-Path -LiteralPath $snapshot)) {
            Move-Item -LiteralPath $snapshot -Destination $launcherRoot
            $movedExisting = $false
        }
        throw
    }

    Get-ChildItem -LiteralPath $lkgRoot -Directory -Filter 'launcher-*' |
        Sort-Object Name -Descending |
        Select-Object -Skip 5 |
        ForEach-Object {
            Remove-Item -LiteralPath (Assert-PathWithinRoot -Path $_.FullName -Root $lkgRoot) -Recurse -Force
        }

    [pscustomobject]@{
        LauncherPath = Join-Path $launcherRoot 'PSOBB.Launcher.exe'
        PayloadSha256 = $buildRecord.payloadSha256
        PayloadManifest = Join-Path $launcherRoot 'launcher-build.json'
        PayloadSignature = Join-Path $launcherRoot 'launcher-build.json.sig'
        TrustedPublicKey = Join-Path $launcherRoot 'release-public-key.pem'
        PreviousSnapshot = if ($movedExisting) { $snapshot } else { $null }
        Authenticode = $buildRecord.authenticode
    }
} finally {
    if (-not $installedNew -and (Test-Path -LiteralPath $temporaryRoot)) {
        $safeTemporary = Assert-PathWithinRoot -Path $temporaryRoot -Root $layout.Root
        Remove-Item -LiteralPath $safeTemporary -Recurse -Force
    }
}
