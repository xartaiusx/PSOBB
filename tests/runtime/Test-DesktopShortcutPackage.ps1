[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1')
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function Copy-BuildRecord([Parameter(Mandatory)]$Record) {
    $Record | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$LauncherRoot,
        [Parameter(Mandatory)][string]$MessagePattern
    )

    $rejected = $false
    $detail = 'verification unexpectedly passed'
    try {
        Assert-PSOBBLauncherPayloadInventory `
            -LauncherRoot $LauncherRoot `
            -Record $Record | Out-Null
    } catch {
        $detail = $_.Exception.Message
        $rejected = $detail -match $MessagePattern
    }
    Add-Result $Name $rejected $detail
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-ShortcutPackageTests-' + [Guid]::NewGuid().ToString('N'))
try {
    $launcherRoot = Join-Path $temporaryRoot 'launcher'
    $nestedRoot = Join-Path $launcherRoot 'nested'
    New-Item -ItemType Directory -Path $nestedRoot -Force | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $launcherRoot 'PSOBB.Launcher.exe'),
        [byte[]](0x50, 0x53, 0x4F, 0x42, 0x42))
    [System.IO.File]::WriteAllText(
        (Join-Path $launcherRoot 'release-public-key.pem'),
        "fixture public key`n",
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllBytes(
        (Join-Path $nestedRoot 'PSOBB.Launcher.dll'),
        [byte[]](1, 3, 3, 7, 9))

    $payloadFiles = @(Get-ChildItem -LiteralPath $launcherRoot -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject][ordered]@{
                path = [System.IO.Path]::GetRelativePath(
                    $launcherRoot,
                    $_.FullName).Replace('\', '/')
                size = $_.Length
                sha256 = Get-LowerSha256 -Path $_.FullName
            }
        })
    $publisherIndex = ($payloadFiles | ForEach-Object {
        "$($_.path)`0$($_.size)`0$($_.sha256)"
    }) -join "`n"
    $publisherPayloadHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.Encoding]::UTF8.GetBytes($publisherIndex))).ToLowerInvariant()
    $launcherEntry = @($payloadFiles | Where-Object path -ceq 'PSOBB.Launcher.exe')
    $buildRecord = [pscustomobject][ordered]@{
        schemaVersion = 2
        launcherSha256 = $launcherEntry[0].sha256
        payloadSha256 = $publisherPayloadHash
        payloadIndexExcludes = @('launcher-build.json', 'launcher-build.json.sig')
        files = $payloadFiles
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $launcherRoot 'launcher-build.json'),
        ($buildRecord | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $launcherRoot 'launcher-build.json.sig'),
        'fixture detached signature',
        [System.Text.UTF8Encoding]::new($false))

    $verified = Assert-PSOBBLauncherPayloadInventory `
        -LauncherRoot $launcherRoot `
        -Record $buildRecord
    Add-Result 'complete signed launcher payload inventory verifies' (
        $verified.Entries.Count -eq $payloadFiles.Count -and
        $verified.PayloadSha256 -ceq $publisherPayloadHash) `
        "$($verified.Entries.Count) entries; $($verified.PayloadSha256)"

    $canonicalHash = Get-PSOBBLauncherPayloadSha256 -Entries $payloadFiles
    Add-Result 'payloadSha256 matches the publisher canonical algorithm' (
        $canonicalHash -ceq $publisherPayloadHash) $canonicalHash

    $unsafeCases = @(
        '../escape.dll',
        'nested\PSOBB.Launcher.dll',
        '/absolute.dll',
        'C:/absolute.dll',
        'nested//PSOBB.Launcher.dll',
        'nested/./PSOBB.Launcher.dll',
        'nested/trailing.'
    )
    foreach ($unsafePath in $unsafeCases) {
        $candidate = Copy-BuildRecord $buildRecord
        $candidate.files[0].path = $unsafePath
        Assert-Rejected `
            -Name "unsafe payload path is rejected: $unsafePath" `
            -Record $candidate `
            -LauncherRoot $launcherRoot `
            -MessagePattern 'unsafe non-canonical path'
    }

    $duplicate = Copy-BuildRecord $buildRecord
    $duplicateEntry = Copy-BuildRecord $duplicate.files[0]
    $duplicateEntry.path = ([string]$duplicateEntry.path).ToUpperInvariant()
    $duplicate.files = @($duplicate.files) + $duplicateEntry
    Assert-Rejected `
        -Name 'case-insensitive duplicate payload path is rejected' `
        -Record $duplicate `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'duplicate path'

    $wrongOrder = Copy-BuildRecord $buildRecord
    $first = $wrongOrder.files[0]
    $wrongOrder.files[0] = $wrongOrder.files[1]
    $wrongOrder.files[1] = $first
    Assert-Rejected `
        -Name 'non-canonical signed payload order is rejected' `
        -Record $wrongOrder `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'inventory or canonical order'

    $wrongSize = Copy-BuildRecord $buildRecord
    $wrongSize.files[-1].size = [long]$wrongSize.files[-1].size + 1
    Assert-Rejected `
        -Name 'non-launcher payload size mismatch is rejected' `
        -Record $wrongSize `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'payload size'

    $wrongHash = Copy-BuildRecord $buildRecord
    $wrongHash.files[-1].sha256 = '0' * 64
    Assert-Rejected `
        -Name 'non-launcher payload SHA-256 mismatch is rejected' `
        -Record $wrongHash `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'payload SHA-256'

    $wrongPayloadHash = Copy-BuildRecord $buildRecord
    $wrongPayloadHash.payloadSha256 = '0' * 64
    Assert-Rejected `
        -Name 'payloadSha256 mismatch is rejected' `
        -Record $wrongPayloadHash `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'payload index does not match payloadSha256'

    $wrongExclusions = Copy-BuildRecord $buildRecord
    [array]::Reverse($wrongExclusions.payloadIndexExcludes)
    Assert-Rejected `
        -Name 'non-exact payload-index exclusions are rejected' `
        -Record $wrongExclusions `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'exclusion list is not exact'

    $unexpectedFile = Join-Path $launcherRoot '.unexpected-hidden-payload.dll'
    [System.IO.File]::WriteAllBytes($unexpectedFile, [byte[]](4, 2))
    Assert-Rejected `
        -Name 'unexpected hidden package file fails exact inventory' `
        -Record $buildRecord `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'inventory does not exactly match'
    Remove-Item -LiteralPath $unexpectedFile -Force

    $missingPayload = Join-Path $nestedRoot 'PSOBB.Launcher.dll'
    $missingBackup = Join-Path $temporaryRoot 'missing-payload.backup'
    Move-Item -LiteralPath $missingPayload -Destination $missingBackup
    Assert-Rejected `
        -Name 'missing signed package file fails exact inventory' `
        -Record $buildRecord `
        -LauncherRoot $launcherRoot `
        -MessagePattern 'inventory does not exactly match'
    Move-Item -LiteralPath $missingBackup -Destination $missingPayload

    $installerSource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1')
    $trustChecksPresent =
        $installerSource -match 'ImportFromPem' -and
        $installerSource -match 'ExportSubjectPublicKeyInfo' -and
        $installerSource -match '\.VerifyData\(' -and
        $installerSource -match 'IeeeP1363FixedFieldConcatenation' -and
        $installerSource -match 'Assert-PSOBBLauncherPayloadInventory'
    Add-Result 'trust-anchor and detached-signature checks precede payload verification' (
        $trustChecksPresent) 'existing ECDSA P-256 trust and signature verification remains wired'

    $profileMapValid =
        $installerSource -match "'lab-widescreen-hd-16x10' = 'LocalLab'" -and
        $installerSource -notmatch "'lab-widescreen-cas-16x10' = 'LocalLab'" -and
        $installerSource -match "'LocalLab' \{ 'lab-widescreen-16x10' \}"
    $lifecycleShortcutsValid =
        $installerSource -match "-Name 'PSOBB Start Server'" -and
        $installerSource -match "-Name 'PSOBB Stop Server'" -and
        $installerSource -match "-Name 'PSOBB Play'" -and
        $installerSource -match '\$startServerArguments = ''--start-server' -and
        $installerSource -match '\$stopServerArguments = ''--stop-all' -and
        $installerSource -match "'PSOBB Control Center\.lnk'"
    Add-Result 'desktop shortcut set has exact lifecycle roles and removes the obsolete link' (
        $lifecycleShortcutsValid) 'start server, safe stop-all, and play are the only installed definitions'

    $publisherSource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'scripts\Publish-PSOBBLauncher.ps1')
    $relocatablePublishValid =
        $publisherSource -notmatch 'GetTempPath\(\)' -and
        $publisherSource -match '"-p:PublishDir=\$buildPublishDirectory"' -and
        $publisherSource -notmatch '--output\s+\$temporaryRoot' -and
        $publisherSource -match 'Set-PSOBBProtectedAcl\s+-Path\s+\$temporaryParent' -and
        $publisherSource -match "\.staging\\launcher-publish-" -and
        $publisherSource -match '-Root\s+\$layout\.Root' -and
        $publisherSource -notmatch 'Join-Path\s+\$layout\.Stable\s+\(''\.launcher-new-'
    Add-Result 'launcher publishing uses a same-volume protected staging path' (
        $relocatablePublishValid) 'a relative MSBuild output feeds the runtime-owned staging tree for atomic installation on any selected local volume'

    Add-Result 'desktop shortcuts allow private HD but exclude evidence-only CAS' (
        $profileMapValid) 'LocalLab defaults to clean widescreen; HD requires an explicit profile ID'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) desktop-shortcut package test(s) failed"
}
[pscustomobject]@{
    Suite = 'DesktopShortcutPackage'
    Passed = $results.Count
    Failed = 0
}
