[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [switch]$SkipLiveDrillEvidence
)

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$liveLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$results = [System.Collections.Generic.List[object]]::new()
$restoreDrillSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Test-PSOBBRestoreDrill.ps1')
$credentialDumpCommandPattern =
    '(?im)(?:WriteLine|Write|Send|SendLine)\s*\(\s*[''"]list-accounts[''"]'

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Test-RecoveryInterlockContract(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][int]$MinimumGlobalGateCount,
    [switch]$RequireEphemeralLifecycleCoverage
) {
    $clientLock = $Source.IndexOf(
        'Enter-PSOBBClientOperationLock', [System.StringComparison]::Ordinal)
    $lifecycleLock = $Source.IndexOf(
        "'Local\PSOBB.Newserv.Start.'", [System.StringComparison]::Ordinal)
    $globalGates = @([regex]::Matches(
            $Source, 'Assert-PSOBBGlobalStoppedRuntime') | ForEach-Object Index)
    $activityBoundary = if ($globalGates.Count -gt 0) { $globalGates[0] } else { -1 }
    $lifecycleRelease = $Source.LastIndexOf(
        '$mutex.ReleaseMutex()', [System.StringComparison]::Ordinal)
    $clientRelease = $Source.LastIndexOf(
        'Exit-PSOBBClientOperationLock', [System.StringComparison]::Ordinal)
    $baseContract = ($clientLock -ge 0) -and
        ($lifecycleLock -gt $clientLock) -and
        ($activityBoundary -gt $lifecycleLock) -and
        ($globalGates.Count -ge $MinimumGlobalGateCount) -and
        ($lifecycleRelease -gt $activityBoundary) -and
        ($clientRelease -gt $lifecycleRelease) -and
        ($Source -notmatch '(?im)^\s*Stop-Process\b')
    if (-not $baseContract -or -not $RequireEphemeralLifecycleCoverage) {
        return $baseContract
    }

    $ephemeralStart = $Source.IndexOf(
        '$process.Start()', [System.StringComparison]::Ordinal)
    $ephemeralExit = $Source.IndexOf(
        '$process.WaitForExit(30000)', [System.StringComparison]::Ordinal)
    ($ephemeralStart -gt $activityBoundary) -and
        ($globalGates[-1] -lt $ephemeralStart) -and
        ($ephemeralExit -gt $ephemeralStart) -and
        ($lifecycleRelease -gt $ephemeralExit) -and
        ($clientRelease -gt $ephemeralExit)
}

$recoveryOperationSources = [ordered]@{
    Backup = [pscustomobject]@{
        Source = Get-Content -Raw -LiteralPath (
            Join-Path $repositoryRoot 'scripts\Backup-PSOBB.ps1')
        Gates = 2
        Ephemeral = $false
    }
    Restore = [pscustomobject]@{
        Source = Get-Content -Raw -LiteralPath (
            Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1')
        Gates = 3
        Ephemeral = $false
    }
    RestoreDrill = [pscustomobject]@{
        Source = $restoreDrillSource
        Gates = 2
        Ephemeral = $true
    }
}
foreach ($entry in $recoveryOperationSources.GetEnumerator()) {
    Add-Result "$($entry.Key) uses the global stopped-runtime boundary" (
        Test-RecoveryInterlockContract `
            -Source ([string]$entry.Value.Source) `
            -MinimumGlobalGateCount ([int]$entry.Value.Gates) `
            -RequireEphemeralLifecycleCoverage:$entry.Value.Ephemeral) `
        'client lock precedes lifecycle lock; shared census rejects lifecycle evidence, named processes/helpers, and every reserved listener'
}

function Test-ProtectedTree([Parameter(Mandatory)][string]$Path) {
    $items = @(Get-Item -Force -LiteralPath $Path) +
        @(Get-ChildItem -Force -LiteralPath $Path -Recurse)
    foreach ($item in $items) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not (Test-PSOBBProtectedAcl -Path $item.FullName)) {
            return $false
        }
    }
    $true
}

function Test-SuccessfulDrillEvidenceBinding(
    [Parameter(Mandatory)]$Drill,
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory)][string]$ManifestPath
) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        return $false
    }
    ($Drill.schemaVersion -eq 3) -and ($Drill.passed -eq $true) -and
        ($Manifest.schemaVersion -eq 3) -and
        ([string]$Drill.backupManifestSha256 -ceq (Get-LowerSha256 $ManifestPath)) -and
        ([string]$Drill.serverExecutableSha256 -ceq [string]$Drill.approvedServerExecutableSha256) -and
        ([string]$Drill.serverExecutableSha256 -ceq [string]$Manifest.serverExecutable.sha256) -and
        ([string]$Drill.clientPatchProfile -ceq [string]$Manifest.clientPatchState.profile) -and
        ([string]$Drill.clientPatchPolicySha256 -ceq [string]$Manifest.clientPatchState.policySha256) -and
        ([string]$Drill.clientPatchConfigSha256 -ceq [string]$Manifest.clientPatchState.configSha256) -and
        ([string]$Drill.installationRecordSha256 -ceq [string]$Manifest.clientPatchState.installationSha256)
}

Add-Result 'restore drill never invokes credential-dumping list-accounts' `
    ($restoreDrillSource -notmatch $credentialDumpCommandPattern) `
    'account indexing uses restored license files without shell credential output'

function New-FixtureConfig([Parameter(Mandatory)][string]$Fixture) {
    @"
{
  "BBRequiredPatches": [],
  "AutoPatches": [],
  "fixture": "$Fixture"
}
"@
}

function New-FixtureInstallationRecord(
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$RuntimeRoot,
    [string]$Profile = 'baseline'
) {
    $hash = [string]::new([char]'0', 64)
    [ordered]@{
        schemaVersion = 2
        installationId = $InstallationId
        initializedAtUtc = '2026-07-19T00:00:00.0000000+00:00'
        runtimeRoot = $RuntimeRoot
        serverVersion = 'fixture'
        serverArchiveSha256 = $hash
        serverExecutableSha256 = $hash
        serverBaseManifestSha256 = $hash
        clientVersion = 'fixture'
        clientArchiveSha256 = $hash
        baseClientExecutableSha256 = $hash
        baseClientManifestSha256 = $hash
        clientExecutableSha256 = $hash
        rendererVersion = 'fixture'
        rendererArchiveSha256 = $hash
        rendererWrapperSha256 = $hash
        rendererConfigurationSha256 = $hash
        patchManifestSha256 = $hash
        synchronizedPatchFiles = 0
        clientPatchProfile = $Profile
        clientPatchPolicySha256 = Get-LowerSha256 (
            Join-Path $repositoryRoot 'config\client-patch-profiles.json')
        networkScope = 'loopback-only'
    }
}

function Get-StateFingerprint(
    [Parameter(Mandatory)][string]$BaseRoot,
    [Parameter(Mandatory)][string]$InstallRecordPath
) {
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in @('system\licenses', 'system\players', 'system\teams')) {
        $root = Join-Path $BaseRoot $relative
        foreach ($file in @(Get-ChildItem -Force -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
            $path = [System.IO.Path]::GetRelativePath($BaseRoot, $file.FullName).Replace('\', '/')
            $records.Add("$path|$($file.Length)|$(Get-LowerSha256 $file.FullName)")
        }
    }
    $config = Join-Path $BaseRoot 'system\config.json'
    $configItem = Get-Item -LiteralPath $config
    $records.Add("system/config.json|$($configItem.Length)|$(Get-LowerSha256 $config)")
    $installItem = Get-Item -LiteralPath $InstallRecordPath
    $records.Add("stable/installation.json|$($installItem.Length)|$(Get-LowerSha256 $InstallRecordPath)")
    @($records | Sort-Object)
}

function Get-FullRecoveryFixtureFingerprint(
    [Parameter(Mandatory)][string]$Root
) {
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @((Get-Item -Force -LiteralPath $Root)) +
        @(Get-ChildItem -Force -LiteralPath $Root -Recurse | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($Root, $item.FullName).Replace('\', '/')
        $kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
        $digest = if ($item.PSIsContainer) { '-' } else { Get-LowerSha256 $item.FullName }
        $sddl = (Get-Acl -LiteralPath $item.FullName).Sddl
        $records.Add("$relative|$kind|$($item.Attributes)|$digest|$sddl")
    }
    @($records)
}

function Invoke-RestoreHardExitChild(
    [Parameter(Mandatory)][string]$RestoreScript,
    [Parameter(Mandatory)][string]$BackupPath,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$Nonce,
    [Parameter(Mandatory)][string]$Point
) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Join-Path $PSHOME 'pwsh.exe'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $RestoreScript,
            '-BackupPath', $BackupPath, '-RuntimeRoot', $Layout.Root,
            '-Confirm:$false', '-InternalTestHardExitPoint', $Point,
            '-InternalTestFaultToken', $InstallationId,
            '-InternalTestFaultNonce', $Nonce)) {
        $startInfo.ArgumentList.Add([string]$argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Hard-exit restore fixture process did not start'
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(90000)) {
            $process.Kill($true)
            throw 'Hard-exit restore fixture process timed out'
        }
        [void]$stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Set-FixtureLiveMutation(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Timestamp
) {
    [System.IO.File]::WriteAllText(
        (Join-Path $Layout.Server 'system\config.json'),
        (New-FixtureConfig -Fixture $Name),
        [System.Text.UTF8Encoding]::new($false))
    $record = (Read-PSOBBInstallationRecordSnapshot `
        -Path $Layout.InstallRecord -Root $Layout.Root `
        -ExpectedInstallationId $InstallationId `
        -ExpectedRuntimeRoot $Layout.Root).Value
    $record.initializedAtUtc = $Timestamp
    [System.IO.File]::WriteAllText(
        $Layout.InstallRecord,
        ($record | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    & (Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1') `
        -RuntimeRoot $Layout.Root -Confirm:$false | Out-Null
}

function Test-RejectedBackup(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$SourceBackup,
    [Parameter(Mandatory)][scriptblock]$Mutator,
    [Parameter(Mandatory)][string]$ExpectedMessage
) {
    $testBackup = Join-Path $Layout.Backups ('state-validation-test-' + [Guid]::NewGuid().ToString('N'))
    Assert-PathWithinRoot -Path $testBackup -Root $Layout.Backups | Out-Null
    try {
        Copy-Item -LiteralPath $SourceBackup -Destination $testBackup -Recurse
        & $Mutator $testBackup
        Set-PSOBBProtectedTreeAcl -Path $testBackup -Root $Layout.Backups
        try {
            & (Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1') `
                -BackupPath $testBackup -RuntimeRoot $Layout.Root -ValidateOnly | Out-Null
            return $false
        } catch {
            return $_.Exception.Message -match $ExpectedMessage
        }
    } finally {
        if (Test-Path -LiteralPath $testBackup) {
            Remove-Item -LiteralPath $testBackup -Recurse -Force
        }
    }
}

function Test-RedactedBackupRejection(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$SourceBackup,
    [Parameter(Mandatory)][string]$RelativePath,
    [Parameter(Mandatory)][string]$Sentinel
) {
    $testBackup = Join-Path $Layout.Backups (
        'state-redaction-test-' + [Guid]::NewGuid().ToString('N'))
    try {
        Copy-Item -LiteralPath $SourceBackup -Destination $testBackup -Recurse
        $target = Join-Path $testBackup ($RelativePath.Replace('/', '\'))
        [System.IO.File]::AppendAllText($target, 'tampered')
        Set-PSOBBProtectedTreeAcl -Path $testBackup -Root $Layout.Backups
        try {
            & (Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1') `
                -BackupPath $testBackup -RuntimeRoot $Layout.Root `
                -ValidateOnly | Out-Null
            return $false
        } catch {
            return $_.Exception.Message -notmatch [regex]::Escape($Sentinel)
        }
    } finally {
        if (Test-Path -LiteralPath $testBackup) {
            Remove-Item -LiteralPath $testBackup -Recurse -Force
        }
    }
}

$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
$testRoot = Join-Path $temporaryBase ('PSOBB-RecoveryTests-' + [Guid]::NewGuid().ToString('N'))
$testLayout = Get-PSOBBLayout -RuntimeRoot $testRoot
if (-not $testLayout.Root.StartsWith($temporaryBase + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovery test root is not beneath the current user temporary directory'
}

try {
    foreach ($directory in @(
        $testLayout.Server,
        (Join-Path $testLayout.Server 'system\licenses'),
        (Join-Path $testLayout.Server 'system\players'),
        (Join-Path $testLayout.Server 'system\teams'),
        $testLayout.Backups,
        $testLayout.Secrets,
        $testLayout.Logs,
        (Join-Path $testLayout.Root 'graphics-evidence'),
        (Join-Path $testLayout.Archives 'graphics-lab\local-assets'),
        (Join-Path $testLayout.LocalLab 'asset-overlays'),
        (Join-Path $testLayout.LocalLab 'asset-activations'),
        (Join-Path $testLayout.LocalLab 'visual-asset-activations')
    )) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $liveLayout.Server 'newserv-windows.exe') `
        -Destination (Join-Path $testLayout.Server 'newserv-windows.exe')
    [System.IO.File]::WriteAllText(
        (Join-Path $testLayout.Server 'system\config.json'),
        (New-FixtureConfig -Fixture 'original'),
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $testLayout.Server 'system\licenses\0000000001.json'),
        '{"fixture":"license-original"}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $testLayout.Server 'system\teams\base.json'),
        '{"fixture":true}',
        [System.Text.UTF8Encoding]::new($false))
    $redactionFixtures = [ordered]@{
        'DO-NOT-LEAK-LICENSE.json' = 'system/licenses/DO-NOT-LEAK-LICENSE.json'
        'DO-NOT-LEAK-PLAYER.psochar' = 'system/players/DO-NOT-LEAK-PLAYER.psochar'
        'DO-NOT-LEAK-BANK.psobank' = 'system/players/DO-NOT-LEAK-BANK.psobank'
        'DO-NOT-LEAK-TEAM.json' = 'system/teams/DO-NOT-LEAK-TEAM.json'
    }
    foreach ($fixture in $redactionFixtures.GetEnumerator()) {
        [System.IO.File]::WriteAllText(
            (Join-Path $testLayout.Server ($fixture.Value.Replace('/', '\'))),
            '{"fixture":true}',
            [System.Text.UTF8Encoding]::new($false))
    }
    $testMarker = Initialize-PSOBBRuntimeMarker -Layout $testLayout
    [System.IO.File]::WriteAllText(
        (Join-Path $testLayout.Root '.recovery-test.json'),
        '{"fixture":true}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path (Join-Path $testLayout.Root '.recovery-test.json')
    [System.IO.File]::WriteAllText(
        $testLayout.InstallRecord,
        ((New-FixtureInstallationRecord `
                -InstallationId $testMarker.installationId `
                -RuntimeRoot $testLayout.Root) | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))

    $backup = & (Join-Path $repositoryRoot 'scripts\Backup-PSOBB.ps1') `
        -RuntimeRoot $testLayout.Root -Retention 2
    Add-Result 'published backup tree has exact protected DACLs' `
        (Test-ProtectedTree -Path $backup.BackupPath) `
        'all backup directories and files are explicit, protected, and reparse-free'
    $original = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    $validation = & (Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1') `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root -ValidateOnly
    $validationManifestSnapshot = Read-PSOBBRecoveryManifestSnapshot `
        -Path (Join-Path $backup.BackupPath 'manifest.json') `
        -Root $backup.BackupPath
    $validationManifest = $validationManifestSnapshot.Value
    Add-Result 'schema-v3 backup validates' `
        (($validationManifest.schemaVersion -eq 3) -and
        ([string]$validation.ClientPatchProfile -ceq 'baseline') -and
        ($validation.PSObject.Properties.Name -notcontains 'Manifest') -and
        (@($validationManifest.files | Where-Object path -CEQ 'system/config.json').Count -eq 1) -and
        (@($validationManifest.files | Where-Object path -CEQ 'stable/installation.json').Count -eq 1) -and
        (@($validationManifest.stateRoots | Where-Object path -CEQ 'stable/installation.json').Count -eq 1)) `
        $validation.ManifestSha256
    $validationJson = $validation | ConvertTo-Json -Depth 5
    Add-Result 'restore validation result redacts account and save filenames' (
        @($redactionFixtures.Keys | Where-Object {
                $validationJson.Contains(
                    [string]$_, [System.StringComparison]::Ordinal)
            }).Count -eq 0) `
        'the public validation object exposes counts and digests, never manifest paths'

    $licenseReaderRoot = Join-Path $testLayout.Backups (
        'license-reader-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $licenseReaderRoot | Out-Null
    $escapedLicensePath = Join-Path $licenseReaderRoot 'escaped-license.json'
    [System.IO.File]::WriteAllText(
        $escapedLicensePath,
        '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"escapeuser","Password":"ESCAPED\u0053ECRET"}]}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl `
        -Path $licenseReaderRoot -Root $testLayout.Backups
    $decodedNames = [System.Collections.Generic.Dictionary[string, int]]::new(
        [System.StringComparer]::Ordinal)
    $decodedPasswords = [System.Collections.Generic.List[string]]::new()
    $decodedCount = Add-PSOBBRecoveryBBLicenseRedactionTerms `
        -Path $escapedLicensePath -Root $licenseReaderRoot `
        -UserNameCounts $decodedNames -Passwords $decodedPasswords `
        -Label 'escaped license fixture'
    Add-Result 'license redaction uses decoded strict JSON passwords' (
        $decodedCount -eq 1 -and $decodedNames['escapeuser'] -eq 1 -and
        $decodedPasswords.Count -eq 1 -and
        $decodedPasswords[0] -ceq 'ESCAPEDSECRET') `
        'escaped JSON content is decoded before bounded redaction terms are collected'
    Remove-PSOBBValidatedRecoveryTree `
        -Path $licenseReaderRoot -Root $testLayout.Backups `
        -Label 'license reader fixture' -RequireProtectedAcl

    $reparseTarget = Join-Path $testLayout.Root 'reparse-target'
    New-Item -ItemType Directory -Path $reparseTarget | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $reparseTarget 'target.txt'), 'target',
        [System.Text.UTF8Encoding]::new($false))
    $backupReparseSentinel = 'DO-NOT-LEAK-BACKUP-REPARSE'
    $backupReparsePath = Join-Path $testLayout.Server (
        'system\players\' + $backupReparseSentinel)
    New-Item -ItemType Junction -Path $backupReparsePath `
        -Target $reparseTarget | Out-Null
    $backupCountBeforeReparse = @(Get-ChildItem -LiteralPath $testLayout.Backups `
        -Directory -Filter 'state-*').Count
    try {
        & (Join-Path $repositoryRoot 'scripts\Backup-PSOBB.ps1') `
            -RuntimeRoot $testLayout.Root | Out-Null
        $backupReparseRejected = $false
    } catch {
        $backupReparseRejected =
            -not $_.Exception.Message.Contains(
                $backupReparseSentinel,
                [System.StringComparison]::Ordinal)
    } finally {
        if (Test-Path -LiteralPath $backupReparsePath) {
            Remove-Item -LiteralPath $backupReparsePath -Force
        }
    }
    $backupCountAfterReparse = @(Get-ChildItem -LiteralPath $testLayout.Backups `
        -Directory -Filter 'state-*').Count
    Add-Result 'direct backup rejects and redacts a private reparse item' (
        $backupReparseRejected -and
        $backupCountAfterReparse -eq $backupCountBeforeReparse) `
        'no path disclosure and no backup publication'

    $restoreReparseSentinel = 'DO-NOT-LEAK-RESTORE-REPARSE'
    $restoreReparseBackup = Join-Path $testLayout.Backups (
        'state-reparse-' + [Guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $backup.BackupPath `
        -Destination $restoreReparseBackup -Recurse
    $restoreReparsePath = Join-Path $restoreReparseBackup (
        'system\players\' + $restoreReparseSentinel)
    New-Item -ItemType Junction -Path $restoreReparsePath `
        -Target $reparseTarget | Out-Null
    $liveBeforeRestoreReparse = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    try {
        & (Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1') `
            -BackupPath $restoreReparseBackup `
            -RuntimeRoot $testLayout.Root -ValidateOnly | Out-Null
        $restoreReparseRejected = $false
    } catch {
        $restoreReparseRejected =
            -not $_.Exception.Message.Contains(
                $restoreReparseSentinel,
                [System.StringComparison]::Ordinal)
    }
    $liveAfterRestoreReparse = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    if (Test-Path -LiteralPath $restoreReparsePath) {
        Remove-Item -LiteralPath $restoreReparsePath -Force
    }
    Remove-Item -LiteralPath $restoreReparseBackup -Recurse -Force
    Add-Result 'direct restore rejects and redacts a private reparse item' (
        $restoreReparseRejected -and
        @(Compare-Object $liveBeforeRestoreReparse $liveAfterRestoreReparse).Count -eq 0) `
        'validation neither leaks the item name nor mutates live state'

    $drillReparseSentinel = 'DO-NOT-LEAK-DRILL-REPARSE'
    $drillReparsePath = Join-Path $testLayout.Server $drillReparseSentinel
    New-Item -ItemType Junction -Path $drillReparsePath `
        -Target $reparseTarget | Out-Null
    try {
        & (Join-Path $repositoryRoot 'scripts\Test-PSOBBRestoreDrill.ps1') `
            -BackupPath $backup.BackupPath `
            -RuntimeRoot $testLayout.Root | Out-Null
        $drillReparseRejected = $false
    } catch {
        $drillReparseRejected =
            -not $_.Exception.Message.Contains(
                $drillReparseSentinel,
                [System.StringComparison]::Ordinal)
    } finally {
        if (Test-Path -LiteralPath $drillReparsePath) {
            Remove-Item -LiteralPath $drillReparsePath -Force
        }
    }
    Add-Result 'restore drill redacts a scaffold reparse item' `
        $drillReparseRejected `
        'the pre-scaffold boundary reports only a category and ordinal'

    $retentionFixtures = [System.Collections.Generic.List[string]]::new()
    for ($retentionIndex = 1; $retentionIndex -le 9; $retentionIndex++) {
        $retentionPath = Join-Path $testLayout.Backups (
            'pre-restore-20000101T00000' + $retentionIndex + '000Z')
        Copy-Item -LiteralPath $backup.BackupPath `
            -Destination $retentionPath -Recurse
        $retentionManifestPath = Join-Path $retentionPath 'manifest.json'
        $retentionManifest = Get-Content -Raw -LiteralPath $retentionManifestPath |
            ConvertFrom-Json
        $retentionManifest.backupKind = 'pre-restore'
        [System.IO.File]::WriteAllText(
            $retentionManifestPath,
            ($retentionManifest | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedTreeAcl `
            -Path $retentionPath -Root $testLayout.Backups
        $retentionFixtures.Add($retentionPath)
    }
    $preservedOldest = [string]$retentionFixtures[0]
    $preservedOldestManifestSha256 = Get-LowerSha256 (
        Join-Path $preservedOldest 'manifest.json')
    $retentionBackup = & (Join-Path $repositoryRoot 'scripts\Backup-PSOBB.ps1') `
        -RuntimeRoot $testLayout.Root -BackupKind pre-restore -Retention 7 `
        -PreserveBackupPath $preservedOldest `
        -PreserveBackupManifestSha256 $preservedOldestManifestSha256
    $remainingPreRestore = @(Get-ChildItem -LiteralPath $testLayout.Backups `
        -Directory -Filter 'pre-restore-*')
    Add-Result 'nested pre-restore retention preserves its selected target' (
        (Test-Path -LiteralPath $preservedOldest -PathType Container) -and
        (Test-ProtectedTree -Path $preservedOldest) -and
        $remainingPreRestore.Count -eq 8) `
        'seven newest backups plus the exact older protected target remain'
    foreach ($retentionPath in @($remainingPreRestore.FullName)) {
        Remove-PSOBBValidatedRecoveryTree `
            -Path $retentionPath -Root $testLayout.Backups `
            -Label 'retention fixture cleanup' -RequireProtectedAcl
    }

    $legacySuccessfulDrill = [pscustomobject]@{
        schemaVersion = 2
        passed = $true
        backupManifestSha256 = $validation.ManifestSha256
        approvedServerExecutableSha256 = $validation.ApprovedServerExecutableSha256
        serverExecutableSha256 = $validation.ApprovedServerExecutableSha256
        clientPatchProfile = $validation.ClientPatchProfile
        clientPatchPolicySha256 = $validation.ClientPatchPolicySha256
        clientPatchConfigSha256 = $validation.ClientPatchConfigSha256
        installationRecordSha256 = $validation.InstallationRecordSha256
    }
    $legacyDrillRejected = -not (Test-SuccessfulDrillEvidenceBinding `
        -Drill $legacySuccessfulDrill `
        -Manifest $validationManifest `
        -ManifestPath (Join-Path $backup.BackupPath 'manifest.json'))
    Add-Result 'schema-v2 successful drill evidence rejected' $legacyDrillRejected `
        'a prior evidence schema cannot satisfy the current live recovery gate'

    $patchManifestMismatchRejected = Test-RejectedBackup `
        -Layout $testLayout `
        -SourceBackup $backup.BackupPath `
        -ExpectedMessage 'clientPatchState does not match' `
        -Mutator {
        param($root)
        $manifestPath = Join-Path $root 'manifest.json'
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        $manifest.clientPatchState.configSha256 = [string]::new([char]'0', 64)
        [System.IO.File]::WriteAllText(
            $manifestPath,
            ($manifest | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
    }
    Add-Result 'client-patch manifest mismatch rejected' $patchManifestMismatchRejected `
        'manifest semantics are bound to verified file hashes'

    $legacyRejected = Test-RejectedBackup -Layout $testLayout -SourceBackup $backup.BackupPath `
        -ExpectedMessage '(exact property set|schema)' -Mutator {
        param($root)
        $manifestPath = Join-Path $root 'manifest.json'
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        $manifest.schemaVersion = 2
        $manifest.PSObject.Properties.Remove('clientPatchState')
        $manifest.stateRoots = @($manifest.stateRoots | Where-Object path -ne 'stable/installation.json')
        $manifest.files = @($manifest.files | Where-Object path -ne 'stable/installation.json')
        Remove-Item -LiteralPath (Join-Path $root 'stable\installation.json') -Force
        Remove-Item -LiteralPath (Join-Path $root 'stable') -Force
        [System.IO.File]::WriteAllText(
            $manifestPath,
            ($manifest | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
    }
    Add-Result 'incomplete schema-v2 backup rejected' $legacyRejected `
        'old backups cannot restore config without installation metadata'

    $profileMismatchRejected = Test-RejectedBackup `
        -Layout $testLayout `
        -SourceBackup $backup.BackupPath `
        -ExpectedMessage 'config does not match client-patch profile metadata' `
        -Mutator {
        param($root)
        $installPath = Join-Path $root 'stable\installation.json'
        $record = Get-Content -Raw -LiteralPath $installPath | ConvertFrom-Json
        $record.clientPatchProfile = 'stable-qol'
        [System.IO.File]::WriteAllText(
            $installPath,
            ($record | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
        $manifestPath = Join-Path $root 'manifest.json'
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        $entry = @($manifest.files | Where-Object path -CEQ 'stable/installation.json')[0]
        $entry.size = (Get-Item -LiteralPath $installPath).Length
        $entry.sha256 = Get-LowerSha256 $installPath
        $manifest.clientPatchState.profile = 'stable-qol'
        $manifest.clientPatchState.installationSha256 = $entry.sha256
        [System.IO.File]::WriteAllText(
            $manifestPath,
            ($manifest | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
    }
    Add-Result 'config and installation profile mismatch rejected' $profileMismatchRejected `
        'semantic client-patch profile binding'

    $extraRejected = Test-RejectedBackup -Layout $testLayout -SourceBackup $backup.BackupPath `
        -ExpectedMessage 'exact manifest' -Mutator {
        param($root)
        [System.IO.File]::WriteAllText(
            (Join-Path $root 'system\licenses\unmanifested.json'),
            '{}',
            [System.Text.UTF8Encoding]::new($false))
    }
    Add-Result 'unmanifested file rejected' $extraRejected 'exact-file-set enforcement'

    $missingRejected = Test-RejectedBackup -Layout $testLayout -SourceBackup $backup.BackupPath `
        -ExpectedMessage 'missing' -Mutator {
        param($root)
        $manifest = Get-Content -Raw -LiteralPath (Join-Path $root 'manifest.json') | ConvertFrom-Json
        $target = @($manifest.files | Where-Object path -match '^system/licenses/' | Select-Object -First 1)
        if ($target.Count -ne 1) { throw 'Test backup has no removable state file' }
        Remove-Item -LiteralPath (Join-Path $root ($target[0].path.Replace('/', '\'))) -Force
    }
    Add-Result 'manifested missing file rejected' $missingRejected 'completeness enforcement'

    $corruptRejected = Test-RejectedBackup -Layout $testLayout -SourceBackup $backup.BackupPath `
        -ExpectedMessage '(size|checksum)' -Mutator {
        param($root)
        $stream = [System.IO.File]::Open((Join-Path $root 'system\config.json'), [System.IO.FileMode]::Append)
        try { $stream.WriteByte(0) } finally { $stream.Dispose() }
    }
    Add-Result 'corrupt file rejected' $corruptRejected 'size and SHA-256 enforcement'

    foreach ($fixture in $redactionFixtures.GetEnumerator()) {
        Add-Result "restore error redacts $($fixture.Key)" (
            Test-RedactedBackupRejection `
                -Layout $testLayout -SourceBackup $backup.BackupPath `
                -RelativePath ([string]$fixture.Value) `
                -Sentinel ([string]$fixture.Key)) `
            'account, character, bank, and team filenames never cross the error boundary'
    }

    $failedDrillBackup = Join-Path $testLayout.Backups ('state-failed-drill-' + [Guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $backup.BackupPath -Destination $failedDrillBackup -Recurse
    [System.IO.File]::WriteAllText(
        (Join-Path $failedDrillBackup 'system\licenses\unmanifested.json'),
        '{}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl `
        -Path $failedDrillBackup -Root $testLayout.Backups
    $failedDrillManifestHash = (Read-PSOBBRecoveryManifestSnapshot `
        -Path (Join-Path $failedDrillBackup 'manifest.json') `
        -Root $failedDrillBackup).Sha256
    try {
        & (Join-Path $repositoryRoot 'scripts\Test-PSOBBRestoreDrill.ps1') `
            -BackupPath $failedDrillBackup -RuntimeRoot $testLayout.Root | Out-Null
        $failedDrillRejected = $false
    } catch {
        $failedDrillRejected = $true
    }
    $failedDrillRoot = Get-ChildItem -LiteralPath $testLayout.Backups -Directory -Filter 'restore-drill-*' |
        Sort-Object Name -Descending | Select-Object -First 1
    $failedDrillResult = Get-Content -Raw -LiteralPath (Join-Path $failedDrillRoot.FullName 'drill-result.json') | ConvertFrom-Json
    $failedEvidenceBound = $failedDrillRejected -and ($failedDrillResult.passed -eq $false) -and
        ($failedDrillResult.schemaVersion -eq 3) -and
        ($failedDrillResult.backupManifestSha256 -eq $failedDrillManifestHash) -and
        ($failedDrillResult.approvedServerExecutableSha256 -eq $validation.ApprovedServerExecutableSha256)
    Add-Result 'failed drill writes bound evidence' $failedEvidenceBound (
        "rejected=$failedDrillRejected; schema=$($failedDrillResult.schemaVersion); " +
        "manifest=$($failedDrillResult.backupManifestSha256); approved=$($failedDrillResult.approvedServerExecutableSha256)")
    $failedDrillResultText = Get-Content -Raw -LiteralPath (
        Join-Path $failedDrillRoot.FullName 'drill-result.json')
    Add-Result 'failed drill result redacts account and save filenames' (
        @($redactionFixtures.Keys | Where-Object {
                $failedDrillResultText.Contains(
                    [string]$_, [System.StringComparison]::Ordinal)
            }).Count -eq 0) `
        'persisted failure evidence contains only a generic protected boundary'
    $failedDrillChildren = @(Get-ChildItem -Force -LiteralPath $failedDrillRoot.FullName)
    Add-Result 'failed drill retains result only' `
        (($failedDrillChildren.Count -eq 1) -and ($failedDrillChildren[0].Name -eq 'drill-result.json')) `
        "$($failedDrillChildren.Count) retained item(s)"
    Add-Result 'failed drill evidence has exact protected DACLs' `
        (Test-ProtectedTree -Path $failedDrillRoot.FullName) `
        'retained drill directory and result are explicit and protected'
    Remove-Item -LiteralPath $failedDrillBackup -Recurse -Force

    # Prove the real transaction replaces extras, captures an emergency backup,
    # preserves exact bytes, and leaves no stage or rollback tree behind.
    [System.IO.File]::WriteAllText(
        (Join-Path $testLayout.Server 'system\config.json'),
        (New-FixtureConfig -Fixture 'mutated-before-restore'),
        [System.Text.UTF8Encoding]::new($false))
    $mutatedRecord = (Read-PSOBBInstallationRecordSnapshot `
        -Path $testLayout.InstallRecord -Root $testLayout.Root `
        -ExpectedInstallationId ([string]$testMarker.installationId) `
        -ExpectedRuntimeRoot $testLayout.Root).Value
    $mutatedRecord.initializedAtUtc = '2026-07-19T00:00:01.0000000+00:00'
    [System.IO.File]::WriteAllText(
        $testLayout.InstallRecord,
        ($mutatedRecord | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $testLayout.Server 'system\players\unmanifested-live.json'),
        '{"fixture":"must-be-replaced"}',
        [System.Text.UTF8Encoding]::new($false))
    $preRestore = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    $restored = & (Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1') `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root -Confirm:$false
    $afterRestore = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    $restoredExactly = @(Compare-Object -ReferenceObject $original -DifferenceObject $afterRestore).Count -eq 0
    Add-Result 'staged restore reproduces state and patch metadata' `
        $restoredExactly "$($afterRestore.Count) restored fingerprints"

    $emergencyValidation = & (Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1') `
        -BackupPath $restored.EmergencyBackup -RuntimeRoot $testLayout.Root -ValidateOnly
    $emergencyState = @(Get-StateFingerprint `
        -BaseRoot $emergencyValidation.BackupPath `
        -InstallRecordPath (Join-Path $emergencyValidation.BackupPath 'stable\installation.json'))
    $emergencyExact = @(Compare-Object -ReferenceObject $preRestore -DifferenceObject $emergencyState).Count -eq 0
    Add-Result 'emergency backup captures pre-restore state' $emergencyExact $restored.EmergencyManifestSha256
    Add-Result 'emergency backup tree has exact protected DACLs' `
        (Test-ProtectedTree -Path $restored.EmergencyBackup) `
        'pre-restore evidence uses the same protected publication path'

    $restoreScript = Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1'
    Set-FixtureLiveMutation `
        -Layout $testLayout `
        -InstallationId ([string]$testMarker.installationId) `
        -Name 'hard-exit-after-original' `
        -Timestamp '2026-07-19T00:00:02.0000000+00:00'
    $afterOriginalExitCode = Invoke-RestoreHardExitChild `
        -RestoreScript $restoreScript -BackupPath $backup.BackupPath `
        -Layout $testLayout `
        -InstallationId ([string]$testMarker.installationId) `
        -Nonce ([Guid]::NewGuid().ToString('N')) `
        -Point 'swap-1-after-original-move'
    $afterOriginalInterrupted = @(Get-FullRecoveryFixtureFingerprint `
        -Root $testLayout.Root)
    $afterOriginalValidation = & $restoreScript `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root `
        -ValidateOnly
    $afterOriginalAfterValidation = @(Get-FullRecoveryFixtureFingerprint `
        -Root $testLayout.Root)
    $afterOriginalWhatIf = & $restoreScript `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root -WhatIf
    $afterOriginalAfterWhatIf = @(Get-FullRecoveryFixtureFingerprint `
        -Root $testLayout.Root)
    Add-Result 'validation and WhatIf do not resume an interrupted restore' (
        $afterOriginalExitCode -eq 86 -and
        $afterOriginalValidation.RecoveryRequired -and
        $afterOriginalWhatIf.RecoveryRequired -and
        @(Compare-Object $afterOriginalInterrupted $afterOriginalAfterValidation).Count -eq 0 -and
        @(Compare-Object $afterOriginalInterrupted $afterOriginalAfterWhatIf).Count -eq 0) `
        'journal, ACL, tree, and split live-state bytes remain unchanged'
    $afterOriginalResume = & $restoreScript `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root `
        -Confirm:$false
    $afterOriginalState = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    $afterOriginalDebris = @(Get-ChildItem -Force `
        -LiteralPath $testLayout.Stable -Filter '.psobb-restore-*')
    Add-Result 'hard exit after original move resumes idempotently' (
        $afterOriginalResume.RecoveredInterruptedTransaction -and
        @(Compare-Object $original $afterOriginalState).Count -eq 0 -and
        $afterOriginalDebris.Count -eq 0) `
        'protected rollback is restored, verified, then the requested target is applied'

    Set-FixtureLiveMutation `
        -Layout $testLayout `
        -InstallationId ([string]$testMarker.installationId) `
        -Name 'hard-exit-accepted-cleanup' `
        -Timestamp '2026-07-19T00:00:03.0000000+00:00'
    $acceptedCleanupExitCode = Invoke-RestoreHardExitChild `
        -RestoreScript $restoreScript -BackupPath $backup.BackupPath `
        -Layout $testLayout `
        -InstallationId ([string]$testMarker.installationId) `
        -Nonce ([Guid]::NewGuid().ToString('N')) `
        -Point 'cleanup-stage-after-removal'
    $acceptedCleanupInterrupted = @(Get-FullRecoveryFixtureFingerprint `
        -Root $testLayout.Root)
    $acceptedCleanupValidation = & $restoreScript `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root `
        -ValidateOnly
    $acceptedCleanupAfterValidation = @(Get-FullRecoveryFixtureFingerprint `
        -Root $testLayout.Root)
    Add-Result 'accepted partial cleanup is read-only under validation' (
        $acceptedCleanupExitCode -eq 86 -and
        $acceptedCleanupValidation.RecoveryRequired -and
        @(Compare-Object $acceptedCleanupInterrupted $acceptedCleanupAfterValidation).Count -eq 0) `
        'an absent staging tree is accepted only after exact target-state proof'
    $acceptedCleanupResume = & $restoreScript `
        -BackupPath $backup.BackupPath -RuntimeRoot $testLayout.Root `
        -Confirm:$false
    $acceptedCleanupState = @(Get-StateFingerprint `
        -BaseRoot $testLayout.Server `
        -InstallRecordPath $testLayout.InstallRecord)
    $acceptedCleanupDebris = @(Get-ChildItem -Force `
        -LiteralPath $testLayout.Stable -Filter '.psobb-restore-*')
    Add-Result 'accepted cleanup hard exit resumes idempotently' (
        $acceptedCleanupResume.RecoveredInterruptedTransaction -and
        @(Compare-Object $original $acceptedCleanupState).Count -eq 0 -and
        $acceptedCleanupDebris.Count -eq 0) `
        'remaining protected rollback and journal artifacts are removed in order'

    $debris = @(Get-ChildItem -Force -LiteralPath $testLayout.Stable -Filter '.psobb-restore-*')
    Add-Result 'restore leaves no transaction debris' ($debris.Count -eq 0) "$($debris.Count) item(s)"
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        if (Test-Path -LiteralPath $testLayout.RuntimeMarker -PathType Leaf) {
            Assert-PSOBBRuntimeMarker -Layout $testLayout | Out-Null
        }
        Assert-PathWithinRoot -Path $testRoot -Root $temporaryBase | Out-Null
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

$latestDrill = if (-not $SkipLiveDrillEvidence) {
    Get-ChildItem -LiteralPath $liveLayout.Backups -Directory -Filter 'restore-drill-*' |
        Sort-Object Name -Descending |
        Select-Object -First 1
} else { $null }
if (-not $SkipLiveDrillEvidence -and $latestDrill -and
    (Test-Path -LiteralPath (Join-Path $latestDrill.FullName 'drill-result.json') -PathType Leaf)) {
    $drillPath = Join-Path $latestDrill.FullName 'drill-result.json'
    $drill = Get-Content -Raw -LiteralPath $drillPath | ConvertFrom-Json
    $drillBackupManifest = Join-Path (Join-Path $liveLayout.Backups $drill.backup) 'manifest.json'
    $drillManifest = if (Test-Path -LiteralPath $drillBackupManifest -PathType Leaf) {
        Get-Content -Raw -LiteralPath $drillBackupManifest | ConvertFrom-Json
    } else { $null }
    $bound = ($null -ne $drillManifest) -and (Test-SuccessfulDrillEvidenceBinding `
        -Drill $drill -Manifest $drillManifest -ManifestPath $drillBackupManifest)
    $bindingDetail = if ($bound) {
        $latestDrill.Name
    } else {
        "$($latestDrill.Name); drillSchema=$($drill.schemaVersion); " +
            "backup=$($drill.backup); backupSchema=$($drillManifest.schemaVersion); " +
            "passed=$($drill.passed); required=schema-v3 backup plus schema-v3 successful drill"
    }
    Add-Result 'drill evidence is cryptographically bound' $bound $bindingDetail
    $children = @(Get-ChildItem -Force -LiteralPath $latestDrill.FullName)
    $small = ($children.Count -eq 1) -and ($children[0].Name -eq 'drill-result.json') -and
        ($children[0].Length -lt 64KB)
    Add-Result 'drill retains result only' $small "$($children.Count) retained item(s)"
} elseif (-not $SkipLiveDrillEvidence) {
    Add-Result 'drill evidence is cryptographically bound' $false 'no drill result'
    Add-Result 'drill retains result only' $false 'no drill result'
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) recovery-script test(s) failed"
}
[pscustomobject]@{ Suite = 'RecoveryScripts'; Passed = $results.Count; Failed = 0 }
