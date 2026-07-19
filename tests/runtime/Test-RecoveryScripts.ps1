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
    $testMarker = Initialize-PSOBBRuntimeMarker -Layout $testLayout
    [System.IO.File]::WriteAllText(
        $testLayout.InstallRecord,
        ([ordered]@{
            schemaVersion = 2
            installationId = $testMarker.installationId
            runtimeRoot = $testLayout.Root
            clientPatchProfile = 'baseline'
            clientPatchPolicySha256 = Get-LowerSha256 (
                Join-Path $repositoryRoot 'config\client-patch-profiles.json')
            fixture = 'installation-original'
        } | ConvertTo-Json -Depth 5),
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
    Add-Result 'schema-v3 backup validates' `
        (($validation.Manifest.schemaVersion -eq 3) -and
        ([string]$validation.Manifest.clientPatchState.profile -ceq 'baseline') -and
        (@($validation.Manifest.files | Where-Object path -CEQ 'system/config.json').Count -eq 1) -and
        (@($validation.Manifest.files | Where-Object path -CEQ 'stable/installation.json').Count -eq 1) -and
        (@($validation.Manifest.stateRoots | Where-Object path -CEQ 'stable/installation.json').Count -eq 1)) `
        $validation.ManifestSha256

    $legacySuccessfulDrill = [pscustomobject]@{
        schemaVersion = 2
        passed = $true
        backupManifestSha256 = $validation.ManifestSha256
        approvedServerExecutableSha256 = $validation.ApprovedServerExecutableSha256
        serverExecutableSha256 = $validation.ApprovedServerExecutableSha256
        clientPatchProfile = $validation.Manifest.clientPatchState.profile
        clientPatchPolicySha256 = $validation.Manifest.clientPatchState.policySha256
        clientPatchConfigSha256 = $validation.Manifest.clientPatchState.configSha256
        installationRecordSha256 = $validation.Manifest.clientPatchState.installationSha256
    }
    $legacyDrillRejected = -not (Test-SuccessfulDrillEvidenceBinding `
        -Drill $legacySuccessfulDrill `
        -Manifest $validation.Manifest `
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
        -ExpectedMessage 'schema 2.*installation.json.*schema 3' -Mutator {
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

    $failedDrillBackup = Join-Path $testLayout.Backups ('state-failed-drill-' + [Guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $backup.BackupPath -Destination $failedDrillBackup -Recurse
    [System.IO.File]::WriteAllText(
        (Join-Path $failedDrillBackup 'system\licenses\unmanifested.json'),
        '{}',
        [System.Text.UTF8Encoding]::new($false))
    $failedDrillManifestHash = Get-LowerSha256 (Join-Path $failedDrillBackup 'manifest.json')
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
    $mutatedRecord = Get-Content -Raw -LiteralPath $testLayout.InstallRecord | ConvertFrom-Json
    $mutatedRecord.fixture = 'installation-mutated-before-restore'
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

    $debris = @(Get-ChildItem -Force -LiteralPath $testLayout.Stable -Filter '.psobb-restore-*')
    Add-Result 'restore leaves no transaction debris' ($debris.Count -eq 0) "$($debris.Count) item(s)"
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Assert-PSOBBRuntimeMarker -Layout $testLayout | Out-Null
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
