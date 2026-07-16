[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
$initializerPath = Join-Path $repositoryRoot 'scripts\Initialize-PSOBBClientRegistry.ps1'
. $commonPath

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function New-NativeGraphicsFixture {
    param([ValidateSet('High', 'Mid')][string]$Preset)

    if ($Preset -ceq 'High') {
        [pscustomobject]@{
            presetId = 'high-end'
            graphicCtrlDwords = @(0, 0, 0, 0, 1, 1, 1, 0, 0)
            graphicCtrlSha256 = '302f04ac1917b0eaecef147a99f7cada007b8bb8cc9ac1d9fd16b1a47d72e8a4'
            advancedEffectsPolicy = 'enabled'
            pixelFogPolicy = 'pixel'
            lowResolutionTexturesPolicy = 'disabled'
            frameSkipPolicy = 'disabled'
        }
    } else {
        [pscustomobject]@{
            presetId = 'mid-compatibility'
            graphicCtrlDwords = @(1, 0, 0, 0, 1, 1, 1, 0, 0)
            graphicCtrlSha256 = 'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917'
            advancedEffectsPolicy = 'compatibility'
            pixelFogPolicy = 'pixel'
            lowResolutionTexturesPolicy = 'disabled'
            frameSkipPolicy = 'disabled'
        }
    }
}

function Test-ByteSequence {
    param([byte[]]$Left, [byte[]]$Right)

    if ($Left.Count -ne $Right.Count) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Count; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    $true
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-GraphicCtrlTests-' + [Guid]::NewGuid().ToString('N'))
$registryPath = 'HKCU:\Software\PSOBB-GraphicCtrlTests-' +
    [Guid]::NewGuid().ToString('N')
$accountSentinel = 'fixture-account-preserve'
$passwordSentinel = [byte[]](0x81, 0x19, 0x42, 0xEE, 0x07)
$controlSentinel = [byte[]](9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8)
$soundSentinel = [byte[]](7, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0, 0)

try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    $layout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    Initialize-PSOBBRuntimeMarker -Layout $layout | Out-Null
    New-Item -Path $registryPath -Force | Out-Null
    $midBytes = ConvertTo-PSOBBGraphicCtrlBytes `
        -Dwords ([object[]]@(1, 0, 0, 0, 1, 1, 1, 0, 0))
    New-ItemProperty -LiteralPath $registryPath -Name GRAPHICCTRL `
        -PropertyType Binary -Value $midBytes | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name ACCOUNT_CHECK `
        -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name ACCOUNT `
        -PropertyType String -Value $accountSentinel | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name PASSWORD `
        -PropertyType Binary -Value $passwordSentinel | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name CTRLBUF `
        -PropertyType Binary -Value $controlSentinel | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name SOUNDCTRL `
        -PropertyType Binary -Value $soundSentinel | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name WINDOW_MODE `
        -PropertyType DWord -Value 0 | Out-Null

    $highProfile = [pscustomobject]@{
        nativeGraphics = New-NativeGraphicsFixture -Preset High
    }
    $transaction = Set-PSOBBClientNativeGraphics `
        -Layout $layout `
        -Profile $highProfile `
        -RegistryPath $registryPath
    $highState = Get-PSOBBClientGraphicCtrlState -RegistryPath $registryPath
    Add-Result 'high profile applies exact nine-DWORD vector' (
        $transaction.Applied -and
        $transaction.PresetId -ceq 'high-end' -and
        $highState.Sha256 -ceq
            '302f04ac1917b0eaecef147a99f7cada007b8bb8cc9ac1d9fd16b1a47d72e8a4') `
        'the exact little-endian 36-byte value is hash verified after write'

    $registry = Get-Item -LiteralPath $registryPath
    $accountAfter = $registry.GetValue('ACCOUNT')
    $passwordAfter = [byte[]]$registry.GetValue('PASSWORD')
    Add-Result 'graphics application preserves remembered login values' (
        [string]$accountAfter -ceq $accountSentinel -and
        (Test-ByteSequence -Left $passwordAfter -Right $passwordSentinel) -and
        $registry.GetValueKind('ACCOUNT') -eq
            [Microsoft.Win32.RegistryValueKind]::String -and
        $registry.GetValueKind('PASSWORD') -eq
            [Microsoft.Win32.RegistryValueKind]::Binary -and
        [int]$registry.GetValue('ACCOUNT_CHECK') -eq 1) `
        'ACCOUNT, PASSWORD, ACCOUNT_CHECK, and their registry kinds are unchanged'

    $backupText = Get-Content -Raw -LiteralPath $transaction.BackupPath
    $backup = $backupText | ConvertFrom-Json -Depth 5
    $backupAcl = Get-Acl -LiteralPath $transaction.BackupPath
    Add-Result 'backup is ACL-protected and GRAPHICCTRL-only' (
        $backupAcl.AreAccessRulesProtected -and
        [string]$backup.registryValueName -ceq 'GRAPHICCTRL' -and
        [string]$backup.registryValueKind -ceq 'Binary' -and
        [string]$backup.graphicCtrlSha256 -ceq
            'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917' -and
        $backupText -cnotmatch 'ACCOUNT|PASSWORD|credential') `
        'no whole-key export or credential-bearing field is written'

    $backupCountBeforeNoOp = @(Get-ChildItem -LiteralPath (
        Split-Path -Parent $transaction.BackupPath) -File).Count
    $noOp = Set-PSOBBClientNativeGraphics `
        -Layout $layout `
        -Profile $highProfile `
        -RegistryPath $registryPath
    $backupCountAfterNoOp = @(Get-ChildItem -LiteralPath (
        Split-Path -Parent $transaction.BackupPath) -File).Count
    Add-Result 'already-active vector is verified without redundant backup' (
        -not $noOp.Applied -and
        $null -eq $noOp.BackupPath -and
        $backupCountAfterNoOp -eq $backupCountBeforeNoOp) `
        'idempotent starts do not grow value-only recovery state'

    $restored = Restore-PSOBBClientGraphicCtrlBackup `
        -Layout $layout `
        -BackupPath $transaction.BackupPath `
        -RegistryPath $registryPath
    $midState = Get-PSOBBClientGraphicCtrlState -RegistryPath $registryPath
    Add-Result 'protected backup restores the prior vector' (
        $restored.Restored -and
        $midState.Sha256 -ceq
            'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917') `
        'startup failure can restore the exact pre-launch GRAPHICCTRL value'

    Set-PSOBBClientNativeGraphics -Layout $layout -Profile $highProfile `
        -RegistryPath $registryPath | Out-Null
    $midProfile = [pscustomobject]@{
        nativeGraphics = New-NativeGraphicsFixture -Preset Mid
    }
    $rollbackProfile = Set-PSOBBClientNativeGraphics `
        -Layout $layout `
        -Profile $midProfile `
        -RegistryPath $registryPath
    $rollbackState = Get-PSOBBClientGraphicCtrlState -RegistryPath $registryPath
    Add-Result 'rollback profile applies its own native graphics contract' (
        $rollbackProfile.Applied -and
        $rollbackProfile.PresetId -ceq 'mid-compatibility' -and
        $rollbackState.Sha256 -ceq
            'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917') `
        'rollback is profile-owned instead of depending on stale global state'

    $invalidProfile = [pscustomobject]@{
        nativeGraphics = New-NativeGraphicsFixture -Preset High
    }
    $invalidProfile.nativeGraphics.graphicCtrlDwords[8] = 1
    $stateBeforeInvalid = Get-PSOBBClientGraphicCtrlState -RegistryPath $registryPath
    $backupCountBeforeInvalid = @(Get-ChildItem -LiteralPath (
        Split-Path -Parent $transaction.BackupPath) -File).Count
    $invalidRejected = $false
    try {
        Set-PSOBBClientNativeGraphics -Layout $layout `
            -Profile $invalidProfile -RegistryPath $registryPath | Out-Null
    } catch {
        $invalidRejected = $_.Exception.Message -match
            'exact vector, digest, or native-detail policy'
    }
    $stateAfterInvalid = Get-PSOBBClientGraphicCtrlState -RegistryPath $registryPath
    $backupCountAfterInvalid = @(Get-ChildItem -LiteralPath (
        Split-Path -Parent $transaction.BackupPath) -File).Count
    Add-Result 'invalid profile fails before backup or registry mutation' (
        $invalidRejected -and
        $stateAfterInvalid.Sha256 -ceq $stateBeforeInvalid.Sha256 -and
        $backupCountAfterInvalid -eq $backupCountBeforeInvalid) `
        'vector and digest disagreement fails closed'

    Set-PSOBBGraphicCtrlRegistryBytes `
        -Bytes (Assert-PSOBBNativeGraphicsContract `
            -NativeGraphics $highProfile.nativeGraphics).GraphicCtrlBytes `
        -RegistryPath $registryPath | Out-Null
    $initializer = & $initializerPath `
        -RuntimeRoot $temporaryRoot `
        -ClientRegistryPath $registryPath `
        -Confirm:$false
    $initializedState = Get-PSOBBClientGraphicCtrlState -RegistryPath $registryPath
    $registry = Get-Item -LiteralPath $registryPath
    Add-Result 'initializer preserves existing saved login while restoring baseline graphics' (
        $initializer.ExistingLoginValuesPreserved -and
        $initializer.BackupContainsCredentials -eq $false -and
        $initializedState.Sha256 -ceq
            'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917' -and
        [string]$registry.GetValue('ACCOUNT') -ceq $accountSentinel -and
        (Test-ByteSequence -Left ([byte[]]$registry.GetValue('PASSWORD')) `
            -Right $passwordSentinel) -and
        [int]$registry.GetValue('ACCOUNT_CHECK') -eq 1) `
        (("preserved={0}; backupCredentials={1}; graphicCtrl={2}; account={3}; " +
            "passwordBytes={4}; accountCheck={5}") -f `
            $initializer.ExistingLoginValuesPreserved,
            $initializer.BackupContainsCredentials,
            $initializedState.Sha256,
            ([string]$registry.GetValue('ACCOUNT') -ceq $accountSentinel),
            (Test-ByteSequence -Left ([byte[]]$registry.GetValue('PASSWORD')) `
                -Right $passwordSentinel),
            [int]$registry.GetValue('ACCOUNT_CHECK'))

    Add-Result 'initializer preserves existing controls sound and window policy' (
        (Test-ByteSequence -Left ([byte[]]$registry.GetValue('CTRLBUF')) `
            -Right $controlSentinel) -and
        (Test-ByteSequence -Left ([byte[]]$registry.GetValue('SOUNDCTRL')) `
            -Right $soundSentinel) -and
        [int]$registry.GetValue('WINDOW_MODE') -eq 0) `
        'rerunning initialization fills missing defaults without replacing user settings'

    $initializerBackupText = Get-Content -Raw `
        -LiteralPath $initializer.GraphicCtrlBackupPath
    Add-Result 'initializer recovery artifact excludes credentials' (
        $initializerBackupText -cnotmatch 'ACCOUNT|PASSWORD|credential' -and
        (Get-Acl -LiteralPath $initializer.GraphicCtrlBackupPath).
            AreAccessRulesProtected) `
        'initializer writes only a protected GRAPHICCTRL JSON record'
} finally {
    if (Test-Path -LiteralPath $registryPath) {
        Remove-Item -LiteralPath $registryPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    $failed | Format-List Name, Detail | Out-Host
    throw "$($failed.Count) client graphics registry test(s) failed"
}
Write-Output "Client graphics registry tests passed: $($results.Count)/$($results.Count)"
