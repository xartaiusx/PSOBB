[CmdletBinding(SupportsShouldProcess)]
param([string]$RuntimeRoot)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$safeBackups = Assert-PathWithinRoot -Path $layout.Backups -Root $layout.Root
$registryPath = 'Registry::HKEY_CURRENT_USER\Software\SonicTeam\PSOBB'
$nativeRegistryPath = 'HKEY_CURRENT_USER\Software\SonicTeam\PSOBB'

if (-not $PSCmdlet.ShouldProcess($nativeRegistryPath, 'Initialize local PSOBB client settings')) {
    return
}

if (Test-Path -LiteralPath $registryPath) {
    New-Item -ItemType Directory -Force -Path $safeBackups | Out-Null
    $backupPath = Join-Path $safeBackups ('psobb-registry-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.reg')
    Assert-PathWithinRoot -Path $backupPath -Root $layout.Root | Out-Null
    & reg.exe export $nativeRegistryPath $backupPath /y | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not back up the existing PSOBB registry key'
    }
}

New-Item -Path $registryPath -Force | Out-Null
$values = [ordered]@{
    CTRLBUF       = [byte[]](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    GRAPHICCTRL   = [byte[]](1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    SOUNDCTRL     = [byte[]](1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0)
    FONT_JPN      = 'Dotum'
    ACCOUNT_CHECK = [uint32]0
    WINDOW_MODE   = [uint32]1
    FOCUS_SOUND   = [uint32]1
    WORD_WRAP     = [uint32]1
    ACCOUNT       = ''
    PASSWORD      = ''
    INSTALL       = [uint32]0
    CLIENT_CODE   = [uint32]14
    BILLING_SITE  = ''
    OldCheck      = [uint32]0
    EXT0          = [uint32]2
    OFFICIAL_SITE = ''
    ACCOUNT_CTRL  = [byte[]](0x3d, 0xaa, 0xd0, 0x6e, 0xae, 0x64, 0xcd, 0x48)
}

foreach ($entry in $values.GetEnumerator()) {
    $propertyType = if ($entry.Value -is [byte[]]) {
        'Binary'
    } elseif ($entry.Value -is [uint32]) {
        'DWord'
    } else {
        'String'
    }
    New-ItemProperty -LiteralPath $registryPath -Name $entry.Key -Value $entry.Value -PropertyType $propertyType -Force | Out-Null
}

[pscustomobject]@{
    RegistryPath = $nativeRegistryPath
    Windowed = $true
    ExternalWebLinksDisabled = $true
    CredentialsStored = $false
    BackupPath = if (Get-Variable -Name backupPath -ErrorAction SilentlyContinue) { $backupPath } else { $null }
}
