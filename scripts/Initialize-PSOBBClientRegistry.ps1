[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RuntimeRoot,
    [Parameter(DontShow)]
    [ValidatePattern('^(?:HKCU:|Registry::HKEY_CURRENT_USER\\)')]
    [string]$ClientRegistryPath =
        'Registry::HKEY_CURRENT_USER\Software\SonicTeam\PSOBB'
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$registryPath = $ClientRegistryPath
$nativeRegistryPath = if ($registryPath -ceq
    'Registry::HKEY_CURRENT_USER\Software\SonicTeam\PSOBB') {
    'HKEY_CURRENT_USER\Software\SonicTeam\PSOBB'
} else {
    $registryPath
}

if (-not $PSCmdlet.ShouldProcess($nativeRegistryPath, 'Initialize local PSOBB client settings')) {
    return
}

$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {
    Assert-PSOBBNoRunningClients -Layout $layout | Out-Null
    Assert-PSOBBNoNamedClientProcesses | Out-Null
    $existingKey = Test-Path -LiteralPath $registryPath -PathType Container
    $priorGraphicCtrl = $null
    $backupPath = $null
    $hadGraphicCtrl = $false
    $createdValueNames = [System.Collections.Generic.List[string]]::new()
    if ($existingKey) {
        $registry = Get-Item -LiteralPath $registryPath
        $names = @($registry.GetValueNames())
        foreach ($credentialName in @('ACCOUNT', 'PASSWORD')) {
            if ($names -ccontains $credentialName -and
                $registry.GetValueKind($credentialName) -notin @(
                    [Microsoft.Win32.RegistryValueKind]::String,
                    [Microsoft.Win32.RegistryValueKind]::Binary)) {
                throw "PSOBB client login registry value has an unexpected type: $credentialName"
            }
        }
        if ($names -ccontains 'ACCOUNT_CHECK' -and
            $registry.GetValueKind('ACCOUNT_CHECK') -ne
                [Microsoft.Win32.RegistryValueKind]::DWord) {
            throw 'PSOBB client login registry value has an unexpected type: ACCOUNT_CHECK'
        }
        if ($names -ccontains 'GRAPHICCTRL') {
            $hadGraphicCtrl = $true
            $priorGraphicCtrl = Get-PSOBBClientGraphicCtrlState `
                -RegistryPath $registryPath
            $backupPath = New-PSOBBClientGraphicCtrlBackup `
                -Layout $layout `
                -State $priorGraphicCtrl
        }
    }

    if (-not $existingKey) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    $values = [ordered]@{
        CTRLBUF       = [byte[]](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        SOUNDCTRL     = [byte[]](1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0)
        FONT_JPN      = 'Dotum'
        WINDOW_MODE   = [uint32]1
        FOCUS_SOUND   = [uint32]1
        WORD_WRAP     = [uint32]1
        INSTALL       = [uint32]0
        CLIENT_CODE   = [uint32]14
        BILLING_SITE  = ''
        OldCheck      = [uint32]0
        EXT0          = [uint32]2
        OFFICIAL_SITE = ''
        ACCOUNT_CTRL  = [byte[]](0x3d, 0xaa, 0xd0, 0x6e, 0xae, 0x64, 0xcd, 0x48)
    }

    try {
        $registry = Get-Item -LiteralPath $registryPath
        $names = @($registry.GetValueNames())
        foreach ($entry in $values.GetEnumerator()) {
            $propertyType = if ($entry.Value -is [byte[]]) {
                'Binary'
            } elseif ($entry.Value -is [uint32]) {
                'DWord'
            } else {
                'String'
            }
            if ($names -ccontains $entry.Key) {
                $expectedKind = [Microsoft.Win32.RegistryValueKind]::$propertyType
                if ($registry.GetValueKind($entry.Key) -ne $expectedKind) {
                    throw "PSOBB client setting has an unexpected type: $($entry.Key)"
                }
                continue
            }
            New-ItemProperty -LiteralPath $registryPath -Name $entry.Key `
                -Value $entry.Value -PropertyType $propertyType | Out-Null
            $createdValueNames.Add($entry.Key)
        }

        # Create only missing login fields. Existing remembered credentials and
        # ACCOUNT_CHECK policy are never read, exported, cleared, or rewritten.
        $registry = Get-Item -LiteralPath $registryPath
        $names = @($registry.GetValueNames())
        if ($names -cnotcontains 'ACCOUNT') {
            New-ItemProperty -LiteralPath $registryPath -Name 'ACCOUNT' `
                -PropertyType String -Value '' | Out-Null
            $createdValueNames.Add('ACCOUNT')
        }
        if ($names -cnotcontains 'PASSWORD') {
            New-ItemProperty -LiteralPath $registryPath -Name 'PASSWORD' `
                -PropertyType String -Value '' | Out-Null
            $createdValueNames.Add('PASSWORD')
        }
        if ($names -cnotcontains 'ACCOUNT_CHECK') {
            New-ItemProperty -LiteralPath $registryPath -Name 'ACCOUNT_CHECK' `
                -PropertyType DWord -Value 0 | Out-Null
            $createdValueNames.Add('ACCOUNT_CHECK')
        }

        $midGraphicCtrl = ConvertTo-PSOBBGraphicCtrlBytes `
            -Dwords ([object[]]@(1, 0, 0, 0, 1, 1, 1, 0, 0))
        Set-PSOBBGraphicCtrlRegistryBytes `
            -Bytes $midGraphicCtrl `
            -RegistryPath $registryPath | Out-Null
        $loginPolicy = Assert-PSOBBClientLoginRegistry -RegistryPath $registryPath
    } catch {
        $initializationError = $_
        try {
            if (-not $existingKey) {
                Remove-Item -LiteralPath $registryPath -Recurse -Force
            } else {
                foreach ($createdValueName in $createdValueNames) {
                    Remove-ItemProperty -LiteralPath $registryPath `
                        -Name $createdValueName -ErrorAction SilentlyContinue
                }
                if ($priorGraphicCtrl) {
                    Set-PSOBBGraphicCtrlRegistryBytes `
                        -Bytes $priorGraphicCtrl.Bytes `
                        -RegistryPath $registryPath | Out-Null
                } elseif (-not $hadGraphicCtrl) {
                    Remove-ItemProperty -LiteralPath $registryPath `
                        -Name 'GRAPHICCTRL' -ErrorAction SilentlyContinue
                }
            }
        } catch {
            throw ('PSOBB client registry initialization failed and the prior ' +
                "non-credential state could not be restored. Initialization: $($initializationError.Exception.Message) " +
                "Rollback: $($_.Exception.Message)")
        }
        throw $initializationError
    }

    [pscustomobject]@{
        RegistryPath = $nativeRegistryPath
        Windowed = $true
        ExternalWebLinksDisabled = $true
        ExistingLoginValuesPreserved = [bool]$existingKey
        RememberLoginEnabled = [bool]$loginPolicy.RememberLoginEnabled
        GraphicCtrlPresetId = 'mid-compatibility'
        GraphicCtrlSha256 = 'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917'
        GraphicCtrlBackupPath = $backupPath
        BackupContainsCredentials = $false
        BackupProtected = [bool]$backupPath
    }
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
