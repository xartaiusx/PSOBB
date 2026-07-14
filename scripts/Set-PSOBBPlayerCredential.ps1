[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,
    [switch]$Relaunch,
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$RelaunchChannel = 'Stable',
    [ValidateSet('ProfileDefault', 'Borderless', 'Resizable')]
    [string]$WindowMode = 'Borderless'
)

$ErrorActionPreference = 'Stop'

# Credential rotation shares the already-tested lifecycle, ACL, protected-file,
# offline-newserv, and manual-login helpers with the administrator workflow.
# Supplying the current parameters prevents the dot-sourced script's parameter
# block from replacing this script's values; its dot-source guard skips its
# operator entry point.
. (Join-Path $PSScriptRoot 'Set-PSOBBAdminCredential.ps1') `
    -RuntimeRoot $RuntimeRoot `
    -Relaunch:$Relaunch

function Test-PSOBBPlayerUsername {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Username)

    $Username -cmatch '\A[a-z][a-z0-9_-]{2,15}\z'
}

function Test-PSOBBPlayerPassword {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Password)

    (Test-PSOBBGamePasswordLength -Password $Password) -and
        ($Password -cmatch '\A[A-Za-z0-9]+\z')
}

function Read-PSOBBPlayerCredential {
    [CmdletBinding()]
    param()

    $username = (Read-Host 'Player username (3-16 lowercase letters, digits, _ or -; start with a letter)').Trim()
    if (-not (Test-PSOBBPlayerUsername -Username $username)) {
        throw 'Player username must match: ^[a-z][a-z0-9_-]{2,15}$'
    }

    Write-Host 'Use a unique password that you do not use anywhere else; 12-16 characters is recommended.' -ForegroundColor Yellow
    while ($true) {
        $password = Read-Host 'New player password (1-16 letters and digits)' -AsSecureString
        $confirmation = $null
        $plainPassword = $null
        $plainConfirmation = $null
        $accepted = $false
        try {
            $plainPassword = ConvertFrom-PSOBBSecureString -SecureString $password
            if (($plainPassword.Length -lt 1) -or ($plainPassword.Length -gt 16)) {
                Write-Warning "Password must contain 1-16 characters; the entry had $($plainPassword.Length). Try again."
                continue
            }
            if (-not (Test-PSOBBPlayerPassword -Password $plainPassword)) {
                Write-Warning 'Password may contain only ASCII letters and digits. Try again.'
                continue
            }

            $confirmation = Read-Host 'Confirm new player password' -AsSecureString
            $plainConfirmation = ConvertFrom-PSOBBSecureString -SecureString $confirmation
            if (-not $plainPassword.Equals($plainConfirmation, [System.StringComparison]::Ordinal)) {
                Write-Warning 'The password confirmation did not match. Enter both values again.'
                continue
            }

            $credential = [pscredential]::new($username, $password)
            $accepted = $true
            return $credential
        } finally {
            $plainPassword = $null
            $plainConfirmation = $null
            if ($confirmation) {
                $confirmation.Dispose()
            }
            if (-not $accepted -and $password) {
                $password.Dispose()
            }
        }
    }
}

function Read-PSOBBCurrentPlayerPassword {
    [CmdletBinding()]
    param()

    while ($true) {
        $securePassword = Read-Host 'Current player password' -AsSecureString
        $plainPassword = $null
        $accepted = $false
        try {
            $plainPassword = ConvertFrom-PSOBBSecureString -SecureString $securePassword
            if (-not (Test-PSOBBPlayerPassword -Password $plainPassword)) {
                Write-Warning 'Current password must contain 1-16 ASCII letters and digits. Try again.'
                continue
            }
            $accepted = $true
            return $securePassword
        } finally {
            $plainPassword = $null
            if ($securePassword -and -not $accepted) {
                $securePassword.Dispose()
            }
        }
    }
}

function Get-PSOBBPlayerState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $credentialPath = Assert-PathWithinRoot -Path (
        Join-Path $Layout.Secrets 'player.credential.clixml') -Root $Layout.Root
    $metadataPath = Assert-PathWithinRoot -Path (
        Join-Path $Layout.Secrets 'player.account.json') -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf) -or
        -not (Test-PSOBBProtectedAcl -Path $metadataPath)) {
        throw 'The protected player account metadata file is missing or has an unsafe ACL'
    }

    $metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
    if (-not ([string]$metadata.role).Equals('Player', [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]$metadata.accountId -notmatch '^[0-9A-Fa-f]{8}$' -or
        -not (Test-PSOBBPlayerUsername -Username ([string]$metadata.username))) {
        throw 'The player account metadata is invalid or does not identify an unprivileged Player account'
    }
    $accountNumber = [Convert]::ToUInt32([string]$metadata.accountId, 16)
    if (($accountNumber -eq 0) -or ($accountNumber -gt 0x7FFFFFFF)) {
        throw 'The player account ID is not a nonzero 31-bit value'
    }
    $accountId = $accountNumber.ToString('X8')

    $licenseDirectory = Assert-PathWithinRoot -Path (
        Join-Path $Layout.Server 'system\licenses') -Root $Layout.Root
    $licensePath = Assert-PathWithinRoot -Path (
        Join-Path $licenseDirectory ($accountNumber.ToString('D10') + '.json')) -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf) -or
        -not (Test-PSOBBProtectedAcl -Path $licensePath)) {
        throw 'The protected player license file is missing or has an unsafe ACL'
    }

    $accountMatches = [System.Collections.Generic.List[string]]::new()
    $usernameMatches = [System.Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $licenseDirectory -Filter '*.json' -File -Force)) {
        Assert-PathWithinRoot -Path $file.FullName -Root $Layout.Root | Out-Null
        $candidate = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json
        if ([uint32]$candidate.AccountID -eq $accountNumber) {
            $accountMatches.Add($file.FullName)
        }
        foreach ($bbLicense in @($candidate.BBLicenses)) {
            if ([string]$bbLicense.UserName -and
                ([string]$bbLicense.UserName).Equals(
                    [string]$metadata.username,
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                $usernameMatches.Add($file.FullName)
            }
        }
    }
    if (($accountMatches.Count -ne 1) -or
        -not $accountMatches[0].Equals($licensePath, [System.StringComparison]::OrdinalIgnoreCase) -or
        ($usernameMatches.Count -ne 1) -or
        -not $usernameMatches[0].Equals($licensePath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The player account ID or username is ambiguous across persisted newserv licenses'
    }

    $license = Get-Content -Raw -LiteralPath $licensePath | ConvertFrom-Json
    $bbLicenses = @($license.BBLicenses)
    if (([uint32]$license.AccountID -ne $accountNumber) -or
        ([uint32]$license.Flags -ne [uint32]0) -or
        ($bbLicenses.Count -ne 1) -or
        -not ([string]$bbLicenses[0].UserName).Equals(
            [string]$metadata.username, [System.StringComparison]::Ordinal) -or
        -not (Test-PSOBBPlayerPassword -Password ([string]$bbLicenses[0].Password))) {
        throw 'The target is not exactly one no-flags account with one matching BB license'
    }

    $credential = $null
    if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
        if (-not (Test-PSOBBProtectedAcl -Path $credentialPath)) {
            throw 'The legacy DPAPI player credential has an unsafe ACL'
        }
        $credential = Import-Clixml -LiteralPath $credentialPath
        $plainCredential = $null
        try {
            $plainCredential = $credential.GetNetworkCredential().Password
            if (-not $credential.UserName.Equals(
                    [string]$metadata.username, [System.StringComparison]::Ordinal) -or
                -not ([string]$bbLicenses[0].Password).Equals(
                    $plainCredential, [System.StringComparison]::Ordinal) -or
                -not (Test-PSOBBPlayerPassword -Password $plainCredential)) {
                throw 'The legacy DPAPI credential, player metadata, and BB license do not agree'
            }
        } finally {
            $plainCredential = $null
        }
    } elseif (-not ([string]$metadata.credentialStorage).Equals(
            'manual-only', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The legacy DPAPI player credential is unexpectedly missing'
    }

    [pscustomobject]@{
        AccountId = $accountId
        AccountNumber = $accountNumber
        Username = [string]$metadata.username
        Credential = $credential
        HadCredential = [bool]$credential
        CredentialPath = $credentialPath
        Metadata = $metadata
        MetadataPath = $metadataPath
        LicensePath = $licensePath
    }
}

function Test-PSOBBPlayerLicensePassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$PlayerState,
        [Parameter(Mandatory)][string]$Password
    )

    $license = Get-Content -Raw -LiteralPath $PlayerState.LicensePath | ConvertFrom-Json
    $bbLicenses = @($license.BBLicenses)
    ($bbLicenses.Count -eq 1) -and
        ([string]$bbLicenses[0].Password).Equals($Password, [System.StringComparison]::Ordinal)
}

function New-PSOBBPlayerCredentialRotationBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$PlayerState,
        [Parameter(Mandatory)][string]$StateBackupPath
    )

    $safeStateBackupPath = Assert-PathWithinRoot -Path $StateBackupPath -Root $Layout.Backups
    if (-not (Test-Path -LiteralPath $safeStateBackupPath -PathType Container)) {
        throw "State backup is missing: $safeStateBackupPath"
    }
    $backupName = 'player-credential-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') +
        '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $backupPath = Assert-PathWithinRoot -Path (
        Join-Path $Layout.Backups $backupName) -Root $Layout.Backups
    New-Item -ItemType Directory -Path $backupPath | Out-Null
    Set-PSOBBProtectedAcl -Path $backupPath

    $files = [ordered]@{
        License = Join-Path $backupPath 'license.json'
        Credential = Join-Path $backupPath 'player.credential.clixml'
        Metadata = Join-Path $backupPath 'player.account.json'
    }
    Copy-PSOBBProtectedFile -Source $PlayerState.LicensePath -Destination $files.License -Root $Layout.Root
    Copy-PSOBBProtectedFile -Source $PlayerState.MetadataPath -Destination $files.Metadata -Root $Layout.Root
    if ($PlayerState.HadCredential) {
        Copy-PSOBBProtectedFile -Source $PlayerState.CredentialPath -Destination $files.Credential -Root $Layout.Root
    }

    $manifestFiles = [System.Collections.Generic.List[object]]::new()
    $manifestFiles.Add([ordered]@{ path = 'license.json'; sha256 = Get-LowerSha256 $files.License })
    $manifestFiles.Add([ordered]@{ path = 'player.account.json'; sha256 = Get-LowerSha256 $files.Metadata })
    if ($PlayerState.HadCredential) {
        $manifestFiles.Add([ordered]@{
            path = 'player.credential.clixml'
            sha256 = Get-LowerSha256 $files.Credential
        })
    }
    $manifestPath = Join-Path $backupPath 'manifest.json'
    $manifest = [ordered]@{
        schemaVersion = 1
        status = 'prepared'
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        role = 'Player'
        accountId = $PlayerState.AccountId
        previousUsername = $PlayerState.Username
        hadLegacyDpapiCredential = [bool]$PlayerState.HadCredential
        stateBackup = [System.IO.Path]::GetRelativePath(
            $Layout.Backups, $safeStateBackupPath).Replace('\', '/')
        files = @($manifestFiles)
    }
    Write-PSOBBProtectedText `
        -Path $manifestPath `
        -Text ($manifest | ConvertTo-Json -Depth 6) `
        -Root $Layout.Root

    [pscustomobject]@{
        Path = $backupPath
        ManifestPath = $manifestPath
        Files = $files
        HadCredential = [bool]$PlayerState.HadCredential
    }
}

function Restore-PSOBBPlayerCredentialRotationBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$PlayerState,
        [Parameter(Mandatory)]$RotationBackup
    )

    if (@(Get-NewservProcessesAtPath -Layout $Layout).Count -gt 0) {
        throw 'Cannot roll back player credential files while newserv is running'
    }
    Copy-PSOBBProtectedFile `
        -Source $RotationBackup.Files.License `
        -Destination $PlayerState.LicensePath `
        -Root $Layout.Root
    Copy-PSOBBProtectedFile `
        -Source $RotationBackup.Files.Metadata `
        -Destination $PlayerState.MetadataPath `
        -Root $Layout.Root
    if ($RotationBackup.HadCredential) {
        Copy-PSOBBProtectedFile `
            -Source $RotationBackup.Files.Credential `
            -Destination $PlayerState.CredentialPath `
            -Root $Layout.Root
    } else {
        Remove-Item -LiteralPath $PlayerState.CredentialPath -Force -ErrorAction SilentlyContinue
    }
    Set-PSOBBRotationBackupStatus `
        -Layout $Layout `
        -RotationBackup $RotationBackup `
        -Status 'rolled-back'
}

function Set-PSOBBPlayerManualSecretState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$PlayerState,
        [Parameter(Mandatory)][string]$Username
    )

    $metadataTemporary = $PlayerState.MetadataPath + '.new-' + [Guid]::NewGuid().ToString('N')
    Assert-PathWithinRoot -Path $metadataTemporary -Root $Layout.Root | Out-Null
    try {
        $metadata = $PlayerState.Metadata
        $metadata.username = $Username
        $metadata | Add-Member -NotePropertyName credentialStorage -NotePropertyValue 'manual-only' -Force
        $metadata | Add-Member -NotePropertyName credentialRotatedAtUtc -NotePropertyValue (
            [DateTime]::UtcNow.ToString('o')) -Force
        [System.IO.File]::WriteAllText(
            $metadataTemporary,
            ($metadata | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $metadataTemporary
        Move-Item -LiteralPath $metadataTemporary -Destination $PlayerState.MetadataPath -Force
        Set-PSOBBProtectedAcl -Path $PlayerState.MetadataPath

        # The new player password intentionally exists only in newserv's
        # required license JSON. Retire the bootstrap DPAPI copy only after the
        # license operation and metadata swap have both succeeded.
        if (Test-Path -LiteralPath $PlayerState.CredentialPath -PathType Leaf) {
            Remove-Item -LiteralPath $PlayerState.CredentialPath -Force -ErrorAction Stop
        }
    } finally {
        Remove-Item -LiteralPath $metadataTemporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-PSOBBRotatedPlayerState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ExpectedAccountId,
        [Parameter(Mandatory)][string]$ExpectedUsername,
        [Parameter(Mandatory)][string]$ExpectedPassword
    )

    $state = Get-PSOBBPlayerState -Layout $Layout
    if (-not $state.AccountId.Equals($ExpectedAccountId, [System.StringComparison]::Ordinal) -or
        -not $state.Username.Equals($ExpectedUsername, [System.StringComparison]::Ordinal) -or
        $state.HadCredential -or
        -not ([string]$state.Metadata.credentialStorage).Equals(
            'manual-only', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-PSOBBPlayerLicensePassword -PlayerState $state -Password $ExpectedPassword) -or
        -not (Test-PSOBBProtectedAcl -Path $state.LicensePath) -or
        -not (Test-PSOBBProtectedAcl -Path $state.MetadataPath)) {
        throw 'Post-rotation unprivileged player account verification failed'
    }
    $state
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
if (-not $PSCmdlet.ShouldProcess(
    $layout.Root,
    'close the local game/server, back up state, rotate exactly one no-flags BB player license, retire the legacy DPAPI copy, and optionally relaunch')) {
    return
}

$initialState = Get-PSOBBPlayerState -Layout $layout
$newCredential = Read-PSOBBPlayerCredential
$promptedCurrentPassword = $null
$oldPassword = $null
$newPassword = $null
$stateBackup = $null
$rotationBackup = $null
$playerState = $null
$verifiedState = $null
try {
    if ($initialState.Credential) {
        $oldPassword = $initialState.Credential.GetNetworkCredential().Password
    } else {
        $promptedCurrentPassword = Read-PSOBBCurrentPlayerPassword
        $oldPassword = ConvertFrom-PSOBBSecureString -SecureString $promptedCurrentPassword
    }
    if (-not (Test-PSOBBPlayerLicensePassword -PlayerState $initialState -Password $oldPassword)) {
        throw 'The current player password is incorrect'
    }
    $newPassword = $newCredential.GetNetworkCredential().Password
    if ($initialState.Username.Equals($newCredential.UserName, [System.StringComparison]::Ordinal) -and
        $oldPassword.Equals($newPassword, [System.StringComparison]::Ordinal)) {
        throw 'The requested player username and password are already active'
    }

    Assert-PSOBBUsernameAvailable `
        -Layout $layout `
        -AdminState $initialState `
        -Username $newCredential.UserName
    Stop-PSOBBForCredentialRotation -Layout $layout

    # Re-read after shutdown so the transaction is based on the exact persisted
    # state that will be backed up and changed.
    $playerState = Get-PSOBBPlayerState -Layout $layout
    if (-not $playerState.AccountId.Equals($initialState.AccountId, [System.StringComparison]::Ordinal) -or
        -not $playerState.Username.Equals($initialState.Username, [System.StringComparison]::Ordinal) -or
        -not (Test-PSOBBPlayerLicensePassword -PlayerState $playerState -Password $oldPassword)) {
        throw 'Player account state changed while the client/server were closing; nothing was modified'
    }
    Assert-PSOBBUsernameAvailable `
        -Layout $layout `
        -AdminState $playerState `
        -Username $newCredential.UserName

    $stateBackup = & (Join-Path $PSScriptRoot 'Backup-PSOBB.ps1') -RuntimeRoot $layout.Root
    $rotationBackup = New-PSOBBPlayerCredentialRotationBackup `
        -Layout $layout `
        -PlayerState $playerState `
        -StateBackupPath $stateBackup.BackupPath
    try {
        Invoke-PSOBBOfflineLicenseRotation `
            -Layout $layout `
            -AccountId $playerState.AccountId `
            -OldUsername $playerState.Username `
            -OldPassword $oldPassword `
            -NewUsername $newCredential.UserName `
            -NewPassword $newPassword
        Set-PSOBBProtectedAcl -Path $playerState.LicensePath
        Set-PSOBBPlayerManualSecretState `
            -Layout $layout `
            -PlayerState $playerState `
            -Username $newCredential.UserName
        $verifiedState = Test-PSOBBRotatedPlayerState `
            -Layout $layout `
            -ExpectedAccountId $playerState.AccountId `
            -ExpectedUsername $newCredential.UserName `
            -ExpectedPassword $newPassword
        Set-PSOBBRotationBackupStatus `
            -Layout $layout `
            -RotationBackup $rotationBackup `
            -Status 'completed'
    } catch {
        $rotationError = $_
        try {
            Restore-PSOBBPlayerCredentialRotationBackup `
                -Layout $layout `
                -PlayerState $playerState `
                -RotationBackup $rotationBackup
        } catch {
            throw "Player credential rotation failed and rollback also failed. Rotation: $($rotationError.Exception.Message) Rollback: $($_.Exception.Message)"
        }
        throw $rotationError
    }

    $session = $null
    if ($Relaunch) {
        Set-PSOBBClientManualLogin
        $session = & (Join-Path $PSScriptRoot 'Start-PSOBBSession.ps1') `
            -RuntimeRoot $layout.Root `
            -Channel $RelaunchChannel `
            -WindowMode $WindowMode
    }

    [pscustomobject]@{
        Rotated = $true
        Role = 'Player'
        AccountId = $verifiedState.AccountId
        Username = $verifiedState.Username
        StateBackup = $stateBackup.BackupPath
        CredentialBackup = $rotationBackup.Path
        PasswordStorage = 'manual-only'
        ServerRelaunched = [bool]$Relaunch
        ClientChannel = if ($session) { $session.ClientChannel } else { $null }
        ClientPid = if ($session) { $session.ClientPid } else { $null }
        LoginCacheCleared = [bool]$Relaunch
        NextStep = if ($Relaunch) {
            'Enter the player username and password manually in the PSOBB login window'
        } else {
            'Remember or independently store the password, then start a session and enter it manually'
        }
    }
} finally {
    $oldPassword = $null
    $newPassword = $null
    if ($promptedCurrentPassword) {
        $promptedCurrentPassword.Dispose()
    }
    if ($newCredential) {
        $newCredential.Password.Dispose()
    }
    if ($verifiedState -and $verifiedState.Credential) {
        $verifiedState.Credential.Password.Dispose()
    }
    if ($playerState -and $playerState.Credential) {
        $playerState.Credential.Password.Dispose()
    }
    if ($initialState -and $initialState.Credential) {
        $initialState.Credential.Password.Dispose()
    }
    $promptedCurrentPassword = $null
    $newCredential = $null
    $verifiedState = $null
    $playerState = $null
    $initialState = $null
}
