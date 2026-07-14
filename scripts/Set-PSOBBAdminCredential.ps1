[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,
    [switch]$Relaunch
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Test-PSOBBAdminUsername {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Username)

    $Username -cmatch '\A[a-z][a-z0-9_-]{2,15}\z'
}

function Test-PSOBBAdminPassword {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Password)

    # The upstream BB protocol allows 1-16 bytes. Keeping the local
    # operator credential alphanumeric also makes it an unambiguous newserv
    # shell token and reliable to enter in the legacy client.
    (Test-PSOBBGamePasswordLength -Password $Password) -and
        ($Password -cmatch '\A[A-Za-z0-9]+\z')
}

function ConvertFrom-PSOBBSecureString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    $pointer = [IntPtr]::Zero
    try {
        $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Read-PSOBBAdminCredential {
    [CmdletBinding()]
    param()

    $username = (Read-Host 'New admin username (3-16 lowercase letters, digits, _ or -; start with a letter)').Trim()
    if (-not (Test-PSOBBAdminUsername -Username $username)) {
        throw 'Admin username must match: ^[a-z][a-z0-9_-]{2,15}$'
    }

    Write-Host 'Use a unique password that you do not use anywhere else; 12-16 characters is recommended.' -ForegroundColor Yellow
    while ($true) {
        $password = Read-Host 'New admin password (1-16 letters and digits)' -AsSecureString
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
            if (-not (Test-PSOBBAdminPassword -Password $plainPassword)) {
                Write-Warning 'Password may contain only ASCII letters and digits. Try again.'
                continue
            }

            $confirmation = Read-Host 'Confirm new admin password' -AsSecureString
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

function Test-PSOBBProtectedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -Force -LiteralPath $Path
    $allowed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$allowed.Add([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    [void]$allowed.Add('S-1-5-32-544')
    [void]$allowed.Add('S-1-5-18')
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        return $false
    }
    $rules = @($acl.GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $allowed.Count) {
        return $false
    }
    $expectedInheritance = if ($item.PSIsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $rules) {
        if (($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) -or
            -not $allowed.Contains($rule.IdentityReference.Value) -or
            $rule.IsInherited -or
            ($rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) -or
            ($rule.InheritanceFlags -ne $expectedInheritance) -or
            ($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None)) {
            return $false
        }
        [void]$found.Add($rule.IdentityReference.Value)
    }
    $found.SetEquals($allowed)
}

function New-PSOBBProtectedSecurityDescriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][bool]$IsContainer)

    $security = if ($IsContainer) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($sid in @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    $security
}

function Set-PSOBBProtectedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -Force -LiteralPath $Path
    # Do not reuse a whole descriptor returned by Get-Acl here. On an audited
    # parent, Set-Acl can attempt to persist its SACL section after applying the
    # DACL, which requires SeSecurityPrivilege. A fresh descriptor contains only
    # the access rules this operation owns. FileSystemAclExtensions then persists
    # only its modified DACL section and leaves owner, group, and SACL untouched.
    $security = New-PSOBBProtectedSecurityDescriptor -IsContainer $item.PSIsContainer
    if ($item.PSIsContainer) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo]$item, [System.Security.AccessControl.DirectorySecurity]$security)
    } else {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo]$item, [System.Security.AccessControl.FileSecurity]$security)
    }
}

function Write-PSOBBProtectedText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Root
    )

    Assert-PathWithinRoot -Path $Path -Root $Root | Out-Null
    $temporary = $Path + '.new-' + [Guid]::NewGuid().ToString('N')
    Assert-PathWithinRoot -Path $temporary -Root $Root | Out-Null
    try {
        [System.IO.File]::WriteAllText($temporary, $Text, [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $Path -Force
        Set-PSOBBProtectedAcl -Path $Path
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Copy-PSOBBProtectedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Root
    )

    Assert-PathWithinRoot -Path $Source -Root $Root | Out-Null
    Assert-PathWithinRoot -Path $Destination -Root $Root | Out-Null
    $temporary = $Destination + '.new-' + [Guid]::NewGuid().ToString('N')
    Assert-PathWithinRoot -Path $temporary -Root $Root | Out-Null
    try {
        Copy-Item -LiteralPath $Source -Destination $temporary
        Set-PSOBBProtectedAcl -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
        Set-PSOBBProtectedAcl -Path $Destination
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-PSOBBAdminState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $credentialPath = Assert-PathWithinRoot -Path (Join-Path $Layout.Secrets 'admin.credential.clixml') -Root $Layout.Root
    $metadataPath = Assert-PathWithinRoot -Path (Join-Path $Layout.Secrets 'admin.account.json') -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw 'The provisioned admin credential or metadata file is missing'
    }
    if (-not (Test-PSOBBProtectedAcl -Path $credentialPath) -or
        -not (Test-PSOBBProtectedAcl -Path $metadataPath)) {
        throw 'The provisioned admin credential files do not have the required protected ACL'
    }

    $metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
    if (-not ([string]$metadata.role).Equals('Admin', [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]$metadata.accountId -notmatch '^[0-9A-Fa-f]{8}$') {
        throw 'The admin account metadata is invalid'
    }
    $accountNumber = [Convert]::ToUInt32([string]$metadata.accountId, 16)
    if (($accountNumber -eq 0) -or ($accountNumber -gt 0x7FFFFFFF)) {
        throw 'The admin account ID is not a nonzero 31-bit value'
    }
    $accountId = $accountNumber.ToString('X8')
    $licensePath = Assert-PathWithinRoot -Path (
        Join-Path $Layout.Server ('system\licenses\' + $accountNumber.ToString('D10') + '.json')) -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf) -or
        -not (Test-PSOBBProtectedAcl -Path $licensePath)) {
        throw 'The protected admin license file is missing'
    }

    $licenseText = Get-Content -Raw -LiteralPath $licensePath
    $license = $licenseText | ConvertFrom-Json
    $bbLicenses = @($license.BBLicenses)
    $credential = Import-Clixml -LiteralPath $credentialPath
    $plainCredential = $null
    try {
        $plainCredential = $credential.GetNetworkCredential().Password
        if (([uint32]$license.AccountID -ne $accountNumber) -or
            ([uint32]$license.Flags -ne [uint32]0x7FFFFFFF) -or
            ($bbLicenses.Count -ne 1) -or
            -not ([string]$bbLicenses[0].UserName).Equals([string]$metadata.username, [System.StringComparison]::Ordinal) -or
            -not $credential.UserName.Equals([string]$metadata.username, [System.StringComparison]::Ordinal) -or
            -not ([string]$bbLicenses[0].Password).Equals($plainCredential, [System.StringComparison]::Ordinal) -or
            -not (Test-PSOBBAdminUsername -Username ([string]$metadata.username)) -or
            -not (Test-PSOBBAdminPassword -Password $plainCredential)) {
            throw 'The admin metadata, DPAPI credential, root flags, or BB license do not agree'
        }
    } finally {
        $plainCredential = $null
    }

    [pscustomobject]@{
        AccountId = $accountId
        AccountNumber = $accountNumber
        Username = [string]$metadata.username
        Credential = $credential
        CredentialPath = $credentialPath
        Metadata = $metadata
        MetadataPath = $metadataPath
        LicensePath = $licensePath
    }
}

function Get-PSOBBUsernameBoundFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PlayersDirectory,
        [Parameter(Mandatory)][string]$Username
    )

    if (-not (Test-Path -LiteralPath $PlayersDirectory -PathType Container)) {
        throw "Player-data directory is missing: $PlayersDirectory"
    }
    $escaped = [regex]::Escape($Username)
    $pattern = '^(system_' + $escaped + '\.psosys|guild_cards_' + $escaped +
        '\.psocard|account_' + $escaped + '\.nsa|shared_bank_' + $escaped +
        '\.psobank|player_' + $escaped + '_[0-9]+\.(psochar|psobank|nsc))$'
    @(Get-ChildItem -LiteralPath $PlayersDirectory -File -Force | Where-Object {
        $_.Name -match $pattern
    })
}

function Assert-PSOBBUsernameAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$AdminState,
        [Parameter(Mandatory)][string]$Username
    )

    $licenseDirectory = Assert-PathWithinRoot -Path (Join-Path $Layout.Server 'system\licenses') -Root $Layout.Root
    foreach ($file in @(Get-ChildItem -LiteralPath $licenseDirectory -Filter '*.json' -File -Force)) {
        if ($file.FullName.Equals($AdminState.LicensePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $account = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json
        foreach ($bbLicense in @($account.BBLicenses)) {
            if ([string]$bbLicense.UserName -and
                ([string]$bbLicense.UserName).Equals($Username, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Another BB account already uses username $Username"
            }
        }
    }

    if (-not $AdminState.Username.Equals($Username, [System.StringComparison]::Ordinal)) {
        $playersDirectory = Join-Path $Layout.Server 'system\players'
        $boundFiles = @(Get-PSOBBUsernameBoundFiles -PlayersDirectory $playersDirectory -Username $AdminState.Username)
        if ($boundFiles.Count -gt 0) {
            throw 'This admin username already owns saved player data. Rename is blocked until a separately tested data migration exists; rotate only the password or use a fresh account.'
        }
        $collidingFiles = @(Get-PSOBBUsernameBoundFiles -PlayersDirectory $playersDirectory -Username $Username)
        if ($collidingFiles.Count -gt 0) {
            throw 'The requested username already has username-bound player data. Refusing to attach another account to those files.'
        }
    }
}

function Get-PSOBBExactPathProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedPath
    )

    @(Get-PSOBBProcessesAtExactPath -Name $Name -ExpectedPath $ExpectedPath)
}

function Close-PSOBBWindowProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Processes,
        [Parameter(Mandatory)][string]$Description,
        [string]$ProcessName,
        [string]$ExpectedPath,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 20
    )

    if ([string]::IsNullOrWhiteSpace($ProcessName) -ne
        [string]::IsNullOrWhiteSpace($ExpectedPath)) {
        throw 'ProcessName and ExpectedPath must be provided together'
    }

    foreach ($process in $Processes) {
        $candidateId = [string]$process.Id
        $closeRequested = $false
        try {
            $process.Refresh()
            if ($process.HasExited) {
                continue
            }
            if ($ExpectedPath -and -not (Test-PSOBBProcessAtExactPath `
                -Process $process `
                -Name $ProcessName `
                -ExpectedPath $ExpectedPath)) {
                throw 'The process identity changed after enumeration'
            }
            $closeRequested = $process.CloseMainWindow()
        } catch {
            $closeFailure = $_.Exception.Message
            $exitedAfterFailure = $false
            try {
                $process.Refresh()
                $exitedAfterFailure = $process.HasExited
            } catch {
                # Fail closed when Windows cannot confirm that the process exited.
            }
            if ($exitedAfterFailure) {
                continue
            }
            throw "Could not request a normal close for $Description PID $candidateId. $closeFailure"
        }
        if (-not $closeRequested) {
            $process.Refresh()
            if ($process.HasExited) {
                continue
            }
            throw "Could not request a normal close for $Description PID $candidateId. Close it manually and rerun this command."
        }
    }
    foreach ($process in $Processes) {
        $candidateId = [string]$process.Id
        try {
            $process.Refresh()
            if ($process.HasExited) {
                continue
            }
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                throw "$Description PID $candidateId did not close normally. No forceful termination was attempted."
            }
        } catch {
            $waitFailure = $_.Exception.Message
            $exitedAfterFailure = $false
            try {
                $process.Refresh()
                $exitedAfterFailure = $process.HasExited
            } catch {
                # Fail closed when Windows cannot confirm that the process exited.
            }
            if (-not $exitedAfterFailure) {
                throw "$Description PID $candidateId could not be confirmed closed. $waitFailure"
            }
        }
    }
}

function Stop-PSOBBForCredentialRotation {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $launcherPath = Assert-PathWithinRoot -Path (Join-Path $Layout.Stable 'launcher\PSOBB.Launcher.exe') -Root $Layout.Root
    & (Join-Path $PSScriptRoot 'Stop-PSOBBClient.ps1') `
        -RuntimeRoot $Layout.Root `
        -Channel All | Out-Host
    Assert-PSOBBNoRunningClients -Layout $Layout | Out-Null

    $launchers = @(Get-PSOBBExactPathProcesses -Name 'PSOBB.Launcher' -ExpectedPath $launcherPath)
    if ($launchers.Count -gt 0) {
        Close-PSOBBWindowProcesses `
            -Processes $launchers `
            -Description 'PSOBB launcher' `
            -ProcessName 'PSOBB.Launcher' `
            -ExpectedPath $launcherPath `
            -TimeoutSeconds 30
        if (@(Get-PSOBBExactPathProcesses -Name 'PSOBB.Launcher' -ExpectedPath $launcherPath).Count -gt 0) {
            throw 'The stopped PSOBB launcher is still running. No credential was changed.'
        }
    }

    if (@(Get-NewservProcessesAtPath -Layout $Layout).Count -gt 0) {
        & (Join-Path $PSScriptRoot 'Stop-PSOBB.ps1') -RuntimeRoot $Layout.Root | Out-Host
    }
    if (@(Get-NewservProcessesAtPath -Layout $Layout).Count -gt 0) {
        throw 'An exact-path newserv process is still running; refusing offline credential rotation'
    }
}

function New-PSOBBCredentialRotationBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$AdminState,
        [Parameter(Mandatory)][string]$StateBackupPath
    )

    $safeStateBackupPath = Assert-PathWithinRoot -Path $StateBackupPath -Root $Layout.Backups
    if (-not (Test-Path -LiteralPath $safeStateBackupPath -PathType Container)) {
        throw "State backup is missing: $safeStateBackupPath"
    }
    $backupPath = Assert-PathWithinRoot -Path (Join-Path $Layout.Backups (
        'admin-credential-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) -Root $Layout.Backups
    New-Item -ItemType Directory -Path $backupPath | Out-Null
    Set-PSOBBProtectedAcl -Path $backupPath
    $files = [ordered]@{
        License = Join-Path $backupPath 'license.json'
        Credential = Join-Path $backupPath 'admin.credential.clixml'
        Metadata = Join-Path $backupPath 'admin.account.json'
    }
    Copy-PSOBBProtectedFile -Source $AdminState.LicensePath -Destination $files.License -Root $Layout.Root
    Copy-PSOBBProtectedFile -Source $AdminState.CredentialPath -Destination $files.Credential -Root $Layout.Root
    Copy-PSOBBProtectedFile -Source $AdminState.MetadataPath -Destination $files.Metadata -Root $Layout.Root

    $manifestPath = Join-Path $backupPath 'manifest.json'
    $manifest = [ordered]@{
        schemaVersion = 1
        status = 'prepared'
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        accountId = $AdminState.AccountId
        previousUsername = $AdminState.Username
        stateBackup = [System.IO.Path]::GetRelativePath($Layout.Backups, $safeStateBackupPath).Replace('\', '/')
        files = @(
            [ordered]@{ path = 'license.json'; sha256 = Get-LowerSha256 $files.License }
            [ordered]@{ path = 'admin.credential.clixml'; sha256 = Get-LowerSha256 $files.Credential }
            [ordered]@{ path = 'admin.account.json'; sha256 = Get-LowerSha256 $files.Metadata }
        )
    }
    Write-PSOBBProtectedText -Path $manifestPath -Text ($manifest | ConvertTo-Json -Depth 6) -Root $Layout.Root
    [pscustomobject]@{
        Path = $backupPath
        ManifestPath = $manifestPath
        Files = $files
    }
}

function Set-PSOBBRotationBackupStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$RotationBackup,
        [Parameter(Mandatory)][ValidateSet('completed', 'rolled-back')][string]$Status
    )

    $manifest = Get-Content -Raw -LiteralPath $RotationBackup.ManifestPath | ConvertFrom-Json
    $manifest.status = $Status
    $manifest | Add-Member -NotePropertyName completedAtUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-PSOBBProtectedText -Path $RotationBackup.ManifestPath -Text (
        $manifest | ConvertTo-Json -Depth 6) -Root $Layout.Root
}

function Restore-PSOBBCredentialRotationBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$AdminState,
        [Parameter(Mandatory)]$RotationBackup
    )

    if (@(Get-NewservProcessesAtPath -Layout $Layout).Count -gt 0) {
        throw 'Cannot roll back credential files while newserv is running'
    }
    Copy-PSOBBProtectedFile -Source $RotationBackup.Files.License -Destination $AdminState.LicensePath -Root $Layout.Root
    Copy-PSOBBProtectedFile -Source $RotationBackup.Files.Credential -Destination $AdminState.CredentialPath -Root $Layout.Root
    Copy-PSOBBProtectedFile -Source $RotationBackup.Files.Metadata -Destination $AdminState.MetadataPath -Root $Layout.Root
    Set-PSOBBRotationBackupStatus -Layout $Layout -RotationBackup $RotationBackup -Status 'rolled-back'
}

function Invoke-PSOBBOfflineLicenseRotation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$AccountId,
        [Parameter(Mandatory)][string]$OldUsername,
        [Parameter(Mandatory)][string]$OldPassword,
        [Parameter(Mandatory)][string]$NewUsername,
        [Parameter(Mandatory)][string]$NewPassword,
        [string[]]$ExpectedListeners = @(
            '127.0.0.1:11000',
            '127.0.0.1:12000',
            '127.0.0.1:12001'
        )
    )

    if (@(Get-NewservProcessesAtPath -Layout $Layout).Count -gt 0) {
        throw 'newserv must be stopped before offline license rotation'
    }
    $expectedListeners = @($ExpectedListeners | Sort-Object -Unique)
    if ($expectedListeners.Count -ne 3 -or @($expectedListeners | Where-Object {
        $_ -notmatch '^127\.0\.0\.1:[1-9][0-9]{0,4}$' -or
        [int]($_ -split ':')[-1] -gt 65535
    }).Count -gt 0) {
        throw 'Credential rotation requires exactly three unique loopback TCP listeners'
    }
    $executable = Assert-PathWithinRoot -Path (Join-Path $Layout.Server 'newserv-windows.exe') -Root $Layout.Root
    $process = $null
    $stdoutTask = $null
    $stderrTask = $null
    $commands = $null
    $rawOutput = $null
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $executable
        $startInfo.WorkingDirectory = $Layout.Server
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'newserv did not start for offline license rotation'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $ready = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) {
                break
            }
            $listeners = @(Get-NetTCPConnection -OwningProcess $process.Id -State Listen -ErrorAction SilentlyContinue)
            $actual = @($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" } | Sort-Object -Unique)
            if (@($listeners | Where-Object LocalAddress -ne '127.0.0.1').Count -gt 0) {
                throw 'Offline newserv opened a non-loopback listener; refusing credential rotation'
            }
            if ($actual.Count -eq $expectedListeners.Count -and
                -not (Compare-Object -ReferenceObject $expectedListeners -DifferenceObject $actual)) {
                $ready = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
        if (-not $ready) {
            throw 'Offline newserv did not reach the exact loopback listener set'
        }

        $commands = @(
            "delete-license $AccountId BB $OldUsername",
            "add-license $AccountId BB $NewUsername $NewPassword",
            'exit'
        )
        foreach ($command in $commands) {
            $process.StandardInput.WriteLine($command)
        }
        $process.StandardInput.Flush()
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) {
            throw 'Offline newserv did not exit after license rotation'
        }

        $rawOutput = $stdoutTask.GetAwaiter().GetResult() + [Environment]::NewLine + $stderrTask.GetAwaiter().GetResult()
        $confirmation = "Account $AccountId updated"
        $reportedFailure = $rawOutput -match '(?mi)^FAILED:|\bERROR\b|\bException\b'
        $confirmationCount = [regex]::Matches($rawOutput, [regex]::Escape($confirmation)).Count
        if (($process.ExitCode -ne 0) -or
            $reportedFailure -or
            ($confirmationCount -lt 2)) {
            $failureLines = @($rawOutput -split "\r?\n" | Where-Object {
                $_ -match 'FAILED:|ERROR|Exception'
            } | Select-Object -First 8)
            $shortSecret = @(@($OldPassword, $NewPassword) | Where-Object {
                -not [string]::IsNullOrEmpty($_) -and $_.Length -lt 4
            }).Count -gt 0
            if ($failureLines.Count -eq 0) {
                $detail = 'newserv did not confirm both license operations'
            } elseif ($shortSecret) {
                $detail = 'newserv reported a credential operation error; details were withheld to protect a short password'
            } else {
                $safeFailureLines = foreach ($line in $failureLines) {
                    foreach ($secret in @($OldPassword, $NewPassword)) {
                        if (-not [string]::IsNullOrEmpty($secret)) {
                            $line = $line.Replace($secret, '[REDACTED]')
                        }
                    }
                    $line
                }
                $detail = $safeFailureLines -join '; '
            }
            throw "newserv rejected credential rotation: $detail"
        }
    } finally {
        $commands = $null
        $rawOutput = $null
        if ($process -and -not $process.HasExited) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        if ($process) {
            $process.Dispose()
        }
    }
}

function Set-PSOBBAdminSecretState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$AdminState,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    $credentialTemporary = $AdminState.CredentialPath + '.new-' + [Guid]::NewGuid().ToString('N')
    $metadataTemporary = $AdminState.MetadataPath + '.new-' + [Guid]::NewGuid().ToString('N')
    Assert-PathWithinRoot -Path $credentialTemporary -Root $Layout.Root | Out-Null
    Assert-PathWithinRoot -Path $metadataTemporary -Root $Layout.Root | Out-Null
    $plain = $null
    $roundTripPlain = $null
    try {
        $Credential | Export-Clixml -LiteralPath $credentialTemporary
        Set-PSOBBProtectedAcl -Path $credentialTemporary
        $roundTrip = Import-Clixml -LiteralPath $credentialTemporary
        $plain = $Credential.GetNetworkCredential().Password
        $roundTripPlain = $roundTrip.GetNetworkCredential().Password
        if (-not $roundTrip.UserName.Equals($Credential.UserName, [System.StringComparison]::Ordinal) -or
            -not $roundTripPlain.Equals($plain, [System.StringComparison]::Ordinal)) {
            throw 'DPAPI credential round-trip verification failed'
        }

        $metadata = $AdminState.Metadata
        $metadata.username = $Credential.UserName
        $metadata | Add-Member -NotePropertyName credentialRotatedAtUtc -NotePropertyValue (
            [DateTime]::UtcNow.ToString('o')) -Force
        [System.IO.File]::WriteAllText(
            $metadataTemporary,
            ($metadata | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $metadataTemporary

        Move-Item -LiteralPath $credentialTemporary -Destination $AdminState.CredentialPath -Force
        Set-PSOBBProtectedAcl -Path $AdminState.CredentialPath
        Move-Item -LiteralPath $metadataTemporary -Destination $AdminState.MetadataPath -Force
        Set-PSOBBProtectedAcl -Path $AdminState.MetadataPath
    } finally {
        $plain = $null
        $roundTripPlain = $null
        Remove-Item -LiteralPath $credentialTemporary -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $metadataTemporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-PSOBBRotatedAdminState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ExpectedUsername,
        [Parameter(Mandatory)][string]$ExpectedPassword
    )

    $state = Get-PSOBBAdminState -Layout $Layout
    $licenseText = Get-Content -Raw -LiteralPath $state.LicensePath
    $canonicalLicenses = [regex]::Matches(
        $licenseText,
        '\{"UserName"\s*:\s*"(?<username>[^"]+)",\s*"Password"\s*:\s*"(?<password>[^"]+)"\}')
    $savedId = [regex]::Match($licenseText, '(?m)^\s*"AccountID"\s*:\s*0x([0-9A-Fa-f]+),').Groups[1].Value
    $flags = [regex]::Match($licenseText, '(?m)^\s*"Flags"\s*:\s*([^,]+),').Groups[1].Value.Trim()
    $persistedPassword = $null
    try {
        $persistedPassword = $state.Credential.GetNetworkCredential().Password
        if (-not $state.Username.Equals($ExpectedUsername, [System.StringComparison]::Ordinal) -or
            -not $persistedPassword.Equals($ExpectedPassword, [System.StringComparison]::Ordinal) -or
            ($canonicalLicenses.Count -ne 1) -or
            -not $canonicalLicenses[0].Groups['username'].Value.Equals($ExpectedUsername, [System.StringComparison]::Ordinal) -or
            -not $canonicalLicenses[0].Groups['password'].Value.Equals($ExpectedPassword, [System.StringComparison]::Ordinal) -or
            ($savedId.ToUpperInvariant() -ne $state.AccountId) -or
            ($flags -ne '0x7FFFFFFF') -or
            -not (Test-PSOBBProtectedAcl -Path $state.LicensePath)) {
            throw 'Post-rotation admin account verification failed'
        }
    } finally {
        $persistedPassword = $null
    }
    $state
}

function Set-PSOBBClientManualLogin {
    [CmdletBinding()]
    param([string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB')

    if (-not (Test-Path -LiteralPath $RegistryPath -PathType Container)) {
        throw "PSOBB client registry key is missing: $RegistryPath"
    }
    Remove-ItemProperty -LiteralPath $RegistryPath -Name 'ACCOUNT_CHECK', 'ACCOUNT', 'PASSWORD' -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $RegistryPath -Name 'ACCOUNT_CHECK' -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -LiteralPath $RegistryPath -Name 'ACCOUNT' -PropertyType String -Value '' -Force | Out-Null
    New-ItemProperty -LiteralPath $RegistryPath -Name 'PASSWORD' -PropertyType String -Value '' -Force | Out-Null
}

function New-PSOBBClientStartInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientExecutable,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ClientExecutable
    $startInfo.WorkingDirectory = $WorkingDirectory
    # ShellExecute keeps the GUI process detached from non-interactive capture
    # handles. The compatibility layer is applied briefly by the launch helper
    # and restored immediately after process creation.
    $startInfo.UseShellExecute = $true
    $startInfo.CreateNoWindow = $false

    # The historic 59NL executable embeds requireAdministrator even though the
    # disposable runtime is user-writable. Apply Microsoft's RunAsInvoker
    # compatibility fix only to this child process so a normal operator shell
    # can verify and close it without weakening UAC or changing the base client.
    $startInfo
}

function Start-PSOBBClientProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientExecutable,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )

    $startInfo = New-PSOBBClientStartInfo `
        -ClientExecutable $ClientExecutable `
        -WorkingDirectory $WorkingDirectory
    $previousCompatibilityLayer =
        [Environment]::GetEnvironmentVariable('__COMPAT_LAYER', 'Process')
    try {
        # The historic 59NL executable embeds requireAdministrator even though
        # the verified disposable runtime is user-writable. Apply Microsoft's
        # RunAsInvoker compatibility layer only during this child creation.
        [Environment]::SetEnvironmentVariable(
            '__COMPAT_LAYER', 'RunAsInvoker', 'Process')
        $process = [System.Diagnostics.Process]::Start($startInfo)
    } finally {
        [Environment]::SetEnvironmentVariable(
            '__COMPAT_LAYER', $previousCompatibilityLayer, 'Process')
    }
    if (-not $process) {
        throw 'Windows did not start the PSOBB client process'
    }
    $process
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
if (-not $PSCmdlet.ShouldProcess(
    $layout.Root,
    'close the local game/server, back up state, rotate the existing root BB license, and optionally relaunch')) {
    return
}

$initialState = Get-PSOBBAdminState -Layout $layout
$newCredential = Read-PSOBBAdminCredential
$newPassword = $null
$oldPassword = $null
$rotationBackup = $null
$stateBackup = $null
$adminState = $null
$verifiedState = $null
$shutdownPassword = $null
try {
    $newPassword = $newCredential.GetNetworkCredential().Password
    $oldPassword = $initialState.Credential.GetNetworkCredential().Password
    if ($initialState.Username.Equals($newCredential.UserName, [System.StringComparison]::Ordinal) -and
        $oldPassword.Equals($newPassword, [System.StringComparison]::Ordinal)) {
        throw 'The requested admin username and password are already active'
    }

    Assert-PSOBBUsernameAvailable -Layout $layout -AdminState $initialState -Username $newCredential.UserName
    Stop-PSOBBForCredentialRotation -Layout $layout

    # Re-read after shutdown so the transaction is based on the exact persisted
    # state that is about to be backed up and changed.
    $adminState = Get-PSOBBAdminState -Layout $layout
    $shutdownPassword = $adminState.Credential.GetNetworkCredential().Password
    if (-not $adminState.AccountId.Equals($initialState.AccountId, [System.StringComparison]::Ordinal) -or
        -not $adminState.Username.Equals($initialState.Username, [System.StringComparison]::Ordinal) -or
        -not $shutdownPassword.Equals($oldPassword, [System.StringComparison]::Ordinal)) {
        throw 'Admin account state changed while the client/server were closing; nothing was modified'
    }
    $shutdownPassword = $null
    Assert-PSOBBUsernameAvailable -Layout $layout -AdminState $adminState -Username $newCredential.UserName

    $stateBackup = & (Join-Path $PSScriptRoot 'Backup-PSOBB.ps1') -RuntimeRoot $layout.Root
    $rotationBackup = New-PSOBBCredentialRotationBackup -Layout $layout -AdminState $adminState -StateBackupPath $stateBackup.BackupPath
    try {
        Invoke-PSOBBOfflineLicenseRotation -Layout $layout -AccountId $adminState.AccountId -OldUsername $adminState.Username -OldPassword $oldPassword -NewUsername $newCredential.UserName -NewPassword $newPassword
        Set-PSOBBProtectedAcl -Path $adminState.LicensePath
        Set-PSOBBAdminSecretState -Layout $layout -AdminState $adminState -Credential $newCredential
        $verifiedState = Test-PSOBBRotatedAdminState -Layout $layout -ExpectedUsername $newCredential.UserName -ExpectedPassword $newPassword
        Set-PSOBBRotationBackupStatus -Layout $layout -RotationBackup $rotationBackup -Status 'completed'
    } catch {
        $rotationError = $_
        try {
            Restore-PSOBBCredentialRotationBackup -Layout $layout -AdminState $adminState -RotationBackup $rotationBackup
        } catch {
            throw "Admin credential rotation failed and rollback also failed. Rotation: $($rotationError.Exception.Message) Rollback: $($_.Exception.Message)"
        }
        throw $rotationError
    }

    $clientProcess = $null
    if ($Relaunch) {
        Set-PSOBBClientManualLogin
        $serverStarted = $false
        try {
            & (Join-Path $PSScriptRoot 'Start-PSOBB.ps1') -RuntimeRoot $layout.Root | Out-Host
            $serverStarted = $true
            & (Join-Path $PSScriptRoot 'Test-PSOBB.ps1') -Suite Baseline -RuntimeRoot $layout.Root | Out-Host
            $clientExecutable = Assert-PathWithinRoot -Path (Join-Path $layout.Client 'Psobb.exe') -Root $layout.Root
            $clientProcess = Start-PSOBBClientProcess `
                -ClientExecutable $clientExecutable `
                -WorkingDirectory $layout.Client
        } catch {
            if ($serverStarted) {
                try {
                    & (Join-Path $PSScriptRoot 'Stop-PSOBB.ps1') -RuntimeRoot $layout.Root | Out-Host
                } catch {
                    Write-Warning 'The post-rotation acceptance check failed and the newly started server also failed to stop cleanly.'
                }
            }
            throw
        }
    }

    [pscustomobject]@{
        Rotated = $true
        AccountId = $verifiedState.AccountId
        Username = $verifiedState.Username
        StateBackup = $stateBackup.BackupPath
        CredentialBackup = $rotationBackup.Path
        ServerRelaunched = [bool]$Relaunch
        ClientPid = if ($clientProcess) { $clientProcess.Id } else { $null }
        LoginCacheCleared = [bool]$Relaunch
        NextStep = if ($Relaunch) {
            'Enter the new username and password manually in the PSOBB login window'
        } else {
            'Run with -Relaunch when ready to start the server and client with an empty login form'
        }
    }
} finally {
    $newPassword = $null
    $oldPassword = $null
    $shutdownPassword = $null
    if ($newCredential) {
        $newCredential.Password.Dispose()
    }
    if ($verifiedState) {
        $verifiedState.Credential.Password.Dispose()
    }
    if ($adminState) {
        $adminState.Credential.Password.Dispose()
    }
    if ($initialState) {
        $initialState.Credential.Password.Dispose()
    }
    $newCredential = $null
    $verifiedState = $null
    $adminState = $null
    $initialState = $null
}
