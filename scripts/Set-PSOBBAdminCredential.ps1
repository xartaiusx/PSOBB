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

function Initialize-PSOBBClientProcessLauncherType {
    [CmdletBinding()]
    param()

    if ($null -ne ('PSOBBClientProcessLauncher' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public sealed class PSOBBPathLease : IDisposable
{
    internal IntPtr Handle { get; private set; }
    public string FullPath { get; private set; }
    public bool IsDirectory { get; private set; }
    public uint VolumeSerialNumber { get; private set; }
    public ulong FileId { get; private set; }
    public long Length { get; private set; }

    internal PSOBBPathLease(
        IntPtr handle,
        string fullPath,
        bool isDirectory,
        uint volumeSerialNumber,
        ulong fileId,
        long length)
    {
        Handle = handle;
        FullPath = fullPath;
        IsDirectory = isDirectory;
        VolumeSerialNumber = volumeSerialNumber;
        FileId = fileId;
        Length = length;
    }

    public byte[] ReadPrefix(int byteCount)
    {
        return PSOBBClientProcessLauncher.ReadPrefix(this, byteCount);
    }

    public string ComputeSha256()
    {
        return PSOBBClientProcessLauncher.ComputeSha256(this);
    }

    public void Dispose()
    {
        IntPtr handle = Handle;
        Handle = IntPtr.Zero;
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            PSOBBClientProcessLauncher.CloseNativeHandle(handle);
        }
    }

    internal IntPtr DangerousHandle
    {
        get
        {
            if (Handle == IntPtr.Zero || Handle == new IntPtr(-1))
            {
                throw new ObjectDisposedException("PSOBBPathLease");
            }
            return Handle;
        }
    }
}

public static class PSOBBClientProcessLauncher
{
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public uint Size;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        IntPtr file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr file,
        StringBuilder path,
        uint pathLength,
        uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(
        string path,
        IntPtr securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        IntPtr file,
        int informationClass,
        ref FileDispositionInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(
        IntPtr file,
        long distance,
        out long newPosition,
        uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        IntPtr file,
        byte[] buffer,
        uint bytesToRead,
        out uint bytesRead,
        IntPtr overlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenEventW(
        uint desiredAccess,
        bool inheritHandle,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        IntPtr handle,
        uint milliseconds);

    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint StartfUseShowWindow = 0x00000001;
    private const ushort SwShowNormal = 1;
    private const ushort SwShowNoActivate = 4;
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint EventModifyState = 0x00000002;
    private const uint Synchronize = 0x00100000;
    private const uint OpenExisting = 3;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileNameNormalized = 0x0;
    private const uint VolumeNameDos = 0x0;
    private const int FileDispositionInfo = 4;
    private const uint FileBegin = 0;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const string ObservationRunIdName =
        "PSOBB_GAMEPLAY_OBSERVATION_RUN_ID";

    private static string NormalizeLocalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("A native path is missing or invalid.");
        }
        string fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new ArgumentException("PSOBB native paths must be on a local Windows volume.");
        }
        return fullPath.Length > 3 ? fullPath.TrimEnd('\\') : fullPath;
    }

    private static string ExtendedPath(string path)
    {
        return path.StartsWith("\\\\?\\", StringComparison.Ordinal)
            ? path
            : "\\\\?\\" + path;
    }

    private static PSOBBPathLease OpenExactPath(
        string path,
        bool directory,
        long expectedLength,
        bool allowSharedWrite)
    {
        string fullPath = NormalizeLocalPath(path);
        uint access = directory ? FileReadAttributes | DeleteAccess : GenericRead;
        uint flags = FileFlagOpenReparsePoint |
            (directory ? FileFlagBackupSemantics : FileFlagSequentialScan);
        IntPtr handle = CreateFileW(
            fullPath,
            access,
            FileShareRead | (allowSharedWrite ? FileShareWrite : 0),
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (handle == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            bool actualDirectory =
                (information.FileAttributes & FileAttributeDirectory) != 0;
            if (actualDirectory != directory ||
                (information.FileAttributes & FileAttributeReparsePoint) != 0 ||
                (!directory && information.NumberOfLinks != 1))
            {
                throw new IOException("The native path identity is not exact.");
            }

            StringBuilder finalPath = new StringBuilder(32768);
            uint finalLength = GetFinalPathNameByHandleW(
                handle,
                finalPath,
                unchecked((uint)finalPath.Capacity),
                FileNameNormalized | VolumeNameDos);
            if (finalLength == 0 || finalLength >= finalPath.Capacity)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (!string.Equals(
                finalPath.ToString(),
                ExtendedPath(fullPath),
                StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("The native path escaped its exact canonical location.");
            }

            long length = unchecked((long)(
                ((ulong)information.FileSizeHigh << 32) |
                information.FileSizeLow));
            if (!directory && expectedLength >= 0 && length != expectedLength)
            {
                throw new IOException("The native file length is not exact.");
            }
            ulong fileId = ((ulong)information.FileIndexHigh << 32) |
                information.FileIndexLow;
            PSOBBPathLease lease = new PSOBBPathLease(
                handle,
                fullPath,
                directory,
                information.VolumeSerialNumber,
                fileId,
                length);
            handle = IntPtr.Zero;
            return lease;
        }
        finally
        {
            if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            {
                CloseHandle(handle);
            }
        }
    }

    public static PSOBBPathLease OpenDirectory(string path)
    {
        return OpenExactPath(path, true, -1, true);
    }

    public static PSOBBPathLease CreateDirectoryChild(
        PSOBBPathLease parent,
        string childName)
    {
        if (parent == null || !parent.IsDirectory ||
            string.IsNullOrWhiteSpace(childName) ||
            childName == "." || childName == ".." ||
            childName.IndexOf('\0') >= 0 ||
            childName.IndexOf('\\') >= 0 || childName.IndexOf('/') >= 0)
        {
            throw new ArgumentException("The native child directory name is invalid.");
        }
        parent.DangerousHandle.ToInt64();
        string path = NormalizeLocalPath(Path.Combine(parent.FullPath, childName));
        if (!CreateDirectoryW(path, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return OpenDirectory(path);
    }

    public static PSOBBPathLease OpenFile(
        PSOBBPathLease parent,
        string childName,
        long expectedLength)
    {
        if (parent == null || !parent.IsDirectory || expectedLength < 0 ||
            string.IsNullOrWhiteSpace(childName) || childName == "." ||
            childName == ".." || childName.IndexOf('\0') >= 0 ||
            childName.IndexOf('\\') >= 0 || childName.IndexOf('/') >= 0)
        {
            throw new ArgumentException("The native child file request is invalid.");
        }
        parent.DangerousHandle.ToInt64();
        return OpenExactPath(
            Path.Combine(parent.FullPath, childName),
            false,
            expectedLength,
            true);
    }

    public static PSOBBPathLease OpenReadLockedFile(
        PSOBBPathLease parent,
        string childName,
        long expectedLength)
    {
        if (parent == null || !parent.IsDirectory || expectedLength < 0 ||
            string.IsNullOrWhiteSpace(childName) || childName == "." ||
            childName == ".." || childName.IndexOf('\0') >= 0 ||
            childName.IndexOf('\\') >= 0 || childName.IndexOf('/') >= 0)
        {
            throw new ArgumentException("The locked native child file request is invalid.");
        }
        parent.DangerousHandle.ToInt64();
        return OpenExactPath(
            Path.Combine(parent.FullPath, childName),
            false,
            expectedLength,
            false);
    }

    public static byte[] ReadPrefix(PSOBBPathLease file, int byteCount)
    {
        if (file == null || file.IsDirectory || byteCount < 1 ||
            byteCount > file.Length)
        {
            throw new ArgumentException("The native prefix request is invalid.");
        }
        IntPtr handle = file.DangerousHandle;
        long position;
        if (!SetFilePointerEx(handle, 0, out position, FileBegin))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        byte[] bytes = new byte[byteCount];
        uint total = 0;
        while (total < byteCount)
        {
            byte[] remaining = total == 0
                ? bytes
                : new byte[byteCount - total];
            uint read;
            if (!ReadFile(
                handle,
                remaining,
                unchecked((uint)remaining.Length),
                out read,
                IntPtr.Zero) || read == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (total != 0)
            {
                Buffer.BlockCopy(remaining, 0, bytes, unchecked((int)total), unchecked((int)read));
            }
            total += read;
        }
        return bytes;
    }

    public static string ComputeSha256(PSOBBPathLease file)
    {
        const int maximumBytes = 16 * 1024 * 1024;
        if (file == null || file.IsDirectory || file.Length < 0 ||
            file.Length > maximumBytes)
        {
            throw new ArgumentException("The native file digest request is invalid.");
        }
        IntPtr handle = file.DangerousHandle;
        long position;
        if (!SetFilePointerEx(handle, 0, out position, FileBegin))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buffer = new byte[64 * 1024];
            long total = 0;
            while (total < file.Length)
            {
                uint request = unchecked((uint)Math.Min(
                    buffer.Length,
                    file.Length - total));
                uint read;
                if (!ReadFile(handle, buffer, request, out read, IntPtr.Zero) ||
                    read == 0 || read > request)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                hash.AppendData(buffer, 0, checked((int)read));
                total += read;
            }
            Array.Clear(buffer, 0, buffer.Length);
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }
    }

    private static string ObservationEventSuffix(
        uint processId,
        ulong processStartFileTime)
    {
        if (processId == 0 || processStartFileTime == 0)
        {
            throw new ArgumentException("The observation process identity is invalid.");
        }
        return processId.ToString("x8") + "." +
            processStartFileTime.ToString("x16");
    }

    public static bool FinalizeObservationEvidence(
        uint processId,
        ulong processStartFileTime,
        uint timeoutMilliseconds)
    {
        if (timeoutMilliseconds < 1 || timeoutMilliseconds > 10000)
        {
            throw new ArgumentOutOfRangeException("timeoutMilliseconds");
        }
        string suffix = ObservationEventSuffix(processId, processStartFileTime);
        string finalizeName =
            "Local\\PSOBB.Gameplay.Observation.Finalize." + suffix;
        string completionName =
            "Local\\PSOBB.Gameplay.Observation.Completed." + suffix;
        IntPtr finalize = OpenEventW(EventModifyState, false, finalizeName);
        if (finalize == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 2)
            {
                return false;
            }
            throw new Win32Exception(error);
        }
        IntPtr completion = IntPtr.Zero;
        try
        {
            completion = OpenEventW(Synchronize, false, completionName);
            if (completion == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (!SetEvent(finalize))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint wait = WaitForSingleObject(completion, timeoutMilliseconds);
            if (wait == WaitObject0)
            {
                return true;
            }
            if (wait == WaitTimeout)
            {
                throw new TimeoutException(
                    "Gameplay observation evidence did not finalize before shutdown.");
            }
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            if (completion != IntPtr.Zero)
            {
                CloseHandle(completion);
            }
            CloseHandle(finalize);
        }
    }

    public static void DeleteEmptyDirectory(
        PSOBBPathLease directory,
        uint expectedVolumeSerialNumber,
        ulong expectedFileId)
    {
        if (directory == null || !directory.IsDirectory ||
            directory.VolumeSerialNumber != expectedVolumeSerialNumber ||
            directory.FileId != expectedFileId)
        {
            throw new IOException("The empty directory identity changed before cleanup.");
        }
        FileDispositionInformation disposition = new FileDispositionInformation
        {
            DeleteFile = true,
        };
        if (!SetFileInformationByHandle(
            directory.DangerousHandle,
            FileDispositionInfo,
            ref disposition,
            unchecked((uint)Marshal.SizeOf(typeof(FileDispositionInformation)))))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    private static IntPtr BuildEnvironmentBlock(string observationRunId)
    {
        SortedDictionary<string, string> variables =
            new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in
            Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Process))
        {
            string key = Convert.ToString(entry.Key);
            string value = Convert.ToString(entry.Value) ?? string.Empty;
            if (string.IsNullOrEmpty(key) || key.IndexOf('\0') >= 0 ||
                value.IndexOf('\0') >= 0)
            {
                throw new InvalidOperationException("The parent environment contains an invalid entry.");
            }
            variables[key] = value;
        }
        variables["__COMPAT_LAYER"] = "RunAsInvoker";
        variables.Remove(ObservationRunIdName);
        if (!string.IsNullOrEmpty(observationRunId))
        {
            variables[ObservationRunIdName] = observationRunId;
        }

        StringBuilder block = new StringBuilder();
        foreach (KeyValuePair<string, string> variable in variables)
        {
            block.Append(variable.Key);
            block.Append('=');
            block.Append(variable.Value);
            block.Append('\0');
        }
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }

    public static int Start(
        string executable,
        string workingDirectory,
        bool preserveForeground,
        string observationRunId)
    {
        if (string.IsNullOrWhiteSpace(executable) || executable.IndexOf('\0') >= 0 ||
            string.IsNullOrWhiteSpace(workingDirectory) || workingDirectory.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("Executable and working-directory paths must be non-empty and contain no nulls.");
        }

        var startupInfo = new StartupInfo
        {
            Size = unchecked((uint)Marshal.SizeOf<StartupInfo>()),
            Flags = StartfUseShowWindow,
            ShowWindow = preserveForeground ? SwShowNoActivate : SwShowNormal,
        };
        var commandLine = new StringBuilder("\"" + executable + "\"");
        IntPtr environment = BuildEnvironmentBlock(observationRunId);
        ProcessInformation processInformation;
        try
        {
            if (!CreateProcessW(
                executable,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CreateNoWindow | CreateUnicodeEnvironment,
                environment,
                workingDirectory,
                ref startupInfo,
                out processInformation))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(environment);
        }

        try
        {
            return checked((int)processInformation.ProcessId);
        }
        finally
        {
            if (processInformation.Thread != IntPtr.Zero)
            {
                CloseHandle(processInformation.Thread);
            }
            if (processInformation.Process != IntPtr.Zero)
            {
                CloseHandle(processInformation.Process);
            }
        }
    }

    internal static void CloseNativeHandle(IntPtr handle)
    {
        if (!CloseHandle(handle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
}

function Open-PSOBBGameplayObservationDirectoryLeaseChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Initialize-PSOBBClientProcessLauncherType
    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PathWithinRoot -Path $Path -Root $safeRoot
    $relativePath = [System.IO.Path]::GetRelativePath($safeRoot, $safePath)
    if ([System.IO.Path]::IsPathRooted($relativePath) -or
        $relativePath -eq '..' -or $relativePath.StartsWith(
            '..\', [System.StringComparison]::Ordinal)) {
        throw 'The Gameplay observation lease path is outside its runtime root'
    }

    $leases = [System.Collections.Generic.List[object]]::new()
    try {
        $cursor = $safeRoot
        $leases.Add(
            [PSOBBClientProcessLauncher]::OpenDirectory($cursor))
        if ($relativePath -ne '.') {
            foreach ($segment in $relativePath.Split(
                    [char[]]@('\'),
                    [System.StringSplitOptions]::RemoveEmptyEntries)) {
                if ($segment -eq '.' -or $segment -eq '..') {
                    throw 'The Gameplay observation lease path has an invalid segment'
                }
                $cursor = Join-Path $cursor $segment
                $leases.Add(
                    [PSOBBClientProcessLauncher]::OpenDirectory($cursor))
            }
        }
        $leases.ToArray()
    } catch {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            try {
                $leases[$index].Dispose()
            } catch { }
        }
        throw
    }
}

function Close-PSOBBGameplayObservationDirectoryLeaseChain {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Leases)

    $closeFailure = $null
    for ($index = $Leases.Count - 1; $index -ge 0; $index--) {
        try {
            $Leases[$index].Dispose()
        } catch {
            if (-not $closeFailure) {
                $closeFailure = $_
            }
        }
    }
    if ($closeFailure) {
        throw $closeFailure
    }
}

function Assert-PSOBBGameplayObservationClientContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Contract)

    $validSchema = $false
    if ($Contract.PSObject.Properties.Name -contains 'Binding' -and
        $Contract.Binding -and
        $Contract.Binding.PSObject.Properties.Name -contains 'schemaVersion') {
        try {
            $validSchema = [long]$Contract.Binding.schemaVersion -eq 2L
        } catch {
            $validSchema = $false
        }
    }

    $expectedPaths = @(
        'dinput8.dll',
        'plugins/PSOBB.Gameplay.asi',
        'plugins/PSOBB.Gameplay.ini')
    $actualPaths = @()
    if ($Contract.PSObject.Properties.Name -contains
            'GameplayOverlayEntries') {
        $actualPaths = @($Contract.GameplayOverlayEntries | ForEach-Object {
                if ($_ -and $_.PSObject.Properties.Name -contains 'path') {
                    [string]$_.path
                } else {
                    [System.Management.Automation.Language.NullString]::Value
                }
            })
    }
    $pathsExact = $actualPaths.Count -eq $expectedPaths.Count
    foreach ($expectedPath in $expectedPaths) {
        if (@($actualPaths | Where-Object {
                    $_ -ceq $expectedPath
                }).Count -ne 1) {
            $pathsExact = $false
        }
    }
    if (-not $validSchema -or -not $pathsExact) {
        throw 'Gameplay observation evidence requires the exact active schema-2 Gameplay overlay'
    }
    $true
}

function Open-PSOBBGameplayOverlayLaunchLeaseSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ClientRoot,
        [Parameter(Mandatory)]$Contract
    )

    Assert-PSOBBGameplayObservationClientContract -Contract $Contract |
        Out-Null
    Initialize-PSOBBClientProcessLauncherType
    $safeClientRoot = Assert-PathWithinRoot `
        -Path $ClientRoot -Root $Layout.Root
    $directoryLeases = @()
    $fileLeases = [System.Collections.Generic.List[object]]::new()
    try {
        $directoryLeases = @(
            Open-PSOBBGameplayObservationDirectoryLeaseChain `
                -Path $safeClientRoot -Root $Layout.Root)
        $clientLease = $directoryLeases[-1]
        $pluginsRoot = Assert-PathWithinRoot `
            -Path (Join-Path $safeClientRoot 'plugins') -Root $Layout.Root
        $pluginsLease = [PSOBBClientProcessLauncher]::OpenDirectory(
            $pluginsRoot)
        $directoryLeases += $pluginsLease

        $specifications = @(
            [pscustomobject]@{
                Path = 'dinput8.dll'
                Parent = $clientLease
                Name = 'dinput8.dll'
            },
            [pscustomobject]@{
                Path = 'plugins/PSOBB.Gameplay.asi'
                Parent = $pluginsLease
                Name = 'PSOBB.Gameplay.asi'
            },
            [pscustomobject]@{
                Path = 'plugins/PSOBB.Gameplay.ini'
                Parent = $pluginsLease
                Name = 'PSOBB.Gameplay.ini'
            })
        foreach ($specification in $specifications) {
            $entries = @($Contract.GameplayOverlayEntries | Where-Object {
                    [string]$_.path -ceq [string]$specification.Path
                })
            if ($entries.Count -ne 1 -or
                [long]$entries[0].size -lt 1 -or
                [long]$entries[0].size -gt 16MB -or
                [string]$entries[0].sha256 -cnotmatch '\A[a-f0-9]{64}\z') {
                throw "The Gameplay overlay launch identity for $($specification.Path) is invalid"
            }
            $lease = [PSOBBClientProcessLauncher]::OpenReadLockedFile(
                $specification.Parent,
                [string]$specification.Name,
                [long]$entries[0].size)
            $expectedPath = [System.IO.Path]::GetFullPath(
                (Join-Path $safeClientRoot (
                    [string]$specification.Path).Replace('/', '\')))
            if (-not ([string]$lease.FullPath).Equals(
                    $expectedPath,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]$lease.ComputeSha256() -cne
                    [string]$entries[0].sha256) {
                $lease.Dispose()
                throw "The locked Gameplay overlay file $($specification.Path) is not exact"
            }
            $fileLeases.Add([pscustomobject]@{
                    Path = [string]$specification.Path
                    FullPath = $expectedPath
                    Size = [long]$entries[0].size
                    Sha256 = [string]$entries[0].sha256
                    Lease = $lease
                })
        }

        [pscustomobject]@{
            ClientRoot = $safeClientRoot
            DirectoryLeases = $directoryLeases
            Files = $fileLeases.ToArray()
        }
    } catch {
        for ($index = $fileLeases.Count - 1; $index -ge 0; $index--) {
            try { $fileLeases[$index].Lease.Dispose() } catch { }
        }
        if ($directoryLeases.Count -gt 0) {
            try {
                Close-PSOBBGameplayObservationDirectoryLeaseChain `
                    -Leases $directoryLeases
            } catch { }
        }
        throw
    }
}

function Assert-PSOBBGameplayOverlayLaunchLeaseSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$LeaseSet)

    $files = @($LeaseSet.Files)
    if ($files.Count -ne 3) {
        throw 'The Gameplay overlay launch lease set is incomplete'
    }
    foreach ($file in $files) {
        if (-not $file.Lease -or $file.Lease.IsDirectory -or
            [long]$file.Lease.Length -ne [long]$file.Size -or
            -not ([string]$file.Lease.FullPath).Equals(
                [string]$file.FullPath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$file.Lease.ComputeSha256() -cne
                [string]$file.Sha256) {
            throw "The locked Gameplay overlay file $($file.Path) changed during client startup"
        }
    }
    $true
}

function Close-PSOBBGameplayOverlayLaunchLeaseSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$LeaseSet)

    $closeFailure = $null
    $files = @($LeaseSet.Files)
    for ($index = $files.Count - 1; $index -ge 0; $index--) {
        try {
            $files[$index].Lease.Dispose()
        } catch {
            if (-not $closeFailure) { $closeFailure = $_ }
        }
    }
    try {
        Close-PSOBBGameplayObservationDirectoryLeaseChain `
            -Leases @($LeaseSet.DirectoryLeases)
    } catch {
        if (-not $closeFailure) { $closeFailure = $_ }
    }
    if ($closeFailure) { throw $closeFailure }
}

function New-PSOBBGameplayObservationRunDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$ServerLayout
    )

    if ([string]$ServerLayout.Environment -cne 'CombatCanary' -or
        [string]$ServerLayout.EnvironmentId -cne 'combat-canary') {
        throw 'Gameplay observation evidence requires the exact CombatCanary environment'
    }

    Initialize-PSOBBClientProcessLauncherType
    $evidenceRoot = Assert-PathWithinRoot `
        -Path (Join-Path $ServerLayout.EnvironmentRoot 'evidence') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $evidenceRoot -PathType Container)) {
        throw 'The protected CombatCanary evidence root is missing'
    }
    $leases = @()
    $runLease = $null
    $runCreated = $false
    try {
        $leases = @(Open-PSOBBGameplayObservationDirectoryLeaseChain `
                -Path $evidenceRoot -Root $Layout.Root)
        if ($leases.Count -lt 1 -or
            -not (Test-PSOBBProtectedAcl -Path $evidenceRoot)) {
            throw 'The CombatCanary evidence root is not an exact protected non-reparse directory'
        }

        $observationRoot = Assert-PathWithinRoot `
            -Path (Join-Path $evidenceRoot 'gameplay-observation') `
            -Root $Layout.Root
        $observationExisted = Test-Path -LiteralPath $observationRoot
        $observationLease = if ($observationExisted) {
            [PSOBBClientProcessLauncher]::OpenDirectory($observationRoot)
        } else {
            [PSOBBClientProcessLauncher]::CreateDirectoryChild(
                $leases[-1], 'gameplay-observation')
        }
        $leases += $observationLease
        if (-not $observationExisted) {
            Set-PSOBBProtectedAcl -Path $observationRoot
        }
        if (-not (Test-PSOBBProtectedAcl -Path $observationRoot)) {
            throw 'The Gameplay observation evidence root is not an exact protected non-reparse directory'
        }

        $runId = '{0}-gameplay-{1}' -f `
            [DateTime]::UtcNow.ToString(
                'yyyyMMddTHHmmssfffZ',
                [System.Globalization.CultureInfo]::InvariantCulture), `
            ([Guid]::NewGuid().ToString('N').Substring(0, 12))
        if ($runId -cnotmatch
            '\A[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}\z') {
            throw 'The generated Gameplay observation run ID is not canonical'
        }

        $runRoot = Assert-PathWithinRoot `
            -Path (Join-Path $observationRoot $runId) `
            -Root $Layout.Root
        $runLease = [PSOBBClientProcessLauncher]::CreateDirectoryChild(
            $observationLease, $runId)
        $runCreated = $true
        $leases += $runLease
        Set-PSOBBProtectedAcl -Path $runRoot
        if (-not (Test-PSOBBProtectedAcl -Path $runRoot)) {
            throw 'The Gameplay observation run directory did not receive the protected DACL'
        }

        [pscustomobject]@{
            RunId = $runId
            Path = $runRoot
            EvidenceFilePath = Join-Path $runRoot 'events-v1.partial'
            VolumeSerialNumber = [uint32]$runLease.VolumeSerialNumber
            FileId = [uint64]$runLease.FileId
        }
    } catch {
        $creationFailure = $_
        if ($runCreated -and $runLease) {
            try {
                $firstEntry = Get-ChildItem -Force -LiteralPath $runLease.FullPath |
                    Select-Object -First 1
                if (-not $firstEntry) {
                    [PSOBBClientProcessLauncher]::DeleteEmptyDirectory(
                        $runLease,
                        [uint32]$runLease.VolumeSerialNumber,
                        [uint64]$runLease.FileId)
                }
            } catch {
                throw ('Gameplay observation run creation failed and its exact ' +
                    "empty-directory cleanup also failed. Creation: $($creationFailure.Exception.Message) " +
                    "Cleanup: $($_.Exception.Message)")
            }
        }
        throw $creationFailure
    } finally {
        if ($leases.Count -gt 0) {
            Close-PSOBBGameplayObservationDirectoryLeaseChain `
                -Leases $leases
        }
    }
}

function Remove-PSOBBGameplayObservationEmptyRunDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Run
    )

    if (-not $Run.PSObject.Properties['RunId'] -or
        [string]$Run.RunId -cnotmatch
            '\A[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}\z' -or
        -not $Run.PSObject.Properties['Path'] -or
        -not $Run.PSObject.Properties['VolumeSerialNumber'] -or
        -not $Run.PSObject.Properties['FileId']) {
        throw 'The Gameplay observation cleanup identity is incomplete'
    }
    $expectedPath = Assert-PathWithinRoot `
        -Path (Join-Path (
                Join-Path $Layout.CombatCanary 'evidence\gameplay-observation') `
                ([string]$Run.RunId)) `
        -Root $Layout.Root
    $runPath = Assert-PathWithinRoot -Path ([string]$Run.Path) -Root $Layout.Root
    if (-not $runPath.Equals(
            $expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Gameplay observation cleanup path does not match its run ID'
    }

    $leases = @()
    try {
        $leases = @(Open-PSOBBGameplayObservationDirectoryLeaseChain `
                -Path $runPath -Root $Layout.Root)
        $runLease = $leases[-1]
        if ([uint32]$runLease.VolumeSerialNumber -ne
                [uint32]$Run.VolumeSerialNumber -or
            [uint64]$runLease.FileId -ne [uint64]$Run.FileId -or
            -not (Test-PSOBBProtectedAcl -Path $runPath)) {
            throw 'The Gameplay observation cleanup directory identity changed'
        }
        $firstEntry = Get-ChildItem -Force -LiteralPath $runPath |
            Select-Object -First 1
        if ($firstEntry) {
            return $false
        }
        [PSOBBClientProcessLauncher]::DeleteEmptyDirectory(
            $runLease,
            [uint32]$Run.VolumeSerialNumber,
            [uint64]$Run.FileId)
    } finally {
        if ($leases.Count -gt 0) {
            Close-PSOBBGameplayObservationDirectoryLeaseChain `
                -Leases $leases
        }
    }
    if (Test-Path -LiteralPath $runPath) {
        throw 'The exact empty Gameplay observation run directory was not removed'
    }
    $true
}

function Test-PSOBBGameplayObservationEvidenceFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RunRoot
    )

    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    $exactLeaf = @(Get-ChildItem -Force -LiteralPath $RunRoot |
        Where-Object { $_.Name -ceq 'events-v1.partial' })
    if ($exactLeaf.Count -ne 1 -or $exactLeaf[0].PSIsContainer -or
        $item.PSIsContainer -or
        ($item.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }
    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$allowed.Add(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    [void]$allowed.Add('S-1-5-32-544')
    [void]$allowed.Add('S-1-5-18')
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules(
            $true, $true,
            [System.Security.Principal.SecurityIdentifier]))
    if ($acl.AreAccessRulesProtected -or $rules.Count -ne $allowed.Count) {
        return $false
    }
    $found = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            -not $rule.IsInherited -or
            -not $allowed.Contains($rule.IdentityReference.Value) -or
            $rule.FileSystemRights -ne
                [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None) {
            return $false
        }
        [void]$found.Add($rule.IdentityReference.Value)
    }
    $found.SetEquals($allowed)
}

function Wait-PSOBBGameplayObservationEvidenceReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)]
        [ValidatePattern('\A[a-f0-9]{64}\z')]
        [string]$ExpectedClientSha256,
        [ValidateRange(50, 10000)][int]$TimeoutMilliseconds = 5000
    )

    $expectedEvidenceLength = 524544L
    $expectedHeaderLength = 256
    $expectedCapacity = 16384L
    $leases = @()
    $lastValidationFailure = $null
    try {
        $leases = @(Open-PSOBBGameplayObservationDirectoryLeaseChain `
                -Path ([string]$Run.Path) -Root $Layout.Root)
        $runLease = $leases[-1]
        if ([uint32]$runLease.VolumeSerialNumber -ne
                [uint32]$Run.VolumeSerialNumber -or
            [uint64]$runLease.FileId -ne [uint64]$Run.FileId -or
            -not (Test-PSOBBProtectedAcl -Path ([string]$Run.Path))) {
            throw 'The Gameplay observation run directory identity changed before readiness'
        }
        $expectedFilePath = Assert-PathWithinRoot `
            -Path (Join-Path $runLease.FullPath 'events-v1.partial') `
            -Root $Layout.Root
        if (-not $expectedFilePath.Equals(
                [string]$Run.EvidenceFilePath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The Gameplay observation evidence path changed before readiness'
        }
        $expectedStartFileTime = [uint64](
            $Process.StartTime.ToUniversalTime().ToFileTimeUtc())
        $expectedSha256 = $ExpectedClientSha256.ToUpperInvariant()
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
            $Process.Refresh()
            if ($Process.HasExited) {
                throw "The Gameplay observation producer exited before evidence readiness with code $($Process.ExitCode)"
            }

            $fileLease = $null
            $header = $null
            try {
                if ([System.IO.File]::Exists($expectedFilePath)) {
                    $fileLease = [PSOBBClientProcessLauncher]::OpenFile(
                        $runLease, 'events-v1.partial', $expectedEvidenceLength)
                    if (-not (Test-PSOBBGameplayObservationEvidenceFileAcl `
                            -Path $expectedFilePath `
                            -RunRoot $runLease.FullPath)) {
                        throw 'The Gameplay observation evidence file DACL is invalid'
                    }
                    $header = $fileLease.ReadPrefix($expectedHeaderLength)
                    $magic = [System.Text.Encoding]::ASCII.GetString(
                        $header, 0, 8)
                    $structSize = [BitConverter]::ToUInt32($header, 8)
                    $formatVersion = [BitConverter]::ToUInt32($header, 12)
                    $byteOrder = [BitConverter]::ToUInt32($header, 16)
                    $maximumSize = [BitConverter]::ToUInt32($header, 20)
                    $eventAbiVersion = [BitConverter]::ToUInt32($header, 24)
                    $eventRecordSize = [BitConverter]::ToUInt32($header, 28)
                    $eventCapacity = [BitConverter]::ToUInt32($header, 32)
                    $committedCount = [BitConverter]::ToUInt32($header, 36)
                    $identityVersion = [BitConverter]::ToUInt32($header, 40)
                    $shaByteCount = [BitConverter]::ToUInt32($header, 44)
                    $consumerThreadId = [BitConverter]::ToUInt32($header, 84)
                    $producerProcessId = [BitConverter]::ToUInt32($header, 88)
                    $reserved0 = [BitConverter]::ToUInt32($header, 92)
                    $producerStartFileTime = [BitConverter]::ToUInt64($header, 96)
                    $clientSha256 = [Convert]::ToHexString($header[120..151])
                    $expectedModuleField = [byte[]]::new(32)
                    [System.Text.Encoding]::ASCII.GetBytes(
                        '0.4.0-observation-evidence').CopyTo(
                            $expectedModuleField, 0)
                    $moduleFieldExact = [Convert]::ToHexString(
                        $header[152..183]) -ceq
                        [Convert]::ToHexString($expectedModuleField)
                    $lifecycleState = [BitConverter]::ToUInt32($header, 184)
                    $terminalFailureCode = [BitConverter]::ToUInt32(
                        $header, 188)
                    $captureStartFileTime = [BitConverter]::ToUInt64(
                        $header, 192)
                    $lastCommitFileTime = [BitConverter]::ToUInt64(
                        $header, 200)
                    $completionFileTime = [BitConverter]::ToUInt64(
                        $header, 208)
                    $heartbeatCount = [BitConverter]::ToUInt64($header, 216)
                    $activeStartTickMilliseconds =
                        [BitConverter]::ToUInt64($header, 224)
                    $lastCommitTickMilliseconds =
                        [BitConverter]::ToUInt64($header, 232)
                    $reservedTailZero = [Convert]::ToHexString(
                        $header[240..255]) -ceq ('00' * 16)
                    if ($magic -cne 'PSOBBOBS' -or $structSize -ne 256 -or
                        $formatVersion -ne 1 -or
                        $byteOrder -ne 0x01020304 -or
                        $maximumSize -ne $expectedEvidenceLength -or
                        $eventAbiVersion -ne 1 -or $eventRecordSize -ne 32 -or
                        $eventCapacity -ne $expectedCapacity -or
                        $committedCount -gt $expectedCapacity -or
                        $identityVersion -ne 1 -or $shaByteCount -ne 32 -or
                        $reserved0 -ne 0 -or -not $moduleFieldExact -or
                        $lifecycleState -ne 2 -or
                        $terminalFailureCode -ne 0 -or
                        $captureStartFileTime -eq 0 -or
                        $lastCommitFileTime -lt $captureStartFileTime -or
                        $completionFileTime -ne 0 -or
                        $heartbeatCount -lt 1 -or -not $reservedTailZero -or
                        $activeStartTickMilliseconds -eq 0 -or
                        $lastCommitTickMilliseconds -lt
                            $activeStartTickMilliseconds -or
                        $consumerThreadId -eq 0 -or
                        $producerProcessId -ne [uint32]$Process.Id -or
                        $producerStartFileTime -ne $expectedStartFileTime -or
                        $clientSha256 -cne $expectedSha256) {
                        throw 'The Gameplay observation evidence header is not ready or does not match the launched client'
                    }
                    return [pscustomobject]@{
                        Path = $expectedFilePath
                        VolumeSerialNumber = [uint32]$fileLease.VolumeSerialNumber
                        FileId = [uint64]$fileLease.FileId
                        Length = [long]$fileLease.Length
                        ProcessId = [int]$producerProcessId
                        ProcessStartTimeFileTimeUtc = [uint64]$producerStartFileTime
                        ConsumerThreadId = [uint32]$consumerThreadId
                        CommittedEventCount = [uint32]$committedCount
                        LifecycleState = [uint32]$lifecycleState
                        CaptureStartFileTime = [uint64]$captureStartFileTime
                        LastCommitFileTime = [uint64]$lastCommitFileTime
                        HeartbeatCount = [uint64]$heartbeatCount
                        ActiveStartTickMilliseconds =
                            [uint64]$activeStartTickMilliseconds
                        LastCommitTickMilliseconds =
                            [uint64]$lastCommitTickMilliseconds
                    }
                }
            } catch {
                $lastValidationFailure = $_
            } finally {
                if ($header) {
                    [Array]::Clear($header, 0, $header.Length)
                }
                if ($fileLease) {
                    $fileLease.Dispose()
                }
            }
            Start-Sleep -Milliseconds 50
        }
        $detail = if ($lastValidationFailure) {
            ": $($lastValidationFailure.Exception.Message)"
        } else {
            ''
        }
        throw "The Gameplay observation evidence did not become ready within $TimeoutMilliseconds ms$detail"
    } finally {
        if ($leases.Count -gt 0) {
            Close-PSOBBGameplayObservationDirectoryLeaseChain `
                -Leases $leases
        }
    }
}

function New-PSOBBGameplayObservationRunManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$ServerLayout,
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)]$Readiness,
        [Parameter(Mandatory)]$ClientContract,
        [Parameter(Mandatory)]$ClientIdentity
    )

    if ([string]$ServerLayout.Environment -cne 'CombatCanary' -or
        [string]$ServerLayout.EnvironmentId -cne 'combat-canary') {
        throw 'The Gameplay observation run manifest requires CombatCanary'
    }
    Assert-PSOBBGameplayObservationClientContract `
        -Contract $ClientContract | Out-Null
    if (-not $ClientContract.PSObject.Properties['Verification'] -or
        [string]$ClientContract.Verification.ClientBindingSha256 -cnotmatch
            '\A[a-f0-9]{64}\z' -or
        [string]$ClientIdentity.Sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or
        [long]$ClientIdentity.Size -lt 1) {
        throw 'The Gameplay observation run manifest client identity is invalid'
    }

    $moduleEntry = @($ClientContract.GameplayOverlayEntries |
        Where-Object { [string]$_.path -ceq 'plugins/PSOBB.Gameplay.asi' })
    $configurationEntry = @($ClientContract.GameplayOverlayEntries |
        Where-Object { [string]$_.path -ceq 'plugins/PSOBB.Gameplay.ini' })
    if ($moduleEntry.Count -ne 1 -or $configurationEntry.Count -ne 1 -or
        [long]$moduleEntry[0].size -lt 1 -or
        [string]$moduleEntry[0].sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or
        [long]$configurationEntry[0].size -lt 1 -or
        [string]$configurationEntry[0].sha256 -cnotmatch
            '\A[a-f0-9]{64}\z') {
        throw 'The Gameplay observation run manifest overlay identity is invalid'
    }

    $leases = @()
    $evidenceLease = $null
    $temporaryPath = $null
    try {
        $leases = @(Open-PSOBBGameplayObservationDirectoryLeaseChain `
                -Path ([string]$Run.Path) -Root $Layout.Root)
        $runLease = $leases[-1]
        if ([uint32]$runLease.VolumeSerialNumber -ne
                [uint32]$Run.VolumeSerialNumber -or
            [uint64]$runLease.FileId -ne [uint64]$Run.FileId -or
            -not (Test-PSOBBProtectedAcl -Path ([string]$Run.Path))) {
            throw 'The Gameplay observation run identity changed before manifest creation'
        }
        $evidenceLease = [PSOBBClientProcessLauncher]::OpenFile(
            $runLease, 'events-v1.partial', 524544L)
        if ([string]$Readiness.Path -cne [string]$Run.EvidenceFilePath -or
            [uint32]$evidenceLease.VolumeSerialNumber -ne
                [uint32]$Readiness.VolumeSerialNumber -or
            [uint64]$evidenceLease.FileId -ne [uint64]$Readiness.FileId -or
            [long]$evidenceLease.Length -ne [long]$Readiness.Length -or
            -not (Test-PSOBBGameplayObservationEvidenceFileAcl `
                -Path ([string]$Readiness.Path) `
                -RunRoot $runLease.FullPath)) {
            throw 'The Gameplay observation evidence identity changed before manifest creation'
        }

        $manifestPath = Assert-PathWithinRoot `
            -Path (Join-Path $runLease.FullPath 'run-manifest-v1.json') `
            -Root $Layout.Root
        if (Test-Path -LiteralPath $manifestPath) {
            throw 'The Gameplay observation run manifest already exists'
        }
        $manifest = [ordered]@{
            schemaVersion = 1
            createdAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
            environmentId = [string]$ServerLayout.EnvironmentId
            runId = [string]$Run.RunId
            evidenceFileName = 'events-v1.partial'
            evidenceLength = [long]$Readiness.Length
            evidenceVolumeSerialNumber = ('{0:x8}' -f
                [uint32]$Readiness.VolumeSerialNumber)
            evidenceFileId = ('{0:x16}' -f [uint64]$Readiness.FileId)
            clientBindingSha256 =
                [string]$ClientContract.Verification.ClientBindingSha256
            clientExecutableSize = [long]$ClientIdentity.Size
            clientExecutableSha256 = [string]$ClientIdentity.Sha256
            gameplayModulePath = [string]$moduleEntry[0].path
            gameplayModuleSize = [long]$moduleEntry[0].size
            gameplayModuleSha256 = [string]$moduleEntry[0].sha256
            gameplayConfigurationPath = [string]$configurationEntry[0].path
            gameplayConfigurationSize = [long]$configurationEntry[0].size
            gameplayConfigurationSha256 =
                [string]$configurationEntry[0].sha256
            processId = [long]$Readiness.ProcessId
            processStartTimeFileTimeUtc =
                [long]$Readiness.ProcessStartTimeFileTimeUtc
            consumerThreadId = [long]$Readiness.ConsumerThreadId
        }
        $manifestText = $manifest | ConvertTo-Json -Depth 4
        $temporaryPath = Assert-PathWithinRoot `
            -Path (Join-Path $runLease.FullPath (
                    '.run-manifest-v1.json.new-' +
                    [Guid]::NewGuid().ToString('N'))) `
            -Root $Layout.Root
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            $manifestText)
        $stream = $null
        try {
            $stream = [System.IO.FileStream]::new(
                $temporaryPath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            if ($stream) {
                $stream.Dispose()
            }
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
        Set-PSOBBProtectedAcl -Path $temporaryPath
        if (-not (Test-PSOBBProtectedAcl -Path $temporaryPath) -or
            (Test-Path -LiteralPath $manifestPath)) {
            throw 'The Gameplay observation run manifest staging identity is invalid'
        }
        [System.IO.File]::Move($temporaryPath, $manifestPath, $false)
        $temporaryPath = $null
        if (-not (Test-PSOBBProtectedAcl -Path $manifestPath)) {
            throw 'The Gameplay observation run manifest is not protected'
        }

        $snapshot = Read-PSOBBStrictJsonSnapshot `
            -Path $manifestPath -Root $runLease.FullPath `
            -MaximumBytes 32KB -MaximumDepth 4 `
            -Label 'Gameplay observation run manifest'
        $value = $snapshot.Value
        [void](Assert-PSOBBStrictDataObjectProperties `
                -Value $value `
                -Expected @($manifest.Keys) `
                -Label 'Gameplay observation run manifest')
        foreach ($propertyName in $manifest.Keys) {
            if ([string]$value.$propertyName -cne
                [string]$manifest[$propertyName]) {
                throw "The Gameplay observation run manifest $propertyName value changed during readback"
            }
        }
        if (-not (Test-PSOBBProtectedAcl -Path $manifestPath)) {
            throw 'The Gameplay observation run manifest protection changed during readback'
        }
        [pscustomobject]@{
            Path = $manifestPath
            Sha256 = [string]$snapshot.Sha256
        }
    } finally {
        $cleanupFailure = $null
        if ($temporaryPath -and (Test-Path -LiteralPath $temporaryPath)) {
            try {
                Remove-Item -LiteralPath $temporaryPath -Force
            } catch {
                $cleanupFailure = $_
            }
        }
        if ($evidenceLease) {
            try {
                $evidenceLease.Dispose()
            } catch {
                if (-not $cleanupFailure) {
                    $cleanupFailure = $_
                }
            }
        }
        if ($leases.Count -gt 0) {
            try {
                Close-PSOBBGameplayObservationDirectoryLeaseChain `
                    -Leases $leases
            } catch {
                if (-not $cleanupFailure) {
                    $cleanupFailure = $_
                }
            }
        }
        if ($cleanupFailure) {
            throw $cleanupFailure
        }
    }
}

function Start-PSOBBClientProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientExecutable,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [switch]$PreserveForeground,
        [AllowEmptyString()][string]$GameplayObservationRunId
    )

    if (-not [string]::IsNullOrEmpty($GameplayObservationRunId) -and
        $GameplayObservationRunId -cnotmatch
            '\A[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}\z') {
        throw 'The Gameplay observation run ID is invalid'
    }

    Initialize-PSOBBClientProcessLauncherType
    $processId = $null
    Assert-PSOBBClientLoginRegistry | Out-Null
    $processId = [PSOBBClientProcessLauncher]::Start(
        $ClientExecutable,
        $WorkingDirectory,
        [bool]$PreserveForeground,
        $(if ([string]::IsNullOrEmpty($GameplayObservationRunId)) {
                $null
            } else {
                $GameplayObservationRunId
            }))
    try {
        $process = [System.Diagnostics.Process]::GetProcessById($processId)
        # Force Process to retain a native handle while the child is alive so
        # HasExited and ExitCode remain reliable after a bounded WaitForExit.
        [void]$process.Handle
    } catch {
        $_.Exception.Data['PSOBBClientCreated'] = $true
        $_.Exception.Data['PSOBBClientProcessId'] = [int]$processId
        throw
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

Assert-PSOBBClientLoginRegistry | Out-Null
$initialState = Get-PSOBBAdminState -Layout $layout
$newCredential = Read-PSOBBAdminCredential
$newPassword = $null
$oldPassword = $null
$rotationBackup = $null
$stateBackup = $null
$adminState = $null
$verifiedState = $null
$shutdownPassword = $null
$loginPolicy = $null
$loginCacheCleared = $false
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
        $loginPolicy = Clear-PSOBBClientSavedCredentials
        $loginCacheCleared = $true
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

    $clientLaunch = $null
    if ($Relaunch) {
        $serverStarted = $false
        try {
            & (Join-Path $PSScriptRoot 'Start-PSOBB.ps1') -RuntimeRoot $layout.Root | Out-Host
            $serverStarted = $true
            & (Join-Path $PSScriptRoot 'Test-PSOBB.ps1') -Suite Baseline -RuntimeRoot $layout.Root | Out-Host
            $clientLaunch = & (Join-Path $PSScriptRoot 'Start-PSOBBClient.ps1') `
                -Channel Stable `
                -WindowMode ProfileDefault `
                -RuntimeRoot $layout.Root
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
        ClientPid = if ($clientLaunch) { $clientLaunch.Pid } else { $null }
        LoginCacheCleared = [bool]$loginCacheCleared
        RememberLoginEnabled = [bool]$loginPolicy.RememberLoginEnabled
        NextStep = if ($Relaunch) {
            'Enter the new username and password once in PSOBB; remembered login will save them when enabled'
        } else {
            'The stale saved login was cleared; enter the new credentials once at the next client launch'
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
