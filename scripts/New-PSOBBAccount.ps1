[CmdletBinding(DefaultParameterSetName = 'Generate')]
param(
    [Parameter(Mandatory)][ValidateSet('Admin', 'Player')][string]$Role,
    [Parameter(ParameterSetName = 'Generate')][switch]$RotateCredential,
    [Parameter(ParameterSetName = 'Prepare', Mandatory)][ValidatePattern('^[0-9A-Fa-f]{8}$')][string]$AccountId,
    [Parameter(ParameterSetName = 'Prepare', Mandatory)][switch]$PrepareLicenseClipboard,
    [Parameter(ParameterSetName = 'Provision', Mandatory)][switch]$Provision,
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
Assert-PathWithinRoot -Path $layout.Secrets -Root $layout.Root | Out-Null
New-Item -ItemType Directory -Force -Path $layout.Secrets | Out-Null
$credentialPath = Join-Path $layout.Secrets ($Role.ToLowerInvariant() + '.credential.clixml')
$metadataPath = Join-Path $layout.Secrets ($Role.ToLowerInvariant() + '.account.json')
Assert-PathWithinRoot -Path $credentialPath -Root $layout.Root | Out-Null
Assert-PathWithinRoot -Path $metadataPath -Root $layout.Root | Out-Null

if ($PSCmdlet.ParameterSetName -eq 'Generate') {
    if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
        throw "The $Role account is already provisioned; this bootstrap command never rotates a live account"
    }
    if ((Test-Path -LiteralPath $credentialPath -PathType Leaf) -and -not $RotateCredential) {
        throw "The $Role credential already exists. Use -RotateCredential only before the account is provisioned"
    }
    if ((Test-Path -LiteralPath $credentialPath -PathType Leaf) -and $RotateCredential) {
        $existingCredential = Import-Clixml -LiteralPath $credentialPath
        $licenseDirectory = Join-Path $layout.Server 'system\licenses'
        Assert-PathWithinRoot -Path $licenseDirectory -Root $layout.Root | Out-Null
        if (Test-Path -LiteralPath $licenseDirectory -PathType Container) {
            foreach ($licenseFile in @(Get-ChildItem -LiteralPath $licenseDirectory -Filter '*.json' -File -Force)) {
                Assert-PathWithinRoot -Path $licenseFile.FullName -Root $layout.Root | Out-Null
                $savedAccount = Get-Content -Raw -LiteralPath $licenseFile.FullName | ConvertFrom-Json
                if (@($savedAccount.BBLicenses | Where-Object {
                    ([string]$_.UserName).Equals(
                        $existingCredential.UserName, [System.StringComparison]::OrdinalIgnoreCase)
                }).Count -gt 0) {
                    throw 'The existing credential is linked to a provisioned account and cannot be replaced here'
                }
            }
        }
    }

    $prefix = if ($Role -eq 'Admin') { 'psoadm-' } else { 'psoplay-' }
    $username = $prefix + (New-CrockfordSecret -Length 6).ToLowerInvariant()
    $password = New-CrockfordSecret -Length 16
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    $temporaryCredentialPath = $credentialPath + '.new'
    Assert-PathWithinRoot -Path $temporaryCredentialPath -Root $layout.Root | Out-Null
    [pscredential]::new($username, $secure) | Export-Clixml -LiteralPath $temporaryCredentialPath
    $acl = if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
        Get-Acl -LiteralPath $credentialPath
    } else {
        Get-Acl -LiteralPath $temporaryCredentialPath
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($existingRule)
    }
    foreach ($sid in @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $temporaryCredentialPath -AclObject $acl
    Move-Item -LiteralPath $temporaryCredentialPath -Destination $credentialPath -Force
    [pscustomobject]@{
        Role = $Role
        Username = $username
        CredentialPath = $credentialPath
        NextStep = "Provision atomically with -Role $Role -Provision while the local server is stopped"
    }
    return
}

if (-not (Test-Path -LiteralPath $credentialPath)) {
    throw "Generate the $Role credential first: $credentialPath"
}
$credential = Import-Clixml -LiteralPath $credentialPath
$plainPassword = $credential.GetNetworkCredential().Password
if (-not (Test-PSOBBGamePasswordLength -Password $plainPassword) -or
    $plainPassword -cnotmatch '\A[A-Za-z0-9]+\z') {
    $plainPassword = $null
    throw 'The protected BB credential must contain 1-16 ASCII letters and digits'
}

if ($PSCmdlet.ParameterSetName -eq 'Provision') {
    if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
        throw "The $Role account is already provisioned; refusing to modify it"
    }
    if (@(Get-NewservProcessesAtPath -Layout $layout).Count -gt 0) {
        throw 'Stop the exact PSOBB newserv process before offline account provisioning'
    }

    $licenseDirectory = Join-Path $layout.Server 'system\licenses'
    Assert-PathWithinRoot -Path $licenseDirectory -Root $layout.Root | Out-Null
    if (-not (Test-Path -LiteralPath $licenseDirectory -PathType Container)) {
        throw "newserv license directory is missing: $licenseDirectory"
    }
    $existingUsername = $false
    foreach ($licenseFile in @(Get-ChildItem -LiteralPath $licenseDirectory -Filter '*.json' -File -Force)) {
        Assert-PathWithinRoot -Path $licenseFile.FullName -Root $layout.Root | Out-Null
        $savedAccount = Get-Content -Raw -LiteralPath $licenseFile.FullName | ConvertFrom-Json
        if (@($savedAccount.BBLicenses | Where-Object {
            ([string]$_.UserName).Equals($credential.UserName, [System.StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0) {
            $existingUsername = $true
            break
        }
    }
    if ($existingUsername) {
        throw "A BB license already uses username $($credential.UserName)"
    }

    do {
        $accountIdBytes = [byte[]]::new(4)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($accountIdBytes)
        $accountNumber = [BitConverter]::ToUInt32($accountIdBytes, 0) -band [uint32]0x7FFFFFFF
        $generatedAccountId = $accountNumber.ToString('X8')
        $licensePath = Join-Path $licenseDirectory ($accountNumber.ToString('D10') + '.json')
    } while (($accountNumber -eq 0) -or (Test-Path -LiteralPath $licensePath))
    Assert-PathWithinRoot -Path $licensePath -Root $layout.Root | Out-Null

    $serverExecutable = Join-Path $layout.Server 'newserv-windows.exe'
    Assert-PathWithinRoot -Path $serverExecutable -Root $layout.Root | Out-Null
    if (-not (Test-Path -LiteralPath $serverExecutable -PathType Leaf)) {
        throw "newserv executable is missing: $serverExecutable"
    }
    $flags = if ($Role -eq 'Admin') { 'root' } else { 'none' }
    $addAccountCommand = "add-account id=$generatedAccountId flags=$flags"
    $addLicenseCommand = 'add-license {0} BB {1} {2}' -f $generatedAccountId, $credential.UserName, $plainPassword
    $accountCreated = $false

    function Invoke-LocalNewservShell {
        param([Parameter(Mandatory)][string[]]$Commands)

        $process = $null
        try {
            $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $serverExecutable
            $startInfo.WorkingDirectory = $layout.Server
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardInput = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true

            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            if (-not $process.Start()) {
                throw 'newserv did not start for offline account provisioning'
            }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()

            $ready = $false
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            while ([DateTime]::UtcNow -lt $deadline) {
                if ($process.HasExited) {
                    break
                }
                $listeners = Get-NetTCPConnection -OwningProcess $process.Id -State Listen -ErrorAction SilentlyContinue
                if ($listeners | Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.LocalPort -eq 11000 }) {
                    $ready = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            if (-not $ready) {
                throw 'newserv did not reach its loopback-ready state for provisioning'
            }

            foreach ($shellCommand in @($Commands + 'exit')) {
                $process.StandardInput.WriteLine($shellCommand)
            }
            $process.StandardInput.Flush()
            $process.StandardInput.Close()
            if (-not $process.WaitForExit(30000)) {
                throw 'newserv did not exit after account provisioning'
            }
            [pscustomobject]@{
                ExitCode = $process.ExitCode
                Stdout = $stdoutTask.GetAwaiter().GetResult()
                Stderr = $stderrTask.GetAwaiter().GetResult()
            }
        } finally {
            if ($process -and -not $process.HasExited) {
                $process.Kill($true)
                $process.WaitForExit()
            }
            if ($process) {
                $process.Dispose()
            }
        }
    }

    try {
        $result = Invoke-LocalNewservShell -Commands @($addAccountCommand, $addLicenseCommand)
        $accountCreated = Test-Path -LiteralPath $licensePath -PathType Leaf
        $safeStdout = $result.Stdout.Replace($plainPassword, '[REDACTED]')
        $safeStderr = $result.Stderr.Replace($plainPassword, '[REDACTED]')
        if (($result.ExitCode -ne 0) -or (($safeStdout + $safeStderr) -match '(?mi)^FAILED:|\bERROR\b|\bException\b')) {
            $failureLines = (($safeStdout + [Environment]::NewLine + $safeStderr) -split "`r?`n") |
                Where-Object { $_ -match 'FAILED:|ERROR|Exception' } |
                Select-Object -First 10
            throw ('newserv rejected account provisioning: ' + ($failureLines -join '; '))
        }
        if ($safeStdout -notmatch [regex]::Escape("Account $generatedAccountId added")) {
            throw 'newserv did not confirm account creation'
        }
        if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
            throw "newserv did not persist the expected license file: $licensePath"
        }
        $savedLicense = Get-Content -Raw -LiteralPath $licensePath | ConvertFrom-Json
        $expectedFlags = if ($Role -eq 'Admin') { 0x7FFFFFFF } else { 0 }
        $savedBBLicenses = @($savedLicense.BBLicenses)
        if (([uint32]$savedLicense.AccountID -ne $accountNumber) -or
            ([uint32]$savedLicense.Flags -ne [uint32]$expectedFlags) -or
            ($savedBBLicenses.Count -ne 1) -or
            -not ([string]$savedBBLicenses[0].UserName).Equals(
                $credential.UserName, [System.StringComparison]::Ordinal) -or
            -not ([string]$savedBBLicenses[0].Password).Equals(
                $plainPassword, [System.StringComparison]::Ordinal)) {
            throw 'Persisted BB license verification failed'
        }

        $metadata = [ordered]@{
            role = $Role
            username = $credential.UserName
            accountId = $generatedAccountId
            provisionedAtUtc = [DateTime]::UtcNow.ToString('o')
        }
        [System.IO.File]::WriteAllText(
            $metadataPath,
            ($metadata | ConvertTo-Json),
            [System.Text.UTF8Encoding]::new($false))
        $metadataAcl = Get-Acl -LiteralPath $credentialPath
        Set-Acl -LiteralPath $metadataPath -AclObject $metadataAcl

        [pscustomobject]@{
            Role = $Role
            Username = $credential.UserName
            AccountId = $generatedAccountId
            CredentialPath = $credentialPath
            MetadataPath = $metadataPath
            Provisioned = $true
            VerifiedBy = 'persisted account ID, flags, and single BB license'
        }
        return
    } catch {
        $provisioningError = $_
        if ($accountCreated -or (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
            try {
                $rollback = Invoke-LocalNewservShell -Commands @("delete-account $generatedAccountId")
                $safeRollbackOutput = ($rollback.Stdout + [Environment]::NewLine + $rollback.Stderr).Replace(
                    $plainPassword, '[REDACTED]')
                if (($rollback.ExitCode -ne 0) -or
                    ($safeRollbackOutput -match '(?mi)^FAILED:|\bERROR\b|\bException\b') -or
                    ($safeRollbackOutput -notmatch 'Account deleted') -or
                    (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
                    throw 'newserv did not confirm complete rollback of the newly created account'
                }
                if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
                    Remove-Item -LiteralPath $metadataPath -Force
                }
            } catch {
                throw "Account provisioning failed and compensating delete-account also failed. Original: $($provisioningError.Exception.Message) Rollback: $($_.Exception.Message)"
            }
        }
        throw $provisioningError
    } finally {
        $addLicenseCommand = $null
        $result = $null
        $plainPassword = $null
    }
}

$preparedAccountNumber = [Convert]::ToUInt32($AccountId, 16)
if ($preparedAccountNumber -eq 0 -or $preparedAccountNumber -gt 0x7FFFFFFF) {
    throw 'The prepared account ID must be a nonzero 31-bit value'
}
$preparedLicensePath = Join-Path (Join-Path $layout.Server 'system\licenses') (
    $preparedAccountNumber.ToString('D10') + '.json')
Assert-PathWithinRoot -Path $preparedLicensePath -Root $layout.Root | Out-Null
if (-not (Test-Path -LiteralPath $preparedLicensePath -PathType Leaf)) {
    throw 'The prepared account ID does not identify a persisted local newserv account'
}
$preparedAccount = Get-Content -Raw -LiteralPath $preparedLicensePath | ConvertFrom-Json
$expectedPreparedFlags = if ($Role -eq 'Admin') { 0x7FFFFFFF } else { 0 }
if (([uint32]$preparedAccount.AccountID -ne $preparedAccountNumber) -or
    ([uint32]$preparedAccount.Flags -ne [uint32]$expectedPreparedFlags) -or
    (@($preparedAccount.BBLicenses).Count -ne 0)) {
    throw 'The prepared account is not an unlicensed bootstrap account with the expected role'
}
$command = 'add-license {0} BB {1} {2}' -f $AccountId.ToUpperInvariant(), $credential.UserName, $plainPassword
Set-Clipboard -Value $command
[pscustomobject]@{
    Role = $Role
    Username = $credential.UserName
    AccountId = $AccountId.ToUpperInvariant()
    ClipboardPrepared = $true
    Warning = 'Paste once into the local newserv console, then clear the clipboard.'
}
