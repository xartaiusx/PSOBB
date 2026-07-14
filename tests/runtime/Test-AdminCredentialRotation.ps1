[CmdletBinding()]
param(
    [switch]$OfflineIntegration,
    [string]$RuntimeRoot
)

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1')
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

$acceptedUsernames = @('admin', 'psoadm-123abc', 'a_1')
$rejectedUsernames = @('', 'ab', 'Admin', '1admin', 'admin name', 'a2345678901234567', '..\admin', "admin`n")
Add-Result 'admin username policy accepts safe values' (
    @($acceptedUsernames | Where-Object { -not (Test-PSOBBAdminUsername $_) }).Count -eq 0) '3-16 lowercase path-safe characters'
Add-Result 'admin username policy rejects unsafe values' (
    @($rejectedUsernames | Where-Object { Test-PSOBBAdminUsername $_ }).Count -eq 0) 'case, length, token, and path traversal checks'

$acceptedPasswords = @('a', 'short', 'Abcd1234Efgh5678', '0123456789ABCDEF')
$rejectedPasswords = @('', 'Abcd1234 Efgh567', 'Abcd1234-Efgh567', 'Abcd1234Efgh56789', "Abcd1234`n")
Add-Result 'admin password policy accepts 1-16 alphanumeric characters' (
    @($acceptedPasswords | Where-Object { -not (Test-PSOBBAdminPassword $_) }).Count -eq 0) 'upstream BB length; legacy-client and shell-safe alphabet'
Add-Result 'admin password policy rejects ambiguous values' (
    @($rejectedPasswords | Where-Object { Test-PSOBBAdminPassword $_ }).Count -eq 0) 'length range and alphabet checks'
Add-Result 'shared BB password length accepts 1-16 characters' (
    (Test-PSOBBGamePasswordLength 'a') -and
    (Test-PSOBBGamePasswordLength '1234567890123456') -and
    -not (Test-PSOBBGamePasswordLength '') -and
    -not (Test-PSOBBGamePasswordLength '12345678901234567')) 'baseline and rotation share the upstream newserv limit'

$fileSecurity = New-PSOBBProtectedSecurityDescriptor -IsContainer $false
$directorySecurity = New-PSOBBProtectedSecurityDescriptor -IsContainer $true
$daclOnlyDescriptors =
    $fileSecurity.AreAccessRulesProtected -and
    $directorySecurity.AreAccessRulesProtected -and
    (@($fileSecurity.GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier])).Count -eq 3) -and
    (@($directorySecurity.GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier])).Count -eq 3) -and
    [string]::IsNullOrEmpty($fileSecurity.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Audit)) -and
    [string]::IsNullOrEmpty($directorySecurity.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Audit))
Add-Result 'protected ACL descriptors contain only a DACL' $daclOnlyDescriptors 'normal operators never request SeSecurityPrivilege for credential backups'

$promptRetries = & {
    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $responses = [System.Collections.Generic.Queue[string]]::new()
    @(
        'fixtureadmin',
        'Abcd1234Efgh56789',
        'Abcd1234Efgh5678',
        '0123456789ABCDEF',
        'Abcd1234Efgh5678',
        'Abcd1234Efgh5678'
    ) | ForEach-Object { $responses.Enqueue($_) }
    function Read-Host {
        param([string]$Prompt, [switch]$AsSecureString)
        $value = $responses.Dequeue()
        if ($AsSecureString) {
            ConvertTo-SecureString $value -AsPlainText -Force
        } else {
            $value
        }
    }
    $credential = Read-PSOBBAdminCredential 6>$null
    try {
        ($credential.UserName -ceq 'fixtureadmin') -and
            ($credential.GetNetworkCredential().Password -ceq 'Abcd1234Efgh5678') -and
            ($responses.Count -eq 0)
    } finally {
        $credential.Password.Dispose()
    }
}
Add-Result 'password prompt retries length and confirmation errors' $promptRetries 'invalid entries no longer abort the whole command'

$pathFailureProcess = [pscustomobject]@{ Id = 4242; HasExited = $false }
$pathFailureProcess | Add-Member -MemberType ScriptProperty -Name Path -Value { throw 'simulated path access failure' }
$pathGuardError = $null
try {
    Test-PSOBBProcessAtExactPath -Process $pathFailureProcess -Name 'fixture' -ExpectedPath 'C:\fixture.exe' -PathProbeAttempts 1 -PathProbeDelayMilliseconds 0 | Out-Null
} catch {
    $pathGuardError = $_.Exception.Message
}
$pathGuarded = $pathGuardError -match 'fixture PID 4242' -and
    $pathGuardError -notmatch "property 'Id'"
Add-Result 'process path failures retain the candidate PID' $pathGuarded 'caught errors no longer replace the process pipeline variable'

$script:transientPathReads = 0
$transientPathProcess = [pscustomobject]@{ Id = 4244; HasExited = $false }
$transientPathProcess | Add-Member -MemberType ScriptProperty -Name Path -Value {
    $script:transientPathReads++
    if ($script:transientPathReads -eq 1) { return $null }
    'C:\fixture.exe'
}
$transientPathRecovered = Test-PSOBBProcessAtExactPath -Process $transientPathProcess -Name 'fixture' -ExpectedPath 'C:\fixture.exe' -PathProbeAttempts 2 -PathProbeDelayMilliseconds 0
Add-Result 'transient null process paths are retried safely' (
    $transientPathRecovered -and ($script:transientPathReads -eq 2)) 'a live process must resolve to the exact expected path on a later bounded probe'
Remove-Variable transientPathReads -Scope Script -ErrorAction SilentlyContinue

$exitedProcess = [pscustomobject]@{ Id = 4243; HasExited = $true }
$exitedProcess | Add-Member -MemberType ScriptProperty -Name Path -Value { throw 'path should not be read' }
$exitedIgnored = -not (Test-PSOBBProcessAtExactPath -Process $exitedProcess -Name 'fixture' -ExpectedPath 'C:\fixture.exe')
Add-Result 'process exit races are ignored safely' $exitedIgnored 'exited candidates cannot block a verified restart'

$currentPwshPath = (Get-Process -Id $PID).Path
$nativeCaller = Get-PSOBBNativeProcessInfo -ProcessId $PID
Add-Result 'limited native process query resolves the caller' (
    $nativeCaller.IsRunning -and
    ([System.IO.Path]::GetFullPath($nativeCaller.ImagePath)).Equals(
        [System.IO.Path]::GetFullPath($currentPwshPath),
        [System.StringComparison]::OrdinalIgnoreCase) -and
    ($nativeCaller.CreationTimeUtc -ne [DateTime]::MinValue)) 'QueryFullProcessImageNameW and GetProcessTimes use PROCESS_QUERY_LIMITED_INFORMATION'
$sharedMatches = @(Get-PSOBBProcessesAtExactPath -Name 'pwsh' -ExpectedPath $currentPwshPath)
Add-Result 'shared exact-path process inventory finds the caller' (
    @($sharedMatches | Where-Object Id -eq $PID).Count -eq 1) 'client, launcher, and newserv use the same race-safe helper'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PSOBB-AdminCredentialTests-' + [Guid]::NewGuid().ToString('N'))
$registryPath = 'HKCU:\Software\PSOBB-AdminCredentialTests-' + [Guid]::NewGuid().ToString('N')
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    foreach ($name in @(
        'system_oldadmin.psosys',
        'guild_cards_oldadmin.psocard',
        'account_oldadmin.nsa',
        'shared_bank_oldadmin.psobank',
        'player_oldadmin_0.psochar',
        'player_oldadmin_31.psobank',
        'player_oldadmin_4.nsc',
        'backup_player_100_0.psochar',
        'player_someoneelse_0.psochar')) {
        [System.IO.File]::WriteAllText((Join-Path $temporaryRoot $name), '')
    }
    $bound = @(Get-PSOBBUsernameBoundFiles -PlayersDirectory $temporaryRoot -Username 'oldadmin')
    Add-Result 'username-bound player files are detected' ($bound.Count -eq 7) "$($bound.Count) bound file(s)"

    $availabilityLayout = Get-PSOBBLayout -RuntimeRoot (Join-Path $temporaryRoot 'availability-runtime')
    $availabilityLicense = Join-Path $availabilityLayout.Server 'system\licenses\0000000001.json'
    $availabilityPlayers = Join-Path $availabilityLayout.Server 'system\players'
    New-Item -ItemType Directory -Path (Split-Path $availabilityLicense -Parent) -Force | Out-Null
    New-Item -ItemType Directory -Path $availabilityPlayers -Force | Out-Null
    [System.IO.File]::WriteAllText($availabilityLicense, '{}')
    [System.IO.File]::WriteAllText((Join-Path $availabilityPlayers 'system_newadmin.psosys'), '')
    $collisionRejected = $false
    try {
        Assert-PSOBBUsernameAvailable -Layout $availabilityLayout -AdminState ([pscustomobject]@{
            Username = 'oldadmin'
            LicensePath = $availabilityLicense
        }) -Username 'newadmin'
    } catch {
        $collisionRejected = $_.Exception.Message -match 'requested username already has'
    }
    Add-Result 'orphaned target-username player data is rejected' $collisionRejected 'prevents cross-account file adoption'

    $fixtureLayout = Get-PSOBBLayout -RuntimeRoot (Join-Path $temporaryRoot 'runtime')
    $fixtureLicense = Join-Path $fixtureLayout.Server 'system\licenses\0000000001.json'
    $fixtureCredential = Join-Path $fixtureLayout.Secrets 'admin.credential.clixml'
    $fixtureMetadata = Join-Path $fixtureLayout.Secrets 'admin.account.json'
    $fixtureStateBackup = Join-Path $fixtureLayout.Backups 'state-fixture'
    foreach ($directory in @(
        (Split-Path $fixtureLicense -Parent),
        $fixtureLayout.Secrets,
        $fixtureLayout.Backups,
        $fixtureStateBackup)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        Set-PSOBBProtectedAcl -Path $directory
    }
    [System.IO.File]::WriteAllText($fixtureLicense, 'license-original')
    [System.IO.File]::WriteAllText($fixtureCredential, 'credential-original')
    [System.IO.File]::WriteAllText($fixtureMetadata, 'metadata-original')
    foreach ($path in @($fixtureLicense, $fixtureCredential, $fixtureMetadata)) {
        Set-PSOBBProtectedAcl -Path $path
    }
    $fixtureAdmin = [pscustomobject]@{
        AccountId = '00000001'
        Username = 'oldadmin'
        LicensePath = $fixtureLicense
        CredentialPath = $fixtureCredential
        MetadataPath = $fixtureMetadata
    }
    $rotationBackup = New-PSOBBCredentialRotationBackup -Layout $fixtureLayout -AdminState $fixtureAdmin -StateBackupPath $fixtureStateBackup
    [System.IO.File]::WriteAllText($fixtureLicense, 'license-mutated')
    [System.IO.File]::WriteAllText($fixtureCredential, 'credential-mutated')
    [System.IO.File]::WriteAllText($fixtureMetadata, 'metadata-mutated')
    Restore-PSOBBCredentialRotationBackup -Layout $fixtureLayout -AdminState $fixtureAdmin -RotationBackup $rotationBackup
    $restoredExactly = ((Get-LowerSha256 $fixtureLicense) -eq (Get-LowerSha256 $rotationBackup.Files.License)) -and
        ((Get-LowerSha256 $fixtureCredential) -eq (Get-LowerSha256 $rotationBackup.Files.Credential)) -and
        ((Get-LowerSha256 $fixtureMetadata) -eq (Get-LowerSha256 $rotationBackup.Files.Metadata)) -and
        (Test-PSOBBProtectedAcl -Path $fixtureLicense) -and
        (Test-PSOBBProtectedAcl -Path $fixtureCredential) -and
        (Test-PSOBBProtectedAcl -Path $fixtureMetadata) -and
        ((Get-Content -Raw -LiteralPath $rotationBackup.ManifestPath | ConvertFrom-Json).status -eq 'rolled-back')
    Add-Result 'protected credential backup rolls back exactly' $restoredExactly $rotationBackup.Path

    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name ACCOUNT_CHECK -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name ACCOUNT -PropertyType String -Value 'oldadmin' | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name PASSWORD -PropertyType Binary -Value ([byte[]](1, 2, 3)) | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name WIDTH -PropertyType DWord -Value 2560 | Out-Null
    Set-PSOBBClientManualLogin -RegistryPath $registryPath
    $registry = Get-Item -LiteralPath $registryPath
    $values = Get-ItemProperty -LiteralPath $registryPath
    $manualLogin = ($values.ACCOUNT_CHECK -eq 0) -and ($values.ACCOUNT -eq '') -and ($values.PASSWORD -eq '') -and
        ($values.WIDTH -eq 2560) -and
        ($registry.GetValueKind('ACCOUNT') -eq [Microsoft.Win32.RegistryValueKind]::String) -and
        ($registry.GetValueKind('PASSWORD') -eq [Microsoft.Win32.RegistryValueKind]::String)
    Add-Result 'manual-login reset is narrow and type-correct' $manualLogin 'graphics value preserved; password cache no longer binary'

    $clientStartInfo = New-PSOBBClientStartInfo -ClientExecutable 'C:\fixture\Psobb.exe' -WorkingDirectory 'C:\fixture'
    $clientRunsAsInvoker =
        ($clientStartInfo.FileName -eq 'C:\fixture\Psobb.exe') -and
        ($clientStartInfo.WorkingDirectory -eq 'C:\fixture') -and
        $clientStartInfo.UseShellExecute -and
        (-not $clientStartInfo.RedirectStandardInput) -and
        (-not $clientStartInfo.RedirectStandardOutput) -and
        (-not $clientStartInfo.RedirectStandardError)
    Add-Result 'client relaunch uses a detached process-local RunAsInvoker fix' $clientRunsAsInvoker 'legacy embedded requireAdministrator manifest does not force a high-integrity client or inherit caller capture handles'
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $registryPath -Recurse -Force -ErrorAction SilentlyContinue
}

$scriptPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Add-Result 'credential helper parses cleanly' ($parseErrors.Count -eq 0) "$($parseErrors.Count) parser error(s)"
$parameterNames = @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath)
$noSecretArguments = ($parameterNames -notcontains 'Username') -and ($parameterNames -notcontains 'Password')
Add-Result 'credentials cannot be supplied as shell arguments' $noSecretArguments ($parameterNames -join ', ')

$emptyCloseAccepted = $true
try {
    Close-PSOBBWindowProcesses -Processes @() -Description 'test process'
} catch {
    $emptyCloseAccepted = $false
}
Add-Result 'already-closed client and launcher are accepted' $emptyCloseAccepted 'empty exact-path process set is a no-op'

$closingRace = [pscustomobject]@{ Id = 4244; ExitChecks = 0 }
$closingRace | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
$closingRace | Add-Member -MemberType ScriptProperty -Name HasExited -Value {
    $this.ExitChecks++
    $this.ExitChecks -ge 2
}
$closingRace | Add-Member -MemberType ScriptMethod -Name CloseMainWindow -Value { $false }
$closingRace | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($Milliseconds) $true }
$closeRaceAccepted = $true
try {
    Close-PSOBBWindowProcesses -Processes @($closingRace) -Description 'race fixture'
} catch {
    $closeRaceAccepted = $false
}
Add-Result 'window-close exit races are accepted' $closeRaceAccepted 'a process exiting during CloseMainWindow does not require a rerun'

if ($OfflineIntegration) {
    $integrationRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'PSOBB-AdminCredentialIntegration-' + [Guid]::NewGuid().ToString('N'))
    $integrationLayout = Get-PSOBBLayout -RuntimeRoot $integrationRoot
    $liveLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
    $oldPassword = $null
    $newPassword = $null
    try {
        New-Item -ItemType Directory -Path (Split-Path $integrationLayout.Server -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $liveLayout.ServerBase -Destination $integrationLayout.Server -Recurse
        Copy-Item -LiteralPath (Join-Path $liveLayout.Server 'system\config.json') -Destination (
            Join-Path $integrationLayout.Server 'system\config.json') -Force
        Copy-Item -LiteralPath (Join-Path $liveLayout.Server 'system\patch-bb\data') -Destination (
            Join-Path $integrationLayout.Server 'system\patch-bb') -Recurse -Force

        $ports = [System.Collections.Generic.List[int]]::new()
        while ($ports.Count -lt 3) {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            try {
                $listener.Start()
                $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
                if (-not $ports.Contains($port)) {
                    $ports.Add($port)
                }
            } finally {
                $listener.Stop()
            }
        }
        $configPath = Join-Path $integrationLayout.Server 'system\config.json'
        $config = Get-Content -Raw -LiteralPath $configPath
        $config = $config.Replace(
            '"bb-patch": [["127.0.0.1", 11000]',
            ('"bb-patch": [["127.0.0.1", {0}]' -f $ports[0]))
        $config = $config.Replace(
            '"bb-data1": [["127.0.0.1", 12000]',
            ('"bb-data1": [["127.0.0.1", {0}]' -f $ports[1]))
        $config = $config.Replace(
            '"bb-data2": [["127.0.0.1", 12001]',
            ('"bb-data2": [["127.0.0.1", {0}]' -f $ports[2]))
        [System.IO.File]::WriteAllText($configPath, $config, [System.Text.UTF8Encoding]::new($false))

        $oldUsername = 'testoldadmin'
        $newUsername = 'testnewadmin'
        $oldPassword = New-CrockfordSecret -Length 16
        $newPassword = New-CrockfordSecret -Length 1
        $licensePath = Join-Path $integrationLayout.Server 'system\licenses\0000000001.json'
        $license = @"
{
  "BBTeamID": 0x0,
  "FormatVersion": 0x1,
  "AccountID": 0x00000001,
  "LastPlayerName": "",
  "DCNTELicenses": [],
  "BBLicenses": [
    {"UserName": "$oldUsername", "Password": "$oldPassword"}
  ],
  "BanEndTime": 0x0,
  "PCLicenses": [],
  "AutoReplyMessage": "",
  "GCLicenses": [],
  "AutoPatchesEnabled": [],
  "XBLicenses": [],
  "Flags": 0x7FFFFFFF,
  "Ep3TotalMesetaEarned": 0x0,
  "Ep3CurrentMeseta": 0x0,
  "DCLicenses": [],
  "UserFlags": 0x0
}
"@
        [System.IO.File]::WriteAllText($licensePath, $license, [System.Text.UTF8Encoding]::new($false))
        $expectedListeners = @($ports | ForEach-Object { "127.0.0.1:$_" })
        Invoke-PSOBBOfflineLicenseRotation -Layout $integrationLayout -AccountId '00000001' -OldUsername $oldUsername -OldPassword $oldPassword -NewUsername $newUsername -NewPassword $newPassword -ExpectedListeners $expectedListeners
        $savedText = Get-Content -Raw -LiteralPath $licensePath
        $saved = $savedText | ConvertFrom-Json
        $canonical = [regex]::Matches(
            $savedText,
            '\{"UserName"\s*:\s*"(?<username>[^"]+)",\s*"Password"\s*:\s*"(?<password>[^"]+)"\}')
        $integrated = (@($saved.BBLicenses).Count -eq 1) -and
            ([string]$saved.BBLicenses[0].UserName -ceq $newUsername) -and
            ([string]$saved.BBLicenses[0].Password -ceq $newPassword) -and
            ([uint32]$saved.Flags -eq [uint32]0x7FFFFFFF) -and
            ($canonical.Count -eq 1)
        Add-Result 'upstream newserv rotates the root license offline' $integrated 'one-character boundary; isolated loopback ports; canonical persisted license'
    } finally {
        $oldPassword = $null
        $newPassword = $null
        if (Test-Path -LiteralPath $integrationRoot) {
            Remove-Item -LiteralPath $integrationRoot -Recurse -Force
        }
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) admin-credential test(s) failed"
}
[pscustomobject]@{ Suite = 'AdminCredentialRotation'; Passed = $results.Count; Failed = 0 }
