[CmdletBinding()]
param()

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\Set-PSOBBPlayerCredential.ps1')
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

$acceptedUsernames = @('player', 'psoplay-123abc', 'a_1')
$rejectedUsernames = @('', 'ab', 'Player', '1player', 'player name', 'a2345678901234567', '..\player', "player`n")
Add-Result 'player username policy accepts safe values' (
    @($acceptedUsernames | Where-Object { -not (Test-PSOBBPlayerUsername $_) }).Count -eq 0) '3-16 lowercase path-safe characters'
Add-Result 'player username policy rejects unsafe values' (
    @($rejectedUsernames | Where-Object { Test-PSOBBPlayerUsername $_ }).Count -eq 0) 'case, length, token, and path traversal checks'

$acceptedPasswords = @('a', 'short', 'Abcd1234Efgh5678', '0123456789ABCDEF')
$rejectedPasswords = @('', 'Abcd1234 Efgh567', 'Abcd1234-Efgh567', 'Abcd1234Efgh56789', "Abcd1234`n")
Add-Result 'player password policy accepts 1-16 alphanumeric characters' (
    @($acceptedPasswords | Where-Object { -not (Test-PSOBBPlayerPassword $_) }).Count -eq 0) 'upstream BB length and legacy-client-safe alphabet'
Add-Result 'player password policy rejects ambiguous values' (
    @($rejectedPasswords | Where-Object { Test-PSOBBPlayerPassword $_ }).Count -eq 0) 'length range and alphabet checks'

$promptRetries = & {
    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $responses = [System.Collections.Generic.Queue[string]]::new()
    @(
        'fixtureplayer',
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
    $credential = Read-PSOBBPlayerCredential 6>$null
    try {
        ($credential.UserName -ceq 'fixtureplayer') -and
            ($credential.GetNetworkCredential().Password -ceq 'Abcd1234Efgh5678') -and
            ($responses.Count -eq 0)
    } finally {
        $credential.Password.Dispose()
    }
}
Add-Result 'new player password prompt retries safely' $promptRetries 'length and confirmation failures never enter command arguments'

$currentPromptRetries = & {
    $WarningPreference = 'SilentlyContinue'
    $responses = [System.Collections.Generic.Queue[string]]::new()
    @('-', 'Current12345678') | ForEach-Object { $responses.Enqueue($_) }
    function Read-Host {
        param([string]$Prompt, [switch]$AsSecureString)
        ConvertTo-SecureString $responses.Dequeue() -AsPlainText -Force
    }
    $secure = Read-PSOBBCurrentPlayerPassword
    try {
        (ConvertFrom-PSOBBSecureString $secure) -ceq 'Current12345678' -and
            $responses.Count -eq 0
    } finally {
        $secure.Dispose()
    }
}
Add-Result 'manual current-password fallback retries safely' $currentPromptRetries 'supports later rotation without persistent DPAPI storage'

$scriptPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBPlayerCredential.ps1'
$scriptText = Get-Content -Raw -LiteralPath $scriptPath
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$parseErrors)
Add-Result 'player credential helper parses cleanly' ($parseErrors.Count -eq 0) "$($parseErrors.Count) parser error(s)"
$parameterNames = @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath)
Add-Result 'player secrets cannot be supplied as shell arguments' (
    ($parameterNames -notcontains 'Username') -and
    ($parameterNames -notcontains 'Password') -and
    ($parameterNames -notcontains 'CurrentPassword')) ($parameterNames -join ', ')
Add-Result 'player helper does not persist or export the new password' (
    $scriptText -notmatch '(?i)Export-Clixml|Set-Clipboard|list-accounts') 'new password exists only in memory and the required newserv license'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-PlayerCredentialTests-' + [Guid]::NewGuid().ToString('N'))
try {
    $layout = Get-PSOBBLayout -RuntimeRoot (Join-Path $temporaryRoot 'runtime')
    $licenseDirectory = Join-Path $layout.Server 'system\licenses'
    foreach ($directory in @(
        $licenseDirectory,
        (Join-Path $layout.Server 'system\players'),
        $layout.Secrets,
        $layout.Backups)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        Set-PSOBBProtectedAcl -Path $directory
    }

    $accountNumber = [uint32]2
    $accountId = $accountNumber.ToString('X8')
    $username = 'fixtureplayer'
    $password = 'Player123456789'
    $licensePath = Join-Path $licenseDirectory ($accountNumber.ToString('D10') + '.json')
    $credentialPath = Join-Path $layout.Secrets 'player.credential.clixml'
    $metadataPath = Join-Path $layout.Secrets 'player.account.json'
    $stateBackupPath = Join-Path $layout.Backups 'state-fixture'
    New-Item -ItemType Directory -Path $stateBackupPath | Out-Null
    Set-PSOBBProtectedAcl -Path $stateBackupPath

    $license = [ordered]@{
        AccountID = $accountNumber
        BBLicenses = @([ordered]@{ UserName = $username; Password = $password })
        Flags = 0
    }
    [System.IO.File]::WriteAllText(
        $licensePath,
        ($license | ConvertTo-Json -Depth 4),
        [System.Text.UTF8Encoding]::new($false))
    [pscredential]::new(
        $username,
        (ConvertTo-SecureString $password -AsPlainText -Force)) |
        Export-Clixml -LiteralPath $credentialPath
    [System.IO.File]::WriteAllText(
        $metadataPath,
        ([ordered]@{
            role = 'Player'
            username = $username
            accountId = $accountId
            provisionedAtUtc = [DateTime]::UtcNow.ToString('o')
        } | ConvertTo-Json),
        [System.Text.UTF8Encoding]::new($false))
    foreach ($path in @($licensePath, $credentialPath, $metadataPath)) {
        Set-PSOBBProtectedAcl -Path $path
    }

    $state = Get-PSOBBPlayerState -Layout $layout
    Add-Result 'exact no-flags player account resolves from protected metadata' (
        ($state.AccountId -ceq $accountId) -and
        ($state.Username -ceq $username) -and
        $state.HadCredential -and
        (Test-PSOBBPlayerLicensePassword -PlayerState $state -Password $password)) 'one account ID, one username, one BB license, Flags=0'
    $state.Credential.Password.Dispose()

    $rootRejected = $false
    $license.Flags = 0x7FFFFFFF
    [System.IO.File]::WriteAllText($licensePath, ($license | ConvertTo-Json -Depth 4))
    Set-PSOBBProtectedAcl -Path $licensePath
    try {
        Get-PSOBBPlayerState -Layout $layout | Out-Null
    } catch {
        $rootRejected = $_.Exception.Message -match 'no-flags'
    }
    Add-Result 'root or administrator flags are rejected' $rootRejected 'authorization-negative target can never carry privileges'
    $license.Flags = 0
    [System.IO.File]::WriteAllText($licensePath, ($license | ConvertTo-Json -Depth 4))
    Set-PSOBBProtectedAcl -Path $licensePath

    $duplicatePath = Join-Path $licenseDirectory '0000000003.json'
    $duplicate = [ordered]@{
        AccountID = 3
        BBLicenses = @([ordered]@{ UserName = $username; Password = 'Different123456' })
        Flags = 0
    }
    [System.IO.File]::WriteAllText($duplicatePath, ($duplicate | ConvertTo-Json -Depth 4))
    Set-PSOBBProtectedAcl -Path $duplicatePath
    $ambiguityRejected = $false
    try {
        Get-PSOBBPlayerState -Layout $layout | Out-Null
    } catch {
        $ambiguityRejected = $_.Exception.Message -match 'ambiguous'
    }
    Add-Result 'duplicate persisted player usernames are rejected' $ambiguityRejected 'no ambiguous account selection'
    Remove-Item -LiteralPath $duplicatePath -Force

    $state = Get-PSOBBPlayerState -Layout $layout
    $originalHashes = [ordered]@{
        License = Get-LowerSha256 $state.LicensePath
        Credential = Get-LowerSha256 $state.CredentialPath
        Metadata = Get-LowerSha256 $state.MetadataPath
    }
    $rotationBackup = New-PSOBBPlayerCredentialRotationBackup `
        -Layout $layout `
        -PlayerState $state `
        -StateBackupPath $stateBackupPath
    $state.Credential.Password.Dispose()
    [System.IO.File]::WriteAllText($licensePath, 'mutated')
    [System.IO.File]::WriteAllText($metadataPath, 'mutated')
    Remove-Item -LiteralPath $credentialPath -Force
    Restore-PSOBBPlayerCredentialRotationBackup `
        -Layout $layout `
        -PlayerState $state `
        -RotationBackup $rotationBackup
    $rollbackExact =
        ((Get-LowerSha256 $licensePath) -eq $originalHashes.License) -and
        ((Get-LowerSha256 $credentialPath) -eq $originalHashes.Credential) -and
        ((Get-LowerSha256 $metadataPath) -eq $originalHashes.Metadata) -and
        (Test-PSOBBProtectedAcl -Path $licensePath) -and
        (Test-PSOBBProtectedAcl -Path $credentialPath) -and
        (Test-PSOBBProtectedAcl -Path $metadataPath) -and
        ((Get-Content -Raw -LiteralPath $rotationBackup.ManifestPath | ConvertFrom-Json).status -eq 'rolled-back')
    Add-Result 'protected player backup rolls back all original files exactly' $rollbackExact $rotationBackup.Path

    $state = Get-PSOBBPlayerState -Layout $layout
    Set-PSOBBPlayerManualSecretState -Layout $layout -PlayerState $state -Username $username
    $state.Credential.Password.Dispose()
    $manualState = Get-PSOBBPlayerState -Layout $layout
    Add-Result 'successful rotation state retires the live DPAPI password' (
        -not $manualState.HadCredential -and
        -not (Test-Path -LiteralPath $credentialPath) -and
        ([string]$manualState.Metadata.credentialStorage -ceq 'manual-only')) 'new password is not persisted outside the required license JSON'

    $manualBackup = New-PSOBBPlayerCredentialRotationBackup `
        -Layout $layout `
        -PlayerState $manualState `
        -StateBackupPath $stateBackupPath
    [System.IO.File]::WriteAllText($licensePath, 'mutated-again')
    [System.IO.File]::WriteAllText($metadataPath, 'mutated-again')
    Restore-PSOBBPlayerCredentialRotationBackup `
        -Layout $layout `
        -PlayerState $manualState `
        -RotationBackup $manualBackup
    $manualRollbackState = Get-PSOBBPlayerState -Layout $layout
    Add-Result 'later manual-only rotations retain rollback coverage' (
        -not $manualBackup.HadCredential -and
        -not $manualRollbackState.HadCredential -and
        -not (Test-Path -LiteralPath $credentialPath) -and
        ((Get-Content -Raw -LiteralPath $manualBackup.ManifestPath | ConvertFrom-Json).status -eq 'rolled-back')) 'backup manifest records that no DPAPI credential existed'
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) player-credential test(s) failed"
}
[pscustomobject]@{ Suite = 'PlayerCredentialRotation'; Passed = $results.Count; Failed = 0 }
