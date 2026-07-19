[CmdletBinding()]
param(
    [string]$BackupPath,
    [string]$RuntimeRoot,
    [ValidateRange(1, 20)][int]$ResultRetention = 5
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedServerExecutableHash {
    $lockPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config\sources.lock.json'
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
    $component = @($lock.components | Where-Object id -eq 'newserv-stable-release')
    $member = if ($component.Count -eq 1) {
        @($component[0].members | Where-Object path -eq 'release/newserv-windows.exe')
    } else {
        @()
    }
    if (($member.Count -ne 1) -or ([string]$member[0].sha256 -notmatch '^[0-9a-f]{64}$')) {
        throw 'Source lock has no valid approved newserv-windows.exe member'
    }
    ([string]$member[0].sha256).ToLowerInvariant()
}

function Get-RunningServerProcesses([Parameter(Mandatory)]$Layout) {
    $expected = [System.IO.Path]::GetFullPath((Join-Path $Layout.Server 'newserv-windows.exe'))
    $matches = [System.Collections.Generic.List[object]]::new()
    if (Get-Command -Name Get-NewservProcessesAtPath -ErrorAction SilentlyContinue) {
        try {
            foreach ($process in @(Get-NewservProcessesAtPath -Layout $Layout)) {
                if ($process) { $matches.Add($process) }
            }
            return @($matches)
        } catch {
            # Fall through to an independent exact executable-path check.
        }
    }
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name = 'newserv-windows.exe'" -ErrorAction Stop)) {
        if ($process.ExecutablePath -and
            [System.IO.Path]::GetFullPath($process.ExecutablePath).Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            $matches.Add($process)
        }
    }
    @($matches)
}

function Test-IsStatePath([string]$RelativePath) {
    ($RelativePath -eq 'system/config.json') -or
    ($RelativePath -in @('system/licenses', 'system/players', 'system/teams')) -or
    ($RelativePath -match '^system/(licenses|players|teams)/')
}

function Remove-DrillPayloads(
    [Parameter(Mandatory)]$Layout,
    [int]$Retention,
    [Parameter(Mandatory)][string]$CurrentDrillRoot
) {
    $drills = @(Get-ChildItem -LiteralPath $Layout.Backups -Directory -Filter 'restore-drill-*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending)
    foreach ($drill in $drills) {
        Assert-PathWithinRoot -Path $drill.FullName -Root $Layout.Backups | Out-Null
        foreach ($item in @(Get-ChildItem -Force -LiteralPath $drill.FullName -ErrorAction SilentlyContinue |
            Where-Object Name -ne 'drill-result.json')) {
            Assert-PathWithinRoot -Path $item.FullName -Root $drill.FullName | Out-Null
            Remove-Item -LiteralPath $item.FullName -Recurse -Force
        }
        if (-not $drill.FullName.Equals($CurrentDrillRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not (Test-Path -LiteralPath (Join-Path $drill.FullName 'drill-result.json') -PathType Leaf)) {
            Remove-Item -LiteralPath $drill.FullName -Force
        }
    }
    $retainedDrills = @(Get-ChildItem -LiteralPath $Layout.Backups -Directory -Filter 'restore-drill-*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending)
    foreach ($expired in @($retainedDrills | Select-Object -Skip $Retention)) {
        Assert-PathWithinRoot -Path $expired.FullName -Root $Layout.Backups | Out-Null
        Remove-Item -LiteralPath $expired.FullName -Recurse -Force
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if (-not (Test-Path -LiteralPath $layout.Backups -PathType Container)) {
    New-Item -ItemType Directory -Path $layout.Backups -Force | Out-Null
}
Assert-PathWithinRoot -Path $layout.Backups -Root $layout.Root | Out-Null
Set-PSOBBProtectedAcl -Path $layout.Backups
$drillRoot = Join-Path $layout.Backups ('restore-drill-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
$workRoot = Join-Path $drillRoot '.work'
$drillServer = Join-Path $workRoot 'server\release'
$resultPath = Join-Path $drillRoot 'drill-result.json'
Assert-PathWithinRoot -Path $drillRoot -Root $layout.Backups | Out-Null
New-Item -ItemType Directory -Path $drillRoot | Out-Null
Set-PSOBBProtectedAcl -Path $drillRoot

$result = [ordered]@{
    schemaVersion = 3
    startedAtUtc = [DateTime]::UtcNow.ToString('o')
    completedAtUtc = $null
    backup = $null
    backupManifestSha256 = $null
    approvedServerExecutableSha256 = $null
    serverExecutableSha256 = $null
    serverScaffoldFilesVerified = 0
    clientPatchProfile = $null
    clientPatchPolicySha256 = $null
    clientPatchConfigSha256 = $null
    installationRecordSha256 = $null
    expectedAccounts = 2
    accountsIndexed = 0
    listeners = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
    passed = $false
    failureType = $null
    failure = $null
}
$process = $null
$credentials = @{}
$passwords = @()
$failureRecord = $null

try {
    $result.approvedServerExecutableSha256 = Get-ApprovedServerExecutableHash
    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $latest = Get-ChildItem -LiteralPath $layout.Backups -Directory -Filter 'state-*' -ErrorAction SilentlyContinue |
            Where-Object Name -NotMatch '\.partial-' |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if (-not $latest) {
            throw 'No state backup exists for the restore drill'
        }
        $BackupPath = $latest.FullName
    }

    # Record the exact attempted input before semantic validation, so failed as
    # well as successful drills remain bound to their manifest bytes.
    $attemptedBackup = (Resolve-Path -LiteralPath $BackupPath).Path
    Assert-PathWithinRoot -Path $attemptedBackup -Root $layout.Backups | Out-Null
    $result.backup = Split-Path -Leaf $attemptedBackup
    $attemptedManifest = Join-Path $attemptedBackup 'manifest.json'
    if (Test-Path -LiteralPath $attemptedManifest -PathType Leaf) {
        $result.backupManifestSha256 = Get-LowerSha256 $attemptedManifest
    }

    if (@(Get-RunningServerProcesses -Layout $layout).Count -gt 0) {
        throw 'Stop the exact stable newserv process before a restore drill'
    }
    $occupied = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object LocalPort -in @(11000, 12000, 12001))
    if ($occupied.Count -gt 0) {
        throw 'A required restore-drill loopback port is already in use'
    }

    $validation = & (Join-Path $PSScriptRoot 'Restore-PSOBB.ps1') `
        -BackupPath $BackupPath -RuntimeRoot $layout.Root -ValidateOnly
    $resolvedBackup = $validation.BackupPath
    if (($result.backupManifestSha256 -cne $validation.ManifestSha256) -or
        ($result.approvedServerExecutableSha256 -cne $validation.ApprovedServerExecutableSha256)) {
        throw 'Restore validation returned evidence that differs from the attempted-input binding'
    }
    $result.clientPatchProfile = $validation.ClientPatchProfile
    $result.clientPatchPolicySha256 = $validation.ClientPatchPolicySha256
    $result.clientPatchConfigSha256 = [string]$validation.Manifest.clientPatchState.configSha256
    $result.installationRecordSha256 = [string]$validation.Manifest.clientPatchState.installationSha256

    New-Item -ItemType Directory -Path $drillServer -Force | Out-Null

    # Build an ephemeral server scaffold. Every copied file is hashed before copy
    # and verified after copy; live state is excluded and replaced only from the
    # already validated schema-v3 backup entries below.
    $allSourceItems = @(Get-ChildItem -Force -LiteralPath $layout.Server -Recurse)
    foreach ($sourceItem in $allSourceItems) {
        if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Stable server scaffold contains a reparse point: $($sourceItem.FullName)"
        }
    }
    foreach ($sourceDirectory in @($allSourceItems | Where-Object PSIsContainer | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($layout.Server, $sourceDirectory.FullName).Replace('\', '/')
        if (-not (Test-IsStatePath $relative)) {
            $destination = Assert-PathWithinRoot -Path (Join-Path $drillServer ($relative.Replace('/', '\'))) -Root $workRoot
            New-Item -ItemType Directory -Path $destination -Force | Out-Null
        }
    }
    foreach ($sourceFile in @($allSourceItems | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($layout.Server, $sourceFile.FullName).Replace('\', '/')
        if (Test-IsStatePath $relative) {
            continue
        }
        $sourceHash = Get-LowerSha256 $sourceFile.FullName
        $destination = Assert-PathWithinRoot -Path (Join-Path $drillServer ($relative.Replace('/', '\'))) -Root $workRoot
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $sourceFile.FullName -Destination $destination
        if (((Get-Item -LiteralPath $destination).Length -ne $sourceFile.Length) -or
            ((Get-LowerSha256 $destination) -ne $sourceHash)) {
            throw "Restore-drill server scaffold copy verification failed: $relative"
        }
        $result.serverScaffoldFilesVerified++
    }

    foreach ($name in @('licenses', 'players', 'teams')) {
        New-Item -ItemType Directory -Path (Join-Path $drillServer ('system\' + $name)) -Force | Out-Null
    }
    foreach ($entry in @($validation.Manifest.files)) {
        $source = Assert-PathWithinRoot -Path (Join-Path $resolvedBackup (([string]$entry.path).Replace('/', '\'))) -Root $resolvedBackup
        $destinationRoot = if ([string]$entry.path -eq 'stable/installation.json') {
            $workRoot
        } else {
            $drillServer
        }
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $destinationRoot (([string]$entry.path).Replace('/', '\'))) `
            -Root $workRoot
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
        if (((Get-Item -LiteralPath $destination).Length -ne [long]$entry.size) -or
            ((Get-LowerSha256 $destination) -cne [string]$entry.sha256)) {
            throw "Restore-drill backup copy verification failed: $($entry.path)"
        }
    }

    $drillPatchState = Assert-PSOBBClientPatchStateCoherent `
        -ConfigPath (Join-Path $drillServer 'system\config.json') `
        -InstallRecordPath (Join-Path $workRoot 'stable\installation.json') `
        -InstallationId ([string]$validation.Manifest.clientPatchState.installationId)
    if (($drillPatchState.Profile -cne $result.clientPatchProfile) -or
        ($drillPatchState.PolicySha256 -cne $result.clientPatchPolicySha256) -or
        ($drillPatchState.ConfigSha256 -cne $result.clientPatchConfigSha256) -or
        ($drillPatchState.InstallationSha256 -cne $result.installationRecordSha256)) {
        throw 'Restore-drill client-patch state differs from its validated backup manifest'
    }

    $drillExecutable = Join-Path $drillServer 'newserv-windows.exe'
    $result.serverExecutableSha256 = Get-LowerSha256 $drillExecutable
    if ($result.serverExecutableSha256 -cne $result.approvedServerExecutableSha256) {
        throw 'Restore-drill server executable does not match the approved source-lock hash'
    }

    foreach ($role in @('admin', 'player')) {
        $path = Join-Path $layout.Secrets ($role + '.credential.clixml')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Restore drill credential is missing for role: $role"
        }
        $credentials[$role] = Import-Clixml -LiteralPath $path
    }
    $expectedUserNames = @{
        admin = [string]$credentials.admin.UserName
        player = [string]$credentials.player.UserName
    }
    $passwords = @(
        $credentials.admin.GetNetworkCredential().Password,
        $credentials.player.GetNetworkCredential().Password
    )
    # A restore drill may intentionally use a backup from before a password
    # rotation. Redact every verified BB license password in that backup, not
    # only the two current DPAPI-held credentials.
    $restoredUserNameCounts = [System.Collections.Generic.Dictionary[string, int]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($licenseEntry in @($validation.Manifest.files | Where-Object path -match '^system/licenses/')) {
        $licensePath = Join-Path $resolvedBackup (([string]$licenseEntry.path).Replace('/', '\'))
        $licenseText = Get-Content -Raw -LiteralPath $licensePath
        $licenseData = $licenseText | ConvertFrom-Json -Depth 20
        foreach ($bbLicense in @($licenseData.BBLicenses)) {
            $userName = [string]$bbLicense.UserName
            if ([string]::IsNullOrWhiteSpace($userName)) {
                throw "Restored BB license has no username: $($licenseEntry.path)"
            }
            if ($restoredUserNameCounts.ContainsKey($userName)) {
                $restoredUserNameCounts[$userName]++
            } else {
                $restoredUserNameCounts.Add($userName, 1)
            }
        }
        foreach ($match in [regex]::Matches($licenseText, '"Password"\s*:\s*"([^"]*)"')) {
            $passwords += $match.Groups[1].Value
        }
    }
    $passwords = @($passwords | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique)
    foreach ($role in @('admin', 'player')) {
        $expectedUserName = [string]$expectedUserNames[$role]
        if (-not $restoredUserNameCounts.ContainsKey($expectedUserName) -or
            $restoredUserNameCounts[$expectedUserName] -ne 1) {
            throw "Restored license files do not index exactly one expected $role BB username"
        }
        $result.accountsIndexed++
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $drillExecutable
    $startInfo.WorkingDirectory = $drillServer
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Restored newserv process did not start'
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
        $observedEndpoints = @($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" } | Sort-Object -Unique)
        if ((@(Compare-Object @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001') $observedEndpoints)).Count -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        throw 'Restored server did not reach its exact loopback listener state'
    }

    $process.StandardInput.WriteLine('exit')
    $process.StandardInput.Flush()
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(30000)) {
        throw 'Restored server did not exit after verification'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    foreach ($password in $passwords) {
        if (-not [string]::IsNullOrEmpty($password)) {
            $stdout = $stdout.Replace($password, '[REDACTED]')
            $stderr = $stderr.Replace($password, '[REDACTED]')
        }
    }
    if (($process.ExitCode -ne 0) -or (($stdout + $stderr) -match '(?m)^FAILED:')) {
        throw 'Restored server reported a startup failure'
    }
    $result.passed = $true
} catch {
    $failureRecord = $_
    $result.failureType = $_.Exception.GetType().FullName
    $result.failure = $_.Exception.Message
} finally {
    if ($process -and -not $process.HasExited) {
        try {
            $process.Kill($true)
            $process.WaitForExit()
        } catch {
            if (-not $failureRecord) {
                $failureRecord = $_
                $result.failureType = $_.Exception.GetType().FullName
                $result.failure = 'Restore-drill process cleanup failed'
            }
            $result.passed = $false
        }
    }
    foreach ($password in $passwords) {
        if (-not [string]::IsNullOrEmpty($password) -and $result.failure) {
            $result.failure = $result.failure.Replace($password, '[REDACTED]')
        }
    }
    $passwords = @()
    $credentials = @{}
    if (Test-Path -LiteralPath $workRoot) {
        try {
            Remove-Item -LiteralPath $workRoot -Recurse -Force
        } catch {
            if (-not $failureRecord) {
                $failureRecord = $_
                $result.failureType = $_.Exception.GetType().FullName
                $result.failure = 'Restore-drill work-tree cleanup failed'
            }
            $result.passed = $false
        }
    }
}

$result.completedAtUtc = [DateTime]::UtcNow.ToString('o')
try {
    Remove-DrillPayloads -Layout $layout -Retention $ResultRetention -CurrentDrillRoot $drillRoot
} catch {
    if (-not $failureRecord) {
        $failureRecord = $_
        $result.failureType = $_.Exception.GetType().FullName
        $result.failure = 'Historical restore-drill cleanup failed'
    }
    $result.passed = $false
}
[System.IO.File]::WriteAllText(
    $resultPath,
    ($result | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false))
Set-PSOBBProtectedAcl -Path $resultPath

if ($failureRecord) {
    throw $failureRecord
}
[pscustomobject]@{
    Passed = $true
    Backup = $result.backup
    BackupManifestSha256 = $result.backupManifestSha256
    ApprovedServerExecutableSha256 = $result.approvedServerExecutableSha256
    ClientPatchProfile = $result.clientPatchProfile
    ClientPatchPolicySha256 = $result.clientPatchPolicySha256
    DrillRoot = $drillRoot
    AccountsIndexed = $result.accountsIndexed
    Listeners = $result.listeners -join ', '
}
