[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [switch]$Background,
    [ValidateRange(5, 120)][int]$StartupTimeoutSeconds = 45
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedNewservExecutable {
    $lockPath = Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
    $components = @($lock.components | Where-Object { $_.id -eq 'newserv-stable-release' })
    if ($components.Count -ne 1) {
        throw 'sources.lock.json must contain exactly one newserv-stable-release component'
    }
    $members = @($components[0].members | Where-Object { $_.path -eq 'release/newserv-windows.exe' })
    if ($members.Count -ne 1 -or [string]$members[0].sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'sources.lock.json does not contain one valid approved newserv executable member'
    }
    [pscustomobject]@{
        Sha256 = [string]$members[0].sha256
        Size = [long]$members[0].size
    }
}

function Set-LifecycleFileAcl {
    param([Parameter(Mandatory)][string]$Path)

    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $sids = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    )
    foreach ($sid in $sids) {
        $security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new($sid, $fullControl, $allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Assert-LifecycleFileAcl {
    param([Parameter(Mandatory)][string]$Path)

    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    ) | ForEach-Object { $allowed.Add($_.Value) | Out-Null }

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Lifecycle file inherits permissions: $Path"
    }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            -not $allowed.Contains($sid)) {
            throw "Lifecycle file grants access outside the runtime identities: $Path"
        }
    }
}

function Write-ProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Root
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $temporary = $safePath + '.' + [Guid]::NewGuid().ToString('N') + '.new'
    Assert-PathWithinRoot -Path $temporary -Root $Root | Out-Null
    [System.IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false))
    try {
        Set-LifecycleFileAcl -Path $temporary
        [System.IO.File]::Move($temporary, $safePath, $true)
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-ExactLoopbackListeners {
    param([Parameter(Mandatory)][int]$ProcessId)

    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $_.OwningProcess -eq $ProcessId })
    $actual = @($listeners | ForEach-Object {
        '{0}:{1}' -f $_.LocalAddress, $_.LocalPort
    } | Sort-Object -Unique)
    $expected = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
    if ($actual.Count -ne $expected.Count) {
        return $false
    }
    -not (Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$approved = Get-ApprovedNewservExecutable
$executable = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Server executable is missing; run Initialize-PSOBB.ps1 first: $executable"
}
$executableItem = Get-Item -LiteralPath $executable
if ($executableItem.Length -ne $approved.Size -or (Get-LowerSha256 $executable) -ne $approved.Sha256) {
    throw 'The runtime newserv executable does not match the approved sources.lock member'
}

# Background is retained for command-line compatibility. Supervised operation is
# always hidden because the controller, rather than a console window, owns stdin.
$null = $Background

$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
try {
    $ownsMutex = $mutex.WaitOne(0)
    if (-not $ownsMutex) {
        throw 'Another PSOBB start or stop operation is already in progress'
    }

    $running = @(Get-NewservProcessesAtPath -Layout $layout)
    if ($running.Count -gt 0) {
        throw "The approved newserv executable is already running (PID(s): $($running.Id -join ', '))"
    }

    $lifecycleFiles = @(
        $layout.PidFile,
        $layout.LegacyPidFile,
        $layout.HostPidFile,
        $layout.ControlState,
        $layout.ControlRequest
    )
    foreach ($path in $lifecycleFiles) {
        $safePath = Assert-PathWithinRoot -Path $path -Root $layout.Root
        Remove-Item -LiteralPath $safePath -Force -ErrorAction SilentlyContinue
    }

    $tokenBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    $controlToken = [Convert]::ToBase64String($tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)

    $startupState = [ordered]@{
        schemaVersion = 1
        state = 'starting'
        installationId = [string]$marker.installationId
        executablePath = $executable
        executableSha256 = $approved.Sha256
        controlToken = $controlToken
        requestedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-ProtectedJson -Path $layout.ControlState -Value $startupState -Root $layout.Root

    $hostInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $hostInfo.FileName = Join-Path $PSHOME 'pwsh.exe'
    $hostInfo.WorkingDirectory = $script:PSOBBRepositoryRoot
    $hostInfo.UseShellExecute = $false
    $hostInfo.CreateNoWindow = $true
    $hostInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    # A long-lived supervisor must not inherit the invoking shell's capture
    # handles. Otherwise a non-interactive caller waits for EOF until the game
    # server exits even though this start operation has already completed.
    $hostInfo.RedirectStandardInput = $true
    $hostInfo.RedirectStandardOutput = $true
    $hostInfo.RedirectStandardError = $true
    @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', (Join-Path $PSScriptRoot 'Invoke-NewservSupervisor.ps1'),
        '-RuntimeRoot', $layout.Root
    ) | ForEach-Object { $hostInfo.ArgumentList.Add($_) }
    $hostProcess = [System.Diagnostics.Process]::Start($hostInfo)
    if (-not $hostProcess) {
        throw 'Failed to create the hidden newserv supervisor process'
    }
    $hostProcess.StandardInput.Close()

    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    $serverProcess = $null
    $startResult = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $hostProcess.Refresh()
        if ($hostProcess.HasExited) {
            $detail = 'The newserv supervisor exited during startup'
            if (Test-Path -LiteralPath $layout.ControlState -PathType Leaf) {
                Assert-LifecycleFileAcl -Path $layout.ControlState
                try {
                    $state = Get-Content -Raw -LiteralPath $layout.ControlState | ConvertFrom-Json
                    if (-not [string]::IsNullOrWhiteSpace([string]$state.message)) {
                        $detail += ': ' + [string]$state.message
                    }
                } catch { }
            }
            throw $detail
        }

        if (Test-Path -LiteralPath $layout.PidFile -PathType Leaf) {
            Assert-LifecycleFileAcl -Path $layout.PidFile
            $serverProcess = Get-NewservProcess -Layout $layout
            if ($serverProcess) {
                $record = Get-Content -Raw -LiteralPath $layout.PidFile | ConvertFrom-Json
                if ([int]$record.hostPid -ne $hostProcess.Id -or
                    [string]$record.executablePath -ne $executable -or
                    [string]$record.executableSha256 -ne $approved.Sha256 -or
                    [string]$record.controlToken -ne $controlToken) {
                    throw 'The supervisor process record did not match this start request'
                }
                if (Test-ExactLoopbackListeners -ProcessId $serverProcess.Id) {
                    $controlToken = $null
                    $startResult = [pscustomobject]@{
                        Pid = $serverProcess.Id
                        HostPid = $hostProcess.Id
                        Supervised = $true
                        ExecutableSha256 = $approved.Sha256
                        Listeners = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
                    }
                    break
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }

    if ($startResult) {
        Write-Output -NoEnumerate $startResult
    } else {
        if ($serverProcess -and -not $serverProcess.HasExited) {
            $request = [ordered]@{
                schemaVersion = 1
                action = 'exit'
                pid = $serverProcess.Id
                startTimeUtc = [string]$record.startTimeUtc
                controlToken = $controlToken
                requestedAtUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-ProtectedJson -Path $layout.ControlRequest -Value $request -Root $layout.Root
            $serverProcess.WaitForExit(10000) | Out-Null
        }
        throw 'newserv did not reach the exact approved loopback listener set before the startup timeout'
    }
} finally {
    $controlToken = $null
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
