[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [switch]$Force,
    [ValidateRange(5, 120)][int]$ShutdownTimeoutSeconds = 30,
    [Parameter(DontShow)][switch]$ClientOperationLockHeld
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedNewservExecutable {
    $lockPath = Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
    $components = @($lock.components | Where-Object { $_.id -eq 'newserv-stable-release' })
    $members = if ($components.Count -eq 1) {
        @($components[0].members | Where-Object { $_.path -eq 'release/newserv-windows.exe' })
    } else { @() }
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
    @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    ) | ForEach-Object {
        $security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new($_, $fullControl, $allow))
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

function Remove-LifecycleFiles {
    param([Parameter(Mandatory)]$Layout)
    @(
        $Layout.PidFile,
        $Layout.LegacyPidFile,
        $Layout.HostPidFile,
        $Layout.ControlRequest,
        $Layout.ControlState
    ) | ForEach-Object {
        $safePath = Assert-PathWithinRoot -Path $_ -Root $Layout.Root
        Remove-Item -LiteralPath $safePath -Force -ErrorAction SilentlyContinue
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$clientOperationMutex = if ($ClientOperationLockHeld) {
    $null
} else {
    Enter-PSOBBClientOperationLock -Layout $layout
}
try {
Assert-PSOBBNoRunningClients -Layout $layout | Out-Null
$approved = Get-ApprovedNewservExecutable
$executable = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
    (Get-Item -LiteralPath $executable).Length -ne $approved.Size -or
    (Get-LowerSha256 $executable) -ne $approved.Sha256) {
    throw 'The runtime newserv executable does not match the approved sources.lock member'
}

$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
try {
    $ownsMutex = $mutex.WaitOne([TimeSpan]::FromSeconds(5))
    if (-not $ownsMutex) {
        throw 'Another PSOBB start or stop operation is already in progress'
    }

    $exactPathProcesses = @(Get-NewservProcessesAtPath -Layout $layout)
    $process = Get-NewservProcess -Layout $layout
    if (-not $process) {
        if ($exactPathProcesses.Count -gt 0) {
            throw 'An exact-path newserv process exists without a valid supervised process record; refusing unsafe PID action'
        }
        Remove-LifecycleFiles -Layout $layout
        return [pscustomobject]@{ Stopped = $false; Reason = 'not-running' }
    }

    if ($exactPathProcesses.Count -ne 1 -or $exactPathProcesses[0].Id -ne $process.Id) {
        throw 'The exact-path process inventory does not match the validated supervisor record'
    }
    Assert-LifecycleFileAcl -Path $layout.PidFile
    $record = Get-Content -Raw -LiteralPath $layout.PidFile | ConvertFrom-Json
    if ([string]$record.controlToken -notmatch '^[A-Za-z0-9_-]{43}$' -or
        [string]$record.executableSha256 -ne $approved.Sha256 -or
        [string]$record.executablePath -ne $executable -or
        [int]$record.pid -ne $process.Id) {
        throw 'The supervised process record is incomplete or inconsistent with the approved executable'
    }

    $hostProcess = Get-Process -Id ([int]$record.hostPid) -ErrorAction SilentlyContinue
    if (-not $hostProcess -and -not $Force) {
        throw 'The supervisor is not running, so a graceful shell exit cannot be authenticated; use -Force only after confirming clients are disconnected'
    }

    $requestSent = $false
    if ($hostProcess) {
        $request = [ordered]@{
            schemaVersion = 1
            action = 'exit'
            pid = $process.Id
            startTimeUtc = [string]$record.startTimeUtc
            controlToken = [string]$record.controlToken
            requestedAtUtc = [DateTime]::UtcNow.ToString('o')
        }
        Write-ProtectedJson -Path $layout.ControlRequest -Value $request -Root $layout.Root
        Assert-LifecycleFileAcl -Path $layout.ControlRequest
        $requestSent = $true
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($ShutdownTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 250
    }

    $forced = $false
    $process.Refresh()
    if (-not $process.HasExited) {
        if (-not $Force) {
            throw 'newserv did not stop after the authenticated shell exit request; rerun with -Force only after confirming clients are disconnected'
        }

        # Re-read through the shared identity validator immediately before the
        # only forceful operation. This catches PID reuse, path swaps, and hash
        # changes between the request and termination.
        $revalidated = Get-NewservProcess -Layout $layout
        if (-not $revalidated -or $revalidated.Id -ne $process.Id) {
            throw 'newserv identity changed before forced termination; refusing to kill a PID that was not revalidated'
        }
        Stop-Process -Id $revalidated.Id -Force
        $revalidated.WaitForExit(5000) | Out-Null
        $forced = $true
    }

    if ($hostProcess) {
        $hostProcess.WaitForExit(10000) | Out-Null
    }
    Remove-LifecycleFiles -Layout $layout
    [pscustomobject]@{
        Stopped = $true
        Pid = $process.Id
        Graceful = -not $forced
        Forced = $forced
        AuthenticatedShellExitRequested = $requestSent
    }
} finally {
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
} finally {
    if ($clientOperationMutex) {
        Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
    }
}
