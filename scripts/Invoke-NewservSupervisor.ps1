[CmdletBinding()]
param([Parameter(Mandatory)][string]$RuntimeRoot)

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

function Test-FixedTimeToken {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual
    )
    $expectedBytes = [System.Text.Encoding]::UTF8.GetBytes($Expected)
    $actualBytes = [System.Text.Encoding]::UTF8.GetBytes($Actual)
    try {
        if ($expectedBytes.Length -ne $actualBytes.Length) {
            return $false
        }
        [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
            $expectedBytes, $actualBytes)
    } finally {
        [Array]::Clear($expectedBytes, 0, $expectedBytes.Length)
        [Array]::Clear($actualBytes, 0, $actualBytes.Length)
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$child = $null
$stdoutStream = $null
$stderrStream = $null
$stdoutPump = $null
$stderrPump = $null
$controlToken = $null
$gracefulRequested = $false

try {
    $marker = Assert-PSOBBRuntimeMarker -Layout $layout
    $approved = Get-ApprovedNewservExecutable
    $executable = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
        (Get-Item -LiteralPath $executable).Length -ne $approved.Size -or
        (Get-LowerSha256 $executable) -ne $approved.Sha256) {
        throw 'The runtime newserv executable does not match the approved sources.lock member'
    }
    if (@(Get-NewservProcessesAtPath -Layout $layout).Count -gt 0) {
        throw 'An exact-path newserv process already exists'
    }
    if (-not (Test-Path -LiteralPath $layout.ControlState -PathType Leaf)) {
        throw 'The protected supervisor startup state is missing'
    }
    Assert-LifecycleFileAcl -Path $layout.ControlState
    $startup = Get-Content -Raw -LiteralPath $layout.ControlState | ConvertFrom-Json
    if ($startup.schemaVersion -ne 1 -or $startup.state -ne 'starting' -or
        [string]$startup.installationId -ne [string]$marker.installationId -or
        [string]$startup.executablePath -ne $executable -or
        [string]$startup.executableSha256 -ne $approved.Sha256 -or
        [string]$startup.controlToken -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'The protected supervisor startup state is invalid'
    }
    $controlToken = [string]$startup.controlToken

    New-Item -ItemType Directory -Path $layout.Logs -Force | Out-Null
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfff')
    $stdoutPath = Assert-PathWithinRoot -Path (Join-Path $layout.Logs "newserv-$stamp.stdout.log") -Root $layout.Root
    $stderrPath = Assert-PathWithinRoot -Path (Join-Path $layout.Logs "newserv-$stamp.stderr.log") -Root $layout.Root
    $stdoutStream = [System.IO.FileStream]::new(
        $stdoutPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    $stderrStream = [System.IO.FileStream]::new(
        $stderrPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    Set-LifecycleFileAcl -Path $stdoutPath
    Set-LifecycleFileAcl -Path $stderrPath

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executable
    $startInfo.WorkingDirectory = $layout.Server
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $child = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $child) {
        throw 'Failed to create the newserv process'
    }
    $stdoutPump = $child.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
    $stderrPump = $child.StandardError.BaseStream.CopyToAsync($stderrStream)
    $childStartUtc = $child.StartTime.ToUniversalTime()
    $hostStartUtc = (Get-Process -Id $PID).StartTime.ToUniversalTime()
    # ConvertFrom-Json treats round-trip ISO timestamps as DateTime values in
    # current PowerShell, then stringifies them in local time. RFC1123 remains
    # a string and is still unambiguously parseable by Get-NewservProcess.
    $childStartRecord = $childStartUtc.ToString(
        'r', [System.Globalization.CultureInfo]::InvariantCulture)
    $hostStartRecord = $hostStartUtc.ToString(
        'r', [System.Globalization.CultureInfo]::InvariantCulture)

    $record = [ordered]@{
        schemaVersion = 1
        pid = $child.Id
        executablePath = $executable
        executableSha256 = $approved.Sha256
        startTimeUtc = $childStartRecord
        hostPid = $PID
        hostStartTimeUtc = $hostStartRecord
        controlToken = $controlToken
        controlProtocol = 'protected-filesystem-exit-v1'
        stdoutLog = $stdoutPath
        stderrLog = $stderrPath
    }
    Write-ProtectedJson -Path $layout.PidFile -Value $record -Root $layout.Root
    [System.IO.File]::WriteAllText($layout.HostPidFile, $PID.ToString(), [System.Text.Encoding]::ASCII)
    Set-LifecycleFileAcl -Path $layout.HostPidFile

    $readyState = [ordered]@{
        schemaVersion = 1
        state = 'child-started'
        installationId = [string]$marker.installationId
        pid = $child.Id
        hostPid = $PID
        startTimeUtc = $childStartUtc.ToString('o')
        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-ProtectedJson -Path $layout.ControlState -Value $readyState -Root $layout.Root

    while (-not $child.HasExited) {
        if (Test-Path -LiteralPath $layout.ControlRequest -PathType Leaf) {
            try {
                Assert-LifecycleFileAcl -Path $layout.ControlRequest
                $request = Get-Content -Raw -LiteralPath $layout.ControlRequest | ConvertFrom-Json
                $requestStartUtc = if ($request.startTimeUtc -is [DateTime]) {
                    ([DateTime]$request.startTimeUtc).ToUniversalTime()
                } else {
                    [DateTimeOffset]::Parse(
                        [string]$request.startTimeUtc,
                        [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
                }
                $validRequest = $request.schemaVersion -eq 1 -and
                    $request.action -eq 'exit' -and
                    [int]$request.pid -eq $child.Id -and
                    [Math]::Abs(($requestStartUtc - $childStartUtc).TotalSeconds) -le 2 -and
                    (Test-FixedTimeToken -Expected $controlToken -Actual ([string]$request.controlToken))
                if ($validRequest -and -not $gracefulRequested) {
                    $child.StandardInput.WriteLine('exit')
                    $child.StandardInput.Flush()
                    $gracefulRequested = $true
                    $stoppingState = [ordered]@{
                        schemaVersion = 1
                        state = 'shell-exit-requested'
                        installationId = [string]$marker.installationId
                        pid = $child.Id
                        hostPid = $PID
                        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
                    }
                    Write-ProtectedJson -Path $layout.ControlState -Value $stoppingState -Root $layout.Root
                }
            } catch {
                # Malformed, incorrectly permissioned, or unauthenticated files
                # are rejected without forwarding any input to newserv.
            } finally {
                Remove-Item -LiteralPath $layout.ControlRequest -Force -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Milliseconds 200
        $child.Refresh()
    }

    $stdoutPump.GetAwaiter().GetResult()
    $stderrPump.GetAwaiter().GetResult()
    $stoppedState = [ordered]@{
        schemaVersion = 1
        state = if ($gracefulRequested) { 'stopped' } else { 'exited' }
        installationId = [string]$marker.installationId
        pid = $child.Id
        exitCode = $child.ExitCode
        gracefulShellExitRequested = $gracefulRequested
        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-ProtectedJson -Path $layout.ControlState -Value $stoppedState -Root $layout.Root
} catch {
    try {
        if ($child -and -not $child.HasExited) {
            $child.StandardInput.WriteLine('exit')
            $child.StandardInput.Flush()
            $child.WaitForExit(10000) | Out-Null
        }
        $failureState = [ordered]@{
            schemaVersion = 1
            state = 'failed'
            message = $_.Exception.Message
            updatedAtUtc = [DateTime]::UtcNow.ToString('o')
        }
        Write-ProtectedJson -Path $layout.ControlState -Value $failureState -Root $layout.Root
    } catch { }
    exit 1
} finally {
    $controlToken = $null
    if ($stdoutStream) { $stdoutStream.Dispose() }
    if ($stderrStream) { $stderrStream.Dispose() }
    if (-not $child -or $child.HasExited) {
        @($layout.PidFile, $layout.LegacyPidFile, $layout.HostPidFile, $layout.ControlRequest) |
            ForEach-Object {
                $safePath = Assert-PathWithinRoot -Path $_ -Root $layout.Root
                Remove-Item -LiteralPath $safePath -Force -ErrorAction SilentlyContinue
            }
    }
    if ($child) { $child.Dispose() }
}
