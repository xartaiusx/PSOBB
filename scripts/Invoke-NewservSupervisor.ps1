[CmdletBinding()]
param([Parameter(Mandatory)][string]$RuntimeRoot)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')

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
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Set-PSOBBLifecyclePathAcl -Path $Path -Root $Root | Out-Null
}

function Assert-LifecycleFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Assert-PSOBBLifecyclePathAcl `
        -Path $Path -Root $Root -IsContainer $false | Out-Null
}

function Write-ProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Root
    )
    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $temporary = $safePath + '.' + [Guid]::NewGuid().ToString('N') + '.new'
    $jsonBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 6))
    $temporaryStream = $null
    try {
        $temporaryStream = [System.IO.FileStream]::new(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        $temporaryStream.Write($jsonBytes, 0, $jsonBytes.Length)
        $temporaryStream.Flush($true)
        $temporaryStream.Dispose()
        $temporaryStream = $null
        Set-LifecycleFileAcl -Path $temporary -Root $Root
        [System.IO.File]::Move($temporary, $safePath, $true)
    } finally {
        if ($temporaryStream) { $temporaryStream.Dispose() }
        [Array]::Clear($jsonBytes, 0, $jsonBytes.Length)
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

function Move-NewservControlRequestToClaim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlRequestPath,
        [Parameter(Mandatory)][string]$Root
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safeRequestPath = [System.IO.Path]::GetFullPath($ControlRequestPath)
    $controlDirectory = [System.IO.Path]::GetDirectoryName($safeRequestPath)
    Assert-PSOBBLifecyclePathAcl `
        -Path $controlDirectory -Root $safeRoot -IsContainer $true | Out-Null
    $expectedRequestPath = [System.IO.Path]::GetFullPath(
        (Join-Path $controlDirectory 'newserv-control.request.json'))
    if (-not $safeRequestPath.Equals(
            $expectedRequestPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The fixed newserv control-request path is invalid'
    }
    $claimedPath = Assert-PathWithinRoot `
        -Path (Join-Path $controlDirectory (
            'newserv-control.in-progress.' + [Guid]::NewGuid().ToString('N') + '.json')) `
        -Root $safeRoot
    [System.IO.File]::Move($safeRequestPath, $claimedPath)
    $claimedPath
}

if ($MyInvocation.InvocationName -eq '.') {
    return
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
    Assert-PSOBBLifecyclePathAcl `
        -Path $layout.ControlDirectory -Root $layout.Root -IsContainer $true | Out-Null
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
    Assert-LifecycleFileAcl -Path $layout.ControlState -Root $layout.Root
    $startup = Get-Content -Raw -LiteralPath $layout.ControlState | ConvertFrom-Json
    if ($startup.schemaVersion -ne 1 -or $startup.state -ne 'starting' -or
        [string]$startup.installationId -ne [string]$marker.installationId -or
        [string]$startup.executablePath -ne $executable -or
        [string]$startup.executableSha256 -ne $approved.Sha256 -or
        [string]$startup.startupRequestId -notmatch '^[0-9a-f]{32}$' -or
        [string]$startup.controlToken -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'The protected supervisor startup state is invalid'
    }
    $controlToken = [string]$startup.controlToken
    $startupRequestId = [string]$startup.startupRequestId

    $hostProcess = Get-Process -Id $PID -ErrorAction Stop
    try {
        $hostExecutablePath = [System.IO.Path]::GetFullPath($hostProcess.Path)
        $expectedHostExecutablePath = [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
        $hostStartUtc = $hostProcess.StartTime.ToUniversalTime()
        $hostStartTimeFileTimeUtc = $hostStartUtc.ToFileTimeUtc()
        if (-not $hostExecutablePath.Equals(
                $expectedHostExecutablePath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The supervisor host executable identity is invalid'
        }
    } finally {
        $hostProcess.Dispose()
    }

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
    Set-LifecycleFileAcl -Path $stdoutPath -Root $layout.Root
    Set-LifecycleFileAcl -Path $stderrPath -Root $layout.Root

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
        hostStartTimeFileTimeUtc = [long]$hostStartTimeFileTimeUtc
        hostExecutablePath = $hostExecutablePath
        startupRequestId = $startupRequestId
        controlToken = $controlToken
        controlProtocol = 'protected-filesystem-exit-v1'
        stdoutLog = $stdoutPath
        stderrLog = $stderrPath
    }
    Write-ProtectedJson -Path $layout.PidFile -Value $record -Root $layout.Root
    $hostPidBytes = [System.Text.Encoding]::ASCII.GetBytes($PID.ToString())
    $hostPidStream = $null
    try {
        $hostPidStream = [System.IO.FileStream]::new(
            $layout.HostPidFile,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        $hostPidStream.Write($hostPidBytes, 0, $hostPidBytes.Length)
        $hostPidStream.Flush($true)
    } finally {
        if ($hostPidStream) { $hostPidStream.Dispose() }
        [Array]::Clear($hostPidBytes, 0, $hostPidBytes.Length)
    }
    Set-LifecycleFileAcl -Path $layout.HostPidFile -Root $layout.Root

    $readyState = [ordered]@{
        schemaVersion = 1
        state = 'child-started'
        installationId = [string]$marker.installationId
        pid = $child.Id
        hostPid = $PID
        hostStartTimeFileTimeUtc = [long]$hostStartTimeFileTimeUtc
        startupRequestId = $startupRequestId
        startTimeUtc = $childStartUtc.ToString('o')
        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-ProtectedJson -Path $layout.ControlState -Value $readyState -Root $layout.Root

    while (-not $child.HasExited) {
        $claimedRequestPath = $null
        if (Test-Path -LiteralPath $layout.ControlRequest) {
            try {
                $claimedRequestPath = Move-NewservControlRequestToClaim `
                    -ControlRequestPath $layout.ControlRequest -Root $layout.Root
                Assert-LifecycleFileAcl `
                    -Path $claimedRequestPath -Root $layout.Root
                $requestFile = Get-Item -LiteralPath $claimedRequestPath -Force
                if (($requestFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    $requestFile.Length -le 0 -or $requestFile.Length -gt 16KB) {
                    throw 'The protected supervisor request has an invalid filesystem type or size'
                }
                $request = Get-Content -Raw -LiteralPath $claimedRequestPath |
                    ConvertFrom-Json -Depth 10 -DateKind String
                $validExitRequest = $false
                if ($request.schemaVersion -eq 1 -and $request.action -ceq 'exit') {
                    $requestStartUtc = if ($request.startTimeUtc -is [DateTime]) {
                        ([DateTime]$request.startTimeUtc).ToUniversalTime()
                    } else {
                        [DateTimeOffset]::Parse(
                            [string]$request.startTimeUtc,
                            [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
                    }
                    $validExitRequest =
                        [int]$request.pid -eq $child.Id -and
                        [Math]::Abs(($requestStartUtc - $childStartUtc).TotalSeconds) -le 2 -and
                        (Test-FixedTimeToken -Expected $controlToken -Actual ([string]$request.controlToken))
                }
                $validCancelRequest = $request.schemaVersion -eq 1 -and
                    $request.action -ceq 'cancel-start' -and
                    [int]$request.hostPid -eq $PID -and
                    [long]$request.hostStartTimeFileTimeUtc -eq [long]$hostStartTimeFileTimeUtc -and
                    [string]$request.startupRequestId -eq $startupRequestId -and
                    (Test-FixedTimeToken -Expected $controlToken -Actual ([string]$request.controlToken))
                $validRequest = $validExitRequest -or $validCancelRequest
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
                if ($claimedRequestPath) {
                    Remove-Item `
                        -LiteralPath $claimedRequestPath -Force -ErrorAction SilentlyContinue
                }
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
        @($layout.PidFile, $layout.LegacyPidFile, $layout.HostPidFile) |
            ForEach-Object {
                $safePath = Assert-PathWithinRoot -Path $_ -Root $layout.Root
                Remove-Item -LiteralPath $safePath -Force -ErrorAction SilentlyContinue
            }
    }
    if ($child) { $child.Dispose() }
}
