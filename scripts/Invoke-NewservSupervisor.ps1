[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RuntimeRoot,
    [ValidateSet('Stable', 'CombatCanary')]
    [string]$ServerEnvironment = 'Stable'
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')

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

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$serverEnvironmentName = Resolve-PSOBBServerEnvironmentName `
    -Environment $ServerEnvironment
$layout = Get-PSOBBServerEnvironmentLayout `
    -Layout $rootLayout -Environment $serverEnvironmentName
$child = $null
$stdoutStream = $null
$stderrStream = $null
$stdoutPump = $null
$stderrPump = $null
$controlToken = $null
$controlIdentity = $null
$componentId = Get-PSOBBServerComponentId `
    -ServerEnvironment $serverEnvironmentName
$gracefulRequested = $false
$startupAuthenticated = $false

try {
    $marker = Assert-PSOBBRuntimeMarker -Layout $rootLayout
    Assert-PSOBBServerEnvironmentIsolation -Layout $rootLayout | Out-Null
    $installedBinding = if ($serverEnvironmentName -ceq 'CombatCanary') {
        Get-PSOBBCombatCanaryInstalledBinding -Layout $rootLayout
    } else {
        $null
    }
    Assert-PSOBBLifecyclePathAcl `
        -Path $layout.ControlDirectory -Root $layout.Root -IsContainer $true | Out-Null
    $approved = Get-PSOBBApprovedNewservExecutableIdentity `
        -Layout $rootLayout -ServerEnvironment $serverEnvironmentName
    $componentId = $approved.ComponentId
    $executable = Assert-PathWithinRoot `
        -Path $approved.ExecutablePath -Root $layout.EnvironmentRoot
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
        (Get-Item -LiteralPath $executable).Length -ne $approved.Size -or
        (Get-LowerSha256 $executable) -ne $approved.Sha256) {
        throw "The $serverEnvironmentName newserv executable does not match its exact approved component"
    }
    Assert-PSOBBExclusiveServerStartBoundary `
        -ServerEnvironment $serverEnvironmentName `
        -ServerProcesses @(Get-PSOBBServerEnvironmentProcessRecords -Layout $rootLayout) `
        -ReservedPortListeners @(Get-PSOBBReservedServerPortListeners) | Out-Null
    if (-not (Test-Path -LiteralPath $layout.ControlState -PathType Leaf)) {
        throw 'The protected supervisor startup state is missing'
    }
    Assert-LifecycleFileAcl -Path $layout.ControlState -Root $layout.Root
    $startup = Read-PSOBBStrictLifecycleJson `
        -Path $layout.ControlState -Root $layout.Root -Contract ServerControlState
    $expectedControlIdentity = Get-PSOBBServerControlIdentity `
        -InstallationId ([string]$marker.installationId) `
        -EnvironmentId $layout.EnvironmentId `
        -ComponentId $approved.ComponentId `
        -StartupRequestId ([string]$startup.startupRequestId) `
        -ExecutableSha256 $approved.Sha256
    if ($startup.schemaVersion -ne 3 -or $startup.state -ne 'starting' -or
        [string]$startup.installationId -ne [string]$marker.installationId -or
        [string]$startup.serverEnvironment -cne $serverEnvironmentName -or
        [string]$startup.environmentId -cne $layout.EnvironmentId -or
        [string]$startup.componentId -cne $approved.ComponentId -or
        -not (Test-PSOBBFixedTimeTextEquals `
            -Expected $expectedControlIdentity `
            -Actual ([string]$startup.controlIdentity)) -or
        [string]$startup.executablePath -ne $executable -or
        [string]$startup.executableSha256 -ne $approved.Sha256 -or
        [string]$startup.startupRequestId -notmatch '^[0-9a-f]{32}$' -or
        [string]$startup.controlToken -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'The protected supervisor startup state is invalid'
    }
    if ($installedBinding) {
        if ([string]$startup.buildContractSha256 -cne
                [string]$installedBinding.BuildContractSha256 -or
            [string]$startup.clientBindingSha256 -cne
                [string]$installedBinding.ClientBindingSha256 -or
            [string]$startup.stateBindingSha256 -cne
                [string]$installedBinding.StateBindingSha256) {
            throw 'The protected supervisor startup state does not match the sealed combat-canary installation'
        }
    } elseif ($null -ne $startup.buildContractSha256 -or
        $null -ne $startup.clientBindingSha256 -or
        $null -ne $startup.stateBindingSha256) {
        throw 'Stable supervisor startup state contains an unexpected combat-canary binding'
    }
    $controlToken = [string]$startup.controlToken
    $controlIdentity = [string]$startup.controlIdentity
    $startupRequestId = [string]$startup.startupRequestId
    $startupAuthenticated = $true

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
    $childStartTimeFileTimeUtc = [long]$childStartUtc.ToFileTimeUtc()
    $childStartRecord = $childStartUtc.ToString(
        'r', [System.Globalization.CultureInfo]::InvariantCulture)
    $hostStartRecord = $hostStartUtc.ToString(
        'r', [System.Globalization.CultureInfo]::InvariantCulture)

    $record = [ordered]@{
        schemaVersion = 3
        serverEnvironment = $serverEnvironmentName
        environmentId = $layout.EnvironmentId
        componentId = $approved.ComponentId
        controlIdentity = $controlIdentity
        pid = $child.Id
        executablePath = $executable
        executableSha256 = $approved.Sha256
        startTimeUtc = $childStartRecord
        startTimeFileTimeUtc = $childStartTimeFileTimeUtc
        hostPid = $PID
        hostStartTimeUtc = $hostStartRecord
        hostStartTimeFileTimeUtc = [long]$hostStartTimeFileTimeUtc
        hostExecutablePath = $hostExecutablePath
        startupRequestId = $startupRequestId
        controlToken = $controlToken
        controlProtocol = 'protected-filesystem-exit-v2'
        buildContractSha256 = if ($installedBinding) {
            [string]$installedBinding.BuildContractSha256
        } else { $null }
        clientBindingSha256 = if ($installedBinding) {
            [string]$installedBinding.ClientBindingSha256
        } else { $null }
        stateBindingSha256 = if ($installedBinding) {
            [string]$installedBinding.StateBindingSha256
        } else { $null }
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
        schemaVersion = 3
        state = 'child-started'
        installationId = [string]$marker.installationId
        serverEnvironment = $serverEnvironmentName
        environmentId = $layout.EnvironmentId
        componentId = $approved.ComponentId
        controlIdentity = $controlIdentity
        pid = $child.Id
        startTimeFileTimeUtc = $childStartTimeFileTimeUtc
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
                $request = Read-PSOBBStrictLifecycleJson `
                    -Path $claimedRequestPath `
                    -Root $layout.Root `
                    -Contract ServerControlRequest
                $validExitRequest = $false
                if ($request.schemaVersion -eq 3 -and
                    $request.action -ceq 'exit' -and
                    [string]$request.serverEnvironment -ceq $serverEnvironmentName -and
                    [string]$request.environmentId -ceq $layout.EnvironmentId -and
                    [string]$request.componentId -ceq $approved.ComponentId -and
                    (Test-PSOBBFixedTimeTextEquals `
                        -Expected $controlIdentity `
                        -Actual ([string]$request.controlIdentity)) -and
                    [string]$request.startupRequestId -ceq $startupRequestId) {
                    [DateTimeOffset]::Parse(
                        [string]$request.startTimeUtc,
                        [System.Globalization.CultureInfo]::InvariantCulture) | Out-Null
                    $validExitRequest =
                        [int]$request.pid -eq $child.Id -and
                        [long]$request.startTimeFileTimeUtc -eq
                            $childStartTimeFileTimeUtc -and
                        (Test-FixedTimeToken -Expected $controlToken -Actual ([string]$request.controlToken))
                }
                $validCancelRequest = $request.schemaVersion -eq 3 -and
                    $request.action -ceq 'cancel-start' -and
                    [string]$request.serverEnvironment -ceq $serverEnvironmentName -and
                    [string]$request.environmentId -ceq $layout.EnvironmentId -and
                    [string]$request.componentId -ceq $approved.ComponentId -and
                    (Test-PSOBBFixedTimeTextEquals `
                        -Expected $controlIdentity `
                        -Actual ([string]$request.controlIdentity)) -and
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
                        schemaVersion = 3
                        state = 'shell-exit-requested'
                        installationId = [string]$marker.installationId
                        serverEnvironment = $serverEnvironmentName
                        environmentId = $layout.EnvironmentId
                        componentId = $approved.ComponentId
                        controlIdentity = $controlIdentity
                        pid = $child.Id
                        startTimeFileTimeUtc = $childStartTimeFileTimeUtc
                        hostPid = $PID
                        hostStartTimeFileTimeUtc = [long]$hostStartTimeFileTimeUtc
                        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
                    }
                    Write-ProtectedJson -Path $layout.ControlState -Value $stoppingState -Root $layout.Root
                }
            } catch {
                # Malformed, incorrectly permissioned, or unauthenticated files
                # are rejected without forwarding any input to newserv.
            } finally {
                if ($claimedRequestPath) {
                    $safeClaimPath = Assert-PathWithinRoot `
                        -Path $claimedRequestPath -Root $layout.Root
                    if (Test-Path -LiteralPath $safeClaimPath) {
                        Remove-Item `
                            -LiteralPath $safeClaimPath -Force -ErrorAction Stop
                    }
                    if (Test-Path -LiteralPath $safeClaimPath) {
                        throw 'The claimed lifecycle request did not reach verified absence'
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 200
        $child.Refresh()
    }

    $stdoutPump.GetAwaiter().GetResult()
    $stderrPump.GetAwaiter().GetResult()
    $stoppedState = [ordered]@{
        schemaVersion = 3
        state = if ($gracefulRequested) { 'stopped' } else { 'exited' }
        installationId = [string]$marker.installationId
        serverEnvironment = $serverEnvironmentName
        environmentId = $layout.EnvironmentId
        componentId = $approved.ComponentId
        controlIdentity = $controlIdentity
        pid = $child.Id
        startTimeFileTimeUtc = $childStartTimeFileTimeUtc
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
        if ($startupAuthenticated) {
            $failureState = [ordered]@{
                schemaVersion = 3
                state = 'failed'
                serverEnvironment = $serverEnvironmentName
                environmentId = $layout.EnvironmentId
                componentId = $componentId
                controlIdentity = $controlIdentity
                message = $_.Exception.Message
                updatedAtUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-ProtectedJson `
                -Path $layout.ControlState -Value $failureState -Root $layout.Root
        }
    } catch { }
    exit 1
} finally {
    $controlToken = $null
    if ($stdoutStream) { $stdoutStream.Dispose() }
    if ($stderrStream) { $stderrStream.Dispose() }
    # Preserve the complete process/host record through natural or requested
    # termination. A controlling Start/Stop operation authenticates the exact
    # recorded host, waits for its exit, proves process/listener absence, and
    # only then removes lifecycle evidence.
    if ($child) { $child.Dispose() }
}
