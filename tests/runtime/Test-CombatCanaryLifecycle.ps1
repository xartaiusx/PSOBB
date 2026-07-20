[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1')
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail
    )
    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

$scriptNames = @(
    'PSOBB.Common.ps1',
    'Start-PSOBB.ps1',
    'Stop-PSOBB.ps1',
    'Invoke-NewservSupervisor.ps1',
    'Start-PSOBBSession.ps1',
    'Stop-PSOBBSession.ps1',
    'Start-PSOBBClient.ps1',
    'Stop-PSOBBClient.ps1')
$sources = [ordered]@{}
foreach ($scriptName in $scriptNames) {
    $path = Join-Path $repositoryRoot ('scripts\' + $scriptName)
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$errors) | Out-Null
    Add-Result "$scriptName parses cleanly" ($errors.Count -eq 0) `
        "$($errors.Count) parser error(s)"
    $sources[$scriptName] = Get-Content -Raw -LiteralPath $path
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-combat-lifecycle-' + [Guid]::NewGuid().ToString('N'))
$layout = Get-PSOBBLayout -RuntimeRoot $fixtureRoot
$stable = Get-PSOBBServerEnvironmentLayout -Layout $layout -Environment Stable
$combat = Get-PSOBBServerEnvironmentLayout `
    -Layout $layout -Environment CombatCanary
$isolation = Assert-PSOBBServerEnvironmentIsolation -Layout $layout
Add-Result 'Stable and CombatCanary lifecycle roots are pairwise isolated' (
    $isolation.Passed -and
    $stable.ControlDirectory -cne $combat.ControlDirectory -and
    $stable.Server -cne $combat.Server -and
    $stable.Client -cne $combat.Client) 'server, client, and control roots do not overlap'

$deletionSucceeded = $false
$unsafeDeletionRejected = $false
try {
    [System.IO.Directory]::CreateDirectory($combat.ControlDirectory) | Out-Null
    @(
        $combat.PidFile,
        $combat.LegacyPidFile,
        $combat.HostPidFile,
        $combat.ControlState,
        $combat.ControlRequest
    ) | ForEach-Object { [System.IO.File]::WriteAllText($_, 'fixture') }
    Remove-PSOBBLifecycleFilesVerified -Layout $combat | Out-Null
    $deletionSucceeded = @(
        $combat.PidFile,
        $combat.LegacyPidFile,
        $combat.HostPidFile,
        $combat.ControlState,
        $combat.ControlRequest
    ).Where({ Test-Path -LiteralPath $_ }).Count -eq 0
    @(
        $combat.PidFile,
        $combat.LegacyPidFile,
        $combat.HostPidFile,
        $combat.ControlState,
        $combat.ControlRequest
    ) | ForEach-Object { [System.IO.File]::WriteAllText($_, 'preserved-fixture') }
    Remove-Item -LiteralPath $combat.ControlState -Force
    [System.IO.Directory]::CreateDirectory($combat.ControlState) | Out-Null
    try {
        Remove-PSOBBLifecycleFilesVerified -Layout $combat | Out-Null
    } catch {
        $unsafeDeletionRejected =
            $_.Exception.Message -match 'unsafe filesystem type' -and
            (Test-Path -LiteralPath $combat.ControlState -PathType Container) -and
            (Test-Path -LiteralPath $combat.PidFile -PathType Leaf) -and
            (Test-Path -LiteralPath $combat.LegacyPidFile -PathType Leaf) -and
            (Test-Path -LiteralPath $combat.HostPidFile -PathType Leaf) -and
            (Test-Path -LiteralPath $combat.ControlRequest -PathType Leaf)
    }
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
Add-Result 'verified lifecycle deletion removes exact files and rejects unsafe types' (
    $deletionSucceeded -and $unsafeDeletionRejected) `
    'temporary exact files reached absence; a later unsafe path failed closed before any earlier evidence was deleted'

function Write-TerminalSupervisorFixture {
    param(
        [Parameter(Mandatory)]$RootLayout,
        [Parameter(Mandatory)]$EnvironmentLayout,
        [Parameter(Mandatory)]$Marker,
        [Parameter(Mandatory)]$HostProcess,
        [ValidateSet('Stable', 'CombatCanary')]
        [string]$ServerEnvironment = 'Stable'
    )

    $approvedFixture = Get-PSOBBApprovedNewservExecutableIdentity `
        -Layout $RootLayout -ServerEnvironment $ServerEnvironment
    $requestId = [Guid]::NewGuid().ToString('N')
    $fixtureControlIdentity = Get-PSOBBServerControlIdentity `
        -InstallationId ([string]$Marker.installationId) `
        -EnvironmentId $EnvironmentLayout.EnvironmentId `
        -ComponentId $approvedFixture.ComponentId `
        -StartupRequestId $requestId `
        -ExecutableSha256 $approvedFixture.Sha256
    $hostStartUtc = $HostProcess.StartTime.ToUniversalTime()
    $absentChildStartTimeFileTimeUtc = 1L
    $record = [ordered]@{
        schemaVersion = 3
        serverEnvironment = $ServerEnvironment
        environmentId = $EnvironmentLayout.EnvironmentId
        componentId = $approvedFixture.ComponentId
        controlIdentity = $fixtureControlIdentity
        pid = 2147480000
        executablePath = $approvedFixture.ExecutablePath
        executableSha256 = $approvedFixture.Sha256
        startTimeUtc = [DateTime]::UtcNow.AddMinutes(-1).ToString('r')
        startTimeFileTimeUtc = $absentChildStartTimeFileTimeUtc
        hostPid = $HostProcess.Id
        hostStartTimeUtc = $hostStartUtc.ToString('r')
        hostStartTimeFileTimeUtc = [long]$hostStartUtc.ToFileTimeUtc()
        hostExecutablePath = [System.IO.Path]::GetFullPath($HostProcess.Path)
        startupRequestId = $requestId
        controlToken = 'A' * 43
        controlProtocol = 'protected-filesystem-exit-v2'
        buildContractSha256 = $null
        clientBindingSha256 = $null
        stateBindingSha256 = $null
        stdoutLog = Join-Path $EnvironmentLayout.Logs 'fixture.stdout.log'
        stderrLog = Join-Path $EnvironmentLayout.Logs 'fixture.stderr.log'
    }
    [System.IO.File]::WriteAllText(
        $EnvironmentLayout.PidFile,
        ($record | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBLifecyclePathAcl `
        -Path $EnvironmentLayout.PidFile -Root $EnvironmentLayout.Root | Out-Null
    [System.IO.File]::WriteAllText(
        $EnvironmentLayout.HostPidFile,
        [string]$HostProcess.Id)
    Set-PSOBBLifecyclePathAcl `
        -Path $EnvironmentLayout.HostPidFile -Root $EnvironmentLayout.Root | Out-Null
    $terminalState = [ordered]@{
        schemaVersion = 3
        state = 'exited'
        installationId = [string]$Marker.installationId
        serverEnvironment = $ServerEnvironment
        environmentId = $EnvironmentLayout.EnvironmentId
        componentId = $approvedFixture.ComponentId
        controlIdentity = $fixtureControlIdentity
        pid = 2147480000
        startTimeFileTimeUtc = $absentChildStartTimeFileTimeUtc
        exitCode = 0
        gracefulShellExitRequested = $false
        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    [System.IO.File]::WriteAllText(
        $EnvironmentLayout.ControlState,
        ($terminalState | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBLifecyclePathAcl `
        -Path $EnvironmentLayout.ControlState -Root $EnvironmentLayout.Root | Out-Null
}

$terminalRecoveryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-terminal-recovery-' + [Guid]::NewGuid().ToString('N'))
$firstTerminalHost = $null
$secondTerminalHost = $null
$startRecoveryPassed = $false
$emptyStopRecoveryPassed = $false
try {
    [System.IO.Directory]::CreateDirectory($terminalRecoveryRoot) | Out-Null
    $terminalRootLayout = Get-PSOBBLayout -RuntimeRoot $terminalRecoveryRoot
    [System.IO.Directory]::CreateDirectory($terminalRootLayout.Stable) | Out-Null
    $terminalMarker = Initialize-PSOBBRuntimeMarker -Layout $terminalRootLayout
    $terminalLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $terminalRootLayout -Environment Stable
    Initialize-PSOBBLifecycleControlDirectory -Layout $terminalLayout | Out-Null
    $encodedShortSleep = [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes(
            'Start-Sleep -Milliseconds 350'))
    $firstTerminalHost = Start-Process `
        -FilePath (Join-Path $PSHOME 'pwsh.exe') `
        -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            $encodedShortSleep) `
        -WindowStyle Hidden `
        -PassThru
    Write-TerminalSupervisorFixture `
        -RootLayout $terminalRootLayout `
        -EnvironmentLayout $terminalLayout `
        -Marker $terminalMarker `
        -HostProcess $firstTerminalHost
    $startRecovery = Wait-PSOBBRecordedSupervisorHostQuiescence `
        -Layout $terminalLayout -TimeoutMilliseconds 5000
    Remove-PSOBBLifecycleFilesVerified -Layout $terminalLayout | Out-Null
    $firstTerminalHost.Refresh()
    $startRecoveryPassed =
        $startRecovery.Quiescent -and
        $firstTerminalHost.HasExited -and
        -not (Test-Path -LiteralPath $terminalLayout.PidFile) -and
        -not (Test-Path -LiteralPath $terminalLayout.HostPidFile)

    $combatTerminalLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $terminalRootLayout -Environment CombatCanary
    [System.IO.Directory]::CreateDirectory(
        $combatTerminalLayout.EnvironmentRoot) | Out-Null
    Initialize-PSOBBLifecycleControlDirectory `
        -Layout $combatTerminalLayout | Out-Null
    $secondTerminalHost = Start-Process `
        -FilePath (Join-Path $PSHOME 'pwsh.exe') `
        -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            $encodedShortSleep) `
        -WindowStyle Hidden `
        -PassThru
    Write-TerminalSupervisorFixture `
        -RootLayout $terminalRootLayout `
        -EnvironmentLayout $combatTerminalLayout `
        -Marker $terminalMarker `
        -HostProcess $secondTerminalHost `
        -ServerEnvironment CombatCanary
    $emptyStopResult = & (Join-Path $repositoryRoot 'scripts\Stop-PSOBB.ps1') `
        -RuntimeRoot $terminalRecoveryRoot
    $secondTerminalHost.Refresh()
    $emptyStopRecoveryPassed =
        -not $emptyStopResult.Stopped -and
        $emptyStopResult.Reason -ceq 'not-running' -and
        $emptyStopResult.ServerEnvironment -ceq 'CombatCanary' -and
        $emptyStopResult.Selection -ceq 'automatic-evidence' -and
        $secondTerminalHost.HasExited -and
        -not (Test-Path -LiteralPath $combatTerminalLayout.PidFile) -and
        -not (Test-Path -LiteralPath $combatTerminalLayout.HostPidFile)
} finally {
    foreach ($hostProcess in @($firstTerminalHost, $secondTerminalHost)) {
        if ($hostProcess) {
            $hostProcess.Refresh()
            if (-not $hostProcess.HasExited) {
                Stop-Process -Id $hostProcess.Id -Force -ErrorAction SilentlyContinue
                $hostProcess.WaitForExit(5000) | Out-Null
            }
            $hostProcess.Dispose()
        }
    }
    if (Test-Path -LiteralPath $terminalRecoveryRoot) {
        Remove-Item -LiteralPath $terminalRecoveryRoot -Recurse -Force
    }
}
Add-Result 'natural terminal host exit is recoverable by Start preflight and empty Stop' (
    $startRecoveryPassed -and $emptyStopRecoveryPassed) `
    'complete terminal PID/host evidence was authenticated and removed after natural exits; non-explicit Stop selected sole CombatCanary evidence'

$stableIdentity = Get-PSOBBApprovedNewservExecutableIdentity `
    -Layout $layout -ServerEnvironment Stable
$combatIdentity = Get-PSOBBApprovedNewservExecutableIdentity `
    -Layout $layout -ServerEnvironment CombatCanary
Add-Result 'server environments bind distinct approved components' (
    $stableIdentity.ComponentId -ceq 'newserv-stable-release' -and
    $combatIdentity.ComponentId -ceq 'newserv-combat-canary-build' -and
    $stableIdentity.Sha256 -cne $combatIdentity.Sha256 -and
    $combatIdentity.Sha256 -ceq
        '3208b811791e591955a50084276e522cfbfa13f9e807d2287d5ce66f712f717a') `
    'the frozen stable release and deterministic d754 build cannot be confused'

$stablePaths = @(
    Get-PSOBBClientExecutablePath -Layout $layout -ServerEnvironment Stable -Channel Stable
    Get-PSOBBClientExecutablePath -Layout $layout -ServerEnvironment Stable -Channel Canary
    Get-PSOBBClientExecutablePath -Layout $layout -ServerEnvironment Stable -Channel LocalLab)
$nativePath = Get-PSOBBClientExecutablePath `
    -Layout $layout -ServerEnvironment CombatCanary -Channel Native
$badStableNative = $false
$badCombatGraphics = $false
try {
    Get-PSOBBClientExecutablePath `
        -Layout $layout -ServerEnvironment Stable -Channel Native | Out-Null
} catch { $badStableNative = $_.Exception.Message -match 'not valid' }
try {
    Get-PSOBBClientExecutablePath `
        -Layout $layout -ServerEnvironment CombatCanary -Channel Canary | Out-Null
} catch { $badCombatGraphics = $_.Exception.Message -match 'not valid' }
Add-Result 'client channels have an exact environment boundary' (
    @($stablePaths | Sort-Object -Unique).Count -eq 3 -and
    $nativePath -ceq (Join-Path $combat.Client 'Psobb.exe') -and
    $badStableNative -and $badCombatGraphics) `
    'Stable retains three graphics channels; CombatCanary accepts only its isolated Native client'

$controlArguments = @{
    InstallationId = '12345678-1234-1234-1234-123456789abc'
    EnvironmentId = 'stable'
    ComponentId = 'newserv-stable-release'
    StartupRequestId = ('a' * 32)
    ExecutableSha256 = ('b' * 64)
}
$controlA = Get-PSOBBServerControlIdentity @controlArguments
$controlB = Get-PSOBBServerControlIdentity @controlArguments
$controlArguments.EnvironmentId = 'combat-canary'
$controlC = Get-PSOBBServerControlIdentity @controlArguments
Add-Result 'control identity binds installation, environment, component, request, and executable' (
    $controlA -cmatch '^[a-f0-9]{64}$' -and
    (Test-PSOBBFixedTimeTextEquals -Expected $controlA -Actual $controlB) -and
    -not (Test-PSOBBFixedTimeTextEquals -Expected $controlA -Actual $controlC)) `
    'a changed environment produces a distinct fixed-time-compared control identity'

$currentHostProcess = Get-Process -Id $PID -ErrorAction Stop
$currentHostRecord = [pscustomobject]@{
    hostPid = $PID
    hostExecutablePath = [System.IO.Path]::GetFullPath($currentHostProcess.Path)
    hostStartTimeFileTimeUtc = [long](
        $currentHostProcess.StartTime.ToUniversalTime().ToFileTimeUtc())
}
$exactHostState = Get-PSOBBRecordedSupervisorHostState -Record $currentHostRecord
$reusedHostRecord = $currentHostRecord.PSObject.Copy()
$reusedHostRecord.hostStartTimeFileTimeUtc =
    [long]$currentHostRecord.hostStartTimeFileTimeUtc + 1
$reusedHostState = Get-PSOBBRecordedSupervisorHostState -Record $reusedHostRecord
Add-Result 'supervisor host identity binds PID, exact pwsh image, and creation time' (
    $exactHostState.State -ceq 'ExactActive' -and
    $reusedHostState.State -ceq 'Reused' -and
    $null -eq $reusedHostState.Process) `
    'a one-tick PID-reuse simulation is treated as host-absent and exposes no process action target'
$exactHostState.Process.Dispose()
$currentHostProcess.Dispose()

$processBlocked = $false
try {
    Assert-PSOBBExclusiveServerStartBoundary `
        -ServerEnvironment Stable `
        -ServerProcesses @([pscustomobject]@{
            ServerEnvironment = 'Unknown'
            ProcessId = 4242
            Classification = 'Uninspectable'
        }) `
        -ReservedPortListeners @() | Out-Null
} catch { $processBlocked = $_.Exception.Message -match 'Uninspectable' }
$portBlocked = $false
try {
    Assert-PSOBBExclusiveServerStartBoundary `
        -ServerEnvironment CombatCanary `
        -ServerProcesses @() `
        -ReservedPortListeners @([pscustomobject]@{
            LocalAddress = '0.0.0.0'
            LocalPort = 11000
            OwningProcess = 5151
        }) | Out-Null
} catch { $portBlocked = $_.Exception.Message -match '11000.*5151' }
Add-Result 'start boundary rejects unknown processes and reserved listeners' (
    $processBlocked -and $portBlocked) 'neither condition authorizes PID action'

$exactListeners = @(
    [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 11000; OwningProcess = 6161 },
    [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 12000; OwningProcess = 6161 },
    [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 12001; OwningProcess = 6161 })
$foreignListeners = @($exactListeners) + @(
    [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 12001; OwningProcess = 7171 })
Add-Result 'listener contracts distinguish readiness from safe shutdown' (
    (Test-PSOBBExactLoopbackServerListeners `
        -ProcessId 6161 -ListenerRecords $exactListeners) -and
    -not (Test-PSOBBExactLoopbackServerListeners `
        -ProcessId 6161 -ListenerRecords $foreignListeners) -and
    (Test-PSOBBServerListenerSubsetForStop `
        -ProcessId 6161 -ReservedPortListeners @($exactListeners[0])) -and
    (Test-PSOBBServerListenerSubsetForStop `
        -ProcessId 6161 -ReservedPortListeners @()) -and
    -not (Test-PSOBBServerListenerSubsetForStop `
        -ProcessId 6161 -ReservedPortListeners $foreignListeners)) `
    'start requires exactly three loopback listeners; stop tolerates a non-conflicting subset'

$commonSource = $sources['PSOBB.Common.ps1']
$startSource = $sources['Start-PSOBB.ps1']
$stopSource = $sources['Stop-PSOBB.ps1']
$supervisorSource = $sources['Invoke-NewservSupervisor.ps1']
$sessionSource = $sources['Start-PSOBBSession.ps1']
$stopSessionSource = $sources['Stop-PSOBBSession.ps1']
$clientSource = $sources['Start-PSOBBClient.ps1']
$stopClientSource = $sources['Stop-PSOBBClient.ps1']

Add-Result 'all lifecycle entry points expose an explicit server environment' (
    @($scriptNames | Where-Object {
            $_ -ne 'PSOBB.Common.ps1' -and
            $sources[$_] -notmatch "ValidateSet\('Stable', 'CombatCanary'\)"
        }).Count -eq 0) 'Stable remains the declared default'
Add-Result 'server start repeats the all-named client gate immediately before launch' (
    [regex]::Matches($startSource, 'Assert-PSOBBNoRunningClients').Count -ge 2 -and
    $startSource -match 'Get-PSOBBServerEnvironmentProcessRecords' -and
    $startSource -match 'Get-PSOBBReservedServerPortListeners') `
    'both locks remain held across the final client/server/port census'
Add-Result 'named process census classifies uninspectable and unexpected identities' (
    $commonSource -match "classification = 'Uninspectable'" -and
    $commonSource -match "classification = 'UnexpectedPath'" -and
    $commonSource -match "ProcessName 'newserv-windows'" -and
    $commonSource -match "ProcessName 'Psobb'") `
    'all named PIDs are compared to the four client and two server executable paths'
Add-Result 'supervisor owns no lifecycle mutex' (
    $supervisorSource -notmatch 'System\.Threading\.Mutex' -and
    $supervisorSource -notmatch 'Enter-PSOBBClientOperationLock' -and
    $supervisorSource -notmatch '\.WaitOne\(') `
    'the guarded parent owns serialization while the supervisor verifies schema-3 state'
Add-Result 'supervisor preserves complete terminal PID and host evidence' (
    $supervisorSource -match 'Preserve the complete process/host record' -and
    $supervisorSource -notmatch 'Remove-Item[\s\S]{0,180}\$layout\.(?:PidFile|HostPidFile)' -and
    $supervisorSource -notmatch '@\(\$layout\.PidFile, \$layout\.LegacyPidFile, \$layout\.HostPidFile\)') `
    'natural and requested child exits leave the complete process record for a controlling Start or Stop to authenticate after host exit'
Add-Result 'schema-3 controls carry exact environment and component identity' (
    $startSource -match 'schemaVersion = 3' -and
    $startSource -match 'controlIdentity = \$controlIdentity' -and
    $supervisorSource -match "controlProtocol = 'protected-filesystem-exit-v2'" -and
    $supervisorSource -match '\$request\.environmentId -ceq \$layout\.EnvironmentId' -and
    $supervisorSource -match '\$request\.componentId -ceq \$approved\.ComponentId') `
    'startup, process, ready, exit, cancellation, and terminal states share one binding'
Add-Result 'process-record reads recompute the approved control binding' (
    $commonSource -match 'function Get-NewservProcess' -and
    $commonSource -match 'Get-PSOBBApprovedNewservExecutableIdentity[\s\S]*?Get-PSOBBServerControlIdentity' -and
    $commonSource -match 'Test-PSOBBFixedTimeTextEquals[\s\S]*?record\.controlIdentity' -and
    $stopSource -match 'expectedControlIdentity = Get-PSOBBServerControlIdentity') `
    'tampering with environment, component, request, executable, or installation identity invalidates the record'
Add-Result 'stale lifecycle reuse waits for exact supervisor-host quiescence' (
    $startSource -match 'Wait-PSOBBRecordedSupervisorHostQuiescence[\s\S]{0,600}Remove-PSOBBLifecycleFilesVerified' -and
    $stopSource -match 'environmentCensus\.Count -eq 0[\s\S]{0,900}Wait-PSOBBRecordedSupervisorHostQuiescence[\s\S]{0,300}Remove-LifecycleFiles') `
    'Start and empty Stop preserve lifecycle evidence until the exact recorded host is absent'
Add-Result 'stop auto-selects one active environment and proves post-stop absence' (
    $stopSource -match "PSBoundParameters\.ContainsKey\('ServerEnvironment'\)" -and
    $stopSource -match 'environmentCensus\.Count -gt 1' -and
    $stopSource -match 'Test-PSOBBServerListenerSubsetForStop[\s\S]{0,160}-ReservedPortListeners \$reservedListeners' -and
    $stopSource -notmatch 'Test-PSOBBServerListenerSubsetForStop[\s\S]{0,160}-ListenerRecords' -and
    $stopSource -match 'postStopCensus' -and
    $stopSource -match 'postStopListeners' -and
    $stopSource -match 'Get-PSOBBServerLifecycleEvidenceRecords' -and
    $stopSource -match "'automatic-evidence'" -and
    $stopSessionSource -match 'activeEnvironment') `
    'the unchanged Stop All shortcut can stop CombatCanary without accepting ambiguity'
Add-Result 'Stop validates the exact supervisor host before request or wait' (
    $stopSource -match 'Get-PSOBBRecordedSupervisorHostState -Record \$record' -and
    $stopSource -match "hostState\.State -in @\('InvalidRecord', 'Uninspectable'\)" -and
    $stopSource -match "hostState\.State -ceq 'ExactActive'" -and
    $stopSource -match 'no request or wait was attempted') `
    'an absent or PID-reused pwsh host requires explicit Force for the independently revalidated child'
Add-Result 'session stop preserves its resolved environment through server stop' (
    $stopSessionSource -match 'ServerEnvironment = \$serverEnvironmentName' -and
    $stopSessionSource -notmatch 'if \(\$environmentWasExplicit\)[\s\S]{0,160}serverParameters\.ServerEnvironment') `
    'a crashed CombatCanary server with only client state cannot fall back to Stable cleanup'
Add-Result 'server readiness performs a final global client and selected-server census' (
    [regex]::Matches($startSource, 'Assert-PSOBBNoRunningClients').Count -ge 3 -and
    $startSource -match 'readyServerCensus' -and
    $startSource -match 'readyRecordedProcess' -and
    $startSource -match "Classification -cne\s*'ApprovedExactPath'") `
    'ready is reported only while zero clients and exactly the selected approved server remain'
Add-Result 'CombatCanary client launch consumes only the sealed native binding' (
    $clientSource -match 'Get-PSOBBCombatCanaryClientLaunchContract' -and
    [regex]::Matches(
        $clientSource, 'Get-PSOBBAllClientProcessRecords').Count -ge 2 -and
    $clientSource -match 'ClientBindingSha256' -and
    $sessionSource -notmatch 'Get-PSOBBCombatCanaryInstalledBinding' -and
    $sessionSource -match "PSBoundParameters\.ContainsKey\('WindowMode'\)" -and
    $sessionSource -match "serverEnvironmentName -ceq 'CombatCanary'[\s\S]{0,80}'ProfileDefault'" -and
    $stopClientSource -match 'Get-PSOBBAllClientProcessRecords') `
    'native profile, executable, server, default window mode, and stopped-client inventory are environment-bound'
Add-Result 'client creation immediately revalidates the selected server and zero-client boundary' (
    $clientSource -match 'finalClientCensus[\s\S]{0,900}finalServerProcess[\s\S]{0,900}finalServerCensus[\s\S]{0,1200}Start-PSOBBClientProcess' -and
    $clientSource -match 'finalServerProcess\.Id -ne \$serverProcess\.Id' -and
    $clientSource -match 'Test-PSOBBExactLoopbackServerListeners') `
    'the final control record, environment, PID, listeners, and all-named client census precede process creation'
Add-Result 'lifecycle deletion is terminating and post-verified' (
    $commonSource -match 'function Remove-PSOBBLifecycleFilesVerified' -and
    $commonSource -match 'Remove-Item -LiteralPath \$safePath -Force -ErrorAction Stop' -and
    $commonSource -match '\$Layout\.ControlState,\s*\$Layout\.PidFile' -and
    $commonSource -match 'Lifecycle evidence reappeared before process-record deletion' -and
    $commonSource -match 'Lifecycle file removal could not be verified' -and
    $startSource -notmatch 'lifecycleFiles[\s\S]{0,300}ErrorAction SilentlyContinue' -and
    $stopSource -notmatch 'Remove-LifecycleFiles[\s\S]{0,500}ErrorAction SilentlyContinue') `
    'exact lifecycle files are removed with terminating errors and a second absence check'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) combat-canary lifecycle test(s) failed"
}
[pscustomobject]@{
    Suite = 'CombatCanaryLifecycle'
    Passed = $results.Count
    Failed = 0
}
