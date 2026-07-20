[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$startPath = Join-Path $repositoryRoot 'scripts\Start-PSOBB.ps1'
$startSource = Get-Content -Raw -LiteralPath $startPath
$supervisorPath = Join-Path $repositoryRoot 'scripts\Invoke-NewservSupervisor.ps1'
$supervisorSource = Get-Content -Raw -LiteralPath $supervisorPath
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

$tokens = $null
$parseErrors = $null
$startAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $startPath,
    [ref]$tokens,
    [ref]$parseErrors)
Add-Result `
    -Name 'server start script parses cleanly' `
    -Passed ($parseErrors.Count -eq 0) `
    -Detail "$($parseErrors.Count) parser error(s)"

$supervisorTokens = $null
$supervisorParseErrors = $null
$supervisorAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $supervisorPath,
    [ref]$supervisorTokens,
    [ref]$supervisorParseErrors)
Add-Result `
    -Name 'newserv supervisor script parses cleanly' `
    -Passed ($supervisorParseErrors.Count -eq 0) `
    -Detail "$($supervisorParseErrors.Count) parser error(s)"

$nativeContract =
    $startSource -match 'CreateProcessW\(' -and
    $startSource -match 'false,\s*\r?\n\s*CreateNoWindow \| CreateSuspended,' -and
    $startSource -match 'private const uint CreateNoWindow = 0x08000000;' -and
    $startSource -match 'private const uint CreateSuspended = 0x00000004;' -and
    $startSource -match 'GetProcessTimes\(' -and
    $startSource -match 'CreateJobObjectW\(' -and
    $startSource -match 'AssignProcessToJobObject\(' -and
    $startSource -match 'ResumeThread\(processInformation\.hThread\)' -and
    $startSource -notmatch 'RedirectStandard(?:Input|Output|Error)\s*=\s*\$true'
Add-Result `
    -Name 'supervisor launch disables handle inheritance and its console' `
    -Passed $nativeContract `
    -Detail 'CreateProcessW uses no inherited handles, no console, and captures identity before resuming the process'

$identityContract =
    $startSource -match 'CreateProcessW\(\s*\r?\n\s*applicationName,' -and
    $startSource -match '\$nativeHostIdentity\s*=\s*\[PSOBBLifecycle\.NativeSupervisorLauncher\]::Start\(' -and
    $startSource -match 'StartTimeFileTimeUtc\s*=\s*\[long\]\$nativeHostIdentity\.StartTimeFileTimeUtc' -and
    $startSource -match 'NativeIdentity\s*=\s*\$nativeHostIdentity' -and
    $startSource -match '\$hostProbe\s*=\s*Get-LaunchedSupervisorProbe\s+`' -and
    $startSource -notmatch '\$hostProcess\.(?:Path|Kill)' -and
    $startSource -match '\[int\]\$record\.hostPid -ne \$hostProcessId' -and
    $startSource -match '\[long\]\$record\.hostStartTimeFileTimeUtc -ne \[long\]\$hostIdentity\.StartTimeFileTimeUtc' -and
    $startSource -match '\[string\]\$record\.startupRequestId -ne \$startupRequestId'
Add-Result `
    -Name 'supervisor identity is attached by path, start time, PID, and request ID' `
    -Passed $identityContract `
    -Detail 'the native PID is verified immediately and matched against the protected supervisor record'

$failureCleanupContract =
    $startSource -match "action\s*=\s*'cancel-start'" -and
    $startSource -match 'Get-LaunchedSupervisorProbe -Identity \$Identity' -and
    $startSource -match '\$Identity\.NativeIdentity\.TerminateTree\(1\)' -and
    $startSource -match 'assigned job handle.+authoritative' -and
    $startSource -notmatch '\.Kill\(\$true\)' -and
    $startSource -match 'Stop-ExactLaunchedSupervisorAfterFailure\s*`' -and
    $startSource -match 'A newserv process remains after supervisor cleanup' -and
    $startSource -match 'Get-PSOBBServerEnvironmentProcessRecords' -and
    $supervisorSource -match '\$request\.action -ceq ''cancel-start''' -and
    $supervisorSource -match '\[long\]\$request\.hostStartTimeFileTimeUtc -eq \[long\]\$hostStartTimeFileTimeUtc' -and
    $supervisorSource -match '\[string\]\$request\.startupRequestId -eq \$startupRequestId'
Add-Result `
    -Name 'failed startup cancels or force-cleans only the verified supervisor tree' `
    -Passed $failureCleanupContract `
    -Detail 'cooperative cancellation is verified-only, while the retained assigned-job handle always terminates its exact tree before global absence proof'

$recordContract =
    $supervisorSource -match 'hostStartTimeFileTimeUtc\s*=\s*\[long\]\$hostStartTimeFileTimeUtc' -and
    $supervisorSource -match 'hostExecutablePath\s*=\s*\$hostExecutablePath' -and
    $supervisorSource -match 'startupRequestId\s*=\s*\$startupRequestId' -and
    $supervisorSource -match '\[string\]\$startup\.startupRequestId -notmatch ''\^\[0-9a-f\]\{32\}\$'''
Add-Result `
    -Name 'supervisor publishes the stronger launch identity contract' `
    -Passed $recordContract `
    -Detail 'the protected record carries exact host path, file-time creation identity, and startup request ID'

$standardInputWrites = @([regex]::Matches(
    $supervisorSource,
    'StandardInput\.WriteLine\((?<Argument>[^)]*)\)'))
$retiredIngressMarkers = @(
    'chat' + '-command',
    'Newserv' + 'Chat',
    'Forwarded' + 'Line',
    'PSOBB-newserv-chat-' + 'ack',
    'on ' + '{0} cc',
    'protected-filesystem-' + 'control-v3')
$retiredIngressAbsent = -not ($retiredIngressMarkers | Where-Object {
    $supervisorSource.Contains($_, [System.StringComparison]::OrdinalIgnoreCase)
})
$nativeControlContract =
    $supervisorSource -match "controlProtocol\s*=\s*'protected-filesystem-exit-v2'" -and
    $supervisorSource -match '\$request\.action -ceq ''exit''' -and
    $supervisorSource -match '\$request\.action -ceq ''cancel-start''' -and
    $retiredIngressAbsent -and
    $standardInputWrites.Count -eq 2 -and
    @($standardInputWrites | Where-Object {
        $_.Groups['Argument'].Value.Trim() -cne "'exit'"
    }).Count -eq 0
Add-Result `
    -Name 'supervisor stdin accepts only native lifecycle shutdown' `
    -Passed $nativeControlContract `
    -Detail 'only authenticated exit/cancel-start requests remain and both stdin writes are the literal exit command'

$supervisorOwnsNoMutex =
    $supervisorSource -notmatch 'System\.Threading\.Mutex' -and
    $supervisorSource -notmatch 'Enter-PSOBBClientOperationLock' -and
    $supervisorSource -notmatch '\.WaitOne\('
Add-Result `
    -Name 'supervisor acquires neither lifecycle mutex' `
    -Passed $supervisorOwnsNoMutex `
    -Detail 'the guarded parent retains lifecycle serialization while the detached supervisor only validates protected state'

$claimFunction = @($supervisorAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Move-NewservControlRequestToClaim'
}, $true))
$claimFunctionLoaded = $claimFunction.Count -eq 1
if ($claimFunctionLoaded) {
    Invoke-Expression $claimFunction[0].Extent.Text
}
Add-Result `
    -Name 'supervisor exposes one fixed-request claim primitive' `
    -Passed $claimFunctionLoaded `
    -Detail "$($claimFunction.Count) exact claim function(s) found"

$handleCleanup =
    $startSource -match 'CloseHandle\(processInformation\.hThread\)' -and
    $startSource -match 'retainedProcessHandle\?\.Dispose\(\)' -and
    $startSource -match 'retainedJobHandle\?\.Dispose\(\)' -and
    $startSource -match '\$nativeHostIdentity\.Dispose\(\)'
Add-Result `
    -Name 'native handles have explicit scoped ownership' `
    -Passed $handleCleanup `
    -Detail 'the thread closes immediately while stable process and job handles remain owned until lifecycle startup finishes'

$launcherMatch = [regex]::Match(
    $startSource,
    "(?s)\`$nativeSupervisorLauncherSource\s*=\s*@'\r?\n(?<Source>.*?)\r?\n'@")
$dummyProcess = $null
$dummyChildProcess = $null
$dummyLaunch = $null
$exit259Launch = $null
$collisionProcess = $null
$collisionChildProcess = $null
$collisionLaunch = $null
$collisionChildPidPath = $null
$uninspectableProcess = $null
$uninspectableLaunch = $null
$unrelatedProcess = $null
$dummyChildPidPath = $null
$cleanupFixtureRoot = $null
try {
    if (-not $launcherMatch.Success) {
        throw 'The embedded native supervisor launcher source could not be located'
    }
    if (-not ('PSOBBLifecycle.NativeSupervisorLauncher' -as [type])) {
        Add-Type -TypeDefinition $launcherMatch.Groups['Source'].Value -Language CSharp
    }

    $cleanupFunctionNames = @(
        'ConvertTo-PSOBBSafeLifecycleDiagnostic',
        'Get-LaunchedSupervisorProbe',
        'Stop-ExactLaunchedSupervisorAfterFailure'
    )
    $cleanupFunctions = @($startAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -in $cleanupFunctionNames
    }, $true))
    if ($cleanupFunctions.Count -ne $cleanupFunctionNames.Count) {
        throw 'The exact supervisor cleanup functions could not be located'
    }
    foreach ($functionAst in $cleanupFunctions) {
        Invoke-Expression $functionAst.Extent.Text
    }

    function Write-ProtectedJson {
        param([string]$Path, $Value, [string]$Root, [switch]$CreateOnly)
        $null = $Root
        if ($CreateOnly -and (Test-Path -LiteralPath $Path)) {
            throw 'Fixture create-only path already exists'
        }
        [System.IO.File]::WriteAllText(
            $Path,
            ($Value | ConvertTo-Json -Depth 6),
            [System.Text.UTF8Encoding]::new($false))
    }
    function Assert-PathWithinRoot {
        param([string]$Path, [string]$Root)
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
        if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Fixture path escaped its root'
        }
        $fullPath
    }
    function Get-NewservProcessesAtPath {
        param($Layout)
        $null = $Layout
        @()
    }
    function Get-PSOBBReservedServerPortListeners {
        @()
    }
    function Get-PSOBBServerEnvironmentProcessRecords {
        param($Layout)
        $null = $Layout
        @()
    }

    $jsonDiagnostic = ConvertTo-PSOBBSafeLifecycleDiagnostic -Value (
        '{"password":"super-secret","token":"abc123"} 12000 | listener failed')
    Add-Result `
        -Name 'lifecycle diagnostics redact quoted JSON secrets without truncating pipe text' `
        -Passed (
            $jsonDiagnostic -eq '{"password":"[REDACTED]","token":"[REDACTED]"} 12000 | listener failed' -and
            $jsonDiagnostic -notmatch 'super-secret|abc123') `
        -Detail $jsonDiagnostic

    $pwshPath = Join-Path $PSHOME 'pwsh.exe'
    $exit259Launch = [PSOBBLifecycle.NativeSupervisorLauncher]::Start(
        $pwshPath,
        $repositoryRoot,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 259'))
    $exit259Exited = $exit259Launch.WaitForExit(5000)
    $exit259Probe = $exit259Launch.Probe(
        [System.IO.Path]::GetFullPath($pwshPath),
        [long]$exit259Launch.StartTimeFileTimeUtc)
    Add-Result `
        -Name 'exit code 259 is classified by handle signal state rather than STILL_ACTIVE' `
        -Passed ($exit259Exited -and [string]$exit259Probe.State -eq 'Absent') `
        -Detail "waited=$exit259Exited probe=$($exit259Probe.State)"

    $dummyChildPidPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        'psobb-supervisor-child-' + [Guid]::NewGuid().ToString('N') + '.pid')
    $encodedChildCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 30'))
    $escapedPwshPath = $pwshPath.Replace("'", "''")
    $escapedChildPidPath = $dummyChildPidPath.Replace("'", "''")
    $dummyCommand = @"
`$child = Start-Process -FilePath '$escapedPwshPath' -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', '$encodedChildCommand') -WindowStyle Hidden -PassThru
[System.IO.File]::WriteAllText('$escapedChildPidPath', [string]`$child.Id)
Start-Sleep -Seconds 30
"@
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $dummyLaunch = [PSOBBLifecycle.NativeSupervisorLauncher]::Start(
        $pwshPath,
        $repositoryRoot,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $dummyCommand))
    $dummyPid = [int]$dummyLaunch.ProcessId
    $stopwatch.Stop()
    $dummyProcess = Get-Process -Id $dummyPid -ErrorAction Stop
    $childPidDeadline = [DateTime]::UtcNow.AddSeconds(3)
    while (-not (Test-Path -LiteralPath $dummyChildPidPath -PathType Leaf) -and
        [DateTime]::UtcNow -lt $childPidDeadline) {
        Start-Sleep -Milliseconds 25
    }
    if (Test-Path -LiteralPath $dummyChildPidPath -PathType Leaf) {
        $dummyChildPid = [int]([System.IO.File]::ReadAllText($dummyChildPidPath))
        $dummyChildProcess = Get-Process -Id $dummyChildPid -ErrorAction Stop
    }
    $actualPath = [System.IO.Path]::GetFullPath($pwshPath)
    $actualStartFileTime = [long]$dummyLaunch.StartTimeFileTimeUtc
    $launchProbe = $dummyLaunch.Probe($actualPath, $actualStartFileTime)
    $childDetailPid = if ($dummyChildProcess) { [string]$dummyChildProcess.Id } else { 'unavailable' }
    Add-Result `
        -Name 'native launcher returns while a detached supervisor tree remains alive' `
        -Passed (
            $stopwatch.ElapsedMilliseconds -lt 3000 -and
            -not $dummyProcess.HasExited -and
            $null -ne $dummyChildProcess -and
            -not $dummyChildProcess.HasExited -and
            [string]$launchProbe.State -eq 'Verified' -and
            [long]$actualStartFileTime -eq [long]$dummyLaunch.StartTimeFileTimeUtc) `
        -Detail "returned in $($stopwatch.ElapsedMilliseconds) ms with verified supervisor PID $dummyPid and child PID $childDetailPid"

    $cleanupFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'psobb-supervisor-cleanup-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($cleanupFixtureRoot) | Out-Null
    $cleanupControlDirectory = Join-Path $cleanupFixtureRoot 'control'
    [System.IO.Directory]::CreateDirectory($cleanupControlDirectory) | Out-Null
    function Assert-PSOBBLifecyclePathAcl {
        param(
            [string]$Path,
            [string]$Root,
            [bool]$IsContainer
        )
        $null = $IsContainer
        Assert-PathWithinRoot -Path $Path -Root $Root | Out-Null
        $true
    }
    $fixtureLayout = [pscustomobject]@{
        Root = $cleanupFixtureRoot
        Environment = 'Stable'
        EnvironmentId = 'stable'
        ControlDirectory = $cleanupControlDirectory
        PidFile = Join-Path $cleanupControlDirectory 'newserv.process.json'
        LegacyPidFile = Join-Path $cleanupControlDirectory 'newserv.pid'
        HostPidFile = Join-Path $cleanupControlDirectory 'newserv-host.pid'
        ControlState = Join-Path $cleanupControlDirectory 'newserv-control.json'
        ControlRequest = Join-Path $cleanupControlDirectory 'newserv-control.request.json'
    }
    $firstRequestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '{"schemaVersion":1,"action":"cancel-start","sequence":1}')
    $secondRequestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '{"schemaVersion":1,"action":"exit","sequence":2}')
    [System.IO.File]::WriteAllBytes(
        $fixtureLayout.ControlRequest,
        $firstRequestBytes)
    $firstClaim = Move-NewservControlRequestToClaim `
        -ControlRequestPath $fixtureLayout.ControlRequest `
        -Root $fixtureLayout.Root
    [System.IO.File]::WriteAllBytes(
        $fixtureLayout.ControlRequest,
        $secondRequestBytes)
    Remove-Item -LiteralPath $firstClaim -Force
    $secondRequestSurvived =
        (Test-Path -LiteralPath $fixtureLayout.ControlRequest -PathType Leaf) -and
        [Convert]::ToBase64String(
            [System.IO.File]::ReadAllBytes($fixtureLayout.ControlRequest)) -ceq
            [Convert]::ToBase64String($secondRequestBytes)
    $secondClaim = Move-NewservControlRequestToClaim `
        -ControlRequestPath $fixtureLayout.ControlRequest `
        -Root $fixtureLayout.Root
    $secondClaimExact =
        -not (Test-Path -LiteralPath $fixtureLayout.ControlRequest) -and
        $secondClaim -cne $firstClaim -and
        [Convert]::ToBase64String(
            [System.IO.File]::ReadAllBytes($secondClaim)) -ceq
            [Convert]::ToBase64String($secondRequestBytes)
    Remove-Item -LiteralPath $secondClaim -Force
    Add-Result `
        -Name 'claim cleanup cannot erase a newer lifecycle request' `
        -Passed ($secondRequestSurvived -and $secondClaimExact) `
        -Detail 'the first unique claim was removed while the later fixed-name exit request survived and was claimed independently'
    $identity = [pscustomobject]@{
        Pid = $dummyProcess.Id
        ExecutablePath = $actualPath
        StartTimeFileTimeUtc = [long]$actualStartFileTime
        NativeIdentity = $dummyLaunch
    }
    $unrelatedProcess = Start-Process `
        -FilePath $pwshPath `
        -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            $encodedChildCommand) `
        -WindowStyle Hidden `
        -PassThru
    $wrongIdentity = $identity.PSObject.Copy()
    $wrongIdentity.StartTimeFileTimeUtc = [long]$identity.StartTimeFileTimeUtc + 1
    @(
        $fixtureLayout.PidFile,
        $fixtureLayout.LegacyPidFile,
        $fixtureLayout.HostPidFile,
        $fixtureLayout.ControlState
    ) | ForEach-Object { [System.IO.File]::WriteAllText($_, 'fixture') }
    Stop-ExactLaunchedSupervisorAfterFailure `
        -Layout $fixtureLayout `
        -Identity $wrongIdentity `
        -ControlToken ('A' * 43) `
        -StartupRequestId ('b' * 32) `
        -ControlIdentity ('c' * 64) `
        -ComponentId 'newserv-stable-release'
    $dummyProcess.Refresh()
    $dummyChildProcess.Refresh()
    $unrelatedProcess.Refresh()
    $remainingAfterMismatch = @(
        Get-ChildItem -LiteralPath $cleanupFixtureRoot -Force -File -Recurse)
    Add-Result `
        -Name 'mismatched probe still terminates only the authoritative retained job' `
        -Passed (
            $dummyProcess.HasExited -and
            $dummyChildProcess.HasExited -and
            -not $unrelatedProcess.HasExited -and
            $remainingAfterMismatch.Count -eq 0) `
        -Detail 'a one-tick probe mismatch issued no guessed PID action; the assigned job killed its supervisor and child while an unrelated sleeper remained active'

    $transientNativeIdentity = [pscustomobject]@{
        ProcessId = 4242
        ProbeCount = 0
    }
    $transientNativeIdentity | Add-Member -MemberType ScriptMethod -Name Probe -Value {
        param($expectedPath, $expectedStart)
        $null = $expectedPath
        $null = $expectedStart
        $this.ProbeCount++
        if ($this.ProbeCount -lt 3) {
            return [pscustomobject]@{
                State = 'Uninspectable'
                Detail = 'token=transient-secret'
            }
        }
        [pscustomobject]@{ State = 'Verified'; Detail = 'verified' }
    }
    $transientIdentity = [pscustomobject]@{
        Pid = 4242
        ExecutablePath = $pwshPath
        StartTimeFileTimeUtc = 1L
        NativeIdentity = $transientNativeIdentity
    }
    $transientProbe = Get-LaunchedSupervisorProbe `
        -Identity $transientIdentity `
        -ProbeAttempts 3 `
        -ProbeDelayMilliseconds 0
    Add-Result `
        -Name 'transient native inspection failures recover within the bounded probe' `
        -Passed (
            $transientProbe.State -eq 'Verified' -and
            $transientNativeIdentity.ProbeCount -eq 3) `
        -Detail 'two uninspectable results were retried before the stable handle verified'

    $incompleteProbe = Get-LaunchedSupervisorProbe `
        -Identity ([pscustomobject]@{ Pid = 4545 }) `
        -ProbeAttempts 1 `
        -ProbeDelayMilliseconds 0
    Add-Result `
        -Name 'incomplete launch identity returns a structured uninspectable result' `
        -Passed (
            $incompleteProbe.State -eq 'Uninspectable' -and
            $incompleteProbe.Detail -eq 'The stable native supervisor identity handle is unavailable.') `
        -Detail $incompleteProbe.Detail

    $persistentNativeIdentity = [pscustomobject]@{ ProcessId = 4343 }
    $persistentNativeIdentity | Add-Member -MemberType ScriptMethod -Name Probe -Value {
        param($expectedPath, $expectedStart)
        $null = $expectedPath
        $null = $expectedStart
        [pscustomobject]@{
            State = 'Uninspectable'
            Detail = "token=persistent-secret`u{1}"
        }
    }
    $persistentIdentity = [pscustomobject]@{
        Pid = 4343
        ExecutablePath = $pwshPath
        StartTimeFileTimeUtc = 1L
        NativeIdentity = $persistentNativeIdentity
    }
    $persistentProbe = Get-LaunchedSupervisorProbe `
        -Identity $persistentIdentity `
        -ProbeAttempts 2 `
        -ProbeDelayMilliseconds 0
    Add-Result `
        -Name 'persistent inspection failure is returned as a sanitized structured probe' `
        -Passed (
            $persistentProbe.State -eq 'Uninspectable' -and
            $persistentProbe.Detail -match 'token=\[REDACTED\]' -and
            $persistentProbe.Detail -notmatch 'persistent-secret' -and
            $persistentProbe.Detail.ToCharArray().Where({ [char]::IsControl($_) }).Count -eq 0) `
        -Detail $persistentProbe.Detail

    @(
        $fixtureLayout.PidFile,
        $fixtureLayout.LegacyPidFile,
        $fixtureLayout.HostPidFile,
        $fixtureLayout.ControlState
    ) | ForEach-Object { [System.IO.File]::WriteAllText($_, 'uninspectable-fixture') }
    $uninspectableLaunch = [PSOBBLifecycle.NativeSupervisorLauncher]::Start(
        $pwshPath,
        $repositoryRoot,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
            $encodedChildCommand))
    $uninspectableProcess = Get-Process `
        -Id ([int]$uninspectableLaunch.ProcessId) -ErrorAction Stop
    $uninspectableIdentity = [pscustomobject]@{
        Pid = $uninspectableProcess.Id
        NativeIdentity = $uninspectableLaunch
    }
    Stop-ExactLaunchedSupervisorAfterFailure `
        -Layout $fixtureLayout `
        -Identity $uninspectableIdentity `
        -ControlToken ('A' * 43) `
        -StartupRequestId ('b' * 32) `
        -ControlIdentity ('c' * 64) `
        -ComponentId 'newserv-stable-release'
    $uninspectableProcess.Refresh()
    $unrelatedProcess.Refresh()
    $remainingAfterUninspectable = @(
        Get-ChildItem -LiteralPath $cleanupFixtureRoot -Force -File -Recurse)
    Add-Result `
        -Name 'uninspectable probe still terminates only the authoritative retained job' `
        -Passed (
            $uninspectableProcess.HasExited -and
            -not $unrelatedProcess.HasExited -and
            $remainingAfterUninspectable.Count -eq 0 -and
            (Test-Path -LiteralPath $cleanupControlDirectory -PathType Container)) `
        -Detail 'missing path/time probe fields caused no guessed PID action; the assigned job terminated while an unrelated sleeper remained active'

    $collisionChildPidPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        'psobb-supervisor-collision-child-' + [Guid]::NewGuid().ToString('N') + '.pid')
    $escapedCollisionChildPidPath = $collisionChildPidPath.Replace("'", "''")
    $collisionCommand = @"
`$child = Start-Process -FilePath '$escapedPwshPath' -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', '$encodedChildCommand') -WindowStyle Hidden -PassThru
[System.IO.File]::WriteAllText('$escapedCollisionChildPidPath', [string]`$child.Id)
Start-Sleep -Seconds 30
"@
    $collisionLaunch = [PSOBBLifecycle.NativeSupervisorLauncher]::Start(
        $pwshPath,
        $repositoryRoot,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $collisionCommand))
    $collisionProcess = Get-Process -Id ([int]$collisionLaunch.ProcessId) -ErrorAction Stop
    $collisionChildDeadline = [DateTime]::UtcNow.AddSeconds(3)
    while (-not (Test-Path -LiteralPath $collisionChildPidPath -PathType Leaf) -and
        [DateTime]::UtcNow -lt $collisionChildDeadline) {
        Start-Sleep -Milliseconds 25
    }
    if (-not (Test-Path -LiteralPath $collisionChildPidPath -PathType Leaf)) {
        throw 'The collision fixture child did not publish its PID'
    }
    $collisionChildProcess = Get-Process -Id (
        [int]([System.IO.File]::ReadAllText($collisionChildPidPath))) -ErrorAction Stop
    $collisionIdentity = [pscustomobject]@{
        Pid = $collisionProcess.Id
        ExecutablePath = $actualPath
        StartTimeFileTimeUtc = [long]$collisionLaunch.StartTimeFileTimeUtc
        NativeIdentity = $collisionLaunch
    }
    @(
        $fixtureLayout.PidFile,
        $fixtureLayout.LegacyPidFile,
        $fixtureLayout.HostPidFile,
        $fixtureLayout.ControlState
    ) | ForEach-Object { [System.IO.File]::WriteAllText($_, 'collision-fixture') }
    [System.IO.File]::WriteAllText(
        $fixtureLayout.ControlRequest,
        'occupied-create-only-request')
    $collisionMessage = ''
    try {
        Stop-ExactLaunchedSupervisorAfterFailure `
            -Layout $fixtureLayout `
            -Identity $collisionIdentity `
            -ControlToken ('A' * 43) `
            -StartupRequestId ('b' * 32) `
            -ControlIdentity ('c' * 64) `
            -ComponentId 'newserv-stable-release'
    } catch {
        $collisionMessage = $_.Exception.Message
    }
    $collisionProcess.Refresh()
    $collisionChildProcess.Refresh()
    $unrelatedProcess.Refresh()
    $collisionRemainingFiles = @(
        Get-ChildItem -LiteralPath $cleanupFixtureRoot -Force -File -Recurse)
    Add-Result `
        -Name 'failed cancellation publication still terminates only the retained supervisor tree' `
        -Passed (
            $collisionMessage -match 'Cooperative failed-start cancellation failed after exact process and listener absence was verified' -and
            $collisionMessage -match 'create-only path already exists' -and
            $collisionProcess.HasExited -and
            $collisionChildProcess.HasExited -and
            -not $unrelatedProcess.HasExited -and
            $collisionRemainingFiles.Count -eq 0) `
        -Detail 'a fixed-request collision was reported only after the supervisor and child exited; an unrelated sleeper remained active'
} finally {
    if ($exit259Launch) {
        $exit259Launch.Dispose()
    }
    if ($dummyLaunch) {
        try {
            $dummyLaunch.TerminateTree(1)
            $dummyLaunch.WaitForExit(5000) | Out-Null
        } catch {
            # The normal cleanup path may already have closed every job process.
        }
        $dummyLaunch.Dispose()
    }
    if ($collisionLaunch) {
        try {
            $collisionLaunch.TerminateTree(1)
            $collisionLaunch.WaitForExit(5000) | Out-Null
        } catch {
            # The tested cleanup path may already have closed every job process.
        }
        $collisionLaunch.Dispose()
    }
    if ($uninspectableLaunch) {
        try {
            $uninspectableLaunch.TerminateTree(1)
            $uninspectableLaunch.WaitForExit(5000) | Out-Null
        } catch {
            # The tested cleanup path may already have closed every job process.
        }
        $uninspectableLaunch.Dispose()
    }
    if ($dummyProcess) {
        $dummyProcess.Dispose()
    }
    if ($dummyChildProcess) {
        $dummyChildProcess.Refresh()
        if (-not $dummyChildProcess.HasExited) {
            Stop-Process -Id $dummyChildProcess.Id -Force -ErrorAction SilentlyContinue
        }
        $dummyChildProcess.Dispose()
    }
    if ($collisionProcess) {
        $collisionProcess.Dispose()
    }
    if ($uninspectableProcess) {
        $uninspectableProcess.Dispose()
    }
    if ($collisionChildProcess) {
        $collisionChildProcess.Refresh()
        if (-not $collisionChildProcess.HasExited) {
            Stop-Process -Id $collisionChildProcess.Id -Force -ErrorAction SilentlyContinue
        }
        $collisionChildProcess.Dispose()
    }
    if ($unrelatedProcess) {
        $unrelatedProcess.Refresh()
        if (-not $unrelatedProcess.HasExited) {
            Stop-Process -Id $unrelatedProcess.Id -Force -ErrorAction SilentlyContinue
            $unrelatedProcess.WaitForExit(5000) | Out-Null
        }
        $unrelatedProcess.Dispose()
    }
    if ($dummyChildPidPath) {
        Remove-Item -LiteralPath $dummyChildPidPath -Force -ErrorAction SilentlyContinue
    }
    if ($collisionChildPidPath) {
        Remove-Item -LiteralPath $collisionChildPidPath -Force -ErrorAction SilentlyContinue
    }
    if ($cleanupFixtureRoot -and (Test-Path -LiteralPath $cleanupFixtureRoot)) {
        Remove-Item -LiteralPath $cleanupFixtureRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) supervisor-detachment test(s) failed"
}

[pscustomobject]@{
    Suite = 'SupervisorDetachment'
    Passed = $results.Count
    Failed = 0
}
