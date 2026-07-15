[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
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
[System.Management.Automation.Language.Parser]::ParseFile(
    $supervisorPath,
    [ref]$supervisorTokens,
    [ref]$supervisorParseErrors) | Out-Null
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
    $startSource -match 'Get-Process -Id \$hostProcessId -ErrorAction Stop' -and
    $startSource -match '\$observedHostPath\s*=\s*\[System\.IO\.Path\]::GetFullPath\(\$hostProcess\.Path\)' -and
    $startSource -match '\$observedHostStartFileTime\s*=\s*\$hostProcess\.StartTime\.ToUniversalTime\(\)\.ToFileTimeUtc\(\)' -and
    $startSource -match '\[int\]\$record\.hostPid -ne \$hostProcess\.Id' -and
    $startSource -match '\[long\]\$record\.hostStartTimeFileTimeUtc -ne \[long\]\$hostIdentity\.StartTimeFileTimeUtc' -and
    $startSource -match '\[string\]\$record\.startupRequestId -ne \$startupRequestId'
Add-Result `
    -Name 'supervisor identity is attached by path, start time, PID, and request ID' `
    -Passed $identityContract `
    -Detail 'the native PID is verified immediately and matched against the protected supervisor record'

$failureCleanupContract =
    $startSource -match "action\s*=\s*'cancel-start'" -and
    $startSource -match 'Get-ExactLaunchedSupervisor -Identity \$Identity' -and
    $startSource -match '\$revalidated\.Kill\(\$true\)' -and
    $startSource -match 'Stop-ExactLaunchedSupervisorAfterFailure\s*`' -and
    $startSource -match 'A newserv process remains after supervisor cleanup' -and
    $supervisorSource -match '\$request\.action -eq ''cancel-start''' -and
    $supervisorSource -match '\[long\]\$request\.hostStartTimeFileTimeUtc -eq \[long\]\$hostStartTimeFileTimeUtc' -and
    $supervisorSource -match '\[string\]\$request\.startupRequestId -eq \$startupRequestId'
Add-Result `
    -Name 'failed startup cancels or force-cleans only the verified supervisor tree' `
    -Passed $failureCleanupContract `
    -Detail 'authenticated cancellation is followed by path/start-time revalidation before process-tree termination'

$recordContract =
    $supervisorSource -match 'hostStartTimeFileTimeUtc\s*=\s*\[long\]\$hostStartTimeFileTimeUtc' -and
    $supervisorSource -match 'hostExecutablePath\s*=\s*\$hostExecutablePath' -and
    $supervisorSource -match 'startupRequestId\s*=\s*\$startupRequestId' -and
    $supervisorSource -match '\[string\]\$startup\.startupRequestId -notmatch ''\^\[0-9a-f\]\{32\}\$'''
Add-Result `
    -Name 'supervisor publishes the stronger launch identity contract' `
    -Passed $recordContract `
    -Detail 'the protected record carries exact host path, file-time creation identity, and startup request ID'

$handleCleanup =
    $startSource -match 'CloseHandle\(processInformation\.hThread\)' -and
    $startSource -match 'CloseHandle\(processInformation\.hProcess\)'
Add-Result `
    -Name 'native process and thread handles are closed after launch' `
    -Passed $handleCleanup `
    -Detail 'the supervisor remains alive by PID without leaking launcher-owned native handles'

$launcherMatch = [regex]::Match(
    $startSource,
    "(?s)\`$nativeSupervisorLauncherSource\s*=\s*@'\r?\n(?<Source>.*?)\r?\n'@")
$dummyProcess = $null
$cleanupFixtureRoot = $null
try {
    if (-not $launcherMatch.Success) {
        throw 'The embedded native supervisor launcher source could not be located'
    }
    if (-not ('PSOBBLifecycle.NativeSupervisorLauncher' -as [type])) {
        Add-Type -TypeDefinition $launcherMatch.Groups['Source'].Value -Language CSharp
    }

    $cleanupFunctionNames = @(
        'Get-ExactLaunchedSupervisor',
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
        param([string]$Path, $Value, [string]$Root)
        $null = $Root
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

    $pwshPath = Join-Path $PSHOME 'pwsh.exe'
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $dummyLaunch = [PSOBBLifecycle.NativeSupervisorLauncher]::Start(
        $pwshPath,
        $repositoryRoot,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30'))
    $dummyPid = [int]$dummyLaunch.ProcessId
    $stopwatch.Stop()
    $dummyProcess = Get-Process -Id $dummyPid -ErrorAction Stop
    $actualPath = [System.IO.Path]::GetFullPath($dummyProcess.Path)
    $actualStartFileTime = $dummyProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    Add-Result `
        -Name 'native launcher returns while a detached child remains alive' `
        -Passed (
            $stopwatch.ElapsedMilliseconds -lt 3000 -and
            -not $dummyProcess.HasExited -and
            $actualPath -ceq [System.IO.Path]::GetFullPath($pwshPath) -and
            [long]$actualStartFileTime -eq [long]$dummyLaunch.StartTimeFileTimeUtc) `
        -Detail "returned in $($stopwatch.ElapsedMilliseconds) ms with verified PID $dummyPid"

    $cleanupFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'psobb-supervisor-cleanup-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($cleanupFixtureRoot) | Out-Null
    $fixtureLayout = [pscustomobject]@{
        Root = $cleanupFixtureRoot
        PidFile = Join-Path $cleanupFixtureRoot 'newserv.process.json'
        LegacyPidFile = Join-Path $cleanupFixtureRoot 'newserv.pid'
        HostPidFile = Join-Path $cleanupFixtureRoot 'newserv-host.pid'
        ControlState = Join-Path $cleanupFixtureRoot 'newserv-control.json'
        ControlRequest = Join-Path $cleanupFixtureRoot 'newserv-control-request.json'
    }
    $identity = [pscustomobject]@{
        Pid = $dummyProcess.Id
        ExecutablePath = $actualPath
        StartTimeFileTimeUtc = $dummyProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    }
    $wrongIdentity = $identity.PSObject.Copy()
    $wrongIdentity.StartTimeFileTimeUtc = [long]$identity.StartTimeFileTimeUtc + 1
    Stop-ExactLaunchedSupervisorAfterFailure `
        -Layout $fixtureLayout `
        -Identity $wrongIdentity `
        -ControlToken ('A' * 43) `
        -StartupRequestId ('b' * 32)
    $dummyProcess.Refresh()
    Add-Result `
        -Name 'cleanup refuses a PID whose creation identity does not match' `
        -Passed (-not $dummyProcess.HasExited) `
        -Detail 'a one-tick creation-time mismatch left the live dummy supervisor untouched'

    @(
        $fixtureLayout.PidFile,
        $fixtureLayout.LegacyPidFile,
        $fixtureLayout.HostPidFile,
        $fixtureLayout.ControlState
    ) | ForEach-Object { [System.IO.File]::WriteAllText($_, 'fixture') }
    Stop-ExactLaunchedSupervisorAfterFailure `
        -Layout $fixtureLayout `
        -Identity $identity `
        -ControlToken ('A' * 43) `
        -StartupRequestId ('b' * 32)
    $dummyProcess.Refresh()
    $remainingFixtureFiles = @(Get-ChildItem -LiteralPath $cleanupFixtureRoot -Force)
    Add-Result `
        -Name 'live failed-start cleanup terminates the exact detached supervisor' `
        -Passed ($dummyProcess.HasExited -and $remainingFixtureFiles.Count -eq 0) `
        -Detail 'authenticated cancellation timed out, then exact path/start-time revalidation allowed process-tree cleanup'
} finally {
    if ($dummyProcess) {
        $dummyProcess.Refresh()
        if (-not $dummyProcess.HasExited -and
            [System.IO.Path]::GetFullPath($dummyProcess.Path) -ceq
                [System.IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))) {
            $dummyProcess.Kill($true)
            $dummyProcess.WaitForExit(5000) | Out-Null
        }
        $dummyProcess.Dispose()
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
