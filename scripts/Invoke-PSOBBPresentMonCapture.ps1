[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Lobby', 'Gameplay', 'Soak')]
    [string]$Scenario,

    [Parameter(Mandatory)]
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$Channel,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]+(?:-[a-z0-9]+)*$')]
    [string]$ProfileId,

    [string]$RuntimeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$durationByScenario = [ordered]@{
    Lobby = 120
    Gameplay = 600
    Soak = 1800
}

function Close-PSOBBPresentMonClientProcessRecords {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Records = @())

    foreach ($ownedRecord in @($Records)) {
        if ($null -ne $ownedRecord -and
            $ownedRecord.PSObject.Properties.Name -contains 'Process' -and
            $null -ne $ownedRecord.Process) {
            $ownedRecord.Process.Dispose()
            $ownedRecord.Process = $null
        }
    }
}

function Complete-PSOBBRedirectedOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Threading.Tasks.Task[string]]$StandardOutputTask,
        [Parameter(Mandatory)][System.Threading.Tasks.Task[string]]$StandardErrorTask,
        [Parameter(Mandatory)]
        [System.Threading.CancellationTokenSource]$CancellationSource,
        [ValidateRange(1, 30000)][int]$TimeoutMilliseconds = 5000
    )

    $deadline = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($drain in @($StandardOutputTask, $StandardErrorTask)) {
        $remaining = [Math]::Max(
            1,
            $TimeoutMilliseconds - [int]$deadline.ElapsedMilliseconds)
        if (-not $drain.Wait($remaining)) {
            $CancellationSource.Cancel()
            throw "Redirected process output did not drain within $TimeoutMilliseconds milliseconds"
        }
    }
    [pscustomobject]@{
        StandardOutput = $StandardOutputTask.GetAwaiter().GetResult()
        StandardError = $StandardErrorTask.GetAwaiter().GetResult()
    }
}

function Get-PSOBBValidatedCaptureProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][ValidateSet('Stable', 'Canary', 'LocalLab')][string]$SelectedChannel,
        [Parameter(Mandatory)][string]$SelectedProfileId
    )

    $catalogPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
    $catalog = Get-Content -Raw -LiteralPath $catalogPath | ConvertFrom-Json -Depth 50
    $catalogChannel = switch ($SelectedChannel) {
        'Stable' { 'stable' }
        'Canary' { 'canary' }
        'LocalLab' { 'local-lab' }
    }
    $declaredProfiles = @($catalog.profiles | Where-Object {
        [string]$_.id -ceq $SelectedProfileId -and
        [string]$_.channel -ceq $catalogChannel
    })
    if ([int]$catalog.schemaVersion -ne 1 -or $declaredProfiles.Count -ne 1) {
        throw "Profile '$SelectedProfileId' is not declared exactly once for channel '$catalogChannel'"
    }
    $declared = $declaredProfiles[0]
    $clientExecutable = Get-PSOBBClientExecutablePath `
        -Layout $Layout `
        -Channel $SelectedChannel
    $identity = Assert-PSOBBApprovedClientExecutable -Path $clientExecutable
    if ([string]$catalog.baseClient.executableSha256 -cne $identity.Sha256) {
        throw 'The graphics profile catalog does not match the approved PSOBB executable'
    }
    $clientRoot = Split-Path -Parent $clientExecutable
    $profilePath = Assert-PathWithinRoot `
        -Path (Join-Path $clientRoot 'client-profile.json') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        throw "The materialized client profile is missing: $profilePath"
    }

    $materialized = if ($SelectedChannel -eq 'LocalLab') {
        Assert-PSOBBLocalLabClientRuntimeContract -Layout $Layout
    } else {
        & (Join-Path $PSScriptRoot 'Test-PSOBBClientGraphics.ps1') `
            -Channel $SelectedChannel `
            -RuntimeRoot $Layout.Root | Out-Null
        Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -Depth 30
    }
    if (-not ([string]$materialized.baseExecutableSha256).Equals(
        $identity.Sha256,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The materialized client profile does not match the approved PSOBB executable'
    }

    $materializedProfileId = if ($materialized.PSObject.Properties.Name -contains 'profileId') {
        [string]$materialized.profileId
    } else {
        $legacyProfile = if ($SelectedChannel -eq 'Stable') {
            'safe-native-4x3'
        } elseif ($SelectedChannel -eq 'Canary') {
            'clarity-dgvoodoo-4x3'
        } else {
            ''
        }
        if ($SelectedProfileId -cne $legacyProfile) {
            throw "The legacy $SelectedChannel runtime has no explicit profile ID and can only identify as '$legacyProfile'"
        }
        $legacyProfile
    }
    if ($materializedProfileId -cne $SelectedProfileId) {
        throw "The running client materialization is '$materializedProfileId', not '$SelectedProfileId'"
    }

    if ($SelectedProfileId -ceq 'safe-native-4x3') {
        if ([string]$materialized.renderer -cne 'Native' -or
            [string]$declared.renderer.d3d8Owner.kind -cne 'application') {
            throw 'The native capture profile does not match the stable runtime renderer'
        }
    } else {
        if (-not ($materialized.PSObject.Properties.Name -contains 'outputApi') -or
            [string]$materialized.outputApi -cne [string]$declared.renderer.outputApi) {
            throw 'The materialized output API does not match the declared capture profile'
        }
        if ($materialized.PSObject.Properties.Name -contains 'renderWidth') {
            $renderCandidate = @($declared.display.internalRenderCandidates | Where-Object {
                [int]$_.width -eq [int]$materialized.renderWidth -and
                [int]$_.height -eq [int]$materialized.renderHeight
            })
            if ($renderCandidate.Count -ne 1 -or
                [string]$materialized.aspectPolicy -cne [string]$declared.display.aspectPolicy -or
                [int]$materialized.desktopWidth -ne [int]$declared.display.output.width -or
                [int]$materialized.desktopHeight -ne [int]$declared.display.output.height -or
                $materialized.watermarkEnabled -ne $false) {
                throw 'The materialized render, output, aspect, or watermark state does not match the declared capture profile'
            }
        }
    }

    [pscustomobject]@{
        ProfileId = $SelectedProfileId
        CatalogChannel = $catalogChannel
        Declared = $declared
        Materialized = $materialized
        ProfilePath = $profilePath
        ProfileSha256 = Get-LowerSha256 -Path $profilePath
        ClientExecutable = $clientExecutable
        ClientExecutableSha256 = $identity.Sha256
        ClientExecutableSize = $identity.Size
    }
}

function Get-PSOBBValidatedCaptureProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][ValidateSet('Stable', 'Canary', 'LocalLab')][string]$SelectedChannel
    )

    $records = @()
    try {
    $records = @(Get-PSOBBClientProcessRecords -Layout $Layout -Channel All)
    if ($records.Count -ne 1) {
        throw "PresentMon capture requires exactly one approved PSOBB client process; found $($records.Count)"
    }
    $record = $records[0]
    if ([string]$record.Channel -cne $SelectedChannel -or
        -not ([System.IO.Path]::GetFullPath([string]$record.ExecutablePath)).Equals(
            [System.IO.Path]::GetFullPath([string]$Profile.ClientExecutable),
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$record.ExecutableSha256).Equals(
            [string]$Profile.ClientExecutableSha256,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The sole running PSOBB client does not match the requested channel, path, or executable hash'
    }
    $process = $record.Process
    if (-not $process -or
        -not (Test-PSOBBProcessAtExactPath `
            -Process $process `
            -Name 'Psobb' `
            -ExpectedPath ([string]$Profile.ClientExecutable))) {
        throw 'The PSOBB client process identity could not be revalidated immediately before capture'
    }
    try {
        $startTimeUtc = $process.StartTime.ToUniversalTime()
        $startTimeFileTimeUtc = [long]$startTimeUtc.ToFileTimeUtc()
    } catch {
        throw "The creation time for approved PSOBB PID $($record.ProcessId) could not be verified"
    }
    if ($null -eq $record.StartTimeFileTimeUtc -or
        $startTimeFileTimeUtc -ne [long]$record.StartTimeFileTimeUtc) {
        throw 'The PSOBB process ID was reused before capture'
    }
    $validatedProcess = [pscustomobject]@{
        Process = $process
        ProcessId = [int]$process.Id
        StartTimeUtc = $startTimeUtc
        StartTimeFileTimeUtc = $startTimeFileTimeUtc
        Channel = [string]$record.Channel
        ExecutablePath = [string]$record.ExecutablePath
        ExecutableSha256 = [string]$record.ExecutableSha256
    }
    $record.Process = $null
    $validatedProcess
    } finally {
        Close-PSOBBPresentMonClientProcessRecords -Records $records
    }
}

function Get-PSOBBLockedPresentMon {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $sourcesPath = Join-Path $repositoryRoot 'config\sources.lock.json'
    $sources = Get-Content -Raw -LiteralPath $sourcesPath | ConvertFrom-Json -Depth 50
    $components = @($sources.components | Where-Object id -ceq 'presentmon-portable')
    if ($components.Count -ne 1 -or
        [string]$components[0].version -cne 'v2.5.1' -or
        [string]$components[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [long]$components[0].size -le 0) {
        throw 'sources.lock.json does not contain one valid PresentMon 2.5.1 component'
    }
    $component = $components[0]
    $path = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Archives 'graphics-lab\PresentMon-2.5.1-x64.exe') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The locked PresentMon executable is missing: $path"
    }
    $item = Get-Item -LiteralPath $path -Force
    $hash = Get-LowerSha256 -Path $path
    if ($item.Length -ne [long]$component.size -or $hash -cne [string]$component.sha256) {
        throw 'PresentMon does not match its locked size and SHA-256'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    $signerSubject = if ($signature.SignerCertificate) {
        [string]$signature.SignerCertificate.Subject
    } else {
        ''
    }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signerSubject.StartsWith('CN=Intel Corporation', [System.StringComparison]::Ordinal)) {
        throw "PresentMon does not have the required valid Intel Authenticode signature (status=$($signature.Status); signer=$signerSubject)"
    }
    [pscustomobject]@{
        Path = $path
        Version = [string]$component.version
        Size = [long]$item.Length
        Sha256 = $hash
        SignerSubject = $signerSubject
        SignerThumbprint = [string]$signature.SignerCertificate.Thumbprint
    }
}

function Assert-PSOBBCaptureIdentityUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$InitialProcess,
        [Parameter(Mandatory)][ValidateSet('Stable', 'Canary', 'LocalLab')][string]$SelectedChannel
    )

    $currentProfile = Get-PSOBBValidatedCaptureProfile `
        -Layout $Layout `
        -SelectedChannel $SelectedChannel `
        -SelectedProfileId ([string]$Profile.ProfileId)
    if ([string]$currentProfile.ProfileSha256 -cne [string]$Profile.ProfileSha256) {
        throw 'The materialized client profile changed during capture'
    }
    $currentProcess = $null
    try {
        $currentProcess = Get-PSOBBValidatedCaptureProcess `
            -Layout $Layout `
            -Profile $currentProfile `
            -SelectedChannel $SelectedChannel
        if ([int]$currentProcess.ProcessId -ne [int]$InitialProcess.ProcessId -or
            [long]$currentProcess.StartTimeFileTimeUtc -ne
                [long]$InitialProcess.StartTimeFileTimeUtc) {
            throw 'The PSOBB client exited or restarted during capture'
        }
        $true
    } finally {
        if ($currentProcess -and $currentProcess.Process) {
            $currentProcess.Process.Dispose()
        }
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$target = $null
try {
$durationSeconds = [int]$durationByScenario[$Scenario]
$profile = Get-PSOBBValidatedCaptureProfile `
    -Layout $layout `
    -SelectedChannel $Channel `
    -SelectedProfileId $ProfileId
$target = Get-PSOBBValidatedCaptureProcess `
    -Layout $layout `
    -Profile $profile `
    -SelectedChannel $Channel
$presentMon = Get-PSOBBLockedPresentMon -Layout $layout

$evidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Root 'graphics-evidence') `
    -Root $layout.Root
[void][System.IO.Directory]::CreateDirectory($evidenceRoot)
$profileEvidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $evidenceRoot $ProfileId) `
    -Root $layout.Root
[void][System.IO.Directory]::CreateDirectory($profileEvidenceRoot)
$runId = '{0}-{1}-{2}' -f `
    [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), `
    $Scenario.ToLowerInvariant(), `
    [Guid]::NewGuid().ToString('N').Substring(0, 12)
$runRoot = Assert-PathWithinRoot `
    -Path (Join-Path $profileEvidenceRoot $runId) `
    -Root $layout.Root
if (Test-Path -LiteralPath $runRoot) {
    throw "The unique graphics-evidence run directory already exists: $runRoot"
}
[void][System.IO.Directory]::CreateDirectory($runRoot)

$csvPath = Join-Path $runRoot 'presentmon-v2.csv'
$stdoutPath = Join-Path $runRoot 'presentmon.stdout.log'
$stderrPath = Join-Path $runRoot 'presentmon.stderr.log'
$metricsPath = Join-Path $runRoot 'presentmon-metrics.json'
$telemetryBeforePath = Join-Path $runRoot 'telemetry-before.json'
$telemetryAfterPath = Join-Path $runRoot 'telemetry-after.json'
$manifestPath = Join-Path $runRoot 'capture-manifest.json'
$sessionName = 'PSOBB-{0}' -f [Guid]::NewGuid().ToString('N')
$arguments = @(
    '--process_id', [string]$target.ProcessId,
    '--output_file', $csvPath,
    '--session_name', $sessionName,
    '--timed', [string]$durationSeconds,
    '--terminate_after_timed',
    '--terminate_on_proc_exit',
    '--v2_metrics',
    '--no_track_input',
    '--no_console_stats'
)

$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $presentMon.Path
$startInfo.WorkingDirectory = Split-Path -Parent $presentMon.Path
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
foreach ($argument in $arguments) {
    $startInfo.ArgumentList.Add([string]$argument)
}

$telemetryBefore = & (Join-Path $PSScriptRoot 'Capture-PSOBBGraphicsTelemetry.ps1') `
    -Channel $Channel -ProfileId $ProfileId -Phase Before -Scenario $Scenario `
    -OutputPath $telemetryBeforePath -RuntimeRoot $layout.Root
$captureStartedAtUtc = [DateTime]::UtcNow
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$captureProcess = $null
$stdoutTask = $null
$stderrTask = $null
$outputCancellation = $null
$stdout = ''
$stderr = ''
try {
    $captureProcess = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $captureProcess) {
        throw 'Windows did not start the locked PresentMon executable'
    }
    $outputCancellation = [System.Threading.CancellationTokenSource]::new()
    $stdoutTask = $captureProcess.StandardOutput.ReadToEndAsync(
        $outputCancellation.Token)
    $stderrTask = $captureProcess.StandardError.ReadToEndAsync(
        $outputCancellation.Token)
    $maximumWaitMilliseconds = [int](($durationSeconds + 90) * 1000)
    if (-not $captureProcess.WaitForExit($maximumWaitMilliseconds)) {
        try { $captureProcess.Kill($true) } catch { }
        if (-not $captureProcess.WaitForExit(10000)) {
            throw 'PresentMon did not terminate within 10 seconds after cancellation'
        }
        throw "PresentMon did not exit within 90 seconds after the $durationSeconds-second capture window"
    }
    $drainedOutput = Complete-PSOBBRedirectedOutput `
        -StandardOutputTask $stdoutTask `
        -StandardErrorTask $stderrTask `
        -CancellationSource $outputCancellation
    $stdout = $drainedOutput.StandardOutput
    $stderr = $drainedOutput.StandardError
    if ($captureProcess.ExitCode -ne 0) {
        throw "PresentMon failed with exit code $($captureProcess.ExitCode): $($stderr.Trim())"
    }
} finally {
    $stopwatch.Stop()
    if ($outputCancellation) {
        $outputCancellation.Cancel()
        $outputCancellation.Dispose()
    }
    [System.IO.File]::WriteAllText($stdoutPath, $stdout, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($stderrPath, $stderr, [System.Text.UTF8Encoding]::new($false))
    if ($captureProcess) {
        $captureProcess.Dispose()
    }
}

if ($stopwatch.Elapsed.TotalSeconds -lt ($durationSeconds - 2)) {
    throw "PresentMon returned before the required $durationSeconds-second $Scenario capture completed"
}
Assert-PSOBBCaptureIdentityUnchanged `
    -Layout $layout `
    -Profile $profile `
    -InitialProcess $target `
    -SelectedChannel $Channel | Out-Null
$telemetryAfter = & (Join-Path $PSScriptRoot 'Capture-PSOBBGraphicsTelemetry.ps1') `
    -Channel $Channel -ProfileId $ProfileId -Phase After -Scenario $Scenario `
    -OutputPath $telemetryAfterPath -RuntimeRoot $layout.Root
$presentMonAfter = Get-PSOBBLockedPresentMon -Layout $layout
if ([string]$presentMonAfter.Sha256 -cne [string]$presentMon.Sha256) {
    throw 'The PresentMon executable changed during capture'
}
if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf) -or
    (Get-Item -LiteralPath $csvPath -Force).Length -le 0) {
    throw 'PresentMon completed without producing a non-empty v2 CSV'
}

$metrics = & (Join-Path $PSScriptRoot 'Get-PSOBBPresentMonMetrics.ps1') `
    -CsvPath $csvPath `
    -ExpectedProcessId $target.ProcessId `
    -ExpectedApplication 'Psobb.exe' `
    -OutputPath $metricsPath
if ([int]$metrics.inputTracking.validInputLatencySampleCount -ne 0) {
    throw 'PresentMon produced input-latency samples despite the mandatory --no_track_input option'
}

$completedAtUtc = [DateTime]::UtcNow
$relativeExecutable = [System.IO.Path]::GetRelativePath(
    $layout.Root,
    [string]$target.ExecutablePath).Replace('\', '/')
$manifest = [ordered]@{
    schemaVersion = 1
    runId = $runId
    scenario = $Scenario.ToLowerInvariant()
    requiredDurationSeconds = $durationSeconds
    observedWallClockSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
    startedAtUtc = $captureStartedAtUtc.ToString('o')
    completedAtUtc = $completedAtUtc.ToString('o')
    channel = $profile.CatalogChannel
    profile = [ordered]@{
        id = $ProfileId
        materializedFile = 'client-profile.json'
        materializedSha256 = $profile.ProfileSha256
    }
    target = [ordered]@{
        application = 'Psobb.exe'
        processId = $target.ProcessId
        processStartTimeUtc = ([DateTime]$target.StartTimeUtc).ToString('o')
        processStartTimeFileTimeUtc = [long]$target.StartTimeFileTimeUtc
        executable = 'runtime:' + $relativeExecutable
        executableSize = $profile.ClientExecutableSize
        executableSha256 = $profile.ClientExecutableSha256
    }
    presentMon = [ordered]@{
        componentId = 'presentmon-portable'
        version = $presentMon.Version
        byteSize = $presentMon.Size
        sha256 = $presentMon.Sha256
        authenticodeStatus = 'Valid'
        signerSubject = $presentMon.SignerSubject
        signerThumbprint = $presentMon.SignerThumbprint
        sessionName = $sessionName
        metricsVersion = 2
        inputTracking = $false
        displayTracking = $true
        gpuTracking = $true
        options = @(
            '--process_id <validated-pid>',
            '--output_file presentmon-v2.csv',
            '--session_name <unique-guid>',
            "--timed $durationSeconds",
            '--terminate_after_timed',
            '--terminate_on_proc_exit',
            '--v2_metrics',
            '--no_track_input',
            '--no_console_stats'
        )
    }
    artifacts = @(
        [ordered]@{
            file = 'presentmon-v2.csv'
            byteSize = (Get-Item -LiteralPath $csvPath -Force).Length
            sha256 = Get-LowerSha256 -Path $csvPath
        },
        [ordered]@{
            file = 'presentmon-metrics.json'
            byteSize = (Get-Item -LiteralPath $metricsPath -Force).Length
            sha256 = Get-LowerSha256 -Path $metricsPath
        },
        [ordered]@{
            file = 'presentmon.stdout.log'
            byteSize = (Get-Item -LiteralPath $stdoutPath -Force).Length
            sha256 = Get-LowerSha256 -Path $stdoutPath
        },
        [ordered]@{
            file = 'presentmon.stderr.log'
            byteSize = (Get-Item -LiteralPath $stderrPath -Force).Length
            sha256 = Get-LowerSha256 -Path $stderrPath
        },
        [ordered]@{
            file = 'telemetry-before.json'
            byteSize = (Get-Item -LiteralPath $telemetryBeforePath -Force).Length
            sha256 = [string]$telemetryBefore.Sha256
        },
        [ordered]@{
            file = 'telemetry-after.json'
            byteSize = (Get-Item -LiteralPath $telemetryAfterPath -Force).Length
            sha256 = [string]$telemetryAfter.Sha256
        }
    )
}
$temporaryManifest = $manifestPath + '.new'
try {
    [System.IO.File]::WriteAllText(
        $temporaryManifest,
        ($manifest | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryManifest -Destination $manifestPath
} finally {
    if (Test-Path -LiteralPath $temporaryManifest) {
        Remove-Item -LiteralPath $temporaryManifest -Force
    }
}

[pscustomobject]@{
    Captured = $true
    Scenario = $Scenario
    DurationSeconds = $durationSeconds
    Channel = $Channel
    ProfileId = $ProfileId
    ProcessId = $target.ProcessId
    RunId = $runId
    EvidenceRoot = $runRoot
    CsvPath = $csvPath
    MetricsPath = $metricsPath
    TelemetryBeforePath = $telemetryBeforePath
    TelemetryAfterPath = $telemetryAfterPath
    ManifestPath = $manifestPath
    DominantSwapChain = $metrics.selection.dominantSwapChainAddress
    FrameTimeP50Ms = $metrics.frameTime.p50
    FrameTimeP95Ms = $metrics.frameTime.p95
    FrameTimeP99Ms = $metrics.frameTime.p99
}
} finally {
    if ($target -and $target.Process) {
        $target.Process.Dispose()
    }
}
