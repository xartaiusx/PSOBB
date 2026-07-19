[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$captureScript = Join-Path $repositoryRoot 'scripts\Invoke-PSOBBPresentMonCapture.ps1'
$metricsScript = Join-Path $repositoryRoot 'scripts\Get-PSOBBPresentMonMetrics.ps1'
$telemetryScript = Join-Path $repositoryRoot 'scripts\Capture-PSOBBGraphicsTelemetry.ps1'
$captureSource = Get-Content -Raw -LiteralPath $captureScript
$metricsSource = Get-Content -Raw -LiteralPath $metricsScript
$telemetrySource = Get-Content -Raw -LiteralPath $telemetryScript
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

foreach ($scriptPath in @($captureScript, $metricsScript, $telemetryScript)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors) | Out-Null
    Add-Result `
        -Name "$(Split-Path -Leaf $scriptPath) parses cleanly" `
        -Passed ($parseErrors.Count -eq 0) `
        -Detail "$($parseErrors.Count) parser error(s)"
}

$durationContract =
    $captureSource -match '(?m)^\s*Lobby\s*=\s*120\s*$' -and
    $captureSource -match '(?m)^\s*Gameplay\s*=\s*600\s*$' -and
    $captureSource -match '(?m)^\s*Soak\s*=\s*1800\s*$' -and
    $captureSource -notmatch '(?m)^\s*\[int\]\$Duration'
Add-Result 'capture scenarios have fixed acceptance durations' $durationContract `
    'lobby=120s; gameplay=600s; soak=1800s; no arbitrary duration parameter'

$artifactGuard =
    $captureSource -match "id -ceq 'presentmon-portable'" -and
    $captureSource -match "version -cne 'v2\.5\.1'" -and
    $captureSource -match 'component\.size' -and
    $captureSource -match 'component\.sha256' -and
    $captureSource -match 'Get-AuthenticodeSignature' -and
    $captureSource -match 'SignatureStatus\]::Valid' -and
    $captureSource -match 'CN=Intel Corporation'
Add-Result 'capture requires the locked signed PresentMon 2.5.1 binary' $artifactGuard `
    'component/version/size/SHA-256 and valid Intel Authenticode signature are mandatory'

$clientGuard =
    $captureSource -match 'Get-PSOBBValidatedCaptureProfile' -and
    $captureSource -match 'Get-PSOBBClientProcessRecords -Layout \$Layout -Channel All' -and
    $captureSource -match 'records\.Count -ne 1' -and
    $captureSource -match 'Test-PSOBBProcessAtExactPath' -and
    $captureSource -match 'Assert-PSOBBApprovedClientExecutable' -and
    $captureSource -match 'StartTimeUtc' -and
    $captureSource -match 'Assert-PSOBBCaptureIdentityUnchanged'
Add-Result 'capture pins one exact running PSOBB profile and process' $clientGuard `
    'catalog, materialized profile, path, hash, PID, and start time are checked before and after capture'

$telemetryContract =
    $captureSource -match 'Capture-PSOBBGraphicsTelemetry\.ps1' -and
    $captureSource -match 'telemetry-before\.json' -and
    $captureSource -match 'telemetry-after\.json' -and
    $telemetrySource -match 'workingSetBytes' -and
    $telemetrySource -match 'privateBytes' -and
    $telemetrySource -match 'memoryUsedMiB' -and
    $telemetrySource -match 'temperatureC' -and
    $telemetrySource -match 'hardwareThermalSlowdown' -and
    $telemetrySource -match 'hardwarePowerBrakeSlowdown' -and
    $telemetrySource -match 'perApplicationUserGpuPreferencePresent' -and
    $telemetrySource -match 'windowedGameOptimizationPolicy' -and
    $telemetrySource -match 'startupEvidence' -and
    $telemetrySource -match 'startupElapsedMilliseconds' -and
    $telemetrySource -match '\[DateTimeOffset\]::Parse' -and
    $telemetrySource -match '\[Globalization\.DateTimeStyles\]::RoundtripKind' -and
    $telemetrySource -match 'Assert-PSOBBLocalLabClientRuntimeContract' -and
    $telemetrySource -notmatch '(?i)password|credential|account'
Add-Result 'capture binds before/after memory, GPU, thermal, and throttle telemetry' `
    $telemetryContract `
    'two hash-bound telemetry artifacts accompany every timed PresentMon run'

$utcSample = '2026-07-15T21:35:51.4621924Z'
$parsedUtcSample = [DateTimeOffset]::Parse(
    $utcSample,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::RoundtripKind).UtcDateTime
$utcReceiptComparisonValid =
    $parsedUtcSample.Kind -eq [DateTimeKind]::Utc -and
    $parsedUtcSample.ToString('o') -ceq '2026-07-15T21:35:51.4621924Z'
Add-Result 'startup receipt timestamps preserve UTC across local time zones' `
    $utcReceiptComparisonValid $parsedUtcSample.ToString('o')

$requiredOptions = @(
    '--process_id',
    '--output_file',
    '--session_name',
    '--timed',
    '--terminate_after_timed',
    '--terminate_on_proc_exit',
    '--v2_metrics',
    '--no_track_input',
    '--no_console_stats'
)
$missingOptions = @($requiredOptions | Where-Object {
    -not $captureSource.Contains("'$_'", [System.StringComparison]::Ordinal)
})
$blockedOptions = @(
    '--stop_existing_session',
    '--terminate_existing_session',
    '--restart_as_admin',
    '--exclude_dropped',
    '--no_track_display',
    '--no_track_gpu'
)
$presentMonCommandSafe = $missingOptions.Count -eq 0 -and
    @($blockedOptions | Where-Object {
        $captureSource.Contains("'$_'", [System.StringComparison]::Ordinal)
    }).Count -eq 0
Add-Result 'capture command retains display/GPU/dropped data and disables input tracking' `
    $presentMonCommandSafe "missing=$($missingOptions -join ',')"

$evidenceIsolation =
    $captureSource -match 'Join-Path \$layout\.Root ''graphics-evidence''' -and
    $captureSource -match 'Assert-PathWithinRoot' -and
    $captureSource -match 'PSOBB-\{0\}' -and
    $captureSource -match "Guid\]::NewGuid\(\)\.ToString\('N'\)" -and
    $captureSource -notmatch '(?i)password|credential|username|accountname'
Add-Result 'capture uses unique credential-free evidence and ETW identities' $evidenceIsolation `
    'raw artifacts remain under runtime graphics-evidence with GUID-based run and session names'

$streamingAnalysis =
    $metricsSource -match 'TextFieldParser' -and
    $metricsSource -match 'Get-PSOBBStreamingSha256' -and
    $metricsSource -notmatch 'Import-Csv|ReadAllBytes' -and
    $metricsSource -match 'unambiguous dominant swapchain' -and
    $metricsSource -match 'MsBetweenPresents' -and
    $metricsSource -match 'MsBetweenDisplayChange' -and
    $metricsSource -match 'DisplayLatency' -and
    $metricsSource -match 'validInputLatencySampleCount'
Add-Result 'metrics analysis streams and reports availability honestly' $streamingAnalysis `
    'two-pass CSV parsing avoids row-object retention and preserves NA/invalid counts'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-PresentMonTests-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
try {
    $fixturePath = Join-Path $temporaryRoot 'presentmon-v2.csv'
    $metricsPath = Join-Path $temporaryRoot 'presentmon-metrics.json'
    $rows = [System.Collections.Generic.List[object]]::new()

    function Add-FixtureRow {
        param(
            [int]$ProcessId,
            [string]$SwapChain,
            [double]$FrameMs,
            [string]$DisplayedTime,
            [string]$GpuLatency,
            [string]$GpuWait,
            [string]$Mode,
            [int]$Tearing
        )

        $rows.Add([pscustomobject][ordered]@{
            Application = 'Psobb.exe'
            ProcessID = $ProcessId
            SwapChainAddress = $SwapChain
            PresentRuntime = 'DXGI'
            AllowsTearing = $Tearing
            PresentMode = $Mode
            DisplayedTime = $DisplayedTime
            MsBetweenPresents = $FrameMs.ToString(
                [System.Globalization.CultureInfo]::InvariantCulture)
            MsBetweenDisplayChange = $FrameMs.ToString(
                [System.Globalization.CultureInfo]::InvariantCulture)
            MsGPULatency = $GpuLatency
            MsGPUTime = '3.0'
            MsGPUBusy = '2.5'
            MsGPUWait = $GpuWait
            DisplayLatency = '5.0'
            MsUntilDisplayed = '1.0'
            MsRenderPresentLatency = '2.0'
            MsInPresentAPI = '0.2'
            MsCPUBusy = '1.5'
            MsClickToPhotonLatency = 'NA'
            MsAllInputToPhotonLatency = 'NA'
        })
    }

    $frameValues = @(10.0, 10.0, 10.0, 10.0, 20.0, 100.1, 10.0, 10.0)
    for ($index = 0; $index -lt $frameValues.Count; $index++) {
        Add-FixtureRow `
            -ProcessId 4242 `
            -SwapChain '0xABC' `
            -FrameMs $frameValues[$index] `
            -DisplayedTime $(if ($index -eq 6) { 'NA' } else { '10.0' }) `
            -GpuLatency $(if ($index -eq 7) { 'NA' } else { '2.0' }) `
            -GpuWait 'NA' `
            -Mode $(if ($index -lt 6) { 'Composed: Flip' } else { 'Hardware: Independent Flip' }) `
            -Tearing $(if ($index -ge 6) { 1 } else { 0 })
    }
    foreach ($index in 1..2) {
        Add-FixtureRow -ProcessId 4242 -SwapChain '0xDEF' -FrameMs 8 `
            -DisplayedTime '8' -GpuLatency '1' -GpuWait '0' `
            -Mode 'Composed: Flip' -Tearing 0
    }
    foreach ($index in 1..9) {
        Add-FixtureRow -ProcessId 9001 -SwapChain '0xOTHER' -FrameMs 4 `
            -DisplayedTime '4' -GpuLatency '1' -GpuWait '0' `
            -Mode 'Composed: Flip' -Tearing 0
    }
    [System.IO.File]::WriteAllLines(
        $fixturePath,
        @($rows | ConvertTo-Csv -NoTypeInformation),
        [System.Text.UTF8Encoding]::new($false))

    $metrics = & $metricsScript `
        -CsvPath $fixturePath `
        -ExpectedProcessId 4242 `
        -ExpectedApplication 'Psobb.exe' `
        -OutputPath $metricsPath
    $dominantSelectionValid =
        [int]$metrics.selection.dominantProcessId -eq 4242 -and
        [string]$metrics.selection.dominantSwapChainAddress -ceq '0xABC' -and
        [long]$metrics.selection.candidateRowCount -eq 10 -and
        [long]$metrics.selection.dominantRowCount -eq 8 -and
        [double]$metrics.selection.dominantSharePercent -eq 80
    Add-Result 'metrics select the dominant swapchain after PID filtering' `
        $dominantSelectionValid "swapchain=$($metrics.selection.dominantSwapChainAddress); rows=$($metrics.selection.dominantRowCount)"

    $percentilesValid =
        [double]$metrics.frameTime.p50 -eq 10 -and
        [double]$metrics.frameTime.p95 -eq 72.065 -and
        [double]$metrics.frameTime.p99 -eq 94.493 -and
        [string]$metrics.cadence.sourceColumn -ceq 'MsBetweenDisplayChange' -and
        [int]$metrics.cadence.missCount -eq 2 -and
        [int]$metrics.cadence.over100MsStallCount -eq 1
    Add-Result 'metrics compute p50/p95/p99 and strict cadence thresholds' `
        $percentilesValid "p50=$($metrics.frameTime.p50); p95=$($metrics.frameTime.p95); p99=$($metrics.frameTime.p99)"

    $availabilityValid =
        [int]$metrics.frames.displayedTimeNaOrNotDisplayedCount -eq 1 -and
        [string]$metrics.gpuAndLatency.gpuLatency.status -ceq 'available' -and
        [int]$metrics.gpuAndLatency.gpuLatency.naCount -eq 1 -and
        [string]$metrics.gpuAndLatency.gpuWait.status -ceq 'unavailable' -and
        [int]$metrics.gpuAndLatency.gpuWait.naCount -eq 8 -and
        [int]$metrics.inputTracking.validInputLatencySampleCount -eq 0
    Add-Result 'metrics preserve dropped, NA, GPU, latency, and input availability' `
        $availabilityValid "dropped=$($metrics.frames.displayedTimeNaOrNotDisplayedCount); input=$($metrics.inputTracking.validInputLatencySampleCount)"

    $compactSchemaPath = Join-Path $temporaryRoot 'presentmon-v2-live-compact.csv'
    $compactSchemaRows = @(
        [pscustomobject][ordered]@{
            Application = 'Psobb.exe'
            ProcessID = 4242
            SwapChainAddress = '0xABC'
            PresentRuntime = 'DXGI'
            AllowsTearing = 1
            PresentMode = 'Hardware: Independent Flip'
            FrameTime = '33.3333'
            CPUBusy = '1.2'
            CPUWait = '32.1'
            GPULatency = '1.0'
            GPUTime = '2.0'
            GPUBusy = '0.5'
            GPUWait = '1.5'
            DisplayLatency = '34.0'
            DisplayedTime = '33.3333'
        },
        [pscustomobject][ordered]@{
            Application = 'Psobb.exe'
            ProcessID = 4242
            SwapChainAddress = '0xABC'
            PresentRuntime = 'DXGI'
            AllowsTearing = 1
            PresentMode = 'Hardware: Independent Flip'
            FrameTime = '33.4000'
            CPUBusy = '1.3'
            CPUWait = '32.1'
            GPULatency = '1.1'
            GPUTime = '2.1'
            GPUBusy = '0.6'
            GPUWait = '1.5'
            DisplayLatency = '34.1'
            DisplayedTime = '33.4000'
        }
    )
    [System.IO.File]::WriteAllLines(
        $compactSchemaPath,
        @($compactSchemaRows | ConvertTo-Csv -NoTypeInformation),
        [System.Text.UTF8Encoding]::new($false))
    $compactMetrics = & $metricsScript `
        -CsvPath $compactSchemaPath `
        -ExpectedProcessId 4242 `
        -ExpectedApplication 'Psobb.exe'
    $compactSchemaValid =
        [long]$compactMetrics.frames.dominantRowCount -eq 2 -and
        [string]$compactMetrics.frameTime.column -ceq 'FrameTime' -and
        [string]$compactMetrics.inputTracking.metrics.clickToPhotonLatency.status -ceq 'column-missing' -and
        [string]$compactMetrics.inputTracking.metrics.allInputToPhotonLatency.status -ceq 'column-missing' -and
        [int]$compactMetrics.inputTracking.validInputLatencySampleCount -eq 0
    Add-Result 'live compact v2 schema tolerates absent optional metric columns' `
        $compactSchemaValid 'missing optional input and extended latency columns remain explicitly unavailable'

    $presentationValid =
        [string]$metrics.presentation.presentModeStatus -ceq 'available' -and
        [string]$metrics.presentation.presentModes[0].mode -ceq 'Composed: Flip' -and
        [long]$metrics.presentation.presentModes[0].count -eq 6 -and
        [long]$metrics.presentation.tearingAllowedCount -eq 2 -and
        [long]$metrics.presentation.tearingNotAllowedCount -eq 6 -and
        [double]$metrics.presentation.tearingAllowedShareOfKnownPercent -eq 25
    Add-Result 'metrics report present-mode and tearing shares' $presentationValid `
        "mode=$($metrics.presentation.presentModes[0].mode); tearing=$($metrics.presentation.tearingAllowedShareOfKnownPercent)%"

    $writtenMetrics = Get-Content -Raw -LiteralPath $metricsPath | ConvertFrom-Json -Depth 20
    Add-Result 'metrics output is an atomic reusable JSON artifact' (
        (Test-Path -LiteralPath $metricsPath -PathType Leaf) -and
        [int]$writtenMetrics.schemaVersion -eq 1 -and
        [string]$writtenMetrics.source.sha256 -cmatch '^[a-f0-9]{64}$') $metricsPath

    $tiePath = Join-Path $temporaryRoot 'presentmon-tie.csv'
    $tieRows = @(
        [pscustomobject]@{ Application = 'Psobb.exe'; ProcessID = 4242; SwapChainAddress = '0x1'; MsBetweenPresents = 10 },
        [pscustomobject]@{ Application = 'Psobb.exe'; ProcessID = 4242; SwapChainAddress = '0x2'; MsBetweenPresents = 10 }
    )
    [System.IO.File]::WriteAllLines(
        $tiePath,
        @($tieRows | ConvertTo-Csv -NoTypeInformation),
        [System.Text.UTF8Encoding]::new($false))
    $tieRejected = $false
    try {
        & $metricsScript -CsvPath $tiePath -ExpectedProcessId 4242 | Out-Null
    } catch {
        $tieRejected = $_.Exception.Message -match 'unambiguous dominant swapchain'
    }
    Add-Result 'ambiguous dominant swapchains fail closed' $tieRejected `
        'equal swapchain row counts cannot silently select a winner'

    $missingHeaderPath = Join-Path $temporaryRoot 'presentmon-missing-header.csv'
    [System.IO.File]::WriteAllText(
        $missingHeaderPath,
        "Application,ProcessID,MsBetweenPresents`r`nPsobb.exe,4242,10`r`n",
        [System.Text.UTF8Encoding]::new($false))
    $missingHeaderRejected = $false
    try {
        & $metricsScript -CsvPath $missingHeaderPath -ExpectedProcessId 4242 | Out-Null
    } catch {
        $missingHeaderRejected = $_.Exception.Message -match 'SwapChainAddress'
    }
    Add-Result 'missing process/swapchain identity columns fail closed' $missingHeaderRejected `
        'dominant selection requires the PresentMon process and swapchain contract'

    $inRepoRejected = $false
    try {
        & $metricsScript `
            -CsvPath (Join-Path $repositoryRoot 'config\graphics-evidence.json') | Out-Null
    } catch {
        $inRepoRejected = $_.Exception.Message -match 'outside Git-tracked source'
    }
    Add-Result 'raw evidence inside Git-tracked source is rejected' $inRepoRejected `
        'the analyzer enforces the private graphics-evidence boundary'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) PresentMon tooling test(s) failed"
}
[pscustomobject]@{
    Suite = 'PresentMonTooling'
    Passed = $results.Count
    Failed = 0
}
