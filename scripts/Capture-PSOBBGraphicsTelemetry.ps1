[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$Channel,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]+(?:-[a-z0-9]+)*$')]
    [string]$ProfileId,

    [Parameter(Mandatory)]
    [ValidateSet('Before', 'After', 'Snapshot')]
    [string]$Phase,

    [Parameter(Mandatory)]
    [ValidateSet('Lobby', 'Gameplay', 'Soak', 'Other')]
    [string]$Scenario,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$RuntimeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Convert-NullableDouble {
    param([Parameter(Mandatory)][string]$Value)

    $trimmed = $Value.Trim()
    if ($trimmed -in @('', '[N/A]', 'N/A')) { return $null }
    $parsed = 0.0
    if (-not [double]::TryParse(
            $trimmed,
            [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed)) {
        throw "NVIDIA telemetry returned a non-numeric value: $trimmed"
    }
    $parsed
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$fullOutputPath = [IO.Path]::GetFullPath($OutputPath)
$evidenceRoot = [IO.Path]::GetFullPath(
    (Join-Path $layout.Root 'graphics-evidence')).TrimEnd('\')
if (-not $fullOutputPath.StartsWith(
        $evidenceRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetExtension($fullOutputPath) -ine '.json' -or
    (Test-Path -LiteralPath $fullOutputPath)) {
    throw 'Telemetry must be a new JSON file under the private graphics-evidence tree'
}

$records = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel $Channel)
if ($records.Count -ne 1) {
    throw "Telemetry requires exactly one approved $Channel PSOBB client"
}
$record = $records[0]
$process = Get-Process -Id ([int]$record.ProcessId) -ErrorAction SilentlyContinue
if (-not $process -or
    -not (Test-PSOBBProcessAtExactPath `
        -Process $process -Name 'Psobb' -ExpectedPath ([string]$record.ExecutablePath))) {
    throw 'The approved PSOBB process identity cannot be revalidated'
}
$identity = Assert-PSOBBApprovedClientExecutable -Path ([string]$record.ExecutablePath)
if ($identity.Sha256 -cne [string]$record.ExecutableSha256) {
    throw 'The approved PSOBB executable changed before telemetry capture'
}

$clientRoot = Split-Path -Parent ([string]$record.ExecutablePath)
$profilePath = Join-Path $clientRoot 'client-profile.json'
$profile = if ($Channel -eq 'LocalLab') {
    Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
} else {
    & (Join-Path $PSScriptRoot 'Test-PSOBBClientGraphics.ps1') `
        -Channel $Channel -RuntimeRoot $layout.Root | Out-Null
    Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -Depth 30
}
$materializedProfileId = if ($profile.PSObject.Properties.Name -contains 'profileId') {
    [string]$profile.profileId
} elseif ($Channel -eq 'Stable') {
    'safe-native-4x3'
} elseif ($Channel -eq 'Canary') {
    'clarity-dgvoodoo-4x3'
} else { '' }
if ($materializedProfileId -cne $ProfileId) {
    throw "The running materialization is '$materializedProfileId', not '$ProfileId'"
}

$nvidiaCommands = @(Get-Command nvidia-smi.exe -CommandType Application -ErrorAction SilentlyContinue)
if ($nvidiaCommands.Count -ne 1) {
    throw 'Graphics telemetry requires exactly one discoverable NVIDIA nvidia-smi.exe'
}
$nvidiaSmi = [IO.Path]::GetFullPath($nvidiaCommands[0].Source)
$nvidiaSignature = Get-AuthenticodeSignature -FilePath $nvidiaSmi
if ($nvidiaSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    [string]$nvidiaSignature.SignerCertificate.Subject -notmatch
        '(NVIDIA|Microsoft Windows Hardware Compatibility Publisher)') {
    throw 'nvidia-smi.exe does not have a valid NVIDIA or WHQL Authenticode signature'
}

$query = @(
    'index', 'name', 'uuid', 'driver_version', 'pstate', 'temperature.gpu',
    'memory.total', 'memory.used', 'memory.free', 'utilization.gpu',
    'power.draw', 'power.limit', 'clocks.current.graphics',
    'clocks.current.memory', 'clocks_event_reasons.sw_power_cap',
    'clocks_event_reasons.hw_thermal_slowdown',
    'clocks_event_reasons.hw_power_brake_slowdown',
    'clocks_event_reasons.sw_thermal_slowdown')
$rawRows = @(& $nvidiaSmi `
    "--query-gpu=$($query -join ',')" '--format=csv,noheader,nounits')
if ($LASTEXITCODE -ne 0 -or $rawRows.Count -eq 0) {
    throw 'nvidia-smi failed to return GPU telemetry'
}
$gpus = [Collections.Generic.List[object]]::new()
foreach ($row in $rawRows) {
    $values = @([string]$row -split ',' | ForEach-Object { $_.Trim() })
    if ($values.Count -ne $query.Count) {
        throw 'nvidia-smi returned an unexpected telemetry column count'
    }
    $gpus.Add([ordered]@{
        index = [int]$values[0]
        name = $values[1]
        uuid = $values[2]
        driverVersion = $values[3]
        performanceState = $values[4]
        temperatureC = Convert-NullableDouble $values[5]
        memoryTotalMiB = Convert-NullableDouble $values[6]
        memoryUsedMiB = Convert-NullableDouble $values[7]
        memoryFreeMiB = Convert-NullableDouble $values[8]
        utilizationPercent = Convert-NullableDouble $values[9]
        powerDrawW = Convert-NullableDouble $values[10]
        powerLimitW = Convert-NullableDouble $values[11]
        graphicsClockMHz = Convert-NullableDouble $values[12]
        memoryClockMHz = Convert-NullableDouble $values[13]
        clockEventReasons = [ordered]@{
            softwarePowerCap = ($values[14] -eq 'Active')
            hardwareThermalSlowdown = ($values[15] -eq 'Active')
            hardwarePowerBrakeSlowdown = ($values[16] -eq 'Active')
            softwareThermalSlowdown = ($values[17] -eq 'Active')
        }
    })
}

$process.Refresh()
$presentation = Get-PSOBBClientWindowPresentation -Process $process
$capturedAtUtc = [DateTime]::UtcNow
$catalogChannel = switch ($Channel) {
    'Stable' { 'stable' }
    'Canary' { 'canary' }
    'LocalLab' { 'local-lab' }
}
$userGpuPreferencesPath = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
$userGpuPreference = $null
if (Test-Path -LiteralPath $userGpuPreferencesPath) {
    $preferenceKey = Get-ItemProperty -LiteralPath $userGpuPreferencesPath
    $preferenceProperty =
        $preferenceKey.PSObject.Properties[[string]$record.ExecutablePath]
    if ($preferenceProperty) {
        $userGpuPreference = [string]$preferenceProperty.Value
    }
}
$startupReceiptRoot = Join-Path $layout.Logs 'client-startup'
$startupReceipts = @(if (
    Test-Path -LiteralPath $startupReceiptRoot -PathType Container) {
        Get-ChildItem -LiteralPath $startupReceiptRoot `
            -Filter "*-$($process.Id).json" -File -Force
    })
if ($startupReceipts.Count -gt 1) {
    throw 'More than one startup receipt targets the approved PSOBB process'
}
$startupEvidence = [ordered]@{ available = $false }
if ($startupReceipts.Count -eq 1) {
    $startupReceipt = Get-Content -Raw -LiteralPath $startupReceipts[0].FullName |
        ConvertFrom-Json -Depth 12 -DateKind String
    $receiptProcessStartUtc = [DateTimeOffset]::Parse(
        [string]$startupReceipt.processStartTimeUtc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).UtcDateTime
    if ([int]$startupReceipt.schemaVersion -ne 1 -or
        [int]$startupReceipt.processId -ne $process.Id -or
        [string]$startupReceipt.executableSha256 -cne $identity.Sha256 -or
        [string]$startupReceipt.profileId -cne $ProfileId -or
        [Math]::Abs((
            $receiptProcessStartUtc -
            $process.StartTime.ToUniversalTime()).TotalSeconds) -gt 0.5) {
        throw 'The startup receipt does not match the approved PSOBB process and profile'
    }
    $startupEvidence = [ordered]@{
        available = $true
        file = 'runtime:' + [IO.Path]::GetRelativePath(
            $layout.Root, $startupReceipts[0].FullName).Replace('\', '/')
        byteSize = $startupReceipts[0].Length
        sha256 = Get-LowerSha256 -Path $startupReceipts[0].FullName
        startupElapsedMilliseconds = [double]$startupReceipt.startupElapsedMilliseconds
    }
}
$document = [ordered]@{
    schemaVersion = 1
    capturedAtUtc = $capturedAtUtc.ToString('o')
    phase = $Phase.ToLowerInvariant()
    scenario = $Scenario.ToLowerInvariant()
    channel = $catalogChannel
    profile = [ordered]@{
        id = $ProfileId
        materializedSha256 = Get-LowerSha256 -Path $profilePath
        configurationSha256 = [string]$profile.configurationSha256
    }
    process = [ordered]@{
        application = 'Psobb.exe'
        processId = $process.Id
        processStartTimeUtc = $process.StartTime.ToUniversalTime().ToString('o')
        elapsedSeconds = [Math]::Round(($capturedAtUtc - $process.StartTime.ToUniversalTime()).TotalSeconds, 3)
        executableSize = $identity.Size
        executableSha256 = $identity.Sha256
        workingSetBytes = $process.WorkingSet64
        privateBytes = $process.PrivateMemorySize64
        virtualBytes = $process.VirtualMemorySize64
        pagedBytes = $process.PagedMemorySize64
        handleCount = $process.HandleCount
        threadCount = $process.Threads.Count
        responding = $process.Responding
    }
    presentation = [ordered]@{
        x = $presentation.X
        y = $presentation.Y
        width = $presentation.Width
        height = $presentation.Height
        clientWidth = $presentation.ClientWidth
        clientHeight = $presentation.ClientHeight
        style = ('0x{0:X8}' -f [long]$presentation.Style)
    }
    windowsPresentation = [ordered]@{
        operatingSystem = [Environment]::OSVersion.VersionString
        perApplicationUserGpuPreferencePresent = ($null -ne $userGpuPreference)
        perApplicationUserGpuPreference = $userGpuPreference
        windowedGameOptimizationPolicy = if ($null -eq $userGpuPreference) {
            'system-default'
        } elseif ($userGpuPreference -match 'SwapEffectUpgradeEnable=0') {
            'disabled-for-application'
        } else {
            'application-override-present'
        }
    }
    startupEvidence = $startupEvidence
    nvidiaSmi = [ordered]@{
        byteSize = (Get-Item -LiteralPath $nvidiaSmi -Force).Length
        sha256 = Get-LowerSha256 -Path $nvidiaSmi
        signerSubject = [string]$nvidiaSignature.SignerCertificate.Subject
        signerThumbprint = [string]$nvidiaSignature.SignerCertificate.Thumbprint
    }
    gpus = @($gpus)
}

[void][IO.Directory]::CreateDirectory((Split-Path -Parent $fullOutputPath))
$temporaryPath = $fullOutputPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
try {
    [IO.File]::WriteAllText(
        $temporaryPath,
        ($document | ConvertTo-Json -Depth 12),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $fullOutputPath
} finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

[pscustomobject]@{
    Captured = $true
    Phase = $Phase
    Scenario = $Scenario
    Channel = $Channel
    ProfileId = $ProfileId
    ProcessId = $process.Id
    OutputPath = $fullOutputPath
    Sha256 = Get-LowerSha256 -Path $fullOutputPath
}
