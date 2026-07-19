[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CsvPath,
    [ValidateRange(0, [int]::MaxValue)][int]$ExpectedProcessId = 0,
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$ExpectedApplication = 'Psobb.exe',
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Assert-PSOBBEvidencePathOutsideRepository {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Purpose
    )

    Assert-PSOBBPathOutsideTrackedSource -Path $Path -Purpose $Purpose
}

function Get-PSOBBStreamingSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    } finally {
        $stream.Dispose()
    }
}

function Open-PSOBBPresentMonCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    Add-Type -AssemblyName Microsoft.VisualBasic
    $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new(
        $Path,
        [System.Text.UTF8Encoding]::new($false, $true),
        $true)
    try {
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false
        if ($parser.EndOfData) {
            throw 'The PresentMon CSV is empty'
        }
        $headers = @($parser.ReadFields())
        if ($headers.Count -eq 0) {
            throw 'The PresentMon CSV has no header row'
        }
        $headers[0] = ([string]$headers[0]).TrimStart([char]0xFEFF)
        $indexes = [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        for ($index = 0; $index -lt $headers.Count; $index++) {
            $header = ([string]$headers[$index]).Trim()
            if ([string]::IsNullOrWhiteSpace($header) -or -not $indexes.TryAdd($header, $index)) {
                throw "The PresentMon CSV contains an empty or duplicate header: '$header'"
            }
            $headers[$index] = $header
        }
        [pscustomobject]@{
            Parser = $parser
            Headers = $headers
            Indexes = $indexes
        }
    } catch {
        $parser.Dispose()
        throw
    }
}

function Get-PSOBBCsvColumnName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Reader,
        [Parameter(Mandatory)][string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if ($Reader.Indexes.ContainsKey($candidate)) {
            return [string]$Reader.Headers[$Reader.Indexes[$candidate]]
        }
    }
    $null
}

function Get-PSOBBCsvField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Reader,
        [Parameter(Mandatory)][string[]]$Fields,
        [AllowNull()][string]$Column
    )

    if ([string]::IsNullOrWhiteSpace($Column)) {
        return $null
    }
    if (-not $Reader.Indexes.ContainsKey($Column)) {
        throw "The requested PresentMon CSV column is not present: '$Column'"
    }
    $columnIndex = [int]$Reader.Indexes[$Column]
    if ($columnIndex -lt 0 -or $columnIndex -ge $Fields.Count) {
        throw "The PresentMon CSV row does not contain column '$Column'"
    }
    [string]$Fields[$columnIndex]
}

function Test-PSOBBUnavailableMetricValue {
    [CmdletBinding()]
    param([AllowNull()][string]$Value)

    [string]::IsNullOrWhiteSpace($Value) -or
        $Value.Trim() -in @('NA', 'N/A', 'NULL', 'NotAvailable')
}

function ConvertTo-PSOBBFiniteDouble {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory)][ref]$Result
    )

    if (Test-PSOBBUnavailableMetricValue -Value $Value) {
        return $false
    }
    [double]$parsed = 0
    if (-not [double]::TryParse(
        $Value.Trim(),
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$parsed) -or
        [double]::IsNaN($parsed) -or
        [double]::IsInfinity($parsed)) {
        return $false
    }
    $Result.Value = $parsed
    $true
}

function Get-PSOBBPercentile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][double[]]$SortedValues,
        [Parameter(Mandatory)][ValidateRange(0, 1)][double]$Probability
    )

    if ($SortedValues.Count -eq 0) {
        return $null
    }
    if ($SortedValues.Count -eq 1) {
        return [Math]::Round($SortedValues[0], 4)
    }
    $rank = ($SortedValues.Count - 1) * $Probability
    $lower = [int][Math]::Floor($rank)
    $upper = [int][Math]::Ceiling($rank)
    $value = if ($lower -eq $upper) {
        $SortedValues[$lower]
    } else {
        $SortedValues[$lower] + (($SortedValues[$upper] - $SortedValues[$lower]) * ($rank - $lower))
    }
    [Math]::Round($value, 4)
}

function New-PSOBBMetricAccumulator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$Column
    )

    [pscustomobject]@{
        Name = $Name
        Column = if ([string]::IsNullOrWhiteSpace($Column)) { $null } else { $Column }
        Values = [System.Collections.Generic.List[double]]::new()
        NaCount = 0
        InvalidCount = 0
    }
}

function Add-PSOBBMetricValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Accumulator,
        [AllowNull()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace([string]$Accumulator.Column)) {
        return
    }
    if (Test-PSOBBUnavailableMetricValue -Value $Value) {
        $Accumulator.NaCount++
        return
    }
    [double]$parsed = 0
    if (-not (ConvertTo-PSOBBFiniteDouble -Value $Value -Result ([ref]$parsed))) {
        $Accumulator.InvalidCount++
        return
    }
    $Accumulator.Values.Add($parsed)
}

function ConvertTo-PSOBBMetricSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Accumulator,
        [switch]$PositiveOnly
    )

    $values = if ($PositiveOnly) {
        @($Accumulator.Values | Where-Object { $_ -gt 0 })
    } else {
        @($Accumulator.Values)
    }
    [double[]]$sorted = @($values | Sort-Object)
    $nonPositive = if ($PositiveOnly) {
        @($Accumulator.Values | Where-Object { $_ -le 0 }).Count
    } else {
        0
    }
    [pscustomobject][ordered]@{
        status = if ([string]::IsNullOrWhiteSpace([string]$Accumulator.Column)) {
            'column-missing'
        } elseif ($sorted.Count -eq 0) {
            'unavailable'
        } else {
            'available'
        }
        column = $Accumulator.Column
        unit = 'ms'
        validCount = $sorted.Count
        naCount = [int]$Accumulator.NaCount
        invalidCount = [int]$Accumulator.InvalidCount
        nonPositiveExcludedCount = $nonPositive
        p50 = Get-PSOBBPercentile -SortedValues $sorted -Probability 0.50
        p95 = Get-PSOBBPercentile -SortedValues $sorted -Probability 0.95
        p99 = Get-PSOBBPercentile -SortedValues $sorted -Probability 0.99
    }
}

$CsvPath = Assert-PSOBBEvidencePathOutsideRepository -Path $CsvPath -Purpose 'The raw PresentMon CSV'
if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
    throw "The PresentMon CSV does not exist: $CsvPath"
}
$csvItem = Get-Item -LiteralPath $CsvPath -Force
if ($csvItem.Length -le 0) {
    throw 'The PresentMon CSV is empty'
}
$csvHashBefore = Get-PSOBBStreamingSha256 -Path $CsvPath

$firstReader = Open-PSOBBPresentMonCsv -Path $CsvPath
try {
    $applicationColumn = Get-PSOBBCsvColumnName -Reader $firstReader -Candidates @('Application')
    $processIdColumn = Get-PSOBBCsvColumnName -Reader $firstReader -Candidates @('ProcessID')
    $swapChainColumn = Get-PSOBBCsvColumnName -Reader $firstReader -Candidates @('SwapChainAddress')
    if ($null -eq $applicationColumn -or $null -eq $processIdColumn -or $null -eq $swapChainColumn) {
        throw 'The PresentMon CSV must contain Application, ProcessID, and SwapChainAddress columns'
    }

    $swapChainCounts = [System.Collections.Generic.Dictionary[string, long]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $swapChainIdentities = @{}
    [long]$candidateRows = 0
    [long]$malformedRows = 0
    while (-not $firstReader.Parser.EndOfData) {
        $fields = @($firstReader.Parser.ReadFields())
        if ($fields.Count -ne $firstReader.Headers.Count) {
            $malformedRows++
            continue
        }
        $application = (Get-PSOBBCsvField -Reader $firstReader -Fields $fields -Column $applicationColumn).Trim()
        if (-not [string]::IsNullOrWhiteSpace($ExpectedApplication) -and
            -not $application.Equals($ExpectedApplication, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        [int]$processId = 0
        $processIdText = Get-PSOBBCsvField -Reader $firstReader -Fields $fields -Column $processIdColumn
        if (-not [int]::TryParse(
            $processIdText,
            [System.Globalization.NumberStyles]::Integer,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$processId) -or
            $processId -le 0 -or
            ($ExpectedProcessId -gt 0 -and $processId -ne $ExpectedProcessId)) {
            continue
        }
        $swapChain = (Get-PSOBBCsvField -Reader $firstReader -Fields $fields -Column $swapChainColumn).Trim()
        if ([string]::IsNullOrWhiteSpace($swapChain)) {
            continue
        }
        $key = '{0}|{1}' -f $processId, $swapChain.ToLowerInvariant()
        if ($swapChainCounts.ContainsKey($key)) {
            $swapChainCounts[$key]++
        } else {
            $swapChainCounts.Add($key, 1)
            $swapChainIdentities[$key] = [pscustomobject]@{
                Application = $application
                ProcessId = $processId
                SwapChain = $swapChain
            }
        }
        $candidateRows++
    }
} finally {
    $firstReader.Parser.Dispose()
}

if ($candidateRows -eq 0 -or $swapChainCounts.Count -eq 0) {
    throw 'The PresentMon CSV has no rows matching the expected PSOBB process'
}
$rankedSwapChains = @($swapChainCounts.GetEnumerator() | Sort-Object `
    @{ Expression = 'Value'; Descending = $true }, `
    @{ Expression = 'Key'; Descending = $false })
if ($rankedSwapChains.Count -gt 1 -and
    [long]$rankedSwapChains[0].Value -eq [long]$rankedSwapChains[1].Value) {
    throw 'The PresentMon CSV does not have one unambiguous dominant swapchain'
}
$dominantKey = [string]$rankedSwapChains[0].Key
$dominantIdentity = $swapChainIdentities[$dominantKey]
$dominantRows = [long]$rankedSwapChains[0].Value

$secondReader = Open-PSOBBPresentMonCsv -Path $CsvPath
try {
    $applicationColumn = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates @('Application')
    $processIdColumn = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates @('ProcessID')
    $swapChainColumn = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates @('SwapChainAddress')
    $presentModeColumn = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates @('PresentMode')
    $allowsTearingColumn = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates @('AllowsTearing')
    $presentRuntimeColumn = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates @('PresentRuntime')

    $metricDefinitions = [ordered]@{
        frameTime = @('MsBetweenPresents', 'MsBetweenAppStart', 'CPUFrameTime', 'FrameTime')
        displayCadence = @('MsBetweenDisplayChange', 'DisplayedTime')
        displayedTime = @('DisplayedTime')
        gpuLatency = @('MsGPULatency', 'GPULatency')
        gpuTime = @('MsGPUTime', 'GPUTime')
        gpuBusy = @('MsGPUBusy', 'GPUBusy')
        gpuWait = @('MsGPUWait', 'GPUWait')
        displayLatency = @('DisplayLatency', 'MsDisplayLatency')
        untilDisplayed = @('MsUntilDisplayed')
        renderPresentLatency = @('MsRenderPresentLatency')
        inPresentApi = @('MsInPresentAPI', 'MsInPresent')
        cpuBusy = @('MsCPUBusy', 'CPUBusy')
        clickToPhotonLatency = @('MsClickToPhotonLatency', 'ClickToPhotonLatency')
        allInputToPhotonLatency = @('MsAllInputToPhotonLatency', 'AllInputToPhotonLatency')
    }
    $accumulators = [ordered]@{}
    foreach ($definition in $metricDefinitions.GetEnumerator()) {
        $column = Get-PSOBBCsvColumnName -Reader $secondReader -Candidates $definition.Value
        $accumulators[$definition.Key] = New-PSOBBMetricAccumulator `
            -Name $definition.Key `
            -Column $column
    }
    if ($null -eq $accumulators.frameTime.Column -and
        $null -eq $accumulators.displayCadence.Column) {
        throw 'The PresentMon CSV has no supported v2 frame-time or display-cadence column'
    }

    $presentModeCounts = [System.Collections.Generic.Dictionary[string, long]]::new(
        [System.StringComparer]::Ordinal)
    $runtimeCounts = [System.Collections.Generic.Dictionary[string, long]]::new(
        [System.StringComparer]::Ordinal)
    [long]$presentModeUnavailable = 0
    [long]$runtimeUnavailable = 0
    [long]$tearingAllowed = 0
    [long]$tearingNotAllowed = 0
    [long]$tearingUnavailable = 0
    [long]$observedDominantRows = 0
    while (-not $secondReader.Parser.EndOfData) {
        $fields = @($secondReader.Parser.ReadFields())
        if ($fields.Count -ne $secondReader.Headers.Count) {
            continue
        }
        [int]$processId = 0
        $processIdText = Get-PSOBBCsvField -Reader $secondReader -Fields $fields -Column $processIdColumn
        if (-not [int]::TryParse(
            $processIdText,
            [System.Globalization.NumberStyles]::Integer,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$processId)) {
            continue
        }
        $swapChain = (Get-PSOBBCsvField -Reader $secondReader -Fields $fields -Column $swapChainColumn).Trim()
        $key = '{0}|{1}' -f $processId, $swapChain.ToLowerInvariant()
        if ($key -cne $dominantKey) {
            continue
        }
        $observedDominantRows++

        foreach ($entry in $accumulators.GetEnumerator()) {
            Add-PSOBBMetricValue `
                -Accumulator $entry.Value `
                -Value (Get-PSOBBCsvField -Reader $secondReader -Fields $fields -Column $entry.Value.Column)
        }

        $presentMode = Get-PSOBBCsvField -Reader $secondReader -Fields $fields -Column $presentModeColumn
        if (Test-PSOBBUnavailableMetricValue -Value $presentMode) {
            $presentModeUnavailable++
        } elseif ($presentModeCounts.ContainsKey($presentMode.Trim())) {
            $presentModeCounts[$presentMode.Trim()]++
        } else {
            $presentModeCounts.Add($presentMode.Trim(), 1)
        }

        $runtime = Get-PSOBBCsvField -Reader $secondReader -Fields $fields -Column $presentRuntimeColumn
        if (Test-PSOBBUnavailableMetricValue -Value $runtime) {
            $runtimeUnavailable++
        } elseif ($runtimeCounts.ContainsKey($runtime.Trim())) {
            $runtimeCounts[$runtime.Trim()]++
        } else {
            $runtimeCounts.Add($runtime.Trim(), 1)
        }

        $tearing = Get-PSOBBCsvField -Reader $secondReader -Fields $fields -Column $allowsTearingColumn
        if ($null -eq $allowsTearingColumn -or
            (Test-PSOBBUnavailableMetricValue -Value $tearing)) {
            $tearingUnavailable++
        } elseif ($tearing.Trim() -in @('1', 'true', 'True', 'TRUE')) {
            $tearingAllowed++
        } elseif ($tearing.Trim() -in @('0', 'false', 'False', 'FALSE')) {
            $tearingNotAllowed++
        } else {
            $tearingUnavailable++
        }
    }
} finally {
    $secondReader.Parser.Dispose()
}

if ($observedDominantRows -ne $dominantRows) {
    throw 'The PresentMon CSV changed while it was being analyzed'
}
$csvHashAfter = Get-PSOBBStreamingSha256 -Path $CsvPath
if ($csvHashAfter -cne $csvHashBefore) {
    throw 'The PresentMon CSV changed while it was being analyzed'
}

$frameTime = ConvertTo-PSOBBMetricSummary -Accumulator $accumulators.frameTime -PositiveOnly
$displayCadence = ConvertTo-PSOBBMetricSummary -Accumulator $accumulators.displayCadence -PositiveOnly
$cadenceAccumulator = if ($displayCadence.status -ceq 'available') {
    $accumulators.displayCadence
} else {
    $accumulators.frameTime
}
[double[]]$positiveCadence = @($cadenceAccumulator.Values | Where-Object { $_ -gt 0 } | Sort-Object)
$cadenceMedian = Get-PSOBBPercentile -SortedValues $positiveCadence -Probability 0.50
$missThreshold = if ($null -ne $cadenceMedian) {
    [Math]::Round(([double]$cadenceMedian * 1.5), 4)
} else {
    $null
}
$cadenceMisses = if ($null -ne $missThreshold) {
    @($positiveCadence | Where-Object { $_ -gt $missThreshold }).Count
} else {
    $null
}
$stalls = if ($positiveCadence.Count -gt 0) {
    @($positiveCadence | Where-Object { $_ -gt 100 }).Count
} else {
    $null
}

$presentModeShares = @($presentModeCounts.GetEnumerator() | Sort-Object `
    @{ Expression = 'Value'; Descending = $true }, `
    @{ Expression = 'Key'; Descending = $false } | ForEach-Object {
    [pscustomobject][ordered]@{
        mode = [string]$_.Key
        count = [long]$_.Value
        shareOfRowsPercent = [Math]::Round((100.0 * [long]$_.Value / $dominantRows), 4)
    }
})
$runtimeShares = @($runtimeCounts.GetEnumerator() | Sort-Object `
    @{ Expression = 'Value'; Descending = $true }, `
    @{ Expression = 'Key'; Descending = $false } | ForEach-Object {
    [pscustomobject][ordered]@{
        runtime = [string]$_.Key
        count = [long]$_.Value
        shareOfRowsPercent = [Math]::Round((100.0 * [long]$_.Value / $dominantRows), 4)
    }
})
$knownTearing = $tearingAllowed + $tearingNotAllowed
$displayedTimeAccumulator = $accumulators.displayedTime
$droppedCount = if ($null -eq $displayedTimeAccumulator.Column) {
    $null
} else {
    [long]$displayedTimeAccumulator.NaCount
}
$droppedShare = if ($null -ne $droppedCount) {
    [Math]::Round((100.0 * [long]$droppedCount / $dominantRows), 4)
} else {
    $null
}
$metricNaTotal = [long]0
$metricInvalidTotal = [long]0
foreach ($entry in $accumulators.GetEnumerator()) {
    $metricNaTotal += [long]$entry.Value.NaCount
    $metricInvalidTotal += [long]$entry.Value.InvalidCount
}

$gpuAndLatency = [ordered]@{}
foreach ($name in @(
    'gpuLatency', 'gpuTime', 'gpuBusy', 'gpuWait', 'displayLatency',
    'untilDisplayed', 'renderPresentLatency', 'inPresentApi', 'cpuBusy')) {
    $gpuAndLatency[$name] = ConvertTo-PSOBBMetricSummary -Accumulator $accumulators[$name]
}
$inputMetrics = [ordered]@{
    clickToPhotonLatency = ConvertTo-PSOBBMetricSummary -Accumulator $accumulators.clickToPhotonLatency
    allInputToPhotonLatency = ConvertTo-PSOBBMetricSummary -Accumulator $accumulators.allInputToPhotonLatency
}
$validInputSamples = [int]$inputMetrics.clickToPhotonLatency.validCount +
    [int]$inputMetrics.allInputToPhotonLatency.validCount

$result = [pscustomobject][ordered]@{
    schemaVersion = 1
    analyzedAtUtc = [DateTime]::UtcNow.ToString('o')
    source = [pscustomobject][ordered]@{
        fileName = $csvItem.Name
        byteSize = [long]$csvItem.Length
        sha256 = $csvHashAfter
        malformedRowCount = $malformedRows
    }
    selection = [pscustomobject][ordered]@{
        expectedApplication = $ExpectedApplication
        expectedProcessId = if ($ExpectedProcessId -gt 0) { $ExpectedProcessId } else { $null }
        candidateRowCount = $candidateRows
        swapchainCount = $swapChainCounts.Count
        dominantApplication = [string]$dominantIdentity.Application
        dominantProcessId = [int]$dominantIdentity.ProcessId
        dominantSwapChainAddress = [string]$dominantIdentity.SwapChain
        dominantRowCount = $dominantRows
        dominantSharePercent = [Math]::Round((100.0 * $dominantRows / $candidateRows), 4)
    }
    frames = [pscustomobject][ordered]@{
        dominantRowCount = $dominantRows
        displayedTimeNaOrNotDisplayedCount = $droppedCount
        displayedTimeNaOrNotDisplayedSharePercent = $droppedShare
        droppedInference = if ($null -eq $droppedCount) {
            'unavailable: DisplayedTime column missing'
        } else {
            'PresentMon v2 DisplayedTime=NA means the frame was not displayed'
        }
        selectedMetricNaValueCount = $metricNaTotal
        selectedMetricInvalidValueCount = $metricInvalidTotal
    }
    frameTime = $frameTime
    displayCadence = $displayCadence
    cadence = [pscustomobject][ordered]@{
        sourceColumn = [string]$cadenceAccumulator.Column
        baseline = 'median of positive dominant-swapchain cadence values'
        baselineMs = $cadenceMedian
        missThreshold = 'greater than 1.5x baseline'
        missThresholdMs = $missThreshold
        missCount = $cadenceMisses
        over100MsStallCount = $stalls
    }
    presentation = [pscustomobject][ordered]@{
        presentModeStatus = if ($null -eq $presentModeColumn) { 'column-missing' } elseif ($presentModeShares.Count -eq 0) { 'unavailable' } else { 'available' }
        presentModes = $presentModeShares
        presentModeUnavailableCount = $presentModeUnavailable
        presentRuntimes = $runtimeShares
        presentRuntimeUnavailableCount = $runtimeUnavailable
        tearingStatus = if ($null -eq $allowsTearingColumn) { 'column-missing' } elseif ($knownTearing -eq 0) { 'unavailable' } else { 'available' }
        tearingAllowedCount = $tearingAllowed
        tearingNotAllowedCount = $tearingNotAllowed
        tearingUnavailableCount = $tearingUnavailable
        tearingAllowedShareOfKnownPercent = if ($knownTearing -gt 0) {
            [Math]::Round((100.0 * $tearingAllowed / $knownTearing), 4)
        } else {
            $null
        }
    }
    gpuAndLatency = [pscustomobject]$gpuAndLatency
    inputTracking = [pscustomobject][ordered]@{
        expected = 'disabled by capture wrapper'
        validInputLatencySampleCount = $validInputSamples
        metrics = [pscustomobject]$inputMetrics
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Assert-PSOBBEvidencePathOutsideRepository -Path $OutputPath -Purpose 'The PresentMon metrics output'
    if (Test-Path -LiteralPath $OutputPath) {
        throw "Refusing to overwrite existing PresentMon metrics output: $OutputPath"
    }
    $outputDirectory = Split-Path -Parent $OutputPath
    [void][System.IO.Directory]::CreateDirectory($outputDirectory)
    $temporaryOutput = $OutputPath + '.new'
    try {
        [System.IO.File]::WriteAllText(
            $temporaryOutput,
            ($result | ConvertTo-Json -Depth 20),
            [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryOutput -Destination $OutputPath
    } finally {
        if (Test-Path -LiteralPath $temporaryOutput) {
            Remove-Item -LiteralPath $temporaryOutput -Force
        }
    }
}

$result
