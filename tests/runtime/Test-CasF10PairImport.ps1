[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptPath = Join-Path $repositoryRoot 'scripts\Import-PSOBBCasF10Pair.ps1'
$supportPath = Join-Path $repositoryRoot 'scripts\support\PSOBB.CasF10Pair.ps1'
$scriptSource = Get-Content -Raw -LiteralPath $scriptPath
$supportSource = Get-Content -Raw -LiteralPath $supportPath
. $supportPath

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

foreach ($path in @($scriptPath, $supportPath)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$parseErrors) | Out-Null
    Add-Result "$(Split-Path -Leaf $path) parses cleanly" ($parseErrors.Count -eq 0) `
        "$($parseErrors.Count) parser error(s)"
}

$profileGuards =
    $scriptSource -match 'Assert-PSOBBRuntimeMarker' -and
    $scriptSource -match 'Assert-PSOBBLocalLabClientRuntimeContract' -and
    $scriptSource -match "'lab-widescreen-cas-16x10', 'cas-evaluation-16x10'" -and
    $scriptSource -match '\@\(0\.15, 0\.25, 0\.35\)' -and
    $scriptSource -match 'profileHash'
Add-Result 'import binds the exact LocalLab CAS profile, strength, and profile hash' `
    $profileGuards 'only the two declared CAS profiles at 0.15, 0.25, or 0.35 are eligible'

$analysisGuards =
    $scriptSource -match 'Get-PSOBBScreenshotEvidence\.ps1' -and
    $scriptSource -match '-ScreenshotPath \$afterStaged' -and
    $scriptSource -match '-ReferencePath \$beforeStaged' -and
    $scriptSource -match '-Disposition pending' -and
    $scriptSource -match '-ValidationSpecPath \$validationSpec\.FullName'
Add-Result 'import analyzes After as candidate and Before as reference with a required spec' `
    $analysisGuards 'technical disposition remains evidence-derived and pending review'

$lifecycleFree = $scriptSource -notmatch '(?i)Start-Process|Stop-Process|CloseMainWindow|Start-PSOBB|Stop-PSOBB|password|credential|username|accountname'
Add-Result 'import performs no process lifecycle or credential operation' `
    $lifecycleFree 'the running or stopped client is observed, never controlled'

$transactionGuards =
    $supportSource -match 'FileShare\]::None' -and
    $supportSource -match 'Directory\]::Move\(\$stage, \$final\)' -and
    $supportSource -match 'File\]::Move\(\$move\.Staged, \$move\.Source\)' -and
    $supportSource -match 'Refusing to overwrite an existing CAS evidence run'
Add-Result 'stable exclusive reads feed transactional same-volume publication and rollback' `
    $transactionGuards 'the final run appears through one directory rename and existing runs are immutable'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('PSOBB-CasImportTests-' + [Guid]::NewGuid().ToString('N'))
try {
    $source = Join-Path $temporaryRoot 'client'
    $evidenceParent = Join-Path $temporaryRoot 'graphics-evidence\lab-widescreen-cas-16x10'
    New-Item -ItemType Directory -Path $source, $evidenceParent -Force | Out-Null
    $png = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4)
    $before = Join-Path $source 'Psobb 2026-07-14 19-00-00_001 Before.png'
    $after = Join-Path $source 'Psobb 2026-07-14 19-00-00_001 After.png'
    [System.IO.File]::WriteAllBytes($before, $png)
    [System.IO.File]::WriteAllBytes($after, $png)

    $pair = Get-PSOBBCasF10Pair -SourceDirectory $source
    Add-Result 'exact same-stem Before and After files form one pair' `
        ($pair.Stem -ceq 'Psobb 2026-07-14 19-00-00_001' -and
            $pair.BeforePath -ceq $before -and $pair.AfterPath -ceq $after) `
        $pair.Stem

    $stable = Wait-PSOBBCasF10PairStable -Pair $pair `
        -StableObservationCount 2 -PollMilliseconds 50 -TimeoutSeconds 2
    Add-Result 'closed unchanged PNGs satisfy the bounded stability gate' `
        ($stable.StableObservations -eq 2 -and
            $stable.Before.Sha256 -cmatch '^[a-f0-9]{64}$') `
        "observations=$($stable.StableObservations)"

    $stage = Join-Path $evidenceParent '.import-success'
    $final = Join-Path $evidenceParent 'cas-success'
    $published = Move-PSOBBCasF10PairTransactional `
        -SourceBeforePath $before `
        -SourceAfterPath $after `
        -StagingRoot $stage `
        -FinalRoot $final `
        -BeforeDestinationName 'cas-025-before.png' `
        -AfterDestinationName 'cas-025-after.png' `
        -Analyze {
            param($beforePath, $afterPath, $indexRoot)
            [System.IO.File]::WriteAllText(
                (Join-Path $indexRoot 'cas-0.25.json'),
                '{"state":"pending"}',
                [System.Text.UTF8Encoding]::new($false))
            [pscustomobject]@{ State = 'pending' }
        }
    $publishedValid =
        -not (Test-Path -LiteralPath $before) -and
        -not (Test-Path -LiteralPath $after) -and
        -not (Test-Path -LiteralPath $stage) -and
        (Test-Path -LiteralPath $published.BeforePath -PathType Leaf) -and
        (Test-Path -LiteralPath $published.AfterPath -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $published.IndexRoot 'cas-0.25.json') -PathType Leaf)
    Add-Result 'successful transaction publishes both canonical captures and the index' `
        $publishedValid $published.PublishedRoot

    $overwriteSource = Join-Path $temporaryRoot 'overwrite-client'
    New-Item -ItemType Directory -Path $overwriteSource | Out-Null
    $overwriteBefore = Join-Path $overwriteSource 'Psobb 2026-07-14 19-00-30_006 Before.png'
    $overwriteAfter = Join-Path $overwriteSource 'Psobb 2026-07-14 19-00-30_006 After.png'
    [System.IO.File]::WriteAllBytes($overwriteBefore, $png)
    [System.IO.File]::WriteAllBytes($overwriteAfter, $png)
    $overwriteRejected = $false
    try {
        Move-PSOBBCasF10PairTransactional `
            -SourceBeforePath $overwriteBefore `
            -SourceAfterPath $overwriteAfter `
            -StagingRoot (Join-Path $evidenceParent '.import-overwrite') `
            -FinalRoot $final `
            -BeforeDestinationName 'cas-025-before.png' `
            -AfterDestinationName 'cas-025-after.png' `
            -Analyze { throw 'must not run' } | Out-Null
    } catch {
        $overwriteRejected = $_.Exception.Message -match 'Refusing to overwrite'
    }
    Add-Result 'an existing evidence run is rejected before either source moves' `
        ($overwriteRejected -and
            (Test-Path -LiteralPath $overwriteBefore -PathType Leaf) -and
            (Test-Path -LiteralPath $overwriteAfter -PathType Leaf)) `
        'published evidence remains immutable'

    $rollbackSource = Join-Path $temporaryRoot 'rollback-client'
    New-Item -ItemType Directory -Path $rollbackSource | Out-Null
    $rollbackBefore = Join-Path $rollbackSource 'Psobb 2026-07-14 19-01-00_002 Before.png'
    $rollbackAfter = Join-Path $rollbackSource 'Psobb 2026-07-14 19-01-00_002 After.png'
    [System.IO.File]::WriteAllBytes($rollbackBefore, $png)
    [System.IO.File]::WriteAllBytes($rollbackAfter, $png)
    $rollbackStage = Join-Path $evidenceParent '.import-rollback'
    $rollbackFinal = Join-Path $evidenceParent 'cas-rollback'
    $analysisFailureObserved = $false
    try {
        Move-PSOBBCasF10PairTransactional `
            -SourceBeforePath $rollbackBefore `
            -SourceAfterPath $rollbackAfter `
            -StagingRoot $rollbackStage `
            -FinalRoot $rollbackFinal `
            -BeforeDestinationName 'cas-035-before.png' `
            -AfterDestinationName 'cas-035-after.png' `
            -Analyze { throw 'synthetic analyzer failure' } | Out-Null
    } catch {
        $analysisFailureObserved = $_.Exception.Message -match 'synthetic analyzer failure'
    }
    $rollbackValid = $analysisFailureObserved -and
        (Test-Path -LiteralPath $rollbackBefore -PathType Leaf) -and
        (Test-Path -LiteralPath $rollbackAfter -PathType Leaf) -and
        -not (Test-Path -LiteralPath $rollbackStage) -and
        -not (Test-Path -LiteralPath $rollbackFinal)
    Add-Result 'analyzer failure restores both original screenshots and removes staging' `
        $rollbackValid 'no partial evidence run is visible'

    $extraSource = Join-Path $temporaryRoot 'extra-client'
    New-Item -ItemType Directory -Path $extraSource | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $extraSource 'Psobb 2026-07-14 19-02-00_003 Before.png'), $png)
    [System.IO.File]::WriteAllBytes(
        (Join-Path $extraSource 'Psobb 2026-07-14 19-02-00_003 After.png'), $png)
    [System.IO.File]::WriteAllBytes((Join-Path $extraSource 'unrelated.png'), $png)
    $extraRejected = $false
    try {
        Get-PSOBBCasF10Pair -SourceDirectory $extraSource | Out-Null
    } catch {
        $extraRejected = $_.Exception.Message -match 'exactly one'
    }
    Add-Result 'an extra PNG rejects the otherwise valid pair' `
        $extraRejected 'no ambiguous inventory is imported'

    $mismatchSource = Join-Path $temporaryRoot 'mismatch-client'
    New-Item -ItemType Directory -Path $mismatchSource | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $mismatchSource 'Psobb 2026-07-14 19-03-00_004 Before.png'), $png)
    [System.IO.File]::WriteAllBytes(
        (Join-Path $mismatchSource 'Psobb 2026-07-14 19-03-01_005 After.png'), $png)
    $mismatchRejected = $false
    try {
        Get-PSOBBCasF10Pair -SourceDirectory $mismatchSource | Out-Null
    } catch {
        $mismatchRejected = $_.Exception.Message -match 'same capture stem'
    }
    Add-Result 'different Before and After stems are rejected' `
        $mismatchRejected 'pair alignment fails closed'

    $lockedSource = Join-Path $temporaryRoot 'locked-client'
    New-Item -ItemType Directory -Path $lockedSource | Out-Null
    $lockedBefore = Join-Path $lockedSource 'Psobb 2026-07-14 19-04-00_007 Before.png'
    $lockedAfter = Join-Path $lockedSource 'Psobb 2026-07-14 19-04-00_007 After.png'
    [System.IO.File]::WriteAllBytes($lockedBefore, $png)
    [System.IO.File]::WriteAllBytes($lockedAfter, $png)
    $lockedPair = Get-PSOBBCasF10Pair -SourceDirectory $lockedSource
    $lock = [System.IO.File]::Open(
        $lockedBefore,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $lockedRejected = $false
    try {
        Wait-PSOBBCasF10PairStable -Pair $lockedPair `
            -StableObservationCount 2 -PollMilliseconds 50 -TimeoutSeconds 1 | Out-Null
    } catch {
        $lockedRejected = $_.Exception.Message -match 'did not become stable'
    } finally {
        $lock.Dispose()
    }
    Add-Result 'a still-open screenshot cannot satisfy the stability gate' `
        $lockedRejected 'exclusive read proof is required before moving either file'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) CAS F10 pair import test(s) failed"
}
[pscustomobject]@{ Suite = 'CasF10PairImport'; Passed = $results.Count; Failed = 0 }
