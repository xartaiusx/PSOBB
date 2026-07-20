[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runtimeRoot = Join-Path $repositoryRoot 'PSOBB-Runtime'
$buildScript = Join-Path $repositoryRoot 'scripts\Build-PSOBBCombatCanaryServer.ps1'
$contractPath = Join-Path $repositoryRoot 'config\combat-canary-build.json'
$contractSchemaPath = Join-Path $repositoryRoot `
    'config\schemas\combat-canary-build.schema.json'
$seriesSchemaPath = Join-Path $repositoryRoot `
    'config\schemas\newserv-patch-series.schema.json'
$nativeManifestPath = Join-Path $repositoryRoot 'config\native-execution-payloads.json'
$nativeManifestSchemaPath = Join-Path $repositoryRoot `
    'config\schemas\native-execution-payloads.schema.json'
$seriesPath = Join-Path $repositoryRoot 'patches\newserv\series.json'
$patchPath = Join-Path $repositoryRoot `
    'patches\newserv\0001-deterministic-revision-metadata.patch'
$testRunId = [Guid]::NewGuid()
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-combat-canary-build-test-' + $testRunId.ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
$testRootMarkerPath = Join-Path $temporaryRoot '.psobb-combat-canary-build-test.json'
[System.IO.File]::WriteAllText(
    $testRootMarkerPath,
    (([ordered]@{
                schemaVersion = 1
                testRunId = $testRunId.ToString('D')
                root = [System.IO.Path]::GetFullPath($temporaryRoot)
            } | ConvertTo-Json -Depth 4) + "`n"),
    [System.Text.UTF8Encoding]::new($false))
$fixtureJunctions = [System.Collections.Generic.List[string]]::new()
$helperProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Remove-CombatCanaryBuildTestRoot {
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath($Path))
    $temporary = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()))
    if (-not [string]::Equals(
            [System.IO.Path]::GetDirectoryName($full),
            $temporary,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Build-test cleanup target is not an immediate child of the OS temporary root'
    }
    $match = [regex]::Match(
        [System.IO.Path]::GetFileName($full),
        '^psobb-combat-canary-build-test-(?<id>[0-9a-f]{32})$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $nameId = [Guid]::Empty
    if (-not $match.Success -or
        -not [Guid]::TryParseExact($match.Groups['id'].Value, 'N', [ref]$nameId)) {
        throw 'Build-test cleanup target does not contain one exact GUID marker'
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Build-test cleanup target is a reparse point'
    }
    $markerPath = Join-Path $full '.psobb-combat-canary-build-test.json'
    $markerItem = Get-Item -LiteralPath $markerPath -Force
    if (($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Build-test cleanup marker is a reparse point'
    }
    $marker = Get-Content -Raw -LiteralPath $markerPath | ConvertFrom-Json -Depth 4
    $markerId = [Guid]::Empty
    if ([int]$marker.schemaVersion -ne 1 -or
        -not [Guid]::TryParseExact([string]$marker.testRunId, 'D', [ref]$markerId) -or
        $markerId -ne $nameId -or
        -not [string]::Equals(
            [System.IO.Path]::TrimEndingDirectorySeparator(
                [System.IO.Path]::GetFullPath([string]$marker.root)),
            $full,
            [System.StringComparison]::Ordinal)) {
        throw 'Build-test cleanup marker identity is invalid'
    }
    $cleanupItems = @(Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction Stop)
    $cleanupReparse = @($cleanupItems | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [string]::IsNullOrWhiteSpace([string]$_.LinkType)
        })
    if ($cleanupReparse.Count -ne 0) {
        throw 'Build-test cleanup target contains an unexpected reparse point'
    }
    foreach ($item in $cleanupItems) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                $item.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly))
        }
    }
    [System.IO.Directory]::Delete($full, $true)
}

function Write-JsonFixture {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    [System.IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 50) + "`n"),
        [System.Text.UTF8Encoding]::new($false))
}

function Test-Rejected {
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [Parameter(Mandatory)][string]$Pattern
    )
    try {
        & $Operation | Out-Null
        $false
    } catch {
        $_.Exception.Message -match $Pattern
    }
}

function Test-Accepted {
    param([Parameter(Mandatory)][scriptblock]$Operation)
    try {
        & $Operation | Out-Null
        $true
    } catch {
        $false
    }
}

function Start-MutexLeaseFixture {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FixtureName
    )
    $scriptPath = Join-Path $temporaryRoot ($FixtureName + '.ps1')
    $readyPath = Join-Path $temporaryRoot ($FixtureName + '.ready')
    $releasePath = Join-Path $temporaryRoot ($FixtureName + '.release')
    $source = @'
param([string]$Name, [string]$ReadyPath, [string]$ReleasePath)
$ErrorActionPreference = 'Stop'
$mutex = [System.Threading.Mutex]::new($false, $Name)
$owns = $false
try {
    try { $owns = $mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $owns = $true }
    if (-not $owns) { exit 3 }
    [System.IO.File]::WriteAllText($ReadyPath, 'ready')
    while (-not (Test-Path -LiteralPath $ReleasePath -PathType Leaf)) {
        Start-Sleep -Milliseconds 20
    }
} finally {
    if ($owns) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
'@
    [System.IO.File]::WriteAllText(
        $scriptPath, $source, [System.Text.UTF8Encoding]::new($false))
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath,
            '-Name', $Name, '-ReadyPath', $readyPath, '-ReleasePath', $releasePath)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $helperProcesses.Add($process)
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
        if ($process.HasExited) { throw 'Mutex fixture exited before acquiring its mutex' }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Mutex fixture acquisition timed out' }
        Start-Sleep -Milliseconds 20
    }
    [pscustomobject]@{
        Process = $process
        ReleasePath = $releasePath
    }
}

function Stop-MutexLeaseFixture {
    param([Parameter(Mandatory)]$Lease)
    [System.IO.File]::WriteAllText([string]$Lease.ReleasePath, 'release')
    if (-not $Lease.Process.WaitForExit(5000)) {
        throw 'Mutex fixture did not release promptly'
    }
}

function New-ContractFixture {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Mutate
    )
    $contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json -Depth 50
    & $Mutate $contract
    $path = Join-Path $temporaryRoot ($Name + '.json')
    Write-JsonFixture -Value $contract -Path $path
    $path
}

function Test-SchemaRejected {
    param([Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Depth 50
    -not ($json | Test-Json -SchemaFile $contractSchemaPath -ErrorAction SilentlyContinue)
}

try {
    . $buildScript -RuntimeRoot $runtimeRoot

    $verified = & $buildScript -Action Verify -RuntimeRoot $runtimeRoot
    Add-Result 'canonical deterministic build contract verifies' (
        $verified.Verified -and
        $verified.SourceCommit -ceq 'd754a34e271a4fb387be63db34ef0c303e49dcf2' -and
        $verified.VersionOutput -ceq
            'newserv-d754a34 built 2026-07-11 14:06:17.000000 UTC' -and
        $verified.RuntimeImportCount -eq 17 -and
        $verified.ExecutableSha256 -ceq
            '3208b811791e591955a50084276e522cfbfa13f9e807d2287d5ce66f712f717a') `
        "files=$($verified.FileCount); bytes=$($verified.TotalBytes)"

    $contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json -Depth 50
    $zlibCTestExpected = @($contract.validation.dependencyTests)[0]
    $ctestExactTotalAccepted = Test-Accepted {
        Assert-CTestSummary -Result ([pscustomobject]@{
                StdOut = "Test project P:/build-zlib`n100% tests passed out of 18`n" +
                    "Total Test time (real) = 1.00 sec`n"
            }) -Expected $zlibCTestExpected
    }
    $ctestMutatedTotalRejected = Test-Rejected -Pattern 'totals do not match' {
        Assert-CTestSummary -Result ([pscustomobject]@{
                StdOut = "100% tests passed out of 17`n"
            }) -Expected $zlibCTestExpected
    }
    $ctestAmbiguousTotalRejected = Test-Rejected -Pattern 'ambiguous' {
        Assert-CTestSummary -Result ([pscustomobject]@{
                StdOut = "100% tests passed out of 18`n100% tests passed out of 18`n"
            }) -Expected $zlibCTestExpected
    }
    $ctestLegacySummaryRejected = Test-Rejected -Pattern 'parseable' {
        Assert-CTestSummary -Result ([pscustomobject]@{
                StdOut = "100% tests passed, 0 tests failed out of 18`n"
            }) -Expected $zlibCTestExpected
    }
    Add-Result 'CTest totals use the exact pinned output grammar' (
        $ctestExactTotalAccepted -and $ctestMutatedTotalRejected -and
        $ctestAmbiguousTotalRejected -and $ctestLegacySummaryRejected) `
        'one all-pass total is required; mutated, duplicate, and legacy summaries fail closed'

    $acceptedPreflight = Invoke-CombatCanaryPreflight
    $nativeManifestText = Get-Content -Raw -LiteralPath $nativeManifestPath
    $nativeManifest = $nativeManifestText | ConvertFrom-Json -Depth 20
    $nativePayloadIds = @($nativeManifest.payloads | ForEach-Object { [string]$_.id })
    $nativeFileCount = (@($nativeManifest.payloads) |
        Measure-Object -Property fileCount -Sum).Sum
    $ordinaryTreeFileCount = (@($nativeManifest.ordinaryFileTrees) |
        Measure-Object -Property fileCount -Sum).Sum
    Add-Result 'all non-OS native execution payloads are exact-manifested' (
        ($nativeManifestText | Test-Json -SchemaFile $nativeManifestSchemaPath `
            -ErrorAction SilentlyContinue) -and
        $nativeFileCount -eq 993 -and $ordinaryTreeFileCount -eq 30244 -and
        ($nativePayloadIds -join ',') -ceq
            'cmake,git-for-windows,gnupg,ninja,winlibs') `
        "payloads=$($nativePayloadIds -join ','); native=$nativeFileCount; ordinary=$ordinaryTreeFileCount"

    $payloadFixtureRoot = Join-Path $temporaryRoot 'native-payload-fixture'
    $payloadFixtureSubdirectory = Join-Path $payloadFixtureRoot 'sub'
    New-Item -ItemType Directory -Path $payloadFixtureSubdirectory -Force | Out-Null
    $payloadFixtureFirst = Join-Path $payloadFixtureRoot 'alpha.exe'
    $payloadFixtureSecond = Join-Path $payloadFixtureSubdirectory 'beta.dll'
    $fixtureCommand = Get-ToolPath -Id 'cmd'
    Copy-Item -LiteralPath $fixtureCommand -Destination $payloadFixtureFirst
    Copy-Item -LiteralPath $fixtureCommand -Destination $payloadFixtureSecond
    $payloadFixtureRecords = @(
        [pscustomobject]@{
            path = 'alpha.exe'
            size = (Get-Item -LiteralPath $payloadFixtureFirst).Length
            sha256 = Get-LowerSha256 -Path $payloadFixtureFirst
        },
        [pscustomobject]@{
            path = 'sub/beta.dll'
            size = (Get-Item -LiteralPath $payloadFixtureSecond).Length
            sha256 = Get-LowerSha256 -Path $payloadFixtureSecond
        }
    )
    $payloadFixture = [pscustomobject]@{
        id = 'fixture'
        fileCount = 2
        totalBytes = [long]$payloadFixtureRecords[0].size +
            [long]$payloadFixtureRecords[1].size
        files = $payloadFixtureRecords
    }
    $payloadFixtureAccepted = Test-Accepted {
        Assert-NativeExecutionPayloadFiles -Payload $payloadFixture `
            -Root $payloadFixtureRoot -Extensions @('.dll', '.exe')
    }
    [System.IO.File]::AppendAllText($payloadFixtureSecond, 'tamper')
    $payloadMutationRejected = Test-Rejected -Pattern 'hash or size changed' {
        Assert-NativeExecutionPayloadFiles -Payload $payloadFixture `
            -Root $payloadFixtureRoot -Extensions @('.dll', '.exe')
    }
    Copy-Item -LiteralPath $fixtureCommand -Destination $payloadFixtureSecond -Force
    Copy-Item -LiteralPath $fixtureCommand `
        -Destination (Join-Path $payloadFixtureRoot 'extra.exe')
    $unlistedPayloadRejected = Test-Rejected -Pattern 'file count changed' {
        Assert-NativeExecutionPayloadFiles -Payload $payloadFixture `
            -Root $payloadFixtureRoot -Extensions @('.dll', '.exe')
    }
    Add-Result 'native execution payload tampering and additions fail closed' (
        $payloadFixtureAccepted -and $payloadMutationRejected -and
        $unlistedPayloadRejected) `
        "accepted=$payloadFixtureAccepted; mutation=$payloadMutationRejected; extra=$unlistedPayloadRejected"

    $buildNativePaths = @(
        (Split-Path -Parent (Get-ToolPath -Id 'cmake')),
        (Split-Path -Parent (Get-ToolPath -Id 'ninja')),
        (Split-Path -Parent (Get-ToolPath -Id 'gcc')),
        (Split-Path -Parent (Get-ToolPath -Id 'sh')),
        (Split-Path -Parent (Get-ToolPath -Id 'tar'))
    )
    $ctestPayloadIds = @(Get-NativePayloadsForInvocation `
            -ToolPath (Get-ToolPath -Id 'ctest') -PathDirectories $buildNativePaths `
            -Manifest $script:NativeExecutionManifest | ForEach-Object {
                [string]$_.Payload.id
            })
    $ninjaPayloadIds = @(Get-NativePayloadsForInvocation `
            -ToolPath (Get-ToolPath -Id 'ninja') `
            -PathDirectories @((Split-Path -Parent (Get-ToolPath -Id 'ninja'))) `
            -Manifest $script:NativeExecutionManifest | ForEach-Object {
                [string]$_.Payload.id
            })
    $windowsSubdirectoryRejected = Test-Rejected -Pattern 'not covered' {
        Get-NativePayloadsForInvocation -ToolPath (Get-ToolPath -Id 'cmd') `
            -PathDirectories @((Join-Path (
                        Split-Path -Parent ([Environment]::SystemDirectory)) 'Temp')) `
            -Manifest $script:NativeExecutionManifest
    }
    Add-Result 'native payload selection follows the exact tool and exposed PATH roots' (
        ($ctestPayloadIds -join ',') -ceq 'cmake,git-for-windows,ninja,winlibs' -and
        ($ninjaPayloadIds -join ',') -ceq 'ninja' -and
        $windowsSubdirectoryRejected) `
        "ctest=$($ctestPayloadIds -join ','); ninja=$($ninjaPayloadIds -join ','); windows=$windowsSubdirectoryRejected"

    $localAppData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::LocalApplicationData)
    if (-not (Test-PathWithinRoot -Path $temporaryRoot -Root $localAppData)) {
        throw 'Native boundary fixture is not below LOCALAPPDATA'
    }
    $boundaryFixtureRoot = Join-Path $temporaryRoot 'native-boundary-fixture'
    $boundaryPayloads = [System.Collections.Generic.List[object]]::new()
    $boundaryRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($id in @('fixture-cmake', 'fixture-git', 'fixture-ninja', 'fixture-winlibs')) {
        $root = Join-Path $boundaryFixtureRoot $id
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $file = Join-Path $root 'tool.exe'
        Copy-Item -LiteralPath $fixtureCommand -Destination $file
        $item = Get-Item -LiteralPath $file
        $relativeRoot = [System.IO.Path]::GetRelativePath($localAppData, $root).
            Replace('\', '/')
        $boundaryPayloads.Add([pscustomobject]@{
                id = $id
                pathRoot = 'LOCALAPPDATA'
                relativeRoot = $relativeRoot
                fileCount = 1
                totalBytes = [long]$item.Length
                files = @([pscustomobject]@{
                        path = 'tool.exe'
                        size = [long]$item.Length
                        sha256 = Get-LowerSha256 -Path $file
                    })
            })
        $boundaryRoots.Add($root)
    }
    $boundaryManifest = [pscustomobject]@{
        extensions = @('.exe')
        payloads = @($boundaryPayloads)
    }
    $savedNativeManifest = $script:NativeExecutionManifest
    $boundaryAccepted = $false
    $boundaryTamperRejections = [System.Collections.Generic.List[bool]]::new()
    try {
        $script:NativeExecutionManifest = $boundaryManifest
        $boundaryAccepted = Test-Accepted {
            Assert-NativeToolPayloadBoundary -Id 'fixture' `
                -ToolPath (Join-Path $boundaryRoots[0] 'tool.exe') `
                -PathDirectories @($boundaryRoots)
        }
        foreach ($root in @($boundaryRoots)) {
            $file = Join-Path $root 'tool.exe'
            [System.IO.File]::AppendAllText($file, 'tamper')
            $boundaryTamperRejections.Add((Test-Rejected -Pattern 'hash or size changed' {
                        Assert-NativeToolPayloadBoundary -Id 'fixture' `
                            -ToolPath (Join-Path $boundaryRoots[0] 'tool.exe') `
                            -PathDirectories @($boundaryRoots)
                    }))
            Copy-Item -LiteralPath $fixtureCommand -Destination $file -Force
        }
    } finally {
        $script:NativeExecutionManifest = $savedNativeManifest
    }
    Add-Result 'every exposed non-system payload is rehashed immediately before execution' (
        $boundaryAccepted -and $boundaryTamperRejections.Count -eq $boundaryRoots.Count -and
        @($boundaryTamperRejections | Where-Object { -not $_ }).Count -eq 0) `
        "accepted=$boundaryAccepted; tamperRejections=$($boundaryTamperRejections.Count)"

    $ordinaryFixtureRoot = Join-Path $temporaryRoot 'ordinary-tree-fixture'
    New-Item -ItemType Directory -Path $ordinaryFixtureRoot | Out-Null
    $ordinaryModule = Join-Path $ordinaryFixtureRoot 'platform.cmake'
    $ordinaryLibrary = Join-Path $ordinaryFixtureRoot 'runtime.a'
    [System.IO.File]::WriteAllText($ordinaryModule, 'set(FIXTURE 1)')
    [System.IO.File]::WriteAllText($ordinaryLibrary, 'static-library-fixture')
    $ordinaryState = Get-OrdinaryFileTreeState -Root $ordinaryFixtureRoot `
        -Label 'ordinary tree fixture'
    $ordinaryFixture = [pscustomobject]@{
        id = 'fixture'
        fileCount = $ordinaryState.FileCount
        totalBytes = $ordinaryState.TotalBytes
        rootSha256 = $ordinaryState.RootSha256
    }
    $ordinaryFixtureAccepted = Test-Accepted {
        Assert-OrdinaryFileTree -Tree $ordinaryFixture -Root $ordinaryFixtureRoot
    }
    [System.IO.File]::AppendAllText($ordinaryModule, 'tamper')
    $ordinaryMutationRejected = Test-Rejected -Pattern 'tree changed' {
        Assert-OrdinaryFileTree -Tree $ordinaryFixture -Root $ordinaryFixtureRoot
    }
    [System.IO.File]::WriteAllText($ordinaryModule, 'set(FIXTURE 1)')
    [System.IO.File]::WriteAllText(
        (Join-Path $ordinaryFixtureRoot 'unlisted.h'), 'unlisted-input')
    $ordinaryAdditionRejected = Test-Rejected -Pattern 'tree changed' {
        Assert-OrdinaryFileTree -Tree $ordinaryFixture -Root $ordinaryFixtureRoot
    }
    Add-Result 'non-executable build-input mutation and addition fail closed' (
        $ordinaryFixtureAccepted -and $ordinaryMutationRejected -and
        $ordinaryAdditionRejected) `
        "accepted=$ordinaryFixtureAccepted; mutation=$ordinaryMutationRejected; extra=$ordinaryAdditionRejected"
    $interceptionRoot = Join-Path $temporaryRoot 'path-interception'
    New-Item -ItemType Directory -Path $interceptionRoot | Out-Null
    foreach ($name in @(
            'cmd.exe', 'git.exe', 'gpgv.exe', 'tar.exe', 'cmake.exe', 'ctest.exe',
            'objdump.exe')) {
        Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $interceptionRoot $name)
    }
    $interceptionVerified = & {
        param($InterceptPath)
        $savedPath = $env:PATH
        function gpgv { throw 'function interception executed' }
        function tar { throw 'function interception executed' }
        Set-Alias -Name git -Value Get-Date -Scope Local
        Set-Alias -Name cmake -Value Get-Date -Scope Local
        try {
            $env:PATH = $InterceptPath + ';' + $savedPath
            $gitVersion = Invoke-PinnedNative -Id 'git' -Arguments @('--version') `
                -Label 'intercepted Git fixture' `
                -PathDirectories @((Split-Path -Parent (Get-ToolPath -Id 'git')))
            $cmakeVersion = Invoke-PinnedNative -Id 'cmake' -Arguments @('--version') `
                -Label 'intercepted CMake fixture' `
                -PathDirectories @((Split-Path -Parent (Get-ToolPath -Id 'cmake')))
            $gpgvVersion = Invoke-PinnedNative -Id 'gpgv' -Arguments @('--version') `
                -Label 'intercepted gpgv fixture' `
                -PathDirectories @((Split-Path -Parent (Get-ToolPath -Id 'gpgv')))
            [pscustomobject]@{
                Verified = $gitVersion.StdOut -match '^git version ' -and
                    $cmakeVersion.StdOut -match '^cmake version ' -and
                    $gpgvVersion.StdOut -match '^gpgv \(GnuPG\) '
            }
        } finally {
            $env:PATH = $savedPath
        }
    } $interceptionRoot
    Add-Result 'alias, function, and PATH interception cannot replace pinned tools' (
        $interceptionVerified.Verified) `
        'Verify used exact full Application paths after hash/version checks'

    $gitRecord = @($contract.toolchain.tools | Where-Object id -ceq 'git')[0]
    $bashRecord = @($contract.toolchain.tools | Where-Object id -ceq 'bash')[0]
    $gpgvRecord = @($contract.toolchain.tools | Where-Object id -ceq 'gpgv')[0]
    $objdumpRecord = @($contract.toolchain.tools | Where-Object id -ceq 'objdump')[0]
    $keyringPath = Join-Path $runtimeRoot `
        ([string]$contract.signatureVerification.keyring.source).Replace('/', '\')
    $keyringItem = Get-Item -LiteralPath $keyringPath -Force
    Add-Result 'Git, Bash, gpgv, PE parser, and the public keyring are exact' (
        [string]$gitRecord.relativePath -ceq 'Git\mingw64\bin\git.exe' -and
        [string]$bashRecord.relativePath -ceq 'Git\usr\bin\bash.exe' -and
        [string]$gpgvRecord.relativePath -ceq 'GnuPG\bin\gpgv.exe' -and
        [string]$objdumpRecord.relativePath -like '*\mingw64\bin\objdump.exe' -and
        [string]$objdumpRecord.sha256 -ceq
            '726acab4db3267478f323bee4092824c29e583c036e93aaef7e8846f7107b9bf' -and
        $keyringItem.IsReadOnly -and
        $keyringItem.Length -eq [long]$contract.signatureVerification.keyring.size -and
        (Get-LowerSha256 -Path $keyringPath) -ceq
            [string]$contract.signatureVerification.keyring.sha256) `
        'no launcher shim, default keyring, or writable trust file is accepted'

    $injectionVariables = @(
        'BASH_ENV', 'ENV', 'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS',
        'MAKEFLAGS', 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_PROJECT_INCLUDE',
        'GIT_CONFIG_COUNT', 'GIT_ASKPASS', 'SSH_ASKPASS', 'HTTP_PROXY', 'HTTPS_PROXY',
        'GIT_NO_REPLACE_OBJECTS', 'GIT_REPLACE_REF_BASE', 'GIT_OBJECT_DIRECTORY',
        'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'PROCESSOR_ARCHITECTURE')
    $savedInjection = @{}
    foreach ($name in $injectionVariables) {
        $savedInjection[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, 'injected-fixture', 'Process')
    }
    try {
        $environmentResult = Invoke-PinnedNative -Id 'cmd' `
            -Arguments @('/d', '/c', 'set') -Label 'hermetic environment fixture'
    } finally {
        foreach ($name in $injectionVariables) {
            [Environment]::SetEnvironmentVariable($name, $savedInjection[$name], 'Process')
        }
    }
    $leakedNames = @($injectionVariables | Where-Object {
            $_ -cne 'PROCESSOR_ARCHITECTURE' -and
            [string]$environmentResult.StdOut -match (
                '(?im)^' + [regex]::Escape($_) + '=')
        })
    $childArchitecture = [regex]::Match(
        [string]$environmentResult.StdOut,
        '(?im)^PROCESSOR_ARCHITECTURE=(?<value>[^\r\n]+)\r?$').Groups['value'].Value
    Add-Result 'native child environment rejects caller injection variables' (
        $leakedNames.Count -eq 0 -and $childArchitecture -ceq 'AMD64') `
        ('leaked=' + ($leakedNames -join ',') + '; architecture=' + $childArchitecture)

    $profileHome = Join-Path $temporaryRoot 'bash-profile-home'
    New-Item -ItemType Directory -Path $profileHome | Out-Null
    $profileMarker = Join-Path $profileHome 'profile-loaded'
    [System.IO.File]::WriteAllText(
        (Join-Path $profileHome '.bash_profile'),
        'touch "$HOME/profile-loaded"',
        [System.Text.UTF8Encoding]::new($false))
    $bashResult = Invoke-PinnedNative -Id 'bash' -Arguments @(
        '--noprofile', '--norc', '-c', 'exit 0') -Label 'bash profile isolation fixture' `
        -Environment @{ HOME = (Convert-ToMsysPath -Path $profileHome) } `
        -PathDirectories @((Split-Path -Parent (Get-ToolPath -Id 'bash')))
    Add-Result 'Bash login and environment profiles are never loaded' (
        $bashResult.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $profileMarker)) `
        '--noprofile --norc -c is mandatory'

    $toolCopy = Join-Path $temporaryRoot 'tool-copy.exe'
    Copy-Item -LiteralPath (Get-ToolPath -Id 'cmd') -Destination $toolCopy
    $toolCopyItem = Get-Item -LiteralPath $toolCopy
    $savedToolRecords = $script:ToolRecords
    $fixtureRecords = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $fixtureRecords.Add('cmd', $savedToolRecords['cmd'])
    $fixtureRecords.Add('fixture', [pscustomobject]@{
            Path = $toolCopy
            Record = [pscustomobject]@{
                executableSize = [long]$toolCopyItem.Length
                sha256 = Get-LowerSha256 -Path $toolCopy
            }
        })
    try {
        $script:ToolRecords = $fixtureRecords
        $stream = [System.IO.File]::Open($toolCopy, [System.IO.FileMode]::Append)
        try { $stream.WriteByte(0) } finally { $stream.Dispose() }
        $changedToolRejected = Test-Rejected -Pattern 'changed before invocation' {
            Invoke-PinnedNative -Id 'fixture' -Arguments @('/d', '/c', 'exit 0')
        }
    } finally {
        $script:ToolRecords = $savedToolRecords
    }
    Add-Result 'tool size and hash are rechecked immediately before invocation' `
        $changedToolRejected 'a post-preflight executable replacement is rejected'

    $deterministic = @($contract.reproducibility.builds)
    Add-Result 'contract records two byte-identical clean builds' (
        $deterministic.Count -eq 2 -and
        [long]$deterministic[0].size -eq [long]$deterministic[1].size -and
        [string]$deterministic[0].sha256 -ceq [string]$deterministic[1].sha256 -and
        [string]$deterministic[1].sha256 -ceq [string]$contract.output.executable.sha256) `
        "sha256=$($deterministic[0].sha256)"

    $wrongRecordedBuild = New-ContractFixture -Name 'wrong-recorded-build' -Mutate {
        param($value)
        $value.reproducibility.builds[1].sha256 = '0' * 64
    }
    Add-Result 'Verify rejects inconsistent deterministic build records' (
        Test-Rejected -Pattern 'build contract identity is not exact' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongRecordedBuild
        }) 'both recorded builds must equal each other and the executable contract'

    $seriesText = Get-Content -Raw -LiteralPath $seriesPath
    Add-Result 'ordered patch series matches its tracked exact schema' (
        $seriesText | Test-Json -SchemaFile $seriesSchemaPath -ErrorAction SilentlyContinue) `
        'the local schema fixes source, environment, order, scope, and one patch'

    $duplicateDependencyContract = $contract | ConvertTo-Json -Depth 50 |
        ConvertFrom-Json -Depth 50
    $duplicateDependencyContract.dependencies[1].id = 'asio'
    $duplicateToolContract = $contract | ConvertTo-Json -Depth 50 |
        ConvertFrom-Json -Depth 50
    $duplicateToolContract.toolchain.tools[2].id = 'gcc'
    $wrongBuildRunsContract = $contract | ConvertTo-Json -Depth 50 |
        ConvertFrom-Json -Depth 50
    $wrongBuildRunsContract.reproducibility.builds[1].run = 1
    Add-Result 'schema enforces exact unique dependency/tool IDs and build runs' (
        (Test-SchemaRejected -Value $duplicateDependencyContract) -and
        (Test-SchemaRejected -Value $duplicateToolContract) -and
        (Test-SchemaRejected -Value $wrongBuildRunsContract)) `
        'duplicate IDs and duplicate run 1 are rejected'

    $exactClaimMutations = [System.Collections.Generic.List[bool]]::new()
    foreach ($mutation in @(
            { param($value) $value.reproducibility.pathNormalization[0] = '-ffile-prefix-map=X:=.' },
            { param($value) $value.reproducibility.linkerFlags += '-static-libgcc' },
            { param($value) $value.validation.dependencyTests[0].passed = 17 },
            { param($value) $value.validation.dependencyTests[1].name = 'other CTest' },
            { param($value) $value.validation.newservCTest = 'passed' },
            { param($value) $value.output.versionOutput = 'unverified version' },
            {
                param($value)
                $first = $value.output.runtimeImports[0]
                $value.output.runtimeImports[0] = $value.output.runtimeImports[1]
                $value.output.runtimeImports[1] = $first
            }
        )) {
        $fixture = $contract | ConvertTo-Json -Depth 50 | ConvertFrom-Json -Depth 50
        & $mutation $fixture
        $exactClaimMutations.Add((Test-SchemaRejected -Value $fixture))
    }
    Add-Result 'schema fixes every reproducibility and output claim exactly' (
        @($exactClaimMutations | Where-Object { -not $_ }).Count -eq 0) `
        'path maps, passed counts, linker flags, newserv status, version, and import order are constants'

    $releaseRoot = Join-Path $runtimeRoot ($contract.output.rootRelative.Replace('/', '\'))
    $manifestPath = Join-Path $releaseRoot $contract.output.releaseManifest.path
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -Depth 20
    $total = [long]0
    foreach ($file in @($manifest.files)) { $total += [long]$file.size }
    $reparse = @(Get-ChildItem -LiteralPath $releaseRoot -Recurse -Force | Where-Object {
            $_.LinkType -or
            (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
        })
    Add-Result 'release manifest is complete and reparse-free' (
        $reparse.Count -eq 0 -and
        @($manifest.files).Count -eq [int]$contract.output.fileCount -and
        $total -eq [long]$contract.output.totalBytes) `
        "manifestFiles=$(@($manifest.files).Count); reparse=$($reparse.Count)"

    $manifestPaths = [string[]]@($manifest.files | ForEach-Object { [string]$_.path })
    $ordinalManifestPaths = [string[]]@($manifestPaths)
    [Array]::Sort($ordinalManifestPaths, [System.StringComparer]::Ordinal)
    Add-Result 'release manifest paths are unique and strictly ordinal' (
        ($manifestPaths -join "`n") -ceq ($ordinalManifestPaths -join "`n") -and
        ([System.Collections.Generic.HashSet[string]]::new(
                $manifestPaths, [System.StringComparer]::OrdinalIgnoreCase)).Count -eq
            $manifestPaths.Count) `
        "paths=$($manifestPaths.Count)"

    $inventoryOid = '0' * 40
    $duplicateInventoryRejected = Test-Rejected -Pattern 'duplicate or case-colliding' {
        ConvertFrom-GitTrackedFileInventoryText -Text (
            "100644 $inventoryOid 0`tSystem/file.dat$([char]0)" +
            "100755 $inventoryOid 0`tsystem/FILE.dat$([char]0)")
    }
    $unsupportedModeRejected = Test-Rejected -Pattern 'unsupported Git mode' {
        ConvertFrom-GitTrackedFileInventoryText -Text (
            "160000 $inventoryOid 0`tsystem/submodule$([char]0)")
    }
    $unsafeInventoryPathRejected = Test-Rejected -Pattern 'unsafe' {
        ConvertFrom-GitTrackedFileInventoryText -Text (
            "100644 $inventoryOid 0`tsystem/../outside.dat$([char]0)")
    }
    Add-Result 'tracked inventory rejects collisions, unsafe paths, and unexpected modes' (
        $duplicateInventoryRejected -and $unsupportedModeRejected -and
        $unsafeInventoryPathRejected) `
        "collision=$duplicateInventoryRejected; mode=$unsupportedModeRejected; unsafe=$unsafeInventoryPathRejected"

    $generatedRevisionRoot = Join-Path $temporaryRoot 'generated-revision-fixture'
    $generatedRevisionSource = Join-Path $generatedRevisionRoot 'src'
    New-Item -ItemType Directory -Path $generatedRevisionSource -Force | Out-Null
    $generatedRevisionPath = Join-Path $generatedRevisionSource 'Revision.cc'
    $generatedPlaceholderPath = Join-Path $generatedRevisionSource '__Revision__.cc'
    $generatedRevisionText = "#include `"Revision.hh`"`n`n" +
        "const char* GIT_REVISION_HASH = `"$($script:BuildRevision)`";`n" +
        'const uint64_t BUILD_TIMESTAMP = static_cast<uint64_t>(' +
        "$($script:SourceDateEpoch)) * 1000000;`n"
    $generatedCheckout = [pscustomobject]@{ Repository = $generatedRevisionRoot }
    [System.IO.File]::WriteAllText(
        $generatedRevisionPath, $generatedRevisionText,
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllBytes($generatedPlaceholderPath, [byte[]]::new(0))
    $generatedRevisionAccepted = Test-Accepted {
        Remove-NewservGeneratedRevisionFiles -Checkout $generatedCheckout
    }
    $generatedRevisionRemoved = -not (Test-Path -LiteralPath $generatedRevisionPath) -and
        -not (Test-Path -LiteralPath $generatedPlaceholderPath)
    [System.IO.File]::WriteAllText(
        $generatedRevisionPath, ($generatedRevisionText + 'tamper'),
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllBytes($generatedPlaceholderPath, [byte[]]::new(0))
    $generatedRevisionMutationRejected = Test-Rejected -Pattern 'not the exact deterministic' {
        Remove-NewservGeneratedRevisionFiles -Checkout $generatedCheckout
    }
    Add-Result 'only exact deterministic generated revision files are removed' (
        $generatedRevisionAccepted -and $generatedRevisionRemoved -and
        $generatedRevisionMutationRejected) `
        "accepted=$generatedRevisionAccepted; removed=$generatedRevisionRemoved; mutation=$generatedRevisionMutationRejected"

    $packageSourceOrigin = Join-Path $runtimeRoot 'sources\newserv-git-d754a34e'
    $packageCheckout = New-LocalObjectGitCheckout -SourcePath $packageSourceOrigin `
        -DestinationPath (Join-Path $temporaryRoot 'newserv-package-checkout') `
        -Commit ([string]$contract.source.commit) -Label 'package inventory fixture'
    Invoke-HermeticGit -RepositoryPath $packageCheckout.Repository `
        -AllowedAlternateObjectRoot $packageCheckout.AlternateObjectRoot `
        -Arguments @('apply', '--cached', '--whitespace=error-all', $patchPath) `
        -Label 'package inventory fixture patch' | Out-Null
    $packageCheckoutPrefix = [System.IO.Path]::TrimEndingDirectorySeparator(
        [string]$packageCheckout.Repository) + [System.IO.Path]::DirectorySeparatorChar
    Invoke-HermeticGit -RepositoryPath $packageCheckout.Repository `
        -AllowedAlternateObjectRoot $packageCheckout.AlternateObjectRoot `
        -Arguments @('checkout-index', '--all', '--force',
            ('--prefix=' + $packageCheckoutPrefix)) `
        -Label 'package inventory fixture worktree' | Out-Null
    Assert-NewservPatchedCheckoutStatus -Checkout $packageCheckout -Run 0
    $ignoredCachePaths = @(
        'system/patch-bb/.metadata-cache.json',
        'system/patch-pc/.metadata-cache.json',
        'system/untracked-package-fixture.dat'
    )
    foreach ($relative in $ignoredCachePaths) {
        $path = Join-Path $packageCheckout.Repository $relative.Replace('/', '\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        [System.IO.File]::WriteAllText($path, 'untracked package fixture')
    }
    $packageInventory = Get-GitTrackedFileInventory `
        -RepositoryPath $packageCheckout.Repository `
        -AllowedAlternateObjectRoot $packageCheckout.AlternateObjectRoot `
        -Label 'package inventory fixture tracked files'
    $packagePlan = @(Get-NewservPackageSystemPlan `
            -RepositoryPath $packageCheckout.Repository -Inventory $packageInventory)
    $plannedSystemPaths = [string[]]@($packagePlan | ForEach-Object {
            [string]$_.DestinationPath
        })
    $publishedSystemPaths = [string[]]@($manifestPaths | Where-Object {
            $_.StartsWith('system/', [System.StringComparison]::Ordinal)
        })
    $packagePathDiff = @(Compare-Object -ReferenceObject $plannedSystemPaths `
        -DifferenceObject $publishedSystemPaths -CaseSensitive)
    $untrackedPlanEntries = @($packagePlan | Where-Object {
            [string]$_.TrackedPath -cin $ignoredCachePaths -or
            [string]$_.DestinationPath -cin $ignoredCachePaths
        })
    $resolvedLinks = @($packagePlan | Where-Object Mode -ceq '120000')
    $trackedReadme = Resolve-GitTrackedWorktreeSource `
        -RepositoryPath $packageCheckout.Repository -Inventory $packageInventory `
        -TrackedPath 'README.md'
    $trackedLicense = Resolve-GitTrackedWorktreeSource `
        -RepositoryPath $packageCheckout.Repository -Inventory $packageInventory `
        -TrackedPath 'LICENSE'
    Add-Result 'package inventory is exactly tracked, link-resolved, and origin-independent' (
        $packagePlan.Count -eq 2905 -and $packagePathDiff.Count -eq 0 -and
        $untrackedPlanEntries.Count -eq 0 -and $resolvedLinks.Count -gt 0 -and
        $trackedReadme.ResolvedTrackedPath -ceq 'README.md' -and
        $trackedLicense.ResolvedTrackedPath -ceq 'LICENSE') `
        "planned=$($packagePlan.Count); diff=$($packagePathDiff.Count); links=$($resolvedLinks.Count); untracked=$($untrackedPlanEntries.Count)"

    $releaseExecutable = Join-Path $releaseRoot ([string]$contract.output.executable.path)
    $actualVersion = Get-ReleaseVersionOutput -ExecutablePath $releaseExecutable
    $actualImports = @(Get-PeRuntimeImports -ExecutablePath $releaseExecutable)
    Add-Result 'version output and PE imports are recomputed from the release' (
        $actualVersion -ceq [string]$contract.output.versionOutput -and
        ($actualImports -join "`n") -ceq
            (@($contract.output.runtimeImports | ForEach-Object { [string]$_ }) -join "`n")) `
        "version=$actualVersion; imports=$($actualImports.Count)"

    $pathNeedleRoot = Join-Path $temporaryRoot 'path-needle-fixture'
    New-Item -ItemType Directory -Path $pathNeedleRoot | Out-Null
    $pathNeedleFile = Join-Path $pathNeedleRoot 'fixture.bin'
    [System.IO.File]::WriteAllBytes($pathNeedleFile, [byte[]](1, 2, 3, 4))
    $cleanPathFixtureAccepted = Test-Accepted {
        Assert-NoDeterministicBuildPathNeedles -Root $pathNeedleRoot
    }
    [System.IO.File]::WriteAllBytes(
        $pathNeedleFile, [System.Text.Encoding]::ASCII.GetBytes('prefix P:\build'))
    $asciiPathRejected = Test-Rejected -Pattern 'ASCII P:\\' {
        Assert-NoDeterministicBuildPathNeedles -Root $pathNeedleRoot
    }
    [System.IO.File]::WriteAllBytes(
        $pathNeedleFile, [System.Text.Encoding]::Unicode.GetBytes('prefix P:/build'))
    $utf16PathRejected = Test-Rejected -Pattern 'UTF-16LE P:/' {
        Assert-NoDeterministicBuildPathNeedles -Root $pathNeedleRoot
    }
    Add-Result 'ASCII and UTF-16 deterministic build paths fail closed' (
        $cleanPathFixtureAccepted -and $asciiPathRejected -and $utf16PathRejected) `
        "clean=$cleanPathFixtureAccepted; ascii=$asciiPathRejected; utf16=$utf16PathRejected"

    $expectedClientFunctions = @(
        'AccurateKillCount.s',
        'FastTekker.s',
        'HungryMagSound.s',
        'NoRareSelling.s',
        'PaletteBB.s',
        'notes.txt'
    )
    $clientFunctionRoot = Join-Path $releaseRoot 'system\client-functions'
    $actualClientFunctions = @(Get-ChildItem -LiteralPath $clientFunctionRoot -File -Force |
        Sort-Object Name | ForEach-Object Name)
    $clientFunctionDiff = @(Compare-Object -ReferenceObject $expectedClientFunctions `
        -DifferenceObject $actualClientFunctions -CaseSensitive)
    Add-Result 'package contains only reviewed Phase 1 client-function sources' (
        $clientFunctionDiff.Count -eq 0) (
        'files=' + ($actualClientFunctions -join ','))

    $sourceLock = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'config\sources.lock.json') | ConvertFrom-Json -Depth 50
    $buildComponent = @($sourceLock.components |
        Where-Object id -ceq 'newserv-combat-canary-build')
    $criticalMembers = @($buildComponent[0].members | ForEach-Object path)
    $expectedCriticalMembers = @(
        'config/combat-canary-build.json',
        'config/schemas/combat-canary-build.schema.json',
        'config/native-execution-payloads.json',
        'config/schemas/native-execution-payloads.schema.json',
        'patches/newserv/series.json',
        'config/schemas/newserv-patch-series.schema.json',
        'release/release-manifest.json',
        'release/newserv-windows.exe'
    )
    $criticalDiff = @(Compare-Object -ReferenceObject $expectedCriticalMembers `
        -DifferenceObject $criticalMembers -CaseSensitive)
    Add-Result 'source lock has one exact record for every critical build artifact' (
        $buildComponent.Count -eq 1 -and
        $criticalMembers.Count -eq $expectedCriticalMembers.Count -and
        $criticalDiff.Count -eq 0) ('members=' + ($criticalMembers -join ','))

    $duplicateLock = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'config\sources.lock.json') | ConvertFrom-Json -Depth 50
    $duplicateComponent = $duplicateLock.components |
        Where-Object id -ceq 'newserv-combat-canary-build'
    $duplicateComponent.members = @($duplicateComponent.members) +
        @($duplicateComponent.members | Where-Object path -ceq 'release/newserv-windows.exe')[0]
    $duplicateLockPath = Join-Path $temporaryRoot 'duplicate-source-lock.json'
    Write-JsonFixture -Value $duplicateLock -Path $duplicateLockPath
    $canonicalSourceLockPath = $script:SourceLockPath
    try {
        $script:SourceLockPath = $duplicateLockPath
        $duplicateRejected = Test-Rejected -Pattern 'exactly eight critical members|ambiguous' {
            Assert-SourceLockInputs -Contract $contract
        }
    } finally {
        $script:SourceLockPath = $canonicalSourceLockPath
    }
    Add-Result 'duplicate critical source-lock member is rejected' $duplicateRejected `
        'release members cannot be ambiguous'

    $wrongCommit = New-ContractFixture -Name 'wrong-commit' -Mutate {
        param($value)
        $value.source.commit = '0000000000000000000000000000000000000000'
    }
    Add-Result 'wrong source commit is rejected' (Test-Rejected `
            -Pattern 'does not match its tracked schema|identity is not exact' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongCommit
        }) 'source commit is exact-client-gated'

    $wrongArchiveHash = New-ContractFixture -Name 'wrong-archive-hash' -Mutate {
        param($value)
        ($value.dependencies | Where-Object id -ceq 'libiconv').sha256 = '0' * 64
    }
    Add-Result 'wrong dependency hash is rejected' (Test-Rejected -Pattern 'SHA-256 mismatch' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongArchiveHash
        }) 'locked archive hash is mandatory'

    $wrongSeriesHash = New-ContractFixture -Name 'wrong-series-hash' -Mutate {
        param($value)
        $value.patchSeries.sha256 = '0' * 64
    }
    Add-Result 'wrong patch-series hash is rejected' (Test-Rejected `
            -Pattern 'patch-series hash changed' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongSeriesHash
        }) 'ordered series hash is mandatory'

    $wrongToolHash = New-ContractFixture -Name 'wrong-tool-hash' -Mutate {
        param($value)
        ($value.toolchain.tools | Where-Object id -ceq 'gcc').sha256 = '0' * 64
    }
    Add-Result 'wrong toolchain hash is rejected' (Test-Rejected `
            -Pattern 'Toolchain binary mismatch' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongToolHash
        }) 'compiler executable is hash-locked'

    $wrongNativeManifestHash = New-ContractFixture -Name 'wrong-native-manifest-hash' `
        -Mutate {
        param($value)
        $value.toolchain.nativeExecutionManifest.sha256 = '0' * 64
    }
    Add-Result 'wrong native execution manifest hash is rejected' (Test-Rejected `
            -Pattern 'File SHA-256 mismatch' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongNativeManifestHash
        }) 'all non-OS native executable and loadable-code records are hash-locked'

    $wrongManifestHash = New-ContractFixture -Name 'wrong-manifest-hash' -Mutate {
        param($value)
        $value.output.releaseManifest.sha256 = '0' * 64
    }
    Add-Result 'wrong release-manifest contract is rejected' (Test-Rejected `
            -Pattern 'File (size|SHA-256) mismatch|source-lock' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -BuildContractPath $wrongManifestHash
        }) 'the tracked contract and release manifest are hash-locked together'

    $seriesFixtureRoot = Join-Path $temporaryRoot 'unlisted-series'
    New-Item -ItemType Directory -Path $seriesFixtureRoot | Out-Null
    Copy-Item -LiteralPath $seriesPath -Destination (Join-Path $seriesFixtureRoot 'series.json')
    Copy-Item -LiteralPath $patchPath -Destination (
        Join-Path $seriesFixtureRoot '0001-deterministic-revision-metadata.patch')
    Copy-Item -LiteralPath $patchPath -Destination (
        Join-Path $seriesFixtureRoot '9999-unlisted.patch')
    Add-Result 'unlisted patch is rejected' (Test-Rejected `
            -Pattern 'unlisted newserv patch' {
            & $buildScript -Action Verify -RuntimeRoot $runtimeRoot `
                -PatchSeriesPath (Join-Path $seriesFixtureRoot 'series.json')
        }) 'only the single reviewed patch may exist'

    $preflightText = (Get-Command Invoke-CombatCanaryPreflight).ScriptBlock.ToString()
    $preflightAccepted = $null -ne $acceptedPreflight
    Add-Result 'Build preflight is independent from published release verification' (
        $preflightAccepted -and $preflightText -notmatch 'Assert-Release') `
        'missing or corrupt releases can reach guarded publication replacement'

    $gitConfigFixture = Join-Path $temporaryRoot 'git-config-fixture'
    New-Item -ItemType Directory -Path (Join-Path $gitConfigFixture '.git') -Force | Out-Null
    $minimalGitConfig = "[core]`n" +
        "`trepositoryformatversion = 0`n" +
        "`tfilemode = false`n" +
        "`tbare = false`n" +
        "`tlogallrefupdates = true`n" +
        "`tsymlinks = false`n" +
        "`tignorecase = true`n"
    $gitFixtureConfigPath = Join-Path $gitConfigFixture '.git\config'
    [System.IO.File]::WriteAllText(
        $gitFixtureConfigPath, $minimalGitConfig, [System.Text.UTF8Encoding]::new($false))
    $minimalGitConfigAccepted = Test-Accepted {
        Assert-GitRepositoryConfig -Path $gitConfigFixture -Label 'config fixture'
    }
    $disallowedConfigResults = [System.Collections.Generic.List[bool]]::new()
    foreach ($addition in @(
            "[include]`n`tpath = elsewhere.cfg`n",
            "[includeIf `"gitdir:work/`"]`n`tpath = elsewhere.cfg`n",
            "[url `"https://invalid.example/`"]`n`tinsteadOf = local`n",
            "[filter `"fixture`"]`n`tprocess = command`n",
            "[credential]`n`thelper = command`n",
            "[http]`n`tproxy = http://invalid.example/`n",
            "[core]`n`thooksPath = hooks`n",
            "[core]`n`tfsmonitor = command`n",
            "[core]`n`tunknown = value`n"
        )) {
        [System.IO.File]::WriteAllText(
            $gitFixtureConfigPath,
            ($minimalGitConfig + $addition),
            [System.Text.UTF8Encoding]::new($false))
        $disallowedConfigResults.Add((Test-Rejected `
                    -Pattern 'disallowed|minimal exact|unsupported|duplicate' {
                    Assert-GitRepositoryConfig -Path $gitConfigFixture -Label 'config fixture'
                }))
    }
    Add-Result 'repository-local Git config uses a strict minimal allowlist' (
        $minimalGitConfigAccepted -and
        @($disallowedConfigResults | Where-Object { -not $_ }).Count -eq 0) `
        'include, URL, filter, credential, proxy, hooks, fsmonitor, and unknown keys are rejected'

    [System.IO.File]::WriteAllText(
        $gitFixtureConfigPath, $minimalGitConfig, [System.Text.UTF8Encoding]::new($false))
    $metadataRejections = [System.Collections.Generic.List[bool]]::new()
    foreach ($case in @(
            @{ Path = 'refs\replace\0000000000000000000000000000000000000000'; Text = 'replacement' },
            @{ Path = 'logs\refs\replace\0000000000000000000000000000000000000000'; Text = 'log' },
            @{ Path = 'info\grafts'; Text = '0000000000000000000000000000000000000000' },
            @{ Path = 'shallow'; Text = '0000000000000000000000000000000000000000' },
            @{ Path = 'info\attributes'; Text = '* filter=fixture' },
            @{ Path = 'objects\info\http-alternates'; Text = 'https://invalid.example/' },
            @{ Path = 'commondir'; Text = '..' },
            @{
                Path = 'packed-refs'
                Text = '0000000000000000000000000000000000000000 refs/replace/fixture'
            }
        )) {
        $path = Join-Path (Join-Path $gitConfigFixture '.git') ([string]$case.Path)
        $parent = Split-Path -Parent $path
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        [System.IO.File]::WriteAllText(
            $path, ([string]$case.Text + "`n"), [System.Text.UTF8Encoding]::new($false))
        $metadataRejections.Add((Test-Rejected `
                    -Pattern 'forbidden|replacement reference' {
                    Assert-GitRepositoryConfig -Path $gitConfigFixture `
                        -Label 'metadata fixture'
                }))
        [System.IO.File]::Delete($path)
        $current = $parent
        $metadataRoot = Join-Path $gitConfigFixture '.git'
        while (-not [string]::Equals($current, $metadataRoot,
                [System.StringComparison]::OrdinalIgnoreCase) -and
            @(Get-ChildItem -LiteralPath $current -Force).Count -eq 0) {
            [System.IO.Directory]::Delete($current)
            $current = Split-Path -Parent $current
        }
    }
    Add-Result 'replace, graft, shallow, and attributes metadata fails closed' (
        @($metadataRejections | Where-Object { -not $_ }).Count -eq 0) `
        'loose and packed replacement refs plus equivalent metadata mechanisms are rejected before Git'

    $metadataTargetRoot = Join-Path $temporaryRoot 'git-metadata-reparse-target'
    New-Item -ItemType Directory -Path $metadataTargetRoot | Out-Null
    $metadataTargetFile = Join-Path $metadataTargetRoot 'index'
    [System.IO.File]::WriteAllText($metadataTargetFile, 'index target')
    $metadataFileLink = Join-Path $gitConfigFixture '.git\index'
    New-Item -ItemType SymbolicLink -Path $metadataFileLink `
        -Target $metadataTargetFile | Out-Null
    $metadataFileReparseRejected = Test-Rejected `
        -Pattern 'metadata contains a reparse point' {
        Assert-GitRepositoryConfig -Path $gitConfigFixture -Label 'metadata file fixture'
    }
    [System.IO.File]::Delete($metadataFileLink)
    $metadataDirectoryTarget = Join-Path $metadataTargetRoot 'objects'
    New-Item -ItemType Directory -Path $metadataDirectoryTarget | Out-Null
    $metadataDirectoryLink = Join-Path $gitConfigFixture '.git\objects'
    New-Item -ItemType Junction -Path $metadataDirectoryLink `
        -Target $metadataDirectoryTarget | Out-Null
    $fixtureJunctions.Add($metadataDirectoryLink)
    $metadataAncestorReparseRejected = Test-Rejected `
        -Pattern 'metadata contains a reparse point' {
        Assert-GitRepositoryConfig -Path $gitConfigFixture `
            -Label 'metadata ancestor fixture'
    }
    [System.IO.Directory]::Delete($metadataDirectoryLink)
    Add-Result 'metadata file and ancestor reparse points fail before Git' (
        $metadataFileReparseRejected -and $metadataAncestorReparseRejected) `
        "file=$metadataFileReparseRejected; ancestor=$metadataAncestorReparseRejected"

    $gitWorkingDirectory = Get-VerifiedGitWorkingDirectory
    Add-Result 'Git always runs from a verified empty working directory' (
        @(Get-ChildItem -LiteralPath $gitWorkingDirectory -Force).Count -eq 0) `
        "empty=$gitWorkingDirectory"

    $alternateRuntime = Join-Path $temporaryRoot 'ordinary-alternate-runtime'
    New-Item -ItemType Directory -Path $alternateRuntime | Out-Null
    Write-JsonFixture -Value ([ordered]@{
            schemaVersion = 1
            installationId = [Guid]::NewGuid().ToString('D')
            runtimeRoot = [System.IO.Path]::GetFullPath($alternateRuntime)
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
        }) -Path (Join-Path $alternateRuntime '.psobb-runtime.json')
    $alternateRootRejected = Test-Rejected -Pattern 'exact canonical path' {
        & $buildScript -Action Verify -RuntimeRoot $alternateRuntime
    }
    Add-Result 'public Verify rejects an ordinary self-marked alternate runtime first' `
        $alternateRootRejected 'canonical-root rejection precedes missing source or release input checks'

    $rootJunction = Join-Path $temporaryRoot 'runtime-root-junction'
    New-Item -ItemType Junction -Path $rootJunction -Target $runtimeRoot | Out-Null
    $fixtureJunctions.Add($rootJunction)
    $rootJunctionRejected = Test-Rejected -Pattern 'Reparse point in runtime root hierarchy' {
        Assert-ReparseFreeDirectory -Path $rootJunction -Label 'runtime root'
    }
    $intermediateRuntime = Join-Path $temporaryRoot 'intermediate-runtime'
    New-Item -ItemType Directory -Path $intermediateRuntime | Out-Null
    $sourceJunction = Join-Path $intermediateRuntime 'sources'
    New-Item -ItemType Junction -Path $sourceJunction `
        -Target (Join-Path $runtimeRoot 'sources') | Out-Null
    $fixtureJunctions.Add($sourceJunction)
    $intermediateJunctionRejected = Test-Rejected `
        -Pattern 'Reparse point in newserv checkout hierarchy' {
        Assert-GitCheckout -Path $sourceJunction -Commit ([string]$contract.source.commit) `
            -Label 'newserv'
    }
    Add-Result 'runtime roots and intermediate source junctions are rejected' (
        $rootJunctionRejected -and $intermediateJunctionRejected) `
        "root=$rootJunctionRejected; intermediate=$intermediateJunctionRejected"

    $publicationWithoutBoundaryRejected = Test-Rejected `
        -Pattern 'requires the exclusive combat-canary build' {
        Publish-CombatCanaryRelease -StageRelease (Join-Path $temporaryRoot 'unused-stage') `
            -ReleaseRoot (Join-Path $temporaryRoot 'unused-release') `
            -StagingRoot (Join-Path $temporaryRoot 'unused-staging') `
            -VerifyAction { }
    }
    Add-Result 'publication cannot bypass the build and lifecycle boundary' `
        $publicationWithoutBoundaryRejected 'direct publication without both mutexes is rejected'
    $savedBoundaryDepth = $script:BuildBoundaryDepth
    $script:BuildBoundaryDepth = 1

    $publicationRoot = Join-Path $temporaryRoot 'publication-bootstrap'
    $publicationStaging = Join-Path $publicationRoot '.staging'
    $bootstrapStage = Join-Path $publicationStaging 'bootstrap-stage'
    $bootstrapRelease = Join-Path $publicationRoot 'server-base\release'
    New-Item -ItemType Directory -Path $bootstrapStage -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $bootstrapStage 'new.txt'), 'new')
    Publish-CombatCanaryRelease -StageRelease $bootstrapStage `
        -ReleaseRoot $bootstrapRelease -StagingRoot $publicationStaging `
        -VerifyAction { if (-not (Test-Path -LiteralPath (
                        Join-Path $bootstrapRelease 'new.txt'))) { throw 'missing new release' } } |
        Out-Null
    $absentPublishPassed = (Test-Path -LiteralPath (
            Join-Path $bootstrapRelease 'new.txt') -PathType Leaf) -and
        -not (Test-Path -LiteralPath $bootstrapStage) -and
        @(Get-ChildItem -LiteralPath $publicationStaging -Directory -Filter 'previous-release-*').Count -eq 0

    $failedBootstrapStage = Join-Path $publicationStaging 'failed-bootstrap-stage\release'
    $failedBootstrapRelease = Join-Path $publicationRoot 'failed-server-base\release'
    New-Item -ItemType Directory -Path $failedBootstrapStage -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $failedBootstrapStage 'new.txt'), 'new')
    $absentFailureRejected = Test-Rejected -Pattern 'fixture verification failure' {
        Publish-CombatCanaryRelease -StageRelease $failedBootstrapStage `
            -ReleaseRoot $failedBootstrapRelease -StagingRoot $publicationStaging `
            -VerifyAction { throw 'fixture verification failure' }
    }
    $absentFailurePassed = $absentFailureRejected -and
        -not (Test-Path -LiteralPath $failedBootstrapRelease) -and
        @(Get-ChildItem -LiteralPath $publicationStaging -Directory -Filter 'failed-release-*').Count -eq 1
    Add-Result 'publication supports an absent release without fabricated rollback state' (
        $absentPublishPassed -and $absentFailurePassed) `
        "publish=$absentPublishPassed; failure=$absentFailurePassed"

    $replacementStage = Join-Path $publicationStaging 'replacement-stage\release'
    $replacementRelease = Join-Path $publicationRoot 'replacement-server-base\release'
    New-Item -ItemType Directory -Path $replacementStage, $replacementRelease -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $replacementStage 'new.txt'), 'new')
    [System.IO.File]::WriteAllText((Join-Path $replacementRelease 'old.txt'), 'old')
    $replacementRejected = Test-Rejected -Pattern 'fixture replacement failure' {
        Publish-CombatCanaryRelease -StageRelease $replacementStage `
            -ReleaseRoot $replacementRelease -StagingRoot $publicationStaging `
            -VerifyAction { throw 'fixture replacement failure' }
    }
    $replacementPassed = $replacementRejected -and
        (Test-Path -LiteralPath (Join-Path $replacementRelease 'old.txt') -PathType Leaf) -and
        -not (Test-Path -LiteralPath (Join-Path $replacementRelease 'new.txt')) -and
        @(Get-ChildItem -LiteralPath $publicationStaging -Directory `
            -Filter 'previous-release-*').Count -eq 0
    Add-Result 'failed replacement restores the prior release only when one existed' `
        $replacementPassed "restored=$replacementPassed"

    $junctionPublicationRoot = Join-Path $temporaryRoot 'junction-publication'
    $junctionPublicationStaging = Join-Path $junctionPublicationRoot '.staging'
    $junctionPublicationStage = Join-Path $junctionPublicationStaging 'candidate\release'
    $junctionPublicationTarget = Join-Path $temporaryRoot 'junction-publication-target'
    New-Item -ItemType Directory -Path $junctionPublicationStage, `
        $junctionPublicationTarget -Force | Out-Null
    $junctionPublicationParent = Join-Path $junctionPublicationRoot 'server-base'
    New-Item -ItemType Junction -Path $junctionPublicationParent `
        -Target $junctionPublicationTarget | Out-Null
    $fixtureJunctions.Add($junctionPublicationParent)
    $publicationJunctionRejected = Test-Rejected `
        -Pattern 'Reparse point in publication release root hierarchy' {
        Publish-CombatCanaryRelease -StageRelease $junctionPublicationStage `
            -ReleaseRoot (Join-Path $junctionPublicationParent 'release') `
            -StagingRoot $junctionPublicationStaging -VerifyAction { }
    }
    Add-Result 'publication rejects an intermediate release junction' `
        $publicationJunctionRejected "rejected=$publicationJunctionRejected"
    $script:BuildBoundaryDepth = $savedBoundaryDepth

    $boundaryRoot = Join-Path $temporaryRoot 'boundary-runtime'
    New-Item -ItemType Directory -Path $boundaryRoot | Out-Null
    $boundaryId = [Guid]::NewGuid().ToString('D')
    Write-JsonFixture -Value ([ordered]@{
            schemaVersion = 1
            installationId = $boundaryId
            runtimeRoot = [System.IO.Path]::GetFullPath($boundaryRoot)
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
        }) -Path (Join-Path $boundaryRoot '.psobb-runtime.json')
    $boundaryToken = $boundaryId.Replace('-', '').ToLowerInvariant()
    $canonicalRuntimeRoot = $script:RuntimeRoot
    $buildLease = Start-MutexLeaseFixture `
        -Name "Local\PSOBB.CombatCanary.Build.$boundaryToken" `
        -FixtureName 'build-mutex-lease'
    try {
        $script:RuntimeRoot = $boundaryRoot
        $buildCollisionRejected = Test-Rejected -Pattern 'Another combat-canary build' {
            Enter-CombatCanaryBuildBoundary
        }
    } finally {
        $script:RuntimeRoot = $canonicalRuntimeRoot
        Stop-MutexLeaseFixture -Lease $buildLease
    }
    $lifecycleLease = Start-MutexLeaseFixture `
        -Name "Local\PSOBB.Newserv.Start.$boundaryToken" `
        -FixtureName 'lifecycle-mutex-lease'
    try {
        $script:RuntimeRoot = $boundaryRoot
        $lifecycleCollisionRejected = Test-Rejected -Pattern 'lifecycle is changing' {
            Enter-CombatCanaryBuildBoundary
        }
    } finally {
        $script:RuntimeRoot = $canonicalRuntimeRoot
        Stop-MutexLeaseFixture -Lease $lifecycleLease
    }
    Add-Result 'build and lifecycle mutex collisions fail closed' (
        $buildCollisionRejected -and $lifecycleCollisionRejected -and
        $script:BuildBoundaryDepth -eq 0) `
        "build=$buildCollisionRejected; lifecycle=$lifecycleCollisionRejected"

    $buildsBefore = @(Get-ChildItem -LiteralPath (
            Join-Path $runtimeRoot 'combat-canary\builds') -Directory -Force).Count
    & $buildScript -Action Build -RuntimeRoot $runtimeRoot -WhatIf | Out-Null
    $buildsAfter = @(Get-ChildItem -LiteralPath (
            Join-Path $runtimeRoot 'combat-canary\builds') -Directory -Force).Count
    Add-Result 'Build honors ShouldProcess before mutation' ($buildsBefore -eq $buildsAfter) `
        "before=$buildsBefore; after=$buildsAfter"

    $scriptText = Get-Content -Raw -LiteralPath $buildScript
    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $buildScript, [ref]$tokens, [ref]$parseErrors)
    $nativeToolNames = @(
        'cmd', 'cmd.exe', 'git', 'git.exe', 'gpgv', 'gpgv.exe', 'tar', 'tar.exe',
        'cmake', 'cmake.exe', 'ctest', 'ctest.exe', 'ninja', 'ninja.exe',
        'gcc', 'gcc.exe', 'g++', 'g++.exe', 'mingw32-make', 'mingw32-make.exe',
        'objdump', 'objdump.exe', 'bash', 'bash.exe', 'sh', 'sh.exe',
        'subst', 'subst.exe'
    )
    $bareNativeCommands = @($scriptAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $null -ne $node.GetCommandName() -and
                $node.GetCommandName() -cin $nativeToolNames
            }, $true))
    Add-Result 'all native tools are exact-path verified before use' (
        $parseErrors.Count -eq 0 -and
        $bareNativeCommands.Count -eq 0 -and
        $scriptText -match '-DSH_EXECUTABLE=\$sh' -and
        $scriptText -match 'Tool was not verified before use' -and
        $scriptText -match 'Toolchain binary changed before invocation' -and
        $scriptText -match 'Environment\.Clear\(\)') `
        "bareCommands=$($bareNativeCommands.Count); parseErrors=$($parseErrors.Count)"

    $ordinaryBuildBoundaryCalls = [regex]::Matches(
        $scriptText,
        'Assert-OrdinaryBuildInputBoundary -Contract \$contract').Count
    Add-Result 'Build path is local, static, and atomic' (
        $scriptText -match 'SOURCE_DATE_EPOCH' -and
        $scriptText -match '--no-insert-timestamp' -and
        $scriptText -match '--noprofile' -and
        $scriptText -match "export PATH='/p/tools:\$\{mingwUnix\}:/usr/bin'" -and
        $scriptText -match "Assert-FileRecord -Path 'P:\\tools\\make\.exe'" -and
        $scriptText -match 'GIT_CONFIG_NOSYSTEM' -and
        $scriptText -match "GIT_NO_REPLACE_OBJECTS = '1'" -and
        $scriptText -match 'Get-VerifiedGitWorkingDirectory' -and
        $scriptText -match 'git-empty-exec-path' -and
        $scriptText -match 'New-LocalObjectGitCheckout' -and
        [regex]::Matches($scriptText, "'-C'").Count -eq 1 -and
        $scriptText -notmatch "'clone'" -and
        $scriptText -notmatch "'fetch'" -and
        $scriptText -match 'gpgv-empty-home' -and
        $scriptText -match 'native-execution-payloads\.json' -and
        $scriptText -match 'Assert-NoDeterministicBuildPathNeedles' -and
        $scriptText -match 'Assert-CTestSummary' -and
        $ordinaryBuildBoundaryCalls -eq 1 -and
        $scriptText.IndexOf('Assert-NativeToolPayloadBoundary -Id $Id',
            [System.StringComparison]::Ordinal) -lt
            $scriptText.IndexOf('$process.Start()',
                [System.StringComparison]::Ordinal) -and
        $scriptText -match 'Assert-OrdinaryExecutionTrees -Manifest \$nativeExecutionManifest' -and
        $scriptText -match 'Get-NativePayloadsForInvocation' -and
        $scriptText -match 'Get-GitTrackedFileInventory' -and
        $scriptText -match 'Get-NewservPackageSystemPlan' -and
        $scriptText -match 'Resolve-GitTrackedWorktreeSource' -and
        $scriptText -notmatch 'Sort-Object FullName' -and
        $scriptText -notmatch 'Get-ChildItem -LiteralPath \$systemRoot' -and
        $scriptText -notmatch 'Join-Path \$sourceOrigin ''(README\.md|LICENSE)''' -and
        $scriptText -match 'previous-release-' -and
        $scriptText.IndexOf('remove deterministic P: build drive',
            [System.StringComparison]::Ordinal) -lt
            $scriptText.LastIndexOf('Publish-CombatCanaryRelease -StageRelease',
                [System.StringComparison]::Ordinal) -and
        $scriptText -match 'PSOBB\.CombatCanary\.Build' -and
        $scriptText -match 'PSOBB\.Newserv\.Start' -and
        $scriptText -match 'Assert-PSOBBBuildStoppedBoundary' -and
        $scriptText -notmatch 'make_release\.py') `
        "fixed epoch, PATH-derived payload checks, tracked-only ordinal packaging, clean-build tree checks=$ordinaryBuildBoundaryCalls, stopped lifecycle, teardown-before-publish, and rollback are wired"

    $substPath = Get-ToolPath -Id 'subst'
    $substMappings = @(& $substPath)
    $pMapped = (Test-Path -LiteralPath 'P:\') -or
        @($substMappings | Where-Object { [string]$_ -match '^P:\\:' }).Count -ne 0
    Add-Result 'deterministic P drive is not mapped after verification' (-not $pMapped) `
        "mapped=$pMapped"

    $results | Format-Table -AutoSize
    $failed = @($results | Where-Object { -not $_.Passed })
    if ($failed.Count -gt 0) {
        throw "$($failed.Count) combat-canary build test(s) failed"
    }
    [pscustomobject]@{
        Suite = 'CombatCanaryBuild'
        Passed = $results.Count
        Failed = 0
    }
} finally {
    foreach ($helper in @($helperProcesses)) {
        try {
            if (-not $helper.HasExited) { $helper.Kill($true) }
            $helper.WaitForExit(5000) | Out-Null
            $helper.Dispose()
        } catch { }
    }
    foreach ($junction in @($fixtureJunctions)) {
        if (Test-Path -LiteralPath $junction) {
            [System.IO.Directory]::Delete($junction)
        }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-CombatCanaryBuildTestRoot -Path $temporaryRoot
    }
}
